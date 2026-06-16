# PIM4EntraPS -- safe, reversible commits for Review & Save (REQUIREMENTS.md s28 [M1]).
# Dot-sourced by the pim-manager (after PIM-SqlStore.ps1, whose row helpers it
# orchestrates) and standalone by the offline tests.
#
# THE PROBLEM ([M1]): the Review & Save commit was non-transactional and had no
# snapshot. A mid-loop failure half-applied an entity's row-set (some upserts/
# deletes landed, the rest didn't) with nothing to roll back to, and there was no
# operator "undo".
#
# THE FIX -- three guarantees, each with a PURE, INJECTABLE core so it is unit-
# testable offline (no live SQL required):
#   1. BACKUP BEFORE APPLY  -- New-PimCommitSnapshot captures the affected entity's
#      CURRENT rows + header into an immutable snapshot record BEFORE any write.
#      The snapshot is persisted (SQL: pim.Backups; file: a sibling JSON) so it
#      survives a crash, keeping only the last N (Get-PimBackupRetentionPlan).
#   2. TRANSACTIONAL APPLY  -- Invoke-PimCommitTransaction applies the whole change
#      set all-or-nothing. The actual write is an injectable -ApplyScript; on ANY
#      failure mid-apply it runs the injectable -RestoreScript (restore the
#      snapshot) and rethrows a clear error, so the store is left exactly as before.
#   3. UNDO / ROLLBACK      -- Restore-from-snapshot replays a stored snapshot back
#      over the entity (Get-PimSnapshotRestorePlan is the pure planner), letting an
#      operator reverse the last commit from the Manager.
#
# PS 5.1-safe: no ?./??, no RSA.ImportFromPem; never indexes $null; Set-Content via
# explicit UTF-8 (no BOM) where a file is written.

Set-StrictMode -Off

# A snapshot record (the immutable unit of backup/undo). One snapshot captures the
# pre-commit state of ONE entity:
#   @{ id; entity; base; takenUtc; by; reason; header[]; rows[]; rowCount }
# 'id' is a sortable, collision-resistant token: <utc-compact>-<entity>-<rand>.

function New-PimBackupId {
    # Sortable id: yyyyMMddTHHmmssfffZ + entity + 4 hex. Sorts chronologically as a
    # plain string, which is what the retention planner relies on.
    param([Parameter(Mandatory)][string]$Entity, [string]$TakenUtc)
    $ts = if ("$TakenUtc".Trim()) { [datetime]::Parse($TakenUtc).ToUniversalTime() } else { [datetime]::UtcNow }
    $stamp = $ts.ToString('yyyyMMddTHHmmssfff') + 'Z'
    $rand  = ([guid]::NewGuid().ToString('N')).Substring(0, 4)
    $safeEntity = ($Entity -replace '[^A-Za-z0-9_\.-]', '_')
    return "$stamp-$safeEntity-$rand"
}

function New-PimCommitSnapshot {
    # PURE: build an immutable snapshot record from the entity's CURRENT (pre-commit)
    # rows. No I/O -- the caller passes the rows it already read for the diff, so the
    # snapshot is exactly the before-state the commit will replace.
    param(
        [Parameter(Mandatory)][string]$Entity,
        [string]$Base,
        [AllowNull()][object[]]$Rows = @(),
        [AllowNull()][string[]]$Header = @(),
        [string]$By = "$env:USERNAME",
        [string]$Reason = 'review-and-save commit',
        [string]$TakenUtc
    )
    $base = if ("$Base".Trim()) { $Base } else { $Entity }
    $taken = if ("$TakenUtc".Trim()) { [datetime]::Parse($TakenUtc).ToUniversalTime().ToString('o') } else { ([datetime]::UtcNow).ToString('o') }
    $rowsArr = @($Rows)
    return [pscustomobject]@{
        id       = (New-PimBackupId -Entity $Entity -TakenUtc $taken)
        entity   = "$Entity"
        base     = "$base"
        takenUtc = $taken
        by       = "$By"
        reason   = "$Reason"
        header   = @($Header)
        rows     = $rowsArr
        rowCount = $rowsArr.Count
    }
}

function Get-PimBackupRetentionPlan {
    # PURE: given existing snapshot ids (or records) for ONE entity and a keep-count
    # N, return @{ keep = [ids]; prune = [ids] } -- the OLDEST beyond N are pruned.
    # Ids sort chronologically as strings (New-PimBackupId), so newest = last.
    param(
        [AllowNull()][object[]]$Snapshots = @(),
        [int]$Keep = 10
    )
    if ($Keep -lt 0) { $Keep = 0 }
    # Normalise to id strings, preserving any record's id.
    $ids = @()
    foreach ($s in @($Snapshots)) {
        if ($null -eq $s) { continue }
        if ($s -is [string]) { $ids += $s }
        elseif ($s.PSObject.Properties['id']) { $ids += "$($s.id)" }
        elseif ($s -is [System.Collections.IDictionary] -and $s.Contains('id')) { $ids += "$($s['id'])" }
    }
    $ids = @($ids | Where-Object { "$_".Trim() } | Sort-Object)   # oldest -> newest
    $n = $ids.Count
    if ($n -le $Keep) { return @{ keep = @($ids); prune = @() } }
    $pruneCount = $n - $Keep
    return @{
        keep  = @($ids[$pruneCount..($n - 1)])
        prune = @($ids[0..($pruneCount - 1)])
    }
}

function Get-PimSnapshotRestorePlan {
    # PURE: turn a snapshot record into the rows+header to full-set replace the
    # entity with. The restore is a FULL-SET replace (the same semantics as a
    # commit), so an undo perfectly reproduces the pre-commit state -- including
    # rows the bad commit had deleted. Returns @{ entity; base; header; rows }.
    param([Parameter(Mandatory)][object]$Snapshot)
    $entity = "$($Snapshot.entity)"
    $base = if ("$($Snapshot.base)".Trim()) { "$($Snapshot.base)" } else { $entity }
    return @{
        entity = $entity
        base   = $base
        header = @($Snapshot.header)
        rows   = @($Snapshot.rows)
    }
}

function Invoke-PimCommitTransaction {
    # The all-or-nothing seam. Pure + injectable so the offline tests drive it with
    # in-memory closures (no live SQL). Sequence:
    #   1. (caller already built $Snapshot from the pre-commit rows)
    #   2. persist the snapshot   -> & $SaveSnapshotScript $Snapshot
    #   3. apply the change set    -> & $ApplyScript            (the real write)
    #   4. on ANY failure in (3):  -> & $RestoreScript $Snapshot (put it back)
    #                                 then rethrow a clear, prefixed error.
    #   5. on success: prune old snapshots -> & $PruneScript    (best-effort)
    # The snapshot is saved BEFORE the apply so a crash between (2) and (4) still
    # leaves a restorable copy on disk/in SQL. RestoreScript MUST be all-or-nothing
    # itself (it replays a known-good full-set), so the worst case is "restored to
    # the pre-commit state", never a half-state.
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][scriptblock]$ApplyScript,
        [Parameter(Mandatory)][scriptblock]$RestoreScript,
        [scriptblock]$SaveSnapshotScript,
        [scriptblock]$PruneScript
    )
    $result = [ordered]@{
        ok          = $false
        snapshotId  = "$($Snapshot.id)"
        entity      = "$($Snapshot.entity)"
        applied     = $false
        restored    = $false
        rowsAffected = 0
        error       = $null
    }

    # 1) persist the backup FIRST (so a crash still leaves an undo point).
    if ($SaveSnapshotScript) {
        try { [void](& $SaveSnapshotScript $Snapshot) }
        catch {
            $result.error = "backup write failed (commit refused, store untouched): $($_.Exception.Message)"
            throw [System.Exception]::new($result.error)
        }
    }

    # 2) apply the change set; on failure restore and rethrow.
    try {
        $applyRes = & $ApplyScript
        $result.applied = $true
        if ($null -ne $applyRes) {
            if ($applyRes.PSObject.Properties['rowsAffected']) { $result.rowsAffected = [int]$applyRes.rowsAffected }
            elseif ($applyRes.PSObject.Properties['rowCount']) { $result.rowsAffected = [int]$applyRes.rowCount }
        }
    } catch {
        $applyErr = "$($_.Exception.Message)"
        # roll back to the snapshot -- the whole point of [M1].
        $restoreErr = $null
        try { [void](& $RestoreScript $Snapshot); $result.restored = $true }
        catch { $restoreErr = "$($_.Exception.Message)" }
        if ($result.restored) {
            $result.error = "commit failed and was ROLLED BACK to the pre-commit snapshot ($($Snapshot.id)); store is unchanged. Cause: $applyErr"
        } else {
            $result.error = "commit failed AND rollback ALSO failed -- store may be inconsistent. Restore snapshot $($Snapshot.id) manually. Apply error: $applyErr. Restore error: $restoreErr"
        }
        throw [System.Exception]::new($result.error)
    }

    # 3) success -- prune old snapshots (never fatal).
    if ($PruneScript) {
        try { [void](& $PruneScript) } catch { Write-Warning "  [backup] retention prune failed (non-fatal): $($_.Exception.Message)" }
    }

    $result.ok = $true
    return [pscustomobject]$result
}

# ---------------------------------------------------------------------------
# SQL persistence (pim.Backups) -- the storage adapter the Manager wires the
# pure core to. Mirrors the PIM-SqlStore.ps1 style (raw ADO.NET via the shared
# Invoke-PimSql* helpers). A snapshot row stores the whole entity body as JSON.
# ---------------------------------------------------------------------------

function Initialize-PimBackupStore {
    # Create pim.Backups if missing. Idempotent. Safe to call on every Manager open.
    param([Parameter(Mandatory)][string]$ConnectionString)
    $ddl = @"
IF SCHEMA_ID('pim') IS NULL EXEC ('CREATE SCHEMA pim');
IF OBJECT_ID('pim.Backups') IS NULL
CREATE TABLE pim.Backups (
    Id        NVARCHAR(200) NOT NULL PRIMARY KEY,
    Entity    NVARCHAR(100) NOT NULL,
    TakenUtc  DATETIME2     NOT NULL CONSTRAINT DF_Backups_Taken DEFAULT SYSUTCDATETIME(),
    [By]      NVARCHAR(256) NULL,
    Reason    NVARCHAR(400) NULL,
    RowCount2 INT           NOT NULL CONSTRAINT DF_Backups_RowCount DEFAULT 0,
    BodyJson  NVARCHAR(MAX) NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_Backups_Entity_Taken' AND object_id = OBJECT_ID('pim.Backups'))
CREATE INDEX IX_pim_Backups_Entity_Taken ON pim.Backups (Entity, TakenUtc);
"@
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql $ddl)
}

function Save-PimSqlBackupSnapshot {
    # Persist one snapshot record into pim.Backups. The full record (header + rows)
    # is serialised to BodyJson so a restore is a pure read-back.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][object]$Snapshot)
    $body = $Snapshot | ConvertTo-Json -Depth 25 -Compress
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
INSERT INTO pim.Backups (Id, Entity, TakenUtc, [By], Reason, RowCount2, BodyJson)
VALUES (@id, @e, @t, @by, @r, @rc, @b);
"@ -Parameters @{
        id = "$($Snapshot.id)"; e = "$($Snapshot.entity)"; t = [datetime]$Snapshot.takenUtc
        by = "$($Snapshot.by)"; r = "$($Snapshot.reason)"; rc = [int]$Snapshot.rowCount; b = $body
    })
}

function Get-PimSqlBackupSnapshots {
    # List snapshot METADATA (no body) for an entity, oldest -> newest. For the GUI
    # undo list + the retention planner.
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$Entity)
    $where = if ("$Entity".Trim()) { 'WHERE Entity = @e' } else { '' }
    $params = if ("$Entity".Trim()) { @{ e = $Entity } } else { @{} }
    $raw = Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT Id, Entity, TakenUtc, [By], Reason, RowCount2 FROM pim.Backups $where ORDER BY Id" -Parameters $params
    return @($raw | ForEach-Object {
        [pscustomobject]@{
            id = "$($_.Id)"; entity = "$($_.Entity)"
            takenUtc = ([datetime]$_.TakenUtc).ToString('o')
            by = "$($_.By)"; reason = "$($_.Reason)"; rowCount = [int]$_.RowCount2
        }
    })
}

function Get-PimSqlBackupSnapshot {
    # Read ONE full snapshot record (header + rows) back from pim.Backups.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Id)
    $j = Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql "SELECT BodyJson FROM pim.Backups WHERE Id=@id" -Parameters @{ id = $Id }
    if ($null -eq $j -or "$j".Trim() -eq '') { return $null }
    $rec = $j | ConvertFrom-Json
    # Normalise rows/header to arrays (ConvertFrom-Json gives a scalar for 1-elem).
    return [pscustomobject]@{
        id = "$($rec.id)"; entity = "$($rec.entity)"; base = "$($rec.base)"
        takenUtc = "$($rec.takenUtc)"; by = "$($rec.by)"; reason = "$($rec.reason)"
        header = @($rec.header); rows = @($rec.rows); rowCount = [int]$rec.rowCount
    }
}

function Remove-PimSqlBackupSnapshot {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Id)
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql "DELETE FROM pim.Backups WHERE Id=@id" -Parameters @{ id = $Id })
}

function Invoke-PimSqlBackupRetention {
    # Apply the retention plan for one entity against pim.Backups. Returns pruned ids.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity, [int]$Keep = 10)
    $existing = @(Get-PimSqlBackupSnapshots -ConnectionString $ConnectionString -Entity $Entity)
    $plan = Get-PimBackupRetentionPlan -Snapshots $existing -Keep $Keep
    foreach ($id in @($plan.prune)) { Remove-PimSqlBackupSnapshot -ConnectionString $ConnectionString -Id $id }
    return @($plan.prune)
}
