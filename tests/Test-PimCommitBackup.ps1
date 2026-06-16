#Requires -Version 5.1
<#
.SYNOPSIS
    OFFLINE tests for safe, reversible Review & Save commits (REQUIREMENTS.md s28 [M1]).
    No live SQL / no tenant -- the pure core (engine/_shared/PIM-CommitBackup.ps1) is
    driven with in-memory closures, and the transactional store is exercised against a
    fake in-memory pim.Rows so a simulated mid-commit failure can be proven to leave the
    store unchanged.

    Asserts:
      * a timestamped backup is written BEFORE the apply runs;
      * a simulated mid-commit failure leaves the store unchanged (rollback) AND
        surfaces a clear error;
      * undo restores the prior snapshot (full-set replace, incl. rows the bad commit deleted);
      * N-retention prunes the oldest snapshots, keeps the newest N.

        powershell -NoProfile -File .\tests\Test-PimCommitBackup.ps1
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'engine\_shared\PIM-CommitBackup.ps1')

$fail = New-Object System.Collections.Generic.List[string]; $pass = 0
function A($cond, $name) { if ($cond) { $script:pass++; Write-Host "  [PASS] $name" -ForegroundColor Green } else { $script:fail.Add($name); Write-Host "  [FAIL] $name" -ForegroundColor Red } }

# ---------------------------------------------------------------------------
Write-Host "Pure snapshot + retention planner" -ForegroundColor Cyan

$before = @(
    [pscustomobject]@{ GroupTag='G1'; RoleDefinitionName='Reader' }
    [pscustomobject]@{ GroupTag='G2'; RoleDefinitionName='Owner' }
)
$snap = New-PimCommitSnapshot -Entity 'PIM-Assignments-Roles-Groups' -Rows $before -Header @('GroupTag','RoleDefinitionName') -By 'tester' -Reason 'unit'
A ($snap.rowCount -eq 2) 'snapshot captures the pre-commit row count'
A ($snap.id -match '^\d{8}T\d{9}Z-') 'snapshot id is timestamp-sortable'
A ("$($snap.entity)" -eq 'PIM-Assignments-Roles-Groups' -and "$($snap.by)" -eq 'tester') 'snapshot records entity + actor'

# Two ids generated later sort after earlier ones (string-sortable).
$idA = New-PimBackupId -Entity 'E' -TakenUtc '2026-06-16T08:00:00Z'
$idB = New-PimBackupId -Entity 'E' -TakenUtc '2026-06-16T09:00:00Z'
A (($idA, $idB | Sort-Object)[0] -eq $idA) 'ids sort chronologically as strings'

# Retention: keep last 3 of 5 -> prune the 2 oldest.
$ids = 1..5 | ForEach-Object { New-PimBackupId -Entity 'E' -TakenUtc ('2026-06-16T0{0}:00:00Z' -f $_) }
$plan = Get-PimBackupRetentionPlan -Snapshots $ids -Keep 3
A (@($plan.keep).Count -eq 3 -and @($plan.prune).Count -eq 2) 'retention keeps N, prunes the rest'
A (@($plan.prune)[0] -eq $ids[0] -and @($plan.prune)[1] -eq $ids[1]) 'retention prunes the OLDEST first'
$planNone = Get-PimBackupRetentionPlan -Snapshots $ids -Keep 10
A (@($planNone.prune).Count -eq 0) 'retention prunes nothing when under the keep count'

# Restore plan reproduces the snapshot rows as a full-set replace.
$rp = Get-PimSnapshotRestorePlan -Snapshot $snap
A (@($rp.rows).Count -eq 2 -and "$($rp.entity)" -eq 'PIM-Assignments-Roles-Groups') 'restore plan reproduces the snapshot rows'

# ---------------------------------------------------------------------------
Write-Host "Transactional commit core: backup-before-apply + rollback-on-failure" -ForegroundColor Cyan

# In-memory store + ordered trace so we can prove ordering and all-or-nothing.
$store = [ordered]@{ 'G1'='Reader'; 'G2'='Owner' }     # current entity rows by key
$saved = New-Object System.Collections.ArrayList        # snapshots persisted
$trace = New-Object System.Collections.ArrayList

$mkSnap = { New-PimCommitSnapshot -Entity 'E' -Rows $before -Header @('GroupTag','RoleDefinitionName') -By 'tester' -Reason 'unit' }

# 1) HAPPY PATH ----------------------------------------------------------------
$snap1 = & $mkSnap
$save  = { param($s) [void]$saved.Add($s); [void]$trace.Add('save') }
$apply = { [void]$trace.Add('apply'); $script:store = [ordered]@{ 'G1'='Reader'; 'G3'='Contributor' }; @{ rowsAffected = 2 } }
$rest  = { param($s) [void]$trace.Add('restore') }
$prune = { [void]$trace.Add('prune') }
$res1 = Invoke-PimCommitTransaction -Snapshot $snap1 -ApplyScript $apply -RestoreScript $rest -SaveSnapshotScript $save -PruneScript $prune
A ($res1.ok -and $res1.applied -and -not $res1.restored) 'happy-path commit succeeds (applied, not restored)'
A (@($trace)[0] -eq 'save' -and @($trace)[1] -eq 'apply') 'BACKUP is written BEFORE the apply'
A (@($trace) -contains 'prune' -and -not (@($trace) -contains 'restore')) 'success prunes; no restore on success'
A (@($saved).Count -eq 1) 'one snapshot persisted on the happy path'

# 2) MID-COMMIT FAILURE -> ROLLBACK -------------------------------------------
$store = [ordered]@{ 'G1'='Reader'; 'G2'='Owner' }      # reset
$restoredTo = $null
$trace.Clear(); $saved.Clear()
$snap2 = & $mkSnap
$applyFail = {
    [void]$trace.Add('apply')
    # simulate a half-applied write, THEN fail mid-loop.
    $script:store = [ordered]@{ 'G1'='Reader' }          # G2 already deleted (partial)
    throw 'boom: connection dropped mid-commit'
}
$restoreFn = { param($s) [void]$trace.Add('restore'); $script:restoredTo = @($s.rows); $script:store = [ordered]@{ 'G1'='Reader'; 'G2'='Owner' } }
$threw = $false; $err = ''
try { [void](Invoke-PimCommitTransaction -Snapshot $snap2 -ApplyScript $applyFail -RestoreScript $restoreFn -SaveSnapshotScript $save -PruneScript $prune) }
catch { $threw = $true; $err = "$($_.Exception.Message)" }
A ($threw) 'a mid-commit failure THROWS (commit not silently swallowed)'
A ($err -match 'ROLLED BACK') 'the error CLEARLY states the commit was rolled back'
A (@($trace) -contains 'restore') 'failure triggers the restore (rollback) path'
A (-not (@($trace) -contains 'prune')) 'no prune after a failed commit'
A ($store.Count -eq 2 -and $store['G2'] -eq 'Owner') 'store left EXACTLY as before the commit (G2 restored)'
A (@($restoredTo).Count -eq 2) 'restore replayed the full pre-commit snapshot'

# 3) restore-ALSO-fails surfaces a louder message -----------------------------
$trace.Clear()
$snap3 = & $mkSnap
$restoreBad = { param($s) throw 'restore also failed' }
$err3 = ''
try { [void](Invoke-PimCommitTransaction -Snapshot $snap3 -ApplyScript $applyFail -RestoreScript $restoreBad -SaveSnapshotScript $save) }
catch { $err3 = "$($_.Exception.Message)" }
A ($err3 -match 'rollback ALSO failed') 'a failed rollback surfaces a louder, distinct error'

# 4) backup write failure REFUSES the commit (store untouched) ----------------
$applyShouldNotRun = $true
$applyGuard = { $script:applyShouldNotRun = $false; @{ rowsAffected = 1 } }
$saveBad = { param($s) throw 'cannot write backup' }
$err4 = ''
try { [void](Invoke-PimCommitTransaction -Snapshot (& $mkSnap) -ApplyScript $applyGuard -RestoreScript $rest -SaveSnapshotScript $saveBad) }
catch { $err4 = "$($_.Exception.Message)" }
A ($err4 -match 'backup write failed' -and $applyShouldNotRun) 'a failed backup REFUSES the commit (apply never runs)'

# ---------------------------------------------------------------------------
Write-Host "SQL transactional store (fake in-memory ADO.NET) -- all-or-nothing apply" -ForegroundColor Cyan
# Drive Set-PimSqlEntityRowsTransactional against a fake connection that mutates an
# in-memory table only on Commit() and discards on Rollback(). Proves a real
# mid-loop failure (the -FailAfter test seam) leaves pim.Rows unchanged.
. (Join-Path $root 'engine\_shared\PIM-SqlStore.ps1')

# A fake SqlConnection/Transaction/Command backed by a script-scope table.
# Keys are the natural composite keys the store derives (GroupTag|RoleDefinitionName).
$script:FakeRows = [ordered]@{ 'G1|Reader'='{"GroupTag":"G1","RoleDefinitionName":"Reader"}'; 'G2|Owner'='{"GroupTag":"G2","RoleDefinitionName":"Owner"}' }
$script:FakeStaged = $null

function New-FakeSqlConn {
    $conn = New-Object psobject
    $conn | Add-Member ScriptMethod Open  { } -Force
    $conn | Add-Member ScriptMethod Close { } -Force
    $conn | Add-Member ScriptMethod BeginTransaction {
        $script:FakeStaged = [ordered]@{}
        foreach ($k in $script:FakeRows.Keys) { $script:FakeStaged[$k] = $script:FakeRows[$k] }
        $tx = New-Object psobject
        $tx | Add-Member ScriptMethod Commit   { foreach ($k in @($script:FakeRows.Keys)) { $script:FakeRows.Remove($k) }; foreach ($k in $script:FakeStaged.Keys) { $script:FakeRows[$k] = $script:FakeStaged[$k] } } -Force
        $tx | Add-Member ScriptMethod Rollback { $script:FakeStaged = $null } -Force
        return $tx
    } -Force
    $conn | Add-Member ScriptMethod CreateCommand {
        $cmd = New-Object psobject
        $cmd | Add-Member NoteProperty Transaction $null
        $cmd | Add-Member NoteProperty CommandText ''
        $params = New-Object System.Collections.ArrayList
        $cmd | Add-Member NoteProperty _params $params
        $paramColl = New-Object psobject
        $paramColl | Add-Member NoteProperty _list $params
        $paramColl | Add-Member ScriptMethod AddWithValue { param($n,$v) [void]$this._list.Add([pscustomobject]@{ n=$n; v=$v }) } -Force
        $cmd | Add-Member NoteProperty Parameters $paramColl
        $cmd | Add-Member ScriptMethod ExecuteNonQuery {
            $p = @{}; foreach ($x in $this._params) { $p[$x.n] = $x.v }
            if ($this.CommandText -match 'MERGE') { $script:FakeStaged[[string]$p['@k']] = [string]$p['@d'] }
            elseif ($this.CommandText -match 'DELETE') { if ($script:FakeStaged.Contains([string]$p['@k'])) { $script:FakeStaged.Remove([string]$p['@k']) } }
        } -Force
        $cmd | Add-Member ScriptMethod ExecuteReader {
            $keys = @($script:FakeStaged.Keys)
            $rd = New-Object psobject
            $rd | Add-Member NoteProperty _keys $keys
            $rd | Add-Member NoteProperty _i (-1)
            $rd | Add-Member ScriptMethod Read     { $this._i++; return ($this._i -lt $this._keys.Count) } -Force
            $rd | Add-Member ScriptMethod GetValue { param($i) return $this._keys[$this._i] } -Force
            $rd | Add-Member ScriptMethod Close    { } -Force
            return $rd
        } -Force
        return $cmd
    } -Force
    return $conn
}
# Override the connection factory for this test only.
function New-PimSqlConnection { param([string]$ConnectionString) return (New-FakeSqlConn) }

$newRows = @(
    [pscustomobject]@{ GroupTag='G1'; RoleDefinitionName='Reader' }
    [pscustomobject]@{ GroupTag='G3'; RoleDefinitionName='Contributor' }   # add G3, drop G2
)

# Happy path: G2 removed, G3 added, committed.
$r = Set-PimSqlEntityRowsTransactional -ConnectionString 'fake' -Entity 'E' -Base 'PIM-Assignments-Roles-Groups' -Rows $newRows
A ($script:FakeRows.Contains('G3|Contributor') -and -not $script:FakeRows.Contains('G2|Owner')) 'transactional commit applied the full delta (G3 added, G2 dropped)'
A ($r.removed -eq 1) 'transactional commit reports the removed count'

# Failure path: -FailAfter throws mid-loop; the table must be UNCHANGED from here.
$snapshotRows = [ordered]@{}; foreach ($k in $script:FakeRows.Keys) { $snapshotRows[$k] = $script:FakeRows[$k] }
$threwSql = $false
try { [void](Set-PimSqlEntityRowsTransactional -ConnectionString 'fake' -Entity 'E' -Base 'PIM-Assignments-Roles-Groups' -Rows @([pscustomobject]@{ GroupTag='G9'; RoleDefinitionName='X' }) -FailAfter 1) }
catch { $threwSql = $true }
A ($threwSql) 'a mid-loop SQL failure throws'
$unchanged = ($script:FakeRows.Count -eq $snapshotRows.Count)
foreach ($k in $snapshotRows.Keys) { if (-not $script:FakeRows.Contains($k)) { $unchanged = $false } }
A ($unchanged -and -not $script:FakeRows.Contains('G9|X')) 'rollback left pim.Rows EXACTLY unchanged (no half-apply)'

# ---------------------------------------------------------------------------
Write-Host ('=' * 70)
if ($fail.Count -eq 0) { Write-Host ("ALL {0} ASSERTIONS PASSED." -f $pass) -ForegroundColor Green; exit 0 }
else { Write-Host ("{0} passed, {1} FAILED:" -f $pass, $fail.Count) -ForegroundColor Red; $fail | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
