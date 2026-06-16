# PIM4EntraPS -- DB cutover ceremony + on-demand recalc change-detector.
# Dot-sourced by PIM-Functions.psm1 (after PIM-SqlStore.ps1 + PIM-SchemaConformance.ps1,
# whose functions it orchestrates) and standalone by the pim-manager.
#
# THE INVARIANTS (REQUIREMENTS.md  5):
#   * Azure SQL is the single desired store in ALL modes (hosted, VM, emergency).
#   * SQLEXPRESS / Integrated is a DEV-ONLY convenience -- NEVER a production or
#     break-glass store. The ceremony refuses to "finalize" a cutover whose target
#     is a local/Express/Integrated store (a cutover means: become authoritative,
#     and only Azure SQL may be authoritative).
#   * break-glass = a client PC connecting DIRECT to the same Azure SQL -- still
#     Azure SQL, never a local copy.
#   * The CSV source is READ-ONLY: the migration reads it, never writes back.
#
# THE CEREMONY (a gated state machine the Manager drives via /api/cutover):
#   1. preflight       -- schema conformance + connectivity + data-shape audit,
#                         BEFORE touching anything (read-only).
#   2. upgrade         -- one-time idempotent schema CREATE+ALTER on the target.
#   3. import          -- TRANSACTIONAL CSV -> pim.Rows (all-or-nothing); every
#                         imported entity/row count is captured for the audit.
#   4. set-source      -- flip the persisted config source to SQL (StorageBackend=sql).
#   5. re-preflight    -- re-run preflight against the NOW-populated SQL store.
#   6. finalize        -- explicit operator "Finalize Cutover" confirmation; only
#                         then is the cutover marked Final + every imported row audited.
# Each stage is guarded: a stage may run only when the prior stage succeeded
# (Get-PimCutoverNextStage is the pure gate). The whole thing is idempotent --
# re-running a completed stage is a no-op that returns the recorded result.

Set-StrictMode -Off

# --- the ordered ceremony stages (single source of truth) -----------------------
$script:PimCutoverStages = @('preflight','upgrade','import','set-source','re-preflight','finalize')

function Get-PimCutoverStages { return [string[]]@($script:PimCutoverStages) }

# --- PURE GATE: given the completed-stages set, what may run next? ---------------
# Returns the next runnable stage name, or '' when the ceremony is finished.
# A stage is runnable only when every PRIOR stage is in $Completed. Re-running an
# already-completed (non-final) stage is allowed (idempotent) but never SKIPS ahead.
function Get-PimCutoverNextStage {
    param([AllowNull()][string[]]$Completed = @())
    $done = @{}; foreach ($c in @($Completed)) { if ("$c".Trim()) { $done["$c".ToLowerInvariant()] = $true } }
    if ($done.ContainsKey('finalize')) { return '' }   # ceremony complete
    foreach ($s in $script:PimCutoverStages) {
        if (-not $done.ContainsKey($s.ToLowerInvariant())) { return $s }
    }
    return ''
}

# --- PURE GATE: may this requested stage run now? -------------------------------
# A stage runs only when all earlier stages are complete. Returns @{ allowed; reason }.
function Test-PimCutoverStageAllowed {
    param([Parameter(Mandatory)][string]$Stage, [AllowNull()][string[]]$Completed = @())
    $idx = [array]::IndexOf($script:PimCutoverStages, $Stage)
    if ($idx -lt 0) { return @{ allowed = $false; reason = "unknown stage '$Stage'" } }
    $done = @{}; foreach ($c in @($Completed)) { if ("$c".Trim()) { $done["$c".ToLowerInvariant()] = $true } }
    if ($done.ContainsKey('finalize')) { return @{ allowed = $false; reason = 'cutover already finalized' } }
    for ($i = 0; $i -lt $idx; $i++) {
        $prior = $script:PimCutoverStages[$i]
        if (-not $done.ContainsKey($prior.ToLowerInvariant())) {
            return @{ allowed = $false; reason = "stage '$Stage' blocked: prior stage '$prior' not complete" }
        }
    }
    return @{ allowed = $true; reason = '' }
}

# --- PURE: classify a connection string as a PRODUCTION-grade store or not -------
# Azure SQL (database.windows.net, token auth) = production-grade (authoritative).
# Integrated / SQLEXPRESS / localdb / (local) = DEV-ONLY (never authoritative).
# Returns @{ kind = 'azure-sql'|'dev-local'|'unknown'; isProduction = [bool] }.
function Get-PimSqlStoreKind {
    param([AllowNull()][string]$ConnectionString)
    $cs = "$ConnectionString"
    if ($cs -match '(?i)database\.windows\.net') { return @{ kind = 'azure-sql'; isProduction = $true } }
    if ($cs -match '(?i)Integrated\s*Security' -or $cs -match '(?i)\\SQLEXPRESS' -or $cs -match '(?i)\(localdb\)' -or $cs -match '(?i)Server\s*=\s*\.?[\\;]' -or $cs -match '(?i)Server\s*=\s*\(local\)') {
        return @{ kind = 'dev-local'; isProduction = $false }
    }
    return @{ kind = 'unknown'; isProduction = $false }
}

# --- PURE: data-shape audit of the migration SOURCE vs the locked schema ---------
# Reports, per known base, whether the source needs schema conformance (drop/add/
# migrate). Pure over already-parsed rows -- no file IO, no DB. Used by stage 1
# (preflight) so the operator sees what the upgrade will do BEFORE it runs.
#   $SourceColumns = @{ <base> = [string[]] header }  (only present bases)
function Get-PimCutoverPreflightAudit {
    param([Parameter(Mandatory)][hashtable]$SourceColumns)
    if (-not (Get-Command Get-PimLockedSchema -ErrorAction SilentlyContinue)) {
        throw 'Get-PimCutoverPreflightAudit requires PIM-SchemaConformance.ps1 (Get-PimLockedSchema).'
    }
    $schema = Get-PimLockedSchema
    $rows = New-Object System.Collections.Generic.List[object]
    $needsUpgrade = $false
    foreach ($base in @($SourceColumns.Keys)) {
        $spec = $schema[$base]
        if (-not $spec) { $rows.Add([pscustomobject]@{ base = $base; known = $false; conformant = $true; toDrop = @(); toAdd = @(); toMigrate = @() }); continue }
        $plan = Get-PimSchemaConformancePlan -ActualColumns @($SourceColumns[$base]) -Spec $spec
        if (-not $plan.Conformant) { $needsUpgrade = $true }
        $rows.Add([pscustomobject]@{
            base = $base; known = $true; conformant = $plan.Conformant
            toDrop = @($plan.ToDrop); toAdd = @($plan.ToAdd)
            toMigrate = @(@($plan.ToMigrate) | ForEach-Object { "$($_.from)->$($_.to)" })
        })
    }
    return [pscustomobject]@{ needsUpgrade = $needsUpgrade; entities = $rows.ToArray() }
}

# --- CHANGE-DETECTOR: a stable signature of the SQL store's data state -----------
# On-demand recalc triggers off a CHANGE in this signature (row count + max
# UpdatedUtc over pim.Rows). Pure over the two inputs so it is unit-testable;
# Get-PimSqlDataSignature (below) reads them from SQL.
function New-PimDataSignature {
    param([int]$RowCount = 0, [AllowNull()][string]$MaxUpdatedUtc)
    $m = if ("$MaxUpdatedUtc".Trim()) { "$MaxUpdatedUtc".Trim() } else { 'none' }
    return ("rows={0}|max={1}" -f $RowCount, $m)
}

# Reads the live signature from the SQL store (COUNT + MAX(UpdatedUtc) over pim.Rows).
# Fail-OPEN: on any read error returns a unique signature so the caller never caches
# a stale "no change" verdict (a missed recalc is worse than a redundant one).
function Get-PimSqlDataSignature {
    param([Parameter(Mandatory)][string]$ConnectionString)
    try {
        $r = Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT COUNT(*) AS c, CONVERT(VARCHAR(33), MAX(UpdatedUtc), 126) AS m FROM pim.Rows" | Select-Object -First 1
        return (New-PimDataSignature -RowCount ([int]$r.c) -MaxUpdatedUtc "$($r.m)")
    } catch {
        return ("err|" + [datetime]::UtcNow.ToString('o'))
    }
}

# PURE recalc decision: has the data changed since the last signature we acted on?
# Returns @{ changed; signature }. A blank/absent last-signature counts as changed
# (first run after boot should recalc once).
function Test-PimRecalcNeeded {
    param([AllowNull()][string]$LastSignature, [Parameter(Mandatory)][string]$CurrentSignature)
    $changed = ("$LastSignature".Trim() -ne "$CurrentSignature".Trim())
    return @{ changed = $changed; signature = $CurrentSignature }
}

# --- ON-DEMAND RECALC: SQL change-detector that triggers an engine recalc --------
# REQUIREMENTS.md  5: "a monitor detecting a SQL change triggers an engine recalc."
# The scheduler already drains 'engine-delta' triggers each tick (PIM-Scheduler.ps1).
# This monitor reads the live SQL DATA signature, compares it to the last one we
# acted on (persisted in pim.Settings 'RecalcSignature'), and ENQUEUES an engine-delta
# trigger when it changed -- catching OUT-OF-BAND writes (another MSP node, a direct
# SQL edit, the cutover import) that never bumped the Manager's in-process watermark.
# Idempotent + cheap (COUNT + MAX(UpdatedUtc), not a table scan). Returns
# @{ changed; signature; triggered }.
function Invoke-PimSqlChangeDetector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [string]$Scope = 'All',
        [string]$Reason = 'sql-change'
    )
    $last = $null
    try { $last = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'RecalcSignature' } catch { }
    $cur  = Get-PimSqlDataSignature -ConnectionString $ConnectionString
    $dec  = Test-PimRecalcNeeded -LastSignature "$last" -CurrentSignature $cur
    $triggered = $false
    if ($dec.changed) {
        # Persist the new signature FIRST so a crash mid-trigger doesn't re-fire forever;
        # a redundant recalc is safe (idempotent engine), a missed one is not.
        try { Set-PimSqlSetting -ConnectionString $ConnectionString -Name 'RecalcSignature' -Value $cur } catch { }
        if (Get-Command Add-PimJobTrigger -ErrorAction SilentlyContinue) {
            [void](Add-PimJobTrigger -Type 'engine-delta' -Scope $Scope -Reason $Reason)
            $triggered = $true
        }
    }
    return @{ changed = $dec.changed; signature = $cur; triggered = $triggered }
}

# --- PERSISTENT-SQL requirement (REQUIREMENTS.md  5 new persistent-SQL req) ------
# Azure SQL serverless auto-pause makes /health and the first request after an idle
# window cold-start (and time out behind a probe). The hosted PIM SQL compute MUST
# run persistent: auto-pause DISABLED (provisioned or serverless with AutoPauseDelay
# = -1 / "never"). This is a PURE validator over the auto-pause-delay value the
# control-plane reports (minutes; -1 = disabled; provisioned tier reports $null).
#   Returns @{ persistent; reason }.
function Test-PimSqlPersistentCompute {
    param([AllowNull()]$AutoPauseDelayMinutes, [string]$Tier)
    # Serverless SKUs are named either with the word 'serverless' or the Azure
    # family marker '_S_' (e.g. GP_S_Gen5_2). Anything else is provisioned compute,
    # which never auto-pauses -> persistent by construction.
    $isServerless = ("$Tier" -match '(?i)serverless') -or ("$Tier" -match '(?i)_S_')
    if ("$Tier" -and -not $isServerless) {
        return @{ persistent = $true; reason = "tier '$Tier' is provisioned (no auto-pause)" }
    }
    if ($null -eq $AutoPauseDelayMinutes -or "$AutoPauseDelayMinutes".Trim() -eq '') {
        return @{ persistent = $true; reason = 'no auto-pause delay configured (provisioned)' }
    }
    $val = $null
    if ([int]::TryParse("$AutoPauseDelayMinutes", [ref]$val)) {
        if ($val -lt 0) { return @{ persistent = $true; reason = 'auto-pause disabled (delay = -1)' } }
        return @{ persistent = $false; reason = "auto-pause ENABLED ($val min) -- disable it: serverless must run persistent (AutoPauseDelay = -1) so /health + the desired store never cold-start" }
    }
    return @{ persistent = $false; reason = "unparseable auto-pause delay '$AutoPauseDelayMinutes'" }
}

# --- /health PAYLOAD (resilient to transient SQL blips) --------------------------
# The hosted /health probe must stay 200 across a transient SQL blip (a single
# failed ping is not "unhealthy") but report degraded so the operator can see it.
# PURE state machine over (probeOk, consecutiveFailures, threshold):
#   probeOk            -> healthy, counter reset
#   !probeOk & < thr   -> degraded (transient) -- STILL serve 200 (don't flap the probe)
#   !probeOk & >= thr  -> unhealthy -- 503 (sustained outage; let the platform react)
# Returns @{ status; httpStatus; consecutiveFailures }.
function Get-PimHealthState {
    param([bool]$ProbeOk, [int]$ConsecutiveFailures = 0, [int]$Threshold = 3)
    if ($Threshold -lt 1) { $Threshold = 1 }
    if ($ProbeOk) { return @{ status = 'healthy'; httpStatus = 200; consecutiveFailures = 0 } }
    $n = $ConsecutiveFailures + 1
    if ($n -lt $Threshold) { return @{ status = 'degraded'; httpStatus = 200; consecutiveFailures = $n } }
    return @{ status = 'unhealthy'; httpStatus = 503; consecutiveFailures = $n }
}

# --- TRANSACTIONAL IMPORT (stage 3): CSV -> pim.Rows, all-or-nothing -------------
# Reads each <base>.custom.csv (READ-ONLY -- the CSV is never written), and applies
# a FULL-SET replace of every entity inside ONE transaction. On any failure the
# whole import rolls back (the store is left exactly as it was). Returns a per-entity
# audit @{ ok; total; entities = @(@{ base; rows }) } that the ceremony records.
#
# Uses one SqlTransaction across all entities (the SqlStore CRUD helpers each open
# their own connection, so the transactional path is implemented here directly via
# New-PimSqlConnection -- the same auth/token path).
function Invoke-PimCutoverImport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfigDir,
        [Parameter(Mandatory)][string]$ConnectionString,
        [switch]$WhatIf
    )
    if (-not (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue)) {
        throw 'Invoke-PimCutoverImport requires PIM-SqlStore.ps1 (Get-PimStoreRowKey).'
    }
    $files = @(Get-ChildItem -LiteralPath $ConfigDir -Filter '*.custom.csv' -File -ErrorAction Stop | Sort-Object Name)
    $entities = New-Object System.Collections.Generic.List[object]
    $total = 0

    if ($WhatIf) {
        foreach ($f in $files) {
            $base = $f.BaseName -replace '\.custom$', ''
            $rows = @(Import-Csv -Path $f.FullName -Delimiter ';' -Encoding UTF8)
            $entities.Add([pscustomobject]@{ base = $base; rows = $rows.Count }); $total += $rows.Count
        }
        return [pscustomobject]@{ ok = $true; whatIf = $true; total = $total; entities = $entities.ToArray() }
    }

    $conn = New-PimSqlConnection -ConnectionString $ConnectionString
    $conn.Open()
    $tx = $conn.BeginTransaction()
    try {
        foreach ($f in $files) {
            $base = $f.BaseName -replace '\.custom$', ''
            $rows = @(Import-Csv -Path $f.FullName -Delimiter ';' -Encoding UTF8)   # READ-ONLY source
            # Replace this entity's rows wholesale, inside the shared transaction.
            $delCmd = $conn.CreateCommand(); $delCmd.Transaction = $tx
            $delCmd.CommandText = "DELETE FROM pim.Rows WHERE Entity = @e"
            [void]$delCmd.Parameters.AddWithValue('@e', $base)
            [void]$delCmd.ExecuteNonQuery()
            $n = 0
            foreach ($r in $rows) {
                $k = Get-PimStoreRowKey -Base $base -Row $r
                if (-not $k) { continue }
                $json = $r | ConvertTo-Json -Depth 12 -Compress
                $insCmd = $conn.CreateCommand(); $insCmd.Transaction = $tx
                $insCmd.CommandText = "INSERT INTO pim.Rows (Entity, [Key], DataJson, UpdatedUtc) VALUES (@e, @k, @d, SYSUTCDATETIME())"
                [void]$insCmd.Parameters.AddWithValue('@e', $base)
                [void]$insCmd.Parameters.AddWithValue('@k', $k)
                [void]$insCmd.Parameters.AddWithValue('@d', $json)
                [void]$insCmd.ExecuteNonQuery()
                $n++
            }
            $entities.Add([pscustomobject]@{ base = $base; rows = $n }); $total += $n
        }
        $tx.Commit()
        return [pscustomobject]@{ ok = $true; whatIf = $false; total = $total; entities = $entities.ToArray() }
    } catch {
        try { $tx.Rollback() } catch { }
        throw "cutover import rolled back (store unchanged): $($_.Exception.Message)"
    } finally {
        $conn.Close()
    }
}

# --- CEREMONY STATE persisted in pim.Settings (key 'CutoverState') ---------------
# Shape: @{ completed = [string[]]; final = [bool]; audit = @{ <stage> = <result> }; updatedUtc }.
function Get-PimCutoverState {
    param([Parameter(Mandatory)][string]$ConnectionString)
    $s = $null
    try { $s = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'CutoverState' } catch { }
    if (-not $s) { return [pscustomobject]@{ completed = @(); final = $false; audit = @{}; updatedUtc = $null } }
    # ConvertFrom-Json returns a PSCustomObject; normalize completed -> array.
    $completed = @(); if ($s.PSObject.Properties['completed']) { $completed = @($s.completed) }
    $final = $false; if ($s.PSObject.Properties['final']) { $final = [bool]$s.final }
    $audit = @{}; if ($s.PSObject.Properties['audit'] -and $s.audit) { foreach ($p in $s.audit.PSObject.Properties) { $audit[$p.Name] = $p.Value } }
    return [pscustomobject]@{ completed = $completed; final = $final; audit = $audit; updatedUtc = $(if ($s.PSObject.Properties['updatedUtc']) { $s.updatedUtc } else { $null }) }
}

function Set-PimCutoverState {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][object]$State)
    # Cutover state lives in pim.Settings, which the schema-upgrade stage creates.
    # State can be recorded as early as the (read-only) preflight stage, before
    # upgrade has run, so ensure the table exists first (idempotent, cheap).
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
IF SCHEMA_ID('pim') IS NULL EXEC ('CREATE SCHEMA pim');
IF OBJECT_ID('pim.Settings') IS NULL
CREATE TABLE pim.Settings (
    Name        NVARCHAR(200) NOT NULL PRIMARY KEY,
    ValueJson   NVARCHAR(MAX) NULL,
    UpdatedUtc  DATETIME2     NOT NULL CONSTRAINT DF_Settings_Updated DEFAULT SYSUTCDATETIME()
);
"@)
    $body = [ordered]@{
        completed  = @($State.completed)
        final      = [bool]$State.final
        audit      = $State.audit
        updatedUtc = [datetime]::UtcNow.ToString('o')
    }
    Set-PimSqlSetting -ConnectionString $ConnectionString -Name 'CutoverState' -Value $body
}

# Record a completed stage (idempotent: a stage is listed once) + its audit result.
function Add-PimCutoverCompletedStage {
    param([Parameter(Mandatory)][object]$State, [Parameter(Mandatory)][string]$Stage, [object]$Audit)
    $c = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($State.completed)) { if ("$x".Trim() -and -not ($c -contains "$x")) { $c.Add("$x") } }
    if (-not ($c -contains $Stage)) { $c.Add($Stage) }
    $a = @{}; if ($State.audit) { if ($State.audit -is [hashtable]) { $a = $State.audit.Clone() } else { foreach ($p in $State.audit.PSObject.Properties) { $a[$p.Name] = $p.Value } } }
    if ($PSBoundParameters.ContainsKey('Audit')) { $a[$Stage] = $Audit }
    return [pscustomobject]@{ completed = $c.ToArray(); final = ($Stage -eq 'finalize'); audit = $a; updatedUtc = [datetime]::UtcNow.ToString('o') }
}
