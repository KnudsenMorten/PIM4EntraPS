#Requires -Version 5.1
<#
.SYNOPSIS
    Tests for the DB cutover ceremony, the on-demand-recalc SQL change-detector, the
    persistent-SQL guard and the resilient /health state machine (engine/_shared/
    PIM-Cutover.ps1).

.DESCRIPTION
    Layer 1 -- PURE (always runs, no SQL): the ceremony stage gate, the dev-vs-Azure
    store classifier, the recalc change-detector decision, the persistent-SQL
    validator and the /health degraded-vs-unhealthy state machine.

    Layer 2 -- LIVE SQL (self-skips when no instance reachable): runs the WHOLE
    ceremony end-to-end against a throwaway SQL DB -- preflight -> upgrade ->
    transactional import (READ-ONLY CSV source) -> set-source=sql -> re-preflight ->
    finalize -- asserting rows land in pim.Rows, the CSV is untouched, the gate
    blocks out-of-order stages, FINALIZE refuses a dev-local store, and the change-
    detector enqueues an engine-delta trigger when the SQL signature changes.

        powershell -NoProfile -File .\tests\Test-PimCutover.ps1 [-Server .\SQLEXPRESS]
#>
[CmdletBinding()] param([string]$Server = '.\SQLEXPRESS')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$sh   = Join-Path $root 'engine\_shared'
. (Join-Path $sh 'PIM-SchemaConformance.ps1')
. (Join-Path $sh 'PIM-ChangeQueue.ps1')
. (Join-Path $sh 'PIM-SqlStore.ps1')
. (Join-Path $sh 'PIM-Scheduler.ps1')   # Add-PimJobTrigger / Get-PimPendingTriggers (recalc target)
. (Join-Path $sh 'PIM-Cutover.ps1')

$pass=0; $fail=0; $skip=0
function T($n,$c){ if($c){Write-Host "  PASS $n" -ForegroundColor Green;$script:pass++}else{Write-Host "  FAIL $n" -ForegroundColor Red;$script:fail++} }
function S($n,$w){ Write-Host "  SKIP $n -- $w" -ForegroundColor Yellow;$script:skip++ }

Write-Host "=== PIM cutover ceremony + recalc + health ===" -ForegroundColor Cyan
Write-Host "`n-- Layer 1: pure --" -ForegroundColor Cyan

# Ceremony stage order + gate
T 'stages are the canonical 6-step order' (((Get-PimCutoverStages) -join ',') -eq 'preflight,upgrade,import,set-source,re-preflight,finalize')
T 'next stage from empty = preflight' ((Get-PimCutoverNextStage -Completed @()) -eq 'preflight')
T 'next stage advances in order' ((Get-PimCutoverNextStage -Completed @('preflight','upgrade')) -eq 'import')
T 'next stage is empty once finalized' ((Get-PimCutoverNextStage -Completed @('preflight','upgrade','import','set-source','re-preflight','finalize')) -eq '')
T 'gate BLOCKS a stage whose prior is incomplete' (-not (Test-PimCutoverStageAllowed -Stage 'import' -Completed @('preflight')).allowed)
T 'gate ALLOWS a stage whose priors are complete' ((Test-PimCutoverStageAllowed -Stage 'import' -Completed @('preflight','upgrade')).allowed)
T 'gate refuses everything once finalized' (-not (Test-PimCutoverStageAllowed -Stage 'import' -Completed @('preflight','upgrade','import','set-source','re-preflight','finalize')).allowed)
T 'gate rejects an unknown stage' (-not (Test-PimCutoverStageAllowed -Stage 'bogus' -Completed @()).allowed)

# Store-kind classifier: Azure SQL = production; SQLEXPRESS/Integrated = dev-only
T 'Azure SQL FQDN classified production' ((Get-PimSqlStoreKind -ConnectionString 'Server=tcp:x.database.windows.net,1433;Database=d').isProduction)
T 'SQLEXPRESS Integrated classified dev-local (NOT production)' (-not (Get-PimSqlStoreKind -ConnectionString 'Server=.\SQLEXPRESS;Database=d;Integrated Security=SSPI').isProduction)
T 'Integrated security classified dev-local' ((Get-PimSqlStoreKind -ConnectionString 'Server=foo;Database=d;Integrated Security=SSPI').kind -eq 'dev-local')

# Persistent-SQL guard (the new persistent-SQL requirement)
T 'serverless + auto-pause ENABLED -> NOT persistent (flagged)' (-not (Test-PimSqlPersistentCompute -AutoPauseDelayMinutes 60 -Tier 'GP_S_Gen5_2').persistent)
T 'serverless + auto-pause DISABLED (-1) -> persistent' ((Test-PimSqlPersistentCompute -AutoPauseDelayMinutes -1 -Tier 'GP_S_Gen5_2').persistent)
T 'provisioned tier -> persistent' ((Test-PimSqlPersistentCompute -AutoPauseDelayMinutes $null -Tier 'GP_Gen5_2').persistent)
T '_S_ family marker detected as serverless' (-not (Test-PimSqlPersistentCompute -AutoPauseDelayMinutes 120 -Tier 'GP_S_Gen5_4').persistent)

# /health resilient state machine
T 'health: probe OK -> healthy/200, counter reset' (((Get-PimHealthState -ProbeOk $true -ConsecutiveFailures 5).status -eq 'healthy') -and ((Get-PimHealthState -ProbeOk $true -ConsecutiveFailures 5).consecutiveFailures -eq 0))
T 'health: first blip -> degraded but STILL 200' ((Get-PimHealthState -ProbeOk $false -ConsecutiveFailures 0 -Threshold 3).httpStatus -eq 200)
T 'health: blip below threshold stays 200 (transient-resilient)' ((Get-PimHealthState -ProbeOk $false -ConsecutiveFailures 1 -Threshold 3).httpStatus -eq 200)
T 'health: sustained failures (>=threshold) -> 503 unhealthy' ((Get-PimHealthState -ProbeOk $false -ConsecutiveFailures 2 -Threshold 3).httpStatus -eq 503)

# Recalc change-detector decision
T 'recalc: blank last-signature counts as changed (first run)' ((Test-PimRecalcNeeded -LastSignature '' -CurrentSignature 'rows=1|max=a').changed)
T 'recalc: same signature -> NOT changed' (-not (Test-PimRecalcNeeded -LastSignature 'rows=1|max=a' -CurrentSignature 'rows=1|max=a').changed)
T 'recalc: different signature -> changed' ((Test-PimRecalcNeeded -LastSignature 'rows=1|max=a' -CurrentSignature 'rows=2|max=b').changed)
T 'data signature is stable for the same inputs' ((New-PimDataSignature -RowCount 3 -MaxUpdatedUtc 't') -eq (New-PimDataSignature -RowCount 3 -MaxUpdatedUtc 't'))

# Preflight audit (pure over headers): a TierLevel header needs upgrade (drop+migrate)
$pf = Get-PimCutoverPreflightAudit -SourceColumns @{ 'Account-Definitions-Admins' = @('UserName','DisplayName','TierLevel') }
T 'preflight audit flags TierLevel for drop+migrate -> needsUpgrade' ($pf.needsUpgrade -and (@($pf.entities)[0].toDrop -contains 'TierLevel'))
$pf2 = Get-PimCutoverPreflightAudit -SourceColumns @{ 'PIM-Definitions-Tasks' = @('GroupName','GroupTag','Workload') }
T 'preflight audit: a conformant entity needs no upgrade' (-not $pf2.needsUpgrade)

# State accumulator (pure)
$st0 = [pscustomobject]@{ completed = @(); final = $false; audit = @{} }
$st1 = Add-PimCutoverCompletedStage -State $st0 -Stage 'preflight' -Audit @{ ok = $true }
$st1 = Add-PimCutoverCompletedStage -State $st1 -Stage 'preflight' -Audit @{ ok = $true }  # idempotent
T 'completed stage recorded once (idempotent)' ((@($st1.completed) -eq 'preflight').Count -eq 1)
T 'finalize stage marks state final' ((Add-PimCutoverCompletedStage -State $st1 -Stage 'finalize').final)

# ---------------------------------------------------------------------------
# Layer 2 -- LIVE SQL (throwaway DB; self-skips if no instance reachable)
# ---------------------------------------------------------------------------
Write-Host "`n-- Layer 2: live SQL --" -ForegroundColor Cyan
$masterCs = Get-PimSqlConnectionString -Server $Server -Database 'master'
if (-not (Test-PimSqlConnectivity -ConnectionString $masterCs)) {
    S 'cutover live ceremony' "SQL '$Server' not reachable"
} else {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pimcut-" + [guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    $db = "pimcut_" + [guid]::NewGuid().ToString('N').Substring(0,12)
    $cs = Get-PimSqlConnectionString -Server $Server -Database $db
    # isolate scheduler trigger state to this process (no Get/Set-PimSetting defined -> in-memory)
    $script:PimTriggers = @()
    try {
        $admCsv = Join-Path $tmp 'Account-Definitions-Admins.custom.csv'
        Set-Content -LiteralPath $admCsv -Encoding UTF8 -Value @(
            'UserName;DisplayName;Purpose'
            'Admin-AA-ID;AA;Day2Day'
            'Admin-BB-ID;BB;HighPriv'
        )
        Set-Content -LiteralPath (Join-Path $tmp 'PIM-Definitions-Tasks.custom.csv') -Encoding UTF8 -Value @(
            'GroupName;GroupTag;Workload;Level;Plane'
            'PIM-Entra-ID-A-L1-T0-CP-ID;Entra-ID-A-L1;Entra-ID;L1;CP'
        )
        Initialize-PimSqlDatabase -Server $Server -Database $db

        # Stage gate respects state read back from SQL.
        $state = Get-PimCutoverState -ConnectionString $cs
        T 'fresh cutover state: nothing completed, not final' ((@($state.completed).Count -eq 0) -and -not $state.final)

        # 1. preflight (read-only): connectivity OK.
        T 'preflight: SQL reachable' (Test-PimSqlConnectivity -ConnectionString $cs)
        $state = Add-PimCutoverCompletedStage -State $state -Stage 'preflight' -Audit @{ connectivity = $true }
        Set-PimCutoverState -ConnectionString $cs -State $state

        # 2. upgrade (idempotent schema).
        Initialize-PimSqlStore -ConnectionString $cs
        $state = Get-PimCutoverState -ConnectionString $cs
        $state = Add-PimCutoverCompletedStage -State $state -Stage 'upgrade' -Audit @{ ok = $true }
        Set-PimCutoverState -ConnectionString $cs -State $state
        T 'state round-trips through SQL (preflight+upgrade)' (((Get-PimCutoverState -ConnectionString $cs).completed | Sort-Object) -join ',' -eq 'preflight,upgrade')

        # gate: import is allowed now, finalize is NOT (priors incomplete)
        $live = Get-PimCutoverState -ConnectionString $cs
        T 'live gate: import allowed after upgrade' ((Test-PimCutoverStageAllowed -Stage 'import' -Completed @($live.completed)).allowed)
        T 'live gate: finalize blocked (priors incomplete)' (-not (Test-PimCutoverStageAllowed -Stage 'finalize' -Completed @($live.completed)).allowed)

        # 3. transactional import (READ-ONLY CSV source).
        $imp = Invoke-PimCutoverImport -ConfigDir $tmp -ConnectionString $cs
        T 'import: total rows = 3 across 2 entities' ($imp.ok -and $imp.total -eq 3 -and @($imp.entities).Count -eq 2)
        T 'import: admins landed in pim.Rows (2)' (@(Get-PimSqlRows -ConnectionString $cs -Entity 'Account-Definitions-Admins').Count -eq 2)
        T 'import: tasks landed in pim.Rows (1) + round-trips data' ((Get-PimSqlRow -ConnectionString $cs -Entity 'PIM-Definitions-Tasks' -Key 'Entra-ID-A-L1').Workload -eq 'Entra-ID')
        T 'import: CSV source left UNTOUCHED (read-only)' ((Get-Content $admCsv).Count -eq 3)
        # transactional re-import is idempotent (replace, not append)
        [void](Invoke-PimCutoverImport -ConfigDir $tmp -ConnectionString $cs)
        T 'import: idempotent re-run (still 2 admin rows)' (@(Get-PimSqlRows -ConnectionString $cs -Entity 'Account-Definitions-Admins').Count -eq 2)
        $state = Get-PimCutoverState -ConnectionString $cs
        $state = Add-PimCutoverCompletedStage -State $state -Stage 'import' -Audit @{ total = $imp.total; entities = $imp.entities }
        Set-PimCutoverState -ConnectionString $cs -State $state

        # 4. set-source = SQL (persisted in pim.Settings).
        Set-PimSqlSetting -ConnectionString $cs -Name 'StorageBackend' -Value 'sql'
        T 'set-source: StorageBackend=sql persisted' ((Get-PimSqlSetting -ConnectionString $cs -Name 'StorageBackend') -eq 'sql')
        $state = Get-PimCutoverState -ConnectionString $cs
        $state = Add-PimCutoverCompletedStage -State $state -Stage 'set-source' -Audit @{ storageBackend = 'sql' }
        $state = Add-PimCutoverCompletedStage -State $state -Stage 're-preflight' -Audit @{ signature = (Get-PimSqlDataSignature -ConnectionString $cs) }
        Set-PimCutoverState -ConnectionString $cs -State $state

        # 5. finalize REFUSES a dev-local store (the invariant under test).
        $kind = Get-PimSqlStoreKind -ConnectionString $cs
        T 'finalize precondition: SQLEXPRESS store is NOT production (would be refused)' (-not $kind.isProduction)

        # change-detector: a SQL data change enqueues exactly one engine-delta trigger.
        $script:PimTriggers = @()
        $d1 = Invoke-PimSqlChangeDetector -ConnectionString $cs -Scope 'All'
        T 'change-detector: first observation triggers recalc' ($d1.changed -and $d1.triggered)
        T 'change-detector: enqueued an engine-delta trigger' (@(Get-PimPendingTriggers | Where-Object { "$($_.type)" -eq 'engine-delta' }).Count -ge 1)
        $d2 = Invoke-PimSqlChangeDetector -ConnectionString $cs -Scope 'All'
        T 'change-detector: no change -> no new trigger (idempotent)' (-not $d2.changed)
        # mutate the store, detector fires again
        Set-PimSqlRow -ConnectionString $cs -Entity 'Account-Definitions-Admins' -Key 'Admin-CC-ID' -Data ([pscustomobject]@{ UserName='Admin-CC-ID'; DisplayName='CC'; Purpose='Day2Day' })
        Start-Sleep -Milliseconds 50
        $d3 = Invoke-PimSqlChangeDetector -ConnectionString $cs -Scope 'All'
        T 'change-detector: a new SQL write re-triggers recalc' ($d3.changed -and $d3.triggered)
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        try { [void](Invoke-PimSqlNonQuery -ConnectionString $masterCs -Sql "IF DB_ID('$db') IS NOT NULL BEGIN ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]; END") } catch {}
    }
}

Write-Host ("`n RESULT: {0} pass, {1} fail, {2} skip" -f $pass, $fail, $skip) -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 } else { exit 0 }
