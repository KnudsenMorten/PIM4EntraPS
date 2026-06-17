#Requires -Version 5.1
<#
.SYNOPSIS
    Tests for the DB cutover ABORT / rollback + the human-readable stage audit
    (REQUIREMENTS.md s28 [L3]) -- engine/_shared/PIM-Cutover.ps1.

.DESCRIPTION
    Layer 1 -- PURE (always runs, no SQL): the abort gate (allowed only when started
    + not finalized; refused once final / when nothing started), the abort plan
    (revert-source only after set-source), and the human-readable audit formatter
    (every stage rendered as plain lines; never raw JSON; nothing hidden).

    Layer 2 -- LIVE SQL (self-skips when no instance reachable): runs a partial
    ceremony (preflight -> upgrade -> import -> set-source) against a throwaway DB,
    aborts it, and asserts StorageBackend reverts to csv, the ceremony state is
    cleared back to the start, and a finalized ceremony refuses abort.

        powershell -NoProfile -File .\tests\Test-PimCutoverAbort.ps1 [-Server .\SQLEXPRESS]
#>
[CmdletBinding()] param([string]$Server = '.\SQLEXPRESS')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$sh   = Join-Path $root 'engine\_shared'
. (Join-Path $sh 'PIM-SchemaConformance.ps1')
. (Join-Path $sh 'PIM-ChangeQueue.ps1')
. (Join-Path $sh 'PIM-SqlStore.ps1')
. (Join-Path $sh 'PIM-Scheduler.ps1')
. (Join-Path $sh 'PIM-Cutover.ps1')

$pass=0; $fail=0; $skip=0
function T($n,$c){ if($c){Write-Host "  PASS $n" -ForegroundColor Green;$script:pass++}else{Write-Host "  FAIL $n" -ForegroundColor Red;$script:fail++} }
function S($n,$w){ Write-Host "  SKIP $n -- $w" -ForegroundColor Yellow;$script:skip++ }

Write-Host "=== PIM cutover abort / rollback + human-readable audit ([L3]) ===" -ForegroundColor Cyan
Write-Host "`n-- Layer 1: pure --" -ForegroundColor Cyan

# --- Abort GATE -----------------------------------------------------------------
T 'abort refused when nothing started' (-not (Test-PimCutoverAbortAllowed -Completed @() -Final $false).allowed)
T 'abort allowed after a stage has started' ((Test-PimCutoverAbortAllowed -Completed @('preflight') -Final $false).allowed)
T 'abort allowed mid-ceremony (after set-source)' ((Test-PimCutoverAbortAllowed -Completed @('preflight','upgrade','import','set-source') -Final $false).allowed)
T 'abort REFUSED once finalized (final flag)' (-not (Test-PimCutoverAbortAllowed -Completed @('preflight','upgrade','import','set-source','re-preflight','finalize') -Final $true).allowed)
T 'abort REFUSED when finalize in completed even without final flag' (-not (Test-PimCutoverAbortAllowed -Completed @('finalize') -Final $false).allowed)
T 'finalized abort-refusal reason mentions point of no return' ((Test-PimCutoverAbortAllowed -Completed @('finalize') -Final $true).reason -match 'point of no return')

# --- Abort PLAN -----------------------------------------------------------------
$planEarly = Get-PimCutoverAbortPlan -Completed @('preflight','upgrade')
T 'plan before set-source does NOT revert source' (-not $planEarly.revertSource)
T 'plan before set-source still clears state' ($planEarly.clearState -and @($planEarly.steps).Count -ge 1)
$planAfter = Get-PimCutoverAbortPlan -Completed @('preflight','upgrade','import','set-source')
T 'plan after set-source DOES revert source' ($planAfter.revertSource)
T 'plan after set-source mentions reverting to CSV' (@($planAfter.steps) -join ' ' -match '(?i)StorageBackend = csv')
T 'plan after import mentions CSV source was read-only' (@($planAfter.steps) -join ' ' -match '(?i)read-only')

# --- Human-readable audit formatter ---------------------------------------------
$audit = @{
    preflight    = [pscustomobject]@{ connectivity = $true; needsUpgrade = $true; entities = @([pscustomobject]@{ base='Account-Definitions-Admins'; toDrop=@('TierLevel'); toAdd=@(); toMigrate=@('TierLevel->Purpose') }, [pscustomobject]@{ base='PIM-Definitions-Tasks'; toDrop=@(); toAdd=@(); toMigrate=@() }) }
    upgrade      = [pscustomobject]@{ schemaInitialized = $true }
    import       = [pscustomobject]@{ total = 3; whatIf = $false; entities = @([pscustomobject]@{ base='Account-Definitions-Admins'; rows=2 }, [pscustomobject]@{ base='PIM-Definitions-Tasks'; rows=1 }) }
    'set-source' = [pscustomobject]@{ storageBackend = 'sql' }
}
$fmt = Format-PimCutoverAudit -Audit $audit
T 'formatter returns one block per completed stage in canonical order' ((@($fmt).Count -eq 4) -and (@($fmt)[0].stage -eq 'preflight') -and (@($fmt)[3].stage -eq 'set-source'))
$allText = (@($fmt) | ForEach-Object { $_.lines }) -join "`n"
T 'preflight block renders connectivity + upgrade verdict' ($allText -match 'SQL connectivity: OK' -and $allText -match 'Schema upgrade needed: yes')
T 'preflight block renders the migrate detail (TierLevel->Purpose)' ($allText -match 'TierLevel->Purpose')
T 'preflight block renders a conformant entity as no-change' ($allText -match 'PIM-Definitions-Tasks : conformant')
T 'import block renders the imported row total + per-entity counts' ($allText -match 'Imported 3 row' -and $allText -match 'Account-Definitions-Admins : 2 row')
T 'set-source block renders the flipped backend' ($allText -match 'flipped to: sql')
T 'formatter output contains NO raw JSON braces' (-not ($allText -match '[\{\}]'))
# WhatIf import renders "Would import"
$fmtWi = Format-PimCutoverAudit -Audit @{ import = [pscustomobject]@{ total = 5; whatIf = $true; entities = @() } }
T 'whatIf import renders "Would import"' ((@($fmtWi)[0].lines -join "`n") -match 'Would import 5 row')
# finalize block
$fmtFin = Format-PimCutoverAudit -Audit @{ finalize = [pscustomobject]@{ storeKind = 'azure-sql'; importAudit = [pscustomobject]@{ total = 7 } } }
T 'finalize block names the authoritative store + import total' ((@($fmtFin)[0].lines -join "`n") -match 'FINALIZED' -and (@($fmtFin)[0].lines -join "`n") -match 'Imported total: 7')
# unknown-shape fallback never hides a key
$fmtUnk = Format-PimCutoverAudit -Audit @{ preflight = [pscustomobject]@{ mysteryField = 'xyz' } }
T 'unknown audit keys are surfaced, never hidden' ((@($fmtUnk)[0].lines -join "`n") -match 'mysteryField : xyz')
# hashtable-shaped stage results work too (state read back from SQL is PSCustomObject; in-proc is hashtable)
$fmtHt = Format-PimCutoverAudit -Audit @{ 'set-source' = @{ storageBackend = 'sql' } }
T 'formatter accepts hashtable stage results' ((@($fmtHt)[0].lines -join "`n") -match 'flipped to: sql')
T 'empty audit -> empty formatter output' ((@(Format-PimCutoverAudit -Audit @{})).Count -eq 0)

# ---------------------------------------------------------------------------
# Layer 2 -- LIVE SQL (throwaway DB; self-skips if no instance reachable)
# ---------------------------------------------------------------------------
Write-Host "`n-- Layer 2: live SQL --" -ForegroundColor Cyan
$masterCs = Get-PimSqlConnectionString -Server $Server -Database 'master'
if (-not (Test-PimSqlConnectivity -ConnectionString $masterCs)) {
    S 'cutover abort live ceremony' "SQL '$Server' not reachable"
} else {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pimabort-" + [guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    $db = "pimabort_" + [guid]::NewGuid().ToString('N').Substring(0,12)
    $cs = Get-PimSqlConnectionString -Server $Server -Database $db
    try {
        $admCsv = Join-Path $tmp 'Account-Definitions-Admins.custom.csv'
        Set-Content -LiteralPath $admCsv -Encoding UTF8 -Value @(
            'UserName;DisplayName;Purpose'
            'Admin-AA-ID;AA;Day2Day'
        )
        Initialize-PimSqlDatabase -Server $Server -Database $db

        # Run a partial ceremony up through set-source.
        $state = Get-PimCutoverState -ConnectionString $cs
        $state = Add-PimCutoverCompletedStage -State $state -Stage 'preflight' -Audit @{ connectivity = $true; needsUpgrade = $false; entities = @() }
        Set-PimCutoverState -ConnectionString $cs -State $state
        Initialize-PimSqlStore -ConnectionString $cs
        $state = Get-PimCutoverState -ConnectionString $cs
        $state = Add-PimCutoverCompletedStage -State $state -Stage 'upgrade' -Audit @{ schemaInitialized = $true }
        Set-PimCutoverState -ConnectionString $cs -State $state
        $imp = Invoke-PimCutoverImport -ConfigDir $tmp -ConnectionString $cs
        $state = Get-PimCutoverState -ConnectionString $cs
        $state = Add-PimCutoverCompletedStage -State $state -Stage 'import' -Audit @{ total = $imp.total; whatIf = $false; entities = $imp.entities }
        Set-PimCutoverState -ConnectionString $cs -State $state
        Set-PimSqlSetting -ConnectionString $cs -Name 'StorageBackend' -Value 'sql'
        $state = Get-PimCutoverState -ConnectionString $cs
        $state = Add-PimCutoverCompletedStage -State $state -Stage 'set-source' -Audit @{ storageBackend = 'sql' }
        Set-PimCutoverState -ConnectionString $cs -State $state

        T 'precondition: StorageBackend = sql before abort' ((Get-PimSqlSetting -ConnectionString $cs -Name 'StorageBackend') -eq 'sql')
        T 'precondition: cutover state has 4 completed stages' (@((Get-PimCutoverState -ConnectionString $cs).completed).Count -eq 4)

        # ABORT.
        $res = Invoke-PimCutoverAbort -ConnectionString $cs
        T 'abort: ok + reverted source' ($res.ok -and $res.revertedSource)
        T 'abort: StorageBackend reverted to csv' ((Get-PimSqlSetting -ConnectionString $cs -Name 'StorageBackend') -eq 'csv')
        $after = Get-PimCutoverState -ConnectionString $cs
        T 'abort: cutover state cleared (nothing completed, not final)' ((@($after.completed).Count -eq 0) -and -not $after.final)
        T 'abort: next stage is back to preflight' ((Get-PimCutoverNextStage -Completed @($after.completed)) -eq 'preflight')
        T 'abort: imported rows left in SQL (harmless; re-import on retry)' (@(Get-PimSqlRows -ConnectionString $cs -Entity 'Account-Definitions-Admins').Count -eq 1)
        T 'abort: CSV source left UNTOUCHED (read-only)' ((Get-Content $admCsv).Count -eq 2)

        # Aborting again with nothing started is refused.
        $threw = $false
        try { Invoke-PimCutoverAbort -ConnectionString $cs } catch { $threw = $true }
        T 'abort: refused when nothing started (after clear)' ($threw)

        # A FINALIZED ceremony refuses abort.
        $finState = Add-PimCutoverCompletedStage -State ([pscustomobject]@{ completed = @('preflight','upgrade','import','set-source','re-preflight'); final = $false; audit = @{} }) -Stage 'finalize' -Audit @{ finalized = $true }
        Set-PimCutoverState -ConnectionString $cs -State $finState
        $threwFin = $false
        try { Invoke-PimCutoverAbort -ConnectionString $cs } catch { $threwFin = $true }
        T 'abort: refused once finalized' ($threwFin)
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        try { [void](Invoke-PimSqlNonQuery -ConnectionString $masterCs -Sql "IF DB_ID('$db') IS NOT NULL BEGIN ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]; END") } catch {}
    }
}

Write-Host ("`n RESULT: {0} pass, {1} fail, {2} skip" -f $pass, $fail, $skip) -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 } else { exit 0 }
