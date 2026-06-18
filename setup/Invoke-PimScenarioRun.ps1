#Requires -Version 5.1
<#
.SYNOPSIS
    §31.3 Phase-2 -- the SCENARIO-BOUND engine runner live wrapper. Thin
    orchestrator over the PURE core in engine/_shared/PIM-Downlink.ps1
    (Invoke-PimScenarioDeploy / Get-PimScenarioRunPlan).

.DESCRIPTION
    Resolves the active deployment scenario (S1-S6) and runs the right path for the
    topology:
      * single  (S1/S2) -> engine apply only.
      * master  (S3/S4) -> engine apply only (the master hosts its own estate).
      * managed (S5/S6) -> downlink-sync (ring pull -> verify -> master->slave admin
                           sync) THEN engine apply.

    Composes Invoke-PimEngineCore for the engine apply (which honours the
    mass-disable guard: -Prune is opt-in + Full-only, and an empty desired set
    never prunes). Composes Invoke-PimManagedDownlink for the managed path.

    This is what the live scenario matrix's `scenario-runner-triggers-engine` +
    `idempotent-second-pass` steps assert exists, runs, and is a no-op on a second
    pass. PURE decisions (the topology branch) are offline-tested in
    tests/Test-PimDownlink.ps1. PS 5.1-safe; SPN + certificate only.

.PARAMETER Scenario
    'S1'..'S6'. When omitted, resolves the active scenario from the store
    (Get-PimActiveScenario), defaulting to S1.

.PARAMETER EngineScope / EngineMode
    Forwarded to Invoke-PimEngineCore (default All / Delta).

.PARAMETER TenantId / SlaveRing / BaselineDocPath / BaselineUrl / BaselineAccessToken
    Managed (S5/S6) downlink inputs -- the signed baseline + the slave tenant/ring.

.PARAMETER CentralRoot / LocalRoot / SqlServer / SqlDatabase
    Staging roots + the platform registry (defaults from env / .\SQLEXPRESS).

.PARAMETER WhatIfMode
    Default ON: plan/preview, no live writes. -WhatIfMode:$false applies.

.EXAMPLE
    # single-tenant (S1): engine apply only.
    .\Invoke-PimScenarioRun.ps1 -Scenario S1 -WhatIfMode:$false

.EXAMPLE
    # managed local (S6): downlink-sync then engine apply.
    .\Invoke-PimScenarioRun.ps1 -Scenario S6 -TenantId <tenant-id-2linkit> -SlaveRing 2 `
        -BaselineDocPath C:\TMP\baseline-latest.json -WhatIfMode:$false
#>
[CmdletBinding()]
param(
    [ValidateSet('S1','S2','S3','S4','S5','S6')][string]$Scenario,

    [string]$EngineScope = 'All',
    [ValidateSet('Full','Delta')][string]$EngineMode = 'Delta',

    [string]$TenantId,
    [ValidateRange(0,2)][int]$SlaveRing = 2,
    [string]$BaselineDocPath,
    [string]$BaselineUrl,
    [string]$BaselineAccessToken,

    [string]$CentralRoot = $env:PIM_SyncRootCentral,
    [string]$LocalRoot   = $env:PIM_SyncRootLocal,
    [string]$SqlServer   = $env:PIM_SqlServer,
    [string]$SqlDatabase = $env:PIM_SqlDatabase,

    [int64]$LastVersion = 0,
    [switch]$WhatIfMode = $true
)

$ErrorActionPreference = 'Stop'
$shared = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared'
. (Join-Path $shared 'PIM-ScenarioProfile.ps1')   # also dot-sources PIM-Downlink.ps1
. (Join-Path $shared 'PIM-Baseline.ps1')

if (-not $SqlServer)   { $SqlServer = '.\SQLEXPRESS' }
if (-not $SqlDatabase) { $SqlDatabase = 'PimPlatform' }
$global:PIM_SqlServer   = $SqlServer
$global:PIM_SqlDatabase = $SqlDatabase
$global:PIM_UseGraphSdk = $false

# resolve the scenario (explicit id, else the active scenario from the store).
$sc = if ("$Scenario".Trim()) { Get-PimScenario -Id $Scenario } else { Get-PimActiveScenario }
if (-not $sc) { throw "could not resolve scenario '$Scenario'." }
$null = Set-PimScenarioContext -Scenario $sc   # apply the runtime knobs

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " PIM4EntraPS §31.3 scenario-run ($($sc.id), $($sc.role)) $(if ($WhatIfMode) { '(WHATIF)' } else { '(LIVE)' })" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# managed scenarios need the signed baseline doc loaded (file or HTTPS pull).
$doc = $null
$run = Get-PimScenarioRunPlan -Scenario $sc
if ($run.runDownlink) {
    if ("$BaselineDocPath".Trim()) {
        if (-not (Test-Path -LiteralPath $BaselineDocPath)) { throw "baseline doc not found: $BaselineDocPath" }
        $raw = Get-Content -LiteralPath $BaselineDocPath -Raw
        $br = $raw.IndexOf('{'); if ($br -gt 0) { $raw = $raw.Substring($br) }
        $doc = $raw | ConvertFrom-Json
    } elseif ("$BaselineUrl".Trim()) {
        $headers = @{ 'x-ms-version' = '2021-08-06' }
        if ("$BaselineAccessToken".Trim()) { $headers['Authorization'] = "Bearer $BaselineAccessToken" }
        $raw = Invoke-RestMethod -Method GET -Uri $BaselineUrl -Headers $headers -ErrorAction Stop
        if ($raw -is [string]) { $br = $raw.IndexOf('{'); if ($br -gt 0) { $raw = $raw.Substring($br) }; $doc = $raw | ConvertFrom-Json }
        else { $doc = $raw }
    } else {
        throw "managed scenario $($sc.id) needs -BaselineDocPath or -BaselineUrl (the signed master baseline)."
    }
}

$result = Invoke-PimScenarioDeploy -Scenario $sc -EngineScope $EngineScope -EngineMode $EngineMode `
    -Doc $doc -TenantId $TenantId -SlaveRing $SlaveRing `
    -CentralRoot $CentralRoot -LocalRoot $LocalRoot -SqlServer $SqlServer -SqlDatabase $SqlDatabase `
    -LastVersion $LastVersion -WhatIfMode:$WhatIfMode

Write-Host ""
$col = if ($result.ok) { 'Green' } else { 'Red' }
Write-Host ("SCENARIO RUN $($result.scenarioId): {0}" -f $(if ($result.ok) { 'OK' } else { 'FAILED' })) -ForegroundColor $col
foreach ($s in @($result.steps)) {
    Write-Host ("  [{0}] {1} -- {2}" -f $(if ($s.ok) { 'OK' } else { 'XX' }), $s.step, $s.detail) -ForegroundColor $(if ($s.ok) { 'DarkGray' } else { 'Red' })
}
$result
if (-not $result.ok) { exit 1 }
