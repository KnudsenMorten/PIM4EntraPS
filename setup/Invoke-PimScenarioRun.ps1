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

    # BUG-84: fallback TAP delivery address for synced admins. The AdminTap guard refuses to mint a
    # credential it cannot deliver, so without this a pull creates admin accounts that nobody can
    # sign in as. Per-admin ManagerEmail from the bundle still wins; absent => the guard still
    # refuses, which stays the correct behaviour rather than a silent downgrade.
    [string]$DefaultManagerEmail = $env:PIM_DefaultManagerEmail,

    [int64]$LastVersion = 0,
    [switch]$WhatIfMode = $true
)

$ErrorActionPreference = 'Stop'
$shared = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared'
. (Join-Path $shared 'PIM-ScenarioProfile.ps1')   # also dot-sources PIM-Downlink.ps1
. (Join-Path $shared 'PIM-Baseline.ps1')
# 🔴 BUG-80 -- THE TOKEN PROVIDER WAS MISSING HERE, AND ITS ABSENCE IS SILENT BY DESIGN.
# New-PimSqlConnection acquires a token only `if (Get-Command Get-PimRestToken ...)`, so a caller
# that loads PIM-SqlStore (via PIM-Downlink) WITHOUT PIM-Rest skips token acquisition entirely,
# presents no credential, and Azure SQL answers `Login failed for user ''`. BUG-33 wrote that
# signature down -- "the common cause is not 'auth failed' but 'the token provider was never
# loaded'" -- and this runner was doing exactly that.
# MEASURED on the greenfield slave 2026-08-27: with the slave store finally wired (BUG-79), the
# downlink's own reads failed as
#     [downlink] roles: could not read PIM-Assignments-Admins from the slave store:
#                "Login failed for user ''."
# while the ENGINE -- a separate process that does load PIM-Rest -- reached the same database
# perfectly well in the same run. That split is the tell: same store, same identity, two processes,
# one of them missing a dot-source.
# PIM-AccountRest.ps1 provides Get-PimRestDefaultDomain, which the local-slave path needs to
# resolve the managed tenant's UPN domain (IMP-12 / BUG-81). It is loaded here rather than probed
# for, because the probe was `Get-Command ... -ErrorAction SilentlyContinue` and a missing module
# therefore SKIPPED the resolution without a word -- so the downlink kept refusing to stage admins
# and the reason ("no ambient tenant to read it from") pointed away from the real cause. That is
# the recorded trap: a Get-Command-guarded optional dependency turns a missing file into silently
# skipped behaviour, not a visible error.
foreach ($__dep in @('PIM-Rest.ps1','PIM-SqlStore.ps1','PIM-AccountRest.ps1')) {
    $__p = Join-Path $shared $__dep
    if (-not (Test-Path -LiteralPath $__p)) { throw "required by the downlink's own store reads and not found: $__p" }
    . $__p
}

# 🔴 BUG-83 -- THIS PROCESS HAD NO IDENTITY, SO IT SILENTLY BECAME THE MANAGED IDENTITY.
# Get-PimRestToken takes the MI branch when `$env:IDENTITY_ENDPOINT` is set AND there is no client
# id. This runner set neither $global:PIM_ClientId nor $global:PIM_TenantId, so every Graph call it
# makes -- including the default-domain lookup the local-slave path depends on -- authenticated as
# the container's managed identity instead of the engine SPN.
# MEASURED on the greenfield slave 2026-08-27, and the comparison is the proof: the SAME
# /domains call, with the SAME grant, succeeded from mgmt1 as the engine SPN at 15:16:12 and
# returned 403 from the container 35 seconds later. Not propagation -- a different identity. The
# MI holds ZERO Graph app-roles; the engine SPN holds 100. The ENGINE, a separate process that
# reads these from env, authenticates correctly and prints "Auth : SPN a399691f..." in the same run.
# Same family as BUG-80: the runner process lacked what the engine process had, and the gap showed
# up as a permissions error pointing at the wrong principal.
# The SECRET is deliberately not set here: Get-PimRestToken reads $env:AZURE_CLIENT_SECRET itself,
# so the credential never has to be copied into a global.
if ($env:PIM_TenantId -and -not $global:PIM_TenantId) { $global:PIM_TenantId = "$($env:PIM_TenantId)".Trim() }
if ($env:PIM_ClientId -and -not $global:PIM_ClientId) {
    $global:PIM_ClientId = "$($env:PIM_ClientId)".Trim()
    Write-Host "[scenario-run] identity: engine SPN $($global:PIM_ClientId) (Graph calls in THIS process, not the container's managed identity)" -ForegroundColor DarkGray
} elseif ($env:IDENTITY_ENDPOINT) {
    Write-Host '[scenario-run] identity: no PIM_ClientId -- Graph calls in this process will use the MANAGED IDENTITY, which may hold no app-roles.' -ForegroundColor Yellow
}

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
    -LastVersion $LastVersion -DefaultManagerEmail $DefaultManagerEmail -WhatIfMode:$WhatIfMode

Write-Host ""
$col = if ($result.ok) { 'Green' } else { 'Red' }
Write-Host ("SCENARIO RUN $($result.scenarioId): {0}" -f $(if ($result.ok) { 'OK' } else { 'FAILED' })) -ForegroundColor $col
foreach ($s in @($result.steps)) {
    Write-Host ("  [{0}] {1} -- {2}" -f $(if ($s.ok) { 'OK' } else { 'XX' }), $s.step, $s.detail) -ForegroundColor $(if ($s.ok) { 'DarkGray' } else { 'Red' })
}
$result
if (-not $result.ok) { exit 1 }
