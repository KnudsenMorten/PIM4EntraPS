#Requires -Version 5.1
<#
.SYNOPSIS
    §31.3 Phase-2 -- the ring-gated master->managed (slave) admin/permission SYNC
    (downlink) live wrapper. Thin orchestrator over the PURE core in
    engine/_shared/PIM-Downlink.ps1 (Invoke-PimManagedDownlink).

.DESCRIPTION
    For ONE managed/slave tenant (S5 central-hosted | S6 local-hosted):

      1. PULL the master's SIGNED baseline bundle (HTTPS GET from private-endpoint
         blob storage, OAuth bearer over REST) -- the SAME bundle New-PimBaselineBundle
         publishes. -BaselineDocPath lets the main session feed a locally-pulled
         bundle instead (e.g. when the seeder produced it).
      2. VERIFY it offline (RSA-SHA256 against the embedded PUBLIC baseline cert;
         refuse on bad signature / expiry / anti-rollback) -- pull-not-push trust
         model identical to the offline .pimlicense.
      3. RING-GATE the admin set to admin.Ring <= slave.Ring.
      4. STAGE the per-tenant sync files in the resolved folder (central-msp via
         -CentralRoot / $env:PIM_SyncRootCentral, local-slave via -LocalRoot /
         $env:PIM_SyncRootLocal). Idempotent: only rewrites on content change.
      5. APPLY into the slave by composing Invoke-PimMspFanout -- which authenticates
         per-tenant with the SLAVE's OWN SPN + certificate and CREATES the MSP admins
         IN the slave. The MASTER never writes into the managed tenant.

    PURE decisions live in engine/_shared/PIM-Downlink.ps1 (offline-tested in
    tests/Test-PimDownlink.ps1). This wrapper only gathers facts (pull + read
    registry) and acts. PS 5.1-safe; SPN + certificate only (never interactive,
    never a secret, never device-code).

.PARAMETER Scenario
    'S5' (central-hosted managed) or 'S6' (local-hosted managed).

.PARAMETER TenantId / SlaveRing
    The managed tenant id + its registry ring (default 2 = test).

.PARAMETER BaselineUrl
    HTTPS URL of the master's signed baseline bundle (baseline-latest.json).
    Mutually exclusive with -BaselineDocPath.

.PARAMETER BaselineAccessToken
    Storage bearer token for the pull (minted by the caller over REST/MI).

.PARAMETER BaselineDocPath
    Local path to an already-pulled signed bundle JSON (skips the HTTPS pull).

.PARAMETER CentralRoot / LocalRoot
    Sync-file staging roots (per syncFileLocation). Default from
    $env:PIM_SyncRootCentral / $env:PIM_SyncRootLocal.

.PARAMETER SqlServer / SqlDatabase
    The platform registry the fan-out reads. Default .\SQLEXPRESS / PimPlatform.

.PARAMETER WhatIfMode
    Default ON: verify + stage files + PLAN the fan-out only. -WhatIfMode:$false applies.

.EXAMPLE
    # MAIN SESSION (creds from kv-automatit-dev), S6 local-hosted managed (2linkit):
    $env:PIM_SyncRootLocal = 'C:\ProgramData\PIM4EntraPS\sync'
    .\Invoke-PimDownlinkSync.ps1 -Scenario S6 -TenantId <tenant-id-2linkit> -SlaveRing 2 `
        -BaselineDocPath C:\TMP\baseline-latest.json -WhatIfMode:$false
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('S5','S6')][string]$Scenario,
    [Parameter(Mandatory)][string]$TenantId,
    [ValidateRange(0,2)][int]$SlaveRing = 2,

    [string]$BaselineUrl,
    [string]$BaselineAccessToken,
    [string]$BaselineDocPath,

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

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " PIM4EntraPS §31.3 downlink-sync ($Scenario, tenant $TenantId, ring $SlaveRing) $(if ($WhatIfMode) { '(WHATIF)' } else { '(LIVE)' })" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# 1) obtain the signed baseline bundle (local file OR HTTPS pull).
$doc = $null
if ("$BaselineDocPath".Trim()) {
    if (-not (Test-Path -LiteralPath $BaselineDocPath)) { throw "baseline doc not found: $BaselineDocPath" }
    $raw = Get-Content -LiteralPath $BaselineDocPath -Raw
    $br = $raw.IndexOf('{'); if ($br -gt 0) { $raw = $raw.Substring($br) }
    $doc = $raw | ConvertFrom-Json
    Write-Host "  baseline: loaded from $BaselineDocPath" -ForegroundColor DarkGray
} elseif ("$BaselineUrl".Trim()) {
    $headers = @{ 'x-ms-version' = '2021-08-06' }
    if ("$BaselineAccessToken".Trim()) { $headers['Authorization'] = "Bearer $BaselineAccessToken" }
    $raw = Invoke-RestMethod -Method GET -Uri $BaselineUrl -Headers $headers -ErrorAction Stop
    if ($raw -is [string]) { $br = $raw.IndexOf('{'); if ($br -gt 0) { $raw = $raw.Substring($br) }; $doc = $raw | ConvertFrom-Json }
    else { $doc = $raw }
    Write-Host "  baseline: pulled from $BaselineUrl" -ForegroundColor DarkGray
} else {
    throw 'supply -BaselineDocPath (local) or -BaselineUrl (HTTPS pull) for the signed baseline.'
}

# 2-5) verify + ring-filter + stage + apply via the orchestrator (prod cert path:
# no -PublicKey -> Invoke-PimManagedDownlink uses the embedded baseline cert).
$result = Invoke-PimManagedDownlink -Scenario $Scenario -Doc $doc `
    -TenantId $TenantId -SlaveRing $SlaveRing `
    -CentralRoot $CentralRoot -LocalRoot $LocalRoot `
    -SqlServer $SqlServer -SqlDatabase $SqlDatabase `
    -LastVersion $LastVersion -WhatIfMode:$WhatIfMode

Write-Host ""
if ($result.ok) {
    Write-Host "DOWNLINK $(if ($WhatIfMode) { 'PLANNED' } else { 'APPLIED' }): $($result.reason)" -ForegroundColor Green
    Write-Host ("  staged files: {0}" -f (@($result.staged | ForEach-Object { "$($_.action):$([System.IO.Path]::GetFileName($_.file))" }) -join ', ')) -ForegroundColor DarkGray
} else {
    Write-Host "DOWNLINK FAILED: $($result.reason)" -ForegroundColor Red
}
$result
if (-not $result.ok) { exit 1 }
