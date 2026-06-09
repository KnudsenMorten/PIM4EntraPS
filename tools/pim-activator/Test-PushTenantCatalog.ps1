#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end test of the PIM Activator tenant-catalog Intune push for the
    CURRENTLY-CONNECTED Entra tenant. Auto-discovers the PIM Activator app
    reg appId, builds a 1-entry catalog, and POSTs the Intune Custom
    Configuration Profile (OMA-URI / Registry CSP).

.DESCRIPTION
    Designed for the MSP admin's first test in their own tenant. Auto-
    discovery only -- no manual paste needed. After the test you'll have:

      1. An Intune profile `[PimActivator] Tenant catalog (chrome.storage.managed)`
         visible at Devices > Configuration profiles.
      2. A 1-entry catalog containing the connected tenant's PIM Activator
         app reg.

    Add more customer entries later by editing sample-tenant-catalog.json
    and re-running Push-PimActivatorTenantCatalogIntune.ps1 directly.

.NOTES
    Required Graph scopes (delegated):
      - Organization.Read.All
      - Application.Read.All
      - DeviceManagementConfiguration.ReadWrite.All
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---- 1. Connect Graph -----------------------------------------------------
$_scopes = @(
    'Organization.Read.All'
    'Application.Read.All'
    'DeviceManagementConfiguration.ReadWrite.All'
)
Import-Module Microsoft.Graph.Authentication              -ErrorAction Stop
Import-Module Microsoft.Graph.Applications                -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop

$ctx = Get-MgContext -ErrorAction SilentlyContinue
$missing = if ($ctx) { $_scopes | Where-Object { $_ -notin $ctx.Scopes } } else { $_scopes }
if (-not $ctx -or $missing) {
    Write-Host "Connecting to Microsoft Graph (scopes: $($_scopes -join ', '))..." -ForegroundColor Yellow
    if ($ctx) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
    Connect-MgGraph -Scopes $_scopes -NoWelcome -ErrorAction Stop
    $ctx = Get-MgContext
}
Write-Host "[OK] Connected to tenant $($ctx.TenantId) as $($ctx.Account)" -ForegroundColor Green

# ---- 2. Discover tenant name ----------------------------------------------
$org = Get-MgOrganization -ErrorAction Stop
$tenantId   = $ctx.TenantId
$tenantName = $org.DisplayName
Write-Host "Tenant:    $tenantName ($tenantId)" -ForegroundColor Cyan

# ---- 3. Discover PIM Activator app reg ------------------------------------
# Try the App Registration object first (Get-MgApplication). Some Graph SDK
# versions drop AppId / DisplayName from the default projection on $filter
# queries, so request the fields explicitly. Fall back to ServicePrincipal
# search if no App reg is found (e.g. the customer-tenant SPN was created
# via consent of an app reg owned in a different tenant).
function _SearchByDisplayName {
    param([string]$Pattern)
    $hits = @()
    try {
        # 1. App Registrations (Application)
        $apps = Get-MgApplication `
            -Filter "startswith(displayName,'$Pattern')" `
            -Property 'id,appId,displayName' `
            -ConsistencyLevel eventual `
            -CountVariable c `
            -ErrorAction Stop
        if ($apps) {
            foreach ($a in $apps) {
                $hits += [pscustomobject]@{
                    Source      = 'Application'
                    DisplayName = $a.DisplayName
                    AppId       = $a.AppId
                    ObjectId    = $a.Id
                }
            }
        }
    } catch {
        Write-Warning "Get-MgApplication failed: $($_.Exception.Message). Falling back to ServicePrincipal."
    }
    if ($hits.Count -eq 0) {
        try {
            # 2. Service Principals (the runtime side; works even when the
            #    Application object lives in a different tenant).
            $sps = Get-MgServicePrincipal `
                -Filter "startswith(displayName,'$Pattern')" `
                -Property 'id,appId,displayName' `
                -ConsistencyLevel eventual `
                -CountVariable c2 `
                -ErrorAction Stop
            if ($sps) {
                foreach ($s in $sps) {
                    $hits += [pscustomobject]@{
                        Source      = 'ServicePrincipal'
                        DisplayName = $s.DisplayName
                        AppId       = $s.AppId
                        ObjectId    = $s.Id
                    }
                }
            }
        } catch {
            Write-Warning "Get-MgServicePrincipal failed: $($_.Exception.Message)."
        }
    }
    return $hits
}

Write-Host "Searching app registrations + service principals for displayName starting with 'PIM Activator'..." -ForegroundColor Cyan
$hits = _SearchByDisplayName -Pattern 'PIM Activator'
$valid = $hits | Where-Object { $_.AppId -and $_.AppId -ne '00000000-0000-0000-0000-000000000000' }
if (-not $valid -or $valid.Count -eq 0) {
    if ($hits.Count -gt 0) {
        Write-Warning "Found object(s) but AppId is blank -- usually means the directory has a deleted/orphaned entry."
        $hits | ForEach-Object { Write-Warning "  $($_.Source): displayName='$($_.DisplayName)' appId='$($_.AppId)' objectId='$($_.ObjectId)'" }
    }
    throw "No usable 'PIM Activator*' app reg / SPN found in tenant '$tenantName'. Run Deploy-PimActivatorBackend.ps1 first (creates the per-tenant app reg), then re-run this test."
}
if ($valid.Count -gt 1) {
    Write-Warning "Multiple PIM Activator entries found:"
    $valid | ForEach-Object { Write-Warning "  $($_.Source): $($_.DisplayName)  (appId $($_.AppId))" }
    Write-Warning "Using the first match -- edit the catalog manually if that's wrong."
}
$picked   = $valid[0]
$clientId = $picked.AppId
Write-Host "App reg:   $($picked.DisplayName) (appId $clientId; source $($picked.Source))" -ForegroundColor Cyan

# ---- 4. Build catalog JSON -----------------------------------------------
$catalog = @(
    [ordered]@{
        name                 = $tenantName
        tenantId             = $tenantId
        clientId             = $clientId
        defaultJustification = 'Change in infrastructure'
        defaultDurationHours = 8
        prefix               = 'PIM-'
        entraPrefix          = @('PIM-Entra','PIM-AAD')
        azurePrefix          = @('PIM-Azure','PIM-AzRes')
    }
)
$catalogPath = Join-Path $scriptDir 'discovered-tenant-catalog.json'
($catalog | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $catalogPath -Encoding UTF8
Write-Host "[OK] Catalog written to $catalogPath" -ForegroundColor Green
Get-Content $catalogPath

# ---- 5. Hand off to the push script --------------------------------------
$pushScript = Join-Path $scriptDir 'Push-PimActivatorTenantCatalogIntune.ps1'
Write-Host ""
Write-Host "Handing off to $pushScript..." -ForegroundColor Yellow
& $pushScript -CatalogJsonPath $catalogPath
