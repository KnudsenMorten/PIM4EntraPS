#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Create / update an Intune Configuration Profile (Custom OMA-URI / Registry
    CSP) that pushes the PIM Activator tenant catalog to every Intune-managed
    Windows device. Native Intune policy -- continuously enforced. No
    PowerShell remediation script in the loop.

.DESCRIPTION
    The PIM Activator extension v1.6.0+ reads its tenant catalog via
    chrome.storage.managed.tenantCatalog. Chromium populates that from the
    registry path:
        HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<extId>\policy\tenantCatalog
    (and the same path under Google\Chrome for Chrome users).

    Intune Settings Catalog does NOT expose this path for arbitrary
    extensions (no ADMX template exists for self-hosted CRXs). The two
    standard ways to push to it are:

      1. Custom Configuration Profile + OMA-URI + Registry CSP  <-- this script
      2. PowerShell remediation that does a Set-ItemProperty

    This script uses option 1: creates / updates a single
    windowsCustomConfiguration with one omaSetting per browser (Edge +
    Chrome), value = the JSON-encoded catalog. Intune writes the registry
    value on every sync and re-enforces if anything overwrites it.

    Idempotent. Looks up by display name, PATCHes if found, POSTs if new.

.PARAMETER CatalogJsonPath
    Path to a JSON file containing the tenant catalog array. Required.

    Schema (each array element):
      {
        "name":        "Contoso",                       (required)
        "tenantId":    "<GUID>",                        (required)
        "clientId":    "<GUID>",                        (required)
        "prefix":      "PIM-",                          (optional)
        "entraPrefix": ["PIM-Entra","PIM-AAD"],         (optional, str or str[])
        "azurePrefix": ["PIM-Azure","PIM-AzRes"]        (optional, str or str[])
      }

.PARAMETER DisplayName
    Display name of the Intune profile. Default:
    '[PimActivator] Tenant catalog (chrome.storage.managed)'.

.PARAMETER ExtensionId
    Chrome/Edge extension id. Default 'eheocihmlppcophaeakmdenhgcookkab'.

.PARAMETER Browser
    'Both' (default), 'Edge', or 'Chrome'. Picks which browser the policy
    targets. Each browser gets its own OMA-URI line in the profile.

.PARAMETER AssignToGroupId
    Optional Entra group object id to assign the profile to. Without it the
    profile is created but unassigned (assign later in portal).

.PARAMETER Remove
    Delete the profile. Idempotent.

.EXAMPLE
    .\Push-PimActivatorTenantCatalogIntune.ps1 -CatalogJsonPath .\my-tenants.json

.EXAMPLE
    .\Push-PimActivatorTenantCatalogIntune.ps1 -Remove

.NOTES
    Required Graph scopes (delegated):
      - DeviceManagementConfiguration.ReadWrite.All
      - Group.Read.All (only when -AssignToGroupId is passed)
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Install')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CatalogJsonPath,

    [Parameter()]
    [string]$DisplayName = '[PimActivator] Tenant catalog (chrome.storage.managed)',

    [Parameter()]
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId = 'eheocihmlppcophaeakmdenhgcookkab',

    [Parameter()]
    [ValidateSet('Both','Edge','Chrome')]
    [string]$Browser = 'Both',

    [Parameter(ParameterSetName = 'Install')]
    [string]$AssignToGroupId,

    [Parameter(Mandatory, ParameterSetName = 'Uninstall')]
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

# ---- 1. Graph context -----------------------------------------------------
$_requiredScopes = @('DeviceManagementConfiguration.ReadWrite.All')
if ($AssignToGroupId) { $_requiredScopes += 'Group.Read.All' }
$ctx = Get-MgContext -ErrorAction SilentlyContinue
if (-not $ctx) {
    Write-Host "Not connected to Microsoft Graph. Launching interactive sign-in (scopes: $($_requiredScopes -join ', '))..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes $_requiredScopes -NoWelcome -ErrorAction Stop
    $ctx = Get-MgContext
}
$missingScopes = $_requiredScopes | Where-Object { $_ -notin $ctx.Scopes }
if ($missingScopes) {
    Write-Host "Re-connecting Graph to include missing scope(s): $($missingScopes -join ', ')" -ForegroundColor Yellow
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Connect-MgGraph -Scopes $_requiredScopes -NoWelcome -ErrorAction Stop
    $ctx = Get-MgContext
}
Write-Host "Connected to tenant $($ctx.TenantId) as $($ctx.Account)" -ForegroundColor Gray

# ---- 2. Lookup existing profile by display name ---------------------------
$listUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=displayName eq '$DisplayName'"
$existing = $null
try {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $listUri -ErrorAction Stop
    if ($resp.value -and $resp.value.Count -gt 0) {
        $existing = $resp.value[0]
    }
} catch {
    Write-Warning "Lookup failed (will attempt POST): $($_.Exception.Message)"
}

if ($Remove) {
    if ($existing) {
        Write-Host "Removing existing profile '$DisplayName' (id $($existing.id))..." -ForegroundColor Yellow
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($existing.id)" -ErrorAction Stop | Out-Null
        Write-Host "[OK] Removed." -ForegroundColor Green
    } else {
        Write-Host "Nothing to remove -- no profile named '$DisplayName' in tenant $($ctx.TenantId)." -ForegroundColor Gray
    }
    return
}

# ---- 3. Read + validate the catalog JSON ----------------------------------
$catalogJson = Get-Content -LiteralPath $CatalogJsonPath -Raw -Encoding UTF8
try {
    $catalog = $catalogJson | ConvertFrom-Json
} catch {
    throw "Could not parse '$CatalogJsonPath' as JSON: $($_.Exception.Message)"
}
$count = @($catalog).Count
if ($count -eq 0) {
    throw "Catalog JSON is an empty array."
}
foreach ($entry in $catalog) {
    if (-not $entry.name)     { throw "Catalog entry missing 'name'." }
    if (-not $entry.tenantId) { throw "Catalog entry '$($entry.name)' missing 'tenantId'." }
    if (-not $entry.clientId) { throw "Catalog entry '$($entry.name)' missing 'clientId'." }
}
# Minify so the OMA-URI value is compact (Intune has a per-value-length budget).
$minifiedCatalog = ($catalog | ConvertTo-Json -Depth 10 -Compress)

Write-Host "Catalog loaded: $count tenant(s) -- $((($catalog | ForEach-Object name) -join ', '))" -ForegroundColor Cyan

# ---- 4. Build OMA-URI settings per browser -------------------------------
# Registry CSP namespace: ./Device/Vendor/MSFT/Registry/HKLM/<keypath>/<valuename>
# For Chromium 3rdparty extension policy, the key path is:
#   SOFTWARE\Policies\<vendor>\<browser>\3rdparty\extensions\<extId>\policy
# Each value under that key becomes a chrome.storage.managed property in
# the extension's MV3 service worker context.
$browsersToInclude = switch ($Browser) {
    'Both'   { @('Edge','Chrome') }
    'Edge'   { @('Edge') }
    'Chrome' { @('Chrome') }
}
$browserPaths = @{
    Edge   = "Microsoft/Edge"
    Chrome = "Google/Chrome"
}
$omaSettings = foreach ($b in $browsersToInclude) {
    $vendor = $browserPaths[$b]
    @{
        '@odata.type' = '#microsoft.graph.omaSettingString'
        displayName   = "tenantCatalog ($b)"
        description   = "Writes HKLM\SOFTWARE\Policies\$vendor\3rdparty\extensions\$ExtensionId\policy\tenantCatalog ($count tenant(s)) for the PIM Activator extension to read via chrome.storage.managed."
        omaUri        = "./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/$vendor/3rdparty/extensions/$ExtensionId/policy/tenantCatalog"
        value         = $minifiedCatalog
    }
}

# ---- 5. Build profile body -----------------------------------------------
$bodyHashtable = @{
    '@odata.type'    = '#microsoft.graph.windows10CustomConfiguration'
    displayName      = $DisplayName
    description      = "[PimActivator] Pushes the tenant catalog ($count tenant(s)) to HKLM Edge + Chrome 3rdparty extension policy registry via Registry CSP. PIM Activator extension reads via chrome.storage.managed.tenantCatalog. Generated by PIM4EntraPS/tools/pim-activator/Push-PimActivatorTenantCatalogIntune.ps1."
    roleScopeTagIds  = @('0')
    omaSettings      = @($omaSettings)
}
$body = $bodyHashtable | ConvertTo-Json -Depth 20

# ---- 6. Create or update --------------------------------------------------
if ($existing) {
    Write-Host "Profile '$DisplayName' exists (id $($existing.id)). PATCHing settings..." -ForegroundColor Cyan
    Invoke-MgGraphRequest -Method PATCH `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($existing.id)" `
        -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
    $profileId = $existing.id
    Write-Host "[OK] Profile updated. id=$profileId  tenants=$count  browsers=$($browsersToInclude -join '+')" -ForegroundColor Green
} else {
    Write-Host "Creating profile '$DisplayName'..." -ForegroundColor Cyan
    $created = Invoke-MgGraphRequest -Method POST `
        -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations' `
        -Body $body -ContentType 'application/json' -ErrorAction Stop
    $profileId = $created.id
    Write-Host "[OK] Profile created. id=$profileId  tenants=$count  browsers=$($browsersToInclude -join '+')" -ForegroundColor Green
}

# ---- 7. Optional assignment ----------------------------------------------
if ($AssignToGroupId) {
    Write-Host ""
    Write-Host "Assigning profile to group $AssignToGroupId ..." -ForegroundColor Cyan
    $assignBody = @{
        assignments = @(
            @{
                target = @{
                    '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                    groupId       = $AssignToGroupId
                }
            }
        )
    } | ConvertTo-Json -Depth 10
    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$profileId/assign" `
        -Body $assignBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
    Write-Host "[OK] Assignment created." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Profile is UNASSIGNED. Assign in portal:" -ForegroundColor Yellow
    Write-Host "  Intune admin center -> Devices -> Configuration profiles -> '$DisplayName' -> Assignments" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done. Targeted devices receive the policy on next Intune sync (~8h, or force from device)." -ForegroundColor Green
Write-Host ""
Write-Host "Verify on a target device (as admin) after sync:" -ForegroundColor Gray
Write-Host "  Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$ExtensionId\policy' -Name tenantCatalog" -ForegroundColor Gray
