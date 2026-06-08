#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Create / update an Intune PowerShell script (deviceManagementScripts)
    that pushes the PIM Activator tenant catalog to every targeted Windows
    device by writing the registry value the extension reads via
    chrome.storage.managed.tenantCatalog.

.DESCRIPTION
    The PIM Activator extension v1.6.0+ reads its tenant catalog via
    chrome.storage.managed.tenantCatalog. Chromium populates that from:
        HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<extId>\policy\tenantCatalog
        HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<extId>\policy\tenantCatalog

    HISTORY (why not Registry CSP / Custom OMA-URI?):
    Earlier versions of this script used Registry CSP via Custom
    Configuration Profile (./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/...).
    That approach FAILS with error 0x87d1fde8 because Edge owns the
    SOFTWARE\Policies\Microsoft\Edge\* ADMX namespace and Microsoft blocks
    Registry CSP from writing under it. Settings Catalog "Configure managed
    extensions" controls install behavior but does NOT carry per-extension
    chrome.storage.managed data. ADMX template ingestion would work but
    needs a custom ADMX file maintained per release.

    PowerShell remediation is the documented reliable path -- the script
    runs as SYSTEM on each Intune-managed device, writes the registry
    directly, no CSP restrictions apply.

    Idempotent. Lookup by display name, PATCH if found, POST if new.

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
    Display name of the Intune script policy. Default:
    '[PimActivator] Push tenant catalog (chrome.storage.managed)'.

.PARAMETER ExtensionId
    Chrome/Edge extension id. Default 'eheocihmlppcophaeakmdenhgcookkab'.

.PARAMETER Browser
    'Both' (default), 'Edge', or 'Chrome'. Picks which browser root the
    on-device script writes to.

.PARAMETER RemoveLegacyOmaUriProfile
    If set, also DELETES the v2.4.90's failed-by-design Custom Configuration
    Profile (display name '[PimActivator] Tenant catalog (chrome.storage.managed)').
    Use once when migrating from the Registry-CSP approach to PS remediation.

.PARAMETER Remove
    Delete the script policy. Idempotent.

.EXAMPLE
    .\Push-PimActivatorTenantCatalogIntune.ps1 -CatalogJsonPath .\my-tenants.json

.EXAMPLE
    # First migration -- also kills the old failing OMA-URI profile:
    .\Push-PimActivatorTenantCatalogIntune.ps1 -CatalogJsonPath .\my-tenants.json -RemoveLegacyOmaUriProfile

.EXAMPLE
    .\Push-PimActivatorTenantCatalogIntune.ps1 -Remove

.NOTES
    Required Graph scopes (delegated):
      - DeviceManagementConfiguration.ReadWrite.All
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Install')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CatalogJsonPath,

    [Parameter()]
    [string]$DisplayName = '[PimActivator] Push tenant catalog (chrome.storage.managed)',

    [Parameter()]
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId = 'eheocihmlppcophaeakmdenhgcookkab',

    [Parameter()]
    [ValidateSet('Both','Edge','Chrome')]
    [string]$Browser = 'Both',

    [Parameter(ParameterSetName = 'Install')]
    [switch]$RemoveLegacyOmaUriProfile,

    [Parameter(Mandatory, ParameterSetName = 'Uninstall')]
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

# ---- 1. Graph context -----------------------------------------------------
$_requiredScopes = @('DeviceManagementConfiguration.ReadWrite.All')
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

# ---- 1a. (Optional) clean up the legacy Registry-CSP profile -------------
if ($RemoveLegacyOmaUriProfile) {
    $legacyName = '[PimActivator] Tenant catalog (chrome.storage.managed)'
    Write-Host "Looking for legacy Registry-CSP profile '$legacyName'..." -ForegroundColor Cyan
    try {
        $legacyResp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=displayName eq '$legacyName'" `
            -ErrorAction Stop
        if ($legacyResp.value -and $legacyResp.value.Count -gt 0) {
            foreach ($p in $legacyResp.value) {
                Write-Host "  Deleting legacy profile id $($p.id)..." -ForegroundColor Yellow
                Invoke-MgGraphRequest -Method DELETE `
                    -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($p.id)" `
                    -ErrorAction Stop | Out-Null
            }
            Write-Host "[OK] Legacy Registry-CSP profile(s) removed." -ForegroundColor Green
        } else {
            Write-Host "  No legacy profile found (already clean)." -ForegroundColor Gray
        }
    } catch {
        Write-Warning "Legacy profile cleanup failed: $($_.Exception.Message). Continuing."
    }
}

# ---- 2. Lookup existing script by display name ---------------------------
$listUri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?`$filter=displayName eq '$DisplayName'"
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
        Write-Host "Removing existing script '$DisplayName' (id $($existing.id))..." -ForegroundColor Yellow
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($existing.id)" -ErrorAction Stop | Out-Null
        Write-Host "[OK] Removed." -ForegroundColor Green
    } else {
        Write-Host "Nothing to remove -- no script named '$DisplayName' in tenant $($ctx.TenantId)." -ForegroundColor Gray
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
if ($count -eq 0) { throw "Catalog JSON is an empty array." }
foreach ($entry in $catalog) {
    if (-not $entry.name)     { throw "Catalog entry missing 'name'." }
    if (-not $entry.tenantId) { throw "Catalog entry '$($entry.name)' missing 'tenantId'." }
    if (-not $entry.clientId) { throw "Catalog entry '$($entry.name)' missing 'clientId'." }
}
$minifiedCatalog = ConvertTo-Json -InputObject @($catalog) -Depth 10 -Compress

Write-Host "Catalog loaded: $count tenant(s) -- $((($catalog | ForEach-Object name) -join ', '))" -ForegroundColor Cyan

# ---- 4. Build the on-device PowerShell script body -----------------------
$browsersToInclude = switch ($Browser) {
    'Both'   { @('Edge','Chrome') }
    'Edge'   { @('Edge') }
    'Chrome' { @('Chrome') }
}
$pathList = foreach ($b in $browsersToInclude) {
    switch ($b) {
        'Edge'   { "HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$ExtensionId\policy" }
        'Chrome' { "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$ExtensionId\policy" }
    }
}
$pathArrayLiteral = '@(' + (($pathList | ForEach-Object { "'$_'" }) -join ',') + ')'

# Runs as SYSTEM on the endpoint. Uses a single-quoted here-string for the
# catalog JSON so embedded quotes don't break the script. Idempotent on the
# device too -- existing value gets overwritten with the new content.
$scriptBody = @"
# Generated by Push-PimActivatorTenantCatalogIntune.ps1 -- PIM4EntraPS
`$ErrorActionPreference = 'Stop'
`$paths = $pathArrayLiteral
`$value = @'
$minifiedCatalog
'@
foreach (`$p in `$paths) {
    if (-not (Test-Path `$p)) { New-Item -Path `$p -Force | Out-Null }
    New-ItemProperty -Path `$p -Name 'tenantCatalog' -Value `$value -PropertyType String -Force | Out-Null
    Write-Output "Wrote `$(`$value.Length) chars to `$p\tenantCatalog"
}
exit 0
"@

$scriptBytes  = [System.Text.Encoding]::UTF8.GetBytes($scriptBody)
$scriptBase64 = [Convert]::ToBase64String($scriptBytes)

$bodyHashtable = @{
    '@odata.type'         = '#microsoft.graph.deviceManagementScript'
    displayName           = $DisplayName
    description           = "[PimActivator] Writes the tenant catalog ($count tenant(s)) to HKLM Edge + Chrome 3rdparty extension policy registry so the PIM Activator extension reads it via chrome.storage.managed.tenantCatalog. Generated by PIM4EntraPS/tools/pim-activator/Push-PimActivatorTenantCatalogIntune.ps1."
    runAsAccount          = 'system'
    enforceSignatureCheck = $false
    fileName              = 'Push-PimActivatorTenantCatalog.ps1'
    runAs32Bit            = $false
    scriptContent         = $scriptBase64
}
$body = $bodyHashtable | ConvertTo-Json -Depth 20

# ---- 5. Create or update ---------------------------------------------------
if ($existing) {
    Write-Host "Script '$DisplayName' exists (id $($existing.id)). PATCHing body..." -ForegroundColor Cyan
    Invoke-MgGraphRequest -Method PATCH `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($existing.id)" `
        -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
    $scriptId = $existing.id
    Write-Host "[OK] Script updated. id=$scriptId  tenants=$count  browsers=$($browsersToInclude -join '+')" -ForegroundColor Green
} else {
    Write-Host "Creating script '$DisplayName'..." -ForegroundColor Cyan
    $created = Invoke-MgGraphRequest -Method POST `
        -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts' `
        -Body $body -ContentType 'application/json' -ErrorAction Stop
    $scriptId = $created.id
    Write-Host "[OK] Script created. id=$scriptId  tenants=$count  browsers=$($browsersToInclude -join '+')" -ForegroundColor Green
}

Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Intune admin center -> Devices -> Scripts and remediations -> Platform scripts ->" -ForegroundColor Yellow
Write-Host "     '$DisplayName' -> Assignments -> assign to your MSP-admin device group." -ForegroundColor Yellow
Write-Host "  2. Wait for next Intune sync (~8h, or force from device)." -ForegroundColor Yellow
Write-Host "  3. Verify on a target device:" -ForegroundColor Yellow
Write-Host "       Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$ExtensionId\policy' -Name tenantCatalog" -ForegroundColor Gray
Write-Host "  4. PIM Activator extension reads it via chrome.storage.managed.tenantCatalog on next popup load." -ForegroundColor Yellow
Write-Host ""
Write-Host "Done." -ForegroundColor Green
