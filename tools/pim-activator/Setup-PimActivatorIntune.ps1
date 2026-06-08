#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    ONE-stop Intune setup for the PIM Activator browser extension. Creates a
    single Group Policy Configuration profile carrying ALL three policies
    per browser:

      1. ExtensionInstallForcelist  -- force-install the extension from
                                       gh-pages CRX update URL
      2. ExtensionInstallSources    -- whitelist the gh-pages host for
                                       self-hosted CRX installation
      3. TenantCatalog              -- push the tenant catalog JSON for
                                       chrome.storage.managed (uses our
                                       ingested ADMX template)

    After this script runs, the operator's only remaining manual step is
    assigning the profile to a device group. Customer endpoints sync, get
    the policies, install the extension, and read the tenant catalog --
    zero further intervention.

.DESCRIPTION
    Prerequisite: Push-PimActivatorADMXToIntune.ps1 must have been run
    once in this tenant (uploads the custom ADMX exposing TenantCatalog
    as a Group Policy definition).

    Idempotent: lookup by display name, PATCH existing in-place (wipes
    prior definitionValues + posts fresh).

.PARAMETER CatalogJsonPath
    Path to a JSON file containing the tenant catalog array. Required.

.PARAMETER DisplayName
    Display name of the unified Configuration Profile. Default:
    '[PimActivator] All-in-one (forcelist + sources + tenant catalog)'.

.PARAMETER ExtensionId
    Chrome/Edge extension id. Default 'eheocihmlppcophaeakmdenhgcookkab'.

.PARAMETER UpdateUrl
    Self-hosted updates.xml URL. Default
    'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml'.

.PARAMETER SourcePattern
    URL pattern for ExtensionInstallSources. Default
    'https://knudsenmorten.github.io/*'.

.PARAMETER Browser
    'Both' (default), 'Edge', or 'Chrome'.

.PARAMETER AssignToGroupId
    Optional Entra group object id to assign the profile to.

.PARAMETER Remove
    Delete the profile. Idempotent.

.EXAMPLE
    .\Setup-PimActivatorIntune.ps1 -CatalogJsonPath .\discovered-tenant-catalog.json

.EXAMPLE
    .\Setup-PimActivatorIntune.ps1 -CatalogJsonPath .\discovered-tenant-catalog.json -AssignToGroupId 11111111-2222-3333-4444-555555555555

.EXAMPLE
    .\Setup-PimActivatorIntune.ps1 -Remove

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
    [string]$DisplayName = '[PimActivator] All-in-one (forcelist + sources + tenant catalog)',

    [Parameter()]
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId = 'eheocihmlppcophaeakmdenhgcookkab',

    [Parameter()]
    [string]$UpdateUrl = 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml',

    [Parameter()]
    [string]$SourcePattern = 'https://knudsenmorten.github.io/*',

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

# ---- 2. Lookup existing Configuration Profile by display name -----------
$listUri  = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?`$filter=displayName eq '$DisplayName'"
$existing = $null
try {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $listUri -ErrorAction Stop
    if ($resp.value -and $resp.value.Count -gt 0) { $existing = $resp.value[0] }
} catch {
    Write-Warning "Lookup failed (will attempt POST): $($_.Exception.Message)"
}

if ($Remove) {
    if ($existing) {
        Write-Host "Removing existing profile '$DisplayName' (id $($existing.id))..." -ForegroundColor Yellow
        Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($existing.id)" -ErrorAction Stop | Out-Null
        Write-Host "[OK] Removed." -ForegroundColor Green
    } else {
        Write-Host "Nothing to remove -- no profile named '$DisplayName' in tenant $($ctx.TenantId)." -ForegroundColor Gray
    }
    return
}

# ---- 3. Helper: look up policy by displayName + categoryPath + machine class
function Find-PolicyDef {
    param([string]$DisplayNameLike, [string]$CategoryPath)
    $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=categoryPath eq '$CategoryPath'&`$top=999"
    $r = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    $hit = $r.value | Where-Object { $_.classType -eq 'machine' -and $_.displayName -eq $DisplayNameLike } | Select-Object -First 1
    if (-not $hit) {
        $hit = $r.value | Where-Object { $_.classType -eq 'machine' -and $_.displayName -match [regex]::Escape($DisplayNameLike) } | Select-Object -First 1
    }
    return $hit
}

function Get-Presentations {
    param([string]$DefinitionId)
    $r = Invoke-MgGraphRequest -Method GET `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions/$DefinitionId/presentations" `
        -ErrorAction Stop
    return @($r.value)
}

# ---- 4. Read + validate the catalog JSON --------------------------------
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
# PS 5.1's ConvertTo-Json drops the outer array brackets when piped a
# single-element array (PS 7+ has -AsArray to override; 5.1 doesn't).
# Use -InputObject + @($catalog) to force ConvertTo-Json to see the value
# as an array, so the JSON always emits [{...}, ...] not {...}.
$minifiedCatalog = ConvertTo-Json -InputObject @($catalog) -Depth 10 -Compress
Write-Host "Catalog loaded: $count tenant(s) -- $((($catalog | ForEach-Object name) -join ', '))" -ForegroundColor Cyan

$forcelistValue = "$ExtensionId;$UpdateUrl"
Write-Host "Forcelist:     $forcelistValue" -ForegroundColor Cyan
Write-Host "Source:        $SourcePattern" -ForegroundColor Cyan

# ---- 5. Discover all the policies we need -------------------------------
$browsersToInclude = switch ($Browser) {
    'Both'   { @('Edge','Chrome') }
    'Edge'   { @('Edge') }
    'Chrome' { @('Chrome') }
}

# Policy display-name + category-path mapping. Microsoft's ADMX uses these
# exact strings; resolved once at runtime to per-tenant policy IDs.
$policyMap = @{
    Edge   = @{
        Forcelist = @{ displayName = 'Control which extensions are installed silently';     categoryPath = '\Microsoft Edge\Extensions' }
        Sources   = @{ displayName = 'Configure extension and user script install sources'; categoryPath = '\Microsoft Edge\Extensions' }
        Catalog   = @{ displayName = 'Tenant catalog -- Microsoft Edge';                    categoryPath = '\PIM4EntraPS\PIM Activator' }
    }
    Chrome = @{
        Forcelist = @{ displayName = 'Configure the list of force-installed apps and extensions';        categoryPath = '\Google\Google Chrome\Extensions' }
        Sources   = @{ displayName = 'Configure extension, app, and user script install sources';        categoryPath = '\Google\Google Chrome\Extensions' }
        Catalog   = @{ displayName = 'Tenant catalog -- Google Chrome';                                  categoryPath = '\PIM4EntraPS\PIM Activator' }
    }
}

$resolved = @{}
foreach ($b in $browsersToInclude) {
    $resolved[$b] = @{}
    foreach ($k in 'Forcelist','Sources','Catalog') {
        $spec = $policyMap[$b][$k]
        $def  = Find-PolicyDef -DisplayNameLike $spec.displayName -CategoryPath $spec.categoryPath
        if (-not $def) {
            $hint = if ($k -eq 'Catalog') { ' -- run Push-PimActivatorADMXToIntune.ps1 first to ingest the ADMX' } else { '' }
            throw "Could not find $b policy '$($spec.displayName)' under '$($spec.categoryPath)' (machine class)$hint."
        }
        $pres = Get-Presentations -DefinitionId $def.id
        Write-Host "  $b/$k -> '$($def.displayName)' (id $($def.id), $($pres.Count) presentation(s))" -ForegroundColor Gray
        $resolved[$b][$k] = @{ Definition = $def; Presentations = $pres }
    }
}

# ---- 6. Create / get the Configuration Profile shell --------------------
if (-not $existing) {
    Write-Host "Creating profile '$DisplayName'..." -ForegroundColor Cyan
    $profileBody = @{
        displayName     = $DisplayName
        description     = "[PimActivator] All-in-one Intune Configuration Profile. Force-installs the PIM Activator extension ($ExtensionId) from $UpdateUrl, whitelists $SourcePattern as an install source, and pushes the tenant catalog ($count tenant(s)) for chrome.storage.managed.tenantCatalog. Generated by PIM4EntraPS/tools/pim-activator/Setup-PimActivatorIntune.ps1."
        roleScopeTagIds = @('0')
    } | ConvertTo-Json -Depth 10
    $created = Invoke-MgGraphRequest -Method POST `
        -Uri 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations' `
        -Body $profileBody -ContentType 'application/json' -ErrorAction Stop
    $profileId = $created.id
    Write-Host "[OK] Profile created. id=$profileId" -ForegroundColor Green
} else {
    $profileId = $existing.id
    Write-Host "Profile '$DisplayName' exists (id $profileId). Wiping prior definition values + writing fresh..." -ForegroundColor Cyan
    try {
        $existingVals = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$profileId/definitionValues" `
            -ErrorAction Stop
        foreach ($v in @($existingVals.value)) {
            Invoke-MgGraphRequest -Method DELETE `
                -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$profileId/definitionValues/$($v.id)" `
                -ErrorAction Stop | Out-Null
        }
    } catch {
        Write-Warning "Could not clear prior definition values: $($_.Exception.Message)."
    }
}

# ---- 7. POST definition values --------------------------------------------
function New-DefValue {
    param(
        [Parameter(Mandatory)] $Definition,
        [Parameter(Mandatory)] $Presentation,
        [Parameter(Mandatory)] [ValidateSet('Text','List')] [string]$Kind,
        [Parameter(Mandatory)] [object]$Value      # string for Text, string[] for List
    )
    $presValue = if ($Kind -eq 'Text') {
        @{
            '@odata.type'                = '#microsoft.graph.groupPolicyPresentationValueText'
            'presentation@odata.bind'    = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($Definition.id)')/presentations('$($Presentation.id)')"
            value                         = [string]$Value
        }
    } else {
        # For non-explicit-value listBox (e.g. Chromium ExtensionInstallForcelist,
        # ExtensionInstallSources), the Intune portal editor renders the `name`
        # field as the row's visible data AND the Group Policy CSP write to the
        # device's registry reads from `name` too. The `value` field is only
        # meaningful for explicitValue=true listBoxes (key=>value pairs).
        # Setting both to the same data covers both possibilities + matches
        # what the portal shows after manual entry.
        $valuesList = @( foreach ($v in @($Value)) {
            @{ name = [string]$v; value = [string]$v }
        })
        @{
            '@odata.type'                = '#microsoft.graph.groupPolicyPresentationValueList'
            'presentation@odata.bind'    = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($Definition.id)')/presentations('$($Presentation.id)')"
            values                        = $valuesList
        }
    }
    return @{
        enabled                          = $true
        'definition@odata.bind'          = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($Definition.id)')"
        presentationValues               = @($presValue)
    }
}

foreach ($b in $browsersToInclude) {
    # Forcelist: list of "<extId>;<updateUrl>"
    $defFL = $resolved[$b]['Forcelist'].Definition
    $prFL  = $resolved[$b]['Forcelist'].Presentations | Select-Object -First 1
    $bodyFL = (New-DefValue -Definition $defFL -Presentation $prFL -Kind List -Value @($forcelistValue)) | ConvertTo-Json -Depth 20
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$profileId/definitionValues" -Body $bodyFL -ContentType 'application/json' -ErrorAction Stop | Out-Null
    Write-Host "  [OK] $b Forcelist set ($forcelistValue)" -ForegroundColor Green

    # Sources: list of URL patterns
    $defSR = $resolved[$b]['Sources'].Definition
    $prSR  = $resolved[$b]['Sources'].Presentations | Select-Object -First 1
    $bodySR = (New-DefValue -Definition $defSR -Presentation $prSR -Kind List -Value @($SourcePattern)) | ConvertTo-Json -Depth 20
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$profileId/definitionValues" -Body $bodySR -ContentType 'application/json' -ErrorAction Stop | Out-Null
    Write-Host "  [OK] $b Sources set ($SourcePattern)" -ForegroundColor Green

    # Tenant catalog: single JSON string
    $defTC = $resolved[$b]['Catalog'].Definition
    $prTC  = $resolved[$b]['Catalog'].Presentations | Where-Object { $_.'@odata.type' -match 'TextBox|Text$' } | Select-Object -First 1
    if (-not $prTC) { $prTC = $resolved[$b]['Catalog'].Presentations | Select-Object -First 1 }
    $bodyTC = (New-DefValue -Definition $defTC -Presentation $prTC -Kind Text -Value $minifiedCatalog) | ConvertTo-Json -Depth 20
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$profileId/definitionValues" -Body $bodyTC -ContentType 'application/json' -ErrorAction Stop | Out-Null
    Write-Host "  [OK] $b TenantCatalog set ($($minifiedCatalog.Length) chars)" -ForegroundColor Green
}

# ---- 8. Optional assignment ---------------------------------------------
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
        -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$profileId/assign" `
        -Body $assignBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
    Write-Host "[OK] Assignment created." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Profile is UNASSIGNED. Assign in portal:" -ForegroundColor Yellow
    Write-Host "  Intune admin center -> Devices -> Configuration profiles -> '$DisplayName' -> Assignments" -ForegroundColor Yellow
    Write-Host "Or re-run with -AssignToGroupId <group-id>." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done. Customer endpoints receive the unified policy on next Intune sync (~8h, or force from device)." -ForegroundColor Green
Write-Host ""
Write-Host "Verify on a target device after sync:" -ForegroundColor Gray
Write-Host "  Get-Item       'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist'" -ForegroundColor Gray
Write-Host "  Get-Item       'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallSources'" -ForegroundColor Gray
Write-Host "  Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$ExtensionId\policy' -Name tenantCatalog" -ForegroundColor Gray
