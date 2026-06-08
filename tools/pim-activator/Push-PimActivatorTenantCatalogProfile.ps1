#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Create / update the Intune ADMX-backed Configuration Profile that pushes
    the PIM Activator tenant catalog JSON. Companion to
    Push-PimActivatorADMXToIntune.ps1 (which uploads the ADMX template).

.DESCRIPTION
    After the ADMX is ingested via Push-PimActivatorADMXToIntune.ps1, an
    admin still has to create a Configuration Profile that uses the new
    policy and pastes the catalog JSON into its textbox. This script wraps
    that portal flow:

      1. Look up the uploaded ADMX in /groupPolicyUploadedDefinitionFiles
      2. Look up the Edge + Chrome policy definitions under that ADMX
      3. Look up each definition's presentation (textbox) ids
      4. Read the catalog JSON file + minify it
      5. Create (or PATCH) a /groupPolicyConfigurations profile with the
         catalog value bound to both policies
      6. Optionally assign to an Entra group

    Idempotent: lookup by display name, PATCH if found, POST if new.

.PARAMETER CatalogJsonPath
    Path to a JSON file containing the tenant catalog array. Required.

.PARAMETER DisplayName
    Display name of the Configuration Profile. Default:
    '[PimActivator] Tenant catalog (ADMX-backed)'.

.PARAMETER AdmxFileName
    File name of the ingested ADMX (used to look it up). Default:
    'PIM4EntraPS.PimActivator.admx'.

.PARAMETER AssignToGroupId
    Optional Entra group object id to assign the profile to.

.PARAMETER Browser
    'Both' (default), 'Edge', or 'Chrome'. Controls which policy values
    the profile sets.

.PARAMETER Remove
    Delete the profile. Idempotent.

.EXAMPLE
    .\Push-PimActivatorTenantCatalogProfile.ps1 -CatalogJsonPath .\discovered-tenant-catalog.json

.EXAMPLE
    .\Push-PimActivatorTenantCatalogProfile.ps1 -Remove

.NOTES
    Required Graph scopes (delegated):
      - DeviceManagementConfiguration.ReadWrite.All
      - Group.Read.All (only when -AssignToGroupId is passed)

    Run Push-PimActivatorADMXToIntune.ps1 FIRST so the ADMX is ingested
    and the policy definitions exist. This script errors out if the ADMX
    is missing or still in transient state.
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Install')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$CatalogJsonPath,

    [Parameter()]
    [string]$DisplayName = '[PimActivator] Tenant catalog (ADMX-backed)',

    [Parameter()]
    [string]$AdmxFileName = 'PIM4EntraPS.PimActivator.admx',

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
    if ($resp.value -and $resp.value.Count -gt 0) {
        $existing = $resp.value[0]
    }
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

# ---- 3. Look up the uploaded ADMX file -----------------------------------
$admxLookupUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles?`$filter=fileName eq '$AdmxFileName'"
$admxFile = $null
try {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $admxLookupUri -ErrorAction Stop
    if ($resp.value -and $resp.value.Count -gt 0) { $admxFile = $resp.value[0] }
} catch {
    throw "Could not list ingested ADMX files: $($_.Exception.Message)"
}
if (-not $admxFile) {
    throw "ADMX '$AdmxFileName' not found in tenant. Run Push-PimActivatorADMXToIntune.ps1 first."
}
if ($admxFile.status -ne 'available') {
    throw "ADMX '$AdmxFileName' is in status '$($admxFile.status)' (not 'available'). Wait for ingestion to finish, then re-run."
}
Write-Host "ADMX: $($admxFile.fileName) (id $($admxFile.id), status $($admxFile.status))" -ForegroundColor Cyan

# ---- 4. Look up the policy definitions ingested from this ADMX -----------
# Use $expand=definitions so the policy definitions inside the ADMX file
# come back in one round trip. Each definition has Id, displayName,
# classType (Machine/User), and presentations (the textbox elements).
# The uploaded-file navigation property isn't queryable (400 'No method match
# route template' on /definitions, and $expand=definitions returns empty).
# Definitions surface in the global /groupPolicyDefinitions list with a
# categoryPath matching what's inside the ADMX. Filter by that.
$defLookupUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions?`$filter=startswith(categoryPath,'\PIM4EntraPS')"
$defResp = Invoke-MgGraphRequest -Method GET -Uri $defLookupUri -ErrorAction Stop
$definitions = @($defResp.value)
if ($definitions.Count -eq 0) {
    throw "No policy definitions found under categoryPath '\PIM4EntraPS'. Check that Push-PimActivatorADMXToIntune.ps1 finished with status 'available'."
}
Write-Host "Found $($definitions.Count) policy definition(s) under \PIM4EntraPS:" -ForegroundColor Cyan
$definitions | ForEach-Object { Write-Host "  $($_.displayName)  (id $($_.id))" -ForegroundColor DarkGray }

# Hydrate presentations per definition (separate call -- $expand depth limit).
for ($i = 0; $i -lt $definitions.Count; $i++) {
    $defId = $definitions[$i].id
    try {
        $presResp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions/$defId/presentations" `
            -ErrorAction Stop
        $definitions[$i] | Add-Member -NotePropertyName presentations -NotePropertyValue @($presResp.value) -Force
    } catch {
        Write-Warning "Could not fetch presentations for definition $defId : $($_.Exception.Message)"
    }
}

# Match by displayName -- the ADMX uses 'TenantCatalog_Edge' / '_Chrome' names
# which Intune mirrors as the displayName from the ADML strings.
function _PickDefinition($wantSubstring) {
    $hit = $definitions | Where-Object { $_.displayName -match $wantSubstring } | Select-Object -First 1
    if (-not $hit) {
        Write-Host "Available definitions:" -ForegroundColor Red
        $definitions | ForEach-Object { Write-Host "  '$($_.displayName)'  classType=$($_.classType)  id=$($_.id)" -ForegroundColor Red }
        throw "Could not find a policy definition matching '$wantSubstring'. ADMX may have changed."
    }
    return $hit
}

$browsersToInclude = switch ($Browser) {
    'Both'   { @('Edge','Chrome') }
    'Edge'   { @('Edge') }
    'Chrome' { @('Chrome') }
}

# ---- 5. Read + validate the catalog JSON --------------------------------
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

# ---- 6. Create / get the Configuration Profile shell --------------------
if (-not $existing) {
    Write-Host "Creating profile '$DisplayName'..." -ForegroundColor Cyan
    $profileBody = @{
        displayName     = $DisplayName
        description     = "[PimActivator] Pushes the tenant catalog ($count tenant(s)) to HKLM Edge + Chrome 3rdparty extension policy registry via the ADMX-ingested Group Policy CSP. PIM Activator extension reads it via chrome.storage.managed.tenantCatalog. Generated by PIM4EntraPS/tools/pim-activator/Push-PimActivatorTenantCatalogProfile.ps1."
        roleScopeTagIds = @('0')
    } | ConvertTo-Json -Depth 10
    $created = Invoke-MgGraphRequest -Method POST `
        -Uri 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations' `
        -Body $profileBody -ContentType 'application/json' -ErrorAction Stop
    $profileId = $created.id
    Write-Host "[OK] Profile created. id=$profileId" -ForegroundColor Green
} else {
    $profileId = $existing.id
    Write-Host "Profile '$DisplayName' exists (id $profileId). Will overwrite definition values." -ForegroundColor Cyan
    # Clean out any existing definition values so PATCH'ing in fresh ones
    # doesn't double-write.
    try {
        $existingVals = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$profileId/definitionValues" `
            -ErrorAction Stop
        foreach ($v in @($existingVals.value)) {
            Write-Host "  Removing prior definition value id $($v.id)..." -ForegroundColor DarkGray
            Invoke-MgGraphRequest -Method DELETE `
                -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$profileId/definitionValues/$($v.id)" `
                -ErrorAction Stop | Out-Null
        }
    } catch {
        Write-Warning "Could not clear prior definition values: $($_.Exception.Message). Continuing -- new values may stack on top."
    }
}

# ---- 7. POST definition values for each targeted browser ----------------
foreach ($b in $browsersToInclude) {
    $needle = "Microsoft Edge"
    if ($b -eq 'Chrome') { $needle = "Google Chrome" }
    $def = _PickDefinition -wantSubstring $needle
    Write-Host "  $b -> definition '$($def.displayName)' (id $($def.id))" -ForegroundColor Cyan

    $pres = @($def.presentations)
    $textPres = $pres | Where-Object { $_.'@odata.type' -match 'TextBox|Text$' } | Select-Object -First 1
    if (-not $textPres) {
        Write-Warning "  Definition has no text presentation. Skipping $b."
        continue
    }

    $valBody = @{
        enabled = $true
        'definition@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($def.id)')"
        presentationValues = @(
            @{
                '@odata.type' = '#microsoft.graph.groupPolicyPresentationValueText'
                'presentation@odata.bind' = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($def.id)')/presentations('$($textPres.id)')"
                value = $minifiedCatalog
            }
        )
    } | ConvertTo-Json -Depth 20

    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$profileId/definitionValues" `
        -Body $valBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
    Write-Host "  [OK] $b definition value written ($($minifiedCatalog.Length) chars)." -ForegroundColor Green
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
Write-Host "Done. Targeted devices receive the policy on next Intune sync (~8h, or force from device)." -ForegroundColor Green
Write-Host ""
Write-Host "Verify on a target device after sync:" -ForegroundColor Gray
Write-Host "  Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\eheocihmlppcophaeakmdenhgcookkab\policy' -Name tenantCatalog" -ForegroundColor Gray
