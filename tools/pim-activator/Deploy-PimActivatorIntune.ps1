#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Groups
<#
.SYNOPSIS
    Create / update the Intune Settings Catalog profile that force-installs
    the PIM Activator browser extension on Edge + Chrome.

.DESCRIPTION
    Wraps the manual portal flow (Endpoint Manager -> Devices -> Configuration
    profiles -> Settings catalog -> "Configure the list of force-installed
    apps and extensions") into one re-runnable script. Same defaults as
    Deploy-PimActivatorClient.ps1 -- a zero-arg invocation creates the
    profile with the canonical extension id + update URL.

    Idempotent. If a profile with the same -DisplayName already exists, the
    script PATCHes its settings rather than creating a duplicate. Re-running
    after changing the extension id or update URL updates in place.

    Optional: -AssignToGroupId <group-id> assigns the profile to a Entra
    group. Without it the profile is created but unassigned (operator can
    assign later in the portal).

.PARAMETER ExtensionId
    Chrome/Edge extension id. Default: 'eheocihmlppcophaeakmdenhgcookkab'
    (the canonical PIM Activator id; same in every install). Override only
    when forking under a different signing key.

.PARAMETER UpdateUrl
    HTTPS URL to the Chromium update manifest (updates.xml). Default:
    'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml'. Override
    only when self-hosting the CRX mirror.

.PARAMETER DisplayName
    Intune profile display name. Default: 'PIM Activator -- Force-install
    extension (Edge + Chrome)'. Used for the idempotency lookup.

.PARAMETER Description
    Intune profile description. Default: explains what it does.

.PARAMETER Browser
    Which browser to target. Default: 'Both'. Use 'Edge' or 'Chrome' to
    create a profile that only covers one.

.PARAMETER AssignToGroupId
    Optional Entra group object id to assign the profile to. Without this,
    the profile is created unassigned (assign later via the portal).

.PARAMETER Remove
    Remove the profile instead of creating / updating it. Looks up by
    DisplayName, deletes if found. Idempotent (no-op when not found).

.EXAMPLE
    # Zero-arg: script auto-runs Connect-MgGraph interactively if no Graph
    # context exists, with the right scopes. Creates the profile with the
    # canonical defaults, unassigned.
    .\Deploy-PimActivatorIntune.ps1

.EXAMPLE
    # Create + auto-assign to a target group:
    .\Deploy-PimActivatorIntune.ps1 -AssignToGroupId 11111111-2222-3333-4444-555555555555

.EXAMPLE
    # Remove (cleanup):
    .\Deploy-PimActivatorIntune.ps1 -Remove

.NOTES
    Re-introduced in PIM4EntraPS v2.4.72 after the v1.2.0 activator overhaul
    deleted the original Deploy-PimActivatorIntune script. Solution +
    architecture: Morten Knudsen, 2linkIT.

    Required Graph scopes (delegated):
      - DeviceManagementConfiguration.ReadWrite.All  (create/update profile)
      - Group.Read.All                               (resolve -AssignToGroupId)

    The script uses the BETA Graph endpoint /beta/deviceManagement/
    configurationPolicies (Settings Catalog v2). Microsoft has been
    promising GA for years; until then the beta endpoint is the canonical
    one for Settings-Catalog automation.
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter()]
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId = 'eheocihmlppcophaeakmdenhgcookkab',

    [Parameter(ParameterSetName = 'Install')]
    [string]$UpdateUrl = 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml',

    [Parameter()]
    [string]$DisplayName = '[PimActivator] Force-install extension (Edge + Chrome)',

    [Parameter()]
    [string]$Description = '[PimActivator] Force-installs the PIM Activator browser extension on Edge + Chrome via Chromium ExtensionInstallForcelist policy. Created by PIM4EntraPS/tools/pim-activator/Deploy-PimActivatorIntune.ps1.',

    [Parameter()]
    [ValidateSet('Both','Edge','Chrome')]
    [string]$Browser = 'Both',

    [Parameter(ParameterSetName = 'Install')]
    [string]$AssignToGroupId,

    [Parameter(Mandatory, ParameterSetName = 'Uninstall')]
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

# ---- 1. Verify / establish Graph context ----------------------------------
# DeviceManagementConfiguration.ReadWrite.All is required for the policy CRUD.
# Group.Read.All is required only when -AssignToGroupId is passed (Get-MgGroup
# call for the friendly-name lookup). Request both up-front so the operator
# isn't re-prompted later if they decide to assign mid-session.
$_requiredScopes = @(
    'DeviceManagementConfiguration.ReadWrite.All'
    'Group.Read.All'
)

$ctx = Get-MgContext -ErrorAction SilentlyContinue
if (-not $ctx) {
    Write-Host "Not connected to Microsoft Graph. Launching interactive sign-in (scopes: $($_requiredScopes -join ', '))..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes $_requiredScopes -NoWelcome -ErrorAction Stop | Out-Null
    $ctx = Get-MgContext -ErrorAction Stop
}

$missing = $_requiredScopes | Where-Object { $_ -notin $ctx.Scopes }
if ($missing) {
    Write-Host "Current Graph session is missing required scopes: $($missing -join ', '). Re-connecting interactively..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes $_requiredScopes -NoWelcome -ErrorAction Stop | Out-Null
    $ctx = Get-MgContext -ErrorAction Stop
    $stillMissing = $_requiredScopes | Where-Object { $_ -notin $ctx.Scopes }
    if ($stillMissing) {
        throw "After re-connect, Graph session is STILL missing: $($stillMissing -join ', '). Admin consent may be required."
    }
}

Write-Host "Tenant   : $($ctx.TenantId)"  -ForegroundColor Cyan
Write-Host "Signed-in: $($ctx.Account)"   -ForegroundColor Cyan
Write-Host ""

# ---- 2. Look up existing profile (idempotency) ----------------------------
$forcelistValue = "$ExtensionId;$UpdateUrl"
$listUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=name eq '$DisplayName'"
$existing = $null
try {
    $listResp = Invoke-MgGraphRequest -Method GET -Uri $listUri -ErrorAction Stop
    $existing = $listResp.value | Select-Object -First 1
} catch {
    throw "Failed to list existing configuration policies: $($_.Exception.Message)"
}

# ---- Remove path ----------------------------------------------------------
if ($Remove) {
    if (-not $existing) {
        Write-Host "No profile named '$DisplayName' found in tenant. Nothing to remove." -ForegroundColor Yellow
        return
    }
    Write-Host "Removing profile '$DisplayName' (id $($existing.id))..." -ForegroundColor Yellow
    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($existing.id)" -ErrorAction Stop | Out-Null
    Write-Host "[OK] Removed." -ForegroundColor Green
    return
}

# ---- 3. Build settings array (Edge and/or Chrome) -------------------------
# Settings-Catalog parent/child structure:
#   - Parent is a CHOICE setting with options Disabled (_0) and Enabled (_1).
#   - Enabled REQUIRES a child SimpleSettingCollection containing the actual
#     list of "<extension-id>;<update-url>" strings (the *desc setting).
# IDs are static across tenants (Microsoft-owned, queried from
# /beta/deviceManagement/configurationSettings).
$browserSchemas = @{
    Edge = @{
        ParentId       = 'device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~extensions_extensioninstallforcelist'
        EnabledOptionId= 'device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~extensions_extensioninstallforcelist_1'
        ChildId        = 'device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~extensions_extensioninstallforcelist_extensioninstallforcelistdesc'
    }
    Chrome = @{
        ParentId       = 'device_vendor_msft_policy_config_chromeintunev1~policy~googlechrome~extensions_extensioninstallforcelist'
        EnabledOptionId= 'device_vendor_msft_policy_config_chromeintunev1~policy~googlechrome~extensions_extensioninstallforcelist_1'
        ChildId        = 'device_vendor_msft_policy_config_chromeintunev1~policy~googlechrome~extensions_extensioninstallforcelist_extensioninstallforcelistdesc'
    }
}

$browsersToInclude = switch ($Browser) {
    'Both'   { @('Edge','Chrome') }
    'Edge'   { @('Edge') }
    'Chrome' { @('Chrome') }
}

$settings = foreach ($b in $browsersToInclude) {
    $schema = $browserSchemas[$b]
    @{
        '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
        settingInstance = @{
            '@odata.type'        = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId  = $schema.ParentId
            choiceSettingValue   = @{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value         = $schema.EnabledOptionId
                children      = @(
                    @{
                        '@odata.type'                = '#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance'
                        settingDefinitionId          = $schema.ChildId
                        simpleSettingCollectionValue = @(
                            @{
                                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
                                value         = $forcelistValue
                            }
                        )
                    }
                )
            }
        }
    }
}

# ---- 4. Create or update ---------------------------------------------------
$body = @{
    name         = $DisplayName
    description  = $Description
    platforms    = 'windows10'
    technologies = 'mdm'
    roleScopeTagIds = @('0')
    settings     = @($settings)
} | ConvertTo-Json -Depth 20

if ($existing) {
    Write-Host "Profile '$DisplayName' exists (id $($existing.id)). PATCHing settings..." -ForegroundColor Cyan
    Invoke-MgGraphRequest -Method PUT `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($existing.id)" `
        -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
    $policyId = $existing.id
    Write-Host "[OK] Profile updated. ExtensionInstallForcelist value: $forcelistValue" -ForegroundColor Green
} else {
    Write-Host "Creating profile '$DisplayName'..." -ForegroundColor Cyan
    $created = Invoke-MgGraphRequest -Method POST `
        -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' `
        -Body $body -ContentType 'application/json' -ErrorAction Stop
    $policyId = $created.id
    Write-Host "[OK] Profile created. id=$policyId  forcelist=$forcelistValue" -ForegroundColor Green
}

# ---- 5. Optional assignment -----------------------------------------------
if ($AssignToGroupId) {
    Write-Host ""
    Write-Host "Assigning profile to group $AssignToGroupId ..." -ForegroundColor Cyan
    # Verify the group exists (friendly error if the ID is wrong)
    try {
        $grp = Get-MgGroup -GroupId $AssignToGroupId -ErrorAction Stop
        Write-Host "  Target group: '$($grp.DisplayName)' ($AssignToGroupId)" -ForegroundColor Gray
    } catch {
        throw "Group $AssignToGroupId not found in tenant: $($_.Exception.Message)"
    }
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
        -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$policyId/assign" `
        -Body $assignBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
    Write-Host "[OK] Assignment created." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Profile is UNASSIGNED. Assign in portal:" -ForegroundColor Yellow
    Write-Host "  Intune admin center -> Devices -> Configuration profiles -> '$DisplayName' -> Assignments" -ForegroundColor Yellow
    Write-Host "Or re-run this script with -AssignToGroupId <group-id>." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done. Targeted devices receive the policy on next Intune sync (~8h, or force from device)." -ForegroundColor Green
