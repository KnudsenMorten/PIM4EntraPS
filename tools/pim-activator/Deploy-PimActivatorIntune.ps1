#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Intune setup for the PIM Activator browser extension. Creates a
    single Group Policy Configuration profile ('[PimActivator] client
    settings') carrying every client-side policy per browser:

      1. ExtensionInstallForcelist  -- force-install the extension from
                                       gh-pages CRX update URL
      2. ExtensionInstallSources    -- whitelist the gh-pages host for
                                       self-hosted CRX installation
      3. ExtensionSettings          -- pre-grants <all_urls> runtime
                                       permissions so Chrome's permission-
                                       expansion gate doesn't silently
                                       disable auto-update from earlier
                                       narrower-permission versions
      4. TenantCatalog              -- push the tenant catalog JSON for
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
    '[PimActivator] client settings'.

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
    .\Deploy-PimActivatorIntune.ps1 -CatalogJsonPath .\discovered-tenant-catalog.json

.EXAMPLE
    .\Deploy-PimActivatorIntune.ps1 -CatalogJsonPath .\discovered-tenant-catalog.json -AssignToGroupId 11111111-2222-3333-4444-555555555555

.EXAMPLE
    .\Deploy-PimActivatorIntune.ps1 -Remove

.NOTES
    Required Graph scopes (delegated):
      - DeviceManagementConfiguration.ReadWrite.All
      - Group.Read.All (only when -AssignToGroupId is passed)
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    # Optional. When supplied, the profile also includes the TenantCatalog
    # setting (chrome.storage.managed.tenantCatalog) so the popup's
    # 'Use centrally deployed' tile is active immediately on every box. When
    # OMITTED, the script ships the three install policies (forcelist + sources
    # + ExtensionSettings) only -- the extension installs fine, and users
    # populate their tenants via the in-popup wizard ('Add single tenant' or
    # 'Import JSON catalog'). Mandatory in v2.4.98; demoted to optional in
    # v2.4.99 after customer tenants without a prepared catalog couldn't
    # complete a zero-arg deploy.
    [Parameter(ParameterSetName = 'Install')]
    [ValidateScript({ -not $_ -or (Test-Path -LiteralPath $_ -PathType Leaf) })]
    [string]$CatalogJsonPath,

    [Parameter()]
    [string]$DisplayName = '[PimActivator] client settings',

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

    # Skip the Entra /applications round-trip and use the provided clientId
    # directly. Tenant id + tenant name are still auto-resolved via
    # Graph /organization. Use this when you ran Deploy-PimActivatorBackend.ps1
    # earlier and already know the appId. Ignored when -CatalogJsonPath is
    # also supplied (file takes precedence over both flags).
    [Parameter(ParameterSetName = 'Install')]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    # Optional. Override the auto-resolved tenant display name (from
    # /organization). Useful when you want a friendlier label in the popup's
    # tenant chip. Ignored when -CatalogJsonPath is supplied.
    [Parameter(ParameterSetName = 'Install')]
    [string]$TenantName,

    # Bypass the pre-flight scan for existing Intune policies that already
    # manage ExtensionInstallForcelist on Chrome / Edge. By default the script
    # aborts if any other policy is found, because mixing Settings Catalog +
    # ADMX writes to the SAME registry key (HKLM\Policies\<browser>\
    # ExtensionInstallForcelist) causes IME to cycle entries on every sync --
    # one source's writes survive, the others get overwritten. Settings
    # Catalog wins over ADMX in our experience. -Force skips the check and
    # creates the ADMX profile anyway; only use this if you've manually
    # verified the existing policy doesn't conflict (e.g. it only targets
    # an empty group).
    [Parameter(ParameterSetName = 'Install')]
    [switch]$Force,

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

# ---- 1.25. Pre-flight: scan for existing ExtensionInstallForcelist policies ---
#
# IME does NOT merge ExtensionInstallForcelist writes across mechanisms
# (Settings Catalog vs ADMX-backed Administrative Templates). If a customer
# already has, say, a Settings Catalog profile pushing Dashlane + Google Docs
# Offline to the same HKLM key, our ADMX-backed forcelist write will land
# briefly and then be overwritten on the next sync cycle. The fix is to add
# our extension id to the CUSTOMER'S existing policy instead of creating a
# new ADMX profile that fights with it.
#
# This block runs read-only against Graph and lists every Intune policy that
# touches Chrome / Edge ExtensionInstallForcelist (excluding any profile with
# our own $DisplayName). If matches are found, prints them and aborts -- the
# operator can either (a) add our extension id to the existing policy in the
# Intune portal, or (b) re-run with -Force.
if (-not $Remove) {
    Write-Host ''
    Write-Host "Pre-flight: scanning for existing Intune policies that manage ExtensionInstallForcelist..." -ForegroundColor Cyan

    $conflicts = New-Object System.Collections.Generic.List[object]

    # 1.25a. Settings Catalog (deviceManagement/configurationPolicies)
    $cpResp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' -ErrorAction SilentlyContinue
    $policies = if ($cpResp) { @($cpResp.value) } else { @() }
    while ($cpResp.'@odata.nextLink') {
        $cpResp = Invoke-MgGraphRequest -Method GET -Uri $cpResp.'@odata.nextLink' -ErrorAction SilentlyContinue
        if ($cpResp) { $policies += $cpResp.value }
    }
    foreach ($p in $policies) {
        if ($p.name -eq $DisplayName) { continue }
        $sResp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/{0}/settings" -f $p.id) -ErrorAction SilentlyContinue
        if (-not $sResp) { continue }
        $jsonBlob = ($sResp.value | ConvertTo-Json -Depth 30 -Compress -ErrorAction SilentlyContinue)
        if ($jsonBlob -match 'ExtensionInstallForcelist' -or $jsonBlob -match 'extensioninstallforcelist') {
            $ids = @()
            foreach ($m in [regex]::Matches($jsonBlob, '"value"\s*:\s*"([a-p]{32};[^"]+)"')) { $ids += $m.Groups[1].Value }
            $conflicts.Add([pscustomobject]@{
                Type   = 'SettingsCatalog'
                Name   = $p.name
                Id     = $p.id
                Values = ($ids | Select-Object -Unique)
            })
        }
    }

    # 1.25b. ADMX-backed (deviceManagement/groupPolicyConfigurations)
    $gpResp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations' -ErrorAction SilentlyContinue
    $configs = if ($gpResp) { @($gpResp.value) } else { @() }
    while ($gpResp.'@odata.nextLink') {
        $gpResp = Invoke-MgGraphRequest -Method GET -Uri $gpResp.'@odata.nextLink' -ErrorAction SilentlyContinue
        if ($gpResp) { $configs += $gpResp.value }
    }
    foreach ($c in $configs) {
        if ($c.displayName -eq $DisplayName) { continue }
        $dvResp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/{0}/definitionValues?`$expand=definition" -f $c.id) -ErrorAction SilentlyContinue
        if (-not $dvResp) { continue }
        foreach ($dv in @($dvResp.value)) {
            $defName = $dv.definition.displayName
            if ($defName -notmatch 'ExtensionInstallForcelist' -and $defName -notmatch 'Configure the list of force-installed' -and $defName -notmatch 'Control which extensions are installed silently') { continue }
            $pvResp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/{0}/definitionValues/{1}/presentationValues?`$expand=presentation" -f $c.id, $dv.id) -ErrorAction SilentlyContinue
            $ids = @()
            foreach ($pv in @($pvResp.value)) {
                if ($pv.values) {
                    foreach ($v in @($pv.values)) {
                        if ($v -is [System.Collections.IDictionary] -and $v.ContainsKey('value')) { $ids += [string]$v['value'] }
                    }
                } elseif ($pv.value -is [string]) { $ids += $pv.value }
            }
            $conflicts.Add([pscustomobject]@{
                Type   = 'AdminTemplate'
                Name   = ("{0}  ({1})" -f $c.displayName, $defName)
                Id     = $c.id
                Values = ($ids | Select-Object -Unique)
            })
        }
    }

    if ($conflicts.Count -gt 0) {
        Write-Host ''
        Write-Host "[CONFLICT] Found $($conflicts.Count) other Intune policy/policies that already manage ExtensionInstallForcelist:" -ForegroundColor Yellow
        foreach ($c in $conflicts) {
            Write-Host ("  - [{0}] {1}" -f $c.Type, $c.Name) -ForegroundColor Yellow
            foreach ($v in $c.Values) { Write-Host ("        {0}" -f $v) -ForegroundColor Gray }
        }
        Write-Host ''
        Write-Host "Why this matters:" -ForegroundColor Cyan
        Write-Host "  IME does NOT reliably merge ExtensionInstallForcelist writes across mechanisms." -ForegroundColor Gray
        Write-Host "  Creating an ADMX-backed '$DisplayName' profile in this tenant will cause" -ForegroundColor Gray
        Write-Host "  PIM Activator's forcelist entry to cycle on/off in the HKLM registry on every" -ForegroundColor Gray
        Write-Host "  sync, because the other policy/policies above will overwrite our entry." -ForegroundColor Gray
        Write-Host ''
        Write-Host "Recommended fix:" -ForegroundColor Cyan
        Write-Host "  Open the existing policy in Intune portal and ADD this forcelist row to both" -ForegroundColor Gray
        Write-Host "  the Chrome and Edge extension lists (then delete any blank trailing rows):" -ForegroundColor Gray
        Write-Host ("    {0};{1}" -f $ExtensionId, $UpdateUrl) -ForegroundColor Green
        Write-Host ''
        Write-Host "  The other settings this script ships (ExtensionInstallSources, ExtensionSettings," -ForegroundColor Gray
        Write-Host "  Tenant catalog) DON'T conflict with any Settings Catalog policy, so you can still" -ForegroundColor Gray
        Write-Host "  run this script with -Force to push them -- it will write the forcelist entry too" -ForegroundColor Gray
        Write-Host "  but understand that the existing policy will overwrite it on every sync until you" -ForegroundColor Gray
        Write-Host "  also add our extension id there." -ForegroundColor Gray
        Write-Host ''
        if (-not $Force) {
            Write-Host "Aborting. Re-run with -Force to proceed anyway." -ForegroundColor Red
            return
        }
        Write-Host "-Force supplied; proceeding despite conflict." -ForegroundColor Yellow
    } else {
        Write-Host "[OK] No existing ExtensionInstallForcelist policies found in tenant." -ForegroundColor Green
    }
}


# ---- 1.5. Ensure the PIM Activator ADMX is ingested in this tenant -------
# Idempotent. Skips entirely if the ADMX is already uploaded + available;
# uploads it (with the sibling intune\*.admx + en-US\*.adml pair) only
# when missing. Previously this was a separate script
# (Push-PimActivatorADMXToIntune.ps1); folded inline 2026-06-10 to make
# Deploy-PimActivatorIntune.ps1 the ONLY Intune script the operator runs.
$admxPath  = Join-Path $PSScriptRoot 'intune\PIM4EntraPS.PimActivator.admx'
$admlPath  = Join-Path $PSScriptRoot 'intune\en-US\PIM4EntraPS.PimActivator.adml'
$admxFileName = if (Test-Path -LiteralPath $admxPath) { Split-Path -Leaf $admxPath } else { 'PIM4EntraPS.PimActivator.admx' }
$admxListUri  = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles?`$filter=fileName eq '$admxFileName'"
$admxRow = $null
try {
    $admxResp = Invoke-MgGraphRequest -Method GET -Uri $admxListUri -ErrorAction Stop
    if ($admxResp.value) { $admxRow = $admxResp.value | Select-Object -First 1 }
} catch {
    Write-Warning "ADMX lookup failed (will still try upload): $($_.Exception.Message)"
}

if ($admxRow -and $admxRow.status -in @('available','uploadCompleted')) {
    Write-Host "ADMX '$admxFileName' already ingested (status=$($admxRow.status), id=$($admxRow.id)). Skipping upload." -ForegroundColor Gray
} else {
    if (-not (Test-Path -LiteralPath $admxPath)) { throw "ADMX file not found at '$admxPath' -- can't auto-ingest. Place the .admx + .adml pair under .\intune\ next to this script." }
    if (-not (Test-Path -LiteralPath $admlPath)) { throw "ADML file not found at '$admlPath' -- can't auto-ingest." }
    $admxBytes  = [System.IO.File]::ReadAllBytes($admxPath)
    $admlBytes  = [System.IO.File]::ReadAllBytes($admlPath)
    $admxBase64 = [Convert]::ToBase64String($admxBytes)
    $admlBase64 = [Convert]::ToBase64String($admlBytes)
    $admlFileName = Split-Path -Leaf $admlPath
    # If a stale row exists (failed / transient), /remove first.
    if ($admxRow) {
        Write-Host "Existing ADMX row in non-available state '$($admxRow.status)' -- removing before re-upload..." -ForegroundColor Yellow
        try { Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($admxRow.id)/remove" -ErrorAction Stop | Out-Null } catch { Write-Warning "/remove failed: $($_.Exception.Message)" }
        $rmDeadline = (Get-Date).AddMinutes(2)
        do {
            Start-Sleep -Seconds 3
            try {
                $chk = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($admxRow.id)" -ErrorAction Stop
                Write-Host "  status: $($chk.status)" -ForegroundColor Gray
            } catch { if ($_.Exception.Message -match '404|NotFound') { break } else { Write-Warning $_.Exception.Message; break } }
        } while ((Get-Date) -lt $rmDeadline)
    }
    Write-Host "Uploading ADMX ($($admxBytes.Length) bytes) + ADML ($($admlBytes.Length) bytes)..." -ForegroundColor Cyan
    $admxBody = @{
        fileName                          = $admxFileName
        languageCodes                     = @('en-US')
        targetPrefix                      = 'pimactivator'
        targetNamespace                   = 'MortenKnudsen.PIM4EntraPS.PimActivator'
        policyType                        = 'admxIngested'
        revision                          = '1.0'
        content                           = $admxBase64
        groupPolicyUploadedLanguageFiles  = @(@{ fileName = $admlFileName; languageCode = 'en-US'; content = $admlBase64 })
    } | ConvertTo-Json -Depth 20
    $admxCreated = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles' -Body $admxBody -ContentType 'application/json' -ErrorAction Stop
    Write-Host "[OK] ADMX uploaded (id=$($admxCreated.id), status=$($admxCreated.status)). Waiting for Intune to process..." -ForegroundColor Green
    $upDeadline = (Get-Date).AddMinutes(3)
    do {
        Start-Sleep -Seconds 4
        try {
            $chk = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($admxCreated.id)" -ErrorAction Stop
            Write-Host "  status: $($chk.status)" -ForegroundColor Gray
            if ($chk.status -in @('available','uploadCompleted')) { break }
            if ($chk.status -in @('uploadFailed','removalFailed')) {
                throw "Intune rejected the ADMX. status=$($chk.status). uploadInfo: $($chk.uploadInfo | ConvertTo-Json -Compress)"
            }
        } catch { Write-Warning "Status poll failed: $($_.Exception.Message)"; break }
    } while ((Get-Date) -lt $upDeadline)
}

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

# ---- 4. Catalog: read from file OR auto-discover from Entra -------------
# If -CatalogJsonPath is supplied, use it verbatim. Otherwise auto-discover
# the per-tenant PIM Activator app registration (created by
# Deploy-PimActivatorBackend.ps1 -- default displayName 'PIM Activator')
# and the current tenant via Microsoft Graph, then build a single-entry
# catalog from those facts. Customers no longer need to hand-craft the
# JSON before they can run this script.
if ($CatalogJsonPath) {
    $catalogJson = Get-Content -LiteralPath $CatalogJsonPath -Raw -Encoding UTF8
    try {
        $catalog = $catalogJson | ConvertFrom-Json
    } catch {
        throw "Could not parse '$CatalogJsonPath' as JSON: $($_.Exception.Message)"
    }
} else {
    # No -CatalogJsonPath. Two sub-paths:
    #   (a) operator passed -ClientId         -> skip Entra /applications round-trip, use it directly
    #   (b) operator passed nothing extra     -> auto-discover via /applications?displayName eq 'PIM Activator'
    # Tenant id + tenant name come from /organization either way (unless
    # -TenantName was passed to override the label).
    $needsOrgScope = $true
    $needsAppScope = -not $ClientId   # only query /applications if we don't already know clientId
    $scopesNeeded  = @('DeviceManagementConfiguration.ReadWrite.All','Organization.Read.All')
    if ($needsAppScope) { $scopesNeeded += 'Application.Read.All' }
    $missing = $scopesNeeded | Where-Object { $_ -notin (Get-MgContext).Scopes }
    if ($missing) {
        Connect-MgGraph -Scopes $scopesNeeded -NoWelcome -ErrorAction Stop | Out-Null
    }

    # Tenant id + display name from Graph /organization
    $org = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization').value | Select-Object -First 1
    if (-not $org) { throw "Could not resolve current tenant via /organization. Re-run with -CatalogJsonPath <file> to bypass auto-discovery." }
    $tenantIdResolved   = $org.id
    $tenantNameResolved = if ($TenantName) { $TenantName } else { $org.displayName }

    if ($ClientId) {
        $clientIdResolved = $ClientId
        Write-Host ("Using provided -ClientId for tenant '{0}' ({1})." -f $tenantNameResolved, $tenantIdResolved) -ForegroundColor Cyan
    } else {
        Write-Host "Auto-discovering PIM Activator app registration from Entra..." -ForegroundColor Cyan
        # startswith() rather than `eq` so the lookup still works when the
        # operator renamed the app to a variant like 'PIM Activator (prod)'
        # or '[2linkIT] PIM Activator'. Same pattern as the popup's
        # onboarding wizard uses.
        $appName = 'PIM Activator'
        $appResp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/v1.0/applications?`$filter=startswith(displayName,'$appName')")
        $app = $appResp.value | Select-Object -First 1
        if (-not $app) {
            throw "No app registration with displayName starting with '$appName' found in tenant '$tenantNameResolved' ($tenantIdResolved). Run Deploy-PimActivatorBackend.ps1 once to create it, OR pass -ClientId <guid>, OR pass -CatalogJsonPath <file>."
        }
        $clientIdResolved = $app.appId
        Write-Host ("Found app '{0}' (clientId {1})." -f $app.displayName, $clientIdResolved) -ForegroundColor Green
    }

    $catalog = @(
        [pscustomobject]@{
            name                  = $tenantNameResolved
            tenantId              = $tenantIdResolved
            clientId              = $clientIdResolved
            defaultJustification  = 'Change in infrastructure'
            defaultDurationHours  = 8
        }
    )
    Write-Host ("Catalog built  : name='{0}'  tenantId={1}  clientId={2}" -f $tenantNameResolved, $tenantIdResolved, $clientIdResolved) -ForegroundColor Green
}

$count = @($catalog).Count
if ($count -eq 0) { throw "Catalog is empty after $(if ($CatalogJsonPath) { 'reading file' } else { 'auto-discovery' })." }
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
Write-Host "Catalog ready: $count tenant(s) -- $((($catalog | ForEach-Object name) -join ', '))" -ForegroundColor Cyan

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
#
# FOUR policies pushed per browser:
#   Forcelist : install + keep installed (the install directive itself)
#   Sources   : whitelist the gh-pages host as a CRX install source
#   Settings  : ExtensionSettings JSON -- pre-grants runtime_allowed_hosts =
#               '<all_urls>' to bypass Chrome's permission-expansion gate
#               (added 2026-06-10 after the v1.5.11 host_permissions=https://*/*
#               change froze the fleet on managed Chrome -- the gate silently
#               disables every auto-update from a narrower-permission install
#               and DeveloperToolsAvailability=2 hides the Enable button)
#   Catalog   : tenant catalog JSON via chrome.storage.managed (custom ADMX)
$policyMap = @{
    Edge   = @{
        Forcelist = @{ displayName = 'Control which extensions are installed silently';     categoryPath = '\Microsoft Edge\Extensions' }
        Sources   = @{ displayName = 'Configure extension and user script install sources'; categoryPath = '\Microsoft Edge\Extensions' }
        Settings  = @{ displayName = 'Extension management settings';                       categoryPath = '\Microsoft Edge\Extensions' }
        Catalog   = @{ displayName = 'Tenant catalog -- Microsoft Edge';                    categoryPath = '\PIM4EntraPS\PIM Activator' }
    }
    Chrome = @{
        Forcelist = @{ displayName = 'Configure the list of force-installed apps and extensions';        categoryPath = '\Google\Google Chrome\Extensions' }
        Sources   = @{ displayName = 'Configure extension, app, and user script install sources';        categoryPath = '\Google\Google Chrome\Extensions' }
        Settings  = @{ displayName = 'Extension management settings';                                    categoryPath = '\Google\Google Chrome\Extensions' }
        Catalog   = @{ displayName = 'Tenant catalog -- Google Chrome';                                  categoryPath = '\PIM4EntraPS\PIM Activator' }
    }
}

# ExtensionSettings policy value (single JSON string keyed by extension id).
# runtime_allowed_hosts=['<all_urls>'] pre-grants the broad scope so Chrome's
# auto-update doesn't trip the permission-expansion gate.
$extSettingsJson = (@{ $ExtensionId = @{
    installation_mode    = 'force_installed'
    update_url           = $UpdateUrl
    runtime_allowed_hosts = @('<all_urls>')
}} | ConvertTo-Json -Depth 5 -Compress)

$resolved = @{}
foreach ($b in $browsersToInclude) {
    $resolved[$b] = @{}
    foreach ($k in 'Forcelist','Sources','Settings','Catalog') {
        $spec = $policyMap[$b][$k]
        $def  = Find-PolicyDef -DisplayNameLike $spec.displayName -CategoryPath $spec.categoryPath
        if (-not $def) {
            $hint = if ($k -eq 'Catalog') { ' -- the custom ADMX is auto-ingested at the top of this script; if you see this error it means the ADMX upload itself failed. Re-run after addressing that.' } else { '' }
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
        description     = "[PimActivator] client-side policies for Edge + Chrome. Force-installs the PIM Activator extension ($ExtensionId) from $UpdateUrl, whitelists $SourcePattern as an install source, pre-grants <all_urls> runtime permissions (so the manifest's broad host scope doesn't trip Chrome's permission-expansion gate during auto-update), and pushes the tenant catalog ($count tenant(s)) for chrome.storage.managed.tenantCatalog. Generated by PIM4EntraPS/tools/pim-activator/Deploy-PimActivatorIntune.ps1."
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

    # ExtensionSettings: single JSON string. Pre-grants <all_urls> runtime
    # hosts for our ext id so Chrome's permission-expansion gate skips the
    # auto-update silent-disable. Only takes effect for THIS extension id.
    $defXS = $resolved[$b]['Settings'].Definition
    $prXS  = $resolved[$b]['Settings'].Presentations | Where-Object { $_.'@odata.type' -match 'TextBox|Text$' } | Select-Object -First 1
    if (-not $prXS) { $prXS = $resolved[$b]['Settings'].Presentations | Select-Object -First 1 }
    $bodyXS = (New-DefValue -Definition $defXS -Presentation $prXS -Kind Text -Value $extSettingsJson) | ConvertTo-Json -Depth 20
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$profileId/definitionValues" -Body $bodyXS -ContentType 'application/json' -ErrorAction Stop | Out-Null
    Write-Host "  [OK] $b ExtensionSettings set (runtime_allowed_hosts=<all_urls> for $ExtensionId -- bypasses permission-expansion gate)" -ForegroundColor Green

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
