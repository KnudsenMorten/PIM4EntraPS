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

    # The pre-flight scan finds existing Intune policies that already manage
    # ExtensionInstallForcelist. Default behavior (v2.4.150): the profile is
    # still created, but the forcelist setting for any CONFLICTING browser is
    # left 'Not configured' -- mixing two writers on the same registry key
    # (HKLM\Policies\<browser>\ExtensionInstallForcelist) makes IME cycle the
    # entries on every sync. Forcelist slots are per-browser, so a Chrome-only
    # conflict still gets the Edge forcelist written (and vice versa). -Force
    # writes EVERY forcelist value despite detected conflicts; only use it
    # when you've manually verified the existing policy is harmless (e.g. it
    # targets an empty group).
    [Parameter(ParameterSetName = 'Install')]
    [switch]$Force,

    [Parameter(Mandatory, ParameterSetName = 'Uninstall')]
    [switch]$Remove,

    # Default ON: run the interactive sign-in through Microsoft Edge
    # explicitly instead of the system default browser (legacy IE on many
    # servers mangles the auth redirect -> MSAL 'state mismatch'). Same
    # mechanism as Deploy-PimActivatorBackend.ps1; see _PimActivatorAuth.ps1.
    # Pass -UseEdge:$false to fall back to MSAL's default-browser flow.
    [Parameter()]
    [switch]$UseEdge = $true
)

$ErrorActionPreference = 'Stop'

# Shared auth machinery: version banner, Graph SDK version-conflict check,
# Edge-forced PKCE sign-in, session probe/heal.
. (Join-Path $PSScriptRoot '_PimActivatorAuth.ps1')

Write-Host "Deploy-PimActivatorIntune -- PIM4EntraPS $(Get-PimActivatorSolutionVersion)" -ForegroundColor Cyan
Write-Host "Graph SDK  : v$(Assert-GraphModuleVersions)" -ForegroundColor Cyan

# ---- 1. Graph context -----------------------------------------------------
# Request EVERY scope this run can need up front. The Edge flow's token
# carries exactly what was requested (no accumulated-consent padding like a
# cached MSAL session), so the later auto-discovery step must not rely on a
# mid-run scope escalation.
$_requiredScopes = @('DeviceManagementConfiguration.ReadWrite.All')
if ($AssignToGroupId) { $_requiredScopes += 'Group.Read.All' }
if (-not $Remove -and -not $CatalogJsonPath) {
    $_requiredScopes += 'Organization.Read.All'                      # tenant id + display name via /organization
    if (-not $ClientId) { $_requiredScopes += 'Application.Read.All' }  # auto-discover the app reg by displayName
}
$ctx = Connect-PimActivatorGraph -RequiredScopes $_requiredScopes -UseEdge:([bool]$UseEdge)
Write-Host "Connected to tenant $($ctx.TenantId) as $($ctx.Account)" -ForegroundColor Gray

# Intune authorizes WRITES by directory role, not by the Graph scope --
# field case: every read worked, the first POST 403'd because the freshly
# activated Intune Administrator role was not in the (older) token. Check
# the session token's wids up front and re-auth once if missing. SoftFail:
# a scoped Intune RBAC assignment (not a directory role) can also authorize
# the writes and never appears in wids -- don't hard-block those operators.
Assert-PaSessionRole -SoftFail `
    -AnyOfRoleIds @(
        '3a2c62db-5318-420d-8d74-23affee5d9d5'   # Intune Administrator
        '62e90394-69f5-4237-9190-012177145e10'   # Global Administrator
    ) `
    -RoleDescription "an ACTIVE 'Intune Administrator' (or Global Administrator) role" `
    -Reconnect { $script:ctx = Connect-PimActivatorGraph -RequiredScopes $_requiredScopes -UseEdge:([bool]$UseEdge) }

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

    # Forcelist registry keys are PER-BROWSER (HKLM\...\Google\Chrome\... vs
    # HKLM\...\Microsoft\Edge\...), so a Chrome-only policy does NOT conflict
    # with our Edge forcelist write. Classify which browser(s) a conflicting
    # policy owns from its forcelist setting-definition ids; unrecognizable
    # ids are treated as owning both (conservative).
    function Get-PaForcelistBrowsersFromBlob {
        param([string]$Blob)
        $browsers = @()
        foreach ($m in [regex]::Matches($Blob, '"settingDefinitionId"\s*:\s*"([^"]*extensioninstallforcelist[^"]*)"', 'IgnoreCase')) {
            $sid = $m.Groups[1].Value.ToLowerInvariant()
            if ($sid -match 'edge')               { $browsers += 'Edge' }
            elseif ($sid -match 'chrome|google')  { $browsers += 'Chrome' }
            else                                  { $browsers += 'Chrome', 'Edge' }
        }
        if (-not $browsers) { $browsers = @('Chrome', 'Edge') }
        @($browsers | Select-Object -Unique)
    }

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
        if ($jsonBlob -match 'extensioninstallforcelist') {
            $ids = @()
            foreach ($m in [regex]::Matches($jsonBlob, '"value"\s*:\s*"([a-p]{32};[^"]+)"')) { $ids += $m.Groups[1].Value }
            $conflicts.Add([pscustomobject]@{
                Type     = 'SettingsCatalog'
                Name     = $p.name
                Id       = $p.id
                Browsers = @(Get-PaForcelistBrowsersFromBlob -Blob $jsonBlob)
                Values   = ($ids | Select-Object -Unique)
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
            $catText  = "$($dv.definition.categoryPath) $defName".ToLowerInvariant()
            $dvBrowsers = @()
            if ($catText -match 'edge')          { $dvBrowsers += 'Edge' }
            if ($catText -match 'chrome|google') { $dvBrowsers += 'Chrome' }
            if (-not $dvBrowsers)                { $dvBrowsers = @('Chrome', 'Edge') }
            $conflicts.Add([pscustomobject]@{
                Type     = 'AdminTemplate'
                Name     = ("{0}  ({1})" -f $c.displayName, $defName)
                Id       = $c.id
                Browsers = $dvBrowsers
                Values   = ($ids | Select-Object -Unique)
            })
        }
    }

    # v2.4.150: a conflict no longer aborts. Forcelist registry slots are
    # PER-BROWSER, so only the browser(s) actually owned by another policy
    # get their forcelist setting left 'Not configured' in our profile;
    # everything else (the other browser's forcelist, Sources,
    # ExtensionSettings, Tenant catalog) is still pushed. -Force writes
    # every forcelist value anyway -- only for operators who verified the
    # overlap is harmless.
    $script:SkipForcelistBrowsers = @()
    if ($conflicts.Count -gt 0) {
        Write-Host ''
        Write-Host "[CONFLICT] Found $($conflicts.Count) other Intune policy/policies that already manage ExtensionInstallForcelist:" -ForegroundColor Yellow
        foreach ($c in $conflicts) {
            Write-Host ("  - [{0}] {1}  (browser: {2})" -f $c.Type, $c.Name, ($c.Browsers -join ' + ')) -ForegroundColor Yellow
            foreach ($v in $c.Values) { Write-Host ("        {0}" -f $v) -ForegroundColor Gray }
        }
        Write-Host ''
        Write-Host "Why this matters:" -ForegroundColor Cyan
        Write-Host "  IME does NOT reliably merge ExtensionInstallForcelist writes across mechanisms;" -ForegroundColor Gray
        Write-Host "  double-writing the same browser's forcelist slot makes the entries cycle on/off" -ForegroundColor Gray
        Write-Host "  in the HKLM registry on every sync." -ForegroundColor Gray
        Write-Host ''
        if ($Force) {
            Write-Host "-Force supplied: writing ALL forcelist values anyway (you have verified the overlap is harmless)." -ForegroundColor Yellow
        } else {
            $script:SkipForcelistBrowsers = @($conflicts | ForEach-Object { $_.Browsers } | Select-Object -Unique)
            Write-Host ("Proceeding: this profile will leave the {0} forcelist setting(s) 'Not configured' so the" -f ($script:SkipForcelistBrowsers -join ' + ')) -ForegroundColor Yellow
            Write-Host "existing policy keeps sole ownership of that registry slot. The exact Intune setting" -ForegroundColor Yellow
            Write-Host "name(s) to re-enable later are printed below at the [SKIP] line(s)." -ForegroundColor Yellow
            Write-Host ''
            Write-Host "To force-install PIM Activator on the skipped browser(s) NOW, add this row to the" -ForegroundColor Cyan
            Write-Host "existing policy's forcelist instead (then delete any blank trailing rows):" -ForegroundColor Cyan
            Write-Host ("    {0};{1}" -f $ExtensionId, $UpdateUrl) -ForegroundColor Green
        }
        Write-Host ''
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
    # v2.4.107: explicit @odata.type discriminators on both the outer entity
    # and the inner groupPolicyUploadedLanguageFile collection items. Without
    # them, some strict Intune tenants (observed 2026-06-10) silently NULL out
    # every field in the POSTed payload -- the row gets created but
    # targetNamespace, targetPrefix, content, languageCodes,
    # groupPolicyUploadedLanguageFiles all come back as null/empty, and
    # status flips to uploadFailed with uploadInfo:null. With the explicit
    # types Intune's strict validator can deserialize the entity correctly.
    # Other tenants (2linkit) tolerated the missing types because their
    # endpoint version has a default type fallback; we now always set them
    # so every tenant works regardless of strictness.
    # NOTE: do NOT include 'defaultLanguageCode' in the payload -- Intune
    # rejects with 400 "ADMX DefaultLanguageCode needs to be null, it will
    # taken from ADML file" (CustomApiErrorPhrase ADMXDefaultLanguageCodeNotNull).
    # The service derives defaultLanguageCode from the first ADML's
    # languageCode field, and we just observe it as 'en-US' on the row
    # after upload. v2.4.107 added it explicitly trying to satisfy a strict
    # tenant; v2.4.108 reverted that part. The @odata.type discriminators
    # stay -- those ARE required by strict tenants.
    $admxBody = @{
        '@odata.type'                     = '#microsoft.graph.groupPolicyUploadedDefinitionFile'
        fileName                          = $admxFileName
        languageCodes                     = @('en-US')
        targetPrefix                      = 'pimactivator'
        targetNamespace                   = 'MortenKnudsen.PIM4EntraPS.PimActivator'
        policyType                        = 'admxIngested'
        revision                          = '1.0'
        content                           = $admxBase64
        groupPolicyUploadedLanguageFiles  = @(@{
            '@odata.type' = '#microsoft.graph.groupPolicyUploadedLanguageFile'
            fileName      = $admlFileName
            languageCode  = 'en-US'
            content       = $admlBase64
        })
    } | ConvertTo-Json -Depth 20
    # v2.4.150: one POST + poll, returning a verdict instead of throwing from
    # inside the poll's try -- the old deliberate uploadFailed throw was
    # swallowed by the poll's own catch ("Status poll failed" warning) and
    # the script limped on until a confusing 'Could not find Tenant catalog'
    # error much later.
    function Invoke-PaAdmxUploadOnce {
        param([string]$Body, [int]$Attempt)
        try {
            $created = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles' -Body $Body -ContentType 'application/json' -ErrorAction Stop
        } catch {
            # First WRITE of every run. A 403 here despite the
            # DeviceManagementConfiguration.ReadWrite.All scope means the
            # Intune SERVICE rejected the caller's directory roles -- the
            # Graph scope alone is not enough for Intune writes.
            if ("$_" -match '403|Forbidden|not authorized') {
                throw ("Intune refused the write (403): $($_.Exception.Message)`nYour Graph scope is fine -- this is Intune RBAC. Activate 'Intune Administrator' (or a scoped Intune RBAC role with Device Configurations create/update) in PIM, then run Disconnect-MgGraph and re-run this script so the fresh token carries the role.")
            }
            throw
        }
        Write-Host "[OK] ADMX uploaded (id=$($created.id), status=$($created.status)). Waiting for Intune to process (attempt $Attempt)..." -ForegroundColor Green
        $deadline = (Get-Date).AddMinutes(3)
        do {
            Start-Sleep -Seconds 4
            $chk = $null
            try { $chk = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($created.id)" -ErrorAction Stop }
            catch { Write-Warning "Status poll failed (will keep polling): $($_.Exception.Message)"; continue }
            Write-Host "  status: $($chk.status)" -ForegroundColor Gray
            if ($chk.status -in @('available', 'uploadCompleted')) { return @{ Ok = $true; Row = $chk } }
            if ($chk.status -in @('uploadFailed', 'removalFailed')) {
                # uploadInfo is often null on uploadFailed; dump the WHOLE row
                # to surface anything Intune did set, plus the
                # groupPolicyOperations sub-collection which sometimes carries
                # the validation error when uploadInfo doesn't.
                Write-Host '--- Failed ADMX row (full Graph response) ---' -ForegroundColor Red
                Write-Host (($chk | ConvertTo-Json -Depth 8) -split "`n" | ForEach-Object { "  $_" } | Out-String) -ForegroundColor Gray
                try {
                    $opsResp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($created.id)/groupPolicyOperations" -ErrorAction Stop
                    if ($opsResp.value -and $opsResp.value.Count -gt 0) {
                        Write-Host '--- groupPolicyOperations sub-collection ---' -ForegroundColor Red
                        foreach ($op in $opsResp.value) {
                            Write-Host ("  operationType={0,-20} status={1,-15} errorCode={2,-10} errorMessage={3}" -f $op.operationType, $op.status, $op.lastModifiedDateTime, $op.errorMessage) -ForegroundColor Gray
                            if ($op.statusDetails) { Write-Host ("    statusDetails: {0}" -f ($op.statusDetails | ConvertTo-Json -Depth 4 -Compress)) -ForegroundColor Gray }
                        }
                    }
                } catch {
                    Write-Host "  (could not fetch groupPolicyOperations sub-collection: $($_.Exception.Message))" -ForegroundColor Gray
                }
                Write-Host '--- end of failure detail ---' -ForegroundColor Red
                return @{ Ok = $false; Row = $chk }
            }
        } while ((Get-Date) -lt $deadline)
        return @{ Ok = $false; Row = $null; TimedOut = $true }
    }

    $admxResult = Invoke-PaAdmxUploadOnce -Body $admxBody -Attempt 1
    if (-not $admxResult.Ok -and $admxResult.Row) {
        # Field case (2026-06-12): first ingest nulled the row + uploadFailed,
        # the immediate re-run succeeded -- Intune's ADMX pipeline is
        # transiently flaky. Remove the corpse, let the service settle, retry once.
        Write-Host 'First ingestion attempt failed -- removing the failed row and retrying once...' -ForegroundColor Yellow
        try { Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($admxResult.Row.id)/remove" -ErrorAction Stop | Out-Null } catch { Write-Warning "/remove failed: $($_.Exception.Message)" }
        $rmDeadline2 = (Get-Date).AddMinutes(2)
        do {
            Start-Sleep -Seconds 3
            try { Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($admxResult.Row.id)" -ErrorAction Stop | Out-Null }
            catch { break }   # 404 = corpse gone
        } while ((Get-Date) -lt $rmDeadline2)
        Start-Sleep -Seconds 10
        $admxResult = Invoke-PaAdmxUploadOnce -Body $admxBody -Attempt 2
    }
    if (-not $admxResult.Ok) {
        $why = if ($admxResult.TimedOut) { 'Intune did not reach a terminal ADMX status within 3 minutes' } else { 'Intune rejected the ADMX (status=uploadFailed) twice in a row' }
        throw "$why. The Tenant catalog policy cannot deploy without the ingested ADMX, so stopping here. Wait 5-10 minutes and re-run this script (stale rows are removed automatically). If it persists: check Devices > Configuration > Import ADMX in the Intune portal and Intune service health."
    }
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
    # Scopes for this branch (Organization.Read.All + Application.Read.All
    # when auto-discovering) are requested up front in step 1 -- the Edge
    # flow's token cannot be scope-escalated mid-run. This safety net only
    # fires for pre-connected MSAL sessions that are missing them.
    $scopesNeeded = @('DeviceManagementConfiguration.ReadWrite.All', 'Organization.Read.All')
    if (-not $ClientId) { $scopesNeeded += 'Application.Read.All' }
    $missing = $scopesNeeded | Where-Object { $_ -notin (Get-MgContext).Scopes }
    if ($missing -and (Get-MgContext).TokenCredentialType -ne 'UserProvidedAccessToken') {
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
# Always resolve all four definitions -- even a conflict-skipped browser's
# Forcelist is resolved, because the [SKIP] message prints its exact Intune
# setting name + category so the operator can configure it manually later.
# Only the WRITE is skipped (write loop below).
$policyKeys = @('Forcelist','Sources','Settings','Catalog')
foreach ($b in $browsersToInclude) {
    $resolved[$b] = @{}
    foreach ($k in $policyKeys) {
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
    # v2.4.150: leave the Forcelist 'Not configured' (= no definition value)
    # for browsers whose registry slot another tenant policy already owns.
    # Print the exact Intune setting name + category so the operator can
    # configure it in THIS profile later if the conflicting policy goes away.
    if ($script:SkipForcelistBrowsers -contains $b) {
        $defFL = $resolved[$b]['Forcelist'].Definition
        Write-Host "  [SKIP] $b Forcelist left 'Not configured' -- another policy in the tenant owns this registry slot." -ForegroundColor Yellow
        Write-Host ("         To configure it later in this profile ('{0}') once the conflict is gone:" -f $DisplayName) -ForegroundColor Gray
        Write-Host ("           Setting : '{0}'  (category: {1})" -f $defFL.displayName, $defFL.categoryPath) -ForegroundColor Gray
        Write-Host ("           Row     : {0}" -f $forcelistValue) -ForegroundColor Gray
    } else {
        # Forcelist: list of "<extId>;<updateUrl>"
        $defFL = $resolved[$b]['Forcelist'].Definition
        $prFL  = $resolved[$b]['Forcelist'].Presentations | Select-Object -First 1
        $bodyFL = (New-DefValue -Definition $defFL -Presentation $prFL -Kind List -Value @($forcelistValue)) | ConvertTo-Json -Depth 20
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$profileId/definitionValues" -Body $bodyFL -ContentType 'application/json' -ErrorAction Stop | Out-Null
        Write-Host "  [OK] $b Forcelist set ($forcelistValue)" -ForegroundColor Green
    }

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
