#Requires -Version 5.1
<#
.SYNOPSIS
    Hybrid (on-prem / standalone) setup for the PIM Activator browser extension
    -- the on-prem sibling of Deploy-PimActivatorIntune.ps1. An MSP deploys the
    SAME client-side managed configuration (forcelist + sources + extension
    settings + multi-tenant catalog) to its admins' HYBRID machines (on-prem
    AD domain-joined OR standalone) WITHOUT Intune, via one of three targets:

      -Target Json       emit the managed-config JSON artifact (inspect/import)
      -Target DomainGpo  create/update an AD domain Group Policy Object
      -Target LocalGpo   write the LOCAL machine policy (HKLM registry) -- no
                         domain required (standalone / hybrid box)

    All three targets converge on the SAME registry policy values that the
    Intune deploy produces, built by the shared pure builder
    _PimActivatorHybridPolicy.ps1, so a hybrid endpoint ends up byte-equivalent
    to an Intune-managed one.

.DESCRIPTION
    Config source: a JSON file (typically on a UNC share) holding the MSP's
    per-tenant Activator config for up to 25 tenants. Pass it with
    -TenantConfigJsonPath (alias -ConfigUncPath). Schema -- the file is EITHER
    a bare array of tenant entries OR an object { "tenants": [ ... ] }:

      [
        {
          "name":     "Customer A",                 (required, display label)
          "tenantId": "<GUID>",                     (required)
          "clientId": "<GUID>",                     (required, the per-tenant
                                                     PIM Activator app reg id)
          "defaultJustification":  "...",           (optional)
          "defaultDurationHours":  8,               (optional)
          "prefix":      "PIM-",                    (optional)
          "entraPrefix": ["PIM-Entra","PIM-AAD"],   (optional, string|array)
          "azurePrefix": ["PIM-Azure","PIM-AzRes"], (optional, string|array)
          "groupNameFilter": "...",                 (optional)
          "entraGroupRegex": "...",                 (optional)
          "azureGroupRegex": "...",                 (optional)
          "bulkActivateConfirmThreshold": 5         (optional, per-tenant)
        }
        // ... up to 25 entries
      ]

    This is the SAME per-entry shape Deploy-PimActivatorIntune.ps1 reads via
    -CatalogJsonPath and that managed-schema.json documents for tenantCatalog.

    Validation: empty set, >25 tenants, missing name/tenantId/clientId,
    malformed GUID, or a duplicate tenantId all FAIL with a clear message
    before anything is written.

    -WhatIf (SupportsShouldProcess): every target prints exactly what it WOULD
    do (GPO + registry values, or the JSON artifact path) and makes NO changes.

    PS 5.1-safe throughout (no ?./??, no RSA.ImportFromPem, ConvertTo-Json
    array shape forced via -InputObject @(...)).

.PARAMETER TenantConfigJsonPath
    Path (local or UNC) to the per-tenant Activator config JSON. Required for
    every target. Alias: -ConfigUncPath.

.PARAMETER Target
    Json | DomainGpo | LocalGpo. Default: Json (safe -- writes only an artifact).

.PARAMETER OutputPath
    -Target Json only. Where to write the managed-config artifact. Default:
    .\pim-activator-hybrid-managed-config.json next to this script.

.PARAMETER GpoName
    -Target DomainGpo only. Display name of the GPO to create/update. Default:
    '[PimActivator] client settings' (mirrors the Intune profile display name).

.PARAMETER LinkToOu
    -Target DomainGpo only. Optional distinguished name of an OU to link the
    GPO to. Omitted = GPO created/updated but left UNLINKED.

.PARAMETER ExtensionId
    Chrome/Edge extension id. Default 'eheocihmlppcophaeakmdenhgcookkab'
    (mirrors Deploy-PimActivatorIntune.ps1).

.PARAMETER UpdateUrl
    Self-hosted updates.xml URL. Default
    'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml' (mirrors Intune).

.PARAMETER SourcePattern
    URL pattern for ExtensionInstallSources. Default
    'https://knudsenmorten.github.io/*' (mirrors Intune).

.PARAMETER Browser
    'Both' (default), 'Edge', or 'Chrome' (mirrors Intune).

.PARAMETER DefaultJustification
    Opt-in. When supplied, OVERWRITES defaultJustification on EVERY tenant entry
    written to the managed catalog (all <=25 tenants) -- whether the value came
    from the -TenantConfigJsonPath file or was absent. The extension popup
    pre-fills the Activate form with it. Omit to keep each entry's own value.
    Mirrors Deploy-PimActivatorClient.ps1 / Deploy-PimActivatorIntune.ps1.

.PARAMETER DefaultDurationHours
    Opt-in. Like -DefaultJustification but for the default activation length
    (whole hours, 1..24). OVERWRITES defaultDurationHours on every tenant entry.

.PARAMETER Channel
    Released (default) or Test. Test points at the TEST extension id + updates-test.xml
    unless -ExtensionId / -UpdateUrl are passed explicitly (mirrors
    Deploy-PimActivatorClient.ps1 / Deploy-PimActivatorIntune.ps1).

.PARAMETER MinimumVersion
    Optional ExtensionSettings minimum_version_required: an install BELOW it is disabled
    and pushed to update. Name only a version that is already published and installable.

.PARAMETER BulkThreshold
    Optional tenant-wide bulk-activate confirm threshold (1..100), written as the
    bulkActivateConfirmThreshold DWORD next to tenantCatalog. A per-tenant value inside
    the catalog still wins for that tenant.

.NOTES (existing policies)
    The org's own extension policies are never overwritten: our forcelist /
    sources rows go into the slot already holding our id, else the lowest free slot, and
    our ExtensionSettings entry is MERGED into the org's dictionary. LocalGpo reads the
    machine's HKLM policy keys first; DomainGpo reads the target GPO first and also treats
    the slots in effect on THIS machine as taken (another GPO may own them).

.EXAMPLE
    .\Deploy-PimActivatorHybrid.ps1 -TenantConfigJsonPath \\fs01\pim\tenants.json -Target Json

.EXAMPLE
    # Force the org's activation defaults (justification + duration) on EVERY
    # tenant in the UNC config when applying the local machine policy:
    .\Deploy-PimActivatorHybrid.ps1 -ConfigUncPath \\fs01\pim\tenants.json -Target LocalGpo `
        -DefaultJustification 'Approved change / incident work' -DefaultDurationHours 4

.EXAMPLE
    .\Deploy-PimActivatorHybrid.ps1 -ConfigUncPath \\fs01\pim\tenants.json -Target LocalGpo -WhatIf

.EXAMPLE
    .\Deploy-PimActivatorHybrid.ps1 -ConfigUncPath \\fs01\pim\tenants.json -Target DomainGpo -LinkToOu 'OU=Admins,DC=corp,DC=local'

.NOTES
    -Target LocalGpo / DomainGpo require an elevated (admin) session.
    -Target DomainGpo requires the GroupPolicy module (RSAT) + a writable AD.
    -Target Json needs neither admin nor a domain.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]   # not Mandatory on purpose: bare invocation prints usage instead of prompting
    [Alias('ConfigUncPath')]
    [string]$TenantConfigJsonPath,

    [Parameter()]
    [ValidateSet('Json','DomainGpo','LocalGpo')]
    [string]$Target = 'Json',

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$GpoName = '[PimActivator] client settings',

    [Parameter()]
    [string]$LinkToOu,

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

    # Opt-in: OVERWRITE the per-tenant activation defaults the popup pre-fills,
    # on EVERY tenant entry written to the managed catalog (all <=25 tenants),
    # whether the value came from the -TenantConfigJsonPath file or not.
    # -DefaultJustification sets the justification text; -DefaultDurationHours
    # sets the activation length (whole hours, 1..24). Mirrors the same two
    # params on Deploy-PimActivatorClient.ps1 / Deploy-PimActivatorIntune.ps1.
    # Additive + opt-in: absent => the catalog's own values are kept unchanged.
    [Parameter()]
    [string]$DefaultJustification,

    [Parameter()]
    [ValidateRange(1, 24)]
    [int]$DefaultDurationHours,

    [Parameter()]
    [int]$MaxTenants = 25,

    # IMP-49 r: the channel, the minimum-version floor and the tenant-wide bulk threshold
    # were documented / half-built in the builder but unreachable from this script.
    [Parameter()]
    [ValidateSet('Released','Test')]
    [string]$Channel = 'Released',

    [Parameter()]
    [ValidatePattern('^$|^\d+(\.\d+){0,3}$')]
    [string]$MinimumVersion,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$BulkThreshold
)

$ErrorActionPreference = 'Stop'

# ---- Channel defaults (Test = the SEPARATE test id + update manifest) -------
if ($Channel -eq 'Test') {
    if (-not $PSBoundParameters.ContainsKey('ExtensionId')) { $ExtensionId = 'glldnbmjpdkjemcnficagdhgienfdpoo' }
    if (-not $PSBoundParameters.ContainsKey('UpdateUrl'))   { $UpdateUrl   = 'https://knudsenmorten.github.io/PIM4EntraPS/updates-test.xml' }
}

# Run with no config path -> show syntax/usage instead of prompting for it.
if ([string]::IsNullOrWhiteSpace($TenantConfigJsonPath)) {
    Write-Host "PIM Activator -- Hybrid client setup (on-prem / standalone)" -ForegroundColor Cyan
    Write-Host "Deploy the Activator managed config to hybrid admin machines WITHOUT Intune.`n" -ForegroundColor Gray
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "  .\Deploy-PimActivatorHybrid.ps1 -TenantConfigJsonPath <path|UNC> [-Target Json|DomainGpo|LocalGpo] [options]`n"
    Write-Host "TARGETS:" -ForegroundColor Yellow
    Write-Host "  -Target Json       (default) emit the managed-config JSON artifact (inspect/import) -- no admin/domain"
    Write-Host "  -Target LocalGpo   write the LOCAL machine policy (HKLM) -- standalone/hybrid box, needs elevation"
    Write-Host "  -Target DomainGpo  create/update an AD domain GPO -- needs RSAT GroupPolicy + a writable AD"
    Write-Host "`nKEY PARAMS:" -ForegroundColor Yellow
    Write-Host "  -TenantConfigJsonPath <p>  per-tenant config JSON (<=25 tenants); alias -ConfigUncPath   [required to act]"
    Write-Host "  -LinkToOu <DN>             (DomainGpo) OU to link the GPO to; omit = created but unlinked"
    Write-Host "  -Browser Both|Edge|Chrome  (default Both)   -GpoName <name>   -WhatIf  (preview, no changes)"
    Write-Host "  -DefaultJustification <text>   override the org's default activation justification (ALL tenants) [opt-in]"
    Write-Host "  -DefaultDurationHours <1..24>  override the org's default activation length in hours (ALL tenants) [opt-in]"
    Write-Host "`nEXAMPLES:" -ForegroundColor Yellow
    Write-Host "  .\Deploy-PimActivatorHybrid.ps1 -ConfigUncPath \\fs01\pim\tenants.json -Target Json"
    Write-Host "  .\Deploy-PimActivatorHybrid.ps1 -ConfigUncPath \\fs01\pim\tenants.json -Target LocalGpo -WhatIf"
    Write-Host "  .\Deploy-PimActivatorHybrid.ps1 -ConfigUncPath \\fs01\pim\tenants.json -Target DomainGpo -LinkToOu 'OU=Admins,DC=corp,DC=local'"
    Write-Host "  .\Deploy-PimActivatorHybrid.ps1 -ConfigUncPath \\fs01\pim\tenants.json -Target LocalGpo -DefaultJustification 'Approved change / incident work' -DefaultDurationHours 4"
    Write-Host "`nFull help: Get-Help .\Deploy-PimActivatorHybrid.ps1 -Detailed`n" -ForegroundColor Gray
    return
}

# Pure registry-policy/plan builder -- shared by all three targets so each is
# equivalent to the Intune output. Dot-source defines functions, no side effects.
. (Join-Path $PSScriptRoot '_PimActivatorHybridPolicy.ps1')

Write-Host "=== PIM Activator -- Hybrid client setup (on-prem / standalone) ===" -ForegroundColor Cyan
Write-Host ("Target       : {0}" -f $Target) -ForegroundColor Gray
Write-Host ("Config       : {0}" -f $TenantConfigJsonPath) -ForegroundColor Gray
Write-Host ("Extension id : {0}" -f $ExtensionId) -ForegroundColor Gray
Write-Host ("Browser(s)   : {0}" -f $Browser) -ForegroundColor Gray
Write-Host ''

# ---- 1. Read + parse the UNC/local config JSON ----------------------------
if (-not (Test-Path -LiteralPath $TenantConfigJsonPath)) {
    throw "Tenant config not found at '$TenantConfigJsonPath'. Pass a valid local or UNC path via -TenantConfigJsonPath / -ConfigUncPath."
}
$rawJson = Get-Content -LiteralPath $TenantConfigJsonPath -Raw -Encoding UTF8
$parsed = $null
try {
    $parsed = $rawJson | ConvertFrom-Json
} catch {
    throw "Could not parse '$TenantConfigJsonPath' as JSON: $($_.Exception.Message)"
}

# ---- 2. Validate + normalise (clear failure on bad input) -----------------
$catalog = New-PaHybridConfig -InputObject $parsed -MaxTenants $MaxTenants
$count = @($catalog).Count
# Member-access enumeration (.name), NOT `| ForEach-Object name` -- the latter
# supports ShouldProcess and emits "What if: Retrieve the value..." lines per
# entry when this script runs with -WhatIf.
$catalogNames = @($catalog).name
Write-Host ("Config valid : {0} tenant(s) -- {1}" -f $count, ($catalogNames -join ', ')) -ForegroundColor Green

# ---- 2b. Apply opt-in activation-default overrides ------------------------
# When -DefaultJustification / -DefaultDurationHours are supplied, OVERWRITE
# defaultJustification / defaultDurationHours on EVERY tenant entry (all <=25),
# whether the value came from the UNC/local config file or was absent. The
# extension popup reads these from chrome.storage.managed.tenantCatalog to
# pre-fill the Activate form. Add-Member -Force overwrites the note property if
# the entry already carried one (PS 5.1-safe). Opt-in: absent => unchanged.
if ($PSBoundParameters.ContainsKey('DefaultJustification') -or $PSBoundParameters.ContainsKey('DefaultDurationHours')) {
    foreach ($entry in @($catalog)) {
        if ($PSBoundParameters.ContainsKey('DefaultJustification')) {
            $entry | Add-Member -NotePropertyName defaultJustification -NotePropertyValue $DefaultJustification -Force
        }
        if ($PSBoundParameters.ContainsKey('DefaultDurationHours')) {
            $entry | Add-Member -NotePropertyName defaultDurationHours -NotePropertyValue $DefaultDurationHours -Force
        }
    }
    $_ovr = @()
    if ($PSBoundParameters.ContainsKey('DefaultJustification')) { $_ovr += "justification='$DefaultJustification'" }
    if ($PSBoundParameters.ContainsKey('DefaultDurationHours'))  { $_ovr += "duration=${DefaultDurationHours}h" }
    Write-Host ("Defaults     : OVERRIDDEN on all $count entr$(if($count -eq 1){'y'}else{'ies'}) -- $($_ovr -join ', ')") -ForegroundColor Yellow
}

# ---- 3. Build the shared registry policy plan -----------------------------
# Built once WITHOUT existing state (the Json artifact / previews), then rebuilt by
# LocalGpo / DomainGpo against what is ALREADY in the target, so the org's own
# forcelist rows and ExtensionSettings entries are kept (BUG-182).
$planArgs = @{
    Catalog = $catalog; Browser = $Browser
    ExtensionId = $ExtensionId; UpdateUrl = $UpdateUrl; SourcePattern = $SourcePattern
    MinimumVersion = $MinimumVersion
}
if ($PSBoundParameters.ContainsKey('BulkThreshold')) { $planArgs['BulkThreshold'] = $BulkThreshold }
$plan = Get-PaHybridRegistryPlan @planArgs
Write-Host ("Plan built   : {0} registry value(s) across {1}" -f $plan.Entries.Count, ($plan.Browsers -join ' + ')) -ForegroundColor Green
Write-Host ("Forcelist    : {0}" -f $plan.ForcelistValue) -ForegroundColor Gray
Write-Host ("Source       : {0}" -f $SourcePattern) -ForegroundColor Gray
if ($Channel -ne 'Released') { Write-Host ("Channel      : {0}" -f $Channel) -ForegroundColor Yellow }
if ($MinimumVersion)         { Write-Host ("Min version  : {0}  (installs below it are disabled until they update)" -f $MinimumVersion) -ForegroundColor Yellow }
if ($PSBoundParameters.ContainsKey('BulkThreshold')) { Write-Host ("Bulk confirm : {0} (tenant-wide)" -f $BulkThreshold) -ForegroundColor Gray }
Write-Host ''

# ---- helper: pretty-print the plan (for -WhatIf + DomainGpo preview) -------
function Write-PaPlan {
    param($Plan)
    foreach ($e in $Plan.Entries) {
        $v = "$($e.Value)"
        $shown = if ($v.Length -gt 90) { $v.Substring(0,90) + '...' } else { $v }
        $act = if ($e.PSObject.Properties['Action'] -and $e.Action -and $e.Action -ne 'Set') { " [$($e.Action)]" } else { '' }
        Write-Host ("  [{0}/{1}]{6} HKLM\{2}  {3} ({4}) = {5}" -f $e.Browser, $e.Policy, $e.Key, $e.ValueName, $e.ValueKind, $shown, $act) -ForegroundColor Gray
    }
    foreach ($b in @($Plan.Slots.Keys)) {
        $s = $Plan.Slots[$b]
        Write-Host ("  [{0}] forcelist slot {1}{2}; sources slot {3}; ExtensionSettings layout {4}" -f $b, $s.Forcelist, $(if ($s.ForcelistReused) { ' (reused -- already held our id)' } else { ' (lowest free)' }), $s.Sources, $s.SettingsLayout) -ForegroundColor DarkGray
    }
}

$browserLabels = @($plan.Browsers)

# Read one browser's extension policies out of a DOMAIN GPO (GroupPolicy module).
function Read-PaGpoPolicyState {
    param([string]$Name, [string]$PolicyKey)
    function Read-PaGpoValues([string]$Key) {
        $h = @{}
        $vals = @()
        try { $vals = @(Get-GPRegistryValue -Name $Name -Key "HKLM\$Key" -ErrorAction Stop) } catch { $vals = @() }
        foreach ($v in $vals) {
            if ($v.ValueName -and "$($v.PolicyState)" -ne 'Delete') { $h["$($v.ValueName)"] = "$($v.Value)" }
        }
        return $h
    }
    $rootVals = Read-PaGpoValues $PolicyKey
    return @{
        Forcelist      = Read-PaGpoValues "$PolicyKey\ExtensionInstallForcelist"
        Sources        = Read-PaGpoValues "$PolicyKey\ExtensionInstallSources"
        Allowlist      = Read-PaGpoValues "$PolicyKey\ExtensionInstallAllowlist"
        SettingsValue  = $(if ($rootVals.ContainsKey('ExtensionSettings')) { $rootVals['ExtensionSettings'] } else { $null })
        SettingsSubkey = Read-PaGpoValues "$PolicyKey\ExtensionSettings"
    }
}

# ---- 4. Dispatch by target ------------------------------------------------
switch ($Target) {

    'Json' {
        if (-not $OutputPath) {
            $OutputPath = Join-Path $PSScriptRoot 'pim-activator-hybrid-managed-config.json'
        }
        $artifact = ConvertTo-PaHybridManagedConfigObject -Plan $plan
        $artifactJson = ConvertTo-Json -InputObject $artifact -Depth 12
        if ($PSCmdlet.ShouldProcess($OutputPath, "Write managed-config JSON artifact ($count tenant(s))")) {
            Set-Content -LiteralPath $OutputPath -Value $artifactJson -Encoding UTF8
            Write-Host "[OK] Managed-config artifact written:" -ForegroundColor Green
            Write-Host "       $OutputPath" -ForegroundColor Green
            Write-Host ''
            Write-Host "This artifact is for inspection / manual import. To APPLY the same" -ForegroundColor Gray
            Write-Host "configuration to machines, re-run with -Target LocalGpo (this box) or" -ForegroundColor Gray
            Write-Host "-Target DomainGpo (a domain GPO)." -ForegroundColor Gray
        } else {
            Write-Host "[WhatIf] Would write managed-config artifact to: $OutputPath" -ForegroundColor Yellow
            Write-Host "[WhatIf] It would contain the following registry-equivalent values:" -ForegroundColor Yellow
            Write-PaPlan -Plan $plan
        }
    }

    'LocalGpo' {
        # LOCAL machine policy: write the HKLM policy registry keys directly.
        # No domain needed -- works on a standalone / hybrid box. (No LGPO.exe
        # ships in this repo, so we use the direct HKLM policy-key approach,
        # which is exactly what a Local GPO would materialise on disk.)
        Write-Host "Target LocalGpo: writing HKLM machine policy keys on THIS machine." -ForegroundColor Cyan
        if (-not $WhatIfPreference) {
            $isAdmin = $false
            try {
                $wi = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $wp = New-Object System.Security.Principal.WindowsPrincipal($wi)
                $isAdmin = $wp.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
            } catch { $isAdmin = $false }
            if (-not $isAdmin) {
                throw "-Target LocalGpo writes under HKLM and requires an ELEVATED (Run as administrator) session. Re-run elevated, or use -WhatIf to preview without writing."
            }
        }

        # Rebuild the plan against what is ALREADY in this machine's policy keys, so the
        # org's forcelist rows keep their slots and its ExtensionSettings entries are
        # merged, not replaced (BUG-182). Reading needs no elevation.
        $existingState = @{}
        foreach ($b in $browserLabels) {
            $existingState[$b] = Read-PaPolicyRegistryState -PolicyRoot "HKLM:\SOFTWARE\Policies\$($script:PaHybridVendorPath[$b])"
        }
        $plan = Get-PaHybridRegistryPlan @planArgs -ExistingState $existingState

        foreach ($e in $plan.Entries) {
            $v = "$($e.Value)"
            $opLabel = ("HKLM\{0}  {1} = {2}" -f $e.Key, $e.ValueName, ($(if ($v.Length -gt 60) { $v.Substring(0,60) + '...' } else { $v })))
            $verb = switch ($e.Action) { 'Remove' { 'Remove local machine policy value' } 'RemoveKeyIfEmpty' { 'Remove empty local policy key' } default { 'Set local machine policy' } }
            if ($PSCmdlet.ShouldProcess($opLabel, $verb)) {
                $applied = @(Invoke-PaPolicyRegistryOps -Hive 'HKLM:' -Entries @($e))
                foreach ($line in $applied) { Write-Host ("  [OK] {0}/{1}: {2}" -f $e.Browser, $e.Policy, $line) -ForegroundColor Green }
            } else {
                Write-Host ("  [WhatIf] would {0} HKLM\{1}  {2} ({3})" -f $(if ($e.Action) { $e.Action.ToLower() } else { 'set' }), $e.Key, $e.ValueName, $e.ValueKind) -ForegroundColor Yellow
            }
        }
        foreach ($b in @($plan.Slots.Keys)) {
            $s = $plan.Slots[$b]
            Write-Host ("  [{0}] forcelist slot {1}{2}; ExtensionSettings {3}" -f $b, $s.Forcelist, $(if ($s.ForcelistReused) { ' (reused)' } else { ' (lowest free)' }), $(if ($s.SettingsLayout -eq 'Subkey') { "entry added to the org's per-id ExtensionSettings key" } else { 'merged into the ExtensionSettings dictionary' })) -ForegroundColor DarkGray
        }
        if (-not $WhatIfPreference) {
            Write-Host ''
            Write-Host "[OK] Local machine policy written. Restart Edge/Chrome (or run gpupdate /force" -ForegroundColor Green
            Write-Host "     where applicable) so the browser re-reads chrome.storage.managed." -ForegroundColor Green
        }
    }

    'DomainGpo' {
        # Thin wrapper over the GroupPolicy (RSAT) module. Guard module presence.
        Write-Host "Target DomainGpo: create/update an AD domain Group Policy Object." -ForegroundColor Cyan
        $gpModule = Get-Module -ListAvailable -Name GroupPolicy | Select-Object -First 1
        if (-not $gpModule) {
            $msg = "The GroupPolicy PowerShell module (RSAT: Group Policy Management Tools) is not installed -- required for -Target DomainGpo. Install RSAT, or use -Target LocalGpo (per-machine) / -Target Json (artifact)."
            if ($WhatIfPreference) {
                Write-Host "[WhatIf] $msg" -ForegroundColor Yellow
                Write-Host "[WhatIf] Would create/update GPO '$GpoName' with these registry values:" -ForegroundColor Yellow
                Write-PaPlan -Plan $plan
                if ($LinkToOu) { Write-Host ("[WhatIf] Would link GPO to OU: {0}" -f $LinkToOu) -ForegroundColor Yellow }
                return
            }
            throw $msg
        }

        if ($WhatIfPreference) {
            Write-Host "[WhatIf] Would ensure GPO '$GpoName' exists (New-GPO if missing)." -ForegroundColor Yellow
            Write-Host "[WhatIf] Would Set-GPRegistryValue for each of the following:" -ForegroundColor Yellow
            Write-PaPlan -Plan $plan
            if ($LinkToOu) { Write-Host ("[WhatIf] Would New-GPLink to OU: {0}" -f $LinkToOu) -ForegroundColor Yellow }
            return
        }

        Import-Module GroupPolicy -ErrorAction Stop

        # Ensure the GPO exists (idempotent: get-or-create).
        $gpo = $null
        try { $gpo = Get-GPO -Name $GpoName -ErrorAction Stop } catch { $gpo = $null }
        if (-not $gpo) {
            if ($PSCmdlet.ShouldProcess($GpoName, "New-GPO")) {
                $gpo = New-GPO -Name $GpoName -Comment "PIM Activator client settings ($count tenant(s)) -- created by Deploy-PimActivatorHybrid.ps1"
                Write-Host ("  [OK] Created GPO '{0}' (id {1})" -f $GpoName, $gpo.Id) -ForegroundColor Green
            }
        } else {
            Write-Host ("  GPO '{0}' already exists (id {1}) -- updating values." -f $GpoName, $gpo.Id) -ForegroundColor Gray
        }

        # BUG-182: rebuild the plan against (a) what THIS GPO already carries and (b) the
        # policy in effect on THIS machine, which is where the org's OTHER GPOs show up.
        #   * list slots: reuse the GPO's slot holding our id, else the lowest slot free in
        #     BOTH -- a slot another GPO owns is never taken (it would override that row).
        #   * ExtensionSettings is ONE value per browser: the GPO with the higher precedence
        #     replaces the other's WHOLE dictionary. If the GPO has none yet but the machine
        #     has the org's entries, seed from them so this GPO does not drop the org's '*'
        #     defaults where it wins -- and say loudly that it is a snapshot.
        $existingState = @{}
        foreach ($b in $browserLabels) {
            $polKey = "SOFTWARE\Policies\$($script:PaHybridVendorPath[$b])"
            $gpoState = Read-PaGpoPolicyState -Name $GpoName -PolicyKey $polKey
            $local    = Read-PaPolicyRegistryState -PolicyRoot "HKLM:\$polKey"
            $gpoState['ForcelistReserved'] = @($local.Forcelist.Keys | Where-Object { -not $gpoState.Forcelist.ContainsKey($_) -and ("$($local.Forcelist[$_])" -notlike "$ExtensionId;*") })
            $gpoState['SourcesReserved']   = @($local.Sources.Keys   | Where-Object { -not $gpoState.Sources.ContainsKey($_) -and ("$($local.Sources[$_])" -ine $SourcePattern) })
            $gpoHasSettings = ("$($gpoState.SettingsValue)".Trim()) -or $gpoState.SettingsSubkey.Count -gt 0
            $localForeignSub = @($local.SettingsSubkey.Keys | Where-Object { $_ -ne $ExtensionId })
            if (-not $gpoHasSettings -and $localForeignSub.Count -gt 0) {
                # The org uses the per-id layout: values merge across GPOs by name. Adding
                # only ours in the same layout keeps theirs.
                $gpoState['SettingsSubkey'] = @{ '__pima_layout_probe__' = '{}' }
            } elseif (-not $gpoHasSettings -and "$($local.SettingsValue)".Trim()) {
                $gpoState['SettingsValue'] = $local.SettingsValue
                Write-Warning ("[{0}] ExtensionSettings: this GPO has none yet; seeded it from the ExtensionSettings in effect on THIS machine so the org's entries are kept where this GPO wins precedence. It is a SNAPSHOT: a later change to the org's own ExtensionSettings GPO must keep the '{1}' entry (or re-run this script)." -f $b, $ExtensionId)
            }
            $existingState[$b] = $gpoState
        }
        $plan = Get-PaHybridRegistryPlan @planArgs -ExistingState $existingState
        # The probe only chose the layout; it is not a real value and must never be written.
        $plan.Entries = @($plan.Entries | Where-Object { $_.ValueName -ne '__pima_layout_probe__' })

        foreach ($e in $plan.Entries) {
            $fullKey = "HKLM\$($e.Key)"
            $regType = if ($e.ValueKind -eq 'Dword') { 'DWord' } else { 'String' }
            switch ($e.Action) {
                'Remove' {
                    if ($PSCmdlet.ShouldProcess(("{0}  {1}" -f $fullKey, $e.ValueName), "Remove-GPRegistryValue")) {
                        Remove-GPRegistryValue -Name $GpoName -Key $fullKey -ValueName $e.ValueName -ErrorAction SilentlyContinue | Out-Null
                        Write-Host ("  [OK] {0}/{1} removed {2}\{3}" -f $e.Browser, $e.Policy, $e.Key, $e.ValueName) -ForegroundColor Green
                    }
                }
                'RemoveKeyIfEmpty' { }   # an empty key in a GPO is inert -- nothing to do
                default {
                    if ($PSCmdlet.ShouldProcess(("{0}  {1}" -f $fullKey, $e.ValueName), "Set-GPRegistryValue")) {
                        Set-GPRegistryValue -Name $GpoName -Key $fullKey -ValueName $e.ValueName -Type $regType -Value $e.Value | Out-Null
                        Write-Host ("  [OK] {0}/{1} -> {2}\{3}" -f $e.Browser, $e.Policy, $e.Key, $e.ValueName) -ForegroundColor Green
                    }
                }
            }
        }
        foreach ($b in @($plan.Slots.Keys)) {
            $s = $plan.Slots[$b]
            Write-Host ("  [{0}] forcelist slot {1}{2}; ExtensionSettings layout {3}" -f $b, $s.Forcelist, $(if ($s.ForcelistReused) { ' (reused)' } else { ' (lowest free in this GPO and on this machine)' }), $s.SettingsLayout) -ForegroundColor DarkGray
        }
        Write-Host "  Verify on a target machine: gpresult /h + edge://policy -- another GPO writing the SAME slot number would still win by precedence." -ForegroundColor Yellow

        if ($LinkToOu) {
            if ($PSCmdlet.ShouldProcess($LinkToOu, "New-GPLink '$GpoName'")) {
                try {
                    New-GPLink -Name $GpoName -Target $LinkToOu -LinkEnabled Yes -ErrorAction Stop | Out-Null
                    Write-Host ("  [OK] Linked GPO to OU {0}" -f $LinkToOu) -ForegroundColor Green
                } catch {
                    Write-Warning "Could not link GPO to OU '$LinkToOu' (it may already be linked): $($_.Exception.Message)"
                }
            }
        } else {
            Write-Host ''
            Write-Host "GPO is UNLINKED. Link it in GPMC (or re-run with -LinkToOu <DN>) to apply to a target OU." -ForegroundColor Yellow
        }
    }
}

Write-Host ''
Write-Host "Done ($Target)." -ForegroundColor Green
