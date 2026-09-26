#Requires -Version 5.1
<#
.SYNOPSIS
    Force-install the PIM Activator browser extension (Edge, Chrome, or both)
    via Chromium enterprise policy. Designed for unattended Intune / Group
    Policy / Configuration Manager rollout.

.DESCRIPTION
    Writes the Chromium policies that tell the browser to install + auto-update
    the extension from the given -UpdateUrl on next launch
    (ExtensionInstallForcelist, ExtensionInstallSources, ExtensionSettings), plus
    the tenant catalog the popup reads from chrome.storage.managed.

    Per-machine (-Scope Machine, default, HKLM, requires admin) or per-user
    (-Scope User, HKCU, no admin). Both browsers read the SAME key names
    under different roots:
      Edge   : SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist
      Chrome : SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist

    The tenant catalog (tenant id + client id per tenant) goes to
    <policy root>\3rdparty\extensions\<id>\policy\tenantCatalog, which the popup's
    "Use centrally deployed" option reads. Users can instead import a catalog or
    type one tenant in the popup's setup wizard.

    Re-runnable. Safe under SYSTEM. Exit code 0 on success; 1 when the tenant
    catalog was asked for but could not be written (the policies are still written).

.PARAMETER ExtensionId
    32-char Chromium extension id (lowercase a-p). Required.

.PARAMETER UpdateUrl
    The update.xml URL the extension auto-updates from. For the
    PIM4EntraPS-hosted CRX this is
    https://knudsenmorten.github.io/PIM4EntraPS/updates.xml

.PARAMETER Scope
    'Machine' (default, HKLM, requires admin, force-installs for every user
    on the box) or 'User' (HKCU, no admin required, current-user only, no
    Intune conflict).

    On Intune-managed devices the HKLM ExtensionInstallForcelist value will
    be overwritten by Intune's policy on next sync -- use Intune's own
    Settings Catalog entry instead (see Deploy-PimActivatorIntune.ps1).

.PARAMETER Browser
    'Edge', 'Chrome', or 'Both' (default).

.PARAMETER Uninstall
    Remove ONLY what this script wrote for this extension id: our forcelist /
    allowlist rows, our install-source row (kept while another forcelist row still
    installs from that host), our ExtensionSettings entry and our 3rdparty policy
    tree. The org's own rows and ExtensionSettings entries are left in place.

.PARAMETER ClientId
    Optional. The PIM Activator app registration's Application (client) id for the
    tenant catalog. When omitted, the app is resolved by EXACT display name
    (-AppDisplayName) and must be unique -- never "the first app whose name starts
    with PIM Activator".

.PARAMETER AppDisplayName
    Exact display name used to find the app registration when -ClientId is not given.
    Default 'PIM Activator' (what Deploy-PimActivatorBackend.ps1 creates).

.NOTES (existing policies)
    The org's own extension policies are never overwritten: our rows go
    into the slot already holding our id, else the lowest free slot, and our
    ExtensionSettings entry is MERGED into the org's dictionary. Same layout and the
    same code (_PimActivatorHybridPolicy.ps1) as Deploy-PimActivatorHybrid.ps1 -Target
    LocalGpo, so the two writers cannot disagree. That file must sit next to this one.

.EXAMPLE
    # Default per-machine install (HKLM, requires admin, applies to every
    # user on this box):
    .\Deploy-PimActivatorClient.ps1

    # On next Edge / Chrome launch the extension installs for every user.
    # Each user then opens the popup, picks the centrally deployed tenant,
    # signs in, and starts activating PIM eligibilities.

.EXAMPLE
    # Current-user install (HKCU, no admin needed, won't conflict with
    # Intune-pushed policy):
    .\Deploy-PimActivatorClient.ps1 -Scope User

.EXAMPLE
    # Edge only:
    .\Deploy-PimActivatorClient.ps1 `
        -ExtensionId 'eheocihmlppcophaeakmdenhgcookkab' `
        -UpdateUrl   'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml' `
        -Browser Edge

.EXAMPLE
    # Force the org's activation defaults (justification + duration) for every
    # tenant entry written -- overrides the auto-discover fallback ('Change in
    # infrastructure' / 8h) or any value carried in -CatalogJsonPath:
    .\Deploy-PimActivatorClient.ps1 `
        -DefaultJustification 'Approved change / incident work' `
        -DefaultDurationHours 4

.EXAMPLE
    # Server: cap auto-activation at 3 groups on THIS machine for the TEST extension, leaving the rest as is.
    # 0 turns auto-activation off; -1 removes the cap again.
    .\Deploy-PimActivatorClient.ps1 -Channel Test -AutoActivateMaxGroups 3

.EXAMPLE
    # Uninstall (removes only OUR policy rows / entries; the extension
    # self-removes on next launch):
    .\Deploy-PimActivatorClient.ps1 `
        -ExtensionId 'eheocihmlppcophaeakmdenhgcookkab' `
        -Uninstall

.EXAMPLE
    # Intune managed-policy equivalent (per-user, no script needed):
    # Microsoft Edge -> Configuration profile -> Settings catalog
    # -> Extensions -> Configure which extensions are installed silently
    # -> Add: eheocihmlppcophaeakmdenhgcookkab;https://knudsenmorten.github.io/PIM4EntraPS/updates.xml

.NOTES
    Tested on Edge for Business 120+ and Chrome 120+. Both browsers pick up
    policy changes on next launch; no reboot required.
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    # Extension id is constant across every install of this distribution
    # (derived from manifest.json "key" field). Default so the vanilla call
    # works without docs lookup. Override only if you fork the extension.
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId = 'eheocihmlppcophaeakmdenhgcookkab',

    # Update manifest is hosted on the published gh-pages of the upstream
    # repo. Default so single-tenant operators don't need to type the URL.
    [Parameter(ParameterSetName = 'Install')]
    [string]$UpdateUrl = 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml',

    # Update channel. 'Test' targets the test extension id + updates-test.xml so this
    # writes the SEPARATE test forcelist + managed catalog (same tenant catalog as
    # released; only the id/URL differ). 'Released' (default) is unchanged. Mirrors
    # Update-PimActivator-Extension.ps1 / Deploy-PimActivatorIntune.ps1.
    [Parameter()]
    [ValidateSet('Released','Test')]
    [string]$Channel = 'Released',

    [Parameter()]
    [ValidateSet('Machine', 'User')]
    [string]$Scope = 'Machine',

    [Parameter()]
    [ValidateSet('Edge', 'Chrome', 'Both')]
    [string]$Browser = 'Both',

    # Optional path to the tenant catalog JSON. v2.4.111 removed the previous
    # sibling-file default ('discovered-tenant-catalog.json' next to this
    # script) after a customer-tenant incident where that file -- left over
    # in a working dir from a different tenant -- got picked up silently and
    # written 2linkIT's tenant id + client id into the customer's registry.
    # Now: when omitted (the common case), the script auto-discovers the
    # tenant + PIM Activator app registration from the LIVE Microsoft Graph
    # context on the box (Connect-MgGraph runs interactively if not already
    # connected, exactly like Deploy-PimActivatorIntune.ps1's auto-discover).
    # That guarantees the catalog matches the tenant the operator is signed
    # into right now -- never a stale file from elsewhere. Pass an explicit
    # path to override, or -SkipTenantCatalog to skip the catalog write
    # entirely (still writes the forcelist / sources / settings policies).
    [Parameter(ParameterSetName = 'Install')]
    [string]$CatalogJsonPath,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$SkipTenantCatalog,

    # Opt-in: also write ExtensionInstallAllowlist for our id. Only useful
    # in environments where the admin has set ExtensionInstallBlocklist='*'.
    # Default OFF since this caused "can't install any other extension" on
    # some Chromium versions where the presence of an Allowlist key with
    # a single entry was interpreted as "deny everything else" (2026-06-10).
    [Parameter(ParameterSetName = 'Install')]
    [switch]$WriteAllowlist,

    # Override the per-tenant activation defaults the popup pre-fills.
    # -DefaultJustification sets the justification text; -DefaultDurationHours
    # sets the activation length (whole hours). When supplied they OVERWRITE
    # whatever the resolved catalog carried -- the value from -CatalogJsonPath
    # or the auto-discover fallback ('Change in infrastructure' / 8h) -- on
    # EVERY tenant entry written to the registry. Omit them to keep the
    # catalog's own values. Additive + opt-in: absent => nothing changes.
    [Parameter(ParameterSetName = 'Install')]
    [string]$DefaultJustification,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(1, 24)]
    [int]$DefaultDurationHours,

    # Per-DEVICE cap on auto-activation (2026-09-23): writes ...\3rdparty\extensions\<id>\policy\
    # autoActivateMaxGroups (REG_DWORD). 0 = auto-activation off on this machine; N = at most N groups;
    # -1 = remove the value (no limit). Not passed = the machine's current value is left alone.
    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(-1, 100)]
    [int]$AutoActivateMaxGroups,

    [Parameter(ParameterSetName = 'Install')]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'Install')]
    [string]$AppDisplayName = 'PIM Activator',

    [Parameter(Mandatory, ParameterSetName = 'Uninstall')]
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

# ---- Channel defaults (Test writes the SEPARATE test forcelist + catalog) ----
if ($Channel -eq 'Test') {
    if (-not $PSBoundParameters.ContainsKey('ExtensionId')) { $ExtensionId = 'glldnbmjpdkjemcnficagdhgienfdpoo' }
    if (-not $PSBoundParameters.ContainsKey('UpdateUrl'))   { $UpdateUrl   = 'https://knudsenmorten.github.io/PIM4EntraPS/updates-test.xml' }
    Write-Host "Channel = TEST -> id $ExtensionId, $UpdateUrl" -ForegroundColor Yellow
}

# Troubleshooting banner (script + solution + module + PS versions). Guarded:
# this script is sometimes copied to a client box standalone, without the
# sibling _PimActivatorAuth.ps1 -- skip the banner rather than break.
$_authLib = Join-Path $PSScriptRoot '_PimActivatorAuth.ps1'
if (Test-Path $_authLib) {
    . $_authLib
    Show-PimActivatorBanner -ScriptName 'Deploy-PimActivatorClient' -GraphModules 'Microsoft.Graph.Authentication' -GraphOptional
}

# HKLM requires admin. Fail fast with a clear message instead of letting
# New-Item fault out mid-write with an opaque registry-permission error.
if ($Scope -eq 'Machine') {
    $isAdmin = ([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "-Scope Machine writes to HKLM and requires elevation. Re-run from an elevated PowerShell session, or pass -Scope User to write only the current-user HKCU forcelist."
    }
}

# ---------------------------------------------------------------------------
# Build the list of policy roots we'll operate on, one per targeted browser.
# Edge   : SOFTWARE\Policies\Microsoft\Edge
# Chrome : SOFTWARE\Policies\Google\Chrome
# Both browsers read identical key names under their own root.
# ---------------------------------------------------------------------------

$hiveRoot = if ($Scope -eq 'Machine') { 'HKLM:' } else { 'HKCU:' }

$policyRoots = New-Object System.Collections.Generic.List[object]
if ($Browser -in @('Edge','Both')) {
    $policyRoots.Add([pscustomobject]@{ Name = 'Edge';   Path = "$hiveRoot\SOFTWARE\Policies\Microsoft\Edge"; Rel = 'SOFTWARE\Policies\Microsoft\Edge' })
}
if ($Browser -in @('Chrome','Both')) {
    $policyRoots.Add([pscustomobject]@{ Name = 'Chrome'; Path = "$hiveRoot\SOFTWARE\Policies\Google\Chrome"; Rel = 'SOFTWARE\Policies\Google\Chrome' })
}

function New-PolicyKey {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
}

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [Microsoft.Win32.RegistryValueKind]$Kind = [Microsoft.Win32.RegistryValueKind]::String)
    New-PolicyKey -Path $Path
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Kind -Force | Out-Null
}

# ---------------------------------------------------------------------------
# WHERE our rows go (BUG-182 / BUG-220). The list policies are SHARED with the
# org's own force-installed extensions, and ExtensionSettings is ONE dictionary
# per browser. The slot + merge logic lives in _PimActivatorHybridPolicy.ps1 and
# is the same code Deploy-PimActivatorHybrid.ps1 -Target LocalGpo runs, so the
# two writers produce one layout.
#
# The slot USED to be ([Math]::Abs($ExtensionId.GetHashCode()) % 9000) + 1000.
# String.GetHashCode() is randomised per PROCESS on .NET Core (pwsh 7), so every
# run picked a different slot: re-runs piled up duplicate rows and -Uninstall
# looked in the wrong slot and removed nothing (mgmt1, 2026-09-18: four rows for
# the released id at 1590 / 3077 / 5148 / 7772).
# Now: our row goes in the lowest slot nobody else uses (reusing ours if it is
# already there); every other row carrying our id is removed.
# ---------------------------------------------------------------------------
$_policyLib = Join-Path $PSScriptRoot '_PimActivatorHybridPolicy.ps1'
if (-not (Test-Path -LiteralPath $_policyLib)) {
    throw "_PimActivatorHybridPolicy.ps1 was not found next to this script ($PSScriptRoot). It holds the slot + ExtensionSettings merge logic that keeps the organisation's own extension policies intact -- copy it alongside Deploy-PimActivatorClient.ps1 and re-run. Nothing was written."
}
. $_policyLib

# (Matchers are built by the library, never with .GetNewClosure() -- see New-PaRowMatcher.)
$isOurForcelistRow = New-PaRowMatcher -ExtensionId $ExtensionId
$isOurAllowRow     = New-PaRowMatcher -Exact $ExtensionId

function Get-PaSourcePatternFromUrl {
    param([string]$Url)
    try {
        $u = [Uri]::new($Url)
        if ($u.Scheme -and $u.Host) { return "$($u.Scheme)://$($u.Host)/*" }
    } catch { }
    return $null
}

if ($Uninstall) {
    Write-Host "Removing PIM Activator force-install ($Scope scope, $Browser) for extension $ExtensionId..." -ForegroundColor Yellow
    Write-Host "  Only OUR rows / entries are removed; the organisation's own extension policies stay." -ForegroundColor DarkGray
    $ourSource = Get-PaSourcePatternFromUrl $UpdateUrl
    $uninstallProblems = 0

    foreach ($root in $policyRoots) {
        $state   = Read-PaPolicyRegistryState -PolicyRoot $root.Path
        $entries = New-Object System.Collections.Generic.List[object]

        # Forcelist + allowlist: every row that carries OUR id (any slot, incl. the old
        # hashed 1000-9999 ones), and the hole it leaves is refilled.
        $fl = Get-PaPolicyListPlan -Existing $state.Forcelist -Value "$ExtensionId;$UpdateUrl" -IsOurs $isOurForcelistRow -Remove
        foreach ($e in (ConvertTo-PaPolicyEntries -Browser $root.Name -Policy 'Forcelist' -PolicyKey $root.Rel -ListKeyName 'ExtensionInstallForcelist' -ListOps $fl.Ops)) { $entries.Add($e) }
        $al = Get-PaPolicyListPlan -Existing $state.Allowlist -Value $ExtensionId -IsOurs $isOurAllowRow -Remove
        foreach ($e in (ConvertTo-PaPolicyEntries -Browser $root.Name -Policy 'Allowlist' -PolicyKey $root.Rel -ListKeyName 'ExtensionInstallAllowlist' -ListOps $al.Ops)) { $entries.Add($e) }

        # Install source: a pattern is not id-tagged, so it is removed only when no
        # REMAINING forcelist row still installs from that host (the test channel, or
        # the org's own extension served from the same site).
        if ($ourSource) {
            $stillNeeded = @($fl.Final.Values | Where-Object {
                $u = ("$_" -split ';', 2)[1]
                $u -and ((Get-PaSourcePatternFromUrl $u) -ieq $ourSource)
            }).Count -gt 0
            $keep = if ($stillNeeded) { { $true } } else { $null }
            $sr = Get-PaPolicyListPlan -Existing $state.Sources -Value $ourSource -Remove -KeepOnRemove $keep
            foreach ($e in (ConvertTo-PaPolicyEntries -Browser $root.Name -Policy 'Sources' -PolicyKey $root.Rel -ListKeyName 'ExtensionInstallSources' -ListOps $sr.Ops)) { $entries.Add($e) }
            if ($stillNeeded) { Write-Host "  [$($root.Name)] install source $ourSource kept -- another forcelist row still installs from it" -ForegroundColor DarkGray }
        }

        # ExtensionSettings: take OUR id out of the dictionary / per-id key only.
        $es = Get-PaExtensionSettingsPlan -ExistingValue $state.SettingsValue -ExistingSubkey $state.SettingsSubkey -ExtensionId $ExtensionId -Remove
        if ($es.Error) { Write-Warning "  [$($root.Name)] $($es.Error)"; $uninstallProblems++ }
        foreach ($e in (ConvertTo-PaPolicyEntries -Browser $root.Name -Policy 'Settings' -PolicyKey $root.Rel -SettingsOps $es.Ops)) { $entries.Add($e) }

        foreach ($line in @(Invoke-PaPolicyRegistryOps -Hive $hiveRoot -Entries $entries.ToArray())) {
            Write-Host "  [$($root.Name)] $line" -ForegroundColor DarkGray
        }

        # The 3rdparty\extensions\<id> tree (tenantCatalog) is keyed by OUR id -- all ours.
        $catalogRoot = Join-Path $root.Path "3rdparty\extensions\$ExtensionId"
        if (Test-Path -LiteralPath $catalogRoot) {
            Remove-Item -LiteralPath $catalogRoot -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  [$($root.Name)] removed 3rdparty\extensions\$ExtensionId" -ForegroundColor DarkGray
        }
    }

    if ($uninstallProblems -gt 0) {
        Write-Warning "Uninstall finished with $uninstallProblems ExtensionSettings value(s) left untouched (see above) -- remove the '$ExtensionId' entry from them by hand."
        exit 1
    }
    Write-Host "Done. Restart $Browser to apply." -ForegroundColor Green
    return
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

if ($Scope -eq 'Machine') {
    Write-Host ""
    Write-Host "  -Scope Machine (default) -- writing to HKLM, applies to every user on this box." -ForegroundColor Cyan
    Write-Host "  Note: on Intune-managed devices, the Intune-pushed ExtensionInstallForcelist will" -ForegroundColor DarkGray
    Write-Host "        overwrite this on next sync -- use Deploy-PimActivatorIntune.ps1 there." -ForegroundColor DarkGray
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "  -Scope User selected -- HKCU-only. Won't affect other users or Intune." -ForegroundColor Green
    Write-Host ""
}

Write-Host "Installing PIM Activator force-install policy ($Scope scope, $Browser)..." -ForegroundColor Cyan
# Only echo ExtensionId / UpdateUrl when the operator explicitly overrode the
# baked-in defaults. v2.4.57 made both defaultable so a zero-arg invocation
# Just Works -- noise in the output (and the operator wondering "did I have
# to pass that?") is a downgrade.
$_defaultExtId  = 'eheocihmlppcophaeakmdenhgcookkab'
$_defaultUpdUrl = 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml'
if ($ExtensionId -ne $_defaultExtId)  { Write-Host "  ExtensionId : $ExtensionId  (overridden -- default is $_defaultExtId)" -ForegroundColor Yellow }
if ($UpdateUrl   -ne $_defaultUpdUrl) { Write-Host "  UpdateUrl   : $UpdateUrl  (overridden -- default is $_defaultUpdUrl)" -ForegroundColor Yellow }

# Derive the source-host pattern from the update URL so a customer who
# self-hosts the CRX (different update.xml host) gets the right allow
# pattern instead of a stale knudsenmorten.github.io one. $null (unparseable)
# => ExtensionInstallSources is skipped.
$sourcePattern = Get-PaSourcePatternFromUrl $UpdateUrl

# ---- Plan EVERY browser's policy writes first, write nothing until all are known ----
# A plan that cannot be made safely (an ExtensionSettings value we cannot parse) stops
# the run BEFORE any browser is touched -- fail closed, never a half-applied policy.
$ourSettings = New-PaExtensionSettingsEntry -UpdateUrl $UpdateUrl
$policyPlans = @{}
foreach ($root in $policyRoots) {
    $state   = Read-PaPolicyRegistryState -PolicyRoot $root.Path
    $entries = New-Object System.Collections.Generic.List[object]
    $notes   = New-Object System.Collections.Generic.List[string]

    # 1. ExtensionInstallForcelist -- "<extension-id>;<update-url>" in the slot that
    #    already holds our id (reused, any stray duplicates removed), else the lowest
    #    free slot. The org's rows are never overwritten.
    $fl = Get-PaPolicyListPlan -Existing $state.Forcelist -Value "$ExtensionId;$UpdateUrl" -IsOurs $isOurForcelistRow
    foreach ($e in (ConvertTo-PaPolicyEntries -Browser $root.Name -Policy 'Forcelist' -PolicyKey $root.Rel -ListKeyName 'ExtensionInstallForcelist' -ListOps $fl.Ops)) { $entries.Add($e) }
    $notes.Add("ExtensionInstallForcelist slot $($fl.Slot) $(if ($fl.Reused) { '(reused -- already held our id)' } else { '(lowest free slot)' }) = $ExtensionId;$UpdateUrl")

    # 2. ExtensionInstallAllowlist -- OPT-IN ONLY (-WriteAllowlist).
    #
    # 2026-06-10: this used to be written by default as "belt and braces"
    # in case the admin had ExtensionInstallBlocklist='*'. In practice it
    # backfired -- on some Chromium versions an Allowlist with ONLY one
    # id is interpreted as "deny every other extension" even without a
    # '*' blocklist in play. Symptom: users couldn't install any other
    # extension. Forcelist already overrides the blocklist for our id,
    # so the Allowlist write was redundant. Now only written when the
    # operator explicitly opts in for an environment that DOES set a
    # '*' blocklist.
    if ($WriteAllowlist) {
        $al = Get-PaPolicyListPlan -Existing $state.Allowlist -Value $ExtensionId -IsOurs $isOurAllowRow
        foreach ($e in (ConvertTo-PaPolicyEntries -Browser $root.Name -Policy 'Allowlist' -PolicyKey $root.Rel -ListKeyName 'ExtensionInstallAllowlist' -ListOps $al.Ops)) { $entries.Add($e) }
        $notes.Add("ExtensionInstallAllowlist slot $($al.Slot) = $ExtensionId  [opt-in, -WriteAllowlist]")
    }

    # 3. ExtensionInstallSources -- allow the host the CRX + updates.xml are served
    #    from. Required if the admin has restricted ExtensionInstallSources (some
    #    hardened baselines do). A row with exactly our pattern is reused.
    if ($sourcePattern) {
        $sr = Get-PaPolicyListPlan -Existing $state.Sources -Value $sourcePattern
        foreach ($e in (ConvertTo-PaPolicyEntries -Browser $root.Name -Policy 'Sources' -PolicyKey $root.Rel -ListKeyName 'ExtensionInstallSources' -ListOps $sr.Ops)) { $entries.Add($e) }
        $notes.Add("ExtensionInstallSources slot $($sr.Slot) = $sourcePattern")
    }

    # 4. ExtensionSettings -- our entry pre-grants runtime_allowed_hosts for THIS
    #    extension only (the 2026-06-10 fleet-freeze fix: an auto-update that looked
    #    like a permission expansion was silently disabled; the policy-level grant
    #    stops that gate firing). It is MERGED into the org's ExtensionSettings --
    #    their '*' defaults and other extensions' entries are kept (BUG-182).
    #    Layout: the documented single REG_SZ 'ExtensionSettings' JSON under the policy
    #    root, UNLESS the org already uses the per-id key layout (<root>\ExtensionSettings
    #    with one value per id), in which case our value is added next to theirs. A
    #    per-id key holding only OUR id (what this script used to write) is removed,
    #    because Chromium lets that key shadow the whole root value.
    $es = Get-PaExtensionSettingsPlan -ExistingValue $state.SettingsValue -ExistingSubkey $state.SettingsSubkey -ExtensionId $ExtensionId -Settings $ourSettings
    if ($es.Error) { throw "[$($root.Name)] $($es.Error)" }
    foreach ($e in (ConvertTo-PaPolicyEntries -Browser $root.Name -Policy 'Settings' -PolicyKey $root.Rel -SettingsOps $es.Ops)) { $entries.Add($e) }
    $notes.Add("ExtensionSettings: our entry $(if ($es.Layout -eq 'Subkey') { "added to the org's per-id ExtensionSettings key" } else { 'merged into the ExtensionSettings dictionary' }) (runtime_allowed_hosts = <all_urls>)")

    $policyPlans[$root.Name] = [pscustomobject]@{ Entries = $entries.ToArray(); Notes = $notes.ToArray() }
}
$catalogMissing = New-Object System.Collections.Generic.List[string]

foreach ($root in $policyRoots) {
    Write-Host ""
    Write-Host "  [$($root.Name)] writing under $($root.Path)" -ForegroundColor Cyan

    $pp = $policyPlans[$root.Name]
    foreach ($line in @(Invoke-PaPolicyRegistryOps -Hive $hiveRoot -Entries $pp.Entries)) {
        Write-Host "    -> $line" -ForegroundColor DarkGray
    }
    foreach ($n in $pp.Notes) { Write-Host "    -> $n" -ForegroundColor DarkGray }

    # 5. Tenant catalog (chrome.storage.managed.tenantCatalog).
    #
    # On Intune-managed boxes the catalog arrives through the custom ADMX
    # template (Group Policy CSP), surfacing under chrome.storage.managed
    # so the popup's 'Use centrally deployed' tile turns active. On
    # non-Intune boxes the same data path -- the chrome.storage.managed
    # registry namespace -- is directly writable from an admin shell:
    #
    #   <policy-root>\3rdparty\extensions\<EXT_ID>\policy\
    #     tenantCatalog (REG_SZ) = minified JSON array of tenant entries
    #
    # The extension reads chrome.storage.managed.tenantCatalog at popup
    # open time. Same effect as Intune ADMX delivery, just locally pushed.
    # Skipped when -SkipTenantCatalog OR when the JSON file isn't present.
    if ($SkipTenantCatalog) {
        Write-Host "    -> tenantCatalog skipped (-SkipTenantCatalog)" -ForegroundColor DarkGray
    } else {
        # Resolve the catalog object: explicit file > live Entra auto-discover.
        # No more silent fallback to a sibling 'discovered-tenant-catalog.json' --
        # see v2.4.111 release notes for the cross-tenant-leak incident.
        $catalog = $null
        if ($CatalogJsonPath -and (Test-Path -LiteralPath $CatalogJsonPath)) {
            try {
                $catalogRaw = Get-Content -LiteralPath $CatalogJsonPath -Raw -Encoding UTF8
                $catalog    = $catalogRaw | ConvertFrom-Json
                Write-Host "    -> catalog source: -CatalogJsonPath '$CatalogJsonPath'" -ForegroundColor DarkGray
            } catch {
                Write-Warning "    -CatalogJsonPath parse failed: $($_.Exception.Message). Will try live Entra auto-discover instead."
                $catalog = $null
            }
        } elseif ($CatalogJsonPath) {
            Write-Warning "    -CatalogJsonPath '$CatalogJsonPath' not found. Falling back to live Entra auto-discover."
        }

        if (-not $catalog) {
            # Live auto-discover from the connected Microsoft Graph context.
            # Mirrors Deploy-PimActivatorIntune.ps1's discover logic so the same
            # catalog ends up in registry for non-Intune-managed boxes.
            if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
                Write-Warning "    Microsoft.Graph.Authentication module not installed; tenantCatalog skipped. Install with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
            } else {
                Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
                $ctx = Get-MgContext -ErrorAction SilentlyContinue
                if (-not $ctx) {
                    Write-Host "    -> connecting to Microsoft Graph (interactive) to auto-discover tenant + PIM Activator app..." -ForegroundColor Cyan
                    try { Connect-MgGraph -Scopes 'Organization.Read.All','Application.Read.All' -NoWelcome -ErrorAction Stop; $ctx = Get-MgContext } catch { Write-Warning "    Connect-MgGraph failed: $($_.Exception.Message). tenantCatalog skipped."; $ctx = $null }
                }
                if ($ctx) {
                    try {
                        $orgResp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization' -ErrorAction Stop
                        $org = @($orgResp.value)[0]
                        # BUG-220: select the app DETERMINISTICALLY -- by -ClientId, else by
                        # EXACT display name, and refuse when that is not unique. It used to
                        # take the first app whose name merely STARTS WITH 'PIM Activator'
                        # (Graph returns no guaranteed order), so a tenant holding e.g. a
                        # 'PIM Activator (old)' registration could get the wrong clientId
                        # baked into every admin's browser.
                        $appFilter = if ($ClientId) { "appId eq '$ClientId'" } else { "displayName eq '$($AppDisplayName -replace "'", "''")'" }
                        $appResp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/v1.0/applications?`$filter={0}&`$select=appId,displayName" -f [uri]::EscapeDataString($appFilter)) -ErrorAction Stop
                        $pick = Select-PaActivatorApp -Apps @($appResp.value) -ClientId $ClientId -DisplayName $AppDisplayName
                        $app = $pick.App
                        if (-not $org -or -not $app) {
                            $why = if (-not $org) { 'the organization could not be read' } else { $pick.Error }
                            Write-Warning "    Live Entra auto-discover incomplete: $why. tenantCatalog skipped."
                        } else {
                            $catalog = [pscustomobject]@{
                                name                  = $org.displayName
                                tenantId              = $org.id
                                clientId              = $app.appId
                                defaultJustification  = 'Change in infrastructure'
                                defaultDurationHours  = 8
                            }
                            Write-Host ("    -> catalog source: live Entra auto-discover  (tenant '{0}' / {1}  clientId {2})" -f $org.displayName, $org.id, $app.appId) -ForegroundColor Cyan
                        }
                    } catch {
                        Write-Warning "    Live Entra auto-discover failed: $($_.Exception.Message). tenantCatalog skipped."
                    }
                }
            }
        }

        # Apply explicit activation-default overrides (-DefaultJustification /
        # -DefaultDurationHours) onto every resolved tenant entry, whether the
        # catalog came from -CatalogJsonPath or live auto-discover. The popup
        # reads these from chrome.storage.managed.tenantCatalog and pre-fills
        # the Activate form with them. Add-Member -Force overwrites the property
        # if the entry already carried one. Opt-in: untouched unless passed.
        if ($catalog -and ($PSBoundParameters.ContainsKey('DefaultJustification') -or $PSBoundParameters.ContainsKey('DefaultDurationHours'))) {
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
            Write-Host ("    -> activation defaults overridden on all $(@($catalog).Count) entr$(if(@($catalog).Count -eq 1){'y'}else{'ies'}): $($_ovr -join ', ')") -ForegroundColor DarkGray
        }

        if ($catalog) {
            try {
                # PS 5.1 unwraps single-element arrays during pipeline -- use
                # InputObject + @($catalog) so the JSON keeps its [ ] brackets
                # whether the catalog has 1 or many tenants.
                $catalogMin = ConvertTo-Json -InputObject @($catalog) -Depth 10 -Compress
                $catalogKey = Join-Path $root.Path "3rdparty\extensions\$ExtensionId\policy"
                New-PolicyKey -Path $catalogKey
                Set-Reg -Path $catalogKey -Name 'tenantCatalog' -Value $catalogMin
                $tenantCount = @($catalog).Count
                Write-Host "    -> tenantCatalog written ($tenantCount tenant(s)) under 3rdparty\extensions\$ExtensionId\policy" -ForegroundColor DarkGray
            } catch {
                Write-Warning "    Tenant catalog write failed: $($_.Exception.Message). Other policies were still written."
                $catalogMissing.Add($root.Name)
            }
        } else {
            $catalogMissing.Add($root.Name)
        }
    }

    # Per-DEVICE auto-activate cap (2026-09-23). Written independently of the catalog, so it also applies
    # with -SkipTenantCatalog. Not passed = this device's current value is left alone; 0..100 = written as
    # REG_DWORD; -1 = removed (no limit).
    if ($PSBoundParameters.ContainsKey('AutoActivateMaxGroups')) {
        $amKey = Join-Path $root.Path "3rdparty\extensions\$ExtensionId\policy"
        if ($AutoActivateMaxGroups -ge 0) {
            Set-Reg -Path $amKey -Name 'autoActivateMaxGroups' -Value $AutoActivateMaxGroups -Kind DWord
            $amTxt = if ($AutoActivateMaxGroups -eq 0) { 'auto-activation OFF' } else { "at most $AutoActivateMaxGroups group(s)" }
            Write-Host "    -> autoActivateMaxGroups = $AutoActivateMaxGroups ($amTxt) under 3rdparty\extensions\$ExtensionId\policy" -ForegroundColor DarkGray
        } else {
            if (Test-Path -LiteralPath $amKey) { Remove-ItemProperty -LiteralPath $amKey -Name 'autoActivateMaxGroups' -ErrorAction SilentlyContinue }
            Write-Host "    -> autoActivateMaxGroups removed (no limit) under 3rdparty\extensions\$ExtensionId\policy" -ForegroundColor DarkGray
        }
    }
}

# Fail LOUD, never a quiet success: the catalog was asked for (no -SkipTenantCatalog)
# but not written, so the extension installs with no tenant to sign in to.
if ($catalogMissing.Count -gt 0) {
    Write-Host ""
    Write-Host ("INCOMPLETE: the force-install policies were written, but the tenant catalog was NOT written for {0} (see the warnings above). Fix the cause and re-run, pass -CatalogJsonPath / -ClientId, or pass -SkipTenantCatalog if the catalog is delivered another way." -f ($catalogMissing -join ', ')) -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Done. Restart $Browser (or wait for next launch) to apply policy." -ForegroundColor Green
Write-Host ""
Write-Host "First-run user experience:" -ForegroundColor Yellow
Write-Host "  1. Browser auto-installs the extension on next launch."
Write-Host "  2. User clicks the PIM Activator icon -> setup wizard appears."
Write-Host "  3. User picks 'Use centrally deployed' (the tenant catalog written above) and"
$_jdefault = if ($PSBoundParameters.ContainsKey('DefaultJustification')) { $DefaultJustification } else { 'Change in infrastructure' }
$_ddefault = if ($PSBoundParameters.ContainsKey('DefaultDurationHours'))  { "$DefaultDurationHours" } else { '8' }
Write-Host "     signs in once -> defaults pre-filled ($_jdefault / ${_ddefault}h)."
Write-Host "  4. Activate / My Access tabs are live. Sign-in lasts for the browser session."
if ($Browser -in @('Edge','Both'))   { Write-Host "Validate force-install: edge://policy   -> search 'ExtensionInstallForcelist' / extension id." -ForegroundColor DarkGray }
if ($Browser -in @('Chrome','Both')) { Write-Host "Validate force-install: chrome://policy -> search 'ExtensionInstallForcelist' / extension id." -ForegroundColor DarkGray }
