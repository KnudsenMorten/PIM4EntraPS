#Requires -Version 5.1
<#
.SYNOPSIS
    Force-install the PIM Activator browser extension (Edge, Chrome, or both)
    via Chromium enterprise policy. Designed for unattended Intune / Group
    Policy / Configuration Manager rollout.

.DESCRIPTION
    Writes a single Chromium policy value -- ExtensionInstallForcelist --
    that tells the browser to install + auto-update the extension from the
    given -UpdateUrl on next launch.

    Per-machine (-Scope Machine, default, HKLM, requires admin) or per-user
    (-Scope User, HKCU, no admin). Both browsers read the SAME key names
    under different roots:
      Edge   : SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist
      Chrome : SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist

    v1.2.0+ of the extension reads its tenant id + client id from a per-
    browser-profile chrome.storage.local entry the user fills in via the
    in-popup onboarding wizard on first run -- no admin push of tenant
    config is needed (or supported). This script's only job is to make sure
    the extension itself is present.

    Re-runnable. Safe under SYSTEM. Returns exit code 0 on success.

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
    Remove the forcelist entry this script writes.

.EXAMPLE
    # Default per-machine install (HKLM, requires admin, applies to every
    # user on this box):
    .\Deploy-PimActivatorClient.ps1

    # On next Edge / Chrome launch the extension installs for every user.
    # Each user then opens the popup, completes the one-time onboarding
    # wizard (work email -> tenant + app reg auto-discovered), and starts
    # activating PIM eligibilities.

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
    # Uninstall (removes the forcelist entry, the extension self-removes
    # on next launch):
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

    [Parameter(Mandatory, ParameterSetName = 'Uninstall')]
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

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
    $policyRoots.Add([pscustomobject]@{ Name = 'Edge';   Path = "$hiveRoot\SOFTWARE\Policies\Microsoft\Edge" })
}
if ($Browser -in @('Chrome','Both')) {
    $policyRoots.Add([pscustomobject]@{ Name = 'Chrome'; Path = "$hiveRoot\SOFTWARE\Policies\Google\Chrome" })
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

# Slot number derived from the extension id. Same hash on every run, so
# re-installs always overwrite the same slot (idempotent) and never collide
# with other policy-installed extensions in the same ExtensionInstallForcelist.
$slot = ([System.Math]::Abs($ExtensionId.GetHashCode()) % 9000) + 1000

if ($Uninstall) {
    Write-Host "Removing PIM Activator force-install ($Scope scope, $Browser) for extension $ExtensionId..." -ForegroundColor Yellow

    foreach ($root in $policyRoots) {
        # Also clean up the 3rdparty\extensions\<id> tree (tenantCatalog) on uninstall.
        $catalogRoot = Join-Path $root.Path "3rdparty\extensions\$ExtensionId"
        if (Test-Path $catalogRoot) {
            Remove-Item -Path $catalogRoot -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  [$($root.Name)] removed 3rdparty\extensions\$ExtensionId" -ForegroundColor DarkGray
        }
        foreach ($subKey in 'ExtensionInstallForcelist','ExtensionInstallAllowlist','ExtensionInstallSources','ExtensionSettings') {
            $kp = Join-Path $root.Path $subKey
            if (Test-Path -LiteralPath $kp) {
                if (Get-ItemProperty -Path $kp -Name "$slot" -ErrorAction SilentlyContinue) {
                    Remove-ItemProperty -Path $kp -Name "$slot" -Force
                    Write-Host "  [$($root.Name)] removed $subKey slot $slot at $kp" -ForegroundColor DarkGray
                }
            }
        }

        # v1.1.x left behind chrome.storage.managed config under
        # 3rdparty\extensions\<id>\policy. v1.2.0+ ignores it but cleaning it
        # up here keeps `regedit` tidy.
        $managedPath = Join-Path $root.Path "3rdparty\extensions\$ExtensionId\policy"
        if (Test-Path -LiteralPath $managedPath) {
            Remove-Item -Path $managedPath -Recurse -Force
            Write-Host "  [$($root.Name)] removed legacy managed-config key at $managedPath" -ForegroundColor DarkGray
        }
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
# pattern instead of a stale knudsenmorten.github.io one.
$sourcePattern = $null
try {
    $u = [Uri]::new($UpdateUrl)
    if ($u.Scheme -and $u.Host) {
        $sourcePattern = "$($u.Scheme)://$($u.Host)/*"
    }
} catch {
    # Leave $sourcePattern null; we'll skip writing ExtensionInstallSources.
}

foreach ($root in $policyRoots) {
    Write-Host ""
    Write-Host "  [$($root.Name)] writing under $($root.Path)" -ForegroundColor Cyan

    # 1. ExtensionInstallForcelist -- the "install this extension and keep it
    #    installed" directive. Value format is "<extension-id>;<update-url>".
    #    Each entry occupies a named slot (a free-form string); re-running with
    #    the same ExtensionId lands in the same slot (deterministic hash) so
    #    re-runs are idempotent and never collide with other policy-installed
    #    extensions in the same forcelist.
    $forcelistPath = Join-Path $root.Path 'ExtensionInstallForcelist'
    New-PolicyKey -Path $forcelistPath
    Set-Reg -Path $forcelistPath -Name "$slot" -Value "$ExtensionId;$UpdateUrl"
    Write-Host "    -> ExtensionInstallForcelist slot $slot set ($ExtensionId;$UpdateUrl)" -ForegroundColor DarkGray

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
        $allowPath = Join-Path $root.Path 'ExtensionInstallAllowlist'
        New-PolicyKey -Path $allowPath
        Set-Reg -Path $allowPath -Name "$slot" -Value $ExtensionId
        Write-Host "    -> ExtensionInstallAllowlist slot $slot set ($ExtensionId)  [opt-in, -WriteAllowlist]" -ForegroundColor DarkGray
    }

    # 3. ExtensionInstallSources -- whitelist the host the CRX + updates.xml
    #    are served from. Required if the admin has restricted ExtensionInstallSources
    #    to a non-default value (some hardened baselines do). Without this,
    #    a CRX download from a non-Web-Store URL silently fails the integrity
    #    check on download. Skipped when $UpdateUrl can't be URL-parsed.
    if ($sourcePattern) {
        $sourcesPath = Join-Path $root.Path 'ExtensionInstallSources'
        New-PolicyKey -Path $sourcesPath
        Set-Reg -Path $sourcesPath -Name "$slot" -Value $sourcePattern
        Write-Host "    -> ExtensionInstallSources slot $slot set ($sourcePattern)" -ForegroundColor DarkGray
    }

    # 4. ExtensionSettings -- per-extension override that pre-grants the
    #    runtime hosts (a.k.a. <all_urls>) for THIS extension only.
    #
    # 2026-06-10 fleet-freeze root cause: from v1.5.11 onward the extension
    # manifest declares 'https://*/*' in host_permissions (needed by the
    # /.well-known/pim-activator.json auto-discover feature). Chrome's
    # auto-update detects this as a permission EXPANSION vs the previously-
    # installed version and SILENTLY DISABLES the upgrade until the user
    # clicks Enable in chrome://extensions. With managed Chrome and
    # DeveloperToolsAvailability=2 (our standard hardening), the user
    # can't click Enable -- the device is frozen at whatever version it
    # last consented to. Whole fleet ended up stuck on a mix of v1.1.1,
    # v1.6.14, etc., with no path forward via the forcelist alone.
    #
    # ExtensionSettings runtime_allowed_hosts:['<all_urls>'] pre-grants
    # the broad scope at policy level, so the permission-expansion gate
    # never fires and auto-update proceeds silently. Targeted at the
    # extension id only -- it does NOT grant <all_urls> to anything else.
    #
    # Registry layout for Chromium's ExtensionSettings policy on Windows:
    #   - Key  : <policy-root>\ExtensionSettings
    #   - Value NAME = the extension id (or '*' for the wildcard default)
    #   - Value DATA = JSON string of the per-extension settings dict
    # i.e. NOT {"eheoci...":{...}} written under value name '*' -- that
    # combo is interpreted as {"*":{"eheoci...":{...}}} which fails
    # schema validation ("Unknown property: eheoci...") and Chrome silently
    # drops the policy (2026-06-10 bug). Value name carries the id;
    # value data carries only the inner per-extension dict.
    $extSettingsPath = Join-Path $root.Path 'ExtensionSettings'
    New-PolicyKey -Path $extSettingsPath
    $extSettingsJson = (@{
        installation_mode     = 'force_installed'
        update_url            = $UpdateUrl
        runtime_allowed_hosts = @('<all_urls>')
    } | ConvertTo-Json -Depth 5 -Compress)
    Set-Reg -Path $extSettingsPath -Name $ExtensionId -Value $extSettingsJson
    Write-Host "    -> ExtensionSettings configured (runtime_allowed_hosts = <all_urls>) -- bypasses permission-expansion gate" -ForegroundColor DarkGray

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
                        $appResp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=startswith(displayName,'PIM Activator')" -ErrorAction Stop
                        $app = @($appResp.value)[0]
                        if (-not $org -or -not $app) {
                            Write-Warning "    Live Entra auto-discover incomplete (org or PIM Activator app missing). tenantCatalog skipped."
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
            }
        }
    }
}

Write-Host ""
Write-Host "Done. Restart $Browser (or wait for next launch) to apply policy." -ForegroundColor Green
Write-Host ""
Write-Host "First-run user experience:" -ForegroundColor Yellow
Write-Host "  1. Browser auto-installs the extension on next launch."
Write-Host "  2. User clicks the PIM Activator icon -> onboarding wizard appears."
Write-Host "  3. User types work email -> sign in once -> tenant + app reg auto-"
$_jdefault = if ($PSBoundParameters.ContainsKey('DefaultJustification')) { $DefaultJustification } else { 'Change in infrastructure' }
$_ddefault = if ($PSBoundParameters.ContainsKey('DefaultDurationHours'))  { "$DefaultDurationHours" } else { '8' }
Write-Host "     discovered -> defaults pre-filled ($_jdefault / ${_ddefault}h)."
Write-Host "  4. Click Save and continue -- done. Activate / My Access tabs are live."
if ($Browser -in @('Edge','Both'))   { Write-Host "Validate force-install: edge://policy   -> search 'ExtensionInstallForcelist' / extension id." -ForegroundColor DarkGray }
if ($Browser -in @('Chrome','Both')) { Write-Host "Validate force-install: chrome://policy -> search 'ExtensionInstallForcelist' / extension id." -ForegroundColor DarkGray }
