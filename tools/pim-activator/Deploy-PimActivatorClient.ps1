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

    Per-user (-Scope User, default, HKCU) or per-machine (-Scope Machine,
    HKLM). Both browsers read the SAME key names under different roots:
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
    'User' (default, HKCU, no admin required, no Intune conflict) or
    'Machine' (HKLM, requires admin, conflicts with Intune-managed
    ExtensionInstallForcelist policy if the device is enrolled).

.PARAMETER Browser
    'Edge', 'Chrome', or 'Both' (default).

.PARAMETER Uninstall
    Remove the forcelist entry this script writes.

.EXAMPLE
    # Dev-box install (HKCU, no admin):
    .\Deploy-PimActivatorClient.ps1 `
        -ExtensionId 'eheocihmlppcophaeakmdenhgcookkab' `
        -UpdateUrl   'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml'

    # On next Edge / Chrome launch the extension installs.
    # The user then opens the popup, completes the one-time onboarding
    # wizard (work email -> tenant + app reg auto-discovered), and starts
    # activating PIM eligibilities.

.EXAMPLE
    # Per-machine install on an isolated test box (HKLM, requires admin,
    # do NOT use on Intune-managed devices):
    .\Deploy-PimActivatorClient.ps1 `
        -ExtensionId 'eheocihmlppcophaeakmdenhgcookkab' `
        -UpdateUrl   'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml' `
        -Scope Machine

.EXAMPLE
    # Edge only:
    .\Deploy-PimActivatorClient.ps1 `
        -ExtensionId 'eheocihmlppcophaeakmdenhgcookkab' `
        -UpdateUrl   'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml' `
        -Browser Edge

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
    [string]$Scope = 'User',

    [Parameter()]
    [ValidateSet('Edge', 'Chrome', 'Both')]
    [string]$Browser = 'Both',

    [Parameter(Mandatory, ParameterSetName = 'Uninstall')]
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

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
        $forcelistPath = Join-Path $root.Path 'ExtensionInstallForcelist'
        if (Test-Path -LiteralPath $forcelistPath) {
            if (Get-ItemProperty -Path $forcelistPath -Name "$slot" -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $forcelistPath -Name "$slot" -Force
                Write-Host "  [$($root.Name)] removed forcelist slot $slot at $forcelistPath" -ForegroundColor DarkGray
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
    Write-Host "  *** -Scope Machine selected -- HKLM writes will be applied. ***" -ForegroundColor Yellow
    Write-Host "  HKLM ExtensionInstallForcelist CONFLICTS with Intune-managed policy." -ForegroundColor Yellow
    Write-Host "  Only use Machine scope on isolated test machines that are NOT Intune-managed." -ForegroundColor Yellow
    Write-Host "  Production rollouts: push the same forcelist entry via Intune instead." -ForegroundColor Yellow
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

foreach ($root in $policyRoots) {
    Write-Host ""
    Write-Host "  [$($root.Name)] writing under $($root.Path)" -ForegroundColor Cyan

    # ExtensionInstallForcelist value format is "<extension-id>;<update-url>".
    # Each entry occupies a named slot (a free-form string), and Chromium
    # iterates every value under the key. Re-running this script with the
    # same ExtensionId always lands in the same slot (deterministic hash).
    $forcelistPath = Join-Path $root.Path 'ExtensionInstallForcelist'
    New-PolicyKey -Path $forcelistPath
    Set-Reg -Path $forcelistPath -Name "$slot" -Value "$ExtensionId;$UpdateUrl"
    Write-Host "    -> forcelist slot $slot set" -ForegroundColor DarkGray

    # v1.1.x of the extension also read chrome.storage.managed config that
    # this script used to push (tenantId/clientId/Tenants/etc.). v1.2.0+
    # ignores it entirely -- tenant id + client id now come from the in-
    # popup onboarding wizard (per browser profile) instead. Any legacy
    # managed-config key sitting around is harmless but stale; we leave it
    # alone here (use -Uninstall to wipe it cleanly).
}

Write-Host ""
Write-Host "Done. Restart $Browser (or wait for next launch) to apply policy." -ForegroundColor Green
Write-Host ""
Write-Host "First-run user experience:" -ForegroundColor Yellow
Write-Host "  1. Browser auto-installs the extension on next launch."
Write-Host "  2. User clicks the PIM Activator icon -> onboarding wizard appears."
Write-Host "  3. User types work email -> sign in once -> tenant + app reg auto-"
Write-Host "     discovered -> defaults pre-filled (Change in infrastructure / 8h)."
Write-Host "  4. Click Save and continue -- done. Activate / My Access tabs are live."
if ($Browser -in @('Edge','Both'))   { Write-Host "Validate force-install: edge://policy   -> search 'ExtensionInstallForcelist' / extension id." -ForegroundColor DarkGray }
if ($Browser -in @('Chrome','Both')) { Write-Host "Validate force-install: chrome://policy -> search 'ExtensionInstallForcelist' / extension id." -ForegroundColor DarkGray }
