#Requires -Version 5.1
<#
.SYNOPSIS
    Per-machine installer for the PIM Activator Edge extension. Pushes
    force-install + tenant configuration via Edge enterprise policy. Designed
    for unattended Intune / Group Policy / Configuration Manager rollout.

.DESCRIPTION
    Writes two sets of HKLM policy keys that Edge reads at next launch:

    1. ExtensionInstallForcelist
       Tells Edge to install + auto-update the extension from -UpdateUrl
       (the update.xml of a private CRX host, or 'https://edge.microsoft.com/extensionwebstorebase/v1/crx'
       for the Edge Add-ons store).

    2. 3rdparty\extensions\<ExtensionId>\policy
       The managed_storage payload (chrome.storage.managed) the extension's
       popup.js reads on load: tenantId, clientId, groupNameFilter,
       defaultDurationHours, defaultJustification. Admin-pushed values
       override anything the user might set locally.

    Re-runnable. Safe under SYSTEM. Returns exit code 0 on success.

.PARAMETER ExtensionId
    32-char Chromium extension id assigned by Edge Add-ons store / your
    signing process. Required.

.PARAMETER UpdateUrl
    The update.xml URL the extension auto-updates from. For the Edge
    Add-ons store this is 'https://edge.microsoft.com/extensionwebstorebase/v1/crx'.
    For a private CRX host, use the URL of your update manifest XML.

.PARAMETER TenantId
    Entra tenant id (GUID) the activator signs into.

.PARAMETER ClientId
    App registration client id (output by Install-PimActivatorAppRegistration.ps1).

.PARAMETER GroupNameFilter
    Optional regex limiting which eligible groups are shown. Default '^PIM-'.

.PARAMETER DefaultDurationHours
    Optional default activation duration (hours). Default 1.

.PARAMETER DefaultJustification
    Optional default text for the justification field. Default 'Daily ops'.

.PARAMETER Scope
    'Machine' (default, HKLM, requires admin) or 'User' (HKCU, no admin).
    Intune deploys typically run as SYSTEM -> use Machine.

.PARAMETER Uninstall
    Remove all policy keys this script writes.

.EXAMPLE
    # Intune Win32 install command (run as SYSTEM):
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-PimActivator.ps1 `
        -ExtensionId 'abcdefghijklmnopabcdefghijklmnop' `
        -UpdateUrl 'https://edge.microsoft.com/extensionwebstorebase/v1/crx' `
        -TenantId '00000000-0000-0000-0000-000000000000' `
        -ClientId '11111111-2222-3333-4444-555555555555'

.EXAMPLE
    # Detection / uninstall:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-PimActivator.ps1 -ExtensionId abcd... -Uninstall

.NOTES
    Tested on Edge for Business 120+. Edge picks up policy changes on next
    launch; no reboot required.
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId,

    [Parameter(Mandatory, ParameterSetName = 'Install')]
    [string]$UpdateUrl,

    [Parameter(Mandatory, ParameterSetName = 'Install')]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory, ParameterSetName = 'Install')]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'Install')]
    [string]$GroupNameFilter = '^PIM-',

    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(0.5, 24)]
    [double]$DefaultDurationHours = 1,

    [Parameter(ParameterSetName = 'Install')]
    [string]$DefaultJustification = 'Daily ops',

    [Parameter()]
    [ValidateSet('Machine', 'User')]
    [string]$Scope = 'Machine',

    [Parameter(Mandatory, ParameterSetName = 'Uninstall')]
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

$root = if ($Scope -eq 'Machine') { 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' } else { 'HKCU:\SOFTWARE\Policies\Microsoft\Edge' }

function New-PolicyKey {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
}

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [Microsoft.Win32.RegistryValueKind]$Kind = [Microsoft.Win32.RegistryValueKind]::String)
    New-PolicyKey -Path $Path
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Kind -Force | Out-Null
}

if ($Uninstall) {
    Write-Host "Removing PIM Activator policy keys ($Scope scope) for extension $ExtensionId..." -ForegroundColor Yellow

    # Forcelist: clear the slot we wrote to. We use a stable slot number derived
    # from the extension id so re-runs are idempotent and uninstall is targeted.
    $forcelistPath = Join-Path $root 'ExtensionInstallForcelist'
    if (Test-Path -LiteralPath $forcelistPath) {
        Get-ItemProperty -Path $forcelistPath | ForEach-Object {
            foreach ($prop in $_.PSObject.Properties) {
                if ($prop.Value -like "$ExtensionId;*") {
                    Remove-ItemProperty -Path $forcelistPath -Name $prop.Name -ErrorAction SilentlyContinue
                    Write-Host "  removed forcelist entry $($prop.Name) = $($prop.Value)" -ForegroundColor DarkGray
                }
            }
        }
    }

    $managedPath = Join-Path $root "3rdparty\extensions\$ExtensionId\policy"
    if (Test-Path -LiteralPath $managedPath) {
        Remove-Item -Path $managedPath -Recurse -Force
        Write-Host "  removed managed config key $managedPath" -ForegroundColor DarkGray
    }

    Write-Host "PIM Activator policy removed. Restart Edge to apply." -ForegroundColor Green
    return
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

Write-Host "Installing PIM Activator policy ($Scope scope)..." -ForegroundColor Cyan
Write-Host "  ExtensionId : $ExtensionId"
Write-Host "  TenantId    : $TenantId"
Write-Host "  ClientId    : $ClientId"
Write-Host "  UpdateUrl   : $UpdateUrl"

# 1) Force-install via ExtensionInstallForcelist. The value format is:
#    "<extension-id>;<update-url>"
# We allocate slots by hashing the extension id, so re-runs always overwrite
# the same slot (idempotent) and never collide with other policy-installed
# extensions.
$forcelistPath = Join-Path $root 'ExtensionInstallForcelist'
New-PolicyKey -Path $forcelistPath
$slot = ([System.Math]::Abs($ExtensionId.GetHashCode()) % 9000) + 1000
Set-Reg -Path $forcelistPath -Name "$slot" -Value "$ExtensionId;$UpdateUrl"
Write-Host "  -> forcelist slot $slot set" -ForegroundColor DarkGray

# 2) Managed config (chrome.storage.managed). Edge maps the registry sub-tree
# under 3rdparty\extensions\<id>\policy directly to managed-storage keys, so
# REG_SZ "tenantId" becomes managed.tenantId at runtime.
$managedPath = Join-Path $root "3rdparty\extensions\$ExtensionId\policy"
New-PolicyKey -Path $managedPath
Set-Reg -Path $managedPath -Name 'tenantId'             -Value $TenantId
Set-Reg -Path $managedPath -Name 'clientId'             -Value $ClientId
Set-Reg -Path $managedPath -Name 'groupNameFilter'      -Value $GroupNameFilter
Set-Reg -Path $managedPath -Name 'defaultJustification' -Value $DefaultJustification
# defaultDurationHours is a number; Edge accepts REG_SZ and parses to number per the schema.
Set-Reg -Path $managedPath -Name 'defaultDurationHours' -Value ([string]$DefaultDurationHours)

Write-Host "  -> managed config keys set under $managedPath" -ForegroundColor DarkGray

Write-Host ""
Write-Host "Done. Restart Edge (or wait for next launch) to apply policy." -ForegroundColor Green
Write-Host "Validate from any Edge window: edge://policy -> Search 'PIM' / extension id." -ForegroundColor DarkGray
