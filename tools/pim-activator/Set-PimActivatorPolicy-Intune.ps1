<#
.SYNOPSIS
    Self-contained Intune Platform Script that writes the PIM Activator
    extension's managed-storage policy keys (tenantId / clientId / etc.) to
    HKLM so the extension's chrome.storage.managed API returns them on next
    Edge / Chrome launch.

.DESCRIPTION
    Customer-specific values are HARDCODED in the CUSTOMER CONFIG block below
    (Intune Platform Scripts cannot accept runtime parameters). Each customer
    duplicates this file, edits ONLY the constants in that block, uploads
    to: Intune Admin Center -> Devices -> Scripts and remediations ->
        Platform scripts -> Add -> Windows 10 and later -> upload this .ps1
        -> Run this script using the logged on credentials = No
        -> Enforce script signature check = No
        -> Run script in 64 bit PowerShell host = Yes
        -> Assign to device group(s)

    Writes to HKCU (per-user policy hive). Each user logging into the device
    gets their own copy of the managed-storage values. Intune Platform Script
    must be configured: "Run this script using the logged on credentials = Yes"
    so it executes in the user's hive context. Idempotent: re-runs are safe
    (sets values; doesn't delete or alter unrelated registry keys).

    Edge / Chrome read these keys at next browser launch via
    chrome.storage.managed.get() inside the extension popup. Together with
    the forcelist policy (which installs the CRX), this gives a fully
    unattended end-user experience: extension auto-installs + auto-configures
    + signs into the right tenant.

.NOTES
    Companion to the forcelist Settings Catalog policy:
      Microsoft Edge\Extensions\Configure which extensions are installed silently
        = eheocihmlppcophaeakmdenhgcookkab;https://knudsenmorten.github.io/PIM4EntraPS/updates.xml
      Google Chrome\Extensions\Configure the list of force-installed apps and extensions
        = same value
    Push both the forcelist + this script for a complete deployment.
#>

# ============================================================================
#  CUSTOMER CONFIG -- EDIT ONLY THIS BLOCK PER CUSTOMER
# ============================================================================

$ExtensionId          = 'eheocihmlppcophaeakmdenhgcookkab'
$TenantId             = 'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e'   # Customer's Entra tenant id
$ClientId             = 'e96afaa6-1c00-4320-9a4c-334558138e09'   # Customer's PIM Activator app reg client id (from Deploy-PimActivatorBackend.ps1)
$GroupNameFilter      = '^PIM-'                                   # Regex limiting which eligible groups appear in popup
$DefaultDurationHours = 8                                         # Default activation duration (typically a workday)
$DefaultJustification = 'Daily ops'                               # Default text in justification field

# ============================================================================
#  END CUSTOMER CONFIG
# ============================================================================

$ErrorActionPreference = 'Stop'
$logPrefix = '[PIM-Activator-Policy]'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Write-Host "$ts $logPrefix [$Level] $Message"
}

function Set-PolicyValue {
    param(
        [Parameter(Mandatory)][string]$RegPath,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Kind = [Microsoft.Win32.RegistryValueKind]::String
    )
    if (-not (Test-Path -LiteralPath $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }
    New-ItemProperty -Path $RegPath -Name $Name -Value $Value -PropertyType $Kind -Force | Out-Null
}

function Write-BrowserPolicy {
    param(
        [Parameter(Mandatory)][ValidateSet('Edge','Chrome')][string]$Browser
    )
    $vendorPath = if ($Browser -eq 'Edge') { 'Microsoft\Edge' } else { 'Google\Chrome' }
    # HKCU instead of HKLM: per-user policy. No admin required + Intune
    # Platform Script must be set to "Run this script using the logged on
    # credentials = Yes" so it executes in the user's hive context. Each
    # user logging into the device gets their own copy of these values.
    $policyRoot = "HKCU:\SOFTWARE\Policies\$vendorPath\3rdparty\extensions\$ExtensionId\policy"

    Write-Log "$Browser : writing managed-storage values under $policyRoot"

    Set-PolicyValue -RegPath $policyRoot -Name 'tenantId'             -Value $TenantId             -Kind String
    Set-PolicyValue -RegPath $policyRoot -Name 'clientId'             -Value $ClientId             -Kind String
    Set-PolicyValue -RegPath $policyRoot -Name 'groupNameFilter'      -Value $GroupNameFilter      -Kind String
    Set-PolicyValue -RegPath $policyRoot -Name 'defaultDurationHours' -Value $DefaultDurationHours -Kind DWord
    Set-PolicyValue -RegPath $policyRoot -Name 'defaultJustification' -Value $DefaultJustification -Kind String

    Write-Log "$Browser : 5 managed-storage values set"
}

try {
    Write-Log "Starting PIM Activator policy push (Extension $ExtensionId, Tenant $TenantId, Client $ClientId)"
    Write-Log "Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

    Write-BrowserPolicy -Browser Edge
    Write-BrowserPolicy -Browser Chrome

    Write-Log "DONE -- managed-storage policy values landed for both Edge and Chrome." 'OK'
    Write-Log "Next browser launch will pick them up; extension popup uses tenantId $TenantId." 'OK'
    exit 0
} catch {
    Write-Log "FAILED: $($_.Exception.Message)" 'ERROR'
    Write-Log "Line: $($_.InvocationInfo.ScriptLineNumber); Statement: $($_.InvocationInfo.Line.Trim())" 'ERROR'
    exit 1
}
