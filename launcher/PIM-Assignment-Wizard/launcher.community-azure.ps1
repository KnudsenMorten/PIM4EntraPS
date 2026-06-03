#Requires -Version 5.1
<#
.SYNOPSIS
    Community cloud-native launcher for PIM4EntraPS\PIM-Assignment-Wizard
    (Azure Function / Logic App / Hybrid Worker / Container Apps Job).

.DESCRIPTION
    Runs PIM4EntraPS\PIM-Assignment-Wizard in the customer's own Azure-hosted
    compute. Reads credentials from the layered config (closest layer wins):

      * config\PIM4EntraPS.custom.ps1                  (solution-wide; covers every engine)
      * launcher\<engine>\LauncherConfig.custom.ps1    (per-engine override)

    See LauncherConfig.custom.sample.ps1 in this same folder for the 4 auth
    method blocks. Mirrors SecurityInsight launcher.community-vm.ps1 verbatim
    so SI customers don't have to learn a different model.

    The most common configuration for cloud hosts is METHOD 1 (Managed Identity)
    in config\PIM4EntraPS.custom.ps1 -- the Function/LogicApp's MI then
    authenticates without any secret leaving the host. KV-secret (METHOD 2)
    is also supported for hosts that already lean on a customer KV.

.NOTES
    Solution       : PIM4EntraPS
    File           : launcher.community-azure.ps1
    Engine         : PIM-Assignment-Wizard
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.
#>
[CmdletBinding()]
param(
    [string]$InstallPath,
    [string]$LauncherConfigPath,
    [switch]$WhatIfMode,
    [switch]$SuppressErrors,
    [switch]$SuppressWarnings
)
$ErrorActionPreference = 'Stop'

# Resolve install + solution root. Community-azure layout is identical to
# community-vm: <install>\launcher\<engine>\launcher.community-azure.ps1
# (2-up from $PSScriptRoot = solution root).
if (-not $InstallPath) {
    $InstallPath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}
$solutionRoot = $InstallPath

# Optional per-host pre-bootstrap (e.g. set env-var-derived globals BEFORE
# the layered config loads). Drop a launcher.override.ps1 next to this
# launcher to e.g. resolve env:PLATFORM_TENANT_ID -> $global:SpnTenantId.
$overrideFile = Join-Path $PSScriptRoot 'launcher.override.ps1'
if (Test-Path -LiteralPath $overrideFile) { . $overrideFile }

# Layered config: shared-defaults -> *.locked.ps1 -> PIM4EntraPS.custom.ps1
# -> LauncherConfig.defaults.ps1 -> LauncherConfig.custom.ps1.
. (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1') -LauncherPath $PSCommandPath -SolutionRoot $solutionRoot

# Auth helper -- mirrors SI launcher.community-vm.ps1 auth flow verbatim.
. (Join-Path $PSScriptRoot '..\_lib\Connect-PimLauncherAuth.ps1')

# Per-engine LauncherConfig.custom.ps1 OVERRIDE path (CLI > Init default).
if ($LauncherConfigPath -and (Test-Path -LiteralPath $LauncherConfigPath)) {
    . $LauncherConfigPath
}

$global:AutomationFramework = $false
$global:SettingsPath        = $PSScriptRoot
$global:WhatIfMode          = [bool]$WhatIfMode
$global:SuppressErrors      = [bool]$SuppressErrors
$global:SuppressWarnings    = [bool]$SuppressWarnings

# Authenticate (sets $global:SpnAuthMode on success).
Connect-PimLauncherAuth | Out-Null

# Optional transcript (Start-LauncherTranscript honours $global:PIM_DisableTranscript).
. (Join-Path $PSScriptRoot '..\_lib\Start-LauncherTranscript.ps1') -Flavour 'community-azure'

# Resolve + invoke engine.
$engine = Join-Path $solutionRoot 'engine\PIM-Assignment-Wizard\PIM-Assignment-Wizard.ps1'
if (-not (Test-Path -LiteralPath $engine)) {
    throw "Launcher: engine script not found at $engine. Expected <solroot>\engine\PIM-Assignment-Wizard\PIM-Assignment-Wizard.ps1."
}

try {
    & $engine
}
finally {
    # Scrub any plaintext SPN secret pulled into the session by the helper.
    if ($global:SpnAuthMode -in @('KeyVaultSecret','PlainTextSecret')) {
        $global:SpnClientSecret = $null
        [System.GC]::Collect()
    }
}
