#Requires -Version 5.1
<#
.SYNOPSIS
    Community VM launcher for PIM4EntraPS\PIM-Baseline-Management-CSV-AdministrativeUnitsOnly. Invokes the engine
    after dot-sourcing the layered config (solution-wide + per-engine) and
    running Connect-PimLauncherAuth to authenticate via one of the 4 supported
    methods (Managed Identity, SPN+KV secret, SPN+cert, SPN+plaintext secret).

.DESCRIPTION
    Runs PIM4EntraPS\PIM-Baseline-Management-CSV-AdministrativeUnitsOnly on a Windows box in the customer's own tenant.
    Reads credentials from the layered config (closest layer wins):

      * config\PIM4EntraPS.custom.ps1                  (solution-wide; covers every engine)
      * launcher\<engine>\LauncherConfig.custom.ps1    (per-engine override)

    See LauncherConfig.custom.sample.ps1 in this same folder for the 4 auth
    method blocks. Mirrors SecurityInsight launcher.community-vm.ps1 verbatim
    so SI customers don't have to learn a different model.

.NOTES
    Solution       : PIM4EntraPS
    File           : launcher.community-vm.ps1
    Engine         : PIM-Baseline-Management-CSV-AdministrativeUnitsOnly
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

# Windows PS 5.1 + PS 7 coexistence: scrub PS7 module paths so
# Microsoft.PowerShell.Security loads cleanly (PS7's TypeData clashes
# with the v5.1 host -> ConvertTo-SecureString refuses to load).
if ($PSVersionTable.PSVersion.Major -lt 6) {
    $env:PSModulePath = ($env:PSModulePath -split ';' |
                         Where-Object { $_ -and ($_ -notmatch '(?i)\\powershell\\7') }) -join ';'
}

function Resolve-RepoRoot {
    param([string]$Start = $PSScriptRoot)
    $cur = $Start
    $communityMatch = $null
    while ($cur) {
        if (Test-Path (Join-Path $cur 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1')) { return $cur }
        if (-not $communityMatch) {
            $dirs = Get-ChildItem -LiteralPath $cur -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            if (($dirs -ccontains 'scripts') -and ($dirs -ccontains 'launchers')) { $communityMatch = $cur }
            elseif (($dirs -ccontains 'engine') -and ($dirs -ccontains 'launcher')) { $communityMatch = $cur }
        }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    if ($communityMatch) { return $communityMatch }
    throw ("Launcher: cannot locate solution repo root walking up from '{0}'. Expected FUNCTIONS\AutomateITPS\AutomateITPS.psd1 (monorepo) or a lowercase scripts/+launchers/ pair (community repo)." -f $Start)
}

# Resolve install + solution root.
# Community-vm always lives at <install>\launcher\<engine>\launcher.community-vm.ps1.
# 2-up from $PSScriptRoot IS the solution root by file-layout convention.
if (-not $InstallPath) {
    try   { $InstallPath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
    catch { $InstallPath = Resolve-RepoRoot }
}
$solutionRoot = $InstallPath

# Layered config: shared-defaults -> *.locked.ps1 -> PIM4EntraPS.custom.ps1
# -> LauncherConfig.defaults.ps1 -> LauncherConfig.custom.ps1.
. (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1') -LauncherPath $PSCommandPath -SolutionRoot $solutionRoot

# Auth helper -- mirrors SI launcher.community-vm.ps1 auth flow verbatim.
. (Join-Path $PSScriptRoot '..\_lib\Connect-PimLauncherAuth.ps1')

# Per-engine LauncherConfig.custom.ps1 OVERRIDE path (CLI > Init default).
# When set, we re-dot-source so a user-specified path wins over the
# auto-discovered launcher\<engine>\LauncherConfig.custom.ps1 that
# Initialize-LauncherConfig already loaded.
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
. (Join-Path $PSScriptRoot '..\_lib\Start-LauncherTranscript.ps1') -Flavour 'community-vm'

# Resolve + invoke engine.
$engine = Join-Path $solutionRoot 'engine\PIM-Baseline-Management-CSV-AdministrativeUnitsOnly\PIM-Baseline-Management-CSV-AdministrativeUnitsOnly.ps1'
if (-not (Test-Path -LiteralPath $engine)) {
    throw "Launcher: engine script not found at $engine. Expected <solroot>\engine\PIM-Baseline-Management-CSV-AdministrativeUnitsOnly\PIM-Baseline-Management-CSV-AdministrativeUnitsOnly.ps1."
}
& $engine
