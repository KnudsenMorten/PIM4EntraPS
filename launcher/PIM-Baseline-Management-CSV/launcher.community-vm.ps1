#Requires -Version 5.1
<#
.SYNOPSIS
    Community launcher for PIM4EntraPS\PIM-Baseline-Management-CSV (user VM / box).
.DESCRIPTION
    Dot-sources LauncherConfig.ps1 (user copies from LauncherConfig.custom.sample.ps1)
    to set SPN tenant + client id + secret. No internal-only modules.

.NOTES
    Solution       : PIM4EntraPS
    File           : launcher.community-vm.ps1
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
    [switch]$SuppressWarnings,
    [ValidateSet('local','msp','')]
    [string]$ConfigVariant = ''
)

$ErrorActionPreference = 'Stop'

function Resolve-RepoRoot {
    param([string]$Start = $PSScriptRoot)
    $cur = $Start
    $communityMatch = $null
    while ($cur) {
        if (Test-Path (Join-Path $cur 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1')) { return $cur }
        if (-not $communityMatch) {
            $dirs = Get-ChildItem -LiteralPath $cur -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            if (($dirs -ccontains 'scripts') -and ($dirs -ccontains 'launchers')) { $communityMatch = $cur }
        }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    if ($communityMatch) { return $communityMatch }
    throw ("Launcher: cannot locate solution repo root walking up from '{0}'. Expected FUNCTIONS\AutomateITPS\AutomateITPS.psd1 (monorepo) or a lowercase scripts/+launchers/ pair (community repo)." -f $Start)
}
if (-not $InstallPath) { $InstallPath = Resolve-RepoRoot }

if (-not $LauncherConfigPath) { $LauncherConfigPath = Join-Path $PSScriptRoot 'LauncherConfig.custom.ps1' }
if (-not (Test-Path -LiteralPath $LauncherConfigPath)) {
    throw "Community launcher: $LauncherConfigPath not found. Copy LauncherConfig.custom.sample.ps1 to LauncherConfig.custom.ps1 and fill in SPN values."
}
. $LauncherConfigPath

$global:AutomationFramework = $false
$global:SettingsPath        = $PSScriptRoot
$global:WhatIfMode          = [bool]$WhatIfMode
$global:SuppressErrors      = [bool]$SuppressErrors
$global:SuppressWarnings    = [bool]$SuppressWarnings
$global:PIM_ConfigVariant   = $ConfigVariant   # '', 'local', or 'msp' (v2.1.0+)

# Resolve engine path portably -- works in the monorepo, in a published
# community repo, and inside a bundled dependency under dependencies/<dep>/.
$launcherDir = $PSScriptRoot
$engineOwner = Split-Path -Parent (Split-Path -Parent $launcherDir)
$solutionRoot = Split-Path -Parent (Split-Path -Parent $launcherDir)
$engine = Join-Path $solutionRoot 'engine\PIM-Baseline-Management-CSV\PIM-Baseline-Management-CSV.ps1'
if (-not (Test-Path -LiteralPath $engine)) { throw "Launcher: engine script not found at $engine. Expected <solroot>\engine\PIM-Baseline-Management-CSV\PIM-Baseline-Management-CSV.ps1." }

# MSP variant: pull central config BEFORE the engine reads anything.
# Sync-PimMspConfig is defined in engine/_shared/PIM-Functions.psm1 and
# is a no-op when $global:PIM_ConfigVariant != 'msp'.
if ($global:PIM_ConfigVariant -eq 'msp') {
    Import-Module (Join-Path $solutionRoot 'engine\_shared\PIM-Functions.psm1') -Global -Force -WarningAction SilentlyContinue
    Sync-PimMspConfig
}

& $engine


