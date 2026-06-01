#Requires -Version 5.1
<#
.SYNOPSIS
    Community launcher for PIM4EntraPS\SQL-Connect (user VM / box).
.DESCRIPTION
    Dot-sources LauncherConfig.ps1 (user copies from LauncherConfig.sample.ps1)
    to set SPN tenant + client id + secret. No internal-only modules.

.NOTES
    Solution       : PIM4EntraPS
    File           : launcher.community-vm.template.ps1
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

if (-not $LauncherConfigPath) { $LauncherConfigPath = Join-Path $PSScriptRoot 'LauncherConfig.ps1' }
if (-not (Test-Path -LiteralPath $LauncherConfigPath)) {
    throw "Community launcher: $LauncherConfigPath not found. Copy LauncherConfig.sample.ps1 to LauncherConfig.ps1 and fill in SPN values."
}
. $LauncherConfigPath

$global:AutomationFramework = $false
$global:SettingsPath        = $PSScriptRoot
$global:WhatIfMode          = [bool]$WhatIfMode
$global:SuppressErrors      = [bool]$SuppressErrors
$global:SuppressWarnings    = [bool]$SuppressWarnings

$engine = Join-Path $InstallPath 'SOLUTIONS\PIM4EntraPS\CUSTOMSCRIPTS\SQL-Connect.ps1'
if (-not (Test-Path -LiteralPath $engine)) { throw "Launcher: engine script not found at $engine." }
& $engine
