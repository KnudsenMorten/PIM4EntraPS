#Requires -Version 5.1
<#
.SYNOPSIS
    Layered config loader for PIM4EntraPS launchers. Resolves repo root,
    loads shared defaults, locked + custom config files in order, and
    leaves customer overrides last (highest precedence).

.PARAMETER LauncherPath
    Full path to the launcher script that invoked this loader (typically
    `$PSCommandPath` from the launcher). Used to derive the engine task
    name (the parent directory).

.PARAMETER SolutionRoot
    Optional override for the PIM4EntraPS solution root. Auto-detected by
    walking up from the launcher until the `VERSION` file is found.

.NOTES
    Mirrors SecurityInsight's launcher/_lib/Initialize-LauncherConfig.ps1
    pattern. Layer order documented in shared-defaults.ps1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$LauncherPath,

    [Parameter()]
    [string]$SolutionRoot
)

# ---- 1. Resolve solution root ------------------------------------------------
if (-not $SolutionRoot) {
    $probe = Split-Path -Parent $LauncherPath
    while ($probe -and -not (Test-Path (Join-Path $probe 'VERSION'))) {
        $parent = Split-Path -Parent $probe
        if ($parent -eq $probe) { break }
        $probe = $parent
    }
    if (-not $probe -or -not (Test-Path (Join-Path $probe 'VERSION'))) {
        throw "Initialize-LauncherConfig: cannot locate solution root (no VERSION file up the tree from $LauncherPath)."
    }
    $SolutionRoot = $probe
}
$global:PIM_SolutionRoot = $SolutionRoot

# ---- 2. Derive engine task name (parent folder of launcher) ------------------
$global:PIM_EngineName = Split-Path -Leaf (Split-Path -Parent $LauncherPath)

# ---- 3. Layer 0: shared defaults ---------------------------------------------
$sharedDefaults = Join-Path $SolutionRoot 'launcher\_lib\PIM4EntraPS.shared-defaults.ps1'
if (Test-Path $sharedDefaults) { . $sharedDefaults }

# ---- 4. Layers 1-5: config/ locked + custom ----------------------------------
$configRoot = if ($global:PIM_ConfigRoot) { $global:PIM_ConfigRoot } else { Join-Path $SolutionRoot 'config' }
$global:PIM_ConfigRoot = $configRoot

# .locked.ps1 files (policy data from CUSTOMSCRIPTS legacy) -- load all
Get-ChildItem -Path $configRoot -Filter '*.locked.ps1' -File -ErrorAction SilentlyContinue | ForEach-Object {
    . $_.FullName
}

# Naming conventions: locked then custom
$namingLocked = Join-Path $configRoot 'PIM4EntraPS.NamingConventions.locked.ps1'
$namingCustom = Join-Path $configRoot 'PIM4EntraPS.NamingConventions.custom.ps1'
if (Test-Path $namingLocked) { . $namingLocked }
if (Test-Path $namingCustom) { . $namingCustom }

# Filters: locked then custom
$filtersLocked = Join-Path $configRoot 'PIM4EntraPS.Filters.locked.ps1'
$filtersCustom = Join-Path $configRoot 'PIM4EntraPS.Filters.custom.ps1'
if (Test-Path $filtersLocked) { . $filtersLocked }
if (Test-Path $filtersCustom) { . $filtersCustom }

# ---- 5. Layers 6-7: per-launcher defaults + custom ---------------------------
$launcherDir       = Split-Path -Parent $LauncherPath
$launcherDefaults  = Join-Path $launcherDir 'LauncherConfig.defaults.ps1'
$launcherCustom    = Join-Path $launcherDir 'LauncherConfig.custom.ps1'
if (Test-Path $launcherDefaults) { . $launcherDefaults }
if (Test-Path $launcherCustom)   { . $launcherCustom }

# ---- 6. Derived defaults (after all layers) ----------------------------------
if (-not $global:PIM_OutputRoot) {
    $global:PIM_OutputRoot = Join-Path $SolutionRoot 'output'
}
if (-not $global:PIM_ModulePath) {
    $global:PIM_ModulePath = Join-Path $SolutionRoot 'engine\_shared\PIM-Functions.psm1'
}

Write-Verbose ("Initialize-LauncherConfig: solution={0} engine={1} config={2} output={3}" -f `
    $SolutionRoot, $global:PIM_EngineName, $configRoot, $global:PIM_OutputRoot)
