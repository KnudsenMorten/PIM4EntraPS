#Requires -Version 5.1
<#
.SYNOPSIS
    Solution-wide shared defaults for PIM4EntraPS engines.

.DESCRIPTION
    Loaded by Initialize-LauncherConfig as Layer 0 -- BEFORE any per-engine
    defaults.ps1, .locked.ps1 in config/, or .custom.ps1 override. Customer
    overrides (any later layer) win.

    Layered config order:
      0. PIM4EntraPS.shared-defaults.ps1   (this file)
      1. config/*.locked.ps1                (CSV path resolvers, policy data)
      2. config/PIM4EntraPS.NamingConventions.locked.ps1
      3. config/PIM4EntraPS.NamingConventions.custom.ps1   (if present)
      4. config/PIM4EntraPS.Filters.locked.ps1
      5. config/PIM4EntraPS.Filters.custom.ps1             (if present)
      6. launcher/<task>/LauncherConfig.defaults.ps1
      7. launcher/<task>/LauncherConfig.custom.ps1         (if present)

.NOTES
    Solution     : PIM4EntraPS
    Developed by : Morten Knudsen, Microsoft MVP
#>

# --- Logging ---
# Default ON. Customer opts out via `$global:PIM_DisableTranscript = $true` in
# LauncherConfig.custom.ps1 (lab/silent mode).
$global:PIM_DisableTranscript = $false
$global:PIM_LogRetentionDays  = 30

# --- Module path (engine/_shared/PIM-Functions.psm1) ---
# Resolved by each engine at startup; set here so customer can override path
# without forking the engine.
$global:PIM_ModulePath = $null   # null = use default at engine/_shared/PIM-Functions.psm1

# --- Config root + .custom -> .locked resolution ---
# Engines call Get-PimConfigFile -BaseName 'PIM-Assignments-Groups' -Extension 'csv'
# which returns the .custom path if it exists, else .locked.
$global:PIM_ConfigRoot = $null   # null = auto-derive as <solution>/config

# --- Output root for engine exports (CSV/JSON) ---
$global:PIM_OutputRoot = $null   # null = auto-derive as <solution>/output
