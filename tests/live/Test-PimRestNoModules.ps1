<#
.SYNOPSIS
  Validates that the PIM4EntraPS engine's read + decision path runs with NO
  PowerShell modules (no Microsoft.Graph, no Az, no ExchangeOnlineManagement) --
  100% REST via PIM-Rest.ps1. Builds the real Entra context (users/groups/AUs/
  roles) over Graph REST, runs the engine filters + decision core over it, and
  asserts that no Graph/Az module ever loads.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests\live' }
$shared = Resolve-Path "$here\..\..\engine\_shared"
$config = Resolve-Path "$here\..\..\config"

$pass=0; $fail=0
function Assert($n,$c){ if($c){ $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }
function ModulesLoaded { @(Get-Module | Where-Object { $_.Name -like 'Microsoft.Graph*' -or $_.Name -like 'Az.*' -or $_.Name -eq 'Az' -or $_.Name -eq 'ExchangeOnlineManagement' }) }

Write-Host "=== PIM4EntraPS engine: NO-MODULES (100% REST) validation ===" -ForegroundColor Cyan

# 0) start clean. NOTE: the modules may be INSTALLED on this box (PowerShell would
# auto-import them on first Get-Mg*/Az* use). The real proof is that the REST path
# never USES such a cmdlet, so nothing auto-loads -- asserted again at the end.
ModulesLoaded | ForEach-Object { Remove-Module $_.Name -Force -ErrorAction SilentlyContinue }
Assert "no Graph/Az/EXO modules loaded at start" ((ModulesLoaded).Count -eq 0)
$global:PIM_UseGraphSdk = $false   # engine default is REST-first; make it explicit here

# 1) load ONLY the engine's REST core + filters + context builder + decision core
. "$shared\PIM-Rest.ps1"
. "$config\PIM4EntraPS.Filters.locked.ps1"
. "$shared\PIM-ContextBuilder.ps1"
. "$shared\PIM-PortalAccess.ps1"
Assert "PIM_Filters loaded"                      ($null -ne $global:PIM_Filters)

# 2) build the REAL Entra context over pure REST
Build-PimContext -Refresh | Out-Null
Assert "Users_All_ID populated (REST)"           (@($Global:Users_All_ID).Count -gt 0)
Assert "Groups_All_ID populated (REST)"          (@($Global:Groups_All_ID).Count -gt 0)
Assert "AU_All_ID populated (REST)"              (@($Global:AU_All_ID).Count -gt 0)
Assert "Roles_All_ID populated (REST)"           (@($Global:Roles_All_ID).Count -gt 0)

# 3) SDK-shape normalization works: filters that use SDK casing still match
$u0 = @($Global:Users_All_ID)[0]
Assert "REST user has SDK-cased UserPrincipalName" ([bool]$u0.UserPrincipalName -and [bool]$u0.userPrincipalName)
Assert "REST group has SDK-cased DisplayName"      ([bool](@($Global:Groups_All_ID)[0].DisplayName))

# 4) the engine filters produced the well-known globals over REST data
$pimGroups = @($Global:PIM_Groups_Definitions_ID)
Assert "PimGroup filter found PIM-* groups"      ($pimGroups.Count -gt 0)
Assert "  incl. the live lab helpdesk L2 group"  ($pimGroups.DisplayName -contains 'PIM-Entra-Helpdesk-L2-T2-USER-ID')
$auRoles = @($Global:Role_AU_Definitions_ID)
Assert "AURoleAllowed filter found AU roles"     ($auRoles.Count -gt 0)
Assert "  incl. Helpdesk Administrator"          ($auRoles.DisplayName -contains 'Helpdesk Administrator')

# 5) end-to-end into the decision core, still module-free
$facets = Get-PimGroupFacets -Row ([pscustomobject]@{ GroupName = ($pimGroups | Where-Object { $_.DisplayName -eq 'PIM-Entra-Helpdesk-L2-T2-USER-ID' } | Select-Object -First 1).DisplayName })
Assert "decision core parses REST group -> T2/L2 entra" ($facets.service -eq 'entra' -and $facets.tier -eq 2 -and $facets.level -eq 2)

# 6) STILL no modules after doing all the real work
Assert "STILL no Graph/Az/EXO modules loaded"    ((ModulesLoaded).Count -eq 0)

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass,$fail) -ForegroundColor ($(if($fail){'Red'}else{'Green'}))
Write-Host ("context built over REST: {0} users, {1} groups, {2} AUs, {3} roles" -f @($Global:Users_All_ID).Count,@($Global:Groups_All_ID).Count,@($Global:AU_All_ID).Count,@($Global:Roles_All_ID).Count) -ForegroundColor DarkGray
if ($fail) { exit 1 }
