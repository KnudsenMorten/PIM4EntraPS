<#
.SYNOPSIS
  RICH scenario seed for the PIM4EntraPS engine + Manager scenario-simulation suite.

  This is a deliberately FULLER desired-set than tests/live/Seed-PimBaselineDataset.ps1
  (which stays the small "representative deploy" seed). It is built for END-TO-END
  SCENARIO SIMULATION (REQUIREMENTS.md §20): it exercises every provider and every
  delegation surface so a scenario can prove the engine AND the Manager GUI work
  together over a realistic estate:

     * Administrative Units (AU-L0 high-priv global, AU-L1 platform, AU-L2 scoped helpdesk)
     * Departments with people-based owners (IT, Security, HR) -- the source for
       department->owner delegation-approval routing
     * Role groups (job functions) at Tier 0 and Tier 1
     * Permission/service groups across Levels L0-L3 and planes (CP / MP / WDP),
       Entra-ID roles AND Azure-RBAC scopes
     * Power BI workspace delegation group (discovery target)
     * Admin accounts (T0 break-glass, T1 day-to-day, a consultant with scheduled TAP,
       and a flagged OFFBOARDING admin -- Lifecycle=Retire)
     * Admin->group delegations + group nesting (role group -> permission groups)
     * Entra role -> group bindings, Azure RBAC -> group bindings
     * People-based GA + PRA activation approval (approval-required policy on the
       high-priv groups; approvers resolve from the group's department owner)

  STORE: writes DESIRED rows into the SQL desired store (pim.Rows) so BOTH the real
  engine (reads desired from SQL) and the Manager (renders SQL in SQL mode) see the
  same single source of truth. Every created tenant object's display name is prefixed
  with the marker (default 'PIMSCENARIO-') so the fake-tenant cleanup and any live
  cleanup only ever touch marked objects.

  This script is DOT-SOURCEABLE: dot-source it to get Get-PimScenarioSeedSpec (the pure
  in-memory desired-set, no SQL) for the offline engine sim, OR run it to write that
  set into SQL. The two paths share ONE definition so the GUI (SQL) and the engine sim
  (in-memory) never drift.

.EXAMPLE
  # Write the rich seed into a throwaway local SQL DB (for the Manager / GUI specs):
  $env:PIM_SqlServer='.\SQLEXPRESS'; $env:PIM_SqlDatabase='PimScenario'
  .\Seed-PimScenarioDataset.ps1 -OwnerUpn admin@example.onmicrosoft.com -DefaultDomain example.onmicrosoft.com
.EXAMPLE
  # Remove ALL marked desired rows from SQL (keeps any tenant objects):
  .\Seed-PimScenarioDataset.ps1 -Clear
.EXAMPLE
  # Get the desired-set as in-memory hashtable (no SQL) for the offline engine sim:
  . .\Seed-PimScenarioDataset.ps1
  $spec = Get-PimScenarioSeedSpec -OwnerUpn a@x -DefaultDomain x -Marker 'PIMSCENARIO-'
#>
# NB: OwnerUpn/DefaultDomain are NOT declared Mandatory so this file can be DOT-SOURCED
# (to expose Get-PimScenarioSeedSpec) without PowerShell prompting for them. Script-mode
# enforces them below.
[CmdletBinding()]
param(
    [string]$OwnerUpn,
    [string]$DefaultDomain,
    [string]$AzSubscriptionId = '00000000-0000-0000-0000-0000000000aa',
    [string]$AzRoleName = 'Owner',
    [switch]$Clear,
    [string]$Marker      = 'PIMSCENARIO-',
    [string]$SqlServer   = $env:PIM_SqlServer,
    [string]$SqlDatabase = $env:PIM_SqlDatabase
)

# The pure desired-set builder lives in the PARAMLESS PIM-ScenarioSeedSpec.ps1 (so the
# harness can dot-source it without a param() block clobbering caller variables).
. (Join-Path $PSScriptRoot 'PIM-ScenarioSeedSpec.ps1')

# Script mode requires the seed inputs (unless clearing).
if (-not $Clear) {
    if (-not $OwnerUpn)      { throw "Seed mode requires -OwnerUpn (a real resolvable account in the target tenant)." }
    if (-not $DefaultDomain) { throw "Seed mode requires -DefaultDomain (e.g. example.onmicrosoft.com)." }
}

# ---------------------------------------------------------------------------
# SCRIPT MODE: write/clear the rich seed in SQL.
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$shared = Resolve-Path "$here\..\..\engine\_shared"
if (-not $SqlServer)   { $SqlServer = '.\SQLEXPRESS' }
if (-not $SqlDatabase) { throw "Set -SqlDatabase or `$env:PIM_SqlDatabase (e.g. PimScenario)." }
$global:PIM_UseGraphSdk = $false; $global:PIM_SqlServer = $SqlServer; $global:PIM_SqlDatabase = $SqlDatabase
. "$shared\PIM-ChangeQueue.ps1"; . "$shared\PIM-SqlStore.ps1"

Initialize-PimSqlDatabase -Server $SqlServer -Database $SqlDatabase
$cs = Get-PimSqlConnectionString
Initialize-PimSqlStore -ConnectionString $cs

$entities = @(
    'PIM-Definitions-AU','PIM-Definitions-Roles','PIM-Definitions-Services',
    'PIM-Definitions-Departments','Account-Definitions-Admins','PIM-Assignments-Admins',
    'PIM-Assignments-Groups','PIM-Assignments-Roles-Groups','PIM-Assignments-Azure-Resources'
)

if ($Clear) {
    $removed = 0
    foreach ($e in $entities) {
        $n = Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "DELETE FROM pim.Rows WHERE Entity=@e AND ([Key] LIKE @m OR DataJson LIKE @md)" -Parameters @{ e=$e; m="$Marker%"; md="%$Marker%" }
        $removed += [int]$n
    }
    Write-Host "Cleared $removed marked scenario rows from SQL (tenant objects untouched)." -ForegroundColor Green
    return
}

$spec = Get-PimScenarioSeedSpec -OwnerUpn $OwnerUpn -DefaultDomain $DefaultDomain -Marker $Marker -AzSubscriptionId $AzSubscriptionId -AzRoleName $AzRoleName

Write-Host "Seeding RICH scenario baseline into $SqlServer / $SqlDatabase (marker '$Marker', owner '$OwnerUpn')..." -ForegroundColor Cyan
foreach ($entity in $spec.Keys) {
    $rows = @($spec[$entity])
    if ($entity -eq 'PIM-Definitions-Departments') {
        foreach ($d in $rows) { Set-PimSqlRow -ConnectionString $cs -Entity $entity -Key $d.Department -Data $d }
        Write-Host ("  seeded {0,-34} {1} rows" -f $entity, $rows.Count)
        continue
    }
    $count = 0
    foreach ($r in $rows) {
        $key = Get-PimStoreRowKey -Base $entity -Row $r
        if (-not $key) { Write-Warning "  no key derived for a $entity row -- skipped"; continue }
        Set-PimSqlRow -ConnectionString $cs -Entity $entity -Key $key -Data $r
        $count++
    }
    Write-Host ("  seeded {0,-34} {1} rows" -f $entity, $count)
}

$marked = Invoke-PimSqlScalar -ConnectionString $cs -Sql "SELECT COUNT(*) FROM pim.Rows WHERE DataJson LIKE @md" -Parameters @{ md = "%$Marker%" }
Write-Host "Scenario seed complete: $marked marked rows in pim.Rows." -ForegroundColor Green
