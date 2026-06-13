#Requires -Version 5.1
<#
.SYNOPSIS
    PIM-Engine -- the single consolidated engine entrypoint. Replaces the many
    PIM-Baseline-Management-CSV[-*Only] scripts with one command + a -Scope (and
    -Mode) selector. "CSV" is gone from the name: the backend is the SQL store
    (or, in the legacy path, the per-scope scripts this dispatches to).

.DESCRIPTION
    Additive + non-breaking: this routes -Scope to the existing, proven per-scope
    engine scripts and passes through any remaining arguments, so current
    schedules keep working while everything moves to the PIM-Engine name. The
    physical de-CSV of the underlying dirs happens in the SQL-only cleanup.

.PARAMETER Scope
    What to reconcile: All (full baseline) | Admins | EntraRoles | AzRes |
    AdministrativeUnits | GroupsAssignment | GroupsPolicies |
    GroupsCreateModifyPolicy | Export.

.PARAMETER Mode
    Full (reconcile everything) or Delta (apply only queued changes -- the SQL
    change-queue path). Legacy per-scope scripts run Full.

.EXAMPLE
    .\PIM-Engine.ps1                       # full baseline
.EXAMPLE
    .\PIM-Engine.ps1 -Scope Admins         # admins only
.EXAMPLE
    .\PIM-Engine.ps1 -Scope EntraRoles -Mode Full
#>
[CmdletBinding()]
param(
    [ValidateSet('All','Admins','EntraRoles','AzRes','AdministrativeUnits','GroupsAssignment','GroupsPolicies','GroupsCreateModifyPolicy','Export')]
    [string]$Scope = 'All',
    [ValidateSet('Full','Delta')]
    [string]$Mode = 'Full',
    [Parameter(ValueFromRemainingArguments = $true)]
    [object[]]$Rest
)
$ErrorActionPreference = 'Stop'
$engineRoot = Split-Path -Parent $PSScriptRoot

# -Scope -> the proven per-scope engine script (legacy dir names retain 'CSV'
# until the SQL-only cleanup physically renames them).
$map = [ordered]@{
    All                      = 'PIM-Baseline-Management-CSV'
    Admins                   = 'PIM-Baseline-Management-CSV-AdminsOnly'
    EntraRoles               = 'PIM-Baseline-Management-CSV-EntraIDRolesOnly'
    AzRes                    = 'PIM-Baseline-Management-CSV-AzResOnly'
    AdministrativeUnits      = 'PIM-Baseline-Management-CSV-AdministrativeUnitsOnly'
    GroupsAssignment         = 'PIM-Baseline-Management-CSV-PIM4GroupsAssignmentOnly'
    GroupsPolicies           = 'PIM-Baseline-Management-CSV-PIM4GroupsPoliciesOnly'
    GroupsCreateModifyPolicy = 'PIM-Baseline-Management-CSV-PIM4GroupsCreateModifyPolicyOnly'
    Export                   = 'PIM-Assignment-Exporter'
}

function Get-PimEngineTargetPath {
    # Pure mapping helper (testable): -Scope -> the script path under engine/.
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$EngineRoot)
    $m = [ordered]@{
        All='PIM-Baseline-Management-CSV'; Admins='PIM-Baseline-Management-CSV-AdminsOnly'
        EntraRoles='PIM-Baseline-Management-CSV-EntraIDRolesOnly'; AzRes='PIM-Baseline-Management-CSV-AzResOnly'
        AdministrativeUnits='PIM-Baseline-Management-CSV-AdministrativeUnitsOnly'
        GroupsAssignment='PIM-Baseline-Management-CSV-PIM4GroupsAssignmentOnly'
        GroupsPolicies='PIM-Baseline-Management-CSV-PIM4GroupsPoliciesOnly'
        GroupsCreateModifyPolicy='PIM-Baseline-Management-CSV-PIM4GroupsCreateModifyPolicyOnly'
        Export='PIM-Assignment-Exporter'
    }
    if (-not $m.Contains($Scope)) { return $null }
    $d = $m[$Scope]
    return (Join-Path $EngineRoot (Join-Path $d "$d.ps1"))
}

$target = Get-PimEngineTargetPath -Scope $Scope -EngineRoot $engineRoot
if (-not $target -or -not (Test-Path -LiteralPath $target)) { throw "PIM-Engine: scope '$Scope' did not resolve to an engine script ($target)." }
if ($Mode -eq 'Delta') { Write-Host "[PIM-Engine] Delta = the SQL change-queue path; legacy scope scripts run Full. Use the SQL store engine for true delta." -ForegroundColor Yellow }
Write-Host ("[PIM-Engine] Scope={0} Mode={1} -> {2}" -f $Scope, $Mode, (Split-Path -Leaf $target)) -ForegroundColor Cyan
& $target @Rest
exit $LASTEXITCODE
