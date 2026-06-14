<#
.SYNOPSIS
  Safe live-test harness for the NEW pim core engine. Marks the DESIRED group/AU names
  in SQL with a prefix so the engine creates BRAND-NEW objects (distinct from prod), then
  lets you verify and delete ONLY the marked objects. Your existing prod PIM groups
  (which never carry the marker) are never touched.

  Flow:
    .\Manage-PimCoreEngineTest.ps1 -Apply        # prefix GroupName/AUDisplayName in SQL
    .\Run-PimEngineOnMgmt.ps1 -Scope AdministrativeUnits   # create AUs
    .\Run-PimEngineOnMgmt.ps1 -Scope Groups                # create groups
    .\Run-PimEngineOnMgmt.ps1 -Scope EntraRoles            # assign roles to groups
    .\Run-PimEngineOnMgmt.ps1 -Scope AdminMembers          # admins -> eligible members
    .\Manage-PimCoreEngineTest.ps1 -Verify       # confirm created correctly
    .\Manage-PimCoreEngineTest.ps1 -Cleanup      # delete ONLY marked tenant objects
    .\Manage-PimCoreEngineTest.ps1 -Revert       # strip the marker from SQL

  -Apply/-Revert mutate the SQL desired rows REVERSIBLY (idempotent prefix add/strip).
  -Cleanup deletes only directory objects whose displayName starts with the marker.
#>
[CmdletBinding(DefaultParameterSetName = 'Verify')]
param(
    [Parameter(ParameterSetName = 'Apply')][switch]$Apply,
    [Parameter(ParameterSetName = 'Revert')][switch]$Revert,
    [Parameter(ParameterSetName = 'Cleanup')][switch]$Cleanup,
    [Parameter(ParameterSetName = 'Verify')][switch]$Verify,
    [string]$Marker      = 'PIMCOREENGINE-',
    [string]$SqlServer   = $env:PIM_SqlServer,
    [string]$SqlDatabase = $env:PIM_SqlDatabase
)
$ErrorActionPreference = 'Stop'
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$shared = Resolve-Path "$here\..\..\engine\_shared"
if (-not $SqlServer)   { throw "Set -SqlServer or `$env:PIM_SqlServer." }
if (-not $SqlDatabase) { throw "Set -SqlDatabase or `$env:PIM_SqlDatabase." }
$global:PIM_UseGraphSdk = $false
$global:PIM_SqlServer   = $SqlServer
$global:PIM_SqlDatabase = $SqlDatabase
. "$shared\PIM-Rest.ps1"
. "$shared\PIM-SqlStore.ps1"
$cs = Get-PimSqlConnectionString

# Group-name lives in these entities; AU-name in PIM-Definitions-AU.
$GroupEntities = @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization', 'PIM-Definitions-Tasks')
$NameField = @{
    'PIM-Definitions-Roles' = 'GroupName'; 'PIM-Definitions-Services' = 'GroupName'
    'PIM-Definitions-Organization' = 'GroupName'; 'PIM-Definitions-Tasks' = 'GroupName'
    'PIM-Definitions-AU' = 'AUDisplayName'
}

function Set-Marker {
    # One set-based UPDATE per entity (JSON_MODIFY) -- avoids opening a connection per
    # row (this DB has a 300-session cap). $fld is a fixed identifier we control.
    param([bool]$Add)
    $total = 0
    foreach ($entity in ($GroupEntities + 'PIM-Definitions-AU')) {
        $fld = $NameField[$entity]
        if ($Add) {
            $sql = "UPDATE pim.Rows SET DataJson = JSON_MODIFY(DataJson, '$.$fld', @m + JSON_VALUE(DataJson,'$.$fld')) " +
                   "WHERE Entity=@e AND JSON_VALUE(DataJson,'$.$fld') IS NOT NULL AND JSON_VALUE(DataJson,'$.$fld') NOT LIKE @ml"
        } else {
            $sql = "UPDATE pim.Rows SET DataJson = JSON_MODIFY(DataJson, '$.$fld', STUFF(JSON_VALUE(DataJson,'$.$fld'),1,LEN(@m),'')) " +
                   "WHERE Entity=@e AND JSON_VALUE(DataJson,'$.$fld') LIKE @ml"
        }
        $n = Invoke-PimSqlNonQuery -ConnectionString $cs -Sql $sql -Parameters @{ e = $entity; m = $Marker; ml = "$Marker%" }
        Write-Host ("  {0,-32} {1} row(s)" -f $entity, $n)
        $total += [int]$n
    }
    Write-Host ("{0} marker on {1} name(s)." -f $(if ($Add) {'Added'} else {'Removed'}), $total) -ForegroundColor Green
}

switch ($PSCmdlet.ParameterSetName) {
    'Apply'  { Write-Host "Marking desired group/AU names with '$Marker' ..." -ForegroundColor Cyan; Set-Marker -Add $true }
    'Revert' { Write-Host "Stripping '$Marker' from desired group/AU names ..." -ForegroundColor Cyan; Set-Marker -Add $false }
    'Verify' {
        Write-Host "Verifying tenant objects created with marker '$Marker' ..." -ForegroundColor Cyan
        $grps = @(Invoke-PimGraph -Path "/groups?`$filter=startswith(displayName,'$Marker')&`$select=id,displayName,isAssignableToRole" -All)
        $aus  = @(Invoke-PimGraph -Path "/directory/administrativeUnits?`$select=id,displayName" -All | Where-Object { "$($_.displayName)" -like "$Marker*" })
        Write-Host ("  AUs    : {0}" -f $aus.Count) -ForegroundColor Yellow
        Write-Host ("  Groups : {0}" -f $grps.Count) -ForegroundColor Yellow
        $sample = $grps | Select-Object -First 5
        foreach ($g in $sample) {
            $elig = @(Invoke-PimGraph -Path "/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$($g.id)'&`$expand=roleDefinition" -All)
            $act  = @(Invoke-PimGraph -Path "/roleManagement/directory/roleAssignmentSchedules?`$filter=principalId eq '$($g.id)'&`$expand=roleDefinition" -All)
            $mem  = @(Invoke-PimGraph -Path "/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($g.id)'" -All)
            Write-Host ("    {0}  roleAssignable={1}  roles(elig/active)={2}/{3}  members(elig)={4}" -f $g.displayName, $g.isAssignableToRole, $elig.Count, $act.Count, $mem.Count)
        }
    }
    'Cleanup' {
        Write-Host "Deleting ONLY tenant objects whose name starts with '$Marker' ..." -ForegroundColor Cyan
        $grps = @(Invoke-PimGraph -Path "/groups?`$filter=startswith(displayName,'$Marker')&`$select=id,displayName" -All)
        foreach ($g in $grps) { try { Invoke-PimGraph -Method DELETE -Path "/groups/$($g.id)" | Out-Null; Write-Host "  del group  $($g.displayName)" } catch { Write-Warning "  group $($g.displayName): $($_.Exception.Message)" } }
        $aus = @(Invoke-PimGraph -Path "/directory/administrativeUnits?`$select=id,displayName" -All | Where-Object { "$($_.displayName)" -like "$Marker*" })
        foreach ($a in $aus) { try { Invoke-PimGraph -Method DELETE -Path "/directory/administrativeUnits/$($a.id)" | Out-Null; Write-Host "  del AU     $($a.displayName)" } catch { Write-Warning "  AU $($a.displayName): $($_.Exception.Message)" } }
        Write-Host ("Deleted {0} group(s) + {1} AU(s)." -f $grps.Count, $aus.Count) -ForegroundColor Green
    }
}
