<#
.SYNOPSIS
  Seed a small, REPRESENTATIVE PIM baseline desired-set into the SQL desired store
  (pim.Rows) so the real engine (Invoke-PimEngineCore.ps1) can deploy it end-to-end.

  This is the first-time-deploy dataset: a couple of Administrative Units, a role group,
  a few atomic permission (service) groups across planes, departments-with-owners, admin
  accounts, admin->group delegations, group nesting, an Entra-role->group assignment, and
  an approval-required policy on the high-priv group. It is deliberately SMALL (deploys in
  seconds, not the full ~300-group production model) yet exercises every provider.

  SAFETY: every created tenant object's display name is prefixed with the marker
  (default 'PIMCOREENGINE-') so cleanup (Manage-PimCoreEngineTest.ps1 -Cleanup or
  Seed-PimDummyData.ps1 -DeleteTenantObjects) only ever touches marked objects. Prod
  groups (no marker) are never created or deleted by this path.

  Owners must be REAL resolvable users in the target tenant (you cannot own a group with
  a non-existent user). Pass -OwnerUpn with a real account in the tenant you deploy to.

.EXAMPLE
  $env:PIM_SqlServer='.\SQLEXPRESS'; $env:PIM_SqlDatabase='PimPlatform'
  .\Seed-PimBaselineDataset.ps1 -OwnerUpn admin@2linkit.onmicrosoft.com -DefaultDomain 2linkit.onmicrosoft.com
.EXAMPLE
  .\Seed-PimBaselineDataset.ps1 -Clear     # remove ALL marked desired rows from SQL (keeps tenant objects)
#>
[CmdletBinding(DefaultParameterSetName = 'Seed')]
param(
    [Parameter(ParameterSetName = 'Seed', Mandatory)][string]$OwnerUpn,
    [Parameter(ParameterSetName = 'Seed', Mandatory)][string]$DefaultDomain,
    # Optional: add the Azure-RBAC delegation surface (an Azure role eligible to a PIM group at this
    # subscription scope). Without it the seed covers Entra-roles + PIM-for-Groups only.
    [Parameter(ParameterSetName = 'Seed')][string]$AzSubscriptionId,
    [Parameter(ParameterSetName = 'Seed')][string]$AzRoleName = 'Reader',
    [Parameter(ParameterSetName = 'Clear')][switch]$Clear,
    [string]$Marker      = 'PIMCOREENGINE-',
    [string]$SqlServer   = $env:PIM_SqlServer,
    [string]$SqlDatabase = $env:PIM_SqlDatabase
)
$ErrorActionPreference = 'Stop'
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$shared = Resolve-Path "$here\..\..\engine\_shared"
if (-not $SqlServer)   { $SqlServer = '.\SQLEXPRESS' }
if (-not $SqlDatabase) { throw "Set -SqlDatabase or `$env:PIM_SqlDatabase (e.g. PimPlatform)." }
$global:PIM_UseGraphSdk = $false; $global:PIM_SqlServer = $SqlServer; $global:PIM_SqlDatabase = $SqlDatabase
. "$shared\PIM-ChangeQueue.ps1"; . "$shared\PIM-SqlStore.ps1"

# ensure DB + schema exist (local store first-time bootstrap)
Initialize-PimSqlDatabase -Server $SqlServer -Database $SqlDatabase
$cs = Get-PimSqlConnectionString
Initialize-PimSqlStore -ConnectionString $cs

# Entities this seed owns -- a -Clear removes only marked rows from these.
$entities = @(
    'PIM-Definitions-AU','PIM-Definitions-Roles','PIM-Definitions-Services',
    'PIM-Definitions-Departments','Account-Definitions-Admins','PIM-Assignments-Admins',
    'PIM-Assignments-Groups','PIM-Assignments-Roles-Groups','PIM-Assignments-Azure-Resources'
)

if ($Clear) {
    $removed = 0
    foreach ($e in $entities) {
        $n = Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "DELETE FROM pim.Rows WHERE Entity=@e AND ([Key] LIKE @m OR DataJson LIKE @md)" -Parameters @{ e = $e; m = "$Marker%"; md = "%$Marker%" }
        $removed += [int]$n
    }
    Write-Host "Cleared $removed marked desired rows from SQL (tenant objects untouched)." -ForegroundColor Green
    return
}

# ---- the representative desired set (all names marker-prefixed) ----------------
$m   = $Marker
$own = $OwnerUpn

# Administrative Units (scope containers)
$aus = @(
    @{ AdministrativeUnitTag = 'AU-L0'; AUDisplayName = "${m}AU-HighPrivGlobalRoles"; AUDescription = 'High-priv global roles (seed)'; Workload='PIM'; Level='L0'; Visibility='Public' }
    @{ AdministrativeUnitTag = 'AU-L2'; AUDisplayName = "${m}AU-ScopedHelpdesk";       AUDescription = 'AU-scoped helpdesk (seed)';     Workload='PIM'; Level='L2'; Visibility='Public' }
)
# Departments (owner source -- a group with a blank Owners column inherits these)
$departments = @(
    @{ Department = 'IT';       Owners = $own; Mode = 'Serial' }
    @{ Department = 'Security'; Owners = $own; Mode = 'Serial' }
)
# Role group (job function -- Tier 2)
$roles = @(
    @{ GroupName = "${m}PIM-ROLE-CloudEngineer"; GroupTag = "${m}ROLE-CloudEngineer"; GroupDescription = 'Cloud engineer role group (seed)'; IsRoleAssignable = 'TRUE'; Department = 'IT'; SponsorUpn = $own; PolicyTemplate = '' }
)
# Permission (service) groups (atomic capability -- Tier 3) across planes.
# High-priv (GA + PRA) carry approval-required; everything else is the no-approval baseline.
$services = @(
    @{ GroupName = "${m}PIM-Entra-ID-GlobalAdministrator-L0-T0-CP-ID";          GroupTag = "${m}Entra-ID-GlobalAdministrator-L0"; GroupDescription = 'Global Administrator (seed)';            IsRoleAssignable = 'TRUE';  Workload='Entra-ID'; Level='L0'; Plane='CP'; CPPlatform='ID'; Department='Security'; PolicyTemplate='approval-required' }
    @{ GroupName = "${m}PIM-Entra-ID-PrivilegedRoleAdministrator-L1-T0-CP-ID";  GroupTag = "${m}Entra-ID-PrivilegedRoleAdministrator-L1"; GroupDescription = 'Privileged Role Administrator (seed)'; IsRoleAssignable = 'TRUE';  Workload='Entra-ID'; Level='L1'; Plane='CP'; CPPlatform='ID'; Department='Security'; PolicyTemplate='approval-required' }
    @{ GroupName = "${m}PIM-Entra-ID-UserAdministrator-L1-T0-CP-ID";            GroupTag = "${m}Entra-ID-UserAdministrator-L1";   GroupDescription = 'User Administrator (seed)';              IsRoleAssignable = 'TRUE';  Workload='Entra-ID'; Level='L1'; Plane='CP'; CPPlatform='ID'; Department='IT';       PolicyTemplate='' }
    @{ GroupName = "${m}PIM-Entra-Helpdesk-L2-T0-CP-ID";                        GroupTag = "${m}Entra-Helpdesk-L2";               GroupDescription = 'Helpdesk Administrator (seed)';          IsRoleAssignable = 'TRUE';  Workload='Entra-ID'; Level='L2'; Plane='CP'; CPPlatform='ID'; AdministrativeUnitTag='AU-L2'; Department='IT'; PolicyTemplate='' }
)
# Azure-RBAC permission group (non-role-assignable; the delegation target is an Azure scope).
$azGroups = @()
$azAssignments = @()
if ($AzSubscriptionId) {
    $azGroups += @{ GroupName = "${m}PIM-AzRes-Subscription-${AzRoleName}-L5-T1-MP-RES"; GroupTag = "${m}AzRes-Subscription-${AzRoleName}-L5"; GroupDescription = "Azure $AzRoleName at subscription (seed)"; IsRoleAssignable = 'FALSE'; Workload='Azure'; Level='L5'; Plane='MP'; CPPlatform='RES'; Department='IT'; PolicyTemplate='' }
    $azAssignments += @{ GroupTag = "${m}AzRes-Subscription-${AzRoleName}-L5"; AzScope = "/subscriptions/$AzSubscriptionId"; AzScopePermission = $AzRoleName; AssignmentType='Eligible'; Action='Assign'; Permanent='FALSE'; NumOfDaysWhenExpire='365' }
}
# Admin accounts (Tier 1)
$admins = @(
    @{ FirstName='Cloud'; LastName='Engineer'; Initials='CE'; TargetUsage='Cloud'; TargetPlatform='ID'; UserType='Member'; UserName="${m}Admin-CE-L1-T0-ID"; DisplayName="${m}Admin Cloud Engineer (seed)"; UserPrincipalName="$($m.ToLower())admin-ce-l1-t0-id@$DefaultDomain"; UsageLocation='DK'; AccountStatus='Enabled'; CreateTAP='FALSE'; Purpose='Service' }
)
# Admin -> role group delegation (membership)
$adminAssignments = @(
    @{ Username = "$($m.ToLower())admin-ce-l1-t0-id@$DefaultDomain"; GroupTag = "${m}ROLE-CloudEngineer"; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE' }
)
# Group nesting: role group -> permission groups (Tier 2 -> Tier 3)
$groupAssignments = @(
    @{ TargetGroupTag = "${m}Entra-ID-UserAdministrator-L1"; SourceGroupTag = "${m}ROLE-CloudEngineer"; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE' }
)
# Entra role -> permission group assignment (the role binding)
$roleGroupAssignments = @(
    @{ GroupTag = "${m}Entra-ID-GlobalAdministrator-L0";         RoleDefinitionName = 'Global Administrator';            AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE'; Plane='CP'; PermissionScope='Global' }
    @{ GroupTag = "${m}Entra-ID-PrivilegedRoleAdministrator-L1"; RoleDefinitionName = 'Privileged Role Administrator';   AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE'; Plane='CP'; PermissionScope='Global' }
    @{ GroupTag = "${m}Entra-ID-UserAdministrator-L1";           RoleDefinitionName = 'User Administrator';              AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE'; Plane='CP'; PermissionScope='Global' }
    @{ GroupTag = "${m}Entra-Helpdesk-L2";                       RoleDefinitionName = 'Helpdesk Administrator';          AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='90';  Permanent='FALSE'; Plane='CP'; PermissionScope='AU' }
)

function Seed-Rows([string]$Entity, [object[]]$Rows, [string]$Base) {
    $b = if ($Base) { $Base } else { $Entity }
    $count = 0
    foreach ($r in $Rows) {
        $obj = [pscustomobject]$r
        $key = Get-PimStoreRowKey -Base $b -Row $obj
        if (-not $key) { Write-Warning "  no key derived for a $Entity row -- skipped"; continue }
        Set-PimSqlRow -ConnectionString $cs -Entity $Entity -Key $key -Data $obj
        $count++
    }
    Write-Host ("  seeded {0,-32} {1} rows" -f $Entity, $count)
}

Write-Host "Seeding representative PIM baseline into $SqlServer / $SqlDatabase (marker '$Marker', owner '$OwnerUpn')..." -ForegroundColor Cyan
Seed-Rows 'PIM-Definitions-AU'            $aus                 'PIM-Definitions-AU'
# Departments are keyed by Department name (no GroupTag/GroupName column -> set key directly).
foreach ($d in $departments) { Set-PimSqlRow -ConnectionString $cs -Entity 'PIM-Definitions-Departments' -Key $d.Department -Data ([pscustomobject]$d) }
Write-Host ("  seeded {0,-32} {1} rows" -f 'PIM-Definitions-Departments', $departments.Count)
Seed-Rows 'PIM-Definitions-Roles'        $roles               'PIM-Definitions-Roles'
Seed-Rows 'PIM-Definitions-Services'     ($services + $azGroups) 'PIM-Definitions-Services'
Seed-Rows 'Account-Definitions-Admins'   $admins              'Account-Definitions-Admins'
Seed-Rows 'PIM-Assignments-Admins'       $adminAssignments    'PIM-Assignments-Admins'
Seed-Rows 'PIM-Assignments-Groups'       $groupAssignments    'PIM-Assignments-Groups'
Seed-Rows 'PIM-Assignments-Roles-Groups' $roleGroupAssignments 'PIM-Assignments-Roles-Groups'
if ($azAssignments.Count) { Seed-Rows 'PIM-Assignments-Azure-Resources' $azAssignments 'PIM-Assignments-Azure-Resources' }

$marked = Invoke-PimSqlScalar -ConnectionString $cs -Sql "SELECT COUNT(*) FROM pim.Rows WHERE DataJson LIKE @md" -Parameters @{ md = "%$Marker%" }
Write-Host "Seed complete: $marked marked rows in pim.Rows. Deploy with Invoke-PimEngineCore.ps1 -Scope All -Mode Delta." -ForegroundColor Green
