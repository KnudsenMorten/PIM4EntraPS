<#
.SYNOPSIS
  The PURE desired-set builder for the PIM4EntraPS scenario simulation. NO param() block,
  so it is SAFE to dot-source at any scope (a script param() block would clobber same-named
  caller variables when dot-sourced). It is the single source of truth shared by:
     * Seed-PimScenarioDataset.ps1  -- writes the set into the SQL store (Manager / GUI).
     * PIM-ScenarioHarness.ps1      -- loads the same set for the offline engine sim.

  Returns an ORDERED hashtable Entity -> @(rows...). Entity names + bases mirror the
  engine's pim.Rows entities (Get-PimStoreRowKey understands them). See the header of
  Seed-PimScenarioDataset.ps1 for what the rich estate covers.
#>

function Get-PimScenarioSeedSpec {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OwnerUpn,
        [Parameter(Mandatory)][string]$DefaultDomain,
        [string]$Marker = 'PIMSCENARIO-',
        [string]$AzSubscriptionId = '00000000-0000-0000-0000-0000000000aa',
        [string]$AzRoleName = 'Owner'
    )
    $m   = $Marker
    $own = $OwnerUpn
    $hr  = "hrmanager@$DefaultDomain"   # a second real-ish owner used for HR department routing

    # Administrative Units (scope containers across tiers)
    $aus = @(
        @{ AdministrativeUnitTag='AU-L0'; AUDisplayName="${m}AU-HighPrivGlobalRoles"; AUDescription='High-priv global roles (scenario)'; Workload='PIM'; Level='L0'; Visibility='Public' }
        @{ AdministrativeUnitTag='AU-L1'; AUDisplayName="${m}AU-PlatformAdmins";      AUDescription='Platform admins (scenario)';        Workload='PIM'; Level='L1'; Visibility='Public' }
        @{ AdministrativeUnitTag='AU-L2'; AUDisplayName="${m}AU-ScopedHelpdesk";      AUDescription='AU-scoped helpdesk (scenario)';     Workload='PIM'; Level='L2'; Visibility='Public' }
    )

    # Departments (people-based owner source -- a blank-Owners group inherits these).
    $departments = @(
        @{ Department='IT';       Owners=$own; Mode='Serial' }
        @{ Department='Security'; Owners=$own; Mode='Serial' }
        @{ Department='HR';       Owners=$hr;  Mode='Parallel' }
    )

    # Role groups (job functions). T0 break-glass + T1 day-to-day.
    $roles = @(
        @{ GroupName="${m}PIM-ROLE-SecurityLead"; GroupTag="${m}ROLE-SecurityLead"; GroupDescription='Security lead role group (scenario)'; IsRoleAssignable='TRUE'; Department='Security'; SponsorUpn=$own; PolicyTemplate='approval-required' }
        @{ GroupName="${m}PIM-ROLE-CloudEngineer"; GroupTag="${m}ROLE-CloudEngineer"; GroupDescription='Cloud engineer role group (scenario)'; IsRoleAssignable='TRUE'; Department='IT'; SponsorUpn=$own; PolicyTemplate='' }
        @{ GroupName="${m}PIM-ROLE-WorkloadOwner"; GroupTag="${m}ROLE-WorkloadOwner"; GroupDescription='Azure workload owner role group (scenario)'; IsRoleAssignable='FALSE'; Department='IT'; SponsorUpn=$own; PolicyTemplate='' }
    )

    # Permission/service groups -- Levels L0-L3, planes CP/MP/WDP, Entra + Azure + Power BI.
    # High-priv (GA + PRA) carry approval-required; the rest are the no-approval baseline.
    $services = @(
        @{ GroupName="${m}PIM-Entra-ID-GlobalAdministrator-L0-T0-CP-ID";         GroupTag="${m}Entra-ID-GlobalAdministrator-L0";         GroupDescription='Global Administrator (scenario)';          IsRoleAssignable='TRUE'; Workload='Entra-ID'; Level='L0'; Plane='CP'; CPPlatform='ID'; Department='Security'; PolicyTemplate='approval-required' }
        @{ GroupName="${m}PIM-Entra-ID-PrivilegedRoleAdministrator-L0-T0-CP-ID"; GroupTag="${m}Entra-ID-PrivilegedRoleAdministrator-L0"; GroupDescription='Privileged Role Administrator (scenario)'; IsRoleAssignable='TRUE'; Workload='Entra-ID'; Level='L0'; Plane='CP'; CPPlatform='ID'; Department='Security'; PolicyTemplate='approval-required' }
        @{ GroupName="${m}PIM-Entra-ID-UserAdministrator-L1-T0-CP-ID";           GroupTag="${m}Entra-ID-UserAdministrator-L1";           GroupDescription='User Administrator (scenario)';            IsRoleAssignable='TRUE'; Workload='Entra-ID'; Level='L1'; Plane='CP'; CPPlatform='ID'; Department='IT'; PolicyTemplate='' }
        @{ GroupName="${m}PIM-Entra-Helpdesk-L2-T1-CP-ID";                       GroupTag="${m}Entra-Helpdesk-L2";                       GroupDescription='Helpdesk Administrator (scenario)';        IsRoleAssignable='TRUE'; Workload='Entra-ID'; Level='L2'; Plane='CP'; CPPlatform='ID'; AdministrativeUnitTag='AU-L2'; Department='IT'; PolicyTemplate='' }
        @{ GroupName="${m}PIM-PowerBI-WorkspaceAdmin-L3-T1-WDP-PBI";            GroupTag="${m}PowerBI-WorkspaceAdmin-L3";               GroupDescription='Power BI workspace admin (scenario)';      IsRoleAssignable='FALSE'; Workload='PowerBI'; Level='L3'; Plane='WDP'; CPPlatform='PBI'; Department='IT'; PolicyTemplate='' }
    )

    # Azure-RBAC permission group (delegation target is an Azure scope) -- the workload-owner surface.
    $azGroups = @(
        @{ GroupName="${m}PIM-AzRes-Subscription-${AzRoleName}-L5-T0-MP-RES"; GroupTag="${m}AzRes-Subscription-${AzRoleName}-L5"; GroupDescription="Azure $AzRoleName at subscription (scenario)"; IsRoleAssignable='FALSE'; Workload='Azure'; Level='L5'; Plane='MP'; CPPlatform='RES'; Department='IT'; PolicyTemplate='' }
    )
    $azAssignments = @(
        @{ GroupTag="${m}AzRes-Subscription-${AzRoleName}-L5"; AzScope="/subscriptions/$AzSubscriptionId"; AzScopePermission=$AzRoleName; AssignmentType='Eligible'; Action='Assign'; Permanent='FALSE'; NumOfDaysWhenExpire='365' }
    )

    # Admin accounts (T0 break-glass, T1 day-to-day cloud engineer, a consultant with a
    # scheduled TAP, and a flagged OFFBOARDING admin).
    $lm = $m.ToLower()
    $admins = @(
        @{ FirstName='Break'; LastName='Glass';  Initials='BG'; TargetUsage='Cloud'; TargetPlatform='ID'; UserType='Member'; UserName="${m}Admin-BG-L0-T0-ID"; DisplayName="${m}Admin Break Glass (scenario)";  UserPrincipalName="${lm}admin-bg-l0-t0-id@$DefaultDomain"; UsageLocation='DK'; AccountStatus='Enabled'; CreateTAP='FALSE'; Purpose='Service'; Department='Security' }
        @{ FirstName='Cloud'; LastName='Engineer'; Initials='CE'; TargetUsage='Cloud'; TargetPlatform='ID'; UserType='Member'; UserName="${m}Admin-CE-L1-T1-ID"; DisplayName="${m}Admin Cloud Engineer (scenario)"; UserPrincipalName="${lm}admin-ce-l1-t1-id@$DefaultDomain"; UsageLocation='DK'; AccountStatus='Enabled'; CreateTAP='FALSE'; Purpose='Day2Day'; Department='IT' }
        @{ FirstName='Connie'; LastName='Sultant'; Initials='CS'; TargetUsage='Cloud'; TargetPlatform='ID'; UserType='Member'; UserName="${m}Admin-CS-L2-T1-ID"; DisplayName="${m}Admin Consultant (scenario)";    UserPrincipalName="${lm}admin-cs-l2-t1-id@$DefaultDomain"; UsageLocation='DK'; AccountStatus='Enabled'; CreateTAP='TRUE'; TAPStartDate='Now'; TAPLifetimeHours='8'; Purpose='Day2Day'; Department='IT' }
        @{ FirstName='Olive'; LastName='Boarding'; Initials='OB'; TargetUsage='Cloud'; TargetPlatform='ID'; UserType='Member'; UserName="${m}Admin-OB-L2-T1-ID"; DisplayName="${m}Admin Offboarding (scenario)";   UserPrincipalName="${lm}admin-ob-l2-t1-id@$DefaultDomain"; UsageLocation='DK'; AccountStatus='Enabled'; CreateTAP='FALSE'; Purpose='Day2Day'; Department='IT'; Lifecycle='Retire' }
    )

    # Admin -> role-group delegations (membership).
    $adminAssignments = @(
        @{ Username="${lm}admin-bg-l0-t0-id@$DefaultDomain"; GroupTag="${m}ROLE-SecurityLead";  AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE' }
        @{ Username="${lm}admin-ce-l1-t1-id@$DefaultDomain"; GroupTag="${m}ROLE-CloudEngineer"; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE' }
        @{ Username="${lm}admin-cs-l2-t1-id@$DefaultDomain"; GroupTag="${m}ROLE-CloudEngineer"; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='90';  Permanent='FALSE' }
        @{ Username="${lm}admin-cs-l2-t1-id@$DefaultDomain"; GroupTag="${m}ROLE-WorkloadOwner"; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='90';  Permanent='FALSE' }
        @{ Username="${lm}admin-ob-l2-t1-id@$DefaultDomain"; GroupTag="${m}ROLE-CloudEngineer"; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='90';  Permanent='FALSE' }
    )

    # Group nesting: role group -> permission groups (Tier 2 -> Tier 3).
    $groupAssignments = @(
        @{ TargetGroupTag="${m}Entra-ID-GlobalAdministrator-L0";         SourceGroupTag="${m}ROLE-SecurityLead";  AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE' }
        @{ TargetGroupTag="${m}Entra-ID-PrivilegedRoleAdministrator-L0"; SourceGroupTag="${m}ROLE-SecurityLead";  AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE' }
        @{ TargetGroupTag="${m}Entra-ID-UserAdministrator-L1";           SourceGroupTag="${m}ROLE-CloudEngineer"; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE' }
        @{ TargetGroupTag="${m}Entra-Helpdesk-L2";                       SourceGroupTag="${m}ROLE-CloudEngineer"; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE' }
        @{ TargetGroupTag="${m}AzRes-Subscription-${AzRoleName}-L5";     SourceGroupTag="${m}ROLE-WorkloadOwner"; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE' }
    )

    # Entra role -> permission group bindings.
    $roleGroupAssignments = @(
        @{ GroupTag="${m}Entra-ID-GlobalAdministrator-L0";         RoleDefinitionName='Global Administrator';          AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE'; Plane='CP'; PermissionScope='Global' }
        @{ GroupTag="${m}Entra-ID-PrivilegedRoleAdministrator-L0"; RoleDefinitionName='Privileged Role Administrator'; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE'; Plane='CP'; PermissionScope='Global' }
        @{ GroupTag="${m}Entra-ID-UserAdministrator-L1";           RoleDefinitionName='User Administrator';            AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE'; Plane='CP'; PermissionScope='Global' }
        @{ GroupTag="${m}Entra-Helpdesk-L2";                       RoleDefinitionName='Helpdesk Administrator';        AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='90';  Permanent='FALSE'; Plane='CP'; PermissionScope='AU' }
    )

    [ordered]@{
        'PIM-Definitions-AU'                = $aus              | ForEach-Object { [pscustomobject]$_ }
        'PIM-Definitions-Departments'       = $departments     | ForEach-Object { [pscustomobject]$_ }
        'PIM-Definitions-Roles'             = $roles           | ForEach-Object { [pscustomobject]$_ }
        'PIM-Definitions-Services'          = ($services + $azGroups) | ForEach-Object { [pscustomobject]$_ }
        'Account-Definitions-Admins'        = $admins          | ForEach-Object { [pscustomobject]$_ }
        'PIM-Assignments-Admins'            = $adminAssignments | ForEach-Object { [pscustomobject]$_ }
        'PIM-Assignments-Groups'            = $groupAssignments | ForEach-Object { [pscustomobject]$_ }
        'PIM-Assignments-Roles-Groups'      = $roleGroupAssignments | ForEach-Object { [pscustomobject]$_ }
        'PIM-Assignments-Azure-Resources'   = $azAssignments   | ForEach-Object { [pscustomobject]$_ }
    }
}
