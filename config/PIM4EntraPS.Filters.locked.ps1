#Requires -Version 5.1
<#
.SYNOPSIS
    Default user/group/role selection filters for PIM4EntraPS engines.

.DESCRIPTION
    Engines call Build-PimContext (engine/_shared/PIM-ContextBuilder.ps1) which
    fetches the raw lists from Graph (Users, Groups, AUs, Roles) and then pipes
    each through one of these scriptblocks to produce filtered lists assigned to
    well-known $Global:*_Definitions_ID variables.

    Customers override by copying PIM4EntraPS.Filters.custom.sample.ps1 to
    PIM4EntraPS.Filters.custom.ps1 and reassigning any scriptblock. Filter keys
    you don't touch keep the locked default.

.NOTES
    Solution     : PIM4EntraPS
    Developed by : Morten Knudsen, Microsoft MVP
#>

$global:PIM_Filters = @{

    # ----- Admin candidates --------------------------------------------------
    # Default mirrors the original engine pattern: UPN starts with 'Admin-' or
    # 'X-Admin' AND contains '-ID' (Identity-domain admin tier marker).
    AdminCandidate = {
        param($user)
        ($user.UserPrincipalName -like 'Admin-*' -or $user.UserPrincipalName -like 'X-Admin*') `
            -and $user.UserPrincipalName -like '*-ID*'
    }

    # ----- PIM-managed groups (all) -----------------------------------------
    # All security groups whose DisplayName starts with the PIM- prefix.
    PimGroup = {
        param($group)
        $group.DisplayName -like 'PIM-*'
    }

    # ----- Subset: PIM Resource groups, AD-synced --------------------------
    # 'PIM-RES*-S_AD' pattern from the original engine. These represent
    # AD-synced resource scopes that are part of the nested-group PIM design.
    PimGroupResourceSyncAD = {
        param($group)
        $group.DisplayName -like 'PIM-RES*' -and $group.DisplayName -like '*-S_AD'
    }

    # ----- Subset: PIM Service groups, AD-synced ---------------------------
    PimGroupServiceSyncAD = {
        param($group)
        $group.DisplayName -like 'PIM-SERV*' -and $group.DisplayName -like '*-S_AD'
    }

    # ----- Roles allowed in Administrative Units ---------------------------
    # The 11 built-in Entra roles that the engine considers AU-scoped. Customer
    # tenants vary -- override this list per-tenant in the .custom.ps1 file.
    AURoleAllowed = {
        param($role)
        $role.DisplayName -in @(
            'Authentication Administrator'
            'Cloud Device Administrator'
            'Groups Administrator'
            'Helpdesk Administrator'
            'License Administrator'
            'Password Administrator'
            'Printer Administrator'
            'SharePoint Administrator'
            'Teams Administrator'
            'Teams Devices Administrator'
            'User Administrator'
        )
    }

    # ----- Azure subscriptions in PIM scope --------------------------------
    # Default: include every subscription the SPN can see. Override to a tag
    # or name filter for production-only scope, etc.
    AzureSubscription = {
        param($sub)
        $true
    }

}
