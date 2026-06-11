#Requires -Version 5.1
<#
.SYNOPSIS
    Default naming conventions for admin accounts, PIM groups, and resource
    groups created/managed by PIM4EntraPS.

.DESCRIPTION
    These are the defaults that ship from the repo. Customers override per-tenant
    by copying PIM4EntraPS.NamingConventions.custom.sample.ps1 to
    PIM4EntraPS.NamingConventions.custom.ps1 and editing the pattern strings
    or hashtable values they need to change.

    Engines look up names via helper functions in engine/_shared/PIM-Functions.psm1:

      Resolve-PimAdminName      -Owner 'morten'         -> e.g. 'adm_morten'
      Resolve-PimGroupName      -Role 'GlobalAdmin' -Department 'IT'  -> e.g. 'PIM_GlobalAdmin_IT'
      Resolve-PimResourceGroup  -Tier 0                 -> e.g. 'rg-pim-t0'

    The helpers read $global:PIM_NamingConventions set by this file (and
    optionally overridden by the .custom.ps1 file loaded after).

    The PIM Manager UI (tools/pim-manager/) also reads from this hashtable to
    drive the "Re-add definition" / "Fix-all" wizards -- specifically
    TagPrefixToCsv and PimGroupTagRegex (see .custom.sample.ps1 for the
    full schema + per-key documentation).

.NOTES
    Solution     : PIM4EntraPS
    Developed by : Morten Knudsen, Microsoft MVP
#>

$global:PIM_NamingConventions = @{

    # ----- Admin accounts ---------------------------------------------------
    # TWO separate concepts, often confused:
    #
    #   AdminAccountPattern  (singular, string, has {Owner} token)
    #     -> TEMPLATE used by Resolve-PimAdminName to GENERATE new admin UPNs.
    #        E.g. 'Admin-{Owner}-L0-T0-ID' + Owner 'Brian' yields
    #        'Admin-Brian-L0-T0-ID'. Only matters when the engine creates
    #        new admins.
    #
    #   AdminAccountPatterns (plural; accepts string[], hashtable, or single string)
    #     -> Prefix(es) used by Get-PimAdminsFiltered to build the Graph
    #        $filter that decides which existing users get loaded into the
    #        $Global:Users_All_ID cache. If your tenant has admins under
    #        multiple prefix conventions (Admin-*, X-Admin*, ...), list
    #        them ALL here so the cache catches them all.
    #
    # Defaults below assume the 'Admin-' / 'X-Admin' tier-naming convention
    # observed in production tenants. Override either key in
    # PIM4EntraPS.NamingConventions.custom.ps1 if your tenant differs.
    AdminAccountPattern  = 'Admin-{Owner}'
    AdminAccountPatterns = @('Admin-', 'X-Admin')

    # UPN suffix for admin accounts (when creating new ones). Null = use tenant default.
    AdminAccountUpnSuffix = $null

    # ----- PIM groups -------------------------------------------------------
    # Security groups created/managed for PIM role assignment.
    # Tokens: {Role}, {Department}, {Tier}
    # v2.4.69: switched separator '_' -> '-'. The underscore-form was a
    # legacy carry-over and didn't match what any in-the-wild customer
    # uses (PIM-DEPT-Finance, PIM-ROLE-Internal-IT, etc.). The mismatch
    # caused Get-PimGroupsFiltered to query startswith(displayName,'PIM_')
    # and return zero rows, which collapsed the cache and led every
    # CreateUpdate-PIM-Group call to look up an empty cache, find $null,
    # and create a duplicate group every run. If your tenant really does
    # use underscores, override in PIM4EntraPS.NamingConventions.custom.ps1.
    PimGroupPattern = 'PIM-{Role}-{Department}'

    # Subset for AU-bound assignments (administrative unit)
    PimGroupAuPattern = 'PIM-{Role}-AU-{AdminUnit}'

    # Optional STRICT regex for GroupTag values. When set, the PIM Manager's
    # naming-convention warning (PIM-NAME-001) fires on any tag that doesn't
    # match. Default (null) = Manager accepts any alphanumeric tag.
    PimGroupTagRegex = $null

    # ----- Tag-prefix -> Definition CSV map (Manager wizard input) ---------
    # When the Manager re-adds a missing definition, it uses this map to
    # pick the right PIM-Definitions-*.csv. Longest-prefix match wins. If
    # empty, the Manager falls back to scanning the customer's existing
    # rows to learn which CSV historically holds tags with each prefix.
    # See .custom.sample.ps1 for a complete worked example.
    TagPrefixToCsv = @{}

    # ----- On-prem AD OU paths ---------------------------------------------
    # Where the PIM-Baseline-Management-CSV engine's AD-Create branch lands
    # new admin accounts (New-ADUser -Path <DN>). Two OUs:
    #
    #   PathAdmins     -- general admin accounts (no L0/T0 marker in name)
    #   PathAdminsL0T0 -- high-priv admins whose UserName carries L0 or T0
    #                     (e.g. 'Admin-SKR-L0-T0-AD'); routed automatically
    #                     by the v2.4.122 UserName-regex check.
    #
    # Both default to $null -- customers must override in
    # PIM4EntraPS.NamingConventions.custom.ps1, e.g.:
    #   $global:PIM_NamingConventions.PathAdmins     = 'OU=...,DC=casa,DC=dk'
    #   $global:PIM_NamingConventions.PathAdminsL0T0 = 'OU=...,DC=casa,DC=dk'
    # Co-mingled tenants point both at the same DN.
    PathAdmins     = $null
    PathAdminsL0T0 = $null

    # ----- Azure resource groups -------------------------------------------
    # When PIM4EntraPS provisions Azure resources (e.g. AU storage), naming pattern:
    ResourceGroupPattern = 'rg-pim-{Tier}'

    # ----- Display name suffix conventions (optional polish) ---------------
    AdminAccountDisplayNameSuffix = ' (Admin)'

}
