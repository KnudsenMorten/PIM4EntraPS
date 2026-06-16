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

      Resolve-PimAdminName      -Owner 'mok'            -> e.g. 'admin-mok-id'
      Resolve-PimGroupName      -Role 'GlobalAdmin' -Department 'IT'  -> e.g. 'PIM-GlobalAdmin-IT'
      Resolve-PimResourceGroup  -Tier 1 -Workload 'AzDevOps' -Scope 'OrgCollectionAdministrators' -Level 2 -Plane 'WDP' -Platform 'ID'
                                                        -> e.g. 'PIM-AzDevOps-OrgCollectionAdministrators-L2-T1-WDP-ID'

    The helpers read $global:PIM_NamingConventions set by this file (and
    optionally overridden by the .custom.ps1 file loaded after).

    The PIM Manager UI (tools/pim-manager/) also reads from this hashtable to
    drive the "Re-add definition" / "Fix-all" wizards -- specifically
    PimGroupTagRegex (see .custom.sample.ps1 for the full schema + per-key
    documentation).

.NOTES
    Solution     : PIM4EntraPS
    Developed by : Morten Knudsen, Microsoft MVP
#>

$global:PIM_NamingConventions = @{

    # ----- Admin accounts ---------------------------------------------------
    # Admin name = {AdminTypePrefix} + 'Admin-{Owner}' + {EnvironmentSuffix}, in
    # one of TWO purpose conventions (day-2-day vs high-priv). The prefix varies by
    # admin-type and the suffix varies by environment (see the maps further down).
    #
    #   Day-2-day admin   -> {AdminTypePrefix}Admin-{Initial}{Platform}
    #     e.g. admin-mok-id (internal/Entra) / x-admin-vnd-ad (external-adminuser/AD).
    #     The rendered name is LOWER-CASED. NO level/tier markers in the name:
    #     one day-2-day account spans multiple level/tier assignments over time
    #     (L3-T1 one day, L2-T0 the next), so a baked-in L#-T# pair would mislead.
    #
    #   High-priv admin   -> Admin-{Initial}-L0-T0{Platform}
    #     e.g. admin-mok-l0-t0-id (Entra) / admin-mok-l0-t0-ad (legacy AD).
    #     A DEDICATED account for the tier-0 boundary. The -L0-T0- markers
    #     in the UserName drive OU/tier routing (see PathAdmins /
    #     PathAdminsL0T0 below); the Account-Definitions-Admins 'Purpose'
    #     column (Day2Day | HighPriv) is the explicit selector, with the
    #     marker check as legacy fallback for blank Purpose.
    #
    # THREE separate config concepts, often confused:
    #
    #   AdminAccountPattern  (singular, string, has {Owner} token)
    #     -> TEMPLATE used by Resolve-PimAdminName to GENERATE new
    #        day-2-day admin UPNs. Only matters when the engine creates
    #        new admins.
    #
    #   AdminAccountPatternHighPriv (singular, string)
    #     -> TEMPLATE for the DEDICATED high-priv accounts (the marker-
    #        carrying convention). Used by the Manager wizard's naming
    #        preview and accepted by the PIM-NAME-002 validator alongside
    #        the day-2-day pattern.
    #
    #   AdminAccountPatterns (plural; accepts string[], hashtable, or single string)
    #     -> Prefix(es) used by Get-PimAdminsFiltered to build the Graph
    #        $filter that decides which existing users get loaded into the
    #        $Global:Users_All_ID cache. If your tenant has admins under
    #        multiple prefix conventions (Admin-*, X-Admin*, ...), list
    #        them ALL here so the cache catches them all.
    #
    # The admin name is composed from THREE configurable pieces (REQUIREMENTS § 17):
    #   {AdminTypePrefix}  -- a VARIABLE prefix driven by the row's *admin-type*:
    #                         internal-adminuser = '' (NO prefix), external-adminuser
    #                         = 'x-', external-guest = '' (NO prefix)  (all editable
    #                         below / in the Manager Settings naming panel).
    #   Admin-{Initial}    -- the fixed core ("Admins", never "candidates"). {Initial}
    #                         is the initials/owner token ({Owner} is a synonym).
    #   {Platform}         -- a VARIABLE suffix driven by the target *environment*:
    #                         cloud/Entra = '-ID', legacy/AD = '-AD'. The suffix is
    #                         NO LONGER hard-coded to '-ID' -- it follows Environment.
    # The rendered name is LOWER-CASED. So internal Entra -> 'admin-mok-id';
    # external-adminuser AD -> 'x-admin-vnd-ad'.
    AdminAccountPattern         = '{AdminTypePrefix}Admin-{Initial}{Platform}'
    AdminAccountPatternHighPriv = 'Admin-{Initial}-L0-T0{Platform}'
    AdminAccountPatterns        = @('Admin-', 'x-Admin', 'g-Admin')

    # Per-admin-type PREFIX map. internal + external-guest = no prefix; only
    # external-adminuser carries one by default. Edit to fit your tenant.
    AdminTypePrefixes = [ordered]@{
        'internal-adminuser' = ''
        'external-adminuser' = 'x-'
        'external-guest'     = ''
    }
    AdminTypeDefault  = 'internal-adminuser'

    # Per-environment SUFFIX map. Entra/cloud = '-ID', AD/legacy = '-AD'.
    EnvironmentSuffixes = [ordered]@{
        'entra' = '-ID'
        'ad'    = '-AD'
    }
    EnvironmentDefault  = 'entra'

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
    # When PIM4EntraPS provisions Azure resources, the RG name follows the FULL
    # PIM naming convention -- the same token grammar as the group-name resolver:
    #   PIM-{Workload}-{Scope}-{Permission/Role}-{Level}-{Tier}-{Plane}-{Platform}
    #   e.g. PIM-AzDevOps-OrgCollectionAdministrators-L2-T1-WDP-ID
    # ({Role} is honoured as a synonym for {Permission}.) A legacy lower-case
    # 'rg-pim-{Tier}' pattern still works if you override it.
    ResourceGroupPattern = 'PIM-{Workload}-{Scope}-{Permission}-L{Level}-T{Tier}-{Plane}-{Platform}'

    # ----- Display name suffix conventions (optional polish) ---------------
    AdminAccountDisplayNameSuffix = ' (Admin)'

}
