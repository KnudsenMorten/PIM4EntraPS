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
    # Single privileged-tier admin account per human user.
    # Token: {Owner} = the human user's display name or sAMAccountName
    AdminAccountPattern = 'adm_{Owner}'

    # UPN suffix for admin accounts (when creating new ones). Null = use tenant default.
    AdminAccountUpnSuffix = $null

    # ----- PIM groups -------------------------------------------------------
    # Security groups created/managed for PIM role assignment.
    # Tokens: {Role}, {Department}, {Tier}
    PimGroupPattern = 'PIM_{Role}_{Department}'

    # Subset for AU-bound assignments (administrative unit)
    PimGroupAuPattern = 'PIM_{Role}_AU_{AdminUnit}'

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

    # ----- Azure resource groups -------------------------------------------
    # When PIM4EntraPS provisions Azure resources (e.g. AU storage), naming pattern:
    ResourceGroupPattern = 'rg-pim-{Tier}'

    # ----- Display name suffix conventions (optional polish) ---------------
    AdminAccountDisplayNameSuffix = ' (Admin)'

}
