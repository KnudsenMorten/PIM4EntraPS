#Requires -Version 5.1
<#
.SYNOPSIS
    CUSTOMER TEMPLATE / SCHEMA DOC -- copy this file to
    PIM4EntraPS.NamingConventions.custom.ps1 and edit only the keys you
    need to override. The .custom.ps1 file is .gitignored and never
    leaves your VM.

.HOW IT'S LOADED
    Initialize-LauncherConfig loads PIM4EntraPS.NamingConventions.locked.ps1
    FIRST (ships with the repo, sets `$global:PIM_NamingConventions`), then
    loads your .custom.ps1 SECOND. Anything you set here overwrites the
    locked defaults; anything you leave unset keeps the locked default.

.WHO READS THIS
    - The engines (PIM-Functions.psm1 helpers Resolve-PimAdminName /
      Resolve-PimGroupName / Resolve-PimResourceGroup) consume the patterns
      when CREATING new admins / groups in the tenant.
    - The PIM Manager UI (tools/pim-manager/) reads the patterns + tag-prefix
      map + regex to drive the wizards, the "Re-add definition" dialog, the
      validator's naming check, and the dropdown defaults.

.SCHEMA -- the full set of keys the engine + Manager understand

      AdminAccountPatterns           -- hashtable: UserType -> name template
      AdminAccountPattern            -- legacy fallback (single string); use AdminAccountPatterns if you have internal vs external admins
      AdminAccountUpnSuffix          -- the bit after the @ in admin UPNs (null = tenant default)
      AdminAccountDisplayNameSuffix  -- appended to DisplayName

      PimGroupPattern                -- Entra group name template (tokens: {Role}, {Department}, {Tier}, ...)
      PimGroupAuPattern              -- AU-bound group template (tokens: {Role}, {AdminUnit}, ...)
      PimGroupTagRegex               -- optional strict GroupTag regex (null = wide-open)

      TagPrefixToCsv                 -- hashtable: tag prefix -> which PIM-Definitions-*.csv that prefix belongs to (longest match wins)

      ResourceGroupPattern           -- Azure RG name template (token: {Tier})

    All templates use {Token} placeholders that the engine + Manager substitute
    at runtime. Unknown tokens are left as-is (visible bug instead of silent
    drift). Token names are case-sensitive.
#>

# NOTE (v2.2.0): the optional admin metadata columns Company / Notes /
# ManagerEmail / StartDate on Account-Definitions-Admins.custom.csv and the
# SponsorUpn / SponsorNotes columns on PIM-Definitions-Roles.custom.csv are
# free-text -- they have no naming-convention pattern to override here. Set
# them directly in the CSV (or via the PIM Manager wizard).
#
# ----- Admin accounts ------------------------------------------------------

# Per-UserType admin name patterns. The engine + Manager pick by the row's
# `UserType` column in Account-Definitions-Admins (case-insensitive).
# Tokens: {Initials}, {Owner}, {Tier}, {Level}, {Platform}
#
# Customer A (Admin- / X-Admin- with tier suffix):
#   Internal -> Admin-{Initials}-L{Level}-T{Tier}-{Platform}   e.g. Admin-ABC-L0-T0-ID
#   External -> X-Admin-{Initials}-L{Level}-T{Tier}-{Platform} e.g. X-Admin-VND-L1-T1-ID
#
# Customer B (compact form):
#   Internal -> adm{Initials}                                  e.g. admABC
#   External -> extadm{Initials}                               e.g. extadmVND
#
# Customer C (verbose):
#   Internal -> a-{Owner}                                      e.g. a-john
#   External -> g-{Owner}                                      e.g. g-vendor1
#
# $global:PIM_NamingConventions.AdminAccountPatterns = @{
#     Internal = 'Admin-{Initials}-L{Level}-T{Tier}-{Platform}'
#     External = 'X-Admin-{Initials}-L{Level}-T{Tier}-{Platform}'
#     Guest    = 'g-{Owner}'                # rare
# }

# UPN suffix for new admin accounts. Null = use the tenant's default verified
# domain. Set explicitly when you have a dedicated admin domain (recommended).
#
# $global:PIM_NamingConventions.AdminAccountUpnSuffix = '@adm.contoso.com'

# Visible suffix on Entra DisplayName (UI polish only):
#
# $global:PIM_NamingConventions.AdminAccountDisplayNameSuffix = ' (Admin)'


# ----- PIM groups ----------------------------------------------------------

# Entra ID group name template for PIM permission groups.
# Tokens: {Role}, {Department}, {Tier}, {Service}, {Workload}
#
# Examples seen at real customers:
#   'PIM-{Service}-{Name}-L{Level}-T{Tier}-{Code}-{Domain}'     (the canonical PIM v2 shape)
#   'PIM_{Role}_{Department}'                                   (underscore-separated)
#   'pim-grp-{Role}-{Department}-prod'                          (lowercase + env suffix)
#   'grp-e-pim-{Role}-{Department}'                             (custom prefix scheme)
#   'sec_priv_{Service}_{Tier}'                                 (older convention)
#
# $global:PIM_NamingConventions.PimGroupPattern = 'PIM-{Service}-{Name}-L{Level}-T{Tier}-{Code}-{Domain}'

# Same shape but for AU-bound permission groups.
#
# $global:PIM_NamingConventions.PimGroupAuPattern = 'PIM-{Service}-{Name}-AU-{AdminUnit}-L{Level}-T{Tier}-{Code}-{Domain}'

# Optional strict regex for GroupTag values. When set, the Manager's
# PIM-NAME-001 validation rule fires on any tag that doesn't match. Default
# (null) = Manager accepts any alphanumeric tag. Set this when you want
# tighter enforcement (typically AFTER you've cleaned up legacy tags).
#
# $global:PIM_NamingConventions.PimGroupTagRegex = '^[A-Za-z0-9][A-Za-z0-9._-]*-L[0-9]-T[0-2]-(CP|WDP|MP|APP|USER)-(ID|RES|DAT)(-S_AD)?$'


# ----- Tag prefix -> Definition CSV map (PIM Manager wizard) --------------

# The Manager's "Re-add missing definition" wizard uses this to pick the
# right PIM-Definitions-*.csv automatically based on the tag's prefix.
# Longest-prefix match wins. If empty, the Manager falls back to scanning
# the customer's existing rows and learning the mapping from observed data
# (works well once you have a few hundred rows; useful to set explicitly
# when bootstrapping a fresh tenant).
#
# $global:PIM_NamingConventions.TagPrefixToCsv = @{
#     # Microsoft services -> Tasks (atomic capabilities) or Services
#     'Entra-ID-'    = 'PIM-Definitions-Tasks'
#     'Defender-'    = 'PIM-Definitions-Services'
#     'Intune-'      = 'PIM-Definitions-Services'
#     'Exchange-'    = 'PIM-Definitions-Services'
#     'Sharepoint-'  = 'PIM-Definitions-Services'
#     'Teams-'       = 'PIM-Definitions-Services'
#     'AzDevOps-'    = 'PIM-Definitions-Services'
#     'PowerBI-'     = 'PIM-Definitions-Resources'
#     'Azure-'       = 'PIM-Definitions-Resources'
#
#     # On-prem / hybrid
#     'AD-'          = 'PIM-Definitions-Tasks'
#
#     # Role + org structure
#     'ROLE-'        = 'PIM-Definitions-Roles'
#     'DEPT-'        = 'PIM-Definitions-Departments'
#     'ORG-'         = 'PIM-Definitions-Organization'
#     'PROCESS-'     = 'PIM-Definitions-Processes'
# }


# ----- Azure resource groups ----------------------------------------------

# Azure RG name template when PIM4EntraPS provisions Azure resources.
# Tokens: {Tier}, {Env}
#
# $global:PIM_NamingConventions.ResourceGroupPattern = 'rg-prd-pim-tier{Tier}'


# ===========================================================================
# Performance optimization (consumed by PIM4EntraPS.Filters.*.ps1)
# ===========================================================================
#
# The engine's filter scriptblocks (Filters.locked.ps1 / Filters.custom.ps1)
# can use the LITERAL prefix of these patterns to short-circuit Graph queries
# server-side instead of fetching every group/user and filtering in PowerShell.
#
# Concrete: the literal prefix of a pattern is everything BEFORE the first
# `{Token}` placeholder. Examples:
#
#     'PIM-{Service}-{Name}-L{Level}-T{Tier}-{Code}-{Domain}'   -> 'PIM-'
#     'grp-e-pim-{Role}-{Department}'                            -> 'grp-e-pim-'
#     'PIM_{Role}_{Department}'                                  -> 'PIM_'
#     'Admin-{Initials}-L{Level}-T{Tier}-{Platform}'             -> 'Admin-'
#     'X-Admin-{Initials}-L{Level}-T{Tier}-{Platform}'           -> 'X-Admin-'
#     'adm{Initials}'                                            -> 'adm'
#
# In your `PIM4EntraPS.Filters.custom.ps1`, derive the prefix once at file
# load time and inject it into the filter scriptblock. Example:
#
#     # Compute prefixes from naming conventions (no engine code change needed).
#     $_groupPrefix = ($global:PIM_NamingConventions.PimGroupPattern -split '\{')[0]
#     $_admIntPrefix  = ($global:PIM_NamingConventions.AdminAccountPatterns.Internal -split '\{')[0]
#     $_admExtPrefix  = ($global:PIM_NamingConventions.AdminAccountPatterns.External -split '\{')[0]
#
#     $global:PIM_Filters.PimGroup = {
#         param($Group)
#         # CLIENT-side filter (the safety net):
#         $Group.DisplayName -like "$_groupPrefix*"
#     }
#     $global:PIM_Filters.AdminCandidate = {
#         param($User)
#         $User.UserPrincipalName -like "$_admIntPrefix*" -or
#         $User.UserPrincipalName -like "$_admExtPrefix*"
#     }
#
# For the SERVER-side speed-up, override the engine's Graph-fetch in
# `repository.custom.ps1` to pass a `$filter=startswith(displayName,'...')`
# clause to Get-MgGroup / Get-MgUser. Example:
#
#     $_groupPrefix = ($global:PIM_NamingConventions.PimGroupPattern -split '\{')[0]
#     $global:PimGroupGraphFilter = "startswith(displayName,'$_groupPrefix')"
#
# A future engine release (v2.1.3+) will read $global:PimGroupGraphFilter
# directly and pass it to the Get-MgGroup query, turning an O(N=tenant-size)
# fetch into O(N=PIM-prefixed-groups-only). Until then, the client-side
# filter still works -- just slower for large tenants.
