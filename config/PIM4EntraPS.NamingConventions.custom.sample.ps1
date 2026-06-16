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

      AdminAccountPattern            -- admin name template; default
                                        '{AdminTypePrefix}Admin-{Initial}{Platform}'  (rendered lower-case, e.g. admin-mok-id)
      AdminAccountPatternHighPriv    -- dedicated tier-0 template; default
                                        'Admin-{Initial}-L0-T0{Platform}'             (rendered lower-case, e.g. admin-mok-l0-t0-id)
      AdminTypePrefixes              -- map admin-type -> name PREFIX
                                        (internal-adminuser '', external-adminuser 'x-', external-guest '')
      AdminTypeDefault               -- admin-type used when a row doesn't set one
      EnvironmentSuffixes            -- map environment -> name SUFFIX (entra '-ID', ad '-AD'); the {Platform} token
      EnvironmentDefault             -- environment used when a row doesn't set one
      AdminAccountPatterns           -- prefix list widening the Graph admin-load filter
      AdminAccountUpnSuffix          -- the bit after the @ in admin UPNs (null = tenant default)
      AdminAccountDisplayNameSuffix  -- appended to DisplayName

      PimGroupPattern                -- Entra group name template (tokens: {Role}, {Department}, {Tier}, ...)
      PimGroupAuPattern              -- AU-bound group template (tokens: {Role}, {AdminUnit}, ...)
      PimGroupTagRegex               -- optional strict GroupTag regex (null = wide-open)

      ResourceGroupPattern           -- Azure RG name template; default follows the full PIM convention
                                        'PIM-{Workload}-{Scope}-{Permission}-L{Level}-T{Tier}-{Plane}-{Platform}'

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
# Customer A (Admin- / X-Admin-). Day-2-day admin accounts carry NO level/tier
# markers -- one account spans multiple L/T assignments (L3-T1 one day, L2-T0
# the next), so a baked-in pair would mislead. Markers are reserved for
# DEDICATED tier-0 accounts (Admin-ABC-L0-T0-ID), where they drive OU/tier routing:
#   Internal -> Admin-{Initials}-{Platform}                    e.g. Admin-ABC-ID
#   External -> X-Admin-{Initials}-{Platform}                  e.g. X-Admin-VND-ID
#   Dedicated T0 -> Admin-{Initials}-L{Level}-T{Tier}-{Platform} e.g. Admin-ABC-L0-T0-ID
#
# Customer B (compact form):
#   Internal -> adm{Initials}                                  e.g. admABC
#   External -> extadm{Initials}                               e.g. extadmVND
#
# Customer C (verbose):
#   Internal -> a-{Owner}                                      e.g. a-john
#   External -> g-{Owner}                                      e.g. g-vendor1
#
# --- Form A: hashtable (UserType -> template) ---
# Use this when you have generative templates per user-type AND want the
# engine to also use the hashtable VALUES as the Graph-filter prefix
# source (engine derives the prefix from each value).
#
# $global:PIM_NamingConventions.AdminAccountPatterns = @{
#     Internal = 'Admin-{Initials}-{Platform}'
#     External = 'X-Admin-{Initials}-{Platform}'
#     Guest    = 'g-{Owner}'                # rare
# }
#
# --- Form B: string array (simple prefix list) ---
# Use this when all you need is to widen the Graph-filter prefix list so
# Get-PimAdminsFiltered loads existing admins under multiple naming
# conventions. Simpler than Form A. The engine treats each entry as a
# bare prefix (no token substitution). Filtering only; generation still
# uses AdminAccountPattern (singular).
#
# $global:PIM_NamingConventions.AdminAccountPatterns = @(
#     'Admin-'           # ADMIN-Brian-L0-T0-ID@...
#     'X-Admin'          # x-Admin-MOK-L0-T0-ID@...
#     'adm_'             # legacy short-form (drop if not used)
# )

# --- Admin name PREFIX (by admin-type) + SUFFIX (by environment) ---
# The admin name is {AdminTypePrefix} + 'Admin-{Initial}' + {Platform}, rendered
# lower-case. Override these maps to change the per-type prefix / per-environment
# suffix. internal-adminuser AND external-guest have NO prefix by default.
#
# $global:PIM_NamingConventions.AdminTypePrefixes = [ordered]@{
#     'internal-adminuser' = ''
#     'external-adminuser' = 'ext-'     # e.g. ext-admin-vnd-id
#     'external-guest'     = ''         # default: no prefix (set e.g. 'g-' if you want one)
# }
# $global:PIM_NamingConventions.AdminTypeDefault = 'internal-adminuser'
#
# $global:PIM_NamingConventions.EnvironmentSuffixes = [ordered]@{
#     'entra' = '-ID'
#     'ad'    = '-AD'
# }
# $global:PIM_NamingConventions.EnvironmentDefault = 'entra'

# UPN suffix for new admin accounts. Null = use the tenant's default verified
# domain. Set explicitly when you have a dedicated admin domain (recommended).
#
# $global:PIM_NamingConventions.AdminAccountUpnSuffix = '@adm.contoso.com'

# Visible suffix on Entra DisplayName (UI polish only):
#
# $global:PIM_NamingConventions.AdminAccountDisplayNameSuffix = ' (Admin)'


# ----- On-prem AD OU paths -------------------------------------------------
# Where the PIM-Baseline-Management-CSV engine's AD-Create branch lands new
# admin accounts (New-ADUser -Path <DN>).
#
#   PathAdmins     -- general admins (no L0/T0 marker in name)
#   PathAdminsL0T0 -- high-priv admins (UserName carries L0 or T0, e.g.
#                     'Admin-SKR-L0-T0-AD'); routed automatically by the
#                     engine's UserName-regex check.
#
# Tenants that co-mingle both classes in one OU just point both at the
# same DN. Single-quote the strings -- spaces and hyphens in OU names
# (e.g. 'OnPrem Only - No Sync to Cloud') need no escaping.
#
# $global:PIM_NamingConventions.PathAdmins     = 'OU=Admin Accounts,OU=OnPrem Only - No Sync to Cloud,OU=SPECIAL ACCOUNTS,DC=casa,DC=dk'
# $global:PIM_NamingConventions.PathAdminsL0T0 = 'OU=Admin Accounts,OU=OnPrem Only - No Sync to Cloud,OU=SPECIAL ACCOUNTS,DC=casa,DC=dk'


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


# ----- Azure resource groups ----------------------------------------------

# Azure RG name template when PIM4EntraPS provisions Azure resources. The default
# follows the full PIM naming convention (same token grammar as PimGroupPattern):
#   'PIM-{Workload}-{Scope}-{Permission}-L{Level}-T{Tier}-{Plane}-{Platform}'
#   e.g. PIM-AzDevOps-OrgCollectionAdministrators-L2-T1-WDP-ID
# Tokens: {Workload}, {Scope}, {Permission} (alias {Role}), {Level}, {Tier},
# {Plane}, {Platform}. A legacy lower-case form still works if you prefer it:
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

# ----- Deployment ring (MSP rollout staging, v2.4.134) ---------------------
#
# Declares which ring THIS tenant belongs to. Set it in the tenant's own
# config-local custom file -- never in the MSP-synced files (every tenant
# would get the same value, defeating the point).
#
#   2 = test tenant      (new-hire admins land here first)
#   1 = pilot tenant     (early production)
#   0 = production       (default when not set -- only ring-0 admins apply)
#
# The engine provisions an admin from Account-Definitions-Admins in this
# tenant only when the admin's Ring column <= this value (blank Ring = 0 =
# veteran with full reach). Promotion of an admin = edit the ONE Ring cell
# in the central MSP CSV: 2 -> 1 -> 0. No per-person exceptions needed.
#
# $global:PIM_TenantRing = 2


# ===========================================================================
# Delegation depth (engine/_shared/PIM-DelegationDepth.ps1) -- all optional
# ===========================================================================
# These keys are read via Get-PimPolicySetting, so you can set them either as
# $global:PIM_<Name> OR as $global:PIM_NamingConventions.<Name>. All have safe
# defaults; leave them unset unless you want to change behaviour.

# --- Local self-delegation plane ---
# 'local' (default) = full local autonomy: local IT may self-delegate any
#   permission (incl. privileged) with no MSP request.
# 'msp'             = self-delegation is refused (the customer pulls its
#   baseline; an MSP admin never self-grants into a customer tenant).
# Super-admins are NEVER locked out regardless of this setting.
#
# $global:PIM_DelegationPlane = 'local'

# --- Enforced baseline keys (opt-in; default = none) ---
# GroupTags that even a LOCAL admin may NOT self-override (e.g. tier-0). Empty
# by default = full local autonomy. Case-insensitive.
#
# $global:PIM_EnforcedBaselineTags = @('Entra-ID-GA-L0', 'Azure-Root-Owner-L0')

# --- PAW detection / reachability-restriction (OPT-IN; default = OFF) ---
# PAW (Privileged Access Workstation) detection and the reachability-restriction it
# drives are OFF by default -- "tight is NOT the default; PAW/tier-0 is opt-in". A
# fresh/low-maturity tenant is never confined to a PAW segment it may not even have:
# with detection OFF, EVERY classification resolves to 'whole-network' (no PAW-based
# deny) and reachability never blocks. Super-admins are never locked out regardless.
# Turn it ON only when your tenant actually runs PAW/SAW segmentation:
#
# $global:PIM_PawDetection = $true       # opt in to PAW detection + reachability
# (alias: $global:PIM_EnforcePaw = $true is honoured as a synonym, and also drives
#  the device PAW gate via $global:PIM_PawEnforcement.)

# --- Reachability-by-classification policy (only applies when PawDetection is ON) ---
# Maps a group's (tier, plane, level) to a network reach class:
#   'paw-only'      most restricted (only the privileged/PAW segment)
#   'limited'       a constrained segment
#   'whole-network' unrestricted within the corp network
# First match wins; unmatched -> 'whole-network'. Ignored entirely while PawDetection
# is OFF (the default). When you opt IN, the built-in default is:
#   tier 0 -> paw-only ; tier 1 + plane MP -> limited ;
#   tier 1 + plane WDP + level >= 3 -> whole-network ; everything else -> whole-network.
# Override to fit your own segmentation, e.g. confine all of tier 1 to 'limited':
#
# $global:PIM_ReachPolicy = @(
#     @{ tier = 0;                              reach = 'paw-only' }
#     @{ tier = 1; plane = 'MP';                reach = 'limited' }
#     @{ tier = 1; plane = 'WDP'; minLevel = 3; reach = 'whole-network' }
# )

# --- Named support-function personas (used by approver rules + escalation) ---
# Reference these in the approver matrix as '@CISO' / '@ITManager' etc. For the
# Entra-native ACTIVATION policy these are auto-resolved to the underlying PEOPLE
# (Entra PIM does not accept a department/persona as approver).
#
# $global:PIM_SupportFunctions = @{
#     CISO               = @('ciso@contoso.com')
#     ITManager          = @('itmanager@contoso.com')
#     PIMDelegationOwner = @('pim-owners@contoso.com')
#     HRManager          = @('hr-manager@contoso.com')
#     BCSettingsOwner    = @('bc-admin@contoso.com')
# }
