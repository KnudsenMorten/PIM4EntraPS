#Requires -Version 5.1
# PIM4EntraPS -- day-to-day naming convention helpers + validation (REQUIREMENTS § 17).
#
# Pure, offline, PS 5.1-safe. No I/O, no module deps, no live calls. Dot-sourced by
# PIM-Functions.psm1 (engine + GUI + validator must resolve names identically) and
# stand-alone by the migration planner (PIM-Migration.ps1).
#
# Source of truth for the convention values is $global:PIM_NamingConventions, set by
# config/PIM4EntraPS.NamingConventions.locked.ps1 (then optionally overridden by the
# .custom.ps1). These helpers are the long-documented-but-missing implementation the
# locked config's header points at:
#     Resolve-PimAdminName     -Owner 'mok'                 -> 'admin-mok-id'
#     Resolve-PimGroupName     -Role 'Helpdesk' -Department 'IT'  -> 'PIM-Helpdesk-IT'
#     Resolve-PimResourceGroup -Tier 1 -Workload 'AzDevOps' -Scope 'OrgCollectionAdministrators' -Permission '' -Level 2 -Plane 'WDP' -Platform 'ID'
#                                                          -> 'PIM-AzDevOps-OrgCollectionAdministrators-L2-T1-WDP-ID'
#
# Grammar (mirrors the wizard in tools/pim-manager/pim-manager.html + PIM-PermissionWizard.ps1):
#   day-2-day admin   {AdminTypePrefix}Admin-{Initial}{Platform}   (NO L#/T# markers; lower-cased)
#   high-priv admin   Admin-{Initial}-L0-T0{Platform}              (dedicated tier-0; lower-cased)
#   permission group  PIM-{Service}-{Name}-L{Level}-T{Tier}-{Code}-{Domain}
#                                       (+ -AU-{AU} after {Name} for AU-scoped entra)
#   AU subset group   PIM-{Role}-AU-{AdminUnit}
#   resource group    PIM-{Workload}-{Scope}-{Permission/Role}-{Level}-{Tier}-{Plane}-{Platform}
# Separator is ALWAYS '-' (never '_' / 'adm_' / 'PIM_' literals -- the underscore form
# broke startswith(displayName,'PIM_') and produced duplicate creates; see locked config).
#
# Admin name = a VARIABLE PREFIX (driven by admin-type) + the 'Admin-{Initial}' core +
# a VARIABLE SUFFIX (driven by the target environment), lower-cased. See REQUIREMENTS § 17.
#   AdminType  -> {AdminTypePrefix} token:  internal-adminuser '' (no prefix),
#                 external-adminuser 'x-', external-guest '' (no prefix)  (all configurable).
#   Environment-> {Platform}/{EnvironmentSuffix} token: cloud/Entra '-ID', legacy/AD '-AD'
#                 (configurable). The suffix is NO LONGER hard-coded to '-ID'.
# So internal Entra -> 'admin-mok-id'; external-adminuser AD -> 'x-admin-vnd-ad'.

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# Convention lookup. Reads $global:PIM_NamingConventions if present, else the
# shipped defaults (kept in 1:1 sync with the .locked.ps1). Never mutates global.
# ---------------------------------------------------------------------------
function Get-PimRequiredNamingConventionKeys {
    <#
      PURE. The convention keys that PRODUCE A NAME. If one of these is absent from the store, every
      name the engine computes changes -- so the engine refuses to run rather than invent one.
    #>
    @('AdminAccountPattern', 'AdminAccountPatternHighPriv', 'PimGroupPattern', 'ResourceGroupPattern')
}

function Test-PimNamingConventionsUsable {
    <#
      🔴 PURE. Does the STORE carry a usable naming convention? (operator, 2026-09-20: *"naming is defined
      at build time and goes into sql ... we can not have drifts here or sudden changes o admin accounts or
      group names. that is a critical no-go"*, and *"refuse engine to run"*.)

      Why refusing beats falling back: the shipped defaults are NOT a safe substitute for a customer's
      convention. MSP-SETUP-GUIDE §5 records what happens when the name is wrong -- the managed tenant's
      Admins provider builds its live set with startswith(userPrincipalName, <prefix>), so an account that
      does not match is INVISIBLE to it, is never in the live set, and is therefore RE-CREATED on every
      tick. Nothing errors; unmanaged privileged accounts just accumulate in the customer's directory
      (IMP-13). A wrong name is not a cosmetic problem, so a guessed name is not an acceptable default.

      -Stored = pim.Settings['NamingConventions'] as read (a map, an object, or $null).
      Returns @{ ok; missing = @(keys); reason }.
    #>
    [CmdletBinding()] param([AllowNull()][object]$Stored)
    $req = @(Get-PimRequiredNamingConventionKeys)
    if ($null -eq $Stored) {
        return @{ ok = $false; missing = $req
                  reason = "pim.Settings['NamingConventions'] is not set in this environment's store" }
    }
    $have = @{}
    if ($Stored -is [System.Collections.IDictionary]) { foreach ($k in @($Stored.Keys)) { $have["$k"] = $Stored[$k] } }
    elseif ($Stored -is [System.Management.Automation.PSCustomObject]) { foreach ($p in $Stored.PSObject.Properties) { $have[$p.Name] = $p.Value } }
    else { return @{ ok = $false; missing = $req; reason = "pim.Settings['NamingConventions'] is a $($Stored.GetType().Name), not a convention map" } }
    $missing = @($req | Where-Object { -not $have.ContainsKey($_) -or -not "$($have[$_])".Trim() })
    if ($missing.Count) {
        return @{ ok = $false; missing = @($missing)
                  reason = ("pim.Settings['NamingConventions'] is missing: " + ($missing -join ', ')) }
    }
    return @{ ok = $true; missing = @(); reason = 'the store carries a complete naming convention' }
}

function Get-PimShippedNamingConventions {
    <#
      🔴 THE ONE SHIPPED COPY OF THE NAMING DEFAULTS (operator, 2026-09-20).
      There used to be THREE copies: this hashtable, config\PIM4EntraPS.NamingConventions.locked.ps1,
      and pim.Settings. The file was a hand-maintained duplicate of what is already here -- the header
      of this function literally said "kept in 1:1 sync with the .locked.ps1", which is the two-copies-
      of one-list pattern BUG-181 was. They had ALREADY drifted: 'PathAdmins' / 'PathAdminsL0T0' existed
      only in the file, never here -- and they are LIVE v2 settings (Resolve-PimHybridAdTargetOu routes a
      new on-prem admin to its OU; Settings > "AD OU placement" edits them). They are deliberately NOT in
      this shipped set and NOT in Get-PimRequiredNamingConventionKeys, because they are OPTIONAL: for
      tenants with on-premises AD only (operator 2026-09-20: "this naming is optional, as not everyone
      have ad"). A cloud-only tenant leaves them blank, so their absence must never block the engine.
      Operator: *"naming convention are always per customer. if this are samples or default or initial,
      then we should incude that in the deployment instead. i dont understand the purpose"* -- correct.
      So: the DEFAULTS are here, in code; a customer's values live in pim.Settings (SQL) and are seeded
      there at store init (Initialize-PimSqlStore); NO config file is a naming source any more.
      Returns a FRESH copy, so no caller can mutate the shipped set.
      tests/Test-PimNaming.ps1 fails if a config file ever becomes a naming source again.
    #>
    [CmdletBinding()] param()
    return (Get-PimNamingConvention -ShippedOnly)
}

function Get-PimNamingConvention {
    [CmdletBinding()] param([string]$Key, [switch]$ShippedOnly)
    $defaults = @{
        # Admin name = {AdminTypePrefix} + 'Admin-{Initial}' core + {Platform}.
        # The prefix comes from the row's AdminType; the {Platform} suffix from its
        # Environment (entra -> -ID, ad -> -AD). {Initial} is the owner/initials token
        # ({Owner} is honoured as a synonym). The rendered name is lower-cased, e.g.
        # internal Entra 'mok' -> 'admin-mok-id'; high-priv -> 'admin-mok-l0-t0-id'.
        AdminWord                     = 'Admin'
        AdminAccountPattern           = '{AdminTypePrefix}{AdminWord}-{Initial}{Platform}'
        # 🔴 2026-09-20 -- {AdminWord}, NOT a literal 'Admin'. This is the drift the three-copy problem
        # actually produced: v2.4.333 made the admin word configurable and tokenised it, the .locked.ps1
        # copy was updated ('{AdminWord}-{Initial}-L0-T0{Platform}') and THIS copy was not. Deleting the
        # file would have silently shipped the stale literal, so a customer with AdminWord='adm' would get
        # 'adm-mok-id' day-to-day but 'Admin-mok-l0-t0-id' high-priv -- two conventions in one estate.
        # PIM.Features.Tests.ps1 "17. Naming" caught it. Renders identically for the default word.
        AdminAccountPatternHighPriv   = '{AdminWord}-{Initial}-L0-T0{Platform}'
        AdminAccountPatterns          = @('Admin-', 'x-Admin', 'g-Admin')
        # Per-admin-type prefix map (configurable). internal + external-guest = NO prefix.
        AdminTypePrefixes             = [ordered]@{
            'internal-adminuser' = ''
            'external-adminuser' = 'x-'
            'external-guest'     = ''
        }
        # Default admin-type when a row/wizard doesn't specify one.
        AdminTypeDefault              = 'internal-adminuser'
        # Per-environment suffix map (configurable). Entra/cloud = '-ID', AD/legacy = '-AD'.
        EnvironmentSuffixes           = [ordered]@{
            'entra' = '-ID'
            'ad'    = '-AD'
        }
        # Default environment when a row/wizard doesn't specify one.
        EnvironmentDefault            = 'entra'
        AdminAccountUpnSuffix         = $null
        AdminAccountDisplayNameSuffix = ' (Admin)'
        PimGroupPattern               = 'PIM-{Role}-{Department}'
        PimGroupAuPattern             = 'PIM-{Role}-AU-{AdminUnit}'
        PimGroupTagRegex              = $null
        # Azure RG name follows the full PIM naming convention (same token grammar as
        # the group-name resolver): PIM-{Workload}-{Scope}-{Permission/Role}-{Level}-{Tier}-{Plane}-{Platform}
        # e.g. PIM-AzDevOps-OrgCollectionAdministrators-L2-T1-WDP-ID.
        ResourceGroupPattern          = 'PIM-{Workload}-{Scope}-{Permission}-L{Level}-T{Tier}-{Plane}-{Platform}'
        # Operator 2026-09-21: "you must add them in the naming conventions so i can use them as variables" -- the
        # values the wizards and the engine had HARD-CODED. Each default is exactly the value that was hard-coded, so
        # a tenant that never touches them gets byte-identical tags, names and AUs.
        # Direct-group types: the TAG prefix ({GroupTypePrefix}; the rest of the tag is {ShortName}) ...
        GroupTypePrefixes             = [ordered]@{ role = 'ROLE-'; organisation = 'ORG-'; department = 'DEPT-'; project = 'PROJ-'; crossorg = 'CORG-' }
        # ... and the administrative unit a new group of that type is placed in.
        GroupTypeAdminUnits           = [ordered]@{ role = 'PIM-ROLES'; organisation = 'PIM-ORGANIZATION'; department = 'PIM-DEPARTMENTS'; project = 'PIM-PROJECTS'; crossorg = 'PIM-CROSSORG' }
        # Permission groups: the AU by privilege level.
        PermissionGroupAdminUnits     = [ordered]@{ L0 = 'PIM-L0'; L1 = 'PIM-L1'; L2 = 'PIM-L2' }
        # Display name of an administrative unit the wizard creates ({AdminUnit} = its tag without 'PIM-').
        AdminUnitNamePattern          = 'PIM-Groups-{AdminUnit}'
        # The service segment at the start of a permission-group tag ({Service}).
        ServiceNames                  = [ordered]@{ entra = 'Entra-ID'; azure = 'Azure'; powerbi = 'PowerBI'; powerplatform = 'PowerPlatform'; bundle = 'Bundle' }
    }
    $conv = $defaults.Clone()
    # -ShippedOnly: the defaults as SHIPPED, ignoring this environment's stored values. The import
    # validator and the template planner need exactly that -- they judge rows against the product's
    # conventions, not against whatever a customer has overridden.
    if ($ShippedOnly) {
        if ($Key) { if ($conv.ContainsKey($Key)) { return $conv[$Key] }; return $null }
        return $conv
    }
    if ($global:PIM_NamingConventions -is [hashtable]) {
        foreach ($k in @($global:PIM_NamingConventions.Keys)) { $conv[$k] = $global:PIM_NamingConventions[$k] }
    }
    if ($Key) {
        if ($conv.ContainsKey($Key)) { return $conv[$Key] }
        return $null
    }
    return $conv
}

# ---------------------------------------------------------------------------
# Admin-type + environment normalisation. Both accept friendly aliases so the
# wizard/CSV can pass 'internal'/'external'/'guest' or 'cloud'/'legacy'/'ID'/'AD'
# and still resolve to the canonical key used in the configurable maps.
# ---------------------------------------------------------------------------
function Resolve-PimAdminTypeKey {
    # Normalise an admin-type value to a canonical key:
    #   internal-adminuser | external-adminuser | external-guest
    [CmdletBinding()] param([AllowNull()][string]$AdminType)
    $t = "$AdminType".Trim().ToLowerInvariant() -replace '[\s_]+', '-'
    switch ($t) {
        'internal-adminuser' { return 'internal-adminuser' }
        'external-adminuser' { return 'external-adminuser' }
        'external-guest'     { return 'external-guest' }
        'internal'           { return 'internal-adminuser' }
        'external'           { return 'external-adminuser' }
        'guest'              { return 'external-guest' }
        ''                   { return $null }
        default              { return $t }   # unknown -> pass through (looked up as-is)
    }
}
function Resolve-PimEnvironmentKey {
    # Normalise an environment value to a canonical key: entra | ad.
    [CmdletBinding()] param([AllowNull()][string]$Environment)
    $e = "$Environment".Trim().ToLowerInvariant()
    switch ($e) {
        'entra'  { return 'entra' }
        'ad'     { return 'ad' }
        'id'     { return 'entra' }   # platform marker ID == Entra/cloud
        'cloud'  { return 'entra' }
        'azuread' { return 'entra' }
        'legacy' { return 'ad' }
        'onprem' { return 'ad' }
        ''       { return $null }
        default  { return $e }
    }
}
function Get-PimAdminTypePrefix {
    # Look up the configured prefix for an admin-type. internal = '' (no prefix).
    # Unknown/blank type -> the configured default type's prefix.
    [CmdletBinding()] param([AllowNull()][string]$AdminType)
    $conv = Get-PimNamingConvention
    $map  = $conv.AdminTypePrefixes
    $key  = Resolve-PimAdminTypeKey $AdminType
    if (-not $key) { $key = Resolve-PimAdminTypeKey "$($conv.AdminTypeDefault)"; if (-not $key) { $key = 'internal-adminuser' } }
    if ($map -and ($map.PSObject -or $map -is [System.Collections.IDictionary])) {
        # hashtable / ordered dict / PSCustomObject (from JSON) all supported
        $val = $null
        if ($map -is [System.Collections.IDictionary]) {
            foreach ($k in @($map.Keys)) { if ("$k".ToLowerInvariant() -eq $key) { $val = $map[$k]; break } }
        } else {
            foreach ($p in $map.PSObject.Properties) { if ("$($p.Name)".ToLowerInvariant() -eq $key) { $val = $p.Value; break } }
        }
        if ($null -ne $val) { return "$val" }
    }
    return ''   # default = no prefix
}
function Get-PimEnvironmentSuffix {
    # Look up the configured suffix for an environment. Entra='-ID', AD='-AD'.
    # Unknown/blank -> the configured default environment's suffix.
    [CmdletBinding()] param([AllowNull()][string]$Environment)
    $conv = Get-PimNamingConvention
    $map  = $conv.EnvironmentSuffixes
    $key  = Resolve-PimEnvironmentKey $Environment
    if (-not $key) { $key = Resolve-PimEnvironmentKey "$($conv.EnvironmentDefault)"; if (-not $key) { $key = 'entra' } }
    if ($map) {
        $val = $null
        if ($map -is [System.Collections.IDictionary]) {
            foreach ($k in @($map.Keys)) { if ("$k".ToLowerInvariant() -eq $key) { $val = $map[$k]; break } }
        } else {
            foreach ($p in $map.PSObject.Properties) { if ("$($p.Name)".ToLowerInvariant() -eq $key) { $val = $p.Value; break } }
        }
        if ($null -ne $val) { return "$val" }
    }
    # Hard fallback so the suffix is never silently '' (env is meant to drive it).
    if ($key -eq 'ad') { return '-AD' }
    return '-ID'
}

# ---------------------------------------------------------------------------
# Token helpers. Sanitise a single name part (dash-cased, no spaces/specials) and
# expand a {Token} pattern from a substitution hashtable (case-insensitive keys).
# ---------------------------------------------------------------------------
function ConvertTo-PimNamePart {
    # Compress a label into a single dash-safe part. Matches the JS sanitizePart()
    # in pim-manager.html: spaces -> '-', then strip anything not [A-Za-z0-9.-].
    param([AllowNull()][string]$Text)
    $t = "$Text".Trim()
    if (-not $t) { return '' }
    $t = $t -replace '\s+', '-'
    $t = $t -replace '[^A-Za-z0-9.\-]', ''
    return $t
}

function Expand-PimNamePattern {
    # Replace {Token} placeholders (case-insensitive) from a tokens hashtable.
    # Unknown tokens are left as-is; null/blank values expand to ''.
    param(
        [Parameter(Mandatory)][string]$Pattern,
        [hashtable]$Tokens = @{}
    )
    # Operator 2026-09-21: "make sure i can use any variables here" -- a token may sit INSIDE another token's
    # value (an admin-type prefix 'adm-{TenantCommonName}-', a suffix '-{AdminWord}'). One pass in hashtable
    # order expanded such a nested token only when its key happened to come later, so the same setting worked on
    # one run and not the next. Repeat until nothing changes; the pass cap stops a value that names itself.
    $out = $Pattern
    for ($pass = 0; $pass -lt 5; $pass++) {
        $before = $out
        foreach ($k in @($Tokens.Keys)) {
            $val = "$($Tokens[$k])"
            $out = [regex]::Replace($out, [regex]::Escape('{' + $k + '}'), [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $val }, 'IgnoreCase')
        }
        if ($out -ceq $before) { break }
    }
    return $out
}

# ---------------------------------------------------------------------------
# Name generators (the documented Resolve-Pim* helpers).
# ---------------------------------------------------------------------------
function Resolve-PimAdminName {
    # Generate an admin UPN/UserName from the convention. The name carries a VARIABLE
    # PREFIX (from -AdminType) and a VARIABLE SUFFIX (from -Environment). The rendered
    # name is LOWER-CASED (operator convention):
    #   internal Entra        -> 'admin-mok-id'
    #   external-adminuser AD -> 'x-admin-vnd-ad'
    #   external-guest Entra  -> 'admin-gst-id'   (external-guest carries NO prefix)
    #   high-priv Entra       -> 'admin-mok-l0-t0-id'
    # -HighPriv switches to the dedicated L0-T0 pattern. -Platform is a back-compat
    # alias for -Environment (ID -> entra, AD -> ad) when -Environment is not given.
    # Tokens: {Initial} (preferred) / {Owner} (synonym) = the initials; {Platform} /
    # {EnvironmentSuffix} = the environment suffix (-ID/-AD); {AdminTypePrefix} = prefix.
    # Returns the local part only unless AdminAccountUpnSuffix is set ('<name>@<suffix>').
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Owner,    # initials / short owner token
        [string]$AdminType,                       # internal-adminuser | external-adminuser | external-guest
        [string]$Environment,                     # entra | ad
        [string]$Platform,                        # legacy alias for -Environment (ID/AD)
        [switch]$HighPriv,
        # Operator 2026-09-21: "in the naming we need to have the {Company} as a variable to use - cnsultant naming
        # could be KONS-{Company}-{Initial}-{Tier}-c". {Company} = the admin's OWN company (the row's Company
        # column, which also becomes the account's companyName) -- per admin, unlike {TenantCommonName}. {Tier} /
        # {Level} = the admin's tier / level, the same tokens group names already use ('1', not 'T1').
        # All three are blank when not given, and a blank token disappears (the '--' collapse below), so every
        # existing pattern renders byte-identical names.
        [string]$Company,
        [string]$Tier,
        [string]$Level
    )
    $conv = Get-PimNamingConvention
    $pat  = if ($HighPriv) { "$($conv.AdminAccountPatternHighPriv)" } else { "$($conv.AdminAccountPattern)" }
    if (-not $pat) { $pat = if ($HighPriv) { '{AdminWord}-{Initial}-L0-T0{Platform}' } else { '{AdminTypePrefix}{AdminWord}-{Initial}{Platform}' } }
    # Environment falls back to the legacy -Platform alias (ID/AD) then the default.
    $env = if ("$Environment".Trim()) { $Environment } elseif ("$Platform".Trim()) { $Platform } else { $null }
    $prefix = Get-PimAdminTypePrefix  -AdminType   $AdminType
    $suffix = Get-PimEnvironmentSuffix -Environment $env
    $initial = (ConvertTo-PimNamePart $Owner)
    $name = Expand-PimNamePattern -Pattern $pat -Tokens @{
        AdminTypePrefix   = $prefix
        Initial           = $initial
        Owner             = $initial   # synonym so legacy {Owner} patterns keep working
        EnvironmentSuffix = $suffix
        # {Platform} expands to the SAME environment suffix (e.g. -ID/-AD).
        Platform          = $suffix
        # 🔑 {AdminWord} -- THE WORD IN THE MIDDLE OF AN ADMIN NAME, and it used to be LITERAL.
        # Operator, 2026-09-12: "some customer wants to use fx adm others admin - but here i have
        # not defined the word admin ... we cannot enforce admin in the name". Everything around it
        # was already a token ({AdminTypePrefix}, {Initial}, {Platform}); only the product's own
        # opinion was hard-coded, so a customer whose convention says "adm" could not express it
        # without hand-editing the raw pattern in the advanced key/value table.
        # Defaults to 'Admin', so every existing tenant renders byte-identical names.
        AdminWord         = $(if ("$($conv.AdminWord)".Trim()) { "$($conv.AdminWord)".Trim() } else { 'Admin' })
        # 🔑 {TenantCommonName} -- THE TENANT'S COMMON NAME (operator 2026-09-20: "add a name as
        # variable per env that can be included also in naming like EFIF, RIDE").
        # This is how EFIF's convention is expressed today, and it is hard-coded into the PATTERN:
        # MSP-SETUP-GUIDE §5 ships '{AdminTypePrefix}Admin-efif-{Initial}{Platform}' in a per-deployment
        # file, so 'efif' is baked into the template and the template cannot be shared between tenants.
        # With this token the SAME pattern serves every environment --
        # 🪤 NOT called EnvName/Environment*: in this convention 'Environment' already means the
        # PLATFORM -- EnvironmentSuffixes maps entra -> '-ID' and ad -> '-AD', and EnvironmentDefault
        # picks between them. A second meaning on the same word would be read wrong by whoever comes
        # next (operator: "envname is someting diferent in the naming" / "use tenant common name").
        #     '{AdminTypePrefix}{AdminWord}-{TenantCommonName}-{Initial}{Platform}' + TenantCommonName='efif'
        # renders 'admin-efif-khrs-id' -- and the per-customer part is ONE editable value, which is what
        # makes a naming TEMPLATE reusable across tenants.
        # Empty by default, and the '--' collapse below removes the separator it leaves behind, so every
        # existing tenant renders byte-identical names.
        TenantCommonName  = (ConvertTo-PimNamePart "$($conv.TenantCommonName)")
        Company           = (ConvertTo-PimNamePart $Company)
        # 'T1' / 'L2' are accepted and reduced to the number, because the pattern supplies the letter (T{Tier}).
        Tier              = (ConvertTo-PimNamePart ("$Tier".Trim() -replace '^(?i)T(?=\d)', ''))
        Level             = (ConvertTo-PimNamePart ("$Level".Trim() -replace '^(?i)L(?=\d)', ''))
    }
    # collapse any doubled separator a blank token may have left.
    $name = $name -replace '--+', '-'
    # ...and one a blank token left at either end ('KONS-{Company}-...' with no company would otherwise start 'KONS--').
    $name = $name.Trim('-')
    # operator convention: admin account names are lower-cased.
    $name = $name.ToLowerInvariant()
    $upnSuffix = "$($conv.AdminAccountUpnSuffix)".Trim()
    if ($upnSuffix) {
        $upnSuffix = $upnSuffix.TrimStart('@')
        return ('{0}@{1}' -f $name, $upnSuffix)
    }
    return $name
}

function Resolve-PimGroupName {
    # Generate a PIM group display name. Two shapes: the simple {Role}/{Department}
    # pattern (default), or -AdminUnit for the AU subset pattern. Extra tokens
    # (Level/Tier/Service/Name/Code/Domain) are honoured if the pattern uses them.
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Role,
        [string]$Department,
        [string]$AdminUnit,
        [hashtable]$ExtraTokens = @{}
    )
    $conv = Get-PimNamingConvention
    $tokens = @{ Role = (ConvertTo-PimNamePart $Role) }
    foreach ($k in @($ExtraTokens.Keys)) { $tokens[$k] = (ConvertTo-PimNamePart "$($ExtraTokens[$k])") }
    if ("$AdminUnit".Trim()) {
        $pat = "$($conv.PimGroupAuPattern)"; if (-not $pat) { $pat = 'PIM-{Role}-AU-{AdminUnit}' }
        $tokens['AdminUnit'] = (ConvertTo-PimNamePart $AdminUnit)
    } else {
        $pat = "$($conv.PimGroupPattern)"; if (-not $pat) { $pat = 'PIM-{Role}-{Department}' }
        $tokens['Department'] = (ConvertTo-PimNamePart $Department)
    }
    $name = Expand-PimNamePattern -Pattern $pat -Tokens $tokens
    # collapse a trailing '-' left by a blank Department token (PIM-Role- -> PIM-Role)
    $name = $name -replace '-+$', ''
    $name = $name -replace '--+', '-'
    return $name
}

# ---------------------------------------------------------------------------
# REQ-U (2026-09-19) -- GroupTag <-> group name through the TENANT's pattern.
# Operator: "customer can have different naming convention so you must make sure code uses the actual naming
# per tenant and not generic". A tag is tenant-neutral ('Intune-HelpDeskOperator-L4-T1-WDP-ID'); the NAME is
# the tenant's PimGroupPattern around it ('PIM-{Role}' -> 'PIM-Intune-...', 'GRP-{Role}' -> 'GRP-Intune-...').
# These mirror the Manager's pimGroupNameFromTag / pimGroupTagFromName (pim-manager.html) so the engine, the
# Manager and the validator agree on one answer -- and nothing hard-codes a 'PIM-' prefix.
# ---------------------------------------------------------------------------
function Get-PimGroupNameAffixes {
    # PURE. The literal text the tenant's PimGroupPattern puts BEFORE and AFTER the {Role} (tag) part, with every
    # other token dropped and separators collapsed exactly like the GUI: 'PIM-{Role}-{Department}' -> PIM- / '',
    # 'GRP-{Role}' -> GRP- / '', '{Role}-X' -> '' / -X. -Pattern overrides the stored convention.
    [CmdletBinding()] param([string]$Pattern)
    $pat = "$Pattern"
    if (-not $pat.Trim()) { $pat = "$(Get-PimNamingConvention -Key 'PimGroupPattern')" }
    if (-not $pat.Trim()) { $pat = 'PIM-{Role}-{Department}' }
    $mark = [string][char]1
    $p = [regex]::Replace($pat, '\{Role\}', $mark, 'IgnoreCase')
    $p = $p -replace '\{[A-Za-z]+\}', ''
    $p = $p -replace '-{2,}', '-'
    $p = $p -replace '^-+|-+$', ''
    # ORDINAL: a culture-aware IndexOf treats the control-character marker as ignorable and answers 0 (pwsh 7 / ICU).
    $i = $p.IndexOf($mark, [System.StringComparison]::Ordinal)
    if ($i -lt 0) {
        # A pattern without {Role} spells the whole grammar in tokens ('PIM-{Service}-{Name}-L{Level}-...'): the tag
        # IS that grammar, so the name is the literal text before the first token + the tag.
        $b = $pat.IndexOf('{')
        $pre = if ($b -lt 0) { $(if ($pat.Trim()) { $pat.Trim().TrimEnd('-') + '-' } else { '' }) } else { $pat.Substring(0, $b) }
        return [pscustomobject]@{ prefix = $pre; suffix = ''; pattern = $pat }
    }
    return [pscustomobject]@{ prefix = $p.Substring(0, $i); suffix = $p.Substring($i + 1); pattern = $pat }
}

function Get-PimNamingMapValue {
    # PURE-ish. One entry of a naming MAP setting (GroupTypePrefixes, ServiceNames, ...), case-insensitive key; the
    # shipped default for that key when the tenant's map lacks it or holds a blank. Never throws.
    param([Parameter(Mandatory)][string]$Map, [Parameter(Mandatory)][string]$Key)
    $want = "$Key".ToLowerInvariant()
    # 🪤 No intermediate list of (key, value) pairs: a ONE-entry map made it a single pair that PowerShell unrolled
    # into two loose strings, so the key was never found and a tenant value silently lost to the default.
    foreach ($src in @((Get-PimNamingConvention -Key $Map), (Get-PimNamingConvention -Key $Map -ShippedOnly))) {
        if ($null -eq $src) { continue }
        if ($src -is [System.Collections.IDictionary]) {
            foreach ($k in @($src.Keys)) { if ("$k".ToLowerInvariant() -eq $want -and "$($src[$k])".Trim()) { return "$($src[$k])".Trim() } }
        } else {
            foreach ($pp in @($src.PSObject.Properties)) { if ("$($pp.Name)".ToLowerInvariant() -eq $want -and "$($pp.Value)".Trim()) { return "$($pp.Value)".Trim() } }
        }
    }
    return ''
}

function Get-PimServiceName {
    # The service segment of a permission-group tag ({Service}): pim.Settings NamingConventions.ServiceNames[<key>]
    # (entra / azure / powerbi / powerplatform / bundle), defaulting to the value that used to be hard-coded.
    param([Parameter(Mandatory)][string]$Key)
    $v = Get-PimNamingMapValue -Map 'ServiceNames' -Key $Key
    if ($v) { return $v }
    return $Key
}

function Get-PimPermissionGroupAdminUnit {
    # The AU a permission group of privilege level L<n> is placed in (PermissionGroupAdminUnits), default PIM-L<n>.
    param([Parameter(Mandatory)][string]$Level)
    $k = "L$("$Level".Trim() -replace '^(?i)L', '')"
    $v = Get-PimNamingMapValue -Map 'PermissionGroupAdminUnits' -Key $k
    if ($v) { return $v }
    return "PIM-$k"
}

function Expand-PimGroupNamePattern {
    <#
      PURE. A GROUP-name pattern with its tokens filled from -Tokens (case-insensitive keys, values used verbatim).
      Operator 2026-09-21 ("where is this extr underscore __ coming from" / "you must add them in the naming
      conventions so i can use them as variables"): the old rule kept only {Role} and deleted every other token,
      so 'grp-e-PIM_{Department}_{Role}-T{Tier}{Platform}' became 'grp-e-PIM__ROLE-x-T' -- a doubled '_', a bare
      'T', no platform suffix. Now every token gets its value, and a token with NO value disappears cleanly:
        * with ONE of the separators around it ('_{Department}_' -> '_'),
        * with a single letter glued to it ('-T{Tier}' -> '-': T{Tier} / L{Level} are the convention),
        * at either end, with the separator that joined it.
      An UNKNOWN token (no key in -Tokens) is treated as blank -- the old rule deleted those too, so default
      patterns ('PIM-{Role}-{Department}') render byte-identical names.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Pattern, [hashtable]$Tokens = @{})
    $map = @{}
    foreach ($k in @($Tokens.Keys)) { $map["$k".ToLowerInvariant()] = "$($Tokens[$k])" }
    $blank = [string][char]2
    $s = [regex]::Replace($Pattern, '\{([A-Za-z]+)\}', [System.Text.RegularExpressions.MatchEvaluator]{
        param($m) $k = $m.Groups[1].Value.ToLowerInvariant(); if ($map.ContainsKey($k) -and "$($map[$k])" -ne '') { $map[$k] } else { $blank } })
    $b = [regex]::Escape($blank)
    $s = [regex]::Replace($s, "([-_.])[A-Za-z]$b", "`$1$blank")          # '-T{Tier}' with no tier -> '-'
    for ($i = 0; $i -lt 10 -and $s.Contains($blank); $i++) {
        $before = $s
        $s = [regex]::Replace($s, "([-_.])(?:$b)+[-_.]", '$1')           # '_{X}_' -> '_'
        $s = [regex]::Replace($s, "^(?:$b)+[-_.]?", '')                  # leading blank + its separator
        $s = [regex]::Replace($s, "[-_.]?(?:$b)+$", '')                  # trailing blank + its separator
        if ($s -ceq $before) { break }
    }
    $s = $s.Replace($blank, '')
    $s = $s -replace '-{2,}', '-' -replace '_{2,}', '_'
    return $s.Trim('-', '_')
}

function Get-PimGroupNameTokensFromTag {
    <#
      PURE. What a TAG alone says about the name tokens: {Role} = the tag; the tag grammar
      '<Service>-<Name>-L<n>-T<n>-<Plane>-<Domain>' fills {Service} {Level} {Tier} {Plane} {Domain}; a direct-group
      tag starting with a configured GroupTypePrefix fills {GroupTypePrefix} + {ShortName}; the tenant-level tokens
      ({TenantCommonName}, {AdminWord}, {Platform} / {EnvironmentSuffix} of the default environment) always.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Tag)
    $t = "$Tag".Trim()
    $conv = Get-PimNamingConvention
    $tok = @{ Role = $t }
    $m = [regex]::Match($t, '(?i)^(?<svc>[A-Za-z0-9]+(?:-[A-Za-z0-9]+)?)-.*-L(?<lvl>\d+)-T(?<tier>\d+)-(?<code>[A-Za-z]+)-(?<dom>[A-Za-z]+)')
    if ($m.Success) {
        $tok.Service = $m.Groups['svc'].Value; $tok.Level = $m.Groups['lvl'].Value; $tok.Tier = $m.Groups['tier'].Value
        $tok.Plane = $m.Groups['code'].Value; $tok.Domain = $m.Groups['dom'].Value
    }
    $gtp = $conv.GroupTypePrefixes
    $vals = @()
    if ($gtp -is [System.Collections.IDictionary]) { $vals = @($gtp.Values) } elseif ($gtp) { $vals = @($gtp.PSObject.Properties | ForEach-Object { $_.Value }) }
    foreach ($p in @($vals | ForEach-Object { "$_" } | Where-Object { $_ } | Sort-Object Length -Descending)) {
        if ($t.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase) -and $t.Length -gt $p.Length) {
            $tok.GroupTypePrefix = $t.Substring(0, $p.Length); $tok.ShortName = $t.Substring($p.Length); break
        }
    }
    $tok.TenantCommonName = ConvertTo-PimNamePart "$($conv.TenantCommonName)"
    $tok.AdminWord = $(if ("$($conv.AdminWord)".Trim()) { "$($conv.AdminWord)".Trim() } else { 'Admin' })
    $sfx = ''; try { $sfx = "$(Get-PimEnvironmentSuffix -Environment $null)" } catch { $sfx = '' }
    $tok.Platform = $sfx; $tok.EnvironmentSuffix = $sfx
    return $tok
}

function Resolve-PimGroupNameFromTag {
    <#
      PURE. GroupTag -> the group NAME under the tenant's pattern (or -Pattern). The tag is kept verbatim (it is
      already the tenant's identifier). Blank tag -> ''.
      -Tokens: values the CALLER knows (a wizard's department, tier, ...) -- they win over what the tag says.
      -Legacy: the pre-2026-09-21 rule (only the text around {Role}, every other token deleted). Lookups of
      EXISTING groups try it as well, so a group named under the old rule is still found.
      A pattern WITHOUT {Role} keeps its old meaning: the literal text before the first token + the tag.
    #>
    [CmdletBinding()] param([AllowNull()][string]$Tag, [string]$Pattern, [hashtable]$Tokens = @{}, [switch]$Legacy)
    $t = "$Tag".Trim()
    if (-not $t) { return '' }
    $a = Get-PimGroupNameAffixes -Pattern $Pattern
    if ($Legacy -or "$($a.pattern)" -notmatch '(?i)\{Role\}') { return ("{0}{1}{2}" -f $a.prefix, $t, $a.suffix) }
    $tok = Get-PimGroupNameTokensFromTag -Tag $t
    foreach ($k in @($Tokens.Keys)) { if ($null -ne $Tokens[$k] -and "$($Tokens[$k])" -ne '') { $tok["$k"] = "$($Tokens[$k])" } }
    $tok.Role = $t
    return (Expand-PimGroupNamePattern -Pattern "$($a.pattern)" -Tokens $tok)
}

function Get-PimGroupNameCandidatesFromTag {
    # PURE. Every name an EXISTING group for this tag may carry under the tenant's pattern: the current rule first,
    # then the pre-2026-09-21 rule (tokens deleted) -- de-duplicated. For LOOKUPS; creation uses the first.
    [CmdletBinding()] param([AllowNull()][string]$Tag, [string]$Pattern)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($n in @((Resolve-PimGroupNameFromTag -Tag $Tag -Pattern $Pattern), (Resolve-PimGroupNameFromTag -Tag $Tag -Pattern $Pattern -Legacy))) {
        $v = "$n".Trim(); if ($v -and -not $out.Contains($v)) { $out.Add($v) }
    }
    return $out.ToArray()
}

function ConvertFrom-PimGroupNameToTag {
    <#
      PURE. The inverse: the TAG inside a group NAME. A name that is not this pattern's -> '' (there is deliberately
      no 'strip a leading PIM-' fallback: that is the generic assumption REQ-U removes).
      1. the pre-2026-09-21 rule (strip the literal text around {Role}) -- how existing groups are named;
      2. a regex built from the pattern (2026-09-21, tokens now carry values): tenant-level tokens as their
         configured literals, {Platform} as one of the configured suffixes, every per-group token as an OPTIONAL
         segment with its separator, {Role} as the tag. A tag that itself contains the separator a per-group token
         uses can be ambiguous; rule 1 wins whenever it applies.
    #>
    [CmdletBinding()] param([AllowNull()][string]$Name, [string]$Pattern)
    $n = "$Name".Trim()
    if (-not $n) { return '' }
    $a = Get-PimGroupNameAffixes -Pattern $Pattern
    $pre = "$($a.prefix)"; $suf = "$($a.suffix)"
    if ($n.Length -gt ($pre.Length + $suf.Length) -and
        (-not $pre -or $n.StartsWith($pre, [System.StringComparison]::OrdinalIgnoreCase)) -and
        (-not $suf -or $n.EndsWith($suf, [System.StringComparison]::OrdinalIgnoreCase))) {
        return $n.Substring($pre.Length, $n.Length - $pre.Length - $suf.Length)
    }
    $pat = "$($a.pattern)"
    if ($pat -notmatch '(?i)\{Role\}') { return '' }
    $conv = Get-PimNamingConvention
    $tcn = ConvertTo-PimNamePart "$($conv.TenantCommonName)"
    $aw  = if ("$($conv.AdminWord)".Trim()) { "$($conv.AdminWord)".Trim() } else { 'Admin' }
    $sfxs = @()
    $es = $conv.EnvironmentSuffixes
    if ($es -is [System.Collections.IDictionary]) { $sfxs = @($es.Values) } elseif ($es) { $sfxs = @($es.PSObject.Properties | ForEach-Object { $_.Value }) }
    $sfxAlt = (@($sfxs | ForEach-Object { "$_" } | Where-Object { $_ } | ForEach-Object { [regex]::Escape($_) }) -join '|')
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('^')
    foreach ($m in [regex]::Matches($pat, '([-_.]?[A-Za-z]?)\{([A-Za-z]+)\}|([^{]+?)(?=[-_.]?[A-Za-z]?\{|$)')) {
        if ($m.Groups[2].Success) {
            $lead = [regex]::Escape($m.Groups[1].Value); $k = $m.Groups[2].Value.ToLowerInvariant()
            switch ($k) {
                'role'             { [void]$sb.Append("$lead(?<tag>.+?)") }
                'tenantcommonname' { if ($tcn) { [void]$sb.Append("(?:$lead$([regex]::Escape($tcn)))?") } }
                'adminword'        { [void]$sb.Append("(?:$lead$([regex]::Escape($aw)))?") }
                { $_ -in 'platform','environmentsuffix' } { if ($sfxAlt) { [void]$sb.Append("(?:$lead(?:$sfxAlt))?") } }
                default            { [void]$sb.Append("(?:$lead[A-Za-z0-9.]+)?") }
            }
        } elseif ($m.Groups[3].Success) { [void]$sb.Append([regex]::Escape($m.Groups[3].Value)) }
    }
    [void]$sb.Append('$')
    $mm = $null
    try { $mm = [regex]::Match($n, $sb.ToString(), 'IgnoreCase') } catch { return '' }
    if ($mm -and $mm.Success -and $mm.Groups['tag'].Value) { return $mm.Groups['tag'].Value.Trim('-', '_') }
    return ''
}

function Get-PimGroupNamePrefix {
    # PURE. The literal text before the first {Token} of the tenant's PimGroupPattern -- the same rule as
    # Get-PimActiveAssignmentsGroupPrefix / Get-PimTenantSyncGroupPrefix. Returns '' when the pattern has no
    # literal prefix of at least -MinLength characters: callers that select groups BY PREFIX must then select
    # nothing, never fall back to a generic 'PIM-'.
    [CmdletBinding()] param([string]$Pattern, [int]$MinLength = 3)
    $pat = "$Pattern"
    if (-not $pat.Trim()) { $pat = "$(Get-PimNamingConvention -Key 'PimGroupPattern')" }
    if (-not $pat.Trim()) { $pat = 'PIM-{Role}-{Department}' }
    $i = $pat.IndexOf('{')
    $p = if ($i -lt 0) { $pat } else { $pat.Substring(0, $i) }
    if ($p.Length -lt $MinLength) { return '' }
    return $p
}

function ConvertTo-PimTenantGroupName {
    # PURE. Re-express a group NAME authored under one pattern (-FromPattern, a shipped pack's 'PIM-{Role}') under
    # the tenant's own pattern. A name that does not carry -FromPattern's affixes is returned unchanged -- it was
    # not written in that convention, so there is nothing to translate.
    [CmdletBinding()] param([AllowNull()][string]$Name, [string]$FromPattern = 'PIM-{Role}', [string]$ToPattern)
    $n = "$Name".Trim()
    if (-not $n) { return '' }
    $tag = ConvertFrom-PimGroupNameToTag -Name $n -Pattern $FromPattern
    if (-not $tag) { return $n }
    return (Resolve-PimGroupNameFromTag -Tag $tag -Pattern $ToPattern)
}

function Resolve-PimResourceGroup {
    # Generate the Azure RG name. The default now follows the FULL PIM naming
    # convention (same token grammar as Resolve-PimGroupName):
    #   PIM-{Workload}-{Scope}-{Permission}-L{Level}-T{Tier}-{Plane}-{Platform}
    #   e.g. PIM-AzDevOps-OrgCollectionAdministrators-L2-T1-WDP-ID
    # All tokens are optional; supply what the pattern needs via the parameters
    # (or -ExtraTokens for any not surfaced as a named parameter). Case is
    # PRESERVED (the convention is mixed-case, unlike the old lower-case rg-pim-*).
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Tier,
        [string]$Workload,
        [string]$Scope,
        [string]$Permission,
        [string]$Level,
        [string]$Plane,
        [string]$Platform,
        [hashtable]$ExtraTokens = @{}
    )
    $conv = Get-PimNamingConvention
    $pat  = "$($conv.ResourceGroupPattern)"; if (-not $pat) { $pat = 'rg-pim-{Tier}' }
    $tokens = @{ Tier = (ConvertTo-PimNamePart $Tier) }
    if ($PSBoundParameters.ContainsKey('Workload'))   { $tokens['Workload']   = (ConvertTo-PimNamePart $Workload) }
    if ($PSBoundParameters.ContainsKey('Scope'))      { $tokens['Scope']      = (ConvertTo-PimNamePart $Scope) }
    if ($PSBoundParameters.ContainsKey('Permission')) { $tokens['Permission'] = (ConvertTo-PimNamePart $Permission); $tokens['Role'] = $tokens['Permission'] }
    if ($PSBoundParameters.ContainsKey('Level'))      { $tokens['Level']      = (ConvertTo-PimNamePart $Level) }
    if ($PSBoundParameters.ContainsKey('Plane'))      { $tokens['Plane']      = (ConvertTo-PimNamePart $Plane) }
    if ($PSBoundParameters.ContainsKey('Platform'))   { $tokens['Platform']   = (ConvertTo-PimNamePart $Platform) }
    foreach ($k in @($ExtraTokens.Keys)) { $tokens[$k] = (ConvertTo-PimNamePart "$($ExtraTokens[$k])") }
    $name = Expand-PimNamePattern -Pattern $pat -Tokens $tokens
    # collapse separators left by blank tokens (PIM-...--L2 -> PIM-...-L2) + trim trailing '-'.
    $name = $name -replace '--+', '-'
    $name = $name -replace '-+$', ''
    # A legacy lower-case rg-pim-* pattern stays lower-case; the PIM-* convention
    # keeps its mixed case. Detect by the literal prefix of the configured pattern.
    if ("$pat" -cmatch '^[a-z]') { $name = $name.ToLowerInvariant() }   # -cmatch: case-SENSITIVE
    return $name
}

# ---------------------------------------------------------------------------
# Pattern -> validation regex. A pattern like 'Admin-{Owner}-L0-T0-{Platform}'
# becomes ^Admin-[A-Za-z0-9.\-]+-L0-T0-[A-Za-z0-9.\-]+$ so a generated name can be
# checked back against the convention that produced it.
# ---------------------------------------------------------------------------
function ConvertTo-PimNameRegex {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Pattern)
    # split into literal + {token} segments, escape literals, replace tokens with a part class.
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('^')
    foreach ($m in [regex]::Matches($Pattern, '(\{[^}]+\})|([^{]+)')) {
        if ($m.Groups[1].Success) {
            [void]$sb.Append('[A-Za-z0-9.\-]+')          # a token expands to >=1 dash-safe char
        } else {
            [void]$sb.Append([regex]::Escape($m.Groups[2].Value))
        }
    }
    [void]$sb.Append('$')
    return [regex]::new($sb.ToString(), 'IgnoreCase')
}

# ---------------------------------------------------------------------------
# Validation predicates (used by the engine + the GUI validator's PIM-NAME-* rules).
# ---------------------------------------------------------------------------
function ConvertTo-PimAdminNameRegex {
    # Like ConvertTo-PimNameRegex, but the admin-name pattern has two SPECIAL tokens
    # whose legal values are an enumerated, possibly-empty set (not a free [A-Za-z0-9]+):
    #   {AdminTypePrefix}   -> one of the configured prefixes (incl. '' for internal)
    #   {EnvironmentSuffix} -> one of the configured suffixes (e.g. -ID / -AD)
    # So 'Admin-JDO-ID' (no prefix) AND 'x-Admin-VND-AD' both validate, while a wrong
    # prefix/suffix is rejected. {Owner}/{Platform}/other tokens stay the generic class.
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Pattern)
    $conv = Get-PimNamingConvention
    function _altClass([object]$Map) {
        $vals = @()
        if ($Map -is [System.Collections.IDictionary]) { $vals = @($Map.Values) }
        elseif ($Map -and $Map.PSObject) { $vals = @($Map.PSObject.Properties | ForEach-Object { $_.Value }) }
        $vals = @($vals | ForEach-Object { "$_" } | Sort-Object -Unique)
        # alternation of the literal values; an empty value -> the alternative may be absent.
        $hasEmpty = $false
        $lits = New-Object System.Collections.Generic.List[string]
        # 2026-09-21 ("make sure i can use any variables here"): a prefix/suffix may carry tokens. Render it the way
        # the generator does -- {AdminWord} / {TenantCommonName} as their configured literals, any other token as the
        # generic class, doubled dashes collapsed -- instead of escaping the braces as literal text, which made every
        # correctly generated name fail validation.
        $aw  = if ("$($conv.AdminWord)".Trim()) { "$($conv.AdminWord)".Trim() } else { 'Admin' }
        $tcn = ConvertTo-PimNamePart "$($conv.TenantCommonName)"
        $mark = [string][char]1
        foreach ($v in $vals) {
            if ($v -eq '') { $hasEmpty = $true; continue }
            $r = [regex]::Replace($v, '\{AdminWord\}', [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $aw }, 'IgnoreCase')
            $r = [regex]::Replace($r, '\{TenantCommonName\}', [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $tcn }, 'IgnoreCase')
            $r = [regex]::Replace($r, '\{[A-Za-z]+\}', $mark)
            $r = $r -replace '--+', '-'
            if ($r -eq '') { $hasEmpty = $true; continue }
            [void]$lits.Add(([regex]::Escape($r)).Replace($mark, '[A-Za-z0-9.\-]*'))
        }
        if ($lits.Count -eq 0) { return '' }   # nothing but empties -> token contributes nothing
        $alt = ($lits -join '|')
        if ($hasEmpty) { return "(?:$alt)?" } else { return "(?:$alt)" }
    }
    $prefixClass = _altClass $conv.AdminTypePrefixes
    $suffixClass = _altClass $conv.EnvironmentSuffixes
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('^')
    foreach ($m in [regex]::Matches($Pattern, '(\{[^}]+\})|([^{]+)')) {
        if ($m.Groups[1].Success) {
            $tok = $m.Groups[1].Value
            switch -Regex ($tok) {
                '^\{AdminTypePrefix\}$'   { [void]$sb.Append($prefixClass) }
                # {Platform} is a synonym for {EnvironmentSuffix} in the admin pattern --
                # both expand to the configured environment-suffix set (-ID/-AD/...).
                '^\{(EnvironmentSuffix|Platform)\}$' { [void]$sb.Append($suffixClass) }
                # 🔴 {AdminWord} (v2.4.333) is ONE configured literal ('Admin' by default, 'adm' where a
                # customer chose it). It fell through to the generic class below, which accepts dashes --
                # so 'z-Admin-JDO-ID' matched as a single "word" and a wrong prefix was no longer caught.
                '^\{AdminWord\}$' {
                    $aw = if ("$($conv.AdminWord)".Trim()) { "$($conv.AdminWord)".Trim() } else { 'Admin' }
                    [void]$sb.Append([regex]::Escape($aw))
                }
                # {TenantCommonName} is a configured literal too ('efif', 'ride', ...). Same reasoning as
                # {AdminWord}: the generic class accepts dashes, so it would swallow the next segment
                # and stop the rule from catching a name built for the WRONG environment. Empty =
                # matches nothing extra, which is right for a tenant that does not use the token.
                '^\{TenantCommonName\}$' {
                    $ev = "$($conv.TenantCommonName)".Trim()
                    if ($ev) { [void]$sb.Append([regex]::Escape($ev)) }
                }
                default                   { [void]$sb.Append('[A-Za-z0-9.\-]+') }
            }
        } else {
            [void]$sb.Append([regex]::Escape($m.Groups[2].Value))
        }
    }
    [void]$sb.Append('$')
    return [regex]::new($sb.ToString(), 'IgnoreCase')
}

function Test-PimAdminName {
    # Does the admin name match the convention its Purpose selects? Purpose=HighPriv ->
    # the L0-T0 pattern; Purpose=Day2Day -> the day-2-day pattern; blank -> either passes.
    # The admin-type PREFIX and environment SUFFIX are validated against the configured
    # sets: 'Admin-JDO-ID' and 'x-Admin-VND-AD' pass; 'z-Admin-JDO-ID' (bad prefix) or
    # 'Admin-JDO-XX' (bad suffix) are rejected.
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('Day2Day', 'HighPriv', '')][string]$Purpose = ''
    )
    $conv = Get-PimNamingConvention
    $d2d  = if ($conv.AdminAccountPattern)         { ConvertTo-PimAdminNameRegex $conv.AdminAccountPattern }         else { $null }
    $hp   = if ($conv.AdminAccountPatternHighPriv) { ConvertTo-PimAdminNameRegex $conv.AdminAccountPatternHighPriv } else { $null }
    # match against the local part if the name is a UPN (the patterns describe the local part).
    $local = "$Name"; if ($local -match '@') { $local = $local.Split('@')[0] }
    $applicable = switch ("$Purpose") {
        'HighPriv' { @($hp) }
        'Day2Day'  { @($d2d) }
        default    { @($d2d, $hp) }
    }
    $applicable = @($applicable | Where-Object { $_ })
    if ($applicable.Count -eq 0) { return $true }   # no convention configured -> nothing to enforce
    foreach ($rx in $applicable) { if ($rx.IsMatch($local)) { return $true } }
    return $false
}

function Test-PimGroupName {
    # Validate a PIM group display name / tag. If PimGroupTagRegex is set it wins
    # (strict tag check); otherwise we assert the canonical group grammar shape.
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name)
    $conv = Get-PimNamingConvention
    if ("$($conv.PimGroupTagRegex)".Trim()) {
        return ([regex]::new($conv.PimGroupTagRegex, 'IgnoreCase')).IsMatch("$Name")
    }
    # Canonical shape (mirrors the validator's PIM-NAME-001 suggestion):
    #   [PIM-]<...>-L<0-9>-T<0-2>-<CP|WDP|MP|APP|USER>-<ID|RES|DAT>[-S_AD]
    # ...OR the simple {Role}-{Department} / AU subset shape (PIM-Helpdesk-IT etc.).
    $canonical = '^(PIM-)?.+-L[0-9]+-T[0-2]-(CP|WDP|MP|APP|USER)-(ID|RES|DAT)(-S_[A-Za-z0-9]+)?$'
    if ([regex]::IsMatch("$Name", $canonical, 'IgnoreCase')) { return $true }
    # fall back to the simple pattern's shape (PIM-<Role>[-<Department>]). Build the
    # regex from the literal segments of PimGroupPattern, making the {Department}
    # token (and its leading separator) optional so 'PIM-Helpdesk' and 'PIM-Helpdesk-IT'
    # both pass.
    $simplePat = "$($conv.PimGroupPattern)"; if (-not $simplePat) { $simplePat = 'PIM-{Role}-{Department}' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('^')
    foreach ($m in [regex]::Matches($simplePat, '(-?)(\{[^}]+\})|([^{]+)')) {
        if ($m.Groups[2].Success) {
            $sep = $m.Groups[1].Value
            if ("$($m.Groups[2].Value)" -ieq '{Department}') {
                [void]$sb.Append('(' + [regex]::Escape($sep) + '[A-Za-z0-9.\-]+)?')   # optional dept (+ its sep)
            } else {
                [void]$sb.Append([regex]::Escape($sep) + '[A-Za-z0-9.\-]+')
            }
        } else {
            [void]$sb.Append([regex]::Escape($m.Groups[3].Value))
        }
    }
    [void]$sb.Append('$')
    return ([regex]::new($sb.ToString(), 'IgnoreCase')).IsMatch("$Name")
}

# ---------------------------------------------------------------------------
# Convention summary -- one object the GUI/migration report can render.
# ---------------------------------------------------------------------------
function Get-PimNamingSummary {
    [CmdletBinding()] param()
    $c = Get-PimNamingConvention
    return [pscustomobject]@{
        AdminDay2Day        = "$($c.AdminAccountPattern)"
        AdminHighPriv       = "$($c.AdminAccountPatternHighPriv)"
        AdminPrefixes       = @($c.AdminAccountPatterns)
        AdminTypePrefixes   = $c.AdminTypePrefixes
        AdminTypeDefault    = "$($c.AdminTypeDefault)"
        EnvironmentSuffixes = $c.EnvironmentSuffixes
        EnvironmentDefault  = "$($c.EnvironmentDefault)"
        GroupPattern        = "$($c.PimGroupPattern)"
        GroupAuPattern      = "$($c.PimGroupAuPattern)"
        ResourceGroup       = "$($c.ResourceGroupPattern)"
        GroupTagRegex       = "$($c.PimGroupTagRegex)"
        Separator           = '-'
    }
}
