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
function Get-PimNamingConvention {
    [CmdletBinding()] param([string]$Key)
    $defaults = @{
        # Admin name = {AdminTypePrefix} + 'Admin-{Initial}' core + {Platform}.
        # The prefix comes from the row's AdminType; the {Platform} suffix from its
        # Environment (entra -> -ID, ad -> -AD). {Initial} is the owner/initials token
        # ({Owner} is honoured as a synonym). The rendered name is lower-cased, e.g.
        # internal Entra 'mok' -> 'admin-mok-id'; high-priv -> 'admin-mok-l0-t0-id'.
        AdminAccountPattern           = '{AdminTypePrefix}Admin-{Initial}{Platform}'
        AdminAccountPatternHighPriv   = 'Admin-{Initial}-L0-T0{Platform}'
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
    }
    $conv = $defaults.Clone()
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
    $out = $Pattern
    foreach ($k in @($Tokens.Keys)) {
        $val = "$($Tokens[$k])"
        $out = [regex]::Replace($out, [regex]::Escape('{' + $k + '}'), [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $val }, 'IgnoreCase')
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
        [switch]$HighPriv
    )
    $conv = Get-PimNamingConvention
    $pat  = if ($HighPriv) { "$($conv.AdminAccountPatternHighPriv)" } else { "$($conv.AdminAccountPattern)" }
    if (-not $pat) { $pat = if ($HighPriv) { 'Admin-{Initial}-L0-T0{Platform}' } else { '{AdminTypePrefix}Admin-{Initial}{Platform}' } }
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
    }
    # collapse any doubled separator a blank token may have left.
    $name = $name -replace '--+', '-'
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
        foreach ($v in $vals) { if ($v -eq '') { $hasEmpty = $true } else { [void]$lits.Add([regex]::Escape($v)) } }
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
