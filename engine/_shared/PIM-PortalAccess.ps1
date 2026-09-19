# PIM4EntraPS -- portal-admin scoping (delegated GUI managers).
# Dot-sourced by PIM-Functions.psm1 and standalone by the pim-manager.
#
# The Manager keeps its flat Reader/Admin/SuperAdmin role (manager-access). On
# TOP of that, portal-admins are delegated GUI managers (helpdesk, business IT,
# dept owners, workload managers) scoped by tier/level/service/scope/capability,
# controlled by super-admins via SQL pim.Settings['PortalAdmins'] (Set-PimPortalAdmins.ps1). A SuperAdmin bypasses
# ALL of this (sees + manages everything, no validation).
#
# Privilege ordering: T0 most privileged (tier int 0), L0 most privileged
# (level int 0). A portal-admin may touch a group only at-or-below their ceiling:
#   group.tier  >= profile.tierMax   AND   group.level >= profile.levelMax
# (so tierMax=1 excludes T0; levelMax=2 excludes L0+L1). Plus the group's service
# must be in profile.services (or '*'), and for azure the group's scope must sit
# under one of profile.scopes. Pure + time-free -> fully testable offline.

Set-StrictMode -Off

# REQ-U: the name-grammar fallback in Get-PimGroupFacets reads names through the tenant's pattern (PIM-Naming.ps1).
if (-not (Get-Command ConvertFrom-PimGroupNameToTag -ErrorAction SilentlyContinue)) {
    $__pimNamingLibPa = Join-Path $PSScriptRoot 'PIM-Naming.ps1'
    if (Test-Path -LiteralPath $__pimNamingLibPa) { . $__pimNamingLibPa }
}

# Capabilities a portal-admin profile may carry.
$script:PimPortalCapabilities = @('manage-direct','manage-indirect','assign','assign-admin','enable-consultants','invite-guest','approve-assignment','access-review')

function Get-PimPolicySetting {
    # EVERYTHING is configurable in the config file. Resolution order:
    #   1. the loaded config hashtable $global:PIM_NamingConventions[<Name>]
    #      (set by config/PIM4EntraPS.NamingConventions.locked|custom.ps1)
    #   2. an individual $global:PIM_<Name> override (runtime / launcher)
    #   3. the supplied default
    # So a customer tunes PawEnforcement / PawPolicy / PawSignals / naming /
    # network zones etc. entirely in the file -- nothing is hardcoded in the engine.
    param([Parameter(Mandatory)][string]$Name, $Default)
    if ($global:PIM_NamingConventions -is [hashtable] -and $global:PIM_NamingConventions.ContainsKey($Name)) { return $global:PIM_NamingConventions[$Name] }
    $g = Get-Variable -Name "PIM_$Name" -Scope Global -ErrorAction SilentlyContinue
    if ($g -and $null -ne $g.Value) { return $g.Value }
    # 4. container-friendly: an env var PIM_<Name> (e.g. PIM_StorageBackend=sql)
    $e = Get-Item -LiteralPath "Env:PIM_$Name" -ErrorAction SilentlyContinue
    if ($e -and "$($e.Value)".Trim() -ne '') { return $e.Value }
    return $Default
}

function Resolve-PimServiceType {
    # Map a Workload/Service token to the coarse service axis used for scoping.
    param([AllowNull()][string]$Workload)
    $w = "$Workload".Trim().ToLowerInvariant()
    if (-not $w) { return 'unknown' }
    if ($w -like 'entra*' -or $w -eq 'ad' -or $w -like 'entra-*') { return 'entra' }
    if ($w -eq 'azure' -or $w -like 'azure*' -or $w -eq 'res' -or $w -like 'res-*') { return 'azure' }
    return 'workload'   # defender, powerbi, intune, exchange, teams, sharepoint, azdevops, dataverse, ...
}

function ConvertTo-PimIntTierLevel {
    # 'T0'/'t0'/'0' -> 0 ; 'L2'/'2' -> 2 ; blank -> $null.
    param([AllowNull()][string]$Value)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return $null }
    $m = [regex]::Match("$Value", '(?i)[TL]?\s*(\d+)')
    if ($m.Success) { return [int]$m.Groups[1].Value }
    return $null
}

function Get-PimGroupFacets {
    # Extract scoping facets from a definition ROW (or fall back to parsing the
    # group NAME via the locked naming grammar). Returns:
    #   @{ service; tier(int|null); level(int|null); plane; scope; groupTag; name; kind }
    # kind = 'indirect' for permission groups (carry a Workload) else 'direct'
    # (role/process/dept/org business groups).
    param([Parameter(Mandatory)][object]$Row, [string]$Base)
    $get = {
        param($n)
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { return "$($Row[$n])" } ; return '' }
        $p = $Row.PSObject.Properties[$n]; if ($p) { return "$($p.Value)" } else { return '' }
    }
    $name     = & $get 'GroupName'
    $tag      = & $get 'GroupTag'
    $workload = & $get 'Workload'
    $plane    = & $get 'Plane'
    $tierRaw  = & $get 'TierLevel'
    $levelRaw = & $get 'Level'
    # scope is a GENERAL dimension: Azure ARM scope, Defender device-group scope
    # (all assets / servers / workstations), Power BI workspace, and for ENTRA the
    # Administrative Unit (L2 auth-admin-on-AU vs L1 tenant-wide vs L0 GA).
    $scope    = & $get 'PermissionScope'; if (-not $scope) { $scope = & $get 'AzScope' }; if (-not $scope) { $scope = & $get 'Scope' }; if (-not $scope) { $scope = & $get 'AdministrativeUnitTag' }
    # Defender (and similar) encode scope as a NAME SEGMENT: ...-Scope-<Clients|Servers>-L<n>...
    if (-not $scope -and $name) { $ms = [regex]::Match($name, '(?i)-Scope-([A-Za-z0-9]+)-L\d'); if ($ms.Success) { $scope = $ms.Groups[1].Value } }
    $au       = & $get 'AdministrativeUnitTag'

    # Name-grammar fallback: {Service}-{Name}-L{n}-T{n}-{Code}-{Domain}, read from the tenant-neutral part.
    # 🔴 REQ-U (2026-09-19): this matched '^PIM-...' against the NAME, so on a tenant whose pattern is
    # 'GRP-{Role}' no group ever yielded a service / tier / level and every delegated portal profile scoped by
    # them silently matched nothing. The grammar is now read from the GroupTag, else from the name with the
    # TENANT's pattern affixes stripped (ConvertFrom-PimGroupNameToTag) -- never from a hard-coded prefix.
    if ((-not $workload -or -not $tierRaw -or -not $levelRaw -or -not $plane) -and ($name -or $tag)) {
        $gram = '(?i)^(?<svc>[A-Za-z0-9]+(?:-[A-Za-z0-9]+)?)-.*-L(?<lvl>\d+)-T(?<tier>\d+)-(?<code>[A-Za-z]+)-(?<dom>[A-Za-z]+)'
        $cands = New-Object System.Collections.Generic.List[string]
        if ($tag) { $cands.Add("$tag") }
        if ($name -and (Get-Command ConvertFrom-PimGroupNameToTag -ErrorAction SilentlyContinue)) {
            $np = "$(ConvertFrom-PimGroupNameToTag -Name $name)"; if ($np) { $cands.Add($np) }
        }
        $m = $null
        foreach ($c in $cands) { $mm = [regex]::Match($c, $gram); if ($mm.Success) { $m = $mm; break } }
        if ($m -and $m.Success) {
            if (-not $workload) { $workload = $m.Groups['svc'].Value }
            if (-not $levelRaw) { $levelRaw = $m.Groups['lvl'].Value }
            if (-not $tierRaw)  { $tierRaw  = $m.Groups['tier'].Value }
            if (-not $plane)    { $plane    = $m.Groups['code'].Value }
        }
    }

    $kind = if ("$workload".Trim()) { 'indirect' } else { 'direct' }
    # Tag-prefix hint for direct kinds (ROLE-/PROCESS-/DEPT-/ORG-).
    if ($kind -eq 'direct' -and $tag) {
        # already direct; nothing more needed
    }
    return @{
        service  = (Resolve-PimServiceType -Workload $workload)
        workload = "$workload"
        tier     = (ConvertTo-PimIntTierLevel -Value $tierRaw)
        level    = (ConvertTo-PimIntTierLevel -Value $levelRaw)
        plane    = "$plane"
        scope    = "$scope"
        au       = "$au"
        groupTag = "$tag"
        name     = "$name"
        kind     = $kind
    }
}

function Read-PimPortalProfiles {
    # Returns the delegated portal-admin profiles (tier/level/service/scope scoping).
    # 🔒 SQL-ONLY, in every mode (operator, 2026-09-12: "we dont use settings files anymore, sql
    # only"). The profiles live in pim.Settings['PortalAdmins'] (JSON), written by
    # tools/setup/Set-PimPortalAdmins.ps1 and hydrated into $global:PIM_NamingConventions at boot.
    # 🔴 SEC-15 / §36.3 phase 2 -- THIS IS AN AUTHORIZATION READ, so it fails CLOSED.
    #
    # History: it used to prefer SQL, then fall back to config/portal-admins.json (local/dev), and
    # before that to the shipped SAMPLE. Anyone able to write that file could grant themselves L0
    # across every service, and nothing distinguished "the authorization model" from "a JSON file
    # somebody left on the box". The file branch is now GONE, not merely unreached: no parameter
    # names a file, and a store with no profiles answers "no profiles" -- which denies every
    # non-SuperAdmin, the safe direction. The SOURCE is recorded so the Manager can say which
    # store answered (sql | sql-empty | sql-invalid).
    # Unit tests inject profiles the same way production does: through the hydrated setting.
    param()

    if (($global:PIM_NamingConventions -is [hashtable]) -and $global:PIM_NamingConventions['PortalAdmins']) {
        $raw = $global:PIM_NamingConventions['PortalAdmins']
        try {
            # 🔴 B1-class (2026-09-10): the boot hydration returns settings ALREADY JSON-PARSED, so
            # re-parsing a PSCustomObject stringifies it to `@{portalAdmins=System.Object[]}`, throws,
            # and this catch DENIES EVERY delegated profile -- reporting 'sql-invalid' about a value
            # that is perfectly valid. Parse only what is still text. (Fixed with B1 in the Manager's
            # Get-PimManagerRole; identical shape, identical consequence: authorization silently off.)
            $parsed = if ($raw -is [string]) { "$raw" | ConvertFrom-Json } else { $raw }
            $script:PimPortalProfileSource = 'sql'
            if ($parsed.PSObject.Properties['portalAdmins']) { return @($parsed.portalAdmins) }
            return @($parsed)
        } catch {
            # 🔒 Malformed authorization JSON must NOT degrade to anything. Deny instead.
            $script:PimPortalProfileSource = 'sql-invalid'
            Write-Warning "  [portal] SQL 'PortalAdmins' setting is not valid JSON -- DENYING all delegated access: $($_.Exception.Message)"
            return @()
        }
    }

    # No SQL profiles == there are none. Say so; never go looking on a filesystem.
    $script:PimPortalProfileSource = 'sql-empty'
    return @()
}

function Get-PimPortalProfileSource {
    <#
      Which store answered the last Read-PimPortalProfiles: sql | sql-empty | sql-invalid
      (SQL is the only store; there is no file source). Surfaced on /api/portal-access so "why can this person suddenly
      do that?" is answerable -- a silent fallback is the SEC-15 defect, and knowing the source is
      how it stops being silent.
    #>
    if ($script:PimPortalProfileSource) { return "$($script:PimPortalProfileSource)" }
    return 'unknown'
}

function Get-PimPortalProfile {
    # Resolve one identity -> its portal profile (case-insensitive), or $null.
    param([object[]]$Profiles = @(), [Parameter(Mandatory)][string]$Identity)
    foreach ($p in @($Profiles)) {
        if ("$($p.identity)" -and ("$($p.identity)".ToLowerInvariant() -eq "$Identity".ToLowerInvariant())) { return $p }
    }
    return $null
}

function Test-PimScopeUnder {
    # TRUE when $Scope is at or under one of $Allowed (prefix match, path-segment
    # aware). Used for azure scope gating. Empty $Allowed = no azure restriction.
    param([AllowNull()][string]$Scope, [object[]]$Allowed = @())
    $allowed = @(@($Allowed) | Where-Object { "$_".Trim() })
    if ($allowed.Count -eq 0) { return $true }
    $s = "$Scope".Trim().TrimEnd('/').ToLowerInvariant()
    if (-not $s) { return $false }
    foreach ($a in $allowed) {
        $aa = "$a".Trim().TrimEnd('/').ToLowerInvariant()
        if ($s -eq $aa -or $s.StartsWith($aa + '/')) { return $true }
    }
    return $false
}

function Test-PimPortalCanSeeGroup {
    # Can this profile SEE a group with these facets? (service + tier + level +
    # azure-scope gates). $IsSuperAdmin bypasses everything.
    param([AllowNull()][object]$Profile, [Parameter(Mandatory)][hashtable]$Facets, [switch]$IsSuperAdmin)
    if ($IsSuperAdmin) { return $true }
    if ($null -eq $Profile) { return $false }
    # service axis
    $svcs = @(@($Profile.services) | ForEach-Object { "$_".ToLowerInvariant() })
    if ($svcs.Count -gt 0 -and $svcs -notcontains '*' -and $svcs -notcontains "$($Facets.service)".ToLowerInvariant()) { return $false }
    # tier ceiling (T0 most privileged): group.tier >= tierMax
    if ($null -ne $Profile.tierMax -and "$($Profile.tierMax)" -ne '') {
        if ($null -eq $Facets.tier -or [int]$Facets.tier -lt [int]$Profile.tierMax) { return $false }
    }
    # level ceiling (L0 most privileged): group.level >= levelMax
    if ($null -ne $Profile.levelMax -and "$($Profile.levelMax)" -ne '') {
        if ($null -eq $Facets.level -or [int]$Facets.level -lt [int]$Profile.levelMax) { return $false }
    }
    # azure scope gate (only when scopes constrained AND this is an azure group)
    if ("$($Facets.service)" -eq 'azure') {
        if (-not (Test-PimScopeUnder -Scope $Facets.scope -Allowed @($Profile.scopes))) { return $false }
    }
    # explicit group allowlist (optional, additive narrowing)
    $allow = @(@($Profile.managedGroupTags) | Where-Object { "$_".Trim() })
    if ($allow.Count -gt 0 -and ($allow -notcontains "$($Facets.groupTag)")) { return $false }
    return $true
}

function Resolve-PimDevicePawLevel {
    # PAW detection is environment-specific (device GROUP MEMBERSHIP, device
    # extensionAttribute, CA named location, network). The endpoint resolves those
    # signals upstream and passes them; this returns the device's PAW LEVEL (0/1/2,
    # 0 = most secure) or $null (not a PAW). Signals: an explicit { pawLevel = N },
    # or per-level booleans whose key contains 'l0'/'l1'/'l2'; the LOWEST matching
    # level wins. Trusted-signal set customizable via $global:PIM_PawSignals.
    param([hashtable]$Signals = @{})
    $cfgTrust = Get-PimPolicySetting -Name 'PawSignals' -Default @()
    $trust = if ($cfgTrust) { @(@($cfgTrust) | ForEach-Object { "$_".ToLowerInvariant() }) } else { @() }
    $best = $null
    foreach ($k in $Signals.Keys) {
        if ($trust.Count -gt 0 -and ($trust -notcontains "$k".ToLowerInvariant())) { continue }
        $kl = "$k".ToLowerInvariant()
        if ($kl -eq 'pawlevel' -and "$($Signals[$k])" -match '^\d+$') { $lvl = [int]$Signals[$k]; if ($null -eq $best -or $lvl -lt $best) { $best = $lvl }; continue }
        if (-not [bool]$Signals[$k]) { continue }
        $m = [regex]::Match($kl, 'l([012])')
        if ($m.Success) { $lvl = [int]$m.Groups[1].Value; if ($null -eq $best -or $lvl -lt $best) { $best = $lvl } }
    }
    return $best
}

function Get-PimDefaultPawPolicy {
    # Which (tier, plane, level) require a PAW, and at what level. First match wins;
    # pawLevel 'group' = the group's own level, 'none' = whole-network OK, or a
    # fixed int. Unmatched -> no PAW. Fully overridable via $global:PIM_PawPolicy
    # to fit customer maturity. Default reflects: tier-0 -> PAW; tier-1 management
    # plane (MP) -> PAW (privileged platform); everything else (tier-1 WDP incl.
    # level 3+, tier-2) -> whole network.
    return @(
        @{ tier = 0;            pawLevel = 'group' }
        @{ tier = 1; plane = 'MP'; pawLevel = 'group' }
    )
}

function Get-PimRequiredPawLevel {
    # The PAW level a (tier, plane, level) requires, or $null when none is required.
    param([Parameter(Mandatory)][int]$Tier, [string]$Plane, [int]$Level = 0, [object[]]$Policy)
    if (-not $Policy) { $Policy = @(Get-PimPolicySetting -Name 'PawPolicy' -Default (Get-PimDefaultPawPolicy)) }
    foreach ($r in @($Policy)) {
        if ($null -ne $r.tier -and "$($r.tier)" -ne '' -and [int]$r.tier -ne $Tier) { continue }
        if ("$($r.plane)".Trim() -and "$($r.plane)" -ine "$Plane") { continue }
        if ($null -ne $r.minLevel -and "$($r.minLevel)" -ne '' -and $Level -lt [int]$r.minLevel) { continue }
        if ($null -ne $r.maxLevel -and "$($r.maxLevel)" -ne '' -and $Level -gt [int]$r.maxLevel) { continue }
        $pl = "$($r.pawLevel)".Trim()
        if ($pl -ieq 'none') { return $null }
        if ($pl -eq '' -or $pl -ieq 'group') { return $Level }
        if ($pl -match '^\d+$') { return [int]$pl }
        return $Level
    }
    return $null
}

function Test-PimPawAllowed {
    # PAW gate -- OPT-IN (OFF by default; many customers have no PAW). When enabled
    # ($global:PIM_PawEnforcement or -Enforce), the group's (tier, plane, level) is
    # matched to the policy -> a required PAW level (or none). A more-privileged PAW
    # (lower level) may manage less-privileged work (RequestPawLevel <= required).
    param([Parameter(Mandatory)][int]$Tier, [string]$Plane, [int]$Level = 0, [Nullable[int]]$RequestPawLevel, [object[]]$Policy, [Nullable[bool]]$Enforce)
    if ($null -eq $Enforce) { $Enforce = [bool](Get-PimPolicySetting -Name 'PawEnforcement' -Default $false) }
    if (-not $Enforce) { return $true }
    $req = Get-PimRequiredPawLevel -Tier $Tier -Plane $Plane -Level $Level -Policy $Policy
    if ($null -eq $req) { return $true }                 # whole-network OK
    if ($null -eq $RequestPawLevel) { return $false }    # PAW required, none present
    return ([int]$RequestPawLevel -le [int]$req)
}

function Test-PimPortalCanManageGroup {
    # Can-see AND has the matching manage capability for the group's kind.
    #
    # NETWORK GATE: tier-0 management requires the PAW zone -- BUT super-admins are
    # NOT zone-locked by default (break-glass safety; a misdetected/blank zone must
    # never lock a super-admin out of tier 0). Set $Tier0RequiresPawForSuperAdmin
    # (or $global:PIM_Tier0RequiresPawForSuperAdmin) to ALSO gate super-admins.
    # Regular portal-admins are always zone-gated for tier 0 when a zone is given.
    param(
        [AllowNull()][object]$Profile, [Parameter(Mandatory)][hashtable]$Facets,
        [switch]$IsSuperAdmin, [Nullable[int]]$RequestPawLevel, [Nullable[bool]]$EnforcePaw,
        [Nullable[bool]]$EnforcePawForSuperAdmin
    )
    $enforce = if ($null -ne $EnforcePaw) { [bool]$EnforcePaw } else { [bool](Get-PimPolicySetting -Name 'PawEnforcement' -Default $false) }
    if ($enforce) {
        if ($null -eq $EnforcePawForSuperAdmin) { $EnforcePawForSuperAdmin = [bool](Get-PimPolicySetting -Name 'PawEnforcementForSuperAdmin' -Default $false) }  # default $false: never lock out super-admins
        $applies = if ($IsSuperAdmin) { [bool]$EnforcePawForSuperAdmin } else { $true }
        # Policy maps (tier, plane, level) -> required PAW level (helpdesk L2 PAW ->
        # only L2; consultant L1 -> L1/L2; high-priv L0 -> all; tier-1 WDP L3+ -> none).
        if ($applies -and -not (Test-PimPawAllowed -Tier ([int]$Facets.tier) -Plane "$($Facets.plane)" -Level ([int]$Facets.level) -RequestPawLevel $RequestPawLevel -Enforce $true)) { return $false }
    }
    if ($IsSuperAdmin) { return $true }
    if (-not (Test-PimPortalCanSeeGroup -Profile $Profile -Facets $Facets)) { return $false }
    $caps = @(@($Profile.capabilities) | ForEach-Object { "$_".ToLowerInvariant() })
    if ("$($Facets.kind)" -eq 'direct')   { return ($caps -contains 'manage-direct') }
    return ($caps -contains 'manage-indirect')
}

function Test-PimPortalCanAssign {
    # Can this profile make assignments at all (assign / assign-admin capability)?
    param([AllowNull()][object]$Profile, [switch]$IsSuperAdmin)
    if ($IsSuperAdmin) { return $true }
    if ($null -eq $Profile) { return $false }
    $caps = @(@($Profile.capabilities) | ForEach-Object { "$_".ToLowerInvariant() })
    return ($caps -contains 'assign' -or $caps -contains 'assign-admin')
}

function Test-PimPortalCanAssignAdmin {
    # Can this profile assign permissions TO a given admin/consultant? Only the
    # consultants the profile manages (managedAdmins; '*' = any). Requires the
    # assign-admin capability.
    param([AllowNull()][object]$Profile, [Parameter(Mandatory)][string]$AdminName, [switch]$IsSuperAdmin)
    if ($IsSuperAdmin) { return $true }
    if ($null -eq $Profile) { return $false }
    $caps = @(@($Profile.capabilities) | ForEach-Object { "$_".ToLowerInvariant() })
    if ($caps -notcontains 'assign-admin') { return $false }
    $managed = @(@($Profile.managedAdmins) | ForEach-Object { "$_".ToLowerInvariant() })
    if ($managed -contains '*') { return $true }
    return ($managed -contains "$AdminName".ToLowerInvariant())
}

function Test-PimPortalCanEnableConsultant {
    # Self-service: a dept/service owner enabling/disabling THEIR OWN consultant.
    param([AllowNull()][object]$Profile, [Parameter(Mandatory)][string]$AdminName, [switch]$IsSuperAdmin)
    if ($IsSuperAdmin) { return $true }
    if ($null -eq $Profile) { return $false }
    $caps = @(@($Profile.capabilities) | ForEach-Object { "$_".ToLowerInvariant() })
    if ($caps -notcontains 'enable-consultants') { return $false }
    $managed = @(@($Profile.managedAdmins) | ForEach-Object { "$_".ToLowerInvariant() })
    if ($managed -contains '*') { return $true }
    return ($managed -contains "$AdminName".ToLowerInvariant())
}

function Test-PimPortalCanManageAdmin {
    <#
      REQUIREMENTS §35.3 -- may this caller perform an ACCOUNT OPERATION on this admin?
      (enable/disable · reset TAP · flag for deletion · revoke sign-in sessions · modify)

      🔑 WHY THIS IS ITS OWN CAPABILITY, AND NOT `assign-admin`.
      Before this, the only two gates taking an ADMIN as the subject were
      Test-PimPortalCanAssignAdmin (`assign-admin`) and Test-PimPortalCanEnableConsultant
      (`enable-consultants`). Both answer "may this profile GRANT to this person?" --
      a different authority from "may this profile ACT ON this person's account".
      Reusing `assign-admin` would have compiled and would have meant that anyone who
      may grant access may also kill sessions and queue deletions. Those are not the
      same power, and conflating them is how a permission model quietly stops matching
      the thing its own documentation claims.

      🔒 DEFAULT-DENY, DELIBERATELY. `manage-account` is a NEW capability, so no existing
      portal profile holds it and every non-SuperAdmin is refused until an operator adds
      it explicitly. That is the correct direction to fail for destructive verbs: the
      alternative -- seeding it into existing profiles so nothing "breaks" -- would grant
      account-destruction rights to everyone who already had any portal profile, silently.
      SuperAdmin bypasses, as everywhere else in this file.
    #>
    param([AllowNull()][object]$Profile, [Parameter(Mandatory)][string]$AdminName, [switch]$IsSuperAdmin)
    if ($IsSuperAdmin) { return $true }
    if ($null -eq $Profile) { return $false }
    $caps = @(@($Profile.capabilities) | ForEach-Object { "$_".ToLowerInvariant() })

    # 🔒 OPERATOR DECISION 2026-08-31: "grant manage-account (level 0-2)".
    # The capability shipped default-deny, which meant only SuperAdmin could act on an account
    # and the §35.2 grid was empty for everyone else. Profiles whose ceiling is L0-L2 -- the
    # admin/helpdesk tiers that already manage privileged accounts day to day -- now hold it
    # implicitly. L3+ (business/workload owners) still need it granted explicitly.
    # 🔑 This is a DELIBERATE relaxation of default-deny, not a default drifting open: it is
    # scoped by LEVEL, it does not widen WHICH admins are reachable (managedAdmins still
    # decides that), and an explicit capability list is still honoured.
    $lvl = $null
    if ($Profile.PSObject.Properties['levelMax'] -and "$($Profile.levelMax)".Trim() -ne '') {
        $n = 0; if ([int]::TryParse("$($Profile.levelMax)", [ref]$n)) { $lvl = $n }
    }
    $byLevel = ($null -ne $lvl -and $lvl -ge 0 -and $lvl -le 2)

    if (-not ($caps -contains 'manage-account') -and -not $byLevel) { return $false }
    $managed = @(@($Profile.managedAdmins) | ForEach-Object { "$_".ToLowerInvariant() })
    if ($managed -contains '*') { return $true }
    return ($managed -contains "$AdminName".ToLowerInvariant())
}

function Select-PimPortalVisibleRows {
    # Filter definition rows to those a profile can SEE. $IsSuperAdmin -> all.
    param([AllowNull()][object]$Profile, [object[]]$Rows = @(), [string]$Base, [switch]$IsSuperAdmin)
    if ($IsSuperAdmin) { return @($Rows) }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        $f = Get-PimGroupFacets -Row $r -Base $Base
        if (Test-PimPortalCanSeeGroup -Profile $Profile -Facets $f) { $out.Add($r) }
    }
    return $out.ToArray()
}
