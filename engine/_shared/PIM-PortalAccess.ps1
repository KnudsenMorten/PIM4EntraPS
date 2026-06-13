# PIM4EntraPS -- portal-admin scoping (delegated GUI managers).
# Dot-sourced by PIM-Functions.psm1 and standalone by the pim-manager.
#
# The Manager keeps its flat Reader/Admin/SuperAdmin role (manager-access). On
# TOP of that, portal-admins are delegated GUI managers (helpdesk, business IT,
# dept owners, workload managers) scoped by tier/level/service/scope/capability,
# controlled by super-admins via config/portal-admins.json. A SuperAdmin bypasses
# ALL of this (sees + manages everything, no validation).
#
# Privilege ordering: T0 most privileged (tier int 0), L0 most privileged
# (level int 0). A portal-admin may touch a group only at-or-below their ceiling:
#   group.tier  >= profile.tierMax   AND   group.level >= profile.levelMax
# (so tierMax=1 excludes T0; levelMax=2 excludes L0+L1). Plus the group's service
# must be in profile.services (or '*'), and for azure the group's scope must sit
# under one of profile.scopes. Pure + time-free -> fully testable offline.

Set-StrictMode -Off

# Capabilities a portal-admin profile may carry.
$script:PimPortalCapabilities = @('manage-direct','manage-indirect','assign','assign-admin','enable-consultants','invite-guest')

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
    $scope    = & $get 'PermissionScope'; if (-not $scope) { $scope = & $get 'AzScope' }
    $au       = & $get 'AdministrativeUnitTag'

    # Name-grammar fallback: PIM-{Service}-{Name}-L{n}-T{n}-{Code}-{Domain}
    if ((-not $workload -or -not $tierRaw -or -not $levelRaw -or -not $plane) -and $name) {
        $m = [regex]::Match($name, '(?i)^PIM-(?<svc>[A-Za-z0-9]+(?:-[A-Za-z0-9]+)?)-.*-L(?<lvl>\d+)-T(?<tier>\d+)-(?<code>[A-Za-z]+)-(?<dom>[A-Za-z]+)')
        if ($m.Success) {
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
    # Load config/portal-admins.json (sample fallback). Returns array of profiles.
    param([string]$ConfigDir, [string]$ProfilesFile)
    $f = $ProfilesFile
    if (-not $f) {
        $f = Join-Path $ConfigDir 'portal-admins.json'
        if (-not (Test-Path -LiteralPath $f)) {
            $s = Join-Path $ConfigDir 'portal-admins.sample.json'
            if (Test-Path -LiteralPath $s) { $f = $s } else { return @() }
        }
    }
    if (-not (Test-Path -LiteralPath $f)) { return @() }
    try { return @((Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json).portalAdmins) } catch { return @() }
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

function Test-PimPortalCanManageGroup {
    # Can-see AND has the matching manage capability for the group's kind.
    param([AllowNull()][object]$Profile, [Parameter(Mandatory)][hashtable]$Facets, [switch]$IsSuperAdmin)
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
