<#
  PIM4EntraPS -- NEW engine scope providers (REST + SQL). Each provider plugs into
  PIM-EngineCore.ps1. Add a scope by registering a provider here.

  Implemented now:
    * Admins  -- ensure the admin accounts (Account-Definitions-Admins) exist + enabled
                 in Entra, fully over Graph REST.

  Contract for the remaining scopes (EntraRoles, AzRes, GroupsAssignment, GroupsPolicies,
  AdministrativeUnits, Workloads) is the same hashtable shape; they are added
  incrementally (their PIM REST apply workflows are larger). Until a provider is
  registered, Invoke-PimEngineScope returns "no provider" for that scope (handled
  gracefully by the scheduler).
#>

Set-StrictMode -Off

function Get-PimRowProp {
    param([object]$Row, [string[]]$Names)
    foreach ($n in $Names) {
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { return "$($Row[$n])" } }
        else { $p = $Row.PSObject.Properties[$n]; if ($p) { return "$($p.Value)" } }
    }
    return ''
}

function New-PimAdminsProvider {
    @{
        scope  = 'Admins'
        entity = 'Account-Definitions-Admins'
        order  = 30
        # ACCOUNT-DISABLE scope: its ApplyRemove sets accountEnabled=$false and its
        # GetLive is the WHOLE tenant user population, so a wrong/empty desired set could
        # disable everything it scans (incident 2026-06-15). isAccountDisable routes its
        # removals through PIM-DisableGuard (feature opt-in + positively-resolved desired
        # set + mass-disable circuit breaker) in PIM-EngineCore before any disable runs.
        isAccountDisable = $true
        GetDesired = { param($ctx) Get-PimDesiredRows -Entity 'Account-Definitions-Admins' }
        GetLive    = {
            param($ctx)
            @(Invoke-PimGraph -Path "/users?`$select=id,userPrincipalName,displayName,accountEnabled" -All)
        }
        KeyOf = { param($r) Get-PimRowProp -Row $r -Names @('userPrincipalName','UserPrincipalName','UPN','upn') }
        # desired = account should EXIST and be ENABLED. (Equality is against live.)
        Equal = { param($d,$l) [bool]$l.accountEnabled }
        ApplyCreate = {
            param($item,$ctx)
            $upn  = "$($item.key)"
            $disp = Get-PimRowProp -Row $item.desired -Names @('DisplayName','displayName')
            if (-not $disp) { $disp = $upn }
            $nick = ($upn -split '@')[0]
            $pw   = ([guid]::NewGuid().ToString('N').Substring(0,12)) + '!Aa9'
            $u = Invoke-PimGraph -Method POST -Path '/users' -Body @{
                accountEnabled=$true; displayName=$disp; mailNickname=$nick; userPrincipalName=$upn
                passwordProfile=@{ forceChangePasswordNextSignIn=$true; password=$pw }
            }
            if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind User -Object $u }   # incremental cache
            # new-admin notification (best-effort) -> the admin's manager
            if (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue) {
                $mgr = Get-PimRowProp -Row $item.desired -Names @('ManagerEmail')
                $toks = @{ UserPrincipalName=$upn; DisplayName=$disp; Date=([datetime]::UtcNow.ToString('yyyy-MM-dd'))
                    TierLevel=(Get-PimRowProp -Row $item.desired -Names @('TargetUsage','Purpose')); Company=(Get-PimRowProp -Row $item.desired -Names @('Company')); ManagerEmail=$mgr }
                try { Send-PimNotifyMail -Type 'new-admin' -Tokens $toks -Recipient $mgr | Out-Null } catch { Write-Verbose "new-admin mail ($upn): $($_.Exception.Message)" }
            }
            $u
        }
        ApplyUpdate = {
            param($item,$ctx)
            # exists but disabled -> enable
            Invoke-PimGraph -Method PATCH -Path "/users/$($item.live.id)" -Body @{ accountEnabled=$true }
        }
        ApplyRemove = {
            param($item,$ctx)
            # Full reconcile: disable (never delete) an admin account not in desired.
            # DEFENSE-IN-DEPTH: the orchestrator already runs the disable circuit breaker
            # (feature opt-in + resolved-desired + blast-radius cap) before this is ever
            # called. This final per-account opt-in check makes a direct call to this
            # handler still safe: with the feature OFF, no account is ever disabled.
            if ((Get-Command Test-PimAccountDisableEnabled -ErrorAction SilentlyContinue) -and -not (Test-PimAccountDisableEnabled)) {
                Write-Host ("    [skip] {0}: account-disable is OFF (opt-in required) -- not disabling" -f $item.key) -ForegroundColor Yellow
                return
            }
            Invoke-PimGraph -Method PATCH -Path "/users/$($item.live.id)" -Body @{ accountEnabled=$false }
        }
    }
}

# ---------------------------------------------------------------------------
# EntraRoles scope -- PIM enablement/delegation of Entra DIRECTORY ROLES to the
# role-assignable PIM groups. Desired = PIM-Assignments-Roles-Groups (GroupTag +
# RoleDefinitionName + Eligible/Active + Permanent/expiry). Live + apply via the
# Graph PIM REST (roleEligibilityScheduleRequests / roleAssignmentScheduleRequests).
# ---------------------------------------------------------------------------

function New-PimRoleScheduleBody {
    # PURE: build the Graph PIM schedule-request body. Permanent (or Days<=0) ->
    # noExpiration; else afterDuration P{Days}D.
    param(
        [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$RoleDefId,
        [switch]$Permanent, [int]$Days = 0, [string]$Action = 'adminAssign',
        [string]$Justification = 'PIM4EntraPS engine', [string]$StartUtc, [string]$DirectoryScopeId = '/'
    )
    $sched = @{ expiration = $(if ($Permanent -or $Days -le 0) { @{ type = 'noExpiration' } } else { @{ type = 'afterDuration'; duration = "P$Days" + 'D' } }) }
    if ($StartUtc) { $sched.startDateTime = $StartUtc }
    return @{ action=$Action; justification=$Justification; roleDefinitionId=$RoleDefId; principalId=$PrincipalId; directoryScopeId=$DirectoryScopeId; scheduleInfo=$sched }
}

function Get-PimEntraRoleKey {
    # PURE: uniform key for desired + live rows -> "<groupTag>|<roleName>|<type>".
    param([object]$Row)
    $tag  = Get-PimRowProp -Row $Row -Names @('GroupTag')
    $role = Get-PimRowProp -Row $Row -Names @('RoleDefinitionName','RoleName')
    $type = Get-PimRowProp -Row $Row -Names @('AssignmentType')
    return ("$tag|$role|$type").ToLowerInvariant()
}

function New-PimEntraRolesProvider {
    @{
        scope  = 'EntraRoles'
        entity = 'PIM-Assignments-Roles-Groups'
        order  = 40
        refreshBefore = $true
        GetDesired = {
            param($ctx)
            @(Get-PimDesiredRows -Entity 'PIM-Assignments-Roles-Groups' | Where-Object { (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' })
        }
        GetLive = {
            param($ctx)
            if (-not $Global:PimContextBuiltAt) { try { Build-PimContext | Out-Null } catch {} }
            $groupsByName = @{}; foreach ($g in @($Global:Groups_All_ID)) { $n = "$($g.DisplayName)"; if ($n) { $groupsByName[$n.ToLowerInvariant()] = "$($g.Id)" } }
            $rolesByName  = @{}; foreach ($r in @($Global:Roles_All_ID))  { $n = "$($r.DisplayName)"; if ($n) { $rolesByName[$n.ToLowerInvariant()]  = "$($r.Id)" } }
            # GroupTag -> GroupName across ALL definition entities (role-assignment tags
            # live in Services/Organization/Tasks too, not just Roles) -> groupId.
            $tagToName = Get-PimTagToGroupName
            $ctx['tagToGroupId'] = @{}; $ctx['roleNameToId'] = $rolesByName
            $desired = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Roles-Groups')
            $tags = @($desired | ForEach-Object { Get-PimRowProp -Row $_ -Names @('GroupTag') } | Where-Object { $_ } | Select-Object -Unique)
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($tag in $tags) {
                $nm = $tagToName[$tag.ToLowerInvariant()]; if (-not $nm) { continue }
                $gid = $groupsByName[$nm.ToLowerInvariant()]; if (-not $gid) { continue }
                $ctx['tagToGroupId'][$tag.ToLowerInvariant()] = $gid
                foreach ($s in (Get-PimLiveDirRoleSchedules -PrincipalId $gid)) {
                    if ("$($s.directoryScopeId)" -ne '/') { continue }   # EntraRoles = tenant-scope only (AU-scoped handled by RolesAUs)
                    $live.Add([pscustomobject]@{ GroupTag=$tag; RoleDefinitionName=$s.RoleDefinitionName; AssignmentType=$s.AssignmentType; principalId=$gid; roleDefinitionId=$s.roleDefinitionId })
                }
            }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimEntraRoleKey -Row $r }
        Equal = { param($d,$l) $true }   # existence-based (group already holds the role at the right tier)
        ApplyCreate = {
            param($item,$ctx)
            $d = $item.desired
            $tag = (Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant()
            $gid = $ctx['tagToGroupId'][$tag]
            $rn  = Get-PimRowProp -Row $d -Names @('RoleDefinitionName','RoleName')
            $rid = $ctx['roleNameToId'][$rn.ToLowerInvariant()]
            if (-not $gid -or -not $rid) { throw "EntraRoles: unresolved group/role ($tag / $rn)" }
            $type = Get-PimRowProp -Row $d -Names @('AssignmentType')
            $perm = (Get-PimRowProp -Row $d -Names @('Permanent')) -match '(?i)true'
            $days = [int]("0" + (Get-PimRowProp -Row $d -Names @('NumOfDaysWhenExpire')))
            $body = New-PimRoleScheduleBody -PrincipalId $gid -RoleDefId $rid -Permanent:$perm -Days $days -Action 'adminAssign' -StartUtc ((Get-Date).ToUniversalTime().ToString('o'))
            $ep = if ($type -eq 'Active') { 'roleAssignmentScheduleRequests' } else { 'roleEligibilityScheduleRequests' }
            Invoke-PimScheduleCreate -Path "/roleManagement/directory/$ep" -Body $body
        }
        ApplyRemove = {
            param($item,$ctx)
            $l = $item.live
            $type = "$($l.AssignmentType)"
            $body = New-PimRoleScheduleBody -PrincipalId "$($l.principalId)" -RoleDefId "$($l.roleDefinitionId)" -Action 'adminRemove'
            $ep = if ($type -eq 'Active') { 'roleAssignmentScheduleRequests' } else { 'roleEligibilityScheduleRequests' }
            Invoke-PimGraph -Method POST -Path "/roleManagement/directory/$ep" -Body $body
        }
    }
}

# ===========================================================================
# Shared resolvers (REST + SQL). Ported from PIM-Functions.psm1 (the most-updated
# CSV-engine logic) but module-free: all directory reads go through Build-PimContext
# ($Global:Groups_All_ID / Users_All_ID / AU_All_ID, filled via Invoke-PimGraph).
# ===========================================================================

function Get-PimMailNickname {
    # mailNickname allows no spaces/specials and is <=64. Legacy used the display name
    # verbatim (PIM names are already hyphen-cased); we sanitise defensively.
    param([string]$Name)
    $n = ($Name -replace '[^A-Za-z0-9._-]', '')
    if ($n.Length -gt 64) { $n = $n.Substring(0, 64) }
    if (-not $n) { $n = 'g' + ([guid]::NewGuid().ToString('N').Substring(0, 8)) }
    return $n
}

function Ensure-PimContextLoaded {
    if (-not $Global:PimContextBuiltAt -and (Get-Command Build-PimContext -ErrorAction SilentlyContinue)) {
        try { Build-PimContext | Out-Null } catch { Write-Warning "  [engine] Build-PimContext failed: $($_.Exception.Message)" }
    }
}

function Get-PimGroupDefinitionRows {
    # Every entity that DEFINES a group becomes one create candidate. All share the
    # GroupName/GroupTag/GroupDescription/IsRoleAssignable/AdministrativeUnitTag columns.
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($e in @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization', 'PIM-Definitions-Tasks')) {
        foreach ($r in @(Get-PimDesiredRows -Entity $e)) {
            $gn = Get-PimRowProp -Row $r -Names @('GroupName'); if (-not $gn) { continue }
            $list.Add([pscustomobject]@{
                GroupName             = $gn
                GroupTag              = (Get-PimRowProp -Row $r -Names @('GroupTag'))
                GroupDescription      = (Get-PimRowProp -Row $r -Names @('GroupDescription'))
                IsRoleAssignable      = (Get-PimRowProp -Row $r -Names @('IsRoleAssignable'))
                AdministrativeUnitTag = (Get-PimRowProp -Row $r -Names @('AdministrativeUnitTag'))
                Owners                = (Get-PimRowProp -Row $r -Names @('Owners'))
                SponsorUpn            = (Get-PimRowProp -Row $r -Names @('SponsorUpn'))
                Department            = (Get-PimRowProp -Row $r -Names @('Department','DepartmentTag'))
                PolicyTemplate        = (Get-PimRowProp -Row $r -Names @('PolicyTemplate'))
                ReviewCycle           = (Get-PimRowProp -Row $r -Names @('ReviewCycle'))
                SourceEntity          = $e
            })
        }
    }
    $list.ToArray()
}

function Get-PimTagToGroupName {
    $h = @{}; foreach ($d in (Get-PimGroupDefinitionRows)) { $t = "$($d.GroupTag)"; if ($t) { $h[$t.ToLowerInvariant()] = $d.GroupName } }; $h
}
function Get-PimTagToAuName {
    $h = @{}; foreach ($r in @(Get-PimDesiredRows -Entity 'PIM-Definitions-AU')) {
        $t = Get-PimRowProp -Row $r -Names @('AdministrativeUnitTag'); $n = Get-PimRowProp -Row $r -Names @('AUDisplayName')
        if ($t) { $h[$t.ToLowerInvariant()] = $n }
    }; $h
}

function Resolve-PimLiveGroupIdByName {
    # Cache first (lean context holds only PIM-prefixed groups + engine-created ones); on a
    # miss, resolve ON-DEMAND by displayName (a 150k-group tenant is never bulk-listed) + cache.
    param([string]$Name)
    if (-not $Name) { return $null }
    $g = @($Global:Groups_All_ID) | Where-Object { "$($_.DisplayName)" -eq "$Name" } | Select-Object -First 1
    if ($g) { return "$($g.Id)" }
    try {
        $esc = $Name -replace "'", "''"
        $r = @(Invoke-PimGraph -Headers @{ ConsistencyLevel = 'eventual' } -All -Path "/groups?`$filter=displayName eq '$esc'&`$count=true&`$select=id,displayName,securityEnabled,mailNickname")
        if ($r.Count) { if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind Group -Object $r[0] }; return "$($r[0].id)" }
    } catch { Write-Verbose "group resolve ($Name): $($_.Exception.Message)" }
    return $null
}
function Resolve-PimPrincipalId {
    # Cache first; on a miss resolve ON-DEMAND by UPN (a 500k-user tenant is never bulk-listed)
    # + cache. GUIDs pass through. /users/{upn} returns a single object (not .value).
    param([string]$UpnOrId)
    if (-not $UpnOrId) { return $null }
    if ($UpnOrId -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return "$UpnOrId" }
    $u = @($Global:Users_All_ID) | Where-Object { "$($_.UserPrincipalName)" -eq "$UpnOrId" } | Select-Object -First 1
    if ($u) { return "$($u.Id)" }
    try {
        $r = Invoke-PimGraph -Path "/users/$([uri]::EscapeDataString($UpnOrId))?`$select=id,userPrincipalName"
        if ($r.id) { if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind User -Object $r }; return "$($r.id)" }
    } catch { Write-Verbose "user resolve ($UpnOrId): $($_.Exception.Message)" }
    return $null
}

function Get-PimDepartmentOwnerIndex {
    # Department -> owner UPN list, from PIM-Definitions-Departments (Department + Owners),
    # so a group can inherit owners from its department when its own Owners column is blank.
    # Cached per run. Empty if the Departments table isn't present.
    if ($script:__pimDeptOwners) { return $script:__pimDeptOwners }
    $h = @{}
    foreach ($r in @(Get-PimDesiredRows -Entity 'PIM-Definitions-Departments')) {
        $dept = Get-PimRowProp -Row $r -Names @('Department', 'DepartmentName', 'Name')
        $own  = Get-PimRowProp -Row $r -Names @('Owners', 'DeptOwner', 'DepartmentOwner', 'ManagerEmail')
        if ($dept) { $h[$dept.ToLowerInvariant()] = $own }
    }
    $script:__pimDeptOwners = $h; return $h
}

function Split-PimOwners {
    # Owners are pipe-joined UPNs per the Manager UX; also accept ; and , for safety.
    param([string]$Raw)
    @("$Raw" -split '[|;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Resolve-PimGroupOwnerIds {
    # Owner object-ids for a group definition row: Owners column -> SponsorUpn (Roles) ->
    # the group's Department contact (PIM-Definitions-Departments). UPN -> id; unresolved
    # owners are dropped. Returns @() when nothing resolves (caller enforces the rule).
    param([object]$Row, [hashtable]$Ctx = @{})
    $upns = @()
    $upns += Split-PimOwners (Get-PimRowProp -Row $Row -Names @('Owners'))
    if (-not $upns.Count) { $upns += Split-PimOwners (Get-PimRowProp -Row $Row -Names @('SponsorUpn')) }
    if (-not $upns.Count) {
        $dept = Get-PimRowProp -Row $Row -Names @('Department', 'DepartmentTag')
        if ($dept) { $di = Get-PimDepartmentOwnerIndex; if ($di.ContainsKey($dept.ToLowerInvariant())) { $upns += Split-PimOwners $di[$dept.ToLowerInvariant()] } }
    }
    $ids = New-Object System.Collections.Generic.List[object]
    foreach ($u in ($upns | Select-Object -Unique)) { $id = Resolve-PimPrincipalId $u; if ($id) { [void]$ids.Add($id) } }
    , $ids.ToArray()
}

function New-PimGroupMembershipBody {
    # PURE: PIM-for-Groups schedule-request body (accessId member/owner). Matches the
    # legacy Assign-User-PIM-PAG-Group shape; afterDuration instead of afterDateTime.
    param(
        [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$GroupId,
        [string]$AccessId = 'member', [switch]$Permanent, [int]$Days = 0,
        [string]$Action = 'adminAssign', [string]$Justification = 'PIM4EntraPS engine'
    )
    $exp = if ($Permanent -or $Days -le 0) { @{ type = 'noExpiration' } } else { @{ type = 'afterDuration'; duration = "P$Days" + 'D' } }
    @{ accessId = $AccessId; groupId = $GroupId; action = $Action; justification = $Justification; principalId = $PrincipalId
       scheduleInfo = @{ startDateTime = ([datetime]::UtcNow.ToString('o')); expiration = $exp } }
}

function Invoke-PimScheduleCreate {
    # POST a PIM schedule-request body, with a DURATION-LADDER fallback: PIM policies cap the
    # max eligible/active duration, and a request longer than the cap returns
    # RoleAssignmentRequestPolicyValidationFailed (ExpirationRule). On that specific error we
    # retry with progressively shorter afterDuration, then noExpiration -- so a data duration
    # that exceeds the tenant policy still lands at the policy max instead of failing.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Body)
    $sched = if ($Body.scheduleInfo) { $Body.scheduleInfo } elseif ($Body.properties) { $Body.properties.scheduleInfo } else { $null }
    try { return Invoke-PimGraph -Method POST -Path $Path -Body $Body }
    catch { if ("$($_.Exception.Message)" -notmatch '(?i)greater than maximum allowed duration|ExpirationRule') { throw } }
    foreach ($d in @(180, 90, 30, 0)) {
        if ($sched) { $sched.expiration = if ($d -le 0) { @{ type = 'noExpiration' } } else { @{ type = 'afterDuration'; duration = "P$d" + 'D' } } }
        try { return Invoke-PimGraph -Method POST -Path $Path -Body $Body }
        catch { if ("$($_.Exception.Message)" -notmatch '(?i)greater than maximum allowed duration|ExpirationRule') { throw } }
    }
    throw "schedule create still rejected after duration ladder ($Path)"
}

function Get-PimGroupSchedulePreload {
    # TENANT-WIDE preload of ALL PIM-for-Groups eligibility + assignment schedules, indexed
    # by groupId -- ported from Get-PimGroupSchedulesPreloaded (the func lib). One bulk read
    # (paged) instead of a per-group `$filter=groupId eq ...` round-trip. Cached 5 min.
    param([switch]$Force)
    if (-not $Force -and $script:PimGrpSchedAt -and ((Get-Date) - $script:PimGrpSchedAt).TotalMinutes -lt 5) { return }
    $elig = @{}; $act = @{}
    foreach ($pair in @(@{ ep = 'eligibilitySchedules'; idx = $elig }, @{ ep = 'assignmentSchedules'; idx = $act })) {
        try {
            foreach ($s in @(Invoke-PimGraph -Path "/identityGovernance/privilegedAccess/group/$($pair.ep)" -All)) {
                $gid = "$($s.groupId)"; if (-not $gid) { continue }
                if (-not $pair.idx.ContainsKey($gid)) { $pair.idx[$gid] = New-Object System.Collections.ArrayList }
                [void]$pair.idx[$gid].Add($s)
            }
        } catch { Write-Warning "  [perf] group $($pair.ep) preload failed: $($_.Exception.Message)" }
    }
    $script:PimGrpElig = $elig; $script:PimGrpAct = $act; $script:PimGrpSchedAt = Get-Date
    $ec = 0; foreach ($v in $elig.Values) { $ec += $v.Count }; $ac = 0; foreach ($v in $act.Values) { $ac += $v.Count }
    Write-Host ("  [perf] group schedules preloaded: $ec eligible + $ac active (tenant-wide)") -ForegroundColor DarkGray
}
function Get-PimLiveGroupMembership {
    # Eligible + Active PIM-for-Groups schedules for one group. NB: the group schedule list
    # endpoints REQUIRE a groupId/principalId filter (an unfiltered tenant-wide list now 400s
    # MissingParameters), so this is a per-group filtered query -- there is no valid bulk
    # preload for PIM-for-Groups (unlike directory roles). Cached per group per run.
    param([Parameter(Mandatory)][string]$GroupId, [string]$GroupTag)
    if (-not $script:PimGrpMemCache) { $script:PimGrpMemCache = @{} }
    if ($script:PimGrpMemCache.ContainsKey($GroupId)) {
        return @($script:PimGrpMemCache[$GroupId] | ForEach-Object { [pscustomobject]@{ principalId = $_.principalId; accessId = $_.accessId; GroupTag = $GroupTag; AssignmentType = $_.AssignmentType } })
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($pair in @(@{ ep = 'eligibilitySchedules'; type = 'Eligible' }, @{ ep = 'assignmentSchedules'; type = 'Active' })) {
        try {
            foreach ($s in @(Invoke-PimGraph -All -Path "/identityGovernance/privilegedAccess/group/$($pair.ep)?`$filter=groupId eq '$GroupId'")) {
                $out.Add([pscustomobject]@{ principalId = "$($s.principalId)"; accessId = "$($s.accessId)"; GroupTag = $GroupTag; AssignmentType = $pair.type })
            }
        } catch { Write-Verbose "group membership ($GroupTag/$($pair.type)): $($_.Exception.Message)" }
    }
    $arr = $out.ToArray(); $script:PimGrpMemCache[$GroupId] = $arr; $arr
}

function Get-PimDirRoleSchedulePreload {
    # TENANT-WIDE preload of ALL directory roleEligibility + roleAssignment schedules,
    # indexed by principalId (the PIM group). One bulk read instead of per-group filters.
    param([switch]$Force)
    if (-not $Force -and $script:PimDirSchedAt -and ((Get-Date) - $script:PimDirSchedAt).TotalMinutes -lt 5) { return }
    $elig = @{}; $act = @{}
    foreach ($pair in @(@{ ep = 'roleEligibilitySchedules'; idx = $elig }, @{ ep = 'roleAssignmentSchedules'; idx = $act })) {
        try {
            foreach ($s in @(Invoke-PimGraph -Path "/roleManagement/directory/$($pair.ep)?`$expand=roleDefinition" -All)) {
                $pp = "$($s.principalId)"; if (-not $pp) { continue }
                if (-not $pair.idx.ContainsKey($pp)) { $pair.idx[$pp] = New-Object System.Collections.ArrayList }
                [void]$pair.idx[$pp].Add($s)
            }
        } catch { Write-Warning "  [perf] dir $($pair.ep) preload failed: $($_.Exception.Message)" }
    }
    $script:PimDirElig = $elig; $script:PimDirAct = $act; $script:PimDirSchedAt = Get-Date
    $ec = 0; foreach ($v in $elig.Values) { $ec += $v.Count }; $ac = 0; foreach ($v in $act.Values) { $ac += $v.Count }
    Write-Host ("  [perf] directory role schedules preloaded: $ec eligible + $ac active (tenant-wide)") -ForegroundColor DarkGray
}
function Get-PimLiveDirRoleSchedules {
    # Directory role schedules for one principal (group) from the preload -> uniform rows.
    param([Parameter(Mandatory)][string]$PrincipalId)
    Get-PimDirRoleSchedulePreload
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($pair in @(@{ idx = $script:PimDirElig; type = 'Eligible' }, @{ idx = $script:PimDirAct; type = 'Active' })) {
        if ($pair.idx -and $pair.idx.ContainsKey($PrincipalId)) {
            foreach ($s in $pair.idx[$PrincipalId]) { $out.Add([pscustomobject]@{ principalId = $PrincipalId; RoleDefinitionName = "$($s.roleDefinition.displayName)"; AssignmentType = $pair.type; roleDefinitionId = "$($s.roleDefinitionId)"; directoryScopeId = "$($s.directoryScopeId)" }) }
        }
    }
    $out.ToArray()
}

# ---------------------------------------------------------------------------
# AdministrativeUnits scope -- create the AUs (PIM-Definitions-AU) groups attach to.
# ---------------------------------------------------------------------------
function New-PimAdministrativeUnitsProvider {
    @{
        scope = 'AdministrativeUnits'; entity = 'PIM-Definitions-AU'; order = 10
        GetDesired = { param($ctx) @(Get-PimDesiredRows -Entity 'PIM-Definitions-AU' | Where-Object { Get-PimRowProp -Row $_ -Names @('AUDisplayName') }) }
        GetLive    = { param($ctx) Ensure-PimContextLoaded; @($Global:AU_All_ID) }
        KeyOf = { param($r) Get-PimRowProp -Row $r -Names @('AUDisplayName', 'DisplayName', 'displayName') }
        Equal = { param($d, $l) $true }   # existence-based
        ApplyCreate = {
            param($item, $ctx)
            $d = $item.desired
            $vis = Get-PimRowProp -Row $d -Names @('Visibility'); if (-not $vis) { $vis = 'Public' }
            $au = Invoke-PimGraph -Method POST -Path '/directory/administrativeUnits' -Body @{
                displayName = "$($item.key)"; description = (Get-PimRowProp -Row $d -Names @('AUDescription')); visibility = $vis
            }
            if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind AU -Object $au }   # incremental cache
            $au
        }
    }
}

# ---------------------------------------------------------------------------
# Groups scope -- create the delegation groups from ALL definition entities
# (Roles/Services/Organization/Tasks). isAssignableToRole from IsRoleAssignable;
# attach to its AU; add owners. Ported from Create-PIM-Group-Role / CreateUpdate-PIM-Group.
# ---------------------------------------------------------------------------
function New-PimGroupsProvider {
    @{
        scope = 'Groups'; entity = 'PIM-Definitions'; order = 20
        GetDesired = { param($ctx) $ctx['tagToAuName'] = Get-PimTagToAuName; @(Get-PimGroupDefinitionRows) }
        GetLive    = { param($ctx) Ensure-PimContextLoaded; @($Global:Groups_All_ID) }
        KeyOf = { param($r) Get-PimRowProp -Row $r -Names @('GroupName', 'DisplayName', 'displayName') }
        Equal = { param($d, $l) $true }   # existence-based (create if absent)
        ApplyCreate = {
            param($item, $ctx)
            $d = $item.desired
            $gn = "$($item.key)"
            $assignable = (Get-PimRowProp -Row $d -Names @('IsRoleAssignable')) -match '(?i)true'
            $body = @{
                displayName = $gn; mailNickname = (Get-PimMailNickname $gn)
                securityEnabled = $true; mailEnabled = $false; groupTypes = @()
                isAssignableToRole = $assignable
            }
            # Graph requires description 1-1024 chars when present -> only send if non-empty.
            $desc = Get-PimRowProp -Row $d -Names @('GroupDescription')
            if ("$desc".Trim()) { $body['description'] = $desc }
            # OWNERS: a group must never be created without an owner. Owners come from the
            # definition's Owners column (pipe-joined UPNs per the Manager UX; also accept
            # ; or ,), Roles use SponsorUpn, falling back to the group's Department contact
            # (PIM-Definitions-Departments: Department -> Owners). Resolve BEFORE create and
            # refuse (throw) if none resolve -- surfaces the data gap instead of creating an
            # orphaned, ownerless group. Opt out only via $global:PIM_RequireGroupOwners=$false.
            $ownerIds = Resolve-PimGroupOwnerIds -Row $d -Ctx $ctx
            $require = $true; if ($null -ne $global:PIM_RequireGroupOwners) { $require = [bool]$global:PIM_RequireGroupOwners }
            if ($require -and -not $ownerIds.Count) {
                throw "no owner resolves for group '$gn' (set Owners/SponsorUpn on the definition, or a Department contact)"
            }
            $g = Invoke-PimGraph -Method POST -Path '/groups' -Body $body
            if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind Group -Object $g }   # incremental cache
            # attach to its AU (best-effort)
            $auTag = Get-PimRowProp -Row $d -Names @('AdministrativeUnitTag')
            if ($auTag -and $g.id) {
                $auName = $ctx['tagToAuName'][$auTag.ToLowerInvariant()]
                $au = @($Global:AU_All_ID) | Where-Object { "$($_.DisplayName)" -eq "$auName" } | Select-Object -First 1
                if ($au) {
                    try { Invoke-PimGraph -Method POST -Path "/directory/administrativeUnits/$($au.Id)/members/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/groups/$($g.id)" } | Out-Null }
                    catch { Write-Verbose "AU attach ($gn -> $auName): $($_.Exception.Message)" }
                }
            }
            # owners are enforced above (refuse ownerless) but ATTACHED by the GroupOwners
            # scope (order 25) -- a separate, re-runnable pass that tolerates replication of
            # the just-created group and repairs missing owners on existing groups.
            $g
        }
    }
}

# ---------------------------------------------------------------------------
# AdminMembers scope -- admins (PIM-Assignments-Admins) become Eligible/Active
# members of their PIM group (PIM-for-Groups). This is "admins get access to the
# org groups". Ported from Assign-User-PIM-PAG-Group / Assign-Groups-Accounts.
# ---------------------------------------------------------------------------
function New-PimAdminMembersProvider {
    @{
        scope = 'AdminMembers'; entity = 'PIM-Assignments-Admins'; order = 50; refreshBefore = $true
        GetDesired = { param($ctx) @(Get-PimDesiredRows -Entity 'PIM-Assignments-Admins' | Where-Object { (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' }) }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = Get-PimTagToGroupName; $ctx['admTagToGid'] = @{}
            $desired = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Admins')
            $tags = @($desired | ForEach-Object { Get-PimRowProp -Row $_ -Names @('GroupTag') } | Where-Object { $_ } | Select-Object -Unique)
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($tag in $tags) {
                $nm = $tagToName[$tag.ToLowerInvariant()]; if (-not $nm) { continue }
                $gid = Resolve-PimLiveGroupIdByName $nm; if (-not $gid) { continue }
                $ctx['admTagToGid'][$tag.ToLowerInvariant()] = $gid
                foreach ($m in (Get-PimLiveGroupMembership -GroupId $gid -GroupTag $tag)) { $live.Add($m) }
            }
            $live.ToArray()
        }
        KeyOf = {
            param($r)
            $prinId = Get-PimRowProp -Row $r -Names @('principalId')
            if (-not $prinId) { $prinId = Resolve-PimPrincipalId (Get-PimRowProp -Row $r -Names @('Username')) }
            $tag = (Get-PimRowProp -Row $r -Names @('GroupTag')).ToLowerInvariant()
            $type = (Get-PimRowProp -Row $r -Names @('AssignmentType')).ToLowerInvariant()
            "$prinId|$tag|$type"
        }
        Equal = { param($d, $l) $true }
        ApplyCreate = {
            param($item, $ctx)
            $d = $item.desired
            $prinId = Resolve-PimPrincipalId (Get-PimRowProp -Row $d -Names @('Username'))
            $tag = (Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant()
            $gid = $ctx['admTagToGid'][$tag]
            if (-not $prinId -or -not $gid) { throw "AdminMembers: unresolved principal/group ($(Get-PimRowProp -Row $d -Names @('Username')) / $tag)" }
            $type = Get-PimRowProp -Row $d -Names @('AssignmentType')
            $perm = (Get-PimRowProp -Row $d -Names @('Permanent')) -match '(?i)true'
            $days = [int]("0" + (Get-PimRowProp -Row $d -Names @('NumOfDaysWhenExpire')))
            $body = New-PimGroupMembershipBody -PrincipalId $prinId -GroupId $gid -AccessId 'member' -Permanent:$perm -Days $days
            $ep = if ($type -eq 'Active') { 'assignmentScheduleRequests' } else { 'eligibilityScheduleRequests' }
            Invoke-PimScheduleCreate -Path "/identityGovernance/privilegedAccess/group/$ep" -Body $body
        }
    }
}

# ---------------------------------------------------------------------------
# GroupMembers scope -- nested PIM-for-Groups (PIM-Assignments-Groups): a SOURCE
# group becomes an Eligible/Active member of a TARGET group.
# ---------------------------------------------------------------------------
function New-PimGroupMembersProvider {
    @{
        scope = 'GroupMembers'; entity = 'PIM-Assignments-Groups'; order = 55; refreshBefore = $true
        GetDesired = { param($ctx) @(Get-PimDesiredRows -Entity 'PIM-Assignments-Groups' | Where-Object { (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' }) }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = Get-PimTagToGroupName; $ctx['grpTagToGid'] = @{}
            $desired = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Groups')
            $tags = @($desired | ForEach-Object { @((Get-PimRowProp -Row $_ -Names @('TargetGroupTag')), (Get-PimRowProp -Row $_ -Names @('SourceGroupTag'))) } | ForEach-Object { $_ } | Where-Object { $_ } | Select-Object -Unique)
            foreach ($tag in $tags) { $nm = $tagToName[$tag.ToLowerInvariant()]; if ($nm) { $gid = Resolve-PimLiveGroupIdByName $nm; if ($gid) { $ctx['grpTagToGid'][$tag.ToLowerInvariant()] = $gid } } }
            $live = New-Object System.Collections.Generic.List[object]
            $targetTags = @($desired | ForEach-Object { Get-PimRowProp -Row $_ -Names @('TargetGroupTag') } | Where-Object { $_ } | Select-Object -Unique)
            foreach ($tag in $targetTags) {
                $gid = $ctx['grpTagToGid'][$tag.ToLowerInvariant()]; if (-not $gid) { continue }
                foreach ($m in (Get-PimLiveGroupMembership -GroupId $gid -GroupTag $tag)) { $live.Add($m) }
            }
            $live.ToArray()
        }
        KeyOf = {
            param($r)
            # desired: SourceGroupTag joins TargetGroupTag; live: principalId in TargetGroup
            $tgt = (Get-PimRowProp -Row $r -Names @('TargetGroupTag', 'GroupTag')).ToLowerInvariant()
            $type = (Get-PimRowProp -Row $r -Names @('AssignmentType')).ToLowerInvariant()
            $src = Get-PimRowProp -Row $r -Names @('principalId')   # live row
            if (-not $src) { $src = "src:" + (Get-PimRowProp -Row $r -Names @('SourceGroupTag')).ToLowerInvariant() }
            "$src|$tgt|$type"
        }
        Equal = { param($d, $l) $true }
        ApplyCreate = {
            param($item, $ctx)
            $d = $item.desired
            $tgt = (Get-PimRowProp -Row $d -Names @('TargetGroupTag')).ToLowerInvariant()
            $srcTag = (Get-PimRowProp -Row $d -Names @('SourceGroupTag')).ToLowerInvariant()
            $gid = $ctx['grpTagToGid'][$tgt]; $sid = $ctx['grpTagToGid'][$srcTag]
            if (-not $gid -or -not $sid) { throw "GroupMembers: unresolved target/source ($tgt / $srcTag)" }
            $type = Get-PimRowProp -Row $d -Names @('AssignmentType')
            $perm = (Get-PimRowProp -Row $d -Names @('Permanent')) -match '(?i)true'
            $days = [int]("0" + (Get-PimRowProp -Row $d -Names @('NumOfDaysWhenExpire')))
            $body = New-PimGroupMembershipBody -PrincipalId $sid -GroupId $gid -AccessId 'member' -Permanent:$perm -Days $days
            $ep = if ($type -eq 'Active') { 'assignmentScheduleRequests' } else { 'eligibilityScheduleRequests' }
            Invoke-PimScheduleCreate -Path "/identityGovernance/privilegedAccess/group/$ep" -Body $body
        }
    }
}

# ---------------------------------------------------------------------------
# RolesAUs scope -- AU-SCOPED Entra directory roles to a PIM group
# (PIM-Assignments-Roles-AUs). Same PIM directory-role REST as EntraRoles but
# directoryScopeId = /administrativeUnits/<auId>. Ported from
# Assign-Roles-AdministrativeUnits-From-SQL.
# ---------------------------------------------------------------------------
function New-PimRolesAUsProvider {
    @{
        scope = 'RolesAUs'; entity = 'PIM-Assignments-Roles-AUs'; order = 45; refreshBefore = $true
        GetDesired = { param($ctx) @(Get-PimDesiredRows -Entity 'PIM-Assignments-Roles-AUs' | Where-Object { (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' }) }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = Get-PimTagToGroupName; $tagToAu = Get-PimTagToAuName
            $rolesByName = @{}; foreach ($r in @($Global:Roles_All_ID)) { $n = "$($r.DisplayName)"; if ($n) { $rolesByName[$n.ToLowerInvariant()] = "$($r.Id)" } }
            $auByName = @{}; foreach ($a in @($Global:AU_All_ID)) { $n = "$($a.DisplayName)"; if ($n) { $auByName[$n.ToLowerInvariant()] = "$($a.Id)" } }
            $ctx['rolesByName'] = $rolesByName; $ctx['auTagToId'] = @{}; $ctx['rauGid'] = @{}
            $desired = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Roles-AUs')
            $pairs = @{}   # gid -> $true (which groups to read live for)
            foreach ($d in $desired) {
                $gt = (Get-PimRowProp -Row $d -Names @('GroupTag')); $at = (Get-PimRowProp -Row $d -Names @('AdministrativeUnitTag'))
                if ($gt) { $gn = $tagToName[$gt.ToLowerInvariant()]; if ($gn) { $gid = Resolve-PimLiveGroupIdByName $gn; if ($gid) { $ctx['rauGid'][$gt.ToLowerInvariant()] = $gid; $pairs[$gid] = $true } } }
                if ($at) { $an = $tagToAu[$at.ToLowerInvariant()]; if ($an) { $aid = $auByName[$an.ToLowerInvariant()]; if ($aid) { $ctx['auTagToId'][$at.ToLowerInvariant()] = $aid } } }
            }
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($gid in $pairs.Keys) {
                foreach ($s in (Get-PimLiveDirRoleSchedules -PrincipalId $gid)) {
                    if ("$($s.directoryScopeId)" -notmatch '(?i)/administrativeUnits/') { continue }   # RolesAUs = AU-scoped only
                    $live.Add([pscustomobject]@{ principalId=$gid; RoleDefinitionName=$s.RoleDefinitionName; AssignmentType=$s.AssignmentType; directoryScopeId=$s.directoryScopeId })
                }
            }
            $live.ToArray()
        }
        KeyOf = {
            param($r)
            # desired: GroupTag + AdministrativeUnitTag + role + type ; live: principalId + scopeId + role + type
            $gid = Get-PimRowProp -Row $r -Names @('principalId')
            if ($gid) {
                $scope = Get-PimRowProp -Row $r -Names @('directoryScopeId'); $au = ($scope -split '/')[-1]
                $role = (Get-PimRowProp -Row $r -Names @('RoleDefinitionName')).ToLowerInvariant()
                $type = (Get-PimRowProp -Row $r -Names @('AssignmentType')).ToLowerInvariant()
                return "$gid|$au|$role|$type"
            }
            $gt=(Get-PimRowProp -Row $r -Names @('GroupTag')).ToLowerInvariant(); $at=(Get-PimRowProp -Row $r -Names @('AdministrativeUnitTag')).ToLowerInvariant()
            $role=(Get-PimRowProp -Row $r -Names @('RoleDefinitionName')).ToLowerInvariant(); $type=(Get-PimRowProp -Row $r -Names @('AssignmentType')).ToLowerInvariant()
            "tag:$gt|autag:$at|$role|$type"   # placeholder; resolved form differs, so unmatched desired => create
        }
        Equal = { param($d,$l) $true }
        ApplyCreate = {
            param($item,$ctx)
            $d = $item.desired
            $gt=(Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant(); $at=(Get-PimRowProp -Row $d -Names @('AdministrativeUnitTag')).ToLowerInvariant()
            $gid=$ctx['rauGid'][$gt]; $aid=$ctx['auTagToId'][$at]
            $rn=Get-PimRowProp -Row $d -Names @('RoleDefinitionName'); $rid=$ctx['rolesByName'][$rn.ToLowerInvariant()]
            if (-not $gid -or -not $aid -or -not $rid) { throw "RolesAUs: unresolved group/AU/role ($gt / $at / $rn)" }
            $type=Get-PimRowProp -Row $d -Names @('AssignmentType')
            $perm=(Get-PimRowProp -Row $d -Names @('Permanent')) -match '(?i)true'
            $days=[int]("0"+(Get-PimRowProp -Row $d -Names @('NumOfDaysWhenExpire')))
            $body=New-PimRoleScheduleBody -PrincipalId $gid -RoleDefId $rid -Permanent:$perm -Days $days -Action 'adminAssign' -StartUtc ((Get-Date).ToUniversalTime().ToString('o')) -DirectoryScopeId "/administrativeUnits/$aid"
            $ep = if ($type -eq 'Active') { 'roleAssignmentScheduleRequests' } else { 'roleEligibilityScheduleRequests' }
            Invoke-PimScheduleCreate -Path "/roleManagement/directory/$ep" -Body $body
        }
    }
}

# ---------------------------------------------------------------------------
# AzRes scope -- Azure RBAC PIM role assignment to a PIM group at an ARM scope
# (PIM-Assignments-Azure-Resources). ARM REST (management.azure.com), api 2020-10-01-preview.
# Ported from Assign-AzResources-Groups-From-SQL. NB: the engine SPN needs Owner /
# User Access Administrator on the target scope (an Azure RBAC grant, separate from Graph).
# ---------------------------------------------------------------------------
function Resolve-PimArmRoleId {
    # ARM role NAME -> role definition GUID at a scope (cached per scope+name).
    param([string]$Scope, [string]$RoleName, [hashtable]$Cache)
    $k = "$Scope|$($RoleName.ToLowerInvariant())"
    if ($Cache.ContainsKey($k)) { return $Cache[$k] }
    $id = $null
    try {
        $r = @(Invoke-PimArm -Path "$Scope/providers/Microsoft.Authorization/roleDefinitions?`$filter=roleName eq '$RoleName'" -ApiVersion '2022-04-01' -All)
        if ($r.Count) { $id = "$($r[0].name)" }
    } catch { Write-Verbose "ARM roledef ($RoleName @ $Scope): $($_.Exception.Message)" }
    $Cache[$k] = $id; return $id
}
function New-PimAzResProvider {
    @{
        scope = 'AzRes'; entity = 'PIM-Assignments-Azure-Resources'; order = 60; refreshBefore = $true
        GetDesired = { param($ctx) $ctx['armRoleCache'] = @{}; @(Get-PimDesiredRows -Entity 'PIM-Assignments-Azure-Resources' | Where-Object { (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' }) }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = Get-PimTagToGroupName; $ctx['azGid'] = @{}
            $desired = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Azure-Resources')
            foreach ($d in $desired) { $gt=(Get-PimRowProp -Row $d -Names @('GroupTag')); if ($gt) { $gn=$tagToName[$gt.ToLowerInvariant()]; if ($gn) { $gid=Resolve-PimLiveGroupIdByName $gn; if ($gid) { $ctx['azGid'][$gt.ToLowerInvariant()]=$gid } } } }
            $live = New-Object System.Collections.Generic.List[object]
            $seen = @{}
            foreach ($d in $desired) {
                $scope = Get-PimRowProp -Row $d -Names @('AzScope'); $gt=(Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant()
                $gid=$ctx['azGid'][$gt]; if (-not $scope -or -not $gid) { continue }
                foreach ($pair in @(@{ ep='roleAssignmentScheduleInstances'; type='Active' }, @{ ep='roleEligibilityScheduleInstances'; type='Eligible' })) {
                    $sk = "$scope|$gid|$($pair.ep)"; if ($seen.ContainsKey($sk)) { continue }; $seen[$sk]=$true
                    try {
                        foreach ($s in @(Invoke-PimArm -Path "$scope/providers/Microsoft.Authorization/$($pair.ep)?`$filter=principalId eq '$gid'" -ApiVersion '2020-10-01-preview' -All)) {
                            $rid = ($s.properties.roleDefinitionId -split '/')[-1]
                            $live.Add([pscustomobject]@{ principalId=$gid; AzScope=$scope; RoleId=$rid; AssignmentType=$pair.type })
                        }
                    } catch { Write-Verbose "AzRes live ($scope/$gid): $($_.Exception.Message)" }
                }
            }
            $live.ToArray()
        }
        KeyOf = {
            param($r)
            $gid = Get-PimRowProp -Row $r -Names @('principalId')
            $scope = Get-PimRowProp -Row $r -Names @('AzScope')
            $type = (Get-PimRowProp -Row $r -Names @('AssignmentType')).ToLowerInvariant()
            if ($gid) { return "$gid|$($scope.ToLowerInvariant())|rid:$((Get-PimRowProp -Row $r -Names @('RoleId')).ToLowerInvariant())|$type" }
            # desired: resolve later; key by tag+scope+rolename+type (won't match live rid form -> create)
            $gt=(Get-PimRowProp -Row $r -Names @('GroupTag')).ToLowerInvariant(); $perm=(Get-PimRowProp -Row $r -Names @('AzScopePermission')).ToLowerInvariant()
            "tag:$gt|$($scope.ToLowerInvariant())|perm:$perm|$type"
        }
        Equal = { param($d,$l) $true }
        ApplyCreate = {
            param($item,$ctx)
            $d=$item.desired
            $gt=(Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant(); $gid=$ctx['azGid'][$gt]
            $scope=Get-PimRowProp -Row $d -Names @('AzScope'); $perm=Get-PimRowProp -Row $d -Names @('AzScopePermission')
            if (-not $gid -or -not $scope -or -not $perm) { throw "AzRes: unresolved group/scope/role ($gt / $scope / $perm)" }
            $rid = Resolve-PimArmRoleId -Scope $scope -RoleName $perm -Cache $ctx['armRoleCache']
            if (-not $rid) { throw "AzRes: ARM role '$perm' not found at $scope" }
            $type=Get-PimRowProp -Row $d -Names @('AssignmentType')
            $permFlag=(Get-PimRowProp -Row $d -Names @('Permanent')) -match '(?i)true'
            $days=[int]("0"+(Get-PimRowProp -Row $d -Names @('NumOfDaysWhenExpire')))
            $start=[datetime]::UtcNow.ToString('o')
            $exp = if ($permFlag -or $days -le 0) { @{ type='noExpiration' } } else { @{ type='AfterDateTime'; endDateTime=([datetime]::UtcNow.AddDays($days).ToString('o')) } }
            $body=@{ properties=@{ principalId=$gid; roleDefinitionId="$scope/providers/Microsoft.Authorization/roleDefinitions/$rid"; requestType='AdminAssign'; justification='PIM4EntraPS engine'; scheduleInfo=@{ startDateTime=$start; expiration=$exp } } }
            $guid=[guid]::NewGuid().ToString()
            $ep = if ($type -eq 'Active') { 'roleAssignmentScheduleRequests' } else { 'roleEligibilityScheduleRequests' }
            Invoke-PimArm -Method PUT -Path "$scope/providers/Microsoft.Authorization/$ep/$guid" -ApiVersion '2020-10-01-preview' -Body $body
        }
    }
}

# ---------------------------------------------------------------------------
# GroupsPolicies scope -- PIM member-activation policy on a group, specifically the
# ACTIVATION-REQUIRES-APPROVAL rule (e.g. the GA delegation group must require
# approval). Driven by the definition's PolicyTemplate column: a value containing
# 'approval' marks the group as approval-required; approvers come from Owners.
# Ported from Set-PimGroupApprovalRule / CreateUpdate-Policies-PIM-Groups.
# ---------------------------------------------------------------------------
function Get-PimGroupMemberPolicyId {
    param([string]$GroupId)
    try { $a = @(Invoke-PimGraph -All -Path "/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '$GroupId' and scopeType eq 'Group' and roleDefinitionId eq 'member'"); if ($a.Count) { return "$($a[0].policyId)" } } catch { Write-Verbose "policyId ($GroupId): $($_.Exception.Message)" }
    return $null
}

# ---------------------------------------------------------------------------
# v1->v2 policy-rule parity: v1 PIM_Policy_Check_Update wrote FOUR rule families
# (Approval, Enablement, Expiration, Notification). v2 GroupsPolicies originally
# wrote only Approval + Enablement. These pure builders let a policy template also
# declare Expiration (max activation duration) and Notification recipients, kept as
# standalone functions so the rule-body shaping is unit-testable offline (no Graph).
# The PATCH plumbing is identical to the Approval/Enablement rule patches.
# ---------------------------------------------------------------------------
# Map the three v1 expiration targets to (rule id, caller, level). The group member
# policy carries exactly these three Expiration rules (v1 Custom-Policies.ps1 baseline).
$script:PimExpirationTargets = @(
    @{ Key='EndUser_Assignment';  Id='Expiration_EndUser_Assignment';  Caller='EndUser'; Level='Assignment'  }
    @{ Key='Admin_Assignment';    Id='Expiration_Admin_Assignment';    Caller='Admin';   Level='Assignment'  }
    @{ Key='Admin_Eligibility';   Id='Expiration_Admin_Eligibility';   Caller='Admin';   Level='Eligibility' }
)
function New-PimGroupExpirationRuleBody {
    # Build ONE unifiedRoleManagementPolicyExpirationRule for the given target.
    # $MaxDuration is an ISO-8601 duration (e.g. 'PT8H'/'P1D'/'P365D'); blank/absent -> $null (no rule).
    # Default target = EndUser/Assignment (member activation cap), so the legacy single-arg
    # call -MaxDuration 'PT8H' stays valid; pass -Caller/-Level (+ optional -Id) for the
    # Admin/Assignment and Admin/Eligibility rules that bring the policy to full v1 parity.
    param(
        [string]$MaxDuration,
        [ValidateSet('EndUser','Admin')][string]$Caller = 'EndUser',
        [ValidateSet('Assignment','Eligibility')][string]$Level = 'Assignment',
        [string]$Id,
        [bool]$IsExpirationRequired = $true
    )
    $dur = "$MaxDuration".Trim()
    if (-not $dur) { return $null }
    $rid = if ("$Id".Trim()) { "$Id".Trim() } else { "Expiration_${Caller}_${Level}" }
    @{
        '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'
        id            = $rid
        target        = @{ caller=$Caller; operations=@('all'); level=$Level; inheritableSettings=@(); enforcedSettings=@() }
        isExpirationRequired = $IsExpirationRequired
        maximumDuration      = $dur
    }
}
function ConvertTo-PimExpirationRuleBodies {
    # Normalise a template's "Expiration" value into the FULL v1 expiration rule set.
    #   - a plain string ('P1D')         -> just the EndUser/Assignment cap (legacy shape)
    #   - an object keyed by target name  -> one rule per declared target, e.g.
    #       { "EndUser_Assignment": { "maximumDuration":"P1D",  "isExpirationRequired":true },
    #         "Admin_Assignment":   { "maximumDuration":"P365D","isExpirationRequired":true },
    #         "Admin_Eligibility":  { "maximumDuration":"P365D","isExpirationRequired":true } }
    #     (each value may also be a bare duration string).
    # Returns an array of rule bodies (possibly empty).
    param($Expiration)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Expiration) { return $out.ToArray() }
    if ($Expiration -is [string]) {
        $b = New-PimGroupExpirationRuleBody -MaxDuration "$Expiration"
        if ($b) { $out.Add($b) }
        return $out.ToArray()
    }
    foreach ($t in $script:PimExpirationTargets) {
        $val = $null
        if ($Expiration.PSObject -and $Expiration.PSObject.Properties[$t.Key]) { $val = $Expiration.$($t.Key) }
        elseif ($Expiration -is [hashtable] -and $Expiration.ContainsKey($t.Key)) { $val = $Expiration[$t.Key] }
        if ($null -eq $val) { continue }
        $dur = $null; $req = $true
        if ($val -is [string]) { $dur = "$val" }
        else {
            if ($val.PSObject -and $val.PSObject.Properties['maximumDuration']) { $dur = "$($val.maximumDuration)" }
            elseif ($val -is [hashtable] -and $val.ContainsKey('maximumDuration')) { $dur = "$($val['maximumDuration'])" }
            if ($val.PSObject -and $val.PSObject.Properties['isExpirationRequired']) { $req = [bool]$val.isExpirationRequired }
            elseif ($val -is [hashtable] -and $val.ContainsKey('isExpirationRequired')) { $req = [bool]$val['isExpirationRequired'] }
        }
        $b = New-PimGroupExpirationRuleBody -MaxDuration $dur -Caller $t.Caller -Level $t.Level -Id $t.Id -IsExpirationRequired $req
        if ($b) { $out.Add($b) }
    }
    $out.ToArray()
}
# Map the v1 enablement targets to (rule id, caller, level). The group member policy
# carries MFA+Justification on EndUser/Assignment AND Admin/Eligibility, and NONE on
# Admin/Assignment (v1 Custom-Policies.ps1 baseline).
$script:PimEnablementTargets = @(
    @{ Key='EndUser_Assignment'; Id='Enablement_EndUser_Assignment'; Caller='EndUser'; Level='Assignment'  }
    @{ Key='Admin_Eligibility';  Id='Enablement_Admin_Eligibility';  Caller='Admin';   Level='Eligibility' }
    @{ Key='Admin_Assignment';   Id='Enablement_Admin_Assignment';   Caller='Admin';   Level='Assignment'  }
)
function New-PimGroupEnablementRuleBody {
    # Build ONE unifiedRoleManagementPolicyEnablementRule for the given target.
    # $EnabledRules = e.g. @('MultiFactorAuthentication','Justification') (empty = clear the rule).
    param(
        [string[]]$EnabledRules = @(),
        [ValidateSet('EndUser','Admin')][string]$Caller = 'EndUser',
        [ValidateSet('Assignment','Eligibility')][string]$Level = 'Assignment',
        [string]$Id
    )
    $rid = if ("$Id".Trim()) { "$Id".Trim() } else { "Enablement_${Caller}_${Level}" }
    @{
        '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule'
        id            = $rid
        target        = @{ caller=$Caller; operations=@('all'); level=$Level; inheritableSettings=@(); enforcedSettings=@() }
        enabledRules  = @($EnabledRules | Where-Object { $_ })
    }
}
function ConvertTo-PimEnablementRuleBodies {
    # Normalise a template's enablement declaration into the FULL v1 enablement rule set.
    # Accepts either the structured "Enablement" object:
    #   { "EndUser_Assignment": ["MultiFactorAuthentication","Justification"],
    #     "Admin_Eligibility":  ["MultiFactorAuthentication","Justification"],
    #     "Admin_Assignment":   [] }
    # OR the legacy single key value (Member_Enablement_EndUser_Assignment_enabledRules),
    # which maps to EndUser/Assignment only. Returns an array of rule bodies.
    param($Enablement, $LegacyEndUserAssignment)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Enablement) {
        foreach ($t in $script:PimEnablementTargets) {
            $val = $null; $present = $false
            if ($Enablement.PSObject -and $Enablement.PSObject.Properties[$t.Key]) { $val = $Enablement.$($t.Key); $present = $true }
            elseif ($Enablement -is [hashtable] -and $Enablement.ContainsKey($t.Key)) { $val = $Enablement[$t.Key]; $present = $true }
            if (-not $present) { continue }
            $out.Add((New-PimGroupEnablementRuleBody -EnabledRules @($val) -Caller $t.Caller -Level $t.Level -Id $t.Id))
        }
        return $out.ToArray()
    }
    if ($null -ne $LegacyEndUserAssignment) {
        $out.Add((New-PimGroupEnablementRuleBody -EnabledRules @($LegacyEndUserAssignment) -Caller 'EndUser' -Level 'Assignment'))
    }
    $out.ToArray()
}
function New-PimGroupNotificationRuleBody {
    # One notification rule (Graph requires one rule per recipient-type x event).
    # $RecipientType in Admin|Requestor|Approver; $Level in Eligibility|Assignment;
    # $NotificationLevel in All|Critical; $Recipients = extra email addresses.
    param(
        [Parameter(Mandatory)][ValidateSet('Admin','Requestor','Approver')][string]$RecipientType,
        [Parameter(Mandatory)][ValidateSet('Eligibility','Assignment')][string]$Level,
        [ValidateSet('All','Critical')][string]$NotificationLevel = 'All',
        [string[]]$Recipients = @(),
        [bool]$DefaultRecipientsEnabled = $true
    )
    $id = "Notification_${RecipientType}_EndUser_${Level}"
    @{
        '@odata.type'             = '#microsoft.graph.unifiedRoleManagementPolicyNotificationRule'
        id                        = $id
        target                    = @{ caller='EndUser'; operations=@('all'); level=$Level; inheritableSettings=@(); enforcedSettings=@() }
        notificationType          = 'Email'
        recipientType             = $RecipientType
        notificationLevel         = $NotificationLevel
        isDefaultRecipientsEnabled= $DefaultRecipientsEnabled
        notificationRecipients    = @($Recipients | Where-Object { $_ })
    }
}

# ---------------------------------------------------------------------------
# GroupsCreateModifyPolicy -- full idempotent compare for a group's PIM member
# policy. The provider PATCHes FOUR rule families (Approval, Expiration x3,
# Enablement x3, Notification per recipient-type x event). To be genuinely
# create/modify + idempotent (no redundant PATCH when already matching, modify
# only when drifted), the diff must read back + compare EVERY rule it writes --
# not just the EndUser/Assignment subset. These PURE builders normalise the
# desired template + the live policy into the SAME comparable shape, so a single
# string compare per rule decides in-sync vs drift. No Graph here -> unit-testable.
# (The Approval/Expiration/Enablement/Notification rule BODIES are the existing
# New-PimGroup*RuleBody / ConvertTo-Pim*RuleBodies builders -- reused verbatim.)
# ---------------------------------------------------------------------------
function ConvertTo-PimSortedList {
    # PURE: a deterministic, case-insensitive, comma-joined string for an unordered
    # string set (enabledRules, recipient lists) so order never causes a false drift.
    param([object]$Values)
    @(@($Values) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Sort-Object -Unique) -join ','
}
function Get-PimGroupPolicyDesiredFacets {
    # PURE: the comparable snapshot the engine WANTS for a group, derived from a desired
    # row (the object GetDesired emits: Approval/Expiration/Enablement/EnablementLegacy/
    # Notification + already-resolved ApproverIds). Returns a hashtable keyed by rule id;
    # each value is a normalised string. Only rules the provider would PATCH appear -- so a
    # facet absent from the template is absent here (the compare won't demand it live).
    param([Parameter(Mandatory)][object]$Desired)
    $f = @{}
    foreach ($b in @(ConvertTo-PimExpirationRuleBodies -Expiration $Desired.Expiration)) {
        $f[$b.id] = "exp|dur=$($b.maximumDuration)|req=$([bool]$b.isExpirationRequired)"
    }
    foreach ($b in @(ConvertTo-PimEnablementRuleBodies -Enablement $Desired.Enablement -LegacyEndUserAssignment $Desired.EnablementLegacy)) {
        $f[$b.id] = "en|rules=$(ConvertTo-PimSortedList $b.enabledRules)"
    }
    if ($Desired.Notification) {
        foreach ($n in @($Desired.Notification)) {
            $rt = "$($n.recipientType)"; $lvl = "$($n.level)"
            if (-not $rt -or -not $lvl) { continue }
            $recips = @(); if ($n.recipients) { $recips = @($n.recipients) }
            $nlvl = if ("$($n.notificationLevel)") { "$($n.notificationLevel)" } else { 'All' }
            $defOn = if ($n.PSObject -and $n.PSObject.Properties['defaultRecipientsEnabled']) { [bool]$n.defaultRecipientsEnabled } else { $true }
            $nb = New-PimGroupNotificationRuleBody -RecipientType $rt -Level $lvl -NotificationLevel $nlvl -Recipients $recips -DefaultRecipientsEnabled $defOn
            $f[$nb.id] = "notify|lvl=$($nb.notificationLevel)|def=$($nb.isDefaultRecipientsEnabled)|recips=$(ConvertTo-PimSortedList $nb.notificationRecipients)"
        }
    }
    if ($Desired.Approval) {
        # Approver identity set (already resolved upstream into ApproverIds) is part of the
        # facet so that adding/removing an owner is a detectable drift, not a silent nochange.
        $approverIds = ConvertTo-PimSortedList $Desired.ApproverIds
        $f['Approval_EndUser_Assignment'] = "appr|required=true|approvers=$approverIds"
    }
    $f
}
function Get-PimGroupPolicyLiveFacets {
    # PURE: the comparable snapshot a LIVE policy currently HAS, from its expanded rules
    # collection (the array under roleManagementPolicies/{id}?$expand=rules). Keyed by rule
    # id with the SAME normalised string shape as Get-PimGroupPolicyDesiredFacets, so the
    # two are directly comparable. A rule the policy doesn't carry simply isn't present.
    param([object[]]$Rules)
    $f = @{}
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        $id = "$($r.id)"; if (-not $id) { continue }
        $type = "$($r.'@odata.type')"
        if ($id -like 'Expiration_*' -or $type -like '*ExpirationRule') {
            $f[$id] = "exp|dur=$($r.maximumDuration)|req=$([bool]$r.isExpirationRequired)"
        }
        elseif ($id -like 'Enablement_*' -or $type -like '*EnablementRule') {
            $f[$id] = "en|rules=$(ConvertTo-PimSortedList $r.enabledRules)"
        }
        elseif ($id -like 'Notification_*' -or $type -like '*NotificationRule') {
            $f[$id] = "notify|lvl=$($r.notificationLevel)|def=$([bool]$r.isDefaultRecipientsEnabled)|recips=$(ConvertTo-PimSortedList $r.notificationRecipients)"
        }
        elseif ($id -eq 'Approval_EndUser_Assignment' -or $type -like '*ApprovalRule') {
            $required = $false; $approverIds = @()
            if ($r.setting) {
                $required = [bool]$r.setting.isApprovalRequired
                foreach ($st in @($r.setting.approvalStages)) {
                    foreach ($a in @($st.primaryApprovers)) { if ($a.userId) { $approverIds += "$($a.userId)" } }
                }
            }
            $f[$id] = "appr|required=$($required.ToString().ToLowerInvariant())|approvers=$(ConvertTo-PimSortedList $approverIds)"
        }
    }
    $f
}
function Test-PimGroupPolicyInSync {
    # PURE: is the live policy already at the desired baseline? In-sync iff EVERY desired
    # facet exists live AND its normalised value matches. Live MAY carry extra rules the
    # engine doesn't manage -- those never force an update (the engine only owns what its
    # template declares). Returns $true (nochange) / $false (needs a modify PATCH).
    param([Parameter(Mandatory)][hashtable]$Desired, [hashtable]$Live = @{})
    foreach ($k in $Desired.Keys) {
        if (-not $Live.ContainsKey($k)) { return $false }
        if ("$($Live[$k])" -ne "$($Desired[$k])") { return $false }
    }
    return $true
}

# Policy templates: templates/policy/*.policytemplate.json (+ *.policytemplate.custom.json,
# custom id wins), single-level 'extends' merged + a content Hash -- IDENTICAL semantics to
# Get-PimPolicyTemplates in PIM-Functions.psm1 (the established engine). A definition's
# PolicyTemplate column selects one; BLANK = 'default' (every group is linked).
# (PimEngineRoot = the PIM4EntraPS solution root.)
$script:PimEngineRoot = if ($PSScriptRoot) { (Resolve-Path "$PSScriptRoot\..\..").Path } else { $null }
function Get-PimEnginePolicyTemplates {
    $dir = if ($global:PIM_TemplateDir) { $global:PIM_TemplateDir } elseif ($script:PimEngineRoot) { Join-Path $script:PimEngineRoot 'templates\policy' } else { $null }
    $byId = @{}
    if ($dir -and (Test-Path -LiteralPath $dir)) {
        $files = @(Get-ChildItem -LiteralPath $dir -Filter '*.policytemplate.json' -EA SilentlyContinue) +
                 @(Get-ChildItem -LiteralPath $dir -Filter '*.policytemplate.custom.json' -EA SilentlyContinue)   # custom enumerates last -> same id wins
        foreach ($f in $files) {
            try { $j = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json; if ($j.id) { $byId["$($j.id)"] = $j } }
            catch { Write-Warning "  [policy] template '$($f.Name)' unreadable: $($_.Exception.Message)" }
        }
    }
    $out = @{}
    foreach ($id in @($byId.Keys)) {
        $j = $byId[$id]; $rules = @{}
        if ($j.extends -and $byId.ContainsKey("$($j.extends)")) { $base = $byId["$($j.extends)"]; if ($base.rules) { foreach ($p in $base.rules.PSObject.Properties) { $rules[$p.Name] = $p.Value } } }
        if ($j.rules) { foreach ($p in $j.rules.PSObject.Properties) { $rules[$p.Name] = $p.Value } }
        $out[$id] = [pscustomobject]@{ id = $id; rules = $rules }
    }
    $out
}
function Get-PimEnginePolicyTemplate {
    # Resolve ONE template id; BLANK -> 'default' (matches Get-PimDefinitionPolicyMap).
    param([string]$Id)
    $tid = if ("$Id".Trim()) { "$Id".Trim() } else { 'default' }
    $all = if ($script:__pimTplCache) { $script:__pimTplCache } else { $script:__pimTplCache = Get-PimEnginePolicyTemplates; $script:__pimTplCache }
    if ($all.ContainsKey($tid)) { return $all[$tid] }
    Write-Warning "  [policy] template '$tid' not found in templates/policy"; return $null
}

function New-PimGroupsPoliciesProvider {
    @{
        scope = 'GroupsPolicies'; entity = 'PIM-Definitions'; order = 70; refreshBefore = $true
        # DESIRED = EVERY managed group's member policy brought to the v1 baseline. The
        # baseline (Expiration + Enablement + Notification) is applied to ALL linked groups
        # (blank PolicyTemplate = 'default'); the Approval rule is applied ONLY when the
        # template declares one (e.g. 'approval-required'). The engine still never touches an
        # approval rule it did not itself apply (default-linked groups carry no Approval).
        GetDesired = {
            param($ctx)
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($g in (Get-PimGroupDefinitionRows)) {
                # blank PolicyTemplate -> 'default' (every managed group gets the baseline)
                $tplId = Get-PimRowProp -Row $g -Names @('PolicyTemplate')
                $tpl = Get-PimEnginePolicyTemplate -Id $tplId; if (-not $tpl) { continue }
                $hasApproval = $tpl.rules.ContainsKey('Approval')
                $expiration = if ($tpl.rules.ContainsKey('Expiration')) { $tpl.rules['Expiration'] } else { $null }
                $notify     = if ($tpl.rules.ContainsKey('Notification')) { $tpl.rules['Notification'] } else { $null }
                # Enablement: prefer the structured 'Enablement' object (per-target MFA/Justification);
                # fall back to the legacy single EndUser/Assignment key for back-compat.
                $enablement = if ($tpl.rules.ContainsKey('Enablement')) { $tpl.rules['Enablement'] } else { $null }
                $enLegacy   = if ($tpl.rules.ContainsKey('Member_Enablement_EndUser_Assignment_enabledRules')) { $tpl.rules['Member_Enablement_EndUser_Assignment_enabledRules'] } else { $null }
                # Approver IDs follow the SAME resolution as group ownership: Owners column ->
                # SponsorUpn -> the group's Department contact. A service group usually has a BLANK
                # Owners column and inherits its department's owners; an approval rule with ZERO
                # approvers is rejected by Graph ('InvalidPolicy'), so resolve through the full chain.
                $approverIds = if ($hasApproval) { @(Resolve-PimGroupOwnerIds -Row $g) } else { @() }
                $out.Add([pscustomobject]@{ GroupName=$g.GroupName; Owners=$g.Owners; ApproverIds=$approverIds; TemplateId=$tpl.id; Approval=$(if ($hasApproval) { $tpl.rules['Approval'] } else { $null }); Enablement=$enablement; EnablementLegacy=$enLegacy; Expiration=$expiration; Notification=$notify })
            }
            $out.ToArray()
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($g in (Get-PimGroupDefinitionRows)) {
                $tplId = Get-PimRowProp -Row $g -Names @('PolicyTemplate')
                $tpl = Get-PimEnginePolicyTemplate -Id $tplId; if (-not $tpl) { continue }
                $gid = Resolve-PimLiveGroupIdByName $g.GroupName; if (-not $gid) { continue }
                $polId = Get-PimGroupMemberPolicyId -GroupId $gid; if (-not $polId) { continue }
                # FULL read-back: the create/modify diff compares EVERY rule the provider
                # PATCHes (Approval + Expiration x3 + Enablement x3 + Notification), so the
                # live row carries the whole expanded rules collection (Get-PimGroupPolicyLiveFacets
                # normalises it in Equal). A group with no readable policy yet is simply absent
                # from live -> the diff classifies it as a create.
                $rules = @()
                try {
                    $pol = Invoke-PimGraph -Path "/policies/roleManagementPolicies/$polId`?`$expand=rules"
                    $rules = @($pol.rules)
                } catch { Write-Verbose "policy read ($($g.GroupName)): $($_.Exception.Message)" }
                $live.Add([pscustomobject]@{ GroupName=$g.GroupName; PolicyId=$polId; Rules=$rules })
            }
            $live.ToArray()
        }
        KeyOf = { param($r) (Get-PimRowProp -Row $r -Names @('GroupName')).ToLowerInvariant() }
        # nochange ONLY when the live policy already matches the desired baseline across
        # the WHOLE managed rule set: Approval (when the template asks for it, incl. the
        # approver identity set), all three Expiration caps, all three Enablement rules,
        # and every declared Notification rule. Anything drifted -> modify (a single
        # idempotent string compare per rule via the pure facet builders).
        Equal = {
            param($d,$l)
            $want = Get-PimGroupPolicyDesiredFacets -Desired $d
            $have = Get-PimGroupPolicyLiveFacets -Rules $l.Rules
            Test-PimGroupPolicyInSync -Desired $want -Live $have
        }
        ApplyCreate = { param($item,$ctx) & (Get-PimEngineProvider -Scope 'GroupsPolicies').ApplyUpdate $item $ctx }
        ApplyUpdate = {
            param($item,$ctx)
            $d=$item.desired; $gn=$d.GroupName
            $gid=Resolve-PimLiveGroupIdByName $gn; if (-not $gid) { throw "GroupsPolicies: group '$gn' not found" }
            $polId=Get-PimGroupMemberPolicyId -GroupId $gid; if (-not $polId) { throw "GroupsPolicies: no member policy for '$gn'" }
            # --- v1 baseline: Enablement + Expiration + Notification on EVERY managed group ---
            # Member enablement (MFA / Justification) per target (EndUser/Assignment +
            # Admin/Eligibility get MFA+Justification; Admin/Assignment is cleared) from the template.
            foreach ($enBody in @(ConvertTo-PimEnablementRuleBodies -Enablement $d.Enablement -LegacyEndUserAssignment $d.EnablementLegacy)) {
                try { Invoke-PimGraph -Method PATCH -Path "/policies/roleManagementPolicies/$polId/rules/$($enBody.id)" -Body $enBody | Out-Null } catch { Write-Verbose "enablement patch ($gn/$($enBody.id)): $($_.Exception.Message)" }
            }
            # Member expiration (v1 parity: EndUser/activation P1D, Admin/Assignment + Admin/Eligibility
            # P365D, all isExpirationRequired) from the template.
            foreach ($exBody in @(ConvertTo-PimExpirationRuleBodies -Expiration $d.Expiration)) {
                try { Invoke-PimGraph -Method PATCH -Path "/policies/roleManagementPolicies/$polId/rules/$($exBody.id)" -Body $exBody | Out-Null } catch { Write-Verbose "expiration patch ($gn/$($exBody.id)): $($_.Exception.Message)" }
            }
            # Notification rules (v1 parity: extra recipients per recipient-type x event) from the template
            if ($d.Notification) {
                foreach ($n in @($d.Notification)) {
                    $rt = "$($n.recipientType)"; $lvl = "$($n.level)"
                    if (-not $rt -or -not $lvl) { continue }
                    $recips = @(); if ($n.recipients) { $recips = @($n.recipients) }
                    $nlvl = if ("$($n.notificationLevel)") { "$($n.notificationLevel)" } else { 'All' }
                    $defOn = if ($n.PSObject.Properties['defaultRecipientsEnabled']) { [bool]$n.defaultRecipientsEnabled } else { $true }
                    try {
                        $nBody = New-PimGroupNotificationRuleBody -RecipientType $rt -Level $lvl -NotificationLevel $nlvl -Recipients $recips -DefaultRecipientsEnabled $defOn
                        Invoke-PimGraph -Method PATCH -Path "/policies/roleManagementPolicies/$polId/rules/$($nBody.id)" -Body $nBody | Out-Null
                    } catch { Write-Verbose "notification patch ($gn/$rt/$lvl): $($_.Exception.Message)" }
                }
            }
            # --- Approval rule: ONLY when the template declares one (default-linked groups skip) ---
            if (-not $d.Approval) { return }
            # approvers: template approversSource=Owners -> the ALREADY-RESOLVED approver ids
            # (Owners -> SponsorUpn -> Department, computed in GetDesired). Build into a typed List
            # so a SINGLE approver still serialises as a JSON ARRAY (PS ConvertTo-Json unwraps a
            # 1-element @() to an object -> 'InvalidPolicy'). A singleUser approver carries ONLY
            # @odata.type + userId; a 'description' property also triggers 'InvalidPolicy'.
            $approversList = New-Object System.Collections.Generic.List[object]
            $approverIds = @($d.ApproverIds)
            if (-not $approverIds.Count) { foreach ($o in ("$($d.Owners)" -split '[|,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) { $oid=Resolve-PimPrincipalId $o; if ($oid) { $approverIds += $oid } } }
            foreach ($oid in (@($approverIds) | Select-Object -Unique)) { if ($oid) { $approversList.Add(@{ '@odata.type'='#microsoft.graph.singleUser'; userId="$oid" }) } }
            $approvers = $approversList.ToArray()
            if (-not $approvers.Count) { throw "GroupsPolicies: approval-required for '$gn' but NO approver resolved (set Owners/SponsorUpn on the definition, or an Owners contact on its Department)" }
            $serial = ("$($d.Approval.mode)" -match '(?i)serial')
            $escMin = [int]("0" + "$($d.Approval.escalationHours)") * 60
            # Escalation approvers (optional template field 'escalationApprovers' = pipe/;/, UPN list).
            # Graph rejects a SingleStage approval rule with isEscalationEnabled=true but NO
            # escalationApprovers (InvalidPolicy). So escalation is ON only when both the template
            # asks for it (Serial) AND at least one escalation approver resolves.
            $escApprovers=@()
            foreach ($o in ("$($d.Approval.escalationApprovers)" -split '[|,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) { $oid=Resolve-PimPrincipalId $o; if ($oid) { $escApprovers += @{ '@odata.type'='#microsoft.graph.singleUser'; userId=$oid } } }
            $escalationOn = ($serial -and $escApprovers.Count -gt 0)
            $body=@{ '@odata.type'='#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'; id='Approval_EndUser_Assignment'
                target=@{ caller='EndUser'; operations=@('all'); level='Assignment'; inheritableSettings=@(); enforcedSettings=@() }
                setting=@{ isApprovalRequired=$true; isApprovalRequiredForExtension=$false; isRequestorJustificationRequired=$true; approvalMode='SingleStage'
                    approvalStages=@(@{ approvalStageTimeOutInDays=1; isApproverJustificationRequired=$true; escalationTimeInMinutes=$(if ($escalationOn) { $escMin } else { 0 }); isEscalationEnabled=$escalationOn; primaryApprovers=$approvers; escalationApprovers=$escApprovers }) } }
            Invoke-PimGraph -Method PATCH -Path "/policies/roleManagementPolicies/$polId/rules/Approval_EndUser_Assignment" -Body $body
        }
    }
}

# ---------------------------------------------------------------------------
# AdminTap scope -- issue a Temporary Access Pass for admin accounts flagged
# CreateTAP=TRUE (Account-Definitions-Admins). Ported from New-PimTemporaryAccessPass.
# ---------------------------------------------------------------------------
function New-PimAdminTapProvider {
    @{
        scope = 'AdminTap'; entity = 'Account-Definitions-Admins'; order = 35; refreshBefore = $true
        GetDesired = { param($ctx) @(Get-PimDesiredRows -Entity 'Account-Definitions-Admins' | Where-Object { (Get-PimRowProp -Row $_ -Names @('CreateTAP')) -match '(?i)true' }) }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $desired = @(Get-PimDesiredRows -Entity 'Account-Definitions-Admins' | Where-Object { (Get-PimRowProp -Row $_ -Names @('CreateTAP')) -match '(?i)true' })
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($d in $desired) {
                $upn = Get-PimRowProp -Row $d -Names @('UserPrincipalName'); $uid = Resolve-PimPrincipalId $upn; if (-not $uid) { continue }
                try { $taps = @(Invoke-PimGraph -Path "/users/$uid/authentication/temporaryAccessPassMethods"); if ($taps.Count) { $live.Add([pscustomobject]@{ UserPrincipalName=$upn }) } } catch { Write-Verbose "TAP live ($upn): $($_.Exception.Message)" }
            }
            $live.ToArray()
        }
        KeyOf = { param($r) (Get-PimRowProp -Row $r -Names @('UserPrincipalName')).ToLowerInvariant() }
        Equal = { param($d,$l) $true }   # has a TAP already -> nochange
        ApplyCreate = {
            param($item,$ctx)
            $d=$item.desired; $upn=Get-PimRowProp -Row $d -Names @('UserPrincipalName'); $uid=Resolve-PimPrincipalId $upn
            if (-not $uid) { throw "AdminTap: user '$upn' not found" }
            $hrs=[int]("0"+(Get-PimRowProp -Row $d -Names @('TAPLifetimeHours'))); if ($hrs -le 0) { $hrs = 4 }
            $body=@{ isUsableOnce=$false; lifetimeInMinutes=($hrs*60) }
            $tap = Invoke-PimGraph -Method POST -Path "/users/$uid/authentication/temporaryAccessPassMethods" -Body $body
            # deliver the TAP by mail (best-effort) -- to the admin's manager
            if (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue) {
                $mgr = Get-PimRowProp -Row $d -Names @('ManagerEmail')
                $toks = @{ UserPrincipalName=$upn; TapCode="$($tap.temporaryAccessPass)"; TapStartLocal="$($tap.startDateTime)"; TapStartUtc="$($tap.startDateTime)"; TapLifetimeMinutes="$($tap.lifetimeInMinutes)"; TapExpiresUtc='' }
                try { Send-PimNotifyMail -Type 'tap-delivery' -Tokens $toks -Recipient $mgr | Out-Null } catch { Write-Verbose "tap mail ($upn): $($_.Exception.Message)" }
            }
            $tap
        }
    }
}

# ---------------------------------------------------------------------------
# AccessReviews scope -- create an access-review schedule for groups that opt in via a
# ReviewCycle column. Reviewers = the group's Owners; auto-apply is OFF (the engine never
# auto-applies decisions on an engine-managed group -- matches LIFECYCLE-GOVERNANCE).
# Needs AccessReview.ReadWrite.All on the engine SPN; built REST-only.
# ---------------------------------------------------------------------------
function Get-PimReviewRecurrence {
    # ReviewCycle text -> Graph accessReview recurrence pattern + a sensible instance duration.
    param([string]$Cycle)
    switch -Regex ("$Cycle") {
        '(?i)week'                 { return @{ pattern = @{ type = 'weekly';        interval = 1 }; days = 3  } }
        '(?i)month'                { return @{ pattern = @{ type = 'absoluteMonthly'; interval = 1 }; days = 7  } }
        '(?i)quarter'              { return @{ pattern = @{ type = 'absoluteMonthly'; interval = 3 }; days = 14 } }
        '(?i)semi|half'            { return @{ pattern = @{ type = 'absoluteMonthly'; interval = 6 }; days = 21 } }
        '(?i)ann|year'             { return @{ pattern = @{ type = 'absoluteYearly';  interval = 1 }; days = 30 } }
        default                    { return @{ pattern = @{ type = 'absoluteMonthly'; interval = 3 }; days = 14 } }
    }
}
function New-PimAccessReviewsProvider {
    @{
        scope = 'AccessReviews'; entity = 'PIM-Definitions'; order = 80; refreshBefore = $true
        GetDesired = {
            param($ctx)
            Ensure-PimContextLoaded
            @(Get-PimGroupDefinitionRows | Where-Object { "$(Get-PimRowProp -Row $_ -Names @('ReviewCycle'))".Trim() } |
                ForEach-Object { [pscustomobject]@{ GroupName = $_.GroupName; Owners = $_.Owners; SponsorUpn = $_.SponsorUpn; Department = $_.Department; ReviewCycle = (Get-PimRowProp -Row $_ -Names @('ReviewCycle')) } })
        }
        GetLive = {
            param($ctx)
            $live = New-Object System.Collections.Generic.List[object]
            try { foreach ($d in @(Invoke-PimGraph -All -Path "/identityGovernance/accessReviews/definitions?`$select=id,displayName")) { if ("$($d.displayName)" -like 'PIM4EntraPS review - *') { $live.Add([pscustomobject]@{ GroupName = ("$($d.displayName)" -replace '^PIM4EntraPS review - ', '') }) } } } catch { Write-Warning "  [AccessReviews] list failed: $($_.Exception.Message)" }
            $live.ToArray()
        }
        KeyOf = { param($r) (Get-PimRowProp -Row $r -Names @('GroupName')).ToLowerInvariant() }
        Equal = { param($d, $l) $true }   # one review schedule per group (existence-based)
        ApplyCreate = {
            param($item, $ctx)
            $d = $item.desired; $gn = $d.GroupName
            $gid = Resolve-PimLiveGroupIdByName $gn; if (-not $gid) { throw "AccessReviews: group '$gn' not found" }
            $reviewerIds = Resolve-PimGroupOwnerIds -Row $d -Ctx $ctx
            if (-not $reviewerIds.Count) { throw "AccessReviews: no reviewer (owner) resolves for '$gn'" }
            $rev = @($reviewerIds | ForEach-Object { @{ query = "/users/$_"; queryType = 'MicrosoftGraph' } })
            $rc = Get-PimReviewRecurrence -Cycle $d.ReviewCycle
            $body = @{
                displayName = "PIM4EntraPS review - $gn"
                descriptionForAdmins = "Engine-managed access review for PIM group $gn (reviewers = owners; auto-apply OFF)."
                scope = @{ '@odata.type' = '#microsoft.graph.accessReviewQueryScope'; query = "/groups/$gid/transitiveMembers"; queryType = 'MicrosoftGraph' }
                reviewers = $rev
                settings = @{
                    mailNotificationsEnabled = $true; reminderNotificationsEnabled = $true
                    justificationRequiredOnApproval = $true; recommendationsEnabled = $true
                    defaultDecisionEnabled = $false; defaultDecision = 'None'
                    autoApplyDecisionsEnabled = $false            # engine never auto-applies
                    instanceDurationInDays = $rc.days
                    recurrence = @{ pattern = $rc.pattern; range = @{ type = 'noEnd'; startDate = ([datetime]::UtcNow.ToString('yyyy-MM-dd')) } }
                }
            }
            Invoke-PimGraph -Method POST -Path '/identityGovernance/accessReviews/definitions' -Body $body
        }
    }
}

# ---------------------------------------------------------------------------
# GroupOwners scope -- attach each group's resolved owners (Owners/SponsorUpn/Department).
# Separate from Groups create so it (a) tolerates replication of a just-created group
# (retry), (b) is re-runnable -- repairs missing owners on EXISTING groups (Groups itself
# is existence-based nochange and would never re-add them). Proper diff via $expand=owners.
# ---------------------------------------------------------------------------
function New-PimGroupOwnersProvider {
    @{
        scope = 'GroupOwners'; entity = 'PIM-Definitions'; order = 25; refreshBefore = $true
        GetDesired = {
            param($ctx)
            Ensure-PimContextLoaded
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($g in (Get-PimGroupDefinitionRows)) {
                foreach ($oid in (Resolve-PimGroupOwnerIds -Row $g -Ctx $ctx)) {
                    $out.Add([pscustomobject]@{ GroupName = $g.GroupName; OwnerId = "$oid" })
                }
            }
            $out.ToArray()
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $live = New-Object System.Collections.Generic.List[object]
            try {
                foreach ($grp in @(Invoke-PimGraph -Path "/groups?`$select=id,displayName&`$expand=owners" -All)) {
                    $gn = "$($grp.displayName)"; if (-not $gn) { continue }
                    foreach ($o in @($grp.owners)) { if ($o.id) { $live.Add([pscustomobject]@{ GroupName = $gn; OwnerId = "$($o.id)" }) } }
                }
            } catch { Write-Warning "  [GroupOwners] owners preload failed: $($_.Exception.Message)" }
            $live.ToArray()
        }
        KeyOf = { param($r) ("$(Get-PimRowProp -Row $r -Names @('GroupName'))").ToLowerInvariant() + '|' + "$(Get-PimRowProp -Row $r -Names @('OwnerId'))" }
        Equal = { param($d, $l) $true }
        ApplyCreate = {
            param($item, $ctx)
            $gn = Get-PimRowProp -Row $item.desired -Names @('GroupName'); $oid = Get-PimRowProp -Row $item.desired -Names @('OwnerId')
            $gid = Resolve-PimLiveGroupIdByName $gn
            if (-not $gid) { throw "GroupOwners: group '$gn' not found" }
            $ok = $false
            for ($t = 0; $t -lt 4 -and -not $ok; $t++) {
                try { Invoke-PimGraph -Method POST -Path "/groups/$gid/owners/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$oid" } | Out-Null; $ok = $true }
                catch { $em = "$($_.Exception.Message)"; if ($em -match '(?i)already exist|references already exist') { throw }  else { Start-Sleep -Seconds 3 } }   # exists -> let core validate-skip; else replication, retry
            }
            if (-not $ok) { throw "GroupOwners: owner add failed after retries ($oid -> $gn)" }
        }
    }
}

# ---------------------------------------------------------------------------
# EntraRolesDirect scope -- PIM v1-style DIRECT directory-role assignment to an
# ADMIN PRINCIPAL (a user), as opposed to the group-centric v2 model where the
# principal is always a PIM group. Some tenants still carry roles assigned
# directly to the admin (eligible or active) -- e.g. break-glass accounts that
# must not depend on the group fabric. Desired = PIM-Assignments-Roles-Direct
# (UserPrincipalName + RoleDefinitionName + AssignmentType[Eligible|Active] +
# Permanent/NumOfDaysWhenExpire). Same Graph PIM directory-role REST as
# EntraRoles, but principalId is the USER's id, tenant scope ('/'). The group
# model is preferred; the engine emits a deprecation note once per run so the
# data owner is nudged toward a group. Ported intent from the legacy v1 direct
# role path; module-free, REST-only, PS 5.1-safe.
# ---------------------------------------------------------------------------
function Get-PimDirectRoleKey {
    # PURE: uniform key for desired + live direct-role rows -> "<principalId|upn>|<role>|<type>".
    param([object]$Row)
    $prin = Get-PimRowProp -Row $Row -Names @('principalId')
    if (-not $prin) { $prin = Get-PimRowProp -Row $Row -Names @('UserPrincipalName','Username','UPN','upn') }
    $role = Get-PimRowProp -Row $Row -Names @('RoleDefinitionName','RoleName')
    $type = Get-PimRowProp -Row $Row -Names @('AssignmentType')
    return ("$prin|$role|$type").ToLowerInvariant()
}
function New-PimEntraRolesDirectProvider {
    @{
        scope  = 'EntraRolesDirect'
        entity = 'PIM-Assignments-Roles-Direct'
        order  = 48   # after group-centric EntraRoles(40)/RolesAUs(45), before AdminMembers(50)
        refreshBefore = $true
        GetDesired = {
            param($ctx)
            $rows = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Roles-Direct' | Where-Object { (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' -and (Get-PimRowProp -Row $_ -Names @('UserPrincipalName','Username','UPN','upn')) })
            if (@($rows).Count) {
                # DEPRECATION nudge: v2 is group-centric; direct role assignment to a user is a v1 holdover.
                Write-Host ("  [EntraRolesDirect] {0} DIRECT (v1-style) role assignment(s) to user principals -- supported, but the group model is preferred (assign the role to a PIM group + make the admin a member). See DESIGN 'PIM v1 direct assignments'." -f @($rows).Count) -ForegroundColor DarkYellow
            }
            @($rows)
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $rolesByName = @{}; foreach ($r in @($Global:Roles_All_ID)) { $n = "$($r.DisplayName)"; if ($n) { $rolesByName[$n.ToLowerInvariant()] = "$($r.Id)" } }
            $ctx['directRoleNameToId'] = $rolesByName; $ctx['directUpnToId'] = @{}
            $desired = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Roles-Direct')
            $upns = @($desired | ForEach-Object { Get-PimRowProp -Row $_ -Names @('UserPrincipalName','Username','UPN','upn') } | Where-Object { $_ } | Select-Object -Unique)
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($upn in $upns) {
                $uid = Resolve-PimPrincipalId $upn; if (-not $uid) { continue }
                $ctx['directUpnToId'][$upn.ToLowerInvariant()] = $uid
                foreach ($s in (Get-PimLiveDirRoleSchedules -PrincipalId $uid)) {
                    if ("$($s.directoryScopeId)" -ne '/') { continue }   # tenant-scope direct roles only
                    $live.Add([pscustomobject]@{ principalId=$uid; UserPrincipalName=$upn; RoleDefinitionName=$s.RoleDefinitionName; AssignmentType=$s.AssignmentType; roleDefinitionId=$s.roleDefinitionId })
                }
            }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimDirectRoleKey -Row $r }
        Equal = { param($d,$l) $true }   # existence-based (user already holds the role at the right type)
        ApplyCreate = {
            param($item,$ctx)
            $d = $item.desired
            $upn = Get-PimRowProp -Row $d -Names @('UserPrincipalName','Username','UPN','upn')
            $uid = $ctx['directUpnToId'][$upn.ToLowerInvariant()]; if (-not $uid) { $uid = Resolve-PimPrincipalId $upn }
            $rn  = Get-PimRowProp -Row $d -Names @('RoleDefinitionName','RoleName')
            $rid = $ctx['directRoleNameToId'][$rn.ToLowerInvariant()]
            if (-not $uid -or -not $rid) { throw "EntraRolesDirect: unresolved user/role ($upn / $rn)" }
            $type = Get-PimRowProp -Row $d -Names @('AssignmentType')
            $perm = (Get-PimRowProp -Row $d -Names @('Permanent')) -match '(?i)true'
            $days = [int]("0" + (Get-PimRowProp -Row $d -Names @('NumOfDaysWhenExpire')))
            $body = New-PimRoleScheduleBody -PrincipalId $uid -RoleDefId $rid -Permanent:$perm -Days $days -Action 'adminAssign' -StartUtc ((Get-Date).ToUniversalTime().ToString('o'))
            $ep = if ($type -eq 'Active') { 'roleAssignmentScheduleRequests' } else { 'roleEligibilityScheduleRequests' }
            Invoke-PimScheduleCreate -Path "/roleManagement/directory/$ep" -Body $body
        }
        ApplyRemove = {
            param($item,$ctx)
            $l = $item.live
            $type = "$($l.AssignmentType)"
            $body = New-PimRoleScheduleBody -PrincipalId "$($l.principalId)" -RoleDefId "$($l.roleDefinitionId)" -Action 'adminRemove'
            $ep = if ($type -eq 'Active') { 'roleAssignmentScheduleRequests' } else { 'roleEligibilityScheduleRequests' }
            Invoke-PimGraph -Method POST -Path "/roleManagement/directory/$ep" -Body $body
        }
    }
}

# ---------------------------------------------------------------------------
# Offboarding -- remove an admin principal's DELEGATIONS cleanly. The legacy CSV
# engine (PIM-Functions.psm1 Invoke-PimAdminOffboarding) handled account revoke +
# delete; the REST engine needs the delegation-removal half: when an admin is
# retired (Account-Definitions-Admins Lifecycle=Retire OR a past OffboardDate),
# strip every PIM-for-Groups membership (eligible + active) they hold across the
# managed groups -- so no lingering privileged reach survives the offboarding.
#
# Pure planner (Get-PimOffboardingPlan) decides WHO is to be offboarded + which
# live memberships to remove (fully testable, no Graph). The provider wraps it as
# a real REST-applying scope, GATED like every destructive path:
#   * runs only under -Mode Full -Prune (the engine's standard destructive gate), AND
#   * $global:PIM_OffboardCleanupMode controls intent: Off (skip) | Report
#     (plan only, the default) | Enforce (apply removals). Report/Off never write.
# An admin NOT flagged for offboarding is never touched (only flagged principals
# contribute live memberships, so the diff can only ever remove their rows).
# ---------------------------------------------------------------------------
function Test-PimAdminOffboarded {
    # PURE: is this admin row flagged for offboarding as of $NowUtc?
    #   Lifecycle=Retire  -> yes (immediate)
    #   OffboardDate (a date expression / ISO) at or before NowUtc -> yes
    # Returns @{ offboard=[bool]; reason=<text> }.
    param([Parameter(Mandatory)][object]$Row, [datetime]$NowUtc = [datetime]::UtcNow)
    $life = (Get-PimRowProp -Row $Row -Names @('Lifecycle')).Trim()
    if ($life -match '(?i)^retire') { return @{ offboard = $true; reason = 'Lifecycle=Retire' } }
    $od = (Get-PimRowProp -Row $Row -Names @('OffboardDate')).Trim()
    if ($od) {
        $when = $null
        if (Get-Command Resolve-PimDateExpression -ErrorAction SilentlyContinue) { try { $when = Resolve-PimDateExpression -Expression $od } catch { $when = $null } }
        if (-not $when) { $tmp = [datetime]::MinValue; if ([datetime]::TryParse($od, [ref]$tmp)) { $when = $tmp.ToUniversalTime() } }
        if ($when -and $when -le $NowUtc) { return @{ offboard = $true; reason = "OffboardDate $($when.ToString('yyyy-MM-dd')) reached" } }
    }
    return @{ offboard = $false; reason = '' }
}
function Get-PimOffboardingPlan {
    # PURE: given the admin definition rows + a (principalId -> live memberships)
    # map, return the removal plan -- one entry per live membership held by an
    # offboarded admin. $LiveByPrincipal[$pid] = @( @{ principalId; accessId;
    # GroupTag; AssignmentType }, ... ) (the shape Get-PimLiveGroupMembership
    # returns). Non-offboarded admins contribute nothing.
    param(
        [object[]]$AdminRows = @(),
        [Parameter(Mandatory)][hashtable]$LiveByPrincipal,
        [hashtable]$UpnToId = @{},
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($AdminRows)) {
        $flag = Test-PimAdminOffboarded -Row $a -NowUtc $NowUtc
        if (-not $flag.offboard) { continue }
        $upn = Get-PimRowProp -Row $a -Names @('UserPrincipalName','Username','UPN','upn')
        $prinId = Get-PimRowProp -Row $a -Names @('principalId')
        if (-not $prinId -and $upn) { $prinId = $UpnToId["$upn".ToLowerInvariant()] }
        if (-not $prinId) { continue }
        foreach ($m in @($LiveByPrincipal[$prinId])) {
            if ($null -eq $m) { continue }
            $plan.Add([pscustomobject]@{
                principalId       = $prinId
                UserPrincipalName = $upn
                GroupTag          = "$($m.GroupTag)"
                accessId          = $(if ("$($m.accessId)") { "$($m.accessId)" } else { 'member' })
                AssignmentType    = "$($m.AssignmentType)"
                Reason            = $flag.reason
            })
        }
    }
    return $plan.ToArray()
}

# OPERATOR POLICY (mass-disable incident, env-aware refinement): automatic offboarding
# (removing an offboarded admin's PIM-group memberships across the whole managed set) is
# ENVIRONMENT-AWARE -- it DEFAULTS ON in a test tenant and OFF in a protected one, and an
# explicit $global:PIM_EnableAutomaticOffboarding (true/false) always overrides that
# default in either direction. This is in addition to the existing -Mode Full -Prune +
# OffboardCleanupMode=Enforce gates. Self-contained here because the REST engine does not
# load PIM-Functions.psm1. Automatic offboarding stays prohibited in production until an
# approval flow exists (docs/REQUIREMENTS.md) -- protected env keeps it off by default.
function Test-PimAutoOffboardingEnabled {
    $val = Get-Variable -Name 'PIM_EnableAutomaticOffboarding' -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    # Explicit operator setting (true/false) always wins.
    if (Get-Command Test-PimExplicitFlagValue -ErrorAction SilentlyContinue) {
        $explicit = Test-PimExplicitFlagValue -Value $val
        if ($null -ne $explicit) { return [bool]$explicit }
        if (Get-Command Resolve-PimDestructiveFeatureDefault -ErrorAction SilentlyContinue) {
            return [bool](Resolve-PimDestructiveFeatureDefault)
        }
    }
    # Fallback (DisableGuard not loaded): preserve the post-incident OFF-by-default.
    return ("$val".Trim().ToLowerInvariant() -in @('true','1','yes','y','on','enable','enabled'))
}

function New-PimOffboardingProvider {
    @{
        scope = 'AdminOffboarding'; entity = 'Account-Definitions-Admins'; order = 90; refreshBefore = $true
        # GetLive already restricts to ONLY offboarded admins' memberships, so an empty
        # desired is authoritative (remove-only by construction) -- opt out of the
        # empty-desired prune guard in PIM-EngineCore.
        allowEmptyDesiredPrune = $true
        # DESIRED is EMPTY by design: the desired end-state for an offboarded admin's
        # delegations is "none". GetLive surfaces the memberships an offboarded admin
        # still holds; with -Prune those become removals. This means the scope ONLY
        # ever removes (it never creates) -- and only memberships of admins explicitly
        # flagged Lifecycle=Retire / past OffboardDate.
        GetDesired = {
            param($ctx)
            $mode = "$($global:PIM_OffboardCleanupMode)"; if (-not $mode) { $mode = 'Report' }
            $ctx['offboardMode'] = $mode
            @()
        }
        GetLive = {
            param($ctx)
            # OPERATOR POLICY: automatic offboarding is OFF by default. Surface nothing
            # (no removals) unless the operator explicitly opted in.
            if (-not (Test-PimAutoOffboardingEnabled)) {
                Write-Host "    [AdminOffboarding] SKIPPED -- automatic offboarding is DISABLED (operator policy). Set `$global:PIM_EnableAutomaticOffboarding=`$true to opt in (prohibited until an approval flow exists)." -ForegroundColor DarkYellow
                return @()
            }
            Ensure-PimContextLoaded
            $mode = "$($ctx['offboardMode'])"; if (-not $mode) { $mode = "$($global:PIM_OffboardCleanupMode)" }; if (-not $mode) { $mode = 'Report' }
            if ($mode -match '(?i)^off') { return @() }
            $admins = @(Get-PimDesiredRows -Entity 'Account-Definitions-Admins')
            # which admins are offboarded?
            $now = [datetime]::UtcNow
            $offUpnToId = @{}
            $offAdmins = New-Object System.Collections.Generic.List[object]
            foreach ($a in $admins) {
                if ((Test-PimAdminOffboarded -Row $a -NowUtc $now).offboard) {
                    $upn = Get-PimRowProp -Row $a -Names @('UserPrincipalName','Username','UPN','upn')
                    $prinId = Resolve-PimPrincipalId $upn
                    if ($prinId -and $upn) { $offUpnToId[$upn.ToLowerInvariant()] = $prinId; $offAdmins.Add($a) }
                }
            }
            if (-not $offAdmins.Count) { return @() }
            # build (principalId -> live group memberships) across the managed groups
            $tagToName = Get-PimTagToGroupName
            $liveByPrin = @{}
            foreach ($prinId in ($offUpnToId.Values | Select-Object -Unique)) { $liveByPrin[$prinId] = New-Object System.Collections.Generic.List[object] }
            foreach ($tag in @($tagToName.Keys)) {
                $nm = $tagToName[$tag]; if (-not $nm) { continue }
                $gid = Resolve-PimLiveGroupIdByName $nm; if (-not $gid) { continue }
                foreach ($m in (Get-PimLiveGroupMembership -GroupId $gid -GroupTag $tag)) {
                    $mp = "$($m.principalId)"
                    if ($liveByPrin.ContainsKey($mp)) { [void]$liveByPrin[$mp].Add($m) }
                }
            }
            $map = @{}; foreach ($k in @($liveByPrin.Keys)) { $map[$k] = $liveByPrin[$k].ToArray() }
            @(Get-PimOffboardingPlan -AdminRows $offAdmins.ToArray() -LiveByPrincipal $map -UpnToId $offUpnToId -NowUtc $now)
        }
        KeyOf = { param($r) ("$($r.principalId)|$($r.GroupTag)|$($r.AssignmentType)").ToLowerInvariant() }
        Equal = { param($d,$l) $true }
        # No ApplyCreate -- desired is always empty so create never fires. Removal only
        # under -Mode Full -Prune AND OffboardCleanupMode=Enforce (Report logs the plan
        # but ApplyRemove no-ops).
        ApplyRemove = {
            param($item,$ctx)
            # OPERATOR POLICY: defense-in-depth -- never apply an offboarding removal
            # unless the operator explicitly opted in (GetLive already returns empty when off).
            if (-not (Test-PimAutoOffboardingEnabled)) {
                Write-Host "    [AdminOffboarding] removal SKIPPED -- automatic offboarding is DISABLED (operator policy)." -ForegroundColor DarkYellow
                return
            }
            $mode = "$($ctx['offboardMode'])"; if (-not $mode) { $mode = "$($global:PIM_OffboardCleanupMode)" }; if (-not $mode) { $mode = 'Report' }
            $l = $item.live
            if ($mode -notmatch '(?i)^enforce') {
                Write-Host ("    [report] would offboard: {0} -> {1} ({2}, {3})" -f $l.UserPrincipalName, $l.GroupTag, $l.AssignmentType, $l.Reason) -ForegroundColor DarkYellow
                return
            }
            $tagToName = Get-PimTagToGroupName
            $gid = Resolve-PimLiveGroupIdByName $tagToName["$($l.GroupTag)".ToLowerInvariant()]
            if (-not $gid) { $gid = Resolve-PimLiveGroupIdByName "$($l.GroupTag)" }
            if (-not $gid) { throw "AdminOffboarding: group for tag '$($l.GroupTag)' not found" }
            $body = New-PimGroupMembershipBody -PrincipalId "$($l.principalId)" -GroupId $gid -AccessId "$($l.accessId)" -Action 'adminRemove'
            $ep = if ("$($l.AssignmentType)" -eq 'Active') { 'assignmentScheduleRequests' } else { 'eligibilityScheduleRequests' }
            Invoke-PimGraph -Method POST -Path "/identityGovernance/privilegedAccess/group/$ep" -Body $body
        }
    }
}

# ===========================================================================
# Workload-RBAC providers: Defender XDR + Intune (REQUIREMENTS §7). Group-centric,
# existence-based, idempotent, REST-only over Microsoft Graph (cert app-only).
#
# Both delegate a NATIVE workload RBAC role to a PIM GROUP (the principal is always
# a group, per the v2 model -- the admin gets the workload role by being a member of
# the group). They follow the same provider contract as EntraRoles/AzRes:
#   GetDesired -> the PIM-Assignments-* rows (Action!=Remove)
#   GetLive    -> the live role assignments the managed groups already hold
#   KeyOf      -> stable "<groupId>|<roleId>|..." key on BOTH desired + live
#   Equal      -> existence-based ($true: the group already holds the role => nochange)
#   ApplyCreate-> POST the workload role assignment for the group
#   ApplyRemove-> DELETE it (Full reconcile / -Prune only)
#
# READ-ONLY at collection: GetDesired/GetLive only read; nothing is written unless
# a create/remove is applied. -Mode Full reconciles create/update only; removal of a
# live-not-desired assignment needs -Prune (the engine's standard destructive gate).
#
# Each provider's RBAC prerequisite (REQUIREMENTS §7 "each connector enables its RBAC
# prerequisite"): Defender XDR needs Microsoft 365 Defender Unified RBAC activated and
# the engine SPN granted the Graph role-management.defender scope; Intune RBAC is on by
# default and needs DeviceManagementRBAC.ReadWrite.All.
# ===========================================================================

# Shared resolver: GroupTag -> live PIM group object id, via the tenant-wide tag map.
# (Same chain as the other assignment providers: a tag defined in any definition entity
# resolves to a GroupName, then to a live group id -- cache-first, on-demand fallback.)
function Resolve-PimGroupIdByTag {
    param([string]$Tag, [hashtable]$TagToName)
    if (-not $Tag) { return $null }
    $nm = $TagToName[$Tag.ToLowerInvariant()]; if (-not $nm) { return $null }
    return Resolve-PimLiveGroupIdByName $nm
}

# ---------------------------------------------------------------------------
# DefenderXdrRoles scope -- delegate a Microsoft Defender XDR (Microsoft 365
# Defender Unified RBAC) role to a PIM GROUP. Desired = PIM-Assignments-Defender
# (GroupTag + RoleDefinitionName + optional DataSources/UnitTag). Live + apply via
# the Graph Defender RBAC REST (roleManagement/defender/roleDefinitions +
# roleAssignments). Defender RBAC is a beta surface; the principal is the PIM group.
#
# NB: Defender Unified RBAC must be ACTIVATED in the security portal first (this is
# the connector's RBAC prerequisite); until it is, the role-definition list is empty
# and a clear "not activated / no roles" message is surfaced rather than a crash.
# ---------------------------------------------------------------------------
function Get-PimDefenderRoleKey {
    # PURE: uniform key for desired + live Defender rows -> "<groupId-or-tag>|<role>".
    param([object]$Row)
    $gid  = Get-PimRowProp -Row $Row -Names @('principalId')
    if (-not $gid) { $gid = 'tag:' + (Get-PimRowProp -Row $Row -Names @('GroupTag')) }
    $role = Get-PimRowProp -Row $Row -Names @('RoleDefinitionName','RoleName','RoleDefinitionId','roleDefinitionId')
    return ("$gid|$role").ToLowerInvariant()
}
function Get-PimDefenderRoleNameToId {
    # Live Defender role-definition NAME -> id map (cached per run). Empty when Unified
    # RBAC isn't activated -> caller surfaces a clear message.
    if ($script:__pimDefenderRoles) { return $script:__pimDefenderRoles }
    $h = @{}
    try {
        foreach ($r in @(Invoke-PimGraph -Beta -All -Path "/roleManagement/defender/roleDefinitions?`$select=id,displayName")) {
            $n = "$($r.displayName)"; if ($n) { $h[$n.ToLowerInvariant()] = "$($r.id)" }
        }
    } catch { Write-Warning "  [DefenderXdrRoles] role-definition list failed (Unified RBAC activated? engine SPN granted?): $($_.Exception.Message)" }
    $script:__pimDefenderRoles = $h; return $h
}
function New-PimDefenderXdrRolesProvider {
    @{
        scope  = 'DefenderXdrRoles'
        entity = 'PIM-Assignments-Defender'
        order  = 62   # after AzRes(60), a workload-RBAC delegation surface
        feature = 'connectors.workload'   # s29/s30: advanced (Pro) workload connector; gated
        refreshBefore = $true
        GetDesired = {
            param($ctx)
            $ctx['defTagToName'] = Get-PimTagToGroupName
            $rows = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Defender' | Where-Object {
                (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' -and
                (Get-PimRowProp -Row $_ -Names @('GroupTag')) -and
                (Get-PimRowProp -Row $_ -Names @('RoleDefinitionName','RoleName')) })
            @($rows)
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = if ($ctx['defTagToName']) { $ctx['defTagToName'] } else { Get-PimTagToGroupName }
            $roleNameToId = Get-PimDefenderRoleNameToId
            $roleIdToName = @{}; foreach ($k in @($roleNameToId.Keys)) { $roleIdToName[$roleNameToId[$k].ToLowerInvariant()] = $k }
            $ctx['defRoleNameToId'] = $roleNameToId; $ctx['defGid'] = @{}
            $desired = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Defender')
            # which group ids do we care about (the desired tags)?
            $wantGids = @{}
            foreach ($d in $desired) {
                $gt = Get-PimRowProp -Row $d -Names @('GroupTag'); if (-not $gt) { continue }
                $gid = Resolve-PimGroupIdByTag -Tag $gt -TagToName $tagToName
                if ($gid) { $ctx['defGid'][$gt.ToLowerInvariant()] = $gid; $wantGids[$gid] = $true }
            }
            $live = New-Object System.Collections.Generic.List[object]
            if ($wantGids.Count) {
                try {
                    foreach ($a in @(Invoke-PimGraph -Beta -All -Path "/roleManagement/defender/roleAssignments?`$select=id,displayName,roleDefinitionId,principalIds")) {
                        $rid = "$($a.roleDefinitionId)"
                        foreach ($prinId in @($a.principalIds)) {
                            $pp = "$prinId"; if (-not $wantGids.ContainsKey($pp)) { continue }
                            $rn = $roleIdToName[$rid.ToLowerInvariant()]
                            $live.Add([pscustomobject]@{ principalId=$pp; RoleDefinitionName=$rn; roleDefinitionId=$rid; assignmentId="$($a.id)" })
                        }
                    }
                } catch { Write-Warning "  [DefenderXdrRoles] assignment list failed: $($_.Exception.Message)" }
            }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimDefenderRoleKey -Row $r }
        Equal = { param($d,$l) $true }   # existence-based (group already holds the Defender role)
        ApplyCreate = {
            param($item,$ctx)
            $d = $item.desired
            $gt = (Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant()
            $gid = $ctx['defGid'][$gt]
            $rn = Get-PimRowProp -Row $d -Names @('RoleDefinitionName','RoleName')
            $rid = $ctx['defRoleNameToId'][$rn.ToLowerInvariant()]
            if (-not $gid) { throw "DefenderXdrRoles: group for tag '$gt' not found" }
            if (-not $rid) { throw "DefenderXdrRoles: Defender role '$rn' not found (Unified RBAC activated? role spelled correctly?)" }
            $disp = Get-PimRowProp -Row $d -Names @('AssignmentName'); if (-not $disp) { $disp = "PIM4EntraPS - $rn" }
            $body = @{ '@odata.type'='#microsoft.graph.unifiedRbacResourceNamespace'; displayName=$disp; roleDefinitionId=$rid; principalIds=@($gid); appScopeIds=@('/') }
            Invoke-PimGraph -Beta -Method POST -Path '/roleManagement/defender/roleAssignments' -Body $body
        }
        ApplyRemove = {
            param($item,$ctx)
            $aid = "$($item.live.assignmentId)"
            if (-not $aid) { throw "DefenderXdrRoles: no assignment id to remove for '$($item.key)'" }
            Invoke-PimGraph -Beta -Method DELETE -Path "/roleManagement/defender/roleAssignments/$aid"
        }
    }
}

# ---------------------------------------------------------------------------
# IntuneRoles scope -- delegate an Intune (Microsoft Intune / deviceManagement)
# RBAC role to a PIM GROUP, optionally bounded by Intune SCOPE TAGS. Desired =
# PIM-Assignments-Intune (GroupTag + RoleDefinitionName + optional ScopeTags
# pipe/;/,-joined names + optional MemberScope All|Tagged). Live + apply via the
# Graph Intune RBAC REST (deviceManagement/roleDefinitions + roleAssignments +
# roleScopeTags). The principal (members) is the PIM group; scope tags name the
# resource-scope boundary. Intune RBAC needs DeviceManagementRBAC.ReadWrite.All.
# ---------------------------------------------------------------------------
function Get-PimIntuneRoleKey {
    # PURE: uniform key for desired + live Intune rows -> "<groupId-or-tag>|<role>".
    param([object]$Row)
    $gid  = Get-PimRowProp -Row $Row -Names @('principalId')
    if (-not $gid) { $gid = 'tag:' + (Get-PimRowProp -Row $Row -Names @('GroupTag')) }
    $role = Get-PimRowProp -Row $Row -Names @('RoleDefinitionName','RoleName','RoleDefinitionId','roleDefinitionId')
    return ("$gid|$role").ToLowerInvariant()
}
function Get-PimIntuneRoleNameToId {
    # Live Intune role-definition NAME -> id (built-in + custom), cached per run.
    if ($script:__pimIntuneRoles) { return $script:__pimIntuneRoles }
    $h = @{}
    try {
        foreach ($r in @(Invoke-PimGraph -All -Path "/deviceManagement/roleDefinitions?`$select=id,displayName")) {
            $n = "$($r.displayName)"; if ($n) { $h[$n.ToLowerInvariant()] = "$($r.id)" }
        }
    } catch { Write-Warning "  [IntuneRoles] role-definition list failed (engine SPN granted DeviceManagementRBAC?): $($_.Exception.Message)" }
    $script:__pimIntuneRoles = $h; return $h
}
function Get-PimIntuneScopeTagNameToId {
    # Live Intune scope-tag NAME -> id, cached per run. Used to translate the desired
    # ScopeTags (names) into the roleScopeTags ids the assignment carries.
    if ($script:__pimIntuneScopeTags) { return $script:__pimIntuneScopeTags }
    $h = @{}
    try {
        foreach ($t in @(Invoke-PimGraph -All -Path "/deviceManagement/roleScopeTags?`$select=id,displayName")) {
            $n = "$($t.displayName)"; if ($n) { $h[$n.ToLowerInvariant()] = "$($t.id)" }
        }
    } catch { Write-Verbose "Intune scope-tag list: $($_.Exception.Message)" }
    $script:__pimIntuneScopeTags = $h; return $h
}
function Resolve-PimIntuneScopeTagIds {
    # PURE-ish: desired ScopeTags (pipe/;/,-joined NAMES, or numeric ids) -> id list.
    # A name that doesn't resolve is dropped (warned). Blank -> @() (the default scope tag
    # '0' is applied by the create body so an untagged assignment still validates).
    param([string]$Raw, [hashtable]$NameToId)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($s in @("$Raw" -split '[|;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        if ($s -match '^\d+$') { [void]$out.Add($s); continue }
        $id = $NameToId[$s.ToLowerInvariant()]
        if ($id) { [void]$out.Add("$id") } else { Write-Warning "  [IntuneRoles] scope tag '$s' not found -- dropped" }
    }
    return $out.ToArray()
}
function New-PimIntuneRolesProvider {
    @{
        scope  = 'IntuneRoles'
        entity = 'PIM-Assignments-Intune'
        order  = 64   # after AzRes(60)/DefenderXdrRoles(62), a workload-RBAC delegation surface
        feature = 'connectors.workload'   # s29/s30: advanced (Pro) workload connector; gated
        refreshBefore = $true
        GetDesired = {
            param($ctx)
            $ctx['intTagToName'] = Get-PimTagToGroupName
            $rows = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Intune' | Where-Object {
                (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' -and
                (Get-PimRowProp -Row $_ -Names @('GroupTag')) -and
                (Get-PimRowProp -Row $_ -Names @('RoleDefinitionName','RoleName')) })
            @($rows)
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = if ($ctx['intTagToName']) { $ctx['intTagToName'] } else { Get-PimTagToGroupName }
            $roleNameToId = Get-PimIntuneRoleNameToId
            $roleIdToName = @{}; foreach ($k in @($roleNameToId.Keys)) { $roleIdToName[$roleNameToId[$k].ToLowerInvariant()] = $k }
            $ctx['intRoleNameToId'] = $roleNameToId; $ctx['intGid'] = @{}; $ctx['intScopeTagNameToId'] = Get-PimIntuneScopeTagNameToId
            $desired = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Intune')
            $wantGids = @{}
            foreach ($d in $desired) {
                $gt = Get-PimRowProp -Row $d -Names @('GroupTag'); if (-not $gt) { continue }
                $gid = Resolve-PimGroupIdByTag -Tag $gt -TagToName $tagToName
                if ($gid) { $ctx['intGid'][$gt.ToLowerInvariant()] = $gid; $wantGids[$gid] = $true }
            }
            $live = New-Object System.Collections.Generic.List[object]
            if ($wantGids.Count) {
                try {
                    # roleAssignments expand members; an Intune RBAC assignment carries the member
                    # group ids in 'members' (a deviceAndAppManagementRoleAssignment).
                    foreach ($a in @(Invoke-PimGraph -All -Path "/deviceManagement/roleAssignments?`$select=id,displayName,members,roleDefinition&`$expand=roleDefinition")) {
                        $rid = "$($a.roleDefinition.id)"
                        foreach ($m in @($a.members)) {
                            $pp = "$m"; if (-not $wantGids.ContainsKey($pp)) { continue }
                            $rn = $roleIdToName[$rid.ToLowerInvariant()]
                            $live.Add([pscustomobject]@{ principalId=$pp; RoleDefinitionName=$rn; roleDefinitionId=$rid; assignmentId="$($a.id)" })
                        }
                    }
                } catch { Write-Warning "  [IntuneRoles] assignment list failed: $($_.Exception.Message)" }
            }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimIntuneRoleKey -Row $r }
        Equal = { param($d,$l) $true }   # existence-based (group already holds the Intune role)
        ApplyCreate = {
            param($item,$ctx)
            $d = $item.desired
            $gt = (Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant()
            $gid = $ctx['intGid'][$gt]
            $rn = Get-PimRowProp -Row $d -Names @('RoleDefinitionName','RoleName')
            $rid = $ctx['intRoleNameToId'][$rn.ToLowerInvariant()]
            if (-not $gid) { throw "IntuneRoles: group for tag '$gt' not found" }
            if (-not $rid) { throw "IntuneRoles: Intune role '$rn' not found (role spelled correctly? custom role created?)" }
            $disp = Get-PimRowProp -Row $d -Names @('AssignmentName'); if (-not $disp) { $disp = "PIM4EntraPS - $rn" }
            $scopeTags = @(Resolve-PimIntuneScopeTagIds -Raw (Get-PimRowProp -Row $d -Names @('ScopeTags','ScopeTagNames')) -NameToId $ctx['intScopeTagNameToId'])
            if (-not $scopeTags.Count) { $scopeTags = @('0') }   # default scope tag so the body validates
            # MemberScope: 'All' -> scopeType allDevicesAndLicensedUsers (org-wide); else 'resourceScope'
            # (the scope tags bound the resources). Default = Tagged when scope tags are given, else All.
            $memberScope = Get-PimRowProp -Row $d -Names @('MemberScope')
            $allScope = if ($memberScope) { $memberScope -match '(?i)all' } else { -not (Get-PimRowProp -Row $d -Names @('ScopeTags','ScopeTagNames')) }
            $body = @{
                '@odata.type'    = '#microsoft.graph.deviceAndAppManagementRoleAssignment'
                displayName      = $disp
                description      = 'PIM4EntraPS engine'
                members          = @($gid)
                roleDefinition   = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/deviceManagement/roleDefinitions/$rid" }
                roleScopeTagIds  = $scopeTags
            }
            if ($allScope) { $body['scopeType'] = 'allDevicesAndLicensedUsers' } else { $body['scopeType'] = 'resourceScope'; $body['resourceScopes'] = @() }
            Invoke-PimGraph -Method POST -Path "/deviceManagement/roleDefinitions/$rid/roleAssignments" -Body $body
        }
        ApplyRemove = {
            param($item,$ctx)
            $aid = "$($item.live.assignmentId)"
            if (-not $aid) { throw "IntuneRoles: no assignment id to remove for '$($item.key)'" }
            Invoke-PimGraph -Method DELETE -Path "/deviceManagement/roleAssignments/$aid"
        }
    }
}

# ---------------------------------------------------------------------------
# EntraAppRole scope -- GENERIC enterprise-app app-role delegation. ONE pattern
# assigns a PIM GROUP to ANY enterprise application's app role via the Graph
# servicePrincipals/{resourceSpId}/appRoleAssignedTo relationship -- so every
# gallery / line-of-business app is covered without a per-app connector. Desired =
# PIM-Assignments-AppRole (GroupTag + the target app (servicePrincipal) identified
# by AppDisplayName | AppId(application id) | ServicePrincipalId | ResourceSpId,
# + AppRole value/displayName, OR the special value 'Default Access' / blank for
# the implicit no-role app-role id all-zeros GUID). The app-role VALUE is resolved
# to its id from the resource SP's appRoles collection (fail loud on an unknown
# value, like every other connector). Live + apply via Graph appRoleAssignedTo
# (POST/DELETE). Existence-based + idempotent (group already holds the app role ->
# nochange; a live assignment not desired is pruned under -Mode Full -Prune).
# RBAC: the engine SPN needs AppRoleAssignment.ReadWrite.All (or be an owner of
# each target app) to read/POST/DELETE appRoleAssignedTo.
# ---------------------------------------------------------------------------
# The implicit "default access" app role -- Graph uses an all-zeros GUID when an
# app exposes no app roles (or the assignment targets the app generally).
$script:PimAppRoleDefaultId = '00000000-0000-0000-0000-000000000000'

function Get-PimAppRoleTargetKey {
    # PURE: stable key for the TARGET app across desired (names/appId) + the cached
    # resolved id. Prefer the resolved resource SP id; else fall back to the most
    # specific identifier present (ResourceSpId/ServicePrincipalId -> AppId ->
    # AppDisplayName), so an unresolved desired row never collides with a live row.
    param([object]$Row)
    $sp = Get-PimRowProp -Row $Row -Names @('resourceSpId','ResourceSpId','ServicePrincipalId','servicePrincipalId')
    if ($sp) { return "$sp".ToLowerInvariant() }
    $appId = Get-PimRowProp -Row $Row -Names @('AppId','ApplicationId','appId')
    if ($appId) { return ('appid:' + "$appId".ToLowerInvariant()) }
    return ('app:' + (Get-PimRowProp -Row $Row -Names @('AppDisplayName','AppName','ResourceDisplayName')).ToLowerInvariant())
}
function Get-PimAppRoleKey {
    # PURE: uniform key for desired + live app-role rows -> "<group-or-tag>|<app>|<approle>".
    # Group: resolved principalId if present, else 'tag:<GroupTag>'. App: per
    # Get-PimAppRoleTargetKey. App-role: the resolved appRoleId if present, else the
    # declared value (case-insensitive) -- blank/'default access' normalise to the
    # all-zeros default id so a "default access" assignment is existence-matched.
    param([object]$Row)
    $gid = Get-PimRowProp -Row $Row -Names @('principalId')
    if (-not $gid) { $gid = 'tag:' + (Get-PimRowProp -Row $Row -Names @('GroupTag')) }
    $app = Get-PimAppRoleTargetKey -Row $Row
    $rid = Get-PimRowProp -Row $Row -Names @('appRoleId','AppRoleId')
    if ($rid) { $role = "$rid" }
    else {
        $rv = (Get-PimRowProp -Row $Row -Names @('AppRole','AppRoleValue','AppRoleName','AppRoleDisplayName')).Trim()
        if (-not $rv -or $rv -match '(?i)^default access$') { $role = $script:PimAppRoleDefaultId } else { $role = $rv }
    }
    return ("$gid|$app|$role").ToLowerInvariant()
}
function Resolve-PimAppRoleId {
    # PURE: resolve a desired app-role VALUE (or displayName) to the app-role id from
    # the resource SP's appRoles array. Blank or 'Default Access' -> the all-zeros
    # default app-role id (Graph's implicit role). A non-blank value that matches no
    # appRole.value AND no appRole.displayName THROWS -- fail loud, like the other
    # connectors (Defender/Intune role-not-found). Match is case-insensitive.
    param([string]$Value, [object[]]$AppRoles)
    $v = "$Value".Trim()
    if (-not $v -or $v -match '(?i)^default access$') { return $script:PimAppRoleDefaultId }
    foreach ($r in @($AppRoles)) {
        if ("$($r.value)" -and "$($r.value)".ToLowerInvariant() -eq $v.ToLowerInvariant()) { return "$($r.id)" }
    }
    foreach ($r in @($AppRoles)) {
        if ("$($r.displayName)" -and "$($r.displayName)".ToLowerInvariant() -eq $v.ToLowerInvariant()) { return "$($r.id)" }
    }
    throw "EntraAppRole: app role '$Value' not found on the target application (check the value/displayName against the app's exposed app roles)"
}
function New-PimAppRoleAssignmentBody {
    # PURE: the appRoleAssignedTo POST body -- principalId = the PIM group, resourceId
    # = the target app's service-principal id, appRoleId = the resolved app-role id.
    param(
        [Parameter(Mandatory)][string]$PrincipalId,
        [Parameter(Mandatory)][string]$ResourceSpId,
        [Parameter(Mandatory)][string]$AppRoleId
    )
    @{ principalId = $PrincipalId; resourceId = $ResourceSpId; appRoleId = $AppRoleId }
}
function Resolve-PimAppServicePrincipal {
    # Resolve the TARGET enterprise app's service principal (id + appRoles) from any of
    # ServicePrincipalId/ResourceSpId (object id), AppId (application id), or
    # AppDisplayName. Cached per-run by the identifier used. Returns $null on a miss
    # (caller fails loud). Module-free REST.
    param([object]$Row)
    if (-not $script:__pimAppSpCache) { $script:__pimAppSpCache = @{} }
    $spId  = Get-PimRowProp -Row $Row -Names @('resourceSpId','ResourceSpId','ServicePrincipalId','servicePrincipalId')
    $appId = Get-PimRowProp -Row $Row -Names @('AppId','ApplicationId','appId')
    $disp  = Get-PimRowProp -Row $Row -Names @('AppDisplayName','AppName','ResourceDisplayName')
    $ck = ("$spId|$appId|$disp").ToLowerInvariant()
    if ($script:__pimAppSpCache.ContainsKey($ck)) { return $script:__pimAppSpCache[$ck] }
    $sp = $null
    try {
        if ($spId) {
            $sp = Invoke-PimGraph -Path "/servicePrincipals/$spId`?`$select=id,appId,displayName,appRoles"
        } elseif ($appId) {
            $r = @(Invoke-PimGraph -All -Path "/servicePrincipals?`$filter=appId eq '$appId'&`$select=id,appId,displayName,appRoles")
            if ($r.Count) { $sp = $r[0] }
        } elseif ($disp) {
            $esc = $disp -replace "'", "''"
            $r = @(Invoke-PimGraph -All -Path "/servicePrincipals?`$filter=displayName eq '$esc'&`$select=id,appId,displayName,appRoles")
            if ($r.Count) { $sp = $r[0] }
        }
    } catch { Write-Verbose "EntraAppRole SP resolve ($spId/$appId/$disp): $($_.Exception.Message)" }
    $script:__pimAppSpCache[$ck] = $sp; return $sp
}
function New-PimEntraAppRoleProvider {
    @{
        scope  = 'EntraAppRole'
        entity = 'PIM-Assignments-AppRole'
        order  = 66   # after AzRes(60)/DefenderXdrRoles(62)/IntuneRoles(64), a workload-RBAC delegation surface
        feature = 'connectors.workload'   # s29/s30: advanced (Pro) workload connector; gated
        refreshBefore = $true
        GetDesired = {
            param($ctx)
            $ctx['appRoleTagToName'] = Get-PimTagToGroupName
            # A row is valid when it names a GROUP (GroupTag) AND a TARGET APP (one of
            # ServicePrincipalId / AppId / AppDisplayName). The app-role value may be
            # blank (-> default access). Action=Remove rows are dropped (prune handles
            # removal of live-only rows under -Mode Full -Prune).
            $rows = @(Get-PimDesiredRows -Entity 'PIM-Assignments-AppRole' | Where-Object {
                (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' -and
                (Get-PimRowProp -Row $_ -Names @('GroupTag')) -and
                ( (Get-PimRowProp -Row $_ -Names @('ServicePrincipalId','servicePrincipalId','resourceSpId','ResourceSpId')) -or
                  (Get-PimRowProp -Row $_ -Names @('AppId','ApplicationId','appId')) -or
                  (Get-PimRowProp -Row $_ -Names @('AppDisplayName','AppName','ResourceDisplayName')) ) })
            @($rows)
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = if ($ctx['appRoleTagToName']) { $ctx['appRoleTagToName'] } else { Get-PimTagToGroupName }
            $ctx['appRoleGid'] = @{}; $ctx['appRoleSp'] = @{}
            $desired = @(Get-PimDesiredRows -Entity 'PIM-Assignments-AppRole')
            # which (group, app) pairs do we care about?
            $wantGids = @{}
            foreach ($d in $desired) {
                $gt = Get-PimRowProp -Row $d -Names @('GroupTag'); if (-not $gt) { continue }
                $gid = Resolve-PimGroupIdByTag -Tag $gt -TagToName $tagToName
                if ($gid) { $ctx['appRoleGid'][$gt.ToLowerInvariant()] = $gid; $wantGids[$gid] = $true }
            }
            # resolve every distinct target app once + index its appRoles (id->value/displayName)
            $appsByKey = @{}
            foreach ($d in $desired) {
                $ak = Get-PimAppRoleTargetKey -Row $d
                if ($appsByKey.ContainsKey($ak)) { continue }
                $sp = Resolve-PimAppServicePrincipal -Row $d
                $appsByKey[$ak] = $sp
                if ($sp) { $ctx['appRoleSp'][$ak] = $sp }
            }
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($ak in $appsByKey.Keys) {
                $sp = $appsByKey[$ak]; if (-not $sp -or -not $sp.id) { continue }
                try {
                    foreach ($a in @(Invoke-PimGraph -All -Path "/servicePrincipals/$($sp.id)/appRoleAssignedTo?`$select=id,principalId,appRoleId,principalType")) {
                        $pp = "$($a.principalId)"; if (-not $wantGids.ContainsKey($pp)) { continue }
                        $live.Add([pscustomobject]@{ principalId=$pp; resourceSpId="$($sp.id)"; appRoleId="$($a.appRoleId)"; assignmentId="$($a.id)" })
                    }
                } catch { Write-Warning "  [EntraAppRole] appRoleAssignedTo list failed for '$($sp.displayName)' (engine SPN granted AppRoleAssignment.ReadWrite.All / app owner?): $($_.Exception.Message)" }
            }
            $live.ToArray()
        }
        KeyOf = { param($r) Get-PimAppRoleKey -Row $r }
        Equal = { param($d,$l) $true }   # existence-based (group already holds the app role)
        ApplyCreate = {
            param($item,$ctx)
            $d = $item.desired
            $gt = (Get-PimRowProp -Row $d -Names @('GroupTag')).ToLowerInvariant()
            $gid = $ctx['appRoleGid'][$gt]
            if (-not $gid) { throw "EntraAppRole: group for tag '$gt' not found" }
            $ak = Get-PimAppRoleTargetKey -Row $d
            $sp = $ctx['appRoleSp'][$ak]; if (-not $sp) { $sp = Resolve-PimAppServicePrincipal -Row $d }
            if (-not $sp -or -not $sp.id) { throw "EntraAppRole: target application not found ($ak) -- check AppDisplayName / AppId / ServicePrincipalId" }
            $rv = Get-PimRowProp -Row $d -Names @('AppRole','AppRoleValue','AppRoleName','AppRoleDisplayName')
            $rid = Resolve-PimAppRoleId -Value $rv -AppRoles @($sp.appRoles)
            $body = New-PimAppRoleAssignmentBody -PrincipalId $gid -ResourceSpId "$($sp.id)" -AppRoleId $rid
            Invoke-PimGraph -Method POST -Path "/servicePrincipals/$($sp.id)/appRoleAssignedTo" -Body $body
        }
        ApplyRemove = {
            param($item,$ctx)
            $l = $item.live
            $sp = "$($l.resourceSpId)"; $aid = "$($l.assignmentId)"
            if (-not $sp -or -not $aid) { throw "EntraAppRole: no resource SP / assignment id to remove for '$($item.key)'" }
            Invoke-PimGraph -Method DELETE -Path "/servicePrincipals/$sp/appRoleAssignedTo/$aid"
        }
    }
}

# ===========================================================================
# HybridAdProvisioning scope (order 95) -- on-prem AD account + gMSA/sMSA support
# (REQUIREMENTS § 6). CLOUD-ONLY ENGINE CONSTRAINT: this provider is a PLANNER. It
# computes WHAT on-prem AD objects should exist for the AD-platform admin rows and
# emits a work package -- it NEVER imports the ActiveDirectory module or writes to a
# DC from the cloud engine. The actual on-prem write is a HYBRID-WORKER step
# (Invoke-PimHybridAdApply -Apply on a domain-joined host), flagged [ ] in DESIGN.
#
# It is read-only at collection time: GetLive returns @() (the cloud engine has no DC
# line-of-sight), so the diff is always "all desired AD rows = create-or-update intent",
# materialised as the plan + a work package the worker consumes. ApplyCreate/ApplyUpdate
# only LOG the planned on-prem action + (best-effort) write the work package; they do not
# touch AD. Gated by $global:PIM_HybridAdMode = Off (default) | Plan -- never auto-applies.
# ===========================================================================
function New-PimHybridAdProvider {
    @{
        scope  = 'HybridAdProvisioning'
        entity = 'Account-Definitions-Admins'
        order  = 95
        GetDesired = {
            param($ctx)
            $mode = "$($global:PIM_HybridAdMode)"; if (-not $mode) { $mode = 'Off' }
            $ctx['hybridAdMode'] = $mode
            if ($mode -match '(?i)^off') { return @() }
            if (-not (Get-Command Get-PimHybridAdPlan -ErrorAction SilentlyContinue)) {
                Write-Warning '  [HybridAdProvisioning] PIM-HybridAd.ps1 not loaded; skipping.'
                return @()
            }
            $admins = @(Get-PimDesiredRows -Entity 'Account-Definitions-Admins')
            $nc = $global:PIM_NamingConventions
            $pa  = if ($nc) { "$($nc.PathAdmins)" } else { '' }
            $pal = if ($nc) { "$($nc.PathAdminsL0T0)" } else { '' }
            $dom = "$($global:PIM_AdDomain)"
            # CLOUD-ONLY: no DC access here -> Live = @(); the plan is pure desired intent.
            $plan = Get-PimHybridAdPlan -AdminRows $admins -Live @() -PathAdmins $pa -PathAdminsL0T0 $pal -Domain $dom
            $ctx['hybridAdPlan'] = $plan
            @($plan.desired)
        }
        # No DC line-of-sight from the cloud engine -- live AD is read on the worker.
        GetLive = { param($ctx) @() }
        KeyOf = { param($r) Get-PimHybridAdDesiredKey -Record $r }
        Equal = { param($d,$l) $true }
        ApplyCreate = {
            param($item,$ctx)
            # [ ] On-prem write is HYBRID-WORKER-ONLY. The cloud engine only PLANS + logs.
            $d = $item.desired
            $kind = "$($d.accountKind)"
            Write-Host ("    [hybrid-ad/plan] would provision on worker: {0} (kind={1}, ou={2}) -- on-prem write deferred to hybrid worker" -f $d.samAccountName, $kind, $(if ($d.targetOu) { $d.targetOu } else { '<unset>' })) -ForegroundColor DarkCyan
            # Best-effort: emit the work package once per run so a worker can pick it up.
            if (-not $ctx['hybridAdPackageWritten'] -and $ctx['hybridAdPlan'] -and (Get-Command Export-PimHybridAdWorkPackage -ErrorAction SilentlyContinue)) {
                try {
                    $outDir = if ($global:PIM_OutputDir) { $global:PIM_OutputDir } else { Join-Path (Get-Location) 'output' }
                    $stateDir = Join-Path $outDir 'state'
                    if (-not (Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
                    $pkgPath = Join-Path $stateDir 'hybrid-ad-workpackage.json'
                    Export-PimHybridAdWorkPackage -Plan $ctx['hybridAdPlan'] -Path $pkgPath | Out-Null
                    $ctx['hybridAdPackageWritten'] = $true
                    Write-Host ("    [hybrid-ad/plan] work package written: {0} (worker applies it with Invoke-PimHybridAdApply -Apply)" -f $pkgPath) -ForegroundColor DarkGray
                } catch { Write-Verbose "hybrid-ad work package write failed: $($_.Exception.Message)" }
            }
        }
        ApplyUpdate = { param($item,$ctx) & (Get-PimEngineProvider -Scope 'HybridAdProvisioning').ApplyCreate $item $ctx }
    }
}

function Register-PimDefaultEngineProviders {
    if (-not (Get-Command Register-PimEngineProvider -ErrorAction SilentlyContinue)) { throw 'PIM-EngineCore.ps1 not loaded.' }
    Register-PimEngineProvider -Provider (New-PimAdministrativeUnitsProvider)   # order 10
    Register-PimEngineProvider -Provider (New-PimGroupsProvider)                # order 20
    Register-PimEngineProvider -Provider (New-PimGroupOwnersProvider)           # order 25
    Register-PimEngineProvider -Provider (New-PimAdminsProvider)                # order 30
    Register-PimEngineProvider -Provider (New-PimAdminTapProvider)              # order 35
    Register-PimEngineProvider -Provider (New-PimEntraRolesProvider)            # order 40
    Register-PimEngineProvider -Provider (New-PimRolesAUsProvider)              # order 45
    Register-PimEngineProvider -Provider (New-PimEntraRolesDirectProvider)      # order 48 (PIM v1 direct)
    Register-PimEngineProvider -Provider (New-PimAdminMembersProvider)          # order 50
    Register-PimEngineProvider -Provider (New-PimGroupMembersProvider)          # order 55
    Register-PimEngineProvider -Provider (New-PimAzResProvider)                 # order 60
    Register-PimEngineProvider -Provider (New-PimDefenderXdrRolesProvider)      # order 62 (workload RBAC: Defender XDR)
    Register-PimEngineProvider -Provider (New-PimIntuneRolesProvider)           # order 64 (workload RBAC: Intune + scope tags)
    Register-PimEngineProvider -Provider (New-PimEntraAppRoleProvider)          # order 66 (generic enterprise-app app-role)
    Register-PimEngineProvider -Provider (New-PimGroupsPoliciesProvider)        # order 70
    Register-PimEngineProvider -Provider (New-PimAccessReviewsProvider)         # order 80
    Register-PimEngineProvider -Provider (New-PimOffboardingProvider)           # order 90 (delegation removal; -Prune + Enforce gated)
    if (Get-Command New-PimHybridAdProvider -ErrorAction SilentlyContinue) {
        Register-PimEngineProvider -Provider (New-PimHybridAdProvider)          # order 95 (on-prem AD/gMSA PLANNER; on-prem write = hybrid worker [ ])
    }
    # Notifications wired into Admins/AdminTap (new-admin/tap-delivery). Remaining for full
    # parity: admin lifecycle schedules/reminders into the REST engine -- tracked separately.
}
