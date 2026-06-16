<#
.SYNOPSIS
  A STATEFUL in-memory fake Microsoft Graph + ARM tenant for the PIM4EntraPS scenario
  simulation. It lets the REAL engine (Invoke-PimEngine + the real providers) run
  end-to-end OFFLINE -- no live tenant, no certificate, no network -- yet exercise the
  genuine create/diff/idempotency logic.

  HOW IT WORKS
  ------------
  The engine's providers read LIVE state two ways:
     1. The directory context caches ($Global:Groups_All_ID / Users_All_ID /
        AU_All_ID / Roles_All_ID), populated by Build-PimContext.
     2. On-demand REST via Invoke-PimGraph / Invoke-PimArm (resolves + schedule reads +
        every write: POST creates, PATCH updates).

  This fake SHADOWS Build-PimContext, Invoke-PimGraph and Invoke-PimArm (function
  definitions in the caller's scope win over the dot-sourced engine ones) so:
     * GET  returns what the fake store currently holds (initially: only a couple of
       built-in role definitions + the owner user; everything the seed wants is ABSENT).
     * POST records a create into the fake store and returns a created object with a new
       id -- exactly as Graph/ARM would, so Add-PimContextObject caches it and the next
       GET sees it.
     * PATCH mutates the stored object.
  Because the store is stateful, the SAME engine run that creates everything on -Mode
  Full will, on a second -Mode Delta run, find everything already present -> 0 creates.
  That is the idempotency proof the scenario asserts.

  It is deliberately scoped to the surface the scenario seed exercises (users, groups,
  AUs, directory-role schedules, PIM-for-Groups schedules, group owners/members, role
  policies, Azure RBAC role assignments + role definitions). Unknown paths return an
  empty Graph-shaped payload (so a stray read never throws) and are counted so a test
  can assert no unexpected traffic.

  USAGE
  -----
     . .\PIM-FakeTenant.ps1
     $t = New-PimFakeTenant -OwnerUpn 'admin@example.onmicrosoft.com'
     Enable-PimFakeTenant -Tenant $t        # installs the shadow functions + context
     ... run the engine ...
     Get-PimFakeTenantStats -Tenant $t       # creates/updates/reads per kind
     Disable-PimFakeTenant                   # (optional) drop the shadows
#>

function New-PimFakeTenant {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OwnerUpn,
        [string]$OrgName = 'Scenario Tenant'
    )
    $t = [pscustomobject]@{
        OrgName     = $OrgName
        Users       = @{}   # id   -> @{ id; userPrincipalName; displayName; accountEnabled }
        UsersByUpn  = @{}   # upn  -> id
        Groups      = @{}   # id   -> @{ id; displayName; mailNickname; isAssignableToRole; description; owners=@(); members=@() }
        GroupsByName= @{}   # name -> id
        AUs         = @{}   # id   -> @{ id; displayName; visibility; members=@() }
        AUsByName   = @{}   # name -> id
        Roles       = @{}   # id   -> @{ id; displayName }
        RolesByName = @{}   # name(lower) -> id
        DirElig     = @()   # directory-role eligibility schedules
        DirAssign   = @()   # directory-role assignment schedules
        GrpElig     = @()   # PIM-for-Groups eligibility schedules
        GrpAssign   = @()   # PIM-for-Groups assignment schedules
        RolePolicies= @{}   # groupId -> policy body (last PATCH/PUT)
        AzAssign    = @()   # ARM role assignments
        TAPs        = @()   # temporaryAccessPass methods created
        Stats       = @{ create=@{}; update=@{}; read=@{}; unknown=@() }
    }
    # Seed the genuinely pre-existing directory: the owner user + a small set of built-in
    # directory roles the scenario binds to. NOTHING the seed wants to CREATE is present.
    $oid = [guid]::NewGuid().ToString()
    $t.Users[$oid] = @{ id=$oid; userPrincipalName=$OwnerUpn; displayName='Scenario Owner'; accountEnabled=$true }
    $t.UsersByUpn[$OwnerUpn.ToLower()] = $oid
    $t.UsersByUpn["hrmanager@$($OwnerUpn.Split('@')[1])".ToLower()] = $oid  # HR owner resolves to a real user
    foreach ($rn in @('Global Administrator','Privileged Role Administrator','User Administrator','Helpdesk Administrator')) {
        $rid = [guid]::NewGuid().ToString()
        $t.Roles[$rid] = @{ id=$rid; displayName=$rn; templateId=$rid; isBuiltIn=$true }
        $t.RolesByName[$rn.ToLower()] = $rid
    }
    return $t
}

function Bump-PimFakeStat { param($Tenant,[string]$Bucket,[string]$Kind)
    if (-not $Tenant.Stats[$Bucket].ContainsKey($Kind)) { $Tenant.Stats[$Bucket][$Kind] = 0 }
    $Tenant.Stats[$Bucket][$Kind]++
}

# --- the fake Graph dispatcher -------------------------------------------------
function Invoke-PimFakeGraph {
    param([string]$Method='GET',[string]$Path,[object]$Body,[switch]$All,[switch]$Beta,[hashtable]$Headers=@{})
    $T = $script:__PimFakeTenant
    $p = ($Path -replace '^/(v1\.0|beta)','')   # strip version prefix if present
    $pl = $p.ToLower()
    $M = $Method.ToUpper()

    # The real Invoke-PimGraph returns the AGGREGATED bare array when -All is set, and the
    # raw payload (with a .value collection) otherwise. Mirror BOTH so providers that do
    # `@(Invoke-PimGraph -All ...)` AND those that read `$resp.value` both work. (PS nested
    # functions read the parent function's $All via dynamic scope.)
    function AsValue($arr) { if ($All) { return @($arr) } [pscustomobject]@{ value = @($arr) } }

    # ----- organization -----
    if ($pl -like '/organization*') { return AsValue @([pscustomobject]@{ id=[guid]::NewGuid().ToString(); displayName=$T.OrgName }) }

    # ----- users -----
    if ($pl -like '/users*' -and $M -eq 'GET') {
        Bump-PimFakeStat $T 'read' 'users'
        # single user by upn/id
        $mm = [regex]::Match($p, '^/users/([^/?]+)')
        if ($mm.Success) {
            $key = [uri]::UnescapeDataString($mm.Groups[1].Value)
            $id = if ($T.Users.ContainsKey($key)) { $key } else { $T.UsersByUpn[$key.ToLower()] }
            if ($id) { $u=$T.Users[$id]; return [pscustomobject]@{ id=$u.id; userPrincipalName=$u.userPrincipalName; displayName=$u.displayName; accountEnabled=$u.accountEnabled } }
            throw "fake-graph 404: user '$key' not found"
        }
        return AsValue @($T.Users.Values | ForEach-Object { [pscustomobject]$_ })
    }
    if ($pl -eq '/users' -and $M -eq 'POST') {
        Bump-PimFakeStat $T 'create' 'user'
        $id=[guid]::NewGuid().ToString(); $upn="$($Body.userPrincipalName)"
        $T.Users[$id]=@{ id=$id; userPrincipalName=$upn; displayName="$($Body.displayName)"; accountEnabled=$true }
        if ($upn) { $T.UsersByUpn[$upn.ToLower()]=$id }
        return [pscustomobject]@{ id=$id; userPrincipalName=$upn; displayName="$($Body.displayName)"; accountEnabled=$true }
    }
    if ($pl -like '/users/*' -and $M -eq 'PATCH') {
        Bump-PimFakeStat $T 'update' 'user'
        $id=($p -replace '^/users/','' -replace '\?.*$','')
        if ($T.Users.ContainsKey($id) -and $null -ne $Body.accountEnabled) { $T.Users[$id].accountEnabled=[bool]$Body.accountEnabled }
        return [pscustomobject]@{ id=$id }
    }
    # temporaryAccessPass
    if ($pl -like '*/authentication/temporaryaccesspassmethods*' -and $M -eq 'POST') {
        Bump-PimFakeStat $T 'create' 'tap'
        $T.TAPs += @{ path=$p; body=$Body }
        return [pscustomobject]@{ id=[guid]::NewGuid().ToString(); temporaryAccessPass='FAKE-TAP-1234'; isUsable=$true }
    }

    # ----- groups -----
    if ($pl -like '/groups*' -and $M -eq 'GET') {
        Bump-PimFakeStat $T 'read' 'groups'
        $f = [regex]::Match($Path, "displayName eq '([^']*)'")
        if ($f.Success) {
            $name=$f.Groups[1].Value; $id=$T.GroupsByName[$name.ToLower()]
            if ($id) { $g=$T.Groups[$id]; return AsValue @([pscustomobject]@{ id=$g.id; displayName=$g.displayName; securityEnabled=$true; mailNickname=$g.mailNickname; description=$g.description }) }
            return AsValue @()
        }
        # full list -- include expanded owners when $expand=owners is requested (GroupOwners GetLive)
        $expandOwners = $Path -match '(?i)\$expand=owners'
        return AsValue @($T.Groups.Values | ForEach-Object {
            $o = [ordered]@{ id=$_.id; displayName=$_.displayName; securityEnabled=$true; mailNickname=$_.mailNickname; description=$_.description; groupTypes=@() }
            if ($expandOwners) { $o['owners'] = @($_.owners | ForEach-Object { [pscustomobject]@{ id=$_ } }) }
            [pscustomobject]$o
        })
    }
    if ($pl -eq '/groups' -and $M -eq 'POST') {
        Bump-PimFakeStat $T 'create' 'group'
        $id=[guid]::NewGuid().ToString(); $name="$($Body.displayName)"
        $T.Groups[$id]=@{ id=$id; displayName=$name; mailNickname="$($Body.mailNickname)"; isAssignableToRole=[bool]$Body.isAssignableToRole; description="$($Body.description)"; owners=@(); members=@() }
        if ($name) { $T.GroupsByName[$name.ToLower()]=$id }
        return [pscustomobject]@{ id=$id; displayName=$name }
    }
    # group owners: POST /groups/{id}/owners/$ref
    if ($pl -match '^/groups/[^/]+/owners' -and $M -eq 'GET') {
        Bump-PimFakeStat $T 'read' 'group-owners'
        $gid=($p -replace '^/groups/','' -replace '/owners.*$','')
        $owners = if ($T.Groups.ContainsKey($gid)) { $T.Groups[$gid].owners } else { @() }
        return AsValue @($owners | ForEach-Object { [pscustomobject]@{ id=$_ } })
    }
    if ($pl -match '^/groups/[^/]+/owners' -and $M -eq 'POST') {
        Bump-PimFakeStat $T 'create' 'group-owner'
        $gid=($p -replace '^/groups/','' -replace '/owners.*$','')
        $ref="$($Body.'@odata.id')"; $oid=($ref -split '/')[-1]
        if ($T.Groups.ContainsKey($gid) -and $T.Groups[$gid].owners -notcontains $oid) { $T.Groups[$gid].owners += $oid }
        return $null
    }
    # group members (PIM-for-Groups uses schedule endpoints, but direct membership ref may appear)
    if ($pl -match '^/groups/[^/]+/members' -and $M -eq 'POST') { Bump-PimFakeStat $T 'create' 'group-member'; return $null }

    # ----- administrative units -----
    if ($pl -like '/directory/administrativeunits*' -and $M -eq 'GET') {
        Bump-PimFakeStat $T 'read' 'aus'
        return AsValue @($T.AUs.Values | ForEach-Object { [pscustomobject]@{ id=$_.id; displayName=$_.displayName; visibility=$_.visibility } })
    }
    if ($pl -eq '/directory/administrativeunits' -and $M -eq 'POST') {
        Bump-PimFakeStat $T 'create' 'au'
        $id=[guid]::NewGuid().ToString(); $name="$($Body.displayName)"
        $T.AUs[$id]=@{ id=$id; displayName=$name; visibility="$($Body.visibility)"; members=@() }
        if ($name) { $T.AUsByName[$name.ToLower()]=$id }
        return [pscustomobject]@{ id=$id; displayName=$name }
    }
    if ($pl -match '^/directory/administrativeunits/[^/]+/members' -and $M -eq 'POST') {
        Bump-PimFakeStat $T 'create' 'au-member'
        $aid=($p -replace '^/directory/administrativeunits/','' -replace '/members.*$','')
        $oid=("$($Body.'@odata.id')" -split '/')[-1]
        if ($T.AUs.ContainsKey($aid)) { $T.AUs[$aid].members += $oid }
        return $null
    }

    # ----- role definitions -----
    if ($pl -like '/rolemanagement/directory/roledefinitions*' -and $M -eq 'GET') {
        Bump-PimFakeStat $T 'read' 'roledefs'
        return AsValue @($T.Roles.Values | ForEach-Object { [pscustomobject]@{ id=$_.id; displayName=$_.displayName; templateId=$_.templateId; isBuiltIn=$true } })
    }

    # ----- directory-role schedules (read) -----
    if ($pl -like '/rolemanagement/directory/roleeligibilityschedules*' -and $M -eq 'GET') { Bump-PimFakeStat $T 'read' 'dir-elig'; return AsValue @($T.DirElig) }
    if ($pl -like '/rolemanagement/directory/roleassignmentschedules*'  -and $M -eq 'GET') { Bump-PimFakeStat $T 'read' 'dir-assign'; return AsValue @($T.DirAssign) }
    # directory-role schedule requests (write)
    if ($pl -like '/rolemanagement/directory/roleeligibilityschedulerequests*' -and $M -eq 'POST') {
        return Add-PimFakeDirSchedule $T $Body 'Eligible'
    }
    if ($pl -like '/rolemanagement/directory/roleassignmentschedulerequests*' -and $M -eq 'POST') {
        return Add-PimFakeDirSchedule $T $Body 'Active'
    }

    # ----- PIM-for-Groups schedules -----
    if ($pl -like '/identitygovernance/privilegedaccess/group/eligibilityschedules*' -and $M -eq 'GET') { Bump-PimFakeStat $T 'read' 'grp-elig'; return AsValue @(Filter-PimFakeGrpSched $T $Path $T.GrpElig) }
    if ($pl -like '/identitygovernance/privilegedaccess/group/assignmentschedules*'  -and $M -eq 'GET') { Bump-PimFakeStat $T 'read' 'grp-assign'; return AsValue @(Filter-PimFakeGrpSched $T $Path $T.GrpAssign) }
    if ($pl -like '/identitygovernance/privilegedaccess/group/eligibilityschedulerequests*' -and $M -eq 'POST') { return Add-PimFakeGrpSchedule $T $Body 'Eligible' }
    if ($pl -like '/identitygovernance/privilegedaccess/group/assignmentschedulerequests*'  -and $M -eq 'POST') { return Add-PimFakeGrpSchedule $T $Body 'Active' }

    # ----- role-management policy ASSIGNMENTS (scope -> policyId). Must be matched BEFORE
    #       the generic policy GET below. Get-PimGroupMemberPolicyId reads $a[0].policyId.
    #       We mint ONE stable policy per group scope so PATCHes + reads are consistent. -----
    if ($pl -like '*rolemanagementpolicyassignments*' -and $M -eq 'GET') {
        Bump-PimFakeStat $T 'read' 'policy-assignments'
        $sf = [regex]::Match($Path, "scopeId eq '([^']*)'")
        $scopeId = if ($sf.Success) { $sf.Groups[1].Value } else { 'global' }
        $polId = "fake-policy-$scopeId"
        if (-not $T.RolePolicies.ContainsKey($polId)) { $T.RolePolicies[$polId] = @{ id=$polId; scopeId=$scopeId; rules=@{} } }
        return AsValue @([pscustomobject]@{ id="pa-$scopeId"; policyId=$polId; scopeId=$scopeId; roleDefinitionId='member' })
    }
    # ----- role-management POLICY (single, with rules). GroupsPolicies GetLive reads $pol.rules. -----
    if ($pl -like '*rolemanagementpolicies/*' -and $M -eq 'GET') {
        Bump-PimFakeStat $T 'read' 'policy'
        $polId = ($p -replace '.*rolemanagementpolicies/','' -replace '\?.*$','')
        $stored = if ($T.RolePolicies.ContainsKey($polId)) { $T.RolePolicies[$polId] } else { @{ id=$polId; rules=@{} } }
        # rules stored as a hashtable id->body; surface as an array of {id; setting; ...}
        $rules = @($stored.rules.GetEnumerator() | ForEach-Object { $_.Value })
        return [pscustomobject]@{ id=$polId; rules=$rules }
    }
    # ----- policy rule PATCH (Enablement/Expiration/Approval/Notification on a group) -----
    if ($pl -like '*rolemanagementpolicies/*/rules/*' -and ($M -eq 'PATCH' -or $M -eq 'PUT')) {
        Bump-PimFakeStat $T 'update' 'policy-rule'
        $polId = ($p -replace '.*rolemanagementpolicies/','' -replace '/rules/.*$','')
        $ruleId = ($p -replace '.*/rules/','' -replace '\?.*$','')
        if (-not $T.RolePolicies.ContainsKey($polId)) { $T.RolePolicies[$polId] = @{ id=$polId; rules=@{} } }
        $T.RolePolicies[$polId].rules[$ruleId] = $Body
        return [pscustomobject]@{ id=$ruleId }
    }
    if ($pl -like '*rolemanagementpolic*' -and ($M -eq 'PATCH' -or $M -eq 'PUT')) {
        Bump-PimFakeStat $T 'update' 'policy'
        return [pscustomobject]@{ id='fake-policy' }
    }
    if ($pl -like '*rolemanagementpolic*' -and $M -eq 'GET') {
        Bump-PimFakeStat $T 'read' 'policies'
        return AsValue @()
    }

    # ----- access reviews (best effort empty) -----
    if ($pl -like '*accessreview*') { Bump-PimFakeStat $T 'read' 'access-reviews'; return AsValue @() }

    # ----- service principals (app-role connectors) -----
    if ($pl -like '/serviceprincipals*' -and $M -eq 'GET') { Bump-PimFakeStat $T 'read' 'spns'; return AsValue @() }

    # ----- sendMail (notifications) -----
    if ($pl -like '*/sendmail*' -and $M -eq 'POST') { Bump-PimFakeStat $T 'create' 'mail'; return $null }

    # ----- unknown path: count + return empty shape (never throw on a stray read) -----
    $T.Stats.unknown += "$M $p"
    if ($M -eq 'GET') { return AsValue @() }
    return $null
}

function Add-PimFakeDirSchedule { param($T,$Body,[string]$Type)
    $action="$($Body.action)"
    $prinId="$($Body.principalId)"; $rid="$($Body.roleDefinitionId)"; $scope= if ($Body.directoryScopeId) { "$($Body.directoryScopeId)" } else { '/' }
    $rdn = ($T.Roles.Values | Where-Object { $_.id -eq $rid } | Select-Object -First 1).displayName
    $rec=[pscustomobject]@{ id=[guid]::NewGuid().ToString(); principalId=$prinId; roleDefinitionId=$rid; directoryScopeId=$scope; roleDefinition=[pscustomobject]@{ displayName=$rdn } }
    if ($action -match 'remove') {
        Bump-PimFakeStat $T 'update' "dir-$Type-remove"
        if ($Type -eq 'Eligible') { $T.DirElig = @($T.DirElig | Where-Object { -not ($_.principalId -eq $prinId -and $_.roleDefinitionId -eq $rid) }) }
        else { $T.DirAssign = @($T.DirAssign | Where-Object { -not ($_.principalId -eq $prinId -and $_.roleDefinitionId -eq $rid) }) }
    } else {
        # idempotency: a duplicate create returns the Graph 'RoleAssignmentExists' conflict so
        # the engine's exists->skipped path fires (matching a real re-run), not a new row.
        $existing = if ($Type -eq 'Eligible') { $T.DirElig } else { $T.DirAssign }
        if (@($existing | Where-Object { $_.principalId -eq $prinId -and $_.roleDefinitionId -eq $rid -and $_.directoryScopeId -eq $scope }).Count) {
            throw "RoleAssignmentExists: The Role assignment already exists."
        }
        Bump-PimFakeStat $T 'create' "dir-$Type"
        if ($Type -eq 'Eligible') { $T.DirElig += $rec } else { $T.DirAssign += $rec }
    }
    return $rec
}

function Filter-PimFakeGrpSched { param($T,$Path,$All)
    $f=[regex]::Match($Path, "groupId eq '([^']*)'")
    if ($f.Success) { $gid=$f.Groups[1].Value; return @($All | Where-Object { $_.groupId -eq $gid }) }
    return @($All)
}

function Add-PimFakeGrpSchedule { param($T,$Body,[string]$Type)
    $action="$($Body.action)"; $gid="$($Body.groupId)"; $prinId="$($Body.principalId)"; $accessId= if ($Body.accessId) { "$($Body.accessId)" } else { 'member' }
    $rec=[pscustomobject]@{ id=[guid]::NewGuid().ToString(); groupId=$gid; principalId=$prinId; accessId=$accessId }
    if ($action -match 'remove|revoke') {
        Bump-PimFakeStat $T 'update' "grp-$Type-remove"
        if ($Type -eq 'Eligible') { $T.GrpElig = @($T.GrpElig | Where-Object { -not ($_.groupId -eq $gid -and $_.principalId -eq $prinId) }) }
        else { $T.GrpAssign = @($T.GrpAssign | Where-Object { -not ($_.groupId -eq $gid -and $_.principalId -eq $prinId) }) }
    } else {
        $existing = if ($Type -eq 'Eligible') { $T.GrpElig } else { $T.GrpAssign }
        if (@($existing | Where-Object { $_.groupId -eq $gid -and $_.principalId -eq $prinId -and $_.accessId -eq $accessId }).Count) {
            throw "RoleAssignmentExists: An assignment already exists for this principal."
        }
        Bump-PimFakeStat $T 'create' "grp-$Type"
        if ($Type -eq 'Eligible') { $T.GrpElig += $rec } else { $T.GrpAssign += $rec }
    }
    return $rec
}

# --- the fake ARM dispatcher ---------------------------------------------------
function Invoke-PimFakeArm {
    param([string]$Method='GET',[string]$Path,[object]$Body,[string]$ApiVersion,[switch]$All,[hashtable]$Headers=@{})
    $T = $script:__PimFakeTenant
    $pl = $Path.ToLower(); $M=$Method.ToUpper()
    function AsValue($arr) { if ($All) { return @($arr) } [pscustomobject]@{ value = @($arr) } }
    # role definitions at a scope (filter by roleName so Resolve-PimArmRoleId gets the right one)
    if ($pl -like '*/providers/microsoft.authorization/roledefinitions*' -and $M -eq 'GET') {
        Bump-PimFakeStat $T 'read' 'arm-roledefs'
        $rf = [regex]::Match($Path, "roleName eq '([^']*)'")
        $allDefs = @(
            [pscustomobject]@{ id='/providers/Microsoft.Authorization/roleDefinitions/fake-owner';  name='fake-owner';  properties=[pscustomobject]@{ roleName='Owner' } }
            [pscustomobject]@{ id='/providers/Microsoft.Authorization/roleDefinitions/fake-reader'; name='fake-reader'; properties=[pscustomobject]@{ roleName='Reader' } }
        )
        if ($rf.Success) { $want=$rf.Groups[1].Value; return AsValue @($allDefs | Where-Object { $_.properties.roleName -eq $want }) }
        return AsValue $allDefs
    }
    # PIM eligibility/assignment schedule reads
    if (($pl -like '*roleeligibilityschedule*' -or $pl -like '*roleassignmentschedule*') -and $M -eq 'GET') {
        Bump-PimFakeStat $T 'read' 'arm-schedules'
        return AsValue @($T.AzAssign)
    }
    # PIM schedule request (write)
    if (($pl -like '*roleeligibilityschedulerequest*' -or $pl -like '*roleassignmentschedulerequest*') -and ($M -eq 'PUT' -or $M -eq 'POST')) {
        $isRemove = ("$($Body.properties.requestType)" -match 'Remove')
        if ($isRemove) { Bump-PimFakeStat $T 'update' 'arm-schedule-remove' }
        else {
            $pp = "$($Body.properties.principalId)"; $rd = "$($Body.properties.roleDefinitionId)"
            if (@($T.AzAssign | Where-Object { "$($_.properties.principalId)" -eq $pp -and "$($_.properties.roleDefinitionId)" -eq $rd }).Count) {
                throw "RoleAssignmentExists: The role assignment already exists."
            }
            Bump-PimFakeStat $T 'create' 'arm-schedule'
            $T.AzAssign += [pscustomobject]@{ id=[guid]::NewGuid().ToString(); properties=$Body.properties }
        }
        return [pscustomobject]@{ id=[guid]::NewGuid().ToString(); properties=$Body.properties }
    }
    $T.Stats.unknown += "ARM $M $Path"
    if ($M -eq 'GET') { return AsValue @() }
    return $null
}

# --- install / remove the shadows ---------------------------------------------
function Enable-PimFakeTenant {
    [CmdletBinding()] param([Parameter(Mandatory)]$Tenant)
    $script:__PimFakeTenant = $Tenant
    $global:__PimFakeTenant = $Tenant
    # Shadow the engine's REST + context entry points in the GLOBAL scope so the
    # dot-sourced provider scriptblocks call THESE.
    Set-Item -Path function:global:Invoke-PimGraph -Value ${function:Invoke-PimFakeGraph}
    Set-Item -Path function:global:Invoke-PimArm   -Value ${function:Invoke-PimFakeArm}
    # token + low-level rest never hit the network
    Set-Item -Path function:global:Get-PimRestToken -Value { param([string]$Resource='graph') 'FAKE-TOKEN' }
    Set-Item -Path function:global:Invoke-PimRest -Value { param([string]$Method='GET',[string]$Url,[object]$Body,[string]$Resource='graph',[hashtable]$Headers=@{},[switch]$All,[int]$MaxRetry=5) ,@() }
    # Build-PimContext: mark "already built" and populate the caches from the fake store.
    Set-Item -Path function:global:Build-PimContext -Value {
        param([switch]$Refresh,[int]$CacheSeconds=300)
        $t = $global:__PimFakeTenant
        $Global:Users_All_ID  = @($t.Users.Values  | ForEach-Object { [pscustomobject]@{ Id=$_.id; UserPrincipalName=$_.userPrincipalName; DisplayName=$_.displayName; AccountEnabled=$_.accountEnabled } })
        $Global:Groups_All_ID = @($t.Groups.Values | ForEach-Object { [pscustomobject]@{ Id=$_.id; DisplayName=$_.displayName; MailNickname=$_.mailNickname; Description=$_.description } })
        $Global:AU_All_ID     = @($t.AUs.Values    | ForEach-Object { [pscustomobject]@{ Id=$_.id; DisplayName=$_.displayName; Visibility=$_.visibility } })
        $Global:Roles_All_ID  = @($t.Roles.Values  | ForEach-Object { [pscustomobject]@{ Id=$_.id; DisplayName=$_.displayName; TemplateId=$_.templateId } })
        $Global:PimContextBuiltAt = Get-Date
    }
    # NB: Add-PimContextObject is NOT overridden -- the REAL one (PIM-ContextBuilder.ps1) is
    # pure (no network) and self-heals cache nesting via Merge-PimCacheItem. It expects the
    # created object to expose .id/.displayName (camelCase) which the fake POST handlers return.
    # Notifications -> no-op (counted by the fake graph sendMail handler if it ever routes there)
    Set-Item -Path function:global:Send-PimNotifyMail -Value { param() $null }
    # build the initial context
    Build-PimContext | Out-Null
}

function Disable-PimFakeTenant {
    foreach ($f in 'Invoke-PimGraph','Invoke-PimArm','Get-PimRestToken','Invoke-PimRest','Build-PimContext','Send-PimNotifyMail') {
        if (Test-Path "function:global:$f") { Remove-Item "function:global:$f" -Force -ErrorAction SilentlyContinue }
    }
    $script:__PimFakeTenant = $null; $global:__PimFakeTenant = $null
}

function Get-PimFakeTenantStats { param([Parameter(Mandatory)]$Tenant) $Tenant.Stats }
function Get-PimFakeTenantSummary { param([Parameter(Mandatory)]$Tenant)
    [pscustomobject]@{
        users=$Tenant.Users.Count; groups=$Tenant.Groups.Count; aus=$Tenant.AUs.Count
        dirElig=$Tenant.DirElig.Count; dirAssign=$Tenant.DirAssign.Count
        grpElig=$Tenant.GrpElig.Count; grpAssign=$Tenant.GrpAssign.Count
        azAssign=$Tenant.AzAssign.Count; policies=$Tenant.RolePolicies.Count; taps=$Tenant.TAPs.Count
        unknown=$Tenant.Stats.unknown.Count
    }
}
