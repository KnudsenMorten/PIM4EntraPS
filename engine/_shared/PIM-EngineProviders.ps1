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
            Invoke-PimGraph -Method POST -Path '/users' -Body @{
                accountEnabled=$true; displayName=$disp; mailNickname=$nick; userPrincipalName=$upn
                passwordProfile=@{ forceChangePasswordNextSignIn=$true; password=$pw }
            }
        }
        ApplyUpdate = {
            param($item,$ctx)
            # exists but disabled -> enable
            Invoke-PimGraph -Method PATCH -Path "/users/$($item.live.id)" -Body @{ accountEnabled=$true }
        }
        ApplyRemove = {
            param($item,$ctx)
            # Full reconcile: disable (never delete) an admin account not in desired.
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
        GetDesired = {
            param($ctx)
            @(Get-PimDesiredRows -Entity 'PIM-Assignments-Roles-Groups' | Where-Object { (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' })
        }
        GetLive = {
            param($ctx)
            if (-not $Global:PimContextBuiltAt) { try { Build-PimContext | Out-Null } catch {} }
            $groupsByName = @{}; foreach ($g in @($Global:Groups_All_ID)) { $n = "$($g.DisplayName)"; if ($n) { $groupsByName[$n.ToLowerInvariant()] = "$($g.Id)" } }
            $rolesByName  = @{}; foreach ($r in @($Global:Roles_All_ID))  { $n = "$($r.DisplayName)"; if ($n) { $rolesByName[$n.ToLowerInvariant()]  = "$($r.Id)" } }
            # GroupTag -> GroupName (PIM-Definitions-Roles) -> groupId
            $tagToName = @{}; foreach ($d in @(Get-PimDesiredRows -Entity 'PIM-Definitions-Roles')) {
                $t = Get-PimRowProp -Row $d -Names @('GroupTag'); $nm = Get-PimRowProp -Row $d -Names @('GroupName')
                if ($t) { $tagToName[$t.ToLowerInvariant()] = $nm }
            }
            $ctx['tagToGroupId'] = @{}; $ctx['roleNameToId'] = $rolesByName
            $desired = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Roles-Groups')
            $tags = @($desired | ForEach-Object { Get-PimRowProp -Row $_ -Names @('GroupTag') } | Where-Object { $_ } | Select-Object -Unique)
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($tag in $tags) {
                $nm = $tagToName[$tag.ToLowerInvariant()]; if (-not $nm) { continue }
                $gid = $groupsByName[$nm.ToLowerInvariant()]; if (-not $gid) { continue }
                $ctx['tagToGroupId'][$tag.ToLowerInvariant()] = $gid
                foreach ($pair in @(@{ ep='roleEligibilitySchedules'; type='Eligible' }, @{ ep='roleAssignmentSchedules'; type='Active' })) {
                    try {
                        foreach ($s in @(Invoke-PimGraph -Path "/roleManagement/directory/$($pair.ep)?`$filter=principalId eq '$gid'&`$expand=roleDefinition" -All)) {
                            $rn = "$($s.roleDefinition.displayName)"
                            $live.Add([pscustomobject]@{ GroupTag=$tag; RoleDefinitionName=$rn; AssignmentType=$pair.type; principalId=$gid; roleDefinitionId="$($s.roleDefinitionId)" })
                        }
                    } catch { Write-Verbose "EntraRoles live read ($tag/$($pair.type)): $($_.Exception.Message)" }
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
            Invoke-PimGraph -Method POST -Path "/roleManagement/directory/$ep" -Body $body
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

function Register-PimDefaultEngineProviders {
    if (-not (Get-Command Register-PimEngineProvider -ErrorAction SilentlyContinue)) { throw 'PIM-EngineCore.ps1 not loaded.' }
    Register-PimEngineProvider -Provider (New-PimAdminsProvider)
    Register-PimEngineProvider -Provider (New-PimEntraRolesProvider)
    # TODO (incremental): AzRes, GroupsAssignment, GroupsPolicies, AdministrativeUnits,
    # Workloads -- same contract, REST live + apply.
}
