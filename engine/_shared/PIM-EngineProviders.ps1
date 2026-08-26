# IMP-02: the locale-safe stamp reader. Loaded defensively so this file stays correct
# when a test dot-sources it on its own (PIM-Functions.psm1 also loads it up front).
if (-not (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-DateSafe.ps1') }
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
            # BUG-12 (fixed 2026-08-06). This was `/users` with NO filter -- the WHOLE
            # tenant population -- compared against the ADMIN definitions, so every
            # ordinary user was a removal candidate. That is the mechanism of the
            # 2026-06-15 incident (53 users disabled): measured here on 2026-08-06 it
            # returned 79 users, only 13 of them admin accounts.
            #
            # The live set is now restricted to ADMIN ACCOUNTS by the configured naming
            # convention (s17), server-side, so desired and live are the same population
            # and an ordinary user CANNOT be classified as a removal by construction.
            #
            # FAILS CLOSED: with no prefix configured we throw rather than scanning
            # everything. An unfiltered fallback is precisely the defect being fixed --
            # do not "helpfully" restore one (the legacy Get-PimAdminsFiltered has such a
            # fallback; it must not be copied here).
            # Resolve the prefixes from the THREE legitimate sources, in order. These are
            # all the same configured value seen from different processes -- none of them
            # is a wildcard, so trying the next one is not a weakening. The REST engine
            # does not hydrate naming conventions the way the Manager does, so without
            # this the scope could not run at all.
            # UNION them, do not stop at the first non-empty source. Each source declares
            # "what an admin account looks like"; taking only the first found silently
            # DROPS admin shapes the others know about. Observed exactly that: the store
            # yielded only 'admin-', so 'x-Admin'/'g-Admin' accounts from the locked
            # config fell out of the live set -- they would then never be reconciled
            # (and, under -Prune, never removed either). Under-scoping is safer than
            # over-scoping but it is still wrong; the union is the correct semantic, and
            # it still cannot admit an ordinary user.
            $prefixes = @()
            if (Get-Command Get-PimAdminAccountPrefixes -ErrorAction SilentlyContinue) {
                $acc = New-Object System.Collections.Generic.List[string]
                $merge = { param($list) foreach ($x in @($list)) { $s = "$x".Trim().ToLowerInvariant(); if ($s -and -not $acc.Contains($s)) { [void]$acc.Add($s) } } }
                & $merge (Get-PimAdminAccountPrefixes)                                       # 1. already in-process
                if (Get-Command Import-PimSettingsFromStore -ErrorAction SilentlyContinue) {
                    try { [void](Import-PimSettingsFromStore) } catch { }                    # 2. persisted pim.Settings
                    & $merge (Get-PimAdminAccountPrefixes)
                }
                try {                                                                        # 3. the shipped locked config
                    $cfg = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'config\PIM4EntraPS.NamingConventions.locked.ps1'
                    if (Test-Path -LiteralPath $cfg) {
                        $saved = $global:PIM_NamingConventions
                        . $cfg
                        & $merge (Get-PimAdminAccountPrefixes)
                        if ($saved) { $global:PIM_NamingConventions = $saved }                # don't clobber the live config
                    }
                } catch { }
                $prefixes = $acc.ToArray()
            }
            if ($prefixes.Count -eq 0) {
                throw ("Admins scope: no admin naming prefix is configured (`$global:PIM_NamingConventions.AdminAccountPatterns), " +
                       "so the live set cannot be limited to admin accounts. REFUSING to scan the whole user population -- " +
                       "that is what disabled 53 production users on 2026-06-15 (REQUIREMENTS s33 BUG-12).")
            }
            # Server-side filter, one startswith per configured prefix, unioned + deduped
            # by id. Also keeps the LEAN-context promise: never bulk-list a big tenant.
            $seen = @{}
            $rows = New-Object System.Collections.Generic.List[object]
            foreach ($p in $prefixes) {
                $esc = "$p".Replace("'", "''")
                $q = "/users?`$select=id,userPrincipalName,displayName,accountEnabled&`$filter=startswith(userPrincipalName,'$esc')"
                foreach ($u in @(Invoke-PimGraph -Path $q -All)) {
                    if ($null -eq $u) { continue }
                    $k = "$($u.id)"
                    if ($k -and -not $seen.ContainsKey($k)) { $seen[$k] = $true; [void]$rows.Add($u) }
                }
            }
            $live = $rows.ToArray()
            # Structural assertion: both sides of the diff must be the same population.
            # If anything non-admin slipped through (a server-side filter that silently
            # did nothing, say), stop -- do not diff a mixed population.
            if (Get-Command Assert-PimAdminPopulationComparable -ErrorAction SilentlyContinue) {
                $chk = Assert-PimAdminPopulationComparable -Live $live -Prefixes $prefixes
                if (-not $chk.ok) { throw ("Admins scope: " + $chk.reason) }
            }
            Write-Host ("    [admins] live set limited to {0} admin account(s) by prefix: {1}" -f $live.Count, ($prefixes -join ', ')) -ForegroundColor DarkGray
            $live
        }
        # BUG-13: key on the UPN's LOCAL PART, not the whole UPN. The desired UPN is
        # built as {UserName}@{DefaultDomainUPN} -- ONE default domain -- while a tenant
        # legitimately holds admin accounts across several verified domains. Keying on
        # the full UPN meant the SAME admin on a second domain could never match its
        # desired row and was classed as a removal. The account name is the identity;
        # the domain is a tenant detail.
        KeyOf = {
            param($r)
            $upn = Get-PimRowProp -Row $r -Names @('userPrincipalName','UserPrincipalName','UPN','upn')
            if (-not $upn) { $upn = Get-PimRowProp -Row $r -Names @('UserName','Username') }
            if (Get-Command Get-PimUpnLocalPart -ErrorAction SilentlyContinue) { return (Get-PimUpnLocalPart -Upn "$upn") }
            $s = "$upn".Trim(); $i = $s.IndexOf('@')
            if ($i -ge 0) { $s = $s.Substring(0, $i) }
            $s.ToLowerInvariant()
        }
        # desired = account should EXIST and be ENABLED. (Equality is against live.)
        Equal = { param($d,$l) [bool]$l.accountEnabled }
        ApplyCreate = {
            param($item,$ctx)
            # BUG-15. This read `$upn = "$($item.key)"`. That was correct while KeyOf returned
            # the whole UPN -- but the BUG-13 fix (rightly) changed KeyOf to the UPN LOCAL PART,
            # so the create started POSTing a userPrincipalName with NO DOMAIN and Entra rejected
            # every new admin with HTTP 400 "The domain portion of the userPrincipalName property
            # is invalid". The diff KEY is an identity, not an address: the address comes from the
            # desired row (as AdminTap.ApplyCreate already does), and only if the row carries none
            # do we compose it from the tenant's default verified domain.
            $upn = "$(Get-PimRowProp -Row $item.desired -Names @('UserPrincipalName','userPrincipalName','UPN','upn'))".Trim()
            if ($upn -notmatch '@') {
                $local = if ($upn) { $upn } else { "$($item.key)" }
                $dom = "$($global:DefaultDomainUPN)".Trim()
                if (-not $dom) { $dom = "$($global:PIM_DefaultDomainUPN)".Trim() }
                # BUG-20: this used to carry its OWN copy of the /organization lookup. It was
                # the CORRECT copy -- it unwrapped .value -- while Get-PimTargetDefaultDomain's
                # did not, so the two disagreed in every tenant: accounts were created at the
                # right domain while the assignment to those same accounts could not resolve
                # them. One resolver now serves both paths, so they cannot diverge again.
                # The $global: overrides above still win, on purpose: in an MSP fanout the
                # operator may pin the domain, and Get-PimTargetDefaultDomain deliberately
                # answers for the tenant the CURRENT token authenticates to.
                if (-not $dom) { $dom = "$(Get-PimTargetDefaultDomain)".Trim() }
                if (-not $dom) { throw "Admins: cannot create '$local' -- the desired row carries no UserPrincipalName and no default verified domain could be resolved. Refusing to POST a domainless UPN." }
                $upn = "$local@$dom"
            }
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
            # BUG-14 defense-in-depth: the orchestrator already drops break-glass from the
            # remove set, but this handler can be called directly. A break-glass account
            # must never be disabled by ANY route.
            if (Get-Command Get-PimBreakGlassIdentifiers -ErrorAction SilentlyContinue) {
                $bg = @(Get-PimBreakGlassIdentifiers)
                if ($bg.Count -gt 0 -and (Test-PimRowIsBreakGlass -Row $item.live -Identifiers $bg)) {
                    Write-Host ("    [skip] {0}: BREAK-GLASS account -- never disabled" -f $item.key) -ForegroundColor Yellow
                    return
                }
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
            $rolesByName  = @{}; foreach ($r in @($Global:Roles_All_ID))  { $n = "$($r.DisplayName)"; if ($n) { $rolesByName[$n.ToLowerInvariant()]  = "$($r.Id)" } }
            $ctx['roleNameToId'] = $rolesByName
            # BUG-17: this used to enumerate ONLY the group tags found in the desired rows,
            # so deleting a desired row also removed its live assignment from view and the
            # prune it should have caused did nothing -- the assignment stayed in the tenant
            # forever, unreported. The live universe is the groups the SOLUTION owns.
            # (This provider's keys already agreed across both sides -- GroupTag|role|type --
            # so unlike RolesAUs/GroupMembers it needed only the live-set half of the fix.)
            $owned = Get-PimSolutionOwnedGroups
            $ctx['tagToGroupId'] = @{}
            foreach ($t in @($owned.byTag.Keys)) { $ctx['tagToGroupId'][$t] = $owned.byTag[$t] }
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($gid in @($owned.byId.Keys)) {
                $tag = "$($owned.byId[$gid].tag)"; if (-not $tag) { continue }
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

function Get-PimSolutionOwnedGroups {
    <#
      BUG-17. THE set of groups this solution owns, resolved to live ids.

      Why this exists: every assignment scope used to build its LIVE set out of the
      tags found in its own DESIRED rows. That makes desired and live the same
      universe, so an assignment whose desired row is DELETED stops being read -- and
      a prune, whose entire job is to remove exactly that, cannot see it. The orphan
      stays in the tenant forever and no report mentions it.

      The correct universe is not "what the assignment rows point at" but "the groups
      this solution manages", which comes from the group DEFINITIONS -- a different
      entity, owned by the Groups scope. Deleting an assignment row then leaves its
      live row plainly visible; deleting a GROUP is a separate operation with its own
      scope. That separation is what makes an assignment prune authoritative without
      making it able to reach anything the solution does not own.

      Returns @{ byId = @{ gid -> @{ id; name; tag } }; byTag = @{ tag -> gid } }.
      Cached with the same short TTL as the directory-role preload, so a long-running
      scheduler process picks up newly-created groups without re-resolving every scope.
    #>
    [CmdletBinding()] param([switch]$Force)
    if (-not $Force -and $script:PimSolutionGroupsAt -and ((Get-Date) - $script:PimSolutionGroupsAt).TotalMinutes -lt 5) {
        return $script:PimSolutionGroups
    }
    $byId = @{}; $byTag = @{}
    foreach ($d in (Get-PimGroupDefinitionRows)) {
        $name = "$($d.GroupName)"; if (-not $name) { continue }
        $tag  = "$($d.GroupTag)"
        $gid  = Resolve-PimLiveGroupIdByName $name
        # No live id = the group has not been created yet (a first deploy, or the Groups
        # scope has not run). There is nothing live to reconcile for it, so it simply is
        # not in the live universe -- the assignment will be a create, which is right.
        if (-not $gid) { continue }
        $byId[$gid] = [pscustomobject]@{ id = $gid; name = $name; tag = $tag }
        if ($tag) { $byTag[$tag.ToLowerInvariant()] = $gid }
    }
    $script:PimSolutionGroups = [pscustomobject]@{ byId = $byId; byTag = $byTag }
    $script:PimSolutionGroupsAt = Get-Date
    Write-Host ("  [engine] solution-owned groups resolved: {0} of {1} defined" -f $byId.Count, @(Get-PimGroupDefinitionRows).Count) -ForegroundColor DarkGray
    return $script:PimSolutionGroups
}

function Test-PimNameAlreadyLive {
    <#
      BUG-18. Does an object with this displayName ALREADY exist? A DIRECT, freshly-read
      query -- never the context cache.

      Why: the engine decides create-vs-nochange from ONE bulk live LIST read, and Graph
      reads are not replica-pinned. A plan reported a scope fully converged and a real run
      four seconds later created the object AGAIN, because that call landed on a replica
      that had not caught up. Entra does not enforce unique displayName on AUs or groups,
      so the duplicate was accepted silently: no conflict, no error, errors=0. Observed
      three times in one session; the tenant then held two AUs with the same name, and
      since the engine KEYS on display name, every later run resolved that name to
      whichever copy a replica returned first.

      This is a CHECK, not a wait. A sleep or a retry delay would be guesswork about a
      window nobody can measure; one extra filtered read immediately before the POST is
      cheap, deterministic, and closes the case where the object demonstrably exists.
      It cannot close a window narrower than a single round-trip -- nothing can, short of
      a uniqueness constraint the directory does not offer -- so the caller treats a hit
      as validate-and-skip and carries on.

      Returns the existing object's id, or $null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('group', 'administrativeUnit')][string]$Kind,
        [Parameter(Mandatory)][string]$DisplayName
    )
    $n = "$DisplayName".Trim(); if (-not $n) { return $null }
    $esc = $n -replace "'", "''"
    try {
        if ($Kind -eq 'group') {
            $r = @(Invoke-PimGraph -Headers @{ ConsistencyLevel = 'eventual' } -All `
                    -Path "/groups?`$filter=displayName eq '$esc'&`$count=true&`$select=id,displayName")
        } else {
            $r = @(Invoke-PimGraph -All -Path "/directory/administrativeUnits?`$filter=displayName eq '$esc'&`$select=id,displayName")
        }
        foreach ($o in $r) { if ($o -and "$($o.displayName)" -eq $n) { return "$($o.id)" } }
    } catch { Write-Verbose "existence probe ($Kind '$n'): $($_.Exception.Message)" }
    return $null
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
function Get-PimTargetDefaultDomain {
    # The TARGET tenant's default (primary) verified domain -- the tenant the engine
    # token currently authenticates to (Invoke-PimGraph always hits that tenant). Used
    # to build a UPN from a bare central UserName in the MSP master->slave flow, where
    # PIM-Assignments-Admins rows carry the bare UserName (e.g. PIMSCEN-Admin-...-ID),
    # not the per-tenant UPN. Resolved ONCE per run and cached (don't re-query per
    # principal). Returns $null on any failure (caller then falls through to unresolved).
    if ($script:__pimTargetDefaultDomain) { return $script:__pimTargetDefaultDomain }
    if ($script:__pimTargetDefaultDomainTried) { return $null }   # a REAL miss is cached; never re-query
    try {
        # BUG-20: this read `@($org) | Select-Object -First 1` and then $row.verifiedDomains.
        # Invoke-PimGraph (without -All) returns the RAW OData envelope -- @odata.context +
        # value -- so $row was the ENVELOPE, not the organization, and the isDefault lookup
        # found nothing. This function therefore returned $null in EVERY tenant, which meant
        # the MSP master->slave fallback it exists for (resolve a bare central UserName as
        # "{UserName}@{slave default domain}") had never once worked: every
        # PIM-Assignments-Admins row carrying a bare UserName failed "unresolved principal".
        # Admins.ApplyCreate already did the unwrap correctly -- the two had silently
        # diverged, which is why admin accounts got created at the right domain while the
        # assignment to them could not find them. Measured live: the old shape saw 1
        # "verifiedDomain" and no default; the unwrapped shape sees 3 and the real default.
        $org = Invoke-PimGraph -Path "/organization?`$select=verifiedDomains"
        $row = if ($org.value) { @($org.value)[0] } else { @($org) | Select-Object -First 1 }
        $def = @($row.verifiedDomains) | Where-Object { $_.isDefault } | Select-Object -First 1
        if (-not $def) { $def = @($row.verifiedDomains) | Where-Object { $_.isInitial } | Select-Object -First 1 }
        if ($def -and "$($def.name)") { $script:__pimTargetDefaultDomain = "$($def.name)"; return $script:__pimTargetDefaultDomain }
        # The query WORKED and the tenant genuinely has no default/initial domain: cache
        # that, it will not change mid-run.
        $script:__pimTargetDefaultDomainTried = $true
    } catch {
        # A THROWN query is transient (throttling, a dropped socket). Deliberately NOT
        # cached as a miss: with BUG-19 fixed the engine can run for the life of a
        # container, and one unlucky 429 must not disable admin resolution until restart.
        Write-Verbose "default-domain resolve: $($_.Exception.Message)"
    }
    return $null
}

function Reset-PimTargetDefaultDomainCache {
    # Test seam + the honest way for a caller that switches TARGET TENANT mid-process
    # (the MSP fanout does exactly that) to drop a domain resolved for the previous tenant.
    $script:__pimTargetDefaultDomain = $null
    $script:__pimTargetDefaultDomainTried = $false
}
function Resolve-PimPrincipalId {
    # Cache first; on a miss resolve ON-DEMAND by UPN (a 500k-user tenant is never bulk-listed)
    # + cache. GUIDs pass through. /users/{upn} returns a single object (not .value).
    # FALLBACK (MSP master->slave): when the value is a BARE username (no '@') and the
    # direct lookup yields nothing, retry once as "{UserName}@{targetTenantDefaultDomain}".
    # The fanout rewrites UserName->UPN when CREATING the slave account, but the desired
    # PIM-Assignments-Admins rows are not rewritten before engine-apply, so the assignment
    # carries the bare central UserName. The fallback ONLY triggers on a no-'@' value whose
    # primary resolution failed -- a real UPN or a value that resolves directly is unchanged.
    param([string]$UpnOrId)
    if (-not $UpnOrId) { return $null }
    if ($UpnOrId -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return "$UpnOrId" }
    $u = @($Global:Users_All_ID) | Where-Object { "$($_.UserPrincipalName)" -eq "$UpnOrId" } | Select-Object -First 1
    if ($u) { return "$($u.Id)" }
    # NOTE (2026-08-09): a bare name can never match /users/{key}, so this first call always
    # 404s for the MSP master->slave case and writes a TerminatingError into the log of an
    # otherwise SUCCESSFUL run -- noise that caused a real misdiagnosis (see the retracted
    # BUG-35 in docs/REQUIREMENTS.md §33.9). Composing the UPN first was tried and REVERTED:
    # tests/Test-PimPrincipalResolveUpnFallback.ps1 deliberately pins this order
    # ("direct bare lookup tried first, then the UPN"), the behaviour is already correct, and
    # the only gain was tidier logs. Not worth overruling a deliberate assertion.
    try {
        $r = Invoke-PimGraph -Path "/users/$([uri]::EscapeDataString($UpnOrId))?`$select=id,userPrincipalName"
        if ($r.id) { if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind User -Object $r }; return "$($r.id)" }
    } catch { Write-Verbose "user resolve ($UpnOrId): $($_.Exception.Message)" }
    # Fallback: bare username (no '@') that didn't resolve -> retry as UserName@defaultDomain.
    if ("$UpnOrId" -notmatch '@') {
        $dom = Get-PimTargetDefaultDomain
        if ($dom) {
            $upn = "$UpnOrId@$dom"
            $cu = @($Global:Users_All_ID) | Where-Object { "$($_.UserPrincipalName)" -eq "$upn" } | Select-Object -First 1
            if ($cu) { return "$($cu.Id)" }
            try {
                $r2 = Invoke-PimGraph -Path "/users/$([uri]::EscapeDataString($upn))?`$select=id,userPrincipalName"
                if ($r2.id) { if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind User -Object $r2 }; return "$($r2.id)" }
            } catch { Write-Verbose "user resolve fallback ($upn): $($_.Exception.Message)" }
        }
    }
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
    # TENANT-WIDE preload of ALL directory role eligibility + assignment SCHEDULE INSTANCES,
    # indexed by principalId (the PIM group). One bulk read instead of per-group filters.
    #
    # 🔴 INSTANCES, NOT SCHEDULES -- and this is a correctness fix, not a preference.
    # This used to read /roleEligibilitySchedules + /roleAssignmentSchedules. An UNFILTERED
    # enumeration of those collections is INCOMPLETE: measured on myfamilynetwork 2026-08-10,
    #     roleAssignmentSchedules          total=613  AU-scoped=359  -> row ABSENT
    #     roleAssignmentScheduleInstances  total=602  AU-scoped=346  -> row PRESENT
    # for an assignment that a per-principal `$filter=principalId eq '<id>'` query on the SAME
    # schedules endpoint DID return. So the bulk read silently dropped rows that exist.
    # Consequence: RolesAUs re-planned 17 already-existing assignments as CREATEs on every single
    # run and skipped them at apply ("exists -- validated, skipped"). Harmless writes, but the scope
    # could never reach a steady state, so an operator could never tell "nothing to do" from
    # "17 things to do" -- on the scope that grants AU-scoped admin rights.
    # INSTANCES are also the semantically correct source for LIVE STATE: an instance is what is
    # currently in effect, whereas a schedule object can be expired or superseded (hence 602 < 613).
    param([switch]$Force)
    if (-not $Force -and $script:PimDirSchedAt -and ((Get-Date) - $script:PimDirSchedAt).TotalMinutes -lt 5) { return }
    $elig = @{}; $act = @{}
    foreach ($pair in @(@{ ep = 'roleEligibilityScheduleInstances'; idx = $elig }, @{ ep = 'roleAssignmentScheduleInstances'; idx = $act })) {
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
            # BUG-18: the diff said "create" from a bulk list read that may have been served
            # by a lagging replica. Re-check by name, directly, immediately before writing --
            # Entra does not enforce unique displayName, so without this a second run inside
            # the replication window silently makes a DUPLICATE and the engine (which keys on
            # display name) can never tell the two apart again.
            $existing = Test-PimNameAlreadyLive -Kind administrativeUnit -DisplayName "$($item.key)"
            if ($existing) {
                Write-Host ("    [=] {0} (already exists -- validated, skipped)" -f $item.key) -ForegroundColor DarkGray
                $au = [pscustomobject]@{ id = $existing; displayName = "$($item.key)" }
                if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind AU -Object $au }
                return $au
            }
            $vis = Get-PimRowProp -Row $d -Names @('Visibility'); if (-not $vis) { $vis = 'Public' }
            $au = Invoke-PimGraph -Method POST -Path '/directory/administrativeUnits' -Body @{
                displayName = "$($item.key)"; description = (Get-PimRowProp -Row $d -Names @('AUDescription')); visibility = $vis
            }
            if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind AU -Object $au }   # incremental cache
            # TEST-16: remember that THIS pass created it, so AdministrativeUnitMembers (order 22)
            # can tell replication lag from a genuinely missing AU. Only here -- the already-exists
            # branch above returns early and deliberately does not register.
            Register-PimAuCreatedThisPass -Context $ctx -AuId "$($au.id)" -AuName "$($item.key)"
            $au
        }
    }
}

# ---------------------------------------------------------------------------
# TEST-16 -- a freshly-created AU 404s when the SAME pass attaches its members.
#
# Measured on the run that CREATED the two scenario AUs: `AdministrativeUnits` (order 10)
# reported `create=2 errors=0`, and `AdministrativeUnitMembers` (order 22) -- later in the SAME
# pass -- got `Request_ResourceNotFound` for both the read and the write of those brand-new AU
# ids. Entra had not yet made them servable.
#
# 🪤 THE DISTINCTION IS THE WHOLE FIX, and it is why this is not just "retry 404s". A 404 on an
# AU this pass created is REPLICATION LAG and will resolve on its own. A 404 on an AU it did NOT
# create is a REAL missing-object signal -- the object was deleted, or the id is wrong -- and
# retrying that one only delays an accurate error. So the retry is gated on provenance, not on
# the status code.
#
# Impact was already bounded (BUG-16's reconciling scope repairs it next run, and the failure is
# REPORTED, not swallowed) -- but a first-ever deploy into a new customer tenant ended with AU
# membership unapplied and a red count, which reads as a broken deploy.
# ---------------------------------------------------------------------------
function Register-PimAuCreatedThisPass {
    # Record an AU that THIS pass genuinely created. Deliberately NOT called for the
    # already-exists validate-skip path in ApplyCreate: that AU predates the run, so a later
    # 404 on it is a real signal and must not be retried away.
    param([hashtable]$Context, [string]$AuId, [string]$AuName)
    if ($null -eq $Context -or -not "$AuId".Trim()) { return }
    if (-not $Context.ContainsKey('auCreatedThisPass') -or $null -eq $Context['auCreatedThisPass']) {
        $Context['auCreatedThisPass'] = @{}
    }
    $Context['auCreatedThisPass']["$AuId"] = "$AuName"
}
function Test-PimAuCreatedThisPass {
    # PURE: did this pass create that AU?
    param([hashtable]$Context, [string]$AuId)
    if ($null -eq $Context -or -not "$AuId".Trim()) { return $false }
    $set = $Context['auCreatedThisPass']
    if ($null -eq $set) { return $false }
    return [bool]$set.ContainsKey("$AuId")
}
function Test-PimGraphNotFound {
    # PURE: is this failure a Graph 404? Matched on both the status and the error code, because
    # only one of the two is present depending on which layer surfaced it.
    param([string]$Message)
    return ("$Message" -match '(?i)HTTP\s*404|\bRequest_ResourceNotFound\b|ResourceNotFound')
}
function Invoke-PimAuReplicationRetry {
    <#
      Run $Action. If it fails with a 404 AND $AuId is an AU this pass created, wait and retry;
      otherwise rethrow immediately.

      -DelaySeconds is a parameter so the offline tests can drive the whole retry loop with 0 --
      a test that has to sleep to prove a backoff either takes seconds or gets deleted.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [hashtable]$Context,
        [string]$AuId,
        [string]$What = 'AU operation',
        [int]$MaxAttempts = 4,
        [int]$DelaySeconds = 5
    )
    for ($attempt = 1; ; $attempt++) {
        try { return (& $Action) }
        catch {
            $msg = "$($_.Exception.Message)"
            $retryable = (Test-PimGraphNotFound $msg) -and (Test-PimAuCreatedThisPass -Context $Context -AuId $AuId)
            if (-not $retryable -or $attempt -ge $MaxAttempts) { throw }
            Write-Host ("    [engine] {0}: AU {1} was created THIS pass and is not servable yet (404) -- retrying in {2}s ({3}/{4})." -f `
                        $What, $AuId, $DelaySeconds, $attempt, ($MaxAttempts - 1)) -ForegroundColor DarkGray
            if ($DelaySeconds -gt 0) { Start-Sleep -Seconds $DelaySeconds }
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
            # BUG-18, same as the AU create: re-check by name directly before writing. The
            # diff's live set came from ONE bulk list read and Graph is not replica-pinned,
            # so "not there" can simply mean "not there YET". Entra allows duplicate group
            # display names, and the engine keys on display name -- a duplicate is therefore
            # permanent ambiguity, not a tidy-up job.
            $existingGid = Test-PimNameAlreadyLive -Kind group -DisplayName $gn
            if ($existingGid) {
                Write-Host ("    [=] {0} (already exists -- validated, skipped)" -f $gn) -ForegroundColor DarkGray
                $g0 = [pscustomobject]@{ id = $existingGid; displayName = $gn }
                if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind Group -Object $g0 }
                return $g0
            }
            $assignable = (Get-PimRowProp -Row $d -Names @('IsRoleAssignable')) -match '(?i)true'
            $body = @{
                displayName = $gn; mailNickname = (Get-PimMailNickname $gn)
                securityEnabled = $true; mailEnabled = $false; groupTypes = @()
                isAssignableToRole = $assignable
            }
            # Graph requires description 1-1024 chars when present -> only send if non-empty.
            $desc = Get-PimRowProp -Row $d -Names @('GroupDescription')
            if ("$desc".Trim()) { $body['description'] = $desc }
            # OWNERS: come from the definition's Owners column (pipe-joined UPNs per the Manager
            # UX; also accept ; or ,), Roles use SponsorUpn, falling back to the group's Department
            # contact (PIM-Definitions-Departments: Department -> Owners).
            #
            # 🔴 THIS NO LONGER REFUSES THE CREATE (operator, 2026-08-10):
            #   "it is important that the engine doesn't refuse to create an ownerless group.
            #    i acknowledge the purpose, but it must be support to add this later and should
            #    be optional."
            # It used to THROW, and that default was untenable in the real estate: 239 of the 259
            # authored service definitions carry a BLANK Owners column, so a strict engine would
            # refuse to (re)create the overwhelming majority of the estate's own groups -- measured
            # on myfamilynetwork while creating 4 legitimately-authored groups, all four refused.
            #
            # The purpose is kept, just not as a blocker: an ownerless create is WARNED about every
            # run, so the gap stays visible instead of silent, and OWNERSHIP IS ADDED LATER BY
            # DESIGN -- the GroupOwners scope reconciles owners on every run, so filling in the
            # Owners column at any point converges without touching the group.
            # Set $global:PIM_RequireGroupOwners = $true to restore the strict, refuse-to-create
            # behaviour; the knob now works in BOTH directions.
            $ownerIds = Resolve-PimGroupOwnerIds -Row $d -Ctx $ctx
            $require = $false; if ($null -ne $global:PIM_RequireGroupOwners) { $require = [bool]$global:PIM_RequireGroupOwners }
            if (-not $ownerIds.Count) {
                if ($require) {
                    throw "no owner resolves for group '$gn' and \$global:PIM_RequireGroupOwners is set -- set Owners/SponsorUpn on the definition, or a Department contact, or clear the flag to create it and assign the owner later."
                }
                Write-Warning ("  [engine] Groups: creating '$gn' with NO owner -- set Owners/SponsorUpn on the " +
                               "definition (or a Department contact) and the GroupOwners scope will attach it on a later run.")
            }
            $g = Invoke-PimGraph -Method POST -Path '/groups' -Body $body
            if (Get-Command Add-PimContextObject -ErrorAction SilentlyContinue) { Add-PimContextObject -Kind Group -Object $g }   # incremental cache
            # Attach to its AU. This is an OPTIMISATION, not the guarantee: the
            # AdministrativeUnitMembers scope (order 22) reconciles AU membership on every
            # run and is what actually keeps it correct.
            #
            # BUG-16: this used to be the ONLY attach, it read the possibly-stale context
            # cache, and it swallowed every failure to Write-Verbose. When the AU had been
            # created moments earlier by the AdministrativeUnits scope and had not yet
            # replicated to the replica this process reads, the lookup missed, the attach
            # was skipped silently, and nothing ever repaired it -- the Groups provider's
            # Equal is existence-based, so the group is `nochange` forever. AU membership is
            # the SCOPE BOUNDARY for AU-scoped delegation, so the group quietly had a
            # different reach than the model said. Observed in 1 of 3 identical runs.
            # Now: a miss is a WARNING that names the repair, never silence.
            $auTag = Get-PimRowProp -Row $d -Names @('AdministrativeUnitTag')
            if ($auTag -and $g.id) {
                $auName = $ctx['tagToAuName'][$auTag.ToLowerInvariant()]
                $au = @($Global:AU_All_ID) | Where-Object { "$($_.DisplayName)" -eq "$auName" } | Select-Object -First 1
                if ($au) {
                    try { Invoke-PimGraph -Method POST -Path "/directory/administrativeUnits/$($au.Id)/members/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/groups/$($g.id)" } | Out-Null }
                    catch { Write-Warning "  [engine] Groups: AU attach at create time failed for '$gn' -> '$auName' ($($_.Exception.Message)). The AdministrativeUnitMembers scope will reconcile it." }
                } else {
                    Write-Warning "  [engine] Groups: AU '$auName' (tag '$auTag') is not visible yet, so '$gn' was NOT attached at create time. The AdministrativeUnitMembers scope will reconcile it."
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
# AdministrativeUnitMembers scope (BUG-16) -- a PIM group belongs to the AU its
# definition names, and STAYS there.
#
# Why this is its own scope. The attach used to happen once, inside Groups.ApplyCreate,
# from a possibly-stale context cache, with the failure swallowed to Write-Verbose. Miss
# it and nothing ever repaired it: the Groups provider's Equal is existence-based, so on
# every later run the group is `nochange`. AU membership is the SCOPE BOUNDARY for
# AU-scoped delegation -- an L2 helpdesk role is granted AT the AU -- so a group that
# never joined its AU silently has a different reach than the delegation model says. A
# model that quietly disagrees with the directory is the thing this product exists to
# prevent, so the attach has to be RECONCILED, not attempted once.
#
# NB: create-only by design. There is deliberately no ApplyRemove -- pulling a group OUT
# of an AU changes the blast radius of every role scoped to that AU, and that belongs in
# the same approval conversation as wiring ApplyRemove on the other assignment scopes.
# A prune here therefore PLANS the removal and reports it; it does not execute it.
# ---------------------------------------------------------------------------
function New-PimAuMembersProvider {
    @{
        scope = 'AdministrativeUnitMembers'; entity = 'PIM-Definitions'; order = 22; refreshBefore = $true
        GetDesired = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToAu = Get-PimTagToAuName
            $auByName = @{}; foreach ($a in @($Global:AU_All_ID)) { $n = "$($a.DisplayName)"; if ($n) { $auByName[$n.ToLowerInvariant()] = "$($a.Id)" } }
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($d in (Get-PimGroupDefinitionRows)) {
                $auTag = "$($d.AdministrativeUnitTag)"; if (-not $auTag) { continue }   # not an AU-scoped group
                $gn = "$($d.GroupName)"; if (-not $gn) { continue }
                $gid = Resolve-PimLiveGroupIdByName $gn
                $auName = $tagToAu[$auTag.ToLowerInvariant()]
                $auId = if ($auName) { $auByName["$auName".ToLowerInvariant()] } else { $null }
                # Group or AU not live yet -> nothing to reconcile this pass; the next run
                # picks it up. That is the self-healing the old create-time attach lacked.
                if (-not $gid -or -not $auId) { continue }
                $out.Add([pscustomobject]@{ auId = $auId; auName = $auName; groupId = $gid; GroupName = $gn })
            }
            $out.ToArray()
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $owned = Get-PimSolutionOwnedGroups
            $out = New-Object System.Collections.Generic.List[object]
            # Only the AUs the SOLUTION defines, and only members that are groups it owns --
            # so this scope can never see, let alone plan against, anything else in the tenant.
            foreach ($r in @(Get-PimDesiredRows -Entity 'PIM-Definitions-AU')) {
                $auName = "$(Get-PimRowProp -Row $r -Names @('AUDisplayName'))"; if (-not $auName) { continue }
                $au = @($Global:AU_All_ID) | Where-Object { "$($_.DisplayName)" -eq $auName } | Select-Object -First 1
                if (-not $au) { continue }
                try {
                    # TEST-16: a 404 here on an AU this pass just created is replication lag, not a
                    # missing AU. Reading it as "no members" would make the diff plan a create that
                    # then 404s too -- which is exactly the reported failure.
                    $members = Invoke-PimAuReplicationRetry -Context $ctx -AuId "$($au.Id)" -What 'AdministrativeUnitMembers read' -Action {
                        @(Invoke-PimGraph -All -Path "/directory/administrativeUnits/$($au.Id)/members?`$select=id")
                    }
                    foreach ($m in @($members)) {
                        if (-not $m -or -not $m.id) { continue }
                        if (-not $owned.byId.ContainsKey("$($m.id)")) { continue }
                        $out.Add([pscustomobject]@{ auId = "$($au.Id)"; auName = $auName; groupId = "$($m.id)"; GroupName = "$($owned.byId["$($m.id)"].name)" })
                    }
                } catch { Write-Warning "  [engine] AdministrativeUnitMembers: could not read members of AU '$auName': $($_.Exception.Message)" }
            }
            $out.ToArray()
        }
        KeyOf = { param($r) "$(Get-PimRowProp -Row $r -Names @('auId'))|$(Get-PimRowProp -Row $r -Names @('groupId'))".ToLowerInvariant() }
        Equal = { param($d, $l) $true }   # membership exists -> nothing to change
        ApplyCreate = {
            param($item, $ctx)
            $d = $item.desired
            # TEST-16: same provenance-gated retry as the read above. A 404 on an AU this pass did
            # NOT create still fails immediately -- that is a real missing object.
            Invoke-PimAuReplicationRetry -Context $ctx -AuId "$($d.auId)" -What 'AdministrativeUnitMembers attach' -Action {
                Invoke-PimGraph -Method POST -Path "/directory/administrativeUnits/$($d.auId)/members/`$ref" `
                    -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/groups/$($d.groupId)" }
            }
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
            # BUG-17: the live universe is every group the SOLUTION owns, not just the tags
            # that happen to appear in the desired rows. Reading only the desired tags meant
            # a deleted desired row took its live membership out of view with it, so the
            # prune that removal was supposed to trigger silently did nothing.
            $owned = Get-PimSolutionOwnedGroups
            foreach ($t in @($tagToName.Keys)) { $gid = $owned.byTag[$t]; if ($gid) { $ctx['admTagToGid'][$t] = $gid } }
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($gid in @($owned.byId.Keys)) {
                $tag = "$($owned.byId[$gid].tag)"
                foreach ($m in (Get-PimLiveGroupMembership -GroupId $gid -GroupTag $tag)) {
                    # Complement of the GroupMembers filter: a nested GROUP membership belongs
                    # to that scope, not this one. Without this split each scope would see the
                    # other's rows as unowned and, under -Prune, as removals.
                    if ($owned.byId.ContainsKey("$($m.principalId)")) { continue }
                    $live.Add($m)
                }
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
        # BUG-11/BUG-17, same two fixes as RolesAUs: resolve the desired row's SOURCE group
        # to its live id so both sides key alike, and read live membership across every
        # group the solution owns rather than only the target tags found in desired.
        GetDesired = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = Get-PimTagToGroupName
            if (-not $ctx['grpTagToGid']) { $ctx['grpTagToGid'] = @{} }
            $resolve = {
                param($tag)
                $t = "$tag".ToLowerInvariant(); if (-not $t) { return $null }
                if ($ctx['grpTagToGid'].ContainsKey($t)) { return $ctx['grpTagToGid'][$t] }
                $nm = $tagToName[$t]; if (-not $nm) { return $null }
                $gid = Resolve-PimLiveGroupIdByName $nm
                if ($gid) { $ctx['grpTagToGid'][$t] = $gid }
                return $gid
            }
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($d in @(Get-PimDesiredRows -Entity 'PIM-Assignments-Groups' | Where-Object { (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' })) {
                # 🔴 DIRECTION: the TARGET group is nested INTO the SOURCE group.
                # SourceGroupTag is where the permission comes FROM (the service group); the
                # TargetGroupTag group is the one that RECEIVES it and is therefore the MEMBER.
                # This was inverted -- principalId was stamped from the SOURCE -- so no desired key
                # could ever match a live one (measured: desired=206, live=199, nochange=0) and
                # ApplyCreate would have written 206 memberships the wrong way round, nesting
                # service groups inside role groups.
                # Verified against the live tenant: PIM-ROLE-Management-IT-OperationSecurity is a
                # MEMBER OF 50 service groups (Entra-ID-SecurityAdministrator-L1, ...) and contains
                # 1 member -- while its desired rows are all Target='ROLE-Mgmt-IT-OperationSecurity'
                # with Source='<service group>'.
                $tgtGid = & $resolve (Get-PimRowProp -Row $d -Names @('TargetGroupTag'))
                [void](& $resolve (Get-PimRowProp -Row $d -Names @('SourceGroupTag')))   # cache for ApplyCreate
                $row = $d | Select-Object *
                # The live row's principal IS the member, i.e. the TARGET group. Stamping its id
                # makes the desired key identical to the live one. Unresolved (target group not
                # created yet) keys as unresolved -> a create, which is right on a first deploy.
                if ($tgtGid) { Add-Member -InputObject $row -NotePropertyName principalId -NotePropertyValue $tgtGid -Force }
                $out.Add($row)
            }
            $out.ToArray()
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = Get-PimTagToGroupName
            if (-not $ctx['grpTagToGid']) { $ctx['grpTagToGid'] = @{} }
            foreach ($t in @($tagToName.Keys)) {
                if ($ctx['grpTagToGid'].ContainsKey($t)) { continue }
                $gid = Resolve-PimLiveGroupIdByName $tagToName[$t]; if ($gid) { $ctx['grpTagToGid'][$t] = $gid }
            }
            # BUG-17: every solution-owned group is a potential TARGET, whether or not a
            # desired row currently points at it. Reading only the target tags in desired is
            # what made a deleted desired row invisible to prune.
            $owned = Get-PimSolutionOwnedGroups
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($gid in @($owned.byId.Keys)) {
                $tag = "$($owned.byId[$gid].tag)"
                foreach ($m in (Get-PimLiveGroupMembership -GroupId $gid -GroupTag $tag)) {
                    # A PIM group's membership holds BOTH nested groups (this scope) and admin
                    # USERS (the AdminMembers scope) -- the same Graph endpoint serves both.
                    # Keep only the nested-GROUP rows here, or every admin membership would be
                    # an unmatched live row in this scope and a removal candidate under -Prune.
                    # This mattered only once the keys were fixed: before, nothing matched
                    # anything, so the overlap was invisible.
                    if (-not $owned.byId.ContainsKey("$($m.principalId)")) { continue }
                    $live.Add($m)
                }
            }
            $live.ToArray()
        }
        KeyOf = {
            param($r)
            # ONE shape both sides produce: <member principal id>|<container tag>|<type>.
            # The MEMBER is the TARGET group; the CONTAINER is the SOURCE group. On a live row the
            # container tag arrives as GroupTag (the group whose membership was enumerated).
            $container = (Get-PimRowProp -Row $r -Names @('SourceGroupTag', 'GroupTag')).ToLowerInvariant()
            $type = (Get-PimRowProp -Row $r -Names @('AssignmentType')).ToLowerInvariant()
            $member = Get-PimRowProp -Row $r -Names @('principalId')   # live row, and the resolved desired row
            if (-not $member) { $member = "unresolved:" + (Get-PimRowProp -Row $r -Names @('TargetGroupTag')).ToLowerInvariant() }
            "$member|$container|$type"
        }
        Equal = { param($d, $l) $true }
        ApplyCreate = {
            param($item, $ctx)
            $d = $item.desired
            $tgt = (Get-PimRowProp -Row $d -Names @('TargetGroupTag')).ToLowerInvariant()
            $srcTag = (Get-PimRowProp -Row $d -Names @('SourceGroupTag')).ToLowerInvariant()
            $memberId    = $ctx['grpTagToGid'][$tgt]      # TARGET receives the access -> it is the MEMBER
            $containerId = $ctx['grpTagToGid'][$srcTag]   # SOURCE supplies the access -> it is the CONTAINER
            if (-not $memberId -or -not $containerId) { throw "GroupMembers: unresolved target/source ($tgt / $srcTag)" }
            $type = Get-PimRowProp -Row $d -Names @('AssignmentType')
            $perm = (Get-PimRowProp -Row $d -Names @('Permanent')) -match '(?i)true'
            $days = [int]("0" + (Get-PimRowProp -Row $d -Names @('NumOfDaysWhenExpire')))
            # Was PrincipalId=$sid / GroupId=$gid, i.e. nesting the SOURCE into the TARGET -- the
            # exact inverse of what the tenant has, and of what v1 built.
            $body = New-PimGroupMembershipBody -PrincipalId $memberId -GroupId $containerId -AccessId 'member' -Permanent:$perm -Days $days
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
        # BUG-11: the desired row is RESOLVED here -- tag -> live group id, AU tag -> live
        # AU id -- and the resolved ids are stamped onto the row. KeyOf then produces the
        # SAME key shape for desired and live, instead of a `tag:` placeholder that could
        # never match a resolved live key. That mismatch meant desired rows were re-created
        # on every run (never `nochange`) and, under -Prune, every live row was classed as
        # a removal -- including rows the very same pass had just created.
        GetDesired = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = Get-PimTagToGroupName; $tagToAu = Get-PimTagToAuName
            $auByName = @{}; foreach ($a in @($Global:AU_All_ID)) { $n = "$($a.DisplayName)"; if ($n) { $auByName[$n.ToLowerInvariant()] = "$($a.Id)" } }
            $ctx['auTagToId'] = @{}; $ctx['rauGid'] = @{}
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($d in @(Get-PimDesiredRows -Entity 'PIM-Assignments-Roles-AUs' | Where-Object { (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' })) {
                $gt = "$(Get-PimRowProp -Row $d -Names @('GroupTag'))"; $at = "$(Get-PimRowProp -Row $d -Names @('AdministrativeUnitTag'))"
                $gid = $null; $aid = $null
                if ($gt) { $gn = $tagToName[$gt.ToLowerInvariant()]; if ($gn) { $gid = Resolve-PimLiveGroupIdByName $gn; if ($gid) { $ctx['rauGid'][$gt.ToLowerInvariant()] = $gid } } }
                if ($at) { $an = $tagToAu[$at.ToLowerInvariant()]; if ($an) { $aid = $auByName[$an.ToLowerInvariant()]; if ($aid) { $ctx['auTagToId'][$at.ToLowerInvariant()] = $aid } } }
                $row = $d | Select-Object *
                # Both must resolve for the key to be the live shape. If either does not,
                # the group/AU does not exist yet -- there is nothing live to match, the
                # row keys as unresolved and becomes a create. That is correct on a first
                # deploy and is NOT the old placeholder problem: an unresolvable row has
                # no live counterpart by definition.
                if ($gid -and $aid) {
                    Add-Member -InputObject $row -NotePropertyName principalId      -NotePropertyValue $gid -Force
                    Add-Member -InputObject $row -NotePropertyName directoryScopeId -NotePropertyValue "/administrativeUnits/$aid" -Force
                }
                $out.Add($row)
            }
            $out.ToArray()
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $rolesByName = @{}; foreach ($r in @($Global:Roles_All_ID)) { $n = "$($r.DisplayName)"; if ($n) { $rolesByName[$n.ToLowerInvariant()] = "$($r.Id)" } }
            $ctx['rolesByName'] = $rolesByName
            # BUG-17: read the AU-scoped role schedules of every group THIS SOLUTION OWNS,
            # not just the groups the desired rows happen to mention. Otherwise deleting a
            # desired row hides its live assignment and the prune it was meant to trigger
            # silently does nothing. Free here -- the schedules come from the tenant-wide
            # preload, so this is index lookups, not extra calls.
            $owned = Get-PimSolutionOwnedGroups
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($gid in @($owned.byId.Keys)) {
                foreach ($s in (Get-PimLiveDirRoleSchedules -PrincipalId $gid)) {
                    if ("$($s.directoryScopeId)" -notmatch '(?i)/administrativeUnits/') { continue }   # RolesAUs = AU-scoped only
                    $live.Add([pscustomobject]@{ principalId=$gid; RoleDefinitionName=$s.RoleDefinitionName; AssignmentType=$s.AssignmentType; directoryScopeId=$s.directoryScopeId })
                }
            }
            $live.ToArray()
        }
        KeyOf = {
            param($r)
            # ONE key shape for both sides: resolved principal + AU id + role + type.
            # GetDesired stamps principalId/directoryScopeId, so a desired row that
            # resolves keys identically to its live counterpart.
            $gid = Get-PimRowProp -Row $r -Names @('principalId')
            if ($gid) {
                $scope = Get-PimRowProp -Row $r -Names @('directoryScopeId'); $au = ($scope -split '/')[-1]
                $role = (Get-PimRowProp -Row $r -Names @('RoleDefinitionName')).ToLowerInvariant()
                $type = (Get-PimRowProp -Row $r -Names @('AssignmentType')).ToLowerInvariant()
                return "$gid|$($au.ToLowerInvariant())|$role|$type"
            }
            # UNRESOLVED desired row (group or AU not live yet) -> deliberately distinct, so
            # it becomes a create. It can never collide with a live key because a live row
            # always carries a principalId.
            $gt=(Get-PimRowProp -Row $r -Names @('GroupTag')).ToLowerInvariant(); $at=(Get-PimRowProp -Row $r -Names @('AdministrativeUnitTag')).ToLowerInvariant()
            $role=(Get-PimRowProp -Row $r -Names @('RoleDefinitionName')).ToLowerInvariant(); $type=(Get-PimRowProp -Row $r -Names @('AssignmentType')).ToLowerInvariant()
            "unresolved:$gt|autag:$at|$role|$type"
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
        # BUG-11: resolve the desired row to the SAME shape the live row has -- the group's
        # live id and the ARM role DEFINITION GUID (the live side only ever reports the guid,
        # never the role name). Without this, `tag:…|perm:reader` could never equal
        # `<gid>|…|rid:<guid>`, so every run re-created assignments that already existed and
        # a -Prune classed every live assignment as a removal.
        GetDesired = {
            param($ctx)
            Ensure-PimContextLoaded
            $ctx['armRoleCache'] = @{}
            $tagToName = Get-PimTagToGroupName
            if (-not $ctx['azGid']) { $ctx['azGid'] = @{} }
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($d in @(Get-PimDesiredRows -Entity 'PIM-Assignments-Azure-Resources' | Where-Object { (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' })) {
                $gt = "$(Get-PimRowProp -Row $d -Names @('GroupTag'))".ToLowerInvariant()
                $scope = "$(Get-PimRowProp -Row $d -Names @('AzScope'))"
                $perm  = "$(Get-PimRowProp -Row $d -Names @('AzScopePermission'))"
                $gid = $null
                if ($gt) {
                    if ($ctx['azGid'].ContainsKey($gt)) { $gid = $ctx['azGid'][$gt] }
                    else { $gn = $tagToName[$gt]; if ($gn) { $gid = Resolve-PimLiveGroupIdByName $gn; if ($gid) { $ctx['azGid'][$gt] = $gid } } }
                }
                $rid = $null
                if ($scope -and $perm) { $rid = Resolve-PimArmRoleId -Scope $scope -RoleName $perm -Cache $ctx['armRoleCache'] }
                $row = $d | Select-Object *
                if ($gid -and $rid) {
                    Add-Member -InputObject $row -NotePropertyName principalId -NotePropertyValue $gid -Force
                    Add-Member -InputObject $row -NotePropertyName RoleId      -NotePropertyValue $rid -Force
                }
                $out.Add($row)
            }
            $out.ToArray()
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $tagToName = Get-PimTagToGroupName
            if (-not $ctx['azGid']) { $ctx['azGid'] = @{} }
            foreach ($t in @($tagToName.Keys)) {
                if ($ctx['azGid'].ContainsKey($t)) { continue }
                $gid = Resolve-PimLiveGroupIdByName $tagToName[$t]; if ($gid) { $ctx['azGid'][$t] = $gid }
            }
            $owned = Get-PimSolutionOwnedGroups
            # BUG-17. Two changes, both about not letting DESIRED define the live universe:
            #   * the SCOPES come from the Azure resource DEFINITIONS (plus whatever the
            #     assignment rows mention), not from the assignment rows alone -- so deleting
            #     an assignment row leaves its scope in view and the orphan is visible;
            #   * at each scope we list ALL PIM schedule instances ONCE and keep the ones held
            #     by a solution-owned group, instead of one filtered call per (scope, group).
            #     That is bounded by the number of DEFINED SCOPES, not by scopes x groups.
            $scopes = @{}
            foreach ($r in @(Get-PimDesiredRows -Entity 'PIM-Definitions-Resources')) {
                $s = "$(Get-PimRowProp -Row $r -Names @('AzScope','Scope','ResourceScope'))".Trim()
                if ($s -like '/subscriptions/*' -or $s -like '/providers/Microsoft.Management/*') { $scopes[$s] = $true }
            }
            foreach ($d in @(Get-PimDesiredRows -Entity 'PIM-Assignments-Azure-Resources')) {
                $s = "$(Get-PimRowProp -Row $d -Names @('AzScope'))".Trim(); if ($s) { $scopes[$s] = $true }
            }
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($scope in @($scopes.Keys)) {
                foreach ($pair in @(@{ ep='roleAssignmentScheduleInstances'; type='Active' }, @{ ep='roleEligibilityScheduleInstances'; type='Eligible' })) {
                    try {
                        foreach ($s in @(Invoke-PimArm -Path "$scope/providers/Microsoft.Authorization/$($pair.ep)" -ApiVersion '2020-10-01-preview' -All)) {
                            # NB: NOT $pid -- that is a read-only PowerShell automatic variable
                            # (the process id) and assigning to it throws. The throw landed in
                            # the catch below, so the whole live read came back EMPTY and silent.
                            $prin = "$($s.properties.principalId)"
                            if (-not $owned.byId.ContainsKey($prin)) { continue }        # not ours -- never a removal candidate
                            $atScope = "$($s.properties.scope)"; if (-not $atScope) { $atScope = $scope }
                            if ($atScope -ne $scope) { continue }                        # inherited from an ancestor; owned there, not here
                            $rid = ($s.properties.roleDefinitionId -split '/')[-1]
                            $live.Add([pscustomobject]@{ principalId=$prin; AzScope=$scope; RoleId=$rid; AssignmentType=$pair.type })
                        }
                    } catch { Write-Verbose "AzRes live ($scope/$($pair.ep)): $($_.Exception.Message)" }
                }
            }
            $live.ToArray()
        }
        KeyOf = {
            param($r)
            # ONE shape both sides produce: principal id | scope | role definition guid | type.
            $gid = Get-PimRowProp -Row $r -Names @('principalId')
            $scope = Get-PimRowProp -Row $r -Names @('AzScope')
            $type = (Get-PimRowProp -Row $r -Names @('AssignmentType')).ToLowerInvariant()
            $rid = "$(Get-PimRowProp -Row $r -Names @('RoleId'))"
            if ($gid -and $rid) { return "$gid|$($scope.ToLowerInvariant())|rid:$($rid.ToLowerInvariant())|$type" }
            # UNRESOLVED desired row (group not live yet, or the ARM role name did not resolve
            # at this scope) -> distinct by construction, so it becomes a create and can never
            # collide with a live key.
            $gt=(Get-PimRowProp -Row $r -Names @('GroupTag')).ToLowerInvariant(); $perm=(Get-PimRowProp -Row $r -Names @('AzScopePermission')).ToLowerInvariant()
            "unresolved:$gt|$($scope.ToLowerInvariant())|perm:$perm|$type"
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
function Assert-PimGroupPolicyPatchesApplied {
    <#
      BUG-52 -- turn collected rule-PATCH failures into a REAL failure for the item.

      The engine counts a provider's ApplyUpdate as applied unless it throws. So a swallowed
      PATCH error produced `applied=N errors=0` for work that never happened, and the scope
      printed its PLAN (`GroupsPolicies: c0/u112/r0`) as if it were the result. That is the
      condition that made a three-session non-convergence undiagnosable from the logs.

      Throwing here is deliberate over warning: "the policy is not what the template says" is not
      a degraded success, and the next run's diff will simply re-plan the item. Every failing rule
      is named in ONE message so a partially-applied policy is fully described rather than
      reported one rule at a time.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$GroupName, $Failures)
    $f = @($Failures)
    if (-not $f.Count) { return }
    throw ("GroupsPolicies '$GroupName': $($f.Count) rule PATCH(es) FAILED, so the policy does NOT " +
           "match the template: " + ($f -join ' | '))
}

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
# BUG-56 -- turning approval OFF, and getting out of a WRITE-LOCKED policy.
#
# Two facts, both measured live on throwaway roles in an isolated test tenant (2026-08-11).
# They are the whole reason these three helpers exist; do not "simplify" them away.
#
# 1. THE OFF BODY MUST BE COMPLETE. The obvious minimal merge -- setting.isApprovalRequired
#    = false on its own -- is rejected with `400 ArgumentNullException "Value cannot be null.
#    Parameter name: source"`. Entra wants the whole setting object, including an
#    approvalStages entry with an EMPTY primaryApprovers list. That reads like belt-and-braces
#    and is not: the short body simply does not work.
#
# 2. A POLICY CAN BE WRITE-LOCKED, AND THEN ONLY THE WHOLE-POLICY ROUTE WORKS. If a policy's
#    Notification_Approver_* rule ever ends up with isDefaultRecipientsEnabled=false AND a
#    non-empty recipient list, Entra treats that list as the policy's "activation custom
#    approvers" and refuses EVERY subsequent PATCH to /rules/{ruleId} with
#        400 ActivationCustomApproversNotEmpty "The activation custom approvers should be empty."
#    -- including rules that have nothing to do with approval (proven with an Expiration
#    rule), and including the PATCH that would clear the offending recipients. The poisoning
#    write itself is ACCEPTED, so nothing fails at the time it is done.
#    `PATCH /policies/roleManagementPolicies/{policyId}` with a `rules` COLLECTION stays open
#    in that state and is the only way back. It is also the only shape that can express
#    "approvers gone" and "approval not required" atomically, which is what the portal's
#    single Update does.
#
# The engine no longer ships that poisoning shape (guarded by
# tests/Test-PimPolicyTemplateSatisfiable.ps1), but a customer's policy can already be in the
# state -- set by hand in the portal, or by an older engine build -- so the recovery path has
# to exist rather than log the same refusal forever.
# ---------------------------------------------------------------------------
function New-PimApprovalOffRuleBody {
    # PURE: the approval rule body that turns approval OFF. Complete by necessity -- see (1).
    @{
        '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'
        id            = 'Approval_EndUser_Assignment'
        target        = @{ caller='EndUser'; operations=@('all'); level='Assignment'; inheritableSettings=@(); enforcedSettings=@() }
        setting       = @{
            isApprovalRequired               = $false
            isApprovalRequiredForExtension   = $false
            isRequestorJustificationRequired = $true
            approvalMode                     = 'NoApproval'
            approvalStages                   = @(@{
                approvalStageTimeOutInDays      = 1
                isApproverJustificationRequired = $true
                escalationTimeInMinutes         = 0
                isEscalationEnabled             = $false
                primaryApprovers                = @()
                escalationApprovers             = @()
            })
        }
    }
}
function Test-PimPolicyWriteLocked {
    # PURE: is this Graph failure the write-lock described in (2)? Matched on the error CODE
    # and on the message text, because the code is not always present in the surfaced string.
    param([string]$Message)
    return ("$Message" -match '(?i)ActivationCustomApproversNotEmpty|activation custom approvers should be empty')
}
function Set-PimPolicyRuleSet {
    # The whole-policy route. `rules` is a COLLECTION here, not a single rule.
    # A 1-element array survives as a JSON array because it is a hashtable PROPERTY -- the
    # ConvertTo-Json unwrap trap this codebase records applies to the PIPELINE form
    # (`@($x) | ConvertTo-Json`), not to this one. Verified before relying on it.
    param([Parameter(Mandatory)][string]$PolicyId, [Parameter(Mandatory)][object[]]$Rules)
    Invoke-PimGraph -Method PATCH -Path "/policies/roleManagementPolicies/$PolicyId" -Body @{ rules = @($Rules) } | Out-Null
}
function Repair-PimWriteLockedPolicy {
    <#
      Clear the POISON, not just the symptom.

      Working around a write-locked policy by routing one PATCH through the whole-policy
      endpoint leaves the offending Notification_Approver_* rule in place, so the NEXT run is
      locked again -- and the engine would quietly depend on the fallback forever. This flips
      the rule's isDefaultRecipientsEnabled back ON, which is the half that makes the pair
      poisonous, while KEEPING the recipient list: who gets told is a deliberate setting and
      losing it silently would be its own defect. `defaults=true` with explicit recipients is
      exactly what the shipped approval template uses and is measured safe.

      🪤 TWO THINGS ABOUT THE UNLOCK CALL, BOTH MEASURED LIVE AND BOTH COUNTER-INTUITIVE.
      1. IT MUST GO ALONE. The obvious version rode the caller's rule along in the same
         whole-policy PATCH so the unlock and the change would be atomic. That payload is
         REFUSED with the very error it is clearing; the identical PATCH carrying only the
         notification rule is ACCEPTED.
      2. THE RECIPIENTS CANNOT BE KEPT. The first version of this flipped
         isDefaultRecipientsEnabled back on and preserved the recipient list, on the theory that
         the FLAG was the poisonous half. It is not: on a clean policy, defaults=TRUE with two
         explicit Approver recipients locks it just as hard as defaults=false does, and
         defaults=false with an EMPTY list does not lock it at all. The RECIPIENT LIST ALONE is
         the trigger. So the list has to go, and it cannot be restored afterwards -- putting it
         back re-locks the policy immediately (observed: the unlock succeeded, the restore
         succeeded, and the very next per-rule PATCH was refused again).
         The removed addresses are therefore NAMED in a warning rather than dropped quietly.
         Approver notification then falls back to Entra's default routing, which is the only
         thing Entra actually supports for this rule.
      Returns $true when it sent something.
    #>
    param([Parameter(Mandatory)][string]$PolicyId)
    $rules = @()
    try { $rules = @((Invoke-PimGraph -Path "/policies/roleManagementPolicies/$PolicyId`?`$expand=rules").rules) }
    catch { Write-Verbose "write-lock repair: could not read policy ${PolicyId}: $($_.Exception.Message)" }

    $send = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($rules)) {
        if ("$($r.id)" -notlike 'Notification_Approver_*') { continue }
        # The RECIPIENT LIST is the trigger, on its own. isDefaultRecipientsEnabled is NOT part
        # of the test -- see (2) in the header.
        # 🪤 Filter blanks BEFORE counting: @($null).Count is 1, so a rule with no
        # notificationRecipients property at all would otherwise look poisoned and be "repaired".
        $lost = @($r.notificationRecipients | Where-Object { "$_".Trim() })
        if (-not $lost.Count) { continue }
        $lvl = ("$($r.id)" -split '_')[-1]
        if ($lvl -notin @('Assignment','Eligibility')) { continue }
        $nlvl = if ("$($r.notificationLevel)") { "$($r.notificationLevel)" } else { 'All' }
        $send.Add((New-PimGroupNotificationRuleBody -RecipientType 'Approver' -Level $lvl -NotificationLevel $nlvl `
                    -Recipients @() -DefaultRecipientsEnabled $true)) | Out-Null
        # NAME the addresses being removed. They cannot be kept (restoring them re-locks the
        # policy), so this is the only record that the redirect existed at all.
        Write-Warning ("  [engine] policy $PolicyId was WRITE-LOCKED by $($r.id): Entra treats an explicit " +
                       "Approver-notification recipient list as the policy's 'activation custom approvers' and then " +
                       'refuses every per-rule PATCH. REMOVING those recipients (' + ($lost -join ', ') + ') is the only ' +
                       'way to unlock it, and they CANNOT be restored -- approver notification falls back to Entra default ' +
                       'routing. See BUG-56.')
    }
    if (-not $send.Count) { return $false }
    Set-PimPolicyRuleSet -PolicyId $PolicyId -Rules $send.ToArray()
    return $true
}
function Invoke-PimPolicyRulePatch {
    <#
      PATCH one rule, and if the policy turns out to be WRITE-LOCKED, unlock it and apply the
      same rule in one whole-policy PATCH.

      Deliberately NOT a blanket retry: the fallback fires ONLY on the write-lock signature.
      Any other failure is re-thrown unchanged, so a genuine bad-payload error still surfaces
      as itself instead of being retried into a second, more confusing error.
    #>
    param(
        [Parameter(Mandatory)][string]$PolicyId,
        [Parameter(Mandatory)][object]$Body,
        [ref]$Recovered
    )
    try {
        Invoke-PimGraph -Method PATCH -Path "/policies/roleManagementPolicies/$PolicyId/rules/$($Body.id)" -Body $Body | Out-Null
        return
    } catch {
        if (-not (Test-PimPolicyWriteLocked $_.Exception.Message)) { throw }
    }
    # Write-locked. Clear the poison first (its own call -- see Repair-PimWriteLockedPolicy),
    # then re-apply the caller's rule normally, now that the policy accepts writes again.
    if (Repair-PimWriteLockedPolicy -PolicyId $PolicyId) {
        Invoke-PimGraph -Method PATCH -Path "/policies/roleManagementPolicies/$PolicyId/rules/$($Body.id)" -Body $Body | Out-Null
    }
    else {
        # Locked, but no poisoned Notification_Approver_* rule to explain it. Last resort: the
        # whole-policy route, which is the only shape that can express "approvers gone AND
        # approval not required" atomically. NOT live-proven for this case -- no way was found
        # to produce a lock without the notification pair -- so it is a fallback, not the path.
        Set-PimPolicyRuleSet -PolicyId $PolicyId -Rules @($Body)
    }
    if ($Recovered) { $Recovered.Value = $true }
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
    else {
        # BUG-56: a template WITHOUT an Approval block means approval must be OFF -- it does not
        # mean "don't look". The old behaviour ("the engine never touches an approval rule it did
        # not itself apply") left a live approval stranded and unmanaged forever, so the product
        # could switch a role INTO approval and never back out. That is exactly what happened to a
        # production role: it was the ONLY drifting role of 96, because every write to its policy
        # was being refused and nothing converged it.
        #
        # Stating the OFF expectation here is what makes it a detectable drift instead of a silent
        # nochange. It is a desired-state change, so it was WhatIf'd against production before
        # shipping: both policy scopes stayed at update=0 (no managed role or group currently
        # carries an approval the engine did not itself apply), i.e. it converges nothing today and
        # arms the engine for the case that previously stranded.
        $f['Approval_EndUser_Assignment'] = 'appr|required=false|approvers='
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
        if (-not $Live.ContainsKey($k)) {
            # BUG-56: ONE exception to "a desired facet missing live means drift" -- a policy that
            # carries NO approval rule at all already satisfies "approval must be OFF". Absence and
            # required=false are the same state, so demanding a PATCH here would be a write that
            # changes nothing, forever, on every policy that simply has no approval rule.
            # Narrow on purpose: it applies ONLY to the approval facet and ONLY to the OFF value.
            # A missing rule can never satisfy required=TRUE.
            if ($k -eq 'Approval_EndUser_Assignment' -and "$($Desired[$k])" -eq 'appr|required=false|approvers=') { continue }
            return $false
        }
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
            # 🔴 BUG-52 -- A SWALLOWED PATCH FAILURE IS WHY THIS SCOPE COULD NOT BE DIAGNOSED.
            # Every rule PATCH below used to be `try { ... } catch { Write-Verbose ... }`. Graph's
            # refusal therefore went to a stream nobody reads, the item still counted as APPLIED,
            # and the scope reported the PLAN as though it were the outcome -- `GroupsPolicies:
            # c0/u112/r0` with no indication that any of it failed. When the tenant then failed to
            # converge, the logs contained nothing to explain it, which sent a later session
            # chasing a non-existent security gap through the audit log instead (BUG-52's withdrawn
            # original text).
            # Failures are now COLLECTED and thrown together at the end of the item, so:
            #   * the engine counts the item as an ERROR, not an apply;
            #   * every failing rule is named in one message, instead of the first one aborting
            #     the rest -- a policy half-applied silently is worse than one that fails loudly;
            #   * a run that changes nothing can no longer look identical to one that worked.
            $ruleFailures = New-Object System.Collections.Generic.List[string]
            # --- v1 baseline: Enablement + Expiration + Notification on EVERY managed group ---
            # Member enablement (MFA / Justification) per target (EndUser/Assignment +
            # Admin/Eligibility get MFA+Justification; Admin/Assignment is cleared) from the template.
            foreach ($enBody in @(ConvertTo-PimEnablementRuleBodies -Enablement $d.Enablement -LegacyEndUserAssignment $d.EnablementLegacy)) {
                try { Invoke-PimPolicyRulePatch -PolicyId $polId -Body $enBody } catch { $ruleFailures.Add("enablement/$($enBody.id): $($_.Exception.Message)") | Out-Null }
            }
            # Member expiration (v1 parity: EndUser/activation P1D, Admin/Assignment + Admin/Eligibility
            # P365D, all isExpirationRequired) from the template.
            foreach ($exBody in @(ConvertTo-PimExpirationRuleBodies -Expiration $d.Expiration)) {
                try { Invoke-PimPolicyRulePatch -PolicyId $polId -Body $exBody } catch { $ruleFailures.Add("expiration/$($exBody.id): $($_.Exception.Message)") | Out-Null }
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
                        Invoke-PimPolicyRulePatch -PolicyId $polId -Body $nBody
                    } catch { $ruleFailures.Add("notification/$rt/${lvl}: $($_.Exception.Message)") | Out-Null }
                }
            }
            # --- Approval rule: ONLY when the template declares one (default-linked groups skip) ---
            # 🪤 BUG-52: this early `return` is the DEFAULT path (every default-linked group takes
            # it), so the failure check has to happen HERE as well as at the end -- putting it only
            # after the approval block would leave the common case silent, which is the exact
            # defect being fixed.
            if (-not $d.Approval) {
                # BUG-56 -- the same one-way defect the directory-role provider had. A template
                # with no Approval block means approval must be OFF, not "leave whatever is
                # there". Only written when the live policy actually HAS approval on, so the
                # common default-linked group still takes the cheap path and sends nothing.
                $liveApprovalOn = $false
                foreach ($r in @($item.live.Rules)) {
                    if ("$($r.id)" -ne 'Approval_EndUser_Assignment') { continue }
                    if ($r.setting -and [bool]$r.setting.isApprovalRequired) { $liveApprovalOn = $true }
                }
                if ($liveApprovalOn) {
                    try { Invoke-PimPolicyRulePatch -PolicyId $polId -Body (New-PimApprovalOffRuleBody) }
                    catch { $ruleFailures.Add("approval-off: $($_.Exception.Message)") | Out-Null }
                }
                Assert-PimGroupPolicyPatchesApplied -GroupName $gn -Failures $ruleFailures; return
            }
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
            # The approval PATCH is deliberately NOT wrapped: an approval rule that fails to apply
            # means the group is not actually approval-gated, which must stop the item outright.
            Invoke-PimPolicyRulePatch -PolicyId $polId -Body $body
            Assert-PimGroupPolicyPatchesApplied -GroupName $gn -Failures $ruleFailures
        }
    }
}

# ---------------------------------------------------------------------------
# EntraRolePolicies scope -- the PIM policy on an ENTRA DIRECTORY ROLE.
#
# WHY THIS EXISTS (operator, 2026-08-10): "we have a complete policy engine where we define
# explicitly how policies must be set, and it must verify it matches that at every run and set if
# not set. it is not ms standard." Until now the policy engine covered ONLY PIM-for-Groups member
# policies -- its single Graph filter was `scopeType eq 'Group' and roleDefinitionId eq 'member'`.
# Directory-role policies were never read and never written, so they sat at whatever Microsoft
# defaults to, unverified. Measured on the production tenant: Global Administrator, User
# Administrator and Helpdesk Administrator all carried Admin_Eligibility=[] / Admin_Assignment=[]
# purely because that is the Entra default -- not because anything had decided it.
#
# Directory-role policies are per-ROLE at TENANT scope (scopeId '/'); an AU-scoped assignment still
# activates through the role's tenant policy, so this manages one policy per managed role.
# ---------------------------------------------------------------------------
function Get-PimDirectoryRolePolicyId {
    param([Parameter(Mandatory)][string]$RoleDefinitionId)
    try {
        $a = @(Invoke-PimGraph -All -Path "/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$RoleDefinitionId'")
        if ($a.Count) { return "$($a[0].policyId)" }
    } catch { Write-Verbose "dir role policyId ($RoleDefinitionId): $($_.Exception.Message)" }
    return $null
}
function Get-PimManagedRolePolicyTargets {
    <#
      PURE-ish: the distinct set of directory ROLES the solution manages, with the policy template
      each one is linked to. Sources are the role-assignment entities, because a role the engine
      assigns is a role whose activation policy the engine is responsible for.

      Template selection: the row's PolicyTemplate column; blank -> 'EntraIDRoles_Standard'.
      CONFLICT RULE: if two rows name the same role with different templates, the one that requires
      APPROVAL wins and the conflict is reported. Silently picking either way would make a
      high-privilege role's approval requirement depend on row order.
    #>
    $byRole = @{}
    foreach ($ent in @('PIM-Assignments-Roles-Groups','PIM-Assignments-Roles-AUs')) {
        foreach ($r in @(Get-PimDesiredRows -Entity $ent | Where-Object { (Get-PimRowProp -Row $_ -Names @('Action')) -ne 'Remove' })) {
            $rn = "$(Get-PimRowProp -Row $r -Names @('RoleDefinitionName','RoleName'))".Trim()
            if (-not $rn) { continue }
            $tpl = "$(Get-PimRowProp -Row $r -Names @('PolicyTemplate'))".Trim()
            if (-not $tpl) { $tpl = 'EntraIDRoles_Standard' }
            $appr = "$(Get-PimRowProp -Row $r -Names @('ApproverUpns','Approvers'))".Trim()
            $noti = "$(Get-PimRowProp -Row $r -Names @('NotifyUpns'))".Trim()
            $k = $rn.ToLowerInvariant()
            if (-not $byRole.ContainsKey($k)) { $byRole[$k] = [pscustomobject]@{ RoleDefinitionName=$rn; TemplateId=$tpl; ApproverUpns=$appr; NotifyUpns=$noti } }
            elseif ($byRole[$k].TemplateId -ne $tpl) {
                $existing = $byRole[$k].TemplateId
                $wantsApproval = { param($t) "$t" -match '(?i)approval' }
                if ((& $wantsApproval $tpl) -and -not (& $wantsApproval $existing)) {
                    Write-Warning "  [engine] EntraRolePolicies: role '$rn' is linked to BOTH '$existing' and '$tpl' -- using '$tpl' (approval wins)."
                    $byRole[$k].TemplateId = $tpl
                    if ($appr) { $byRole[$k].ApproverUpns = $appr }
                } elseif (-not (& $wantsApproval $tpl) -and (& $wantsApproval $existing)) {
                    Write-Warning "  [engine] EntraRolePolicies: role '$rn' is linked to BOTH '$existing' and '$tpl' -- using '$existing' (approval wins)."
                } else {
                    Write-Warning "  [engine] EntraRolePolicies: role '$rn' is linked to BOTH '$existing' and '$tpl' -- using '$existing'."
                }
            }
            elseif ($appr -and -not $byRole[$k].ApproverUpns) { $byRole[$k].ApproverUpns = $appr }
            if ($noti -and -not $byRole[$k].NotifyUpns) { $byRole[$k].NotifyUpns = $noti }
        }
    }
    @($byRole.Values)
}
function New-PimEntraRolePoliciesProvider {
    @{
        scope = 'EntraRolePolicies'; entity = 'PIM-Assignments-Roles-Groups'; order = 75; refreshBefore = $true
        GetDesired = {
            param($ctx)
            $out = New-Object System.Collections.Generic.List[object]
            $script:PimRolePolicyNoAudience = New-Object System.Collections.Generic.List[string]
            foreach ($t in (Get-PimManagedRolePolicyTargets)) {
                $tpl = Get-PimEnginePolicyTemplate -Id $t.TemplateId
                if (-not $tpl) { Write-Warning "  [engine] EntraRolePolicies: unknown PolicyTemplate '$($t.TemplateId)' for role '$($t.RoleDefinitionName)' -- skipped."; continue }
                $hasApproval = $tpl.rules.ContainsKey('Approval')
                $approverIds = @()
                if ($hasApproval) {
                    foreach ($u in ("$($t.ApproverUpns)" -split '[|,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                        $oid = Resolve-PimPrincipalId $u; if ($oid) { $approverIds += $oid }
                    }
                }
                # Notification: resolve `recipientsSource` against the row. An approval rule whose
                # approvers are never NOTIFIED is an outage, not a control -- measured live: a real
                # selfActivate sat in PendingApproval while the approver got no mail, because Entra's
                # stock rule carries isDefaultRecipientsEnabled=true with an EMPTY explicit list and
                # relies purely on default routing. Naming the approvers as explicit recipients keeps
                # who-gets-told from diverging from who-can-approve. Real addresses come from the row,
                # never from the template (templates ship publicly).
                $notify = $null
                if ($tpl.rules.ContainsKey('Notification')) {
                    $notify = New-Object System.Collections.Generic.List[object]
                    foreach ($n in @($tpl.rules['Notification'])) {
                        $entry = $n | Select-Object *
                        $src = "$(if ($entry.PSObject.Properties['recipientsSource']) { $entry.recipientsSource } else { '' })".Trim()
                        if ($src -eq 'ApproverUpns') {
                            $ups = @("$($t.ApproverUpns)" -split '[|,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                            Add-Member -InputObject $entry -NotePropertyName recipients -NotePropertyValue $ups -Force
                        }
                        elseif ($src -eq 'NotifyUpns') {
                            # Who should hear about activations of THIS role. Separate from the
                            # approvers on purpose: plenty of roles need an audience without needing
                            # an approval gate.
                            $ups = @("$($t.NotifyUpns)" -split '[|,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                            Add-Member -InputObject $entry -NotePropertyName recipients -NotePropertyValue $ups -Force
                        }
                        # 🔒 NEVER SILENCE A NOTIFICATION. A rule with defaultRecipientsEnabled=false
                        # and NO resolved recipients tells Entra to mail nobody -- strictly worse than
                        # the default fan-out it was meant to replace, and invisible afterwards. When
                        # the redirect target cannot be resolved, leave the live rule alone.
                        $defOn = if ($entry.PSObject.Properties['defaultRecipientsEnabled']) { [bool]$entry.defaultRecipientsEnabled } else { $true }
                        $recipCount = @($entry.recipients | Where-Object { "$_".Trim() }).Count
                        if (-not $defOn -and $recipCount -eq 0) {
                            # An unconfigured opt-in is NOT a failure, so it gets ONE summary line at
                            # the end of the scope rather than a warning per role -- 95 identical
                            # warnings per run is how real ones get missed.
                            if ($null -eq $script:PimRolePolicyNoAudience) { $script:PimRolePolicyNoAudience = New-Object System.Collections.Generic.List[string] }
                            [void]$script:PimRolePolicyNoAudience.Add("$($t.RoleDefinitionName)")
                            continue
                        }
                        $notify.Add($entry)
                    }
                    $notify = $notify.ToArray()
                }
                $out.Add([pscustomobject]@{
                    GroupName    = $t.RoleDefinitionName          # reuse the facet builders' key field
                    RoleDefinitionName = $t.RoleDefinitionName
                    TemplateId   = $t.TemplateId
                    ApproverIds  = $approverIds
                    Approval     = $(if ($hasApproval) { $tpl.rules['Approval'] } else { $null })
                    Enablement   = $(if ($tpl.rules.ContainsKey('Enablement')) { $tpl.rules['Enablement'] } else { $null })
                    Expiration   = $(if ($tpl.rules.ContainsKey('Expiration')) { $tpl.rules['Expiration'] } else { $null })
                    Notification = $notify
                })
            }
            if ($script:PimRolePolicyNoAudience -and $script:PimRolePolicyNoAudience.Count) {
                $n = $script:PimRolePolicyNoAudience.Count
                $sample = ($script:PimRolePolicyNoAudience | Select-Object -First 3) -join ', '
                Write-Host ("    [engine] EntraRolePolicies: {0} role(s) have no NotifyUpns, so their activation " -f $n) -ForegroundColor DarkGray -NoNewline
                Write-Host ("notices keep Entra's DEFAULT recipients (i.e. the privileged admins). e.g. {0}{1}. " -f $sample, $(if ($n -gt 3) { ', ...' } else { '' })) -ForegroundColor DarkGray -NoNewline
                Write-Host "Set NotifyUpns on the role's assignment row to redirect them." -ForegroundColor DarkGray
            }
            $out.ToArray()
        }
        GetLive = {
            param($ctx)
            Ensure-PimContextLoaded
            $rolesByName = @{}; foreach ($r in @($Global:Roles_All_ID)) { $n = "$($r.DisplayName)"; if ($n) { $rolesByName[$n.ToLowerInvariant()] = "$($r.Id)" } }
            $ctx['rolePolRoleIds'] = $rolesByName
            $live = New-Object System.Collections.Generic.List[object]
            foreach ($t in (Get-PimManagedRolePolicyTargets)) {
                $rid = $rolesByName[$t.RoleDefinitionName.ToLowerInvariant()]
                if (-not $rid) { continue }   # role does not exist -> nothing live; the diff makes it a create and ApplyUpdate reports it
                $polId = Get-PimDirectoryRolePolicyId -RoleDefinitionId $rid
                if (-not $polId) { continue }
                $rules = @()
                try { $rules = @((Invoke-PimGraph -Path "/policies/roleManagementPolicies/$polId`?`$expand=rules").rules) }
                catch { Write-Verbose "dir role policy read ($($t.RoleDefinitionName)): $($_.Exception.Message)" }
                $live.Add([pscustomobject]@{ GroupName=$t.RoleDefinitionName; PolicyId=$polId; Rules=$rules })
            }
            $live.ToArray()
        }
        KeyOf = { param($r) (Get-PimRowProp -Row $r -Names @('GroupName','RoleDefinitionName')).ToLowerInvariant() }
        # Same pure facet comparison the group policies use -- the builders are keyed by RULE ID,
        # which is identical for group and directory-role policies.
        Equal = {
            param($d,$l)
            $want = Get-PimGroupPolicyDesiredFacets -Desired $d
            $have = Get-PimGroupPolicyLiveFacets -Rules $l.Rules
            Test-PimGroupPolicyInSync -Desired $want -Live $have
        }
        ApplyCreate = { param($item,$ctx) & (Get-PimEngineProvider -Scope 'EntraRolePolicies').ApplyUpdate $item $ctx }
        ApplyUpdate = {
            param($item,$ctx)
            $d = $item.desired; $rn = "$($d.RoleDefinitionName)"
            $rid = $ctx['rolePolRoleIds'][$rn.ToLowerInvariant()]
            if (-not $rid) { throw "EntraRolePolicies: directory role '$rn' not found in this tenant" }
            $polId = Get-PimDirectoryRolePolicyId -RoleDefinitionId $rid
            if (-not $polId) { throw "EntraRolePolicies: no roleManagementPolicy for directory role '$rn'" }

            # PATCH ONLY THE RULES THAT ACTUALLY DRIFTED.
            # Re-sending every rule because ONE drifted is not merely wasteful -- Graph rejects a
            # re-PATCH of an already-correct approval rule with
            #   400 ActivationCustomApproversNotEmpty "The activation custom approvers should be empty."
            # so a notification-only drift failed the whole update and left the role reported as
            # broken while nothing was actually wrong with it. Re-read live here (rather than trust
            # the diff's snapshot) so the comparison is against the state we are about to write to.
            $liveRules = @()
            try { $liveRules = @((Invoke-PimGraph -Path "/policies/roleManagementPolicies/$polId`?`$expand=rules").rules) }
            catch { Write-Verbose "role policy re-read ($rn): $($_.Exception.Message)" }
            $have = Get-PimGroupPolicyLiveFacets -Rules $liveRules
            $want = Get-PimGroupPolicyDesiredFacets -Desired $d
            $drifted = @{}
            foreach ($k in @($want.Keys)) {
                # Same BUG-56 exemption Test-PimGroupPolicyInSync makes, and for the same reason:
                # a policy carrying NO approval rule already satisfies "approval off". Without
                # this, any OTHER drift on such a policy would drag a pointless approval-off
                # PATCH along with it. Equal() and this loop must agree, or the item that Equal
                # called in-sync would be applied differently once something else drifted.
                if ($k -eq 'Approval_EndUser_Assignment' -and -not $have.ContainsKey($k) `
                    -and "$($want[$k])" -eq 'appr|required=false|approvers=') { continue }
                if (-not $have.ContainsKey($k) -or "$($have[$k])" -ne "$($want[$k])") { $drifted[$k] = $true }
            }
            if (-not $drifted.Count) { return [pscustomobject]@{ role=$rn; policyId=$polId; template=$d.TemplateId; note='already in sync' } }

            foreach ($enBody in @(ConvertTo-PimEnablementRuleBodies -Enablement $d.Enablement)) {
                if (-not $drifted.ContainsKey($enBody.id)) { continue }
                try { Invoke-PimPolicyRulePatch -PolicyId $polId -Body $enBody }
                catch { Write-Verbose "role enablement patch ($rn/$($enBody.id)): $($_.Exception.Message)" }
            }
            foreach ($exBody in @(ConvertTo-PimExpirationRuleBodies -Expiration $d.Expiration)) {
                if (-not $drifted.ContainsKey($exBody.id)) { continue }
                try { Invoke-PimPolicyRulePatch -PolicyId $polId -Body $exBody }
                catch { Write-Verbose "role expiration patch ($rn/$($exBody.id)): $($_.Exception.Message)" }
            }
            # Notification rules. NOT best-effort for the APPROVER rule: an approval whose approvers
            # are never told about the request is indistinguishable from a broken role.
            foreach ($n in @($d.Notification)) {
                $rt = "$($n.recipientType)"; $lvl = "$($n.level)"
                if (-not $rt -or -not $lvl) { continue }
                if (-not $drifted.ContainsKey("Notification_${rt}_EndUser_${lvl}")) { continue }
                $recips = @(); if ($n.recipients) { $recips = @($n.recipients) }
                $nlvl = if ("$($n.notificationLevel)") { "$($n.notificationLevel)" } else { 'All' }
                $defOn = if ($n.PSObject.Properties['defaultRecipientsEnabled']) { [bool]$n.defaultRecipientsEnabled } else { $true }
                $nBody = New-PimGroupNotificationRuleBody -RecipientType $rt -Level $lvl -NotificationLevel $nlvl -Recipients $recips -DefaultRecipientsEnabled $defOn
                try { Invoke-PimPolicyRulePatch -PolicyId $polId -Body $nBody }
                catch {
                    if ($rt -eq 'Approver') { throw "EntraRolePolicies: could not set the APPROVER notification rule on '$rn' ($($nBody.id)): $($_.Exception.Message). Refusing to leave an approval nobody is told about." }
                    # NOT Write-Verbose. A swallowed notification failure is how "applied=1, errors=0"
                    # was reported for a run that changed nothing -- measured: the Admin rule stayed
                    # at defaultRecipients=True while the engine claimed success. Whoever reads the
                    # run output must see that the redirect did not take.
                    Write-Warning ("  [engine] EntraRolePolicies: FAILED to set $($nBody.id) on '$rn' -- the notification " +
                                   "is UNCHANGED (still whatever Entra had): $($_.Exception.Message)")
                }
            }
            $approvalOff = $false
            if ($drifted.ContainsKey('Approval_EndUser_Assignment')) {
                if ($d.Approval) {
                    # An approval rule with ZERO approvers is rejected by Graph (InvalidPolicy), and
                    # silently skipping it would leave a high-privilege role WITHOUT the approval its
                    # template demands -- so this is a hard failure, not a Write-Verbose.
                    $approvers = @(); foreach ($oid in @($d.ApproverIds)) { $approvers += @{ '@odata.type'='#microsoft.graph.singleUser'; userId=$oid } }
                    if (-not $approvers.Count) {
                        throw "EntraRolePolicies: template '$($d.TemplateId)' requires approval for '$rn' but NO approver resolved (set ApproverUpns on the role-assignment row)."
                    }
                    $serial = ("$($d.Approval.mode)" -match '(?i)serial')
                    $escMin = 240; if ($d.Approval.escalationHours) { $escMin = [int]$d.Approval.escalationHours * 60 }
                    $body = @{ '@odata.type'='#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'; id='Approval_EndUser_Assignment'
                        target=@{ caller='EndUser'; operations=@('all'); level='Assignment'; inheritableSettings=@(); enforcedSettings=@() }
                        setting=@{ isApprovalRequired=$true; isApprovalRequiredForExtension=$false; isRequestorJustificationRequired=$true; approvalMode='SingleStage'
                            approvalStages=@(@{ approvalStageTimeOutInDays=1; isApproverJustificationRequired=$true; escalationTimeInMinutes=$(if ($serial) { $escMin } else { 0 }); isEscalationEnabled=$false; primaryApprovers=$approvers; escalationApprovers=@() }) } }
                    Invoke-PimPolicyRulePatch -PolicyId $polId -Body $body
                }
                else {
                    # BUG-56 -- SWITCHING A ROLE BACK OUT OF APPROVAL. This branch did not exist:
                    # the condition was `if ($d.Approval -and ...)`, so a role moved to a standard
                    # template kept its live approval forever and the product was one-way.
                    # Not best-effort. A role the operator has moved to a standard template but
                    # which still demands an approver is a role nobody can activate through the
                    # engine, so a failure here must stop the item rather than be logged and passed.
                    Invoke-PimPolicyRulePatch -PolicyId $polId -Body (New-PimApprovalOffRuleBody)
                    $approvalOff = $true
                }
            }
            $res = [pscustomobject]@{ role=$rn; policyId=$polId; template=$d.TemplateId }
            if ($approvalOff) { $res | Add-Member -NotePropertyName note -NotePropertyValue 'approval turned OFF' }
            $res
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
                # 🔴 -All IS LOAD-BEARING, and its absence made this scope a no-op.
                # Invoke-PimRest returns the RAW RESPONSE unless -All is passed (`if (-not $All)
                # { return $resp }`), so without it $taps was the response WRAPPER object, not the
                # TAP collection -- and @(wrapper).Count is 1 even when the user has NO TAP.
                # Every resolvable account was therefore classified as "already has a TAP", Equal
                # returned $true, and the scope reported c0/u0/r0 while minting nothing.
                # MEASURED in EFIF: four accounts with CreateTAP=TRUE sat at TAP=none across
                # repeated runs, each reporting AdminTap:c0/u0/r0 with no error. The only TAP that
                # ever appeared did so by ACCIDENT -- a freshly-created account is briefly
                # unresolvable, so it fell out of the live set and became a create candidate.
                # With -All the aggregated .value is returned, so an account with no TAP yields 0.
                # 🔴 BUG-66 -- "HAS A TAP" IS NOT "HAS A USABLE TAP", and the difference is whether
                # the admin can ever sign in again. This counted ANY temporaryAccessPassMethods
                # entry as satisfied, so an EXPIRED pass classified the account as done: the scope
                # reported ok=True on six consecutive runs against the live master while minting
                # nothing, and the admin had no route to a credential. Deleting the dead method by
                # hand re-armed it and the next tick minted one within seconds.
                # Entra reports usability directly (isUsable / methodUsabilityReason), so filter on
                # it: a dead pass now leaves the account OUT of the live set, which makes it a
                # create candidate and ApplyCreate replaces it.
                # 🪤 An UNREADABLE probe must count as SATISFIED, not as missing. If Graph errors
                # here, treating the account as "no TAP" would mint a fresh credential on every
                # tick for as long as the read keeps failing -- the runaway this scope must never
                # become. Failing closed costs a delayed re-issue; failing open mails credentials
                # in a loop.
                try {
                    $taps = @(Invoke-PimGraph -All -Path "/users/$uid/authentication/temporaryAccessPassMethods")
                    $usable = @($taps | Where-Object { "$($_.isUsable)" -match '(?i)true' })
                    if ($usable.Count) { $live.Add([pscustomobject]@{ UserPrincipalName=$upn }) }
                    elseif ($taps.Count) {
                        Write-Host "  [AdminTap] $upn holds a TAP that is NOT usable ($($taps[0].methodUsabilityReason)) -- replacing it." -ForegroundColor Yellow
                    }
                } catch {
                    # fail CLOSED (see above): unreadable => leave it in the live set => no mint.
                    $live.Add([pscustomobject]@{ UserPrincipalName=$upn })
                    Write-Verbose "TAP live ($upn): $($_.Exception.Message) -- treating as satisfied (fail-closed)"
                }
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

            # 🔴 BUG-66 -- REFUSE BEFORE MINTING when the mail cannot be delivered.
            # Now that GetLive replaces an EXPIRED pass, this scope re-mints on expiry -- which is
            # the behaviour that made the fix an operator decision in the first place: on a tenant
            # that cannot send mail, a self-healing scope mints a fresh UNDELIVERABLE credential
            # every cycle. Refusing first turns that runaway into one honest warning per run.
            # The guard is the SAME one the Manager's re-issue button uses (PIM-Notify.ps1), so the
            # two paths cannot disagree about whether a credential may be issued.
            $mgr = Get-PimRowProp -Row $d -Names @('ManagerEmail')
            if (Get-Command Test-PimTapMailReady -ErrorAction SilentlyContinue) {
                $mailChk = Test-PimTapMailReady -Recipient $mgr
                if (-not $mailChk.ok) {
                    # Not a throw: one unreachable admin must not fail the whole scope. Reported
                    # loudly, and NOTHING is created -- the existing (dead) pass is left untouched,
                    # which is strictly better than a live credential nobody received.
                    Write-Warning "  [AdminTap] $upn -- REFUSING to issue a TAP that cannot be delivered: $($mailChk.reason). Nothing was changed."
                    # 🔴 `return $null` HERE WAS COUNTED AS APPLIED. Measured live on EFIF 2026-08-25:
                    # the guard refused all six admins, printed "Nothing was changed" six times, and
                    # the run still summarised `applied=6 errors=0 ok=True`. Six dead accounts, a
                    # perfect green, on a 15-minute job -- the failure would never have surfaced.
                    # BUG-35a already built the convention for exactly this ("a handler that RETURNS
                    # WITHOUT ACTING must not be counted as applied") but its default is
                    # anything-that-is-not-pimApplied-false counts as applied, and **$null is
                    # 'anything'**. The refusal was written before that convention and never adopted
                    # it, so the loudest possible warning was reported as a success.
                    # 🪤 A refusal that reports success is worse than no guard at all: without the
                    # guard you get a bad credential you can see, with it you get a green you trust.
                    return [pscustomobject]@{ pimApplied = $false; reason = "$($mailChk.reason)" }
                }
            }

            # Entra allows exactly ONE TAP per user, so a dead pass must be REMOVED before a new
            # one can be created. This is the step that was done by hand to recover the master.
            try {
                foreach ($old in @(Invoke-PimGraph -All -Path "/users/$uid/authentication/temporaryAccessPassMethods")) {
                    if (-not "$($old.id)".Trim()) { continue }
                    Invoke-PimGraph -Method DELETE -Path "/users/$uid/authentication/temporaryAccessPassMethods/$($old.id)" | Out-Null
                    Write-Host "  [AdminTap] $upn -- removed the previous TAP ($($old.methodUsabilityReason))." -ForegroundColor DarkGray
                }
            } catch { Write-Verbose "TAP delete ($upn): $($_.Exception.Message)" }

            $body=@{ isUsableOnce=$false; lifetimeInMinutes=($hrs*60) }
            $tap = Invoke-PimGraph -Method POST -Path "/users/$uid/authentication/temporaryAccessPassMethods" -Body $body
            # deliver the TAP by mail (best-effort) -- to the admin's manager
            if (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue) {
                # $mgr is already resolved above -- the refuse-before-minting guard needs it BEFORE
                # anything is created, so re-reading it here would be a second source of truth.
                # {{TapExpiresUtc}} is IN the shipped tap-delivery template, and this used to pass
                # it as a hardcoded '' -- so every TAP mail ever sent rendered an EMPTY "expires at".
                # The recipient got a code with no deadline, which is the one fact a time-boxed
                # credential has to carry. Reported by the operator on the first mail that actually
                # arrived, 2026-08-12. Computed from the values Graph returns on the TAP itself.
                $__tapMins = 0; [void][int]::TryParse("$($tap.lifetimeInMinutes)", [ref]$__tapMins)
                $__tapStart = $null
                if ("$($tap.startDateTime)".Trim()) {
                    try { $__tapStart = [datetime]::Parse("$($tap.startDateTime)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() } catch { $__tapStart = $null }
                }
                # Fall back to "now" only when Graph gave no parseable start: the TAP was minted
                # moments ago, so now+lifetime is accurate to seconds -- and a near-exact deadline
                # is far more useful to the recipient than the blank this replaces.
                if (-not $__tapStart) { $__tapStart = [datetime]::UtcNow }
                $__tapExpires = if ($__tapMins -gt 0) { $__tapStart.AddMinutes($__tapMins).ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' } else { '' }
                $toks = @{ UserPrincipalName=$upn; TapCode="$($tap.temporaryAccessPass)"; TapStartLocal="$($tap.startDateTime)"; TapStartUtc="$($tap.startDateTime)"; TapLifetimeMinutes="$($tap.lifetimeInMinutes)"; TapExpiresUtc=$__tapExpires }
                # THE RESULT IS NOT OPTIONAL INFORMATION, and piping it to Out-Null hid the one
                # failure this scope must never hide. Send-PimNotifyMail NEVER throws for a
                # refused send -- an allowlist miss, a kill switch flipped between the pre-check
                # and the send, a template that vanished, or a Graph 4xx all come back as
                # sent=$false in the RETURN VALUE. Discarding it meant the scope reported
                # applied=1 / ok=True over a live credential nobody received, with the previous
                # pass already deleted -- the exact outcome BUG-66's refuse-before-minting guard
                # exists to prevent, arriving one step later than the guard can see. The guard
                # answers "may we issue?"; nothing answered "did it actually get there?".
                # This cannot be undone here (the old pass is gone by now), so the only correct
                # action is to say so LOUDLY, naming the account, the recipient and the reason.
                # Measured 2026-08-21 on the live master: the happy path returns sent=True.
                $mailRes = $null
                try { $mailRes = Send-PimNotifyMail -Type 'tap-delivery' -Tokens $toks -Recipient $mgr } catch { Write-Verbose "tap mail ($upn): $($_.Exception.Message)" }
                if ("$($mailRes.sent)" -notmatch '(?i)true') {
                    $why = if ("$($mailRes.reason)".Trim()) { "$($mailRes.reason)" } else { 'the send threw' }
                    Write-Warning "  [AdminTap] $upn -- a TAP WAS MINTED but the mail to '$mgr' did NOT go out: $why. A live credential now exists that nobody received -- delete it, or re-issue from the Manager's Accounts & TAP tab once mail works."
                }
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
        if (-not $when) { $when = Get-PimUtcStamp $od }   # IMP-02: unreadable -> no offboard
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
                # BUG-35a: tell the core this was NOT applied, so the summary cannot report a
                # removal that never left the building.
                return [pscustomobject]@{ pimApplied = $false; reason = 'auto-offboarding disabled' }
            }
            $mode = "$($ctx['offboardMode'])"; if (-not $mode) { $mode = "$($global:PIM_OffboardCleanupMode)" }; if (-not $mode) { $mode = 'Report' }
            $l = $item.live
            if ($mode -notmatch '(?i)^enforce') {
                Write-Host ("    [report] would offboard: {0} -> {1} ({2}, {3})" -f $l.UserPrincipalName, $l.GroupTag, $l.AssignmentType, $l.Reason) -ForegroundColor DarkYellow
                # BUG-35a: REPORT mode changes nothing, so it must not be counted as applied.
                # The detail line above was always honest ("would offboard"), but the run summary
                # still said `remove=1 applied=1` -- identical to a run that really revoked. The
                # summary is the number an operator reads, and a dry run must not look like a
                # change there. Verified both ways on one tenant: Report -> eligibility unchanged,
                # Enforce -> eligibility 1 -> 0.
                return [pscustomobject]@{ pimApplied = $false; reason = "offboardMode=$mode (report only)" }
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
    Register-PimEngineProvider -Provider (New-PimAuMembersProvider)             # order 22 (BUG-16: AU membership is RECONCILED, not create-time-only)
    Register-PimEngineProvider -Provider (New-PimGroupOwnersProvider)           # order 25
    Register-PimEngineProvider -Provider (New-PimAdminsProvider)                # order 30
    Register-PimEngineProvider -Provider (New-PimAdminTapProvider)              # order 35
    Register-PimEngineProvider -Provider (New-PimEntraRolesProvider)            # order 40
    Register-PimEngineProvider -Provider (New-PimRolesAUsProvider)              # order 45
    Register-PimEngineProvider -Provider (New-PimEntraRolePoliciesProvider)     # order 75 -- Entra ROLE policies
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
