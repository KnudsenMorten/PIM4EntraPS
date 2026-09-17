#Requires -Version 5.1
<#
  PIM4EntraPS -- THE SQL ADMIN GROUP (2026-09-15). Dot-sourced by Initialize-PimSqlAdminGroup.ps1,
  Deploy-PimUpdateJob.ps1 and New-PimHostingPrerequisites.ps1; offline-tested by
  tests/Test-PimSqlAdminGroup.ps1.

  Operator, 2026-09-15: "remember we have a sql admin group where the managed identity + the
  troubleshooting spn must be member, same as in internal. efif and ride must be similar, and the
  updater logic must handle this so we are ready to roll this out to ring 2 very soon".

  THE MODEL
    Azure SQL allows exactly ONE Entra admin. Giving it to ONE principal (the deploy SPN on public SQL, a
    SQL user-assigned identity on private SQL) meant every other identity that must administer the
    database -- the unattended updater's schema step, the operator's troubleshooting identity -- needed a
    contained user created by that one principal, and an environment whose admin was a secret-only app
    could not be fixed unattended at all (EFIF/RIDE, UPD-15). The admin is therefore a SECURITY GROUP,
    default 'grp-pim-sql-admins', whose members are:
      * the environment's user-assigned identity  id-pim-<token>
      * the updater job's system-assigned identity (ca-pim-update)
      * the in-VNet SQL identity id-pim-sql-<token> on private SQL, so the in-cloud bootstrap still works
      * the troubleshooting identity (by appId or object id), when given
      * the previous admin, so converging never takes access away from whoever had it
    Contained users that exist keep working; nothing here drops one.

  GRAPH / ARM FACTS THIS HANDLES, EACH MEASURED LIVE ON EFIF + RIDE 2026-09-15
    1. GET /groups/{id}/members returned 0 items for SERVICE-PRINCIPAL members with an app-only token,
       while /groups/{id}/members/microsoft.graph.servicePrincipal listed them. Membership is read
       through the TYPED casts (servicePrincipal, user, group), unioned with the untyped list.
    2. Adding a member that is already there answers an error containing "already exist" -- success.
    3. PUT .../administrators/ActiveDirectory is asynchronous (202): the new admin is POLLED on read-back.
    4. A naive "keep the current admin as a member" step added the group to ITSELF when the admin already
       was the group. The plan refuses any member whose object id is the group's.

  Certificate or managed-identity auth only: the invokers take a token from the signed-in az context
  (which the deploy scripts sign in with a certificate) or mint one from a certificate in the local
  store. There is no client-secret parameter anywhere in this file.
  ASCII only: read by Windows PowerShell 5.1 on deploy hosts.
#>

Set-StrictMode -Off

$script:PimSqlAdminGroupDefaultName = 'grp-pim-sql-admins'
$script:PimSqlApi  = '2021-11-01'
$script:PimMiApi   = '2023-01-31'
$script:PimJobApi  = '2024-03-01'
$script:PimGraphBase = 'https://graph.microsoft.com/v1.0'

function Test-PimSqlAdminGuid {
    param([AllowEmptyString()][AllowNull()][string]$Value)
    $g = [guid]::Empty
    return ([bool]"$Value".Trim() -and [guid]::TryParse("$Value".Trim(), [ref]$g))
}

function Test-PimSqlAdminPermissionError {
    <# PURE. Is this error text Graph/ARM refusing the CALLER (not a missing object)? #>
    param([AllowEmptyString()][string]$Text)
    return ("$Text" -match '(?i)Authorization_RequestDenied|Insufficient privileges|HTTP 403\b|AuthorizationFailed|\bForbidden\b')
}

function Get-PimSqlAdminGroupPlan {
    <#
      PURE. What converging an environment's SQL admin onto the group would change.
        -Group          : $null (absent) or { id; displayName }
        -CurrentMemberIds : object ids already in the group (typed-cast read)
        -DesiredMembers : @{ objectId; label } -- duplicates collapse, first label wins
        -CurrentAdmin   : $null (no Entra admin) or { sid; login; objectId } where objectId is the sid
                          resolved to a directory object ('' when it could not be resolved)
        -Mode           : converge     -- create the group if absent, add members, make it the admin
                          membersOnly  -- only add members, and only when the group already IS the admin
      Returns { mode; groupName; groupId; createGroup; add; present; refused; keepCurrentAdmin; adminIsGroup;
                setAdmin; blocked; changes; messages }.
    #>
    param(
        [string]$GroupName = 'grp-pim-sql-admins',
        [object]$Group,
        [AllowEmptyCollection()][string[]]$CurrentMemberIds = @(),
        [AllowEmptyCollection()][object[]]$DesiredMembers = @(),
        [object]$CurrentAdmin,
        [ValidateSet('converge', 'membersOnly')][string]$Mode = 'converge',
        [switch]$DoNotKeepCurrentAdmin
    )
    $msgs    = New-Object System.Collections.Generic.List[string]
    $add     = New-Object System.Collections.Generic.List[object]
    $present = New-Object System.Collections.Generic.List[object]
    $refused = New-Object System.Collections.Generic.List[object]
    $gid = if ($Group -and "$($Group.id)".Trim()) { "$($Group.id)".Trim() } else { '' }
    $adminSid = if ($CurrentAdmin) { "$($CurrentAdmin.sid)".Trim() } else { '' }
    $adminOid = if ($CurrentAdmin) { "$($CurrentAdmin.objectId)".Trim() } else { '' }
    $adminLogin = if ($CurrentAdmin) { "$($CurrentAdmin.login)".Trim() } else { '' }
    $adminIsGroup = [bool]($gid -and (($adminSid -and $adminSid -ieq $gid) -or ($adminOid -and $adminOid -ieq $gid)))
    $blocked = ''
    $keep = $null

    if ($Mode -eq 'membersOnly') {
        if (-not $gid) {
            $blocked = "the SQL admin group '$GroupName' does not exist -- nothing to join (Initialize-PimSqlAdminGroup.ps1 converges an environment onto it)"
        } elseif (-not $adminIsGroup) {
            $who = if ($adminLogin) { "'$adminLogin'" } elseif ($adminSid) { $adminSid } else { 'nobody' }
            $blocked = "'$GroupName' is not this SQL server's Entra admin (the admin is $who) -- membership would grant nothing, so none is added"
        }
        if ($blocked) {
            [void]$msgs.Add($blocked)
            return [pscustomobject]@{ mode = $Mode; groupName = $GroupName; groupId = $gid; createGroup = $false
                add = @(); present = @(); refused = @(); keepCurrentAdmin = $null; adminIsGroup = $adminIsGroup
                setAdmin = $false; blocked = $blocked; changes = 0; messages = @($msgs.ToArray()) }
        }
    }

    $wanted = New-Object System.Collections.Generic.List[object]
    foreach ($m in @($DesiredMembers)) { if ($null -ne $m) { [void]$wanted.Add($m) } }
    if ($Mode -eq 'converge' -and $CurrentAdmin -and -not $adminIsGroup -and -not $DoNotKeepCurrentAdmin) {
        if ($adminOid) {
            $keep = [pscustomobject]@{ objectId = $adminOid; label = "previous SQL admin ($(if ($adminLogin) { $adminLogin } else { $adminSid }))" }
            [void]$wanted.Add($keep)
        } else {
            $blocked = "the current SQL admin '$adminLogin' ($adminSid) could not be resolved to a directory object, so it cannot be kept as a member -- REFUSING to move the admin (it would lose access)"
            [void]$msgs.Add($blocked)
        }
    }

    $have = @{}
    foreach ($id in @($CurrentMemberIds)) { if ("$id".Trim()) { $have["$id".Trim().ToLowerInvariant()] = $true } }
    $seen = @{}
    foreach ($m in $wanted) {
        $oid = "$($m.objectId)".Trim()
        $label = if ("$($m.label)".Trim()) { "$($m.label)".Trim() } else { $oid }
        if (-not (Test-PimSqlAdminGuid $oid)) {
            [void]$refused.Add([pscustomobject]@{ objectId = $oid; label = $label; reason = 'not an object id' }); continue
        }
        $k = $oid.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        if ($gid -and $k -eq $gid.ToLowerInvariant()) {
            [void]$refused.Add([pscustomobject]@{ objectId = $oid; label = $label; reason = 'is the group itself -- a group is never made a member of itself' })
            continue
        }
        $entry = [pscustomobject]@{ objectId = $oid; label = $label }
        if ($have.ContainsKey($k)) { [void]$present.Add($entry) } else { [void]$add.Add($entry) }
    }
    foreach ($r in $refused) { [void]$msgs.Add("refused member $($r.label): $($r.reason)") }

    $create = ($Mode -eq 'converge' -and -not $gid)
    $setAdmin = ($Mode -eq 'converge' -and -not $adminIsGroup -and -not $blocked)
    if ($create)   { [void]$msgs.Add("create security group '$GroupName'") }
    foreach ($a in $add) { [void]$msgs.Add("add member $($a.label) ($($a.objectId))") }
    if ($setAdmin) { [void]$msgs.Add("make '$GroupName' the SQL server's Entra admin (was $(if ($adminLogin) { "'$adminLogin'" } else { 'none' }))") }
    $changes = [int]$create + $add.Count + [int]$setAdmin
    if (-not $changes -and -not $blocked) { [void]$msgs.Add("no changes -- '$GroupName' is the admin and holds every member") }
    return [pscustomobject]@{
        mode = $Mode; groupName = $GroupName; groupId = $gid; createGroup = $create
        add = @($add.ToArray()); present = @($present.ToArray()); refused = @($refused.ToArray())
        keepCurrentAdmin = $keep; adminIsGroup = $adminIsGroup; setAdmin = $setAdmin; blocked = $blocked
        changes = $changes; messages = @($msgs.ToArray())
    }
}

function Get-PimGraphGroupMemberIds {
    <#
      Object ids of a group's members, read through the TYPED casts (Graph fact 1: the untyped list
      returned 0 service principals app-only) and unioned with the untyped list. Follows paging.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$GroupId)
    $ids = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($suffix in @('/microsoft.graph.servicePrincipal', '/microsoft.graph.user', '/microsoft.graph.group', '')) {
        $path = "/groups/$GroupId/members$suffix" + '?$select=id&$top=999'
        $guard = 0
        while ($path -and $guard -lt 50) {
            $guard++
            $page = & $Graph -Method GET -Path $path
            foreach ($o in @($page.value)) {
                $id = "$($o.id)".Trim()
                if ($id -and -not $seen.ContainsKey($id.ToLowerInvariant())) { $seen[$id.ToLowerInvariant()] = $true; [void]$ids.Add($id) }
            }
            $next = ''
            if ($page -and $page.PSObject.Properties['@odata.nextLink']) { $next = "$($page.'@odata.nextLink')" }
            $path = if ($next) { $next } else { '' }
        }
    }
    return @($ids.ToArray())
}

function Resolve-PimDirectoryObjectId {
    <#
      A SQL admin 'sid' is a directory object id, or for some applications their APP id. Try the object id
      first, then the app id. Returns '' when neither resolves.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [AllowEmptyString()][string]$Sid)
    $s = "$Sid".Trim()
    if (-not (Test-PimSqlAdminGuid $s)) { return '' }
    try { $o = & $Graph -Method GET -Path ("/directoryObjects/$s" + '?$select=id'); if ("$($o.id)".Trim()) { return "$($o.id)".Trim() } } catch { }
    try { $o = & $Graph -Method GET -Path ("/servicePrincipals(appId='$s')" + '?$select=id'); if ("$($o.id)".Trim()) { return "$($o.id)".Trim() } } catch { }
    return ''
}

function Resolve-PimServicePrincipalObjectId {
    <# The service principal object id for an app id. Throws when it does not exist. #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$AppId)
    $o = & $Graph -Method GET -Path ("/servicePrincipals(appId='$("$AppId".Trim())')" + '?$select=id,displayName')
    if (-not "$($o.id)".Trim()) { throw "no service principal for app id $AppId" }
    return "$($o.id)".Trim()
}

function Resolve-PimSqlServerFromFqdn {
    <#
      The SQL server resource for an FQDN or bare name, searched across the subscription (the server may
      live in another resource group). Returns { id; name; resourceGroup } or $null.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$Server)
    $name = ("$Server".Trim() -replace '^tcp:', '' -replace ',\d+$', '').Split('.')[0].ToLowerInvariant()
    if (-not $name) { return $null }
    $list = & $Arm -Method GET -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Sql/servers?api-version=$($script:PimSqlApi)"
    foreach ($s in @($list.value)) {
        if ("$($s.name)".ToLowerInvariant() -eq $name) {
            $rg = ''
            if ("$($s.id)" -match '(?i)/resourceGroups/([^/]+)/') { $rg = $Matches[1] }
            return [pscustomobject]@{ id = "$($s.id)"; name = "$($s.name)"; resourceGroup = $rg }
        }
    }
    return $null
}

function Invoke-PimSqlAdminGroup {
    <#
      Converge (or, -Mode membersOnly, join) an environment's SQL admin group. Reads everything first,
      plans with Get-PimSqlAdminGroupPlan, applies, then READS EVERYTHING BACK. Never throws for a Graph
      or ARM refusal -- returns { ok; applied; permissionDenied; problems } so a caller decides.
        -Graph / -Arm : scriptblocks param([string]$Method, [string]$Path, [object]$Body) that return the
                        parsed response and throw "<METHOD> <path> -> HTTP <code> : <detail>" on failure
        -Members      : @{ objectId; label }
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Graph,
        [Parameter(Mandatory)][scriptblock]$Arm,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$SqlServerName,
        [Parameter(Mandatory)][string]$TenantId,
        [string]$GroupName = 'grp-pim-sql-admins',
        [string]$GroupObjectId,
        [AllowEmptyCollection()][object[]]$Members = @(),
        [ValidateSet('converge', 'membersOnly')][string]$Mode = 'converge',
        [switch]$DoNotKeepCurrentAdmin,
        [switch]$PlanOnly,
        [int]$PollSeconds = 5,
        [int]$PollCount = 36,
        [scriptblock]$Sleep = { param([int]$Seconds) Start-Sleep -Seconds $Seconds }
    )
    $problems = New-Object System.Collections.Generic.List[string]
    $notes    = New-Object System.Collections.Generic.List[string]
    $state    = @{ denied = $false }
    $srvPath  = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Sql/servers/$SqlServerName"
    $result = {
        param($plan, $applied, $extra)
        $o = [ordered]@{
            ok = ($problems.Count -eq 0); applied = [bool]$applied; permissionDenied = [bool]$state.denied
            groupName = $GroupName; groupId = $(if ($plan) { "$($plan.groupId)" } else { '' })
            created = $false; added = @(); present = @(); refused = @(); adminChanged = $false
            adminBefore = ''; adminIsGroup = $false; adAuthOnlyBefore = $null; adAuthOnlyAfter = $null
            blocked = $(if ($plan) { "$($plan.blocked)" } else { '' }); plan = $plan
            problems = @($problems.ToArray()); notes = @($notes.ToArray())
        }
        foreach ($e in @($extra)) { if ($e) { foreach ($k in @($e.Keys)) { $o[$k] = $e[$k] } } }
        [pscustomobject]$o
    }
    $fail = {
        param([string]$What, $Err)
        $t = "$Err"
        if (Test-PimSqlAdminPermissionError $t) { $state.denied = $true }
        [void]$problems.Add("$What`: $t")
    }

    # ---- read: the group --------------------------------------------------------------------------
    $group = $null
    try {
        if ("$GroupObjectId".Trim()) {
            $group = & $Graph -Method GET -Path ("/groups/$("$GroupObjectId".Trim())" + '?$select=id,displayName,securityEnabled')
            if ($group -and "$($group.displayName)".Trim()) { $GroupName = "$($group.displayName)".Trim() }
        } else {
            $flt = [uri]::EscapeDataString("displayName eq '$($GroupName.Replace("'", "''"))'")
            $found = @((& $Graph -Method GET -Path ('/groups?$filter=' + $flt + '&$select=id,displayName,securityEnabled')).value | Where-Object { $_ })
            if ($found.Count -gt 1) {
                [void]$problems.Add("$($found.Count) groups are named '$GroupName' -- ambiguous; pass -GroupObjectId")
                return (& $result $null $false @{})
            }
            if ($found.Count -eq 1) { $group = $found[0] }
        }
        if ($group -and $group.PSObject.Properties['securityEnabled'] -and $group.securityEnabled -eq $false) {
            [void]$problems.Add("'$GroupName' ($($group.id)) is not a SECURITY group -- Azure SQL cannot use it as an admin")
            return (& $result $null $false @{})
        }
    } catch { & $fail "read group '$GroupName'" $_.Exception.Message; return (& $result $null $false @{}) }

    # ---- read: the current Entra admin and AD-only -----------------------------------------------
    $admin = $null
    try {
        $list = & $Arm -Method GET -Path "$srvPath/administrators?api-version=$($script:PimSqlApi)"
        $a = @($list.value | Where-Object { $_ }) | Select-Object -First 1
        if ($a) {
            $sid = "$($a.properties.sid)".Trim()
            $oid = if ($group -and $sid -ieq "$($group.id)") { $sid } else { Resolve-PimDirectoryObjectId -Graph $Graph -Sid $sid }
            $admin = [pscustomobject]@{ sid = $sid; login = "$($a.properties.login)"; objectId = $oid }
        }
    } catch { & $fail "read the Entra admin of $SqlServerName" $_.Exception.Message; return (& $result $null $false @{}) }
    $adOnlyBefore = $null
    try {
        $ao = & $Arm -Method GET -Path "$srvPath/azureADOnlyAuthentications/Default?api-version=$($script:PimSqlApi)"
        if ($ao -and $ao.properties -and $null -ne $ao.properties.azureADOnlyAuthentication) { $adOnlyBefore = [bool]$ao.properties.azureADOnlyAuthentication }
    } catch { [void]$notes.Add("Entra-only authentication could not be read before: $($_.Exception.Message)") }

    # ---- read: members ----------------------------------------------------------------------------
    $memberIds = @()
    if ($group) {
        try { $memberIds = @(Get-PimGraphGroupMemberIds -Graph $Graph -GroupId "$($group.id)") }
        catch { & $fail "read members of '$GroupName'" $_.Exception.Message; return (& $result $null $false @{}) }
    }

    $plan = Get-PimSqlAdminGroupPlan -GroupName $GroupName -Group $group -CurrentMemberIds $memberIds -DesiredMembers $Members `
                -CurrentAdmin $admin -Mode $Mode -DoNotKeepCurrentAdmin:$DoNotKeepCurrentAdmin
    $base = @{ adminBefore = $(if ($admin) { "$($admin.login)" } else { '' }); adminIsGroup = $plan.adminIsGroup; adAuthOnlyBefore = $adOnlyBefore
               present = @($plan.present); refused = @($plan.refused) }
    if ($Mode -eq 'converge' -and $plan.blocked) { [void]$problems.Add($plan.blocked) }
    if ($PlanOnly -or ($Mode -eq 'membersOnly' -and $plan.blocked)) { return (& $result $plan $false $base) }

    # ---- apply: the group -------------------------------------------------------------------------
    $gid = "$($plan.groupId)"
    $created = $false
    if ($plan.createGroup) {
        $nick = (($GroupName -replace '[^A-Za-z0-9]', '').ToLowerInvariant())
        if (-not $nick) { $nick = 'pimsqladmins' }
        try {
            $g = & $Graph -Method POST -Path '/groups' -Body ([ordered]@{
                    displayName = $GroupName; mailEnabled = $false; mailNickname = $nick; securityEnabled = $true
                    description = 'PIM4EntraPS: Entra admin of the environment SQL server (managed identities + troubleshooting identity).' })
            $gid = "$($g.id)".Trim()
            if (-not $gid) { throw 'the create returned no id' }
            $created = $true
            # A new group is not readable everywhere at once; wait until it is before adding members.
            $seenGroup = $false
            for ($i = 0; $i -lt $PollCount; $i++) {
                try { $gr = & $Graph -Method GET -Path ("/groups/$gid" + '?$select=id'); if ("$($gr.id)" -ieq $gid) { $seenGroup = $true; break } } catch { }
                & $Sleep $PollSeconds
            }
            if (-not $seenGroup) { [void]$notes.Add("the new group $gid was not readable after $($PollCount * $PollSeconds)s -- continuing") }
        } catch {
            & $fail "create group '$GroupName'" $_.Exception.Message
            return (& $result $plan $false @($base, @{ created = $false }))
        }
    }

    # ---- apply: members (Graph fact 2: "already exist" is success) -------------------------------
    $added = New-Object System.Collections.Generic.List[object]
    foreach ($m in @($plan.add)) {
        if ("$($m.objectId)" -ieq $gid) { continue }   # Graph fact 4, re-checked against a freshly created id
        $ok = $false; $last = ''
        foreach ($d in @(0, 5, 10, 20)) {
            if ($d) { & $Sleep $d }
            try {
                [void](& $Graph -Method POST -Path "/groups/$gid/members/`$ref" -Body @{ '@odata.id' = "$($script:PimGraphBase)/directoryObjects/$($m.objectId)" })
                $ok = $true; break
            } catch {
                $last = "$($_.Exception.Message)"
                if ($last -match '(?i)already exist') { $ok = $true; break }
                if (Test-PimSqlAdminPermissionError $last) { break }
                if ($last -notmatch '(?i)HTTP 404\b|Request_ResourceNotFound|does not exist') { break }   # only replication lag is retried
            }
        }
        if ($ok) { [void]$added.Add($m) } else { & $fail "add $($m.label) ($($m.objectId)) to '$GroupName'" $last }
    }

    # ---- apply: the Entra admin (ARM fact 3: asynchronous) ---------------------------------------
    $adminChanged = $false
    if ($plan.setAdmin -and -not $problems.Count) {
        try {
            [void](& $Arm -Method PUT -Path "$srvPath/administrators/ActiveDirectory?api-version=$($script:PimSqlApi)" -Body ([ordered]@{
                        properties = [ordered]@{ administratorType = 'ActiveDirectory'; login = $GroupName; sid = $gid; tenantId = $TenantId } }))
            $adminChanged = $true
        } catch { & $fail "make '$GroupName' the Entra admin of $SqlServerName" $_.Exception.Message }
    } elseif ($plan.setAdmin) {
        [void]$notes.Add("the Entra admin was NOT moved to '$GroupName' because a member could not be added -- the previous admin keeps it")
    }

    # ---- read back ------------------------------------------------------------------------------
    $adminIsGroupAfter = [bool]$plan.adminIsGroup
    if ($gid -and ($adminChanged -or $plan.adminIsGroup)) {
        $adminIsGroupAfter = $false
        for ($i = 0; $i -lt $PollCount; $i++) {
            try {
                $cur = & $Arm -Method GET -Path "$srvPath/administrators/ActiveDirectory?api-version=$($script:PimSqlApi)"
                if ("$($cur.properties.sid)".Trim() -ieq $gid) { $adminIsGroupAfter = $true; break }
            } catch { }
            if (-not $adminChanged) { break }
            & $Sleep $PollSeconds
        }
        if (-not $adminIsGroupAfter) { [void]$problems.Add("read-back: the Entra admin of $SqlServerName is not '$GroupName' ($gid)$(if ($adminChanged) { " after $($PollCount * $PollSeconds)s" })") }
    }
    if ($gid) {
        try {
            # TRAP: a member ADDED seconds ago is not listed yet (Graph replication). Measured on RIDE 2026-09-15: the
            # POST succeeded, the immediate read-back missed it, the deploy reported "is NOT a member" and fell
            # through to the contained-user step -- while a read a minute later listed it. So when this run added
            # members, the read-back polls (same bound as the admin read-back) before calling anything missing.
            $wantIds = @(@(@($plan.add) + @($plan.present)) | Where-Object { "$($_.objectId)" -ine $gid } | ForEach-Object { "$($_.objectId)".ToLowerInvariant() })
            $after = @(); $afterSet = @{}
            for ($i = 0; $i -lt [Math]::Max(1, $PollCount); $i++) {
                $after = @(Get-PimGraphGroupMemberIds -Graph $Graph -GroupId $gid)
                $afterSet = @{}; foreach ($x in $after) { $afterSet["$x".ToLowerInvariant()] = $true }
                if (-not $added.Count -or -not @($wantIds | Where-Object { -not $afterSet.ContainsKey($_) }).Count) { break }
                & $Sleep $PollSeconds
            }
            foreach ($m in @(@($plan.add) + @($plan.present))) {
                if ("$($m.objectId)" -ieq $gid) { continue }
                if (-not $afterSet.ContainsKey("$($m.objectId)".ToLowerInvariant())) { [void]$problems.Add("read-back: $($m.label) ($($m.objectId)) is NOT a member of '$GroupName'") }
            }
            if ($afterSet.ContainsKey($gid.ToLowerInvariant())) { [void]$problems.Add("read-back: '$GroupName' is a member of ITSELF -- remove it") }
        } catch { [void]$problems.Add("read-back of the members of '$GroupName' failed: $($_.Exception.Message)") }
    }
    $adOnlyAfter = $null
    try {
        $ao2 = & $Arm -Method GET -Path "$srvPath/azureADOnlyAuthentications/Default?api-version=$($script:PimSqlApi)"
        if ($ao2 -and $ao2.properties -and $null -ne $ao2.properties.azureADOnlyAuthentication) { $adOnlyAfter = [bool]$ao2.properties.azureADOnlyAuthentication }
    } catch { }
    if ($adOnlyBefore -eq $true -and $adOnlyAfter -ne $true) { [void]$problems.Add("read-back: Entra-only authentication was ON before and is not ON now") }

    return (& $result $plan $true @($base, @{ groupId = $gid; created = $created; added = @($added.ToArray()); adminChanged = $adminChanged
                                               adminIsGroup = $adminIsGroupAfter; adAuthOnlyAfter = $adOnlyAfter }))
}

function Invoke-PimSqlAdminGroupStep {
    <#
      Resolve WHO belongs in the group for one environment, then Invoke-PimSqlAdminGroup. Used by the
      script and by both deploy scripts, so the member list cannot differ between them.
        environment identity : -EnvironmentIdentityName, else the one id-pim-* (not id-pim-sql-*) in the group
        SQL identity         : -SqlAdminIdentityName, else the one id-pim-sql-* in the group (private SQL)
        updater identity     : -UpdateJobName's system-assigned identity, when the job exists
        troubleshooting      : -TroubleshootingAppId / -TroubleshootingObjectId
        extras               : -ExtraMembers @{ objectId; label } and -ExtraMemberObjectIds
      -NoDiscovery skips the two identity look-ups (a caller that knows exactly whom to add).
      Returns the Invoke-PimSqlAdminGroup result plus { members (resolved) }.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Graph,
        [Parameter(Mandatory)][scriptblock]$Arm,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$SqlServerName,
        [string]$SqlResourceGroup,
        [string]$GroupName = 'grp-pim-sql-admins',
        [string]$GroupObjectId,
        [string]$EnvironmentIdentityName,
        [string]$SqlAdminIdentityName,
        [string]$UpdateJobName = 'ca-pim-update',
        [string]$TroubleshootingAppId,
        [string]$TroubleshootingObjectId,
        [AllowEmptyCollection()][object[]]$ExtraMembers = @(),
        [AllowEmptyCollection()][string[]]$ExtraMemberObjectIds = @(),
        [ValidateSet('converge', 'membersOnly')][string]$Mode = 'converge',
        [switch]$NoDiscovery,
        [switch]$DoNotKeepCurrentAdmin,
        [switch]$PlanOnly,
        [int]$PollSeconds = 5,
        [int]$PollCount = 36,
        [scriptblock]$Sleep = { param([int]$Seconds) Start-Sleep -Seconds $Seconds }
    )
    $members = New-Object System.Collections.Generic.List[object]
    $resolveProblems = New-Object System.Collections.Generic.List[string]
    $resolveNotes = New-Object System.Collections.Generic.List[string]
    $rgPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"

    if (-not $NoDiscovery) {
        $uamis = @()
        try { $uamis = @((& $Arm -Method GET -Path "$rgPath/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=$($script:PimMiApi)").value | Where-Object { $_ }) }
        catch { [void]$resolveProblems.Add("list the user-assigned identities in $ResourceGroup`: $($_.Exception.Message)") }
        $pick = {
            param([string]$Named, [string]$Pattern, [string]$NotPattern, [string]$What)
            if ("$Named".Trim()) {
                $hit = @($uamis | Where-Object { "$($_.name)" -ieq "$Named".Trim() })
                if (-not $hit.Count) { [void]$resolveProblems.Add("$What '$Named' was not found in $ResourceGroup"); return }
            } else {
                $hit = @($uamis | Where-Object { "$($_.name)" -match $Pattern -and (-not $NotPattern -or "$($_.name)" -notmatch $NotPattern) })
                if ($hit.Count -gt 1) { [void]$resolveNotes.Add("$($hit.Count) candidates for the $What ($(@($hit.name) -join ', ')) -- pass its name explicitly; none added"); return }
                if (-not $hit.Count) { [void]$resolveNotes.Add("no $What found in $ResourceGroup"); return }
            }
            $pid0 = "$($hit[0].properties.principalId)".Trim()
            if (-not $pid0) { [void]$resolveProblems.Add("$What '$($hit[0].name)' has no principalId"); return }
            [void]$members.Add([pscustomobject]@{ objectId = $pid0; label = "$What $($hit[0].name)" })
        }
        & $pick $EnvironmentIdentityName '^(?i)id-pim-' '^(?i)id-pim-sql-' 'environment identity'
        & $pick $SqlAdminIdentityName '^(?i)id-pim-sql-' '' 'SQL identity'
    }
    if ("$UpdateJobName".Trim()) {
        try {
            $job = & $Arm -Method GET -Path "$rgPath/providers/Microsoft.App/jobs/$("$UpdateJobName".Trim())?api-version=$($script:PimJobApi)"
            $jp = "$($job.identity.principalId)".Trim()
            if ($jp) { [void]$members.Add([pscustomobject]@{ objectId = $jp; label = "updater identity $UpdateJobName" }) }
            else { [void]$resolveProblems.Add("$UpdateJobName has no system-assigned identity") }
        } catch {
            $m = "$($_.Exception.Message)"
            if ($m -match '(?i)HTTP 404\b|ResourceNotFound|was not found') { [void]$resolveNotes.Add("$UpdateJobName does not exist yet -- Deploy-PimUpdateJob.ps1 adds its identity when it creates it") }
            else { [void]$resolveProblems.Add("read $UpdateJobName`: $m") }
        }
    }
    if ("$TroubleshootingObjectId".Trim()) {
        [void]$members.Add([pscustomobject]@{ objectId = "$TroubleshootingObjectId".Trim(); label = 'troubleshooting identity' })
    } elseif ("$TroubleshootingAppId".Trim()) {
        try { [void]$members.Add([pscustomobject]@{ objectId = (Resolve-PimServicePrincipalObjectId -Graph $Graph -AppId $TroubleshootingAppId); label = "troubleshooting identity (app $("$TroubleshootingAppId".Trim()))" }) }
        catch { [void]$resolveProblems.Add("resolve the troubleshooting identity (app $TroubleshootingAppId): $($_.Exception.Message)") }
    }
    foreach ($x in @($ExtraMembers)) { if ($x) { [void]$members.Add($x) } }
    foreach ($x in @($ExtraMemberObjectIds)) { if ("$x".Trim()) { [void]$members.Add([pscustomobject]@{ objectId = "$x".Trim(); label = 'extra member' }) } }

    $sqlRg = if ("$SqlResourceGroup".Trim()) { "$SqlResourceGroup".Trim() } else { $ResourceGroup }
    $r = Invoke-PimSqlAdminGroup -Graph $Graph -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $sqlRg -SqlServerName $SqlServerName `
            -TenantId $TenantId -GroupName $GroupName -GroupObjectId $GroupObjectId -Members @($members.ToArray()) -Mode $Mode `
            -DoNotKeepCurrentAdmin:$DoNotKeepCurrentAdmin -PlanOnly:$PlanOnly -PollSeconds $PollSeconds -PollCount $PollCount -Sleep $Sleep
    $allProblems = @(@($resolveProblems.ToArray()) + @($r.problems))
    $r | Add-Member -NotePropertyName members -NotePropertyValue @($members.ToArray()) -Force
    $r.problems = $allProblems
    $r.notes = @(@($resolveNotes.ToArray()) + @($r.notes))
    $r.ok = ($allProblems.Count -eq 0)
    return $r
}

function Write-PimSqlAdminGroupReport {
    <# Print a result the same way from every caller. -Indent keeps it inside a deploy step. #>
    param([Parameter(Mandatory)][object]$Result, [string]$Indent = '    ')
    $p = $Result.plan
    if ($p) { foreach ($m in @($p.messages)) { Write-Host "$Indent$m" -ForegroundColor DarkGray } }
    foreach ($m in @($Result.members)) { if ($m) { Write-Host "$Indent  member wanted: $($m.label) ($($m.objectId))" -ForegroundColor DarkGray } }
    foreach ($n in @($Result.notes)) { Write-Host "$Indent$n" -ForegroundColor Yellow }
    if ($Result.applied) {
        if ($Result.created) { Write-Host "$Indent[CHANGED] created '$($Result.groupName)' ($($Result.groupId))" -ForegroundColor Green }
        foreach ($a in @($Result.added)) { Write-Host "$Indent[CHANGED] member $($a.label) ($($a.objectId))" -ForegroundColor Green }
        foreach ($a in @($Result.present)) { Write-Host "$Indent[OK] member $($a.label)" -ForegroundColor DarkGray }
        if ($Result.adminChanged) { Write-Host "$Indent[CHANGED] Entra admin '$($Result.adminBefore)' -> '$($Result.groupName)' (read back)" -ForegroundColor Green }
        elseif ($Result.adminIsGroup) { Write-Host "$Indent[OK] '$($Result.groupName)' is the Entra admin" -ForegroundColor DarkGray }
    }
    foreach ($x in @($Result.problems)) { Write-Host "$Indent[FAIL] $x" -ForegroundColor Red }
    if ($Result.permissionDenied) {
        Write-Host "${Indent}the identity running this was refused by Microsoft Graph or ARM. It needs Graph Group.Create + GroupMember.ReadWrite.All" -ForegroundColor Yellow
        Write-Host "${Indent}(or Group.ReadWrite.All), Directory.Read.All, and rights to set the SQL server's Entra admin." -ForegroundColor Yellow
    }
}

function New-PimSqlAdminGroupInvokers {
    <#
      Graph + ARM callers for one subscription's tenant. Two credential sources, never a secret:
        default                         -- the signed-in az context (the deploy scripts sign in with a certificate)
        -ClientId + -CertThumbprint     -- a certificate in the local store, via Get-PimRestToken
      The token's tenant is checked against -TenantId (or the subscription's tenant): on a host holding
      several logins the default az context is frequently another directory.
      Returns { Graph; Arm; TenantId }.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertThumbprint
    )
    $decodeTid = {
        param([string]$Tok)
        try {
            $p = "$Tok".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }
            "$(([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json).tid)".Trim().ToLowerInvariant()
        } catch { '' }
    }
    $want = "$TenantId".Trim().ToLowerInvariant()
    if ("$ClientId".Trim() -or "$CertThumbprint".Trim()) {
        if (-not ("$ClientId".Trim() -and "$CertThumbprint".Trim() -and $want)) { throw 'New-PimSqlAdminGroupInvokers: certificate auth needs -TenantId, -ClientId and -CertThumbprint together.' }
        $rest = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-Rest.ps1'
        if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . $rest }
        $graphTok = "$(Get-PimRestToken -Resource 'https://graph.microsoft.com' -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint)"
        $armTok   = "$(Get-PimRestToken -Resource 'https://management.azure.com' -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint)"
    } else {
        if (-not $want) {
            try { $want = "$(((az account show --subscription $SubscriptionId -o json 2>$null) | Out-String | ConvertFrom-Json).tenantId)".Trim().ToLowerInvariant() } catch { $want = '' }
        }
        $graphTok = ''; $armTok = ''
        try { $graphTok = "$(((az account get-access-token --subscription $SubscriptionId --resource https://graph.microsoft.com/ -o json 2>$null) | Out-String | ConvertFrom-Json).accessToken)" } catch { }
        try { $armTok   = "$(((az account get-access-token --subscription $SubscriptionId --resource https://management.azure.com/ -o json 2>$null) | Out-String | ConvertFrom-Json).accessToken)" } catch { }
    }
    if (-not $graphTok -or -not $armTok) { throw "New-PimSqlAdminGroupInvokers: no Graph/ARM token for subscription $SubscriptionId (sign in first)." }
    foreach ($t in @($graphTok, $armTok)) {
        $tid = & $decodeTid $t
        if (-not $want -or $tid -ne $want) { throw "New-PimSqlAdminGroupInvokers: a token is for tenant '$tid', not '$want' -- REFUSING." }
    }
    $mk = {
        param([string]$Base, [string]$Token)
        {
            param([string]$Method = 'GET', [string]$Path, [object]$Body)
            $uri = if ($Path -match '^https://') { $Path } else { "$Base$Path" }
            $h = @{ Authorization = "Bearer $Token" }
            try {
                if ($Method -eq 'GET' -or $Method -eq 'DELETE') { return (Invoke-RestMethod -Method $Method -Uri $uri -Headers $h -UseBasicParsing) }
                $json = if ($null -eq $Body) { '{}' } else { $Body | ConvertTo-Json -Depth 20 -Compress }
                return (Invoke-RestMethod -Method $Method -Uri $uri -Headers $h -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($json)) -UseBasicParsing)
            } catch {
                $code = ''; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
                $detail = "$($_.ErrorDetails.Message)"; if (-not $detail) { $detail = "$($_.Exception.Message)" }
                throw ("$Method $Path -> HTTP $code : $detail")
            }
        }.GetNewClosure()
    }
    return [pscustomobject]@{
        Graph = (& $mk 'https://graph.microsoft.com/v1.0' $graphTok)
        Arm   = (& $mk 'https://management.azure.com' $armTok)
        TenantId = $want
    }
}
