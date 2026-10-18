#Requires -Version 5.1
<#
.SYNOPSIS
  PIM REQUIREMENTS 100.116 (framework 4.1b) -- the Invardia Support app's STANDING access to the PIM database: its own
  database user, created from the application's CLIENT id in SID form, in the database owner role; and its membership of
  the SQL admin group. Shared by the install (Grant-PimSupportAccess.ps1), the one-time script for existing installs
  (Grant-PimSupportSqlAccess.ps1) and the end-of-install check (Confirm-PimInstall.ps1).

.DESCRIPTION
  Why a database user and not only the group: membership of the SQL admin group has not given an APPLICATION a database
  sign-in on the servers this was measured on ("Login failed for user '<token-identified principal>'" with the group in
  the token). A contained user made from the client id needs no directory lookup and works at once.

  The user is looked up BY SID, never by name: one SID can exist once in a database, so an earlier grant under another
  name (Grant-PimSupportAccess -Level troubleshoot makes [invardia-support]) is found and reused, never duplicated.

  Two SQL facts this file is written around (measured, PIM REQUIREMENTS 100.116):
    * EXEC('...' + QUOTENAME(@n)) is a syntax error -- the statement is built in a variable first, then run;
    * joining text to a name column of sys.database_principals needs COLLATE DATABASE_DEFAULT.

  Nothing here signs in. Every caller hands in:
    -Arm   { param([string]$Method, [string]$Path, $Body) }  ARM, the path carries its api-version; throws "... HTTP <code> ..."
    -Graph { param([string]$Method, [string]$Path, $Body) }  Microsoft Graph v1.0
    -Sql   { param([string]$Query) }                         ONE scalar from the PIM database, a new sign-in each call
  Defaults are functions that return a literal (a $script: variable is $null in a child script scope).
#>

function Get-PimSupportSqlUserDefaultName { return 'invardia-support' }
function Get-PimSupportSqlRoleName { return 'db_owner' }
function Get-PimSupportSqlArmApi { return '2021-11-01' }
function Get-PimSupportSqlHostRuleName { return 'AllowSetupHost' }
function Get-PimSupportSqlScriptName { return 'Grant-PimSupportSqlAccess' }

function ConvertTo-PimSupportSqlSid {
    # PURE. The application's CLIENT id as a SQL SID literal: the GUID's bytes in ToByteArray order, as hex.
    param([Parameter(Mandatory)][string]$AppId)
    $t = "$AppId".Trim()
    if ($t -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { throw "ConvertTo-PimSupportSqlSid: '$AppId' is not an application (client) id." }
    $g = [guid]$t
    if ($g -eq [guid]::Empty) { throw 'ConvertTo-PimSupportSqlSid: the empty id is not an application (client) id.' }
    return ('0x' + ((@($g.ToByteArray()) | ForEach-Object { $_.ToString('X2') }) -join ''))
}

function Test-PimSupportSqlNames {
    # PURE. Throws on a user or role name that is not safe to put into a statement.
    param([string]$DbUserName, [string]$Role)
    if ("$DbUserName" -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$') { throw "'$DbUserName' is not a safe database user name." }
    if ("$Role" -cnotmatch '^db_[a-z]{3,30}$') { throw "'$Role' is not a fixed database role." }
}

function Get-PimSupportSqlUserSql {
    <#
      PURE. The statement that puts the Support app's database user in place. Idempotent:
        no principal has the SID -> CREATE USER [<name>] WITH SID = <sid>, TYPE = E
        the principal with that SID (whatever its name) is not in the role -> ALTER ROLE ... ADD MEMBER
    #>
    param([Parameter(Mandatory)][string]$AppId, [string]$DbUserName = (Get-PimSupportSqlUserDefaultName), [string]$Role = (Get-PimSupportSqlRoleName))
    Test-PimSupportSqlNames -DbUserName $DbUserName -Role $Role
    $sid = ConvertTo-PimSupportSqlSid -AppId $AppId
    $q = '[' + "$DbUserName".Replace(']', ']]') + ']'
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add("IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE sid = $sid)")
    $l.Add("    CREATE USER $q WITH SID = $sid, TYPE = E;")
    $l.Add("DECLARE @n SYSNAME = (SELECT TOP 1 name FROM sys.database_principals WHERE sid = $sid);")
    $l.Add("IF @n IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id JOIN sys.database_principals p ON p.principal_id = m.member_principal_id WHERE r.name = N'$Role' AND p.sid = $sid)")
    $l.Add('BEGIN')
    # the statement is built in a variable FIRST: EXEC('...' + QUOTENAME(@n)) is a syntax error
    $l.Add("    DECLARE @q NVARCHAR(600) = N'ALTER ROLE [$Role] ADD MEMBER ' + QUOTENAME(@n) + N';';")
    $l.Add('    EXEC sp_executesql @q;')
    $l.Add('END')
    return ($l -join "`r`n")
}

function Get-PimSupportSqlUserReadSql {
    <#
      PURE. ONE scalar that says what is there: '<in role 0|1>|<name taken by another id 0|1>|<name of the user with the SID>'.
      The name is last (it is the only free text) and carries COLLATE DATABASE_DEFAULT: a catalog name column cannot be
      joined to text without it.
    #>
    param([Parameter(Mandatory)][string]$AppId, [string]$DbUserName = (Get-PimSupportSqlUserDefaultName), [string]$Role = (Get-PimSupportSqlRoleName))
    Test-PimSupportSqlNames -DbUserName $DbUserName -Role $Role
    $sid = ConvertTo-PimSupportSqlSid -AppId $AppId
    $n = "$DbUserName".Replace("'", "''")
    return ("SELECT CAST((SELECT COUNT(*) FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id JOIN sys.database_principals p ON p.principal_id = m.member_principal_id WHERE r.name = N'$Role' AND p.sid = $sid) AS NVARCHAR(10))" +
            " + N'|' + CAST((SELECT COUNT(*) FROM sys.database_principals WHERE name = N'$n' AND (sid IS NULL OR sid <> $sid)) AS NVARCHAR(10))" +
            " + N'|' + ISNULL((SELECT TOP 1 name COLLATE DATABASE_DEFAULT FROM sys.database_principals WHERE sid = $sid), N'')")
}

function Get-PimSupportSqlUserDropSql {
    # PURE. Take the access back: drop the user that has the Support app's id, whatever its name. Nothing when there is none.
    param([Parameter(Mandatory)][string]$AppId)
    $sid = ConvertTo-PimSupportSqlSid -AppId $AppId
    return (@("DECLARE @n SYSNAME = (SELECT TOP 1 name FROM sys.database_principals WHERE sid = $sid);",
              'IF @n IS NOT NULL',
              'BEGIN',
              "    DECLARE @q NVARCHAR(600) = N'DROP USER ' + QUOTENAME(@n) + N';';",
              '    EXEC sp_executesql @q;',
              'END') -join "`r`n")
}

function ConvertFrom-PimSupportSqlUserRead {
    # PURE. The scalar of Get-PimSupportSqlUserReadSql -> @{ inRole; nameTaken; userName }. Anything else THROWS (no answer is never "absent").
    param([AllowNull()]$Raw)
    $t = "$Raw"
    if ($t -notmatch '^(\d+)\|(\d+)\|(.*)$') { throw 'the database did not answer the read of the Support app''s database user' }
    return @{ inRole = ([int]$Matches[1] -ge 1); nameTaken = ([int]$Matches[2] -ge 1); userName = "$($Matches[3])" }
}

function Invoke-PimSupportSqlUser {
    <#
      Put the Support app's database user in place through -Sql and READ IT BACK. Never throws.
      Returns { ok; existed; created; userName; inRole; role; problem }.
        -ReadOnly : read only (the check, a preview)
      A user of the wanted NAME that belongs to ANOTHER id is never dropped or reused: reported, nothing changed.
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [Parameter(Mandatory)][string]$AppId,
          [string]$DbUserName = (Get-PimSupportSqlUserDefaultName), [string]$Role = (Get-PimSupportSqlRoleName), [switch]$ReadOnly)
    $o = [ordered]@{ ok = $false; existed = $false; created = $false; userName = ''; inRole = $false; role = $Role; problem = '' }
    try {
        $readSql = Get-PimSupportSqlUserReadSql -AppId $AppId -DbUserName $DbUserName -Role $Role
        $b = ConvertFrom-PimSupportSqlUserRead (& $Sql $readSql)
        $o.existed = [bool]$b.userName; $o.userName = $b.userName; $o.inRole = [bool]$b.inRole
        if ($o.existed -and $o.inRole) { $o.ok = $true; return [pscustomobject]$o }
        if ($ReadOnly) {
            $o.problem = if ($o.existed) { "the database user [$($o.userName)] of the Support app is not in $Role" } else { 'the Support app has no database user' }
            return [pscustomobject]$o
        }
        if (-not $o.existed -and $b.nameTaken) {
            $o.problem = "a database user named [$DbUserName] exists but belongs to ANOTHER id (an earlier Support app) -- nothing was changed. Run again with -DbUserName <another name>, or drop the old user first."
            return [pscustomobject]$o
        }
        [void](& $Sql (Get-PimSupportSqlUserSql -AppId $AppId -DbUserName $DbUserName -Role $Role))
        $a = ConvertFrom-PimSupportSqlUserRead (& $Sql $readSql)
        $o.userName = $a.userName; $o.inRole = [bool]$a.inRole
        $o.created = ([bool]$a.userName -and -not $o.existed)
        if ($a.userName -and $a.inRole) { $o.ok = $true }
        else { $o.problem = "read-back: $(if ($a.userName) { "the database user [$($a.userName)] is not in $Role" } else { 'no database user has the Support app''s id' }) after the statement ran" }
    } catch { $o.problem = (("$($_.Exception.Message)" -split "`n")[0]).Trim() }
    return [pscustomobject]$o
}

function Add-PimSupportSqlAdminGroupMember {
    <#
      Make the Support app's service principal a member of the SQL admin group, and say what happened. Never throws.
      Returns { state; detail; spObjectId; spName; groupId }:
        member    already a member            added     added now
        would-add -ReadOnly, not a member     no-group  the group does not exist in this tenant
        no-sp     the application has no service principal here
        refused   Microsoft Graph refused (a role-assignable group needs Privileged Role Administrator)
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$SupportAppId, [string]$GroupName = 'grp-pim-sql-admins', [switch]$ReadOnly)
    $o = [ordered]@{ state = ''; detail = ''; spObjectId = ''; spName = ''; groupId = '' }
    try {
        $f = [uri]::EscapeDataString("appId eq '$("$SupportAppId".Trim())'")
        $sp = @((& $Graph 'GET' "/servicePrincipals?`$select=id,appId,displayName&`$filter=$f" $null).value | Where-Object { $_ }) | Select-Object -First 1
        if (-not $sp -or -not "$($sp.id)".Trim()) { $o.state = 'no-sp'; $o.detail = "the application $SupportAppId has no service principal in this tenant"; return [pscustomobject]$o }
        $o.spObjectId = "$($sp.id)".Trim(); $o.spName = "$($sp.displayName)".Trim()
        $gf = [uri]::EscapeDataString("displayName eq '$($GroupName.Replace("'", "''"))'")
        $grps = @((& $Graph 'GET' "/groups?`$select=id,displayName&`$filter=$gf" $null).value | Where-Object { $_ })
        if (-not $grps.Count) { $o.state = 'no-group'; $o.detail = "the group '$GroupName' does not exist in this tenant"; return [pscustomobject]$o }
        if ($grps.Count -gt 1) { $o.state = 'refused'; $o.detail = "$($grps.Count) groups are named '$GroupName' -- not changed"; return [pscustomobject]$o }
        $gid = "$($grps[0].id)".Trim(); $o.groupId = $gid
        # 2.4.649 (live 2026-10-18): GET /groups/{id}/members LEAVES OUT service principals the caller cannot read -- at 16
        # installs the Support app was a member while the list showed 0-1 members. Asked from the MEMBER's side first
        # (checkMemberObjects is a POST that reads, it changes nothing); the list below stays as the fallback.
        try {
            $cmo = & $Graph 'POST' "/servicePrincipals/$($o.spObjectId)/checkMemberObjects" @{ ids = @($gid) }
            if (@($cmo.value) -contains $gid) { $o.state = 'member'; $o.detail = "already a member of '$GroupName'"; return [pscustomobject]$o }
        } catch { }
        $ids = New-Object System.Collections.Generic.List[string]
        $next = "/groups/$gid/members?`$select=id&`$top=999"
        while ($next) {
            $page = & $Graph 'GET' $next $null
            foreach ($m in @($page.value)) { if ($m -and "$($m.id)".Trim()) { $ids.Add("$($m.id)".Trim().ToLowerInvariant()) } }
            $next = "$($page.'@odata.nextLink')".Trim()
        }
        if ($ids.Contains($o.spObjectId.ToLowerInvariant())) { $o.state = 'member'; $o.detail = "already a member of '$GroupName'"; return [pscustomobject]$o }
        if ($ReadOnly) { $o.state = 'would-add'; $o.detail = "not a member of '$GroupName' yet"; return [pscustomobject]$o }
        try {
            [void](& $Graph 'POST' "/groups/$gid/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($o.spObjectId)" })
            $o.state = 'added'; $o.detail = "added to '$GroupName'"
        } catch {
            $m = (("$($_.Exception.Message)" -split "`n")[0]).Trim()
            if ($m -match '(?i)already exist') { $o.state = 'member'; $o.detail = "already a member of '$GroupName'" }
            else { $o.state = 'refused'; $o.detail = "Microsoft Graph refused the membership of '$GroupName': $m" }
        }
    } catch { $o.state = 'refused'; $o.detail = "the group membership could not be read: $((("$($_.Exception.Message)" -split "`n")[0]).Trim())" }
    return [pscustomobject]$o
}

function Get-PimSupportSqlAdminSnapshot {
    # PURE. The server's Entra administrator EXACTLY as the server object carries it (only the properties that are there).
    param([AllowNull()]$Server)
    $a = $null
    if ($Server -and $Server.properties) { $a = $Server.properties.administrators }
    if (-not $a -or -not "$($a.sid)".Trim()) { return $null }
    $o = [ordered]@{}
    foreach ($k in 'administratorType', 'principalType', 'login', 'sid', 'tenantId') { if ($null -ne $a.$k -and "$($a.$k)" -ne '') { $o[$k] = "$($a.$k)" } }
    if ($null -ne $a.azureADOnlyAuthentication) { $o['azureADOnlyAuthentication'] = [bool]$a.azureADOnlyAuthentication }
    return $o
}

function Compare-PimSupportSqlAdmin {
    # PURE. The differences between the administrator that was read (-Want) and what is there now (-Have); none = the same.
    param([AllowNull()]$Want, [AllowNull()]$Have)
    $d = New-Object System.Collections.Generic.List[string]
    if (-not $Want) { return @() }
    if (-not $Have) { return @('the server has no Entra administrator now') }
    foreach ($k in @($Want.Keys)) {
        $w = "$($Want[$k])"; $h = "$($Have[$k])"
        $same = if ($k -eq 'login') { $w -ceq $h } else { $w -ieq $h }
        if (-not $same) { $d.Add("$k is '$h', was '$w'") }
    }
    return @($d.ToArray())
}

function Get-PimSupportSqlFixCommand {
    # PURE. The two lines a person runs for an existing install: the download, then the run (framework 12.10 item 11).
    param([string]$TenantId, [string]$SubscriptionId, [string]$ResourceGroup, [string]$SqlServerName, [string]$SupportAppId)
    $name = Get-PimSupportSqlScriptName
    $srv = ("$SqlServerName".Trim() -split '\.')[0]
    $run = ".\$name.ps1 -TenantId '$TenantId' -SubscriptionId '$SubscriptionId' -ResourceGroup '$ResourceGroup' -SqlServerName '$srv' -SupportAppId '$SupportAppId'"
    return @(Get-PimSupportScriptCommand -Script $name -Run @($run))
}

function Invoke-PimSupportSqlAccessGrant {
    <#
      The one-time step for an EXISTING install (PIM REQUIREMENTS 100.116, the method measured at a customer):
        1. read and keep the server's Entra administrator and the Entra-only setting; read the setup-host firewall rule
        2. the Support app joins the SQL admin group (a refusal is a WARNING with the next step)
        3. open the install's own setup-host firewall rule (only when it is not there; a rule of another address stops the run)
        4. try a database sign-in as this session. Refused, and this session IS the Support app: make the Support app the
           server's administrator FOR THE STEP (PATCH of the server, the Entra-only setting sent back as read) and wait
           until a database sign-in answers
        5. create the database user from the client id + the role; read it back
        6. finally: put the administrator back EXACTLY as read and read it back; remove the firewall rule this run opened
           and read that back -- also after a failed step
        7. proof: a new database sign-in as the Support app (a Support session only; otherwise "not checked")
      -WhatIfOnly: steps 1 and 2 are READ, the rest is printed. Nothing is written.
      Never throws. Returns { ok; exit (0 done, 1 not done, 2 the administrator was NOT put back); whatIf; before; after; swapped;
      restored; ruleOpened; ruleClosed; group; user; proof; warnings; problems }.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Arm,
        [scriptblock]$Graph,
        [scriptblock]$Sql,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$SqlServerName,
        [string]$SqlDatabase = 'PimPlatform',
        [Parameter(Mandatory)][string]$SupportAppId,
        [bool]$SessionIsSupportApp = $false,
        [string]$DbUserName = (Get-PimSupportSqlUserDefaultName),
        [string]$SqlAdminGroupName = 'grp-pim-sql-admins',
        [string]$HostIp = '',
        [int]$SignInWaitSeconds = 300,
        [int]$PollSeconds = 20,
        [int]$ReadBackTries = 36,
        [int]$FirewallWaitSeconds = 30,
        [scriptblock]$Sleep = { param([int]$Seconds) Start-Sleep -Seconds $Seconds },
        [string[]]$FixCommand = @(),
        [switch]$WhatIfOnly
    )
    $role = Get-PimSupportSqlRoleName
    $rule = Get-PimSupportSqlHostRuleName
    $api = Get-PimSupportSqlArmApi
    $srv = ("$SqlServerName".Trim() -replace '^tcp:', '' -replace ',\d+$', '').Split('.')[0].ToLowerInvariant()
    $srvPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Sql/servers/$srv"
    $warnings = New-Object System.Collections.Generic.List[string]
    $problems = New-Object System.Collections.Generic.List[string]
    $res = [ordered]@{ ok = $false; exit = 1; whatIf = [bool]$WhatIfOnly; before = $null; after = $null; swapped = $false; restored = $false
                       ruleOpened = $false; ruleClosed = $false; group = $null; user = $null; proof = @{ state = 'not-checked'; detail = '' }
                       warnings = @(); problems = @() }
    $say = { param([string]$m, [string]$c = 'Gray') Write-Host "  $m" -ForegroundColor $c }
    $first = { param($e) (("$($e.Exception.Message)" -split "`n")[0]).Trim() }
    $get = {
        param([string]$P)
        try { return (& $Arm 'GET' "$P`?api-version=$api" $null) }
        catch { if ("$($_.Exception.Message)" -match '(?i)HTTP 404\b|ResourceNotFound|was not found|NotFound') { return $null }; throw }
    }
    $adOnly = {
        $x = & $get "$srvPath/azureADOnlyAuthentications/Default"
        if ($x -and $x.properties -and $null -ne $x.properties.azureADOnlyAuthentication) { return [bool]$x.properties.azureADOnlyAuthentication }
        return $null
    }
    $ruleIp = { $x = & $get "$srvPath/firewallRules/$rule"; if ($x -and $x.properties) { return "$($x.properties.startIpAddress)".Trim() }; return '' }
    $show = {
        param([string]$Label, $Admin, $EntraOnly, [string]$RuleNow)
        & $say ("{0} administrator: {1}; Entra-only sign-in: {2}; firewall rule '{3}': {4}" -f $Label,
            $(if ($Admin) { "'$($Admin['login'])' ($(if ($Admin.Contains('principalType')) { $Admin['principalType'] } else { 'type not given' }), id $($Admin['sid']))" } else { 'none read' }),
            $(if ($null -eq $EntraOnly) { 'not read' } elseif ($EntraOnly) { 'on' } else { 'off' }), $rule, $(if ($RuleNow) { $RuleNow } else { 'not there' }))
    }
    $finish = {
        $res.warnings = @($warnings.ToArray()); $res.problems = @($problems.ToArray())
        $res.exit = if ($res.swapped -and -not $res.restored) { 2 } elseif ($problems.Count) { 1 } else { 0 }
        $res.ok = ($res.exit -eq 0)
        return [pscustomobject]$res
    }

    # ---- 1. read and keep -----------------------------------------------------------------------------------------
    $server = $null; $before = $null; $adOnlyBefore = $null; $ruleBefore = ''
    try {
        $server = & $get $srvPath
        if (-not $server) { $problems.Add("the SQL server '$srv' was not found in resource group '$ResourceGroup' (subscription $SubscriptionId)"); return (& $finish) }
        $before = Get-PimSupportSqlAdminSnapshot -Server $server
        $adOnlyBefore = & $adOnly
        $ruleBefore = & $ruleIp
    } catch { $problems.Add("the SQL server could not be read: $(& $first $_) -- nothing was changed"); return (& $finish) }
    $res.before = @{ admin = $before; entraOnly = $adOnlyBefore; rule = $ruleBefore }
    & $show 'before:' $before $adOnlyBefore $ruleBefore

    # ---- what stops the run BEFORE anything is changed (the group membership below is the first change) --------------
    if ("$($server.properties.publicNetworkAccess)" -ieq 'Disabled') {
        $problems.Add("the SQL server $srv has public network access OFF -- this machine cannot reach the database. Run this script from a machine inside the PIM network. Nothing was changed.")
        return (& $finish)
    }
    $ip = "$HostIp".Trim()
    if ($ruleBefore -and $ip -and $ruleBefore -ne $ip) {
        $problems.Add("the firewall rule '$rule' is already on $srv for another address ($ruleBefore) -- another setup run may be using it, so it is not changed. When no install is running: Azure portal > SQL server $srv > Networking > Firewall rules: delete '$rule', then run this script again. Nothing was changed.")
        return (& $finish)
    }
    if (-not $WhatIfOnly) {
        if (-not $Sql) { $problems.Add('no database session in this run -- nothing was changed'); return (& $finish) }
        if (-not $ruleBefore -and $ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { $problems.Add("this machine's public address is not known ('$ip') -- pass -SetupHostIp <address>. Nothing was changed."); return (& $finish) }
    }

    # ---- 2. the SQL admin group -----------------------------------------------------------------------------------
    if ($Graph) {
        $g = Add-PimSupportSqlAdminGroupMember -Graph $Graph -SupportAppId $SupportAppId -GroupName $SqlAdminGroupName -ReadOnly:$WhatIfOnly
        $res.group = $g
        switch ("$($g.state)") {
            'member'    { & $say "SQL admin group: the Invardia Support app is $($g.detail)" 'Green' }
            'added'     { & $say "SQL admin group: the Invardia Support app was $($g.detail) (it stays a member)" 'Green' }
            'would-add' { Write-Host "What if: add the Invardia Support app ($($g.spObjectId)) as a member of the group '$SqlAdminGroupName'" }
            'no-sp'     { $problems.Add("$($g.detail) -- create the Invardia Support app in this tenant first (Invardia's New-InvardiaSupportApp.ps1); nothing was changed"); return (& $finish) }
            'no-group'  {
                $mk = @(Get-PimSupportScriptCommand -Script 'Initialize-PimSqlAdminGroup' -Run @(".\Initialize-PimSqlAdminGroup.ps1 -TenantId '$TenantId' -SubscriptionId '$SubscriptionId' -ResourceGroup '$ResourceGroup' -SqlServerName '$srv' -SupportAppId '$SupportAppId'")) -join "`n"
                $warnings.Add("SQL admin group: $($g.detail), so the Invardia Support app is not a member of it. The database user below is what gives the access. To create the group with the Support app in it, a Privileged Role Administrator runs:`n$mk")
            }
            default     { $warnings.Add("SQL admin group: $($g.detail). The database user below is what gives the access; to add the membership, a Privileged Role Administrator adds the Invardia Support app to '$SqlAdminGroupName' (Microsoft Entra admin center > Groups > $SqlAdminGroupName > Members > Add members).") }
        }
    } else { $warnings.Add('SQL admin group: not checked (no Microsoft Graph session in this run)') }

    $sid = ConvertTo-PimSupportSqlSid -AppId $SupportAppId
    if ($WhatIfOnly) {
        Write-Host "What if: open the firewall rule '$rule' on $srv for this machine's public address$(if ("$HostIp".Trim()) { " ($("$HostIp".Trim()))" })$(if ($ruleBefore) { " -- it is already there ($ruleBefore) and would be left as found" }), and remove it at the end"
        Write-Host "What if: when the database refuses this sign-in and this run is the Invardia Support app's session: make the Invardia Support app the administrator of $srv for the step, then put $(if ($before) { "'$($before['login'])'" } else { 'the administrator' }) back exactly as read"
        Write-Host "What if: in the database $SqlDatabase, create the user [$DbUserName] from the Support app's client id (SID $sid) when no user has that id, and add it to $role"
        return (& $finish)
    }

    # ---- 3. the firewall rule -------------------------------------------------------------------------------------
    if (-not $ruleBefore) {
        try {
            [void](& $Arm 'PUT' "$srvPath/firewallRules/$rule`?api-version=$api" @{ properties = @{ startIpAddress = $ip; endIpAddress = $ip } })
            $res.ruleOpened = $true
            if ((& $ruleIp) -ne $ip) { throw "the rule did not read back for $ip" }
            & $say "opened: firewall rule '$rule' = $ip on $srv (read back; removed again at the end)" 'Yellow'
            if ($FirewallWaitSeconds -gt 0) { & $Sleep $FirewallWaitSeconds }
        } catch { $problems.Add("the firewall rule '$rule' could not be opened: $(& $first $_)") }
    } else { & $say "firewall rule '$rule' ($ruleBefore) was already there -- used and left exactly as found" 'DarkGray' }

    $ownerSql = "SELECT CASE WHEN IS_ROLEMEMBER(N'$role') = 1 OR USER_NAME() = N'dbo' THEN 1 ELSE 0 END"
    try {
        if (-not $problems.Count) {
            try {
                # ---- 4. a database sign-in as this session; the Support app as administrator for the step when refused
                $direct = $false; $why = ''
                try { $direct = ("$(& $Sql $ownerSql)".Trim() -eq '1'); if (-not $direct) { $why = "this sign-in is not a database owner in $SqlDatabase" } }
                catch { $direct = $false; $why = & $first $_ }
                if ($direct) { & $say "database sign-in: accepted with the database owner right -- the server's administrator is not touched" 'Green' }
                elseif (-not $SessionIsSupportApp) {
                    $problems.Add("the database refused this sign-in ($why). Sign in as a member of '$SqlAdminGroupName' (or the server's administrator), or have Invardia support run this script in its Support session. The server's administrator was not touched.")
                } elseif (-not $before) {
                    $problems.Add("the database refused the sign-in ($why) and the server's Entra administrator could not be read in full -- it could not be put back afterwards, so it is not changed.")
                } else {
                    $swapLogin = if ($res.group -and "$($res.group.spName)".Trim()) { "$($res.group.spName)".Trim() } else { 'Invardia Support' }
                    $swap = [ordered]@{ administratorType = 'ActiveDirectory'; principalType = 'Application'; login = $swapLogin; sid = "$SupportAppId".Trim().ToLowerInvariant(); tenantId = "$TenantId".Trim().ToLowerInvariant() }
                    if ($null -ne $adOnlyBefore) { $swap['azureADOnlyAuthentication'] = [bool]$adOnlyBefore } elseif ($before.Contains('azureADOnlyAuthentication')) { $swap['azureADOnlyAuthentication'] = [bool]$before['azureADOnlyAuthentication'] }
                    & $say "the database refused the sign-in ($why) -- making the Invardia Support app the administrator of $srv FOR THIS STEP (was '$($before['login'])')" 'Yellow'
                    $res.swapped = $true     # set BEFORE the call: a call that fails half-way is still put back
                    [void](& $Arm 'PATCH' "$srvPath`?api-version=$api" @{ properties = @{ administrators = $swap } })
                    $tries = [Math]::Max(1, [int][Math]::Ceiling($SignInWaitSeconds / [double][Math]::Max(1, $PollSeconds)))
                    $in = $false; $last = ''
                    for ($i = 1; $i -le $tries; $i++) {
                        try { [void](& $Sql 'SELECT 1'); $in = $true; break } catch { $last = & $first $_ }
                        & $Sleep $PollSeconds
                    }
                    if ($in) { & $say 'database sign-in as the Invardia Support app: accepted' 'Green' }
                    else { $problems.Add("the database did not accept the Invardia Support app's sign-in within $SignInWaitSeconds seconds ($last) -- the user was not created. Run the script again in a few minutes.") }
                }
                # ---- 5. the user + the role
                if (-not $problems.Count) {
                    $u = Invoke-PimSupportSqlUser -Sql $Sql -AppId $SupportAppId -DbUserName $DbUserName -Role $role
                    $res.user = $u
                    if ($u.ok) { & $say "database user [$($u.userName)] (the Support app's client id, SID $sid): $(if ($u.created) { 'created' } elseif ($u.existed) { 'was already there' } else { 'in place' }), member of $role (read back)" 'Green' }
                    else { $problems.Add("the database user was not put in place: $($u.problem)") }
                }
            } catch { $problems.Add("the step stopped: $(& $first $_)") }
            finally {
                # ---- 6a. the administrator back EXACTLY as read, and read back -- also after a failed step
                if ($res.swapped) {
                    $body = @{ properties = @{ administrators = $before } }
                    $sent = $false; $sendErr = ''
                    foreach ($n in 1..3) {
                        try { [void](& $Arm 'PATCH' "$srvPath`?api-version=$api" $body); $sent = $true; break } catch { $sendErr = & $first $_; & $Sleep 5 }
                    }
                    $diff = @('not read back')
                    for ($i = 0; $i -lt [Math]::Max(1, $ReadBackTries); $i++) {
                        try {
                            $nowAdmin = Get-PimSupportSqlAdminSnapshot -Server (& $get $srvPath)
                            $diff = @(Compare-PimSupportSqlAdmin -Want $before -Have $nowAdmin)
                            if (-not $diff.Count -and $null -ne $adOnlyBefore) { $ao = & $adOnly; if ($ao -ne $adOnlyBefore) { $diff = @("Entra-only sign-in is '$ao', was '$adOnlyBefore'") } }
                        } catch { $diff = @("read-back failed: $(& $first $_)") }
                        if (-not $diff.Count) { break }
                        & $Sleep 5
                    }
                    if (-not $diff.Count) { $res.restored = $true; & $say "restored: the administrator of $srv is '$($before['login'])' again, exactly as read (read back)" 'Green' }
                    else {
                        $problems.Add("THE ADMINISTRATOR OF $srv WAS NOT PUT BACK ($($diff -join '; ')$(if (-not $sent) { "; the request failed: $sendErr" })). Put it back by hand NOW: Azure portal > SQL server $srv > Microsoft Entra ID > Set admin: '$($before['login'])' (id $($before['sid']))$(if ($null -ne $adOnlyBefore) { "; 'Support only Microsoft Entra authentication' = $(if ($adOnlyBefore) { 'on' } else { 'off' })" }).")
                    }
                }
            }
            # ---- 7. proof: a NEW database sign-in as the Support app, after the administrator is back
            if ($res.user -and $res.user.ok) {
                if (-not $SessionIsSupportApp) { $res.proof = @{ state = 'not-checked'; detail = 'this run is not the Invardia Support app''s session, so a sign-in as the Support app was not tried; the evidence is the user and its role, read back' } }
                elseif ($res.swapped -and -not $res.restored) { $res.proof = @{ state = 'not-checked'; detail = 'the administrator was not put back, so a sign-in now proves nothing' } }
                else {
                    try { $as = "$(& $Sql 'SELECT USER_NAME()')".Trim(); $res.proof = @{ state = 'proven'; detail = "a new database sign-in as the Invardia Support app answered (database user: $as)" } }
                    catch {
                        $res.proof = @{ state = 'failed'; detail = "a new database sign-in as the Invardia Support app was refused: $(& $first $_)" }
                        $warnings.Add("$($res.proof.detail). The user and its role are in place (read back); a new right can take a few minutes -- run the script again to check.")
                    }
                }
                & $say "proof: $($res.proof.detail)" $(if ($res.proof.state -eq 'proven') { 'Green' } else { 'Yellow' })
            }
        }
    } finally {
        # ---- 6b. the firewall rule this run opened: removed and read back -- also after a failed step
        if ($res.ruleOpened) {
            $left = $rule
            foreach ($n in 1..3) {
                try { try { [void](& $Arm 'DELETE' "$srvPath/firewallRules/$rule`?api-version=$api" $null) } catch { if ("$($_.Exception.Message)" -notmatch '(?i)HTTP 404\b|NotFound') { throw } }; $left = & $ruleIp } catch { $left = "not read: $(& $first $_)" }
                if (-not $left) { break }
                & $Sleep 5
            }
            if (-not $left) { $res.ruleClosed = $true; & $say "closed: firewall rule '$rule' removed from $srv (read back)" 'Green' }
            else { $problems.Add("the firewall rule '$rule' is STILL on $srv ($left) -- this machine keeps network access to the SQL server. Remove it: Azure portal > SQL server $srv > Networking > Firewall rules: delete '$rule'.") }
        }
    }
    try {
        $res.after = @{ admin = (Get-PimSupportSqlAdminSnapshot -Server (& $get $srvPath)); entraOnly = (& $adOnly); rule = (& $ruleIp) }
        & $show 'after: ' $res.after.admin $res.after.entraOnly $res.after.rule
    } catch { $warnings.Add("the state after the run could not be read: $(& $first $_)") }
    return (& $finish)
}
