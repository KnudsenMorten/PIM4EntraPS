#Requires -Version 5.1
<#
.SYNOPSIS
    G3A-COPY-LEFTOVER (PIM REQUIREMENTS 100.156 B, framework 12.23 P5; Invardia 2026-11-07) -- the managed-tenant PULL JOB's
    OWN least-privilege database user, converged by the in-cloud UPDATER at installs deployed before 100.156 B.

.DESCRIPTION
    A pull job (ca-pim-downlink-*) deployed before 100.156 B signs in to SQL as its managed identity and has NO contained
    database user of its own: it reaches the store only because that identity is a member of the SQL Entra admin group (the
    v1 shape). Deploy-PimDownlinkJob.ps1 gives a NEW deploy its own user; this file brings the EXISTING ones there, on every
    update, through the SAME path the updater already uses for the as-built reader:
      * the pull job(s) in the install's resource group (ARM GET), the identity each signs in to SQL with (the user-assigned
        identity named in PIM_ManagedIdentityClientId, else the job's SYSTEM identity), its app id (ARM, else Graph);
      * the roles = the access catalog's downlink component (Get-PimSqlComponentAccess -Component downlink: pim_downlink +
        pim_engine) -- nothing wider: never a fixed db_* role;
      * created THROUGH the signed access procedure (pim.usp_ApplyAccess @Action = 'user': CREATE USER ... WITH SID = <the app
        id>, TYPE = E -- never FROM EXTERNAL PROVIDER), the two roles + their catalog grants first, all through it. No
        procedure (an install before the access model's run 1) = nothing is sent, said;
      * READ BACK: the user's SID (and its roles, where this identity can see them; else through the read-only access facts
        procedure, SID only);
      * whether the job identity is STILL a member of the SQL admin group is READ (Read-PimDbInitAdminMembership) and
        REPORTED. It is NEVER removed here: the removal is a separate support step after one pull ran green on its own user
        (tools/setup/_PimSqlAdminGroup.ps1 Remove-PimSqlAdminGroupMember).
    Creating a user / a role membership / a grant is the 'grants' kind of SCHEMA-QUIESCE-818 (framework 8.18): it may run
    beside a running PIM job. No table, no column, no procedure is created or changed here.
    RULES OF THIS FILE (Test-PimDownlinkSqlUser Z): no ARM or Graph WRITE at all (GET only), no group membership write, no
    DROP, no REVOKE, no fixed db_* role, ASCII only; PS 5.1 + 7; no modules.
#>
Set-StrictMode -Off

function Get-PimDownlinkSqlUserJobPattern { <# PURE. LITERAL. A pull job's name. #> return '^(?i)caj?-pim-downlink' }

function Get-PimDownlinkSqlUserField {
    # PURE. A property of an object or a dictionary ($null when absent).
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Get-PimDownlinkSqlUserRoles {
    <#
      PURE. The pull job's database roles = the access catalog's downlink component (Get-PimSqlComponentAccess). Only pim_<x>
      custom roles pass: a fixed db_* role is never returned (the catalog never names one for this component). Catalog not
      loaded -> @() (the caller then sends nothing: never a guess).
    #>
    if (-not (Get-Command Get-PimSqlComponentAccess -ErrorAction SilentlyContinue)) { return @() }
    return @(@((Get-PimSqlComponentAccess -Component downlink).roles) | Where-Object { "$_" -cmatch '^pim_[a-z]{2,30}$' })
}

function Get-PimDownlinkSqlIdentity {
    <#
      PURE. Which identity the pull job signs in to SQL with (the one its container's token call returns):
        user    PIM_ManagedIdentityClientId names a user-assigned identity the job carries -> its clientId IS the app id
        system  no client id setting -> the job's SYSTEM identity (identity.principalId; the app id is resolved separately)
        none    a client id the job does not carry, or no identity at all -> nothing is created (said)
      Returns @{ kind; appId; principalId; reason }.
    #>
    param([AllowNull()][object]$Job)
    $o = [ordered]@{ kind = 'none'; appId = ''; principalId = ''; reason = '' }
    $cid = ''
    $tpl = Get-PimDownlinkSqlUserField (Get-PimDownlinkSqlUserField $Job 'properties') 'template'
    foreach ($c in @(Get-PimDownlinkSqlUserField $tpl 'containers')) {
        foreach ($e in @(Get-PimDownlinkSqlUserField $c 'env')) {
            if ($e -and "$(Get-PimDownlinkSqlUserField $e 'name')" -ceq 'PIM_ManagedIdentityClientId' -and "$(Get-PimDownlinkSqlUserField $e 'value')".Trim()) { $cid = "$(Get-PimDownlinkSqlUserField $e 'value')".Trim(); break }
        }
        if ($cid) { break }
    }
    $idn = Get-PimDownlinkSqlUserField $Job 'identity'
    if ($cid) {
        $ua = Get-PimDownlinkSqlUserField $idn 'userAssignedIdentities'
        $pairs = @()
        if ($ua -is [System.Collections.IDictionary]) { $pairs = @($ua.Keys | ForEach-Object { $ua[$_] }) } elseif ($ua) { $pairs = @($ua.PSObject.Properties | ForEach-Object { $_.Value }) }
        $hit = @($pairs | Where-Object { $_ -and "$(Get-PimDownlinkSqlUserField $_ 'clientId')".Trim() -ieq $cid })[0]
        if (-not $hit) { $o.reason = "PIM_ManagedIdentityClientId names $cid, which the job does not carry -- not determined"; return $o }
        $g = [guid]::Empty
        if (-not [guid]::TryParse($cid, [ref]$g)) { $o.reason = "PIM_ManagedIdentityClientId '$cid' is not a client id"; return $o }
        $o.kind = 'user'; $o.appId = $g.ToString(); $o.principalId = "$(Get-PimDownlinkSqlUserField $hit 'principalId')".Trim()
        $o.reason = 'the user-assigned identity named in PIM_ManagedIdentityClientId'
        return $o
    }
    $pid0 = "$(Get-PimDownlinkSqlUserField $idn 'principalId')".Trim()
    $g2 = [guid]::Empty
    if (-not [guid]::TryParse($pid0, [ref]$g2)) { $o.reason = 'the job has no system identity and names no user-assigned one -- not determined'; return $o }
    $o.kind = 'system'; $o.principalId = $g2.ToString(); $o.reason = 'the job''s system identity (no client id setting)'
    return $o
}

function Resolve-PimDownlinkSqlAppId {
    <#
      The app (client) id of a job's SYSTEM identity (= the contained user's SID). ARM first: the identity's own record
      (<job id>/providers/Microsoft.ManagedIdentity/identities/default -> properties.clientId), then Microsoft Graph
      (GET /servicePrincipals/<object id>?$select=id,appId -- the updater holds Application.Read.All, framework 4.5 G5). GET
      only. Never throws. Returns @{ appId; via; reason }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [AllowNull()][scriptblock]$Graph, [Parameter(Mandatory)][string]$JobId, [AllowEmptyString()][string]$PrincipalId)
    $o = @{ appId = ''; via = ''; reason = '' }
    $first = { param($e) ((("$($e.Exception.Message)") -split "`n")[0]).Trim() }
    $why = New-Object System.Collections.Generic.List[string]
    $g = [guid]::Empty
    try {
        $r = & $Arm 'GET' "$("$JobId".TrimEnd('/'))/providers/Microsoft.ManagedIdentity/identities/default?api-version=2023-01-31" $null
        $c = "$(Get-PimDownlinkSqlUserField (Get-PimDownlinkSqlUserField $r 'properties') 'clientId')".Trim()
        if ([guid]::TryParse($c, [ref]$g)) { $o.appId = $g.ToString(); $o.via = 'arm'; return $o }
        [void]$why.Add('ARM named no client id')
    } catch { [void]$why.Add("ARM: $(& $first $_)") }
    if ($Graph -and [guid]::TryParse("$PrincipalId".Trim(), [ref]$g)) {
        try {
            $sp = & $Graph ("/servicePrincipals/$($g.ToString())" + '?$select=id,appId')
            $a = "$(Get-PimDownlinkSqlUserField $sp 'appId')".Trim()
            $g3 = [guid]::Empty
            if ([guid]::TryParse($a, [ref]$g3)) { $o.appId = $g3.ToString(); $o.via = 'graph'; return $o }
            [void]$why.Add('Graph named no app id')
        } catch { [void]$why.Add("Graph: $(& $first $_)") }
    } elseif (-not $Graph) { [void]$why.Add('Graph was not asked') }
    $o.reason = "the app id of the job's identity could not be read ($($why -join '; '))"
    return $o
}

function Test-PimDownlinkSqlUserName {
    # PURE. A safe database user name (the access procedure's own rule, mirrored).
    param([AllowEmptyString()][string]$Name)
    return [bool]("$Name" -match '^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$')
}

function Get-PimDownlinkSqlUserReadSql {
    <#
      PURE. READ-ONLY, ONE row: may this caller see other users (db_owner / VIEW DEFINITION), is the signed access procedure
      there, and the user's SID, type and roles (NULL where the caller cannot see it).
    #>
    param([Parameter(Mandatory)][string]$UserName)
    if (-not (Test-PimDownlinkSqlUserName $UserName)) { throw "Get-PimDownlinkSqlUserReadSql: '$UserName' is not a safe database user name." }
    $n = "$UserName".Replace("'", "''")
    return ("SELECT ISNULL(IS_ROLEMEMBER('db_owner'), 0) AS callerDbOwner, ISNULL(HAS_PERMS_BY_NAME(NULL, N'DATABASE', N'VIEW DEFINITION'), 0) AS callerViewDefinition, " +
            "CASE WHEN OBJECT_ID(N'pim.usp_ApplyAccess') IS NULL THEN 0 ELSE 1 END AS hasProc, " +
            "(SELECT TOP 1 CONVERT(VARCHAR(40), p.sid, 1) FROM sys.database_principals p WHERE p.name = N'$n') AS sid, " +
            "(SELECT TOP 1 p.type FROM sys.database_principals p WHERE p.name = N'$n') AS type, " +
            "(SELECT STRING_AGG(r.name, ',') FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id " +
            "JOIN sys.database_principals u ON u.principal_id = m.member_principal_id WHERE u.name = N'$n') AS roles;")
}

function ConvertTo-PimDownlinkSqlSid {
    # PURE. The contained user's SID from its app id: '0x' + Guid.ToByteArray() hex (never the object id).
    param([Parameter(Mandatory)][string]$AppId)
    $g = [guid]"$AppId".Trim()
    return '0x' + (($g.ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Test-PimDownlinkSqlUserState {
    <#
      PURE. Judge what was read about the pull job's user.
        -Row    Get-PimDownlinkSqlUserReadSql's row ($null = not read)
        -Facts  Read-PimAccessFacts (PIM-SetupSteps.ps1) for -AppId / the user name ($null = not asked)
      Seen DIRECTLY when the caller may see other users (db_owner / VIEW DEFINITION): exists, SID, roles. Else through the access
      facts procedure (signed, VIEW DEFINITION): exists + SID, roles NOT readable ($null). Else nothing is known.
      Returns @{ seen = direct | facts | none; exists ($true/$false/$null); sidOk ($true/$false/$null); rolesOk ($true/$false/$null);
                 missingRoles[]; broadRoles[] (fixed db_* roles it holds -- reported, never changed here); hasProc ($true/$false/$null) }.
    #>
    param([AllowNull()][object]$Row, [AllowNull()][object]$Facts, [Parameter(Mandatory)][string]$AppId, [string[]]$Roles = @())
    $o = [ordered]@{ seen = 'none'; exists = $null; sidOk = $null; rolesOk = $null; missingRoles = @(); broadRoles = @(); hasProc = $null }
    $want = ConvertTo-PimDownlinkSqlSid -AppId $AppId
    if ($Row) {
        $o.hasProc = ("$(Get-PimDownlinkSqlUserField $Row 'hasProc')" -eq '1')
        $vis = ("$(Get-PimDownlinkSqlUserField $Row 'callerDbOwner')" -eq '1') -or ("$(Get-PimDownlinkSqlUserField $Row 'callerViewDefinition')" -eq '1')
        if ($vis) {
            $o.seen = 'direct'
            $sid = "$(Get-PimDownlinkSqlUserField $Row 'sid')".Trim()
            $o.exists = [bool]$sid
            if ($o.exists) {
                $o.sidOk = ($sid -ieq $want) -and ("$(Get-PimDownlinkSqlUserField $Row 'type')".Trim() -eq 'E')
                $held = @("$(Get-PimDownlinkSqlUserField $Row 'roles')".Split(',') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
                $o.missingRoles = @(@($Roles) | Where-Object { $held -notcontains "$_" })
                $o.broadRoles = @($held | Where-Object { "$_" -match '^db_' })
                $o.rolesOk = ($o.missingRoles.Count -eq 0)
            }
            return $o
        }
    }
    $f = Get-PimDownlinkSqlUserField $Facts 'facts'
    if ((Get-PimDownlinkSqlUserField $Facts 'present') -eq $true -and $f -and [bool](Get-PimDownlinkSqlUserField $f 'visible')) {
        $o.seen = 'facts'
        $o.exists = [bool](Get-PimDownlinkSqlUserField $f 'namedExists')
        if ($o.exists) {
            $o.sidOk = ("$(Get-PimDownlinkSqlUserField $f 'namedAppId')".Trim() -ieq ([guid]"$AppId").ToString())
            if ([int]"$(Get-PimDownlinkSqlUserField $f 'namedInRole')" -gt 0) { $o.broadRoles = @('db_owner') }
        }
    }
    return $o
}

function Get-PimDownlinkSqlUserApplyLines {
    <#
      PURE. What the updater sends for ONE pull job user, ALL through the signed access procedure: each component role
      (@Action = 'role'), exactly its catalog grants, then the user in each role (@Action = 'user': CREATE USER WITH SID =
      <app id>, TYPE = E when missing, then the role membership when missing). The procedure's own refusals stand (another
      principal with that name, an unsigned procedure). A role that is not pim_<x> is REFUSED (throws): never a fixed role.
    #>
    param([Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$AppId, [Parameter(Mandatory)][string[]]$Roles, [System.Collections.IDictionary]$Catalog)
    if (-not (Test-PimDownlinkSqlUserName $UserName)) { throw "Get-PimDownlinkSqlUserApplyLines: '$UserName' is not a safe database user name." }
    $roles = @(@($Roles) | Where-Object { "$_".Trim() })
    if (-not $roles.Count) { throw 'Get-PimDownlinkSqlUserApplyLines: no roles -- refusing to create a user without its catalog roles.' }
    foreach ($r in $roles) { if ("$r" -cnotmatch '^pim_[a-z]{2,30}$') { throw "Get-PimDownlinkSqlUserApplyLines: '$r' is not a pim_<x> catalog role -- never a fixed role." } }
    if (-not $Catalog) { $Catalog = Get-PimSqlAccessCatalog }
    $sub = [ordered]@{}
    foreach ($r in $roles) {
        if (-not $Catalog.Contains($r)) { throw "Get-PimDownlinkSqlUserApplyLines: '$r' is not in the access catalog." }
        $sub[$r] = @($Catalog[$r])
    }
    $users = @(foreach ($r in $roles) { [pscustomobject]@{ userName = $UserName; appId = $AppId; role = $r } })
    return @(Get-PimSqlAccessApplyBatches -Catalog $sub -Users $users)
}

function Get-PimDownlinkSqlUserSetupFact {
    <#
      PURE. The run record (UpdateState.setupFacts) from the converge's result:
        downlinkDbUser          ok (every pull job has its own user, SID read back, no catalog role missing) | missing | n/a
                                (no pull job) | unknown
        downlinkInAdminGroup    yes (a pull job identity is STILL a member of the SQL admin group) | no | n/a | unknown
        downlinkDbUserDetail    one line, at most 200 characters
    #>
    param([AllowNull()][object]$Result)
    $cut = { param($t) $t = ("$t" -replace '[\r\n\t]+', ' ').Trim(); if ($t.Length -gt 200) { $t = $t.Substring(0, 197) + '...' }; $t }
    if ($null -eq $Result) { return [ordered]@{ downlinkDbUser = 'unknown'; downlinkInAdminGroup = 'unknown'; downlinkDbUserDetail = 'pull job database user: not checked this run' } }
    return [ordered]@{ downlinkDbUser = "$($Result.state)"; downlinkInAdminGroup = "$($Result.inAdminGroup)"; downlinkDbUserDetail = (& $cut "$($Result.detail)") }
}

function Invoke-PimDownlinkSqlUserConverge {
    <#
      The UPDATER's step (update-job-entry.ps1 2e-quinquies). Per pull job in the resource group: its SQL identity + app id, its
      SQL admin group membership (READ), its own database user (read; created through the signed procedure when missing or a
      catalog role is missing; READ BACK). Never removes the membership, never drops or revokes anything, never throws.
      Seams: -Arm { param($method, $path, $body) } (GET only is ever called), -Graph { param($path) } (GET, one page),
      -Query { param($sql) } -> rows, -Exec { param($sql) }, -Scalar { param($sql) } -> one value (the access facts read).
      -Query / -Exec $null = no store this run: the database part is not done (said).
      Returns @{ lines; changed; warnings; state; inAdminGroup; detail; jobs[] ({ jobName; identityKind; appId; principalId;
                 ownUser; sidOk; rolesOk; created; seen; inAdminGroup; statements; reason }) }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][scriptblock]$Arm,
          [AllowNull()][scriptblock]$Graph = $null, [AllowNull()][scriptblock]$Query = $null, [AllowNull()][scriptblock]$Exec = $null,
          [AllowNull()][scriptblock]$Scalar = $null, [AllowEmptyString()][string]$SqlServer = '', [AllowEmptyString()][string]$SqlSkipReason = '')
    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param($level, $text) $lines.Add([pscustomobject]@{ id = 'downlink-db-user'; level = $level; text = "pull job database user: $text" }) }
    $first = { param($e) ((("$($e.Exception.Message)") -split "`n")[0]).Trim() }
    $jobs = New-Object System.Collections.Generic.List[object]
    $o = [ordered]@{ lines = $null; changed = 0; warnings = 0; state = 'unknown'; inAdminGroup = 'unknown'; detail = ''; jobs = $null }
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $aca = 'api-version=2024-03-01'
    try {
        $list = & $Arm 'GET' "$rg/providers/Microsoft.App/jobs?$aca" $null
        $pat = Get-PimDownlinkSqlUserJobPattern
        $found = @(@(Get-PimDownlinkSqlUserField $list 'value') | Where-Object { $_ -and "$(Get-PimDownlinkSqlUserField $_ 'name')" -match $pat } | Sort-Object { "$(Get-PimDownlinkSqlUserField $_ 'name')" })
        if (-not $found.Count) {
            $o.state = 'n/a'; $o.inAdminGroup = 'n/a'; $o.detail = 'no pull job in this install -- nothing to do'
            $o.lines = @($lines.ToArray()); $o.jobs = @(); return [pscustomobject]$o
        }
        $roles = @(Get-PimDownlinkSqlUserRoles)
        foreach ($job in $found) {
            $jn = "$(Get-PimDownlinkSqlUserField $job 'name')"
            $jid = "$(Get-PimDownlinkSqlUserField $job 'id')".Trim(); if (-not $jid) { $jid = "$rg/providers/Microsoft.App/jobs/$jn" }
            $j = [ordered]@{ jobName = $jn; identityKind = ''; appId = ''; principalId = ''; ownUser = $null; sidOk = $null; rolesOk = $null; created = $false; seen = 'none'; inAdminGroup = $null; statements = 0; reason = '' }
            [void]$jobs.Add($j)
            # the job resource itself (the list may not carry the template / identity)
            $full = $job
            if (-not (Get-PimDownlinkSqlUserField (Get-PimDownlinkSqlUserField $job 'properties') 'template') -or -not (Get-PimDownlinkSqlUserField $job 'identity')) {
                try { $tmp = & $Arm 'GET' "$jid`?$aca" $null; if ($tmp) { $full = $tmp } } catch { }
            }
            $idn = Get-PimDownlinkSqlIdentity -Job $full
            $j.identityKind = "$($idn.kind)"; $j.principalId = "$($idn.principalId)"; $j.appId = "$($idn.appId)"
            if ($idn.kind -eq 'none') { $j.reason = "$($idn.reason)"; & $add 'warn' "$jn -- $($idn.reason)"; continue }
            if ($idn.kind -eq 'system') {
                $ap = Resolve-PimDownlinkSqlAppId -Arm $Arm -Graph $Graph -JobId $jid -PrincipalId $idn.principalId
                $j.appId = "$($ap.appId)"
                if (-not $j.appId) { $j.reason = "$($ap.reason)"; & $add 'warn' "$jn -- $($ap.reason); its own user was not made this run (the next update retries)" }
            }
            # the SQL admin group membership of the job identity: READ only, never written here
            if ($j.principalId) {
                $mem = Read-PimDbInitAdminMembership -Arm $Arm -Graph $Graph -ResourceGroupId $rg -SqlServer $SqlServer -PrincipalId $j.principalId
                if ($mem.adminIsGroup -eq $false) { $j.inAdminGroup = $false } else { $j.inAdminGroup = $mem.inAdminGroup }
                if ($null -eq $j.inAdminGroup -and "$($mem.reason)".Trim()) { & $add 'info' "$jn -- its SQL admin group membership could not be read ($($mem.reason))" }
            }
            if (-not $j.appId) { continue }
            if (-not $Query -or -not $Exec) {
                $j.reason = $(if ("$SqlSkipReason".Trim()) { "$SqlSkipReason".Trim() } else { 'no store connection this run' })
                & $add 'info' "$jn -- not read: $($j.reason)"; continue
            }
            if (-not (Test-PimDownlinkSqlUserName $jn)) { $j.reason = "'$jn' is not a safe database user name"; & $add 'warn' "$jn -- $($j.reason)"; continue }
            if (-not $roles.Count) { $j.reason = 'the access catalog (PIM-SqlAccess.ps1) is not loaded -- nothing sent'; & $add 'warn' "$jn -- $($j.reason)"; continue }
            $readOnce = {
                $row = $null; try { $row = @(& $Query (Get-PimDownlinkSqlUserReadSql -UserName $jn))[0] } catch { $row = $null }
                $fx = $null
                if ($Scalar -and (Get-Command Read-PimAccessFacts -ErrorAction SilentlyContinue)) { $fx = Read-PimAccessFacts -Scalar $Scalar -AppIds @($j.appId) -DbUserName $jn }
                return (Test-PimDownlinkSqlUserState -Row $row -Facts $fx -AppId $j.appId -Roles $roles)
            }
            $st = & $readOnce
            $j.seen = "$($st.seen)"
            if ($st.exists -eq $true -and $st.sidOk -eq $false) {
                $j.ownUser = $false; $j.sidOk = $false
                $j.reason = "a database principal named $jn exists with ANOTHER sid -- an admin must resolve it (nothing changed)"
                & $add 'warn' "$jn -- $($j.reason)"; continue
            }
            if ($st.exists -eq $true -and $st.sidOk -eq $true -and $st.rolesOk -eq $true) {
                $j.ownUser = $true; $j.sidOk = $true; $j.rolesOk = $true
                & $add 'info' "$jn has its own database user (sid read back; roles $($roles -join ', ')) -- unchanged"
                if (@($st.broadRoles).Count) { & $add 'warn' "$jn also holds $(@($st.broadRoles) -join ', ') (reported only -- the updater never takes a role away)" }
                continue
            }
            if ($st.hasProc -eq $false) {
                $j.ownUser = $(if ($st.exists -eq $false) { $false } else { $null })
                $j.reason = 'the signed access procedure is not installed yet (the access model''s run 1) -- its own user waits for it; nothing sent'
                & $add 'warn' "$jn -- $($j.reason)"; continue
            }
            $sent = 0; $err = ''
            try {
                foreach ($l in @(Get-PimDownlinkSqlUserApplyLines -UserName $jn -AppId $j.appId -Roles $roles)) { & $Exec $l; $sent++ }
            } catch { $err = & $first $_ }
            $j.statements = $sent
            if ($err) { $j.reason = "not created through the signed access procedure: $err"; & $add 'warn' "$jn -- $($j.reason) (the next update retries; a name held by another principal needs an admin)" }
            # READ BACK, never assumed
            $bk = & $readOnce
            $j.seen = "$($bk.seen)"; $j.sidOk = $bk.sidOk; $j.rolesOk = $bk.rolesOk
            if ($bk.exists -eq $true -and $bk.sidOk -eq $true -and $bk.rolesOk -ne $false) {
                $j.ownUser = $true; $j.created = ($st.exists -ne $true)
                $rb = $(if ($bk.rolesOk -eq $true) { "roles $($roles -join ', ') read back" } else { "roles $($roles -join ', ') set through the signed procedure (this identity cannot read another user's roles)" })
                # created (or a missing catalog role added, read back) = changed; an existing user whose roles this identity
                # cannot read was only re-sent through the idempotent procedure = info (not a change every run)
                $lvl = $(if ($j.created -or @($st.missingRoles).Count) { 'changed' } else { 'info' })
                & $add $lvl "$jn -- its own database user $(if ($j.created) { 'created' } else { 'converged' }) from its app id $($j.appId) (sid read back$(if ($bk.seen -eq 'facts') { ' through the access facts procedure' }); $rb)"
            } elseif ($bk.exists -eq $false -or $bk.sidOk -eq $false -or $bk.rolesOk -eq $false) {
                $j.ownUser = $false
                if (-not $err) { $j.reason = "read back: $(if ($bk.exists -eq $false) { 'no such user' } elseif ($bk.sidOk -eq $false) { 'another sid' } else { "missing $(@($bk.missingRoles) -join ', ')" })"; & $add 'warn' "$jn -- $($j.reason)" }
            } else {
                $j.ownUser = $null
                if (-not $err) { $j.reason = 'sent through the signed procedure, but this identity cannot read it back (no access facts procedure) -- not proven'; & $add 'warn' "$jn -- $($j.reason)" }
            }
        }
    } catch { & $add 'warn' "not checked: $(& $first $_)" }
    # ---- the verdict over every pull job ----------------------------------------------------------------------------------
    $ja = @($jobs.ToArray())
    if ($ja.Count) {
        if (@($ja | Where-Object { $_.ownUser -eq $false }).Count) { $o.state = 'missing' }
        elseif (@($ja | Where-Object { $_.ownUser -ne $true }).Count) { $o.state = 'unknown' }
        else { $o.state = 'ok' }
        if (@($ja | Where-Object { $_.inAdminGroup -eq $true }).Count) { $o.inAdminGroup = 'yes' }
        elseif (@($ja | Where-Object { $null -eq $_.inAdminGroup }).Count) { $o.inAdminGroup = 'unknown' }
        else { $o.inAdminGroup = 'no' }
        $o.detail = (@($ja | ForEach-Object {
            $u = $(if ($_.ownUser -eq $true) { 'own user' } elseif ($_.ownUser -eq $false) { 'NO own user' } else { 'own user not proven' })
            $m = $(if ($_.inAdminGroup -eq $true) { 'still in the SQL admin group' } elseif ($_.inAdminGroup -eq $false) { 'not in the SQL admin group' } else { 'admin group membership unknown' })
            "$($_.jobName): $u, $m"
        }) -join '; ')
        foreach ($x in @($ja | Where-Object { $_.ownUser -eq $true -and $_.inAdminGroup -eq $true })) {
            & $add 'info' "$($x.jobName) is STILL a member of the SQL admin group -- the updater never removes it; a support step does, after one pull ran green on its own user"
        }
    }
    $o.lines = @($lines.ToArray()); $o.jobs = $ja
    $o.changed = @($lines | Where-Object { $_.level -eq 'changed' }).Count; $o.warnings = @($lines | Where-Object { $_.level -eq 'warn' }).Count
    return [pscustomobject]$o
}
