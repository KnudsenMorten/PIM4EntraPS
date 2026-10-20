#Requires -Version 5.1

<#
.SYNOPSIS
  Gives (or with -Remove takes back) the customer's Invardia Support app its access to this PIM Manager installation: troubleshoot = a read-only contained SQL user; setup = member of the SQL admin group and owner of PIM's own app registrations and groups; asbuilt = start the as-built job (caj-pim-asbuilt) and read the PDFs it writes, nothing else (troubleshoot and setup include it). Every change is read back. Every level also gives the Support app its standing database access: membership of the SQL admin group and its own database user in the database owner role.

.DESCRIPTION
  §95.2 / GUIDED-INSTALL §4.6.
  Grant-PimSupportAccess -AppId <support app client id> -Level troubleshoot|setup [-Remove]
      -TenantId <t> -SubscriptionId <s> -ResourceGroup <rg> -SqlServer <server>.database.windows.net [-EnvLabel <label>]

  troubleshoot  a contained SQL user created FROM THE APP'S SID (never FROM EXTERNAL PROVIDER) with db_datareader +
                VIEW DEFINITION -- it can read the store and its schema, nothing else.
  setup         member of the SQL admin group (grp-pim-sql-admins: create users, deploy schema, repair) AND owner of PIM's
                own app registrations and groups -- the Manager's sign-in app, the access request API app, the members
                group and the SQL admin group -- so the support app's Application.ReadWrite.OwnedBy is enough later.
  asbuilt       (PIM 100.61, framework 8.12) ONLY the as-built document: the custom role 'PIM Manager as-built runner (<rg>)'
                (Microsoft.App/jobs/start/action + Microsoft.App/jobs/executions/read) on the ONE job caj-pim-asbuilt, and
                Storage Blob Data Reader on the ONE container 'asbuilt' of the PIM storage account (the account the job names in
                PIM_ASBUILT_STORAGE). troubleshoot and setup include it when -SubscriptionId and -ResourceGroup are given; there a
                failure is reported and the rest of the access stands. Needs Owner / User Access Administrator (or Role Based
                Access Control Administrator once the role exists) on the PIM resource group.
  -Remove       takes back every level: the membership, the ownerships, the contained user and the as-built assignments.

  EVERY level (PIM REQUIREMENTS 100.116, framework 4.1b) also gives the Support app its STANDING database access: it is
  made a member of the SQL admin group, and it gets its own database user -- created from the application's client id,
  found by that id whatever its name -- in db_owner (database owner: what PIM Manager's setup and repair scripts need to
  create database users, add them to fixed database roles and apply the schema). It stays until -Remove, or until the
  customer switches the Support app off in Microsoft Entra ID. With -Level asbuilt it needs -SqlServer (the installer
  passes it); without a SQL server it is said in one line and nothing is created.

  The support app's Azure roles and API permissions are granted by Invardia's New-InvardiaSupportApp.ps1, not here.
  Runs as the signed-in account (PIM-Rest: the Invardia Support app's REST session, else the browser sign-in; no az CLI);
  never a stored secret. Every change is read back.
  Adding a member to the role-assignable SQL admin group needs Privileged Role Administrator; without it that part is
  reported and the rest continues (exit 1). Container installs have no Key Vault, so there is no vault grant.

.EXAMPLE
  ./Grant-PimSupportAccess.ps1 -AppId 00000000-0000-0000-0000-000000000000 -Level setup -TenantId <t> -SubscriptionId <s> `
      -ResourceGroup rg-pim -SqlServer sql-pim-ab12cd.database.windows.net

.LINK
  https://invardia.com/docs/pim/scripts/Grant-PimSupportAccess/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$AppId,
    [ValidateSet('troubleshoot', 'setup', 'asbuilt')][string]$Level = 'troubleshoot',
    [Parameter(Mandatory)][string]$TenantId,
    [string]$SubscriptionId = '',
    [string]$ResourceGroup = '',
    [string]$SqlServer = '',
    [string]$SqlDatabase = 'PimPlatform',
    [ValidatePattern('^$|^[a-z0-9][a-z0-9-]{0,19}$')][string]$EnvLabel = '',
    [string]$SqlAdminGroupName = 'grp-pim-sql-admins',
    [string]$DbUserName = 'invardia-support',
    [string]$AsBuiltJobName = 'caj-pim-asbuilt',
    [switch]$Remove,
    # --- test seams (tests/Test-PimSupportAccess.ps1) ---
    [scriptblock]$Graph,
    [scriptblock]$Sql,
    # ARM: param([string]$Method, [string]$Path, $Body, [string]$ApiVersion) -> the response object ($null = not found)
    [scriptblock]$Arm
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. (Join-Path $here '_PimSetupShared.ps1')
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
. (Join-Path $PSScriptRoot '_PimSupportSqlAccess.ps1')   # 100.116: the standing database access (the user by SID + db_owner)
$null = Start-PimScriptRun -Script 'Grant-PimSupportAccess'
$script:grantRc = 0
try {

$G = 'https://graph.microsoft.com/v1.0'
# 100.41 (NO-AZ): every token comes from PIM-Rest's ONE token client, PINNED to -TenantId -- never a default context, which
# on a machine holding several logins is another directory (code audit 2026-10-04). A caller that already set up PIM-Rest's
# identity keeps it; otherwise sign in: the Invardia Support app's REST session for this tenant, else the person's browser.
. (Join-Path (Split-Path -Parent (Split-Path -Parent $here)) 'engine\_shared\PIM-AsBuilt.ps1')   # 100.61: the as-built grants (pure)
. (Join-Path (Split-Path -Parent (Split-Path -Parent $here)) 'engine\_shared\PIM-InstallNames.ps1')   # CR5: names + display-name forms
# 100.61 (framework 8.12): the as-built document access -- start the ONE job caj-pim-asbuilt + read its executions, and
# Storage Blob Data Reader on the ONE container 'asbuilt'. Level asbuilt grants ONLY that; troubleshoot and setup include it
# (it is less than either); -Remove takes it back. Needs the subscription + resource group (where the job is).
$abWanted = ($Level -eq 'asbuilt') -or ($Level -in @('troubleshoot', 'setup')) -or $Remove
$abScoped = [bool]("$SubscriptionId".Trim() -and "$ResourceGroup".Trim())
# A failure is a PROBLEM (exit 1) when the as-built access is the point of the run (-Level asbuilt) or when it is taken back
# (-Remove); with troubleshoot / setup it is REPORTED and the rest of the access stands.
$abHard = ($Level -eq 'asbuilt') -or $Remove
# 100.116: the standing database access is given at EVERY level, so -Level asbuilt reaches the database too when -SqlServer
# is given (asbuilt never goes looking for the server itself).
$needRest = (-not $Graph) -or (-not $Sql -and ("$SqlServer".Trim() -or ($Level -ne 'asbuilt' -and "$ResourceGroup".Trim() -and "$SubscriptionId".Trim()))) -or ($abWanted -and $abScoped -and -not $Arm)
if ($needRest -and -not $global:PIM_SetupRestMode -and -not "$($global:PIM_ClientId)".Trim()) {
    if ("$SubscriptionId".Trim()) { [void](Connect-PimSetupRest -SubscriptionId "$SubscriptionId".Trim() -TenantId $TenantId) } else { [void](Connect-PimSetupRest -TenantId $TenantId) }
}
# No -SqlServer given: the PIM store in -ResourceGroup (a guided install has exactly one). az sql server list -g over ARM.
$script:gsaSqlAdminGroupId = ''
if ($Level -ne 'asbuilt' -and -not "$SqlServer".Trim() -and "$ResourceGroup".Trim() -and "$SubscriptionId".Trim() -and -not $Sql) {
    $srvList = @(@(Invoke-PimSetupArm -Path "/subscriptions/$("$SubscriptionId".Trim())/resourceGroups/$ResourceGroup/providers/Microsoft.Sql/servers" -ApiVersion (Get-PimSetupApiVersion sql) -All -ErrorAsNull) |
                 Where-Object { $_ -and "$($_.properties.fullyQualifiedDomainName)".Trim() })
    $found = @($srvList | ForEach-Object { "$($_.properties.fullyQualifiedDomainName)".Trim() })
    if ($found.Count -eq 1) {
        $SqlServer = "$($found[0])".Trim(); Write-Host "  SQL server in $($ResourceGroup): $SqlServer" -ForegroundColor DarkGray
        # 33.0 item 5 (2026-10-20): the server list already carries the server's Entra administrator -- when it is a GROUP its
        # sid IS the SQL admin group's object id, and Find-One reads the group by that id (a renamed group is still found)
        $adm1 = $srvList[0].properties.administrators
        if ($adm1 -and "$($adm1.principalType)" -ieq 'Group' -and "$($adm1.sid)".Trim()) { $script:gsaSqlAdminGroupId = "$($adm1.sid)".Trim() }
    }
    elseif ($found.Count -gt 1) { throw "resource group '$ResourceGroup' holds $($found.Count) SQL servers -- name the PIM one with -SqlServer" }
}
if (-not $Graph) {
    $gTok = ''; try { $gTok = "$(Get-PimRestToken -Resource 'graph' -TenantId $TenantId)".Trim() } catch { $gTok = '' }
    if (-not $gTok) { throw "no Graph token for tenant $TenantId -- sign in to that tenant (a browser sign-in opens in a PowerShell window), or connect its Invardia Support app (Connect-InvardiaSupport.ps1 -Environment <handle>)" }
    $Graph = {
        param([string]$Method, [string]$Path, $Body)
        $h = @{ Authorization = "Bearer $gTok"; ConsistencyLevel = 'eventual' }
        $a = @{ Method = $Method; Uri = "$G$Path"; Headers = $h }
        if ($null -ne $Body) { $a['Body'] = ($Body | ConvertTo-Json -Depth 6 -Compress); $a['ContentType'] = 'application/json' }
        Invoke-RestMethod @a
    }.GetNewClosure()
}
if (-not $Sql -and "$SqlServer".Trim()) {
    . (Join-Path (Split-Path -Parent (Split-Path -Parent $here)) 'engine\_shared\PIM-SqlStore.ps1')
    $script:gsaSqlToken = ''; try { $script:gsaSqlToken = "$(Get-PimRestToken -Resource 'https://database.windows.net' -TenantId $TenantId)".Trim() } catch { $script:gsaSqlToken = '' }
    $script:gsaSqlConn = "Server=tcp:$SqlServer,1433;Database=$SqlDatabase;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
    # 100.116 (the defect found): this was a .GetNewClosure() block. A closure runs in its own module scope and cannot see
    # Resolve-PimSqlClientType, which the line above loads into THIS script's scope (the trap recorded in
    # engine\_shared\PIM-EngineCore.ps1, 2.4.466) -- so a real run (no -Sql seam) ends in "The term
    # 'Resolve-PimSqlClientType' is not recognized", the SQL part is reported as not done, and the Support app gets no
    # database user. Found by reading the code; every test hands in -Sql. A PLAIN scriptblock sees this script's scope.
    $Sql = {
        param([string]$Query)
        $c = New-Object (Resolve-PimSqlClientType).FullName $script:gsaSqlConn
        $c.AccessToken = $script:gsaSqlToken; $c.Open()
        try { $cmd = $c.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 60; return $cmd.ExecuteScalar() } finally { $c.Close() }
    }
}

$problems = New-Object System.Collections.Generic.List[string]
function Say([string]$m, [string]$c = 'Gray') { Write-Host "  $m" -ForegroundColor $c }
function Find-One([string]$Kind, [string]$DisplayName, [string]$Id = '') {
    # 33.0 item 5 (2026-10-20): -Id (the SQL server administrator's sid, when the script has it) is read first; the
    # display name below is the fallback (an id that does not read falls through to it)
    if ("$Id".Trim()) {
        try { $byId = & $Graph 'GET' "/$Kind/$([uri]::EscapeDataString("$Id".Trim()))?`$select=id,displayName" $null; if ($byId -and "$($byId.id)".Trim()) { return $byId } } catch { }
    }
    # CR5 item 5: the name in BOTH forms ('PIM4EntraPS Manager ...' / 'PIM Manager ...') -- the update may have renamed it,
    # and a new-name install (CR5 step 2) created it with the new one
    foreach ($dn in @(Get-PimDisplayNameForms $DisplayName)) {
        $f = [uri]::EscapeDataString("displayName eq '$($dn.Replace("'", "''"))'")
        $hit = @((& $Graph 'GET' "/$Kind`?`$select=id,displayName,appId&`$filter=$f" $null).value) | Select-Object -First 1
        if ($hit) { return $hit }
    }
    return $null
}
function Get-Ids([string]$Path) { @((& $Graph 'GET' $Path $null).value | ForEach-Object { "$($_.id)" }) }

# ---- the support app's service principal in THIS tenant
$sp = @((& $Graph 'GET' "/servicePrincipals?`$select=id,appId,displayName&`$filter=$([uri]::EscapeDataString("appId eq '$AppId'"))" $null).value) | Select-Object -First 1
if (-not $sp) { throw "the support app $AppId has no service principal in tenant $TenantId -- run Invardia's New-InvardiaSupportApp.ps1 (admin consent) first" }
Write-Host "Invardia Support app: $($sp.displayName) ($AppId) -- $(if ($Remove) { 'REMOVE all access' } else { "grant '$Level'" })" -ForegroundColor Cyan
$ref = @{ '@odata.id' = "$G/directoryObjects/$($sp.id)" }

# ---- PIM's own objects (a label = the per-environment names of Invoke-PimDeployAll -EnvLabel)
$suffix = if ("$EnvLabel".Trim()) { " ($EnvLabel)" } else { '' }
$objects = @(
    @{ kind = 'groups';       name = $SqlAdminGroupName;                                                                  what = 'SQL admin group' }
    @{ kind = 'applications'; name = "PIM4EntraPS Manager$suffix";                                                          what = 'Manager sign-in app' }
    @{ kind = 'applications'; name = "PIM access request API$suffix";                                                       what = 'access request API app' }
    @{ kind = 'groups';       name = $(if ($suffix) { "PIM4EntraPS Manager users$suffix (members, no guests)" } else { 'PIM4EntraPS Manager users (members, no guests)' }); what = 'Manager members group' }
)

# ---- ownerships: granted only at setup. SQL admin group MEMBERSHIP: at every level (100.116 / framework 4.1b: the Support
# app is a member of the SQL admin group of every install and stays one). Both are taken back by -Remove.
$ownerLevel = ($Level -eq 'setup' -or $Remove)
foreach ($o in $objects) {
    if (-not $ownerLevel -and $o.what -ne 'SQL admin group') { continue }
    $obj = Find-One $o.kind $o.name $(if ($o.what -eq 'SQL admin group') { $script:gsaSqlAdminGroupId } else { '' })
    if (-not $obj) { Say "($($o.what) '$($o.name)' does not exist here -- nothing to do)" 'DarkGray'; continue }
    if ($ownerLevel) {
        $owners = Get-Ids "/$($o.kind)/$($obj.id)/owners?`$select=id"
        $isOwner = $owners -contains "$($sp.id)"
        if ($Remove -and $isOwner -and $PSCmdlet.ShouldProcess($o.name, 'remove owner')) {
            try { [void](& $Graph 'DELETE' "/$($o.kind)/$($obj.id)/owners/$($sp.id)/`$ref" $null); Say "owner removed: $($o.what) '$($o.name)'" 'Green' } catch { $problems.Add("remove owner of '$($o.name)': $($_.Exception.Message)") }
        } elseif (-not $Remove -and -not $isOwner -and $PSCmdlet.ShouldProcess($o.name, 'add owner')) {
            try { [void](& $Graph 'POST' "/$($o.kind)/$($obj.id)/owners/`$ref" $ref); Say "owner added: $($o.what) '$($o.name)'" 'Green' }
            catch { if ("$_" -match 'already exist') { Say "owner (already): $($o.what) '$($o.name)'" } else { $problems.Add("add owner of '$($o.name)': $($_.Exception.Message)") } }
        } elseif (-not $Remove) { Say "owner (already): $($o.what) '$($o.name)'" }
    }
    if ($o.what -ne 'SQL admin group') { continue }
    $members = Get-Ids "/groups/$($obj.id)/members?`$select=id"
    $isMember = $members -contains "$($sp.id)"
    if ($Remove -and $isMember -and $PSCmdlet.ShouldProcess($o.name, 'remove member')) {
        try { [void](& $Graph 'DELETE' "/groups/$($obj.id)/members/$($sp.id)/`$ref" $null); Say "member removed: SQL admin group '$($o.name)'" 'Green' } catch { $problems.Add("remove member of '$($o.name)': $($_.Exception.Message) (a role-assignable group needs Privileged Role Administrator)") }
    } elseif (-not $Remove -and -not $isMember -and $PSCmdlet.ShouldProcess($o.name, 'add member')) {
        try { [void](& $Graph 'POST' "/groups/$($obj.id)/members/`$ref" $ref); Say "member added: SQL admin group '$($o.name)' (it stays a member; SQL picks it up with the app's next token)" 'Green' }
        catch { if ("$_" -match 'already exist') { Say "member (already): SQL admin group '$($o.name)'" } else { $problems.Add("add member to '$($o.name)': $($_.Exception.Message) (a role-assignable group needs Privileged Role Administrator)") } }
    } elseif (-not $Remove) { Say "member (already): SQL admin group '$($o.name)'" }
}

# ---- 100.116 (framework 4.1b): the STANDING database access, at every level -- the Support app's own database user,
# looked up BY ITS ID (the client id as a SID, never by name, never FROM EXTERNAL PROVIDER), in the database owner role.
# Why a user and not only the group: membership alone has not given an APPLICATION a database sign-in on the servers this
# was measured on. Why db_owner: PIM's setup scripts add identities to fixed database roles, which needs db_owner.
if (-not $Remove) {
    $stRole = Get-PimSupportSqlRoleName
    if (-not $Sql) {
        Write-Host '  standing database access NOT set: no -SqlServer given -- no database user was created for the Support app' -ForegroundColor Yellow
    } elseif ($PSCmdlet.ShouldProcess("$SqlServer/$SqlDatabase", "standing database access: the Support app's own database user (from its client id) in $stRole")) {
        $st = Invoke-PimSupportSqlUser -Sql $Sql -AppId $AppId -DbUserName $DbUserName -Role $stRole
        if ($st.ok) {
            Say "standing database access: database user [$($st.userName)] ($(if ($st.created) { 'created from the client id' } else { 'already there' })) is in $stRole (read back). It ends when the Support app is switched off in Microsoft Entra ID, or with -Remove." 'Green'
            # a user of the Support app that already exists under another name is the one every later statement uses
            if ("$($st.userName)".Trim()) { $DbUserName = "$($st.userName)" }
        } else { $problems.Add("standing database access: $($st.problem) (the signed-in account must be a member of '$SqlAdminGroupName' or the server's Entra admin)") }
    }
}

# ---- troubleshoot: read access + VIEW DEFINITION on the same user (and the user is dropped by -Remove)
if (($Level -eq 'troubleshoot' -or $Remove) -and $Sql) {
    $u = $DbUserName.Replace(']', ']]')
    try {
        if ($Remove) {
            if ($PSCmdlet.ShouldProcess("$SqlServer/$SqlDatabase", "DROP USER [$DbUserName]")) {
                # the user of the Support app's id whatever its name (100.116), then the one of this name
                [void](& $Sql (Get-PimSupportSqlUserDropSql -AppId $AppId))
                [void](& $Sql "IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$($DbUserName.Replace("'", "''"))') DROP USER [$u];")
                Say "SQL user [$DbUserName] removed" 'Green'
            }
        } elseif ($PSCmdlet.ShouldProcess("$SqlServer/$SqlDatabase", "contained user [$DbUserName] (db_datareader + VIEW DEFINITION)")) {
            # 100.116: db_owner is no longer taken back here -- it is the standing right given above
            $t = Get-PimSqlContainedUserSql -DbUserName $DbUserName -AppId $AppId -Roles @('db_datareader') -RevokeRoles @('db_datawriter', 'db_ddladmin')
            [void](& $Sql ($t + "`nGRANT VIEW DEFINITION TO [$u];"))
            $back = & $Sql "SELECT COUNT(*) FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id JOIN sys.database_principals p ON p.principal_id = m.member_principal_id WHERE r.name = N'db_datareader' AND p.name = N'$($DbUserName.Replace("'", "''"))'"
            if ([int]"$back" -ge 1) { Say "SQL user [$DbUserName]: db_datareader + VIEW DEFINITION (read back)" 'Green' } else { $problems.Add("SQL user [$DbUserName] was not read back in db_datareader") }
        }
    } catch { $problems.Add("SQL on $SqlServer : $($_.Exception.Message) (the signed-in account must be a member of '$SqlAdminGroupName' or the server's Entra admin)") }
} elseif (($Level -eq 'troubleshoot' -or $Remove) -and -not $Sql) { $problems.Add('no -SqlServer given -- the SQL part was not done') }

# ---- 100.61 as-built: start + read executions on the job caj-pim-asbuilt, Storage Blob Data Reader on the container 'asbuilt'
$abNotes = New-Object System.Collections.Generic.List[string]
$abProblem = { param($m) if ($abHard) { $problems.Add("as-built: $m") } else { $abNotes.Add($m) } }
if ($abWanted -and -not $abScoped) {
    if ($abHard) { $problems.Add('as-built: no -SubscriptionId / -ResourceGroup given -- the as-built access was not done') }
} elseif ($abWanted) {
    if (-not $Arm) {
        $Arm = {
            param([string]$Method, [string]$Path, $Body, [string]$ApiVersion)
            if ($Method -eq 'GET') { return (Invoke-PimSetupArm -Path $Path -ApiVersion $ApiVersion -NotFoundOk) }
            if ($null -ne $Body) { return (Invoke-PimSetupArm -Method $Method -Path $Path -Body $Body -ApiVersion $ApiVersion) }
            return (Invoke-PimSetupArm -Method $Method -Path $Path -ApiVersion $ApiVersion)
        }
    }
    $sub = "$SubscriptionId".Trim(); $rg = "$ResourceGroup".Trim()
    $apiAuth = Get-PimSetupApiVersion authorization; $apiAca = Get-PimSetupApiVersion aca
    try {
        $job = & $Arm 'GET' "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/jobs/$AsBuiltJobName" $null $apiAca
        if (-not $job) { & $abProblem "the as-built job '$AsBuiltJobName' is not deployed in $rg (tools/setup/Deploy-PimAsBuiltJob.ps1 installs it) -- nothing granted for it" }
        else {
            # where the job writes: its own env (Deploy-PimAsBuiltJob stamped it) -- never a guess
            $jenv = @{}; foreach ($c in @($job.properties.template.containers)) { foreach ($e in @($c.env)) { if ($e -and "$($e.name)") { $jenv["$($e.name)"] = "$($e.value)" } } }
            $acct = "$($jenv['PIM_ASBUILT_STORAGE'])".Trim(); $cont = "$($jenv['PIM_ASBUILT_CONTAINER'])".Trim(); if (-not $cont) { $cont = 'asbuilt' }
            if ($acct -notmatch '^[a-z0-9]{3,24}$') { & $abProblem "the job '$AsBuiltJobName' names no storage account (PIM_ASBUILT_STORAGE) -- re-run Deploy-PimAsBuiltJob.ps1" }
            else {
                $grants = @(Get-PimAsBuiltSupportGrants -SubscriptionId $sub -ResourceGroup $rg -StorageAccount $acct -JobName $AsBuiltJobName -Container $cont)
                # the custom role (start + read executions only) must exist before it can be assigned
                $rd = Get-PimAsBuiltRoleDefinition -SubscriptionId $sub -ResourceGroup $rg
                if (-not $Remove -and $PSCmdlet.ShouldProcess($rd.body.properties.roleName, 'create / converge the custom role (start the as-built job + read its executions)')) {
                    $have = $null; try { $have = & $Arm 'GET' $rd.path $null $apiAuth } catch { $have = $null }
                    if (-not $have) { [void](& $Arm 'PUT' $rd.path $rd.body $apiAuth); Say "custom role created: $($rd.body.properties.roleName)" 'Green' }
                }
                foreach ($g in $grants) {
                    $wantGuid = (("$($g.roleDefinitionId)" -split '/')[-1]).ToLowerInvariant()
                    $f = [uri]::EscapeDataString("principalId eq '$($sp.id)'")
                    $list = & $Arm 'GET' "$($g.scope)/providers/Microsoft.Authorization/roleAssignments?`$filter=$f" $null $apiAuth
                    $mine = @(@($list.value) | Where-Object { $_ -and "$($_.properties.principalId)" -eq "$($sp.id)" -and "$($_.properties.scope)".TrimEnd('/') -ieq $g.scope -and (("$($_.properties.roleDefinitionId)" -split '/')[-1]).ToLowerInvariant() -eq $wantGuid })
                    if ($Remove) {
                        foreach ($a in $mine) {
                            if ($PSCmdlet.ShouldProcess($g.scope, "remove: $($g.what)")) { [void](& $Arm 'DELETE' "$($a.id)" $null $apiAuth); Say "removed: $($g.what)" 'Green' }
                        }
                        continue
                    }
                    if ($mine.Count) { Say "(already) $($g.what)"; continue }
                    if (-not $PSCmdlet.ShouldProcess($g.scope, "grant: $($g.what)")) { continue }
                    $body = @{ properties = @{ roleDefinitionId = $g.roleDefinitionId; principalId = "$($sp.id)"; principalType = 'ServicePrincipal' } }
                    try { [void](& $Arm 'PUT' "$($g.scope)/providers/Microsoft.Authorization/roleAssignments/$([guid]::NewGuid().ToString())" $body $apiAuth) }
                    catch { if ("$($_.Exception.Message)" -notmatch '(?i)RoleAssignmentExists|already exists') { throw } }
                    $back = & $Arm 'GET' "$($g.scope)/providers/Microsoft.Authorization/roleAssignments?`$filter=$f" $null $apiAuth
                    $ok = @(@($back.value) | Where-Object { $_ -and "$($_.properties.principalId)" -eq "$($sp.id)" -and (("$($_.properties.roleDefinitionId)" -split '/')[-1]).ToLowerInvariant() -eq $wantGuid }).Count -gt 0
                    if ($ok) { Say "granted (read back): $($g.what)" 'Green' } else { & $abProblem "not read back: $($g.what) on $($g.scope)" }
                }
            }
        }
    } catch { & $abProblem "$($_.Exception.Message) (assigning Azure roles needs Owner, User Access Administrator or Role Based Access Control Administrator on the PIM resource group; creating the custom role needs Owner or User Access Administrator)" }
}
foreach ($n in $abNotes) { Write-Host "  as-built access NOT given: $n (the rest of the access stands)" -ForegroundColor Yellow }

if ($problems.Count) {
    Write-Host 'NOT everything was done:' -ForegroundColor Yellow
    foreach ($p in $problems) { Write-Host "  - $p" -ForegroundColor Yellow }
    $script:grantRc = 1
} elseif ($WhatIfPreference) {
    Write-Host 'preview only -- nothing was changed' -ForegroundColor Green
} else {
    Write-Host 'done' -ForegroundColor Green
}
} finally { Stop-PimScriptRun -Script 'Grant-PimSupportAccess' }
$global:LASTEXITCODE = $script:grantRc
exit $script:grantRc
