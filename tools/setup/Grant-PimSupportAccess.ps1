#Requires -Version 5.1

<#
.SYNOPSIS
  Gives (or with -Remove takes back) the customer's Invardia Support app its access to this PIM Manager installation: its own read-only database user (the read role pim_support_read) and the time-limited support access module with the level as the consent (troubleshoot = read only; setup = admin rights only inside an open support session, at most 8 hours); asbuilt = start the as-built job (caj-pim-asbuilt) and read the PDFs it writes (troubleshoot and setup include it). The Support app is never made a member of the SQL admin group, never a database owner and never an owner of PIM's app registrations or groups. Every change is read back.

.DESCRIPTION
  §95.2 / GUIDED-INSTALL §4.6; framework SECAUDIT-1a / OPEN-01 (the Support app's standing access is read-only).
  Grant-PimSupportAccess -AppId <support app client id> -Level troubleshoot|setup|asbuilt [-Remove]
      -TenantId <t> -SubscriptionId <s> -ResourceGroup <rg> -SqlServer <server>.database.windows.net [-EnvLabel <label>]

  EVERY level gives the Support app ONE standing right: its own database user -- created from the application's client
  id as a SID (never FROM EXTERNAL PROVIDER), found by that id whatever its name -- in the read role pim_support_read
  (SELECT on the product schemas pim and platform, nothing else). It is made by the time-limited support access module,
  installed in the same run (the consent table, the read role, the signed procedures), with this level as the consent:
  troubleshoot  the read-only user, and nothing more.
  setup         the read-only user; admin rights (db_owner) exist only inside an open support session (at most 8 hours),
                opened and closed by the installation's own support job -- never a standing right.
  asbuilt       (PIM 100.61, framework 8.12) the read-only user (with -SqlServer; consent troubleshoot), and the as-built
                document: the custom role 'PIM Manager as-built runner (<rg>)' (Microsoft.App/jobs/start/action +
                Microsoft.App/jobs/executions/read) on the ONE job caj-pim-asbuilt, and Storage Blob Data Reader on the ONE
                container 'asbuilt' of the PIM storage account (the account the job names in PIM_ASBUILT_STORAGE).
                troubleshoot and setup include it when -SubscriptionId and -ResourceGroup are given; there a failure is
                reported and the rest of the access stands. Needs Owner / User Access Administrator (or Role Based Access
                Control Administrator once the role exists) on the PIM resource group.
  -Remove       takes back everything a grant of this or an earlier version gave: the database user (by the Support app's
                id, with every role it holds), a membership of the SQL admin group, owner entries on PIM's app
                registrations and groups, and the as-built assignments.

  No level adds the Support app to the SQL admin group, puts it in db_owner or db_datareader, grants it VIEW DEFINITION
  or makes it an owner of PIM's app registrations or groups. A re-run on an installation where an earlier version gave
  any of these says so in one line and leaves it as found; -Remove takes it back.
  Without -SqlServer no database user is made: said in one line (a problem at troubleshoot and setup).

  The support app's Azure roles and API permissions are granted by Invardia's New-InvardiaSupportApp.ps1, not here.
  Runs as the signed-in account (PIM-Rest: the Invardia Support app's REST session, else the browser sign-in; no az CLI);
  never a stored secret. Every change is read back. The database part needs a database owner sign-in (a member of the
  SQL admin group or the server's Entra admin -- the installer during an installation). Removing a member from the
  role-assignable SQL admin group (-Remove) needs Privileged Role Administrator; without it that part is reported and the
  rest continues (exit 1). Container installs have no Key Vault, so there is no vault grant.

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
. (Join-Path $PSScriptRoot '_PimSupportSqlAccess.ps1')   # 100.116: the Support app's database user, found by SID (the read)
# OPEN-01 (framework SECAUDIT-1a): the time-limited support access module -- the read role pim_support_read, the consent, the
# signed procedures (Invoke-PimSupportJitInstall). The Support app's ONLY standing database right is that read role.
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-SupportJit.ps1')
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
# OPEN-01: the read-only database user is given at EVERY level, so -Level asbuilt reaches the database too when -SqlServer
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

# ---- PIM's own objects (a label = the per-environment names of Invoke-PimDeployAll -EnvLabel)
$suffix = if ("$EnvLabel".Trim()) { " ($EnvLabel)" } else { '' }
$objects = @(
    @{ kind = 'groups';       name = $SqlAdminGroupName;                                                                  what = 'SQL admin group' }
    @{ kind = 'applications'; name = "PIM4EntraPS Manager$suffix";                                                          what = 'Manager sign-in app' }
    @{ kind = 'applications'; name = "PIM access request API$suffix";                                                       what = 'access request API app' }
    @{ kind = 'groups';       name = $(if ($suffix) { "PIM4EntraPS Manager users$suffix (members, no guests)" } else { 'PIM4EntraPS Manager users (members, no guests)' }); what = 'Manager members group' }
)

# ---- PIM's own objects. OPEN-01 (framework SECAUDIT-1a): a grant ADDS nothing here -- the Support app is never made a
# member of the SQL admin group (a standing database administrator) and never an owner of PIM's app registrations or
# groups. A grant only READS whether an earlier version left a membership, and says so; -Remove takes back the membership
# and every owner entry an earlier grant gave.
$earlier = New-Object System.Collections.Generic.List[string]
foreach ($o in $objects) {
    if (-not $Remove -and $o.what -ne 'SQL admin group') { continue }
    $obj = Find-One $o.kind $o.name $(if ($o.what -eq 'SQL admin group') { $script:gsaSqlAdminGroupId } else { '' })
    if (-not $obj) { Say "($($o.what) '$($o.name)' does not exist here -- nothing to do)" 'DarkGray'; continue }
    if ($Remove) {
        $owners = Get-Ids "/$($o.kind)/$($obj.id)/owners?`$select=id"
        $isOwner = $owners -contains "$($sp.id)"
        if ($Remove -and $isOwner -and $PSCmdlet.ShouldProcess($o.name, 'remove owner')) {
            try { [void](& $Graph 'DELETE' "/$($o.kind)/$($obj.id)/owners/$($sp.id)/`$ref" $null); Say "owner removed: $($o.what) '$($o.name)'" 'Green' } catch { $problems.Add("remove owner of '$($o.name)': $($_.Exception.Message)") }
        }
    }
    if ($o.what -ne 'SQL admin group') { continue }
    $members = Get-Ids "/groups/$($obj.id)/members?`$select=id"
    $isMember = $members -contains "$($sp.id)"
    if ($Remove -and $isMember -and $PSCmdlet.ShouldProcess($o.name, 'remove member')) {
        try { [void](& $Graph 'DELETE' "/groups/$($obj.id)/members/$($sp.id)/`$ref" $null); Say "member removed: SQL admin group '$($o.name)'" 'Green' } catch { $problems.Add("remove member of '$($o.name)': $($_.Exception.Message) (a role-assignable group needs Privileged Role Administrator)") }
    } elseif (-not $Remove -and $isMember) {
        $earlier.Add("a member of the SQL admin group '$($o.name)'")
    } elseif (-not $Remove) { Say "SQL admin group '$($o.name)': the Support app is not a member (no standing administrator right)" 'DarkGray' }
}

# ---- OPEN-01 (framework SECAUDIT-1a, Invardia audit item 3): the Support app's ONE standing database right -- its own
# database user, looked up BY ITS ID (the client id as a SID, never by name, never FROM EXTERNAL PROVIDER), in the read
# role pim_support_read. Made by the time-limited support access module (Invoke-PimSupportJitInstall), installed in this
# run with the level as the consent: troubleshoot and asbuilt = read only; setup = admin rights ONLY inside an open support
# session (at most 8 h). No db_owner, no db_datareader, no VIEW DEFINITION from here.
if (-not $Remove) {
    $readRole = Get-PimSupportJitReadOnlyRole
    $consent = if ($Level -eq 'setup') { 'setup' } else { 'troubleshoot' }
    if (-not $Sql) {
        Write-Host '  read-only database access NOT set: no -SqlServer given -- no database user was created for the Support app' -ForegroundColor Yellow
        if ($Level -ne 'asbuilt') { $problems.Add('no -SqlServer given -- the database part was not done') }
    } elseif ($PSCmdlet.ShouldProcess("$SqlServer/$SqlDatabase", "the Support app's own database user (from its client id) in $readRole only, and the support access module with consent '$consent'")) {
        try {
            # a user of the Support app that already exists under another name is the one every statement uses
            $pre = Invoke-PimSupportSqlUser -Sql $Sql -AppId $AppId -DbUserName $DbUserName -Role $readRole -ReadOnly
            if ("$($pre.userName)".Trim()) { $DbUserName = "$($pre.userName)" }
            elseif ("$($pre.problem)" -ne 'the Support app has no database user') { throw "$($pre.problem)" }   # the database did not answer the read
            $ji = Invoke-PimSupportJitInstall -Sql $Sql -SupportAppId $AppId -ConsentLevel $consent -UserName $DbUserName -SetBy 'Grant-PimSupportAccess (installation)'
            $st = Invoke-PimSupportSqlUser -Sql $Sql -AppId $AppId -DbUserName $DbUserName -Role $readRole -ReadOnly
            if ($ji.ok -and $st.ok) {
                Say "read-only database access: database user [$($st.userName)] ($(if ($pre.userName) { 'already there' } else { 'created from the client id' })) is in $readRole only (read back); support access consent '$consent'$(if ($consent -eq 'setup') { ' -- admin rights only inside an open support session, at most 8 hours' }). It ends when the Support app is switched off in Microsoft Entra ID, or with -Remove." 'Green'
                # what an EARLIER version of this script gave is said, never added again and never widened
                foreach ($legacyRole in @('db_owner', (Get-PimSupportJitLegacyReadOnlyRole))) {
                    $lr = Invoke-PimSupportSqlUser -Sql $Sql -AppId $AppId -DbUserName $DbUserName -Role $legacyRole -ReadOnly
                    if ($lr.inRole) { $earlier.Add("in $legacyRole") }
                }
            } else {
                $why = @(@($ji.problems) + @($(if (-not $st.ok) { "$($st.problem)" })) | Where-Object { "$_".Trim() }) -join '; '
                $problems.Add("read-only database access: $why (the signed-in account must be a member of '$SqlAdminGroupName' or the server's Entra admin)")
            }
        } catch { $problems.Add("read-only database access: $((("$($_.Exception.Message)") -split "`n")[0]) (the signed-in account must be a member of '$SqlAdminGroupName' or the server's Entra admin)") }
    }
    if ($earlier.Count) {
        Write-Host "  from an earlier grant the Support app is still $($earlier -join ', ') -- this run did not add it and left it as found; -Remove takes it back" -ForegroundColor Yellow
    }
}

# ---- -Remove: the user of the Support app's id whatever its name (with every role it holds), then the one of this name
if ($Remove -and $Sql) {
    $u = $DbUserName.Replace(']', ']]')
    try {
        if ($PSCmdlet.ShouldProcess("$SqlServer/$SqlDatabase", "DROP USER [$DbUserName]")) {
            [void](& $Sql (Get-PimSupportSqlUserDropSql -AppId $AppId))
            [void](& $Sql "IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$($DbUserName.Replace("'", "''"))') DROP USER [$u];")
            Say "SQL user [$DbUserName] removed" 'Green'
        }
    } catch { $problems.Add("SQL on $SqlServer : $($_.Exception.Message) (the signed-in account must be a member of '$SqlAdminGroupName' or the server's Entra admin)") }
} elseif ($Remove -and -not $Sql) { $problems.Add('no -SqlServer given -- the SQL part was not done') }

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
