#Requires -Version 5.1
<#
.SYNOPSIS
  §95.2 / GUIDED-INSTALL §4.6 -- give (or take back) the customer's Invardia Support app its access to THIS PIM install.

.DESCRIPTION
  Grant-PimSupportAccess -AppId <support app client id> -Level troubleshoot|setup [-Remove]
      -TenantId <t> -SubscriptionId <s> -ResourceGroup <rg> -SqlServer <server>.database.windows.net [-EnvLabel <label>]

  troubleshoot  a contained SQL user created FROM THE APP'S SID (never FROM EXTERNAL PROVIDER) with db_datareader +
                VIEW DEFINITION -- it can read the store and its schema, nothing else.
  setup         member of the SQL admin group (grp-pim-sql-admins: create users, deploy schema, repair) AND owner of PIM's
                own app registrations and groups -- the Manager's sign-in app, the access request API app, the members
                group and the SQL admin group -- so the support app's Application.ReadWrite.OwnedBy is enough later.
  -Remove       takes back BOTH levels: the membership, the ownerships and the contained user.

  The support app's Azure roles and API permissions are granted by Invardia's New-InvardiaSupportApp.ps1, not here.
  Runs as the signed-in account (PIM-Rest: the Invardia Support app's REST session, else the browser sign-in; no az CLI);
  never a stored secret. Every change is read back.
  Adding a member to the role-assignable SQL admin group needs Privileged Role Administrator; without it that part is
  reported and the rest continues (exit 1). Container installs have no Key Vault, so there is no vault grant.

.EXAMPLE
  ./Grant-PimSupportAccess.ps1 -AppId 00000000-0000-0000-0000-000000000000 -Level setup -TenantId <t> -SubscriptionId <s> `
      -ResourceGroup rg-pim -SqlServer sql-pim-ab12cd.database.windows.net
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$AppId,
    [ValidateSet('troubleshoot', 'setup')][string]$Level = 'troubleshoot',
    [Parameter(Mandatory)][string]$TenantId,
    [string]$SubscriptionId = '',
    [string]$ResourceGroup = '',
    [string]$SqlServer = '',
    [string]$SqlDatabase = 'PimPlatform',
    [ValidatePattern('^$|^[a-z0-9][a-z0-9-]{0,19}$')][string]$EnvLabel = '',
    [string]$SqlAdminGroupName = 'grp-pim-sql-admins',
    [string]$DbUserName = 'invardia-support',
    [switch]$Remove,
    # --- test seams (tests/Test-PimSupportAccess.ps1) ---
    [scriptblock]$Graph,
    [scriptblock]$Sql
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. (Join-Path $here '_PimSetupShared.ps1')

$G = 'https://graph.microsoft.com/v1.0'
# 100.41 (NO-AZ): every token comes from PIM-Rest's ONE token client, PINNED to -TenantId -- never a default context, which
# on a machine holding several logins is another directory (code audit 2026-10-04). A caller that already set up PIM-Rest's
# identity keeps it; otherwise sign in: the Invardia Support app's REST session for this tenant, else the person's browser.
$needRest = (-not $Graph) -or (-not $Sql -and ("$SqlServer".Trim() -or ("$ResourceGroup".Trim() -and "$SubscriptionId".Trim())))
if ($needRest -and -not $global:PIM_SetupRestMode -and -not "$($global:PIM_ClientId)".Trim()) {
    if ("$SubscriptionId".Trim()) { [void](Connect-PimSetupRest -SubscriptionId "$SubscriptionId".Trim() -TenantId $TenantId) } else { [void](Connect-PimSetupRest -TenantId $TenantId) }
}
# No -SqlServer given: the PIM store in -ResourceGroup (a guided install has exactly one). az sql server list -g over ARM.
if (-not "$SqlServer".Trim() -and "$ResourceGroup".Trim() -and "$SubscriptionId".Trim() -and -not $Sql) {
    $found = @(@(Invoke-PimSetupArm -Path "/subscriptions/$("$SubscriptionId".Trim())/resourceGroups/$ResourceGroup/providers/Microsoft.Sql/servers" -ApiVersion (Get-PimSetupApiVersion sql) -All -ErrorAsNull) |
                 Where-Object { $_ } | ForEach-Object { "$($_.properties.fullyQualifiedDomainName)".Trim() } | Where-Object { $_ })
    if ($found.Count -eq 1) { $SqlServer = "$($found[0])".Trim(); Write-Host "  SQL server in $($ResourceGroup): $SqlServer" -ForegroundColor DarkGray }
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
    $sTok = ''; try { $sTok = "$(Get-PimRestToken -Resource 'https://database.windows.net' -TenantId $TenantId)".Trim() } catch { $sTok = '' }
    $cs = "Server=tcp:$SqlServer,1433;Database=$SqlDatabase;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
    $Sql = {
        param([string]$Query)
        $c = New-Object (Resolve-PimSqlClientType).FullName $cs
        $c.AccessToken = $sTok; $c.Open()
        try { $cmd = $c.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 60; return $cmd.ExecuteScalar() } finally { $c.Close() }
    }.GetNewClosure()
}

$problems = New-Object System.Collections.Generic.List[string]
function Say([string]$m, [string]$c = 'Gray') { Write-Host "  $m" -ForegroundColor $c }
function Find-One([string]$Kind, [string]$DisplayName) {
    $f = [uri]::EscapeDataString("displayName eq '$($DisplayName.Replace("'", "''"))'")
    @((& $Graph 'GET' "/$Kind`?`$select=id,displayName,appId&`$filter=$f" $null).value) | Select-Object -First 1
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

# ---- setup: SQL admin group membership + ownerships (granted only at setup; taken back by -Remove)
if ($Level -eq 'setup' -or $Remove) {
    foreach ($o in $objects) {
        $obj = Find-One $o.kind $o.name
        if (-not $obj) { Say "($($o.what) '$($o.name)' does not exist here -- nothing to do)" 'DarkGray'; continue }
        $owners = Get-Ids "/$($o.kind)/$($obj.id)/owners?`$select=id"
        $isOwner = $owners -contains "$($sp.id)"
        if ($Remove -and $isOwner -and $PSCmdlet.ShouldProcess($o.name, 'remove owner')) {
            try { [void](& $Graph 'DELETE' "/$($o.kind)/$($obj.id)/owners/$($sp.id)/`$ref" $null); Say "owner removed: $($o.what) '$($o.name)'" 'Green' } catch { $problems.Add("remove owner of '$($o.name)': $($_.Exception.Message)") }
        } elseif (-not $Remove -and -not $isOwner -and $PSCmdlet.ShouldProcess($o.name, 'add owner')) {
            try { [void](& $Graph 'POST' "/$($o.kind)/$($obj.id)/owners/`$ref" $ref); Say "owner added: $($o.what) '$($o.name)'" 'Green' }
            catch { if ("$_" -match 'already exist') { Say "owner (already): $($o.what) '$($o.name)'" } else { $problems.Add("add owner of '$($o.name)': $($_.Exception.Message)") } }
        } elseif (-not $Remove) { Say "owner (already): $($o.what) '$($o.name)'" }
        if ($o.what -ne 'SQL admin group') { continue }
        $members = Get-Ids "/groups/$($obj.id)/members?`$select=id"
        $isMember = $members -contains "$($sp.id)"
        if ($Remove -and $isMember -and $PSCmdlet.ShouldProcess($o.name, 'remove member')) {
            try { [void](& $Graph 'DELETE' "/groups/$($obj.id)/members/$($sp.id)/`$ref" $null); Say "member removed: SQL admin group '$($o.name)'" 'Green' } catch { $problems.Add("remove member of '$($o.name)': $($_.Exception.Message) (a role-assignable group needs Privileged Role Administrator)") }
        } elseif (-not $Remove -and -not $isMember -and $PSCmdlet.ShouldProcess($o.name, 'add member')) {
            try { [void](& $Graph 'POST' "/groups/$($obj.id)/members/`$ref" $ref); Say "member added: SQL admin group '$($o.name)' (SQL picks it up with the app's next token)" 'Green' }
            catch { if ("$_" -match 'already exist') { Say "member (already): SQL admin group '$($o.name)'" } else { $problems.Add("add member to '$($o.name)': $($_.Exception.Message) (a role-assignable group needs Privileged Role Administrator)") } }
        } elseif (-not $Remove) { Say "member (already): SQL admin group '$($o.name)'" }
    }
}

# ---- troubleshoot: a read-only contained user from the app's SID (and dropped by -Remove)
if (($Level -eq 'troubleshoot' -or $Remove) -and $Sql) {
    $u = $DbUserName.Replace(']', ']]')
    try {
        if ($Remove) {
            if ($PSCmdlet.ShouldProcess("$SqlServer/$SqlDatabase", "DROP USER [$DbUserName]")) {
                [void](& $Sql "IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$($DbUserName.Replace("'", "''"))') DROP USER [$u];")
                Say "SQL user [$DbUserName] removed" 'Green'
            }
        } elseif ($PSCmdlet.ShouldProcess("$SqlServer/$SqlDatabase", "contained user [$DbUserName] (db_datareader + VIEW DEFINITION)")) {
            $t = Get-PimSqlContainedUserSql -DbUserName $DbUserName -AppId $AppId -Roles @('db_datareader') -RevokeRoles @('db_datawriter', 'db_ddladmin', 'db_owner')
            [void](& $Sql ($t + "`nGRANT VIEW DEFINITION TO [$u];"))
            $back = & $Sql "SELECT COUNT(*) FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id JOIN sys.database_principals p ON p.principal_id = m.member_principal_id WHERE r.name = N'db_datareader' AND p.name = N'$($DbUserName.Replace("'", "''"))'"
            if ([int]"$back" -ge 1) { Say "SQL user [$DbUserName]: db_datareader + VIEW DEFINITION (read back)" 'Green' } else { $problems.Add("SQL user [$DbUserName] was not read back in db_datareader") }
        }
    } catch { $problems.Add("SQL on $SqlServer : $($_.Exception.Message) (the signed-in account must be a member of '$SqlAdminGroupName' or the server's Entra admin)") }
} elseif (($Level -eq 'troubleshoot' -or $Remove) -and -not $Sql) { $problems.Add('no -SqlServer given -- the SQL part was not done') }

if ($problems.Count) {
    Write-Host 'NOT everything was done:' -ForegroundColor Yellow
    foreach ($p in $problems) { Write-Host "  - $p" -ForegroundColor Yellow }
    $global:LASTEXITCODE = 1
    exit 1
}
Write-Host 'done' -ForegroundColor Green
$global:LASTEXITCODE = 0
exit 0
