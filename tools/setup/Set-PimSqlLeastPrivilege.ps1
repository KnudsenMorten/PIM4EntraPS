#Requires -Version 5.1
<#
.SYNOPSIS
  Least privilege in PIM's database (framework 12.11f CR8 steps 1 + 3): proves the shared pull identity has NO database user,
  and takes db_ddladmin away from the Manager's database user -- from a machine that reaches the database (a private one
  from inside the network).

.DESCRIPTION
  1. PROOF (read only): every Microsoft Entra user of the database with its client id, and every role membership. The proof
     holds when no database user carries -SharedPullClientId (the shared pull identity id-pim-<token>). Then Invardia takes
     that identity out of the SQL admin group from outside (Microsoft Graph; step 2).
  2. CHANGE: when the Manager's user [ca-pim-manager] is in db_ddladmin, it is dropped from it (the Manager no longer needs
     it since 2.4.631) and read back. Nothing else is changed. -WhatIf prints the change and makes none.
  Sign-in: the same as Grant-PimSupportSqlAccess.ps1 -- your browser (or the Invardia Support app's session in this window);
  an Azure Arc / VM machine identity on this machine is ignored for the run. A private server must be reachable from this
  machine on port 1433 (its private endpoint). No PowerShell module, no Azure CLI.

.EXAMPLE
  .\Set-PimSqlLeastPrivilege.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -SqlServerName sql-pim-contoso -SharedPullClientId <client id of id-pim-<token>> -WhatIf
  Preview: the proof and what would change. Then the same command without -WhatIf.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$TenantId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SubscriptionId,
    # the SQL server name or its FQDN (sql-x or sql-x.database.windows.net)
    [Parameter(Mandatory)][string]$SqlServerName,
    [string]$SqlDatabase = 'PimPlatform',
    # the client id of the shared pull identity id-pim-<token>: it must have NO database user
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SharedPullClientId,
    [string]$ManagerUser = 'ca-pim-manager'
)
$ErrorActionPreference = 'Stop'
# Published as ONE standalone file: every helper is dot-sourced by a literal path relative to this script (Build-PimSupportScripts inlines it).
# BUILD-NO-OPTIONAL-LOADS
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Rest.ps1')       # the ONE token client (framework 12.17)
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-SqlStore.ps1')   # Resolve-PimSqlClientType (.NET SqlClient, no module)
. (Join-Path $PSScriptRoot '_PimSignedIn.ps1')                        # the sign-in rule: the Support session, else the browser
$rc = 1
$srv = ("$SqlServerName".Trim() -replace '^tcp:', '' -replace ',\d+$', '').Split('.')[0].ToLowerInvariant()
if ($srv -notmatch '^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$') { throw "Set-PimSqlLeastPrivilege: not a SQL server name: $SqlServerName" }
if ($SqlDatabase -notmatch '^[^<>*%&:\\/?\[\]'';]{1,128}$') { throw "Set-PimSqlLeastPrivilege: not a database name: $SqlDatabase" }
if ($ManagerUser -notmatch '^[A-Za-z0-9_.-]{1,128}$') { throw "Set-PimSqlLeastPrivilege: not a user name: $ManagerUser" }
$tid = "$TenantId".Trim().ToLowerInvariant(); $sub = "$SubscriptionId".Trim().ToLowerInvariant(); $pull = "$SharedPullClientId".Trim().ToLowerInvariant()
$fqdn = "$srv.database.windows.net"
Write-Host ('=' * 78) -ForegroundColor Cyan
Write-Host " PIM MANAGER -- LEAST PRIVILEGE IN THE DATABASE  ($srv / $SqlDatabase)$(if ($WhatIfPreference) { '   PREVIEW' })" -ForegroundColor Cyan
Write-Host ('=' * 78) -ForegroundColor Cyan

# ---- reach (a private server: its private endpoint, from inside the network) ---------------------------------------------
$tcp = New-Object System.Net.Sockets.TcpClient
$ok = $false; try { $t = $tcp.ConnectAsync($fqdn, 1433); $ok = ($t.Wait(8000) -and $tcp.Connected) } catch { $ok = $false } finally { $tcp.Close() }
if (-not $ok) { Write-Host "  NOT DONE: $fqdn is not reachable on port 1433 from this machine -- run this from a machine inside the PIM network (check: Test-NetConnection $fqdn -Port 1433). Nothing was changed." -ForegroundColor Red; exit 1 }
Write-Host "  $fqdn reachable on port 1433 from this machine" -ForegroundColor DarkGray

# ---- sign-in ---------------------------------------------------------------------------------------------------------
$who = Get-PimSignedInIdentity -TenantId $tid -SubscriptionId $sub
if (-not $who.ok) { Write-Host "  NOT DONE: REFUSED (nothing was touched) -- $($who.reason)" -ForegroundColor Red; exit 1 }
Write-Host "  $($who.reason)" -ForegroundColor DarkGray
$tok = "$(Get-PimRestToken -Resource 'https://database.windows.net' -TenantId $tid -Force)".Trim()
if (-not $tok) { Write-Host '  NOT DONE: no database token -- nothing was changed.' -ForegroundColor Red; exit 1 }
$c = New-Object (Resolve-PimSqlClientType).FullName "Server=tcp:$fqdn,1433;Database=$SqlDatabase;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;Pooling=False"
$c.AccessToken = $tok
try {
    $c.Open()
    $rows = { param([string]$q) $cmd = $c.CreateCommand(); $cmd.CommandText = $q; $cmd.CommandTimeout = 60; $r = $cmd.ExecuteReader(); $out = @()
              while ($r.Read()) { $o = [ordered]@{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $o[$r.GetName($i)] = "$($r.GetValue($i))" }; $out += [pscustomobject]$o }; $r.Close(); , $out }
    $scalar = { param([string]$q) $cmd = $c.CreateCommand(); $cmd.CommandText = $q; $cmd.CommandTimeout = 60; "$($cmd.ExecuteScalar())" }

    # ---- 1. the proof (read only) ----------------------------------------------------------------------------------------
    $users = & $rows "SELECT p.name, p.type_desc AS type, LOWER(CONVERT(varchar(36), CONVERT(uniqueidentifier, p.sid))) AS client_id FROM sys.database_principals p WHERE p.type IN ('E','X') ORDER BY p.name"
    $roles = & $rows "SELECT u.name AS member, r.name AS role FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id JOIN sys.database_principals u ON u.principal_id = m.member_principal_id WHERE u.type IN ('E','X') ORDER BY u.name, r.name"
    Write-Host ''
    Write-Host '  Microsoft Entra users of the database:' -ForegroundColor Cyan
    foreach ($u in $users) { Write-Host ("    {0,-40} {1,-16} {2}  roles: {3}" -f $u.name, $u.type, $u.client_id, ((@($roles | Where-Object { $_.member -eq $u.name } | ForEach-Object { $_.role })) -join ', ')) }
    $hit = @($users | Where-Object { $_.client_id -eq $pull })
    if ($hit.Count) { Write-Host "  PROOF: NO -- the shared pull identity ($pull) HAS a database user: $($hit[0].name). Do not take it out of the SQL admin group yet." -ForegroundColor Red }
    else { Write-Host "  PROOF: yes -- the shared pull identity ($pull) has NO database user." -ForegroundColor Green }

    # ---- 2. db_ddladmin off the Manager's user ---------------------------------------------------------------------------
    $isDdl = (& $scalar "SELECT ISNULL(IS_ROLEMEMBER(N'db_ddladmin', N'$ManagerUser'), 0)") -eq '1'
    $exists = (& $scalar "SELECT COUNT(*) FROM sys.database_principals WHERE name = N'$ManagerUser'") -ne '0'
    if (-not $exists) { Write-Host "  [$ManagerUser]: no such database user -- nothing to change" -ForegroundColor Yellow; $rc = $(if ($hit.Count) { 1 } else { 0 }) }
    elseif (-not $isDdl) { Write-Host "  [$ManagerUser]: not in db_ddladmin -- nothing to change" -ForegroundColor Green; $rc = $(if ($hit.Count) { 1 } else { 0 }) }
    elseif (-not $PSCmdlet.ShouldProcess("database $SqlDatabase", "ALTER ROLE db_ddladmin DROP MEMBER [$ManagerUser]")) {
        Write-Host "  What if: ALTER ROLE db_ddladmin DROP MEMBER [$ManagerUser]" ; $rc = 0
    } else {
        [void](& $scalar "ALTER ROLE db_ddladmin DROP MEMBER [$ManagerUser]")
        $back = (& $scalar "SELECT ISNULL(IS_ROLEMEMBER(N'db_ddladmin', N'$ManagerUser'), 0)")
        if ($back -eq '0') { Write-Host "  [$ManagerUser]: db_ddladmin DROPPED (read back). To undo: ALTER ROLE db_ddladmin ADD MEMBER [$ManagerUser]" -ForegroundColor Green; $rc = $(if ($hit.Count) { 1 } else { 0 }) }
        else { Write-Host "  NOT DONE: [$ManagerUser] is still in db_ddladmin after the change" -ForegroundColor Red; $rc = 1 }
    }
} catch {
    Write-Host "  NOT DONE: $((("$($_.Exception.Message)") -split "`n")[0])" -ForegroundColor Red; $rc = 1
} finally { try { $c.Close() } catch { } }
Write-Host ''
Write-Host "RESULT: $(if ($rc -eq 0) { 'done' } else { 'NOT DONE (see above)' })$(if ($WhatIfPreference) { ' -- preview, nothing was changed' })" -ForegroundColor $(if ($rc -eq 0) { 'Green' } else { 'Red' })
exit $rc
