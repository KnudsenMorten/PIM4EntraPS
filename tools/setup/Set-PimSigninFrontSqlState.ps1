#Requires -Version 5.1

<#
.SYNOPSIS
  Give the sign-in front its place in a private PIM database.

.DESCRIPTION
  Gives the PIM Manager's sign-in front exactly what it needs in the PIM database: a database user for the front's managed
  identity, the schema 'signin' owned by it, and the right to create tables there. It never adds a role. -WhatIf shows it
  first; running it again changes nothing.

  For a PRIVATE database (framework 12.11g item 9, front 1.3.0+), from a machine inside the network. The front keeps its sessions, token cache and key ring in two tables it creates itself in the schema 'signin'. This script
  gives its identity exactly that and no more: the user (made from the identity's client id), the schema owned by it, and the
  right to create tables. It never adds a role. Read back after each change; -WhatIf prints and changes nothing. Idempotent.
  Sign-in: the same as Grant-PimSupportSqlAccess.ps1 (your browser; an Azure Arc / VM machine identity is ignored).

.EXAMPLE
  .\Set-PimSigninFrontSqlState.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -SqlServerName sql-pim-contoso -IdentityName id-pim-contoso -IdentityClientId <client id> -WhatIf
  Preview: connects, reads and prints the statements it would run. Then the same command without -WhatIf.

.LINK
  https://invardia.com/docs/pim/scripts/Set-PimSigninFrontSqlState/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$TenantId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$SqlServerName,
    [string]$SqlDatabase = 'PimPlatform',
    # the front's managed identity: its name (the database user's name) and its client id (the user's SID)
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.-]{1,128}$')][string]$IdentityName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$IdentityClientId,
    # --- test seams (tests/script-docs/Set-PimSigninFrontSqlState.case.ps1); omit them for a real run ---
    [scriptblock]$Reach,
    [scriptblock]$Sql
)
$ErrorActionPreference = 'Stop'
# Published as ONE standalone file (https://invardia.com/support/pim/Set-PimSigninFrontSqlState.ps1): Build-PimSupportScripts.ps1
# inlines every helper loaded below by its literal path; the next line tells it to leave out the libraries' OPTIONAL loads.
# BUILD-NO-OPTIONAL-LOADS
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Rest.ps1')
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-SqlStore.ps1')
. (Join-Path $PSScriptRoot '_PimSignedIn.ps1')
$null = Start-PimScriptRun -Script 'Set-PimSigninFrontSqlState'
$rc = 1
try {
$srv = ("$SqlServerName".Trim() -replace '^tcp:', '' -replace ',\d+$', '').Split('.')[0].ToLowerInvariant()
if ($srv -notmatch '^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$') { throw "Set-PimSigninFrontSqlState: not a SQL server name: $SqlServerName" }
if ($SqlDatabase -notmatch '^[^<>*%&:\\/?\[\]'';]{1,128}$') { throw "Set-PimSigninFrontSqlState: not a database name: $SqlDatabase" }
$tid = "$TenantId".Trim().ToLowerInvariant(); $sub = "$SubscriptionId".Trim().ToLowerInvariant()
$fqdn = "$srv.database.windows.net"
$sid = '0x' + ((([guid]"$IdentityClientId").ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
Write-Host ('=' * 78) -ForegroundColor Cyan
Write-Host " PIM MANAGER -- THE SIGN-IN FRONT'S PLACE IN THE DATABASE  ($srv / $SqlDatabase)$(if ($WhatIfPreference) { '   PREVIEW' })" -ForegroundColor Cyan
Write-Host ('=' * 78) -ForegroundColor Cyan

$ok = $false
if ($Reach) { $ok = [bool](& $Reach $fqdn) }
else {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try { $t = $tcp.ConnectAsync($fqdn, 1433); $ok = ($t.Wait(8000) -and $tcp.Connected) } catch { $ok = $false } finally { $tcp.Close() }
}
if (-not $ok) { Write-Host "  NOT DONE: $fqdn is not reachable on port 1433 from this machine -- run this from a machine inside the PIM network. Nothing was changed." -ForegroundColor Red; exit 1 }
Write-Host "  $fqdn reachable on port 1433 from this machine" -ForegroundColor DarkGray

$who = Get-PimSignedInIdentity -TenantId $tid -SubscriptionId $sub
if (-not $who.ok) { Write-Host "  NOT DONE: REFUSED (nothing was touched) -- $($who.reason)" -ForegroundColor Red; exit 1 }
Write-Host "  $($who.reason)" -ForegroundColor DarkGray
$tok = "$(Get-PimRestToken -Resource 'https://database.windows.net' -TenantId $tid -Force)".Trim()
if (-not $tok) { Write-Host '  NOT DONE: no database token -- nothing was changed.' -ForegroundColor Red; exit 1 }
$c = $null
if ($Sql) { $q = { param([string]$s) "$(& $Sql $s)" } }
else {
    $c = New-Object (Resolve-PimSqlClientType).FullName "Server=tcp:$fqdn,1433;Database=$SqlDatabase;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;Pooling=False"
    $c.AccessToken = $tok
    $q = { param([string]$s) $cmd = $c.CreateCommand(); $cmd.CommandText = $s; $cmd.CommandTimeout = 60; "$($cmd.ExecuteScalar())" }
}
try {
    if ($c) { $c.Open() }
    $user = & $q "SELECT name FROM sys.database_principals WHERE sid = $sid"
    $owner = & $q "SELECT USER_NAME(principal_id) FROM sys.schemas WHERE name = N'signin'"
    $grant = & $q "SELECT COUNT(*) FROM sys.database_permissions p JOIN sys.database_principals u ON u.principal_id = p.grantee_principal_id WHERE u.sid = $sid AND p.permission_name = 'CREATE TABLE' AND p.state IN ('G','W')"
    Write-Host ("  now: database user {0}; schema signin owner {1}; CREATE TABLE granted {2}" -f $(if ($user) { "[$user]" } else { '(none)' }), $(if ($owner) { "[$owner]" } else { '(no schema)' }), $(if ($grant -ne '0') { 'yes' } else { 'no' }))
    $plan = @()
    if (-not $user) { $plan += "CREATE USER [$IdentityName] WITH SID = $sid, TYPE = E" }
    $u = if ($user) { $user } else { $IdentityName }
    if (-not $owner) { $plan += "CREATE SCHEMA signin AUTHORIZATION [$u]" } elseif ($owner -ne $u) { $plan += "ALTER AUTHORIZATION ON SCHEMA::signin TO [$u]" }
    if ($grant -eq '0') { $plan += "GRANT CREATE TABLE TO [$u]" }
    if (-not $plan.Count) { Write-Host '  nothing to do -- already in place' -ForegroundColor Green; $rc = 0 }
    elseif (-not $PSCmdlet.ShouldProcess("database $SqlDatabase", ($plan -join '; '))) { foreach ($p in $plan) { Write-Host "  What if: $p" }; $rc = 0 }
    else {
        foreach ($p in $plan) { if ($p -like 'CREATE SCHEMA*') { [void](& $q "EXEC(N'$($p -replace "'", "''")')") } else { [void](& $q $p) }; Write-Host "  done: $p" -ForegroundColor Green }
        $user = & $q "SELECT name FROM sys.database_principals WHERE sid = $sid"
        $owner = & $q "SELECT USER_NAME(principal_id) FROM sys.schemas WHERE name = N'signin'"
        $grant = & $q "SELECT COUNT(*) FROM sys.database_permissions p JOIN sys.database_principals u ON u.principal_id = p.grantee_principal_id WHERE u.sid = $sid AND p.permission_name = 'CREATE TABLE' AND p.state IN ('G','W')"
        $good = ($user -and $owner -eq $user -and $grant -ne '0')
        Write-Host ("  read back: user [{0}], schema signin owner [{1}], CREATE TABLE {2}" -f $user, $owner, $(if ($grant -ne '0') { 'yes' } else { 'NO' })) -ForegroundColor $(if ($good) { 'Green' } else { 'Red' })
        $rc = if ($good) { 0 } else { 1 }
    }
} catch {
    Write-Host "  NOT DONE: $((("$($_.Exception.Message)") -split "`n")[0])" -ForegroundColor Red; $rc = 1
} finally { if ($c) { try { $c.Close() } catch { } } }
Write-Host ''
Write-Host "RESULT: $(if ($rc -eq 0) { 'done' } else { 'NOT DONE (see above)' })$(if ($WhatIfPreference) { ' -- preview, nothing was changed' })" -ForegroundColor $(if ($rc -eq 0) { 'Green' } else { 'Red' })
} finally { Stop-PimScriptRun -Script 'Set-PimSigninFrontSqlState' }
exit $rc
