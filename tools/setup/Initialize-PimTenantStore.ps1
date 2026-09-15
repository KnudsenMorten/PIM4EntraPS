<#
.SYNOPSIS
  Make a tenant's PIM SQL store usable by the environment's own identity. Unattended, idempotent.

.DESCRIPTION
  Between "an Azure SQL database exists" and "the PIM engine can use it" sit three steps that
  were each done BY HAND while bringing the test estate up. They belong in a script, because a
  proof environment must be reachable only by automation:

    1. the modern (Tier0) SPN needs a user in `master` with dbmanager -- Initialize-PimSqlDatabase
       connects to master to test sys.databases, and without this it cannot;
    2. it needs a contained user in the PIM database with db_owner;
    3. the pim schema (Rows / Settings / ChangeQueue) has to exist.

  Steps 1 and 2 connect as the server's Entra admin (the onboarding SPN). Step 3 connects AS
  THE MODERN SPN WITH ITS CERTIFICATE -- deliberately, because that is the identity the engine
  will use, so a run that succeeds here proves the path the product actually takes rather than
  a privileged shortcut.

  🪤 Cross-tenant note (BUG-34): this host's managed identity belongs to a DIFFERENT tenant.
  MI acquisition would SUCCEED and hand Azure SQL a valid token for the wrong directory, which
  fails as "Login failed ... The server is not currently configured to accept this token" and
  reads like a permissions problem. The explicit SPN globals below prevent ambient MI winning.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    # NOT Mandatory, because nothing here reads it. This script talks to Entra and to SQL over
    # tokens; it never calls az, so there is no subscription to scope. Demanding a value the
    # script cannot use is a lie in the contract -- it makes callers hunt for a subscription id
    # to satisfy a parameter that is then discarded. Kept as an accepted parameter so the
    # existing call sites (which pass it for symmetry with the az-calling scripts) still bind.
    # audit:unused-ok SubscriptionId
    [string]$SubscriptionId,
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [Parameter(Mandatory)][string]$ModernAppId,
    [Parameter(Mandatory)][string]$ModernThumbprint,
    [Parameter(Mandatory)][string]$AdminAppId,        # server's Entra admin (onboarding SPN)
    # ONE of these. 🔴 The secret used to be Mandatory, which made a CLIENT SECRET structurally
    # required to stand up a tenant store -- against the repo-root rule ("authenticate as its SPN
    # using a CERTIFICATE, never a client secret") and unsatisfiable where the onboarding SPN is
    # cert-only. Grant-PimMiSql was fixed for exactly this on 2026-08-09; this script was not.
    [string]$AdminSecret,
    [string]$AdminCertThumbprint,
    [string]$Database = 'PimPlatform',
    [string]$DbUserName                                # defaults to AutomateIT-Modern-<token-ish>
)
$ErrorActionPreference = 'Stop'
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$shared = Resolve-Path (Join-Path $here '..\..\engine\_shared')
. (Join-Path $shared 'PIM-Rest.ps1')
. (Join-Path $shared 'PIM-ChangeQueue.ps1')
. (Join-Path $shared 'PIM-SqlStore.ps1')

if (-not $DbUserName) { $DbUserName = "AutomateIT-Modern-$(($SqlServerFqdn -split '\.')[0] -replace '^sql-ait-','')" }
$sidHex = '0x' + ((([guid]$ModernAppId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')

Write-Host "=== tenant store -- $SqlServerFqdn / $Database ===" -ForegroundColor Cyan
Write-Host "  modern spn : $ModernAppId"
Write-Host "  db user    : $DbUserName"

# --- admin token for the grants (Entra admin of the server) -------------------
# 🔑 Routed through Get-PimRestToken rather than a hand-rolled client_credentials POST. Two
# reasons, and the second is why it matters beyond cert support:
#   * it accepts a CERTIFICATE (JWT client assertion), which a raw client_secret POST cannot;
#   * it is the ONE token path that carries SEC-12's refusal -- an explicit identity that cannot
#     be honoured throws instead of quietly becoming an ambient one. The hand-rolled call here was
#     a second implementation that could never gain that, and a duplicate auth path is exactly
#     where a security fix goes missing.
if ($AdminSecret -and $AdminCertThumbprint) { throw 'Initialize-PimTenantStore: pass EITHER -AdminSecret OR -AdminCertThumbprint, not both.' }
if (-not $AdminSecret -and -not $AdminCertThumbprint) { throw 'Initialize-PimTenantStore: one of -AdminSecret / -AdminCertThumbprint is required.' }
$adminTok = Get-PimRestToken -Resource 'https://database.windows.net' -TenantId $TenantId `
                -ClientId $AdminAppId -ClientSecret $AdminSecret -CertThumbprint $AdminCertThumbprint -Force
if (-not $adminTok) { throw 'could not obtain a SQL admin token for the onboarding SPN' }
$type = Resolve-PimSqlClientType

function Invoke-AsAdmin([string]$Db, [string]$Sql) {
    $c = $type::new("Server=tcp:$SqlServerFqdn,1433;Database=$Db;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30")
    $c.AccessToken = $adminTok
    $c.Open()
    try { $cmd = $c.CreateCommand(); $cmd.CommandText = $Sql; [void]$cmd.ExecuteNonQuery() } finally { $c.Close() }
}

Write-Host "[1] master: user + dbmanager ..." -ForegroundColor Yellow
Invoke-AsAdmin 'master' @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$DbUserName')
    CREATE USER [$DbUserName] WITH SID = $sidHex, TYPE = E;
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members rm
               JOIN sys.database_principals r ON r.principal_id=rm.role_principal_id AND r.name='dbmanager'
               JOIN sys.database_principals m ON m.principal_id=rm.member_principal_id AND m.name=N'$DbUserName')
    ALTER ROLE dbmanager ADD MEMBER [$DbUserName];
"@

Write-Host "[2] $Database : contained user + db_owner ..." -ForegroundColor Yellow
Invoke-AsAdmin $Database @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$DbUserName')
    CREATE USER [$DbUserName] WITH SID = $sidHex, TYPE = E;
ALTER ROLE db_owner ADD MEMBER [$DbUserName];
"@

Write-Host "[3] pim schema, connecting AS the modern SPN (certificate) ..." -ForegroundColor Yellow
$global:PIM_TenantId          = $TenantId
$global:PIM_ClientId          = $ModernAppId
$global:PIM_CertThumbprint    = $ModernThumbprint
$global:PIM_SqlClientId       = $ModernAppId
$global:PIM_SqlCertThumbprint = $ModernThumbprint
$global:PIM_ClientSecret      = $null
$global:PIM_SqlClientSecret   = $null
$global:PIM_SqlServer         = $SqlServerFqdn
$global:PIM_SqlDatabase       = $Database

$cs = Get-PimSqlConnectionString -Server $SqlServerFqdn -Database $Database
if ($cs -match '(?i)Integrated\s*Security') { throw "got an Integrated Security connection string for Azure SQL -- this store is Entra-only and needs a token, not integrated auth" }
Initialize-PimSqlStore -ConnectionString $cs

# --- VERIFY: read back as the engine identity, not as the admin ---------------
Write-Host ""
Write-Host "=== VERIFY ===" -ForegroundColor Cyan
$who = Invoke-PimSqlQuery -ConnectionString $cs -Sql "SELECT SUSER_SNAME() AS who, DB_NAME() AS db"
foreach ($r in $who) { Write-Host "  connected as : $($r.who)"; Write-Host "  database     : $($r.db)" }
$tables = @(Invoke-PimSqlQuery -ConnectionString $cs -Sql "SELECT s.name + '.' + t.name AS n FROM sys.tables t JOIN sys.schemas s ON s.schema_id=t.schema_id ORDER BY n" | ForEach-Object { $_.n })
Write-Host "  tables       : $($tables -join ', ')"
$need = @('pim.Rows','pim.Settings','pim.ChangeQueue')
$missing = @($need | Where-Object { $tables -notcontains $_ })
if ($missing.Count) { Write-Host "RESULT: FAILED -- missing $($missing -join ', ')" -ForegroundColor Red; exit 1 }
if ("$($who[0].who)" -notlike "$ModernAppId*") { Write-Host "RESULT: FAILED -- connected as the wrong identity" -ForegroundColor Red; exit 1 }
Write-Host "RESULT: OK -- store reachable over the AutomateIT chain (cert -> Azure SQL)" -ForegroundColor Green
exit 0
