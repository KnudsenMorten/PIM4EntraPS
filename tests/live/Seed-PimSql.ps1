<#
.SYNOPSIS
  One-time bootstrap of the hosted PIM Manager's Azure SQL: grants the web app's
  system Managed Identity a DB user (passwordless runtime auth) and seeds the
  config (CSV -> pim.Rows + pim.Settings) so the hosted GUI shows data.

  Run as a SQL AAD admin (interactive) from a box on the VNet that can reach the
  SQL private endpoint. Uses System.Data.SqlClient (in-box on Windows PowerShell
  5.1) with an AAD access token -- no password.
#>
[CmdletBinding()]
param(
  [string]$ServerFqdn = 'sql-pimplatform-we484.database.windows.net',
  [string]$Database   = 'PimPlatform',
  [string]$MiUser     = 'app-pim-manager-2lk4175',
  [string]$ConfigDir
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests\live' }
if (-not $ConfigDir) { $ConfigDir = (Resolve-Path "$here\..\..\config").Path }

Write-Host "=== PIM SQL bootstrap + seed ===" -ForegroundColor Cyan
Write-Host "server $ServerFqdn / db $Database / MI $MiUser" -ForegroundColor DarkGray

$token = (az account get-access-token --resource https://database.windows.net --query accessToken -o tsv 2>$null)
if (-not $token) { throw "could not get a SQL access token (az login?)" }
$cs = "Server=tcp:$ServerFqdn,1433;Database=$Database;Encrypt=True;TrustServerCertificate=False;Connection Timeout=60;"

function New-OpenSqlConnection {
  # serverless Azure SQL auto-pauses; first connect triggers a resume (~30-60s)
  # and fails transiently ("not currently available", 40613/40197/...). Retry.
  for ($i=0; $i -lt 12; $i++) {
    $c = New-Object System.Data.SqlClient.SqlConnection $cs
    $c.AccessToken = $token
    try { $c.Open(); return $c }
    catch {
      if ("$_" -match 'not currently available|40613|40197|40501|49918|is paused|resuming' -and $i -lt 11) {
        Write-Host ("    SQL resuming... retry {0}/12" -f ($i+1)) -ForegroundColor DarkYellow
        Start-Sleep -Seconds 15; continue
      }
      throw
    }
  }
}
function Invoke-SqlNonQuery([string]$sql) {
  $c = New-OpenSqlConnection
  try { $cmd = $c.CreateCommand(); $cmd.CommandText = $sql; $cmd.CommandTimeout = 180; [void]$cmd.ExecuteNonQuery() }
  finally { $c.Close() }
}
function Invoke-SqlScalar([string]$sql) {
  $c = New-OpenSqlConnection
  try { $cmd = $c.CreateCommand(); $cmd.CommandText = $sql; return $cmd.ExecuteScalar() }
  finally { $c.Close() }
}

# 1) connectivity
$who = Invoke-SqlScalar "SELECT SUSER_SNAME();"
Write-Host "[1] connected as: $who" -ForegroundColor Green

# 2) grant the web app MI a DB user (idempotent)
Write-Host "[2] granting MI user $MiUser ..." -ForegroundColor Cyan
Invoke-SqlNonQuery @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'$MiUser')
    CREATE USER [$MiUser] FROM EXTERNAL PROVIDER;
"@
foreach ($role in 'db_datareader','db_datawriter','db_ddladmin') {
  Invoke-SqlNonQuery "ALTER ROLE $role ADD MEMBER [$MiUser];"
}
Write-Host "    MI user granted db_datareader + db_datawriter + db_ddladmin" -ForegroundColor Green

# 3) seed config -> SQL via the engine's migrator (creates pim.Rows/Settings/ChangeQueue)
Write-Host "[3] seeding config -> SQL (Migrate-PimToSql) ..." -ForegroundColor Cyan
$global:PIM_SqlConnectionString = $cs
$global:PIM_SqlAccessToken      = $token
& "$here\..\..\setup\Migrate-PimToSql.ps1" -ConfigDir $ConfigDir -Database $Database

# 4) verify
Write-Host "[4] verify row counts" -ForegroundColor Cyan
try { $rows = Invoke-SqlScalar "SELECT COUNT(*) FROM pim.Rows;" } catch { $rows = "(pim.Rows n/a: $_)" }
try { $sett = Invoke-SqlScalar "SELECT COUNT(*) FROM pim.Settings;" } catch { $sett = "(pim.Settings n/a)" }
Write-Host ("    pim.Rows = {0} ; pim.Settings = {1}" -f $rows, $sett) -ForegroundColor Green
Write-Host "DONE." -ForegroundColor Cyan
