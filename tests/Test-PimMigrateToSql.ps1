#Requires -Version 5.1
<#
.SYNOPSIS
    LIVE test of setup/Migrate-PimToSql.ps1 -- migrates a temp CSV config into a
    throwaway SQL DB (same code path that targets Azure SQL) and verifies rows +
    seeded settings, then drops the DB. Skips if no SQL instance is reachable.
#>
[CmdletBinding()] param([string]$Server = '.\SQLEXPRESS')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'engine\_shared\PIM-ChangeQueue.ps1')
. (Join-Path $root 'engine\_shared\PIM-SqlStore.ps1')

$pass=0; $fail=0
function T($n,$c){ if($c){Write-Host "  [PASS] $n" -ForegroundColor Green;$script:pass++}else{Write-Host "  [FAIL] $n" -ForegroundColor Red;$script:fail++} }

$masterCs = Get-PimSqlConnectionString -Server $Server -Database 'master'
if (-not (Test-PimSqlConnectivity -ConnectionString $masterCs)) { Write-Host "SQL '$Server' not reachable -- SKIPPING migrate test." -ForegroundColor Yellow; exit 0 }

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pimmig-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$db = "pimmig_" + [guid]::NewGuid().ToString('N').Substring(0,12)
$cs = Get-PimSqlConnectionString -Server $Server -Database $db
try {
    Set-Content -LiteralPath (Join-Path $tmp 'Account-Definitions-Admins.custom.csv') -Encoding UTF8 -Value @(
        'UserName;DisplayName;Purpose'
        'Admin-AA-ID;AA;Day2Day'
        'Admin-BB-ID;BB;HighPriv'
    )
    Set-Content -LiteralPath (Join-Path $tmp 'PIM-Definitions-Tasks.custom.csv') -Encoding UTF8 -Value @(
        'GroupName;GroupTag;Workload;Level;TierLevel;Plane'
        'PIM-Entra-ID-A-L1-T0-CP-ID;Entra-ID-A-L1;Entra-ID;L1;T0;CP'
    )
    Set-Content -LiteralPath (Join-Path $tmp 'PIM4EntraPS.NamingConventions.custom.ps1') -Encoding UTF8 -Value '$global:PIM_NamingConventions = @{ PawEnforcement = $false; PimGroupPattern = "PIM-{Service}-{Name}-L{Level}-T{Tier}-{Code}-{Domain}" }'

    Initialize-PimSqlDatabase -Server $Server -Database $db
    $rep = & (Join-Path $root 'setup\Migrate-PimToSql.ps1') -ConfigDir $tmp -ConnectionString $cs
    T 'migrate reported 2 entities' (@($rep).Count -eq 2)
    T 'admins migrated to SQL (2 rows)' (@(Get-PimSqlRows -ConnectionString $cs -Entity 'Account-Definitions-Admins').Count -eq 2)
    T 'tasks migrated to SQL (1 row)' (@(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Tasks').Count -eq 1)
    T 'a migrated row round-trips its data' ((Get-PimSqlRow -ConnectionString $cs -Entity 'PIM-Definitions-Tasks' -Key 'Entra-ID-A-L1').Workload -eq 'Entra-ID')
    T 'settings seeded from NamingConventions' ((Get-PimAllSqlSettings -ConnectionString $cs).ContainsKey('PimGroupPattern'))
    # CSV files untouched (non-destructive)
    T 'CSV files left intact' ((Get-Content (Join-Path $tmp 'PIM-Definitions-Tasks.custom.csv')).Count -eq 2)
    # idempotent re-run
    [void](& (Join-Path $root 'setup\Migrate-PimToSql.ps1') -ConfigDir $tmp -ConnectionString $cs)
    T 're-run is idempotent (still 1 task row)' (@(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Tasks').Count -eq 1)
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    try { [void](Invoke-PimSqlNonQuery -ConnectionString $masterCs -Sql "IF DB_ID('$db') IS NOT NULL BEGIN ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]; END") } catch {}
}

Write-Host ('=' * 70)
if ($fail -eq 0) { Write-Host ("ALL {0} ASSERTIONS PASSED." -f $pass) -ForegroundColor Green; exit 0 }
else { Write-Host ("{0} passed, {1} FAILED." -f $pass, $fail) -ForegroundColor Red; exit 1 }
