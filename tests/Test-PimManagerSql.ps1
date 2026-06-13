#Requires -Version 5.1
<#
.SYNOPSIS
    LIVE proof of the manager SQL cutover: boots Open-PimManager.ps1 in SQL mode
    (via $env:PIM_SqlConnectionString -> a throwaway DB) and exercises the
    storage-neutral /api/data/<entity> GET/PUT, verifying rows land in SQL (not
    CSV). Creates + drops the DB. Skips cleanly if no SQL instance is reachable.

        powershell -NoProfile -File .\tests\Test-PimManagerSql.ps1 [-Server .\SQLEXPRESS] [-Port 8811]
#>
[CmdletBinding()] param([string]$Server = '.\SQLEXPRESS', [int]$Port = 8811)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'engine\_shared\PIM-ChangeQueue.ps1')
. (Join-Path $root 'engine\_shared\PIM-SqlStore.ps1')

$pass=0; $fail=0
function T($n,$c){ if($c){Write-Host "  PASS $n" -ForegroundColor Green;$script:pass++}else{Write-Host "  FAIL $n" -ForegroundColor Red;$script:fail++} }

$masterCs = Get-PimSqlConnectionString -Server $Server -Database 'master'
if (-not (Test-PimSqlConnectivity -ConnectionString $masterCs)) { Write-Host "SQL '$Server' not reachable -- SKIPPING manager SQL cutover test." -ForegroundColor Yellow; exit 0 }

$db = "pimmgr_" + [guid]::NewGuid().ToString('N').Substring(0,12)
$cs = Get-PimSqlConnectionString -Server $Server -Database $db
$mgr = Join-Path $root 'tools\pim-manager\Open-PimManager.ps1'
$out = Join-Path $env:TEMP "pim-mgrsql-$Port.out"
if (Test-Path $out) { Remove-Item $out -Force }
$proc = $null
try {
    Initialize-PimSqlDatabase -Server $Server -Database $db   # the manager creates the schema, not the DB
    $env:PIM_SqlConnectionString = $cs                         # child process inherits -> SQL mode
    Write-Host "Booting Manager in SQL mode (db $db) on port $Port ..."
    $proc = Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$mgr`"",'-Server','-NoLaunch','-Port',"$Port") -RedirectStandardOutput $out -RedirectStandardError "$out.err" -PassThru -WindowStyle Hidden

    $token = $null
    for ($i=0; $i -lt 60; $i++) { Start-Sleep -Milliseconds 750
        if (Test-Path $out) { $m = Select-String -Path $out -Pattern 'session token:\s*([0-9a-fA-F\-]{16,})' -EA SilentlyContinue | Select-Object -First 1; if ($m) { $token = $m.Matches[0].Groups[1].Value; break } }
        if ($proc.HasExited) { break } }
    T 'Manager booted in SQL mode' ([bool]$token)
    if (-not $token) { Get-Content $out,"$out.err" -EA SilentlyContinue | Select-Object -Last 20 | ForEach-Object { Write-Host "    $_" }; throw 'no token' }
    $sqlMode = (Select-String -Path $out -Pattern '\[store\] SQL mode' -EA SilentlyContinue | Select-Object -First 1)
    T 'Manager reports [store] SQL mode' ([bool]$sqlMode)

    $base = "http://127.0.0.1:$Port"; $hdr = @{ Authorization = "Bearer $token" }
    function Beat { try { Invoke-RestMethod -Method POST -Uri "$base/api/heartbeat" -Headers $hdr -TimeoutSec 10 | Out-Null } catch {} }
    Beat

    # PUT two rows via the storage-neutral /api/data endpoint
    $putBody = @{ rows = @(
        @{ GroupName='PIM-Entra-ID-A-L1-T0-CP-ID'; GroupTag='Entra-ID-A-L1'; Workload='Entra-ID'; Level='L1'; TierLevel='T0'; Plane='CP' }
        @{ GroupName='PIM-Entra-ID-B-L1-T0-CP-ID'; GroupTag='Entra-ID-B-L1'; Workload='Entra-ID'; Level='L1'; TierLevel='T0'; Plane='CP' }
    ) } | ConvertTo-Json -Depth 6
    $putRes = Invoke-RestMethod -Uri "$base/api/data/PIM-Definitions-Tasks" -Headers $hdr -Method Put -Body $putBody -ContentType 'application/json' -TimeoutSec 60
    T 'PUT /api/data persisted (path=sql)' ("$($putRes.path)" -eq 'sql' -and $putRes.rowCount -eq 2)

    # GET back through the manager
    $getRes = Invoke-RestMethod -Uri "$base/api/data/PIM-Definitions-Tasks" -Headers $hdr -TimeoutSec 30
    T 'GET /api/data returns 2 rows from SQL' (@($getRes.rows).Count -eq 2 -and "$($getRes.source)" -eq 'sql')

    # verify directly in the database (bypassing the manager)
    $direct = @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Tasks')
    $tags = @($direct | ForEach-Object { "$($_.GroupTag)" })
    T 'rows are physically in pim.Rows (SQL, not CSV)' ($direct.Count -eq 2 -and ($tags -contains 'Entra-ID-A-L1'))

    # full-set replace: PUT one row -> the other is deleted
    $putRes2 = Invoke-RestMethod -Uri "$base/api/data/PIM-Definitions-Tasks" -Headers $hdr -Method Put -ContentType 'application/json' -TimeoutSec 60 -Body (@{ rows=@(@{ GroupName='x'; GroupTag='Entra-ID-A-L1'; Workload='Entra-ID'; Level='L1'; TierLevel='T0'; Plane='CP' }) } | ConvertTo-Json -Depth 6)
    T 'PUT full-set replace drops the removed row' (@(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Tasks').Count -eq 1)
} finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
    $env:PIM_SqlConnectionString = $null
    Get-ChildItem "$out*" -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
    try { [void](Invoke-PimSqlNonQuery -ConnectionString $masterCs -Sql "IF DB_ID('$db') IS NOT NULL BEGIN ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]; END") } catch { Write-Warning "cleanup failed: $($_.Exception.Message)" }
}

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 }
