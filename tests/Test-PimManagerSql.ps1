#Requires -Version 5.1
<#
.SYNOPSIS
    LIVE proof of the manager SQL cutover: boots Open-PimManager.ps1 in SQL mode
    (via $env:PIM_SqlConnectionString -> a throwaway DB) and exercises the
    storage-neutral /api/data/<entity> GET/PUT, verifying rows land in SQL (not
    CSV). Creates + drops the DB. Skips cleanly if no SQL instance is reachable.

        powershell -NoProfile -File .\tests\Test-PimManagerSql.ps1 [-Server .\SQLEXPRESS]
    (The Manager binds a free loopback port at runtime -- no fixed port to collide on.)
#>
[CmdletBinding()] param([string]$Server = '.\SQLEXPRESS', [int]$Port = 0)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot '_shared\PimManagerBoot.ps1')   # -Port 0 => helper allocates a free port (no fixed-port collision)
. (Join-Path $root 'engine\_shared\PIM-ChangeQueue.ps1')
. (Join-Path $root 'engine\_shared\PIM-SqlStore.ps1')

$pass=0; $fail=0
function T($n,$c){ if($c){Write-Host "  PASS $n" -ForegroundColor Green;$script:pass++}else{Write-Host "  FAIL $n" -ForegroundColor Red;$script:fail++} }

$masterCs = Get-PimSqlConnectionString -Server $Server -Database 'master'
if (-not (Test-PimSqlConnectivity -ConnectionString $masterCs)) { Write-Host "SQL '$Server' not reachable -- SKIPPING manager SQL cutover test." -ForegroundColor Yellow; exit 0 }

$db = "pimmgr_" + [guid]::NewGuid().ToString('N').Substring(0,12)
$cs = Get-PimSqlConnectionString -Server $Server -Database $db
$mgr = Join-Path $root 'tools\pim-manager\Open-PimManager.ps1'
$out = Join-Path $env:TEMP ("pim-mgrsql-{0}.out" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
if (Test-Path $out) { Remove-Item $out -Force }
$proc = $null
try {
    Initialize-PimSqlDatabase -Server $Server -Database $db   # the manager creates the schema, not the DB
    $env:PIM_SqlConnectionString = $cs                         # child process inherits -> SQL mode
    Write-Host "Booting Manager in SQL mode (db $db) on a dynamic free port ..."
    $ctx  = Start-PimManagerForTest -ManagerPath $mgr -StdoutPath $out -TimeoutSec 45
    $proc = $ctx.Process

    $token = $ctx.Token
    T 'Manager booted in SQL mode' ([bool]$token -and $ctx.Port -gt 0)
    if (-not $token) { Get-Content $out,"$out.err" -EA SilentlyContinue | Select-Object -Last 20 | ForEach-Object { Write-Host "    $_" }; throw 'no token' }
    Write-Host "  Manager bound port $($ctx.Port)" -ForegroundColor DarkGray
    $sqlMode = (Select-String -Path $out -Pattern '\[store\] SQL mode' -EA SilentlyContinue | Select-Object -First 1)
    T 'Manager reports [store] SQL mode' ([bool]$sqlMode)

    $base = $ctx.BaseUrl; $hdr = @{ Authorization = "Bearer $token" }
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

    # --- SQL render regression (fix/manager-gui-sql-render) -----------------
    # The graph model + banner must report SQL as the source, NOT the config
    # path, and the SPA must render read-WRITE (not 'static (read-only)') when
    # the store is SQL. Earlier the page wrongly labelled SQL mode static.
    $cfg = Invoke-RestMethod -Uri "$base/api/config" -Headers $hdr -TimeoutSec 30
    T '/api/config sourceRoot reports SQL (not config path)' ("$($cfg.sourceRoot)" -like 'SQL:*')
    T '/api/config storageMode = sql' ("$($cfg.storageMode)" -eq 'sql')

    $spa = Invoke-WebRequest -Uri "$base/" -TimeoutSec 30 -UseBasicParsing
    $spaHtml = "$($spa.Content)"
    # The server-rendered <meta name="pim-mode"> must carry the SQL label so the
    # client treats the page as read-write server mode (isServer = true).
    $modeMeta = ([regex]::Match($spaHtml, '(?is)<meta[^>]*name=["'']pim-mode["''][^>]*content=["'']([^"'']*)["'']')).Groups[1].Value
    T '/ render: pim-mode meta = SQL: <db>' ($modeMeta -like 'SQL:*')
    T '/ render: pim-mode meta is not static' ($modeMeta -ne 'static')
    # The page must ship a bearer token (server mode), without which the client
    # forces static/read-only regardless of the mode label.
    $tokMeta = ([regex]::Match($spaHtml, '(?is)<meta[^>]*name=["'']pim-token["''][^>]*content=["'']([^"'']*)["'']')).Groups[1].Value
    T '/ render: pim-token meta is present (server/read-write)' ([bool]$tokMeta)

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
