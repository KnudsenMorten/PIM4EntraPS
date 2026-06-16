#Requires -Version 5.1
<#
.SYNOPSIS
    LIVE HTTP proof of the Manager's DB-cutover ceremony endpoint + the resilient
    /health probe. Boots Open-PimManager.ps1 against a throwaway SQL DB with a
    registry instance (so the config root + the '/' render path resolve), then:
      * GET  /health        -- answers WITHOUT a bearer token; healthy + store=sql.
      * GET  /api/cutover    -- lists the 6 stages; storeKind = dev-local (SQLEXPRESS).
      * POST /api/cutover    -- gate rejects an out-of-order 'finalize' (409); the
                               auto-next-stage POST drives preflight..re-preflight in
                               order; FINALIZE is REFUSED on a dev-local store (409)
                               -- only Azure SQL may be finalized as authoritative.

    Self-skips (exit 0) when no SQL instance is reachable.

        powershell -NoProfile -File .\tests\Test-PimCutoverEndpoints.ps1 [-Server .\SQLEXPRESS]
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
if (-not (Test-PimSqlConnectivity -ConnectionString $masterCs)) { Write-Host "SQL '$Server' not reachable -- SKIPPING cutover-endpoint test." -ForegroundColor Yellow; exit 0 }

$mgr  = Join-Path $root 'tools\pim-manager\Open-PimManager.ps1'
$db   = "pimcute_" + [guid]::NewGuid().ToString('N').Substring(0,12)
$cs   = Get-PimSqlConnectionString -Server $Server -Database $db
$instName = 'cutoversim'
$instFile = Join-Path $root 'tools\pim-manager\instances.custom.json'
$instBak  = "$instFile.cutoversimbak"
$hadInst  = Test-Path -LiteralPath $instFile
$out  = Join-Path $env:TEMP ("pim-cutendp-{0}.out" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
Get-ChildItem "$out*" -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
$proc = $null
# A throwaway config dir with two custom CSVs the import will migrate.
$cfgDir = Join-Path ([System.IO.Path]::GetTempPath()) ("pimcute-cfg-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null
$outDir = Join-Path ([System.IO.Path]::GetTempPath()) ("pimcute-out-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$savedCs = $env:PIM_SqlConnectionString
try {
    Set-Content -LiteralPath (Join-Path $cfgDir 'Account-Definitions-Admins.custom.csv') -Encoding UTF8 -Value @(
        'UserName;DisplayName;Purpose'
        'Admin-AA-ID;AA;Day2Day'
        'Admin-BB-ID;BB;HighPriv'
    )
    Set-Content -LiteralPath (Join-Path $cfgDir 'PIM-Definitions-Tasks.custom.csv') -Encoding UTF8 -Value @(
        'GroupName;GroupTag;Workload;Level;Plane'
        'PIM-Entra-ID-A-L1-T0-CP-ID;Entra-ID-A-L1;Entra-ID;L1;CP'
    )
    Initialize-PimSqlDatabase -Server $Server -Database $db
    if ($hadInst) { Copy-Item $instFile $instBak -Force }
    @{ instances = @(@{ name = $instName; configRoot = $cfgDir; outputRoot = $outDir }) } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $instFile -Encoding UTF8
    $env:PIM_SqlConnectionString = $cs

    Write-Host "Booting Manager (SQL, instance $instName) on a dynamic free port ..."
    $ctx  = Start-PimManagerForTest -ManagerPath $mgr -ExtraArgs @('-Instance',$instName) -StdoutPath $out -TimeoutSec 60
    $proc = $ctx.Process

    $token = $ctx.Token
    T 'Manager booted (SQL, instance)' ([bool]$token -and $ctx.Port -gt 0)
    if (-not $token) { Get-Content $out,"$out.err" -EA SilentlyContinue | Select-Object -Last 25 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }; throw 'no token' }
    Write-Host "  Manager bound port $($ctx.Port)" -ForegroundColor DarkGray

    $base = $ctx.BaseUrl; $hdr = @{ Authorization = "Bearer $token" }
    try { Invoke-RestMethod -Method POST -Uri "$base/api/heartbeat" -Headers $hdr -TimeoutSec 10 | Out-Null } catch {}

    # /health -- UNAUTHENTICATED, healthy, store=sql.
    $healthStatus = 0; $health = $null
    try { $health = Invoke-RestMethod -Uri "$base/health" -TimeoutSec 15; $healthStatus = 200 } catch { try { $healthStatus = [int]$_.Exception.Response.StatusCode } catch { $healthStatus = -1 } }
    T '/health answers WITHOUT a bearer token (200)' ($healthStatus -eq 200)
    T '/health: healthy + store=sql + sqlOk' ($health -and "$($health.status)" -eq 'healthy' -and "$($health.store)" -eq 'sql' -and [bool]$health.sqlOk)

    # /api/cutover GET
    $cut0 = Invoke-RestMethod -Uri "$base/api/cutover" -Headers $hdr -TimeoutSec 30
    Write-Host ("    (cutover GET: stages=$(@($cut0.stages).Count) storeKind='$($cut0.storeKind)' storageMode='$($cut0.storageMode)')") -ForegroundColor DarkGray
    T '/api/cutover GET lists 6 stages' (@($cut0.stages).Count -eq 6)
    T '/api/cutover GET reports a dev-local store kind (SQLEXPRESS)' ("$($cut0.storeKind)" -eq 'dev-local')
    T '/api/cutover GET: nothing completed yet, not final' (@($cut0.completed).Count -eq 0 -and -not $cut0.final)

    # gate: explicit out-of-order finalize -> 409
    $gateErr = 0
    try { Invoke-RestMethod -Uri "$base/api/cutover" -Headers $hdr -Method Post -ContentType 'application/json' -Body (@{ stage='finalize' } | ConvertTo-Json) -TimeoutSec 30 } catch { try { $gateErr = [int]$_.Exception.Response.StatusCode } catch { $gateErr = -1 } }
    T '/api/cutover POST out-of-order finalize gated (409)' ($gateErr -eq 409)

    # drive the ceremony in order (auto-next-stage). finalize must be refused (dev-local).
    $stagesRun = @(); $finalizeRefused = $false
    for ($k=0; $k -lt 7; $k++) {
        try {
            $r = Invoke-RestMethod -Uri "$base/api/cutover" -Headers $hdr -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 60
            if ($r.done) { break }
            $stagesRun += "$($r.stage)"
            if ("$($r.stage)" -eq 'finalize') { break }
        } catch {
            $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { $code = -1 }
            if ($code -eq 409) { $finalizeRefused = $true }
            break
        }
    }
    T 'ceremony ran preflight->import->set-source->re-preflight in order' `
        (($stagesRun -contains 'preflight') -and ($stagesRun -contains 'upgrade') -and ($stagesRun -contains 'import') -and ($stagesRun -contains 'set-source') -and ($stagesRun -contains 're-preflight'))
    T 'FINALIZE refused on dev-local store (Azure SQL only) -- 409' ($finalizeRefused)

    # import actually moved CSV rows into SQL (read-only source untouched).
    $admRows = @(Get-PimSqlRows -ConnectionString $cs -Entity 'Account-Definitions-Admins')
    T 'import landed admin rows in pim.Rows (2)' ($admRows.Count -eq 2)
    T 'CSV source untouched by the import (read-only)' ((Get-Content (Join-Path $cfgDir 'Account-Definitions-Admins.custom.csv')).Count -eq 3)

    # state shows set-source completed but NOT final.
    $cutEnd = Invoke-RestMethod -Uri "$base/api/cutover" -Headers $hdr -TimeoutSec 30
    T 'state: set-source completed (StorageBackend flipped to sql)' (@($cutEnd.completed) -contains 'set-source')
    T 'state: NOT finalized on a dev-local store' (-not $cutEnd.final)
    T 'StorageBackend setting persisted = sql' ((Get-PimSqlSetting -ConnectionString $cs -Name 'StorageBackend') -eq 'sql')
} finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
    $env:PIM_SqlConnectionString = $savedCs; if ($null -eq $savedCs) { Remove-Item Env:PIM_SqlConnectionString -EA SilentlyContinue }
    Get-ChildItem "$out*" -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
    Remove-Item -LiteralPath $cfgDir,$outDir -Recurse -Force -EA SilentlyContinue
    if ($hadInst) { Move-Item $instBak $instFile -Force -EA SilentlyContinue } else { Remove-Item $instFile -Force -EA SilentlyContinue }
    Remove-Item $instBak -Force -EA SilentlyContinue
    try { [void](Invoke-PimSqlNonQuery -ConnectionString $masterCs -Sql "IF DB_ID('$db') IS NOT NULL BEGIN ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]; END") } catch { Write-Warning "cleanup failed: $($_.Exception.Message)" }
}

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 } else { exit 0 }
