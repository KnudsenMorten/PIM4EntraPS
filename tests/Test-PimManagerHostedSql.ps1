#Requires -Version 5.1
<#
.SYNOPSIS
    Hosted + SQL hardening proof for the PIM Manager (Open-PimManager.ps1).

.DESCRIPTION
    Two parts, both OFFLINE (no live tenant, no container):

    A) Unit: dot-source PIM-Rest.ps1 + _tenantSync.ps1 and prove the tenant
       CONNECT CONTEXT resolves in hosted mode from the engine SPN / managed
       identity ALONE -- i.e. with NO $global:HighPriv_Modern_* and NO
       -ConnectPlatform / baseline-engine run. This is the regression guard for
       the live "GET /api/active-assignments -> 500 (requires the engine SPN
       context ... Missing ...)" failure.

    B) Boot: launch Open-PimManager.ps1 with PIM_HOSTED=1 + PIM_SqlConnectionString
       (a throwaway DB) + fake engine-SPN env vars, capture stdout, and assert the
       Manager DEFAULTS TO THE SQL INSTANCE ('sql:<db>') -- not the contextless
       'local' -- and that it resolves a tenant-auth context at startup. Skips
       cleanly if no SQL instance is reachable.

        powershell -NoProfile -File .\tests\Test-PimManagerHostedSql.ps1 [-Server .\SQLEXPRESS]
#>
[CmdletBinding()] param([string]$Server = '.\SQLEXPRESS')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

# ---------------------------------------------------------------------------
# Part A -- tenant connect-context resolves from SPN / MI alone (no HighPriv_*).
# Runs in a child process so the fake globals/env never leak into this session.
# ---------------------------------------------------------------------------
Write-Host "Part A -- hosted tenant connect-context (REST/MI, no -ConnectPlatform)" -ForegroundColor Cyan
$unit = @'
$ErrorActionPreference = "Stop"
$root = $args[0]
. (Join-Path $root "engine\_shared\PIM-Rest.ps1")
. (Join-Path $root "tools\pim-manager\_tenantSync.ps1")

# Ensure a clean slate: NO HighPriv_Modern_* anywhere, no Graph SDK loaded.
$global:HighPriv_Modern_ApplicationID_Azure = $null
$global:HighPriv_Modern_CertificateThumbprint_Azure = $null
$global:HighPriv_Modern_Secret_Azure = $null
$global:AzureTenantID = $null

$results = [ordered]@{}

# (1) engine SPN (clientid + cert thumbprint + tenant) -- the hosted app-setting shape.
$global:PIM_ClientId = "11111111-1111-1111-1111-111111111111"
$global:PIM_CertThumbprint = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
$global:PIM_TenantId = "22222222-2222-2222-2222-222222222222"
$results.restAvail_spn = [bool](Test-PimRestTenantAuthAvailable)
try { $results.ctx_spn = [string](Assert-PimTenantConnectionContext) } catch { $results.ctx_spn = "THROW: $($_.Exception.Message)" }

# (2) managed identity (no client id) -- App Service IDENTITY_ENDPOINT present.
$global:PIM_ClientId = $null; $global:PIM_CertThumbprint = $null; $global:PIM_TenantId = $null
$global:AzureTenantID = $null
$env:IDENTITY_ENDPOINT = "http://localhost/msi"; $env:IDENTITY_HEADER = "x"
$results.restAvail_mi = [bool](Test-PimRestTenantAuthAvailable)
try { $r = Assert-PimTenantConnectionContext; $results.ctx_mi = "OK:" + $r } catch { $results.ctx_mi = "THROW: $($_.Exception.Message)" }
$env:IDENTITY_ENDPOINT = $null; $env:IDENTITY_HEADER = $null

# (3) NOTHING configured -> must still throw a clear error (fail closed).
$results.restAvail_none = [bool](Test-PimRestTenantAuthAvailable)
try { [void](Assert-PimTenantConnectionContext); $results.ctx_none = "NO-THROW" } catch { $results.ctx_none = "THROW" }

# (4) connect helpers are no-ops when the Graph/Az SDK is absent (REST-only).
# Only meaningful when the SDK is genuinely absent (the container). On a dev box
# with the SDK installed, a real connect with a fake cert is EXPECTED to throw --
# so we report whether the SDK is present and let the parent decide.
$results.sdkPresent = [bool](Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)
$global:PIM_ClientId = "11111111-1111-1111-1111-111111111111"
$global:PIM_CertThumbprint = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
$global:PIM_TenantId = "22222222-2222-2222-2222-222222222222"
if (-not $results.sdkPresent) {
    try { Connect-PimManagerGraph -TenantId $global:PIM_TenantId; Connect-PimManagerAz -TenantId $global:PIM_TenantId; $results.connect_noop = "OK" } catch { $results.connect_noop = "THROW: $($_.Exception.Message)" }
} else {
    $results.connect_noop = "SKIP-SDK-PRESENT"
}

$results | ConvertTo-Json -Compress
'@
$unitFile = Join-Path $env:TEMP ("pim-hosted-unit-{0}.ps1" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
Set-Content -LiteralPath $unitFile -Value $unit -Encoding UTF8
try {
    $raw = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $unitFile $root 2>&1
    $jsonLine = @($raw | Where-Object { "$_".Trim().StartsWith('{') } | Select-Object -Last 1)
    $u = if ($jsonLine) { $jsonLine[0] | ConvertFrom-Json } else { $null }
    if (-not $u) { Write-Host ("    unit output: " + ($raw -join ' | ')) -ForegroundColor DarkGray }
    T 'SPN (clientid+cert+tenant) => REST tenant auth available' ($u -and $u.restAvail_spn)
    T 'SPN context resolves to the tenant id (no HighPriv_*, no -ConnectPlatform)' ($u -and "$($u.ctx_spn)" -eq '22222222-2222-2222-2222-222222222222')
    T 'Managed identity => REST tenant auth available' ($u -and $u.restAvail_mi)
    T 'Managed identity context resolves (tenant carried by MI token)' ($u -and "$($u.ctx_mi)" -like 'OK:*')
    T 'No credential => REST auth NOT available' ($u -and -not $u.restAvail_none)
    T 'No credential => connect-context FAILS CLOSED (throws)' ($u -and "$($u.ctx_none)" -eq 'THROW')
    if ($u -and $u.sdkPresent) {
        Write-Host "  SKIP Connect-PimManagerGraph/Az no-op check (Graph SDK present on this box; container-only behavior)" -ForegroundColor DarkYellow
    } else {
        T 'Connect-PimManagerGraph/Az are no-ops when SDK absent (REST-only)' ($u -and "$($u.connect_noop)" -eq 'OK')
    }
} finally {
    Remove-Item -LiteralPath $unitFile -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# Part B -- hosted boot defaults to the SQL instance (not 'local').
# ---------------------------------------------------------------------------
Write-Host "`nPart B -- hosted boot defaults to the SQL instance" -ForegroundColor Cyan
. (Join-Path $root 'engine\_shared\PIM-ChangeQueue.ps1')
. (Join-Path $root 'engine\_shared\PIM-SqlStore.ps1')
$masterCs = Get-PimSqlConnectionString -Server $Server -Database 'master'
if (-not (Test-PimSqlConnectivity -ConnectionString $masterCs)) {
    Write-Host "SQL '$Server' not reachable -- SKIPPING Part B (hosted boot)." -ForegroundColor Yellow
    Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
    if ($fail) { exit 1 } else { exit 0 }
}

$db = "pimhosted_" + [guid]::NewGuid().ToString('N').Substring(0, 12)
$cs = Get-PimSqlConnectionString -Server $Server -Database $db
$mgr = Join-Path $root 'tools\pim-manager\Open-PimManager.ps1'
$out = Join-Path $env:TEMP "pim-hostedsql.out"
if (Test-Path $out) { Remove-Item $out -Force }
$proc = $null
$saved = @{
    PIM_HOSTED = $env:PIM_HOSTED; PIM_SqlConnectionString = $env:PIM_SqlConnectionString
    PIM_ClientId = $env:PIM_ClientId; PIM_CertThumbprint = $env:PIM_CertThumbprint; PIM_TenantId = $env:PIM_TenantId
}
try {
    Initialize-PimSqlDatabase -Server $Server -Database $db
    # Hosted shape: PIM_HOSTED=1 + SQL connection + engine SPN as app settings.
    # (http://+: bind needs a URL-ACL we don't have in CI, so the listener may
    #  not start -- but the instance-default + tenant-auth logs print BEFORE the
    #  bind, which is exactly what we assert.)
    $env:PIM_HOSTED = '1'
    $env:PIM_SqlConnectionString = $cs
    $env:PIM_ClientId = '11111111-1111-1111-1111-111111111111'
    $env:PIM_CertThumbprint = 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'
    $env:PIM_TenantId = '22222222-2222-2222-2222-222222222222'
    Write-Host "Booting Manager in HOSTED+SQL mode (db $db) ..."
    $proc = Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$mgr`"", '-Server', '-NoLaunch') -RedirectStandardOutput $out -RedirectStandardError "$out.err" -PassThru -WindowStyle Hidden
    # Wait until the startup banner has printed (or the process exits).
    $sawSql = $false; $sawAuth = $false; $sawLocalDefault = $false
    for ($i = 0; $i -lt 50; $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-Path $out) {
            $txt = (Get-Content $out -Raw -ErrorAction SilentlyContinue)
            if ($txt) {
                if ($txt -match "hosted/SQL default -> active instance 'sql:$db'") { $sawSql = $true }
                if ($txt -match '\[tenant-auth\].*auth=SPN') { $sawAuth = $true }
                # the contextless 'local' must NOT be the final active instance line
                if ($txt -match "instance: local\b" -and -not $sawSql) { $sawLocalDefault = $true }
            }
        }
        if ($sawSql -and $sawAuth) { break }
        if ($proc.HasExited -and (Test-Path $out)) { Start-Sleep -Milliseconds 300; break }
    }
    if (-not ($sawSql -and $sawAuth)) { Get-Content $out, "$out.err" -EA SilentlyContinue | Select-Object -Last 25 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray } }
    T "hosted+SQL defaults to the SQL instance ('sql:$db', not 'local')" $sawSql
    T 'hosted resolves a tenant-auth context from the engine SPN (no -ConnectPlatform)' $sawAuth
} finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
    foreach ($k in $saved.Keys) { Set-Item -Path ("Env:\$k") -Value $saved[$k] -ErrorAction SilentlyContinue }
    Get-ChildItem "$out*" -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
    try { [void](Invoke-PimSqlNonQuery -ConnectionString $masterCs -Sql "IF DB_ID('$db') IS NOT NULL BEGIN ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]; END") } catch { Write-Warning "cleanup failed: $($_.Exception.Message)" }
}

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
