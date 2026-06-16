#Requires -Version 5.1
<#
.SYNOPSIS
  Boot a LOCAL PIM Manager instance for the Playwright GUI test suite, seeded
  from a throwaway local SQLEXPRESS `pim.Rows` database, and emit the base URL +
  per-session bearer token + child PID to a JSON sidecar the Playwright global
  setup reads.

.DESCRIPTION
  This is the *local-instance harness* (the primary mode for the GUI suite). It:
    1. Seeds a throwaway, marker-fenced ('PIMCOREENGINE-') desired-set into a
       local SQLEXPRESS database (default `.\SQLEXPRESS` / `PimGuiTest`) using the
       same code path the real engine reads (tests/live/Seed-PimBaselineDataset.ps1,
       which auto-creates the DB + schema). No tenant, no Graph, no Azure.
    2. Boots tools/pim-manager/Open-PimManager.ps1 -Server -NoLaunch in SQL mode
       (PIM_SqlServer/PIM_SqlDatabase env -> the Manager's SQL-only store path),
       captures the "session token: <hex>" printed to stdout, and confirms the
       loopback URL.
    3. Writes <OutFile> = { baseUrl, token, port, pid, mode, role, db } so the
       Node global-setup can attach `Authorization: Bearer <token>` and drive the
       real GUI end-to-end.

  Auth note: the hosted Container App (ca-pim-manager) is behind Entra Easy Auth,
  which is hard to drive interactively. Driving a LOCAL instance exercises the
  real GUI + the real /api/* backend without the Entra wall -- full coverage of
  every offline-safe feature. Live-only features (active-assignments, revoke,
  refresh-tenant-lists, workload-roles, conformance deploy) need a tenant and are
  tagged @live in the specs (auto-skipped here).

  -Stop tears the instance down: kills the child PID from the sidecar and (unless
  -KeepDb) drops the throwaway database.

.PARAMETER OutFile
  Path to the JSON sidecar to write (default: alongside this script, .manager.json).

.PARAMETER Port
  Loopback port to request (default 8861). 0 = let the Manager pick a free port.

.PARAMETER SqlServer
  SQLEXPRESS instance (default .\SQLEXPRESS).

.PARAMETER Database
  Throwaway database name (default PimGuiTest). Created if missing.

.PARAMETER Role
  Optional Manager role to force for role-tier tests: Reader|Admin|SuperAdmin|Delegated.
  Default (omitted / SuperAdmin with no access file) = SuperAdmin (single-operator).
  When a non-default role is requested a manager-access.custom.json is written into
  the config root naming the current Windows identity; -Stop removes it.

.PARAMETER KeepDb
  With -Stop, do not DROP the throwaway database (faster re-runs).

.PARAMETER Stop
  Tear down the instance described by <OutFile>.
#>
[CmdletBinding(DefaultParameterSetName = 'Start')]
param(
    [string]$OutFile,
    [Parameter(ParameterSetName = 'Start')][int]$Port = 8861,
    [string]$SqlServer = '.\SQLEXPRESS',
    [string]$Database  = 'PimGuiTest',
    [Parameter(ParameterSetName = 'Start')][ValidateSet('Reader', 'Admin', 'SuperAdmin', 'Delegated')][string]$Role,
    [switch]$KeepDb,
    [Parameter(ParameterSetName = 'Stop')][switch]$Stop
)

$ErrorActionPreference = 'Stop'
$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$pimRoot = Resolve-Path (Join-Path $here '..\..\..\..')   # SOLUTIONS\PIM4EntraPS (tests\playwright\feature-suite\harness -> up 4)
$mgr     = Join-Path $pimRoot 'tools\pim-manager\Open-PimManager.ps1'
$seed    = Join-Path $pimRoot 'tests\live\Seed-PimBaselineDataset.ps1'
$cfgRoot = Join-Path $pimRoot 'config'
$accessFile = Join-Path $cfgRoot 'manager-access.custom.json'
if (-not $OutFile) { $OutFile = Join-Path $here '.manager.json' }

function Test-SqlReachable {
    param([string]$Server)
    try {
        $cs = "Server=$Server;Database=master;Integrated Security=SSPI;TrustServerCertificate=True;Connect Timeout=4"
        $c = New-Object System.Data.SqlClient.SqlConnection $cs
        $c.Open(); $c.Close(); return $true
    } catch { return $false }
}

function Drop-TestDb {
    param([string]$Server, [string]$Db)
    try {
        $cs = "Server=$Server;Database=master;Integrated Security=SSPI;TrustServerCertificate=True;Connect Timeout=8"
        $c = New-Object System.Data.SqlClient.SqlConnection $cs; $c.Open()
        $cmd = $c.CreateCommand()
        $cmd.CommandText = "IF DB_ID(@n) IS NOT NULL BEGIN ALTER DATABASE [$Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$Db]; END"
        [void]$cmd.Parameters.AddWithValue('@n', $Db)
        [void]$cmd.ExecuteNonQuery(); $c.Close()
        Write-Host "  [harness] dropped test DB $Db" -ForegroundColor DarkGray
    } catch { Write-Warning "  [harness] could not drop $Db -- $($_.Exception.Message)" }
}

# ---------------------------------------------------------------------------
# STOP / teardown
# ---------------------------------------------------------------------------
if ($Stop) {
    if (Test-Path $OutFile) {
        try {
            $info = Get-Content $OutFile -Raw | ConvertFrom-Json
            if ($info.pid) {
                $p = Get-Process -Id $info.pid -ErrorAction SilentlyContinue
                if ($p) { Stop-Process -Id $info.pid -Force -ErrorAction SilentlyContinue; Write-Host "  [harness] stopped Manager pid $($info.pid)" -ForegroundColor DarkGray }
            }
            if ($info.db -and -not $KeepDb -and (Test-SqlReachable -Server $info.server)) { Drop-TestDb -Server $info.server -Db $info.db }
        } catch { Write-Warning "  [harness] stop: $($_.Exception.Message)" }
        Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path "$OutFile.stdout") { Remove-Item "$OutFile.stdout","$OutFile.stderr" -Force -ErrorAction SilentlyContinue }
    if (Test-Path $accessFile) { Remove-Item $accessFile -Force -ErrorAction SilentlyContinue; Write-Host "  [harness] removed temp manager-access.custom.json" -ForegroundColor DarkGray }
    return
}

# ---------------------------------------------------------------------------
# START
# ---------------------------------------------------------------------------
if (-not (Test-SqlReachable -Server $SqlServer)) {
    # Signal a clean SKIP to the Node side -- it self-skips the whole suite.
    $skip = @{ skip = $true; reason = "SQLEXPRESS not reachable at $SqlServer" } | ConvertTo-Json
    [System.IO.File]::WriteAllText($OutFile, $skip, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "  [harness] SKIP -- SQL not reachable at $SqlServer; GUI suite will self-skip." -ForegroundColor Yellow
    return
}

Write-Host "  [harness] seeding throwaway DB $SqlServer / $Database ..." -ForegroundColor Cyan
$env:PIM_SqlServer = $SqlServer; $env:PIM_SqlDatabase = $Database
# clear any prior marked rows then seed fresh
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$seed" -Clear -SqlServer $SqlServer -SqlDatabase $Database *>$null
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$seed" -OwnerUpn 'admin@example.onmicrosoft.com' -DefaultDomain 'example.onmicrosoft.com' -SqlServer $SqlServer -SqlDatabase $Database
if ($LASTEXITCODE -ne 0) { throw "seed failed (exit $LASTEXITCODE)" }

# Optional role forcing (default SuperAdmin via no access file)
if ($Role -and $Role -ne 'SuperAdmin') {
    $who = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
    @(@{ identity = $who; role = $Role }) | ConvertTo-Json | Set-Content -Path $accessFile -Encoding UTF8
    Write-Host "  [harness] forced Manager role '$Role' for '$who'" -ForegroundColor DarkGray
} elseif (Test-Path $accessFile) {
    # ensure default SuperAdmin (no leftover file from a prior role run)
    Remove-Item $accessFile -Force -ErrorAction SilentlyContinue
}

$stdout = "$OutFile.stdout"; $stderr = "$OutFile.stderr"
if (Test-Path $stdout) { Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue }

Write-Host "  [harness] booting Manager (SQL mode) on port $Port ..." -ForegroundColor Cyan
$mgrArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$mgr`"",'-Server','-NoLaunch')
if ($Port -gt 0) { $mgrArgs += @('-Port', "$Port") }
$proc = Start-Process powershell.exe -ArgumentList $mgrArgs -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden

$token = $null; $boundPort = $Port
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 500
    if (Test-Path $stdout) {
        $txt = Get-Content $stdout -Raw -ErrorAction SilentlyContinue
        if ($txt) {
            $m = [regex]::Match($txt, 'session token:\s*([0-9a-fA-F]{16,})')
            $pm = [regex]::Match($txt, 'loopback listening on http://127\.0\.0\.1:(\d+)/')
            if ($pm.Success) { $boundPort = [int]$pm.Groups[1].Value }
            if ($m.Success) { $token = $m.Groups[1].Value; break }
        }
    }
    if ($proc.HasExited) { break }
}

if (-not $token) {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "---- Manager stdout ----"; Get-Content $stdout -ErrorAction SilentlyContinue | Select-Object -Last 25 | ForEach-Object { Write-Host "  $_" }
    Write-Host "---- Manager stderr ----"; Get-Content $stderr -ErrorAction SilentlyContinue | Select-Object -Last 25 | ForEach-Object { Write-Host "  $_" }
    throw "Manager did not emit a session token within timeout."
}

$effectiveRole = if ($Role) { $Role } else { 'SuperAdmin' }
$info = [ordered]@{
    skip    = $false
    baseUrl = "http://127.0.0.1:$boundPort"
    token   = $token
    port    = $boundPort
    pid     = $proc.Id
    mode    = 'server'
    role    = $effectiveRole
    server  = $SqlServer
    db      = $Database
}
[System.IO.File]::WriteAllText($OutFile, ($info | ConvertTo-Json), (New-Object System.Text.UTF8Encoding $false))
Write-Host "  [harness] Manager up: $($info.baseUrl)  role=$($info.role)  pid=$($proc.Id)" -ForegroundColor Green
Write-Host "  [harness] sidecar: $OutFile" -ForegroundColor DarkGray
