<#
.SYNOPSIS
  Boot the PIM Manager in SQL mode over a throwaway local SQL database SEEDED with the
  rich scenario dataset, and emit a sidecar (.manager.json) Playwright reads to drive the
  GUI. Mirrors the GUI-test PR's harness (tests/playwright/harness/Start-PimManagerForGui.ps1)
  but seeds the RICHER scenario set so the GUI scenario specs see the full estate.

  COORDINATION: this is a NEW, self-contained boot harness for the scenario-sim GUI specs.
  When the GUI-test PR (feat/pim-gui-tests / PR #13) is merged, its page-object
  (pages/ManagerPage.js) + fixtures (fixtures.js) can be reused by these specs; until then
  this harness boots the SAME Open-PimManager.ps1 the GUI-test harness uses, with the same
  stdout contract (`loopback listening on http://127.0.0.1:<port>/` + `session token: <tok>`),
  so the two harnesses are drop-in compatible.

  -Stop  : kill the Manager (pid from the sidecar) and drop the throwaway DB.
#>
[CmdletBinding()]
param(
    [string]$OutFile,
    [string]$SqlServer = $(if ($env:PIM_SqlServer) { $env:PIM_SqlServer } else { '.\SQLEXPRESS' }),
    [string]$Database  = $(if ($env:PIM_GUI_DB)   { $env:PIM_GUI_DB }   else { "PimScnGui_$([guid]::NewGuid().ToString('N').Substring(0,8))" }),
    [int]$Port = 0,
    [switch]$Stop
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
if (-not $OutFile) { $OutFile = Join-Path $here '.manager.json' }
$sln  = (Resolve-Path (Join-Path $here '..\..\..')).Path
$mgr  = Join-Path $sln 'tools\pim-manager\Open-PimManager.ps1'
$seed = Join-Path $sln 'tests\scenario\Seed-PimScenarioDataset.ps1'

function Write-Side($obj) { [System.IO.File]::WriteAllText($OutFile, ($obj | ConvertTo-Json), (New-Object System.Text.UTF8Encoding $false)) }

if ($Stop) {
    if (Test-Path $OutFile) {
        try { $info = Get-Content $OutFile -Raw | ConvertFrom-Json } catch { $info = $null }
        if ($info -and $info.pid) { try { Stop-Process -Id $info.pid -Force -ErrorAction SilentlyContinue } catch {} }
        if ($info -and $info.db -and -not $info.skip) {
            try {
                $cs = "Server=$($info.server);Database=master;Integrated Security=SSPI;TrustServerCertificate=True;Connect Timeout=8"
                $c = New-Object System.Data.SqlClient.SqlConnection $cs; $c.Open()
                $cmd = $c.CreateCommand(); $cmd.CommandText = "IF DB_ID('$($info.db)') IS NOT NULL BEGIN ALTER DATABASE [$($info.db)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($info.db)]; END"
                $cmd.ExecuteNonQuery() | Out-Null; $c.Close()
            } catch { Write-Warning "scenario GUI DB cleanup: $($_.Exception.Message)" }
        }
        Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
    }
    return
}

# prereq: SQLEXPRESS reachable
try {
    $cs = "Server=$SqlServer;Database=master;Integrated Security=SSPI;TrustServerCertificate=True;Connect Timeout=4"
    $c = New-Object System.Data.SqlClient.SqlConnection $cs; $c.Open(); $c.Close()
} catch { Write-Side @{ skip = $true; reason = "SQLEXPRESS not reachable at $SqlServer" }; return }

# seed the rich scenario set into the throwaway DB
$env:PIM_SqlServer = $SqlServer; $env:PIM_SqlDatabase = $Database
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $seed -OwnerUpn 'admin@example.onmicrosoft.com' -DefaultDomain 'example.onmicrosoft.com' -SqlServer $SqlServer -SqlDatabase $Database 2>&1 | Out-Null
} catch { Write-Side @{ skip = $true; reason = "scenario seed failed: $($_.Exception.Message)" }; return }

# boot the Manager (loopback, SQL mode via env, no browser launch)
$stdout = Join-Path $here '.mgr-stdout.txt'; $stderr = Join-Path $here '.mgr-stderr.txt'
Remove-Item $stdout,$stderr -Force -ErrorAction SilentlyContinue
$psargs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$mgr`"",'-Server','-NoLaunch')
if ($Port -gt 0) { $psargs += @('-Port',"$Port") }
$proc = Start-Process powershell.exe -ArgumentList $psargs -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden

$token = $null; $boundPort = $Port
for ($i = 0; $i -lt 80; $i++) {
    Start-Sleep -Milliseconds 500
    if (Test-Path $stdout) {
        $txt = Get-Content $stdout -Raw -ErrorAction SilentlyContinue
        if ($txt) {
            $pm = [regex]::Match($txt, 'listening on http://(?:127\.0\.0\.1|localhost):(\d+)/')
            if ($pm.Success) { $boundPort = [int]$pm.Groups[1].Value }
            $tm = [regex]::Match($txt, 'session token:\s*([0-9a-fA-F\-]{16,})')
            if ($tm.Success) { $token = $tm.Groups[1].Value }
            if ($token -and $boundPort -gt 0) { break }
        }
    }
    if ($proc.HasExited) { break }
}

if (-not $token -or $boundPort -le 0) {
    $err = if (Test-Path $stderr) { Get-Content $stderr -Raw } else { '' }
    Write-Side @{ skip = $true; reason = "Manager did not report a token/port (exited=$($proc.HasExited)). $err" }
    try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
    return
}

Write-Side ([ordered]@{
    skip    = $false
    baseUrl = "http://127.0.0.1:$boundPort"
    token   = $token
    port    = $boundPort
    pid     = $proc.Id
    role    = 'SuperAdmin'
    server  = $SqlServer
    db      = $Database
})
Write-Host "[scenario-gui] Manager ready at http://127.0.0.1:$boundPort (pid $($proc.Id), db $Database)" -ForegroundColor Green
