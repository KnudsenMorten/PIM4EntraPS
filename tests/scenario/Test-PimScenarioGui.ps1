#Requires -Version 5.1
<#
.SYNOPSIS
  Run the engine+GUI scenario-simulation Playwright specs (REQUIREMENTS.md §20). Boots the
  Manager in SQL mode over the rich scenario seed and drives the GUI to assert it reflects
  the engine state AND that GUI actions round-trip to SQL.

  SELF-SKIPS (exit 0) -- mirroring the Live-test doctrine -- when any prerequisite is
  missing: Node.js, the Playwright package (run once with -Install), or SQLEXPRESS. A skip
  means the gate did not run; it is NOT a pass and NOT a failure.

.EXAMPLE
  powershell -NoProfile -File tests\scenario\Test-PimScenarioGui.ps1 -Install   # first time
  powershell -NoProfile -File tests\scenario\Test-PimScenarioGui.ps1
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [string]$SqlServer = $(if ($env:PIM_SqlServer) { $env:PIM_SqlServer } else { '.\SQLEXPRESS' }),
    # drive an already-running hosted Manager instead of booting a local one
    [string]$LiveUrl,
    [string]$LiveToken
)
$ErrorActionPreference = 'Stop'
$gui = Join-Path $PSScriptRoot 'gui'
function Skip([string]$why) { Write-Host "  SKIP (scenario GUI): $why" -ForegroundColor Yellow; exit 0 }

# Node present?
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) { Skip 'Node.js not found on PATH.' }

# Install on request (npm deps + Chromium).
if ($Install) {
    Write-Host "Installing Playwright + Chromium for the scenario GUI specs..." -ForegroundColor Cyan
    Push-Location $gui
    try {
        & npm install
        if ($LASTEXITCODE -ne 0) { throw "npm install failed ($LASTEXITCODE)" }
        & npx playwright install chromium
        if ($LASTEXITCODE -ne 0) { throw "playwright install failed ($LASTEXITCODE)" }
    } finally { Pop-Location }
    Write-Host "Install complete." -ForegroundColor Green
}

# Playwright installed?
if (-not (Test-Path (Join-Path $gui 'node_modules\@playwright\test'))) { Skip 'Playwright not installed (run once with -Install).' }

$live = ($LiveUrl -and $LiveToken)
if ($live) {
    $env:PIM_GUI_LIVE_URL   = $LiveUrl
    $env:PIM_GUI_LIVE_TOKEN = $LiveToken
} else {
    # local mode needs SQLEXPRESS for the throwaway store the Manager renders
    try {
        $cs = "Server=$SqlServer;Database=master;Integrated Security=SSPI;TrustServerCertificate=True;Connect Timeout=4"
        $c = New-Object System.Data.SqlClient.SqlConnection $cs; $c.Open(); $c.Close()
    } catch { Skip "SQLEXPRESS not reachable at $SqlServer (no local Manager to drive)." }
    $env:PIM_SqlServer = $SqlServer
}

Write-Host "Running scenario GUI specs (Playwright)..." -ForegroundColor Cyan
Push-Location $gui
try {
    & npx playwright test
    $code = $LASTEXITCODE
} finally { Pop-Location }
if ($code -ne 0) { Write-Host "  scenario GUI specs FAILED ($code)" -ForegroundColor Red; exit 1 }
Write-Host "  scenario GUI specs GREEN" -ForegroundColor Green
