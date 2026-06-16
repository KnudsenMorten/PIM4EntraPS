#Requires -Version 5.1
<#
.SYNOPSIS
    Run the PIM4EntraPS Manager GUI test suite (Playwright). Self-skips cleanly
    when Node / Playwright / SQLEXPRESS are unavailable -- so it is safe to wire
    into the offline release gate.

.DESCRIPTION
    The GUI suite (tests/playwright) drives the REAL PIM Manager GUI end-to-end:
    it boots a LOCAL Open-PimManager.ps1 -Server instance in SQL mode against a
    throwaway local SQLEXPRESS pim.Rows DB (seeded by Seed-PimBaselineDataset.ps1),
    captures the per-session bearer token, and exercises every released GUI
    feature (Create wizard, Delegation Map, Validate, Review & Save, Maintenance,
    Advanced View grid, Governance, Conformance, role tiers, SQL banner, auth).

    This script is the single entrypoint:
      - checks prerequisites (Node + the @playwright/test package + a Chromium
        browser + a reachable SQLEXPRESS); if any is missing it prints a SKIP and
        exits 0 (absence is not a failure -- mirrors the PS Live-test rule);
      - installs npm deps + the Chromium browser on first run when -Install is set;
      - runs `npx playwright test` (optionally once per role with -AllRoles);
      - for a live smoke run, pass -LiveUrl/-LiveToken (points at ca-pim-manager).

.PARAMETER Install
    npm install + playwright install chromium before running (first-time setup).

.PARAMETER AllRoles
    Run the suite once per Manager role (SuperAdmin, Admin, Reader, Delegated) to
    exercise the role-tier read-only/read-write contract end-to-end.

.PARAMETER Headed
    Run with a visible browser (debugging).

.PARAMETER Live
    Include the @live-tagged specs (need a real tenant + a live Manager).

.PARAMETER LiveUrl / .PARAMETER LiveToken
    Drive the hosted Manager (ca-pim-manager) instead of booting locally. The
    token must be a valid Easy-Auth/session bearer for that instance.

.EXAMPLE
    powershell -NoProfile -File tests\playwright\feature-suite\Run-PimGuiTests.ps1 -Install
.EXAMPLE
    powershell -NoProfile -File tests\playwright\feature-suite\Run-PimGuiTests.ps1 -AllRoles
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$AllRoles,
    [switch]$Headed,
    [switch]$Live,
    [string]$LiveUrl,
    [string]$LiveToken,
    [string]$SqlServer = '.\SQLEXPRESS'
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Skip([string]$why) { Write-Host "  SKIP (GUI suite): $why" -ForegroundColor Yellow; exit 0 }

# --- prerequisites -------------------------------------------------------
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) { Skip 'Node.js not found on PATH.' }

Push-Location $here
try {
    if ($Install) {
        Write-Host "  installing npm deps + Chromium ..." -ForegroundColor Cyan
        & npm install --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { Skip 'npm install failed.' }
        & npx playwright install chromium
        if ($LASTEXITCODE -ne 0) { Skip 'playwright browser install failed.' }
    }

    if (-not (Test-Path (Join-Path $here 'node_modules\@playwright\test'))) {
        Skip 'Playwright not installed (run with -Install once).'
    }

    # SQL reachability (only needed for the LOCAL harness, not live mode).
    $liveMode = ($LiveUrl -and $LiveToken)
    if (-not $liveMode) {
        $reachable = $false
        try {
            $cs = "Server=$SqlServer;Database=master;Integrated Security=SSPI;TrustServerCertificate=True;Connect Timeout=4"
            $c = New-Object System.Data.SqlClient.SqlConnection $cs; $c.Open(); $c.Close(); $reachable = $true
        } catch { $reachable = $false }
        if (-not $reachable) { Skip "SQLEXPRESS not reachable at $SqlServer (no local Manager to drive)." }
        $env:PIM_SqlServer = $SqlServer
        if (-not $env:PIM_SqlDatabase) { $env:PIM_SqlDatabase = 'PimGuiTest' }
    } else {
        $env:PIM_GUI_LIVE_URL = $LiveUrl
        $env:PIM_GUI_LIVE_TOKEN = $LiveToken
    }

    if ($Live) { $env:PIM_GUI_LIVE = '1' }

    $pwArgs = @('playwright', 'test')
    if ($Headed) { $pwArgs += '--headed' }

    $fail = 0
    if ($AllRoles) {
        foreach ($role in 'SuperAdmin', 'Admin', 'Reader', 'Delegated') {
            Write-Host "`n############ GUI suite -- role: $role ############" -ForegroundColor Cyan
            $env:PIM_GUI_ROLE = $role
            & npx @pwArgs
            if ($LASTEXITCODE -ne 0) { $fail++ }
        }
        Remove-Item Env:\PIM_GUI_ROLE -ErrorAction SilentlyContinue
    } else {
        & npx @pwArgs
        if ($LASTEXITCODE -ne 0) { $fail++ }
    }

    if ($fail) { Write-Host "`n GUI suite: $fail run(s) FAILED" -ForegroundColor Red; exit 1 }
    Write-Host "`n GUI suite: GREEN" -ForegroundColor Green
} finally {
    Pop-Location
}
