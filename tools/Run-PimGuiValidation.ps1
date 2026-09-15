#Requires -Version 5.1
<#
.SYNOPSIS
    REAL-BROWSER (headless chromium) GUI validation gate for the PIM4EntraPS
    Manager. Serves the Manager locally with seeded data, then drives EVERY tab
    in a real browser and reports any render / paint / layout breakage.

.DESCRIPTION
    This is the *real* GUI gate. The jsdom structural check
    (tests/Test-PimManagerGuiPanels.ps1) verifies the panels/handlers EXIST in
    the markup, but jsdom has no CSS/layout engine and never runs the live-server
    render path -- so it cannot see a panel that paints blank, a control clipped
    off the edge, a banner that wraps mid-token, or a dropdown that renders as raw
    text. This gate runs Playwright against a HEADLESS-but-REAL chromium, against
    a LIVE local Manager server (so `isServer === true` and the panels render real
    data instead of the "Static mode -- needs the server" short-circuit).

    Two targets:
      -Target local  (default) -- spins up Open-PimManager.ps1 -Server on a
                                  THROWAWAY SQL database (.\SQLEXPRESS) seeded
                                  with the representative synthetic desired set
                                  (tests/_shared/PimSqlTestHarness.ps1), then
                                  tears it down and drops the database. No files,
                                  no tenant. SQL-only since 2026-09-12.
      -Target <url>            -- points the spec at an already-running Manager
                                  (e.g. a hosted deploy). The URL must include the
                                  ?token=... handshake. The server is NOT managed.

    Headless on purpose: never pops a visible window. It is still a real browser.

.PARAMETER Target
    'local' (default) to serve + drive a local server, or a full tokenised URL
    of an already-running Manager.

.PARAMETER Port
    Ignored (kept for command-line compatibility): the local server binds a free
    loopback port and the harness reads it back, so runs never collide.

.PARAMETER Project
    Playwright project: 'desktop' (default) or 'narrow-laptop' or 'all'.

.PARAMETER KeepServer
    Leave the local server running after the run (for manual poking). Default off.

.PARAMETER SkipInstall
    Skip `npm install` / browser install (assume node_modules + chromium present).

.EXAMPLE
    .\tools\Run-PimGuiValidation.ps1
.EXAMPLE
    .\tools\Run-PimGuiValidation.ps1 -Project all
.EXAMPLE
    .\tools\Run-PimGuiValidation.ps1 -Target "http://127.0.0.1:8080/?token=abc..."
#>
[CmdletBinding()]
param(
    [string]$Target = 'local',
    [int]$Port = 8899,
    [ValidateSet('desktop', 'narrow-laptop', 'all')] [string]$Project = 'desktop',
    [switch]$KeepServer,
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'
$here       = Split-Path -Parent $MyInvocation.MyCommand.Path           # ...\tools
$solDir     = Split-Path -Parent $here                                  # ...\PIM4EntraPS
$mgrPs      = Join-Path $here 'pim-manager\Open-PimManager.ps1'
$pwDir      = Join-Path $solDir 'tests\playwright'

function Info($m) { Write-Host $m -ForegroundColor Cyan }
function Ok($m)   { Write-Host $m -ForegroundColor Green }
function Warn($m) { Write-Host $m -ForegroundColor Yellow }

if (-not (Test-Path -LiteralPath $mgrPs))  { throw "Open-PimManager.ps1 not found at $mgrPs" }
if (-not (Test-Path -LiteralPath $pwDir))  { throw "Playwright suite not found at $pwDir" }

# ---------------------------------------------------------------------------
# 1. Resolve the target URL (serve locally, or use the given URL).
# ---------------------------------------------------------------------------
$serverProc = $null
$serverLog  = $null
$mgrUrl     = $null

$testStore = $null
$serverCtx = $null
if ($Target -ieq 'local') {
    # SQL-ONLY (2026-09-12): the Manager has no file store to seed. A throwaway SQL database gets the
    # representative synthetic desired set, and the identity running this gate is SuperAdmin in SQL
    # ManagerAccess -- so the Admin-only Authoring / Onboarding panels render their real UI.
    . (Join-Path $solDir 'tests\_shared\PimSqlTestHarness.ps1')
    Info "Creating a throwaway SQL store and seeding the synthetic desired set ..."
    $testStore = New-PimTestSqlStore -Prefix 'pimguival'
    if (-not $testStore) { throw "SQL '.\SQLEXPRESS' is not reachable -- the local GUI gate needs a SQL store (the Manager is SQL-only)." }
    Import-PimTestBaselineSeed -Store $testStore
    Ok "  seeded $($testStore.Database)"

    Info "Starting Manager (Open-PimManager.ps1 -Server) on a free loopback port ..."
    $serverLog = Join-Path ([IO.Path]::GetTempPath()) ("pim-gui-server-{0}.log" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    $serverCtx = Start-PimManagerOnTestStore -Store $testStore -StdoutPath $serverLog -TimeoutSec 90
    $serverProc = $serverCtx.Process
    if (-not $serverCtx.Token -or $serverCtx.Port -le 0) {
        $outTxt = if (Test-Path $serverLog) { Get-Content $serverLog -Raw } else { '' }
        $errTxt = if (Test-Path "$serverLog.err") { Get-Content "$serverLog.err" -Raw } else { '' }
        Remove-PimTestSqlStore -Store $testStore
        throw "Did not see a session token from the Manager within 90s.`nSTDOUT:`n$outTxt`nSTDERR:`n$errTxt"
    }
    $mgrUrl = "$($serverCtx.BaseUrl)/?token=$($serverCtx.Token)"
    Ok "  Manager live at $mgrUrl"
}
else {
    if ($Target -notmatch '^https?://') { throw "-Target must be 'local' or a full http(s) URL (got '$Target')." }
    if ($Target -notmatch 'token=')     { Warn "  -Target URL has no token= -- /api calls will 401 and tabs will show errors." }
    $mgrUrl = $Target
    Info "Using already-running Manager at $mgrUrl"
}

# ---------------------------------------------------------------------------
# 2. Run Playwright (headless real chromium) against the URL.
# ---------------------------------------------------------------------------
$exit = 1
Push-Location $pwDir
try {
    if (-not $SkipInstall) {
        if (-not (Test-Path (Join-Path $pwDir 'node_modules\@playwright'))) {
            Info "Installing Playwright (npm install) ..."
            & npm install --no-audit --no-fund
            if ($LASTEXITCODE -ne 0) { throw "npm install failed ($LASTEXITCODE)" }
        }
        Info "Ensuring chromium is installed ..."
        & npx playwright install chromium | Out-Null
    }

    $env:PIM_MGR_URL = $mgrUrl
    $projArgs = if ($Project -eq 'all') { @() } else { @('--project', $Project) }
    Info "Running Playwright GUI validation (headless chromium) ..."
    & npx playwright test manager-gui-validation --grep '@gui' @projArgs --reporter=list
    $exit = $LASTEXITCODE
    if ($exit -eq 0) { Ok  "`nGUI VALIDATION: PASS -- every tab rendered, painted, and was layout-sane." }
    else             { Warn "`nGUI VALIDATION: FAIL -- see the FOUND ... GUI problem(s) list + test-results/ screenshots." }
}
finally {
    Pop-Location
    if ($serverProc -and -not $serverProc.HasExited) {
        if ($KeepServer) {
            Warn "  -KeepServer set: Manager left running at $mgrUrl (PID $($serverProc.Id)) on SQL database $($testStore.Database). Stop it and drop the database manually."
        } else {
            Info "  stopping local Manager (PID $($serverProc.Id)) ..."
            try { Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
    if ($testStore -and -not $KeepServer) { Remove-PimTestSqlStore -Store $testStore }
}

exit $exit
