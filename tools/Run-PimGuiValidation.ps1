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
      -Target local  (default) -- spins up Open-PimManager.ps1 -Server against a
                                  temp config root seeded from the shipped
                                  *.custom.sample.* files, on a pinned port, then
                                  tears it down. Self-contained, no tenant.
      -Target <url>            -- points the spec at an already-running Manager
                                  (e.g. a hosted deploy). The URL must include the
                                  ?token=... handshake. The server is NOT managed.

    Headless on purpose: never pops a visible window. It is still a real browser.

.PARAMETER Target
    'local' (default) to serve + drive a local server, or a full tokenised URL
    of an already-running Manager.

.PARAMETER Port
    Loopback port for the local server (default 8899).

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
$configDir  = Join-Path $solDir 'config'
$pwDir      = Join-Path $solDir 'tests\playwright'
$seedDir    = Join-Path $pwDir '.seed-config'

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

function Seed-ConfigRoot {
    # Build a temp config root the live server can load: the Manager reads
    # *.custom.csv (+ *.custom.ps1 / *.custom.json), and the repo ships
    # *.custom.sample.* representative data. Copy sample -> active so a fresh
    # checkout has a populated, realistic delegation model to render.
    if (Test-Path -LiteralPath $seedDir) { Remove-Item -LiteralPath $seedDir -Recurse -Force }
    New-Item -ItemType Directory -Path $seedDir -Force | Out-Null

    # Locked/shipped files (naming/filters/etc) -- copy as-is so the engine libs load.
    Get-ChildItem -LiteralPath $configDir -File | Where-Object { $_.Name -like '*.locked.*' } |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $seedDir $_.Name) -Force }

    # Sample customer overrides -> the active .custom.* names the Manager loads.
    # EXCEPT manager-access.custom.json: omitting it makes the local launcher the
    # implicit SuperAdmin (Open-PimManager.ps1 "default (no manager-access...)"),
    # so the validator exercises the FULL render path (Admin-only Authoring /
    # Onboarding panels render their real UI instead of a role-gated stub).
    $copied = 0
    Get-ChildItem -LiteralPath $configDir -File | Where-Object { $_.Name -like '*.custom.sample.*' -and $_.Name -notlike 'manager-access.*' } | ForEach-Object {
        $active = $_.Name -replace '\.custom\.sample\.', '.custom.'
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $seedDir $active) -Force
        $copied++
    }
    # Plain .sample.json (exemptions/portal-admins) -> their non-sample names.
    Get-ChildItem -LiteralPath $configDir -File | Where-Object { $_.Name -like '*.sample.json' -and $_.Name -notlike '*.custom.sample.*' } | ForEach-Object {
        $active = $_.Name -replace '\.sample\.', '.'
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $seedDir $active) -Force
    }
    Ok "  seeded $copied customer CSV/config files into $seedDir"
    return $seedDir
}

if ($Target -ieq 'local') {
    Info "Seeding a temp config root from shipped sample data ..."
    $root = Seed-ConfigRoot

    Info "Starting Manager (Open-PimManager.ps1 -Server) on loopback port $Port ..."
    $serverLog = Join-Path ([IO.Path]::GetTempPath()) ("pim-gui-server-{0}.log" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    # Run in its own powershell.exe so the HttpListener loop owns the process; we
    # parse its stdout for the session token. -NoLaunch keeps any browser closed.
    $psExe = (Get-Process -Id $PID).Path
    if (-not $psExe) { $psExe = 'powershell.exe' }
    $args = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $mgrPs,
        '-Server', '-NoLaunch', '-Port', $Port, '-ConfigRoot', $root
    )
    $serverProc = Start-Process -FilePath $psExe -ArgumentList $args -PassThru `
        -RedirectStandardOutput $serverLog -RedirectStandardError "$serverLog.err" -WindowStyle Hidden

    # Wait for the "session token:" line + confirm the port is listening.
    $token = $null
    $deadline = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $deadline) {
        if ($serverProc.HasExited) {
            $errTxt = if (Test-Path "$serverLog.err") { Get-Content "$serverLog.err" -Raw } else { '' }
            $outTxt = if (Test-Path $serverLog) { Get-Content $serverLog -Raw } else { '' }
            throw "Manager server exited early (code $($serverProc.ExitCode)).`nSTDOUT:`n$outTxt`nSTDERR:`n$errTxt"
        }
        if (Test-Path -LiteralPath $serverLog) {
            $log = Get-Content -LiteralPath $serverLog -Raw -ErrorAction SilentlyContinue
            $mt = [regex]::Match("$log", 'session token:\s*([0-9a-fA-F]{32})')
            if ($mt.Success) { $token = $mt.Groups[1].Value; break }
        }
        Start-Sleep -Milliseconds 400
    }
    if (-not $token) {
        $outTxt = if (Test-Path $serverLog) { Get-Content $serverLog -Raw } else { '' }
        throw "Did not see a session token from the Manager within 90s.`nServer log:`n$outTxt"
    }
    $mgrUrl = "http://127.0.0.1:$Port/?token=$token"
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
            Warn "  -KeepServer set: Manager left running at $mgrUrl (PID $($serverProc.Id)). Stop it manually."
        } else {
            Info "  stopping local Manager (PID $($serverProc.Id)) ..."
            try { Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
}

exit $exit
