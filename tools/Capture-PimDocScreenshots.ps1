#Requires -Version 5.1
<#
.SYNOPSIS
    Recapture the public-doc screenshots of the PIM Manager (docs/img/manager-*.png) against
    SYNTHETIC data, headless, in one command.

.DESCRIPTION
    The release checklist requires the docs/img screenshots to match the current Manager UI, captured
    headlessly against seeded synthetic data -- never a real tenant, never a visible browser. This is
    that capture, end to end:

      1. a THROWAWAY SQL database on .\SQLEXPRESS (tests/_shared/PimSqlTestHarness.ps1);
      2. the synthetic Contoso estate, pending queue, drift + standing-access snapshots and job runs
         (tests/gui-headless/Seed-PimDocScreenshotData.ps1);
      3. Open-PimManager.ps1 -Server on a free loopback port, the identity running this as SuperAdmin;
      4. tests/playwright/doc-screenshots.spec.ts in headless chromium at 1366x900, driving the grouped
         menu to each surface and writing one PNG per surface;
      5. stop the Manager and DROP the database (unless -KeepServer).

    The spec masks the Windows identity running the capture (shown in the header and in Settings)
    as a synthetic Contoso account before each screenshot, so no machine or user name is published.

    Surfaces (file -> screen):
      manager-home.png             Overview > Home
      manager-nav.png              the six-menu navigation, a menu open
      manager-access-map.png       Access > Access map
      manager-pending-changes.png  Pending changes > Review & commit queue
      manager-drift.png            Reviews & controls > Drift: live vs desired
      manager-jobs-logs.png        Jobs > Engine logs & errors (with a run's log open)
      manager-standing-access.png  Reviews & controls > Review current delegations
      manager-reports.png          Reviews & controls > Reports
      manager-role-lookup.png      Access > Look up a role
      manager-settings.png         Audit & Settings > Settings

.PARAMETER OutDir
    Where the PNGs are written. Default: docs/img of this solution.

.PARAMETER Only
    Capture only these files (e.g. -Only manager-drift.png,manager-home.png). Default: all.

.PARAMETER KeepServer
    Leave the Manager running and the database in place afterwards (prints both). Default off.
    Note the Manager self-exits after ~45 s without a browser heartbeat; the database stays until dropped.

.PARAMETER SkipInstall
    Skip `npm ci` / `npx playwright install chromium`.

.EXAMPLE
    powershell -NoProfile -File .\tools\Capture-PimDocScreenshots.ps1
.EXAMPLE
    powershell -NoProfile -File .\tools\Capture-PimDocScreenshots.ps1 -Only manager-drift.png -SkipInstall
#>
[CmdletBinding()]
param(
    [string]$OutDir,
    [string[]]$Only = @(),
    [switch]$KeepServer,
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path          # ...\tools
$solDir = Split-Path -Parent $here                                 # ...\PIM4EntraPS
$pwDir  = Join-Path $solDir 'tests\playwright'
$seeder = Join-Path $solDir 'tests\gui-headless\Seed-PimDocScreenshotData.ps1'
if (-not $OutDir) { $OutDir = Join-Path $solDir 'docs\img' }
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path

function Info($m) { Write-Host $m -ForegroundColor Cyan }
function Ok($m)   { Write-Host $m -ForegroundColor Green }
function Warn($m) { Write-Host $m -ForegroundColor Yellow }

. (Join-Path $solDir 'tests\_shared\PimSqlTestHarness.ps1')

$store = $null; $ctx = $null; $exit = 1; $noAzDir = $null
$serverLog = Join-Path ([IO.Path]::GetTempPath()) ("pim-docshots-server-{0}.log" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
try {
    Info "Creating a throwaway SQL store ..."
    $store = New-PimTestSqlStore -Prefix 'pimdocshots'
    if (-not $store) { throw "SQL '.\SQLEXPRESS' is not reachable -- the capture needs a local throwaway SQL store (the Manager is SQL-only)." }
    Ok "  $($store.Database)"

    Info "Seeding synthetic screenshot data ..."
    $seedOut = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$seeder" -ConnectionString $store.ConnectionString 2>&1
    $seedExit = $LASTEXITCODE
    @($seedOut) | ForEach-Object { Write-Host "    $_" }
    if ($seedExit -ne 0) { throw "Seed-PimDocScreenshotData.ps1 failed (exit $seedExit)" }

    Info "Starting the Manager on the store (no tenant identity reachable) ..."
    # 🔒 NO TENANT, EVER. With no explicit identity configured, PIM-Rest's token helper falls back to the
    # ambient `az` login -- on the dev machine that is a REAL tenant (often another company's). A doc capture
    # must never read a directory, so the Manager child gets an EMPTY az config dir (az answers "not logged
    # in") and no managed-identity endpoint. Tenant-backed tiles then show their honest "could not check" state.
    $noAzDir = Join-Path ([IO.Path]::GetTempPath()) ("pim-docshots-noaz-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    New-Item -ItemType Directory -Force -Path $noAzDir | Out-Null
    $isolation = @{ AZURE_CONFIG_DIR = $noAzDir; IDENTITY_ENDPOINT = $null; IDENTITY_HEADER = $null; MSI_ENDPOINT = $null
                    AZURE_CLIENT_ID = $null; AZURE_TENANT_ID = $null; AZURE_CLIENT_SECRET = $null; AZURE_CLIENT_CERTIFICATE_PATH = $null }
    $ctx = Start-PimManagerOnTestStore -Store $store -StdoutPath $serverLog -TimeoutSec 90 -Environment $isolation
    if (-not $ctx.Token -or $ctx.Port -le 0) {
        $o = if (Test-Path $serverLog) { Get-Content $serverLog -Raw } else { '' }
        $e = if (Test-Path "$serverLog.err") { Get-Content "$serverLog.err" -Raw } else { '' }
        throw "The Manager did not report a session token within 90s.`nSTDOUT:`n$o`nSTDERR:`n$e"
    }
    $url = "$($ctx.BaseUrl)/?token=$($ctx.Token)"
    Ok "  Manager live on $($ctx.BaseUrl)"

    Push-Location $pwDir
    try {
        if (-not $SkipInstall) {
            if (-not (Test-Path (Join-Path $pwDir 'node_modules\@playwright'))) {
                Info "Installing Playwright (npm ci) ..."
                & npm ci --no-audit --no-fund
                if ($LASTEXITCODE -ne 0) { throw "npm ci failed ($LASTEXITCODE)" }
            }
            Info "Ensuring headless chromium is installed ..."
            & npx playwright install chromium | Out-Null
        }
        $env:PIM_MGR_URL          = $url
        $env:PIM_DOC_IMG_DIR      = $OutDir
        $env:PIM_DOC_ONLY         = (@($Only | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ',')
        $env:PIM_DOC_MASK_IDENTITY = (Get-PimTestIdentity)
        $env:PIM_DOC_MASK_DATABASE = "$($store.Database)"
        Info "Capturing screenshots (headless chromium, 1366x900) -> $OutDir"
        & npx playwright test doc-screenshots --grep '@docshots' --project desktop --reporter=list
        $exit = $LASTEXITCODE
    } finally {
        Pop-Location
        foreach ($v in 'PIM_MGR_URL', 'PIM_DOC_IMG_DIR', 'PIM_DOC_ONLY', 'PIM_DOC_MASK_IDENTITY', 'PIM_DOC_MASK_DATABASE') { Remove-Item "Env:$v" -ErrorAction SilentlyContinue }
    }
    if ($exit -eq 0) { Ok "`nDOC SCREENSHOTS: captured." } else { Warn "`nDOC SCREENSHOTS: the capture reported a failure (exit $exit) -- see the list above." }
}
finally {
    if ($KeepServer -and $ctx -and $ctx.Process -and -not $ctx.Process.HasExited) {
        Warn "  -KeepServer: Manager left running at $($ctx.BaseUrl)/?token=$($ctx.Token) (PID $($ctx.Process.Id)); database $($store.Database). Stop the process and drop the database when done."
    } else {
        if ($ctx) { Info "  stopping the Manager ..."; Stop-PimManagerForTest -Context $ctx }
        if ($store) { Info "  dropping $($store.Database) ..."; Remove-PimTestSqlStore -Store $store }
        if ($noAzDir -and (Test-Path -LiteralPath $noAzDir)) { Remove-Item -LiteralPath $noAzDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
exit $exit
