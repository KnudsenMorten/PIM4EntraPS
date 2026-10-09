#Requires -Version 5.1
<#
.SYNOPSIS
    Capture the invardia.com PRODUCT-PAGE screenshots of PIM Manager (<feature-slug>-<n>.png, 1600 px wide) against
    SYNTHETIC data, headless, in one command.

.DESCRIPTION
    The product pages (pim-manager.features.json) show one or more pictures per feature. This is the capture for the
    features that have no picture yet (Invardia 2026-10-09: "many of the pics are empty"):

      1. a THROWAWAY SQL database on .\SQLEXPRESS (tests/_shared/PimSqlTestHarness.ps1);
      2. the synthetic Contoso estate of the doc screenshots (tests/gui-headless/Seed-PimDocScreenshotData.ps1);
      3. Open-PimManager.ps1 -Server on a free loopback port, with NO tenant identity reachable (empty az config dir,
         no managed-identity endpoint) -- a capture never reads a directory;
      4. tests/playwright/product-pages.spec.ts in headless chromium at 1600 x 1000:
           - the real Manager pages, driven through the grouped menu. Where a page needs a state a throwaway store
             cannot hold (a Pro licence, a managing tenant, a held policy plan, managed tenants), the BROWSER is served a
             synthetic answer for that one API call -- the page code that renders it is the shipped code;
           - the PIM Activator popup (tools/pim-activator/popup.html) with a stubbed chrome.* and synthetic Graph / ARM
             answers -- no sign-in, no tenant;
           - diagrams (inline SVG, rendered by the same headless browser) for what has no screen;
      5. stop the Manager and DROP the database.

    Every name on every image is synthetic (contoso.onmicrosoft.com, role-named accounts, generic tenant names); the
    capturing machine's identity and the database name are masked and then asserted absent before each screenshot.

.PARAMETER OutDir
    Where the PNGs are written. Default: <solution>\tests\playwright\product-shots (git-ignored output).

.PARAMETER Only
    Capture only these files (e.g. -Only safety-brake-1.png). Default: all.

.PARAMETER SkipInstall
    Skip `npm ci` / `npx playwright install chromium`.

.EXAMPLE
    powershell -NoProfile -File .\tools\Capture-PimProductPageScreenshots.ps1 -OutDir C:\work\shots
#>
[CmdletBinding()]
param(
    [string]$OutDir,
    [string[]]$Only = @(),
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path          # ...\tools
$solDir = Split-Path -Parent $here                                 # ...\PIM4EntraPS
$pwDir  = Join-Path $solDir 'tests\playwright'
$seeder = Join-Path $solDir 'tests\gui-headless\Seed-PimDocScreenshotData.ps1'
if (-not $OutDir) { $OutDir = Join-Path $pwDir 'product-shots' }
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path

function Info($m) { Write-Host $m -ForegroundColor Cyan }
function Ok($m)   { Write-Host $m -ForegroundColor Green }
function Warn($m) { Write-Host $m -ForegroundColor Yellow }

. (Join-Path $solDir 'tests\_shared\PimSqlTestHarness.ps1')

$store = $null; $ctx = $null; $exit = 1; $noAzDir = $null
$serverLog = Join-Path ([IO.Path]::GetTempPath()) ("pim-prodshots-server-{0}.log" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
try {
    Info "Creating a throwaway SQL store ..."
    $store = New-PimTestSqlStore -Prefix 'pimprodshots'
    if (-not $store) { throw "SQL '.\SQLEXPRESS' is not reachable -- the capture needs a local throwaway SQL store (the Manager is SQL-only)." }
    Ok "  $($store.Database)"

    Info "Seeding synthetic screenshot data ..."
    $seedOut = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$seeder" -ConnectionString $store.ConnectionString 2>&1
    $seedExit = $LASTEXITCODE
    @($seedOut) | ForEach-Object { Write-Host "    $_" }
    if ($seedExit -ne 0) { throw "Seed-PimDocScreenshotData.ps1 failed (exit $seedExit)" }

    Info "Starting the Manager on the store (no tenant identity reachable) ..."
    # NO TENANT, EVER: the Manager child gets an EMPTY az config dir and no managed-identity endpoint (see
    # Capture-PimDocScreenshots.ps1 for why).
    $noAzDir = Join-Path ([IO.Path]::GetTempPath()) ("pim-prodshots-noaz-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
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
        $env:PIM_MGR_URL           = $url
        $env:PIM_SHOT_DIR          = $OutDir
        $env:PIM_SHOT_ONLY         = (@($Only | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ',')
        $env:PIM_DOC_MASK_IDENTITY = (Get-PimTestIdentity)
        $env:PIM_DOC_MASK_DATABASE = "$($store.Database)"
        $env:PIM_DOC_MASK_HOST     = "$env:COMPUTERNAME"
        $env:PIM_ACTIVATOR_DIR     = (Join-Path $solDir 'tools\pim-activator')
        $env:PIM_VERSION           = (Get-Content (Join-Path $solDir 'VERSION') -Raw).Trim()
        Info "Capturing product-page screenshots (headless chromium, 1600x1000) -> $OutDir"
        & npx playwright test product-pages --grep '@productshots' --project desktop --reporter=list
        $exit = $LASTEXITCODE
    } finally {
        Pop-Location
        foreach ($v in 'PIM_MGR_URL', 'PIM_SHOT_DIR', 'PIM_SHOT_ONLY', 'PIM_DOC_MASK_IDENTITY', 'PIM_DOC_MASK_DATABASE', 'PIM_DOC_MASK_HOST', 'PIM_ACTIVATOR_DIR', 'PIM_VERSION') { Remove-Item "Env:$v" -ErrorAction SilentlyContinue }
    }
    if ($exit -eq 0) { Ok "`nPRODUCT-PAGE SCREENSHOTS: captured." } else { Warn "`nPRODUCT-PAGE SCREENSHOTS: the capture reported a failure (exit $exit) -- see the list above." }
}
finally {
    if ($ctx) { Info "  stopping the Manager ..."; Stop-PimManagerForTest -Context $ctx }
    if ($store) { Info "  dropping $($store.Database) ..."; Remove-PimTestSqlStore -Store $store }
    if ($noAzDir -and (Test-Path -LiteralPath $noAzDir)) { Remove-Item -LiteralPath $noAzDir -Recurse -Force -ErrorAction SilentlyContinue }
}
exit $exit
