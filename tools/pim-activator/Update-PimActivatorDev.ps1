#Requires -Version 5.1
<#
.SYNOPSIS
    Dev-loop helper for rapid PIM Activator iteration. Two modes:

    1. Default (no flags)  -> just flush local browser caches + restart Edge so
                              the next launch pulls the latest CRX from
                              GitHub Pages via the forcelist policy.

    2. -Repack             -> also bumps the patch version, repacks the CRX
                              with placeholder config, pushes pim-activator.crx
                              + updates.xml to the gh-pages branch, THEN does
                              the flush + restart. End-to-end "make my browser
                              show the latest code" in one command.

    Built for iterations 0.4.2 -> 0.4.3 -> 0.4.4 -> ... where you don't want
    to manually kill processes, patch Preferences JSON, push gh-pages, etc.

.PARAMETER Repack
    If set, repacks the extension and pushes it to gh-pages before flushing
    the local browser. Bumps the patch version in manifest.json
    (0.4.2 -> 0.4.3) and updates.xml automatically.

.PARAMETER PackOnly
    Repack + push to gh-pages but DO NOT flush the local browser. Useful when
    you want to push a release without disrupting your current browser session.

.PARAMETER Browser
    Which browser(s) to flush + restart. Edge, Chrome, or Both. Default Both.

.PARAMETER NoRestart
    Skip the final browser launch. Just flush; you start the browser yourself.

.PARAMETER GhPagesDir
    Local clone of the gh-pages branch. Auto-cloned to a temp dir on first use.

.EXAMPLE
    # I edited popup.js, gh-pages is already up to date, just want local browser
    # to redownload the existing CRX. Quick flush + restart.
    .\Update-PimActivatorDev.ps1

.EXAMPLE
    # I edited popup.js, bump version + push CRX + flush my browser. Full loop.
    .\Update-PimActivatorDev.ps1 -Repack

.EXAMPLE
    # CI-style: pack + push but don't touch my running browser.
    .\Update-PimActivatorDev.ps1 -PackOnly

.NOTES
    Companion to Setup-PimActivator.ps1 (the customer-facing installer) +
    Deploy-PimActivatorClient.ps1 (registry forcelist writer). Those are
    for one-time customer onboarding; this is for the maintainer's dev loop.
#>

[CmdletBinding()]
param(
    [switch]$Repack,
    [switch]$PackOnly,
    [string]$Version,                # set exact manifest version (e.g. 1.0.0) instead of patch bump
    [ValidateSet('Edge','Chrome','Both')]
    [string]$Browser = 'Both',
    [switch]$NoRestart,
    [string]$GhPagesDir = (Join-Path $env:LOCALAPPDATA 'PimActivatorPages')
)

$ErrorActionPreference = 'Stop'
$EXT_ID = 'eheocihmlppcophaeakmdenhgcookkab'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Step { param([string]$Msg) Write-Host "`n>> $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "   $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "   $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "   $Msg" -ForegroundColor Red }

# ============================================================================
# Repack mode (optional)
# ============================================================================
if ($Repack -or $PackOnly) {

    # ---- Pre-flight: syntax-check popup.js via Node ----------------------
    # SyntaxError in popup.js silently hangs the popup ("Loading ..." forever);
    # Edge doesn't surface JS parse errors to the user. Catch them before pack
    # so we never ship a CRX that bricks the popup. Skipped if Node isn't on
    # PATH (some lock-down dev boxes); -Repack proceeds without it.
    $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
    if ($nodeCmd) {
        Write-Step "Pre-flight: syntax-check popup.js"
        $popupJs = Join-Path $SCRIPT_DIR 'popup.js'
        # PowerShell 5.1 doesn't support `<` input redirection (reserved).
        # Pipe via Get-Content -Raw instead.
        $output = Get-Content -LiteralPath $popupJs -Raw | & node --input-type=module --check 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Err "popup.js has a SyntaxError -- refusing to pack:"
            $output | ForEach-Object { Write-Err "  $_" }
            throw "popup.js syntax check failed. Fix the error above and re-run."
        }
        Write-Ok "popup.js parses cleanly"
    } else {
        Write-Warn "Node not on PATH -- skipping popup.js syntax check (consider installing Node so future SyntaxErrors get caught before pack)"
    }

    # ---- Bump manifest.json version ------------------------------------------
    # Default: increment the last (patch) component. Override with -Version
    # to pin an exact version (used for milestone releases like 1.0.0 where
    # the auto-bump would land on the wrong number).
    $manifestPath = Join-Path $SCRIPT_DIR 'manifest.json'
    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
    $oldVer = $manifest.version
    if ($Version) {
        Write-Step "Pinning manifest.json version to $Version (overriding auto-bump)"
        $newVer = $Version
    } else {
        Write-Step "Bumping manifest.json patch version"
        $parts = $oldVer.Split('.')
        $parts[-1] = ([int]$parts[-1] + 1).ToString()
        $newVer = $parts -join '.'
    }
    $manifest.version = $newVer
    ($manifest | ConvertTo-Json -Depth 20) | Set-Content $manifestPath -Encoding UTF8
    Write-Ok "Bumped: $oldVer -> $newVer"

    # ---- Repack CRX with placeholder config ---------------------------------
    Write-Step "Repacking CRX with placeholder config"
    $edgeExe = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
    if (-not (Test-Path $edgeExe)) {
        $edgeExe = 'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
    }
    if (-not (Test-Path $edgeExe)) { throw "msedge.exe not found" }

    $keyPath = "$env:USERPROFILE\.pim-activator\signing-key.pem"
    if (-not (Test-Path $keyPath)) { throw "signing key missing: $keyPath" }

    $cfgPath  = Join-Path $SCRIPT_DIR 'config.js'
    $tmplPath = Join-Path $SCRIPT_DIR 'config.template.js'
    $savedCfg = if (Test-Path $cfgPath) { Get-Content -LiteralPath $cfgPath -Raw } else { $null }

    # msedge cannot pack while a running instance holds the source dir.
    Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2

    try {
        if (Test-Path $tmplPath) {
            Copy-Item -LiteralPath $tmplPath -Destination $cfgPath -Force
        } else {
            throw "config.template.js missing - refusing to pack (would leak maintainer tenant)"
        }

        $crxOutput = "$SCRIPT_DIR.crx"
        if (Test-Path $crxOutput) { Remove-Item $crxOutput -Force }

        $packArgs = @("--pack-extension=$SCRIPT_DIR", "--pack-extension-key=$keyPath")
        Start-Process -FilePath $edgeExe -ArgumentList $packArgs -NoNewWindow -Wait | Out-Null
        Start-Sleep -Seconds 2

        if (-not (Test-Path $crxOutput)) {
            throw "msedge.exe --pack-extension did not produce $crxOutput"
        }
        $crxSize = (Get-Item $crxOutput).Length
        Write-Ok "CRX packed: $crxSize bytes ($crxOutput)"

        # Sanity-check CRX magic
        $magic = -join ([System.IO.File]::ReadAllBytes($crxOutput) | Select-Object -First 4 | ForEach-Object { [char]$_ })
        if ($magic -ne 'Cr24') { throw "CRX magic header invalid - got '$magic'" }
    } finally {
        if ($savedCfg) {
            Set-Content -LiteralPath $cfgPath -Value $savedCfg -Encoding UTF8 -NoNewline
        } elseif (Test-Path $cfgPath) {
            Remove-Item $cfgPath -Force
        }
    }

    # ---- Publish to gh-pages -------------------------------------------------
    Write-Step "Publishing CRX + updates.xml to gh-pages"
    $repoUrl = 'https://github.com/KnudsenMorten/PIM4EntraPS.git'

    if (-not (Test-Path (Join-Path $GhPagesDir '.git'))) {
        Write-Ok "Cloning gh-pages into $GhPagesDir (one-time)"
        if (Test-Path $GhPagesDir) { Remove-Item $GhPagesDir -Recurse -Force }
        New-Item -ItemType Directory -Path $GhPagesDir -Force | Out-Null
        & git clone --branch gh-pages --depth 1 $repoUrl $GhPagesDir 2>&1 | Out-Null
    } else {
        Write-Ok "Refreshing existing gh-pages clone"
        Push-Location $GhPagesDir
        try { & git pull --quiet origin gh-pages 2>&1 | Out-Null } finally { Pop-Location }
    }

    Copy-Item "$SCRIPT_DIR.crx" (Join-Path $GhPagesDir 'pim-activator.crx') -Force

    $updatesXml = @"
<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='$EXT_ID'>
    <updatecheck codebase='https://knudsenmorten.github.io/PIM4EntraPS/pim-activator.crx' version='$newVer' />
  </app>
</gupdate>
"@
    Set-Content (Join-Path $GhPagesDir 'updates.xml') -Value $updatesXml -Encoding UTF8 -NoNewline

    Push-Location $GhPagesDir
    try {
        & git add pim-activator.crx updates.xml | Out-Null
        & git -c user.email='mok@mortenknudsen.net' -c user.name='Morten Knudsen' commit -m "PIM Activator extension v$newVer (dev iteration)" 2>&1 | Out-Null
        & git push origin gh-pages 2>&1 | ForEach-Object { Write-Host "   $_" -ForegroundColor Gray }
    } finally { Pop-Location }
    Write-Ok "v$newVer published to https://knudsenmorten.github.io/PIM4EntraPS/"

    if ($PackOnly) {
        Write-Step "PackOnly mode - skipping local browser flush"
        Write-Ok  "Done. To pull on this machine later: run this script without -PackOnly."
        return
    }
}

# ============================================================================
# Local browser flush
# ============================================================================

$browsers = switch ($Browser) {
    'Edge'   { @(@{Name='Edge';   ExeName='msedge'; UserData="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"}) }
    'Chrome' { @(@{Name='Chrome'; ExeName='chrome'; UserData="$env:LOCALAPPDATA\Google\Chrome\User Data\Default"}) }
    'Both'   { @(
        @{Name='Edge';   ExeName='msedge'; UserData="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"},
        @{Name='Chrome'; ExeName='chrome'; UserData="$env:LOCALAPPDATA\Google\Chrome\User Data\Default"}
    ) }
}

Write-Step "Killing browser processes"
foreach ($b in $browsers) {
    $procs = Get-Process $b.ExeName -ErrorAction SilentlyContinue
    if ($procs) {
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Ok "$($b.Name): killed $($procs.Count) process(es)"
    } else {
        Write-Warn "$($b.Name): not running"
    }
}
Start-Sleep -Seconds 3

Write-Step "Deleting cached extension binaries"
foreach ($b in $browsers) {
    $path = Join-Path $b.UserData "Extensions\$EXT_ID"
    if (Test-Path $path) {
        try { Remove-Item $path -Recurse -Force -ErrorAction Stop; Write-Ok "$($b.Name): removed $path" }
        catch { Write-Err "$($b.Name): failed - $($_.Exception.Message)" }
    } else {
        Write-Warn "$($b.Name): no cached extension folder"
    }
}

Write-Step "Patching Preferences JSON (settings + HMACs + pin/toolbar)"
# Aggressive scrub: covers extensions.settings.<id>, the HMAC integrity hash
# at protection.macs.extensions.settings.<id> (without removing the MAC,
# Edge rejects our scrub + reinstates the stale entry), plus pinned/toolbar
# arrays. Hard-won lesson from the 0.4.0 -> 0.4.2 dev loop where the user
# kept getting "file not found" because Secure Preferences held a path to
# a deleted version folder. See feedback_pim_no_update_button.md.
foreach ($b in $browsers) {
    foreach ($name in 'Preferences','Secure Preferences') {
        $prefPath = Join-Path $b.UserData $name
        if (-not (Test-Path $prefPath)) { continue }
        try {
            $json = Get-Content -LiteralPath $prefPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $touched = $false
            if ($json.extensions -and $json.extensions.settings -and $json.extensions.settings.$EXT_ID) {
                $json.extensions.settings.PSObject.Properties.Remove($EXT_ID)
                $touched = $true
            }
            if ($json.protection -and $json.protection.macs -and $json.protection.macs.extensions -and $json.protection.macs.extensions.settings -and $json.protection.macs.extensions.settings.$EXT_ID) {
                $json.protection.macs.extensions.settings.PSObject.Properties.Remove($EXT_ID)
                $touched = $true
            }
            if ($json.extensions -and $json.extensions.pinned_extensions -and ($json.extensions.pinned_extensions -contains $EXT_ID)) {
                $json.extensions.pinned_extensions = @($json.extensions.pinned_extensions | Where-Object { $_ -ne $EXT_ID })
                $touched = $true
            }
            if ($json.extensions -and $json.extensions.toolbar -and ($json.extensions.toolbar -contains $EXT_ID)) {
                $json.extensions.toolbar = @($json.extensions.toolbar | Where-Object { $_ -ne $EXT_ID })
                $touched = $true
            }
            if ($touched) {
                ($json | ConvertTo-Json -Depth 100 -Compress) | Set-Content -LiteralPath $prefPath -Encoding UTF8 -NoNewline
                Write-Ok "$($b.Name) $name : scrubbed"
            }
        } catch {
            Write-Err "$($b.Name) $name : $($_.Exception.Message)"
        }
    }
}

# Also clear secondary extension caches (Local Extension Settings, Sync, etc.)
Write-Step "Deleting secondary extension caches"
foreach ($b in $browsers) {
    foreach ($sub in 'Local Extension Settings','Sync Extension Settings','Extension State','Extension Scripts','Extension Rules') {
        $f = Join-Path $b.UserData "$sub\$EXT_ID"
        if (Test-Path $f) {
            try { Remove-Item $f -Recurse -Force -ErrorAction Stop; Write-Ok "$($b.Name): removed $sub\$EXT_ID" }
            catch { Write-Err "$($b.Name): $sub - $($_.Exception.Message)" }
        }
    }
}

if ($NoRestart) {
    Write-Step "Done - browser not restarted (-NoRestart)"
    Write-Ok "Launch Edge/Chrome yourself; forcelist will pull the latest CRX."
    return
}

Write-Step "Relaunching browser(s)"
foreach ($b in $browsers) {
    $exe = if ($b.Name -eq 'Edge') {
        'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
    } else {
        @(
            "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
            'C:\Program Files\Google\Chrome\Application\chrome.exe',
            'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
        ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if (-not $exe -or -not (Test-Path $exe)) {
        Write-Warn "$($b.Name): exe not found, skipping launch"
        continue
    }
    Start-Process -FilePath $exe | Out-Null
    Write-Ok "$($b.Name): launched"
}

Write-Step "Done"
Write-Ok "Browser launched. Forcelist policy will pull the latest CRX within ~30s."
Write-Ok "Check progress at edge://extensions / chrome://extensions (Developer mode on)."
