#Requires -Version 5.1
<#
.SYNOPSIS
    Trigger a PIM Activator extension update on the local browser.

    Core purpose: make Edge / Chrome pick up the latest CRX from GitHub
    Pages NOW, instead of waiting hours for Chromium's default update
    poll. The forcelist policy (ExtensionInstallForcelist) is what
    actually installs / refreshes the extension; this script just
    convinces the browser to run that update check immediately.

    Two modes:

    1. Default (no flags)  -> evict the cached extension binary
                              (<UserData>\Extensions\<EXT_ID>), then
                              relaunch the browser with the Chromium
                              update flags --extensions-update-frequency=30
                              so the forcelist update kicks within ~30s.
                              No Preferences / Secure Preferences /
                              Service Worker touching -- profile data
                              is left fully intact.

    2. -Repack             -> also bumps the patch version, repacks the
                              CRX, pushes pim-activator.crx + updates.xml
                              to the gh-pages branch, THEN runs the
                              flush + restart. End-to-end "make my
                              browser show the latest code" in one
                              command.

    Built for iterations 0.4.2 -> 0.4.3 -> 0.4.4 -> ... where you don't
    want to manually kill processes, evict the cached CRX, wait hours
    for the update poll, etc.

.WARNING (2026-06-09 incident)
    Earlier versions of this script ran TWO destructive actions on every
    "flush" invocation: (1) rewrote <profile>\Preferences + Secure
    Preferences via a PS 5.1 ConvertFrom-Json / ConvertTo-Json round-trip,
    and (2) deleted <profile>\Service Worker. At least one device lost
    its entire Edge profile (bookmarks, history, saved tabs, sign-ins)
    because the JSON round-trip corrupted Preferences and Chromium reset
    the profile on next launch.

    Neither is necessary to trigger an extension update -- the cached
    binary evict + fast-poll relaunch (default path above) does that on
    its own. Both destructive paths are now OPT-IN behind explicit
    switches and should normally never be used:
      -DangerouslyPatchPreferences   (the JSON rewrite)
      -DangerouslyWipeServiceWorker  (the SW dir delete)

    A casual re-run can no longer destroy profile data.

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
    .\Update-PimActivator-Extension.ps1

.EXAMPLE
    # I edited popup.js, bump version + push CRX + flush my browser. Full loop.
    .\Update-PimActivator-Extension.ps1 -Repack

.EXAMPLE
    # CI-style: pack + push but don't touch my running browser.
    .\Update-PimActivator-Extension.ps1 -PackOnly

.NOTES
    Maintainer-only -- iterates the published CRX during development.
    Customer-facing scripts:
      Deploy-PimActivatorBackend.ps1 -- creates the per-tenant Entra app
        registration + grants admin consent (one-time per tenant).
      Deploy-PimActivatorClient.ps1  -- pushes the ExtensionInstallForcelist
        policy to user machines (one-time per machine / fleet).
    Tenant config (tenantId + clientId) is no longer pushed via this
    script -- the in-popup onboarding wizard captures it per browser
    profile on first run.
#>

[CmdletBinding()]
param(
    [switch]$Repack,
    [switch]$PackOnly,
    [string]$Version,                # set exact manifest version (e.g. 1.0.0) instead of patch bump
    [ValidateSet('Edge','Chrome','Both')]
    [string]$Browser = 'Both',
    [switch]$NoRestart,
    [string]$GhPagesDir = (Join-Path $env:LOCALAPPDATA 'PimActivatorPages'),
    # ----- DESTRUCTIVE opt-in flags (DEFAULT: OFF) -----
    # 2026-06-09 -- earlier versions of this script ran both of these by
    # default during a "flush" run, and at least one device lost the entire
    # Edge profile (bookmarks / history / saved tabs reset) because the
    # PS 5.1 JSON round-trip in DangerouslyPatchPreferences corrupted the
    # Preferences file. Both are now opt-in and gated behind explicit
    # switches so a casual re-run can never destroy profile data again.
    [switch]$DangerouslyPatchPreferences,   # JSON-rewrite Preferences + Secure Preferences -- CAN BRICK A PROFILE
    [switch]$DangerouslyWipeServiceWorker   # delete <profile>\Service Worker -- evicts SW registrations for ALL extensions/sites
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

    # ---- Repack CRX ---------------------------------------------------------
    Write-Step "Repacking CRX"
    $edgeExe = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
    if (-not (Test-Path $edgeExe)) {
        $edgeExe = 'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
    }
    if (-not (Test-Path $edgeExe)) { throw "msedge.exe not found" }

    $keyPath = "$env:USERPROFILE\.pim-activator\signing-key.pem"
    if (-not (Test-Path $keyPath)) { throw "signing key missing: $keyPath" }

    # v1.2.0+: no config.js / config.template.js swap. The extension no
    # longer has a baked-in config -- the in-popup onboarding wizard is the
    # only source of tenant id / client id (per browser profile).

    # msedge cannot pack while a running instance holds the source dir.
    Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2

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

# ============================================================================
# Preferences / Secure Preferences JSON rewrite
# ============================================================================
# DESTRUCTIVE -- opt-in only (-DangerouslyPatchPreferences).
#
# 2026-06-09 incident: this block ran by default in every "flush" run.
# PowerShell 5.1's `ConvertTo-Json -Depth 100 -Compress` round-trip is
# unreliable for the Edge/Chrome Preferences shape (Unicode, deeply
# nested objects, integer/number type drift). The corruption produced a
# file Edge/Chrome could not parse on next launch -- Chromium then
# silently RESETS the entire profile to defaults, losing bookmarks,
# history, saved tabs, signed-in accounts, etc.
#
# The original purpose was solving a v0.4.x dev-loop quirk where Secure
# Preferences cached a path to a deleted extension version folder. The
# extension-binary cleanup at line ~234 already covers that path.
# Preferences rewrite is no longer needed for the normal flush.
#
# Pass -DangerouslyPatchPreferences ONLY when you specifically need to
# scrub the extensions.settings.<id> + protection.macs.extensions.* keys
# (the dev-iteration use case) AND you have backups of the profile.
if ($DangerouslyPatchPreferences) {
    Write-Warn "DangerouslyPatchPreferences set -- writing Preferences JSON. Profile data can be lost if the JSON round-trip drops content."
    Write-Step "Patching Preferences JSON (settings + HMACs + pin/toolbar)"
    foreach ($b in $browsers) {
        foreach ($name in 'Preferences','Secure Preferences') {
            $prefPath = Join-Path $b.UserData $name
            if (-not (Test-Path $prefPath)) { continue }
            # Belt-and-braces: timestamped backup of the raw bytes BEFORE we
            # touch the file. If our rewrite corrupts it, the operator can
            # restore from the .bak.<ts> sidecar.
            try {
                $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
                Copy-Item -LiteralPath $prefPath -Destination "$prefPath.bak.$stamp" -Force -ErrorAction Stop
                Write-Ok "$($b.Name) $name : backup saved as $name.bak.$stamp"
            } catch {
                Write-Err "$($b.Name) $name : could NOT create backup -- aborting rewrite to be safe. $($_.Exception.Message)"
                continue
            }
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
} else {
    Write-Warn "Skipping Preferences JSON rewrite (default since 2026-06-09 -- pass -DangerouslyPatchPreferences to opt in)"
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

# ============================================================================
# MV3 Service Worker registration cache wipe
# ============================================================================
# DESTRUCTIVE -- opt-in only (-DangerouslyWipeServiceWorker).
#
# Chromium stores service-worker registration metadata + the cached SW
# script bytes under `<profile>\Service Worker\`. This dir is SHARED
# across every extension AND every website in the profile -- removing
# it forces every other extension/site to re-register its SW on next
# launch. In addition, in some profile configurations this dir contains
# transient state that other Chromium subsystems depend on; wiping it
# has been correlated with profile-data oddities post-launch.
#
# 2026-06-09: made opt-in alongside the Preferences rewrite, since both
# were running together by default during the same flush run that
# caused the profile loss. The extension-binary delete at line ~234 is
# usually enough to make Chrome pull the latest CRX on next launch.
if ($DangerouslyWipeServiceWorker) {
    Write-Warn "DangerouslyWipeServiceWorker set -- wiping <profile>\Service Worker. ALL extensions + sites re-register their SWs."
    Write-Step "Nuking MV3 Service Worker registration cache"
    foreach ($b in $browsers) {
        $swDir = Join-Path $b.UserData 'Service Worker'
        if (Test-Path $swDir) {
            try {
                Remove-Item $swDir -Recurse -Force -ErrorAction Stop
                Write-Ok "$($b.Name): removed $swDir (all SW registrations evicted; will re-register on next launch)"
            } catch {
                Write-Err "$($b.Name): Service Worker dir - $($_.Exception.Message)"
            }
        } else {
            Write-Warn "$($b.Name): no Service Worker dir to evict"
        }
    }
} else {
    Write-Warn "Skipping Service Worker dir wipe (default since 2026-06-09 -- pass -DangerouslyWipeServiceWorker to opt in)"
}

if ($NoRestart) {
    Write-Step "Done - browser not restarted (-NoRestart)"
    Write-Ok "Launch Edge/Chrome yourself; forcelist will pull the latest CRX."
    return
}

Write-Step "Relaunching browser(s) with fast-update-poll flag"
# --extensions-update-frequency=30 tells Chromium to poll every extension's
# update_url every 30 seconds (default is 5 hours). Without this flag, the
# forcelist update kicks "eventually" -- often not at all during a 1-min
# dev iteration. With it, the new CRX from gh-pages lands within ~30s of
# launch. The flag only affects extension update cadence -- no profile
# data is touched.
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
    Start-Process -FilePath $exe -ArgumentList '--extensions-update-frequency=30' | Out-Null
    Write-Ok "$($b.Name): launched (--extensions-update-frequency=30)"
}

Write-Step "Done"
Write-Ok "Browser launched. Forcelist policy will pull the latest CRX within ~30s."
Write-Ok "Check progress at edge://extensions / chrome://extensions (Developer mode on)."
Write-Ok "If it doesn't appear: open edge://extensions, enable Developer mode, click 'Update'."
