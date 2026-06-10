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

.WARNING (2026-06-10 incident)
    A second profile-loss event: Chrome's Local State (the JSON registry
    at <User Data>\Local State -- one level above \Default) ended up
    reset to a near-empty form during a flush run, and Chrome forgot
    every profile even though every Profile NN\ folder was still intact
    on disk. The script doesn't write to Local State, but surrounding
    Chromium machinery does (auto-recovery on unparseable Preferences,
    etc.). Root cause wasn't reproducible.

    Defense-in-depth now lives in the script itself: EVERY run makes a
    timestamped Local State.bak.<ts> copy of both browsers' registry
    BEFORE touching any extension folder. If the picker ever comes back
    empty after a relaunch, just copy that .bak file over the broken
    Local State and reopen Chrome -- 30-second recovery.

    The backup step refuses to proceed if it can't write the .bak; that
    is intentional. A flush that can't be undone is not worth running.

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
$EXT_ID    = 'eheocihmlppcophaeakmdenhgcookkab'
$UPDATE_URL = 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Step { param([string]$Msg) Write-Host "`n>> $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "   $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "   $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "   $Msg" -ForegroundColor Red }

# ============================================================================
# Compliance pre-flight: minimum machine config required for the
# ExtensionInstallForcelist install/update path to actually work.
# ============================================================================
# We check exactly the keys Chromium consults on launch. If any are
# missing, we print the gap with a remediation hint and continue --
# the operator may be running this on an unmanaged dev box and that's
# fine; the goal is to surface WHY a flush isn't taking effect, not
# to block the run.
function Test-PimActivatorCompliance {
    Write-Step "Compliance check: machine config for ExtensionInstallForcelist"
    $expectedValue = "$EXT_ID;$UPDATE_URL"
    Write-Host ("   Expected forcelist value: {0}" -f $expectedValue) -ForegroundColor Cyan
    Write-Host ("   Expected ext id        : {0}" -f $EXT_ID) -ForegroundColor Cyan
    Write-Host ("   Expected update URL    : {0}" -f $UPDATE_URL) -ForegroundColor Cyan
    $rows = @()
    $browsers = @(
        @{ Name='Edge';   ForcelistKeys=@('HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist','HKCU:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist') ; BlocklistKeys=@('HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist','HKCU:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist'); AllowlistKeys=@('HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist','HKCU:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist') },
        @{ Name='Chrome'; ForcelistKeys=@('HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist','HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist')   ; BlocklistKeys=@('HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist','HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist'); AllowlistKeys=@('HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist','HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist') }
    )
    $anyMissing = $false
    foreach ($b in $browsers) {
        # 1) Forcelist entry present anywhere (HKLM or HKCU) with our ext id + update url?
        $forcelistEntry = $null
        foreach ($k in $b.ForcelistKeys) {
            if (-not (Test-Path $k)) { continue }
            foreach ($p in (Get-Item $k).Property) {
                $v = (Get-ItemProperty $k -Name $p).$p
                if ($v -like "*$EXT_ID*") { $forcelistEntry = @{ Path=$k; Value=$v }; break }
            }
            if ($forcelistEntry) { break }
        }
        if ($forcelistEntry) {
            $urlOk = $forcelistEntry.Value -like "*$UPDATE_URL*"
            $rows += [pscustomobject]@{ Browser=$b.Name; Check='Forcelist entry'; State='OK'; Detail="$($forcelistEntry.Path -replace '^HKLM:\\SOFTWARE\\Policies\\','HKLM\') (URL match: $urlOk)" }
            if (-not $urlOk) {
                $rows += [pscustomobject]@{ Browser=$b.Name; Check='Forcelist URL'; State='WARN'; Detail="Update URL differs from expected: $UPDATE_URL  (got: $($forcelistEntry.Value))" }
                $anyMissing = $true
            }
        } else {
            $rows += [pscustomobject]@{ Browser=$b.Name; Check='Forcelist entry'; State='MISSING'; Detail="Add REG_SZ value to $($b.ForcelistKeys[0]) with name='1' and data='$expectedValue'" }
            $anyMissing = $true
        }
        # 2) Blocklist sanity: is the extension explicitly blocked, OR is there a '*' block-everything entry?
        $blockedExplicit = $false; $blockAll = $false
        foreach ($k in $b.BlocklistKeys) {
            if (-not (Test-Path $k)) { continue }
            foreach ($p in (Get-Item $k).Property) {
                $v = (Get-ItemProperty $k -Name $p).$p
                if ($v -eq '*')       { $blockAll = $true }
                if ($v -eq $EXT_ID)   { $blockedExplicit = $true }
            }
        }
        if ($blockedExplicit) {
            $rows += [pscustomobject]@{ Browser=$b.Name; Check='Blocklist'; State='FAIL'; Detail="Extension explicitly blocked (remove $EXT_ID from ExtensionInstallBlocklist)" }
            $anyMissing = $true
        } elseif ($blockAll) {
            # If a '*' block is in place the extension must be in the allowlist OR forcelist (forcelist overrides).
            $rows += [pscustomobject]@{ Browser=$b.Name; Check='Blocklist'; State='INFO'; Detail="ExtensionInstallBlocklist = '*' (every extension blocked); forcelist still bypasses this for $EXT_ID" }
        } else {
            $rows += [pscustomobject]@{ Browser=$b.Name; Check='Blocklist'; State='OK'; Detail='Extension not blocked' }
        }
    }
    # 3) gh-pages updates.xml reachable + advertises our extension id
    try {
        $r = Invoke-WebRequest -Uri $UPDATE_URL -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        if ($r.StatusCode -eq 200 -and $r.Content -like "*$EXT_ID*") {
            # Use a tight regex on <updatecheck ... version='X.Y.Z' /> so we
            # don't accidentally pick up the XML declaration's version='1.0'.
            if ($r.Content -match "<updatecheck\b[^>]*\bversion\s*=\s*['""]([^'""]+)['""]") {
                $rows += [pscustomobject]@{ Browser='*'; Check='gh-pages updates.xml'; State='OK'; Detail="reachable, advertises v$($Matches[1])" }
            } else {
                $rows += [pscustomobject]@{ Browser='*'; Check='gh-pages updates.xml'; State='OK'; Detail='reachable, references extension id (version not parseable)' }
            }
        } else {
            $rows += [pscustomobject]@{ Browser='*'; Check='gh-pages updates.xml'; State='WARN'; Detail="HTTP $($r.StatusCode), body does not reference $EXT_ID" }
            $anyMissing = $true
        }
    } catch {
        $rows += [pscustomobject]@{ Browser='*'; Check='gh-pages updates.xml'; State='FAIL'; Detail="Unreachable: $($_.Exception.Message)" }
        $anyMissing = $true
    }
    # Render
    $rows | ForEach-Object {
        $line = ('   [{0,-7}] {1,-7} {2,-22} {3}' -f $_.State, $_.Browser, $_.Check, $_.Detail)
        switch ($_.State) {
            'OK'      { Write-Host $line -ForegroundColor Green }
            'INFO'    { Write-Host $line -ForegroundColor Cyan  }
            'WARN'    { Write-Host $line -ForegroundColor Yellow }
            'FAIL'    { Write-Host $line -ForegroundColor Red }
            'MISSING' { Write-Host $line -ForegroundColor Red }
        }
    }
    if ($anyMissing) {
        Write-Warn "One or more compliance gaps above -- the cache-flush + relaunch may not produce an install/update until they're fixed."
        Write-Host  ""
        Write-Host  "   Quick-fix PowerShell (run elevated; sets HKLM forcelist for Edge + Chrome):" -ForegroundColor Cyan
        Write-Host  "     foreach (`$p in 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist','HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist') {" -ForegroundColor White
        Write-Host  "         if (-not (Test-Path `$p)) { New-Item -Path `$p -Force | Out-Null }" -ForegroundColor White
        Write-Host  ("         New-ItemProperty -Path `$p -Name '1' -PropertyType String -Value '{0}' -Force | Out-Null" -f $expectedValue) -ForegroundColor White
        Write-Host  "     }" -ForegroundColor White
        Write-Host  ""
        Write-Warn "Or run Deploy-PimActivatorClient.ps1 (handles Edge + Chrome + Tenant Catalog), or assign the Intune profile '[PimActivator] All-in-one ...' to this device's group."
    } else {
        Write-Ok "All compliance checks passed -- forcelist install/update path is wired correctly."
    }
}

# Run the check up front so the operator sees the machine state BEFORE any
# destructive op. This is read-only and very fast (<1s on a healthy box).
Test-PimActivatorCompliance

# ============================================================================
# Live CRX signing-key sanity check.
# ============================================================================
# 2026-06-10 incident: gh-pages was serving a CRX signed with a different
# key than what the ExtensionInstallForcelist policy expects. Chromium
# silently rejected every update, so the whole fleet froze at the last
# version installed with the correct key. We didn't know until we deleted
# the cached binary on a box, which produced ERR_FILE_NOT_FOUND because
# the registered extension's files were gone and no replacement could
# install.
#
# Catching this BEFORE we flush turns a "fleet bricked" outcome into a
# "rerun aborted, no harm done". We download the live CRX, derive its
# embedded extension id (SHA256 of the v3 header, first 16 bytes,
# remapped from 0-15 -> 'a'-'p' per Chromium's id encoding), and refuse
# to proceed if it doesn't match the policy id.
function Test-CrxSigningKey {
    # Pull the codebase URL out of updates.xml so we always probe the
    # actual CRX the forcelist is pointing at (not a hardcoded URL).
    try {
        $u = Invoke-WebRequest -Uri $UPDATE_URL -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    } catch {
        Write-Warn "Could not fetch updates.xml ($UPDATE_URL): $($_.Exception.Message). Skipping CRX signing-key check."
        return
    }
    if ($u.Content -notmatch "<updatecheck\b[^>]*\bcodebase\s*=\s*['""]([^'""]+)['""]") {
        Write-Warn "Could not parse codebase URL out of updates.xml. Skipping CRX signing-key check."
        return
    }
    $crxUrl = $Matches[1]
    $crxTmp = Join-Path $env:TEMP "pim-activator-probe.crx"
    try {
        Invoke-WebRequest -Uri $crxUrl -OutFile $crxTmp -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
    } catch {
        Write-Warn "Could not download CRX from $crxUrl. Skipping signing-key check."
        return
    }
    # CORRECT CRX id derivation (replaced an earlier buggy version on 2026-06-10
    # that hashed the whole CrxFileHeader -- which produced a number unrelated
    # to the canonical Chromium id and caused a false-alarm cascade during the
    # wrong-key recovery). The canonical Chromium id is:
    #
    #   SHA256( first AsymmetricKeyProof.public_key field ).Substring(0, 16)
    #   mapped from nibbles 0..15 to characters 'a'..'p'.
    #
    # We parse the protobuf header manually: scan for field 2 (sha256_with_rsa)
    # with wire_type 2 (length-delimited), descend into the AsymmetricKeyProof
    # submessage, find field 1 (public_key, wire_type 2), and hash THOSE bytes.
    $bytes = [System.IO.File]::ReadAllBytes($crxTmp)
    $magic = -join ($bytes[0..3] | ForEach-Object { [char]$_ })
    $ver   = [System.BitConverter]::ToUInt32($bytes, 4)
    if ($magic -ne 'Cr24' -or $ver -lt 3) {
        Write-Warn "CRX at $crxUrl is not a v3 (or higher) CRX -- can't derive id. magic=$magic, version=$ver"
        return
    }
    $hdrLen  = [System.BitConverter]::ToUInt32($bytes, 8)
    $endIx   = 12 + $hdrLen
    $i       = 12
    $publicKey = $null
    while ($i -lt $endIx -and -not $publicKey) {
        # Read outer field tag (varint)
        $tag = 0; $shift = 0
        while ($i -lt $endIx) {
            $x = $bytes[$i]; $tag = $tag -bor (($x -band 0x7F) -shl $shift); $i++
            if (($x -band 0x80) -eq 0) { break }
            $shift += 7
        }
        $fieldNum = $tag -shr 3
        $wireType = $tag -band 7
        if ($fieldNum -eq 2 -and $wireType -eq 2) {
            # sha256_with_rsa AsymmetricKeyProof message; read length-delimited body
            $msgLen = 0; $shift = 0
            while ($i -lt $endIx) {
                $x = $bytes[$i]; $msgLen = $msgLen -bor (($x -band 0x7F) -shl $shift); $i++
                if (($x -band 0x80) -eq 0) { break }
                $shift += 7
            }
            $msgEnd = $i + $msgLen
            while ($i -lt $msgEnd -and -not $publicKey) {
                # Inner field tag
                $itag = 0; $shift = 0
                while ($i -lt $msgEnd) {
                    $x = $bytes[$i]; $itag = $itag -bor (($x -band 0x7F) -shl $shift); $i++
                    if (($x -band 0x80) -eq 0) { break }
                    $shift += 7
                }
                $iField = $itag -shr 3
                $iWire  = $itag -band 7
                if ($iField -eq 1 -and $iWire -eq 2) {
                    # public_key bytes
                    $keyLen = 0; $shift = 0
                    while ($i -lt $msgEnd) {
                        $x = $bytes[$i]; $keyLen = $keyLen -bor (($x -band 0x7F) -shl $shift); $i++
                        if (($x -band 0x80) -eq 0) { break }
                        $shift += 7
                    }
                    $publicKey = $bytes[$i..($i + $keyLen - 1)]
                    $i += $keyLen
                } else {
                    # Skip unknown inner field
                    if ($iWire -eq 2) {
                        $skipLen = 0; $shift = 0
                        while ($i -lt $msgEnd) {
                            $x = $bytes[$i]; $skipLen = $skipLen -bor (($x -band 0x7F) -shl $shift); $i++
                            if (($x -band 0x80) -eq 0) { break }
                            $shift += 7
                        }
                        $i += $skipLen
                    } elseif ($iWire -eq 0) {
                        while ($i -lt $msgEnd) { $x = $bytes[$i]; $i++; if (($x -band 0x80) -eq 0) { break } }
                    } else { break }
                }
            }
        } else {
            # Skip unknown outer field
            if ($wireType -eq 2) {
                $skipLen = 0; $shift = 0
                while ($i -lt $endIx) {
                    $x = $bytes[$i]; $skipLen = $skipLen -bor (($x -band 0x7F) -shl $shift); $i++
                    if (($x -band 0x80) -eq 0) { break }
                    $shift += 7
                }
                $i += $skipLen
            } elseif ($wireType -eq 0) {
                while ($i -lt $endIx) { $x = $bytes[$i]; $i++; if (($x -band 0x80) -eq 0) { break } }
            } else { break }
        }
    }
    if (-not $publicKey) {
        Write-Warn "Could not extract public_key from CRX header. Skipping signing-key check."
        return
    }
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($publicKey)
    $sb   = [System.Text.StringBuilder]::new()
    foreach ($byte in $hash[0..15]) {
        $hi = ($byte -shr 4) -band 0xF
        $lo = $byte -band 0xF
        [void]$sb.Append([char](97 + $hi))
        [void]$sb.Append([char](97 + $lo))
    }
    $derived = $sb.ToString()
    Write-Step "Verifying gh-pages CRX signing key matches the policy-registered extension id"
    Write-Host ("   CRX URL                : {0}" -f $crxUrl) -ForegroundColor Cyan
    Write-Host ("   Derived extension id   : {0}" -f $derived) -ForegroundColor Cyan
    Write-Host ("   Policy-registered id   : {0}" -f $EXT_ID) -ForegroundColor Cyan
    if ($derived -eq $EXT_ID) {
        Write-Ok "CRX signing key matches the registered extension id. Updates will install correctly."
        return $true
    } else {
        Write-Err "CRX SIGNING KEY MISMATCH -- the CRX on gh-pages is signed with a key that derives id '$derived', NOT '$EXT_ID'."
        Write-Err "Chromium will silently reject every update from this CRX. Flushing the cached binary on a box will BRICK the installed instance"
        Write-Err "(registered extension files deleted, replacement install blocked -> ERR_FILE_NOT_FOUND on icon click)."
        return $false
    }
}
# We DON'T call Test-CrxSigningKey here at top level -- pack/repack mode is
# the recovery path for a wrong-key gh-pages CRX, and a top-level throw would
# block the very command that fixes the situation. The check runs from inside
# the flush section instead, so it gates the destructive cache delete only.

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

    # PRE-PACK GUARD (added 2026-06-10 after the wrong-key CRX bricked
    # the update path for the whole fleet). Compute the extension id that
    # WOULD result from packing with this local key, and refuse to pack
    # if it doesn't match the policy-registered EXT_ID. Stops a wrong-key
    # CRX from EVER reaching gh-pages, which is the only way to keep
    # already-installed instances upgrading.
    Write-Step "Pre-pack guard: verifying local signing key derives the correct extension id"
    $derivedFromLocalKey = $null
    try {
        $pem = [System.IO.File]::ReadAllText($keyPath)
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $rsa.ImportFromPem($pem) | Out-Null
        $pubDer = $rsa.ExportSubjectPublicKeyInfo()
        $hash   = [System.Security.Cryptography.SHA256]::Create().ComputeHash($pubDer)
        $sb     = [System.Text.StringBuilder]::new()
        foreach ($byte in $hash[0..15]) {
            $hi = ($byte -shr 4) -band 0xF
            $lo = $byte -band 0xF
            [void]$sb.Append([char](97 + $hi))
            [void]$sb.Append([char](97 + $lo))
        }
        $derivedFromLocalKey = $sb.ToString()
    } catch {
        throw "Could not derive extension id from local signing key at '$keyPath': $($_.Exception.Message). Refusing to pack."
    }
    Write-Host ("   Key path                : {0}" -f $keyPath) -ForegroundColor Cyan
    Write-Host ("   Derived extension id    : {0}" -f $derivedFromLocalKey) -ForegroundColor Cyan
    Write-Host ("   Policy-registered id    : {0}" -f $EXT_ID) -ForegroundColor Cyan
    if ($derivedFromLocalKey -ne $EXT_ID) {
        Write-Err "WRONG SIGNING KEY -- this key produces id '$derivedFromLocalKey', NOT '$EXT_ID'."
        Write-Err "Packing with this key and pushing to gh-pages would brick the entire fleet's update path"
        Write-Err "(every installed instance is registered against '$EXT_ID' and would silently reject a CRX with any other id)."
        throw "Pack aborted. The signing key at '$keyPath' is not the master key. Recover the correct '$EXT_ID' key from another machine / backup / Key Vault before re-running -Repack or -PackOnly."
    }
    Write-Ok "Local signing key matches the policy-registered extension id. Safe to pack."

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

# 2026-06-10: $browsers entries now carry BOTH UserDataRoot (one level up;
# holds Local State + all profile folders) AND UserData (= Default profile,
# for backward compat with the destructive opt-in paths that still target a
# single profile). All non-opt-in flush operations are now applied across
# EVERY profile folder under UserDataRoot, not just Default -- the 25+ Chrome
# profile case revealed the previous Default-only behaviour was misleading.
$browsers = switch ($Browser) {
    'Edge'   { @(@{Name='Edge';   ExeName='msedge'; UserDataRoot="$env:LOCALAPPDATA\Microsoft\Edge\User Data"; UserData="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"}) }
    'Chrome' { @(@{Name='Chrome'; ExeName='chrome'; UserDataRoot="$env:LOCALAPPDATA\Google\Chrome\User Data"; UserData="$env:LOCALAPPDATA\Google\Chrome\User Data\Default"}) }
    'Both'   { @(
        @{Name='Edge';   ExeName='msedge'; UserDataRoot="$env:LOCALAPPDATA\Microsoft\Edge\User Data"; UserData="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"},
        @{Name='Chrome'; ExeName='chrome'; UserDataRoot="$env:LOCALAPPDATA\Google\Chrome\User Data"; UserData="$env:LOCALAPPDATA\Google\Chrome\User Data\Default"}
    ) }
}

# Helper: enumerate every profile folder for a browser (Default + Profile N).
function Get-BrowserProfiles($userDataRoot) {
    if (-not (Test-Path -LiteralPath $userDataRoot)) { return @() }
    Get-ChildItem -LiteralPath $userDataRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(Default|Profile \d+)$' }
}

Write-Step "Closing browser processes (graceful first, force-kill only stragglers)"
# 2026-06-10 root-cause analysis of the Local State reset:
# Chrome rewrites Local State (the profile registry) constantly --
# every profile switch, every new tab in another profile, every
# extension state update, plus a periodic flush. A bare
# `Stop-Process -Force` can land mid-write, leaving Local State
# truncated. On next launch Chromium falls back to its documented
# "Local State unparseable -> regenerate with single Default entry"
# recovery path -- exactly the symptom we saw (59 Profile NN\ folders
# on disk, picker shows only Default).
#
# Fix: ask main windows to close politely first (CloseMainWindow ->
# WM_CLOSE), wait up to 10s for the whole browser tree to exit so
# Local State + all per-profile Preferences flush, THEN force-kill
# any straggler renderers / GPU / utility processes that ignored
# the close request. End result: same "no Chrome running" outcome
# as before, without the in-flight-write corruption window.
foreach ($b in $browsers) {
    $procs = @(Get-Process $b.ExeName -ErrorAction SilentlyContinue)
    if (-not $procs) { Write-Warn "$($b.Name): not running"; continue }
    $initialPids = @($procs | ForEach-Object { $_.Id })
    $initialCount = $initialPids.Count
    # Step 1: WM_CLOSE every main window we can find (only the browser
    # process has a main window; renderers / GPU / utility procs don't).
    foreach ($p in $procs) {
        try { if ($p.MainWindowHandle -ne 0) { [void]$p.CloseMainWindow() } } catch {}
    }
    # Step 2: poll-wait up to 10s for the ORIGINAL processes to exit.
    # New child processes can spawn during the wait (renderers for
    # background pages, etc.), so we explicitly track the initial PID set
    # -- not the total proc count -- to know whether the graceful close
    # finished its job.
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        $stillFromInitial = @(Get-Process -Id $initialPids -ErrorAction SilentlyContinue)
        if ($stillFromInitial.Count -eq 0) { break }
        Start-Sleep -Milliseconds 300
    }
    $stillFromInitial = @(Get-Process -Id $initialPids -ErrorAction SilentlyContinue)
    $gracefullyClosed = $initialCount - $stillFromInitial.Count

    # Step 3: kill anything still running (both original stragglers and
    # any newly-spawned procs). These are renderers / GPU / utility --
    # they don't touch Local State, so force-kill is safe.
    $allStillRunning = @(Get-Process $b.ExeName -ErrorAction SilentlyContinue)
    if ($allStillRunning) {
        $allStillRunning | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Ok ("$($b.Name): graceful-closed $gracefullyClosed of $initialCount original (renderers exit when parent dies); force-killed $($allStillRunning.Count) remaining proc(s)")
    } else {
        Write-Ok "$($b.Name): graceful-closed all $initialCount process(es), nothing left to kill"
    }
}
# Extra settle time so the OS finishes the per-process file-handle release
# before we start deleting extension folders.
Start-Sleep -Seconds 3

# ============================================================================
# DEFENSE-IN-DEPTH: ALWAYS back up Local State (the profile registry) before
# touching anything else.
# ============================================================================
# 2026-06-10 incident: Local State (the JSON file at
# <UserData>\..\Local State -- one level ABOVE \Default) got reset to a
# near-empty form during a flush run, causing Chrome to forget all 59
# profiles even though every Profile NN\ folder was still on disk. The
# script itself doesn't write to Local State, but the surrounding
# Chromium machinery does (auto-recovery if Preferences is unparseable,
# extension state changes triggering rewrites, etc.). The exact trigger
# wasn't reproducible, so we add an unconditional safety net here:
# timestamped copy of Local State for both browsers BEFORE we touch
# anything destructive. Restore in seconds if the picker comes back
# empty after relaunch.
Write-Step "Backing up Local State (profile registry) -- defense-in-depth"
foreach ($b in $browsers) {
    $localState   = Join-Path $b.UserDataRoot 'Local State'
    if (Test-Path -LiteralPath $localState) {
        $stamp  = (Get-Date).ToString('yyyyMMddHHmmss')
        $backup = "$localState.bak.$stamp"
        try {
            Copy-Item -LiteralPath $localState -Destination $backup -Force -ErrorAction Stop
            Write-Ok "$($b.Name): Local State backed up to Local State.bak.$stamp ($((Get-Item $localState).Length) bytes)"
        } catch {
            Write-Err "$($b.Name): could NOT back up Local State: $($_.Exception.Message)"
            throw "Aborting -- refusing to proceed without a Local State backup. Fix the error above and rerun."
        }
    } else {
        Write-Warn "$($b.Name): no Local State file at $localState (fresh install?)"
    }
}

# Pure brace-counting JSON property removal. Same shape as
# Fix-PimActivatorStuck.ps1 / Reset-CorruptedExtensions.ps1 -- no PS 5.1
# ConvertTo-Json round-trip, so the 2026-06-09 profile-corruption footgun
# cannot fire. Removes every JSON occurrence of "<EXT_ID>": ... (object,
# array, string, or scalar value) plus swallows one comma so the result
# stays valid JSON. Returns the count of entries removed.
function Remove-JsonExtensionEntry {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $text = [System.IO.File]::ReadAllText($Path, $utf8)
    $orig = $text
    $removed = 0
    $key = '"' + $EXT_ID + '":'
    while ($true) {
        $s = $text.IndexOf($key)
        if ($s -lt 0) { break }
        $vs = $s + $key.Length
        while ($vs -lt $text.Length -and [char]::IsWhiteSpace($text[$vs])) { $vs++ }
        if ($vs -ge $text.Length) { break }
        $ch = $text[$vs]
        $endIdx = -1
        if ($ch -eq '{' -or $ch -eq '[') {
            $open  = $ch; $close = if ($open -eq '{') { '}' } else { ']' }
            $depth = 1; $i = $vs + 1
            while ($depth -gt 0 -and $i -lt $text.Length) {
                $c = $text[$i]
                if ($c -eq '"') { $i++; while ($i -lt $text.Length -and $text[$i] -ne '"') { if ($text[$i] -eq '\') { $i++ }; $i++ } }
                elseif ($c -eq $open) { $depth++ } elseif ($c -eq $close) { $depth-- }
                $i++
            }
            $endIdx = $i
        } elseif ($ch -eq '"') {
            $i = $vs + 1
            while ($i -lt $text.Length -and $text[$i] -ne '"') { if ($text[$i] -eq '\') { $i++ }; $i++ }
            $endIdx = $i + 1
        } else {
            $i = $vs; while ($i -lt $text.Length -and $text[$i] -notin @(',','}',']')) { $i++ }
            $endIdx = $i
        }
        if ($endIdx -lt 0) { break }
        $cs = $s; $ce = $endIdx
        $j = $cs - 1; while ($j -ge 0 -and [char]::IsWhiteSpace($text[$j])) { $j-- }
        if ($j -ge 0 -and $text[$j] -eq ',') { $cs = $j }
        else {
            $k = $ce; while ($k -lt $text.Length -and [char]::IsWhiteSpace($text[$k])) { $k++ }
            if ($k -lt $text.Length -and $text[$k] -eq ',') { $ce = $k + 1 }
        }
        $text = $text.Substring(0, $cs) + $text.Substring($ce)
        $removed++
    }
    if ($removed -gt 0 -and $text -ne $orig) {
        $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
        Copy-Item -LiteralPath $Path -Destination "$Path.bak.$stamp" -Force
        [System.IO.File]::WriteAllText($Path, $text, $utf8)
    }
    return $removed
}

Write-Step "Deleting cached extension binaries + stale Secure Preferences registration (across ALL profiles)"
foreach ($b in $browsers) {
    $profiles = @(Get-BrowserProfiles $b.UserDataRoot)
    if (-not $profiles) { Write-Warn "$($b.Name): no profile folders found under $($b.UserDataRoot)"; continue }
    $hit = 0; $miss = 0; $prefsCleared = 0
    foreach ($profile in $profiles) {
        $path = Join-Path $profile.FullName "Extensions\$EXT_ID"
        $deletedThisProfile = $false
        if (Test-Path -LiteralPath $path) {
            try {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
                Write-Ok "$($b.Name) [$($profile.Name)]: removed cached extension"
                $hit++
                $deletedThisProfile = $true
            } catch {
                Write-Err "$($b.Name) [$($profile.Name)]: failed - $($_.Exception.Message)"
            }
        } else {
            $miss++
        }
        # 2026-06-10 (v2.4.103): UNCONDITIONAL scrub of stale Preferences +
        # Secure Preferences registrations -- not gated on whether the on-disk
        # extension folder was found. The v2.4.100 fix only scrubbed when the
        # binary was deleted, but the trap shape is the opposite: profiles can
        # have STALE registration entries WITHOUT a cached binary (Chrome
        # already self-removed the corrupted folder but kept the registration
        # with disable_reasons=1024 DISABLE_CORRUPTED, refusing forcelist
        # retry). Those profiles report 'no Extensions\<id> folder yet' which
        # looked like 'nothing to do' to v2.4.100 -- but they were exactly the
        # ones blocking install. Now we always sweep. Pure string surgery,
        # no JSON round-trip, .bak files written before any rewrite.
        $n = 0
        $n += (Remove-JsonExtensionEntry -Path (Join-Path $profile.FullName 'Preferences'))
        $n += (Remove-JsonExtensionEntry -Path (Join-Path $profile.FullName 'Secure Preferences'))
        if ($n -gt 0) {
            Write-Ok "$($b.Name) [$($profile.Name)]: cleared $n stale registration entries from (Secure )Preferences"
            $prefsCleared += $n
        }
    }
    Write-Ok "$($b.Name): scanned $($profiles.Count) profile(s) -- removed cache from $hit, none present in $miss, registration entries scrubbed: $prefsCleared"
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
# across ALL profiles -- multi-profile fix 2026-06-10.
Write-Step "Deleting secondary extension caches (across ALL profiles)"
foreach ($b in $browsers) {
    $profiles = @(Get-BrowserProfiles $b.UserDataRoot)
    foreach ($profile in $profiles) {
        foreach ($sub in 'Local Extension Settings','Sync Extension Settings','Extension State','Extension Scripts','Extension Rules') {
            $f = Join-Path $profile.FullName "$sub\$EXT_ID"
            if (Test-Path -LiteralPath $f) {
                try { Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction Stop; Write-Ok "$($b.Name) [$($profile.Name)]: removed $sub" }
                catch { Write-Err "$($b.Name) [$($profile.Name)]: $sub - $($_.Exception.Message)" }
            }
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

Write-Step "Verifying extension install across ALL profiles (polling up to 120s per browser)"
# Chromium's first extension-update poll after launch is gated by an
# initial startup delay (kExtensionUpdaterStartupDelaySeconds, default
# ~60s) BEFORE --extensions-update-frequency kicks in. So we wait + poll
# instead of declaring victory the instant the browser process spawns.
# Per-profile verification: report what version is installed in EACH
# profile folder, so the multi-profile case (where some profiles update
# fast and others lag) is visible.
$expectedVersion = $null
try {
    $r = Invoke-WebRequest -Uri $UPDATE_URL -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    if ($r.Content -match "<updatecheck\b[^>]*\bversion\s*=\s*['""]([^'""]+)['""]") {
        $expectedVersion = $Matches[1]
        Write-Ok "Expected version (per gh-pages updates.xml): $expectedVersion"
    }
} catch {}

foreach ($b in $browsers) {
    $profiles = @(Get-BrowserProfiles $b.UserDataRoot)
    if (-not $profiles) { Write-Warn "$($b.Name): no profile folders to verify"; continue }
    Write-Ok "$($b.Name): verifying $($profiles.Count) profile(s) ..."
    $deadline = (Get-Date).AddSeconds(120)
    $profileStatus = @{}   # profileName -> installed version (string) or $null
    foreach ($profile in $profiles) { $profileStatus[$profile.Name] = $null }

    while ((Get-Date) -lt $deadline) {
        $allDone = $true
        foreach ($profile in $profiles) {
            if ($profileStatus[$profile.Name] -and ($profileStatus[$profile.Name] -eq $expectedVersion -or -not $expectedVersion)) { continue }
            $extDir = Join-Path $profile.FullName "Extensions\$EXT_ID"
            if (Test-Path -LiteralPath $extDir) {
                $vf = Get-ChildItem -LiteralPath $extDir -Directory -ErrorAction SilentlyContinue |
                    Sort-Object { try { [version]($_.Name -replace '_\d+$','') } catch { [version]'0.0.0' } } -Descending |
                    Select-Object -First 1
                if ($vf) {
                    $profileStatus[$profile.Name] = ($vf.Name -replace '_\d+$','')
                }
            }
            if (-not $profileStatus[$profile.Name] -or ($expectedVersion -and $profileStatus[$profile.Name] -ne $expectedVersion)) { $allDone = $false }
        }
        if ($allDone) { break }
        Start-Sleep -Seconds 3
    }

    # Render per-profile results
    $upgraded = 0; $stale = 0; $missing = 0
    foreach ($profile in $profiles) {
        $installed = $profileStatus[$profile.Name]
        if (-not $installed) {
            Write-Warn ("  [{0,-12}] {1,-18} MISSING (no Extensions\<id> folder yet)" -f $b.Name, $profile.Name)
            $missing++
        } elseif ($expectedVersion -and $installed -eq $expectedVersion) {
            Write-Ok   ("  [{0,-12}] {1,-18} v{2}  OK" -f $b.Name, $profile.Name, $installed)
            $upgraded++
        } else {
            Write-Warn ("  [{0,-12}] {1,-18} v{2}  STALE (expected v{3})" -f $b.Name, $profile.Name, $installed, $expectedVersion)
            $stale++
        }
    }
    Write-Ok ("$($b.Name): {0} up-to-date, {1} stale, {2} missing (of {3} profile(s))" -f $upgraded, $stale, $missing, $profiles.Count)

    if ($stale -gt 0 -or $missing -gt 0) {
        $schemeName = if ($b.Name -eq 'Edge') { 'edge' } else { 'chrome' }
        Write-Warn "$($b.Name): some profiles still not on $expectedVersion. Diagnostics:"
        Write-Warn "  -> Open $schemeName`://policy and verify ExtensionInstallForcelist shows '$EXT_ID;$UPDATE_URL' (status should be 'OK' not 'Error')."
        Write-Warn "  -> Open $schemeName`://extensions inside a stale profile, Developer mode ON, click 'Update' to force a poll right now."
        Write-Warn "  -> Open $schemeName`://net-export to capture the gh-pages CRX download attempt (look for 'pim-activator.crx' in the trace)."
    }
}

Write-Step "Done"
Write-Ok "If verification passed above, the extension is installed and at the version reported."
Write-Ok "Open edge://extensions / chrome://extensions (Developer mode on) to see the live version chip."
