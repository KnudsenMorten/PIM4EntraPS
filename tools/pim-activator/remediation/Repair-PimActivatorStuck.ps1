#Requires -Version 5.1
<#
.SYNOPSIS
    Intune DEVICE REMEDIATION -- remediation half. Clears the stale PIM Activator entries from a
    browser's own preference files so the ExtensionInstallForcelist policy reinstalls the current
    CRX cleanly.

.DESCRIPTION
    Pairs with Detect-PimActivatorStuck.ps1; read that file's header for the measurement behind it.
    The one-line version: FRESH INSTALLS LAND, UPDATES DO NOT. Proven 2026-09-04 -- on one laptop,
    in one browser, under one policy, the extension that arrived as a new install was current
    (1.6.124) while the one sitting there since June was not (1.6.25). Purging the stale entries
    and reopening the browser brought BOTH channels to 1.6.124 within a minute.

    ✅ ROOT CAUSE FOUND 2026-09-04: the extension never carried its own `update_url`, so the
    browsers had nothing to poll. v1.6.126 adds it; mgmt1 then self-updated 1.6.126 -> 1.6.127 in
    40-180s with no purge. This script is therefore a ONE-TIME MIGRATION for copies predating
    1.6.126 (which have no pointer and stay stuck no matter what is published), not standing
    infrastructure. See Detect-PimActivatorStuck.ps1 for the controlled experiment.

    🔑 WHY A REPUBLISH ALONE DOES NOT RESCUE A PRE-1.6.126 COPY. Everything server-side verifies: the CRX3
    signature is valid, its key derives to the extension id the forcelist installs, the embedded
    version matches updates.xml. The package was never wrong, so shipping a NEWER package sends it
    down the same path that already failed to deliver for ten weeks. The stale state is local, so
    the fix has to run locally -- which is exactly what a remediation is for.

    🪤 WHAT THIS DELIBERATELY DOES NOT DO: kill the user's browser.
    Doing that on one machine you own is fine. Doing it on 10,000 is a fleet-wide interruption, and
    an update that has already waited ten weeks can wait for the next time the browser is closed.
    So: if the browser is RUNNING, this exits non-zero WITHOUT touching anything, and Intune simply
    retries on its next cycle -- catching the device at logon, after a reboot, or overnight. Pass
    -Force only for an attended run where you accept the interruption.
    (It also has to be this way to be correct, not just polite: Chrome rewrites its preference
    files from memory on exit, so a purge performed while it is running would be undone.)

    🪤 SECURE PREFERENCES IS HMAC-PROTECTED, AND THAT IS FINE HERE. Removing an entry invalidates
    that entry's MAC, so Chrome discards it as tampered on next start -- which is precisely the
    outcome wanted: the extension is treated as absent and the forcelist installs it fresh. Every
    file is backed up beside itself first.

.NOTES
    Intune remediation convention: exit 0 = remediated, non-zero = not remediated (retry later).
    Runs in SYSTEM context by default -- see -UserDataRoots for how per-user profiles are found.
#>
[CmdletBinding()]
param(
    [string[]]$ExtensionIds = @('eheocihmlppcophaeakmdenhgcookkab','glldnbmjpdkjemcnficagdhgienfdpoo'),
    # Close running browsers instead of deferring. NOT for fleet use -- see the header.
    [switch]$Force,
    # Explicit roots, for testing. Empty = discover every user profile on the box, which is what a
    # SYSTEM-context remediation needs (it is not running as the person whose browser is stuck).
    [string[]]$UserDataRoots = @()
)

$ErrorActionPreference = 'Stop'
function Say($m){ Write-Output $m }

# ---- 1. locate every browser User Data root on the device ------------------------------------
$roots = New-Object System.Collections.Generic.List[string]
if ($UserDataRoots.Count) {
    foreach ($r in $UserDataRoots) { if (Test-Path -LiteralPath $r) { $roots.Add($r) } }
} else {
    foreach ($u in (Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue)) {
        foreach ($rel in 'AppData\Local\Google\Chrome\User Data','AppData\Local\Microsoft\Edge\User Data') {
            $p = Join-Path $u.FullName $rel
            if (Test-Path -LiteralPath $p) { $roots.Add($p) }
        }
    }
}
if (-not $roots.Count) { Say 'no browser User Data roots on this device -- nothing to do'; exit 0 }

# ---- 2. refuse to run while the browser is up (see header) -----------------------------------
$running = @(Get-Process chrome,msedge -ErrorAction SilentlyContinue)
if ($running.Count -and -not $Force) {
    Say ("DEFERRED: {0} browser process(es) running; a purge would be overwritten when the browser writes its prefs on exit. Will retry next cycle." -f $running.Count)
    exit 2
}
if ($running.Count -and $Force) {
    Say ("-Force: closing {0} browser process(es)" -f $running.Count)
    $running | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}

# ---- 3. purge the extension's entries from every profile's preference files -------------------
$stamp    = Get-Date -Format 'yyyyMMddHHmmss'
$scanned  = 0
$removed  = 0
$touched  = New-Object System.Collections.Generic.List[string]

foreach ($root in $roots) {
    $profiles = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })
    foreach ($p in $profiles) {
        foreach ($file in 'Preferences','Secure Preferences') {
            $fp = Join-Path $p.FullName $file
            if (-not (Test-Path -LiteralPath $fp)) { continue }
            $scanned++
            try {
                $raw = Get-Content -LiteralPath $fp -Raw -ErrorAction Stop
                if (-not $raw.Trim()) { continue }
                $json = $raw | ConvertFrom-Json -ErrorAction Stop
            } catch { Say ("  skip (unreadable): {0}" -f $fp); continue }

            $hit = 0
            foreach ($id in $ExtensionIds) {
                # extensions.settings.<id> is the install record. Removing it is what makes the
                # browser treat the extension as absent, so the forcelist installs it fresh.
                $settings = $null
                if ($json.PSObject.Properties['extensions']) { $settings = $json.extensions.PSObject.Properties['settings'] }
                if ($settings -and $json.extensions.settings.PSObject.Properties[$id]) {
                    $json.extensions.settings.PSObject.Properties.Remove($id); $hit++
                }
                # the pending/external install bookkeeping, which can also pin a stale version
                foreach ($branch in 'pending_extension_installs','external_extensions') {
                    if ($json.PSObject.Properties['extensions'] -and $json.extensions.PSObject.Properties[$branch] `
                        -and $json.extensions.$branch.PSObject.Properties[$id]) {
                        $json.extensions.$branch.PSObject.Properties.Remove($id); $hit++
                    }
                }
            }
            if ($hit -gt 0) {
                $bak = "$fp.bak.$stamp"
                Copy-Item -LiteralPath $fp -Destination $bak -Force
                # -Depth 100: Chrome's prefs nest deeply and ConvertTo-Json SILENTLY TRUNCATES past
                # its default of 2, which would write a wrecked prefs file back over a working one.
                ($json | ConvertTo-Json -Depth 100 -Compress) | Set-Content -LiteralPath $fp -Encoding UTF8 -NoNewline
                $removed += $hit
                $touched.Add($fp)
                Say ("  purged {0} entr(ies) from {1}\{2}  (backup: {3})" -f $hit, (Split-Path $root -Leaf), $p.Name, (Split-Path $bak -Leaf))
            }
        }
    }
}

Say ''
Say ("Profiles files scanned : {0}" -f $scanned)
Say ("Entries removed        : {0}" -f $removed)
if ($removed -eq 0) { Say 'nothing stale found -- the device was already clean'; exit 0 }
Say 'Reopen the browser: the forcelist reinstalls the current CRX from gh-pages within ~60s.'
exit 0
