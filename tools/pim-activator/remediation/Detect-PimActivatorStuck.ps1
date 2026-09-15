#Requires -Version 5.1
<#
.SYNOPSIS
    Intune DEVICE REMEDIATION -- detection half. Exit 1 when a browser profile on this device
    carries a PIM Activator install that is STUCK below the required version.

.DESCRIPTION
    🔴 WHY THIS EXISTS. Measured 2026-09-04 across two managed machines:

      laptop  PROD 1.6.25  (2026-06-10)   TEST 1.6.124   <- TEST was a FRESH install
      mgmt1   PROD 1.6.122 (2026-06-25)   TEST 1.6.122   <- neither took the 26 Jun release

    1.6.124 was published 2026-06-26 and NO existing install anywhere had moved to it, on either
    channel, for ten weeks -- while the browsers demonstrably ran in that window (Chrome's Local
    State was rewritten 10 Aug, Edge's 1 Sep). Everything server-side checked out: the CRX3
    signature verifies, its key derives to the very extension id the forcelist installs, the
    version inside the CRX matches updates.xml, and it is served as application/x-chrome-extension.

    🔑 The distinction that matters: FRESH INSTALLS LAND, UPDATES DO NOT. The laptop proved it --
    same browser, same policy mechanism, same gh-pages host: the extension that arrived as a new
    install was current, the one that had been sitting there since June was not. The fix that
    worked was purging the extension's stale entries from the browser's own preference files and
    letting the forcelist reinstall it clean.

    ✅ ROOT CAUSE FOUND 2026-09-04, AND IT IS NOT WHAT THIS SCRIPT ORIGINALLY ASSUMED.
    The extension never carried its own `update_url`. Policy force-install worked every time --
    that path takes the URL from the POLICY -- but auto-update needs the pointer in the
    extension's OWN manifest, and it was empty in every installed copy (verified in Secure
    Preferences: update_url='' on both browsers, both channels, location=7). So the browsers had
    nothing to poll and never checked. Ten weeks, two machines, zero updates.

    v1.6.126 added `"update_url"` to manifest.json. Controlled experiment on mgmt1 -- same
    machine, same policy, same host, same browsers, only that one variable changed:

        1.6.126 -> 1.6.127 self-updated with NO purge and no forced check
        Edge   ~40s      Chrome ~180s      both channels

    🪤 SO WHAT IS THIS SCRIPT STILL FOR? A ONE-TIME MIGRATION, not standing infrastructure.
    A copy that predates 1.6.126 has no pointer to self-update WITH, so it stays stuck no matter
    what is published -- the original reasoning holds, but only for those. Once a device reaches
    1.6.126+ it maintains itself and never needs this again. Run it to clear the backlog, then
    retire it; leaving it scheduled forever would imply the class is still open when it is closed.

.NOTES
    Intune remediation convention: exit 0 = healthy (do nothing), exit 1 = remediate.
    Read-only. Touches nothing. Safe to schedule as often as you like.
#>
[CmdletBinding()]
param(
    # The floor. A profile carrying LESS than this is reported as stuck.
    # 🪤 Name a version you have PUBLISHED and confirmed installable -- this drives a remediation
    # that deletes local extension state, so pointing it at a version the update URL cannot serve
    # would churn every device on every cycle and never converge.
    [string]$RequiredVersion = '1.6.125',
    # Both channels. They are independent extensions with independent ids and both can stick.
    [string[]]$ExtensionIds = @('eheocihmlppcophaeakmdenhgcookkab','glldnbmjpdkjemcnficagdhgienfdpoo')
)

$ErrorActionPreference = 'Stop'

function Compare-ExtVersion {
    # Chrome compares each dotted component NUMERICALLY, not as text: 1.6.124 is NEWER than
    # 1.6.25 even though it sorts earlier as a string. Getting this wrong would report every
    # healthy machine as stuck (and, worse, every stuck one as healthy).
    param([string]$Left,[string]$Right)
    $l = @($Left  -split '\.' | ForEach-Object { [int]($_ -replace '\D','0') })
    $r = @($Right -split '\.' | ForEach-Object { [int]($_ -replace '\D','0') })
    for ($i=0; $i -lt [Math]::Max($l.Count,$r.Count); $i++) {
        $a = if ($i -lt $l.Count) { $l[$i] } else { 0 }
        $b = if ($i -lt $r.Count) { $r[$i] } else { 0 }
        if ($a -lt $b) { return -1 }
        if ($a -gt $b) { return 1 }
    }
    return 0
}

# 🔴 ENUMERATE EVERY USER PROFILE, NOT $env:LOCALAPPDATA.
# An Intune remediation runs as SYSTEM by default, and SYSTEM's LOCALAPPDATA is
# C:\Windows\System32\config\systemprofile\AppData\Local -- which contains no browser profile at
# all. A detection built on $env:LOCALAPPDATA therefore finds nothing under SYSTEM and reports
# every device HEALTHY, which is a fleet-wide false negative that looks exactly like success.
# (Caught before deployment 2026-09-04: the REMEDIATION half already walked C:\Users, so the two
# halves of the same pair disagreed about where browser profiles live.)
# Walking C:\Users makes this correct in BOTH contexts -- as SYSTEM it sees every user, and as a
# logged-on user it still sees that user's own profile.
$roots = New-Object System.Collections.Generic.List[string]
foreach ($u in (Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue)) {
    foreach ($rel in 'AppData\Local\Google\Chrome\User Data','AppData\Local\Microsoft\Edge\User Data') {
        $p = Join-Path $u.FullName $rel
        if (Test-Path -LiteralPath $p) { $roots.Add($p) }
    }
}

$stuck = New-Object System.Collections.Generic.List[string]
foreach ($root in $roots) {
    # Every profile, not just Default. The laptop had 46 of them; a per-profile stale entry in any
    # one of them is a stuck install for whoever uses that profile.
    $profiles = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })
    foreach ($p in $profiles) {
        foreach ($id in $ExtensionIds) {
            $extDir = Join-Path $p.FullName "Extensions\$id"
            if (-not (Test-Path -LiteralPath $extDir)) { continue }
            $vers = @(Get-ChildItem -LiteralPath $extDir -Directory -ErrorAction SilentlyContinue |
                      ForEach-Object { ($_.Name -split '_')[0] })
            if (-not $vers.Count) { continue }
            # The HIGHEST present version is what the browser will run, so that is what to judge.
            $best = $vers[0]
            foreach ($v in $vers) { if ((Compare-ExtVersion $v $best) -gt 0) { $best = $v } }
            if ((Compare-ExtVersion $best $RequiredVersion) -lt 0) {
                # 🪤 Name the BROWSER and the CHANNEL, not "User Data\Default". Both Chrome and
                # Edge roots end in "User Data", so the first version of this line reported four
                # identical-looking rows and an operator reading the Intune report could not tell
                # which browser -- or which channel -- was actually stuck.
                $browser = if ($root -match 'Microsoft\\Edge') { 'Edge' } elseif ($root -match 'Google\\Chrome') { 'Chrome' } else { 'Browser' }
                $channel = if ($id -eq 'glldnbmjpdkjemcnficagdhgienfdpoo') { 'TEST' } else { 'PROD' }
                # Name the USER as well: one device carries a profile per account, and "Default"
                # on its own does not say whose. Under SYSTEM this is the only way to tell them
                # apart, and it is what makes the Intune report actionable.
                # 🪤 Derive the user from the PATH, not by counting .Parent hops. Counting hops is
                # off-by-one-prone (the first attempt printed "AppData" as the username) and it
                # silently breaks if a browser ever nests its User Data one level deeper.
                $who = if ($root -match '(?i)\\Users\\([^\\]+)\\') { $Matches[1] } else { '?' }
                $stuck.Add(("{0}/{1} {2}\{3} : {4} (< {5})" -f $browser, $channel, $who, $p.Name, $best, $RequiredVersion))
            }
        }
    }
}

if ($stuck.Count -gt 0) {
    # Intune surfaces stdout in the remediation report, so say WHICH profile and WHICH version --
    # "stuck" with no version is a finding nobody can act on or verify afterwards.
    Write-Output ("PIM Activator STUCK below {0} in {1} profile-install(s): {2}" -f `
        $RequiredVersion, $stuck.Count, (($stuck | Select-Object -First 8) -join ' | '))
    exit 1
}

Write-Output "PIM Activator OK (no install below $RequiredVersion)"
exit 0
