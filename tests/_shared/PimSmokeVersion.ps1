#Requires -Version 5.1
<#
.SYNOPSIS
    PURE, offline-testable helpers for the post-deploy hosted-smoke SERVED-VERSION
    check (used by tests/live/Test-PimManagerHostedSmoke.ps1).

.DESCRIPTION
    The hosted smoke must assert the LIVE Manager is serving the EXPECTED version
    (SOLUTIONS/PIM4EntraPS/VERSION). The original gate derived the served version
    ONLY from Log Analytics boot logs (ContainerAppConsoleLogs_CL). LA ingestion
    LAGS: right after a container roll the new revision is live + healthy, but its
    boot "[version]" line has not yet landed in LA -- so the gate read the PRIOR
    revision's version and emitted a FALSE FAILURE on a healthy deploy (the 2.4.229
    roll). The integrity requirement is unchanged: a live container genuinely
    running the WRONG version MUST still FAIL.

    These helpers are PURE -- they take the "get log text" call as an injected
    scriptblock (the codebase's standard pattern for testable fetchers), so the
    parse + compare + retry decision can be unit-tested offline with NO live az.

    Two functions:
      * Get-PimSmokeServedVersion  -- extract the MOST RECENT
            "[version] PIM Manager v<X.Y.Z>" from a blob of log text. Returns the
            version string, or $null when no version line is present.
      * Resolve-PimSmokeVersionCheck -- the full decision: invoke the injected
            log-fetcher, parse, compare to Expected, and RETRY WITH BACKOFF while the
            parse is empty/blank (a slow-booting replica that has not logged yet) OR
            (optionally) while it is stale-but-not-yet-fresh. Returns a result object
            { Ok; Found; Reason; Attempts } with NO host writes (pure), so it is
            deterministic to unit-test.

    DECISION CONTRACT (integrity-preserving):
      * Found == Expected on ANY attempt  -> Ok=$true  (PASS) immediately.
      * Found is empty/absent on an attempt -> RETRY (a replica that has not logged
        its boot line yet must not false-fail). After all attempts still empty ->
        Ok=$false (FAIL -- a healthy current image ALWAYS emits the line; absence
        means we could not prove the running version, which is NOT a pass).
      * Found is a CONCRETE-but-WRONG version -> RETRY (covers the LA-lag case where
        an early read returns the PRIOR revision's still-ingesting line) and on the
        FINAL attempt, if it is STILL the wrong concrete version, Ok=$false (FAIL --
        a live container genuinely running the wrong version must fail the gate).

    The retry loop sleeps via an injected -Sleep scriptblock so tests run instantly
    (default sleeps for real in production). PowerShell 5.1 safe -- no ?. / ?? .
#>

# Extract the newest "[version] PIM Manager v<X.Y.Z>" version from log text.
# $LogText may be a single multi-line string or an array of lines. Returns the
# version string (e.g. '2.4.229') or $null if no version line is present.
# "Newest" = we scan top-to-bottom and the caller is expected to pass log rows
# ordered newest-first (as the LA query / live-log tail does); the FIRST match
# wins. If order is unknown, every match is the same image anyway.
function Get-PimSmokeServedVersion {
    [CmdletBinding()]
    param([Parameter(Mandatory=$false)] $LogText)

    if ($null -eq $LogText) { return $null }
    # Normalise to a single string (accept string OR array of lines).
    if ($LogText -is [array]) { $text = ($LogText -join "`n") } else { $text = [string]$LogText }
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }

    # Split to lines and take the FIRST line that carries a version (newest-first input).
    $lines = $text -split "`r?`n"
    foreach ($line in $lines) {
        $m = [regex]::Match([string]$line, '\[version\]\s*PIM Manager\s*v?([0-9]+\.[0-9]+\.[0-9]+)')
        if ($m.Success) { return $m.Groups[1].Value }
    }
    return $null
}

# Full served-version decision with retry/backoff. PURE: all I/O is injected.
#
#   -GetLogText   scriptblock returning the log text for one attempt (live console
#                 logs of the active revision, or the LA fallback). Called once per
#                 attempt. Should return $null/'' when nothing is available yet.
#   -ExpectedVersion  the VERSION-file value the live Manager must be serving.
#   -MaxAttempts  total tries (default 5).
#   -DelaySeconds backoff seconds between tries (default 15 -> ~60s over 5 tries).
#   -Sleep        scriptblock invoked with the seconds to wait (injected so tests
#                 don't actually sleep). Default = Start-Sleep.
#
# Returns a PSCustomObject:
#   Ok        [bool]   $true only if a read proved Found == ExpectedVersion.
#   Found     [string] the last concrete version parsed (or '' if none ever).
#   Reason    [string] human-readable outcome (for the smoke's PASS/FAIL line).
#   Attempts  [int]    how many fetches were made.
function Resolve-PimSmokeVersionCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][scriptblock]$GetLogText,
        [Parameter(Mandatory=$false)][string]$ExpectedVersion,
        [Parameter(Mandatory=$false)][int]$MaxAttempts = 5,
        [Parameter(Mandatory=$false)][int]$DelaySeconds = 15,
        [Parameter(Mandatory=$false)][scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }
    )

    if ($MaxAttempts -lt 1) { $MaxAttempts = 1 }

    if ([string]::IsNullOrWhiteSpace($ExpectedVersion)) {
        return [pscustomobject]@{
            Ok       = $false
            Found    = ''
            Reason   = 'could not read SOLUTIONS/PIM4EntraPS/VERSION (no expected version to compare)'
            Attempts = 0
        }
    }
    $expected = $ExpectedVersion.Trim()

    $lastFound = ''
    $attempts  = 0
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        $attempts = $i
        $text = $null
        try { $text = & $GetLogText $i } catch { $text = $null }

        $found = Get-PimSmokeServedVersion -LogText $text
        if ($found) { $lastFound = $found }

        if ($found -and ($found -eq $expected)) {
            return [pscustomobject]@{
                Ok       = $true
                Found    = $found
                Reason   = ("served version v{0} matches VERSION (attempt {1}/{2})" -f $found, $i, $MaxAttempts)
                Attempts = $attempts
            }
        }

        # Not a match yet. If more attempts remain, back off and retry -- this is
        # what makes both the LA-lag (stale concrete version) and slow-boot (no
        # version line yet) cases self-heal instead of false-failing.
        if ($i -lt $MaxAttempts) {
            if ($DelaySeconds -gt 0 -and $Sleep) { try { & $Sleep $DelaySeconds } catch {} }
            continue
        }
    }

    # Exhausted all attempts without a match. Distinguish the two failure shapes
    # for an actionable message -- but BOTH are a FAIL (never a silent pass).
    if (-not $lastFound) {
        return [pscustomobject]@{
            Ok       = $false
            Found    = ''
            Reason   = ("expected v{0}; NO [version] line found after {1} attempt(s) -- replica never logged its boot version (stale/un-booted image?)" -f $expected, $attempts)
            Attempts = $attempts
        }
    }
    return [pscustomobject]@{
        Ok       = $false
        Found    = $lastFound
        Reason   = ("live Manager serving v{0} but VERSION expects v{1} after {2} attempt(s) -- deploy did NOT roll the image" -f $lastFound, $expected, $attempts)
        Attempts = $attempts
    }
}
