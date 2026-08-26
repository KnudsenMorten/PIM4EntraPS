#Requires -Version 5.1
<#
.SYNOPSIS
    IMP-02 -- the locale-safe reader for machine-written UTC stamps (PIM-DateSafe.ps1),
    plus a whole-source sweep proving no shipped file has gone back to a bare
    [datetime]::Parse / ::TryParse on an ambient culture.

    §22 requires locale-safe date parsing. Ensure-DateTime does that for USER-supplied
    dates, but 26 sites read stamps THIS PRODUCT wrote (always ToString('o')) with the
    ambient culture. BUG-02 was that class: a lease whose expiry could not be parsed was
    treated as FREE, letting two schedulers run at once.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $solRoot 'engine\_shared\PIM-DateSafe.ps1')

Write-Host "=== PIM-DateSafe (IMP-02 locale-safe stamps) ===" -ForegroundColor Cyan

$known = [datetime]::SpecifyKind([datetime]'2026-06-17T09:30:00', [System.DateTimeKind]::Utc)

# --- the round-trip that matters: what we write, we must read ------------------
Assert "reads back a ToString('o') stamp exactly" ((Get-PimUtcStamp $known.ToString('o')) -eq $known)
Assert "reads a plain Z stamp"                    ((Get-PimUtcStamp '2026-06-17T09:30:00Z') -eq $known)
Assert "result is UTC kind"                       ((Get-PimUtcStamp $known.ToString('o')).Kind -eq [System.DateTimeKind]::Utc)
# an offset stamp must be NORMALISED to UTC, not taken at face value
Assert "a +02:00 offset is converted to UTC"      ((Get-PimUtcStamp '2026-06-17T11:30:00+02:00') -eq $known)

# --- unreadable input returns $null, and NEVER throws --------------------------
foreach ($bad in @($null, '', '   ', 'not-a-date', '2026-13-45T99:99:99Z', '2026-06-17T12:')) {
    $shown = if ($null -eq $bad) { '<null>' } else { "'$bad'" }
    $threw = $false; $r = 'x'
    try { $r = Get-PimUtcStamp $bad } catch { $threw = $true }
    Assert "unreadable $shown -> `$null, no throw" ((-not $threw) -and ($null -eq $r))
}

# --- the actual IMP-02 bug: ambient culture ------------------------------------
# On da-DK a bare [datetime]::TryParse can misread or fail on a stamp the product
# itself wrote. Prove the helper is stable across cultures with a date whose day and
# month are BOTH valid but different (03/04) -- the case where a locale-sensitive
# parse silently returns the WRONG date rather than failing.
$prev = [System.Threading.Thread]::CurrentThread.CurrentCulture
try {
    foreach ($c in @('da-DK', 'en-US', 'de-DE')) {
        [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo($c)
        $got = Get-PimUtcStamp '2026-03-04T00:00:00Z'
        Assert "[$c] ISO stamp reads as 4 March (not 3 April)" ($got.Month -eq 3 -and $got.Day -eq 4)
        Assert "[$c] round-trips the stamp we wrote"           ((Get-PimUtcStamp $known.ToString('o')) -eq $known)
    }
} finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $prev }

# --- no shipped file may go back to a bare ambient-culture parse ---------------
# This is the anti-regression half: the fix is only durable if a NEW bare parse fails
# the suite. Sites that pass an explicit CultureInfo are fine -- that is the fix, not
# the defect -- and PIM-Functions.psm1 owns Ensure-DateTime, the deliberate ladder.
Write-Host "`n-- no bare ambient-culture parses in shipped source --" -ForegroundColor Cyan
$exempt = @('PIM-Functions.psm1', 'PIM-DateSafe.ps1', 'PIM-ApprovalGate.ps1')
$offenders = New-Object System.Collections.Generic.List[string]
foreach ($dir in @('engine', 'tools', 'config')) {
    $p = Join-Path $solRoot $dir
    if (-not (Test-Path -LiteralPath $p)) { continue }
    foreach ($f in Get-ChildItem -LiteralPath $p -Recurse -File -Include '*.ps1','*.psm1' -EA SilentlyContinue) {
        if ($exempt -contains $f.Name) { continue }
        $n = 0
        foreach ($line in ([System.IO.File]::ReadAllText($f.FullName) -split "`n")) {
            $n++
            if ($line -match '^\s*#') { continue }                       # a comment, not code
            if ($line -notmatch '\[datetime\]::(Try)?Parse') { continue }
            if ($line -match 'CultureInfo') { continue }                 # explicit culture = the fix
            $rel = $f.FullName.Substring($solRoot.Length).TrimStart('\', '/')
            $offenders.Add("${rel}:${n}")
        }
    }
}
foreach ($o in $offenders) { Write-Host "    BARE PARSE: $o" -ForegroundColor Red }
Assert "no shipped file parses a date with the ambient culture ($($offenders.Count) found)" ($offenders.Count -eq 0)

# Guard the guard: the sweep must be able to see a bare parse at all.
$decoy = '$x = [datetime]::TryParse($s, [ref]$d)'
Assert "the sweep would flag a bare parse (not a tautology)" (
    ($decoy -match '\[datetime\]::(Try)?Parse') -and ($decoy -notmatch 'CultureInfo'))

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
