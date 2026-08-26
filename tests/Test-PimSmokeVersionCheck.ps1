#Requires -Version 5.1
<#
.SYNOPSIS
    Offline unit tests for the post-deploy hosted-smoke SERVED-VERSION check
    (tests/_shared/PimSmokeVersion.ps1). NO live az, NO tenant -- pure helpers.

.DESCRIPTION
    Proves the LA-lag-resilient version gate is correct AND integrity-preserving:
      1. Correct version in (live) log text         -> PASS.
      2. Stale-then-fresh across retries            -> PASS after retry
         (the LA-ingestion-lag / slow-roll case: first read returns the PRIOR
         revision's version, a later read returns the new one).
      3. Genuinely-wrong version on EVERY read       -> FAIL (the gate must still
         fail when the live container really runs the wrong version).
      4. Empty / no-version log on every read        -> FAIL (never a silent pass).
    Plus parse-helper edge cases and the "no expected version" guard.

    The retry loop's Sleep is injected as a no-op so the suite runs instantly.

        powershell -NoProfile -File .\tests\Test-PimSmokeVersionCheck.ps1
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_shared\PimSmokeVersion.ps1')

$pass=0; $fail=0
function T($n,$c){ if($c){Write-Host "  PASS $n" -ForegroundColor Green;$script:pass++}else{Write-Host "  FAIL $n" -ForegroundColor Red;$script:fail++} }

# No-op sleep so retries don't actually wait during the unit test.
$noSleep = { param($s) }

Write-Host "=== PIM hosted-smoke served-version check (offline unit tests) ===" -ForegroundColor Cyan

# --- Get-PimSmokeServedVersion: parse correctness --------------------------
$logFresh = @"
2026-06-18T10:00:01 some other line
2026-06-18T10:00:02   [version] PIM Manager v2.4.229 (from VERSION)
2026-06-18T10:00:03 listening on ...
"@
T 'parse: extracts version from a boot-log line'        ((Get-PimSmokeServedVersion -LogText $logFresh) -eq '2.4.229')
T 'parse: returns newest (first) when multiple present' ((Get-PimSmokeServedVersion -LogText "[version] PIM Manager v2.4.229`n[version] PIM Manager v2.4.228") -eq '2.4.229')
T 'parse: accepts an array of lines'                    ((Get-PimSmokeServedVersion -LogText @('noise','[version] PIM Manager v1.2.3')) -eq '1.2.3')
T 'parse: $null log -> $null'                           ($null -eq (Get-PimSmokeServedVersion -LogText $null))
T 'parse: empty/whitespace log -> $null'                ($null -eq (Get-PimSmokeServedVersion -LogText "   `n  "))
T 'parse: no version line -> $null'                     ($null -eq (Get-PimSmokeServedVersion -LogText "just boot noise, no version here"))

# --- (1) correct version in live-log text -> PASS --------------------------
$r1 = Resolve-PimSmokeVersionCheck -GetLogText { param($a) $logFresh } -ExpectedVersion '2.4.229' -MaxAttempts 5 -DelaySeconds 0 -Sleep $noSleep
T '(1) correct version -> Ok=$true'        ($r1.Ok -eq $true)
T '(1) correct version -> Found=2.4.229'   ($r1.Found -eq '2.4.229')
T '(1) correct version -> 1 attempt'       ($r1.Attempts -eq 1)

# --- (2) stale-then-fresh across retries -> PASS after retry ---------------
# First two reads return the PRIOR revision (LA still ingesting); the 3rd read
# returns the rolled version. The gate must PASS, on attempt 3, NOT false-fail.
$script:calls = 0
$staleThenFresh = {
    param($a)
    $script:calls++
    if ($script:calls -lt 3) { return "[version] PIM Manager v2.4.228 (from VERSION)" }  # prior revision (lagging)
    return "[version] PIM Manager v2.4.229 (from VERSION)"                                # new revision
}
$r2 = Resolve-PimSmokeVersionCheck -GetLogText $staleThenFresh -ExpectedVersion '2.4.229' -MaxAttempts 5 -DelaySeconds 0 -Sleep $noSleep
T '(2) stale-then-fresh -> Ok=$true (self-heals)'  ($r2.Ok -eq $true)
T '(2) stale-then-fresh -> resolved on attempt 3'  ($r2.Attempts -eq 3)
T '(2) stale-then-fresh -> Found=2.4.229'          ($r2.Found -eq '2.4.229')

# --- (2b) empty-then-fresh (slow-booting replica) -> PASS after retry ------
$script:calls2 = 0
$emptyThenFresh = {
    param($a)
    $script:calls2++
    if ($script:calls2 -lt 2) { return "" }   # replica hasn't logged its boot line yet
    return "[version] PIM Manager v2.4.229 (from VERSION)"
}
$r2b = Resolve-PimSmokeVersionCheck -GetLogText $emptyThenFresh -ExpectedVersion '2.4.229' -MaxAttempts 5 -DelaySeconds 0 -Sleep $noSleep
T '(2b) empty-then-fresh -> Ok=$true (slow boot self-heals)' ($r2b.Ok -eq $true)

# --- (3) genuinely-wrong version on EVERY read -> FAIL ---------------------
# Integrity proof: a live container really running the wrong version must FAIL
# even after every retry. (The deploy-did-not-roll case.)
$r3 = Resolve-PimSmokeVersionCheck -GetLogText { param($a) "[version] PIM Manager v2.4.100 (from VERSION)" } -ExpectedVersion '2.4.229' -MaxAttempts 4 -DelaySeconds 0 -Sleep $noSleep
T '(3) always-wrong version -> Ok=$false (gate still fails)' ($r3.Ok -eq $false)
T '(3) always-wrong version -> Found=2.4.100 (the wrong one)' ($r3.Found -eq '2.4.100')
T '(3) always-wrong version -> retried all attempts'         ($r3.Attempts -eq 4)
T '(3) always-wrong reason names the mismatch'               ($r3.Reason -match 'did NOT roll')

# --- (4) empty / no version on EVERY read -> FAIL (not a silent pass) ------
$r4 = Resolve-PimSmokeVersionCheck -GetLogText { param($a) "" } -ExpectedVersion '2.4.229' -MaxAttempts 3 -DelaySeconds 0 -Sleep $noSleep
T '(4) always-empty log -> Ok=$false (not a silent pass)' ($r4.Ok -eq $false)
T '(4) always-empty log -> Found is blank'                ([string]::IsNullOrEmpty($r4.Found))
T '(4) always-empty reason names "NO [version] line"'     ($r4.Reason -match 'NO \[version\] line')

# --- (5) no expected version (VERSION unreadable) -> FAIL ------------------
$r5 = Resolve-PimSmokeVersionCheck -GetLogText { param($a) $logFresh } -ExpectedVersion '' -MaxAttempts 3 -DelaySeconds 0 -Sleep $noSleep
T '(5) no ExpectedVersion -> Ok=$false (cannot pass blind)' ($r5.Ok -eq $false)

# --- (6) fetcher that throws is treated as no-text, then succeeds ----------
$script:calls3 = 0
$throwThenFresh = {
    param($a)
    $script:calls3++
    if ($script:calls3 -lt 2) { throw 'az transient error' }
    return "[version] PIM Manager v2.4.229 (from VERSION)"
}
$r6 = Resolve-PimSmokeVersionCheck -GetLogText $throwThenFresh -ExpectedVersion '2.4.229' -MaxAttempts 5 -DelaySeconds 0 -Sleep $noSleep
T '(6) throwing fetcher does not crash; retries then PASS' ($r6.Ok -eq $true)

# =============================================================================
# TEST-05 -- the hosted smoke's RELEASE-GATE mode: a self-skip must be a FAILURE.
#
# CLAUDE.md §7a already said "a self-skip is a SKIP, not a pass", but the script did
# not implement it: with no Easy Auth audience it skipped the entire live-HTTP layer
# and still exited 0, so `GET /` = 200 and `/api/active-assignments` = 200 -- the two
# assertions §7a calls THE gate -- had never been enforced on a deploy.
#
# Driven OFFLINE, with no live app: run the real script against an app/RG that cannot
# exist and confirm it exits non-zero under -AsReleaseGate precisely BECAUSE it could
# not run, and exits 0 in the same conditions without the switch. That difference IS
# the fix.
# =============================================================================
Write-Host "`n-- TEST-05: release-gate mode turns a self-skip into a failure --" -ForegroundColor Cyan
$smoke = Join-Path (Split-Path -Parent $PSScriptRoot) 'tests\live\Test-PimManagerHostedSmoke.ps1'
T 'TEST-05: the hosted smoke script is present' (Test-Path -LiteralPath $smoke)
if (Test-Path -LiteralPath $smoke) {
    $prevAud = $env:PIM_HOSTED_EASYAUTH_AUD; $prevReq = $env:PIM_HOSTED_SMOKE_REQUIRE
    try {
        $env:PIM_HOSTED_EASYAUTH_AUD = ''; $env:PIM_HOSTED_SMOKE_REQUIRE = ''
        # *>&1 (not 2>&1): the smoke reports through Write-Host, which is the INFORMATION
        # stream -- 2>&1 captures none of it and the text assertions below would be vacuous.
        $ad = & $smoke -App 'ca-does-not-exist-test05' -ResourceGroup 'rg-does-not-exist-test05' *>&1
        $adCode = $LASTEXITCODE
        $gate = & $smoke -App 'ca-does-not-exist-test05' -ResourceGroup 'rg-does-not-exist-test05' -AsReleaseGate *>&1
        $gateCode = $LASTEXITCODE

        T 'TEST-05: ad-hoc run still self-skips cleanly (exit 0) -- engineers keep the honest skip' ($adCode -eq 0)
        T 'TEST-05: the SAME conditions under -AsReleaseGate exit NON-ZERO'                         ($gateCode -ne 0)
        T 'TEST-05: gate mode announces itself'                                                     ("$gate" -match 'RELEASE GATE')
        T 'TEST-05: gate mode NAMES what did not run'                                               ("$gate" -match 'did not run')
        T 'TEST-05: ad-hoc run does NOT claim to be a release gate'                                 ("$ad" -notmatch 'a gate that did not run')
    } finally { $env:PIM_HOSTED_EASYAUTH_AUD = $prevAud; $env:PIM_HOSTED_SMOKE_REQUIRE = $prevReq }

    # The deploy path must actually ASK for gate mode -- a switch nothing uses is the
    # same defect one level up.
    $upd = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\setup\Update-PimContainers.ps1'
    if (Test-Path -LiteralPath $upd) {
        $updText = [System.IO.File]::ReadAllText($upd)
        T 'TEST-05: the deploy path invokes the smoke with -AsReleaseGate' ($updText -match '\$smoke\s+-AsReleaseGate')
    }
}

# ---------------------------------------------------------------------------
# TEST-10 -- the N() "not applicable, and something else proved it" downgrade.
#
# The three /api probes cannot run behind a hosted Easy Auth edge by construction
# (the edge token and the app's per-session GUID both want the one Authorization
# header). Under -AsReleaseGate they were hard failures, so EVERY deploy exited
# non-zero even when the deployment was perfect -- and an always-red gate is one an
# operator learns to ignore, which is the exact failure mode TEST-05 exists to stop.
#
# The danger in fixing that is obvious: it must not become a back door to
# "a skip is a pass". So N() downgrades ONLY when the named compensating assertion
# actually ran and PASSED in the same run. These tests are the proof of that, in
# BOTH directions -- the downgrade working, and the downgrade REFUSING.
# ---------------------------------------------------------------------------
Write-Host "`n-- TEST-10: N/A downgrade is conditional on a compensating PASS --" -ForegroundColor Cyan
$smokeSrc = Join-Path $PSScriptRoot 'live\Test-PimManagerHostedSmoke.ps1'
if (-not (Test-Path -LiteralPath $smokeSrc)) {
    T 'TEST-10: hosted smoke script present' $false
} else {
    $sText = [System.IO.File]::ReadAllText($smokeSrc)

    # Extract and load JUST the helper trio so the real N()/S()/T() logic is exercised
    # (not a reimplementation of it -- that would prove nothing about the shipped file).
    $harness = @'
$script:AsReleaseGate = $true
$pass=0; $fail=0; $skip=0
$script:skipReasons = New-Object System.Collections.Generic.List[string]
$script:naReasons   = New-Object System.Collections.Generic.List[string]
$script:passedNames = New-Object System.Collections.Generic.HashSet[string]
'@
    $fnT = [regex]::Match($sText, '(?ms)^function T\(\$n,\$c\)\{.*?^\}')
    $fnS = [regex]::Match($sText, '(?ms)^function S\(\$n,\$why\)\{.*?^\}')
    $fnN = [regex]::Match($sText, '(?ms)^function N\(\$n, \$why, \[string\[\]\]\$CoveredBy\) \{.*?^\}')
    T 'TEST-10: the shipped T/S/N helpers were all located' ($fnT.Success -and $fnS.Success -and $fnN.Success)

    if ($fnT.Success -and $fnS.Success -and $fnN.Success) {
        # Each case runs in its OWN powershell process. A [scriptblock]::Create invoked
        # with & shares `$script:` with THIS file, so S()'s `$script:fail++` incremented
        # the parent suite's own counter instead of the harness's -- the harness read 0
        # failures while this suite silently gained them. Separate processes make the
        # scope unambiguous, which is the only way this proof means anything.
        function Invoke-PimNCase {
            param([string]$Body)
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pim-test10-{0}.ps1" -f ([guid]::NewGuid().ToString('N')))
            $src = $harness + "`n" + $fnT.Value + "`n" + $fnS.Value + "`n" + $fnN.Value + "`n" + $Body + "`n" +
                   'Write-Output ("RESULT|fail={0}|na={1}|skips={2}" -f $script:fail, $script:naReasons.Count, $script:skipReasons.Count)'
            try {
                Set-Content -LiteralPath $tmp -Value $src -Encoding UTF8
                $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tmp 2>&1
                $line = @($out | Where-Object { "$_" -match '^RESULT\|' }) | Select-Object -Last 1
                if (-not $line) { return $null }
                $h = @{}
                foreach ($kv in ("$line" -split '\|' | Select-Object -Skip 1)) { $p = $kv -split '=',2; $h[$p[0]] = [int]$p[1] }
                return $h
            } finally { Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue }
        }

        # (a) compensating assertion PASSED -> N/A, and NOT a failure.
        $r1 = Invoke-PimNCase @"
T 'covering-assert' `$true
N 'unrunnable-probe' 'cannot run behind Easy Auth' -CoveredBy @('covering-assert')
"@
        T 'TEST-10: with the compensating assertion GREEN -> 0 failures'  ($null -ne $r1 -and $r1['fail'] -eq 0)
        T 'TEST-10: ...and it is recorded as N/A, never silently dropped' ($null -ne $r1 -and $r1['na'] -eq 1)

        # (b) compensating assertion ABSENT -> must become a hard FAILURE.
        #     This is THE assertion that stops N() being a back door to skip-as-pass.
        $r2 = Invoke-PimNCase @"
N 'unrunnable-probe' 'cannot run behind Easy Auth' -CoveredBy @('an-assertion-that-never-ran')
"@
        T 'TEST-10: with NO compensating pass -> a HARD FAILURE under the gate' ($null -ne $r2 -and $r2['fail'] -ge 1)
        T 'TEST-10: ...and it is NOT recorded as N/A'                           ($null -ne $r2 -and $r2['na'] -eq 0)

        # (c) compensating assertion RAN BUT FAILED -> also a hard failure.
        $r3 = Invoke-PimNCase @"
T 'covering-assert' `$false
N 'unrunnable-probe' 'cannot run behind Easy Auth' -CoveredBy @('covering-assert')
"@
        T 'TEST-10: a compensating assertion that FAILED does not license an N/A' ($null -ne $r3 -and $r3['fail'] -ge 2 -and $r3['na'] -eq 0)
    }

    # The three real probes must each name a compensating assertion -- an N() with no
    # -CoveredBy would be exactly the loophole this design exists to prevent.
    foreach ($probe in @('/api/portal-access','/api/tenant-lists','/api/active-assignments')) {
        $m = [regex]::Match($sText, [regex]::Escape("N '$probe") + "(?s).{0,900}?-CoveredBy")
        T ("TEST-10: '{0}' declares a -CoveredBy compensating assertion" -f $probe) $m.Success
    }
    # And each must still be a real failure when a session token WAS supplied -- the
    # construction excuse only applies when there is genuinely no token to be had.
    T 'TEST-10: a supplied -SessionToken still yields a hard failure path' `
        ($sText -match 'a -SessionToken WAS supplied but')
}

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 }
# Explicit: this suite now SHELLS OUT to the hosted smoke, so a green run would
# otherwise inherit that child's exit code and report red for no reason.
exit 0
