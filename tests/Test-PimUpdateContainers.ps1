#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-09 -- the deploy script must never report a deploy that did not happen.

    Update-PimContainers.ps1 once printed "All apps rolled to 2.4.238 ... Done. All apps
    on 2.4.238 and post-deploy GUI smoke gate passed" and exited 0 on a run where
    `apps present:` was EMPTY and it rolled NOTHING. Five workers stayed 8 versions
    behind -- including the engine/scheduler safety fixes from this audit -- while the
    deploy reported success. That is a plausible mechanism for TEST-09's 7-week drift.

    The trigger was a caller passing -Apps as one comma-joined string. The DEFECT is the
    script turning that into a green deploy: it silently intersected the requested apps
    with the ones that exist, so anything misspelled, renamed, in another resource group
    or momentarily unreadable evaporated without a word -- and the summary was a fixed
    string that never consulted reality.

    These tests cover the pure decision core. The equally important half -- post-roll
    verification against the LIVE image -- is asserted statically here and exercised for
    real on every deploy.

    Offline. No az, no network (the script returns early when dot-sourced).
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
$upd = Join-Path $solRoot 'tools\setup\Update-PimContainers.ps1'
Assert "Update-PimContainers.ps1 exists" (Test-Path -LiteralPath $upd)
if (-not (Test-Path -LiteralPath $upd)) { Write-Host "`n RESULT: $pass passed, $fail failed" -ForegroundColor Red; exit 1 }
# Dot-source for the pure helpers. Dummy values satisfy the mandatory params; the script
# returns immediately (InvocationName -eq '.') so nothing live is touched.
. $upd -ImageTag '0.0.0-test' -ResourceGroup 'rg-does-not-exist-bug09' -AcrName 'acrdoesnotexistbug09'

Write-Host "=== Update-PimContainers deploy honesty (BUG-09) ===" -ForegroundColor Cyan

$ALL = @('ca-pim-manager','ca-pim-scheduler','ca-pim-engine')

# --- -Apps normalisation: the exact mis-invocation that started this --------------
$r = Resolve-PimAppList -Apps @('ca-pim-scheduler,ca-pim-engine,ca-pim-connector')
Assert "a comma-joined single string splits into 3 apps" (@($r).Count -eq 3 -and $r[0] -eq 'ca-pim-scheduler' -and $r[2] -eq 'ca-pim-connector')
$r = Resolve-PimAppList -Apps @('a','b')
Assert "a proper array is unchanged"                     (@($r).Count -eq 2)
$r = Resolve-PimAppList -Apps @('a', 'a', ' a ')
Assert "duplicates and whitespace collapse"              (@($r).Count -eq 1 -and $r[0] -eq 'a')
$r = Resolve-PimAppList -Apps @('a;b', $null, '', 'c d')
Assert "semicolon/space separators and nulls handled"    (@($r).Count -eq 4)
Assert "an empty list stays empty"                       (@(Resolve-PimAppList -Apps @()).Count -eq 0)

# --- the plan: THE regression that mattered ---------------------------------------
# The real failure: -Apps was one joined string, so NOTHING matched, and it still passed.
$p = Get-PimAppRollPlan -Requested @('ca-pim-scheduler,ca-pim-engine') -Existing $ALL
Assert "the ORIGINAL bug shape (no app matches) is NOT ok"   (-not $p.ok)
Assert "  ...and rolls nothing"                              (@($p.roll).Count -eq 0)
Assert "  ...and the reason says it refuses to report a deploy" ("$($p.reason)" -match 'rolled nothing')

# zero apps is NEVER ok -- not even with the escape hatch. Rolling nothing is not a deploy.
$p = Get-PimAppRollPlan -Requested @('nope') -Existing $ALL -AllowMissing $true
Assert "zero rollable apps is not ok EVEN with -AllowMissingApps" (-not $p.ok)

# a missing app must be named and must fail by default
$p = Get-PimAppRollPlan -Requested @('ca-pim-manager','ca-pim-typo') -Existing $ALL
Assert "a missing app fails by default"          (-not $p.ok)
Assert "  ...and is NAMED in the reason"         ("$($p.reason)" -match 'ca-pim-typo')
Assert "  ...and is listed in .missing"          (@($p.missing) -contains 'ca-pim-typo')
Assert "  ...while the valid app is still in .roll" (@($p.roll) -contains 'ca-pim-manager')

# ...but a deliberate partial environment can proceed
$p = Get-PimAppRollPlan -Requested @('ca-pim-manager','ca-pim-typo') -Existing $ALL -AllowMissing $true
Assert "-AllowMissingApps lets a partial roll proceed" ($p.ok -and @($p.roll).Count -eq 1)

# --- and the happy path must still WORK (a gate that can never pass proves nothing) --
$p = Get-PimAppRollPlan -Requested $ALL -Existing $ALL
Assert "a normal full deploy is ok"              ($p.ok -and @($p.roll).Count -eq 3 -and @($p.missing).Count -eq 0)
$p = Get-PimAppRollPlan -Requested @('ca-pim-manager') -Existing $ALL
Assert "a deliberate single-app deploy is ok"    ($p.ok -and @($p.roll).Count -eq 1)

# --- the live half, asserted statically ------------------------------------------
$t = [System.IO.File]::ReadAllText($upd)
Assert "the roll loop checks az update's exit code"        ($t -match "az containerapp update[\s\S]{0,400}?LASTEXITCODE -ne 0")
Assert "post-roll VERIFIES the live image"                 ($t -match 'post-roll verification FAILED')
Assert "  ...and names the apps not running it"            ($t -match 'notOnImage')
# BUG-40 tightened what this check MEANS. It used to compare the live TAG against the requested
# TAG, which is not a verification at all: rebuilding a tag leaves both strings identical while
# the running content is stale, and it passed on exactly that deploy. The comparison is now
# digest-based via the pure Test-PimImageDeployed (proven in Test-PimSetupHosting.ps1), and the
# roll pins the digest rather than the tag.
Assert "post-roll comparison is digest-based, not tag-substring" (($t -match 'Test-PimImageDeployed') -and ($t -notmatch "LastIndexOf\('\:'\)"))
Assert "the roll pins the tag to its digest before updating"     (($t -match 'Resolve-PimAcrImageDigest') -and ($t -match 'New-PimImageReference'))
Assert "it refuses to report success having rolled nothing" ($t -match 'nothing was rolled -- refusing to report success')
Assert "the summary reports the COUNT actually rolled"     ($t -match 'Rolled \{0\} app\(s\)')
# The old fixed strings must no longer be EMITTED. Match the emitting statement, not the
# bare phrase -- the phrase legitimately survives in the comment explaining the defect,
# and an assertion that fires on its own documentation is a false alarm waiting to happen.
Assert "no longer EMITS the fixed 'All apps rolled to' claim" ($t -notmatch 'Step\s+"All apps rolled to')
Assert "no longer EMITS the fixed 'Done. All apps on' claim"  ($t -notmatch 'Step\s+"Done\. All apps on')
Assert "the smoke gate is told what was really rolled"     ($t -notmatch 'RolledApps \$existing')
# rollback path: same honesty
Assert "rollback refuses to claim success on zero matches" ($t -match 'nothing was rolled back')
Assert "rollback names apps with no matching revision"     ($t -match 'NO revision matching')

# --- BUG-48: the scheduled tick JOB is rolled here too, off the SAME digest -------------------
# The defect: INFRA stamped the Job with the digest the tag pointed at BEFORE the code step
# rebuilt that tag, and the code step rolled only the apps -- so one deploy run left the GUI on
# the new build and the reconciling engine on the old one, durably (BUG-40's pinning is what
# stops it self-healing). Measured live across three consecutive runs on production.
# 🪤 THESE MUST MATCH THE EXECUTED STATEMENT, NOT THE ERROR TEXT. Both traps below were found by
# negative verification -- the first two versions of this assert PASSED with the fix deliberately
# broken:
#   1. `-match` is CASE-INSENSITIVE, so `--image \$image` also matches `--image $ImageTag`. Hence \b.
#   2. The throw message contains a copy-paste hint that includes the whole `az containerapp job
#      update ... --image $image` command, so an unanchored match was satisfied by the error string
#      describing the failure. Hence the (?m)^\s* anchor -- a real statement starts the line; the
#      hint lives inside `throw "..."`.
# This is the same lesson already recorded above for the fixed-claim asserts: match the emitting
# statement, never the bare phrase.
$jobStmt = '(?m)^\s*az containerapp job update[^\r\n]*'
Assert "BUG-48: the tick Job is rolled from here"            ($t -match $jobStmt)
Assert "  ...with the SAME resolved digest the apps got"     ($t -match ($jobStmt + '--image \$image\b'))
Assert "  ...and az job update's exit code is checked"       ($t -match ($jobStmt + "[\s\S]{0,600}?LASTEXITCODE -ne 0"))
Assert "  ...and the failure says the deploy is now SKEWED"  ($t -match 'SKEWED')
Assert "  ...and the Job image is VERIFIED after stamping"   ($t -match "jobLive[\s\S]{0,300}?Test-PimImageDeployed")
Assert "  ...digest-verified, not tag-compared"              ($t -notmatch 'jobLive[^\r\n]*-eq \$ImageTag')
# A missing Job is the NORMAL always-on shape -- it must not fail the deploy, but it must not be
# silent either: "no Job here" and "we forgot the Job" looked identical before.
Assert "  ...a missing tick Job is a SKIP, not a throw"      ($t -match 'nothing to roll \(expected in always-on mode\)')
# The inverse skew, during an incident: a Job has no revisions, so an app-revision rollback
# cannot include it. Unfixable here, so it must be STATED.
Assert "  ...rollback WARNS the Job was not rolled back"     ($t -match '\[BUG-48\][\s\S]{0,300}?not rolled back')

# --- BUG-57: the closing line must never CLAIM a gate that did not run ------------------------
# Found by running the roll live against an estate environment on 2026-08-11: with -SkipSmoke the
# output read "skipping post-deploy GUI smoke gate (NOT recommended)" and then, two lines later,
# "post-deploy GUI smoke gate passed". Four paths never run the gate (-WhatIf, -SkipSmoke, the
# Manager not among the rolled apps, the smoke script missing) and all four claimed a pass.
# Exactly the BUG-09 family this file is the home of, and §7a is explicit that a self-skip is a
# SKIP, not a pass.
Assert "BUG-57: the gate RETURNS a verdict rather than being fire-and-forget" ($t -match 'return ''PASSED''')
Assert "BUG-57:  ...-SkipSmoke returns a verdict that says NOT a pass"        ($t -match "return 'SKIPPED \(-SkipSmoke -- NOT a pass\)'")
Assert "BUG-57:  ...a missing smoke script is NOT RUN, not a pass"            ($t -match "return 'NOT RUN \(smoke script missing -- NOT a pass\)'")
Assert "BUG-57:  ...-WhatIf is NOT RUN"                                       ($t -match "return 'NOT RUN \(-WhatIf\)'")
# The load-bearing one: the closing Step must INTERPOLATE the verdict, never assert a pass.
Assert "BUG-57: the closing line PRINTS the verdict, not a fixed 'passed'"    ($t -match 'post-deploy GUI smoke gate: \{2\}')
Assert "BUG-57:  ...and no longer emits the fixed 'smoke gate passed' claim"  ($t -notmatch 'GUI smoke gate passed \(rollback')
# Both call sites must CAPTURE it -- an uncaptured return would also leak the string into output.
Assert "BUG-57: the roll path captures the verdict"                           ($t -match '\$smokeVerdict = Invoke-ManagerSmokeGate')
Assert "BUG-57: the ROLLBACK path captures it too"                            ($t -match '\$rbVerdict = Invoke-ManagerSmokeGate')

# --- BUG-48 passthrough: the name must actually REACH the roller ------------------------------
# BUG-46 was "the SIXTH missing passthrough" -- a value correct at the top of a script that never
# reached the call. The roller's default is right today, so a missing passthrough would be
# invisible until someone renamed the Job. Assert the wiring, not the default.
$here2 = Split-Path -Parent $PSScriptRoot
foreach ($c in @(
    @{ f = 'tools\setup\Invoke-PimUpdate.ps1';         what = 'Invoke-PimUpdate' }
    @{ f = 'tools\setup\Invoke-PimSyncAutomateIT.ps1'; what = 'Invoke-PimSyncAutomateIT (the CUSTOMER auto-update path)' }
)) {
    $p = Join-Path $here2 $c.f
    $src = if (Test-Path -LiteralPath $p) { [System.IO.File]::ReadAllText($p) } else { '' }
    Assert "$($c.what) declares -TickJobName"            ($src -match '\[string\]\$TickJobName')
    Assert "$($c.what) FORWARDS it to the roller"        ($src -match '\$roller[^\r\n]*-TickJobName \$TickJobName')
}
$dap = Join-Path $here2 'tools\setup\Invoke-PimDeployAll.ps1'
$dsrc = if (Test-Path -LiteralPath $dap) { [System.IO.File]::ReadAllText($dap) } else { '' }
Assert "Invoke-PimDeployAll forwards -TickJobName into the code step" ($dsrc -match '\$upd[\s\S]{0,400}?-TickJobName \$TickJobName')

# --- BUG-128: a CAUGHT, non-fatal native failure must not leave a fatal exit code -------
# The image built fine; the digest lookup after it failed (non-fatal, caught, warned). But the
# az call inside the lookup left $LASTEXITCODE = -1, and Invoke-PimUpdate judges THE BUILD by
# that same variable -- so a successful build was reported as "exit -1" and the deploy aborted.
# Observed on the internal prod environment 2026-09-05 (PIM-Update-mfnpr-internal, lastResult=1).
Write-Host "=== BUG-128: a warning must not become a release failure ===" -ForegroundColor Cyan
$bpm  = Join-Path $here2 'tools\setup\Build-PimManagerImage.ps1'
$bsrc = if (Test-Path -LiteralPath $bpm) { [System.IO.File]::ReadAllText($bpm) } else { '' }
$ipu  = Join-Path $here2 'tools\setup\Invoke-PimUpdate.ps1'
$isrc = if (Test-Path -LiteralPath $ipu) { [System.IO.File]::ReadAllText($ipu) } else { '' }

Assert 'Build-PimManagerImage: the digest catch CLEARS $LASTEXITCODE' `
    ($bsrc -match "could not resolve the built image's digest[\s\S]{0,600}?\`$global:LASTEXITCODE = 0")
Assert '  ...and the clear sits in the DIGEST catch (warn, comments, then the clear)' `
    ($bsrc -match "could not resolve the built image's digest[^\r\n]*\r?\n(?:[ \t]*#[^\r\n]*\r?\n)*[ \t]*\`$global:LASTEXITCODE = 0")
Assert 'Invoke-PimUpdate: clears $LASTEXITCODE BEFORE invoking the builder' `
    ($isrc -match "\`$global:LASTEXITCODE = 0[\s\S]{0,200}?& \`$builder")
Assert "  ...and STILL checks the builder's exit code afterwards" `
    ($isrc -match "& \`$builder[\s\S]{0,300}?LASTEXITCODE -ne 0[\s\S]{0,80}?failed \(exit")

# --- BUG-129: an az WARNING on stderr must not abort the update ---------------------------
# Same defect CLASS as BUG-128 one step further out. PowerShell 5.1 turns ANY write to a native
# command's stderr into a NativeCommandError, and the whole update path runs with
# $ErrorActionPreference='Stop' -- so a warning from az aborts the deploy. Measured on internal
# prod 2026-09-05: the image built and pushed, then container-app DISCOVERY died on
#   "...cryptography/hazmat/backends/openssl/backend.py:8: UserWarning: You are using
#    cryptography on a 32-bit Python on a 64-bit Windows Operating System."
#   -> outcome=failure (built=True deployed=False)
# 🪤 `2>$null` does NOT prevent it (all five call shapes were measured throwing), and it only
# bites hosts whose az config dir has extensions installed -- which is why the two customer
# environments went green nightly while internal prod could not deploy at all.
Write-Host ""
Write-Host "=== BUG-129: an az stderr WARNING must not be fatal ===" -ForegroundColor Cyan
$azGuard = Join-Path $here2 'tools\setup\_PimAz.ps1'
Assert 'the guarded az shadow (_PimAz.ps1) ships' (Test-Path -LiteralPath $azGuard)
$gsrc = if (Test-Path -LiteralPath $azGuard) { [System.IO.File]::ReadAllText($azGuard) } else { '' }
Assert '  ...it neutralises $ErrorActionPreference around the native call' ($gsrc -match "ErrorActionPreference = 'Continue'")
Assert '  ...it restores the caller''s preference afterwards'              ($gsrc -match 'finally\s*\{[\s\S]{0,200}?ErrorActionPreference = \$prevEA')
Assert '  ...and success is still decided by the EXIT CODE alone'          ($gsrc -match '\$global:LASTEXITCODE = \$code')
# 🪤 The shadow must declare NO parameters: a param()/[CmdletBinding()] makes PowerShell bind
# az's short flags, and `-o tsv` then dies as "the parameter name 'o' is ambiguous".
Assert '  ...the shadow declares no parameters (or -o binds as -OutVariable)' `
    ($gsrc -match '(?m)^function az \{ Invoke-PimAz @args \}')
Assert '  ...and it resolves the real CLI by -CommandType Application (no recursion)' `
    ($gsrc -match "-CommandType Application")

# Every entry point that calls az must load the guard BEFORE its first az call.
foreach ($pair in @(
    @{ Name = 'Update-PimContainers'; Path = 'tools\setup\Update-PimContainers.ps1' },
    @{ Name = 'Invoke-PimUpdate';     Path = 'tools\setup\Invoke-PimUpdate.ps1' },
    @{ Name = 'Build-PimManagerImage';Path = 'tools\setup\Build-PimManagerImage.ps1' },
    @{ Name = '_PimSetupShared';      Path = 'tools\setup\_PimSetupShared.ps1' },
    # 🔴 The RELEASE GATE itself. Here the class is worse than a failed deploy: its first az call is
    # inside `try { } catch {}`, so a swallowed warning leaves the account unread and the gate
    # reports "az not logged in" and SKIPS -- not a pass, not a failure, and the deploy proceeds
    # without the one check that proves the hosted GUI still works.
    @{ Name = 'Test-PimManagerHostedSmoke'; Path = 'tests\live\Test-PimManagerHostedSmoke.ps1' },
    @{ Name = 'Invoke-PimSyncAutomateIT';   Path = 'tools\setup\Invoke-PimSyncAutomateIT.ps1' },
    @{ Name = 'Invoke-PimDeployAll';        Path = 'tools\setup\Invoke-PimDeployAll.ps1' },
    @{ Name = 'Test-PimDeployedVersionDrift'; Path = 'tools\setup\Test-PimDeployedVersionDrift.ps1' }
)) {
    $p = Join-Path $here2 $pair.Path
    $s = if (Test-Path -LiteralPath $p) { [System.IO.File]::ReadAllText($p) } else { '' }
    # 🪤 Match the FILE NAME, not one quoting style: the entry points use `. "$here\_PimAz.ps1"`
    # and _PimSetupShared uses `. (Join-Path $PSScriptRoot '_PimAz.ps1')`. The first version of
    # this assertion hard-coded the single quote and reported three correctly-wired files as
    # unwired -- a guard that fails on formatting teaches you to ignore it.
    $loadMatch = [regex]::Match($s, '_PimAz\.ps1')
    $loadIdx   = if ($loadMatch.Success) { $loadMatch.Index + 1 } else { -1 }
    # First az call on a CODE line. 🪤 Blank out BLOCK comments too, not just `#` lines: every
    # one of these files opens with a <# .DESCRIPTION #> that talks about `az acr build` and
    # `az containerapp update` in prose. Scanning raw text put the "first az call" in the help
    # header, so three correctly-wired files failed. Replace with newlines so offsets stay true.
    $sCode = [regex]::Replace($s, '(?s)<#.*?#>', { param($m) ($m.Value -replace '[^\r\n]', ' ') })
    $firstAz = -1; $offset = 0
    foreach ($line in ($sCode -split "`n")) {
        if ($line.TrimStart() -notmatch '^#' -and $line -match '(?<![\w-])az\s+(account|containerapp|acr|tag|login|group|role|ad|deployment|network|sql|monitor|storage|keyvault|extension|version|--version)') {
            $firstAz = $offset; break
        }
        $offset += $line.Length + 1
    }
    Assert ("{0}: loads _PimAz.ps1" -f $pair.Name) ($loadIdx -gt 0)
    Assert ("  ...BEFORE its first az call" -f $pair.Name) ($firstAz -lt 0 -or ($loadIdx -gt 0 -and $loadIdx -lt $firstAz))
}

# --- and now EXECUTE it. A source match proves the guard is written, not that it works. ------
# Runs in a CHILD process at $ErrorActionPreference='Stop' with a fake `az` on PATH that writes
# to stderr and exits 0 -- the exact shape that killed the deploy. No Azure, no network.
Write-Host "  -- executing the guard against a stderr-writing fake az --" -ForegroundColor DarkGray
$azProbe = Join-Path ([System.IO.Path]::GetTempPath()) ("pimazprobe-" + [guid]::NewGuid().ToString('N').Substring(0,8))
try {
    [void](New-Item -ItemType Directory -Path $azProbe -Force)
    # A .cmd, because the real az is az.cmd and that is what Get-Command resolves.
    @'
@echo off
echo WARNING: this command has been altered by an extension 1>&2
echo UserWarning: you are using cryptography on a 32-bit Python 1>&2
if "%1"=="fail" exit /b 7
echo ca-pim-manager
exit /b 0
'@ | Set-Content -LiteralPath (Join-Path $azProbe 'az.cmd') -Encoding ASCII

    $probe = Join-Path $azProbe 'probe.ps1'
    @'
param([string]$Guard)
$ErrorActionPreference = 'Stop'
. $Guard
$ok = 'unset'; $code = 'unset'; $failCode = 'unset'
try {
    # the exact discovery shape from Update-PimContainers.ps1
    $d = @(az containerapp list --query "[].name" -o tsv 2>$null | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $ok = ($d -join ',')
    $code = $LASTEXITCODE
} catch { $ok = "THREW: $($_.Exception.Message)" }
try { $null = az fail -o tsv 2>$null; $failCode = $LASTEXITCODE } catch { $failCode = "THREW: $($_.Exception.Message)" }
Write-Output ("PROBE " + ([pscustomobject]@{ Out = "$ok"; Code = "$code"; FailCode = "$failCode" } | ConvertTo-Json -Compress))
'@ | Set-Content -LiteralPath $probe -Encoding UTF8

    $psExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $prevPath = $env:PATH
    $env:PATH = $azProbe + ';' + $env:PATH        # the fake az must win over the real one
    $raw = & $psExe -NoProfile -ExecutionPolicy Bypass -File $probe -Guard $azGuard 2>&1
    $env:PATH = $prevPath
    $line = @($raw | ForEach-Object { "$_" } | Where-Object { $_ -like 'PROBE {*' }) | Select-Object -Last 1
    $res  = if ($line) { $line.Substring(6) | ConvertFrom-Json } else { $null }

    Assert 'the guard SURVIVES an az that writes warnings to stderr (executed, not matched)' `
        ($null -ne $res -and $res.Out -eq 'ca-pim-manager')
    if ($res -and $res.Out -ne 'ca-pim-manager') { Write-Host ("        got: " + $res.Out) -ForegroundColor DarkYellow }
    Assert '  ...and reports exit 0 for that call'            ($null -ne $res -and "$($res.Code)" -eq '0')
    Assert '  ...while a REAL az failure still exits non-zero' ($null -ne $res -and "$($res.FailCode)" -eq '7')
} finally {
    Remove-Item -LiteralPath $azProbe -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("Update-PimContainers honesty (BUG-09): {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
