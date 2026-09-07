#Requires -Version 5.1
<#
.SYNOPSIS
    Register-PimSyncSchedule.ps1 -- the wrapper it GENERATES, and the run lock inside it.

.DESCRIPTION
    One host updates several environments, and every one of them pulls into the SAME tree before
    building an image from it. Two things follow, and neither was covered before:

      1. -AtHour alone cannot express "04:00, 04:20, 04:40". Asking for three environments "at 4am"
         produced three tasks at 04:00 that would sync C:\AutomateIT concurrently. `-MultipleInstances
         IgnoreNew` does not help -- it is per-task, and these are three different tasks.
      2. The stagger is a plan, not a guarantee. A run that overruns its slot still collides. So the
         generated wrapper takes an exclusive lock on the shared tree and SKIPS (exit 6) rather than
         building from a directory another run is rewriting.

    🔴 The lock assertions EXECUTE the real locking shape in child processes. A regex over the
    generated text would prove the code is written, not that two runs actually exclude each other --
    and "the guard is present but does not guard" is the failure mode this whole file exists for.

    Offline. Generates wrappers with -WhatIf (no task is ever registered). No az, no network.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
$reg     = Join-Path $solRoot 'tools\setup\Register-PimSyncSchedule.ps1'
$psExe   = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

Write-Host "=== Register-PimSyncSchedule: the generated wrapper ===" -ForegroundColor Cyan
Assert 'Register-PimSyncSchedule.ps1 ships' (Test-Path -LiteralPath $reg)

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pimsched-" + [guid]::NewGuid().ToString('N').Substring(0,8))
try {
    [void](New-Item -ItemType Directory -Path $tmp -Force)
    # A stand-in for the puller. It is never RUN here (-WhatIf stops before the task exists and we
    # only read the generated file), but the registration Test-Paths it, on purpose: a bad path
    # must fail in front of the operator, not at 04:00 unattended.
    $fakeSync = Join-Path $tmp 'Sync-Fake.ps1'
    'exit 0' | Set-Content -LiteralPath $fakeSync -Encoding UTF8

    $out = & $psExe -NoProfile -ExecutionPolicy Bypass -File $reg -WhatIf `
        -TaskName 'PIM-Update-unittest' -AtHour 4 -AtMinute 20 -LogDir $tmp `
        -ResourceGroup 'rg-x' -AcrName 'acrx' -Recipient 'a@b.c' `
        -SubscriptionId '11111111-1111-1111-1111-111111111111' `
        -SyncScript $fakeSync -SyncArgs '-Solutions PIM4EntraPS' 2>&1
    $outText = ($out | ForEach-Object { "$_" }) -join "`n"

    $wrapper = Join-Path $tmp 'PIM-Update-unittest.run.ps1'
    Assert 'the wrapper is written even under -WhatIf (it is the artifact you ran -WhatIf to read)' (Test-Path -LiteralPath $wrapper)
    $wsrc = if (Test-Path -LiteralPath $wrapper) { [System.IO.File]::ReadAllText($wrapper) } else { '' }

    # --- -AtMinute -----------------------------------------------------------------------------
    Assert '-AtMinute reaches the registration message (04:20, not 04:00)' ($outText -match 'daily 04:20')
    Assert '  ...and no message still hard-codes :00' (-not ($outText -match 'daily 04:00'))
    $rsrc = [System.IO.File]::ReadAllText($reg)
    Assert '  ...and the TRIGGER itself uses it (a correct message with a 04:00 trigger is worse than neither)' `
        ($rsrc -match 'AddHours\(\$AtHour\)\.AddMinutes\(\$AtMinute\)')

    # --- the wrapper must be valid PowerShell --------------------------------------------------
    # 🪤 It is built by string concatenation across several quoting levels, and it has shipped
    # broken twice before (a literal "$(Get-Date ...)" in a filename; a collapsed Write-Host).
    $perrs = $null
    if ($wsrc) { [void][System.Management.Automation.Language.Parser]::ParseInput($wsrc, [ref]$null, [ref]$perrs) }
    Assert 'the generated wrapper PARSES' (@($perrs).Count -eq 0)
    if (@($perrs).Count) { @($perrs) | Select-Object -First 3 | ForEach-Object { Write-Host ("        " + $_.Message) -ForegroundColor DarkYellow } }

    # --- the run lock --------------------------------------------------------------------------
    Assert 'the wrapper takes an exclusive lock before doing anything'  ($wsrc -match "\[System\.IO\.File\]::Open\(\`$lockPath, 'OpenOrCreate', 'ReadWrite', 'None'\)")
    Assert '  ...waits rather than failing instantly'                    ($wsrc -match 'lockDeadline' -and $wsrc -match 'Start-Sleep')
    Assert '  ...SKIPS with a distinct exit code when it cannot get it'  ($wsrc -match 'exit 6')
    Assert '  ...and RELEASES it in finally (a wedged lock would break every following night)' `
        ($wsrc -match 'finally \{ if \(\$lockFs\) \{ \$lockFs\.Close\(\)')
    Assert '  ...the lock is taken BEFORE the pull, not after it' `
        ($wsrc.IndexOf('update lock held') -gt 0 -and $wsrc.IndexOf('update lock held') -lt $wsrc.IndexOf('--- PULL:'))

    # Two environments pulling into the SAME tree must share one lock; two different trees must not.
    $out2 = & $psExe -NoProfile -ExecutionPolicy Bypass -File $reg -WhatIf `
        -TaskName 'PIM-Update-unittest2' -AtHour 4 -AtMinute 40 -LogDir $tmp `
        -ResourceGroup 'rg-y' -AcrName 'acry' -Recipient 'a@b.c' `
        -SyncScript $fakeSync -SyncArgs '-Solutions PIM4EntraPS' 2>&1
    $w2 = [System.IO.File]::ReadAllText((Join-Path $tmp 'PIM-Update-unittest2.run.ps1'))
    $lock1 = ([regex]::Match($wsrc, "\`$lockPath = '([^']+)'")).Groups[1].Value
    $lock2 = ([regex]::Match($w2,   "\`$lockPath = '([^']+)'")).Groups[1].Value
    Assert 'two tasks pulling into the SAME tree resolve to the SAME lock file' ($lock1 -and $lock1 -eq $lock2)

    $otherDir  = Join-Path $tmp 'othertree'
    [void](New-Item -ItemType Directory -Path $otherDir -Force)
    $fakeSync2 = Join-Path $otherDir 'Sync-Fake.ps1'
    'exit 0' | Set-Content -LiteralPath $fakeSync2 -Encoding UTF8
    $out3 = & $psExe -NoProfile -ExecutionPolicy Bypass -File $reg -WhatIf `
        -TaskName 'PIM-Update-unittest3' -AtHour 5 -LogDir $tmp `
        -ResourceGroup 'rg-z' -AcrName 'acrz' -Recipient 'a@b.c' `
        -SyncScript $fakeSync2 -SyncArgs '-Solutions PIM4EntraPS' 2>&1
    $w3 = [System.IO.File]::ReadAllText((Join-Path $tmp 'PIM-Update-unittest3.run.ps1'))
    $lock3 = ([regex]::Match($w3, "\`$lockPath = '([^']+)'")).Groups[1].Value
    Assert '  ...and a task pulling into a DIFFERENT tree gets its own lock (it must not be serialised)' ($lock3 -and $lock3 -ne $lock1)

    # --- EXECUTE the locking shape: does it actually exclude? ----------------------------------
    Write-Host "  -- executing the lock shape in two child processes --" -ForegroundColor DarkGray
    # 🪤 The holder announces itself through a FILE, not stdout: a detached Start-Process has no
    # readable stdout here, so probing on a timer alone cannot tell "the lock does not exclude"
    # apart from "the holder had not opened it yet". The first version of this test raced and
    # reported the lock broken when it was fine.
    $holder = Join-Path $tmp 'holder.ps1'
    @'
param([string]$Lock, [int]$HoldSeconds, [string]$Signal)
try {
    $fs = [System.IO.File]::Open($Lock, 'OpenOrCreate', 'ReadWrite', 'None')
    Set-Content -LiteralPath $Signal -Value 'HELD' -Encoding UTF8
    Start-Sleep -Seconds $HoldSeconds
    $fs.Close(); $fs.Dispose()
} catch {
    Set-Content -LiteralPath $Signal -Value ("ERR " + $_.Exception.Message) -Encoding UTF8
}
'@ | Set-Content -LiteralPath $holder -Encoding UTF8

    $tryLock = Join-Path $tmp 'trylock.ps1'
    @'
param([string]$Lock)
try {
    $fs = [System.IO.File]::Open($Lock, 'OpenOrCreate', 'ReadWrite', 'None')
    Write-Output 'GOT'
    $fs.Close(); $fs.Dispose()
} catch { Write-Output 'BLOCKED' }
'@ | Set-Content -LiteralPath $tryLock -Encoding UTF8

    $testLock = Join-Path $tmp 'exec.lock'
    $signal   = Join-Path $tmp 'holder.signal'
    $p = Start-Process -FilePath $psExe -PassThru -WindowStyle Hidden -ArgumentList @(
        '-NoProfile','-ExecutionPolicy','Bypass','-File',$holder,
        '-Lock',$testLock,'-HoldSeconds','8','-Signal',$signal)
    # Wait for the holder to CONFIRM it owns the handle, then probe. No timing assumptions.
    $deadline = (Get-Date).AddSeconds(30); $held = $false
    while ((Get-Date) -lt $deadline -and -not $held) {
        if (Test-Path -LiteralPath $signal) { $held = ((Get-Content -LiteralPath $signal -Raw).Trim() -eq 'HELD') ; break }
        Start-Sleep -Milliseconds 200
    }
    Assert 'the holder process really took the lock (test precondition)' $held
    $r = @(& $psExe -NoProfile -ExecutionPolicy Bypass -File $tryLock -Lock $testLock 2>&1 | ForEach-Object { "$_".Trim() })
    Assert 'a second run is BLOCKED while the first holds the lock' ($r -contains 'BLOCKED')
    if ($r -notcontains 'BLOCKED') { Write-Host ("        probe said: " + ($r -join ' | ')) -ForegroundColor DarkYellow }
    $p.WaitForExit(40000) | Out-Null
    $after = & $psExe -NoProfile -ExecutionPolicy Bypass -File $tryLock -Lock $testLock 2>&1 | ForEach-Object { "$_" }
    Assert '  ...and the lock is FREE again once the first run exits' ($after -contains 'GOT')
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("Update schedule (stagger + run lock): {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
