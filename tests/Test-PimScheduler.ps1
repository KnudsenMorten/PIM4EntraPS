<#
  Offline tests for the PIM4EntraPS scheduler / job runner (PIM-Scheduler.ps1).
  Pure due-calculation, dispatch, tick advancement, lease logic. No network.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-Scheduler.ps1"

$pass=0; $fail=0
function Assert($n,$c){ if($c){ $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }
$now = ([datetime]'2026-06-13T12:00:00Z').ToUniversalTime()   # UTC-kind so comparisons match the runner

Write-Host "=== PIM-Scheduler tests ===" -ForegroundColor Cyan

# next-run
$job = [pscustomobject]@{ name='x'; type='reminders'; intervalMinutes=60; enabled=$true }
Assert "next run = now + interval" ((Get-PimNextRunUtc -Job $job -FromUtc $now) -eq $now.AddMinutes(60))
$job0 = [pscustomobject]@{ name='y'; type='reminders'; intervalMinutes=0; enabled=$true }
Assert "interval<=0 falls back to 60m" ((Get-PimNextRunUtc -Job $job0 -FromUtc $now) -eq $now.AddMinutes(60))

# due detection
Assert "never-run job is due"            (Test-PimJobDue -Job $job -NowUtc $now)
$future = [pscustomobject]@{ name='f'; type='reminders'; intervalMinutes=60; enabled=$true; nextRunUtc=$now.AddMinutes(30).ToString('o') }
Assert "future nextRun -> not due"       (-not (Test-PimJobDue -Job $future -NowUtc $now))
$pastj  = [pscustomobject]@{ name='p'; type='reminders'; intervalMinutes=60; enabled=$true; nextRunUtc=$now.AddMinutes(-5).ToString('o') }
Assert "past nextRun -> due"             (Test-PimJobDue -Job $pastj -NowUtc $now)
$off    = [pscustomobject]@{ name='o'; type='reminders'; intervalMinutes=60; enabled=$false }
Assert "disabled job -> not due"         (-not (Test-PimJobDue -Job $off -NowUtc $now))

# Get-PimDueJobs filters
$set = @($job, $future, $pastj, $off)
$due = @(Get-PimDueJobs -Jobs $set -NowUtc $now)
Assert "Get-PimDueJobs returns the 2 due" ($due.Count -eq 2 -and ($due.name -contains 'x') -and ($due.name -contains 'p'))

# default schedule shape
$sched = @(Get-PimDefaultJobSchedule)
Assert "default schedule has the core job types" ((($sched.type) -contains 'queue-apply') -and (($sched.type) -contains 'escalations') -and (($sched.type) -contains 'engine-full'))
Assert "msp-pull disabled by default"   (($sched | Where-Object { $_.type -eq 'msp-pull' }).enabled -eq $false)

# tenant-cache refresh job (engine/jobs/GUI alignment fix)
Assert "tenant-cache is a known job type"          ($script:PimJobTypes -contains 'tenant-cache')
$tcJob = @($sched | Where-Object { $_.type -eq 'tenant-cache' })
Assert "default schedule includes a tenant-cache job" ($tcJob.Count -eq 1)
Assert "tenant-cache enabled by default"           ($tcJob[0].enabled -eq $true)
Assert "tenant-cache cadence inside 24h freshness window" ($tcJob[0].intervalMinutes -gt 0 -and $tcJob[0].intervalMinutes -lt 1440)
# default handler is registered + degrades to a no-op when the refresher is absent
Initialize-PimDefaultJobHandlers
Assert "tenant-cache handler registered by default" ((Get-PimJobHandler -Type 'tenant-cache') -ne $null)
$tcNoop = Invoke-PimScheduledJob -Job ([pscustomobject]@{ name='tc'; type='tenant-cache' }) -NowUtc $now
Assert "tenant-cache no-ops (logged) without the refresher" ($tcNoop.ok -and $tcNoop.result.ran -eq $false -and $tcNoop.result.detail -like 'no-handler:Invoke-PimTenantListRefresh*')
# with a stub refresher present, the handler drives it (and WhatIf writes nothing)
$script:tcRefreshHits = 0
function Invoke-PimTenantListRefresh { param([switch]$Quiet) $script:tcRefreshHits++; [ordered]@{ ok=$true; results=@{ 'entra-roles'=@{ ok=$true; count=3 } } } }
$tcWhatIf = Invoke-PimScheduledJob -Job ([pscustomobject]@{ name='tc'; type='tenant-cache' }) -NowUtc $now -WhatIf
Assert "tenant-cache WhatIf does not call the refresher" ($tcWhatIf.ok -and $script:tcRefreshHits -eq 0 -and $tcWhatIf.result.detail -like '*whatif*')
$tcRun = Invoke-PimScheduledJob -Job ([pscustomobject]@{ name='tc'; type='tenant-cache' }) -NowUtc $now
Assert "tenant-cache live run calls the refresher" ($tcRun.ok -and $script:tcRefreshHits -eq 1 -and $tcRun.result.ran -eq $true -and $tcRun.result.detail -like '*entra-roles=3*')
Remove-Item function:Invoke-PimTenantListRefresh -ErrorAction SilentlyContinue

# handler registry + dispatch
$script:hit = 0
Register-PimJobHandler -Type 'reminders' -Handler { param($j,$n,$w) $script:hit++; [pscustomobject]@{ ran=$true; detail="hit=$script:hit" } }
$r = Invoke-PimScheduledJob -Job $job -NowUtc $now
Assert "dispatch runs the registered handler" ($r.ok -and $script:hit -eq 1)
$rUnknown = Invoke-PimScheduledJob -Job ([pscustomobject]@{ name='z'; type='does-not-exist' }) -NowUtc $now
Assert "unknown type -> no-handler, no crash" (-not $rUnknown.ok -and $rUnknown.detail -eq 'no-handler-registered')

# tick advances nextRun + persists (in-memory)
$global:PIM_SchedulerStatePath = $null
$jobs = @([pscustomobject]@{ name='rem'; type='reminders'; intervalMinutes=60; enabled=$true })
$res = @(Invoke-PimSchedulerTick -Jobs $jobs -NowUtc $now)
Assert "tick ran the due job"             ($res.Count -eq 1 -and $res[0].name -eq 'rem')
Assert "tick advanced nextRunUtc"         ($jobs[0].nextRunUtc -eq $now.AddMinutes(60).ToString('o'))
Assert "same job not due again now"        (-not (Test-PimJobDue -Job $jobs[0] -NowUtc $now))

# lease logic
Assert "no lease -> free"                 (Test-PimSchedulerLeaseFree -Lease $null -Owner 'A' -NowUtc $now)
Assert "own lease -> free"                (Test-PimSchedulerLeaseFree -Lease ([pscustomobject]@{owner='A';expiresUtc=$now.AddMinutes(10).ToString('o')}) -Owner 'A' -NowUtc $now)
Assert "other live lease -> not free"     (-not (Test-PimSchedulerLeaseFree -Lease ([pscustomobject]@{owner='B';expiresUtc=$now.AddMinutes(10).ToString('o')}) -Owner 'A' -NowUtc $now))
Assert "other expired lease -> free"      (Test-PimSchedulerLeaseFree -Lease ([pscustomobject]@{owner='B';expiresUtc=$now.AddMinutes(-1).ToString('o')}) -Owner 'A' -NowUtc $now)

# BUG-02: a HELD lease whose expiry cannot be READ must be treated as HELD. The old code
# fell through to "free", so an unreadable stamp let every instance run the tick at once --
# the double-apply the lease exists to prevent. One skipped tick is recoverable; a
# concurrent engine apply against the same tenant is not.
# NB: '2026-06-1' is deliberately NOT in this list -- it parses fine as 1 June, so it is
# a readable stamp, not a corrupt one. Only genuinely unreadable input belongs here.
foreach ($bad in @('', '   ', 'not-a-date', '2026-13-45T99:99:99Z', '2026-06-17T12:')) {
    $lease = [pscustomobject]@{ owner = 'B'; expiresUtc = $bad }
    Assert "BUG-02: unreadable expiry '$bad' -> lease treated as HELD (fail-closed)" (
        -not (Test-PimSchedulerLeaseFree -Lease $lease -Owner 'A' -NowUtc $now -WarningAction SilentlyContinue))
}
# A MISSING expiresUtc property entirely (an older/partial lease record) is equally unreadable.
Assert "BUG-02: lease with no expiresUtc at all -> HELD" (
    -not (Test-PimSchedulerLeaseFree -Lease ([pscustomobject]@{ owner = 'B' }) -Owner 'A' -NowUtc $now -WarningAction SilentlyContinue))
# ...but an unreadable expiry on OUR OWN lease is still ours -- owner match short-circuits
# before the expiry is consulted, so fail-closed must not lock an instance out of itself.
Assert "BUG-02: our own lease is still ours even with an unreadable expiry" (
    Test-PimSchedulerLeaseFree -Lease ([pscustomobject]@{ owner = 'A'; expiresUtc = 'garbage' }) -Owner 'A' -NowUtc $now)
# IMP-02: expiresUtc is written with ToString('o'); parse it INVARIANTLY so a da-DK host
# can read the stamp it wrote itself. Proven by parsing under a comma-decimal culture.
$prevCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
try {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('da-DK')
    Assert "IMP-02: live lease still reads as HELD under da-DK" (
        -not (Test-PimSchedulerLeaseFree -Lease ([pscustomobject]@{owner='B';expiresUtc=$now.AddMinutes(10).ToString('o')}) -Owner 'A' -NowUtc $now))
    Assert "IMP-02: expired lease still reads as FREE under da-DK" (
        Test-PimSchedulerLeaseFree -Lease ([pscustomobject]@{owner='B';expiresUtc=$now.AddMinutes(-1).ToString('o')}) -Owner 'A' -NowUtc $now)
} finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $prevCulture }

# on-demand triggers (event-driven recompute)
$global:PIM_DataWatermark = $null
Save-PimJobTriggers -Triggers @()
$script:engineHits = 0
Register-PimJobHandler -Type 'engine-delta' -Handler { param($j,$n,$w) $script:engineHits++; [pscustomobject]@{ ran=$true; detail="delta scope=$($j.scope)" } }
Add-PimJobTrigger -Type 'engine-delta' -Scope 'EntraRoles' -Reason 'sql-change' -NowUtc $now | Out-Null
Assert "trigger enqueued"                 (@(Get-PimPendingTriggers).Count -eq 1)
Assert "trigger dedup (same type+scope)"  ((Add-PimJobTrigger -Type 'engine-delta' -Scope 'EntraRoles' -NowUtc $now) -eq 1)
$idleJobs = @([pscustomobject]@{ name='full'; type='engine-full'; intervalMinutes=1440; enabled=$true; nextRunUtc=$now.AddMinutes(60).ToString('o') })
$tr = @(Invoke-PimSchedulerTick -Jobs $idleJobs -NowUtc $now)
Assert "trigger ran immediately (off-cadence)" (@($tr | Where-Object { $_.trigger }).Count -eq 1 -and $script:engineHits -eq 1)
Assert "triggers cleared after run"       (@(Get-PimPendingTriggers).Count -eq 0)

# watermark change auto-enqueues a recompute
$script:engineHits = 0
$global:PIM_DataWatermark = 'v2'
$tw = @(Invoke-PimSchedulerTick -Jobs $idleJobs -NowUtc $now.AddMinutes(1))
Assert "watermark change triggered recompute" ($script:engineHits -eq 1)
$tw2 = @(Invoke-PimSchedulerTick -Jobs $idleJobs -NowUtc $now.AddMinutes(2))
Assert "same watermark -> no re-trigger"   ($script:engineHits -eq 1)
Assert "watermark-changed compare is pure" ((Test-PimWatermarkChanged -LastSeen 'v2' -Current 'v3') -and -not (Test-PimWatermarkChanged -LastSeen 'v3' -Current 'v3'))

# default handlers initialize + a bounded loop runs one tick
Initialize-PimDefaultJobHandlers
Assert "default handlers registered"      ((Get-PimJobHandler -Type 'escalations') -ne $null)
Start-PimScheduler -IntervalSeconds 1 -MaxTicks 1 -WhatIf | Out-Null
Assert "bounded loop completed one tick"  $true

# ---- run history + per-run logs + jobs-status view model (GUI Jobs tab) ----
# Use a temp file-backed store so the history round-trips like the real (cross-process) path.
$tmpDir = Join-Path ([IO.Path]::GetTempPath()) ("pimsched-" + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $tmpDir -Force)
$global:PIM_SchedulerStatePath = Join-Path $tmpDir 'pim-scheduler-state.json'
$script:PimRunHistory = $null
Save-PimJobRunHistory -Runs @()
Assert "run history starts empty"          (@(Get-PimJobRunHistory).Count -eq 0)

# a finished run is recorded with status/log/duration from a dispatch result
$rJob = [pscustomobject]@{ name='reminders'; type='reminders'; intervalMinutes=720; enabled=$true }
$dispatch = [pscustomobject]@{ name='reminders'; type='reminders'; ok=$true; detail='upcoming=2 renew=0'; result=[pscustomobject]@{ ran=$true; detail='upcoming=2 renew=0'; log=@('line A','line B') } }
$rec = Write-PimJobRunRecord -Job $rJob -Result $dispatch -StartedUtc $now
Assert "run record written + readable"     (@(Get-PimJobRunHistory).Count -eq 1)
Assert "run record status=completed"       ($rec.status -eq 'completed' -and $rec.ok -and $rec.ran)
Assert "run record carries a runId"        ("$($rec.runId)".Trim().Length -gt 0)
$logRec = Get-PimJobRunLog -RunId $rec.runId
Assert "per-run log readable by runId"      ($logRec -and $logRec.log -like '*line A*' -and $logRec.log -like '*upcoming=2*')
Assert "unknown runId -> null log"          ($null -eq (Get-PimJobRunLog -RunId 'nope'))

# BUG-04 (2026-08-05) -- a LONG-duration run record must be WRITTEN, never throw.
# durationMs was `[int]([Math]::Max(0, <double>))`. The literal 0 is an Int32, so the
# Max(Int32,Int32) overload was selected and TotalMilliseconds got coerced to Int32 ->
# "Value was either too large or too small for an Int32" once the duration passed
# Int32.MaxValue ms (~24.9 days). That threw away the ENTIRE run record.
# This suite pins $now to a fixed date for determinism, so real elapsed time crossed
# that threshold on ~2026-07-08 and the suite went red BY CALENDAR, with no code change.
# Assert the boundary explicitly so it can never rot back in, on any date.
$longStart = ([datetime]::UtcNow).AddDays(-40)          # > 24.9 days => overflowed before
$longRec = $null
$longThrew = $false
try { $longRec = Write-PimJobRunRecord -Job $rJob -Result $dispatch -StartedUtc $longStart }
catch { $longThrew = $true; Write-Host "      ($($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
Assert "BUG-04: 40-day duration record is written (no Int32 overflow)" (-not $longThrew -and $null -ne $longRec)
Assert "BUG-04: durationMs exceeds Int32.MaxValue and is exact"        ($null -ne $longRec -and [int64]$longRec.durationMs -gt [int]::MaxValue)
Assert "BUG-04: a NEGATIVE elapsed (clock skew) still clamps to 0"     ((Write-PimJobRunRecord -Job $rJob -Result $dispatch -StartedUtc ([datetime]::UtcNow).AddHours(2)).durationMs -eq 0)
# READ-BACK matters as much as the write: fixing only the write site left [int] narrowing
# casts in the history normalizer and the jobs-status view model, which re-threw on read.
$longReadThrew = $false; $longBack = $null
try { $longBack = @(Get-PimJobRunHistory | Where-Object { $_.runId -eq $longRec.runId })[0] } catch { $longReadThrew = $true }
Assert "BUG-04: the long record READS BACK (history normalizer not narrowed)" (-not $longReadThrew -and $null -ne $longBack -and [int64]$longBack.durationMs -gt [int]::MaxValue)
$statusThrew = $false
try { [void](Get-PimJobsStatus) } catch { $statusThrew = $true; Write-Host "      ($($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
Assert "BUG-04: the jobs-status view model builds with a long duration"        (-not $statusThrew)

# a failed run is recorded as failed
$fJob = [pscustomobject]@{ name='delta-admins'; type='engine-delta'; scope='Admins'; intervalMinutes=15; enabled=$true }
$failDispatch = [pscustomobject]@{ name='delta-admins'; type='engine-delta'; ok=$false; detail='error: boom' }
[void](Write-PimJobRunRecord -Job $fJob -Result $failDispatch -StartedUtc $now.AddMinutes(1))
$failRow = @(Get-PimJobRunHistory -Name 'delta-admins')[0]
Assert "failed run recorded as failed"     ($failRow.status -eq 'failed' -and -not $failRow.ok)

# an in-progress run (no finishedUtc) marks the job running and sorts to the TOP
$running = [pscustomobject]@{ runId='run-inprog'; name='full-reconcile'; type='engine-full'; scope='All'; ok=$true; ran=$true; status='running'; detail='engine Full [All] running'; startedUtc=$now.AddMinutes(5).ToString('o'); finishedUtc=''; durationMs=0; log='engine Full started' }
Add-PimJobRunRecord -Run $running
$jobsForStatus = @($rJob, $fJob, [pscustomobject]@{ name='full-reconcile'; type='engine-full'; scope='All'; intervalMinutes=1440; enabled=$true })
$vm = Get-PimJobsStatus -Jobs $jobsForStatus -NowUtc $now
Assert "jobs-status has a row per job"      ($vm.total -eq 3 -and @($vm.jobs).Count -eq 3)
Assert "in-progress count = 1"              ($vm.runningCount -eq 1)
Assert "in-progress job sorts to the TOP"   ($vm.jobs[0].name -eq 'full-reconcile' -and $vm.jobs[0].inProgress -and $vm.jobs[0].status -eq 'running')
$remRow = @($vm.jobs | Where-Object { $_.name -eq 'reminders' })[0]
Assert "row carries cadence + last result"  ($remRow.cadence -eq 'every 12 h' -and $remRow.lastResult -eq 'upcoming=2 renew=0' -and $remRow.lastOk)
$admRow = @($vm.jobs | Where-Object { $_.name -eq 'delta-admins' })[0]
Assert "failed row exposes lastOk=false"    (-not $admRow.lastOk -and $admRow.status -eq 'failed')
Assert "cadence formatting (daily/min)"     ((Format-PimCadence -IntervalMinutes 1440) -eq 'daily' -and (Format-PimCadence -IntervalMinutes 5) -eq 'every 5 min' -and (Format-PimCadence -IntervalMinutes 0) -eq 'on-demand')

# per-job ring trim keeps history bounded
1..($script:PimRunHistoryMax + 5) | ForEach-Object { [void](Write-PimJobRunRecord -Job $rJob -Result $dispatch -StartedUtc $now.AddSeconds($_)) }
Assert "history ring trims per job"         (@(Get-PimJobRunHistory -Name 'reminders').Count -le $script:PimRunHistoryMax)

# ---- never-run rows synthesize a next-run (no dead view) --------------------
# A job with NO run history + NO persisted lastRunUtc must surface neverRun=true
# and a computed (synthesized) nextRunUtc so the GUI shows "next run <t>" instead
# of an empty "-" for both last and next.
$script:PimRunHistory = $null
Save-PimJobRunHistory -Runs @()
$freshJobs = @([pscustomobject]@{ name='delta-pim-azure'; type='engine-delta'; scope='AzRes'; intervalMinutes=30; enabled=$true })
$vmFresh = Get-PimJobsStatus -Jobs $freshJobs -NowUtc $now
$freshRow = @($vmFresh.jobs)[0]
Assert "never-run row flagged neverRun"      ($freshRow.neverRun -eq $true)
Assert "never-run row synthesizes nextRunUtc" ($freshRow.nextRunSynthesized -eq $true -and "$($freshRow.nextRunUtc)".Trim() -ne '')
Assert "synthesized next = now + cadence"     ($freshRow.nextRunUtc -eq $now.AddMinutes(30).ToString('o'))
Assert "never-run row has no last run"        ("$($freshRow.lastRunUtc)".Trim() -eq '')
# a DISABLED never-run job does not synthesize a next-run (it isn't scheduled)
$offJobs = @([pscustomobject]@{ name='msp-pull'; type='msp-pull'; intervalMinutes=240; enabled=$false })
$vmOff = @((Get-PimJobsStatus -Jobs $offJobs -NowUtc $now).jobs)[0]
Assert "disabled never-run -> no synthesized next" (-not $vmOff.nextRunSynthesized -and "$($vmOff.nextRunUtc)".Trim() -eq '')
# a job WITH a run is not "never run" and keeps its real last-run time
[void](Write-PimJobRunRecord -Job $freshJobs[0] -Result ([pscustomobject]@{ name='delta-pim-azure'; type='engine-delta'; ok=$true; detail='ran'; result=[pscustomobject]@{ ran=$true } }) -StartedUtc $now)
$vmRan = @((Get-PimJobsStatus -Jobs $freshJobs -NowUtc $now).jobs)[0]
Assert "ran row clears neverRun"             ($vmRan.neverRun -eq $false -and "$($vmRan.lastRunUtc)".Trim() -ne '')

# ---- force-start ("Run now") records running -> completed -------------------
$script:PimRunHistory = $null
Save-PimJobRunHistory -Runs @()
$script:forceHits = 0
Register-PimJobHandler -Type 'engine-delta' -Handler { param($j,$n,$w) $script:forceHits++; [pscustomobject]@{ ran=$true; detail="forced scope=$($j.scope)"; log=@('forced run log') } }
$fsJob = [pscustomobject]@{ name='delta-pim-entra'; type='engine-delta'; scope='EntraRoles'; intervalMinutes=20; enabled=$true }
$fs = Invoke-PimJobForceStart -Name 'delta-pim-entra' -Job $fsJob -NowUtc $now
Assert "force-start ok + ran the handler"     ($fs.ok -and $script:forceHits -eq 1 -and "$($fs.runId)".Trim().Length -gt 0)
$fsHist = @(Get-PimJobRunHistory -Name 'delta-pim-entra')
Assert "force-start leaves exactly ONE record (placeholder replaced by runId)" ($fsHist.Count -eq 1)
Assert "force-start record is completed + trigger" ($fsHist[0].status -eq 'completed' -and $fsHist[0].trigger -eq $true -and "$($fsHist[0].reason)" -eq 'force-start')
$fsLog = Get-PimJobRunLog -RunId $fs.runId
Assert "force-start run log readable by runId" ($fsLog -and $fsLog.log -like '*forced run log*')
# unknown job name -> clear error, no record written
$fsBad = Invoke-PimJobForceStart -Name 'no-such-job' -NowUtc $now
Assert "force-start unknown job -> ok=false"  (-not $fsBad.ok -and "$($fsBad.error)" -like '*no job named*')
Remove-Item function:Invoke-PimTenantListRefresh -ErrorAction SilentlyContinue

# ============================================================================
# [M6] failure history + overdue detection + acknowledge / clear (REQUIREMENTS s28)
# ============================================================================
Write-Host "`n--- [M6] Jobs controls: failure history / overdue / acknowledge ---" -ForegroundColor Cyan

# ---- failure history (PURE): recent runs with pass/fail/when, failures surfaced ----
$m6Runs = @(
    [pscustomobject]@{ runId='m1'; name='delta-admins'; type='engine-delta'; ok=$true;  status='completed'; detail='ok';        startedUtc=$now.AddMinutes(-50).ToString('o'); finishedUtc=$now.AddMinutes(-50).ToString('o'); durationMs=120 }
    [pscustomobject]@{ runId='m2'; name='delta-admins'; type='engine-delta'; ok=$false; status='failed';    detail='error: 401';  startedUtc=$now.AddMinutes(-40).ToString('o'); finishedUtc=$now.AddMinutes(-40).ToString('o'); durationMs=90 }
    [pscustomobject]@{ runId='m3'; name='delta-admins'; type='engine-delta'; ok=$false; status='failed';    detail='error: 500';  startedUtc=$now.AddMinutes(-30).ToString('o'); finishedUtc=$now.AddMinutes(-30).ToString('o'); durationMs=70 }
    [pscustomobject]@{ runId='m4'; name='delta-admins'; type='engine-delta'; ok=$true;  status='completed'; detail='recovered'; startedUtc=$now.AddMinutes(-10).ToString('o'); finishedUtc=$now.AddMinutes(-10).ToString('o'); durationMs=80 }
    # a still-running placeholder MUST be excluded from finished history
    [pscustomobject]@{ runId='m5'; name='delta-admins'; type='engine-delta'; ok=$true;  status='running';   detail='running...'; startedUtc=$now.ToString('o'); finishedUtc=''; durationMs=0 }
    # another job's run must not leak into a name-filtered view
    [pscustomobject]@{ runId='x1'; name='reminders';    type='reminders';    ok=$false; status='failed';    detail='error: boom'; startedUtc=$now.AddMinutes(-5).ToString('o');  finishedUtc=$now.AddMinutes(-5).ToString('o');  durationMs=10 }
)
$fh = Get-PimRunFailureHistory -Runs $m6Runs -Name 'delta-admins'
Assert "failure history filters to the named job" (@($fh.runs).Count -eq 4 -and -not (@($fh.runs.name) -contains 'reminders'))
Assert "failure history is newest-first"          ($fh.runs[0].runId -eq 'm4' -and $fh.runs[3].runId -eq 'm1')
Assert "failure history excludes running placeholder" (-not (@($fh.runs.runId) -contains 'm5'))
Assert "failure history surfaces the 2 failures"  ($fh.failureCount -eq 2 -and ($fh.failures.runId -contains 'm2') -and ($fh.failures.runId -contains 'm3'))
Assert "failed runs flagged failed + ok=false"    ($fh.failures[0].failed -and -not $fh.failures[0].ok)
Assert "all failures unacked when no acks given"  ($fh.unackedFailures -eq 2)
# -Take bounds the recent window
$fhTake = Get-PimRunFailureHistory -Runs $m6Runs -Name 'delta-admins' -Take 2
Assert "Take bounds the recent window"            (@($fhTake.runs).Count -eq 2 -and $fhTake.runs[0].runId -eq 'm4')
# acknowledged failures are flagged + drop out of the unacked count
$fhAck = Get-PimRunFailureHistory -Runs $m6Runs -Name 'delta-admins' -AcknowledgedRunIds @('m2')
Assert "acknowledged failure is flagged"          ((@($fhAck.failures | Where-Object { $_.runId -eq 'm2' })[0]).acknowledged -eq $true)
Assert "ack drops one from unacked failures"      ($fhAck.failureCount -eq 2 -and $fhAck.unackedFailures -eq 1)

# ---- overdue detection (PURE): last-run + interval < now (grace) ----
$ovJob = [pscustomobject]@{ name='delta-admins'; type='engine-delta'; intervalMinutes=15; enabled=$true }
# last run 60m ago, 15m cadence (grace=15m) -> expected at -45m, deadline at -30m -> overdue
$odLate = Get-PimJobOverdueState -Job $ovJob -NowUtc $now -LastRunUtc $now.AddMinutes(-60).ToString('o')
Assert "overdue when last-run + interval well past now" ($odLate.overdue -and $odLate.overdueByMinutes -ge 45)
# last run 5m ago -> next due at +10m -> not overdue
$odFresh = Get-PimJobOverdueState -Job $ovJob -NowUtc $now -LastRunUtc $now.AddMinutes(-5).ToString('o')
Assert "not overdue when last run is recent"       (-not $odFresh.overdue -and $odFresh.reason -eq 'on-time')
# explicit nextRunUtc in the past (beyond grace) -> overdue
$odNext = Get-PimJobOverdueState -Job $ovJob -NowUtc $now -NextRunUtc $now.AddMinutes(-30).ToString('o')
Assert "overdue when persisted next-run is past grace" ($odNext.overdue)
# a job currently running is never "overdue"
$odRun = Get-PimJobOverdueState -Job $ovJob -NowUtc $now -LastRunUtc $now.AddMinutes(-99).ToString('o') -InProgress $true
Assert "running job is not overdue"                (-not $odRun.overdue -and $odRun.reason -eq 'running')
# a disabled job is never overdue
$odOff = Get-PimJobOverdueState -Job ([pscustomobject]@{ name='x'; intervalMinutes=15; enabled=$false }) -NowUtc $now -LastRunUtc $now.AddMinutes(-999).ToString('o')
Assert "disabled job is not overdue"               (-not $odOff.overdue -and $odOff.reason -eq 'disabled')
# an on-demand (interval<=0) job is never overdue
$odOnDemand = Get-PimJobOverdueState -Job ([pscustomobject]@{ name='q'; intervalMinutes=0; enabled=$true }) -NowUtc $now -LastRunUtc $now.AddMinutes(-999).ToString('o')
Assert "on-demand job is not overdue"              (-not $odOnDemand.overdue -and $odOnDemand.reason -eq 'on-demand')
# a never-run job (no last-run, no next-run) is not "overdue" (just never fired)
$odNever = Get-PimJobOverdueState -Job $ovJob -NowUtc $now
Assert "never-run job is not overdue"              (-not $odNever.overdue -and $odNever.reason -eq 'never-run')

# ---- acknowledge / clear (store-backed, file path) ----
$ackDir = Join-Path ([IO.Path]::GetTempPath()) ("pimack-" + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $ackDir -Force)
$global:PIM_SchedulerStatePath = Join-Path $ackDir 'pim-scheduler-state.json'
$script:PimAckRunIds = $null
Save-PimRunAcknowledgements -RunIds @()
Assert "ack store starts empty"                    (@(Get-PimRunAcknowledgements).Count -eq 0)
$ackR = Set-PimRunAcknowledged -RunId 'm2'
Assert "acknowledge marks the run"                 ($ackR.ok -and $ackR.acknowledged -and $ackR.changed -and (Test-PimRunAcknowledged -RunId 'm2'))
$ackR2 = Set-PimRunAcknowledged -RunId 'm2'
Assert "acknowledge is idempotent"                 ($ackR2.ok -and -not $ackR2.changed -and (@(Get-PimRunAcknowledgements).Count -eq 1))
# round-trips via the file store (cross-process path)
$script:PimAckRunIds = $null
Assert "acknowledgement persists to the store"     (Test-PimRunAcknowledged -RunId 'm2')
$clrR = Set-PimRunAcknowledged -RunId 'm2' -Clear
Assert "clear un-acknowledges the run"             ($clrR.ok -and -not $clrR.acknowledged -and $clrR.changed -and -not (Test-PimRunAcknowledged -RunId 'm2'))
$clrR2 = Set-PimRunAcknowledged -RunId 'm2' -Clear
Assert "clear is idempotent"                       (-not $clrR2.changed)
Assert "ack requires a runId"                      (-not (Set-PimRunAcknowledged -RunId '   ').ok)

# ---- Get-PimJobFailureHistory (store-backed) reflects the ack store ----
$script:PimRunHistory = $null
Save-PimJobRunHistory -Runs $m6Runs
Save-PimRunAcknowledgements -RunIds @('m3')
$jfh = Get-PimJobFailureHistory -Name 'delta-admins'
Assert "store-backed failure history surfaces failures" ($jfh.failureCount -eq 2)
Assert "store-backed failure history honours acks"  ($jfh.unackedFailures -eq 1 -and (@($jfh.failures | Where-Object { $_.runId -eq 'm3' })[0]).acknowledged)

# ---- Get-PimJobsStatus surfaces overdue + ack + recent-failure counts ----
# Use the FINISHED runs only (drop the still-running placeholder m5 -- a job with a live
# run is correctly NOT overdue; here we assert the genuinely-missed-window case).
$m6Finished = @($m6Runs | Where-Object { "$($_.status)" -ne 'running' })
$script:PimRunHistory = $null
Save-PimJobRunHistory -Runs $m6Finished
Save-PimRunAcknowledgements -RunIds @()
# job whose last run was long ago + a persisted next-run in the past -> overdue row
$statusJobs = @([pscustomobject]@{ name='delta-admins'; type='engine-delta'; intervalMinutes=15; enabled=$true; nextRunUtc=$now.AddMinutes(-40).ToString('o') })
$svm = Get-PimJobsStatus -Jobs $statusJobs -NowUtc $now
$srow = @($svm.jobs | Where-Object { $_.name -eq 'delta-admins' })[0]
Assert "jobs-status row carries overdue flag"      ($srow.overdue -eq $true -and $srow.overdueByMinutes -gt 0)
Assert "jobs-status overdueCount summary"          ($svm.overdueCount -ge 1)
Assert "jobs-status row carries recent-failure count" ($srow.recentFailureCount -eq 2 -and $srow.unackedFailureCount -eq 2)
Assert "jobs-status failingCount summary"          ($svm.failingCount -ge 1)
# acknowledge BOTH recent failures -> unacked drops to 0, failingCount drops
Save-PimRunAcknowledgements -RunIds @('m2','m3')
$svm2 = Get-PimJobsStatus -Jobs $statusJobs -NowUtc $now
$srow2 = @($svm2.jobs | Where-Object { $_.name -eq 'delta-admins' })[0]
Assert "acks clear the unacked-failure signal"     ($srow2.unackedFailureCount -eq 0 -and $svm2.failingCount -eq 0 -and $srow2.recentFailureCount -eq 2)

$global:PIM_SchedulerStatePath = $null
$script:PimRunHistory = $null
$script:PimAckRunIds = $null
Remove-Item -LiteralPath $ackDir -Recurse -Force -ErrorAction SilentlyContinue

$global:PIM_SchedulerStatePath = $null
$script:PimRunHistory = $null
Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# BUG-36 -- the lease is now ACQUIRED, not merely checked.
#
# Test-PimSchedulerLeaseFree was always correct and always tested; the defect was that NOTHING
# EVER WROTE A LEASE, so the check found none and permitted every tick. These tests therefore
# assert the WRITE side, and above all that a SECOND runner is actually REFUSED -- the one
# behaviour that has never worked.
#
# A fake store stands in for pim.Settings so the compare-and-set can be driven deterministically,
# including the case that matters most: the value changing BETWEEN our read and our write.
# ---------------------------------------------------------------------------
Write-Host "`n--- BUG-36: lease acquisition ---" -ForegroundColor Cyan

$script:FakeStore = @{}          # Name -> raw json (or $null)
$script:FakeRace  = $null        # set to a scriptblock to mutate the store mid-CAS
function Get-PimSqlSettingRaw { param($ConnectionString, $Name) return $script:FakeStore[$Name] }
function Set-PimSqlSettingIfUnchanged {
    param($ConnectionString, $Name, $NewValueJson, $ExpectedValueJson)
    if ($script:FakeRace) { & $script:FakeRace; $script:FakeRace = $null }   # simulate a racer
    $cur = $script:FakeStore[$Name]
    if ("$cur" -ne "$ExpectedValueJson") { return 0 }                        # lost the race
    $script:FakeStore[$Name] = $NewValueJson
    return 1
}
function Get-PimSchedulerLeaseStoreCs { return 'Server=fake;Database=fake' }

$t0 = ([datetime]'2026-08-09T10:00:00Z').ToUniversalTime()

# pure: the lease document
$lease = New-PimSchedulerLease -Owner 'A' -NowUtc $t0 -TtlMinutes 15
Assert "New lease carries the owner"        ($lease.owner -eq 'A')
Assert "New lease expires now+TTL"          (([datetime]$lease.expiresUtc).ToUniversalTime() -eq $t0.AddMinutes(15))
Assert "TTL below 1 minute is clamped"      ((([datetime](New-PimSchedulerLease -Owner 'A' -NowUtc $t0 -TtlMinutes 0).expiresUtc).ToUniversalTime()) -eq $t0.AddMinutes(1))

# pure: renewal timing
Assert "fresh lease is not renew-due"       (-not (Test-PimSchedulerLeaseRenewDue -Lease $lease -NowUtc $t0 -TtlMinutes 15))
Assert "past half-TTL IS renew-due"         (Test-PimSchedulerLeaseRenewDue -Lease $lease -NowUtc $t0.AddMinutes(8) -TtlMinutes 15)
Assert "unparseable expiry IS renew-due"    (Test-PimSchedulerLeaseRenewDue -Lease ([pscustomobject]@{owner='A';expiresUtc='garbage'}) -NowUtc $t0 -TtlMinutes 15)
Assert "missing lease IS renew-due"         (Test-PimSchedulerLeaseRenewDue -Lease $null -NowUtc $t0 -TtlMinutes 15)

# acquisition + the contention that BUG-36 was about
$script:FakeStore = @{}
Assert "A acquires a free lease"            (Request-PimSchedulerLease -Owner 'A' -NowUtc $t0 -TtlMinutes 15)
Assert "the lease was actually WRITTEN"     ([bool]$script:FakeStore['SchedulerLease'])
Assert "stored lease names A"               ((($script:FakeStore['SchedulerLease'] | ConvertFrom-Json).owner) -eq 'A')
Assert "B is REFUSED while A holds it"      (-not (Request-PimSchedulerLease -Owner 'B' -NowUtc $t0.AddMinutes(1) -TtlMinutes 15))
Assert "A re-entering its own lease is ok"  (Request-PimSchedulerLease -Owner 'A' -NowUtc $t0.AddMinutes(1) -TtlMinutes 15)
Assert "B takes over once A's lease EXPIRED"(Request-PimSchedulerLease -Owner 'B' -NowUtc $t0.AddMinutes(30) -TtlMinutes 15)
Assert "stored lease now names B"           ((($script:FakeStore['SchedulerLease'] | ConvertFrom-Json).owner) -eq 'B')

# release
Assert "A cannot release B's lease"         (-not (Remove-PimSchedulerLease -Owner 'A'))
Assert "B releases its own lease"           (Remove-PimSchedulerLease -Owner 'B')
Assert "released lease is empty"            (-not $script:FakeStore['SchedulerLease'])
Assert "A acquires after release"           (Request-PimSchedulerLease -Owner 'A' -NowUtc $t0.AddMinutes(31) -TtlMinutes 15)

# THE race: the store changes between our read and our write. Read-then-write would both
# succeed here -- which is exactly the double-apply the lease exists to prevent.
$script:FakeStore = @{}
$script:FakeRace = { $script:FakeStore['SchedulerLease'] = (New-PimSchedulerLease -Owner 'RACER' -NowUtc $t0 -TtlMinutes 15 | ConvertTo-Json -Depth 4 -Compress) }
Assert "CAS REFUSES when another runner wrote first" (-not (Request-PimSchedulerLease -Owner 'A' -NowUtc $t0 -TtlMinutes 15))
Assert "the racer still owns the lease"     ((($script:FakeStore['SchedulerLease'] | ConvertFrom-Json).owner) -eq 'RACER')

# renewal keeps ownership and pushes the expiry out
$script:FakeStore = @{}
[void](Request-PimSchedulerLease -Owner 'A' -NowUtc $t0 -TtlMinutes 15)
Assert "A renews its lease"                 (Update-PimSchedulerLease -Owner 'A' -NowUtc $t0.AddMinutes(9) -TtlMinutes 15)
Assert "renewal pushed the expiry out"      ((([datetime]($script:FakeStore['SchedulerLease'] | ConvertFrom-Json).expiresUtc).ToUniversalTime()) -eq $t0.AddMinutes(24))
Assert "B cannot renew A's lease"           (-not (Update-PimSchedulerLease -Owner 'B' -NowUtc $t0.AddMinutes(9) -TtlMinutes 15))

# tick-level: a second runner must SKIP, and the holder must release afterwards
$script:FakeStore = @{}
$script:FakeStore['SchedulerLease'] = (New-PimSchedulerLease -Owner 'OTHER' -NowUtc $t0 -TtlMinutes 15 | ConvertTo-Json -Depth 4 -Compress)
$skipped = @(Invoke-PimSchedulerTick -Jobs @() -NowUtc $t0.AddMinutes(1) -Owner 'ME' -WhatIf)
Assert "tick SKIPS when another runner holds the lease" ($skipped.Count -eq 1 -and $skipped[0].type -eq 'lease' -and -not $skipped[0].ran)
Assert "a skipped tick did not steal the lease" ((($script:FakeStore['SchedulerLease'] | ConvertFrom-Json).owner) -eq 'OTHER')

$script:FakeStore = @{}
[void](Invoke-PimSchedulerTick -Jobs @() -NowUtc $t0 -Owner 'ME' -WhatIf)
Assert "tick RELEASES the lease when it finishes" (-not $script:FakeStore['SchedulerLease'])

# a job that throws must still release, or every later cron run is blocked until the TTL
$script:FakeStore = @{}
Register-PimJobHandler -Type 'reminders' -Handler { throw 'boom' }
$boom = [pscustomobject]@{ name='b'; type='reminders'; intervalMinutes=1; enabled=$true }
try { [void](Invoke-PimSchedulerTick -Jobs @($boom) -NowUtc $t0 -Owner 'ME') } catch { }
Assert "lease released even when a job THREW" (-not $script:FakeStore['SchedulerLease'])

# -NoLease escape hatch for offline tests that drive the tick directly
$script:FakeStore = @{}
$script:FakeStore['SchedulerLease'] = (New-PimSchedulerLease -Owner 'OTHER' -NowUtc $t0 -TtlMinutes 15 | ConvertTo-Json -Depth 4 -Compress)
$nl = @(Invoke-PimSchedulerTick -Jobs @() -NowUtc $t0 -Owner 'ME' -NoLease -WhatIf)
Assert "-NoLease bypasses the lease entirely" (-not ($nl | Where-Object { $_.type -eq 'lease' }))

# ---------------------------------------------------------------------------
# BUG-54: WHO the lease names. Everything above proves the lease arbitrates between two
# DIFFERENT owners -- and it always did. The live defect was that in a container every
# runner produced the SAME owner, '-1' ("$env:COMPUTERNAME-$PID" with COMPUTERNAME unset and
# pwsh at pid 1), so the arbitration above was never even reached: each of 12 concurrent
# ca-pim-tick executions saw "that lease is mine" and ran.
# These tests drive the resolver with an environment MAP rather than the real environment --
# the defect survived because the only environment ever exercised was one where COMPUTERNAME
# happened to be set.
Write-Host "`n-- BUG-54: lease owner identity --" -ForegroundColor Cyan

# THE regression test: the exact container shape must not produce '-1'.
$linuxContainerEnv = @{ COMPUTERNAME = $null; HOSTNAME = $null }
Assert "container env + pid 1 does NOT yield the '-1' owner" `
    ((Get-PimSchedulerOwnerId -EnvMap $linuxContainerEnv -ProcessId 1 -MachineName '' -FallbackId 'abc') -ne '-1')
Assert "..and never yields an owner starting with '-'" `
    (-not (Get-PimSchedulerOwnerId -EnvMap $linuxContainerEnv -ProcessId 1 -MachineName '' -FallbackId 'abc').StartsWith('-'))

# preference order -- most specific to the execution first
Assert "ACA job execution name wins" `
    ((Get-PimSchedulerOwnerId -EnvMap @{ CONTAINER_APP_JOB_EXECUTION_NAME='ca-pim-tick-abc123'; HOSTNAME='pod-x'; COMPUTERNAME='WINBOX' } -ProcessId 1) -eq 'ca-pim-tick-abc123-1')
Assert "replica name is used when there is no execution name" `
    ((Get-PimSchedulerOwnerId -EnvMap @{ CONTAINER_APP_REPLICA_NAME='ca-pim-manager--rev1-xyz'; HOSTNAME='pod-x' } -ProcessId 7) -eq 'ca-pim-manager--rev1-xyz-7')
Assert "HOSTNAME is used when neither ACA variable is set" `
    ((Get-PimSchedulerOwnerId -EnvMap @{ HOSTNAME='pod-x' } -ProcessId 7) -eq 'pod-x-7')
Assert "COMPUTERNAME still works (the Windows/VM path is unchanged)" `
    ((Get-PimSchedulerOwnerId -EnvMap @{ COMPUTERNAME='MGMT1' } -ProcessId 7660) -eq 'MGMT1-7660')
Assert "machine name is the fallback when the env map is empty" `
    ((Get-PimSchedulerOwnerId -EnvMap @{} -ProcessId 7 -MachineName 'somehost') -eq 'somehost-7')

# The APP name must never be used: it is shared by every replica, which is the same defect
# wearing a hostname-shaped disguise.
Assert "CONTAINER_APP_NAME is NOT accepted as an identity" `
    (-not ((Get-PimSchedulerOwnerId -EnvMap @{ CONTAINER_APP_NAME='ca-pim-tick' } -ProcessId 1 -FallbackId 'abc') -like '*ca-pim-tick*'))

# nothing identifies us: a guid keeps the lease UNIQUE (correct) while saying it is untraceable
$anon = Get-PimSchedulerOwnerId -EnvMap @{} -ProcessId 1 -MachineName '' -FallbackId 'deadbeef'
Assert "no identity at all -> a labelled unique fallback, not a degenerate value" ($anon -eq 'unidentified-deadbeef')
Assert "the fallback is still a USABLE owner" (Test-PimSchedulerOwnerUsable -Owner $anon)
Assert "no identity and no fallback -> '' (the caller decides, nothing is coined here)" `
    ((Get-PimSchedulerOwnerId -EnvMap @{} -ProcessId 1 -MachineName '' -FallbackId '') -eq '')

# the usability predicate itself
Assert "'-1' is NOT a usable owner"          (-not (Test-PimSchedulerOwnerUsable -Owner '-1'))
Assert "'' is NOT a usable owner"            (-not (Test-PimSchedulerOwnerUsable -Owner ''))
Assert "whitespace is NOT a usable owner"    (-not (Test-PimSchedulerOwnerUsable -Owner '   '))
Assert "'MGMT1-7660' IS usable"              (Test-PimSchedulerOwnerUsable -Owner 'MGMT1-7660')
Assert "an ACA replica name with '--' IS usable (dashes are legal INSIDE the host half)" `
    (Test-PimSchedulerOwnerUsable -Owner 'ca-pim-manager--rev1-xyz-3')

# Defence in depth: a caller that hands in the old value must be REFUSED, not accommodated.
$script:FakeStore = @{}
Assert "Request-PimSchedulerLease REFUSES the '-1' owner" `
    (-not (Request-PimSchedulerLease -Owner '-1' -NowUtc $t0 -TtlMinutes 15 -WarningAction SilentlyContinue))
Assert "..and wrote NOTHING to the store"    (-not $script:FakeStore['SchedulerLease'])

# ..and the tick reports WHICH fault it hit -- a refused owner is not a lost race (BUG-41).
$script:FakeStore = @{}
$bad = @(Invoke-PimSchedulerTick -Jobs @() -NowUtc $t0 -Owner '-1' -WhatIf -WarningAction SilentlyContinue)
Assert "tick with a non-identifying owner does NOT run" ($bad.Count -eq 1 -and $bad[0].type -eq 'lease' -and -not $bad[0].ran)
Assert "..and reports it as NOT ok (a store fault, not a normal skip)" (-not $bad[0].ok)
Assert "..naming the owner as the cause, not contention" ($bad[0].detail -match "not identifying")

# TWO container runners are now told apart -- the property that failed live.
$script:FakeStore = @{}
$r1 = Get-PimSchedulerOwnerId -EnvMap @{ CONTAINER_APP_JOB_EXECUTION_NAME='ca-pim-tick-aaa' } -ProcessId 1
$r2 = Get-PimSchedulerOwnerId -EnvMap @{ CONTAINER_APP_JOB_EXECUTION_NAME='ca-pim-tick-bbb' } -ProcessId 1
Assert "two overlapping executions get DIFFERENT owners" ($r1 -ne $r2)
Assert "the first acquires"                  (Request-PimSchedulerLease -Owner $r1 -NowUtc $t0 -TtlMinutes 15)
Assert "the second is REFUSED (the live failure, now caught)" `
    (-not (Request-PimSchedulerLease -Owner $r2 -NowUtc $t0.AddMinutes(1) -TtlMinutes 15))

# Resolve-PimSchedulerOwner reads the REAL environment; on any host we can run tests on it
# must produce something usable.
$resolved = Resolve-PimSchedulerOwner
Assert "Resolve-PimSchedulerOwner returns a usable owner on this host" (Test-PimSchedulerOwnerUsable -Owner $resolved)
Assert "..and an explicit owner always wins" ((Resolve-PimSchedulerOwner -Owner 'EXPLICIT') -eq 'EXPLICIT')

# ---------------------------------------------------------------------------
# BUG-41: what the CAS actually BINDS to SQL for "expected absent".
#
# Everything above this line drives a fake store whose parameters are UNTYPED, so $null
# survives into it. The real Set-PimSqlSettingIfUnchanged declares [string]$ExpectedValueJson,
# and PowerShell coerces $null to '' at that boundary -- so the real function bound @e='' where
# the stub saw $null, took the ELSE branch, and could never reach the INSERT that creates the
# lease. 132 green tests said otherwise because the stub was more permissive than the thing it
# stood in for. Live result: two ticks 'Succeeded', both claimed contention, pim.Settings empty.
#
# So this drives the REAL function and captures what it hands to SQL. No database needed --
# the binding decision IS the defect, and it is decidable offline.
# ---------------------------------------------------------------------------
Write-Host "`n--- BUG-41: the CAS must bind DBNull for 'expected absent' ---" -ForegroundColor Cyan

. "$here\..\engine\_shared\PIM-SqlStore.ps1"        # real Set-PimSqlSettingIfUnchanged, after the stubs

$script:CapturedParams = $null
function Invoke-PimSqlScalar { param($ConnectionString, $Sql, $Parameters) $script:CapturedParams = $Parameters; return 1 }

[void](Set-PimSqlSettingIfUnchanged -ConnectionString 'x' -Name 'SchedulerLease' -NewValueJson '{"owner":"ME"}' -ExpectedValueJson $null)
Assert "expected-absent binds @e as DBNull (NOT '')"  ($script:CapturedParams.e -is [DBNull])
Assert "  ...so the IF @e IS NULL branch is reachable" (-not ($script:CapturedParams.e -is [string]))
Assert "a real expected value is bound through"        ((Set-PimSqlSettingIfUnchanged -ConnectionString 'x' -Name 'n' -NewValueJson 'b' -ExpectedValueJson 'a') -ge 0 -and $script:CapturedParams.e -eq 'a')

# Release passes -NewValueJson $null to clear the row; the same coercion was storing '' as a
# VALUE instead of NULL, which is a different row state than "no lease".
[void](Set-PimSqlSettingIfUnchanged -ConnectionString 'x' -Name 'SchedulerLease' -NewValueJson $null -ExpectedValueJson '{"owner":"ME"}')
Assert "release binds @v as DBNull (stores NULL, not '')" ($script:CapturedParams.v -is [DBNull])

# And the guard that makes the next failure legible rather than misattributed.
$schedSrc = [System.IO.File]::ReadAllText("$here\..\engine\_shared\PIM-Scheduler.ps1")
Assert "lease-acquire failure is no longer silent"        ($schedSrc -match 'lease acquire FAILED against the SQL store')
Assert "a 0-row CAS on an EMPTY store is called a fault"  ($schedSrc -match 'NOT contention')
Assert "the tick only claims contention when a lease IS present" ($schedSrc -match 'another runner holds the lease \(owner')

# ---- BUG-45: a tick that cannot reach its store must NOT report success -------------------
# Measured on mfnpr 2026-08-09/10: correct SQL coordinates, a valid MI token, "[scheduler] SQL
# store wired -> ..." printed -- and every read failing with "Login failed for user
# '<token-identified principal>'" because the deploy died (BUG-44) before creating the contained
# DB user. FeatureGates unreadable -> built-in defaults -> every job gated off -> exit 0.
# Four consecutive Job executions reported Succeeded having done nothing.
Write-Host "`n-- BUG-45 store-reachability verdict --" -ForegroundColor Cyan

$vOk = Get-PimSchedulerStoreVerdict -Hosted $true -SqlConfigured $true -ConnectionStringResolved $true -ProbeOk $true
Assert "reachable store -> ok"                     ($vOk.level -eq 'ok')

$vMfnpr = Get-PimSchedulerStoreVerdict -Hosted $true -SqlConfigured $true -ConnectionStringResolved $true `
             -ProbeOk $false -ProbeError "Login failed for user '<token-identified principal>'."
Assert "THE mfnpr shape (wired, unreachable, hosted) -> FATAL" ($vMfnpr.level -eq 'fatal')
Assert "and it is named store-unreachable"         ($vMfnpr.reason -eq 'store-unreachable')
Assert "the detail names the missing contained DB user, not a generic SQL error" `
    ($vMfnpr.detail -match 'contained DB user' -and $vMfnpr.detail -match 'Grant-PimMiSql')
Assert "the probe error itself is carried through"  ($vMfnpr.detail -match 'token-identified principal')

# NOT hosted = a workstation run. Degrading to a file store is legitimate there, so the same
# unreachable store is a warning. Making this fatal too would break every local run.
$vLocal = Get-PimSchedulerStoreVerdict -Hosted $false -SqlConfigured $true -ConnectionStringResolved $true -ProbeOk $false -ProbeError 'x'
Assert "unreachable but NOT hosted -> warn, not fatal" ($vLocal.level -eq 'warn')

$vNoCs = Get-PimSchedulerStoreVerdict -Hosted $true -SqlConfigured $true -ConnectionStringResolved $false -ProbeOk $false
Assert "hosted, coordinates set, no connection string -> fatal" ($vNoCs.level -eq 'fatal')
$vNoCsLocal = Get-PimSchedulerStoreVerdict -Hosted $false -SqlConfigured $true -ConnectionStringResolved $false -ProbeOk $false
Assert "same, not hosted -> warn"                  ($vNoCsLocal.level -eq 'warn')

$vHostedNoSql = Get-PimSchedulerStoreVerdict -Hosted $true -SqlConfigured $false -ConnectionStringResolved $false -ProbeOk $false
Assert "hosted with NO sql configured at all -> fatal (ephemeral file store is not a mode)" ($vHostedNoSql.level -eq 'fatal')
$vLocalNoSql = Get-PimSchedulerStoreVerdict -Hosted $false -SqlConfigured $false -ConnectionStringResolved $false -ProbeOk $false
Assert "local with no sql -> ok (file store by design)" ($vLocalNoSql.level -eq 'ok')

# The gate outcome is NOT the trigger. "Every job skipped" is the DESIGNED safe default for a
# protected environment (SEC-02); treating it as failure would make a correctly configured
# tenant fail forever. The verdict must depend only on reachability.
Assert "verdict has no notion of how many jobs ran" `
    (-not (Get-Command Get-PimSchedulerStoreVerdict).Parameters.ContainsKey('JobsRun') -and
     -not (Get-Command Get-PimSchedulerStoreVerdict).Parameters.ContainsKey('SkippedCount'))

# And the entry point must actually ACT on the verdict -- a decision nothing carries out is
# exactly the "correct fix, unreachable from the front door" class that hid BUG-37.
$startSrc = [System.IO.File]::ReadAllText("$here\..\tools\pim-scheduler\Start-PimScheduler.ps1")
Assert "Start-PimScheduler calls the verdict"      ($startSrc -match 'Get-PimSchedulerStoreVerdict')
Assert "a fatal verdict THROWS (non-zero exit is the only signal a cron Job has)" `
    ($startSrc -match "'fatal'\s*\{[\s\S]{0,400}?throw")
Assert "the store is PROVED with a login probe, not assumed from a connection string" `
    ($startSrc -match "Invoke-PimSqlScalar[^\r\n]*'SELECT 1'")
Assert "the probe does NOT depend on pim.Settings existing (schema lands after infra)" `
    ($startSrc -notmatch "Get-PimSqlSetting -ConnectionString \`$global:PIM_SqlConnectionString -Name 'FeatureGates'")

# --- runtime context as PARAMETERS, not env-only (2026-08-10) ----------------
# An external scheduler passes ARGUMENTS, not environment. VisualCron's Execute task has an
# arguments field and no environment field, so before this the only options were machine-wide env
# vars (global, and needing a service restart) or a per-site wrapper script holding real tenant
# values. MEASURED consequence of getting it wrong: with none of them set the scheduler cannot
# reach SQL, cannot read FeatureGates, falls back to 'scheduler.jobs' = disabled, skips all twelve
# jobs -- AND EXITS 0. A green task forever, reconciling nothing.
$startParams = (Get-Command "$here\..\tools\pim-scheduler\Start-PimScheduler.ps1").Parameters
foreach ($p in @('TenantId','ClientId','CertThumbprint','SqlServer','SqlDatabase','StorageBackend','Jobs')) {
    Assert "Start-PimScheduler accepts -$p as a parameter" ($startParams.ContainsKey($p))
}
# Backwards compatibility is the whole risk of this change: the container path and Setup-PimVM's
# machine env vars must keep working when nothing is passed. Each assignment is therefore guarded.
Assert "a supplied -TenantId overrides the environment" ($startSrc -match '\$env:PIM_TenantId\s*=\s*\$TenantId')
Assert "an OMITTED parameter leaves the environment untouched (container/VM paths unaffected)" `
    ($startSrc -match 'if \("\$TenantId"\.Trim\(\)\)\s*\{\s*\$env:PIM_TenantId')
Assert "-Jobs maps to PIM_SCHED_JOBS (empty = ALL jobs, incl. mail + account creation)" `
    ($startSrc -match '\$env:PIM_SCHED_JOBS\s*=\s*\$Jobs')

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass,$fail) -ForegroundColor ($(if($fail){'Red'}else{'Green'}))
if ($fail) { exit 1 }
