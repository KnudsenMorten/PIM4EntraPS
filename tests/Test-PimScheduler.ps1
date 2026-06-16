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

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass,$fail) -ForegroundColor ($(if($fail){'Red'}else{'Green'}))
if ($fail) { exit 1 }
