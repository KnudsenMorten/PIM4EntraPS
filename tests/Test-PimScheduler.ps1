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
Assert "trigger ran immediately (off-cadence)" (($tr | Where-Object { $_.trigger }).Count -eq 1 -and $script:engineHits -eq 1)
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

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass,$fail) -ForegroundColor ($(if($fail){'Red'}else{'Green'}))
if ($fail) { exit 1 }
