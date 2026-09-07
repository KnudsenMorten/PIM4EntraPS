#Requires -Version 5.1
<#
  ALERT-01 -- "a failed job run raises an alert, wherever the run happened".

  THE DEFECT. `engine-failure` had exactly two producers and both were Manager
  REQUEST paths: POST /api/jobs/run (a human clicking Run on the Jobs tab) and the
  "send a test alert" button. PIM-Scheduler.ps1 -- which owns Invoke-PimSchedulerTick
  and actually runs due jobs -- never called Send-PimManagerAlert at all. So a job
  that failed on a SCHEDULED tick raised nothing: alerting worked when somebody was
  already watching and was silent when nobody was.

  WHAT THIS SUITE PINS, and why each one is here rather than assumed:

  1. The decision is PURE and only 'failed' fires. BUG-92 and BUG-114 both came from
     collapsing 'skipped'/'unimplemented' into failed, and BUG-92 put six job types
     permanently red on a healthy deployment. Repeating that here would convert it
     into recurring EMAIL every tick -- strictly worse than a wrong count in a tab.

  2. Both real completion paths raise it. Write-PimJobRunRecord is NOT the single
     choke point it looks like: Invoke-PimJobForceStart builds its own record and
     calls Add-PimJobRunRecord directly, so hooking only the first would have left
     the GUI path silent after the Manager's own call site was removed.

  3. It is NOT hooked into Add-PimJobRunRecord, which looks tidier and is wrong:
     tools/pim-scheduler/Seed-PimSchedulerRuns.ps1 calls it to write SYNTHETIC failed
     runs so the Jobs tab has a representative dataset. Hooking there would make
     seeding a demo send real failure mail to the configured recipients.

  4. The Manager no longer fires it from /api/jobs/run -- that would double-alert now
     that the run itself raises it.

  PURE + offline: no store, no mail path, no clock.
#>
param()
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
. "$root\engine\_shared\PIM-JobAlert.ps1"
. "$here\_shared\PimSourceScope.ps1"

$pass = 0; $fail = 0
function T($n, $c) { if ($c) { $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }

function New-Run {
    param([string]$Status = 'failed', [string]$Name = 'engine-delta', [string]$Detail = 'boom',
          [string]$Type = 'engine', [string]$Scope = 'All', [bool]$Trigger = $false)
    [pscustomobject]@{ name = $Name; type = $Type; scope = $Scope; status = $Status; detail = $Detail; trigger = $Trigger }
}

Write-Host "`n== 1. ONLY a real failure fires ==" -ForegroundColor Cyan
T "'failed' fires"                       ((Get-PimJobFailureAlert -Run (New-Run -Status 'failed')).fire)
T "'completed' does NOT fire"            (-not (Get-PimJobFailureAlert -Run (New-Run -Status 'completed')).fire)
# The two that cost us BUG-92 / BUG-114. A job this deployment does not run, and a
# placeholder handler that does nothing, are not failures -- and mailing about them
# every tick would be a worse version of the same mistake.
T "'skipped' does NOT fire (BUG-92)"     (-not (Get-PimJobFailureAlert -Run (New-Run -Status 'skipped')).fire)
T "'unimplemented' does NOT fire (BUG-114)" (-not (Get-PimJobFailureAlert -Run (New-Run -Status 'unimplemented')).fire)
# The 'running' placeholder is written through the same ring; it must never alert.
T "'running' placeholder does NOT fire"  (-not (Get-PimJobFailureAlert -Run (New-Run -Status 'running')).fire)
T 'a declined decision says why'         ((Get-PimJobFailureAlert -Run (New-Run -Status 'completed')).reason -match 'not a failure')
# Case/whitespace noise in a stored status must not turn a failure into a non-failure.
T 'status is matched case-insensitively' ((Get-PimJobFailureAlert -Run (New-Run -Status 'FAILED')).fire)
# A record with no job name cannot produce a useful alert; refuse rather than mail "Job '' FAILED".
T 'a nameless run does NOT fire'         (-not (Get-PimJobFailureAlert -Run (New-Run -Name '')).fire)

Write-Host "`n== 2. the alert says which job, and whether anyone was watching ==" -ForegroundColor Cyan
$d = Get-PimJobFailureAlert -Run (New-Run -Name 'tenant-cache' -Detail 'graph 403' -Type 'cache' -Scope 'T0')
T 'title names the job'          ($d.title -eq "Job 'tenant-cache' FAILED")
T 'event is engine-failure'      ($d.event -eq 'engine-failure')
T 'detail carries the reason'    ($d.detail -match 'graph 403')
T 'detail carries type + scope'  ($d.detail -match 'type=cache' -and $d.detail -match 'scope=T0')
# This is the distinction the whole finding is about: a 03:00 scheduled failure reads
# very differently from one an operator just clicked, so the alert has to say which.
T 'a scheduled run is labelled scheduled' ($d.detail -match 'scheduled run')
T 'a triggered run is labelled triggered' ((Get-PimJobFailureAlert -Run (New-Run -Trigger $true)).detail -match 'triggered run')

Write-Host "`n== 3. shape tolerance (records round-trip through a store) ==" -ForegroundColor Cyan
# In-process a run record is a PSCustomObject; read back from a store it is a
# dictionary. PSObject.Properties does NOT see dictionary keys.
$asDict = @{ name = 'engine-full'; status = 'failed'; detail = 'x'; type = 'engine'; scope = ''; trigger = $false }
T 'a dictionary run record is understood' ((Get-PimJobFailureAlert -Run $asDict).fire)
T '   ...and still names the job'         ((Get-PimJobFailureAlert -Run $asDict).title -eq "Job 'engine-full' FAILED")

Write-Host "`n== 4. dispatch: never throws, prefers the Manager sender ==" -ForegroundColor Cyan
# No sender loaded at all (a bare engine process): must be a quiet no-op, not a crash.
T 'no sender -> none, no throw' ((Invoke-PimJobRunAlert -Run (New-Run)) -eq 'none')
T 'a non-failure -> none'       ((Invoke-PimJobRunAlert -Run (New-Run -Status 'completed')) -eq 'none')

# With the Manager's sender present it must win: it is the full path (per-event
# toggles, debounce, webhook, audit event, recorded-send feed).
$script:__mgrCalls = New-Object System.Collections.Generic.List[object]
function Send-PimManagerAlert { param($Event, $Title, $Detail, $LinkTab, $DebounceMinutes, [switch]$WhatIf)
    $script:__mgrCalls.Add(@{ event = $Event; title = $Title; detail = $Detail; tab = $LinkTab }); return @{ sent = 1 } }
T 'the Manager sender is preferred' ((Invoke-PimJobRunAlert -Run (New-Run -Name 'j1')) -eq 'manager')
T '   ...called exactly once'       ($script:__mgrCalls.Count -eq 1)
T '   ...with the jobs tab link'    ("$($script:__mgrCalls[0].tab)" -eq 'jobs')
T '   ...and the engine-failure event' ("$($script:__mgrCalls[0].event)" -eq 'engine-failure')
# A throwing sender must not propagate: the run record is already persisted by then.
function Send-PimManagerAlert { param($Event, $Title, $Detail, $LinkTab, $DebounceMinutes, [switch]$WhatIf) throw 'mail exploded' }
$threw = $false
try { $r = Invoke-PimJobRunAlert -Run (New-Run) } catch { $threw = $true }
T 'a throwing sender is swallowed' ((-not $threw) -and $r -eq 'none')
Remove-Item Function:\Send-PimManagerAlert -ErrorAction SilentlyContinue

Write-Host "`n== 5. the wiring is where it has to be ==" -ForegroundColor Cyan
$strip = { param($t) ($t -replace '(?s)<#.*?#>', '') -replace '(?m)^\s*#.*$', '' }
$sch = & $strip (Get-Content -LiteralPath "$root\engine\_shared\PIM-Scheduler.ps1" -Raw)
$mgr = & $strip (Get-Content -LiteralPath "$root\tools\pim-manager\Open-PimManager.ps1" -Raw)
$sta = & $strip (Get-Content -LiteralPath "$root\tools\pim-scheduler\Start-PimScheduler.ps1" -Raw)
$seed = "$root\tools\pim-scheduler\Seed-PimSchedulerRuns.ps1"

# BOTH real completion paths -- Write-PimJobRunRecord AND Invoke-PimJobForceStart,
# which writes its own record and does not call the former.
T 'the scheduler raises the alert in TWO places' (@([regex]::Matches($sch, 'Invoke-PimJobRunAlert -Run \$rec')).Count -eq 2)
# NOT inside Add-PimJobRunRecord: the seeder calls that to write synthetic failed runs.
T 'Add-PimJobRunRecord itself does NOT alert' ((Get-PimSourceFunctionBody -Text $sch -Name 'Add-PimJobRunRecord') -notmatch 'Invoke-PimJobRunAlert')
T 'the seeder still exists (the reason for that)' (Test-Path -LiteralPath $seed)
T '   ...and writes failed runs on purpose' ((Get-Content -LiteralPath $seed -Raw) -match "'failed'|failed runs")

# The Manager must LOAD the layer (so the good sender is the one that answers)...
T 'the Manager loads PIM-JobAlert' ($mgr -match 'PIM-JobAlert\.ps1')
# ...and must no longer fire engine-failure from the run endpoint, or it double-alerts.
T 'the Manager no longer alerts from /api/jobs/run' ($mgr -notmatch "Send-PimManagerAlert -Event 'engine-failure' -Title ""Job ")
# The test-alert button is a DIFFERENT producer and must survive -- it is how an
# operator proves delivery works without breaking something first.
T 'the "send a test alert" button survives' ($mgr -match 'PIM Manager test alert')

# The scheduler process must load it, or the whole fix is inert exactly where the
# defect was. It already had a mail path; it lacked the alerting on top.
T 'the scheduler process loads PIM-JobAlert' ($sta -match 'PIM-JobAlert\.ps1')
T 'the scheduler process loads the feed adapter' ($sta -match 'PIM-AlertFeed\.ps1')
T '   ...and still loads the mail path it needs' ($sta -match 'PIM-Notify\.ps1')

Write-Host "`n== 6. the scheduler sender shares config + proof with the Manager ==" -ForegroundColor Cyan
$ja = & $strip (Get-Content -LiteralPath "$root\engine\_shared\PIM-JobAlert.ps1" -Raw)
# Two senders exist by necessity (different processes, different available state).
# What must NOT diverge is who gets notified, which events are on, and where the
# proof goes -- otherwise this becomes the two-writers problem SEC-16 was about.
T 'the scheduler reads the SAME Alerting key' ($ja -match "-Name 'Alerting'")
T 'the scheduler honours the per-event toggle' ($ja -match '\$cfg\.events\[\$Event\]')
T 'the scheduler refuses with no recipients'  ($ja -match '@\(\$cfg\.recipients\)\.Count -eq 0')
T 'the scheduler debounces off the SAME feed' ($ja -match 'Read-PimAlertFeedSql')
T 'the scheduler records proof to the SAME store' ($ja -match 'Write-PimAlertFeedSql')

# Config reader: defaults must be ON (matching the Manager) and survive no store.
$cfg = Get-PimJobAlertingConfig -ConnectionString ''
T 'events default ON with no store'      ([bool]$cfg.events['engine-failure'])
T 'recipients default EMPTY with no store' (@($cfg.recipients).Count -eq 0)

Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
