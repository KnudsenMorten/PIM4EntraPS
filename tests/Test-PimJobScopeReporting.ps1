#Requires -Version 5.1
<#
.SYNOPSIS
  BUG-92 -- a job this worker is NOT SCOPED to run must never be reported as FAILED.

.DESCRIPTION
  $env:PIM_SCHED_JOBS scopes a worker to a subset of job types; Select-PimJobHandlers then
  removes the handlers for the rest. The SCHEDULE still lists every job, so the dispatcher was
  still called for the excluded ones, found no handler, and returned ok=$false -- which
  Write-PimJobRunRecord stores as status='failed'.

  MEASURED IN PRODUCTION 2026-08-30: 390 of 863 recorded runs were this, and six job types sat
  permanently red on the Overview -- including servicenow-intake, on a tenant with no
  ServiceNow. The operator reported it as "i see references to failed jobs including
  servicenow, i dont have any servicenow", and it survived a whole release because nothing
  asserted the difference.

  🔑 THE PROPERTY UNDER TEST: excluding a job by design and reporting it as broken must not be
  the same code path -- AND the real signal (a job that IS in scope with no implementation)
  must still fail loudly. A fix that made everything green would be worse than the bug.

  PURE: no store, no network, no container. Drives the real scheduler functions.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'engine\_shared\PIM-Scheduler.ps1')

$pass = 0; $fail = 0
function T($name, $cond) {
    if ($cond) { $script:pass++; Write-Host "  PASS $name" -ForegroundColor Green }
    else       { $script:fail++; Write-Host "  FAIL $name" -ForegroundColor Red }
}

Write-Host "`n== BUG-92: out-of-scope is a SKIP, not a failure ==" -ForegroundColor Cyan

Initialize-PimDefaultJobHandlers
$before = @(Get-PimJobHandlerTypes).Count
T 'default handlers register (baseline)' ($before -gt 5)

# Scope this "worker" the way ca-pim-tick is scoped in production.
$kept = Select-PimJobHandlers -Only @('engine-delta','engine-full','queue-apply','tenant-cache','discovery')
T 'scoping keeps only the named types'            (@($kept).Count -eq 5)
T 'the scope is REMEMBERED, not just applied'     ((Get-PimJobScope) -contains 'servicenow-intake' -eq $false -and (Get-PimJobScope).Count -eq 5)
T 'Test-PimJobInScope: an in-scope type is in'    (Test-PimJobInScope -Type 'queue-apply')
T 'Test-PimJobInScope: an excluded type is out'   (-not (Test-PimJobInScope -Type 'servicenow-intake'))

# THE REGRESSION: dispatching an out-of-scope job.
$snow = [pscustomobject]@{ name = 'servicenow-intake'; type = 'servicenow-intake'; enabled = $true }
$r = Invoke-PimScheduledJob -Job $snow -NowUtc ([datetime]::UtcNow)
T 'out-of-scope dispatch does NOT report ok=false' ([bool]$r.ok)
T 'out-of-scope dispatch is flagged outOfScope'    ([bool]$r.outOfScope)
T 'out-of-scope dispatch did NOT run'              (-not [bool]$r.ran)
T 'the detail says WHY, naming the scope'          ("$($r.detail)" -match 'not scheduled on this worker')
T 'the detail is NOT the misleading no-handler text' ("$($r.detail)" -notmatch 'no-handler-registered')

# The recorded run must carry the third status, so the GUI can tell the difference.
$rec = $null
try {
    $script:PimRunHistory = @()
    Write-PimJobRunRecord -Job $snow -Result $r -StartedUtc ([datetime]::UtcNow) | Out-Null
    $rec = @(Get-PimJobRunHistory -Name 'servicenow-intake')[0]
} catch { }
T 'a run record was written for the skip'          ($null -ne $rec)
T "recorded status is 'skipped' (not failed)"      ("$($rec.status)" -eq 'skipped')
T "recorded status is NOT 'completed' either"      ("$($rec.status)" -ne 'completed')


# ===========================================================================================
# BUG-113 -- "DISABLED" AND "NOT IMPLEMENTED HERE" ARE NOT FAILURES, AND NOT EACH OTHER
#
# Reported as: "it should not report failed if disabled" -- with a Jobs view in which EVERY
# red count was `no-handler-registered`: tenant-cache 9, reminders 9, daily-summary 9,
# tier-report 9, discovery-entra/azure/powerbi 5 each, full-reconcile 5, and NOT ONE of them a
# run that went wrong. tenant-cache's own most recent run was a healthy refresh of 146 Entra
# roles at the same time it was being shown as nine-times failed.
#
# Two independent defects produced that, and both are asserted here:
#   1. ORDER. The feature gate sat BELOW the handler lookup, so a job whose feature is switched
#      OFF on a worker without that handler was recorded as failed/no-handler instead of
#      "disabled -- skipped". The operator is told the wrong one of two true things.
#   2. COUNTING. "No handler on this worker" is ONE fact about the deployment, repeated once
#      per tick. Counted per run it inflates into "9 failures", attaches an Ack button to
#      something acknowledging cannot fix, and buries failures that are real runs.
#
# 🔒 The real signal must survive both: in scope + ENABLED + no implementation still fails.
# ===========================================================================================
Write-Host "`n== BUG-113: a DISABLED job reports disabled, not 'no handler' ==" -ForegroundColor Cyan

# Reset scope so nothing here is answered by the out-of-scope path above.
[void](Select-PimJobHandlers -Only @())
Initialize-PimDefaultJobHandlers

# Feature stub: 'discovery.sweep' OFF, the master switch ON. Defined GLOBAL so the function
# under test resolves it -- a script-scoped stub is invisible to the callee.
function global:Test-PimFeatureAvailable {
    param([string]$Key, [switch]$Quiet)
    if ("$Key" -eq 'discovery.sweep') { return $false }
    return $true
}
# ...and no handler for it either, which is the combination that used to answer wrongly.
if ($script:PimJobHandlers.ContainsKey('discovery')) { [void]$script:PimJobHandlers.Remove('discovery') }

$disabled = [pscustomobject]@{ name = 'discovery-entra'; type = 'discovery'; scope = 'Entra'; enabled = $true }
$rd = Invoke-PimScheduledJob -Job $disabled -NowUtc ([datetime]::UtcNow)
T 'disabled + no handler: reports the FEATURE, not the handler' ("$($rd.detail)" -match "disabled -- skipped")
T 'disabled + no handler: is NOT a failure'                     ([bool]$rd.ok)
T 'disabled + no handler: names the feature key'                ("$($rd.skippedFeature)" -eq 'discovery.sweep')
T 'disabled + no handler: did not run'                          (-not [bool]$rd.ran)

# The gate must not swallow the real signal: same job, feature ON, still no handler.
function global:Test-PimFeatureAvailable { param([string]$Key, [switch]$Quiet) return $true }
$re = Invoke-PimScheduledJob -Job $disabled -NowUtc ([datetime]::UtcNow)
T 'ENABLED + no handler still FAILS (the signal survives)'      (-not [bool]$re.ok)
T 'ENABLED + no handler still says no-handler-registered'       ("$($re.detail)" -eq 'no-handler-registered')
T 'ENABLED + no handler is marked noHandler for the view'       ([bool]$re.noHandler)
Remove-Item function:\global:Test-PimFeatureAvailable -ErrorAction SilentlyContinue

Write-Host "`n== BUG-113: 'no handler here' is counted apart from failed RUNS ==" -ForegroundColor Cyan
# Craft the exact history shape measured in production: nine no-handler records and one real
# failure, for one job, inside the 10-run window the view reads.
$hist = New-Object System.Collections.Generic.List[object]
for ($i = 1; $i -le 9; $i++) {
    $hist.Add([pscustomobject]@{
        runId = "nh$i"; name = 'tenant-cache'; type = 'tenant-cache'; ok = $false; ran = $false
        status = 'failed'; detail = 'no-handler-registered'
        startedUtc = ([datetime]::UtcNow.AddHours(-$i)).ToString('o')
        finishedUtc = ([datetime]::UtcNow.AddHours(-$i)).ToString('o'); durationMs = 5
    })
}
$hist.Add([pscustomobject]@{
    runId = 'real1'; name = 'tenant-cache'; type = 'tenant-cache'; ok = $false; ran = $true
    status = 'failed'; detail = 'error: Graph returned 403'
    startedUtc = ([datetime]::UtcNow.AddHours(-10)).ToString('o')
    finishedUtc = ([datetime]::UtcNow.AddHours(-10)).ToString('o'); durationMs = 900
})
Save-PimJobRunHistory -Runs $hist.ToArray()

$vm  = Get-PimJobsStatus -Jobs @([pscustomobject]@{ name = 'tenant-cache'; type = 'tenant-cache'; enabled = $true; intervalMinutes = 720 })
$row = @($vm.jobs) | Where-Object { $_.name -eq 'tenant-cache' } | Select-Object -First 1
T 'view: the 9 no-handler records are NOT counted as failures' ($row.recentFailureCount -eq 1)
T 'view: they are reported separately as unrunnable'           ($row.unrunnableCount -eq 9)
T 'view: the ONE real failure is still counted'                ($row.recentFailureCount -eq 1)
T 'view: unacked failures exclude the no-handler records'      ($row.unackedFailureCount -eq 1)
T 'view: the job is not marked out of scope'                   (-not [bool]$row.outOfScope)

# ...and with ONLY no-handler records, the row is quiet: no red count, no Ack demanded.
$only = @($hist | Where-Object { "$($_.detail)" -eq 'no-handler-registered' })
Save-PimJobRunHistory -Runs $only
$vm2  = Get-PimJobsStatus -Jobs @([pscustomobject]@{ name = 'tenant-cache'; type = 'tenant-cache'; enabled = $true; intervalMinutes = 720 })
$row2 = @($vm2.jobs) | Where-Object { $_.name -eq 'tenant-cache' } | Select-Object -First 1
T 'view: no-handler-only history shows ZERO failures'          ($row2.recentFailureCount -eq 0)
T 'view: no-handler-only history demands NO acknowledgement'   ($row2.unackedFailureCount -eq 0)
T 'view: and the summary does not call the job failing'        ($vm2.failingCount -eq 0)
T 'view: but the operator can still SEE the 9 unrunnable runs' ($row2.unrunnableCount -eq 9)
Save-PimJobRunHistory -Runs @()
Write-Host "`n== BUG-114: a PLACEHOLDER handler is not a clean run, and not a failure ==" -ForegroundColor Cyan
# The shape that made `full-reconcile` look healthy for months. A registered-but-placeholder
# handler returns ran=$false, but the DISPATCH succeeded -- so ok=$true, the record said
# 'completed', and the view rendered amber "no-op", i.e. "there was nothing to do". That is the
# answer an operator most wants to be true, which is exactly why it must not be borrowed.
$stubRes = [pscustomobject]@{
    name = 'full-reconcile'; type = 'engine-full'; ok = $true
    detail = 'unimplemented:engine-full scope=All (no real handler registered on this worker)'
    result = [pscustomobject]@{ ran = $false; unimplemented = $true; detail = 'unimplemented:engine-full scope=All' }
}
$stubJob = [pscustomobject]@{ name = 'full-reconcile'; type = 'engine-full'; enabled = $true; intervalMinutes = 1440 }
Save-PimJobRunHistory -Runs @()
$recStub = Write-PimJobRunRecord -Job $stubJob -Result $stubRes
T 'record: a placeholder run is NOT status=completed'    ("$($recStub.status)" -ne 'completed')
T 'record: it is status=unimplemented'                   ("$($recStub.status)" -eq 'unimplemented')
T 'record: ran stays false (it really did no work)'      (-not [bool]$recStub.ran)
T 'record: ok stays true -- the DISPATCH did not fail'   ([bool]$recStub.ok)

# A real converged run must be untouched: ran=$false + ok=$true WITHOUT the flag is a genuine
# no-op, and collapsing the two would trade one wrong word for another.
$noopRes = [pscustomobject]@{
    name = 'full-reconcile'; type = 'engine-full'; ok = $true; detail = 'nothing to do'
    result = [pscustomobject]@{ ran = $false; detail = 'nothing to do' }
}
$recNoop = Write-PimJobRunRecord -Job $stubJob -Result $noopRes
T 'record: a GENUINE no-op is still completed'           ("$($recNoop.status)" -eq 'completed')

# outOfScope must still win -- a job this deployment does not run has nothing to answer for.
$oosRes = [pscustomobject]@{
    name = 'full-reconcile'; type = 'engine-full'; ok = $true; outOfScope = $true; detail = 'out of scope'
    result = [pscustomobject]@{ ran = $false; unimplemented = $true; detail = 'unimplemented:engine-full' }
}
T 'record: outOfScope beats unimplemented (BUG-112 order)' ("$(( Write-PimJobRunRecord -Job $stubJob -Result $oosRes ).status)" -eq 'skipped')

# View: counted apart from BOTH failures and successes.
$uhist = New-Object System.Collections.Generic.List[object]
for ($i = 1; $i -le 5; $i++) {
    $uhist.Add([pscustomobject]@{
        runId = "un$i"; name = 'full-reconcile'; type = 'engine-full'; ok = $true; ran = $false
        status = 'unimplemented'; detail = 'unimplemented:engine-full scope=All'
        startedUtc = ([datetime]::UtcNow.AddHours(-$i)).ToString('o')
        finishedUtc = ([datetime]::UtcNow.AddHours(-$i)).ToString('o'); durationMs = 4
    })
}
Save-PimJobRunHistory -Runs $uhist.ToArray()
$vm3  = Get-PimJobsStatus -Jobs @($stubJob)
$row3 = @($vm3.jobs) | Where-Object { $_.name -eq 'full-reconcile' } | Select-Object -First 1
T 'view: placeholder runs are NOT counted as failures'   ($row3.recentFailureCount -eq 0)
T 'view: they demand no acknowledgement'                 ($row3.unackedFailureCount -eq 0)
T 'view: they are NOT counted as unrunnable (different fact)' ($row3.unrunnableCount -eq 0)
T 'view: they are reported as unimplemented'             ($row3.unimplementedCount -eq 5)
T 'view: the job status is unimplemented, not completed' ("$($row3.status)" -eq 'unimplemented')
T 'view: the summary does not call the job failing'      ($vm3.failingCount -eq 0)
Save-PimJobRunHistory -Runs @()

# The GUI must not render it with the borrowed word. Source-scan, comments stripped.
$guiPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\pim-manager\pim-manager.html'
if (Test-Path -LiteralPath $guiPath) {
    $gui = (Get-Content -LiteralPath $guiPath -Raw) -replace '(?m)^\s*//.*$', ''
    T 'GUI: renders an unimplemented badge'               ($gui -match "status === 'unimplemented'")
    T 'GUI: labels it "not implemented", not "no-op"'     ($gui -match "label = 'not implemented'")
    T 'GUI: surfaces unimplementedCount'                  ($gui -match 'unimplementedCount')
} else { T 'GUI present for the badge assert' $false }

Write-Host "`n== the real signal must SURVIVE the fix ==" -ForegroundColor Cyan
# A type that IS in scope but has no handler is a genuine defect and must still fail. This is
# how BUG-92's second half was found; softening it would have hidden that permanently.
[void]$script:PimJobHandlers.Remove('queue-apply')
$qa = [pscustomobject]@{ name = 'queue-apply'; type = 'queue-apply'; enabled = $true }
$r2 = Invoke-PimScheduledJob -Job $qa -NowUtc ([datetime]::UtcNow)
T 'in-scope + no handler STILL fails'              (-not [bool]$r2.ok)
T 'in-scope + no handler is NOT marked outOfScope' (-not ($r2.PSObject.Properties['outOfScope'] -and $r2.outOfScope))
T 'in-scope + no handler still says no-handler'    ("$($r2.detail)" -eq 'no-handler-registered')

Write-Host "`n== no scope set => every job runs (single all-in-one runner) ==" -ForegroundColor Cyan
[void](Select-PimJobHandlers -Only @())
T 'an empty scope clears the restriction'          ($null -eq (Get-PimJobScope))
T 'with no scope, any type is in scope'            (Test-PimJobInScope -Type 'servicenow-intake')

Write-Host ""
if ($fail) { Write-Host " RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
Write-Host " RESULT: $pass pass, 0 fail" -ForegroundColor Green
exit 0
