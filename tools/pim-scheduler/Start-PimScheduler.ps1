<#
.SYNOPSIS
  PIM4EntraPS scheduler/job runner entrypoint. Runs the in-process job engine
  (PIM-Scheduler.ps1) that fires the phase-split delta, queue-apply, reminders and
  escalations on a cadence.

  Runs identically on a VM and in a container (REST-only, no modules):
    * VM        : Task Scheduler / a service / `pwsh -File Start-PimScheduler.ps1`
    * Container : as a sidecar entrypoint, or started as a background runspace by
                  the manager. Interval from -IntervalSeconds or $env:PIM_SCHED_INTERVAL.

  -Once runs a single tick (useful for an external cron that prefers to own timing).

.NOTES
  Reminders / escalations / queue-apply use the existing tested logic. The per-scope
  engine apply (engine-delta/full) is registered here only when an engine entrypoint is
  configured via $global:PIM_EngineEntryPath -- so this runner never hard-depends on the
  legacy engine location (which is being retired) and stays module-free by default.
#>
[CmdletBinding()]
param([int]$IntervalSeconds = 0, [switch]$Once, [switch]$WhatIf)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tools\pim-scheduler' }
$shared = Resolve-Path "$here\..\..\engine\_shared"

$global:PIM_UseGraphSdk = $false   # REST-first; no Graph/Az modules
. "$shared\PIM-Rest.ps1"
. "$shared\PIM-PortalAccess.ps1"      # Get-PimPolicySetting (config-driven schedule)
. "$shared\PIM-ChangeQueue.ps1"       # Get-PimQueueApplyPlan (queue-apply handler)
. "$shared\PIM-Approvals.ps1"         # escalation logic
. "$shared\PIM-Lifecycle.ps1"         # reminders / expirations
. "$shared\PIM-Scheduler.ps1"

Initialize-PimDefaultJobHandlers

# Optional: wire the real per-scope engine apply when an entrypoint is configured.
# (Kept decoupled from the legacy engine path so retiring it doesn't break the runner.)
$engine = $global:PIM_EngineEntryPath
if ($engine -and (Test-Path $engine)) {
    $h = {
        param($job,$now,$whatIf)
        $scope = if ($job.PSObject.Properties['scope']) { "$($job.scope)" } else { 'All' }
        $mode  = if ("$($job.type)" -eq 'engine-full') { 'Full' } else { 'Delta' }
        if ($whatIf) { return [pscustomobject]@{ ran=$true; detail="WhatIf: engine -Scope $scope -Mode $mode" } }
        & $global:PIM_EngineEntryPath -Scope $scope -Mode $mode
        [pscustomobject]@{ ran=$true; detail="engine -Scope $scope -Mode $mode" }
    }
    Register-PimJobHandler -Type 'engine-delta' -Handler $h
    Register-PimJobHandler -Type 'engine-full'  -Handler $h
    Write-Host "[scheduler] real engine handler wired: $engine" -ForegroundColor Cyan
} else {
    Write-Host "[scheduler] engine apply runs in INTENT mode (set \$global:PIM_EngineEntryPath to execute)" -ForegroundColor DarkYellow
}

$iv = if ($IntervalSeconds -gt 0) { $IntervalSeconds } elseif ($env:PIM_SCHED_INTERVAL) { [int]$env:PIM_SCHED_INTERVAL } else { 300 }

if ($Once) {
    @(Invoke-PimSchedulerTick -WhatIf:$WhatIf) | ForEach-Object { Write-Host ("  {0,-20} {1}" -f $_.name, $_.detail) }
    return
}
Start-PimScheduler -IntervalSeconds $iv -WhatIf:$WhatIf
