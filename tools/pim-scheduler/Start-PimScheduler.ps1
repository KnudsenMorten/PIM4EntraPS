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
. "$shared\PIM-SqlStore.ps1"          # SQL store (signature read for the change-detector)
. "$shared\PIM-Cutover.ps1"           # Invoke-PimSqlChangeDetector (on-demand recalc on SQL change)
. "$shared\PIM-Approvals.ps1"         # escalation logic
. "$shared\PIM-DelegationDepth.ps1"   # two-approval split + reachability + self-deleg
. "$shared\PIM-Lifecycle.ps1"         # reminders / expirations
. "$shared\PIM-EngineCore.ps1"        # NEW REST+SQL engine (diff + providers)
. "$shared\PIM-DisableGuard.ps1"      # account-disable circuit breaker (incident 2026-06-15)
. "$shared\PIM-HybridAd.ps1"          # on-prem AD/gMSA-sMSA PLANNER + hybrid-worker seam (on-prem write is worker-only)
. "$shared\PIM-EngineProviders.ps1"
. "$shared\PIM-Scheduler.ps1"

# State + run-history file location (file-backed VM/local deployments). SQL-backed
# deployments persist via pim.Settings and ignore this. Default to the solution's
# output\scheduler dir so the Manager's Jobs tab (/api/jobs) reads the SAME state +
# run history this runner writes. Override with $global:PIM_SchedulerStatePath /
# $env:PIM_SCHED_STATE_PATH before launch.
if (-not "$($global:PIM_SchedulerStatePath)".Trim()) {
    if ("$env:PIM_SCHED_STATE_PATH".Trim()) {
        $global:PIM_SchedulerStatePath = "$env:PIM_SCHED_STATE_PATH"
    } else {
        $_schedDir = Join-Path (Resolve-Path "$here\..\..").Path 'output\scheduler'
        if (-not (Test-Path -LiteralPath $_schedDir)) { try { [void](New-Item -ItemType Directory -Path $_schedDir -Force) } catch {} }
        $global:PIM_SchedulerStatePath = Join-Path $_schedDir 'pim-scheduler-state.json'
    }
}

# Tenant-list cache refresher (Invoke-PimTenantListRefresh + cache read/write/path
# helpers) lives with the Manager. Dot-source it so the scheduler's 'tenant-cache'
# job can keep the per-instance cache fresh (entra-roles / AUs / PIM-* groups /
# Azure scopes + RBAC roles) WITHOUT a Manager restart. Best-effort: if the file
# isn't present (a worker image that drops the Manager files), the default
# 'tenant-cache' handler degrades to a logged no-op.
$tenantSync = Resolve-Path "$here\..\pim-manager\_tenantSync.ps1" -ErrorAction SilentlyContinue
if ($tenantSync) {
    . "$tenantSync"
    Write-Host "[scheduler] tenant-cache refresher wired (Invoke-PimTenantListRefresh)" -ForegroundColor Cyan
} else {
    Write-Host "[scheduler] tenant-cache refresher NOT found (_tenantSync.ps1 absent) -- 'tenant-cache' job will no-op" -ForegroundColor DarkYellow
}

Initialize-PimDefaultJobHandlers
Register-PimDefaultEngineProviders     # register the REST scope providers (Admins, ...)

# Wire the per-scope engine-delta / engine-full jobs to the NEW REST engine.
# WhatIf (intent/recalc) -> plan only; otherwise the provider applies via REST.
$engineHandler = {
    param($job,$now,$whatIf)
    $scope = if ($job.PSObject.Properties['scope'] -and "$($job.scope)".Trim()) { "$($job.scope)" } else { 'All' }
    $mode  = if ("$($job.type)" -eq 'engine-full') { 'Full' } else { 'Delta' }
    $res = Invoke-PimEngine -Scope $scope -Mode $mode -WhatIf:$whatIf
    $sum = @($res) | ForEach-Object { "$($_.scope):c$($_.create)/u$($_.update)/r$($_.remove)" }
    [pscustomobject]@{ ran=$true; detail=("engine $mode [$scope] " + ($sum -join ' ')); whatIf=[bool]$whatIf }
}
Register-PimJobHandler -Type 'engine-delta' -Handler $engineHandler
Register-PimJobHandler -Type 'engine-full'  -Handler $engineHandler
Write-Host "[scheduler] REST engine wired (scopes: $((Get-PimEngineScopes) -join ', '))" -ForegroundColor Cyan

# Worker-container scoping: $env:PIM_SCHED_JOBS (comma list of job types) makes this
# container run only those jobs -- so the SAME image is deployed N times as
# manager/scheduler/engine/connector/delta-queue/discovery workers, each scoped via env.
# Unset/empty = all jobs (single all-in-one runner). "Don't know how many" -> config-driven.
if ("$env:PIM_SCHED_JOBS".Trim()) {
    $only = "$env:PIM_SCHED_JOBS" -split '[,; ]+' | Where-Object { $_ }
    $kept = Select-PimJobHandlers -Only $only
    Write-Host ("[scheduler] job filter PIM_SCHED_JOBS -> running ONLY: {0}" -f ($kept -join ', ')) -ForegroundColor Yellow
} else {
    Write-Host ("[scheduler] no job filter -> running ALL: {0}" -f ((Get-PimJobHandlerTypes) -join ', ')) -ForegroundColor DarkCyan
}

$iv = if ($IntervalSeconds -gt 0) { $IntervalSeconds } elseif ($env:PIM_SCHED_INTERVAL) { [int]$env:PIM_SCHED_INTERVAL } else { 300 }

if ($Once) {
    @(Invoke-PimSchedulerTick -WhatIf:$WhatIf) | ForEach-Object { Write-Host ("  {0,-20} {1}" -f $_.name, $_.detail) }
    return
}
Start-PimScheduler -IntervalSeconds $iv -WhatIf:$WhatIf
