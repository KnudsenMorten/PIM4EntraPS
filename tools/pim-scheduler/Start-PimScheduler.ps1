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
. "$shared\PIM-PermissionWizard.ps1"  # Azure scope derivation/depth + group naming (used by the Azure reconcile planner)
. "$shared\PIM-AzureDiscovery.ps1"    # Get-PimAzureReconcilePlan / ConvertTo-PimReconcileQueueChanges
. "$shared\PIM-Discovery.ps1"         # discovery enumerators + sweep (Invoke-PimDiscoveryJobSweep)
. "$shared\PIM-License.ps1"           # offline Core/Pro edition model (Get-PimEdition)
. "$shared\PIM-FeatureCatalog.ps1"    # feature catalog + gates (Test-PimFeatureAvailable) -- s29/s30
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

# Wire the REAL discovery handler (the three discovery jobs: Azure / PowerBI / Entra).
# It reconciles the live enumerated scopes against the current definitions, surfaces
# ONLY not-yet-handled items (the handled-set delta, persisted per scope under
# output/state/discovery-handled-<scope>.json) and enqueues just those fresh items
# onto the SAME change queue queue-apply drains -- propose-don't-auto-map, never
# auto-delete (orphans are surfaced, never removed by a scheduled run). The existing
# definition rows come from $global:PIM_DiscoveryExistingReader (a launcher hook that
# knows the desired store) when present; absent -> empty (a fresh tenant just sees
# all-create, still gated by the per-type auto-import rules). The discovered items use
# the REST enumerators. The change queue file defaults next to the scheduler state.
$discoQueueFile = if ("$($global:PIM_ChangeQueueFile)".Trim()) { "$($global:PIM_ChangeQueueFile)" }
                  else { Join-Path (Split-Path -Parent $global:PIM_SchedulerStatePath) 'pim-change-queue.json' }
Register-PimDiscoveryHandler `
    -GetDiscovered {
        param($scope)
        switch ($scope) {
            'Azure'   { try { @(Get-PimLiveAzureScopes -IncludeManagementGroups) } catch { @() } }
            'PowerBI' { try { @(Get-PimLivePowerBiWorkspaces) } catch { @() } }
            default   { @() }
        }
    } `
    -GetExisting {
        param($scope)
        if ($global:PIM_DiscoveryExistingReader) { try { @(& $global:PIM_DiscoveryExistingReader $scope) } catch { @() } } else { @() }
    } `
    -GetAutoImportRules {
        param($scope)
        if ($global:PIM_DiscoveryAutoImportRules) { @($global:PIM_DiscoveryAutoImportRules) } else { @() }
    } `
    -GetLiveRoles {
        param($service)
        # ENTRA scope = the role-CATALOG delta (new built-in roles per service). Uses the
        # REST role-definition enumerator, normalised to { id; name }. Best-effort -> @().
        $svc = if ("$service".Trim()) { "$service".Trim().ToLowerInvariant() } else { 'entra' }
        if ($svc -notin @('entra','defender','intune')) { return @() }
        try { @(Get-PimLiveServiceRoles -Service $svc) } catch { @() }
    } `
    -EnqueueChange {
        param($change)
        if (Get-Command Add-PimChangeToQueue -ErrorAction SilentlyContinue) {
            Add-PimChangeToQueue -QueueFile $discoQueueFile -Change $change | Out-Null
        }
    } `
    -AutoImportPowerBI:([bool]$global:PIM_DiscoveryAutoImportPowerBi)
Write-Host "[scheduler] discovery handler wired (Azure/PowerBI scope-discovery + Entra role-catalog -> change queue: $discoQueueFile)" -ForegroundColor Cyan

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
