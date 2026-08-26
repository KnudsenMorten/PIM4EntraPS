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
param(
    [int]$IntervalSeconds = 0,
    [int]$LeaseTtlMinutes = 0,
    [switch]$Once,
    [switch]$WhatIf,

    # --- RUNTIME CONTEXT AS PARAMETERS (added 2026-08-10) --------------------
    # Everything below was previously readable ONLY from the process environment. That is right
    # for a container (the Job YAML sets it) and wrong for every external scheduler, which passes
    # ARGUMENTS, not env. VisualCron's Execute task in particular has an arguments field and no
    # environment field, so the only ways to run this were machine-wide env vars (global, needs a
    # service restart to take effect) or a per-site wrapper script holding real tenant values.
    # Both are worse than a parameter.
    #
    # 🪤 THE FAILURE THIS PREVENTS, MEASURED 2026-08-10. Started with none of these set, the
    # scheduler cannot reach SQL, so it cannot read the FeatureGates row, so it falls back to the
    # shipped default for 'scheduler.jobs' (defaultEnabled = $false), skips ALL TWELVE JOBS --
    # and exits 0. An external scheduler shows a green task forever while nothing reconciles.
    #
    # BACKWARDS COMPATIBLE: each one only overrides when actually supplied, so the container path
    # (env-driven) and Setup-PimVM's machine env vars keep working untouched.
    [string]$TenantId,
    [string]$ClientId,              # engine SPN appId (cert auth -- see internal/ENGINE-IDENTITY.md)
    [string]$CertThumbprint,        # thumbprint in LocalMachine\My; the private key never leaves it
    [string]$SqlServer,
    [string]$SqlDatabase,
    [ValidateSet('','sql','file')][string]$StorageBackend = '',
    # PIM_SCHED_JOBS. 🔴 Leaving this unset means RUN ALL JOBS, which includes the ones that send
    # mail (reminders / escalations / daily-summary / tier-report) and create accounts
    # (scheduled-creation). An external trigger that only wants the delta must say so.
    [string]$Jobs
)
$ErrorActionPreference = 'Stop'

# Parameters win over inherited environment, and are applied BEFORE anything is dot-sourced --
# every module below reads these at load time, so setting them later would be too late.
if ("$TenantId".Trim())       { $env:PIM_TenantId       = $TenantId.Trim() }
if ("$ClientId".Trim())       { $env:PIM_ClientId       = $ClientId.Trim() }
if ("$CertThumbprint".Trim()) { $env:PIM_CertThumbprint = $CertThumbprint.Trim() }
if ("$SqlServer".Trim())      { $env:PIM_SqlServer      = $SqlServer.Trim() }
if ("$SqlDatabase".Trim())    { $env:PIM_SqlDatabase    = $SqlDatabase.Trim() }
if ("$StorageBackend".Trim()) { $env:PIM_StorageBackend = $StorageBackend.Trim() }
if ("$Jobs".Trim())           { $env:PIM_SCHED_JOBS     = $Jobs.Trim() }
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
. "$shared\PIM-Notify.ps1"            # mail notifications (REST sendMail) -- so the daily-summary / tier-report / escalation jobs can actually send AND the send path hydrates EmailControls (kill switch / redirect / allowlist) from pim.Settings for this cold scheduler process
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

# ---- SQL store wiring (BUG-39) --------------------------------------------
# MEASURED on a live ACA Job run 2026-08-09: this entrypoint never touched the SQL store. It
# read NONE of the PIM_Sql* env vars the container is given, and Get-/Set-PimSetting are
# defined by the MANAGER (Open-PimManager.ps1), not here -- so in a scheduler container both
# were absent and every store write fell back to a JSON file inside an EPHEMERAL container.
# Two consequences, neither of which announced itself:
#   1. Scheduler STATE did not survive the run. Every job's nextRunUtc was lost, so on the next
#      tick every job looked never-run and was therefore DUE -- the daily engine-full and the
#      daily discovery sweeps would have run on EVERY 5-minute cron tick.
#   2. The single-runner lease (BUG-36) fell back to its in-memory path, which cannot arbitrate
#      between processes. Each cron run would take a fresh lease and believe it held it, so two
#      overlapping runs would BOTH proceed -- the exact double-apply the lease exists to stop.
# The Job reported "Succeeded" throughout, and pim.Settings stayed EMPTY.
if ("$env:PIM_SqlServer".Trim()   -and -not "$($global:PIM_SqlServer)".Trim())   { $global:PIM_SqlServer   = "$env:PIM_SqlServer" }
if ("$env:PIM_SqlDatabase".Trim() -and -not "$($global:PIM_SqlDatabase)".Trim()) { $global:PIM_SqlDatabase = "$env:PIM_SqlDatabase" }
if ("$env:PIM_TenantId".Trim()    -and -not "$($global:PIM_TenantId)".Trim())    { $global:PIM_TenantId    = "$env:PIM_TenantId" }
# 🔴 THE ENGINE IDENTITY MUST REACH THE SQL LAYER, AND IT DID NOT.
# BUG-39 bridged three env vars into globals and stopped there. But `New-PimSqlConnection` decides
# WHICH IDENTITY to authenticate with by reading $global:PIM_ClientId / $global:PIM_CertThumbprint
# ($explicitSpn) -- never the environment. With those two unbridged the test is always false, so
# the explicit SPN never gets a turn and the connection falls through to the machine's ambient
# MANAGED IDENTITY.
#
# MEASURED on mgmt1 2026-08-10, and note how quiet the failure is: the VM's MI authenticates
# FINE (it has a contained DB user for the VisualCron trigger, with SELECT on two objects), so
# the `SELECT 1` login probe SUCCEEDS and the scheduler reports "SQL store reachable". The wrong
# principal is only revealed later, on the first WRITE:
#     lease acquire FAILED ... The UPDATE permission was denied on the object 'Settings'
# and the tick then skips every job as though another runner held the lease. Before that DB user
# existed the MI login was simply rejected, which was WRONG BUT LOUD -- a read-only probe guarding
# a write path is the same class as SEC-08.
#
# The container path is unaffected: it configures no SPN, so $explicitSpn stays false and MI
# remains plan A -- which is correct there, because the container's identity holds real rights.
if ("$env:PIM_ClientId".Trim()       -and -not "$($global:PIM_ClientId)".Trim())       { $global:PIM_ClientId       = "$env:PIM_ClientId" }
if ("$env:PIM_CertThumbprint".Trim() -and -not "$($global:PIM_CertThumbprint)".Trim()) { $global:PIM_CertThumbprint = "$env:PIM_CertThumbprint" }

# Bridge Get-/Set-PimSetting onto the SQL store, mirroring what the Manager does -- so the
# scheduler persists into the SAME pim.Settings the Manager and engine read. Defined only when
# a host has not already provided them (idempotent; never clobbers the Manager's bridge).
$_schedHosted        = ("$env:PIM_HOSTED" -eq '1')
$_schedSqlConfigured = [bool]("$($global:PIM_SqlServer)".Trim() -or "$($global:PIM_SqlConnectionString)".Trim())
$_schedCsOk          = $false
$_schedProbeOk       = $false
$_schedProbeErr      = ''
if ($_schedSqlConfigured) {
    $_schedCs = $null
    try { $_schedCs = Get-PimSqlConnectionString } catch { $_schedCs = $null }
    if ($_schedCs) {
        $_schedCsOk = $true
        $global:PIM_SqlConnectionString = $_schedCs
        if (-not (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) {
            function Get-PimSetting { param([Parameter(Mandatory)][string]$Name) Get-PimSqlSetting -ConnectionString $global:PIM_SqlConnectionString -Name $Name }
        }
        if (-not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) {
            function Set-PimSetting { param([Parameter(Mandatory)][string]$Name, [object]$Value) Set-PimSqlSetting -ConnectionString $global:PIM_SqlConnectionString -Name $Name -Value $Value }
        }
        Write-Host "[scheduler] SQL store wired -> $($global:PIM_SqlServer)/$($global:PIM_SqlDatabase) (state + lease persist in pim.Settings)" -ForegroundColor Cyan
        # BUG-45: PROVE the store opens. "Wired" only means a connection string was built -- the
        # token is minted locally and the string is a string, so both succeed against a database
        # this identity cannot log into. On mfnpr that gap produced four green Job executions in
        # a row that read nothing, gated every job off and exited 0. One read settles it.
        # `SELECT 1`, deliberately NOT a read of pim.Settings. The schema step runs AFTER infra,
        # so a table-dependent probe would make every fresh deploy fatal for the minutes between
        # the containers standing up and the schema landing. Login is the thing that failed here
        # and login is what this proves.
        try {
            [void](Invoke-PimSqlScalar -ConnectionString $global:PIM_SqlConnectionString -Sql 'SELECT 1')
            $_schedProbeOk = $true
            Write-Host "[scheduler] SQL store reachable (login probe succeeded)" -ForegroundColor DarkGray
        } catch {
            $_schedProbeErr = "$($_.Exception.Message)"
        }
    }
}
# The verdict itself is a pure decision (Get-PimSchedulerStoreVerdict) so it is provable offline
# without a database; this only carries it out.
$_schedVerdict = Get-PimSchedulerStoreVerdict -Hosted $_schedHosted -SqlConfigured $_schedSqlConfigured `
                    -ConnectionStringResolved $_schedCsOk -ProbeOk $_schedProbeOk -ProbeError $_schedProbeErr
switch ($_schedVerdict.level) {
    'fatal' {
        # Non-zero exit is the ONLY signal a scheduled ACA Job gives an operator. Exiting 0 from
        # a tick that cannot reach its store is what let mfnpr look healthy while doing nothing.
        throw "[scheduler] REFUSING to run ($($_schedVerdict.reason)): $($_schedVerdict.detail)"
    }
    'warn' { Write-Warning "[scheduler] $($_schedVerdict.detail) State and the single-runner lease will NOT persist, so every job looks due every tick and overlapping runs cannot be arbitrated." }
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
        # 🔴 SQL FIRST -- the JSON queue file is EPHEMERAL in a container.
        # `pim.ChangeQueue` has existed (and been used by the Manager's commit path) all along;
        # this handler was still writing to a JSON file under output/, which in a scale-to-zero
        # ACA container is destroyed with the replica. So every discovery proposal was written and
        # then thrown away, and `queue-apply` drained a queue nobody had written to. Operator
        # requirement, 2026-08-10: "everything SQL, no files at all."
        if ($global:PIM_SqlConnectionString -and (Get-Command Add-PimSqlQueueChange -ErrorAction SilentlyContinue)) {
            try { Add-PimSqlQueueChange -ConnectionString $global:PIM_SqlConnectionString -Change $change; return }
            catch { Write-Warning "  [discovery] SQL enqueue failed, falling back to the JSON queue: $($_.Exception.Message)" }
        }
        if (Get-Command Add-PimChangeToQueue -ErrorAction SilentlyContinue) {
            Add-PimChangeToQueue -QueueFile $discoQueueFile -Change $change | Out-Null
        }
    } `
    -AutoImportPowerBI:([bool]$global:PIM_DiscoveryAutoImportPowerBi)
$_queueSink = if ($global:PIM_SqlConnectionString) { 'SQL pim.ChangeQueue' } else { "JSON file $discoQueueFile (EPHEMERAL in a container)" }
Write-Host "[scheduler] discovery handler wired (Azure/PowerBI scope-discovery + Entra role-catalog -> change queue: $_queueSink)" -ForegroundColor Cyan

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

# BUG-36: the single-runner lease is taken inside the tick. The owner defaults to
# <host>-<pid>, which is exactly right for cron: every run is a new process, so two OVERLAPPING
# runs have different owners and the second is refused instead of double-applying. Raise the TTL
# when a full reconcile can run long -- PIM_SCHED_LEASE_TTL, minutes.
$ttl = if ($LeaseTtlMinutes -gt 0) { $LeaseTtlMinutes } elseif ($env:PIM_SCHED_LEASE_TTL) { [int]$env:PIM_SCHED_LEASE_TTL } else { 15 }

if ($Once) {
    @(Invoke-PimSchedulerTick -WhatIf:$WhatIf -LeaseTtlMinutes $ttl) | ForEach-Object { Write-Host ("  {0,-20} {1}" -f $_.name, $_.detail) }
    return
}
Start-PimScheduler -IntervalSeconds $iv -LeaseTtlMinutes $ttl -WhatIf:$WhatIf
