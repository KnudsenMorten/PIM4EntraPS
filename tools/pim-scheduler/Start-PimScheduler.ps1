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
    # IMP-42 (§33.28): 'file' is gone -- PIM v2 is SQL-only; a caller still passing it fails at binding, loudly.
    [ValidateSet('','sql')][string]$StorageBackend = '',
    # PIM_SCHED_JOBS. 🔴 Leaving this unset means RUN ALL JOBS, which includes the ones that send
    # mail (reminders / escalations / daily-summary / tier-report) and create accounts
    # (scheduled-creation). An external trigger that only wants the delta must say so.
    [string]$Jobs,
    # §80.2 PIM_SCHED_INSTANCE: a SECOND scheduler against the same store (the hybrid worker: -Instance hybrid) keeps its
    # own lease, state and scope record so it neither fights the main tick nor advances the jobs it does not run.
    [string]$Instance,
    # §80.2: authenticate to SQL AND Graph as this host's managed identity (a VM: IMDS). The hybrid worker has no engine
    # certificate on it by design; without this switch a VM would try the SPN path and fail.
    [switch]$UseManagedIdentity,
    # §80.2: run ONE job continuously instead of ticking (operator 2026-09-29: an activation must reach AD in seconds, as
    # v1's endless PIM-Sync-ID-AD loop did, not at the next 5-minute slot). Only 'hybrid-ad-sync' is allowed.
    # 2026-10-04 lanes: hybrid-ad-sync (critical groups), hybrid-ad-sync-servers (per-server groups, parallel batches),
    # hybrid-ad-changes (AD accounts + AD groups the moment their definitions change) -- one process each.
    [ValidateSet('', 'hybrid-ad-sync', 'hybrid-ad-sync-servers', 'hybrid-ad-changes')][string]$ContinuousJob = '',
    [int]$ContinuousPauseSeconds = 5
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
if ("$Instance".Trim())       { $env:PIM_SCHED_INSTANCE = $Instance.Trim() }
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tools\pim-scheduler' }
$shared = Resolve-Path "$here\..\..\engine\_shared"

$global:PIM_UseGraphSdk = $false   # REST-first; no Graph/Az modules
if ($UseManagedIdentity -or "$env:PIM_UseManagedIdentity".Trim() -eq '1') { $global:PIM_UseManagedIdentity = $true }
. "$shared\PIM-Rest.ps1"
. "$shared\PIM-PortalAccess.ps1"      # Get-PimPolicySetting (config-driven schedule)
. "$shared\PIM-ChangeQueue.ps1"       # Get-PimQueueApplyPlan (queue-apply handler)
# 🔴 §65 -- WITHOUT THIS THE QUEUE IS A BLACK HOLE. queue-apply gates on
# Invoke-PimQueueActionDrain; if the file that defines it is not loaded here the gate simply skips,
# the job reports what it drained (nothing), and every queued revoke / TAP reset / session revoke
# sits in the queue for ever. That is the BUG-134 failure class exactly -- a capability that is
# absent rather than broken, so nothing errors. Caught by Test-PimScheduler's
# "every gated capability is DEFINED IN A FILE THE TICK LOADS" assertion, which exists for this.
. "$shared\PIM-QueueActions.ps1"      # Invoke-PimQueueActionDrain (the ACTION half of queue-apply)
. "$shared\PIM-SqlStore.ps1"          # SQL store (signature read for the change-detector)
. "$shared\PIM-AuditEvent.ps1"        # REQ 100.42 / BUG: Write-PimAuditEvent, the engine's audit writer -- it lived only in the deleted PIM-Functions.psm1, which this entry point never loaded, so every guarded engine audit call (account.create, tap.create, approval.*, license.blocked, rfa.*) was a silent no-op
. "$shared\PIM-Cutover.ps1"           # Invoke-PimSqlChangeDetector (on-demand recalc on SQL change)
. "$shared\PIM-Approvals.ps1"         # escalation logic
. "$shared\PIM-DelegationDepth.ps1"   # two-approval split + reachability + self-deleg
. "$shared\PIM-Lifecycle.ps1"         # reminders / expirations
. "$shared\PIM-Notify.ps1"            # mail notifications (REST sendMail) -- so the daily-summary / tier-report / escalation jobs can actually send AND the send path hydrates EmailControls (kill switch / redirect / allowlist) from pim.Settings for this cold scheduler process
. "$shared\PIM-MailTemplateStore.ps1"  # the ONE mail template store (pim.Settings MailTemplates); merged/seeded at wiring below
. "$shared\PIM-MailLayout.ps1"         # MAIL-2: the designed mail / report layout (the daily changes + tier report mails)
. "$shared\PIM-MailNotifications.ps1"  # MAIL-2: per-recipient Notifications + audience links, read by every sender at send time
. "$shared\PIM-GetStartedReminder.ps1" # MAIL-2 item 8: the daily Get Started reminder (run by the daily-summary job)
. "$shared\PIM-FailureCatalog.ps1"    # classified item failures (cause/remedy/auto-fix), persisted in SQL
. "$shared\PIM-EngineCore.ps1"        # NEW REST+SQL engine (diff + providers)
. "$shared\PIM-DisableGuard.ps1"      # account-disable circuit breaker (incident 2026-06-15)
. "$shared\PIM-Guard.ps1"             # GUARD-1: a guard trip -> state + audit + mail + telemetry
if (Test-Path -LiteralPath "$shared\..\hybrid-ad\PIM-HybridAd.ps1") { . "$shared\..\hybrid-ad\PIM-HybridAd.ps1" }   # §84 Pro: loaded only when present          # on-prem AD/gMSA-sMSA PLANNER + hybrid-worker seam (on-prem write is worker-only)
if (Test-Path -LiteralPath "$shared\..\hybrid-ad\PIM-HybridAdGroups.ps1") { . "$shared\..\hybrid-ad\PIM-HybridAdGroups.ps1" }   # §84 Pro: loaded only when present    # §80.2 PIM-for-AD replacement: AD group mirror + JIT membership (hybrid worker only)
. "$shared\PIM-EngineProviders.ps1"
# REQ-U wave 2: the workload role catalogs (discovery-defender / discovery-intune -> Invoke-PimWorkloadRoleDiscoveryJob). The
# providers file dot-sources it too; named here so the tick's gated capability is visibly loaded (Test-PimScheduler).
. "$shared\PIM-WorkloadRoles.ps1"
# REQ-W (2.4.380): the workload-prerequisite rule the providers apply before creating a workload role assignment
# (Get-PimWorkloadAssignmentGate). The providers file dot-sources it too; named here for the same reason as above.
. "$shared\PIM-WorkloadPrereqs.ps1"
# 🔴 THE ENTRA ROLE CATALOG WAS NEVER LOADED IN THE TICK (found 2026-09-12). Invoke-PimEngineCore.ps1
# loads PIM-ContextBuilder.ps1 + the filters; this runner -- which is what actually runs every
# scheduled job in the cloud -- loaded neither. Build-PimContext therefore did not exist, the
# providers' `try { Build-PimContext } catch {}` swallowed "command not found", $Global:Roles_All_ID
# and $Global:AU_All_ID stayed empty, and EVERY EntraRoles create failed as "unresolved group/role"
# (136 identical failures on internal since 2026-09-10; every attempt since 2026-08-19), while the
# same run resolved all 342 groups. AU attach-at-create silently skipped for the same reason.
# 🔒 NO FILE IS LOADED FOR THIS (operator, 2026-09-12: "we dont use files in pim v2 -- we use only
# sql"). The role catalog and AUs come from Graph; the v1 filters file only feeds filtered lists
# that no v2 engine code reads, and Build-PimContext no longer requires it.
. "$shared\PIM-ContextBuilder.ps1"
. "$shared\PIM-PermissionWizard.ps1"  # Azure scope derivation/depth + group naming (used by the Azure reconcile planner)
# Pro (discovery): loaded only when present -- Get-PimAzureReconcilePlan / ConvertTo-PimReconcileQueueChanges
if (Test-Path -LiteralPath "$shared\..\discovery\PIM-AzureDiscovery.ps1") { . "$shared\..\discovery\PIM-AzureDiscovery.ps1" }
if (Test-Path -LiteralPath "$shared\..\discovery\PIM-Discovery.ps1") { . "$shared\..\discovery\PIM-Discovery.ps1" }   # §84 Pro: loaded only when present         # discovery enumerators + sweep (Invoke-PimDiscoveryJobSweep)
. "$shared\PIM-License.ps1"           # offline Core/Pro edition model (Get-PimEdition)
. "$shared\PIM-FeatureCatalog.ps1"    # feature catalog + gates (Test-PimFeatureAvailable) -- s29/s30
. "$shared\PIM-AlertFeed.ps1"         # ALERT-01: recorded-send proof + the shared SQL feed adapter
# 🔴 TWO SCHEDULED JOBS WERE PERMANENTLY INERT BECAUSE THIS LINE WAS MISSING.
# 'escalations' and 'scheduled-creation' are registered, scheduled and enabled -- and both are
# capability-gated on a function from THIS file (Build-PimLifecycleCalendar,
# Get-PimDueScheduledCreations). It was never dot-sourced here, so every tick in every deployment
# found the function absent and reported `no-op` / `no-handler:Build-PimLifecycleCalendar` --
# forever, and truthfully, which is why nobody chased it: a job that says "no-op" looks like a job
# with nothing to do. Reported 2026-09-10: "why does these 2 say no-op".
# 🪤 The capability gate is right (a worker without the feature must not fail); what was wrong is
# that the capability was never present ANYWHERE. A gate on something nothing loads is a switch
# with no wire behind it.
. "$shared\PIM-Governance.ps1"        # lifecycle calendar + due scheduled creations (escalations / scheduled-creation)
. "$shared\PIM-Notifications.ps1"     # daily-summary / tier-report / servicenow intake poll
. "$shared\PIM-DateSafe.ps1"          # Get-PimUtcStamp, gated on by several handlers
. "$shared\PIM-ArmContainerApps.ps1"  # §56.5 the ARM roller (Set-PimAcaJobImage) the watchdog repairs with
. "$shared\PIM-UpdateWatchdog.ps1"    # §56.5 restore the updater when it adopts a build it cannot run
. "$shared\PIM-JobAlert.ps1"          # ALERT-01: a FAILED scheduled run now raises engine-failure.
                                      # This process already had a mail path (PIM-Notify above) but
                                      # no alerting logic on top of it, so a 03:00 failure was silent.
. "$shared\PIM-Scheduler.ps1"
# §70.1b option 2: the active-assignments LIVE READ (Entra-role / Azure-RBAC / PIM-for-Groups) that used to freeze
# the Manager's single request loop for 140-170 s. Job 'active-assignments-snapshot' runs it here and stores it in
# pim.TenantCache; the Manager only reads that row. Needs _tenantSync.ps1 (below) for the store + connection helpers.
. "$shared\PIM-ActiveAssignments.ps1"
# Drift page (2026-09-14): the live-vs-desired plan that used to run inside the Manager's GET /api/drift. Job
# 'drift-snapshot' runs it here and stores pim.TenantCache kind 'drift'; the Manager only reads that row.
. "$shared\PIM-DriftSnapshot.ps1"
# REQ-I + REQ-U (Coverage & gaps page): job 'coverage' compares the tenant caches with pim.Rows here and stores
# pim.TenantCache kind 'coverage-report'; the Manager only reads that row.
if (Test-Path -LiteralPath "$shared\..\coverage\PIM-Coverage.ps1") { . "$shared\..\coverage\PIM-Coverage.ps1" }   # §84 Pro: loaded only when present
# §79.1: job 'target-check' -- do the Azure scopes and roles the delegation rows point at still exist? Reports only.
. "$shared\PIM-TargetCheck.ps1"
# §79.2: job 'pending-check' -- staged changes (the shared store, §79.13) and queued actions nobody committed.
. "$shared\PIM-SharedPending.ps1"
. "$shared\PIM-PendingCheck.ps1"
# §95.2: job 'licence-request' -- ask Invardia for this install's licence (OFF unless 'licence.autoRequest').
. "$shared\PIM-LicenceRequest.ps1"
# §95.3: job 'uplink' -- status telemetry to Invardia (OFF unless 'telemetry.uplink'); the framework client is a pinned copy.
. "$shared\AitUplink.framework.ps1"
. "$shared\PIM-Uplink.ps1"
# PIM 100.10 (framework 8.7 UPLINK-SETUP): the setup report + the control list (one source with Home) + the ring resolver.
. "$shared\PIM-UplinkSetup.ps1"
# §95.4: job 'install-key' -- claim the Invardia install key (OFF unless 'updates.invardia'); the uplink + Pro updates use it.
. "$shared\PIM-InvardiaUpdate.ps1"
# UPLINK-ENROL (PIM 99): job 'enrolled-tenants' -- the managing tenant allows its enrolled managed tenants' subnets by itself.
# §97.1: job 'workload-prereqs' -- the engine checks the workload prerequisites itself (read-only) and records them. The runner
# (the same checks a person's Initialize-PimWorkloadPrereqs.ps1 makes, read-only in self-check mode) is loaded HERE, at file scope.
. "$shared\PIM-WorkloadPrereqSelfCheck.ps1"
if (Test-Path -LiteralPath "$shared\..\..\tools\setup\_PimWorkloadPrereqRunner.ps1") { . "$shared\..\..\tools\setup\_PimWorkloadPrereqRunner.ps1" }
if (Test-Path -LiteralPath "$shared\..\msp\PIM-InvardiaEnrollment.ps1") { . "$shared\..\msp\PIM-InvardiaEnrollment.ps1" }   # Pro (MSP): loaded only when present -- the community payload has no engine\msp
# REQ-AR-2: job 'access-review-cycle' -- the per-department access review campaigns.
if (Test-Path -LiteralPath "$shared\..\access-reviews\PIM-AccessReviewCycle.ps1") { . "$shared\..\access-reviews\PIM-AccessReviewCycle.ps1" }   # §84 Pro: loaded only when present
if (Test-Path -LiteralPath "$shared\..\rfa\PIM-RfaSync.ps1") { . "$shared\..\rfa\PIM-RfaSync.ps1" }   # §82 Pro: loaded only when present
if (Test-Path -LiteralPath "$shared\..\consultant-lifecycle\PIM-CompanyReviewJob.ps1") { . "$shared\..\consultant-lifecycle\PIM-CompanyReviewJob.ps1" }   # §82 Pro
# REQ-AR-2 remove-on-undecided: an unanswered review whose rule removes undecided people raises the offboard approval
# request (Add-PimApprovalRequest / Get-PimApprovalRequests, pim.Settings through Get-/Set-PimSetting wired below).
. "$shared\PIM-ApprovalGate.ps1"
# §79.7: job 'owner-review' -- department owners confirm (Keep / Extend / Remove) their people on My people.
. "$shared\PIM-OwnerPortal.ps1"
# §83: auto-extend governance (lead time, review Keep, owner Deny, default ON) + the monthly 'autoextend-report'.
. "$shared\PIM-AutoExtend.ps1"

# Scheduler state + run history + acknowledgements live in SQL pim.Settings (SchedulerState /
# JobRunHistory / JobAcknowledgements) -- the SAME store the Manager's Jobs tab reads. The old
# file location ($global:PIM_SchedulerStatePath / $env:PIM_SCHED_STATE_PATH ->
# output\scheduler\pim-scheduler-state.json) is gone: PIM v2 is SQL-only (2026-09-13).

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
        # The ONE mail template store: make sure the retired MailTemplateOverrides are merged in
        # before anything this process sends reads the store (idempotent; once per store).
        if ($_schedProbeOk -and (Get-Command Update-PimMailTemplateStore -ErrorAction SilentlyContinue)) {
            try {
                $_mt = Update-PimMailTemplateStore -ConnectionString $global:PIM_SqlConnectionString -TemplateDir (Join-Path (Resolve-Path "$here\..\..").Path 'templates\mail') -Actor 'scheduler'
                Write-Host "[scheduler] mail templates: $($_mt.count) in SQL ($($_mt.reason))" -ForegroundColor DarkGray
            } catch { Write-Warning "[scheduler] mail template store could NOT be updated: $($_.Exception.Message)" }
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
# §70.1b option 2: the REAL 'active-assignments-snapshot' handler. Registered ONLY here -- the default handler
# declares itself unimplemented, so the Manager (which also initialises the default handlers) can never run it.
Register-PimActiveAssignmentsSnapshotHandler
Write-Host "[scheduler] active-assignments snapshot wired (pim.TenantCache/active-assignments; the Manager reads it)" -ForegroundColor Cyan
# Drift page: the REAL 'drift-snapshot' handler -- registered ONLY here, after the defaults (which declare it unimplemented).
Register-PimDriftSnapshotHandler
Write-Host "[scheduler] drift snapshot wired (pim.TenantCache/drift; the Manager's Drift page reads it)" -ForegroundColor Cyan
# REQ-I + REQ-U: the REAL 'coverage' handler -- registered ONLY here, after the defaults (which declare it unimplemented).
Register-PimJobHandler -Type 'coverage' -Handler {
    param($job, $now, $whatIf)
    Invoke-PimCoverageJob -Job $job -NowUtc $now -WhatIf:$whatIf
}
Write-Host "[scheduler] coverage report wired (pim.TenantCache/coverage-report; the Manager's Coverage & gaps page reads it)" -ForegroundColor Cyan
# §79.1: the REAL 'target-check' handler -- registered ONLY here, after the defaults (which declare it unimplemented).
Register-PimJobHandler -Type 'target-check' -Handler {
    param($job, $now, $whatIf)
    Invoke-PimTargetCheckJob -Job $job -NowUtc $now -WhatIf:$whatIf
}
Write-Host "[scheduler] target check wired (pim.TenantCache/target-check; missing Azure scopes / roles are reported, never removed)" -ForegroundColor Cyan
# §95.2: the REAL 'licence-request' handler. A network failure is reported in the result (asked again next run), never thrown.
# §95.3: the REAL 'uplink' handler. A failed send is reported in the result and sent again next run, never thrown.
Register-PimJobHandler -Type 'uplink' -Handler {
    param($job, $now, $whatIf)
    Invoke-PimUplinkJob -Job $job -NowUtc $now -WhatIf:$whatIf
}
# GUARD-1: the REAL 'licence-check' handler (msp.licence guard). A refused licence is a guard trip, not a failed run.
Register-PimJobHandler -Type 'licence-check' -Handler {
    param($job, $now, $whatIf)
    Invoke-PimLicenceCheckJob -Job $job -NowUtc $now -WhatIf:$whatIf
}
# AUDIT-1.3: the REAL 'audit-retention' handler. Keep-forever (the default) does nothing; a failed delete FAILS the run.
Register-PimJobHandler -Type 'audit-retention' -Handler {
    param($job, $now, $whatIf)
    Invoke-PimAuditRetentionJob -Job $job -NowUtc $now -WhatIf:$whatIf
}
# CONFIG-1.3 / PIM §96.3: the REAL 'config-backup' handler (PIM-ConfigBackup.ps1, loaded with the store). A backup that
# cannot be written FAILS the run (it throws); an unchanged configuration is recorded as "no change", not copied again.
Register-PimJobHandler -Type 'config-backup' -Handler {
    param($job, $now, $whatIf)
    Invoke-PimConfigBackupJob -Job $job -NowUtc $now -WhatIf:$whatIf
}
# §95.4: the REAL 'install-key' handler. A refused or failed claim is reported in the result, never thrown.
Register-PimJobHandler -Type 'install-key' -Handler {
    param($job, $now, $whatIf)
    Invoke-PimInstallKeyJob -Job $job -NowUtc $now -WhatIf:$whatIf
}
Register-PimJobHandler -Type 'licence-request' -Handler {
    param($job, $now, $whatIf)
    Invoke-PimLicenceRequestJob -Job $job -NowUtc $now -WhatIf:$whatIf
}
# UPLINK-ENROL: the REAL 'enrolled-tenants' handler. Invardia not live yet (404) ends OK with that sentence; a refused key,
# an unreadable store or a write that does not read back FAILS the run (it throws).
if (Get-Command Invoke-PimEnrolledTenantsJob -ErrorAction SilentlyContinue) {
    Register-PimJobHandler -Type 'enrolled-tenants' -Handler {
        param($job, $now, $whatIf)
        Invoke-PimEnrolledTenantsJob -Job $job -NowUtc $now -WhatIf:$whatIf
    }
}
# §97.1: the REAL 'workload-prereqs' handler. A store that cannot be read / written or a read-back mismatch FAILS the run.
Register-PimJobHandler -Type 'workload-prereqs' -Handler {
    param($job, $now, $whatIf)
    Invoke-PimWorkloadPrereqSelfCheckJob -Job $job -NowUtc $now -WhatIf:$whatIf
}
# §79.2: the REAL 'pending-check' handler -- registered ONLY here, after the defaults (which declare it unimplemented).
Register-PimJobHandler -Type 'pending-check' -Handler {
    param($job, $now, $whatIf)
    Invoke-PimPendingCheckJob -Job $job -NowUtc $now -WhatIf:$whatIf
}
# §83: the REAL 'autoextend-report' handler. A mail that could not be sent (not a deliberate hold) FAILS the run.
Register-PimJobHandler -Type 'autoextend-report' -Handler {
    param($job, $now, $whatIf)
    $r = Invoke-PimAutoExtendReportJob -Job $job -NowUtc $now -WhatIf:$whatIf
    if ($r.failed) { throw "[autoextend-report] $($r.detail)" }
    $r
}
# §79.7: the REAL 'owner-review' handler. A mail that could not be sent (not a deliberate hold) FAILS the run.
Register-PimJobHandler -Type 'owner-review' -Handler {
    param($job, $now, $whatIf)
    $r = Invoke-PimOwnerReviewJob -Job $job -NowUtc $now -WhatIf:$whatIf
    if ($r.failed) { throw "[owner-review] $($r.detail)" }
    $r
}
Write-Host "[scheduler] pending check wired (uncommitted staged changes + queued actions older than a day are mailed)" -ForegroundColor Cyan
# REQ-AR-2: the REAL 'access-review-cycle' handler. A review that could not be started FAILS the run (it is retried next time).
Register-PimJobHandler -Type 'access-review-cycle' -Handler {
    param($job, $now, $whatIf)
    Invoke-PimAccessReviewCycleJob -Job $job -NowUtc $now -WhatIf:$whatIf
}
Write-Host "[scheduler] access review cycle wired (per-department campaigns from Settings > Access reviews)" -ForegroundColor Cyan
# §82: the REAL 'rfa-sync' / 'company-review' handlers -- only when the Pro libraries are present (Community has neither).
# A run with errors (a row or a mail that failed) FAILS, so status = latest run shows it and the next run retries.
if (Get-Command Invoke-PimRfaSyncJob -ErrorAction SilentlyContinue) {
    Register-PimJobHandler -Type 'rfa-sync' -Handler {
        param($job, $now, $whatIf)
        $r = Invoke-PimRfaSyncJob -Job $job -NowUtc $now -WhatIf:$whatIf
        if ($r.failed) { throw "[rfa-sync] $($r.detail)" }
        $r
    }
    Write-Host "[scheduler] rfa-sync wired (RFA store -> requests -> admin rows; inert until the RFA portal is deployed)" -ForegroundColor Cyan
}
if (Get-Command Invoke-PimCompanyReviewJob -ErrorAction SilentlyContinue) {
    Register-PimJobHandler -Type 'company-review' -Handler {
        param($job, $now, $whatIf)
        $r = Invoke-PimCompanyReviewJob -Job $job -NowUtc $now -WhatIf:$whatIf
        if ($r.failed) { throw "[company-review] $($r.detail)" }
        $r
    }
    Write-Host "[scheduler] company-review wired (consultant lifecycle; inert until a company is defined)" -ForegroundColor Cyan
}

# Wire the per-scope engine-delta / engine-full jobs to the NEW REST engine.
# WhatIf (intent/recalc) -> plan only; otherwise the provider applies via REST.
$engineHandler = {
    param($job,$now,$whatIf)
    $scope = if ($job.PSObject.Properties['scope'] -and "$($job.scope)".Trim()) { "$($job.scope)" } else { 'All' }
    $mode  = if ("$($job.type)" -eq 'engine-full') { 'Full' } else { 'Delta' }
    # 96.5 / D4: a PAUSE stops ONLY the daily reconcile (commits, deltas and Run now still apply). Read right before it runs,
    # so a pause set in the Manager a minute ago holds; the run is recorded as SKIPPED with who / since / why.
    # Purpose 2: the daily reconcile also plans the removal of PIM-managed leftovers -- REPORT ONLY unless pim.Settings
    # 'ReconcileRemovalMode' says enforce (PIM-ReconcileRemoval.ps1).
    $__rrMode = ''
    if ($mode -eq 'Full' -and (Get-Command Get-PimReconcileJobName -ErrorAction SilentlyContinue) -and "$($job.name)" -eq (Get-PimReconcileJobName)) {
        $__gate = Get-PimReconcilePauseGate -Job $job -NowUtc $now -WhatIf:$whatIf
        if ($__gate) { return $__gate }
        $__rrMode = Get-PimReconcileRemovalMode
    }
    $res = if ($__rrMode) { Invoke-PimEngine -Scope $scope -Mode $mode -WhatIf:$whatIf -ReconcileRemoval $__rrMode } else { Invoke-PimEngine -Scope $scope -Mode $mode -WhatIf:$whatIf }
    # 🔴 BUG-134 -- A SCOPE NO PROVIDER SERVES IS A NO-OP THAT REPORTS SUCCESS, FOR EVER.
    # Invoke-PimEngineScope answers an unknown scope with { ok=$false; detail="no provider for
    # scope '<x>'" } and NO create/update/remove. This handler ignored `ok` and formatted the
    # missing counts anyway, so the tick logged
    #     delta-groups-assign  engine Delta [GroupsAssignment] GroupsAssignment:c/u/r
    # and the job was recorded SUCCEEDED. Every other scope printed real numbers
    # (AdministrativeUnits:c16/u0/r0), so the blank one read as "nothing to do".
    # 🔑 MEASURED ON THE INTERNAL ENVIRONMENT 2026-09-12. Two of the five scheduled jobs --
    # 'GroupsAssignment' and 'GroupsCreateModifyPolicy' -- are LEGACY CSV-ENGINE scope names that
    # the REST engine does not register. GroupsAssignment is what nests a role group into its
    # permission groups, so a delegation authored in the Manager was created, committed, shown
    # correctly on the Access map, and NEVER APPLIED to Entra. The operator's report was exactly
    # that: "i created this delegation but it hasnt added the pim-role to the 2 permission groups".
    # The provider that does this work is registered as 'GroupMembers'; nothing ever called it.
    # 🪤 An unserved scope is a CONFIGURATION error, not an empty result, and the two must not look
    # alike. Fail the job so it surfaces as a failed tick instead of a silent success.
    # 🔑 `ok` is FALSE in two distinct situations, and they need DIFFERENT operator actions:
    #   (a) the scope bound to no provider          -> a configuration error (BUG-134)
    #   (b) the scope ran but item applies FAILED   -> errors>0, e.g. Graph throttling that
    #       survived all 5 retries, or a genuine permission/data problem.
    # (b) is the one that decides whether a delegation can be TRUSTED as deployed: without this,
    # a run whose applies all failed reported `Succeeded` and the operator had no signal at all.
    # Invoke-PimEngineScope sets ok=($errors -eq 0), so both land here -- but the message must
    # say which, or the next reader debugs the wrong thing.
    $bad = @(@($res) | Where-Object { $_ -and $_.PSObject.Properties['ok'] -and -not $_.ok })
    # 71.13 -- a run whose ONLY errors are policy mass-change HOLDS is 'held' (needs approval), not failed.
    # A real item failure or an unbound scope in the same run still falls through to the throw below.
    $outcome = $null
    if ($bad.Count -and (Get-Command Get-PimEngineRunOutcome -ErrorAction SilentlyContinue)) { $outcome = Get-PimEngineRunOutcome -Results @($res) }
    if ($outcome -and $outcome.outcome -eq 'held') {
        $sumH = @($res) | ForEach-Object { "$($_.scope):c$($_.create)/u$($_.update)/r$($_.remove)" }
        return [pscustomobject]@{ ran=$true; held=$true; heldCount=[int]$outcome.heldCount; holds=@($outcome.holds)
            detail=("engine $mode [$scope] " + ($sumH -join ' ') + " -- NEEDS APPROVAL: " + $outcome.detail); whatIf=[bool]$whatIf }
    }
    # 🔴 WAITING IS NOT FAILING (operator, 2026-09-22: an alert for 'delta-admins' whose only problem
    # was "1x The group this item needs does not exist yet [GROUP-NOT-CREATED-YET]" -- "bug"). That
    # item is ORDER: the Groups job creates the group in the same cycle and the membership applies on
    # the next run. Failing the job for it raises an alert every cycle for something that fixes
    # itself -- and an alert that cries wolf is how the next REAL failure goes unread. A run whose
    # only failures are transient + retryable (and have not outlived their cause) is reported OK,
    # saying how many items are waiting and why.
    if ($bad.Count -and (Get-Command Test-PimEngineFailuresAreAllTransient -ErrorAction SilentlyContinue)) {
        $__failedScopes = @($bad | Where-Object { [int]$_.errors -gt 0 })
        $__allItems = @($__failedScopes | ForEach-Object { if ($_.PSObject.Properties['failures']) { @($_.failures) } })
        $__unboundAny = @($bad | Where-Object { "$($_.detail)" -match 'no provider for scope' }).Count
        if (-not $__unboundAny -and $__allItems.Count -and (Test-PimEngineFailuresAreAllTransient -Failures $__allItems -NowUtc $now)) {
            $sumW = @($res) | ForEach-Object { "$($_.scope):c$($_.create)/u$($_.update)/r$($_.remove)" }
            $waitTxt = if (Get-Command Format-PimFailureSummary -ErrorAction SilentlyContinue) { Format-PimFailureSummary -Failures $__allItems } else { "$($__allItems.Count) item(s) waiting" }
            return [pscustomobject]@{ ran=$true; waiting=[int]$__allItems.Count; whatIf=[bool]$whatIf
                detail=("engine $mode [$scope] " + ($sumW -join ' ') + ' -- ' + $waitTxt) }
        }
    }
    if ($bad.Count) {
        $unbound = @($bad | Where-Object { "$($_.detail)" -match 'no provider for scope' })
        $failed  = @($bad | Where-Object { [int]$_.errors -gt 0 })
        $parts = @()
        if ($unbound.Count) {
            $known = @()
            try { $known = @(Get-PimEngineScopes) } catch { }
            $parts += ("scope '$scope' is bound to NO PROVIDER (" +
                       (@($unbound | ForEach-Object { "$($_.detail)" }) -join '; ') +
                       "). This job is a no-op. Registered scopes: " + ($known -join ', '))
        }
        if ($failed.Count) {
            $n = (@($failed) | Measure-Object -Property errors -Sum).Sum
            # 🔴 The old message pointed the reader at per-item log lines in a container log the Manager cannot show (operator,
            # 2026-09-12: "the eror msg was useless"). Say WHAT failed, grouped by cause, and where the
            # per-item detail and fixes are.
            $__items = @($failed | ForEach-Object { if ($_.PSObject.Properties['failures']) { @($_.failures) } })
            $__summary = if ($__items.Count -and (Get-Command Format-PimFailureSummary -ErrorAction SilentlyContinue)) { Format-PimFailureSummary -Failures $__items } else { '' }
            if ($__summary) {
                $parts += ("[" + (@($failed | ForEach-Object { "$($_.scope)" }) -join ', ') + "] " + $__summary)
            } else {
                $parts += ("$n item(s) FAILED to apply in [" +
                           (@($failed | ForEach-Object { "$($_.scope):errors=$($_.errors)" }) -join ', ') +
                           "]. The desired state is NOT deployed for those items.")
            }
        }
        if (-not $parts.Count) { $parts += (@($bad | ForEach-Object { "$($_.detail)" }) -join '; ') }
        throw ("[scheduler] engine job '$($job.name)' FAILED: " + ($parts -join ' | '))
    }
    $sum = @($res) | ForEach-Object { "$($_.scope):c$($_.create)/u$($_.update)/r$($_.remove)" }
    # REQ-U (2.4.378): scope WARNINGS (e.g. "group X has a Workload but its binding provider is turned off", or an area
    # NOT CHECKED) reach the run's summary line -- the Jobs page and the run record -- not only the captured log.
    $warns = @(@($res) | ForEach-Object { $sc = "$($_.scope)"; if ($_.PSObject.Properties['warnings']) { @($_.warnings) | Where-Object { "$_".Trim() } | ForEach-Object { "${sc}: $_" } } })
    $notChk = @(@($res) | Where-Object { $_.PSObject.Properties['notChecked'] -and $_.notChecked } | ForEach-Object { "$($_.scope) NOT CHECKED ($($_.skippedReason)$($_.error))" })
    $tail = ''
    if ($notChk.Count) { $tail += ' | ' + ($notChk -join '; ') }
    if ($warns.Count) { $tail += " | $($warns.Count) warning(s): " + (@($warns | Select-Object -First 5) -join '; ') + $(if ($warns.Count -gt 5) { "; +$($warns.Count - 5) more (see the run's log)" } else { '' }) }
    if ($__rrMode) {
        # 96.5: the removal plan in one line (the full report is on the Jobs page).
        $__rrW = 0; $__rrC = 0; $__rrR = 0
        foreach ($__x in @($res)) { if ($__x -and $__x.PSObject.Properties['reconcileRemoval'] -and $__x.reconcileRemoval) { $__rrW += [int]$__x.reconcileRemoval.wouldRemove; $__rrC += [int]$__x.reconcileRemoval.candidates }; if ($__x -and $__x.PSObject.Properties['reconcileRemoved']) { $__rrR += [int]$__x.reconcileRemoved } }
        $tail += $(if ($__rrMode -eq 'enforce') { " | reconcile removal (enforce): $__rrR removed of $__rrW qualifying; $($__rrC - $__rrW) left alone" } else { " | reconcile removal (report only): would remove $__rrW; $($__rrC - $__rrW) held by a rule" })
    }
    [pscustomobject]@{ ran=$true; detail=("engine $mode [$scope] " + ($sum -join ' ') + $tail); warnings=@($warns); notChecked=@($notChk); whatIf=[bool]$whatIf }
}
Register-PimJobHandler -Type 'engine-delta' -Handler $engineHandler
Register-PimJobHandler -Type 'engine-full'  -Handler $engineHandler

# 🔴 BUG-185 (§33.28): the break-glass (emergency) override had NO v2 consumer -- the Manager recorded it and
# nothing read it. Every tick now applies an active override (approval OFF on the scoped groups, audited, owners
# notified) and restores the linked policy at expiry (Invoke-PimEmergencyOverrideStep, PIM-EngineProviders.ps1).
Register-PimJobHandler -Type 'emergency-override' -Handler {
    param($job,$now,$whatIf)
    Invoke-PimEmergencyOverrideStep -NowUtc $now -WhatIf:$whatIf
}
Write-Host "[scheduler] emergency override wired (pim.Settings/EmergencyOverride -> approval off / restore at expiry)" -ForegroundColor Cyan

# --- THE TRUST JOB: prove DESIRED == LIVE, cheaply, and keep proving it ---------
# Operator, 2026-09-12: "it is critical that we can trust that the delegation is actual deployed
# into the platform - otherwise customer will not trust it. how do you control this desired state
# ... so it matches the actual delegation in pim".
#
# 🔑 Every other job makes a FAILURE visible. This one makes SUCCESS PROVABLE, which is a
# different claim -- BUG-134 is precisely a case where nothing errored and nothing was deployed.
# The measurement is taken FROM THE TENANT: `-Mode Full -WhatIf` re-reads live via Graph, diffs
# against desired in pim.Rows, and returns create = desired-but-not-live. WhatIf writes nothing.
#
# CACHING (operator: "cache the result, so you dont have to run every hour all checks"): each
# scope is skipped while its DESIRED SIGNATURE is unchanged AND its last result was clean AND the
# cache is younger than the backstop. Hashing the desired side is what makes the cache safe --
# an age-only cache would be stale exactly in the minutes after a commit, when the truth matters
# most. An unconverged scope is ALWAYS re-checked; that is the one we are waiting to see go green.
$convScopes = @(
    @{ scope = 'GroupMembers';      entity = 'PIM-Assignments-Groups' }            # delegation nesting
    @{ scope = 'AdminMembers';      entity = 'PIM-Assignments-Admins' }            # admin -> PIM group
    @{ scope = 'EntraRoles';        entity = 'PIM-Assignments-Roles-Groups' }      # role -> group
    @{ scope = 'RolesAUs';          entity = 'PIM-Assignments-Roles-AUs' }         # role scoped to an AU
    @{ scope = 'AzRes';             entity = 'PIM-Assignments-Azure-Resources' }   # Azure resource roles
)
Register-PimJobHandler -Type 'verify-convergence' -Handler {
    param($job,$now,$whatIf)
    $cs = "$($global:PIM_EngineSqlCs)"; if (-not $cs) { $cs = "$($global:PIM_SqlConnectionString)" }
    # State lives beside the scheduler's other state so it survives a scale-to-zero replica.
    $cache = @{}; $seen = @{}
    try {
        $cs0 = Get-PimConvergenceState
        $cache = ConvertTo-PimPlainMap $cs0.cache
        $seen  = ConvertTo-PimPlainMap $cs0.firstSeen
    } catch { }

    # 1. What needs verifying this cycle?
    $sig = @()
    foreach ($s in $convScopes) {
        $h = ''
        if ($cs -and (Get-Command Get-PimDesiredStateSignature -ErrorAction SilentlyContinue)) {
            $h = Get-PimDesiredStateSignature -ConnectionString $cs -Entity $s.entity
        }
        # '' = signature UNKNOWN. Make it unique per run so it can never compare equal to the
        # cached value -- an unreadable signature must force a verify, never imply "unchanged".
        if (-not "$h".Trim()) { $h = "unknown-$([guid]::NewGuid())" }
        $sig += [pscustomobject]@{ scope = $s.scope; desiredHash = $h }
    }
    $plan = @(Get-PimConvergenceScopePlan -Scopes $sig -Cache $cache -NowUtc $now)

    # 2. Verify the ones that need it; carry the rest from cache.
    $unconverged = New-Object System.Collections.Generic.List[string]
    $unverifiable = New-Object System.Collections.Generic.List[string]
    $checked = 0; $fromCache = 0
    foreach ($p in $plan) {
        $hash = @($sig | Where-Object { $_.scope -eq $p.scope })[0].desiredHash
        if (-not $p.verify) {
            # 🔑 INVARIANT: a scope is only skipped when its cached result was CLEAN
            # (Get-PimConvergenceScopePlan always re-verifies unconverged>0), so it has no
            # outstanding findings to carry. Contributing nothing here is therefore correct --
            # and is ONLY correct because of that rule. If the skip condition is ever widened,
            # this must start carrying the scope's findings forward like the failure path below.
            $fromCache++
            continue
        }
        $checked++
        try {
            # Plan-only: reads live, writes nothing. `create` = desired but NOT present live.
            $r = @(Invoke-PimEngine -Scope $p.scope -Mode Full -WhatIf)
            $n = 0
            foreach ($x in $r) {
                $n += [int]$x.create
                foreach ($pl in @($x.plan)) { if ("$($pl.op)" -eq 'Create') { $unconverged.Add("$($p.scope)|$($pl.key)") } }
            }
            $cache[$p.scope] = @{ desiredHash = "$hash"; checkedUtc = $now.ToUniversalTime().ToString('o'); unconverged = $n }
            $col = if ($n) { 'Yellow' } else { 'DarkGray' }
            Write-Host ("[verify] {0,-16} unconverged={1}  ({2})" -f $p.scope, $n, $p.reason) -ForegroundColor $col
        } catch {
            # 🔴 A VERIFICATION THAT FAILED PROVES NOTHING -- and must not be recorded as either
            # outcome. Two separate mistakes are avoided here:
            #   1. it must not be CACHED AS CLEAN (that would be an error read as a good result --
            #      the exact conflation behind BUG-134), so the cache entry is dropped; and
            #   2. it must not RESET THE AGE CLOCK of findings this scope already had. Dropping
            #      them from the verdict's input would do precisely that, because a key absent
            #      from $Unconverged falls out of the state. Repeated Graph throttling is the
            #      likeliest cause of a failed verification, so that is exactly the situation
            #      where the clocks must keep running -- otherwise an environment that can never
            #      complete a verification would never raise a convergence failure either.
            $cache.Remove($p.scope)
            foreach ($k in @($seen.Keys)) { if ("$k".StartsWith("$($p.scope)|")) { $unverifiable.Add("$k") } }
            Write-Warning "[verify] $($p.scope) could not be verified (findings keep their age): $($_.Exception.Message)"
        }
    }

    # 3. Age the findings. New != broken; persistent == broken.
    $verdict = Get-PimConvergenceVerdict -Unconverged @($unconverged.ToArray()) -Previous $seen -NowUtc $now `
                   -Unverifiable @($unverifiable.ToArray())
    [void](Save-PimConvergenceState -Cache $cache -FirstSeen $verdict.state)

    $detail = "verify scopes checked=$checked cached=$fromCache unconverged=$($verdict.total) (new=$($verdict.new) persistent=$($verdict.persistent))"
    if (-not $verdict.ok) {
        $top = @($verdict.items | Where-Object { [int]$_.ageMinutes -ge 60 } | Select-Object -First 10 |
                 ForEach-Object { "$($_.key) (unapplied $($_.ageMinutes)m)" })
        throw ("[scheduler] CONVERGENCE FAILURE -- $($verdict.persistent) delegation/assignment(s) exist in the " +
               "Manager but NOT in the tenant, and have stayed that way past the grace window. " +
               "The desired state is NOT deployed: " + ($top -join '; ') +
               ". Run tools/setup/Repair-PimJobBindingBacklog.ps1 to quantify and clear the backlog.")
    }
    [pscustomobject]@{ ran=$true; detail=$detail; unconverged=$verdict.total; whatIf=[bool]$whatIf }
}
Write-Host "[scheduler] convergence verification wired (scopes: $(($convScopes | ForEach-Object { $_.scope }) -join ', '))" -ForegroundColor Cyan
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
# the REST enumerators. The queue is SQL pim.ChangeQueue only (IMP-40).
Register-PimDiscoveryHandler `
    -GetDiscovered {
        param($scope)
        switch ($scope) {
            'Azure'   { try { @(Get-PimLiveAzureScopes -IncludeManagementGroups) } catch { @() } }
            'PowerBI' {
                try {
                    $ws = @(Get-PimLivePowerBiWorkspaces)
                    # REQ-DISC-2: the Discovery inbox lists workspaces from the tenant cache -- store what was read.
                    if (Get-Command Set-PimTenantCacheEntry -ErrorAction SilentlyContinue) {
                        try { [void](Set-PimTenantCacheEntry -Kind 'powerbi-workspaces' -Value ([ordered]@{ readUtc = [datetime]::UtcNow.ToString('o'); items = @($ws | ForEach-Object { [ordered]@{ workspaceId = "$($_.workspaceId)"; workspaceName = "$($_.workspaceName)" } }) })) }
                        catch { Write-Warning "[discovery] the Power BI workspace list could not be stored for the Discovery page: $($_.Exception.Message)" }
                    }
                    $ws
                } catch { @() }
            }
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
        # 🔴 IMP-40 (§33.28) -- SQL ONLY. This used to fall back to a JSON queue FILE on a SQL failure: EPHEMERAL in a
        # container and never drained by queue-apply, so the proposals were lost while the job reported success.
        # A proposal that cannot be written to pim.ChangeQueue now FAILS the discovery job (the throw propagates out of
        # the sweep), so the operator sees it and the next run proposes it again.
        # 🔴 BUG-212 -- DE-DUPLICATED. discovery-entra re-proposed the same ~130 Creates every day and pending rows piled
        # up; Add-PimSqlQueueChangeIfAbsent adds nothing when an open entry for the same entity/key/op already exists.
        if (-not "$($global:PIM_SqlConnectionString)".Trim()) {
            throw "[discovery] no SQL store is wired -- the proposal '$($change.entity)/$($change.key)' cannot be queued (PIM v2 keeps the change queue in SQL only)"
        }
        try {
            if (-not (Add-PimSqlQueueChangeIfAbsent -ConnectionString $global:PIM_SqlConnectionString -Change $change)) {
                $script:__discoDupes++
                Write-Verbose "  [discovery] '$($change.entity)/$($change.key)' ($($change.op)) is already open in the queue -- not added again"
            }
        } catch {
            throw "[discovery] the proposal '$($change.entity)/$($change.key)' could NOT be written to pim.ChangeQueue -- it is NOT queued: $($_.Exception.Message)"
        }
    } `
    -AutoImportPowerBI:([bool]$global:PIM_DiscoveryAutoImportPowerBi)
$script:__discoDupes = 0
Write-Host "[scheduler] discovery handler wired (Azure/PowerBI scope-discovery + Entra role-catalog -> change queue: SQL pim.ChangeQueue, de-duplicated)" -ForegroundColor Cyan

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

# §56.5 -- WATCH THE UPDATER, BECAUSE THE UPDATER CANNOT WATCH ITSELF.
# `ca-pim-update` stamps itself onto each new image after the MANAGER has proved healthy on it --
# but the Manager and the updater are different entry points in the SAME image, so an image can
# boot the Manager perfectly and still be unable to run the updater (measured: 2.4.296-2.4.301).
# An updater that adopts such an image fails every night and CANNOT REPAIR ITSELF: the thing that
# would fix it is the broken thing. Recovery would need a human inside the customer's tenant.
#
# 🔑 THIS tick is the right place, and the only place available: it runs every five minutes, from
# the same image, and it keeps running when the update job does not.
#
# 🔒 It NEVER throws at the tick. The tick's real job is engine reconciliation; a watchdog that can
# break what it rides on is worse than no watchdog. Off unless the environment says where it is.
function Invoke-PimUpdaterWatchdogIfConfigured {
    $wsub = "$($env:PIM_SubscriptionId)".Trim()
    $wrg  = "$($env:PIM_ResourceGroup)".Trim()
    if (-not $wsub -or -not $wrg) { return }
    if ("$($env:PIM_UPDATE_WATCHDOG)".Trim() -eq '0') { return }   # explicit opt-out
    if (-not (Get-Command Invoke-PimUpdateWatchdog -ErrorAction SilentlyContinue)) { return }
    $stale = if ("$($env:PIM_UPDATE_STALE_HOURS)".Trim()) { [double]"$($env:PIM_UPDATE_STALE_HOURS)".Trim() } else { 48 }
    $jn    = if ("$($env:PIM_UpdateJobName)".Trim()) { "$($env:PIM_UpdateJobName)".Trim() } else { 'ca-pim-update' }
    try {
        [void](Invoke-PimUpdateWatchdog -SubscriptionId $wsub -ResourceGroup $wrg -JobName $jn `
                 -StaleAfterHours $stale -Log { param($m, $c) Write-Host $m -ForegroundColor $c })
    } catch { Write-Host "  [watchdog] skipped: $($_.Exception.Message)" -ForegroundColor Yellow }
}

if ($ContinuousJob) {
    # No lease / no scheduler state: the loop owns exactly one job type, the scheduler instance does not schedule it.
    # It stops when the installed VERSION changes (the hybrid worker's updater swapped the code), so the task that keeps it
    # alive restarts it on the new code.
    $verFile = Join-Path $here '..\..\VERSION'
    $verAtStart = if (Test-Path $verFile) { (Get-Content -LiteralPath $verFile -Raw).Trim() } else { '' }
    Write-Host "[scheduler] CONTINUOUS $ContinuousJob (pause ${ContinuousPauseSeconds}s, version $verAtStart)" -ForegroundColor Cyan
    [void](Invoke-PimHybridAdSyncLoop -JobName $ContinuousJob -PauseSeconds $ContinuousPauseSeconds -WhatIf:$WhatIf -StopWhen {
        $v = if (Test-Path $verFile) { (Get-Content -LiteralPath $verFile -Raw).Trim() } else { '' }
        if ($v -ne $verAtStart) { "the installed version changed ($verAtStart -> $v)" } })
    return
}
if ($Once) {
    # Self-healing layer 2 (operator 2026-10-02: "it must be running 24x7x365"): the 5-minute hybrid tick runs as the SAME gMSA as
    # the continuous sync loop, so it may end a loop that stopped making progress; the sync task restarts it within a minute.
    # (Instance 'hybridsrv' runs as another gMSA and could not -- it does not try.)
    if ("$Instance".Trim() -eq 'hybrid' -and (Get-Command Invoke-PimHybridSyncWatchdogCheck -ErrorAction SilentlyContinue)) {
        # every continuous lane has its own liveness stamp; each is judged on its own (a lane that never ran has none: no action)
        foreach ($lane in @('hybrid-ad-sync', 'hybrid-ad-sync-servers', 'hybrid-ad-changes')) {
            try { $wd = Invoke-PimHybridSyncWatchdogCheck -Lane $lane; if ($wd.action -ne 'none' -or $lane -eq 'hybrid-ad-sync') { Write-Host "  [$lane watchdog] $($wd.action): $($wd.detail)" -ForegroundColor $(if ($wd.action -eq 'killed') { 'Yellow' } else { 'DarkGray' }) } }
            catch { Write-Host "  [$lane watchdog] check failed: $($_.Exception.Message)" -ForegroundColor Yellow }
        }
    }
    # MAIL-STEP-PROOF (owner 2026-10-09: "i have run 3 cmdlet, and test mail works - but it still shows eros"): Send test mail
    # in the Manager queues ONE engine test send (pim.Settings 'MailEngineTest') and starts this job; it is sent FIRST, as the
    # engine job's own identity, so its send proof lands within about a minute. Main tick only (a hybrid worker is not the
    # engine's mail identity). Never throws -- it must not cost the tick.
    if (-not $WhatIf -and -not "$Instance".Trim() -and -not "$($env:PIM_SCHED_INSTANCE)".Trim() -and (Get-Command Invoke-PimMailEngineTest -ErrorAction SilentlyContinue)) {
        try { $_met = Invoke-PimMailEngineTest; if ($_met.ran) { Write-Host "  [mail] $($_met.detail)" -ForegroundColor $(if ($_met.sent) { 'Green' } else { 'Yellow' }) } }
        catch { Write-Host "  [mail] engine test mail skipped: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
    @(Invoke-PimSchedulerTick -WhatIf:$WhatIf -LeaseTtlMinutes $ttl) | ForEach-Object { Write-Host ("  {0,-20} {1}" -f $_.name, $_.detail) }
    if (-not $WhatIf) { Invoke-PimUpdaterWatchdogIfConfigured }
    return
}
Start-PimScheduler -IntervalSeconds $iv -LeaseTtlMinutes $ttl -WhatIf:$WhatIf
