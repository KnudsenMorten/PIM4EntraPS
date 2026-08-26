# IMP-02: the locale-safe stamp reader. Loaded defensively so this file stays correct
# when a test dot-sources it on its own (PIM-Functions.psm1 also loads it up front).
if (-not (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-DateSafe.ps1') }
<#
  PIM4EntraPS -- scheduler / job runner.

  The always-on container's job engine (see docs/ARCHITECTURE-HOSTING.md "Execution
  model"). A PURE due-calculation core (fully testable, time injected) + a pluggable
  handler registry + a thin loop the container runs. Drives the existing job logic
  (lifecycle reminders/escalations, change-queue apply, engine Full/Delta, MSP pull).
  No PowerShell modules; single-runner via a SQL/state lease.

  Design:
    * schedule  = array of jobs { name; type; intervalMinutes; enabled; nextRunUtc? }
    * Get-PimDueJobs / Test-PimJobDue / Get-PimNextRunUtc   -- pure, tested offline
    * Register-PimJobHandler / Invoke-PimScheduledJob       -- dispatch by type
    * Invoke-PimSchedulerTick                               -- run all due jobs once
    * Start-PimScheduler                                    -- the loop (container)
  State (last/next run) + the single-runner lease persist via the settings store when
  available (SQL pim.Settings), else a JSON file, else in-memory.
#>

Set-StrictMode -Off

# Job types. The on-demand TRIGGER fires on COMMIT ONLY (Request-PimCommit), or when the
# monitor detects an already-COMMITTED change in SQL -> 'engine-delta' recomputes +
# reconciles that scope. **Queuing a change does NOT trigger anything** (it just stages
# rows in the queue); the engine recalculates only at commit time.
# NOTE (operator correction 2026-06-18): the UPDATE (code / SQL-schema / Manager-GUI roll) is
# DELIBERATELY NOT a scheduler job type. The engine + scheduler are for engine runs / slave DATA
# downlink ONLY. The standalone update mechanism -- tools/setup/Invoke-PimUpdate.ps1, run by
# VisualCron / Task Scheduler (tools/setup/Register-PimSyncSchedule.ps1) or the bootstrap
# post-sync deploy hook (sync/_SyncDeploy.ps1) -- owns code+schema+GUI updates. Do NOT re-add a
# 'sync-automateit' / 'update' job type here; that re-couples the update to the scheduler.
# See docs/REQUIREMENTS.md "Update is SEPARATE from the PIM engine + job-scheduler".
$script:PimJobTypes    = @('queue-apply','engine-delta','engine-full','msp-pull','reminders','escalations','discovery','scheduled-creation','daily-summary','tier-report','servicenow-intake','tenant-cache')
$script:PimJobHandlers = @{}      # type -> scriptblock(job, nowUtc, whatIf)
$script:PimSchedState  = $null    # in-memory fallback for state

# ---- schedule (config-driven, overridable) --------------------------------
function Get-PimDefaultJobSchedule {
    # PHASE-SPLIT delta: each domain (entra / groups / azure / workloads) is its own
    # job with its own cadence, so a change in one domain is detected + committed fast
    # without waiting for a whole-tenant pass, and domains run independently (and can be
    # parallelized). The 'scope' maps onto the engine's existing -Scope. A daily
    # engine-full does the whole-tenant reconcile. Split finer (per-tenant in MSP, or
    # per-workload) by overriding 'JobSchedule' in config -- nothing here is hardcoded.
    # 'scope' = the engine's existing -Scope token, so each phase is just
    # `PIM-Engine -Scope <scope> -Mode Delta`. Phases map to what the engine does today:
    # admin accounts, group deployment, group assignments, PIM enablement/delegation
    # (Entra roles / Azure resources / AUs), and PIM policies -- each with its own
    # cadence so a change commits fast without a whole-tenant pass. Override 'JobSchedule'
    # in config to split finer (per workload, per customer tenant in MSP) or coarser.
    @(
        [pscustomobject]@{ name='queue-apply';        type='queue-apply';  intervalMinutes=5;    enabled=$true  }
        [pscustomobject]@{ name='delta-admins';       type='engine-delta'; scope='Admins';                  intervalMinutes=15;   enabled=$true  }
        # AdminTap is its OWN provider (order 35), NOT part of the Admins scope -- so without a job
        # here nothing ever ran it except the daily `full-reconcile` (scope All). Measured in EFIF:
        # four accounts created at 18:22 with CreateTAP=TRUE all had TAP=none, and would have kept
        # it until 06:05 the next morning. No error anywhere -- the TAP, and therefore the
        # tap-delivery mail, just silently did not happen for ~12 hours. Paired with delta-admins'
        # cadence so a newly-created admin gets its TAP on the next pass, not the next day.
        [pscustomobject]@{ name='delta-admin-tap';    type='engine-delta'; scope='AdminTap';                intervalMinutes=15;   enabled=$true  }
        [pscustomobject]@{ name='delta-groups-assign';type='engine-delta'; scope='GroupsAssignment';        intervalMinutes=15;   enabled=$true  }
        [pscustomobject]@{ name='delta-groups-deploy';type='engine-delta'; scope='GroupsCreateModifyPolicy';intervalMinutes=30;   enabled=$true  }
        [pscustomobject]@{ name='delta-policies';     type='engine-delta'; scope='GroupsPolicies';          intervalMinutes=60;   enabled=$true  }
        [pscustomobject]@{ name='delta-pim-entra';    type='engine-delta'; scope='EntraRoles';              intervalMinutes=20;   enabled=$true  }
        [pscustomobject]@{ name='delta-pim-azure';    type='engine-delta'; scope='AzRes';                   intervalMinutes=30;   enabled=$true  }
        [pscustomobject]@{ name='delta-pim-au';       type='engine-delta'; scope='AdministrativeUnits';     intervalMinutes=30;   enabled=$true  }
        [pscustomobject]@{ name='delta-workloads';    type='engine-delta'; scope='Workloads';               intervalMinutes=60;   enabled=$true  }
        [pscustomobject]@{ name='escalations';        type='escalations';     intervalMinutes=60;   enabled=$true  }
        [pscustomobject]@{ name='discovery-entra';    type='discovery'; scope='Entra';   intervalMinutes=1440; enabled=$true  }
        [pscustomobject]@{ name='discovery-azure';    type='discovery'; scope='Azure';   intervalMinutes=1440; enabled=$true  }
        [pscustomobject]@{ name='discovery-powerbi';  type='discovery'; scope='PowerBI'; intervalMinutes=1440; enabled=$true  }
        [pscustomobject]@{ name='reminders';          type='reminders';       intervalMinutes=720;  enabled=$true  }
        [pscustomobject]@{ name='scheduled-creation'; type='scheduled-creation'; intervalMinutes=30; enabled=$true  }  # § 13: future-dated admin create + TAP
        [pscustomobject]@{ name='servicenow-intake';  type='servicenow-intake'; intervalMinutes=10;   enabled=$true  }  # poll the store-and-forward drop store
        [pscustomobject]@{ name='daily-summary';      type='daily-summary';   intervalMinutes=1440; enabled=$true  }
        [pscustomobject]@{ name='tier-report';        type='tier-report';     intervalMinutes=1440; enabled=$true  }
        # Tenant-list cache refresh: pull entra-roles / AUs / PIM-* groups / Azure
        # scopes + RBAC roles into the per-instance cache so role-name validation,
        # the autocomplete pickers, and the role-permission drill-down stay fresh
        # WITHOUT relying on a Manager restart. 12h cadence keeps it inside the
        # 24h freshness window the GUI badge + validator use. The Manager process
        # is read-only on this cache; the SCHEDULER owns the refresh.
        [pscustomobject]@{ name='tenant-cache';       type='tenant-cache';    intervalMinutes=720;  enabled=$true  }
        [pscustomobject]@{ name='full-reconcile';     type='engine-full';  scope='All';      intervalMinutes=1440; enabled=$true  }
        [pscustomobject]@{ name='msp-pull';           type='msp-pull';        intervalMinutes=240;  enabled=$false }  # MSP deployments only
        # NOTE: NO 'sync-automateit' / update job here by design (operator correction 2026-06-18).
        # Code/SQL-schema/Manager-GUI updates are a STANDALONE mechanism run OUTSIDE the engine +
        # scheduler -- tools/setup/Invoke-PimUpdate.ps1, scheduled by VisualCron / Task Scheduler
        # (Register-PimSyncSchedule.ps1) or fired by the bootstrap post-sync deploy hook. The
        # scheduler stays for engine runs / slave data downlink only.
    )
}
function Get-PimJobSchedule {
    if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) {
        $c = Get-PimPolicySetting -Name 'JobSchedule' -Default $null; if ($c) { return @($c) }
    }
    if ($global:PIM_JobSchedule) { return @($global:PIM_JobSchedule) }
    return Get-PimDefaultJobSchedule
}

# ---- cold-boot settings hydration (GUI-state == actual-behavior fix) -------
# Get-PimJobSchedule resolves 'JobSchedule' via Get-PimPolicySetting, which reads
# $global:PIM_NamingConventions. In the MANAGER that bag is hydrated from SQL pim.Settings
# at boot, so a GUI-saved cadence is honoured. A COLD-booted scheduler / one-shot tick
# never ran that boot path, so without this it would silently fall back to the DEFAULT
# schedule and ignore the persisted cadence. Import-PimSchedulerSettingsFromStore loads
# pim.Settings into $global:PIM_NamingConventions (incl. JobSchedule + EmailControls) once
# per process so a freshly-booted scheduler honours the persisted source of truth. FAIL-
# SAFE: a store-read failure leaves the in-process schedule as-is (the default), never
# crashes a tick. No-op when no SQL store is configured (file/in-memory deployments).
function Import-PimSchedulerSettingsFromStore {
    param([switch]$Force)
    if ($script:PimSchedSettingsHydrated -and -not $Force) { return $false }
    if (-not (Get-Command Import-PimSettingsFromStore -ErrorAction SilentlyContinue)) { return $false }
    $n = -1
    try { $n = Import-PimSettingsFromStore } catch { $n = -1 }
    if ($n -ge 0) {
        $script:PimSchedSettingsHydrated = $true
        if ($n -gt 0) { Write-Host "[scheduler] hydrated $n setting(s) from pim.Settings (JobSchedule/EmailControls honoured from the GUI source of truth)" -ForegroundColor DarkCyan }
        return $true
    }
    return $false   # store unreachable -> keep current/default schedule (fail-safe), retry next boot/tick
}

# ---- pure due-calculation core (testable) ---------------------------------
function Get-PimNextRunUtc {
    param([Parameter(Mandatory)][object]$Job, [Parameter(Mandatory)][datetime]$FromUtc)
    $iv = [int]$Job.intervalMinutes; if ($iv -le 0) { $iv = 60 }
    return $FromUtc.ToUniversalTime().AddMinutes($iv)
}
function Test-PimJobDue {
    param([Parameter(Mandatory)][object]$Job, [Parameter(Mandatory)][datetime]$NowUtc)
    $en = $true; if ($Job.PSObject.Properties['enabled']) { $en = [bool]$Job.enabled }
    if (-not $en) { return $false }
    $next = $null
    if ($Job.PSObject.Properties['nextRunUtc'] -and "$($Job.nextRunUtc)".Trim()) {
        $next = Get-PimUtcStamp $Job.nextRunUtc   # IMP-02; unreadable -> treated as never scheduled (due)
    }
    if ($null -eq $next) { return $true }                 # never scheduled -> due
    return ($NowUtc.ToUniversalTime() -ge $next)
}
function Get-PimDueJobs {
    param([object[]]$Jobs, [Parameter(Mandatory)][datetime]$NowUtc)
    if (-not $Jobs) { $Jobs = Get-PimJobSchedule }
    @(@($Jobs) | Where-Object { Test-PimJobDue -Job $_ -NowUtc $NowUtc })
}

# ---- handler registry -----------------------------------------------------
function Register-PimJobHandler {
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][scriptblock]$Handler)
    $script:PimJobHandlers["$Type".ToLowerInvariant()] = $Handler
}
function Get-PimJobHandler { param([string]$Type) $script:PimJobHandlers["$Type".ToLowerInvariant()] }
function Get-PimJobHandlerTypes { @($script:PimJobHandlers.Keys) }

function Select-PimJobHandlers {
    # Worker-container scoping: keep ONLY the named job types, drop the rest. Lets one
    # image run as any subset of workers (manager+all-in-one, or split engine /
    # connector / delta-queue / discovery containers) purely via $env:PIM_SCHED_JOBS.
    # No filter (empty) = run everything.
    param([string[]]$Only)
    $keep = @($Only | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    if ($keep.Count -eq 0) { return @($script:PimJobHandlers.Keys) }
    foreach ($t in @($script:PimJobHandlers.Keys)) { if ($t -notin $keep) { [void]$script:PimJobHandlers.Remove($t) } }
    return @($script:PimJobHandlers.Keys)
}

function Initialize-PimDefaultJobHandlers {
    # Wire handlers to the EXISTING logic where it's present; otherwise a clearly
    # logged no-op stub (so a tick never crashes and the gap is visible). Real engine
    # handlers are registered by the launcher/container as the REST engine matures.
    Register-PimJobHandler -Type 'reminders' -Handler {
        param($job,$now,$whatIf)
        if (Get-Command Build-PimLifecycleCalendar -ErrorAction SilentlyContinue) {
            $items = @(); if ($global:PIM_LifecycleItems) { $items = @($global:PIM_LifecycleItems) }
            $cal = Build-PimLifecycleCalendar -Items $items -NowUtc $now -NotifyLog ($(if ($global:PIM_LifecycleNotifyLog) { $global:PIM_LifecycleNotifyLog } else { @{} }))
            # auto-renew AutoExtend items within the window -> change queue (commit later)
            $renewals = @($cal.renewals)
            return [pscustomobject]@{ ran=$true; detail="upcoming=$(@($cal.upcoming).Count) renew=$($renewals.Count)"; calendar=$cal; whatIf=[bool]$whatIf }
        }
        return [pscustomobject]@{ ran=$false; detail='no-handler:Build-PimLifecycleCalendar' }
    }
    Register-PimJobHandler -Type 'escalations' -Handler {
        param($job,$now,$whatIf)
        if (Get-Command Build-PimLifecycleCalendar -ErrorAction SilentlyContinue) {
            $items = @(); if ($global:PIM_LifecycleItems) { $items = @($global:PIM_LifecycleItems) }
            $cal = Build-PimLifecycleCalendar -Items $items -NowUtc $now -NotifyLog ($(if ($global:PIM_LifecycleNotifyLog) { $global:PIM_LifecycleNotifyLog } else { @{} }))
            $due = @($cal.escalations)
            if ($due.Count -and (Get-Command Send-PimLifecycleEscalations -ErrorAction SilentlyContinue)) {
                $send = Send-PimLifecycleEscalations -Calendar $cal -RecipientResolver $global:PIM_LifecycleRecipientResolver -NotifyLog ($(if ($global:PIM_LifecycleNotifyLog) { $global:PIM_LifecycleNotifyLog } else { @{} })) -WhatIf:$whatIf
                $global:PIM_LifecycleNotifyLog = $send.notifyLog
            }
            return [pscustomobject]@{ ran=$true; detail="escalations-due=$($due.Count)"; calendar=$cal; whatIf=[bool]$whatIf }
        }
        return [pscustomobject]@{ ran=$false; detail='no-handler:Build-PimLifecycleCalendar' }
    }
    Register-PimJobHandler -Type 'scheduled-creation' -Handler {
        param($job,$now,$whatIf)
        # § 13: which future-dated admin rows are due to be created now (+ TAP).
        # The container/launcher registers the REAL create handler; until then we
        # compute the due set (pure) and record intent (no tenant write here).
        if (Get-Command Get-PimDueScheduledCreations -ErrorAction SilentlyContinue) {
            $rows = @(); if ($global:PIM_ScheduledAdminRows) { $rows = @($global:PIM_ScheduledAdminRows) }
            $due = @(Get-PimDueScheduledCreations -Rows $rows -NowUtc $now)
            $tap = @($due | Where-Object { $_.decision.tapDue }).Count
            return [pscustomobject]@{ ran=$true; detail="create-due=$($due.Count) tap-due=$tap"; due=$due; whatIf=[bool]$whatIf }
        }
        return [pscustomobject]@{ ran=$false; detail='no-handler:Get-PimDueScheduledCreations' }
    }
    Register-PimJobHandler -Type 'queue-apply' -Handler {
        param($job,$now,$whatIf)
        if (Get-Command Get-PimQueueApplyPlan -ErrorAction SilentlyContinue) {
            return [pscustomobject]@{ ran=$true; detail='queue-apply-plan'; whatIf=[bool]$whatIf }
        }
        return [pscustomobject]@{ ran=$false; detail='no-handler:Get-PimQueueApplyPlan' }
    }
    # (1) Daily summary of delegation/assignment changes -- read this month's audit jsonl,
    # fold into a 24h digest, render + send to the configured digest recipients.
    Register-PimJobHandler -Type 'daily-summary' -Handler {
        param($job,$now,$whatIf)
        if (-not (Get-Command Get-PimDailySummary -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ ran=$false; detail='no-handler:Get-PimDailySummary' } }
        $events = @()
        if ($global:PIM_SummaryEvents) { $events = @($global:PIM_SummaryEvents) }   # injected by the launcher; else read audit jsonl below
        elseif ((Get-Command Get-PimOutputDir -ErrorAction SilentlyContinue)) {
            try {
                $f = Join-Path (Join-Path (Get-PimOutputDir) 'audit') ("pim-audit-{0}.jsonl" -f $now.ToString('yyyyMM'))
                if (Test-Path -LiteralPath $f) { $events = @(Get-Content -LiteralPath $f -Encoding UTF8 | Where-Object { "$_".Trim() } | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} }) }
            } catch {}
        }
        $sum = Get-PimDailySummary -Events $events -NowUtc $now
        $rcpts = @($global:PIM_DigestRecipients) | Where-Object { "$_".Trim() }
        if ($rcpts.Count -gt 0 -and (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) {
            $tok = ConvertTo-PimDailySummaryTokens -Summary $sum -TenantLabel "$($global:PIM_TenantLabel)"
            foreach ($r in $rcpts) { Send-PimNotifyMail -Type 'daily-summary' -Tokens $tok -Recipient "$r" -WhatIf:$whatIf | Out-Null }
        }
        return [pscustomobject]@{ ran=$true; detail="daily-summary changes=$($sum.totalChanges) recipients=$($rcpts.Count)"; whatIf=[bool]$whatIf }
    }
    # (2) Tier 0/1 report -- needs the assignment rows; launcher injects them in
    # $global:PIM_TierReportAssignments (data query lives in the engine providers).
    Register-PimJobHandler -Type 'tier-report' -Handler {
        param($job,$now,$whatIf)
        if (-not (Get-Command Get-PimTierZeroOneReport -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ ran=$false; detail='no-handler:Get-PimTierZeroOneReport' } }
        $rows = @(); if ($global:PIM_TierReportAssignments) { $rows = @($global:PIM_TierReportAssignments) }
        $rep = Get-PimTierZeroOneReport -Assignments $rows
        $rcpts = @($global:PIM_TierReportRecipients) | Where-Object { "$_".Trim() }
        if ($rcpts.Count -gt 0 -and (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) {
            $tok = ConvertTo-PimTierReportTokens -Report $rep -TenantLabel "$($global:PIM_TenantLabel)"
            foreach ($r in $rcpts) { Send-PimNotifyMail -Type 'tier-report' -Tokens $tok -Recipient "$r" -WhatIf:$whatIf | Out-Null }
        }
        return [pscustomobject]@{ ran=$true; detail="tier-report users=$($rep.Count) recipients=$($rcpts.Count)"; whatIf=[bool]$whatIf }
    }
    # (4) ServiceNow intake poll -- read the store-and-forward drop store, route each
    # pending record (approve -> approval request/mail; auto-apply -> change queue). The
    # poll itself never mutates; routing decisions are returned for the caller/engine to apply.
    Register-PimJobHandler -Type 'servicenow-intake' -Handler {
        param($job,$now,$whatIf)
        if (-not (Get-Command Invoke-PimIntakePoll -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ ran=$false; detail='no-handler:Invoke-PimIntakePoll' } }
        $store = "$($global:PIM_IntakeStoreFile)".Trim()
        if (-not $store) { return [pscustomobject]@{ ran=$false; detail='no PIM_IntakeStoreFile configured' } }
        $decisions = @(Invoke-PimIntakePoll -StoreFile $store -NowUtc $now)
        $approve = @($decisions | Where-Object { $_.route -eq 'approve' }).Count
        $auto    = @($decisions | Where-Object { $_.route -eq 'auto-apply' }).Count
        $reject  = @($decisions | Where-Object { $_.route -eq 'reject' }).Count
        return [pscustomobject]@{ ran=$true; detail="intake poll approve=$approve auto-apply=$auto reject=$reject"; decisions=$decisions; whatIf=[bool]$whatIf }
    }
    # Tenant-list cache refresh. The real refresher (Invoke-PimTenantListRefresh)
    # lives in tools/pim-manager/_tenantSync.ps1; the scheduler launcher dot-sources
    # it so this default handler drives it. When it isn't loaded (e.g. a worker that
    # doesn't carry the Manager files, or the offline unit tests) the handler is a
    # clearly-logged no-op -- a tick never crashes and the gap is visible.
    Register-PimJobHandler -Type 'tenant-cache' -Handler {
        param($job,$now,$whatIf)
        if (-not (Get-Command Invoke-PimTenantListRefresh -ErrorAction SilentlyContinue)) {
            return [pscustomobject]@{ ran=$false; detail='no-handler:Invoke-PimTenantListRefresh (dot-source tools/pim-manager/_tenantSync.ps1)'; whatIf=[bool]$whatIf }
        }
        # WhatIf = intent only; the live refresh writes the per-instance cache files.
        if ($whatIf) { return [pscustomobject]@{ ran=$true; detail='tenant-cache refresh (whatif: no write)'; whatIf=$true } }
        $r = Invoke-PimTenantListRefresh -Quiet
        if ($r.ok) {
            $counts = @()
            if ($r.results) { foreach ($k in $r.results.Keys) { $counts += ("{0}={1}" -f $k, $(if ($r.results[$k].ok) { $r.results[$k].count } else { 'ERR' })) } }
            return [pscustomobject]@{ ran=$true; detail=("tenant-cache refreshed " + ($counts -join ' ')); result=$r; whatIf=$false }
        }
        return [pscustomobject]@{ ran=$false; detail=("tenant-cache refresh skipped: " + ("$($r.reason)").Trim()); result=$r; whatIf=$false }
    }
    foreach ($t in 'engine-delta','engine-full','msp-pull') {
        Register-PimJobHandler -Type $t -Handler {
            param($job,$now,$whatIf)
            # The container/launcher registers the real engine handler; until then,
            # the runner records intent (incl. the -Scope phase) rather than touching the
            # legacy entrypoints. Real handler: PIM-Engine -Scope $job.scope -Mode Delta.
            $scope = if ($job.PSObject.Properties['scope']) { "$($job.scope)" } else { 'All' }
            [pscustomobject]@{ ran=$false; detail="stub:$($job.type) scope=$scope (register a real handler)"; whatIf=[bool]$whatIf }
        }
    }
    # discovery: a default handler that drives the REAL sweep (Invoke-PimDiscoveryJobSweep)
    # via the seam wired by Register-PimDiscoveryHandler. Until the launcher supplies the
    # live enumerator + store readers, it is a clearly-logged no-op (never crashes, the
    # gap is visible) -- mirroring the tenant-cache handler.
    Register-PimJobHandler -Type 'discovery' -Handler {
        param($job,$now,$whatIf)
        $scope = if ($job.PSObject.Properties['scope']) { "$($job.scope)" } else { 'All' }
        [pscustomobject]@{ ran=$false; detail="no-handler:discovery scope=$scope (call Register-PimDiscoveryHandler with the live enumerator/store seams)"; whatIf=[bool]$whatIf }
    }
    # NOTE: NO 'sync-automateit' / update handler is registered here by design (operator
    # correction 2026-06-18). The UPDATE is a STANDALONE mechanism (tools/setup/Invoke-PimUpdate.ps1)
    # invoked by VisualCron / Task Scheduler / the bootstrap post-sync deploy hook -- it is NEVER
    # triggered or run by the engine or the in-container scheduler. The former
    # Register-PimSyncAutomateItHandler seam (which shelled the update orchestrator with -Apply from
    # a scheduler tick) was REMOVED to enforce that separation. Do not re-introduce it.
}

function Register-PimDiscoveryHandler {
    <#
      Wire the REAL discovery handler. The container/launcher (which has the live
      REST enumerators + the desired/definition store reader loaded) calls this with
      the seams the PURE sweep needs, so the in-container scheduler can run the three
      'discovery' jobs (Entra / Azure / PowerBI) on their cadence. The handler maps
      the job's -Scope to Invoke-PimDiscoveryJobSweep (PIM-Discovery.ps1):

        -GetDiscovered  : scriptblock(scope) -> the live enumerated items for a scope
                          (e.g. Get-PimLiveAzureScopes / Get-PimLivePowerBiWorkspaces)
        -GetExisting    : scriptblock(scope) -> current definition rows for a scope
        -EnqueueChange  : scriptblock(change) -> push a fresh change-queue record
                          (e.g. Add-PimChangeToQueue against the queue file / SQL)
        -GetAutoImportRules : optional scriptblock(scope) -> Azure auto-import rules
        -AutoImportPowerBI  : opt PowerBI auto-import on (default OFF -> propose only)

      A WhatIf tick computes + reports but writes nothing (no enqueue, no handled-set).
      The Entra discovery scope is the role-CATALOG delta (Invoke-PimRoleCatalogJobSweep
      over Get-PimRoleCatalogDelta) -- a different shape from the scope sweep -- so when
      a -GetLiveRoles seam is supplied the Entra-scope job catalogs new built-in roles;
      with no -GetLiveRoles seam it degrades to a clear "scope not wired" no-op (kept
      explicit rather than silently doing nothing). REQUIREMENTS §8.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$GetDiscovered,
        [Parameter(Mandatory)][scriptblock]$GetExisting,
        [Parameter(Mandatory)][scriptblock]$EnqueueChange,
        [scriptblock]$GetAutoImportRules,
        [scriptblock]$GetLiveRoles,
        [switch]$AutoImportPowerBI
    )
    if (-not (Get-Command Invoke-PimDiscoveryJobSweep -ErrorAction SilentlyContinue)) {
        throw "Invoke-PimDiscoveryJobSweep not loaded (dot-source engine/_shared/PIM-Discovery.ps1 before wiring the discovery handler)."
    }
    $script:PimDiscoveryGetDiscovered  = $GetDiscovered
    $script:PimDiscoveryGetExisting    = $GetExisting
    $script:PimDiscoveryEnqueueChange  = $EnqueueChange
    $script:PimDiscoveryGetAutoRules   = $GetAutoImportRules
    $script:PimDiscoveryGetLiveRoles   = $GetLiveRoles
    $script:PimDiscoveryAutoImportPbi  = [bool]$AutoImportPowerBI
    Register-PimJobHandler -Type 'discovery' -Handler {
        param($job,$now,$whatIf)
        $scope = if ($job.PSObject.Properties['scope']) { "$($job.scope)" } else { 'All' }

        # ENTRA scope = the role-CATALOG delta (new built-in roles), a different shape
        # from the Azure/PowerBI scope sweep. Wired only when -GetLiveRoles was supplied.
        if ($scope -eq 'Entra') {
            if (-not $script:PimDiscoveryGetLiveRoles) {
                return [pscustomobject]@{ ran=$false; detail="discovery scope 'Entra' not wired (no -GetLiveRoles seam supplied)"; whatIf=[bool]$whatIf }
            }
            $service = if ($job.PSObject.Properties['service'] -and "$($job.service)") { "$($job.service)" } else { 'entra' }
            $live = @(& $script:PimDiscoveryGetLiveRoles $service)
            $roleArgs = @{
                Service       = $service
                Live          = $live
                EnqueueChange = $script:PimDiscoveryEnqueueChange
            }
            if ($whatIf) { $roleArgs['WhatIf'] = $true }
            $rr = Invoke-PimRoleCatalogJobSweep @roleArgs
            return [pscustomobject]@{ ran=$true; detail="$($rr.detail)"; result=$rr; whatIf=[bool]$whatIf }
        }

        if ($scope -ne 'Azure' -and $scope -ne 'PowerBI') {
            return [pscustomobject]@{ ran=$false; detail="discovery scope '$scope' not wired (Azure/PowerBI scope-discovery + Entra role-catalog are handled)"; whatIf=[bool]$whatIf }
        }
        $discovered = @(& $script:PimDiscoveryGetDiscovered $scope)
        $existing   = @(& $script:PimDiscoveryGetExisting   $scope)
        $rules      = @()
        if ($scope -eq 'Azure' -and $script:PimDiscoveryGetAutoRules) { $rules = @(& $script:PimDiscoveryGetAutoRules $scope) }
        $sweepArgs = @{
            Scope         = $scope
            Discovered    = $discovered
            Existing      = $existing
            EnqueueChange = $script:PimDiscoveryEnqueueChange
        }
        if ($scope -eq 'Azure')   { $sweepArgs['AutoImportRules'] = $rules }
        if ($scope -eq 'PowerBI') { $sweepArgs['AutoImport'] = $script:PimDiscoveryAutoImportPbi }
        if ($whatIf) { $sweepArgs['WhatIf'] = $true }
        $r = Invoke-PimDiscoveryJobSweep @sweepArgs
        [pscustomobject]@{ ran=$true; detail="$($r.detail)"; result=$r; whatIf=[bool]$whatIf }
    }
}

# Map a scheduled job TYPE to the PIM-FeatureCatalog feature key it belongs to, so
# the scheduler gate (REQUIREMENTS s29) covers "gates everywhere, not just GUI":
# a disabled feature performs no work no matter how it is triggered (incl. schedule).
function Get-PimJobFeatureKey {
    param([Parameter(Mandatory)][string]$Type)
    switch ("$Type".ToLowerInvariant()) {
        'discovery'        { return 'discovery.sweep' }
        'daily-summary'    { return 'alerting.email' }
        'tier-report'      { return 'alerting.email' }
        'reminders'        { return 'alerting.email' }
        'escalations'      { return 'alerting.email' }
        'msp-pull'         { return 'msp.downlink' }
        default            { return $null }   # core/engine jobs are not gated by a feature
    }
}

function Invoke-PimScheduledJob {
    param([Parameter(Mandatory)][object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $h = Get-PimJobHandler -Type "$($Job.type)"
    if (-not $h) { return [pscustomobject]@{ name="$($Job.name)"; type="$($Job.type)"; ok=$false; detail='no-handler-registered'; ranUtc=$NowUtc.ToString('o') } }
    # --- FEATURE GATE (REQUIREMENTS s29) -- a job whose feature is disabled/unlicensed
    # NO-OPs (no writes/sends), regardless of schedule. The 'scheduler.jobs' feature is
    # the master switch for ALL scheduled jobs; a per-type feature gates its own job.
    if (Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) {
        if (-not (Test-PimFeatureAvailable -Key 'scheduler.jobs' -Quiet)) {
            return [pscustomobject]@{ name="$($Job.name)"; type="$($Job.type)"; ok=$true; detail="feature 'scheduler.jobs' disabled -- skipped"; skippedFeature='scheduler.jobs'; ranUtc=$NowUtc.ToString('o') }
        }
        $fk = Get-PimJobFeatureKey -Type "$($Job.type)"
        if ($fk -and -not (Test-PimFeatureAvailable -Key $fk -Quiet)) {
            return [pscustomobject]@{ name="$($Job.name)"; type="$($Job.type)"; ok=$true; detail="feature '$fk' disabled -- skipped"; skippedFeature=$fk; ranUtc=$NowUtc.ToString('o') }
        }
    }
    try {
        $r = & $h $Job $NowUtc.ToUniversalTime() $WhatIf
        return [pscustomobject]@{ name="$($Job.name)"; type="$($Job.type)"; ok=$true; detail="$($r.detail)"; result=$r; ranUtc=$NowUtc.ToString('o') }
    } catch {
        return [pscustomobject]@{ name="$($Job.name)"; type="$($Job.type)"; ok=$false; detail="error: $($_.Exception.Message)"; ranUtc=$NowUtc.ToString('o') }
    }
}

function Get-PimSchedulerStoreVerdict {
    <#
      BUG-45 -- decide whether an unreachable store is fatal. PURE: no SQL, no env, no output.

      MEASURED on mfnpr 2026-08-09/10. The tick was given correct SQL coordinates, acquired a
      managed-identity token, printed "[scheduler] SQL store wired -> ...", and then every single
      read failed with "Login failed for user '<token-identified principal>'" -- the contained DB
      user had never been created, because the deploy died before the grant (BUG-44). The tick
      could not read FeatureGates, fell back to built-in defaults, skipped EVERY job, and
      **exited 0**. Four consecutive executions reported Succeeded having done nothing at all.

      "Wired" is not "reachable", and that gap is the whole defect: a connection string resolves
      long before anyone proves a connection opens. So the probe is separate from the wiring, and
      its verdict is graded rather than boolean:

        fatal -- HOSTED and the store cannot be reached. There is no useful degraded mode here:
                 scheduler state does not persist (so every job looks due on every tick) and the
                 single-runner lease (BUG-36) cannot arbitrate between processes. Non-zero exit
                 is the only signal a cron Job has; taking it away is what made this invisible.
        warn  -- not hosted (a workstation run). Degrading to a file store is legitimate there.
        ok    -- reachable, or no SQL configured at all (file store by design).

      Deliberately NOT fatal: "every job was skipped by the feature gate". That is the DESIGNED
      safe default for a protected environment (SEC-02) and firing on it would make a correctly
      configured tenant fail forever. The defect is the unreachable store, not the gate.
    #>
    [CmdletBinding()]
    param(
        [bool]$Hosted,
        # SQL coordinates were supplied (PIM_SqlServer / PIM_SqlConnectionString).
        [bool]$SqlConfigured,
        # A connection string was successfully resolved from them.
        [bool]$ConnectionStringResolved,
        # A real read against the store succeeded.
        [bool]$ProbeOk,
        [string]$ProbeError = ''
    )
    if (-not $SqlConfigured) {
        if ($Hosted) {
            return [pscustomobject]@{ level = 'fatal'; reason = 'hosted-no-sql'
                detail = 'PIM_HOSTED=1 but no PIM_SqlServer/PIM_SqlConnectionString. A hosted tick has no durable store: scheduler state cannot survive the container and the single-runner lease cannot arbitrate between runs.' }
        }
        return [pscustomobject]@{ level = 'ok'; reason = 'file-store'; detail = 'no SQL configured -- file store (local run).' }
    }
    if (-not $ConnectionStringResolved) {
        $d = 'SQL coordinates are set but no connection string could be resolved from them.'
        if ($Hosted) { return [pscustomobject]@{ level = 'fatal'; reason = 'no-connection-string'; detail = $d } }
        return [pscustomobject]@{ level = 'warn'; reason = 'no-connection-string'; detail = $d }
    }
    if (-not $ProbeOk) {
        $d = "the SQL store was wired but is NOT reachable: $ProbeError"
        if ($Hosted) {
            return [pscustomobject]@{ level = 'fatal'; reason = 'store-unreachable'
                detail = ($d + " A 'Login failed for user <token-identified principal>' here means the identity has no contained DB user in this database -- the deploy's Grant-PimMiSql step did not run or did not succeed. Refusing to report success for a tick that can do no work.") }
        }
        return [pscustomobject]@{ level = 'warn'; reason = 'store-unreachable'; detail = $d }
    }
    return [pscustomobject]@{ level = 'ok'; reason = 'store-reachable'; detail = 'SQL store reachable.' }
}

# ---- state persistence (SQL settings -> file -> memory) -------------------
function Get-PimSchedulerState {
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { $v = Get-PimSetting -Name 'SchedulerState'; if ($v) { return ($v | ConvertFrom-Json) } } catch {}
    }
    if ($global:PIM_SchedulerStatePath -and (Test-Path $global:PIM_SchedulerStatePath)) {
        try { return (Get-Content $global:PIM_SchedulerStatePath -Raw | ConvertFrom-Json) } catch {}
    }
    return $script:PimSchedState
}
function Save-PimSchedulerState {
    param([Parameter(Mandatory)][object]$State)
    $script:PimSchedState = $State
    $json = $State | ConvertTo-Json -Depth 8
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { try { Set-PimSetting -Name 'SchedulerState' -Value $json | Out-Null; return } catch {} }
    if ($global:PIM_SchedulerStatePath) { try { Set-Content -Path $global:PIM_SchedulerStatePath -Value $json -Encoding UTF8 } catch {} }
}

# ---- run history + per-run logs (SQL settings -> file -> memory) -----------
# The scheduler keeps a bounded ring of recent runs so the Manager GUI can show
# "last run + result + log" and mark in-progress jobs. A run record:
#   { runId; name; type; scope; ok; ran; detail; status(running|completed|failed);
#     startedUtc; finishedUtc; durationMs; log(string) }
# Persisted via the SAME store chain as scheduler state (shared across the
# manager + scheduler processes): SQL pim.Settings 'JobRunHistory', else the JSON
# sibling of $global:PIM_SchedulerStatePath, else in-memory.
$script:PimRunHistory     = $null            # in-memory fallback
$script:PimRunHistoryMax  = 50               # ring size PER job name

function Get-PimRunHistoryPath {
    if ("$($global:PIM_SchedulerStatePath)".Trim()) {
        $dir = Split-Path -Parent $global:PIM_SchedulerStatePath
        if (-not $dir) { $dir = '.' }
        return (Join-Path $dir 'pim-scheduler-runs.json')
    }
    return $null
}
function Get-PimJobRunHistory {
    # Returns an array of run records (newest first). Optional -Name filters to one job.
    param([string]$Name)
    $all = $null
    # NOTE (PS 5.1): assign ConvertFrom-Json to a temp FIRST, then @($tmp). Wrapping the
    # pipeline directly -- @(... | ConvertFrom-Json) -- collapses a JSON array into a
    # single Object[] element (count 1) on Windows PowerShell. The temp forces enumeration.
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { $v = Get-PimSetting -Name 'JobRunHistory'; if ($v) { $tmp = $v | ConvertFrom-Json; $all = @($tmp) } } catch {}
    }
    if ($null -eq $all) {
        $p = Get-PimRunHistoryPath
        if ($p -and (Test-Path -LiteralPath $p)) { try { $tmp = (Get-Content -LiteralPath $p -Raw -Encoding UTF8) | ConvertFrom-Json; $all = @($tmp) } catch {} }
    }
    if ($null -eq $all) { $all = @($script:PimRunHistory) }
    $all = @(@($all) | Where-Object { $_ })
    if ("$Name".Trim()) { $all = @($all | Where-Object { "$($_.name)" -eq "$Name" }) }
    return @($all | Sort-Object { "$($_.startedUtc)" } -Descending)
}
function Save-PimJobRunHistory {
    param([object[]]$Runs = @())
    $script:PimRunHistory = @($Runs)
    $json = (@($Runs) | ConvertTo-Json -Depth 8)
    if ($null -eq $json) { $json = '[]' }
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { try { Set-PimSetting -Name 'JobRunHistory' -Value $json | Out-Null; return } catch {} }
    $p = Get-PimRunHistoryPath
    if ($p) { try { Set-Content -LiteralPath $p -Value $json -Encoding UTF8 } catch {} }
}
function Add-PimJobRunRecord {
    # Append one finished run to the ring, trimming to $script:PimRunHistoryMax per job.
    param([Parameter(Mandatory)][object]$Run)
    $all = @(Get-PimJobRunHistory)
    # drop any prior 'running' placeholder for the same runId (it's now finished)
    if ("$($Run.runId)".Trim()) { $all = @($all | Where-Object { "$($_.runId)" -ne "$($Run.runId)" }) }
    $all = @(@($Run) + $all)
    # per-job trim
    $kept = New-Object System.Collections.Generic.List[object]
    $counts = @{}
    foreach ($r in @($all | Sort-Object { "$($_.startedUtc)" } -Descending)) {
        $n = "$($r.name)"; if (-not $counts.ContainsKey($n)) { $counts[$n] = 0 }
        if ($counts[$n] -lt $script:PimRunHistoryMax) { $kept.Add($r); $counts[$n]++ }
    }
    Save-PimJobRunHistory -Runs $kept.ToArray()
}
function Get-PimJobRunLog {
    # Read one run's log text by runId (for the GUI "Logs" button).
    param([Parameter(Mandatory)][string]$RunId)
    $rec = @(Get-PimJobRunHistory | Where-Object { "$($_.runId)" -eq "$RunId" }) | Select-Object -First 1
    if (-not $rec) { return $null }
    return [pscustomobject]@{ runId="$RunId"; name="$($rec.name)"; type="$($rec.type)"; status="$($rec.status)"; startedUtc="$($rec.startedUtc)"; finishedUtc="$($rec.finishedUtc)"; ok=[bool]$rec.ok; log="$($rec.log)" }
}
# ---- [M6] failure history + overdue detection + acknowledge (pure core) -----
# These three are the Jobs-tab gaps called out in REQUIREMENTS.md s28 [M6]:
#   * failure history  -- recent runs per job with pass/fail/when (not just the last)
#   * overdue detection -- a job that SHOULD have fired by now but did not
#   * acknowledge/clear -- mute a known failure so the operator can clear the signal
# All are PURE (run records + a now-time injected) so they unit-test offline with no
# network, no clock dependency, and no store. The Manager/scheduler wrappers below
# (Get-PimJobFailureHistory / Set-PimRunAcknowledged) bind them to the run-history
# store; the cores take their inputs as parameters.

function Get-PimRunFailureHistory {
    # PURE: given an array of run records (any order) for ONE OR MANY jobs, return the
    # recent runs newest-first with a normalised { ok; failed; when; status } shape, and
    # the failed subset surfaced. Acknowledged runs are still listed but flagged so the
    # GUI can dim/hide them. -Take bounds the recent window; -Name filters to one job.
    param(
        [object[]]$Runs = @(),
        [string]$Name,
        [int]$Take = 10,
        [string[]]$AcknowledgedRunIds = @()
    )
    $ackSet = @{}
    foreach ($id in @($AcknowledgedRunIds)) { if ("$id".Trim()) { $ackSet["$id"] = $true } }
    $list = @(@($Runs) | Where-Object { $_ })
    if ("$Name".Trim()) { $list = @($list | Where-Object { "$($_.name)" -eq "$Name" }) }
    # Only FINISHED runs count toward history (a 'running' placeholder is not a result).
    $finished = @($list | Where-Object { "$($_.status)" -ne 'running' -and "$($_.finishedUtc)".Trim() })
    $sorted = @($finished | Sort-Object { "$($_.startedUtc)" } -Descending)
    if ($Take -gt 0) { $recent = @($sorted | Select-Object -First $Take) } else { $recent = $sorted }
    $shaped = New-Object System.Collections.Generic.List[object]
    foreach ($r in $recent) {
        $rid = "$($r.runId)"
        $shaped.Add([pscustomobject]@{
            runId        = $rid
            name         = "$($r.name)"
            type         = "$($r.type)"
            scope        = "$($r.scope)"
            ok           = [bool]$r.ok
            failed       = (-not [bool]$r.ok)
            status       = "$($r.status)"
            detail       = "$($r.detail)"
            startedUtc   = "$($r.startedUtc)"
            finishedUtc  = "$($r.finishedUtc)"
            # [int64], not [int] -- a >24.9-day duration overflows Int32 and would throw
            # here even though the record was written correctly (BUG-04; fixing only the
            # write site left this narrowing cast to re-throw on READ).
            durationMs   = $(if ($r.PSObject.Properties['durationMs']) { [int64]$r.durationMs } else { [int64]0 })
            trigger      = [bool]$r.trigger
            reason       = "$($r.reason)"
            acknowledged = [bool]($ackSet.ContainsKey($rid))
        })
    }
    $fails  = @($shaped | Where-Object { $_.failed })
    $unack  = @($fails | Where-Object { -not $_.acknowledged })
    $runsArr = @($shaped.ToArray())
    return [pscustomobject]@{
        runs            = $runsArr
        failures        = $fails
        failureCount    = $fails.Count
        unackedFailures = $unack.Count
        total           = $runsArr.Count
    }
}

function Get-PimJobOverdueState {
    # PURE: is ONE job overdue? Overdue = enabled, has a cadence, and its NEXT scheduled
    # run (last run + interval, or the persisted nextRunUtc) is in the past by more than a
    # grace margin AND it is not currently running. A never-run job is NOT "overdue" -- it
    # has simply never fired yet (the GUI surfaces that separately). Inputs are injected so
    # this is fully testable: -LastRunUtc / -NextRunUtc / -NowUtc.
    #   GraceMinutes = how late counts as overdue (default = max(1 cadence, 5 min)).
    param(
        [Parameter(Mandatory)][object]$Job,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [string]$LastRunUtc,
        [string]$NextRunUtc,
        [bool]$InProgress = $false,
        [int]$GraceMinutes = 0
    )
    $now = $NowUtc.ToUniversalTime()
    $en = $true; if ($Job.PSObject.Properties['enabled']) { $en = [bool]$Job.enabled }
    $iv = 0; if ($Job.PSObject.Properties['intervalMinutes']) { $iv = [int]$Job.intervalMinutes }
    $result = [pscustomobject]@{ overdue = $false; expectedUtc = $null; overdueByMinutes = 0; reason = '' }
    if (-not $en)    { $result.reason = 'disabled';  return $result }
    if ($iv -le 0)   { $result.reason = 'on-demand'; return $result }   # no cadence -> never "overdue"
    if ($InProgress) { $result.reason = 'running';   return $result }
    # Resolve the EXPECTED fire time: prefer an explicit nextRunUtc; else last run + interval.
    $expected = $null
    # IMP-02: locale-safe; an unreadable stamp yields no basis -> 'never-run', not overdue.
    $tmp = Get-PimUtcStamp $NextRunUtc
    if ($null -ne $tmp) {
        $expected = $tmp
    } else {
        $tmp = Get-PimUtcStamp $LastRunUtc
        if ($null -ne $tmp) { $expected = $tmp.AddMinutes($iv) }
    }
    if ($null -eq $expected) { $result.reason = 'never-run'; return $result }   # no basis -> not overdue
    $grace = if ($GraceMinutes -gt 0) { $GraceMinutes } else { [Math]::Max(5, $iv) }
    $deadline = $expected.AddMinutes($grace)
    if ($now -gt $deadline) {
        $result.overdue = $true
        $result.expectedUtc = $expected.ToString('o')
        $result.overdueByMinutes = [int][Math]::Round(($now - $expected).TotalMinutes)
        $result.reason = "expected by $($expected.ToString('o')), now overdue by $($result.overdueByMinutes)m"
    } else {
        $result.expectedUtc = $expected.ToString('o')
        $result.reason = 'on-time'
    }
    return $result
}

# ---- acknowledge / clear (store-backed) -----------------------------------
# A bounded set of acknowledged runIds, persisted via the SAME store chain as the run
# history (SQL pim.Settings 'JobAcknowledgements', else the JSON sibling, else memory).
# Acknowledging a failed run mutes its signal (failure/overdue badges) WITHOUT deleting
# the run record, so the audit trail stays intact.
$script:PimAckRunIds = $null

function Get-PimAckPath {
    if ("$($global:PIM_SchedulerStatePath)".Trim()) {
        $dir = Split-Path -Parent $global:PIM_SchedulerStatePath
        if (-not $dir) { $dir = '.' }
        return (Join-Path $dir 'pim-scheduler-acks.json')
    }
    return $null
}
function Get-PimRunAcknowledgements {
    # Returns an array of acknowledged runIds (strings).
    $all = $null
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { $v = Get-PimSetting -Name 'JobAcknowledgements'; if ($v) { $tmp = $v | ConvertFrom-Json; $all = @($tmp) } } catch {}
    }
    if ($null -eq $all) {
        $p = Get-PimAckPath
        if ($p -and (Test-Path -LiteralPath $p)) { try { $tmp = (Get-Content -LiteralPath $p -Raw -Encoding UTF8) | ConvertFrom-Json; $all = @($tmp) } catch {} }
    }
    if ($null -eq $all) { $all = @($script:PimAckRunIds) }
    return @(@($all) | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
}
function Save-PimRunAcknowledgements {
    param([string[]]$RunIds = @())
    $clean = @(@($RunIds) | Where-Object { "$_".Trim() } | Select-Object -Unique | ForEach-Object { "$_" })
    $script:PimAckRunIds = $clean
    $json = (@($clean) | ConvertTo-Json -Depth 4)
    if ($null -eq $json) { $json = '[]' }
    # ConvertTo-Json on a single-element array yields a scalar; force an array literal.
    if ($clean.Count -eq 1) { $json = '["' + $clean[0] + '"]' }
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { try { Set-PimSetting -Name 'JobAcknowledgements' -Value $json | Out-Null; return } catch {} }
    $p = Get-PimAckPath
    if ($p) { try { Set-Content -LiteralPath $p -Value $json -Encoding UTF8 } catch {} }
}
function Set-PimRunAcknowledged {
    # Acknowledge ("clear") one run by runId, or un-acknowledge with -Clear. Acknowledging
    # an already-acked run is idempotent. Returns the resulting ack set + whether it changed.
    param([Parameter(Mandatory)][string]$RunId, [switch]$Clear)
    $rid = "$RunId".Trim()
    if (-not $rid) { return [pscustomobject]@{ ok = $false; error = 'runId is required' } }
    $cur = @(Get-PimRunAcknowledgements)
    $has = ($cur -contains $rid)
    $changed = $false
    if ($Clear) {
        if ($has) { $cur = @($cur | Where-Object { $_ -ne $rid }); $changed = $true }
    } else {
        if (-not $has) { $cur = @($cur + $rid); $changed = $true }
    }
    # Bound the ack set so it can't grow forever (keep the most recent 500).
    if ($cur.Count -gt 500) { $cur = @($cur | Select-Object -Last 500) }
    if ($changed) { Save-PimRunAcknowledgements -RunIds $cur }
    return [pscustomobject]@{ ok = $true; runId = $rid; acknowledged = (-not [bool]$Clear); changed = $changed; count = $cur.Count }
}
function Test-PimRunAcknowledged {
    param([Parameter(Mandatory)][string]$RunId)
    return (@(Get-PimRunAcknowledgements) -contains "$RunId".Trim())
}
function Get-PimJobFailureHistory {
    # Store-backed convenience over Get-PimRunFailureHistory: reads the run-history ring +
    # the ack store, returns the recent runs (newest-first) + the failed subset, with each
    # run flagged acknowledged. -Name filters to one job; -Take bounds the window.
    param([string]$Name, [int]$Take = 10)
    $runs = @(Get-PimJobRunHistory -Name $Name)
    $acks = @(Get-PimRunAcknowledgements)
    return (Get-PimRunFailureHistory -Runs $runs -Name $Name -Take $Take -AcknowledgedRunIds $acks)
}

function Get-PimJobsStatus {
    # Build the GUI view model: one row per configured job, joined to the latest run
    # from the run history + the persisted scheduler state (last/next run). In-progress
    # jobs (a 'running' record with no finishedUtc) sort to the TOP, then the rest by
    # most-recent activity. Pure read -- never runs a job. -NowUtc lets tests inject time.
    param([object[]]$Jobs, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $state = Get-PimSchedulerState
    if (-not $Jobs) {
        if ($state -and $state.jobs) { $Jobs = @($state.jobs) } else { $Jobs = Get-PimJobSchedule }
    }
    # The caller may pass the EFFECTIVE schedule (name/type/enabled/cadence only, no
    # last/next-run stamps -- e.g. the Manager's /api/jobs). Build a by-name lookup of the
    # PERSISTED scheduler state so we can fall back to its lastRunUtc/nextRunUtc stamps for
    # overdue/next-run -- otherwise an effective-schedule row would never look overdue.
    $stateByName = @{}
    if ($state -and $state.jobs) { foreach ($sj in @($state.jobs)) { if ("$($sj.name)".Trim()) { $stateByName["$($sj.name)"] = $sj } } }
    $history = @(Get-PimJobRunHistory)
    $acks = @(Get-PimRunAcknowledgements)        # [M6] muted runIds (failure/overdue signals cleared)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($j in @($Jobs)) {
        $name = "$($j.name)"
        $sj = $stateByName["$name"]              # persisted-state fallback for this job (may be $null)
        $runs = @($history | Where-Object { "$($_.name)" -eq $name })
        $last = $runs | Select-Object -First 1
        $inProg = @($runs | Where-Object { "$($_.status)" -eq 'running' -or -not "$($_.finishedUtc)".Trim() }) | Select-Object -First 1
        $en = $true; if ($j.PSObject.Properties['enabled']) { $en = [bool]$j.enabled }
        $iv = 0; if ($j.PSObject.Properties['intervalMinutes']) { $iv = [int]$j.intervalMinutes }
        $next = $null
        if ($j.PSObject.Properties['nextRunUtc'] -and "$($j.nextRunUtc)".Trim()) { $next = "$($j.nextRunUtc)" }
        elseif ($sj -and $sj.PSObject.Properties['nextRunUtc'] -and "$($sj.nextRunUtc)".Trim()) { $next = "$($sj.nextRunUtc)" }
        $lastRun = $null
        if ($last) { $lastRun = "$($last.startedUtc)" }
        elseif ($j.PSObject.Properties['lastRunUtc'] -and "$($j.lastRunUtc)".Trim()) { $lastRun = "$($j.lastRunUtc)" }
        elseif ($sj -and $sj.PSObject.Properties['lastRunUtc'] -and "$($sj.lastRunUtc)".Trim()) { $lastRun = "$($sj.lastRunUtc)" }
        $status = 'idle'
        if ($inProg) { $status = 'running' }
        elseif ($last) { $status = "$($last.status)" }
        # "Never run" = no run-history record AND no persisted lastRunUtc on the job.
        # This is the normal state on a fresh deployment (or before the scheduler has
        # ticked once) -- the row must NOT look dead. We synthesize a forward-looking
        # nextRunUtc (now + cadence) so the GUI can say "no runs yet -- next run <time>"
        # instead of an empty "-" for BOTH last and next run. The flag lets the GUI
        # render the explicit message; the synthesized time is clearly marked so it is
        # never mistaken for a scheduler-persisted next-run.
        $neverRun = (-not $last -and -not $lastRun)
        $nextSynth = $false
        if (-not "$next".Trim() -and $en -and $iv -gt 0) {
            $next = (Get-PimNextRunUtc -Job $j -FromUtc $now).ToString('o')
            $nextSynth = $true
        }
        # [M6] OVERDUE: did this job miss its scheduled fire window? Compute against the
        # PERSISTED next-run (job-carried or state-fallback) -- NOT the synthesized one,
        # so a never-run job is not "overdue", only "never fired".
        $persistNext = $null
        if ($j.PSObject.Properties['nextRunUtc'] -and "$($j.nextRunUtc)".Trim()) { $persistNext = "$($j.nextRunUtc)" }
        elseif ($sj -and $sj.PSObject.Properties['nextRunUtc'] -and "$($sj.nextRunUtc)".Trim()) { $persistNext = "$($sj.nextRunUtc)" }
        $od = Get-PimJobOverdueState -Job $j -NowUtc $now -LastRunUtc "$lastRun" -NextRunUtc "$persistNext" -InProgress ([bool]$inProg)
        # [M6] LAST-RUN ACK: is the latest FAILED run muted? + recent failure count.
        $lastRunId = $(if ($last) { "$($last.runId)" } else { '' })
        $lastAcked = ($lastRunId -and ($acks -contains $lastRunId))
        $finishedRuns = @($runs | Where-Object { "$($_.status)" -ne 'running' -and "$($_.finishedUtc)".Trim() })
        $recentWindow = @($finishedRuns | Sort-Object { "$($_.startedUtc)" } -Descending | Select-Object -First 10)
        $recentFails  = @($recentWindow | Where-Object { -not [bool]$_.ok })
        $unackedFails = @($recentFails | Where-Object { -not ($acks -contains "$($_.runId)") })
        $rows.Add([pscustomobject]@{
            name            = $name
            type            = "$($j.type)"
            scope           = $(if ($j.PSObject.Properties['scope']) { "$($j.scope)" } else { '' })
            intervalMinutes = $iv
            cadence         = (Format-PimCadence -IntervalMinutes $iv)
            enabled         = $en
            status          = $status
            inProgress      = [bool]$inProg
            neverRun        = [bool]$neverRun
            lastRunUtc      = $lastRun
            lastResult      = $(if ($last) { "$($last.detail)" } else { '' })
            lastOk          = $(if ($last) { [bool]$last.ok } else { $null })
            lastRan         = $(if ($last) { [bool]$last.ran } else { $null })
            lastDurationMs  = $(if ($last) { [int64]$last.durationMs } else { $null })   # [int64] -- see BUG-04
            lastRunId       = $lastRunId
            lastAcknowledged   = [bool]$lastAcked
            runningRunId    = $(if ($inProg) { "$($inProg.runId)" } else { '' })
            nextRunUtc      = $next
            nextRunSynthesized = [bool]$nextSynth
            overdue            = [bool]$od.overdue
            overdueByMinutes   = [int]$od.overdueByMinutes
            expectedRunUtc     = "$($od.expectedUtc)"
            recentFailureCount = $recentFails.Count
            unackedFailureCount = $unackedFails.Count
        })
    }
    # in-progress first, then by last activity (newest first), then name
    $sorted = @($rows | Sort-Object `
        @{ Expression = { if ($_.inProgress) { 0 } else { 1 } } }, `
        @{ Expression = { "$($_.lastRunUtc)" }; Descending = $true }, `
        @{ Expression = { $_.name } })
    return [pscustomobject]@{
        jobs       = @($sorted)
        generatedUtc = $now.ToString('o')
        runningCount = @($rows | Where-Object { $_.inProgress }).Count
        overdueCount = @($rows | Where-Object { $_.overdue }).Count
        failingCount = @($rows | Where-Object { $_.unackedFailureCount -gt 0 }).Count
        total        = $rows.Count
    }
}
function Format-PimCadence {
    param([int]$IntervalMinutes)
    $m = [int]$IntervalMinutes
    if ($m -le 0)       { return 'on-demand' }
    if ($m -lt 60)      { return "every $m min" }
    if ($m -eq 60)      { return 'hourly' }
    if ($m -lt 1440)    { $h = [Math]::Round($m / 60.0, 1); return "every $h h" }
    if ($m -eq 1440)    { return 'daily' }
    $d = [Math]::Round($m / 1440.0, 1); return "every $d d"
}
function ConvertTo-PimRunLogText {
    # Build a readable per-run log from a dispatch result object. Handlers may add a
    # 'log' (string or string[]); otherwise we synthesize from detail + sub-results.
    param([object]$Result, [object]$Job, [datetime]$StartedUtc)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(("[{0}] job '{1}' (type={2}{3})" -f $StartedUtc.ToString('o'), "$($Job.name)", "$($Job.type)", $(if ($Job.PSObject.Properties['scope'] -and "$($Job.scope)".Trim()) { " scope=$($Job.scope)" } else { '' })))
    if ($Result) {
        $lines.Add("result.ok      = $([bool]$Result.ok)")
        if ($Result.PSObject.Properties['detail']) { $lines.Add("detail         = $($Result.detail)") }
        $inner = if ($Result.PSObject.Properties['result']) { $Result.result } else { $null }
        if ($inner) {
            if ($inner.PSObject.Properties['ran'])    { $lines.Add("ran            = $([bool]$inner.ran)") }
            if ($inner.PSObject.Properties['whatIf']) { $lines.Add("whatIf         = $([bool]$inner.whatIf)") }
            if ($inner.PSObject.Properties['detail'] -and "$($inner.detail)" -ne "$($Result.detail)") { $lines.Add("handler.detail = $($inner.detail)") }
            if ($inner.PSObject.Properties['log'] -and $inner.log) { foreach ($l in @($inner.log)) { $lines.Add("$l") } }
        }
    }
    return ($lines -join "`n")
}
function Write-PimJobRunRecord {
    # Persist a finished run (called from the tick for every scheduled + trigger run).
    # 'ran' reflects whether the handler actually did work (vs a logged no-op stub);
    # 'status' is completed when the dispatch succeeded, failed otherwise.
    param([Parameter(Mandatory)][object]$Job, [Parameter(Mandatory)][object]$Result, [datetime]$StartedUtc = [datetime]::UtcNow, [switch]$Trigger, [string]$Reason = '')
    $fin = [datetime]::UtcNow
    $inner = if ($Result.PSObject.Properties['result']) { $Result.result } else { $null }
    $ran = $false; if ($inner -and $inner.PSObject.Properties['ran']) { $ran = [bool]$inner.ran }
    $rec = [pscustomobject]@{
        runId       = [guid]::NewGuid().ToString('N')
        name        = "$($Job.name)"
        type        = "$($Job.type)"
        scope       = $(if ($Job.PSObject.Properties['scope']) { "$($Job.scope)" } else { '' })
        ok          = [bool]$Result.ok
        ran         = $ran
        status      = $(if ($Result.ok) { 'completed' } else { 'failed' })
        detail      = "$($Result.detail)"
        trigger     = [bool]$Trigger
        reason      = "$Reason"
        startedUtc  = $StartedUtc.ToUniversalTime().ToString('o')
        finishedUtc = $fin.ToString('o')
        # [double]0 and [int64] are BOTH load-bearing (audit finding BUG-04).
        # `[Math]::Max(0, <double>)` binds to the Max(Int32,Int32) OVERLOAD -- the literal
        # 0 is an Int32, so PowerShell coerces TotalMilliseconds into an Int32 and THROWS
        # ("Value was either too large or too small for an Int32") once the duration
        # exceeds Int32.MaxValue ms = ~24.9 days. The outer [int] cast overflowed at the
        # same threshold. That killed the WHOLE run-record write, so a run was never
        # recorded at all -- losing Jobs-tab history exactly when something had gone wrong
        # (a stale 'running' placeholder or clock skew is enough to trigger it).
        # [double]0 selects Max(Double,Double); [int64] holds the result.
        durationMs  = [int64][Math]::Max([double]0, ($fin - $StartedUtc.ToUniversalTime()).TotalMilliseconds)
        log         = (ConvertTo-PimRunLogText -Result $Result -Job $Job -StartedUtc $StartedUtc.ToUniversalTime())
    }
    Add-PimJobRunRecord -Run $rec
    return $rec
}

function Invoke-PimJobForceStart {
    # FORCE-START ("Run now"): run ONE configured job immediately, off-cadence, and
    # record it in the SAME run-history ring the scheduler + the Manager's /api/jobs
    # read. Used by the GUI's per-row "Run now" button. Two records are written so the
    # GUI sees the job MOVE: first a 'running' placeholder (no finishedUtc -> sorts to
    # the TOP, live-tail-able), then -- after the handler returns -- the finished record
    # under the SAME runId (Add-PimJobRunRecord drops the prior placeholder by runId).
    # Resolves the job from the persisted schedule/state by name unless -Job is given.
    # Honors handlers registered in THIS process; an unregistered type records a clear
    # no-handler run rather than throwing (the gap stays visible, nothing crashes).
    param(
        [Parameter(Mandatory)][string]$Name,
        [object]$Job,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [switch]$WhatIf
    )
    $now = $NowUtc.ToUniversalTime()
    if (-not $Job) {
        $state = Get-PimSchedulerState
        $catalog = if ($state -and $state.jobs) { @($state.jobs) } else { @(Get-PimJobSchedule) }
        $Job = @($catalog | Where-Object { "$($_.name)" -eq "$Name" }) | Select-Object -First 1
    }
    if (-not $Job) { return [pscustomobject]@{ ok = $false; error = "no job named '$Name' in the schedule" } }
    if ($script:PimJobHandlers.Count -eq 0) { Initialize-PimDefaultJobHandlers }

    $runId = [guid]::NewGuid().ToString('N')
    $started = $now
    # (1) in-progress placeholder -> GUI shows it move to "running" at the top.
    $placeholder = [pscustomobject]@{
        runId       = $runId
        name        = "$($Job.name)"
        type        = "$($Job.type)"
        scope       = $(if ($Job.PSObject.Properties['scope']) { "$($Job.scope)" } else { '' })
        ok          = $true
        ran         = $true
        status      = 'running'
        detail      = 'force-start: running ...'
        trigger     = $true
        reason      = 'force-start'
        startedUtc  = $started.ToString('o')
        finishedUtc = ''
        durationMs  = 0
        log         = ("[{0}] job '{1}' FORCE-START requested{2}" -f $started.ToString('o'), "$($Job.name)", $(if ($Job.PSObject.Properties['scope'] -and "$($Job.scope)".Trim()) { " scope=$($Job.scope)" } else { '' }))
    }
    Add-PimJobRunRecord -Run $placeholder

    # (2) dispatch the real handler, then (3) replace the placeholder with the finished
    # record under the same runId.
    $res = Invoke-PimScheduledJob -Job $Job -NowUtc $now -WhatIf:$WhatIf
    $fin = [datetime]::UtcNow
    $inner = if ($res.PSObject.Properties['result']) { $res.result } else { $null }
    $ran = $false; if ($inner -and $inner.PSObject.Properties['ran']) { $ran = [bool]$inner.ran }
    $rec = [pscustomobject]@{
        runId       = $runId
        name        = "$($Job.name)"
        type        = "$($Job.type)"
        scope       = $(if ($Job.PSObject.Properties['scope']) { "$($Job.scope)" } else { '' })
        ok          = [bool]$res.ok
        ran         = $ran
        status      = $(if ($res.ok) { 'completed' } else { 'failed' })
        detail      = "$($res.detail)"
        trigger     = $true
        reason      = 'force-start'
        startedUtc  = $started.ToString('o')
        finishedUtc = $fin.ToString('o')
        # See Write-PimJobRunRecord: [double]0 picks the Max(Double,Double) overload and
        # [int64] holds a >24.9-day duration. Both are required (BUG-04).
        durationMs  = [int64][Math]::Max([double]0, ($fin - $started).TotalMilliseconds)
        log         = (ConvertTo-PimRunLogText -Result $res -Job $Job -StartedUtc $started)
    }
    Add-PimJobRunRecord -Run $rec
    return [pscustomobject]@{ ok = [bool]$res.ok; runId = $runId; name = "$($Job.name)"; type = "$($Job.type)"; status = $rec.status; detail = "$($res.detail)" }
}

# ---- on-demand triggers + change watermark --------------------------------
# Event-driven recompute on COMMIT (not on queue): when the user COMMITS, the manager
# enqueues a trigger and/or bumps a cheap WATERMARK; the runner drains triggers on its
# next (short) tick and recomputes immediately -- no waiting for the per-domain cadence.
# Queuing a change stages rows only and does NOT enqueue a trigger. Triggers persist in
# the shared settings store so the MANAGER and SCHEDULER processes see the same queue.
function Get-PimPendingTriggers {
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { $v = Get-PimSetting -Name 'SchedulerTriggers'; if ($v) { return @(@($v | ConvertFrom-Json) | Where-Object { $_ }) } } catch {}
    }
    if ($null -eq $script:PimTriggers) { return @() }
    return @(@($script:PimTriggers) | Where-Object { $_ })
}
function Save-PimJobTriggers {
    param([object[]]$Triggers = @())
    $script:PimTriggers = @($Triggers)
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { try { Set-PimSetting -Name 'SchedulerTriggers' -Value (@($Triggers) | ConvertTo-Json -Depth 6) | Out-Null } catch {} }
}
function Add-PimJobTrigger {
    # Enqueue an on-demand run. Call from the manager right after it writes a change,
    # or from a monitor that detects a SQL change. Deduped by type+scope.
    param([Parameter(Mandatory)][string]$Type, [string]$Scope = 'All', [string]$Reason = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $t = @(Get-PimPendingTriggers)
    if (-not ($t | Where-Object { "$($_.type)" -eq $Type -and "$($_.scope)" -eq $Scope })) {
        $t += [pscustomobject]@{ type = $Type; scope = $Scope; reason = $Reason; requestedUtc = $NowUtc.ToUniversalTime().ToString('o') }
        Save-PimJobTriggers -Triggers $t
    }
    return $t.Count
}
function Request-PimCommit {
    # Call this ONLY when the user COMMITS (not when they queue). Enqueues a recompute +
    # reconcile of the committed scope against the tenant. The monitor/watermark path
    # below does the same for changes committed out-of-band (e.g. another MSP node).
    param([string]$Scope = 'All', [string]$Reason = 'commit')
    Add-PimJobTrigger -Type 'engine-delta' -Scope $Scope -Reason $Reason | Out-Null
}
function Get-PimChangeWatermark {
    # Cheap "desired config changed" signal. The manager bumps 'DataWatermark' on every
    # write; the runner compares it each tick to catch out-of-band changes (e.g. another
    # MSP node) without scanning the whole DB.
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { try { $v = Get-PimSetting -Name 'DataWatermark'; if ($v) { return "$v" } } catch {} }
    return "$($global:PIM_DataWatermark)"
}
function Test-PimWatermarkChanged {
    param([string]$LastSeen, [string]$Current)
    return ("$Current".Trim() -ne '' -and "$Current" -ne "$LastSeen")
}

# ---- single-runner lease (so two instances don't double-run) --------------
function Test-PimSchedulerLeaseFree {
    # Pure: is the lease free for $Owner at $NowUtc? Free when no lease, expired, or ours.
    param([object]$Lease, [Parameter(Mandatory)][string]$Owner, [Parameter(Mandatory)][datetime]$NowUtc)
    if (-not $Lease -or -not "$($Lease.owner)".Trim()) { return $true }
    if ("$($Lease.owner)" -eq $Owner) { return $true }
    # BUG-02: a lease that is HELD but whose expiry cannot be UNDERSTOOD must be treated
    # as HELD, not free. The old code fell through to `return $true` when TryParse failed,
    # so a truncated / blank / locale-unparseable expiresUtc made EVERY instance believe
    # the lease was free -- two schedulers then run engine ticks against the same tenant,
    # the exact double-apply this lease exists to prevent. Fail CLOSED instead: the cost
    # of a wrongly-held lease is one skipped tick (the next tick retries); the cost of a
    # wrongly-free lease is a concurrent double-apply.
    # IMP-02: parse locale-safely. expiresUtc is always written with ToString('o'), so
    # InvariantCulture is the correct reading of it -- the bare TryParse used ambient
    # culture, which is why a da-DK host could fail to read a stamp it wrote itself.
    $exp = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    $raw = "$($Lease.expiresUtc)"
    if ([datetime]::TryParse($raw, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$exp)) {
        return ($NowUtc.ToUniversalTime() -ge $exp.ToUniversalTime())
    }
    # Last resort before failing closed: the project's own locale-safe parser, for a lease
    # written by an older build in some other format.
    if (Get-Command Ensure-DateTime -ErrorAction SilentlyContinue) {
        $alt = Ensure-DateTime $raw
        if ($alt -is [datetime]) { return ($NowUtc.ToUniversalTime() -ge $alt.ToUniversalTime()) }
    }
    Write-Warning ("scheduler lease held by '{0}' has an UNREADABLE expiry ('{1}') -- treating the lease as HELD (fail-closed). This instance skips the tick." -f "$($Lease.owner)", $raw)
    return $false
}

# ---- BUG-36: ACQUIRING the lease, not just checking it --------------------
# Test-PimSchedulerLeaseFree above has always been correct. What was missing is that NOTHING
# EVER WROTE A LEASE: the check read $st.lease, found nothing, and returned $true every time.
# The guard has never once refused a tick. That was invisible while exactly one always-on
# worker ran, and becomes a live double-apply the moment cron Jobs can overlap.
#
# The lease is its OWN setting key, deliberately NOT a field inside SchedulerState:
# Save-PimSchedulerState rewrites that whole blob, so a lease living inside it would be
# clobbered by any concurrent state write -- reintroducing the race at a different layer.
$script:PimLeaseSettingName = 'SchedulerLease'
$script:PimLeaseMemory      = $null      # in-memory fallback (single-process deployments)

# ---- BUG-54: WHO holds the lease is the whole safety property --------------
# Two runners are only kept apart if neither can mistake the other's lease for its own.
# The old owner default, "$($env:COMPUTERNAME)-$PID", is Windows-shaped and COLLAPSES in a
# Linux container: COMPUTERNAME is not set there and pwsh is normally pid 1, so every
# container tick took the lease under the literal owner '-1'. Test-PimSchedulerLeaseFree
# then answers "that lease is yours" to ALL of them, and the guard whose entire job is to
# make an overrun tick skip waves every one of them through.
# MEASURED consequence on `ca-pim-tick`: 12 concurrent executions in Running state, each
# renewing one lease under '-1', none completing, the job reporting healthy throughout --
# which is also why three sessions could not work out why the engine "never converged".
#
# So: resolve the owner from whatever the runtime DOES set, and never hold a lease under an
# owner whose host half is empty.
$script:PimSchedulerOwnerKeys = @(
    # Most specific to THIS execution first. In an ACA Job the two runners that must be told
    # apart are two OVERLAPPING EXECUTIONS, and the execution name is both unique per
    # execution and the identifier the operator sees in `az containerapp job execution list`
    # -- so a stuck lease names something they can go and look at.
    'CONTAINER_APP_JOB_EXECUTION_NAME'
    'CONTAINER_APP_REPLICA_NAME'
    'HOSTNAME'          # k8s/ACA always set this to the pod name; unique per replica
    'COMPUTERNAME'      # Windows
)
# Deliberately NOT in that list: CONTAINER_APP_NAME / CONTAINER_APP_JOB_NAME. They name the
# APP, not the instance, so every replica would share one owner -- the '-1' bug again with a
# friendlier spelling.

function Test-PimSchedulerOwnerUsable {
    <#
      PURE. Is this string safe to hold a lease under? Safe means IDENTIFYING: no second,
      unrelated runner may produce the same value. A leading '-' is the structural tell that
      the host half was empty -- '-1' is exactly what "<unset host>-<pid 1>" collapses to.
      That leading '-' is the ONLY structural rejection, because ACA replica names
      legitimately contain '--', so a "no empty segments" rule would refuse good owners.
    #>
    [CmdletBinding()]
    param([string]$Owner)
    $o = "$Owner".Trim()
    if (-not $o) { return $false }
    if ($o.StartsWith('-')) { return $false }
    return $true
}

function Get-PimSchedulerOwnerId {
    <#
      PURE. Build the owner id from an environment MAP + a pid, so the container case is
      testable on Windows -- the defect existed precisely because the real environment was
      only ever read on a machine where COMPUTERNAME happened to be set.
      Returns '' when nothing identifies the instance and no fallback was supplied; the
      caller decides what to do about that rather than a silent degenerate value being coined
      here.
    #>
    [CmdletBinding()]
    param([hashtable]$EnvMap, [int]$ProcessId = 0, [string]$MachineName = '', [string]$FallbackId = '')
    if (-not $EnvMap) { $EnvMap = @{} }
    $hostPart = ''
    foreach ($k in $script:PimSchedulerOwnerKeys) {
        $v = "$($EnvMap[$k])".Trim()
        if ($v) { $hostPart = $v; break }
    }
    if (-not $hostPart) { $hostPart = "$MachineName".Trim() }
    if (-not $hostPart) {
        # No host at all. A GUID is still CORRECT -- uniqueness is what the lease needs, and a
        # guid never collides -- it is only untraceable, so it is labelled as such rather than
        # passed off as a hostname.
        $fb = "$FallbackId".Trim()
        if (-not $fb) { return '' }
        return "unidentified-$fb"
    }
    if ($ProcessId -gt 0) { return "$hostPart-$ProcessId" }
    return $hostPart
}

function Resolve-PimSchedulerOwner {
    # The one impure step: read the real environment. An explicitly-supplied owner wins.
    [CmdletBinding()]
    param([string]$Owner = '')
    if ("$Owner".Trim()) { return "$Owner".Trim() }
    $map = @{}
    foreach ($k in $script:PimSchedulerOwnerKeys) {
        try { $map[$k] = [System.Environment]::GetEnvironmentVariable($k) } catch { }
    }
    $mn = ''; try { $mn = [System.Environment]::MachineName } catch { $mn = '' }
    $id = Get-PimSchedulerOwnerId -EnvMap $map -ProcessId $PID -MachineName $mn `
                                  -FallbackId ([guid]::NewGuid().ToString('N'))
    if ($id -like 'unidentified-*') {
        Write-Warning ("[scheduler] nothing in this runtime identifies the instance (none of " +
                       ($script:PimSchedulerOwnerKeys -join '/') + ", no machine name) -- holding the lease as " +
                       "'$id'. The lease stays UNIQUE and therefore correct, but a stuck lease cannot be traced " +
                       "back to a container.")
    }
    return $id
}

function New-PimSchedulerLease {
    # PURE. The lease document, given an owner, a clock and a TTL. No I/O.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Owner, [Parameter(Mandatory)][datetime]$NowUtc, [int]$TtlMinutes = 15)
    if ($TtlMinutes -lt 1) { $TtlMinutes = 1 }
    [pscustomobject]@{
        owner      = $Owner
        acquiredUtc= $NowUtc.ToUniversalTime().ToString('o')
        expiresUtc = $NowUtc.ToUniversalTime().AddMinutes($TtlMinutes).ToString('o')
    }
}

function Test-PimSchedulerLeaseRenewDue {
    <#
      PURE. Should the holder renew yet? True once we are past HALF the TTL, so a long job
      refreshes well before expiry but we are not writing to the store every few seconds.
      A lease we cannot parse is treated as due -- renewing early is harmless; letting an
      unreadable lease silently lapse while we are still working is not.
    #>
    [CmdletBinding()]
    param([object]$Lease, [Parameter(Mandatory)][datetime]$NowUtc, [int]$TtlMinutes = 15)
    if (-not $Lease -or -not "$($Lease.expiresUtc)".Trim()) { return $true }
    # IMP-02, same styles as Test-PimSchedulerLeaseFree: InvariantCulture because expiresUtc is
    # always written with ToString('o'). NOTE RoundtripKind is NOT usable here -- .NET rejects it
    # combined with AdjustToUniversal/AssumeUniversal, which throws rather than returning false.
    $exp = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if (-not [datetime]::TryParse("$($Lease.expiresUtc)", [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$exp)) { return $true }
    return ($NowUtc.ToUniversalTime() -ge $exp.ToUniversalTime().AddMinutes(-([math]::Max(1, $TtlMinutes / 2))))
}

function Get-PimSchedulerLeaseStoreCs {
    # The SQL connection string, when there IS one. Only the SQL path is truly atomic.
    if ("$($global:PIM_SqlConnectionString)".Trim()) { return "$($global:PIM_SqlConnectionString)" }
    if ((Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) -and
        ("$($global:PIM_SqlServer)".Trim() -or "$($global:PIM_SqlConnStringVault)".Trim())) {
        try { return (Get-PimSqlConnectionString) } catch { return $null }
    }
    return $null
}

function Get-PimSchedulerLeaseRaw {
    # Returns @{ Raw = <exact stored json or $null>; Lease = <parsed or $null> }. Raw is what a
    # compare-and-set must compare against -- re-serialising would change the bytes.
    $cs = Get-PimSchedulerLeaseStoreCs
    if ($cs -and (Get-Command Get-PimSqlSettingRaw -ErrorAction SilentlyContinue)) {
        try {
            $raw = Get-PimSqlSettingRaw -ConnectionString $cs -Name $script:PimLeaseSettingName
            $obj = $null; if ("$raw".Trim()) { try { $obj = $raw | ConvertFrom-Json } catch { $obj = $null } }
            return @{ Raw = $raw; Lease = $obj; Backend = 'sql'; Cs = $cs }
        } catch { }
    }
    $raw = $script:PimLeaseMemory
    $obj = $null; if ("$raw".Trim()) { try { $obj = $raw | ConvertFrom-Json } catch { $obj = $null } }
    return @{ Raw = $raw; Lease = $obj; Backend = 'memory'; Cs = $null }
}

function Request-PimSchedulerLease {
    <#
      Try to take the lease. Returns $true only if THIS process now holds it.
      SQL: a real compare-and-set -- read the exact stored value, decide with the pure
      Test-PimSchedulerLeaseFree, then write ONLY IF the stored value has not changed since.
      Losing the race returns $false, which is the correct outcome, not an error.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Owner, [datetime]$NowUtc = [datetime]::UtcNow, [int]$TtlMinutes = 15)
    # BUG-54: refuse the lease outright rather than take it under an owner that identifies
    # nobody. This is the defence-in-depth half -- Resolve-PimSchedulerOwner should never coin
    # such a value, but ANY caller may pass -Owner, and a caller that computes it the old way
    # ("$env:COMPUTERNAME-$PID") would otherwise re-create the exact 12-stacked-runners defect
    # here. Refusing costs one skipped tick; accepting costs a lease that cannot arbitrate.
    if (-not (Test-PimSchedulerOwnerUsable -Owner $Owner)) {
        Write-Warning (("[scheduler] REFUSING to take the lease under the non-identifying owner '{0}' (BUG-54). " -f $Owner) +
                       "An owner with an empty host half is shared by every instance, so the lease could not tell " +
                       "one runner from another. Pass -Owner explicitly, or let Resolve-PimSchedulerOwner derive it.")
        return $false
    }
    $cur = Get-PimSchedulerLeaseRaw
    if (-not (Test-PimSchedulerLeaseFree -Lease $cur.Lease -Owner $Owner -NowUtc $NowUtc)) { return $false }
    $new  = New-PimSchedulerLease -Owner $Owner -NowUtc $NowUtc -TtlMinutes $TtlMinutes
    $json = $new | ConvertTo-Json -Depth 4 -Compress
    if ($cur.Backend -eq 'sql') {
        try {
            $n = Set-PimSqlSettingIfUnchanged -ConnectionString $cur.Cs -Name $script:PimLeaseSettingName `
                    -NewValueJson $json -ExpectedValueJson $cur.Raw
            if ($n -ge 1) { $script:PimLeaseHeld = $json; return $true }
            # BUG-41: losing the CAS when we had just read the lease as FREE is not a normal
            # race -- it means the write did not land for some other reason (a store that
            # cannot be written, or a CAS that cannot express "expected absent"). Say so.
            # Reporting every $false as contention is what hid a lease that could never be
            # acquired at all: "another runner holds it" is the one explanation a reader
            # cannot disprove without inspecting the store by hand.
            if (-not "$($cur.Raw)".Trim()) {
                Write-Warning ("[scheduler] lease NOT acquired although the store shows no lease -- the compare-and-set " +
                               "wrote 0 rows. This is NOT contention; the store rejected or ignored the write.")
            }
            return $false
        } catch {
            # fail CLOSED: could not prove we own it, so we do not run -- but never silently.
            Write-Warning "[scheduler] lease acquire FAILED against the SQL store (not contention): $($_.Exception.Message)"
            return $false
        }
    }
    # No SQL store: single-process deployment (VM / local). Best effort, and NOT atomic --
    # said plainly rather than implied, because a file/in-memory "lease" cannot arbitrate
    # between machines. Multi-runner safety requires the SQL store.
    $script:PimLeaseMemory = $json; $script:PimLeaseHeld = $json
    return $true
}

function Update-PimSchedulerLease {
    # Extend OUR lease. CAS from the exact value we wrote, so a lease stolen after expiry is
    # not silently taken back mid-run.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Owner, [datetime]$NowUtc = [datetime]::UtcNow, [int]$TtlMinutes = 15)
    $cur = Get-PimSchedulerLeaseRaw
    if (-not $cur.Lease -or "$($cur.Lease.owner)" -ne $Owner) { return $false }
    $new  = New-PimSchedulerLease -Owner $Owner -NowUtc $NowUtc -TtlMinutes $TtlMinutes
    $json = $new | ConvertTo-Json -Depth 4 -Compress
    if ($cur.Backend -eq 'sql') {
        try {
            $n = Set-PimSqlSettingIfUnchanged -ConnectionString $cur.Cs -Name $script:PimLeaseSettingName `
                    -NewValueJson $json -ExpectedValueJson $cur.Raw
            if ($n -ge 1) { $script:PimLeaseHeld = $json; return $true }
            return $false
        } catch { return $false }
    }
    $script:PimLeaseMemory = $json; $script:PimLeaseHeld = $json
    return $true
}

function Remove-PimSchedulerLease {
    # Release, so the NEXT run starts immediately instead of waiting out the TTL. Only ever
    # releases a lease we still own -- never clears someone else's.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Owner)
    $cur = Get-PimSchedulerLeaseRaw
    if (-not $cur.Lease -or "$($cur.Lease.owner)" -ne $Owner) { return $false }
    if ($cur.Backend -eq 'sql') {
        try {
            $n = Set-PimSqlSettingIfUnchanged -ConnectionString $cur.Cs -Name $script:PimLeaseSettingName `
                    -NewValueJson $null -ExpectedValueJson $cur.Raw
            $script:PimLeaseHeld = $null
            return ($n -ge 1)
        } catch { return $false }
    }
    $script:PimLeaseMemory = $null; $script:PimLeaseHeld = $null
    return $true
}

# ---- one tick + the loop --------------------------------------------------
function Invoke-PimSchedulerTick {
    # Run every due job once; advance each job's nextRunUtc; persist. Returns results.
    #
    # BUG-36: the lease is taken HERE, around the TICK, not around the loop in
    # Start-PimScheduler. The tick is the unit of work that must not run twice, and it is what
    # an external cron invokes via `-Once` -- so protecting the loop alone would leave every
    # cron-driven deployment (framework ESTATE-06) completely unguarded. Held for the duration
    # and released in `finally`, so the next run starts immediately rather than waiting out the
    # TTL. -NoLease is for offline tests that drive the tick directly.
    param([object[]]$Jobs, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf,
          [string]$Owner, [int]$LeaseTtlMinutes = 15, [switch]$NoLease)
    $now = $NowUtc.ToUniversalTime()
    # BUG-54: was "$($env:COMPUTERNAME)-$PID", which is '-1' in every Linux container.
    if (-not "$Owner".Trim()) { $Owner = Resolve-PimSchedulerOwner }
    $haveLease = $false
    if (-not $NoLease) {
        # BUG-54: say WHICH of the two failures happened. A refused owner and a lost race are
        # different faults with different fixes, and reporting the second for the first is the
        # mistake BUG-41 already cost a session over.
        if (-not (Test-PimSchedulerOwnerUsable -Owner $Owner)) {
            Write-Host "[scheduler] owner '$Owner' identifies no instance -- skipping tick rather than holding a lease nobody can own (BUG-54)" -ForegroundColor Red
            return @([pscustomobject]@{ name = 'lease'; type = 'lease'; ok = $false; ran = $false
                                        detail = "skipped: owner '$Owner' is not identifying -- an empty host half is shared by every instance" })
        }
        $haveLease = Request-PimSchedulerLease -Owner $Owner -NowUtc $now -TtlMinutes $LeaseTtlMinutes
        if (-not $haveLease) {
            # BUG-41: do not ASSERT contention -- report what was actually observed. The lease
            # is only "held by another runner" if the store shows a live lease; otherwise the
            # acquire failed for a different reason, which Request-PimSchedulerLease has just
            # warned about in detail. Stating the wrong cause here cost a whole session.
            $seen = $null; try { $seen = (Get-PimSchedulerLeaseRaw).Lease } catch { }
            if ($seen) {
                Write-Host "[scheduler] another runner holds the lease (owner '$($seen.owner)'); skipping tick" -ForegroundColor DarkYellow
                if (-not (Test-PimSchedulerOwnerUsable -Owner "$($seen.owner)")) {
                    # Named on sight so nobody re-debugs it: a lease owned by '-1' was written by a
                    # PRE-BUG-54 build. Nothing can release it (no runner answers to that name), so it
                    # clears when the TTL expires and normal ticks resume by themselves.
                    Write-Host "[scheduler]   ^ that owner is non-identifying -- a leftover from a pre-BUG-54 build. It expires at its TTL; no action needed." -ForegroundColor DarkYellow
                }
                return @([pscustomobject]@{ name = 'lease'; type = 'lease'; ok = $true; ran = $false
                                            detail = "skipped: lease held by '$($seen.owner)'" })
            }
            Write-Host "[scheduler] lease NOT acquired and the store shows NO lease -- skipping tick (this is a store/write fault, not contention)" -ForegroundColor Red
            return @([pscustomobject]@{ name = 'lease'; type = 'lease'; ok = $false; ran = $false
                                        detail = 'skipped: lease could not be acquired and no lease is held -- the store did not accept the write' })
        }
    }
    try {
    # Hydrate JobSchedule + EmailControls from pim.Settings ONCE so even a one-shot
    # (-Once) cold tick honours the GUI-persisted cadence + email controls, not the
    # in-process default. Fail-safe / no-op when no store is configured.
    [void](Import-PimSchedulerSettingsFromStore)
    if (-not $Jobs) {
        $st = Get-PimSchedulerState
        if ($st -and $st.jobs) { $Jobs = @($st.jobs) } else { $Jobs = Get-PimJobSchedule }
    }
    $results = New-Object System.Collections.Generic.List[object]
    $st = Get-PimSchedulerState
    $lastWm = if ($st -and $st.PSObject.Properties['lastWatermark']) { "$($st.lastWatermark)" } else { '' }

    # (a) WATERMARK: desired config changed out-of-band -> enqueue an immediate recompute.
    $wm = Get-PimChangeWatermark
    if (Test-PimWatermarkChanged -LastSeen $lastWm -Current $wm) {
        Add-PimJobTrigger -Type 'engine-delta' -Scope 'All' -Reason 'watermark' -NowUtc $now | Out-Null
        $lastWm = $wm
    }

    # (a-sql) ON-DEMAND RECALC ON SQL CHANGE: read the live SQL data signature and
    # enqueue an engine-delta when it changed since we last acted. Catches OUT-OF-BAND
    # SQL writes (another MSP node, a direct SQL edit, the cutover import) that never
    # bumped the in-process watermark above. No-op unless a SQL store is configured.
    if (Get-Command Invoke-PimSqlChangeDetector -ErrorAction SilentlyContinue) {
        $sqlCs = $null
        if ("$($global:PIM_SqlConnectionString)".Trim()) { $sqlCs = "$($global:PIM_SqlConnectionString)" }
        elseif ((Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) -and ("$($global:PIM_SqlServer)".Trim() -or "$($global:PIM_SqlConnStringVault)".Trim())) {
            try { $sqlCs = Get-PimSqlConnectionString } catch { $sqlCs = $null }
        }
        if ($sqlCs) { try { [void](Invoke-PimSqlChangeDetector -ConnectionString $sqlCs -Scope 'All' -Reason 'sql-change') } catch { } }
    }

    # (b) TRIGGERS: run on-demand requests NOW (event-driven), then clear them.
    $triggers = @(Get-PimPendingTriggers)
    if ($triggers.Count) {
        foreach ($tg in $triggers) {
            $tjob = [pscustomobject]@{ name = "trigger:$($tg.type):$($tg.scope)"; type = "$($tg.type)"; scope = "$($tg.scope)"; enabled = $true }
            $started = [datetime]::UtcNow
            $r = Invoke-PimScheduledJob -Job $tjob -NowUtc $now -WhatIf:$WhatIf
            $r | Add-Member -NotePropertyName trigger -NotePropertyValue $true -Force
            $r | Add-Member -NotePropertyName reason  -NotePropertyValue "$($tg.reason)" -Force
            $results.Add($r)
            Write-PimJobRunRecord -Job $tjob -Result $r -StartedUtc $started -Trigger -Reason "$($tg.reason)" | Out-Null
        }
        Save-PimJobTriggers -Triggers @()
    }

    # (c) SCHEDULED: run due jobs on their cadence; advance next-run.
    foreach ($j in @($Jobs)) {
        if (Test-PimJobDue -Job $j -NowUtc $now) {
            $started = [datetime]::UtcNow
            $res = Invoke-PimScheduledJob -Job $j -NowUtc $now -WhatIf:$WhatIf
            $results.Add($res)
            Write-PimJobRunRecord -Job $j -Result $res -StartedUtc $started | Out-Null
            $nr = (Get-PimNextRunUtc -Job $j -FromUtc $now).ToString('o')
            if ($j.PSObject.Properties['nextRunUtc']) { $j.nextRunUtc = $nr } else { $j | Add-Member -NotePropertyName nextRunUtc -NotePropertyValue $nr -Force }
            if ($j.PSObject.Properties['lastRunUtc']) { $j.lastRunUtc = $now.ToString('o') } else { $j | Add-Member -NotePropertyName lastRunUtc -NotePropertyValue $now.ToString('o') -Force }
            # Renew mid-tick: a scheduled run can outlive the TTL (a full reconcile is not
            # quick), and a lapsed lease would let a second runner start while this one is
            # still writing. Renewal is half-TTL-gated, so this is not a per-job store write.
            if ($haveLease -and (Test-PimSchedulerLeaseRenewDue -Lease (Get-PimSchedulerLeaseRaw).Lease -NowUtc ([datetime]::UtcNow) -TtlMinutes $LeaseTtlMinutes)) {
                [void](Update-PimSchedulerLease -Owner $Owner -NowUtc ([datetime]::UtcNow) -TtlMinutes $LeaseTtlMinutes)
            }
        }
    }
    Save-PimSchedulerState -State ([pscustomobject]@{ jobs = @($Jobs); lastWatermark = $lastWm; updatedUtc = $now.ToString('o') })
    return $results.ToArray()
    }
    finally {
        # Release even when a job threw. A crash that leaves the lease held would block every
        # later run until the TTL expires -- for a cron deployment that is silent downtime.
        if ($haveLease) { [void](Remove-PimSchedulerLease -Owner $Owner) }
    }
}

function Start-PimScheduler {
    # The container's job loop. Ticks every IntervalSeconds. MaxTicks>0 bounds it
    # (tests/one-shot); 0 = forever. Honors a single-runner lease.
    param([int]$IntervalSeconds = 300, [int]$MaxTicks = 0, [string]$Owner = '',
          [int]$LeaseTtlMinutes = 15, [switch]$WhatIf)
    # BUG-54: the default used to be a bare GUID. Unique, so never WRONG -- but it named
    # nothing, so a lease held by a long-running loop could not be attributed to a replica.
    # Resolve-PimSchedulerOwner yields <replica-or-host>-<pid> and only falls back to a guid
    # when the runtime genuinely identifies nothing.
    $Owner = Resolve-PimSchedulerOwner -Owner $Owner
    if ($script:PimJobHandlers.Count -eq 0) { Initialize-PimDefaultJobHandlers }
    # Hydrate the persisted JobSchedule + EmailControls from pim.Settings at BOOT so a
    # freshly-started scheduler honours the GUI-saved cadence + a GUI-set email kill
    # switch from the first tick (the GUI-state == actual-behavior fix). Fail-safe.
    [void](Import-PimSchedulerSettingsFromStore)
    Write-Host "[scheduler] starting (interval ${IntervalSeconds}s, owner $Owner)" -ForegroundColor Cyan
    $tick = 0
    while ($true) {
        $now = [datetime]::UtcNow
        # BUG-36: the lease is acquired INSIDE the tick now, so this loop no longer does its own
        # check. The old check here read $st.lease from SchedulerState -- a field nothing ever
        # wrote -- so it found no lease and permitted every tick, unconditionally. Deleting it
        # rather than leaving it alongside the real one matters: two half-guards read as
        # defence-in-depth while neither actually arbitrates.
        $res = @(Invoke-PimSchedulerTick -NowUtc $now -WhatIf:$WhatIf -Owner $Owner -LeaseTtlMinutes $LeaseTtlMinutes)
        foreach ($r in $res) { Write-Host ("[scheduler] {0,-16} {1}" -f $r.name, $r.detail) -ForegroundColor DarkGray }
        $tick++
        if ($MaxTicks -gt 0 -and $tick -ge $MaxTicks) { break }
        Start-Sleep -Seconds $IntervalSeconds
    }
}
