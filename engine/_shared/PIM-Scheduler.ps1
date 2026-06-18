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
        $tmp = [datetime]::MinValue
        if ([datetime]::TryParse("$($Job.nextRunUtc)", [ref]$tmp)) { $next = $tmp.ToUniversalTime() }
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
            durationMs   = $(if ($r.PSObject.Properties['durationMs']) { [int]$r.durationMs } else { 0 })
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
    $tmp = [datetime]::MinValue
    if ("$NextRunUtc".Trim() -and [datetime]::TryParse("$NextRunUtc", [ref]$tmp)) {
        $expected = $tmp.ToUniversalTime()
    } elseif ("$LastRunUtc".Trim() -and [datetime]::TryParse("$LastRunUtc", [ref]$tmp)) {
        $expected = $tmp.ToUniversalTime().AddMinutes($iv)
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
            lastDurationMs  = $(if ($last) { [int]$last.durationMs } else { $null })
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
        durationMs  = [int]([Math]::Max(0, ($fin - $StartedUtc.ToUniversalTime()).TotalMilliseconds))
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
        durationMs  = [int]([Math]::Max(0, ($fin - $started).TotalMilliseconds))
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
    $exp = [datetime]::MinValue
    if ([datetime]::TryParse("$($Lease.expiresUtc)", [ref]$exp)) { return ($NowUtc.ToUniversalTime() -ge $exp.ToUniversalTime()) }
    return $true
}

# ---- one tick + the loop --------------------------------------------------
function Invoke-PimSchedulerTick {
    # Run every due job once; advance each job's nextRunUtc; persist. Returns results.
    param([object[]]$Jobs, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $now = $NowUtc.ToUniversalTime()
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
        }
    }
    Save-PimSchedulerState -State ([pscustomobject]@{ jobs = @($Jobs); lastWatermark = $lastWm; updatedUtc = $now.ToString('o') })
    return $results.ToArray()
}

function Start-PimScheduler {
    # The container's job loop. Ticks every IntervalSeconds. MaxTicks>0 bounds it
    # (tests/one-shot); 0 = forever. Honors a single-runner lease.
    param([int]$IntervalSeconds = 300, [int]$MaxTicks = 0, [string]$Owner = "$([guid]::NewGuid())", [switch]$WhatIf)
    if ($script:PimJobHandlers.Count -eq 0) { Initialize-PimDefaultJobHandlers }
    Write-Host "[scheduler] starting (interval ${IntervalSeconds}s, owner $Owner)" -ForegroundColor Cyan
    $tick = 0
    while ($true) {
        $now = [datetime]::UtcNow
        $st = Get-PimSchedulerState
        $lease = if ($st) { $st.lease } else { $null }
        if (Test-PimSchedulerLeaseFree -Lease $lease -Owner $Owner -NowUtc $now) {
            $res = @(Invoke-PimSchedulerTick -NowUtc $now -WhatIf:$WhatIf)
            foreach ($r in $res) { Write-Host ("[scheduler] {0,-16} {1}" -f $r.name, $r.detail) -ForegroundColor DarkGray }
        } else {
            Write-Host "[scheduler] another runner holds the lease; skipping tick" -ForegroundColor DarkYellow
        }
        $tick++
        if ($MaxTicks -gt 0 -and $tick -ge $MaxTicks) { break }
        Start-Sleep -Seconds $IntervalSeconds
    }
}
