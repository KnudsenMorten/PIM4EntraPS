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
$script:PimJobTypes    = @('queue-apply','engine-delta','engine-full','msp-pull','reminders','escalations','discovery','scheduled-creation','daily-summary','tier-report','servicenow-intake','tenant-cache','verify-convergence','hybrid-ad-apply','active-assignments-snapshot','drift-snapshot')
# 🔒 TICK-ONLY job types: their REAL handler is registered only by tools/pim-scheduler/Start-PimScheduler.ps1 (the
# Manager initialises the same defaults, which are placeholders). "Run now" in the Manager QUEUES these for the tick
# instead of running a placeholder in the web process. Operator, 2026-09-14, on verify-convergence: Run now recorded
# "not implemented" and the job went red. A type added to Start-PimScheduler's registrations belongs here too --
# tests/Test-PimJobsRunLogs.ps1 derives that set from the script and fails when this list falls behind.
$script:PimTickOnlyJobTypes = @('engine-delta','engine-full','msp-pull','active-assignments-snapshot','drift-snapshot','verify-convergence','discovery')
function Get-PimTickOnlyJobTypes { @($script:PimTickOnlyJobTypes) }
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
        # BUG-137: 'AdminAccounts' = Admins + AdminMembers. AdminMembers (which admins hold which
        # PIM group) was reached by NOTHING but the daily full-reconcile, so an admin assignment
        # saved in the Manager could sit unapplied for up to 24h -- the same "I saved it and
        # nothing happened" symptom as the delegation bug, with a ceiling instead of forever.
        [pscustomobject]@{ name='delta-admins';       type='engine-delta'; scope='AdminAccounts';           intervalMinutes=5 ;   enabled=$true  }
        # AdminTap is its OWN provider (order 35), NOT part of the Admins scope -- so without a job
        # here nothing ever ran it except the daily `full-reconcile` (scope All). Measured in EFIF:
        # four accounts created at 18:22 with CreateTAP=TRUE all had TAP=none, and would have kept
        # it until 06:05 the next morning. No error anywhere -- the TAP, and therefore the
        # tap-delivery mail, just silently did not happen for ~12 hours. Paired with delta-admins'
        # cadence so a newly-created admin gets its TAP on the next pass, not the next day.
        [pscustomobject]@{ name='delta-admin-tap';    type='engine-delta'; scope='AdminTap';                intervalMinutes=10;   enabled=$true  }
        # 🔴 BUG-134 -- THESE TWO CARRIED v1 CSV-ENGINE SCOPE NAMES THE REST ENGINE NEVER REGISTERED.
        # 'GroupsAssignment' and 'GroupsCreateModifyPolicy' resolved to NO PROVIDER, so both jobs
        # were permanent no-ops that reported SUCCESS on every tick. delta-groups-assign is the job
        # that nests a PIM-ROLE group into its permission groups -- i.e. EVERY DELEGATION authored
        # in the Manager was committed to pim.Rows, shown correctly on the Access map, and never
        # applied to Entra until the daily full-reconcile (scope All) happened to sweep it up.
        # Measured on the internal environment 2026-09-12; see Get-PimEngineScopeAliasMap.
        # 🪤 Correcting this default alone repairs only deployments that have never persisted a
        # JobSchedule. Every environment whose cadences were touched in the GUI keeps its own copy
        # of the broken names -- which is why the real repair is the resolve-time alias map, and
        # this change is just making the shipped default honest.
        # 'GroupsAssignment' was a pure misnomer -> the provider is 'GroupMembers', named here now.
        # 'GroupsCreateModifyPolicy' / 'Workloads' stay: they are genuine SCOPE GROUPS (one job,
        # several providers -- group+owners+AU-membership; Defender+Intune+app-role) and the alias
        # map is what expands them. Both are asserted by the release gate, so neither can rot.
        [pscustomobject]@{ name='delta-groups-assign';type='engine-delta'; scope='GroupMembers';            intervalMinutes=5 ;   enabled=$true  }
        [pscustomobject]@{ name='delta-groups-deploy';type='engine-delta'; scope='GroupsCreateModifyPolicy';intervalMinutes=10;   enabled=$true  }
        # BUG-137: both widened to scope GROUPS so the providers that only the daily reconcile
        # reached now run on the job that already covers their domain -- 'PimPolicies' adds
        # EntraRolePolicies (policy on an Entra role), 'EntraRoleAssignments' adds RolesAUs
        # (role scoped to an AU) and EntraRolesDirect (v1-style direct assignment).
        [pscustomobject]@{ name='delta-policies';     type='engine-delta'; scope='PimPolicies';             intervalMinutes=30;   enabled=$true  }
        [pscustomobject]@{ name='delta-pim-entra';    type='engine-delta'; scope='EntraRoleAssignments';    intervalMinutes=10;   enabled=$true  }
        [pscustomobject]@{ name='delta-pim-azure';    type='engine-delta'; scope='AzRes';                   intervalMinutes=15;   enabled=$true  }
        # Azure resource role POLICIES (ARM roleManagementPolicies), verified against the current policy
        # template and PATCHed where they differ. Operator, 2026-09-12: "azure policies must be on like
        # entra and pim for groups". So it copies delta-policies above: same type, same 30-minute cadence,
        # enabled, no feature gate (GroupsPolicies/EntraRolePolicies carry no `feature` key). It is its own
        # row because the 'PimPolicies' scope group lives in PIM-EngineCore.ps1.
        [pscustomobject]@{ name='delta-pim-azure-policies'; type='engine-delta'; scope='AzResPolicies';       intervalMinutes=30;   enabled=$true  }
        [pscustomobject]@{ name='delta-pim-au';       type='engine-delta'; scope='AdministrativeUnits';     intervalMinutes=15;   enabled=$true  }
        # 'Workloads' = DefenderXdrRoles + IntuneRoles + EntraAppRole + WorkloadConnectors (the v1 dispatcher
        # over PIM-Assignments-Workloads). Gated by connectors.workload, which is on whenever those rows exist.
        [pscustomobject]@{ name='delta-workloads';    type='engine-delta'; scope='Workloads';               intervalMinutes=30;   enabled=$true  }
        [pscustomobject]@{ name='escalations';        type='escalations';     intervalMinutes=60;   enabled=$true  }
        [pscustomobject]@{ name='discovery-entra';    type='discovery'; scope='Entra';   intervalMinutes=1440; enabled=$true  }
        [pscustomobject]@{ name='discovery-azure';    type='discovery'; scope='Azure';   intervalMinutes=1440; enabled=$true  }
        [pscustomobject]@{ name='discovery-powerbi';  type='discovery'; scope='PowerBI'; intervalMinutes=1440; enabled=$true  }
        [pscustomobject]@{ name='reminders';          type='reminders';       intervalMinutes=720;  enabled=$true  }
        # §13 / #8 (2026-09-12): REPORT ONLY -- which admin rows wait for their ProvisionDate and which
        # TAPs wait for their lead window, read from SQL. Creation itself is delta-admins (Admins
        # holds a row back until due) and delta-admin-tap; this job used to read a global nothing set.
        [pscustomobject]@{ name='scheduled-creation'; type='scheduled-creation'; intervalMinutes=30; enabled=$true  }
        # #12 (2026-09-12, v1 parity): OFFBOARDING on its own cadence, without a global -Prune. The
        # provider is per admin and gated inside (automatic offboarding opt-in, removal budget, the
        # account-disable circuit breaker, break-glass), so the job itself is safe to leave enabled:
        # in a protected tenant with the opt-in unset it processes nothing and says so.
        [pscustomobject]@{ name='admin-offboarding';  type='engine-delta'; scope='AdminOffboarding';        intervalMinutes=30;   enabled=$true  }
        # #12: on-premises AD accounts (TargetPlatform=AD). Applies only on a HYBRID WORKER -- a host
        # with the ActiveDirectory module and an AD credential (v1's condition); everywhere else it
        # reports that a hybrid worker is required, instead of planning in silence.
        [pscustomobject]@{ name='hybrid-ad-apply';    type='hybrid-ad-apply';  intervalMinutes=60; enabled=$true  }
        # 🔴 OFF BY DEFAULT (operator, 2026-09-10: "it must be disabled by default").
        # This job can ONLY ever no-op until $global:PIM_IntakeStoreFile names a drop store, which
        # is a deliberate integration nobody gets by accident. Shipped enabled, it put a permanent
        # row in every customer's Jobs list for an integration they do not have -- the same
        # complaint that produced BUG-92 ("i see references to failed jobs including servicenow, i
        # dont have any servicenow"). BUG-92 fixed how it was REPORTED (out-of-scope is not a
        # failure); it left the job switched on, so the row never went away.
        # 🔑 A default that can only ever do nothing should be off: a deployment that configures
        # the drop store turns it on, and every other deployment stops carrying it.
        [pscustomobject]@{ name='servicenow-intake';  type='servicenow-intake'; intervalMinutes=10;   enabled=$false }  # poll the store-and-forward drop store (enable when PIM_IntakeStoreFile is configured)
        [pscustomobject]@{ name='daily-summary';      type='daily-summary';   intervalMinutes=1440; enabled=$true  }
        [pscustomobject]@{ name='tier-report';        type='tier-report';     intervalMinutes=1440; enabled=$true  }
        # Tenant-list cache refresh: pull entra-roles / AUs / PIM-* groups / Azure
        # scopes + RBAC roles into the per-instance cache so role-name validation,
        # the autocomplete pickers, and the role-permission drill-down stay fresh
        # WITHOUT relying on a Manager restart. 12h cadence keeps it inside the
        # 24h freshness window the GUI badge + validator use. The Manager process
        # is read-only on this cache; the SCHEDULER owns the refresh.
        [pscustomobject]@{ name='tenant-cache';       type='tenant-cache';    intervalMinutes=720;  enabled=$true  }
        # §70.1b option 2 (2026-09-13): the Revoke tab / "Review standing access" / Home expiring-access read.
        # It used to run LIVE on the Manager's single request loop (140-170 s under Graph throttling) and froze
        # every user. It now runs HERE and lands in pim.TenantCache kind 'active-assignments'; the Manager only
        # reads that row, and its Refresh button queues a trigger for this job. Operator: a delay of a few hours
        # is acceptable -> every 120 min, editable on the Jobs page like every other job.
        [pscustomobject]@{ name='active-assignments-snapshot'; type='active-assignments-snapshot'; intervalMinutes=120; enabled=$true }
        # Drift page (operator, 2026-09-14: "why is this option not its own page and automatically run"): the live-vs-desired
        # plan (every scope, Full, Prune, WhatIf -- NO writes) used to run inside GET /api/drift on the Manager's one request
        # loop. It runs HERE and lands in pim.TenantCache kind 'drift'; the Drift page reads it and 'Check now' queues a trigger.
        # §70.22: every 4 h, not hourly -- the plan re-reads the whole tenant and holds the tick lease meanwhile (measured: a full
        # engine pass is 10-25 min on internal). The Drift page's Check now queues a run on demand.
        [pscustomobject]@{ name='drift-snapshot'; type='drift-snapshot'; intervalMinutes=240; enabled=$true }
        # 🔑 THE TRUST JOB (operator, 2026-09-12: "it is critical that we can trust that the
        # delegation is actual deployed into the platform"). Every other job makes a FAILURE
        # visible; this one makes SUCCESS provable. It re-reads LIVE from the tenant and diffs it
        # against DESIRED in pim.Rows -- writing nothing -- and reports how many delegations the
        # Manager shows that Entra does not actually hold. BUG-134 is exactly the case where
        # nothing errored and nothing was deployed, so "no job failed" was never the same claim.
        # Cached per scope and invalidated by a DESIRED-STATE HASH (see Get-PimConvergenceScopePlan),
        # so a fresh commit is re-verified immediately while an unchanged clean scope is not
        # re-read every cycle. An item is only a FAILURE once it stays unconverged past the grace
        # window -- a delegation committed 30s ago is legitimately not applied yet.
        [pscustomobject]@{ name='verify-convergence'; type='verify-convergence'; intervalMinutes=30; enabled=$true }
        [pscustomobject]@{ name='full-reconcile';     type='engine-full';  scope='All';      intervalMinutes=1440; enabled=$true  }
        [pscustomobject]@{ name='msp-pull';           type='msp-pull';        intervalMinutes=240;  enabled=$false }  # MSP deployments only
        # NOTE: NO 'sync-automateit' / update job here by design (operator correction 2026-06-18).
        # Code/SQL-schema/Manager-GUI updates are a STANDALONE mechanism run OUTSIDE the engine +
        # scheduler -- tools/setup/Invoke-PimUpdate.ps1, scheduled by VisualCron / Task Scheduler
        # (Register-PimSyncSchedule.ps1) or fired by the bootstrap post-sync deploy hook. The
        # scheduler stays for engine runs / slave data downlink only.
    )
}
function Disable-PimUnconfiguredIntegrationJobs {
    <#
      🔴 AN OPTIONAL INTEGRATION IS OFF UNLESS ITS INTEGRATION IS CONFIGURED -- in EVERY deployment,
      not just new ones (operator, 2026-09-10: "optional and must be disabled by default in all
      deployments").

      🪤 CHANGING THE DEFAULT WAS NOT ENOUGH, and this is the trap. Get-PimJobSchedule returns the
      STORED JobSchedule when there is one and only falls back to the default -- so every
      environment that had ever persisted a schedule (which is every environment whose cadences
      have been touched in the GUI) kept servicenow-intake switched on, and a new default would
      never reach it. The fix has to live where the schedule is RESOLVED, or it reaches only the
      deployments that did not need it.

      servicenow-intake polls a store-and-forward drop store named by $global:PIM_IntakeStoreFile.
      Without it the handler can only ever return no-op, so "enabled" is not a preference an
      operator can meaningfully hold -- it is a row in the Jobs list for an integration they do not
      have. That produced BUG-92's complaint ("i see references to failed jobs including
      servicenow, i dont have any servicenow"); BUG-92 fixed how it was REPORTED and left it on.
      🔑 It re-enables itself the moment the drop store IS configured, which is what makes this a
      capability gate rather than a hardcoded refusal.
    #>
    param([object[]]$Schedule)
    $out = @()
    foreach ($j in @($Schedule)) {
        if ($j -and "$($j.type)" -eq 'servicenow-intake' -and -not "$($global:PIM_IntakeStoreFile)".Trim()) {
            # Copy, never mutate the caller's object: the stored schedule is also what the GUI
            # renders, and silently rewriting it here would make the GUI disagree with the store.
            $c = $j.PSObject.Copy()
            try { $c.enabled = $false } catch { }
            $out += $c
            continue
        }
        $out += $j
    }
    @($out)
}

function Merge-PimJobSchedule {
    <#
      🔴 BUG-136 -- THE SCHEDULER AND THE GUI DISAGREED ABOUT WHAT A STORED SCHEDULE *IS*, AND
      THAT DISAGREEMENT IS WHY A SHIPPED FIX COULD NEVER REACH AN EXISTING CUSTOMER.

      The Manager has always treated the two halves correctly
      (Get-PimManagerEffectiveSchedule): the shipped default list is the CATALOG -- it owns each
      job's name, type and SCOPE -- and the stored 'JobSchedule' setting supplies only the two
      things an operator can actually set in the GUI, `enabled` and `intervalMinutes`. The GUI
      then writes a FULL snapshot back, stale `scope` included.

      Get-PimJobSchedule took that snapshot WHOLESALE. So the moment anyone touched a cadence in
      the Jobs tab, that environment froze its own private copy of every job's scope, and:
        * a corrected scope name in the shipped default could never reach it  (BUG-134's repair),
        * a NEWLY ADDED job could never reach it either -- it simply was not in the snapshot,
        * and the GUI kept rendering the catalog, so the Jobs tab showed a job the scheduler was
          not running, with no indication anywhere that the two lists had diverged.
      Three separate defects in this file have now each had to route around this
      (Disable-PimUnconfiguredIntegrationJobs, the BUG-134 alias map, and this). It is the trap
      itself that needed fixing.

      🔑 ONE MERGE, SHARED SEMANTICS: the catalog wins for identity (name/type/scope), the store
      wins for the operator's choices (enabled/intervalMinutes). The scheduler now resolves the
      SAME list the GUI renders, which is what "GUI-state == actual-behavior" was supposed to
      mean, and a released fix reaches every deployment by rolling the image.

      🪤 A stored job with NO catalog entry is KEPT, not dropped -- a hand-authored job, or one
      retired from the catalog, must not vanish silently (that would be this same bug pointing
      the other way). It is kept and then checked by Test-PimJobScopeBinding, so if it names a
      scope nothing serves, the boot report says so instead of ticking green.
    #>
    param([object[]]$Stored, [object[]]$Catalog)
    $cat = @($Catalog); if (-not $cat.Count) { $cat = @(Get-PimDefaultJobSchedule) }
    $storedByName = @{}
    foreach ($s in @($Stored)) { if ($s -and "$($s.name)".Trim()) { $storedByName["$($s.name)"] = $s } }
    $out = New-Object System.Collections.Generic.List[object]
    $seen = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($d in $cat) {
        if (-not $d) { continue }
        [void]$seen.Add("$($d.name)")
        # Copy the CATALOG row (it owns name/type/scope and any future field), then apply only
        # the operator-owned overrides. Never mutate the caller's object.
        $e = $d.PSObject.Copy()
        if ($storedByName.ContainsKey("$($d.name)")) {
            $ov = $storedByName["$($d.name)"]
            if ($ov.PSObject.Properties['enabled'])         { try { $e.enabled = [bool]$ov.enabled } catch { } }
            if ($ov.PSObject.Properties['intervalMinutes']) { try { $e.intervalMinutes = [int]$ov.intervalMinutes } catch { } }
        }
        $out.Add($e)
    }
    foreach ($s in @($Stored)) {
        if ($s -and "$($s.name)".Trim() -and -not $seen.Contains("$($s.name)")) { $out.Add($s) }
    }
    @($out.ToArray())
}

function Get-PimJobSchedule {
    # Resolution order: stored overrides (SQL pim.Settings, else the in-process mirror) merged
    # ONTO the shipped catalog -- see Merge-PimJobSchedule for why this is a merge and not a
    # replacement. Falls back to the catalog alone when nothing is stored.
    $stored = $null
    if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) {
        $stored = Get-PimPolicySetting -Name 'JobSchedule' -Default $null
    }
    if (-not $stored -and $global:PIM_JobSchedule) { $stored = @($global:PIM_JobSchedule) }
    $merged = Merge-PimJobSchedule -Stored @($stored) -Catalog (Get-PimDefaultJobSchedule)
    @(Disable-PimUnconfiguredIntegrationJobs -Schedule $merged)
}

function Test-PimJobScopeBinding {
    <#
      🔴 BUG-134 RUNTIME GATE -- "IS EVERY ENGINE JOB ACTUALLY BOUND TO A PROVIDER?"

      The release gate (tests/Test-PimJobScopeBinding.ps1) proves the SHIPPED schedule binds. It
      cannot prove anything about a deployment's STORED schedule, and the stored one is what runs:
      Get-PimJobSchedule prefers pim.Settings 'JobSchedule', so a customer whose cadences were
      edited in the GUI carries their own copy of every scope name -- including the broken ones
      this bug shipped, and including any hand-edit. That is the population that silently lost
      their delegations, so the check has to exist at runtime too, against the resolved list.

      PURE: takes the schedule, returns a verdict. The caller decides how loud to be.
      Returns @{ ok; checked; unbound = @(@{ name; scope; detail }) }.
    #>
    param([object[]]$Schedule)
    $jobs = @(@($Schedule) | Where-Object { $_ -and "$($_.type)" -in @('engine-delta','engine-full') })
    $unbound = New-Object System.Collections.Generic.List[object]
    if (-not (Get-Command Resolve-PimEngineScope -ErrorAction SilentlyContinue)) {
        # The engine core isn't loaded (Manager-only / unit-test host) -- we cannot answer, and
        # "cannot answer" must never be reported as "all bound". That conflation is this bug.
        return [pscustomobject]@{ ok = $true; checked = 0; unbound = @(); indeterminate = $true }
    }
    foreach ($j in $jobs) {
        $scope = if ($j.PSObject.Properties['scope'] -and "$($j.scope)".Trim()) { "$($j.scope)" } else { 'All' }
        $r = Resolve-PimEngineScope -Scope $scope
        if (-not $r.ok) { $unbound.Add([pscustomobject]@{ name = "$($j.name)"; scope = $scope; detail = "$($r.detail)" }) }
    }
    [pscustomobject]@{ ok = ($unbound.Count -eq 0); checked = $jobs.Count; unbound = $unbound.ToArray(); indeterminate = $false }
}

function Get-PimConvergenceVerdict {
    <#
      🔑 "HOW DO I KNOW THE DELEGATION IS ACTUALLY DEPLOYED?" -- the attestation, not a promise.

      Operator, 2026-09-12: *"it is critical that we can trust that the delegation is actual
      deployed into the platform - otherwise customer will not trust it. how do you control this
      desired state ... so it matches the actual delegation in pim"*.

      Everything else in this file makes a FAILURE visible. That is necessary and not sufficient:
      it proves no job reported an error, which is not the same claim as "what the Manager shows
      is what Entra holds". BUG-134 is precisely a case where nothing errored and nothing was
      deployed. Trust needs a POSITIVE measurement taken from the tenant.

      The engine already computes it, exactly, for free: `-Mode Full -WhatIf` over an assignment
      scope re-reads LIVE from Graph, diffs it against DESIRED in pim.Rows, and returns
      `create` = desired-but-not-present-live. That number IS the unconverged delegation count.
      WhatIf means the verification itself writes nothing.

      🪤 ">0 is not automatically a fault." A delegation committed 30 seconds ago is legitimately
      not applied yet -- failing on first sight would cry wolf on every normal commit, and an
      alarm that is usually wrong is an alarm nobody reads (BUG-92's lesson). So an item is only a
      FAILURE once it has stayed unconverged past $GraceMinutes, measured from when this verdict
      FIRST saw it. New items are reported and carried; persistent ones fail the job.

      PURE: no Graph, no SQL, no clock of its own. Takes the current unconverged keys, the
      previous state and 'now'; returns the verdict plus the state to persist for the next run.
      Returns @{ ok; total; new; persistent; items; state }.
    #>
    param(
        [string[]]$Unconverged = @(),        # stable keys, e.g. "GroupMembers|role-ciooffice|perm-x"
        [hashtable]$Previous   = @{},        # key -> ISO8601 first-seen
        [datetime]$NowUtc      = [datetime]::UtcNow,
        [int]$GraceMinutes     = 60,
        # Keys belonging to a scope we FAILED to verify this run. We did not observe them, so they
        # are not counted as a measurement -- but their clocks must keep running. Dropping them
        # would reset the age of every finding in a scope that cannot be verified, and repeated
        # Graph throttling is exactly when verification fails: an environment that can never
        # complete a check would then never raise a convergence failure either.
        [string[]]$Unverifiable = @()
    )
    $now  = $NowUtc.ToUniversalTime()
    $prev = if ($Previous -is [hashtable]) { $Previous } else { @{} }
    $state = @{}
    $persistent = New-Object System.Collections.Generic.List[object]
    $fresh      = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($Unconverged)) {
        $key = "$k".Trim()
        if (-not $key) { continue }
        # Carry the ORIGINAL first-seen forward; only a key absent from $Previous starts its clock
        # now. Resetting the clock on every observation would mean nothing ever became persistent.
        $firstSeen = $now
        if ($prev.ContainsKey($key)) { try { $firstSeen = ([datetime]$prev[$key]).ToUniversalTime() } catch { $firstSeen = $now } }
        $state[$key] = $firstSeen.ToString('o')
        $ageMin = [int][Math]::Floor(($now - $firstSeen).TotalMinutes)
        $row = [pscustomobject]@{ key = $key; firstSeenUtc = $firstSeen.ToString('o'); ageMinutes = $ageMin }
        if ($ageMin -ge $GraceMinutes) { $persistent.Add($row) } else { $fresh.Add($row) }
    }
    # Carry the clocks of an unverifiable scope's prior findings, without counting them above.
    foreach ($k in @($Unverifiable)) {
        $key = "$k".Trim()
        if ($key -and -not $state.ContainsKey($key) -and $prev.ContainsKey($key)) { $state[$key] = $prev[$key] }
    }
    # Keys that converged since last time simply drop out of $state -- the record of an item that
    # is now correct is the absence of a finding, not a growing history.
    [pscustomobject]@{
        ok         = ($persistent.Count -eq 0)
        total      = @($Unconverged).Count
        new        = $fresh.Count
        persistent = $persistent.Count
        items      = @($persistent.ToArray() + $fresh.ToArray())
        state      = $state
    }
}

function ConvertTo-PimPlainMap {
    # ConvertFrom-Json yields PSCustomObject, not hashtable, and the convergence helpers index by
    # key. One level deep is all these maps are. A $null / already-hashtable input round-trips.
    param([object]$Object)
    if ($null -eq $Object) { return @{} }
    if ($Object -is [hashtable]) { return $Object }
    $h = @{}
    if ($Object -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = $p.Value }
    }
    $h
}

function Get-PimConvergenceState {
    <#
      Convergence state (per-scope cache + per-item first-seen) lives in its OWN setting rather
      than inside SchedulerState. SchedulerState is rewritten wholesale by every tick's job
      bookkeeping, so folding another writer into it would lose one side of a concurrent write --
      and the thing we would lose is the first-seen clock that decides whether an unapplied
      delegation is "just committed" or "broken". Same store chain as the run history.
    #>
    $v = $null
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { $v = Get-PimSetting -Name 'ConvergenceState' } catch { $v = $null }
    }
    if (-not $v) { return [pscustomobject]@{ cache = @{}; firstSeen = @{} } }
    try { if ($v -is [string]) { $v = "$v" | ConvertFrom-Json } } catch { return [pscustomobject]@{ cache = @{}; firstSeen = @{} } }
    [pscustomobject]@{
        cache     = (ConvertTo-PimPlainMap $v.cache)
        firstSeen = (ConvertTo-PimPlainMap $v.firstSeen)
    }
}

function Save-PimConvergenceState {
    param([hashtable]$Cache = @{}, [hashtable]$FirstSeen = @{})
    $json = ([pscustomobject]@{ cache = $Cache; firstSeen = $FirstSeen } | ConvertTo-Json -Depth 8)
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) {
        try { Set-PimSetting -Name 'ConvergenceState' -Value $json | Out-Null; return $true }
        catch { Write-Warning "[verify] ConvergenceState did NOT persist ($($_.Exception.Message)). Every finding will look NEW on the next run, so nothing will ever age into a failure." }
    }
    $false
}

function Get-PimConvergenceScopePlan {
    <#
      🔑 CACHE THE VERIFICATION, so proving "it really is deployed" does not cost a full tenant
      re-read every cycle (operator, 2026-09-12: *"cache the result, so you dont have to run every
      hour all checks"*).

      A verification of scope S is still VALID if nothing that could change the answer has changed:
        * the DESIRED side is unchanged -- `desiredHash` is a hash of that scope's pim.Rows, so any
          Manager commit touching it changes the hash and forces a re-check. This is the signal
          that matters: a new delegation must be verified promptly, not on the next slow cycle.
        * the cached result was CLEAN -- an unconverged scope is always re-checked, regardless of
          age or hash, because that is the one we are waiting to see turn green.
        * the cache is younger than $MaxAgeMinutes -- a live-side change (someone edits a group in
          the portal) is invisible to the desired hash, so a clean scope is still re-read
          periodically. This is the backstop that keeps the cache honest rather than merely cheap.

      🪤 A cache whose only invalidation is AGE would answer the wrong question: it would go stale
      exactly when the operator most needs the truth -- in the minutes after they commit. Hashing
      the desired side is what makes "cached" safe to trust here.

      PURE: decides, does not measure. Returns one row per scope with {scope; verify; reason}.
    #>
    param(
        [object[]]$Scopes = @(),      # @{ scope; desiredHash }
        [hashtable]$Cache = @{},      # scope -> @{ desiredHash; checkedUtc; unconverged }
        [datetime]$NowUtc = [datetime]::UtcNow,
        [int]$MaxAgeMinutes = 720     # 12h backstop for a scope that looks clean and unchanged
    )
    $now = $NowUtc.ToUniversalTime()
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($s in @($Scopes)) {
        if (-not $s) { continue }
        $name = "$($s.scope)".Trim(); if (-not $name) { continue }
        $hash = "$($s.desiredHash)"
        $c = $null
        if ($Cache -is [hashtable] -and $Cache.ContainsKey($name)) { $c = $Cache[$name] }
        $verify = $true; $reason = 'no cached result'
        if ($c) {
            $cachedHash = "$($c.desiredHash)"
            $unconv = 0; try { $unconv = [int]$c.unconverged } catch { $unconv = 0 }
            $age = [int]::MaxValue
            try { $age = [int][Math]::Floor(($now - ([datetime]$c.checkedUtc).ToUniversalTime()).TotalMinutes) } catch { $age = [int]::MaxValue }
            if ($unconv -gt 0)              { $verify = $true;  $reason = "last result had $unconv unconverged item(s)" }
            elseif ($cachedHash -ne $hash)  { $verify = $true;  $reason = 'desired state changed since last check' }
            elseif ($age -ge $MaxAgeMinutes){ $verify = $true;  $reason = "cache is ${age}m old (max ${MaxAgeMinutes}m)" }
            else                            { $verify = $false; $reason = "cached clean ${age}m ago, desired unchanged" }
        }
        $out.Add([pscustomobject]@{ scope = $name; verify = $verify; reason = $reason })
    }
    @($out.ToArray())
}

function Write-PimJobScopeBindingReport {
    # Report the verdict ONCE per process, at boot, in a form an operator cannot read as healthy.
    param([object[]]$Schedule)
    if ($script:PimJobBindingReported) { return }
    $v = Test-PimJobScopeBinding -Schedule $Schedule
    if ($v.indeterminate) { return }          # engine core not loaded here; nothing to claim
    $script:PimJobBindingReported = $true
    if ($v.ok) {
        Write-Host "[scheduler] job->provider binding OK ($($v.checked) engine job(s) all resolve)" -ForegroundColor DarkGray
        return
    }
    foreach ($u in $v.unbound) {
        Write-Host "[scheduler] [!] JOB '$($u.name)' IS A NO-OP -- $($u.detail)" -ForegroundColor Red
        Write-Warning "[scheduler] job '$($u.name)' (scope '$($u.scope)') binds to NO engine provider. It will do nothing on every tick. Fix the 'JobSchedule' setting or the alias map; do not treat its green ticks as work done."
    }
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
# 🔴 A JOB MISSED ITS SLOT BY ONE SECOND, AND THEN BY HALF AN HOUR (measured on internal,
# 2026-09-12). delta-pim-au was due at 19:30:21; the 19:30 tick started at 19:30:20, so the strict
# `now -ge next` said "not yet". The 19:35 tick was lease-skipped (the 19:30 tick was still running),
# so the job ran ~30 minutes late and the Jobs view read "last run 24m ago, next run 8m ago".
# 🔑 A tick is a coarse clock -- it fires every few minutes and its start jitters by seconds -- so
# "due" must mean "due by the time this tick is running", not "due to the millisecond".
# The tolerance is 60 seconds -- the literal default of -ToleranceSeconds on Test-PimJobDue,
# Get-PimNextRunAfterRun and Resolve-PimSchedulerJobs (a literal, not a script variable, so a
# caller in another scope can never silently get 0).

function Get-PimNextRunAfterRun {
    <#
      PURE: the next slot after a scheduled run.
      🔴 THE OLD STAMP WAS "TICK START + INTERVAL". A tick runs its due jobs one after another, so a
      job could start 13 minutes after the tick did while its next slot was still counted from the
      tick -- and the next slot drifted every time a tick ran long.
      🔑 Anchor on the SLOT the run was scheduled for, so cadence does not drift:
            next = max(slot + interval, actualStart + interval - tolerance)
      The second term stops a job that started very late (a long tick, a skipped lease) from being
      due again moments after it finished. Minus the tolerance so the tick one interval later still
      catches it, instead of missing it by the seconds the previous tick took to reach the job.
    #>
    param([Parameter(Mandatory)][object]$Job, [Parameter(Mandatory)][datetime]$ScheduledUtc,
          [Parameter(Mandatory)][datetime]$StartedUtc, [int]$ToleranceSeconds = 60)
    $fromSlot  = Get-PimNextRunUtc -Job $Job -FromUtc $ScheduledUtc
    $fromStart = (Get-PimNextRunUtc -Job $Job -FromUtc $StartedUtc).AddSeconds(-$ToleranceSeconds)
    if ($fromSlot -ge $fromStart) { return $fromSlot }
    return $fromStart
}

function Resolve-PimSchedulerJobs {
    <#
      PURE: the job list a tick runs.
      🔴 THE TICK RAN ON A SNAPSHOT OF OLD CADENCES (measured on internal, 2026-09-12). With no job
      list passed, Invoke-PimSchedulerTick used SchedulerState.jobs -- the list the PREVIOUS tick
      saved, intervals included -- and only fell back to Get-PimJobSchedule when there was no state.
      State always exists after the first tick, so the catalog cadence change in 30ef4130
      (entra 20->10, azure/au 30->15, workloads 60->30) and every interval an operator saved in the
      Jobs tab never reached the runner. The Jobs tab showed the new cadence; the tick kept the old.
      🔑 The EFFECTIVE schedule (catalog + stored JobSchedule overrides, Get-PimJobSchedule) decides
      WHAT runs and HOW OFTEN. State contributes only what it is actually the record of: when each
      job last ran and when it is next due, joined by name. A job in state but not in the schedule is
      dropped -- the schedule no longer runs it.
      When the cadence changed, or the stored next slot is further out than one new interval, the
      next slot is re-derived: last run + new interval (or now + new interval when it never ran,
      whichever is sooner than the stored slot).
    #>
    param([object[]]$Schedule, [object[]]$StateJobs, [datetime]$NowUtc = [datetime]::UtcNow,
          [int]$ToleranceSeconds = 60)
    $now = $NowUtc.ToUniversalTime()
    $sched = @(@($Schedule) | Where-Object { $_ -and "$($_.name)".Trim() })
    if (-not $sched.Count) { return @(@($StateJobs) | Where-Object { $_ }) }   # nothing resolvable: keep running what we have
    $stateByName = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in @($StateJobs)) { if ($s -and "$($s.name)".Trim()) { $stateByName["$($s.name)"] = $s } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($d in $sched) {
        $e = $d.PSObject.Copy()   # never mutate the schedule the GUI also renders
        foreach ($p in @('lastRunUtc', 'nextRunUtc')) { if ($e.PSObject.Properties[$p]) { $e.PSObject.Properties.Remove($p) } }
        $sj = $null; [void]$stateByName.TryGetValue("$($d.name)", [ref]$sj)
        if ($sj) {
            foreach ($p in @('lastRunUtc', 'nextRunUtc')) {
                if ($sj.PSObject.Properties[$p] -and "$($sj.$p)".Trim()) { $e | Add-Member -NotePropertyName $p -NotePropertyValue "$($sj.$p)" -Force }
            }
            $iv = 0; try { $iv = [int]$e.intervalMinutes } catch { }
            if ($iv -le 0) { $iv = 60 }
            $next = $null; if ($e.PSObject.Properties['nextRunUtc']) { $next = Get-PimUtcStamp $e.nextRunUtc }
            $last = $null; if ($e.PSObject.Properties['lastRunUtc']) { $last = Get-PimUtcStamp $e.lastRunUtc }
            $oldIv = $null
            if ($sj.PSObject.Properties['intervalMinutes'] -and "$($sj.intervalMinutes)".Trim()) { try { $oldIv = [int]$sj.intervalMinutes } catch { } }
            $changed = ($null -ne $oldIv -and $oldIv -ne $iv)
            $tooFar  = ($null -ne $next -and $next -gt $now.AddMinutes($iv).AddSeconds($ToleranceSeconds))
            if ($null -ne $next -and ($changed -or $tooFar)) {
                if ($null -ne $last) { $nr = $last.AddMinutes($iv) }
                else { $nr = $now.AddMinutes($iv); if ($next -lt $nr) { $nr = $next } }
                $e.nextRunUtc = $nr.ToString('o')
                $why = if ($changed) { "cadence $oldIv -> $iv min" } else { "stored next slot was further out than one $iv-min interval" }
                Write-Host "[scheduler] '$($d.name)': $why -- next run re-derived to $($e.nextRunUtc)" -ForegroundColor DarkCyan
            }
        }
        $out.Add($e)
    }
    @($out.ToArray())
}

function Test-PimJobDue {
    param([Parameter(Mandatory)][object]$Job, [Parameter(Mandatory)][datetime]$NowUtc,
          [int]$ToleranceSeconds = 60)
    $en = $true; if ($Job.PSObject.Properties['enabled']) { $en = [bool]$Job.enabled }
    if (-not $en) { return $false }
    $next = $null
    if ($Job.PSObject.Properties['nextRunUtc'] -and "$($Job.nextRunUtc)".Trim()) {
        $next = Get-PimUtcStamp $Job.nextRunUtc   # IMP-02; unreadable -> treated as never scheduled (due)
    }
    if ($null -eq $next) { return $true }                 # never scheduled -> due
    # Tolerant: due when the slot falls within this tick (see the tolerance note above Get-PimNextRunAfterRun).
    return ($NowUtc.ToUniversalTime().AddSeconds($ToleranceSeconds) -ge $next)
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
    if ($keep.Count -eq 0) { $script:PimJobScope = $null; return @($script:PimJobHandlers.Keys) }
    # BUG-92: REMEMBER the scope, do not just delete the handlers.
    # Deleting alone left the dispatcher unable to tell "this worker is not supposed to run
    # that job" from "that job has no implementation" -- both surfaced as
    # no-handler-registered, which is recorded as status='failed'. On this deployment that put
    # SIX job types on the Overview permanently in red, including servicenow-intake for a
    # customer with no ServiceNow: "i see references to failed jobs including servicenow, i
    # dont have any servicenow". 390 of 863 recorded runs were this.
    # 🔑 Excluding a job by design and reporting it as broken must not be the same code path.
    $script:PimJobScope = $keep
    foreach ($t in @($script:PimJobHandlers.Keys)) { if ($t -notin $keep) { [void]$script:PimJobHandlers.Remove($t) } }
    return @($script:PimJobHandlers.Keys)
}

function Get-PimJobScope {
    # The job types this worker is scoped to run ($env:PIM_SCHED_JOBS), or $null for "all".
    if ($script:PimJobScope) { return @($script:PimJobScope) }
    return $null
}

# 🔴 BUG-112. The RUNNER knows its scope; the MANAGER renders the Jobs view. They are different
# processes -- on this deployment, different machines entirely: the jobs run from VisualCron on
# the management box out of the synced tree, while the GUI is a container. The Manager therefore
# has no $env:PIM_SCHED_JOBS of its own and could only INFER scope from run history, which is
# stale for any job whose cadence is 12-24h.
# So the runner PUBLISHES its scope to the shared store on every tick, and the Manager reads it.
# A fact, written once by the process that knows it, instead of guessed by the one that does not.
function Save-PimJobScopeToStore {
    param([string[]]$Scope)
    if (-not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) { return }
    try {
        $payload = [ordered]@{
            scope      = @($Scope)          # empty array = this worker runs everything
            owner      = (Resolve-PimSchedulerOwner)
            updatedUtc = ([datetime]::UtcNow.ToString('o'))
        }
        Set-PimSetting -Name 'JobScope' -Value ($payload | ConvertTo-Json -Depth 4 -Compress)
    } catch {
        # Never let publishing telemetry break a tick -- the worst case is the GUI keeps
        # showing what it showed before.
        Write-Verbose "could not publish job scope: $($_.Exception.Message)"
    }
}

function Get-PimPersistedJobScope {
    # The scope the RUNNER last published, lower-cased. $null = unknown or "runs everything",
    # which both mean "do not suppress anything" -- the safe direction: a job wrongly shown as
    # failing is noise, but a REAL failure hidden because we guessed the scope is a defect.
    if (-not (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) { return $null }
    try {
        $raw = Get-PimSetting -Name 'JobScope'
        if (-not $raw) { return $null }
        # 🔴 B1-class (2026-09-10): Get-PimSetting returns the value ALREADY JSON-PARSED, so the
        # first parse threw on a PSCustomObject and this whole function returned $null from the
        # catch -- i.e. "this worker has no declared scope", which switches the Jobs view's
        # out-of-scope muting OFF for every job. The store was fine; the reader broke it.
        $o = if ($raw -is [string]) { "$raw" | ConvertFrom-Json } else { $raw }
        if ($o -is [string]) { $o = "$o" | ConvertFrom-Json }
        $s = @($o.scope | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
        if ($s.Count -eq 0) { return $null }
        return $s
    } catch { return $null }
}

function Test-PimJobInScope {
    # BUG-92: is this job type this worker's responsibility at all? No scope set = run everything.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Type)
    $scope = Get-PimJobScope
    if (-not $scope) { return $true }
    return ("$Type".Trim().ToLowerInvariant() -in $scope)
}

function Send-PimDigestJobMail {
    <#
      Deliver a digest job's mail (daily-summary / tier-report) and report ONLY what happened.
      ran=$true requires at least one mail actually handed over; no recipients, no mail path, or
      every send refused (kill switch, disabled email feature, allowlist, no sender) is ran=$false
      with the reason -- the old handlers counted a digest nobody received as a successful run.
    #>
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][hashtable]$Tokens, [string]$What = '', [object]$Result, [switch]$WhatIf)
    $rc = if (Get-Command Get-PimDigestRecipients -ErrorAction SilentlyContinue) { Get-PimDigestRecipients -Kind $Type } else { [pscustomobject]@{ recipients = @(); source = 'none' } }
    $rcpts = @(@($rc.recipients) | Where-Object { "$_".Trim() })
    if (-not $rcpts.Count) {
        return [pscustomobject]@{ ran=$false; noRecipients=$true; whatIf=[bool]$WhatIf; result=$Result
            detail=("{0} built ({1}) but NOT sent -- no recipients: add them under Settings > Alerting" -f $Type, $What) }
    }
    if (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ ran=$false; whatIf=[bool]$WhatIf; result=$Result
            detail=("{0} built ({1}) but NOT sent -- the mail path (Send-PimNotifyMail) is not loaded in this process" -f $Type, $What) }
    }
    $sent = 0; $would = 0; $refused = New-Object System.Collections.Generic.List[string]
    foreach ($r in $rcpts) {
        $res = $null
        try { $res = Send-PimNotifyMail -Type $Type -Tokens $Tokens -Recipient "$r" -WhatIf:$WhatIf }
        catch { $res = @{ sent = $false; reason = "$($_.Exception.Message)" } }
        if ("$($res.sent)" -match '(?i)^true$') { $sent++ }
        elseif ("$($res.reason)" -eq 'whatif') { $would++ }
        else { $refused.Add(("{0}: {1}" -f $r, $res.reason)) }
    }
    $refTxt = if ($refused.Count) { " refused: " + ($refused.ToArray() -join '; ') } else { '' }
    if ($WhatIf) {
        return [pscustomobject]@{ ran=$false; whatIf=$true; result=$Result
            detail=("whatif:{0} -- would send to {1} of {2} recipient(s) ({3}){4}" -f $Type, $would, $rcpts.Count, $What, $refTxt) }
    }
    if ($sent -eq 0) {
        return [pscustomobject]@{ ran=$false; sent=0; recipients=$rcpts.Count; whatIf=$false; result=$Result
            detail=("{0} built ({1}) but NOT sent --{2}" -f $Type, $What, $refTxt) }
    }
    return [pscustomobject]@{ ran=$true; sent=$sent; recipients=$rcpts.Count; whatIf=$false; result=$Result
        detail=("{0} sent={1}/{2} ({3}){4}" -f $Type, $sent, $rcpts.Count, $What, $refTxt) }
}

function Initialize-PimDefaultJobHandlers {
    # Wire handlers to the EXISTING logic where it's present; otherwise a clearly
    # logged no-op stub (so a tick never crashes and the gap is visible). Real engine
    # handlers are registered by the launcher/container as the REST engine matures.
    Register-PimJobHandler -Type 'reminders' -Handler {
        param($job,$now,$whatIf)
        # 🔴 HOLLOW JOB (found 2026-09-12). This reported ran=true with "upcoming=0 renew=0" on every
        # tick for as long as it existed: it read $global:PIM_LifecycleItems, which NOTHING sets, so
        # the calendar was always built over an empty list. "0 upcoming" was never a measurement.
        # Now the items come from the DESIRED rows in SQL (Get-PimLifecycleItemsFromStore): admin
        # OffboardDate (71.21: NOT a delete date -- PIM never deletes an account), plus any assignment row with an explicit
        # lifecycle date. Three honest outcomes: cannot read the store -> unimplemented; nothing in the
        # window -> ran=false "nothing due"; something due -> ran=true, and the 'expiring-access' alert
        # is raised (debounced daily) through the scheduler's notify path, to the Alerting recipients.
        if (-not (Get-Command Build-PimLifecycleCalendar -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ ran=$false; detail='no-handler:Build-PimLifecycleCalendar' } }
        if (-not (Get-Command Get-PimLifecycleItemsFromStore -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ ran=$false; detail='no-handler:Get-PimLifecycleItemsFromStore' } }
        $src = Get-PimLifecycleItemsFromStore -NowUtc $now
        if (-not $src.ok) {
            return [pscustomobject]@{ ran=$false; unimplemented=$true; whatIf=[bool]$whatIf
                detail=("unimplemented:reminders -- {0} (cannot answer, not 'nothing due')" -f $src.error) }
        }
        $horizon = 30
        $cal = Build-PimLifecycleCalendar -Items @($src.items) -NowUtc $now -HorizonDays $horizon -KeyField 'Id' -NotifyLog @{}
        $upcoming = @($cal.upcoming | Where-Object { [int]$_.daysLeft -ge 0 })
        $overdue  = @($cal.upcoming | Where-Object { [int]$_.daysLeft -lt 0 })
        $renewals = @($cal.renewals)
        $readTxt = (@($src.read.Keys | ForEach-Object { "$($_)=$($src.read[$_])" }) -join ' ')
        $bad = if ([int]$src.unparseable -gt 0) { " unparseable-dates=$($src.unparseable)" } else { '' }
        if (($upcoming.Count + $overdue.Count) -eq 0) {
            return [pscustomobject]@{ ran=$false; nothingDue=$true; whatIf=[bool]$whatIf; calendar=$cal
                detail=("nothing due -- {0} lifecycle date(s) in SQL, none within {1} days (rows read: {2}){3}" -f @($src.items).Count, $horizon, $readTxt, $bad) }
        }
        $alert = 'not-sent'
        $lines = @(@($upcoming + $overdue) | Sort-Object { [int]$_.daysLeft } | Select-Object -First 12 | ForEach-Object {
            $it = $_.item
            "{0} {1}: {2} ({3} day(s))" -f "$($it.Kind)", "$($it.UserName)", ([datetime]$_.expiryUtc).ToUniversalTime().ToString('yyyy-MM-dd'), [int]$_.daysLeft })
        if ($whatIf) { $alert = 'whatif' }
        elseif (Get-Command Send-PimJobAlertViaNotify -ErrorAction SilentlyContinue) {
            $sent = $false
            try { $sent = [bool](Send-PimJobAlertViaNotify -Event 'expiring-access' -Title ("{0} access lifecycle date(s) due within {1} days" -f ($upcoming.Count + $overdue.Count), $horizon) -Detail ($lines -join '; ') -DebounceMinutes 1440) } catch { $sent = $false }
            $alert = if ($sent) { 'raised' } else { 'not-raised (event off, no recipients, or debounced)' }
        }
        return [pscustomobject]@{ ran=$true; whatIf=[bool]$whatIf; calendar=$cal; upcoming=$upcoming.Count; overdue=$overdue.Count
            detail=("upcoming={0} overdue={1} renew={2} alert={3} -- from SQL ({4}){5}" -f $upcoming.Count, $overdue.Count, $renewals.Count, $alert, $readTxt, $bad) }
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
        # §13 / #8 (2026-09-12). 🔴 THIS USED TO REPORT ran=true OVER NOTHING: it read a global
        # (PIM_ScheduledAdminRows) that no code in the product ever set, so every tick said
        # "create-due=0 tap-due=0" while future-dated admins were in fact created IMMEDIATELY by
        # delta-admins (the Admins provider ignored ProvisionDate).
        # 🔑 Now the Admins provider holds a row back until its ProvisionDate is due, and AdminTap
        # holds a TAP back until its lead window -- so creation needs no job of its own. This job is
        # the honest REPORT of what is waiting, read from SQL, and it creates nothing.
        if (Get-Command Get-PimScheduledAdminCreationReport -ErrorAction SilentlyContinue) {
            $rep = Get-PimScheduledAdminCreationReport -NowUtc $now
            if (-not $rep.ok) { return [pscustomobject]@{ ran=$false; detail="scheduled-creation: cannot report -- $($rep.reason)"; whatIf=[bool]$whatIf } }
            $next = if ($rep.next) { " next=$($rep.next.upn) at $(([datetime]$rep.next.provisionUtc).ToString('yyyy-MM-dd HH:mm')) UTC" } else { '' }
            return [pscustomobject]@{ ran=$true; reportOnly=$true; pending=@($rep.pending).Count; tapDeferred=@($rep.tapDeferred).Count
                detail=("scheduled-creation (report only; delta-admins creates each row when due): pending={0}{1} tap-deferred={2}" -f @($rep.pending).Count, $next, @($rep.tapDeferred).Count)
                whatIf=[bool]$whatIf }
        }
        return [pscustomobject]@{ ran=$false; unimplemented=$true; detail='unimplemented:scheduled-creation (the engine providers are not loaded on this worker)'; whatIf=[bool]$whatIf }
    }
    # #12 (2026-09-12): on-premises AD provisioning, applied only on a hybrid worker -- see
    # Invoke-PimHybridAdWorkerJob (PIM-HybridAd.ps1). On a host that cannot write AD it returns
    # unimplemented + requiresHybridWorker with the number of AD rows waiting.
    Register-PimJobHandler -Type 'hybrid-ad-apply' -Handler {
        param($job,$now,$whatIf)
        if (-not (Get-Command Invoke-PimHybridAdWorkerJob -ErrorAction SilentlyContinue)) {
            return [pscustomobject]@{ ran=$false; unimplemented=$true; detail='unimplemented:hybrid-ad-apply (PIM-HybridAd.ps1 is not loaded on this worker)'; whatIf=[bool]$whatIf }
        }
        Invoke-PimHybridAdWorkerJob -NowUtc $now -WhatIf:$whatIf
    }
    Register-PimJobHandler -Type 'verify-convergence' -Handler {
        param($job,$now,$whatIf)
        # The REAL handler is wired by tools/pim-scheduler/Start-PimScheduler.ps1, which is the
        # process that carries the engine + providers. Here (Manager-only host, offline tests) it
        # DECLARES itself unimplemented rather than recording a completed no-op -- BUG-114's rule,
        # and doubly so for the one job whose whole purpose is to be believed.
        [pscustomobject]@{ ran=$false; unimplemented=$true
            detail='unimplemented:verify-convergence (wired by Start-PimScheduler, which loads the engine providers)'
            whatIf=[bool]$whatIf }
    }
    Register-PimJobHandler -Type 'active-assignments-snapshot' -Handler {
        param($job,$now,$whatIf)
        # §70.1b option 2. The REAL handler is registered by tools/pim-scheduler/Start-PimScheduler.ps1
        # (Register-PimActiveAssignmentsSnapshotHandler, engine/_shared/PIM-ActiveAssignments.ps1). 🔒 It is
        # deliberately NOT wired here: the Manager calls this initializer too (Invoke-PimJobForceStart), and a
        # live 140-170 s tenant read on the Manager's one request loop is precisely the freeze this job removes.
        [pscustomobject]@{ ran=$false; unimplemented=$true
            detail='unimplemented:active-assignments-snapshot (wired by Start-PimScheduler; the Manager never runs the live read)'
            whatIf=[bool]$whatIf }
    }
    Register-PimJobHandler -Type 'drift-snapshot' -Handler {
        param($job,$now,$whatIf)
        # Drift page (2026-09-14). The REAL handler is registered by tools/pim-scheduler/Start-PimScheduler.ps1
        # (Register-PimDriftSnapshotHandler, engine/_shared/PIM-DriftSnapshot.ps1). 🔒 Deliberately NOT wired here: the Manager
        # initialises these handlers too, and a full engine plan over every scope on its one request loop is the freeze this removes.
        [pscustomobject]@{ ran=$false; unimplemented=$true
            detail='unimplemented:drift-snapshot (wired by Start-PimScheduler; the Manager never runs the drift plan)'
            whatIf=[bool]$whatIf }
    }
    Register-PimJobHandler -Type 'queue-apply' -Handler {
        param($job,$now,$whatIf)
        # 🔴 BUG-135 -- THIS HANDLER HAS NEVER APPLIED ANYTHING, AND SAID `ran=$true` EVERY 5 MINUTES.
        # It checked that Get-PimQueueApplyPlan was LOADED and returned success on the strength of
        # that. It never read pim.ChangeQueue, never built a plan, never wrote a row. Found while
        # tracing BUG-134: the same "a step that cannot work reports success" class, in the job an
        # operator is most likely to read as proof their commit was applied.
        # 🔑 WHAT ACTUALLY DRAINS WHAT, measured 2026-09-12 -- do not "repair" this by auto-applying:
        #   * The Manager's Commit writes desired state STRAIGHT to pim.Rows
        #     (Invoke-PimManagerSafeCommit). It does NOT use pim.ChangeQueue, so a delegation does
        #     not depend on this job -- the engine-delta scopes are what push pim.Rows to Entra.
        #   * pim.ChangeQueue is the DISCOVERY PROPOSAL inbox ("propose-don't-auto-map, never
        #     auto-delete"). Draining it automatically would auto-import every discovered scope --
        #     the exact behaviour the discovery design refuses. So the honest state of this job is
        #     "nothing to do here", NOT "applied".
        #   * Invoke-PimSqlCommit (PIM-SqlStore.ps1) is the drainer, and it has NO CALLERS.
        # Declared unimplemented via the BUG-114 pattern so it shows as a gap in the Jobs list
        # instead of a green tick. Wiring a reviewed drain is tracked separately -- it is a
        # behaviour change and needs the review UI, not a silent switch-on here.
        # ✅ §65 -- THIS NOW DRAINS, and what it drains is precisely defined:
        #   * ONLY Status='committed'. A 'pending' entry is one nobody selected, and applying it
        #     would be the auto-import the discovery design refuses -- BUG-135's rule, now carried
        #     by the schema instead of by this job refusing to do anything at all.
        #   * DesiredState entries land in pim.Rows (Invoke-PimSqlCommit).
        #   * Action entries are applied against the directory by the engine's own applier.
        # 🪤 STILL NEVER REPORT ran=$true ON A PATH THAT CANNOT WORK. Without SQL, or without the
        # drain loaded, this declares itself rather than counting a no-op as a success -- that
        # conflation IS BUG-134/BUG-135.
        if (-not (Get-Command Invoke-PimSqlCommit -ErrorAction SilentlyContinue)) {
            return [pscustomobject]@{ ran=$false; detail='no-handler:Invoke-PimSqlCommit' }
        }
        if (-not $global:PIM_SqlConnectionString) {
            return [pscustomobject]@{ ran=$false; unimplemented=$true
                detail='unimplemented:queue-apply -- no SQL connection string in this host, so the queue cannot be read (this is "cannot answer", not "nothing to do")'
                whatIf=[bool]$whatIf }
        }
        $cs = $global:PIM_SqlConnectionString
        $pending = $null
        try { $pending = @(Get-PimSqlQueue -ConnectionString $cs -Status 'pending').Count } catch { $pending = $null }

        if ($whatIf) {
            $c = $null
            try { $c = @(Get-PimSqlQueue -ConnectionString $cs -Status 'committed').Count } catch { $c = $null }
            return [pscustomobject]@{ ran=$false; whatIf=$true; pendingProposals=$pending; committed=$c
                detail="whatif:queue-apply -- would drain $c committed entr(ies); $pending awaiting operator commit" }
        }

        $ds = $null; $act = $null; $errDetail = ''
        try { $ds = Invoke-PimSqlCommit -ConnectionString $cs -AppliedBy 'scheduler' }
        catch { $errDetail = "desired-state drain failed: $($_.Exception.Message)" }
        if (Get-Command Invoke-PimQueueActionDrain -ErrorAction SilentlyContinue) {
            try { $act = Invoke-PimQueueActionDrain -ConnectionString $cs -AppliedBy 'scheduler' }
            catch { $errDetail = ("$errDetail action drain failed: $($_.Exception.Message)").Trim() }
        }

        $applied  = [int]$ds.applied  + [int]$act.applied
        $failed   = [int]$ds.failed   + [int]$act.failed
        $retrying = [int]$ds.retrying + [int]$act.retrying
        # §70.1b option 2: an ASSIGNMENT REVOKE that was actually applied makes the stored active-assignments
        # snapshot stale -- queue one refresh (deduped) so the Revoke tab catches up on a following tick instead of
        # waiting out the 2-hour cadence. Only revokes: a TAP reset or a session revoke changes no assignment.
        $revokesApplied = @(@($act.results) | Where-Object { $_ -and "$($_.outcome)" -eq 'applied' -and "$($_.type)" -in @('entra-role-revoke','group-assignment-revoke','azure-rbac-revoke') }).Count
        if ($revokesApplied -gt 0) {
            try { [void](Add-PimJobTrigger -Type 'active-assignments-snapshot' -Scope 'All' -Reason "queue-apply:revokes-applied=$revokesApplied") }
            catch { Write-Warning "[scheduler] could not queue an active-assignments refresh after $revokesApplied applied revoke(s): $($_.Exception.Message)" }
        }
        # 🔑 A FAILED ENTRY IS REPORTED, NOT SWALLOWED. The whole point of §65.8 is that a queued
        # action whose failure nobody sees is worse than a synchronous one that throws.
        [pscustomobject]@{ ran=$true; applied=$applied; failed=$failed; retrying=$retrying
            pendingProposals=$pending
            detail=("queue-apply: applied=$applied failed=$failed retrying=$retrying; $pending awaiting operator commit" + $(if ($errDetail) { " -- $errDetail" } else { '' }))
            whatIf=$false }
    }
    # (1) Daily summary of delegation/assignment changes -- read this month's audit jsonl,
    # fold into a 24h digest, render + send to the configured digest recipients.
    # 🔴 HOLLOW (found 2026-09-12): it read only output/audit/*.jsonl, a FILE the hosted runtime never
    # writes (the audit trail is pim.AuditEvents), and sent to $global:PIM_DigestRecipients, which
    # nothing sets -- so it recorded ran=true, "changes=0 recipients=0", every day, and never mailed.
    # Now: events from the SQL audit trail, a Manager commit counted by what it changed, recipients
    # from pim.Settings['Alerting']. ran=true only when a digest was actually handed to the mailer.
    Register-PimJobHandler -Type 'daily-summary' -Handler {
        param($job,$now,$whatIf)
        if (-not (Get-Command Get-PimDailySummary -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ ran=$false; detail='no-handler:Get-PimDailySummary' } }
        if (-not (Get-Command Get-PimDailySummaryEventsFromStore -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ ran=$false; detail='no-handler:Get-PimDailySummaryEventsFromStore' } }
        $src = Get-PimDailySummaryEventsFromStore -NowUtc $now
        if (-not $src.ok) {
            return [pscustomobject]@{ ran=$false; unimplemented=$true; whatIf=[bool]$whatIf
                detail=("unimplemented:daily-summary -- {0} (cannot answer, not 'nothing due')" -f $src.error) }
        }
        $sum = Get-PimDailySummary -Events @($src.events) -NowUtc $now
        if ([int]$sum.totalChanges -eq 0) {
            return [pscustomobject]@{ ran=$false; nothingDue=$true; whatIf=[bool]$whatIf; summary=$sum
                detail=("nothing due -- 0 delegation/assignment changes in the last 24h ({0} audit event(s) read from {1})" -f @($src.events).Count, $src.source) }
        }
        return (Send-PimDigestJobMail -Type 'daily-summary' -WhatIf:$whatIf -Result $sum `
                    -Tokens (ConvertTo-PimDailySummaryTokens -Summary $sum -TenantLabel "$($global:PIM_TenantLabel)") `
                    -What ("changes={0} (admins={1} delegations={2} removals={3}; {4} audit event(s) from {5})" -f $sum.totalChanges, @($sum.admins).Count, @($sum.delegations).Count, @($sum.removals).Count, @($src.events).Count, $src.source))
    }
    # (2) Tier 0/1 report. 🔴 HOLLOW (found 2026-09-12): it read $global:PIM_TierReportAssignments
    # and $global:PIM_TierReportRecipients, which nothing sets -- "users=0 recipients=0", ran=true.
    # Now: admin -> PIM group assignments from SQL with each grant's tier/level from its definition
    # row and its live state from the verify-convergence result; recipients from Alerting.
    Register-PimJobHandler -Type 'tier-report' -Handler {
        param($job,$now,$whatIf)
        if (-not (Get-Command Get-PimTierZeroOneReport -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ ran=$false; detail='no-handler:Get-PimTierZeroOneReport' } }
        $rows = @(); $srcTxt = 'injected'; $liveTxt = ''
        if ($null -ne $global:PIM_TierReportAssignments) { $rows = @($global:PIM_TierReportAssignments) }
        else {
            if (-not (Get-Command Get-PimTierReportAssignmentsFromStore -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ ran=$false; detail='no-handler:Get-PimTierReportAssignmentsFromStore' } }
            $src = Get-PimTierReportAssignmentsFromStore
            if (-not $src.ok) {
                return [pscustomobject]@{ ran=$false; unimplemented=$true; whatIf=[bool]$whatIf
                    detail=("unimplemented:tier-report -- {0} (cannot answer, not 'nothing due')" -f $src.error) }
            }
            $rows = @($src.rows); $srcTxt = "SQL PIM-Assignments-Admins rows=$($src.read)"
            $notLive = @($rows | Where-Object { "$($_.Live)" -eq 'not-deployed' }).Count
            $liveTxt = if ($src.live -and "$($src.live.checkedUtc)".Trim()) { "; live verified $($src.live.checkedUtc) unconverged=$($src.live.unconverged) not-deployed-grants=$notLive" } else { "; live: no convergence result yet" }
        }
        if ($rows.Count -eq 0) {
            return [pscustomobject]@{ ran=$false; nothingDue=$true; whatIf=[bool]$whatIf
                detail=("nothing due -- no admin assignments to report ({0})" -f $srcTxt) }
        }
        $rep = @(Get-PimTierZeroOneReport -Assignments $rows)
        $t0 = @($rep | Where-Object { [int]$_.highestTier -eq 0 }).Count
        return (Send-PimDigestJobMail -Type 'tier-report' -WhatIf:$whatIf -Result $rep `
                    -Tokens (ConvertTo-PimTierReportTokens -Report $rep -TenantLabel "$($global:PIM_TenantLabel)") `
                    -What ("users={0} (T0={1} T1={2}) from {3}{4}" -f $rep.Count, $t0, ($rep.Count - $t0), $srcTxt, $liveTxt))
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
            # BUG-114: as above -- declare it, or it records as a completed no-op.
            return [pscustomobject]@{ ran=$false; unimplemented=$true; detail='unimplemented:tenant-cache (dot-source tools/pim-manager/_tenantSync.ps1 to wire Invoke-PimTenantListRefresh)'; whatIf=[bool]$whatIf }
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
            # 🔴 BUG-114 -- `unimplemented` is a FOURTH outcome, and it must say so.
            # This placeholder returns ran=$false, and the dispatcher sets ok=$true because the
            # DISPATCH succeeded -- so before this flag the record was status='completed' and the
            # Jobs view rendered it as amber **"no-op"**. That is the single most misleading word
            # available: "no-op" means "there was nothing to do", which is the answer an operator
            # most wants to be true, while the truth is "nobody has implemented this". A daily
            # full-reconcile said "no-op" for months and looked healthy doing it.
            [pscustomobject]@{ ran=$false; unimplemented=$true; detail="unimplemented:$($job.type) scope=$scope (no real handler registered on this worker)"; whatIf=[bool]$whatIf }
        }
    }
    # discovery: a default handler that drives the REAL sweep (Invoke-PimDiscoveryJobSweep)
    # via the seam wired by Register-PimDiscoveryHandler. Until the launcher supplies the
    # live enumerator + store readers, it is a clearly-logged no-op (never crashes, the
    # gap is visible) -- mirroring the tenant-cache handler.
    Register-PimJobHandler -Type 'discovery' -Handler {
        param($job,$now,$whatIf)
        $scope = if ($job.PSObject.Properties['scope']) { "$($job.scope)" } else { 'All' }
        # BUG-114: same shape as the engine-* placeholder above -- a registered handler that
        # cannot do the work still yields ok=$true, so without this flag it recorded as a
        # completed "no-op" run rather than as an unwired capability.
        [pscustomobject]@{ ran=$false; unimplemented=$true; detail="unimplemented:discovery scope=$scope (call Register-PimDiscoveryHandler with the live enumerator/store seams)"; whatIf=[bool]$whatIf }
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
    param([Parameter(Mandatory)][object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [string]$CorrelationId = '')
    # BUG-92 -- OUT OF SCOPE IS NOT A FAILURE, and it is checked BEFORE the handler lookup.
    # $env:PIM_SCHED_JOBS scopes a worker to a subset of job types; Select-PimJobHandlers then
    # removes the other handlers. The SCHEDULE still lists every job, so this dispatcher was
    # still called for them, found no handler, and returned ok=$false -- recorded as FAILED.
    # A deployment that had deliberately excluded servicenow-intake, escalations,
    # scheduled-creation, reminders, daily-summary and tier-report therefore showed all six as
    # failing forever, and the real signal (a job IN scope with no implementation) was buried
    # in the noise. Reported as: "i see references to failed jobs including servicenow, i dont
    # have any servicenow".
    if (-not (Test-PimJobInScope -Type "$($Job.type)")) {
        return [pscustomobject]@{ name="$($Job.name)"; type="$($Job.type)"; ok=$true; ran=$false
                                   outOfScope=$true
                                   detail="not scheduled on this worker (PIM_SCHED_JOBS = $((Get-PimJobScope) -join ', '))"
                                   ranUtc=$NowUtc.ToString('o') }
    }
    # 🔴 BUG-113 -- ASK "IS IT SWITCHED OFF?" BEFORE "IS IT IMPLEMENTED HERE?"
    # This gate used to sit BELOW the handler lookup, so a job whose feature is DISABLED but
    # which has no handler on this worker was recorded as **failed / no-handler-registered**
    # instead of the truth, "disabled -- skipped". Reported as: *"it should not report failed
    # if disabled"*.
    # 🔑 Both questions have an answer, and the order decides which one the operator is told.
    #    "Switched off" is the one they can act on, and it is the one they already know is true
    #    -- being told a deliberately-disabled feature FAILED teaches them to distrust the
    #    column. Scope (above) then disabled (here) then implementation (below) runs from the
    #    most deliberate cause to the least.
    if (Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) {
        if (-not (Test-PimFeatureAvailable -Key 'scheduler.jobs' -Quiet)) {
            return [pscustomobject]@{ name="$($Job.name)"; type="$($Job.type)"; ok=$true; ran=$false; detail="feature 'scheduler.jobs' disabled -- skipped"; skippedFeature='scheduler.jobs'; ranUtc=$NowUtc.ToString('o') }
        }
        $fk = Get-PimJobFeatureKey -Type "$($Job.type)"
        if ($fk -and -not (Test-PimFeatureAvailable -Key $fk -Quiet)) {
            return [pscustomobject]@{ name="$($Job.name)"; type="$($Job.type)"; ok=$true; ran=$false; detail="feature '$fk' disabled -- skipped"; skippedFeature=$fk; ranUtc=$NowUtc.ToString('o') }
        }
    }
    $h = Get-PimJobHandler -Type "$($Job.type)"
    # 🔒 STILL NOT SOFTENED TO GREEN. A job that is in scope, ENABLED, and has no implementation
    # is exactly the signal the BUG-92 noise was hiding -- it stays ok=$false. What changed is
    # only that it can no longer be reached by a job the operator switched OFF, and that the
    # Jobs view counts it as "not runnable here" rather than as a failed RUN (see BUG-113 in
    # Get-PimJobsView): the fault is in the deployment, not in a run that went wrong.
    if (-not $h) { return [pscustomobject]@{ name="$($Job.name)"; type="$($Job.type)"; ok=$false; ran=$false; noHandler=$true; detail='no-handler-registered'; ranUtc=$NowUtc.ToString('o') } }
    # §70.15 LOG-04: one correlation id per job run. The engine stamps it on every change it audits
    # (Write-PimEngineChangeAudit) and the run record uses it as its runId, so "which run made this
    # change" and "what did this run change" are the same lookup.
    $corr = if ("$CorrelationId".Trim()) { "$CorrelationId" } else { [guid]::NewGuid().ToString('N') }
    $global:PIM_JobCorrelationId = $corr; $global:PIM_JobName = "$($Job.name)"
    # 🔑 THE RUN'S OWN OUTPUT (operator, 2026-09-14: "when i click logs i expected a real logs with entries"). The Logs
    # button showed only a summary built from the handler's return value; everything the engine prints -- the per-scope
    # desired/live/create lines, warnings, per-item errors -- went to the container console alone. The handler's
    # information (Write-Host) and warning streams are captured HERE, echoed to the console exactly as before, and
    # stored per job (Save-PimJobRunOutput) -- flushed while a long run is still going, so live tail shows progress.
    $cap = New-PimJobOutputCapture -Job $Job -RunId $corr -Persist:(-not $WhatIf)
    try {
        $out = New-Object System.Collections.Generic.List[object]
        & $h $Job $NowUtc.ToUniversalTime() $WhatIf 3>&1 6>&1 | ForEach-Object {
            # The capture must never be what fails a run (2.4.357: an echo error failed every engine job on internal).
            $item = $_
            $isLog = $true
            try { $isLog = [bool](Add-PimJobOutputRecord -Capture $cap -Record $item) }
            catch { $isLog = ($item -is [System.Management.Automation.InformationRecord] -or $item -is [System.Management.Automation.WarningRecord]) }
            if (-not $isLog) { $out.Add($item) }
        }
        $r = if ($out.Count -eq 1) { $out[0] } elseif ($out.Count -eq 0) { $null } else { $out.ToArray() }
        Complete-PimJobOutputCapture -Capture $cap
        return [pscustomobject]@{ name="$($Job.name)"; type="$($Job.type)"; ok=$true; detail="$($r.detail)"; result=$r; ranUtc=$NowUtc.ToString('o'); correlationId=$corr }
    } catch {
        $cap.lines.Add(([datetime]::UtcNow.ToString('HH:mm:ss')) + " ERROR: $($_.Exception.Message)")
        Complete-PimJobOutputCapture -Capture $cap
        return [pscustomobject]@{ name="$($Job.name)"; type="$($Job.type)"; ok=$false; detail="error: $($_.Exception.Message)"; ranUtc=$NowUtc.ToString('o'); correlationId=$corr }
    } finally {
        $global:PIM_JobCorrelationId = ''; $global:PIM_JobName = ''
    }
}

# ---- per-run OUTPUT (the lines a run printed) -------------------------------
# Stored per JOB NAME in pim.Settings 'JobRunOutput:<name>' = the newest $PimJobRunOutputKeep runs, each capped. NOT in
# JobRunHistory: that one value is rewritten on every run of every job and was already 1.98 MB before §70.8 cut it.
$script:PimJobRunOutputKeep          = 3
$script:PimJobRunOutputHeadLines     = 200
$script:PimJobRunOutputTailLines     = 1800
$script:PimJobRunOutputMaxLineChars  = 1000
$script:PimJobRunOutputFlushSeconds  = 30
$script:PimJobRunOutputMemory        = @{}    # this process only (no SQL store / offline tests)

function Get-PimJobRunOutputSettingName {
    param([string]$Name)
    $n = "$Name".Trim(); if ($n.Length -gt 180) { $n = $n.Substring(0, 180) }
    return "JobRunOutput:$n"
}

function Limit-PimJobRunOutputLines {
    # PURE. Keep the first HeadLines and the last TailLines; every line cut to MaxLineChars.
    param([string[]]$Lines = @(), [int]$Head = $script:PimJobRunOutputHeadLines, [int]$Tail = $script:PimJobRunOutputTailLines, [int]$MaxChars = $script:PimJobRunOutputMaxLineChars)
    $all = @($Lines | ForEach-Object { $s = "$_"; if ($s.Length -gt $MaxChars) { $s.Substring(0, $MaxChars) + ' ...' } else { $s } })
    if ($all.Count -le ($Head + $Tail)) { return [pscustomobject]@{ lines = $all; omitted = 0 } }
    $omitted = $all.Count - $Head - $Tail
    $kept = @($all[0..($Head - 1)]) + @("... ($omitted line(s) omitted) ...") + @($all[($all.Count - $Tail)..($all.Count - 1)])
    return [pscustomobject]@{ lines = $kept; omitted = $omitted }
}

function Save-PimJobRunOutput {
    # Persist one run's output under its job, replacing an earlier save of the same run. Never throws: losing the
    # output of a run must not fail the run.
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$RunId, [string[]]$Lines = @(), [switch]$Running)
    try {
        $lim = Limit-PimJobRunOutputLines -Lines $Lines
        $entry = [pscustomobject]@{ runId = "$RunId"; running = [bool]$Running; updatedUtc = [datetime]::UtcNow.ToString('o'); omitted = [int]$lim.omitted; lines = @($lim.lines) }
        $key = Get-PimJobRunOutputSettingName -Name $Name
        $existing = @(Get-PimJobRunOutputEntries -Name $Name | Where-Object { "$($_.runId)" -ne "$RunId" })
        $keep = @(@($entry) + $existing | Select-Object -First $script:PimJobRunOutputKeep)
        $script:PimJobRunOutputMemory[$key] = $keep
        if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { Set-PimSetting -Name $key -Value ([object[]]$keep) | Out-Null }
        return $true
    } catch {
        Write-Verbose "[scheduler] output of run $RunId ($Name) not saved: $($_.Exception.Message)"
        return $false
    }
}

function Get-PimJobRunOutputEntries {
    param([Parameter(Mandatory)][string]$Name)
    $key = Get-PimJobRunOutputSettingName -Name $Name
    $v = $null
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { $v = Get-PimSetting -Name $key; if ($v -is [string]) { $v = $v | ConvertFrom-Json } } catch { $v = $null }
    }
    if ($null -eq $v -and $script:PimJobRunOutputMemory.ContainsKey($key)) { $v = $script:PimJobRunOutputMemory[$key] }
    return @(@($v) | Where-Object { $_ -and "$($_.runId)" })
}

function Get-PimJobRunOutput {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$RunId)
    return (@(Get-PimJobRunOutputEntries -Name $Name | Where-Object { "$($_.runId)" -eq "$RunId" }) | Select-Object -First 1)
}

function New-PimJobOutputCapture {
    param([object]$Job, [string]$RunId, [switch]$Persist)
    return [pscustomobject]@{ name = "$($Job.name)"; runId = "$RunId"; persist = [bool]$Persist
        lines = (New-Object System.Collections.Generic.List[string]); lastFlush = [datetime]::UtcNow; flushedCount = 0 }
}

function Test-PimConsoleColorValue {
    # PURE. $true only for a real ConsoleColor (0-15). A container console reports -1 for "no colour".
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $false }
    try { $i = [int]$Value } catch { return $false }
    return ($i -ge 0 -and $i -le 15)
}

function Add-PimJobOutputRecord {
    <#
      One item from the handler's merged output. An information record (Write-Host) or a warning is captured, echoed
      to the console as it was, and $true is returned; anything else is the handler's return value ($false).
    #>
    param([Parameter(Mandatory)][object]$Capture, [AllowNull()][object]$Record)
    $stamp = [datetime]::UtcNow.ToString('HH:mm:ss')
    if ($Record -is [System.Management.Automation.InformationRecord]) {
        $md = $Record.MessageData
        $text = if ($md -is [System.Management.Automation.HostInformationMessage]) { "$($md.Message)" } else { "$md" }
        $Capture.lines.Add("$stamp $text")
        # 🔴 2.4.357 LIVE REGRESSION (internal, 2026-09-14 20:40Z): in the Linux container a Write-Host with no colour
        # carries ForegroundColor/BackgroundColor = -1 (the console has no colour), and re-echoing that value threw
        # "Cannot process the color because -1 is not a valid color" INSIDE the handler's pipeline -- every engine job
        # failed at its first colourless line. Only a defined ConsoleColor is passed on, and the echo can NEVER fail
        # the job: the console copy is a courtesy, the run is not.
        try {
            if ($md -is [System.Management.Automation.HostInformationMessage]) {
                $p = @{ Object = $md.Message; NoNewline = [bool]$md.NoNewLine }
                if (Test-PimConsoleColorValue $md.ForegroundColor) { $p.ForegroundColor = $md.ForegroundColor }
                if (Test-PimConsoleColorValue $md.BackgroundColor) { $p.BackgroundColor = $md.BackgroundColor }
                Write-Host @p
            } else { Write-Host $text }
        } catch { try { Write-Host $text } catch { } }
    } elseif ($Record -is [System.Management.Automation.WarningRecord]) {
        $Capture.lines.Add("$stamp WARNING: $($Record.Message)")
        try { Write-Warning $Record.Message } catch { }
    } else {
        return $false
    }
    if ($Capture.persist -and $script:PimJobRunOutputFlushSeconds -gt 0 -and $Capture.lines.Count -gt $Capture.flushedCount -and
        ([datetime]::UtcNow - $Capture.lastFlush).TotalSeconds -ge $script:PimJobRunOutputFlushSeconds) {
        [void](Save-PimJobRunOutput -Name $Capture.name -RunId $Capture.runId -Lines $Capture.lines.ToArray() -Running)
        $Capture.lastFlush = [datetime]::UtcNow; $Capture.flushedCount = $Capture.lines.Count
    }
    return $true
}

function Complete-PimJobOutputCapture {
    param([Parameter(Mandatory)][object]$Capture)
    # A run that printed nothing stores nothing: queue-apply runs every tick, and an empty entry would be one more
    # pim.Settings write per job per tick for no reader.
    if (-not $Capture.persist -or -not "$($Capture.runId)" -or -not "$($Capture.name)" -or $Capture.lines.Count -eq 0) { return }
    [void](Save-PimJobRunOutput -Name $Capture.name -RunId $Capture.runId -Lines $Capture.lines.ToArray())
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

# ---- state persistence (SQL settings -> memory) ---------------------------
# 🔒 SQL-ONLY (2026-09-13). SchedulerState, JobRunHistory and JobAcknowledgements live in
# pim.Settings. The JSON files beside $global:PIM_SchedulerStatePath (pim-scheduler-state.json,
# pim-scheduler-runs.json, pim-scheduler-acks.json) are no longer read or written. The in-process
# memory copy remains for ONE process (offline tests, a single tick) and is never presented as
# persistence: a save that does not reach SQL warns.
function Get-PimSchedulerState {
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        # B1-class hardening: Save-PimSchedulerState writes a STRING (already JSON), which
        # Set-PimSqlSetting then JSON-encodes again -- so the read comes back as text today and
        # this parse is correct. It is only correct BY SYMMETRY, though: a single-encoded value
        # (written by any other path) would come back already parsed and the parse would throw
        # into a bare catch, silently reverting the whole scheduler to file/memory state and
        # making every job look due. Accept both shapes, and never fail in silence.
        try {
            $v = Get-PimSetting -Name 'SchedulerState'
            if ($v) { if ($v -is [string]) { return ("$v" | ConvertFrom-Json) } else { return $v } }
        } catch { Write-Warning "  [scheduler] SchedulerState read failed -- using this process's in-memory state: $($_.Exception.Message)" }
    }
    return $script:PimSchedState
}
function Save-PimSchedulerState {
    param([Parameter(Mandatory)][object]$State)
    $script:PimSchedState = $State
    $json = $State | ConvertTo-Json -Depth 8
    # 🔴 A PERSIST THAT FAILS SILENTLY IS INVISIBLE; ITS CONSEQUENCE IS NOT.
    # Every tick is a NEW process, so state that does not reach the store does not exist: the next
    # tick sees no last-run times and EVERY JOB LOOKS DUE EVERY TICK. Start-PimScheduler warns
    # loudly when the store is not WIRED -- but wired-and-failing produced the identical outcome
    # with no warning at all, because the write was in a bare catch.
    # 🔑 SQL is the only persistence; the memory copy above serves this process only.
    $saved = $false; $why = 'no SQL settings store (Set-PimSetting) is wired -- PIM v2 is SQL-only'
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) {
        try { Set-PimSetting -Name 'SchedulerState' -Value $json | Out-Null; $saved = $true } catch { $why = "$($_.Exception.Message)" }
    }
    if (-not $saved) { Write-Warning "[scheduler] SchedulerState did NOT persist ($why). Every job will look due on the next tick." }
}

# ---- run history + per-run logs (SQL settings -> memory) -------------------
# The scheduler keeps a bounded ring of recent runs so the Manager GUI can show
# "last run + result + log" and mark in-progress jobs. A run record:
#   { runId; name; type; scope; ok; ran; detail; status(running|completed|failed);
#     startedUtc; finishedUtc; durationMs; log(string) }
# Persisted in SQL pim.Settings 'JobRunHistory' (shared across the manager + scheduler
# processes); the in-memory copy serves one process only. No file (SQL-only).
$script:PimRunHistory     = $null            # in-memory (this process only)
# §70.8 (2026-09-13): 50 -> 10. The ring is ONE pim.Settings value rewritten on every job run; at 50 per job it
# held 1,227 runs (1.98 MB) on internal and each save took ~6 s against the Basic tier's log-rate cap. Ten recent
# runs per job still answers "did it fail recently, and when" (Jobs tab failure history); full logs live in
# Log Analytics.
$script:PimRunHistoryMax  = 10               # ring size PER job name

function Get-PimJobRunHistory {
    # Returns an array of run records (newest first). Optional -Name filters to one job.
    param([string]$Name)
    $all = $null
    # NOTE (PS 5.1): assign ConvertFrom-Json to a temp FIRST, then @($tmp). Wrapping the
    # pipeline directly -- @(... | ConvertFrom-Json) -- collapses a JSON array into a
    # single Object[] element (count 1) on Windows PowerShell. The temp forces enumeration.
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        # §70.8: two stored shapes -- the legacy double-encoded JSON TEXT (a string that parses to the array), and
        # the compact single-encoded array (comes back already parsed). Accept both; a parse failure is warned,
        # never silently turned into "no history".
        try {
            $v = Get-PimSetting -Name 'JobRunHistory'
            if ($v) {
                if ($v -is [string]) { $tmp = $v | ConvertFrom-Json; $all = @($tmp) }
                else { $all = @($v) }
            }
        } catch { Write-Warning "  [scheduler] JobRunHistory read failed -- using this process's in-memory history: $($_.Exception.Message)" }
    }
    if ($null -eq $all) { $all = @($script:PimRunHistory) }
    $all = @(@($all) | Where-Object { $_ })
    if ("$Name".Trim()) { $all = @($all | Where-Object { "$($_.name)" -eq "$Name" }) }
    return @($all | Sort-Object { "$($_.startedUtc)" } -Descending)
}
function Save-PimJobRunHistory {
    param([object[]]$Runs = @())
    $script:PimRunHistory = @($Runs)
    # Same cascade, same silence: run history that does not persist means the Jobs tab shows no
    # recent runs and an operator cannot tell a job that failed from one that never ran.
    # §70.8: the ARRAY is handed to the store, which serialises it ONCE (compact). This used to pass
    # pre-serialised, indented JSON TEXT, which the store JSON-encoded AGAIN -- every quote and newline
    # escaped, roughly doubling the bytes written on every job run.
    $saved = $false; $why = 'no SQL settings store (Set-PimSetting) is wired -- PIM v2 is SQL-only'
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) {
        try { Set-PimSetting -Name 'JobRunHistory' -Value ([object[]]@($Runs)) | Out-Null; $saved = $true } catch { $why = "$($_.Exception.Message)" }
    }
    if (-not $saved) { Write-Warning "[scheduler] JobRunHistory did NOT persist ($why). Recent runs will not appear in the Jobs tab." }
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
    # The summary, then what the run PRINTED (Save-PimJobRunOutput) -- for a running job, what it has printed so far.
    $log = "$($rec.log)"
    $lineCount = 0
    $o = $null; try { $o = Get-PimJobRunOutput -Name "$($rec.name)" -RunId "$RunId" } catch { $o = $null }
    if ($o -and @($o.lines).Count) {
        $lineCount = @($o.lines).Count
        $hdr = "---- output ($(if ($o.running) { 'so far, still running' } else { 'complete' })$(if ([int]$o.omitted -gt 0) { "; $($o.omitted) line(s) omitted in the middle" })) ----"
        $log = $log + "`n`n" + $hdr + "`n" + (@($o.lines) -join "`n")
    } elseif ("$($rec.status)" -ne 'running') {
        $log = $log + "`n`n(no output was kept for this run -- it printed nothing, or it ran before run output was recorded)"
    }
    return [pscustomobject]@{ runId="$RunId"; name="$($rec.name)"; type="$($rec.type)"; status="$($rec.status)"; startedUtc="$($rec.startedUtc)"; finishedUtc="$($rec.finishedUtc)"; ok=[bool]$rec.ok; log=$log; outputLines=$lineCount }
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
# A bounded set of acknowledged runIds, persisted like the run history
# (SQL pim.Settings 'JobAcknowledgements'; the memory copy serves this process only).
# Acknowledging a failed run mutes its signal (failure/overdue badges) WITHOUT deleting
# the run record, so the audit trail stays intact.
$script:PimAckRunIds = $null

function Get-PimRunAcknowledgements {
    # Returns an array of acknowledged runIds (strings). SQL pim.Settings 'JobAcknowledgements',
    # else this process's memory copy (no file -- SQL-only).
    $all = $null
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { $v = Get-PimSetting -Name 'JobAcknowledgements'; if ($v) { $tmp = $v | ConvertFrom-Json; $all = @($tmp) } } catch {}
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
    # An acknowledgement that does not persist re-raises the same failure on the next tick, so the
    # operator acks it again, and again -- looking like a fault that will not clear.
    $saved = $false; $why = 'no SQL settings store (Set-PimSetting) is wired -- PIM v2 is SQL-only'
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) {
        try { Set-PimSetting -Name 'JobAcknowledgements' -Value $json | Out-Null; $saved = $true } catch { $why = "$($_.Exception.Message)" }
    }
    if (-not $saved) { Write-Warning "[scheduler] JobAcknowledgements did NOT persist ($why). Acknowledged failures will re-appear." }
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
        # The effective schedule, not state.jobs: state carries the cadence of whichever tick last
        # saved it. Last/next-run stamps are still joined from state below ($stateByName).
        $Jobs = @(Get-PimJobSchedule)
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
        # 🔴 B10 (2026-09-10) -- A JOB THAT RAN 32 SECONDS AGO WAS SHOWN "overdue 12m".
        # Screenshot: queue-apply, cadence 5 min, Status ok, Last run 32s ago, Next run 12m AGO,
        # and the banner escalating it as "a scheduled run did not fire on time". Those cannot all
        # be true -- a job that ran 32s ago on a 5-minute cadence is next due ~4 minutes from now.
        # 🔑 The view trusted a persisted nextRunUtc that was OLDER THAN THE LAST RUN. A next-run
        # stamp that precedes the run it was supposed to schedule is stale BY DEFINITION: the run
        # already happened, so the stamp describes a fire window that is closed. Whatever failed to
        # advance it (a path that records history without advancing cadence, or two workers each
        # persisting only their own slice of the shared state blob), the view must never claim a
        # job that just ran is late. So: if lastRun >= persistedNext, the stamp is spent -- recompute
        # the expectation from lastRun + cadence, which is what the scheduler itself would have
        # written. This holds regardless of mechanism, which is the point: the operator asked this
        # exact question once before, it was ANSWERED IN CHAT and never guarded, and it came back.
        # 🔒 INVARIANT, asserted in Test-PimScheduler.ps1: after a successful run, nextRun is
        # strictly in the future and overdue is false.
        $persistNext = $null
        if ($j.PSObject.Properties['nextRunUtc'] -and "$($j.nextRunUtc)".Trim()) { $persistNext = "$($j.nextRunUtc)" }
        elseif ($sj -and $sj.PSObject.Properties['nextRunUtc'] -and "$($sj.nextRunUtc)".Trim()) { $persistNext = "$($sj.nextRunUtc)" }
        # B10: retire a next-run stamp the last run has already overtaken, and re-derive it from
        # the run that actually happened. Locale-safe parsing (IMP-02) on both sides; an unreadable
        # stamp changes nothing and falls through to the existing never-run handling.
        $nextStale = $false
        if ("$persistNext".Trim() -and "$lastRun".Trim() -and $iv -gt 0) {
            $pn = Get-PimUtcStamp $persistNext
            $lr = Get-PimUtcStamp $lastRun
            if ($null -ne $pn -and $null -ne $lr -and $lr -ge $pn) {
                $persistNext = $lr.AddMinutes($iv).ToString('o')
                $nextStale = $true
                # The GUI shows this value, so keep the two in step -- a row that says
                # "next run 12m ago" while claiming not to be overdue is just a different lie.
                $next = $persistNext
            }
        }
        # 🔴 THE VIEW SHOWED THE NEW CADENCE AND THE OLD NEXT RUN (internal, 2026-09-12):
        # delta-workloads, "every 30 min", last run 20s ago, next run in 52m. The row's interval came
        # from the effective schedule (30) while its next-run came from state written under the old
        # one (60). A stamp more than one interval past the last run cannot be what the current
        # cadence schedules, so re-derive it -- the same rule Resolve-PimSchedulerJobs applies for the
        # tick, so the view and the runner agree. Also when the stored cadence differs outright
        # (a cadence that GREW would otherwise keep the old, shorter slot on screen).
        if (-not $nextStale -and "$persistNext".Trim() -and $iv -gt 0) {
            $pn = Get-PimUtcStamp $persistNext
            if ($null -ne $pn) {
                $lr = $null; if ("$lastRun".Trim()) { $lr = Get-PimUtcStamp $lastRun }
                $cap = if ($null -ne $lr) { $lr.AddMinutes($iv) } else { $now.AddMinutes($iv) }
                $oldIv = $null
                if ($sj -and $sj.PSObject.Properties['intervalMinutes'] -and "$($sj.intervalMinutes)".Trim()) { try { $oldIv = [int]$sj.intervalMinutes } catch { } }
                $cadenceChanged = ($null -ne $oldIv -and $oldIv -ne $iv -and $null -ne $lr)
                # 120s margin: the runner anchors on the slot, which may sit up to its 60s due tolerance
                # after the job's actual start.
                if ($cadenceChanged -or $pn -gt $cap.AddSeconds(120)) {
                    $persistNext = $cap.ToString('o')
                    $next = $persistNext
                    $nextStale = $true
                }
            }
        }
        $od = Get-PimJobOverdueState -Job $j -NowUtc $now -LastRunUtc "$lastRun" -NextRunUtc "$persistNext" -InProgress ([bool]$inProg)
        # 🔴 BUG-112 -- SCOPE IS A PROPERTY OF THE JOB, NOT OF ITS LAST RUN.
        # BUG-92 stopped RECORDING an out-of-scope dispatch as a failure, but the Jobs view
        # still judged each job by its most recent run record. So nine jobs this deployment
        # never runs sat in `failed / no-handler-registered` from BEFORE that fix, with next
        # runs 7-17 HOURS away -- they would have stayed red until tomorrow, kept an "Ack"
        # button, and counted toward "10 failing" the whole time.
        # 🔑 The last run's status is stale data about a question that no longer applies. The
        # worker's scope is persisted by the runner (Save-PimJobScopeToStore), so the view can
        # answer "does this deployment run this job at all?" directly and stop inferring it
        # from history. Out of scope => never failing, never overdue, never needs attention.
        $jobScope   = Get-PimPersistedJobScope
        $outOfScope = $false
        if ($jobScope -and @($jobScope).Count -gt 0) {
            $outOfScope = ("$($j.type)".Trim().ToLowerInvariant() -notin @($jobScope))
        }
        if ($outOfScope) { $od = [pscustomobject]@{ overdue = $false; expectedUtc = $null; overdueByMinutes = 0; reason = 'not scheduled on this deployment' } }
        # [M6] LAST-RUN ACK: is the latest FAILED run muted? + recent failure count.
        $lastRunId = $(if ($last) { "$($last.runId)" } else { '' })
        $lastAcked = ($lastRunId -and ($acks -contains $lastRunId))
        $finishedRuns = @($runs | Where-Object { "$($_.status)" -ne 'running' -and "$($_.finishedUtc)".Trim() })
        $recentWindow = @($finishedRuns | Sort-Object { "$($_.startedUtc)" } -Descending | Select-Object -First 10)
        $allNotOk     = @($recentWindow | Where-Object { -not [bool]$_.ok })
        # 🔴 BUG-113 -- "NO HANDLER HERE" IS NOT A FAILED RUN, IT IS A MISSING CAPABILITY.
        # Measured in prod 2026-08-30: every single red count in the Jobs view -- tenant-cache 9,
        # reminders 9, daily-summary 9, tier-report 9, discovery-entra/azure/powerbi 5 each,
        # full-reconcile 5 -- was `no-handler-registered`, and NOT ONE was a run that went wrong.
        # tenant-cache's most recent run was a healthy refresh of 146 Entra roles.
        # 🔑 Nothing about it is per-run: it is one fact about the worker, repeated once per
        # tick. Counting it per run inflates one deployment fact into "9 failures", attaches an
        # Ack button to something no acknowledgement can fix, and buries the failures that ARE
        # runs. It is the same class BUG-92 fixed at RECORD time -- but records already written
        # live in the history ring for 50 runs, so the view has to answer for them too.
        $unrunnable   = @($allNotOk | Where-Object { "$($_.detail)" -match '^no-handler' })
        $recentFails  = @($allNotOk | Where-Object { "$($_.detail)" -notmatch '^no-handler' })
        # 🔑 A FAILURE THE JOB HAS SINCE RECOVERED FROM IS NOT "FAILING" (operator, 2026-09-14: "3 jobs are still
        # failing, how to fix" -- delta-pim-azure-policies had run clean for two hours, its last run was green, and it
        # still counted as failing with NO Ack button, because Ack is offered only when the LAST run failed). A failed
        # run older than a later COMPLETED, ok run is recovered: still counted and listed under History, never demanding
        # attention. A placeholder ('unimplemented') or skipped run is not a recovery.
        $lastGood = @($recentWindow | Where-Object { [bool]$_.ok -and "$($_.status)" -eq 'completed' }) | Select-Object -First 1
        $lastGoodAt = if ($lastGood) { Get-PimUtcStamp "$($lastGood.startedUtc)" } else { $null }
        $isRecovered = { param($run) if ($null -eq $lastGoodAt) { return $false }; $t = Get-PimUtcStamp "$($run.startedUtc)"; return ($null -ne $t -and $t -lt $lastGoodAt) }
        $recoveredFails = @($recentFails | Where-Object { & $isRecovered $_ })
        $unackedFails = @($recentFails | Where-Object { -not ($acks -contains "$($_.runId)") -and -not (& $isRecovered $_) })
        # BUG-112: a job this deployment does not run has no failures to answer for. Its
        # history is real and stays readable under History -- but it must not demand an Ack or
        # be counted as failing, or the operator is asked to acknowledge a bug we already fixed.
        # 🔴 BUG-114 -- a placeholder handler is NOT a clean run, and it is not a failure either.
        # These records carry ok=$true (the dispatch worked), so they never reach $allNotOk and
        # are counted here from their own status. Before this they were indistinguishable from a
        # real converged run: the view called them "no-op".
        $unimplemented = @($recentWindow | Where-Object { "$($_.status)" -eq 'unimplemented' })
        # 71.13: a HELD run (a safety breaker awaiting approval) is neither a failure nor a success. It needs
        # attention until a LATER completed run shows the approved plan applied -- the same recovery rule as a failure.
        $heldRuns = @($recentWindow | Where-Object { "$($_.status)" -eq 'held' })
        $standingHeld = @($heldRuns | Where-Object { -not (& $isRecovered $_) })
        if ($outOfScope) { $recentFails = @(); $unackedFails = @(); $recoveredFails = @(); $unrunnable = @(); $unimplemented = @(); $heldRuns = @(); $standingHeld = @() }
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
            # BUG-92: the GUI needs the THREE-WAY outcome, not just ok/not-ok. Without this
            # the Overview can only ask "did it fail?", and "not scheduled on this worker"
            # has no answer to that question except the wrong one.
            lastStatus      = $(if ($last -and $last.PSObject.Properties['status']) { "$($last.status)" } elseif ($last) { $(if ($last.ok) { 'completed' } else { 'failed' }) } else { '' })
            # BUG-112: the GUI renders these muted and excludes them from "needs attention".
            outOfScope      = [bool]$outOfScope
            lastRan         = $(if ($last) { [bool]$last.ran } else { $null })
            lastDurationMs  = $(if ($last) { [int64]$last.durationMs } else { $null })   # [int64] -- see BUG-04
            lastRunId       = $lastRunId
            lastAcknowledged   = [bool]$lastAcked
            runningRunId    = $(if ($inProg) { "$($inProg.runId)" } else { '' })
            nextRunUtc      = $next
            nextRunSynthesized = [bool]$nextSynth
            # B10: true when the persisted next-run had been overtaken by the last run and was
            # re-derived here. Surfaced so "why does this differ from the store?" is answerable
            # without reading code -- and so a test can prove the re-derivation actually fired.
            nextRunRederived   = [bool]$nextStale
            overdue            = [bool]$od.overdue
            overdueByMinutes   = [int]$od.overdueByMinutes
            expectedRunUtc     = "$($od.expectedUtc)"
            recentFailureCount = $recentFails.Count
            unackedFailureCount = $unackedFails.Count
            # Failed runs followed by a later clean run (see $isRecovered): shown muted, never "failing".
            recoveredFailureCount = $recoveredFails.Count
            # The runs Ack clears: every failure still standing, not only the newest. A job whose last run was a
            # placeholder (Run now on a tick-only type before 2.4.357) has lastOk=true, and Ack was never offered.
            unackedFailureRunIds = @($unackedFails | ForEach-Object { "$($_.runId)" } | Where-Object { $_ })
            # ISO 'o' from the parsed stamp: pwsh 7's ConvertFrom-Json hands back a [datetime], which "$()" renders in
            # the host culture (the history is JSON-round-tripped through pim.Settings).
            lastSuccessUtc     = $(if ($null -ne $lastGoodAt) { $lastGoodAt.ToUniversalTime().ToString('o') } else { '' })
            # BUG-113: reported SEPARATELY and rendered muted -- the operator still sees that the
            # job has no implementation on this worker, but it never shows as a red failed run.
            unrunnableCount    = $unrunnable.Count
            # BUG-114: reported separately from BOTH failures and successes. "No handler at all"
            # (unrunnableCount) and "a handler that is a placeholder" (this) are different
            # deployment facts, and neither is a run that went wrong.
            unimplementedCount = $unimplemented.Count
            # 71.13: held runs (awaiting an operator's approval), and whether one is still standing.
            heldCount          = $heldRuns.Count
            needsApproval      = [bool]($standingHeld.Count -gt 0)
            heldDetail         = $(if ($standingHeld.Count) { "$(@($standingHeld)[0].detail)" } else { '' })
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
        # 71.13: jobs with a standing HOLD (needs approval) -- counted under "needs attention", never under failing.
        heldCount    = @($rows | Where-Object { $_.needsApproval }).Count
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
    param([Parameter(Mandatory)][object]$Job, [Parameter(Mandatory)][object]$Result, [datetime]$StartedUtc = [datetime]::UtcNow, [switch]$Trigger, [string]$Reason = '', [string]$RunId = '')
    $fin = [datetime]::UtcNow
    $inner = if ($Result.PSObject.Properties['result']) { $Result.result } else { $null }
    $ran = $false; if ($inner -and $inner.PSObject.Properties['ran']) { $ran = [bool]$inner.ran }
    # BUG-114: the handler declares this about itself; it is never inferred from the detail
    # string, because a message is prose and prose gets reworded.
    $unimplemented = $false; if ($inner -and $inner.PSObject.Properties['unimplemented']) { $unimplemented = [bool]$inner.unimplemented }
    # 71.13: the handler declares a HOLD about itself (policy mass-change breaker awaiting approval) -- a FIFTH outcome.
    $held = $false; if ($Result.ok -and $inner -and $inner.PSObject.Properties['held']) { $held = [bool]$inner.held }
    $rec = [pscustomobject]@{
        # §70.15 LOG-04: the run's id IS the correlation id the engine stamped on every change it audited.
        # -RunId (the tick's id, also on its 'running' record) wins, so an early return without a correlation id
        # (out of scope / disabled / no handler) still REPLACES the running record instead of leaving it stale.
        runId       = $(if ("$RunId".Trim()) { "$RunId" } elseif ($Result.PSObject.Properties['correlationId'] -and "$($Result.correlationId)".Trim()) { "$($Result.correlationId)" } else { [guid]::NewGuid().ToString('N') })
        name        = "$($Job.name)"
        type        = "$($Job.type)"
        scope       = $(if ($Job.PSObject.Properties['scope']) { "$($Job.scope)" } else { '' })
        ok          = [bool]$Result.ok
        ran         = $ran
        # BUG-92: 'skipped' is a THIRD outcome. Collapsing it into completed would claim work
        # that never happened; collapsing it into failed is what put six job types
        # permanently in red on a healthy deployment.
        # BUG-114: 'unimplemented' is a FOURTH outcome, and it is NOT a clean run. The dispatch
        # succeeds (ok=$true) whenever a handler is registered, even a placeholder that does
        # nothing -- so without this the record said 'completed' and the view said "no-op",
        # i.e. "there was nothing to do". Ordering is deliberate: outOfScope wins, because a job
        # this deployment does not run has nothing to answer for either way (BUG-112).
        # 71.13: 'held' is a FIFTH outcome -- the run did its work and a safety breaker HELD a change set for an
        # operator's approval. Never 'completed' (that would hide the approval), never 'failed' (nothing broke).
        status      = $(if ($Result.PSObject.Properties['outOfScope'] -and $Result.outOfScope) { 'skipped' } elseif ($unimplemented) { 'unimplemented' } elseif ($held) { 'held' } elseif ($Result.ok) { 'completed' } else { 'failed' })
        held        = [bool]$held
        heldCount   = $(if ($held -and $inner.PSObject.Properties['heldCount']) { [int]$inner.heldCount } else { 0 })
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
    # ALERT-01: a finished run raises the failure alert HERE. Previously the ONLY
    # engine-failure producer was the Manager's POST /api/jobs/run handler, so a job
    # that failed on a SCHEDULED tick raised nothing -- alerting worked when someone
    # was already watching and was silent when nobody was. Both real completion paths
    # (this one and Invoke-PimJobForceStart) now go through the same decision.
    # Guarded + never throws: the run record is already persisted above, and an
    # alerting fault must not take the tick down or lose run history.
    if (Get-Command Invoke-PimJobRunAlert -ErrorAction SilentlyContinue) { [void](Invoke-PimJobRunAlert -Run $rec) }
    return $rec
}

function Write-PimJobRunningRecord {
    # §70.18 (operator 2026-09-13: "where do i see what is happening right now in the queue/jobs ? logs ? realtime
    # view ?"). A scheduled tick wrote its run record only when a job FINISHED, so a 10-20 minute engine run was
    # invisible in the Manager until it was over. The tick now writes a 'running' record at the START of every
    # engine job under the run's correlation id; Write-PimJobRunRecord replaces it by that same runId. Engine types
    # only: the short jobs finish within seconds, and every record is a pim.Settings write on a small database.
    param([Parameter(Mandatory)][object]$Job, [Parameter(Mandatory)][string]$RunId, [datetime]$StartedUtc = [datetime]::UtcNow, [switch]$Trigger, [string]$Reason = '')
    if ("$($Job.type)" -notin @('engine-delta', 'engine-full', 'msp-pull')) { return }
    try {
        $scope = if ($Job.PSObject.Properties['scope']) { "$($Job.scope)" } else { '' }
        Add-PimJobRunRecord -Run ([pscustomobject]@{
            runId = $RunId; name = "$($Job.name)"; type = "$($Job.type)"; scope = $scope
            ok = $true; ran = $true; status = 'running'
            detail = "running since $($StartedUtc.ToUniversalTime().ToString('HH:mm:ss')) UTC$(if ($scope) { " (scope $scope)" })"
            trigger = [bool]$Trigger; reason = "$Reason"
            startedUtc = $StartedUtc.ToUniversalTime().ToString('o'); finishedUtc = ''; durationMs = 0
            log = ("[{0}] job '{1}' started by the scheduler{2}" -f $StartedUtc.ToUniversalTime().ToString('o'), "$($Job.name)", $(if ($scope) { " scope=$scope" } else { '' }))
        })
    } catch { Write-Verbose "[scheduler] running record for $($Job.name) not written: $($_.Exception.Message)" }
}

function Close-PimStaleRunningRecords {
    param([datetime]$NowUtc = [datetime]::UtcNow, [int]$OlderThanMinutes = 30)
    try {
        $all = @(Get-PimJobRunHistory)
        $cut = $NowUtc.ToUniversalTime().AddMinutes(-$OlderThanMinutes)
        $stale = @($all | Where-Object { "$($_.status)" -eq 'running' -and -not "$($_.finishedUtc)".Trim() -and (Get-PimUtcStamp $_.startedUtc) -and (Get-PimUtcStamp $_.startedUtc) -lt $cut })
        if (-not $stale.Count) { return 0 }
        $ids = @{}; foreach ($s in $stale) { $ids["$($s.runId)"] = $true }
        $fixed = @($all | ForEach-Object {
            if ($ids.ContainsKey("$($_.runId)") -and "$($_.status)" -eq 'running') {
                $_.status = 'failed'; $_.ok = $false
                $_.detail = "interrupted: the run started $($_.startedUtc) and never reported back (the scheduler process ended while it ran)"
                $_.finishedUtc = $NowUtc.ToUniversalTime().ToString('o')
            }
            $_ })
        Save-PimJobRunHistory -Runs $fixed
        Write-Host "[scheduler] closed $($stale.Count) stale 'running' record(s) as interrupted" -ForegroundColor DarkYellow
        return $stale.Count
    } catch { Write-Verbose "[scheduler] stale running records not closed: $($_.Exception.Message)"; return 0 }
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
    $res = Invoke-PimScheduledJob -Job $Job -NowUtc $now -WhatIf:$WhatIf -CorrelationId $runId
    $fin = [datetime]::UtcNow
    $inner = if ($res.PSObject.Properties['result']) { $res.result } else { $null }
    $ran = $false; if ($inner -and $inner.PSObject.Properties['ran']) { $ran = [bool]$inner.ran }
    # §70.19: the same fourth outcome Write-PimJobRunRecord already records (BUG-114). Run now on a worker with a
    # placeholder handler said "completed" -- measured on internal 2026-09-13, green for a run that did nothing.
    $unimpl = $false; if ($inner -and $inner.PSObject.Properties['unimplemented']) { $unimpl = [bool]$inner.unimplemented }
    $heldF = $false; if ($res.ok -and $inner -and $inner.PSObject.Properties['held']) { $heldF = [bool]$inner.held }   # 71.13
    $rec = [pscustomobject]@{
        runId       = $runId
        name        = "$($Job.name)"
        type        = "$($Job.type)"
        scope       = $(if ($Job.PSObject.Properties['scope']) { "$($Job.scope)" } else { '' })
        ok          = [bool]$res.ok
        ran         = $ran
        status      = $(if ($res.PSObject.Properties['outOfScope'] -and $res.outOfScope) { 'skipped' } elseif ($unimpl) { 'unimplemented' } elseif ($heldF) { 'held' } elseif ($res.ok) { 'completed' } else { 'failed' })   # BUG-92 / BUG-114 / 71.13
        held        = [bool]$heldF
        heldCount   = $(if ($heldF -and $inner.PSObject.Properties['heldCount']) { [int]$inner.heldCount } else { 0 })
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
    # ALERT-01: a finished run raises the failure alert HERE. Previously the ONLY
    # engine-failure producer was the Manager's POST /api/jobs/run handler, so a job
    # that failed on a SCHEDULED tick raised nothing -- alerting worked when someone
    # was already watching and was silent when nobody was. Both real completion paths
    # (this one and Invoke-PimJobForceStart) now go through the same decision.
    # Guarded + never throws: the run record is already persisted above, and an
    # alerting fault must not take the tick down or lose run history.
    if (Get-Command Invoke-PimJobRunAlert -ErrorAction SilentlyContinue) { [void](Invoke-PimJobRunAlert -Run $rec) }
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
    # A trigger that does not persist is a "Run now" the operator pressed and the scheduler will
    # never see -- the button appears to work and nothing happens.
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) {
        try { Set-PimSetting -Name 'SchedulerTriggers' -Value (@($Triggers) | ConvertTo-Json -Depth 6) | Out-Null }
        catch { Write-Warning "[scheduler] SchedulerTriggers did NOT persist ($($_.Exception.Message)). A requested run will not fire." }
    }
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
        Write-Warning (("[scheduler] REFUSING to take the lease under the non-identifying owner '{0}'. " -f $Owner) +
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
function Invoke-PimSchedulerTriggerDrain {
    # The tick's "(b) TRIGGERS" block, unchanged in behaviour, made callable so the tick can also drain
    # BETWEEN scheduled jobs. Runs every pending trigger (running record -> dispatch -> run record, with the
    # trigger/reason members), then removes ONLY the triggers that ran. Emits the result objects -- and
    # nothing else, so a caller can collect the output straight into its results list.
    param([datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $now = $NowUtc
    $out = New-Object System.Collections.Generic.List[object]
    $triggers = @(Get-PimPendingTriggers)
    if ($triggers.Count) {
        foreach ($tg in $triggers) {
            $tjob = [pscustomobject]@{ name = "trigger:$($tg.type):$($tg.scope)"; type = "$($tg.type)"; scope = "$($tg.scope)"; enabled = $true }
            $started = [datetime]::UtcNow
            $tRunId = [guid]::NewGuid().ToString('N')
            if (-not $WhatIf) { [void](Write-PimJobRunningRecord -Job $tjob -RunId $tRunId -StartedUtc $started -Trigger -Reason "$($tg.reason)") }
            $r = Invoke-PimScheduledJob -Job $tjob -NowUtc $now -WhatIf:$WhatIf -CorrelationId $tRunId
            $r | Add-Member -NotePropertyName trigger -NotePropertyValue $true -Force
            $r | Add-Member -NotePropertyName reason  -NotePropertyValue "$($tg.reason)" -Force
            $out.Add($r)
            Write-PimJobRunRecord -Job $tjob -Result $r -StartedUtc $started -Trigger -Reason "$($tg.reason)" -RunId $tRunId | Out-Null
        }
        # 🔴 §70.19: this was `Save-PimJobTriggers -Triggers @()` -- it cleared EVERY trigger, including one
        # queued while these ran (a trigger run takes minutes; the Manager's "Run now" now queues here), so
        # a request made mid-run vanished. Remove only what was actually run (type + scope + requestedUtc).
        $ranKeys = @{}
        foreach ($tg in $triggers) { $ranKeys["$($tg.type)|$($tg.scope)|$($tg.requestedUtc)"] = $true }
        $still = @(@(Get-PimPendingTriggers) | Where-Object { -not $ranKeys.ContainsKey("$($_.type)|$($_.scope)|$($_.requestedUtc)") })
        [void](Save-PimJobTriggers -Triggers $still)
    }
    return $out.ToArray()
}

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
            Write-Host "[scheduler] owner '$Owner' identifies no instance -- skipping tick rather than holding a lease nobody can own" -ForegroundColor Red
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
                    Write-Host "[scheduler]   ^ that owner is non-identifying -- a leftover from a pre-build. It expires at its TTL; no action needed." -ForegroundColor DarkYellow
                }
                return @([pscustomobject]@{ name = 'lease'; type = 'lease'; ok = $true; ran = $false
                                            detail = "skipped: lease held by '$($seen.owner)'" })
            }
            Write-Host "[scheduler] lease NOT acquired and the store shows NO lease -- skipping tick (this is a store/write fault, not contention)" -ForegroundColor Red
            return @([pscustomobject]@{ name = 'lease'; type = 'lease'; ok = $false; ran = $false
                                        detail = 'skipped: lease could not be acquired and no lease is held -- the store did not accept the write' })
        }
        # §70.18: holding the lease means no other runner is mid-job, so a scheduler 'running' record older than
        # the lease TTL belongs to a tick that died (container timeout / restart). Close it as interrupted
        # rather than showing "running" forever.
        if (-not $WhatIf) { [void](Close-PimStaleRunningRecords -NowUtc $now -OlderThanMinutes ([Math]::Max(30, 2 * $LeaseTtlMinutes))) }
    }
    # In-job heartbeat. Renewing only BETWEEN jobs was not enough: on internal (2026-09-13) one
    # engine job spent 23 minutes in GroupsPolicies, the 15-minute lease lapsed, and the next
    # cron tick started writing alongside it. The engine calls Invoke-PimSchedulerLeaseHeartbeat
    # while it applies items; it is a no-op outside a leased tick.
    if ($haveLease) {
        $global:PIM_LeaseHeartbeat = [pscustomobject]@{ owner = $Owner; ttl = $LeaseTtlMinutes; lastUtc = $now; lost = $false }
    }
    try {
    # Hydrate JobSchedule + EmailControls from pim.Settings ONCE so even a one-shot
    # (-Once) cold tick honours the GUI-persisted cadence + email controls, not the
    # in-process default. Fail-safe / no-op when no store is configured.
    [void](Import-PimSchedulerSettingsFromStore)
    # BUG-112: publish THIS worker's job scope so the Manager (a different process, here a
    # different machine) can show which jobs this deployment actually runs, instead of judging
    # every job by a last-run record that may be 24h old.
    Save-PimJobScopeToStore -Scope @(Get-PimJobScope)
    # The tick's own clock, offset by real elapsed time, gives each job's ACTUAL start: the real
    # start in production, and deterministic when a test injects -NowUtc.
    $wallStart = [datetime]::UtcNow
    if (-not $Jobs) {
        # 🔴 This used to be `state.jobs` whenever state existed -- i.e. always after the first tick --
        # so no cadence change ever reached the runner. The EFFECTIVE schedule decides what runs and
        # how often; state supplies only last/next-run stamps. See Resolve-PimSchedulerJobs.
        $st = Get-PimSchedulerState
        $stJobs = @(); if ($st -and $st.PSObject.Properties['jobs'] -and $st.jobs) { $stJobs = @($st.jobs) }
        $Jobs = @(Resolve-PimSchedulerJobs -Schedule @(Get-PimJobSchedule) -StateJobs $stJobs -NowUtc $now)
    }
    # BUG-134: the RESOLVED list is what runs -- check THAT, not the shipped default (once/process).
    Write-PimJobScopeBindingReport -Schedule @($Jobs)
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
    $sqlCs = $null
    if (Get-Command Invoke-PimSqlChangeDetector -ErrorAction SilentlyContinue) {
        if ("$($global:PIM_SqlConnectionString)".Trim()) { $sqlCs = "$($global:PIM_SqlConnectionString)" }
        elseif ((Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) -and ("$($global:PIM_SqlServer)".Trim() -or "$($global:PIM_SqlConnStringVault)".Trim())) {
            try { $sqlCs = Get-PimSqlConnectionString } catch { $sqlCs = $null }
        }
        if ($sqlCs) { try { [void](Invoke-PimSqlChangeDetector -ConnectionString $sqlCs -Scope 'All' -Reason 'sql-change') } catch { } }
    }

    # IN-TICK PICKUP (operator 2026-09-13: "why 20 min ... we need things as fast as possible"). Triggers and
    # committed queue actions used to be read ONLY at the start of the tick, so a commit made while (c) ran its
    # 5-10 minutes of scheduled jobs waited for the whole tick AND the next cron start. After each scheduled
    # job we now repeat the cheap part: the SQL change detector (two small aggregate queries), a committed
    # queue-action check, and the trigger drain. Every step is guarded -- a failure here never breaks the tick.
    $qaJob = @(@($Jobs) | Where-Object { $_ -and "$($_.type)" -eq 'queue-apply' -and $_.enabled -ne $false })
    $qaJob = if ($qaJob.Count) { $qaJob[0] } else { $null }
    $qaSeen = @{}   # queue entry ids already run between jobs this tick -- never re-run the same entry in a loop
    # 🔴 §70.22 (measured 2026-09-14 07:20Z): a queued TAP re-issue + session revoke committed at 07:20 waited for a
    # `trigger:engine-delta:All` that had started at 07:17 -- ONE job, many scopes, so "between jobs" never came.
    # Queue actions do not depend on engine state, so the engine now calls this between its SCOPES as well
    # ($global:PIM_BetweenScopesHook, Invoke-PimEngine). Queue actions ONLY -- never a nested engine run.
    $queuePickup = {
        $n = 0
        if ($qaJob -and $sqlCs -and (Get-Command Get-PimSqlQueue -ErrorAction SilentlyContinue)) {
            $fresh = @()
            try {
                $fresh = @(@(Get-PimSqlQueue -ConnectionString $sqlCs -Status 'committed') | Where-Object {
                    $_ -and [int]"$(if ($_.PSObject.Properties['attempts']) { $_.attempts } else { 0 })" -eq 0 -and -not $qaSeen.ContainsKey("$($_.id)") })
            } catch { $fresh = @() }
            if ($fresh.Count -ge 1) {
                foreach ($fe in $fresh) { $qaSeen["$($fe.id)"] = $true }
                try {
                    $qStarted = [datetime]::UtcNow
                    $qRunId = [guid]::NewGuid().ToString('N')
                    [void](Write-PimJobRunningRecord -Job $qaJob -RunId $qRunId -StartedUtc $qStarted)
                    $qRes = Invoke-PimScheduledJob -Job $qaJob -NowUtc $now -CorrelationId $qRunId
                    $results.Add($qRes)
                    Write-PimJobRunRecord -Job $qaJob -Result $qRes -StartedUtc $qStarted -RunId $qRunId | Out-Null
                    $n++
                } catch { Write-Warning "[scheduler] in-run queue-apply pickup failed: $($_.Exception.Message)" }
            }
        }
        $n
    }
    if (-not $WhatIf) {
        # NO GetNewClosure: a closure is bound to a new module and cannot see functions dot-sourced into a SCRIPT scope (the scheduler
        # entry point and every test do exactly that). The hook runs INSIDE this tick's call stack, so dynamic scoping resolves
        # $queuePickup / $qaJob / $sqlCs / $results; outside a tick it is cleared (finally below) and would fail harmlessly anyway.
        $global:PIM_BetweenScopesHook = {
            $k = 0; try { $k = [int](@(& $queuePickup) | Select-Object -Last 1) } catch { $k = 0 }
            if ($k -gt 0) { Write-Host "[scheduler] applied $k committed queue action(s) between engine scopes" -ForegroundColor Cyan }
        }
    }

    # (b) TRIGGERS: run on-demand requests NOW (event-driven), then clear them.
    # Invoke-PimSchedulerTriggerDrain is this block, moved verbatim so (c) can call it between jobs.
    foreach ($tr in @(Invoke-PimSchedulerTriggerDrain -NowUtc $now -WhatIf:$WhatIf)) { if ($null -ne $tr) { $results.Add($tr) } }

    $interJobPickup = {
        $picked = 0
        if ($sqlCs -and (Get-Command Invoke-PimSqlChangeDetector -ErrorAction SilentlyContinue)) {
            try { [void](Invoke-PimSqlChangeDetector -ConnectionString $sqlCs -Scope 'All' -Reason 'sql-change') } catch { }
        }
        # committed queue actions (not yet attempted; retrying ones keep queue-apply's cadence + backoff) -- see $queuePickup
        try { $picked += [int](@(& $queuePickup) | Select-Object -Last 1) } catch { }
        try {
            foreach ($tr in @(Invoke-PimSchedulerTriggerDrain -NowUtc $now)) { if ($null -ne $tr) { $results.Add($tr); $picked++ } }
        } catch { Write-Warning "[scheduler] in-tick trigger drain failed: $($_.Exception.Message)" }
        $picked
    }

    # (c) SCHEDULED: run due jobs on their cadence; advance next-run.
    foreach ($j in @($Jobs)) {
        if (Test-PimJobDue -Job $j -NowUtc $now) {
            # The slot this run fills: the stored next-run, or this tick when it was never scheduled.
            $slot = $null
            if ($j.PSObject.Properties['nextRunUtc'] -and "$($j.nextRunUtc)".Trim()) { $slot = Get-PimUtcStamp $j.nextRunUtc }
            if ($null -eq $slot) { $slot = $now }
            $started  = [datetime]::UtcNow
            $jobStart = $now.Add($started - $wallStart)
            $jRunId = [guid]::NewGuid().ToString('N')
            if (-not $WhatIf) { [void](Write-PimJobRunningRecord -Job $j -RunId $jRunId -StartedUtc $started) }
            $res = Invoke-PimScheduledJob -Job $j -NowUtc $now -WhatIf:$WhatIf -CorrelationId $jRunId
            $results.Add($res)
            Write-PimJobRunRecord -Job $j -Result $res -StartedUtc $started -RunId $jRunId | Out-Null
            # 🔴 Both stamps used to be the TICK start. A tick runs its jobs in sequence, so a job
            # that started 13 minutes into the tick recorded a last run 13 minutes early, and its next
            # slot drifted with every long tick. lastRun = when THIS job started (what run history
            # records); next = anchored on the slot (Get-PimNextRunAfterRun).
            $nr = (Get-PimNextRunAfterRun -Job $j -ScheduledUtc $slot -StartedUtc $jobStart).ToString('o')
            $lr = $jobStart.ToString('o')
            if ($j.PSObject.Properties['nextRunUtc']) { $j.nextRunUtc = $nr } else { $j | Add-Member -NotePropertyName nextRunUtc -NotePropertyValue $nr -Force }
            if ($j.PSObject.Properties['lastRunUtc']) { $j.lastRunUtc = $lr } else { $j | Add-Member -NotePropertyName lastRunUtc -NotePropertyValue $lr -Force }
            # Renew mid-tick: a scheduled run can outlive the TTL (a full reconcile is not
            # quick), and a lapsed lease would let a second runner start while this one is
            # still writing. Renewal is half-TTL-gated, so this is not a per-job store write.
            if ($haveLease -and (Test-PimSchedulerLeaseRenewDue -Lease (Get-PimSchedulerLeaseRaw).Lease -NowUtc ([datetime]::UtcNow) -TtlMinutes $LeaseTtlMinutes)) {
                [void](Update-PimSchedulerLease -Owner $Owner -NowUtc ([datetime]::UtcNow) -TtlMinutes $LeaseTtlMinutes)
            }
            if (-not $WhatIf) {
                $pickedN = 0
                try { $pickedN = [int](@(. $interJobPickup) | Select-Object -Last 1) } catch { $pickedN = 0 }
                if ($pickedN -gt 0) {
                    Write-Host "[scheduler] picked up $pickedN trigger(s)/queue action(s) between jobs" -ForegroundColor Cyan
                    try {
                        if ($haveLease -and (Test-PimSchedulerLeaseRenewDue -Lease (Get-PimSchedulerLeaseRaw).Lease -NowUtc ([datetime]::UtcNow) -TtlMinutes $LeaseTtlMinutes)) {
                            [void](Update-PimSchedulerLease -Owner $Owner -NowUtc ([datetime]::UtcNow) -TtlMinutes $LeaseTtlMinutes)
                        }
                    } catch { }
                }
            }
        }
    }
    Save-PimSchedulerState -State ([pscustomobject]@{ jobs = @($Jobs); lastWatermark = $lastWm; updatedUtc = $now.ToString('o') })
    return $results.ToArray()
    }
    finally {
        # Release even when a job threw. A crash that leaves the lease held would block every
        # later run until the TTL expires -- for a cron deployment that is silent downtime.
        $global:PIM_LeaseHeartbeat = $null
        $global:PIM_BetweenScopesHook = $null
        if ($haveLease) { [void](Remove-PimSchedulerLease -Owner $Owner) }
    }
}

function Invoke-PimSchedulerLeaseHeartbeat {
    <#
      Renew the tick's lease from INSIDE a long job. Time-gated in memory (a third of the TTL
      since the last renewal), so calling it once per applied item costs nothing between
      renewals. Returns $false only when the lease is known LOST (someone else holds it), so a
      caller can stop writing; $true otherwise, including when no leased tick is running.
    #>
    [CmdletBinding()]
    param([datetime]$NowUtc = [datetime]::UtcNow)
    $hb = $global:PIM_LeaseHeartbeat
    if ($null -eq $hb) { return $true }
    if ($hb.lost) { return $false }
    $now = $NowUtc.ToUniversalTime()
    $gap = [math]::Max(1, [int]$hb.ttl / 3)
    if (($now - [datetime]$hb.lastUtc).TotalMinutes -lt $gap) { return $true }
    $ok = $false
    try { $ok = [bool](Update-PimSchedulerLease -Owner $hb.owner -NowUtc $now -TtlMinutes $hb.ttl) } catch { $ok = $false }
    if ($ok) { $hb.lastUtc = $now; return $true }
    # Could not renew. Only call it lost when the store shows another owner; a transient store
    # error must not stop a run that still holds a valid lease.
    $seen = $null; try { $seen = (Get-PimSchedulerLeaseRaw).Lease } catch { }
    if ($seen -and "$($seen.owner)" -ne "$($hb.owner)") {
        $hb.lost = $true
        Write-Warning ("[scheduler] lease LOST mid-job to '{0}' -- this run stops applying further items." -f $seen.owner)
        return $false
    }
    return $true
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
    # BUG-134: prove every engine job binds to a provider BEFORE the first tick, against the
    # hydrated (stored) schedule -- so an environment carrying broken scope names says so at
    # startup instead of reporting green ticks for jobs that cannot do anything.
    Write-PimJobScopeBindingReport -Schedule @(Get-PimJobSchedule)
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
