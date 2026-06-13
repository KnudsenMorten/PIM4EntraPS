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
$script:PimJobTypes    = @('queue-apply','engine-delta','engine-full','msp-pull','reminders','escalations','discovery')
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
        [pscustomobject]@{ name='full-reconcile';     type='engine-full';  scope='All';      intervalMinutes=1440; enabled=$true  }
        [pscustomobject]@{ name='msp-pull';           type='msp-pull';        intervalMinutes=240;  enabled=$false }  # MSP deployments only
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

function Initialize-PimDefaultJobHandlers {
    # Wire handlers to the EXISTING logic where it's present; otherwise a clearly
    # logged no-op stub (so a tick never crashes and the gap is visible). Real engine
    # handlers are registered by the launcher/container as the REST engine matures.
    Register-PimJobHandler -Type 'reminders' -Handler {
        param($job,$now,$whatIf)
        if (Get-Command Get-PimUpcomingExpirations -ErrorAction SilentlyContinue) {
            $items = @(); if ($global:PIM_LifecycleItems) { $items = @($global:PIM_LifecycleItems) }
            $up = @(Get-PimUpcomingExpirations -Items $items -NowUtc $now)
            return [pscustomobject]@{ ran=$true; detail="upcoming=$($up.Count)"; whatIf=[bool]$whatIf }
        }
        return [pscustomobject]@{ ran=$false; detail='no-handler:Get-PimUpcomingExpirations' }
    }
    Register-PimJobHandler -Type 'escalations' -Handler {
        param($job,$now,$whatIf)
        if (Get-Command Get-PimDueEscalation -ErrorAction SilentlyContinue) {
            return [pscustomobject]@{ ran=$true; detail='escalation-scan'; whatIf=[bool]$whatIf }
        }
        return [pscustomobject]@{ ran=$false; detail='no-handler:Get-PimDueEscalation' }
    }
    Register-PimJobHandler -Type 'queue-apply' -Handler {
        param($job,$now,$whatIf)
        if (Get-Command Get-PimQueueApplyPlan -ErrorAction SilentlyContinue) {
            return [pscustomobject]@{ ran=$true; detail='queue-apply-plan'; whatIf=[bool]$whatIf }
        }
        return [pscustomobject]@{ ran=$false; detail='no-handler:Get-PimQueueApplyPlan' }
    }
    foreach ($t in 'engine-delta','engine-full','msp-pull','discovery') {
        Register-PimJobHandler -Type $t -Handler {
            param($job,$now,$whatIf)
            # The container/launcher registers the real engine handler; until then,
            # the runner records intent (incl. the -Scope phase) rather than touching the
            # legacy entrypoints. Real handler: PIM-Engine -Scope $job.scope -Mode Delta.
            $scope = if ($job.PSObject.Properties['scope']) { "$($job.scope)" } else { 'All' }
            [pscustomobject]@{ ran=$false; detail="stub:$($job.type) scope=$scope (register a real handler)"; whatIf=[bool]$whatIf }
        }
    }
}

function Invoke-PimScheduledJob {
    param([Parameter(Mandatory)][object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $h = Get-PimJobHandler -Type "$($Job.type)"
    if (-not $h) { return [pscustomobject]@{ name="$($Job.name)"; type="$($Job.type)"; ok=$false; detail='no-handler-registered'; ranUtc=$NowUtc.ToString('o') } }
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

    # (b) TRIGGERS: run on-demand requests NOW (event-driven), then clear them.
    $triggers = @(Get-PimPendingTriggers)
    if ($triggers.Count) {
        foreach ($tg in $triggers) {
            $tjob = [pscustomobject]@{ name = "trigger:$($tg.type):$($tg.scope)"; type = "$($tg.type)"; scope = "$($tg.scope)"; enabled = $true }
            $r = Invoke-PimScheduledJob -Job $tjob -NowUtc $now -WhatIf:$WhatIf
            $r | Add-Member -NotePropertyName trigger -NotePropertyValue $true -Force
            $r | Add-Member -NotePropertyName reason  -NotePropertyValue "$($tg.reason)" -Force
            $results.Add($r)
        }
        Save-PimJobTriggers -Triggers @()
    }

    # (c) SCHEDULED: run due jobs on their cadence; advance next-run.
    foreach ($j in @($Jobs)) {
        if (Test-PimJobDue -Job $j -NowUtc $now) {
            $res = Invoke-PimScheduledJob -Job $j -NowUtc $now -WhatIf:$WhatIf
            $results.Add($res)
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
