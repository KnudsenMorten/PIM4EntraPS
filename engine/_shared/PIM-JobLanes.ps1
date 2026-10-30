<#
  PIM4EntraPS -- job LANES: per-area locks instead of one tick-wide lease (REQUIREMENTS §95.2o, operator 2026-10-07).

  Measured on a customer environment 2026-10-07: the whole tick ran under ONE lease, so a 30-minute full reconcile made
  every 5-minute tick skip ("another runner holds the lease"), a "Run now" pressed meanwhile waited the whole time, and a
  job that had failed BEFORE the fix stayed red while the fix ran. Operator: "why can we only have one job run at the same
  time, it makes no sense" / "i wi let you decide what to build".

  What this file decides:
    * AREAS -- what a job writes. Every engine scope belongs to ONE area (groups / admins / entra-roles / policies / azure /
      workloads / reviews); the other jobs that write the tenant name theirs; every job also holds 'job:<name>' so the same
      job never runs twice at once. Two runs on the same area never run side by side; runs on different areas do.
    * LOCKS -- one pim.Settings row ('SchedulerLocks', per scheduler instance) holding { areas: { <area>: { owner, job,
      runId, acquiredUtc, expiresUtc, execution } } }, changed only by a compare-and-set (like the trigger list). A lock
      expires at its TTL unless the run renews it (the engine's per-item heartbeat does). A lock whose execution the
      platform reports ENDED is taken over at once (the BUG-268 rule, per area).
    * CAP -- at most $script:PimLaneCapDefault runs side by side (Graph throttling, CPU, SQL); PIM_SCHED_MAX_PARALLEL (1-8).
    * A multi-area engine run (the daily full reconcile, a trigger over 'All') holds only 'job:<name>' plus the ONE area
      of the scope it is on: the engine asks the scope gate before each scope (Invoke-PimScopeGate).
    * The EXECUTION TIME LIMIT -- a job that will not fit in what is left of this execution waits for the next one instead
      of being killed half-way (which is what left runs 'running' until a later tick closed them as interrupted).
    * Why a run was INTERRUPTED (Get-PimInterruptedRunVerdict): an update restart or a platform stop is not a product
      failure; a crash or a time-limit kill is. An execution that ended Succeeded without the run's result (RUN-NO-RESULT,
      PIM 100.143) is interrupted: once is not a failure, twice in a row is.

  Every pure function takes its inputs as parameters (time injected) and is tested offline: tests/Test-PimJobLanes.ps1.
#>

Set-StrictMode -Off

$script:PimLocksSettingName      = 'SchedulerLocks'
$script:PimLocksMemory           = $null     # in-memory lock document (one process: tests, a single local tick)
$script:PimLaneCapDefault        = 4
$script:PimScopeGateWaitSeconds  = 900       # how long a multi-area run waits for the area its next scope needs
$script:PimScopeGatePollSeconds  = 10
$script:PimLockGraceMinutes      = 3         # a 'running' record whose owner holds no lock is closed after this
$script:PimHeldAreas             = @{}       # area -> runId, held by THIS process
$script:PimExecStatusCache       = @{}       # execution -> platform status, per tick
$script:PimDeadLockOwners        = @{}       # owner -> @{ execution; status } taken over this tick
$script:PimScopeGateCtx          = $null
# PIM 100.166 (c) NO-PROGRESS REPORT (owner 2026-10-15 via SI: "report on no progress, keep running"; "a log gap is not a
# hang" -- logs lag 10-20 min and some reads are silent ~25 min). A live run whose progress mark has not moved for this long
# is REPORTED once per stall (Jobs page line + one warning mail, debounced a day); it is never stopped or failed.
$script:PimNoProgressMinutes     = 60

# One area per engine scope (provider scope, lower case). A scope missing here is its own area 'engine:<scope>' -- never
# shared with anything, so an unknown provider can never run beside the provider it might collide with... except itself.
$script:PimEngineScopeAreas = [ordered]@{
    'administrativeunits' = 'groups'; 'groups' = 'groups'; 'administrativeunitmembers' = 'groups'; 'groupowners' = 'groups'
    'groupmembers' = 'groups'; 'groupretirement' = 'groups'
    'admins' = 'admins'; 'admintap' = 'admins'; 'adminmembers' = 'admins'; 'adminoffboarding' = 'admins'; 'hybridadprovisioning' = 'admins'
    'entraroles' = 'entra-roles'; 'rolesaus' = 'entra-roles'; 'entrarolesdirect' = 'entra-roles'
    'groupspolicies' = 'policies'; 'entrarolepolicies' = 'policies'
    'azres' = 'azure'; 'azrespolicies' = 'azure'
    'defenderxdrroles' = 'workloads'; 'intuneroles' = 'workloads'; 'entraapprole' = 'workloads'; 'workloadconnectors' = 'workloads'
    'accessreviews' = 'reviews'
}
# The shipped scope GROUPS (Get-PimEngineScopeAliasMap), for a process that has not loaded the engine (the Manager).
$script:PimScopeGroupAreas = @{
    'adminaccounts' = @('admins'); 'entraroleassignments' = @('entra-roles'); 'pimpolicies' = @('policies')
    'groupscreatemodifypolicy' = @('groups'); 'groupsassignment' = @('groups'); 'workloads' = @('workloads')
}
# Jobs that are not engine runs but WRITE something an engine area owns, or must never overlap another writer.
$script:PimJobTypeAreas = @{
    'emergency-override' = @('policies')        # turns approval off / restores it on group policies
    'queue-apply'        = @('queue')           # committed queue actions (TAP re-issue, revoke, ...)
    'servicenow-intake'  = @('queue')
    'msp-pull'           = @('msp')
    'rfa-sync'           = @('admins')          # RFA windows: admin access on / off
    'company-review'     = @('admins')          # consultant lifecycle
    'access-review-cycle'= @('reviews')
    'hybrid-ad-apply'    = @('hybrid-ad'); 'hybrid-ad-groups' = @('hybrid-ad'); 'hybrid-ad-sync' = @('hybrid-ad'); 'hybrid-ad-changes' = @('hybrid-ad')
    'hybrid-ad-servers'  = @('hybrid-servers'); 'hybrid-ad-sync-servers' = @('hybrid-servers')
}
# Jobs page groups (operator 2026-10-07: "if the gui layout for the job queue can be improved").
$script:PimJobGroupByType = @{
    'engine-delta' = 'Engine'; 'engine-full' = 'Engine'; 'queue-apply' = 'Engine'; 'emergency-override' = 'Engine'; 'msp-pull' = 'Engine'
    'hybrid-ad-apply' = 'Engine'; 'hybrid-ad-groups' = 'Engine'; 'hybrid-ad-sync' = 'Engine'; 'hybrid-ad-changes' = 'Engine'
    'hybrid-ad-servers' = 'Engine'; 'hybrid-ad-sync-servers' = 'Engine'; 'rfa-sync' = 'Engine'
    'reminders' = 'Reports'; 'escalations' = 'Reports'; 'daily-summary' = 'Reports'; 'tier-report' = 'Reports'
    'owner-review' = 'Reports'; 'autoextend-report' = 'Reports'; 'mgmt-report' = 'Reports'; 'coverage' = 'Reports'; 'target-check' = 'Reports'; 'pending-check' = 'Reports'; 'workload-prereqs' = 'Reports'; 'policy-defaults' = 'Reports'
    'licence-request' = 'Updates'; 'licence-check' = 'Updates'; 'uplink' = 'Updates'; 'install-key' = 'Updates'; 'enrolled-tenants' = 'Updates'
}

function Get-PimJobGroup {
    # PURE. Engine / Maintenance / Reports / Updates -- the section of the Jobs page a job type is listed under.
    param([string]$Type)
    $t = "$Type".Trim().ToLowerInvariant()
    if ($script:PimJobGroupByType.ContainsKey($t)) { return $script:PimJobGroupByType[$t] }
    return 'Maintenance'
}

function Get-PimEngineScopeArea {
    # PURE. The area one engine scope writes.
    param([string]$Scope)
    $k = "$Scope".Trim().ToLowerInvariant()
    if (-not $k) { return '' }
    if ($script:PimEngineScopeAreas.Contains($k)) { return $script:PimEngineScopeAreas[$k] }
    return "engine:$k"
}

function Get-PimJobAreas {
    <#
      PURE-ish (uses Resolve-PimEngineScope when the engine is loaded, else the shipped scope groups). What ONE job writes:
        @{ job = 'job:<name>'; areas = @(<area>...); perScope = <bool> }
      perScope: an engine run over more than one area takes them one at a time, as it reaches each scope.
    #>
    param([Parameter(Mandatory)][object]$Job)
    $name = "$($Job.name)".Trim(); $type = "$($Job.type)".Trim().ToLowerInvariant()
    $set = New-Object System.Collections.Generic.List[string]
    $add = { param($a) if ("$a".Trim() -and -not $set.Contains("$a")) { $set.Add("$a") } }
    if ($type -in @('engine-delta', 'engine-full')) {
        $keys = @()
        if (Get-Command Get-PimEngineJobScopeKeys -ErrorAction SilentlyContinue) { try { $keys = @(Get-PimEngineJobScopeKeys -Job $Job) } catch { $keys = @() } }
        if ($keys.Count) { foreach ($k in $keys) { & $add (Get-PimEngineScopeArea -Scope $k) } }
        else {
            $sc = if ($Job.PSObject.Properties['scope'] -and "$($Job.scope)".Trim()) { "$($Job.scope)" } else { 'All' }
            foreach ($p in @("$sc" -split ',')) {
                $pk = "$p".Trim().ToLowerInvariant(); if (-not $pk) { continue }
                if ($pk -eq 'all') { foreach ($v in @($script:PimEngineScopeAreas.Values | Select-Object -Unique)) { & $add $v } }
                elseif ($script:PimScopeGroupAreas.ContainsKey($pk)) { foreach ($v in $script:PimScopeGroupAreas[$pk]) { & $add $v } }
                else { & $add (Get-PimEngineScopeArea -Scope $pk) }
            }
        }
    } elseif ($script:PimJobTypeAreas.ContainsKey($type)) {
        foreach ($v in $script:PimJobTypeAreas[$type]) { & $add $v }
    }
    $areas = @($set.ToArray() | Sort-Object)
    return [pscustomobject]@{ job = "job:$name"; areas = $areas; perScope = [bool]($type -in @('engine-delta', 'engine-full') -and $areas.Count -gt 1) }
}

function Get-PimLaneCap {
    $c = 0
    if ([int]::TryParse("$($env:PIM_SCHED_MAX_PARALLEL)".Trim(), [ref]$c) -and $c -ge 1) { return [Math]::Min(8, $c) }
    return $script:PimLaneCapDefault
}

function Test-PimAreaLockLive {
    # PURE. A lock is live until its expiry. An expiry that cannot be READ is live (fail closed, the BUG-02 rule).
    param([object]$Lock, [Parameter(Mandatory)][datetime]$NowUtc)
    if (-not $Lock -or -not "$($Lock.owner)".Trim()) { return $false }
    $exp = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    $raw = if ($Lock.expiresUtc -is [datetime]) { $Lock.expiresUtc.ToUniversalTime().ToString('o') } else { "$($Lock.expiresUtc)" }
    if ([datetime]::TryParse($raw, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$exp)) { return ($NowUtc.ToUniversalTime() -lt $exp.ToUniversalTime()) }
    return $true
}

# ---- PIM 100.166 (c3): a lock past its TTL whose execution is still RUNNING is NOT dead --------------------------------
# With the 7-day run limit (framework 12.24) one step can be silent longer than the 15-min lock TTL -- one long SQL
# statement, a Graph page loop with no heartbeat in between. Before this, the next tick swept such a lock away, took its
# areas over and closed the run's 'running' record while the run was still working: two writers on one area.
# DESIGN (SI's rule, 2026-10-15: "heartbeat for dead, report for slow, a person for stop"): a lock whose TTL has passed is
# still HELD while the platform reports its execution Running / Processing (the per-tick cached execution-status read the
# lanes already use, Get-PimLockHolderStatus; the tick's identity holds 'Reader' on its own job, BUG-268). An execution
# that ENDED, or a status that cannot be read, keeps today's rule (the TTL decides). A slow run is never stopped here;
# the no-progress report (100.166 c) names it.
# WHY NOT a background heartbeat (a timer / runspace renewing the lock row during long calls): it adds a second writer
# with its own SQL token and connection racing the main thread's compare-and-set on the same row, and it would keep a
# truly HUNG process looking alive forever. The status guard is read-only, adds no writer, cannot deadlock, and it
# answers the actual question -- is that execution still there? -- instead of trusting a timer.
$script:PimLockAliveStatuses = @('Running', 'Processing')

function Test-PimAreaLockHeld {
    <#
      PURE. A lock is HELD when it is live by its TTL (Test-PimAreaLockLive), or -- past its TTL -- when the execution it
      names is in -AliveExecutions (execution name -> status, from Get-PimAliveExpiredExecutions). Without -AliveExecutions
      this is exactly Test-PimAreaLockLive.
    #>
    param([object]$Lock, [Parameter(Mandatory)][datetime]$NowUtc, [hashtable]$AliveExecutions = @{})
    if (Test-PimAreaLockLive -Lock $Lock -NowUtc $NowUtc) { return $true }
    if (-not $Lock -or -not "$($Lock.owner)".Trim() -or -not $AliveExecutions -or -not $AliveExecutions.Count) { return $false }
    $e = if ($Lock.PSObject.Properties['execution']) { "$($Lock.execution)".Trim() } else { '' }
    return [bool]($e -and $AliveExecutions.ContainsKey($e))
}

function Get-PimAliveExpiredExecutions {
    <#
      The executions named by locks that are PAST their TTL but whose execution the platform still reports Running /
      Processing: @{ <execution> = <status> }. -Status: param([string]$Execution) -> status ('' = unknown); default
      Get-PimLockHolderStatus (cached per tick, '' for this process's own execution). Never throws; unknown = not alive.
    #>
    param([System.Collections.IDictionary]$Map, [Parameter(Mandatory)][datetime]$NowUtc, [scriptblock]$Status)
    $out = @{}
    if ($null -eq $Map) { return $out }
    foreach ($k in @($Map.Keys)) {
        $l = $Map[$k]
        if (-not $l -or -not "$($l.owner)".Trim() -or (Test-PimAreaLockLive -Lock $l -NowUtc $NowUtc)) { continue }
        $e = if ($l.PSObject.Properties['execution']) { "$($l.execution)".Trim() } else { '' }
        if (-not $e -or $out.ContainsKey($e)) { continue }
        $st = ''
        try { $st = if ($Status) { "$(& $Status $e)".Trim() } else { "$(Get-PimLockHolderStatus -Execution $e)".Trim() } } catch { $st = '' }
        if ($st -in $script:PimLockAliveStatuses) { $out[$e] = $st }
    }
    return $out
}

function ConvertFrom-PimLocksJson {
    # The stored lock document -> an ordered hashtable area -> lock object. Accepts JSON text (once or twice encoded) or a parsed object.
    param([AllowNull()][object]$Value)
    $map = [ordered]@{}
    $o = $Value
    if ($o -is [string]) { $s = "$o".Trim(); if (-not $s) { return $map }; try { $o = $s | ConvertFrom-Json } catch { return $map }; if ($o -is [string]) { try { $o = $o | ConvertFrom-Json } catch { return $map } } }
    if ($null -eq $o -or -not $o.PSObject.Properties['areas'] -or $null -eq $o.areas) { return $map }
    foreach ($p in $o.areas.PSObject.Properties) { if ($p.Value) { $map[$p.Name] = $p.Value } }
    return $map
}

function ConvertTo-PimLocksJson {
    param([System.Collections.IDictionary]$Map)
    $o = [ordered]@{}
    foreach ($k in @($Map.Keys | Sort-Object)) { $o[$k] = $Map[$k] }
    return (ConvertTo-Json -InputObject ([pscustomobject]@{ areas = [pscustomobject]$o }) -Depth 6 -Compress)
}

function Get-PimSchedulerLocksRaw {
    # @{ Raw; Map; Backend = sql | read | memory; Cs; Name }. 'read' = no compare-and-set store in this process (a Manager
    # without SQL coordinates): the locks can be SHOWN, never written.
    $name = Get-PimSchedulerSettingName -Base $script:PimLocksSettingName
    $cs = Get-PimSchedulerLeaseStoreCs
    if ($cs -and (Get-Command Get-PimSqlSettingRaw -ErrorAction SilentlyContinue) -and (Get-Command Set-PimSqlSettingIfUnchanged -ErrorAction SilentlyContinue)) {
        try {
            $raw = Get-PimSqlSettingRaw -ConnectionString $cs -Name $name
            return @{ Raw = $raw; Map = (ConvertFrom-PimLocksJson -Value $raw); Backend = 'sql'; Cs = $cs; Name = $name }
        } catch { Write-Verbose "[lanes] lock read failed: $($_.Exception.Message)" }
    }
    if (-not $cs -and (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) -and -not "$($script:PimLocksMemory)".Trim()) {
        try { $v = Get-PimSetting -Name $name; if ($null -ne $v) { return @{ Raw = $null; Map = (ConvertFrom-PimLocksJson -Value $v); Backend = 'read'; Cs = $null; Name = $name } } } catch { }
    }
    return @{ Raw = $script:PimLocksMemory; Map = (ConvertFrom-PimLocksJson -Value $script:PimLocksMemory); Backend = 'memory'; Cs = $null; Name = $name }
}

function Update-PimSchedulerLocks {
    <#
      Change the lock document by ONE compare-and-set (retried). -Mutate gets (map, ctx), changes the map in place and
      returns $true to write ($false = nothing to write). Returns $true when the change landed (or none was needed), $false
      when it could not be written -- never a silent overwrite.
    #>
    param([Parameter(Mandatory)][scriptblock]$Mutate, [hashtable]$Ctx = @{}, [int]$Attempts = 8)
    for ($i = 0; $i -lt $Attempts; $i++) {
        $cur = Get-PimSchedulerLocksRaw
        if ($cur.Backend -eq 'read') { return $false }
        $map = $cur.Map
        $write = [bool](& $Mutate $map $Ctx)
        if (-not $write) { return $true }
        $json = ConvertTo-PimLocksJson -Map $map
        if ($cur.Backend -eq 'memory') { $script:PimLocksMemory = $json; return $true }
        $n = 0
        try { $n = Set-PimSqlSettingIfUnchanged -ConnectionString $cur.Cs -Name $cur.Name -NewValueJson $json -ExpectedValueJson $cur.Raw } catch { $n = 0 }
        if ($n -ge 1) { return $true }
        Start-Sleep -Milliseconds (40 * ($i + 1))
    }
    Write-Warning "[lanes] the job locks changed under every one of $Attempts attempts -- this change was NOT saved."
    return $false
}

function Get-PimLockHolderStatus {
    # The platform's status for the execution a lock names ('' = unknown). Cached per tick; never for this process's own execution.
    param([string]$Execution)
    $e = "$Execution".Trim()
    if (-not $e -or $e -eq (Get-PimSchedulerExecutionName)) { return '' }
    if ($script:PimExecStatusCache.ContainsKey($e)) { return $script:PimExecStatusCache[$e] }
    $s = ''
    try { $s = "$(Get-PimSchedulerExecutionStatus -ExecutionName $e)".Trim() } catch { $s = '' }
    $script:PimExecStatusCache[$e] = $s
    return $s
}

function Get-PimLockConflict {
    # PURE. The first lock in -Map on one of -Areas held by another run, or $null. Same owner + same run = no conflict.
    # PIM 100.166 (c3): -AliveExecutions -- a lock past its TTL whose execution is still Running counts as held.
    param([System.Collections.IDictionary]$Map, [string[]]$Areas, [string]$Owner, [string]$RunId = '', [Parameter(Mandatory)][datetime]$NowUtc,
          [hashtable]$AliveExecutions = @{})
    foreach ($a in @($Areas)) {
        if (-not $Map.Contains($a)) { continue }
        $l = $Map[$a]
        if (-not (Test-PimAreaLockHeld -Lock $l -NowUtc $NowUtc -AliveExecutions $AliveExecutions)) { continue }
        if ("$($l.owner)" -eq "$Owner" -and (-not "$RunId".Trim() -or -not "$($l.runId)".Trim() -or "$($l.runId)" -eq "$RunId")) { continue }
        return [pscustomobject]@{ area = "$a"; job = "$($l.job)"; owner = "$($l.owner)"; runId = "$($l.runId)"; sinceUtc = $(if ($l.acquiredUtc -is [datetime]) { $l.acquiredUtc.ToUniversalTime().ToString('o') } else { "$($l.acquiredUtc)" }); execution = "$($l.execution)" }
    }
    return $null
}

function Get-PimLiveLockOwners {
    # PURE. The distinct owners holding a live lock in -Map (PIM 100.166 c3: or a lock past its TTL whose execution is in
    # -AliveExecutions -- that owner's run is still working, its 'running' record must not be closed).
    param([System.Collections.IDictionary]$Map, [Parameter(Mandatory)][datetime]$NowUtc, [hashtable]$AliveExecutions = @{})
    $o = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($Map.Keys)) { $l = $Map[$k]; if ((Test-PimAreaLockHeld -Lock $l -NowUtc $NowUtc -AliveExecutions $AliveExecutions) -and -not $o.Contains("$($l.owner)")) { $o.Add("$($l.owner)") } }
    return @($o.ToArray())
}

function Request-PimAreaLocks {
    <#
      Take ALL of -Areas for one run, or none. Returns @{ ok; conflict; capReached; busy; error }.
      * a live lock of another run on one of the areas -> conflict (the job waits; nothing is taken)
      * a lock whose execution the platform reports ENDED is removed first (BUG-268 per area), its owner remembered so the
        tick closes that owner's 'running' records
      * -Cap > 0: refused while -Cap other owners already hold locks and this owner holds none (the lane cap)
    #>
    param([Parameter(Mandatory)][string]$Owner, [Parameter(Mandatory)][string[]]$Areas, [string]$Job = '', [string]$RunId = '',
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$TtlMinutes = 15, [int]$Cap = 0,
          # PIM 100.166 (c3) test seam: param([string]$Execution) -> the platform status; default Get-PimLockHolderStatus
          [scriptblock]$AliveStatus)
    $ctx = @{ ok = $false; conflict = $null; capReached = $false; busy = 0; error = '' }
    $ttl = [Math]::Max(1, $TtlMinutes)
    $wrote = Update-PimSchedulerLocks -Ctx $ctx -Mutate {
        param($map, $c)
        $c.ok = $false; $c.conflict = $null; $c.capReached = $false
        $changed = $false
        # PIM 100.166 (c3): a lock past its TTL is swept ONLY when its execution is not reported Running -- a silent long step
        # (one long SQL statement) keeps its areas; unknown status = today's TTL rule.
        $alive = Get-PimAliveExpiredExecutions -Map $map -NowUtc $NowUtc -Status $AliveStatus
        foreach ($k in @($map.Keys)) { if (-not (Test-PimAreaLockHeld -Lock $map[$k] -NowUtc $NowUtc -AliveExecutions $alive)) { $map.Remove($k); $changed = $true } }
        $conf = Get-PimLockConflict -Map $map -Areas $Areas -Owner $Owner -RunId $RunId -NowUtc $NowUtc -AliveExecutions $alive
        while ($conf -and "$($conf.execution)".Trim()) {
            $st = if ($AliveStatus) { try { "$(& $AliveStatus "$($conf.execution)")".Trim() } catch { '' } } else { Get-PimLockHolderStatus -Execution $conf.execution }
            if (-not (Test-PimSchedulerLeaseHolderGone -Lease ([pscustomobject]@{ execution = $conf.execution }) -Status $st)) { break }
            $dead = "$($conf.owner)"
            foreach ($k in @($map.Keys)) { if ("$($map[$k].owner)" -eq $dead) { $map.Remove($k) } }
            $script:PimDeadLockOwners[$dead] = @{ execution = "$($conf.execution)"; status = $st }
            $changed = $true
            $conf = Get-PimLockConflict -Map $map -Areas $Areas -Owner $Owner -RunId $RunId -NowUtc $NowUtc -AliveExecutions $alive
        }
        if ($conf) { $c.conflict = $conf; return $changed }
        if ($Cap -gt 0) {
            $others = @(Get-PimLiveLockOwners -Map $map -NowUtc $NowUtc -AliveExecutions $alive | Where-Object { $_ -ne $Owner })
            $mine = @($map.Keys | Where-Object { "$($map[$_].owner)" -eq $Owner }).Count
            if (-not $mine -and $others.Count -ge $Cap) { $c.capReached = $true; $c.busy = $others.Count; return $changed }
        }
        $exec = Get-PimSchedulerExecutionName
        foreach ($a in @($Areas)) {
            $l = [ordered]@{ owner = $Owner; job = $Job; runId = $RunId; acquiredUtc = $NowUtc.ToUniversalTime().ToString('o'); expiresUtc = $NowUtc.ToUniversalTime().AddMinutes($ttl).ToString('o') }
            if ($exec) { $l['execution'] = $exec }
            $map[$a] = [pscustomobject]$l
        }
        $c.ok = $true
        return $true
    }
    if (-not $wrote) { $ctx.ok = $false; if (-not $ctx.conflict -and -not $ctx.capReached) { $ctx.error = 'the job locks could not be written' } }
    if ($ctx.ok) { foreach ($a in @($Areas)) { $script:PimHeldAreas[$a] = $RunId } }
    return [pscustomobject]$ctx
}

function Remove-PimAreaLocks {
    # Release this owner's locks: all of them, those of -RunId, or only -Areas; -Except keeps the named ones.
    param([Parameter(Mandatory)][string]$Owner, [string]$RunId = '', [string[]]$Areas = @(), [string[]]$Except = @())
    $ok = Update-PimSchedulerLocks -Mutate {
        param($map, $c)
        $changed = $false
        foreach ($k in @($map.Keys)) {
            $l = $map[$k]
            if ("$($l.owner)" -ne $Owner) { continue }
            if ("$RunId".Trim() -and "$($l.runId)" -ne $RunId) { continue }
            if (@($Areas).Count -and $k -notin @($Areas)) { continue }
            if ($k -in @($Except)) { continue }
            $map.Remove($k); $changed = $true
        }
        return $changed
    }
    foreach ($k in @($script:PimHeldAreas.Keys)) {
        if ("$RunId".Trim() -and "$($script:PimHeldAreas[$k])" -ne $RunId) { continue }
        if (@($Areas).Count -and $k -notin @($Areas)) { continue }
        if ($k -in @($Except)) { continue }
        $script:PimHeldAreas.Remove($k)
    }
    return $ok
}

function Update-PimAreaLocks {
    # Renew every lock this owner holds. @{ ok; lost } -- lost = an area this process holds is now another owner's.
    # PIM 100.166 (c): -ProgressUtc = the run's last progress mark; written as 'progressUtc' on this owner's locks (never
    # moved back), so another execution can see a run that is alive but not moving.
    param([Parameter(Mandatory)][string]$Owner, [datetime]$NowUtc = [datetime]::UtcNow, [int]$TtlMinutes = 15,
          [AllowNull()][object]$ProgressUtc = $null)
    $prog = $null; if ($null -ne $ProgressUtc) { $prog = Get-PimNoProgressStamp $ProgressUtc }
    $ctx = @{ lost = @() }
    $ok = Update-PimSchedulerLocks -Ctx $ctx -Mutate {
        param($map, $c)
        $c.lost = @(); $changed = $false
        foreach ($a in @($script:PimHeldAreas.Keys)) {
            if ($map.Contains($a) -and "$($map[$a].owner)" -ne $Owner -and (Test-PimAreaLockLive -Lock $map[$a] -NowUtc $NowUtc)) { $c.lost += $a }
        }
        foreach ($k in @($map.Keys)) {
            $l = $map[$k]
            if ("$($l.owner)" -ne $Owner) { continue }
            $n = [ordered]@{}; foreach ($p in $l.PSObject.Properties) { $n[$p.Name] = $p.Value }
            $n['expiresUtc'] = $NowUtc.ToUniversalTime().AddMinutes([Math]::Max(1, $TtlMinutes)).ToString('o')
            if ($null -ne $prog) {
                $had = $null; if ($n.Contains('progressUtc')) { $had = Get-PimNoProgressStamp $n['progressUtc'] }
                if ($null -eq $had -or $prog -gt $had) { $n['progressUtc'] = $prog.ToString('o') }
            }
            $map[$k] = [pscustomobject]$n; $changed = $true
        }
        return $changed
    }
    return [pscustomobject]@{ ok = [bool]$ok; lost = @($ctx.lost) }
}

# ---- PIM 100.166 (c): the NO-PROGRESS report -- report, keep running ----------------------------------------------------
function Get-PimNoProgressStamp {
    # PURE. A lock time field (ISO text or [datetime]) -> UTC [datetime], or $null when it cannot be read.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse("$Value", [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d.ToUniversalTime() }
    return $null
}

function Get-PimRunProgressState {
    <#
      PURE. One live run, seen through its lock (any of its areas: they are renewed together). Its progress mark is the
      newer of 'progressUtc' (the engine's last item / page / scope, written at lock renewal) and 'acquiredUtc' (the start).
      @{ noProgress; sinceUtc; minutes; reportDue; text }:
        noProgress  the lock is live and the mark has not moved for -ThresholdMinutes or more
        reportDue   noProgress and this stall was not reported yet ('noProgressReportedUtc' older than the mark, or none)
      A lock that is not live (ended, expired) is never "no progress" -- the run is over, the report clears itself.
    #>
    # PIM 100.166 (c3): -AliveExecutions -- a lock past its TTL whose execution is still Running is a live run (a silent
    # long step is exactly the case to report).
    param([AllowNull()][object]$Lock, [Parameter(Mandatory)][datetime]$NowUtc, [int]$ThresholdMinutes = 0, [hashtable]$AliveExecutions = @{})
    $th = if ($ThresholdMinutes -gt 0) { $ThresholdMinutes } else { [int]$script:PimNoProgressMinutes }
    $out = [ordered]@{ noProgress = $false; sinceUtc = ''; minutes = 0; reportDue = $false; text = '' }
    if (-not $Lock -or -not (Test-PimAreaLockHeld -Lock $Lock -NowUtc $NowUtc -AliveExecutions $AliveExecutions)) { return [pscustomobject]$out }
    $acq = Get-PimNoProgressStamp $(if ($Lock.PSObject.Properties['acquiredUtc']) { $Lock.acquiredUtc })
    $prg = Get-PimNoProgressStamp $(if ($Lock.PSObject.Properties['progressUtc']) { $Lock.progressUtc })
    $mark = $acq; if ($null -ne $prg -and ($null -eq $mark -or $prg -gt $mark)) { $mark = $prg }
    if ($null -eq $mark) { return [pscustomobject]$out }
    $min = [int][Math]::Floor(($NowUtc.ToUniversalTime() - $mark).TotalMinutes)
    $out.sinceUtc = $mark.ToString('o'); $out.minutes = [Math]::Max(0, $min)
    if ($min -lt $th) { return [pscustomobject]$out }
    $out.noProgress = $true
    $rep = Get-PimNoProgressStamp $(if ($Lock.PSObject.Properties['noProgressReportedUtc']) { $Lock.noProgressReportedUtc })
    $out.reportDue = [bool]($null -eq $rep -or $rep -lt $mark)
    # One calm line (owner 2026-10-13): what, that nothing is wrong yet, that it clears itself.
    $out.text = "No progress for $min min -- the run keeps going; this clears itself when it moves on or ends."
    return [pscustomobject]$out
}

function Get-PimNoProgressRuns {
    <#
      PURE. The live runs in a lock map, one entry per run (owner + runId), each with its Get-PimRunProgressState.
      -ExceptOwner: leave this process's own runs out (a tick reports OTHER executions; its own run is busy, not stalled).
    #>
    param([System.Collections.IDictionary]$Map, [Parameter(Mandatory)][datetime]$NowUtc, [string]$ExceptOwner = '', [int]$ThresholdMinutes = 0,
          [hashtable]$AliveExecutions = @{})
    $seen = @{}; $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Map) { return @() }
    foreach ($k in @($Map.Keys | Sort-Object)) {
        $l = $Map[$k]
        if (-not $l -or -not (Test-PimAreaLockHeld -Lock $l -NowUtc $NowUtc -AliveExecutions $AliveExecutions)) { continue }
        if ("$ExceptOwner".Trim() -and "$($l.owner)" -eq "$ExceptOwner") { continue }
        $key = "$($l.owner)|$($l.runId)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $st = Get-PimRunProgressState -Lock $l -NowUtc $NowUtc -ThresholdMinutes $ThresholdMinutes -AliveExecutions $AliveExecutions
        $out.Add([pscustomobject]@{ owner = "$($l.owner)"; runId = "$($l.runId)"; job = ("$($l.job)" -replace '^job:', ''); area = "$k"; state = $st })
    }
    return @($out.ToArray())
}

function Invoke-PimNoProgressCheck {
    <#
      Once per tick: every OTHER live run whose progress has not moved for the threshold is REPORTED -- one log line and
      one warning mail (the job alert's warning class, Invoke-PimJobRunAlert: identical-alert debounce, a day) -- and the
      report is MARKED on that run's locks ('noProgressReportedUtc'), so the next ticks stay quiet until the run moves
      again (a new stall is a new report) or ends (its locks go, the report goes with them). NOTHING is stopped, failed,
      released or retried here. Never throws. Returns the runs it reported.
      -Alert: test seam, param($run) -- default Invoke-PimJobRunAlert.
    #>
    param([string]$Owner = '', [datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$Alert,
          # PIM 100.166 (c3): a run past its lock TTL whose execution is still Running is reported too (test seam: -AliveStatus)
          [scriptblock]$AliveStatus)
    $reported = New-Object System.Collections.Generic.List[object]
    try {
        $map = (Get-PimSchedulerLocksRaw).Map
        $alive = Get-PimAliveExpiredExecutions -Map $map -NowUtc $NowUtc -Status $AliveStatus
        $due = @(Get-PimNoProgressRuns -Map $map -NowUtc $NowUtc -ExceptOwner $Owner -AliveExecutions $alive | Where-Object { $_.state.reportDue })
        foreach ($r in $due) {
            # Mark first: a mark that cannot be written means another tick is reporting it (or the store is busy) -- no mail.
            $runKey = "$($r.owner)|$($r.runId)"
            $marked = Update-PimSchedulerLocks -Mutate {
                param($m, $c)
                $ch = $false
                foreach ($k in @($m.Keys)) {
                    $l = $m[$k]
                    if ("$($l.owner)|$($l.runId)" -ne $runKey) { continue }
                    $n = [ordered]@{}; foreach ($p in $l.PSObject.Properties) { $n[$p.Name] = $p.Value }
                    $n['noProgressReportedUtc'] = $NowUtc.ToUniversalTime().ToString('o')
                    $m[$k] = [pscustomobject]$n; $ch = $true
                }
                return $ch
            }
            if (-not $marked) { continue }
            Write-Host ("[scheduler] job '{0}' (run {1}): {2}" -f $r.job, $r.runId, $r.state.text) -ForegroundColor DarkYellow
            # The alert's summary is STABLE (no minutes, no times) so the day-long identical-alert debounce holds every repeat.
            $run = [pscustomobject]@{ name = $r.job; type = 'no-progress'; status = 'warning'; runId = $r.runId
                warningSummary = 'a run has made no progress for over an hour; it keeps running and nothing was stopped'
                detail = $r.state.text }
            try { if ($Alert) { [void](& $Alert $run) } elseif (Get-Command Invoke-PimJobRunAlert -ErrorAction SilentlyContinue) { [void](Invoke-PimJobRunAlert -Run $run) } }
            catch { Write-Verbose "[scheduler] no-progress alert: $($_.Exception.Message)" }
            $reported.Add($r)
        }
    } catch { Write-Verbose "[scheduler] no-progress check skipped: $($_.Exception.Message)" }
    return @($reported.ToArray())
}

function Get-PimJobLaneState {
    <#
      For the Manager (Jobs page, Run now): is this job free to start, or what is it waiting for?
      @{ conflict = @{ area; job; sinceUtc } | $null; capReached; busy; live = <owners> }. -Map: a lock map already read.
    #>
    param([Parameter(Mandatory)][object]$Job, [System.Collections.IDictionary]$Map, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Map) { $Map = (Get-PimSchedulerLocksRaw).Map }
    $a = Get-PimJobAreas -Job $Job
    $want = @($a.job) + $(if ($a.perScope) { @() } else { @($a.areas) })
    $conf = Get-PimLockConflict -Map $Map -Areas $want -Owner '' -NowUtc $NowUtc
    $live = @(Get-PimLiveLockOwners -Map $Map -NowUtc $NowUtc)
    $cap = Get-PimLaneCap
    return [pscustomobject]@{ conflict = $conf; capReached = [bool](-not $conf -and $live.Count -ge $cap); busy = $live.Count; cap = $cap; live = $live; areas = @($a.areas) }
}

function Get-PimCoveringCleanRun {
    <#
      PURE. A failed engine run is HEALED when a later CLEAN run -- of any job -- reconciled every scope the failed job runs,
      and started after the failed run ended (so it saw the state the failure left). Returns that run, or $null.
      Only records that carry 'scopes' (written since this build) can heal; a run that was not clean carries none.
    #>
    param([Parameter(Mandatory)][object]$FailedRun, [string[]]$ScopeKeys = @(), [object[]]$History = @())
    $want = @(@($ScopeKeys) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    if (-not $want.Count) { return $null }
    $fEnd = Get-PimUtcStamp $FailedRun.finishedUtc
    if ($null -eq $fEnd) { $fEnd = Get-PimUtcStamp $FailedRun.startedUtc }
    if ($null -eq $fEnd) { return $null }
    foreach ($h in @($History)) {
        if (-not $h -or "$($h.runId)" -eq "$($FailedRun.runId)") { continue }
        if ("$($h.status)" -ne 'completed' -or -not [bool]$h.ok) { continue }
        if (-not $h.PSObject.Properties['scopes']) { continue }
        $hs = @(@($h.scopes) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
        if (-not $hs.Count) { continue }
        $hStart = Get-PimUtcStamp $h.startedUtc
        if ($null -eq $hStart -or $hStart -lt $fEnd) { continue }
        if (@($want | Where-Object { $_ -notin $hs }).Count) { continue }
        return $h
    }
    return $null
}

# ---- the scope gate: a multi-area engine run holds ONE area at a time -------------------------------------------------
function Invoke-PimScopeGate {
    <#
      Called by Invoke-PimEngine before each scope ($global:PIM_ScopeGateHook). Holds the area this scope writes, releasing
      the area of the previous scope first, so the run never holds two areas and never waits while holding one (no
      deadlock). Waits up to $script:PimScopeGateWaitSeconds for an area another run holds; then the scope is reported NOT
      CHECKED (the run itself is not failed -- the next run does it). Returns @{ ok; detail }.
    #>
    param([Parameter(Mandatory)][string]$Scope)
    $g = $script:PimScopeGateCtx
    if (-not $g) { return [pscustomobject]@{ ok = $true; detail = '' } }
    $area = Get-PimEngineScopeArea -Scope $Scope
    if ($area -eq $g.current) { return [pscustomobject]@{ ok = $true; detail = '' } }
    if ($g.current) { [void](Remove-PimAreaLocks -Owner $g.owner -RunId $g.runId -Areas @($g.current)); $g.current = '' }
    $deadline = [datetime]::UtcNow.AddSeconds([Math]::Max(0, $script:PimScopeGateWaitSeconds))
    $said = $false
    while ($true) {
        $r = Request-PimAreaLocks -Owner $g.owner -Areas @($area) -Job $g.job -RunId $g.runId -NowUtc ([datetime]::UtcNow) -TtlMinutes $g.ttl
        if ($r.ok) { $g.current = $area; return [pscustomobject]@{ ok = $true; detail = '' } }
        $who = if ($r.conflict) { "$($r.conflict.job)" -replace '^job:', '' } else { 'the lock store' }
        if (-not $said) { Write-Host ("[lanes] {0}: scope {1} waits for {2} (area {3})" -f $g.job, $Scope, $who, $area) -ForegroundColor DarkYellow; $said = $true }
        if ([datetime]::UtcNow -ge $deadline) {
            return [pscustomobject]@{ ok = $false; detail = ("waited {0} min for {1} (area {2}); the next run checks it" -f [Math]::Round($script:PimScopeGateWaitSeconds / 60.0), $who, $area) }
        }
        try { [void](Invoke-PimSchedulerLeaseHeartbeat -Waiting) } catch { Write-Verbose "[lanes] heartbeat while waiting: $($_.Exception.Message)" }
        Start-Sleep -Seconds ([Math]::Max(1, $script:PimScopeGatePollSeconds))
    }
}

# ---- the execution time limit ----------------------------------------------------------------------------------------
function Get-PimSchedulerTimeLimitSeconds {
    # The tick job's replica timeout: PIM_SCHED_TIME_LIMIT_SECONDS, else the 7-day run limit inside a Container Apps job
    # execution (framework 12.24 JOB-RUN-LIMIT, owner 2026-10-15: no product-chosen cap -- the planner defers a job only when
    # it would not fit inside 7 days), else 0 = no limit (a VM / workstation loop).
    $v = 0
    if ([int]::TryParse("$($env:PIM_SCHED_TIME_LIMIT_SECONDS)".Trim(), [ref]$v) -and $v -gt 0) { return $v }
    if ((Get-PimSchedulerExecutionName)) { return 604800 }
    return 0
}

function Get-PimJobDurationEstimateSeconds {
    # PURE. How long this job's last finished run took (seconds); a full reconcile with no history is assumed 35 minutes.
    param([Parameter(Mandatory)][object]$Job, [object[]]$History = @())
    $n = "$($Job.name)"
    $last = @(@($History) | Where-Object { $_ -and "$($_.name)" -eq $n -and "$($_.status)" -in @('completed', 'held') -and $_.PSObject.Properties['durationMs'] } | Select-Object -First 1)
    if ($last.Count) { return [int][Math]::Ceiling([double]$last[0].durationMs / 1000.0) }
    if ("$($Job.type)" -eq 'engine-full') { return 2100 }
    return 0
}

function Test-PimJobFitsExecution {
    <#
      PURE. Does a job of -EstimateSeconds fit in what is left of this execution? A fresh execution (under 90 s in) always
      starts it -- a job longer than a whole execution must still run somewhere -- and no limit (0) means it always fits.
    #>
    param([int]$ElapsedSeconds, [int]$LimitSeconds, [int]$EstimateSeconds)
    if ($LimitSeconds -le 0) { return $true }
    if ($ElapsedSeconds -lt 90) { return $true }
    $need = [int][Math]::Ceiling($EstimateSeconds * 1.2) + 120
    return (($ElapsedSeconds + $need) -le $LimitSeconds)
}

# ---- why a run never reported back -----------------------------------------------------------------------------------
function Get-PimRunningVersion {
    if ($null -ne $script:PimRunningVersionCache) { return $script:PimRunningVersionCache }
    $v = ''
    try { $f = Join-Path $PSScriptRoot '..\..\VERSION'; if (Test-Path -LiteralPath $f) { $v = "$(Get-Content -Raw -LiteralPath $f)".Trim() } } catch { $v = '' }
    if (-not $v -and "$($env:PIM_VERSION)".Trim()) { $v = "$($env:PIM_VERSION)".Trim() }
    $script:PimRunningVersionCache = $v
    return $v
}

function Get-PimInterruptedRunVerdict {
    <#
      PURE. A 'running' record whose run will never report back: what happened, and is it a product failure?
      Returns @{ status = interrupted | failed; cause; detail }.
        update        -- the record was written by another VERSION: the scheduler restarted for an update. Not a failure.
        stopped       -- the platform reports the execution Stopped (a roll, a manual stop, a retry the platform removed).
        manager       -- a Run now inside the Manager, and the Manager restarted.
        time-limit    -- the execution Failed after running for the whole time limit: the job is longer than one execution.
        crashed       -- the execution Failed earlier (out of memory, a crash).
        unrecorded    -- the execution Succeeded but this run's result was never written. Failure class RUN-NO-RESULT
                         (PIM 100.143): 'interrupted', not 'failed' -- the job ran, only its record was lost (the run-history
                         write lost every compare-and-set to another execution), and the next turn runs it again. Like
                         'unknown': not counted as a failure once; two in a row are (Get-PimJobsStatus, the uplink).
        unknown       -- nothing says why. Not counted as a failure once; two in a row are (Get-PimJobsStatus).
    #>
    param([Parameter(Mandatory)][object]$Run, [string]$CurrentVersion = '', [string]$PlatformStatus = '', [string]$Execution = '',
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$TimeLimitSeconds = 0)
    $started = Get-PimUtcStamp $Run.startedUtc
    $at = if ($null -ne $started) { $started.ToString('HH:mm') + ' UTC' } else { "$($Run.startedUtc)" }
    $rv = if ($Run.PSObject.Properties['version']) { "$($Run.version)".Trim() } else { '' }
    $exec = if ("$Execution".Trim()) { "$Execution".Trim() } elseif ($Run.PSObject.Properties['execution']) { "$($Run.execution)".Trim() } else { '' }
    $execTxt = if ($exec) { " '$exec'" } else { '' }
    $ps = "$PlatformStatus".Trim()
    if ($rv -and "$CurrentVersion".Trim() -and $rv -ne "$CurrentVersion".Trim()) {
        return [pscustomobject]@{ status = 'interrupted'; cause = 'update'
            detail = "interrupted by the update to $($CurrentVersion.Trim()): the scheduler restarted while this run (started $at on $rv) was in progress. Nothing is wrong with the job; it runs again on its next turn." }
    }
    if ($ps -eq 'Stopped') {
        return [pscustomobject]@{ status = 'interrupted'; cause = 'stopped'
            detail = "interrupted: the platform stopped the execution$execTxt (an update roll or a manual stop) while this run (started $at) was in progress; it runs again on its next turn" }
    }
    if ($ps -eq 'Failed') {
        $ran = if ($null -ne $started) { ($NowUtc.ToUniversalTime() - $started).TotalSeconds } else { 0 }
        if ($TimeLimitSeconds -gt 0 -and $ran -ge ($TimeLimitSeconds - 60)) {
            return [pscustomobject]@{ status = 'failed'; cause = 'time-limit'
                detail = ("stopped at the execution time limit ({0} min): the run started {1} and took longer than one execution allows{2}" -f [Math]::Round($TimeLimitSeconds / 60.0), $at, $(if ($exec) { " ('$exec')" } else { '' })) }
        }
        return [pscustomobject]@{ status = 'failed'; cause = 'crashed'
            detail = "interrupted: the execution$execTxt ended in Failed while this run (started $at) was in progress -- its container stopped (out of memory or a crash); it runs again on its next turn" }
    }
    if ($ps -eq 'Succeeded') {
        # PIM 100.143: the [RUN-NO-RESULT] tag is the failure class (PIM-FailureCatalog.ps1) the uplink sends -- never UNCLASSIFIED.
        return [pscustomobject]@{ status = 'interrupted'; cause = 'unrecorded'
            detail = "the execution$execTxt finished without recording this run's result (started $at) [RUN-NO-RESULT]; it runs again on its next turn -- one such run is not a failure, two in a row show as failing" }
    }
    $own = if ($Run.PSObject.Properties['owner']) { "$($Run.owner)".Trim() } else { '' }
    if (-not $own -and "$($Run.reason)" -eq 'force-start') {
        return [pscustomobject]@{ status = 'interrupted'; cause = 'manager'
            detail = "interrupted: the Manager restarted while it ran this job (Run now, started $at); run it again" }
    }
    return [pscustomobject]@{ status = 'interrupted'; cause = 'unknown'
        detail = "interrupted: the run started $at and its execution ended before it reported back (no cause was recorded). It runs again on its next turn; two interruptions in a row show as failing." }
}

# ---- the run-history ring and the scheduler state, by compare-and-set ------------------------------------------------
# Runs now go side by side, so a read-modify-write of one pim.Settings value LOSES records: execution A reads the ring, B
# writes its finished run, A writes the ring it read -- B's result is gone and its 'running' record is back, to be closed
# later as "interrupted". Every change to these two values is therefore one compare-and-set on the SQL row.
function ConvertFrom-PimStoredJsonValue {
    param([AllowNull()][object]$Raw)
    if ($null -eq $Raw) { return $null }
    $s = "$Raw".Trim(); if (-not $s) { return $null }
    $o = $s | ConvertFrom-Json
    if ($o -is [string]) { $t = "$o".Trim(); if ($t.StartsWith('[') -or $t.StartsWith('{')) { $o = $t | ConvertFrom-Json } }
    return ,$o
}

function Get-PimCasStore {
    # @{ Cs } when this process can compare-and-set pim.Settings, else $null.
    # A connection string that comes from Key Vault (PIM_SqlConnStringVault) is kept for 10 minutes: the Jobs page reads
    # the ring, the state, the locks and the triggers per request, and each must not be a vault call.
    $cs = $null
    if (-not "$($global:PIM_SqlConnectionString)".Trim() -and "$($global:PIM_SqlConnStringVault)".Trim() -and $script:PimCasCsCache -and ([datetime]::UtcNow - $script:PimCasCsCache.at).TotalMinutes -lt 10) { $cs = $script:PimCasCsCache.cs }
    if (-not $cs) {
        $cs = Get-PimSchedulerLeaseStoreCs
        if ($cs -and "$($global:PIM_SqlConnStringVault)".Trim()) { $script:PimCasCsCache = @{ cs = $cs; at = [datetime]::UtcNow } }
    }
    if ($cs -and (Get-Command Get-PimSqlSettingRaw -ErrorAction SilentlyContinue) -and (Get-Command Set-PimSqlSettingIfUnchanged -ErrorAction SilentlyContinue)) { return @{ Cs = $cs } }
    return $null
}

function Update-PimCasSetting {
    <#
      Read -Name raw, hand the parsed value to -Mutate (it RETURNS the new value, or $null for "no change"), write it only if
      the row is unchanged since the read; retried. -Fallback supplies the current value when the row is empty (a value an
      older writer stored through Set-PimSetting). Returns @{ ok; value }.
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Mutate, [scriptblock]$Fallback, [int]$Attempts = 8, [int]$Depth = 10)
    $st = Get-PimCasStore
    if (-not $st) { return @{ ok = $false; value = $null; noStore = $true } }
    for ($i = 0; $i -lt $Attempts; $i++) {
        $raw = $null
        try { $raw = Get-PimSqlSettingRaw -ConnectionString $st.Cs -Name $Name } catch { Write-Warning "[scheduler] $Name could not be READ for an update ($($_.Exception.Message))"; return @{ ok = $false; value = $null } }
        $cur = $null
        if ("$raw".Trim()) { try { $cur = ConvertFrom-PimStoredJsonValue -Raw $raw } catch { $cur = $null } }
        elseif ($Fallback) { try { $cur = & $Fallback } catch { $cur = $null } }
        $new = & $Mutate $cur
        if ($null -eq $new) { return @{ ok = $true; value = $cur } }
        $json = ConvertTo-Json -InputObject $new -Depth $Depth -Compress
        if ("$raw" -eq $json) { return @{ ok = $true; value = $new } }
        $n = 0
        try { $n = Set-PimSqlSettingIfUnchanged -ConnectionString $st.Cs -Name $Name -NewValueJson $json -ExpectedValueJson $raw } catch { $n = 0 }
        if ($n -ge 1) { return @{ ok = $true; value = $new } }
        # PIM 100.143: a RANDOM part on top of the growing wait. Two executions that lost to each other used to wait exactly
        # the same 40/80/120... ms and collide again on every attempt (live 2026-10-14 07:05 UTC: two overlapping ticks,
        # the run-history ring changed under all 8 attempts and a finished run's record was lost).
        Start-Sleep -Milliseconds ((40 * ($i + 1)) + (Get-Random -Minimum 0 -Maximum (60 * ($i + 1))))
    }
    Write-Warning "[scheduler] $Name changed under every one of $Attempts attempts -- this change was NOT saved."
    return @{ ok = $false; value = $null }
}

function Merge-PimSchedulerStateJobs {
    <#
      PURE. The stored scheduler state with THIS execution's job stamps merged in: a job this execution RAN takes its own
      stamps; a job another execution ran later (newer lastRunUtc in the store) keeps the store's; jobs this execution did
      not list are kept. -LastWatermark '' keeps the stored one.
    #>
    param([AllowNull()][object]$Current, [object[]]$Jobs = @(), [string[]]$RanNames = @(), [string]$LastWatermark = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $byName = [ordered]@{}
    if ($Current -and $Current.PSObject.Properties['jobs'] -and $Current.jobs) { foreach ($c in @($Current.jobs)) { if ($c -and "$($c.name)".Trim()) { $byName["$($c.name)"] = $c } } }
    $ran = @{}; foreach ($n in @($RanNames)) { if ("$n".Trim()) { $ran["$n"] = $true } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($j in @($Jobs)) {
        if (-not $j) { continue }
        $n = "$($j.name)"; $c = if ($byName.Contains($n)) { $byName[$n] } else { $null }
        if ($ran.ContainsKey($n) -or -not $c) { $out.Add($j) }
        else {
            $cs = Get-PimUtcStamp $c.lastRunUtc; $js = Get-PimUtcStamp $j.lastRunUtc
            if ($null -ne $cs -and ($null -eq $js -or $cs -gt $js)) { $out.Add($c) } else { $out.Add($j) }
        }
        if ($byName.Contains($n)) { $byName.Remove($n) }
    }
    foreach ($k in @($byName.Keys)) { $out.Add($byName[$k]) }
    $wm = if ("$LastWatermark".Trim()) { "$LastWatermark" } elseif ($Current -and $Current.PSObject.Properties['lastWatermark']) { "$($Current.lastWatermark)" } else { '' }
    return [pscustomobject]@{ jobs = @($out.ToArray()); lastWatermark = $wm; updatedUtc = $NowUtc.ToUniversalTime().ToString('o') }
}

function Save-PimSchedulerJobStamps {
    # Persist the stamps of the jobs this execution ran (merged, compare-and-set). Without a CAS store: the old full save.
    param([object[]]$Jobs = @(), [string[]]$RanNames = @(), [string]$LastWatermark = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $name = Get-PimSchedulerSettingName -Base 'SchedulerState'
    $r = Update-PimCasSetting -Name $name -Fallback { $s = $script:PimSchedState; if ($null -eq $s -and (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) { try { $v = Get-PimSetting -Name $name; if ($v -is [string]) { $s = $v | ConvertFrom-Json } else { $s = $v } } catch { } }; $s } -Mutate {
        param($cur) Merge-PimSchedulerStateJobs -Current $cur -Jobs $Jobs -RanNames $RanNames -LastWatermark $LastWatermark -NowUtc $NowUtc }
    if ($r.noStore) {
        $merged = Merge-PimSchedulerStateJobs -Current (Get-PimSchedulerState) -Jobs $Jobs -RanNames $RanNames -LastWatermark $LastWatermark -NowUtc $NowUtc
        Save-PimSchedulerState -State $merged
        return $true
    }
    if ($r.ok -and $r.value) { $script:PimSchedState = $r.value }
    if (-not $r.ok) { Write-Warning "[scheduler] SchedulerState did NOT persist for $(@($RanNames) -join ', '). The job may look due on the next tick." }
    return [bool]$r.ok
}

# ---- PIM 100.166 (b) CANCEL THE RUNNING RUN (owner wizard 2026-10-15; SI #700's model) -----------------------------------
# "Heartbeat for dead, report for slow, a PERSON for stop" (framework 12.24): with a 7-day run limit nothing ever stops a
# slow run by the clock, so a person must be able to. A SuperAdmin presses "Cancel the running run" on the Jobs page: the
# platform stops the run's execution (ARM POST <job>/executions/<name>/stop), then its record becomes 'cancelled' -- FINAL:
# never closed as interrupted, never retried, never resumed, never counted as a failure (ok stays $true: nothing broke), and
# a late write by the dying run cannot turn it back (Add-PimJobRunRecord keeps a cancelled record). The job runs again on its
# next normal turn, as a NEW run. Other jobs of the same execution stop with it; the scheduler closes those the normal way
# (platform Stopped = interrupted, runs again). The Manager never runs the engine (section 22): it only asks the platform.
$script:PimJobCancelApi = '2024-03-01'

function Get-PimJobCancelTarget {
    <#
      PURE. Which run would "Cancel the running run" on -Name stop? -History: the run-history ring (any order).
      -TickJobId: the engine job's ARM resource id. Returns @{ ok; code; message; run; execution; jobId; jobName }.
        not-running    no 'running' record for the job
        no-execution   the run is not inside a Container Apps job execution (a VM / workstation loop) -- cannot be stopped here
        not-configured the engine job's resource id is unknown (SchedulerTickJobId / PIM_TickJobId)
        other-job      the execution belongs to another job than the engine job
        ok             the newest running record, its execution, and the job it runs in
    #>
    param([Parameter(Mandatory)][string]$Name, [object[]]$History = @(), [string]$TickJobId = '')
    $out = [ordered]@{ ok = $false; code = ''; message = ''; run = $null; execution = ''; jobId = ''; jobName = '' }
    $running = @(@($History) | Where-Object { $_ -and "$($_.name)" -eq "$Name" -and "$($_.status)" -eq 'running' -and -not "$($_.finishedUtc)".Trim() } |
        Sort-Object { "$($_.startedUtc)" } -Descending)
    if (-not $running.Count) { $out.code = 'not-running'; $out.message = "Nothing is running for $Name right now."; return [pscustomobject]$out }
    $run = $running[0]; $out.run = $run
    $exec = if ($run.PSObject.Properties['execution']) { "$($run.execution)".Trim() } else { '' }
    if (-not $exec) { $out.code = 'no-execution'; $out.message = "This run of $Name is not in a container job, so it cannot be stopped from here."; return [pscustomobject]$out }
    $out.execution = $exec
    if ("$TickJobId" -notmatch '(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.App/jobs/([^/]+)$') {
        $out.code = 'not-configured'; $out.message = 'The engine job is not known to this Manager (pim.Settings SchedulerTickJobId), so the run cannot be stopped from here.'
        return [pscustomobject]$out
    }
    $jn = $Matches[1]
    if ($exec -notmatch ('^(?i)' + [regex]::Escape($jn) + '-[a-z0-9]+$')) {
        $out.code = 'other-job'; $out.message = "This run of $Name runs in '$exec', not in the engine job $jn, so it cannot be stopped from here."
        return [pscustomobject]$out
    }
    $out.ok = $true; $out.code = 'ok'; $out.jobId = "$TickJobId"; $out.jobName = $jn
    return [pscustomobject]$out
}

function New-PimCancelledRunRecord {
    <# PURE. The 'running' record -Run as a FINAL 'cancelled' record: by whom, when, and why it is final. #>
    param([Parameter(Mandatory)][object]$Run, [string]$By = '', [datetime]$NowUtc = [datetime]::UtcNow, [string]$Note = '')
    $o = [ordered]@{}
    foreach ($p in @($Run.PSObject.Properties)) { $o[$p.Name] = $p.Value }
    $now = $NowUtc.ToUniversalTime()
    $who = if ("$By".Trim()) { "$By".Trim() } else { 'a SuperAdmin' }
    $st = Get-PimUtcStamp "$($Run.startedUtc)"
    $o['status'] = 'cancelled'
    $o['ok'] = $true                 # nothing broke: a person stopped it on purpose -- never a failed run
    $o['cancelled'] = $true
    $o['final'] = $true              # never retried, never resumed; the job's next normal turn is a NEW run
    $o['cancelledBy'] = $who
    $o['cancelledUtc'] = $now.ToString('o')
    $o['finishedUtc'] = $now.ToString('o')
    $o['durationMs'] = $(if ($null -ne $st) { [int64][Math]::Max([double]0, ($now - $st).TotalMilliseconds) } else { [int64]0 })
    $o['detail'] = ("cancelled by {0} at {1} UTC -- stopped on purpose; it is not retried and runs again only on its next normal turn{2}" -f $who, $now.ToString('HH:mm'), $(if ("$Note".Trim()) { ". $Note" } else { '' }))
    return [pscustomobject]$o
}

function Invoke-PimJobCancel {
    <#
      Cancel the running run of -Name. I/O injected:
        -Arm      param($Method, $Path) -> the ARM answer; THROWS on an HTTP error (the message carries the status)
        -History  the run-history ring (default: Get-PimJobRunHistory)
        -Job      the job's schedule entry (its interval) -- a scheduled run's next turn is set from it
      Order: the platform stops the execution FIRST; only a stop that landed (or an execution that had already ended, 404)
      makes the record 'cancelled' -- a refused stop changes nothing, so a run that keeps going is never shown cancelled.
      Then the cancelled run's area locks are released (its execution is gone). Never throws.
      Returns @{ ok; code; status; message; moreInfo; run; execution; alsoStopped[] }.
        code: cancelled | not-running | no-execution | not-configured | other-job | not-allowed | error | not-recorded
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Arm, [object[]]$History, [string]$TickJobId = '',
          [string]$By = '', [datetime]$NowUtc = [datetime]::UtcNow, [object]$Job)
    $res = [ordered]@{ ok = $false; code = ''; status = ''; message = ''; moreInfo = ''; run = $null; execution = ''; alsoStopped = @() }
    try {
        $hist = if ($PSBoundParameters.ContainsKey('History')) { @($History) } else { @(Get-PimJobRunHistory) }
        $t = Get-PimJobCancelTarget -Name $Name -History $hist -TickJobId $TickJobId
        if (-not $t.ok) { $res.code = $t.code; $res.message = $t.message; return [pscustomobject]$res }
        $run = $t.run; $exec = $t.execution; $res.execution = $exec
        $note = ''
        try { [void](& $Arm 'POST' ('{0}/executions/{1}/stop?api-version={2}' -f $t.jobId, $exec, $script:PimJobCancelApi)) }
        catch {
            $m = "$($_.Exception.Message)"
            if ($m -match '(?i)\b403\b|AuthorizationFailed|forbidden') {
                $res.code = 'not-allowed'
                $res.message = 'PIM Manager is not allowed to stop the engine run. Nothing was changed.'
                $res.moreInfo = ("The Manager's identity needs the action Microsoft.App/jobs/stop/action on the engine job {0} (scope: that job only). Without it the run keeps going and finishes by itself. Platform answer: {1}" -f $t.jobName, $m.Substring(0, [Math]::Min(200, $m.Length)))
                return [pscustomobject]$res
            }
            if ($m -match '(?i)\b404\b|NotFound') { $note = 'Its execution had already ended' }
            else {
                $res.code = 'error'
                $res.message = 'The engine run could not be stopped. Nothing was changed.'
                $res.moreInfo = "Platform answer: $($m.Substring(0, [Math]::Min(300, $m.Length)))"
                return [pscustomobject]$res
            }
        }
        $cancelled = New-PimCancelledRunRecord -Run $run -By $By -NowUtc $NowUtc -Note $note
        $rid = "$($run.runId)"
        $also = @(@($hist) | Where-Object { $_ -and "$($_.status)" -eq 'running' -and "$($_.runId)" -ne $rid -and $_.PSObject.Properties['execution'] -and "$($_.execution)" -eq $exec } | ForEach-Object { "$($_.name)" } | Select-Object -Unique)
        $script:PimRunHistoryWriteOk = $true
        Update-PimJobRunHistory -Attempts 16 -Mutate {
            param($all)
            $all = @($all)
            ,@(@($cancelled) + @($all | Where-Object { "$($_.runId)" -ne $rid }))
        }
        $res.run = $cancelled; $res.alsoStopped = $also
        if (-not $script:PimRunHistoryWriteOk) {
            $res.code = 'not-recorded'; $res.status = 'cancelled'
            $res.message = "The run of $Name was stopped, but it could not be recorded as cancelled yet."
            $res.moreInfo = 'The scheduler closes it as interrupted by the platform stop; it then runs again on its next turn.'
            return [pscustomobject]$res
        }
        # NEVER RESUMED: the next tick must not start the same work again at once. A trigger run's trigger is removed only when
        # its run ENDS (so it would be drained again); a scheduled run's slot is stamped only when it ends (so it would look
        # due). Both are done here, as the run's end: the trigger(s) it was draining go, the job's next turn = now + interval.
        $resumeNote = ''
        $isTrig = [bool]($run.PSObject.Properties['trigger'] -and [bool]$run.trigger)
        try {
            if ($isTrig) {
                $rs = Get-PimUtcStamp "$($run.startedUtc)"
                [void](Update-PimJobTriggerList -Mutate {
                    param($cur)
                    @($cur) | Where-Object {
                        $tq = Get-PimUtcStamp "$($_.requestedUtc)"
                        -not ("$($_.type)" -eq "$($run.type)" -and "$($_.scope)" -eq "$($run.scope)" -and ($null -eq $rs -or $null -eq $tq -or $tq -le $rs)) } })
            } elseif ($Job) {
                $jc = $Job.PSObject.Copy()
                $nr = (Get-PimNextRunAfterRun -Job $jc -ScheduledUtc $NowUtc -StartedUtc $NowUtc -FinishedUtc $NowUtc.ToUniversalTime()).ToString('o')
                foreach ($kv in @(@('lastRunUtc', "$($run.startedUtc)"), @('lastFinishedUtc', $NowUtc.ToUniversalTime().ToString('o')), @('nextRunUtc', $nr))) { $jc | Add-Member -NotePropertyName $kv[0] -NotePropertyValue $kv[1] -Force }
                [void](Save-PimSchedulerJobStamps -Jobs @($jc) -RanNames @("$Name") -NowUtc $NowUtc)
            }
        } catch { $resumeNote = " (its next turn could not be set: $($_.Exception.Message))" }
        $own = if ($run.PSObject.Properties['owner']) { "$($run.owner)".Trim() } else { '' }
        # The whole execution is gone, so are its locks. A release that does not land is SAID: the locks then expire by
        # their own TTL (or the next run finds their execution ended and takes them over) -- the job is only delayed.
        $lockNote = ''
        if ($own) {
            $relOk = $false
            try { $relOk = [bool](Remove-PimAreaLocks -Owner $own) } catch { $relOk = $false; $lockNote = " (its locks were not released: $($_.Exception.Message) -- they expire by themselves)" }
            if (-not $relOk -and -not $lockNote) { $lockNote = ' (its locks were not released -- they expire by themselves)' }
        }
        $res.ok = $true; $res.code = 'cancelled'; $res.status = 'cancelled'
        $res.message = "The run of $Name was cancelled. It runs again on its next normal turn."
        $res.moreInfo = ("Stopped execution {0}. The run is recorded as cancelled by {1}: it is final -- not retried, not resumed, not a failure{2}.{3}" -f $exec, "$($cancelled.cancelledBy)", "$resumeNote$lockNote", $(if ($also.Count) { " Also stopped with it (they run again on their next turn): $($also -join ', ')." } else { '' }))
        return [pscustomobject]$res
    } catch {
        $res.code = 'error'; $res.message = 'The run could not be cancelled. Nothing was changed.'; $res.moreInfo = "$($_.Exception.Message)"
        return [pscustomobject]$res
    }
}
