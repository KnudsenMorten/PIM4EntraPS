#Requires -Version 5.1
<#
.SYNOPSIS
    The CADENCE of the two MSP jobs, set in the Manager's Job schedule and decided by each job itself:
      pull     the managed tenant's Data Definition Updater (ca-pim-downlink-s6, tools/pim-engine/downlink-job-entry.ps1)
      publish  the master's signed-baseline publish            (ca-pim-publish,      tools/pim-engine/publish-job-entry.ps1)

.DESCRIPTION
    Operator, 2026-09-18: "can the pull run every 30 min" ... "i need to be able to control cadence" ... "gui must be
    made to control". Both jobs used to run on a FIXED Container Apps cron (daily 03:00 / 04:00 UTC), and nothing in the
    Manager could change it.

    THE MODEL. The job's trigger cron fires every 5 minutes (the finest interval the GUI allows) and the job GATES
    ITSELF from its OWN store -- the cadence is LOCAL to the tenant that runs the job, the same principle as rings:
      * <job>Schedule  { enabled; intervalMinutes }   written by the Manager (Job schedule page, SuperAdmin, audited)
      * <job>RunNow    { requestedUtc; requestedBy }   written by the Manager's "Run now" button (SuperAdmin, audited)
      * <job>LastRun   { startedUtc; finishedUtc; state; trigger; detail; failures; version } written by the job
    A not-due execution logs ONE line ("[cadence] SKIPPED: not-due -- ...") and exits 0 without loading the engine.

    NO SILENT BEHAVIOUR CHANGE:
      * NOTHING STORED = TODAY'S CADENCE: every 1440 minutes (daily), ENABLED. Deliberately NOT the tick catalog's
        'msp-pull' row (intervalMinutes 240, enabled $false): that row belongs to the tick's placeholder, and every save
        of the Jobs / Job schedule page persists it verbatim -- reading it here would have switched the pull OFF on
        every environment whose schedule had ever been touched. That is why the cadence has its own setting.
      * "disabled" in the GUI is honoured: the job does not run, and its log says it is disabled in the Job schedule.
      * A store that cannot be READ never stops the job: it runs (the pull is signature-verified and the publish is
        verified end to end, so an extra run is safe) and the log says loudly that the schedule could not be read.
      * A run that FAILED is retried on the next three triggers (the Container Apps retry used to do this once),
        then with a doubling back-off capped at the interval -- never more often than the old cron plus its retry
        in the steady state, and never silently.
      * A REDEPLOY of the job runs it once on its next trigger (PIM_CadenceDeployedUtc in the job's env): a deploy
        that changed the job's inputs (trusted keys, URL, image) takes effect without waiting a day, and the build's
        "start and verify" steps keep working.

    PURE except Invoke-PimJobCadenceGate / Complete-PimJobCadenceRun, whose I/O is injected (-ReadValues,
    -CompareAndSet, -Write), so the offline tests drive the real gate with the store stubbed. ASCII only; PS 5.1 + 7.
#>
Set-StrictMode -Off

$script:PimJobCadenceTriggerMinutes   = 5      # the job's cron: '*/5 * * * *'
$script:PimJobCadenceMinInterval      = 5
$script:PimJobCadenceMaxInterval      = 1440
$script:PimJobCadenceDefaultInterval  = 1440   # the old daily cron
$script:PimJobCadenceGraceSeconds     = 150    # half a trigger: a start at 10:00:07 is due again at the 10:30:03 trigger
$script:PimJobCadenceImmediateRetries = 3
$script:PimJobCadenceSkipMarker       = '[cadence] SKIPPED:'
$script:PimJobCadenceDefaultCron      = '*/5 * * * *'

function Get-PimJobCadenceDefaultCron { return $script:PimJobCadenceDefaultCron }

function Get-PimJobCadenceDefinition {
    <# PURE. The fixed facts of one job: the setting names, the Job schedule row, the plain label. #>
    param([Parameter(Mandatory)][ValidateSet('pull', 'publish')][string]$Job)
    if ($Job -eq 'pull') {
        return [pscustomobject]@{
            job = 'pull'; row = 'msp-pull'; type = 'msp-pull'; verb = 'pull'
            label = 'Managed-tenant pull (Data Definition Updater)'
            plain = 'Pulls the signed configuration from the master tenant and applies it here (the Data Definition Updater job). Runs as its own job on this managed tenant, not in the scheduler tick.'
            scheduleKey = 'DownlinkSchedule'; runNowKey = 'DownlinkRunNow'; lastRunKey = 'DownlinkLastRun'
            jobName = 'ca-pim-downlink-s6'
            # replicaTimeout 1800 s (Get-PimDownlinkJobYaml) + one trigger: a 'running' record older than this was killed.
            staleMinutes = 35
        }
    }
    return [pscustomobject]@{
        job = 'publish'; row = 'baseline-publish'; type = 'baseline-publish'; verb = 'publish'
        label = 'Publish to managed tenants'
        plain = 'Signs and publishes the configuration the managed tenants pull (the publish job). A commit that changes what is published also requests a publish.'
        scheduleKey = 'PublishSchedule'; runNowKey = 'PublishRunNow'; lastRunKey = 'PublishLastRun'
        jobName = 'ca-pim-publish'
        staleMinutes = 25   # replicaTimeout 1200 s (Get-PimBaselinePublishJobSpec) + one trigger
    }
}

function Get-PimJobCadenceLimits {
    return [pscustomobject]@{
        minIntervalMinutes = $script:PimJobCadenceMinInterval; maxIntervalMinutes = $script:PimJobCadenceMaxInterval
        defaultIntervalMinutes = $script:PimJobCadenceDefaultInterval; triggerMinutes = $script:PimJobCadenceTriggerMinutes
    }
}

function Get-PimJobCadenceValue {
    # Null-safe property read (IDictionary or PSCustomObject).
    param([object]$Object, [Parameter(Mandatory)][string]$Key)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Key)) { return $Object[$Key] }; return $null }
    $p = $Object.PSObject.Properties[$Key]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-PimJobCadenceUtc {
    <#
      PURE. A stamp -> [datetime] UTC, or $null. Handles the three shapes a stamp arrives in: an ISO string (what this file
      writes), a [datetime] (pwsh 7's ConvertFrom-Json turns ISO strings into dates, Local or Utc kind), a DateTimeOffset.
      TRAP: never "$date": string interpolation drops the Kind, and a Local date re-read as UTC is off by the UTC offset.
    #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    if ($Value -is [System.DateTimeOffset]) { return $Value.UtcDateTime }
    $s = "$Value".Trim()
    if (-not $s) { return $null }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d.ToUniversalTime() }
    return $null
}

function ConvertTo-PimJobCadenceStamp {
    param([AllowNull()][object]$Value)
    $d = ConvertTo-PimJobCadenceUtc $Value
    if ($null -eq $d) { return '' }
    return $d.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-PimJobCadenceJson {
    # A stored value as read (raw JSON text, or an already-parsed object). Unparseable text -> @{ ok = $false }.
    param([AllowNull()][object]$Raw)
    if ($null -eq $Raw -or $Raw -is [System.DBNull]) { return [pscustomobject]@{ ok = $true; value = $null } }
    if ($Raw -isnot [string]) { return [pscustomobject]@{ ok = $true; value = $Raw } }
    if (-not "$Raw".Trim()) { return [pscustomobject]@{ ok = $true; value = $null } }
    try { return [pscustomobject]@{ ok = $true; value = ("$Raw" | ConvertFrom-Json) } }
    catch { return [pscustomobject]@{ ok = $false; value = $null } }
}

function Test-PimJobCadenceInterval {
    <# PURE. The Manager's PUT validation: a whole number of minutes, 5..1440. Returns @{ ok; value; reason }. #>
    param([AllowNull()][object]$Value)
    $s = "$Value".Trim()
    $n = 0
    if (-not $s -or -not [int]::TryParse($s, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) {
        return [pscustomobject]@{ ok = $false; value = $null; reason = "the interval '$s' is not a whole number of minutes ($($script:PimJobCadenceMinInterval)-$($script:PimJobCadenceMaxInterval))" }
    }
    if ($n -lt $script:PimJobCadenceMinInterval -or $n -gt $script:PimJobCadenceMaxInterval) {
        return [pscustomobject]@{ ok = $false; value = $n; reason = "the interval must be $($script:PimJobCadenceMinInterval)-$($script:PimJobCadenceMaxInterval) minutes (got $n): the job's trigger fires every $($script:PimJobCadenceTriggerMinutes) minutes, and anything slower than daily would be slower than the job has ever run" }
    }
    return [pscustomobject]@{ ok = $true; value = $n; reason = '' }
}

function Test-PimJobCadenceFalse {
    param([AllowNull()][object]$Value)
    if ($Value -is [bool]) { return (-not $Value) }
    return ("$Value".Trim() -match '^(?i)(false|0|no|off)$')
}

function Resolve-PimJobCadenceSchedule {
    <#
      PURE. The EFFECTIVE cadence from the stored <job>Schedule value (or $null). Returns
      @{ enabled; intervalMinutes; source = 'default'|'stored'; note; updatedUtc; updatedBy }.
      NOTHING STORED = enabled, every 1440 minutes: the daily cadence the job had before the Manager could set it.
      A stored interval outside 5..1440 is clamped (the Manager's PUT refuses it; a hand edit is honoured as closely as
      it safely can be, and the note says so). A stored value that is not a schedule at all falls back to the default.
    #>
    param([AllowNull()][object]$Stored, [switch]$Unparseable)
    $out = [ordered]@{ enabled = $true; intervalMinutes = $script:PimJobCadenceDefaultInterval; source = 'default'
                       note = 'nothing set in the Manager''s Job schedule -- the default applies (daily, the cadence this job always had)'
                       updatedUtc = ''; updatedBy = '' }
    if ($Unparseable) { $out.note = 'the stored schedule is not readable JSON -- the default applies (daily); save the row in the Job schedule to repair it'; return [pscustomobject]$out }
    if ($null -eq $Stored -or ($Stored -is [string])) {
        if ($Stored -is [string] -and "$Stored".Trim()) { $out.note = 'the stored schedule is not a schedule object -- the default applies (daily)' }
        return [pscustomobject]$out
    }
    $out.source = 'stored'; $out.note = 'set in the Manager''s Job schedule'
    $en = Get-PimJobCadenceValue -Object $Stored -Key 'enabled'
    if ($null -ne $en) { $out.enabled = -not (Test-PimJobCadenceFalse $en) }
    $iv = Get-PimJobCadenceValue -Object $Stored -Key 'intervalMinutes'
    if ($null -ne $iv -and "$iv".Trim()) {
        $n = 0
        if ([int]::TryParse("$iv".Trim(), [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) {
            if ($n -lt $script:PimJobCadenceMinInterval) { $out.intervalMinutes = $script:PimJobCadenceMinInterval; $out.note = "the stored interval $n is below $($script:PimJobCadenceMinInterval) minutes -- $($script:PimJobCadenceMinInterval) is used" }
            elseif ($n -gt $script:PimJobCadenceMaxInterval) { $out.intervalMinutes = $script:PimJobCadenceMaxInterval; $out.note = "the stored interval $n is above $($script:PimJobCadenceMaxInterval) minutes -- $($script:PimJobCadenceMaxInterval) is used" }
            else { $out.intervalMinutes = $n }
        } else { $out.note = "the stored interval '$iv' is not a number -- the default $($script:PimJobCadenceDefaultInterval) minutes is used" }
    }
    $out.updatedUtc = ConvertTo-PimJobCadenceStamp (Get-PimJobCadenceValue -Object $Stored -Key 'updatedUtc')
    $out.updatedBy  = "$(Get-PimJobCadenceValue -Object $Stored -Key 'updatedBy')"
    return [pscustomobject]$out
}

function Get-PimJobCadenceLastRunView {
    # PURE. Normalise a stored <job>LastRun value.
    param([AllowNull()][object]$LastRun)
    $f = 0; [void][int]::TryParse("$(Get-PimJobCadenceValue -Object $LastRun -Key 'failures')", [ref]$f)
    return [pscustomobject]@{
        startedUtc    = ConvertTo-PimJobCadenceUtc (Get-PimJobCadenceValue -Object $LastRun -Key 'startedUtc')
        finishedUtc   = ConvertTo-PimJobCadenceUtc (Get-PimJobCadenceValue -Object $LastRun -Key 'finishedUtc')
        state         = "$(Get-PimJobCadenceValue -Object $LastRun -Key 'state')".Trim().ToLowerInvariant()
        trigger       = "$(Get-PimJobCadenceValue -Object $LastRun -Key 'trigger')"
        detail        = "$(Get-PimJobCadenceValue -Object $LastRun -Key 'detail')"
        executionName = "$(Get-PimJobCadenceValue -Object $LastRun -Key 'executionName')".Trim()
        version       = "$(Get-PimJobCadenceValue -Object $LastRun -Key 'version')"
        failures      = [Math]::Max(0, $f)
    }
}

function Get-PimJobCadenceDecision {
    <#
      PURE. Does this execution run the job? Returns @{ run; code; reason; enabled; intervalMinutes; source; nextDueUtc }.
      Order (first match wins):
        store-unreadable  the store could not be read -> RUN (loud). An unknown schedule must not stop the job.
        retry             this is the Container Apps retry of the SAME execution whose run failed or was killed -> RUN
        in-progress       another execution started a run less than staleMinutes ago and has not finished -> SKIP
        run-now           a Run now request newer than the last start -> RUN (even when disabled: it is an explicit act)
        redeployed        the job was redeployed after the last start -> RUN once (PIM_CadenceDeployedUtc)
        disabled          switched off in the Job schedule -> SKIP
        first-run         no run recorded yet -> RUN
        retry-after-failure / backoff   the last run failed: the next three triggers retry, then 10, 20, 40 ... minutes,
                          capped at the interval
        due / not-due     the interval since the last START has elapsed (minus half a trigger of grace)
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('pull', 'publish')][string]$Job,
        [AllowNull()][object]$Schedule,
        [AllowNull()][object]$LastRun,
        [AllowNull()][object]$RunNow,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [string]$StoreError = '',
        [string]$ExecutionName = '',
        [AllowNull()][object]$DeployedUtc,
        [switch]$ScheduleUnparseable
    )
    $def = Get-PimJobCadenceDefinition -Job $Job
    $now = (ConvertTo-PimJobCadenceUtc $NowUtc)
    $sched = Resolve-PimJobCadenceSchedule -Stored $Schedule -Unparseable:$ScheduleUnparseable
    $base = [ordered]@{ run = $false; code = ''; reason = ''; enabled = [bool]$sched.enabled; intervalMinutes = [int]$sched.intervalMinutes
                        source = "$($sched.source)"; scheduleNote = "$($sched.note)"; nextDueUtc = ''; job = $Job }
    $mk = { param($run, $code, $reason, $next) $o = [ordered]@{}; foreach ($k in $base.Keys) { $o[$k] = $base[$k] }; $o.run = [bool]$run; $o.code = $code; $o.reason = $reason; $o.nextDueUtc = "$next"; [pscustomobject]$o }
    $where = if ($sched.source -eq 'default') { "interval $($sched.intervalMinutes) min, the default -- nothing set in the Manager's Job schedule" } else { "interval $($sched.intervalMinutes) min, set in the Manager's Job schedule" }

    if ("$StoreError".Trim()) {
        return (& $mk $true 'store-unreadable' ("the Job schedule could NOT be read from this tenant's store ($StoreError) -- the $($def.verb) runs anyway, because an unknown schedule must never stop it; fix the store access, or every trigger ($($script:PimJobCadenceTriggerMinutes) min) will $($def.verb)") '')
    }
    $last = Get-PimJobCadenceLastRunView -LastRun $LastRun
    $exec = "$ExecutionName".Trim()
    if ($exec -and $last.executionName -and $last.executionName -eq $exec -and $last.state -in @('failed', 'running')) {
        return (& $mk $true 'retry' ("the platform retried execution $exec after its $($def.verb) $(if ($last.state -eq 'failed') { 'failed' } else { 'was interrupted' })") '')
    }
    $abandoned = ''
    if ($last.state -eq 'running' -and $last.startedUtc) {
        if ($last.startedUtc -gt $now.AddMinutes(-1 * $def.staleMinutes)) {
            return (& $mk $false 'in-progress' ("another execution started a $($def.verb) at $(ConvertTo-PimJobCadenceStamp $last.startedUtc) and has not finished") '')
        }
        $abandoned = " (the run started at $(ConvertTo-PimJobCadenceStamp $last.startedUtc) never recorded an end -- treated as abandoned)"
    }
    $rn = ConvertTo-PimJobCadenceUtc (Get-PimJobCadenceValue -Object $RunNow -Key 'requestedUtc')
    if ($rn -and (-not $last.startedUtc -or $rn -gt $last.startedUtc)) {
        $by = "$(Get-PimJobCadenceValue -Object $RunNow -Key 'requestedBy')".Trim()
        $why = "$(Get-PimJobCadenceValue -Object $RunNow -Key 'reason')".Trim()
        return (& $mk $true 'run-now' ("Run now was requested at $(ConvertTo-PimJobCadenceStamp $rn)$(if ($by) { " by $by" })$(if ($why) { " ($why)" })$(if (-not $sched.enabled) { ' -- it runs although the job is disabled in the Job schedule' })$abandoned") '')
    }
    $dep = ConvertTo-PimJobCadenceUtc $DeployedUtc
    if ($dep -and (-not $last.startedUtc -or $dep -gt $last.startedUtc) -and $dep -le $now.AddMinutes(5)) {
        return (& $mk $true 'redeployed' ("the job was deployed at $(ConvertTo-PimJobCadenceStamp $dep), after the last $($def.verb) -- one run so the new definition takes effect now$abandoned") '')
    }
    if (-not $sched.enabled) {
        return (& $mk $false 'disabled' ("the $($def.verb) is DISABLED in the Manager's Job schedule ($($def.label)) -- it does not run until it is enabled there, or Run now is used") '')
    }
    if (-not $last.startedUtc) {
        return (& $mk $true 'first-run' ("no $($def.verb) is recorded in this tenant's store yet ($where)") '')
    }
    $grace = [double]$script:PimJobCadenceGraceSeconds
    if ($last.state -eq 'failed' -and $last.failures -ge 1) {
        $delay = 0
        if ($last.failures -gt $script:PimJobCadenceImmediateRetries) {
            $delay = [Math]::Min([double]$sched.intervalMinutes, 5.0 * [Math]::Pow(2, $last.failures - $script:PimJobCadenceImmediateRetries))
        }
        $retryAt = $last.startedUtc.AddMinutes($delay)
        if ($now -ge $retryAt.AddSeconds(-1 * $grace)) {
            return (& $mk $true 'retry-after-failure' ("the last $($def.verb) (started $(ConvertTo-PimJobCadenceStamp $last.startedUtc)) FAILED ($($last.failures) in a row) -- retrying$abandoned") '')
        }
        return (& $mk $false 'backoff' ("the last $($def.verb) FAILED ($($last.failures) in a row); the next retry is at $(ConvertTo-PimJobCadenceStamp $retryAt) (back-off, capped at the $($sched.intervalMinutes) min interval)") (ConvertTo-PimJobCadenceStamp $retryAt))
    }
    $next = $last.startedUtc.AddMinutes([double]$sched.intervalMinutes)
    if ($now -ge $next.AddSeconds(-1 * $grace)) {
        return (& $mk $true 'due' ("due: the last $($def.verb) started $(ConvertTo-PimJobCadenceStamp $last.startedUtc) ($where)$abandoned") (ConvertTo-PimJobCadenceStamp $next))
    }
    return (& $mk $false 'not-due' ("not due (next at $(ConvertTo-PimJobCadenceStamp $next), $where)") (ConvertTo-PimJobCadenceStamp $next))
}

function New-PimJobCadenceRunRecord {
    # PURE. The 'running' record the gate claims before the job does its work.
    param([Parameter(Mandatory)][object]$Decision, [AllowNull()][object]$PreviousLastRun, [datetime]$NowUtc = [datetime]::UtcNow, [string]$ExecutionName = '')
    $prev = Get-PimJobCadenceLastRunView -LastRun $PreviousLastRun
    # Consecutive failures carry over until a run succeeds; a retry of the SAME execution keeps the count it had.
    $fails = if ($prev.state -in @('failed', 'running')) { [int]$prev.failures } else { 0 }
    return [ordered]@{
        startedUtc = ConvertTo-PimJobCadenceStamp $NowUtc; finishedUtc = ''; state = 'running'
        trigger = "$($Decision.code)"; detail = "$($Decision.reason)"; executionName = "$ExecutionName".Trim()
        failures = $fails; version = ''
    }
}

function Complete-PimJobCadenceRunRecord {
    # PURE. The record at the end of the run. failures counts CONSECUTIVE failed runs (0 after a success).
    param([Parameter(Mandatory)][object]$Record, [Parameter(Mandatory)][ValidateSet('succeeded', 'failed', 'held')][string]$State,
          [string]$Detail = '', [string]$Version = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $o = [ordered]@{}
    foreach ($k in @('startedUtc', 'finishedUtc', 'state', 'trigger', 'detail', 'executionName', 'failures', 'version')) { $o[$k] = Get-PimJobCadenceValue -Object $Record -Key $k }
    $o.finishedUtc = ConvertTo-PimJobCadenceStamp $NowUtc
    $o.state = $State
    if ("$Detail".Trim()) { $d = "$Detail".Trim(); if ($d.Length -gt 600) { $d = $d.Substring(0, 600) + '...' }; $o.detail = $d }
    if ("$Version".Trim()) { $o.version = "$Version".Trim() }
    $f = 0; [void][int]::TryParse("$($o.failures)", [ref]$f)
    $o.failures = if ($State -eq 'failed') { $f + 1 } else { 0 }
    return $o
}

function ConvertTo-PimJobCadenceJson {
    param([Parameter(Mandatory)][object]$Value)
    return ($Value | ConvertTo-Json -Depth 5 -Compress)
}

function Invoke-PimJobCadenceGate {
    <#
      The gate a job runs FIRST. I/O injected:
        -ReadValues     param([string[]]$Names) -> hashtable Name -> raw stored JSON (or $null). THROW = store unreadable.
        -CompareAndSet  param($Name, $NewJson, $ExpectedJson) -> rows written (1 = claimed, 0 = another execution won).
        -Log            param($Message, $Level)
      Returns @{ run; claimed; decision; record; def }. A skip logs exactly one line carrying the skip marker, so the
      deploy/verify helpers can tell a gate skip from a run (Get-PimJobCadenceSkipFromLog).
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('pull', 'publish')][string]$Job,
        [scriptblock]$ReadValues,
        [scriptblock]$CompareAndSet,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [string]$ExecutionName = '',
        [AllowNull()][object]$DeployedUtc,
        [string]$StoreError = '',
        [scriptblock]$Log = { param($m, $l) Write-Host "[$l] $m" }
    )
    $def = Get-PimJobCadenceDefinition -Job $Job
    $err = "$StoreError".Trim()
    $raw = @{}
    if (-not $err) {
        if (-not $ReadValues) { $err = 'no store is configured for this job' }
        else {
            try {
                $got = & $ReadValues @($def.scheduleKey, $def.runNowKey, $def.lastRunKey)
                if ($got -is [System.Collections.IDictionary]) { $raw = $got } else { $err = 'the store read returned no values' }
            } catch { $err = "$($_.Exception.Message)" }
        }
    }
    $sched = ConvertFrom-PimJobCadenceJson $raw[$def.scheduleKey]
    $rnow  = ConvertFrom-PimJobCadenceJson $raw[$def.runNowKey]
    $lrun  = ConvertFrom-PimJobCadenceJson $raw[$def.lastRunKey]
    $d = Get-PimJobCadenceDecision -Job $Job -Schedule $sched.value -ScheduleUnparseable:(-not $sched.ok) -LastRun $lrun.value -RunNow $rnow.value `
            -NowUtc $NowUtc -StoreError $err -ExecutionName $ExecutionName -DeployedUtc $DeployedUtc
    $res = [ordered]@{ run = [bool]$d.run; claimed = $false; decision = $d; record = $null; def = $def }
    if (-not $d.run) {
        & $Log ("{0} {1} -- the {2} {3}" -f $script:PimJobCadenceSkipMarker, $d.code, $def.verb, $d.reason) 'INFO'
        return [pscustomobject]$res
    }
    if ($d.code -eq 'store-unreadable') {
        & $Log ("CADENCE: {0}" -f $d.reason) 'ERROR'
        return [pscustomobject]$res
    }
    if ("$($d.scheduleNote)" -match 'not readable|not a schedule|not a number|is below|is above') { & $Log ("CADENCE: $($d.scheduleNote)") 'WARN' }
    $rec = New-PimJobCadenceRunRecord -Decision $d -PreviousLastRun $lrun.value -NowUtc $NowUtc -ExecutionName $ExecutionName
    $res.record = $rec
    $expected = $raw[$def.lastRunKey]
    if ($expected -is [System.DBNull]) { $expected = $null }
    $n = $null
    if ($CompareAndSet) {
        try { $n = & $CompareAndSet $def.lastRunKey (ConvertTo-PimJobCadenceJson $rec) $expected }
        catch {
            & $Log ("CADENCE: the start of this {0} could NOT be recorded in the store ({1}) -- running anyway; until it can be recorded, every trigger will {0}" -f $def.verb, $_.Exception.Message) 'WARN'
            $res.record = $null
            & $Log ("CADENCE: running -- {0}" -f $d.reason) 'INFO'
            return [pscustomobject]$res
        }
    }
    if ($null -ne $n -and [int]$n -lt 1) {
        $res.run = $false
        & $Log ("{0} claimed-elsewhere -- another execution started this {1} a moment ago" -f $script:PimJobCadenceSkipMarker, $def.verb) 'INFO'
        return [pscustomobject]$res
    }
    $res.claimed = ($null -ne $n)
    & $Log ("CADENCE: running -- {0}" -f $d.reason) $(if ($d.code -in @('retry-after-failure', 'retry')) { 'WARN' } else { 'INFO' })
    return [pscustomobject]$res
}

function Complete-PimJobCadenceRun {
    <# Record how the run ended (-Write param($Name, $Json)). Never throws: a failed write is logged, the run's own exit code stands. #>
    param([AllowNull()][object]$Gate, [Parameter(Mandatory)][ValidateSet('succeeded', 'failed', 'held')][string]$State,
          [string]$Detail = '', [string]$Version = '', [scriptblock]$Write, [datetime]$NowUtc = [datetime]::UtcNow,
          [scriptblock]$Log = { param($m, $l) Write-Host "[$l] $m" })
    if (-not $Gate -or -not $Gate.claimed -or -not $Gate.record -or -not $Write) { return $null }
    $done = Complete-PimJobCadenceRunRecord -Record $Gate.record -State $State -Detail $Detail -Version $Version -NowUtc $NowUtc
    try { [void](& $Write $Gate.def.lastRunKey (ConvertTo-PimJobCadenceJson $done)); & $Log ("CADENCE: recorded {0} {1} (last run in the Manager's Job schedule)" -f $Gate.def.verb, $State) 'INFO' }
    catch { & $Log ("CADENCE: the end of this {0} could NOT be recorded ({1}) -- the Job schedule will show it as running until it goes stale" -f $Gate.def.verb, $_.Exception.Message) 'WARN' }
    return $done
}

function Get-PimJobCadenceSkipFromLog {
    <# PURE. Did an execution's log end in a gate skip? @{ skipped; code; line } (the LAST marker line wins). #>
    param([AllowNull()][string]$LogText)
    $hit = $null
    foreach ($ln in @("$LogText" -split "`r?`n")) {
        $i = $ln.IndexOf($script:PimJobCadenceSkipMarker)
        if ($i -ge 0) { $hit = $ln.Substring($i) }
    }
    if (-not $hit) { return [pscustomobject]@{ skipped = $false; code = ''; line = '' } }
    $code = ''
    if ($hit -match '\[cadence\] SKIPPED:\s*([a-z-]+)') { $code = $Matches[1] }
    return [pscustomobject]@{ skipped = $true; code = $code; line = $hit.Trim() }
}

function Get-PimJobCadenceStatus {
    <#
      PURE. What the Manager's Job schedule shows for one job: the effective cadence, the last run (what the job recorded),
      the next due time, and whether a Run now is pending.
    #>
    param([Parameter(Mandatory)][ValidateSet('pull', 'publish')][string]$Job, [AllowNull()][object]$Schedule, [AllowNull()][object]$LastRun,
          [AllowNull()][object]$RunNow, [datetime]$NowUtc = [datetime]::UtcNow)
    $def = Get-PimJobCadenceDefinition -Job $Job
    $sched = Resolve-PimJobCadenceSchedule -Stored $Schedule
    $last = Get-PimJobCadenceLastRunView -LastRun $LastRun
    $d = Get-PimJobCadenceDecision -Job $Job -Schedule $Schedule -LastRun $LastRun -RunNow $RunNow -NowUtc $NowUtc
    $rn = ConvertTo-PimJobCadenceUtc (Get-PimJobCadenceValue -Object $RunNow -Key 'requestedUtc')
    $pending = [bool]($rn -and (-not $last.startedUtc -or $rn -gt $last.startedUtc))
    $nextText = switch ($d.code) {
        'in-progress' { "running now (started $(ConvertTo-PimJobCadenceStamp $last.startedUtc))" }
        'disabled'    { 'disabled -- it does not run until enabled here (Run now still runs it once)' }
        'run-now'     { "within $($script:PimJobCadenceTriggerMinutes) minutes (Run now requested)" }
        'first-run'   { "within $($script:PimJobCadenceTriggerMinutes) minutes (no run recorded yet)" }
        default       { if ($d.run) { "within $($script:PimJobCadenceTriggerMinutes) minutes (due now)" } elseif ($d.nextDueUtc) { "$($d.nextDueUtc)" } else { '' } }
    }
    $lastOut = $null
    if ($last.startedUtc) {
        $lastOut = [ordered]@{ startedUtc = ConvertTo-PimJobCadenceStamp $last.startedUtc; finishedUtc = ConvertTo-PimJobCadenceStamp $last.finishedUtc
                               state = $last.state; trigger = $last.trigger; detail = $last.detail; version = $last.version; failures = $last.failures }
    }
    return [ordered]@{
        job = $Job; row = $def.row; label = $def.label; plain = $def.plain; jobName = $def.jobName
        enabled = [bool]$sched.enabled; intervalMinutes = [int]$sched.intervalMinutes; source = "$($sched.source)"; note = "$($sched.note)"
        updatedUtc = "$($sched.updatedUtc)"; updatedBy = "$($sched.updatedBy)"
        minIntervalMinutes = $script:PimJobCadenceMinInterval; maxIntervalMinutes = $script:PimJobCadenceMaxInterval
        triggerMinutes = $script:PimJobCadenceTriggerMinutes
        lastRun = $lastOut; nextDueUtc = $(if ($d.run) { '' } else { "$($d.nextDueUtc)" }); nextDueText = "$nextText"; nextCode = "$($d.code)"
        inProgress = [bool]($d.code -eq 'in-progress')
        runNowPending = $pending; runNowRequestedUtc = $(if ($pending) { ConvertTo-PimJobCadenceStamp $rn } else { '' })
        runNowRequestedBy = $(if ($pending) { "$(Get-PimJobCadenceValue -Object $RunNow -Key 'requestedBy')" } else { '' })
    }
}

function New-PimJobCadenceScheduleValue {
    param([bool]$Enabled = $true, [Parameter(Mandatory)][int]$IntervalMinutes, [string]$By = '', [datetime]$NowUtc = [datetime]::UtcNow)
    return [ordered]@{ enabled = [bool]$Enabled; intervalMinutes = [int]$IntervalMinutes; updatedUtc = ConvertTo-PimJobCadenceStamp $NowUtc; updatedBy = "$By" }
}

function New-PimJobCadenceRunNowValue {
    param([string]$By = '', [string]$Reason = 'Run now', [datetime]$NowUtc = [datetime]::UtcNow)
    return [ordered]@{ requestedUtc = ConvertTo-PimJobCadenceStamp $NowUtc; requestedBy = "$By"; reason = "$Reason" }
}

# ---------------------------------------------------------------------------------------------------------------------
# SQL. The pull job reads + writes pim.Settings directly (its identity administers its own store). The PUBLISH job does
# NOT: its identity is a least-privilege READER (SEC-39: SELECT on the four registry tables), and pim.Settings also holds
# who is SuperAdmin (ManagerAccess). So it reaches exactly three rows through two views:
#   pim.vw_PublishJobControl   SELECT             PublishSchedule, PublishRunNow, PublishLastRun
#   pim.vw_PublishJobLastRun   SELECT/INSERT/UPDATE  PublishLastRun only, WITH CHECK OPTION (it cannot write any other row)
# Ownership chaining (view and table share the pim schema's owner) means no right on pim.Settings itself.
# ---------------------------------------------------------------------------------------------------------------------
$script:PimJobCadenceReadObjects  = @('pim.Settings', 'pim.vw_PublishJobControl')
$script:PimJobCadenceWriteObjects = @('pim.Settings', 'pim.vw_PublishJobLastRun')

function Get-PimPublishJobControlObjects {
    <# PURE. What the publish job's database user is granted for the cadence (Deploy-PimBaselinePublishJob). #>
    return [pscustomobject]@{ select = @('pim.vw_PublishJobControl', 'pim.vw_PublishJobLastRun'); write = @('pim.vw_PublishJobLastRun') }
}

function Get-PimPublishJobControlViewSql {
    <#
      PURE. Idempotent DDL for the two views (each CREATE VIEW is its own batch, hence EXEC).
      REQ-Y (2026-09-19): the control view also carries the 'License' row -- the signed licence document, which is not a
      secret (anyone may verify it) -- because an MSP master's publish job refuses without a Pro licence and this view is
      the only part of pim.Settings its identity may read. ManagerAccess and every other row stay out of reach.
      REQUIREMENTS 77.20 (2026-09-21): and the 'DeploymentRings' row (the name + tag rule of each ring), which the producer
      signs into the bundle -- configuration, not a secret, read the same way.
      §79.6 (2026-09-25): and the 'DownlinkIntents' row -- the withdrawals / renames / session revokes the operator
      authorised centrally, which the producer signs into the bundle. Keys, who and why; no secret. Without it the job
      could not read them and every bundle shipped none.
    #>
    $d = (Get-PimJobCadenceDefinition -Job 'publish')
    $v1 = "CREATE OR ALTER VIEW pim.vw_PublishJobControl AS SELECT Name, ValueJson, UpdatedUtc FROM pim.Settings WHERE Name IN (N''$($d.scheduleKey)'', N''$($d.runNowKey)'', N''$($d.lastRunKey)'', N''License'', N''DeploymentRings'', N''DownlinkIntents'')"
    $v2 = "CREATE OR ALTER VIEW pim.vw_PublishJobLastRun AS SELECT Name, ValueJson, UpdatedUtc FROM pim.Settings WHERE Name = N''$($d.lastRunKey)'' WITH CHECK OPTION"
    return ("IF OBJECT_ID(N'pim.Settings') IS NULL THROW 50001, 'pim.Settings does not exist in this store -- the Manager has not initialised it', 1;`n" +
            "EXEC (N'$v1');`nEXEC (N'$v2');")
}

function Get-PimPublishJobControlViewRefreshSql {
    <#
      PURE. REQ-Y: re-apply the two views ONLY where they already exist (a master whose publish job was deployed). The
      Manager runs this at startup, so an upgraded master's view gains the 'License' row without redeploying the publish
      job -- otherwise that job would read "no licence" through the old view and refuse. CREATE OR ALTER keeps the grants.
      A store without the views (every non-master) is left untouched.
    #>
    return ("IF OBJECT_ID(N'pim.vw_PublishJobControl', N'V') IS NOT NULL`nBEGIN`n" + (Get-PimPublishJobControlViewSql) + "`nEND")
}

function Get-PimJobCadenceReadSql {
    <# PURE. One SELECT for the three cadence rows. Returns @{ sql; parameters }. #>
    param([Parameter(Mandatory)][string]$Object, [Parameter(Mandatory)][string[]]$Names)
    if ($script:PimJobCadenceReadObjects -notcontains $Object) { throw "Get-PimJobCadenceReadSql: '$Object' is not a cadence object" }
    $p = @{}; $i = 0; $ph = @()
    foreach ($n in @($Names)) { $p["n$i"] = "$n"; $ph += "@n$i"; $i++ }
    return [pscustomobject]@{ sql = "SELECT Name, ValueJson FROM $Object WHERE Name IN ($($ph -join ', '))"; parameters = $p }
}

function Get-PimJobCadenceCasSql {
    <#
      PURE. Compare-and-set of one row (@n name, @v new JSON, @e expected JSON or NULL = expected absent/NULL). SELECTs the
      rows written: 1 = claimed, 0 = someone else changed it first. Same shape as Set-PimSqlSettingIfUnchanged.
    #>
    param([Parameter(Mandatory)][string]$Object)
    if ($script:PimJobCadenceWriteObjects -notcontains $Object) { throw "Get-PimJobCadenceCasSql: '$Object' is not a cadence object" }
    return @"
SET NOCOUNT ON;
DECLARE @affected INT = 0;
IF @e IS NULL
BEGIN
    UPDATE $Object SET ValueJson=@v, UpdatedUtc=SYSUTCDATETIME() WHERE Name=@n AND ValueJson IS NULL;
    SET @affected = @@ROWCOUNT;
    IF @affected = 0 AND NOT EXISTS (SELECT 1 FROM $Object WHERE Name=@n)
    BEGIN
        INSERT INTO $Object (Name, ValueJson, UpdatedUtc) VALUES (@n, @v, SYSUTCDATETIME());
        SET @affected = @@ROWCOUNT;
    END
END
ELSE
BEGIN
    UPDATE $Object SET ValueJson=@v, UpdatedUtc=SYSUTCDATETIME() WHERE Name=@n AND CAST(ValueJson AS VARBINARY(MAX)) = CAST(@e AS VARBINARY(MAX));
    SET @affected = @@ROWCOUNT;
END
SELECT @affected;
"@
}

function Get-PimJobCadenceUpsertSql {
    <# PURE. Unconditional write of one row (the end-of-run record). #>
    param([Parameter(Mandatory)][string]$Object)
    if ($script:PimJobCadenceWriteObjects -notcontains $Object) { throw "Get-PimJobCadenceUpsertSql: '$Object' is not a cadence object" }
    return @"
SET NOCOUNT ON;
UPDATE $Object SET ValueJson=@v, UpdatedUtc=SYSUTCDATETIME() WHERE Name=@n;
IF @@ROWCOUNT = 0 INSERT INTO $Object (Name, ValueJson, UpdatedUtc) VALUES (@n, @v, SYSUTCDATETIME());
"@
}

# The SQL I/O behind the gate's seams, over PIM-SqlStore's invokers (Invoke-PimSqlQuery / -Scalar / -NonQuery must be
# loaded). The entry scripts wrap these in PLAIN scriptblocks -- never .GetNewClosure(): a closure runs in a new module
# scope that chains to GLOBAL, so functions dot-sourced into a -File script are invisible inside it (the 71.32 trap).
function Read-PimJobCadenceValues {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Object, [Parameter(Mandatory)][string[]]$Names)
    $q = Get-PimJobCadenceReadSql -Object $Object -Names $Names
    $h = @{}
    foreach ($r in @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql $q.sql -Parameters $q.parameters)) {
        if ($r) { $h["$($r.Name)"] = $(if ($null -eq $r.ValueJson -or $r.ValueJson -is [System.DBNull]) { $null } else { "$($r.ValueJson)" }) }
    }
    return $h
}
function Set-PimJobCadenceValueIfUnchanged {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Object, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$NewJson, [AllowNull()][AllowEmptyString()][string]$ExpectedJson)
    # IsNullOrEmpty, not `-ne $null`: a [string] parameter turns $null into '' (BUG-41, Set-PimSqlSettingIfUnchanged).
    $e = if ([string]::IsNullOrEmpty($ExpectedJson)) { [System.DBNull]::Value } else { $ExpectedJson }
    $r = Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql (Get-PimJobCadenceCasSql -Object $Object) -Parameters @{ n = $Name; v = $NewJson; e = $e }
    if ($null -eq $r -or $r -is [System.DBNull]) { return 0 }
    return [int]$r
}
function Write-PimJobCadenceValue {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Object, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Json)
    [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimJobCadenceUpsertSql -Object $Object) -Parameters @{ n = $Name; v = $Json })
}

# ---------------------------------------------------------------------------------------------------------------------
# What the publisher reads from pim.Rows. ONE list, used by the producer (Get-PimBaselineBundlePayload) and by the
# Manager's commit hook that requests a publish when a commit changed one of these entities -- so the two cannot drift.
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimBaselinePublishedDefinitionEntities {
    # BUG-60 / 71.7 (a): every entity the engine creates groups from (Get-PimGroupDefinitionRows); 'PIM-Definitions'
    # stays so an estate seeded that way is not stranded.
    return @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization', 'PIM-Definitions-Tasks',
             'PIM-Definitions-Departments', 'PIM-Definitions-Processes', 'PIM-Definitions-Projects', 'PIM-Definitions-CrossOrg', 'PIM-Definitions')
}
function Get-PimBaselinePublishedEntities {
    # REQUIREMENTS 68.6 row 35 + 71: admin definitions, tenant-scoped resource bindings and the AU definitions they need.
    return @(@('PIM-Assignments-Admins', 'PIM-Assignments-Groups', 'PIM-Assignments-Roles-Groups', 'Account-Definitions-Admins',
               'PIM-Assignments-Roles-AUs', 'PIM-Assignments-Azure-Resources', 'PIM-Assignments-Workloads', 'PIM-Definitions-AU') +
             @(Get-PimBaselinePublishedDefinitionEntities))
}
function Test-PimBaselinePublishedEntity {
    param([string]$Entity)
    return [bool](@(Get-PimBaselinePublishedEntities) -contains "$Entity".Trim())
}
