#Requires -Version 5.1
<#
.SYNOPSIS
  OPEN-13 / framework "Pipeline.longRun on the heartbeat" (DELIVERY-CONTRACT A): EVERY identified heartbeat carries Pipeline
  (Invardia's PIM contract = SI's Pipeline spec, 2026-11-06). While an engine run goes: { runId; state 'running'; startedUtc;
  step; stepSinceUtc; lastEndedUtc; longRun { usualMin; ageMin; ratio; state ok|long|stuck; newerWaiting; action; at } } --
  the product's own judgement of the run going now, so Invardia alerts the owner when a run goes far past its usual length
  (and red when a newer release waits behind it). Nothing going: { state = the last finished engine run's outcome
  (succeeded | failed | stopped); lastEndedUtc = its real end } -- Invardia's "no run ended for 48 h" check reads it -- or
  { state 'idle' } with NO lastEndedUtc when the history holds no finished engine run (never a guess).

.DESCRIPTION
  The source is the engine's OWN run history (pim.Settings 'JobRunHistory', the same list the heartbeat already reads):
  the tick writes a 'running' record at the START of every engine run (engine-delta / engine-full / msp-pull) and replaces
  it when the run ends. No ARM, no Log Analytics, no new right.

    usual   = the LONGEST of the job's last 5 finished, completed runs (Get-PimSchemaQuiesceUsualSeconds -- the same rule
              the updater's schema quiesce waits by)
    ratio   = age / usual
    state   = ok (< 1.5x) | long (>= 1.5x) | stuck (past 3x AND no progress mark for > 30 min -- Get-PimSchemaQuiesceHung,
              the quiesce's own rule; the progress mark is the run's lock 'progressUtc', the engine's "still alive" stamp;
              not readable = NOT stuck)
    newerWaiting = the version the ring approved (UpdateState.approvedVersion) when it is newer than the version the run
              started on (its record's 'version', else UpdateState.runningVersion); else null
    action  = 'none' ALWAYS: REPORT ONLY. Nothing here, or anywhere in the heartbeat, stops or cancels a customer's run.

  A running run whose job has no finished run yet = Pipeline without longRun (Invardia then judges by its own 24-hour rule). Several running = the one with the highest
  ratio (unknown usual counts lowest; the oldest wins a tie).
  Privacy: the step is the job TYPE ('pim-engine-delta'), never a name a customer typed; the run id is the engine's
  correlation id (a GUID) or, when that is not a plain id, the step + its start time.

  Its own switch PIM_UPLINK_PIPELINE (framework rule for every new heartbeat field: shipped OFF behind a per-ring switch
  until Invardia's PIM contract takes it): 1/true/on/yes = on, 0/false/off/no = off, unset = AUTO = rings 0-3 (Invardia
  deployed the field for PIM 2026-11-06, 0cafb4e0).
  Additive on the heartbeat (a refusal naming it holds just it for 24 h, Invoke-PimUplinkCycle).

  PURE (every input a parameter). ASCII; 5.1 + 7. Needs PIM-SchemaQuiesce.ps1 (loaded here when the caller has not).
#>
Set-StrictMode -Off
if (-not (Get-Command Get-PimSchemaQuiesceUsualSeconds -ErrorAction SilentlyContinue)) {
    $__pimPlLib = Join-Path $PSScriptRoot 'PIM-SchemaQuiesce.ps1'
    if (Test-Path -LiteralPath $__pimPlLib) { . $__pimPlLib }
}

function Get-PimLongRunLongFactor   { <# PURE. LITERAL. At or past this many times its usual length = 'long'. #> return 1.5 }
function Get-PimLongRunMaxMinutes   { <# PURE. LITERAL. Invardia's bound of every minute value (one year). #> return 525600 }
function Get-PimLongRunEngineTypes  { <# PURE. LITERAL. The run types the tick writes a 'running' record for (Write-PimJobRunningRecord). #> return @('engine-delta', 'engine-full', 'msp-pull') }

function Test-PimUplinkPipelineOn {
    <# PURE. PIM_UPLINK_PIPELINE: 1/true/on/yes = on; 0/false/off/no = off; anything else (unset) = AUTO = rings 0-3
       (Invardia deployed Pipeline in PIM's heartbeat contract 2026-11-06, 0cafb4e0; before that AUTO was ring 0 only). #>
    param([AllowNull()][string]$Value, [AllowNull()][object]$Ring)
    $v = "$Value".Trim()
    if ($v -match '^(?i)(1|true|on|yes)$') { return $true }
    if ($v -match '^(?i)(0|false|off|no)$') { return $false }
    return ("$Ring".Trim() -in @('0', '1', '2', '3'))
}

function ConvertTo-PimLongRunUtc {
    <# PURE. A stored time -> [datetime] UTC, or $null. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d }
    return $null
}

function Test-PimLongRunRunning {
    <# PURE. A run record that is going now: status 'running' (the tick's start record), no finish time. #>
    param([AllowNull()][object]$Run)
    if ($null -eq $Run) { return $false }
    if ("$($Run.status)".Trim() -notmatch '^(?i)running$') { return $false }
    if ($Run.PSObject.Properties['finishedUtc'] -and "$($Run.finishedUtc)".Trim()) { return $false }
    return ($null -ne (ConvertTo-PimLongRunUtc $Run.startedUtc))
}

function Test-PimLongRunCompleted {
    <# PURE. A FINISHED run that did its work (the "Succeeded" of the usual length): not running / failed / skipped /
       cancelled / interrupted / throttled / held, and not ok=false. A run that ended with a warning did its work: counted. #>
    param([AllowNull()][object]$Run)
    if ($null -eq $Run) { return $false }
    $st = "$($Run.status)".Trim().ToLowerInvariant()
    if ($st -in @('', 'running', 'failed', 'skipped', 'unimplemented', 'outofscope', 'disabled', 'cancelled', 'interrupted', 'throttled', 'held', 'queued')) { return $false }
    if ($Run.PSObject.Properties['ok'] -and $null -ne $Run.ok -and -not [bool]$Run.ok) { return $false }
    if ($Run.PSObject.Properties['held'] -and [bool]$Run.held) { return $false }
    return ($null -ne (ConvertTo-PimLongRunUtc $Run.finishedUtc))
}

function ConvertTo-PimLongRunExecutions {
    <# PURE. The run history of ONE job (by name) -> the executions shape Get-PimSchemaQuiesceUsualSeconds reads:
       @{ name; status = 'Succeeded'; startUtc; endUtc } for every completed run (others are left out). #>
    param([AllowNull()][object[]]$Runs, [Parameter(Mandatory)][string]$Job)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Runs)) {
        if ($null -eq $r -or "$($r.name)".Trim() -ne "$Job".Trim()) { continue }
        if (-not (Test-PimLongRunCompleted -Run $r)) { continue }
        $out.Add([pscustomobject]@{ name = "$($r.runId)"; status = 'Succeeded'; startUtc = (ConvertTo-PimLongRunUtc $r.startedUtc); endUtc = (ConvertTo-PimLongRunUtc $r.finishedUtc) })
    }
    return @($out.ToArray())
}

function Compare-PimLongRunVersion {
    <# PURE. -1 / 0 / 1 for dotted numeric versions (a pre-release suffix is ignored), $null when either is not one. #>
    param([AllowNull()][string]$A, [AllowNull()][string]$B)
    $p = { param($v) $t = ("$v".Trim() -replace '^[vV]', '') -replace '[-+].*$', ''; if ($t -notmatch '^\d+(\.\d+){0,3}$') { return $null }; @($t.Split('.') | ForEach-Object { [long]$_ }) }
    $x = & $p $A; $y = & $p $B
    if ($null -eq $x -or $null -eq $y) { return $null }
    $n = [math]::Max($x.Count, $y.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $xi = $(if ($i -lt $x.Count) { $x[$i] } else { 0 }); $yi = $(if ($i -lt $y.Count) { $y[$i] } else { 0 })
        if ($xi -lt $yi) { return -1 }; if ($xi -gt $yi) { return 1 }
    }
    return 0
}

function Get-PimLongRunNewerWaiting {
    <# PURE. The approved version when it is NEWER than the version the run started on ('' / unreadable = $null). #>
    param([AllowNull()][string]$ApprovedVersion, [AllowNull()][string]$RunVersion)
    $ap = "$ApprovedVersion".Trim()
    if (-not $ap -or $ap.Length -gt 50 -or $ap -notmatch '^[0-9A-Za-z][0-9A-Za-z.+-]*$') { return $null }
    $c = Compare-PimLongRunVersion -A $ap -B "$RunVersion"
    if ($c -eq 1) { return $ap }
    return $null
}

function Get-PimLongRunProgressMap {
    <# PURE. The scheduler's lock map (Get-PimSchedulerLocksRaw .Map: area -> { owner; runId; acquiredUtc; progressUtc })
       -> @{ runId = newest of progressUtc / acquiredUtc } (the run's last "still alive" mark). Anything unreadable is skipped. #>
    param([AllowNull()][object]$Map)
    $out = @{}
    if ($null -eq $Map) { return $out }
    $entries = @()
    if ($Map -is [System.Collections.IDictionary]) { $entries = @($Map.Values) } else { $entries = @($Map.PSObject.Properties | ForEach-Object { $_.Value }) }
    foreach ($l in $entries) {
        if ($null -eq $l) { continue }
        $get = { param($k) if ($l -is [System.Collections.IDictionary]) { if ($l.Contains($k)) { $l[$k] } else { $null } } elseif ($l.PSObject.Properties[$k]) { $l.$k } else { $null } }
        $rid = "$(& $get 'runId')".Trim(); if (-not $rid) { continue }
        foreach ($k in 'progressUtc', 'acquiredUtc') {
            $t = ConvertTo-PimLongRunUtc (& $get $k)
            if ($null -ne $t -and (-not $out.ContainsKey($rid) -or $t -gt $out[$rid])) { $out[$rid] = $t }
        }
    }
    return $out
}

function Get-PimLongRunVerdict {
    <#
      PURE. One running run -> the longRun object, or $null when its usual length is not known (no completed run yet).
      -UsualSeconds: Get-PimSchemaQuiesceUsualSeconds of its job; -LastProgressUtc: its last progress mark ($null = not
      readable = never 'stuck'); -NewerWaiting: Get-PimLongRunNewerWaiting. action is ALWAYS 'none' (report only).
    #>
    param([Parameter(Mandatory)][object]$Run, [AllowNull()][object]$UsualSeconds, [AllowNull()][object]$LastProgressUtc,
          [AllowNull()][string]$NewerWaiting = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $st = ConvertTo-PimLongRunUtc $Run.startedUtc
    if ($null -eq $st -or $null -eq $UsualSeconds -or [int]$UsualSeconds -le 0) { return $null }
    # every operand a [double]: [math]::Min / Max with an [int] first argument picks the INTEGER overload and rounds the
    # ratio to a whole number (1.25 -> 1) -- measured in the suite
    $max = [double](Get-PimLongRunMaxMinutes)
    $ageMin = [math]::Min($max, [math]::Max([double]0, [math]::Round([double]($now - $st).TotalMinutes, 1)))
    $usualMin = [math]::Min($max, [math]::Max([double]0.1, [math]::Round([double][int]$UsualSeconds / 60.0, 1)))
    $ratio = [math]::Min([double]10000, [math]::Round([double]($now - $st).TotalSeconds / [double][int]$UsualSeconds, 2))
    if ($ratio -lt 0) { $ratio = [double]0 }
    $state = 'ok'
    if ($ratio -ge (Get-PimLongRunLongFactor)) { $state = 'long' }
    $h = Get-PimSchemaQuiesceHung -Run ([pscustomobject]@{ job = "$($Run.name)"; execution = "$($Run.runId)"; startUtc = $st }) -UsualSeconds ([int]$UsualSeconds) -LastLogUtc $LastProgressUtc -NowUtc $now
    if ($h.hung) { $state = 'stuck' }
    $nw = $null; if ("$NewerWaiting".Trim()) { $nw = "$NewerWaiting".Trim() }
    return [pscustomobject][ordered]@{ usualMin = $usualMin; ageMin = $ageMin; ratio = $ratio; state = $state; newerWaiting = $nw; action = 'none'
                                       at = $now.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") }
}

function ConvertTo-PimLongRunStep {
    <# PURE. The step name Invardia shows: 'pim-' + the run TYPE (a product word, never a name a customer typed). '' = none. #>
    param([AllowNull()][object]$Run)
    $t = "$($Run.type)".Trim().ToLowerInvariant()
    $t = ($t -replace '[^a-z0-9-]', '-').Trim('-')
    if (-not $t) { return '' }
    $s = "pim-$t"; if ($s.Length -gt 60) { $s = $s.Substring(0, 60).Trim('-') }
    return $s
}

function Get-PimPipelineStates { <# PURE. LITERAL. Invardia's closed list of Pipeline.state (SI's spec, the same for PIM). #> return @('running', 'idle', 'failed', 'succeeded', 'stopped') }
function Get-PimPipelineFieldNames {
    <# PURE. LITERAL. The Pipeline keys PIM sends -- a subset of Invardia's spec (runId, state, startedUtc, step, stepSinceUtc,
       lastEndedUtc, nextStartUtc, stepsDone, stepsTotal, longRun, ...). nextStartUtc / stepsDone / stepsTotal are NOT sent:
       PIM does not know them truthfully for an engine run, and a key is never invented. #>
    return @('runId', 'state', 'startedUtc', 'step', 'stepSinceUtc', 'lastEndedUtc', 'longRun', 'stalledSteps')
}

function Get-PimStallTriggers { <# PURE. LITERAL. STALL-1: the closed list of stall triggers. #> return @('no-progress', 'over-2x-usual') }

function ConvertTo-PimStallSlug {
    <# PURE. A lower-case [a-z0-9-] word of at most 60 characters ('' = none) -- Invardia's step / job shape. #>
    param([AllowNull()][object]$Value)
    $s = ("$Value".Trim().ToLowerInvariant() -replace '[^a-z0-9-]', '-') -replace '-{2,}', '-'
    $s = $s.Trim('-'); if ($s.Length -gt 60) { $s = $s.Substring(0, 60).Trim('-') }
    return $s
}

function New-PimUplinkStalledFields {
    <#
      PURE. STALL-1 (framework 8.18 "STALLED is not died"; Invardia decision 2026-11-10: the Pipeline contract is CLOSED) --
      the stalled runs (Get-PimStalledRuns, PIM-JobLanes.ps1) -> { stalledSteps } for Invardia's Fleet display, exactly
      Invardia's agreed item [{ step; sinceUtc; lastProgressUtc }] (lastProgressUtc null = no progress since the run
      started), or $null when none is stalled (the key is then LEFT OUT: the stall cleared itself). The ticket comes from
      the stall's RUN REPORT (Register-PimStallRunReport), not from here.
      Privacy: step is the engine scope the run is on (its StepsOk name) when recorded, else the area word it works on
      (groups, entra-roles, ...), else a SHIPPED job name
      (-ProductJobNames) or 'pim-<type>' -- never a name a customer typed. At most 12, longest stall first.
      REPORT ONLY: nothing here, or anywhere in the heartbeat, stops or cancels a run (PIM 100.166 (c)).
    #>
    param([AllowNull()][object[]]$Stalled, [AllowNull()][string[]]$ProductJobNames = @())
    $prod = @{}; foreach ($n in @($ProductJobNames)) { if ("$n".Trim()) { $prod["$n".Trim().ToLowerInvariant()] = $true } }
    $iso = { param($v) $d = ConvertTo-PimLongRunUtc $v; if ($null -eq $d) { $null } else { $d.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") } }
    $rows = @(@($Stalled) | Where-Object { $null -ne $_ -and "$($_.trigger)" -in (Get-PimStallTriggers) -and $null -ne (ConvertTo-PimLongRunUtc $_.sinceUtc) } |
              Sort-Object @{ Expression = { [int]$(if ("$($_.trigger)" -eq 'no-progress') { $_.minutes } else { $_.runMinutes }) }; Descending = $true } |
              Select-Object -First 12)   # Invardia: stalledSteps max 12 (a literal: this file does not need PIM-JobLanes.ps1)
    if (-not $rows.Count) { return $null }
    $steps = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        # the engine scope it is on (the StepsOk name) when recorded, else the area it works on
        $step = ConvertTo-PimStallSlug $(if ($r.PSObject.Properties['scope'] -and "$($r.scope)".Trim()) { $r.scope } else { $r.step })
        if (-not $step) {
            $jn = "$($r.job)".Trim()
            if ($jn -and $prod.ContainsKey($jn.ToLowerInvariant())) { $step = ConvertTo-PimStallSlug $jn }
            else { $t = ConvertTo-PimStallSlug $r.type; $step = $(if ($t) { "pim-$t" } else { 'pim-job' }) }
        }
        $steps.Add([pscustomobject][ordered]@{ step = $step; sinceUtc = (& $iso $r.sinceUtc); lastProgressUtc = (& $iso $r.lastProgressUtc) })
    }
    return [pscustomobject][ordered]@{ stalledSteps = [object[]]$steps.ToArray() }
}

function Get-PimPipelineLastEnded {
    <#
      PURE. The last FINISHED engine run (engine-delta / engine-full / msp-pull) in the run history: @{ endUtc; state }, or
      $null when none is recorded. A run that did nothing (skipped / held / queued / unimplemented / out of scope / disabled)
      is not "a run that ended". state: succeeded (completed, a warning included) | failed | stopped (interrupted / cancelled
      / throttled). The end time is the record's own finishedUtc -- never a guess.
    #>
    param([AllowNull()][object[]]$Runs)
    $types = Get-PimLongRunEngineTypes
    $best = $null; $bestEnd = $null
    foreach ($r in @($Runs)) {
        if ($null -eq $r) { continue }
        $ty = "$($r.type)".Trim(); if ($ty -and $ty -notin $types) { continue }
        $st = "$($r.status)".Trim().ToLowerInvariant()
        if ($st -in @('', 'running', 'skipped', 'held', 'queued', 'unimplemented', 'outofscope', 'disabled')) { continue }
        if ($r.PSObject.Properties['held'] -and [bool]$r.held) { continue }
        $e = ConvertTo-PimLongRunUtc $r.finishedUtc
        if ($null -eq $e) { continue }
        if ($null -eq $bestEnd -or $e -gt $bestEnd) { $best = $r; $bestEnd = $e }
    }
    if ($null -eq $best) { return $null }
    $bs = "$($best.status)".Trim().ToLowerInvariant()
    $state = 'succeeded'
    if ($bs -in @('interrupted', 'cancelled', 'throttled')) { $state = 'stopped' }
    elseif ($bs -eq 'failed' -or ($best.PSObject.Properties['ok'] -and $null -ne $best.ok -and -not [bool]$best.ok)) { $state = 'failed' }
    return [pscustomobject]@{ endUtc = $bestEnd; state = $state }
}

function ConvertTo-PimPipelineRunId {
    <# PURE. The run id Invardia keys a run by: the Container Apps EXECUTION name when the record carries a plain one, else the
       engine's run id, else <step>:<start>. Invardia's shape: ^[A-Za-z0-9._:-]{1,64}$. #>
    param([Parameter(Mandatory)][object]$Run, [AllowEmptyString()][string]$Step = '')
    foreach ($c in @($(if ($Run.PSObject.Properties['execution']) { "$($Run.execution)" } else { '' }), "$($Run.runId)")) {
        $v = "$c".Trim(); if ($v -match '^[A-Za-z0-9._:-]{1,64}$') { return $v }
    }
    $st = ConvertTo-PimLongRunUtc $Run.startedUtc
    return "$(if ($Step) { $Step } else { 'pim-run' }):$($st.ToString('yyyyMMddTHHmmssZ'))"
}

function New-PimUplinkPipelineField {
    <#
      PURE. The heartbeat's Pipeline -- on EVERY identified heartbeat (Invardia's PIM contract = SI's Pipeline spec):
        an engine run going    { runId; state 'running'; startedUtc; step; stepSinceUtc; lastEndedUtc?; longRun? }
                               (longRun only when the job's usual length is known)
        nothing going          { state = the last finished engine run's outcome (succeeded | failed | stopped); lastEndedUtc }
                               or { state 'idle' } when the history holds no finished engine run (lastEndedUtc left OUT)
      -Runs        the run history (Get-PimJobRunHistory); the caller passes it only when it was READ ($null here = no field)
      -UpdateState the environment's UpdateState (approvedVersion / runningVersion) -- object, JSON text or $null
      -Progress    @{ runId = [datetime] last progress } (Get-PimLongRunProgressMap); $null = not readable
      -Stalled     STALL-1: New-PimUplinkStalledFields' object ({ stalledSteps }) -- the key is added, in any state, while
                   a run is stalled; $null = none stalled = left out
      'state' is always present; only Get-PimPipelineFieldNames keys are ever sent; times ISO-8601 UTC to the second.
    #>
    param([AllowNull()][object[]]$Runs, [AllowNull()][object]$UpdateState = $null, [AllowNull()][hashtable]$Progress = $null,
          [datetime]$NowUtc = [datetime]::UtcNow, [AllowNull()][object]$Stalled = $null)
    $now = $NowUtc.ToUniversalTime()
    $iso = { param($d) $d.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") }
    $addStall = { param($o)
        if ($null -ne $Stalled -and $Stalled.PSObject.Properties['stalledSteps'] -and @($Stalled.stalledSteps).Count) {
            $o['stalledSteps'] = [object[]]@($Stalled.stalledSteps)
        }
        [pscustomobject]$o }
    $types = Get-PimLongRunEngineTypes
    $last = Get-PimPipelineLastEnded -Runs $Runs
    $running = @(@($Runs) | Where-Object { (Test-PimLongRunRunning -Run $_) -and ("$($_.type)".Trim() -in $types -or -not "$($_.type)".Trim()) })
    if (-not $running.Count) {
        if ($null -eq $last) { return (& $addStall ([ordered]@{ state = 'idle' })) }
        return (& $addStall ([ordered]@{ state = $last.state; lastEndedUtc = (& $iso $last.endUtc) }))
    }
    $us = $UpdateState
    try { if ($us -is [string]) { $us = $(if ("$us".Trim().StartsWith('{')) { "$us" | ConvertFrom-Json } else { $null }) } } catch { $us = $null }
    $usGet = { param($k) if ($null -eq $us) { '' } elseif ($us -is [System.Collections.IDictionary]) { if ($us.Contains($k)) { "$($us[$k])" } else { '' } } elseif ($us.PSObject.Properties[$k]) { "$($us.$k)" } else { '' } }
    $approved = & $usGet 'approvedVersion'; $runningVer = & $usGet 'runningVersion'
    $best = $null; $bestRatio = -1.0; $bestStart = $null
    foreach ($r in $running) {
        $usual = Get-PimSchemaQuiesceUsualSeconds -Executions @(ConvertTo-PimLongRunExecutions -Runs $Runs -Job "$($r.name)")
        $prog = $null; if ($null -ne $Progress -and "$($r.runId)".Trim() -and $Progress.ContainsKey("$($r.runId)".Trim())) { $prog = $Progress["$($r.runId)".Trim()] }
        $rv = $(if ($r.PSObject.Properties['version'] -and "$($r.version)".Trim()) { "$($r.version)".Trim() } else { $runningVer })
        $lr = Get-PimLongRunVerdict -Run $r -UsualSeconds $usual -LastProgressUtc $prog -NewerWaiting (Get-PimLongRunNewerWaiting -ApprovedVersion $approved -RunVersion $rv) -NowUtc $now
        $ratio = $(if ($null -ne $lr) { [double]$lr.ratio } else { -0.5 })
        $st = ConvertTo-PimLongRunUtc $r.startedUtc
        if ($null -eq $best -or $ratio -gt $bestRatio -or ($ratio -eq $bestRatio -and $st -lt $bestStart)) { $best = [pscustomobject]@{ run = $r; longRun = $lr }; $bestRatio = $ratio; $bestStart = $st }
    }
    $r = $best.run
    $step = ConvertTo-PimLongRunStep -Run $r
    $st = ConvertTo-PimLongRunUtc $r.startedUtc
    $out = [ordered]@{ runId = (ConvertTo-PimPipelineRunId -Run $r -Step $step); state = 'running'; startedUtc = (& $iso $st) }
    # the whole engine run is ONE step: the step started when the run did
    if ($step) { $out['step'] = $step; $out['stepSinceUtc'] = (& $iso $st) }
    if ($null -ne $last) { $out['lastEndedUtc'] = (& $iso $last.endUtc) }
    if ($null -ne $best.longRun) { $out['longRun'] = $best.longRun }
    return (& $addStall $out)
}