#Requires -Version 5.1
<#
.SYNOPSIS
  SCHEMA-QUIESCE-818 (framework DOCS/REQUIREMENTS.md 8.18; owner 2026-11-05 "it can destroy schema"): the updater changes
  the database schema only BETWEEN runs of PIM's other jobs, and a waiting update goes first.

.DESCRIPTION
  Before ANY database change the updater makes (the schema step, the access converge in it, the as-built view and
  procedure), it reads the executions of this install's PIM jobs -- the tick, requests, publish, downlink, as-built,
  database job, support consent -- with the SAME ARM read it uses for its own executions (ConvertTo-PimUpdateNowExecutions).

    nothing running            -> go
    something running          -> wait: poll every Get-PimSchemaQuiescePollSeconds, at most Get-PimSchemaQuiesceWaitMinutes
    still running at the bound -> defer: no schema step, no roll; the run ends 'waiting' (not failed), naming the job;
                                  the next 15-minute updater run retries the roll (ROLL-RETRY-1,
                                  PIM-UpdateNow.ps1 Get-PimUpdateRetryDecision; a retry waits at most 5 min)
    executions NOT READABLE    -> CONSERVATIVE: counted as running (waited for, then deferred) and said so in the line

  While the updater waits it holds the scheduled jobs: pim.Settings 'UpdateSchemaHold' { setUtc; untilUtc; by; reason }.
  The tick (tools/pim-scheduler/Start-PimScheduler.ps1 -Once) and the managed-tenant pull (downlink-job-entry.ps1) read it
  at their start and skip that run with one line (Test-PimSchemaHoldActive). The hold expires by itself
  (Get-PimSchemaQuiesceHoldMinutes) so an updater that dies cannot stop the engine for longer; the updater clears it when
  its run ends (every exit path records its outcome, and the clear rides on that).
  NEVER stops or cancels a running execution itself: this file has no write to ARM at all. The ONE exception is ROLL-HUNG-1
  (below): a run that is HUNG by its exact definition is stopped through the caller's -StopExecution seam, never here.

  PURE except Invoke-PimSchemaQuiesce, whose I/O is injected (seams). ASCII; 5.1 + 7. Needs PIM-UpdateNow.ps1 (the
  executions shape) and, for the names, the install-name and database-job resolvers when loaded.
#>
Set-StrictMode -Off

function Get-PimSchemaQuiesceWaitMinutes  { <# PURE. LITERAL. The longest the updater waits for running PIM jobs before it defers. #> return 20 }
function Get-PimSchemaQuiescePollSeconds  { <# PURE. LITERAL. How often it reads the executions again while it waits. #> return 30 }
function Get-PimSchemaQuiesceHoldMinutes  { <# PURE. LITERAL. A hold expires by itself after this (an updater that died cannot stop the engine longer). #> return 90 }
function Get-PimSchemaQuiesceStaleRunHours { <# PURE. LITERAL. A 'Running' execution older than this is presumed hung and does not block. #> return 24 }
function Get-PimSchemaHoldSettingName     { <# PURE. LITERAL. The pim.Settings row the scheduled jobs read at their start. #> return 'UpdateSchemaHold' }
function Get-PimSchemaQuiesceRoles        { <# PURE. LITERAL. The install roles whose jobs must be quiet before a schema change. #> return @('engine', 'requests', 'publish', 'downlink', 'asbuilt', 'dbinit') }

function ConvertTo-PimSchemaQuiesceUtc {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d }
    return $null
}

function Get-PimSchemaQuiesceJobNames {
    <#
      PURE (with -Record). The job names to read: each role's name from the install resolver (the record, else the
      environment, else today's name) plus every name that role can carry (today's and the CR5 one), the database job by
      Get-PimDbInitJobName, the support consent job by Get-PimSupportConsentJobName. When -Existing (the resource group's
      job names) is given, only names that exist there are kept, plus any other job named like a downlink job
      (ca-pim-downlink-* / caj-pim-downlink*). -Self (the updater) is never in the list. Distinct, in that order.
    #>
    param([AllowNull()][object]$Record = $null, [AllowEmptyString()][string]$ManagerApp = '', [AllowNull()][string[]]$Existing = $null,
          [AllowEmptyString()][string]$Self = '')
    $names = New-Object System.Collections.Generic.List[string]
    $add = { param($n) $v = "$n".Trim(); if ($v -and -not ($names | Where-Object { $_ -ieq $v })) { [void]$names.Add($v) } }
    foreach ($role in @(Get-PimSchemaQuiesceRoles)) {
        if ($role -eq 'dbinit' -and (Get-Command Get-PimDbInitJobName -ErrorAction SilentlyContinue)) { & $add (Get-PimDbInitJobName -ManagerApp $ManagerApp -Record $Record) }
        elseif (Get-Command Get-PimInstallName -ErrorAction SilentlyContinue) { & $add (Get-PimInstallName -Role $role -Record $Record) }
        if (Get-Command Get-PimInstallNameCandidates -ErrorAction SilentlyContinue) { foreach ($c in @(Get-PimInstallNameCandidates -Role $role)) { & $add $c } }
    }
    & $add $(if (Get-Command Get-PimSupportConsentJobName -ErrorAction SilentlyContinue) { Get-PimSupportConsentJobName } else { 'caj-pim-supportconsent' })
    $out = @($names.ToArray())
    if ($null -ne $Existing) {
        $ex = @($Existing | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
        $kept = New-Object System.Collections.Generic.List[string]
        foreach ($n in $out) { if ($ex | Where-Object { $_ -ieq $n }) { [void]$kept.Add($n) } }
        foreach ($e in $ex) { if ($e -match '^(?i)(ca-pim-downlink-|caj-pim-downlink)' -and -not ($kept | Where-Object { $_ -ieq $e })) { [void]$kept.Add($e) } }
        $out = @($kept.ToArray())
    }
    $me = "$Self".Trim()
    return @($out | Where-Object { -not $me -or $_ -ine $me })
}

function Get-PimSchemaQuiesceState {
    <#
      PURE. -Reads: one entry per job @{ job; absent ($true = the job does not exist here); executions (ConvertTo-PimUpdateNowExecutions
      shape; $null = NOT readable); error }. Returns @{ running = @(@{ job; execution; startUtc }); unreadable = @(@{ job; error });
      quiet = (none running AND none unreadable) }. Running / Processing count; Unknown counts when it started within the
      stale window (as the updater's own check does); a run older than Get-PimSchemaQuiesceStaleRunHours is presumed hung.
    #>
    param([AllowNull()][object[]]$Reads, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime(); $stale = Get-PimSchemaQuiesceStaleRunHours
    $running = New-Object System.Collections.Generic.List[object]; $unread = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Reads | Where-Object { $null -ne $_ })) {
        if ($r.absent) { continue }
        if ($null -eq $r.executions) { [void]$unread.Add([pscustomobject]@{ job = "$($r.job)"; error = $(if ("$($r.error)".Trim()) { (("$($r.error)" -split "`n")[0]).Trim() } else { 'no answer' }) }); continue }
        foreach ($e in @($r.executions | Where-Object { $null -ne $_ })) {
            $st = "$($e.status)".Trim()
            if ($st -notmatch '^(?i)(Running|Processing|Unknown)$') { continue }
            $t = ConvertTo-PimSchemaQuiesceUtc $e.startUtc
            if ($null -ne $t -and ($now - $t).TotalHours -ge $stale) { continue }
            if ($st -ieq 'Unknown' -and $null -eq $t) { continue }
            [void]$running.Add([pscustomobject]@{ job = "$($r.job)"; execution = "$($e.name)"; startUtc = $t })
        }
    }
    return [pscustomobject]@{ running = @($running.ToArray()); unreadable = @($unread.ToArray()); quiet = ($running.Count -eq 0 -and $unread.Count -eq 0) }
}

function Get-PimSchemaQuiesceDecision {
    <#
      PURE. THE decision. -State (Get-PimSchemaQuiesceState), -WaitedSeconds so far, -MaxWaitSeconds (the bound).
      @{ action = go | wait | defer; reason; line }. Unreadable executions are decided CONSERVATIVELY: as running.
    #>
    param([Parameter(Mandatory)]$State, [int]$WaitedSeconds = 0, [int]$MaxWaitSeconds = ((Get-PimSchemaQuiesceWaitMinutes) * 60))
    $run = @($State.running); $unr = @($State.unreadable)
    $what = @()
    if ($run.Count) { $what += ('running: ' + ((@($run | ForEach-Object { if ($null -ne $_.startUtc) { "{0} ({1}, since {2:u})" -f $_.job, $_.execution, $_.startUtc } else { "{0} ({1})" -f $_.job, $_.execution } })) -join ', ')) }
    if ($unr.Count) { $what += ('not readable, counted as running (conservative): ' + ((@($unr | ForEach-Object { "$($_.job) ($($_.error))" })) -join ', ')) }
    $mins = [math]::Round($WaitedSeconds / 60.0, 1)
    if (-not $run.Count -and -not $unr.Count) {
        return [pscustomobject]@{ action = 'go'; reason = 'no PIM job is running'; line = "schema quiesce: no PIM job is running$(if ($WaitedSeconds -gt 0) { " (after waiting $mins min)" }) -- the update goes first" }
    }
    if ($WaitedSeconds -ge $MaxWaitSeconds) {
        $r = "still busy after $mins min -- $($what -join '; ')"
        return [pscustomobject]@{ action = 'defer'; reason = $r; line = "schema quiesce: $r -- the database is NOT changed and nothing is rolled; the next 15-minute update run retries the roll (nothing was stopped)" }
    }
    return [pscustomobject]@{ action = 'wait'; reason = ($what -join '; '); line = "schema quiesce: waiting ($mins of $([math]::Round($MaxWaitSeconds / 60.0, 1)) min) -- $($what -join '; ')" }
}

# ---- SCHEMA-QUIESCE-LONG-SNAPSHOT (live 2026-11-05, a ~124k-group tenant) ------------------------------------------------
# The active-assignments snapshot in the tick runs well over an hour on a big tenant and logs little while it reads, so a
# 20-minute bound deferred EVERY update there, and a working run looked hung (ops stopped one; never again). Now:
#   (1) when ONE long job is all that runs, the updater waits for it up to that job's usual length (its last successful
#       runs), at most Get-PimSchemaQuiesceLongCapMinutes, saying so; the hold is renewed to cover the longer wait;
#   (2) the snapshot's group read logs a progress line at least every 5 minutes (PIM-Rest.ps1 Invoke-PimGraphBatchGet
#       -ProgressLabel), so a working run is visibly alive;
#   (3) only a run with NO log line for > 30 min AND past 3x its usual length counts as hung -- reported once, never
#       stopped. When its log cannot be read, it is NOT called hung (said so).
function Get-PimSchemaQuiesceLongCapMinutes   { <# PURE. LITERAL. The longest the updater waits for ONE known long job. #> return 180 }
function Get-PimSchemaQuiesceLongMarginMinutes { <# PURE. LITERAL. Added to a long job's usual end before the updater defers. #> return 10 }
function Get-PimSchemaQuiesceUsualRuns        { <# PURE. LITERAL. How many of a job's last successful runs set its usual length. #> return 5 }
function Get-PimSchemaQuiesceHungSilentMinutes { <# PURE. LITERAL. No log line for longer than this (and past 3x usual) = hung. #> return 30 }
function Get-PimSchemaQuiesceHungFactor       { <# PURE. LITERAL. Past this many times its usual length (and silent) = hung. #> return 3 }

function Get-PimSchemaQuiesceUsualSeconds {
    <#
      PURE. A job's usual length in seconds: the LONGEST of its last Get-PimSchemaQuiesceUsualRuns successful runs (newest
      first by start; conservative -- the updater would rather wait a little longer than defer again). $null when the job
      has no finished successful run with both times.
    #>
    param([AllowNull()][object[]]$Executions, [int]$Runs = (Get-PimSchemaQuiesceUsualRuns))
    $done = @(@($Executions | Where-Object { $null -ne $_ -and "$($_.status)" -match '^(?i)Succeeded$' }) | ForEach-Object {
        $s = ConvertTo-PimSchemaQuiesceUtc $_.startUtc; $e = ConvertTo-PimSchemaQuiesceUtc $_.endUtc
        if ($null -ne $s -and $null -ne $e -and $e -gt $s) { [pscustomobject]@{ start = $s; seconds = [int]($e - $s).TotalSeconds } }
    } | Sort-Object start -Descending | Select-Object -First ([math]::Max(1, $Runs)))
    if (-not $done.Count) { return $null }
    return [int](@($done | Measure-Object seconds -Maximum).Maximum)
}

function Get-PimSchemaQuiesceLongWait {
    <#
      PURE. When ONE job runs (one execution, nothing unreadable) and its usual length is known and longer than the normal
      bound, the bound becomes: (its start + usual length + margin) - the updater's start, never below -BaseSeconds, never
      above -CapSeconds. @{ extend; seconds; job; execution; usualSeconds; line }. Anything else: extend = $false (the
      normal 20-minute bound applies).
    #>
    param([Parameter(Mandatory)]$State, [AllowNull()][object[]]$Reads, [Parameter(Mandatory)][datetime]$StartUtc,
          [int]$BaseSeconds = ((Get-PimSchemaQuiesceWaitMinutes) * 60), [int]$CapSeconds = ((Get-PimSchemaQuiesceLongCapMinutes) * 60),
          [int]$MarginSeconds = ((Get-PimSchemaQuiesceLongMarginMinutes) * 60))
    $no = [pscustomobject]@{ extend = $false; seconds = $BaseSeconds; job = ''; execution = ''; usualSeconds = $null; line = '' }
    $run = @($State.running); if ($run.Count -ne 1 -or @($State.unreadable).Count) { return $no }
    $r = $run[0]; if ($null -eq $r.startUtc) { return $no }
    $rd = @($Reads | Where-Object { $null -ne $_ -and "$($_.job)" -ieq "$($r.job)" } | Select-Object -First 1)
    if (-not $rd.Count) { return $no }
    $usual = Get-PimSchemaQuiesceUsualSeconds -Executions @($rd[0].executions)
    if ($null -eq $usual -or $usual -le $BaseSeconds) { return $no }
    $want = [int](($r.startUtc.ToUniversalTime().AddSeconds($usual + $MarginSeconds)) - $StartUtc.ToUniversalTime()).TotalSeconds
    $sec = [math]::Min($CapSeconds, [math]::Max($BaseSeconds, $want))
    if ($sec -le $BaseSeconds) { return $no }
    $line = "schema quiesce: {0} ({1}) is a long job -- its usual length is {2} min (its last successful runs), so the update waits for it up to {3} min (at most {4} min) instead of {5}; nothing is stopped" -f $r.job, $r.execution, [math]::Round($usual / 60.0), [math]::Round($sec / 60.0), [math]::Round($CapSeconds / 60.0), [math]::Round($BaseSeconds / 60.0)
    return [pscustomobject]@{ extend = $true; seconds = [int]$sec; job = "$($r.job)"; execution = "$($r.execution)"; usualSeconds = $usual; line = $line }
}

function Get-PimSchemaQuiesceHung {
    <#
      PURE. Is a running execution hung? Only when BOTH: it has run longer than -Factor x its usual length, AND its last log
      line is older than -SilentMinutes. -LastLogUtc $null = the log could not be read -> NOT hung (said so). No usual
      length = NOT hung. @{ hung; past; line }. 'past' = it is past Factor x usual (whatever the log says). Never stops it.
    #>
    param([Parameter(Mandatory)]$Run, [AllowNull()][object]$UsualSeconds, [AllowNull()][object]$LastLogUtc, [datetime]$NowUtc = [datetime]::UtcNow,
          [int]$Factor = (Get-PimSchemaQuiesceHungFactor), [int]$SilentMinutes = (Get-PimSchemaQuiesceHungSilentMinutes))
    $now = $NowUtc.ToUniversalTime(); $st = ConvertTo-PimSchemaQuiesceUtc $Run.startUtc
    $out = [ordered]@{ hung = $false; past = $false; line = '' }
    if ($null -eq $st -or $null -eq $UsualSeconds -or [int]$UsualSeconds -le 0) { return [pscustomobject]$out }
    $ranMin = ($now - $st).TotalMinutes; $usualMin = [int]$UsualSeconds / 60.0
    if ($ranMin -le $Factor * $usualMin) { return [pscustomobject]$out }
    $out.past = $true
    $ll = ConvertTo-PimSchemaQuiesceUtc $LastLogUtc
    if ($null -eq $ll) {
        $out.line = "schema quiesce: {0} ({1}) has run {2} min, past {3}x its usual {4} min; its log could not be read, so it is NOT called hung -- it is not stopped" -f $Run.job, $Run.execution, [math]::Round($ranMin), $Factor, [math]::Round($usualMin)
        return [pscustomobject]$out
    }
    $silent = ($now - $ll).TotalMinutes
    if ($silent -gt $SilentMinutes) {
        $out.hung = $true
        $out.line = "schema quiesce: {0} ({1}) looks HUNG -- {2} min running (usual {3} min) and no log line for {4} min; it is NOT stopped by the updater (an operator decides)" -f $Run.job, $Run.execution, [math]::Round($ranMin), [math]::Round($usualMin), [math]::Round($silent)
    } else {
        $out.line = "schema quiesce: {0} ({1}) runs long ({2} min, usual {3} min) but is alive -- last log line {4} min ago; it is not stopped" -f $Run.job, $Run.execution, [math]::Round($ranMin), [math]::Round($usualMin), [math]::Round($silent)
    }
    return [pscustomobject]$out
}

# ---- ROLL-HUNG-1 (framework, Invardia 2026-11-20; PIM 3.1.60) -- A HUNG RUN NO LONGER HOLDS THE ROLL -----------------------
# Found live 2026-11-20 on a test install: a publish execution sat 'Running' 333 min with ZERO log lines (it normally ends in
# seconds), the quiesce held the roll twice and ring 1 missed its window. An execution is HUNG only when ALL hold:
#   (a) it has run MORE than Get-PimRollHungFactor x its usual length (Get-PimSchemaQuiesceUsualSeconds) AND at least
#       Get-PimRollHungMinMinutes;
#   (b) its log has been READ and holds NO line since its start.
# Then the updater stops that ONE execution (the caller's -StopExecution seam), reads back Stopped, records it, files ONE fix
# request (never an owner mail) and the quiesce no longer waits for it. Fail safe everywhere else:
#   - a run that wrote ANY log line is never stopped, however long it runs (the owner's long-run rule);
#   - a log that cannot be read (a query error, not zero lines) = NOT hung, said as unreadable;
#   - no usual length known = NOT hung;
#   - the stop fails or the read-back is not Stopped = NOT rolled past it: the quiesce holds exactly as before, reported.
function Get-PimRollHungFactor     { <# PURE. LITERAL. Running MORE than this many times its usual length (and silent) = hung. #> return 10 }
function Get-PimRollHungMinMinutes { <# PURE. LITERAL. ...and running at least this many minutes. #> return 120 }
function Get-PimRollHungFixJob     { <# PURE. LITERAL. The uplink job id the fix request is filed under (the updater's run). #> return 'pim-update' }
function Get-PimRollHungStoppedCode    { <# PURE. LITERAL. The fix request's class when the hung run was stopped and read back. #> return 'UPDATE-RUN-HUNG-STOPPED' }
function Get-PimRollHungStopFailedCode { <# PURE. LITERAL. The fix request's class when the stop failed / did not read back Stopped. #> return 'UPDATE-RUN-HUNG-STOP-FAILED' }

function Test-PimRollHungCandidate {
    <#
      PURE. Condition (a) only: @{ candidate; ranMinutes; usualMinutes }. candidate = ran > Factor x usual AND ran >= MinMinutes.
      No start time or no usual length = not a candidate (fail safe).
    #>
    param([Parameter(Mandatory)]$Run, [AllowNull()][object]$UsualSeconds, [datetime]$NowUtc = [datetime]::UtcNow,
          [int]$Factor = (Get-PimRollHungFactor), [int]$MinMinutes = (Get-PimRollHungMinMinutes))
    $out = [ordered]@{ candidate = $false; ranMinutes = $null; usualMinutes = $null }
    $st = ConvertTo-PimSchemaQuiesceUtc $Run.startUtc
    if ($null -eq $st -or $null -eq $UsualSeconds -or [int]$UsualSeconds -le 0) { return [pscustomobject]$out }
    $ran = ($NowUtc.ToUniversalTime() - $st).TotalMinutes; $usual = [int]$UsualSeconds / 60.0
    $out.ranMinutes = [math]::Round($ran, 1); $out.usualMinutes = [math]::Round($usual, 1)
    $out.candidate = [bool]($ran -gt ($Factor * $usual) -and $ran -ge $MinMinutes)
    return [pscustomobject]$out
}

function ConvertTo-PimRollHungLog {
    <#
      PURE. What a -ReadLog seam answered -> @{ readable; lines; error }. Readable ONLY when the answer carries a whole,
      non-negative line count ('lines'); anything else ($null, no count, a non-number) is NOT readable -- never "zero lines".
    #>
    param([AllowNull()][object]$Answer)
    if ($null -eq $Answer) { return [pscustomobject]@{ readable = $false; lines = $null; error = 'no answer' } }
    $get = { param($k) if ($Answer -is [System.Collections.IDictionary]) { if ($Answer.Contains($k)) { $Answer[$k] } else { $null } } elseif ($Answer.PSObject.Properties[$k]) { $Answer.$k } else { $null } }
    $rd = & $get 'readable'
    if ($rd -eq $false) { $e = "$(& $get 'error')".Trim(); return [pscustomobject]@{ readable = $false; lines = $null; error = $(if ($e) { (($e -split "`n")[0]).Trim() } else { 'not readable' }) } }
    $n = & $get 'lines'; $i = [long]-1
    if ($null -eq $n -or -not [long]::TryParse("$n", [ref]$i) -or $i -lt 0) { return [pscustomobject]@{ readable = $false; lines = $null; error = 'the answer holds no line count' } }
    return [pscustomobject]@{ readable = $true; lines = $i; error = '' }
}

function Get-PimRollHungVerdict {
    <#
      PURE. THE decision for ONE running execution: @{ hung; state; line; ranMinutes; usualMinutes }.
        state = not-candidate (condition (a) does not hold) | unreadable (the log could not be read: NOT hung) |
                logging (it wrote log lines: NEVER stopped) | hung (silent since its start, past the bound)
      -Log: ConvertTo-PimRollHungLog's object.
    #>
    param([Parameter(Mandatory)]$Run, [AllowNull()][object]$UsualSeconds, [AllowNull()][object]$Log, [datetime]$NowUtc = [datetime]::UtcNow)
    $c = Test-PimRollHungCandidate -Run $Run -UsualSeconds $UsualSeconds -NowUtc $NowUtc
    $out = [ordered]@{ hung = $false; state = 'not-candidate'; line = ''; ranMinutes = $c.ranMinutes; usualMinutes = $c.usualMinutes }
    if (-not $c.candidate) { return [pscustomobject]$out }
    $what = "{0} ({1}) has run {2} min, more than {3}x its usual {4} min and at least {5} min" -f $Run.job, $Run.execution, [math]::Round([double]$c.ranMinutes), (Get-PimRollHungFactor), [math]::Round([double]$c.usualMinutes, 1), (Get-PimRollHungMinMinutes)
    $lg = $Log; if ($null -eq $lg) { $lg = ConvertTo-PimRollHungLog $null }
    if (-not $lg.readable) {
        $out.state = 'unreadable'
        $out.line = "schema quiesce: $what; its log could not be read ($($lg.error)), so it is NOT called hung and is NOT stopped -- the update keeps waiting for it"
        return [pscustomobject]$out
    }
    if ([long]$lg.lines -gt 0) {
        $out.state = 'logging'
        $out.line = "schema quiesce: $what, but it has written $($lg.lines) log line(s) -- a run that logs is never stopped; the update keeps waiting for it"
        return [pscustomobject]$out
    }
    $out.hung = $true; $out.state = 'hung'
    $out.line = "schema quiesce: $what and has written NO log line since it started -- it is HUNG; the updater stops this one run"
    return [pscustomobject]$out
}

function ConvertTo-PimRollHungPart {
    <#
      PURE. The fix request's item (FailedStep, [a-z0-9.-], at most 60): <job>.<execution suffix>, the job only when it is a
      shipped PIM name (ca-pim-* / caj-pim-*), else 'pim-job' -- never a name a customer typed. -Suffix is added last.
    #>
    param([AllowEmptyString()][string]$Job, [AllowEmptyString()][string]$Execution, [AllowEmptyString()][string]$Suffix = '')
    $j = "$Job".Trim().ToLowerInvariant(); $x = "$Execution".Trim().ToLowerInvariant()
    $js = $(if ($j -match '^(ca|caj)-pim-[a-z0-9-]{1,40}$') { $j } else { 'pim-job' })
    if ($j -and $x.StartsWith("$j-")) { $x = $x.Substring($j.Length + 1) }
    $x = ($x -replace '[^a-z0-9-]', '-').Trim('-'); if (-not $x) { $x = 'run' }
    $p = "$js.$x"; $sf = $(if ("$Suffix".Trim()) { '.' + ("$Suffix".Trim().ToLowerInvariant() -replace '[^a-z0-9-]', '-') } else { '' })
    $max = 60 - $sf.Length; if ($p.Length -gt $max) { $p = $p.Substring(0, $max).TrimEnd('-', '.') }
    return "$p$sf"
}

function Register-PimRollHungReport {
    <#
      ONE fix request per hung execution through the updater's register-once / sent-once run report (Register-PimTrustStaleReport,
      PIM-JobLanes.ps1): job pim-update, item = ConvertTo-PimRollHungPart, since = the execution's start. Stopped and read back
      -> UPDATE-RUN-HUNG-STOPPED; the stop failed -> UPDATE-RUN-HUNG-STOP-FAILED (its own item, '.held'). Never a mail. NEVER
      throws. -GetSetting / -SetSetting: the caller's store seams (passed on only when given). Returns @{ registered; id; reason }.
    #>
    param([Parameter(Mandatory)]$Entry, [scriptblock]$GetSetting = $null, [scriptblock]$SetSetting = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        if (-not (Get-Command Register-PimTrustStaleReport -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ registered = $false; id = ''; reason = 'the run report is not loaded in this process' } }
        $seams = @{}; if ($GetSetting) { $seams['GetSetting'] = $GetSetting }; if ($SetSetting) { $seams['SetSetting'] = $SetSetting }
        $since = "$($Entry.startUtc)"
        if ([bool]$Entry.ok) {
            $part = ConvertTo-PimRollHungPart -Job "$($Entry.job)" -Execution "$($Entry.execution)"
            return (Register-PimTrustStaleReport -Job (Get-PimRollHungFixJob) -Part $part -Code 'UPDATE-RUN-HUNG-STOPPED' -SinceUtc $since -NowUtc $NowUtc @seams)
        }
        $part = ConvertTo-PimRollHungPart -Job "$($Entry.job)" -Execution "$($Entry.execution)" -Suffix 'held'
        return (Register-PimTrustStaleReport -Job (Get-PimRollHungFixJob) -Part $part -Code 'UPDATE-RUN-HUNG-STOP-FAILED' -SinceUtc $since -NowUtc $NowUtc @seams)
    } catch { return [pscustomobject]@{ registered = $false; id = ''; reason = "$($_.Exception.Message)" } }
}

function New-PimRollHungStopRecord {
    <#
      PURE. The record of one stop (or failed stop) the updater keeps in UpdateState 'hungStops' (newest first, at most
      Get-PimRollHungKeep, none older than 30 days) so the Jobs page and the heartbeat can show it. -Previous: the stored list.
    #>
    param([AllowNull()][object[]]$Previous, [Parameter(Mandatory)]$Entry, [datetime]$NowUtc = [datetime]::UtcNow)
    $row = [pscustomobject][ordered]@{ job = "$($Entry.job)"; execution = "$($Entry.execution)"; startUtc = "$($Entry.startUtc)"
        ranMinutes = $Entry.ranMinutes; usualMinutes = $Entry.usualMinutes; stoppedUtc = "$($Entry.stoppedUtc)"
        readBack = "$($Entry.readBack)"; ok = [bool]$Entry.ok; error = "$($Entry.error)" }
    $keep = New-Object System.Collections.Generic.List[object]; [void]$keep.Add($row)
    foreach ($p in @($Previous | Where-Object { $null -ne $_ })) {
        if ("$($p.job)" -eq $row.job -and "$($p.execution)" -eq $row.execution) { continue }
        $t = ConvertTo-PimSchemaQuiesceUtc $p.stoppedUtc
        if ($null -ne $t -and ($NowUtc.ToUniversalTime() - $t).TotalDays -gt 30) { continue }
        if ($keep.Count -lt (Get-PimRollHungKeep)) { [void]$keep.Add($p) }
    }
    return @($keep.ToArray())
}
function Get-PimRollHungKeep { <# PURE. LITERAL. How many stop records UpdateState keeps. #> return 10 }

function New-PimSchemaHoldRecord {
    # PURE. The hold row: set now, expires by itself after -Minutes.
    param([datetime]$NowUtc = [datetime]::UtcNow, [AllowEmptyString()][string]$By = '', [AllowEmptyString()][string]$Reason = '', [int]$Minutes = (Get-PimSchemaQuiesceHoldMinutes))
    $n = $NowUtc.ToUniversalTime()
    return [pscustomobject][ordered]@{ setUtc = $n.ToString('yyyy-MM-ddTHH:mm:ssZ'); untilUtc = $n.AddMinutes($Minutes).ToString('yyyy-MM-ddTHH:mm:ssZ'); by = "$By"; reason = "$Reason" }
}

function New-PimSchemaHoldClearRecord {
    # PURE. The row after the updater lifted the hold (no untilUtc = not active).
    param([datetime]$NowUtc = [datetime]::UtcNow, [AllowEmptyString()][string]$By = '')
    return [pscustomobject][ordered]@{ clearedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); by = "$By" }
}

function Test-PimSchemaHoldActive {
    <#
      PURE. Is the update hold active? -Record: the pim.Settings value (object, hashtable or JSON text; $null = none).
      @{ active; line }. Active = untilUtc in the future. Anything unreadable = NOT active (the job runs as always; the
      updater's own read of the executions still waits for it).
    #>
    param([AllowNull()][object]$Record, [datetime]$NowUtc = [datetime]::UtcNow)
    $rec = $Record
    try { if ($rec -is [string]) { $rec = $(if ("$rec".Trim().StartsWith('{')) { "$rec" | ConvertFrom-Json } else { $null }) } } catch { $rec = $null }
    if ($null -eq $rec) { return [pscustomobject]@{ active = $false; line = '' } }
    $get = { param($k) if ($rec -is [System.Collections.IDictionary]) { if ($rec.Contains($k)) { $rec[$k] } else { $null } } elseif ($rec.PSObject.Properties[$k]) { $rec.$k } else { $null } }
    $until = ConvertTo-PimSchemaQuiesceUtc (& $get 'untilUtc')
    if ($null -eq $until -or $NowUtc.ToUniversalTime() -ge $until) { return [pscustomobject]@{ active = $false; line = '' } }
    $by = "$(& $get 'by')".Trim(); if (-not $by) { $by = 'the updater' }
    return [pscustomobject]@{ active = $true; line = ("skipped: {0} is applying a database update (held since {1}, at most until {2:u}) -- the next run goes ahead" -f $by, "$(& $get 'setUtc')", $until) }
}

function Invoke-PimSchemaQuiesce {
    <#
      Wait until none of -Jobs is running, bounded. Seams:
        -ReadExecutions { param($Job) } -> ARM executions (value[]) | throws (a 404 = the job is not here = not running)
        -SetHold { param($Record) }    -> writes pim.Settings UpdateSchemaHold ($null seam = no store: waits without a hold)
        -Sleep { param($Seconds) }     -Now { } -> [datetime] UTC   -Log { param($Line) }
      Returns @{ go; action (go|defer); line; waitedSeconds; reads; held; holdNote; longWait; maxWaitSeconds; hung (job|execution
      keys); notes (the long-wait / hung lines); stopped / stopFailed (ROLL-HUNG-1 entries); reports (fix request results) }.
      The hold is SET before the first read and stays set on 'go' (the caller lifts it when its run ends); on 'defer' or a
      throw it is lifted here.
      Writes to no execution itself. ROLL-HUNG-1, only when BOTH -ReadLog and -StopExecution are given:
        -ReadLog { param($Job, $Execution, $StartUtc) } -> @{ lines = <count of its log lines since its start> } | throws
                   (a throw, $null or no count = NOT readable = never stopped)
        -StopExecution { param($Job, $Execution) } -> the status read back after the stop ('Stopped' = stopped) | throws
        -ReportHung { param($Entry) } -> one fix request per entry (Register-PimRollHungReport); optional
      Each running execution is judged at most once per call; only one that Get-PimRollHungVerdict calls hung is stopped.
    #>
    param([AllowNull()][string[]]$Jobs, [Parameter(Mandatory)][scriptblock]$ReadExecutions, [AllowNull()][scriptblock]$SetHold = $null,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Now = { [datetime]::UtcNow }, [scriptblock]$Log = $null,
          [int]$MaxWaitSeconds = ((Get-PimSchemaQuiesceWaitMinutes) * 60), [int]$PollSeconds = (Get-PimSchemaQuiescePollSeconds),
          [AllowEmptyString()][string]$By = '', [switch]$NoHold,
          # SCHEMA-QUIESCE-LONG-SNAPSHOT: -LastLog { param($Job, $Execution) } -> the UTC time of that execution's last log line,
          # $null = not readable ($null seam = never readable: nothing is called hung). -NoLongWait keeps the plain bound.
          [AllowNull()][scriptblock]$LastLog = $null, [switch]$NoLongWait,
          # ROLL-HUNG-1 (see above): all three $null = today's behaviour (nothing is ever stopped).
          [AllowNull()][scriptblock]$ReadLog = $null, [AllowNull()][scriptblock]$StopExecution = $null, [AllowNull()][scriptblock]$ReportHung = $null)
    $t0 = ([datetime](& $Now)).ToUniversalTime()
    $out = [ordered]@{ go = $false; action = 'defer'; line = ''; waitedSeconds = 0; reads = 0; held = $false; holdNote = ''
                       longWait = $false; maxWaitSeconds = $MaxWaitSeconds; hung = @(); notes = @(); stopped = @(); stopFailed = @(); reports = @() }
    $keep = $false
    $reported = @{}
    $judged = @{}; $stoppedKeys = @{}
    try {
        if (-not $NoHold) {
            if ($SetHold) {
                try { & $SetHold (New-PimSchemaHoldRecord -NowUtc $t0 -By $By -Reason 'database update') | Out-Null; $out.held = $true }
                catch { $out.holdNote = "the scheduled jobs were NOT held ($((("$($_.Exception.Message)") -split "`n")[0])) -- waiting without a hold" }
            } else { $out.holdNote = 'no store to hold the scheduled jobs in -- waiting without a hold' }
            if ($out.holdNote -and $Log) { & $Log "schema quiesce: $($out.holdNote)" }
        }
        $poll = [math]::Max(1, $PollSeconds)
        while ($true) {
            $reads = @(foreach ($j in @($Jobs | Where-Object { "$_".Trim() })) {
                try { [pscustomobject]@{ job = "$j"; absent = $false; executions = @(ConvertTo-PimUpdateNowExecutions -Items (& $ReadExecutions "$j")); error = '' } }
                catch {
                    $m = "$($_.Exception.Message)"
                    if ($m -match '(?i)\b404\b|ResourceNotFound|NotFound') { [pscustomobject]@{ job = "$j"; absent = $true; executions = @(); error = '' } }
                    else { [pscustomobject]@{ job = "$j"; absent = $false; executions = $null; error = $m } }
                }
            })
            $out.reads++
            $tNow = ([datetime](& $Now)).ToUniversalTime()
            $waited = [int][math]::Max(0, ($tNow - $t0).TotalSeconds)
            $st = Get-PimSchemaQuiesceState -Reads $reads -NowUtc $tNow
            # (0) ROLL-HUNG-1: a run HUNG by the exact definition is stopped (that ONE execution), read back, recorded and
            # reported -- and no longer waited for. Everything that is not proven hung keeps today's behaviour.
            if ($ReadLog -and $StopExecution) {
                foreach ($rr in @($st.running)) {
                    $key = "$($rr.job)|$($rr.execution)"; if ($judged.ContainsKey($key)) { continue }
                    $rdh = @($reads | Where-Object { "$($_.job)" -ieq "$($rr.job)" } | Select-Object -First 1)
                    $us = $(if ($rdh.Count) { Get-PimSchemaQuiesceUsualSeconds -Executions @($rdh[0].executions) } else { $null })
                    if (-not (Test-PimRollHungCandidate -Run $rr -UsualSeconds $us -NowUtc $tNow).candidate) { continue }   # the log is read only for a candidate
                    $judged[$key] = $true
                    $ans = $null; $lg = $null
                    try { $ans = & $ReadLog "$($rr.job)" "$($rr.execution)" $rr.startUtc; $lg = ConvertTo-PimRollHungLog $ans }
                    catch { $lg = [pscustomobject]@{ readable = $false; lines = $null; error = (("$($_.Exception.Message)" -split "`n")[0]).Trim() } }
                    $v = Get-PimRollHungVerdict -Run $rr -UsualSeconds $us -Log $lg -NowUtc $tNow
                    $out.notes += $v.line; if ($Log) { & $Log $v.line }
                    if (-not $v.hung) { continue }
                    $rb = ''; $err = ''
                    try { $rb = "$(& $StopExecution "$($rr.job)" "$($rr.execution)")".Trim() } catch { $err = (("$($_.Exception.Message)" -split "`n")[0]).Trim() }
                    $ok = (-not $err -and $rb -ieq 'Stopped')
                    $entry = [pscustomobject][ordered]@{ job = "$($rr.job)"; execution = "$($rr.execution)"
                        startUtc = $(if ($null -ne $rr.startUtc) { $rr.startUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") } else { '' })
                        ranMinutes = $v.ranMinutes; usualMinutes = $v.usualMinutes; stoppedUtc = ([datetime](& $Now)).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
                        readBack = $rb; ok = $ok; error = $err }
                    if ($ok) {
                        $out.stopped += $entry; $stoppedKeys[$key] = $true
                        $sl = "schema quiesce: {0} ({1}) was stopped and read back Stopped -- the update no longer waits for it; the stuck run is reported" -f $rr.job, $rr.execution
                    } else {
                        $out.stopFailed += $entry
                        $sl = "schema quiesce: {0} ({1}) could NOT be stopped ({2}) -- the update does NOT roll past it and keeps holding exactly as before; reported" -f $rr.job, $rr.execution, $(if ($err) { $err } else { "read back '$(if ($rb) { $rb } else { 'nothing' })', not Stopped" })
                    }
                    $out.notes += $sl; if ($Log) { & $Log $sl }
                    if ($ReportHung) { try { $out.reports += (& $ReportHung $entry) } catch { $out.reports += [pscustomobject]@{ registered = $false; id = ''; reason = "$($_.Exception.Message)" } } }
                }
                if ($stoppedKeys.Count) {
                    $left = @(@($st.running) | Where-Object { -not $stoppedKeys.ContainsKey("$($_.job)|$($_.execution)") })
                    $st = [pscustomobject]@{ running = $left; unreadable = @($st.unreadable); quiet = ($left.Count -eq 0 -and @($st.unreadable).Count -eq 0) }
                }
            }
            # (1) ONE known long job is all that runs: wait for it up to its usual length (once per run), renewing the hold.
            if (-not $NoLongWait -and -not $out.longWait -and $MaxWaitSeconds -gt 0 -and @($st.running).Count) {
                $lw = Get-PimSchemaQuiesceLongWait -State $st -Reads $reads -StartUtc $t0 -BaseSeconds $MaxWaitSeconds
                if ($lw.extend) {
                    $MaxWaitSeconds = [int]$lw.seconds; $out.longWait = $true; $out.maxWaitSeconds = $MaxWaitSeconds
                    $out.notes += $lw.line; if ($Log) { & $Log $lw.line }
                    if ($out.held -and $SetHold) {
                        $holdMin = [math]::Max((Get-PimSchemaQuiesceHoldMinutes), [int][math]::Ceiling(($MaxWaitSeconds - $waited) / 60.0) + 30)
                        try { & $SetHold (New-PimSchemaHoldRecord -NowUtc $tNow -By $By -Reason "database update (waiting for $($lw.job), a long job)" -Minutes $holdMin) | Out-Null }
                        catch { $n = "the hold could not be renewed for the longer wait ($((("$($_.Exception.Message)") -split "`n")[0])) -- it expires at its first time"; $out.notes += $n; if ($Log) { & $Log "schema quiesce: $n" } }
                    }
                }
            }
            # (3) hung = past 3x its usual length AND silent > 30 min in its log -- reported once per execution, never stopped.
            foreach ($rr in @($st.running)) {
                $key = "$($rr.job)|$($rr.execution)"; if ($reported.ContainsKey($key)) { continue }
                $rdh = @($reads | Where-Object { "$($_.job)" -ieq "$($rr.job)" } | Select-Object -First 1)
                $us = $(if ($rdh.Count) { Get-PimSchemaQuiesceUsualSeconds -Executions @($rdh[0].executions) } else { $null })
                if ($null -eq $us) { continue }
                if (-not (Get-PimSchemaQuiesceHung -Run $rr -UsualSeconds $us -LastLogUtc $null -NowUtc $tNow).past) { continue }   # the log is read only for a run already past 3x
                $ll = $null; if ($LastLog) { try { $ll = & $LastLog "$($rr.job)" "$($rr.execution)" } catch { $ll = $null } }
                $h = Get-PimSchemaQuiesceHung -Run $rr -UsualSeconds $us -LastLogUtc $ll -NowUtc $tNow
                if (-not $h.past) { continue }
                $reported[$key] = $true; $out.notes += $h.line; if ($h.hung) { $out.hung += $key }
                if ($Log) { & $Log $h.line }
            }
            $d = Get-PimSchemaQuiesceDecision -State $st -WaitedSeconds $waited -MaxWaitSeconds $MaxWaitSeconds
            $out.waitedSeconds = $waited; $out.line = $d.line; $out.action = $d.action
            if (@($out.stopped).Count) {
                $sn = (@($out.stopped | ForEach-Object { "$($_.job) ($($_.execution))" }) -join ', ')
                if ($d.action -eq 'go') { $out.line = "$($d.line) (after stopping the hung run $sn)" }
                else { $out.line = $d.line.Replace('(nothing was stopped)', "(only the hung run $sn was stopped)") }
            }
            if ($d.action -eq 'go') { $out.go = $true; $keep = $true; break }
            if ($d.action -eq 'defer') { break }
            if ($Log -and ($out.reads -eq 1 -or ($out.reads % 4) -eq 0)) { & $Log $d.line }
            & $Sleep ([math]::Min($poll, [math]::Max(1, $MaxWaitSeconds - $waited)))
        }
    } catch {
        $out.go = $false; $out.action = 'defer'
        $out.line = "schema quiesce: the check stopped ($((("$($_.Exception.Message)") -split "`n")[0])) -- decided conservatively: the database is NOT changed and nothing is rolled; the next 15-minute update run retries the roll"
    } finally {
        if (-not $keep -and $out.held -and $SetHold) {
            try { & $SetHold (New-PimSchemaHoldClearRecord -NowUtc ([datetime](& $Now)) -By $By) | Out-Null; $out.held = $false } catch { $out.holdNote = "the hold could not be lifted ($((("$($_.Exception.Message)") -split "`n")[0])) -- it expires by itself" }
        }
    }
    return [pscustomobject]$out
}

# ---- DBINIT-STEP-FILTER (framework 8.18 amended, Invardia 2026-11-06; PIM 3.0.51) -------------------------------------------
# The database setup job (dbinit-job-entry.ps1) MAY run BESIDE a running PIM pipeline job -- but only the part that changes no
# table or column the run uses: grants and role membership, create-if-missing objects that already exist, and (re)signing a
# procedure the pipeline does not call, the re-sign only while NO Support session is open. Everything else keeps waiting for
# the run end, exactly as above (the updater's quiesce + hold). The job asks for that part with the step filter
#     PIM_DBINIT_STEPS = grants      (per execution; unset or 'all' = every step, today's behaviour, unchanged)
# The rules live HERE, next to the quiesce they extend: which step is which kind (Get-PimDbInitStepClass), what a filter lets
# through (Get-PimSchemaQuiesceDbInitPlan) and whether a re-sign may run now (Get-PimSchemaQuiesceDbInitResign). PURE.
# A grants-only run assumes a run IS going (it never has to read the executions to be safe): it is the part that is safe beside one.
function Get-PimDbInitStepsSettingName { <# PURE. LITERAL. The per-execution setting of the step filter. #> return 'PIM_DBINIT_STEPS' }
function Get-PimDbInitStepIds {
    <# PURE. LITERAL. Every step of the database job, in the order the job runs them. #>
    return @('users', 'schema', 'schema-upgrade', 'statistics', 'access-prerequisites', 'access', 'access-facts', 'access-run2', 'policy-templates', 'mail-templates', 'feature-gates', 'manager-access', 'update-seed', 'drop-old-users', 'support-legacy-owner')
}
function Get-PimDbInitStepClass {
    <#
      PURE. LITERAL. What kind of change a step makes:
        grants   principals, role membership and grants only (users; access = the roles + grants through the signed procedure,
                 which may also re-create / re-sign pim.usp_ApplyAccess -- a procedure only the updater and this job call; that
                 half is decided by Get-PimSchemaQuiesceDbInitResign at run time)
        schema   creates / changes tables, columns, a database setting, or a procedure the pipeline CALLS (base schema, demo
                 tables, statistics = pim.usp_RefreshStatistics, the access facts procedure the engine executes)
        removal  takes roles away from the users the running jobs sign in as (run 2 of the cut-over)
        data     writes rows the running jobs read (templates, feature gates, Manager access, the update ring record)
      An unknown step is 'schema' (the conservative kind: it waits for the run end).
    #>
    param([AllowEmptyString()][string]$Step)
    switch ("$Step".Trim().ToLowerInvariant()) {
        'users'                { return 'grants' }
        'access'               { return 'grants' }
        'access-run2'          { return 'removal' }
        'drop-old-users'       { return 'removal' }   # PIM item 21 (b): the old database users of moved roles
        'support-legacy-owner' { return 'removal' }   # SECAUDIT-1a 4a (104.8): the Support app's legacy standing db_owner, after both proofs
        'policy-templates'     { return 'data' }
        'mail-templates'       { return 'data' }
        'feature-gates'        { return 'data' }
        'manager-access'       { return 'data' }
        'update-seed'          { return 'data' }
        default                { return 'schema' }
    }
}
function ConvertTo-PimDbInitStepFilter {
    <# PURE. The step filter from its setting: '' / 'all' -> all (today's behaviour); 'grants' -> grants. Anything else is REFUSED. @{ ok; filter; reason } #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $v = "$Value".Trim().ToLowerInvariant()
    if ($v -eq '' -or $v -eq 'all') { return [pscustomobject]@{ ok = $true; filter = 'all'; reason = 'every step (no step filter)' } }
    if ($v -eq 'grants') { return [pscustomobject]@{ ok = $true; filter = 'grants'; reason = 'grants only: the part that may run beside a running PIM job (framework 8.18)' } }
    return [pscustomobject]@{ ok = $false; filter = ''; reason = "$(Get-PimDbInitStepsSettingName) is '$("$Value".Trim())' -- it is 'all' or 'grants' (or not set)" }
}
function Get-PimSchemaQuiesceDbInitPlan {
    <#
      PURE. What the database job runs under its step filter.
        -Filter   'all' | 'grants' (ConvertTo-PimDbInitStepFilter)
        -Asked    the steps this execution would run without a filter (Get-PimDbInitStepIds names them)
        -Explicit the steps a STARTER asked for on purpose (a setting given for this run: feature gates, Manager access, the
                  update ring record, run 2). Under 'grants' an explicit ask of any step that is not 'grants' REFUSES the whole
                  run -- nothing is connected to or changed: the starter is told it waits for the run end, never silently
                  dropped. A default step the job's definition carries (the base schema, statistics, templates) is held: not
                  run, said in one line each.
      Returns @{ filter; run[]; held[] (@{ step; class; line }); refused; reason; lines[] }.
    #>
    param([Parameter(Mandatory)][string]$Filter, [AllowNull()][string[]]$Asked = @(), [AllowNull()][string[]]$Explicit = @())
    $ask = @(@($Asked) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Select-Object -Unique)
    $exp = @(@($Explicit) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    $out = [ordered]@{ filter = $Filter; run = @(); held = @(); refused = $false; reason = ''; lines = @() }
    if ($Filter -ne 'grants') { $out.run = $ask; $out.reason = 'every step (no step filter)'; return [pscustomobject]$out }
    $run = New-Object System.Collections.Generic.List[string]; $held = New-Object System.Collections.Generic.List[object]; $bad = New-Object System.Collections.Generic.List[string]
    foreach ($s in $ask) {
        $c = Get-PimDbInitStepClass -Step $s
        if ($c -eq 'grants') { [void]$run.Add($s); continue }
        $why = switch ($c) { 'removal' { 'it takes roles away from the users the running jobs sign in as' } 'data' { 'it writes rows the running jobs read' } default { 'it changes a table, a column, a database setting or a procedure the pipeline calls' } }
        if ($exp -contains $s) { [void]$bad.Add("$s ($why)"); continue }
        [void]$held.Add([pscustomobject]@{ step = $s; class = $c; line = "beside a run: $s REFUSED -- $why; it waits for the run end (SCHEMA-QUIESCE-818: start the job without $(Get-PimDbInitStepsSettingName) between runs)" })
    }
    $out.run = @($run.ToArray()); $out.held = @($held.ToArray())
    if ($bad.Count) {
        $out.refused = $true; $out.run = @()
        $out.reason = "$(Get-PimDbInitStepsSettingName) = grants, but this run also asks for $($bad -join '; ') -- that waits for the run end (SCHEMA-QUIESCE-818); nothing was connected to or changed"
        $out.lines = @("REFUSED: $($out.reason)")
        return [pscustomobject]$out
    }
    $out.reason = "grants only ($(if ($run.Count) { $run -join ', ' } else { 'no grants step asked' })) -- the part that may run beside a running PIM job"
    $out.lines = @(@("step filter: $($out.reason)") + @($held | ForEach-Object { $_.line }))
    return [pscustomobject]$out
}
function Get-PimSchemaQuiesceDbInitResign {
    <#
      PURE. May the grants-only run re-create / re-sign the access procedure NOW? (framework 8.18: a re-sign only while NO
      Support session is open.)
        -Needed        $false = the procedure is current and signed (nothing is re-signed) -> yes
                       $true  = the admin batches would re-create / re-sign it
                       $null  = not known -> no
        -SupportState  Get-PimSupportJitState (engine/_shared/PIM-SupportJit.ps1): installed $false = no session can be open;
                       jitOpen $false = none open; jitOpen $true = open; not read = NOT known -> no re-sign (conservative)
      @{ allow; reason }. Never a guess: anything unreadable keeps the re-sign behind.
    #>
    param([AllowNull()][object]$Needed, [AllowNull()][object]$SupportState)
    if ($Needed -is [bool] -and -not $Needed) { return [pscustomobject]@{ allow = $true; reason = 'nothing to re-sign: the access procedure is current and signed' } }
    if ($null -eq $Needed) { return [pscustomobject]@{ allow = $false; reason = 'whether the access procedure needs a re-sign could not be read -- no re-sign beside a run' } }
    if ($null -eq $SupportState) { return [pscustomobject]@{ allow = $false; reason = 'the Support session state was not read -- the re-sign waits (a re-sign runs only while no Support session is open)' } }
    $g = { param($k) if ($SupportState -is [System.Collections.IDictionary]) { if ($SupportState.Contains($k)) { $SupportState[$k] } else { $null } } elseif ($SupportState.PSObject.Properties[$k]) { $SupportState.$k } else { $null } }
    if ((& $g 'installed') -eq $false) { return [pscustomobject]@{ allow = $true; reason = 'no Support session can be open (time-limited support access is not set up here) -- the access procedure is re-signed' } }
    $open = & $g 'jitOpen'
    if ($open -eq $true) {
        $u = "$(& $g 'jitUntil')".Trim()
        return [pscustomobject]@{ allow = $false; reason = "a Support session is open$(if ($u) { " (until $u)" }) -- the re-sign of the access procedure waits until it is closed; the grants run without it" }
    }
    if ($open -eq $false -and (& $g 'read') -ne $false) { return [pscustomobject]@{ allow = $true; reason = 'no Support session is open -- the access procedure is re-signed' } }
    $p = "$(& $g 'problem')".Trim()
    return [pscustomobject]@{ allow = $false; reason = "the Support session state could not be read$(if ($p) { " ($p)" }) -- the re-sign waits (a re-sign runs only while no Support session is open)" }
}
