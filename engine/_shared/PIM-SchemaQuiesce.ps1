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
                                  the next updater run tries again
    executions NOT READABLE    -> CONSERVATIVE: counted as running (waited for, then deferred) and said so in the line

  While the updater waits it holds the scheduled jobs: pim.Settings 'UpdateSchemaHold' { setUtc; untilUtc; by; reason }.
  The tick (tools/pim-scheduler/Start-PimScheduler.ps1 -Once) and the managed-tenant pull (downlink-job-entry.ps1) read it
  at their start and skip that run with one line (Test-PimSchemaHoldActive). The hold expires by itself
  (Get-PimSchemaQuiesceHoldMinutes) so an updater that dies cannot stop the engine for longer; the updater clears it when
  its run ends (every exit path records its outcome, and the clear rides on that).
  NEVER stops or cancels a running execution: this file has no write to ARM at all.

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
        return [pscustomobject]@{ action = 'defer'; reason = $r; line = "schema quiesce: $r -- the database is NOT changed and nothing is rolled; the next update run tries again (nothing was stopped)" }
    }
    return [pscustomobject]@{ action = 'wait'; reason = ($what -join '; '); line = "schema quiesce: waiting ($mins of $([math]::Round($MaxWaitSeconds / 60.0, 1)) min) -- $($what -join '; ')" }
}

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
      Returns @{ go; action (go|defer); line; waitedSeconds; reads; held; holdNote }. The hold is SET before the first read
      and stays set on 'go' (the caller lifts it when its run ends); on 'defer' or a throw it is lifted here.
      NEVER stops, cancels or writes to any execution.
    #>
    param([AllowNull()][string[]]$Jobs, [Parameter(Mandatory)][scriptblock]$ReadExecutions, [AllowNull()][scriptblock]$SetHold = $null,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Now = { [datetime]::UtcNow }, [scriptblock]$Log = $null,
          [int]$MaxWaitSeconds = ((Get-PimSchemaQuiesceWaitMinutes) * 60), [int]$PollSeconds = (Get-PimSchemaQuiescePollSeconds),
          [AllowEmptyString()][string]$By = '', [switch]$NoHold)
    $t0 = ([datetime](& $Now)).ToUniversalTime()
    $out = [ordered]@{ go = $false; action = 'defer'; line = ''; waitedSeconds = 0; reads = 0; held = $false; holdNote = '' }
    $keep = $false
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
            $d = Get-PimSchemaQuiesceDecision -State $st -WaitedSeconds $waited -MaxWaitSeconds $MaxWaitSeconds
            $out.waitedSeconds = $waited; $out.line = $d.line; $out.action = $d.action
            if ($d.action -eq 'go') { $out.go = $true; $keep = $true; break }
            if ($d.action -eq 'defer') { break }
            if ($Log -and ($out.reads -eq 1 -or ($out.reads % 4) -eq 0)) { & $Log $d.line }
            & $Sleep ([math]::Min($poll, [math]::Max(1, $MaxWaitSeconds - $waited)))
        }
    } catch {
        $out.go = $false; $out.action = 'defer'
        $out.line = "schema quiesce: the check stopped ($((("$($_.Exception.Message)") -split "`n")[0])) -- decided conservatively: the database is NOT changed and nothing is rolled; the next update run tries again"
    } finally {
        if (-not $keep -and $out.held -and $SetHold) {
            try { & $SetHold (New-PimSchemaHoldClearRecord -NowUtc ([datetime](& $Now)) -By $By) | Out-Null; $out.held = $false } catch { $out.holdNote = "the hold could not be lifted ($((("$($_.Exception.Message)") -split "`n")[0])) -- it expires by itself" }
        }
    }
    return [pscustomobject]$out
}
