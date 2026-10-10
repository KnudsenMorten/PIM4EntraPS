<#
  PIM-LogOnce.ps1 -- §100.46 quieter logs (owner 2026-10-10, "approved 1-3").

  The tick starts every 5 minutes (288 times a day) and its console goes to Log Analytics, which every customer pays for
  per GB. Most of what it printed was the SAME text every run: ~20 "wired" start-up lines, the SQL / managed-identity /
  context diagnostics, and per-run reports that do not change between runs. Two helpers make that quiet WITHOUT losing it:

  * Write-PimStartupLine -- a start-up / diagnostic line. Buffered while the process starts; Complete-PimStartupLog then
    prints the whole start-up block when PIM_LOG_VERBOSE=1, when the block changed since it was last printed, at the first
    start of a UTC day, or when there is no store to remember it in -- otherwise ONE summary line.
  * Write-PimLogOnce -Key -Message -- a message that repeats run after run: printed the first time, again when its text
    changes, when it comes back after a gap, and once a day as "still: <message> (since <time>)".

  🔒 NOTHING IS LOST. A line kept off the console is still written to the information stream with the tag 'PimQuiet', so
  a scheduled job's own run log (Add-PimJobOutputRecord -> the Manager's Logs button) keeps every line.
  🔒 ERRORS ARE NEVER SUPPRESSED: -Level Error always prints and is never remembered. Failures, alerts and the uplink read
  run records in SQL, never the console, so none of them depends on a line this file keeps quiet.
  🔒 OFF UNLESS ARMED. Only the tick (Start-PimScheduler.ps1) sets $global:PIM_LogQuiet; everywhere else (the Manager,
  setup tools, tests) both helpers print exactly as Write-Host / Write-Warning did.
  State: ONE pim.Settings row, 'LogRepeatSeen' (a JSON map, pruned to 7 days / 300 keys; runtime state -- the name ends in
  'Seen', so a configuration backup never holds it). State is kept in $global: (not $script:) so it works from any scope.
#>

function Test-PimLogVerbose {
    if ("$($env:PIM_LOG_VERBOSE)".Trim() -match '^(?i:1|true|yes|on)$') { return $true }
    return ($global:PIM_LogVerbose -eq $true)
}

function Test-PimLogQuietArmed {
    return ($global:PIM_LogQuiet -eq $true -and -not (Test-PimLogVerbose))
}

function Get-PimLogOnceHash {
    # PURE. A short stable hash of a message (what the state remembers instead of the text).
    param([AllowNull()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $b = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$Text")) } finally { $sha.Dispose() }
    return (-join ($b[0..7] | ForEach-Object { $_.ToString('x2') }))
}

function ConvertTo-PimLogOnceUtc {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or -not "$Value".Trim()) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    try { return ([datetime]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal')) } catch { return $null }
}

function Get-PimLogOnceDecision {
    <#
      PURE. Should this occurrence of a repeating message print, and what does the state become?
        first    -- never seen                                  -> print the message
        changed  -- the text differs from the remembered one    -> print the message
        again    -- not seen for -GapHours (it went away)        -> print the message
        reminder -- unchanged, last printed -ReminderHours ago    -> print "still: <message> (since <time>)"
        repeat   -- otherwise                                    -> silent
      dirty = the entry must be saved (a print, or 'seen' older than -SeenRefreshMinutes).
    #>
    param([AllowNull()][object]$Entry, [AllowNull()][string]$Message, [Parameter(Mandatory)][datetime]$NowUtc,
          [double]$ReminderHours = 24, [double]$GapHours = 6, [double]$SeenRefreshMinutes = 30)
    $now = $NowUtc.ToUniversalTime(); $nowS = $now.ToString('o')
    $h = Get-PimLogOnceHash $Message
    $fresh = @{ h = $h; since = $nowS; printed = $nowS; seen = $nowS }
    if ($null -eq $Entry) { return [pscustomobject]@{ print = $true; kind = 'first'; text = "$Message"; entry = $fresh; dirty = $true } }
    $eh = "$($Entry.h)"; $since = ConvertTo-PimLogOnceUtc $Entry.since; $printed = ConvertTo-PimLogOnceUtc $Entry.printed; $seen = ConvertTo-PimLogOnceUtc $Entry.seen
    if ($eh -ne $h -or $null -eq $since -or $null -eq $printed -or $null -eq $seen) {
        return [pscustomobject]@{ print = $true; kind = $(if ($eh -ne $h) { 'changed' } else { 'first' }); text = "$Message"; entry = $fresh; dirty = $true }
    }
    if (($now - $seen).TotalHours -ge $GapHours) { return [pscustomobject]@{ print = $true; kind = 'again'; text = "$Message"; entry = $fresh; dirty = $true } }
    if (($now - $printed).TotalHours -ge $ReminderHours) {
        return [pscustomobject]@{ print = $true; kind = 'reminder'; text = ("still: {0} (since {1}Z)" -f $Message, $since.ToString('yyyy-MM-dd HH:mm'))
                                  entry = @{ h = $h; since = $since.ToString('o'); printed = $nowS; seen = $nowS }; dirty = $true }
    }
    $refresh = (($now - $seen).TotalMinutes -ge $SeenRefreshMinutes)
    $e2 = @{ h = $h; since = $since.ToString('o'); printed = $printed.ToString('o'); seen = $(if ($refresh) { $nowS } else { $seen.ToString('o') }) }
    return [pscustomobject]@{ print = $false; kind = 'repeat'; text = "$Message"; entry = $e2; dirty = $refresh }
}

function ConvertTo-PimLogOnceMap {
    # A stored map (JSON text, a PSCustomObject or a hashtable) -> hashtable of hashtables. Junk -> empty.
    param([AllowNull()][object]$Value)
    $m = @{}
    if ($null -eq $Value) { return $m }
    $v = $Value
    if ($v -is [string]) { if (-not $v.Trim()) { return $m }; try { $v = $v | ConvertFrom-Json } catch { return $m } }
    # (a list of objects, never an array of 2-element arrays: one pair would flatten)
    $pairs = New-Object System.Collections.Generic.List[object]
    if ($v -is [System.Collections.IDictionary]) { foreach ($kk in @($v.Keys)) { $pairs.Add([pscustomobject]@{ k = $kk; e = $v[$kk] }) } }
    else { foreach ($pp in @($v.PSObject.Properties)) { $pairs.Add([pscustomobject]@{ k = $pp.Name; e = $pp.Value }) } }
    foreach ($p in $pairs) {
        $k = "$($p.k)"; $e = $p.e
        if (-not $k -or $null -eq $e) { continue }
        # (PowerShell 7's ConvertFrom-Json turns ISO stamps into DateTime -- keep them as round-trip UTC text)
        $get = { param($n) $x = if ($e -is [System.Collections.IDictionary]) { $e[$n] } elseif ($e.PSObject.Properties[$n]) { $e.$n } else { $null }
                 if ($x -is [DateTimeOffset]) { $x.UtcDateTime.ToString('o') } elseif ($x -is [datetime]) { $x.ToUniversalTime().ToString('o') } else { $x } }
        $m[$k] = @{ h = "$(& $get 'h')"; since = "$(& $get 'since')"; printed = "$(& $get 'printed')"; seen = "$(& $get 'seen')"; day = "$(& $get 'day')" }
    }
    return $m
}

function Limit-PimLogOnceMap {
    # PURE. Drop entries not seen for -KeepDays, then keep the -MaxKeys most recently seen.
    param([hashtable]$Map = @{}, [Parameter(Mandatory)][datetime]$NowUtc, [int]$KeepDays = 7, [int]$MaxKeys = 300)
    $cut = $NowUtc.ToUniversalTime().AddDays(-$KeepDays)
    $rows = foreach ($k in @($Map.Keys)) {
        $s = ConvertTo-PimLogOnceUtc $Map[$k].seen
        if ($null -ne $s -and $s -ge $cut) { [pscustomobject]@{ k = $k; s = $s } }
    }
    $out = @{}
    foreach ($r in @($rows | Sort-Object -Property s -Descending | Select-Object -First $MaxKeys)) { $out[$r.k] = $Map[$r.k] }
    return $out
}

function Get-PimLogOnceState {
    # The in-memory map, read from pim.Settings once per process. No store -> an empty map (and $global:PIM_LogOnceNoStore).
    if ($global:PIM_LogOnceMap -is [hashtable]) {
        if (-not ($global:PIM_LogOnceDirty -is [hashtable])) { $global:PIM_LogOnceDirty = @{} }
        if (-not $global:PIM_LogOnceSavedUtc) { $global:PIM_LogOnceSavedUtc = [datetime]::UtcNow }
        return $global:PIM_LogOnceMap
    }
    $global:PIM_LogOnceMap = @{}; $global:PIM_LogOnceDirty = @{}; $global:PIM_LogOnceNoStore = $true
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { $global:PIM_LogOnceMap = ConvertTo-PimLogOnceMap (Get-PimSetting -Name 'LogRepeatSeen'); $global:PIM_LogOnceNoStore = $false } catch { $global:PIM_LogOnceNoStore = $true }
    }
    if (-not $global:PIM_LogOnceSavedUtc) { $global:PIM_LogOnceSavedUtc = [datetime]::UtcNow }
    return $global:PIM_LogOnceMap
}

function Save-PimLogOnceState {
    # Merge this process's changed keys into the stored map (another execution may have written others), prune, write.
    # Never throws: a lost save only means a line prints once more.
    param([datetime]$NowUtc = [datetime]::UtcNow)
    if (-not ($global:PIM_LogOnceDirty -is [hashtable]) -or $global:PIM_LogOnceDirty.Count -eq 0) { return $false }
    if (-not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) { return $false }
    try {
        $cur = @{}
        if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { try { $cur = ConvertTo-PimLogOnceMap (Get-PimSetting -Name 'LogRepeatSeen') } catch { $cur = @{} } }
        foreach ($k in @($global:PIM_LogOnceDirty.Keys)) { if ($global:PIM_LogOnceMap.ContainsKey($k)) { $cur[$k] = $global:PIM_LogOnceMap[$k] } }
        $cur = Limit-PimLogOnceMap -Map $cur -NowUtc $NowUtc
        Set-PimSetting -Name 'LogRepeatSeen' -Value ($cur | ConvertTo-Json -Depth 4 -Compress) | Out-Null
        $global:PIM_LogOnceDirty = @{}; $global:PIM_LogOnceSavedUtc = [datetime]::UtcNow
        return $true
    } catch { Write-Verbose "[log] LogRepeatSeen not saved: $($_.Exception.Message)"; return $false }
}

function Write-PimQuietLine {
    # Off the console, into the run log: an information record tagged 'PimQuiet' (Add-PimJobOutputRecord stores it and
    # does not echo it; outside a job nothing displays it).
    param([AllowNull()][string]$Text)
    Write-Information -MessageData "$Text" -Tags 'PimQuiet'
}

function Write-PimLogLine {
    param([AllowNull()][string]$Text, [ValidateSet('Info', 'Warning', 'Error')][string]$Level = 'Info', [object]$ForegroundColor = $null)
    if ($Level -eq 'Warning') { Write-Warning "$Text"; return }
    if ($Level -eq 'Error' -and $null -eq $ForegroundColor) { $ForegroundColor = 'Red' }
    if ($null -ne $ForegroundColor -and "$ForegroundColor".Trim()) { Write-Host "$Text" -ForegroundColor $ForegroundColor } else { Write-Host "$Text" }
}

function Write-PimLogOnce {
    <#
      A message that repeats run after run. -Key names WHAT it is about (stable: 'engine.critical-gate',
      'tick.result|<job>'); -Message is the current text. Not armed (anything but the tick) -> always printed.
      -Level Error -> always printed, never remembered.
    #>
    param([Parameter(Mandatory)][string]$Key, [AllowNull()][AllowEmptyString()][string]$Message = '',
          [ValidateSet('Info', 'Warning', 'Error')][string]$Level = 'Info', [object]$ForegroundColor = $null,
          [datetime]$NowUtc = [datetime]::UtcNow)
    if ($Level -eq 'Error' -or -not (Test-PimLogQuietArmed)) { Write-PimLogLine -Text $Message -Level $Level -ForegroundColor $ForegroundColor; return }
    $k = $Key
    if (Get-Command Get-PimSchedulerInstance -ErrorAction SilentlyContinue) { try { $i = "$(Get-PimSchedulerInstance)"; if ($i) { $k = "$i|$Key" } } catch { } }
    if ($k.Length -gt 200) { $k = $k.Substring(0, 160) + '#' + (Get-PimLogOnceHash $k) }
    $map = Get-PimLogOnceState
    $d = Get-PimLogOnceDecision -Entry $(if ($map.ContainsKey($k)) { $map[$k] } else { $null }) -Message $Message -NowUtc $NowUtc
    $map[$k] = $d.entry
    if ($d.dirty) { $global:PIM_LogOnceDirty[$k] = $true }
    if ($d.print) {
        Write-PimLogLine -Text $d.text -Level $Level -ForegroundColor $ForegroundColor
        [void](Save-PimLogOnceState -NowUtc $NowUtc)
    } else {
        Write-PimQuietLine -Text $(if ($Level -eq 'Warning') { "WARNING: $Message" } else { $Message })
        if ($d.dirty -and ([datetime]::UtcNow - [datetime]$global:PIM_LogOnceSavedUtc).TotalMinutes -ge 30) { [void](Save-PimLogOnceState -NowUtc $NowUtc) }
    }
}

function Write-PimTickResultLine {
    <#
      One line per tick result ("  <job>  <detail>"). A FAILED or HELD result always prints; anything else (ran OK,
      skipped -- e.g. "hybrid-ad-* skipped -- On-premises Active Directory ...", waiting, covered) repeats only on change,
      keyed by the job.
    #>
    param([AllowNull()][object]$Result, [string]$Format = '  {0,-20} {1}', [object]$ForegroundColor = $null)
    if ($null -eq $Result) { return }
    $m = $Format -f "$($Result.name)", "$($Result.detail)"
    $loud = (($Result.PSObject.Properties['ok'] -and $Result.ok -eq $false) -or ($Result.PSObject.Properties['held'] -and $Result.held))
    if ($loud) { Write-PimLogLine -Text $m -ForegroundColor $ForegroundColor; return }
    Write-PimLogOnce -Key "tick.result|$($Result.name)" -Message $m -ForegroundColor $ForegroundColor
}

# ---- start-up block ----------------------------------------------------------------------------------------------------

function Write-PimStartupLine {
    <#
      A start-up / diagnostic line ("... wired", "[sql] auth plan", "[mi] token", "[context] LEAN fetch").
      Not armed -> Write-Host (unchanged). Armed: buffered until Complete-PimStartupLog decides; after that, printed when
      the start-up block was printed this run, otherwise kept off the console (still in a job's run log).
    #>
    param([AllowNull()][string]$Message, [object]$ForegroundColor = $null)
    if (-not (Test-PimLogQuietArmed)) { Write-PimLogLine -Text $Message -ForegroundColor $ForegroundColor; return }
    $mode = "$($global:PIM_StartupLogMode)"
    if ($mode -eq 'print') { Write-PimLogLine -Text $Message -ForegroundColor $ForegroundColor; return }
    if ($mode -eq 'quiet') { Write-PimQuietLine -Text $Message; return }
    if (-not ($global:PIM_StartupLogBuffer -is [System.Collections.Generic.List[object]])) { $global:PIM_StartupLogBuffer = New-Object System.Collections.Generic.List[object] }
    $global:PIM_StartupLogBuffer.Add([pscustomobject]@{ text = "$Message"; color = $ForegroundColor })
}

function Get-PimStartupFingerprint {
    # PURE. The hash of a start-up block; a token length is not a change.
    param([string[]]$Lines = @())
    return (Get-PimLogOnceHash ((@($Lines) | ForEach-Object { "$_" -replace '\(len \d+\)', '(len #)' }) -join "`n"))
}

function Get-PimStartupLogDecision {
    <#
      PURE. Print the whole start-up block, or one summary line?
        verbose  -- PIM_LOG_VERBOSE=1 / -Verbose
        no-store -- nothing to remember it in (fail open)
        first    -- never printed
        changed  -- the block differs from the one last printed
        new-day  -- first start of a UTC day
        quiet    -- otherwise
    #>
    param([AllowNull()][object]$Entry, [Parameter(Mandatory)][string]$Fingerprint, [Parameter(Mandatory)][datetime]$NowUtc,
          [bool]$VerboseMode = $false, [bool]$NoStore = $false)
    $day = $NowUtc.ToUniversalTime().ToString('yyyyMMdd')   # not an ISO date: ConvertFrom-Json must not turn it into a DateTime
    $why = if ($VerboseMode) { 'verbose' } elseif ($NoStore) { 'no-store' } elseif ($null -eq $Entry -or -not "$($Entry.h)") { 'first' }
           elseif ("$($Entry.h)" -ne $Fingerprint) { 'changed' } elseif ("$($Entry.day)" -ne $day) { 'new-day' } else { 'quiet' }
    return [pscustomobject]@{ print = ($why -ne 'quiet'); reason = $why; day = $day; printedUtc = $(if ($Entry) { "$($Entry.printed)" } else { '' }) }
}

function Complete-PimStartupLog {
    <#
      End of start-up: print the buffered block (see Get-PimStartupLogDecision) or ONE summary line. -Force prints the
      block whatever the state says (a start that is failing must show everything it did). Idempotent.
    #>
    param([string]$Summary = '[scheduler] started', [switch]$Force, [datetime]$NowUtc = [datetime]::UtcNow)
    $buf = @(); if ($global:PIM_StartupLogBuffer -is [System.Collections.Generic.List[object]]) { $buf = @($global:PIM_StartupLogBuffer.ToArray()) }
    $global:PIM_StartupLogBuffer = $null
    if (-not (Test-PimLogQuietArmed)) { foreach ($b in $buf) { Write-PimLogLine -Text $b.text -ForegroundColor $b.color }; return $null }
    if ($Force) { foreach ($b in $buf) { Write-PimLogLine -Text $b.text -ForegroundColor $b.color }; $global:PIM_StartupLogMode = 'print'; return $null }
    if ("$($global:PIM_StartupLogMode)") { foreach ($b in $buf) { Write-PimStartupLine -Message $b.text -ForegroundColor $b.color }; return $null }
    $key = '__startup'
    if (Get-Command Get-PimSchedulerInstance -ErrorAction SilentlyContinue) { try { $i = "$(Get-PimSchedulerInstance)"; if ($i) { $key = "$i|__startup" } } catch { } }
    $map = Get-PimLogOnceState
    $fp = Get-PimStartupFingerprint -Lines @($buf | ForEach-Object { $_.text })
    $d = Get-PimStartupLogDecision -Entry $(if ($map.ContainsKey($key)) { $map[$key] } else { $null }) -Fingerprint $fp -NowUtc $NowUtc `
            -VerboseMode (Test-PimLogVerbose) -NoStore ([bool]$global:PIM_LogOnceNoStore)
    if ($d.print) {
        $global:PIM_StartupLogMode = 'print'
        foreach ($b in $buf) { Write-PimLogLine -Text $b.text -ForegroundColor $b.color }
        $nowS = $NowUtc.ToUniversalTime().ToString('o')
        $map[$key] = @{ h = $fp; day = $d.day; printed = $nowS; since = $nowS; seen = $nowS }
        $global:PIM_LogOnceDirty[$key] = $true
        [void](Save-PimLogOnceState -NowUtc $NowUtc)
    } else {
        $global:PIM_StartupLogMode = 'quiet'
        foreach ($b in $buf) { Write-PimQuietLine -Text $b.text }
        $at = ConvertTo-PimLogOnceUtc $d.printedUtc
        Write-Host ("{0} -- start-up unchanged ({1} line(s), last printed {2}); PIM_LOG_VERBOSE=1 prints it every run" -f $Summary, $buf.Count, $(if ($at) { $at.ToString('yyyy-MM-dd HH:mm') + 'Z' } else { 'earlier today' })) -ForegroundColor DarkGray
        $e = $map[$key]; if ($e) { $e.seen = $NowUtc.ToUniversalTime().ToString('o'); if (([datetime]::UtcNow - [datetime]$global:PIM_LogOnceSavedUtc).TotalMinutes -ge 30) { $global:PIM_LogOnceDirty[$key] = $true } }
    }
    return $d
}
