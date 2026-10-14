#Requires -Version 5.1
<#
.SYNOPSIS
  PIM 100.72 (6) / framework DOCS/REQUIREMENTS.md 12.21 BLOCKERS-VS-ANOMALIES: ANOMALY DETECTION + the ONE daily
  "Data quality alert" mail. Warnings only -- nothing here ever blocks, holds or fails a run.

.DESCRIPTION
  Owner 2026-10-11: "it can base it on last 3 runs and compare key numbers" / "like anomaly detection". Aligned with
  SecurityInsight #577 (median of the last 3 runs, one daily alert).

    1. KEY NUMBERS PER RUN  every engine run (the tick's engine-delta / engine-full jobs) records, per scope and mode, the
                            numbers that show whether the data looks right: desired (definitions), live (what the tenant
                            holds), remove (what the run would take away) and errors. pim.Settings 'DataQualityRunMetrics'
                            keeps the last 10 runs per scope|mode.
    2. ANOMALY              a number is OFF when it lies outside the expected range around the MEDIAN OF THE LAST 3 RUNS:
                            median +/- max(5, 25 % of the median). Fewer than 3 earlier runs = nothing is judged yet.
    3. LIKELY CAUSE         the settings change log (pim.AuditEvents: settings.*, config.save / restore / undo / import,
                            alerting.save, access.map.save, policy.template.*, ...) between the previous run and this one --
                            who changed what, when -- newest first, at most 3.
    4. NOTES                each anomaly (and every other WARNING another part of PIM hands in: the policy mass-change
                            count / percent triggers, a convergence finding past its grace window) is ONE note in
                            pim.Settings 'DataQualityNotes', de-duplicated by kind + area (a repeat counts up).
    5. ONE DAILY MAIL       job 'data-quality' (daily) sends ONE "Data quality alert" (Alerting event 'data-quality') only
                            when there are notes newer than the last mail -- never a mail per check, never two a day.
                            Headline, each item's value vs the expected range (delta %), the likely cause, the fix.
  Every writer NEVER throws: a data-quality failure must never become a run failure. ASCII only (PS 5.1 reads no-BOM as CP1252).
#>

Set-StrictMode -Off

$script:PimDqMetricsSetting = 'DataQualityRunMetrics'
$script:PimDqNotesSetting   = 'DataQualityNotes'
$script:PimDqStateSetting   = 'DataQualityAlertState'
$script:PimDqAlertEvent     = 'data-quality'
# The key numbers compared (create / update follow commits and are expected to swing; they are not judged).
$script:PimDqKeyNumbers     = @('desired', 'live', 'remove', 'errors')
$script:PimDqHistoryKeep    = 10
$script:PimDqMedianOf       = 3
$script:PimDqToleranceMin   = 5
$script:PimDqTolerancePct   = 25
$script:PimDqNotesMax       = 50
$script:PimDqNoteKeepDays   = 7

function Get-PimDqMedian {
    <# PURE. The median of the numbers (the mean of the middle two for an even count). $null for none. #>
    param([AllowNull()][AllowEmptyCollection()][double[]]$Values)
    $v = @(@($Values) | Where-Object { $null -ne $_ } | Sort-Object)
    if (-not $v.Count) { return $null }
    $m = [int][Math]::Floor($v.Count / 2)
    if ($v.Count % 2) { return [double]$v[$m] }
    return ([double]$v[$m - 1] + [double]$v[$m]) / 2.0
}

function ConvertTo-PimDqMap {
    <# PURE. A stored document (JSON text, PSCustomObject or dictionary) -> an ordered dictionary of its top-level members. #>
    param([AllowNull()][object]$Value)
    $o = [ordered]@{}
    if ($null -eq $Value) { return $o }
    $src = $Value
    if ($Value -is [string]) { if (-not $Value.Trim()) { return $o }; try { $src = $Value | ConvertFrom-Json } catch { return $o } }
    if ($src -is [System.Collections.IDictionary]) { foreach ($k in $src.Keys) { $o["$k"] = $src[$k] } }
    elseif ($src) { foreach ($p in $src.PSObject.Properties) { $o[$p.Name] = $p.Value } }
    return $o
}

function Get-PimDqField {
    param([AllowNull()][object]$Item, [string]$Name)
    if ($null -eq $Item) { return $null }
    if ($Item -is [System.Collections.IDictionary]) { return $Item[$Name] }
    $p = $Item.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Get-PimRunKeyNumbers {
    <#
      PURE. The key numbers of one engine run, per scope: @( @{ key = '<scope>|<mode>'; scope; mode; numbers = @{ desired; live;
      remove; errors } } ). A result that did not read both sides (no desiredCount / liveCount -- an unbound scope, a scope
      that was skipped or NOT CHECKED, a WhatIf plan) is left out: a number nobody measured is never compared.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Results, [string]$Mode = '')
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Results)) {
        if ($null -eq $r) { continue }
        $sc = "$(Get-PimDqField $r 'scope')".Trim(); if (-not $sc) { continue }
        if ([bool](Get-PimDqField $r 'whatIf')) { continue }
        if ([bool](Get-PimDqField $r 'notChecked')) { continue }
        $d = Get-PimDqField $r 'desiredCount'; $l = Get-PimDqField $r 'liveCount'
        if ($null -eq $d -or $null -eq $l) { continue }
        $m = "$(Get-PimDqField $r 'mode')".Trim(); if (-not $m) { $m = "$Mode".Trim() }; if (-not $m) { $m = 'Delta' }
        # PIM 100.146 (a customer 2026-10-14, "AdminMembers live 75, expected 18-28"): a NARROWED live read (only the principals
        # the rows name) and a FULL read (every membership of every owned group) count different things -- each has its own
        # history, so a run that switches read is never judged against the other read's numbers
        $narrow = [bool](Get-PimDqField $r 'liveNarrowed')
        $k = "$sc|$m"; if ($narrow) { $k += '|narrowed' }
        $out.Add(@{ key = $k; scope = $sc; mode = $m; narrowed = $narrow; numbers = [ordered]@{
            desired = [int]$d; live = [int]$l; remove = [int](Get-PimDqField $r 'remove'); errors = [int](Get-PimDqField $r 'errors') } })
    }
    return @($out.ToArray())
}

function Test-PimRunAnomaly {
    <#
      PURE. One run's key numbers against the earlier runs of the same scope|mode (-Previous: newest FIRST, each @{ numbers }).
      Only the last -MedianOf (3) earlier runs count; fewer than that = no judgement (@()). A number is OFF when it lies outside
      median +/- max(-ToleranceMin 5, -TolerancePct 25 % of the median). Returns @( @{ number; value; median; low; high;
      deltaPct (null when the median is 0); direction up|down } ).
    #>
    param([Parameter(Mandatory)][object]$Current, [AllowNull()][AllowEmptyCollection()][object[]]$Previous = @(),
          [int]$MedianOf = $script:PimDqMedianOf, [double]$ToleranceMin = $script:PimDqToleranceMin, [double]$TolerancePct = $script:PimDqTolerancePct,
          [string[]]$Numbers = $script:PimDqKeyNumbers)
    if ($MedianOf -lt 1) { $MedianOf = 3 }
    $prev = @(@($Previous) | Where-Object { $null -ne $_ } | Select-Object -First $MedianOf)
    if ($prev.Count -lt $MedianOf) { return @() }
    $curN = Get-PimDqField $Current 'numbers'; if ($null -eq $curN) { $curN = $Current }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($Numbers)) {
        $cv = Get-PimDqField $curN $k; if ($null -eq $cv) { continue }
        $vals = @($prev | ForEach-Object { $pn = Get-PimDqField $_ 'numbers'; if ($null -eq $pn) { $pn = $_ }; Get-PimDqField $pn $k } | Where-Object { $null -ne $_ } | ForEach-Object { [double]$_ })
        if ($vals.Count -lt $MedianOf) { continue }
        $med = Get-PimDqMedian -Values $vals
        $tol = [Math]::Max($ToleranceMin, [Math]::Abs($med) * $TolerancePct / 100.0)
        $low = $med - $tol; $high = $med + $tol
        $v = [double]$cv
        if ($v -ge $low -and $v -le $high) { continue }
        $out.Add([ordered]@{ number = $k; value = [int]$v; median = $med; low = [Math]::Max(0, [Math]::Ceiling($low)); high = [Math]::Floor($high)
            deltaPct = $(if ($med -ne 0) { [Math]::Round(100.0 * ($v - $med) / [Math]::Abs($med), 1) } else { $null })
            direction = $(if ($v -gt $med) { 'up' } else { 'down' }) })
    }
    return @($out.ToArray())
}

function Select-PimAnomalyLikelyCause {
    <#
      PURE. The likely cause from the settings change log: the audit events (Get-PimSqlAuditEvents shape: ts, actor, action,
      target) whose action is a settings / definition change, between -SinceUtc and -UntilUtc, newest first, at most -Top (3).
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Events = @(), [AllowNull()][object]$SinceUtc, [AllowNull()][object]$UntilUtc, [int]$Top = 3)
    $rx = '^(settings\.|config\.(save|restore|undo|import)|alerting\.save|access\.map\.save|policy\.template\.|discovery\.policy\.save|downlink\.policy\.save|accessreview\.rules\.save|feature)'
    $toUtc = { param($x) if ($null -eq $x -or "$x" -eq '') { return $null }; if ($x -is [datetime]) { return $x.ToUniversalTime() }
               try { return ([datetimeoffset]::Parse("$x", [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime } catch { return $null } }
    $s = & $toUtc $SinceUtc; $u = & $toUtc $UntilUtc
    $hits = foreach ($e in @($Events)) {
        if ($null -eq $e) { continue }
        $a = "$(Get-PimDqField $e 'action')".Trim(); if ($a -notmatch $rx) { continue }
        $t = & $toUtc (Get-PimDqField $e 'ts'); if (-not $t) { continue }
        if ($s -and $t -lt $s) { continue }
        if ($u -and $t -gt $u) { continue }
        [pscustomobject][ordered]@{ ts = $t.ToString('o'); actor = "$(Get-PimDqField $e 'actor')".Trim(); action = $a; target = "$(Get-PimDqField $e 'target')".Trim() }
    }
    return @(@($hits) | Sort-Object { $_.ts } -Descending | Select-Object -First ([Math]::Max(1, $Top)))
}

function Format-PimAnomalyCause {
    <# PURE. One line naming who changed what, when -- or '' when the log names nothing. #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Causes = @())
    $c = @(@($Causes) | Where-Object { $_ })
    if (-not $c.Count) { return '' }
    return (@($c | ForEach-Object { "{0} {1}{2} at {3} UTC" -f $(if ($_.actor) { $_.actor } else { 'someone' }), $_.action, $(if ($_.target) { " ($($_.target))" } else { '' }), ("$($_.ts)".Substring(0, [Math]::Min(16, "$($_.ts)".Length)).Replace('T', ' ')) }) -join '; ')
}

function Add-PimRunMetricsToHistory {
    <#
      PURE. The history document with this run's numbers added, newest first, at most -Keep (10) per scope|mode. Returns
      @{ doc (ordered key -> @( @{ utc; numbers } )); anomalies = @( @{ key; scope; mode; items; previousUtc } ) }. The
      anomalies are judged against the history BEFORE this run is added.
    #>
    param([AllowNull()][object]$History, [AllowNull()][AllowEmptyCollection()][object[]]$Runs = @(), [datetime]$NowUtc = [datetime]::UtcNow, [int]$Keep = $script:PimDqHistoryKeep)
    $doc = ConvertTo-PimDqMap $History
    $an = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Runs)) {
        if ($null -eq $r) { continue }
        $k = "$($r.key)"
        $prev = @(if ($doc.Contains($k)) { @($doc[$k]) | Where-Object { $null -ne $_ } } else { @() })
        $items = @(Test-PimRunAnomaly -Current $r -Previous $prev)
        if ($items.Count) { $an.Add(@{ key = $k; scope = $r.scope; mode = $r.mode; items = $items; previousUtc = "$(if ($prev.Count) { Get-PimDqField $prev[0] 'utc' })" }) }
        $entry = [ordered]@{ utc = $NowUtc.ToUniversalTime().ToString('o'); numbers = $r.numbers }
        $doc[$k] = @(@($entry) + @($prev) | Select-Object -First ([Math]::Max(1, $Keep)))
    }
    return @{ doc = $doc; anomalies = @($an.ToArray()) }
}

function Update-PimDataQualityNotes {
    <#
      PURE. The notes document with one note added: de-duplicated by kind + area (lower-case id), a repeat counts up and keeps
      its first sighting; notes older than -KeepDays (7) are dropped; at most -Max (50), newest kept.
    #>
    param([AllowNull()][object]$Notes, [Parameter(Mandatory)][string]$Kind, [string]$Area = '', [string]$Title = '', [string]$Detail = '',
          [string]$Cause = '', [string]$Fix = '', [AllowNull()][object]$Measured, [datetime]$NowUtc = [datetime]::UtcNow,
          [int]$KeepDays = $script:PimDqNoteKeepDays, [int]$Max = $script:PimDqNotesMax)
    $now = $NowUtc.ToUniversalTime()
    $list = @()
    $src = $Notes; if ($src -is [string]) { try { $src = $src | ConvertFrom-Json } catch { $src = $null } }
    $raw = Get-PimDqField $src 'notes'; if ($null -ne $raw) { $list = @(@($raw) | Where-Object { $null -ne $_ }) }
    $id = ("{0}|{1}" -f "$Kind".Trim(), "$Area".Trim()).ToLowerInvariant()
    $cut = $now.AddDays(-1 * [Math]::Max(1, $KeepDays))
    $keep = New-Object System.Collections.Generic.List[object]
    $old = $null
    foreach ($n in $list) {
        $nid = "$(Get-PimDqField $n 'id')".ToLowerInvariant()
        if ($nid -eq $id) { $old = $n; continue }
        $ls = $null; try { $ls = ([datetimeoffset]::Parse("$(Get-PimDqField $n 'lastSeenUtc')", [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime } catch { $ls = $null }
        if ($ls -and $ls -lt $cut) { continue }
        $keep.Add($n)
    }
    $count = 1; $first = $now.ToString('o')
    if ($old) { $c = 0; [void][int]::TryParse("$(Get-PimDqField $old 'count')", [ref]$c); $count = $c + 1; if ("$(Get-PimDqField $old 'firstSeenUtc')") { $first = "$(Get-PimDqField $old 'firstSeenUtc')" } }
    $note = [ordered]@{ id = $id; kind = "$Kind".Trim(); area = "$Area".Trim(); title = "$Title"; detail = "$Detail"; cause = "$Cause"; fix = "$Fix"
        measured = $Measured; count = $count; firstSeenUtc = $first; lastSeenUtc = $now.ToString('o') }
    $all = @(@($keep.ToArray()) + @([pscustomobject]$note) | Sort-Object { "$(Get-PimDqField $_ 'lastSeenUtc')" } -Descending | Select-Object -First ([Math]::Max(1, $Max)))
    return [pscustomobject]@{ notes = @($all) }
}

function Get-PimDqStoreSeams {
    # The default pim.Settings readers / writers (engine or Manager, whichever is loaded).
    @{
        get = { param($n) if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { Get-PimSetting -Name $n } elseif (Get-Command Get-PimManagerSetting -ErrorAction SilentlyContinue) { Get-PimManagerSetting -Name $n } else { $null } }
        set = { param($n, $v) if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { [void](Set-PimSetting -Name $n -Value $v) } elseif (Get-Command Set-PimManagerSetting -ErrorAction SilentlyContinue) { [void](Set-PimManagerSetting -Name $n -Value $v) } else { throw 'no settings store' } }
    }
}

function Add-PimDataQualityNote {
    <#
      Hand ONE warning to the daily "Data quality alert" (kind + area de-duplicates). NEVER throws; returns $true when stored.
      Seams: -GetSetting { param($Name) } / -SetSetting { param($Name, $Value) }.
    #>
    param([Parameter(Mandatory)][string]$Kind, [string]$Area = '', [string]$Title = '', [string]$Detail = '', [string]$Cause = '', [string]$Fix = '',
          [AllowNull()][object]$Measured, [datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$GetSetting = $null, [scriptblock]$SetSetting = $null)
    try {
        $sm = Get-PimDqStoreSeams
        if (-not $GetSetting) { $GetSetting = $sm.get }; if (-not $SetSetting) { $SetSetting = $sm.set }
        $cur = & $GetSetting $script:PimDqNotesSetting
        $new = Update-PimDataQualityNotes -Notes $cur -Kind $Kind -Area $Area -Title $Title -Detail $Detail -Cause $Cause -Fix $Fix -Measured $Measured -NowUtc $NowUtc
        & $SetSetting $script:PimDqNotesSetting $new
        try { Write-Host ("  [data-quality] warning noted for the daily mail: {0}{1} -- {2}" -f $Kind, $(if ($Area) { " ($Area)" } else { '' }), $Title) -ForegroundColor DarkYellow } catch { }
        return $true
    } catch {
        try { Write-Warning "[data-quality] the warning '$Kind $Area' was NOT stored: $($_.Exception.Message)" } catch { }
        return $false
    }
}

function Save-PimRunMetrics {
    <#
      Engine (the tick's engine handler), after a run that wrote (never a WhatIf plan, never a selection run). Records the key
      numbers, judges each scope against the median of its last 3 runs, and hands every anomaly to the daily mail WITH its
      likely cause. NEVER throws. Returns @{ recorded; anomalies }.
      Seams: -GetSetting / -SetSetting (pim.Settings), -GetEvents { param($FromUtc) } (the audit trail; default
      Get-PimSqlAuditEvents on the engine's store).
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Results = @(), [string]$Mode = '', [datetime]$NowUtc = [datetime]::UtcNow,
          [scriptblock]$GetSetting = $null, [scriptblock]$SetSetting = $null, [scriptblock]$GetEvents = $null)
    $res = [ordered]@{ recorded = 0; anomalies = @() }
    try {
        $sm = Get-PimDqStoreSeams
        if (-not $GetSetting) { $GetSetting = $sm.get }; if (-not $SetSetting) { $SetSetting = $sm.set }
        if (-not $GetEvents) {
            $GetEvents = { param($from)
                $cs = $null
                if ("$($global:PIM_EngineSqlCs)".Trim()) { $cs = "$($global:PIM_EngineSqlCs)" }
                elseif (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
                if (-not $cs -or -not (Get-Command Get-PimSqlAuditEvents -ErrorAction SilentlyContinue)) { return @() }
                @(Get-PimSqlAuditEvents -ConnectionString $cs -FromUtc $from -Top 200 -NoPayload) }
        }
        $runs = @(Get-PimRunKeyNumbers -Results $Results -Mode $Mode)
        if (-not $runs.Count) { return [pscustomobject]$res }
        $u = Add-PimRunMetricsToHistory -History (& $GetSetting $script:PimDqMetricsSetting) -Runs $runs -NowUtc $NowUtc
        & $SetSetting $script:PimDqMetricsSetting ([pscustomobject]$u.doc)
        $res.recorded = $runs.Count
        $res.anomalies = @($u.anomalies)
        foreach ($a in @($u.anomalies)) {
            $since = $null; try { if ("$($a.previousUtc)") { $since = ([datetimeoffset]::Parse("$($a.previousUtc)", [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime } } catch { $since = $null }
            if (-not $since) { $since = $NowUtc.ToUniversalTime().AddDays(-1) }
            $ev = @(); try { $ev = @(& $GetEvents $since.AddMinutes(-5)) } catch { $ev = @() }
            $cause = Format-PimAnomalyCause -Causes @(Select-PimAnomalyLikelyCause -Events $ev -SinceUtc $since.AddMinutes(-5) -UntilUtc $NowUtc)
            $parts = @($a.items | ForEach-Object { "{0} {1} (expected {2}-{3}{4})" -f $_.number, $_.value, $_.low, $_.high, $(if ($null -ne $_.deltaPct) { ", {0:+0.#;-0.#}% vs the median of the last 3 runs" -f $_.deltaPct } else { ', the last 3 runs had 0' }) })
            $meas = @{}; foreach ($i in @($a.items)) { $meas["$($i.number)"] = $i.value; $meas["$($i.number)Median"] = $i.median }
            [void](Add-PimDataQualityNote -Kind 'anomaly' -Area "$($a.scope)" -Title ("{0} ({1}): {2}" -f $a.scope, $a.mode, ($parts -join '; ')) `
                -Detail ("The {0} scope's key numbers moved outside the range of its last 3 runs. Nothing was blocked." -f $a.scope) `
                -Cause $(if ($cause) { "Changed since the previous run: $cause" } else { 'No settings or definition change was recorded since the previous run -- check the tenant side (someone changed it outside PIM Manager) or a failed read.' }) `
                -Fix 'If the change is intended, nothing is needed: the next runs become the new normal. If not, undo the change (Commit history / Backups) and run the scope again from the Jobs page.' `
                -Measured $meas -NowUtc $NowUtc -GetSetting $GetSetting -SetSetting $SetSetting)
        }
    } catch { try { Write-Warning "[data-quality] the run's key numbers were NOT recorded: $($_.Exception.Message)" } catch { } }
    return [pscustomobject]$res
}

function Select-PimDataQualityAlertDue {
    <#
      PURE. The notes the next mail carries: every note seen after the last mail (-State.lastSentUtc). Mail due only when
      there is at least one, and no mail went out on this UTC day yet (ONE a day, whatever triggers the job). @{ due; notes; reason }.
    #>
    param([AllowNull()][object]$Notes, [AllowNull()][object]$State, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $src = $Notes; if ($src -is [string]) { try { $src = $src | ConvertFrom-Json } catch { $src = $null } }
    $all = @(@(Get-PimDqField $src 'notes') | Where-Object { $null -ne $_ })
    $st = $State; if ($st -is [string]) { try { $st = $st | ConvertFrom-Json } catch { $st = $null } }
    $last = $null; try { $lv = "$(Get-PimDqField $st 'lastSentUtc')"; if ($lv) { $last = ([datetimeoffset]::Parse($lv, [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime } } catch { $last = $null }
    $new = @($all | Where-Object {
        $ls = $null; try { $ls = ([datetimeoffset]::Parse("$(Get-PimDqField $_ 'lastSeenUtc')", [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime } catch { $ls = $null }
        $ls -and (-not $last -or $ls -gt $last) })
    if (-not $new.Count) { return @{ due = $false; notes = @(); reason = 'nothing is off since the last data quality alert' } }
    if ($last -and $last.Date -eq $now.Date) { return @{ due = $false; notes = @($new); reason = "today's data quality alert was already sent at $($last.ToString('HH:mm')) UTC -- the rest goes in tomorrow's" } }
    return @{ due = $true; notes = @($new | Sort-Object { "$(Get-PimDqField $_ 'lastSeenUtc')" } -Descending); reason = '' }
}

function Format-PimDataQualityMail {
    <# PURE. The ONE daily mail: @{ subject; headline; detailHtml; action }. Most significant first (anomalies, then the rest). #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Notes = @())
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode("$t") }
    $n = @(@($Notes) | Where-Object { $_ })
    $rank = @{ 'anomaly' = 0; 'convergence' = 1; 'policy-mass-change' = 2 }
    $sorted = @($n | Sort-Object @{ e = { if ($rank.ContainsKey("$(Get-PimDqField $_ 'kind')")) { $rank["$(Get-PimDqField $_ 'kind')"] } else { 9 } } }, @{ e = { "$(Get-PimDqField $_ 'lastSeenUtc')" }; Descending = $true })
    $rows = @($sorted | Select-Object -First 20 | ForEach-Object {
        $t = "$(Get-PimDqField $_ 'title')"; $d = "$(Get-PimDqField $_ 'detail')"; $c = "$(Get-PimDqField $_ 'cause')"; $f = "$(Get-PimDqField $_ 'fix')"
        $cnt = 0; [void][int]::TryParse("$(Get-PimDqField $_ 'count')", [ref]$cnt)
        '&bull; <b>' + (& $enc $t) + '</b>' + $(if ($cnt -gt 1) { " <i>(seen $cnt times)</i>" } else { '' }) +
        $(if ($d) { '<br>' + (& $enc $d) } else { '' }) + $(if ($c) { '<br><b>Likely cause:</b> ' + (& $enc $c) } else { '' }) + $(if ($f) { '<br><b>Fix:</b> ' + (& $enc $f) } else { '' }) })
    $more = if ($sorted.Count -gt 20) { "<br>... and $($sorted.Count - 20) more on the Jobs page." } else { '' }
    return @{
        subject    = 'Data quality alert'
        headline   = ("{0} thing(s) look different from the last runs. Nothing was blocked -- these are warnings to check." -f $n.Count)
        detailHtml = (($rows -join '<br><br>') + $more)
        action     = 'Open the Jobs page: check each item; if a change was not intended, undo it and run the scope again.'
    }
}

function Invoke-PimDataQualityJob {
    <#
      Job 'data-quality' (daily). Sends the ONE "Data quality alert" when something is off. Never fails because of what it
      found (warnings only); a mail that could not be sent is said in the run detail and retried on the next run.
      Seams: -GetSetting / -SetSetting, -Send { param($Mail) } -> $true when handed over (default Send-PimJobAlertViaNotify,
      Alerting event 'data-quality').
    #>
    param([object]$Job = $null, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf,
          [scriptblock]$GetSetting = $null, [scriptblock]$SetSetting = $null, [scriptblock]$Send = $null)
    $sm = Get-PimDqStoreSeams
    if (-not $GetSetting) { $GetSetting = $sm.get }; if (-not $SetSetting) { $SetSetting = $sm.set }
    if (-not $Send) {
        $Send = { param($m)
            if (-not (Get-Command Send-PimJobAlertViaNotify -ErrorAction SilentlyContinue)) { return $false }
            # PIM 100.105: the alert table's rows -- warnings to check, nothing was blocked
            $am = @{}; if (Get-Command Get-PimAlertMailArgs -ErrorAction SilentlyContinue) { $am = Get-PimAlertMailArgs -Command 'Send-PimJobAlertViaNotify' -Who 'Customer' -Status 'Warning' `
                -Problem "$($m.headline)" -Todo 'Open the Jobs page and check each item; if a change was not intended, undo it and run the scope again' }
            [bool](Send-PimJobAlertViaNotify -Event $script:PimDqAlertEvent -Title $m.subject -Detail $m.detailHtml -Headline $m.headline -Action $m.action -LinkTab 'jobs' -DebounceMinutes 0 @am) }
    }
    $notes = $null; $state = $null
    try { $notes = & $GetSetting $script:PimDqNotesSetting; $state = & $GetSetting $script:PimDqStateSetting }
    catch { return [pscustomobject]@{ ran = $true; warning = $true; whatIf = [bool]$WhatIf; detail = "data-quality: the notes could not be read ($($_.Exception.Message)) -- asked again on the next run" } }
    $sel = Select-PimDataQualityAlertDue -Notes $notes -State $state -NowUtc $NowUtc
    if (-not $sel.due) { return [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf; notes = @($sel.notes).Count; detail = "data-quality: $($sel.reason)" } }
    $mail = Format-PimDataQualityMail -Notes @($sel.notes)
    if ($WhatIf) { return [pscustomobject]@{ ran = $true; whatIf = $true; notes = @($sel.notes).Count; detail = "data-quality: would send the data quality alert ($(@($sel.notes).Count) item(s))" } }
    $__dqMailed = $false; $why = ''
    try { $__dqMailed = [bool](& $Send $mail) } catch { $__dqMailed = $false; $why = "$($_.Exception.Message)" }
    if ($__dqMailed) {
        try { & $SetSetting $script:PimDqStateSetting ([pscustomobject][ordered]@{ lastSentUtc = $NowUtc.ToUniversalTime().ToString('o'); lastCount = @($sel.notes).Count }) } catch { }
        return [pscustomobject]@{ ran = $true; whatIf = $false; notes = @($sel.notes).Count; mailed = $true; detail = "data-quality: the data quality alert was sent ($(@($sel.notes).Count) item(s))" }
    }
    return [pscustomobject]@{ ran = $true; whatIf = $false; notes = @($sel.notes).Count; mailed = $false
        detail = ("data-quality: {0} item(s) are off, but the data quality alert was NOT sent ({1}) -- the Alerting event 'data-quality' is off, there is no recipient, or the send failed; retried on the next run" -f @($sel.notes).Count, $(if ($why) { $why } else { 'not handed over' })) }
}
