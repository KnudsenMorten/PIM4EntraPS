# PIM-AuditQuery.ps1 -- pure audit-trail query + before/after diff + CSV export
# (LIFECYCLE / GOVERNANCE -- "Audit you can defend", REQUIREMENTS.md s28 [H6]).
#
# The Manager Audit tab historically read only the last THREE monthly files
# (output/audit/pim-audit-<yyyyMM>.jsonl), never surfaced the before/after of a
# change, and only exported the page on screen. This shared, dependency-free,
# PS-5.1-safe library closes all three gaps with ONE decision core that the
# /api/audit + /api/audit/export endpoints (and the engine, if it ever needs to)
# share, so the screen, the export and any test resolve the trail identically:
#
#   Get-PimAuditMonthList   -- discover the available monthly files (FULL history
#                              by default; or the most-recent N).
#   Read-PimAuditEvents     -- read + parse the events across those months.
#   Get-PimAuditChangeSummary -- render a human "field: old -> new" before/after.
#   Select-PimAuditEvents   -- filter (category/search/from/to) + sort newest-first.
#   ConvertTo-PimAuditCsv   -- RFC-4180 CSV (with a formula-injection guard) over
#                              the FULL filtered set, INCLUDING the change column --
#                              so an auditor export is the whole trail, not a page.
#
# Pure: no module deps, no SQL, no network, no global state. The file on disk is
# the source of truth; nothing here writes. Category bucketing matches the
# Manager's Get-PimAuditCategory (kept in sync; this provides a fallback when the
# function isn't loaded so the lib is standalone-testable).

function Get-PimAuditCategoryFallback {
    # Standalone mirror of Open-PimManager.ps1 Get-PimAuditCategory so this lib can
    # be dot-sourced and tested without the Manager. The Manager's own function (if
    # loaded) wins -- see Resolve-PimAuditCategory.
    param([string]$Action)
    $a = "$Action".Trim().ToLowerInvariant()
    if (-not $a) { return 'other' }
    switch -Regex ($a) {
        '^(manager\.login|login)'           { return 'logins' }
        '^emergency\.'                      { return 'emergency' }
        '^approval\.'                       { return 'approvals' }
        '^(account\.|tap\.)'                { return 'accounts' }
        '^(membership\.|group\.|local\.apply|msp\.fanout|cutover\.)' { return 'delegations' }
        '^(policy\.|resource\.|config\.|settings\.|mail\.send|license\.)' { return 'engine' }
        default                             { return 'other' }
    }
}

function Resolve-PimAuditCategory {
    param([string]$Action)
    if (Get-Command Get-PimAuditCategory -ErrorAction SilentlyContinue) {
        return (Get-PimAuditCategory -Action $Action)
    }
    return (Get-PimAuditCategoryFallback -Action $Action)
}

function Get-PimAuditMonthList {
    <#
    .SYNOPSIS
        Discover the audit months available on disk, newest-first.
    .DESCRIPTION
        Lists every pim-audit-<yyyyMM>.jsonl in the audit directory and returns the
        yyyyMM stamps newest-first. With -Months N, returns only the most-recent N
        months that actually exist; with -Months 0 / 'all' (the default), returns the
        FULL history -- which is the [H6] fix (the UI used to be capped at 3).
    .PARAMETER AuditDir
        The directory holding pim-audit-<yyyyMM>.jsonl files (output/audit).
    .PARAMETER Months
        0 (default) = full history (every monthly file on disk). A positive N =
        the last N CALENDAR months (this month + the N-1 preceding), intersected
        with what exists -- so the window is wall-clock-based (back-compat with the
        old now/now-1/now-2 behaviour), NOT "the N newest files that happen to exist".
    .PARAMETER ReferenceDate
        'Now' for the calendar-window calculation -- injectable for tests (UTC).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AuditDir,
        [int]$Months = 0,
        [datetime]$ReferenceDate = [datetime]::UtcNow
    )
    if (-not (Test-Path -LiteralPath $AuditDir)) { return @() }
    $stamps = New-Object System.Collections.Generic.List[string]
    foreach ($f in @(Get-ChildItem -LiteralPath $AuditDir -Filter 'pim-audit-*.jsonl' -File -ErrorAction SilentlyContinue)) {
        if ($f.Name -match '^pim-audit-(\d{6})\.jsonl$') { $stamps.Add($Matches[1]) }
    }
    # Newest-first (yyyyMM sorts lexically == chronologically).
    $sorted = @($stamps | Sort-Object -Descending)
    if ($Months -gt 0) {
        # The set of calendar-month stamps in the wall-clock window [now-(N-1) .. now].
        $window = New-Object System.Collections.Generic.HashSet[string]
        for ($k = 0; $k -lt $Months; $k++) { [void]$window.Add($ReferenceDate.AddMonths(-$k).ToString('yyyyMM')) }
        $sorted = @($sorted | Where-Object { $window.Contains($_) })
    }
    return $sorted
}

function Read-PimAuditEvents {
    <#
    .SYNOPSIS
        Read + parse audit events across the resolved months (newest month first).
    .DESCRIPTION
        Each event keeps its raw fields and gains a stamped `category` (via the
        Manager's resolver when loaded, else the fallback) and a `change` string
        (the human before/after summary). A malformed JSON line is skipped, never
        fatal -- the trail must always render.
    .PARAMETER AuditDir
        output/audit directory.
    .PARAMETER Months
        0 = full history (default); N = most-recent N existing months.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AuditDir,
        [int]$Months = 0,
        [datetime]$ReferenceDate = [datetime]::UtcNow
    )
    $events = New-Object System.Collections.ArrayList
    foreach ($m in (Get-PimAuditMonthList -AuditDir $AuditDir -Months $Months -ReferenceDate $ReferenceDate)) {
        $f = Join-Path $AuditDir "pim-audit-$m.jsonl"
        if (-not (Test-Path -LiteralPath $f)) { continue }
        foreach ($line in @(Get-Content -LiteralPath $f -Encoding UTF8)) {
            if (-not "$line".Trim()) { continue }
            $evt = $null
            try { $evt = $line | ConvertFrom-Json } catch { continue }
            if ($null -eq $evt) { continue }
            # Normalise ts to an invariant ISO-8601 UTC STRING. ConvertFrom-Json may
            # have turned the ISO ts into a [datetime] (whose default ToString is the
            # host's CULTURE-LOCAL format) -- stamping a stable string here keeps the
            # newest-first sort, the date-range filter and the CSV "When" column
            # culture-independent (so an export is identical on any machine).
            try {
                $tsRaw = $evt.ts
                $tsIso = ''
                if ($tsRaw -is [datetime]) {
                    $tsIso = ([datetime]$tsRaw).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
                } else {
                    $parsed = $null
                    if ([datetime]::TryParse("$tsRaw", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$parsed)) {
                        $tsIso = $parsed.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
                    } else {
                        $tsIso = "$tsRaw"
                    }
                }
                $evt | Add-Member -NotePropertyName ts -NotePropertyValue $tsIso -Force
            } catch {}
            try { $evt | Add-Member -NotePropertyName category -NotePropertyValue (Resolve-PimAuditCategory -Action "$($evt.action)") -Force } catch {}
            try { $evt | Add-Member -NotePropertyName change   -NotePropertyValue (Get-PimAuditChangeSummary -Before $evt.before -After $evt.after) -Force } catch {}
            [void]$events.Add($evt)
        }
    }
    return @($events)
}

function ConvertTo-PimAuditFlatMap {
    # Flatten a before/after value to an ordered hashtable of leaf "key = scalar".
    # An object becomes its property map; a scalar becomes { '' = value }; $null -> empty.
    # Nested objects are stringified (one level deep is enough for the human summary;
    # the raw before/after is still available in the JSON for the full picture).
    param([object]$Value)
    $map = [ordered]@{}
    if ($null -eq $Value) { return $map }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
        $map[''] = "$Value"
        return $map
    }
    $props = $null
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($k in $Value.Keys) {
            $v = $Value[$k]
            $map["$k"] = if ($null -eq $v) { '' } elseif ($v -is [string] -or $v.GetType().IsValueType) { "$v" } else { ($v | ConvertTo-Json -Depth 4 -Compress) }
        }
        return $map
    }
    try { $props = $Value.PSObject.Properties } catch { $props = $null }
    if ($props) {
        foreach ($p in $props) {
            $v = $p.Value
            $map["$($p.Name)"] = if ($null -eq $v) { '' } elseif ($v -is [string] -or $v.GetType().IsValueType) { "$v" } else { ($v | ConvertTo-Json -Depth 4 -Compress) }
        }
        return $map
    }
    $map[''] = "$Value"
    return $map
}

function Get-PimAuditChangeSummary {
    <#
    .SYNOPSIS
        Render a human before/after summary for one audit event ([H6] "show me the
        before and after").
    .DESCRIPTION
        Compares the event's `before` and `after` objects field-by-field and returns
        a compact, sortable string of the fields that actually changed, in the form
        "field: old -> new; field2: (none) -> x". Pure + side-effect-free.
          - before only (a removal)  -> "field: x -> (removed)"
          - after only  (a creation) -> "field: (none) -> x"
          - both, differ             -> "field: old -> new"
          - both, equal              -> omitted (only CHANGES are shown)
        With neither before nor after, returns ''.
    #>
    [CmdletBinding()]
    param([object]$Before, [object]$After)

    $b = ConvertTo-PimAuditFlatMap -Value $Before
    $a = ConvertTo-PimAuditFlatMap -Value $After
    if ($b.Count -eq 0 -and $a.Count -eq 0) { return '' }

    # Union of keys, stable order: before-keys first (in their order), then any
    # after-only keys.
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($k in $b.Keys) { if (-not $keys.Contains($k)) { $keys.Add($k) } }
    foreach ($k in $a.Keys) { if (-not $keys.Contains($k)) { $keys.Add($k) } }

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($k in $keys) {
        $hasB = $b.Contains($k); $hasA = $a.Contains($k)
        $ov = if ($hasB) { "$($b[$k])" } else { '' }
        $nv = if ($hasA) { "$($a[$k])" } else { '' }
        $label = if ($k) { "$k`: " } else { '' }
        $ovDisp = if ($ov -eq '') { '(none)' } else { $ov }
        $nvDisp = if ($nv -eq '') { '(none)' } else { $nv }
        if ($hasB -and $hasA) {
            if ($ov -eq $nv) { continue }   # unchanged -- skip
            $parts.Add("$label$ovDisp -> $nvDisp")
        }
        elseif ($hasA) {
            $parts.Add("$label(none) -> $nvDisp")
        }
        else {
            $parts.Add("$label$ovDisp -> (removed)")
        }
    }
    return ($parts -join '; ')
}

function Select-PimAuditEvents {
    <#
    .SYNOPSIS
        Filter (category / free-text / date range) + sort newest-first. Pure.
    .DESCRIPTION
        Shared by the on-screen view AND the CSV export so the export honours the
        SAME filter the operator is looking at. Date bounds are inclusive and
        compared on the event's ISO `ts` (UTC) by string prefix-safe DateTime parse.
    .PARAMETER Events
        Events from Read-PimAuditEvents (carry .category + .change).
    .PARAMETER Category
        '' / 'all' = no category filter; else exact category match.
    .PARAMETER Search
        '' = none; else case-insensitive substring over actor/action/target/result/change.
    .PARAMETER FromUtc / ToUtc
        Optional inclusive date bounds (yyyy-MM-dd or full ISO).
    #>
    [CmdletBinding()]
    param(
        [object[]]$Events = @(),
        [string]$Category = '',
        [string]$Search = '',
        [string]$FromUtc = '',
        [string]$ToUtc = ''
    )
    $cat = "$Category".Trim().ToLowerInvariant(); if ($cat -eq 'all') { $cat = '' }
    $q   = "$Search".Trim().ToLowerInvariant()

    $from = $null; $to = $null
    if ("$FromUtc".Trim()) { try { $from = [datetime]::Parse($FromUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal) } catch { $from = $null } }
    if ("$ToUtc".Trim())   { try { $to   = [datetime]::Parse($ToUtc,   [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal) } catch { $to = $null } }
    # An end-date with no time means "the whole day" -- push to 23:59:59.
    if ($to -and "$ToUtc".Trim().Length -le 10) { $to = $to.Date.AddDays(1).AddSeconds(-1) }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Events)) {
        if ($cat -and "$($e.category)".ToLowerInvariant() -ne $cat) { continue }
        if ($from -or $to) {
            $ets = $null
            try { $ets = [datetime]::Parse("$($e.ts)", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal) } catch { $ets = $null }
            if ($ets) {
                if ($from -and $ets -lt $from) { continue }
                if ($to   -and $ets -gt $to)   { continue }
            }
        }
        if ($q) {
            $hay = ("$($e.actor)|$($e.action)|$($e.target)|$($e.result)|$($e.change)").ToLowerInvariant()
            if (-not $hay.Contains($q)) { continue }
        }
        $out.Add($e)
    }
    return @($out | Sort-Object { "$($_.ts)" } -Descending)
}

function ConvertTo-PimAuditCsvCell {
    # RFC-4180 quoting + CSV formula-injection guard (mirror of the GUI csvCell).
    param([object]$Value)
    $s = if ($null -eq $Value) { '' } else { "$Value" }
    if ($s -match '^[=+\-@\t\r]') { $s = "'" + $s }
    if ($s -match '[",\r\n]') { $s = '"' + ($s -replace '"', '""') + '"' }
    return $s
}

function ConvertTo-PimAuditCsv {
    <#
    .SYNOPSIS
        Render the FULL filtered audit trail to RFC-4180 CSV text -- including a
        before/after Change column ([H5]/[H6] "export with full history + before/after").
    .DESCRIPTION
        Columns: When (UTC), Actor, Category, Action, Target, Result, Change, WhatIf,
        CorrelationId, RunId. CRLF line endings (Excel-friendly); the caller prepends
        the UTF-8 BOM when serving the download. Pure -- returns a string.
    #>
    [CmdletBinding()]
    param([object[]]$Events = @())
    $headers = @('When (UTC)','Actor','Category','Action','Target','Result','Change','WhatIf','CorrelationId','RunId')
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(($headers | ForEach-Object { ConvertTo-PimAuditCsvCell $_ }) -join ',')
    foreach ($e in @($Events)) {
        $when = "$($e.ts)" -replace 'T', ' '
        if ($when.Length -ge 19) { $when = $when.Substring(0, 19) }
        $row = @(
            (ConvertTo-PimAuditCsvCell $when),
            (ConvertTo-PimAuditCsvCell "$($e.actor)"),
            (ConvertTo-PimAuditCsvCell "$($e.category)"),
            (ConvertTo-PimAuditCsvCell "$($e.action)"),
            (ConvertTo-PimAuditCsvCell "$($e.target)"),
            (ConvertTo-PimAuditCsvCell "$($e.result)"),
            (ConvertTo-PimAuditCsvCell "$($e.change)"),
            (ConvertTo-PimAuditCsvCell "$([bool]$e.whatIf)"),
            (ConvertTo-PimAuditCsvCell "$($e.correlationId)"),
            (ConvertTo-PimAuditCsvCell "$($e.runId)")
        )
        $lines.Add(($row -join ','))
    }
    return ($lines -join "`r`n")
}
