#Requires -Version 5.1
<#
  Offline tests for the audit-trail query + before/after diff + full-trail CSV
  export decision core (engine/_shared/PIM-AuditQuery.ps1 -- REQUIREMENTS.md
  §28 [H6] / §26c "Audit you can defend").

  Proves the three [H6] gaps are closed by the pure core (no server, no SQL,
  no clock -- a temp audit dir seeded with several monthly jsonl files):

    1. FULL HISTORY (not just ~3 months) --
         Get-PimAuditMonthList returns ALL months newest-first; -Months N caps;
         Read-PimAuditEvents reads across every month.
    2. BEFORE/AFTER --
         Get-PimAuditChangeSummary renders "field: old -> new", create/remove,
         and omits unchanged fields; ConvertTo-PimAuditFlatMap handles scalar/
         object/null.
    3. FULL-TRAIL CSV EXPORT (whole filtered set, before/after column) --
         Select-PimAuditEvents filters (category/search/date-range) + sorts
         newest-first; ConvertTo-PimAuditCsv emits an RFC-4180 trail with a
         Change column and a CSV formula-injection guard. Culture-independent
         ISO timestamps.

  PURE -- no network, no SQL, no live tenant. Exits 0 (green) / 1 (red).
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-AuditQuery.ps1"

$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }

Write-Host "=== PIM-AuditQuery tests ([H6] audit history + before/after + CSV export) ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Seed a temp audit dir with FOUR monthly files spanning > a quarter, so the
# old hard-coded 3-month cap would have hidden the oldest month.
# ---------------------------------------------------------------------------
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pimauditq_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)
function Write-AuditMonth($month, $events) {
    $p = Join-Path $tmp "pim-audit-$month.jsonl"
    $sb = New-Object System.Text.StringBuilder
    foreach ($e in $events) { [void]$sb.Append(($e | ConvertTo-Json -Depth 6 -Compress)); [void]$sb.Append("`r`n") }
    [System.IO.File]::WriteAllText($p, $sb.ToString(), $utf8)
}

try {
    # January (oldest -- OUTSIDE a 3-month window from June): a creation (before=null).
    Write-AuditMonth '202601' @(
        @{ ts = '2026-01-15T10:00:00.000Z'; actor = 'engine'; action = 'account.create'; target = 'admin-mok-id'; before = $null; after = @{ accountEnabled = $true; dept = 'IT' }; result = 'ok'; whatIf = $false; correlationId = 'c1'; runId = 'r1' }
    )
    # March: a config change (before+after differ on one field, equal on another).
    Write-AuditMonth '202603' @(
        @{ ts = '2026-03-20T09:00:00.000Z'; actor = 'manager:mok'; action = 'settings.naming.save'; target = 'settings:naming'; before = @{ prefix = 'PIM_'; sep = '-' }; after = @{ prefix = 'PIM-'; sep = '-' }; result = 'ok'; whatIf = $false; correlationId = ''; runId = 'r2' }
    )
    # April: an emergency override (search/category target).
    Write-AuditMonth '202604' @(
        @{ ts = '2026-04-02T08:30:00.000Z'; actor = 'manager:mok'; action = 'emergency.passcode.failed'; target = 'emergency-override'; before = $null; after = $null; result = 'denied'; whatIf = $false; correlationId = ''; runId = 'r3' }
    )
    # June (newest): a disable (true->false) + a malformed line that must be skipped.
    $junePath = Join-Path $tmp 'pim-audit-202606.jsonl'
    $jb = New-Object System.Text.StringBuilder
    [void]$jb.Append((@{ ts = '2026-06-10T12:00:00.000Z'; actor = 'manager:mok'; action = 'account.disable'; target = 'admin-x-id'; before = @{ accountEnabled = $true }; after = @{ accountEnabled = $false }; result = 'ok'; whatIf = $false; correlationId = ''; runId = 'r4' } | ConvertTo-Json -Depth 6 -Compress)); [void]$jb.Append("`r`n")
    [void]$jb.Append('{ this is not valid json'); [void]$jb.Append("`r`n")  # must be skipped, never fatal
    [void]$jb.Append((@{ ts = '2026-06-11T07:15:00.000Z'; actor = 'manager:eve'; action = 'manager.login'; target = 'eve@contoso'; before = $null; after = @{ role = 'Admin' }; result = 'ok'; whatIf = $false; correlationId = ''; runId = 'r5' } | ConvertTo-Json -Depth 6 -Compress)); [void]$jb.Append("`r`n")
    [System.IO.File]::WriteAllText($junePath, $jb.ToString(), $utf8)

    # =======================================================================
    # 1. FULL HISTORY -- not capped at 3 months.
    # =======================================================================
    # Fixed reference 'now' = 2026-06-15 so the calendar window is deterministic.
    $refNow = [datetime]'2026-06-15T00:00:00Z'
    $months = Get-PimAuditMonthList -AuditDir $tmp
    Assert 'month list returns ALL 4 months (full history)' ($months.Count -eq 4)
    Assert 'month list newest-first' ($months[0] -eq '202606' -and $months[-1] -eq '202601')
    # Calendar window of 6 months from June 2026 = Jan..Jun -> all 4 existing files.
    $cap6 = Get-PimAuditMonthList -AuditDir $tmp -Months 6 -ReferenceDate $refNow
    Assert '-Months 6 calendar window covers Jan..Jun (all 4 existing)' ($cap6.Count -eq 4)
    # Calendar window of 4 months = Mar..Jun -> excludes January.
    $cap4 = Get-PimAuditMonthList -AuditDir $tmp -Months 4 -ReferenceDate $refNow
    Assert '-Months 4 calendar window (Mar..Jun) excludes Jan' ($cap4.Count -eq 3 -and (@($cap4) -notcontains '202601'))
    # Calendar window of 3 months = Apr..Jun -> excludes Jan + Mar.
    $cap3 = Get-PimAuditMonthList -AuditDir $tmp -Months 3 -ReferenceDate $refNow
    Assert '-Months 3 calendar window (Apr..Jun) excludes Jan + Mar' ($cap3.Count -eq 2 -and (@($cap3) -notcontains '202601') -and (@($cap3) -notcontains '202603'))
    Assert 'calendar window is wall-clock based, not N-newest-files' ($cap3.Count -ne 3)
    Assert 'month list on a missing dir is empty (no throw)' ((Get-PimAuditMonthList -AuditDir (Join-Path $tmp 'nope')).Count -eq 0)

    $all = Read-PimAuditEvents -AuditDir $tmp
    # 5 valid events across 4 months (the malformed June line skipped).
    Assert 'full read sees every valid event across all months (5)' ($all.Count -eq 5)
    Assert 'malformed json line skipped (not 6)' ($all.Count -ne 6)
    $oldest = @($all | Where-Object { $_.runId -eq 'r1' })
    Assert 'the OLDEST (January) event IS readable in full history -- old 3-month cap hid it' ($oldest.Count -eq 1)
    $capRead = Read-PimAuditEvents -AuditDir $tmp -Months 3 -ReferenceDate $refNow
    Assert '-Months 3 read excludes Jan + Mar' (@($capRead | Where-Object { $_.runId -in @('r1','r2') }).Count -eq 0)

    # =======================================================================
    # 2. BEFORE / AFTER summary.
    # =======================================================================
    Assert 'create (before=null) -> "(none) -> value", unchanged fields included as new' (
        (Get-PimAuditChangeSummary -Before $null -After @{ accountEnabled = $true }) -eq 'accountEnabled: (none) -> True'
    )
    Assert 'changed field rendered old -> new; UNCHANGED field omitted' (
        (Get-PimAuditChangeSummary -Before @{ prefix = 'PIM_'; sep = '-' } -After @{ prefix = 'PIM-'; sep = '-' }) -eq 'prefix: PIM_ -> PIM-'
    )
    Assert 'removal (after=null) -> "value -> (removed)"' (
        (Get-PimAuditChangeSummary -Before @{ accountEnabled = $true } -After $null) -eq 'accountEnabled: True -> (removed)'
    )
    Assert 'identical before/after -> empty summary' (
        (Get-PimAuditChangeSummary -Before @{ a = '1' } -After @{ a = '1' }) -eq ''
    )
    Assert 'both null -> empty summary' ((Get-PimAuditChangeSummary -Before $null -After $null) -eq '')
    Assert 'scalar before/after flattens to ''-> ''' (
        (Get-PimAuditChangeSummary -Before 'old' -After 'new') -eq 'old -> new'
    )
    # The read path stamps .change on each event.
    $disable = @($all | Where-Object { $_.runId -eq 'r4' })[0]
    Assert 'read-path stamps a .change on the disable event' ($disable.change -eq 'accountEnabled: True -> False')
    $create = @($all | Where-Object { $_.runId -eq 'r1' })[0]
    Assert 'read-path .change on the create event lists both new fields' (
        $create.change -like '*accountEnabled: (none) -> True*' -and $create.change -like '*dept: (none) -> IT*'
    )

    # =======================================================================
    # 2b. Category stamping (matches the Manager resolver buckets).
    # =======================================================================
    Assert 'account.* -> accounts category' (@($all | Where-Object { $_.runId -eq 'r4' })[0].category -eq 'accounts')
    Assert 'emergency.* -> emergency category' (@($all | Where-Object { $_.runId -eq 'r3' })[0].category -eq 'emergency')
    Assert 'manager.login -> logins category' (@($all | Where-Object { $_.runId -eq 'r5' })[0].category -eq 'logins')
    Assert 'settings.* -> engine category' (@($all | Where-Object { $_.runId -eq 'r2' })[0].category -eq 'engine')

    # =======================================================================
    # 3. FILTER + SORT + CSV export of the FULL trail.
    # =======================================================================
    $sortedAll = Select-PimAuditEvents -Events $all
    Assert 'Select sorts newest-first' ($sortedAll[0].runId -eq 'r5' -and $sortedAll[-1].runId -eq 'r1')

    $accts = Select-PimAuditEvents -Events $all -Category 'accounts'
    Assert 'category filter = accounts -> 2 (create + disable)' ($accts.Count -eq 2)
    Assert 'category ''all'' = no filter' ((Select-PimAuditEvents -Events $all -Category 'all').Count -eq 5)

    $searchPim = @(Select-PimAuditEvents -Events $all -Search 'PIM-')
    Assert 'free-text search matches the before/after CHANGE text too' ($searchPim.Count -eq 1 -and $searchPim[0].runId -eq 'r2')
    $searchEve = @(Select-PimAuditEvents -Events $all -Search 'eve@')
    Assert 'free-text search matches the target' ($searchEve.Count -eq 1 -and $searchEve[0].runId -eq 'r5')

    $q1 = Select-PimAuditEvents -Events $all -FromUtc '2026-03-01' -ToUtc '2026-04-30'
    Assert 'date-range filter (Mar..Apr inclusive whole-day) -> 2 events' ($q1.Count -eq 2)
    $q2 = Select-PimAuditEvents -Events $all -FromUtc '2026-06-01'
    Assert 'open-ended from-date -> only June (2)' ($q2.Count -eq 2)

    # CSV over the WHOLE filtered set (the whole trail, before/after included).
    $csv = ConvertTo-PimAuditCsv -Events $sortedAll
    $rows = $csv -split "`r`n"
    Assert 'CSV header has a Change column' ($rows[0] -eq 'When (UTC),Actor,Category,Action,Target,Result,Change,WhatIf,CorrelationId,RunId')
    Assert 'CSV has a row per event + header (6 lines)' ($rows.Count -eq 6)
    Assert 'CSV covers the FULL history (oldest Jan row present)' ($csv -like '*account.create*admin-mok-id*')
    Assert 'CSV When column is ISO (culture-independent), not US m/d/y' ($rows[1] -like '2026-06-11 07:15:00*')
    Assert 'CSV carries the before/after Change text' ($csv -like '*accountEnabled: True -> False*')

    # CSV formula-injection guard + RFC-4180 quoting.
    $evil = @(
        [pscustomobject]@{ ts = '2026-06-12T00:00:00.000Z'; actor = '=cmd|calc'; action = 'x'; target = 'a,b "c"'; result = 'ok'; change = ''; whatIf = $false; correlationId = ''; runId = 'r9' }
    )
    $evilCsv = ConvertTo-PimAuditCsv -Events $evil
    Assert 'formula-injection: leading = is neutralised with a quote' ($evilCsv -like "*""'=cmd|calc""*" -or $evilCsv -like "*'=cmd|calc*")
    Assert 'RFC-4180: a value with comma + quotes is wrapped + doubled' ($evilCsv -like '*"a,b ""c"""*')

    Assert 'empty event set -> header-only CSV' ((ConvertTo-PimAuditCsv -Events @()) -eq 'When (UTC),Actor,Category,Action,Target,Result,Change,WhatIf,CorrelationId,RunId')
}
finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ("`nRESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 } else { exit 0 }
