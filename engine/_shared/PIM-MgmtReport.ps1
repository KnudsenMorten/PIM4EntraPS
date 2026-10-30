<#
  PIM-MgmtReport.ps1 -- MGMT-REPORT (owner 2026-10-29, Pro, PIM Manager brand): the MANAGEMENT REPORT as a PowerPoint.
    "a wizard for mgmt. reporting, where i can select what i want to export and then get a powerpoint with the exported data ?
     A nice looking powerpoint. alternative a more static version where i export management reports with key figures +
     relevant info" -- owner's choices: BOTH (wizard + static monthly), ALL four sections, Pro.

  Four sections, built ONLY from data the product already stores:
    kpi         Key figures + trends vs the previous period
    risk        Risk & exceptions: standing access, break-glass use, guard holds, held change sets, overdue reviews, failing
                jobs, Tier 0 exposure
    changes     Changes & audit: access added / removed, policy changes, admin accounts, offboardings, approvals + approvers,
                the changes the engine applied
    compliance  Compliance evidence: access review outcomes, policy baseline conformance, discovery gaps, MFA on activation,
                definitions linked to an approval template

  HONEST NUMBERS (the impact counters' rule, PIM-ImpactCounters.ps1): a figure the product cannot read is "not available"
  WITH the reason -- never invented, never 0 by default. A trend needs the previous period: the audit trail answers it when
  it reaches back that far, the job run history when it does, and a snapshot figure (standing access, eligible assignments,
  ...) only from a stored earlier report (history in pim.TenantCache 'mgmt-report'). Otherwise the tile says
  "no earlier data" -- never a trend computed against nothing.

  PURE: the period, the query parsing, the model (New-PimMgmtReportModel), the slides (ConvertTo-PimMgmtReportSlides), the
  config, the file name. Data comes through two seams so the suites stub it:
    -Query   { param($name, $sql, $params, $kind) }   kind 'scalar' | 'rows'; default Invoke-PimSqlScalar / Invoke-PimSqlQuery
    -Readers @{ <name> = { param($period) } }          one per non-SQL source (Get-PimMgmtReportDefaultReaders)
  Each source is read on its own: one that throws is "not available" with its message; the others still answer.

  The WIZARD (Manager, Reports > Management report): GET /api/reports/management?sections=&period=&month= -> the .pptx
  (Invoke-PimMgmtReportRequest). The STATIC MONTHLY report: scheduler job 'mgmt-report' (Invoke-PimMgmtReportMonthlyJob) --
  OFF until pim.Settings 'ManagementReport' monthly.enabled is set; builds the full report for the last month once, stores it
  (pim.TenantCache 'mgmt-report': the latest file + the figure history) and mails it to the configured recipients.
#>

Set-StrictMode -Off

$script:PimMgmtReportLibDir = $PSScriptRoot
if ($PSScriptRoot -and -not (Get-Command New-PimPptxBytes -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PIM-Pptx.ps1'))) {
    . (Join-Path $PSScriptRoot 'PIM-Pptx.ps1')
}

$script:PimMgmtReportFeatureKey = 'reports.management'
$script:PimMgmtReportSettingName = 'ManagementReport'
$script:PimMgmtReportCacheKind = 'mgmt-report'
$script:PimMgmtReportHistoryMax = 36
$script:PimMgmtReportContentType = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
$script:PimMgmtReportMailMaxBytes = 3MB   # the Graph sendMail ceiling for an attachment (PIM-Xlsx / policy hold, section 79.14)

$script:PimMgmtReportSectionCatalog = @(
    [ordered]@{ id = 'kpi';        title = 'Key figures';          description = 'The headline numbers of the period, each with its trend against the previous period.' }
    [ordered]@{ id = 'risk';       title = 'Risk & exceptions';    description = 'Standing access, break-glass use, guard holds and held change sets, overdue reviews, failing jobs, Tier 0 exposure.' }
    [ordered]@{ id = 'changes';    title = 'Changes & audit';      description = 'Access added and removed, policy changes, admin accounts, offboardings, approvals and who approved, the changes applied.' }
    [ordered]@{ id = 'compliance'; title = 'Compliance evidence';  description = 'Access review outcomes, policy baseline conformance, discovery gaps, MFA on activation, approval on privileged groups.' }
)
$script:PimMgmtReportPeriods = @(
    [ordered]@{ id = 'last7';  label = 'Last 7 days' }
    [ordered]@{ id = 'last30'; label = 'Last 30 days' }
    [ordered]@{ id = 'last90'; label = 'Last 90 days' }
    [ordered]@{ id = 'month';  label = 'A calendar month' }
)

# (elements are dictionaries, never arrays: returned unrolled, a caller's @() collects them)
function Get-PimMgmtReportSectionCatalog { return @($script:PimMgmtReportSectionCatalog) }
function Get-PimMgmtReportPeriodCatalog { return @($script:PimMgmtReportPeriods) }

function ConvertTo-PimMgmtReportRowArray {
    <#
      PURE. A row query's answer -> object[] of records, whatever came back: one record, an array of them, or an array
      wrapped once more by a pipeline (a list of ONE record must stay a list of one record, PS 5.1 and 7). Records are never
      arrays, so exactly one level of nesting is flattened.
    #>
    param([AllowNull()][object]$Value)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -ne $Value) {
        if ($Value -is [System.Collections.IList] -and -not ($Value -is [string])) {
            foreach ($x in $Value) {
                if ($x -is [System.Collections.IList] -and -not ($x -is [string])) { foreach ($y in $x) { if ($null -ne $y) { $out.Add($y) } } }
                elseif ($null -ne $x) { $out.Add($x) }
            }
        } else { $out.Add($Value) }
    }
    return , $out.ToArray()
}

function Read-PimMgmtReportCacheEntry {
    # One pim.TenantCache document (the scheduler's snapshots), or THROWS why it is not there: never $null passed off as empty.
    param([Parameter(Mandatory)][string]$Kind, [string]$What = 'snapshot')
    if (-not (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue)) { throw "the snapshot reader is not loaded in this process, so the $What cannot be read" }
    $e = Get-PimTenantCacheEntry -Kind $Kind
    if ($null -eq $e) {
        $err = ''; if (Get-Command Get-PimTenantCacheReadError -ErrorAction SilentlyContinue) { $err = "$(Get-PimTenantCacheReadError -Kind $Kind)" }
        if ($err) { throw "the $What could not be read: $err" }
        throw "no $What has been stored yet"
    }
    return $e
}

function Get-PimMgmtReportField {
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] } else { return $null } }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-PimMgmtReportUtc {
    # PURE. An ISO string / [datetime] -> UTC [datetime], or $null.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }; return $Value.ToUniversalTime() }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse("$Value", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d }
    return $null
}

function Format-PimMgmtReportNumber {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    try { return ([long]$Value).ToString('N0', [System.Globalization.CultureInfo]::InvariantCulture) } catch { return "$Value" }
}

function Format-PimMgmtReportDate {
    param([AllowNull()][object]$Value, [switch]$Time)
    $d = ConvertTo-PimMgmtReportUtc $Value
    if ($null -eq $d) { return '' }
    $f = if ($Time) { 'yyyy-MM-dd HH:mm' } else { 'yyyy-MM-dd' }
    return $d.ToString($f, [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-PimMgmtReportPeriod {
    <#
      PURE. The reporting window and the one before it (the trend's comparison):
        last7 / last30 / last90 -- the N days up to now, compared with the N days before
        month                   -- -Month 'yyyy-MM', or the LAST FULL calendar month; compared with the month before
      { key; kind; fromUtc; toUtc; prevFromUtc; prevToUtc; days; label; prevLabel }. Throws on an unknown period / month.
    #>
    param([string]$Period = 'last30', [string]$Month = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $now = New-Object datetime($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0, [System.DateTimeKind]::Utc)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    switch ("$Period".Trim().ToLowerInvariant()) {
        { $_ -in @('last7', 'last30', 'last90') } {
            $n = [int]("$_" -replace '^last', '')
            $to = $now; $from = $to.AddDays(-$n)
            return [pscustomobject]@{ key = ('{0}-{1}' -f $_, $to.ToString('yyyyMMdd', $inv)); kind = "$_"; fromUtc = $from; toUtc = $to; prevFromUtc = $from.AddDays(-$n); prevToUtc = $from; days = $n
                label = ('Last {0} days ({1} to {2})' -f $n, $from.ToString('yyyy-MM-dd', $inv), $to.ToString('yyyy-MM-dd', $inv)); prevLabel = ('the {0} days before' -f $n) }
        }
        'month' {
            $m = "$Month".Trim()
            if ($m) {
                if ($m -notmatch '^(\d{4})-(0[1-9]|1[0-2])$') { throw "month '$m' is not a month (yyyy-MM)" }
                $from = New-Object datetime([int]$Matches[1], [int]$Matches[2], 1, 0, 0, 0, [System.DateTimeKind]::Utc)
                if ($from -gt $now) { throw "month '$m' has not started yet" }
            } else {
                $first = New-Object datetime($now.Year, $now.Month, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
                $from = $first.AddMonths(-1)
            }
            $to = $from.AddMonths(1)
            $partial = $false
            if ($to -gt $now) { $to = $now; $partial = $true }
            $pf = $from.AddMonths(-1)
            return [pscustomobject]@{ key = $from.ToString('yyyy-MM', $inv); kind = 'month'; fromUtc = $from; toUtc = $to; prevFromUtc = $pf; prevToUtc = $from; days = [int][math]::Round(($to - $from).TotalDays)
                label = ($from.ToString('MMMM yyyy', $inv) + $(if ($partial) { ' (so far)' } else { '' })); prevLabel = $pf.ToString('MMMM yyyy', $inv) }
        }
        default { throw "period '$Period' is not one of last7, last30, last90, month" }
    }
}

function ConvertFrom-PimMgmtReportQuery {
    <#
      PURE. The wizard's query string -> { ok; error; sections; period; month }. Empty sections = all four. An unknown section
      or period is REFUSED (400), never silently dropped.
    #>
    param([AllowNull()][string]$QueryString)
    $q = @{}
    foreach ($pair in @("$QueryString".TrimStart('?') -split '&')) {
        if (-not "$pair".Trim()) { continue }
        $kv = $pair -split '=', 2
        $k = [System.Uri]::UnescapeDataString("$($kv[0])").Trim().ToLowerInvariant()
        $v = if ($kv.Count -gt 1) { [System.Uri]::UnescapeDataString(("$($kv[1])" -replace '\+', ' ')).Trim() } else { '' }
        $q[$k] = $v
    }
    $known = @($script:PimMgmtReportSectionCatalog | ForEach-Object { "$($_.id)" })
    $secs = @("$($q['sections'])" -split '[,;\s]+' | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    $bad = @($secs | Where-Object { $known -notcontains $_ })
    if ($bad.Count) { return [pscustomobject]@{ ok = $false; error = ("unknown section(s): {0} -- choose from {1}" -f ($bad -join ', '), ($known -join ', ')); sections = @(); period = ''; month = '' } }
    if (-not $secs.Count) { $secs = $known }
    $ordered = @($known | Where-Object { $secs -contains $_ })   # always in the report's own order
    $period = "$($q['period'])".Trim().ToLowerInvariant(); if (-not $period) { $period = 'last30' }
    if (@($script:PimMgmtReportPeriods | ForEach-Object { "$($_.id)" }) -notcontains $period) { return [pscustomobject]@{ ok = $false; error = "period '$period' is not one of last7, last30, last90, month"; sections = @(); period = ''; month = '' } }
    $month = "$($q['month'])".Trim()
    if ($month -and $month -notmatch '^\d{4}-(0[1-9]|1[0-2])$') { return [pscustomobject]@{ ok = $false; error = "month '$month' is not a month (yyyy-MM)"; sections = @(); period = ''; month = '' } }
    return [pscustomobject]@{ ok = $true; error = ''; sections = $ordered; period = $period; month = $month }
}

# ---- the SQL the report reads (all from the environment's own store) ----------------------------------------------------
function Get-PimMgmtReportAuditQueries {
    <# PURE. The period counts (scalar, @f / @t = the window). Run for the period AND the period before. #>
    $w = 'Ts >= @f AND Ts < @t'
    $eng = "ActorSource = 'engine' AND ISNULL(WhatIf, 0) = 0"
    $notCore = "Action NOT LIKE 'engine.%policies.%' AND Action NOT LIKE 'engine.admins.%' AND Action NOT LIKE 'engine.admintap.%' AND Action NOT LIKE 'engine.adminoffboarding.%' AND Action NOT LIKE 'engine.remove.budget%'"
    $chg = "(Action LIKE 'engine.%.create' OR Action LIKE 'engine.%.update' OR Action LIKE 'engine.%.remove') AND Action NOT LIKE 'engine.remove.budget%'"
    return [ordered]@{
        engineChanges   = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE $w AND $eng AND Result = 'ok' AND $chg"
        adds            = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE $w AND $eng AND Result = 'ok' AND Action LIKE 'engine.%.create' AND $notCore"
        removals        = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE $w AND $eng AND Result = 'ok' AND Action LIKE 'engine.%.remove' AND $notCore"
        policyChanges   = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE $w AND $eng AND Result = 'ok' AND Action LIKE 'engine.%policies.update'"
        adminCreated    = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE $w AND $eng AND Result = 'ok' AND Action = 'engine.admins.create'"
        offboardings    = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE $w AND $eng AND Result = 'ok' AND Action LIKE 'engine.adminoffboarding.%'"
        engineErrors    = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE $w AND $eng AND Result = 'error' AND $chg"
        approvals       = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE $w AND (Action IN ('approval.request.approved', 'approval.request.denied') OR Action LIKE '%.policy.masschange.approved')"
        reviewDecisions = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE $w AND Action IN ('access-review.decision', 'company-review.answer', 'owner.keep', 'owner.remove', 'owner.extend')"
        breakGlassUse   = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE $w AND Action = 'emergency.activate' AND Result = 'ok'"
        guardTrips      = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE $w AND Action = 'guard.trip'"
    }
}

function Get-PimMgmtReportSnapshotQueries {
    <# PURE. Figures as they are NOW (scalar, no parameters). #>
    return [ordered]@{
        auditSince   = 'SELECT MIN(Ts) AS n FROM pim.AuditEvents'
        eligible     = "SELECT COUNT_BIG(*) AS n FROM pim.ManagedKeys WHERE [Key] LIKE '%|eligible'"
        admins       = "SELECT COUNT_BIG(*) AS n FROM pim.Rows WHERE Entity = 'Account-Definitions-Admins'"
        definitions  = "SELECT COUNT_BIG(*) AS n FROM pim.Rows WHERE Entity LIKE 'PIM-Definitions-%' AND DataJson LIKE '%`"PolicyTemplate`"%'"
        approvalDefs = "SELECT COUNT_BIG(*) AS n FROM pim.Rows WHERE Entity LIKE 'PIM-Definitions-%' AND DataJson LIKE '%`"PolicyTemplate`"%' AND JSON_VALUE(DataJson, '$.PolicyTemplate') LIKE '%approval%'"
    }
}

function Get-PimMgmtReportRowQueries {
    <# PURE. The period lists (rows, @f / @t). #>
    $w = 'Ts >= @f AND Ts < @t'
    return [ordered]@{
        approvers      = "SELECT TOP (10) Actor AS actor, COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE $w AND (Action IN ('approval.request.approved', 'approval.request.denied') OR Action LIKE '%.policy.masschange.approved') GROUP BY Actor ORDER BY COUNT_BIG(*) DESC"
        recentChanges  = "SELECT TOP (30) Ts AS ts, Action AS action, Target AS target, Actor AS actor, Result AS result FROM pim.AuditEvents WHERE $w AND ActorSource = 'engine' AND ISNULL(WhatIf, 0) = 0 AND (Action LIKE 'engine.%.create' OR Action LIKE 'engine.%.update' OR Action LIKE 'engine.%.remove') AND Action NOT LIKE 'engine.remove.budget%' ORDER BY Ts DESC"
        reviewOutcomes = "SELECT JSON_VALUE(AfterJson, '$.outcome') AS outcome, COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE $w AND Action = 'access-review.decision' GROUP BY JSON_VALUE(AfterJson, '$.outcome')"
    }
}

function Get-PimMgmtReportDefaultReaders {
    <#
      The non-SQL sources, each a scriptblock param($period) that RETURNS the value or THROWS the reason it cannot. They read
      what the product already stores (the scheduler's snapshots in pim.TenantCache, the run history, the guard holds, the
      settings); a reader whose library is not loaded in this process says so -- the figure is then "not available".
    #>
    # (plain scriptblocks, no closures: a closure's module scope cannot see the functions of a dot-sourced library)
    return @{
        activeAssignments = {
            param($period)
            $e = Read-PimMgmtReportCacheEntry -Kind 'active-assignments' -What "active-assignments snapshot (job 'active-assignments-snapshot')"
            $ok = Get-PimMgmtReportField $e 'ok'
            if ($null -ne $ok -and -not [bool]$ok) { throw "the last active-assignments snapshot failed: $(Get-PimMgmtReportField $e 'error')" }
            $rows = @(Get-PimMgmtReportField $e 'rows')
            $standing = @($rows | Where-Object { $null -ne $_ -and -not "$(Get-PimMgmtReportField $_ 'end')".Trim() }).Count
            [pscustomobject]@{ standing = [long]$standing; total = [long]$rows.Count; asOfUtc = "$(Get-PimMgmtReportField $e 'refreshedUtc')" }
        }
        drift = {
            param($period)
            $e = Read-PimMgmtReportCacheEntry -Kind 'drift' -What "drift check (job 'drift-snapshot')"
            $pol = @(@(Get-PimMgmtReportField $e 'scopes') | Where-Object { $null -ne $_ -and "$(Get-PimMgmtReportField $_ 'scope')" -match '(?i)policies$' })
            $checked = @($pol | Where-Object { (Get-PimMgmtReportField $_ 'checked') -ne $false -and (Get-PimMgmtReportField $_ 'ok') -ne $false })
            if (-not $checked.Count) { throw 'the last drift check did not compare any policy area' }
            $desired = 0L; $out = 0L
            foreach ($s in $checked) { $desired += [long]"$(Get-PimMgmtReportField $s 'desired')"; $out += [long]"$(Get-PimMgmtReportField $s 'missing')" + [long]"$(Get-PimMgmtReportField $s 'changed')" }
            if ($desired -le 0) { throw 'no policy is defined, so there is no baseline to compare with' }
            [pscustomobject]@{ percent = [long][math]::Floor(100.0 * [math]::Max(0, $desired - $out) / $desired); outOfBaseline = $out; desired = $desired; asOfUtc = "$(Get-PimMgmtReportField $e 'refreshedUtc')"; notChecked = ($pol.Count - $checked.Count) }
        }
        coverage = {
            param($period)
            $e = Read-PimMgmtReportCacheEntry -Kind 'coverage-report' -What "discovery report (job 'coverage')"
            $c = Get-PimMgmtReportField $e 'counts'
            if ($null -eq $c) { throw 'the stored discovery report carries no counts' }
            [pscustomobject]@{ gaps = [long]"$(Get-PimMgmtReportField $c 'Gap')"; covered = [long]"$(Get-PimMgmtReportField $c 'Covered')"; asOfUtc = "$(Get-PimMgmtReportField $e 'refreshedUtc')" }
        }
        guardHolds = {
            param($period)
            if (-not (Get-Command Get-PimGuardHolds -ErrorAction SilentlyContinue)) { throw 'the guard library is not loaded in this process' }
            $h = @(Get-PimGuardHolds -Fresh)
            [pscustomobject]@{ count = [long]$h.Count; guards = @($h | ForEach-Object { "$(Get-PimMgmtReportField $_ 'guardId')" } | Where-Object { $_ } | Select-Object -Unique) }
        }
        jobs = {
            param($period)
            if (-not (Get-Command Get-PimJobRunHistory -ErrorAction SilentlyContinue)) { throw 'the scheduler library is not loaded in this process, so the job run history cannot be read' }
            Get-PimMgmtReportJobFacts -Runs @(Get-PimJobRunHistory) -Period $period
        }
        tier = {
            param($period)
            # (the tick loads PIM-Notifications.ps1; the Manager replaces this reader with its own tier-impact report)
            if (-not (Get-Command Get-PimTierReportAssignmentsFromStore -ErrorAction SilentlyContinue) -or -not (Get-Command Get-PimTierZeroOneReport -ErrorAction SilentlyContinue)) { throw 'the tier report library is not loaded in this process' }
            $src = Get-PimTierReportAssignmentsFromStore
            if (-not $src.ok) { throw "the admin assignments could not be read: $($src.error)" }
            $rep = @(Get-PimTierZeroOneReport -Assignments @($src.rows))
            [pscustomobject]@{ tier0 = [long]@($rep | Where-Object { [int]$_.highestTier -eq 0 }).Count; tier1 = [long]@($rep | Where-Object { [int]$_.highestTier -eq 1 }).Count }
        }
        reviewsOverdue = {
            param($period)
            if (-not (Get-Command Get-PimAccessReviewOverdue -ErrorAction SilentlyContinue)) { throw 'the access review reader is not loaded in this process' }
            $r = @(Get-PimAccessReviewOverdue)
            [pscustomobject]@{ overdue = [long]@($r | Where-Object { $_.IsOverdue }).Count; dueSoon = [long]@($r | Where-Object { $_.IsDueSoon }).Count }
        }
        operationalPolicy = {
            param($period)
            $p = $null
            if (Get-Command Get-PimEngineOperationalPolicy -ErrorAction SilentlyContinue) { $p = Get-PimEngineOperationalPolicy }
            else { throw 'the operational policy library is not loaded in this process' }
            $v = Get-PimMgmtReportField $p 'value'; if ($null -eq $v) { $v = $p }
            $m = Get-PimMgmtReportField $v 'mfaOnActivation'
            if ($null -eq $m) { throw 'the operational policy carries no MFA setting' }
            [pscustomobject]@{ mfaOnActivation = [bool]$m }
        }
    }
}

function Get-PimMgmtReportJobFacts {
    <#
      PURE. The job run history -> { failing (the jobs whose LATEST run failed now); failedRuns / prevFailedRuns in the two
      windows; historySinceUtc }. Skipped, held, out-of-scope and "no handler on this worker" runs are not failures (the Jobs
      page's own rule).
    #>
    param([object[]]$Runs = @(), [Parameter(Mandatory)][object]$Period)
    $isFail = { param($r) (Get-PimMgmtReportField $r 'ok') -eq $false -and "$(Get-PimMgmtReportField $r 'status')" -notin @('skipped', 'held', 'warning', 'cancelled') -and -not [bool](Get-PimMgmtReportField $r 'outOfScope') -and "$(Get-PimMgmtReportField $r 'detail')" -notmatch '^no-handler' }
    $latest = @{}; $since = $null; $cur = 0L; $prev = 0L
    foreach ($r in @($Runs)) {
        if ($null -eq $r) { continue }
        $t = ConvertTo-PimMgmtReportUtc (Get-PimMgmtReportField $r 'startedUtc')
        if ($null -eq $t) { continue }
        if ($null -eq $since -or $t -lt $since) { $since = $t }
        $n = "$(Get-PimMgmtReportField $r 'name')"
        if (-not $latest.ContainsKey($n) -or $t -gt $latest[$n].t) { $latest[$n] = @{ t = $t; r = $r } }
        if (& $isFail $r) {
            if ($t -ge $Period.fromUtc -and $t -lt $Period.toUtc) { $cur++ }
            elseif ($t -ge $Period.prevFromUtc -and $t -lt $Period.prevToUtc) { $prev++ }
        }
    }
    $failing = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($latest.Keys | Sort-Object)) {
        $r = $latest[$k].r
        if (& $isFail $r) { $failing.Add([pscustomobject]@{ name = $k; lastRunUtc = $latest[$k].t.ToString('o'); detail = "$(Get-PimMgmtReportField $r 'detail')" }) }
    }
    return [pscustomobject]@{ failing = $failing.ToArray(); failedRuns = $cur; prevFailedRuns = $prev; historySinceUtc = $(if ($since) { $since.ToString('o') } else { '' }); runs = @($Runs).Count }
}

function Read-PimMgmtReportSources {
    <#
      Runs every query and reader ON ITS OWN -- one unreadable source never hides the others. Returns a hashtable:
        cur.<name> / prev.<name>   the period counts (Get-PimMgmtReportAuditQueries) for the period and the one before
        snap.<name>                the figures as they are now (Get-PimMgmtReportSnapshotQueries)
        rows.<name>                the period lists (Get-PimMgmtReportRowQueries)
        read.<name>                the readers (Get-PimMgmtReportDefaultReaders, or -Readers)
      each @{ ok; value; error }.
    #>
    param([Parameter(Mandatory)][object]$Period, [scriptblock]$Query = $null, [string]$ConnectionString = '', [hashtable]$Readers = $null)
    if (-not $Query) {
        # invoked below, inside this function: $ConnectionString is found by scope, no closure needed
        $Query = {
            param($name, $sql, $params, $kind)
            if (-not "$ConnectionString".Trim()) { throw 'this process has no SQL store, so the figure cannot be read' }
            if ($kind -eq 'rows') { return , (Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql $sql -Parameters $params) }
            return (Invoke-PimSqlScalar -ConnectionString $ConnectionString -Sql $sql -Parameters $params)
        }
    }
    if ($null -eq $Readers) { $Readers = Get-PimMgmtReportDefaultReaders }
    $res = @{}
    $fail = { param($k, $e) $res[$k] = @{ ok = $false; value = $null; error = ("$($e.Exception.Message)" -replace '\s+', ' ').Trim() } }
    $aq = Get-PimMgmtReportAuditQueries
    foreach ($n in @($aq.Keys)) {
        $sql = "$($aq[$n])"
        try { $res["cur.$n"] = @{ ok = $true; value = (& $Query $n $sql @{ f = $Period.fromUtc; t = $Period.toUtc } 'scalar'); error = '' } } catch { & $fail "cur.$n" $_ }
        try { $res["prev.$n"] = @{ ok = $true; value = (& $Query $n $sql @{ f = $Period.prevFromUtc; t = $Period.prevToUtc } 'scalar'); error = '' } } catch { & $fail "prev.$n" $_ }
    }
    $sq = Get-PimMgmtReportSnapshotQueries
    foreach ($n in @($sq.Keys)) {
        try { $res["snap.$n"] = @{ ok = $true; value = (& $Query $n "$($sq[$n])" @{} 'scalar'); error = '' } } catch { & $fail "snap.$n" $_ }
    }
    $rq = Get-PimMgmtReportRowQueries
    foreach ($n in @($rq.Keys)) {
        try { $res["rows.$n"] = @{ ok = $true; value = (ConvertTo-PimMgmtReportRowArray (& $Query $n "$($rq[$n])" @{ f = $Period.fromUtc; t = $Period.toUtc } 'rows')); error = '' } } catch { & $fail "rows.$n" $_ }
        if ($n -eq 'reviewOutcomes') {   # the review outcomes carry a trend too
            try { $res["prevrows.$n"] = @{ ok = $true; value = (ConvertTo-PimMgmtReportRowArray (& $Query $n "$($rq[$n])" @{ f = $Period.prevFromUtc; t = $Period.prevToUtc } 'rows')); error = '' } } catch { & $fail "prevrows.$n" $_ }
        }
    }
    foreach ($n in @($Readers.Keys)) {
        $rdr = $Readers[$n]
        if (-not ($rdr -is [scriptblock])) { continue }
        try { $res["read.$n"] = @{ ok = $true; value = (& $rdr $Period); error = '' } } catch { & $fail "read.$n" $_ }
    }
    return $res
}

function ConvertTo-PimMgmtReportLong {
    # PURE. A scalar result -> [long]; $null when it is not a number (DBNull = 0: COUNT over nothing).
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.DBNull]) { return 0L }
    $d = 0.0
    if ([double]::TryParse("$Value", [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return [long][math]::Round($d) }
    return $null
}

function New-PimMgmtReportFigure {
    <#
      PURE. One figure: available + value (or the reason it is not), and the trend against the previous period when that is
      KNOWN (-PrevKnown); otherwise trendText 'no earlier data'. -Good: which direction is good (up | down | neutral).
      -Display overrides the number text ("On", "93%", "4 of 12").
    #>
    param([string]$Key, [string]$Label, [AllowNull()][object]$Value, [bool]$Available, [string]$Reason = '',
          [AllowNull()][object]$Prev = $null, [bool]$PrevKnown = $false, [string]$PrevLabel = 'the previous period', [string]$NoPrevReason = '',
          [ValidateSet('up', 'down', 'neutral')][string]$Good = 'neutral', [string]$Info = '', [string]$Display = '', [string]$Note = '', [string]$Unit = '',
          # a setting, not a count: no trend line at all
          [switch]$NoTrend)
    if (-not $Available) {
        return [pscustomobject][ordered]@{ key = $Key; label = $Label; available = $false; value = $null; text = 'not available'; reason = $(if ($Reason) { $Reason } else { 'the source could not be read' })
            prev = $null; trend = 'none'; trendText = ''; tone = 'na'; info = $Info; note = $Note }
    }
    $v = ConvertTo-PimMgmtReportLong $Value
    $text = if ($Display) { $Display } elseif ($null -ne $v) { (Format-PimMgmtReportNumber $v) + $Unit } else { "$Value" }
    $trend = 'none'; $tt = 'no earlier data'; $tone = 'neutral'; $pv = $null
    if ($PrevKnown -and $null -ne $v) {
        $pv = ConvertTo-PimMgmtReportLong $Prev
        if ($null -ne $pv) {
            $d = $v - $pv
            if ($d -gt 0) { $trend = 'up'; $tt = ('+{0}{1} vs {2}' -f (Format-PimMgmtReportNumber $d), $Unit, $PrevLabel) }
            elseif ($d -lt 0) { $trend = 'down'; $tt = ('-{0}{1} vs {2}' -f (Format-PimMgmtReportNumber ([math]::Abs($d))), $Unit, $PrevLabel) }
            else { $trend = 'flat'; $tt = "no change vs $PrevLabel" }
            if ($Good -ne 'neutral' -and $trend -in @('up', 'down')) { $tone = if ($trend -eq $Good) { 'good' } else { 'bad' } }
        }
    }
    if ($trend -eq 'none' -and $NoPrevReason) { $tt = "no earlier data ($NoPrevReason)" }
    if ($NoTrend) { $trend = 'none'; $tt = ''; $tone = 'neutral' }
    return [pscustomobject][ordered]@{ key = $Key; label = $Label; available = $true; value = $v; text = $text; reason = ''
        prev = $pv; trend = $trend; trendText = $tt; tone = $tone; info = $Info; note = $Note }
}

function Find-PimMgmtReportHistoryValue {
    <#
      PURE. A snapshot figure's value at the START of the period, from the stored history of earlier reports
      ([{ asOfUtc; figures = { key = value } }]): the entry nearest to -AtUtc within -ToleranceDays. $null = no earlier data.
    #>
    param([object[]]$History = @(), [string]$Key, [datetime]$AtUtc, [double]$ToleranceDays = 1)
    $best = $null; $bestDiff = [double]::MaxValue
    foreach ($h in @($History)) {
        if ($null -eq $h) { continue }
        $t = ConvertTo-PimMgmtReportUtc (Get-PimMgmtReportField $h 'asOfUtc')
        if ($null -eq $t) { continue }
        $f = Get-PimMgmtReportField $h 'figures'
        $v = Get-PimMgmtReportField $f $Key
        if ($null -eq $v) { continue }
        $diff = [math]::Abs(($t - $AtUtc).TotalDays)
        if ($diff -le $ToleranceDays -and $diff -lt $bestDiff) { $best = $v; $bestDiff = $diff }
    }
    return $best
}

function New-PimMgmtReportModel {
    <#
      PURE. Sources (Read-PimMgmtReportSources) + period + chosen sections -> the report model:
        { title; environment; period; generatedUtc; sections = @({ id; title; description; figures; bars; tables; notes });
          figures (key -> value: every AVAILABLE snapshot figure, kept as history for the next report's trends);
          notAvailable (the keys that could not be read) }
    #>
    param([Parameter(Mandatory)][hashtable]$Sources, [Parameter(Mandatory)][object]$Period, [string[]]$Sections = @('kpi', 'risk', 'changes', 'compliance'),
          [string]$Environment = '', [object[]]$History = @(), [datetime]$NowUtc = [datetime]::UtcNow, [string]$Title = 'Management report')
    $src = { param($k) $r = $Sources[$k]; if ($null -eq $r) { @{ ok = $false; value = $null; error = "$k was not read" } } else { $r } }
    $tol = [math]::Max(1.0, 0.25 * [double]$Period.days)
    # the audit trail decides whether the previous period can be compared
    $since = & $src 'snap.auditSince'
    $sinceUtc = if ($since.ok) { ConvertTo-PimMgmtReportUtc $since.value } else { $null }
    $auditPrevOk = ($since.ok -and $null -ne $sinceUtc -and $sinceUtc -le $Period.prevFromUtc)
    $auditNoPrev = if (-not $since.ok) { 'the audit trail could not be read' } elseif ($null -eq $sinceUtc) { 'the audit trail is empty' } elseif (-not $auditPrevOk) { 'the audit trail starts ' + (Format-PimMgmtReportDate $sinceUtc) } else { '' }
    $audit = {
        param($name, $label, $good, $info)
        $c = & $src "cur.$name"; $p = & $src "prev.$name"
        $pk = ($auditPrevOk -and $p.ok)
        New-PimMgmtReportFigure -Key $name -Label $label -Value $c.value -Available ([bool]$c.ok -and $null -ne (ConvertTo-PimMgmtReportLong $c.value)) -Reason $(if ($c.ok) { 'the audit trail returned no number' } else { "the audit trail could not be read: $($c.error)" }) `
            -Prev $p.value -PrevKnown $pk -PrevLabel $Period.prevLabel -NoPrevReason $(if ($auditNoPrev) { $auditNoPrev } elseif (-not $p.ok) { 'the previous period could not be read' } else { '' }) -Good $good -Info $info
    }
    $snapFig = {
        param($key, $label, $value, $ok, $reason, $good, $info, $display, $note)
        $pv = Find-PimMgmtReportHistoryValue -History $History -Key $key -AtUtc $Period.fromUtc -ToleranceDays $tol
        New-PimMgmtReportFigure -Key $key -Label $label -Value $value -Available ([bool]$ok) -Reason $reason -Prev $pv -PrevKnown ($null -ne $pv) -PrevLabel ('the start of the period') `
            -NoPrevReason $(if ($null -eq $pv) { 'no stored report from the start of the period' } else { '' }) -Good $good -Info $info -Display $display -Note $note
    }
    $snapSql = {
        param($name, $label, $good, $info)
        $s = & $src "snap.$name"
        & $snapFig $name $label $s.value ([bool]$s.ok -and $null -ne (ConvertTo-PimMgmtReportLong $s.value)) $(if ($s.ok) { 'the store returned no number' } else { "the store could not be read: $($s.error)" }) $good $info '' ''
    }
    $reader = {
        param($name) $r = & $src "read.$name"; $r
    }
    $readerFig = {
        param($rname, $key, $label, $prop, $good, $info, $notePrefix)
        $r = & $reader $rname
        $val = if ($r.ok) { Get-PimMgmtReportField $r.value $prop } else { $null }
        $asOf = if ($r.ok) { "$(Get-PimMgmtReportField $r.value 'asOfUtc')" } else { '' }
        $note = if ($asOf) { "$notePrefix as of " + (Format-PimMgmtReportDate $asOf -Time) + ' UTC' } else { '' }
        & $snapFig $key $label $val ([bool]$r.ok -and $null -ne (ConvertTo-PimMgmtReportLong $val)) $(if ($r.ok) { 'the source returned no number' } else { "$($r.error)" }) $good $info '' $note
    }
    $flat = [ordered]@{}; $na = New-Object System.Collections.Generic.List[string]
    $secOut = New-Object System.Collections.Generic.List[object]
    $addFigs = { param($list) foreach ($f in @($list)) { if (-not $f.available) { if (-not $na.Contains($f.key)) { $na.Add($f.key) } } } }
    $bar = { param($f, $label) if ($f.available -and $null -ne $f.value) { [pscustomobject]@{ label = $label; value = $f.value; tone = '' } } }
    $naNote = { param($figs) $m = @(@($figs) | Where-Object { -not $_.available } | ForEach-Object { $_.label }); if ($m.Count) { 'Not available (left out of the chart): ' + ($m -join ', ') } else { '' } }

    # the figures the sections share (built once)
    $fEngine   = & $audit 'engineChanges' 'Changes applied by the engine' 'neutral' 'Every create, update and remove the engine carried out in the tenant with result OK (audit trail; dry runs excluded).'
    $fAdds     = & $audit 'adds' 'Access added' 'neutral' 'Delegations the engine created: group memberships, role and Azure assignments, workload roles.'
    $fRemovals = & $audit 'removals' 'Access removed' 'neutral' 'Delegations the engine removed.'
    $fPolicy   = & $audit 'policyChanges' 'Policy changes' 'neutral' 'PIM policies (groups, Entra roles, Azure roles) the engine updated.'
    $fAdminNew = & $audit 'adminCreated' 'Admin accounts created' 'neutral' 'Admin accounts the engine created.'
    $fOffboard = & $audit 'offboardings' 'Offboarding steps' 'neutral' 'Offboarding steps the engine carried out (access removed, accounts disabled).'
    $fErrors   = & $audit 'engineErrors' 'Engine changes that failed' 'down' 'Changes the engine tried and the tenant refused (audit trail, result error).'
    $fApprov   = & $audit 'approvals' 'Approval decisions' 'neutral' 'Requests approved or denied by a second person, and approved mass-change holds.'
    $fReviews  = & $audit 'reviewDecisions' 'Review decisions' 'up' 'Access review decisions, external-company answers and department-owner keep / remove / extend decisions.'
    $fBreak    = & $audit 'breakGlassUse' 'Emergency override activations' 'down' 'Times the emergency (break-glass) override was switched on.'
    $fTrips    = & $audit 'guardTrips' 'Guard holds' 'down' 'Times a protective guard held a change set (a mass removal, a policy weakening, ...) before it reached the tenant.'
    $fEligible = & $snapSql 'eligible' 'Eligible assignments managed' 'up' 'Assignments PIM manages as ELIGIBLE (activated when needed) instead of standing.'
    $fAdmins   = & $snapSql 'admins' 'Admin accounts managed' 'neutral' 'Admin account definitions in PIM Manager.'
    $fStanding = & $readerFig 'activeAssignments' 'standing' 'Standing access (no end date)' 'standing' 'down' 'Active assignments with no end date, from the active-assignments snapshot.' 'snapshot'
    $fHeld     = & $readerFig 'guardHolds' 'heldNow' 'Change sets held now' 'count' 'down' 'Change sets a guard holds right now, waiting for a SuperAdmin.' ''
    $fOverdue  = & $readerFig 'reviewsOverdue' 'overdueReviews' 'Overdue access reviews' 'overdue' 'down' 'Access review instances past their due date (live read).' ''
    $fTier0    = & $readerFig 'tier' 'tier0' 'People with Tier 0 access' 'tier0' 'down' 'People whose highest delegated tier is Tier 0 (from the admin assignments).' ''
    $fGaps     = & $readerFig 'coverage' 'coverageGaps' 'Discovery gaps' 'gaps' 'down' 'Roles, scopes and groups with no delegation, from the discovery report.' 'report'
    # jobs: failing now (snapshot) + failed runs in the period (the run history reaches back only so far)
    $jr = & $reader 'jobs'
    $jobsNow = if ($jr.ok) { [long]@(Get-PimMgmtReportField $jr.value 'failing').Count } else { $null }
    $fFailing = & $snapFig 'openFailures' 'Jobs failing now' $jobsNow ([bool]$jr.ok) "$($jr.error)" 'down' 'Jobs whose latest run failed (the Jobs page).' '' ''
    $histSince = if ($jr.ok) { ConvertTo-PimMgmtReportUtc (Get-PimMgmtReportField $jr.value 'historySinceUtc') } else { $null }
    $runsPrevOk = ($null -ne $histSince -and $histSince -le $Period.prevFromUtc)
    $runsNote = if ($null -ne $histSince -and $histSince -gt $Period.fromUtc) { 'the run history covers this period only from ' + (Format-PimMgmtReportDate $histSince) } else { '' }
    $fFailedRuns = New-PimMgmtReportFigure -Key 'failedRuns' -Label 'Failed job runs' -Value $(if ($jr.ok) { Get-PimMgmtReportField $jr.value 'failedRuns' } else { $null }) -Available ([bool]$jr.ok) -Reason "$($jr.error)" `
        -Prev $(if ($jr.ok) { Get-PimMgmtReportField $jr.value 'prevFailedRuns' } else { $null }) -PrevKnown $runsPrevOk -PrevLabel $Period.prevLabel `
        -NoPrevReason $(if (-not $runsPrevOk -and $null -ne $histSince) { 'the run history starts ' + (Format-PimMgmtReportDate $histSince) } elseif ($jr.ok) { 'the run history is empty' } else { '' }) -Good 'down' -Info 'Scheduled job runs that failed (skipped, held and out-of-scope runs are not failures).' -Note $runsNote
    # compliance
    $tally = {
        param($res)
        $t = @{ approve = 0L; deny = 0L; other = 0L }
        if ($res.ok) { foreach ($row in @($res.value)) { if ($null -eq $row) { continue }; $o = "$(Get-PimMgmtReportField $row 'outcome')".Trim().ToLowerInvariant(); $c = ConvertTo-PimMgmtReportLong (Get-PimMgmtReportField $row 'n'); if ($null -eq $c) { continue }; if ($o -eq 'approve') { $t.approve += $c } elseif ($o -eq 'deny') { $t.deny += $c } else { $t.other += $c } } }
        $t
    }
    $rv = & $src 'rows.reviewOutcomes'; $rvp = & $src 'prevrows.reviewOutcomes'
    $outc = & $tally $rv; $outp = & $tally $rvp
    $rvPk = ($auditPrevOk -and [bool]$rvp.ok)
    $rvNo = if ($auditNoPrev) { $auditNoPrev } elseif (-not $rvp.ok) { 'the previous period could not be read' } else { '' }
    $rvReason = "the audit trail could not be read: $($rv.error)"
    $fRvKeep = New-PimMgmtReportFigure -Key 'reviewApproved' -Label 'Review: access kept' -Value $outc.approve -Available ([bool]$rv.ok) -Reason $rvReason -Prev $outp.approve -PrevKnown $rvPk -PrevLabel $Period.prevLabel -NoPrevReason $rvNo -Info 'Access review decisions Approve (keep) in the period.'
    $fRvDeny = New-PimMgmtReportFigure -Key 'reviewDenied' -Label 'Review: access removed' -Value $outc.deny -Available ([bool]$rv.ok) -Reason $rvReason -Prev $outp.deny -PrevKnown $rvPk -PrevLabel $Period.prevLabel -NoPrevReason $rvNo -Info 'Access review decisions Deny (remove) in the period.'
    $fRvOther = New-PimMgmtReportFigure -Key 'reviewOther' -Label "Review: don't know / other" -Value $outc.other -Available ([bool]$rv.ok) -Reason $rvReason -Prev $outp.other -PrevKnown $rvPk -PrevLabel $Period.prevLabel -NoPrevReason $rvNo -Info 'Access review decisions that were neither Approve nor Deny.'
    $dr = & $reader 'drift'
    $drPct = if ($dr.ok) { Get-PimMgmtReportField $dr.value 'percent' } else { $null }
    $fConf = & $snapFig 'policyConformance' 'Policies matching the baseline' $drPct ([bool]$dr.ok) "$($dr.error)" 'up' 'Defined PIM policies whose live settings match the template (the last drift check of the policy areas).' $(if ($dr.ok) { "$drPct%" } else { '' }) $(if ($dr.ok) { ('{0} of {1} policies differ; as of {2} UTC' -f (Get-PimMgmtReportField $dr.value 'outOfBaseline'), (Get-PimMgmtReportField $dr.value 'desired'), (Format-PimMgmtReportDate (Get-PimMgmtReportField $dr.value 'asOfUtc') -Time)) } else { '' })
    $op = & $reader 'operationalPolicy'
    $mfa = if ($op.ok) { [bool](Get-PimMgmtReportField $op.value 'mfaOnActivation') } else { $null }
    $fMfa = New-PimMgmtReportFigure -Key 'mfaOnActivation' -Label 'MFA required on activation' -Value $(if ($null -eq $mfa) { $null } elseif ($mfa) { 1 } else { 0 }) -Available ([bool]$op.ok) -Reason "$($op.error)" -Display $(if ($null -eq $mfa) { '' } elseif ($mfa) { 'On' } else { 'Off' }) -Info 'The operational policy floor: every activation the engine writes requires MFA (Settings > Operational policy).' -NoTrend
    $ad = & $src 'snap.approvalDefs'; $dd = & $src 'snap.definitions'
    $adV = ConvertTo-PimMgmtReportLong $ad.value; $ddV = ConvertTo-PimMgmtReportLong $dd.value
    $adOk = ($ad.ok -and $dd.ok -and $null -ne $adV -and $null -ne $ddV)
    $fApprDefs = & $snapFig 'approvalDefs' 'Groups that require approval' $adV $adOk $(if (-not $ad.ok) { "the store could not be read: $($ad.error)" } elseif (-not $dd.ok) { "the store could not be read: $($dd.error)" } else { 'the store returned no number' }) 'neutral' `
        'Group definitions linked to an approval policy template (a definition with a blank template uses the default template and is not counted).' $(if ($adOk) { "$adV of $ddV" } else { '' }) ''

    foreach ($sid in @($Sections)) {
        $cat = @($script:PimMgmtReportSectionCatalog | Where-Object { $_.id -eq $sid }) | Select-Object -First 1
        if (-not $cat) { continue }
        $figs = @(); $bars = New-Object System.Collections.Generic.List[object]; $tables = New-Object System.Collections.Generic.List[object]; $notes = New-Object System.Collections.Generic.List[string]
        switch ($sid) {
            'kpi' {
                $figs = @($fEngine, $fAdds, $fRemovals, $fApprov, $fReviews, $fEligible, $fAdmins, $fErrors)
                $kinds = @($fAdds, $fRemovals, $fPolicy, $fAdminNew, $fOffboard)
                $bars.Add([pscustomobject]@{ title = 'Changes in the period, by kind'; orientation = 'h'; items = @(foreach ($f in $kinds) { & $bar $f $f.label }); note = (& $naNote $kinds) })
            }
            'risk' {
                $figs = @($fStanding, $fBreak, $fTrips, $fHeld, $fOverdue, $fFailing, $fTier0, $fFailedRuns)
                if ($jr.ok) {
                    $rows = New-Object System.Collections.Generic.List[object]
                    foreach ($j in @(Get-PimMgmtReportField $jr.value 'failing')) { $rows.Add(@("$($j.name)", (Format-PimMgmtReportDate $j.lastRunUtc -Time), "$($j.detail)")) }
                    if ($rows.Count) { $tables.Add([pscustomobject]@{ title = 'Jobs failing now'; columns = @('Job', 'Last run (UTC)', 'What happened'); rows = $rows.ToArray(); note = 'Each job and its log: Jobs page.' }) }
                    else { $notes.Add('No job is failing now.') }
                } else { $notes.Add("The job run history could not be read: $($jr.error)") }
                $hd = & $reader 'guardHolds'
                if ($hd.ok -and @(Get-PimMgmtReportField $hd.value 'guards').Count) { $notes.Add('Guards holding a change set now: ' + (@(Get-PimMgmtReportField $hd.value 'guards') -join ', ') + '.') }
            }
            'changes' {
                $figs = @($fAdds, $fRemovals, $fPolicy, $fAdminNew, $fOffboard, $fApprov)
                $kinds = @($fAdds, $fRemovals, $fPolicy, $fAdminNew, $fOffboard, $fApprov)
                $bars.Add([pscustomobject]@{ title = 'Changes and approvals in the period'; orientation = 'v'; items = @(foreach ($f in $kinds) { & $bar $f $f.label }); note = (& $naNote $kinds) })
                $ap = & $src 'rows.approvers'
                if ($ap.ok) {
                    $rows = New-Object System.Collections.Generic.List[object]
                    foreach ($r in @($ap.value)) { if ($null -ne $r) { $rows.Add(@("$(Get-PimMgmtReportField $r 'actor')", (Format-PimMgmtReportNumber (ConvertTo-PimMgmtReportLong (Get-PimMgmtReportField $r 'n'))))) } }
                    $tables.Add([pscustomobject]@{ title = 'Who approved'; columns = @('Approver', 'Decisions'); rows = $rows.ToArray(); note = $(if ($rows.Count) { 'Approvals and denials by a second person, and approved mass-change holds.' } else { 'No approval decision was recorded in this period.' }) })
                } else { $notes.Add("Who approved: not available -- the audit trail could not be read: $($ap.error)") }
                $rc = & $src 'rows.recentChanges'
                if ($rc.ok) {
                    $rows = New-Object System.Collections.Generic.List[object]
                    foreach ($r in @($rc.value)) { if ($null -ne $r) { $rows.Add(@((Format-PimMgmtReportDate (Get-PimMgmtReportField $r 'ts') -Time), "$(Get-PimMgmtReportField $r 'target')", "$(Get-PimMgmtReportField $r 'actor')", "$(Get-PimMgmtReportField $r 'result')")) } }
                    $tables.Add([pscustomobject]@{ title = 'Changes applied, newest first'; columns = @('When (UTC)', 'Change', 'Asked by', 'Result'); rows = $rows.ToArray()
                        note = $(if ($rows.Count) { ('The newest {0} changes of the period. The full trail: Audit page.' -f $rows.Count) } else { 'The engine applied no change in this period.' }) })
                } else { $notes.Add("Changes applied: not available -- the audit trail could not be read: $($rc.error)") }
            }
            'compliance' {
                $figs = @($fRvKeep, $fRvDeny, $fConf, $fGaps, $fMfa, $fApprDefs)
                $rvf = @($fRvKeep, $fRvDeny, $fRvOther)
                $bars.Add([pscustomobject]@{ title = 'Access review outcomes in the period'; orientation = 'h'; items = @(foreach ($f in $rvf) { & $bar $f ($f.label -replace '^Review: ', '') }); note = $(if (-not $rv.ok) { "Not available: $rvReason" } else { '' }) })
            }
        }
        & $addFigs $figs
        foreach ($f in $figs) { if ($f.available -and $null -ne $f.value) { $flat[$f.key] = $f.value } }
        $secOut.Add([pscustomobject][ordered]@{ id = $sid; title = "$($cat.title)"; description = "$($cat.description)"; figures = $figs; bars = $bars.ToArray(); tables = $tables.ToArray(); notes = $notes.ToArray() })
    }
    return [pscustomobject][ordered]@{
        title = $Title; environment = $Environment; period = $Period; generatedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        sections = $secOut.ToArray(); figures = $flat; notAvailable = $na.ToArray()
    }
}

function ConvertTo-PimMgmtReportSlides {
    <#
      PURE. The model -> the slide list for New-PimPptxBytes: a title slide, a summary slide (the headline of each section),
      then per section: its KPI tiles, its charts, its tables (split over slides by the writer when long).
    #>
    param([Parameter(Mandatory)][object]$Model)
    $out = New-Object System.Collections.Generic.List[object]
    $p = $Model.period
    $secTitles = @($Model.sections | ForEach-Object { $_.title })
    $out.Add([pscustomobject]@{ kind = 'title'; title = "$($Model.title)"; subtitle = "$($p.label)"
        lines = @(("Environment: {0}" -f $(if ("$($Model.environment)".Trim()) { $Model.environment } else { 'this environment' })),
                  ("Compared with: {0}" -f $p.prevLabel), ("Generated: {0} UTC" -f (Format-PimMgmtReportDate $Model.generatedUtc -Time)),
                  ("Sections: {0}" -f ($secTitles -join ', '))) })
    $sum = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($Model.sections)) {
        $top = @(@($s.figures) | Where-Object { $_.available } | Select-Object -First 3)
        if ($top.Count) { $sum.Add(("{0}: " -f $s.title) + (@($top | ForEach-Object { '{0} {1}{2}' -f $_.label, $_.text, $(if ($_.trend -ne 'none') { " ($($_.trendText))" } else { '' }) }) -join '; ')) }
    }
    $naCount = @($Model.notAvailable).Count
    if ($naCount) { $sum.Add(("{0} figure(s) could not be read -- they are marked 'not available' with the reason, never shown as 0." -f $naCount)) }
    $out.Add([pscustomobject]@{ kind = 'content'; title = 'Summary'; subtitle = "$($p.label)"; bullets = $sum.ToArray()
        note = 'A trend compares with the previous period only where PIM Manager holds data from then; otherwise the tile says "no earlier data".' })
    foreach ($s in @($Model.sections)) {
        $kpis = @(@($s.figures) | ForEach-Object {
            $arrow = switch ("$($_.trend)") { 'up' { 'up' } 'down' { 'down' } 'flat' { 'flat' } default { 'none' } }
            @{ label = $_.label; value = $_.text; sub = $(if ($_.available) { $_.trendText } else { '' }); tone = $_.tone; arrow = $arrow
               note = $(if (-not $_.available) { $_.reason } else { $_.note }) } })
        $notes = @($s.notes)
        $out.Add([pscustomobject]@{ kind = 'content'; title = $s.title; subtitle = $s.description; kpis = $kpis; note = $(if ($notes.Count) { $notes -join ' ' } else { '' }) })
        foreach ($b in @($s.bars)) { $out.Add([pscustomobject]@{ kind = 'content'; title = $s.title; subtitle = $b.title; bars = [pscustomobject]@{ orientation = $b.orientation; items = @($b.items); note = $b.note } }) }
        foreach ($t in @($s.tables)) { $out.Add([pscustomobject]@{ kind = 'content'; title = ('{0} - {1}' -f $s.title, $t.title); subtitle = "$($p.label)"; table = [pscustomobject]@{ columns = @($t.columns); rows = $t.rows; note = $t.note } }) }
    }
    return , $out.ToArray()
}

function Get-PimMgmtReportLogoPng {
    <# The PIM Manager Pro logo (docs/img/brand, shipped in the image -- BRAND-1); the plain logo; $null when neither is there. #>
    param([string]$BrandDir = '')
    $dir = $BrandDir
    if (-not $dir -and "$($global:PIM_BrandDir)".Trim()) { $dir = "$($global:PIM_BrandDir)" }
    if (-not $dir -and $script:PimMgmtReportLibDir) { $dir = Join-Path (Split-Path -Parent (Split-Path -Parent $script:PimMgmtReportLibDir)) 'docs\img\brand' }
    foreach ($f in @('pim-manager-pro-512w.png', 'pim-manager-512w.png')) {
        $p = Join-Path $dir $f
        if (Test-Path -LiteralPath $p) {
            try { $b = [System.IO.File]::ReadAllBytes($p); if ($b.Length -gt 8 -and $b[0] -eq 0x89 -and $b[1] -eq 0x50) { return , $b } } catch { }
        }
    }
    return $null
}

function Get-PimMgmtReportFileName {
    param([Parameter(Mandatory)][object]$Model)
    $env = ("$($Model.environment)" -replace '[^A-Za-z0-9-]+', '-').Trim('-')
    if ($env.Length -gt 40) { $env = $env.Substring(0, 40).Trim('-') }
    $parts = @('PIM-Manager-management-report'); if ($env) { $parts += $env }; $parts += "$($Model.period.key)"
    return (($parts -join '-') + '.pptx')
}

function ConvertTo-PimMgmtReportPptx {
    <# The model -> the .pptx bytes (PIM-Pptx.ps1), with the footer: environment | period | PIM Manager. #>
    param([Parameter(Mandatory)][object]$Model, [AllowNull()][byte[]]$LogoPng = $null)
    $env = if ("$($Model.environment)".Trim()) { "$($Model.environment)" } else { 'This environment' }
    $footer = ('{0} | {1} | PIM Manager' -f $env, $Model.period.label)
    return , (New-PimPptxBytes -Slides (ConvertTo-PimMgmtReportSlides -Model $Model) -Footer $footer -LogoPng $LogoPng -Title ('{0} - {1}' -f $Model.title, $Model.period.label))
}

function Resolve-PimMgmtReportEnvironment {
    # The environment's name, the way the mails name it; '' when nothing knows it.
    try { if (Get-Command Get-PimMailEnvironmentInfo -ErrorAction SilentlyContinue) { $e = Get-PimMailEnvironmentInfo; if ("$($e.name)".Trim()) { return "$($e.name)".Trim() }; if ("$($e.tenantName)".Trim()) { return "$($e.tenantName)".Trim() } } } catch { }
    foreach ($v in @($global:PIM_EnvironmentName, $global:PIM_TenantName, $global:PIM_TenantLabel)) { if ("$v".Trim()) { return "$v".Trim() } }
    return ''
}

function Invoke-PimMgmtReportRequest {
    <#
      The wizard's request (GET /api/reports/management?sections=&period=&month=) -> { status; contentType; fileName; bytes;
      body; model }. Pro (hard): -ProGate { param($key) } must answer ok, else 403 with the licence line and NOTHING is read.
      A bad query = 400. The Manager writes the answer; the suites call this directly.
    #>
    param([string]$QueryString = '', [scriptblock]$ProGate = $null, [scriptblock]$Query = $null, [string]$ConnectionString = '', [hashtable]$Readers = $null,
          [object[]]$History = @(), [string]$Environment = '', [AllowNull()][byte[]]$LogoPng = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not $ProGate) { $ProGate = { param($k) if (Get-Command Test-PimFeatureProLicence -ErrorAction SilentlyContinue) { Test-PimFeatureProLicence -Key $k } else { [pscustomobject]@{ ok = $false; message = 'the licence check is not loaded in this process' } } } }
    $g = & $ProGate $script:PimMgmtReportFeatureKey
    if (-not ($g -and [bool](Get-PimMgmtReportField $g 'ok'))) {
        $msg = "$(Get-PimMgmtReportField $g 'message')"; if (-not $msg) { $msg = 'The management report requires a PIM Manager Pro licence. Contact info@invardia.com for a licence.' }
        return [pscustomobject]@{ status = 403; contentType = 'application/json'; fileName = ''; bytes = $null; model = $null
            body = [ordered]@{ ok = $false; pro = $true; feature = $script:PimMgmtReportFeatureKey; error = $msg; contact = 'info@invardia.com' } }
    }
    $pq = ConvertFrom-PimMgmtReportQuery -QueryString $QueryString
    if (-not $pq.ok) { return [pscustomobject]@{ status = 400; contentType = 'application/json'; fileName = ''; bytes = $null; model = $null; body = [ordered]@{ ok = $false; error = $pq.error } } }
    try { $period = Get-PimMgmtReportPeriod -Period $pq.period -Month $pq.month -NowUtc $NowUtc }
    catch { return [pscustomobject]@{ status = 400; contentType = 'application/json'; fileName = ''; bytes = $null; model = $null; body = [ordered]@{ ok = $false; error = "$($_.Exception.Message)" } } }
    $srcArgs = @{ Period = $period; ConnectionString = $ConnectionString }
    if ($Query) { $srcArgs['Query'] = $Query }
    if ($null -ne $Readers) { $srcArgs['Readers'] = $Readers }
    $sources = Read-PimMgmtReportSources @srcArgs
    $model = New-PimMgmtReportModel -Sources $sources -Period $period -Sections $pq.sections -Environment $Environment -History $History -NowUtc $NowUtc
    $bytes = ConvertTo-PimMgmtReportPptx -Model $model -LogoPng $LogoPng
    return [pscustomobject]@{ status = 200; contentType = $script:PimMgmtReportContentType; fileName = (Get-PimMgmtReportFileName -Model $model); bytes = $bytes; model = $model; body = $null }
}

# ---- the static MONTHLY report (scheduler job 'mgmt-report') ------------------------------------------------------------
function ConvertTo-PimMgmtReportConfig {
    <#
      PURE. pim.Settings 'ManagementReport' (JSON text / object / nothing) -> { monthlyEnabled; recipients }. OFF unless the
      setting says so (owner 2026-10-29: default OFF, a setting turns it on). Recipients: valid mail addresses only, unique.
    #>
    param([AllowNull()][object]$Value)
    $o = $Value
    if ($o -is [string]) { if ("$o".Trim()) { try { $o = $o | ConvertFrom-Json } catch { $o = $null } } else { $o = $null } }
    $m = Get-PimMgmtReportField $o 'monthly'
    $en = Get-PimMgmtReportField $m 'enabled'
    $enabled = if ($en -is [bool]) { $en } else { "$en".Trim() -match '^(?i)(true|1|yes|on)$' }
    $rc = New-Object System.Collections.Generic.List[string]
    foreach ($r in @(Get-PimMgmtReportField $m 'recipients')) {
        $a = "$r".Trim()
        if ($a -match '^[^@\s]+@[^@\s]+\.[^@\s]+$' -and -not ($rc | Where-Object { $_ -ieq $a })) { $rc.Add($a) }
    }
    return [pscustomobject]@{ monthlyEnabled = [bool]$enabled; recipients = $rc.ToArray() }
}

function New-PimMgmtReportMailTokens {
    <# The mail around the attached report: the period, the headline figures as "Topic: text" lines (no tables). #>
    param([Parameter(Mandatory)][object]$Model, [string]$FileName = '', [switch]$NotAttached)
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode("$t") }
    $lines = New-Object System.Text.StringBuilder
    $line = { param($k, $v) [void]$lines.Append('<div style="margin:0 0 8px 0;line-height:21px;"><b>' + (& $enc $k) + ':</b> ' + (& $enc $v) + '</div>') }
    & $line 'Period' $Model.period.label
    & $line 'Compared with' $Model.period.prevLabel
    foreach ($s in @($Model.sections)) {
        foreach ($f in @(@($s.figures) | Select-Object -First 3)) { & $line $f.label $(if ($f.available) { $f.text + $(if ($f.trend -ne 'none') { " ($($f.trendText))" } else { '' }) } else { "not available -- $($f.reason)" }) }
    }
    $att = if ($NotAttached) { 'The report is larger than a mail can carry: download it in PIM Manager, Reports > Management report.' } else { "The full report is attached ($FileName)." }
    $body = '<p style="margin:0 0 12px 0;line-height:21px;">' + (& $enc "The monthly management report of PIM Manager. $att") + '</p>' + $lines.ToString()
    $html = $body
    if (Get-Command New-PimMailDocument -ErrorAction SilentlyContinue) {
        try { $html = New-PimMailDocument -Title 'Monthly management report' -Subtitle "$($Model.period.label)" -Preheader "Management report: $($Model.period.label)" -BodyHtml $body -GeneratedUtc ([datetime]::UtcNow) } catch { $html = $body }
    } else { $html = '<div style="font-family:''Segoe UI'',Arial,sans-serif;font-size:14px;color:#24292f;padding:16px;max-width:600px;">' + $body + '</div>' }
    # PortalTab: the mail's link opens the Reports page (Get-PimPortalLink)
    return @{ ReportHtml = $html; Date = (Format-PimMgmtReportDate $Model.generatedUtc); PeriodLabel = "$($Model.period.label)"; PortalTab = 'reports' }
}

function Invoke-PimMgmtReportMonthlyJob {
    <#
      Job 'mgmt-report'. INERT while the setting is off (one setting read). On: once per month, for the LAST FULL month, it
      builds the full report (all four sections), stores it (pim.TenantCache 'mgmt-report': latest file + figure history, so
      the Manager offers the latest for download and the next report has its trends), and mails it to the configured
      recipients as an attachment. A store that cannot be written FAILS the run (failed=$true); a mail that cannot be sent is
      reported (failed=$true) so the run is red and the next run does NOT build again (the file is stored) -- it says so.
      Seams: -GetSetting, -ReadStore, -WriteStore, -SendMail, -Query, -Readers.
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf,
          [scriptblock]$GetSetting = $null, [scriptblock]$ReadStore = $null, [scriptblock]$WriteStore = $null, [scriptblock]$SendMail = $null,
          [scriptblock]$Query = $null, [string]$ConnectionString = '', [hashtable]$Readers = $null, [string]$Environment = $null, [AllowNull()][byte[]]$LogoPng = $null, [switch]$NoLogo)
    if (-not $GetSetting) { $GetSetting = { if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { Get-PimSetting -Name 'ManagementReport' } else { $null } } }
    if (-not $ReadStore) { $ReadStore = { if (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue) { Get-PimTenantCacheEntry -Kind 'mgmt-report' } else { $null } } }
    if (-not $WriteStore) { $WriteStore = { param($doc) if (-not (Get-Command Set-PimTenantCacheEntry -ErrorAction SilentlyContinue)) { throw 'the snapshot store is not loaded in this process' }; [void](Set-PimTenantCacheEntry -Kind 'mgmt-report' -Value $doc) } }
    if (-not $SendMail) { $SendMail = { param($to, $tokens, $att) if (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) { return @{ sent = $false; reason = 'the mail path is not loaded in this process' } }; Send-PimNotifyMail -Type 'management-report' -Recipient $to -Tokens $tokens -Attachments $att } }
    $cfg = ConvertTo-PimMgmtReportConfig -Value (& $GetSetting)
    if (-not $cfg.monthlyEnabled) {
        return [pscustomobject]@{ ran = $false; off = $true; failed = $false; whatIf = [bool]$WhatIf; detail = 'switched off -- the monthly management report is turned on in PIM Manager, Reports > Management report' }
    }
    $period = Get-PimMgmtReportPeriod -Period 'month' -NowUtc $NowUtc
    $store = $null; try { $store = & $ReadStore } catch { $store = $null }
    $latest = Get-PimMgmtReportField $store 'latest'
    if ($latest -and "$(Get-PimMgmtReportField $latest 'periodKey')" -eq $period.key) {
        return [pscustomobject]@{ ran = $false; failed = $false; whatIf = [bool]$WhatIf; nothingDue = $true
            detail = ('already built for {0} (generated {1} UTC) -- the next report is for the month after' -f $period.label, (Format-PimMgmtReportDate (Get-PimMgmtReportField $latest 'generatedUtc') -Time)) }
    }
    $history = @(Get-PimMgmtReportField $store 'history' | Where-Object { $null -ne $_ })
    $envName = if ($null -ne $Environment) { $Environment } else { Resolve-PimMgmtReportEnvironment }
    $srcArgs = @{ Period = $period; ConnectionString = $ConnectionString }
    if ($Query) { $srcArgs['Query'] = $Query }
    if ($null -ne $Readers) { $srcArgs['Readers'] = $Readers }
    $sources = Read-PimMgmtReportSources @srcArgs
    $model = New-PimMgmtReportModel -Sources $sources -Period $period -Sections @('kpi', 'risk', 'changes', 'compliance') -Environment $envName -History $history -NowUtc $NowUtc -Title 'Monthly management report'
    $logo = if ($NoLogo) { $null } elseif ($null -ne $LogoPng) { $LogoPng } else { Get-PimMgmtReportLogoPng }
    $bytes = ConvertTo-PimMgmtReportPptx -Model $model -LogoPng $logo
    $file = Get-PimMgmtReportFileName -Model $model
    $naTxt = if (@($model.notAvailable).Count) { "; not available: $(@($model.notAvailable) -join ', ')" } else { '' }
    if ($WhatIf) {
        return [pscustomobject]@{ ran = $false; failed = $false; whatIf = $true; detail = ('whatif: would build {0} ({1} bytes) for {2} and mail it to {3} recipient(s){4}' -f $file, $bytes.Length, $period.label, @($cfg.recipients).Count, $naTxt) }
    }
    $hist = New-Object System.Collections.Generic.List[object]
    foreach ($h in $history) { if ("$(Get-PimMgmtReportField $h 'periodKey')" -ne $period.key) { $hist.Add($h) } }
    $hist.Add([ordered]@{ periodKey = $period.key; asOfUtc = $NowUtc.ToUniversalTime().ToString('o'); figures = $model.figures })
    # sorted by the TIME (a stored stamp may come back from JSON as a [datetime] on pwsh 7, never sort its culture text)
    $keep = @($hist.ToArray() | Sort-Object { $t = ConvertTo-PimMgmtReportUtc (Get-PimMgmtReportField $_ 'asOfUtc'); if ($t) { $t.Ticks } else { 0L } } | Select-Object -Last $script:PimMgmtReportHistoryMax)
    $doc = [ordered]@{
        latest  = [ordered]@{ periodKey = $period.key; periodLabel = $period.label; generatedUtc = $NowUtc.ToUniversalTime().ToString('o'); fileName = $file; size = $bytes.Length; contentB64 = [Convert]::ToBase64String($bytes) }
        history = $keep
    }
    try { & $WriteStore $doc }
    catch { return [pscustomobject]@{ ran = $false; failed = $true; whatIf = $false; detail = "the report for $($period.label) was built but could NOT be stored: $($_.Exception.Message)" } }
    $rc = @($cfg.recipients)
    if (-not $rc.Count) {
        return [pscustomobject]@{ ran = $true; failed = $false; sent = 0; recipients = 0; whatIf = $false; detail = ('built and stored {0} for {1}; NOT mailed -- no recipients are set (Reports > Management report){2}' -f $file, $period.label, $naTxt) }
    }
    $big = ($bytes.Length -gt $script:PimMgmtReportMailMaxBytes)
    $tokens = New-PimMgmtReportMailTokens -Model $model -FileName $file -NotAttached:$big
    $att = if ($big) { @() } else { @(@{ name = $file; contentType = $script:PimMgmtReportContentType; bytes = $bytes }) }
    $sent = 0; $refused = New-Object System.Collections.Generic.List[string]
    foreach ($r in $rc) {
        $res = $null
        try { $res = & $SendMail $r $tokens $att } catch { $res = @{ sent = $false; reason = "$($_.Exception.Message)" } }
        if ("$(Get-PimMgmtReportField $res 'sent')" -match '^(?i)true$') { $sent++ } else { $refused.Add(('{0}: {1}' -f $r, "$(Get-PimMgmtReportField $res 'reason')")) }
    }
    $refTxt = if ($refused.Count) { ' -- not sent to ' + ($refused.ToArray() -join '; ') } else { '' }
    return [pscustomobject]@{ ran = $true; failed = ($sent -eq 0); sent = $sent; recipients = $rc.Count; whatIf = $false
        detail = ('built and stored {0} for {1}; mailed to {2} of {3} recipient(s){4}{5}{6}' -f $file, $period.label, $sent, $rc.Count, $(if ($big) { ' (link only: too large to attach)' } else { '' }), $refTxt, $naTxt) }
}

function Get-PimMgmtReportLatestView {
    <# PURE. The stored doc -> what the Manager shows about the latest monthly report (no content). $null when none. #>
    param([AllowNull()][object]$Store)
    $l = Get-PimMgmtReportField $Store 'latest'
    if ($null -eq $l -or -not "$(Get-PimMgmtReportField $l 'contentB64')".Trim()) { return $null }
    $g = ConvertTo-PimMgmtReportUtc (Get-PimMgmtReportField $l 'generatedUtc')
    return [ordered]@{ periodKey = "$(Get-PimMgmtReportField $l 'periodKey')"; periodLabel = "$(Get-PimMgmtReportField $l 'periodLabel')"; generatedUtc = $(if ($g) { $g.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
        fileName = "$(Get-PimMgmtReportField $l 'fileName')"; size = [long]"$(Get-PimMgmtReportField $l 'size')" }
}
