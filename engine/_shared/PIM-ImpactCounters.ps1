#Requires -Version 5.1
<#
.SYNOPSIS
  PIM REQUIREMENTS 100.68 (a) -- the impact counters on the Dashboard: what PIM Manager has done in this environment,
  cumulative, from data PIM already stores. Honest numbers only: every counter names its source and how it is counted
  (Get-PimImpactCounterCatalog -> the More info text), and a source that cannot be read shows "n/a", never 0.

.DESCRIPTION
  Sources (all in the environment's own SQL store):
    activations     pim.ImpactActivations -- a ledger the active-assignments snapshot job fills: every TIME-BOUND active
                    assignment (one with an end time = an activation or a time-boxed grant) it sees is recorded once.
    eligible        pim.ManagedKeys -- assignments PIM manages now whose key ends '|eligible'.
    standingHours   pim.ManagedKeys + pim.ImpactActivations -- the hours each managed eligible assignment has existed
                    (since PIM first confirmed it) minus the hours it was actually active (the recorded activation windows).
    engineChanges   pim.AuditEvents -- engine.<area>.create|update|remove with result ok (WhatIf excluded).
    approvals       pim.AuditEvents -- approval.request.approved / .denied and <area>.policy.masschange.approved.
    reviews         pim.AuditEvents -- access-review.decision, company-review.answer, owner.keep / remove / extend.
    guardHolds      pim.Settings GuardTrips -- the sum of every guard's tripCount (it only counts up).
    tenants         platform.Tenants (enabled) on a managing tenant; 1 elsewhere.
  The audit-based counters count what the audit trail still holds: with Settings > Audit retention set, older events
  are no longer counted (the More info text says so).

  PURE: the catalog, the queries (Get-PimImpactCounterQueries), the arithmetic (ConvertTo-PimImpactCounters), the
  activation selection (Select-PimImpactActivationRows). SQL: Get-PimImpactCounters / Update-PimImpactActivationLedger take
  an invoker so the suites run them over a fixture store.
#>

$script:PimImpactCounterCatalog = @(
    [pscustomobject]@{ key = 'activations'; title = 'Activations handled'; unit = ''
        info = 'Time-bound active assignments (an activation, or a grant with an end time) seen by the active-assignments snapshot job (every 2 hours by default), each counted once, since the first snapshot that recorded one. An activation that starts and ends between two snapshots is not seen, so the real number is at least this.' }
    [pscustomobject]@{ key = 'eligible'; title = 'Eligible instead of standing'; unit = ''
        info = 'Assignments PIM manages right now as ELIGIBLE (activated when needed) rather than permanently active -- from the keys the engine confirmed in the tenant. Counted now, not cumulatively: an assignment PIM removed is no longer counted.' }
    [pscustomobject]@{ key = 'standingHours'; title = 'Standing-access hours removed'; unit = 'h'
        info = 'For every eligible assignment PIM manages: the hours since PIM first confirmed it, minus the hours it was actually active (the activation windows recorded above, start to end or now). That is the time the access would have been standing if it were a permanent assignment. Activations the snapshot did not see are not subtracted, so this is an upper estimate of the real figure for those hours.' }
    [pscustomobject]@{ key = 'engineChanges'; title = 'Changes applied by the engine'; unit = ''
        info = 'Every create, update and remove the engine carried out in the tenant with result OK, from the audit trail (dry runs excluded). Counts what the audit trail holds: with Settings > Audit retention set, older changes are no longer counted.' }
    [pscustomobject]@{ key = 'approvals'; title = 'Approvals'; unit = ''
        info = 'Approval decisions recorded in the audit trail: requests approved or denied by a second person, and approved mass-change holds. Counts what the audit trail holds.' }
    [pscustomobject]@{ key = 'reviews'; title = 'Reviews completed'; unit = ''
        info = 'Access-review decisions recorded in the audit trail: access-review decisions, external-company review answers and department-owner keep / remove / extend decisions. Counts what the audit trail holds.' }
    [pscustomobject]@{ key = 'guardHolds'; title = 'Guard holds caught'; unit = ''
        info = 'How many times a protective guard held a change set (a mass removal, a policy weakening, ...) before it reached the tenant -- the sum of every guard''s trip count, which only counts up.' }
    [pscustomobject]@{ key = 'tenants'; title = 'Tenants managed'; unit = ''
        info = 'On a managing tenant: the enabled managed tenants in the registry. On a single or managed tenant: this tenant (1).' }
)

function Get-PimImpactCounterCatalog { return @($script:PimImpactCounterCatalog) }

function Get-PimImpactActivationLedgerDdl {
    <# PURE. The activation ledger: one row per time-bound active assignment the snapshot job saw (insert-only). #>
@'
IF OBJECT_ID('pim.ImpactActivations') IS NULL
CREATE TABLE pim.ImpactActivations (
    ActivationKey NVARCHAR(400) NOT NULL CONSTRAINT PK_pim_ImpactActivations PRIMARY KEY,
    Kind          NVARCHAR(40)  NULL,
    StartUtc      DATETIME2     NULL,
    EndUtc        DATETIME2     NULL,
    FirstSeenUtc  DATETIME2     NOT NULL CONSTRAINT DF_pim_ImpactActivations_Seen DEFAULT SYSUTCDATETIME()
);
'@
}

function ConvertTo-PimImpactUtc {
    <# PURE. An ISO / [datetime] value -> 'yyyy-MM-ddTHH:mm:ssZ', or '' when it is not a time. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    $d = [datetime]::MinValue
    if ($Value -is [datetime]) { $d = $Value }
    elseif (-not [datetime]::TryParse("$Value", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return '' }
    return $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Select-PimImpactActivationRows {
    <#
      PURE. The snapshot rows that count as activations: an end time AND a start time (time-bound). Key =
      type|principalId|role|scope|start, so the same activation seen by many snapshots is one row; a new activation of the
      same role later is a new row. Returns [{ key; kind; startUtc; endUtc }].
    #>
    param([AllowNull()][object[]]$Rows)
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $g = { param($n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } elseif ($r.PSObject.Properties[$n]) { $r.$n } else { $null } }
        $s = ConvertTo-PimImpactUtc (& $g 'start'); $e = ConvertTo-PimImpactUtc (& $g 'end')
        if (-not $s -or -not $e) { continue }
        $pid0 = "$(& $g 'principalId')".Trim(); if (-not $pid0) { $pid0 = "$(& $g 'principal')".Trim() }
        $k = ("{0}|{1}|{2}|{3}|{4}" -f "$(& $g 'type')".Trim(), $pid0, "$(& $g 'role')".Trim(), "$(& $g 'scope')".Trim(), $s).ToLowerInvariant()
        if ($k.Length -gt 400) { $k = $k.Substring(0, 400) }
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $out.Add([pscustomobject]@{ key = $k; kind = "$(& $g 'type')".Trim(); startUtc = $s; endUtc = $e })
    }
    return @($out.ToArray())
}

function Update-PimImpactActivationLedger {
    <#
      Records the snapshot's activations (insert-only, one statement per 500 rows, OPENJSON). Called by the
      active-assignments snapshot job after it wrote the snapshot. Never throws to the caller's job: returns
      @{ ok; added; error }. -NonQuery is the test seam (default Invoke-PimSqlNonQuery).
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [AllowNull()][object[]]$Rows, [scriptblock]$NonQuery = $null)
    if (-not $NonQuery) { $NonQuery = { param($cs, $sql, $p) Invoke-PimSqlNonQuery -ConnectionString $cs -Sql $sql -Parameters $p } }
    try {
        $acts = @(Select-PimImpactActivationRows -Rows $Rows)
        [void](& $NonQuery $ConnectionString (Get-PimImpactActivationLedgerDdl) @{})
        $added = 0
        for ($i = 0; $i -lt $acts.Count; $i += 500) {
            $chunk = @($acts[$i..([Math]::Min($i + 499, $acts.Count - 1))])
            $json = ConvertTo-Json -InputObject @($chunk | ForEach-Object { [ordered]@{ k = $_.key; t = $_.kind; s = $_.startUtc; e = $_.endUtc } }) -Compress -Depth 3
            $sql = "INSERT INTO pim.ImpactActivations (ActivationKey, Kind, StartUtc, EndUtc) SELECT j.k, j.t, j.s, j.e FROM OPENJSON(@j) WITH (k NVARCHAR(400) '$.k', t NVARCHAR(40) '$.t', s DATETIME2 '$.s', e DATETIME2 '$.e') j WHERE NOT EXISTS (SELECT 1 FROM pim.ImpactActivations a WHERE a.ActivationKey = j.k);"
            $n = & $NonQuery $ConnectionString $sql @{ j = $json }
            if ($n -is [int] -or $n -is [long]) { $added += [int]$n }
        }
        return [pscustomobject]@{ ok = $true; added = $added; seen = $acts.Count; error = '' }
    } catch {
        return [pscustomobject]@{ ok = $false; added = 0; seen = 0; error = "$($_.Exception.Message)" }
    }
}

function Get-PimImpactCounterQueries {
    <#
      PURE. The named read queries (one scalar each, column n). The demo dataset (the Manager's demo-data module) answers the SAME names
      from its own tables, so the arithmetic below is one code path.
    #>
    param([switch]$MspMaster)
    $q = [ordered]@{
        activations        = 'SELECT COUNT_BIG(*) AS n FROM pim.ImpactActivations'
        activationsSince   = 'SELECT MIN(FirstSeenUtc) AS n FROM pim.ImpactActivations'
        eligible           = "SELECT COUNT_BIG(*) AS n FROM pim.ManagedKeys WHERE [Key] LIKE '%|eligible'"
        eligibleMinutes    = "SELECT SUM(CAST(DATEDIFF(minute, FirstSeenUtc, SYSUTCDATETIME()) AS BIGINT)) AS n FROM pim.ManagedKeys WHERE [Key] LIKE '%|eligible'"
        activeMinutes      = 'SELECT SUM(CAST(DATEDIFF(minute, StartUtc, CASE WHEN EndUtc < SYSUTCDATETIME() THEN EndUtc ELSE SYSUTCDATETIME() END) AS BIGINT)) AS n FROM pim.ImpactActivations WHERE StartUtc IS NOT NULL AND EndUtc IS NOT NULL AND StartUtc < SYSUTCDATETIME()'
        engineChanges      = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE ActorSource = 'engine' AND Result = 'ok' AND ISNULL(WhatIf, 0) = 0 AND (Action LIKE 'engine.%.create' OR Action LIKE 'engine.%.update' OR Action LIKE 'engine.%.remove') AND Action NOT LIKE 'engine.remove.budget%'"
        approvals          = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE Action IN ('approval.request.approved', 'approval.request.denied') OR Action LIKE '%.policy.masschange.approved'"
        reviews            = "SELECT COUNT_BIG(*) AS n FROM pim.AuditEvents WHERE Action IN ('access-review.decision', 'company-review.answer', 'owner.keep', 'owner.remove', 'owner.extend')"
        guardHolds         = "SELECT ValueJson AS n FROM pim.Settings WHERE Name = 'GuardTrips'"
        since              = 'SELECT MIN(Ts) AS n FROM pim.AuditEvents'
    }
    if ($MspMaster) { $q['tenants'] = 'SELECT COUNT_BIG(*) AS n FROM platform.Tenants WHERE Enabled = 1' }
    return $q
}

function Get-PimImpactGuardTripTotal {
    <# PURE. The sum of tripCount over the GuardTrips document (JSON text or object). $null when it cannot be read. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or "$Value" -eq '') { return 0 }
    $o = $Value
    if ($Value -is [string]) { try { $o = $Value | ConvertFrom-Json } catch { return $null } }
    $sum = 0L
    $items = if ($o -is [System.Collections.IDictionary]) { @($o.Values) } else { @($o.PSObject.Properties | ForEach-Object { $_.Value }) }
    foreach ($g in $items) {
        if ($null -eq $g) { continue }
        $tc = if ($g -is [System.Collections.IDictionary]) { $g['tripCount'] } elseif ($g.PSObject.Properties['tripCount']) { $g.tripCount } else { 0 }
        $n = 0L; if ([long]::TryParse("$tc", [ref]$n) -and $n -gt 0) { $sum += $n }
    }
    return $sum
}

function ConvertTo-PimImpactCounters {
    <#
      PURE. The query results -> the counters. -Results: name -> @{ ok; value; error } (one per query name). A counter whose
      source failed is { ok = $false; value = $null; text = 'n/a' } with the error -- never 0. tone: green when readable and
      above 0, neutral at 0, na when unreadable. -MspMaster decides tenants (registry) vs 1.
    #>
    param([Parameter(Mandatory)][hashtable]$Results, [switch]$MspMaster, [switch]$DemoData, [datetime]$NowUtc = [datetime]::UtcNow)
    $num = { param($name) $r = $Results[$name]; if ($null -eq $r -or -not $r.ok) { return $null }; $v = $r.value; if ($null -eq $v -or $v -is [System.DBNull]) { return 0L }; $n = 0.0; if ([double]::TryParse("$v", [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { return [long][math]::Round($n) }; return $null }
    $err = { param([string[]]$names) (@($names | ForEach-Object { $r = $Results[$_]; if ($null -eq $r) { "$_ not read" } elseif (-not $r.ok) { "$($r.error)" } } | Where-Object { $_ }) -join '; ') }
    $vals = [ordered]@{}
    $vals['activations'] = & $num 'activations'
    $vals['eligible'] = & $num 'eligible'
    $em = & $num 'eligibleMinutes'; $am = & $num 'activeMinutes'
    $vals['standingHours'] = $(if ($null -eq $em) { $null } else { [long][math]::Max(0, [math]::Floor(($em - $(if ($null -eq $am) { 0 } else { $am })) / 60)) })
    $vals['engineChanges'] = & $num 'engineChanges'
    $vals['approvals'] = & $num 'approvals'
    $vals['reviews'] = & $num 'reviews'
    $gr = $Results['guardHolds']
    $vals['guardHolds'] = $(if ($null -eq $gr -or -not $gr.ok) { $null } else { Get-PimImpactGuardTripTotal -Value $gr.value })
    $vals['tenants'] = $(if ($MspMaster) { & $num 'tenants' } else { 1L })
    $srcNames = @{ activations = @('activations'); eligible = @('eligible'); standingHours = @('eligibleMinutes', 'activeMinutes'); engineChanges = @('engineChanges')
                   approvals = @('approvals'); reviews = @('reviews'); guardHolds = @('guardHolds'); tenants = $(if ($MspMaster) { @('tenants') } else { @() }) }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($c in (Get-PimImpactCounterCatalog)) {
        $v = $vals[$c.key]
        $ok = ($null -ne $v)
        # standing hours: readable when the eligible side is; an unreadable activation side is said in the note
        $note = ''
        if ($c.key -eq 'standingHours' -and $ok -and $null -eq $am) { $note = 'activation windows could not be read, so none were subtracted' }
        $list.Add([pscustomobject][ordered]@{
            key = $c.key; title = $c.title; unit = $c.unit; info = $c.info
            ok = $ok; value = $v; text = $(if ($ok) { "$v" } else { 'n/a' })
            tone = $(if (-not $ok) { 'na' } elseif ($v -gt 0) { 'green' } else { 'neutral' })
            error = $(if ($ok) { '' } else { & $err $srcNames[$c.key] }); note = $note
        })
    }
    $since = ''
    foreach ($n in @('since', 'activationsSince')) { $r = $Results[$n]; if ($r -and $r.ok -and $null -ne $r.value -and -not ($r.value -is [System.DBNull])) { $t = ConvertTo-PimImpactUtc $r.value; if ($t -and (-not $since -or $t -lt $since)) { $since = $t } } }
    return [pscustomobject][ordered]@{ generatedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); sinceUtc = $since; demoData = [bool]$DemoData; counters = @($list.ToArray()) }
}

function Get-PimImpactCounters {
    <#
      Runs the queries (each on its own -- one unreadable source never hides the others) and returns the counters.
      -Query is the test seam: param($name, $sql) -> the scalar (throws = unreadable). Default: Invoke-PimSqlScalar.
      -Queries lets the demo dataset supply its own (same names).
    #>
    param([string]$ConnectionString = '', [switch]$MspMaster, [scriptblock]$Query = $null, [System.Collections.IDictionary]$Queries = $null, [switch]$DemoData)
    if (-not $Queries) { $Queries = Get-PimImpactCounterQueries -MspMaster:$MspMaster }
    if (-not $Query) {
        if (-not "$ConnectionString".Trim()) { throw 'Get-PimImpactCounters: no SQL store (connection string) -- the counters cannot be read' }
        $Query = { param($name, $sql, $cs) Invoke-PimSqlScalar -ConnectionString $cs -Sql $sql }
    }
    $res = @{}
    foreach ($k in @($Queries.Keys)) {
        try { $res[$k] = @{ ok = $true; value = (& $Query $k "$($Queries[$k])" $ConnectionString) } }
        catch { $res[$k] = @{ ok = $false; value = $null; error = ("$($_.Exception.Message)" -replace '\s+', ' ').Trim() } }
    }
    return (ConvertTo-PimImpactCounters -Results $res -MspMaster:$MspMaster -DemoData:$DemoData)
}
