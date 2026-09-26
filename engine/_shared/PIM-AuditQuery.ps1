# PIM-AuditQuery.ps1 -- pure audit-trail query + before/after diff + CSV export
# (LIFECYCLE / GOVERNANCE -- "Audit you can defend", REQUIREMENTS.md s28 [H6]).
#
# The Manager Audit tab reads the trail from SQL pim.AuditEvents (Get-PimSqlAuditEvents).
# This shared, dependency-free, PS-5.1-safe library is the ONE decision core that the
# /api/audit + /api/audit/export endpoints share, so the screen, the export and any test
# resolve the trail identically:
#
#   Get-PimAuditChangeSummary -- render a human "field: old -> new" before/after.
#   Select-PimAuditEvents   -- filter (category/search/from/to) + sort newest-first.
#   ConvertTo-PimAuditCsv   -- RFC-4180 CSV (with a formula-injection guard) over
#                              the FULL filtered set, INCLUDING the change column --
#                              so an auditor export is the whole trail, not a page.
#
# Pure: no module deps, no SQL, no network, no global state, no files. PIM v2 is SQL-only:
# the old monthly-file reader (Get-PimAuditMonthList / Read-PimAuditEvents over
# output/audit/pim-audit-<yyyyMM>.jsonl) was removed 2026-09-13; a pre-v2 file trail is
# imported once with tools/pim-manager/Import-PimAuditFileTrail.ps1. Category bucketing
# matches the Manager's Get-PimAuditCategory (kept in sync; this provides a fallback when
# the function isn't loaded so the lib is standalone-testable).

function Get-PimAuditCategoryFallback {
    # Standalone mirror of Open-PimManager.ps1 Get-PimAuditCategory so this lib can
    # be dot-sourced and tested without the Manager. The Manager's own function (if
    # loaded) wins -- see Resolve-PimAuditCategory.
    param([string]$Action, [string]$Target = '')
    $a = "$Action".Trim().ToLowerInvariant()
    if (-not $a) { return 'other' }
    if ($a -in @('config.save', 'config.csv.save')) {
        $t = "$Target".Trim()
        if ($t -match '^(?i)PIM-Assignments-') { return 'delegations' }
        if ($t -match '^(?i)Account-Definitions-') { return 'accounts' }
    }
    switch -Regex ($a) {
        '^(manager\.login|login)'           { return 'logins' }
        '^emergency\.'                      { return 'emergency' }
        '^approval\.'                       { return 'approvals' }
        '^(account\.|tap\.)'                { return 'accounts' }
        '^engine\.(groupmembers|adminmembers|entraroles|rolesaus|entrarolesdirect|azres|groupowners|administrativeunitmembers|workloadconnectors|defenderxdrroles|intuneroles|entraapprole)\.' { return 'delegations' }
        '^queue\.action\.(entra-role-revoke|group-assignment-revoke|azure-rbac-revoke)\.' { return 'delegations' }
        '^queue\.action\.' { return 'accounts' }
        '^engine\.(admins|admintap|adminoffboarding)\.' { return 'accounts' }
        '^(membership\.|group\.|local\.apply|msp\.fanout|cutover\.|revoke\.)' { return 'delegations' }
        '^(engine\.|policy\.|resource\.|config\.|settings\.|mail\.send|license\.|schedule\.|azres\.policy\.)' { return 'engine' }
        default                             { return 'other' }
    }
}

function Resolve-PimAuditCategory {
    param([string]$Action, [string]$Target = '')
    if (Get-Command Get-PimAuditCategory -ErrorAction SilentlyContinue) {
        return (Get-PimAuditCategory -Action $Action -Target $Target)
    }
    return (Get-PimAuditCategoryFallback -Action $Action -Target $Target)
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

function Get-PimAuditRowValue {
    param([object]$Row, [string]$Name)
    if ($null -eq $Row) { return '' }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { return "$($Row[$Name])".Trim() }; return '' }
    $p = $Row.PSObject.Properties[$Name]
    if ($p) { return "$($p.Value)".Trim() }
    return ''
}

function Format-PimAuditCommitRow {
    <#
      §70.14 (operator 2026-09-13): "log is useless, as I cannot see the change made, like delegation made,
      who did delegate what to whom" / "cannot be used to detail to a ciso what happened in their env".
      One configuration row -> one sentence a reviewer can read: WHO gets WHAT, WHERE, and how.
      PURE. The entity decides the wording; an unknown entity falls back to its identifying columns.
    #>
    param([Parameter(Mandatory)][string]$Base, [object]$Row,
          # §70.22 (operator 2026-09-14: "references to groups are wrong, as it doesnt show prefix ... this group does not
          # exist"): assignment rows name groups by TAG (Entra-ID-Users-CreateModifyDelete-L1); the group is called
          # PIM-Entra-ID-Users-CreateModifyDelete-L1. tag (lower-case) -> GroupName from the definitions; a tag no
          # definition carries says so instead of reading like a real group name.
          [hashtable]$GroupNameByTag)
    $g = { param($n) Get-PimAuditRowValue -Row $Row -Name $n }
    $grp = {
        param($tag)
        $t = "$tag".Trim()
        if (-not $t -or $null -eq $GroupNameByTag) { return "'$t'" }
        $nm = $GroupNameByTag[$t.ToLowerInvariant()]
        if ("$nm".Trim()) { return "'$nm'" }
        return "tag '$t' (no group definition carries this tag)"
    }
    $how = @()
    $t = & $g 'AssignmentType'; if ($t) { $how += $t }
    if ((& $g 'Permanent') -match '^(?i)true$') { $how += 'permanent' }
    else { $d = & $g 'NumOfDaysWhenExpire'; if ($d) { $how += "$d days" } }
    if ((& $g 'Action') -match '^(?i)remove$') { $how += 'Action=Remove' }
    $howText = if ($how.Count) { ' (' + ($how -join ', ') + ')' } else { '' }
    switch -Regex ($Base) {
        '^PIM-Assignments-Admins$'          { return "admin '$(& $g 'Username')' -> member of group $(& $grp (& $g 'GroupTag'))$howText" }
        # DIRECTION (engine, PIM-EngineProviders Groups provider): the TARGET group is nested INTO the SOURCE group.
        '^PIM-Assignments-Groups$'          { return "group $(& $grp (& $g 'TargetGroupTag')) -> member of group $(& $grp (& $g 'SourceGroupTag'))$howText" }
        '^PIM-Assignments-Roles-Groups$'    { return "group $(& $grp (& $g 'GroupTag')) -> Entra role '$(& $g 'RoleDefinitionName')' (tenant-wide)$howText" }
        '^PIM-Assignments-Roles-AUs$'       { return "group $(& $grp (& $g 'GroupTag')) -> Entra role '$(& $g 'RoleDefinitionName')' in administrative unit '$(& $g 'AdministrativeUnitTag')'$howText" }
        '^PIM-Assignments-Azure-Resources$' { return "group $(& $grp (& $g 'GroupTag')) -> Azure role '$(& $g 'AzScopePermission')' at '$(& $g 'AzScope')'$howText" }
        '^PIM-Assignments-Workloads$'       { return "group $(& $grp (& $g 'GroupTag')) -> $(& $g 'Workload') role '$(& $g 'RoleName')' at '$(& $g 'Scope')'$howText" }
        '^PIM-Definitions-AU$'              { return "administrative unit '$(& $g 'AUDisplayName')' (tag '$(& $g 'AdministrativeUnitTag')')" }
        '^PIM-Definitions-'                 {
            $name = & $g 'GroupName'; $tag = & $g 'GroupTag'; $dept = & $g 'Department'
            $kind = ($Base -replace '^PIM-Definitions-', '').ToLowerInvariant()
            $label = if ($name -and $tag -and $name -ne $tag) { "'$name' (tag '$tag')" } elseif ($name) { "'$name'" } elseif ($tag) { "'$tag'" } else { "'$dept'" }
            return "$kind group $label"
        }
        '^Account-Definitions-Admins$'      {
            $u = & $g 'Username'; if (-not $u) { $u = & $g 'UserPrincipalName' }
            return "admin account '$u'"
        }
    }
    # Fallback: the first identifying, non-empty values -- never a dump of every column.
    $vals = New-Object System.Collections.Generic.List[string]
    $names = if ($Row -is [System.Collections.IDictionary]) { @($Row.Keys) } elseif ($null -ne $Row) { @($Row.PSObject.Properties.Name) } else { @() }
    foreach ($n in $names) { $v = & $g "$n"; if ($v) { $vals.Add("$n=$v") }; if ($vals.Count -ge 4) { break } }
    return ($vals -join ', ')
}

function Get-PimAuditCommitChangeLines {
    <#
      §70.14 -- the keyed diff of one commit (Compare-PimRowSets: adds / removes / modifies[{before,after,diffCols}])
      -> ordered sentences: "Added: ...", "Removed: ...", "Changed: ... -- Col: old -> new". Capped at -Max so an
      import of thousands of rows cannot bloat one audit row; the caller records how many were left out. PURE.
    #>
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][object]$Diff, [int]$Max = 200, [hashtable]$GroupNameByTag)
    $lines = New-Object System.Collections.Generic.List[string]
    $total = 0
    $field = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($null -ne $o) { $o.PSObject.Properties[$n].Value } }
    foreach ($r in @(& $field $Diff 'adds'))    { if ($null -eq $r) { continue }; $total++; if ($lines.Count -lt $Max) { $lines.Add('Added: ' + (Format-PimAuditCommitRow -Base $Base -Row $r -GroupNameByTag $GroupNameByTag)) } }
    foreach ($r in @(& $field $Diff 'removes')) { if ($null -eq $r) { continue }; $total++; if ($lines.Count -lt $Max) { $lines.Add('Removed: ' + (Format-PimAuditCommitRow -Base $Base -Row $r -GroupNameByTag $GroupNameByTag)) } }
    foreach ($m in @(& $field $Diff 'modifies')) {
        if ($null -eq $m) { continue }
        $total++
        if ($lines.Count -ge $Max) { continue }
        $b = & $field $m 'before'; $a = & $field $m 'after'
        $cols = @(& $field $m 'diffCols')
        $parts = foreach ($c in $cols) {
            if (-not "$c".Trim()) { continue }
            $ov = Get-PimAuditRowValue -Row $b -Name "$c"; $nv = Get-PimAuditRowValue -Row $a -Name "$c"
            "$c`: $(if ($ov) { $ov } else { '(empty)' }) -> $(if ($nv) { $nv } else { '(empty)' })"
        }
        $lines.Add('Changed: ' + (Format-PimAuditCommitRow -Base $Base -Row $a -GroupNameByTag $GroupNameByTag) + $(if (@($parts).Count) { ' -- ' + (@($parts) -join '; ') } else { '' }))
    }
    return [pscustomobject]@{ lines = @($lines.ToArray()); total = $total; omitted = [Math]::Max(0, $total - $lines.Count) }
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
    param([object]$Before, [object]$After, [string]$Action = '')

    # §70.14 -- a configuration commit carries readable per-row sentences (`changes`). Show THOSE, one per
    # line, under the one-line summary -- never "adds: (none) -> 1; rowCount: (none) -> 28; instance: ...".
    $afterObj = $After
    if ($afterObj -is [string] -and "$afterObj".TrimStart().StartsWith('{')) { try { $afterObj = $afterObj | ConvertFrom-Json } catch { } }
    $chg = $null; $sum = ''; $omit = 0
    if ($afterObj -is [System.Collections.IDictionary]) {
        if ($afterObj.Contains('changes')) { $chg = $afterObj['changes'] }
        if ($afterObj.Contains('summary')) { $sum = "$($afterObj['summary'])" }
        if ($afterObj.Contains('changesOmitted')) { $omit = [int]"$($afterObj['changesOmitted'])" }
    } elseif ($null -ne $afterObj -and -not ($afterObj -is [string]) -and $afterObj.PSObject.Properties['changes']) {
        $chg = $afterObj.changes
        if ($afterObj.PSObject.Properties['summary']) { $sum = "$($afterObj.summary)" }
        if ($afterObj.PSObject.Properties['changesOmitted']) { $omit = [int]"$($afterObj.changesOmitted)" }
    }
    if ($null -ne $chg) {
        $out = New-Object System.Collections.Generic.List[string]
        if ($sum) { $out.Add($sum) }
        foreach ($l in @($chg)) { if ("$l".Trim()) { $out.Add("$l") } }
        if ($omit -gt 0) { $out.Add("... and $omit more change(s) not listed") }
        return ($out -join "`n")
    }
    # A commit recorded before 2.4.348 has counts only -- say so plainly instead of a field dump.
    if ($null -ne $afterObj -and -not ($afterObj -is [string])) {
        $gv = { param($n) if ($afterObj -is [System.Collections.IDictionary]) { if ($afterObj.Contains($n)) { "$($afterObj[$n])" } else { '' } } else { $p = $afterObj.PSObject.Properties[$n]; if ($p) { "$($p.Value)" } else { '' } } }
        $ad = & $gv 'adds'; $rm = & $gv 'removes'; $md = & $gv 'modifies'
        if ("$ad$rm$md" -ne '' -and $null -eq $Before -and "$(& $gv 'rowCount')" -ne '') {
            return ("{0} added, {1} removed, {2} changed ({3} rows now) -- row details were not recorded for commits before v2.4.348" -f $(if ($ad) { $ad } else { 0 }), $(if ($rm) { $rm } else { 0 }), $(if ($md) { $md } else { 0 }), (& $gv 'rowCount'))
        }
    }

    $b = ConvertTo-PimAuditFlatMap -Value $Before
    $a = ConvertTo-PimAuditFlatMap -Value $After
    if ($b.Count -eq 0 -and $a.Count -eq 0) { return '' }

    # Union of keys, stable order: before-keys first (in their order), then any
    # after-only keys.
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($k in $b.Keys) { if (-not $keys.Contains($k)) { $keys.Add($k) } }
    foreach ($k in $a.Keys) { if (-not $keys.Contains($k)) { $keys.Add($k) } }

    # 🔴 AN EVENT THAT RECORDS A STATE IS NOT A CHANGE (operator, 2026-09-22: "these messages are
    # useless - it says none evrywhere"). A login has nothing before it, so every field rendered as
    # "role: (none) -> SuperAdmin; mode: (none) -> hosted; source: (none) -> sql ManagerAccess" -- a
    # column of arrows pointing out of nothing, on 65 rows, saying only what the row already is.
    # With NO before at all, the after fields are stated as FACTS. A login gets the sentence it
    # deserves; anything else state-only reads "role SuperAdmin; mode hosted".
    if ($b.Count -eq 0 -and $a.Count -gt 0) {
        $val = { param($n) if ($a.Contains($n)) { "$($a[$n])".Trim() } else { '' } }
        if ("$Action".Trim().ToLowerInvariant() -eq 'manager.login') {
            $role = & $val 'role'; $mode = & $val 'mode'; $src = & $val 'source'
            $txt = 'signed in'
            if ($role) { $txt += " as $role" }
            $where = New-Object System.Collections.Generic.List[string]
            if ($mode) { $where.Add("$mode Manager") }
            if ($src)  { $where.Add("role from $src") }
            if ($where.Count) { $txt += ' (' + ($where -join ', ') + ')' }
            return $txt
        }
        $facts = New-Object System.Collections.Generic.List[string]
        foreach ($k in $keys) {
            $nv = "$($a[$k])"
            if ($nv -eq '') { continue }        # an empty field states nothing
            $facts.Add($(if ($k) { "$k`: $nv" } else { $nv }))
        }
        if ($facts.Count) { return ($facts -join '; ') }
    }

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
        Events from Get-PimSqlAuditEvents via the Manager (carry .category + .change).
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
