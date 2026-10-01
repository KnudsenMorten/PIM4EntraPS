#Requires -Version 5.1
<#
  PIM-AutoExtend.ps1 -- §83 auto-extend governance (operator 2026-10-01: "critical bug as people would loose their
  permissions"; decisions: "14 days, keep wins, owners approve, silence means extend").

  WHO DECIDES whether an expiring assignment is extended (Resolve-PimAutoExtendDecision), first match wins:
    1. ACCESS REVIEW -- the person's department has an ENABLED review rule and the person's latest review outcome is known
       (PIM-Assignments-Admins rows only: the review is per person over their group memberships):
         Keep                          -> EXTENDED, even when the row says AutoExtend=FALSE ("keep wins").
         Remove (whole account, or this membership) -> NOT extended (the review's removal path takes the access away).
       No outcome yet (no campaign, or still undecided) -> falls through.
    2. OWNER DENY -- a department owner (or an administrator) denied THIS expiry in the upcoming-extension report
       (pim.Settings 'AutoExtendDecisions'; one decision per row AND end date, so the next expiry is asked again).
       An Approve, or no answer at all, does not stop it: silence means extend.
    3. THE ROW -- AutoExtend TRUE/FALSE as written.
    4. THE DEFAULT -- a BLANK cell follows pim.Settings 'AutoExtendPolicy'.defaultOn, which is ON unless switched off.
       Until 2.4.472 a blank cell meant "never extend", so a row created outside the wizards silently lost its access.
  WHEN: when the live assignment ends within 'AutoExtendPolicy'.leadDays (default 14) days. Was a hard-coded 30.

  The engine also records what is coming (Add-PimAutoExtendOutlookItem) so the monthly 'autoextend-report' job can mail
  each department's owners the extensions of the coming month, and the Manager can show them with Approve / Deny.

  Free (both editions). Never loads a Pro file: the review state is read from pim.Settings directly, and the access
  review's own state function is used only when it is loaded.
#>
Set-StrictMode -Off

$script:PimAutoExtendLeadDaysDefault = 14
$script:PimAutoExtendOutlookDays     = 31      # the report looks this far beyond the lead time
$script:PimAutoExtendContextTtlSec   = 120
$script:PimAutoExtendContextCache    = $null
$script:PimAutoExtendOutlook         = @{}     # key -> item, collected by the engine during a run

function Get-PimAutoExtendField {
    param($O, [string]$N)
    if ($null -eq $O) { return $null }
    if ($O -is [System.Collections.IDictionary]) { foreach ($k in @($O.Keys)) { if ("$k" -ieq $N) { return $O[$k] } }; return $null }
    $p = $O.PSObject.Properties[$N]; if ($p) { return $p.Value }; return $null
}

function ConvertTo-PimAutoExtendObject {
    # A stored setting (JSON text, possibly double-encoded, or already parsed) -> object, or $null.
    param([AllowNull()][object]$Value)
    $v = $Value
    for ($i = 0; $i -lt 2 -and $v -is [string]; $i++) {
        if (-not "$v".Trim()) { return $null }
        try { $v = $v | ConvertFrom-Json } catch { return $null }
    }
    return $v
}

function ConvertTo-PimAutoExtendPolicy {
    <# PURE. pim.Settings 'AutoExtendPolicy' -> @{ leadDays (1..90, default 14); defaultOn (default $true) }. #>
    param([AllowNull()][object]$Value)
    $v = ConvertTo-PimAutoExtendObject $Value
    $lead = $script:PimAutoExtendLeadDaysDefault
    $ld = Get-PimAutoExtendField $v 'leadDays'
    if ($null -ne $ld -and "$ld" -match '^\s*\d+\s*$' -and [int]"$ld" -ge 1 -and [int]"$ld" -le 90) { $lead = [int]"$ld" }
    $on = $true
    $d = Get-PimAutoExtendField $v 'defaultOn'
    if ($null -ne $d -and "$d".Trim()) { $on = ("$d".Trim() -match '^(?i)(true|1|yes|y|on)$') }
    return [pscustomobject]@{ leadDays = $lead; defaultOn = [bool]$on }
}

function Get-PimAutoExtendRowKind {
    <# PURE. Which assignment sheet a row belongs to, from the columns it carries. #>
    param([object]$Row)
    $has = { param($n) "$(Get-PimAutoExtendField $Row $n)".Trim() -ne '' }
    if (& $has 'AzScope')               { return 'Azure' }
    if (& $has 'TargetGroupTag')        { return 'Groups' }
    if ((& $has 'RoleDefinitionName') -and (& $has 'AdministrativeUnitTag')) { return 'RolesAUs' }
    if ((& $has 'RoleDefinitionName') -and ((& $has 'Username') -or (& $has 'UserPrincipalName'))) { return 'Direct' }
    if (& $has 'RoleDefinitionName')    { return 'Roles' }
    if ((& $has 'Username') -and (& $has 'GroupTag')) { return 'Admins' }
    return 'Other'
}

function Get-PimAutoExtendRowKey {
    <#
      PURE. A stable identity for one assignment row: kind + the columns that name WHO gets WHAT (never AutoExtend, days,
      permanence or comments, so editing those keeps the decision). Lower case.
    #>
    param([object]$Row)
    $kind = Get-PimAutoExtendRowKind -Row $Row
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add($kind.ToLowerInvariant())
    foreach ($n in 'Username', 'UserPrincipalName', 'SourceGroupTag', 'TargetGroupTag', 'GroupTag', 'RoleDefinitionName', 'AdministrativeUnitTag', 'AzScope', 'AzScopePermission', 'AssignmentType') {
        $v = "$(Get-PimAutoExtendField $Row $n)".Trim()
        if ($v) { $parts.Add("$($n.ToLowerInvariant())=$($v.ToLowerInvariant())") }
    }
    return ($parts -join '|')
}

function Get-PimAutoExtendRowLabel {
    <# PURE. @{ principal; target } in words, for the report and the page. #>
    param([object]$Row)
    $g = { param($n) "$(Get-PimAutoExtendField $Row $n)".Trim() }
    $kind = Get-PimAutoExtendRowKind -Row $Row
    $principal = switch ($kind) {
        'Admins' { & $g 'Username' } 'Direct' { $x = & $g 'Username'; if (-not $x) { $x = & $g 'UserPrincipalName' }; $x } 'Groups' { & $g 'SourceGroupTag' } default { & $g 'GroupTag' }
    }
    $target = switch ($kind) {
        'Admins'   { 'member of ' + (& $g 'GroupTag') }
        'Groups'   { 'member of ' + (& $g 'TargetGroupTag') }
        'Roles'    { 'Entra role ' + (& $g 'RoleDefinitionName') }
        'Direct'   { 'Entra role ' + (& $g 'RoleDefinitionName') }
        'RolesAUs' { 'Entra role ' + (& $g 'RoleDefinitionName') + ' in AU ' + (& $g 'AdministrativeUnitTag') }
        'Azure'    { 'Azure ' + (& $g 'AzScopePermission') + ' on ' + (& $g 'AzScope') }
        default    { '' }
    }
    $t = & $g 'AssignmentType'
    return [pscustomobject]@{ kind = $kind; principal = $principal; target = $target; type = $t }
}

function ConvertTo-PimAutoExtendDecisions {
    <#
      PURE. pim.Settings 'AutoExtendDecisions' -> @{ <row key> = @{ decision approve|deny; endDate yyyy-MM-dd; by; utc; reason } }.
    #>
    param([AllowNull()][object]$Value)
    $out = @{}
    $v = ConvertTo-PimAutoExtendObject $Value
    if ($null -eq $v) { return $out }
    $items = Get-PimAutoExtendField $v 'items'
    if ($null -eq $items) { $items = $v }
    $names = if ($items -is [System.Collections.IDictionary]) { @($items.Keys | ForEach-Object { "$_" }) } else { @($items.PSObject.Properties | ForEach-Object { "$($_.Name)" }) }
    foreach ($n in $names) {
        $e = Get-PimAutoExtendField $items $n
        $dec = "$(Get-PimAutoExtendField $e 'decision')".Trim().ToLowerInvariant()
        if ($dec -notin 'approve', 'deny') { continue }
        $out["$n".ToLowerInvariant()] = @{ decision = $dec; endDate = "$(Get-PimAutoExtendField $e 'endDate')".Trim(); by = "$(Get-PimAutoExtendField $e 'by')"; utc = "$(Get-PimAutoExtendField $e 'utc')"; reason = "$(Get-PimAutoExtendField $e 'reason')" }
    }
    return $out
}

function Get-PimAutoExtendReviewIndex {
    <#
      PURE. From the review rules + campaigns + admin rows: who was KEPT / REMOVED by an access review of a department whose
      review is ENABLED. Latest campaign with a decided outcome per person wins (an open campaign counts once the person is
      decided in it). Returns @{ reviewedDepts = @{dept=1}; personDept = @{user=dept}; keep = @{user=1}; removeAll = @{user=1};
      removeTags = @{ 'user|tag' = 1 } } -- users lower case, by UPN AND by local part.
    #>
    param($Rules, $Campaigns, [object[]]$Admins = @())
    $ix = [pscustomobject]@{ reviewedDepts = @{}; personDept = @{}; keep = @{}; removeAll = @{}; removeTags = @{} }
    $addUser = { param($h, $u, $val) $k = "$u".Trim().ToLowerInvariant(); if ($k) { $h[$k] = $val; $h[($k -split '@')[0]] = $val } }
    foreach ($a in @($Admins)) {
        $d = "$(Get-PimAutoExtendField $a 'Department')".Trim(); if (-not $d) { continue }
        foreach ($n in 'UserPrincipalName', 'UserName', 'Username') { $u = "$(Get-PimAutoExtendField $a $n)".Trim(); if ($u) { & $addUser $ix.personDept $u $d.ToLowerInvariant() } }
    }
    $rulesObj = ConvertTo-PimAutoExtendObject $Rules
    $depts = @($ix.personDept.Values | Sort-Object -Unique)
    foreach ($d in $depts) {
        $on = $false
        if ($rulesObj -and (Get-Command Resolve-PimDepartmentReviewRule -ErrorAction SilentlyContinue)) {
            try { $on = [bool](Resolve-PimDepartmentReviewRule -Rules $rulesObj -Department $d) } catch { $on = $false }
        } elseif ($rulesObj) {
            # the review module is not loaded here: the same rule, read directly (default.enabled, a department 'off' or its own enabled)
            $def = Get-PimAutoExtendField $rulesObj 'default'; $on = [bool]("$(Get-PimAutoExtendField $def 'enabled')" -match '^(?i)(true|1)$')
            $dd = Get-PimAutoExtendField $rulesObj 'departments'
            if ($dd) {
                $names = if ($dd -is [System.Collections.IDictionary]) { @($dd.Keys) } else { @($dd.PSObject.Properties.Name) }
                foreach ($n in $names) {
                    if ("$n".Trim().ToLowerInvariant() -ne $d) { continue }
                    $ov = Get-PimAutoExtendField $dd $n
                    if ("$(Get-PimAutoExtendField $ov 'off')" -match '^(?i)(true|1)$') { $on = $false }
                    elseif ($null -ne (Get-PimAutoExtendField $ov 'enabled')) { $on = [bool]("$(Get-PimAutoExtendField $ov 'enabled')" -match '^(?i)(true|1)$') }
                }
            }
        }
        if ($on) { $ix.reviewedDepts[$d] = 1 }
    }
    $campObj = ConvertTo-PimAutoExtendObject $Campaigns
    $list = @(Get-PimAutoExtendField $campObj 'campaigns')
    if (-not $list.Count -and $campObj -is [array]) { $list = @($campObj) }
    $sorted = @($list | Where-Object { $_ } | Sort-Object { "$(Get-PimAutoExtendField $_ 'startedUtc')" } -Descending)
    $seen = @{}
    foreach ($c in $sorted) {
        $cd = "$(Get-PimAutoExtendField $c 'department')".Trim().ToLowerInvariant()
        if (-not $ix.reviewedDepts.ContainsKey($cd)) { continue }
        foreach ($it in @(Get-PimAutoExtendField $c 'items')) {
            $u = "$(Get-PimAutoExtendField $it 'user')".Trim().ToLowerInvariant(); if (-not $u -or $seen.ContainsKey($u)) { continue }
            $state = ''; $rm = @()
            if ((Get-Command Get-PimReviewItemState -ErrorAction SilentlyContinue) -and "$(Get-PimAutoExtendField $c 'status')" -eq 'open') {
                try { $s = Get-PimReviewItemState -Campaign $c -Item $it; $state = "$($s.state)"; $rm = @($s.removeAccess) } catch { $state = '' }
            } else {
                $o = "$(Get-PimAutoExtendField $it 'outcome')".Trim().ToLowerInvariant()
                if ($o -like 'keep*') { $state = 'keep' } elseif ($o -like 'remove*') { $state = 'remove'; $rm = @(Get-PimAutoExtendField $it 'removeAccess') }
            }
            if ($state -notin 'keep', 'remove') { continue }   # undecided in this campaign: an older one may still decide
            $seen[$u] = 1; $seen[($u -split '@')[0]] = 1
            if ($state -eq 'keep') { & $addUser $ix.keep $u 1 }
            else {
                $tags = @(@($rm) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
                if (-not $tags.Count) { & $addUser $ix.removeAll $u 1 }
                else {
                    & $addUser $ix.keep $u 1   # the memberships the review did NOT remove were kept
                    foreach ($t in $tags) { $ix.removeTags["$u|$t"] = 1; $ix.removeTags["$(($u -split '@')[0])|$t"] = 1 }
                }
            }
        }
    }
    return $ix
}

function New-PimAutoExtendContext {
    <# PURE. Everything Resolve-PimAutoExtendDecision needs, from already-read values. #>
    param($Policy, $Decisions, $ReviewRules, $ReviewCampaigns, [object[]]$Admins = @(), [object[]]$Departments = @())
    $p = ConvertTo-PimAutoExtendPolicy $Policy
    $groupDept = @{}
    foreach ($r in @($Departments)) {
        $d = "$(Get-PimAutoExtendField $r 'Department')".Trim(); $g = "$(Get-PimAutoExtendField $r 'GroupTag')".Trim()
        if ($d -and $g) { $groupDept[$g.ToLowerInvariant()] = $d }
    }
    $deptName = @{}
    foreach ($r in @($Departments)) { $d = "$(Get-PimAutoExtendField $r 'Department')".Trim(); if ($d) { $deptName[$d.ToLowerInvariant()] = $d } }
    [pscustomobject]@{
        leadDays  = $p.leadDays
        defaultOn = $p.defaultOn
        decisions = (ConvertTo-PimAutoExtendDecisions $Decisions)
        review    = (Get-PimAutoExtendReviewIndex -Rules $ReviewRules -Campaigns $ReviewCampaigns -Admins $Admins)
        groupDept = $groupDept
        deptName  = $deptName
        loaded    = $true
    }
}

function Get-PimAutoExtendContext {
    <#
      The context for THIS process, read from the store and cached for $script:PimAutoExtendContextTtlSec. Without a store
      (or when a read fails) the SAFE defaults: 14 days, blank = extend, no review, no denials -- never "stop extending".
    #>
    param([switch]$Refresh)
    $c = $script:PimAutoExtendContextCache
    if (-not $Refresh -and $c -and (([datetime]::UtcNow - $c.at).TotalSeconds -lt $script:PimAutoExtendContextTtlSec)) { return $c.ctx }
    $cs = $null
    if ("$($global:PIM_SqlConnectionString)".Trim()) { $cs = "$($global:PIM_SqlConnectionString)" }
    elseif (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
    $ctx = $null
    if ($cs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue) -and (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue)) {
        try {
            $ctx = New-PimAutoExtendContext -Policy (Get-PimSqlSetting -ConnectionString $cs -Name 'AutoExtendPolicy') `
                -Decisions (Get-PimSqlSetting -ConnectionString $cs -Name 'AutoExtendDecisions') `
                -ReviewRules (Get-PimSqlSetting -ConnectionString $cs -Name 'AccessReviewRules') `
                -ReviewCampaigns (Get-PimSqlSetting -ConnectionString $cs -Name 'AccessReviewCampaigns') `
                -Admins @(Get-PimSqlRows -ConnectionString $cs -Entity 'Account-Definitions-Admins') `
                -Departments @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Departments')
        } catch {
            Write-Warning "[auto-extend] the policy could not be read ($($_.Exception.Message)) -- using the safe defaults (14 days, blank = extend)."
            $ctx = $null
        }
    }
    if (-not $ctx) { $ctx = New-PimAutoExtendContext -Policy $null -Decisions $null -ReviewRules $null -ReviewCampaigns $null; $ctx.loaded = $false }
    $script:PimAutoExtendContextCache = @{ at = [datetime]::UtcNow; ctx = $ctx }
    return $ctx
}

function Get-PimAutoExtendRowDepartment {
    <# PURE. The department an assignment row belongs to: the person's (admin rows), else the group's. '' when unknown. #>
    param([object]$Row, $Context)
    $kind = Get-PimAutoExtendRowKind -Row $Row
    if ($Context -and $kind -in 'Admins', 'Direct') {
        $u = "$(Get-PimAutoExtendField $Row 'Username')".Trim().ToLowerInvariant(); if (-not $u) { $u = "$(Get-PimAutoExtendField $Row 'UserPrincipalName')".Trim().ToLowerInvariant() }
        foreach ($k in @($u, ($u -split '@')[0])) { if ($k -and $Context.review.personDept.ContainsKey($k)) { $d = $Context.review.personDept[$k]; return $(if ($Context.deptName.ContainsKey($d)) { $Context.deptName[$d] } else { $d }) } }
    }
    if ($Context) {
        foreach ($n in 'TargetGroupTag', 'GroupTag', 'SourceGroupTag') {
            $g = "$(Get-PimAutoExtendField $Row $n)".Trim().ToLowerInvariant()
            if ($g -and $Context.groupDept.ContainsKey($g)) { return $Context.groupDept[$g] }
        }
    }
    return ''
}

function Resolve-PimAutoExtendDecision {
    <#
      PURE. Will THIS row's assignment be extended when it is due? @{ extend; source review-keep|review-remove|owner-deny|row|
      default; reason }. -EndUtc = the live assignment's end (an owner decision applies to that end date only).
    #>
    param([object]$Row, [AllowNull()][object]$EndUtc, $Context)
    $ctx = if ($Context) { $Context } else { Get-PimAutoExtendContext }
    $r = { param($e, $s, $why) [pscustomobject]@{ extend = [bool]$e; source = $s; reason = $why } }
    $kind = Get-PimAutoExtendRowKind -Row $Row
    # 1. the access review (per person, over their group memberships)
    if ($kind -eq 'Admins') {
        $u = "$(Get-PimAutoExtendField $Row 'Username')".Trim().ToLowerInvariant()
        $tag = "$(Get-PimAutoExtendField $Row 'GroupTag')".Trim().ToLowerInvariant()
        $lp = ($u -split '@')[0]
        $dept = ''; foreach ($k in @($u, $lp)) { if ($k -and $ctx.review.personDept.ContainsKey($k)) { $dept = $ctx.review.personDept[$k]; break } }
        if ($dept -and $ctx.review.reviewedDepts.ContainsKey($dept)) {
            if ($ctx.review.removeAll.ContainsKey($u) -or $ctx.review.removeAll.ContainsKey($lp)) { return (& $r $false 'review-remove' 'the access review removed this person') }
            if ($ctx.review.removeTags.ContainsKey("$u|$tag") -or $ctx.review.removeTags.ContainsKey("$lp|$tag")) { return (& $r $false 'review-remove' 'the access review removed this membership') }
            if ($ctx.review.keep.ContainsKey($u) -or $ctx.review.keep.ContainsKey($lp)) { return (& $r $true 'review-keep' 'kept in the access review') }
        }
    }
    # 2. an owner / administrator denied THIS expiry
    $key = Get-PimAutoExtendRowKey -Row $Row
    if ($ctx.decisions.ContainsKey($key)) {
        $dc = $ctx.decisions[$key]
        if ($dc.decision -eq 'deny') {
            $endDate = ''; if ($EndUtc -is [datetime]) { $endDate = $EndUtc.ToUniversalTime().ToString('yyyy-MM-dd') }
            $same = (-not $dc.endDate) -or (-not $endDate) -or ($dc.endDate -eq $endDate)
            if (-not $same -and $endDate -and $dc.endDate) {
                try { $same = [math]::Abs(([datetime]::ParseExact($dc.endDate, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) - [datetime]::ParseExact($endDate, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)).TotalDays) -le 1 } catch { $same = $false }
            }
            if ($same) { return (& $r $false 'owner-deny' ("denied by $($dc.by)" + $(if ($dc.reason) { ": $($dc.reason)" } else { '' }))) }
        }
    }
    # 3. the row, 4. the default
    $cell = "$(Get-PimAutoExtendField $Row 'AutoExtend')".Trim()
    if ($cell -match '^(?i)(true|1|yes|y)$')  { return (& $r $true 'row' 'AutoExtend=TRUE on the row') }
    if ($cell -match '^(?i)(false|0|no|n)$') { return (& $r $false 'row' 'AutoExtend=FALSE on the row') }
    if ($ctx.defaultOn) { return (& $r $true 'default' 'AutoExtend blank -- the default (Settings) is ON') }
    return (& $r $false 'default' 'AutoExtend blank -- the default (Settings) is OFF')
}

# ---------------------------------------------------------------------------------------------------------------------
# the OUTLOOK: what the engine saw coming. Collected per run, saved once, read by the report job and the Manager.
# ---------------------------------------------------------------------------------------------------------------------
function Add-PimAutoExtendOutlookItem {
    <# Records one live, time-bound assignment the engine evaluated and that ends within leadDays + 31 days. #>
    param([object]$Row, [datetime]$EndUtc, [datetime]$NowUtc = [datetime]::UtcNow, $Decision, $Context)
    $ctx = if ($Context) { $Context } else { Get-PimAutoExtendContext }
    $days = ($EndUtc.ToUniversalTime() - $NowUtc.ToUniversalTime()).TotalDays
    $key = Get-PimAutoExtendRowKey -Row $Row
    if ($days -lt 0 -or $days -gt ($ctx.leadDays + $script:PimAutoExtendOutlookDays)) {
        # outside the window (e.g. just extended): a tombstone, so a stored item for this row leaves the list at once
        $script:PimAutoExtendOutlook[$key] = [pscustomobject]@{ key = $key; drop = $true }
        return
    }
    $lab = Get-PimAutoExtendRowLabel -Row $Row
    $dec = if ($Decision) { $Decision } else { Resolve-PimAutoExtendDecision -Row $Row -EndUtc $EndUtc -Context $ctx }
    $script:PimAutoExtendOutlook[$key] = [pscustomobject]@{
        key = $key; kind = $lab.kind; principal = $lab.principal; target = $lab.target; type = $lab.type
        department = (Get-PimAutoExtendRowDepartment -Row $Row -Context $ctx)
        endUtc = $EndUtc.ToUniversalTime().ToString('o'); endDate = $EndUtc.ToUniversalTime().ToString('yyyy-MM-dd')
        extendOnUtc = $EndUtc.ToUniversalTime().AddDays(-$ctx.leadDays).ToString('yyyy-MM-dd')
        willExtend = [bool]$dec.extend; source = "$($dec.source)"; reason = "$($dec.reason)"
        days = $(if ("$(Get-PimAutoExtendField $Row 'NumOfDaysWhenExpire')".Trim() -match '^\d+$') { [int]"$(Get-PimAutoExtendField $Row 'NumOfDaysWhenExpire')".Trim() } else { 0 })
        seenUtc = $NowUtc.ToUniversalTime().ToString('o')
    }
}

function Merge-PimAutoExtendOutlook {
    <#
      PURE. Stored outlook items + this run's -> the new list: this run's items replace stored ones by key; a stored item
      whose end has passed, or that no run has seen for 3 days (the row is gone or no longer expiring), is dropped.
    #>
    param([object[]]$Stored = @(), [object[]]$Fresh = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $by = [ordered]@{}
    foreach ($i in @($Stored) + @($Fresh)) {
        if (-not $i) { continue }
        $k = "$(Get-PimAutoExtendField $i 'key')"; if (-not $k) { continue }
        if ([bool](Get-PimAutoExtendField $i 'drop')) { if ($by.Contains($k)) { $by.Remove($k) }; continue }   # a tombstone from this run
        $by[$k] = $i
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($i in $by.Values) {
        $end = $null; try { $end = [datetime]::Parse("$(Get-PimAutoExtendField $i 'endUtc')", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { $end = $null }
        $seen = $null; try { $seen = [datetime]::Parse("$(Get-PimAutoExtendField $i 'seenUtc')", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { $seen = $null }
        if (-not $end -or $end -lt $now) { continue }
        if (-not $seen -or ($now - $seen).TotalDays -gt 3) { continue }
        $out.Add($i)
    }
    return @($out.ToArray() | Sort-Object { "$(Get-PimAutoExtendField $_ 'endUtc')" })
}

function Save-PimAutoExtendOutlook {
    <# Writes this run's collected items into pim.Settings 'AutoExtendOutlook' (merged, pruned) and clears the collector. #>
    param([datetime]$NowUtc = [datetime]::UtcNow)
    if (-not $script:PimAutoExtendOutlook.Count) { return 0 }
    $fresh = @($script:PimAutoExtendOutlook.Values)
    $script:PimAutoExtendOutlook = @{}
    $cs = $null
    if ("$($global:PIM_SqlConnectionString)".Trim()) { $cs = "$($global:PIM_SqlConnectionString)" }
    elseif (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
    if (-not $cs -or -not (Get-Command Get-PimSqlSettingRaw -ErrorAction SilentlyContinue) -or -not (Get-Command Set-PimSqlSettingIfUnchanged -ErrorAction SilentlyContinue)) { return 0 }
    for ($i = 0; $i -lt 5; $i++) {
        $raw = Get-PimSqlSettingRaw -ConnectionString $cs -Name 'AutoExtendOutlook'
        $cur = ConvertTo-PimAutoExtendObject $raw
        $items = Merge-PimAutoExtendOutlook -Stored @(Get-PimAutoExtendField $cur 'items') -Fresh $fresh -NowUtc $NowUtc
        $json = ConvertTo-Json -InputObject ([ordered]@{ updatedUtc = $NowUtc.ToUniversalTime().ToString('o'); items = @($items) }) -Depth 5 -Compress
        if ((Set-PimSqlSettingIfUnchanged -ConnectionString $cs -Name 'AutoExtendOutlook' -NewValueJson $json -ExpectedValueJson $raw) -ge 1) { return @($items).Count }
        Start-Sleep -Milliseconds (40 * ($i + 1))
    }
    Write-Warning '[auto-extend] the upcoming-extension list changed under every attempt -- not saved this run (the next run saves it).'
    return 0
}

# ---------------------------------------------------------------------------------------------------------------------
# the REPORT: what will be extended in the coming month, per department
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimAutoExtendUpcoming {
    <#
      PURE. Outlook items + decisions -> the extensions of the coming period (end within leadDays + -WithinDays days), each
      with the owner decision for THAT end date (approve | deny | ''). -Departments limits it (lower case names; empty = all).
    #>
    param([object[]]$Items = @(), [hashtable]$Decisions = @{}, [int]$LeadDays = 14, [int]$WithinDays = 31, [string[]]$Departments = @(), [switch]$IncludeNotExtending, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $want = @{}; foreach ($d in @($Departments)) { if ("$d".Trim()) { $want["$d".Trim().ToLowerInvariant()] = 1 } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($i in @($Items)) {
        if (-not $i) { continue }
        $end = $null; try { $end = [datetime]::Parse("$($i.endUtc)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { continue }
        if ($end -lt $now -or ($end - $now).TotalDays -gt ($LeadDays + $WithinDays)) { continue }
        if ($want.Count -and -not $want.ContainsKey("$($i.department)".Trim().ToLowerInvariant())) { continue }
        $dc = $null; $k = "$($i.key)".ToLowerInvariant()
        if ($Decisions.ContainsKey($k)) { $d0 = $Decisions[$k]; if (-not $d0.endDate -or $d0.endDate -eq "$($i.endDate)") { $dc = $d0 } }
        $will = [bool]$i.willExtend
        if ($dc -and $dc.decision -eq 'deny' -and "$($i.source)" -notlike 'review-*') { $will = $false }
        if (-not $will -and -not $IncludeNotExtending) { if (-not ($dc -and $dc.decision -eq 'deny')) { continue } }
        $o = [ordered]@{}; foreach ($p in $i.PSObject.Properties) { $o[$p.Name] = $p.Value }
        $o['willExtend'] = $will
        $o['decision'] = $(if ($dc) { $dc.decision } else { '' }); $o['decidedBy'] = $(if ($dc) { $dc.by } else { '' }); $o['decisionReason'] = $(if ($dc) { $dc.reason } else { '' })
        $out.Add([pscustomobject]$o)
    }
    return @($out.ToArray() | Sort-Object { "$($_.department)" }, { "$($_.endUtc)" })
}

function Set-PimAutoExtendDecision {
    <#
      PURE. Decisions map + one decision -> the new map. -Decision approve | deny | clear. The decision is pinned to the end
      date it was made for: the NEXT expiry of the same row is asked again.
    #>
    param([hashtable]$Decisions = @{}, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][ValidateSet('approve', 'deny', 'clear')][string]$Decision,
          [string]$EndDate = '', [string]$By = '', [string]$Reason = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $out = [ordered]@{}
    foreach ($k in @($Decisions.Keys)) { $out[$k] = $Decisions[$k] }
    $k = $Key.Trim().ToLowerInvariant()
    if ($Decision -eq 'clear') { if ($out.Contains($k)) { $out.Remove($k) } }
    else { $out[$k] = [ordered]@{ decision = $Decision; endDate = $EndDate; by = $By; utc = $NowUtc.ToUniversalTime().ToString('o'); reason = $Reason } }
    return $out
}

function Invoke-PimAutoExtendReportJob {
    <#
      The 'autoextend-report' job (monthly). Mails each department's owners the extensions of the coming month with a link to
      the upcoming-extension page (Approve / Deny; no answer = extended), and the administrators (alert recipients) the
      whole list. Mail hold states are SKIPS, not failures. Changes nothing in the store.
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $cs = $null
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
    if (-not $cs) { throw '[autoextend-report] no SQL store -- the upcoming extensions cannot be read' }
    $ctx = Get-PimAutoExtendContext -Refresh
    $out = ConvertTo-PimAutoExtendObject (Get-PimSqlSetting -ConnectionString $cs -Name 'AutoExtendOutlook')
    $items = @(Get-PimAutoExtendUpcoming -Items @(Get-PimAutoExtendField $out 'items') -Decisions $ctx.decisions -LeadDays $ctx.leadDays -WithinDays 31 -NowUtc $NowUtc)
    $owners = @{}
    foreach ($r in @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Departments')) {
        $n = "$(Get-PimAutoExtendField $r 'Department')".Trim(); if (-not $n) { continue }
        $list = @("$(Get-PimAutoExtendField $r 'Owners')" -split '[|;,\s]+' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -match '^[^@\s]+@[^@\s]+$' })
        $k = $n.ToLowerInvariant(); if (-not $owners.ContainsKey($k)) { $owners[$k] = @() }; $owners[$k] = @($owners[$k] + $list | Sort-Object -Unique)
    }
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode("$t") }
    $line = { param($i) '&bull; <b>' + (& $enc $i.principal) + '</b> -- ' + (& $enc $i.target) + $(if ($i.type) { ' (' + (& $enc $i.type) + ')' } else { '' }) + ' -- ends ' + $i.endDate + ', extended on ' + $i.extendOnUtc + $(if ($i.decision -eq 'approve') { ' -- approved' } else { '' }) }
    $send = { param($to, $tok)
        $ok = $false; $why = ''
        try { $m = Send-PimNotifyMail -Type 'alert-notice' -Tokens $tok -Recipient $to -WhatIf:$WhatIf; if ($m -is [hashtable]) { $ok = [bool]$m['sent']; $why = "$($m['reason'])" } elseif ($m) { $ok = [bool]$m.sent; $why = "$($m.reason)" } } catch { $why = "$($_.Exception.Message)" }
        [pscustomobject]@{ ok = ($ok -or $WhatIf); why = $why } }
    $sent = 0; $held = 0; $failed = 0; $noOwner = New-Object System.Collections.Generic.List[string]
    $tally = { param($res, $label)
        if ($res.ok) { $script:__aeSent++ } elseif ((Get-Command Test-PimMailHoldReason -ErrorAction SilentlyContinue) -and (Test-PimMailHoldReason -Reason $res.why)) { $script:__aeHeld++ } else { $script:__aeFailed++; Write-Warning "[autoextend-report] $label not sent: $($res.why)" } }
    $script:__aeSent = 0; $script:__aeHeld = 0; $script:__aeFailed = 0
    $stamp = $NowUtc.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
    foreach ($g in @($items | Group-Object { "$($_.department)".Trim().ToLowerInvariant() })) {
        $dept = "$($g.Group[0].department)"
        $to = if ($g.Name -and $owners.ContainsKey($g.Name)) { @($owners[$g.Name]) } else { @() }
        if (-not $to.Count) { $noOwner.Add($(if ($dept) { $dept } else { '(no department)' })) | Out-Null; continue }
        $tok = @{
            AlertTitle  = ("{0}: {1} permission(s) will be extended in the coming month" -f $(if ($dept) { $dept } else { 'Your department' }), $g.Count)
            AlertEvent  = 'autoextend-report'
            AlertDetail = ("You are an owner of <b>{0}</b>. These permissions end soon and PIM will extend them automatically, {1} days before they end. <b>If they should be extended, do nothing.</b> If one should not, open the link and choose <b>Deny</b> -- that permission then ends on its date.<br><br>{2}" -f (& $enc $dept), $ctx.leadDays, ((@($g.Group | Select-Object -First 40 | ForEach-Object { & $line $_ })) -join '<br>'))
            PortalTab   = 'owner'
            TenantName  = "$($global:PIM_TenantName)"; Instance = 'scheduler'; WhenUtc = $stamp
        }
        foreach ($o in $to) { & $tally (& $send $o $tok) "$dept -> $o" }
    }
    # the administrators: the whole list (alert recipients), so it can be checked when reviews are not used
    if (@($items).Count) {
        $tokA = @{
            AlertTitle  = ("{0} permission(s) will be auto-extended in the coming month" -f @($items).Count)
            AlertEvent  = 'autoextend-report'
            AlertDetail = ("PIM extends these permissions automatically {0} days before they end. Department owners were asked; no answer means extended. Deny one on the upcoming-extension page to let it end.<br><br>{1}" -f $ctx.leadDays, ((@($items | Select-Object -First 80 | ForEach-Object { '[' + (& $enc $(if ($_.department) { $_.department } else { 'no department' })) + '] ' + (& $line $_) })) -join '<br>'))
            PortalTab   = 'owner'
            TenantName  = "$($global:PIM_TenantName)"; Instance = 'scheduler'; WhenUtc = $stamp
        }
        # Alerting event 'expiring-access' (its on/off and recipients are on the Alerting page), linking the owner page.
        if (-not $WhatIf -and (Get-Command Send-PimJobAlertViaNotify -ErrorAction SilentlyContinue)) {
            try { if (Send-PimJobAlertViaNotify -Event 'expiring-access' -Title $tokA.AlertTitle -Detail $tokA.AlertDetail -LinkTab 'owner' -DebounceMinutes 1380) { $script:__aeSent++ } else { $script:__aeHeld++ } }
            catch { $script:__aeFailed++; Write-Warning "[autoextend-report] administrators not mailed: $($_.Exception.Message)" }
        }
    }
    $detail = ("autoextend-report: {0} upcoming extension(s) in {1} department(s); {2} mail(s) sent, {3} held (mail off), {4} failed{5}" -f @($items).Count, @($items | Group-Object department).Count, $script:__aeSent, $script:__aeHeld, $script:__aeFailed,
               $(if ($noOwner.Count) { '; NO owner to ask for: ' + (@($noOwner.ToArray() | Sort-Object -Unique) -join ', ') + ' (they are extended)' } else { '' }))
    [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf; failed = [bool]($script:__aeFailed -gt 0); detail = $detail; count = @($items).Count }
}
