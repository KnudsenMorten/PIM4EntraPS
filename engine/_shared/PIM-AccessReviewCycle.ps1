#Requires -Version 5.1
<#
.SYNOPSIS
    REQ-AR-2 (operator 2026-09-26) -- access reviews PER DEPARTMENT, driven by review RULES in Settings. Job
    'access-review-cycle'.

.DESCRIPTION
    Operator: "access reviews are never per permission group", "one review per department" (wizard), an undecided member
    KEEPS access, "it must also be configured if one approver or 2 approvers are needed per dept. parallel or serial",
    "implement access reviews in my internal env to run every 3 days as a test for all departments".

    What Graph allows (measured on ig798 2026-09-26, tests/live probe): one review covers ONE group (a
    principalResourceMembershipsScope and a multi-group instanceEnumerationScope are both refused); recurrence is weekly /
    monthly-based only (daily/3 refused); 2 stages (serial) and 2 reviewers in one stage (parallel) both work. So:

      * A DEPARTMENT CAMPAIGN = one ONE-TIME review per permission group of the department (every group definition row
        whose Department is that department), all started together and named
        "PIM4EntraPS review - <department> - <group> - <yyyy-MM-dd>".
      * PIM runs the CADENCE itself (any number of days, e.g. 3): this job starts a department's campaign when
        cadenceDays have passed since its last one (pim.Settings 'AccessReviewCycleState').
      * RULES -- pim.Settings 'AccessReviewRules':
          { default = { enabled; cadenceDays; durationDays; reviewers = @(UPN...); approvers = 1|2; mode = parallel|serial;
                        undecided = keep }
            departments = { '<department>' = { off = $true } | { <any default field, overriding it> } } }
        A department with off=$true is OPTED OUT. Reviewers empty = the department's owners (PIM-Definitions-Departments).
      * Undecided = KEEP (defaultDecisionEnabled false; decisions are never auto-applied -- a removal goes through the
        engine's removal and its offboarding/approval gates).
    Pro: 'reviews.campaigns'. Only DEFINED groups are ever reviewed (engine touches only defined).
#>
Set-StrictMode -Off

$script:PimAccessReviewRuleDefaults = [ordered]@{ enabled = $false; cadenceDays = 90; durationDays = 14; reviewers = @(); approvers = 1; mode = 'parallel'; undecided = 'keep' }

function Get-PimArField { param($O, [string]$N) if ($null -eq $O) { return $null }; if ($O -is [System.Collections.IDictionary]) { if ($O.Contains($N)) { return $O[$N] } else { return $null } }; $p = $O.PSObject.Properties[$N]; if ($p) { return $p.Value }; return $null }

function ConvertTo-PimAccessReviewRule {
    <# PURE. One rule (default merged with an override), validated. Throws with the field named on a bad value. #>
    param($Base, $Override)
    $r = [ordered]@{}; foreach ($k in $script:PimAccessReviewRuleDefaults.Keys) { $r[$k] = $script:PimAccessReviewRuleDefaults[$k] }
    foreach ($src in @($Base, $Override)) {
        if ($null -eq $src) { continue }
        foreach ($k in @($script:PimAccessReviewRuleDefaults.Keys)) { $v = Get-PimArField $src $k; if ($null -ne $v -and "$v" -ne '') { $r[$k] = $v } }
    }
    $r.enabled = [bool]$r.enabled
    $r.cadenceDays = [int]"$($r.cadenceDays)"; if ($r.cadenceDays -lt 1 -or $r.cadenceDays -gt 3650) { throw "access review rule: cadenceDays must be 1..3650 (got $($r.cadenceDays))" }
    $r.durationDays = [int]"$($r.durationDays)"; if ($r.durationDays -lt 1 -or $r.durationDays -gt 180) { throw "access review rule: durationDays must be 1..180 (got $($r.durationDays))" }
    $r.reviewers = @(@($r.reviewers) | ForEach-Object { "$_" -split '[,;\s]+' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $r.approvers = [int]"$($r.approvers)"; if ($r.approvers -notin 1, 2) { throw "access review rule: approvers must be 1 or 2 (got $($r.approvers))" }
    $r.mode = "$($r.mode)".Trim().ToLowerInvariant(); if ($r.mode -notin 'parallel', 'serial') { throw "access review rule: mode must be parallel or serial (got '$($r.mode)')" }
    $r.undecided = "$($r.undecided)".Trim().ToLowerInvariant(); if ($r.undecided -ne 'keep') { throw "access review rule: undecided must be 'keep' (removal after a missed review is not built yet; got '$($r.undecided)')" }
    return [pscustomobject]$r
}

function Resolve-PimDepartmentReviewRule {
    <# PURE. The effective rule of one department, or $null when it is opted out / reviews are not enabled for it. #>
    param($Rules, [Parameter(Mandatory)][string]$Department)
    $def = Get-PimArField $Rules 'default'
    $depts = Get-PimArField $Rules 'departments'
    $ov = $null
    if ($depts) {
        $names = if ($depts -is [System.Collections.IDictionary]) { @($depts.Keys) } else { @($depts.PSObject.Properties.Name) }
        foreach ($n in $names) { if ("$n".Trim().ToLowerInvariant() -eq $Department.Trim().ToLowerInvariant()) { $ov = Get-PimArField $depts $n } }
    }
    if ($ov -and [bool](Get-PimArField $ov 'off')) { return $null }
    $rule = ConvertTo-PimAccessReviewRule -Base $def -Override $ov
    if (-not $rule.enabled) { return $null }
    return $rule
}

function Get-PimAccessReviewCyclePlan {
    <#
      PURE. Which department campaigns are DUE now. -Groups: @{ GroupName; Department } (the defined permission groups);
      -Departments: @{ Department; Owners } rows; -State: @{ '<dept lower>' = @{ lastStartedUtc } }.
      Returns @{ due = @({ department; rule; groups; reviewers }); skipped = @({ department; reason }) }.
    #>
    param($Rules, [object[]]$Groups = @(), [object[]]$Departments = @(), $State, [datetime]$NowUtc = [datetime]::UtcNow)
    $byDept = [ordered]@{}
    foreach ($g in @($Groups)) { $d = "$(Get-PimArField $g 'Department')".Trim(); $n = "$(Get-PimArField $g 'GroupName')".Trim(); if ($d -and $n) { if (-not $byDept.Contains($d)) { $byDept[$d] = New-Object System.Collections.Generic.List[string] }; if (-not $byDept[$d].Contains($n)) { $byDept[$d].Add($n) } } }
    $owners = @{}; foreach ($r in @($Departments)) { $d = "$(Get-PimArField $r 'Department')".Trim(); if ($d) { $owners[$d.ToLowerInvariant()] = @("$(Get-PimArField $r 'Owners')" -split '[,;\s]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } }
    $due = New-Object System.Collections.Generic.List[object]; $skipped = New-Object System.Collections.Generic.List[object]
    foreach ($d in @($byDept.Keys)) {
        $rule = $null
        try { $rule = Resolve-PimDepartmentReviewRule -Rules $Rules -Department $d } catch { $skipped.Add([pscustomobject]@{ department = $d; reason = "rule invalid: $($_.Exception.Message)" }); continue }
        if (-not $rule) { $skipped.Add([pscustomobject]@{ department = $d; reason = 'off (opted out, or reviews not enabled)' }); continue }
        $st = Get-PimArField $State $d.ToLowerInvariant()
        $last = $null; $lr = Get-PimArField $st 'lastStartedUtc'
        if ($lr) { try { $last = if ($lr -is [datetime]) { ([datetime]$lr).ToUniversalTime() } else { [datetime]::Parse("$lr", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } } catch { $last = $null } }
        if ($last -and ($NowUtc.ToUniversalTime() - $last).TotalDays -lt $rule.cadenceDays) { $skipped.Add([pscustomobject]@{ department = $d; reason = ("not due (last started {0:u}, every {1} day(s))" -f $last, $rule.cadenceDays) }); continue }
        $rev = @(@(if (@($rule.reviewers).Count) { $rule.reviewers } else { $owners[$d.ToLowerInvariant()] }) | Where-Object { "$_".Trim() })   # a missing owner row is $null -- never a reviewer
        if (-not $rev.Count) { $skipped.Add([pscustomobject]@{ department = $d; reason = 'no reviewer: the rule names none and the department has no owner' }); continue }
        if ($rule.approvers -eq 2 -and $rev.Count -lt 2) { $skipped.Add([pscustomobject]@{ department = $d; reason = 'the rule needs 2 approvers and names 1' }); continue }
        $due.Add([pscustomobject]@{ department = $d; rule = $rule; groups = @($byDept[$d].ToArray()); reviewers = @($rev) })
    }
    return [pscustomobject]@{ due = @($due.ToArray()); skipped = @($skipped.ToArray()) }
}

function New-PimAccessReviewCycleBody {
    <#
      PURE. The ONE-TIME review of one group in a department campaign. -ReviewerIds: user object ids in rule order.
      approvers 1 -> one stage, the first reviewer(s); 2 + parallel -> one stage, both reviewers (Graph: the first decision
      counts); 2 + serial -> two stages, approver 1 then approver 2 (stage 2 sees stage 1's decisions).
    #>
    param([Parameter(Mandatory)][string]$Department, [Parameter(Mandatory)][string]$GroupName, [Parameter(Mandatory)][string]$GroupId,
          [Parameter(Mandatory)]$Rule, [Parameter(Mandatory)][string[]]$ReviewerIds, [datetime]$NowUtc = [datetime]::UtcNow)
    $q = { param($id) @{ query = "/users/$id"; queryType = 'MicrosoftGraph' } }
    $day = $NowUtc.ToUniversalTime().ToString('yyyy-MM-dd')
    $body = [ordered]@{
        displayName          = "PIM4EntraPS review - $Department - $GroupName - $day"
        descriptionForAdmins = "Department access review ($Department), started by PIM4EntraPS every $($Rule.cadenceDays) day(s). Undecided members keep their access; decisions are not applied automatically."
        descriptionForReviewers = "Review who still needs membership of $GroupName ($Department)."
        scope                = @{ '@odata.type' = '#microsoft.graph.accessReviewQueryScope'; query = "/groups/$GroupId/transitiveMembers"; queryType = 'MicrosoftGraph' }
    }
    $settings = [ordered]@{ mailNotificationsEnabled = $true; reminderNotificationsEnabled = $true; justificationRequiredOnApproval = $true; recommendationsEnabled = $true
        defaultDecisionEnabled = $false; defaultDecision = 'None'; autoApplyDecisionsEnabled = $false; instanceDurationInDays = [int]$Rule.durationDays
        recurrence = @{ pattern = @{ type = 'weekly'; interval = 1 }; range = @{ type = 'numbered'; numberOfOccurrences = 1; startDate = $day } } }
    $ids = @($ReviewerIds)
    if ($Rule.approvers -eq 2 -and $Rule.mode -eq 'serial') {
        $half = [math]::Max(1, [math]::Floor([int]$Rule.durationDays / 2))
        $body['stageSettings'] = @(
            @{ stageId = '1'; durationInDays = $half; recommendationsEnabled = $true; decisionsThatWillMoveToNextStage = @('NotReviewed', 'Approve'); reviewers = @(& $q $ids[0]) },
            @{ stageId = '2'; dependsOn = @('1'); durationInDays = [math]::Max(1, [int]$Rule.durationDays - $half); recommendationsEnabled = $true; reviewers = @(& $q $ids[1]) })
    } else {
        $who = if ($Rule.approvers -eq 2) { @($ids | Select-Object -First 2) } else { $ids }
        $body['reviewers'] = @($who | ForEach-Object { & $q $_ })
    }
    $body['settings'] = $settings
    return $body
}

function Get-PimDepartmentsWithoutOwner {
    <#
      PURE (operator 2026-09-26: "a dept with no owners must escalate to alert mail" / "there must be a daily mail if a dept
      has min not 1 owner"). Every department -- a PIM-Definitions-Departments row, or a department a group names -- with NO
      owner. Returns the names, sorted.
    #>
    param([object[]]$Departments = @(), [object[]]$Groups = @())
    $own = @{}
    foreach ($r in @($Departments)) { $d = "$(Get-PimArField $r 'Department')".Trim(); if ($d) { $o = @("$(Get-PimArField $r 'Owners')" -split '[,;\s]+' | Where-Object { "$_".Trim() }); $k = $d.ToLowerInvariant(); if (-not $own.ContainsKey($k)) { $own[$k] = @{ name = $d; n = 0 } }; $own[$k].n += $o.Count } }
    foreach ($g in @($Groups)) { $d = "$(Get-PimArField $g 'Department')".Trim(); if ($d -and -not $own.ContainsKey($d.ToLowerInvariant())) { $own[$d.ToLowerInvariant()] = @{ name = $d; n = 0 } } }
    return @($own.Values | Where-Object { $_.n -lt 1 } | ForEach-Object { $_.name } | Sort-Object)
}

function Invoke-PimAccessReviewCycleJob {
    <# The job. Reads rules + state + the defined groups from SQL, starts every DUE department campaign. #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $cs = $null
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
    if (-not $cs) { throw '[access-review-cycle] no SQL store -- the review rules and the groups cannot be read' }
    # Departments WITHOUT an owner escalate to the alert mail, DAILY while it lasts -- before the Pro / rules checks: an
    # ownerless department has nobody to review it, approve for it or answer for it, reviews on or off.
    $deptRows0 = @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Departments' | ForEach-Object { [pscustomobject]@{ Department = "$(if ($_.Department) { $_.Department } else { $_.Name })"; Owners = "$($_.Owners)" } })
    $groups0 = New-Object System.Collections.Generic.List[object]
    foreach ($e in @('PIM-Definitions-Roles', 'PIM-Definitions-Tasks', 'PIM-Definitions-Services', 'PIM-Definitions-Processes', 'PIM-Definitions-Organization')) {
        foreach ($r in @(Get-PimSqlRows -ConnectionString $cs -Entity $e)) { if ("$($r.Department)".Trim()) { $groups0.Add([pscustomobject]@{ Department = "$($r.Department)".Trim() }) } }
    }
    $noOwner = @(Get-PimDepartmentsWithoutOwner -Departments $deptRows0 -Groups $groups0.ToArray())
    $ownerNote = ''
    if ($noOwner.Count) {
        $ownerNote = " | $($noOwner.Count) department(s) WITHOUT an owner: $($noOwner -join ', ')"
        if (-not $WhatIf -and (Get-Command Send-PimJobAlertViaNotify -ErrorAction SilentlyContinue)) {
            $enc = { param($x) [System.Net.WebUtility]::HtmlEncode("$x") }
            $detail = "These departments have no owner, so nobody reviews, approves or answers for their access:<br><br>" + (@($noOwner | ForEach-Object { '&bull; <b>' + (& $enc $_) + '</b>' }) -join '<br>')
            try { [void](Send-PimJobAlertViaNotify -Event 'coverage' -Title ("{0} department(s) have no owner" -f $noOwner.Count) -Detail $detail -LinkTab 'departments' -DebounceMinutes 1380 `
                            -Headline 'A department needs at least one owner.' -Action 'Open Departments and name an owner for each department listed.') }
            catch { Write-Warning "[access-review-cycle] the no-owner alert could not be sent: $($_.Exception.Message)" }
        }
    }
    if ((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and -not (Test-PimFeatureAvailable -Key 'reviews.campaigns' -Quiet)) {
        return [pscustomobject]@{ ran = $false; skipped = $true; whatIf = [bool]$WhatIf; detail = ('access-review-cycle: access review campaigns are not enabled or not licensed (Pro) -- nothing started' + $ownerNote) }
    }
    $read = { param($n) $v = Get-PimSqlSetting -ConnectionString $cs -Name $n; if ($v -is [string] -and "$v".Trim()) { $v | ConvertFrom-Json } else { $v } }
    $rules = & $read 'AccessReviewRules'
    if (-not $rules) { return [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf; detail = ('access-review-cycle: no review rules (Access reviews > Review rules) -- nothing started' + $ownerNote) } }
    $state = & $read 'AccessReviewCycleState'
    $groups = New-Object System.Collections.Generic.List[object]
    foreach ($e in @('PIM-Definitions-Roles', 'PIM-Definitions-Tasks', 'PIM-Definitions-Services', 'PIM-Definitions-Processes', 'PIM-Definitions-Organization')) {
        foreach ($r in @(Get-PimSqlRows -ConnectionString $cs -Entity $e)) { if ("$($r.GroupName)".Trim() -and "$($r.Department)".Trim()) { $groups.Add([pscustomobject]@{ GroupName = "$($r.GroupName)".Trim(); Department = "$($r.Department)".Trim() }) } }
    }
    $depts = @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Departments' | ForEach-Object { [pscustomobject]@{ Department = "$(if ($_.Department) { $_.Department } else { $_.Name })"; Owners = "$($_.Owners)" } })
    $plan = Get-PimAccessReviewCyclePlan -Rules $rules -Groups $groups.ToArray() -Departments $depts -State $state -NowUtc $NowUtc
    if ($WhatIf) {
        return [pscustomobject]@{ ran = $true; whatIf = $true; detail = ("whatif:access-review-cycle -- would start {0} department campaign(s): {1}" -f @($plan.due).Count, (@($plan.due | ForEach-Object { "$($_.department) ($(@($_.groups).Count) group(s))" }) -join ', ')) }
    }
    $newState = @{}; if ($state) { foreach ($p in $state.PSObject.Properties) { $newState[$p.Name] = $p.Value } }
    $started = 0; $errors = New-Object System.Collections.Generic.List[string]; $done = New-Object System.Collections.Generic.List[string]
    $userCache = @{}
    foreach ($c in @($plan.due)) {
        $ids = New-Object System.Collections.Generic.List[string]
        foreach ($u in @($c.reviewers)) {
            $k = $u.ToLowerInvariant()
            if (-not $userCache.ContainsKey($k)) { try { $userCache[$k] = "$((Invoke-PimGraph -Path "/users/$([uri]::EscapeDataString($u))?`$select=id").id)" } catch { $userCache[$k] = '' } }
            if ($userCache[$k]) { $ids.Add($userCache[$k]) } else { $errors.Add("$($c.department): reviewer '$u' is not a user in this tenant") }
        }
        if (-not $ids.Count -or ($c.rule.approvers -eq 2 -and $ids.Count -lt 2)) { $errors.Add("$($c.department): not started -- its reviewer(s) could not be resolved"); continue }
        $n = 0
        foreach ($gn in @($c.groups)) {
            $esc = $gn.Replace("'", "''")
            $gid = "$(@((Invoke-PimGraph -Path "/groups?`$filter=displayName eq '$esc'&`$select=id").value)[0].id)"
            if (-not $gid) { $errors.Add("$($c.department): group '$gn' not found in the tenant"); continue }
            $body = New-PimAccessReviewCycleBody -Department $c.department -GroupName $gn -GroupId $gid -Rule $c.rule -ReviewerIds $ids.ToArray() -NowUtc $NowUtc
            try { [void](Invoke-PimGraph -Beta -Method POST -Path '/identityGovernance/accessReviews/definitions' -Body $body); $n++ }
            catch { $errors.Add("$($c.department): the review of '$gn' could not be created: $($_.ErrorDetails.Message) $($_.Exception.Message)") }
        }
        if ($n) { $started += $n; $done.Add("$($c.department) ($n)"); $newState[$c.department.ToLowerInvariant()] = [ordered]@{ lastStartedUtc = $NowUtc.ToUniversalTime().ToString('o'); reviews = $n } }
    }
    if ($done.Count) { Set-PimSqlSetting -ConnectionString $cs -Name 'AccessReviewCycleState' -Value ([pscustomobject]$newState | ConvertTo-Json -Depth 5) }
    $detail = "access-review-cycle: started $started review(s) in $($done.Count) department campaign(s)$(if ($done.Count) { ': ' + ($done -join ', ') })$ownerNote"
    if ($errors.Count) { throw ("[access-review-cycle] " + $detail + ' -- ' + ($errors -join '; ')) }
    return [pscustomobject]@{ ran = $true; whatIf = $false; detail = $detail }
}
