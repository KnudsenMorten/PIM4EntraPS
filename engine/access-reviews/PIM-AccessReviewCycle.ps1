#Requires -Version 5.1
<#
.SYNOPSIS
    REQ-AR-2 (operator 2026-09-26) -- access reviews PER DEPARTMENT, run BY PIM, driven by review RULES. Job
    'access-review-cycle'.

.DESCRIPTION
    Operator: "access reviews are never per permission group"; one review per DEPARTMENT -- the reviewers confirm every admin
    account of the department and the access each holds (wizard); an undecided person KEEPS access; "1 or 2 approvers per
    dept, parallel or serial"; "if an access review is not responded it goes back and get a weekly reminder 3 times. then it
    goes to the escalation mail/alert mail"; "a super admin [can] override pending access review and choose what to do";
    "run every 3 days as a test"; decision 2026-09-26: PIM's OWN review, not Microsoft Entra access reviews.

    WHY NOT ENTRA (measured on ig798 2026-09-26): a review over "these users x these groups" (principalResourceMemberships)
    and over several groups are REFUSED; a group review filtered to one department's users needs the Entra ID Governance
    licence ("Tenant is not authorized for Custom Scoping Conditions Feature"); recurrence is weekly at the fastest.

    MODEL -- pim.Settings:
      'AccessReviewRules'     { default = { enabled; cadenceDays; durationDays; reviewers[]; reviewersOnly; approvers 1|2; mode parallel|serial;
                                            undecided keep|remove; remindEveryDays; reminders }
                                departments = { '<dept>' = { off } | { <fields overriding the default> } } }
      'AccessReviewCampaigns' { campaigns = @( { id; department; status open|closed; startedUtc; dueUtc; closedUtc; closeReason;
                                            approvers; mode; undecided; reviewers[]; remindersSent; lastReminderUtc; escalatedUtc;
                                            items = @( { user; displayName; access[]; accessRows[] = { groupTag; type; label; username };
                                                         decisions = { '<reviewer>' = { decision; access[]; utc } };
                                                         override = { decision; access[]; by; utc }; outcome; removeAccess[] } ) } ) }
    DECISIONS per person (Keep | Remove). A Remove may name ACCESS (group tags): then ONLY those memberships go -- a staged
    removal of the PIM-Assignments-Admins rows, carried out on Review & commit. A Remove WITHOUT access removes the whole
    account (the offboard approval request). Operator 2026-09-26: "remove ONE membership instead of offboarding the account".
      * 1 approver         -- any reviewer's decision stands.
      * 2 approvers PARALLEL -- both decide (either order); both Keep = keep, any Remove = remove; what is removed = the
                              union of both Removes, and a whole-account Remove wins.
      * 2 approvers SERIAL   -- reviewer 1 decides first, then reviewer 2 (who sees reviewer 1's decision); reviewer 2 decides.
      * a SuperAdmin OVERRIDE decides the item outright.
    LIFECYCLE: a department's campaign starts when its rule is due (cadenceDays since the last START) and no campaign of it
    is open. It closes when every item is decided; when it is past dueUtc with items open, the reviewers get a reminder every
    remindEveryDays (up to 'reminders' times), then the alert recipients get the ESCALATION and the campaign closes --
    undecided = KEEP by default; a rule with undecided = 'remove' raises the offboard approval request for every undecided
    person instead (operator 2026-09-26: remove-on-undecided as an option). A Remove outcome raises the offboard approval
    request (a PIM administrator approves; the engine executes) -- never a direct removal.
#>
Set-StrictMode -Off

# reviewersOnly (2.4.555, §100.28 REVIEW-OWNERS-VISIBLE): the department OWNERS always review their department; a rule's
# reviewers are reviewers NEXT TO them. Only reviewersOnly = true (and at least one reviewer named) makes the rule's list
# replace the owners. Before 2.4.555 a typed reviewer silently replaced every department's owners.
$script:PimAccessReviewRuleDefaults = [ordered]@{ enabled = $false; cadenceDays = 90; durationDays = 14; reviewers = @(); reviewersOnly = $false; approvers = 1; mode = 'parallel'; undecided = 'keep'; remindEveryDays = 7; reminders = 3 }

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
    $r.reviewersOnly = ("$($r.reviewersOnly)".Trim().ToLowerInvariant() -in 'true', '1', 'yes', 'on')
    $r.approvers = [int]"$($r.approvers)"; if ($r.approvers -notin 1, 2) { throw "access review rule: approvers must be 1 or 2 (got $($r.approvers))" }
    $r.mode = "$($r.mode)".Trim().ToLowerInvariant(); if ($r.mode -notin 'parallel', 'serial') { throw "access review rule: mode must be parallel or serial (got '$($r.mode)')" }
    $r.undecided = "$($r.undecided)".Trim().ToLowerInvariant(); if ($r.undecided -notin 'keep', 'remove') { throw "access review rule: undecided must be keep or remove (got '$($r.undecided)')" }
    $r.remindEveryDays = [int]"$($r.remindEveryDays)"; if ($r.remindEveryDays -lt 1 -or $r.remindEveryDays -gt 90) { throw "access review rule: remindEveryDays must be 1..90 (got $($r.remindEveryDays))" }
    $r.reminders = [int]"$($r.reminders)"; if ($r.reminders -lt 0 -or $r.reminders -gt 10) { throw "access review rule: reminders must be 0..10 (got $($r.reminders))" }
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

function Get-PimEffectiveReviewers {
    <#
      PURE (§100.28 REVIEW-OWNERS-VISIBLE, owner 2026-10-09: "why does access review not pick up the approvers on the dept").
      WHO actually reviews one department under a rule: the department's OWNERS first, then the rule's reviewers (deduplicated,
      case-insensitive) -- unless the rule says reviewersOnly and names at least one reviewer, then only the rule's list.
      Returns { reviewers[] (campaign order); entries[] = { upn; source owner|rule }; source owners|owners+rule|rule|rule-only|none }.
      The job and the Manager's rules page both call this, so the page shows exactly who the job will ask.
    #>
    param($Rule, [string[]]$Owners = @())
    $own = @(@($Owners) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $ruleRev = @(@(Get-PimArField $Rule 'reviewers') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $only = [bool](Get-PimArField $Rule 'reviewersOnly') -and $ruleRev.Count -gt 0
    $cand = @()
    if (-not $only) { foreach ($o in $own) { $cand += ,@("$o", 'owner') } }
    foreach ($x in $ruleRev) { $cand += ,@("$x", 'rule') }
    $entries = @(); $seen = @{}
    foreach ($c in $cand) {
        $k = "$($c[0])".ToLowerInvariant()
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $entries += [pscustomobject]@{ upn = "$($c[0])"; source = "$($c[1])" }
    }
    $src = if ($only) { 'rule-only' } elseif ($own.Count -and $ruleRev.Count) { 'owners+rule' } elseif ($own.Count) { 'owners' } elseif ($ruleRev.Count) { 'rule' } else { 'none' }
    return [pscustomobject]@{ reviewers = @($entries | ForEach-Object { $_.upn }); entries = @($entries); source = $src }
}

function Get-PimDepartmentsWithoutOwner {
    <#
      PURE (operator 2026-09-26: "a dept with no owners must escalate to alert mail" / "there must be a daily mail if a dept
      has min not 1 owner"). Every department -- a PIM-Definitions-Departments row, or a department an admin or a group names --
      with NO owner. Returns the names, sorted.
    #>
    param([object[]]$Departments = @(), [object[]]$Groups = @())
    $own = @{}
    foreach ($r in @($Departments)) { $d = "$(Get-PimArField $r 'Department')".Trim(); if ($d) { $o = @("$(Get-PimArField $r 'Owners')" -split '[,;\s]+' | Where-Object { "$_".Trim() }); $k = $d.ToLowerInvariant(); if (-not $own.ContainsKey($k)) { $own[$k] = @{ name = $d; n = 0 } }; $own[$k].n += $o.Count } }
    foreach ($g in @($Groups)) { $d = "$(Get-PimArField $g 'Department')".Trim(); if ($d -and -not $own.ContainsKey($d.ToLowerInvariant())) { $own[$d.ToLowerInvariant()] = @{ name = $d; n = 0 } } }
    return @($own.Values | Where-Object { $_.n -lt 1 } | ForEach-Object { $_.name } | Sort-Object)
}

# ---------------------------------------------------------------------------------------------------------------------
# campaigns (PURE)
# ---------------------------------------------------------------------------------------------------------------------
function ConvertTo-PimUtcDate { param($V) if ($null -eq $V -or "$V" -eq '') { return $null }; if ($V -is [datetime]) { return ([datetime]$V).ToUniversalTime() }; try { return [datetime]::Parse("$V", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { return $null } }

function Get-PimDepartmentReviewPeople {
    <#
      PURE. The people of one department: every admin definition row (Account-Definitions-Admins) whose Department is it,
      each with the access it holds (PIM-Assignments-Admins GroupTag + type). @{ user; displayName; access[]; accessRows[] }
      -- accessRows = @{ groupTag; type; label; username } per access (username = the row's own Username, its key), so a
      reviewer can remove ONE membership.
    #>
    param([Parameter(Mandatory)][string]$Department, [object[]]$Admins = @(), [object[]]$Assignments = @())
    $acc = @{}
    foreach ($a in @($Assignments)) {
        $u = "$(Get-PimArField $a 'Username')".Trim().ToLowerInvariant(); $gt = "$(Get-PimArField $a 'GroupTag')".Trim()
        if ($u -and $gt -and "$(Get-PimArField $a 'Action')" -notmatch '(?i)^remove') {
            if (-not $acc.ContainsKey($u)) { $acc[$u] = New-Object System.Collections.Generic.List[object] }
            $t = "$(Get-PimArField $a 'AssignmentType')".Trim()
            $acc[$u].Add([pscustomobject]@{ groupTag = $gt; type = $t; label = $(if ($t) { "$gt ($t)" } else { $gt }); username = "$(Get-PimArField $a 'Username')".Trim() })
        }
    }
    # The assignments name the account by its UPN; an admin row may carry only the short UserName (measured on EFIF
    # 2026-09-26: 'adm-e-emaa-t1-c' vs 'adm-e-emaa-t1-c@<tenant>') -- so the access is also found by the UPN's local part.
    $byLocal = @{}
    foreach ($k in @($acc.Keys)) { $lp = ($k -split '@')[0]; if (-not $byLocal.ContainsKey($lp)) { $byLocal[$lp] = $acc[$k] } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Admins)) {
        if ("$(Get-PimArField $r 'Department')".Trim().ToLowerInvariant() -ne $Department.Trim().ToLowerInvariant()) { continue }
        $short = "$(Get-PimArField $r 'UserName')".Trim(); if (-not $short) { $short = "$(Get-PimArField $r 'Username')".Trim() }
        # The review item is the UPN when the row has one: a Remove decision offboards the account by it.
        $u = "$(Get-PimArField $r 'UserPrincipalName')".Trim(); if (-not $u) { $u = $short }; if (-not $u) { continue }
        $dn = "$(Get-PimArField $r 'DisplayName')".Trim(); if (-not $dn) { $dn = ("$(Get-PimArField $r 'FirstName') $(Get-PimArField $r 'LastName')").Trim() }
        $k = $u.ToLowerInvariant()
        # (a plain assignment each -- an if-EXPRESSION would unroll a one-entry list into a string)
        $lk = $k; if (-not $acc.ContainsKey($lk) -and $short) { $lk = $short.ToLowerInvariant() }
        $list = $null; if ($acc.ContainsKey($lk)) { $list = $acc[$lk] } else { $list = $byLocal[($k -split '@')[0]] }
        $rows = @(if ($null -ne $list) { $list.ToArray() })
        $out.Add([pscustomobject]@{ user = $u; displayName = $dn; access = @($rows | ForEach-Object { "$($_.label)" }); accessRows = $rows })
    }
    return @($out.ToArray() | Sort-Object user)
}

function New-PimReviewCampaign {
    <# PURE. A new OPEN campaign for one department. #>
    param([Parameter(Mandatory)][string]$Department, [Parameter(Mandatory)]$Rule, [Parameter(Mandatory)][string[]]$Reviewers, [object[]]$People = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    return [pscustomobject]@{
        id = "{0}-{1}" -f ($Department -replace '[^A-Za-z0-9]', '').ToLowerInvariant(), $now.ToString('yyyyMMddHHmm'); department = $Department; status = 'open'
        startedUtc = $now.ToString('o'); dueUtc = $now.AddDays([int]$Rule.durationDays).ToString('o'); closedUtc = ''; closeReason = ''
        approvers = [int]$Rule.approvers; mode = "$($Rule.mode)"; undecided = $(if ("$($Rule.undecided)" -eq 'remove') { 'remove' } else { 'keep' }); reviewers = @($Reviewers | Select-Object -First $(if ([int]$Rule.approvers -eq 2) { 2 } else { 20 }))
        remindEveryDays = [int]$Rule.remindEveryDays; reminders = [int]$Rule.reminders; remindersSent = 0; lastReminderUtc = ''; escalatedUtc = ''
        items = @($People | ForEach-Object { [pscustomobject]@{ user = "$($_.user)"; displayName = "$($_.displayName)"; access = @($_.access); accessRows = @($_.accessRows); decisions = [pscustomobject]@{}; override = $null; outcome = ''; removeAccess = @() } })
    }
}

function Get-PimReviewItemState {
    <#
      PURE. One person's state in a campaign: @{ state = pending | keep | remove; awaiting = @(reviewers still to decide); by;
      removeAccess = @(group tags) }. removeAccess is set on a REMOVE only: empty = the whole account, else only those
      memberships (PARALLEL: the union of both Removes, a whole-account Remove wins; SERIAL: reviewer 2's).
    #>
    param([Parameter(Mandatory)]$Campaign, [Parameter(Mandatory)]$Item)
    $st = { param($s, $aw, $by, $acc) [pscustomobject]@{ state = $s; awaiting = @($aw); by = $by; removeAccess = @(if ($s -eq 'remove') { @($acc) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Select-Object -Unique }) } }
    $ov = Get-PimArField $Item 'override'
    if ($ov -and "$(Get-PimArField $ov 'decision')") { return (& $st "$(Get-PimArField $ov 'decision')" @() "override: $(Get-PimArField $ov 'by')" @(Get-PimArField $ov 'access')) }
    $revs = @($Campaign.reviewers); $dec = Get-PimArField $Item 'decisions'
    $d = @{}; $da = @{}
    foreach ($r in $revs) { $x = Get-PimArField $dec $r.ToLowerInvariant(); if ($x -and "$(Get-PimArField $x 'decision')") { $d[$r.ToLowerInvariant()] = "$(Get-PimArField $x 'decision')"; $da[$r.ToLowerInvariant()] = @(@(Get-PimArField $x 'access') | Where-Object { "$_".Trim() }) } }
    if ([int]$Campaign.approvers -ne 2) {
        $any = @($revs | Where-Object { $d.ContainsKey($_.ToLowerInvariant()) } | Select-Object -First 1)
        if ($any.Count) { $k = $any[0].ToLowerInvariant(); return (& $st $d[$k] @() $any[0] $da[$k]) }
        return (& $st 'pending' $revs '' @())
    }
    $r1 = "$($revs[0])".ToLowerInvariant(); $r2 = "$($revs[1])".ToLowerInvariant()
    if ("$($Campaign.mode)" -eq 'serial') {
        if (-not $d.ContainsKey($r1)) { return (& $st 'pending' @($revs[0]) '' @()) }
        if (-not $d.ContainsKey($r2)) { return (& $st 'pending' @($revs[1]) '' @()) }
        return (& $st $d[$r2] @() $revs[1] $da[$r2])
    }
    $miss = @($revs | Where-Object { -not $d.ContainsKey($_.ToLowerInvariant()) })
    if ($miss.Count) { return (& $st 'pending' $miss '' @()) }
    $removers = @($d.Keys | Where-Object { $d[$_] -eq 'remove' })
    if (-not $removers.Count) { return (& $st 'keep' @() ($revs -join ' + ') @()) }
    # a whole-account Remove (no access named) wins over a Remove of some memberships
    $whole = @($removers | Where-Object { -not @($da[$_]).Count }).Count -gt 0
    return (& $st 'remove' @() ($revs -join ' + ') $(if ($whole) { @() } else { @($removers | ForEach-Object { $da[$_] }) }))
}

function Set-PimReviewDecision {
    <#
      PURE. Record one reviewer's decision (keep | remove) on one person, or a SuperAdmin -Override. Returns
      @{ ok; reason; campaign }. Refused: a closed campaign, a person not in it, a caller who is not a reviewer, reviewer 2 of a
      SERIAL campaign before reviewer 1 decided, an item already decided, -Access on a Keep, -Access naming a group the person
      does not hold in this review.
      -Access (group tags, Remove only): remove ONLY these memberships instead of the whole account.
    #>
    param([Parameter(Mandatory)]$Campaign, [Parameter(Mandatory)][string]$User, [Parameter(Mandatory)][ValidateSet('keep', 'remove')][string]$Decision,
          [Parameter(Mandatory)][string]$By, [switch]$Override, [string[]]$Access = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $no = { param($w) [pscustomobject]@{ ok = $false; reason = $w; campaign = $Campaign } }
    if ("$($Campaign.status)" -ne 'open') { return (& $no 'this review is closed') }
    $it = @($Campaign.items | Where-Object { "$($_.user)".ToLowerInvariant() -eq $User.Trim().ToLowerInvariant() })[0]
    if (-not $it) { return (& $no "$User is not in this review") }
    $st = Get-PimReviewItemState -Campaign $Campaign -Item $it
    if ($st.state -ne 'pending') { return (& $no "$User is already decided ($($st.state))") }
    $acc = @(@($Access) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if ($acc.Count -and $Decision -ne 'remove') { return (& $no 'access can only be named on a Remove') }
    if ($acc.Count) {
        # the group tags the person holds in THIS review (a campaign from before 2.4.453 has no accessRows: parse the labels)
        $held = @(@($it.accessRows) | Where-Object { $_ } | ForEach-Object { "$(Get-PimArField $_ 'groupTag')".Trim().ToLowerInvariant() })
        if (-not $held.Count) { $held = @(@($it.access) | ForEach-Object { ("$_" -replace '\s*\([^)]*\)\s*$', '').Trim().ToLowerInvariant() }) }
        $bad = @($acc | Where-Object { $held -notcontains $_.ToLowerInvariant() })
        if ($bad.Count) { return (& $no "$User does not hold $($bad -join ', ') in this review") }
    }
    $stamp = $NowUtc.ToUniversalTime().ToString('o')
    if ($Override) { $it.override = [pscustomobject]@{ decision = $Decision; access = $acc; by = $By; utc = $stamp }; return [pscustomobject]@{ ok = $true; reason = ''; campaign = $Campaign } }
    $me = $By.Trim().ToLowerInvariant()
    if (@($Campaign.reviewers | ForEach-Object { "$_".ToLowerInvariant() }) -notcontains $me) { return (& $no "$By is not a reviewer of this review") }
    # No self-review: a reviewer never keeps their OWN account (it stays open for the other approver or a SuperAdmin).
    if ($me -eq $User.Trim().ToLowerInvariant() -or ($me -split '@')[0] -eq ($User.Trim().ToLowerInvariant() -split '@')[0]) { return (& $no "$By cannot review their own account -- another reviewer or a SuperAdmin decides") }
    if (@($st.awaiting | ForEach-Object { "$_".ToLowerInvariant() }) -notcontains $me) { return (& $no $(if ("$($Campaign.mode)" -eq 'serial') { "the first approver ($($Campaign.reviewers[0])) decides first" } else { "$By has already decided on $User" })) }
    $it.decisions | Add-Member -NotePropertyName $me -NotePropertyValue ([pscustomobject]@{ decision = $Decision; access = $acc; utc = $stamp }) -Force
    return [pscustomobject]@{ ok = $true; reason = ''; campaign = $Campaign }
}

function Get-PimReviewMembershipRows {
    <#
      PURE. A Remove that names ACCESS: the stored PIM-Assignments-Admins rows it removes -- the rows of THIS person (the
      item's user, or the Username an accessRow carries) whose GroupTag is one of -Tags. A row already marked Remove is not
      access and is left alone. Returns @{ rows = @(...); missing = @(tags with no stored row) }.
    #>
    param([Parameter(Mandatory)]$Item, [string[]]$Tags = @(), [object[]]$StoredRows = @())
    $want = @{}; foreach ($t in @($Tags)) { if ("$t".Trim()) { $want["$t".Trim().ToLowerInvariant()] = $true } }
    $names = @{}
    $u = "$(Get-PimArField $Item 'user')".Trim().ToLowerInvariant(); if ($u) { $names[$u] = $true; $names[($u -split '@')[0]] = $true }
    foreach ($ar in @(Get-PimArField $Item 'accessRows')) { $n = "$(Get-PimArField $ar 'username')".Trim().ToLowerInvariant(); if ($n) { $names[$n] = $true } }
    $out = New-Object System.Collections.Generic.List[object]; $found = @{}
    foreach ($r in @($StoredRows)) {
        if ($null -eq $r) { continue }
        $ru = "$(Get-PimArField $r 'Username')".Trim().ToLowerInvariant(); $gt = "$(Get-PimArField $r 'GroupTag')".Trim().ToLowerInvariant()
        if (-not $ru -or -not $want.ContainsKey($gt)) { continue }
        if (-not $names.ContainsKey($ru) -and -not $names.ContainsKey(($ru -split '@')[0])) { continue }
        if ("$(Get-PimArField $r 'Action')" -match '(?i)^remove') { continue }
        $out.Add($r); $found[$gt] = $true
    }
    [pscustomobject]@{ rows = @($out.ToArray()); missing = @($want.Keys | Where-Object { -not $found.ContainsKey($_) } | Sort-Object) }
}

function Add-PimReviewRemovalsToPending {
    <#
      PURE (needs PIM-SharedPending.ps1). Stage the TARGETED REMOVAL of each row in the shared pending-changes document (-Doc,
      the hashtable Update-PimSharedPendingStore hands its -Mutate) for entity PIM-Assignments-Admins, held by -By: a MODIFY
      that sets Action=Remove -- the engine then removes exactly that assignment (in every mode) and deletes the row
      (Complete-PimRemoveRows), the same instruction the grid's "Remove access" stages.
      🔴 2.4.454: 2.4.453 staged the row's DELETION instead. A deleted desired row does not remove anything -- the scheduled
      engine never prunes -- so the membership stayed and only turned into drift (found writing the §78 live case).
      A row already staged as that removal is left as it is; a row another administrator has staged a DIFFERENT change on
      is LOCKED and not touched (§79.13). Returns @{ added = @(keys); already = @(keys); locked = @(@{ key; by }) } -- the
      caller writes the document when 'added' is non-empty.
    #>
    param([Parameter(Mandatory)][hashtable]$Doc, [object[]]$Rows = @(), [Parameter(Mandatory)][string]$By, [datetime]$NowUtc = [datetime]::UtcNow)
    $base = 'PIM-Assignments-Admins'
    $cur = if ($Doc.bases.ContainsKey($base)) { $Doc.bases[$base] } else { @{ version = 0; changes = @() } }
    $changes = New-Object System.Collections.Generic.List[object]; foreach ($c in @($cur.changes)) { if ($c) { $changes.Add($c) } }
    $added = New-Object System.Collections.Generic.List[string]; $already = New-Object System.Collections.Generic.List[string]; $locked = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        $k = Get-PimSharedPendingRowKey -Base $base -Row $r; if (-not $k) { continue }
        $held = @($changes | Where-Object { "$($_.key)".ToLowerInvariant() -eq $k })[0]
        if ($held) {
            if ("$($held.op)" -eq 'modify' -and "$(Get-PimArField $held.row 'Action')" -match '(?i)^remove$') { $already.Add($k) } else { $locked.Add([pscustomobject]@{ key = $k; by = "$($held.by)" }) }
            continue
        }
        $after = [ordered]@{}
        $props = if ($r -is [System.Collections.IDictionary]) { @($r.Keys) } else { @($r.PSObject.Properties | ForEach-Object Name) }
        foreach ($pn in $props) { $after["$pn"] = Get-PimArField $r "$pn" }
        $after['Action'] = 'Remove'
        $ch = ConvertTo-PimSharedPendingChange ([ordered]@{ key = $k; op = 'modify'; row = $after; before = $r; by = $By; atUtc = $NowUtc.ToUniversalTime().ToString('o') })
        if ($ch) { $changes.Add($ch); $added.Add($k) }
    }
    if ($added.Count) { $Doc.bases[$base] = @{ version = [int]$cur.version + 1; changes = @($changes.ToArray()) } }
    [pscustomobject]@{ added = @($added.ToArray()); already = @($already.ToArray()); locked = @($locked.ToArray()) }
}

function Get-PimReviewCampaignStep {
    <#
      PURE. What the job does with one OPEN campaign now:
        'close'    -- every person is decided (outcomes applied)
        'remind'   -- past due, items open, a reminder is due (every remindEveryDays, up to 'reminders')
        'escalate' -- past due, the reminders are spent and the last interval has passed: alert mail + close (undecided keep)
        'wait'     -- nothing to do yet
    #>
    param([Parameter(Mandatory)]$Campaign, [datetime]$NowUtc = [datetime]::UtcNow)
    $pending = @($Campaign.items | Where-Object { (Get-PimReviewItemState -Campaign $Campaign -Item $_).state -eq 'pending' })
    if (-not $pending.Count) { return 'close' }
    $now = $NowUtc.ToUniversalTime(); $due = ConvertTo-PimUtcDate $Campaign.dueUtc
    if (-not $due -or $now -lt $due) { return 'wait' }
    $every = [math]::Max(1, [int]$Campaign.remindEveryDays); $sent = [int]$Campaign.remindersSent
    $last = ConvertTo-PimUtcDate $Campaign.lastReminderUtc
    $next = if ($last) { $last.AddDays($every) } else { $due }
    if ($now -lt $next) { return 'wait' }
    if ($sent -lt [int]$Campaign.reminders) { return 'remind' }
    return 'escalate'
}

# ---------------------------------------------------------------------------------------------------------------------
# the job
# ---------------------------------------------------------------------------------------------------------------------
function Read-PimArSetting { param([string]$Cs, [string]$Name) $v = Get-PimSqlSetting -ConnectionString $Cs -Name $Name; if ($v -is [string] -and "$v".Trim()) { return ($v | ConvertFrom-Json) }; return $v }

function Invoke-PimAccessReviewCycleJob {
    <# The job: no-owner escalation, then start what is due, remind / escalate / close what is open. #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $cs = $null
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
    if (-not $cs) { throw '[access-review-cycle] no SQL store -- the review rules and the departments cannot be read' }
    $deptRows = @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Departments' | ForEach-Object { [pscustomobject]@{ Department = "$(if ($_.Department) { $_.Department } else { $_.Name })".Trim(); Owners = "$($_.Owners)" } } | Where-Object { $_.Department })
    $admins = @(Get-PimSqlRows -ConnectionString $cs -Entity 'Account-Definitions-Admins')
    # Departments WITHOUT an owner escalate to the alert mail, DAILY while it lasts -- before the Pro / rules checks.
    $noOwner = @(Get-PimDepartmentsWithoutOwner -Departments $deptRows -Groups @($admins | ForEach-Object { [pscustomobject]@{ Department = "$($_.Department)" } }))
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
        return [pscustomobject]@{ ran = $false; skipped = $true; whatIf = [bool]$WhatIf; detail = ('access-review-cycle: access reviews are not enabled or not licensed (Pro) -- nothing started' + $ownerNote) }
    }
    $rules = Read-PimArSetting $cs 'AccessReviewRules'
    # CAS: the Manager records decisions into the same document -- read the RAW text, write only if it is unchanged.
    $rawCamp = Get-PimSqlSettingRaw -ConnectionString $cs -Name 'AccessReviewCampaigns'
    $store = if ("$rawCamp".Trim()) { $rawCamp | ConvertFrom-Json } else { $null }
    $campaigns = New-Object System.Collections.Generic.List[object]; foreach ($c in @(Get-PimArField $store 'campaigns')) { if ($c) { $campaigns.Add($c) } }
    $assign = @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Assignments-Admins')
    $owners = @{}; foreach ($r in $deptRows) { $owners[$r.Department.ToLowerInvariant()] = @("$($r.Owners)" -split '[,;\s]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $log = New-Object System.Collections.Generic.List[string]; $errors = New-Object System.Collections.Generic.List[string]; $changed = $false
    $portal = "$(if (Get-Command Resolve-PimManagerMailUrl -ErrorAction SilentlyContinue) { try { Resolve-PimManagerMailUrl } catch { '' } })"
    # A reviewer who is an ADMIN ACCOUNT has no mailbox of its own: its review mail goes where PIM sends all mail about that
    # account (Get-PimAdminMailRecipientPlan: MailForwardAddress, else its department's owners). Anyone else: their own address.
    $deptOwnerStr = @{}; foreach ($k in @($owners.Keys)) { $deptOwnerStr[$k] = (@($owners[$k]) -join '|') }
    $mailTargets = { param($reviewer)
        $row = @($admins | Where-Object { "$($_.UserName)$($_.Username)".Trim().ToLowerInvariant() -eq "$reviewer".Trim().ToLowerInvariant() -or "$($_.UserPrincipalName)".Trim().ToLowerInvariant() -eq "$reviewer".Trim().ToLowerInvariant() })[0]
        if ($row -and (Get-Command Get-PimAdminMailRecipientPlan -ErrorAction SilentlyContinue)) {
            try { $pl = Get-PimAdminMailRecipientPlan -Row $row -DepartmentOwners $deptOwnerStr; $rc = @(@($pl.recipients) | Where-Object { "$_".Trim() }); if ($rc.Count) { return $rc } } catch { }
        }
        return @("$reviewer") }
    $mail = { param($reviewer, $title, $body) foreach ($to in @(& $mailTargets $reviewer)) { & $mailOne $to $title $body } }
    $mailOne = { param($to, $title, $body)
        if ($WhatIf -or -not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) { return }
        $tok = @{ AlertTitle = $title; AlertEvent = 'owner-review'; AlertDetail = $body; PortalTab = 'owner'; TenantName = "$($global:PIM_TenantName)"; Instance = 'scheduler'; WhenUtc = $NowUtc.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' }
        try { [void](Send-PimNotifyMail -Type 'alert-notice' -Tokens $tok -Recipient $to) } catch { $errors.Add("mail to $to failed: $($_.Exception.Message)") } }
    $enc = { param($x) [System.Net.WebUtility]::HtmlEncode("$x") }
    # 1. OPEN campaigns: close / remind / escalate
    foreach ($c in @($campaigns | Where-Object { "$($_.status)" -eq 'open' })) {
        $step = Get-PimReviewCampaignStep -Campaign $c -NowUtc $NowUtc
        if ($step -eq 'wait') { continue }
        $pendingItems = @($c.items | Where-Object { (Get-PimReviewItemState -Campaign $c -Item $_).state -eq 'pending' })
        if ($step -eq 'remind') {
            $to = @($pendingItems | ForEach-Object { (Get-PimReviewItemState -Campaign $c -Item $_).awaiting } | Select-Object -Unique)
            foreach ($r in $to) { & $mail $r ("Reminder {0} of {1}: please review access in {2}" -f ([int]$c.remindersSent + 1), $c.reminders, $c.department) ("The access review of <b>$(& $enc $c.department)</b> is overdue: $($pendingItems.Count) person(s) still wait for your decision. Open My people and decide Keep or Remove for each.") }
            if (-not $WhatIf) { $c.remindersSent = [int]$c.remindersSent + 1; $c.lastReminderUtc = $NowUtc.ToUniversalTime().ToString('o'); $changed = $true }
            $log.Add("$($c.department): reminder $($c.remindersSent) sent to $($to -join ', ')"); continue
        }
        if ($step -eq 'escalate') {
            $undecidedRemove = ("$($c.undecided)" -eq 'remove')
            $raiseFailed = $false
            if ($undecidedRemove -and -not $WhatIf) {
                # remove-on-undecided: the SAME gate as a reviewer's Remove -- an offboard approval request, never a direct
                # removal. One per person: a request already pending for them (an earlier run whose write lost the race) is reused.
                foreach ($it in $pendingItems) {
                    try {
                        $open = @(); try { $open = @(Get-PimApprovalRequests -Status Pending -Action offboard -Target "$($it.user)") } catch { $open = @() }
                        if ($open.Count) { $it | Add-Member -NotePropertyName approvalId -NotePropertyValue "$($open[0].id)" -Force; continue }
                        if (-not (Get-Command Add-PimApprovalRequest -ErrorAction SilentlyContinue)) { throw 'the approval library is not loaded in this host' }
                        $apr = Add-PimApprovalRequest -Requestor 'access-review-cycle' -Action 'offboard' -Target "$($it.user)" -Justification ("access review {0} ({1}) was not answered -- the rule removes undecided people" -f $c.id, $c.department)
                        $it | Add-Member -NotePropertyName approvalId -NotePropertyValue "$($apr.id)" -Force
                    } catch { $raiseFailed = $true; $errors.Add("$($c.department): the removal request for $($it.user) could not be raised: $($_.Exception.Message)") }
                }
            }
            # a removal request that could not be raised keeps the campaign OPEN: the next run escalates again (and says so loudly)
            if ($raiseFailed) { $log.Add("$($c.department): stays open -- a removal request could not be raised"); continue }
            if (-not $WhatIf -and (Get-Command Send-PimJobAlertViaNotify -ErrorAction SilentlyContinue)) {
                $lines = @($pendingItems | ForEach-Object { '&bull; <b>' + (& $enc $_.user) + '</b> -- waiting for ' + (& $enc (@((Get-PimReviewItemState -Campaign $c -Item $_).awaiting) -join ', ')) })
                $what = if ($undecidedRemove) { 'This review''s rule REMOVES undecided people: an offboard approval request was raised for each of them -- a PIM administrator approves or denies it on the Approvals tab.' } else { 'Undecided people KEEP their access; a SuperAdmin can still decide on the Access reviews page.' }
                try { [void](Send-PimJobAlertViaNotify -Event 'coverage' -Title ("Access review of {0} not answered ({1} person(s))" -f $c.department, $pendingItems.Count) -Detail ("The reviewers did not answer after $($c.reminders) reminder(s). $what<br><br>" + ($lines -join '<br>')) -LinkTab $(if ($undecidedRemove) { 'approvals' } else { 'accessreview' }) -DebounceMinutes 0 `
                                -Headline 'An access review was not answered.' -Action $(if ($undecidedRemove) { 'Open Approvals: approve or deny the removal of each undecided person.' } else { 'Open Access reviews: decide the open people yourself, or follow up with the reviewers.' })) } catch { $errors.Add("$($c.department): the escalation could not be sent: $($_.Exception.Message)") }
            }
            if (-not $WhatIf) { $c.escalatedUtc = $NowUtc.ToUniversalTime().ToString('o'); $step = 'close'; $c.closeReason = $(if ($undecidedRemove) { 'escalated: removal requested for the undecided people' } else { 'escalated: undecided people keep their access' }) }
            $log.Add("$($c.department): escalated to the alert mail ($($pendingItems.Count) undecided -> $(if ($undecidedRemove) { 'removal requested' } else { 'keep' }))")
        }
        if ($step -eq 'close' -and -not $WhatIf) {
            foreach ($it in @($c.items)) {
                $s = Get-PimReviewItemState -Campaign $c -Item $it
                $it.outcome = $(if ($s.state -eq 'pending') { $(if ("$($c.undecided)" -eq 'remove') { 'remove (undecided)' } else { 'keep (undecided)' }) } else { $s.state })
                if ($s.state -eq 'remove') { $it | Add-Member -NotePropertyName removeAccess -NotePropertyValue @($s.removeAccess) -Force }
                # a Remove outcome already raised its offboard approval request (or staged its membership removals) when it
                # was decided (the Manager, like My people)
            }
            $c.status = 'closed'; $c.closedUtc = $NowUtc.ToUniversalTime().ToString('o'); if (-not $c.closeReason) { $c.closeReason = 'every person decided' }; $changed = $true
            $log.Add("$($c.department): closed -- $(@($c.items | Where-Object { "$($_.outcome)" -like 'remove*' }).Count) removal request(s)")
        }
    }
    # 2. START what is due (one open campaign per department at a time)
    $depts = @($deptRows | ForEach-Object { $_.Department }) + @($admins | ForEach-Object { "$($_.Department)".Trim() } | Where-Object { $_ })
    foreach ($d in @($depts | Sort-Object -Unique)) {
        $rule = $null
        try { $rule = Resolve-PimDepartmentReviewRule -Rules $rules -Department $d } catch { $errors.Add("$($d): rule invalid: $($_.Exception.Message)"); continue }
        if (-not $rule) { continue }
        $mine = @($campaigns | Where-Object { "$($_.department)".ToLowerInvariant() -eq $d.ToLowerInvariant() })
        if (@($mine | Where-Object { "$($_.status)" -eq 'open' }).Count) { continue }
        $last = @($mine | ForEach-Object { ConvertTo-PimUtcDate $_.startedUtc } | Sort-Object -Descending | Select-Object -First 1)
        if ($last.Count -and ($NowUtc.ToUniversalTime() - $last[0]).TotalDays -lt $rule.cadenceDays) { continue }
        # §100.28: the department owners ALWAYS review (the rule's reviewers join them) unless the rule says reviewersOnly.
        $rev = @((Get-PimEffectiveReviewers -Rule $rule -Owners @($owners[$d.ToLowerInvariant()])).reviewers)
        if (-not $rev.Count) { $log.Add("$($d): not started -- no reviewer (the rule names none and the department has no owner)"); continue }
        if ($rule.approvers -eq 2 -and $rev.Count -lt 2) { $log.Add("$($d): not started -- the rule needs 2 approvers and names 1"); continue }
        $people = @(Get-PimDepartmentReviewPeople -Department $d -Admins $admins -Assignments $assign)
        if (-not $people.Count) { continue }
        $c = New-PimReviewCampaign -Department $d -Rule $rule -Reviewers $rev -People $people -NowUtc $NowUtc
        if (-not $WhatIf) { $campaigns.Add($c); $changed = $true }
        foreach ($r in @($c.reviewers)) { & $mail $r ("Please review access in {0} ({1} person(s))" -f $d, $people.Count) ("You review the privileged access of <b>$(& $enc $d)</b>. For each person open My people and choose <b>Keep</b> if they still need it or <b>Remove</b> if not, by $(([datetime](ConvertTo-PimUtcDate $c.dueUtc)).ToString('yyyy-MM-dd')). $(if ($c.approvers -eq 2) { "Two approvers review ($($c.mode))." })$(if ($portal) { "<br><br>$(& $enc $portal)" })") }
        $log.Add("$($d): started ($($people.Count) person(s), reviewers $($c.reviewers -join ', '))")
    }
    if ($changed) {
        # keep the last 200 campaigns (closed ones age out first)
        $keep = @($campaigns | Sort-Object @{ Expression = { "$($_.status)" -eq 'open' }; Descending = $true }, @{ Expression = { "$($_.startedUtc)" }; Descending = $true } | Select-Object -First 200)
        $n = Set-PimSqlSettingIfUnchanged -ConnectionString $cs -Name 'AccessReviewCampaigns' -NewValueJson ([pscustomobject]@{ campaigns = @($keep) } | ConvertTo-Json -Depth 12 -Compress) -ExpectedValueJson $rawCamp
        if ([int]$n -lt 1) { $log.Clear(); $log.Add('a reviewer decided while this run worked -- nothing written; the next run repeats it') }
    }
    $detail = "access-review-cycle: " + $(if ($log.Count) { $log -join '; ' } else { 'nothing due' }) + $ownerNote
    if ($errors.Count) { throw ("[access-review-cycle] $detail -- " + ($errors -join '; ')) }
    return [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf; detail = $(if ($WhatIf) { "whatif:$detail" } else { $detail }) }
}
