#Requires -Version 5.1
<#
  PIM-PendingReminders.ps1 -- PIM REQUIREMENTS 100.57 (owner 2026-10-10, via Invardia: "customer must also get a reminder to
  super admins if there are pending actions they have to do in get started or approvals ... this comes from the solution,
  not invardia").

  WHAT IT DOES
    PIM mails the environment's SuperAdmins whenever something waits on them, ONE mail per cycle listing everything:
      (a) the open REQUIRED Get Started steps (the Manager's recorded status, pim.Settings['GetStartedStatus']);
      (b) pending approvals: policy change sets held by the circuit breaker, maker/checker approval requests (and approved
          offboards nobody queued yet), access requests (RFA) waiting for a decision, guard holds waiting for a release,
          guard releases waiting for a second SuperAdmin, a break-glass account change waiting for a second SuperAdmin, and
          staged changes a second administrator must commit.
    Each item carries a DIRECT link to the exact Get Started step or Approvals / Guards / Access requests entry
    (?tab=getstarted&step=<id>, ?tab=approvals&request=<id>, ?tab=approvals&hold=<code>, ?tab=guards&guard=<id>&scope=<s>,
    ?tab=guards&release=<id>, ?tab=accessrequests&request=<id>, ?tab=emergency, ?tab=save) -- the Manager opens the page and
    scrolls to that entry.

  CADENCE (setting pim.Settings['PendingReminders'], catalog key PendingReminders):
      { enabled = true; approvalsAfterHours = 4; getStartedAfterHours = 24; repeatHours = 24 }
    * the FIRST reminder goes out when an item has waited N hours (approvals: approvalsAfterHours, Get Started:
      getStartedAfterHours). An item's wait counts from its own timestamp (requestedUtc / heldUtc / createdUtc ...) and
      otherwise from the first tick that saw it (state firstSeen).
    * then it REPEATS every repeatHours while anything waits;
    * an item that newly crosses its threshold sends the mail early (it gets its first reminder on time), but never sooner
      than min(approvalsAfterHours, getStartedAfterHours, repeatHours) after the previous mail -- one mail per cycle;
    * it STOPS by itself when nothing waits (the state is cleared, so a new item later gets its first reminder after N h);
    * enabled = false -> silent, nothing read, nothing written.
  DEDUPE across ticks: pim.Settings['PendingRemindersState'] = { firstSeen: { <key>: iso }, lastSentUtc, lastKeys,
    retryAfterUtc, lastResult }. A cycle is CLAIMED with a compare-and-set write BEFORE anything is sent, so two scheduler
    executions can never both send it. A mail held by the email controls (kill switch, feature off, allowlist, no sender =
    a mail-mute environment) is RECORDED as the cycle (lastResult = held: <reason>) and never fails the tick. A real
    delivery failure keeps the previous lastSentUtc and retries after one hour.

  RECIPIENTS (the customer's, never Invardia): the SuperAdmins (pim.Settings['ManagerAccess'] role SuperAdmin + env
    PIM_SuperAdmins) get every item. The alert recipients who are not SuperAdmins keep the Get Started part (MAIL-2 item 8,
    owner 2026-10-09: "not completed get started must be alerted daily by mail to alert emails"); with neither, the admin
    who recorded the Get Started status (installer) gets the Get Started part. Per-recipient Notifications: report
    'get-started' switches the Get Started part off, report 'pending-approvals' the approvals part. One mail per recipient.

  RUN: from the scheduler tick (Invoke-PimSchedulerTick, main instance only), every tick -- no new job. It replaces the
    once-a-day Get Started reminder the daily-summary job used to send (Invoke-PimGetStartedReminder), so a Get Started step
    is never mailed twice; the Get Started helpers in PIM-GetStartedReminder.ps1 are reused, not duplicated.
  PURE planners (items / plan / recipients / HTML / text) + one I/O entry point (Invoke-PimPendingReminder). No az, no
  modules. ASCII only; PS 5.1-safe.
  Test seam: $global:PIM_PendingReminderStore = @{} (setting name -> JSON text) replaces SQL.
#>
Set-StrictMode -Off

if (-not (Get-Command ConvertTo-PimGetStartedStatus -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-GetStartedReminder.ps1') }
if (-not (Get-Command Get-PimAudienceLink -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-MailNotifications.ps1') }
if (-not (Get-Command New-PimMailDocument -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-MailLayout.ps1') }
if (-not (Get-Command Get-PimGuardReleaseCatalog -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PIM-GuardRelease.ps1'))) { . (Join-Path $PSScriptRoot 'PIM-GuardRelease.ps1') }

$script:PimPendingReminderSettingName = 'PendingReminders'
$script:PimPendingReminderStateName = 'PendingRemindersState'
# The Manager's policy-hold panels are keyed by the breaker code (POLICY_HOLD_PROVIDERS in pim-manager.html).
$script:PimPendingReminderPolicyCodes = [ordered]@{ GroupsPolicies = 'GROUP-POLICY-MASS-HOLD'; EntraRolePolicies = 'ENTRA-POLICY-MASS-HOLD'; AzResPolicies = 'AZ-POLICY-MASS-HOLD' }
$script:PimPendingReminderPolicyNouns = @{ GroupsPolicies = 'PIM for Groups policies'; EntraRolePolicies = 'Entra role policies'; AzResPolicies = 'Azure role policies' }

function Get-PimPendingReminderDefaults { [ordered]@{ enabled = $true; approvalsAfterHours = 4; getStartedAfterHours = 24; repeatHours = 24 } }

function Get-PimPendingReminderField {
    param([AllowNull()][object]$Obj, [string]$Name)
    if ($null -eq $Obj -or $Obj -is [string]) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] }; return $null }
    $p = $Obj.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function ConvertFrom-PimPendingReminderJson {
    # PURE. JSON text (possibly double-encoded) / object -> object; '' / invalid -> $null.
    param([AllowNull()][object]$Raw)
    $v = $Raw
    for ($i = 0; $i -lt 2 -and $v -is [string]; $i++) { if ("$v".Trim()) { try { $v = $v | ConvertFrom-Json } catch { $v = $null } } else { $v = $null } }
    return $v
}

function ConvertTo-PimPendingReminderUtc {
    # PURE. A stamp ([datetime] or ISO text) -> UTC [datetime], or $null when nothing parses.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return ([datetime]$Value).ToUniversalTime() }
    $s = "$Value".Trim().Trim('"')
    if (-not $s) { return $null }
    $dt = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dt)) { return $dt.ToUniversalTime() }
    return $null
}

function ConvertTo-PimPendingReminderConfig {
    <#
      PURE. The stored PendingReminders value -> [ordered]@{ enabled; approvalsAfterHours; getStartedAfterHours; repeatHours }.
      Absent = the defaults (ON -- v1->v2 rule: a reminder that exists is on unless someone switched it off). An explicit
      false / 'off' / 0 switches it off. Hours are whole numbers, clamped: approvals 1-168, Get Started 1-336, repeat 1-168;
      a value that is not a number keeps its default.
    #>
    param([AllowNull()][object]$Raw)
    $d = Get-PimPendingReminderDefaults
    $v = ConvertFrom-PimPendingReminderJson $Raw
    if ($null -eq $v) { return $d }
    $en = Get-PimPendingReminderField $v 'enabled'
    if ($null -ne $en) { $d.enabled = -not (Test-PimMailPrefFalse $en) }
    $num = { param($name, $lo, $hi)
        $x = Get-PimPendingReminderField $v $name
        $n = 0
        if ($null -ne $x -and [int]::TryParse("$x".Trim(), [ref]$n)) { $d[$name] = [Math]::Min($hi, [Math]::Max($lo, $n)) }
    }
    & $num 'approvalsAfterHours' 1 168
    & $num 'getStartedAfterHours' 1 336
    & $num 'repeatHours' 1 168
    return $d
}

function ConvertTo-PimPendingReminderState {
    # PURE. The stored state -> [ordered]@{ firstSeen = [ordered]@{ key = iso }; lastSentUtc; lastKeys; retryAfterUtc; lastResult }.
    param([AllowNull()][object]$Raw)
    $v = ConvertFrom-PimPendingReminderJson $Raw
    $st = [ordered]@{ firstSeen = [ordered]@{}; lastSentUtc = ''; lastKeys = @(); retryAfterUtc = ''; lastResult = '' }
    if ($null -eq $v) { return $st }
    $fs = Get-PimPendingReminderField $v 'firstSeen'
    if ($fs -is [System.Collections.IDictionary]) { foreach ($k in @($fs.Keys)) { $t = ConvertTo-PimPendingReminderUtc $fs[$k]; if ($t) { $st.firstSeen["$k"] = $t.ToString('o') } } }
    elseif ($fs) { foreach ($p in $fs.PSObject.Properties) { $t = ConvertTo-PimPendingReminderUtc $p.Value; if ($t) { $st.firstSeen["$($p.Name)"] = $t.ToString('o') } } }
    $ls = ConvertTo-PimPendingReminderUtc (Get-PimPendingReminderField $v 'lastSentUtc'); if ($ls) { $st.lastSentUtc = $ls.ToString('o') }
    $ra = ConvertTo-PimPendingReminderUtc (Get-PimPendingReminderField $v 'retryAfterUtc'); if ($ra) { $st.retryAfterUtc = $ra.ToString('o') }
    $st.lastKeys = @(@(Get-PimPendingReminderField $v 'lastKeys') | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
    $st.lastResult = "$(Get-PimPendingReminderField $v 'lastResult')"
    return $st
}

function Get-PimPendingReminderLink {
    # PURE. The deep link to ONE entry: base/?tab=<tab>&<query> (values URL-encoded), '' when no Manager address is known.
    param([string]$Base, [Parameter(Mandatory)][string]$Tab, [string]$Query = '')
    return "$((Get-PimAudienceLink -Type 'pending-reminder' -Base $Base -LinkTab $Tab -Query $Query).url)"
}

function Get-PimPendingReminderItems {
    <#
      PURE. Everything that waits on a SuperAdmin, as items:
        [pscustomobject]@{ key; kind = get-started | approval; group; title; detail; link; linkLabel; sinceUtc }
      -GetStartedStatus  the recorded Get Started status (only REQUIRED, not done, not skipped steps are items)
      -Sources           @{ policyHolds; approvals; offboardApproved; rfa; guardHolds; guardReleases; breakGlass; staged }
                         (Get-PimPendingReminderSources builds it from the store; tests pass it directly)
      -PortalBase        the Manager address (the links are '' without it)
    #>
    param([AllowNull()][object]$GetStartedStatus, [AllowNull()][object]$Sources, [string]$PortalBase = '')
    $out = New-Object System.Collections.Generic.List[object]
    $f = { param($o, $n) Get-PimPendingReminderField $o $n }
    $add = { param($key, $kind, $group, $title, $detail, $tab, $query, $label, $since)
        $out.Add([pscustomobject][ordered]@{ key = "$key"; kind = $kind; group = $group; title = "$title"; detail = "$detail"
            link = (Get-PimPendingReminderLink -Base $PortalBase -Tab $tab -Query $query); linkLabel = $label
            sinceUtc = $(if ($since) { $t = ConvertTo-PimPendingReminderUtc $since; if ($t) { $t.ToString('o') } else { '' } } else { '' }) }) }

    # (a) Get Started: the required steps still open (ConvertTo-PimGetStartedStatus is the one reader of that record).
    if ($null -ne $GetStartedStatus) {
        $gs = ConvertTo-PimGetStartedStatus $GetStartedStatus
        foreach ($s in @($gs.steps | Where-Object { $_.required -and -not $_.done -and -not $_.deferred })) {
            $t = if ($s.title) { $s.title } else { $s.id }
            & $add "gs:$($s.id)" 'get-started' 'Get Started' $t $(if ($s.what) { $s.what } else { $s.note }) 'getstarted' "step=$($s.id)" "Open $t" ''
        }
    }
    if ($null -eq $Sources) { return @($out.ToArray()) }

    # (b) policy change sets held by the circuit breaker (an Admin approves them on Approvals)
    foreach ($h in @(& $f $Sources 'policyHolds')) {
        if ($null -eq $h) { continue }
        $prov = "$(& $f $h 'provider')"; $code = "$(& $f $h 'code')"
        if (-not $code -and $script:PimPendingReminderPolicyCodes.Contains($prov)) { $code = $script:PimPendingReminderPolicyCodes[$prov] }
        if ($code -notmatch '^[A-Z0-9-]{3,40}$') { continue }
        $noun = if ($script:PimPendingReminderPolicyNouns.ContainsKey($prov)) { $script:PimPendingReminderPolicyNouns[$prov] } else { "$prov policies" }
        $n = "$(& $f $h 'changes')"; $w = "$(& $f $h 'weakening')"
        $plan = "$(& $f $h 'planHash')"; $short = if ($plan.Length -gt 12) { $plan.Substring(0, 12) } else { $plan }
        & $add "policy:$code`:$short" 'approval' 'Policy change sets' ("Policy change set held: {0}" -f $noun) `
            ("{0} change(s){1} -- nothing is written until an Admin approves it" -f $(if ($n) { $n } else { '?' }), $(if ($w -and $w -ne '0') { ", $w weaken a setting" } else { '' })) `
            'approvals' "hold=$code" 'Review the change set' (& $f $h 'heldUtc')
    }
    # maker/checker approval requests (a different Admin decides them)
    foreach ($a in @(& $f $Sources 'approvals')) {
        if ($null -eq $a) { continue }
        $id = "$(& $f $a 'id')"; if ($id -notmatch '^[A-Za-z0-9._-]{1,80}$') { continue }
        & $add "approval:$id" 'approval' 'Approval requests' ("{0}: {1}" -f "$(& $f $a 'action')", "$(& $f $a 'target')") `
            ("Requested by {0} -- waiting for a second administrator" -f "$(& $f $a 'requestor')") 'approvals' "request=$id" 'Decide the request' (& $f $a 'requestedUtc')
    }
    foreach ($a in @(& $f $Sources 'offboardApproved')) {
        if ($null -eq $a) { continue }
        $id = "$(& $f $a 'id')"; if ($id -notmatch '^[A-Za-z0-9._-]{1,80}$') { continue }
        & $add "offboard:$id" 'approval' 'Approval requests' ("Offboard approved, not queued: {0}" -f "$(& $f $a 'target')") `
            'Approved but not handed to the engine yet -- press Queue offboard for the engine' 'approvals' "request=$id" 'Queue the offboard' (& $f $a 'decidedUtc')
    }
    # access requests (RFA) waiting for a department Owner / an Admin
    foreach ($r in @(& $f $Sources 'rfa')) {
        if ($null -eq $r) { continue }
        $id = "$(& $f $r 'id')"; if ($id -notmatch '^[A-Za-z0-9._-]{1,80}$') { continue }
        $dep = "$(& $f $r 'department')"
        & $add "rfa:$id" 'approval' 'Access requests' ("Access request: {0}" -f "$(& $f $r 'upn')") `
            ("Waiting for a decision{0}" -f $(if ($dep) { " (department $dep)" } else { '' })) 'accessrequests' "request=$id" 'Decide the access request' (& $f $r 'requestedUtc')
    }
    # guards holding a plan (a SuperAdmin releases it) and releases waiting for a second SuperAdmin
    foreach ($g in @(& $f $Sources 'guardHolds')) {
        if ($null -eq $g) { continue }
        $gid = "$(& $f $g 'guardId')"; $sc = "$(& $f $g 'scope')"
        if ($gid -notmatch '^[a-z0-9][a-z0-9.-]{0,99}$') { continue }
        $plan = "$(& $f $g 'planHash')"; $short = if ($plan.Length -gt 12) { $plan.Substring(0, 12) } else { $plan }
        $q = "guard=$gid" + $(if ($sc -match '^[A-Za-z0-9._-]{1,80}$') { "&scope=$sc" } else { '' })
        & $add "guard:$gid|$sc|$short" 'approval' 'Guards' ("Guard holding a plan: {0}{1}" -f $gid, $(if ($sc) { " / $sc" } else { '' })) `
            ("{0} item(s) held -- the engine skips them until a SuperAdmin releases this plan or it changes" -f "$(& $f $g 'count')") 'guards' $q 'Review and release' (& $f $g 'firstSeenUtc')
    }
    foreach ($g in @(& $f $Sources 'guardReleases')) {
        if ($null -eq $g) { continue }
        $id = "$(& $f $g 'id')"; if ($id -notmatch '^[A-Za-z0-9._-]{1,80}$') { continue }
        & $add "guardrel:$id" 'approval' 'Guards' ("Guard release waiting for a second SuperAdmin: {0}" -f "$(& $f $g 'guardId')") `
            ("Released by {0} -- a different SuperAdmin approves it" -f "$(& $f $g 'createdBy')") 'guards' "release=$id" 'Approve or revoke the release' (& $f $g 'createdUtc')
    }
    $bg = & $f $Sources 'breakGlass'
    if ($bg) {
        $id = "$(& $f $bg 'id')"
        & $add "breakglass:$id" 'approval' 'Break-glass' 'Break-glass account change waiting for a second SuperAdmin' `
            ("Raised by {0}" -f $(if ("$(& $f $bg 'maker')".Trim()) { "$(& $f $bg 'maker')" } else { 'an administrator' })) 'emergency' '' 'Review the break-glass change' (& $f $bg 'createdUtc')
    }
    foreach ($s in @(& $f $Sources 'staged')) {
        if ($null -eq $s) { continue }
        $by = "$(& $f $s 'by')".Trim().ToLowerInvariant(); if (-not $by) { continue }
        & $add "staged:$by" 'approval' 'Staged changes' ("{0} staged change(s) by {1}" -f "$(& $f $s 'count')", $by) `
            'A second administrator must commit them (second approver)' 'save' '' 'Review and commit' (& $f $s 'oldestUtc')
    }
    return @($out.ToArray())
}

function Get-PimPendingReminderPlan {
    <#
      PURE. Should the reminder go out NOW? Returns
        @{ send; reason; items (every current item + waitedHours + ripe); ripe; state (the new state); stateChanged; dueBy }
      -Items   Get-PimPendingReminderItems   -State   the stored PendingRemindersState   -Config   ConvertTo-PimPendingReminderConfig
      The rules are in the file header (first after N h, repeat, early for a newly ripe item with a floor, stop, off = silent).
    #>
    param([object[]]$Items = @(), [AllowNull()][object]$State, [AllowNull()][object]$Config, [datetime]$NowUtc = [datetime]::UtcNow)
    $cfg = if ($Config -is [System.Collections.IDictionary] -and $Config.Contains('repeatHours')) { $Config } else { ConvertTo-PimPendingReminderConfig $Config }
    $st = ConvertTo-PimPendingReminderState $State
    $now = $NowUtc.ToUniversalTime()
    $nowIso = $now.ToString('o')
    $plan = [ordered]@{ send = $false; reason = ''; items = @(); ripe = @(); state = $st; stateChanged = $false; dueBy = '' }
    if (-not $cfg.enabled) { $plan.reason = 'switched off (Settings > Mail & alerting > Reminders: what waits on you)'; return [pscustomobject]$plan }

    $list = @($Items | Where-Object { $_ -and "$($_.key)".Trim() })
    $newFirst = [ordered]@{}
    $annotated = foreach ($it in $list) {
        $k = "$($it.key)"
        $cands = @()
        $a = ConvertTo-PimPendingReminderUtc $it.sinceUtc; if ($a -and $a -le $now) { $cands += $a }
        if ($st.firstSeen.Contains($k)) { $b = ConvertTo-PimPendingReminderUtc $st.firstSeen[$k]; if ($b -and $b -le $now) { $cands += $b } }
        $since = if ($cands.Count) { ($cands | Sort-Object | Select-Object -First 1) } else { $now }
        $newFirst[$k] = $since.ToString('o')
        $thr = if ("$($it.kind)" -eq 'get-started') { [int]$cfg.getStartedAfterHours } else { [int]$cfg.approvalsAfterHours }
        $w = ($now - $since).TotalHours
        $c = [pscustomobject][ordered]@{}; foreach ($p in $it.PSObject.Properties) { $c | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value }
        $c | Add-Member -NotePropertyName waitedHours -NotePropertyValue ([Math]::Round($w, 2)) -Force
        $c | Add-Member -NotePropertyName ripe -NotePropertyValue ([bool]($w -ge $thr)) -Force
        $c | Add-Member -NotePropertyName firstReminderUtc -NotePropertyValue ($since.AddHours($thr).ToString('o')) -Force
        $c
    }
    $annotated = @($annotated)
    $ripe = @($annotated | Where-Object { $_.ripe })
    $plan.items = $annotated; $plan.ripe = $ripe

    $sameFirst = ((@($st.firstSeen.Keys) | Sort-Object) -join '|') -eq ((@($newFirst.Keys) | Sort-Object) -join '|')
    if ($sameFirst) { foreach ($k in @($newFirst.Keys)) { if ("$($st.firstSeen[$k])" -ne "$($newFirst[$k])") { $sameFirst = $false; break } } }

    if (-not $annotated.Count) {
        # Nothing waits: STOP by itself. The state is cleared, so a new item later gets its first reminder after N hours.
        $plan.reason = 'nothing waits on a SuperAdmin -- no mail'
        $clean = [ordered]@{ firstSeen = [ordered]@{}; lastSentUtc = ''; lastKeys = @(); retryAfterUtc = ''; lastResult = $st.lastResult }
        $plan.stateChanged = [bool]($st.firstSeen.Count -or "$($st.lastSentUtc)" -or @($st.lastKeys).Count -or "$($st.retryAfterUtc)")
        $plan.state = $clean
        return [pscustomobject]$plan
    }
    $next = [ordered]@{ firstSeen = $newFirst; lastSentUtc = $st.lastSentUtc; lastKeys = @($st.lastKeys); retryAfterUtc = $st.retryAfterUtc; lastResult = $st.lastResult }
    $plan.state = $next; $plan.stateChanged = -not $sameFirst
    if (-not $ripe.Count) {
        $first = @($annotated | Sort-Object { "$($_.firstReminderUtc)" } | Select-Object -First 1)
        $plan.dueBy = "$($first[0].firstReminderUtc)"
        $plan.reason = ("{0} item(s) waiting, none long enough yet -- the first reminder goes out at {1} (approvals after {2} h, Get Started after {3} h)" -f $annotated.Count, $plan.dueBy, $cfg.approvalsAfterHours, $cfg.getStartedAfterHours)
        return [pscustomobject]$plan
    }
    $retry = ConvertTo-PimPendingReminderUtc $st.retryAfterUtc
    if ($retry -and $now -lt $retry) {
        $plan.dueBy = $retry.ToString('o')
        $plan.reason = ("the last send failed -- retrying after {0}" -f $plan.dueBy)
        return [pscustomobject]$plan
    }
    $last = ConvertTo-PimPendingReminderUtc $st.lastSentUtc
    $why = ''
    if (-not $last) { $why = ("first reminder: {0} item(s) waited long enough" -f $ripe.Count) }
    else {
        $since = ($now - $last).TotalHours
        $floor = [Math]::Min([Math]::Min([int]$cfg.approvalsAfterHours, [int]$cfg.getStartedAfterHours), [int]$cfg.repeatHours)
        $newRipe = @($ripe | Where-Object { @($st.lastKeys) -notcontains "$($_.key)" })
        if ($since -ge [int]$cfg.repeatHours) { $why = ("repeat: the last reminder went out {0:N1} h ago (every {1} h)" -f $since, $cfg.repeatHours) }
        elseif ($newRipe.Count -and $since -ge $floor) { $why = ("{0} new item(s) waited long enough since the last reminder ({1:N1} h ago)" -f $newRipe.Count, $since) }
        else {
            $plan.dueBy = $last.AddHours([int]$cfg.repeatHours).ToString('o')
            $plan.reason = ("already reminded at {0} -- the next reminder goes out at {1}{2}" -f $last.ToString('o'), $plan.dueBy, $(if ($newRipe.Count) { " (a new item waits for the $floor h floor)" } else { '' }))
            return [pscustomobject]$plan
        }
    }
    $next.lastSentUtc = $nowIso
    $next.lastKeys = @($annotated | ForEach-Object { "$($_.key)" })
    $next.retryAfterUtc = ''
    $plan.state = $next; $plan.stateChanged = $true; $plan.send = $true
    $plan.reason = $why
    return [pscustomobject]$plan
}

function Get-PimPendingReminderRecipients {
    <#
      PURE. Who gets which part. Returns @( [pscustomobject]@{ address; role = superadmin | alert | installer; items } ),
      one per address that has at least one item. SuperAdmins get everything (minus what their Notifications switch off);
      alert recipients who are not SuperAdmins get the Get Started part; with neither, the installer gets the Get Started
      part. Customer addresses only (Test-PimCustomerRecipient: never Invardia).
    #>
    param([object[]]$Items = @(), [string[]]$SuperAdmins = @(), [string[]]$AlertRecipients = @(), [string]$Installer = '', [AllowNull()][object]$Prefs)
    $norm = ConvertTo-PimMailNotificationPrefs $Prefs
    $gsItems = @($Items | Where-Object { $_ -and "$($_.kind)" -eq 'get-started' })
    $apItems = @($Items | Where-Object { $_ -and "$($_.kind)" -ne 'get-started' })
    $clean = { param($list) @(@($list) | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { "$_".Trim() } | Where-Object { Test-PimCustomerRecipient $_ } | Select-Object -Unique) }
    $sa = & $clean $SuperAdmins
    $saLc = @($sa | ForEach-Object { $_.ToLowerInvariant() })
    $al = @(& $clean $AlertRecipients | Where-Object { $saLc -notcontains $_.ToLowerInvariant() })
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $wants = { param($addr, $type) Test-PimRecipientWants -Pref (Get-PimRecipientNotificationPref -Prefs $norm -Address $addr) -Type $type -Kind 'report' }
    foreach ($a in $sa) {
        $lk = $a.ToLowerInvariant(); if ($seen.ContainsKey($lk)) { continue }; $seen[$lk] = $true
        $mine = @()
        if ($gsItems.Count -and (& $wants $a 'get-started')) { $mine += $gsItems }
        if ($apItems.Count -and (& $wants $a 'pending-approvals')) { $mine += $apItems }
        if ($mine.Count) { $out.Add([pscustomobject]@{ address = $a; role = 'superadmin'; items = @($mine) }) }
    }
    foreach ($a in $al) {
        $lk = $a.ToLowerInvariant(); if ($seen.ContainsKey($lk)) { continue }; $seen[$lk] = $true
        if ($gsItems.Count -and (& $wants $a 'get-started')) { $out.Add([pscustomobject]@{ address = $a; role = 'alert'; items = @($gsItems) }) }
    }
    if (-not $sa.Count -and -not $al.Count -and $gsItems.Count -and (Test-PimCustomerRecipient $Installer) -and (& $wants "$Installer".Trim() 'get-started')) {
        $out.Add([pscustomobject]@{ address = "$Installer".Trim(); role = 'installer'; items = @($gsItems) })
    }
    return @($out.ToArray())
}

function Format-PimPendingReminderWait {
    # PURE. 0.4 -> 'less than an hour', 5.2 -> '5 hours', 50 -> '2 days'.
    param([double]$Hours)
    if ($Hours -lt 1) { return 'less than an hour' }
    if ($Hours -lt 48) { $h = [int][Math]::Floor($Hours); return ("{0} hour{1}" -f $h, $(if ($h -eq 1) { '' } else { 's' })) }
    $d = [int][Math]::Floor($Hours / 24); return ("{0} days" -f $d)
}

function Get-PimPendingReminderGroups {
    # PURE. The items grouped in the order the mail shows them.
    param([object[]]$Items = @())
    $order = @('Get Started', 'Policy change sets', 'Approval requests', 'Access requests', 'Guards', 'Break-glass', 'Staged changes')
    $groups = New-Object System.Collections.Generic.List[object]
    foreach ($g in ($order + @(@($Items | ForEach-Object { "$($_.group)" }) | Where-Object { $order -notcontains $_ } | Select-Object -Unique))) {
        $its = @($Items | Where-Object { $_ -and "$($_.group)" -eq $g })
        if ($its.Count) { $groups.Add([pscustomobject]@{ name = $g; items = $its }) }
    }
    return @($groups.ToArray())
}

function ConvertTo-PimPendingReminderHtml {
    # PURE. The reminder as a designed mail (MAIL-2 layout): tiles first, then one section per group, each item a card with
    # how long it has waited and its own blue button straight to that entry.
    param([object[]]$Items = @(), [string]$PortalBase = '', [hashtable]$Environment = @{}, [hashtable]$Config = $null)
    $cfg = if ($Config) { $Config } else { Get-PimPendingReminderDefaults }
    $b = Get-PimMailBrand; $enc = { param($v) ConvertTo-PimMailText $v }
    $list = @($Items | Where-Object { $_ })
    $gs = @($list | Where-Object { "$($_.kind)" -eq 'get-started' }).Count
    $cnt = { param($g) @($list | Where-Object { "$($_.group)" -eq $g }).Count }
    $appr = (& $cnt 'Policy change sets') + (& $cnt 'Approval requests') + (& $cnt 'Break-glass') + (& $cnt 'Staged changes')
    $tiles = New-PimMailSummaryTiles -Tiles @(
        @{ label = 'Get Started steps'; value = "$gs"; tone = $(if ($gs) { 'danger' } else { 'neutral' }) }
        @{ label = 'Approvals'; value = "$appr"; tone = $(if ($appr) { 'warning' } else { 'neutral' }) }
        @{ label = 'Access requests'; value = "$(& $cnt 'Access requests')"; tone = $(if (& $cnt 'Access requests') { 'warning' } else { 'neutral' }) }
        @{ label = 'Guards'; value = "$(& $cnt 'Guards')"; tone = $(if (& $cnt 'Guards') { 'warning' } else { 'neutral' }) })
    $sum = $tiles + '<p style="font-family:' + $b.font + ';font-size:14px;margin:10px 0 0 0;">These are waiting for a SuperAdmin of this PIM Manager environment. Each one has its own button to the exact place where you act. ' +
           ('This reminder repeats every {0} hours while anything waits, and stops by itself when nothing does.' -f $cfg.repeatHours) + '</p>'
    $body = ''
    foreach ($g in @(Get-PimPendingReminderGroups -Items $list)) {
        $cards = foreach ($it in @($g.items)) {
            $tone = if ("$($it.kind)" -eq 'get-started') { $b.danger } else { $b.warning }
            $wait = if ($it.PSObject.Properties['waitedHours']) { 'Waiting ' + (Format-PimPendingReminderWait ([double]$it.waitedHours)) } else { '' }
            '<div class="pim-pr-item" data-key="' + (& $enc $it.key) + '" style="margin:12px 0;padding:10px 14px;border:1px solid ' + $b.border + ';border-left:4px solid ' + $tone + ';border-radius:6px;font-family:' + $b.font + ';">' +
            '<div style="font-size:15px;font-weight:700;color:' + $b.heading + ';">' + (& $enc $it.title) + '</div>' +
            $(if ("$($it.detail)".Trim()) { '<div style="font-size:13px;color:' + $b.text + ';margin-top:2px;">' + (& $enc $it.detail) + '</div>' } else { '' }) +
            $(if ($wait) { '<div style="font-size:12.5px;color:' + $b.muted + ';margin-top:2px;">' + (& $enc $wait) + '</div>' } else { '' }) +
            (New-PimMailButton -Url "$($it.link)" -Label "$($it.linkLabel)") +
            $(if ("$($it.kind)" -eq 'get-started') { '<div style="font-size:12px;"><a href="' + (& $enc (Get-PimGetStartedDocUrl ($it.key -replace '^gs:', ''))) + '" style="color:' + $b.accent + ';">Documentation</a></div>' } else { '' }) +
            '</div>'
        }
        $body += New-PimMailSection -Title ("{0} ({1})" -f $g.name, @($g.items).Count) -Html (@($cards) -join '')
    }
    $homeUrl = (Get-PimAudienceLink -Type 'home' -Base $PortalBase -LinkTab 'home').url -replace '/\?tab=home$', '/'
    $notif = (Get-PimAudienceLink -Type 'settings' -Base $PortalBase -LinkTab 'settings' -Query 'section=notifications').url
    $first = @($list | Select-Object -First 1)
    return (New-PimMailDocument -Title 'Waiting for you in PIM Manager' -Subtitle ("{0} item(s) wait for a SuperAdmin" -f $list.Count) `
        -Preheader ("{0} item(s) wait for you: {1}" -f $list.Count, ((@($list | Select-Object -First 4 | ForEach-Object { $_.title })) -join '; ')) `
        -SummaryHtml $sum -BodyHtml $body -Button $(if ($first.Count -and "$($first[0].link)") { @{ url = "$($first[0].link)"; label = "$($first[0].linkLabel)" } } else { $null }) `
        -HomeUrl $homeUrl -NotificationsUrl $notif -Environment $Environment)
}

function ConvertTo-PimPendingReminderText {
    # PURE. The plain-text version (the sample in the docs, the log, a client that shows text only).
    param([object[]]$Items = @(), [hashtable]$Config = $null, [string]$EnvironmentName = '')
    $cfg = if ($Config) { $Config } else { Get-PimPendingReminderDefaults }
    $list = @($Items | Where-Object { $_ })
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine(("Waiting for you in PIM Manager{0}" -f $(if ($EnvironmentName) { " ($EnvironmentName)" } else { '' })))
    [void]$sb.AppendLine(("{0} item(s) wait for a SuperAdmin. Each link opens the exact place where you act." -f $list.Count))
    foreach ($g in @(Get-PimPendingReminderGroups -Items $list)) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine(("{0} ({1})" -f $g.name, @($g.items).Count))
        foreach ($it in @($g.items)) {
            $wait = if ($it.PSObject.Properties['waitedHours']) { ' -- waiting ' + (Format-PimPendingReminderWait ([double]$it.waitedHours)) } else { '' }
            [void]$sb.AppendLine(("  * {0}{1}" -f $it.title, $wait))
            if ("$($it.detail)".Trim()) { [void]$sb.AppendLine(("    {0}" -f $it.detail)) }
            if ("$($it.link)".Trim()) { [void]$sb.AppendLine(("    {0}: {1}" -f $it.linkLabel, $it.link)) }
        }
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(("This reminder repeats every {0} hours while anything waits and stops by itself when nothing does." -f $cfg.repeatHours))
    return $sb.ToString()
}

# ---- store (SQL pim.Settings; the test seam is $global:PIM_PendingReminderStore) ------------------------------------
function Get-PimPendingReminderStoreCs {
    try { if (Get-Command Get-PimManagerSettingCs -ErrorAction SilentlyContinue) { $c = Get-PimManagerSettingCs; if ("$c".Trim()) { return "$c" } } } catch { }
    if ("$($global:PIM_EngineSqlCs)".Trim()) { return "$($global:PIM_EngineSqlCs)" }
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $c = Get-PimSqlSettingsConnectionString; if ("$c".Trim()) { return "$c" } } catch { } }
    return $null
}

function Get-PimPendingReminderStoreText {
    # The setting's JSON text as stored, or $null. THROWS only when a configured store fails.
    param([Parameter(Mandatory)][string]$Name)
    if ($global:PIM_PendingReminderStore -is [hashtable]) { $v = $global:PIM_PendingReminderStore[$Name]; if ($null -eq $v) { return $null }; return "$v" }
    $cs = Get-PimPendingReminderStoreCs
    if ($cs -and (Get-Command Get-PimSqlSettingRaw -ErrorAction SilentlyContinue)) { return (Get-PimSqlSettingRaw -ConnectionString $cs -Name $Name) }
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        $v = Get-PimSetting -Name $Name
        if ($null -eq $v) { return $null }
        if ($v -is [string]) { return $v }
        return (ConvertTo-Json -InputObject $v -Depth 10 -Compress)
    }
    return $null
}

function Set-PimPendingReminderStoreText {
    # Write the setting. -Cas: only if the stored text is still -Expected; returns 1 written / 0 lost. THROWS with no store.
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Json, [AllowNull()][string]$Expected, [switch]$Cas)
    if ($global:PIM_PendingReminderStore -is [hashtable]) {
        if ($Cas) { $cur = $global:PIM_PendingReminderStore[$Name]; if ("$cur" -cne "$Expected") { return 0 } }
        $global:PIM_PendingReminderStore[$Name] = $Json; return 1
    }
    $cs = Get-PimPendingReminderStoreCs
    if ($cs -and $Cas -and (Get-Command Set-PimSqlSettingIfUnchanged -ErrorAction SilentlyContinue)) {
        return [int](Set-PimSqlSettingIfUnchanged -ConnectionString $cs -Name $Name -NewValueJson $Json -ExpectedValueJson $Expected)
    }
    if ($cs -and (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) { Set-PimSqlSetting -ConnectionString $cs -Name $Name -ValueJson $Json; return 1 }
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { [void](Set-PimSetting -Name $Name -Value $Json); return 1 }
    throw "no settings store to write '$Name' to"
}

function Get-PimPendingReminderSources {
    <#
      Read what waits from the store -- the SAME rules as the Manager's attention badge (Get-PimManagerAttentionSources):
      an expired approval request waits for nobody; an approved offboard counts for 7 days; a guard hold of a RELEASABLE
      guard counts unless an active / pending release covers that exact plan. Returns @{ ...sources...; errors }.
      Every source is read on its own: one that fails is named in errors and the others still count. NEVER throws.
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $src = [ordered]@{ policyHolds = @(); approvals = @(); offboardApproved = @(); rfa = @(); guardHolds = @(); guardReleases = @(); breakGlass = $null; staged = @(); errors = @() }
    $errs = New-Object System.Collections.Generic.List[string]
    $read = { param($n) ConvertFrom-PimPendingReminderJson (Get-PimPendingReminderStoreText -Name $n) }
    $f = { param($o, $n) Get-PimPendingReminderField $o $n }
    # 1. policy change sets held by the circuit breaker -- the engine's own reader (it drops a stale record)
    try {
        if (Get-Command Get-PimPolicyMassHold -ErrorAction SilentlyContinue) {
            $src.policyHolds = @(foreach ($p in @($script:PimPendingReminderPolicyCodes.Keys)) {
                $h = $null; try { $h = Get-PimPolicyMassHold -Provider $p } catch { $h = $null }
                if (-not ($h -and "$($h.planHash)".Trim())) { continue }
                $a = $null; if (Get-Command Get-PimPolicyMassChangeApproval -ErrorAction SilentlyContinue) { try { $a = Get-PimPolicyMassChangeApproval -Provider $p } catch { $a = $null } }
                if ($a -and "$($a.planHash)".Trim().ToLowerInvariant() -eq "$($h.planHash)".Trim().ToLowerInvariant()) {
                    $exp = ConvertTo-PimPendingReminderUtc $a.expiresUtc
                    if (-not "$($a.expiresUtc)".Trim() -or ($exp -and $exp -gt $now)) { continue }   # approved: waits for the engine, not a person
                }
                [pscustomobject]@{ provider = $p; code = $script:PimPendingReminderPolicyCodes[$p]; changes = "$($h.changes)"; weakening = "$($h.weakening)"; planHash = "$($h.planHash)"; heldUtc = "$($h.heldUtc)" }
            })
        }
    } catch { $errs.Add("policy holds: $($_.Exception.Message)") }
    # 2. maker/checker approval requests (pim.Settings 'ApprovalRequests', a JSON array)
    try {
        $all = @(& $read 'ApprovalRequests') | Where-Object { $_ }
        $ttl = 72; if (Get-Command Get-PimApprovalRequestTtlHours -ErrorAction SilentlyContinue) { try { $ttl = [int](Get-PimApprovalRequestTtlHours) } catch { $ttl = 72 } }
        $src.approvals = @($all | Where-Object { "$(& $f $_ 'status')" -eq 'Pending' } | Where-Object {
                $t = ConvertTo-PimPendingReminderUtc (& $f $_ 'requestedUtc'); $t -and (($now - $t).TotalHours -lt $ttl) } |
            ForEach-Object { [pscustomobject]@{ id = "$(& $f $_ 'id')"; action = "$(& $f $_ 'action')"; target = "$(& $f $_ 'target')"; requestor = "$(& $f $_ 'requestor')"; requestedUtc = "$(& $f $_ 'requestedUtc')" } })
        $cut = $now.AddDays(-7)
        $src.offboardApproved = @($all | Where-Object { "$(& $f $_ 'status')" -eq 'Approved' -and "$(& $f $_ 'action')" -eq 'offboard' -and -not "$(& $f $_ 'executedUtc')".Trim() } | Where-Object {
                $t = ConvertTo-PimPendingReminderUtc (& $f $_ 'decidedUtc'); $t -and $t -ge $cut } |
            ForEach-Object { [pscustomobject]@{ id = "$(& $f $_ 'id')"; target = "$(& $f $_ 'target')"; decidedUtc = "$(& $f $_ 'decidedUtc')" } })
    } catch { $errs.Add("approval requests: $($_.Exception.Message)") }
    # 3. access requests (RFA, Pro) waiting for a decision
    try {
        $rfaOn = $true
        if (Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) { $rfaOn = [bool](Test-PimFeatureAvailable -Key 'rfa.portal' -Quiet) }
        if ($rfaOn) {
            $doc = & $read 'RfaRequests'
            $src.rfa = @(@(& $f $doc 'requests') | Where-Object { $_ -and "$(& $f $_ 'state')" -eq 'pending-approval' } |
                ForEach-Object { [pscustomobject]@{ id = "$(& $f $_ 'id')"; upn = "$(& $f $_ 'upn')"; department = "$(& $f $_ 'department')"; requestedUtc = "$(& $f $_ 'requestedUtc')" } })
        }
    } catch { $errs.Add("access requests: $($_.Exception.Message)") }
    # 4. guards: a hold of a RELEASABLE guard not covered by an active / pending release, and releases waiting for a 2nd person
    try {
        if (Get-Command Get-PimGuardReleaseCatalog -ErrorAction SilentlyContinue) {
            $relKind = @{}; foreach ($g in @(Get-PimGuardReleaseCatalog)) { $relKind["$($g.guardId)".ToLowerInvariant()] = "$($g.release)" }
            $rels = @(@(& $f (& $read 'GuardReleases') 'releases') | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ r = $_; state = (Get-PimGuardReleaseState -Release $_ -NowUtc $now) } })
            $covered = @{}; foreach ($x in @($rels | Where-Object { $_.state -in @('active', 'pending') })) { $covered[("{0}|{1}|{2}" -f "$($x.r.guardId)", "$($x.r.scope)", "$($x.r.planHash)").ToLowerInvariant()] = $true }
            $src.guardHolds = @(@(& $f (& $read 'GuardHolds') 'holds') | Where-Object { $_ -and "$($_.planHash)".Trim() -and $relKind["$($_.guardId)".Trim().ToLowerInvariant()] -eq 'release' -and
                    -not $covered[("{0}|{1}|{2}" -f "$($_.guardId)", "$($_.scope)", "$($_.planHash)").ToLowerInvariant()] } |
                ForEach-Object { [pscustomobject]@{ guardId = "$($_.guardId)".Trim().ToLowerInvariant(); scope = "$($_.scope)"; count = "$($_.count)"; planHash = "$($_.planHash)"; firstSeenUtc = "$($_.firstSeenUtc)" } })
            $src.guardReleases = @($rels | Where-Object { $_.state -eq 'pending' } | ForEach-Object { [pscustomobject]@{ id = "$($_.r.id)"; guardId = "$($_.r.guardId)"; scope = "$($_.r.scope)"; createdBy = "$($_.r.createdBy)"; createdUtc = "$($_.r.createdUtc)" } })
        }
    } catch { $errs.Add("guards: $($_.Exception.Message)") }
    # 5. the break-glass account change waiting for a second SuperAdmin (read only -- the Manager closes an expired one)
    try {
        $bg = & $read 'BreakGlassAccountsChange'
        if ($bg -and "$(& $f $bg 'status')".Trim().ToLowerInvariant() -eq 'pending') {
            $exp = ConvertTo-PimPendingReminderUtc (& $f $bg 'expiresUtc')
            if ($exp -and $now -lt $exp) { $src.breakGlass = [pscustomobject]@{ id = "$(& $f $bg 'id')"; maker = "$(& $f $bg 'maker')"; createdUtc = "$(& $f $bg 'createdUtc')" } }
        }
    } catch { $errs.Add("break-glass request: $($_.Exception.Message)") }
    # 6. staged changes a second administrator must commit (setting PendingSecondApprover: sensitive | all; off = nothing waits)
    try {
        $mode = "$(ConvertFrom-PimPendingReminderJson (Get-PimPendingReminderStoreText -Name 'PendingSecondApprover'))".Trim().ToLowerInvariant()
        if ($mode -in @('sensitive', 'all')) {
            $doc = & $read 'PendingChanges'
            $bases = & $f $doc 'bases'
            $by = [ordered]@{}; $oldest = @{}
            $baseNames = if ($bases -is [System.Collections.IDictionary]) { @($bases.Keys) } elseif ($bases) { @($bases.PSObject.Properties | ForEach-Object { $_.Name }) } else { @() }
            foreach ($bn in $baseNames) {
                foreach ($c in @(& $f (& $f $bases $bn) 'changes')) {
                    if (-not $c) { continue }
                    if ($mode -eq 'sensitive') {
                        $sens = $true   # unknown = sensitive (fail closed), the Manager's rule
                        if (Get-Command Get-PimAuthoringSensitivity -ErrorAction SilentlyContinue) {
                            $r = if ("$(& $f $c 'op')" -eq 'remove') { & $f $c 'before' } else { & $f $c 'row' }
                            try { $sens = [bool](Get-PimAuthoringSensitivity -Action 'review-save' -Base $bn -Rows @([pscustomobject]$r)).sensitive } catch { $sens = $true }
                        }
                        if (-not $sens) { continue }
                    }
                    $who = "$(& $f $c 'by')".Trim().ToLowerInvariant(); if (-not $who) { continue }
                    $by[$who] = 1 + [int]$by[$who]
                    $t = ConvertTo-PimPendingReminderUtc (& $f $c 'atUtc')
                    if ($t -and (-not $oldest.ContainsKey($who) -or $t -lt $oldest[$who])) { $oldest[$who] = $t }
                }
            }
            $src.staged = @($by.Keys | ForEach-Object { [pscustomobject]@{ by = $_; count = $by[$_]; oldestUtc = $(if ($oldest.ContainsKey($_)) { $oldest[$_].ToString('o') } else { '' }) } })
        }
    } catch { $errs.Add("staged changes: $($_.Exception.Message)") }
    $src.errors = @($errs.ToArray())
    return [pscustomobject]$src
}

function Get-PimPendingReminderSuperAdmins {
    # The SuperAdmins' mail addresses: pim.Settings['ManagerAccess'] (role SuperAdmin; its 'mail' when recorded, else the
    # sign-in name) + env PIM_SuperAdmins. NEVER throws.
    $out = New-Object System.Collections.Generic.List[string]
    try {
        $v = ConvertFrom-PimPendingReminderJson (Get-PimPendingReminderStoreText -Name 'ManagerAccess')
        if ($v -and -not ($v -is [array]) -and (Get-PimPendingReminderField $v 'managerAccess')) { $v = Get-PimPendingReminderField $v 'managerAccess' }
        foreach ($e in @($v)) {
            if (-not $e -or "$(Get-PimPendingReminderField $e 'role')".Trim() -ne 'SuperAdmin') { continue }
            $m = "$(Get-PimPendingReminderField $e 'mail')".Trim(); if (-not $m) { $m = "$(Get-PimPendingReminderField $e 'identity')".Trim() }
            if ($m) { $out.Add($m) }
        }
    } catch { Write-Warning "  [Mail] the SuperAdmins could not be read for the pending reminder: $($_.Exception.Message)" }
    foreach ($x in @("$($env:PIM_SuperAdmins)" -split '[,;\s]+')) { if ("$x".Trim()) { $out.Add("$x".Trim()) } }
    return @($out.ToArray() | Select-Object -Unique)
}

function Invoke-PimPendingReminder {
    <#
      The tick's step (Invoke-PimSchedulerTick, every run of the main instance). Reads the setting, the state, what waits,
      plans; when due it CLAIMS the cycle (compare-and-set on PendingRemindersState) and only then sends one
      'pending-actions-reminder' mail per recipient. Returns @{ sent; planned; held; failed; detail; plan }. NEVER throws.
      -WhatIf: plans and renders, sends and writes nothing.
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    try {
        $cfg = ConvertTo-PimPendingReminderConfig (Get-PimPendingReminderStoreText -Name $script:PimPendingReminderSettingName)
        if (-not $cfg.enabled) { return [pscustomobject]@{ sent = 0; planned = $false; held = 0; failed = 0; detail = 'not sent -- the pending-actions reminder is switched off'; plan = $null } }
        $stateRaw = Get-PimPendingReminderStoreText -Name $script:PimPendingReminderStateName
        $gsRaw = Get-PimPendingReminderStoreText -Name 'GetStartedStatus'
        $src = Get-PimPendingReminderSources -NowUtc $NowUtc
        $base = if (Get-Command Get-PimPortalBaseUrl -ErrorAction SilentlyContinue) { Get-PimPortalBaseUrl } else { '' }
        $items = @(Get-PimPendingReminderItems -GetStartedStatus $gsRaw -Sources $src -PortalBase $base)
        $plan = Get-PimPendingReminderPlan -Items $items -State $stateRaw -Config $cfg -NowUtc $NowUtc
        $errTxt = if (@($src.errors).Count) { ' (not read: ' + (@($src.errors) -join '; ') + ')' } else { '' }
        if (-not $plan.send) {
            if ($plan.stateChanged -and -not $WhatIf) {
                try { [void](Set-PimPendingReminderStoreText -Name $script:PimPendingReminderStateName -Json (ConvertTo-Json -InputObject $plan.state -Depth 6 -Compress) -Expected $stateRaw -Cas) } catch { Write-Warning "  [Mail] the pending-reminder state was not saved: $($_.Exception.Message)" }
            }
            return [pscustomobject]@{ sent = 0; planned = $false; held = 0; failed = 0; detail = "not sent -- $($plan.reason)$errTxt"; plan = $plan }
        }
        # who gets which part
        if (Get-Command Initialize-PimEmailControlsFromStore -ErrorAction SilentlyContinue) { try { [void](Initialize-PimEmailControlsFromStore) } catch { } }
        $alerts = if (Get-Command Get-PimDigestRecipients -ErrorAction SilentlyContinue) { @((Get-PimDigestRecipients -Kind 'alerts').recipients) } else { @() }
        $inst = "$((ConvertTo-PimGetStartedStatus $gsRaw).installer)"
        $prefs = if (Get-Command Get-PimMailNotificationPrefsFromStore -ErrorAction SilentlyContinue) { Get-PimMailNotificationPrefsFromStore } else { $null }
        $to = @(Get-PimPendingReminderRecipients -Items @($plan.items) -SuperAdmins @(Get-PimPendingReminderSuperAdmins) -AlertRecipients $alerts -Installer $inst -Prefs $prefs)
        # a recipient is mailed only when one of THEIR items has waited long enough (an alert recipient is not mailed about a
        # Get Started step seen an hour ago just because an approval ripened for the SuperAdmins); the mail lists all theirs
        $to = @($to | Where-Object { @($_.items | Where-Object { $_.ripe }).Count -gt 0 })
        if (-not $to.Count) {
            return [pscustomobject]@{ sent = 0; planned = $true; held = 0; failed = 0; detail = "not sent -- nobody to tell: no SuperAdmin mail address, no alert recipient wants it ($($plan.reason))$errTxt"; plan = $plan }
        }
        if ($WhatIf) { return [pscustomobject]@{ sent = 0; planned = $true; held = 0; failed = 0; detail = "whatif -- would send to $($to.Count) ($($plan.reason))"; plan = $plan; recipients = $to } }
        # CLAIM the cycle before sending: a second execution reading the same state loses the compare-and-set and sends nothing.
        $claim = 0
        $claimed = ConvertTo-Json -InputObject $plan.state -Depth 6 -Compress
        try { $claim = [int](Set-PimPendingReminderStoreText -Name $script:PimPendingReminderStateName -Json $claimed -Expected $stateRaw -Cas) }
        catch { return [pscustomobject]@{ sent = 0; planned = $true; held = 0; failed = 0; detail = "not sent -- the reminder cycle could not be recorded, so nothing was sent (it would repeat every run): $($_.Exception.Message)"; plan = $plan } }
        if ($claim -ne 1) { return [pscustomobject]@{ sent = 0; planned = $true; held = 0; failed = 0; detail = 'not sent -- another scheduler run already took this reminder cycle'; plan = $plan } }
        $envI = if (Get-Command Get-PimMailEnvironmentInfo -ErrorAction SilentlyContinue) { Get-PimMailEnvironmentInfo -PortalBase $base } else { @{} }
        $sent = 0; $held = New-Object System.Collections.Generic.List[string]; $fail = New-Object System.Collections.Generic.List[string]
        foreach ($r in $to) {
            $tokens = @{ ReportHtml = (ConvertTo-PimPendingReminderHtml -Items @($r.items) -PortalBase $base -Environment $envI -Config $cfg); ItemCount = "$(@($r.items).Count)"
                         ItemList = ((@($r.items | Select-Object -First 6 | ForEach-Object { $_.title })) -join '; '); PortalTab = $(if (@($r.items | Where-Object { $_.kind -ne 'get-started' }).Count) { 'approvals' } else { 'getstarted' }) }
            $res = $null
            try { $res = Send-PimNotifyMail -Type 'pending-actions-reminder' -Tokens $tokens -Recipient $r.address } catch { $res = @{ sent = $false; reason = "$($_.Exception.Message)" } }
            if ("$($res.sent)" -match '(?i)^true$') { $sent++ }
            elseif ((Get-Command Test-PimMailHoldReason -ErrorAction SilentlyContinue) -and (Test-PimMailHoldReason -Reason "$($res.reason)")) { $held.Add("$($r.address): $($res.reason)") }
            elseif ("$($res.reason)" -in @('email kill switch on', 'email feature disabled', 'recipient not on allowlist', 'no sender')) { $held.Add("$($r.address): $($res.reason)") }
            else { $fail.Add("$($r.address): $($res.reason)") }
        }
        # record the outcome; a real delivery failure (nothing sent, nothing held) keeps the previous stamp and retries in an hour
        $final = ConvertTo-PimPendingReminderState $claimed
        $final.lastResult = ("{0} sent={1} held={2} failed={3}" -f $NowUtc.ToUniversalTime().ToString('o'), $sent, $held.Count, $fail.Count)
        if ($sent -eq 0 -and $held.Count -eq 0 -and $fail.Count) {
            $prev = ConvertTo-PimPendingReminderState $stateRaw
            $final.lastSentUtc = $prev.lastSentUtc; $final.lastKeys = @($prev.lastKeys)
            $final.retryAfterUtc = $NowUtc.ToUniversalTime().AddHours(1).ToString('o')
        }
        try { [void](Set-PimPendingReminderStoreText -Name $script:PimPendingReminderStateName -Json (ConvertTo-Json -InputObject $final -Depth 6 -Compress) -Expected $claimed -Cas) } catch { Write-Warning "  [Mail] the pending-reminder outcome was not recorded: $($_.Exception.Message)" }
        $d = ("sent={0}/{1} ({2})" -f $sent, $to.Count, $plan.reason) +
             $(if ($held.Count) { ' held (mail is muted -- recorded, sent at the next cycle once mail is enabled): ' + ($held.ToArray() -join '; ') } else { '' }) +
             $(if ($fail.Count) { ' FAILED: ' + ($fail.ToArray() -join '; ') } else { '' }) + $errTxt
        return [pscustomobject]@{ sent = $sent; planned = $true; held = $held.Count; failed = $fail.Count; detail = $d; plan = $plan; recipients = $to }
    } catch {
        # a store that cannot be read is "cannot answer", not a delivery failure: nothing was sent, the next tick asks again
        return [pscustomobject]@{ sent = 0; planned = $false; held = 0; failed = 0; detail = "not sent -- the pending-actions reminder could not be evaluated: $($_.Exception.Message)"; plan = $null }
    }
}
