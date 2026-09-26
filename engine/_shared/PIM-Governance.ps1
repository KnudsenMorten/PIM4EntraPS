# PIM4EntraPS -- lifecycle / governance pure helpers (REQUIREMENTS § 13).
#
# Dot-sourced by engine/_shared/PIM-Functions.psm1 AND standalone by the
# pim-manager + the scheduler, so the GUI, the validator, the engine and the
# job runner all decide governance questions identically. PURE (time + inputs
# injected, no Graph/SQL/file I/O in the core), PS 5.1 compatible, fully
# unit-testable offline.
#
# Four areas (all four of the § 13 backlog items):
#   1. Scheduled creation + TAP  -- Get-PimScheduledCreationDue / Get-PimDueScheduledCreations
#                                   (which admin rows whose ProvisionDate has arrived
#                                   should be created now, and is the TAP due yet)
#   2. Lifecycle calendar        -- Build-PimLifecycleCalendar (one pass that folds the
#                                   already-tested PIM-Lifecycle.ps1 core into a calendar
#                                   of upcoming expirations + due escalations + auto-renew
#                                   actions) + the change/notify emitters.
#   3. Emergency break-glass     -- Test-PimPasscodeHash (constant-time), Test-PimLockout,
#                                   Get-PimEmergencyTtlHours (clamp), Resolve-PimEmergencyExpectedHash
#                                   (KV PIM-EmergencyPasscode -> hash, else local hash) --
#                                   the verify the Manager + the engine share, KV-backed.
#   4. Access-review feedback     -- Get-PimAccessReviewDecision (auto-extend rows skip the
#                                   owner gate; everything else needs owner approval) +
#                                   New-PimReviewFeedbackRecord (the removal/extension result
#                                   the engine reads so it does NOT re-add a removed user).
#
# The non-pure surface (mail send, change-queue write, KV REST) is a thin wrapper
# over existing helpers (Send-PimNotifyMail / New-PimRenewalChange / the KV REST
# reader) so this file stays testable without a tenant.

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# Shared field accessor (dict or PSCustomObject), case-insensitive on the
# candidate names. Mirrors the access pattern in PIM-Lifecycle.ps1.
# ---------------------------------------------------------------------------
function Get-PimItemField {
    param([Parameter(Mandatory)][object]$Item, [Parameter(Mandatory)][string[]]$Names, [string]$Default = $null)
    foreach ($n in @($Names)) {
        if ($Item -is [System.Collections.IDictionary]) {
            foreach ($k in @($Item.Keys)) { if ("$k" -ieq $n) { return "$($Item[$k])" } }
        } else {
            $p = $Item.PSObject.Properties | Where-Object { "$($_.Name)" -ieq $n } | Select-Object -First 1
            if ($p) { return "$($p.Value)" }
        }
    }
    return $Default
}

function Test-PimTruthy {
    param([string]$Value)
    return ("$Value".Trim().ToLowerInvariant() -in @('true','1','yes','y','on'))
}

# ===========================================================================
# 1. SCHEDULED CREATION + TAP
# ===========================================================================

function Get-PimScheduledCreationDue {
    <#
    .SYNOPSIS
        Decide whether a scheduled admin row should be CREATED now and whether
        its TAP should be ISSUED now -- both relative to NowUtc.

    .DESCRIPTION
        The admin definition row carries a future ProvisionDate (the account
        "starts on" date) and an optional TAPStartDate (when sign-in is needed).
        Both are date EXPRESSIONS already understood by Resolve-PimDateExpression
        (ISO, anchors, natural language). This function is PURE: the caller
        resolves the expressions to UTC and passes them in (so tests need no
        clock), OR passes the raw row + a resolver scriptblock.

        Account creation is due when ProvisionDate <= NowUtc (or there is no
        ProvisionDate -> create immediately, legacy behaviour). The TAP is due
        when CreateTAP is truthy AND we are within TapLeadHours of TAPStartDate
        (default 24h) -- so a far-future TAP is DEFERRED, matching the existing
        Invoke-PimTapProvisioning lead-window logic, but decided purely here.

    .OUTPUTS
        @{ createAccount; tapDue; provisionUtc; tapStartUtc; reason }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$NowUtc,
        [object]$ProvisionUtc,    # [datetime] or $null (object so PS 5.1 doesn't unwrap a Nullable)
        [object]$TapStartUtc,     # [datetime] or $null
        [bool]$CreateTap = $false,
        [int]$TapLeadHours = 24
    )
    $now = $NowUtc.ToUniversalTime()
    $prov = $null; if ($ProvisionUtc -is [datetime]) { $prov = ([datetime]$ProvisionUtc).ToUniversalTime() }
    $tapStart = $null; if ($TapStartUtc -is [datetime]) { $tapStart = ([datetime]$TapStartUtc).ToUniversalTime() }

    $createAccount = $true
    if ($prov) { $createAccount = ($prov -le $now) }

    $tapDue = $false
    $tapReason = ''
    if ($CreateTap) {
        if (-not $tapStart) {
            $tapDue = $createAccount          # no start date -> issue with the account
            $tapReason = if ($tapDue) { 'tap-immediate' } else { 'tap-waits-for-account' }
        } else {
            $lead = $tapStart.AddHours(-[math]::Abs($TapLeadHours))
            $tapDue = ($now -ge $lead) -and $createAccount
            $tapReason = if (-not $createAccount) { 'tap-waits-for-account' }
                         elseif ($tapDue)        { 'tap-within-lead-window' }
                         else                    { 'tap-deferred' }
        }
    } else { $tapReason = 'no-tap' }

    $reason = if (-not $createAccount) { 'account-scheduled-future' } else { 'account-due' }
    return [pscustomobject]@{
        createAccount = $createAccount
        tapDue        = $tapDue
        provisionUtc  = $(if ($prov) { $prov.ToString('o') } else { $null })
        tapStartUtc   = $(if ($tapStart) { $tapStart.ToString('o') } else { $null })
        reason        = $reason
        tapReason     = $tapReason
    }
}

function Get-PimDueScheduledCreations {
    <#
    .SYNOPSIS
        From a set of admin definition rows, return those whose scheduled
        creation (and/or TAP) is due now -- each annotated with the decision.

    .DESCRIPTION
        PURE except it calls Resolve-PimDateExpression (itself pure) to turn the
        ProvisionDate / TAPStartDate cells into UTC. Rows already created (a
        truthy 'Provisioned'/'AccountCreated' marker column) are skipped so a
        scheduler tick is idempotent. Field names are the ones the CSV/SQL admin
        rows already use (ProvisionDate, TAPStartDate, CreateTAP).
    #>
    [CmdletBinding()]
    param(
        [object[]]$Rows = @(),
        [Parameter(Mandatory)][datetime]$NowUtc,
        [int]$TapLeadHours = 24,
        [string[]]$ProvisionFields    = @('ProvisionDate','ProvisionUtc'),
        [string[]]$TapStartFields     = @('TAPStartDate','TapStartDate'),
        [string[]]$CreateTapFields    = @('CreateTAP','CreateTap'),
        [string[]]$AlreadyDoneFields  = @('Provisioned','AccountCreated')
    )
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        if (Test-PimTruthy (Get-PimItemField -Item $r -Names $AlreadyDoneFields -Default '')) { continue }

        $provExpr = Get-PimItemField -Item $r -Names $ProvisionFields -Default ''
        $tapExpr  = Get-PimItemField -Item $r -Names $TapStartFields  -Default ''
        # 71.17 -- TAP IS ON FOR ALL (operator 2026-09-13 "enforce tap to true", repeated 2026-09-15 "tap is on for all"):
        # every Entra admin gets a TAP whatever CreateTAP says. Only an AD-only admin (TargetPlatform=AD) cannot hold one.
        # $CreateTapFields is kept for callers that still pass it and is deliberately not read.
        $createTap = ("$(Get-PimItemField -Item $r -Names @('TargetPlatform','Platform') -Default '')".Trim() -ine 'AD')

        $provUtc = $null; $tapUtc = $null
        if ("$provExpr".Trim() -and (Get-Command Resolve-PimDateExpression -ErrorAction SilentlyContinue)) {
            try { $provUtc = [datetime](Resolve-PimDateExpression -Expression $provExpr) } catch { $provUtc = $null }
        }
        if ("$tapExpr".Trim() -and (Get-Command Resolve-PimDateExpression -ErrorAction SilentlyContinue)) {
            try { $tapUtc = [datetime](Resolve-PimDateExpression -Expression $tapExpr) } catch { $tapUtc = $null }
        }

        $decision = Get-PimScheduledCreationDue -NowUtc $NowUtc -ProvisionUtc $provUtc -TapStartUtc $tapUtc -CreateTap $createTap -TapLeadHours $TapLeadHours
        if ($decision.createAccount -or $decision.tapDue) {
            $out.Add([pscustomobject]@{ row = $r; decision = $decision })
        }
    }
    return @($out.ToArray())
}

# ===========================================================================
# 2. LIFECYCLE CALENDAR (surface the tested PIM-Lifecycle.ps1 core)
# ===========================================================================

function Build-PimLifecycleCalendar {
    <#
    .SYNOPSIS
        One pass over lifecycle items -> a calendar of upcoming expirations,
        the escalation notification due NOW per item, and the auto-renew action
        for AutoExtend items inside the window.

    .DESCRIPTION
        PURE orchestration over the already-unit-tested PIM-Lifecycle.ps1 core
        (Get-PimUpcomingExpirations / Get-PimDueEscalation / Get-PimAutoRenewal).
        The caller passes a per-item notification log (last stage + last-notified
        time, keyed by the item's natural key) so reminder cadence is honoured.
        The actual mail send + change-queue write are done by the wrappers below
        from the returned plan -- this function touches nothing external.

    .OUTPUTS
        @{ generatedUtc; horizonDays; upcoming=[]; escalations=[]; renewals=[] }
        escalations[]  = @{ key; daysLeft; stage; recipients; isReminder; item }
        renewals[]     = @{ key; newExpiryUtc; daysLeft; item }
    #>
    [CmdletBinding()]
    param(
        [object[]]$Items = @(),
        [Parameter(Mandatory)][datetime]$NowUtc,
        [int]$HorizonDays = 30,
        [int]$RenewWithinDays = 7,
        [int]$ExtendDays = 90,
        [string[]]$DateFields,
        [string]$KeyField = 'UserName',
        [hashtable]$NotifyLog = @{},
        [object]$EscalationPolicy
    )
    $now = $NowUtc.ToUniversalTime()
    $up = @(Get-PimUpcomingExpirations -Items $Items -NowUtc $now -HorizonDays $HorizonDays -DateFields $DateFields -IncludeExpired)

    $escalations = New-Object System.Collections.Generic.List[object]
    $renewals    = New-Object System.Collections.Generic.List[object]

    foreach ($u in $up) {
        $it  = $u.item
        $key = Get-PimItemField -Item $it -Names @($KeyField,'UserName','Id','Name','GroupTag','UserPrincipalName') -Default ''
        $days = [int]$u.daysLeft

        # escalation due now (honouring the per-item notify log)
        $logEntry = $null
        if ($NotifyLog -and $NotifyLog.ContainsKey("$key")) { $logEntry = $NotifyLog["$key"] }
        $lastStage = $null; $lastUtc = ''; $lastRem = 0
        if ($logEntry) {
            if ($logEntry.PSObject.Properties['stage'] -and "$($logEntry.stage)".Trim()) { $lastStage = [int]$logEntry.stage }
            elseif ($logEntry -is [System.Collections.IDictionary] -and $logEntry.Contains('stage') -and "$($logEntry['stage'])".Trim()) { $lastStage = [int]$logEntry['stage'] }
            $lastUtc = if ($logEntry.PSObject.Properties['notifiedUtc']) { "$($logEntry.notifiedUtc)" } elseif ($logEntry -is [System.Collections.IDictionary] -and $logEntry.Contains('notifiedUtc')) { "$($logEntry['notifiedUtc'])" } else { '' }
            # BUG-191 (2.4.371): how many reminders of THIS stage already went out -- the reminder cadence is capped
            # (Get-PimDueEscalation, policy maxRemindersPerStage / remindAfterExpiry).
            $remRaw = if ($logEntry.PSObject.Properties['reminders']) { "$($logEntry.reminders)" } elseif ($logEntry -is [System.Collections.IDictionary] -and $logEntry.Contains('reminders')) { "$($logEntry['reminders'])" } else { '' }
            if ("$remRaw".Trim()) { try { $lastRem = [int]$remRaw } catch { $lastRem = 0 } }
        }
        $due = Get-PimDueEscalation -DaysLeft $days -NowUtc $now -Policy $EscalationPolicy -LastStageAtDays $lastStage -LastNotifiedUtc $lastUtc -ReminderCount $lastRem
        if ($due) {
            $escalations.Add([pscustomobject]@{ key = "$key"; daysLeft = $days; stage = $due.stage; recipients = @($due.recipients); isReminder = [bool]$due.isReminder; reminders = $(if ($due.isReminder) { $lastRem + 1 } else { 0 }); expiryUtc = $u.expiryUtc; item = $it })
        }

        # auto-renew (AutoExtend within the renew window)
        $renew = Get-PimAutoRenewal -Item $it -NowUtc $now -RenewWithinDays $RenewWithinDays -ExtendDays $ExtendDays -DateFields $DateFields
        if ($renew) {
            $renewals.Add([pscustomobject]@{ key = "$key"; newExpiryUtc = $renew.newExpiryUtc; daysLeft = $renew.daysLeft; item = $it })
        }
    }

    return [pscustomobject]@{
        generatedUtc = $now.ToString('o')
        horizonDays  = $HorizonDays
        upcoming     = @($up)
        escalations  = @($escalations.ToArray())
        renewals     = @($renewals.ToArray())
    }
}

function Get-PimLifecycleRenewalChanges {
    <#
    .SYNOPSIS
        Turn a calendar's renewals[] into change-queue Update records that extend
        each item's expiry date field. PURE (returns the change objects).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Calendar,
        [Parameter(Mandatory)][string]$Entity,
        [string]$DateField = 'ExpiresUtc',
        [string]$By = 'auto-renew'
    )
    $changes = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Calendar.renewals)) {
        if (Get-Command New-PimRenewalChange -ErrorAction SilentlyContinue) {
            $changes.Add((New-PimRenewalChange -Entity $Entity -Key "$($r.key)" -DateField $DateField -NewExpiryUtc "$($r.newExpiryUtc)" -By $By))
        }
    }
    return @($changes.ToArray())
}

function Resolve-PimLifecycleEscalationRecipient {
    <#
      BUG-191 (§33.28): the DEFAULT resolver for the escalation policy's symbolic recipients. Nothing ever
      set $global:PIM_LifecycleRecipientResolver, so every symbol resolved to nobody. Returns string[]:
        owner / manager -> (2.4.371, §71.19) the admin's SPONSOR DEPARTMENT's owners via Get-PimAdminMailRecipientPlan
                           (the per-admin forward override first), then the item's ManagerEmail as the LEGACY
                           fallback; an item that resolves to nobody falls back to the Alerting recipients, so an
                           escalation is never silently addressed to nobody
        admin           -> the Manager's Alerting recipients (pim.Settings['Alerting'])
      A symbol that already looks like an address is used as-is.
    #>
    [CmdletBinding()] param([string]$Symbol, [object]$Item)
    $sym = "$Symbol".Trim()
    if ($sym -match '@') { return @($sym) }
    $alerting = @()
    if (Get-Command Get-PimJobAlertingConfig -ErrorAction SilentlyContinue) {
        try { $alerting = @((Get-PimJobAlertingConfig).recipients | Where-Object { "$_".Trim() }) } catch { $alerting = @() }
    }
    $mgr = ''
    if ($null -ne $Item) {
        if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains('ManagerEmail')) { $mgr = "$($Item['ManagerEmail'])".Trim() } }
        elseif ($Item.PSObject.Properties['ManagerEmail']) { $mgr = "$($Item.ManagerEmail)".Trim() }
    }
    $s = $sym.ToLowerInvariant()
    if ($s -eq 'admin') { return @($alerting) }
    if ($s -in @('owner', 'manager', 'sponsor')) {
        # 2.4.371 (§71.19): an admin's mail goes to its SPONSOR DEPARTMENT's owners (or the per-admin forward override),
        # with ManagerEmail only as the legacy fallback -- the same resolver the TAP and every other admin mail use.
        if ($null -ne $Item -and (Get-Command Get-PimAdminMailRecipientPlan -ErrorAction SilentlyContinue)) {
            $pf = { param($n) if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($n)) { return "$($Item[$n])" } } elseif ($Item.PSObject.Properties[$n]) { return "$($Item.$n)" }; return '' }
            $like = [pscustomobject]@{ UserPrincipalName = (& $pf 'UserName'); Department = (& $pf 'Department'); ForwardMailsToContact = (& $pf 'ForwardMailsToContact')
                                       MailForwardAddress = (& $pf 'MailForwardAddress'); ManagerEmail = $mgr }
            $plan = $null
            try { $plan = Get-PimAdminMailRecipientPlan -Row $like } catch { $plan = $null }
            if ($plan -and @($plan.recipients | Where-Object { "$_".Trim() }).Count) { return @($plan.recipients | Where-Object { "$_".Trim() }) }
        }
        if ($mgr) { return @($mgr) }
        return @($alerting)
    }
    return @()
}

function Send-PimLifecycleEscalations {
    <#
    .SYNOPSIS
        Send the calendar's due escalation notifications, resolving symbolic recipients
        (owner/manager/admin) with a resolver (default: Resolve-PimLifecycleEscalationRecipient).
        Returns a result per recipient and an updated notify log (so the next pass honours the
        reminder cadence). Honours -WhatIf (renders, does not send).
      🔴 BUG-191 (§33.28): this sent the SERIAL-APPROVAL escalation template ('approval-escalation',
      tokens ApproverName/RequestorUpn/...) with tokens it does not use, to recipients nothing resolved.
      It now uses 'alert-notice' (event 'expiring-access') with that template's own tokens, READS each
      send result, and advances an item's notify log ONLY when a mail actually went out (or -WhatIf) --
      a stage that reached nobody is re-tried next pass, never recorded as notified.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Calendar,
        [scriptblock]$RecipientResolver,   # { param($symbol,$item) -> email(s) or $null }
        [string]$TemplateType = 'alert-notice',
        [hashtable]$NotifyLog = @{},
        [switch]$WhatIf
    )
    if (-not $RecipientResolver) { $RecipientResolver = { param($s, $i) Resolve-PimLifecycleEscalationRecipient -Symbol $s -Item $i } }
    $log = @{}; foreach ($k in @($NotifyLog.Keys)) { $log[$k] = $NotifyLog[$k] }
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Calendar.escalations)) {
        $it = $e.item
        $kind = if ($it -and $it.PSObject.Properties['Kind']) { "$($it.Kind)" } else { 'access' }
        $what = if ($it -and $it.PSObject.Properties['GroupTag'] -and "$($it.GroupTag)") { " ($($it.GroupTag))" } else { '' }
        $when = "$($e.expiryUtc)"; try { $when = ([datetime]$e.expiryUtc).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC' } catch { }
        $verb = if ([int]$e.daysLeft -lt 0) { 'expired' } else { 'expires' }
        $tokens = @{
            AlertTitle  = ("{0} for {1} {2} in {3} day(s)" -f $kind, "$($e.key)", $verb, [Math]::Abs([int]$e.daysLeft))
            AlertEvent  = 'expiring-access'
            AlertDetail = ("{0}{1}: lifecycle date {2}, escalation stage {3} day(s){4}." -f "$($e.key)", $what, $when, "$($e.stage)", $(if ($e.isReminder) { ' (reminder)' } else { '' }))
            AlertTab    = 'admins'
            TenantName  = "$($global:PIM_TenantName)"
            Instance    = 'scheduler'
            WhenUtc     = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
        }
        # §79.8: an auto-disable links the OWNER page at that person, where the department owner extends the date.
        if ($kind -eq 'admin-offboard' -and [int]$e.daysLeft -ge 0) {
            $who = if ($it -and $it.PSObject.Properties['UserName'] -and "$($it.UserName)".Trim()) { "$($it.UserName)".Trim() } else { ("$($e.key)" -replace '^admin-offboard:', '') }
            $tokens['PortalTab']   = 'owner'
            $tokens['PortalQuery'] = "person=$who"
            $tokens['AlertTitle']  = ("{0} will be disabled in {1} day(s)" -f $who, [int]$e.daysLeft)
            $tokens['AlertDetail'] = ("{0}'s access ends on {1}. If they still need it, open the link below and extend the date -- nothing else is needed. If they do not, no action is required." -f $who, $when)
        }
        $anySent = $false; $seenRcpt = @{}
        foreach ($sym in @($e.recipients)) {
            $rcpts = @()
            try { $rcpts = @(& $RecipientResolver $sym $it | Where-Object { "$_".Trim() }) } catch { $rcpts = @() }
            if (-not $rcpts.Count) {
                $results.Add([pscustomobject]@{ key = "$($e.key)"; symbol = "$sym"; recipient = $null; stage = $e.stage; isReminder = $e.isReminder; sent = $false; held = $false; reason = "no recipient resolved for '$sym'" })
                continue
            }
            foreach ($rcpt in $rcpts) {
                $rk = "$rcpt".Trim().ToLowerInvariant(); if ($seenRcpt.ContainsKey($rk)) { continue }; $seenRcpt[$rk] = $true   # owner + manager can be the same person
                $ok = $false; $why = ''
                if (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) { $why = 'the mail sender is not loaded' }
                else {
                    try {
                        $m = Send-PimNotifyMail -Type $TemplateType -Tokens $tokens -Recipient "$rcpt" -WhatIf:$WhatIf
                        if ($m -is [hashtable]) { $ok = [bool]$m['sent']; $why = "$($m['reason'])" } elseif ($m) { $ok = [bool]$m.sent; $why = "$($m.reason)" }
                    } catch { $why = "$($_.Exception.Message)" }
                }
                if ($ok -or $WhatIf) { $anySent = $true }
                # BUG-191 (2.4.371): a DELIBERATE operator state (kill switch, feature off, allowlist, no sender) is a
                # hold, not a failure -- the caller reports it as skipped and does not fail the job. It is still not
                # recorded as notified, so the stage goes out once mail is enabled.
                $held = (-not $ok) -and (-not $WhatIf) -and (Test-PimMailHoldReason -Reason $why)
                $results.Add([pscustomobject]@{ key = "$($e.key)"; symbol = "$sym"; recipient = "$rcpt"; stage = $e.stage; isReminder = $e.isReminder; sent = [bool]$ok; held = [bool]$held; reason = $why })
            }
        }
        $remN = if ($e.PSObject.Properties['reminders']) { [int]$e.reminders } else { 0 }
        if ($anySent) { $log["$($e.key)"] = [pscustomobject]@{ stage = [int]$e.stage; notifiedUtc = $Calendar.generatedUtc; reminders = $remN } }
    }
    return [pscustomobject]@{ results = @($results.ToArray()); notifyLog = $log }
}

function Get-PimLifecycleEscalationLog {
    # BUG-191: the per-item notify log lives in SQL (pim.Settings['LifecycleEscalationLog']). It used to be a
    # process global, so in a cron tick -- a new process every run -- every stage looked un-notified every hour.
    # THROWS when the store cannot be read (the caller must not re-send everything on a read failure).
    [CmdletBinding()] param()
    if (-not (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) { throw 'no SQL settings store (Get-PimSetting) is wired -- the escalation log cannot be read' }
    $v = Get-PimSetting -Name 'LifecycleEscalationLog'
    if ($v -is [string] -and "$v".Trim()) { $v = $v | ConvertFrom-Json }
    $map = @{}
    if ($null -ne $v) {
        if ($v -is [System.Collections.IDictionary]) { foreach ($k in @($v.Keys)) { $map["$k"] = $v[$k] } }
        else { foreach ($p in $v.PSObject.Properties) { $map["$($p.Name)"] = $p.Value } }
    }
    return $map
}

function Save-PimLifecycleEscalationLog {
    # THROWS when the store rejects the write (the job must then report failure: an unsaved log re-sends).
    [CmdletBinding()] param([hashtable]$Log = @{}, [datetime]$NowUtc = [datetime]::UtcNow, [int]$KeepDays = 120)
    if (-not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) { throw 'no SQL settings store (Set-PimSetting) is wired -- the escalation log cannot be saved' }
    $cut = $NowUtc.ToUniversalTime().AddDays(-[Math]::Abs($KeepDays))
    $o = [ordered]@{}
    foreach ($k in @($Log.Keys | Sort-Object)) {
        $e = $Log[$k]; $t = $null
        try { $t = ([datetime]"$($e.notifiedUtc)").ToUniversalTime() } catch { $t = $null }
        if ($null -ne $t -and $t -lt $cut) { continue }   # history, not state
        $f = { param($n) if ($e -is [System.Collections.IDictionary]) { if ($e.Contains($n)) { return $e[$n] } } elseif ($e.PSObject.Properties[$n]) { return $e.$n }; return $null }
        $rem = 0; $rv = & $f 'reminders'; if ($null -ne $rv -and "$rv".Trim()) { try { $rem = [int]"$rv" } catch { $rem = 0 } }
        $row = [ordered]@{ stage = [int](& $f 'stage'); notifiedUtc = "$(& $f 'notifiedUtc')"; reminders = $rem }
        if ("$(& $f 'seeded')" -match '^(?i)true$') { $row['seeded'] = $true }   # baseline, never mailed (BUG-191)
        $o["$k"] = $row
    }
    Set-PimSetting -Name 'LifecycleEscalationLog' -Value (ConvertTo-Json -InputObject $o -Depth 4 -Compress)
}

function Test-PimMailHoldReason {
    <#
      BUG-191 (§33.28, 2.4.371). PURE. $true when a Send-PimNotifyMail refusal is a DELIBERATE operator state rather
      than a delivery failure: the email kill switch, the 'alerting.email' feature switched off, a recipient not on the
      allowlist, or no sender configured. Those are what the operator chose (or has not set up yet); reporting them as a
      failed job every hour teaches people to ignore the Jobs column. The mail is still NOT recorded as sent -- it goes
      out once mail is enabled. Keep in step with the reason strings Send-PimNotifyMail returns.
    #>
    param([string]$Reason)
    return ("$Reason".Trim() -in @('email kill switch on', 'email feature disabled', 'recipient not on allowlist', 'no sender'))
}

function Get-PimLifecycleEscalationBaseline {
    # BUG-191 (2.4.371): the first-run marker, pim.Settings['LifecycleEscalationBaseline'] = { seededUtc; seeded }.
    # ABSENT means this environment has never baselined its escalations: the first run records every stage that is
    # already due WITHOUT mailing it. A separate value, not "the log is empty": an environment whose log is empty only
    # because nothing was ever due must mail the first stage that becomes due, not swallow it as a baseline.
    # Returns $null when absent; THROWS when the store cannot be read (the caller must not send on a read failure).
    [CmdletBinding()] param()
    if (-not (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) { throw 'no SQL settings store (Get-PimSetting) is wired -- the escalation baseline cannot be read' }
    $v = Get-PimSetting -Name 'LifecycleEscalationBaseline'
    if ($v -is [string]) { if (-not "$v".Trim()) { return $null }; $v = $v | ConvertFrom-Json }
    return $v
}

function Save-PimLifecycleEscalationBaseline {
    [CmdletBinding()] param([datetime]$NowUtc = [datetime]::UtcNow, [int]$Seeded = 0)
    if (-not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) { throw 'no SQL settings store (Set-PimSetting) is wired -- the escalation baseline cannot be saved' }
    Set-PimSetting -Name 'LifecycleEscalationBaseline' -Value (ConvertTo-Json -InputObject ([ordered]@{ seededUtc = $NowUtc.ToUniversalTime().ToString('o'); seeded = [int]$Seeded }) -Compress)
}

function Add-PimLifecycleEscalationSeed {
    <#
      BUG-191 (2.4.371). PURE. Record every escalation the calendar says is due NOW as already notified -- without
      sending anything -- so the first run after an upgrade does not mail every stage that was already due (on an
      environment with dozens of admins that is dozens of mails in one hour, to sponsors and the Alerting list, about
      states nobody chose to be told about). Returns @{ notifyLog; seeded }. After this, only a NEW stage transition
      (or a capped reminder) is due.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][object]$Calendar, [hashtable]$NotifyLog = @{})
    $log = @{}; foreach ($k in @($NotifyLog.Keys)) { $log[$k] = $NotifyLog[$k] }
    $n = 0
    foreach ($e in @($Calendar.escalations)) {
        # A due REMINDER of an already-logged stage is baselined the same way (counted as sent), so it cannot storm either.
        $log["$($e.key)"] = [pscustomobject]@{ stage = [int]$e.stage; notifiedUtc = $Calendar.generatedUtc; reminders = $(if ($e.PSObject.Properties['reminders']) { [int]$e.reminders } else { 0 }); seeded = $true }
        $n++
    }
    return [pscustomobject]@{ notifyLog = $log; seeded = $n }
}

# ===========================================================================
# 3. EMERGENCY BREAK-GLASS -- shared, KV-backed, pure verify
# ===========================================================================

function Get-PimSha256Hex {
    param([Parameter(Mandatory)][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Test-PimConstantTimeEqual {
    # Constant-time string compare (length-safe). PURE.
    param([string]$A, [string]$B)
    $a = "$A"; $b = "$B"
    $diff = $a.Length -bxor $b.Length
    $n = [math]::Min($a.Length, $b.Length)
    for ($i = 0; $i -lt $n; $i++) { $diff = $diff -bor ([int][char]$a[$i] -bxor [int][char]$b[$i]) }
    return ($diff -eq 0)
}

function Test-PimPasscodeHash {
    <#
    .SYNOPSIS
        Verify an entered passcode against an expected SHA256 hex, constant-time.
        PURE -- no I/O, no state. Returns $true/$false.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Passcode, [AllowEmptyString()][string]$ExpectedHashHex)
    if (-not "$ExpectedHashHex".Trim()) { return $false }
    return (Test-PimConstantTimeEqual (Get-PimSha256Hex -Text $Passcode) ("$ExpectedHashHex".Trim().ToLowerInvariant()))
}

function Test-PimLockout {
    <#
    .SYNOPSIS
        Given the UTC timestamps of recent FAILED attempts, decide if the
        endpoint is locked. PURE. Default: 5 failures within 15 minutes locks.

    .OUTPUTS
        @{ locked; recentFailures; window }  where recentFailures is the pruned
        in-window list (caller persists it).
    #>
    param(
        [datetime[]]$Failures = @(),
        [Parameter(Mandatory)][datetime]$NowUtc,
        [int]$MaxFailures = 5,
        [int]$WindowMinutes = 15
    )
    $cutoff = $NowUtc.ToUniversalTime().AddMinutes(-[math]::Abs($WindowMinutes))
    $recent = @(@($Failures) | Where-Object { $_.ToUniversalTime() -gt $cutoff } | Sort-Object)
    return [pscustomobject]@{ locked = ($recent.Count -ge $MaxFailures); recentFailures = $recent; window = $WindowMinutes }
}

function Get-PimEmergencyTtlHours {
    <#
    .SYNOPSIS
        Clamp a requested override TTL to [Min..Max] (default 1..24h, default 4h
        when unset). PURE.
    #>
    param([Nullable[int]]$RequestedHours, [int]$DefaultHours = 4, [int]$MinHours = 1, [int]$MaxHours = 24)
    if ($null -eq $RequestedHours) { return $DefaultHours }
    return [math]::Min($MaxHours, [math]::Max($MinHours, [int]$RequestedHours))
}

function Resolve-PimEmergencyExpectedHash {
    <#
    .SYNOPSIS
        Resolve the EXPECTED passcode hash for the break-glass verify.

    .DESCRIPTION
        Priority (so the override works from a client PC even if KV is the
        source of truth):
          1. KV secret PIM-EmergencyPasscode (name overridable) -- the secret
             VALUE may be a passphrase (we hash it) OR already a 64-char SHA256
             hex (used as-is). Fetched via the existing KV REST reader; never
             cached to disk.
          2. local $global:PIM_EmergencyPasscodeHash (config/emergency.custom.ps1).
        Returns @{ hash; source } or @{ hash=''; source='none' }.
        The KV fetch is the only non-pure path and is fully guarded.
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName    = "$($global:PIM_EmergencyVault)",
        [string]$SecretName   = $(if ($global:PIM_EmergencyPasscodeSecret) { "$($global:PIM_EmergencyPasscodeSecret)" } else { 'PIM-EmergencyPasscode' }),
        [string]$LocalHash    = "$($global:PIM_EmergencyPasscodeHash)"
    )
    if ("$VaultName".Trim() -and (Get-Command Get-PimSqlSecretFromKeyVault -ErrorAction SilentlyContinue)) {
        try {
            $val = Get-PimSqlSecretFromKeyVault -VaultName "$VaultName".Trim() -SecretName "$SecretName".Trim()
            if ("$val".Trim()) {
                $v = "$val".Trim()
                $hash = if ($v -match '^[0-9a-fA-F]{64}$') { $v.ToLowerInvariant() } else { Get-PimSha256Hex -Text $v }
                return [pscustomobject]@{ hash = $hash; source = "keyvault:$SecretName" }
            }
        } catch {
            Write-Warning "  [Emergency] KV passcode '$SecretName' in '$VaultName' unreadable: $($_.Exception.Message) -- falling back to local hash."
        }
    }
    if ("$LocalHash".Trim()) { return [pscustomobject]@{ hash = "$LocalHash".Trim().ToLowerInvariant(); source = 'local' } }
    return [pscustomobject]@{ hash = ''; source = 'none' }
}

function Get-PimEmergencyPassphraseStatus {
    <#
    .SYNOPSIS
        REQ-F (2026-09-19): is an emergency passphrase configured -- WITHOUT ever returning it or its hash.

    .DESCRIPTION
        Same resolution order as Resolve-PimEmergencyExpectedHash (the key vault named by PIM_EmergencyVault
        first, then a host-set in-memory hash), so the Settings card says exactly what an activation will find.
        Measured 2026-09-19: no hosted Manager had PIM_EmergencyVault, so every activation was refused with
        "no emergency passcode configured" -- and nothing on screen said so until somebody tried in an incident.
        Returns @{ configured; source ('keyvault' | 'local' | 'none'); vault; secretName; reason }.
        -SecretReader is the test seam (default: Get-PimSqlSecretFromKeyVault). PS 5.1-safe.
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName  = "$($global:PIM_EmergencyVault)",
        [string]$SecretName = $(if ($global:PIM_EmergencyPasscodeSecret) { "$($global:PIM_EmergencyPasscodeSecret)" } else { 'PIM-EmergencyPasscode' }),
        [string]$LocalHash  = "$($global:PIM_EmergencyPasscodeHash)",
        [scriptblock]$SecretReader
    )
    $v = "$VaultName".Trim(); $s = "$SecretName".Trim()
    $vaultReason = ''
    if ($v) {
        $reader = $SecretReader
        if (-not $reader) {
            if (Get-Command Get-PimSqlSecretFromKeyVault -ErrorAction SilentlyContinue) { $reader = { param($vn, $sn) Get-PimSqlSecretFromKeyVault -VaultName $vn -SecretName $sn } }
        }
        if (-not $reader) {
            $vaultReason = "PIM_EmergencyVault is '$v' but this runtime has no Key Vault reader loaded"
        } else {
            try {
                $val = & $reader $v $s
                if ("$val".Trim()) {
                    return [pscustomobject]@{ configured = $true; source = 'keyvault'; vault = $v; secretName = $s; reason = "the passphrase is stored in key vault '$v' (secret $s)" }
                }
                $vaultReason = "secret '$s' in key vault '$v' is empty"
            } catch {
                $vaultReason = "secret '$s' in key vault '$v' could not be read: $($_.Exception.Message)"
            }
        }
    }
    if ("$LocalHash".Trim()) {
        return [pscustomobject]@{ configured = $true; source = 'local'; vault = $v; secretName = $s; reason = $(if ($vaultReason) { "$vaultReason -- using the passphrase hash this host set in memory" } else { 'a passphrase hash is set in memory by this host (no key vault configured)' }) }
    }
    $why = if ($vaultReason) { $vaultReason } else { 'no key vault is configured for the emergency passphrase (PIM_EmergencyVault is not set on the Manager)' }
    return [pscustomobject]@{ configured = $false; source = 'none'; vault = $v; secretName = $s; reason = $why }
}

function Resolve-PimEmergencyVerification {
    <#
    .SYNOPSIS
        End-to-end break-glass verify, composed of the pure helpers: lockout
        check -> constant-time hash compare -> record a failure on miss. The
        EXPECTED hash is resolved (KV first, then local) by the caller and
        passed in, so this stays pure + testable. Returns the verdict + the
        updated failure list to persist.

    .OUTPUTS
        @{ ok; error; recentFailures }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Passcode,
        [AllowEmptyString()][string]$ExpectedHashHex,
        [Parameter(Mandatory)][datetime]$NowUtc,
        [datetime[]]$Failures = @(),
        [int]$MaxFailures = 5,
        [int]$WindowMinutes = 15
    )
    $lock = Test-PimLockout -Failures $Failures -NowUtc $NowUtc -MaxFailures $MaxFailures -WindowMinutes $WindowMinutes
    if ($lock.locked) { return [pscustomobject]@{ ok = $false; error = "locked: too many failed attempts -- wait $WindowMinutes minutes"; recentFailures = @($lock.recentFailures) } }
    if (-not "$ExpectedHashHex".Trim()) { return [pscustomobject]@{ ok = $false; error = 'no emergency passcode configured (set KV PIM-EmergencyPasscode or $global:PIM_EmergencyPasscodeHash)'; recentFailures = @($lock.recentFailures) } }
    if (Test-PimPasscodeHash -Passcode $Passcode -ExpectedHashHex $ExpectedHashHex) {
        return [pscustomobject]@{ ok = $true; recentFailures = @($lock.recentFailures) }
    }
    $fails = @($lock.recentFailures) + $NowUtc.ToUniversalTime()
    return [pscustomobject]@{ ok = $false; error = 'invalid passcode'; recentFailures = @($fails) }
}

# ===========================================================================
# 4. ACCESS-REVIEW FEEDBACK LOOP
# ===========================================================================

function Get-PimAccessReviewDecision {
    <#
    .SYNOPSIS
        Decide how an access assignment's continuation is governed: owner must
        approve the EXTENSION, EXCEPT where auto-extension is defined (an opt-in
        per-row/per-role column) -- those skip the owner gate.

    .DESCRIPTION
        PURE. The opt-in column (default 'AutoExtend') is the extra config column
        from REQUIREMENTS § 13. When truthy -> action 'auto-extend', no owner
        approval needed. Otherwise -> 'owner-approval', the named owners (pipe-
        joined Owners column, then Department fallback) must approve, and until
        they do the engine must NOT silently re-add (see New-PimReviewFeedbackRecord).

    .OUTPUTS
        @{ key; action(auto-extend|owner-approval); reviewers; reason }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Item,
        [string]$KeyField = 'UserName',
        [string[]]$AutoExtendFields = @('AutoExtend'),
        [string[]]$OwnerFields = @('Owners','Owner'),
        [string[]]$FallbackFields = @('Department')
    )
    $key = Get-PimItemField -Item $Item -Names @($KeyField,'UserName','Id','Name','UserPrincipalName') -Default ''
    if (Test-PimTruthy (Get-PimItemField -Item $Item -Names $AutoExtendFields -Default '')) {
        return [pscustomobject]@{ key = "$key"; action = 'auto-extend'; reviewers = @(); reason = 'auto-extension defined -- owner gate skipped' }
    }
    $owners = @()
    $raw = Get-PimItemField -Item $Item -Names $OwnerFields -Default ''
    if ("$raw".Trim()) { $owners = @("$raw" -split '[|;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    if ($owners.Count -eq 0) {
        $fb = Get-PimItemField -Item $Item -Names $FallbackFields -Default ''
        if ("$fb".Trim()) { $owners = @("$fb".Trim()) }
    }
    return [pscustomobject]@{ key = "$key"; action = 'owner-approval'; reviewers = @($owners); reason = 'owner approval required to extend' }
}

function Get-PimAccessReviewPlan {
    # Map a set of items to their review decisions. PURE.
    param([object[]]$Items = @(), [string]$KeyField = 'UserName', [string[]]$AutoExtendFields = @('AutoExtend'))
    @(@($Items) | ForEach-Object { Get-PimAccessReviewDecision -Item $_ -KeyField $KeyField -AutoExtendFields $AutoExtendFields })
}

function New-PimReviewFeedbackRecord {
    <#
    .SYNOPSIS
        Build the feedback record the engine reads so a review outcome closes the
        loop -- a 'Deny' (owner did not approve / removed the user) records the
        key as removed so the engine does NOT re-add it on its next reconcile;
        an 'Approve' records the extended expiry. PURE.

    .OUTPUTS
        @{ key; outcome(Approve|Deny); decidedUtc; decidedBy; suppressReAdd; newExpiryUtc }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][ValidateSet('Approve','Deny')][string]$Outcome,
        [Parameter(Mandatory)][datetime]$NowUtc,
        [string]$DecidedBy = '',
        [int]$ExtendDays = 90
    )
    $deny = ($Outcome -eq 'Deny')
    return [pscustomobject]@{
        key          = "$Key"
        outcome      = $Outcome
        decidedUtc   = $NowUtc.ToUniversalTime().ToString('o')
        decidedBy    = "$DecidedBy"
        suppressReAdd = $deny
        newExpiryUtc = $(if ($deny) { $null } else { $NowUtc.ToUniversalTime().AddDays($ExtendDays).ToString('o') })
    }
}

function Test-PimReviewSuppressesReAdd {
    <#
    .SYNOPSIS
        Engine guard: given the review-feedback records, should this key be
        suppressed (NOT re-added) on reconcile? PURE -- the engine calls this
        before re-adding a user it found in the desired set.
    #>
    param([Parameter(Mandatory)][string]$Key, [object[]]$Feedback = @())
    $rec = @(@($Feedback) | Where-Object { "$($_.key)" -ieq "$Key" } | Sort-Object { "$($_.decidedUtc)" } | Select-Object -Last 1)
    if ($rec.Count -eq 0) { return $false }
    return [bool]$rec[0].suppressReAdd
}

# ===========================================================================
# 5. DRIFT DETECTION + GATED REMEDIATION (REQUIREMENTS §28 [M5], §26c)
# ===========================================================================
#
# General Governance drift view: compare the LIVE estate against the DESIRED
# store, list drift, and offer a gated "apply now" that runs the EXISTING engine
# create/update path for only the SELECTED drift.
#
# This REUSES the engine's delta computation -- it does NOT reimplement
# reconciliation. The caller runs the engine in plan/WhatIf mode (no writes) for
# each scope, which internally calls Compare-PimDesiredVsLive (create/update/
# remove/nochange). Get-PimDriftReport just NORMALISES those per-scope engine
# diffs into one flat, drift-classified list:
#       create  -> 'missing' (desired but not live)
#       update  -> 'changed' (present but differs from desired)
#       remove  -> 'extra'   (live but not desired)  -- only ever surfaced when
#                  the plan was computed with prune ON; remediation of 'extra'
#                  stays opt-in (-AllowRemove) and maps to the engine's -Prune.
#
# The two functions here are PURE (inject per-scope diffs -> drift list; inject
# drift list + selection -> remediation plan). No Graph/SQL/file I/O, PS 5.1.

function Get-PimDriftType {
    <#
    .SYNOPSIS
        Map an engine diff op -> a drift classification. PURE.
            Create -> missing | Update -> changed | Remove -> extra
    #>
    param([Parameter(Mandatory)][string]$Op)
    switch ("$Op".Trim().ToLowerInvariant()) {
        'create' { 'missing' }
        'update' { 'changed' }
        'remove' { 'extra' }
        default  { "$Op".ToLowerInvariant() }
    }
}

function Get-PimDriftReport {
    <#
    .SYNOPSIS
        Normalise a set of per-scope engine diffs into ONE flat, drift-classified
        list (missing / extra / changed delegations). PURE -- inject the diffs.

    .DESCRIPTION
        Each input item describes one scope's already-computed engine diff:
            @{ scope; entity?; create=[]; update=[]; remove=[] }
        where create/update/remove are the arrays Compare-PimDesiredVsLive (the
        engine delta core) returned -- each element carrying { key; desired?; live? }.
        The caller obtains these by running the engine in PLAN/WhatIf mode (which
        performs NO writes) -- so this function never touches a tenant.

        Output: a stable, sorted drift list plus a per-type + per-scope summary.
        Every drift item carries its (entity,key) so a later remediation plan can
        target exactly the selected ones and the engine can apply just those.

    .OUTPUTS
        @{ generatedUtc; total; counts=@{missing;changed;extra}; scopes=@{...};
           items=[ @{ scope; entity; key; type(missing|changed|extra); op } ] }
    #>
    [CmdletBinding()]
    param(
        [object[]]$ScopeDiffs = @(),
        [datetime]$NowUtc = ([datetime]::UtcNow)
    )
    $items = New-Object System.Collections.Generic.List[object]
    $byScope = @{}
    foreach ($sd in @($ScopeDiffs)) {
        if ($null -eq $sd) { continue }
        $scope  = "$(Get-PimItemField -Item $sd -Names @('scope','Scope') -Default '')".Trim()
        $entity = "$(Get-PimItemField -Item $sd -Names @('entity','Entity') -Default '')".Trim()
        if (-not $entity) { $entity = $scope }
        if (-not $byScope.ContainsKey($scope)) { $byScope[$scope] = [ordered]@{ missing = 0; changed = 0; extra = 0 } }

        $emit = {
            param($op, $arr)
            foreach ($d in @($arr)) {
                if ($null -eq $d) { continue }
                $key = "$(Get-PimItemField -Item $d -Names @('key','Key') -Default '')".Trim()
                if (-not $key) { continue }
                $type = Get-PimDriftType -Op $op
                $items.Add([pscustomobject]@{ scope = $scope; entity = $entity; key = $key; type = $type; op = $op })
                if ($byScope[$scope].Contains($type)) { $byScope[$scope][$type] = [int]$byScope[$scope][$type] + 1 }
            }
        }
        & $emit 'Create' $sd.create
        & $emit 'Update' $sd.update
        & $emit 'Remove' $sd.remove
    }

    $typeOrder = @{ missing = 0; changed = 1; extra = 2 }
    $sorted = @(@($items.ToArray()) | Sort-Object @{ e = { "$($_.scope)" } }, @{ e = { $typeOrder["$($_.type)"] } }, @{ e = { "$($_.key)" } })
    $missing = @(@($sorted) | Where-Object { $_.type -eq 'missing' }).Count
    $changed = @(@($sorted) | Where-Object { $_.type -eq 'changed' }).Count
    $extra   = @(@($sorted) | Where-Object { $_.type -eq 'extra' }).Count

    return [pscustomobject]@{
        generatedUtc = $NowUtc.ToUniversalTime().ToString('o')
        total        = @($sorted).Count
        counts       = [pscustomobject]@{ missing = $missing; changed = $changed; extra = $extra }
        scopes       = $byScope
        items        = @($sorted)
    }
}

function Get-PimDriftRemediationPlan {
    <#
    .SYNOPSIS
        From a drift report + a SELECTION, build the (entity,key) change list the
        engine applies via -Changes -- restricted to ONLY the selected drift, and
        with destructive removal ('extra') gated behind an explicit opt-in. PURE.

    .DESCRIPTION
        The remediation NEVER reimplements reconciliation: it just narrows what
        the engine acts on. The returned plan is the set of @{ Entity; Key } pairs
        to feed Invoke-PimEngine -Mode <delta|full> -Changes <plan> (commit). The
        caller maps the verdict here onto the engine call:
          - any selected 'missing'/'changed' -> -Mode Delta (create/update only).
          - a selected 'extra' is INCLUDED only when -AllowRemove is set, and the
            caller must run -Mode Full -Prune to actually remove it. Without
            -AllowRemove every EXPLICITLY-selected 'extra' is REFUSED (listed in
            .refused) so a single click can never destructively remove a live
            delegation; under -All extras are silently skipped (non-destructive).

        Selection: by drift KEY (the report's per-item key, optionally scoped as
        "<scope>|<key>") OR -All (every NON-extra item; 'extra' still needs
        -AllowRemove). An empty selection yields an empty plan (the engine then
        does nothing).

    .OUTPUTS
        @{ requiresPrune; changes=[ @{Entity;Key} ]; selected=[items];
           refused=[ @{scope;entity;key;type;reason} ]; counts=@{...} }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$DriftReport,
        [string[]]$SelectKeys = @(),     # drift item keys to remediate ("<scope>|<key>" or "<key>")
        [switch]$All,                    # select every non-extra drift item
        [switch]$AllowRemove             # opt-in: also remediate 'extra' (-> engine -Prune)
    )
    $allItems = @($DriftReport.items)
    $want = @{}
    foreach ($k in @($SelectKeys)) {
        $kk = "$k".Trim(); if ($kk) { $want[$kk.ToLowerInvariant()] = $true }
    }
    $changes  = New-Object System.Collections.Generic.List[object]
    $selected = New-Object System.Collections.Generic.List[object]
    $refused  = New-Object System.Collections.Generic.List[object]
    $seen     = @{}   # de-dupe (entity,key) for the engine -Changes list
    foreach ($it in $allItems) {
        $scopeKey = "$($it.scope)|$($it.key)"
        $isSelected = $All.IsPresent -or $want.ContainsKey("$scopeKey".ToLowerInvariant()) -or $want.ContainsKey("$($it.key)".Trim().ToLowerInvariant())
        if (-not $isSelected) { continue }
        if ($it.type -eq 'extra' -and -not $AllowRemove) {
            # Under -All we silently skip extras (non-destructive default); an
            # EXPLICIT key selection of an extra without -AllowRemove is refused
            # loudly so the operator knows it was not acted on.
            if (-not $All.IsPresent) {
                $refused.Add([pscustomobject]@{ scope = "$($it.scope)"; entity = "$($it.entity)"; key = "$($it.key)"; type = 'extra'; reason = 'removal of an extra (live-not-desired) delegation requires explicit opt-in (-AllowRemove / -Prune)' })
            }
            continue
        }
        $selected.Add($it)
        $dk = "$($it.entity)|$($it.key)".ToLowerInvariant()
        if (-not $seen.ContainsKey($dk)) {
            $seen[$dk] = $true
            $changes.Add([pscustomobject]@{ Entity = "$($it.entity)"; Key = "$($it.key)" })
        }
    }
    $selArr = @($selected.ToArray())
    $selExtra = @(@($selArr) | Where-Object { $_.type -eq 'extra' }).Count
    return [pscustomobject]@{
        requiresPrune = ($selExtra -gt 0)   # caller must use -Mode Full -Prune when true
        changes       = @($changes.ToArray())
        selected      = @($selArr)
        refused       = @($refused.ToArray())
        counts        = [pscustomobject]@{
            selected = @($selArr).Count
            missing  = @(@($selArr) | Where-Object { $_.type -eq 'missing' }).Count
            changed  = @(@($selArr) | Where-Object { $_.type -eq 'changed' }).Count
            extra    = $selExtra
            refused  = @($refused.ToArray()).Count
        }
    }
}
