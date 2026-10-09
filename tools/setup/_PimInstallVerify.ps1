#Requires -Version 5.1
<#
.SYNOPSIS
  INSTALL-HARDEN-1 (PIM REQUIREMENTS §99, owner 2026-10-08) -- the PURE parts of the END-OF-INSTALL VERIFY and of the
  alert-recipient default. Offline-tested in tests/Test-PimInstallVerify.ps1.

.DESCRIPTION
  Owner: "make sure to [update the] install script with findings from today so it will not happen again. make sure that
  customers requesting a trial version will not have these issues". The 2026-10-08 installs ended "done" with no
  SuperAdmin (a build interrupted inside 'hosting' and resumed after it), no updater, no alert recipients and a mail
  sender only one of the two sending identities could use. Each was a step that had run -- or had been skipped -- without
  anything checking the RESULT. So every install path (single tenant, managing + managed tenant, the guided/trial install)
  ends with ONE verify that reads the result back, repairs what it can, prints one table and refuses "done" when a REQUIRED
  line fails.

  This file decides; Confirm-PimInstall.ps1 gathers (az / Graph / SQL / Exchange) and repairs. Nothing here touches Azure.

  A line is @{ id; title; required; state = ok | repaired | warning | failed | info; detail; fix }.
  The install is 'done' only when no REQUIRED line is 'failed'. 'warning' never blocks (it carries the exact next step).
#>

# The stable line ids (support tickets and Invardia's status page refer to them), in table order, with the title shown.
$script:PimInstallVerifyLines = [ordered]@{
    'superadmins'        = 'SuperAdmins in the PIM Manager store'
    'updater'            = 'Updater job + update ring'
    'licence'            = 'Licence registered (+ install key)'
    'mailsender'         = 'Mail sender + every sending identity in scope'
    'alerting'           = 'Alert recipients'
    'engine-graph'       = 'Engine Microsoft Graph permissions'
    'engine-root-reader' = 'Engine Reader at the tenant root'
    'manager-rg-reader'  = 'Manager Reader on the PIM resource group'
    'engine-first-run'   = 'Engine first run'
    'engine-size'        = 'Engine job sized for the tenant'
    'easyauth'           = 'Sign-in (Easy Auth) + SuperAdmins allowed'
    'sql-host-rule'      = 'SQL setup host rule closed'
    'msp-registered'     = 'Registered on the managing tenant'
    'msp-subnet'         = 'Pull subnet allowed on the managing tenant'
    'msp-first-pull'     = 'First pull from the managing tenant'
}

function Get-PimInstallVerifyLineIds {
    <# PURE. The line ids a role checks, in order. Single + Master: the common lines. Slave (managed tenant): + the three MSP lines. #>
    param([ValidateSet('Single', 'Master', 'Slave')][string]$Role = 'Single')
    $ids = @('superadmins', 'updater', 'licence', 'mailsender', 'alerting', 'engine-graph', 'engine-root-reader', 'manager-rg-reader', 'engine-first-run', 'engine-size', 'easyauth', 'sql-host-rule')
    if ($Role -eq 'Slave') { $ids += @('msp-registered', 'msp-subnet', 'msp-first-pull') }
    return $ids
}

function New-PimInstallVerifyRow {
    param([string]$Id, [string]$State, [string]$Detail = '', [string]$Fix = '', [bool]$Required = $true)
    $t = if ($script:PimInstallVerifyLines.Contains($Id)) { $script:PimInstallVerifyLines[$Id] } else { $Id }
    [pscustomobject][ordered]@{ id = $Id; title = $t; required = $Required; state = $State; detail = "$Detail"; fix = "$Fix" }
}

function Get-PimFactValue {
    # PURE. A field of a fact that may be a hashtable or an object; $null when absent.
    param([AllowNull()]$Fact, [string]$Name)
    if ($null -eq $Fact) { return $null }
    if ($Fact -is [System.Collections.IDictionary]) { if ($Fact.Contains($Name)) { return $Fact[$Name] }; return $null }
    $p = $Fact.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Get-PimManagerAccessGap {
    <#
      PURE. Which of the wanted SuperAdmins are NOT a SuperAdmin in pim.Settings['ManagerAccess'] (case-insensitive).
      -Stored: the managerAccess entries (@{ identity; role }). Returns the missing UPNs (empty = all present).
    #>
    param([object[]]$Stored = @(), [string[]]$Want = @())
    $have = @{}
    foreach ($e in @($Stored | Where-Object { $_ })) {
        if ("$(Get-PimFactValue $e 'role')".Trim() -eq 'SuperAdmin') { $have["$(Get-PimFactValue $e 'identity')".Trim().ToLowerInvariant()] = $true }
    }
    return @(@($Want | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) | Where-Object { -not $have.ContainsKey($_.ToLowerInvariant()) })
}

function Resolve-PimAlertRecipientsPlan {
    <#
      PURE. INSTALL-HARDEN-1 item 5 -- who gets the alerts after an install. "Alert recipients EMPTY after install (no alert
      reached anyone)": nothing ever wrote pim.Settings['Alerting'].recipients, so every alert rendered and went nowhere.
        * the stored list is NOT empty            -> 'keep' (an install never overwrites what an administrator chose)
        * -Explicit (alertRecipients / -AlertRecipients; the trial: the requester's address) -> 'set' those
        * else the SuperAdmins' MAIL addresses   -> 'set' (resolved UPN -> mail by the caller; one without a mailbox is skipped)
        * nothing usable                          -> 'none' (a warning with the GUI path, never a guess)
      -SuperAdminMail: @(@{ upn; mail }) -- mail '' = no mailbox (skipped, named in the reason).
      Returns @{ action = keep|set|none; recipients[]; skipped[]; reason }.
    #>
    param([string[]]$Current = @(), [string[]]$Explicit = @(), [object[]]$SuperAdminMail = @())
    $isMail = { param($s) "$s" -match '^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$' }
    $cur = @(@($Current) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($cur.Count) { return @{ action = 'keep'; recipients = $cur; skipped = @(); reason = "already set ($($cur -join ', ')) -- left as it is" } }
    $exp = @(@($Explicit) | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $badExp = @($exp | Where-Object { -not (& $isMail $_) })
    $exp = @($exp | Where-Object { & $isMail $_ } | Select-Object -Unique)
    if ($exp.Count) { return @{ action = 'set'; recipients = $exp; skipped = $badExp; reason = "from the install's alert recipients: $($exp -join ', ')" } }
    $rec = New-Object System.Collections.Generic.List[string]; $skipped = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($SuperAdminMail | Where-Object { $_ })) {
        $m = "$(Get-PimFactValue $s 'mail')".Trim(); $u = "$(Get-PimFactValue $s 'upn')".Trim()
        if ($m -and (& $isMail $m)) { if (-not $rec.Contains($m)) { $rec.Add($m) } } elseif ($u) { $skipped.Add($u) }
    }
    if ($rec.Count) { return @{ action = 'set'; recipients = @($rec); skipped = @($skipped); reason = "the SuperAdmins' mailboxes: $(@($rec) -join ', ')$(if ($skipped.Count) { " (no mailbox, skipped: $(@($skipped) -join ', '))" })" } }
    return @{ action = 'none'; recipients = @(); skipped = @($skipped)
              reason = $(if ($skipped.Count) { "no SuperAdmin has a mailbox ($(@($skipped) -join ', ')) and no alert recipients were given" } else { 'no alert recipients were given and no SuperAdmin is known' }) }
}

function ConvertTo-PimAlertingValue {
    <#
      PURE. The pim.Settings['Alerting'] value with -Recipients, in EXACTLY the shape the Manager's PUT /api/alerting writes
      (Open-PimManager.ps1 Set-PimAlertingConfig): recipients, digestRecipients, tierReportRecipients, events, webhookUrl,
      webhookKind. Everything already stored (the per-report lists, the event switches, the webhook) is KEPT; a missing
      event defaults ON, as the Manager does.
    #>
    param([AllowNull()]$Current, [string[]]$Recipients = @(),
          [string[]]$EventCatalog = @('engine-failure', 'drift', 'expiring-access', 'break-glass', 'sessions-revoked', 'coverage', 'target-missing', 'pending-uncommitted'))
    $cur = $Current
    if ($cur -is [string]) { try { $cur = $cur | ConvertFrom-Json } catch { $cur = $null } }
    $list = { param($v) @(@($v) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
    $ev = [ordered]@{}
    $curEv = Get-PimFactValue $cur 'events'
    foreach ($e in $EventCatalog) {
        $v = Get-PimFactValue $curEv $e
        $ev[$e] = $(if ($null -ne $v) { [bool]$v } else { $true })
    }
    $kind = "$(Get-PimFactValue $cur 'webhookKind')".Trim().ToLowerInvariant(); if ($kind -notin 'teams', 'generic') { $kind = 'generic' }
    [ordered]@{
        recipients           = @(& $list $Recipients)
        digestRecipients     = @(& $list (Get-PimFactValue $cur 'digestRecipients'))
        tierReportRecipients = @(& $list (Get-PimFactValue $cur 'tierReportRecipients'))
        events               = $ev
        webhookUrl           = "$(Get-PimFactValue $cur 'webhookUrl')".Trim()
        webhookKind          = $kind
    }
}

function Test-PimEasyAuthSignInAllowed {
    <#
      PURE. May every SuperAdmin sign in to the Manager?
        -Enabled            : the Container App's authConfig platform.enabled
        -AssignmentRequired : the Easy Auth application's appRoleAssignmentRequired (false = every member account may)
        -AssignedPrincipalIds : the principal ids in its appRoleAssignedTo (users and groups)
        -SuperAdmins        : @(@{ upn; id; groupIds[] }) -- id '' = not found in the directory
      Returns @{ ok; enabled; notAllowed[]; reason }.
    #>
    param([bool]$Enabled, [bool]$AssignmentRequired, [string[]]$AssignedPrincipalIds = @(), [object[]]$SuperAdmins = @())
    if (-not $Enabled) { return @{ ok = $false; enabled = $false; notAllowed = @(); reason = 'Easy Auth is NOT enabled on the PIM Manager -- it would answer without a sign-in' } }
    $assigned = @{}; foreach ($i in @($AssignedPrincipalIds)) { if ("$i".Trim()) { $assigned["$i".Trim().ToLowerInvariant()] = $true } }
    $no = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($SuperAdmins | Where-Object { $_ })) {
        $upn = "$(Get-PimFactValue $s 'upn')".Trim(); $id = "$(Get-PimFactValue $s 'id')".Trim()
        if (-not $id) { $no.Add("$upn (not found in the directory)"); continue }
        if (-not $AssignmentRequired) { continue }
        $hit = $assigned.ContainsKey($id.ToLowerInvariant())
        if (-not $hit) { foreach ($g in @(Get-PimFactValue $s 'groupIds')) { if ($assigned.ContainsKey("$g".Trim().ToLowerInvariant())) { $hit = $true; break } } }
        if (-not $hit) { $no.Add($upn) }
    }
    if ($no.Count) { return @{ ok = $false; enabled = $true; notAllowed = @($no); reason = "may NOT sign in: $(@($no) -join ', ')" } }
    return @{ ok = $true; enabled = $true; notAllowed = @(); reason = $(if ($AssignmentRequired) { 'enabled; every SuperAdmin is assigned (directly or through a group)' } else { 'enabled; every member account of the tenant may sign in' }) }
}

function Get-PimInstallVerifyRows {
    <#
      PURE. One row per line of -Role, from the gathered -Facts (keyed by line id; a missing fact = could not be read).
      -Fix: a hashtable of line id -> the exact fix command (built by the gatherer with this environment's values).
      -LicenceExpected: Pro / trial / MSP (the licence line is REQUIRED); otherwise it is 'info' (free edition).
    #>
    param([ValidateSet('Single', 'Master', 'Slave')][string]$Role = 'Single', [hashtable]$Facts = @{}, [hashtable]$Fix = @{}, [bool]$LicenceExpected = $false)
    $rows = New-Object System.Collections.Generic.List[object]
    $fx = { param($id) if ($Fix.ContainsKey($id)) { "$($Fix[$id])" } else { '' } }
    foreach ($id in (Get-PimInstallVerifyLineIds -Role $Role)) {
        $f = if ($Facts.ContainsKey($id)) { $Facts[$id] } else { $null }
        $repaired = [bool](Get-PimFactValue $f 'repaired')
        $okState = if ($repaired) { 'repaired' } else { 'ok' }
        $readable = ($null -ne $f) -and ((Get-PimFactValue $f 'readable') -ne $false)
        $readErr = "$(Get-PimFactValue $f 'error')".Trim()
        # a STORE read that failed (Confirm-PimInstall marks it store = $true) is worded as unreadable -- "not checked (could
        # not read the store: <reason>)" -- never as the thing being missing; a required line stays not-done (fail closed).
        $unread = if ($null -ne $f -and [bool](Get-PimFactValue $f 'store')) { "not checked (could not read the store$(if ($readErr) { ": $readErr" }))" }
                  else { "could not be read$(if ($readErr) { ": $readErr" })" }
        switch ($id) {
            'superadmins' {
                if (-not $readable) { $rows.Add((New-PimInstallVerifyRow $id 'failed' $unread (& $fx $id))); break }
                $want = @(Get-PimFactValue $f 'want' | Where-Object { "$_".Trim() })
                if (-not $want.Count) { $rows.Add((New-PimInstallVerifyRow $id 'failed' 'no SuperAdmin was named for this install -- nobody can administer it' (& $fx $id))); break }
                $miss = @(Get-PimManagerAccessGap -Stored @(Get-PimFactValue $f 'stored') -Want $want)
                if ($miss.Count) { $rows.Add((New-PimInstallVerifyRow $id 'failed' "NOT a SuperAdmin: $($miss -join ', ')" (& $fx $id))) }
                else { $rows.Add((New-PimInstallVerifyRow $id $okState "SuperAdmin: $($want -join ', ')$(if ($repaired) { ' (written by the verify)' })")) }
            }
            'updater' {
                if ([bool](Get-PimFactValue $f 'notApplicable')) { $rows.Add((New-PimInstallVerifyRow $id 'info' "$(Get-PimFactValue $f 'reason')" '' $false)); break }
                if (-not $readable) { $rows.Add((New-PimInstallVerifyRow $id 'failed' $unread (& $fx $id))); break }
                if (-not [bool](Get-PimFactValue $f 'jobExists')) { $rows.Add((New-PimInstallVerifyRow $id 'failed' 'the updater job does not exist -- this environment will never update itself' (& $fx $id))); break }
                $ring = "$(Get-PimFactValue $f 'ringEnv')".Trim(); $want = "$(Get-PimFactValue $f 'wantRing')".Trim()
                if (-not $ring) { $rows.Add((New-PimInstallVerifyRow $id 'failed' 'the updater job carries no PIM_UPDATE_RING -- the ring gate refuses every roll' (& $fx $id))); break }
                if ($want -and $ring -ne $want) { $rows.Add((New-PimInstallVerifyRow $id 'failed' "the updater job is on ring $ring, the install asked for ring $want" (& $fx $id))); break }
                if ([bool](Get-PimFactValue $f 'seedSupported')) {
                    $sr = "$(Get-PimFactValue $f 'stateRing')".Trim()
                    if (-not $sr) { $rows.Add((New-PimInstallVerifyRow $id 'failed' "job ring $ring, but the store has no update-state record (the Manager shows 'not recorded')" (& $fx $id))); break }
                }
                $rows.Add((New-PimInstallVerifyRow $id $okState "job exists, ring $ring read back$(if ([bool](Get-PimFactValue $f 'seedSupported')) { '; update-state record present' })$(if ($repaired) { ' (re-installed by the verify)' })"))
            }
            'licence' {
                if (-not $LicenceExpected) { $rows.Add((New-PimInstallVerifyRow $id 'info' 'free edition -- no licence expected' '' $false)); break }
                if (-not $readable) { $rows.Add((New-PimInstallVerifyRow $id 'failed' $unread (& $fx $id))); break }
                if (-not [bool](Get-PimFactValue $f 'present')) { $rows.Add((New-PimInstallVerifyRow $id 'failed' 'no licence is registered -- the Pro features are off' (& $fx $id))); break }
                $st = "$(Get-PimFactValue $f 'status')".Trim()
                $why = "$(Get-PimFactValue $f 'reason')".Trim()
                if ($st -and $st -notin 'Valid', 'Grace') { $rows.Add((New-PimInstallVerifyRow $id 'failed' "the licence is $st$(if ($why) { " ($why)" })" (& $fx $id))); break }
                if ([bool](Get-PimFactValue $f 'installKey')) { $rows.Add((New-PimInstallVerifyRow $id 'ok' 'registered; install key stored')); break }
                if ([bool](Get-PimFactValue $f 'claimQueued')) { $rows.Add((New-PimInstallVerifyRow $id 'warning' 'registered; the install key claim is queued -- the engine claims it on its next run (about 5 minutes)' (& $fx $id))); break }
                $rows.Add((New-PimInstallVerifyRow $id 'failed' 'registered, but no install key is stored or queued -- Pro updates cannot be pulled' (& $fx $id)))
            }
            'mailsender' {
                # Owner 2026-10-08: "mail is optional" -- an incomplete mail setup is ALWAYS a warning with the exact fix (Get Started >
                # Mail sender shows each prerequisite), never a failed install.
                if (-not $readable) { $rows.Add((New-PimInstallVerifyRow $id 'warning' $unread (& $fx $id) $false)); break }
                $sender = "$(Get-PimFactValue $f 'sender')".Trim()
                $deferred = "$(Get-PimFactValue $f 'deferredReason')".Trim()
                if (-not $sender) {
                    if ($deferred) { $rows.Add((New-PimInstallVerifyRow $id 'warning' "no mail sender yet ($deferred) -- the environment is MAIL-MUTE until it is set" (& $fx $id))) }
                    else { $rows.Add((New-PimInstallVerifyRow $id 'warning' 'no mail sender is set -- TAPs and alerts are rendered and delivered nowhere' (& $fx $id))) }
                    break
                }
                # INSTALL-FIX-EVIDA (100.25 item 4): MailSender is the mailbox's UPN on purpose (BUG-296: Graph sends by UPN), often on the
                # initial domain -- but the customer chose the PRIMARY SMTP address (name@their domain). Show that one, the UPN as detail.
                $addr = "$(Get-PimFactValue $f 'address')".Trim()
                if ($addr -and $addr -ine $sender) { $sender = "$addr (mailbox UPN $sender)" }
                if (-not [bool](Get-PimFactValue $f 'exoReachable')) {
                    $rows.Add((New-PimInstallVerifyRow $id 'warning' "sender $sender set; Exchange is not reachable for the installer, so the send rights could not be tested$(if ("$(Get-PimFactValue $f 'exoError')".Trim()) { " ($(Get-PimFactValue $f 'exoError'))" })" (& $fx $id))); break
                }
                $ids = @(Get-PimFactValue $f 'identities' | Where-Object { $_ })
                if (-not $ids.Count) { $rows.Add((New-PimInstallVerifyRow $id 'warning' "sender $sender set, but no sending identity (engine job, Manager) was found" (& $fx $id))); break }
                $out = @($ids | Where-Object { (Get-PimFactValue $_ 'inScope') -ne $true } | ForEach-Object { "$(Get-PimFactValue $_ 'label')" })
                if ($out.Count) { $rows.Add((New-PimInstallVerifyRow $id 'warning' "sender ${sender}: NOT in scope for $($out -join ', ') -- Exchange refuses their mail" (& $fx $id))) }
                else { $rows.Add((New-PimInstallVerifyRow $id 'ok' "sender $sender; in scope for $(@($ids | ForEach-Object { "$(Get-PimFactValue $_ 'label')" }) -join ', ')")) }
            }
            'alerting' {
                if (-not $readable) { $rows.Add((New-PimInstallVerifyRow $id 'failed' $unread (& $fx $id))); break }
                $r = @(Get-PimFactValue $f 'recipients' | Where-Object { "$_".Trim() })
                if ($r.Count) { $rows.Add((New-PimInstallVerifyRow $id $okState "$($r -join ', ')$(if ($repaired) { ' (set by the verify)' })")) }
                else { $rows.Add((New-PimInstallVerifyRow $id 'failed' "EMPTY -- no alert reaches anyone$(if ("$(Get-PimFactValue $f 'reason')".Trim()) { " ($(Get-PimFactValue $f 'reason'))" })" (& $fx $id))) }
            }
            'engine-graph' {
                if (-not $readable) { $rows.Add((New-PimInstallVerifyRow $id 'failed' $unread (& $fx $id))); break }
                $miss = @(Get-PimFactValue $f 'missing' | Where-Object { "$_".Trim() })
                $n = [int](Get-PimFactValue $f 'required')
                if ($miss.Count) { $rows.Add((New-PimInstallVerifyRow $id 'failed' "$($miss.Count) of $n missing: $($miss -join ', ')" (& $fx $id))) }
                else { $rows.Add((New-PimInstallVerifyRow $id 'ok' "all $n required app roles held")) }
            }
            'engine-root-reader' {
                if (-not $readable -and -not [bool](Get-PimFactValue $f 'refused')) { $rows.Add((New-PimInstallVerifyRow $id 'failed' $unread (& $fx $id))); break }
                if ((Get-PimFactValue $f 'reader') -eq $true) { $rows.Add((New-PimInstallVerifyRow $id $okState "Reader at $(Get-PimFactValue $f 'scope')$(if ($repaired) { ' (granted by the verify)' })")) }
                elseif ([bool](Get-PimFactValue $f 'refused')) {
                    # §97 (owner 2026-10-08): the root grant NEVER stops an install -- assigning at the tenant root needs a
                    # right there the installer often does not hold. The grant was attempted and refused: a WARNING with the
                    # exact command for a Global Administrator (Get Started > Engine permissions shows the same).
                    $rows.Add((New-PimInstallVerifyRow $id 'warning' 'NO Reader at the tenant root, and the installer may not grant it there -- Discovery cannot see management groups or subscriptions until a Global Administrator runs the command' (& $fx $id)))
                }
                # owner 2026-10-08 ("rgr 1"): the root Reader follows the mail pattern -- a WARNING with the exact command, never a stop.
                else { $rows.Add((New-PimInstallVerifyRow $id 'warning' 'NO Reader at the tenant root -- Discovery cannot see management groups or subscriptions until a Global Administrator runs the command' (& $fx $id))) }
            }
            'manager-rg-reader' {
                # PIM 100.22 (b) (owner 2026-10-09): the Manager's Reader on the PIM resource group ONLY -- the Environment report
                # reads the architecture with it. Never a stop (a report, not the engine): missing after the one repair attempt =
                # a WARNING with the exact command; not readable = a WARNING too.
                if (-not $readable) { $rows.Add((New-PimInstallVerifyRow $id 'warning' $unread (& $fx $id) $false)); break }
                if ((Get-PimFactValue $f 'reader') -eq $true) { $rows.Add((New-PimInstallVerifyRow $id $okState "Reader at $(Get-PimFactValue $f 'scope')$(if ($repaired) { ' (granted by the verify)' })" '' $false)) }
                else { $rows.Add((New-PimInstallVerifyRow $id 'warning' 'NO Reader on the PIM resource group -- the Environment report cannot read the architecture until it is granted (resource group only, never wider)' (& $fx $id) $false)) }
            }
            'engine-first-run' {
                # Informational follow-up, never a stop: right after an install the tick may simply not have run yet (5 min).
                $st = "$(Get-PimFactValue $f 'status')".Trim()
                if (-not $readable) { $rows.Add((New-PimInstallVerifyRow $id 'warning' $unread (& $fx $id) $false)); break }
                if ($st -eq 'Succeeded') { $rows.Add((New-PimInstallVerifyRow $id 'ok' "the engine job's latest run succeeded$(if ("$(Get-PimFactValue $f 'at')".Trim()) { " ($(Get-PimFactValue $f 'at'))" })" '' $false)) }
                elseif (-not $st) { $rows.Add((New-PimInstallVerifyRow $id 'warning' 'the engine job has not run yet -- it starts within 5 minutes; check the PIM Manager Home page' (& $fx $id) $false)) }
                else { $rows.Add((New-PimInstallVerifyRow $id 'warning' "the engine job's latest run: $st -- open the PIM Manager Home page for the reason" (& $fx $id) $false)) }
            }
            'engine-size' {
                # 100.31 / framework 12.15: a WARNING (never a stop) when the engine job is below the size its RECORDED tenant
                # count needs, with the az command for THAT tier. Fact: { readable; undersized; reason; command } from
                # Test-PimJobUndersized (engine/_shared/PIM-TenantSizing.ps1). The updater raises it too, on its next run.
                if (-not $readable) { $rows.Add((New-PimInstallVerifyRow $id 'warning' $unread '' $false)); break }
                $cmd = "$(Get-PimFactValue $f 'command')".Trim()
                if ([bool](Get-PimFactValue $f 'undersized')) {
                    $rows.Add((New-PimInstallVerifyRow $id 'warning' "UNDERSIZED: $(Get-PimFactValue $f 'reason') -- it can run out of memory (the next update raises it by itself)" $(if ($cmd) { $cmd } else { & $fx $id }) $false))
                } else { $rows.Add((New-PimInstallVerifyRow $id 'ok' "$(Get-PimFactValue $f 'reason')" '' $false)) }
            }
            'easyauth' {
                if (-not $readable) { $rows.Add((New-PimInstallVerifyRow $id 'failed' $unread (& $fx $id))); break }
                if ([bool](Get-PimFactValue $f 'ok')) { $rows.Add((New-PimInstallVerifyRow $id 'ok' "$(Get-PimFactValue $f 'reason')")) }
                else { $rows.Add((New-PimInstallVerifyRow $id 'failed' "$(Get-PimFactValue $f 'reason')" (& $fx $id))) }
            }
            'sql-host-rule' {
                if ([bool](Get-PimFactValue $f 'notApplicable')) { $rows.Add((New-PimInstallVerifyRow $id 'info' "$(Get-PimFactValue $f 'reason')" '' $false)); break }
                if (-not $readable) { $rows.Add((New-PimInstallVerifyRow $id 'failed' $unread (& $fx $id))); break }
                if ([bool](Get-PimFactValue $f 'present')) {
                    if ("$(Get-PimFactValue $f 'owner')" -eq 'caller') { $rows.Add((New-PimInstallVerifyRow $id 'ok' "open for this build; its last step '$(Get-PimFactValue $f 'closingStep')' removes it and reads it back (the build fails if it stays)")) }
                    else { $rows.Add((New-PimInstallVerifyRow $id 'failed' "'AllowSetupHost' is still on the SQL server -- the installing host keeps SQL network access" (& $fx $id))) }
                } else { $rows.Add((New-PimInstallVerifyRow $id $okState "no 'AllowSetupHost' rule$(if ($repaired) { ' (removed by the verify, read back)' })")) }
            }
            { $_ -in 'msp-registered', 'msp-subnet' } {
                $v = Get-PimFactValue $f 'value'
                if (-not $readable -or $null -eq $v) { $rows.Add((New-PimInstallVerifyRow $id 'warning' "the managing tenant cannot be read from this tenant -- $(Get-PimFactValue $f 'step')" (& $fx $id))); break }
                if ($v -eq $true) { $rows.Add((New-PimInstallVerifyRow $id 'ok' "$(Get-PimFactValue $f 'detail')")) }
                else { $rows.Add((New-PimInstallVerifyRow $id 'failed' "$(Get-PimFactValue $f 'detail')" (& $fx $id))) }
            }
            'msp-first-pull' {
                if (-not $readable) { $rows.Add((New-PimInstallVerifyRow $id 'warning' $unread (& $fx $id))); break }
                $st = "$(Get-PimFactValue $f 'status')".Trim()
                if ($st -eq 'Succeeded') { $rows.Add((New-PimInstallVerifyRow $id 'ok' "the pull job's latest run succeeded$(if ("$(Get-PimFactValue $f 'at')".Trim()) { " ($(Get-PimFactValue $f 'at'))" })")) }
                elseif (-not $st) { $rows.Add((New-PimInstallVerifyRow $id 'warning' 'the pull job has not run yet -- it pulls once the managing tenant allows this subnet' (& $fx $id))) }
                else { $rows.Add((New-PimInstallVerifyRow $id 'warning' "the pull job's latest run: $st -- usually the managing tenant has not allowed this subnet yet" (& $fx $id))) }
            }
        }
    }
    return @($rows.ToArray())
}

function Get-PimInstallVerifyVerdict {
    <# PURE. @{ done; failed[]; warnings[]; sentence }. done = no REQUIRED line failed. #>
    param([object[]]$Rows = @())
    $failed = @(@($Rows) | Where-Object { $_.required -and $_.state -eq 'failed' } | ForEach-Object { $_.id })
    $warn = @(@($Rows) | Where-Object { $_.state -eq 'warning' } | ForEach-Object { $_.id })
    $sentence = if ($failed.Count) { "The installation is NOT done: $($failed.Count) required check(s) failed ($($failed -join ', ')). Run the fix shown for each, then run the verify again." }
                elseif ($warn.Count) { "The installation is done, with $($warn.Count) follow-up(s): $($warn -join ', ')." }
                else { 'The installation is done: every check passed.' }
    return @{ done = (-not $failed.Count); failed = $failed; warnings = $warn; sentence = $sentence }
}

function Format-PimInstallVerifyTable {
    <# PURE. The ONE table the verify prints (lines of text): state, check, detail; the fix under each line that has one. #>
    param([object[]]$Rows = @())
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add(('  {0,-9} {1,-46} {2}' -f 'STATE', 'CHECK', 'DETAIL'))
    $out.Add(('  {0,-9} {1,-46} {2}' -f '-----', '-----', '------'))
    foreach ($r in @($Rows)) {
        $st = "$($r.state)".ToUpperInvariant(); if (-not $r.required -and $r.state -eq 'info') { $st = 'INFO' }
        $out.Add(('  {0,-9} {1,-46} {2}' -f $st, "$($r.title)", "$($r.detail)"))
        if ("$($r.fix)".Trim() -and $r.state -in 'failed', 'warning') { foreach ($l in ("$($r.fix)" -split "`r?`n")) { $out.Add("              fix: $l") } }
    }
    return @($out.ToArray())
}
