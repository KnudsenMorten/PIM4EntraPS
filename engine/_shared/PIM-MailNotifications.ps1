#Requires -Version 5.1
<#
  PIM-MailNotifications.ps1 -- WHO gets WHICH report or alert, and WHERE its button leads (framework DOCS/REQUIREMENTS.md
  §12.11 MAIL-2 items 1, 2, 5, 6; PIM REQUIREMENTS §100.5).

  * The CATALOG of every report and alert PIM sends (Get-PimMailReportCatalog) -- the Notifications page, the
    Settings > Reports view and the senders all read this one list.
  * Per-recipient PREFERENCES, SQL pim.Settings['MailNotifications'] (PIM v2 is SQL-only):
        { recipients: [ { address, audience: soc|posture|manager, reports: { <type>: bool }, alerts: { <event>: bool },
                          severityFloor: info|warning|critical } ],
          reports:    { <type>: { attach: link|pdf } } }
    A recipient with no stored entry gets EVERYTHING, as before this existed (no regression: v1 -> v2 rule). The senders
    read it at SEND time (Select-PimNotificationRecipients) -- a switch in the GUI takes effect on the next mail.
  * AUDIENCE links (Get-PimAudienceLink): the one blue button deep-links to the page that audience works from.
  * AUTO-READER (Merge-PimManagerReaderEntries): a recipient who is not a Manager user becomes a Reader, so the links work.
    PURE: it only ever ADDS Reader entries for unknown identities and never touches an existing entry.
  Everything here is PURE except Get-PimMailNotificationPrefsFromStore (a store read that never throws).
  ASCII only; PS 5.1-safe.
#>
Set-StrictMode -Off

function Get-PimMailAudiences { @('soc', 'posture', 'manager') }
function Get-PimMailAudienceLabel {
    param([string]$Audience)
    switch ("$Audience") { 'soc' { 'SOC analyst' } 'posture' { 'Posture / access owner' } default { 'Manager' } }
}
function Get-PimMailSeverities { @('info', 'warning', 'critical') }
function Get-PimMailSeverityRank { param([string]$Severity) switch ("$Severity".ToLowerInvariant()) { 'critical' { 2 } 'warning' { 1 } default { 0 } } }

function Get-PimMailReportCatalog {
    <#
      Every report and alert PIM sends. kind: 'report' (a scheduled digest, per-recipient on/off + attach-PDF),
      'alert' (an event, per-recipient on/off + severity floor), 'transactional' (sent to the person a request concerns --
      listed in the central view, not switchable per recipient: an approver must get the approval request).
      job = the scheduler job that sends it ('' = raised by events); recipientList = the Alerting list it goes to.
    #>
    @(
        [pscustomobject]@{ type = 'daily-summary'; kind = 'report'; label = 'Daily changes'; job = 'daily-summary'; recipientList = 'digestRecipients'; severity = ''
            plain = 'Every delegation, admin account and safety change of the last 24 hours: who changed what, before and after, with anything risky first.' }
        [pscustomobject]@{ type = 'tier-report'; kind = 'report'; label = 'Tier 0 / Tier 1 access report'; job = 'tier-report'; recipientList = 'tierReportRecipients'; severity = ''
            plain = 'Everyone who holds Tier 0 or Tier 1 access, with the highest tier and the levels they hold.' }
        [pscustomobject]@{ type = 'get-started'; kind = 'report'; label = 'Get Started not complete'; job = 'daily-summary'; recipientList = 'recipients'; severity = ''
            plain = 'Once a day while a required Get Started step is open: which steps, why they matter, a button to each. Stops by itself when they are done.' }
        [pscustomobject]@{ type = 'engine-failure'; kind = 'alert'; label = 'Engine / job run failure'; job = ''; recipientList = 'recipients'; severity = 'critical'; plain = 'A run of the engine or a scheduled job failed.' }
        [pscustomobject]@{ type = 'break-glass'; kind = 'alert'; label = 'Break-glass / emergency override used'; job = ''; recipientList = 'recipients'; severity = 'critical'; plain = 'Somebody used the emergency override or a break-glass account.' }
        [pscustomobject]@{ type = 'drift'; kind = 'alert'; label = 'Configuration drift detected'; job = 'drift-snapshot'; recipientList = 'recipients'; severity = 'warning'; plain = 'Live access differs from what is defined.' }
        [pscustomobject]@{ type = 'coverage'; kind = 'alert'; label = 'New gaps, orphans or unmanaged privileged groups'; job = ''; recipientList = 'recipients'; severity = 'warning'; plain = 'The coverage check found something new that nobody manages.' }
        [pscustomobject]@{ type = 'target-missing'; kind = 'alert'; label = 'Delegation targets that no longer exist'; job = ''; recipientList = 'recipients'; severity = 'warning'; plain = 'An Azure resource or role a delegation points at is gone.' }
        [pscustomobject]@{ type = 'sessions-revoked'; kind = 'alert'; label = 'Sign-in sessions revoked'; job = ''; recipientList = 'recipients'; severity = 'warning'; plain = 'Sessions of an account were revoked.' }
        [pscustomobject]@{ type = 'expiring-access'; kind = 'alert'; label = 'Access expiring soon'; job = 'reminders'; recipientList = 'recipients'; severity = 'info'; plain = 'Admin accounts or assignments reach their end date soon.' }
        [pscustomobject]@{ type = 'pending-uncommitted'; kind = 'alert'; label = 'Changes staged but never committed'; job = ''; recipientList = 'recipients'; severity = 'info'; plain = 'Staged changes or queued actions are older than a day.' }
        [pscustomobject]@{ type = 'approval-escalation'; kind = 'transactional'; label = 'Approval reminders and escalations'; job = 'escalations'; recipientList = ''; severity = ''; plain = 'Sent to the approvers of each waiting request.' }
        [pscustomobject]@{ type = 'access-review-reminder'; kind = 'transactional'; label = 'Access review reminders'; job = ''; recipientList = ''; severity = ''; plain = 'Sent to the reviewers of an open access review.' }
    )
}

function Get-PimAlertSeverity {
    # The severity of an alert event (the per-recipient floor compares against it). Unknown events are 'warning'.
    param([string]$Event)
    $c = @(Get-PimMailReportCatalog | Where-Object { $_.kind -eq 'alert' -and $_.type -eq "$Event" }) | Select-Object -First 1
    if ($c -and "$($c.severity)".Trim()) { return "$($c.severity)" }
    return 'warning'
}

function Get-PimMailPrefField {
    param([object]$Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] }; return $null }
    if ($Obj -is [string]) { return $null }
    $p = $Obj.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Test-PimMailPrefFalse {
    # An explicit OFF: $false, 'false', 0, 'off', 'no'. Anything else (including absent) is ON.
    param([object]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return (-not $Value) }
    return ("$Value".Trim().ToLowerInvariant() -in @('false', '0', 'off', 'no'))
}

function ConvertTo-PimMailNotificationPrefs {
    <#
      PURE. Normalise a stored MailNotifications value (JSON text, object or dictionary) to
        [ordered]@{ recipients = @([ordered]@{ address; audience; reports; alerts; severityFloor }); reports = [ordered]@{ <type> = @{ attach } } }
      Unknown report / alert types and invalid addresses are dropped; an unknown audience is 'manager', an unknown floor
      'info', an unknown attach 'link'. Duplicate addresses: the LAST one wins (a re-save replaces).
    #>
    param([AllowNull()][object]$Raw)
    $v = $Raw
    for ($i = 0; $i -lt 2 -and $v -is [string]; $i++) { if ("$v".Trim()) { try { $v = $v | ConvertFrom-Json } catch { $v = $null } } else { $v = $null } }
    $cat = @(Get-PimMailReportCatalog)
    $reportTypes = @($cat | Where-Object { $_.kind -eq 'report' } | ForEach-Object { $_.type })
    $alertTypes = @($cat | Where-Object { $_.kind -eq 'alert' } | ForEach-Object { $_.type })
    $byAddr = [ordered]@{}
    foreach ($e in @(Get-PimMailPrefField $v 'recipients')) {
        if ($null -eq $e) { continue }
        $addr = "$(Get-PimMailPrefField $e 'address')".Trim()
        if ($addr -notmatch '^[^@\s;,]+@[^@\s;,]+\.[^@\s;,]+$') { continue }
        $aud = "$(Get-PimMailPrefField $e 'audience')".Trim().ToLowerInvariant(); if ($aud -notin (Get-PimMailAudiences)) { $aud = 'manager' }
        $floor = "$(Get-PimMailPrefField $e 'severityFloor')".Trim().ToLowerInvariant(); if ($floor -notin (Get-PimMailSeverities)) { $floor = 'info' }
        $rep = [ordered]@{}; $rIn = Get-PimMailPrefField $e 'reports'
        foreach ($t in $reportTypes) { $rep[$t] = -not (Test-PimMailPrefFalse (Get-PimMailPrefField $rIn $t)) }
        $al = [ordered]@{}; $aIn = Get-PimMailPrefField $e 'alerts'
        foreach ($t in $alertTypes) { $al[$t] = -not (Test-PimMailPrefFalse (Get-PimMailPrefField $aIn $t)) }
        $byAddr[$addr.ToLowerInvariant()] = [ordered]@{ address = $addr; audience = $aud; reports = $rep; alerts = $al; severityFloor = $floor }
    }
    $repCfg = [ordered]@{}; $rcIn = Get-PimMailPrefField $v 'reports'
    foreach ($t in $reportTypes) {
        $att = "$(Get-PimMailPrefField (Get-PimMailPrefField $rcIn $t) 'attach')".Trim().ToLowerInvariant()
        if ($att -notin @('link', 'pdf')) { $att = 'link' }
        $repCfg[$t] = [ordered]@{ attach = $att }
    }
    return [ordered]@{ recipients = @($byAddr.Values); reports = $repCfg }
}

function Get-PimRecipientNotificationPref {
    # PURE. The effective preference of ONE address: its stored entry, else the default (everything on, audience manager,
    # floor info) with stored=$false.
    param([object]$Prefs, [Parameter(Mandatory)][string]$Address)
    $p = ConvertTo-PimMailNotificationPrefs $Prefs   # idempotent on an already-normalised value
    $key = "$Address".Trim().ToLowerInvariant()
    foreach ($e in @(Get-PimMailPrefField $p 'recipients')) {
        if ("$(Get-PimMailPrefField $e 'address')".Trim().ToLowerInvariant() -eq $key) {
            $o = [ordered]@{}; foreach ($k in 'address', 'audience', 'reports', 'alerts', 'severityFloor') { $o[$k] = Get-PimMailPrefField $e $k }
            $o['stored'] = $true
            return $o
        }
    }
    $d = ConvertTo-PimMailNotificationPrefs @{ recipients = @(@{ address = 'default@example.invalid' }) }
    $o = [ordered]@{}; $e0 = @($d.recipients)[0]
    foreach ($k in 'audience', 'reports', 'alerts', 'severityFloor') { $o[$k] = $e0[$k] }
    $o['address'] = "$Address".Trim(); $o['stored'] = $false
    return $o
}

function Test-PimRecipientWants {
    <#
      PURE. Does this recipient want this mail? kind 'report': reports[type] is not OFF. kind 'alert': alerts[type] is not
      OFF AND the alert's severity reaches the recipient's floor. 'transactional' is always wanted (not switchable).
    #>
    param([Parameter(Mandatory)][object]$Pref, [Parameter(Mandatory)][string]$Type, [ValidateSet('report', 'alert', 'transactional')][string]$Kind = 'report', [string]$Severity = '')
    if ($Kind -eq 'transactional') { return $true }
    if ($Kind -eq 'report') { return (-not (Test-PimMailPrefFalse (Get-PimMailPrefField (Get-PimMailPrefField $Pref 'reports') $Type))) }
    if (Test-PimMailPrefFalse (Get-PimMailPrefField (Get-PimMailPrefField $Pref 'alerts') $Type)) { return $false }
    $sev = if ("$Severity".Trim()) { "$Severity" } else { Get-PimAlertSeverity -Event $Type }
    return ((Get-PimMailSeverityRank $sev) -ge (Get-PimMailSeverityRank "$(Get-PimMailPrefField $Pref 'severityFloor')"))
}

function Select-PimNotificationRecipients {
    <#
      PURE. Filter a recipient list by their preferences for ONE mail. Returns @{ keep = @(addresses); skipped = @(@{ address;
      reason }); prefs = @{ <address lower> = <pref> } } -- the caller uses prefs for each recipient's audience button.
    #>
    param([object]$Prefs, [string[]]$Recipients = @(), [Parameter(Mandatory)][string]$Type, [ValidateSet('report', 'alert', 'transactional')][string]$Kind = 'report', [string]$Severity = '')
    $norm = ConvertTo-PimMailNotificationPrefs $Prefs
    $keep = New-Object System.Collections.Generic.List[string]
    $skip = New-Object System.Collections.Generic.List[object]
    $map = @{}
    foreach ($r in @($Recipients | Where-Object { "$_".Trim() })) {
        $pref = Get-PimRecipientNotificationPref -Prefs $norm -Address "$r"
        $map["$r".Trim().ToLowerInvariant()] = $pref
        if (Test-PimRecipientWants -Pref $pref -Type $Type -Kind $Kind -Severity $Severity) { $keep.Add("$r".Trim()) }
        else {
            $why = if ($Kind -eq 'alert' -and -not (Test-PimMailPrefFalse (Get-PimMailPrefField $pref.alerts $Type))) { "below this recipient's severity floor ($($pref.severityFloor))" } else { "switched off by this recipient's notifications" }
            $skip.Add([pscustomobject]@{ address = "$r".Trim(); reason = $why })
        }
    }
    return [pscustomobject]@{ keep = @($keep.ToArray()); skipped = @($skip.ToArray()); prefs = $map }
}

function Get-PimMailNotificationPrefsFromStore {
    <#
      The stored MailNotifications (normalised). Order: an injected $global:PIM_MailNotifications; the settings bridge
      (Get-PimManagerSetting in the Manager, Get-PimSetting in the scheduler); SQL directly. NEVER throws: a store that cannot
      be read gives the DEFAULT (everyone gets everything) -- a preference read failing must not silence an alert.
    #>
    $raw = $null
    try {
        if ($null -ne $global:PIM_MailNotifications) { $raw = $global:PIM_MailNotifications }
        elseif (Get-Command Get-PimManagerSetting -ErrorAction SilentlyContinue) { $raw = Get-PimManagerSetting -Name 'MailNotifications' }
        elseif (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { $raw = Get-PimSetting -Name 'MailNotifications' }
        elseif ((Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue) -and (Get-Command Get-PimNotifySqlConnectionString -ErrorAction SilentlyContinue)) {
            $cs = Get-PimNotifySqlConnectionString
            if ($cs) { $raw = Get-PimSqlSetting -ConnectionString $cs -Name 'MailNotifications' }
        }
    } catch { Write-Warning "  [Mail] notification preferences could not be read (everyone gets every mail): $($_.Exception.Message)"; $raw = $null }
    return (ConvertTo-PimMailNotificationPrefs $raw)
}

function Get-PimAudienceLink {
    <#
      PURE (given the base). MAIL-2 item 1: where the blue button of ONE mail leads for ONE audience. Returns @{ url; label;
      tab; query }. url is '' when no Manager address is known (the mail is then sent without a button, never with a guess).
        -Type     the report / alert type (daily-summary, tier-report, an alert event, ...)
        -LinkTab  for an alert: the page the alert names (drift, coverage, ...) -- everyone goes there, the label differs
        -Query    extra deep-link filter, e.g. 'from=2026-10-08&to=2026-10-09' (keys [a-z0-9], values URL-encoded here)
    #>
    param([string]$Type, [ValidateSet('soc', 'posture', 'manager')][string]$Audience = 'manager', [string]$Base = '', [string]$LinkTab = '', [string]$Query = '')
    $routes = @{
        'daily-summary' = @{
            soc     = @{ tab = 'audit'; query = 'category=all'; label = "Review the day's changes in the audit trail" }
            posture = @{ tab = 'map'; query = ''; label = 'See the access they changed on the delegation map' }
            manager = @{ tab = 'commithistory'; query = ''; label = "Review the day's changes" }
        }
        'tier-report' = @{
            soc     = @{ tab = 'reports'; query = ''; label = 'Investigate Tier 0 / Tier 1 holders' }
            posture = @{ tab = 'map'; query = ''; label = 'See Tier 0 / Tier 1 access on the delegation map' }
            manager = @{ tab = 'accessreview'; query = ''; label = 'Review Tier 0 / Tier 1 access' }
        }
    }
    $r = $null
    if ($routes.ContainsKey("$Type")) { $r = $routes["$Type"][$Audience] }
    else {
        $tab = if ("$LinkTab".Trim() -match '^[a-z0-9-]+$') { "$LinkTab".Trim() } else { 'home' }
        $lab = switch ($Audience) { 'soc' { 'Investigate in PIM Manager' } 'posture' { 'Review the access in PIM Manager' } default { 'Open in PIM Manager' } }
        $r = @{ tab = $tab; query = ''; label = $lab }
    }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($q in @("$($r.query)", "$Query")) {
        foreach ($kv in ("$q" -split '&')) {
            if ($kv -match '^([a-z][a-z0-9]{0,30})=(.{1,200})$') { $parts.Add(('{0}={1}' -f $Matches[1], [uri]::EscapeDataString($Matches[2]))) }
        }
    }
    $b = "$Base".Trim().TrimEnd('/')
    $url = if ($b -match '^(?i)(https://[^\s/?#]+|http://(localhost|127\.0\.0\.1)(:\d+)?)$') { "$b/?tab=$($r.tab)" + $(if ($parts.Count) { '&' + ($parts.ToArray() -join '&') } else { '' }) } else { '' }
    return [pscustomobject]@{ url = $url; label = "$($r.label)"; tab = "$($r.tab)"; query = ($parts.ToArray() -join '&') }
}

function Merge-PimManagerReaderEntries {
    <#
      PURE. MAIL-2 item 5 -- AUTO-READER. Given the stored ManagerAccess entries and the recipient addresses just saved, add
      a Reader entry for every address that is NOT yet a Manager user. Returns @{ entries; added; known; invalid }.
        * an address already in -Entries (any role) is KNOWN: its entry is passed through UNCHANGED -- never upgraded,
          never downgraded, never re-sourced;
        * -AlsoKnown: identities granted outside the map (env PIM_SuperAdmins / PIM_Admins / PIM_DelegatedAdmins) -- they
          are users already, so no Reader row is written beside their real grant;
        * a new entry is { identity; role = 'Reader'; source = 'mail-recipient'; addedBy; addedUtc }.
      Matching is case-insensitive on the identity (the Manager matches the same way).
      -Source: why the entry was added -- 'mail-recipient' (MAIL-2) or 'department-owner' (PIM 100.24 DEPT-OWNER-ACCESS).
    #>
    param([object[]]$Entries = @(), [string[]]$Addresses = @(), [string[]]$AlsoKnown = @(), [string]$AddedBy = '', [string]$NowUtc = '',
          [string]$Source = 'mail-recipient')
    $src = if ("$Source".Trim()) { "$Source".Trim() } else { 'mail-recipient' }
    $stamp = if ("$NowUtc".Trim()) { "$NowUtc".Trim() } else { [datetime]::UtcNow.ToString('o') }
    $known = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Entries)) {
        if ($null -eq $e) { continue }
        $id = "$(Get-PimMailPrefField $e 'identity')".Trim()
        $out.Add($e)   # unchanged, whatever it holds
        if ($id) { $known[$id.ToLowerInvariant()] = "$(Get-PimMailPrefField $e 'role')".Trim() }
    }
    foreach ($k in @($AlsoKnown | Where-Object { "$_".Trim() })) { $lk = "$k".Trim().ToLowerInvariant(); if (-not $known.ContainsKey($lk)) { $known[$lk] = '(granted outside the map)' } }
    $added = New-Object System.Collections.Generic.List[string]
    $kn = New-Object System.Collections.Generic.List[object]
    $bad = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($a in @($Addresses)) {
        $addr = "$a".Trim()
        if (-not $addr) { continue }
        $lk = $addr.ToLowerInvariant()
        if ($seen.ContainsKey($lk)) { continue }; $seen[$lk] = $true
        if ($addr -notmatch '^[^@\s;,]+@[^@\s;,]+\.[^@\s;,]+$') { $bad.Add($addr); continue }
        if ($known.ContainsKey($lk)) { $kn.Add([pscustomobject]@{ identity = $addr; role = $known[$lk] }); continue }
        $out.Add([pscustomobject]@{ identity = $addr; role = 'Reader'; source = $src; addedBy = "$AddedBy"; addedUtc = $stamp })
        $known[$lk] = 'Reader'
        $added.Add($addr)
    }
    return [pscustomobject]@{ entries = @($out.ToArray()); added = @($added.ToArray()); known = @($kn.ToArray()); invalid = @($bad.ToArray()) }
}

function Get-PimRemovedRecipientReaders {
    <#
      PURE. MAIL-2 item 5, the other half: a recipient REMOVED from every list keeps their Manager role -- it is not taken away
      silently. Returns the removed addresses that still hold an entry, with their role, so the page can show them to the
      admin ("keeps Reader access -- remove it under Manager access & roles if it is no longer needed").
    #>
    param([string[]]$Before = @(), [string[]]$After = @(), [object[]]$Entries = @(), [string[]]$AutoSources = @('mail-recipient'))
    $now = @{}; foreach ($a in @($After)) { if ("$a".Trim()) { $now["$a".Trim().ToLowerInvariant()] = $true } }
    $roles = @{}
    foreach ($e in @($Entries)) { $id = "$(Get-PimMailPrefField $e 'identity')".Trim(); if ($id) { $roles[$id.ToLowerInvariant()] = [pscustomobject]@{ role = "$(Get-PimMailPrefField $e 'role')"; source = "$(Get-PimMailPrefField $e 'source')" } } }
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($b in @($Before)) {
        $lk = "$b".Trim().ToLowerInvariant()
        if (-not $lk -or $seen.ContainsKey($lk) -or $now.ContainsKey($lk)) { continue }
        $seen[$lk] = $true
        if ($roles.ContainsKey($lk)) { $out.Add([pscustomobject]@{ identity = "$b".Trim(); role = $roles[$lk].role; autoAdded = (@($AutoSources) -contains $roles[$lk].source) }) }
    }
    return @($out.ToArray())
}

function Get-PimDepartmentOwnerSet {
    # PURE. Every owner identity on a department list, de-duplicated case-insensitively, in first-seen order. A department
    # is @{ name; owners } where owners is an array or a '|' / ';' / ',' joined string (the stored shape).
    param([object[]]$Departments = @())
    $seen = @{}; $out = New-Object System.Collections.Generic.List[string]
    foreach ($d in @($Departments)) {
        if ($null -eq $d) { continue }
        $raw = Get-PimMailPrefField $d 'owners'
        if ($null -eq $raw) { $raw = Get-PimMailPrefField $d 'Owners' }
        foreach ($o in @(@($raw) | ForEach-Object { "$_" -split '[|;,]' })) {
            $s = "$o".Trim(); if (-not $s) { continue }
            if (-not $seen.ContainsKey($s.ToLowerInvariant())) { $seen[$s.ToLowerInvariant()] = $true; $out.Add($s) }
        }
    }
    return @($out.ToArray())
}

function Get-PimDepartmentOwnerReaderPlan {
    <#
      PURE. PIM 100.24 DEPT-OWNER-ACCESS (owner 2026-10-09: "the reader access is default for any dept owners defined with
      their normal access (tick on by default ...)"). Given the departments BEFORE and AFTER a save, decide whose normal
      account is offered to Manager access as a Reader:
        * -Grant $false                  -> nobody (the tick was off / grantReaderToOwners = false);
        * -Only <addresses> (the page's per-owner ticks) -> exactly those, and only when they ARE an owner after the save
          -- this path never grants Reader to somebody who is not an owner;
        * otherwise                      -> every owner who is NEW in this save (not an owner of any department before).
          An owner who already was one is not re-offered: an admin who removed their Reader on purpose is not overridden
          by the next unrelated department save.
      Whether an address actually becomes a Reader is Merge-PimManagerReaderEntries' call (unknown identities only; an
      existing role is never changed). -removed = owners of no department any more; the caller lists the ones that still
      hold a Manager role (Get-PimRemovedRecipientReaders) -- the role is left for the admin to decide.
      Returns @{ grant = string[]; newOwners = string[]; removed = string[]; before = string[]; after = string[] }.
    #>
    param([object[]]$Before = @(), [object[]]$After = @(), [bool]$Grant = $true, [AllowNull()][string[]]$Only = $null)
    $b = @(Get-PimDepartmentOwnerSet -Departments $Before)
    $a = @(Get-PimDepartmentOwnerSet -Departments $After)
    $bk = @{}; foreach ($x in $b) { $bk[$x.ToLowerInvariant()] = $true }
    $ak = @{}; foreach ($x in $a) { $ak[$x.ToLowerInvariant()] = $x }
    $new = @($a | Where-Object { -not $bk.ContainsKey($_.ToLowerInvariant()) })
    $removed = @($b | Where-Object { -not $ak.ContainsKey($_.ToLowerInvariant()) })
    $grantList = @()
    if ($Grant) {
        if ($null -ne $Only) {
            $seen = @{}
            $grantList = @(foreach ($o in @($Only)) {
                $k = "$o".Trim().ToLowerInvariant()
                if ($k -and $ak.ContainsKey($k) -and -not $seen.ContainsKey($k)) { $seen[$k] = $true; $ak[$k] }
            })
        } else { $grantList = $new }
    }
    return [pscustomobject]@{ grant = @($grantList); newOwners = @($new); removed = @($removed); before = $b; after = $a }
}

function Get-PimMailReportLastSent {
    # pim.Settings['MailReportLastSent'] = { <type>: { at; sent; recipients } } (normalised to a hashtable). Never throws.
    $raw = $null
    try {
        if (Get-Command Get-PimManagerSetting -ErrorAction SilentlyContinue) { $raw = Get-PimManagerSetting -Name 'MailReportLastSent' }
        elseif (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { $raw = Get-PimSetting -Name 'MailReportLastSent' }
        elseif ((Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue) -and (Get-Command Get-PimNotifySqlConnectionString -ErrorAction SilentlyContinue)) {
            $cs = Get-PimNotifySqlConnectionString; if ($cs) { $raw = Get-PimSqlSetting -ConnectionString $cs -Name 'MailReportLastSent' }
        }
    } catch { $raw = $null }
    for ($i = 0; $i -lt 2 -and $raw -is [string]; $i++) { if ("$raw".Trim()) { try { $raw = $raw | ConvertFrom-Json } catch { $raw = $null } } else { $raw = $null } }
    $out = @{}
    if ($null -eq $raw) { return $out }
    $names = if ($raw -is [System.Collections.IDictionary]) { @($raw.Keys) } else { @($raw.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($n in $names) { $out["$n"] = Get-PimMailPrefField $raw "$n" }
    return $out
}

function Save-PimMailReportLastSent {
    # Record that a report went out (MAIL-2 item 6, "last sent"). Best-effort: a failure is a warning, never a failed run.
    param([Parameter(Mandatory)][string]$Type, [int]$Sent = 0, [int]$Recipients = 0)
    try {
        $cur = Get-PimMailReportLastSent
        $cur["$Type"] = [ordered]@{ at = [datetime]::UtcNow.ToString('o'); sent = $Sent; recipients = $Recipients }
        if (Get-Command Set-PimManagerSetting -ErrorAction SilentlyContinue) { Set-PimManagerSetting -Name 'MailReportLastSent' -Value $cur; return }
        if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { Set-PimSetting -Name 'MailReportLastSent' -Value $cur | Out-Null; return }
        if ((Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue) -and (Get-Command Get-PimNotifySqlConnectionString -ErrorAction SilentlyContinue)) {
            $cs = Get-PimNotifySqlConnectionString; if ($cs) { Set-PimSqlSetting -ConnectionString $cs -Name 'MailReportLastSent' -Value $cur }
        }
    } catch { Write-Warning "  [Mail] the last-sent time of '$Type' could not be recorded: $($_.Exception.Message)" }
}
