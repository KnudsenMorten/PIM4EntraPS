<#
  PIM-JobAlert.ps1 -- "a failed job run raises an alert", wherever the run happened.

  ALERT-01. Before this, `engine-failure` had exactly two producers, and both were
  Manager REQUEST paths: POST /api/jobs/run (a human clicking Run on the Jobs tab)
  and the "send a test alert" button. PIM-Scheduler.ps1 -- which owns
  Invoke-PimSchedulerTick and actually runs due jobs -- never called
  Send-PimManagerAlert at all.

  So a job that failed on a SCHEDULED tick raised nothing. Alerting worked when you
  were already watching and was silent when you were not, which is the exact inverse
  of what "Email notifications for engine-failure" promises.

  THE FIX IS WHERE, NOT WHAT. The alert now fires from Write-PimJobRunRecord -- the
  single choke point every route to a finished run passes through (tick, trigger,
  force-start) -- instead of from one call site in one handler. Alerting stops being
  a property of HOW the job was launched.

  TWO THINGS THIS DELIBERATELY DOES NOT DO:

  1. It does not alert on 'skipped' or 'unimplemented'. BUG-92 and BUG-114 both came
     from collapsing those into 'failed'; BUG-92 put six job types permanently red on
     a healthy deployment. Re-making that mistake here would turn it into recurring
     EMAIL to the operator every tick, which is worse than a red count in a tab.
     Only status 'failed' is alert-worthy.

  2. It never throws. It is called after the run record is already persisted, so an
     alerting failure must not lose the run history or break the tick. Losing an
     alert is bad; losing the record of the run is worse.

  PS 5.1-safe (no ternary, no ??). The decision half is PURE and time-injectable so
  it can be tested without a mail path, a store, or a clock.
#>

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# PURE: is this finished run alert-worthy, and what should the alert say?
# ---------------------------------------------------------------------------
function Get-PimJobFailureAlert {
    <#
      Input is the run record Write-PimJobRunRecord just built (or anything with the
      same shape). Output:
        @{ fire; event; title; detail; dedupeScope }
      No I/O, no clock -- so the caller's tests do not need either.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Run)

    $out = [ordered]@{ fire = $false; event = 'engine-failure'; title = ''; detail = ''; reason = '' }

    $status = "$(Get-PimJobAlertField -Item $Run -Name 'status')".Trim().ToLowerInvariant()
    $name   = "$(Get-PimJobAlertField -Item $Run -Name 'name')".Trim()
    $type   = "$(Get-PimJobAlertField -Item $Run -Name 'type')".Trim()
    $detail = "$(Get-PimJobAlertField -Item $Run -Name 'detail')".Trim()
    $scope  = "$(Get-PimJobAlertField -Item $Run -Name 'scope')".Trim()

    # ONLY a real failure -- or a HOLD (71.13): a safety breaker stopped a change set and it needs an
    # operator's approval, so someone must be told. 'skipped' (out of scope for this deployment) and
    # 'unimplemented' (a placeholder handler) are neither -- see the header.
    if ($status -notin @('failed', 'held')) {
        $out.reason = "status '$status' is not a failure"
        return $out
    }
    if (-not $name) {
        $out.reason = 'run record has no job name'
        return $out
    }

    $out.fire  = $true
    $out.title = if ($status -eq 'held') { "Job '$name' HELD -- needs approval" } else { "Job '$name' FAILED" }
    $bits = New-Object System.Collections.Generic.List[string]
    if ($detail) { $bits.Add($detail) }
    if ($type)   { $bits.Add("type=$type") }
    if ($scope)  { $bits.Add("scope=$scope") }
    # The trigger flag is what tells an operator whether anyone was watching -- a
    # scheduled failure at 03:00 reads very differently from one they just clicked.
    $trigRaw = Get-PimJobAlertField -Item $Run -Name 'trigger'
    $isTrigger = $false
    if ($null -ne $trigRaw) { $isTrigger = [bool]$trigRaw }
    if ($isTrigger) { $bits.Add('(triggered run)') } else { $bits.Add('(scheduled run)') }
    $out.detail = ($bits.ToArray() -join ' ')
    return $out
}

function Get-PimJobAlertMailParts {
    <#
      The mail parts for a job alert: @{ title; headline; detailHtml; actionHtml; skip }. Never throws.
      * FAILED -> the run's detail, HTML-encoded; the next step in words.
      * HELD   -> each held plan named in the run's detail ("-Provider <p> -PlanHash <h>"), read back from its hold
                  record (Get-PimPolicyMassHold) and rendered by Format-PimPolicyHoldMail. When every one of those
                  plans was ALREADY mailed by the engine's own hold alert in this process ($global:PimPolicyHoldAlerted,
                  set by Write-PimPolicyMassHoldAlert), skip = $true: one mail per hold, not two for the same event.
    #>
    param([Parameter(Mandatory)][object]$Alert, [object]$Run)
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode("$t") }
    $status = "$(Get-PimJobAlertField -Item $Run -Name 'status')".Trim().ToLowerInvariant()
    $name   = "$(Get-PimJobAlertField -Item $Run -Name 'name')".Trim()
    $out = [ordered]@{ title = "$($Alert.title)"; headline = ''; detailHtml = (& $enc "$($Alert.detail)"); actionHtml = ''; skip = $false }
    if ($status -ne 'held') {
        $out.headline = "The job '$name' failed."
        $out.actionHtml = 'Open the PIM Manager, <b>Jobs &rsaquo; Engine logs &amp; errors</b>: every failing item is listed there with its cause and, where there is one, a fix.'
        return [pscustomobject]$out
    }
    try {
        $held = @([regex]::Matches("$($Alert.detail)", '-Provider\s+(\w+)\s+-PlanHash\s+([0-9a-fA-F]{64})') | ForEach-Object { [pscustomobject]@{ provider = $_.Groups[1].Value; hash = $_.Groups[2].Value.ToLowerInvariant() } })
        if ($held.Count) {
            $sentAlready = $global:PimPolicyHoldAlerted
            if ($sentAlready -is [hashtable] -and -not @($held | Where-Object { -not $sentAlready.ContainsKey($_.hash) }).Count) {
                $out.skip = $true; return [pscustomobject]$out
            }
            if ((Get-Command Get-PimPolicyMassHold -ErrorAction SilentlyContinue) -and (Get-Command Format-PimPolicyHoldMail -ErrorAction SilentlyContinue)) {
                $parts = @()
                foreach ($h in $held) {
                    $rec = $null; try { $rec = Get-PimPolicyMassHold -Provider $h.provider } catch { $rec = $null }
                    if ($rec -and "$($rec.planHash)".ToLowerInvariant() -eq $h.hash) { $parts += Format-PimPolicyHoldMail -Hold $rec -Provider $h.provider }
                }
                if ($parts.Count) {
                    $out.headline   = (@($parts | ForEach-Object { $_.headline }) -join ' ')
                    $out.detailHtml = (@($parts | ForEach-Object { $_.detailHtml }) -join '<br><hr>')
                    $out.actionHtml = (@($parts | ForEach-Object { $_.actionHtml }) -join '<br>')
                    $out.title      = "Job '$name': " + (@($parts | ForEach-Object { $_.subject }) -join '; ')
                    return [pscustomobject]$out
                }
            }
        }
    } catch { }
    $out.headline = "The job '$name' is held: a change set needs your approval before it is applied."
    $out.actionHtml = 'Open the PIM Manager, <b>Jobs &rsaquo; Engine logs &amp; errors</b>: the held change is shown there setting by setting, with the button to approve it.'
    return [pscustomobject]$out
}

function Get-PimJobAlertField {
    # Tolerant field read -- run records are PSCustomObjects in-process and
    # dictionaries after a store round-trip. PSObject.Properties does NOT see
    # dictionary keys, so check IDictionary first (same rule as the alerting config).
    param([object]$Item, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Item) { return $null }
    if ($Item -is [System.Collections.IDictionary]) {
        if ($Item.Contains($Name)) { return $Item[$Name] }
        return $null
    }
    $p = $Item.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

# ---------------------------------------------------------------------------
# DISPATCH: raise the alert through whatever sender THIS process has.
# ---------------------------------------------------------------------------
function Invoke-PimJobRunAlert {
    <#
      Called from Write-PimJobRunRecord for every finished run. Returns the sender
      that handled it ('manager' / 'notify' / 'none') for the caller's diagnostics.

      Two processes run jobs and they are NOT the same:
        * the Manager (Open-PimManager.ps1) has Send-PimManagerAlert -- the full
          path: per-event toggles, debounce, outbound webhook, audit event, and the
          recorded-send feed. When it is loaded, it wins; there is no reason to have
          a second implementation take over inside the process that owns the first.
        * the SCHEDULER (Start-PimScheduler.ps1 / the ca-pim-tick Job) does not. It
          already loads PIM-Notify.ps1 so the digest jobs can send mail, so it has a
          delivery path -- it just never had alerting logic on top of it. That is
          what Send-PimJobAlertViaNotify below is.

      NEVER throws.
    #>
    [CmdletBinding()]
    # 2026-09-26: an IDENTICAL failure (same job, same detail) is re-mailed at most once a day while it lasts -- a job on a
    # 5-minute tick that keeps failing the same way sent one mail an hour. A NEW or DIFFERENT failure still mails at once.
    param([Parameter(Mandatory)][object]$Run, [int]$DebounceMinutes = 1440)

    try {
        $d = Get-PimJobFailureAlert -Run $Run
        if (-not $d.fire) { return 'none' }

        # 2026-09-21 (operator: "this email is impossible to read" / "this email needs more details, which policies and
        # what is the change"): the mail body is HTML and tokens go in RAW -- so the plain detail is ENCODED (its
        # '<you>' vanished as a tag), and a HELD run carries the held plan itself: which policies, each setting
        # current -> new, and how to approve (Format-PimPolicyHoldMail, the same text as the engine's hold alert).
        $mail = Get-PimJobAlertMailParts -Alert $d -Run $Run
        if ($mail.skip) { return 'none' }

        if (Get-Command Send-PimManagerAlert -ErrorAction SilentlyContinue) {
            [void](Send-PimManagerAlert -Event $d.event -Title $mail.title -Detail $mail.detailHtml -Headline $mail.headline -Action $mail.actionHtml -LinkTab 'jobs' -DebounceMinutes $DebounceMinutes)
            return 'manager'
        }
        if (Get-Command Send-PimJobAlertViaNotify -ErrorAction SilentlyContinue) {
            $r = Send-PimJobAlertViaNotify -Event $d.event -Title $mail.title -Detail $mail.detailHtml -Headline $mail.headline -Action $mail.actionHtml -DebounceMinutes $DebounceMinutes
            if ($r) { return 'notify' }
            return 'none'
        }
        return 'none'
    } catch {
        # Deliberately swallowed: the run record is already persisted by the time we
        # get here. An alerting fault must not take the tick down or lose history.
        Write-Warning ("job-failure alert could not be raised: {0}" -f $_.Exception.Message)
        return 'none'
    }
}

function Get-PimJobAlertingConfig {
    <#
      The alerting config as the SCHEDULER sees it -- read from the SAME
      pim.Settings['Alerting'] value the Manager's Get-PimAlertingConfig reads, so
      the two cannot disagree about who is notified or which events are on.
      Returns @{ recipients=@(); events=@{}; }; events default ON, matching the Manager.
    #>
    [CmdletBinding()]
    param([string]$ConnectionString)

    # 'coverage' (REQ-I + REQ-U): NEW gaps / orphans / unmanaged privileged groups found by the 'coverage' job.
    # §79.1: 'target-missing' -- delegation targets (Azure scopes / roles, Entra roles) that no longer exist ('target-check' job).
    $catalog = @('engine-failure','drift','expiring-access','break-glass','coverage','target-missing','pending-uncommitted')   # 'pending-uncommitted': §79.2
    $events = @{}
    foreach ($e in $catalog) { $events[$e] = $true }
    $out = [ordered]@{ recipients = @(); events = $events }

    $cs = $ConnectionString
    if (-not "$cs".Trim() -and (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue)) {
        try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null }
    }
    if (-not "$cs".Trim()) { return $out }
    if (-not (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) { return $out }

    $raw = $null
    try { $raw = Get-PimSqlSetting -ConnectionString $cs -Name 'Alerting' } catch { return $out }
    if (-not $raw) { return $out }
    if ($raw -is [string]) { try { $raw = $raw | ConvertFrom-Json } catch { return $out } }

    $rec = Get-PimJobAlertField -Item $raw -Name 'recipients'
    if ($rec) { $out.recipients = @(@($rec) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
    $ev = Get-PimJobAlertField -Item $raw -Name 'events'
    if ($ev) {
        foreach ($e in $catalog) {
            $v = Get-PimJobAlertField -Item $ev -Name $e
            if ($null -ne $v) { $out.events[$e] = [bool]$v }
        }
    }
    return $out
}

function Send-PimJobAlertViaNotify {
    <#
      The scheduler-side sender: honour the event toggle, debounce against the SAME
      feed the Manager uses, deliver through Send-PimNotifyMail, and record the
      recorded-send proof to the SAME store (pim.Settings['AlertFeed']).

      This is intentionally the LEAN path -- no outbound webhook, no Manager audit
      event -- because those need Manager-only state. What it does NOT do is keep a
      private notion of who is notified or where the proof goes: config key, feed
      store and record shape are all shared with the Manager, so the two senders
      cannot drift on the things that matter. Returns $true when it handled the alert.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Event,
        [string]$Title,
        [string]$Detail,
        [int]$DebounceMinutes = 60,
        [string]$Headline = '',
        [string]$Action = '',
        # §79.3: the Manager page the mail links to (drift, coverage, admins ...). 'jobs' keeps every earlier caller as it was.
        [ValidatePattern('^[a-z0-9-]+$')][string]$LinkTab = 'jobs'
    )
    if (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) { return $false }

    $cs = $null
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) {
        try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null }
    }
    $cfg = Get-PimJobAlertingConfig -ConnectionString $cs
    if (-not ($cfg.events.ContainsKey($Event) -and $cfg.events[$Event])) { return $false }
    if (@($cfg.recipients).Count -eq 0) { return $false }

    # Debounce against the shared feed so a job failing every 5 minutes does not mail
    # every 5 minutes. Best-effort: no store means no debounce, not no alert.
    if ($DebounceMinutes -gt 0 -and $cs -and
        (Get-Command Test-PimAlertDebounced -ErrorAction SilentlyContinue) -and
        (Get-Command Read-PimAlertFeedSql   -ErrorAction SilentlyContinue)) {
        try {
            $key = Get-PimAlertDedupeKey -Event $Event -Title $Title -Detail $Detail
            if (Test-PimAlertDebounced -Feed (Read-PimAlertFeedSql -ConnectionString $cs) -DedupeKey $key -DebounceMinutes $DebounceMinutes) {
                return $true
            }
        } catch {}
    }

    $tokens = @{
        AlertTitle  = $(if ("$Title".Trim()) { $Title } else { $Event })
        AlertEvent  = $Event
        AlertDetail = "$Detail"
        AlertTab    = $LinkTab
        TenantName  = "$($global:PIM_TenantName)"
        Instance    = 'scheduler'
        AlertHeadline = $(if ("$Headline".Trim()) { "$Headline" } else { 'A PIM4EntraPS alert was raised for your privileged-access estate.' })
        AlertAction   = $(if ("$Action".Trim()) { "$Action" } else { "Open the PIM Manager and review the $LinkTab view." })
        WhenUtc     = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
    }
    $sent = 0; $lastReason = ''
    foreach ($rcpt in $cfg.recipients) {
        try {
            $r = Send-PimNotifyMail -Type 'alert-notice' -Tokens $tokens -Recipient $rcpt
            if ($r.sent) { $sent++ } elseif ($r.reason) { $lastReason = "$($r.reason)" }
        } catch { $lastReason = "$($_.Exception.Message)" }
    }

    # Record the proof in the shared feed, so a scheduled-run alert is as auditable
    # as a GUI one. Without this the tick would notify people with no record of it.
    if ($cs -and (Get-Command New-PimAlertRecord -ErrorAction SilentlyContinue) -and
                 (Get-Command Write-PimAlertFeedSql -ErrorAction SilentlyContinue)) {
        try {
            $result = [ordered]@{ event = $Event; fired = $true; sent = $sent; recipients = @($cfg.recipients); reason = "$lastReason" }
            $rec = New-PimAlertRecord -Event $Event -Title $Title -Detail $Detail -LinkTab $LinkTab -SendResult $result -Instance 'scheduler'
            [void](Write-PimAlertFeedSql -ConnectionString $cs -Record $rec)
        } catch {
            # Same as the Manager's feed write: the alert went out, the record did not. Warn rather
            # than fail -- turning a delivered alert into an error would be worse -- but do not let
            # the audit trail disagree with reality in silence.
            Write-Warning "[jobalert] '$Event' was raised but NOT recorded in the alert feed ($($_.Exception.Message))."
        }
    }
    return $true
}
