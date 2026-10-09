#Requires -Version 5.1
<#
  PIM-GetStartedReminder.ps1 -- framework DOCS/REQUIREMENTS.md §12.11 MAIL-2 item 8 (owner 2026-10-09: "not completed get
  started must be alerted daily by mail to alert emails" / "to customer it"); PIM REQUIREMENTS §100.5.

  While any REQUIRED Get Started step is open, ONE mail a day goes to this environment's alert recipients: the open steps,
  why each matters, a blue button straight to that step (?tab=getstarted&step=<id>) and a doc link. Optional steps are
  listed as optional and never send the mail on their own; a step a SuperAdmin skipped ("skip for now") is shown as
  skipped, not open. It stops by itself when every required step is done -- no acknowledgement.

  ONE SOURCE for the step status: the Manager's Get Started page (GET_STARTED_STEPS in pim-manager.html) computes every
  step from the data and records the result, pim.Settings['GetStartedStatus'] = { steps: [ { id, title, required, done,
  deferred, note, what } ], evaluatedUtc, evaluatedBy, installer } (PUT /api/get-started/status, Admin). Nothing here
  re-decides a step. 'installer' = the first admin who recorded it: the fallback recipient while no alert recipient is set.
  Recipients are the CUSTOMER's: never an Invardia address; the MSP's own addresses are not in this environment's store.
  PURE planner (Get-PimGetStartedReminderPlan) + one I/O entry point (Invoke-PimGetStartedReminder). ASCII only.
#>
Set-StrictMode -Off

function Get-PimGetStartedDocUrl {
    # The doc link for a step. No per-step doc pages are published yet (PIM REQUIREMENTS §100.5 records the gap), so every
    # step links the product's documentation page.
    param([string]$StepId)
    return 'https://invardia.com/products/pim-manager/'
}

function ConvertTo-PimGetStartedStatus {
    # PURE. A stored GetStartedStatus (JSON text / object / dictionary) -> @{ steps = @(...); evaluatedUtc; evaluatedBy; installer }.
    param([AllowNull()][object]$Raw)
    $v = $Raw
    for ($i = 0; $i -lt 2 -and $v -is [string]; $i++) { if ("$v".Trim()) { try { $v = $v | ConvertFrom-Json } catch { $v = $null } } else { $v = $null } }
    $f = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o[$n] } } else { $p = $o.PSObject.Properties[$n]; if ($p) { $p.Value } } }
    $isTrue = { param($x) ("$x".Trim().ToLowerInvariant() -in @('true', '1', 'yes')) }
    $steps = foreach ($s in @(& $f $v 'steps')) {
        if ($null -eq $s) { continue }
        $id = "$(& $f $s 'id')".Trim().ToLowerInvariant()
        if ($id -notmatch '^[a-z0-9-]{1,40}$') { continue }
        $done = & $isTrue (& $f $s 'done')
        [pscustomobject]@{
            id = $id; title = "$(& $f $s 'title')".Trim(); required = (& $isTrue (& $f $s 'required'))
            done = $done; deferred = ((-not $done) -and (& $isTrue (& $f $s 'deferred')))
            note = "$(& $f $s 'note')".Trim(); what = "$(& $f $s 'what')".Trim()
        }
    }
    return [pscustomobject]@{ steps = @($steps); evaluatedUtc = "$(& $f $v 'evaluatedUtc')"; evaluatedBy = "$(& $f $v 'evaluatedBy')"; installer = "$(& $f $v 'installer')" }
}

function Test-PimCustomerRecipient {
    # A Get Started reminder goes to the CUSTOMER's IT only -- never to Invardia.
    param([string]$Address)
    $a = "$Address".Trim()
    if ($a -notmatch '^[^@\s;,]+@[^@\s;,]+\.[^@\s;,]+$') { return $false }
    return ($a -notmatch '(?i)@(.+\.)?invardia\.com$')
}

function Get-PimGetStartedReminderPlan {
    <#
      PURE. Should the Get Started reminder go out now, to whom, with what? Returns @{ send; reason; recipients; open;
      optional; skipped; done }.
        * open     = required, not done, not skipped -- only these make the mail go out
        * optional = not required and not done (listed as optional, never a trigger)
        * skipped  = a required step a SuperAdmin skipped for now (shown as skipped)
        * once a day: -LastSentUtc on the same UTC day -> no send
        * recipients: the alert recipients (customer addresses only), else the installing admin; none -> no send
        * -MailReady $false (no mail sender set up) -> no send (the GUI shows Mail sender as the first open step instead)
    #>
    param([object]$Status, [string[]]$AlertRecipients = @(), [datetime]$NowUtc = [datetime]::UtcNow, [string]$LastSentUtc = '', [bool]$MailReady = $true)
    $st = ConvertTo-PimGetStartedStatus $Status
    $steps = @($st.steps)
    $open = @($steps | Where-Object { $_.required -and -not $_.done -and -not $_.deferred })
    $opt = @($steps | Where-Object { -not $_.required -and -not $_.done })
    $skip = @($steps | Where-Object { $_.required -and $_.deferred })
    $plan = [ordered]@{ send = $false; reason = ''; recipients = @(); open = $open; optional = $opt; skipped = $skip; done = @($steps | Where-Object { $_.done }) }
    if (-not $steps.Count) { $plan.reason = 'no Get Started status recorded yet (an admin opens the Manager and it is recorded)'; return [pscustomobject]$plan }
    if (-not $open.Count) { $plan.reason = $(if ($opt.Count -or $skip.Count) { 'every required step is done (only optional or skipped steps are open)' } else { 'every step is done' }); return [pscustomobject]$plan }
    if (-not $MailReady) { $plan.reason = 'no mail sender is set up -- no mail (Get Started shows Mail sender as open)'; return [pscustomobject]$plan }
    $last = $null; if ("$LastSentUtc".Trim()) { try { $last = ([datetime]::Parse("$LastSentUtc", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)) } catch { $last = $null } }
    if ($last -and $last.Date -eq $NowUtc.ToUniversalTime().Date) { $plan.reason = 'already sent today'; return [pscustomobject]$plan }
    $rc = @($AlertRecipients | Where-Object { Test-PimCustomerRecipient $_ } | ForEach-Object { "$_".Trim() } | Select-Object -Unique)
    if (-not $rc.Count -and (Test-PimCustomerRecipient $st.installer)) { $rc = @("$($st.installer)".Trim()) }
    if (-not $rc.Count) { $plan.reason = 'no alert recipient and no installing admin address -- nobody to tell'; return [pscustomobject]$plan }
    $plan.recipients = $rc; $plan.send = $true; $plan.reason = ("{0} required step(s) open" -f $open.Count)
    return [pscustomobject]$plan
}

function ConvertTo-PimGetStartedReminderHtml {
    # PURE. The reminder as a designed mail (MAIL-2 layout): the open steps first, each with why it matters, its own blue
    # button to that step and the doc link; then skipped and optional steps.
    param([Parameter(Mandatory)][object]$Plan, [string]$PortalBase = '', [hashtable]$Environment = @{})
    $b = Get-PimMailBrand; $enc = { param($v) ConvertTo-PimMailText $v }
    $stepLink = { param($id) (Get-PimAudienceLink -Type 'get-started' -Base $PortalBase -LinkTab 'getstarted' -Query ("step=$id")).url }
    $open = @($Plan.open); $first = if ($open.Count) { $open[0] } else { $null }
    $tiles = New-PimMailSummaryTiles -Tiles @(
        @{ label = 'Required steps open'; value = "$($open.Count)"; tone = 'danger' }
        @{ label = 'Skipped for now'; value = "$(@($Plan.skipped).Count)"; tone = $(if (@($Plan.skipped).Count) { 'warning' } else { 'neutral' }) }
        @{ label = 'Optional'; value = "$(@($Plan.optional).Count)"; tone = 'neutral' }
        @{ label = 'Done'; value = "$(@($Plan.done).Count)"; tone = 'good' })
    $sum = $tiles + '<p style="font-family:' + $b.font + ';font-size:14px;margin:10px 0 0 0;">This PIM Manager environment is not completely set up. Until the steps below are done, parts of it do not work. This mail comes once a day and stops by itself when every required step is done.</p>'
    $cards = foreach ($s in $open) {
        $u = & $stepLink $s.id
        '<div class="pim-gs-step" style="margin:12px 0;padding:10px 14px;border:1px solid ' + $b.border + ';border-left:4px solid ' + $b.danger + ';border-radius:6px;font-family:' + $b.font + ';">' +
        '<div style="font-size:15px;font-weight:700;color:' + $b.heading + ';">' + (& $enc $s.title) + '</div>' +
        $(if ($s.what) { '<div style="font-size:13px;color:' + $b.text + ';margin-top:2px;">Why it matters: ' + (& $enc $s.what) + '</div>' } else { '' }) +
        $(if ($s.note) { '<div style="font-size:12.5px;color:' + $b.muted + ';margin-top:2px;">Now: ' + (& $enc $s.note) + '</div>' } else { '' }) +
        (New-PimMailButton -Url $u -Label ("Open " + $s.title)) +
        '<div style="font-size:12px;"><a href="' + (& $enc (Get-PimGetStartedDocUrl $s.id)) + '" style="color:' + $b.accent + ';">Documentation</a></div></div>'
    }
    $body = New-PimMailSection -Title ("Required steps still open ({0})" -f $open.Count) -Html (@($cards) -join '')
    if (@($Plan.skipped).Count) {
        $body += New-PimMailSection -Title 'Skipped for now' -Note 'A SuperAdmin chose "skip for now". These do not send this mail, but they are still to do.' `
            -Html (New-PimMailTable -Columns @(@{ key = 'title'; label = 'Step' }, @{ key = 'note'; label = 'Now' }) -Rows @($Plan.skipped))
    }
    if (@($Plan.optional).Count) {
        $body += New-PimMailSection -Title 'Optional' -Note 'Optional steps never send this mail on their own.' `
            -Html (New-PimMailTable -Columns @(@{ key = 'title'; label = 'Step' }, @{ key = 'what'; label = 'What it gives you' }) -Rows @($Plan.optional))
    }
    $homeUrl = (Get-PimAudienceLink -Type 'home' -Base $PortalBase -LinkTab 'home').url -replace '/\?tab=home$', '/'
    $notif = (Get-PimAudienceLink -Type 'settings' -Base $PortalBase -LinkTab 'settings' -Query 'section=notifications').url
    return (New-PimMailDocument -Title 'Get Started is not complete' -Subtitle ("{0} required step(s) still open" -f $open.Count) -Preheader ("{0} required Get Started step(s) still open: {1}" -f $open.Count, ((@($open | ForEach-Object { $_.title })) -join ', ')) `
        -SummaryHtml $sum -BodyHtml $body -Button $(if ($first) { @{ url = (& $stepLink $first.id); label = "Continue with $($first.title)" } } else { $null }) `
        -HomeUrl $homeUrl -NotificationsUrl $notif -Environment $Environment)
}

function Invoke-PimGetStartedReminder {
    <#
      The daily send (called by the scheduler's daily job). Reads the recorded Get Started status, the alert recipients, the
      last-sent stamp and the mail readiness; plans; filters by each recipient's Notifications ('get-started' report); sends
      the 'get-started-reminder' mail; records the day. Returns @{ sent; planned; detail }. Never throws.
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $get = {
        param($name)
        if (Get-Command Get-PimManagerSetting -ErrorAction SilentlyContinue) { return (Get-PimManagerSetting -Name $name) }
        if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { return (Get-PimSetting -Name $name) }
        if ((Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue) -and (Get-Command Get-PimNotifySqlConnectionString -ErrorAction SilentlyContinue)) { $cs = Get-PimNotifySqlConnectionString; if ($cs) { return (Get-PimSqlSetting -ConnectionString $cs -Name $name) } }
        return $null
    }
    try {
        $status = & $get 'GetStartedStatus'
        $rc = if (Get-Command Get-PimDigestRecipients -ErrorAction SilentlyContinue) { @((Get-PimDigestRecipients -Kind 'alerts').recipients) } else { @() }
        $lastRaw = & $get 'GetStartedReminderLastSent'
        $last = if ($lastRaw -is [string]) { "$lastRaw".Trim().Trim('"') } elseif ($lastRaw) { "$(Get-PimMailPrefField $lastRaw 'at')" } else { '' }
        if (Get-Command Initialize-PimEmailControlsFromStore -ErrorAction SilentlyContinue) { try { [void](Initialize-PimEmailControlsFromStore) } catch { } }
        $mode = if (Get-Command Get-PimMailMode -ErrorAction SilentlyContinue) { Get-PimMailMode } else { 'sharedMailbox' }
        $ready = ($mode -eq 'smtp') -or ($mode -ne 'none' -and [bool]"$($global:PIM_MailSender)".Trim())
        $plan = Get-PimGetStartedReminderPlan -Status $status -AlertRecipients $rc -NowUtc $NowUtc -LastSentUtc $last -MailReady $ready
        if (-not $plan.send) { return [pscustomobject]@{ sent = 0; planned = $false; detail = "not sent -- $($plan.reason)"; plan = $plan } }
        $to = @($plan.recipients)
        if (Get-Command Select-PimNotificationRecipients -ErrorAction SilentlyContinue) { $to = @((Select-PimNotificationRecipients -Prefs (Get-PimMailNotificationPrefsFromStore) -Recipients $to -Type 'get-started' -Kind 'report').keep) }
        if (-not $to.Count) { return [pscustomobject]@{ sent = 0; planned = $true; detail = 'not sent -- every recipient switched the Get Started reminder off'; plan = $plan } }
        $base = if (Get-Command Get-PimPortalBaseUrl -ErrorAction SilentlyContinue) { Get-PimPortalBaseUrl } else { '' }
        $envI = if (Get-Command Get-PimMailEnvironmentInfo -ErrorAction SilentlyContinue) { Get-PimMailEnvironmentInfo -PortalBase $base } else { @{} }
        $tokens = @{ ReportHtml = (ConvertTo-PimGetStartedReminderHtml -Plan $plan -PortalBase $base -Environment $envI); OpenCount = "$(@($plan.open).Count)"
                     OpenSteps = ((@($plan.open | ForEach-Object { $_.title })) -join ', '); PortalTab = 'getstarted' }
        $sent = 0; $why = New-Object System.Collections.Generic.List[string]
        foreach ($r in $to) {
            $res = $null
            try { $res = Send-PimNotifyMail -Type 'get-started-reminder' -Tokens $tokens -Recipient $r -WhatIf:$WhatIf } catch { $res = @{ sent = $false; reason = "$($_.Exception.Message)" } }
            if ("$($res.sent)" -match '(?i)^true$') { $sent++ } else { $why.Add("$r`: $($res.reason)") }
        }
        if ($sent -gt 0 -and -not $WhatIf) {
            try {
                $stamp = [ordered]@{ at = $NowUtc.ToUniversalTime().ToString('o'); sent = $sent }
                if (Get-Command Set-PimManagerSetting -ErrorAction SilentlyContinue) { Set-PimManagerSetting -Name 'GetStartedReminderLastSent' -Value $stamp }
                elseif (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { Set-PimSetting -Name 'GetStartedReminderLastSent' -Value $stamp | Out-Null }
                elseif ((Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue) -and (Get-Command Get-PimNotifySqlConnectionString -ErrorAction SilentlyContinue)) { $cs = Get-PimNotifySqlConnectionString; if ($cs) { Set-PimSqlSetting -ConnectionString $cs -Name 'GetStartedReminderLastSent' -Value $stamp } }
            } catch { Write-Warning "  [Mail] the Get Started reminder was sent but its day was not recorded: $($_.Exception.Message)" }
        }
        $d = if ($WhatIf) { "whatif -- would send to $($to.Count) ($($plan.reason))" } else { "sent=$sent/$($to.Count) ($($plan.reason))" + $(if ($why.Count) { ' refused: ' + ($why.ToArray() -join '; ') } else { '' }) }
        return [pscustomobject]@{ sent = $sent; planned = $true; detail = $d; plan = $plan }
    } catch {
        return [pscustomobject]@{ sent = 0; planned = $false; detail = "the Get Started reminder failed: $($_.Exception.Message)" }
    }
}
