<#
  PIM4EntraPS -- notifications (REST-only, no modules). Renders the shipped mail
  templates (templates/mail/*.mailtemplate.html, + .custom.html override) and sends via
  Microsoft Graph /users/<sender>/sendMail (app-only, Mail.Send). Ported from
  Send-PimTemplatedMail / ConvertTo-PimMailRendering in PIM-Functions.psm1.

  Config:
    $global:PIM_MailSender        UPN of the shared sender mailbox (required to send)
    $global:PIM_MailRedirectAllTo lab/test: every mail goes here instead of the real
                                  recipient (original surfaced as {{RedirectedFrom}})
    $global:PIM_MailTemplateDir   override the templates/mail location
  Render is split from send so it is unit-testable with no network.
#>
Set-StrictMode -Off

# The notification BATCH logic (daily summary / tier 0-1 report / approval escalation /
# ServiceNow intake) lives in PIM-Notifications.ps1 -- load it alongside the sender so
# any context that dot-sources PIM-Notify also gets the aggregation/render-prep + intake
# broker (idempotent: re-defining the functions is harmless).
if ($PSScriptRoot) {
    $__pimNotifBatch = Join-Path $PSScriptRoot 'PIM-Notifications.ps1'
    if ((Test-Path -LiteralPath $__pimNotifBatch) -and -not (Get-Command Get-PimDailySummary -ErrorAction SilentlyContinue)) { . $__pimNotifBatch }
}

# --- EMAIL CONTROLS authority (the GUI-state == actual-behavior fix) -----------
# The Manager persists the kill switch / redirect-all / allowlist to SQL pim.Settings
# under 'EmailControls' and mirrors them to $global:PIM_Mail* so its OWN process honours
# them live. But a COLD-booted scheduled job (daily-summary / tier-report / escalations)
# or a one-shot engine run never ran that mirror, so the kill switch would NOT stop the
# send -- the exact "kill switch that doesn't actually stop sends" gap. The two helpers
# below make the SEND PATH itself authoritative against the persisted store, so EVERY
# process honours the GUI-saved controls. FAIL-SAFE throughout: a store-read failure
# NEVER clears an existing kill switch and never relaxes the allowlist/redirect.
function Set-PimEmailControlsGlobals {
    # PURE: apply an EmailControls record { killSwitch; redirectAllTo; allowlist[] } to the
    # $global:PIM_Mail* the send path reads. Accepts a hashtable, PSCustomObject, or a JSON
    # string (SQL keeps scalars as text). FAIL-SAFE: an ON kill switch is only ever turned
    # ON here, never OFF (a malformed/blank record can't silently re-enable sending); the
    # allowlist/redirect are only set from a well-formed record. Returns the applied shape.
    param([object]$EmailControls)
    $rec = $EmailControls
    if ($rec -is [string]) { $s = "$rec".Trim(); if ($s) { try { $rec = $s | ConvertFrom-Json } catch { $rec = $null } } else { $rec = $null } }
    $get = {
        param($obj, $name)
        if ($null -eq $obj) { return $null }
        if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($name)) { return $obj[$name] } ; return $null }
        $p = $obj.PSObject.Properties[$name]; if ($p) { return $p.Value } else { return $null }
    }
    $kill = & $get $rec 'killSwitch'
    if ($null -ne $kill -and [bool]$kill) { $global:PIM_MailKillSwitch = $true }   # only ever ARM, never disarm
    $redir = & $get $rec 'redirectAllTo'
    if ($null -ne $redir -and "$redir".Trim()) { $global:PIM_MailRedirectAllTo = "$redir".Trim() }
    $allow = & $get $rec 'allowlist'
    if ($null -ne $allow) { $global:PIM_MailAllowlist = @(@($allow) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
    return [pscustomobject]@{ killSwitch = [bool]$global:PIM_MailKillSwitch; redirectAllTo = "$($global:PIM_MailRedirectAllTo)"; allowlist = @($global:PIM_MailAllowlist) }
}
function Initialize-PimEmailControlsFromStore {
    # Make the send path authoritative against SQL pim.Settings: read 'EmailControls'
    # directly and apply it to the $global:PIM_Mail* globals BEFORE sending, so a cold
    # scheduled job / engine run honours a GUI-set kill switch / redirect / allowlist.
    # Hydrates ONCE per process by default (cheap; -Force re-reads). FAIL-SAFE: any read
    # failure leaves the current globals untouched -- it never clears an armed kill switch
    # and never opens the allowlist. No-op (returns $false) when no store is configured.
    param([switch]$Force)
    if ($script:PimEmailControlsHydrated -and -not $Force) { return $false }
    if (-not (Get-Command Import-PimSettingsFromStore -ErrorAction SilentlyContinue)) { return $false }
    $n = -1
    try { $n = Import-PimSettingsFromStore } catch { $n = -1 }   # applies EmailControls via Set-PimEmailControlsGlobals
    if ($n -ge 0) { $script:PimEmailControlsHydrated = $true; return $true }
    return $false   # store unreachable -> leave globals as-is (fail-safe), retry next send
}

function Get-PimNotifyTemplateDir {
    if ($global:PIM_MailTemplateDir) { return "$($global:PIM_MailTemplateDir)" }
    if ($PSScriptRoot) { return (Join-Path (Resolve-Path "$PSScriptRoot\..\..").Path 'templates\mail') }
    return $null
}
function Get-PimNotifyTemplate {
    param([Parameter(Mandatory)][string]$Type)
    $dir = Get-PimNotifyTemplateDir; if (-not $dir) { return $null }
    foreach ($cand in @("$Type.mailtemplate.custom.html", "$Type.mailtemplate.html")) {
        $p = Join-Path $dir $cand; if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}
function Get-PimNotifyStoreOverride {
    # The persistent-store override for a template type, set GUI-side via the
    # Manager (SQL pim.Settings 'MailTemplateOverrides' -> hydrated into
    # $global:PIM_NamingConventions at boot, OR an explicit $global override).
    # Returns the override HTML string, or $null when there is none. This is what
    # lets an operator customize a mail WITHOUT copying a file or rebuilding the
    # container image: the store value travels with the instance and is read here
    # at send time. PS 5.1-safe (no null-conditional).
    param([Parameter(Mandatory)][string]$Type)
    $map = $null
    if ($global:PIM_NamingConventions -is [hashtable] -and $global:PIM_NamingConventions.ContainsKey('MailTemplateOverrides')) {
        $map = $global:PIM_NamingConventions['MailTemplateOverrides']
    } elseif ($null -ne $global:PIM_MailTemplateOverrides) {
        $map = $global:PIM_MailTemplateOverrides
    }
    if ($null -eq $map) { return $null }
    # The value may arrive as a JSON string (SQL store keeps scalars as text).
    if ($map -is [string]) {
        $s = "$map".Trim(); if (-not $s) { return $null }
        try { $map = $s | ConvertFrom-Json } catch { return $null }
    }
    $val = $null
    if ($map -is [System.Collections.IDictionary]) {
        if ($map.Contains($Type)) { $val = $map[$Type] }
    } elseif ($map -is [System.Management.Automation.PSCustomObject]) {
        $p = $map.PSObject.Properties[$Type]; if ($p) { $val = $p.Value }
    }
    if ($null -eq $val) { return $null }
    $text = "$val"
    if (-not $text.Trim()) { return $null }
    return $text
}
function Get-PimNotifyTemplateText {
    # Resolve the EFFECTIVE template body for a type, in precedence order:
    #   1. persistent-store override (GUI-saved, no rebuild)   <- wins
    #   2. file-based <type>.mailtemplate.custom.html          (fallback)
    #   3. shipped <type>.mailtemplate.html                    (default)
    # Returns @{ text; source } or $null when no template exists at all.
    param([Parameter(Mandatory)][string]$Type)
    $ov = Get-PimNotifyStoreOverride -Type $Type
    if ($null -ne $ov) { return @{ text = $ov; source = 'store' } }
    $dir = Get-PimNotifyTemplateDir
    if ($dir) {
        $custom = Join-Path $dir "$Type.mailtemplate.custom.html"
        if (Test-Path -LiteralPath $custom) { return @{ text = (Get-Content -LiteralPath $custom -Raw -Encoding UTF8); source = 'file' } }
        $shipped = Join-Path $dir "$Type.mailtemplate.html"
        if (Test-Path -LiteralPath $shipped) { return @{ text = (Get-Content -LiteralPath $shipped -Raw -Encoding UTF8); source = 'shipped' } }
    }
    return $null
}
function ConvertTo-PimNotifyRendering {
    # PURE: template text + tokens -> @{ Subject; BodyHtml; BodyText }. Subject from a
    # leading <!-- subject: ... --> comment. Unknown {{tokens}} render empty (warned).
    param([Parameter(Mandatory)][string]$TemplateText, [Parameter(Mandatory)][hashtable]$Tokens)
    $subject = 'PIM4EntraPS notification'
    if ($TemplateText -match '<!--\s*subject:\s*(.+?)\s*-->') { $subject = $Matches[1] }
    $render = {
        param([string]$text)
        foreach ($k in $Tokens.Keys) { $text = $text -replace ('\{\{' + [regex]::Escape($k) + '\}\}'), ([string]$Tokens[$k] -replace '\$', '$$$$') }
        $leftover = @([regex]::Matches($text, '\{\{(\w+)\}\}') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
        if ($leftover.Count -gt 0) { Write-Warning "  [Mail] unknown token(s): $($leftover -join ', ') -- rendered empty."; $text = [regex]::Replace($text, '\{\{\w+\}\}', '') }
        $text
    }
    $subject  = & $render $subject
    $bodyHtml = & $render $TemplateText
    $bodyText = $bodyHtml -replace '<!--.*?-->', ''
    $bodyText = $bodyText -replace '(?i)<br\s*/?>', "`r`n" -replace '(?i)</(p|div|li|h[1-6]|tr)>', "`r`n"
    $bodyText = $bodyText -replace '<[^>]+>', '' -replace '&nbsp;', ' ' -replace '&amp;', '&' -replace '&lt;', '<' -replace '&gt;', '>' -replace '&quot;', '"'
    $bodyText = (($bodyText -split "`r?`n" | ForEach-Object { $_.TrimEnd() }) -join "`r`n") -replace "(`r`n){3,}", "`r`n`r`n"
    @{ Subject = $subject; BodyHtml = $bodyHtml; BodyText = $bodyText.Trim() }
}
function Send-PimNotifyMail {
    # Render type+tokens and send via Graph sendMail. Returns @{ sent; recipient; subject;
    # rendered; reason }. No send (returns rendered only) when -WhatIf / $global:WhatIfMode,
    # no sender configured, or no template -- so it is safe to call unconditionally.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][hashtable]$Tokens, [string]$Recipient, [switch]$WhatIf)
    $rcpt = $Recipient

    # --- AUTHORITATIVE EMAIL CONTROLS: hydrate from SQL pim.Settings before sending,
    # so a COLD-booted scheduled job / engine run honours the GUI-saved kill switch /
    # redirect / allowlist -- not just the Manager's in-process globals. Fail-safe: a
    # read failure leaves the current globals untouched (never disarms a kill switch).
    if (Get-Command Initialize-PimEmailControlsFromStore -ErrorAction SilentlyContinue) { [void](Initialize-PimEmailControlsFromStore) }

    # --- EMAIL CONTROLS (REQUIREMENTS s29) ------------------------------------
    # 1) Global email KILL SWITCH: when $global:PIM_MailKillSwitch is set, OR the
    #    'alerting.email' feature is disabled/unlicensed, EVERY send is a no-op.
    #    Honoured here so every send path + every job/scheduler is covered at the
    #    one chokepoint. A disabled feature performs NO sends, no matter the trigger.
    if ($global:PIM_MailKillSwitch) { return @{ sent = $false; recipient = $rcpt; reason = 'email kill switch on' } }
    if ((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and -not (Test-PimFeatureAvailable -Key 'alerting.email' -Quiet)) {
        return @{ sent = $false; recipient = $rcpt; reason = 'email feature disabled' }
    }
    # 2) Override/redirect target -- $global:PIM_MailRedirectAllTo handled below
    #    (existing behaviour). 3) Allowlist: when $global:PIM_MailAllowlist is a
    #    non-empty set, a recipient NOT on it (after redirect resolution) is dropped.
    if ($global:PIM_MailRedirectAllTo -and "$($global:PIM_MailRedirectAllTo)".Trim()) {
        $redir = "$($global:PIM_MailRedirectAllTo)".Trim()
        if ($rcpt -and $rcpt -ne $redir) { $Tokens = @{} + $Tokens; $Tokens['RedirectedFrom'] = $rcpt; Write-Host "  [Mail] redirect: '$rcpt' -> $redir" -ForegroundColor DarkYellow }
        $rcpt = $redir
    }
    # Allowlist (REQUIREMENTS s29): when configured + non-empty, drop any recipient
    # not on it (after the redirect resolution above). Empty/unset = no restriction.
    $allow = @($global:PIM_MailAllowlist | Where-Object { "$_".Trim() })
    if ($allow.Count -gt 0 -and $rcpt) {
        $hit = $false
        foreach ($a in $allow) { if ("$a".Trim().ToLowerInvariant() -eq "$rcpt".Trim().ToLowerInvariant()) { $hit = $true; break } }
        if (-not $hit) { Write-Host "  [Mail] '$rcpt' not on allowlist -- not sent." -ForegroundColor DarkYellow; return @{ sent = $false; recipient = $rcpt; reason = 'recipient not on allowlist' } }
    }
    $tpl = Get-PimNotifyTemplateText -Type $Type
    if (-not $tpl) { return @{ sent = $false; recipient = $rcpt; reason = "no template '$Type'" } }
    $r = ConvertTo-PimNotifyRendering -TemplateText $tpl.text -Tokens $Tokens
    $sender = "$($global:PIM_MailSender)".Trim()
    if ($WhatIf -or $global:WhatIfMode) { return @{ sent = $false; recipient = $rcpt; subject = $r.Subject; rendered = $r; reason = 'whatif' } }
    if (-not $sender) { Write-Warning "  [Mail] `$global:PIM_MailSender not set -- rendered only, not sent."; return @{ sent = $false; recipient = $rcpt; subject = $r.Subject; rendered = $r; reason = 'no sender' } }
    if (-not $rcpt)   { return @{ sent = $false; subject = $r.Subject; rendered = $r; reason = 'no recipient' } }
    $body = @{ message = @{ subject = $r.Subject; body = @{ contentType = 'HTML'; content = $r.BodyHtml }; toRecipients = @(@{ emailAddress = @{ address = $rcpt } }) }; saveToSentItems = $false }
    try { Invoke-PimGraph -Method POST -Path "/users/$sender/sendMail" -Body $body | Out-Null; return @{ sent = $true; recipient = $rcpt; subject = $r.Subject; rendered = $r } }
    catch { Write-Warning "  [Mail] send failed ($Type -> $rcpt): $($_.Exception.Message)"; return @{ sent = $false; recipient = $rcpt; subject = $r.Subject; rendered = $r; reason = "$($_.Exception.Message)" } }
}

function Test-PimTapMailReady {
    <#
      Can a TAP mail actually be DELIVERED to this recipient, right now?

      🪤 THE TRAP THIS FUNCTION EXISTS TO AVOID. The obvious pre-check is to call
      Send-PimNotifyMail -WhatIf and look at the reason -- and it is WRONG. In
      PIM-Notify.ps1 the -WhatIf early-return sits BEFORE the 'no sender' and
      'no recipient' checks, so on a tenant with NO notification sender
      configured a -WhatIf probe returns reason='whatif' and looks perfectly
      healthy. That is exactly the tenant this guard is for: the one whose TAP
      mail was never going to arrive.

      So the sender and the recipient are checked EXPLICITLY here, and -WhatIf
      is used only for what it can genuinely answer (kill switch, disabled
      feature, allowlist, missing template).

      Returns @{ ok; reason }. Never throws -- a mail-readiness probe that
      throws would fail the request for a reason the operator cannot action.
    #>
    param([string]$Recipient)

    if (-not "$Recipient".Trim()) {
        return @{ ok = $false; reason = 'this admin row has no ManagerEmail, so there is nowhere to deliver the TAP' }
    }
    # 🔴 HYDRATE BEFORE JUDGING. Measured live on EFIF 2026-08-25: this guard refused ALL SIX admins
    # with "no notification sender is configured" while pim.Settings held a perfectly good
    # 'MailSender' (PIM-Engine@<tenant>). The sender was never missing -- it had not been READ yet.
    # Send-PimNotifyMail hydrates at L169, but this guard runs BEFORE that call and reads the raw
    # global, so on a cold engine run (the scheduled tick Job is always cold) it saw an empty value
    # and refused every account. The engine then healed nothing, every run, silently.
    # 🪤 Same shape as the trap in this function's own docstring: checking a value EARLY is right,
    # but only if what populates it ran earlier still. An "is it configured?" test that runs before
    # configuration is loaded does not report the config -- it reports its own ordering.
    # Fail-safe: Initialize-PimEmailControlsFromStore leaves the globals untouched when the store is
    # unreachable, so this can only ever ADD a sender, never clear one.
    if (Get-Command Initialize-PimEmailControlsFromStore -ErrorAction SilentlyContinue) {
        try { [void](Initialize-PimEmailControlsFromStore) } catch { }
    }
    if (-not "$($global:PIM_MailSender)".Trim()) {
        return @{ ok = $false; reason = 'no notification sender is configured (PIM_MailSender) -- the tenant cannot send mail at all' }
    }
    if (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) {
        return @{ ok = $false; reason = 'the notification path (Send-PimNotifyMail) is not available in this runtime' }
    }
    # Everything the -WhatIf path CAN answer: kill switch, disabled feature,
    # allowlist, missing template. It renders but never sends.
    try {
        # 🪤 BUG-85 -- THE PROBE MUST CARRY EVERY TOKEN THE TEMPLATE USES, OR IT CRIES WOLF.
        # This token set was missing TapStartLocal / TapStartUtc / TapLifetimeMinutes, so each
        # readiness check rendered the real template with holes in it and warned
        #     [Mail] unknown token(s): TapStartLocal, TapStartUtc, TapLifetimeMinutes -- rendered empty.
        # Measured 2026-08-27: three admins produced three of those warnings during a run whose
        # ACTUAL TAP mails were complete and correct -- the real send at
        # PIM-EngineProviders.ps1:2450 passes all six. The warning named a live delivery defect
        # that did not exist, in the one mail where "valid until when?" is the whole point, and it
        # cost a full image-content investigation to disprove.
        # A diagnostic that reports a fault in the thing it is only pretending to do is worse than
        # no diagnostic. Keep this set in step with templates/mail/tap-delivery.mailtemplate.html.
        $probeTokens = @{
            UserPrincipalName = 'probe'; TapCode = ''; TapExpiresUtc = ''
            TapStartLocal = ''; TapStartUtc = ''; TapLifetimeMinutes = ''
        }
        $probe = Send-PimNotifyMail -Type 'tap-delivery' -Tokens $probeTokens -Recipient $Recipient -WhatIf
        $reason = "$($probe.reason)"
        if ($reason -and $reason -ne 'whatif') { return @{ ok = $false; reason = $reason } }
    } catch {
        return @{ ok = $false; reason = "mail pre-check failed: $($_.Exception.Message)" }
    }
    return @{ ok = $true; reason = '' }
}
