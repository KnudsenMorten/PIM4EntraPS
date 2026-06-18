<#
  PIM4EntraPS -- OUTBOUND ALERT CHANNELS (REQUIREMENTS §26c "Alerting (email /
  Teams)" + §28 [H2] residual: "the Teams/webhook channel -- only the email
  channel is wired today; the feed + dispatch are channel-agnostic so a Teams
  sender slots in behind the same Send-PimManagerAlert").

  This is the PURE, offline-testable core for a SECOND alert delivery channel:
  an outbound webhook (Microsoft Teams Incoming Webhook, or a generic JSON
  webhook). The existing email channel (Send-PimManagerAlert -> Send-PimNotifyMail)
  is untouched; a configured webhook fires IN ADDITION to mail, and the outcome of
  BOTH is recorded in the same alert feed (the recorded-send proof) so a
  "owners notified" / "Teams pinged" claim is verifiable.

  NO network here -- this file only:
    - Get-PimAlertChannelConfig    : normalise the stored channel config (defaults
                                     applied; URL kept only when plausibly valid).
    - Test-PimWebhookUrlAllowed    : is a webhook URL safe to POST to (https,
                                     well-formed, not a private/loopback host)?
    - Resolve-PimWebhookKind       : classify a URL as 'teams' | 'generic'.
    - New-PimWebhookPayload        : build the JSON body for the channel kind
                                     (Teams MessageCard / generic JSON) for ONE alert.
    - Get-PimChannelDedupeNote     : a short human note for the feed describing the
                                     channel outcome (delivered / rendered / failed).

  The actual HTTPS POST is the ONLY I/O and lives in the Manager (Open-PimManager.ps1
  Send-PimWebhookAlert) -- the same separation the mail channel uses (pure render
  here, the send in the channel layer). PS 5.1-safe: no ?./??, no
  RSA.ImportFromPem; .ToArray() not @() on List[object]; UTF8 handled by the caller.
#>
Set-StrictMode -Off

# Canonical event types -- mirrors PIM-AlertFeed / the Manager catalog so the
# channel core can label an event without loading the Manager.
$script:PimAlertChannelEventCatalog = @('engine-failure','drift','expiring-access','break-glass')

function Get-PimAlertChannelField {
    # Read a field from a hashtable OR a PSObject, returning '' when absent.
    param([Parameter(Mandatory)][object]$Item, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Item) { return '' }
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($Name)) { return "$($Item[$Name])" }; return '' }
    $p = $Item.PSObject.Properties[$Name]; if ($p) { return "$($p.Value)" }
    return ''
}

function Test-PimWebhookUrlAllowed {
    # PURE: is this a webhook URL we are willing to POST to? Rules (defence so a
    # mis-typed / hostile config can never make the Manager call an internal host
    # or plaintext endpoint):
    #   * must parse as an absolute URI
    #   * scheme MUST be https (an alert webhook over http is rejected)
    #   * host must not be empty, must not be a loopback / link-local / private /
    #     unspecified address or a bare hostname with no dot (SSRF hardening --
    #     a public webhook always has a public FQDN)
    # Returns @{ allowed=$bool; reason=<why-if-not> }.
    param([string]$Url)
    $u = "$Url".Trim()
    if (-not $u) { return @{ allowed = $false; reason = 'empty url' } }
    $uri = $null
    if (-not [System.Uri]::TryCreate($u, [System.UriKind]::Absolute, [ref]$uri)) {
        return @{ allowed = $false; reason = 'not a valid absolute URL' }
    }
    if ($uri.Scheme -ne 'https') { return @{ allowed = $false; reason = 'must be https' } }
    $h = "$($uri.Host)".Trim()
    if (-not $h) { return @{ allowed = $false; reason = 'no host' } }
    $hl = $h.ToLowerInvariant()
    if ($hl -eq 'localhost' -or $hl.EndsWith('.localhost')) { return @{ allowed = $false; reason = 'loopback host not allowed' } }
    # IP-literal host -> reject loopback / private / link-local / unspecified ranges.
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($h, [ref]$ip)) {
        if ([System.Net.IPAddress]::IsLoopback($ip)) { return @{ allowed = $false; reason = 'loopback IP not allowed' } }
        $b = $ip.GetAddressBytes()
        if ($b.Length -eq 4) {
            # IPv4 private / link-local / unspecified.
            if ($b[0] -eq 10) { return @{ allowed = $false; reason = 'private IP not allowed' } }
            if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return @{ allowed = $false; reason = 'private IP not allowed' } }
            if ($b[0] -eq 192 -and $b[1] -eq 168) { return @{ allowed = $false; reason = 'private IP not allowed' } }
            if ($b[0] -eq 169 -and $b[1] -eq 254) { return @{ allowed = $false; reason = 'link-local IP not allowed' } }
            if ($b[0] -eq 0) { return @{ allowed = $false; reason = 'unspecified IP not allowed' } }
        } else {
            # IPv6: reject link-local (fe80::/10) and unique-local (fc00::/7); loopback
            # already handled above.
            if (($b[0] -eq 0xfe) -and (($b[1] -band 0xc0) -eq 0x80)) { return @{ allowed = $false; reason = 'link-local IPv6 not allowed' } }
            if (($b[0] -band 0xfe) -eq 0xfc) { return @{ allowed = $false; reason = 'unique-local IPv6 not allowed' } }
        }
        return @{ allowed = $true; reason = '' }
    }
    # Hostname (not an IP) must contain a dot (no bare intranet names like "teams").
    if ($hl.IndexOf('.') -lt 0) { return @{ allowed = $false; reason = 'bare hostname not allowed (use a public FQDN)' } }
    return @{ allowed = $true; reason = '' }
}

function Resolve-PimWebhookKind {
    # PURE: classify a webhook URL. A Microsoft Teams Incoming Webhook lives on a
    # *.webhook.office.com / outlook.office.com host (Power Automate / connector
    # endpoints) -> render a Teams MessageCard. Anything else is a generic JSON
    # webhook. An explicit -Kind override (teams|generic) wins when supplied.
    param([string]$Url, [string]$Kind)
    $k = "$Kind".Trim().ToLowerInvariant()
    if ($k -eq 'teams' -or $k -eq 'generic') { return $k }
    $u = "$Url".Trim().ToLowerInvariant()
    $host_ = ''
    $uri = $null
    if ([System.Uri]::TryCreate($u, [System.UriKind]::Absolute, [ref]$uri)) { $host_ = "$($uri.Host)".ToLowerInvariant() }
    if ($host_ -match '(^|\.)webhook\.office\.com$' -or $host_ -match '(^|\.)office\.com$' -or $host_ -match 'logic\.azure\.com$') { return 'teams' }
    return 'generic'
}

function New-PimWebhookPayload {
    # PURE: build the JSON-serialisable body for ONE alert on the chosen channel
    # kind. Returns a PSCustomObject the caller serialises with ConvertTo-Json.
    #   * teams   -> a legacy "MessageCard" (the format an Incoming Webhook renders)
    #                with a colour by event severity, title, the detail, and facts.
    #   * generic -> a flat JSON object (event/title/detail/tenant/instance/when/link)
    #                a generic consumer / Logic App can act on.
    # Severity colour: break-glass + engine-failure = red, drift = amber,
    # expiring-access = blue. ManagerBaseUrl (optional) makes the deep-link absolute.
    param(
        [Parameter(Mandatory)][string]$Event,
        [string]$Title,
        [string]$Detail,
        [string]$LinkTab,
        [string]$TenantName = '',
        [string]$Instance = '',
        [string]$Kind = 'generic',
        [string]$ManagerBaseUrl = '',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $ev = "$Event".Trim()
    $title = $(if ("$Title".Trim()) { "$Title".Trim() } else { $ev })
    $whenUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
    $colourMap = @{ 'break-glass' = 'D13438'; 'engine-failure' = 'D13438'; 'drift' = 'D4A72C'; 'expiring-access' = '0078D4' }
    $colour = $(if ($colourMap.ContainsKey($ev)) { $colourMap[$ev] } else { '57606A' })
    $link = ''
    if ("$LinkTab".Trim()) {
        $base = "$ManagerBaseUrl".Trim().TrimEnd('/')
        $link = $(if ($base) { "$base/#$($LinkTab.Trim())" } else { "#$($LinkTab.Trim())" })
    }
    if ($Kind -eq 'teams') {
        $facts = New-Object System.Collections.Generic.List[object]
        $facts.Add([pscustomobject]@{ name = 'Event';    value = $ev })
        if ("$TenantName".Trim()) { $facts.Add([pscustomobject]@{ name = 'Tenant';   value = "$TenantName".Trim() }) }
        if ("$Instance".Trim())   { $facts.Add([pscustomobject]@{ name = 'Instance'; value = "$Instance".Trim() }) }
        $facts.Add([pscustomobject]@{ name = 'When (UTC)'; value = $whenUtc })
        $section = [pscustomobject]@{
            activityTitle    = $title
            activitySubtitle = "PIM4EntraPS alert"
            text             = "$Detail"
            facts            = $facts.ToArray()
            markdown         = $true
        }
        $card = [ordered]@{
            '@type'      = 'MessageCard'
            '@context'   = 'http://schema.org/extensions'
            summary      = "PIM4EntraPS: $title"
            themeColor   = $colour
            title        = "PIM4EntraPS alert: $title"
            sections     = @($section)
        }
        if ($link) {
            $card['potentialAction'] = @([pscustomobject]@{
                '@type'  = 'OpenUri'
                name     = 'Open PIM Manager'
                targets  = @([pscustomobject]@{ os = 'default'; uri = $link })
            })
        }
        return [pscustomobject]$card
    }
    # generic
    return [pscustomobject]@{
        source     = 'PIM4EntraPS'
        event      = $ev
        title      = $title
        detail     = "$Detail"
        severity   = $(if ($ev -eq 'break-glass' -or $ev -eq 'engine-failure') { 'high' } elseif ($ev -eq 'drift') { 'medium' } else { 'info' })
        tenantName = "$TenantName"
        instance   = "$Instance"
        link       = $link
        whenUtc    = $NowUtc.ToUniversalTime().ToString('o')
    }
}

function Get-PimAlertChannelConfig {
    # PURE: normalise the stored webhook-channel config into a stable shape. Reads a
    # hashtable / PSObject / JSON-string store value (the same dual-shape tolerance
    # the rest of the Manager settings use). A URL is kept only when it passes
    # Test-PimWebhookUrlAllowed; an unsafe / blank URL leaves the channel disabled
    # (so a bad value never silently posts somewhere). Shape:
    #   @{ webhookUrl; webhookKind; webhookEnabled; webhookValid; webhookReason }
    param([object]$Raw)
    $url = ''; $kind = ''
    $r = $Raw
    if ($r -is [string]) { try { $r = $r | ConvertFrom-Json } catch { $r = $null } }
    if ($r) {
        $get = {
            param($obj, $key)
            if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($key)) { return $obj[$key] } return $null }
            $p = $obj.PSObject.Properties[$key]; if ($p) { return $p.Value } return $null
        }
        $url  = "$(& $get $r 'webhookUrl')".Trim()
        $kind = "$(& $get $r 'webhookKind')".Trim().ToLowerInvariant()
    }
    $check = Test-PimWebhookUrlAllowed -Url $url
    $valid = [bool]$check.allowed
    $resolvedKind = Resolve-PimWebhookKind -Url $url -Kind $kind
    [ordered]@{
        webhookUrl     = $url
        webhookKind    = $resolvedKind
        webhookEnabled = ($valid -and $url.Length -gt 0)
        webhookValid   = $valid
        webhookReason  = "$($check.reason)"
    }
}

function Get-PimChannelDedupeNote {
    # PURE: a short human note describing a channel send outcome, for the feed's
    # `reason` line so the recorded proof reads cleanly (e.g.
    # "mail: 2 sent; webhook(teams): delivered").
    param([int]$MailSent = 0, [string]$WebhookKind = '', [string]$WebhookState = '')
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add("mail: $([math]::Max(0,$MailSent)) sent")
    if ("$WebhookKind".Trim()) {
        $st = $(if ("$WebhookState".Trim()) { "$WebhookState".Trim() } else { 'n/a' })
        $parts.Add("webhook($($WebhookKind.Trim())): $st")
    }
    return ($parts.ToArray() -join '; ')
}
