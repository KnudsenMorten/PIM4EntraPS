<#
  Offline tests for the OUTBOUND ALERT CHANNELS pure core
  (engine/_shared/PIM-AlertChannels.ps1 -- REQUIREMENTS §26c "Alerting (email /
  Teams)" + §28 [H2] residual "the Teams/webhook channel").

  Proves (PURE -- no network, clock injected):
    * Test-PimWebhookUrlAllowed rejects http / loopback / private / bare hosts and
      accepts a public https FQDN (SSRF hardening for the outbound POST);
    * Resolve-PimWebhookKind auto-detects a Teams webhook host + honours an override;
    * New-PimWebhookPayload renders a Teams MessageCard (colour by severity, facts,
      deep-link action) and a generic JSON body, both JSON-serialisable;
    * Get-PimAlertChannelConfig normalises the stored value, keeps a URL only when
      safe, and disables the channel on a bad/blank/unsafe URL;
    * Get-PimChannelDedupeNote composes a clean two-channel reason line.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-AlertChannels.ps1"

$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }
$now = ([datetime]'2026-06-16T12:00:00Z').ToUniversalTime()

Write-Host "=== PIM-AlertChannels tests ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Test-PimWebhookUrlAllowed -- SSRF / safety hardening
# ---------------------------------------------------------------------------
Assert 'url: public https FQDN allowed'        ((Test-PimWebhookUrlAllowed -Url 'https://contoso.webhook.office.com/webhookb2/abc').allowed)
Assert 'url: generic public https allowed'      ((Test-PimWebhookUrlAllowed -Url 'https://hooks.example.com/services/T/B/X').allowed)
Assert 'url: http rejected (must be https)'     (-not (Test-PimWebhookUrlAllowed -Url 'http://contoso.webhook.office.com/x').allowed)
Assert 'url: blank rejected'                    (-not (Test-PimWebhookUrlAllowed -Url '').allowed)
Assert 'url: garbage rejected'                  (-not (Test-PimWebhookUrlAllowed -Url 'not a url').allowed)
Assert 'url: localhost rejected'                (-not (Test-PimWebhookUrlAllowed -Url 'https://localhost/hook').allowed)
Assert 'url: loopback IP rejected'              (-not (Test-PimWebhookUrlAllowed -Url 'https://127.0.0.1/hook').allowed)
Assert 'url: private 10.x rejected'             (-not (Test-PimWebhookUrlAllowed -Url 'https://10.1.2.3/hook').allowed)
Assert 'url: private 192.168 rejected'          (-not (Test-PimWebhookUrlAllowed -Url 'https://192.168.0.5/hook').allowed)
Assert 'url: private 172.16 rejected'           (-not (Test-PimWebhookUrlAllowed -Url 'https://172.16.0.9/hook').allowed)
Assert 'url: link-local 169.254 rejected'       (-not (Test-PimWebhookUrlAllowed -Url 'https://169.254.169.254/metadata').allowed)
Assert 'url: bare hostname (no dot) rejected'   (-not (Test-PimWebhookUrlAllowed -Url 'https://teams/hook').allowed)
Assert 'url: public IPv4 allowed'               ((Test-PimWebhookUrlAllowed -Url 'https://8.8.8.8/hook').allowed)
Assert 'url: IPv6 loopback rejected'            (-not (Test-PimWebhookUrlAllowed -Url 'https://[::1]/hook').allowed)
Assert 'url: IPv6 unique-local rejected'        (-not (Test-PimWebhookUrlAllowed -Url 'https://[fc00::1]/hook').allowed)
Assert 'url: rejection carries a reason'        (("$((Test-PimWebhookUrlAllowed -Url 'http://x.com').reason)").Length -gt 0)

# ---------------------------------------------------------------------------
# 2. Resolve-PimWebhookKind -- detect Teams vs generic; honour override
# ---------------------------------------------------------------------------
Assert 'kind: office.com webhook -> teams'      ((Resolve-PimWebhookKind -Url 'https://contoso.webhook.office.com/webhookb2/abc') -eq 'teams')
Assert 'kind: logic.azure.com -> teams'         ((Resolve-PimWebhookKind -Url 'https://prod-1.westeurope.logic.azure.com/workflows/x') -eq 'teams')
Assert 'kind: other host -> generic'            ((Resolve-PimWebhookKind -Url 'https://hooks.example.com/x') -eq 'generic')
Assert 'kind: explicit generic overrides host'  ((Resolve-PimWebhookKind -Url 'https://contoso.webhook.office.com/x' -Kind 'generic') -eq 'generic')
Assert 'kind: explicit teams overrides host'    ((Resolve-PimWebhookKind -Url 'https://hooks.example.com/x' -Kind 'teams') -eq 'teams')
Assert 'kind: bad override falls back to detect' ((Resolve-PimWebhookKind -Url 'https://hooks.example.com/x' -Kind 'bogus') -eq 'generic')

# ---------------------------------------------------------------------------
# 3. New-PimWebhookPayload -- Teams MessageCard
# ---------------------------------------------------------------------------
$teams = New-PimWebhookPayload -Event 'break-glass' -Title 'Break-glass ACTIVATED' -Detail 'by ops; reason X' -LinkTab 'governance' -TenantName 'Contoso' -Instance 'prod' -Kind 'teams' -ManagerBaseUrl 'https://pim.example.com/' -NowUtc $now
Assert 'teams: @type=MessageCard'               ($teams.'@type' -eq 'MessageCard')
Assert 'teams: red themeColor for break-glass'  ($teams.themeColor -eq 'D13438')
Assert 'teams: title carries the alert title'   ($teams.title -match 'Break-glass ACTIVATED')
Assert 'teams: detail in section text'          ($teams.sections[0].text -eq 'by ops; reason X')
$factNames = @($teams.sections[0].facts | ForEach-Object { $_.name })
Assert 'teams: facts include Event + Tenant'    (($factNames -contains 'Event') -and ($factNames -contains 'Tenant'))
Assert 'teams: deep-link action present'        ($teams.potentialAction[0].targets[0].uri -eq 'https://pim.example.com/#governance')
$teamsJson = $teams | ConvertTo-Json -Depth 8
Assert 'teams: serialises to JSON'              ("$teamsJson".Length -gt 10 -and "$teamsJson" -match 'MessageCard')

$teamsDrift = New-PimWebhookPayload -Event 'drift' -Title 'Drift' -Detail 'm=1' -Kind 'teams' -NowUtc $now
Assert 'teams: amber themeColor for drift'      ($teamsDrift.themeColor -eq 'D4A72C')
$teamsExp = New-PimWebhookPayload -Event 'expiring-access' -Title 'Exp' -Detail 'x' -Kind 'teams' -NowUtc $now
Assert 'teams: blue themeColor for expiring'    ($teamsExp.themeColor -eq '0078D4')
Assert 'teams: no link -> no potentialAction'   ($null -eq $teamsDrift.potentialAction)

# ---------------------------------------------------------------------------
# 4. New-PimWebhookPayload -- generic JSON
# ---------------------------------------------------------------------------
$gen = New-PimWebhookPayload -Event 'engine-failure' -Title "Job 'x' FAILED" -Detail 'boom' -LinkTab 'jobs' -TenantName 'Contoso' -Instance 'prod' -Kind 'generic' -NowUtc $now
Assert 'generic: source = PIM4EntraPS'          ($gen.source -eq 'PIM4EntraPS')
Assert 'generic: event carried'                 ($gen.event -eq 'engine-failure')
Assert 'generic: severity high for failure'     ($gen.severity -eq 'high')
Assert 'generic: detail carried'                ($gen.detail -eq 'boom')
Assert 'generic: ISO whenUtc'                    ("$($gen.whenUtc)" -match '^\d{4}-\d\d-\d\dT')
Assert 'generic: relative link when no base'     ($gen.link -eq '#jobs')
$genDrift = New-PimWebhookPayload -Event 'drift' -Title 'd' -Detail 'x' -Kind 'generic' -NowUtc $now
Assert 'generic: severity medium for drift'     ($genDrift.severity -eq 'medium')
$genExp = New-PimWebhookPayload -Event 'expiring-access' -Title 'e' -Detail 'x' -Kind 'generic' -NowUtc $now
Assert 'generic: severity info for expiring'    ($genExp.severity -eq 'info')
$genJson = $gen | ConvertTo-Json -Depth 8
Assert 'generic: serialises to JSON'            ("$genJson" -match 'PIM4EntraPS')

# ---------------------------------------------------------------------------
# 5. Get-PimAlertChannelConfig -- normalise stored value (dual shape)
# ---------------------------------------------------------------------------
$cfgHash = Get-PimAlertChannelConfig -Raw @{ webhookUrl = 'https://contoso.webhook.office.com/webhookb2/abc'; webhookKind = '' }
Assert 'cfg(hash): enabled on a safe URL'        ([bool]$cfgHash.webhookEnabled)
Assert 'cfg(hash): kind auto-detected teams'     ($cfgHash.webhookKind -eq 'teams')
Assert 'cfg(hash): valid flag set'               ([bool]$cfgHash.webhookValid)

$cfgJson = Get-PimAlertChannelConfig -Raw ('{"webhookUrl":"https://hooks.example.com/x","webhookKind":"generic"}')
Assert 'cfg(json-string): parsed + enabled'      ([bool]$cfgJson.webhookEnabled -and $cfgJson.webhookKind -eq 'generic')

$cfgPso = Get-PimAlertChannelConfig -Raw ([pscustomobject]@{ webhookUrl = 'https://hooks.example.com/x'; webhookKind = 'generic' })
Assert 'cfg(psobject): parsed + enabled'         ([bool]$cfgPso.webhookEnabled)

$cfgBad = Get-PimAlertChannelConfig -Raw @{ webhookUrl = 'http://10.0.0.1/x'; webhookKind = '' }
Assert 'cfg: unsafe URL -> disabled'             (-not [bool]$cfgBad.webhookEnabled)
Assert 'cfg: unsafe URL -> reason set'           (("$($cfgBad.webhookReason)").Length -gt 0)
Assert 'cfg: unsafe URL kept verbatim'           ($cfgBad.webhookUrl -eq 'http://10.0.0.1/x')

$cfgEmpty = Get-PimAlertChannelConfig -Raw $null
Assert 'cfg: null store -> disabled, blank URL'  ((-not [bool]$cfgEmpty.webhookEnabled) -and ($cfgEmpty.webhookUrl -eq ''))

# ---------------------------------------------------------------------------
# 6. Get-PimChannelDedupeNote -- two-channel reason line
# ---------------------------------------------------------------------------
Assert 'note: mail-only'                         ((Get-PimChannelDedupeNote -MailSent 2) -eq 'mail: 2 sent')
Assert 'note: mail + teams delivered'            ((Get-PimChannelDedupeNote -MailSent 1 -WebhookKind 'teams' -WebhookState 'delivered') -eq 'mail: 1 sent; webhook(teams): delivered')
Assert 'note: webhook-only failed'               ((Get-PimChannelDedupeNote -MailSent 0 -WebhookKind 'generic' -WebhookState 'failed') -eq 'mail: 0 sent; webhook(generic): failed')

Write-Host "`n=== RESULT: $pass pass, $fail fail ===" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 } else { exit 0 }
