#Requires -Version 5.1
<#
.SYNOPSIS
    CUSTOMER TEMPLATE / SCHEMA DOC -- copy this file to
    PIM4EntraPS.NotificationChannels.custom.ps1 and uncomment + edit only
    the channels you actually use. The .custom.ps1 file is .gitignored
    and never leaves your VM.

.HOW IT'S LOADED
    engine/_shared/PIM-Functions.psm1 auto-loads
    PIM4EntraPS.NotificationChannels.locked.ps1 FIRST (ships with the
    repo, sets `$global:PIM_NotificationChannels = @{}`), then loads your
    .custom.ps1 SECOND. Anything you set here overwrites the locked
    defaults on a PER-KEY basis -- e.g. adding only `Smtp = @{...}` leaves
    Teams + Slack unconfigured (Send-PimAdminTap will just skip them).

.WHO READS THIS
    - Send-PimAdminTap                    (v2.2.0, roadmap #11)   -- delivers initial TAP codes
    - Send-PimAuditNotification           (v2.3.0, roadmap #22)   -- assignment created/removed events
    - Send-PimDailySummary                (v2.3.0, roadmap #23)   -- daily change digest

.SCHEMA -- every supported key

      Smtp.Server         -- mail relay hostname / IP                  (string, required)
      Smtp.Port           -- 25 / 465 / 587                            (int, default 25)
      Smtp.UseSsl         -- enable STARTTLS                           (bool, default false)
      Smtp.From           -- envelope FROM address                     (string, required)
      Smtp.Credential     -- PSCredential for AUTH; $null = anonymous  (object)

      Teams.WebhookUrl    -- incoming webhook URL                      (string, required)
                             Works with both classic Office365Connector
                             and Workflows-based Adaptive-Card endpoints.

      Slack.WebhookUrl    -- incoming webhook URL                      (string, required)
                             e.g. https://hooks.slack.com/services/T../B../X..

    All channels are best-effort: a 5xx from Teams won't stop the SMTP
    send and won't fail the engine. Failures are surfaced as
    Write-Warning + appear in the @{ Failed = @(); Errors = @{} } return
    value from the Send-Pim* helpers.

.NO PER-TENANT INFRA DEFAULTS
    Don't put SMTP host / port / webhook URLs anywhere except your own
    .custom.ps1 -- those are environment-specific and would leak into
    other customers if hard-coded in .locked.ps1.
#>

# ----- Example: SMTP only (recommended starting point) ---------------------
#
# $global:PIM_NotificationChannels = @{
#     Smtp = @{
#         Server     = 'smtp.contoso.com'
#         Port       = 587
#         UseSsl     = $true
#         From       = 'pim-noreply@contoso.com'
#         Credential = $null      # anonymous / IP-allow-listed relay
#         # Credential = (Get-Credential -Message 'SMTP AUTH for PIM4EntraPS')   # interactive
#         # Credential = (New-Object PSCredential 'smtpuser',(ConvertTo-SecureString 'kv-fetched' -AsPlainText -Force))
#     }
# }


# ----- Example: SMTP + Teams + Slack (all channels active) -----------------
#
# Send-PimAdminTap with no -Channel argument fans out to ALL configured
# channels best-effort. Useful when you want belt + suspenders delivery
# (Manager email + ops Teams channel + audit Slack channel).
#
# $global:PIM_NotificationChannels = @{
#     Smtp = @{
#         Server     = 'smtp.contoso.com'
#         Port       = 587
#         UseSsl     = $true
#         From       = 'pim-noreply@contoso.com'
#         Credential = $null
#     }
#     Teams = @{
#         WebhookUrl = 'https://contoso.webhook.office.com/webhookb2/...@.../IncomingWebhook/.../...'
#     }
#     Slack = @{
#         WebhookUrl = 'https://hooks.slack.com/services/T01XXXXX/B01XXXXX/xxxxxxxxxxxxxxxx'
#     }
# }


# ----- Example: pulling the SMTP credential from Key Vault -----------------
#
# $kvName = 'kv-contoso-pim-p'
# $smtpUserName = 'pim-smtp-user'
# $smtpSecret = Get-AzKeyVaultSecret -VaultName $kvName -Name 'pim-smtp-password' -AsPlainText
# $smtpCred = New-Object System.Management.Automation.PSCredential `
#     $smtpUserName, (ConvertTo-SecureString $smtpSecret -AsPlainText -Force)
#
# $global:PIM_NotificationChannels = @{
#     Smtp = @{
#         Server     = 'smtp.office365.com'
#         Port       = 587
#         UseSsl     = $true
#         From       = 'pim-noreply@contoso.com'
#         Credential = $smtpCred
#     }
# }


# ===========================================================================
# Redirect-all override (test / lab visibility)
# ===========================================================================
#
# When set, EVERY mail the engine sends (templated lifecycle mail + TAP
# delivery) goes to this one address instead of its real recipient -- so an
# operator can watch the entire mail flow from a single mailbox. The original
# recipient is logged and surfaced in the template token set ({RedirectedFrom}),
# never silently dropped. Leave unset/blank in production.
#
# $global:PIM_MailRedirectAllTo = 'mailflow-watch@contoso.com'


# ===========================================================================
# WhatIf semantics
# ===========================================================================
#
# When `$global:WhatIfMode -eq $true`, every Send-Pim* helper logs
# `[WHATIF] would send ... via <Channel>` and skips the actual POST /
# Send-MailMessage. Configure this once in your launcher (or run the
# engine with -WhatIfMode) when verifying channel wiring without
# spamming real recipients.
