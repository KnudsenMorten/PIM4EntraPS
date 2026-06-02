#Requires -Version 5.1
<#
.SYNOPSIS
    Default notification-channel config for PIM4EntraPS (v2.2.0+, roadmap #11).

.DESCRIPTION
    These are the defaults that ship from the repo: NO channels configured.
    A blank hashtable means Send-PimAdminTap / Send-PimAuditNotification /
    Send-PimDailySummary become no-ops (with a Write-Warning explaining how
    to opt in) instead of crashing on missing webhook URLs / SMTP servers.

    Customers opt in per channel by copying
    PIM4EntraPS.NotificationChannels.custom.sample.ps1 to
    PIM4EntraPS.NotificationChannels.custom.ps1 and uncommenting the entries
    they actually use. The .custom.ps1 is .gitignored and never leaves the
    customer's VM.

.HOW IT'S LOADED
    engine/_shared/PIM-Functions.psm1 auto-loads BOTH files at module-init
    time -- .locked.ps1 first, then .custom.ps1 if present. Per-key override
    semantics (any key set in .custom.ps1 wins over the locked default).

.SCHEMA
    $global:PIM_NotificationChannels = @{
        Smtp  = @{ Server; Port; UseSsl; From; Credential }   # optional
        Teams = @{ WebhookUrl }                               # optional
        Slack = @{ WebhookUrl }                               # optional
    }

    Keys NOT present in the hashtable = that channel is OFF. Engines never
    auto-discover SMTP / webhook URLs; the customer's .custom.ps1 is the
    only source.

.NOTES
    Solution     : PIM4EntraPS
    Developed by : Morten Knudsen, Microsoft MVP
#>

# Locked defaults: empty -- customer must opt in via .custom.ps1.
# DO NOT add per-tenant infra defaults here (SMTP server, port, etc.) --
# those vary per customer environment and belong in the .custom.ps1.
$global:PIM_NotificationChannels = @{}
