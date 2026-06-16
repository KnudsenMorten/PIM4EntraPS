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
    if ($global:PIM_MailRedirectAllTo -and "$($global:PIM_MailRedirectAllTo)".Trim()) {
        $redir = "$($global:PIM_MailRedirectAllTo)".Trim()
        if ($rcpt -and $rcpt -ne $redir) { $Tokens = @{} + $Tokens; $Tokens['RedirectedFrom'] = $rcpt; Write-Host "  [Mail] redirect: '$rcpt' -> $redir" -ForegroundColor DarkYellow }
        $rcpt = $redir
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
