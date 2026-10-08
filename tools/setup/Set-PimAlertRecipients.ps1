#Requires -Version 5.1
<#
.SYNOPSIS
    INSTALL-HARDEN-1 item 5 (PIM REQUIREMENTS §99, owner 2026-10-08) -- the install sets WHO GETS THE ALERTS:
    pim.Settings['Alerting'].recipients, in the shape the PIM Manager's PUT /api/alerting writes.

.DESCRIPTION
    After the 2026-10-08 installs the alert recipients were EMPTY: nothing ever wrote them, so every alert (engine failure,
    drift, break-glass, ...) rendered and reached nobody. Now every install path ends with them set:
      * -AlertRecipients (the install's 'alertRecipients'; a trial: the requester's address) when given, else
      * the -SuperAdmins' MAIL addresses, resolved UPN -> mail through Microsoft Graph (an account without a mailbox is skipped).
    🔒 A NON-EMPTY stored list is NEVER overwritten -- an administrator's choice wins over an install default.
    Everything else in the stored value (digest / tier-report lists, the event switches, the webhook) is kept.
    Written, READ BACK, audited ('settings.alerting.save', like the Manager).
    Exit codes: 0 set or kept; 2 nothing could be set (no address, no mailbox -- the GUI path is printed); 1 failed.

    Identity: -UseSignedInAccount (the signed-in az user or the Invardia Support app, a member of the SQL admin group), or a
    certificate identity (-ClientId / -CertThumbprint). Graph is read with the signed-in az context (pinned to -SubscriptionId).

.EXAMPLE
    .\Set-PimAlertRecipients.ps1 -SqlServerFqdn sql-pim-x.database.windows.net -TenantId <t> -SubscriptionId <s> -SuperAdmins admin@contoso.com -UseSignedInAccount
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [Parameter(Mandatory)][string]$TenantId,
    [string]$SubscriptionId,
    [string[]]$AlertRecipients = @(),
    [string[]]$SuperAdmins = @(),
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseSignedInAccount,
    [string]$OutFile,
    # --- TEST seams (tests/Test-PimInstallVerify.ps1) ---
    [scriptblock]$Store,      # param($op = get|set|audit, $name, $value) -> the stored value for 'get'
    [scriptblock]$Graph       # param($path) -> the Graph response object (throws on failure)
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimInstallVerify.ps1')
$result = [ordered]@{ ok = $false; action = ''; recipients = @(); skipped = @(); reason = '' }
function Write-Out { if ("$OutFile".Trim()) { try { $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutFile -Encoding UTF8 } catch { } } }
$norm = { param($l) @(@($l) | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
$AlertRecipients = @(& $norm $AlertRecipients); $SuperAdmins = @(& $norm $SuperAdmins)

if (-not $Store) {
    . (Join-Path $PSScriptRoot '_PimSetupSql.ps1')
    $cs = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -UseSignedInAccount:$UseSignedInAccount
    $Store = {
        param($op, $name, $value)
        switch ($op) {
            'get'   { return (Get-PimSqlSetting -ConnectionString $cs -Name $name) }
            'set'   { Set-PimSqlSetting -ConnectionString $cs -Name $name -Value $value; return $null }
            'audit' { Write-PimSetupAudit -ConnectionString $cs -Action 'settings.alerting.save' -Target $name -Before $value.before -After $value.after; return $null }
        }
    }
}
if (-not $Graph) {
    $Graph = {
        param($path)
        $ta = @('account', 'get-access-token', '--resource', 'https://graph.microsoft.com', '--query', 'accessToken', '-o', 'tsv')
        if ("$SubscriptionId".Trim()) { $ta += @('--subscription', "$SubscriptionId".Trim()) } else { $ta += @('--tenant', $TenantId) }
        $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        $tok = "$(& az @ta 2>$null)".Trim(); $ErrorActionPreference = $eap
        if (-not $tok) { throw 'no Microsoft Graph token from the signed-in az context' }
        Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/$path" -Headers @{ Authorization = "Bearer $tok" } -TimeoutSec 30
    }
}

Write-Host "==> alert recipients on $SqlServerFqdn" -ForegroundColor Cyan
$cur = $null
try { $cur = & $Store 'get' 'Alerting' $null } catch { $result.reason = "could not read pim.Settings['Alerting']: $($_.Exception.Message) -- refusing to write over an unread setting"; Write-Host "    FAILED: $($result.reason)" -ForegroundColor Red; Write-Out; exit 1 }
if ($cur -is [string]) { try { $cur = $cur | ConvertFrom-Json } catch { } }
$curRec = @(& $norm (Get-PimFactValue $cur 'recipients'))

$mailOf = @()
if (-not $curRec.Count -and -not $AlertRecipients.Count) {
    foreach ($u in $SuperAdmins) {
        $m = ''
        try { $usr = & $Graph "users/$([uri]::EscapeDataString($u))?`$select=mail,userPrincipalName"; $m = "$($usr.mail)".Trim() }
        catch { Write-Host "    $u : no directory read ($((($_.Exception.Message) -split "`n")[0])) -- skipped" -ForegroundColor DarkYellow }
        $mailOf += @{ upn = $u; mail = $m }
    }
}
$plan = Resolve-PimAlertRecipientsPlan -Current $curRec -Explicit $AlertRecipients -SuperAdminMail $mailOf
$result.action = $plan.action; $result.recipients = @($plan.recipients); $result.skipped = @($plan.skipped); $result.reason = $plan.reason
switch ($plan.action) {
    'keep' { Write-Host "    $($plan.reason)" -ForegroundColor DarkGray; $result.ok = $true; Write-Out; exit 0 }
    'none' {
        Write-Host "    NOT SET: $($plan.reason)." -ForegroundColor Yellow
        Write-Host '    Set them in the PIM Manager: Settings > Alerting > Recipients (or re-run this with -AlertRecipients <address>[,...]).' -ForegroundColor Yellow
        Write-Out; exit 2
    }
}
$value = ConvertTo-PimAlertingValue -Current $cur -Recipients $plan.recipients
if (-not $PSCmdlet.ShouldProcess("pim.Settings['Alerting']", "recipients = $($plan.recipients -join ', ')")) { $result.ok = $true; $result.reason = "what-if: $($plan.reason)"; Write-Out; exit 0 }
& $Store 'set' 'Alerting' $value | Out-Null
$back = & $Store 'get' 'Alerting' $null
if ($back -is [string]) { try { $back = $back | ConvertFrom-Json } catch { } }
$backRec = @(& $norm (Get-PimFactValue $back 'recipients'))
if (($backRec -join ',') -ne (@($plan.recipients) -join ',')) { $result.reason = "read-back mismatch: stored '$($backRec -join ',')'"; Write-Host "    FAILED: $($result.reason)" -ForegroundColor Red; Write-Out; exit 1 }
try { & $Store 'audit' 'Alerting' @{ before = @{ recipients = $curRec }; after = @{ recipients = @($plan.recipients) } } | Out-Null } catch { Write-Warning "audit not written: $($_.Exception.Message)" }
Write-Host "    set and read back: $($plan.reason)" -ForegroundColor Green
$result.ok = $true; Write-Out; exit 0
