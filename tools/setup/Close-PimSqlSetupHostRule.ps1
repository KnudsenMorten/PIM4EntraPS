#Requires -Version 5.1
<#
.SYNOPSIS
    Remove THIS build's setup-host firewall rule ('AllowSetupHost') from an environment's SQL server, and read it back.

.DESCRIPTION
    IMP-49 t: host-side SQL steps (schema, grants, access, registry, the job deploys) connect from the build host's public IP
    through the 'AllowSetupHost' firewall rule. The one-shot MSP build runs the hosting step with -KeepSetupHostRule, so the
    store steps AFTER it can still connect -- and this is the build's LAST step on a public store, so a finished build
    leaves no standing hole for the machine that built it. (A private store's 'sqlclose' step, Set-PimSqlBuildWindow.ps1
    -Mode Close, already removes it.)

    Removes ONLY 'AllowSetupHost'. It never touches 'AllowAzureServices' or a virtual network rule: on a public store the
    environment itself may reach SQL through those, and removing them would cut it off its own database.
    Idempotent: a rule that is already gone is reported, not an error. ARM REST only (100.41, no az CLI): every call names
    the subscription; no default context exists to change.

.EXAMPLE
    .\Close-PimSqlSetupHostRule.ps1 -SubscriptionId <sub> -ResourceGroup rg-automateit-<token> -SqlServerName sql-ait-<token>
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$SqlServerName
)
$ErrorActionPreference = 'Stop'
# 100.41 (NO-AZ): ARM REST (engine/_shared/PIM-ArmSetup.ps1) over PIM-Rest's ONE token client. A caller that already set up
# PIM-Rest's identity (the MSP build's step launcher) keeps it; otherwise sign in: the Invardia Support app's REST session for
# this tenant, else the person at the keyboard. Every path names the subscription; there is no default context to change.
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
$subId = "$SubscriptionId".Trim()
$srv = ("$SqlServerName".Trim() -split '\.')[0]
if (-not $global:PIM_SetupRestMode -and -not "$($global:PIM_ClientId)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $subId) }
$acctObj = Get-PimArmSubscription -SubscriptionId $subId -ErrorAsNull
$acct = if ($acctObj) { "$($acctObj.subscriptionId)".Trim() } else { '' }
if ($acct -ne $subId) { throw "the signed-in identity cannot see subscription '$SubscriptionId' (read '$acct') -- refusing." }
Write-Host "==> SQL setup-host rule: close on $srv" -ForegroundColor Cyan
$readRule = { $r = Get-PimArmSqlFirewallRule -SubscriptionId $subId -ResourceGroup $ResourceGroup -Server $srv -Name 'AllowSetupHost' -ErrorAsNull; if ($r -and $r.properties) { "$($r.properties.startIpAddress)".Trim() } else { '' } }
$exists = Get-PimArmSqlServer -SubscriptionId $subId -ResourceGroup $ResourceGroup -Name $srv -ErrorAsNull
if (-not $exists) { throw "SQL server '$srv' not found in $ResourceGroup (subscription $SubscriptionId)" }
$ip = & $readRule
if (-not $ip) { Write-Host "    'AllowSetupHost' is not present -- nothing to close." -ForegroundColor DarkGray; return }
if ($PSCmdlet.ShouldProcess("$srv/AllowSetupHost ($ip)", 'delete firewall rule')) {
    [void](Remove-PimArmSqlFirewallRule -SubscriptionId $subId -ResourceGroup $ResourceGroup -Server $srv -Name AllowSetupHost)
    $after = & $readRule
    if ($after) { throw "'AllowSetupHost' ($after) is STILL present on $srv after the delete -- the build host keeps SQL access; remove it by hand." }
    Write-Host "    CLOSED: 'AllowSetupHost' ($ip) removed from $srv (read back). AllowAzureServices / VNet rules untouched." -ForegroundColor Green
}
