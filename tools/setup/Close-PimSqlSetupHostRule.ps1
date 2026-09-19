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
    Idempotent: a rule that is already gone is reported, not an error. Every az call carries --subscription; the az
    default context is never changed.

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
$sub = @('--subscription', "$SubscriptionId".Trim())
$srv = ("$SqlServerName".Trim() -split '\.')[0]
$acct = "$(az account show @sub --query id -o tsv 2>$null)".Trim()
if ($acct -ne "$SubscriptionId".Trim()) { throw "az cannot see subscription '$SubscriptionId' (read '$acct') -- refusing." }
Write-Host "==> SQL setup-host rule: close on $srv" -ForegroundColor Cyan
$ErrorActionPreference = 'Continue'
$readRule = { "$(az sql server firewall-rule list @sub -g $ResourceGroup -s $srv --query "[?name=='AllowSetupHost'].startIpAddress" -o tsv --only-show-errors 2>$null)".Trim() }
$exists = "$(az sql server show @sub -g $ResourceGroup -n $srv --query name -o tsv --only-show-errors 2>$null)".Trim()
if (-not $exists) { throw "SQL server '$srv' not found in $ResourceGroup (subscription $SubscriptionId)" }
$ip = & $readRule
if (-not $ip) { Write-Host "    'AllowSetupHost' is not present -- nothing to close." -ForegroundColor DarkGray; return }
if ($PSCmdlet.ShouldProcess("$srv/AllowSetupHost ($ip)", 'delete firewall rule')) {
    az sql server firewall-rule delete @sub -g $ResourceGroup -s $srv -n AllowSetupHost -o none --only-show-errors
    $after = & $readRule
    if ($after) { throw "'AllowSetupHost' ($after) is STILL present on $srv after the delete -- the build host keeps SQL access; remove it by hand." }
    Write-Host "    CLOSED: 'AllowSetupHost' ($ip) removed from $srv (read back). AllowAzureServices / VNet rules untouched." -ForegroundColor Green
}
