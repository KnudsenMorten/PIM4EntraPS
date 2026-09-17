#Requires -Version 5.1
<#
.SYNOPSIS
    71.36 -- the PRIVATE store's BUILD WINDOW: -Open lets THIS host reach the environment's Azure SQL server for the minutes
    the MSP build runs its store steps; -Close takes that access away again and READS IT BACK.

.DESCRIPTION
    The MSP build's store steps (access, scenario, registry, register-<n>, the downlink/publish SQL checks, and the hosting
    step's own code/update checks) connect FROM THE DEPLOY HOST, which is not in the environment's VNet.

    TWO SHAPES, decided by what the server has:
      VNET-ONLY (no private endpoint on the server -- the MSP build's default for exposure internal):
        -Open   publicNetworkAccess Enabled + firewall rule AllowSetupHost = this host's public egress IP.
        -Close  deletes AllowSetupHost AND AllowAzureServices; REFUSES unless a virtual network rule remains (the
                environment's Container Apps subnet over its Microsoft.Sql service endpoint), so the Manager and the jobs
                keep their path. Result: the public endpoint accepts ONLY that subnet.
      PRIVATE ENDPOINT (the server has one):
        -Open   publicNetworkAccess Enabled + AllowSetupHost.
        -Close  publicNetworkAccess Disabled (firewall rules are then inert).
        🪤 MEASURED 2026-09-17 on mgmt1: once a SQL server has a private endpoint, public DNS answers its name with a CNAME
        to <server>.privatelink.database.windows.net, and mgmt1's DNS servers (10.100.1.5/.4) answer THAT name with
        NXDOMAIN -- so from mgmt1 the server is unreachable even with public access Enabled ("No such host is known").
        The private-endpoint shape therefore only works from a build host whose DNS resolves privatelink names publicly
        (or to the endpoint). This script says so when it opens a window on such a server.

    Authentication stays Entra-only in both shapes (grp-pim-sql-admins). The build runs -Open before its first store
    step and -Close as its last step; a failed build leaves the window OPEN so the printed -From resume works.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$SqlServerName,
    [Parameter(Mandatory)][ValidateSet('Open', 'Close', 'Show')][string]$Mode,
    [string]$HostIp
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $solRoot 'engine\_shared\PIM-MspBuild.ps1')
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
$sub = @('--subscription', "$SubscriptionId".Trim())
$srv = ("$SqlServerName".Trim() -split '\.')[0]
$acct = "$(az account show --query id -o tsv 2>$null)".Trim()
if ($acct -ne "$SubscriptionId".Trim()) { throw "az context is '$acct', not '$SubscriptionId' -- refusing." }
Write-Host "==> SQL build window: $Mode on $srv" -ForegroundColor Cyan
$ErrorActionPreference = 'Continue'
$readState = {
    $pna = "$(az sql server show @sub -g $ResourceGroup -n $srv --query publicNetworkAccess -o tsv --only-show-errors 2>$null)".Trim()
    $fw = @(az sql server firewall-rule list @sub -g $ResourceGroup -s $srv -o json --only-show-errors 2>$null | Out-String | ConvertFrom-Json)
    $vr = @(az sql server vnet-rule list @sub -g $ResourceGroup -s $srv --query "[].name" -o tsv --only-show-errors 2>$null | Where-Object { "$_".Trim() })
    $pe = @(az network private-endpoint list @sub -g $ResourceGroup -o json --only-show-errors 2>$null | Out-String | ConvertFrom-Json |
            Where-Object { "$(@($_.privateLinkServiceConnections)[0].privateLinkServiceId)" -match "/servers/$srv$" })
    @{ publicNetworkAccess = $pna; firewallRules = @($fw | Where-Object { $_ } | ForEach-Object { "$($_.name)" }); vnetRules = $vr; privateEndpoints = @($pe | ForEach-Object { $_.name }) }
}
$cur = & $readState
if (-not $cur.publicNetworkAccess) {
    # A greenfield build opens the window before the hosting step has created the server; prereq creates it with this
    # host's AllowSetupHost rule, which is exactly what the window would add.
    if ($Mode -eq 'Open') { Write-Host "    '$srv' does not exist yet -- the hosting step creates it with this host allowed; nothing to open." -ForegroundColor DarkGray; return }
    throw "SQL server '$srv' not found in $ResourceGroup"
}
$shape = if (@($cur.privateEndpoints).Count) { 'privateEndpoint' } else { 'vnetOnly' }
Note "now: shape=$shape publicNetworkAccess=$($cur.publicNetworkAccess) firewall=[$($cur.firewallRules -join ', ')] vnetRules=[$($cur.vnetRules -join ', ')] privateEndpoints=[$($cur.privateEndpoints -join ', ')]"
if ($Mode -eq 'Show') { $v = Test-PimSqlBuildWindowState -State $cur -Want 'Closed'; Note "closed: $($v.ok) $($v.reasons -join '; ')"; return }
if ($Mode -eq 'Open') {
    if (-not "$HostIp".Trim()) { $HostIp = "$((Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec 20).ip)".Trim() }
    if ("$HostIp" -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw "could not determine this host's egress IP ('$HostIp')" }
    if ($shape -eq 'privateEndpoint') { Write-Warning "'$srv' has a private endpoint: this host can use the window only if its DNS resolves $srv.privatelink.database.windows.net (mgmt1's DNS does NOT -- measured 2026-09-17)." }
    if ($PSCmdlet.ShouldProcess($srv, "open build window for $HostIp")) {
        if ($cur.publicNetworkAccess -ne 'Enabled') { az sql server update @sub -g $ResourceGroup -n $srv --enable-public-network true -o none --only-show-errors }
        az sql server firewall-rule create @sub -g $ResourceGroup -s $srv -n AllowSetupHost --start-ip-address $HostIp --end-ip-address $HostIp -o none --only-show-errors
    }
    $after = & $readState
    $fwIp = "$(az sql server firewall-rule show @sub -g $ResourceGroup -s $srv -n AllowSetupHost --query startIpAddress -o tsv --only-show-errors 2>$null)".Trim()
    Note "read back: publicNetworkAccess=$($after.publicNetworkAccess) AllowSetupHost=$fwIp"
    if ($after.publicNetworkAccess -ne 'Enabled' -or $fwIp -ne $HostIp) { throw 'build window did NOT open (see above)' }
    Write-Host "    OPEN for $HostIp -- close it with -Mode Close (the build's last step does)" -ForegroundColor Yellow
    Start-Sleep -Seconds 45   # SQL firewall changes take effect within ~a minute
    return
}
# Close
if ($shape -eq 'privateEndpoint') {
    if ($PSCmdlet.ShouldProcess($srv, 'close build window (public network access Disabled)') -and $cur.publicNetworkAccess -ne 'Disabled') {
        az sql server update @sub -g $ResourceGroup -n $srv --enable-public-network false -o none --only-show-errors
    }
} else {
    if (-not @($cur.vnetRules).Count) { throw "REFUSED: '$srv' has NO virtual network rule -- removing its firewall rules would cut the environment off its own database. Run the hosting step (sqlaccess) first." }
    foreach ($r in @('AllowSetupHost', 'AllowAzureServices')) {
        if ($cur.firewallRules -contains $r -and $PSCmdlet.ShouldProcess("$srv/$r", 'delete firewall rule')) {
            az sql server firewall-rule delete @sub -g $ResourceGroup -s $srv -n $r -o none --only-show-errors
        }
    }
}
$after = & $readState
$v = Test-PimSqlBuildWindowState -State $after -Want 'Closed'
Note "read back: publicNetworkAccess=$($after.publicNetworkAccess) firewall=[$($after.firewallRules -join ', ')] vnetRules=[$($after.vnetRules -join ', ')]"
if (-not $v.ok) { throw "build window did NOT close: $($v.reasons -join '; ')" }
Write-Host "    CLOSED: $($v.summary)" -ForegroundColor Green
