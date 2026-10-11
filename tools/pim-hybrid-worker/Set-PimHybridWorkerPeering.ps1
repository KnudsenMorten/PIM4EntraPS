#Requires -Version 5.1

<#
.SYNOPSIS
    §80.2 PIMHYBRIDWRK -- CUT or RESTORE the hybrid worker's network reach in one command (operator 2026-09-29: "so we can
    disconnect the peering if necessary").

.DESCRIPTION
    Shows, cuts or restores the hybrid worker's network reach by turning its VNet peerings off and on, without deleting
    anything.

    -State Disconnected sets allowVirtualNetworkAccess = false on BOTH sides of every peering of the worker's VNet: traffic
    stops at once, the peerings stay (so reconnecting restores exactly the same topology, and the remote networks'
    owners see a deliberate "access disabled", not a deleted object). -State Connected turns it back on. -State Show
    prints the current state (access, forwarded traffic, gateway transit, remote gateways) and changes nothing.
    While disconnected the worker cannot reach a domain controller: its AD jobs FAIL (loudly, in Jobs) rather than act.
    SQL + Graph still work over its egress, which is what lets it report that.

    §100.63 DOMAIN CONTROLLERS BEHIND A HUB GATEWAY (VPN / ExpressRoute), with -State Connected:
      -UseRemoteGateways -GatewayVnetId <hub>  the worker-side peering to the hub uses the hub's gateway. Checked first: the
                                               hub VNet must HAVE a gateway (GatewaySubnet with a virtual network gateway),
                                               and the hub-side peering must allow gateway transit. PIM sets
                                               allowGatewayTransit on the hub side ONLY when PIM created that peering
                                               ('<hub>-to-pimhybridwrk'); otherwise it PRINTS what the hub owner sets and
                                               leaves useRemoteGateways off (Azure refuses it without the hub side).
      -AllowForwardedTraffic                   the worker-side peering(s) accept traffic the hub forwards (an NVA / firewall
                                               in the hub routing your on-premises traffic) -- to -GatewayVnetId only when
                                               given, else every worker-side peering. The hub side is never needed for it.
    The hub owner's side also needs the worker range (-AddressPrefix of the infra build) routed / advertised to on-premises
    (the gateway does that for a peered VNet once gateway transit is on; check BGP / static routes and your firewall).

    100.41 (framework 12.17 NO-AZ): ARM REST through PIM-Rest's ONE token client (engine/_shared/PIM-ArmSetup.ps1) -- a
    calling run's REST session as it is; standalone, the Invardia Support app's session or the person signed in. No az.

.EXAMPLE
    .\Set-PimHybridWorkerPeering.ps1 -SubscriptionId <sub> -TenantId <tenant> -State Disconnected

.EXAMPLE
    .\Set-PimHybridWorkerPeering.ps1 -SubscriptionId <sub> -TenantId <tenant> -State Connected -UseRemoteGateways `
        -GatewayVnetId /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/virtualNetworks/<hub> -AllowForwardedTraffic -WhatIf

.LINK
    https://invardia.com/docs/pim/scripts/Set-PimHybridWorkerPeering/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][ValidateSet('Connected', 'Disconnected', 'Show')][string]$State,
    [string]$ResourceGroup = 'rg-pimhybridwrk',
    [string]$VnetName = 'vnet-pimhybridwrk',
    [switch]$UseRemoteGateways,
    [switch]$AllowForwardedTraffic,
    [string]$GatewayVnetId = ''
)
$ErrorActionPreference = 'Stop'

# 12.7 run frame: "<Script> version <x.y.z> - documentation: <page>" as the first line + a transcript in the temp folder.
. (Join-Path $PSScriptRoot '..\setup\_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Set-PimHybridWorkerPeering'
try {

if (($UseRemoteGateways -or $AllowForwardedTraffic) -and $State -ne 'Connected') { throw '-UseRemoteGateways / -AllowForwardedTraffic go with -State Connected' }
if ($UseRemoteGateways -and -not "$GatewayVnetId".Trim()) { throw '-UseRemoteGateways needs -GatewayVnetId (the hub VNet with the VPN / ExpressRoute gateway)' }
if ("$GatewayVnetId".Trim() -and "$GatewayVnetId".Trim() -notmatch '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/virtualNetworks/[^/]+$') { throw "-GatewayVnetId is not a VNet resource id: '$GatewayVnetId'" }
$hubId = "$GatewayVnetId".Trim()

$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId) }
$net = Get-PimSetupApiVersion network
$acct = Get-PimArmSubscription -SubscriptionId $SubscriptionId
if ("$($acct.tenantId)" -ne $TenantId) { throw "subscription $SubscriptionId reads tenant '$($acct.tenantId)', not '$TenantId'" }
function Get-PeeringList([string]$Sub, [string]$Rg, [string]$Vnet) {
    # az network vnet peering list: ARM nests the peering's fields under .properties
    @(Invoke-PimSetupArm -Path (Get-PimArmResourceId $Sub $Rg 'Microsoft.Network/virtualNetworks' $Vnet 'virtualNetworkPeerings') -ApiVersion $net -All -NotFoundOk | Where-Object { $_ -and $_.name })
}
function Set-PeeringFlags([string]$Id, $Cur, [hashtable]$Change, [string]$Label) {
    # az network vnet peering update --set X=Y: read-modify-write of ALL the writable fields (a PUT without remoteVirtualNetwork
    # or the transit flags would be refused or reset them).
    $cp = $Cur.properties
    $p = @{ remoteVirtualNetwork = @{ id = "$($cp.remoteVirtualNetwork.id)" }; allowVirtualNetworkAccess = [bool]$cp.allowVirtualNetworkAccess
            allowForwardedTraffic = [bool]$cp.allowForwardedTraffic; allowGatewayTransit = [bool]$cp.allowGatewayTransit; useRemoteGateways = [bool]$cp.useRemoteGateways }
    foreach ($k in $Change.Keys) { $p[$k] = [bool]$Change[$k] }
    $what = (@($Change.Keys | Sort-Object | ForEach-Object { "$_ = $([bool]$Change[$_])" })) -join ', '
    if (-not $PSCmdlet.ShouldProcess($Label, $what)) { return $false }
    try { [void](Invoke-PimSetupArm -Method PUT -Path $Id -Body @{ properties = $p } -ApiVersion $net) }
    catch { throw "could not update ${Label}: $($_.Exception.Message)" }
    Write-Host "  ${Label}: $what" -ForegroundColor Green
    return $true
}
function Test-PimHwHubGateway {
    # Does the hub VNet have a VPN / ExpressRoute gateway? (GatewaySubnet carrying a virtualNetworkGateways ip configuration)
    param([string]$VnetId)
    $v = Invoke-PimSetupArm -Path $VnetId -ApiVersion $net -NotFoundOk
    if (-not $v) { throw "hub VNet not found: $VnetId" }
    $gs = @(@($v.properties.subnets) | Where-Object { "$($_.name)" -eq 'GatewaySubnet' })
    return [bool](@($gs | ForEach-Object { @($_.properties.ipConfigurations) } | Where-Object { "$($_.id)" -match '/virtualNetworkGateways/' }).Count)
}

$want = ($State -eq 'Connected')
$selfId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Network/virtualNetworks/$VnetName"
$mine = @(Get-PeeringList $SubscriptionId $ResourceGroup $VnetName)
if (-not $mine.Count -and ($UseRemoteGateways -or $AllowForwardedTraffic)) {
    # a -WhatIf of the infrastructure build calls this before the VNet and its peerings exist: say what will happen
    if ($WhatIfPreference) { Write-Host "  plan only (-WhatIf): $VnetName has no peerings yet -- once they exist:$(if ($UseRemoteGateways) { " useRemoteGateways toward $(($hubId -split '/')[-1]) (after checking its gateway and gateway transit)" })$(if ($AllowForwardedTraffic) { ' allowForwardedTraffic on the worker side' })" -ForegroundColor Gray; return }
    throw "$VnetName has no peerings -- build them with New-PimHybridWorkerInfra.ps1 -PeerVnetId first"
}
foreach ($p in $mine) {
    $sides = @(@{ sub = $SubscriptionId; rg = $ResourceGroup; vnet = $VnetName; name = $p.name; worker = $true })
    if ("$($p.properties.remoteVirtualNetwork.id)" -match '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Network/virtualNetworks/([^/]+)$') {
        $r = @{ sub = $Matches[1]; rg = $Matches[2]; vnet = $Matches[3] }
        $back = @(Get-PeeringList $r.sub $r.rg $r.vnet) | Where-Object { "$($_.properties.remoteVirtualNetwork.id)" -ieq $selfId }
        foreach ($b in @($back)) { $sides += @{ sub = $r.sub; rg = $r.rg; vnet = $r.vnet; name = $b.name; worker = $false } }
    }
    foreach ($s in $sides) {
        $id = Get-PimArmResourceId $s.sub $s.rg 'Microsoft.Network/virtualNetworks' $s.vnet "virtualNetworkPeerings/$($s.name)"
        $cur = Invoke-PimSetupArm -Path $id -ApiVersion $net
        $cp = $cur.properties
        $line = "{0}/{1}: access={2} state={3} forwarded={4} gatewayTransit={5} remoteGateways={6}" -f $s.vnet, $s.name, $cp.allowVirtualNetworkAccess, $cp.peeringState, [bool]$cp.allowForwardedTraffic, [bool]$cp.allowGatewayTransit, [bool]$cp.useRemoteGateways
        if ($State -eq 'Show' -or [bool]$cp.allowVirtualNetworkAccess -eq $want) { Write-Host "  $line" -ForegroundColor Gray; continue }
        [void](Set-PeeringFlags -Id $id -Cur $cur -Change @{ allowVirtualNetworkAccess = $want } -Label "$($s.vnet)/$($s.name)")
    }
}

# ---- §100.63 gateway transit / forwarded traffic (after access, so the read below sees the current state)
if ($AllowForwardedTraffic) {
    $targets = @($mine | Where-Object { -not $hubId -or "$($_.properties.remoteVirtualNetwork.id)" -ieq $hubId })
    if (-not $targets.Count) { throw "no peering of $VnetName points at $(if ($hubId) { $hubId } else { 'any network' })" }
    foreach ($p in $targets) {
        $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/virtualNetworks' $VnetName "virtualNetworkPeerings/$($p.name)"
        $cur = Invoke-PimSetupArm -Path $id -ApiVersion $net
        if ([bool]$cur.properties.allowForwardedTraffic) { Write-Host "  $VnetName/$($p.name): allowForwardedTraffic already on" -ForegroundColor Gray; continue }
        [void](Set-PeeringFlags -Id $id -Cur $cur -Change @{ allowForwardedTraffic = $true } -Label "$VnetName/$($p.name)")
    }
}
if ($UseRemoteGateways) {
    $toHub = @($mine | Where-Object { "$($_.properties.remoteVirtualNetwork.id)" -ieq $hubId }) | Select-Object -First 1
    if (-not $toHub) { throw "no peering of $VnetName points at the hub $hubId -- build it with New-PimHybridWorkerInfra.ps1 -PeerVnetId <hub>" }
    if (-not (Test-PimHwHubGateway -VnetId $hubId)) { throw "the hub VNet $(($hubId -split '/')[-1]) has NO VPN / ExpressRoute gateway (no virtual network gateway in its GatewaySubnet) -- useRemoteGateways cannot work; peer the worker to the network that has the gateway" }
    Write-Host "  hub $(($hubId -split '/')[-1]): a virtual network gateway is present" -ForegroundColor Gray
    $hm = [regex]::Match($hubId, '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.Network/virtualNetworks/([^/]+)$')
    $hSub = $hm.Groups[1].Value; $hRg = $hm.Groups[2].Value; $hName = $hm.Groups[3].Value
    $hubSide = @(Get-PeeringList $hSub $hRg $hName) | Where-Object { "$($_.properties.remoteVirtualNetwork.id)" -ieq $selfId } | Select-Object -First 1
    if (-not $hubSide) { throw "the hub $hName has no peering back to $VnetName" }
    $hubReady = [bool]$hubSide.properties.allowGatewayTransit
    if (-not $hubReady) {
        $ownsHubSide = ("$($hubSide.name)" -ieq "$hName-to-pimhybridwrk")   # the name New-PimHybridWorkerInfra.ps1 gives the hub side it creates
        if ($ownsHubSide) {
            $hid = Get-PimArmResourceId $hSub $hRg 'Microsoft.Network/virtualNetworks' $hName "virtualNetworkPeerings/$($hubSide.name)"
            $hubReady = Set-PeeringFlags -Id $hid -Cur (Invoke-PimSetupArm -Path $hid -ApiVersion $net) -Change @{ allowGatewayTransit = $true } -Label "$hName/$($hubSide.name) (created by PIM)"
            if (-not $hubReady -and $WhatIfPreference) { $hubReady = $true }   # the plan continues as if it were applied
        } else {
            Write-Host ''
            Write-Host "  The hub-side peering $hName/$($hubSide.name) is NOT PIM's -- PIM does not change it. The HUB OWNER sets, on that peering:" -ForegroundColor Yellow
            Write-Host "    allowGatewayTransit = true   (portal: peering > 'Allow gateway transit' / 'use this virtual network's gateway')" -ForegroundColor Yellow
            Write-Host "    and routes / advertises the worker range to on-premises. Then run this again with -UseRemoteGateways." -ForegroundColor Yellow
            Write-Host "  useRemoteGateways stays OFF on the worker side until then (Azure refuses it without the hub side)." -ForegroundColor Yellow
        }
    }
    if ($hubReady) {
        $id = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/virtualNetworks' $VnetName "virtualNetworkPeerings/$($toHub.name)"
        $cur = Invoke-PimSetupArm -Path $id -ApiVersion $net
        if ([bool]$cur.properties.useRemoteGateways) { Write-Host "  $VnetName/$($toHub.name): useRemoteGateways already on" -ForegroundColor Gray }
        else { [void](Set-PeeringFlags -Id $id -Cur $cur -Change @{ useRemoteGateways = $true } -Label "$VnetName/$($toHub.name)") }
    }
}

} finally { Stop-PimScriptRun -Script 'Set-PimHybridWorkerPeering' }
