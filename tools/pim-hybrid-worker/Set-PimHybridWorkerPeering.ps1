#Requires -Version 5.1
<#
.SYNOPSIS
    §80.2 PIMHYBRIDWRK -- CUT or RESTORE the hybrid worker's network reach in one command (operator 2026-09-29: "so we can
    disconnect the peering if necessary").

.DESCRIPTION
    -State Disconnected sets allowVirtualNetworkAccess = false on BOTH sides of every peering of the worker's VNet: traffic
    stops at once, the peerings stay (so reconnecting restores exactly the same topology, and the remote networks'
    owners see a deliberate "access disabled", not a deleted object). -State Connected turns it back on. -State Show
    prints the current state and changes nothing.
    While disconnected the worker cannot reach a domain controller: its AD jobs FAIL (loudly, in Jobs) rather than act.
    SQL + Graph still work over its egress, which is what lets it report that.

    100.41 (framework 12.17 NO-AZ): ARM REST through PIM-Rest's ONE token client (engine/_shared/PIM-ArmSetup.ps1) -- a
    calling run's REST session as it is; standalone, the Invardia Support app's session or the person signed in. No az.

.EXAMPLE
    .\Set-PimHybridWorkerPeering.ps1 -SubscriptionId <sub> -TenantId <tenant> -State Disconnected
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][ValidateSet('Connected', 'Disconnected', 'Show')][string]$State,
    [string]$ResourceGroup = 'rg-pimhybridwrk',
    [string]$VnetName = 'vnet-pimhybridwrk'
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId) }
$net = Get-PimSetupApiVersion network
$acct = Get-PimArmSubscription -SubscriptionId $SubscriptionId
if ("$($acct.tenantId)" -ne $TenantId) { throw "subscription $SubscriptionId reads tenant '$($acct.tenantId)', not '$TenantId'" }
function Get-PeeringList([string]$Sub, [string]$Rg, [string]$Vnet) {
    # az network vnet peering list: ARM nests the peering's fields under .properties
    @(Invoke-PimSetupArm -Path (Get-PimArmResourceId $Sub $Rg 'Microsoft.Network/virtualNetworks' $Vnet 'virtualNetworkPeerings') -ApiVersion $net -All | Where-Object { $_ -and $_.name })
}
$want = ($State -eq 'Connected')
$selfId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Network/virtualNetworks/$VnetName"
foreach ($p in @(Get-PeeringList $SubscriptionId $ResourceGroup $VnetName)) {
    $sides = @(@{ sub = $SubscriptionId; rg = $ResourceGroup; vnet = $VnetName; name = $p.name })
    if ("$($p.properties.remoteVirtualNetwork.id)" -match '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Network/virtualNetworks/([^/]+)$') {
        $r = @{ sub = $Matches[1]; rg = $Matches[2]; vnet = $Matches[3] }
        $back = @(Get-PeeringList $r.sub $r.rg $r.vnet) | Where-Object { "$($_.properties.remoteVirtualNetwork.id)" -ieq $selfId }
        foreach ($b in @($back)) { $sides += @{ sub = $r.sub; rg = $r.rg; vnet = $r.vnet; name = $b.name } }
    }
    foreach ($s in $sides) {
        $id = Get-PimArmResourceId $s.sub $s.rg 'Microsoft.Network/virtualNetworks' $s.vnet "virtualNetworkPeerings/$($s.name)"
        $cur = Invoke-PimSetupArm -Path $id -ApiVersion $net
        $cp = $cur.properties
        $line = "{0}/{1}: access={2} state={3}" -f $s.vnet, $s.name, $cp.allowVirtualNetworkAccess, $cp.peeringState
        if ($State -eq 'Show' -or [bool]$cp.allowVirtualNetworkAccess -eq $want) { Write-Host "  $line" -ForegroundColor Gray; continue }
        if ($PSCmdlet.ShouldProcess("$($s.vnet)/$($s.name)", "allowVirtualNetworkAccess = $want")) {
            # az network vnet peering update --set allowVirtualNetworkAccess=X: read-modify-write of the writable fields (a PUT
            # without remoteVirtualNetwork / the transit flags would be refused or reset them).
            $body = @{ properties = @{ remoteVirtualNetwork = @{ id = "$($cp.remoteVirtualNetwork.id)" }; allowVirtualNetworkAccess = $want
                                       allowForwardedTraffic = [bool]$cp.allowForwardedTraffic; allowGatewayTransit = [bool]$cp.allowGatewayTransit
                                       useRemoteGateways = [bool]$cp.useRemoteGateways } }
            try { [void](Invoke-PimSetupArm -Method PUT -Path $id -Body $body -ApiVersion $net) }
            catch { throw "could not update $($s.vnet)/$($s.name): $($_.Exception.Message)" }
            Write-Host "  $($s.vnet)/$($s.name): access -> $want" -ForegroundColor $(if ($want) { 'Green' } else { 'Yellow' })
        }
    }
}
