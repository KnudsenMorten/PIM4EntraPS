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
function AzJson { $ErrorActionPreference = 'Continue'; $o = & az @args 2>$null; if ($LASTEXITCODE -ne 0) { throw "az $($args[0..3] -join ' ') failed" }; if ("$o".Trim()) { ($o -join "`n") | ConvertFrom-Json } }
$acct = AzJson account show --subscription $SubscriptionId -o json
if ("$($acct.tenantId)" -ne $TenantId) { throw "the az profile is signed in to tenant '$($acct.tenantId)', not '$TenantId'" }
$want = ($State -eq 'Connected')
foreach ($p in @(@(AzJson network vnet peering list -g $ResourceGroup --vnet-name $VnetName --subscription $SubscriptionId -o json) | Where-Object { $_ -and $_.name })) {
    $sides = @(@{ sub = $SubscriptionId; rg = $ResourceGroup; vnet = $VnetName; name = $p.name })
    if ("$($p.remoteVirtualNetwork.id)" -match '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Network/virtualNetworks/([^/]+)$') {
        $r = @{ sub = $Matches[1]; rg = $Matches[2]; vnet = $Matches[3] }
        $back = @(AzJson network vnet peering list -g $r.rg --vnet-name $r.vnet --subscription $r.sub -o json) | Where-Object { "$($_.remoteVirtualNetwork.id)" -ieq "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Network/virtualNetworks/$VnetName" }
        foreach ($b in @($back)) { $sides += @{ sub = $r.sub; rg = $r.rg; vnet = $r.vnet; name = $b.name } }
    }
    foreach ($s in $sides) {
        $cur = AzJson network vnet peering show -g $s.rg --vnet-name $s.vnet -n $s.name --subscription $s.sub -o json
        $line = "{0}/{1}: access={2} state={3}" -f $s.vnet, $s.name, $cur.allowVirtualNetworkAccess, $cur.peeringState
        if ($State -eq 'Show' -or [bool]$cur.allowVirtualNetworkAccess -eq $want) { Write-Host "  $line" -ForegroundColor Gray; continue }
        if ($PSCmdlet.ShouldProcess("$($s.vnet)/$($s.name)", "allowVirtualNetworkAccess = $want")) {
            $ErrorActionPreference = 'Continue'; & az network vnet peering update -g $s.rg --vnet-name $s.vnet -n $s.name --subscription $s.sub --set "allowVirtualNetworkAccess=$($want.ToString().ToLowerInvariant())" -o none 2>$null
            $ErrorActionPreference = 'Stop'; if ($LASTEXITCODE -ne 0) { throw "could not update $($s.vnet)/$($s.name)" }
            Write-Host "  $($s.vnet)/$($s.name): access -> $want" -ForegroundColor $(if ($want) { 'Green' } else { 'Yellow' })
        }
    }
}
