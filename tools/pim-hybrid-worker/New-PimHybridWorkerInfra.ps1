#Requires -Version 5.1
<#
.SYNOPSIS
    §80.2 PIMHYBRIDWRK -- the Azure half of the hybrid worker: its own resource group + VNet, peered to the networks it
    needs so the peering can be CUT (Set-PimHybridWorkerPeering.ps1 -State Disconnected) without touching anything else.

.DESCRIPTION
    Read-before-write and idempotent; -WhatIf prints the plan. Every az call pins --subscription.

      * Resource group + VNet (-AddressPrefix, default 10.221.16.0/24) with ONE subnet carrying the Microsoft.Sql service
        endpoint, so the PIM store admits the worker by SUBNET (a VNet rule), not by an IP allow-list.
      * NSG on the subnet: an explicit DENY-ALL inbound (priority 4096) above Azure's default "allow VNet inbound" -- the
        worker is contacted by nobody. Management is Azure run-command (outbound agent channel), never RDP.
      * Peering to each -PeerVnetId (both directions, no gateway transit): the network with the domain controllers is
        required; the PIM environment's VNet is optional. VNet DNS = -DnsServers (the DCs).
      * The VM: Windows Server 2022 Azure Edition CORE, small disk (-VmSize, default Standard_B2s: 4 GiB), Trusted Launch,
        system-assigned managed identity, hotpatch / platform patching, no public inbound. Egress (Graph, SQL, Windows
        Update): a Standard static public IP with no inbound allowed (-Egress PublicIp, ~3.65 USD/month), or -Egress None
        when your network already provides outbound (NAT gateway / firewall route).
      * The local administrator password is generated, used once and DISCARDED -- break-glass is `az vm user update`.
      * SQL VNet rule on -SqlServerId for the worker subnet.

    Cost (West Europe, pay-as-you-go, 2026-09-29): B2s Windows ~40.9 + E4 disk 2.4 + public IP 3.65 = ~47 USD/month
    (B1ms, 2 GiB, ~26 USD/month works but leaves little memory once both worker tasks run).

.EXAMPLE
    .\New-PimHybridWorkerInfra.ps1 -SubscriptionId <sub> -TenantId <tenant> -ResourceGroup rg-pimhybridwrk `
        -PeerVnetId <dc-vnet-id>,<pim-vnet-id> -DnsServers 10.0.1.4,10.0.1.5 -SqlServerId <sql-server-id> -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$TenantId,
    [string]$ResourceGroup = 'rg-pimhybridwrk',
    [string]$Location = 'westeurope',
    [ValidatePattern('^[A-Za-z0-9-]{1,15}$')][string]$VmName = 'PIMHYBRIDWRK',
    [string]$VmSize = 'Standard_B2s',   # 4 GiB: B1ms (2 GiB) left ~150-250 MB free with both worker tasks running (measured 2026-09-29)
    [string]$VnetName = 'vnet-pimhybridwrk',
    [string]$AddressPrefix = '10.221.16.0/24',
    [string]$SubnetPrefix = '10.221.16.0/27',
    [Parameter(Mandatory)][string[]]$PeerVnetId,
    [Parameter(Mandatory)][string[]]$DnsServers,
    [string]$SqlServerId = '',
    [ValidateSet('PublicIp', 'None')][string]$Egress = 'PublicIp',
    [string]$Image = 'MicrosoftWindowsServer:WindowsServer:2022-datacenter-azure-edition-core-smalldisk:latest'
)
$ErrorActionPreference = 'Stop'
$sub = @('--subscription', $SubscriptionId)
function Step($m) { Write-Host "[infra] $m" -ForegroundColor Cyan }
function Info($m) { Write-Host "        $m" -ForegroundColor Gray }
function AzRun { $ErrorActionPreference = 'Continue'; $o = & az @args 2>&1; if ($LASTEXITCODE -ne 0) { throw "az $($args[0..2] -join ' ') failed: $($o | Out-String)" }; $o | Where-Object { $_ -notmatch 'UserWarning|cryptography|site-packages' } }
function AzJson { $t = (AzRun @args) -join "`n"; if ($t.Trim()) { $t | ConvertFrom-Json } else { $null } }
function AzTry { $ErrorActionPreference = 'Continue'; $o = & az @args 2>$null; if ($LASTEXITCODE -ne 0 -or -not "$o".Trim()) { return $null }; ($o -join "`n") | ConvertFrom-Json }

$acct = AzJson account show @sub -o json
if ("$($acct.tenantId)" -ne $TenantId) { throw "the az profile is signed in to tenant '$($acct.tenantId)', not '$TenantId' -- set AZURE_CONFIG_DIR to a profile of the right tenant" }
Step "tenant $TenantId, subscription $SubscriptionId"

$subnetName = 'snet-worker'; $nsgName = "nsg-$($VmName.ToLowerInvariant())"; $pipName = "pip-$($VmName.ToLowerInvariant())"
if (-not (AzTry group show -n $ResourceGroup @sub -o json)) {
    if ($PSCmdlet.ShouldProcess($ResourceGroup, "create resource group in $Location")) { AzRun group create -n $ResourceGroup -l $Location @sub -o none | Out-Null }
}
Info "resource group $ResourceGroup"

# NSG: deny every inbound flow, including from peered networks
if (-not (AzTry network nsg show -g $ResourceGroup -n $nsgName @sub -o json)) {
    if ($PSCmdlet.ShouldProcess($nsgName, 'create NSG + DenyAllInbound')) {
        AzRun network nsg create -g $ResourceGroup -n $nsgName -l $Location @sub -o none | Out-Null
        AzRun network nsg rule create -g $ResourceGroup --nsg-name $nsgName -n DenyAllInbound --priority 4096 --direction Inbound --access Deny --protocol '*' --source-address-prefixes '*' --source-port-ranges '*' --destination-address-prefixes '*' --destination-port-ranges '*' @sub -o none | Out-Null
    }
}
Info "NSG $nsgName (deny all inbound)"

$vnet = AzTry network vnet show -g $ResourceGroup -n $VnetName @sub -o json
if (-not $vnet) {
    if ($PSCmdlet.ShouldProcess($VnetName, "create VNet $AddressPrefix, subnet $SubnetPrefix, DNS $($DnsServers -join ',')")) {
        AzRun network vnet create -g $ResourceGroup -n $VnetName -l $Location --address-prefixes $AddressPrefix --subnet-name $subnetName --subnet-prefixes $SubnetPrefix --dns-servers @DnsServers @sub -o none | Out-Null
        AzRun network vnet subnet update -g $ResourceGroup --vnet-name $VnetName -n $subnetName --network-security-group $nsgName --service-endpoints Microsoft.Sql Microsoft.Storage @sub -o none | Out-Null
        $vnet = AzJson network vnet show -g $ResourceGroup -n $VnetName @sub -o json
    }
} else {
    $have = @($vnet.dhcpOptions.dnsServers)
    if ((($have | Sort-Object) -join ',') -ne ((@($DnsServers) | Sort-Object) -join ',') -and $PSCmdlet.ShouldProcess($VnetName, "DNS -> $($DnsServers -join ',')")) {
        AzRun network vnet update -g $ResourceGroup -n $VnetName --dns-servers @DnsServers @sub -o none | Out-Null
    }
}
Info "VNet $VnetName $AddressPrefix, DNS $($DnsServers -join ', ')"
$subnetId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Network/virtualNetworks/$VnetName/subnets/$subnetName"
$vnetId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Network/virtualNetworks/$VnetName"

# peerings, both directions
foreach ($rid in $PeerVnetId) {
    if ($rid -notmatch '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Network/virtualNetworks/([^/]+)$') { throw "not a VNet resource id: '$rid'" }
    $rSub = $Matches[1]; $rRg = $Matches[2]; $rName = $Matches[3]
    $toName = "pimhybridwrk-to-$rName"; $fromName = "$rName-to-pimhybridwrk"
    if (-not (AzTry network vnet peering show -g $ResourceGroup --vnet-name $VnetName -n $toName @sub -o json) -and $PSCmdlet.ShouldProcess($toName, 'create peering')) {
        AzRun network vnet peering create -g $ResourceGroup --vnet-name $VnetName -n $toName --remote-vnet $rid --allow-vnet-access true --allow-forwarded-traffic false @sub -o none | Out-Null
    }
    if (-not (AzTry network vnet peering show -g $rRg --vnet-name $rName -n $fromName --subscription $rSub -o json) -and $PSCmdlet.ShouldProcess($fromName, 'create peering')) {
        AzRun network vnet peering create -g $rRg --vnet-name $rName -n $fromName --remote-vnet $vnetId --allow-vnet-access true --allow-forwarded-traffic false --subscription $rSub -o none | Out-Null
    }
    Info "peering $VnetName <-> $rName"
}

# egress
$pipArgs = @('--public-ip-address', '""')
if ($Egress -eq 'PublicIp') {
    if (-not (AzTry network public-ip show -g $ResourceGroup -n $pipName @sub -o json) -and $PSCmdlet.ShouldProcess($pipName, 'create Standard static public IP (egress only)')) {
        AzRun network public-ip create -g $ResourceGroup -n $pipName -l $Location --sku Standard --allocation-method Static @sub -o none | Out-Null
    }
    $pipArgs = @('--public-ip-address', $pipName)
    Info "egress via $pipName (inbound denied by $nsgName)"
}

# the VM
$vm = AzTry vm show -g $ResourceGroup -n $VmName @sub -o json
if (-not $vm) {
    if ($PSCmdlet.ShouldProcess($VmName, "create $VmSize ($Image), managed identity, Trusted Launch")) {
        $chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $bytes = New-Object byte[] 32; $rng.GetBytes($bytes)
        $pw = 'Pw9' + (-join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] }))
        try {
            AzRun vm create -g $ResourceGroup -n $VmName -l $Location --image $Image --size $VmSize --subnet $subnetId --nsg $nsgName @pipArgs `
                --admin-username pimlocal --admin-password $pw --assign-identity '[system]' --security-type TrustedLaunch --enable-secure-boot true --enable-vtpm true `
                --storage-sku StandardSSD_LRS --os-disk-delete-option Delete --nic-delete-option Delete --patch-mode AutomaticByPlatform --enable-hotpatching true `
                --license-type None @sub -o none | Out-Null
        } finally { $pw = $null }
        $vm = AzJson vm show -g $ResourceGroup -n $VmName @sub -o json
        Info 'local administrator password generated and discarded (reset with az vm user update when you need it)'
    }
}
$principalId = if ($vm) { "$($vm.identity.principalId)" } else { '<whatif>' }
Info "VM $VmName ($VmSize) managed identity $principalId"

if ($SqlServerId) {
    if ($SqlServerId -notmatch '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Sql/servers/([^/]+)$') { throw "not a SQL server id: '$SqlServerId'" }
    $sSub = $Matches[1]; $sRg = $Matches[2]; $sName = $Matches[3]
    if (-not (AzTry sql server vnet-rule show -g $sRg -s $sName -n pimhybridwrk --subscription $sSub -o json) -and $PSCmdlet.ShouldProcess($sName, 'SQL VNet rule for the worker subnet')) {
        AzRun sql server vnet-rule create -g $sRg -s $sName -n pimhybridwrk --subnet $subnetId --subscription $sSub -o none | Out-Null
    }
    Info "SQL $sName admits $subnetName"
}

Write-Host ''
Write-Host "[infra] done. Next: Initialize-PimHybridWorkerAd.ps1 (on a DC) -> Install-PimHybridWorker.ps1 -Phase Join / Configure (on $VmName) -> Grant-PimHybridWorkerAccess.ps1" -ForegroundColor Green
[pscustomobject]@{ vmName = $VmName; resourceGroup = $ResourceGroup; principalId = $principalId; subnetId = $subnetId; vnetId = $vnetId }
