#Requires -Version 5.1
<#
.SYNOPSIS
    §80.2 PIMHYBRIDWRK -- the Azure half of the hybrid worker: its own resource group + VNet, peered to the networks it
    needs so the peering can be CUT (Set-PimHybridWorkerPeering.ps1 -State Disconnected) without touching anything else.

.DESCRIPTION
    Read-before-write and idempotent; -WhatIf prints the plan. Every ARM call names the subscription in its path (ARM REST
    through PIM-Rest's ONE token client, engine/_shared/PIM-ArmSetup.ps1 -- no az, 100.41 / framework 12.17).

      * Resource group + VNet (-AddressPrefix, default 10.221.16.0/24) with ONE subnet carrying the Microsoft.Sql service
        endpoint, so the PIM store admits the worker by SUBNET (a VNet rule), not by an IP allow-list.
      * NSG on the subnet: an explicit DENY-ALL inbound (priority 4096) above Azure's default "allow VNet inbound" -- the
        worker is contacted by nobody. Management is Azure run-command (outbound agent channel), never RDP.
      * Peering to each -PeerVnetId (both directions, no gateway transit): the network with the domain controllers is
        required; the PIM environment's VNet is optional. VNet DNS = -DnsServers (the DCs).
      * The VM: Windows Server 2022 Azure Edition CORE, small disk (-VmSize, default Standard_B2s: 4 GiB), Trusted Launch,
        system-assigned managed identity, hotpatch / platform patching, no public inbound. Egress (Graph, SQL, Windows
        Update) goes OUT through a NAT gateway on the subnet (-Egress NatGateway, Set-PimHybridWorkerEgress.ps1); the VM NEVER
        gets a public IP (operator 2026-10-04 -- it is Tier 0): its NIC is created here with NO public IP configuration.
        -Egress None when your network already provides outbound (NAT gateway / firewall route).
      * The local administrator password is generated, used once and DISCARDED -- break-glass is the portal's "Reset
        password" (VMAccess extension).
      * SQL VNet rule on -SqlServerId for the worker subnet.

    Cost (West Europe, pay-as-you-go, 2026-10-04): B2s Windows ~40.9 + E4 disk 2.4 + NAT gateway ~32.9 + its public IP 3.65
    = ~80 USD/month
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
    [ValidateSet('NatGateway', 'None')][string]$Egress = 'NatGateway',   # 🔒 never a public IP on the VM (Set-PimHybridWorkerEgress.ps1)
    [string]$Image = 'MicrosoftWindowsServer:WindowsServer:2022-datacenter-azure-edition-core-smalldisk:latest'
)
$ErrorActionPreference = 'Stop'
function Step($m) { Write-Host "[infra] $m" -ForegroundColor Cyan }
function Info($m) { Write-Host "        $m" -ForegroundColor Gray }
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId) }
$net = Get-PimSetupApiVersion network
$computeApi = '2024-03-01'
function NetId([string]$Type, [string]$Name, [string]$Child) { Get-PimArmResourceId $SubscriptionId $ResourceGroup "Microsoft.Network/$Type" $Name $Child }
function ArmTry([string]$Id, [string]$Api = $net) { Invoke-PimSetupArm -Path $Id -ApiVersion $Api -NotFoundOk }
function ArmPut([string]$Id, $Body, [string]$Api = $net, [int]$TimeoutSeconds = 900) {
    [void](Invoke-PimSetupArm -Method PUT -Path $Id -Body $Body -ApiVersion $Api)
    $st = Wait-PimArmProvisioned -Path $Id -ApiVersion $Api -TimeoutSeconds $TimeoutSeconds
    if ($st -ne 'Succeeded') { throw "$(($Id -split '/')[-1]) did not provision ($st)" }
    Invoke-PimSetupArm -Path $Id -ApiVersion $Api
}

$acct = Get-PimArmSubscription -SubscriptionId $SubscriptionId
if ("$($acct.tenantId)" -ne $TenantId) { throw "subscription $SubscriptionId reads tenant '$($acct.tenantId)', not '$TenantId' -- refusing" }
Step "tenant $TenantId, subscription $SubscriptionId"

$subnetName = 'snet-worker'; $nsgName = "nsg-$($VmName.ToLowerInvariant())"; $nicName = "$($VmName.ToLowerInvariant())-nic"
if (-not (Get-PimArmResourceGroup -SubscriptionId $SubscriptionId -Name $ResourceGroup)) {
    if ($PSCmdlet.ShouldProcess($ResourceGroup, "create resource group in $Location")) { [void](Set-PimArmResourceGroup -SubscriptionId $SubscriptionId -Name $ResourceGroup -Location $Location) }
}
Info "resource group $ResourceGroup"

# NSG: deny every inbound flow, including from peered networks
$nsgId = NetId 'networkSecurityGroups' $nsgName
if (-not (ArmTry $nsgId)) {
    if ($PSCmdlet.ShouldProcess($nsgName, 'create NSG + DenyAllInbound')) {
        # az network nsg create + az network nsg rule create DenyAllInbound (one PUT carrying the rule)
        [void](ArmPut $nsgId @{ location = $Location; properties = @{ securityRules = @(@{ name = 'DenyAllInbound'; properties = @{
            priority = 4096; direction = 'Inbound'; access = 'Deny'; protocol = '*'; sourceAddressPrefix = '*'; sourcePortRange = '*'
            destinationAddressPrefix = '*'; destinationPortRange = '*' } }) } })
    }
}
Info "NSG $nsgName (deny all inbound)"

$vnetId = NetId 'virtualNetworks' $VnetName
$subnetId = NetId 'virtualNetworks' $VnetName "subnets/$subnetName"
$vnet = ArmTry $vnetId
if (-not $vnet) {
    if ($PSCmdlet.ShouldProcess($VnetName, "create VNet $AddressPrefix, subnet $SubnetPrefix, DNS $($DnsServers -join ',')")) {
        # az network vnet create --subnet-name --dns-servers + az network vnet subnet update --network-security-group
        # --service-endpoints Microsoft.Sql Microsoft.Storage: one PUT with the subnet complete
        $vnet = ArmPut $vnetId @{ location = $Location; properties = @{
            addressSpace = @{ addressPrefixes = @($AddressPrefix) }
            dhcpOptions  = @{ dnsServers = @($DnsServers) }
            subnets      = @(@{ name = $subnetName; properties = @{ addressPrefix = $SubnetPrefix; networkSecurityGroup = @{ id = $nsgId }
                                                                   serviceEndpoints = @(@{ service = 'Microsoft.Sql' }, @{ service = 'Microsoft.Storage' }) } }) } }
    }
} else {
    $have = @($vnet.properties.dhcpOptions.dnsServers)
    if ((($have | Sort-Object) -join ',') -ne ((@($DnsServers) | Sort-Object) -join ',') -and $PSCmdlet.ShouldProcess($VnetName, "DNS -> $($DnsServers -join ',')")) {
        # az network vnet update --dns-servers: read-modify-write (the PUT carries the existing subnets + peerings, never drops them)
        $vnet.properties | Add-Member -NotePropertyName dhcpOptions -NotePropertyValue @{ dnsServers = @($DnsServers) } -Force
        $body = @{ location = "$($vnet.location)"; properties = $vnet.properties }
        if ($vnet.tags) { $body.tags = $vnet.tags }
        $vnet = ArmPut $vnetId $body
    }
}
Info "VNet $VnetName $AddressPrefix, DNS $($DnsServers -join ', ')"

# peerings, both directions
foreach ($rid in $PeerVnetId) {
    if ($rid -notmatch '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Network/virtualNetworks/([^/]+)$') { throw "not a VNet resource id: '$rid'" }
    $rSub = $Matches[1]; $rRg = $Matches[2]; $rName = $Matches[3]
    $toName = "pimhybridwrk-to-$rName"; $fromName = "$rName-to-pimhybridwrk"
    if (-not (Get-PimArmVnetPeering -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -VnetName $VnetName -Name $toName) -and $PSCmdlet.ShouldProcess($toName, 'create peering')) {
        [void](New-PimArmVnetPeering -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -VnetName $VnetName -Name $toName -RemoteVnetId $rid -AllowVnetAccess $true -AllowForwardedTraffic $false)
    }
    if (-not (Get-PimArmVnetPeering -SubscriptionId $rSub -ResourceGroup $rRg -VnetName $rName -Name $fromName) -and $PSCmdlet.ShouldProcess($fromName, 'create peering')) {
        [void](New-PimArmVnetPeering -SubscriptionId $rSub -ResourceGroup $rRg -VnetName $rName -Name $fromName -RemoteVnetId $vnetId -AllowVnetAccess $true -AllowForwardedTraffic $false)
    }
    Info "peering $VnetName <-> $rName"
}

# egress -- 🔒 NEVER a public IP on the VM (operator 2026-10-04: "it just cannot have a public ip directly. use the nat
# gateway"). The worker is Tier 0: outbound goes through a NAT gateway on its subnet, nothing can connect in.
# Set-PimHybridWorkerEgress.ps1 is the one implementation (it also migrates a worker installed with the old PublicIp default).
if ($Egress -eq 'NatGateway') {
    & (Join-Path $PSScriptRoot 'Set-PimHybridWorkerEgress.ps1') -SubscriptionId $SubscriptionId -TenantId $TenantId -ResourceGroup $ResourceGroup `
        -Location $Location -VmName $VmName -VnetName $VnetName -SubnetName $subnetName -WhatIf:$WhatIfPreference
} else { Info "egress: -Egress None -- this subnet must already have an outbound path (NAT gateway / firewall route); the VM gets NO public IP" }

# the VM
$vmId = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Compute/virtualMachines' $VmName
$vm = ArmTry $vmId $computeApi
if (-not $vm) {
    if ($PSCmdlet.ShouldProcess($VmName, "create $VmSize ($Image), managed identity, Trusted Launch")) {
        $img = @("$Image" -split ':')
        if ($img.Count -ne 4) { throw "-Image must be Publisher:Offer:Sku:Version, not '$Image'" }
        # az vm create --subnet --nsg --public-ip-address "": the NIC, created here with NO public IP configuration (Tier 0).
        $nicId = NetId 'networkInterfaces' $nicName
        $nic = ArmTry $nicId
        if ($nic -and @(@($nic.properties.ipConfigurations) | Where-Object { $_.properties.publicIPAddress }).Count) { throw "NIC $nicName carries a public IP -- refusing (run Set-PimHybridWorkerEgress.ps1 first)" }
        if (-not $nic) {
            $nic = ArmPut $nicId @{ location = $Location; properties = @{ networkSecurityGroup = @{ id = $nsgId }
                ipConfigurations = @(@{ name = 'ipconfig1'; properties = @{ subnet = @{ id = $subnetId }; privateIPAllocationMethod = 'Dynamic' } }) } }
        }
        $chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $bytes = New-Object byte[] 32; $rng.GetBytes($bytes)
        $pw = 'Pw9' + (-join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] }))
        try {
            # az vm create --assign-identity [system] --security-type TrustedLaunch --enable-secure-boot --enable-vtpm
            # --storage-sku StandardSSD_LRS --os-disk-delete-option Delete --nic-delete-option Delete
            # --patch-mode AutomaticByPlatform --enable-hotpatching --license-type None
            $vm = ArmPut $vmId @{
                location = $Location
                identity = @{ type = 'SystemAssigned' }
                properties = @{
                    hardwareProfile = @{ vmSize = $VmSize }
                    storageProfile  = @{
                        imageReference = @{ publisher = $img[0]; offer = $img[1]; sku = $img[2]; version = $img[3] }
                        osDisk = @{ createOption = 'FromImage'; deleteOption = 'Delete'; managedDisk = @{ storageAccountType = 'StandardSSD_LRS' } }
                    }
                    osProfile = @{
                        computerName = $VmName; adminUsername = 'pimlocal'; adminPassword = $pw
                        windowsConfiguration = @{ provisionVMAgent = $true; enableAutomaticUpdates = $true
                                                  patchSettings = @{ patchMode = 'AutomaticByPlatform'; enableHotpatching = $true } }
                    }
                    networkProfile  = @{ networkInterfaces = @(@{ id = "$($nic.id)"; properties = @{ primary = $true; deleteOption = 'Delete' } }) }
                    securityProfile = @{ securityType = 'TrustedLaunch'; uefiSettings = @{ secureBootEnabled = $true; vTpmEnabled = $true } }
                    licenseType = 'None'
                }
            } $computeApi 1800
        } finally { $pw = $null }
        Info 'local administrator password generated and discarded (reset it from the portal when you need it)'
    }
}
$principalId = if ($vm) { "$($vm.identity.principalId)" } else { '<whatif>' }
Info "VM $VmName ($VmSize) managed identity $principalId"

if ($SqlServerId) {
    if ($SqlServerId -notmatch '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Sql/servers/([^/]+)$') { throw "not a SQL server id: '$SqlServerId'" }
    $sSub = $Matches[1]; $sRg = $Matches[2]; $sName = $Matches[3]
    $haveRule = @(Get-PimArmSqlVnetRules -SubscriptionId $sSub -ResourceGroup $sRg -Server $sName | Where-Object { "$($_.name)" -eq 'pimhybridwrk' }).Count
    if (-not $haveRule -and $PSCmdlet.ShouldProcess($sName, 'SQL VNet rule for the worker subnet')) {
        New-PimArmSqlVnetRule -SubscriptionId $sSub -ResourceGroup $sRg -Server $sName -Name pimhybridwrk -SubnetId $subnetId
    }
    Info "SQL $sName admits $subnetName"
}

Write-Host ''
Write-Host "[infra] done. Next: Initialize-PimHybridWorkerAd.ps1 (on a DC) -> Install-PimHybridWorker.ps1 -Phase Join / Configure (on $VmName) -> Grant-PimHybridWorkerAccess.ps1" -ForegroundColor Green
[pscustomobject]@{ vmName = $VmName; resourceGroup = $ResourceGroup; principalId = $principalId; subnetId = $subnetId; vnetId = $vnetId }
