#Requires -Version 5.1
<#
.SYNOPSIS
    The hybrid worker's OUTBOUND path: a NAT gateway on its subnet, and NO public IP on the VM. Also MIGRATES a worker
    installed with the old default (-Egress PublicIp put a public IP on the VM's NIC).

.DESCRIPTION
    🔒 The worker writes AD (its gMSA can change AdminSDHolder-protected groups): it is a Tier-0 machine. It may reach
       Graph, the PIM store, its update source and Windows Update OUTBOUND, through the subnet's default gateway -- but it
       never has a public IP of its own, and nothing can open a connection to it (operator, 2026-10-04: "it just cannot
       have a public ip directly. use the nat gateway").

    Read-before-write and idempotent; -WhatIf prints the plan. Every ARM call names the subscription in its path (ARM REST
    through PIM-Rest's ONE token client, engine/_shared/PIM-ArmSetup.ps1 -- no az, 100.41 / framework 12.17). In order:
      1. the NAT gateway (Standard, idle timeout 4 min) -- created without an address first;
      2. the VM's NIC: a public IP on it is DETACHED (the address is kept, so an allow-list naming it -- a SQL firewall
         rule -- keeps working);
      3. that same public IP (or a new Standard static one) becomes the NAT gateway's OUTBOUND address;
      4. the worker subnet uses the NAT gateway, and Azure's implicit default outbound access is switched OFF;
      5. verified: no public IP on any NIC of the VM, the subnet points at the NAT gateway.
    Between 2 and 4 the worker has no outbound path for about a minute: its loops fail that pass and recover by themselves.

    Cost (West Europe, pay-as-you-go, 2026-10-04): NAT gateway ~32.9 USD/month + 0.045 USD/GB processed (the worker moves
    a few MB a day) + the Standard public IP 3.65 USD/month (the same one when migrating).

.EXAMPLE
    .\Set-PimHybridWorkerEgress.ps1 -SubscriptionId <sub> -TenantId <tenant> -ResourceGroup rg-pimhybridwrk -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$TenantId,
    [string]$ResourceGroup = 'rg-pimhybridwrk',
    [string]$Location = '',
    [ValidatePattern('^[A-Za-z0-9-]{1,15}$')][string]$VmName = 'PIMHYBRIDWRK',
    [string]$VnetName = 'vnet-pimhybridwrk',
    [string]$SubnetName = 'snet-worker',
    [string]$NatGatewayName = '',
    [string]$PublicIpName = ''
)
$ErrorActionPreference = 'Stop'
function Step($m) { Write-Host "[egress] $m" -ForegroundColor Cyan }
function Info($m) { Write-Host "         $m" -ForegroundColor Gray }
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId) }
$net = Get-PimSetupApiVersion network
$computeApi = '2024-03-01'
function NetId([string]$Type, [string]$Name, [string]$Child) { Get-PimArmResourceId $SubscriptionId $ResourceGroup "Microsoft.Network/$Type" $Name $Child }
function ArmTry([string]$Id, [string]$Api = $net) { Invoke-PimSetupArm -Path $Id -ApiVersion $Api -NotFoundOk }
function ArmPut([string]$Id, $Body, [string]$Api = $net) {
    [void](Invoke-PimSetupArm -Method PUT -Path $Id -Body $Body -ApiVersion $Api)
    $st = Wait-PimArmProvisioned -Path $Id -ApiVersion $Api
    if ($st -ne 'Succeeded') { throw "$(($Id -split '/')[-1]) did not provision ($st)" }
    Invoke-PimSetupArm -Path $Id -ApiVersion $Api
}

$lower = $VmName.ToLowerInvariant()
if (-not $NatGatewayName) { $NatGatewayName = "natgw-$lower" }
if (-not $PublicIpName) { $PublicIpName = "pip-$lower" }

$acct = Get-PimArmSubscription -SubscriptionId $SubscriptionId
if ("$($acct.tenantId)" -ne $TenantId) { throw "subscription $SubscriptionId reads tenant '$($acct.tenantId)', not '$TenantId' -- refusing" }
$subnetId = NetId 'virtualNetworks' $VnetName "subnets/$SubnetName"
$subnet = ArmTry $subnetId
if (-not $subnet) { throw "subnet $VnetName/$SubnetName not found in $ResourceGroup" }
if (-not $Location) { $Location = "$((Invoke-PimSetupArm -Path (NetId 'virtualNetworks' $VnetName) -ApiVersion $net).location)" }
Step "worker $VmName in $ResourceGroup ($Location): outbound through NAT gateway $NatGatewayName, no public IP on the VM"

# 1. the NAT gateway
$natId = NetId 'natGateways' $NatGatewayName
$nat = ArmTry $natId
if (-not $nat -and $PSCmdlet.ShouldProcess($NatGatewayName, 'create NAT gateway (Standard, outbound only)')) {
    # az network nat gateway create --idle-timeout 4
    $nat = ArmPut $natId @{ location = $Location; sku = @{ name = 'Standard' }; properties = @{ idleTimeoutInMinutes = 4 } }
}
Info "NAT gateway $NatGatewayName"

function Get-VmNics {
    $v = ArmTry (Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Compute/virtualMachines' $VmName) $computeApi
    if (-not $v) { return $null }
    return @(@($v.properties.networkProfile.networkInterfaces) | Where-Object { $_ } | ForEach-Object { Invoke-PimSetupArm -Path "$($_.id)" -ApiVersion $net })
}

# 2. no public IP on the VM's NICs (the address itself is kept for step 3)
$nics = Get-VmNics
$detached = @()
if ($null -ne $nics) {
    foreach ($nic in @($nics)) {
        $changed = $false
        foreach ($ipc in @($nic.properties.ipConfigurations)) {
            if (-not $ipc.properties.publicIPAddress) { continue }
            $pipId = "$($ipc.properties.publicIPAddress.id)"
            if ($PSCmdlet.ShouldProcess("$($nic.name)/$($ipc.name)", "DETACH public IP $(($pipId -split '/')[-1])")) {
                # az network nic ip-config update --remove publicIpAddress: read-modify-write of the whole NIC
                $ipc.properties.PSObject.Properties.Remove('publicIPAddress')
                $changed = $true
            }
            $detached += $pipId
            Info "detached $(($pipId -split '/')[-1]) from $($nic.name)"
        }
        if ($changed) {
            $body = @{ location = "$($nic.location)"; properties = $nic.properties }
            if ($nic.tags) { $body.tags = $nic.tags }
            [void](ArmPut "$($nic.id)" $body)
        }
    }
} else { Info "VM $VmName not found -- the subnet is prepared; the VM must be created WITHOUT a public IP" }

# 3. the NAT gateway's outbound address: the detached one (an allow-list naming it keeps working), else pip-<vm>
$pipId = if ($detached.Count) { $detached[0] } else { '' }
if (-not $pipId) {
    $pId = NetId 'publicIPAddresses' $PublicIpName
    $pip = ArmTry $pId
    if ($pip -and $pip.properties.ipConfiguration -and "$($pip.properties.ipConfiguration.id)" -notmatch '/natGateways/') { throw "public IP $PublicIpName is attached to '$($pip.properties.ipConfiguration.id)' -- refusing to move it" }
    if (-not $pip -and $PSCmdlet.ShouldProcess($PublicIpName, 'create Standard static public IP (the NAT gateway''s outbound address)')) {
        # az network public-ip create --sku Standard --allocation-method Static
        $pip = ArmPut $pId @{ location = $Location; sku = @{ name = 'Standard' }; properties = @{ publicIPAllocationMethod = 'Static'; publicIPAddressVersion = 'IPv4' } }
    }
    $pipId = if ($pip) { "$($pip.id)" } else { '<whatif>' }
}
$natIps = if ($nat) { @(@($nat.properties.publicIpAddresses) | Where-Object { $_ } | ForEach-Object { "$($_.id)" }) } else { @() }
if (($natIps -notcontains $pipId) -and $PSCmdlet.ShouldProcess($NatGatewayName, "outbound address $(($pipId -split '/')[-1])")) {
    # az network nat gateway update --public-ip-addresses ID (the list becomes exactly that address, as the flag did)
    $natCur = Invoke-PimSetupArm -Path $natId -ApiVersion $net
    [void](ArmPut $natId @{ location = "$($natCur.location)"; sku = @{ name = 'Standard' }
                            properties = @{ idleTimeoutInMinutes = [int]$(if ($natCur.properties.idleTimeoutInMinutes) { $natCur.properties.idleTimeoutInMinutes } else { 4 }); publicIpAddresses = @(@{ id = $pipId }) } })
}
Info "outbound address $(($pipId -split '/')[-1])"

# 4. the subnet: through the NAT gateway, and no implicit default outbound access
if ($PSCmdlet.ShouldProcess("$VnetName/$SubnetName", "use $NatGatewayName; default outbound access OFF")) {
    # az network vnet subnet update --nat-gateway N --default-outbound false: READ-MODIFY-WRITE (NSG, service endpoints kept)
    $cur = Invoke-PimSetupArm -Path $subnetId -ApiVersion $net
    $props = @{}
    foreach ($p in $cur.properties.PSObject.Properties) { if ($p.Name -notin @('provisioningState', 'ipConfigurations', 'purpose', 'privateEndpoints', 'serviceAssociationLinks', 'resourceNavigationLinks', 'ipConfigurationProfiles')) { $props[$p.Name] = $p.Value } }
    $props.natGateway = @{ id = $natId }
    $props.defaultOutboundAccess = $false
    [void](ArmPut $subnetId @{ properties = $props })
}

# 5. verify
if ($WhatIfPreference) { Step 'plan only (-WhatIf): nothing changed'; return }
$bad = @()
foreach ($nic in @(Get-VmNics | Where-Object { $_ })) {
    foreach ($ipc in @($nic.properties.ipConfigurations)) { if ($ipc.properties.publicIPAddress) { $bad += "$($nic.name)/$($ipc.name) still has a public IP" } }
}
$s2 = Invoke-PimSetupArm -Path $subnetId -ApiVersion $net
if ("$($s2.properties.natGateway.id)" -notmatch "/natGateways/$([regex]::Escape($NatGatewayName))$") { $bad += "the subnet does not use $NatGatewayName" }
if ($bad.Count) { throw ("egress NOT as required: " + ($bad -join '; ')) }
$ip = "$((Invoke-PimSetupArm -Path $pipId -ApiVersion $net).properties.ipAddress)"
Step "done: $VmName has NO public IP; outbound leaves through $NatGatewayName as $ip; inbound stays denied by the NSG"
