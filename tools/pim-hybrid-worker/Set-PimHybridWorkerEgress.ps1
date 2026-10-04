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

    Read-before-write and idempotent; -WhatIf prints the plan. Every az call pins --subscription. In order:
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
$sub = @('--subscription', $SubscriptionId)
function Step($m) { Write-Host "[egress] $m" -ForegroundColor Cyan }
function Info($m) { Write-Host "         $m" -ForegroundColor Gray }
function AzRun { $ErrorActionPreference = 'Continue'; $o = & az @args 2>&1; if ($LASTEXITCODE -ne 0) { throw "az $($args[0..2] -join ' ') failed: $($o | Out-String)" }; $o | Where-Object { "$_" -notmatch '^WARNING|UserWarning|cryptography|site-packages' } }
function AzJson { $t = (AzRun @args) -join "`n"; if ($t.Trim()) { $t | ConvertFrom-Json } else { $null } }
function AzTry { $ErrorActionPreference = 'Continue'; $o = & az @args 2>$null; if ($LASTEXITCODE -ne 0 -or -not "$o".Trim()) { return $null }; ($o -join "`n") | ConvertFrom-Json }

$lower = $VmName.ToLowerInvariant()
if (-not $NatGatewayName) { $NatGatewayName = "natgw-$lower" }
if (-not $PublicIpName) { $PublicIpName = "pip-$lower" }

$acct = AzJson account show @sub -o json
if ("$($acct.tenantId)" -ne $TenantId) { throw "the az profile is signed in to tenant '$($acct.tenantId)', not '$TenantId' -- set AZURE_CONFIG_DIR to a profile of the right tenant" }
$subnet = AzTry network vnet subnet show -g $ResourceGroup --vnet-name $VnetName -n $SubnetName @sub -o json
if (-not $subnet) { throw "subnet $VnetName/$SubnetName not found in $ResourceGroup" }
if (-not $Location) { $Location = "$((AzJson network vnet show -g $ResourceGroup -n $VnetName @sub -o json).location)" }
Step "worker $VmName in $ResourceGroup ($Location): outbound through NAT gateway $NatGatewayName, no public IP on the VM"

# 1. the NAT gateway
$nat = AzTry network nat gateway show -g $ResourceGroup -n $NatGatewayName @sub -o json
if (-not $nat -and $PSCmdlet.ShouldProcess($NatGatewayName, 'create NAT gateway (Standard, outbound only)')) {
    AzRun network nat gateway create -g $ResourceGroup -n $NatGatewayName -l $Location --idle-timeout 4 @sub -o none | Out-Null
    $nat = AzJson network nat gateway show -g $ResourceGroup -n $NatGatewayName @sub -o json
}
Info "NAT gateway $NatGatewayName"

# 2. no public IP on the VM's NICs (the address itself is kept for step 3)
$vm = AzTry vm show -g $ResourceGroup -n $VmName @sub -o json
$detached = @()
if ($vm) {
    foreach ($nicRef in @($vm.networkProfile.networkInterfaces)) {
        $nic = AzJson network nic show --ids "$($nicRef.id)" -o json
        foreach ($ipc in @($nic.ipConfigurations)) {
            if (-not $ipc.publicIPAddress) { continue }
            $pipId = "$($ipc.publicIPAddress.id)"
            if ($PSCmdlet.ShouldProcess("$($nic.name)/$($ipc.name)", "DETACH public IP $(($pipId -split '/')[-1])")) {
                AzRun network nic ip-config update -g "$($nic.resourceGroup)" --nic-name "$($nic.name)" -n "$($ipc.name)" --remove publicIpAddress @sub -o none | Out-Null
            }
            $detached += $pipId
            Info "detached $(($pipId -split '/')[-1]) from $($nic.name)"
        }
    }
} else { Info "VM $VmName not found -- the subnet is prepared; the VM must be created WITHOUT a public IP" }

# 3. the NAT gateway's outbound address: the detached one (an allow-list naming it keeps working), else pip-<vm>
$pipId = if ($detached.Count) { $detached[0] } else { '' }
if (-not $pipId) {
    $pip = AzTry network public-ip show -g $ResourceGroup -n $PublicIpName @sub -o json
    if ($pip -and $pip.ipConfiguration -and "$($pip.ipConfiguration.id)" -notmatch '/natGateways/') { throw "public IP $PublicIpName is attached to '$($pip.ipConfiguration.id)' -- refusing to move it" }
    if (-not $pip -and $PSCmdlet.ShouldProcess($PublicIpName, 'create Standard static public IP (the NAT gateway''s outbound address)')) {
        AzRun network public-ip create -g $ResourceGroup -n $PublicIpName -l $Location --sku Standard --allocation-method Static @sub -o none | Out-Null
        $pip = AzJson network public-ip show -g $ResourceGroup -n $PublicIpName @sub -o json
    }
    $pipId = if ($pip) { "$($pip.id)" } else { '<whatif>' }
}
$natIps = if ($nat) { @($nat.publicIpAddresses | ForEach-Object { "$($_.id)" }) } else { @() }
if (($natIps -notcontains $pipId) -and $PSCmdlet.ShouldProcess($NatGatewayName, "outbound address $(($pipId -split '/')[-1])")) {
    AzRun network nat gateway update -g $ResourceGroup -n $NatGatewayName --public-ip-addresses $pipId @sub -o none | Out-Null
}
Info "outbound address $(($pipId -split '/')[-1])"

# 4. the subnet: through the NAT gateway, and no implicit default outbound access
if ($PSCmdlet.ShouldProcess("$VnetName/$SubnetName", "use $NatGatewayName; default outbound access OFF")) {
    AzRun network vnet subnet update -g $ResourceGroup --vnet-name $VnetName -n $SubnetName --nat-gateway $NatGatewayName --default-outbound false @sub -o none | Out-Null
}

# 5. verify
if ($WhatIfPreference) { Step 'plan only (-WhatIf): nothing changed'; return }
$bad = @()
$vm = AzTry vm show -g $ResourceGroup -n $VmName @sub -o json
if ($vm) {
    foreach ($nicRef in @($vm.networkProfile.networkInterfaces)) {
        $nic = AzJson network nic show --ids "$($nicRef.id)" -o json
        foreach ($ipc in @($nic.ipConfigurations)) { if ($ipc.publicIPAddress) { $bad += "$($nic.name)/$($ipc.name) still has a public IP" } }
    }
}
$s2 = AzJson network vnet subnet show -g $ResourceGroup --vnet-name $VnetName -n $SubnetName @sub -o json
if ("$($s2.natGateway.id)" -notmatch "/natGateways/$([regex]::Escape($NatGatewayName))$") { $bad += "the subnet does not use $NatGatewayName" }
if ($bad.Count) { throw ("egress NOT as required: " + ($bad -join '; ')) }
$ip = "$((AzJson network public-ip show --ids $pipId -o json).ipAddress)"
Step "done: $VmName has NO public IP; outbound leaves through $NatGatewayName as $ip; inbound stays denied by the NSG"
