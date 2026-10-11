#Requires -Version 5.1

<#
.SYNOPSIS
    §80.2 PIMHYBRIDWRK -- the Azure half of the hybrid worker: its own resource group + VNet, peered to the networks it
    needs so the peering can be CUT (Set-PimHybridWorkerPeering.ps1 -State Disconnected) without touching anything else.

.DESCRIPTION
    Builds the Azure side of the PIM for Active Directory hybrid worker -- its own resource group, network, deny-all
    firewall, NAT gateway egress and Windows VM -- or, for an Azure Arc-enabled on-premises server, checks the machine
    and builds nothing.

    Read-before-write and idempotent; -WhatIf prints the plan. Every ARM call names the subscription in its path (ARM REST
    through PIM-Rest's ONE token client, engine/_shared/PIM-ArmSetup.ps1 -- no az, 100.41 / framework 12.17).

      * Resource group + VNet (-AddressPrefix, default 10.221.16.0/24) with ONE subnet carrying the Microsoft.Sql service
        endpoint, so the PIM store admits the worker by SUBNET (a VNet rule), not by an IP allow-list.
      * NSG on the subnet: an explicit DENY-ALL inbound (priority 4096) above Azure's default "allow VNet inbound" -- the
        worker is contacted by nobody. Management is Azure run-command (outbound agent channel), never RDP.
      * Peering to each -PeerVnetId (both directions, no gateway transit): the network with the domain controllers is
        required; the PIM environment's VNet is optional. VNet DNS = -DnsServers (the DCs). DCs behind a hub VPN /
        ExpressRoute gateway: -UseRemoteGateways -GatewayVnetId <hub> (+ -AllowForwardedTraffic) via Set-PimHybridWorkerPeering.ps1.
      * Private-only PIM SQL: -PrivateSqlDnsZoneId links the existing privatelink.database.windows.net zone to the worker VNet
        (and -PrivateDnsLinkVnetId, e.g. the DCs' VNet); the DCs' conditional forwarder is PRINTED (PIM never writes AD DNS).
      * Every resource created carries the tag pim-hybrid-worker = <VmName> (Remove-PimHybridWorker.ps1 deletes only those).
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

.LINK
    https://invardia.com/docs/pim/scripts/New-PimHybridWorkerInfra/
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'AzureVm')]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$TenantId,
    # §100.63(b) ON-PREMISES: the customer's own Windows server, Azure Arc-enabled. Nothing is built in Azure (no resource
    # group, VNet, NSG, NAT gateway, peering or VM -- the on-premises network is the customer's); the machine is checked
    # (connected, Windows, a system-assigned identity) and its identity returned for Grant-PimHybridWorkerAccess.ps1.
    [Parameter(Mandatory, ParameterSetName = 'Arc')][string]$ArcMachineResourceId,
    [Parameter(ParameterSetName = 'Arc')][string]$ArcApiVersion = '2024-07-10',
    # Arc + a PUBLIC SQL endpoint: the on-premises egress address(es) the PIM store must admit (one firewall rule each).
    # Leave empty when the store is reached over a private endpoint (VPN / ExpressRoute) -- the better choice.
    [Parameter(ParameterSetName = 'Arc')][string[]]$SqlAllowedPublicIp = @(),
    [string]$ResourceGroup = 'rg-pimhybridwrk',
    [string]$Location = 'westeurope',
    [ValidatePattern('^[A-Za-z0-9-]{1,15}$')][string]$VmName = 'PIMHYBRIDWRK',
    [string]$VmSize = 'Standard_B2s',   # 4 GiB: B1ms (2 GiB) left ~150-250 MB free with both worker tasks running (measured 2026-09-29)
    [string]$VnetName = 'vnet-pimhybridwrk',
    [string]$AddressPrefix = '10.221.16.0/24',
    [string]$SubnetPrefix = '10.221.16.0/27',
    [Parameter(Mandatory, ParameterSetName = 'AzureVm')][string[]]$PeerVnetId,
    [Parameter(Mandatory, ParameterSetName = 'AzureVm')][string[]]$DnsServers,
    [string]$SqlServerId = '',
    [ValidateSet('NatGateway', 'None')][string]$Egress = 'NatGateway',   # 🔒 never a public IP on the VM (Set-PimHybridWorkerEgress.ps1)
    [string]$Image = 'MicrosoftWindowsServer:WindowsServer:2022-datacenter-azure-edition-core-smalldisk:latest',
    # §100.63 PRIVATE-ONLY PIM SQL. The worker VNet's DNS servers are the DCs, so a privatelink zone is only half the answer:
    # the zone is LINKED here (REST), and the conditional forwarder the AD DNS administrator adds on the DCs is PRINTED (PIM
    # never writes AD DNS). Only the standard zone privatelink.database.windows.net is accepted -- never a zone named after
    # your domain. -CreatePrivateDnsZone creates that standard zone ONLY when it is missing and you ask for it.
    [string]$PrivateSqlDnsZoneId = '',
    [string[]]$PrivateDnsLinkVnetId = @(),
    [switch]$CreatePrivateDnsZone,
    [string]$PrivateDnsZoneResourceGroup = '',
    [switch]$PrivateSql,
    [string]$DnsForwarderIp = '',
    # §100.63 DCs behind a hub VPN / ExpressRoute gateway: use the hub's gateway from the worker side (the hub side must allow
    # gateway transit -- set by PIM only on a hub-side peering PIM created, otherwise printed for the hub owner).
    [Parameter(ParameterSetName = 'AzureVm')][switch]$UseRemoteGateways,
    [Parameter(ParameterSetName = 'AzureVm')][string]$GatewayVnetId = '',
    [Parameter(ParameterSetName = 'AzureVm')][switch]$AllowForwardedTraffic
)
$ErrorActionPreference = 'Stop'

# 12.7 run frame: "<Script> version <x.y.z> - documentation: <page>" as the first line + a transcript in the temp folder.
. (Join-Path $PSScriptRoot '..\setup\_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'New-PimHybridWorkerInfra'
try {

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

# §100.63(e) every resource these scripts create carries this tag, so Remove-PimHybridWorker.ps1 deletes ONLY what they made.
$workerName = if ($PSCmdlet.ParameterSetName -eq 'Arc') { ($ArcMachineResourceId -split '/')[-1] } else { $VmName }
$pimTags = @{ 'pim-hybrid-worker' = $workerName; 'created-by' = 'PIM Manager hybrid worker scripts' }

# ---------------------------------------------------------------------------------------------------- §100.63 private SQL DNS
$script:PimSqlZoneName = 'privatelink.database.windows.net'
function Resolve-PimHwSqlZoneId {
    # PURE. The zone to link: -PrivateSqlDnsZoneId (must be THE standard zone), or the standard zone in -PrivateDnsZoneResourceGroup.
    param([string]$ZoneId, [string]$ZoneRg, [string]$Sub)
    if ("$ZoneId".Trim()) {
        if ("$ZoneId".Trim() -notmatch '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/privateDnsZones/([^/]+)$') { throw "-PrivateSqlDnsZoneId is not a private DNS zone resource id: '$ZoneId'" }
        if ($Matches[1] -ne $script:PimSqlZoneName) { throw "-PrivateSqlDnsZoneId names zone '$($Matches[1])' -- only the standard '$($script:PimSqlZoneName)' is accepted (PIM never creates or links a zone named after your domain)" }
        return "$ZoneId".Trim()
    }
    if ("$ZoneRg".Trim()) { return "/subscriptions/$Sub/resourceGroups/$("$ZoneRg".Trim())/providers/Microsoft.Network/privateDnsZones/$($script:PimSqlZoneName)" }
    return ''
}
function Set-PimHwSqlDnsLinks {
    # Link the standard zone to each VNet (an existing link to that VNet, of any name, is left alone); create the zone only
    # when it is missing AND -CreatePrivateDnsZone; when the SQL server's A record is missing, attach the zone to its private
    # endpoint only if the endpoint has no DNS zone group yet (otherwise say what is missing).
    param([string]$ZoneId, [string[]]$VnetIds)
    $zSub = Get-PimArmIdPart -Id $ZoneId -Segment 'subscriptions'; $zRg = Get-PimArmIdPart -Id $ZoneId -Segment 'resourceGroups'
    $zone = Get-PimArmPrivateDnsZone -SubscriptionId $zSub -ResourceGroup $zRg -Name $script:PimSqlZoneName
    if (-not $zone) {
        if (-not $CreatePrivateDnsZone) { throw "private DNS zone $ZoneId not found -- give the existing zone (the one your SQL private endpoint uses), or add -CreatePrivateDnsZone to create the standard zone" }
        if ($PSCmdlet.ShouldProcess($ZoneId, 'create the standard private DNS zone (it was missing; -CreatePrivateDnsZone)')) {
            [void](Invoke-PimSetupArm -Method PUT -Path $ZoneId -Body @{ location = 'global'; tags = $pimTags } -ApiVersion (Get-PimSetupApiVersion privateDns))
            [void](Wait-PimArmProvisioned -Path $ZoneId -ApiVersion (Get-PimSetupApiVersion privateDns))
        }
    }
    Info "private DNS zone $($script:PimSqlZoneName) ($zRg)"
    $links = @(Get-PimArmPrivateDnsLinks -SubscriptionId $zSub -ResourceGroup $zRg -ZoneName $script:PimSqlZoneName -ErrorAsNull)
    foreach ($v in @($VnetIds | Where-Object { "$_".Trim() } | Select-Object -Unique)) {
        $vn = ($v -split '/')[-1]
        if (@($links | Where-Object { "$($_.properties.virtualNetwork.id)" -ieq $v }).Count) { Info "  linked to $vn (already)"; continue }
        $ln = "link-pimhybridwrk-$($vn.ToLowerInvariant())"; if ($ln.Length -gt 80) { $ln = $ln.Substring(0, 80) }
        if ($PSCmdlet.ShouldProcess("$($script:PimSqlZoneName) -> $vn", "virtual network link $ln (no auto-registration)")) {
            $lid = "$ZoneId/virtualNetworkLinks/$ln"
            [void](Invoke-PimSetupArm -Method PUT -Path $lid -Body @{ location = 'global'; tags = $pimTags; properties = @{ virtualNetwork = @{ id = $v }; registrationEnabled = $false } } -ApiVersion (Get-PimSetupApiVersion privateDns))
            [void](Wait-PimArmProvisioned -Path $lid -ApiVersion (Get-PimSetupApiVersion privateDns))
        }
        Info "  linked to $vn"
    }
    if (-not $SqlServerId -or $WhatIfPreference) { return }
    $sName = ($SqlServerId -split '/')[-1]
    $recs = @(Get-PimArmPrivateDnsARecords -SubscriptionId $zSub -ResourceGroup $zRg -ZoneName $script:PimSqlZoneName -ErrorAsNull)
    if (@($recs | Where-Object { "$($_.name)" -ieq $sName }).Count) { Info "  A record $sName present"; return }
    $srv = Invoke-PimSetupArm -Path $SqlServerId -ApiVersion (Get-PimSetupApiVersion sql) -ErrorAsNull
    $peIds = @(@($srv.properties.privateEndpointConnections) | Where-Object { $_ } | ForEach-Object { "$($_.properties.privateEndpoint.id)" } | Where-Object { $_ })
    if (-not $peIds.Count) { Write-Host "        WARNING: $sName has no private endpoint -- a private-only database needs one (Convert-PimToPrivate.ps1)" -ForegroundColor Yellow; return }
    foreach ($pe in $peIds) {
        $groups = @(Invoke-PimSetupArm -Path "$pe/privateDnsZoneGroups" -ApiVersion (Get-PimSetupApiVersion network) -All -ErrorAsNull | Where-Object { $_ })
        if ($groups.Count) { Write-Host "        WARNING: no A record '$sName' in the zone, and private endpoint $(($pe -split '/')[-1]) already has a DNS zone group pointing elsewhere -- add the record (its private IP) yourself" -ForegroundColor Yellow; continue }
        if ($PSCmdlet.ShouldProcess(($pe -split '/')[-1], "DNS zone group -> $($script:PimSqlZoneName) (writes the A record for $sName)")) {
            $gid = "$pe/privateDnsZoneGroups/default"
            [void](Invoke-PimSetupArm -Method PUT -Path $gid -Body @{ properties = @{ privateDnsZoneConfigs = @(@{ name = 'privatelink-database-windows-net'; properties = @{ privateDnsZoneId = $ZoneId } }) } } -ApiVersion (Get-PimSetupApiVersion network))
            [void](Wait-PimArmProvisioned -Path $gid -ApiVersion (Get-PimSetupApiVersion network))
            Info "  A record for $sName written by the endpoint's new DNS zone group"
        }
    }
}
function Write-PimHwSqlDnsForwarderNote {
    # PRINTED, never applied: PIM does not write AD / on-premises DNS.
    param([ValidateSet('AzureVm', 'Arc')][string]$Mode, [string]$ForwarderIp)
    $sName = if ($SqlServerId) { ($SqlServerId -split '/')[-1] } else { '<server>' }
    Write-Host ''
    if ($Mode -eq 'AzureVm') {
        $ip = if ("$ForwarderIp".Trim()) { "$ForwarderIp".Trim() } else { '168.63.129.16' }
        Write-Host '[infra] PRIVATE SQL -- DNS. The worker asks its DNS servers (your DCs). PIM never writes AD DNS: the AD DNS administrator adds ONE conditional forwarder on the DCs:' -ForegroundColor Yellow
        Info "Add-DnsServerConditionalForwarderZone -Name '$($script:PimSqlZoneName)' -MasterServers $ip -ReplicationScope Forest"
        Info "(or DNS Manager > Conditional Forwarders > New: $($script:PimSqlZoneName) -> $ip, stored in Active Directory, all DNS servers in the forest)"
        Info 'Which address works:'
        Info '  * DCs that are Azure VMs: 168.63.129.16 (Azure DNS, answers only inside Azure). Azure answers from the zones linked to the VNet of'
        Info '    the DNS server that ASKS -- link the zone to the DCs'' VNet too (-PrivateDnsLinkVnetId <dc-vnet-id>), not only to the worker''s.'
        Info '  * DCs on-premises (over VPN / ExpressRoute): 168.63.129.16 does not answer from outside Azure. Create an Azure DNS Private Resolver'
        Info '    with an INBOUND endpoint in a VNet linked to the zone (normally the hub) and forward to that endpoint''s IP (-DnsForwarderIp <ip>).'
    } else {
        $ip = if ("$ForwarderIp".Trim()) { "$ForwarderIp".Trim() } else { '<Private Resolver inbound endpoint IP>' }
        Write-Host '[infra] PRIVATE SQL -- DNS for the on-premises worker. PIM never writes your DNS: your DNS administrator adds ONE conditional forwarder on the on-premises DNS servers (normally the DCs):' -ForegroundColor Yellow
        Info "Add-DnsServerConditionalForwarderZone -Name '$($script:PimSqlZoneName)' -MasterServers $ip -ReplicationScope Forest"
        Info '168.63.129.16 does NOT answer on-premises. The target is an Azure DNS Private Resolver INBOUND endpoint, reachable over your VPN /'
        Info "ExpressRoute, in a VNet the zone is linked to (-PrivateSqlDnsZoneId <zone-id> -PrivateDnsLinkVnetId <resolver-vnet-id> links it)."
    }
    Info "Check on the worker: Resolve-DnsName $sName.database.windows.net -> CNAME $sName.$($script:PimSqlZoneName) -> a PRIVATE address."
    Info '(Microsoft''s guidance also allows forwarding the public zone database.windows.net to the same address; the privatelink zone is the narrower choice.)'
}
$sqlZoneId = Resolve-PimHwSqlZoneId -ZoneId $PrivateSqlDnsZoneId -ZoneRg $PrivateDnsZoneResourceGroup -Sub $SubscriptionId
if ($CreatePrivateDnsZone -and -not $sqlZoneId) { throw '-CreatePrivateDnsZone needs -PrivateDnsZoneResourceGroup (or -PrivateSqlDnsZoneId) -- where the standard zone lives' }
if (@($PrivateDnsLinkVnetId | Where-Object { "$_".Trim() }).Count -and -not $sqlZoneId) { throw '-PrivateDnsLinkVnetId needs -PrivateSqlDnsZoneId (or -PrivateDnsZoneResourceGroup)' }
foreach ($v in @($PrivateDnsLinkVnetId | Where-Object { "$_".Trim() })) { if ($v -notmatch '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/virtualNetworks/[^/]+$') { throw "-PrivateDnsLinkVnetId: not a VNet resource id: '$v'" } }
$privateSqlWanted = [bool]$PrivateSql -or [bool]$sqlZoneId
if ($PSCmdlet.ParameterSetName -eq 'AzureVm') {
    if ($UseRemoteGateways -and -not "$GatewayVnetId".Trim()) { throw '-UseRemoteGateways needs -GatewayVnetId (the hub VNet whose VPN / ExpressRoute gateway reaches your DCs)' }
    if ("$GatewayVnetId".Trim() -and @($PeerVnetId | Where-Object { "$_" -ieq "$GatewayVnetId".Trim() }).Count -eq 0) { throw '-GatewayVnetId must be one of -PeerVnetId' }
}

if ($PSCmdlet.ParameterSetName -eq 'Arc') {
    # ---- §100.63(b) the on-premises worker: READ the Arc machine, build nothing ----
    if ($ArcMachineResourceId -notmatch '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.HybridCompute/machines/([^/]+)$') { throw "not an Azure Arc machine resource id: '$ArcMachineResourceId'" }
    if ($Matches[1] -ne $SubscriptionId) { throw "the Arc machine is in subscription $($Matches[1]), not -SubscriptionId $SubscriptionId -- refusing" }
    $arcRg = $Matches[2]; $arcName = $Matches[3]
    $m = Invoke-PimSetupArm -Path $ArcMachineResourceId -ApiVersion $ArcApiVersion -NotFoundOk
    if (-not $m) { throw "Arc machine not found: $ArcMachineResourceId (onboard the server to Azure Arc first)" }
    $status = "$($m.properties.status)"; $os = "$($m.properties.osType)"
    if ($os -and $os -notmatch '(?i)windows') { throw "the Arc machine $arcName runs '$os' -- the hybrid worker needs Windows Server" }
    if ($status -ne 'Connected') { throw "the Arc machine $arcName reports status '$status', not Connected -- check the agent on the server (azcmagent show) and its outbound access" }
    $principalId = "$($m.identity.principalId)"
    if (-not $principalId) { throw "the Arc machine $arcName carries no system-assigned identity" }
    Info "Arc machine $arcName ($os, $status, agent $("$($m.properties.agentVersion)")), identity $principalId"
    Info 'built NOTHING in Azure: no resource group, VNet, NSG, NAT gateway, peering or VM -- the network is yours'
    if ($SqlServerId -and @($SqlAllowedPublicIp | Where-Object { "$_".Trim() }).Count) {
        if ($SqlServerId -notmatch '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Sql/servers/([^/]+)$') { throw "not a SQL server id: '$SqlServerId'" }
        $sSub = $Matches[1]; $sRg = $Matches[2]; $sName = $Matches[3]
        $i = 0
        foreach ($ip in @($SqlAllowedPublicIp | Where-Object { "$_".Trim() })) {
            $i++; $rule = "pimhybridwrk-arc-$($arcName.ToLowerInvariant())-$i"
            if (-not ([System.Net.IPAddress]::TryParse("$ip".Trim(), [ref]$null))) { throw "not an IP address: '$ip'" }
            $have = Get-PimArmSqlFirewallRule -SubscriptionId $sSub -ResourceGroup $sRg -Server $sName -Name $rule
            if ($have -and "$($have.properties.startIpAddress)" -eq "$ip".Trim()) { Info "SQL firewall $rule = $ip (already)"; continue }
            if ($PSCmdlet.ShouldProcess($sName, "SQL firewall rule $rule = $ip")) { [void](Set-PimArmSqlFirewallRule -SubscriptionId $sSub -ResourceGroup $sRg -Server $sName -Name $rule -StartIp "$ip".Trim() -EndIp "$ip".Trim()) }
            Info "SQL firewall $rule = $ip"
        }
    }
    if ($sqlZoneId) { Set-PimHwSqlDnsLinks -ZoneId $sqlZoneId -VnetIds @($PrivateDnsLinkVnetId) }
    if ($privateSqlWanted) { Write-PimHwSqlDnsForwarderNote -Mode Arc -ForwarderIp $DnsForwarderIp }
    Write-Host ''
    Write-Host '[infra] Arc: the server needs OUTBOUND HTTPS (443) only -- NOTHING inbound:' -ForegroundColor Green
    foreach ($l in @(
        'Azure Arc agent endpoints (the agent''s own list: azcmagent check)',
        'login.microsoftonline.com (Entra ID tokens), graph.microsoft.com (Graph, read only)',
        'the PIM store: <server>.database.windows.net on 1433 -- private endpoint over VPN / ExpressRoute, or public with -SqlAllowedPublicIp',
        'the source store: <account>.blob.core.windows.net (the PIM code, channel.json)',
        'github.com + api.github.com + objects.githubusercontent.com (PowerShell 7 MSI, -Phase Configure only)',
        'the domain controllers (LDAP 389/636, Kerberos 88, the usual AD ports) on your own network')) { Info $l }
    Write-Host '[infra] done. Next: Initialize-PimHybridWorkerAd.ps1 (on a DC, -WorkerComputerName = this server) -> Grant-PimHybridWorkerAccess.ps1 -ArcMachineResourceId -> Install-PimHybridWorker.ps1 -Phase Configure -HostType Arc (Invoke-PimHybridWorkerRunCommand.ps1)' -ForegroundColor Green
    return [pscustomobject]@{ hostType = 'Arc'; vmName = $arcName; resourceGroup = $arcRg; principalId = $principalId; subnetId = $null; vnetId = $null; machineId = $ArcMachineResourceId; location = "$($m.location)" }
}

$subnetName = 'snet-worker'; $nsgName = "nsg-$($VmName.ToLowerInvariant())"; $nicName = "$($VmName.ToLowerInvariant())-nic"
if (-not (Get-PimArmResourceGroup -SubscriptionId $SubscriptionId -Name $ResourceGroup)) {
    if ($PSCmdlet.ShouldProcess($ResourceGroup, "create resource group in $Location")) { [void](Set-PimArmResourceGroup -SubscriptionId $SubscriptionId -Name $ResourceGroup -Location $Location -Tags $pimTags) }
}
Info "resource group $ResourceGroup"

# NSG: deny every inbound flow, including from peered networks
$nsgId = NetId 'networkSecurityGroups' $nsgName
if (-not (ArmTry $nsgId)) {
    if ($PSCmdlet.ShouldProcess($nsgName, 'create NSG + DenyAllInbound')) {
        # az network nsg create + az network nsg rule create DenyAllInbound (one PUT carrying the rule)
        [void](ArmPut $nsgId @{ location = $Location; tags = $pimTags; properties = @{ securityRules = @(@{ name = 'DenyAllInbound'; properties = @{
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
        $vnet = ArmPut $vnetId @{ location = $Location; tags = $pimTags; properties = @{
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
# §100.63 DCs behind a hub gateway: the transit flags are ONE implementation, in Set-PimHybridWorkerPeering.ps1 (it checks the
# hub has a gateway, sets allowGatewayTransit only on a hub-side peering PIM created, and prints what the hub owner sets)
if ($UseRemoteGateways -or $AllowForwardedTraffic) {
    $pf = @{ SubscriptionId = $SubscriptionId; TenantId = $TenantId; State = 'Connected'; ResourceGroup = $ResourceGroup; VnetName = $VnetName; WhatIf = $WhatIfPreference }
    if ($UseRemoteGateways) { $pf.UseRemoteGateways = $true; $pf.GatewayVnetId = "$GatewayVnetId".Trim() }
    if ($AllowForwardedTraffic) { $pf.AllowForwardedTraffic = $true; if ("$GatewayVnetId".Trim()) { $pf.GatewayVnetId = "$GatewayVnetId".Trim() } }
    & (Join-Path $PSScriptRoot 'Set-PimHybridWorkerPeering.ps1') @pf
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
            $nic = ArmPut $nicId @{ location = $Location; tags = $pimTags; properties = @{ networkSecurityGroup = @{ id = $nsgId }
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
                tags     = $pimTags
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
# §100.63 a PRIVATE-ONLY store: the VNet rule above covers the public endpoint only -- link the standard privatelink zone
# (worker VNet + -PrivateDnsLinkVnetId) and print the DCs' conditional forwarder
if ($sqlZoneId) { Set-PimHwSqlDnsLinks -ZoneId $sqlZoneId -VnetIds (@($vnetId) + @($PrivateDnsLinkVnetId)) }
if ($privateSqlWanted) { Write-PimHwSqlDnsForwarderNote -Mode AzureVm -ForwarderIp $DnsForwarderIp }

Write-Host ''
Write-Host "[infra] done. Next, in this order: Initialize-PimHybridWorkerAd.ps1 -ProvisionOdj (on a DC) -> Install-PimHybridWorker.ps1 -Phase Join (on $VmName) -> Grant-PimHybridWorkerAccess.ps1 -> Install-PimHybridWorker.ps1 -Phase Configure (it fetches the code with the identity, so the blob-reader grant must exist first). Deploy-PimHybridWorker.ps1 runs the whole sequence." -ForegroundColor Green
[pscustomobject]@{ hostType = 'AzureVm'; vmName = $VmName; resourceGroup = $ResourceGroup; principalId = $principalId; subnetId = $subnetId; vnetId = $vnetId; machineId = $vmId; location = $Location }

} finally { Stop-PimScriptRun -Script 'New-PimHybridWorkerInfra' }
