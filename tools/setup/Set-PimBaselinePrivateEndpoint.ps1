#Requires -Version 5.1
<#
.SYNOPSIS
    71.36 -- PRIVATE-ENDPOINT access to the MSP master's signed-baseline store (baseline.access = "privateEndpoint").
    For master and managed tenants on PRIVATE networks joined by VNet peering (operator 2026-09-17: "<master> and <managed tenant> are on
    2 completely separate networks. They will run PRIVATE ONLY. They will run global VNet peering").

.DESCRIPTION
    Converges, on the MASTER, in this order (nothing is closed before the private path exists):
      1. the private-endpoint subnet in the master's VNet (never the Container Apps subnet: it is delegated to
         Microsoft.App/environments and cannot hold a private endpoint) -- found, or created from -PrivateEndpointSubnetAddressPrefix
      2. ONE private endpoint pe-<store>-blob (group 'blob') in that subnet
      3. private DNS zone privatelink.blob.core.windows.net in the master's resource group, linked to the master's VNet
         with resolution policy NxDomainRedirect (a storage account elsewhere that has its own private endpoint -- one
         this zone holds no record for -- still resolves publicly instead of failing), and the endpoint's DNS zone group
         (Azure writes the A record)
      4. anonymous read of the BLOB (container access 'blob', no listing) -- KEPT on purpose: the managed tenant's pull job
         has NO identity the master's tenant can authorise (a managed identity cannot be granted data rights on a storage
         account in another tenant) and a SAS is refused by design (no credential, nothing that expires). Over a private
         endpoint the reachability is the peered network; the trust is still the bundle's signature.
      5. publicNetworkAccess DISABLED -- last. After this the store is reachable ONLY through the private endpoint: from the
         master's VNet (the publish job) and from networks peered with it that resolve the name to the endpoint's IP.
    Then READS EVERYTHING BACK and prints the endpoint's private IP for the managed tenants' configs:
        master.privateEndpointIp = <ip>
    The last pipeline output is that IP (a string).

    The public-but-signed posture's VNet/IP rules are left as they are: with public network access disabled they do not
    apply to anything. Undo = Set-PimBaselinePrivateEndpoint.ps1 ... -Rollback (public access back to Enabled; the
    endpoint and zone stay, harmless).

.EXAMPLE
    .\Set-PimBaselinePrivateEndpoint.ps1 -SubscriptionId <sub> -ResourceGroup rg-automateit-<token> -StorageAccount stpimbaseline<token> -VnetName vnet-pim-<token> -PrivateEndpointSubnetName pim-endpoints
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$StorageAccount,
    [string]$Container = 'baselines',
    [string]$VnetName,
    [string]$PrivateEndpointSubnetName = 'pim-endpoints',
    [string]$PrivateEndpointSubnetAddressPrefix,
    [string]$PrivateDnsResourceGroup,
    [switch]$Rollback
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $solRoot 'engine\_shared\PIM-MspBuild.ps1')
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
function AzJson { $A = @($args | ForEach-Object { $_ }); $o = & az @A -o json --only-show-errors 2>$null; if ($LASTEXITCODE -ne 0 -or -not "$o".Trim()) { return $null }; return ($o | Out-String | ConvertFrom-Json) }
$sub = @('--subscription', "$SubscriptionId".Trim())
$zone = 'privatelink.blob.core.windows.net'
if (-not "$VnetName".Trim()) { $tok = $ResourceGroup -replace '^rg-automateit-', ''; if ($tok -eq $ResourceGroup) { throw 'pass -VnetName (cannot derive it from the resource group name)' }; $VnetName = "vnet-pim-$tok" }
$dnsRg = if ("$PrivateDnsResourceGroup".Trim()) { "$PrivateDnsResourceGroup".Trim() } else { $ResourceGroup }
$peName = "pe-$StorageAccount-blob"

$acct = "$(az account show --query id -o tsv 2>$null)".Trim()
if ($acct -ne "$SubscriptionId".Trim()) { throw "az context is '$acct', not the master subscription '$SubscriptionId' -- refusing." }
$ErrorActionPreference = 'Continue'
$sa = AzJson storage account show @sub -g $ResourceGroup -n $StorageAccount
if (-not $sa) { throw "storage account '$StorageAccount' not found in $ResourceGroup -- run the storage step (New-PimBaselineStorage.ps1) first." }

if ($Rollback) {
    Step "ROLLBACK: public network access Enabled on $StorageAccount (endpoint and zone left in place)"
    az storage account update @sub -g $ResourceGroup -n $StorageAccount --public-network-access Enabled -o none --only-show-errors
    $pna = "$(az storage account show @sub -g $ResourceGroup -n $StorageAccount --query publicNetworkAccess -o tsv 2>$null)".Trim()
    Note "publicNetworkAccess = $pna"
    if ($pna -ne 'Enabled') { throw "rollback read-back: publicNetworkAccess is '$pna'" }
    return
}

Step "1. private-endpoint subnet '$PrivateEndpointSubnetName' in $VnetName"
$sn = AzJson network vnet subnet show @sub -g $ResourceGroup --vnet-name $VnetName -n $PrivateEndpointSubnetName
if (-not $sn) {
    if (-not "$PrivateEndpointSubnetAddressPrefix".Trim()) { throw "subnet '$PrivateEndpointSubnetName' does not exist in $VnetName and no -PrivateEndpointSubnetAddressPrefix was given (a free CIDR inside the VNet; NOT the Container Apps subnet, which is delegated)." }
    if ($PSCmdlet.ShouldProcess($PrivateEndpointSubnetName, 'create subnet')) {
        az network vnet subnet create @sub -g $ResourceGroup --vnet-name $VnetName -n $PrivateEndpointSubnetName --address-prefixes $PrivateEndpointSubnetAddressPrefix -o none --only-show-errors
        $sn = AzJson network vnet subnet show @sub -g $ResourceGroup --vnet-name $VnetName -n $PrivateEndpointSubnetName
        if (-not $sn) { throw "could not create subnet '$PrivateEndpointSubnetName'" }
        Note "created $($sn.addressPrefix)"
    }
} else { Note "exists ($($sn.addressPrefix))" }
if (@($sn.delegations).Count) { throw "subnet '$PrivateEndpointSubnetName' is delegated ($(@($sn.delegations | ForEach-Object { $_.serviceName }) -join ', ')) -- a private endpoint cannot live there. Use a separate, undelegated subnet." }

Step "2. private endpoint $peName -> $StorageAccount (blob)"
$pe = AzJson network private-endpoint show @sub -g $ResourceGroup -n $peName
if (-not $pe -and $PSCmdlet.ShouldProcess($peName, 'create private endpoint')) {
    az network private-endpoint create @sub -g $ResourceGroup -n $peName --subnet $sn.id --private-connection-resource-id $sa.id --group-id blob --connection-name blob -l $sa.location -o none --only-show-errors
    $pe = AzJson network private-endpoint show @sub -g $ResourceGroup -n $peName
    if (-not $pe) { throw "the private endpoint '$peName' was NOT created (see the error above)" }
    Note 'created'
} else { Note 'exists' }
$conn = "$(@($pe.privateLinkServiceConnections)[0].privateLinkServiceConnectionState.status)"
if ($conn -ne 'Approved') { throw "private endpoint connection state is '$conn', expected Approved" }

Step "3. private DNS zone $zone in $dnsRg, linked to $VnetName (NxDomainRedirect), zone group on the endpoint"
$vnetId = "$(az network vnet show @sub -g $ResourceGroup -n $VnetName --query id -o tsv 2>$null)".Trim()
if (-not $vnetId) { throw "VNet '$VnetName' not found in $ResourceGroup" }
$z = AzJson network private-dns zone show @sub -g $dnsRg -n $zone
if (-not $z) { az network private-dns zone create @sub -g $dnsRg -n $zone -o none --only-show-errors; $z = AzJson network private-dns zone show @sub -g $dnsRg -n $zone }
if (-not $z) { throw "could not create zone $zone in $dnsRg" }
$linkName = "link-$VnetName"
$lk = AzJson network private-dns link vnet show @sub -g $dnsRg -z $zone -n $linkName
if (-not $lk) { az network private-dns link vnet create @sub -g $dnsRg -z $zone -n $linkName --virtual-network $vnetId --registration-enabled false --resolution-policy NxDomainRedirect -o none --only-show-errors }
elseif ("$($lk.resolutionPolicy)" -ne 'NxDomainRedirect') { az network private-dns link vnet update @sub -g $dnsRg -z $zone -n $linkName --resolution-policy NxDomainRedirect -o none --only-show-errors }
$zg = AzJson network private-endpoint dns-zone-group list @sub -g $ResourceGroup --endpoint-name $peName
if (-not @($zg).Count) { az network private-endpoint dns-zone-group create @sub -g $ResourceGroup --endpoint-name $peName -n zg --private-dns-zone $z.id --zone-name blob -o none --only-show-errors }

Step '4. anonymous read of the blob (no listing) -- the pull job has no cross-tenant identity; the signature is the trust'
if (-not [bool]$sa.allowBlobPublicAccess) { az storage account update @sub -g $ResourceGroup -n $StorageAccount --allow-blob-public-access true -o none --only-show-errors }
$ca = "$(az storage container-rm show @sub -g $ResourceGroup --storage-account $StorageAccount -n $Container --query publicAccess -o tsv 2>$null)".Trim()
if ($ca -ne 'Blob') { az storage container-rm update @sub -g $ResourceGroup --storage-account $StorageAccount -n $Container --public-access blob -o none --only-show-errors }

Step '5. public network access DISABLED (last: the private path exists now)'
if ("$($sa.publicNetworkAccess)" -ne 'Disabled' -and $PSCmdlet.ShouldProcess($StorageAccount, 'disable public network access')) {
    az storage account update @sub -g $ResourceGroup -n $StorageAccount --public-network-access Disabled -o none --only-show-errors
}

Step 'read back'
Start-Sleep -Seconds 5
$sa2 = AzJson storage account show @sub -g $ResourceGroup -n $StorageAccount
$ca2 = "$(az storage container-rm show @sub -g $ResourceGroup --storage-account $StorageAccount -n $Container --query publicAccess -o tsv 2>$null)".Trim()
$pe2 = AzJson network private-endpoint show @sub -g $ResourceGroup -n $peName
$nicIp = ''
$nicId = "$(@($pe2.networkInterfaces)[0].id)"
if ($nicId) { $nicIp = "$(az network nic show @sub --ids $nicId --query 'ipConfigurations[0].privateIPAddress' -o tsv 2>$null)".Trim() }
$recs = AzJson network private-dns record-set a show @sub -g $dnsRg -z $zone -n $StorageAccount
$recIps = @($recs.aRecords | ForEach-Object { "$($_.ipv4Address)" })
$lk2 = AzJson network private-dns link vnet show @sub -g $dnsRg -z $zone -n $linkName
$ErrorActionPreference = 'Stop'
$v = Test-PimBaselinePrivateEndpointState -State @{ publicNetworkAccess = "$($sa2.publicNetworkAccess)"; allowBlobPublicAccess = [bool]$sa2.allowBlobPublicAccess; containerPublicAccess = $ca2
        endpointIp = $nicIp; dnsRecordIps = $recIps; linkResolutionPolicy = "$($lk2.resolutionPolicy)"; linkVnetId = "$($lk2.virtualNetwork.id)"; expectedVnetId = $vnetId }
foreach ($line in $v.lines) { Note $line }
if (-not $v.ok) { throw "private-endpoint posture NOT effective: $($v.reasons -join '; ')" }
Write-Host "    PASS: $StorageAccount is private-endpoint only (public network access Disabled), $zone $StorageAccount -> $nicIp" -ForegroundColor Green
Write-Host "    master.privateEndpointIp = $nicIp   (every managed tenant's build config; its 'privatedns' step writes it into its own zone)" -ForegroundColor Yellow
$nicIp
