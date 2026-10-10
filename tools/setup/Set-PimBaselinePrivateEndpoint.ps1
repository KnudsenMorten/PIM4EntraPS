#Requires -Version 5.1
<#
.SYNOPSIS
    71.36 -- PRIVATE-ENDPOINT access to the managing tenant's signed-baseline store (baseline.access = "privateEndpoint").
    For master and managed tenants on PRIVATE networks joined by VNet peering (operator 2026-09-17: "<master> and <managed tenant> are on
    2 completely separate networks. They will run PRIVATE ONLY. They will run global VNet peering").

.DESCRIPTION
    Converges, on the MASTER, in this order (nothing is closed before the private path exists):
      1. the private-endpoint subnet in the managing tenant's VNet (never the Container Apps subnet: it is delegated to
         Microsoft.App/environments and cannot hold a private endpoint) -- found, or created from -PrivateEndpointSubnetAddressPrefix
      2. ONE private endpoint pe-<store>-blob (group 'blob') in that subnet
      3. private DNS zone privatelink.blob.core.windows.net in the managing tenant's resource group, linked to the managing tenant's VNet
         with resolution policy NxDomainRedirect (a storage account elsewhere that has its own private endpoint -- one
         this zone holds no record for -- still resolves publicly instead of failing), and the endpoint's DNS zone group
         (Azure writes the A record)
      4. anonymous read of the BLOB (container access 'blob', no listing) -- KEPT on purpose: the managed tenant's pull job
         has NO identity the managing tenant's tenant can authorise (a managed identity cannot be granted data rights on a storage
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

    100.41 (framework 12.17 NO-AZ): every call is ARM REST through PIM-Rest's one token client (engine/_shared/
    PIM-ArmSetup.ps1) -- a calling build's REST session is used as it is, else the Invardia Support app's session or the
    person signed in. No az CLI.

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
. (Join-Path $solRoot 'engine\msp\PIM-MspBuild.ps1')
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
$S = "$SubscriptionId".Trim()
$zone = 'privatelink.blob.core.windows.net'
if (-not "$VnetName".Trim()) { $tok = $ResourceGroup -replace '^rg-automateit-', ''; if ($tok -eq $ResourceGroup) { throw 'pass -VnetName (cannot derive it from the resource group name)' }; $VnetName = "vnet-pim-$tok" }
$dnsRg = if ("$PrivateDnsResourceGroup".Trim()) { "$PrivateDnsResourceGroup".Trim() } else { $ResourceGroup }
$peName = "pe-$StorageAccount-blob"

# A calling build's REST session is used as it is; otherwise open one (Support app session / the person signed in).
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $S) }
$acct = "$((Get-PimArmSubscription -SubscriptionId $S -ErrorAsNull).subscriptionId)".Trim()
if ($acct -ne $S) { throw "the signed-in identity cannot read the managing tenant subscription '$SubscriptionId' (read '$acct') -- refusing." }
$sa = Get-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount -ErrorAsNull
if (-not $sa) { throw "storage account '$StorageAccount' not found in $ResourceGroup -- run the storage step (New-PimBaselineStorage.ps1) first." }

if ($Rollback) {
    Step "ROLLBACK: public network access Enabled on $StorageAccount (endpoint and zone left in place)"
    [void](Update-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount -Properties @{ publicNetworkAccess = 'Enabled' })
    $pna = "$((Get-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount -ErrorAsNull).properties.publicNetworkAccess)".Trim()
    Note "publicNetworkAccess = $pna"
    if ($pna -ne 'Enabled') { throw "rollback read-back: publicNetworkAccess is '$pna'" }
    return
}

Step "1. private-endpoint subnet '$PrivateEndpointSubnetName' in $VnetName"
$sn = Get-PimArmSubnet -SubscriptionId $S -ResourceGroup $ResourceGroup -VnetName $VnetName -Name $PrivateEndpointSubnetName -ErrorAsNull
if (-not $sn) {
    if (-not "$PrivateEndpointSubnetAddressPrefix".Trim()) { throw "subnet '$PrivateEndpointSubnetName' does not exist in $VnetName and no -PrivateEndpointSubnetAddressPrefix was given (a free CIDR inside the VNet; NOT the Container Apps subnet, which is delegated)." }
    if ($PSCmdlet.ShouldProcess($PrivateEndpointSubnetName, 'create subnet')) {
        $sn = Set-PimArmSubnet -SubscriptionId $S -ResourceGroup $ResourceGroup -VnetName $VnetName -Name $PrivateEndpointSubnetName -AddressPrefix $PrivateEndpointSubnetAddressPrefix
        if (-not $sn) { throw "could not create subnet '$PrivateEndpointSubnetName'" }
        Note "created $($sn.properties.addressPrefix)"
    }
} else { Note "exists ($($sn.properties.addressPrefix))" }
if (@($sn.properties.delegations | Where-Object { $_ }).Count) { throw "subnet '$PrivateEndpointSubnetName' is delegated ($(@($sn.properties.delegations | ForEach-Object { $_.properties.serviceName }) -join ', ')) -- a private endpoint cannot live there. Use a separate, undelegated subnet." }

Step "2. private endpoint $peName -> $StorageAccount (blob)"
$pe = Get-PimArmPrivateEndpoint -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $peName -ErrorAsNull
if (-not $pe -and $PSCmdlet.ShouldProcess($peName, 'create private endpoint')) {
    $pe = New-PimArmPrivateEndpoint -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $peName -Location "$($sa.location)" -SubnetId "$($sn.id)" -TargetResourceId "$($sa.id)" -GroupId blob -ConnectionName blob
    if (-not $pe) { throw "the private endpoint '$peName' was NOT created (see the error above)" }
    Note 'created'
} else { Note 'exists' }
$conn = "$(@($pe.properties.privateLinkServiceConnections)[0].properties.privateLinkServiceConnectionState.status)"
if ($conn -ne 'Approved') { throw "private endpoint connection state is '$conn', expected Approved" }

Step "3. private DNS zone $zone in $dnsRg, linked to $VnetName (NxDomainRedirect), zone group on the endpoint"
$vnetId = "$((Get-PimArmVnet -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $VnetName -ErrorAsNull).id)".Trim()
if (-not $vnetId) { throw "VNet '$VnetName' not found in $ResourceGroup" }
$z = New-PimArmPrivateDnsZone -SubscriptionId $S -ResourceGroup $dnsRg -Name $zone
if (-not $z) { throw "could not create zone $zone in $dnsRg" }
$linkName = "link-$VnetName"
$lk = Get-PimArmPrivateDnsLink -SubscriptionId $S -ResourceGroup $dnsRg -ZoneName $zone -Name $linkName -ErrorAsNull
if (-not $lk -or "$($lk.properties.resolutionPolicy)" -ne 'NxDomainRedirect') {
    Set-PimArmPrivateDnsLink -SubscriptionId $S -ResourceGroup $dnsRg -ZoneName $zone -Name $linkName -VnetId $(if ($lk) { "$($lk.properties.virtualNetwork.id)" } else { $vnetId }) -ResolutionPolicy NxDomainRedirect
}
if (-not @(Get-PimArmPrivateDnsZoneGroups -SubscriptionId $S -ResourceGroup $ResourceGroup -EndpointName $peName).Count) {
    Set-PimArmPrivateDnsZoneGroup -SubscriptionId $S -ResourceGroup $ResourceGroup -EndpointName $peName -Name zg -ZoneId "$($z.id)" -ConfigName blob
}

Step '4. anonymous read of the blob (no listing) -- the pull job has no cross-tenant identity; the signature is the trust'
if (-not [bool]$sa.properties.allowBlobPublicAccess) { [void](Update-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount -Properties @{ allowBlobPublicAccess = $true }) }
$ca = "$((Get-PimArmBlobContainer -SubscriptionId $S -ResourceGroup $ResourceGroup -Account $StorageAccount -Name $Container -ErrorAsNull).properties.publicAccess)".Trim()
if ($ca -ne 'Blob') { [void](Set-PimArmBlobContainer -SubscriptionId $S -ResourceGroup $ResourceGroup -Account $StorageAccount -Name $Container -PublicAccess Blob) }

Step '5. public network access DISABLED (last: the private path exists now)'
if ("$($sa.properties.publicNetworkAccess)" -ne 'Disabled' -and $PSCmdlet.ShouldProcess($StorageAccount, 'disable public network access')) {
    [void](Update-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount -Properties @{ publicNetworkAccess = 'Disabled' })
}

Step 'read back'
Start-Sleep -Seconds 5
$sa2 = Get-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount -ErrorAsNull
$ca2 = "$((Get-PimArmBlobContainer -SubscriptionId $S -ResourceGroup $ResourceGroup -Account $StorageAccount -Name $Container -ErrorAsNull).properties.publicAccess)".Trim()
$pe2 = Get-PimArmPrivateEndpoint -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $peName -ErrorAsNull
$nicIp = ''
$nicId = "$(@($pe2.properties.networkInterfaces)[0].id)"
if ($nicId) { $nicIp = "$(@((Get-PimArmResource -ResourceId $nicId -Kind network -ErrorAsNull).properties.ipConfigurations)[0].properties.privateIPAddress)".Trim() }
$recs = Get-PimArmPrivateDnsARecord -SubscriptionId $S -ResourceGroup $dnsRg -ZoneName $zone -Name $StorageAccount -ErrorAsNull
$recIps = @($recs.properties.aRecords | Where-Object { $_ } | ForEach-Object { "$($_.ipv4Address)" })
$lk2 = Get-PimArmPrivateDnsLink -SubscriptionId $S -ResourceGroup $dnsRg -ZoneName $zone -Name $linkName -ErrorAsNull
$v = Test-PimBaselinePrivateEndpointState -State @{ publicNetworkAccess = "$($sa2.properties.publicNetworkAccess)"; allowBlobPublicAccess = [bool]$sa2.properties.allowBlobPublicAccess; containerPublicAccess = $ca2
        endpointIp = $nicIp; dnsRecordIps = $recIps; linkResolutionPolicy = "$($lk2.properties.resolutionPolicy)"; linkVnetId = "$($lk2.properties.virtualNetwork.id)"; expectedVnetId = $vnetId }
foreach ($line in $v.lines) { Note $line }
if (-not $v.ok) { throw "private-endpoint posture NOT effective: $($v.reasons -join '; ')" }
Write-Host "    PASS: $StorageAccount is private-endpoint only (public network access Disabled), $zone $StorageAccount -> $nicIp" -ForegroundColor Green
Write-Host "    master.privateEndpointIp = $nicIp   (every managed tenant's build config; its 'privatedns' step writes it into its own zone)" -ForegroundColor Yellow
$nicIp
