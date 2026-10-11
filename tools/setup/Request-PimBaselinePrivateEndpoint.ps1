#Requires -Version 5.1
<#
.SYNOPSIS
    100.59 -- the MANAGED tenant's half of the cross-tenant private endpoint (master.access = "crossTenantPrivateEndpoint"):
    a private endpoint in THIS tenant's VNet to the managing tenant's bundle store, approved by the managing tenant, and this
    tenant's own privatelink.blob A record for it. No peering, no address to copy, no SAS, no key, no secret.

.DESCRIPTION
    Converges, in this order (nothing outside this tenant is written; the managing tenant only APPROVES):
      1. the private-endpoint subnet in this environment's VNet (read from the Container Apps environment; -VnetName is the
         fallback) -- found, or created from -PrivateEndpointSubnetAddressPrefix; never a delegated subnet
      2. ONE private endpoint pe-<store>-blob-xt (sub-resource 'blob') with a MANUAL connection request to the store's full
         id (/subscriptions/<master sub>/resourceGroups/<master rg>/providers/Microsoft.Storage/storageAccounts/<store>).
         The request message names this tenant ("PIM Manager managed-tenant pull: tenant <id>"); the managing tenant
         approves by SUBSCRIPTION (asserted by ARM), the message only has to agree with it.
      3. the connection state, READ BACK:
           Pending  -> STOP POINT, exit 10: prints the exact command the managing tenant's administrator runs
                       (Invoke-PimMspBuild -Role Master ... -From peapprove) and this build's resume command
           Approved -> continue
           Rejected / Disconnected / another target -> exit 1 with the reason (to request again: -Revoke, then run again)
      4. privatelink.blob.core.windows.net in this resource group, linked to this VNet (NxDomainRedirect), A record
         <store> -> the endpoint's private address (Initialize-PimBaselinePrivateDns.ps1, read back)
    The last pipeline output is the endpoint's private address (a string).

    REVOKE (-Revoke): deletes this tenant's endpoint and its A record. The managing tenant can revoke too (reject). Until the
    managing tenant has removed this tenant's public rule (peclose), the public-but-signed path still works after a revoke;
    after it, the managing tenant re-adds the rule: Close-PimBaselinePublicAccess.ps1 -Rollback.

    100.41 (framework 12.17 NO-AZ): every call is ARM REST through PIM-Rest's one token client (engine/_shared/PIM-ArmSetup.ps1).
    A calling build's REST session is used as it is; standalone, the Invardia Support app's session or the person signed in.

.EXAMPLE
    .\Request-PimBaselinePrivateEndpoint.ps1 -SubscriptionId <sub> -ResourceGroup rg-automateit-<token> -TenantId <this tenant> -EnvName cae-pim-ext -MasterSubscriptionId <master sub> -MasterResourceGroup <master rg> -MasterStorageAccount <store> -PrivateEndpointSubnetName pim-endpoints
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$MasterSubscriptionId,
    [Parameter(Mandatory)][string]$MasterResourceGroup,
    [Parameter(Mandatory)][string]$MasterStorageAccount,
    [string]$EnvName,
    [string]$VnetName,
    [string]$PrivateEndpointSubnetName = 'pim-endpoints',
    [string]$PrivateEndpointSubnetAddressPrefix,
    [string]$PrivateDnsResourceGroup,
    # the command that resumes the calling build here (the build passes it; standalone: re-run this script)
    [string]$ResumeCommand,
    [switch]$Revoke
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $solRoot 'engine\msp\PIM-MspBuild.ps1')
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
$S = "$SubscriptionId".Trim()
$guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
foreach ($g in @(@{ n = 'SubscriptionId'; v = $S }, @{ n = 'TenantId'; v = "$TenantId".Trim() }, @{ n = 'MasterSubscriptionId'; v = "$MasterSubscriptionId".Trim() })) {
    if ($g.v -notmatch $guid) { throw "-$($g.n) '$($g.v)' is not a GUID" }
}
$store = "$MasterStorageAccount".Trim().ToLowerInvariant()
if ($store -notmatch '^[a-z0-9]{3,24}$') { throw "'$MasterStorageAccount' is not a storage account name" }
if ("$MasterSubscriptionId".Trim() -ieq $S) { throw "-MasterSubscriptionId is this tenant's own subscription -- a managed tenant does not pull from itself" }
$zone = 'privatelink.blob.core.windows.net'
$dnsRg = if ("$PrivateDnsResourceGroup".Trim()) { "$PrivateDnsResourceGroup".Trim() } else { $ResourceGroup }
$targetId = Get-PimBaselineStoreResourceId -SubscriptionId $MasterSubscriptionId -ResourceGroup $MasterResourceGroup -StorageAccount $store
$peName = Get-PimCrossTenantPeName -StorageAccount $store
$peId = Get-PimArmResourceId $S $ResourceGroup 'Microsoft.Network/privateEndpoints' $peName
$resume = if ("$ResumeCommand".Trim()) { "$ResumeCommand".Trim() } else { "$($MyInvocation.MyCommand.Name) (the same arguments)" }

if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $S) }
$acct = "$((Get-PimArmSubscription -SubscriptionId $S -ErrorAsNull).subscriptionId)".Trim()
if ($acct -ne $S) { throw "subscription '$S' is not visible to this sign-in$(if ($global:PimSetupRestLastError) { " ($($global:PimSetupRestLastError))" }) -- refusing." }

if ($Revoke) {
    Step "REVOKE: delete $peName and the A record $store in $zone (this tenant's side; the managing tenant's approval goes with the endpoint)"
    if ($PSCmdlet.ShouldProcess($peName, 'delete private endpoint')) {
        Remove-PimArmResource -ResourceId $peId -Kind network -Wait -TimeoutSeconds 600
        [void](Remove-PimArmPrivateDnsARecord -SubscriptionId $S -ResourceGroup $dnsRg -ZoneName $zone -Name $store)
        if (Get-PimArmPrivateEndpoint -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $peName -ErrorAsNull) { throw "revoke read-back: $peName still exists" }
        Write-Host "    REVOKED: $peName deleted. If the managing tenant already removed this tenant's public rule (peclose), the pull now fails until it runs Close-PimBaselinePublicAccess.ps1 -Rollback (or this tenant requests again)." -ForegroundColor Yellow
    }
    return
}

Step "1. private-endpoint subnet '$PrivateEndpointSubnetName' in this environment's VNet"
$vnetId = ''
if ("$EnvName".Trim()) {
    $snId = "$((Get-PimArmAcaEnv -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $EnvName -ErrorAsNull).properties.vnetConfiguration.infrastructureSubnetId)".Trim()
    if ($snId -match '^(.*/virtualNetworks/[^/]+)/subnets/') { $vnetId = $Matches[1]; Note "VNet read from the Container Apps environment '$EnvName' (authoritative)" }
}
if (-not $vnetId -and "$VnetName".Trim()) { $vnetId = "$((Get-PimArmVnet -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $VnetName -ErrorAsNull).id)".Trim() }
if (-not $vnetId) { throw "no VNet: the environment '$EnvName' names no subnet and -VnetName '$VnetName' was not found" }
$vnetRg = Get-PimArmIdPart -Id $vnetId -Segment resourceGroups
if (-not $vnetRg) { $vnetRg = $ResourceGroup }
$vnetSub = Get-PimArmIdPart -Id $vnetId -Segment subscriptions
if (-not $vnetSub) { $vnetSub = $S }
$vnetShort = ($vnetId -split '/')[-1]
$vnet = Get-PimArmVnet -SubscriptionId $vnetSub -ResourceGroup $vnetRg -Name $vnetShort -ErrorAsNull
if (-not $vnet) { throw "VNet '$vnetShort' could not be read in $vnetRg" }
$sn = Get-PimArmSubnet -SubscriptionId $vnetSub -ResourceGroup $vnetRg -VnetName $vnetShort -Name $PrivateEndpointSubnetName -ErrorAsNull
if (-not $sn) {
    if (-not "$PrivateEndpointSubnetAddressPrefix".Trim()) { throw "subnet '$PrivateEndpointSubnetName' does not exist in $vnetShort and no -PrivateEndpointSubnetAddressPrefix was given (a free CIDR inside the VNet; NOT the Container Apps subnet, which is delegated)." }
    if ($PSCmdlet.ShouldProcess($PrivateEndpointSubnetName, 'create subnet')) {
        $sn = Set-PimArmSubnet -SubscriptionId $vnetSub -ResourceGroup $vnetRg -VnetName $vnetShort -Name $PrivateEndpointSubnetName -AddressPrefix $PrivateEndpointSubnetAddressPrefix
        if (-not $sn) { throw "could not create subnet '$PrivateEndpointSubnetName'" }
        Note "created $($sn.properties.addressPrefix)"
    } else { Note "What if: create subnet $PrivateEndpointSubnetName ($PrivateEndpointSubnetAddressPrefix)"; return }
} else { Note "exists ($($sn.properties.addressPrefix))" }
if (@($sn.properties.delegations | Where-Object { $_ }).Count) { throw "subnet '$PrivateEndpointSubnetName' is delegated ($(@($sn.properties.delegations | ForEach-Object { $_.properties.serviceName }) -join ', ')) -- a private endpoint cannot live there. Use a separate, undelegated subnet." }

Step "2. private endpoint $peName -> $store (blob) in the managing tenant's subscription $MasterSubscriptionId (connection REQUEST)"
$pe = Get-PimArmPrivateEndpoint -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $peName -ErrorAsNull
if (-not $pe) {
    if (-not $PSCmdlet.ShouldProcess($peName, "request a private endpoint connection to $targetId")) { Note "What if: create $peName with a manual connection request to $targetId"; return }
    # MANUAL connection: this tenant holds no right on the store, so the store's owner (the managing tenant) approves.
    $body = @{ location = "$($vnet.location)"; properties = @{ subnet = @{ id = "$($sn.id)" }
               manualPrivateLinkServiceConnections = @(@{ name = 'blob'; properties = @{ privateLinkServiceId = $targetId; groupIds = @('blob')
                                                                                        requestMessage = (Get-PimCrossTenantPeRequestMessage -TenantId $TenantId) } }) } }
    [void](Invoke-PimSetupArm -Method PUT -Path $peId -Body $body -ApiVersion (Get-PimSetupApiVersion network))
    $prov = Wait-PimArmProvisioned -Path $peId -ApiVersion (Get-PimSetupApiVersion network)
    if ($prov -ne 'Succeeded') { throw "the private endpoint '$peName' did not provision ($prov)" }
    $pe = Get-PimArmPrivateEndpoint -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $peName
    Note 'created (connection requested)'
} else { Note 'exists' }

Step '3. the connection state (read back)'
$verdict = Get-PimCrossTenantPeVerdict -PrivateEndpoint $pe -ExpectedTargetId $targetId
Note "state: $(if ($verdict.status) { $verdict.status } else { '-' }) -- $($verdict.reason)"
if ($verdict.action -eq 'stop') {
    Write-Host ''
    Write-Host "    STOP POINT -- the managing tenant's administrator approves this request now:" -ForegroundColor Yellow
    Write-Host "      1. in the managing tenant's build config: slaves[<n>] = { tenantId: '$("$TenantId".Trim().ToLowerInvariant())', access: 'privateEndpoint', subscriptionId: '$($S.ToLowerInvariant())' }" -ForegroundColor Yellow
    Write-Host "      2. Invoke-PimMspBuild.ps1 -Role Master -ConfigPath <the managing tenant's build config> -Apply -From peapprove" -ForegroundColor Yellow
    Write-Host "         (it approves ONLY a request from subscription $($S.ToLowerInvariant()) for this tenant; endpoint $peName)" -ForegroundColor DarkGray
    Write-Host "    Then resume here: $resume" -ForegroundColor Yellow
    exit 10
}
if ($verdict.action -ne 'continue') { throw "the private endpoint connection cannot be used: $($verdict.reason)" }

$nicIp = ''
$nicId = "$(@($pe.properties.networkInterfaces)[0].id)"
if ($nicId) { $nicIp = "$(@((Get-PimArmResource -ResourceId $nicId -Kind network -ErrorAsNull).properties.ipConfigurations)[0].properties.privateIPAddress)".Trim() }
if (-not (Test-PimPrivateIPv4 -Value $nicIp)) { throw "the endpoint's network interface has no private address yet ('$nicIp') -- run again in a minute" }
Note "endpoint address: $nicIp"

Step "4. privatelink.blob A record in this tenant: $store -> $nicIp"
$dnsArgs = @{ SubscriptionId = $S; ResourceGroup = $ResourceGroup; MasterStorageAccount = $store; PrivateEndpointIp = $nicIp }
if ("$EnvName".Trim()) { $dnsArgs['EnvName'] = "$EnvName".Trim() }
if ("$VnetName".Trim()) { $dnsArgs['VnetName'] = "$VnetName".Trim() }
if ("$PrivateDnsResourceGroup".Trim()) { $dnsArgs['PrivateDnsResourceGroup'] = "$PrivateDnsResourceGroup".Trim() }
& (Join-Path $PSScriptRoot 'Initialize-PimBaselinePrivateDns.ps1') @dnsArgs
Write-Host "    PASS: $peName approved by the managing tenant; from $vnetShort, $store.blob.core.windows.net resolves to $nicIp. Next: the pull proof (pullproof)." -ForegroundColor Green
$nicIp
