#Requires -Version 5.1
<#
.SYNOPSIS
    71.36 -- the MANAGED tenant's half of PRIVATE-ENDPOINT baseline access (master.privateEndpointIp set): make the managing tenant's
    bundle store resolve to the managing tenant's private endpoint IP from THIS environment's VNet.

.DESCRIPTION
    The managing tenant's store has public network access disabled and ONE private endpoint in the managing tenant's VNet. This tenant
    reaches that IP over VNet peering (created by the operator -- a per-tenant deploy identity cannot authorise a peering
    on another tenant's VNet). A private DNS zone cannot be linked across tenants, so the name is published HERE:
      zone   privatelink.blob.core.windows.net       in this resource group
      link   link-<vnet> -> this environment's VNet   registration off, resolution policy NxDomainRedirect (any OTHER
                                                      storage account with its own private endpoint still resolves publicly)
      record A <master store> -> <master.privateEndpointIp>   exactly that one address (a stale address is replaced)
    Public DNS already answers <store>.blob.core.windows.net with a CNAME to <store>.privatelink.blob.core.windows.net once
    the managing tenant has a private endpoint, and Azure DNS (168.63.129.16) answers that name from this linked zone.

    Idempotent; READ BACK. Nothing here is a credential. The VNet is READ FROM THE CONTAINER APPS ENVIRONMENT (its
    infrastructure subnet), -VnetName is the fallback.
    This environment's Container Apps subnet needs NO storage service endpoint in this mode (and one is not added).

    100.41 (framework 12.17 NO-AZ): every call is ARM REST through PIM-Rest's one token client (engine/_shared/PIM-ArmSetup.ps1).
    A calling build's REST session is used as it is; standalone, the Invardia Support app's session or the person signed in.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$MasterStorageAccount,
    [Parameter(Mandatory)][string]$PrivateEndpointIp,
    [string]$EnvName,
    [string]$VnetName,
    [string]$PrivateDnsResourceGroup
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
$store = "$MasterStorageAccount".Trim().ToLowerInvariant()
if ($store -notmatch '^[a-z0-9]{3,24}$') { throw "'$MasterStorageAccount' is not a storage account name" }
if (-not (Test-PimPrivateIPv4 -Value $PrivateEndpointIp)) { throw "-PrivateEndpointIp '$PrivateEndpointIp' is not a private (RFC 1918) IPv4 address" }
$dnsRg = if ("$PrivateDnsResourceGroup".Trim()) { "$PrivateDnsResourceGroup".Trim() } else { $ResourceGroup }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $S) }
# az --subscription X refused a subscription this identity cannot see; the REST read is the same assertion.
$acct = "$((Get-PimArmSubscription -SubscriptionId $S -ErrorAsNull).subscriptionId)".Trim()
if ($acct -ne $S) { throw "subscription '$S' is not visible to this sign-in$(if ($global:PimSetupRestLastError) { " ($($global:PimSetupRestLastError))" }) -- refusing." }

Step "private DNS for the managing tenant's bundle store: $store.$zone -> $PrivateEndpointIp"
$vnetId = ''
if ("$EnvName".Trim()) {
    $snId = "$((Get-PimArmAcaEnv -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $EnvName -ErrorAsNull).properties.vnetConfiguration.infrastructureSubnetId)".Trim()
    if ($snId -match '^(.*/virtualNetworks/[^/]+)/subnets/') { $vnetId = $Matches[1]; Note "VNet read from the Container Apps environment '$EnvName' (authoritative)" }
}
if (-not $vnetId -and "$VnetName".Trim()) { $vnetId = "$((Get-PimArmVnet -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $VnetName -ErrorAsNull).id)".Trim() }
if (-not $vnetId) { throw "no VNet: the environment '$EnvName' names no subnet and -VnetName '$VnetName' was not found" }
$vnetShort = ($vnetId -split '/')[-1]
Note "VNet $vnetId"

if (-not (Get-PimArmPrivateDnsZone -SubscriptionId $S -ResourceGroup $dnsRg -Name $zone -ErrorAsNull)) {
    if ($PSCmdlet.ShouldProcess($zone, 'create private DNS zone')) { [void](New-PimArmPrivateDnsZone -SubscriptionId $S -ResourceGroup $dnsRg -Name $zone) }
}
$linkName = "link-$vnetShort"
$lkNow = Get-PimArmPrivateDnsLink -SubscriptionId $S -ResourceGroup $dnsRg -ZoneName $zone -Name $linkName -ErrorAsNull
$lkPol = "$($lkNow.properties.resolutionPolicy)".Trim()
if (-not $lkNow) {
    if ($PSCmdlet.ShouldProcess($linkName, 'link zone to VNet')) { Set-PimArmPrivateDnsLink -SubscriptionId $S -ResourceGroup $dnsRg -ZoneName $zone -Name $linkName -VnetId $vnetId -RegistrationEnabled $false -ResolutionPolicy NxDomainRedirect }
} elseif ($lkPol -ne 'NxDomainRedirect') {
    # az ... link vnet update --resolution-policy: the link is written WHOLE, keeping the VNet it already points at.
    $lkVnet = "$($lkNow.properties.virtualNetwork.id)"; if (-not $lkVnet) { $lkVnet = $vnetId }
    Set-PimArmPrivateDnsLink -SubscriptionId $S -ResourceGroup $dnsRg -ZoneName $zone -Name $linkName -VnetId $lkVnet -RegistrationEnabled ([bool]$lkNow.properties.registrationEnabled) -ResolutionPolicy NxDomainRedirect
}
$readIps = { @(@((Get-PimArmPrivateDnsARecord -SubscriptionId $S -ResourceGroup $dnsRg -ZoneName $zone -Name $store -ErrorAsNull).properties.aRecords) | Where-Object { $_ } | ForEach-Object { "$($_.ipv4Address)".Trim() } | Where-Object { $_ }) }
$cur = @(& $readIps)
$plan = Get-PimBaselinePrivateDnsPlan -CurrentIps $cur -WantIp $PrivateEndpointIp
Note "record plan: $($plan.summary)"
# az add-record / remove-record --keep-empty-record-set: the record set is written WHOLE with the addresses that remain.
$want = New-Object System.Collections.Generic.List[string]
foreach ($ip in $cur) { $want.Add($ip) }
$changed = $false
foreach ($a in $plan.actions) {
    if (-not $PSCmdlet.ShouldProcess("$store -> $($a.ip)", $a.op)) { continue }
    if ($a.op -eq 'add') { if (-not $want.Contains("$($a.ip)")) { $want.Add("$($a.ip)") } }
    else { [void]$want.Remove("$($a.ip)") }
    $changed = $true
}
if ($changed) {
    # an empty set is kept (as --keep-empty-record-set did): the A record set exists with no address.
    [void](Invoke-PimSetupArm -Method PUT -Path (Get-PimArmResourceId $S $dnsRg 'Microsoft.Network/privateDnsZones' $zone "A/$store") -ApiVersion (Get-PimSetupApiVersion privateDns) `
        -Body @{ properties = @{ ttl = 3600; aRecords = @($want | ForEach-Object { @{ ipv4Address = $_ } }) } })
}

Step 'read back'
$ips = @(& $readIps)
$lkObj = Get-PimArmPrivateDnsLink -SubscriptionId $S -ResourceGroup $dnsRg -ZoneName $zone -Name $linkName -ErrorAsNull
$lk = if ($lkObj) { [pscustomobject]@{ virtualNetwork = $lkObj.properties.virtualNetwork; resolutionPolicy = "$($lkObj.properties.resolutionPolicy)"; virtualNetworkLinkState = "$($lkObj.properties.virtualNetworkLinkState)" } } else { $null }
$okRec = ($ips.Count -eq 1 -and $ips[0] -eq "$PrivateEndpointIp".Trim())
$okLink = ($lk -and "$($lk.virtualNetwork.id)" -ieq $vnetId -and "$($lk.resolutionPolicy)" -eq 'NxDomainRedirect')
Note "A $store = $($ips -join ', ') (want $PrivateEndpointIp): $okRec"
Note "link $linkName -> $($lk.virtualNetwork.id) policy $($lk.resolutionPolicy) state $($lk.virtualNetworkLinkState): $okLink"
if (-not ($okRec -and $okLink)) { throw 'private DNS for the managing tenant store is NOT as intended (see above)' }
Write-Host "    PASS: from $vnetShort, $store.blob.core.windows.net resolves to $PrivateEndpointIp. The pull reaches it only over the peering to the managing tenant's VNet." -ForegroundColor Green
