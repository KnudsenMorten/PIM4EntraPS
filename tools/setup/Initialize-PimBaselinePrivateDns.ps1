#Requires -Version 5.1
<#
.SYNOPSIS
    71.36 -- the MANAGED tenant's half of PRIVATE-ENDPOINT baseline access (master.privateEndpointIp set): make the master's
    bundle store resolve to the master's private endpoint IP from THIS environment's VNet.

.DESCRIPTION
    The master's store has public network access disabled and ONE private endpoint in the master's VNet. This tenant
    reaches that IP over VNet peering (created by the operator -- a per-tenant deploy identity cannot authorise a peering
    on another tenant's VNet). A private DNS zone cannot be linked across tenants, so the name is published HERE:
      zone   privatelink.blob.core.windows.net       in this resource group
      link   link-<vnet> -> this environment's VNet   registration off, resolution policy NxDomainRedirect (any OTHER
                                                      storage account with its own private endpoint still resolves publicly)
      record A <master store> -> <master.privateEndpointIp>   exactly that one address (a stale address is replaced)
    Public DNS already answers <store>.blob.core.windows.net with a CNAME to <store>.privatelink.blob.core.windows.net once
    the master has a private endpoint, and Azure DNS (168.63.129.16) answers that name from this linked zone.

    Idempotent; READ BACK. Nothing here is a credential. The VNet is READ FROM THE CONTAINER APPS ENVIRONMENT (its
    infrastructure subnet), -VnetName is the fallback.
    This environment's Container Apps subnet needs NO storage service endpoint in this mode (and one is not added).
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
. (Join-Path $solRoot 'engine\_shared\PIM-MspBuild.ps1')
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
$sub = @('--subscription', "$SubscriptionId".Trim())
$zone = 'privatelink.blob.core.windows.net'
$store = "$MasterStorageAccount".Trim().ToLowerInvariant()
if ($store -notmatch '^[a-z0-9]{3,24}$') { throw "'$MasterStorageAccount' is not a storage account name" }
if (-not (Test-PimPrivateIPv4 -Value $PrivateEndpointIp)) { throw "-PrivateEndpointIp '$PrivateEndpointIp' is not a private (RFC 1918) IPv4 address" }
$dnsRg = if ("$PrivateDnsResourceGroup".Trim()) { "$PrivateDnsResourceGroup".Trim() } else { $ResourceGroup }
$acct = "$(az account show --query id -o tsv 2>$null)".Trim()
if ($acct -ne "$SubscriptionId".Trim()) { throw "az context is '$acct', not '$SubscriptionId' -- refusing." }

Step "private DNS for the master's bundle store: $store.$zone -> $PrivateEndpointIp"
$ErrorActionPreference = 'Continue'
$vnetId = ''
if ("$EnvName".Trim()) {
    $snId = "$(az containerapp env show @sub -g $ResourceGroup -n $EnvName --query properties.vnetConfiguration.infrastructureSubnetId -o tsv --only-show-errors 2>$null)".Trim()
    if ($snId -match '^(.*/virtualNetworks/[^/]+)/subnets/') { $vnetId = $Matches[1]; Note "VNet read from the Container Apps environment '$EnvName' (authoritative)" }
}
if (-not $vnetId -and "$VnetName".Trim()) { $vnetId = "$(az network vnet show @sub -g $ResourceGroup -n $VnetName --query id -o tsv --only-show-errors 2>$null)".Trim() }
if (-not $vnetId) { throw "no VNet: the environment '$EnvName' names no subnet and -VnetName '$VnetName' was not found" }
$vnetShort = ($vnetId -split '/')[-1]
Note "VNet $vnetId"

if (-not "$(az network private-dns zone show @sub -g $dnsRg -n $zone --query id -o tsv --only-show-errors 2>$null)".Trim()) {
    if ($PSCmdlet.ShouldProcess($zone, 'create private DNS zone')) { az network private-dns zone create @sub -g $dnsRg -n $zone -o none --only-show-errors }
}
$linkName = "link-$vnetShort"
$lkPol = "$(az network private-dns link vnet show @sub -g $dnsRg -z $zone -n $linkName --query resolutionPolicy -o tsv --only-show-errors 2>$null)".Trim()
$lkExists = "$(az network private-dns link vnet show @sub -g $dnsRg -z $zone -n $linkName --query id -o tsv --only-show-errors 2>$null)".Trim()
if (-not $lkExists) {
    if ($PSCmdlet.ShouldProcess($linkName, 'link zone to VNet')) { az network private-dns link vnet create @sub -g $dnsRg -z $zone -n $linkName --virtual-network $vnetId --registration-enabled false --resolution-policy NxDomainRedirect -o none --only-show-errors }
} elseif ($lkPol -ne 'NxDomainRedirect') {
    az network private-dns link vnet update @sub -g $dnsRg -z $zone -n $linkName --resolution-policy NxDomainRedirect -o none --only-show-errors
}
$cur = @(az network private-dns record-set a show @sub -g $dnsRg -z $zone -n $store --query "aRecords[].ipv4Address" -o tsv --only-show-errors 2>$null | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
$plan = Get-PimBaselinePrivateDnsPlan -CurrentIps $cur -WantIp $PrivateEndpointIp
Note "record plan: $($plan.summary)"
foreach ($a in $plan.actions) {
    if (-not $PSCmdlet.ShouldProcess("$store -> $($a.ip)", $a.op)) { continue }
    if ($a.op -eq 'add') { az network private-dns record-set a add-record @sub -g $dnsRg -z $zone -n $store -a $a.ip -o none --only-show-errors }
    else { az network private-dns record-set a remove-record @sub -g $dnsRg -z $zone -n $store -a $a.ip --keep-empty-record-set -o none --only-show-errors }
}

Step 'read back'
$ips = @(az network private-dns record-set a show @sub -g $dnsRg -z $zone -n $store --query "aRecords[].ipv4Address" -o tsv --only-show-errors 2>$null | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
$lk = az network private-dns link vnet show @sub -g $dnsRg -z $zone -n $linkName -o json --only-show-errors 2>$null | Out-String | ConvertFrom-Json
$ErrorActionPreference = 'Stop'
$okRec = ($ips.Count -eq 1 -and $ips[0] -eq "$PrivateEndpointIp".Trim())
$okLink = ($lk -and "$($lk.virtualNetwork.id)" -ieq $vnetId -and "$($lk.resolutionPolicy)" -eq 'NxDomainRedirect')
Note "A $store = $($ips -join ', ') (want $PrivateEndpointIp): $okRec"
Note "link $linkName -> $($lk.virtualNetwork.id) policy $($lk.resolutionPolicy) state $($lk.virtualNetworkLinkState): $okLink"
if (-not ($okRec -and $okLink)) { throw 'private DNS for the master store is NOT as intended (see above)' }
Write-Host "    PASS: from $vnetShort, $store.blob.core.windows.net resolves to $PrivateEndpointIp. The pull reaches it only over the peering to the master's VNet." -ForegroundColor Green
