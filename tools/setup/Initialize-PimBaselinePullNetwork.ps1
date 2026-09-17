#Requires -Version 5.1
<#
.SYNOPSIS
    71.34 -- the MANAGED tenant's half of the public-but-signed pull (DESIGN 13.7): put the Azure Storage service endpoint
    on this environment's Container Apps subnet, and print that subnet's resource id for the MSP master.

.DESCRIPTION
    The master's bundle store denies every network it has not named (Set-PimBaselineNetworkAccess.ps1). It names a
    managed tenant by a VIRTUAL NETWORK RULE for this subnet -- Azure accepts a subnet from another Microsoft Entra tenant
    by its fully qualified id -- and a VNet rule only matches traffic that arrives over a service endpoint:
      Microsoft.Storage         reaches storage accounts in the SAME region as this VNet
      Microsoft.Storage.Global  reaches storage accounts in ANY region (the default: a managed tenant does not need to
                                know which region the master chose)
    A subnet can carry only one of the two; the other one already present is REFUSED, not replaced.

    Nothing is exchanged with the master except the subnet id this script prints. No credential, no link, nothing that
    expires. The subnet is READ FROM THE CONTAINER APPS ENVIRONMENT (authoritative; -SubnetId is only the fallback), and
    the endpoint list is MERGED (az --service-endpoints replaces the whole list) and read back.

    TRAP: adding a service endpoint changes the SOURCE ADDRESS of this subnet's traffic to Azure Storage from a public IP to
    the subnet's private address. A storage account elsewhere that admits this environment by an IP rule stops matching
    it -- such an account needs a VNet rule for this subnet instead.

.OUTPUTS
    The subnet resource id (a string, on the pipeline) -- give it to the master as slaves[<n>].subnetResourceId.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$EnvName,
    [string]$SubnetId,
    [ValidateSet('Microsoft.Storage', 'Microsoft.Storage.Global')][string]$ServiceEndpoint = 'Microsoft.Storage.Global',
    [string]$MasterStorageAccount,
    [string]$MasterContainer = 'baselines',
    # 71.35: run on the MASTER itself -- its own Container Apps subnet is where the cloud publish job writes from. Same
    # endpoint work; only the closing message differs (there is nobody to hand the subnet id to: the storage step reads it).
    [switch]$ForPublisher
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $solRoot 'engine\_shared\PIM-MspBuild.ps1')
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
$sub = @('--subscription', "$SubscriptionId".Trim())

Step "pull network: $ServiceEndpoint on this environment's subnet"
$ErrorActionPreference = 'Continue'
if ("$EnvName".Trim()) {
    $fromEnv = "$(az containerapp env show @sub -g $ResourceGroup -n $EnvName --query properties.vnetConfiguration.infrastructureSubnetId -o tsv --only-show-errors 2>$null)".Trim()
    if ($fromEnv) { $SubnetId = $fromEnv; Note "subnet read from the Container Apps environment '$EnvName' (authoritative)" }
}
$ErrorActionPreference = 'Stop'
$chk = Test-PimBaselineNetworkSource -Value "$SubnetId"
if (-not $chk.ok -or $chk.kind -ne 'subnet') {
    throw "no usable subnet: the environment '$EnvName' did not name one and -SubnetId is '$SubnetId'. $($chk.reason)"
}

$ErrorActionPreference = 'Continue'
$cur = @(az network vnet subnet show @sub --ids $SubnetId --query "serviceEndpoints[].service" -o tsv --only-show-errors 2>$null | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
$ErrorActionPreference = 'Stop'
$plan = Get-PimPullSubnetEndpointPlan -Current $cur -Want $ServiceEndpoint
Note $plan.reason
if ($plan.action -eq 'refuse') { throw "REFUSED: $($plan.reason)" }
if ($plan.action -eq 'add' -and $PSCmdlet.ShouldProcess($SubnetId, "service endpoints = $(@($plan.endpoints) -join ', ')")) {
    $ErrorActionPreference = 'Continue'
    az network vnet subnet update @sub --ids $SubnetId --service-endpoints @($plan.endpoints) -o none --only-show-errors
    $code = $LASTEXITCODE
    $back = @(az network vnet subnet show @sub --ids $SubnetId --query "serviceEndpoints[].service" -o tsv --only-show-errors 2>$null | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $ErrorActionPreference = 'Stop'
    if ($code -ne 0 -or $back -notcontains $ServiceEndpoint) {
        throw ("read-back FAILED: the subnet carries '$($back -join ', ')' after the update (az exit $code). If the subnet is delegated to " +
               'Microsoft.App/environments and the platform refused the endpoint, the fallback is a private endpoint to the master store (DESIGN 13.7 option 1).')
    }
    Note "read back: $($back -join ', ')"
}

$url = if ("$MasterStorageAccount".Trim()) { Get-PimBaselinePullUrl -StorageAccount $MasterStorageAccount -Container $MasterContainer } else { '' }
Write-Host ''
if ($ForPublisher) {
    Write-Host "  publisher network ready: $SubnetId carries $ServiceEndpoint (the storage step allows it before the firewall denies)" -ForegroundColor Green
    Write-Output $SubnetId
    exit 0
}
Write-Host '  GIVE THIS TO THE MSP MASTER (it is an address, not a credential):' -ForegroundColor Yellow
Write-Host "    slaves[<n>].subnetResourceId = $SubnetId" -ForegroundColor Yellow
if ($url) { Write-Host "    this tenant pulls: $url  (public-but-signed; the pull refuses an unsigned bundle)" -ForegroundColor DarkGray }
Write-Output $SubnetId
exit 0
