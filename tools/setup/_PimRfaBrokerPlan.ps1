#Requires -Version 5.1
<#
  §82 P4 -- the PURE deploy plan of the public RFA broker (Pro). REQUIREMENTS §82.6 (placement), §90 (API).
  Deploy-PimRfaBroker.ps1 executes it; tests/Test-PimRfaBrokerDeploy.ps1 proves it offline.

  Placement:
    Shared (default) -- the PIM subscription + the PIM VNet, in its OWN subnet (delegated to Container Apps), an NSG on
                        that subnet that DENIES traffic to the PIM subnets (the broker reaches only its own store + Entra +
                        Graph over the internet).
    Island           -- its own subscription + its own VNet, no peering to the PIM VNet.
  Both: no inbound path from the public side to the PIM network; the engine pulls (outbound only).
#>

function Get-PimRfaBrokerDeployPlan {
    <#
      PURE. Returns { ok; reason; steps[] } -- each step { id; what; sub; rg; args (hashtable) }. Refuses (ok=false):
      a missing PIM subscription / resource group / image / sender, a bad storage name, an Island without its own
      subscription, a Shared placement without the PIM VNet, a subnet prefix that is not a /27 or larger CIDR, an
      ApiAllowedIps entry that is not an IPv4 address / CIDR, and no engine identity to read the store.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
        [ValidateSet('Shared', 'Island')][string]$Placement = 'Shared',
        [string]$RfaSubscriptionId = '', [string]$RfaResourceGroup = '',
        [string]$Location = 'westeurope',
        [string]$VnetName = '', [string]$SubnetName = 'snet-pim-rfa', [string]$SubnetPrefix = '',
        [string[]]$PimSubnetPrefixes = @(),
        [Parameter(Mandatory)][string]$StorageAccountName,
        [string]$EnvironmentName = 'cae-pim-rfa', [string]$AppName = 'ca-pim-rfa',
        [Parameter(Mandatory)][string]$Image, [string]$AcrName = '',
        [Parameter(Mandatory)][string]$SenderMailbox, [string]$TenantName = '',
        [string[]]$EngineIdentityPrincipalIds = @(),
        [string[]]$ApiAllowedIps = @(),
        [int]$MinReplicas = 0,
        # Join a Container Apps environment that is ALREADY public (internal / EFIF / RIDE are, by design): no new
        # subnet, NSG, environment or load balancer (~125 kr./month saved). The broker then shares that environment's
        # subnet with the PIM apps -- acceptable where the environment is public anyway; customers get their own.
        [string]$ExistingEnvironmentName = ''
    )
    $no = { param($r) [pscustomobject]@{ ok = $false; reason = $r; steps = @() } }
    $guid = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    if ($SubscriptionId -notmatch $guid) { return (& $no 'the PIM subscription id must be a GUID') }
    if (-not "$ResourceGroup".Trim()) { return (& $no 'the PIM resource group is required') }
    if ($StorageAccountName -notmatch '^[a-z0-9]{3,24}$') { return (& $no 'the storage account name must be 3-24 lower-case letters / digits') }
    if (-not "$Image".Trim()) { return (& $no 'the image (the PIM manager image, same as the jobs) is required') }
    if ("$SenderMailbox" -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return (& $no 'the sender mailbox (the PIM mail sender) must be an e-mail address') }
    if (-not @($EngineIdentityPrincipalIds | Where-Object { "$_" -match $guid }).Count) { return (& $no 'at least one ENGINE identity (the tick job''s managed identity) must be named -- it pulls the requests from the store') }
    $reuse = [bool]"$ExistingEnvironmentName".Trim()
    if ($reuse -and $Placement -eq 'Island') { return (& $no 'the Island placement builds its own environment -- -ExistingEnvironmentName is for Shared only') }
    if (-not $reuse -and "$SubnetPrefix" -notmatch '^\d{1,3}(\.\d{1,3}){3}/(1[6-9]|2[0-7])$') { return (& $no 'the broker subnet prefix must be an IPv4 CIDR of /27 or larger (Container Apps needs it)') }
    foreach ($ip in @($ApiAllowedIps)) { if ("$ip" -notmatch '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$') { return (& $no "ApiAllowedIps: '$ip' is not an IPv4 address or CIDR") } }
    if ($MinReplicas -lt 0 -or $MinReplicas -gt 2) { return (& $no 'MinReplicas is 0 (scale to zero, default) .. 2') }
    $sub = $SubscriptionId; $rg = $ResourceGroup
    if ($Placement -eq 'Island') {
        if ($RfaSubscriptionId -notmatch $guid) { return (& $no 'the Island placement needs its own subscription (-RfaSubscriptionId)') }
        if ($RfaSubscriptionId -eq $SubscriptionId) { return (& $no 'the Island placement needs a DIFFERENT subscription than PIM''s (use Shared otherwise)') }
        $sub = $RfaSubscriptionId; $rg = $(if ("$RfaResourceGroup".Trim()) { $RfaResourceGroup } else { 'rg-pim-rfa' })
        if (-not "$VnetName".Trim()) { $VnetName = 'vnet-pim-rfa' }
    } elseif (-not $reuse) {
        if (-not "$VnetName".Trim()) { return (& $no 'the Shared placement needs the PIM VNet (-VnetName): the broker gets its own subnet there') }
        if (-not @($PimSubnetPrefixes).Count) { return (& $no 'the Shared placement needs the PIM subnet prefixes (-PimSubnetPrefixes): the broker subnet''s NSG denies traffic to them') }
    }
    if ($reuse) { $EnvironmentName = "$ExistingEnvironmentName".Trim() }
    $steps = New-Object System.Collections.Generic.List[object]
    $add = { param($id, $what, $a) $steps.Add([pscustomobject]@{ id = $id; what = $what; sub = $sub; rg = $rg; args = $a }) }
    if ($Placement -eq 'Island') { & $add 'rg' "resource group $rg in the RFA subscription" @{ name = $rg; location = $Location } }
    & $add 'storage' "storage account $StorageAccountName (Tables; shared-key access DISABLED, TLS 1.2, no public blob)" @{ name = $StorageAccountName; location = $Location; allowSharedKey = $false; minTls = 'TLS1_2' }
    & $add 'tables' 'the RFA tables' @{ account = $StorageAccountName; tables = @('RfaConfig', 'RfaEligibility', 'RfaRequests', 'RfaReviews', 'RfaAnswers', 'RfaPins', 'RfaSessions', 'RfaRate', 'RfaApiKeys') }
    if ($Placement -eq 'Island') { & $add 'vnet' "VNet $VnetName (its own; NOT peered to the PIM VNet)" @{ name = $VnetName; location = $Location; prefix = ($SubnetPrefix -replace '/\d+$', '/24') } }
    if ($reuse) {
        & $add 'env-existing' "JOIN the existing public environment $EnvironmentName (no new subnet / NSG / environment / load balancer)" @{ name = $EnvironmentName; mustBePublic = $true }
    } else {
        & $add 'nsg' "NSG nsg-$AppName on the broker subnet" @{ name = "nsg-$AppName"; location = $Location; denyTo = @($PimSubnetPrefixes) }
        & $add 'subnet' "subnet $SubnetName ($SubnetPrefix) delegated to Microsoft.App/environments" @{ vnet = $VnetName; name = $SubnetName; prefix = $SubnetPrefix; nsg = "nsg-$AppName"; delegation = 'Microsoft.App/environments' }
        & $add 'env' "Container Apps environment $EnvironmentName (PUBLIC, consumption)" @{ name = $EnvironmentName; location = $Location; vnet = $VnetName; subnet = $SubnetName; internal = $false }
    }
    & $add 'app' "container app $AppName (the PIM image, command Start-PimRfaBroker.ps1, scale $MinReplicas..2)" @{ name = $AppName; environment = $EnvironmentName; image = $Image; acr = $AcrName; minReplicas = $MinReplicas; maxReplicas = 2; targetPort = 8080
        command = @('pwsh', '-NoProfile', '-File', '/app/PIM4EntraPS/tools/pim-rfa/Start-PimRfaBroker.ps1'); envVars = [ordered]@{ PIM_RFA_STORE = $StorageAccountName; PIM_RFA_SENDER = $SenderMailbox; PIM_RFA_TENANT_NAME = $TenantName } }
    & $add 'role-app' "Storage Table Data Contributor for $AppName's identity on $StorageAccountName (its ONLY Azure right)" @{ role = 'Storage Table Data Contributor'; scope = 'storage'; principal = 'app' }
    foreach ($e in @($EngineIdentityPrincipalIds | Where-Object { "$_" -match $guid })) { & $add "role-engine-$e" "Storage Table Data Contributor for the engine identity $e on $StorageAccountName (the pull)" @{ role = 'Storage Table Data Contributor'; scope = 'storage'; principal = $e } }
    & $add 'auth' "Easy Auth on ${AppName}: Entra provider, unauthenticated = ALLOW (the portal is PIN-based; /api/v1 needs a validated token or an API key)" @{ app = $AppName; unauthenticated = 'AllowAnonymous' }
    if (@($ApiAllowedIps).Count) { & $add 'ip' "ingress allowed only from $(@($ApiAllowedIps) -join ', ') (the API-only shape: the portal is then NOT public)" @{ app = $AppName; allow = @($ApiAllowedIps) } }
    $steps.Add([pscustomobject]@{ id = 'mail'; what = "let $AppName's identity send as $SenderMailbox ONLY (Exchange-scoped): run Initialize-PimMailSender with -ManagedIdentityObjectId <app identity>"; sub = $SubscriptionId; rg = $ResourceGroup; args = @{ sender = $SenderMailbox } })
    $steps.Add([pscustomobject]@{ id = 'settings'; what = "tell PIM where the broker is: Settings > RFA broker & API -> store $StorageAccountName + the portal URL"; sub = $SubscriptionId; rg = $ResourceGroup; args = @{ storeAccount = $StorageAccountName } })
    return [pscustomobject]@{ ok = $true; reason = ''; placement = $Placement; steps = $steps.ToArray() }
}
