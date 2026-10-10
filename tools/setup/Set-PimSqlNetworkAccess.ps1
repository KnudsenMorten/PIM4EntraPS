#Requires -Version 5.1
<#
.SYNOPSIS
  §52.1 / §52.10 -- grant THIS environment network access to its SQL server, and prove it.

.DESCRIPTION
  🔴 WHY THIS EXISTS, measured at a live customer twice on 2026-09-08/09.

  The Manager starts, resolves its store, mints a managed-identity token, opens the connection --
  and Azure SQL refuses it:

      [store] SQL-only: connect failed ... "Cannot open server '<server>' requested by the login.
      Client with IP address '<addr>' is not allowed to access the server."

  It then refuses to serve and dies, which is correct (§42.2a) and which is why every later probe
  finds no replica, no [version] line, and a boot-log verdict that reads like a broken store.
  ONE cause, every symptom.

  Nothing had ever granted that access. `New-PimHostingPrerequisites` creates an
  `AllowAzureServices` firewall rule under the comment *"ACA reaches SQL from inside the VNet"*,
  and both halves of that are assumptions: the create swallows its own errors and is never read
  back, and a VNet-integrated Container App egresses to a PUBLIC endpoint from a PUBLIC address --
  "inside the VNet" is where the traffic starts, not where SQL sees it arrive.

  🪤 AND WHY IT IS ITS OWN SCRIPT, CALLED BY ITS OWN ALWAYS-RUN STEP.
  The first fix for this went inside `Setup-PimContainers` -- the INFRA step -- which is skipped
  as "already current" the moment the ACA environment exists. So on the very environment that
  needed the repair it never executed, and the next deploy failed identically. That is §45.1's
  rule, which this repo had already written down and which I then re-learned at a customer:
  **a repair gated on a condition that cannot observe the thing being repaired is not a repair.**
  Every read here is cheap and every write is idempotent, so it runs on EVERY deploy.

  🔑 THE VNET RULE IS THE DURABLE HALF; THE FIREWALL RULE IS THE BELT. An IP allow-list is a guess
  about an address that, with no NAT gateway, will change. A service endpoint authorises the
  SUBNET, which is a fact about the environment rather than about today's egress.

  🔑 AND IT ASKS THE ENVIRONMENT WHICH SUBNET IT IS IN. The subnet name has already been wrong
  once in this exact area (§38.1a: infra defaulted to snet-pim-aca while prereq had built
  snet-pim-manager, and ACA refused with NetcfgSubnetRangeOutsideVnet). The Container Apps
  environment knows its own infrastructure subnet; a parameter is only the fallback.

.PARAMETER SqlServerFqdn
  The store's server, e.g. sql-x.database.windows.net. Only its first label is used.

.PARAMETER EnvName
  The Container Apps environment to read the infrastructure subnet from (authoritative).

.PARAMETER SubnetId
  Explicit fallback when the environment cannot be read (or does not exist yet).

.OUTPUTS
  A hashtable: @{ ok; vnetRule; firewallRule; serviceEndpoint; reason }.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$ResourceGroup,
    [string]$EnvName,
    [string]$SubnetId,
    [string]$VnetName,
    [string]$VnetResourceGroup,
    [string]$SubnetName,
    [string]$SqlSubscriptionId,
    [string]$RuleName = 'pim-aca-subnet'
)
$ErrorActionPreference = 'Stop'
# 100.41 (framework 12.17 NO-AZ): ARM REST through PIM-Rest's one token client (engine/_shared/PIM-ArmSetup.ps1). A calling
# deploy's REST session is used as it is; standalone, the Invardia Support app's session or the person signed in. No az.
$solRootSna = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRootSna 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRootSna 'engine\_shared\PIM-ArmSetup.ps1') }

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }

function Get-PimSqlFirewallBeltDecision {
    <#
      PURE (BUG-213). Is the 0.0.0.0 'AllowAzureServices' rule to be CREATED? Only when there is no
      other path: it admits every Azure service of every tenant, so it is never re-opened on a server
      whose environment already reaches it through its own subnet (the build window's closed shape).
    #>
    param([bool]$VnetRule, [bool]$ServiceEndpoint, [bool]$FirewallRulePresent, [string]$PublicNetworkAccess)
    if ("$PublicNetworkAccess".Trim() -ieq 'Disabled') { return @{ create = $false; reason = 'not applicable -- public network access is Disabled (the route is the private endpoint; firewall rules cannot apply)' } }
    if ($FirewallRulePresent) { return @{ create = $false; reason = 'present' } }
    if ($VnetRule -and $ServiceEndpoint) { return @{ create = $false; reason = 'absent and NOT re-created -- the environment reaches the store through its subnet (VNet rule + Microsoft.Sql service endpoint), so opening SQL to every Azure service is not needed' } }
    return @{ create = $true; reason = 'MISSING and there is no working VNet path -- creating it (the only way this environment can reach the store)' }
}

$result = @{ ok = $false; vnetRule = $false; firewallRule = $false; serviceEndpoint = $false; reason = ''
             notApplicable = $false }
$S      = "$SubscriptionId".Trim()
$srv    = ("$SqlServerFqdn".Trim() -split '\.')[0]
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $S) }

Step "SQL network access: let this environment reach $srv"

# ---- 1. WHICH SUBNET? Ask the environment; fall back to what the caller derived. ---------------
if (-not "$SubnetId".Trim() -and "$EnvName".Trim() -and "$ResourceGroup".Trim()) {
    $SubnetId = "$((Get-PimArmAcaEnv -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $EnvName -ErrorAsNull).properties.vnetConfiguration.infrastructureSubnetId)".Trim()
    if ($SubnetId) { Note "subnet read from the Container Apps environment (authoritative)" }
}
if (-not "$SubnetId".Trim() -and "$VnetName".Trim() -and "$SubnetName".Trim()) {
    $vrg = $(if ("$VnetResourceGroup".Trim()) { "$VnetResourceGroup".Trim() } else { "$ResourceGroup".Trim() })
    $SubnetId = "/subscriptions/$SubscriptionId/resourceGroups/$vrg/providers/Microsoft.Network/virtualNetworks/$VnetName/subnets/$SubnetName"
    Note "subnet derived from parameters (the environment could not be read)"
}

# ---- 2. WHERE IS THE SERVER? Ask -- and it is NOT necessarily in this subscription. ------------
# 🔴 THE STORE CAN LIVE IN A DIFFERENT SUBSCRIPTION (operator, 2026-09-09). A central/shared SQL
# server is a supported topology here, so looking only in the deploy's own subscription would find
# nothing and skip the very environments that most need the rule. Search: the deploy's own
# subscription first (the common case, one call), then every subscription this identity can see.
# The VNet rule itself is cross-subscription-capable -- it references the subnet by RESOURCE ID.
$sqlSub = $(if ("$SqlSubscriptionId".Trim()) { "$SqlSubscriptionId".Trim() } else { "$SubscriptionId".Trim() })
# az's "[?name=='X'].resourceGroup": the resource group is the segment of the server's ARM id.
$findRg = { param($inSub) "$(@(Get-PimArmSqlServers -SubscriptionId $inSub | Where-Object { "$($_.name)" -eq $srv } | ForEach-Object { Get-PimArmIdPart -Id "$($_.id)" -Segment 'resourceGroups' }) | Select-Object -First 1)".Trim() }
$sqlRg  = & $findRg $sqlSub
if (-not $sqlRg -and -not "$SqlSubscriptionId".Trim()) {
    Note "not in subscription $sqlSub -- searching the other subscriptions this identity can see"
    foreach ($s in @(Get-PimArmSubscriptions | Where-Object { "$_".Trim() -and "$_".Trim() -ne $sqlSub })) {
        $cand = & $findRg "$s".Trim()
        if ($cand) { $sqlRg = $cand; $sqlSub = "$s".Trim(); Note "found '$srv' in subscription $sqlSub (resource group $sqlRg)"; break }
    }
}
# Every SQL call below is addressed in the subscription the SERVER is in, which is not necessarily
# the one the rest of the deploy runs against.
$ruleNames = { @(Get-PimArmSqlVnetRules -SubscriptionId $sqlSub -ResourceGroup $sqlRg -Server $srv | Where-Object { "$($_.name)" -eq $RuleName } | ForEach-Object { "$($_.name)" }) -join '' }
$fwNames   = { @(Get-PimArmSqlFirewallRules -SubscriptionId $sqlSub -ResourceGroup $sqlRg -Server $srv | Where-Object { "$($_.name)" -eq 'AllowAzureServices' } | ForEach-Object { "$($_.name)" }) -join '' }
if (-not $sqlRg) {
    # 🔴 NOT-APPLICABLE, NOT FAILED -- and the difference is a whole deploy.
    # A central/shared store in another subscription is a legitimate topology; nothing here can
    # configure it, and until this step existed nothing tried. Returning a plain `ok=$false` would
    # make the step HALT AND ROLL BACK a deploy that worked yesterday -- a new failure mode invented
    # by a safety feature. Measured in a dry run before shipping: the verdict said ok=False for a
    # server the deploy simply cannot see.
    # 🪤 The first draft's own comment said "do not fail a deploy over it" while the value it
    # returned did exactly that. An intent stated in a comment is not a behaviour.
    $result.notApplicable = $true
    $result.reason = "SQL server '$srv' is not visible in any subscription this identity can read"
    Write-Warning ("  $($result.reason), so its network access cannot be configured from here. Pass " +
                   "-SqlSubscriptionId if the store's subscription is not in this identity's list, or add a " +
                   "VNet rule on that server yourself for this subnet: " +
                   $(if ("$SubnetId".Trim()) { $SubnetId } else { '(subnet id unresolved)' }))
    return $result
}

# ---- 3. SERVICE ENDPOINT on the subnet (MERGED -- the flag REPLACES the list) ------------------
if ("$SubnetId".Trim()) {
    $readSvc = { @((Get-PimArmResource -ResourceId $SubnetId -Kind network -ErrorAsNull).properties.serviceEndpoints | Where-Object { $_ } | ForEach-Object { "$($_.service)" }) | Where-Object { "$_".Trim() } }
    $svcNow = @(& $readSvc)
    if ($svcNow -notcontains 'Microsoft.Sql') {
        # 🪤 the service-endpoint list is written WHOLE (it REPLACES what is there). Reading first is what keeps an existing
        # endpoint (Storage, KeyVault) from being silently removed by a call that only meant to add.
        $svcWant = @(@($svcNow) + 'Microsoft.Sql' | Where-Object { "$_".Trim() } | Select-Object -Unique)
        if ($PSCmdlet.ShouldProcess($SubnetId, 'add the Microsoft.Sql service endpoint')) {
            # A refused update (policy, delegation) is reported by the read-back below, as before -- never thrown from here.
            try {
                [void](Set-PimArmSubnet -SubscriptionId (Get-PimArmIdPart -Id $SubnetId -Segment 'subscriptions') -ResourceGroup (Get-PimArmIdPart -Id $SubnetId -Segment 'resourceGroups') `
                    -VnetName (Get-PimArmIdPart -Id $SubnetId -Segment 'virtualNetworks') -Name (Get-PimArmIdPart -Id $SubnetId -Segment 'subnets') -ServiceEndpoints $svcWant)
            } catch { Write-Verbose "service endpoint update refused: $($_.Exception.Message)" }
            $svcNow = @(& $readSvc)
        }
    }
    $result.serviceEndpoint = ($svcNow -contains 'Microsoft.Sql')
    Note $(if ($result.serviceEndpoint) { 'subnet carries the Microsoft.Sql service endpoint' }
           else { 'subnet has NO Microsoft.Sql service endpoint (policy? delegation?) -- relying on the firewall rule' })

    # ---- 4. THE VNET RULE ---------------------------------------------------------------------
    $have = "$(& $ruleNames)".Trim()
    if (-not $have -and $PSCmdlet.ShouldProcess("$srv/$RuleName", 'create the SQL VNet rule for this subnet')) {
        # -IgnoreMissingEndpoint so the rule can still exist when the endpoint could not be
        # added: the repair must not be all-or-nothing. A refusal is reported by the read-back.
        try { New-PimArmSqlVnetRule -SubscriptionId $sqlSub -ResourceGroup $sqlRg -Server $srv -Name $RuleName -SubnetId $SubnetId -IgnoreMissingEndpoint }
        catch { Write-Verbose "VNet rule create refused: $($_.Exception.Message)" }
        $have = "$(& $ruleNames)".Trim()
    }
    $result.vnetRule = [bool]$have
} else {
    Write-Warning '  could not resolve the ACA subnet, so no VNet rule can be created -- falling back to the firewall rule alone.'
}

# ---- 5. THE AZURE-SERVICES FIREWALL RULE -- a BELT, only where there is no VNet path -------------
# This is the one that was missing at the customer, and its absence was invisible because the
# create swallows its errors and prereq's own verify block checks a DIFFERENT rule.
# 🔴 BUG-213 -- AND IT RE-OPENED WHAT A CLOSED BUILD WINDOW HAD CLOSED. 0.0.0.0 admits EVERY Azure
# service, any tenant's. Set-PimSqlBuildWindow -Close deletes it deliberately (the store admits ONLY
# the environment's subnet), and this always-run step then re-created it on the next standalone
# deploy -- "prereq swallowed the failure" was the wrong inference: the rule had been REMOVED on
# purpose. Decided now from what the server actually has: when the subnet's VNet rule AND its
# Microsoft.Sql service endpoint are in place, that IS the path and the belt is not re-created.
$pna = "$((Get-PimArmSqlServer -SubscriptionId $sqlSub -ResourceGroup $sqlRg -Name $srv -ErrorAsNull).properties.publicNetworkAccess)".Trim()
$fw = "$(& $fwNames)".Trim()
$belt = Get-PimSqlFirewallBeltDecision -VnetRule ([bool]$result.vnetRule) -ServiceEndpoint ([bool]$result.serviceEndpoint) `
            -FirewallRulePresent ([bool]$fw) -PublicNetworkAccess $pna
Note "Azure-services rule: $($belt.reason)"
if ($belt.create -and $PSCmdlet.ShouldProcess("$srv/AllowAzureServices", 'create the Azure-services firewall rule')) {
    try { [void](Set-PimArmSqlFirewallRule -SubscriptionId $sqlSub -ResourceGroup $sqlRg -Server $srv -Name AllowAzureServices -StartIp 0.0.0.0 -EndIp 0.0.0.0) }
    catch { Write-Verbose "firewall rule create refused: $($_.Exception.Message)" }
}
# READ THE FINAL STATE BACK -- what is reported is what the server has now, not what was intended.
$fw = "$(& $fwNames)".Trim()
$result.firewallRule = [bool]$fw
if ("$SubnetId".Trim()) {
    $result.vnetRule = [bool]"$(& $ruleNames)".Trim()
}
$global:LASTEXITCODE = 0

Note ("final: vnet-rule '{0}' {1} (service endpoint {2}); firewall 'AllowAzureServices' {3}; public network access {4}" -f $RuleName,
      $(if ($result.vnetRule) { 'present' } else { 'ABSENT' }),
      $(if ($result.serviceEndpoint) { 'present' } else { 'ABSENT' }),
      $(if ($result.firewallRule) { 'present' } else { 'ABSENT' }),
      $(if ($pna) { $pna } else { '(unread)' }))

# ---- 6. THE VERDICT ---------------------------------------------------------------------------
# Neither path in place means a Manager that will start, be refused, and die -- and the gate
# afterwards will report a store problem it cannot see. Say it HERE, where the cause is visible.
# 🪤 A VNet rule WITHOUT the subnet's service endpoint is inert (it was created with
# --ignore-missing-endpoint), so it only counts together with the endpoint.
$result.ok = (($result.vnetRule -and $result.serviceEndpoint) -or $result.firewallRule)
if (-not $result.ok -and -not $WhatIfPreference) {
    # 🪤 REPORT, DO NOT THROW. The caller is the deploy's step runner, which reads a verdict object
    # and turns a false `ok` into a clean step failure -- with the rollback path intact. A throw
    # from here escapes as an unhandled exception instead, killing the orchestrator before it can
    # roll anything back: a safety net that fires by cutting the other safety net.
    $result.reason = "no VNet rule and no AllowAzureServices firewall rule on '$sqlRg'"
    Write-Warning ("  nothing grants this environment network access to $SqlServerFqdn ($($result.reason)). " +
                   "The Manager WILL crash at boot with 'Client with IP address ... is not allowed to access " +
                   "the server'. The deploy identity needs SQL Server Contributor on '$sqlRg', or pass " +
                   "-SkipSqlNetworkAccess if the store is reached over a private endpoint.")
}
$result
