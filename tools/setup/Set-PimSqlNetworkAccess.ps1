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
. (Join-Path (Split-Path -Parent $PSCommandPath) '_PimAz.ps1')   # the guarded az shadow

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }

$result = @{ ok = $false; vnetRule = $false; firewallRule = $false; serviceEndpoint = $false; reason = ''
             notApplicable = $false }
$sub    = @('--subscription', "$SubscriptionId".Trim())
$srv    = ("$SqlServerFqdn".Trim() -split '\.')[0]

Step "SQL network access: let this environment reach $srv"

# ---- 1. WHICH SUBNET? Ask the environment; fall back to what the caller derived. ---------------
if (-not "$SubnetId".Trim() -and "$EnvName".Trim() -and "$ResourceGroup".Trim()) {
    $SubnetId = "$(az containerapp env show @sub -g $ResourceGroup -n $EnvName --query properties.vnetConfiguration.infrastructureSubnetId -o tsv 2>$null)".Trim()
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
$sqlRg  = "$(az sql server list --subscription $sqlSub --query "[?name=='$srv'].resourceGroup" -o tsv 2>$null | Select-Object -First 1)".Trim()
if (-not $sqlRg -and -not "$SqlSubscriptionId".Trim()) {
    Note "not in subscription $sqlSub -- searching the other subscriptions this identity can see"
    foreach ($s in @(az account list --query "[].id" -o tsv 2>$null | Where-Object { "$_".Trim() -and "$_".Trim() -ne $sqlSub })) {
        $cand = "$(az sql server list --subscription "$s".Trim() --query "[?name=='$srv'].resourceGroup" -o tsv 2>$null | Select-Object -First 1)".Trim()
        if ($cand) { $sqlRg = $cand; $sqlSub = "$s".Trim(); Note "found '$srv' in subscription $sqlSub (resource group $sqlRg)"; break }
    }
}
# Every SQL call below is scoped to the subscription the SERVER is in, which is not necessarily
# the one the rest of the deploy runs against.
$sqlSubArgs = @('--subscription', $sqlSub)
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
    $svcNow = @(az network vnet subnet show @sub --ids $SubnetId --query "serviceEndpoints[].service" -o tsv 2>$null) |
              Where-Object { "$_".Trim() }
    if ($svcNow -notcontains 'Microsoft.Sql') {
        # 🪤 --service-endpoints REPLACES what is there. Reading first is what keeps an existing
        # endpoint (Storage, KeyVault) from being silently removed by a call that only meant to add.
        $svcWant = @(@($svcNow) + 'Microsoft.Sql' | Where-Object { "$_".Trim() } | Select-Object -Unique)
        if ($PSCmdlet.ShouldProcess($SubnetId, 'add the Microsoft.Sql service endpoint')) {
            az network vnet subnet update @sub --ids $SubnetId --service-endpoints @svcWant -o none 2>$null
            $svcNow = @(az network vnet subnet show @sub --ids $SubnetId --query "serviceEndpoints[].service" -o tsv 2>$null) |
                      Where-Object { "$_".Trim() }
        }
    }
    $result.serviceEndpoint = ($svcNow -contains 'Microsoft.Sql')
    Note $(if ($result.serviceEndpoint) { 'subnet carries the Microsoft.Sql service endpoint' }
           else { 'subnet has NO Microsoft.Sql service endpoint (policy? delegation?) -- relying on the firewall rule' })

    # ---- 4. THE VNET RULE ---------------------------------------------------------------------
    $have = "$(az sql server vnet-rule list @sqlSubArgs -g $sqlRg -s $srv --query "[?name=='$RuleName'].name" -o tsv 2>$null)".Trim()
    if (-not $have -and $PSCmdlet.ShouldProcess("$srv/$RuleName", 'create the SQL VNet rule for this subnet')) {
        # --ignore-missing-endpoint so the rule can still exist when the endpoint could not be
        # added: the repair must not be all-or-nothing.
        az sql server vnet-rule create @sqlSubArgs -g $sqlRg -s $srv -n $RuleName --subnet $SubnetId `
            --ignore-missing-endpoint -o none 2>$null
        $have = "$(az sql server vnet-rule list @sqlSubArgs -g $sqlRg -s $srv --query "[?name=='$RuleName'].name" -o tsv 2>$null)".Trim()
    }
    $result.vnetRule = [bool]$have
} else {
    Write-Warning '  could not resolve the ACA subnet, so no VNet rule can be created -- falling back to the firewall rule alone.'
}

# ---- 5. THE FIREWALL RULE PREREQ BELIEVES IT CREATED -- verify it ------------------------------
# This is the one that was missing at the customer, and its absence was invisible because the
# create swallows its errors and prereq's own verify block checks a DIFFERENT rule.
$fw = "$(az sql server firewall-rule list @sqlSubArgs -g $sqlRg -s $srv --query "[?name=='AllowAzureServices'].name" -o tsv 2>$null)".Trim()
if (-not $fw -and $PSCmdlet.ShouldProcess("$srv/AllowAzureServices", 'create the Azure-services firewall rule')) {
    Note 'AllowAzureServices is MISSING -- creating it (prereq swallowed the failure)'
    az sql server firewall-rule create @sqlSubArgs -g $sqlRg -s $srv -n AllowAzureServices `
        --start-ip-address 0.0.0.0 --end-ip-address 0.0.0.0 -o none 2>$null
    $fw = "$(az sql server firewall-rule list @sqlSubArgs -g $sqlRg -s $srv --query "[?name=='AllowAzureServices'].name" -o tsv 2>$null)".Trim()
}
$result.firewallRule = [bool]$fw

Note ("vnet-rule '{0}' {1}; firewall 'AllowAzureServices' {2}" -f $RuleName,
      $(if ($result.vnetRule) { 'present' } else { 'ABSENT' }),
      $(if ($result.firewallRule) { 'present' } else { 'ABSENT' }))

# ---- 6. THE VERDICT ---------------------------------------------------------------------------
# Neither path in place means a Manager that will start, be refused, and die -- and the gate
# afterwards will report a store problem it cannot see. Say it HERE, where the cause is visible.
$result.ok = ($result.vnetRule -or $result.firewallRule)
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
