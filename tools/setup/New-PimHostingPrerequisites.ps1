<#
.SYNOPSIS
  Everything a tenant needs BEFORE Setup-PimContainers.ps1 can run. Unattended, idempotent.

.DESCRIPTION
  Setup-PimContainers.ps1 assumes the plumbing already exists: registered resource providers,
  a VNet with a delegated Container Apps subnet (/27+ for workload profiles), a Log Analytics workspace, a container
  registry, and a SQL server the Manager's managed identity can actually use. On a FRESH
  subscription none of that is true, so the setup script fails on its first Azure call.

  This script creates that plumbing and nothing else. It is deliberately separate from
  Setup-PimContainers so the two concerns stay apart: this one is "make the subscription
  ready", that one is "deploy PIM".

  🔒 NO MANUAL STEPS. Every action taken by hand while bringing the test estate up -- provider
  registration, the `master` dbmanager grant, the contained DB user -- is scripted here. A
  proof environment must be reachable ONLY by automation, so anything a human had to do by
  hand is a defect in this script, not a runbook step.

.PARAMETER AddressBase
  The /16 the per-environment /21 is carved from. Each environment gets
  <AddressBase>.<Index*8>.0/21 with the ACA subnet as the first /23 inside it -- deterministic
  from the environment index, so two environments can never collide and the plan is
  reproducible without state.

.NOTES
  Idempotent: every step is find-or-create and safe to re-run.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$Token,          # estate token / short suffix, e.g. wa678
    # Stable index -> address space, for the ESTATE scheme only. No longer Mandatory: a customer
    # brings their own IP plan and must not be made to invent an index just to satisfy a parameter
    # whose value is then thrown away. Supply EITHER -Index (estate) OR the two explicit CIDRs
    # (customer). The either/or is enforced below -- neither means no addressing at all.
    [int]$Index = -1,
    [string]$AdminAppId,                           # SPN used to create things (Owner on the sub) -- or -UseSignedInAccount
    # 71.33: create everything as the SIGNED-IN az user (asserted: a user in -TenantId for -SubscriptionId). No SPN login,
    # no isolated profile; the user becomes the create-time SQL Entra admin and a member of the SQL admin group.
    [switch]$UseSignedInAccount,
    # ONE of these two. The estate's throwaway tenants onboard with a secret; a REAL tenant must
    # not -- the repo-root rule is "authenticate as its SPN using a CERTIFICATE, never a client
    # secret". Cert auth was added 2026-08-09 for the myfamilynetwork PRODUCTION build (PIM §34),
    # because this script previously made secret auth structurally mandatory and so could not be
    # pointed at a production tenant at all without breaking that rule.
    [string]$AdminSecret,
    [string]$AdminCertPem,                         # PEM (key+cert) that `az login --certificate` wants
    [string]$Location    = 'swedencentral',        # westeurope/northeurope refuse new resources on FRESH subs
    # 🔴 §52.18 -- S0, NOT Basic. Basic caps the database at 300 CONCURRENT SESSIONS and 5 DTU, and
    # a live environment reaches that: the deploy steps, the Manager, the tick job and an operator's
    # own shell each hold sessions, and a CSV import then fails halfway with "The session limit for
    # the database is 300 and has been reached" -- measured at a live customer 2026-09-09. S0 is
    # 600 sessions and 10 DTU for practically the same money. Overridable for a lab that wants the
    # cheapest possible database.
    [string]$SqlServiceObjective = 'S0',
    # 🔑 AZURE SQL'S CONNECTION POLICY, AND WHY A FIREWALLED DEPLOYMENT NEEDS 'Proxy'.
    # From inside Azure the default is 'Redirect': the client connects to the gateway on 1433, is
    # handed the node's address, and reconnects on a port in 11000-11999. Behind a firewall that
    # allows only 1433 this produces a connection that AUTHENTICATES AND THEN HANGS -- which reads
    # as a database or credential problem, not a port one, and is a long way to debug.
    # 'Proxy' keeps every connection on 1433 (all traffic through the gateway, slightly higher
    # latency). 'Default' leaves whatever Azure chooses.
    [ValidateSet('Default','Proxy','Redirect')][string]$SqlConnectionPolicy = 'Default',
    # 🔑 BASIC AND STANDARD REGISTRIES HAVE NO NETWORK CONTROLS AT ALL -- no private endpoint, no
    # firewall rules. "A registry with public network access disabled" is a PREMIUM-ONLY state, so a
    # tenant whose policy forbids public registries is not asking for a setting, it is asking for a
    # SKU. Basic stays the default because it is ~10x cheaper and right for an estate that does not
    # have that policy.
    # 🪤 With -AcrPublicAccess false, `az acr build` CANNOT run from outside the VNet: ACR Tasks live
    # in ACR's own infrastructure and the registry is no longer reachable from your host. Build
    # first, lock down after -- or run the deploy from inside the network.
    [ValidateSet('Basic','Standard','Premium')][string]$AcrSku = 'Basic',
    [ValidateSet('Default','true','false')][string]$AcrPublicAccess = 'Default',

    # ---- PRIVATE ENDPOINTS (an internal-only design, reproducibly) -------------------------------
    # 🔴 A PRIVATE ENDPOINT CANNOT LIVE IN THE ACA SUBNET. That subnet is delegated to
    # Microsoft.App/environments, and a delegated subnet accepts nothing else -- so an internal
    # deployment needs a SECOND subnet, and deciding that after the VNet is built means moving
    # endpoints, which means recreating them.
    # Required whenever -AcrPublicAccess false: a registry with no public access and no private
    # endpoint is not "locked down", it is unreachable, and the deploy would fail at the pull with
    # an authentication error that names the registry rather than the missing route.
    [string]$PrivateEndpointSubnetName = 'pim-endpoints',
    [string]$PrivateEndpointSubnetAddressPrefix,
    # 🪤 ACR NEEDS **TWO** DNS RECORDS, not one: <name>.azurecr.io AND
    # <name>.<region>.data.azurecr.io -- the data endpoint is where layers actually move. Creating
    # the zone by hand and missing the data record yields a login that succeeds and a pull that
    # hangs. The dns-zone-group below registers both, which is why it is used instead of hand-built
    # A records.
    [string]$PrivateDnsResourceGroup,
    # 🔑 ACR TASKS RUN IN ACR'S OWN INFRASTRUCTURE, so `az acr build` cannot reach a registry whose
    # public access is off -- from anywhere outside the VNet. A dedicated agent pool runs those
    # tasks INSIDE the VNet instead, which is what makes an internal-only build reproducible from a
    # host that is not itself on the network. Premium-only; billed per agent-hour while running.
    # 🔑 SQL with no public endpoint is reachable from NOWHERE until this exists -- it is PaaS, not
    # a VNet resource. Implied by an internal-only design; the ACA env then reaches its own database
    # inside the VNet, and no deploy host ever needs a path to it.
    [switch]$SqlPrivateEndpoint,
    [string]$AcrAgentPoolName,
    [int]$AcrAgentPoolCount = 1,
    [ValidateSet('S1','S2','S3')][string]$AcrAgentPoolTier = 'S1',
    [string]$AddressBase = '10.220',

    # ---- §38.1a PER-CUSTOMER OVERRIDES -------------------------------------------------
    # 🔒 EVERY ONE OF THESE DEFAULTS TO THE TOKEN/INDEX-DERIVED VALUE, so the 28-tenant estate
    # and all ~30 existing environments are bit-for-bit unchanged: pass nothing and this script
    # behaves exactly as it did. Only a CUSTOMER supplies them.
    # Why they exist (operator, 2026-09-08): "all customers are individual". The estate contract
    # -- one token deriving every name, one index deriving every address -- is right for
    # throwaway test tenants and wrong for a customer who arrives with their own naming standard
    # and their own IP plan, and who cannot be given a /21 we chose for them.
    # ⚠️ Invoke-PimDeployAll cross-checks these names against the ones the deploy will use. That
    # check compares the EFFECTIVE names (§38.1b) -- keep it: mismatched names silently build
    # half an environment in one place and half in another.
    [string]$ResourceGroupName,
    [string]$VnetName,
    [string]$SubnetName,
    [string]$VnetAddressPrefix,
    [string]$SubnetAddressPrefix,
    [string]$AcrName,
    [string]$LogAnalyticsName,
    [string]$SqlServerName,
    [switch]$SkipSql,
    # ---- 2026-09-15 THE SQL ADMIN GROUP ------------------------------------------------------------
    # The SQL server's Entra admin converges on this security group, holding the environment identity,
    # the SQL identity (private SQL), this deploy identity, the troubleshooting identity and whoever was
    # admin before. Same model on public and private SQL. -SkipSqlAdminGroup keeps the single-principal
    # admin of earlier versions.
    [string]$SqlAdminGroupName = 'grp-pim-sql-admins',
    [string]$TroubleshootingAppId,
    [switch]$SkipSqlAdminGroup,
    # IMP-49 t -- THIS host's public IP for the setup-host firewall rule. Without it the IP is read from
    # https://api.ipify.org, a third-party web service -- and that is now SAID on screen, every time.
    # The rule is the SETUP window, not a standing grant: Invoke-PimDeployAll removes it when its run
    # ends; run standalone, remove it yourself once the deploy's SQL steps are done (printed below).
    [string]$SetupHostIp
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimSqlAdminGroup.ps1')     # the SQL admin group (plan + converge + read-back)

function Get-PimEffective { param([string]$Override,[string]$Derived)
    if ("$Override".Trim()) { "$Override".Trim() } else { $Derived }
}

$rg      = Get-PimEffective $ResourceGroupName "rg-automateit-$Token"
$vnet    = Get-PimEffective $VnetName          "vnet-pim-$Token"
$subnet  = Get-PimEffective $SubnetName        'snet-pim-aca'
$law     = Get-PimEffective $LogAnalyticsName  "law-pim-$Token"
# ACR: alphanumeric only. An OVERRIDE is sanitised the same way a derived name is -- silently
# accepting 'acr-customer' here would fail minutes later inside az with a name-rules error.
$acr     = (Get-PimEffective $AcrName ("acrpim$Token") -replace '[^A-Za-z0-9]','').ToLowerInvariant()
$sqlSrv  = Get-PimEffective $SqlServerName     "sql-ait-$Token"
$sqlDb   = 'PimPlatform'
# 🔒 ADDRESSING COMES FROM EXACTLY ONE PLACE, and the caller chooses which:
#   * the CUSTOMER's own plan  -> -VnetAddressPrefix + -SubnetAddressPrefix (any range they like;
#     -Index and -AddressBase are then never consulted, so no 10.220 default can leak in), or
#   * the ESTATE scheme        -> -Index, giving <AddressBase>.<Index*8>.0/21.
# Supplying NEITHER is refused rather than defaulted. A default address range is the one thing
# that must never be guessed: two environments that silently share a CIDR cannot be peered to a
# hub afterwards, and that is discovered months later, by which point it is unfixable.
$haveExplicitCidr = ("$VnetAddressPrefix".Trim() -and "$SubnetAddressPrefix".Trim())
if (-not $haveExplicitCidr) {
    if ("$VnetAddressPrefix".Trim() -or "$SubnetAddressPrefix".Trim()) {
        throw "Supply BOTH -VnetAddressPrefix and -SubnetAddressPrefix, or neither. Half an address plan is not one -- the missing half would silently fall back to the estate's $AddressBase scheme and could overlap another environment."
    }
    if ($Index -lt 0) {
        throw "No address plan given. Pass either -VnetAddressPrefix + -SubnetAddressPrefix (the customer's own range) or -Index (the estate scheme, <AddressBase>.<Index*8>.0/21). Refusing to default: two environments sharing a CIDR cannot be peered later."
    }
}
$vnetCidr   = $(if ($haveExplicitCidr) { "$VnetAddressPrefix".Trim() }   else { "$AddressBase.$($Index * 8).0/21" })
$subnetCidr = $(if ($haveExplicitCidr) { "$SubnetAddressPrefix".Trim() } else { "$AddressBase.$($Index * 8).0/23" })

# 🔴 A CUSTOMER CIDR IS NOT DERIVED, SO IT IS NOT AUTOMATICALLY SANE. The derived pair cannot
# disagree -- both come from the same index. An overridden pair can, and the failure is ugly and
# late: ACA accepts a subnet outside the VNet only to fail at environment creation, and a subnet
# too small for the environment kind fails after the VNet already exists. Check both here first.
if ($subnetCidr -notmatch '^\d{1,3}(\.\d{1,3}){3}/(\d{1,2})$') { throw "SubnetAddressPrefix '$subnetCidr' is not valid CIDR." }
if ($vnetCidr   -notmatch '^\d{1,3}(\.\d{1,3}){3}/(\d{1,2})$') { throw "VnetAddressPrefix '$vnetCidr' is not valid CIDR." }
# 🔑 THE MINIMUM DEPENDS ON THE ENVIRONMENT KIND, and this script builds the WORKLOAD-PROFILES
# kind (Setup-PimContainers passes --enable-workload-profiles). Microsoft's requirement:
#     workload profiles  -> /27 or larger    <-- what we create
#     Consumption-only   -> /23 or larger    (the LEGACY kind; we never create it)
# This demanded /23 unconditionally, which is the legacy number, and so refused a customer's
# perfectly valid /24 network outright -- measured 2026-09-08, where the customer owned only a
# /24 and could not be given a /23 at all.
$subnetBits = [int]($subnetCidr -split '/')[1]
if ($subnetBits -gt 27) {
    throw "SubnetAddressPrefix '$subnetCidr' is smaller than /27. A workload-profiles Container Apps environment requires /27 or larger for its infrastructure subnet, and this fails at environment creation -- after the VNet exists."
}
elseif ($subnetBits -gt 23) {
    # Valid, but say it out loud now rather than let it be discovered during an update.
    # ACA reserves 12 addresses for infrastructure and Azure reserves 5 more, so a /27 (32) leaves
    # roughly 15 usable. A deploy rolls a NEW revision while the OLD one is still running, so peak
    # demand is higher than steady state -- the tightest moment is an update, not day one.
    # 🪤 NAME A PREFIX THAT IS ACTUALLY BIGGER THAN THE ONE SUPPLIED. This used to end with a flat
    # "give this subnet /26 or larger", which told an operator deploying a /26 to use a /26 --
    # advice that cannot be acted on, so it reads as a defect in the tool rather than a hint.
    # Measured at a live customer 2026-09-08.
    $usable  = [math]::Pow(2, 32 - $subnetBits) - 17    # 12 reserved by ACA + 5 by Azure
    $suggest = "/$($subnetBits - 1)"
    Write-Warning ("subnet $subnetCidr is valid for a workload-profiles environment (/27 minimum) but has little " +
                   "headroom: Container Apps reserves 12 addresses and Azure 5, leaving about $usable usable, and a " +
                   "revision roll needs the old and new revisions at once. If the VNet has room, $suggest or larger " +
                   "gives more room to roll.")
}

Write-Host "=== hosting prerequisites -- $Token ===" -ForegroundColor Cyan
Write-Host "  subscription : $SubscriptionId"
Write-Host "  location     : $Location"
Write-Host "  vnet/subnet  : $vnet $vnetCidr  /  $subnet $subnetCidr"
Write-Host "  acr / law    : $acr / $law"

$signedIn = $null
if ($UseSignedInAccount) {
    if ("$AdminAppId".Trim() -or $AdminSecret -or $AdminCertPem) { throw '-UseSignedInAccount cannot be combined with -AdminAppId / -AdminSecret / -AdminCertPem -- pick ONE identity.' }
    . (Join-Path $PSScriptRoot '_PimSignedIn.ps1')
    $signedIn = Get-PimSignedInIdentity -TenantId $TenantId -SubscriptionId $SubscriptionId
    if (-not $signedIn.ok) { throw "REFUSED: $($signedIn.reason)" }
    Write-Host "  auth         : SIGNED-IN user $($signedIn.userName) ($($signedIn.objectId))" -ForegroundColor DarkGray
} else {
if (-not "$AdminAppId".Trim()) { throw 'give -AdminAppId with -AdminCertPem (or -AdminSecret), or -UseSignedInAccount.' }
# isolated az profile so the shared context on this host is never disturbed
$cfg = Join-Path $env:TEMP "azcfg-$Token"
New-Item -ItemType Directory -Force $cfg | Out-Null
$env:AZURE_CONFIG_DIR = $cfg
# Drop the cached token before signing in -- this directory persists between runs, so a permission
# granted BETWEEN runs is otherwise invisible to the next one and surfaces as "Insufficient
# privileges" against a permission that is already correct. See the long note at the same point in
# Setup-PimContainers.ps1; the three sign-ins must not disagree. `az account clear` keeps `config`,
# so extension.use_dynamic_install survives and an unattended run cannot hang on an install prompt.
az account clear --only-show-errors 2>&1 | Out-Null
az config set extension.use_dynamic_install=yes_without_prompt --only-show-errors 2>&1 | Out-Null
# Exactly one credential. Refusing BOTH is not pedantry: silently preferring one would make a
# production run that *thought* it was cert-authenticating actually use a secret.
if ($AdminSecret -and $AdminCertPem) { throw 'pass EITHER -AdminSecret OR -AdminCertPem, not both.' }
if (-not $AdminSecret -and -not $AdminCertPem) { throw 'one of -AdminSecret / -AdminCertPem is required.' }
if ($AdminCertPem) {
    if (-not (Test-Path $AdminCertPem)) { throw "certificate PEM not found: $AdminCertPem" }
    Write-Host "  auth         : CERTIFICATE ($AdminAppId)" -ForegroundColor DarkGray
    az login --service-principal -u $AdminAppId --certificate $AdminCertPem --tenant $TenantId --only-show-errors -o none
} else {
    Write-Host "  auth         : client secret ($AdminAppId)" -ForegroundColor DarkGray
    az login --service-principal -u $AdminAppId -p $AdminSecret --tenant $TenantId --only-show-errors -o none
}
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az login failed for $AdminAppId in $TenantId." }
az account set --subscription $SubscriptionId --only-show-errors
}
# Every az call below is scoped explicitly as well: on a host with two logins the default context can
# change under a long run (another shell's `az account set`), and a bare call then acts in that one.
$subArgs = @('--subscription', $SubscriptionId)

# ---- 1. resource providers --------------------------------------------------
# A fresh subscription has none of these. Registration is asynchronous, so wait: creating a
# resource against a Registering provider fails with a message that blames the resource.
Write-Host "[1] resource providers ..." -ForegroundColor Yellow
# 🔴 Microsoft.Storage added 2026-08-25 (operator: "register microsoft.storage must be in the
# script" -- no manual prereqs). The MSP baseline bundle is published to blob, so an MSP master
# needs this provider; a single-tenant install never notices, which is exactly why it was missing.
# 🪤 THE FAILURE DOES NOT SAY "PROVIDER": creating a storage account against an unregistered
# Microsoft.Storage answers `(SubscriptionNotFound) Subscription <id> was not found`. That reads as
# a wrong-tenant or a permissions fault and sends you to check logins and RBAC -- both of which are
# fine. Measured on EFIF's subscription, which had every OTHER provider registered by this very
# list. Registering here costs nothing when it is already registered (the loop probes first).
$providers = 'Microsoft.App','Microsoft.ContainerRegistry','Microsoft.OperationalInsights','Microsoft.Network','Microsoft.Sql','Microsoft.Storage'
foreach ($p in $providers) {
    $state = az provider show @subArgs --namespace $p --query registrationState -o tsv --only-show-errors 2>$null
    if ($state -ne 'Registered') {
        Write-Host "    registering $p ..."
        az provider register @subArgs --namespace $p --wait --only-show-errors 2>&1 | Out-Null
    }
    $state = az provider show @subArgs --namespace $p --query registrationState -o tsv --only-show-errors 2>$null
    Write-Host ("    {0,-32} {1}" -f $p, $state)
    if ($state -ne 'Registered') { throw "provider $p is '$state' -- cannot continue" }
}

# ---- 2. resource group ------------------------------------------------------
Write-Host "[2] resource group ..." -ForegroundColor Yellow
az group create @subArgs -n $rg -l $Location --only-show-errors -o none
Write-Host "    $rg"

# ---- 3. VNet + ACA subnet ---------------------------------------------------
# Container Apps needs a dedicated subnet delegated to Microsoft.App/environments, minimum /23.
# 🪤 -l $Location is NOT optional here. Without it the VNet inherits the RESOURCE GROUP's
# location -- which is the same region every OTHER resource below pins explicitly. That works
# by coincidence wherever this script also created the RG, and fails wherever the RG predates
# it: on test1mspmstintctrr2wa678 the RG is a westeurope remnant of hand-driven work, so the
# VNet was attempted in westeurope and Azure refused it with "The selected region is currently
# not accepting new customers" -- the exact constraint the -Location default exists to avoid.
# An RG's location is metadata only, so a swedencentral VNet in a westeurope RG is fine.
Write-Host "[3] vnet + delegated subnet ..." -ForegroundColor Yellow
$vnetId = az network vnet show @subArgs -g $rg -n $vnet --query id -o tsv --only-show-errors 2>$null
if (-not $vnetId) {
    az network vnet create @subArgs -g $rg -n $vnet -l $Location --address-prefixes $vnetCidr `
        --subnet-name $subnet --subnet-prefixes $subnetCidr --only-show-errors -o none
    # 🔴 STOP HERE IF THE CREATE DID NOT HAPPEN. Measured at a customer 2026-09-11: Azure Policy
    # denied the VNet, the denial was printed -- and the script carried on to `subnet update` and
    # `subnet show` against a VNet that does not exist, finally dying several lines later with
    # "You cannot call a method on a null-valued expression". The policy message was the LAST
    # useful line on screen and the crash was the first thing the operator read, so the real cause
    # was above the noise rather than at the point of failure.
    # A create whose result is never read is the unverified-write class this repo keeps finding.
    $vnetId = az network vnet show @subArgs -g $rg -n $vnet --query id -o tsv --only-show-errors 2>$null
    if (-not $vnetId) {
        throw ("the VNet '$vnet' was NOT created in '$rg' -- see the failure printed immediately above " +
               "(an Azure Policy denial names its assignment and the field it evaluated). Nothing further " +
               "can be built on it, so this stops here rather than failing further down on a null.")
    }
}
az network vnet subnet update @subArgs -g $rg --vnet-name $vnet -n $subnet `
    --delegations Microsoft.App/environments --only-show-errors -o none
$sn = az network vnet subnet show @subArgs -g $rg --vnet-name $vnet -n $subnet --query "{cidr:addressPrefix,deleg:delegations[0].serviceName}" -o tsv --only-show-errors
if (-not "$sn".Trim()) {
    throw ("subnet '$subnet' is missing or not readable in '$vnet'. The ACA environment cannot be " +
           "created without a subnet delegated to Microsoft.App/environments.")
}
Write-Host "    $vnet / $subnet -> $sn"

# ---- 4. Log Analytics (ACA requires a workspace) ----------------------------
Write-Host "[4] log analytics ..." -ForegroundColor Yellow
az monitor log-analytics workspace create @subArgs -g $rg -n $law -l $Location --only-show-errors -o none 2>$null | Out-Null
$lawId = az monitor log-analytics workspace show @subArgs -g $rg -n $law --query customerId -o tsv --only-show-errors
if (-not "$lawId".Trim()) {
    throw ("the Log Analytics workspace '$law' was NOT created in '$rg' -- see the failure printed " +
           "immediately above. The ACA environment cannot be created without a workspace, and " +
           "without THIS one it would silently generate its own while '$law' sits empty and billing.")
}
Write-Host "    $law ($lawId)"

# ---- 5. container registry --------------------------------------------------
Write-Host "[5] container registry ..." -ForegroundColor Yellow
$acrExisting = az acr show @subArgs -g $rg -n $acr --query sku.name -o tsv --only-show-errors 2>$null
if ("$acrExisting".Trim()) {
    Write-Host "    reusing existing registry ($acrExisting)"
    # Upgrade only ever UPWARDS, and only when asked. A downgrade would silently drop private
    # endpoints and firewall rules -- turning a locked-down registry public without saying so.
    $rank = @{ Basic = 1; Standard = 2; Premium = 3 }
    if ($rank[$AcrSku] -gt $rank["$acrExisting".Trim()]) {
        Write-Host "    upgrading $acrExisting -> $AcrSku"
        az acr update @subArgs -g $rg -n $acr --sku $AcrSku --only-show-errors -o none 2>$null | Out-Null
    } elseif ($rank[$AcrSku] -lt $rank["$acrExisting".Trim()]) {
        Write-Warning "    registry is $acrExisting and -AcrSku is $AcrSku -- NOT downgrading (that would drop private endpoints and firewall rules)."
    }
} else {
    $acrArgs = @('acr','create','-g',$rg,'-n',$acr,'--sku',$AcrSku,'-l',$Location)
    # Only pass the flag when the caller chose one: on a tenant with no such policy the ARM default
    # is correct, and passing it explicitly would be a change nobody asked for.
    if ($AcrPublicAccess -ne 'Default') { $acrArgs += @('--public-network-enabled', $AcrPublicAccess) }
    az @acrArgs @subArgs --only-show-errors -o none 2>$null | Out-Null
}
$acrLogin = az acr show @subArgs -g $rg -n $acr --query loginServer -o tsv --only-show-errors
$acrId    = az acr show @subArgs -g $rg -n $acr --query id -o tsv --only-show-errors
# 🔴 Same unverified-create class as the VNet above: a DENIED create left $acrId null, and the run
# carried on to the AcrPull role assignment and later to the image build before dying on a null --
# so the policy denial scrolled past and a null-reference crash was what the operator read.
if (-not "$acrId".Trim()) {
    $hint = if ($AcrSku -eq 'Basic') {
        "You created a BASIC registry. Basic and Standard registries have NO network controls at " +
        "all -- no private endpoint, no firewall rules -- so a 'Disable public network access - " +
        "Container registries' policy cannot be satisfied by one at any setting: it is asking for a " +
        "SKU, not a flag. Re-run with -AcrSku Premium -AcrPublicAccess false, or exempt that " +
        "assignment (a standing waiver -- the registry stays publicly reachable)."
    } else {
        "Re-read the denial above: the assignment names the field it evaluated, which may not match " +
        "its display name."
    }
    throw ("the container registry '$acr' ($AcrSku) was NOT created in '$rg' -- see the failure " +
           "printed immediately above. $hint Nothing downstream can build or pull an image without it.")
}
# 🪤 SAY IT BEFORE THE BUILD FAILS, NOT AFTER. ACR Tasks run inside ACR's own infrastructure, so a
# registry with public access off is unreachable from a host outside the VNet -- `az acr build`
# simply cannot start. Later updates are unaffected (the in-cloud update job runs INSIDE the
# environment); it is the FIRST build that needs reachability.
# ---- 5a. PRIVATE ENDPOINT for the registry, when it has no public access ------------------------
# Built HERE, in the same idempotent pass that creates the registry, because a registry with public
# access off and no private endpoint is not locked down -- it is unreachable, and the first symptom
# is every container app failing to pull.
if ($AcrPublicAccess -eq 'false') {
    Write-Host "[5a] private endpoint for $acr ..." -ForegroundColor Yellow
    $peSubnet = $PrivateEndpointSubnetName
    $peSubnetId = az network vnet subnet show @subArgs -g $rg --vnet-name $vnet -n $peSubnet --query id -o tsv --only-show-errors 2>$null
    if (-not "$peSubnetId".Trim()) {
        if (-not "$PrivateEndpointSubnetAddressPrefix".Trim()) {
            throw ("-AcrPublicAccess false needs a subnet for the private endpoint, and '$peSubnet' does " +
                   "not exist. The ACA subnet cannot be used: it is delegated to " +
                   "Microsoft.App/environments and a delegated subnet accepts nothing else. Pass " +
                   "-PrivateEndpointSubnetAddressPrefix <cidr inside $vnetCidr> (a /26 is plenty; each " +
                   "endpoint takes one address). Refusing to pick a range inside the customer's VNet.")
        }
        az network vnet subnet create @subArgs -g $rg --vnet-name $vnet -n $peSubnet `
            --address-prefixes $PrivateEndpointSubnetAddressPrefix --only-show-errors -o none 2>$null | Out-Null
        $peSubnetId = az network vnet subnet show @subArgs -g $rg --vnet-name $vnet -n $peSubnet --query id -o tsv --only-show-errors 2>$null
        if (-not "$peSubnetId".Trim()) { throw "could not create the private-endpoint subnet '$peSubnet' ($PrivateEndpointSubnetAddressPrefix) -- see the failure above." }
        Write-Host "    subnet $peSubnet $PrivateEndpointSubnetAddressPrefix"
    } else { Write-Host "    subnet $peSubnet (exists)" }

    $peName = "pe-$acr"
    $peId = az network private-endpoint show @subArgs -g $rg -n $peName --query id -o tsv --only-show-errors 2>$null
    if (-not "$peId".Trim()) {
        az network private-endpoint create @subArgs -g $rg -n $peName --vnet-name $vnet --subnet $peSubnet `
            --private-connection-resource-id $acrId --group-id registry --connection-name acr `
            --only-show-errors -o none 2>$null | Out-Null
        $peId = az network private-endpoint show @subArgs -g $rg -n $peName --query id -o tsv --only-show-errors 2>$null
        if (-not "$peId".Trim()) { throw "the private endpoint '$peName' was NOT created -- see the failure above. Without it '$acr' is unreachable." }
    }
    Write-Host "    $peName"

    # The zone lives in the customer's OWN resource group by default -- never in a shared hub RG,
    # which an operator may have no mandate to write into.
    $dnsRg = $(if ("$PrivateDnsResourceGroup".Trim()) { $PrivateDnsResourceGroup } else { $rg })
    az network private-dns zone create @subArgs -g $dnsRg -n 'privatelink.azurecr.io' --only-show-errors -o none 2>$null | Out-Null
    $zoneId = az network private-dns zone show @subArgs -g $dnsRg -n 'privatelink.azurecr.io' --query id -o tsv --only-show-errors 2>$null
    if (-not "$zoneId".Trim()) { throw "could not create the 'privatelink.azurecr.io' zone in '$dnsRg' -- the registry name will not resolve." }
    az network private-dns link vnet create @subArgs -g $dnsRg -z 'privatelink.azurecr.io' -n "link-$vnet" `
        --virtual-network $(az network vnet show @subArgs -g $rg -n $vnet --query id -o tsv --only-show-errors) `
        --registration-enabled false --only-show-errors -o none 2>$null | Out-Null
    # 🪤 BOTH records come from the zone group. Hand-built A records routinely miss
    # <name>.<region>.data.azurecr.io, which is where layers move -- giving a login that works and a
    # pull that hangs.
    az network private-endpoint dns-zone-group create @subArgs -g $rg --endpoint-name $peName -n zg `
        --private-dns-zone $zoneId --zone-name acr --only-show-errors -o none 2>$null | Out-Null
    $recs = @(az network private-dns record-set a list @subArgs -g $dnsRg -z 'privatelink.azurecr.io' --query "[].name" -o tsv --only-show-errors 2>$null)
    Write-Host ("    privatelink.azurecr.io in $dnsRg -- {0} record(s): {1}" -f $recs.Count, ($recs -join ', '))
    if ($recs.Count -lt 2) {
        Write-Warning ("    expected TWO records (the registry and its .data endpoint). Only $($recs.Count) " +
                       "present -- a pull will authenticate and then hang. Give the zone group a moment and re-run.")
    }
}

# ---- 5c. AGENT POOL so `az acr build` can run against a private registry ------------------------
# Without this, an internal-only registry can only be built from a host inside the VNet -- which
# makes the deploy depend on WHERE it is run from, and that is not reproducible.
if ("$AcrAgentPoolName".Trim()) {
    Write-Host "[5c] acr agent pool $AcrAgentPoolName ..." -ForegroundColor Yellow
    if ($AcrSku -ne 'Premium') { throw "-AcrAgentPoolName needs a Premium registry (this one is $AcrSku): agent pools are a Premium feature." }
    $poolState = az acr agentpool show @subArgs -r $acr -n $AcrAgentPoolName --query provisioningState -o tsv --only-show-errors 2>$null
    if (-not "$poolState".Trim()) {
        $poolSubnetId = az network vnet subnet show @subArgs -g $rg --vnet-name $vnet -n $PrivateEndpointSubnetName --query id -o tsv --only-show-errors 2>$null
        $poolArgs = @('acr','agentpool','create','-r',$acr,'-n',$AcrAgentPoolName,'--tier',$AcrAgentPoolTier,'--count',"$AcrAgentPoolCount")
        if ("$poolSubnetId".Trim()) { $poolArgs += @('--subnet-id', $poolSubnetId) }
        az @poolArgs @subArgs --only-show-errors -o none 2>$null | Out-Null
        $poolState = az acr agentpool show @subArgs -r $acr -n $AcrAgentPoolName --query provisioningState -o tsv --only-show-errors 2>$null
        if (-not "$poolState".Trim()) { throw "the ACR agent pool '$AcrAgentPoolName' was NOT created -- see the failure above. Without it 'az acr build' cannot reach a private registry." }
    }
    Write-Host "    $AcrAgentPoolName ($poolState) -- pass -AcrAgentPool $AcrAgentPoolName to the build"
}
Write-Host "    $acr ($acrLogin)"

# ---- 5b. pull identity for the container apps -------------------------------
# WHY A USER-ASSIGNED IDENTITY, created HERE rather than in Setup-PimContainers.
# A container app cannot pull its own first image with its SYSTEM-assigned identity: that
# identity does not exist until the app is created, so it cannot hold AcrPull at the moment
# the very first pull happens. Setup-PimContainers solved that with the registry's ADMIN
# username/password -- but this script never enabled the admin account, so those credentials
# came back EMPTY and step 6 could not create anything.
# A USER-assigned identity has neither problem: it exists before any app, so it can hold
# AcrPull up front, and it leaves NO standing registry credential behind (operator decision
# 2026-08-09, chosen over enabling the ACR admin account). The apps still get their OWN
# system-assigned identity for SQL + Graph -- this one is for the registry pull ONLY.
$uami = "id-pim-$Token"
Write-Host "[5b] pull identity ..." -ForegroundColor Yellow
az identity create @subArgs -g $rg -n $uami -l $Location --only-show-errors -o none 2>$null | Out-Null
$uamiId       = az identity show @subArgs -g $rg -n $uami --query id -o tsv --only-show-errors
$uamiPrincipal= az identity show @subArgs -g $rg -n $uami --query principalId -o tsv --only-show-errors
if (-not "$uamiId".Trim() -or -not "$uamiPrincipal".Trim()) {
    throw ("the pull identity '$uami' was NOT created in '$rg' -- see the failure printed immediately " +
           "above. Every container app pulls its image through this identity, so nothing can start " +
           "without it.")
}
# 🪤 AcrPull IS NOT OPTIONAL, AND ITS FAILURE IS SILENT. The guard used to be `if ($uamiPrincipal
# -and $acrId)` with the result discarded -- so a denied or unauthorised role assignment produced a
# perfectly green prereq, and the first symptom was every container app failing to pull its image
# with an authentication error pointing at the registry rather than at the missing grant.
$raOut = az role assignment create @subArgs --assignee-object-id $uamiPrincipal --assignee-principal-type ServicePrincipal `
            --role AcrPull --scope $acrId --only-show-errors -o none 2>&1
if ($LASTEXITCODE -ne 0 -and "$raOut" -notmatch 'already exists|RoleAssignmentExists') {
    throw ("could not grant AcrPull on '$acr' to '$uami': $raOut`n" +
           "Without it every container app fails to pull its image, and the error names the " +
           "registry rather than this grant.")
}
Write-Host "    $uami"
Write-Host "    $uamiId"

# ---- 6. SQL server + database, Entra-only ----------------------------------
# Skipped for hostingLocation=central-msp: an S5 managed tenant has NO store of its own, it
# uses the master's. Creating one here would quietly turn S5 into S6.
if ($SkipSql) {
    Write-Host "[6] sql ... SKIPPED (this environment uses a central store, by design)" -ForegroundColor DarkGray
} else {
    Write-Host "[6] sql server + database (Entra-only auth) ..." -ForegroundColor Yellow

    # ---- 6a. THE IDENTITY THAT ADMINISTERS SQL, AND WHY IT IS NOT THE DEPLOY SPN ----------------
    # 🔑 THE ENVIRONMENT MUST BE ABLE TO SET UP ITS OWN DATABASE, FROM INSIDE.
    # With publicNetworkAccess disabled (which a policy-restricted tenant requires, and which is
    # correct -- SQL needs no inbound path from the internet), a deploy host OUTSIDE the VNet has no
    # route to SQL at all. Making the deploy SPN the Entra admin therefore hands administration to
    # the one identity that cannot reach the server.
    #
    # A USER-ASSIGNED identity solves it the same way the pull identity solved the first-image
    # problem: it exists BEFORE any container app, so it can be the admin at server-creation time;
    # and it SURVIVES the app being deleted and recreated, unlike a system-assigned identity whose
    # principal is regenerated (measured 2026-09-11 -- that regeneration orphaned every contained
    # user and role assignment in a live environment).
    #
    # 🔒 SEPARATE FROM THE PULL IDENTITY, deliberately. id-pim-<token> holds AcrPull and nothing
    # else; this one administers a database. Collapsing them would mean anything that can pull an
    # image can also administer SQL -- the exact least-privilege split the operator asked for.
    # 🔴 INTERNAL AND EXTERNAL ARE DIFFERENT DESIGNS HERE, AND CONFLATING THEM BREAKS EXTERNAL.
    # An EXTERNAL environment's SQL server keeps a public endpoint, so the deploy host CAN reach it
    # -- and it is the deploy host that creates the contained users and applies the schema today.
    # Handing the Entra admin to a managed identity there would take that ability away from the one
    # identity that uses it, while the in-cloud replacement does not exist yet: every external
    # deploy would break at the store step.
    # The takeover therefore happens ONLY where the in-cloud path is the one being used -- i.e.
    # where SQL is private and no deploy host has a route to it.
    $sqlUami = $null; $sqlUamiId = $null; $sqlUamiOid = $null; $sqlUamiCid = $null
    $spOid  = if ($signedIn) { $signedIn.objectId } else { az ad sp show --id $AdminAppId --query id -o tsv --only-show-errors }
    $deployWho = if ($signedIn) { "(signed-in user $($signedIn.userName))" } else { "$AdminAppId" }
    # ---- 6a-group. 2026-09-15 -- converge the Entra admin onto the SQL ADMIN GROUP ---------------------
    # 🔑 A single-principal admin could administer the database alone; every other identity that must --
    # the unattended updater's schema step, the operator's troubleshooting identity -- needed a contained
    # user made by that one principal, and an environment whose admin could not be used unattended was
    # stuck (EFIF/RIDE refused every release for two nights). A group holding all of them is the model on
    # public AND private SQL. Converged AFTER the server exists (a group admin is not a create-time option
    # here) and read back; the previous admin is always kept as a member.
    # 🪤 Graph may refuse the deploy identity (a customer's least-privilege deploy identity holds no group
    # rights). That is NOT fatal: the single-principal admin of earlier versions stays, and the exact
    # command to converge later with a privileged identity is printed. Any OTHER failure stops the run --
    # a half-moved admin is not a state to build on.
    $sqlAdminGroupOk = $false
    $sqlAdminGroupSkipped = ''
    function Invoke-PimPrereqSqlAdminGroup {
        param([object[]]$ExtraMembers)
        if ($SkipSqlAdminGroup) { $script:sqlAdminGroupSkipped = '-SkipSqlAdminGroup'; return }
        Write-Host "    [6a] sql admin GROUP '$SqlAdminGroupName' ..." -ForegroundColor Yellow
        $inv = $null
        try { $inv = New-PimSqlAdminGroupInvokers -SubscriptionId $SubscriptionId -TenantId $TenantId }
        catch {
            $script:sqlAdminGroupSkipped = "no Graph/ARM token for the group step ($($_.Exception.Message))"
            Write-Warning "the SQL admin group step could not start: $($_.Exception.Message) -- the server keeps its current admin."
            return
        }
        $r = Invoke-PimSqlAdminGroupStep -Graph $inv.Graph -Arm $inv.Arm -TenantId $inv.TenantId -SubscriptionId $SubscriptionId `
                -ResourceGroup $rg -SqlServerName $sqlSrv -GroupName $SqlAdminGroupName -NoDiscovery -UpdateJobName 'ca-pim-update' `
                -TroubleshootingAppId $TroubleshootingAppId -ExtraMembers $ExtraMembers -Mode converge
        Write-PimSqlAdminGroupReport -Result $r -Indent '         '
        if ($r.ok) { $script:sqlAdminGroupOk = $true; return }
        if ($r.permissionDenied) {
            $script:sqlAdminGroupSkipped = 'the deploy identity was refused by Microsoft Graph'
            Write-Warning ("the SQL admin group could not be converged with this deploy identity -- the server keeps its current admin. " +
                           "Converge it with an identity that holds the Graph group rights: tools/setup/Initialize-PimSqlAdminGroup.ps1 " +
                           "-SubscriptionId $SubscriptionId -ResourceGroup $rg -SqlServerName $sqlSrv -TenantId $TenantId -ClientId <app id> -CertThumbprint <thumbprint>")
            return
        }
        throw ("the SQL admin group '$SqlAdminGroupName' was NOT converged on $sqlSrv -- see [FAIL] above. The Entra admin is left " +
               "as it was; fix the cause and re-run (every step is idempotent).")
    }
    if (-not $SqlPrivateEndpoint) {
        Write-Host "    [6a] sql admin: the DEPLOY SPN at create, then the SQL admin group (external/public SQL)" -ForegroundColor Yellow
        $spName = if ($signedIn) { $signedIn.userName } else { az ad sp show --id $AdminAppId --query displayName -o tsv --only-show-errors }
        $sqlId = az sql server show @subArgs -g $rg -n $sqlSrv --query id -o tsv --only-show-errors 2>$null
        if (-not $sqlId) {
            az sql server create @subArgs -g $rg -n $sqlSrv -l $Location `
                --enable-ad-only-auth --external-admin-principal-type $(if ($signedIn) { 'User' } else { 'Application' }) `
                --external-admin-name $spName --external-admin-sid $spOid --only-show-errors -o none
        }
        # The deploy identity stays able to administer the database through the group -- it is what
        # creates the contained users and applies the schema from this host on public SQL.
        Invoke-PimPrereqSqlAdminGroup -ExtraMembers @(
            [pscustomobject]@{ objectId = "$uamiPrincipal".Trim(); label = "environment identity $uami" }
            [pscustomobject]@{ objectId = "$spOid".Trim();         label = "deploy identity $deployWho" })
    } else {

    $sqlUami = "id-pim-sql-$Token"
    Write-Host "    [6a] sql admin identity $sqlUami (private SQL -- the environment administers itself)" -ForegroundColor Yellow
    az identity create @subArgs -g $rg -n $sqlUami -l $Location --only-show-errors -o none 2>$null | Out-Null
    $sqlUamiId   = az identity show @subArgs -g $rg -n $sqlUami --query id -o tsv --only-show-errors 2>$null
    $sqlUamiOid  = az identity show @subArgs -g $rg -n $sqlUami --query principalId -o tsv --only-show-errors 2>$null
    $sqlUamiCid  = az identity show @subArgs -g $rg -n $sqlUami --query clientId -o tsv --only-show-errors 2>$null
    if (-not "$sqlUamiOid".Trim() -or -not "$sqlUamiCid".Trim()) {
        throw ("the SQL admin identity '$sqlUami' was NOT created in '$rg' -- see the failure above. " +
               "Without it the environment cannot administer its own database and SQL would have to " +
               "be opened to the deploy host instead.")
    }
    Write-Host "         principal $sqlUamiOid  client $sqlUamiCid"

    $sqlId = az sql server show @subArgs -g $rg -n $sqlSrv --query id -o tsv --only-show-errors 2>$null
    if (-not $sqlId) {
        # 🪤 AZURE SQL ALLOWS EXACTLY ONE ENTRA ADMIN. Naming the identity here means the deploy SPN
        # is NOT an admin -- by design. Everything that administers this database runs inside the
        # VNet on this identity; nothing outside needs, or gets, a way in.
        az sql server create @subArgs -g $rg -n $sqlSrv -l $Location `
            --enable-ad-only-auth --external-admin-principal-type Application `
            --external-admin-name $sqlUami --external-admin-sid $sqlUamiOid --only-show-errors -o none
    }
    # The SQL identity MUST be a member: the in-cloud bootstrap job administers the database as it.
    Invoke-PimPrereqSqlAdminGroup -ExtraMembers @(
        [pscustomobject]@{ objectId = "$sqlUamiOid".Trim();    label = "SQL identity $sqlUami" }
        [pscustomobject]@{ objectId = "$uamiPrincipal".Trim(); label = "environment identity $uami" }
        [pscustomobject]@{ objectId = "$spOid".Trim();         label = "deploy identity $deployWho" })
    $adminNowSid   = "$(az sql server ad-admin list @subArgs -g $rg -s $sqlSrv --query "[0].sid" -o tsv --only-show-errors 2>$null)".Trim()
    $adminNowLogin = "$(az sql server ad-admin list @subArgs -g $rg -s $sqlSrv --query "[0].login" -o tsv --only-show-errors 2>$null)".Trim()
    if ($sqlAdminGroupOk) {
        Write-Host "         Entra admin verified: the SQL admin group '$SqlAdminGroupName' (holds $sqlUami)"
    } elseif ($adminNowLogin -and $adminNowLogin -ieq "$SqlAdminGroupName".Trim()) {
        # 🔴 NEVER MOVE A GROUP ADMIN BACK TO THE IDENTITY. The group was converged earlier (by a
        # privileged identity) and this run simply could not read its members -- moving the admin to the
        # UAMI here would remove the updater and the troubleshooting identity from the database.
        Write-Warning "         the Entra admin is the SQL admin group '$SqlAdminGroupName' -- kept; its members were NOT verified by this run ($sqlAdminGroupSkipped)."
    } else {
        # Legacy single-principal design (no group rights, or -SkipSqlAdminGroup): the SQL identity is the admin.
        if ($adminNowSid -ne "$sqlUamiOid".Trim()) {
            Write-Host "         moving the Entra admin to $sqlUami (was $adminNowSid)"
            az sql server ad-admin create @subArgs -g $rg -s $sqlSrv --display-name $sqlUami --object-id $sqlUamiOid --only-show-errors -o none 2>$null | Out-Null
            $adminNowSid = "$(az sql server ad-admin list @subArgs -g $rg -s $sqlSrv --query "[0].sid" -o tsv --only-show-errors 2>$null)".Trim()
        }
        if ($adminNowSid -ne "$sqlUamiOid".Trim()) {
            throw ("the SQL Entra admin is '$adminNowSid', not '$sqlUamiOid' ($sqlUami) or the SQL admin group. Nothing inside the " +
                   "environment could then create database users, and the deploy does not connect to SQL " +
                   "at all by design -- so this must be right before anything else runs.")
        }
        Write-Host "         Entra admin verified: $sqlUami (single-principal admin: $sqlAdminGroupSkipped)"
    }
    }   # end of the private-SQL branch
    az sql db create @subArgs -g $rg -s $sqlSrv -n $sqlDb --service-objective $SqlServiceObjective `
        --tags purpose=automateit estate=$Token --only-show-errors -o none 2>$null | Out-Null
    # ACA reaches SQL from inside the VNet; allow Azure services + this host for setup/tests.
    az sql server firewall-rule create @subArgs -g $rg -s $sqlSrv -n AllowAzureServices `
        --start-ip-address 0.0.0.0 --end-ip-address 0.0.0.0 --only-show-errors -o none 2>$null | Out-Null
    try {
        # IMP-49 t: say WHERE the address comes from. It used to ask a third-party web service
        # silently; an operator (or a customer's security review) is entitled to know that.
        $myIp = "$SetupHostIp".Trim()
        if ($myIp) { Write-Host "    setup host IP: $myIp (from -SetupHostIp; no external lookup)" }
        else {
            $myIp = "$((Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec 20).ip)".Trim()
            Write-Host "    setup host IP: $myIp -- read from https://api.ipify.org (a third-party service; pass -SetupHostIp to skip the lookup)"
        }
        if ($myIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw "not an IPv4 address: '$myIp'" }
        az sql server firewall-rule create @subArgs -g $rg -s $sqlSrv -n AllowSetupHost `
            --start-ip-address $myIp --end-ip-address $myIp --only-show-errors -o none 2>$null | Out-Null
        Write-Host ("    'AllowSetupHost' ($myIp) is the SETUP WINDOW for this deploy, not a standing grant: Invoke-PimDeployAll " +
                    "removes it at the end of its run. Standalone, remove it when done: az sql server firewall-rule delete " +
                    "--subscription $SubscriptionId -g $rg -s $sqlSrv -n AllowSetupHost") -ForegroundColor DarkGray
    } catch { Write-Warning "    could not add a setup-host firewall rule: $($_.Exception.Message)" }
    # Applied on EVERY run, not just at create: the policy is a property of an existing server, and
    # an environment that was built before this parameter existed must be able to acquire it by
    # re-running the (idempotent) prereq step rather than by a remembered manual command.
    if ($SqlConnectionPolicy -ne 'Default') {
        $curPol = az sql server conn-policy show @subArgs -g $rg -s $sqlSrv --query connectionType -o tsv --only-show-errors 2>$null
        if ("$curPol".Trim() -ieq $SqlConnectionPolicy) {
            Write-Host "    connection policy already '$SqlConnectionPolicy'"
        } else {
            az sql server conn-policy update @subArgs -g $rg -s $sqlSrv --connection-type $SqlConnectionPolicy --only-show-errors -o none 2>$null | Out-Null
            # Read it back. A connection policy that silently failed to apply looks identical to one
            # that applied, right up until the first connection hangs behind a firewall.
            $newPol = az sql server conn-policy show @subArgs -g $rg -s $sqlSrv --query connectionType -o tsv --only-show-errors 2>$null
            if ("$newPol".Trim() -ieq $SqlConnectionPolicy) { Write-Host "    connection policy '$curPol' -> '$SqlConnectionPolicy'" }
            else { Write-Warning "    connection policy is still '$newPol', wanted '$SqlConnectionPolicy' -- behind a firewall that allows only 1433, connections will hang after authenticating." }
        }
    }
    # ---- 6b. PRIVATE ENDPOINT FOR SQL ----------------------------------------------------------
    # 🔑 SQL IS PaaS -- IT IS NOT IN THE VNET. Turning publicNetworkAccess off does not make it
    # reachable privately; it makes it reachable from NOWHERE until an endpoint exists. This is what
    # gives the container apps a path to their own database with nothing public anywhere.
    # Same shape as the ACR endpoint above, including the DNS zone group: the zone must carry the
    # record the client actually resolves, and a hand-built A record is how that gets missed.
    if ($SqlPrivateEndpoint) {
        Write-Host "    [6b] private endpoint for $sqlSrv ..." -ForegroundColor Yellow
        $peSubnet = $PrivateEndpointSubnetName
        $peSubnetId = az network vnet subnet show @subArgs -g $rg --vnet-name $vnet -n $peSubnet --query id -o tsv --only-show-errors 2>$null
        if (-not "$peSubnetId".Trim()) {
            if (-not "$PrivateEndpointSubnetAddressPrefix".Trim()) {
                throw ("-SqlPrivateEndpoint needs a subnet for it, and '$peSubnet' does not exist. The ACA " +
                       "subnet cannot be used (delegated to Microsoft.App/environments). Pass " +
                       "-PrivateEndpointSubnetAddressPrefix <cidr inside $vnetCidr>.")
            }
            az network vnet subnet create @subArgs -g $rg --vnet-name $vnet -n $peSubnet `
                --address-prefixes $PrivateEndpointSubnetAddressPrefix --only-show-errors -o none 2>$null | Out-Null
            $peSubnetId = az network vnet subnet show @subArgs -g $rg --vnet-name $vnet -n $peSubnet --query id -o tsv --only-show-errors 2>$null
            if (-not "$peSubnetId".Trim()) { throw "could not create the private-endpoint subnet '$peSubnet'." }
        }
        $sqlSrvId = az sql server show @subArgs -g $rg -n $sqlSrv --query id -o tsv --only-show-errors 2>$null
        $peName = "pe-$sqlSrv"
        $peId = az network private-endpoint show @subArgs -g $rg -n $peName --query id -o tsv --only-show-errors 2>$null
        if (-not "$peId".Trim()) {
            az network private-endpoint create @subArgs -g $rg -n $peName --vnet-name $vnet --subnet $peSubnet `
                --private-connection-resource-id $sqlSrvId --group-id sqlServer --connection-name sql `
                --only-show-errors -o none 2>$null | Out-Null
            $peId = az network private-endpoint show @subArgs -g $rg -n $peName --query id -o tsv --only-show-errors 2>$null
            if (-not "$peId".Trim()) { throw "the private endpoint '$peName' was NOT created -- see the failure above. Without it '$sqlSrv' is reachable from nowhere." }
        }
        $dnsRg2 = $(if ("$PrivateDnsResourceGroup".Trim()) { $PrivateDnsResourceGroup } else { $rg })
        az network private-dns zone create @subArgs -g $dnsRg2 -n 'privatelink.database.windows.net' --only-show-errors -o none 2>$null | Out-Null
        $zoneId2 = az network private-dns zone show @subArgs -g $dnsRg2 -n 'privatelink.database.windows.net' --query id -o tsv --only-show-errors 2>$null
        if (-not "$zoneId2".Trim()) { throw "could not create the 'privatelink.database.windows.net' zone in '$dnsRg2' -- the server name will not resolve." }
        az network private-dns link vnet create @subArgs -g $dnsRg2 -z 'privatelink.database.windows.net' -n "link-$vnet" `
            --virtual-network (az network vnet show @subArgs -g $rg -n $vnet --query id -o tsv --only-show-errors) `
            --registration-enabled false --only-show-errors -o none 2>$null | Out-Null
        az network private-endpoint dns-zone-group create @subArgs -g $rg --endpoint-name $peName -n zg `
            --private-dns-zone $zoneId2 --zone-name sql --only-show-errors -o none 2>$null | Out-Null
        $recs2 = @(az network private-dns record-set a list @subArgs -g $dnsRg2 -z 'privatelink.database.windows.net' --query "[].name" -o tsv --only-show-errors 2>$null)
        Write-Host ("         privatelink.database.windows.net in $dnsRg2 -- {0} record(s): {1}" -f $recs2.Count, ($recs2 -join ', '))
        if (-not $recs2.Count) { Write-Warning "         no A record yet -- the zone group may still be settling; re-run to confirm." }
    }

    $fqdn = az sql server show @subArgs -g $rg -n $sqlSrv --query fullyQualifiedDomainName -o tsv --only-show-errors
    Write-Host "    $sqlSrv / $sqlDb ($fqdn)"
    if ($sqlUami) {
        Write-Host "    sql admin identity : $sqlUami (client $sqlUamiCid) -- the environment administers its own database" -ForegroundColor Green
        # HAND IT TO THE CALLER. Setup-PimContainers needs the resource id (to attach the identity
        # to the bootstrap job) and the client id (so the job asks IMDS for THIS identity rather
        # than the system one, which has no database rights). Published rather than re-derived, so
        # the two halves cannot disagree about which identity administers the database.
        $global:PIM_SqlAdminIdentityResourceId = $sqlUamiId
        $global:PIM_SqlAdminIdentityClientId   = $sqlUamiCid
    }
}

# ---- 7. VERIFY by reading back, never by trusting the create calls ----------
Write-Host ""
Write-Host "=== VERIFY ===" -ForegroundColor Cyan
$ok = $true
function Chk($label, $cond, $detail) {
    if ($cond) { Write-Host ("  {0,-22}: {1}" -f $label, $detail) }
    else { Write-Host ("  {0,-22}: MISSING" -f $label) -ForegroundColor Red; $script:ok = $false }
}
$vnetOk   = az network vnet show @subArgs -g $rg -n $vnet --query addressSpace.addressPrefixes[0] -o tsv --only-show-errors 2>$null
$snOk     = az network vnet subnet show @subArgs -g $rg --vnet-name $vnet -n $subnet --query delegations[0].serviceName -o tsv --only-show-errors 2>$null
$lawOk    = az monitor log-analytics workspace show @subArgs -g $rg -n $law --query customerId -o tsv --only-show-errors 2>$null
$acrOk    = az acr show @subArgs -g $rg -n $acr --query loginServer -o tsv --only-show-errors 2>$null
Chk 'vnet'          ([bool]$vnetOk) $vnetOk
Chk 'aca subnet'    ($snOk -eq 'Microsoft.App/environments') "$subnetCidr delegated to $snOk"
Chk 'log analytics' ([bool]$lawOk)  $law
Chk 'acr'           ([bool]$acrOk)  $acrOk
# Verify the ROLE, not just the identity: an identity without AcrPull looks identical to a
# working one right up until the first image pull fails.
$uamiOk = az identity show @subArgs -g $rg -n $uami --query id -o tsv --only-show-errors 2>$null
$pullOk = $null
if ($uamiPrincipal -and $acrId) {
    $pullOk = az role assignment list @subArgs --assignee $uamiPrincipal --scope $acrId --role AcrPull `
                  --query "[0].roleDefinitionName" -o tsv --only-show-errors 2>$null
}
Chk 'pull identity'  ([bool]$uamiOk) $uami
Chk 'acrpull grant'  ($pullOk -eq 'AcrPull') "$uami -> AcrPull on $acr"
if (-not $SkipSql) {
    $dbOk = az sql db show @subArgs -g $rg -s $sqlSrv -n $sqlDb --query status -o tsv --only-show-errors 2>$null
    Chk 'sql database' ($dbOk -eq 'Online') "$sqlSrv/$sqlDb ($dbOk)"
    $adminLoginNow = "$(az sql server ad-admin list @subArgs -g $rg -s $sqlSrv --query "[0].login" -o tsv --only-show-errors 2>$null)".Trim()
    Chk 'sql entra admin' ([bool]$adminLoginNow) $(if ($sqlAdminGroupOk) { "$adminLoginNow (SQL admin group, members read back)" } else { "$adminLoginNow (single-principal admin: $sqlAdminGroupSkipped)" })

    # 🔴 A DATABASE THAT IS "Online" IS NOT A DATABASE THIS HOST CAN REACH, and until now nothing
    # here noticed the difference. The two firewall-rule creates above swallow their errors, and
    # VERIFY only asked whether the database existed -- so on a policy-restricted tenant the server
    # came up with publicNetworkAccess=Disabled, BOTH rules were denied, and prereq still printed
    # "RESULT: OK -- ready for Setup-PimContainers". The deploy then failed two steps later, in
    # Grant-PimMiSql, with "Connection was denied because Deny Public Network Access is set to Yes"
    # -- a long way from the cause. Measured at a live customer 2026-09-08.
    # Reported, NOT failed: a deploy host INSIDE the VNet (private endpoint) is a legitimate and
    # policy-preferred topology, and prereq cannot tell from here whether this host is in it. So say
    # precisely what will break and how to fix it, and let the operator decide.
    # BUG-215: --subscription on both (the only two calls in this script that relied on the default).
    $pna     = "$(az sql server show @subArgs -g $rg -n $sqlSrv --query publicNetworkAccess -o tsv --only-show-errors 2>$null)".Trim()
    $fwSetup = "$(az sql server firewall-rule show @subArgs -g $rg -s $sqlSrv -n AllowSetupHost --query name -o tsv --only-show-errors 2>$null)".Trim()
    if ($pna -eq 'Disabled') {
        Write-Host ("  {0,-22}: PUBLIC ACCESS DISABLED" -f 'sql reachability') -ForegroundColor Yellow
        Write-Warning ("SQL server '$sqlSrv' has publicNetworkAccess=Disabled, so THIS host cannot reach it. " +
                       "The next steps (contained users, schema) will fail with 'Deny Public Network Access is set to Yes'. " +
                       "Either run the deploy from inside the VNet, or enable it: " +
                       "az sql server update --subscription $SubscriptionId -g $rg -n $sqlSrv --enable-public-network true " +
                       "(a Deny policy on Microsoft.Sql/servers/publicNetworkAccess must be exempted first -- and note the " +
                       "assignment governing it may be DISPLAYED as a 'SQL Databases' policy).")
    }
    elseif (-not $fwSetup) {
        Write-Host ("  {0,-22}: NO AllowSetupHost RULE" -f 'sql reachability') -ForegroundColor Yellow
        Write-Warning ("public access is $pna but the AllowSetupHost firewall rule is missing -- its create was " +
                       "denied or failed. This host will be refused at the contained-user and schema steps. Add it: " +
                       "az sql server firewall-rule create --subscription $SubscriptionId -g $rg -s $sqlSrv -n AllowSetupHost " +
                       "--start-ip-address <this host> --end-ip-address <this host>")
    }
    else {
        Write-Host ("  {0,-22}: public access {1} + AllowSetupHost present" -f 'sql reachability', $pna)
    }
}
Write-Host ""
if ($ok) { Write-Host "RESULT: OK -- $Token is ready for Setup-PimContainers" -ForegroundColor Green; exit 0 }
else     { Write-Host "RESULT: FAILED" -ForegroundColor Red; exit 1 }
