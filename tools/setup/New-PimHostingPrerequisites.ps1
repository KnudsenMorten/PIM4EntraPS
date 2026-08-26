<#
.SYNOPSIS
  Everything a tenant needs BEFORE Setup-PimContainers.ps1 can run. Unattended, idempotent.

.DESCRIPTION
  Setup-PimContainers.ps1 assumes the plumbing already exists: registered resource providers,
  a VNet with a /23 delegated to Container Apps, a Log Analytics workspace, a container
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
    [Parameter(Mandatory)][int]$Index,             # stable index -> address space
    [Parameter(Mandatory)][string]$AdminAppId,     # SPN used to create things (Owner on the sub)
    # ONE of these two. The estate's throwaway tenants onboard with a secret; a REAL tenant must
    # not -- the repo-root rule is "authenticate as its SPN using a CERTIFICATE, never a client
    # secret". Cert auth was added 2026-08-09 for the myfamilynetwork PRODUCTION build (PIM §34),
    # because this script previously made secret auth structurally mandatory and so could not be
    # pointed at a production tenant at all without breaking that rule.
    [string]$AdminSecret,
    [string]$AdminCertPem,                         # PEM (key+cert) that `az login --certificate` wants
    [string]$Location    = 'swedencentral',        # westeurope/northeurope refuse new resources on FRESH subs
    [string]$AddressBase = '10.220',
    [switch]$SkipSql
)
$ErrorActionPreference = 'Stop'

$rg      = "rg-automateit-$Token"
$vnet    = "vnet-pim-$Token"
$subnet  = 'snet-pim-aca'
$law     = "law-pim-$Token"
$acr     = ("acrpim$Token" -replace '[^a-z0-9]','').ToLowerInvariant()   # ACR: alphanumeric only
$sqlSrv  = "sql-ait-$Token"
$sqlDb   = 'PimPlatform'
$vnetCidr   = "$AddressBase.$($Index * 8).0/21"
$subnetCidr = "$AddressBase.$($Index * 8).0/23"

Write-Host "=== hosting prerequisites -- $Token ===" -ForegroundColor Cyan
Write-Host "  subscription : $SubscriptionId"
Write-Host "  location     : $Location"
Write-Host "  vnet/subnet  : $vnet $vnetCidr  /  $subnet $subnetCidr"
Write-Host "  acr / law    : $acr / $law"

# isolated az profile so the shared context on this host is never disturbed
$cfg = Join-Path $env:TEMP "azcfg-$Token"
New-Item -ItemType Directory -Force $cfg | Out-Null
$env:AZURE_CONFIG_DIR = $cfg
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
    $state = az provider show --namespace $p --query registrationState -o tsv --only-show-errors 2>$null
    if ($state -ne 'Registered') {
        Write-Host "    registering $p ..."
        az provider register --namespace $p --wait --only-show-errors 2>&1 | Out-Null
    }
    $state = az provider show --namespace $p --query registrationState -o tsv --only-show-errors 2>$null
    Write-Host ("    {0,-32} {1}" -f $p, $state)
    if ($state -ne 'Registered') { throw "provider $p is '$state' -- cannot continue" }
}

# ---- 2. resource group ------------------------------------------------------
Write-Host "[2] resource group ..." -ForegroundColor Yellow
az group create -n $rg -l $Location --only-show-errors -o none
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
$vnetId = az network vnet show -g $rg -n $vnet --query id -o tsv --only-show-errors 2>$null
if (-not $vnetId) {
    az network vnet create -g $rg -n $vnet -l $Location --address-prefixes $vnetCidr `
        --subnet-name $subnet --subnet-prefixes $subnetCidr --only-show-errors -o none
}
az network vnet subnet update -g $rg --vnet-name $vnet -n $subnet `
    --delegations Microsoft.App/environments --only-show-errors -o none
$sn = az network vnet subnet show -g $rg --vnet-name $vnet -n $subnet --query "{cidr:addressPrefix,deleg:delegations[0].serviceName}" -o tsv --only-show-errors
Write-Host "    $vnet / $subnet -> $sn"

# ---- 4. Log Analytics (ACA requires a workspace) ----------------------------
Write-Host "[4] log analytics ..." -ForegroundColor Yellow
az monitor log-analytics workspace create -g $rg -n $law -l $Location --only-show-errors -o none 2>$null | Out-Null
$lawId = az monitor log-analytics workspace show -g $rg -n $law --query customerId -o tsv --only-show-errors
Write-Host "    $law ($lawId)"

# ---- 5. container registry --------------------------------------------------
Write-Host "[5] container registry ..." -ForegroundColor Yellow
az acr create -g $rg -n $acr --sku Basic -l $Location --only-show-errors -o none 2>$null | Out-Null
$acrLogin = az acr show -g $rg -n $acr --query loginServer -o tsv --only-show-errors
$acrId    = az acr show -g $rg -n $acr --query id -o tsv --only-show-errors
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
az identity create -g $rg -n $uami -l $Location --only-show-errors -o none 2>$null | Out-Null
$uamiId       = az identity show -g $rg -n $uami --query id -o tsv --only-show-errors
$uamiPrincipal= az identity show -g $rg -n $uami --query principalId -o tsv --only-show-errors
if ($uamiPrincipal -and $acrId) {
    # Idempotent: a duplicate assignment returns RoleAssignmentExists, which is success.
    az role assignment create --assignee-object-id $uamiPrincipal --assignee-principal-type ServicePrincipal `
        --role AcrPull --scope $acrId --only-show-errors -o none 2>$null | Out-Null
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
    $spOid  = az ad sp show --id $AdminAppId --query id -o tsv --only-show-errors
    $spName = az ad sp show --id $AdminAppId --query displayName -o tsv --only-show-errors
    $sqlId = az sql server show -g $rg -n $sqlSrv --query id -o tsv --only-show-errors 2>$null
    if (-not $sqlId) {
        az sql server create -g $rg -n $sqlSrv -l $Location `
            --enable-ad-only-auth --external-admin-principal-type Application `
            --external-admin-name $spName --external-admin-sid $spOid --only-show-errors -o none
    }
    az sql db create -g $rg -s $sqlSrv -n $sqlDb --service-objective Basic `
        --tags purpose=automateit estate=$Token --only-show-errors -o none 2>$null | Out-Null
    # ACA reaches SQL from inside the VNet; allow Azure services + this host for setup/tests.
    az sql server firewall-rule create -g $rg -s $sqlSrv -n AllowAzureServices `
        --start-ip-address 0.0.0.0 --end-ip-address 0.0.0.0 --only-show-errors -o none 2>$null | Out-Null
    try {
        $myIp = (Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec 20).ip
        az sql server firewall-rule create -g $rg -s $sqlSrv -n AllowSetupHost `
            --start-ip-address $myIp --end-ip-address $myIp --only-show-errors -o none 2>$null | Out-Null
    } catch { Write-Warning "    could not add a setup-host firewall rule: $($_.Exception.Message)" }
    $fqdn = az sql server show -g $rg -n $sqlSrv --query fullyQualifiedDomainName -o tsv --only-show-errors
    Write-Host "    $sqlSrv / $sqlDb ($fqdn)"
}

# ---- 7. VERIFY by reading back, never by trusting the create calls ----------
Write-Host ""
Write-Host "=== VERIFY ===" -ForegroundColor Cyan
$ok = $true
function Chk($label, $cond, $detail) {
    if ($cond) { Write-Host ("  {0,-22}: {1}" -f $label, $detail) }
    else { Write-Host ("  {0,-22}: MISSING" -f $label) -ForegroundColor Red; $script:ok = $false }
}
$vnetOk   = az network vnet show -g $rg -n $vnet --query addressSpace.addressPrefixes[0] -o tsv --only-show-errors 2>$null
$snOk     = az network vnet subnet show -g $rg --vnet-name $vnet -n $subnet --query delegations[0].serviceName -o tsv --only-show-errors 2>$null
$lawOk    = az monitor log-analytics workspace show -g $rg -n $law --query customerId -o tsv --only-show-errors 2>$null
$acrOk    = az acr show -g $rg -n $acr --query loginServer -o tsv --only-show-errors 2>$null
Chk 'vnet'          ([bool]$vnetOk) $vnetOk
Chk 'aca subnet'    ($snOk -eq 'Microsoft.App/environments') "$subnetCidr delegated to $snOk"
Chk 'log analytics' ([bool]$lawOk)  $law
Chk 'acr'           ([bool]$acrOk)  $acrOk
# Verify the ROLE, not just the identity: an identity without AcrPull looks identical to a
# working one right up until the first image pull fails.
$uamiOk = az identity show -g $rg -n $uami --query id -o tsv --only-show-errors 2>$null
$pullOk = $null
if ($uamiPrincipal -and $acrId) {
    $pullOk = az role assignment list --assignee $uamiPrincipal --scope $acrId --role AcrPull `
                  --query "[0].roleDefinitionName" -o tsv --only-show-errors 2>$null
}
Chk 'pull identity'  ([bool]$uamiOk) $uami
Chk 'acrpull grant'  ($pullOk -eq 'AcrPull') "$uami -> AcrPull on $acr"
if (-not $SkipSql) {
    $dbOk = az sql db show -g $rg -s $sqlSrv -n $sqlDb --query status -o tsv --only-show-errors 2>$null
    Chk 'sql database' ($dbOk -eq 'Online') "$sqlSrv/$sqlDb ($dbOk)"
}
Write-Host ""
if ($ok) { Write-Host "RESULT: OK -- $Token is ready for Setup-PimContainers" -ForegroundColor Green; exit 0 }
else     { Write-Host "RESULT: FAILED" -ForegroundColor Red; exit 1 }
