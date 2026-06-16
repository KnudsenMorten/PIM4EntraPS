#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS — hosted container deployment (Azure Container Apps), config-driven.

.DESCRIPTION
    Stands up the whole PIM platform as containers on an INTERNAL Azure Container
    Apps environment in a spoke VNet peered to the connectivity hub. Codifies every
    hard-won lesson from the build-out so it is repeatable per tenant (internal or MSP):

      * Internal, workload-profile ACA environment in a DELEGATED subnet
        (Microsoft.App/environments). Workload-profile is required for the env
        Private Endpoint option and is the robust ingress stack.
      * The web Manager uses **--ingress external** which, on an internal-only env,
        is **VNet-private (no public IP)** and is the ONLY ingress reachable from
        peered/hub VNet clients (MGMT/DC/GSA). `--ingress internal` is env-internal
        ONLY (app-to-app) and is NOT reachable from VNet clients — that one setting
        was the multi-hour gotcha.
      * Worker containers run the SAME image with $env:PIM_SCHED_JOBS selecting which
        job types each runs — so you deploy as many/few workers as you want
        (all-in-one, or split engine / connector / delta-queue / discovery).
      * SQL is **MI-only** (no secret, no SQL user/pwd). Each app's system MI is added
        as a contained DB user via an explicit SID **derived from the MI's appId**
        (NOT objectId — the managed-identity gotcha) using TYPE=E, so the SQL server
        needs no Directory-Reader identity.
      * ACR pull switches to the app MI (AcrPull) after first create.
      * DNS: the app's external FQDN drops ".internal"; this registers it on the
        on-prem/AD DNS server so hub clients resolve it to the env static IP.

.PARAMETER WhatIf
    Print the plan without creating anything.

.NOTES
    Re-runnable. Existing resources are reused/updated. Requires: az CLI logged in to
    the target tenant/subscription; the SQL AAD-admin SPN creds (to mint the contained
    DB users); the DnsServer RSAT module (for the AD DNS records).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # --- target subscription / tenant (no real ids baked in; pass your own) ---
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$TenantId,
    [string]$Location       = 'westeurope',            # West Europe / Denmark East only (never France)

    # --- resource group + networking (spoke VNet peered to hub) ---
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$VnetName,
    [Parameter(Mandatory)][string]$VnetResourceGroup,
    [string]$SubnetName     = 'snet-pim-aca',
    [string]$SubnetPrefix   = '10.100.40.0/23',           # /23 dedicated, delegated to ACA
    [string]$EnvName        = 'cae-pim',

    # --- container registry + image ---
    [Parameter(Mandatory)][string]$AcrName,
    [string]$ImageRepo      = 'pim-manager',
    [Parameter(Mandatory)][string]$ImageTag,

    # --- SQL (MI-only) ---
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase    = 'PimPlatform',
    # SQL AAD-admin SPN (used ONLY here to CREATE the contained MI users; never stored in apps)
    [Parameter(Mandatory)][string]$SqlAdminClientId,
    [Parameter(Mandatory)][string]$SqlAdminClientSecret,

    # --- on-prem/AD DNS (hub clients resolve the env FQDN here); blank = skip ---
    [string]$DnsServer      = '',
    # --- persistent-SQL enforcement (REQUIREMENTS S5): disable serverless auto-pause ---
    [string]$SqlResourceGroup,                            # RG of the SQL server (for auto-pause assert)
    [switch]$SkipPersistentSqlCheck,

    # --- the worker matrix: deploy as many/few as you want -------------------
    # Each entry: name, ingress ('external'=VNet-private web | 'none'=worker),
    # entry ('manager' | 'scheduler'), jobs (PIM_SCHED_JOBS for scheduler workers).
    [object[]]$Workers = @(
        @{ name = 'ca-pim-manager';    ingress = 'external'; entry = 'manager';   jobs = '' }
        @{ name = 'ca-pim-scheduler';  ingress = 'none';     entry = 'scheduler'; jobs = 'queue-apply,reminders,escalations' }
        @{ name = 'ca-pim-engine';     ingress = 'none';     entry = 'scheduler'; jobs = 'engine-delta,engine-full' }
        @{ name = 'ca-pim-connector';  ingress = 'none';     entry = 'scheduler'; jobs = 'connector-sync' }
        @{ name = 'ca-pim-deltaqueue'; ingress = 'none';     entry = 'scheduler'; jobs = 'delta-queue' }
        @{ name = 'ca-pim-discovery';  ingress = 'none';     entry = 'scheduler'; jobs = 'discovery-entra,discovery-azure,discovery-powerbi' }
    )
)

$ErrorActionPreference = 'Stop'
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m){ Write-Host "    $m" -ForegroundColor DarkGray }
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)   # ...\PIM4EntraPS

# Shared setup helpers (banner, region guard, Grant-PimMiSql/Graph, DNS, GSA guidance,
# Set-PimSqlNoAutoPause) + the engine REST/SQL cores the SQL grant needs.
. "$here\_PimSetupShared.ps1"
. "$solRoot\engine\_shared\PIM-Rest.ps1"
. "$solRoot\engine\_shared\PIM-SqlStore.ps1"

Show-PimSetupBanner -ScriptName 'Setup-PimContainers' -SolutionRoot $solRoot
$Location = Assert-PimSetupRegion -Location $Location   # West Europe / Denmark East only; refuse France

$image = "$AcrName.azurecr.io/$ImageRepo`:$ImageTag"
$subnetId = "/subscriptions/$SubscriptionId/resourceGroups/$VnetResourceGroup/providers/Microsoft.Network/virtualNetworks/$VnetName/subnets/$SubnetName"

Step "Target: sub $SubscriptionId / RG $ResourceGroup / env $EnvName / $Location"
Note "image=$image  subnet=$SubnetName ($SubnetPrefix)  sql=$SqlServerFqdn/$SqlDatabase"
Note ("workers: " + (($Workers | ForEach-Object { $_.name }) -join ', '))
if ($WhatIfPreference) { Note 'WhatIf — plan only, nothing created.'; }

az account set --subscription $SubscriptionId 2>$null | Out-Null

Step 'Register resource providers (idempotent)'
if ($PSCmdlet.ShouldProcess('Microsoft.App / Microsoft.OperationalInsights','register')) {
    az provider register -n Microsoft.App --wait 2>$null | Out-Null
    az provider register -n Microsoft.OperationalInsights --wait 2>$null | Out-Null
}

Step "Subnet $SubnetName delegated to Microsoft.App/environments"
if ($PSCmdlet.ShouldProcess($SubnetName,'create/delegate')) {
    $exists = az network vnet subnet show -g $VnetResourceGroup --vnet-name $VnetName -n $SubnetName --query name -o tsv 2>$null
    if (-not $exists) {
        az network vnet subnet create -g $VnetResourceGroup --vnet-name $VnetName -n $SubnetName `
            --address-prefixes $SubnetPrefix --delegations Microsoft.App/environments -o none
    } else { Note 'subnet exists' }
}

Step "ACA environment $EnvName (internal, workload-profile)"
if ($PSCmdlet.ShouldProcess($EnvName,'create')) {
    $exists = az containerapp env show -g $ResourceGroup -n $EnvName --query name -o tsv 2>$null
    if (-not $exists) {
        az containerapp env create -g $ResourceGroup -n $EnvName --location $Location `
            --infrastructure-subnet-resource-id $subnetId --internal-only true `
            --enable-workload-profiles --logs-destination log-analytics -o none
    } else { Note 'env exists' }
}
$envStatic = az containerapp env show -g $ResourceGroup -n $EnvName --query properties.staticIp -o tsv 2>$null
$envDomain = az containerapp env show -g $ResourceGroup -n $EnvName --query properties.defaultDomain -o tsv 2>$null
Note "env static IP = $envStatic   domain = $envDomain"

$acrU = az acr credential show -n $AcrName --query username -o tsv 2>$null
$acrP = az acr credential show -n $AcrName --query "passwords[0].value" -o tsv 2>$null
$acrId = az acr show -n $AcrName --query id -o tsv 2>$null

# SQL contained-DB-user + Graph app-role grants come from _PimSetupShared.ps1
# (Grant-PimMiSql / Grant-PimMiGraph). A thin local wrapper binds this script's
# SQL coordinates so the worker loop call stays a one-liner.
function Grant-PimMiSqlHere {
    param([string]$DbUserName,[string]$MiAppId)
    Grant-PimMiSql -DbUserName $DbUserName -MiAppId $MiAppId `
        -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId `
        -SqlAdminClientId $SqlAdminClientId -SqlAdminClientSecret $SqlAdminClientSecret
}

$commonEnv = @(
    "PIM_HOSTED=1","PIM_StorageBackend=sql",
    "PIM_SqlServer=$SqlServerFqdn","PIM_SqlDatabase=$SqlDatabase","PIM_TenantId=$TenantId"
)

foreach ($w in $Workers) {
    Step "Worker '$($w.name)'  entry=$($w.entry)  ingress=$($w.ingress)  jobs='$($w.jobs)'"
    if (-not $PSCmdlet.ShouldProcess($w.name,'deploy')) { continue }

    $envVars = @($commonEnv)
    if ($w.entry -eq 'scheduler' -and "$($w.jobs)".Trim()) { $envVars += "PIM_SCHED_JOBS=$($w.jobs)" }

    # create or update
    $exists = az containerapp show -g $ResourceGroup -n $w.name --query name -o tsv 2>$null
    if (-not $exists) {
        if ($w.entry -eq 'manager') {
            az containerapp create -g $ResourceGroup -n $w.name --environment $EnvName --workload-profile-name Consumption `
                --image $image --registry-server "$AcrName.azurecr.io" --registry-username $acrU --registry-password $acrP `
                --ingress external --target-port 8080 --transport http --min-replicas 1 --max-replicas 1 --system-assigned `
                --env-vars $envVars -o none
        } else {
            # worker via YAML (reliable command/args array) — same image, scheduler entrypoint
            $envId = az containerapp env show -g $ResourceGroup -n $EnvName --query id -o tsv 2>$null
            $envYaml = ($envVars | ForEach-Object { $kv=$_ -split '=',2; "          - { name: $($kv[0]), value: `"$($kv[1])`" }" }) -join "`n"
            $y = @"
location: $Location
identity: { type: SystemAssigned }
properties:
  environmentId: $envId
  workloadProfileName: Consumption
  configuration:
    activeRevisionsMode: Single
    secrets: [ { name: acr-pwd, value: "$acrP" } ]
    registries: [ { server: $AcrName.azurecr.io, username: $acrU, passwordSecretRef: acr-pwd } ]
  template:
    containers:
      - name: $($w.name)
        image: $image
        command: [pwsh]
        args: ["-NoProfile","-File","/app/PIM4EntraPS/tools/pim-scheduler/Start-PimScheduler.ps1"]
        env:
$envYaml
        resources: { cpu: 0.5, memory: 1Gi }
    scale: { minReplicas: 1, maxReplicas: 1 }
"@
            $tmp = Join-Path $env:TEMP "pim-$($w.name).yaml"; Set-Content -LiteralPath $tmp -Value $y -Encoding utf8
            az containerapp create -g $ResourceGroup -n $w.name --yaml $tmp -o none
        }
    } else {
        az containerapp update -g $ResourceGroup -n $w.name --image $image -o none
        Note 'updated existing'
    }

    # MI -> SQL (SID from appId) + AcrPull + switch registry to MI
    $oid = az containerapp show -g $ResourceGroup -n $w.name --query identity.principalId -o tsv 2>$null
    $appId = az ad sp show --id $oid --query appId -o tsv 2>$null
    Grant-PimMiSqlHere -DbUserName $w.name -MiAppId $appId
    az role assignment create --assignee-object-id $oid --assignee-principal-type ServicePrincipal --role AcrPull --scope $acrId -o none 2>$null
    az containerapp registry set -g $ResourceGroup -n $w.name --server "$AcrName.azurecr.io" --identity system -o none 2>$null
    # Directory app-roles for workers that touch Entra/PIM (everything except a pure
    # read-only manager). Without these the engine 403s on directory reads/writes.
    Grant-PimMiGraph -MiObjectId $oid
    Note "MI $appId granted SQL (db user [$($w.name)]) + AcrPull + Graph app-roles"
}

# --- Persistent SQL compute (REQUIREMENTS S5: no auto-pause / cold starts) -----
# Assert/disable serverless auto-pause on the hosted Azure SQL so /health + the
# first post-idle request never cold-start. Needs the SQL server's RG + short name.
if (-not $SkipPersistentSqlCheck) {
    $sqlServerShort = ($SqlServerFqdn -split '\.')[0]
    $sqlRg = if ($SqlResourceGroup) { $SqlResourceGroup } else { $ResourceGroup }
    Step "SQL persistent compute: assert auto-pause disabled ($sqlServerShort/$SqlDatabase)"
    try { Set-PimSqlNoAutoPause -ResourceGroup $sqlRg -SqlServerName $sqlServerShort -SqlDatabase $SqlDatabase }
    catch { Write-Warning "  persistent-SQL assert skipped: $($_.Exception.Message)" }
}

# --- DNS: register the manager's external FQDN on the AD DNS server -----------
$mgr = $Workers | Where-Object { $_.entry -eq 'manager' } | Select-Object -First 1
$mgrFqdn = $null
if ($mgr) {
    $mgrFqdn = az containerapp ingress show -g $ResourceGroup -n $mgr.name --query fqdn -o tsv 2>$null
    if ($mgrFqdn -and $DnsServer) {
        Step "DNS: $mgrFqdn -> $envStatic on $DnsServer"
        Write-PimDnsRecord -DnsServer $DnsServer -Fqdn $mgrFqdn -EnvDomain $envDomain -StaticIp $envStatic
        Note "Manager URL: https://$mgrFqdn/"
    } elseif ($mgrFqdn) {
        Note "Manager FQDN: $mgrFqdn  (no -DnsServer given; register A '$mgrFqdn' -> $envStatic on your DNS manually)"
    }
}

Step 'Done.'
if ($mgrFqdn) {
    Write-Host "Verify from a hub/VNet client:  curl https://$mgrFqdn/   (expect 200; /api needs the page-embedded token)" -ForegroundColor Green
}
# GSA / Private Access + private-link / DNS guidance (which zones to add)
Show-PimGsaPrivateLinkGuidance -ManagerFqdn $mgrFqdn
