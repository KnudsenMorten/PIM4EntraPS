#Requires -Version 5.1
<#
.SYNOPSIS
    §31.3 CLOUD-NATIVE -- deploy the master->managed (slave) downlink as an Azure
    Container Apps scheduled JOB (cron), NOT a Windows scheduled task. Operator
    directive 2026-06-17: "all run in cloud only compute, in one test"; "run it
    through the containers in the slave".

.DESCRIPTION
    Creates/updates (idempotent) an `az containerapp job` of trigger-type Schedule
    with a configurable cron expression. On its cadence the Job runs the pim-manager
    image with the in-container entrypoint tools/pim-engine/downlink-job-entry.ps1,
    which pulls -> verifies -> stages -> applies the ring-gated downlink + the engine
    apply for the scenario. Everything runs on cloud container compute.

    Two placements (REQUIREMENTS §31.2 matrix):
      * S5 -> the Job runs in the CENTRAL ACA env (cae-pim, MSP tenant) and the
              MULTI-TENANT SPN / MI acts INTO the slave. The central env already
              exists (Setup-PimContainers).
      * S6 -> the Job runs in the SLAVE tenant's OWN ACA env using a LOCAL SPN / MI.
              That env must be stood up first (see -EnvName + the prereq note below).

    Private transport (§31.3 hard constraint): the Job runs on the INTERNAL,
    private-only ACA env. A scheduled Job is NOT an app -- it has NO ingress, so
    there is nothing public to expose. The signed-baseline pull + sync-file staging
    traverse the private cross-tenant VNet only. NO inline secret is ever emitted:
    identity is a Managed Identity (AcrPull + SQL contained user) or an SPN cert
    whose thumbprint/clientId are read from the store and passed as env (not a value).

    PURE plan brain: engine/_shared/PIM-DownlinkJob.ps1 (offline-tested in
    tests/Test-PimDownlinkJob.ps1). This wrapper only probes existence + invokes az.
    PS 5.1-safe; REST/cert + MI only (no PowerShell modules).

.PARAMETER Scenario      S5 | S6 (placement + identity model).
.PARAMETER TenantId      The managed/slave tenant id.
.PARAMETER SlaveRing     The slave's registry ring (default 2 = test).
.PARAMETER Cron          5-field cron expression (UTC). Default '0 3 * * *' (03:00 UTC daily).
.PARAMETER EnvName       ACA environment the Job runs in (S5: the central cae-pim; S6: the slave env).
.PARAMETER ResourceGroup RG of the ACA environment + the Job.
.PARAMETER AcrName       ACR holding the pim-manager image (pulled via MI AcrPull).
.PARAMETER ImageTag      Image tag to run (default: the VERSION file).
.PARAMETER ImageRepo     Image repository (default pim-manager).
.PARAMETER SubscriptionId Subscription to operate in.
.PARAMETER JobName       The ACA Job name (default ca-pim-downlink-<scenario-lower>).
.PARAMETER IdentityResourceId  A USER-assigned MI resource id to attach (else system-assigned MI).
.PARAMETER BaselineUrl   Private-endpoint blob URL of the signed master baseline.
.PARAMETER BaselineDocPath  Container path to a mounted/pulled signed bundle (alt to -BaselineUrl).
.PARAMETER SqlServerFqdn / SqlDatabase  The platform registry the engine/fan-out read (MI-auth).
.PARAMETER SyncRootCentral / SyncRootLocal  In-container sync-file staging roots.
.PARAMETER Start         After deploy (or standalone), START one on-demand execution (verification).
.PARAMETER Unregister    DELETE the Job (and exit). The clean teardown path.
.PARAMETER WhatIf        Print the exact `az containerapp job` commands; invoke nothing.

.EXAMPLE
    # S5 central (cae-pim exists) -- deploy the cron Job, daily 03:00 UTC:
    .\Deploy-PimDownlinkJob.ps1 -Scenario S5 -TenantId <managed-tenant> -SlaveRing 1 `
      -EnvName cae-pim -ResourceGroup rg-pim-manager-web -AcrName acrsecurityinsight `
      -SubscriptionId 54468121-... -SqlServerFqdn sql-...database.windows.net `
      -BaselineUrl https://<priv-blob>/baselines/baseline-latest.json -Cron '0 3 * * *'

.EXAMPLE
    # fire one execution on demand (verification), then check it ran:
    .\Deploy-PimDownlinkJob.ps1 -Scenario S5 -TenantId <managed-tenant> -ResourceGroup rg-pim-manager-web -Start
    .\Deploy-PimDownlinkJob.ps1 -Scenario S5 -TenantId <managed-tenant> -ResourceGroup rg-pim-manager-web -Verify

.EXAMPLE
    # teardown:
    .\Deploy-PimDownlinkJob.ps1 -Scenario S5 -ResourceGroup rg-pim-manager-web -Unregister
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('S5','S6')][string]$Scenario,
    [string]$TenantId,
    [ValidateRange(0,2)][int]$SlaveRing = 2,
    [string]$Cron = '0 3 * * *',
    [string]$EnvName,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$AcrName,
    [string]$ImageTag,
    [string]$ImageRepo = 'pim-manager',
    [string]$SubscriptionId,
    [string]$JobName,
    [string]$IdentityResourceId,
    [string]$RegistryIdentity = 'system',
    [string]$BaselineUrl,
    [string]$BaselineDocPath,
    [string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [string]$SyncRootCentral = '/sync/central',
    [string]$SyncRootLocal   = '/sync/local',
    [string]$EntryPath = '/app/PIM4EntraPS/tools/pim-engine/downlink-job-entry.ps1',
    [switch]$Start,
    [switch]$Verify,
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }

$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)   # SOLUTIONS\PIM4EntraPS
. (Join-Path $solRoot 'engine\_shared\PIM-DownlinkJob.ps1')

# best-effort banner (shared by the setup family).
$bannerShared = Join-Path $here '_PimSetupShared.ps1'
if (Test-Path $bannerShared) { . $bannerShared; if (Get-Command Show-PimSetupBanner -ErrorAction SilentlyContinue) { Show-PimSetupBanner -ScriptName 'Deploy-PimDownlinkJob' -SolutionRoot $solRoot } }

# Job name defaults to ca-pim-downlink-<scenario>.
if (-not "$JobName".Trim()) { $JobName = "ca-pim-downlink-$($Scenario.ToLowerInvariant())" }
# Image tag defaults to the VERSION file.
if (-not "$ImageTag".Trim()) {
    $vf = Join-Path $solRoot 'VERSION'
    if (Test-Path $vf) { $ImageTag = (Get-Content $vf -Raw).Trim() }
}

$placement = Get-PimDownlinkJobPlacement -Scenario $Scenario
Step "Downlink cron Job: $JobName  ($($placement.scenarioId) $($placement.placement)-hosted, $($placement.spnModel))"
Note $placement.reason

# Helper: run an az arg set (or print it under -WhatIf).
function Invoke-Az {
    param([string[]]$Args, [string]$What)
    $pretty = 'az ' + (@($Args) -join ' ')
    if ($WhatIfPreference) { Write-Host "WHATIF> $pretty" -ForegroundColor Yellow; return '' }
    if (-not $PSCmdlet.ShouldProcess($What, 'az')) { return '' }
    Note $pretty
    $out = & az @Args 2>&1
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az failed (exit $LASTEXITCODE): $out" }
    return $out
}

if ("$SubscriptionId".Trim() -and -not $WhatIfPreference) { az account set --subscription $SubscriptionId 2>$null | Out-Null }

# ---- UNREGISTER (delete) -------------------------------------------------------
if ($Unregister) {
    $del = Build-PimDownlinkJobArgs -Action delete -JobName $JobName -ResourceGroup $ResourceGroup
    Step "Unregister (delete) job $JobName"
    Invoke-Az -Args $del.args -What "delete job $JobName" | Out-Null
    Step 'Done (unregistered).'
    return
}

# ---- VERIFY (does NOT need to deploy) ------------------------------------------
if ($Verify -and -not $Start) {
    Step "Verify last execution of $JobName"
    $v = Get-PimDownlinkJobExecutionStatus -JobName $JobName -ResourceGroup $ResourceGroup
    Write-Host ("VERIFY: {0}" -f $v.reason) -ForegroundColor $(if ($v.verified) { 'Green' } else { 'Yellow' })
    $v
    if (-not $v.verified) { exit 1 }
    return
}

# ---- DEPLOY (create or update) -------------------------------------------------
if (-not "$EnvName".Trim()) { throw "-EnvName is required to deploy (S5: the central cae-pim; S6: the slave tenant's ACA env)." }
if (-not "$TenantId".Trim()) { throw "-TenantId (the managed/slave tenant) is required to deploy." }
if (-not "$AcrName".Trim())  { throw "-AcrName is required (the image is pulled via the Job's MI)." }
if (-not "$ImageTag".Trim()) { throw "-ImageTag is required (no VERSION file found to default from)." }

$acrServer = "$AcrName.azurecr.io"
$image     = "$acrServer/$ImageRepo`:$ImageTag"

# Existence probe (idempotent: create vs update).
$exists = $false
if (-not $WhatIfPreference) {
    $name = az containerapp job show -g $ResourceGroup -n $JobName --query name -o tsv 2>$null
    if ("$name".Trim()) { $exists = $true }
}
Note "image=$image  exists=$exists  cron='$Cron'"

# S6 prereq guard: warn loudly that the slave ACA env must already exist.
if ($Scenario -eq 'S6' -and -not $WhatIfPreference) {
    $envOk = az containerapp env show -g $ResourceGroup -n $EnvName --query name -o tsv 2>$null
    if (-not "$envOk".Trim()) {
        Warn "S6 PREREQ: the slave ACA env '$EnvName' (RG $ResourceGroup) does not exist."
        Warn "          Stand it up first: Setup-PimContainers.ps1 -SubscriptionId <slave-sub> -TenantId $TenantId -ResourceGroup $ResourceGroup -EnvName $EnvName ... (internal-only, private)."
        throw "S6 slave ACA env '$EnvName' missing -- create it before deploying the local downlink Job."
    }
}

$plan = Get-PimDownlinkJobDeployPlan -Scenario $Scenario -TenantId $TenantId -SlaveRing $SlaveRing `
    -JobName $JobName -ResourceGroup $ResourceGroup -EnvName $EnvName -Image $image -AcrServer $acrServer `
    -Cron $Cron -EntryPath $EntryPath -BaselineUrl $BaselineUrl -BaselineDocPath $BaselineDocPath `
    -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -SyncRootCentral $SyncRootCentral -SyncRootLocal $SyncRootLocal `
    -IdentityResourceId $IdentityResourceId -RegistryIdentity $RegistryIdentity -Exists $exists

if (-not $plan.ok) { throw "deploy plan invalid: $($plan.reason)" }
if ($plan.jobArgs.hasInlineSecret) { throw "REFUSED: the arg set contains an inline secret (must use MI / secret-ref only)." }

Step ("{0} job {1} (cron '{2}')" -f $plan.action, $JobName, $Cron)
Note ("command: " + (@($plan.command) -join ' '))
Note ("env: " + (@($plan.envVars) -join '  '))
Invoke-Az -Args $plan.jobArgs.args -What "$($plan.action) job $JobName" | Out-Null

# After CREATE, grant the Job's MI AcrPull on the ACR (so the MI pull works) +
# (best-effort) the SQL contained DB user the engine needs. Mirrors Setup-PimContainers.
if ($plan.action -eq 'create' -and -not $WhatIfPreference -and -not "$IdentityResourceId".Trim()) {
    try {
        $oid = az containerapp job show -g $ResourceGroup -n $JobName --query identity.principalId -o tsv 2>$null
        $acrId = az acr show -n $AcrName --query id -o tsv 2>$null
        if ("$oid".Trim() -and "$acrId".Trim()) {
            az role assignment create --assignee-object-id $oid --assignee-principal-type ServicePrincipal --role AcrPull --scope $acrId -o none 2>$null
            Note "granted the Job's system MI AcrPull on $AcrName"
        }
        Warn "SQL: add the Job's MI [$JobName] as a contained DB user on $SqlServerFqdn/$SqlDatabase (Grant-PimMiSql), like the worker matrix, so the engine apply can read pim.Rows."
    } catch { Warn "post-create grant skipped: $($_.Exception.Message)" }
}

# ---- START one on-demand execution (verification) ------------------------------
if ($Start) {
    $startArgs = Build-PimDownlinkJobArgs -Action start -JobName $JobName -ResourceGroup $ResourceGroup
    Step "Start one on-demand execution of $JobName"
    Invoke-Az -Args $startArgs.args -What "start job $JobName" | Out-Null
    Note "execution queued. Verify with: -Verify  (or `az containerapp job execution list -g $ResourceGroup -n $JobName`)"
}

Step 'Done.'
Write-Host ("Schedule: {0} runs '{1}' (UTC) in env {2}. Fire now: -Start ; verify: -Verify ; remove: -Unregister" -f $JobName, $Cron, $EnvName) -ForegroundColor Green

# ---------------------------------------------------------------------------
# VERIFICATION HELPER -- confirm a real EXECUTION ran (not just that the Job
# exists). Queries the Job's last execution status + pulls the execution logs and
# runs the PURE verdict core (Get-PimDownlinkJobExecutionVerdict). Defined at the
# tail so -Verify above can call it (PS dot-source order: param block runs first,
# but function defs in the same script body are available before the -Verify branch
# only if defined earlier -- so we define it BEFORE use via a forward shim).
# (Implemented here AND hoisted: PowerShell parses all function defs in a script
#  before executing the body, so this definition is available to the -Verify path.)
# ---------------------------------------------------------------------------
function Get-PimDownlinkJobExecutionStatus {
    param(
        [Parameter(Mandatory)][string]$JobName,
        [Parameter(Mandatory)][string]$ResourceGroup
    )
    # last execution name + status (newest first).
    $execName = az containerapp job execution list -g $ResourceGroup -n $JobName --query "reverse(sort_by([],&properties.startTime))[0].name" -o tsv 2>$null
    $status   = az containerapp job execution list -g $ResourceGroup -n $JobName --query "reverse(sort_by([],&properties.startTime))[0].properties.status" -o tsv 2>$null
    $log = ''
    if ("$execName".Trim()) {
        try { $log = (az containerapp job logs show -g $ResourceGroup -n $JobName --execution "$execName" --tail 200 2>$null) -join "`n" } catch {}
    }
    $verdict = Get-PimDownlinkJobExecutionVerdict -Status "$status" -LogText "$log"
    $verdict['execution'] = "$execName"
    $verdict['status']    = "$status"
    return $verdict
}
