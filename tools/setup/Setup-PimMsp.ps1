#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS — MSP per-customer deployment (container topology + pull-not-push sync).

.DESCRIPTION
    MSP model (see docs/ARCHITECTURE-HOSTING.md):
      * TWO SQL databases: the MSP **template DB** (baseline config, versioned by ring)
        and a **per-customer LOCAL DB** that lives in the customer's own tenant.
      * **Pull, not push**: the customer's own scheduler PULLS the template version its
        ring points at from the MSP template DB into the customer LOCAL DB, then the
        customer engine applies it. **Customer data never leaves the customer tenant.**
      * Rings drive WHICH template version is pulled (canary -> broad -> stable).

    This script deploys the full container topology INTO THE CUSTOMER TENANT by calling
    Setup-PimContainers.ps1 with the customer's subscription/tenant/RG/VNet/SQL/ACR, then
    wires the template-pull job on the customer scheduler:
        $env:PIM_MspTemplateConn   (read-only conn to the MSP template DB)
        $env:PIM_Ring              (the customer's ring -> template version)
        PIM_SCHED_JOBS includes 'template-pull'
    The pull job copies the ring's template rows MSP-template -> customer-LOCAL; the
    engine then runs delta/full against the customer tenant as usual.

.NOTES
    Run while authenticated to the CUSTOMER tenant (az login --tenant <customer>).
    The MSP template DB conn is passed as a SECRET to the customer scheduler (read-only,
    template only -- never customer data). Idempotent / re-runnable.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # --- customer tenant target (passed straight to Setup-PimContainers) ---
    [Parameter(Mandatory)][string]$CustomerName,            # short slug, e.g. 'contoso'
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$TenantId,
    [string]$Location          = 'westeurope',
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$VnetName,
    [Parameter(Mandatory)][string]$VnetResourceGroup,
    [string]$SubnetName        = 'snet-pim-aca',
    [string]$SubnetPrefix      = '10.50.40.0/23',
    [string]$EnvName           = 'cae-pim',
    [Parameter(Mandatory)][string]$AcrName,                 # customer-reachable ACR (or MSP ACR w/ cross-tenant pull)
    [string]$ImageTag          = '1.1.4',
    [Parameter(Mandatory)][string]$SqlServerFqdn,           # customer LOCAL sql server
    [string]$SqlDatabase       = 'PimPlatform',
    [Parameter(Mandatory)][string]$SqlAdminClientId,
    [Parameter(Mandatory)][string]$SqlAdminClientSecret,
    [string]$DnsServer         = '',

    # --- MSP template DB (read-only, template only; pulled into the customer LOCAL DB) ---
    [Parameter(Mandatory)][string]$MspTemplateConn,         # read-only conn string to MSP template DB
    [ValidateSet('canary','broad','stable')][string]$Ring = 'stable'
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
function Step($m){ Write-Host "==> [MSP:$CustomerName] $m" -ForegroundColor Cyan }

Step "Deploy customer container topology (tenant $TenantId / sub $SubscriptionId)"
# Worker matrix for a customer: manager + scheduler(+template-pull) + engine. Add more
# workers as the customer's scale requires (same config-driven model).
$workers = @(
    @{ name = 'ca-pim-manager';   ingress = 'external'; entry = 'manager';   jobs = '' }
    @{ name = 'ca-pim-scheduler'; ingress = 'none';     entry = 'scheduler'; jobs = 'template-pull,queue-apply,reminders,escalations' }
    @{ name = 'ca-pim-engine';    ingress = 'none';     entry = 'scheduler'; jobs = 'engine-delta,engine-full' }
)
$setup = Join-Path $here 'Setup-PimContainers.ps1'
if ($PSCmdlet.ShouldProcess($CustomerName,'deploy container topology')) {
    & $setup -SubscriptionId $SubscriptionId -TenantId $TenantId -Location $Location `
        -ResourceGroup $ResourceGroup -VnetName $VnetName -VnetResourceGroup $VnetResourceGroup `
        -SubnetName $SubnetName -SubnetPrefix $SubnetPrefix -EnvName $EnvName `
        -AcrName $AcrName -ImageTag $ImageTag `
        -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase `
        -SqlAdminClientId $SqlAdminClientId -SqlAdminClientSecret $SqlAdminClientSecret `
        -DnsServer $DnsServer -Workers $workers
}

Step "Wire template-pull (ring '$Ring', pull-not-push MSP->LOCAL) on the customer scheduler"
if ($PSCmdlet.ShouldProcess('ca-pim-scheduler','set MSP template-pull env + secret')) {
    # Store the MSP template conn as a secret + reference it; set the ring. The
    # template-pull job (PIM-Scheduler) copies ONLY the ring's template rows into the
    # customer LOCAL DB. Customer data is never read by / sent to the MSP.
    az containerapp secret set -g $ResourceGroup -n ca-pim-scheduler --secrets "msp-template-conn=$MspTemplateConn" -o none
    az containerapp update -g $ResourceGroup -n ca-pim-scheduler `
        --set-env-vars "PIM_MspTemplateConn=secretref:msp-template-conn" "PIM_Ring=$Ring" -o none
}

Step "Done. Customer '$CustomerName' deployed; scheduler pulls template ring '$Ring' MSP->LOCAL."
Write-Host "Verify: customer Manager renders LOCAL SQL; template-pull tick logs rows copied; engine applies in-tenant." -ForegroundColor Green
