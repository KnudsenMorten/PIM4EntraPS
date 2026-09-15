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
    [Parameter(Mandatory)][string]$AcrName,                 # customer-reachable ACR (image is imported here)
    [Parameter(Mandatory)][string]$ImageTag,
    [string]$ImageRepo         = 'pim-manager',
    [Parameter(Mandatory)][string]$SqlServerFqdn,           # customer LOCAL sql server
    [string]$SqlDatabase       = 'PimPlatform',
    [Parameter(Mandatory)][string]$SqlAdminClientId,
    # ONE of these. 🔴 The secret used to be Mandatory, which made a CLIENT SECRET structurally
    # required to onboard a customer -- against the repo-root rule ("authenticate as its SPN using
    # a CERTIFICATE, never a client secret") and impossible to satisfy in a tenant whose admin SPN
    # is cert-only. 🪤 And the capability was already THERE: Setup-PimContainers.ps1 (the very
    # script this forwards to) has accepted -SqlAdminCertThumbprint since 2026-08-09, and so has
    # Grant-PimMiSql beneath it. This caller simply never exposed it -- the same shape as BUG-78,
    # one level up: the gate exists downstream and nothing can reach it from here.
    [string]$SqlAdminClientSecret,
    [string]$SqlAdminCertThumbprint,
    [string]$DnsServer         = '',

    # --- image distribution: import the MSP-built image into the customer ACR ---
    # The image is built ONCE centrally and IMPORTED to the customer ACR; MI/SQL/
    # license/config stay local (REQUIREMENTS § 4). Skip with -SkipAcrImport if the
    # customer ACR already has the tag (the import itself is wired via -MspSourceAcr
    # + Invoke-PimAcrImport below).
    [switch]$SkipAcrImport,

    # --- MSP template DB (read-only, template only; pulled into the customer LOCAL DB) ---
    [Parameter(Mandatory)][string]$MspTemplateConn,         # read-only conn string to MSP template DB
    [ValidateSet('canary','broad','stable')][string]$Ring = 'stable',

    # --- image distribution: az acr import (built once centrally -> customer ACR) ---
    # When -MspSourceAcr is supplied, the engine image is mirrored MSP -> customer ACR
    # with `az acr import` (server-side blob copy; no local pull/push) BEFORE deploy.
    # Omit it to skip the import (the image is already in -AcrName).
    [string]$MspSourceAcr           = '',                   # MSP central ACR login server, e.g. mymspacr.azurecr.io
    [string]$ImageRepository        = 'pim4entraps/engine', # repo to mirror
    [string]$MspSourceAcrToken      = '',                   # cross-tenant ACR pull token (SECRET); else same-tenant import
    [string]$MspSourceAcrResourceId = '',                   # same-AAD cross-sub: source ACR resource id

    # --- sync model: don't force one (REQUIREMENTS.md § 4) ---
    [ValidateSet('template-pull','pull-baseline','local-reads-msp','sync-out-status','msp-delegates-local')]
    [string]$SyncModel = 'template-pull'
)
$ErrorActionPreference = 'Stop'
$subArgs = @('--subscription', $SubscriptionId)   # every az call is scoped to the customer subscription

# EITHER a secret OR a certificate, never both and never neither. Validated HERE, before any
# resource is touched, because this script deploys a customer's whole topology -- discovering the
# credential is unusable after the ACR import and the container app is the expensive way to learn
# it. Mirrors Grant-PimMiSql's contract exactly, so the two cannot drift apart.
if ($SqlAdminClientSecret -and $SqlAdminCertThumbprint) { throw 'Setup-PimMsp: pass EITHER -SqlAdminClientSecret OR -SqlAdminCertThumbprint, not both.' }
if (-not $SqlAdminClientSecret -and -not $SqlAdminCertThumbprint) { throw 'Setup-PimMsp: one of -SqlAdminClientSecret / -SqlAdminCertThumbprint is required.' }
# Splatted so the UNUSED one is ABSENT rather than passed as an empty string: Setup-PimContainers
# chooses its branch on truthiness, and an empty -SqlAdminClientSecret would look like a supplied
# credential and silently take the secret path with nothing in it.
$sqlAdminCred = if ($SqlAdminCertThumbprint) { @{ SqlAdminCertThumbprint = $SqlAdminCertThumbprint } }
                else                          { @{ SqlAdminClientSecret   = $SqlAdminClientSecret   } }

$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
function Step($m){ Write-Host "==> [MSP:$CustomerName] $m" -ForegroundColor Cyan }

# Shared setup helpers (banner + region guard + GSA guidance -- same as the rest of the setup family).
. "$here\_PimSetupShared.ps1"
# Substrate helpers (sync-model resolver + az acr import builder).
. (Join-Path (Split-Path -Parent (Split-Path -Parent $here)) 'engine\_shared\PIM-Baseline.ps1')
. (Join-Path (Split-Path -Parent (Split-Path -Parent $here)) 'engine\_shared\PIM-Substrate.ps1')

Show-PimSetupBanner -ScriptName "Setup-PimMsp ($CustomerName)" -SolutionRoot $solRoot
$Location = Assert-PimSetupRegion -Location $Location   # West Europe / Denmark East only; refuse France

# Resolve the requested sync model up front -- fail closed on an invariant-breaking
# or unknown model BEFORE anything is deployed.
$syncPlan = Get-PimSyncModelPlan -Model $SyncModel
Step "Sync model: $($syncPlan.Model) ($($syncPlan.Direction), initiator=$($syncPlan.Initiator), crosses=$($syncPlan.Crosses))"
Write-Host "      $($syncPlan.Description)" -ForegroundColor DarkGray
Write-Host "      invariants: MSP-writes-local=$($syncPlan.MspWritesLocal)  data-leaves=$($syncPlan.DataLeaves) (both MUST be False)" -ForegroundColor DarkGray

# --- Import the central image into the customer ACR (build-once, import-per-customer) ---
# The image is built ONCE centrally and IMPORTED to the customer ACR via `az acr import`
# (server-side blob copy; no local pull/push); MI/SQL/license/config stay local. Skip with
# -SkipAcrImport when the customer ACR already carries the tag.
if (-not $SkipAcrImport -and $MspSourceAcr) {
    Step "Mirror engine image '$ImageRepository`:$ImageTag' ($MspSourceAcr -> $AcrName) via az acr import"
    if ($PSCmdlet.ShouldProcess($AcrName, "az acr import $ImageRepository`:$ImageTag from $MspSourceAcr")) {
        Invoke-PimAcrImport -TargetAcrName $AcrName -SourceLoginServer $MspSourceAcr `
            -Repository $ImageRepository -Tag $ImageTag `
            -SourceToken $MspSourceAcrToken -SourceRegistryResourceId $MspSourceAcrResourceId -Force | Out-Null
        Write-Host "  imported $ImageRepository`:$ImageTag into $AcrName (MI/SQL/license/config remain local to the customer)." -ForegroundColor Green
    }
} else {
    Write-Host "  Skipping az acr import (-SkipAcrImport set or -MspSourceAcr not given); customer ACR must already carry $ImageRepository`:$ImageTag." -ForegroundColor DarkYellow
}

Step "Deploy customer container topology (tenant $TenantId / sub $SubscriptionId)"
# Worker matrix for a customer: manager + scheduler + engine. The scheduler's sync
# job(s) come from the resolved sync model (Get-PimSyncModelPlan), so a customer can
# run any supported model -- not just template-pull. All sync jobs are local-initiated
# (pull-not-push). Add more workers as the customer's scale requires.
$syncJobs    = @($syncPlan.SchedulerJobs)
$schedJobSet = @('queue-apply','reminders','escalations') + $syncJobs
$workers = @(
    @{ name = 'ca-pim-manager';   ingress = 'external'; entry = 'manager';   jobs = '' }
    @{ name = 'ca-pim-scheduler'; ingress = 'none';     entry = 'scheduler'; jobs = ($schedJobSet -join ',') }
    @{ name = 'ca-pim-engine';    ingress = 'none';     entry = 'scheduler'; jobs = 'engine-delta,engine-full' }
)
$setup = Join-Path $here 'Setup-PimContainers.ps1'
if ($PSCmdlet.ShouldProcess($CustomerName,'deploy container topology')) {
    & $setup -SubscriptionId $SubscriptionId -TenantId $TenantId -Location $Location `
        -ResourceGroup $ResourceGroup -VnetName $VnetName -VnetResourceGroup $VnetResourceGroup `
        -SubnetName $SubnetName -SubnetPrefix $SubnetPrefix -EnvName $EnvName `
        -AcrName $AcrName -ImageRepo $ImageRepo -ImageTag $ImageTag `
        -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase `
        -SqlAdminClientId $SqlAdminClientId @sqlAdminCred `
        -DnsServer $DnsServer -Workers $workers
}

# The MSP template conn is only wired when the sync model reads/copies from the MSP
# template DB (template-pull / local-reads-msp). For sync-out-status / msp-delegates-
# local the customer never reaches the MSP template DB, so we skip the secret.
if ($syncJobs -contains 'template-pull' -or $SyncModel -eq 'local-reads-msp') {
    Step "Wire '$SyncModel' (ring '$Ring', pull-not-push MSP->LOCAL) on the customer scheduler"
    if ($PSCmdlet.ShouldProcess('ca-pim-scheduler','set MSP template conn env + secret')) {
        # Store the MSP template conn as a secret + reference it; set the ring. The
        # sync job (PIM-Scheduler) copies/reads ONLY the ring's template rows into the
        # customer LOCAL DB. Customer data is never read by / sent to the MSP.
        # 🔴 B9 (2026-09-10) -- az is az.cmd, so cmd.exe CUTS THIS VALUE AT THE FIRST '&', with no
        # error and no non-zero exit. A SQL connection string separates with ';' so it is usually
        # safe -- but an '&' in the PASSWORD is entirely legal, and the result would be a secret
        # that looks stored, authenticates as nobody, and breaks the MSP template pull at 03:00
        # with a message about SQL rather than about this line. That exact failure shape (a value
        # silently truncated at '&') is what left a customer a release behind on 2026-09-10.
        # 🔑 Refuse loudly rather than store a broken secret. A rotated password is a two-minute
        # fix; a silently half-written credential is a night of debugging the wrong subsystem.
        if ("$MspTemplateConn".Contains('&')) {
            throw ("The MSP template connection string contains '&', which the az CLI silently " +
                   "truncates on Windows (az.cmd -> cmd.exe treats & as a command separator). " +
                   "The secret would be stored INCOMPLETE and fail to authenticate. " +
                   "Use a password without '&', or set this secret through the Azure portal/ARM REST.")
        }
        az containerapp secret set @subArgs -g $ResourceGroup -n ca-pim-scheduler --secrets "msp-template-conn=$MspTemplateConn" -o none
        az containerapp update @subArgs -g $ResourceGroup -n ca-pim-scheduler `
            --set-env-vars "PIM_MspTemplateConn=secretref:msp-template-conn" "PIM_Ring=$Ring" "PIM_SyncModel=$SyncModel" -o none
    }
} else {
    Step "Sync model '$SyncModel' needs no MSP template conn (no MSP->LOCAL copy); setting PIM_SyncModel only"
    if ($PSCmdlet.ShouldProcess('ca-pim-scheduler','set PIM_SyncModel')) {
        az containerapp update @subArgs -g $ResourceGroup -n ca-pim-scheduler --set-env-vars "PIM_SyncModel=$SyncModel" -o none
    }
}

Step "Done. Customer '$CustomerName' deployed; sync model '$SyncModel', ring '$Ring'."
Write-Host "Verify: customer Manager renders LOCAL SQL; sync tick logs per model; engine applies in-tenant." -ForegroundColor Green
# GSA / Private Access + private-link / DNS guidance (which zones to add) -- same as the rest of the setup family.
Show-PimGsaPrivateLinkGuidance
