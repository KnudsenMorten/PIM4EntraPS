#Requires -Version 5.1
<#
.SYNOPSIS
    §31.3 CLOUD-NATIVE -- deploy the master->managed (managed tenant) downlink as an Azure
    Container Apps scheduled JOB (cron), NOT a Windows scheduled task. Operator
    directive 2026-06-17: "all run in cloud only compute, in one test"; "run it
    through the containers in the slave".

.DESCRIPTION
    Creates/updates (idempotent) a Container Apps job (ARM REST, no az CLI -- 100.41) of trigger-type Schedule
    with a configurable cron expression. On its cadence the Job runs the pim-manager
    image with the in-container entrypoint tools/pim-engine/downlink-job-entry.ps1,
    which pulls -> verifies -> stages -> applies the ring-gated downlink + the engine
    apply for the scenario. Everything runs on cloud container compute.

    Two placements (REQUIREMENTS §31.2 matrix):
      * S5 -> the Job runs in the CENTRAL ACA env (cae-pim, MSP tenant) and the
              MULTI-TENANT SPN / MI acts INTO the managed tenant. The central env already
              exists (Setup-PimContainers).
      * S6 -> the Job runs in the SLAVE tenant's OWN ACA env using a LOCAL SPN / MI.
              That env must be stood up first (see -EnvName + the prereq note below).

    Private transport (§31.3 hard constraint): the Job runs on the INTERNAL,
    private-only ACA env. A scheduled Job is NOT an app -- it has NO ingress, so
    there is nothing public to expose. The signed-baseline pull + sync-file staging
    traverse the private cross-tenant VNet only. NO inline secret is ever emitted:
    identity is a Managed Identity (AcrPull + SQL contained user) or an SPN cert
    whose thumbprint/clientId are read from the store and passed as env (not a value).

    PURE plan brain: engine/msp/PIM-DownlinkJob.ps1 (offline-tested in
    tests/Test-PimDownlinkJob.ps1). This wrapper only probes existence + writes the job over ARM REST (engine/_shared/PIM-ArmSetup.ps1).
    PS 5.1-safe; REST/cert + MI only (no PowerShell modules).

.PARAMETER Scenario      S5 | S6 (placement + identity model).
.PARAMETER TenantId      The managed tenant id.
.PARAMETER SlaveRing     THE ring of this managed tenant (0 = dev, 1 = test, 2 = broad; default 0 -- §77.20). LOCAL and authoritative: it is
                         the pull job's own argument. The managing tenant's platform.Tenants.Ring is only its copy.
.PARAMETER Cron          5-field cron expression (UTC) of the job's TRIGGER. Default '*/5 * * * *': the job gates itself
                         against the cadence set in this tenant's Manager (Job schedule > Managed-tenant pull, 5-1440 min;
                         nothing set = daily, the old '0 3 * * *' cadence) -- engine/_shared/PIM-JobCadence.ps1.
.PARAMETER EnvName       ACA environment the Job runs in (S5: the central cae-pim; S6: the managed tenant env).
.PARAMETER ResourceGroup RG of the ACA environment + the Job.
.PARAMETER AcrName       ACR holding the pim-manager image (pulled via MI AcrPull).
.PARAMETER ImageTag      Image tag to run (default: the VERSION file).
.PARAMETER ImageRepo     Image repository (default pim-manager).
.PARAMETER SubscriptionId Subscription to operate in.
.PARAMETER JobName       The ACA Job name (default ca-pim-downlink-<scenario-lower>).
.PARAMETER IdentityResourceId  A USER-assigned MI resource id to attach (else system-assigned MI).
.PARAMETER BaselineUrl   PLAIN blob URL of the signed master baseline (DESIGN 13.7: public-but-signed, or a private
                         endpoint over peering). A URL with a query string is REFUSED: the SAS transport is retired
                         (SEC-27, operator 2026-09-18) -- trust is the signature, reach is the network rule.
.PARAMETER BaselineDocPath  Container path to a mounted/pulled signed bundle (alt to -BaselineUrl).
.PARAMETER SqlServerFqdn / SqlDatabase  The platform registry the engine/fan-out read (MI-auth).
.PARAMETER SyncRootCentral / SyncRootLocal  In-container sync-file staging roots.
.PARAMETER Start         After deploy (or standalone), START one on-demand execution (verification).
.PARAMETER Unregister    DELETE the Job (and exit). The clean teardown path.
.PARAMETER WhatIf        Print every ARM operation and the job resource it would send (secret values withheld); write nothing.

.EXAMPLE
    # S6 -- deploy the Job (trigger every 5 minutes; the cadence itself is set in the tenant's Manager, daily by default):
    .\Deploy-PimDownlinkJob.ps1 -Scenario S6 -TenantId <managed-tenant> -SlaveRing 1 `
      -EnvName <aca-env> -ResourceGroup <resource-group> -AcrName <acr> `
      -SubscriptionId <subscription-id> -SqlServerFqdn <sql-server>.database.windows.net `
      -BaselineUrl https://<store>.blob.core.windows.net/baselines/baseline-latest.json

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
    [ValidateRange(0,2)][int]$SlaveRing = 0,
    # Every 5 minutes -- the finest interval the Manager's Job schedule allows. The job GATES ITSELF against this tenant's
    # own DownlinkSchedule (PIM-JobCadence.ps1): nothing set there = daily, the cadence the old '0 3 * * *' gave.
    [string]$Cron = '*/5 * * * *',
    [string]$EnvName,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$AcrName,
    [string]$ImageTag,
    [string]$ImageRepo = 'pim-manager',
    [string]$SubscriptionId,
    [string]$JobName,
    [string]$IdentityResourceId,
    [string]$RegistryIdentity = '',   # '' = AUTO: the user-assigned MI if attached, else system (BUG-42)
    [string]$BaselineUrl,
    [string]$BaselineDocPath,
    # (SEC-27, operator 2026-09-18: -BaselineSasUrl is GONE. The SAS transport -- BUG-73's account-key read link and its
    # weekly rotation -- is retired: the downlink is public-but-signed or private-endpoint (DESIGN 13.7), with no credential
    # in the URL, and a -BaselineUrl carrying a query string is refused below.)
    # BUG-72: the engine's app-only identity INSIDE the container. Client id + SECRET -- NOT a cert
    # thumbprint: Resolve-PimCertificate searches only Cert:\CurrentUser\My and Cert:\LocalMachine\My,
    # which are empty on Linux, and setting a client id also disables the Managed Identity branch.
    # Same shape as Setup-PimContainers' IMP-08 path. On the estate these are the tenant's own
    # `Modern-AppId` + `Modern-Secret` Key Vault secrets.
    [string]$EngineClientId,
    [string]$EngineClientSecret,
    # BUG-75: the SQL admin used to create the job identity's contained DB user. Without this the
    # job's MI has no user, and the engine apply fails on every run with "cannot reach the desired
    # store" -- an error Azure SQL words as "the server is not currently configured to accept this
    # token", which sends you looking at permissions instead of at the missing user.
    [string]$SqlAdminClientId,
    [string]$SqlAdminClientSecret,
    [string]$SqlAdminCertThumbprint,
    # 71.33: create the job identity's contained user as the SIGNED-IN user (only needed off the SQL admin group model).
    [switch]$UseSignedInAccount,
    # Deliberate escape hatch, e.g. when the contained user is created by another process.
    [switch]$SkipSqlGrant,
    # (71.19: -DefaultManagerEmail removed -- the pull resolves an admin's TAP recipient from its sponsor department's
    # owners, which arrive in the same signed bundle.)
    # IMP-13 -- OPERATOR RULING 2026-09-03: "the MSP admin prefix is MANDATORY in a managed tenant;
    # onboarding refuses a tenant whose naming convention would hide synced admins."
    # These are the managed tenant's admin naming prefixes, e.g. 'admin-','x-admin'. Required
    # unless -AllowUncheckedAdminNaming is given.
    [string[]]$SlaveAdminPrefixes = @(),
    # 71.35 TRUST ANCHOR: the managing tenant's signing key id(s) this tenant pins (PIM_BaselineTrustedKeys). Identifiers, not
    # secrets -- given by the managing tenant's build output, never read from the bundle store. A bundle signed by a key that is
    # not pinned is REFUSED. Several may be pinned (a key roll). A redeploy without it pins nothing again.
    [string[]]$BaselineTrustedKeys = @(),
    # 🔒 The deliberate, greppable opt-out. Onboarding a tenant without declaring its convention
    # leaves the recognisability guard INERT, and the failure that follows is silent and
    # self-perpetuating -- so it must be an explicit choice someone can find later, not a default.
    [switch]$AllowUncheckedAdminNaming,
    [string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    # §71.10 (2026-09-15) -- NO SECRET: when no engine SPN secret is supplied the engine runs as the job's
    # own SYSTEM identity (ca-pim-tick's shape). This deploy grants it the engine's Graph app-role set and
    # makes it a member of the SQL admin group. -SkipGraphGrant / -SkipSqlAdminGroup are the deliberate
    # escape hatches for an identity whose rights are managed elsewhere.
    [string]$SqlAdminGroupName = 'grp-pim-sql-admins',
    [switch]$SkipSqlAdminGroup,
    [switch]$SkipGraphGrant,
    # 71.14: the explicit, default-OFF retraction opt-in. Sets PIM_DOWNLINK_ALLOW_RETRACTION=true on the job, so a
    # pull REMOVES rows that no longer reach this tenant (still within the removal budget). Omitted = report-only.
    # A redeploy without it switches the job back to report-only.
    [switch]$AllowRetraction,
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
. (Join-Path $solRoot 'engine\msp\PIM-DownlinkJob.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-JobCadence.ps1')   # the cadence gate's skip marker (-Verify)
# 100.41: the ONE token client + the ARM REST layer (loaded only when absent: re-loading PIM-Rest resets its token cache)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }

# Shared setup helpers. NOT best-effort any more: this script now needs
# Resolve-PimAcrImageDigest + the pure image-reference helpers it dot-sources (BUG-40), so a
# missing file must fail here and say why rather than surface later as "command not found" in the
# middle of a deploy.
$bannerShared = Join-Path $here '_PimSetupShared.ps1'
if (-not (Test-Path $bannerShared)) { throw "required helper not found: $bannerShared (provides Resolve-PimAcrImageDigest + the image-reference helpers)." }
. $bannerShared
if (Get-Command Show-PimSetupBanner -ErrorAction SilentlyContinue) { Show-PimSetupBanner -ScriptName 'Deploy-PimDownlinkJob' -SolutionRoot $solRoot }

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

# --- §71.10: WHICH IDENTITY THE ENGINE RUNS AS -------------------------------------------------------
# 🔴 FOUND LIVE ON RIDE 2026-09-15. Without an engine SPN secret this job used to run as the user-assigned
# MI it names in PIM_ManagedIdentityClientId -- an identity that holds NO Graph app-roles (it exists to
# pull the first image). The pull therefore could not read the managed tenant's own default domain, so no admin was
# staged, and the engine apply had no directory rights: the only way to a working job was a client SECRET,
# which the machine-wide rule forbids. ca-pim-tick has always run the engine as its SYSTEM identity with
# the UAMI attached for the pull only; this job now does the same.
$engineSystemMi = -not ("$EngineClientId".Trim() -and "$EngineClientSecret".Trim())
if ($engineSystemMi) { Note "engine identity: the job's own SYSTEM managed identity (no secret) -- granted Graph app-roles + SQL admin group membership below" }
else { Warn "engine identity: SPN client id + SECRET (-EngineClientSecret). Omit both to run the engine as the job's system managed identity instead." }

# Helper: run ONE Azure operation over ARM REST (or print it under -WhatIf). 100.41 (NO-AZ): every operation below
# goes through engine\_shared\PIM-ArmSetup.ps1 -- PIM-Rest's ONE token client -- never the az CLI.
#
# 🪤 BUG-43 -- THE PARAMETER IS NOT CALLED $Args, AND MUST NEVER BE AGAIN.
# `$Args` is a PowerShell AUTOMATIC variable. Declaring `param([string[]]$Args)` does not fail --
# it binds nothing: the caller's array is silently discarded and the function sees count=0. In the
# az era that ran BARE `az`, which prints help and exits 0, so nothing threw: every create, update,
# delete and start did NOTHING while reporting success (measured live 2026-08-09).
# The same rule holds for this helper: an operation with no description or no body is REFUSED, never
# run as a silent no-op.
function Invoke-DownlinkJobOp {
    param([string]$Operation, [string]$What, [scriptblock]$Do)
    if (-not "$Operation".Trim() -or -not $Do) {
        # Refuse to run a no-op and call it a deploy -- the BUG-43 shape.
        throw "Invoke-DownlinkJobOp called with NO operation for '$What' -- refusing to run nothing and report success."
    }
    if ($WhatIfPreference) { Write-Host "WHATIF> $Operation" -ForegroundColor Yellow; return $null }
    if (-not $PSCmdlet.ShouldProcess($What, $Operation)) { return $null }
    Note $Operation
    & $Do
}

# A job resource's ARM path in THE subscription (every operation is scoped to it -- BUG-215).
function Get-DownlinkJobPath { "/subscriptions/$($script:sub)/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$JobName" }

# az containerapp job delete --yes: DELETE, then wait until the job is gone (a create right after must not race it).
function Remove-DownlinkJob {
    param([string]$Why)
    Invoke-DownlinkJobOp -Operation "DELETE $(Get-DownlinkJobPath)" -What $Why -Do {
        [void](Invoke-PimSetupArm -Method DELETE -Path (Get-DownlinkJobPath) -ApiVersion (Get-PimSetupApiVersion aca) -NotFoundOk)
        $deadline = (Get-Date).AddMinutes(10)
        while ((Get-PimArmAcaJob -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName -ErrorAsNull) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 10 }
        if (Get-PimArmAcaJob -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName -ErrorAsNull) { throw "job '$JobName' still exists 10 minutes after its delete was accepted." }
    } | Out-Null
}

# 🔴 BUG-215 -- NEVER CHANGE A MACHINE-WIDE DEFAULT. The az era ran `az account set --subscription` here and never restored
# it, so a standalone deploy silently moved every later az call on the box (other sessions included). Over ARM REST there
# is no default context at all: every path names -SubscriptionId, and every token PIM-Rest issues is pinned to that
# subscription's tenant -- so a directory call (Resolve-PimMiAppId, Grant-PimMiGraph) can no longer read the wrong tenant.
$script:sub = "$SubscriptionId".Trim()
if (-not $script:sub) { $script:sub = "$env:PIM_SUBSCRIPTION_ID".Trim() }
$subTenant = ''
if ($script:sub -and -not $WhatIfPreference) {
    # A caller that already set up PIM-Rest's identity (the MSP build's step launcher, a deploy in this process) keeps it;
    # otherwise sign in: the Invardia Support app's REST session for this tenant, else the person at the keyboard.
    if (-not $global:PIM_SetupRestMode -and -not "$($global:PIM_ClientId)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $script:sub) }
    $subObj = Get-PimArmSubscription -SubscriptionId $script:sub -ErrorAsNull
    $subTenant = if ($subObj) { "$($subObj.tenantId)".Trim().ToLowerInvariant() } else { '' }
    if (-not $subTenant) {
        throw ("REFUSED: subscription $($script:sub) is not visible to the signed-in identity ($($global:PimSetupRestLastError)). " +
               'Sign in to its tenant (or connect its Invardia Support app) and re-run -- this script changes no default.')
    }
    $tokTenant = "$($global:PIM_TenantId)".Trim().ToLowerInvariant()
    if ($tokTenant -and $tokTenant -ne $subTenant) {
        throw ("REFUSED: the REST session is pinned to tenant '$tokTenant' but subscription $($script:sub) belongs to tenant '$subTenant'. " +
               'Directory calls in this deploy would read the wrong tenant. Sign in to that tenant and re-run.')
    }
} elseif (-not $script:sub -and -not $WhatIfPreference) {
    throw ('-SubscriptionId is required: every Azure call goes over ARM REST, which addresses the subscription explicitly ' +
           '(there is no default context to fall back on).')
}

# ---- UNREGISTER (delete) -------------------------------------------------------
if ($Unregister) {
    Step "Unregister (delete) job $JobName"
    Remove-DownlinkJob -Why "delete job $JobName"
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
if (-not "$EnvName".Trim()) { throw "-EnvName is required to deploy (S5: the central cae-pim; S6: the managed tenant's ACA env)." }
if (-not "$TenantId".Trim()) { throw "-TenantId (the managed tenant) is required to deploy." }
if (-not "$AcrName".Trim())  { throw "-AcrName is required (the image is pulled via the Job's MI)." }
if (-not "$ImageTag".Trim()) { throw "-ImageTag is required (no VERSION file found to default from)." }

$acrServer = "$AcrName.azurecr.io"
# BUG-40: deploy the immutable DIGEST, not the mutable tag. Rebuilding a tag moves the pointer but
# leaves the Job's image FIELD identical, so ARM sees no change and the platform keeps running the
# image it already pulled -- measured on the ESTATE-06 tick Job, where a rebuild + update reported
# success and the next executions ran the OLD code. Resolved after the REST session is set up below.
$imageTagRef = "$acrServer/$ImageRepo`:$ImageTag"
$image       = $imageTagRef

# Existence probe (idempotent: create vs update).
$exists = $false
if (-not $WhatIfPreference) {
    $jobNow = Get-PimArmAcaJob -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName -ErrorAsNull
    $name = if ($jobNow) { "$($jobNow.name)" } else { '' }
    if ("$name".Trim()) { $exists = $true }
}
Note "image=$image  exists=$exists  cron='$Cron'"

# --- BUG-71a: AN EXISTING **FAILED** JOB MUST BE RECREATED, NOT UPDATED ----------
# 🔴 The existence probe above only asks "is there a job with this name". A job that failed to
# provision answers YES, so the deploy takes the UPDATE path -- and an update does not re-run the
# identity/registry wiring that failed in the first place, so the job stays Failed and the deploy
# still exits 0. That is what a re-run of this script against the broken estate job would have done:
# nothing, successfully. Recovering it by hand (delete, then create) is the step that must NOT live
# in an operator's head -- it is the difference between a script that repairs an environment and one
# that needs someone who already knows the answer.
if ($exists -and -not $WhatIfPreference) {
    $existingProv = "$($jobNow.properties.provisioningState)".Trim()
    if ($existingProv -and $existingProv -ne 'Succeeded') {
        Warn "existing job '$JobName' is provisioningState='$existingProv' -- an update cannot repair that; deleting and recreating it."
        Remove-DownlinkJob -Why "delete failed job $JobName"
        $exists = $false
        Note "deleted the failed job; it will be recreated below with a pull-capable identity."
    }
}


# S6 prereq guard: warn loudly that the managed tenant ACA env must already exist.
if ($Scenario -eq 'S6' -and -not $WhatIfPreference) {
    $envObj = Get-PimArmAcaEnv -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $EnvName -ErrorAsNull
    $envOk = if ($envObj) { "$($envObj.name)" } else { '' }
    if (-not "$envOk".Trim()) {
        Warn "S6 PREREQ: the managed tenant ACA env '$EnvName' (RG $ResourceGroup) does not exist."
        Warn "          Stand it up first: Setup-PimContainers.ps1 -SubscriptionId <slave-sub> -TenantId $TenantId -ResourceGroup $ResourceGroup -EnvName $EnvName ... (internal-only, private)."
        throw "S6 slave ACA env '$EnvName' missing -- create it before deploying the local downlink Job."
    }
}

# --- BUG-71: RESOLVE THE USER-ASSIGNED MI, or refuse to create -------------------
# 🔴 A CREATE WITH NO -IdentityResourceId PRODUCES A JOB THAT CANNOT PULL ITS OWN IMAGE.
# BUG-42 already wrote down the reason, one layer up: "a system identity CANNOT pull the first
# image, because it does not exist until the job it belongs to does." BUG-42 fixed the branch
# where a UAMI *is* supplied. It left the branch where one is NOT, and that branch is the one an
# unattended deploy takes -- so the AUTO fallback to 'system' is unreachable-by-design on a create.
# MEASURED on the estate 2026-08-26: ca-pim-downlink-s6 on the greenfield slave was created without
# -IdentityResourceId -> registries.identity='system' -> provisioningState=Failed, zero executions,
# and the system MI held NO role on the ACR at all. Re-creating it with the tenant's own
# id-pim-<token> UAMI (the one ca-pim-tick already uses) provisioned Succeeded on the first try.
# 🪤 The post-create AcrPull grant below CANNOT save it: it runs after the pull has already been
# attempted, and its failure was swallowed by `2>$null` + catch. A grant that arrives after the
# create is a grant for the NEXT deploy, not this one.
# So: resolve the RG's user-assigned MI automatically, and if there is genuinely none, FAIL HERE
# with the reason -- never emit a job that is guaranteed to fail to provision.
# 🔴 BUG-71d -- THIS GUARD USED TO READ `-and -not $exists`, SO THE FIX APPLIED TO CREATE ONLY.
# That reproduced BUG-42's own mistake one layer up: half the paths fixed, and the unfixed half is
# the one a re-deploy takes. MEASURED 2026-08-26, an hour after fixing BUG-71: an UPDATE of the
# (already healthy, UserAssigned) job re-rendered its YAML with no identity, so ACA reverted the
# registry identity to 'system' and the pull broke again --
#   FetchingKeyVaultSecretFailed: ... Ensure the managed identity 'system' has the correct
#   permissions. Error: ACR token exchange endpoint returned error status: 401
# The job had been working ten minutes earlier. An update must therefore re-resolve the identity
# exactly like a create: the YAML is a FULL document, so anything it omits is not "left alone",
# it is REMOVED.
if (-not "$IdentityResourceId".Trim() -and -not $WhatIfPreference) {
    $uamis = @(Get-PimArmIdentities -SubscriptionId $script:sub -ResourceGroup $ResourceGroup | ForEach-Object { [pscustomobject]@{ id = "$($_.id)"; name = "$($_.name)" } })
    $pick = @($uamis | Where-Object { "$($_.name)" -like 'id-pim*' })
    if (-not $pick.Count) { $pick = @($uamis) }
    if ($pick.Count -eq 1) {
        $IdentityResourceId = "$($pick[0].id)"
        Note "identity: auto-resolved the user-assigned MI '$($pick[0].name)' (a system identity cannot pull the first image)"
    }
    elseif ($pick.Count -gt 1) {
        throw ("REFUSING to create $JobName -- $($pick.Count) user-assigned identities in ${ResourceGroup} " +
               "($(($pick | ForEach-Object { $_.name }) -join ', ')) and no -IdentityResourceId to choose between them. " +
               'Pass -IdentityResourceId explicitly.')
    }
    else {
        throw ("REFUSING to create $JobName -- no user-assigned managed identity in $ResourceGroup, and a " +
               'SYSTEM-assigned identity cannot pull the first image (it does not exist until the job does), ' +
               'so the create would land as provisioningState=Failed with zero executions. ' +
               "Create the identity first (Setup-PimContainers.ps1 makes id-pim-<token> and grants it AcrPull on the ACR), " +
               'or pass -RegistryIdentity explicitly if you have already granted the pull rights another way.')
    }
}

# --- BUG-71e: AN IDENTITY CHANGE CANNOT BE DONE BY UPDATE -- RECREATE ------------
# ACA refuses to swap a job's identity through `job update --yaml`:
#   (FailedIdentityOperation) ... "The request format was unexpected : Request requires
#   identities to be assigned."
# Measured 2026-08-26 while repairing a job a previous bad update had left on the SYSTEM identity.
# Resolving the right identity is NOT enough on its own: without this branch the deploy resolves
# the correct MI, tries to apply it, and dies -- leaving the broken job exactly as it was. The two
# fixes together are what make a re-run actually REPAIR an environment rather than report on it.
# 🪤 THIS MUST RUN **AFTER** THE AUTO-RESOLVE ABOVE. Placed before it (as it first was), the guard
# reads an empty $IdentityResourceId, decides there is nothing to compare, and silently skips --
# so the deploy went straight back to the failing update path. A guard that depends on a value
# computed later is not a guard, and it fails in the quiet direction.
if ($exists -and -not $WhatIfPreference -and "$IdentityResourceId".Trim()) {
    # Read the identity block as text and look for the MI by NAME (the ARM job's identity object, as JSON).
    $curJob = Get-PimArmAcaJob -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName -ErrorAsNull
    $curIdentity = if ($curJob -and $curJob.identity) { $curJob.identity | ConvertTo-Json -Depth 6 -Compress } else { '' }
    $wantedName  = Split-Path "$IdentityResourceId".Trim() -Leaf
    # §71.10: adding the SYSTEM identity to a job that has only the user-assigned one is an identity change
    # too -- ACA refuses it on update just the same, so it takes the same delete + recreate.
    $missingSystem = $engineSystemMi -and -not ("$curIdentity" -match 'SystemAssigned')
    if ($missingSystem -or -not ("$curIdentity" -match [regex]::Escape($wantedName))) {
        Warn "existing job '$JobName' does not carry the intended user-assigned identity '$wantedName' -- ACA cannot swap an identity on update; deleting and recreating."
        Remove-DownlinkJob -Why "delete job $JobName (identity change)"
        $exists = $false
        # the plan below is built from $exists, so it now emits a CREATE
        $plan = $null
    }
}

# --- BUG-76: the container must NAME the identity it wants a token for ----------
# Container Apps attaches a USER-ASSIGNED identity with no system identity beside it, and the
# IDENTITY_ENDPOINT token call cannot choose one on its own -- so without this the container gets
# no token at all and presents no credential to SQL. Resolved here (a live probe) and passed to
# the pure planner as a fact, which is the same split the rest of this script uses.
$miClientId = ''
# §71.10: never name the user-assigned MI when the engine runs as the system identity -- a named client id
# makes every token call pick the role-less UAMI again.
if (-not $WhatIfPreference -and "$IdentityResourceId".Trim() -and -not $engineSystemMi) {
    $miObj = Get-PimArmIdentity -ResourceId "$IdentityResourceId" -ErrorAsNull
    $miClientId = if ($miObj) { "$($miObj.properties.clientId)" } else { '' }
    if ("$miClientId".Trim()) { Note "managed identity client id: $miClientId" }
    else { Warn "could not read the client id of '$IdentityResourceId' -- the container may be unable to obtain a managed-identity token." }
}

# --- facts the job resource needs (BUG-38) + the digest pin (BUG-40) -------------
# The Job is written as ONE ARM resource (command + a separate args array -- the BUG-38 split, where a leading dash is
# just a string). It needs the environment's ARM id and region, which only a live probe knows -- gathered HERE and
# passed to the pure planner.
$envId = ''; $envLocation = ''
if (-not $WhatIfPreference) {
    $envRes      = Get-PimArmAcaEnv -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $EnvName -ErrorAsNull
    $envId       = if ($envRes) { "$($envRes.id)" } else { '' }
    $envLocation = if ($envRes) { "$($envRes.location)" } else { '' }
    if (-not "$envId".Trim()) { throw "could not read the ACA environment '$EnvName' in RG $ResourceGroup -- cannot build the Job resource." }

    $digest = Resolve-PimAcrImageDigest -AcrName $AcrName -Repository $ImageRepo -Tag $ImageTag -SubscriptionId $script:sub
    $image  = New-PimImageReference -Registry $acrServer -Repository $ImageRepo -Digest $digest
    Note "tag $ImageTag => $digest"
    Note "deploying $image"
} else {
    $envId = "/subscriptions/<sub>/resourceGroups/$ResourceGroup/providers/Microsoft.App/managedEnvironments/$EnvName"
    $envLocation = '<location>'
    Note "WhatIf -- the tag would be resolved to a digest here; plan shows $imageTagRef."
}
# 100.41: NO FILE. The az era wrote the job definition to a YAML file in %TEMP% (keyed by resource group + PID, BUG-72:
# it could carry the engine secret) and shredded it afterwards. The definition is now an in-memory ARM body sent over
# REST, so a secret value never touches the disk. The pure planner still renders its YAML text (its tests read it) and
# takes a path label; nothing is ever written to it.
$yamlPath = "in-memory:pim-$JobName-$ResourceGroup"

# The ARM job resource -- the same document Get-PimDownlinkJobYaml renders, field for field (identity, Schedule trigger,
# registry by managed identity, command + args, env with secretRef, the secrets block, resources).
function New-PimDownlinkJobResource {
    param([string]$Location, [string]$EnvironmentId, [string]$Image, [string]$Cron, [string[]]$Command = @(), [string[]]$EnvVars = @(),
          [string]$AcrServer, [string]$IdentityResourceId, [switch]$SystemAssigned, [string]$RegistryIdentity = '',
          [object[]]$Secrets = @(), [double]$Cpu = 0.5, [string]$Memory = '1Gi', [int]$ReplicaTimeout = 1800, [int]$ReplicaRetryLimit = 1)
    if ("$IdentityResourceId".Trim()) {
        $ua = @{}; $ua["$IdentityResourceId".Trim()] = @{}
        $identity = @{ type = $(if ($SystemAssigned) { 'SystemAssigned,UserAssigned' } else { 'UserAssigned' }); userAssignedIdentities = $ua }
    } else { $identity = @{ type = 'SystemAssigned' } }
    $cfg = [ordered]@{ triggerType = 'Schedule'; replicaTimeout = $ReplicaTimeout; replicaRetryLimit = $ReplicaRetryLimit
                       scheduleTriggerConfig = [ordered]@{ cronExpression = $Cron; parallelism = 1; replicaCompletionCount = 1 } }
    if (@($Secrets).Count) { $cfg.secrets = @($Secrets) }
    if ("$AcrServer".Trim()) {
        # BUG-42: '' = AUTO -- the user-assigned MI pulls when one is attached, else the system identity. Explicit wins.
        $regId = "$RegistryIdentity".Trim()
        if (-not $regId) { $regId = if ("$IdentityResourceId".Trim()) { "$IdentityResourceId".Trim() } else { 'system' } }
        $cfg.registries = @(@{ server = "$AcrServer".Trim(); identity = $regId })
    }
    $cmd = @($Command)
    $container = [ordered]@{ name = $JobName; image = $Image; command = @($(if ($cmd.Count) { "$($cmd[0])" } else { 'pwsh' })) }
    if ($cmd.Count -gt 1) { $container.args = @($cmd[1..($cmd.Count - 1)] | ForEach-Object { "$_" }) }
    if (@($EnvVars).Count) {
        $container.env = @(@($EnvVars) | ForEach-Object {
            $kv = "$_" -split '=', 2
            $v = if ($kv.Count -gt 1) { $kv[1] } else { '' }
            if ("$v" -match '^(?i)secretref:(.+)$') { @{ name = $kv[0]; secretRef = $Matches[1] } } else { @{ name = $kv[0]; value = "$v" } }
        })
    }
    $container.resources = @{ cpu = $Cpu; memory = $Memory }
    return @{ location = $Location; identity = $identity
              properties = [ordered]@{ environmentId = $EnvironmentId; workloadProfileName = 'Consumption'; configuration = $cfg; template = @{ containers = @($container) } } }
}

# 🔴 REFUSE A SQL-BACKED JOB WITH NO SQL SERVER. Get-PimDownlinkJobEnv emits
# PIM_StorageBackend=sql and PIM_SqlDatabase UNCONDITIONALLY, but PIM_SqlServer only when one was
# supplied -- so omitting -SqlServerFqdn produces a Job that declares "my store is SQL", names a
# database, and never says on which server. The engine then falls back to the local default and
# the run dies as
#     Preflight FAILED: cannot reach the desired store (.\SQLEXPRESS/PimPlatform): no SELECT 1
# which points at SQL Express -- a thing that cannot exist in this container -- instead of at the
# parameter nobody passed. MEASURED 2026-09-03 onboarding RIDE: the downlink itself succeeded
# (plan, stage and uplink acceptance all OK) and only the engine apply failed, so the run looked
# like a store problem rather than a deploy-argument problem.
# 🪤 It also silently skipped the contained-user grant below, which is guarded on the same value:
# two consequences, one omission, no warning for either. Session 30 burned three rebuild cycles on
# exactly this "silent .\SQLEXPRESS default outranking the configured Azure SQL server".
# 🔒 IMP-13 -- OPERATOR RULING 2026-09-03: the MSP admin prefix is MANDATORY in a managed tenant.
# THE FAILURE THIS PREVENTS IS SILENT AND SELF-PERPETUATING. A synced MSP admin lands in the
# customer's tenant as <UserName>@<managed tenant domain>. If the managed tenant's Admins provider scopes on a prefix
# that does not match, its live set never contains that account -- so the diff says "not present"
# on EVERY tick, the sync recreates it EVERY tick, and each pass leaves another unmanaged
# privileged account in a customer's directory. Nothing errors. It just accumulates.
# 🪤 AND THE GUARD FOR IT ALREADY EXISTED, UNARMED. Select-PimUnrecognisableAdmins withholds those
# admins rather than creating them, and is careful to report `checked = $false` when no prefixes
# are known -- "we did not look", explicitly not "they are fine". But the scheduled Job never
# passed prefixes at all, so every production run took the did-not-look branch. A correct guard
# that nothing arms is the BUG-29 shape, and it is why this refusal lives at DEPLOY time: that is
# the last moment a human is present to answer the question.
if (-not @($SlaveAdminPrefixes | Where-Object { "$_".Trim() }).Count -and -not $AllowUncheckedAdminNaming) {
    throw ("REFUSING to onboard ${JobName}: -SlaveAdminPrefixes was not supplied, so the " +
           "recognisability guard would be INERT for every scheduled run. An admin whose name the " +
           "slave's Admins provider cannot match is never in its live set, so it is recreated on " +
           "every tick and left unmanaged in the customer's tenant -- silently. " +
           "Pass -SlaveAdminPrefixes <the managed tenant's admin prefixes, e.g. 'admin-'>, or " +
           "-AllowUncheckedAdminNaming to accept that risk deliberately.")
}
if (@($SlaveAdminPrefixes | Where-Object { "$_".Trim() }).Count) {
    Note ("admin naming prefixes: {0} (recognisability guard ARMED for every scheduled run)" -f (@($SlaveAdminPrefixes) -join ', '))
} else {
    Warn '-AllowUncheckedAdminNaming given -- the recognisability guard stays INERT for this tenant.'
}

if (-not "$SqlServerFqdn".Trim()) {
    throw ("REFUSING to deploy ${JobName}: an S5/S6 downlink Job is SQL-backed by definition " +
           "(PIM_StorageBackend=sql is always set), but -SqlServerFqdn was not supplied. The Job " +
           "would name database '$SqlDatabase' with no server, the engine would fall back to " +
           ".\SQLEXPRESS, and the identity's contained-user grant would be skipped as well. " +
           "Pass -SqlServerFqdn <the managed tenant's own server>.database.windows.net.")
}

# SEC-27 (operator 2026-09-18): NO SAS. The pull URL is the PLAIN blob URL (public-but-signed or private endpoint,
# DESIGN 13.7). A query string is a credential riding in the job definition -- refused, not stored as a secret.
if ("$BaselineUrl".Trim() -match '[?#]') {
    throw ("REFUSED: -BaselineUrl carries a query string or fragment. The SAS transport is retired: pass the PLAIN " +
           'blob URL, e.g. https://<master-store>.blob.core.windows.net/baselines/baseline-latest.json -- trust is the bundle signature, reach is the storage network rule.')
}
if ("$BaselineUrl".Trim() -and "$BaselineUrl".Trim() -notmatch '^https://') { throw "REFUSED: -BaselineUrl must be an https:// URL (got '$BaselineUrl')." }

# 71.35: a pin that is not a key id is REFUSED here, not silently dropped by the env builder (a typo would pin nothing).
$badPins = @(@($BaselineTrustedKeys) | ForEach-Object { "$_" -split '[,;\s]+' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ -and $_ -cnotmatch '^[A-Za-z0-9_-]{43}$' })
if ($badPins.Count) { throw "REFUSED: -BaselineTrustedKeys '$($badPins -join ', ')' is not a signing key id (43 characters of base64url, as the managing tenant's signingkey step prints)." }
if (@($BaselineTrustedKeys | Where-Object { "$_".Trim() }).Count) { Note ("pinned master signing key(s): {0}" -f (@($BaselineTrustedKeys) -join ', ')) }
else { Warn 'no -BaselineTrustedKeys: only bundles signed by the product''s embedded certificate will verify; a managing tenant publishing from its cloud job will be REFUSED.' }
$plan = Get-PimDownlinkJobDeployPlan -Scenario $Scenario -TenantId $TenantId -SlaveRing $SlaveRing `
    -JobName $JobName -ResourceGroup $ResourceGroup -EnvName $EnvName -Image $image -AcrServer $acrServer `
    -Cron $Cron -EntryPath $EntryPath -BaselineUrl $BaselineUrl -BaselineDocPath $BaselineDocPath `
    -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -SyncRootCentral $SyncRootCentral -SyncRootLocal $SyncRootLocal `
    -IdentityResourceId $IdentityResourceId -RegistryIdentity $RegistryIdentity -Exists $exists `
    -YamlPath $yamlPath -Location $envLocation -EnvironmentId $envId `
    -EngineClientId $EngineClientId -EngineClientSecret $EngineClientSecret `
    -ManagedIdentityClientId $miClientId `
    -SlaveAdminPrefixes $SlaveAdminPrefixes -SystemAssigned:$engineSystemMi -AllowRetraction:$AllowRetraction `
    -BaselineTrustedKeys $BaselineTrustedKeys `
    -DeployedUtc ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))

if (-not $plan.ok) { throw "deploy plan invalid: $($plan.reason)" }
if ($AllowRetraction) { Warn 'retraction: ALLOWED on this job (-AllowRetraction) -- pulls remove rows that no longer reach this tenant, within the removal budget.' }
else { Note 'retraction: report-only (default; pass -AllowRetraction to let the pull remove rows that no longer reach this tenant)' }
Note "engine identity in the plan: $($plan.engineIdentity)"
if ($plan.jobArgs.hasInlineSecret) { throw "REFUSED: the arg set contains an inline secret (must use MI / secret-ref only)." }

Step ("{0} job {1} (cron '{2}')" -f $plan.action, $JobName, $Cron)
Note ("command: " + (@($plan.command) -join ' '))
Note ("env: " + (@($plan.envVars) -join '  '))
# The secrets this definition carries: exactly the ones the plan references (by name), with their values. Today that is
# the engine client secret, when one is given -- a name the planner does not know how to value is a planner change this
# deploy must not guess at.
$jobSecrets = @()
foreach ($sn in @($plan.secretNames)) {
    if ($sn -eq 'pim-engine-client-secret' -and "$EngineClientSecret".Trim()) { $jobSecrets += @{ name = $sn; value = "$EngineClientSecret" } }
    else { throw "the deploy plan references a secret '$sn' this script has no value for -- refusing to deploy a job that would fail on it." }
}
$jobResource = New-PimDownlinkJobResource -Location $envLocation -EnvironmentId $envId -Image $image -Cron $Cron `
    -Command @($plan.command) -EnvVars @($plan.envVars) -AcrServer $acrServer -IdentityResourceId $IdentityResourceId `
    -SystemAssigned:$engineSystemMi -RegistryIdentity $RegistryIdentity -Secrets $jobSecrets
$verb = if ($plan.action -eq 'create') { 'PUT' } else { 'PATCH' }
if ($WhatIfPreference) {
    # the definition as it would be sent -- secret VALUES withheld (the plan names them, it never prints them)
    $shown = $jobResource | ConvertTo-Json -Depth 12
    foreach ($s in $jobSecrets) { $shown = $shown.Replace([string]$s.value, '<secret withheld>') }
    Write-Host "WHATIF> job resource ($verb $(Get-DownlinkJobPath)):" -ForegroundColor Yellow
    Write-Host $shown -ForegroundColor DarkGray
}
# 🔒 BUG-72: the definition can carry a secret VALUE (the engine client secret, when one is given -- that is what an ACA
# secrets block is). It is built in memory and sent over REST; it is never written to a file.
Invoke-DownlinkJobOp -Operation "$verb $(Get-DownlinkJobPath) ($($plan.action) job)" -What "$($plan.action) job $JobName" -Do {
    # A write ARM accepted that then ended in a non-Succeeded state is judged by the provisioningState verification below
    # (BUG-71b, with its cause); any other failure stops here with ARM's code + message.
    try { [void](Set-PimArmAcaJob -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName -Resource $jobResource -Create:($plan.action -eq 'create')) }
    catch { if ("$($_.Exception.Message)" -match 'did not provision') { Warn "$($_.Exception.Message)" } else { throw } }
} | Out-Null

# BUG-40: VERIFY the deployed reference. A Job has no revisions to inspect, so the image field is
# the only thing checkable -- which is exactly why it has to be a digest to mean anything.
if (-not $WhatIfPreference) {
    $jobAfter = Get-PimArmAcaJob -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName -ErrorAsNull
    $running = if ($jobAfter) { "$(@($jobAfter.properties.template.containers)[0].image)" } else { '' }
    $v = Test-PimImageDeployed -Expected $image -Running "$running".Trim()
    if (-not $v.ok) { throw "job '$JobName': $($v.reason)" }
    Note "image verified: $($v.reason)"

    # 🔴 BUG-71b -- THE IMAGE CHECK ABOVE PASSES ON A JOB THAT FAILED TO PROVISION, and that is
    # exactly how this defect survived a full day unnoticed. The broken ca-pim-downlink-s6 carried
    # the CORRECT pinned digest in its image field while provisioningState was 'Failed' -- because
    # the field records what ARM was ASKED to run, not what it managed to run. So the deploy printed
    # "image verified", then "Done.", and exited 0 over a job that could never execute.
    # A deploy that cannot say whether the thing it deployed came up is not a deploy gate.
    $jobProv = Get-PimArmAcaJob -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName -ErrorAsNull
    $prov = if ($jobProv) { "$($jobProv.properties.provisioningState)".Trim() } else { '' }
    if (-not $prov) { throw "job '$JobName': could not read provisioningState -- refusing to report a deploy as successful when its outcome is unknown." }
    if ($prov -ne 'Succeeded') {
        throw ("job '$JobName' deployed but provisioningState='$prov' (expected 'Succeeded'). " +
               'The job exists and will NEVER execute. Most common cause: the identity used for the ' +
               'registry pull has no AcrPull on the ACR -- see BUG-71 above.')
    }
    Note "provisioningState verified: $prov"
}

# --- NO LEFTOVER SECRETS (lead 2026-09-18, measured on RIDE: "legacy leftovers are not allowed") -----------------------
# An update leaves every secret the definition does not list IN PLACE. So after a redeploy with the PLAIN -BaselineUrl,
# the retired SAS transport's 'pim-baseline-url' (a SAS link -- a standing credential to the managing tenant's bundle store)
# stayed on the job, referenced by nothing. Every secret the deployed definition does not reference is removed here, and
# the removal is READ BACK: a secret still listed fails the deploy.
if ($WhatIfPreference) {
    Write-Host "WHATIF> job secrets (ARM listSecrets + PATCH configuration.secrets): every secret on $JobName not referenced by this definition ($(@($plan.secretNames) -join ', ')) would be removed, pim-baseline-url always" -ForegroundColor Yellow
} else {
    # Invoke-PimDownlinkJobSecretCleanup (engine\msp\PIM-DownlinkJob.ps1, offline-tested with a mocked seam) decides and
    # reads back; this seam answers its two requests over ARM REST (100.41: no az) -- 'secret list' = the job's secret
    # names, 'secret remove' = Remove-PimArmAcaJobSecret (every other secret kept, WITH its value).
    $restSeam = {
        param([string[]]$AzArgs)
        $j = @($AzArgs) -join ' '
        $exit = 0; $out = ''
        try {
            if ($j -match '^containerapp job secret list\b') {
                $names = @(Get-PimArmAcaJobSecretNames -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName)
                $out = '[' + ((@($names) | ForEach-Object { '{"name":' + (ConvertTo-Json -InputObject "$_" -Compress) + '}' }) -join ',') + ']'
            } elseif ($j -match '^containerapp job secret remove\b') {
                $i = [Array]::IndexOf(@($AzArgs), '--secret-names')
                $sn = if ($i -ge 0 -and $i + 1 -lt @($AzArgs).Count) { "$(@($AzArgs)[$i + 1])" } else { '' }
                if (-not $sn) { throw 'no secret name to remove' }
                Remove-PimArmAcaJobSecret -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName -SecretName $sn
            } else { throw "unexpected request: $j" }
        } catch { $exit = 1; $out = "$($_.Exception.Message)" }
        [pscustomobject]@{ exitCode = $exit; output = $out }
    }
    $clean = Invoke-PimDownlinkJobSecretCleanup -JobName $JobName -ResourceGroup $ResourceGroup -SubscriptionId $script:sub `
                 -Referenced @($plan.secretNames) -Az $restSeam -Log { param($m) Note $m }
    if (-not $clean.ok) { throw "secrets on ${JobName}: $($clean.reason)" }
    if (@($clean.removed).Count) { Step "secrets on ${JobName}: $($clean.reason)" } else { Note "secrets on ${JobName}: $($clean.reason)" }
}

# After CREATE, grant the Job's MI AcrPull on the ACR (so the MI pull works) +
# (best-effort) the SQL contained DB user the engine needs. Mirrors Setup-PimContainers.
if ($plan.action -eq 'create' -and -not $WhatIfPreference -and -not "$IdentityResourceId".Trim()) {
    try {
        $jobMi = Get-PimArmAcaJob -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName -ErrorAsNull
        $oid = if ($jobMi) { "$($jobMi.identity.principalId)" } else { '' }
        $acrRes = Get-PimArmAcr -SubscriptionId $script:sub -Name $AcrName -ErrorAsNull
        $acrId = if ($acrRes) { "$($acrRes.id)" } else { '' }
        if ("$oid".Trim() -and "$acrId".Trim()) {
            # 🪤 BUG-71c -- this used to swallow its own failure and then print "granted ... AcrPull"
            # unconditionally, so the log CLAIMED a grant that had not happened. Measured: the system MI
            # of the broken job held no role on the ACR at all, while the deploy log said otherwise.
            # Report what actually happened.
            $grantErr = ''
            try { [void](New-PimArmRoleAssignment -SubscriptionId $script:sub -Scope $acrId -PrincipalId "$oid".Trim() -PrincipalType ServicePrincipal -Role AcrPull) }
            catch { $grantErr = "$($_.Exception.Message)" }
            if (-not $grantErr) { Note "granted the Job's system MI AcrPull on $AcrName" }
            else { Warn "AcrPull grant to the Job's system MI FAILED ($grantErr) -- the job will not be able to pull." }
        }
    } catch { Warn "post-create grant skipped: $($_.Exception.Message)" }
}

# --- BUG-75: THE JOB'S IDENTITY NEEDS A SQL CONTAINED USER, AND A WARNING IS NOT A GRANT --------
# 🔴 WHAT ACTUALLY HAPPENS AT RUNTIME, measured on the first successful downlink pull:
#   * GRAPH authenticates as the engine SPN -- Get-PimRestToken reads $env:AZURE_CLIENT_SECRET.
#   * SQL does NOT. PIM-SqlStore.ps1 resolves its credential from $global:PIM_ClientSecret, which
#     is DELIBERATELY never populated from env ("Use-Cfg deliberately has no PIM_ClientSecret
#     entry" -- Setup-PimContainers' own comment). So $explicitSpn is FALSE, the SPN branch is
#     skipped, and the connection falls through to MANAGED IDENTITY.
# The job's MI therefore needs a contained DB user -- and nothing granted it one, so the engine
# apply died on `Preflight FAILED: cannot reach the desired store: no SELECT 1`. Azure SQL reports
# that as "the server is not currently configured to accept this token", which BUG-34's comment in
# that same function already warns "reads like a permissions problem rather than 'you
# authenticated to the wrong directory'".
# 🪤 THIS EXACT STEP WAS ALREADY KNOWN AND ONLY WARNED ABOUT: the block above used to print "SQL:
# add the Job's MI as a contained DB user ... like the worker matrix". Worse, that warning sat in a
# branch guarded by `-not $IdentityResourceId`, so on the path a fixed deploy now takes it never
# printed at all. A warning nobody sees, in a branch that does not run, is indistinguishable from
# having no check -- which is why this is an ACTION, and why it fails loudly instead.
# 📌 Setup-PimContainers already does exactly this for ca-pim-manager and ca-pim-tick. The downlink
# job was simply missing it, which is why those two reach SQL and this one never could.
# --- §71.10: THE SYSTEM IDENTITY GETS WHAT THE TICK'S SYSTEM IDENTITY HAS ------------------------------------
# Graph: the engine's app-role set (Grant-PimMiGraph throws on a role that did not land -- BUG-45).
# SQL: membership of the SQL admin group, members-only (never creates the group, never moves the admin), the
# same step Deploy-PimUpdateJob runs for the updater. A member needs no contained user.
$sqlGroupMember = $false
if (-not $WhatIfPreference -and $engineSystemMi) {
    $jobSys = Get-PimArmAcaJob -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName -ErrorAsNull
    $jobOid = if ($jobSys) { "$($jobSys.identity.principalId)".Trim() } else { '' }
    if (-not $jobOid) { throw "$JobName has no SYSTEM identity after the deploy -- the engine could not authenticate; refusing to report success." }
    if (Get-Command Resolve-PimMiAppId -ErrorAction SilentlyContinue) { [void](Resolve-PimMiAppId -ObjectId $jobOid -What $JobName) }   # BUG-44: wait for the SP to exist
    if ($SkipGraphGrant) { Warn "-SkipGraphGrant: $JobName's system identity ($jobOid) gets NO Graph app-roles here -- the pull cannot read the tenant's domain and the engine apply cannot write the directory until they are granted." }
    else {
        Step "Graph app-roles for $JobName's system identity ($jobOid)"
        $tidForGrant = $subTenant   # the subscription's own tenant, read over ARM above
        Grant-PimMiGraph -MiObjectId $jobOid -SubscriptionId $SubscriptionId -ExpectedTenantId $tidForGrant -RoleSet Engine
        Note "Graph app-roles ensured for $JobName"
    }
    if (-not $SkipSqlAdminGroup -and "$SqlServerFqdn".Trim()) {
        Step "SQL admin group '$SqlAdminGroupName' -- $JobName's system identity"
        try {
            . (Join-Path $here '_PimSqlAdminGroup.ps1')
            $inv = New-PimSqlAdminGroupInvokers -SubscriptionId $SubscriptionId
            $srvRes = Resolve-PimSqlServerFromFqdn -Arm $inv.Arm -SubscriptionId $SubscriptionId -Server "$SqlServerFqdn"
            if (-not $srvRes) { throw "SQL server '$SqlServerFqdn' is not in subscription $SubscriptionId." }
            $gr = Invoke-PimSqlAdminGroupStep -Graph $inv.Graph -Arm $inv.Arm -TenantId $inv.TenantId -SubscriptionId $SubscriptionId `
                      -ResourceGroup $ResourceGroup -SqlResourceGroup $srvRes.resourceGroup -SqlServerName $srvRes.name `
                      -GroupName $SqlAdminGroupName -UpdateJobName '' -ExtraMembers @([pscustomobject]@{ objectId = $jobOid; label = "downlink job identity $JobName" }) `
                      -Mode membersOnly -NoDiscovery
            Write-PimSqlAdminGroupReport -Result $gr
            if ($gr.ok -and -not $gr.blocked) { $sqlGroupMember = $true; Note "$JobName's identity is a member of '$SqlAdminGroupName', the Entra admin of $($srvRes.name) -- no contained user needed" }
            elseif ($gr.ok) { Note "not on the group model -- $JobName reaches SQL through a contained database user (next step)" }
            else {
                # SEC-32: the SQL admin group is created ROLE-ASSIGNABLE (tier 0); only a Privileged Role Administrator or an identity
                # holding Graph RoleManagement.ReadWrite.Directory can change its members -- a deploy identity normally holds neither.
                $why = if ($gr.roleAssignable -eq $true -or $gr.permissionDenied) {
                    "'$SqlAdminGroupName' is ROLE-ASSIGNABLE (tier 0): only a Privileged Role Administrator or an identity with RoleManagement.ReadWrite.Directory can add members, and this deploy identity cannot"
                } else { "membership could not be added ($(@($gr.problems) -join '; '))" }
                Warn "$JobName's identity ($jobOid) was NOT made a member of '$SqlAdminGroupName' -- $why. It reaches SQL through its own contained database user instead (next step). To use the group model, have a Privileged Role Administrator add $jobOid to the group."
            }
        } catch { Warn "SQL admin group step skipped: $($_.Exception.Message) -- the contained-user step below still runs" }
    }
}

if (-not $WhatIfPreference -and -not $SkipSqlGrant -and -not $sqlGroupMember -and "$SqlServerFqdn".Trim()) {
    $sqlAdminGiven = ("$SqlAdminClientId".Trim() -and ("$SqlAdminClientSecret".Trim() -or "$SqlAdminCertThumbprint".Trim())) -or [bool]$UseSignedInAccount
    if (-not $sqlAdminGiven) {
        throw ("REFUSING to finish: $JobName is configured for SQL ($SqlServerFqdn/$SqlDatabase) but no SQL admin " +
               'credential was supplied, so its identity cannot be granted a contained DB user -- and without one the ' +
               'engine apply fails every run with "cannot reach the desired store". Pass -SqlAdminClientId plus ' +
               '-SqlAdminClientSecret or -SqlAdminCertThumbprint, or -SkipSqlGrant if you are granting it another way.')
    }
    # WHICH identity actually connects: the user-assigned MI when one is attached (that is what the
    # container presents), else the job's system-assigned MI.
    $miAppId = ''
    if ("$IdentityResourceId".Trim() -and -not $engineSystemMi) {
        $miRes = Get-PimArmIdentity -ResourceId "$IdentityResourceId" -ErrorAsNull
        $miAppId = if ($miRes) { "$($miRes.properties.clientId)" } else { '' }
    } else {
        $jobId2 = Get-PimArmAcaJob -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName -ErrorAsNull
        $oid2 = if ($jobId2) { "$($jobId2.identity.principalId)" } else { '' }
        # BUG-44: a just-created identity is eventually consistent in the directory; this retries.
        if ("$oid2".Trim() -and (Get-Command Resolve-PimMiAppId -ErrorAction SilentlyContinue)) {
            # 🪤 The parameter is -ObjectId (+ -What). This call named -PrincipalId, which does not exist, so the
            # system-identity branch threw "A parameter cannot be found" the first time anything reached it
            # (§71.10, 2026-09-15 -- unreachable before, because every deploy passed a user-assigned MI).
            $miAppId = Resolve-PimMiAppId -ObjectId "$oid2".Trim() -What $JobName
        }
    }
    if (-not "$miAppId".Trim()) { throw "could not resolve the app id of $JobName's managed identity -- cannot grant it SQL, and the job would fail on every run." }
    # 🪤 BUG-33's lesson, applied before the fact: _PimSetupShared USES New-PimSqlConnection and
    # Get-PimRestToken but does not load them, and a caller that skips the token provider presents
    # NO credential -- Azure SQL then reports `Login failed for user ''`, which points at
    # permissions and wastes the search there. Load them here, and say so if they are missing.
    foreach ($dep in @('engine\_shared\PIM-Rest.ps1','engine\_shared\PIM-SqlStore.ps1')) {
        $depPath = Join-Path $solRoot $dep
        if (-not (Test-Path -LiteralPath $depPath)) { throw "required for the SQL grant and not found: $depPath" }
        # never re-load PIM-Rest when it is already loaded: that would reset its token cache (a browser sign-in made
        # earlier in this run would be asked for again)
        if ($dep -match 'PIM-Rest\.ps1$' -and (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { continue }
        . $depPath
    }
    Step "granting $JobName's identity ($miAppId) a contained user on $SqlServerFqdn/$SqlDatabase"
    $grant = @{
        DbUserName = $JobName; MiAppId = "$miAppId".Trim()
        SqlServerFqdn = $SqlServerFqdn; SqlDatabase = $SqlDatabase; TenantId = $TenantId
        SqlAdminClientId = $SqlAdminClientId
    }
    if ($UseSignedInAccount) { $grant.Remove('SqlAdminClientId'); $grant['UseSignedInAccount'] = $true }
    elseif ("$SqlAdminClientSecret".Trim())    { $grant['SqlAdminClientSecret']   = $SqlAdminClientSecret }
    elseif ("$SqlAdminCertThumbprint".Trim()) { $grant['SqlAdminCertThumbprint'] = $SqlAdminCertThumbprint }
    Grant-PimMiSql @grant
    Note "SQL contained user ensured for $JobName"
}

# ---- START one on-demand execution (verification) ------------------------------
if ($Start) {
    Step "Start one on-demand execution of $JobName"
    Invoke-DownlinkJobOp -Operation "POST $(Get-DownlinkJobPath)/start" -What "start job $JobName" -Do {
        $exec = Start-PimArmAcaJob -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName
        if (-not "$exec".Trim()) { throw "starting job '$JobName' FAILED: $($global:PimSetupRestLastError)" }
        Note "execution: $exec"
    } | Out-Null
    # (no backticks inside this string: "`a" is the BELL escape, and it ate the 'a' of 'az' in the live log)
    Note "execution queued. Verify with: -Verify  (or: az containerapp job execution list -g $ResourceGroup -n $JobName)"
}

Step 'Done.'
Write-Host ("Trigger: {0} fires '{1}' (UTC) in env {2}; the PULL CADENCE is set in this tenant's Manager (Job schedule > Managed-tenant pull; daily when nothing is set), and the next trigger pulls once because of this deploy. Fire now: -Start ; verify: -Verify ; remove: -Unregister" -f $JobName, $Cron, $EnvName) -ForegroundColor Green

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
    # last execution name + status (newest first): ONE ARM list (100.41, no az), sorted in PowerShell by start time --
    # names and statuses from the same call, so they cannot disagree.
    $execs = @()
    try { foreach ($x in @(Get-PimArmAcaJobExecutions -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName)) { if ($x) { $execs += $x } } } catch {}
    $sorted = @($execs | Where-Object { $_ } | Sort-Object { try { [datetime]$_.properties.startTime } catch { [datetime]::MinValue } } -Descending)
    # 🔑 THE CADENCE GATE: the trigger fires every 5 minutes and most executions are a one-line "[cadence] SKIPPED:" exit 0
    # (PIM-JobCadence.ps1). Verifying the NEWEST execution would judge a skip, which never carries downlink evidence -- so
    # walk back (newest first, at most 12) to the newest execution that actually ran the pull, and say how many skips
    # lay in front of it.
    $execName = ''; $status = ''; $log = ''; $skips = @()
    foreach ($e in @($sorted | Select-Object -First 12)) {
        $n = "$($e.name)"; $st = "$($e.properties.status)"; $lg = ''
        # the execution's console lines from the environment's Log Analytics workspace (az's `job logs show` replacement)
        if ("$n".Trim()) { try { $lg = @(Get-PimArmAcaJobLogs -SubscriptionId $script:sub -ResourceGroup $ResourceGroup -Name $JobName -Execution "$n" -Tail 200) -join "`n" } catch {} }
        $sk = Get-PimJobCadenceSkipFromLog -LogText $lg
        if ($sk.skipped -and $st -eq 'Succeeded') { $skips += "$n ($($sk.code))"; continue }
        $execName = $n; $status = $st; $log = $lg; break
    }
    $verdict = Get-PimDownlinkJobExecutionVerdict -Status "$status" -LogText "$log"
    if (-not "$execName".Trim() -and $skips.Count) {
        $verdict['reason'] = "NO pull ran in the last $($skips.Count) execution(s) -- each was a cadence skip ($($skips -join ', ')). Use the Manager's Job schedule > Run pull now, or redeploy (a deploy runs the pull once), then -Verify again."
    } elseif ($skips.Count) { $verdict['reason'] = "$($verdict['reason']) [newest pull: $execName; $($skips.Count) newer cadence skip(s) passed over]" }
    $verdict['execution'] = "$execName"
    $verdict['status']    = "$status"
    $verdict['cadenceSkips'] = @($skips)
    return $verdict
}
