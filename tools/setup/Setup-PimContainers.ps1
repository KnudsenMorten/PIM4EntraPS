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
    # OPTIONAL explicit sign-in. Without these the script uses whatever az context is already
    # active -- right when a human runs it, wrong for an unattended estate run, where each step
    # runs in its OWN process and inherits no context at all. Supply them and the script signs
    # in itself, into an isolated az profile.
    [string]$AdminAppId,
    [string]$AdminSecret,
    # SEC-11: cert auth, so the deploy identity can follow the repo-root rule ("never use client
    # secrets"). This was the ONLY setup script without it -- New-PimHostingPrerequisites and
    # Build-PimManagerImage both take a PEM -- which meant a cert-only operator could pass no
    # identity at all and INFRA silently fell back to the AMBIENT az context: the very hole
    # SS34.2c closed for secret-holders. The secret path stays for community/local callers.
    [string]$AdminCertPem,                             # PEM (key+cert) that `az login --certificate` wants
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
    # Resource id of a USER-assigned identity that already holds AcrPull on $AcrName
    # (New-PimHostingPrerequisites creates `id-pim-<token>` and grants it). Preferred: an app's
    # SYSTEM-assigned identity cannot pull its own FIRST image, because that identity does not
    # exist until the app is created -- which is why this script previously fell back to the
    # registry ADMIN account. When this is supplied no admin credential is used, or needed.
    # Omit it to keep the legacy admin-credential path (community/VM deployments, and any
    # registry that already has admin enabled).
    [string]$RegistryIdentityResourceId,

    # --- SQL (MI-only) ---
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase    = 'PimPlatform',
    # SQL AAD-admin SPN (used ONLY here to CREATE the contained MI users; never stored in apps)
    [Parameter(Mandatory)][string]$SqlAdminClientId,
    # ONE of these two -- see Grant-PimMiSql. A cert-only tenant (any real customer, per the
    # repo-root rule) could not deploy at all while the secret was Mandatory.
    [string]$SqlAdminClientSecret,
    [string]$SqlAdminCertThumbprint,

    # --- Engine SPN identity (IMP-08) ----------------------------------------
    # The engine authenticates to Graph as ITS OWN SPN -- never as the container's managed
    # identity. Passing nothing here is what caused the hosted 403s: with no PIM_ClientId the
    # engine took Get-PimRestToken's "MI is plan A" branch and ran as the container identity,
    # which exists for SQL and holds ZERO Graph app-roles. Measured in EFIF: engine SPN 100
    # app-roles, pim-tick and pim-manager 0, every hosted Graph call 403
    # Authorization_RequestDenied. MI remains the identity for SQL only.
    # CREDENTIAL ORDER (operator, 2026-08-12): CERTIFICATE preferred, client secret as fallback.
    # A container has no cert store, so the estate uses the secret path in practice -- the cert
    # path is what a VM/mgmt-box deployment uses.
    [string]$EngineClientId,
    [string]$EngineCertThumbprint,
    [string]$EngineClientSecret,

    # --- Mail sender (IMP-06a) -----------------------------------------------
    # UPN of the shared sender mailbox the notify path sends AS. Optional, and deliberately so:
    # an environment with no Exchange plan cannot have one, and refusing to deploy over that
    # would block the whole stack for a mail-only gap. But an UNSET sender is silent -- the
    # notify path renders the mail and returns without sending (PIM-Notify.ps1 L201, warning
    # only) while account creation and TAP minting still report success. So when it is not
    # supplied, this script SAYS SO in the deploy output rather than leaving it to be discovered
    # when a TAP never arrives. Initialize-PimMailSender.ps1 is what normally provides it.
    [string]$MailSender,

    # --- Log Analytics (BUG-37) ----------------------------------------------
    # The workspace New-PimHostingPrerequisites already created (`law-pim-<token>`). ACA REQUIRES
    # a workspace, and if it is not given one it silently GENERATES its own
    # (`workspace-<rg-ish><random>`) -- so the environment ends up with two: the intended one,
    # empty and paid for, and an auto-created one holding every log. Measured twice on
    # test1intr2ig798, and it is why the first log queries of a fresh deploy come back empty:
    # they run against the workspace we created, not the one ACA is writing to.
    # Blank = do not pass one, which means ACA generates it -- WARNED about loudly below rather
    # than left to be discovered later.
    [string]$LogAnalyticsWorkspaceName = '',
    [string]$LogAnalyticsResourceGroup = '',              # defaults to -ResourceGroup

    # --- REACHABILITY (BUG-49). The deploy used to build an ISLAND ------------
    # The spoke VNet above is created isolated and nothing ever peered it, and no name was ever
    # published for the environment -- so a deploy could finish with every resource-level check
    # green and a Manager that had no route from anywhere and an FQDN that resolved nowhere.
    # Measured live on the production environment, which was reported as LIVE for a day with a
    # GUI nobody could open. Blank hub = skip peering, and SAY SO rather than pass over it.
    [string]$HubVnetName            = '',   # the VNet the CLIENTS live on (e.g. the platform hub)
    [string]$HubVnetResourceGroup   = '',
    [string]$HubVnetSubscriptionId  = '',   # defaults to -SubscriptionId (same-sub hub)
    # Where the Azure Private DNS zone for the ACA default domain is created. Defaults to the
    # HUB's resource group -- a connectivity zone belongs with the connectivity, not inside a
    # per-environment RG that a redeploy might replace.
    [string]$PrivateDnsResourceGroup = '',
    [switch]$SkipPrivateDns,

    # --- AZURE RBAC for the workload identities (BUG-51) ----------------------
    # The deploy granted these identities their GRAPH app-roles and NO ARM rights, so PIM's
    # entire Azure half was blind: `azure-scopes=0 azure-rbac-roles=0` next to a perfectly
    # healthy directory half. Reader at the subscription is the intended standing privilege;
    # a management-group scope is deliberately opt-in (it is a wider grant).
    [string[]]$AzureRbacRoles           = @('Reader'),
    [string]$AzureRbacManagementGroupId = '',
    [switch]$SkipAzureRbac,
    [switch]$RequireAzureRbac,          # make a failed role assignment fail the deploy

    # --- on-prem/AD DNS (hub clients resolve the env FQDN here); blank = skip ---
    [string]$DnsServer      = '',
    # --- persistent-SQL enforcement (REQUIREMENTS S5): disable serverless auto-pause ---
    [string]$SqlResourceGroup,                            # RG of the SQL server (for auto-pause assert)
    [switch]$SkipPersistentSqlCheck,

    # --- HOW THE SCHEDULE RUNS (ESTATE-06) -----------------------------------
    # 'always-on' : the historical six-app worker matrix. Every app sits at minReplicas 1, so
    #               it is ~3 vCPU / 6 GiB running 24/7 per tenant -- ~$205-230/environment/month
    #               -- to run a timer loop whose delta scopes fire every 15-60 MINUTES.
    # 'cron'      : ONE scheduled ACA Job runs `Start-PimScheduler -Once` on -TickCron. The tick
    #               already decides what is due (Test-PimJobDue), so the SAME job schedule drives
    #               it -- deltas, queue-apply, reminders, discovery, the daily engine-full. A
    #               5-minute cron tick is therefore FASTER than the always-on matrix, and it fits
    #               inside the ACA free grant (180,000 vCPU-seconds per subscription per month),
    #               so it costs ~$0. Framework DOCS/REQUIREMENTS.md §10.0d.
    # ONE job, not one per domain, is deliberate: the single-runner lease (BUG-36) is global, so
    # parallel domain jobs would simply refuse each other. Serialised-and-cheap beats
    # parallel-and-contending, and an overrun tick is skipped, not doubled.
    [ValidateSet('always-on','cron')][string]$WorkerMode = 'always-on',
    [string]$TickCron        = '*/5 * * * *',     # UTC, 5 fields
    [string]$TickJobName     = 'ca-pim-tick',
    [int]$TickReplicaTimeout = 3600,              # a full reconcile must fit inside this
    # Manager replicas. 0 = SCALE TO ZERO: the GUI costs nothing while nobody is using it and
    # cold-starts on the first request. Nothing is lost by being asleep -- the Manager is a
    # read/write front end over SQL, not a listener that could miss an event.
    [int]$ManagerMinReplicas = 1,

    # --- the worker matrix: deploy as many/few as you want -------------------
    # Ignored when -WorkerMode cron (the tick Job replaces the scheduler workers).
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
# Build-PimDownlinkJobArgs / Test-PimDownlinkJobCron -- the PURE, already-offline-tested
# `az containerapp job` argument builder. Reused rather than duplicated: one way to construct a
# scheduled Job, and it already refuses inline secrets and validates the cron expression.
. "$solRoot\engine\_shared\PIM-DownlinkJob.ps1"

Show-PimSetupBanner -ScriptName 'Setup-PimContainers' -SolutionRoot $solRoot
$Location = Assert-PimSetupRegion -Location $Location   # West Europe / Denmark East only; refuse France

# BUG-40: this is the TAG reference -- provenance for humans and logs only. What actually gets
# deployed is $image, which is re-pointed at the immutable DIGEST once there is an az context to
# resolve it with (see "Resolve the image tag to its digest" below). Deploying the tag is what
# let a rebuilt image go un-pulled while every step reported success.
$imageTagRef = "$AcrName.azurecr.io/$ImageRepo`:$ImageTag"
$image = $imageTagRef
$subnetId = "/subscriptions/$SubscriptionId/resourceGroups/$VnetResourceGroup/providers/Microsoft.Network/virtualNetworks/$VnetName/subnets/$SubnetName"

# ESTATE-06: in cron mode the scheduler WORKERS are replaced by one scheduled Job, so the app
# set collapses to the Manager alone. Done here (not by asking the caller to pass -Workers)
# so the mode is a single switch and the two shapes cannot drift apart.
if ($WorkerMode -eq 'cron') {
    $cronCheck = Test-PimDownlinkJobCron -Cron $TickCron
    if (-not $cronCheck.ok) { throw "-TickCron is not a valid 5-field cron expression: $($cronCheck.reason)" }
    $mgrOnly = @($Workers | Where-Object { $_.entry -eq 'manager' })
    if (-not $mgrOnly.Count) { throw "-WorkerMode cron still needs a manager entry in -Workers (the GUI front end)." }
    $Workers = $mgrOnly
}

Step "Target: sub $SubscriptionId / RG $ResourceGroup / env $EnvName / $Location"
Note "image=$image  subnet=$SubnetName ($SubnetPrefix)  sql=$SqlServerFqdn/$SqlDatabase"
Note ("mode: $WorkerMode" + $(if ($WorkerMode -eq 'cron') { "  tick='$TickCron' -> $TickJobName" } else { '' }))
Note ("apps: " + (($Workers | ForEach-Object { $_.name }) -join ', ') + "  (manager min-replicas $ManagerMinReplicas$(if ($ManagerMinReplicas -eq 0) { ' = scale-to-zero' } else { '' }))")
if ($WhatIfPreference) { Note 'WhatIf — plan only, nothing created.'; }

# SEC-11: exactly ONE credential, and refusing both is not pedantry -- silently preferring one
# would make a run that THOUGHT it was cert-authenticating actually use a secret. Same contract as
# New-PimHostingPrerequisites / Build-PimManagerImage, so the three sign-ins cannot disagree.
if ($AdminSecret -and $AdminCertPem) { throw 'pass EITHER -AdminSecret OR -AdminCertPem, not both.' }
if ($AdminAppId -and ($AdminSecret -or $AdminCertPem)) {
    $cfgDir = Join-Path $env:TEMP "azcfg-containers-$AcrName"
    New-Item -ItemType Directory -Force $cfgDir | Out-Null
    $env:AZURE_CONFIG_DIR = $cfgDir
    if ($AdminCertPem) {
        if (-not (Test-Path $AdminCertPem)) { throw "certificate PEM not found: $AdminCertPem" }
        Step "az login (service principal, CERTIFICATE) -> tenant $TenantId"
        az login --service-principal -u $AdminAppId --certificate $AdminCertPem --tenant $TenantId --only-show-errors -o none
    } else {
        Step "az login (service principal, client secret) -> tenant $TenantId"
        az login --service-principal -u $AdminAppId -p $AdminSecret --tenant $TenantId --only-show-errors -o none
    }
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az login failed for tenant $TenantId (exit $LASTEXITCODE)." }
}
az account set --subscription $SubscriptionId 2>$null | Out-Null

# FAIL FAST. Without this the script ran on with NO usable az context: every call failed
# quietly, `env static IP =` printed empty, and the run only died four steps later inside a SQL
# grant with "Cannot bind argument to parameter 'MiAppId' because it is an empty string" -- an
# error that points at the wrong thing entirely. Prove the context BEFORE creating anything.
$activeSub = az account show --query id -o tsv --only-show-errors 2>$null
if (-not $activeSub -or $activeSub -ne $SubscriptionId) {
    throw ("No usable az context for subscription $SubscriptionId (active: '$activeSub'). " +
           "Pass -AdminAppId with -AdminCertPem (or -AdminSecret) so this script can sign in, " +
           "or run 'az login' first. " +
           "Refusing to continue -- every subsequent az call would fail silently.")
}
Note "az context OK -> subscription $activeSub"

# --- BUG-40: resolve the image tag to its digest, and deploy THAT --------------
# A tag is a mutable pointer. Rebuilding `pim-manager:2.4.245` moves it to new content, but the
# container app's image FIELD is unchanged -- so ARM sees no change, makes no revision, and the
# platform keeps running what it already pulled. Measured live: a code fix built + rolled under
# the same tag reported success and the next two scheduled executions ran the OLD image.
# Pinning the digest makes new content a CHANGED FIELD, which is the only thing ARM reacts to.
if (-not $WhatIfPreference) {
    Step "Resolve $ImageRepo`:$ImageTag -> digest (BUG-40: deploy content, not a mutable tag)"
    $imageDigest = Resolve-PimAcrImageDigest -AcrName $AcrName -Repository $ImageRepo -Tag $ImageTag
    $image = New-PimImageReference -Registry "$AcrName.azurecr.io" -Repository $ImageRepo -Digest $imageDigest
    Note "tag $ImageTag => $imageDigest"
    Note "deploying $image"
} else {
    Note "WhatIf -- tag would be resolved to a digest here; plan shows the tag reference $imageTagRef."
}

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
        # BUG-37: hand ACA the workspace we already created. Without --logs-workspace-id it
        # GENERATES one and writes every log there, leaving `law-pim-<token>` empty and billed --
        # and leaving anyone reading logs pointed at the wrong workspace. The key is a secret:
        # it is passed to az and never printed.
        $envCreateArgs = @('containerapp','env','create','-g',$ResourceGroup,'-n',$EnvName,
                           '--location',$Location,
                           '--infrastructure-subnet-resource-id',$subnetId,'--internal-only','true',
                           '--enable-workload-profiles','--logs-destination','log-analytics')
        if ("$LogAnalyticsWorkspaceName".Trim()) {
            $lawRg  = $(if ("$LogAnalyticsResourceGroup".Trim()) { $LogAnalyticsResourceGroup } else { $ResourceGroup })
            $lawCid = az monitor log-analytics workspace show -g $lawRg -n $LogAnalyticsWorkspaceName --query customerId -o tsv --only-show-errors 2>$null
            $lawKey = az monitor log-analytics workspace get-shared-keys -g $lawRg -n $LogAnalyticsWorkspaceName --query primarySharedKey -o tsv --only-show-errors 2>$null
            if (-not "$lawCid".Trim() -or -not "$lawKey".Trim()) {
                throw ("Could not read Log Analytics workspace '$LogAnalyticsWorkspaceName' in RG '$lawRg' " +
                       "(customerId='$lawCid', key=$(if ("$lawKey".Trim()) { 'present' } else { 'MISSING' })). " +
                       "Refusing to create the ACA environment without it -- ACA would silently generate a " +
                       "SECOND workspace and write every log there (BUG-37).")
            }
            $envCreateArgs += @('--logs-workspace-id',$lawCid,'--logs-workspace-key',$lawKey)
            Note "logs -> $LogAnalyticsWorkspaceName ($lawCid)"
        } else {
            Write-Warning ("no -LogAnalyticsWorkspaceName given: ACA will GENERATE its own Log Analytics " +
                           "workspace and write every log there. Any workspace you created for this " +
                           "environment will sit empty and still be billed (BUG-37).")
        }
        az @envCreateArgs -o none
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az containerapp env create failed (exit $LASTEXITCODE)." }
    } else { Note 'env exists' }
}
# VERIFY, do not assume: read back which workspace the environment actually logs to. A create that
# quietly fell back to a generated workspace looks identical to a correct one until someone queries
# logs and finds nothing -- which is exactly how BUG-37 surfaced.
if (-not $WhatIfPreference -and "$LogAnalyticsWorkspaceName".Trim()) {
    $envCid = az containerapp env show -g $ResourceGroup -n $EnvName --query "properties.appLogsConfiguration.logAnalyticsConfiguration.customerId" -o tsv 2>$null
    $lawRg2 = $(if ("$LogAnalyticsResourceGroup".Trim()) { $LogAnalyticsResourceGroup } else { $ResourceGroup })
    $wantCid = az monitor log-analytics workspace show -g $lawRg2 -n $LogAnalyticsWorkspaceName --query customerId -o tsv --only-show-errors 2>$null
    if ("$envCid".Trim() -and "$wantCid".Trim() -and "$envCid".Trim() -ne "$wantCid".Trim()) {
        # 🪤 THIS USED TO SAY "delete and recreate it to move the logs", AND THAT WAS WRONG --
        # dangerously so: deleting an ACA environment takes the Manager app and the tick Job with
        # it, and the advice was aimed at a PRODUCTION environment. It was never tested; it was
        # inferred from the create-time behaviour (a create with no workspace generates one).
        # MEASURED 2026-08-10 on mfnpr: `az containerapp env update --logs-destination log-analytics
        # --logs-workspace-id/--logs-workspace-key` moves an EXISTING environment's workspace in
        # place, 8565d575… -> 9b0ed93b…, with no recreate and no downtime.
        # So this now REPAIRS the environment instead of telling the operator to destroy it.
        Write-Warning ("ACA environment '$EnvName' logs to workspace $envCid, NOT the intended " +
                       "'$LogAnalyticsWorkspaceName' ($wantCid) -- repairing it in place (BUG-37).")
        $lawKey2 = az monitor log-analytics workspace get-shared-keys -g $lawRg2 -n $LogAnalyticsWorkspaceName --query primarySharedKey -o tsv --only-show-errors 2>$null
        if (-not "$lawKey2".Trim()) {
            throw ("ACA environment '$EnvName' logs to the WRONG workspace ($envCid) and the shared key for " +
                   "'$LogAnalyticsWorkspaceName' could not be read, so it cannot be repaired. Grant the " +
                   "deploying identity read on that workspace and re-run (BUG-37).")
        }
        az containerapp env update -g $ResourceGroup -n $EnvName `
            --logs-destination log-analytics --logs-workspace-id $wantCid --logs-workspace-key $lawKey2 -o none
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az containerapp env update (BUG-37 log workspace repair) failed (exit $LASTEXITCODE)." }
        # Read back AGAIN -- a repair that reports success and changes nothing is the whole reason
        # this verification block exists in the first place.
        $envCid2 = az containerapp env show -g $ResourceGroup -n $EnvName --query "properties.appLogsConfiguration.logAnalyticsConfiguration.customerId" -o tsv 2>$null
        if ("$envCid2".Trim() -ne "$wantCid".Trim()) {
            throw ("ACA environment '$EnvName' still logs to $envCid2 after the repair (wanted $wantCid). " +
                   "Do NOT assume the logs moved (BUG-37).")
        }
        Note "logs REPAIRED -> $LogAnalyticsWorkspaceName ($envCid2)"
    } elseif ("$envCid".Trim()) {
        Note "logs verified -> $LogAnalyticsWorkspaceName ($envCid)"
    }
}
$envStatic = az containerapp env show -g $ResourceGroup -n $EnvName --query properties.staticIp -o tsv 2>$null
$envDomain = az containerapp env show -g $ResourceGroup -n $EnvName --query properties.defaultDomain -o tsv 2>$null
Note "env static IP = $envStatic   domain = $envDomain"

# --- BUG-49: MAKE THE ENVIRONMENT REACHABLE ----------------------------------
# This is the step whose ABSENCE produced a deployed, healthy-looking, unreachable Manager. It
# runs HERE -- immediately after the environment exists and its static IP is known -- because
# both halves depend on that IP and neither depends on the apps.
#
# Two halves, and BOTH are required. Peering alone gives a client a route to an address it
# cannot name; DNS alone gives it a name it cannot reach.
$hubSubForPeering = $(if ("$HubVnetSubscriptionId".Trim()) { $HubVnetSubscriptionId } else { $SubscriptionId })
if ("$HubVnetName".Trim() -and "$HubVnetResourceGroup".Trim()) {
    Step "Peering: $VnetName <-> $HubVnetName (BUG-49: the spoke is created isolated)"
    Set-PimVnetPeering -SpokeVnetName $VnetName -SpokeResourceGroup $VnetResourceGroup `
        -SpokeSubscriptionId $SubscriptionId -HubVnetName $HubVnetName `
        -HubResourceGroup $HubVnetResourceGroup -HubSubscriptionId $hubSubForPeering
} else {
    # Not a Note. A skipped reachability step that prints quietly is indistinguishable from one
    # that ran, and that is exactly how an unreachable environment gets called deployed.
    Write-Warning ("NO HUB VNET GIVEN (-HubVnetName/-HubVnetResourceGroup): the PIM spoke VNet '$VnetName' is " +
                   "left ISOLATED. The ACA environment is --internal-only, so the Manager will have NO ROUTE " +
                   "from any client and every resource-level check will still report a healthy deploy (BUG-49).")
}

if ($SkipPrivateDns) {
    Write-Warning "  -SkipPrivateDns: the ACA default domain '$envDomain' is NOT published, so the Manager FQDN will not resolve for peered clients (BUG-49)."
} elseif ("$envDomain".Trim() -and "$envStatic".Trim()) {
    $dnsRg = $(if ("$PrivateDnsResourceGroup".Trim()) { $PrivateDnsResourceGroup }
               elseif ("$HubVnetResourceGroup".Trim()) { $HubVnetResourceGroup }
               else { $ResourceGroup })
    # Link BOTH sides: the hub so clients resolve it, and the spoke so anything running inside
    # the PIM VNet (the tick Job calling the Manager) resolves the same name to the same IP.
    $linkVnets = New-Object System.Collections.Generic.List[string]
    $linkVnets.Add((New-PimVnetResourceId -SubscriptionId $SubscriptionId -ResourceGroup $VnetResourceGroup -VnetName $VnetName)) | Out-Null
    if ("$HubVnetName".Trim() -and "$HubVnetResourceGroup".Trim()) {
        $linkVnets.Add((New-PimVnetResourceId -SubscriptionId $hubSubForPeering -ResourceGroup $HubVnetResourceGroup -VnetName $HubVnetName)) | Out-Null
    }
    Step "Private DNS: zone '$envDomain' -> $envStatic (in $dnsRg)"
    Set-PimPrivateDnsZone -EnvDomain $envDomain -StaticIp $envStatic -ResourceGroup $dnsRg `
        -SubscriptionId $SubscriptionId -LinkVnetIds @($linkVnets.ToArray())
} elseif (-not $WhatIfPreference) {
    Write-Warning "  could not read the environment's defaultDomain/staticIp -- skipping the private DNS zone. The Manager FQDN will not resolve (BUG-49)."
}

$acrId = az acr show -n $AcrName --query id -o tsv 2>$null
$useRegistryIdentity = [bool]$RegistryIdentityResourceId
$acrU = $null; $acrP = $null
if ($useRegistryIdentity) {
    Step "Registry auth: USER-ASSIGNED IDENTITY (no admin credential)"
    Note $RegistryIdentityResourceId
} else {
    # Legacy path. `az acr credential show` returns EMPTY unless the registry was created with
    # --admin-enabled, and an empty username/password does not fail loudly -- it produces a
    # container app that cannot pull. Say so here rather than let it surface as a pull error.
    $acrU = az acr credential show -n $AcrName --query username -o tsv 2>$null
    $acrP = az acr credential show -n $AcrName --query "passwords[0].value" -o tsv 2>$null
    if (-not $acrU -or -not $acrP) {
        throw ("Registry '$AcrName' has no admin credentials (admin account not enabled), and " +
               "-RegistryIdentityResourceId was not supplied. Pass the user-assigned identity that " +
               "holds AcrPull (New-PimHostingPrerequisites creates 'id-pim-<token>'), or enable the " +
               "registry admin account. Refusing to create container apps that cannot pull.")
    }
    Step 'Registry auth: admin credentials (legacy path)'
}

# SQL contained-DB-user + Graph app-role grants come from _PimSetupShared.ps1
# (Grant-PimMiSql / Grant-PimMiGraph). A thin local wrapper binds this script's
# SQL coordinates so the worker loop call stays a one-liner.
function Grant-PimMiSqlHere {
    param([string]$DbUserName,[string]$MiAppId)
    $cred = if ($SqlAdminCertThumbprint) { @{ SqlAdminCertThumbprint = $SqlAdminCertThumbprint } }
            else                          { @{ SqlAdminClientSecret   = $SqlAdminClientSecret } }
    Grant-PimMiSql -DbUserName $DbUserName -MiAppId $MiAppId `
        -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId `
        -SqlAdminClientId $SqlAdminClientId @cred
}

# BUG-40: read back what the platform says it is running and compare it to what we deployed.
# The decision is made by the pure Test-PimImageDeployed so it is provable offline; this only
# fetches the string. THROWS on mismatch -- an update that reported success while continuing to
# run the previous image is the exact failure being closed here, and it must not be survivable.
function Assert-PimDeployedImage {
    param(
        [Parameter(Mandatory)][ValidateSet('app','job')][string]$Kind,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Expected
    )
    $q = 'properties.template.containers[0].image'
    $running = if ($Kind -eq 'job') {
        az containerapp job show -g $ResourceGroup -n $Name --query $q -o tsv 2>$null
    } else {
        az containerapp show     -g $ResourceGroup -n $Name --query $q -o tsv 2>$null
    }
    $v = Test-PimImageDeployed -Expected $Expected -Running "$running".Trim()
    if (-not $v.ok) { throw "$Kind '$Name': $($v.reason)" }
    Note "image verified: $($v.reason)"
}

$commonEnv = @(
    "PIM_HOSTED=1","PIM_StorageBackend=sql",
    "PIM_SqlServer=$SqlServerFqdn","PIM_SqlDatabase=$SqlDatabase","PIM_TenantId=$TenantId"
)
# IMP-06a: carry the sender to BOTH the Manager and the tick Job -- $commonEnv feeds the job YAML
# too, and the tick Job is the process that actually mints TAPs and mails them, so a sender that
# reached only the Manager would look configured in the GUI and still never send.
if ("$MailSender".Trim()) {
    $commonEnv += "PIM_MailSender=$("$MailSender".Trim())"
    Note "mail sender: $("$MailSender".Trim())"
} else {
    # Not fatal -- see the -MailSender parameter comment. But it must never be SILENT.
    Note "mail sender: NOT SET -- this environment will RENDER notification mail and not send it (TAP mails will not arrive). Run Initialize-PimMailSender.ps1, or set a 'MailSender' value in pim.Settings."
}

# --- IMP-08: engine SPN identity, certificate preferred, secret as fallback ---------
# The secret is NEVER written as a plain env var. It goes in as an ACA *secret* and is referenced
# by name, so it does not sit in the container spec (or in `az containerapp show`) as clear text.
$engineSecretName = 'pim-engine-client-secret'
$useEngineSecret  = $false
if ("$EngineClientId".Trim()) {
    # 🔴 BUG-74 -- THE CERTIFICATE BRANCH CANNOT WORK IN A CONTAINER, AND IT USED TO BE PREFERRED.
    # This block said "certificate preferred, client secret as fallback", and the comment three
    # lines above it said "a container has no cert store, so the estate uses the secret path in
    # practice". Both cannot be true, and the CODE won: given a thumbprint it took the cert branch
    # every time. Resolve-PimCertificate (PIM-Rest.ps1) searches only Cert:\CurrentUser\My and
    # Cert:\LocalMachine\My -- EMPTY in a Linux container -- so the SPN could never authenticate.
    # MEASURED on the greenfield slave 2026-08-26: ca-pim-tick reports Succeeded every 5 minutes
    # while logging ~15x "SPN token failed: could not acquire a token for database.windows.net".
    # 🪤 And setting PIM_ClientId with an unusable credential is WORSE than setting nothing:
    # Get-PimRestToken takes the Managed Identity branch only when IDENTITY_ENDPOINT is set AND
    # there is NO client id. So a cert-only container gets neither SPN auth (no cert store) nor MI
    # (suppressed by the client id) -- it authenticates as nothing at all, and still deploys green.
    # THIS SCRIPT ONLY EVER DEPLOYS CONTAINERS, so the secret is not a fallback here: it is the
    # only credential that can work. The cert stays correct for mgmt1/VM runs (Setup-PimVM).
    if ("$EngineClientSecret".Trim()) {
        $commonEnv += "PIM_ClientId=$("$EngineClientId".Trim())"
        $useEngineSecret = $true
        # Get-PimRestToken already reads $env:AZURE_CLIENT_SECRET, so no new config mapping is
        # needed -- Invoke-PimEngineCore's Use-Cfg deliberately has no PIM_ClientSecret entry.
        Note "engine identity: SPN $EngineClientId via CLIENT SECRET -> AZURE_CLIENT_SECRET as an ACA secret (the only credential a container can use)"
        if ("$EngineCertThumbprint".Trim()) { Note "  (-EngineCertThumbprint ignored for containers: no cert store in the image)" }
    } elseif ("$EngineCertThumbprint".Trim()) {
        # Deliberately emit NEITHER PIM_ClientId NOR PIM_CertThumbprint, so the container at least
        # falls back to its Managed Identity (which does work for SQL) instead of authenticating as
        # nothing. Loud, because a silent degrade here is what produced a green deploy over a dead engine.
        Warn "engine identity: -EngineCertThumbprint given but a CONTAINER HAS NO CERT STORE -- that credential cannot work here."
        Warn "  Falling back to MANAGED IDENTITY (works for SQL; Graph calls will 403 unless the MI holds the app roles)."
        Warn "  FIX: pass -EngineClientSecret (on the estate: the tenant's own 'Modern-Secret' Key Vault secret)."
    } else {
        Note "engine identity: -EngineClientId given but NO certificate and NO secret -- the engine CANNOT authenticate as the SPN and every Graph call will 403."
    }
} else {
    # Not fatal: a store-only/offline deployment is legitimate. But it must never be silent -- an
    # engine on managed identity looks deployed and cannot read a single user.
    Note "engine identity: NOT SET -- the engine will fall back to MANAGED IDENTITY, which holds no Graph app-roles. Every Graph call will return 403 Authorization_RequestDenied. Pass -EngineClientId with -EngineCertThumbprint or -EngineClientSecret (IMP-08)."
}

function Get-PimContainerEnvYaml {
    # Renders the container `env:` block. A secret is emitted as `secretRef`, never `value`.
    param([string[]]$Pairs, [bool]$WithEngineSecret, [string]$SecretName)
    $lines = @($Pairs | ForEach-Object { $kv = $_ -split '=', 2; "          - { name: $($kv[0]), value: `"$($kv[1])`" }" })
    if ($WithEngineSecret) { $lines += "          - { name: AZURE_CLIENT_SECRET, secretRef: $SecretName }" }
    return ($lines -join "`n")
}
function Get-PimContainerSecretsYaml {
    # Merges the engine secret into whatever secrets the registry mode already needs, so the two
    # cannot overwrite each other's `secrets:` key (only one is allowed per configuration).
    param([bool]$WithAcrPwd, [string]$AcrPwd, [bool]$WithEngineSecret, [string]$SecretName, [string]$SecretValue)
    $items = @()
    if ($WithAcrPwd)       { $items += "{ name: acr-pwd, value: `"$AcrPwd`" }" }
    if ($WithEngineSecret) { $items += "{ name: $SecretName, value: `"$SecretValue`" }" }
    if (-not $items.Count) { return '' }
    return "    secrets: [ $($items -join ', ') ]"
}

foreach ($w in $Workers) {
    Step "Worker '$($w.name)'  entry=$($w.entry)  ingress=$($w.ingress)  jobs='$($w.jobs)'"
    if (-not $PSCmdlet.ShouldProcess($w.name,'deploy')) { continue }

    $envVars = @($commonEnv)
    if ($w.entry -eq 'scheduler' -and "$($w.jobs)".Trim()) { $envVars += "PIM_SCHED_JOBS=$($w.jobs)" }

    # create or update
    $exists = az containerapp show -g $ResourceGroup -n $w.name --query name -o tsv 2>$null
    if (-not $exists) {
        if ($w.entry -eq 'manager') {
            # --system-assigned is kept in BOTH paths: the app still needs its own identity for
            # SQL + Graph. The user-assigned one is attached purely so the registry pull has a
            # principal that already holds AcrPull at create time.
            $createArgs = @(
                'containerapp','create','-g',$ResourceGroup,'-n',$w.name,'--environment',$EnvName,
                '--workload-profile-name','Consumption','--image',$image,
                '--registry-server',"$AcrName.azurecr.io",
                '--ingress','external','--target-port','8080','--transport','http',
                # min-replicas 0 = scale to zero: ACA keeps the HTTP scale rule and cold-starts
                # the Manager on the first request. Safe here because the Manager holds NO state
                # of its own -- it is a front end over the SQL store.
                '--min-replicas',"$ManagerMinReplicas",'--max-replicas','1','--system-assigned')
            if ($useRegistryIdentity) {
                $createArgs += @('--user-assigned',$RegistryIdentityResourceId,
                                 '--registry-identity',$RegistryIdentityResourceId)
            } else {
                $createArgs += @('--registry-username',$acrU,'--registry-password',$acrP)
            }
            if ($useEngineSecret) {
                # As an ACA secret + a secretref env var, so the value never appears in the
                # container spec as clear text.
                $createArgs += @('--secrets', "$engineSecretName=$EngineClientSecret")
                $envVars += "AZURE_CLIENT_SECRET=secretref:$engineSecretName"
            }
            $createArgs += @('--env-vars') + $envVars + @('-o','none')
            az @createArgs
        } else {
            # worker via YAML (reliable command/args array) — same image, scheduler entrypoint
            $envId = az containerapp env show -g $ResourceGroup -n $EnvName --query id -o tsv 2>$null
            $envYaml = Get-PimContainerEnvYaml -Pairs $envVars -WithEngineSecret $useEngineSecret -SecretName $engineSecretName
            # Identity + registry blocks differ by auth mode. With a user-assigned identity there
            # is no REGISTRY secret in this YAML -- but the engine client secret (when that is the
            # credential in use) still has to be declared, so the secrets block is built centrally
            # rather than per-branch: `configuration` allows only ONE `secrets:` key, and having
            # each branch write its own is how one silently overwrites the other.
            $secretsYaml = Get-PimContainerSecretsYaml -WithAcrPwd (-not $useRegistryIdentity) -AcrPwd $acrP `
                             -WithEngineSecret $useEngineSecret -SecretName $engineSecretName -SecretValue $EngineClientSecret
            if ($useRegistryIdentity) {
                # 🪤 `type` MUST be a QUOTED string. In a YAML flow mapping,
                # `{ type: SystemAssigned, UserAssigned, ... }` parses as `type: SystemAssigned`
                # plus a separate null-valued key `UserAssigned` -- so the type silently became
                # SystemAssigned-only and ARM rejected the identity ids with
                # "(InvalidResourceIdentityType) The identity ids are only supported for
                # 'UserAssigned' identity type." The comma is part of the VALUE, not a separator.
                $identityYaml = "identity: { type: `"SystemAssigned, UserAssigned`", userAssignedIdentities: { `"$RegistryIdentityResourceId`": {} } }"
                $registryYaml = "    registries: [ { server: $AcrName.azurecr.io, identity: `"$RegistryIdentityResourceId`" } ]"
            } else {
                $identityYaml = 'identity: { type: SystemAssigned }'
                $registryYaml = "    registries: [ { server: $AcrName.azurecr.io, username: $acrU, passwordSecretRef: acr-pwd } ]"
            }
            if ($secretsYaml) { $registryYaml = "$secretsYaml`n$registryYaml" }
            $y = @"
location: $Location
$identityYaml
properties:
  environmentId: $envId
  workloadProfileName: Consumption
  configuration:
    activeRevisionsMode: Single
$registryYaml
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
    Assert-PimDeployedImage -Kind app -Name $w.name -Expected $image

    # MI -> SQL (SID from appId) + AcrPull + switch registry to MI
    # identity.principalId is the SYSTEM-assigned principal even when a user-assigned identity
    # is also attached (those live under identity.userAssignedIdentities), so SQL + Graph keep
    # targeting the app's own identity in both auth modes.
    $oid = az containerapp show -g $ResourceGroup -n $w.name --query identity.principalId -o tsv 2>$null
    if (-not $oid) {
        # A failed create shows up HERE as an empty identity. Left unchecked it flowed into
        # Grant-PimMiSql and surfaced as "Cannot bind argument to parameter 'MiAppId' because it
        # is an empty string" -- an error that blames the grant for the create's failure. Name
        # the real problem at the point it is detectable.
        throw ("Container app '$($w.name)' has no identity -- it was not created successfully. " +
               "Check the az error above (the container app create step), not this grant.")
    }
    # BUG-44: retry -- the SP behind a just-created identity is eventually consistent. This call
    # site happened to survive because `containerapp create` blocks on provisioning; the tick Job
    # below does not, and that is where the race actually bit.
    $appId = Resolve-PimMiAppId -ObjectId $oid -What $w.name
    Grant-PimMiSqlHere -DbUserName $w.name -MiAppId $appId
    if (-not $useRegistryIdentity) {
        # Legacy path only: move the registry off the admin credential and onto the app's own
        # identity now that it exists and can be granted AcrPull.
        az role assignment create --assignee-object-id $oid --assignee-principal-type ServicePrincipal --role AcrPull --scope $acrId -o none 2>$null
        az containerapp registry set -g $ResourceGroup -n $w.name --server "$AcrName.azurecr.io" --identity system -o none 2>$null
    }
    # In identity mode the registry is ALREADY on the user-assigned identity, which already
    # holds AcrPull. Re-pointing it at the system identity here would undo that and force an
    # extra revision for no gain.
    # Directory app-roles for workers that touch Entra/PIM (everything except a pure
    # read-only manager). Without these the engine 403s on directory reads/writes.
    Grant-PimMiGraph -MiObjectId $oid
    # BUG-51: the Graph grant above covers the DIRECTORY half only. Without an ARM role this
    # identity sees an empty Azure -- azure-scopes=0, and managementGroups list 403s -- while
    # every directory read works perfectly. Same lesson as framework §10.0b, read backwards.
    if ($SkipAzureRbac) { Write-Warning "  -SkipAzureRbac: $($w.name) gets NO ARM rights, so PIM's Azure half will be blind (BUG-51)." }
    else {
        Grant-PimMiAzureRbac -MiObjectId $oid -Name $w.name -SubscriptionId $SubscriptionId `
            -Roles $AzureRbacRoles -ManagementGroupId $AzureRbacManagementGroupId -Required:$RequireAzureRbac
    }
    Note "MI $appId granted SQL (db user [$($w.name)]) + AcrPull + Graph app-roles + Azure RBAC"
}

# --- ESTATE-06: the scheduled tick Job (replaces the always-on worker matrix) ---
# ONE Job runs `Start-PimScheduler -Once` on the cron. The tick itself decides what is due, so
# the SAME job schedule that drove the always-on workers drives this -- and BUG-36's lease makes
# an overrun tick skip rather than double-apply, which is what makes cron safe here at all.
if ($WorkerMode -eq 'cron') {
    Step "Scheduled tick Job '$TickJobName' (cron '$TickCron' UTC)"
    $jobExists = $false
    if (-not $WhatIfPreference) {
        $jn = az containerapp job show -g $ResourceGroup -n $TickJobName --query name -o tsv 2>$null
        if ("$jn".Trim()) { $jobExists = $true }
    }
    # 🪤 YAML, not `--command`. `az ... --command pwsh -NoProfile -File <x> -Once` FAILS with
    # "unrecognized arguments: -NoProfile -File ... -Once": the CLI's parser treats any token
    # starting with '-' as a new OPTION rather than a value, so a command whose arguments carry
    # leading dashes cannot be expressed that way AT ALL. The worker apps above already learned
    # this ("worker via YAML (reliable command/args array)") and a test pins it; the shared
    # Build-PimDownlinkJobArgs did NOT, so it carried the same latent break -- BUG-38, now fixed
    # there too (it renders the same YAML shape via Get-PimDownlinkJobYaml).
    # Same proven YAML shape as the workers, plus the Job's schedule trigger.
    # THIS is the process that runs the engine, so the engine SPN identity matters most here.
    $envYamlJob = Get-PimContainerEnvYaml -Pairs $commonEnv -WithEngineSecret $useEngineSecret -SecretName $engineSecretName
    $jobSecretsYaml = Get-PimContainerSecretsYaml -WithAcrPwd (-not $useRegistryIdentity) -AcrPwd $acrP `
                        -WithEngineSecret $useEngineSecret -SecretName $engineSecretName -SecretValue $EngineClientSecret
    if ($useRegistryIdentity) {
        $jobIdentityYaml = "identity: { type: `"SystemAssigned, UserAssigned`", userAssignedIdentities: { `"$RegistryIdentityResourceId`": {} } }"
        $jobRegistryYaml = "    registries: [ { server: $AcrName.azurecr.io, identity: `"$RegistryIdentityResourceId`" } ]"
    } else {
        $jobIdentityYaml = 'identity: { type: SystemAssigned }'
        $jobRegistryYaml = "    registries: [ { server: $AcrName.azurecr.io, username: $acrU, passwordSecretRef: acr-pwd } ]"
    }
    if ($jobSecretsYaml) { $jobRegistryYaml = "$jobSecretsYaml`n$jobRegistryYaml" }
    $envIdForJob = az containerapp env show -g $ResourceGroup -n $EnvName --query id -o tsv 2>$null
    $jobYaml = @"
location: $Location
$jobIdentityYaml
properties:
  environmentId: $envIdForJob
  workloadProfileName: Consumption
  configuration:
    triggerType: Schedule
    replicaTimeout: $TickReplicaTimeout
    replicaRetryLimit: 1
    scheduleTriggerConfig:
      cronExpression: "$TickCron"
      parallelism: 1
      replicaCompletionCount: 1
$jobRegistryYaml
  template:
    containers:
      - name: $TickJobName
        image: $image
        command: [pwsh]
        args: ["-NoProfile","-File","/app/PIM4EntraPS/tools/pim-scheduler/Start-PimScheduler.ps1","-Once"]
        env:
$envYamlJob
        resources: { cpu: 0.5, memory: 1Gi }
"@
    $jobAction = $(if ($jobExists) { 'update' } else { 'create' })
    Note "job yaml: triggerType=Schedule cron='$TickCron' timeout=${TickReplicaTimeout}s parallelism=1"
    if ($PSCmdlet.ShouldProcess($TickJobName, "$jobAction scheduled job")) {
        $jobTmp = Join-Path $env:TEMP "pim-$TickJobName.yaml"
        Set-Content -LiteralPath $jobTmp -Value $jobYaml -Encoding utf8
        az containerapp job $jobAction -g $ResourceGroup -n $TickJobName --yaml $jobTmp -o none
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az containerapp job $jobAction failed (exit $LASTEXITCODE)." }
        # BUG-40 was MEASURED on this Job: the update succeeded and the next executions still ran
        # the old image. A Job has no revisions to inspect, so the deployed reference is the only
        # thing that can be checked -- which is why it has to be a digest to mean anything.
        Assert-PimDeployedImage -Kind job -Name $TickJobName -Expected $image
        # The Job's SYSTEM identity needs exactly what a worker app needed: a contained DB user
        # and the directory app-roles. Without these the tick starts and then 403s/`Login failed`,
        # which looks like a scheduling problem and is not.
        $jobOid = az containerapp job show -g $ResourceGroup -n $TickJobName --query identity.principalId -o tsv 2>$null
        if (-not "$jobOid".Trim()) {
            throw "Job '$TickJobName' has no system identity -- it was not created as expected; refusing to leave it unable to reach SQL/Graph."
        }
        # BUG-44 was MEASURED here: `az containerapp job create` returns as soon as ARM accepts it,
        # so the identity's SP is typically NOT in the directory yet when this runs. The deploy
        # threw, and everything below -- the SQL user and the Graph app-roles -- never happened.
        # The Job then ran on schedule, every five minutes, reporting Succeeded and doing nothing.
        $jobAppId = Resolve-PimMiAppId -ObjectId $jobOid -What $TickJobName
        Grant-PimMiSqlHere -DbUserName $TickJobName -MiAppId $jobAppId
        Grant-PimMiGraph -MiObjectId $jobOid
        # BUG-51 was MEASURED on THIS identity: the tick ran, the directory half returned
        # entra-roles=146 aus=36 pim-groups=332, and the Azure half returned azure-scopes=0
        # azure-rbac-roles=0. The tick is the workload that actually reconciles, so an
        # Azure-blind tick is the whole Azure feature set silently absent.
        if ($SkipAzureRbac) { Write-Warning "  -SkipAzureRbac: $TickJobName gets NO ARM rights -- the tick will report azure-scopes=0 (BUG-51)." }
        else {
            Grant-PimMiAzureRbac -MiObjectId $jobOid -Name $TickJobName -SubscriptionId $SubscriptionId `
                -Roles $AzureRbacRoles -ManagementGroupId $AzureRbacManagementGroupId -Required:$RequireAzureRbac
        }
        Note "MI $jobAppId granted SQL (db user [$TickJobName]) + Graph app-roles + Azure RBAC"
        Note "fire one now: az containerapp job start -g $ResourceGroup -n $TickJobName"
    }
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
