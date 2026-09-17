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
    # (71.33: no longer Mandatory -- -UseSignedInAccount is the other way. Missing both is refused below, not prompted.)
    [string]$SqlAdminClientId,
    # ONE of these two -- see Grant-PimMiSql. A cert-only tenant (any real customer, per the
    # repo-root rule) could not deploy at all while the secret was Mandatory.
    [string]$SqlAdminClientSecret,
    [string]$SqlAdminCertThumbprint,
    # 71.33: create the contained users as the SIGNED-IN az user (a member of the SQL admin group).
    [switch]$UseSignedInAccount,

    # --- Support access to the store (operator, 2026-09-12) -------------------
    # The principal an operator uses to TROUBLESHOOT a customer's PIM store from outside:
    # *"so i can troubleshoot any customer from here if i get the spn id + secret + tenant id.
    # it must have the needed permissions incl. sql write"*.
    # 🪤 It is NOT made the server's Entra admin, and cannot be: Azure SQL allows exactly ONE, and
    # that one must be the in-VNet SQL identity or a PRIVATE server has no administrator that can
    # reach it (see the note above Invoke-PimDbInitJob). Instead it gets a CONTAINED DATABASE USER
    # -- db_datareader + db_datawriter + db_ddladmin -- created by the same in-cloud bootstrap job
    # that creates every other principal. Database rights, never server admin.
    # 🔑 DECLARING IT HERE IS THE POINT. Internal had this access only because its Entra admin had
    # drifted to the deploy SPN; re-running the prerequisites would have moved the admin back and
    # silently removed it. An undeclared capability is one the next deploy deletes.
    # Leave blank to grant no support access at all.
    [string]$SupportDbAppId   = "$($env:PIM_SUPPORT_DB_APPID)",
    [string]$SupportDbUserName = $(if ("$($env:PIM_SUPPORT_DB_USER)".Trim()) { "$($env:PIM_SUPPORT_DB_USER)".Trim() } else { 'PIM4EntraPS-Deploy' }),

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
    # The digest to deploy, when the caller already knows it. A private registry cannot be queried
    # from outside its VNet, so the build publishes what it pushed rather than making this step ask.
    [string]$ImageDigest,
    # ---- IN-CLOUD DATABASE BOOTSTRAP (DESIGN.md §27) --------------------------------------------
    # Create the contained users from a one-shot job INSIDE the environment instead of from this
    # host. Required when SQL has no public endpoint, because then this host has no route at all --
    # disabling public access does not create a private path, it removes the only one.
    [switch]$UseInCloudDbInit,
    # The feature baseline, carried by the same in-cloud job. Set-PimFeatureBaseline applies these
    # over a SQL connection from the DEPLOY HOST, which a private store does not have -- and that
    # step HALTS the deploy, so unlike the mail sender it cannot simply degrade. Defaults match
    # Set-PimFeatureBaseline's own, so the two paths turn on the same things.
    [string[]]$FeatureGates        = @('scheduler.jobs','alerting.email','msp.downlink'),
    [string[]]$FeatureGatesDisable = @(),
    # Who administers the Manager. Written by the same in-cloud job for the same reason -- and this
    # is the one whose absence means NOBODY can administer the environment, so it travels with the
    # users rather than being left to a later step that cannot reach the store.
    [string[]]$ManagerSuperAdmins  = @(),
    [string]$DbInitJobName = 'ca-pim-dbinit',
    # The user-assigned identity that IS the SQL Entra admin (New-PimHostingPrerequisites creates
    # 'id-pim-sql-<token>'). The job authenticates as this, not as its system identity -- which has
    # no database rights at the moment it runs.
    [string]$SqlAdminIdentityResourceId,
    [string]$SqlAdminIdentityClientId,
    [switch]$SkipPrivateDns,
    # 🔑 LEAVE THE PEERING TO THE CUSTOMER, KEEP THE DNS. The peering pair names are DERIVED
    # (`<hub-short>-to-<spoke-short>` / the reverse), and a customer with a naming standard cannot
    # accept a derived name on their hub -- which previously left only one option: omit the hub
    # entirely and lose the private DNS zone too, because the zone has to be LINKED to the hub VNet
    # to be worth anything. That is two manual steps to control the naming of one.
    # With this set, the hub is still named (so the zone is created and linked) and only the peering
    # itself is left alone. The reachability check still reports the peering honestly -- an absent
    # peering is reported as absent, never assumed to be fine because it was skipped on purpose.
    [switch]$SkipPeering,
    # §52.1. The deploy grants this environment network access to the SQL server (subnet service
    # endpoint + VNet rule, with the Azure-services firewall rule verified as a belt). Skip it
    # ONLY when the store is reached over a private endpoint -- without one of those paths the
    # Manager starts, is refused by SQL, and dies before it can serve.
    [switch]$SkipSqlNetworkAccess,

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
    #               it is ~3 vCPU / 6 GiB running 24/7 per tenant -- materially more per environment (never measured)
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

    # §38.2a -- ACA environment exposure.
    # 🪤 A STRING ENUM, NOT [bool] AND NOT [switch], AND THAT IS THE WHOLE POINT.
    #   [bool] does not survive `pwsh -File`: -File stringifies EVERY argument, so the caller's
    #   $false arrives as the text "False" and binding dies with "Cannot convert value
    #   System.String to type System.Boolean". Measured 2026-09-08 -- the onboarding driver
    #   invokes Invoke-PimDeployAll exactly that way, so the parameter was unusable end to end.
    #   [switch] would bind, but defaults to $false = EXTERNAL, silently flipping every
    #   environment sync reaches to public ingress the moment it shipped.
    # A ValidateSet string binds identically in-process and through -File, and reads correctly in
    # a log line. Default 'internal' keeps today's behaviour; a customer opts in with 'external'.
    # 🔴 IMMUTABLE ONCE CREATED -- see the comment at the env-create call. This is the choice to
    # get right on day one; the app-level ingress below is the one you can change afterwards.
    # 🔴 §38.2b -- DEFAULT IS external (operator decision, 2026-09-10: "they must be accessible
    # from external"). It was 'internal', which meant the exposure switch existed and nothing ever
    # used it: four environments were built internal-only and CANNOT be opened, because an ACA
    # environment's internal setting is immutable (see the create block below).
    # 🔑 The asymmetry is the whole argument: built EXTERNAL, the Manager can be locked down later
    # with one reversible command (`az containerapp ingress update --type internal`). Built
    # INTERNAL, the only way out is deleting the environment and every app in it.
    # 🔒 External ingress is NOT unauthenticated exposure: the Manager sits behind Easy Auth, which
    # the deploy makes a fatal step precisely so it can never finish with an open console.
    [ValidateSet('internal','external')][string]$Exposure = 'external',

    # --- 2026-09-13: THE RING GATE ------------------------------------------------------------
    # Re-running infra on an EXISTING environment rolls its apps and tick Job to -ImageTag. On an
    # environment whose updater follows ring >= 2 that is refused unless channel.json approves that
    # version for the ring ("nothing releases to ring 2 without my approve"). Greenfield installs and
    # ring 0/1 are unaffected. -OverrideRingGate needs -Reason and is printed/audited.
    [string]$UpdateJobName = 'ca-pim-update',
    [switch]$OverrideRingGate,
    [string]$Reason,

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
# 🔴 THIS WAS MISSING, AND IT TOOK DOWN STEP 6 OF EVERY ESTATE DEPLOY THAT PASSED A CERT.
# Warn is called three times on the engine-identity branch below, and was never defined here --
# the sibling setup scripts (Build-PimManagerImage.ps1, Deploy-PimDownlinkJob.ps1) each define it
# and this copy dropped it. The failure mode is the worst possible shape: the branch exists ONLY
# to say "a container has no cert store, pass -EngineClientSecret instead", so passing the
# cert-only credential the machine rules mandate killed the deploy with
# "The term 'Warn' is not recognized" -- the message that would have told you what to do IS the
# thing that crashed. Measured 2026-09-03 on the EFIF master: steps 1-5 green, step 6 FAILED(1).
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }
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
# Every az call is scoped explicitly, not only through `az account set`: the default context on a
# host with two logins is not reliably the one this run set (ESTATE-14 / BUG-102).
$subArgs = @('--subscription', $SubscriptionId)

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
    # 🔴 DROP THE CACHED TOKEN BEFORE SIGNING IN. This directory PERSISTS between runs, and az
    # keeps its MSAL token cache in it. So a permission granted BETWEEN two runs is invisible to
    # the second one: az serves the still-valid token minted before the grant, the call fails with
    # "Insufficient privileges to complete the operation", and the operator goes off to check a
    # permission that is already correct.
    # Measured at a live customer 2026-09-08. The deploy SPN was granted Directory.Read.All,
    # AppRoleAssignment.ReadWrite.All and Application.ReadWrite.All; its freshly-minted token was
    # decoded and CARRIED ALL THREE; and the very next deploy still failed on the same refusal --
    # because `az account clear` had been run against the DEFAULT profile while this step reads its
    # own isolated one. Two clean runs were lost to it.
    # 🔒 `az account clear`, NOT deleting the directory: the profile and token cache go, while
    # `config` survives -- and that config holds extension.use_dynamic_install, without which a
    # fresh dir makes `az containerapp` PROMPT to install its extension and an unattended run HANGS
    # (the 30-minute stall of 2026-09-03). Isolation is here to stop an ambient context leaking in;
    # it was never meant to carry credentials forward.
    az account clear --only-show-errors 2>&1 | Out-Null
    az config set extension.use_dynamic_install=yes_without_prompt --only-show-errors 2>&1 | Out-Null
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

# ---- 2026-09-13: the RING GATE, before anything in an existing environment is touched ----------
. "$here\_PimUpdateRing.ps1"
Step "Ring gate: may $ResourceGroup take $ImageTag?"
[void](Assert-PimRollRingGate -ResourceGroup $ResourceGroup -SubscriptionArgs @('--subscription', $SubscriptionId) `
          -TargetVersion $ImageTag -UpdateJobName $UpdateJobName -OverrideRingGate:$OverrideRingGate -Reason $Reason `
          -Caller 'Setup-PimContainers')

# --- BUG-40: resolve the image tag to its digest, and deploy THAT --------------
# A tag is a mutable pointer. Rebuilding `pim-manager:2.4.245` moves it to new content, but the
# container app's image FIELD is unchanged -- so ARM sees no change, makes no revision, and the
# platform keeps running what it already pulled. Measured live: a code fix built + rolled under
# the same tag reported success and the next two scheduled executions ran the OLD image.
# Pinning the digest makes new content a CHANGED FIELD, which is the only thing ARM reacts to.
if (-not $WhatIfPreference) {
    Step "Resolve $ImageRepo`:$ImageTag -> digest (deploy content, not a mutable tag)"
    # 🔑 A PRIVATE REGISTRY CANNOT BE QUERIED FROM OUTSIDE ITS VNET, AND THIS IS THE THIRD PLACE
    # THAT MATTERED. Resolve-PimAcrImageDigest reads the registry's DATA PLANE -- exactly what
    # -AcrPublicAccess false closes -- so on an internal-only deployment it fails with "Unable to
    # authenticate using AAD or admin login credentials", having just successfully BUILT the image
    # on an in-VNet agent pool. Measured at a customer 2026-09-11.
    # The build already knows the digest (it reads it out of the ACR build output) and publishes it
    # here. Use that when it is for THIS exact image; otherwise resolve as before.
    $imageDigest = $null
    if ($ImageDigest) { $imageDigest = "$ImageDigest".Trim(); Note "digest supplied by the caller (registry not queried)" }
    elseif ($global:PIM_LastBuiltDigest -and
            "$($global:PIM_LastBuiltImageRef)" -eq "$AcrName/$ImageRepo`:$ImageTag") {
        $imageDigest = "$($global:PIM_LastBuiltDigest)".Trim()
        Note "digest from the build that just ran (registry not queried)"
    }
    if (-not $imageDigest) { $imageDigest = Resolve-PimAcrImageDigest -AcrName $AcrName -Repository $ImageRepo -Tag $ImageTag }
    $image = New-PimImageReference -Registry "$AcrName.azurecr.io" -Repository $ImageRepo -Digest $imageDigest
    Note "tag $ImageTag => $imageDigest"
    Note "deploying $image"
} else {
    Note "WhatIf -- tag would be resolved to a digest here; plan shows the tag reference $imageTagRef."
}

Step 'Register resource providers (idempotent)'
if ($PSCmdlet.ShouldProcess('Microsoft.App / Microsoft.OperationalInsights','register')) {
    az provider register @subArgs -n Microsoft.App --wait 2>$null | Out-Null
    az provider register @subArgs -n Microsoft.OperationalInsights --wait 2>$null | Out-Null
}

Step "Subnet $SubnetName delegated to Microsoft.App/environments"
if ($PSCmdlet.ShouldProcess($SubnetName,'create/delegate')) {
    $exists = az network vnet subnet show @subArgs -g $VnetResourceGroup --vnet-name $VnetName -n $SubnetName --query name -o tsv 2>$null
    if (-not $exists) {
        az network vnet subnet create @subArgs -g $VnetResourceGroup --vnet-name $VnetName -n $SubnetName `
            --address-prefixes $SubnetPrefix --delegations Microsoft.App/environments -o none
    } else { Note 'subnet exists' }
}

# 🪤 The word here was hardcoded "internal" and stayed that way after exposure became a choice, so
# a deploy creating a PUBLIC environment announced "(internal, workload-profile)". A step header
# that contradicts what the step is doing is how a wrong exposure goes unnoticed until DNS says so.
Step "ACA environment $EnvName ($Exposure, workload-profile)"
if ($PSCmdlet.ShouldProcess($EnvName,'create')) {
    $exists = az containerapp env show @subArgs -g $ResourceGroup -n $EnvName --query name -o tsv 2>$null
    if (-not $exists) {
        # BUG-37: hand ACA the workspace we already created. Without --logs-workspace-id it
        # GENERATES one and writes every log there, leaving `law-pim-<token>` empty and billed --
        # and leaving anyone reading logs pointed at the wrong workspace. The key is a secret:
        # it is passed to az and never printed.
        # 🔴 §38.2a -- THIS FLAG IS THE ONE DECISION YOU CANNOT UNDO. An ACA environment's
        # internal-only setting is IMMUTABLE: `az containerapp env update` exposes no option for
        # it (verified 2026-09-08), so changing your mind means deleting the environment and every
        # app in it. The APP's ingress, by contrast, IS mutable
        # (`az containerapp ingress update --type external|internal`).
        # ⇒ Build the environment EXTERNAL-CAPABLE and you can lock the Manager down later, and
        #   re-open it, with one reversible command. Build it internal-only and you are committed.
        # §38.2b (operator, 2026-09-10): the default is now EXTERNAL. The old default was internal
        # "so existing behaviour must not move" -- but an existing environment is never recreated
        # by a deploy, so that default protected nothing and instead guaranteed that every new
        # environment was built the one way that can never be undone. Four were, and none of them
        # can be reached to test. A customer who wants a private one OPTS IN with -Exposure internal.
        $internalOnly = $(if ($Exposure -eq 'internal') { 'true' } else { 'false' })
        Note ("ACA environment exposure: --internal-only $internalOnly" + $(if ($internalOnly -eq 'true') {
                  ' (VNet-private; reachable only from peered/hub clients -- and NOT changeable later)' }
              else { ' (external-capable; lock the Manager down later with `az containerapp ingress update --type internal`)' }))
        $envCreateArgs = @('containerapp','env','create','-g',$ResourceGroup,'-n',$EnvName,
                           '--location',$Location,
                           '--infrastructure-subnet-resource-id',$subnetId,'--internal-only',$internalOnly,
                           '--enable-workload-profiles','--logs-destination','log-analytics')
        if ("$LogAnalyticsWorkspaceName".Trim()) {
            $lawRg  = $(if ("$LogAnalyticsResourceGroup".Trim()) { $LogAnalyticsResourceGroup } else { $ResourceGroup })
            $lawCid = az monitor log-analytics workspace show @subArgs -g $lawRg -n $LogAnalyticsWorkspaceName --query customerId -o tsv --only-show-errors 2>$null
            $lawKey = az monitor log-analytics workspace get-shared-keys @subArgs -g $lawRg -n $LogAnalyticsWorkspaceName --query primarySharedKey -o tsv --only-show-errors 2>$null
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
    } else {
        # §38.2a -- an existing environment KEEPS whatever exposure it was created with, and
        # nothing here can change it. Silently skipping would let a deploy that asked for
        # external quietly produce an internal-only environment (or the reverse) and still report
        # success -- the split-brain shape this file already guards against elsewhere. Say it.
        $actualInternal = az containerapp env show @subArgs -g $ResourceGroup -n $EnvName --query "properties.vnetConfiguration.internal" -o tsv 2>$null
        $wantInternal   = $(if ($Exposure -eq 'internal') { 'true' } else { 'false' })
        if ("$actualInternal".Trim() -and "$actualInternal".Trim().ToLowerInvariant() -ne $wantInternal) {
            Write-Warning ("env exists with --internal-only=$actualInternal but this deploy asked for " +
                           "$wantInternal. THIS CANNOT BE CHANGED: an ACA environment's internal setting is " +
                           "immutable, so the environment stays $actualInternal. To change it you must delete " +
                           "environment '$EnvName' and every app in it and redeploy. If you only need to change " +
                           "who can reach the Manager, use the APP instead: " +
                           "az containerapp ingress update -g $ResourceGroup -n ca-pim-manager --type internal|external.")
        } else { Note "env exists (--internal-only=$actualInternal)" }
    }
}
# VERIFY, do not assume: read back which workspace the environment actually logs to. A create that
# quietly fell back to a generated workspace looks identical to a correct one until someone queries
# logs and finds nothing -- which is exactly how BUG-37 surfaced.
if (-not $WhatIfPreference -and "$LogAnalyticsWorkspaceName".Trim()) {
    $envCid = az containerapp env show @subArgs -g $ResourceGroup -n $EnvName --query "properties.appLogsConfiguration.logAnalyticsConfiguration.customerId" -o tsv 2>$null
    $lawRg2 = $(if ("$LogAnalyticsResourceGroup".Trim()) { $LogAnalyticsResourceGroup } else { $ResourceGroup })
    $wantCid = az monitor log-analytics workspace show @subArgs -g $lawRg2 -n $LogAnalyticsWorkspaceName --query customerId -o tsv --only-show-errors 2>$null
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
        $lawKey2 = az monitor log-analytics workspace get-shared-keys @subArgs -g $lawRg2 -n $LogAnalyticsWorkspaceName --query primarySharedKey -o tsv --only-show-errors 2>$null
        if (-not "$lawKey2".Trim()) {
            throw ("ACA environment '$EnvName' logs to the WRONG workspace ($envCid) and the shared key for " +
                   "'$LogAnalyticsWorkspaceName' could not be read, so it cannot be repaired. Grant the " +
                   "deploying identity read on that workspace and re-run (BUG-37).")
        }
        az containerapp env update @subArgs -g $ResourceGroup -n $EnvName `
            --logs-destination log-analytics --logs-workspace-id $wantCid --logs-workspace-key $lawKey2 -o none
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az containerapp env update (log workspace repair) failed (exit $LASTEXITCODE)." }
        # Read back AGAIN -- a repair that reports success and changes nothing is the whole reason
        # this verification block exists in the first place.
        $envCid2 = az containerapp env show @subArgs -g $ResourceGroup -n $EnvName --query "properties.appLogsConfiguration.logAnalyticsConfiguration.customerId" -o tsv 2>$null
        if ("$envCid2".Trim() -ne "$wantCid".Trim()) {
            throw ("ACA environment '$EnvName' still logs to $envCid2 after the repair (wanted $wantCid). " +
                   "Do NOT assume the logs moved (BUG-37).")
        }
        Note "logs REPAIRED -> $LogAnalyticsWorkspaceName ($envCid2)"
    } elseif ("$envCid".Trim()) {
        Note "logs verified -> $LogAnalyticsWorkspaceName ($envCid)"
    }
}
$envStatic = az containerapp env show @subArgs -g $ResourceGroup -n $EnvName --query properties.staticIp -o tsv 2>$null
$envDomain = az containerapp env show @subArgs -g $ResourceGroup -n $EnvName --query properties.defaultDomain -o tsv 2>$null
Note "env static IP = $envStatic   domain = $envDomain"

# --- BUG-49: MAKE THE ENVIRONMENT REACHABLE ----------------------------------
# This is the step whose ABSENCE produced a deployed, healthy-looking, unreachable Manager. It
# runs HERE -- immediately after the environment exists and its static IP is known -- because
# both halves depend on that IP and neither depends on the apps.
#
# Two halves, and BOTH are required. Peering alone gives a client a route to an address it
# cannot name; DNS alone gives it a name it cannot reach.
$hubSubForPeering = $(if ("$HubVnetSubscriptionId".Trim()) { $HubVnetSubscriptionId } else { $SubscriptionId })
if ("$HubVnetName".Trim() -and "$HubVnetResourceGroup".Trim() -and $SkipPeering) {
    # Say it LOUDLY, and say what is now owed. A skipped step that prints quietly is
    # indistinguishable from one that ran -- the same reason the no-hub branch below warns.
    Write-Warning ("-SkipPeering: the peering between '$VnetName' and '$HubVnetName' was NOT created, by request. " +
                   "The private DNS zone IS still created and linked. Until you create the peering yourself, the " +
                   "Manager has a NAME but no ROUTE, and every resource-level check will still report a healthy deploy.")
    Note ("create it with your own names, e.g.:")
    Note ("  az network vnet peering create -g $VnetResourceGroup --vnet-name $VnetName -n <your-spoke-side-name> " +
          "--remote-vnet /subscriptions/$hubSubForPeering/resourceGroups/$HubVnetResourceGroup/providers/Microsoft.Network/virtualNetworks/$HubVnetName " +
          "--allow-vnet-access")
    Note ("  az network vnet peering create -g $HubVnetResourceGroup --vnet-name $HubVnetName -n <your-hub-side-name> " +
          "--remote-vnet /subscriptions/$SubscriptionId/resourceGroups/$VnetResourceGroup/providers/Microsoft.Network/virtualNetworks/$VnetName " +
          "--allow-vnet-access --subscription $hubSubForPeering")
} elseif ("$HubVnetName".Trim() -and "$HubVnetResourceGroup".Trim()) {
    Step "Peering: $VnetName <-> $HubVnetName (the spoke is created isolated)"
    Set-PimVnetPeering -SpokeVnetName $VnetName -SpokeResourceGroup $VnetResourceGroup `
        -SpokeSubscriptionId $SubscriptionId -HubVnetName $HubVnetName `
        -HubResourceGroup $HubVnetResourceGroup -HubSubscriptionId $hubSubForPeering
} elseif ($Exposure -eq 'internal') {
    # Not a Note. A skipped reachability step that prints quietly is indistinguishable from one
    # that ran, and that is exactly how an unreachable environment gets called deployed.
    Write-Warning ("NO HUB VNET GIVEN (-HubVnetName/-HubVnetResourceGroup): the PIM spoke VNet '$VnetName' is " +
                   "left ISOLATED. The ACA environment is --internal-only, so the Manager will have NO ROUTE " +
                   "from any client and every resource-level check will still report a healthy deploy (BUG-49).")
}
else {
    # 🪤 THE SECOND COPY OF THE BUG-49 WARNING. Invoke-PimDeployAll's copy was made conditional on
    # exposure when -Exposure shipped; THIS one was not, so an EXTERNAL deploy printed
    # "the ACA environment is --internal-only, so the Manager will have NO ROUTE from any client"
    # immediately after creating an environment with a PUBLIC static IP. Measured at a live customer
    # 2026-09-08, with the customer watching. A warning that is confidently wrong is worse than none:
    # it teaches the operator to ignore the next one, which will be right.
    Note ("no hub VNet given, and none is needed: this environment is EXTERNAL, so the Manager is " +
          "reachable without peering. Lock it down later with " +
          "'az containerapp ingress update -g $ResourceGroup -n ca-pim-manager --type internal'.")
}

if ($SkipPrivateDns) {
    Write-Warning "  -SkipPrivateDns: the ACA default domain '$envDomain' is NOT published, so the Manager FQDN will not resolve for peered clients."
} elseif ($Exposure -eq 'external') {
    # 🪤 A PRIVATE DNS ZONE IS FOR A PRIVATE ENDPOINT. On an EXTERNAL environment the default domain
    # already resolves publicly to a public static IP, so publishing a private zone for it only
    # SHADOWS the public name inside every linked VNet -- and the code already knew: it created the
    # zone and then warned "static IP ... is NOT in RFC1918 space -- this environment does not look
    # --internal-only. A private DNS zone ... would SHADOW the public name". Measured at a live
    # customer 2026-09-08: zone created, warning printed, both in the same breath.
    # Harmless while the addresses agree; stale and misleading the moment the environment's IP moves.
    Note ("private DNS skipped: '$envDomain' resolves publicly on an EXTERNAL environment, so a " +
          "private zone would only shadow it inside linked VNets.")
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
    Write-Warning "  could not read the environment's defaultDomain/staticIp -- skipping the private DNS zone. The Manager FQDN will not resolve."
}

# --- THE MANAGER COULD NOT REACH ITS OWN DATABASE ----------------------------
# 🔴 §52.1 / §52.10. The logic lives in Set-PimSqlNetworkAccess.ps1 and the DEPLOY runs it as its
# own always-run step, because putting it HERE alone is what made the first fix a no-op: this
# script is the INFRA step, and INFRA is skipped as "already current" the moment the ACA
# environment exists -- so on the very environment that needed the repair it never executed.
# 🪤 §45.1's rule, re-learned at a customer: a repair gated on a condition that cannot observe the
# thing being repaired is not a repair.
# It is still called here so a FIRST install gets the access in the same pass that creates the
# environment, rather than waiting for the step further down the plan.
if ($UseInCloudDbInit) {
    # 🔑 A PRIVATE SQL SERVER HAS NO FIREWALL TO CONFIGURE, AND TRYING READS AS A FAILURE.
    # -UseInCloudDbInit is set exactly when the server's public endpoint is disabled, and Azure
    # refuses every firewall / vnet-rule call against such a server:
    #     (FirewallChangesDeniedBecausePublicEndpointDisabled) Unable to create or modify firewall
    #     rules when public network access for the server is disabled.
    # That is the CORRECT state -- the route is the private endpoint, not a rule -- but the step
    # printed two red az failures and then "AllowAzureServices is MISSING -- creating it", in the
    # middle of a deploy that was working. An operator reading that log concludes the deploy is
    # broken and starts opening the server, which is the one thing this design exists to prevent.
    # 🪤 Do NOT reach for -SkipSqlNetworkAccess instead: its warning says the Manager will CRASH AT
    # BOOT, which is false for this topology and misleading in a different direction.
    Write-Host "==> SQL network access: NOT APPLICABLE -- $SqlServerFqdn has no public endpoint." -ForegroundColor DarkGray
    Write-Host "    The route is the private endpoint in this VNet; a firewall rule cannot exist on such a server." -ForegroundColor DarkGray
} elseif ($SkipSqlNetworkAccess) {
    Write-Warning ("  -SkipSqlNetworkAccess: nothing will grant this environment access to $SqlServerFqdn. " +
                   "Unless the store is reached over a private endpoint, the Manager will CRASH AT BOOT with " +
                   "'Client with IP address ... is not allowed to access the server'.")
} elseif ("$SqlServerFqdn".Trim()) {
    $sqlNetScript = Join-Path $PSScriptRoot 'Set-PimSqlNetworkAccess.ps1'
    if (-not (Test-Path -LiteralPath $sqlNetScript)) {
        Write-Warning "  Set-PimSqlNetworkAccess.ps1 not found next to this script -- SQL network access NOT configured."
    } else {
        [void](& $sqlNetScript -SubscriptionId $SubscriptionId -SqlServerFqdn $SqlServerFqdn `
                 -ResourceGroup $ResourceGroup -EnvName $EnvName -SubnetId $subnetId)
    }
}

$acrId = az acr show @subArgs -n $AcrName --query id -o tsv 2>$null
# 🪤 A RESOURCE ID THAT ARRIVES LOOKING LIKE A LOCAL PATH WAS MANGLED BY THE CALLER'S SHELL.
# Measured rebuilding mfnpr 2026-09-10: the value reached here as
#     C:/Program Files/Git/subscriptions/<sub>/resourceGroups/.../id-pim-mfnpr
# because MSYS (Git Bash) rewrites any argument that looks like an absolute Unix path into a
# Windows one -- and an Azure resource id looks exactly like one. az then answered
#     --registry-identity must be an identity resource ID or 'system' or 'system-environment'
# which reads as "wrong kind of value" about a value the CALLER had typed correctly, and sent the
# diagnosis into az's validator (both casings are accepted there; that was a wrong turn) instead of
# at the shell. Same cause makes `--scope /subscriptions/...` fail as MissingSubscription.
# Say so here, where the evidence is, rather than let the next reader repeat the hunt.
if ("$RegistryIdentityResourceId".Trim() -and "$RegistryIdentityResourceId" -notmatch '^/subscriptions/') {
    throw ("Setup-PimContainers: -RegistryIdentityResourceId is not a resource id: " +
           "'$RegistryIdentityResourceId'. It must start with '/subscriptions/'. A value beginning " +
           "with a local path was mangled by the calling shell -- Git Bash/MSYS rewrites arguments " +
           "that look like absolute Unix paths. Re-run with MSYS_NO_PATHCONV=1, or call from PowerShell.")
}
$useRegistryIdentity = [bool]$RegistryIdentityResourceId
$acrU = $null; $acrP = $null
if ($useRegistryIdentity) {
    Step "Registry auth: USER-ASSIGNED IDENTITY (no admin credential)"
    Note $RegistryIdentityResourceId
} else {
    # Legacy path. `az acr credential show` returns EMPTY unless the registry was created with
    # --admin-enabled, and an empty username/password does not fail loudly -- it produces a
    # container app that cannot pull. Say so here rather than let it surface as a pull error.
    $acrU = az acr credential show @subArgs -n $AcrName --query username -o tsv 2>$null
    $acrP = az acr credential show @subArgs -n $AcrName --query "passwords[0].value" -o tsv 2>$null
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
# 🔑 TWO WAYS TO CREATE A CONTAINED USER, AND THE NETWORK DECIDES WHICH.
#   * PUBLIC SQL  -- the deploy host can reach the server, so it grants directly. Unchanged.
#   * PRIVATE SQL -- the deploy host has NO ROUTE AT ALL (publicNetworkAccess=Disabled does not
#     create a private path, it removes the only one). Granting from here cannot work, so the
#     principals are COLLECTED and handed to a one-shot job that runs INSIDE the VNet as the
#     identity that is the server's Entra admin. See tools/pim-engine/dbinit-job-entry.ps1.
# Collecting rather than granting also fixes an ordering problem: the job creates every user in ONE
# connection, so it can refuse a partial set instead of leaving half of them made.
$script:PimDbInitPrincipals = @()
function Grant-PimMiSqlHere {
    param([string]$DbUserName,[string]$MiAppId)
    if ($UseInCloudDbInit) {
        $script:PimDbInitPrincipals += @{ name = $DbUserName; appId = $MiAppId }
        Note "db user '$DbUserName' queued for the in-cloud bootstrap (SQL is private; this host has no route)"
        return
    }
    if ($UseSignedInAccount) {
        Grant-PimMiSql -DbUserName $DbUserName -MiAppId $MiAppId -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId -UseSignedInAccount
        return
    }
    if (-not "$SqlAdminClientId".Trim()) { throw "db user '$DbUserName': no -SqlAdminClientId (with -SqlAdminCertThumbprint) and no -UseSignedInAccount -- nothing can create the contained user." }
    $cred = if ($SqlAdminCertThumbprint) { @{ SqlAdminCertThumbprint = $SqlAdminCertThumbprint } }
            else                          { @{ SqlAdminClientSecret   = $SqlAdminClientSecret } }
    Grant-PimMiSql -DbUserName $DbUserName -MiAppId $MiAppId `
        -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId `
        -SqlAdminClientId $SqlAdminClientId @cred
}

function Invoke-PimDbInitJob {
    <#
      Create (or refresh) the one-shot bootstrap job and RUN it, then gate on its result.
      Manual trigger: this is not a schedule, it is a step of the deploy that happens to execute
      somewhere the deploy cannot reach.
    #>
    param([object[]]$Principals)
    if (-not @($Principals).Count) { Note 'in-cloud db bootstrap: no principals queued -- nothing to do.'; return }
    Step "DB bootstrap: create $DbInitJobName and run it INSIDE the environment"

    $payload = (@($Principals) | ConvertTo-Json -Compress -Depth 5)
    # 🪤 A JSON ARRAY OF ONE COLLAPSES TO AN OBJECT in ConvertTo-Json, and the job then reads a
    # single principal as a set of properties. Force an array shape.
    if ($payload -notmatch '^\s*\[') { $payload = "[$payload]" }

    # (The identities are attached through the YAML document below, not with --mi-user-assigned:
    # the whole job definition goes through one --yaml for the reason explained there.)

    $envVars = @(
        "PIM_SqlServer=$SqlServerFqdn"
        "PIM_SqlDatabase=$SqlDatabase"
        "PIM_DBINIT_PRINCIPALS=$payload"
        # 🔑 THE SCHEMA COMES WITH THE USERS, BECAUSE NEITHER CAN BE APPLIED FROM OUTSIDE.
        # This job exists precisely because the deploy host has no route to a private SQL server --
        # and Invoke-PimUpdate's first-install schema apply runs over exactly that missing route.
        # Leaving it to the deploy host would stand up a healthy Manager against an EMPTY database:
        # the BUG-50 shape, green everywhere and functional nowhere. The job is already inside, is
        # already the Entra admin, and is already connected; applying the shipped (idempotent,
        # IF-NOT-EXISTS-guarded) schema here costs one more round trip on the same connection.
        'PIM_DBINIT_SCHEMA=1'
    )
    if ("$SqlAdminIdentityClientId".Trim()) { $envVars += "PIM_DBINIT_MI_CLIENT_ID=$("$SqlAdminIdentityClientId".Trim())" }
    if (@($FeatureGates).Count)        { $envVars += "PIM_DBINIT_FEATURE_GATES=$((@($FeatureGates)        | Where-Object { "$_".Trim() }) -join ',')" }
    if (@($FeatureGatesDisable).Count) { $envVars += "PIM_DBINIT_FEATURE_DISABLE=$((@($FeatureGatesDisable) | Where-Object { "$_".Trim() }) -join ',')" }
    $sa = @($ManagerSuperAdmins | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($sa.Count) {
        # 🪤 Compressed JSON, and the YAML writer quotes + escapes it -- an unquoted JSON array is
        # YAML flow syntax and the document would parse into something else entirely.
        $saJson = ConvertTo-Json -Compress -InputObject @($sa | ForEach-Object { @{ identity = $_; role = 'SuperAdmin' } })
        if ($saJson -notmatch '^\s*\[') { $saJson = "[$saJson]" }   # a one-element array collapses to an object
        $envVars += "PIM_DBINIT_MANAGER_ACCESS=$saJson"
    }

    $exists = az containerapp job show @subArgs -g $ResourceGroup -n $DbInitJobName --query name -o tsv 2>$null

    # 🔴 --yaml, NEVER A MULTI-TOKEN --command. THIRD SCRIPT, SAME DEFECT.
    #     az exit 2: ERROR: unrecognized arguments: -NoProfile,-File,/app/.../dbinit-job-entry.ps1
    # az takes only the FIRST token after --command and then tries to parse the rest as its own
    # arguments; --args does not rescue it. The worker containers learned this, Deploy-PimUpdateJob
    # learned it again on 2026-09-09 and wrote "a rule that lives in a test for one script does not
    # protect the next one" -- and then this job was written with --command anyway.
    # 🪤 AND Test-PimSetupHosting WAS ALREADY FAILING ON IT. Its standing assertion
    # ("container workers deploy via --yaml (NOT multi-token --command)") went red the moment this
    # was added, and was read as one of four "pre-existing, unrelated" failures because it was red
    # before the change too -- for a DIFFERENT script. A ratcheted gate that is already red cannot
    # report the next instance, which is the whole reason this defect reached a customer deploy.
    $entry    = '/app/PIM4EntraPS/tools/pim-engine/dbinit-job-entry.ps1'
    $envId    = "$(az containerapp env show -g $ResourceGroup -n $EnvName --query id -o tsv 2>$null)".Trim()
    if (-not $envId) { throw "Container Apps environment '$EnvName' not found in '$ResourceGroup' -- the bootstrap job has nowhere to run." }
    $location = "$(az containerapp env show -g $ResourceGroup -n $EnvName --query location -o tsv 2>$null)".Trim()

    # The job carries the SQL admin identity (to authenticate to the database) and, when they
    # differ, the pull identity (to get the image). Two identities, two jobs, neither able to do
    # the other's -- the same split the prereq created them for.
    $uaIds = @()
    if ("$SqlAdminIdentityResourceId".Trim()) { $uaIds += "$SqlAdminIdentityResourceId".Trim() }
    if ($useRegistryIdentity -and "$RegistryIdentityResourceId".Trim() -and ("$RegistryIdentityResourceId".Trim() -ne "$SqlAdminIdentityResourceId".Trim())) {
        $uaIds += "$RegistryIdentityResourceId".Trim()
    }
    $identityYaml = 'identity: { type: "SystemAssigned" }'
    if ($uaIds.Count) {
        $identityYaml = 'identity: { type: "SystemAssigned, UserAssigned", userAssignedIdentities: { ' +
                        (($uaIds | ForEach-Object { '"' + $_ + '": {}' }) -join ', ') + ' } }'
    }
    $regIdent = $(if ($useRegistryIdentity -and "$RegistryIdentityResourceId".Trim()) { "$RegistryIdentityResourceId".Trim() } else { 'system' })
    $registryYaml = "    registries: [ { server: `"$AcrName.azurecr.io`", identity: `"$regIdent`" } ]"
    # 🪤 Values are QUOTED. PIM_DBINIT_PRINCIPALS is a JSON array -- unquoted it is YAML flow
    # syntax and the document parses into something else entirely.
    $envYaml = '        env: [ ' + (($envVars | ForEach-Object {
                    $kv = "$_" -split '=', 2
                    '{ name: ' + $kv[0] + ', value: "' + ("$($kv[1])" -replace '\\','\\\\' -replace '"','\"') + '" }' }) -join ', ') + ' ]'

    $y = New-Object System.Collections.Generic.List[string]
    [void]$y.Add("location: $location")
    # The identity block belongs to CREATE only -- `job update --yaml` with an identity: block
    # fails as "Request requires identities to be assigned" (Deploy-PimUpdateJob, third install).
    if (-not "$exists".Trim()) { [void]$y.Add($identityYaml) }
    [void]$y.Add('properties:')
    [void]$y.Add("  environmentId: $envId")
    [void]$y.Add('  configuration:')
    [void]$y.Add('    triggerType: Manual')
    [void]$y.Add('    replicaTimeout: 900')
    [void]$y.Add('    replicaRetryLimit: 0')
    [void]$y.Add('    manualTriggerConfig: { parallelism: 1, replicaCompletionCount: 1 }')
    [void]$y.Add($registryYaml)
    [void]$y.Add('  template:')
    [void]$y.Add('    containers:')
    [void]$y.Add("      - name: $DbInitJobName")
    [void]$y.Add("        image: $image")
    [void]$y.Add('        command: [pwsh]')
    [void]$y.Add("        args: [`"-NoProfile`", `"-ExecutionPolicy`", `"Bypass`", `"-File`", `"$entry`"]")
    [void]$y.Add($envYaml)
    [void]$y.Add('        resources: { cpu: 0.5, memory: 1.0Gi }')
    $yamlPath = Join-Path ([IO.Path]::GetTempPath()) ("pim-dbinit-job-{0}.yaml" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
    Set-Content -LiteralPath $yamlPath -Value (($y.ToArray()) -join "`n") -Encoding ascii
    try {
        if ("$exists".Trim()) { az containerapp job update -g $ResourceGroup -n $DbInitJobName --yaml $yamlPath -o none 2>$null | Out-Null }
        else                  { az containerapp job create -g $ResourceGroup -n $DbInitJobName --yaml $yamlPath -o none 2>$null | Out-Null }
    } finally { Remove-Item -LiteralPath $yamlPath -Force -ErrorAction SilentlyContinue }
    if (-not "$(az containerapp job show -g $ResourceGroup -n $DbInitJobName --query name -o tsv 2>$null)".Trim()) {
        throw "the bootstrap job '$DbInitJobName' was NOT created -- see the failure above. Without it no database user can be created, because this host has no route to a private SQL server."
    }

    $exec = "$(az containerapp job start -g $ResourceGroup -n $DbInitJobName --query name -o tsv 2>$null)".Trim()
    if (-not $exec) { throw "could not start '$DbInitJobName'." }
    Note "execution $exec -- waiting"
    $status = ''
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Seconds 10
        $status = "$(az containerapp job execution show -g $ResourceGroup -n $DbInitJobName --job-execution-name $exec --query properties.status -o tsv 2>$null)".Trim()
        if ($status -in @('Succeeded','Failed','Degraded')) { break }
    }
    if ($status -ne 'Succeeded') {
        throw ("the database bootstrap '$exec' ended '$status'. Read its log:`n" +
               "  az containerapp job logs show -g $ResourceGroup -n $DbInitJobName --execution $exec --container $DbInitJobName --tail 100`n" +
               "Until it succeeds the apps have NO database users and will crash-loop on " +
               "'Login failed for user <token-identified principal>' -- so this deploy stops here rather than exposing that.")
    }
    Note "database bootstrap succeeded ($exec)"
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
        az containerapp job show @subArgs -g $ResourceGroup -n $Name --query $q -o tsv 2>$null
    } else {
        az containerapp show @subArgs     -g $ResourceGroup -n $Name --query $q -o tsv 2>$null
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

# --- ENGINE IDENTITY: MANAGED IDENTITY IS THE DESIGN. A credential is the exception. ----------
# 🔑 OPERATOR DECISION 2026-09-11: "we cannot use secrets. i prefer MI if possible."
# That is not aspirational -- it is what the internal production environment has been running all
# along: ca-pim-tick there carries NO secret and NO PIM_ClientId, and its system-assigned identity
# holds all nine Graph app-roles (RoleManagement.ReadWrite.Directory, Group.ReadWrite.All,
# User.ReadWrite.All, Directory.Read.All, AdministrativeUnit.ReadWrite.All,
# PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup, RoleManagementPolicy.ReadWrite.Directory,
# UserAuthenticationMethod.ReadWrite.All, Domain.Read.All). Verified against the live tenant.
#
# THIS SCRIPT IS WHAT MAKES THAT TRUE: it calls Grant-PimMiGraph for the Manager app AND for the
# jobs, and that helper THROWS when a role fails rather than warning (BUG-45) -- so a deploy that
# returns cannot have left the identity short. The old text here claimed the opposite ("managed
# identity ... holds no Graph app-roles. Every Graph call will return 403"), which was stale and
# steered every deployment toward a standing credential it did not need.
#
# 🪤 SETTING PIM_ClientId WITH AN UNUSABLE CREDENTIAL IS WORSE THAN SETTING NOTHING: Get-PimRestToken
# takes the MI branch only when IDENTITY_ENDPOINT is set AND there is NO client id. So a client id
# with no usable secret suppresses MI and authenticates as nothing at all -- green deploy, dead
# engine. That is why the branches below emit NO client id unless a secret accompanies it.
#
# The secret is NEVER a plain env var: it goes in as an ACA *secret*, referenced by name, so it is
# absent from the container spec and from `az containerapp show`.
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
        # Kept for environments that genuinely need the engine to act as a NAMED SPN -- notably an
        # S5 master acting into a managed tenant, which a managed identity cannot do (an MI exists
        # in one directory and cannot cross tenants). It is no longer "the only credential a
        # container can use": MI is, and is the default.
        Warn "engine identity: SPN $EngineClientId via CLIENT SECRET (stored as an ACA secret, not an env var)."
        Warn "  This puts a STANDING CREDENTIAL in the environment, and it EXPIRES -- an unattended run will"
        Warn "  start failing on its own one day. Omit -EngineClientSecret to use the managed identity instead,"
        Warn "  unless this environment must act as a named SPN across tenants."
        if ("$EngineCertThumbprint".Trim()) { Note "  (-EngineCertThumbprint ignored for containers: no cert store in the image)" }
    } elseif ("$EngineCertThumbprint".Trim()) {
        # A certificate thumbprint names a Windows cert store the Linux image does not have, so it
        # cannot work here (BUG-74). Emit NEITHER PIM_ClientId NOR PIM_CertThumbprint so the
        # container uses its MANAGED IDENTITY -- which this script grants the Graph app-roles to.
        Note "engine identity: MANAGED IDENTITY (-EngineCertThumbprint ignored -- a container has no certificate store)."
        Note "  The app-roles are granted to that identity by this deploy; nothing else is needed."
    } else {
        Note "engine identity: MANAGED IDENTITY (-EngineClientId given without a secret, so it is not emitted -- a client id with no usable credential would SUPPRESS the MI branch and authenticate as nothing)."
    }
} else {
    # THE DEFAULT, AND THE RECOMMENDED SHAPE. No credential exists anywhere in the environment:
    # nothing to store, rotate, leak or expire. Graph, ARM and SQL all run on the identity below.
    Note "engine identity: MANAGED IDENTITY (no credential in this environment -- nothing to rotate or expire)."
    Note "  Graph app-roles are granted to it by this deploy, and a failed grant stops the deploy rather than warning."
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
    $exists = az containerapp show @subArgs -g $ResourceGroup -n $w.name --query name -o tsv 2>$null
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
            $envId = az containerapp env show @subArgs -g $ResourceGroup -n $EnvName --query id -o tsv 2>$null
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
            # 🔴 KEYED BY RESOURCE GROUP + PID -- see the Job yaml below for the measured failure.
            # The app names are identical in every environment ('ca-pim-manager'), so a bare
            # "pim-<name>.yaml" is the SAME PATH for every tenant, and the estate orchestrator
            # deploys 6 environments CONCURRENTLY by default.
            $tmp = Join-Path $env:TEMP "pim-$($w.name)-$ResourceGroup-$PID.yaml"; Set-Content -LiteralPath $tmp -Value $y -Encoding utf8
            az containerapp create @subArgs -g $ResourceGroup -n $w.name --yaml $tmp -o none
        }
    } else {
        az containerapp update @subArgs -g $ResourceGroup -n $w.name --image $image -o none
        Note 'updated existing'
    }
    Assert-PimDeployedImage -Kind app -Name $w.name -Expected $image

    # MI -> SQL (SID from appId) + AcrPull + switch registry to MI
    # identity.principalId is the SYSTEM-assigned principal even when a user-assigned identity
    # is also attached (those live under identity.userAssignedIdentities), so SQL + Graph keep
    # targeting the app's own identity in both auth modes.
    $oid = az containerapp show @subArgs -g $ResourceGroup -n $w.name --query identity.principalId -o tsv 2>$null
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
    # 🔑 PUBLISH THE MANAGER'S MI APP ID. In an MI-only environment there is no engine app
    # REGISTRATION, so -EngineClientId is legitimately empty -- and the mail-sender step, which
    # needs an identity to receive the scoped Mail.Send, concluded there was none:
    #     RESULT: FAILED -- no -EngineAppId ...
    # leaving the environment MAIL-MUTE: TAPs minted and delivered nowhere, which looks like a
    # working "create admin" right up until the person never receives their credential. The engine
    # identity here IS this managed identity, and this line has just resolved it. Published rather
    # than re-derived, for the same reason as the SQL admin identity.
    if ($w.name -eq $ManagerApp) { $global:PIM_ManagerMiAppId = $appId }
    Grant-PimMiSqlHere -DbUserName $w.name -MiAppId $appId
    if (-not $useRegistryIdentity) {
        # Legacy path only: move the registry off the admin credential and onto the app's own
        # identity now that it exists and can be granted AcrPull.
        az role assignment create @subArgs --assignee-object-id $oid --assignee-principal-type ServicePrincipal --role AcrPull --scope $acrId -o none 2>$null
        az containerapp registry set @subArgs -g $ResourceGroup -n $w.name --server "$AcrName.azurecr.io" --identity system -o none 2>$null
    }
    # In identity mode the registry is ALREADY on the user-assigned identity, which already
    # holds AcrPull. Re-pointing it at the system identity here would undo that and force an
    # extra revision for no gain.
    # Directory app-roles for workers that touch Entra/PIM (everything except a pure
    # read-only manager). Without these the engine 403s on directory reads/writes.
    # §65.4 -- the Manager gets the READ-ONLY Graph set; everything else gets the engine set.
    # Keyed off the app name because that is what the workload list carries here; 'ca-pim-manager'
    # is identical in every environment (see the yaml note above), so this is stable across tenants.
    Grant-PimMiGraph -MiObjectId $oid -RoleSet $(if ("$($w.name)" -match 'manager') { 'Manager' } else { 'Engine' })
    # BUG-51: the Graph grant above covers the DIRECTORY half only. Without an ARM role this
    # identity sees an empty Azure -- azure-scopes=0, and managementGroups list 403s -- while
    # every directory read works perfectly. Same lesson as framework §10.0b, read backwards.
    if ($SkipAzureRbac) { Write-Warning "  -SkipAzureRbac: $($w.name) gets NO ARM rights, so PIM's Azure half will be blind." }
    else {
        # 🔴 BUG-153 / §65.4 -- THE MANAGER GETS READ-ONLY AZURE RIGHTS, NEVER THE ENGINE'S.
        # The GUI reads ARM directly (Open-PimManager.ps1 ~5242/5254: /subscriptions and
        # roleAssignmentSchedules), so it DOES need Azure rights -- but only to read. Its revokes
        # are queued and performed by the engine (§65.1), which is the identity that holds User
        # Access Administrator.
        # 🪤 MEASURED ON INTERNAL 2026-09-12: ca-pim-manager held **User Access Administrator at the
        # TENANT ROOT MANAGEMENT GROUP** -- the right to grant or remove ANY Azure role assignment,
        # tenant-wide, for a GUI that only reads. `$AzureRbacRoles` defaults to Reader, but the
        # deploy is invoked with the ENGINE's role set to satisfy the tick job, and this call site
        # passed that same set to every workload. Reader covers every ARM call the Manager makes
        # (`*/read` includes roleAssignments and the PIM schedules).
        $wRoles = if ("$($w.name)" -match 'manager') { @('Reader') } else { $AzureRbacRoles }
        if ("$($w.name)" -match 'manager' -and @($AzureRbacRoles) -join ',' -ne 'Reader') {
            Note "  $($w.name): Azure RBAC narrowed to Reader -- the GUI only reads Azure; revokes are queued and applied by the engine"
        }
        Grant-PimMiAzureRbac -MiObjectId $oid -Name $w.name -SubscriptionId $SubscriptionId `
            -Roles $wRoles -ManagementGroupId $AzureRbacManagementGroupId -Required:$RequireAzureRbac
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
        $jn = az containerapp job show @subArgs -g $ResourceGroup -n $TickJobName --query name -o tsv 2>$null
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
    $envIdForJob = az containerapp env show @subArgs -g $ResourceGroup -n $EnvName --query id -o tsv 2>$null
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
        # 🔴 THIS PATH WAS SHARED BY EVERY ENVIRONMENT, AND IT CORRUPTED A CONCURRENT DEPLOY.
        # $TickJobName is 'ca-pim-tick' in EVERY tenant, so "pim-$TickJobName.yaml" resolved to the
        # SAME file for all of them -- while Invoke-PlatformEstateDeployment runs 6 environments
        # CONCURRENTLY by default. MEASURED 2026-09-03: EFIF (wa678) and RIDE (rj466) deployed in
        # parallel; EFIF's yaml won the write, RIDE then ran
        #   az containerapp job create -g rg-automateit-rj466 --yaml <EFIF's yaml>
        # and Azure refused with "The environment 'cae-pim' in resource group 'rg-automateit-wa678'
        # was not found" -- an error naming a resource group the failing environment never mentions,
        # which is why it reads as nonsense.
        # 🪤 THE CRASH WAS THE LUCKY OUTCOME. It only failed because the two environments are in
        # DIFFERENT subscriptions, so the foreign environmentId was unresolvable. Two environments
        # in ONE subscription would have SUCCEEDED and written one tenant's job definition -- image,
        # identity, SQL server, engine credential -- into the other tenant's resource group.
        $jobTmp = Join-Path $env:TEMP "pim-$TickJobName-$ResourceGroup-$PID.yaml"
        Set-Content -LiteralPath $jobTmp -Value $jobYaml -Encoding utf8
        # 🪤 CAPTURE az's OWN ERROR. This used to throw "failed (exit 1)" and nothing else, with
        # `-o none` swallowing the rest -- so the yaml-collision above surfaced as a bare exit code
        # and the one sentence that identified it ("the environment 'cae-pim' in resource group
        # 'rg-automateit-wa678' was not found") never reached the step log at all. An exit code is
        # not a diagnosis, and this runs unattended where nobody is watching the console.
        $jobOut = az containerapp job $jobAction @subArgs -g $ResourceGroup -n $TickJobName --yaml $jobTmp -o none 2>&1
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            throw "az containerapp job $jobAction failed (exit $LASTEXITCODE): $(($jobOut | Out-String).Trim())"
        }
        # BUG-40 was MEASURED on this Job: the update succeeded and the next executions still ran
        # the old image. A Job has no revisions to inspect, so the deployed reference is the only
        # thing that can be checked -- which is why it has to be a digest to mean anything.
        Assert-PimDeployedImage -Kind job -Name $TickJobName -Expected $image
        # The Job's SYSTEM identity needs exactly what a worker app needed: a contained DB user
        # and the directory app-roles. Without these the tick starts and then 403s/`Login failed`,
        # which looks like a scheduling problem and is not.
        $jobOid = az containerapp job show @subArgs -g $ResourceGroup -n $TickJobName --query identity.principalId -o tsv 2>$null
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
        if ($SkipAzureRbac) { Write-Warning "  -SkipAzureRbac: $TickJobName gets NO ARM rights -- the tick will report azure-scopes=0." }
        else {
            Grant-PimMiAzureRbac -MiObjectId $jobOid -Name $TickJobName -SubscriptionId $SubscriptionId `
                -Roles $AzureRbacRoles -ManagementGroupId $AzureRbacManagementGroupId -Required:$RequireAzureRbac
        }
        Note "MI $jobAppId granted SQL (db user [$TickJobName]) + Graph app-roles + Azure RBAC"
        Note "fire one now: az containerapp job start -g $ResourceGroup -n $TickJobName"
    }
}

# --- THE DATABASE BOOTSTRAP, once every identity exists ------------------------
# 🔑 RUN IT HERE, NOT EARLIER. Each app and job contributes its own managed identity, and a
# principal can only be turned into a contained user once its appId is resolvable. Collecting them
# all and creating them in ONE connection is also what lets the job refuse a partial set -- half a
# set of database users is the failure mode where the deploy reports success and one app cannot log
# in, found days later.
# 🔑 SUPPORT ACCESS TO THE STORE IS PART OF THE DESIGN, NOT AN ACCIDENT (operator, 2026-09-12:
# *"i need to make sure ... the deploy spn have sql admin permission inside internal and in the
# design overall, so i can troubleshoot any customer from here ... it must have the needed
# permissions incl. sql write"*).
#
# 🪤 AZURE SQL ALLOWS EXACTLY ONE ENTRA ADMIN, and New-PimHostingPrerequisites gives it to the SQL
# user-assigned identity ON PURPOSE -- that identity is inside the VNet and can therefore reach a
# private server, which the deploy host cannot. So "make the deploy SPN the admin" is not available:
# it was tried, and it handed administration to the one identity with no route to the server.
# ⚠️ Measured on the internal environment 2026-09-12: its Entra admin was the DEPLOY SPN, not the
# UAMI -- i.e. it did NOT match this design, and the operator's ability to troubleshoot rested on
# that drift. Re-running the prerequisites would have moved the admin to the UAMI and silently
# removed that access. A capability nobody declared is a capability the next deploy deletes.
# 🔑 So it is declared here instead: the support principal gets a CONTAINED DATABASE USER with
# read/write/ddl, created by the same in-cloud job that creates every other principal. That works
# on private SQL, survives the admin moving, and grants database rights only -- never server admin.
if ("$SupportDbAppId".Trim()) {
    Grant-PimMiSqlHere -DbUserName $SupportDbUserName -MiAppId $SupportDbAppId
}
# 🔴 2026-09-13 -- THE NIGHTLY UPDATER CONNECTS TO THE STORE TOO. Its schema step runs as its own managed
# identity before any container moves; with no contained user it cannot verify a release and refuses to
# roll. Same shape as the tick above, and queued into the SAME bootstrap set on private SQL. The updater
# is installed AFTER this step on a first deploy (Deploy-PimUpdateJob grants it then); every later INFRA
# run keeps it granted here. LIST, not show: "not installed yet" is a normal answer.
$updJobs = $null
try { $updJobs = ((az containerapp job list --subscription $SubscriptionId -g $ResourceGroup --query "[].{name:name,oid:identity.principalId}" -o json 2>$null) | Out-String) | ConvertFrom-Json } catch { $updJobs = $null }
$updJob = @($updJobs | Where-Object { $_ -and "$($_.name)" -eq $UpdateJobName }) | Select-Object -First 1
if ($updJob -and "$($updJob.oid)".Trim()) {
    $updAppId = Resolve-PimMiAppId -ObjectId "$($updJob.oid)".Trim() -What $UpdateJobName
    Grant-PimMiSqlHere -DbUserName $UpdateJobName -MiAppId $updAppId
    Note "MI $updAppId granted SQL (db user [$UpdateJobName]) -- the nightly updater's schema step"
} elseif ($updJob) {
    Warn "'$UpdateJobName' has no system identity -- it cannot be granted a database user; re-run Deploy-PimUpdateJob."
} else {
    Note "'$UpdateJobName' is not installed yet -- Deploy-PimUpdateJob grants its database user when it installs it."
}
if ($UseInCloudDbInit) { Invoke-PimDbInitJob -Principals $script:PimDbInitPrincipals }

# --- Persistent SQL compute (REQUIREMENTS S5: no auto-pause / cold starts) -----
# Assert/disable serverless auto-pause on the hosted Azure SQL so /health + the
# first post-idle request never cold-start. Needs the SQL server's RG + short name.
if (-not $SkipPersistentSqlCheck) {
    $sqlServerShort = ($SqlServerFqdn -split '\.')[0]
    $sqlRg = if ($SqlResourceGroup) { $SqlResourceGroup } else { $ResourceGroup }
    Step "SQL persistent compute: assert auto-pause disabled ($sqlServerShort/$SqlDatabase)"
    try { Set-PimSqlNoAutoPause -ResourceGroup $sqlRg -SqlServerName $sqlServerShort -SqlDatabase $SqlDatabase -SubscriptionId $SubscriptionId }
    catch { Write-Warning "  persistent-SQL assert skipped: $($_.Exception.Message)" }
}

# --- DNS: register the manager's external FQDN on the AD DNS server -----------
$mgr = $Workers | Where-Object { $_.entry -eq 'manager' } | Select-Object -First 1
$mgrFqdn = $null
if ($mgr) {
    $mgrFqdn = az containerapp ingress show @subArgs -g $ResourceGroup -n $mgr.name --query fqdn -o tsv 2>$null
    if ($mgrFqdn -and $DnsServer) {
        Step "DNS: $mgrFqdn -> $envStatic on $DnsServer"
        Write-PimDnsRecord -DnsServer $DnsServer -Fqdn $mgrFqdn -EnvDomain $envDomain -StaticIp $envStatic
        Note "Manager URL: https://$mgrFqdn/"
    } elseif ($mgrFqdn -and $Exposure -eq 'internal') {
        Note "Manager FQDN: $mgrFqdn  (no -DnsServer given; register A '$mgrFqdn' -> $envStatic on your DNS manually)"
    } elseif ($mgrFqdn) {
        Note "Manager URL: https://$mgrFqdn/  (EXTERNAL environment -- this name resolves publicly, no DNS record to add)"
    }
}

Step 'Done.'
# 🪤 THE CLOSING GUIDANCE ASSUMED AN INTERNAL ENVIRONMENT, and said so in three ways at once on an
# EXTERNAL deploy: "verify from a hub/VNet client", "register this A record on your DNS manually",
# and a GSA/private-link checklist opening "The Manager stays private ... no public exposure" --
# printed directly under a PUBLIC static IP. Measured at a live customer 2026-09-08. Wrong closing
# advice is the most expensive kind: it is the last thing the operator reads and the first thing
# they act on.
if ($mgrFqdn) {
    if ($Exposure -eq 'internal') {
        Write-Host "Verify from a hub/VNet client:  curl https://$mgrFqdn/   (expect 200; /api needs the page-embedded token)" -ForegroundColor Green
    } else {
        Write-Host "Verify from anywhere:  curl https://$mgrFqdn/   (expect 200; /api needs the page-embedded token)" -ForegroundColor Green
        Write-Host "PUBLIC INGRESS: put Easy Auth in front before anyone opens it, and consider an IP allowlist:" -ForegroundColor Yellow
        Write-Host "  az containerapp ingress access-restriction set -g $ResourceGroup -n $ManagerApp --rule-name office --ip-address <x.x.x.x/32> --action Allow" -ForegroundColor Yellow
        Write-Host "  (to lock it down completely later, reversibly: az containerapp ingress update -g $ResourceGroup -n $ManagerApp --type internal)" -ForegroundColor DarkGray
    }
}
# GSA / Private Access + private-link / DNS guidance -- for a PRIVATE Manager only. On an external
# environment none of it applies: the name resolves publicly, there is no private FQDN to publish
# through Global Secure Access, and no privatelink zone for the app.
if ($Exposure -eq 'internal') { Show-PimGsaPrivateLinkGuidance -ManagerFqdn $mgrFqdn }
