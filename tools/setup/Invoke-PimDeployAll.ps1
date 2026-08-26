#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS -- ONE-SHOT "deploy everything" orchestrator: stand up OR update the WHOLE
    solution end-to-end for a target customer/environment, then PROVE it with the test-tenant
    validation. REQUIREMENTS.md sec.3 (Setup / Deploy) -- the "one-shot deploy everything" item.

.DESCRIPTION
    A SINGLE entry that runs the full deploy IN ORDER, idempotently (safe to re-run -- a re-run
    becomes the updater, every already-current step is a clean no-op):

      1. APP-REG  -- ensure the engine app-registration + Graph/Azure grants exist
                     (Install-PimEngineAppRegistration.ps1). Skipped when already present.
      2. INFRA    -- stand up / refresh the infra: hosted = containers/ACA env + worker matrix
                     (Setup-PimContainers.ps1); community/VM = scheduled-task host (Setup-PimVM.ps1).
                     Skipped when the env already exists.
      3. SCHEMA   -- idempotent SQL schema upgrade (preflight -> apply -> re-preflight; NEVER
                     destructive). Composed via Invoke-PimUpdate (its DETECT + guarded-DDL path).
      4. CODE     -- build + deploy the Manager/scheduler/engine image
                     (Invoke-PimUpdate.ps1 -Apply: build-from-pulled-code -> roll the ACA revision;
                     community = local build/relaunch). This is the ONLY rollbackable step.
      5. VERIFY   -- prove the deployment works: the hosted smoke
                     (tests/live/Test-PimManagerHostedSmoke.ps1) + the deploy-validation tests
                     (tests/live/PIM.DeployValidation.Tests.ps1).
      6. SUMMARY + VERIFY-THEN-ROLLBACK -- on a verify failure, auto-roll the CODE step back to
                     the captured pre-deploy revision; print + return the run summary.

    The ORCHESTRATION CORE is pure + offline-unit-tested (engine/_shared/PIM-DeployAll.ps1):
    the ordered step plan, the per-step gate/skip/idempotent-no-op decisions, the
    verify-then-rollback verdict, and the rollback plan all live there with NO az/SQL/HTTP. This
    script only GATHERS facts (is the app-reg present? does the ACA env exist? does the DB
    conform? is the image current?) and INVOKES each step's runner. The runners are INJECTABLE
    (-StepRunner) so the whole flow is offline-testable without touching Azure.

    This script does NOT reinvent the pieces -- it ORCHESTRATES the existing setup family:
    Install-PimEngineAppRegistration.ps1, Setup-PimContainers.ps1 / Setup-PimVM.ps1, and
    Invoke-PimUpdate.ps1 (which itself owns the build/deploy/schema/verify/rollback lifecycle).

    MODES:
      -WhatIf        : plan only (DEFAULT-SAFE). Prints the ordered plan; makes NO changes.
      -Apply         : run the needed steps in order (idempotent); verify; rollback on failure.
      -ValidateOnly  : run ONLY the test-tenant validation (smoke + deploy-validation tests).

    Parameterised for ANY tenant -- NO hardcoded tenant/sub/SQL/RG/KV (per CLAUDE.md). Cert-auth,
    unattended-capable. The live deploy+validate against a real test tenant is the RELEASE GATE;
    this script delivers the orchestration -- it does not claim live-verified by itself.

.PARAMETER Source
    'sync-automateit' (hosted: ACA + Azure SQL) or 'git-pull' (community/VM/local). Drives whether
    INFRA is Setup-PimContainers (hosted) or Setup-PimVM (community).

.PARAMETER TenantId / SubscriptionId
    Target tenant + subscription (no defaults -- pass your own, per CLAUDE.md).

.PARAMETER ResourceGroup / VnetName / VnetResourceGroup / AcrName / EnvName
    Hosted infra targets (Setup-PimContainers). Required for a hosted INFRA stand-up.

.PARAMETER SqlServerFqdn / SqlDatabase / SqlConnectionString
    SQL target. SqlConnectionString feeds the schema-drift DETECT + idempotent upgrade.

.PARAMETER ImageTag
    Image tag to build/deploy (default = the pulled VERSION file).

.PARAMETER EngineClientId / EngineCertThumbprint
    Engine SPN identity for the deploy-validation tests (cert-auth, unattended).

.PARAMETER WhatIf / Apply / ValidateOnly
    See MODES above. -WhatIf is the default when neither -Apply nor -ValidateOnly is given.

.PARAMETER StepRunner
    (TEST/advanced) a scriptblock invoked instead of the real per-step runner:
    & $StepRunner $stepKey $context -> returns @{ ok=$bool; ran=$bool; detail='' }. Lets the
    orchestration be exercised end-to-end OFFLINE. Omit it for real deploys.

.EXAMPLE
    .\Invoke-PimDeployAll.ps1 -Source sync-automateit -TenantId <tid> -SubscriptionId <sub> `
        -ResourceGroup rg-pim -VnetName vnet -VnetResourceGroup rg-net -AcrName myacr `
        -SqlServerFqdn my.database.windows.net
    Plan-only (default -WhatIf): print the ordered deploy-everything plan; make no changes.

.EXAMPLE
    .\Invoke-PimDeployAll.ps1 -Source sync-automateit -TenantId <tid> -SubscriptionId <sub> `
        -ResourceGroup rg-pim -VnetName vnet -VnetResourceGroup rg-net -AcrName myacr `
        -SqlServerFqdn my.database.windows.net -SqlConnectionString '<conn>' -Apply
    Stand up / update the whole solution, then verify; auto-rollback the code on a verify failure.

.EXAMPLE
    .\Invoke-PimDeployAll.ps1 -Source sync-automateit -TenantId <tid> -ResourceGroup rg-pim `
        -SqlDatabase PimPlatform -EngineClientId <cid> -EngineCertThumbprint <thumb> -ValidateOnly
    Run ONLY the test-tenant validation against an already-deployed environment.

.NOTES
    PS 5.1-safe. Pure decision core: engine/_shared/PIM-DeployAll.ps1. Offline tests:
    tests/Test-PimDeployAll.ps1. Live deploy+validate against a test tenant = the release gate.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('git-pull','sync-automateit')][string]$Source = 'sync-automateit',
    # s31: stand up the right TOPOLOGY for a deployment SCENARIO (S1..S6). When set, the scenario's
    # resolved update source + managed hosting drive the deploy path (overrides -Source); it is also
    # passed through to Invoke-PimUpdate so the from-master (S5/S6) downlink is honoured end-to-end.
    [ValidateSet('S1','S2','S3','S4','S5','S6')][string]$Scenario,
    # The environment's deployment descriptor (bootstrap\platform-deploy.json). Optional and
    # non-breaking: without it this script behaves exactly as it did, which is what keeps every
    # environment deployed before the descriptor existed working (framework §5.4 -- descriptor
    # presence is the v2/v3 switch).
    # 🔒 THE CLI RULE (framework DEPLOY-2 §4): a deploy command line may carry only WHICH descriptor
    # and WHAT MODE -- never an infrastructure value. Adding a resource-naming parameter here
    # re-opens the second configuration surface the descriptor exists to close.
    [string]$Descriptor,
    [switch]$Apply,
    [switch]$ValidateOnly,

    # --- target tenant / subscription (no real ids baked in; pass your own) ---
    [string]$TenantId,
    [string]$SubscriptionId,

    # --- hosted infra targets (Setup-PimContainers) ---
    [string]$ResourceGroup,
    [string]$VnetName,
    [string]$VnetResourceGroup,
    [string]$AcrName,
    # --- COST SHAPE (ESTATE-04). These were MISSING, and their absence was expensive ---------
    # Setup-PimContainers defaults to WorkerMode 'always-on' + ManagerMinReplicas 1: six apps at
    # ~3 vCPU / 6 GiB running 24/7, ~$205-230 per environment per month. This orchestrator could
    # not pass anything else, so "deploy everything" SILENTLY deployed the expensive shape --
    # including to a production tenant -- overriding the operator-approved on-demand design that
    # framework DOCS/REQUIREMENTS.md §10.0d records. Found 2026-08-09 while deploying PIM §34,
    # before the apply, by checking the SKUs rather than trusting the orchestrator.
    #
    # The defaults here are the APPROVED shape, not the historical one, because this script is the
    # "deploy everything" front door and a front door should not need expert flags to avoid a
    # $230/month surprise. Setup-PimContainers keeps its own default for direct callers.
    # Note §10.0d's conclusion explicitly: on-demand "is not a test-estate concession -- it is the
    # right shape for a paying customer too."
    [ValidateSet('always-on','cron')][string]$WorkerMode = 'cron',
    [int]$ManagerMinReplicas = 0,             # 0 = scale-to-zero; GUI cold-starts on first request
    [string]$TickCron        = '*/5 * * * *', # UTC; the tick itself decides what is due
    # In cron mode this Job IS the workload -- the five worker apps do not exist. The infra
    # readiness probe therefore has to know its name (BUG-46), not just the Manager's.
    [string]$TickJobName     = 'ca-pim-tick',
    # IMP-06a: UPN of the shared sender mailbox, forwarded to Setup-PimContainers so BOTH the
    # Manager and the tick Job get it. Optional -- an environment with no Exchange plan cannot
    # have one -- but its absence is REPORTED by Setup-PimContainers rather than left silent,
    # because an unset sender renders notification mail without sending it while account
    # creation and TAP minting still report success. Normally supplied by Initialize-PimMailSender.ps1.
    [string]$MailSender,
    [string]$EnvName        = 'cae-pim',
    [string]$Location       = 'westeurope',
    [string]$ImageRepo      = 'pim-manager',
    [string[]]$Apps         = @('ca-pim-manager','ca-pim-scheduler','ca-pim-engine','ca-pim-connector','ca-pim-deltaqueue','ca-pim-discovery'),
    [string]$ManagerApp     = 'ca-pim-manager',
    [string]$ImageTag,

    # --- SQL ---
    [string]$SqlServerFqdn,
    [string]$SqlDatabase    = 'PimPlatform',
    [string]$SqlConnectionString,
    # The SQL Entra admin used ONLY to create the managed identity's contained DB user. The
    # orchestrator did not expose these at all, so the INFRA step died on "missing mandatory
    # parameters" before touching Azure -- the deploy-everything front door could not run the
    # deploy. Cert is the production form; secret remains for the estate's secret-auth tenants.
    [string]$SqlAdminClientId,
    [string]$SqlAdminClientSecret,
    [string]$SqlAdminCertThumbprint,
    # 🔴 §34.2c -- THE DEPLOY IDENTITY FOR THE `az` DATA PLANE. Setup-PimContainers has always had
    # its own -AdminAppId/-AdminSecret sign-in (into an ISOLATED AZURE_CONFIG_DIR); this
    # orchestrator never passed them, so INFRA alone ran on whatever `az` context happened to be
    # active while every other step signs itself in. That is the BUG-23 class: a credential path
    # that succeeds while being wrong.
    # 🪤 MEASURED 2026-08-13 on the first real greenfield run: the ambient context was
    # **ExpertsLiveDK -- a DIFFERENT COMPANY** (it is regularly the default on this machine), and
    # the deploy stopped only because Setup-PimContainers refuses an unusable context. Without that
    # refusal it would have run against another company's tenant. These are CREDENTIALS, not
    # infrastructure values, so they do not belong in the descriptor and do not breach the
    # DEPLOY-2 §4 CLI rule -- secrets never travel in a config file.
    [string]$AdminAppId,
    [string]$AdminSecret,
    # SEC-11: the CERT form of the same deploy identity. The repo-root rule is "never use client
    # secrets", and every other setup script already takes a PEM -- so without this a cert-only
    # operator passed neither credential, the splat below stayed empty, and INFRA fell back to the
    # AMBIENT context: exactly the hole SS34.2c closed, still open for the identity shape this
    # project actually uses. A path is not a secret, so it could live in a descriptor; it stays on
    # the CLI beside its appid because splitting one credential across two surfaces invites the
    # half-configured deploy.
    [string]$AdminCertPem,
    # --- BUG-68: the PREREQ step's inputs -------------------------------------------------
    # New-PimHostingPrerequisites DERIVES every name from the estate token (rg-automateit-<t>,
    # vnet-pim-<t>, acrpim<t>, sql-ait-<t>, id-pim-<t>) while this orchestrator RECEIVES names
    # explicitly. That mismatch is dangerous, not cosmetic: a token whose derived names disagree
    # with -ResourceGroup/-AcrName would provision a COMPLETE set of resources that `infra` then
    # never looks at -- a silent split-brain deploy, and the most expensive kind of "success".
    # So the step DERIVES the names and REFUSES when they disagree (see the 'prereq' runner).
    [string]$PrereqToken,
    # Stable per-environment index -> address space ($AddressBase.<index*8>.0/21). Mandatory in
    # the prereq script because two environments sharing a CIDR is unrecoverable once peered.
    [int]$PrereqIndex = -1,
    [string]$PrereqAddressBase = '10.220',
    # The AcrPull identity the prereq step creates and INFRA consumes. Derived from the token by
    # the script; named here so the fact-probe can test the ROLE (BUG-42/46) rather than guess.
    [string]$PrereqIdentityName,
    # S5 managed tenants use the MASTER's store and must NOT get one of their own -- creating it
    # here would quietly turn S5 into S6 (the prereq script's own words).
    [switch]$PrereqSkipSql,
    # The user-assigned identity that holds AcrPull, created by New-PimHostingPrerequisites as
    # 'id-pim-<token>'. Setup-PimContainers refuses to create apps without it (the alternative is
    # enabling the ACR admin account, which this design deliberately does not do -- BUG-42 was apps
    # attached to a user identity but told to pull with the SYSTEM one). The orchestrator could not
    # pass it, so INFRA failed after creating the ACA environment: a half-built environment.
    [string]$RegistryIdentityResourceId,
    # BUG-37. Setup-PimContainers only hands ACA an existing workspace when it is TOLD which one;
    # the parameter defaults to empty and the orchestrator never passed it, so ACA generated its own
    # and every log went there while law-pim-<token> sat empty and billed. The fix existed and was
    # simply unreachable from the front door -- reproduced live on mfnpr 2026-08-09, which is the
    # confirmation §33.10 was waiting for.
    [string]$LogAnalyticsWorkspaceName,
    [string]$LogAnalyticsResourceGroup,

    # --- REACHABILITY + AZURE SIGHT (BUG-49 / BUG-51) -------------------------
    # These were the two things "deploy everything" did NOT deploy, and both are invisible to
    # every resource-level check. `New-PimHostingPrerequisites` creates an ISOLATED spoke VNet
    # and this orchestrator never peered it, never passed -DnsServer, and never granted the
    # workload identities any ARM rights. The result, measured on a production tenant: a Manager
    # with no route from anywhere, an FQDN that resolved nowhere, and a tick reporting
    # azure-scopes=0 -- with a green deploy summary over all of it. At 25 tenants that is 25
    # deployed, healthy-looking, unreachable, Azure-blind environments.
    # They are parameters rather than defaults because only the caller knows which VNet its
    # clients live on; but their ABSENCE is now WARNED about, not passed over.
    [string]$HubVnetName,
    [string]$HubVnetResourceGroup,
    [string]$HubVnetSubscriptionId,
    [string]$PrivateDnsResourceGroup,
    [switch]$SkipPrivateDns,
    # AD/on-prem DNS (a domain-joined client resolving via AD DNS does NOT see an Azure private
    # zone unless its DNS forwards to 168.63.129.16 -- so this is the second, independent path).
    [string]$DnsServer,
    [string[]]$AzureRbacRoles = @('Reader'),
    [string]$AzureRbacManagementGroupId,
    [switch]$SkipAzureRbac,
    [switch]$RequireAzureRbac,

    # --- engine identity: deploy-validation tests AND (IMP-08) the containers' Graph auth ---
    # These are now forwarded to Setup-PimContainers as well. Without them the hosted engine falls
    # back to the container's managed identity, which is created for SQL and holds NO Graph
    # app-roles, so every Graph call returns 403 Authorization_RequestDenied and the environment
    # provisions nothing while looking perfectly deployed.
    # Certificate preferred, client secret as fallback (operator, 2026-08-12).
    [string]$EngineClientId,
    [string]$EngineCertThumbprint,
    [string]$EngineClientSecret,
    [string]$DeployMarker   = 'PIMCOREENGINE-',

    # --- app-registration installer passthrough ---
    [string]$EngineAppDisplayName = 'PIM4EntraPS Engine',

    # --- verify knobs ---
    [switch]$SkipVerify,                     # opt out of step 5 entirely (NOT recommended)
    # The engine app-registration is frequently provisioned OUT OF BAND -- by a directory admin, or
    # (myfamilynetwork) years before this orchestrator existed. The deploying identity then usually
    # has Azure rights but NO Graph rights, and Test-EngineAppRegPresent returns $null meaning
    # "cannot determine", which the plan fail-safes to NEEDED. The step then tries to CREATE an app
    # that already exists and dies with Authorization_RequestDenied -- taking the whole deploy with
    # it at step 1, even though every remaining step would have succeeded. Observed 2026-08-09
    # deploying PIM §34 with an SPN that is Owner at the tenant root management group: Owner is
    # Azure control plane and grants nothing in Graph (the exact inverse of the "Global Admin grants
    # nothing in Azure" lesson in framework §10.0b).
    [switch]$SkipAppReg,

    # --- TEST seam: inject the per-step runner so the whole flow is offline-testable ---
    [scriptblock]$StepRunner
)
$ErrorActionPreference = 'Stop'
$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)            # SOLUTIONS/PIM4EntraPS
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Info($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }
function Have($cmd){ [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# ---- load the pure decision core (REUSE; never re-implement) ----
. (Join-Path $solRoot 'engine\_shared\PIM-SyncAutomateIT.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateLifecycle.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-DeployAll.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-ScenarioProfile.ps1')     # s31 scenario -> knob resolver

# default-safe: a bare run is plan-only (-WhatIf). -Apply opens the gate.
$applyGate = [bool]$Apply
if ($ValidateOnly) { $applyGate = $true }   # validate-only still "runs" its single step

# ---- s31: a -Scenario resolves the deploy topology, overriding -Source ----
# The DeployAll CORE (Get-PimDeployAllPlan) + the local fact-probes only model git-pull |
# sync-automateit (hosted vs community), so from-master is mapped to a PLAN source by managed
# hosting: central => sync-automateit (ACA/Azure SQL), local => git-pull (local host). The REAL
# from-master downlink is honoured by passing -Scenario through to Invoke-PimUpdate (below).
$planSource    = $Source
$scenarioArgs  = @{}     # splat threaded into Invoke-PimUpdate sub-calls (empty unless -Scenario)
if ($Scenario) {
    $sPlan = Get-PimScenarioEntryPlan -Scenario $Scenario
    $planSource = if ($sPlan.updateSource -eq 'from-master') { if ($sPlan.managedHosting -eq 'central') { 'sync-automateit' } else { 'git-pull' } }
                  elseif ($sPlan.updateSource -eq 'sync-automateit') { 'sync-automateit' } else { 'git-pull' }
    $Source = $planSource
    $scenarioArgs['Scenario'] = $Scenario
    Write-Host ("[scenario] {0} ({1}) -> updateSource={2} managedHosting={3} planSource={4} hosting={5} spn={6} edition={7}" -f `
        $sPlan.id, $sPlan.role, $sPlan.updateSource, $sPlan.managedHosting, $planSource, $sPlan.hostingLocation, $sPlan.spnModel, $sPlan.activeEdition) -ForegroundColor Cyan
}
$srcProfile = Get-PimUpdateSourceProfile -Source $Source
$hosted  = [bool]$srcProfile.isHosted

# =============================================================================
# 🔑 BUG-67 -- THE DESCRIPTOR ANSWERS "WHAT COMPUTE", INSTEAD OF IT BEING INFERRED FROM "WHOSE
# TENANT". Read this before touching the $hosted logic above.
#
# `Get-PimUpdateSourceProfile` derives hosting from the MSP TOPOLOGY:
#     from-master + ManagedHosting local  ->  isHosted = $false  ->  VM / local-build path
# but "local" carries two unrelated meanings that were treated as one axis:
#     * MSP topology   -- local = in the CUSTOMER'S OWN tenant (vs central = in the MSP's)
#     * hosting flavour-- local = a VM with a local build      (vs hosted = ACA + ACR)
# A managed tenant is routinely topology-local AND hosting-hosted. MEASURED: an S6 managed tenant
# in the estate runs pim-manager (container app), pim-tick (job), cae-pim-ext (managed environment)
# and its own ACR -- Container Apps end to end -- while the plan resolved it to hosted=False. On
# -Apply that sends INFRA to Setup-PimVM.ps1 instead of Setup-PimContainers.ps1, for EVERY S6
# tenant. It had never been hit only because the orchestrator was not in the estate's deploy path.
#
# The fix is not a new private flag: the environment descriptor ALREADY states this.
# `provides.container-apps-environment` is the environment declaring it has ACA, so hosting becomes
# a fact that is READ rather than a consequence inferred from an unrelated axis.
#
# 🔒 NON-BREAKING BY CONSTRUCTION: with no -Descriptor, nothing below runs and the inferred value
# stands, so every environment deployed before this existed behaves exactly as it did (framework
# §5.4 -- "descriptor presence is the v2/v3 switch").
# =============================================================================
$descriptorDoc = $null
if ($Descriptor) {
    $aitDeploy = Join-Path (Split-Path -Parent (Split-Path -Parent $solRoot)) 'sync\_AitPlatformDeploy.ps1'
    if (-not (Test-Path -LiteralPath $aitDeploy)) { throw "-Descriptor supplied but the framework reader is missing: $aitDeploy" }
    . $aitDeploy
    $descriptorDoc = Get-AitPlatformDeploy -Path $Descriptor
    if (-not $descriptorDoc) { throw "-Descriptor '$Descriptor' is missing or empty. Refusing to deploy against a descriptor that says nothing -- that is indistinguishable from deploying with no configuration at all." }

    $resolved = Resolve-AitSolutionDeploy -Config $descriptorDoc -SolutionName 'PIM4EntraPS'

    # THE BUG-67 FIX ITSELF, and it is resolved FIRST because the validation below depends on it:
    # ACA declared => hosted, whatever the MSP topology says.
    $hasAca = $false
    foreach ($k in $resolved.Provides.Keys) { if ("$k".ToLowerInvariant() -eq 'container-apps-environment') { $hasAca = $true; break } }
    if ($hasAca -ne $hosted) {
        Write-Host ("[descriptor] hosting: {0} -> {1} (the descriptor {2} declare container-apps-environment; the MSP topology is a SEPARATE axis -- BUG-67)" -f `
            $hosted, $hasAca, $(if ($hasAca) { 'DOES' } else { 'does NOT' })) -ForegroundColor Yellow
    }
    $hosted = $hasAca

    # Validate BEFORE anything is created. An unresolved dependency must stop the deploy here,
    # where the message is actionable, rather than three scripts deep after infra exists.
    #
    # 🪤 VALIDATE THE CAPABILITIES THAT WILL ACTUALLY RUN, not a fixed list. `infra`'s own
    # `requires` (registry, container-apps-environment, sql) are ACA-SPECIFIC, so demanding them of
    # a VM-hosted environment would make PIM's contract contradict itself: `infra` is declared
    # OPTIONAL precisely so a differently-hosted install is supported, and a validator that refuses
    # that install has turned a supported topology into an error. An earlier version of this block
    # enabled `infra` unconditionally and did exactly that.
    $contractPath = Join-Path $solRoot 'solution.deploy.json'
    if (Test-Path -LiteralPath $contractPath) {
        $contract = Get-Content $contractPath -Raw | ConvertFrom-Json
        $enabled  = @('code', 'schema')
        if (-not $SkipAppReg) { $enabled += 'appreg' }
        if ($hasAca)          { $enabled += 'infra' }
        $verdict = Test-AitSolutionDeployReady -Resolved $resolved -Contract $contract -EnabledCapabilities $enabled
        Format-AitDeployReadiness -Verdict $verdict -SolutionName 'PIM4EntraPS' | ForEach-Object {
            Write-Host $_ -ForegroundColor $(if ($verdict.Ready) { 'Green' } else { 'Red' })
        }
        if (-not $verdict.Ready) { throw 'the descriptor does not satisfy PIM''s own deploy contract (see above). Refusing to deploy.' }
    }
}

# 🪤 -Apps DEFAULTS TO THE SIX-APP MATRIX, WHICH ONLY EXISTS IN 'always-on' MODE. In cron mode
# Setup-PimContainers creates the Manager and ONE tick Job -- the five workers are never created,
# because the tick replaces them. Leaving the default alone made the CODE step ask
# Update-PimContainers to roll six apps, five of which cannot exist, and it correctly refused with
# "no requested app exists in the resource group" -- an error that describes the symptom and hides
# the cause. Only override the DEFAULT: an explicit -Apps from the caller always wins.
if ($WorkerMode -eq 'cron' -and -not $PSBoundParameters.ContainsKey('Apps')) {
    $Apps = @($ManagerApp)
}

Write-Host "=== PIM4EntraPS DEPLOY-ALL ($Source; $(if($ValidateOnly){'VALIDATE-ONLY'}elseif($Apply){'APPLY'}else{'WHATIF / PLAN-ONLY'})) ===" -ForegroundColor Cyan
Info "hosted=$hosted; tenant=$(if($TenantId){'set'}else{'(not set)'}); sub=$(if($SubscriptionId){'set'}else{'(not set)'})"

# =============================================================================
# GATHER FACTS -- the side-effecting reads. The DECISIONS stay in the pure core.
# Each fact answers "is this step NEEDED?" ($true = run; $false = already current).
# Absent / unknown => $true (fail-safe: run rather than skip a real change).
# =============================================================================
function Test-EngineAppRegPresent {
    # present when an app with the engine display name exists AND has a credential. Best-effort
    # via az; unknown (no az / not logged in) => NEEDED=$true (let the idempotent installer run).
    if (-not (Have 'az')) { return $null }
    try {
        $id = az ad app list --display-name $EngineAppDisplayName --query "[0].appId" -o tsv 2>$null
        if ("$id".Trim()) { return $true }
        return $false
    } catch { return $null }
}
function Get-EffectiveImageTag {
    if ("$ImageTag".Trim()) { return $ImageTag }
    $vf = Join-Path $solRoot 'VERSION'
    if (Test-Path $vf) { return (Get-Content -LiteralPath $vf -Raw).Trim() }
    return 'latest'
}

function Test-HostingPrereqsPresent {
    <#
      BUG-68 -- the `prereq` fact. New-PimHostingPrerequisites creates, in order: resource group,
      VNet + delegated subnet, Log Analytics, ACR, the AcrPull identity (and its ROLE), and the
      SQL server + database.

      🔴 PROBE THE LAST THING THE STEP DOES, NOT ITS FIRST ARTEFACT -- the BUG-46 lesson, which
      this codebase has now learned three times. "The resource group exists" is the `az group
      create` on line 102 of a script that then does six more things; a run that died anywhere
      after it would leave a half-built tenant that every later run called "already current" and
      SKIPPED. So this tests the artefacts that are created LAST and fail SILENTLY:
        * the AcrPull ROLE ASSIGNMENT, not merely the identity -- an identity without AcrPull is
          indistinguishable from a working one right up until the first image pull fails, which
          happens inside `infra`, several steps away from the cause (this is BUG-42's shape).
        * the SQL SERVER, unless the environment uses a central store (-SkipSql / S5), because
          `schema` two steps later has nothing to talk to without it.
      Unreadable => $null => NEEDED (fail-safe): one extra idempotent re-run costs far less than
      a permanently half-built tenant.
    #>
    if (-not $hosted) { return $false }
    if (-not (Have 'az') -or -not "$ResourceGroup".Trim() -or -not "$AcrName".Trim()) { return $null }
    try {
        $g = az group show -n $ResourceGroup --query name -o tsv 2>$null
        if (-not "$g".Trim()) { return $false }
        $acrId = az acr show -n $AcrName --query id -o tsv 2>$null
        if (-not "$acrId".Trim()) { return $false }
        # the identity AND its role -- see above.
        $uamiPrincipal = az identity show -g $ResourceGroup -n $PrereqIdentityName --query principalId -o tsv 2>$null
        if (-not "$uamiPrincipal".Trim()) {
            Write-Host "  prereq: registry '$AcrName' exists but pull identity '$PrereqIdentityName' does NOT -- half-built; re-running PREREQ." -ForegroundColor Yellow
            return $false
        }
        $pull = az role assignment list --assignee $uamiPrincipal --scope $acrId --role AcrPull `
                    --query "[0].roleDefinitionName" -o tsv 2>$null
        if (-not "$pull".Trim()) {
            Write-Host "  prereq: '$PrereqIdentityName' exists but holds NO AcrPull on '$AcrName' -- every image pull would fail in INFRA; re-running PREREQ." -ForegroundColor Yellow
            return $false
        }
        if (-not $PrereqSkipSql) {
            $srv = ("$SqlServerFqdn" -split '\.')[0]
            if ("$srv".Trim()) {
                $s = az sql server show -g $ResourceGroup -n $srv --query name -o tsv 2>$null
                if (-not "$s".Trim()) {
                    Write-Host "  prereq: SQL server '$srv' does NOT exist -- SCHEMA would have nothing to talk to; re-running PREREQ." -ForegroundColor Yellow
                    return $false
                }
            }
        }
        return $true
    } catch { return $null }
}
function Test-ManagerImagePresent {
    <#
      BUG-68 -- the `image` fact, and it is deliberately NOT the same question as `code`'s.
      `code` asks "is the RUNNING app on current content?" (Test-ManagerImageCurrent, via the GUI
      detect). This asks only "does the tag EXIST in the registry?", because that is the single
      thing `infra` requires in order to resolve a digest and stand anything up. On a tenant that
      has never been deployed there is no running app to compare against, so the `code` question
      has no answer there -- which is exactly how the cycle stayed invisible.
      Unreadable / no registry => $false (build it): the build is idempotent, and `az acr build`
      on an existing tag is cheap next to a deploy that cannot start.
    #>
    if (-not $hosted) { return $false }
    if (-not (Have 'az') -or -not "$AcrName".Trim()) { return $null }
    try {
        $tag = Get-EffectiveImageTag
        if (-not "$tag".Trim()) { return $null }
        $d = az acr repository show -n $AcrName --image "$ImageRepo`:$tag" --query digest -o tsv 2>$null
        return ([bool]"$d".Trim())
    } catch { return $null }
}
function Test-AcaEnvPresent {
    <#
      🔴 THE PROBE MUST TEST WHAT THE STEP BUILDS, NOT ITS FIRST ARTEFACT.

      This used to return $true as soon as the ACA ENVIRONMENT existed. But the INFRA step's job is
      the environment AND the container apps, and the environment is created FIRST -- so any run
      that died after the environment (this one did, on the missing AcrPull identity) left a
      half-built environment that every later run reported as "target already current" and SKIPPED.
      The apps were then never created, and the deploy failed downstream in `schema` with a
      confusing "no requested app exists", pointing at the wrong step entirely.

      Across 25 customer tenants that is the difference between "one deploy needs a re-run" and
      "one tenant is permanently half-built and the tool refuses to touch it".

      Same family as the SEC-08 read-probe-guarding-a-write: the capability being probed must be
      the capability being used.

      🔴 BUG-46 -- AND IT WAS STILL NOT ENOUGH. Widening the probe from "environment" to
      "environment + Manager app" fixed the case that had just been seen and stopped one artefact
      short of the truth again. In `cron` mode the INFRA step also creates the **tick Job** and --
      the part that actually matters -- **grants its identity a SQL contained user and Graph
      app-roles**. On mfnpr the environment existed, the Manager existed, and the tick Job existed,
      so this returned "already current" and the step was skipped on every re-run. But BUG-44 had
      killed the previous run *between* creating the Job and granting it anything, so the grants
      were permanently missing and the only thing that could have created them was the step this
      probe kept skipping. The Job then ran every five minutes, could not log in to SQL, gated every
      job off and exited 0 (BUG-45). A green deploy, a green Job, and no work being done.

      So the probe now tests the LAST thing the step does, not the first: the app-role assignments.
      Absent or unreadable => NOT current => re-run INFRA, which is idempotent and cheap. Being
      wrong in that direction costs one re-run; being wrong the other way costs a tenant.
    #>
    if (-not $hosted) { return $false }       # non-hosted: infra step is the VM host (handled below)
    if (-not (Have 'az') -or -not "$ResourceGroup".Trim()) { return $null }
    try {
        $e = az containerapp env show -g $ResourceGroup -n $EnvName --query "name" -o tsv 2>$null
        if (-not "$e".Trim()) { return $false }
        # The environment exists. Now the part that actually matters: does the MANAGER app exist?
        $m = az containerapp show -g $ResourceGroup -n $ManagerApp --query "name" -o tsv 2>$null
        if (-not "$m".Trim()) {
            Write-Host "  infra: ACA environment '$EnvName' exists but app '$ManagerApp' does NOT -- half-built; re-running INFRA." -ForegroundColor Yellow
            return $false
        }
        # 🔴 THE SAME LESSON AGAIN, ONE ARTEFACT FURTHER OUT (BUG-49/BUG-51).
        # The INFRA step now also peers the spoke VNet, publishes the environment's default
        # domain, and grants the workload identities their ARM role. If this probe does not test
        # those, then the FIRST re-run of any environment deployed before they existed reports
        # "already current" and skips the only step that could create them -- which is precisely
        # how BUG-44's missing grants became permanent. Being wrong here costs one idempotent
        # re-run; being wrong the other way costs a tenant its reachability, invisibly.
        if ("$HubVnetName".Trim() -and "$HubVnetResourceGroup".Trim() -and "$VnetName".Trim()) {
            $spokeShort = "$VnetName".ToLowerInvariant(); if ($spokeShort -like 'vnet-*') { $spokeShort = $spokeShort.Substring(5) }
            $hubShort   = "$HubVnetName".ToLowerInvariant(); if ($hubShort -like 'vnet-*') { $hubShort = $hubShort.Substring(5) }
            $peerState = az network vnet peering show -g $VnetResourceGroup --vnet-name $VnetName -n "$spokeShort-to-$hubShort" --query peeringState -o tsv 2>$null
            if ("$peerState".Trim() -ne 'Connected') {
                Write-Host "  infra: spoke VNet '$VnetName' is NOT peered to '$HubVnetName' (state='$peerState') -- the Manager has no route from any client; re-running INFRA." -ForegroundColor Yellow
                return $false
            }
        }
        # ARM rights on the identity that actually reconciles: the tick Job in cron mode, the
        # Manager otherwise. Zero role assignments = PIM's Azure half is blind (BUG-51).
        if (-not $SkipAzureRbac -and "$SubscriptionId".Trim()) {
            $rbacOid = $(if ($WorkerMode -eq 'cron') { az containerapp job show -g $ResourceGroup -n $TickJobName --query "identity.principalId" -o tsv 2>$null }
                         else { az containerapp show -g $ResourceGroup -n $ManagerApp --query "identity.principalId" -o tsv 2>$null })
            if ("$rbacOid".Trim()) {
                $armRoles = az role assignment list --assignee "$rbacOid".Trim() --scope "/subscriptions/$SubscriptionId" --query "length(@)" -o tsv 2>$null
                if ("$armRoles".Trim() -and [int]"$armRoles".Trim() -eq 0) {
                    Write-Host "  infra: workload identity holds NO Azure role assignment on /subscriptions/$SubscriptionId -- PIM's Azure half is blind (azure-scopes=0); re-running INFRA." -ForegroundColor Yellow
                    return $false
                }
            }
        }

        # always-on mode: the worker apps are the workload and the Manager standing means the loop
        # ran. cron mode: the tick Job is the workload, so keep going.
        if ($WorkerMode -ne 'cron') { return $true }
        $jobOid = az containerapp job show -g $ResourceGroup -n $TickJobName --query "identity.principalId" -o tsv 2>$null
        if (-not "$jobOid".Trim()) {
            Write-Host "  infra: tick Job '$TickJobName' is missing (or has no identity) -- half-built; re-running INFRA." -ForegroundColor Yellow
            return $false
        }
        # The Job exists. Its GRANTS are the step's real output -- and they are what BUG-44 skipped.
        $roles = az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/$jobOid/appRoleAssignments" --query "length(value)" -o tsv 2>$null
        if (-not "$roles".Trim() -or [int]"$roles".Trim() -eq 0) {
            Write-Host "  infra: tick Job '$TickJobName' exists but its identity holds NO Graph app-roles -- the grant step never completed; re-running INFRA." -ForegroundColor Yellow
            return $false
        }
        return $true
    } catch { return $null }
}
function Test-SchemaConformant {
    # reuse Invoke-PimUpdate's SQL DETECT (it reads the deployed columns + builds the plan). We do
    # NOT duplicate that logic -- we call the detect-only path and read SqlUpdateRequired.
    if (-not "$SqlConnectionString".Trim()) { return $null }   # cannot read => run schema step
    try {
        $upd = Join-Path $here 'Invoke-PimUpdate.ps1'
        $det = & $upd -Source $Source @scenarioArgs -DetectOnly -SqlConnectionString $SqlConnectionString `
                    -ResourceGroup $ResourceGroup -ManagerApp $ManagerApp -ImageTag $ImageTag 6>$null
        $last = @($det) | Where-Object { $_ -and ($_.PSObject.Properties.Name -contains 'SqlUpdateRequired') } | Select-Object -Last 1
        if ($last) { return (-not [bool]$last.SqlUpdateRequired) }
        return $null
    } catch { return $null }
}
function Test-ManagerImageCurrent {
    # reuse Invoke-PimUpdate's GUI DETECT (pulled content hash vs running image). Same as above:
    # detect-only, read GuiUpdateRequired. Unknown => run the code step.
    try {
        $upd = Join-Path $here 'Invoke-PimUpdate.ps1'
        $det = & $upd -Source $Source @scenarioArgs -DetectOnly -SqlConnectionString $SqlConnectionString `
                    -ResourceGroup $ResourceGroup -ManagerApp $ManagerApp -ImageTag $ImageTag 6>$null
        $last = @($det) | Where-Object { $_ -and ($_.PSObject.Properties.Name -contains 'GuiUpdateRequired') } | Select-Object -Last 1
        if ($last) { return (-not [bool]$last.GuiUpdateRequired) }
        return $null
    } catch { return $null }
}

# Build the NEEDED facts. A fact of $true => the target is CURRENT => step NOT needed.
# Get-PimDeployAllPlan wants NEEDED=$true to RUN, so we invert "present/current" facts.
# TEST SEAM: when a -StepRunner is injected the whole flow runs OFFLINE, so we must NOT call the
# side-effecting az/SQL fact probes (they'd hit real Azure, be slow, and make the plan depend on
# the host's logged-in tenant). With the seam present, every step is NEEDED (the fail-safe default)
# so the full ordered plan flows through the injected runner.
$facts = @{}
if (-not $ValidateOnly) {
    if ($StepRunner) {
        $facts['appreg'] = $true; $facts['infra'] = $true; $facts['schema'] = $true; $facts['code'] = $true
        $facts['prereq'] = $true; $facts['image'] = $true   # BUG-68 -- the seam must offer every catalog step
    } else {
        if ($SkipAppReg) {
            # Say it out loud. A skipped step that prints nothing is indistinguishable from a step
            # that ran, which is exactly how a half-deployed environment gets called deployed.
            Write-Host "  appreg: SKIPPED by -SkipAppReg (app-registration assumed provisioned out of band)" -ForegroundColor Yellow
            $facts['appreg'] = $false
        } else {
            $appRegPresent = Test-EngineAppRegPresent
            if ($null -eq $appRegPresent) {
                # NOT the same as absent, and the difference decides whether this deploy can work.
                Write-Host "  appreg: presence UNDETERMINED (no Graph read with this identity) -- assuming NEEDED." -ForegroundColor Yellow
                Write-Host "          If it already exists, re-run with -SkipAppReg." -ForegroundColor DarkGray
            }
            $facts['appreg'] = if ($null -eq $appRegPresent) { $true } else { -not $appRegPresent }  # missing => needed
        }

        # BUG-68: prereq + image, both probed the same idempotent way as everything else. They sit
        # BEFORE infra's fact deliberately -- on a greenfield tenant infra's probe cannot even run
        # (no resource group), and reading these first is what makes the plan legible.
        # $PrereqIdentityName defaults to the script's own convention so the probe tests the REAL
        # identity rather than an empty name that would always read "missing".
        if (-not "$PrereqIdentityName".Trim() -and "$PrereqToken".Trim()) { $PrereqIdentityName = "id-pim-$PrereqToken" }
        $prereqOk = Test-HostingPrereqsPresent
        $facts['prereq'] = if ($null -eq $prereqOk) { $true } else { -not $prereqOk }             # missing => needed

        $imgPresent = Test-ManagerImagePresent
        $facts['image'] = if ($null -eq $imgPresent) { $true } else { -not $imgPresent }          # absent => needed
        $acaPresent = Test-AcaEnvPresent
        $facts['infra'] = if ($null -eq $acaPresent) { $true } else { -not $acaPresent }             # missing => needed

        $schemaOk = Test-SchemaConformant
        $facts['schema'] = if ($null -eq $schemaOk) { $true } else { -not $schemaOk }                # drift => needed

        $imgCurrent = Test-ManagerImageCurrent
        $facts['code'] = if ($null -eq $imgCurrent) { $true } else { -not $imgCurrent }              # stale => needed
    }
}
# 'mailsender' and 'features' are ALWAYS needed, deliberately: both are idempotent (the mail
# setup re-ensures an existing mailbox, the baseline re-asserts gates that are already on), and
# there is no cheap, trustworthy "is it current?" probe for either. The failure they exist to
# prevent -- a deployed-but-inert tenant -- is silent, so the fail-safe is to re-assert every
# deploy rather than to skip on an inference. Both honour -WhatIf through the same gate.
$facts['mailsender'] = $true
$facts['features']   = $true
# verify is always NEEDED (always prove a deploy) unless explicitly skipped.
$facts['verify'] = (-not $SkipVerify)

# =============================================================================
# PLAN -- the pure core fixes the order + gate/skip/no-op decisions.
# =============================================================================
# $hosted may have been corrected from the descriptor (BUG-67) -- pass it, or the plan re-derives
# the stale value from $Source and disagrees with the runner about which infra path to take.
$planArgs = @{}
if ($Descriptor) { $planArgs['HostedOverride'] = $hosted }
$plan = Get-PimDeployAllPlan -Source $Source -Facts $facts -Apply:$applyGate -ValidateOnly:$ValidateOnly @planArgs

Write-Host ""
Write-Host "  DEPLOY-ALL PLAN ($(if($plan.whatIf){'WHATIF'}else{'APPLY'}); hosted=$($plan.hosted)):" -ForegroundColor Cyan
$i = 0
foreach ($s in $plan.steps) { $i++; Write-Host ("    {0}. {1,-8} [{2,-20}] {3}" -f $i, $s.key, $s.action, $s.reason) }
Write-Host ""

if ($plan.whatIf) {
    Step 'WHATIF / PLAN-ONLY -- no changes made. Re-run with -Apply to execute the plan above.'
    $global:LASTEXITCODE = 0   # a plan-only run is clean -- don't leak a best-effort az probe's exit code
    return (Get-PimDeploySummary -StepOutcomes @($plan.steps | ForEach-Object { [pscustomobject]@{ key=$_.key; ran=$false; ok=$true } }) -Verdict $null -PlanOnly)
}

# =============================================================================
# default per-step RUNNERS (the real side-effecting work). Each returns
# @{ ok; ran; detail }. Injected -StepRunner overrides ALL of them (offline tests).
#
# BUG-25 ROOT CAUSE -- why every child invocation below ends in `| Out-Host`.
# A runner's contract is "return EXACTLY ONE @{ok;ran;detail}". `& $child` runs the child
# IN THIS PROCESS, so every object the child puts on its SUCCESS stream -- an uncaptured
# `az ...` line, a stray bare string -- becomes part of THIS function's output. The return
# value then arrives at the caller as an Object[] of {leaked output..., hashtable}, the
# caller's `$res -is [IDictionary]` test fails, `.ok` read off an ARRAY is $null, and
# [bool]$null is $false. A COMPLETELY SUCCESSFUL step was therefore reported as:
#       -> ok=False ran=True            <- note the EMPTY detail: the tell
#     step 'code' FAILED -- halting the deploy.
#     ROLLBACK: code -> reactivate prior ACA revision ...
# ...and the orchestrator tried to roll back a healthy, verified fleet.
# This was NEVER about $LASTEXITCODE -- proven: with the child exiting 0, $LASTEXITCODE
# IS 0 and the step is STILL read as failed, because the verdict never survives the array.
# The two earlier fixes (the updater's explicit `exit 0`; clearing $LASTEXITCODE first)
# were correct and are kept -- they were simply not the cause.
# `| Out-Host` keeps the child's output VISIBLE while emitting nothing downstream, so the
# hashtable is the function's only output. Verified both ways: a child that exits 0 now
# reads ok=True, and one that exits non-zero STILL reads ok=False -- real failures are not
# masked. Every runner clears $LASTEXITCODE first so no step inherits an earlier probe's.
# =============================================================================
function Invoke-DefaultStepRunner {
    param([string]$Key,[hashtable]$Ctx)
    switch ($Key) {
        'appreg' {
            $installer = Join-Path $here 'Install-PimEngineAppRegistration.ps1'
            if (-not (Test-Path $installer)) { return @{ ok=$false; ran=$true; detail="installer not found: $installer" } }
            if ($PSCmdlet.ShouldProcess($EngineAppDisplayName, 'ensure engine app-registration + grants')) {
                $global:LASTEXITCODE = 0
                & $installer -DisplayName $EngineAppDisplayName -TenantId $TenantId -GrantConsent | Out-Host
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                return @{ ok=$ok; ran=$true; detail='app-registration ensured' }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'prereq' {
            # BUG-68: stand up what every later step assumes already exists. This WRAPS the
            # existing, proven New-PimHostingPrerequisites.ps1 -- no provisioning logic was
            # written here, deliberately: the script is idempotent, verifies by reading back, and
            # is what actually built the estate by hand.
            $prq = Join-Path $here 'New-PimHostingPrerequisites.ps1'
            if (-not (Test-Path $prq)) { return @{ ok=$false; ran=$true; detail="prereq script not found: $prq" } }
            if (-not "$PrereqToken".Trim()) {
                return @{ ok=$false; ran=$true; detail='PREREQ needs -PrereqToken (the estate token, e.g. wa678): every prerequisite name is derived from it.' }
            }
            if ($PrereqIndex -lt 0) {
                # Not defaulted on purpose. The index picks the VNet CIDR, and two environments
                # silently sharing one is unrecoverable once anything is peered -- so a wrong
                # guess here is far worse than a refusal.
                return @{ ok=$false; ran=$true; detail='PREREQ needs -PrereqIndex (stable per-environment index -> address space). Refusing to guess: two environments sharing a CIDR cannot be un-peered.' }
            }
            # 🔴 THE SPLIT-BRAIN GUARD. The prereq script derives names from the token; this
            # orchestrator was given them explicitly. If they disagree, prereq would create a
            # COMPLETE, correct-looking set of resources that infra never touches -- and both
            # halves would report success. Prove agreement BEFORE creating anything.
            $derived = @{
                ResourceGroup = "rg-automateit-$PrereqToken"
                AcrName       = ("acrpim$PrereqToken" -replace '[^a-z0-9]','').ToLowerInvariant()
                VnetName      = "vnet-pim-$PrereqToken"
            }
            $mismatch = @()
            if ("$ResourceGroup".Trim() -and $ResourceGroup -ne $derived.ResourceGroup) { $mismatch += "-ResourceGroup '$ResourceGroup' != '$($derived.ResourceGroup)'" }
            if ("$AcrName".Trim()       -and $AcrName       -ne $derived.AcrName)       { $mismatch += "-AcrName '$AcrName' != '$($derived.AcrName)'" }
            if ("$VnetName".Trim()      -and $VnetName      -ne $derived.VnetName)      { $mismatch += "-VnetName '$VnetName' != '$($derived.VnetName)'" }
            if ($mismatch.Count) {
                return @{ ok=$false; ran=$true; detail=("PREREQ token '$PrereqToken' derives names that disagree with the ones this deploy will use: " +
                    ($mismatch -join '; ') + ". Refusing -- provisioning under names INFRA never reads is a silent half-deploy.") }
            }
            if ($PSCmdlet.ShouldProcess($derived.ResourceGroup, 'create hosting prerequisites (RG, VNet, ACR, Log Analytics, SQL, AcrPull identity)')) {
                $prqId = @{}
                if ($AdminAppId -and $AdminCertPem)   { $prqId['AdminAppId'] = $AdminAppId; $prqId['AdminCertPem'] = $AdminCertPem }
                elseif ($AdminAppId -and $AdminSecret){ $prqId['AdminAppId'] = $AdminAppId; $prqId['AdminSecret']  = $AdminSecret }
                else {
                    # This script REQUIRES one of the two (-AdminAppId is Mandatory and it throws
                    # without a credential), so say so here rather than let it throw from inside.
                    return @{ ok=$false; ran=$true; detail='PREREQ needs a deploy identity: -AdminAppId plus -AdminCertPem (production) or -AdminSecret.' }
                }
                $global:LASTEXITCODE = 0
                & $prq @prqId -TenantId $TenantId -SubscriptionId $SubscriptionId -Token $PrereqToken `
                    -Index $PrereqIndex -Location $Location -AddressBase $PrereqAddressBase `
                    -SkipSql:$PrereqSkipSql | Out-Host
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                return @{ ok=$ok; ran=$true; detail=("hosting prerequisites for '$PrereqToken'" + $(if ($PrereqSkipSql) { ' (SQL skipped -- central store)' } else { '' })) }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'image' {
            # BUG-68: build + push ONLY. This is the half that had to come out of `code`, because
            # `code` also ROLLS the apps and the roll refuses to roll zero of them -- so on a
            # tenant with no apps yet, `code` could never run, and `infra` (which needs the image)
            # could never run either. Building here breaks that cycle; the roll stays in `code`.
            $bld = Join-Path $here 'Build-PimManagerImage.ps1'
            if (-not (Test-Path $bld)) { return @{ ok=$false; ran=$true; detail="image builder not found: $bld" } }
            if (-not "$AcrName".Trim()) { return @{ ok=$false; ran=$true; detail='IMAGE needs -AcrName (az acr build targets a registry; it does not create one -- that is PREREQ).' } }
            if ($PSCmdlet.ShouldProcess("$AcrName/$ImageRepo", 'build + push the Manager image')) {
                $bldId = @{}
                if ($AdminAppId -and $AdminCertPem)    { $bldId['AdminAppId'] = $AdminAppId; $bldId['AdminCertPem'] = $AdminCertPem }
                elseif ($AdminAppId -and $AdminSecret) { $bldId['AdminAppId'] = $AdminAppId; $bldId['AdminSecret']  = $AdminSecret }
                $global:LASTEXITCODE = 0
                & $bld @bldId -Source $Source -TenantId $TenantId -AcrName $AcrName -ImageRepo $ImageRepo `
                    -ImageTag (Get-EffectiveImageTag) | Out-Host
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                return @{ ok=$ok; ran=$true; detail="built $AcrName/$ImageRepo`:$(Get-EffectiveImageTag)" }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'infra' {
            # Build the SQL-admin credential splat once. Fail here, before any Azure call, if the
            # caller gave neither -- "missing mandatory parameters" thrown from three scripts deep
            # is the least useful place to learn that a credential was not supplied.
            $sqlAdminCred = @{}
            if ($SqlAdminCertThumbprint) { $sqlAdminCred['SqlAdminCertThumbprint'] = $SqlAdminCertThumbprint }
            elseif ($SqlAdminClientSecret) { $sqlAdminCred['SqlAdminClientSecret'] = $SqlAdminClientSecret }
            elseif ($hosted) {
                return @{ ok=$false; ran=$true; detail='INFRA needs a SQL Entra admin: pass -SqlAdminClientId plus -SqlAdminCertThumbprint (production) or -SqlAdminClientSecret.' }
            }
            $registryIdentity = @{}
            if ($RegistryIdentityResourceId) { $registryIdentity['RegistryIdentityResourceId'] = $RegistryIdentityResourceId }
            if ($LogAnalyticsWorkspaceName)  { $registryIdentity['LogAnalyticsWorkspaceName']  = $LogAnalyticsWorkspaceName }
            if ($LogAnalyticsResourceGroup)  { $registryIdentity['LogAnalyticsResourceGroup']  = $LogAnalyticsResourceGroup }
            # BUG-49/BUG-51 passthrough. Every one of these already existed downstream or was
            # added with them; the defect was that the FRONT DOOR could not reach any of it --
            # the same missing-passthrough class as BUG-37/BUG-42/BUG-46, and the one with the
            # worst failure mode, because what it silently omits is invisible to every check.
            $reach = @{}
            if ($HubVnetName)                { $reach['HubVnetName']                = $HubVnetName }
            if ($HubVnetResourceGroup)       { $reach['HubVnetResourceGroup']       = $HubVnetResourceGroup }
            if ($HubVnetSubscriptionId)      { $reach['HubVnetSubscriptionId']      = $HubVnetSubscriptionId }
            if ($PrivateDnsResourceGroup)    { $reach['PrivateDnsResourceGroup']    = $PrivateDnsResourceGroup }
            if ($SkipPrivateDns)             { $reach['SkipPrivateDns']             = $true }
            if ($DnsServer)                  { $reach['DnsServer']                  = $DnsServer }
            if ($AzureRbacRoles)             { $reach['AzureRbacRoles']             = $AzureRbacRoles }
            if ($AzureRbacManagementGroupId) { $reach['AzureRbacManagementGroupId'] = $AzureRbacManagementGroupId }
            if ($SkipAzureRbac)              { $reach['SkipAzureRbac']              = $true }
            if ($RequireAzureRbac)           { $reach['RequireAzureRbac']           = $true }
            if ($hosted -and -not ($HubVnetName -and $HubVnetResourceGroup)) {
                # Say it at the FRONT DOOR, before anything is created -- not three scripts deep
                # where it reads as a detail of the container setup.
                Warn ("no -HubVnetName/-HubVnetResourceGroup: the PIM spoke VNet will be left ISOLATED and the " +
                      "Manager unreachable from any client. The deploy will still report success (BUG-49).")
            }
            if ($hosted) {
                $setup = Join-Path $here 'Setup-PimContainers.ps1'
                if (-not (Test-Path $setup)) { return @{ ok=$false; ran=$true; detail="setup not found: $setup" } }
                if ($PSCmdlet.ShouldProcess($ResourceGroup, 'stand up / refresh ACA infra')) {
                    $global:LASTEXITCODE = 0
                    # §34.2c: pass the deploy identity so INFRA signs itself in to an isolated
                    # AZURE_CONFIG_DIR like every other step, instead of inheriting the ambient
                    # context. Splatted so an omitted identity keeps the previous behaviour.
                    $deployId = @{}
                    if ($AdminAppId -and ($AdminSecret -or $AdminCertPem)) {
                        $deployId['AdminAppId'] = $AdminAppId
                        if ($AdminCertPem) { $deployId['AdminCertPem'] = $AdminCertPem } else { $deployId['AdminSecret'] = $AdminSecret }
                    }
                    & $setup @deployId -SubscriptionId $SubscriptionId -TenantId $TenantId -Location $Location `
                        -ResourceGroup $ResourceGroup -VnetName $VnetName -VnetResourceGroup $VnetResourceGroup `
                        -EnvName $EnvName -AcrName $AcrName -ImageRepo $ImageRepo -ImageTag (Get-EffectiveImageTag) `
                        -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase `
                        -WorkerMode $WorkerMode -ManagerMinReplicas $ManagerMinReplicas -TickCron $TickCron `
                        -TickJobName $TickJobName -MailSender $MailSender `
                        -EngineClientId $EngineClientId -EngineCertThumbprint $EngineCertThumbprint -EngineClientSecret $EngineClientSecret `
                        -SqlAdminClientId $SqlAdminClientId @sqlAdminCred @registryIdentity @reach | Out-Host
                    $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                    return @{ ok=$ok; ran=$true; detail='ACA infra ensured' }
                }
            } else {
                $setup = Join-Path $here 'Setup-PimVM.ps1'
                if (-not (Test-Path $setup)) { return @{ ok=$false; ran=$true; detail="setup not found: $setup" } }
                if ($PSCmdlet.ShouldProcess('local VM host', 'stand up / refresh VM scheduled-task host')) {
                    $global:LASTEXITCODE = 0
                    & $setup -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId | Out-Host
                    $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                    return @{ ok=$ok; ran=$true; detail='VM host ensured' }
                }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'mailsender' {
            # Onboarding step 7, now a DEPLOY step (operator 2026-08-13: nothing may be left
            # un-provisioned). Ensures the EXO precondition, the shared sender mailbox, the
            # SCOPED send right, and persists MailSender into pim.Settings so a cold-booted
            # scheduled job finds it -- the deploy-time -MailSender passthrough only reaches the
            # container's env, which is why an environment could look configured and still be mute.
            $init = Join-Path $here 'Initialize-PimMailSender.ps1'
            if (-not (Test-Path $init)) { return @{ ok=$false; ran=$true; detail="mail-sender setup not found: $init" } }
            if ($PSCmdlet.ShouldProcess($TenantId, 'ensure the notification sender mailbox + send right')) {
                $global:LASTEXITCODE = 0
                $mailArgs = @{ TenantId = $TenantId; SqlServerFqdn = $SqlServerFqdn; SqlDatabase = $SqlDatabase }
                if ($MailSender) { $mailArgs['MailSender'] = $MailSender }
                & $init @mailArgs | Out-Host
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                # 🪤 Not fatal to the deploy, and deliberately so: a tenant whose Exchange org is
                # still provisioning (the measured 'Substrate Only Agent' case) would otherwise
                # block infra that is otherwise fine. But it MUST be loud -- a silent mail-mute
                # environment is exactly the failure this step was added to end.
                if (-not $ok) { Warn 'MAIL SENDER NOT PROVISIONED -- this environment is MAIL-MUTE: TAPs will be minted and delivered nowhere. Re-run Initialize-PimMailSender.ps1 once Exchange is ready.' }
                return @{ ok=$true; ran=$true; detail=$(if ($ok) { 'sender mailbox + send right ensured' } else { 'DEGRADED: mail sender not provisioned (see warning) -- deploy continued' }) }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'features' {
            # Onboarding step 8 (IMP-07). A disabled gate makes the engine a no-op that logs
            # ok=True, so this is the difference between "deployed" and "running".
            $fb = Join-Path $here 'Set-PimFeatureBaseline.ps1'
            if (-not (Test-Path $fb)) { return @{ ok=$false; ran=$true; detail="feature baseline not found: $fb" } }
            if ($PSCmdlet.ShouldProcess($SqlDatabase, 'turn the shipped feature gates ON')) {
                $global:LASTEXITCODE = 0
                & $fb -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId | Out-Host
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                return @{ ok=$ok; ran=$true; detail='feature gates enabled + verified' }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'schema' {
            # delegate the idempotent schema upgrade to Invoke-PimUpdate (preflight->apply->re-preflight).
            $upd = Join-Path $here 'Invoke-PimUpdate.ps1'
            if (-not (Test-Path $upd)) { return @{ ok=$false; ran=$true; detail="updater not found: $upd" } }
            if ($PSCmdlet.ShouldProcess($SqlDatabase, 'apply idempotent SQL schema upgrade')) {
                $global:LASTEXITCODE = 0
                # -AcrName / -ImageRepo were MISSING here while the 'code' step below passes them.
                # Invoke-PimUpdate -Apply runs its whole detect->build->deploy chain, so it needs the
                # registry even when this step only wants the schema half; without it the step dies
                # with "supply -AcrName" AFTER the infra is already standing. Same missing-passthrough
                # class as the four in Setup-PimContainers, one layer deeper.
                # -Apps was ALSO missing here, and for the same reason: this step only wants the
                # schema half, but `Invoke-PimUpdate -Apply` runs its whole detect->build->deploy
                # chain, so it rolled with ITS OWN default -- the six-app always-on matrix. In cron
                # mode five of those apps do not exist, so the step died with "requested app(s) not
                # found: ca-pim-scheduler, ca-pim-engine, ..." AFTER building and pushing an image.
                # The cron override at the top of this script had already narrowed $Apps correctly;
                # it just never reached here. Measured on mfnpr 2026-08-10.
                # 🔴 BUG-50 -- WITHOUT A CONNECTION STRING THIS STEP APPLIES NOTHING AND SAID IT DID.
                # `Invoke-PimUpdate` degrades to "print the guarded DDL plan" when it has no
                # -SqlConnectionString: it WARNS, sets its own $schemaUpgraded=$false, and still
                # exits 0. This step then reported `ok=True ... 'schema upgrade applied'`, and the
                # deploy summary said the environment was fine.
                # MEASURED on mfnpr 2026-08-10: the store had **3 tables** and
                # RecalcSignature "rows=0|max=none" after repeated "successful" deploys. The
                # Manager and the tick both came up healthy against a database with no schema --
                # so nothing failed, it just could never do any work. At 25 tenants this is the
                # worst possible shape: every environment green, none of them functional.
                # A hosted deploy therefore REFUSES to claim a schema upgrade it cannot perform.
                if (-not "$SqlConnectionString".Trim()) {
                    if ($hosted) {
                        return @{ ok=$false; ran=$true; detail=(
                            "no -SqlConnectionString, so the SQL schema CANNOT be applied -- the updater would only " +
                            "PRINT the DDL while reporting success (BUG-50). Pass -SqlConnectionString for " +
                            "$SqlServerFqdn/$SqlDatabase, or apply sql/platform-schema.sql + sql/local-schema.sql " +
                            "with your SQL deploy identity. Refusing to report a schema upgrade that did not happen.") }
                    }
                    Write-Host "  schema: no -SqlConnectionString and not hosted -- DDL plan only." -ForegroundColor Yellow
                }
                & $upd -Source $Source @scenarioArgs -Apply -SqlConnectionString $SqlConnectionString `
                    -ResourceGroup $ResourceGroup -ManagerApp $ManagerApp -ImageTag (Get-EffectiveImageTag) `
                    -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps `
                    -SkipVerify -SkipNotify | Out-Host
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                return @{ ok=$ok; ran=$true; detail='schema upgrade applied (preflight->apply->re-preflight)' }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'code' {
            # build-from-pulled-code + roll the ACA revision via Invoke-PimUpdate (its lifecycle).
            $upd = Join-Path $here 'Invoke-PimUpdate.ps1'
            if (-not (Test-Path $upd)) { return @{ ok=$false; ran=$true; detail="updater not found: $upd" } }
            if ($PSCmdlet.ShouldProcess($ManagerApp, 'build + deploy Manager/scheduler/engine code')) {
                # BUG-25: clear the exit code FIRST so this step's verdict cannot inherit a
                # stale one from an earlier best-effort native probe (the same leak the
                # plan-only path already guards against above). The updater now also exits 0
                # explicitly on success, so this reads its real status either way.
                # `| Out-Host` is the ROOT-CAUSE fix -- see the block comment above.
                $global:LASTEXITCODE = 0
                # -TickJobName threaded through (BUG-48): the code step is what rebuilds the tag,
                # so the tick Job must be re-stamped from HERE, off the digest the roll resolves.
                # INFRA stamped it earlier in this same run, before this rebuild existed.
                & $upd -Source $Source @scenarioArgs -Apply -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo `
                    -ManagerApp $ManagerApp -Apps $Apps -ImageTag (Get-EffectiveImageTag) -TickJobName $TickJobName `
                    -SqlConnectionString $SqlConnectionString -SkipNotify | Out-Host
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                return @{ ok=$ok; ran=$true; detail='code built + deployed' }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'verify' {
            return (Invoke-DeployValidation)
        }
    }
    return @{ ok=$false; ran=$true; detail="unknown step '$Key'" }
}


# ---- VERIFY: hosted smoke + deploy-validation tests (the test-tenant validation) ----
$script:smokeExit = 0
$script:validationExit = 0
function Invoke-DeployValidation {
    $smokeExit = -1; $valExit = -1            # -1 = did not run (self-skip), not a fail
    $smoke = Join-Path $solRoot 'tests\live\Test-PimManagerHostedSmoke.ps1'
    if ($hosted -and (Test-Path $smoke)) {
        Info 'verify: hosted smoke (Test-PimManagerHostedSmoke.ps1)'
        if ($PSCmdlet.ShouldProcess($ManagerApp, 'run hosted smoke')) {
            $env:PIM_HOSTED_APP = $ManagerApp
            if ("$ResourceGroup".Trim()) { $env:PIM_HOSTED_RG = $ResourceGroup }
            # BUG-25: `| Out-Host` -- a native child's stdout is SUCCESS-stream output too, so
            # without it the smoke's console text becomes part of this function's return value.
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $smoke | Out-Host
            $smokeExit = $LASTEXITCODE
        }
    } else { Info 'verify: hosted smoke skipped (community/local or smoke not found)' }

    $val = Join-Path $solRoot 'tests\live\PIM.DeployValidation.Tests.ps1'
    if (Test-Path $val) {
        Info 'verify: deploy-validation tests (PIM.DeployValidation.Tests.ps1)'
        if ($PSCmdlet.ShouldProcess($SqlDatabase, 'run deploy-validation tests')) {
            $env:PIM_TenantId      = $TenantId
            $env:PIM_ClientId      = $EngineClientId
            $env:PIM_CertThumbprint= $EngineCertThumbprint
            $env:PIM_SqlDatabase   = $SqlDatabase
            $env:PIM_DEPLOY_MARKER = $DeployMarker
            try {
                if (Have 'Invoke-Pester') {
                    $r = Invoke-Pester -Path $val -PassThru -Output Minimal
                    $valExit = if ($r.FailedCount -gt 0) { 1 } else { 0 }
                } else {
                    & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Pester -Path '$val' -CI" | Out-Host
                    $valExit = $LASTEXITCODE
                }
            } catch { Warn "deploy-validation tests errored: $($_.Exception.Message)"; $valExit = 1 }
        }
    } else { Info 'verify: deploy-validation tests not found -- UNVERIFIED' }

    $script:smokeExit = $smokeExit
    $script:validationExit = $valExit
    $ok = (($smokeExit -le 0) -and ($valExit -le 0))   # <=0 means passed or self-skipped (not a fail)
    return @{ ok=$ok; ran=(($smokeExit -ge 0) -or ($valExit -ge 0)); detail="smoke=$smokeExit validation=$valExit" }
}

# =============================================================================
# EXECUTE -- walk plan.steps in order; run each 'do' step via the runner; capture
# the pre-deploy rollback target before CODE; verify-then-rollback at the end.
# =============================================================================
$runner = if ($StepRunner) { $StepRunner } else { { param($k,$ctx) Invoke-DefaultStepRunner -Key $k -Ctx $ctx } }
$ctx = @{ source=$Source; hosted=$hosted; tenantId=$TenantId; resourceGroup=$ResourceGroup; managerApp=$ManagerApp; imageTag=$ImageTag }

# capture pre-deploy rollback target (prior ACA revision) BEFORE any code change.
# Skipped under the -StepRunner test seam (would hit real az and probe a non-existent RG).
$prevRev = ''
if (-not $StepRunner -and $hosted -and -not $ValidateOnly -and (Have 'az') -and "$ResourceGroup".Trim()) {
    try { $prevRev = az containerapp revision list -g $ResourceGroup -n $ManagerApp --query "[?properties.active].name | [0]" -o tsv 2>$null } catch { Write-Verbose "active-revision read failed: $($_.Exception.Message)" }
    if (-not "$prevRev".Trim()) { try { $prevRev = az containerapp revision list -g $ResourceGroup -n $ManagerApp --query "[0].name" -o tsv 2>$null } catch { Write-Verbose "fallback-revision read failed: $($_.Exception.Message)" } }
    Info "pre-deploy revision (rollback target): $(if($prevRev){$prevRev}else{'(unknown)'})"
}

$outcomes = New-Object System.Collections.Generic.List[object]
$ranKeys  = New-Object System.Collections.Generic.List[string]
$verifyResult = $null
$halted = $false

foreach ($s in $plan.steps) {
    if (-not $s.do) {
        Step "$($s.key): $($s.action) -- $($s.reason)"
        $outcomes.Add([pscustomobject]@{ key=$s.key; ran=$false; ok=$true }) | Out-Null
        continue
    }
    Step "$($s.key): RUN -- $($s.name)"
    $res = & $runner $s.key $ctx
    if (-not $res) { $res = @{ ok=$false; ran=$true; detail='runner returned nothing' } }
    # A runner may return a hashtable, a PSCustomObject, or (defensively) a scalar.
    # Read 'ok'/'ran'/'detail' WITHOUT assuming ContainsKey (PSCustomObject/String lack it).
    #
    # BUG-25 defence in depth: a runner that LEAKS success-stream output hands us an
    # Object[] of {leaked..., result}. Reading '.ok' off the array yields $null, and
    # [bool]$null is $false -- i.e. a healthy step reads as FAILED and drives a rollback
    # of a good deploy. The leak itself is fixed at source (`| Out-Host` in every runner),
    # but this must never be the failure mode again, so unwrap arrays here too: take the
    # LAST element that actually carries an 'ok'. Silence is not a verdict -- if nothing in
    # the return value looks like a result, say exactly that instead of implying the step
    # failed on its own merits.
    $unreadable = $false
    if ($res -isnot [System.Collections.IDictionary] -and -not $res.PSObject.Properties['ok']) {
        $cand = @($res) | Where-Object {
            $_ -and ( ($_ -is [System.Collections.IDictionary] -and $_.Contains('ok')) -or $_.PSObject.Properties['ok'] )
        } | Select-Object -Last 1
        if ($cand) {
            Info "  (runner emitted extra output; read the result object out of $(@($res).Count) emitted items)"
            $res = $cand
        } else {
            $unreadable = $true
        }
    }
    $okRaw = $null; $ranRaw = $null; $detail = ''
    if ($unreadable) {
        # Deliberate: an UNKNOWN outcome is treated as a failure (halt, and roll back if the
        # code step ran). It is not evidence the work failed -- but "we could not tell" must
        # never be reported as success, and reverting to the last known-good revision is the
        # safe direction when the outcome is unknown. Say plainly which of the two it is, so
        # nobody debugs the deploy when the harness is what broke.
        $detail = "RUNNER RESULT UNREADABLE -- no {ok;ran;detail} found in $(@($res).Count) emitted item(s). This is a HARNESS fault, not proof the step's work failed -- but an unknown outcome is treated as a failure (halt + rollback) rather than assumed good. Check the step's own output above to see what actually happened."
    }
    elseif ($res -is [System.Collections.IDictionary]) {
        if ($res.Contains('ok'))     { $okRaw  = $res['ok'] }
        if ($res.Contains('ran'))    { $ranRaw = $res['ran'] }
        if ($res.Contains('detail')) { $detail = $res['detail'] }
    } else {
        if ($res.PSObject.Properties['ok'])     { $okRaw  = $res.ok }
        if ($res.PSObject.Properties['ran'])    { $ranRaw = $res.ran }
        if ($res.PSObject.Properties['detail']) { $detail = $res.detail }
    }
    $ok  = [bool]$okRaw
    $ran = if ($null -ne $ranRaw) { [bool]$ranRaw } else { $true }
    Info "  -> ok=$ok ran=$ran $detail"
    $outcomes.Add([pscustomobject]@{ key=$s.key; ran=$ran; ok=$ok }) | Out-Null
    if ($ran) { $ranKeys.Add($s.key) | Out-Null }
    if ($s.key -eq 'verify') { $verifyResult = $res }

    # a failed step (other than verify -- verify failure drives rollback below) HALTS the run.
    if (-not $ok -and $s.key -ne 'verify') {
        Warn "step '$($s.key)' FAILED -- halting the deploy."
        $halted = $true
        break
    }
}

# =============================================================================
# VERIFY VERDICT + VERIFY-THEN-ROLLBACK on failure.
# =============================================================================
$codeRan = ($ranKeys -contains 'code')
$verdict = $null
if ($verifyResult -or $halted) {
    $verdict = Get-PimDeployVerifyVerdict -SmokeExitCode $script:smokeExit -ValidationExitCode $script:validationExit `
                -PreviousRevision $prevRev -CodeStepRan $codeRan
}

$rolledBack = $false
$needRollback = $halted -or ($verdict -and -not $verdict.Healthy)
if ($needRollback -and $codeRan) {
    $rbPlan = Get-PimDeployRollbackPlan -RanStepKeys @($ranKeys.ToArray()) -PreviousRevision $prevRev -Hosted $hosted
    foreach ($a in $rbPlan.actions) {
        Warn "ROLLBACK: $($a.key) -> $($a.action) ($($a.detail))"
        if ($a.action -eq 'rollback-revision' -and $hosted) {
            # BUG-25: a rollback that cannot run is not a safety net, and one that only LOOKS
            # like it ran is worse. Guard the inputs, read the real outcome, and never claim
            # rolledBack=True on faith.
            $roller = Join-Path $here 'Update-PimContainers.ps1'
            if (-not (Test-Path $roller)) {
                Warn "AUTO-ROLLBACK COULD NOT RUN: roller not found ($roller). ROLL BACK BY HAND."
            } elseif (-not "$prevRev".Trim()) {
                Warn "AUTO-ROLLBACK COULD NOT RUN: the pre-deploy revision was never captured, so there is no target to reactivate. ROLL BACK BY HAND: az containerapp revision list -n $ManagerApp -g $ResourceGroup"
            } else {
                try {
                    if ($PSCmdlet.ShouldProcess($ManagerApp, "rollback to $($a.detail)")) {
                        $global:LASTEXITCODE = 0
                        & $roller -Rollback ("$prevRev".Trim()) -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps -SkipSmoke | Out-Host
                        if ((-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)) {
                            $rolledBack = $true
                        } else {
                            Warn "AUTO-ROLLBACK FAILED (exit $LASTEXITCODE) -- the fleet is NOT on the prior revision. ROLL BACK BY HAND: $roller -Rollback $prevRev -ResourceGroup $ResourceGroup -AcrName $AcrName"
                        }
                    }
                } catch {
                    Warn "AUTO-ROLLBACK FAILED: $($_.Exception.Message)"
                    Warn "  the fleet is NOT on the prior revision. ROLL BACK BY HAND: $roller -Rollback $prevRev -ResourceGroup $ResourceGroup -AcrName $AcrName"
                }
            }
        }
    }
}

# =============================================================================
# SUMMARY.
# =============================================================================
$summary = Get-PimDeploySummary -StepOutcomes @($outcomes.ToArray()) -Verdict $verdict -RolledBack $rolledBack
Write-Host ""
Step "DONE. status=$($summary.status) healthy=$($summary.healthy) rolledBack=$($summary.rolledBack)"
foreach ($o in $summary.steps) { Info ("  {0,-8} ran={1} ok={2}" -f $o.key, $o.ran, $o.ok) }
if ($summary.failedSteps.Count) { Warn "failed steps: $($summary.failedSteps -join ', ')" }

$summary
if ($summary.status -eq 'failed' -or $summary.status -eq 'rolledback') { exit 1 }
