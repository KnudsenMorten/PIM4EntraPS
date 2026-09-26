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
    [ValidateSet('S1','S2','S3','S5','S6')][string]$Scenario,
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
    # (§33.28, 2.4.373: Setup-PimContainers now defaults to 'cron' as well; its ManagerMinReplicas default is still 1.)
    # Setup-PimContainers defaulted to WorkerMode 'always-on' + ManagerMinReplicas 1: six apps at
    # ~3 vCPU / 6 GiB running 24/7, materially more per environment per month (never measured; do not quote a figure). This orchestrator could
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
    [string[]]$Apps         = # empty = DISCOVER (Update-PimContainers.ps1 enumerates the resource group).
    # The hard-coded six-app list was wrong for every real topology -- only ca-pim-manager
    # exists -- and it was copy-pasted into FOUR entry points, so fixing one changed nothing.
    @(),
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
    # §64.7b -- support access to a customer store is DECLARED at deploy. Setup-PimContainers gained
    # these two, but this front door never exposed them, so a deploy through it could not declare it.
    [string]$SupportDbAppId    = "$($env:PIM_SUPPORT_DB_APPID)",
    [string]$SupportDbUserName = $(if ("$($env:PIM_SUPPORT_DB_USER)".Trim()) { "$($env:PIM_SUPPORT_DB_USER)".Trim() } else { 'PIM4EntraPS-Deploy' }),
    # 🔴 §34.2c -- THE DEPLOY IDENTITY FOR THE `az` DATA PLANE. Setup-PimContainers has always had
    # its own -AdminAppId/-AdminSecret sign-in (into an ISOLATED AZURE_CONFIG_DIR); this
    # orchestrator never passed them, so INFRA alone ran on whatever `az` context happened to be
    # active while every other step signs itself in. That is the BUG-23 class: a credential path
    # that succeeds while being wrong.
    # 🪤 MEASURED 2026-08-13 on the first real greenfield run: the ambient context was
    # **a DIFFERENT COMPANY's tenant** (it is regularly the default on this machine), and
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
    # §38.1a -- the network shape, for a customer who has their own IP plan and cannot be given a
    # /21 we picked for them. All optional: unset means the token/index-derived value, so the
    # estate and every existing environment are unchanged. The NAMES (-ResourceGroup, -AcrName,
    # -VnetName, -LogAnalyticsWorkspaceName, -SqlServerFqdn) are already parameters of this
    # orchestrator and are now forwarded to prereq instead of being re-derived there (§38.1b).
    [string]$PrereqSubnetName,
    [string]$PrereqVnetAddressPrefix,
    [string]$PrereqSubnetAddressPrefix,
    # The AcrPull identity the prereq step creates and INFRA consumes. Derived from the token by
    # the script; named here so the fact-probe can test the ROLE (BUG-42/46) rather than guess.
    [string]$PrereqIdentityName,
    # S5 managed tenants use the MASTER's store and must NOT get one of their own -- creating it
    # here would quietly turn S5 into S6 (the prereq script's own words).
    [switch]$PrereqSkipSql,
    # 'Proxy' for a firewalled environment: Azure SQL's default from inside Azure is 'Redirect',
    # which reconnects on 11000-11999 after the gateway handshake -- so a firewall allowing only
    # 1433 yields a connection that authenticates and then hangs. See New-PimHostingPrerequisites.
    [ValidateSet('Default','Proxy','Redirect')][string]$SqlConnectionPolicy = 'Default',
    # 🔑 DEFAULTS FROM -Exposure WHEN NOT GIVEN (operator rule, 2026-09-11): PREMIUM for internal,
    # BASIC for external. Basic and Standard registries have NO network controls at all -- no private
    # endpoint, no firewall rules -- so "registry with public access disabled" is a Premium-only
    # state. An INTERNAL deployment whose registry is Basic is publicly reachable in the one place
    # the whole design says it should not be, and the only way to deploy it into a tenant that
    # forbids that is a STANDING exemption. External has no such contradiction, and Basic is roughly
    # a tenth of the cost. Pass -AcrSku explicitly to override; the resolved value is printed.
    # 🪤 -AcrPublicAccess false means `az acr build` cannot run from outside the VNet.
    [ValidateSet('Basic','Standard','Premium')][string]$AcrSku,
    [ValidateSet('Default','true','false')][string]$AcrPublicAccess = 'Default',
    # A private endpoint cannot live in the ACA subnet (it is delegated to Microsoft.App), so an
    # internal-only design needs a second subnet. Required when -AcrPublicAccess false and the
    # subnet does not already exist -- never derived, because it is a range inside the customer's
    # own VNet. And the agent pool is what lets `az acr build` reach a private registry at all.
    [string]$PrivateEndpointSubnetName = 'pim-endpoints',
    [string]$PrivateEndpointSubnetAddressPrefix,
    [string]$AcrAgentPoolName,
    # SQL is PaaS: with no public endpoint it is reachable from NOWHERE until this exists. Defaults
    # ON for -Exposure internal, because an internal design with an unreachable database is not a
    # configuration anyone wants -- see the resolution below.
    [switch]$SqlPrivateEndpoint,
    # 🔴 THE POST-DEPLOY GUI SMOKE GATE, OPTED OUT OF. Read this before using it.
    # The gate opens the hosted Manager and asserts it actually WORKS (SQL render mode, tenant
    # cache, read-write, the right version). It is a release gate precisely because a Manager can
    # be "deployed" and inert, so a skip is NEVER a pass and this flag does not make one.
    # 🔑 THE ONE LEGITIMATE USE, and the reason this exists: an --internal-only environment has no
    # route or DNS from a deploy host outside its VNet, so the gate cannot run AT ALL --
    #     the Container Apps environment is VNet-INTERNAL and '<app>.<env>.azurecontainerapps.io'
    #     does not resolve from this host
    # That is not a broken Manager, and it is not something the gate can be given inputs to fix. A
    # gate that structurally cannot run must be opted out of deliberately and LOUDLY, rather than
    # left to fail every deploy until someone starts ignoring it -- which is how a real red gets
    # missed (measured today: an already-red gate could not report a new defect it would have
    # caught). Verify such an environment from inside the VNet, or in a browser from a peered
    # client, and say so in the deployment record.
    [switch]$SkipHostedSmoke,
    # 🔑 ONE GATE LIST, BOTH PATHS. A disabled gate makes the engine a no-op that logs ok=True, so
    # this is the difference between "deployed" and "running" -- and there are now two places that
    # apply it: Set-PimFeatureBaseline from the deploy host (public SQL) and the in-cloud bootstrap
    # job (private SQL, where this host has no route). Letting each default independently is how the
    # two topologies quietly end up with different features on. Defaults match
    # Set-PimFeatureBaseline's own so nothing changes for an existing environment.
    [string[]]$FeatureGates        = @('scheduler.jobs','alerting.email','msp.downlink'),
    [string[]]$FeatureGatesDisable = @(),
    # A genuine VM install (no ACA). Only needed to override the "-Scenario means Container Apps"
    # rule above -- every S1..S6 scenario in the estate is a Container Apps deployment.
    [switch]$NotHosted,
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
    # §38.2a -- forwarded to Setup-PimContainers. A ValidateSet STRING, not [bool]: the onboarding
    # driver invokes this script with `pwsh -File`, which stringifies every argument, so a [bool]
    # parameter cannot bind across that boundary at all ("Cannot convert value System.String to
    # type System.Boolean"). Default 'internal' = today's behaviour for every environment sync
    # reaches. IMMUTABLE once the environment exists -- see Setup-PimContainers' env-create note.
    # §38.2b -- default external (operator, 2026-09-10). An internal-only environment cannot be
    # reached to TEST it, and cannot be opened afterwards: the setting is immutable. Built
    # external, the Manager can still be locked down with one reversible `ingress update`.
    [ValidateSet('internal','external')][string]$Exposure = 'external',
    # 71.40 -- forwarded to Setup-PimContainers for the MANAGER: the master signing key id(s) it pins and the plain URL
    # the master publishes the signed bundle to (its Downlink view verifies against them). Validated there.
    [string[]]$BaselineTrustedKeys = @(),
    [string]$BaselineDocUrl,
    [string]$HubVnetName,
    [string]$HubVnetResourceGroup,
    [string]$HubVnetSubscriptionId,
    [string]$PrivateDnsResourceGroup,
    [switch]$SkipPrivateDns,
    # Create everything reachability needs EXCEPT the peering itself, which the customer makes with
    # their own naming standard. The hub is still named, so the private DNS zone is created and
    # linked -- omitting the hub entirely would lose that too. See Setup-PimContainers -SkipPeering.
    [switch]$SkipPeering,
    # §52.1. Forwarded to INFRA, which grants this environment network access to the SQL server
    # (subnet service endpoint + VNet rule, Azure-services firewall rule verified). Skip ONLY for
    # a private-endpoint store: without one of those paths the Manager starts, is refused by SQL,
    # and dies before it can serve -- which is exactly how the first go-live ended.
    [switch]$SkipSqlNetworkAccess,
    # The store can live in ANOTHER SUBSCRIPTION (operator, 2026-09-09) -- a central/shared SQL
    # server is a supported topology. The step searches every subscription the deploy identity can
    # read, so this is only needed when the server's subscription is not in that list.
    [string]$SqlSubscriptionId,
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
    # 🔴 §57 -- WHO CAN ADMINISTER THIS ENVIRONMENT ONCE IT EXISTS.
    # A hosted Manager FAILS CLOSED: an identity in neither SQL (pim.Settings ManagerAccess) nor
    # the env vars is a Reader. Nothing in the deploy ever wrote a SuperAdmin, so a freshly-built
    # environment had nobody who could save a change -- measured at a live customer as "now noone
    # can make changes to whole platform". Comma-separated UPNs; each becomes a SuperAdmin.
    # 🔒 Written to SQL, so it survives a CSV import: the import writes pim.Rows, and its only
    # touch on Settings adds keys that are not already there.
    [string]$ManagerSuperAdmins = "$($env:PIM_MANAGER_SUPERADMINS)",
    [string]$EngineClientId,
    [string]$EngineCertThumbprint,
    [string]$EngineClientSecret,
    # ---- what the post-deploy GUI gate needs in order to actually SEE anything -------------
    # Not infrastructure values (DEPLOY-2 §4): these are inputs to the VERIFICATION, and without
    # them the gate self-skips its two most important layers and still exits 0. Defaulted from the
    # same env vars the smoke itself reads, so an operator who exports them once gets a gate that
    # can see, whichever entry point they run.
    [string]$LogAnalyticsWorkspaceId = "$($env:PIM_HOSTED_LA_WORKSPACE)",   # boot-log evidence: render mode SQL vs static
    [string]$EasyAuthAudience        = "$($env:PIM_HOSTED_EASYAUTH_AUD)",   # live HTTP against the served page
    # Front Easy Auth with an app registration you already control. Empty = the deploy creates one
    # (a PRODUCT-named registration in the customer's own tenant), which is the normal case.
    [string]$EasyAuthClientId,
    # §48.1 -- WHO may sign in. Easy Auth alone only proves the caller holds an account in this
    # tenant; on a console that mints TAPs and grants tier-0 roles that is not the question. Given
    # UPNs/groups, the deploy switches the enterprise application to assignment-required and
    # assigns them. Empty leaves it open to the whole tenant, and says so as a warning.
    [string[]]$EasyAuthAllowedPrincipals = @(),
    # 🔴 SEC-44 -- the other explicit answer: every MEMBER account in the tenant, never a guest (a dynamic
    # members-only group, assigned with assignment required -- see Set-PimManagerEasyAuth). A NEW
    # environment with neither this nor -EasyAuthAllowedPrincipals is REFUSED before anything is created.
    [switch]$EasyAuthAllowAllTenantUsers,
    # 🔴 IMP-49 t -- THE SETUP-HOST FIREWALL WINDOW. Host-side SQL steps (schema, grants, feature
    # gates, access) connect from THIS host, so the store must admit its public IP while they run
    # ('AllowSetupHost'). That rule used to be created by prereq and left STANDING forever. Now this run
    # removes the rule at its end when THIS run created it (or opened it); a rule that was already there
    # when the run started belongs to someone else's window and is left alone.
    # -KeepSetupHostRule: for an orchestrator that owns the window itself and closes it later
    # (the MSP build's sqlopen/sqlclose). -SetupHostIp: this host's public IP, so no external lookup
    # is made at all; without it the IP is read from https://api.ipify.org (a third-party service).
    [switch]$KeepSetupHostRule,
    [string]$SetupHostIp,
    # §53 -- the nightly updater installed by the `updater` step.
    [string]$UpdateJobName  = 'ca-pim-update',
    [string]$UpdateCron     = '0 3 * * *',   # UTC; stagger across an estate so 100 do not roll at once
    # §55 -- WHERE THIS ENVIRONMENT FETCHES SOURCE, so it can build its own images and never need a
    # build host. A template with {version} in it; the approved version is substituted at run time.
    # Produced by tools/setup/Publish-PimSourceArchive.ps1. Without it a fresh install gets an
    # updater that can only ROLL, which means that customer needs someone else to build for it
    # forever -- so pass it on every real deployment. Falls back to $env:PIM_UPDATE_SOURCE_URL so an
    # estate can set it once for the whole run rather than on every command line.
    [string]$UpdateSourceUrlTemplate = "$($env:PIM_UPDATE_SOURCE_URL)",
    # 2026-09-13 -- THE UPDATE RING the environment's updater follows (channel.json beside the source
    # archives). DEFAULT 2 = the safe customer ring: nothing reaches it without the operator's approval.
    # Internal and test environments pass -UpdateRing 1. Not passing it on a REDEPLOY keeps the ring
    # the updater already has (never a silent promote/demote). A ring REQUIRES a source: without
    # -UpdateSourceUrlTemplate / $env:PIM_UPDATE_SOURCE_URL (or one already on the job) the updater
    # step REFUSES instead of installing an updater that would ignore its ring.
    [ValidateRange(0,3)][int]$UpdateRing = 2,
    # The HOST-SIDE ring gate (Update-PimContainers / Setup-PimContainers) refuses to roll an
    # environment to a version its ring does not approve. This is the only way past it, and it is
    # printed and audited. -Reason is mandatory with it.
    [switch]$OverrideRingGate,
    [string]$Reason,
    [switch]$SkipUpdater,                    # leaves the environment with NO unattended update path
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

    # 71.18 (Friday build audit, 2026-09-15): the private-store bootstrap job's name. It was USED (infra probe, the
    # updater hand-off and the access step) but never DECLARED, so it was always empty: on private SQL the access step
    # asked `az containerapp job show -n ''` and reported a failure for a job that existed. Same default as
    # Setup-PimContainers.ps1, which creates it.
    [string]$DbInitJobName = 'ca-pim-dbinit',

    # 71.18: forwarded to the prerequisites' SQL admin group step (they were not, so the group never got the
    # troubleshooting identity and a non-default group name was ignored).
    [string]$SqlAdminGroupName = 'grp-pim-sql-admins',
    [string]$TroubleshootingAppId,

    # 71.33 -- DEPLOY AS THE SIGNED-IN az USER (a customer administrator), not as a deploy application. No deploy
    # identity is created, no PEM exists, no SQL admin application is used: every sub-step runs as the signed-in user,
    # who is made a member of the SQL admin group before any SQL is touched. Refused together with any -Admin*/-SqlAdmin*
    # credential (one identity per deploy). The user must be a USER in -TenantId for -SubscriptionId (asserted).
    [switch]$UseSignedInAccount,

    # --- TEST seam: inject the per-step runner so the whole flow is offline-testable ---
    [scriptblock]$StepRunner
)
$ErrorActionPreference = 'Stop'

# =================================================================================================
# BUG-162 (rehearsal master dp998, 2026-09-17) -- $PSBoundParameters IS PER FUNCTION, NOT PER SCRIPT,
# AND THE UPDATE RING WAS DECIDED INSIDE A FUNCTION.
#
# The 'updater' step lives in Invoke-DefaultStepRunner, a function with param($Key,$Ctx). Its test
#     if ($PSBoundParameters.ContainsKey('UpdateRing')) { $upArgs['UpdateRing'] = $UpdateRing }
# therefore asked whether -UpdateRing was passed TO THAT FUNCTION -- which it never is, because the
# function takes Key and Ctx. The answer was ALWAYS false. $UpdateRing itself resolved fine (a script
# variable is visible in the function), so the value was right there and simply never forwarded:
# Deploy-PimUpdateJob ran with its own default and the environment came up on ring 2.
#
# MEASURED: dp998-master.json carries "updater": { "ring": 1 }, PIM-MspBuild forwarded UpdateRing = 1,
# and the deployed ca-pim-update carried PIM_UPDATE_RING=2. That ring then approved 2.4.324 against an
# environment built at 2.4.366, and the nightly updater rolled all five containers 42 versions
# BACKWARD -- which removed publish-job-entry.ps1 and stopped the master publishing.
#
# So the question is answered ONCE, HERE, at script scope, where $PSBoundParameters means what the
# caller passed. Every later use reads this variable. A ring that was not passed keeps whatever ring
# the updater already carries, and a NEW updater gets the documented default (-UpdateRing's own
# default, stated on screen by Deploy-PimUpdateJob -- never silently).
$script:PimDeployRingExplicit = $PSBoundParameters.ContainsKey('UpdateRing')
# The deploy profile (Update-PimCommunity.ps1) is taken from the same script-scope $PSBoundParameters, for the same reason.
$script:PimDeployBound = @{} + $PSBoundParameters

# An array cannot cross `pwsh -File` (the S1 driver and the MSP build call this script that way), so
# callers pass one comma-separated string -- which binds as ONE element. Split it here, once.
$EasyAuthAllowedPrincipals = @(@($EasyAuthAllowedPrincipals) | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

# =================================================================================================
# 🔴 DO NOT LEAVE THE OPERATOR'S az SESSION POINTING AT A SERVICE PRINCIPAL.
#
# The step scripts are invoked with `&`, which runs them IN THIS PROCESS -- and this script is
# normally run straight from the operator's own shell. Setup-PimContainers and
# Build-PimManagerImage each set $env:AZURE_CONFIG_DIR to an isolated per-registry profile and sign
# in there as the deploy SPN. That isolation is right, but nothing ever put the variable back, so
# the setting LEAKED into the caller's shell and survived the run.
#
# MEASURED at a customer 2026-09-11, as two symptoms that did not look related: after a failed run
# the operator had to sign in again (their shell was now reading the SPN's profile directory), and
# a later run then failed with "Insufficient privileges to complete the operation" because that SPN
# holds Owner on the SUBSCRIPTION and nothing in Graph. Both were this one leak.
#
# Captured here and restored on EVERY exit -- success, throw, or Ctrl-C.
$script:PimCallerAzureConfigDir    = $env:AZURE_CONFIG_DIR
$script:PimCallerAzureConfigDirSet = [bool]$env:AZURE_CONFIG_DIR
function Restore-PimCallerAzContext {
    if ($script:PimCallerAzureConfigDirSet) { $env:AZURE_CONFIG_DIR = $script:PimCallerAzureConfigDir }
    elseif (Test-Path Env:\AZURE_CONFIG_DIR) { Remove-Item Env:\AZURE_CONFIG_DIR -ErrorAction SilentlyContinue }
}

# 🔴 THE PEM IS A PRIVATE KEY, AND IT ONLY EXISTS BECAUSE `az` CANNOT READ A WINDOWS CERT STORE.
# The certificate itself lives in LocalMachine\My with its key non-exportable-by-policy-or-not; az
# login --service-principal --certificate insists on a FILE. (PowerShell's Connect-AzAccount
# -CertificateThumbprint reads the store directly and needs no file -- the toolchain here is az, so
# the export is unavoidable DURING a run.)
# It is not unavoidable BETWEEN runs. A key that is re-derivable from the store in a second has no
# business persisting on a shared host, so one this script materialised is shredded on the way out.
# A -AdminCertPem the CALLER supplied is never touched: that is their file, not ours.
$script:PimEphemeralPem = $null
function Clear-PimEphemeralPem {
    if (-not $script:PimEphemeralPem) { return }
    if (Test-Path -LiteralPath $script:PimEphemeralPem) {
        try {
            # Overwrite before unlinking. Deleting a file leaves the bytes on disk until reused, and
            # these bytes are a subscription-Owner key.
            $len = (Get-Item -LiteralPath $script:PimEphemeralPem).Length
            if ($len -gt 0) {
                $junk = [byte[]]::new($len)
                [System.Security.Cryptography.RandomNumberGenerator]::Fill($junk)
                [System.IO.File]::WriteAllBytes($script:PimEphemeralPem, $junk)
            }
        } catch { }
        Remove-Item -LiteralPath $script:PimEphemeralPem -Force -ErrorAction SilentlyContinue
    }
    $script:PimEphemeralPem = $null
}
# Covers the paths a try/finally around the body would miss: a throw from a nested step, and the
# operator interrupting the run.
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -SupportEvent -Action { Restore-PimCallerAzContext; Clear-PimEphemeralPem }
# 🪤 A BARE `throw` INSIDE A TRAP DISCARDS THE ERROR AND RAISES "ScriptHalted", so the one line
# that says what actually went wrong is replaced by a word that says nothing. Measured at a customer
# 2026-09-11: an infra failure surfaced only as "ScriptHalted" at this line. Rethrow $_.
trap {
    Restore-PimCallerAzContext
    # IMP-49 t: a run that dies still closes the setup-host window it opened (best effort, never masking $_).
    if (Get-Command Close-PimSetupHostWindow -ErrorAction SilentlyContinue) { try { Close-PimSetupHostWindow } catch { } }
    Clear-PimEphemeralPem
    throw $_
}
$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
# Guarded `az` shadow -- see _PimAz.ps1. az writes ordinary WARNINGS to stderr and PowerShell 5.1
# makes any such write terminating under $ErrorActionPreference='Stop'. Must precede the first az call.
. "$here\_PimAz.ps1"
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

# ---- the registry SKU follows the EXPOSURE unless the caller said otherwise -------------------
# Stated rather than silent: this is a cost difference (~10x) and a security posture, so a deploy
# must never acquire either one without saying so on screen.
# 🔴 INFRA WAS HANDED AN EMPTY -VnetName AND DIED ON IT, AFTER PREREQ HAD JUST CREATED THE VNET.
# PREREQ derives every name from -PrereqToken (rg-automateit-<tok>, acrpim<tok>, vnet-pim-<tok>) and
# the orchestrator forwards the EFFECTIVE names to it -- but it never derived the VNet for ITSELF,
# so INFRA received "" and Setup-PimContainers refused with "Cannot bind argument to parameter
# 'VnetName' because it is an empty string". Measured at a customer 2026-09-11: prereq reported
# "vnet-pim-pk417 / pim-manager -> 10.200.13.0/26 delegated", the image built, and the next step
# could not name the network that had just been made for it.
# This is the missing-passthrough class again: the value EXISTS and simply was not carried. Derive
# it from the same token prereq used, so the two halves cannot disagree; an explicit -VnetName
# still wins.
if (-not "$VnetName".Trim() -and "$PrereqToken".Trim()) {
    $VnetName = "vnet-pim-$PrereqToken"
    Write-Host "    vnet: $VnetName (derived from -PrereqToken -- the same name prereq creates)" -ForegroundColor DarkGray
}
if (-not "$VnetResourceGroup".Trim() -and "$ResourceGroup".Trim()) {
    # The spoke lives in the environment's own resource group unless told otherwise.
    $VnetResourceGroup = $ResourceGroup
}

# An internal environment whose database has no private endpoint has a database it cannot reach --
# and neither can anything else, since disabling the public endpoint does not create a private one.
# Stated, never silent: this creates a resource and a DNS zone.
if (-not $PSBoundParameters.ContainsKey('SqlPrivateEndpoint') -and $Exposure -eq 'internal' -and "$SqlServerFqdn".Trim()) {
    $SqlPrivateEndpoint = $true
    Write-Host '    sql: private endpoint ON (from -Exposure internal; SQL is PaaS, so disabling its public endpoint makes it reachable from nowhere without one). Override with -SqlPrivateEndpoint:$false.' -ForegroundColor DarkGray
}

if (-not $PSBoundParameters.ContainsKey('AcrSku') -or -not "$AcrSku".Trim()) {
    $AcrSku = $(if ($Exposure -eq 'internal') { 'Premium' } else { 'Basic' })
    Write-Host ("    registry SKU: $AcrSku (from -Exposure $Exposure" +
                $(if ($Exposure -eq 'internal') { '; Basic has no private endpoint or firewall rules' } else { '' }) +
                '). Override with -AcrSku.') -ForegroundColor DarkGray
}

# default-safe: a bare run is plan-only (-WhatIf). -Apply opens the gate.
$applyGate = [bool]$Apply
if ($ValidateOnly) { $applyGate = $true }   # validate-only still "runs" its single step

# =================================================================================================
# 0. THE DEPLOY IDENTITY -- created here when it was not supplied.
#
# 🔴 This step exists because its absence was the ONLY genuinely manual prerequisite left in a
# one-shot deploy. The prereq step refuses without -AdminAppId plus a credential, and nothing in
# the toolchain could make one -- so a first deploy into a new customer tenant stopped dead on a
# portal task, performed by hand, in front of the customer.
#
# Supplying -AdminAppId keeps the old behaviour exactly: an operator who has already provisioned a
# deploy identity out of band is never second-guessed. It is only the ABSENCE that now bootstraps.
# The helper is idempotent, so a re-run reuses the registration and the certificate rather than
# stacking duplicates.
# =================================================================================================
$script:PimSignedInOid = ''
$script:PimSignedInSqlChecked = $false
if ($UseSignedInAccount) {
    # 71.33 -- one identity per deploy: a signed-in deploy never also carries an application credential.
    $mixed = @('AdminAppId', 'AdminSecret', 'AdminCertPem', 'SqlAdminClientId', 'SqlAdminClientSecret', 'SqlAdminCertThumbprint') | Where-Object { "$((Get-Variable -Name $_ -ValueOnly))".Trim() }
    if (@($mixed).Count) { throw "Invoke-PimDeployAll: -UseSignedInAccount cannot be combined with -$(@($mixed) -join ', -') -- pick ONE deploy identity." }
    if (-not "$TenantId".Trim() -or -not "$SubscriptionId".Trim()) { throw 'Invoke-PimDeployAll: -UseSignedInAccount needs -TenantId and -SubscriptionId (asserted against the signed-in az account).' }
    . "$here\_PimSignedIn.ps1"
    if (-not $StepRunner) {
        $who = Get-PimSignedInIdentity -TenantId $TenantId -SubscriptionId $SubscriptionId
        if (-not $who.ok) { throw "Invoke-PimDeployAll: REFUSED (nothing was touched) -- $($who.reason)" }
        $script:PimSignedInOid = $who.objectId
        Set-PimSignedInGlobals -TenantId $TenantId
        Write-Host "    deploy identity: the SIGNED-IN user $($who.userName) ($($who.objectId)) -- no deploy application, no certificate" -ForegroundColor DarkGray
    }
}
function Confirm-PimSignedInSqlAccess {
    # 71.33 -- before the FIRST step that connects to SQL as the signed-in user: make that user a member of the SQL admin
    # group (members-only). Returns '' when fine, else the reason the step must fail. Once per run.
    if (-not $UseSignedInAccount -or $StepRunner -or $script:PimSignedInSqlChecked) { return '' }
    if (-not "$SqlServerFqdn".Trim() -or $SqlPrivateEndpoint) { return '' }
    $script:PimSignedInSqlChecked = $true
    try {
        $m = Invoke-PimSignedInSqlAdminMembership -SubscriptionId $(if ("$SqlSubscriptionId".Trim()) { $SqlSubscriptionId } else { $SubscriptionId }) -TenantId $TenantId `
                -ResourceGroup $ResourceGroup -SqlServerName $SqlServerFqdn -UserObjectId $script:PimSignedInOid -GroupName $SqlAdminGroupName
        if (-not $m.ok -or $m.blocked) { $script:PimSignedInSqlChecked = $false; return "the signed-in user cannot reach SQL: $($m.reason)" }
        return ''
    } catch { $script:PimSignedInSqlChecked = $false; return "the signed-in user's SQL admin group membership could not be ensured: $($_.Exception.Message)" }
}

if (-not "$AdminAppId".Trim() -and -not $ValidateOnly -and -not $StepRunner -and -not $UseSignedInAccount) {
    Step '0. deploy identity'
    if (-not "$TenantId".Trim() -or -not "$SubscriptionId".Trim()) {
        throw 'no -AdminAppId, and -TenantId/-SubscriptionId are missing -- cannot create a deploy identity either.'
    }
    $mk = Join-Path $here 'New-PimDeployIdentity.ps1'
    if (-not (Test-Path -LiteralPath $mk)) { throw "no -AdminAppId supplied and $mk is missing." }
    Info 'no -AdminAppId supplied -- ensuring one exists (idempotent; reused if already present).'
    Info 'this uses YOUR CURRENT az sign-in, which must be able to create an app registration and assign a role.'
    # When the hub is named, the identity also needs peer rights ON the hub VNet -- Owner on the
    # PIM subscription covers the spoke side only, and a cross-subscription hub is the common case.
    $mkArgs = @{ TenantId = $TenantId; SubscriptionId = $SubscriptionId; Apply = $applyGate }
    if ("$HubVnetName".Trim() -and "$HubVnetResourceGroup".Trim()) {
        $hubSub = $(if ("$HubVnetSubscriptionId".Trim()) { $HubVnetSubscriptionId } else { $SubscriptionId })
        $mkArgs['PeerVnetResourceId'] = "/subscriptions/$hubSub/resourceGroups/$HubVnetResourceGroup/providers/Microsoft.Network/virtualNetworks/$HubVnetName"
    }
    $ident = & $mk @mkArgs
    if ($applyGate) {
        if (-not $ident -or -not "$($ident.AppId)".Trim()) { throw 'the deploy identity could not be created.' }
        $AdminAppId   = $ident.AppId
        $AdminCertPem = $ident.PemPath
        # WE created this key file, so WE shred it when the run ends -- see Clear-PimEphemeralPem.
        # It is re-derived from the certificate in the store on the next run, in about a second.
        $script:PimEphemeralPem = $ident.PemPath
        # The SQL Entra admin defaults to the SAME identity unless one was named. It is already the
        # subscription Owner, so making it the server's Entra admin adds no privilege it lacks --
        # and leaving it unset makes the infra step refuse several minutes later.
        if (-not "$SqlAdminClientId".Trim()) {
            $SqlAdminClientId = $ident.AppId
            if (-not "$SqlAdminCertThumbprint".Trim()) { $SqlAdminCertThumbprint = $ident.Thumbprint }
            Info "SQL Entra admin defaults to the same identity ($($ident.AppId))."
        }
        Info "deploy identity: $AdminAppId  (cert $($ident.Thumbprint))"
    } else {
        Info 'PLAN: the identity would be created here, and -AdminAppId/-AdminCertPem filled in from it.'
    }
}

# ---- s31: a -Scenario resolves the deploy topology, overriding -Source ----
# The DeployAll CORE (Get-PimDeployAllPlan) + the local fact-probes only model git-pull |
# sync-automateit (hosted vs community), so from-master is mapped to a PLAN source by managed
# hosting: central => sync-automateit (ACA/Azure SQL), local => git-pull (local host). The REAL
# from-master downlink is honoured by passing -Scenario through to Invoke-PimUpdate (below).
$planSource    = $Source
$scenarioArgs  = @{}     # splat threaded into Invoke-PimUpdate sub-calls (empty unless -Scenario)
# 2026-09-13 -- the ring gate's override, threaded into every step that can ROLL an existing
# environment (infra = Setup-PimContainers, code = Invoke-PimUpdate -> Update-PimContainers). Built
# once so an audited override cannot be honoured by one step and refused by the next. Empty unless the
# operator passed -OverrideRingGate; the gate itself runs regardless.
$ringGateArgs = @{}
if ($OverrideRingGate) {
    if (-not "$Reason".Trim()) { throw "Invoke-PimDeployAll: -OverrideRingGate requires -Reason '<why this environment may take a version its ring does not approve>'." }
    $ringGateArgs = @{ OverrideRingGate = $true; Reason = "$Reason".Trim() }
}
# The SQL identity, threaded into EVERY Invoke-PimUpdate sub-call -- the two DETECT calls as well
# as the schema APPLY. Built once here rather than at each call site: this passthrough has already
# been forgotten once, and a detect that cannot authenticate reports "unknown" instead of failing,
# so a second omission would be silent. Empty unless a SQL admin identity was supplied, which keeps
# every existing caller's behaviour byte-for-byte unchanged.
# Explicit subscription for this script's OWN az calls. mgmt1 (and any deploy host that has ever
# signed into two directories) carries more than one context, and the default is not always the one
# you want -- a bare call then reads somebody else's subscription and answers "not found", which is
# indistinguishable from "not deployed yet". BUG-102's rule, applied here.
$azSubArgs = @()
if ("$SubscriptionId".Trim()) { $azSubArgs = @('--subscription', $SubscriptionId) }
$sqlAuthArgs   = @{}
if ("$SqlAdminClientId".Trim()) {
    $sqlAuthArgs['SqlAdminClientId'] = $SqlAdminClientId
    if     ("$SqlAdminCertThumbprint".Trim()) { $sqlAuthArgs['SqlAdminCertThumbprint'] = $SqlAdminCertThumbprint }
    elseif ("$SqlAdminClientSecret".Trim())   { $sqlAuthArgs['SqlAdminClientSecret']   = $SqlAdminClientSecret }
}
if ("$TenantId".Trim()) { $sqlAuthArgs['TenantId'] = $TenantId }

# 🔴 THE SAME IDENTITY, IN THE SHAPE THE STORE-WRITING STEPS ASK FOR.
# Set-PimFeatureBaseline, Set-PimPortalAdmins and Initialize-PimMailSender all take
# -AdminAppId plus -AdminCertThumbprint / -AdminSecret, and all three REFUSE without one:
#     RESULT: FAILED -- supply -AdminSecret or -AdminCertThumbprint
#     Initialize-PimMailSender: one of -AdminSecret / -AdminCertThumbprint is required
# They were being called with only the server, database and tenant -- so 'features' could never
# succeed on any deploy, and 'mailsender' could never provision a sender on any deploy. The
# mailsender step is deliberately non-fatal, which is exactly why nobody noticed: every deploy
# printed "MAIL SENDER NOT PROVISIONED", which reads like an Exchange timing problem and was in
# fact a missing argument. Same class as -AcrName, -Apps and the SQL identity above.
# The SQL admin is the right identity here: it is the one the infra step made the server's Entra
# admin, so it is the one that can write pim.Settings. -AdminCertPem (this script's other admin
# credential) is a FILE for `az login` and cannot be used by these scripts, which want a
# thumbprint in the local store -- passing it would be a different value wearing the same name.
$storeAdminArgs = @{}
if ("$SqlAdminClientId".Trim() -and ("$SqlAdminCertThumbprint".Trim() -or "$SqlAdminClientSecret".Trim())) {
    $storeAdminArgs['AdminAppId'] = $SqlAdminClientId
    if     ("$SqlAdminCertThumbprint".Trim()) { $storeAdminArgs['AdminCertThumbprint'] = $SqlAdminCertThumbprint }
    else                                      { $storeAdminArgs['AdminSecret']         = $SqlAdminClientSecret }
}
if ($UseSignedInAccount) { $storeAdminArgs = @{ UseSignedInAccount = $true } }   # 71.33: the store-writing steps connect as the signed-in user
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

# 🔴 BUG-67, SECOND HALF: A -Scenario MEANS ACA, AND THE UPDATE SOURCE DOES NOT DECIDE COMPUTE.
# `Get-PimUpdateSourceProfile` keys isHosted off the update SOURCE. For S5/S6 the source resolves
# to 'git-pull' (from-master + managedHosting=local), whose profile says isHosted=$false -- so the
# plan skipped prereq, image, sqlaccess, easyauth, updater and access as "not applicable to the
# hosted flavour", and on -Apply would have sent INFRA to Setup-PimVM.ps1 instead of
# Setup-PimContainers.ps1. For EVERY S5/S6 tenant.
#
# The existing fix reads `provides.container-apps-environment` from a -Descriptor -- correct, and
# the right long-term source of truth. But it only runs when a descriptor is supplied, and the
# estate deploys these scenarios without one, so the wrong inferred value stood. Measured
# 2026-09-11 planning an S6 rebuild: hosted=False on an environment that runs a container app, two
# ACA jobs, a managed environment and its own registry.
#
# S1..S6 are all Container Apps deployments; where they RUN and whose tenant owns them are separate
# axes from what compute they use. A supplied -Descriptor still wins (it is read below and
# overrides this), and -NotHosted remains for a genuine VM install, which is the no-scenario case.
if ($Scenario -and -not $hosted -and -not $NotHosted) {
    # 🪤 -f binds TIGHTER than +, so a format string split across a concatenation only formats the
    # LAST fragment -- the first one printed a literal "{0}". Parenthesise the whole string.
    Write-Host (("[scenario] hosting: False -> True (-Scenario {0} is a Container Apps deployment; " +
                 "the update source '{1}' describes where UPDATES come from, not what compute runs them)") -f $Scenario, $Source) -ForegroundColor Yellow
    $hosted = $true
}
if ($NotHosted) { $hosted = $false }

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
    # BUG-157: the descriptor reader is part of the AutomateIT framework, which the public community
    # edition does not include. Say that, instead of naming a path that can never exist there.
    if (-not (Test-Path -LiteralPath $aitDeploy)) { throw "-Descriptor needs the AutomateIT framework reader ($aitDeploy), which the public community edition does not include. Omit -Descriptor and pass the deployment values as parameters." }
    . $aitDeploy
    $descriptorDoc = Get-AitPlatformDeploy -Path $Descriptor
    if (-not $descriptorDoc) { throw "-Descriptor '$Descriptor' is missing or empty. Refusing to deploy against a descriptor that says nothing -- that is indistinguishable from deploying with no configuration at all." }

    $resolved = Resolve-AitSolutionDeploy -Config $descriptorDoc -SolutionName 'PIM4EntraPS'

    # THE BUG-67 FIX ITSELF, and it is resolved FIRST because the validation below depends on it:
    # ACA declared => hosted, whatever the MSP topology says.
    $hasAca = $false
    foreach ($k in $resolved.Provides.Keys) { if ("$k".ToLowerInvariant() -eq 'container-apps-environment') { $hasAca = $true; break } }
    if ($hasAca -ne $hosted) {
 Write-Host ("[descriptor] hosting: {0} -> {1} (the descriptor {2} declare container-apps-environment; the MSP topology is a SEPARATE axis)" -f `
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
function Invoke-PimTenantGraphGet {
    <#
      🔴 BUG-215 -- A GRAPH READ PINNED TO -TenantId. `az rest` and `az ad` take no --subscription: they
      use the DEFAULT az account's tenant, which on a host signed in to more than one directory is
      regularly ANOTHER COMPANY's (the other-company default recorded in the repo rules). The token is
      minted for THIS tenant by name instead. $null = "could not read", never "empty".
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not "$TenantId".Trim() -or -not (Have 'az')) { return $null }
    $tok = "$(az account get-access-token --tenant $TenantId --resource https://graph.microsoft.com --query accessToken -o tsv 2>$null)".Trim()
    $global:LASTEXITCODE = 0
    if (-not $tok) { return $null }
    try { return (Invoke-RestMethod -Headers @{ Authorization = "Bearer $tok" } -Uri ("https://graph.microsoft.com/v1.0" + $Path) -ErrorAction Stop) }
    catch { return $null }
    finally { $tok = $null }
}
function Test-EngineAppRegPresent {
    # present when an app with the engine display name exists AND has a credential. Best-effort
    # via az; unknown (no az / not logged in) => NEEDED=$true (let the idempotent installer run).
    #
    # 🪤 THIS ONE IS A PROBE, NOT A LOOKUP -- and the difference matters. Set-PimManagerEasyAuth
    # used a display-name search to DECIDE WHICH APP TO USE, so a rename made it create a duplicate
    # (proven in two tenants). Here the answer only decides whether to RUN the idempotent installer:
    # a miss re-runs a step that is safe to re-run, and never creates a second registration. So the
    # name search stays, and says so -- an unexplained inconsistency between the two would look like
    # one of them had been forgotten.
    # 🔑 The installer downstream is what owns identity, and it is the place to key stably.
    if (-not (Have 'az')) { return $null }
    try {
        # BUG-215: asked of -TenantId by name -- `az ad app list` would ask the DEFAULT account's tenant,
        # and an app of the same name in another company's directory would read as "present here".
        $apps = Invoke-PimTenantGraphGet -Path ("/applications?`$filter=displayName eq '" + "$EngineAppDisplayName".Replace("'", "''") + "'&`$select=appId")
        if ($null -eq $apps) { return $null }
        if (@(@($apps.value) | Where-Object { "$($_.appId)".Trim() }).Count) { return $true }
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
        $g = az group show @azSubArgs -n $ResourceGroup --query name -o tsv 2>$null
        if (-not "$g".Trim()) { return $false }
        $acrId = az acr show @azSubArgs -n $AcrName --query id -o tsv 2>$null
        if (-not "$acrId".Trim()) { return $false }
        # the identity AND its role -- see above.
        $uamiPrincipal = az identity show @azSubArgs -g $ResourceGroup -n $PrereqIdentityName --query principalId -o tsv 2>$null
        if (-not "$uamiPrincipal".Trim()) {
            Write-Host "  prereq: registry '$AcrName' exists but pull identity '$PrereqIdentityName' does NOT -- half-built; re-running PREREQ." -ForegroundColor Yellow
            return $false
        }
        $pull = az role assignment list @azSubArgs --assignee $uamiPrincipal --scope $acrId --role AcrPull `
                    --query "[0].roleDefinitionName" -o tsv 2>$null
        if (-not "$pull".Trim()) {
            Write-Host "  prereq: '$PrereqIdentityName' exists but holds NO AcrPull on '$AcrName' -- every image pull would fail in INFRA; re-running PREREQ." -ForegroundColor Yellow
            return $false
        }
        if (-not $PrereqSkipSql) {
            $srv = ("$SqlServerFqdn" -split '\.')[0]
            if ("$srv".Trim()) {
                $s = az sql server show @azSubArgs -g $ResourceGroup -n $srv --query name -o tsv 2>$null
                if (-not "$s".Trim()) {
                    Write-Host "  prereq: SQL server '$srv' does NOT exist -- SCHEMA would have nothing to talk to; re-running PREREQ." -ForegroundColor Yellow
                    return $false
                }
                # 🔴 -SqlPrivateEndpoint CHANGES WHAT "PREREQ IS CURRENT" MEANS, AND THIS PROBE COULD
                # NOT SEE IT. An environment first built WITHOUT the switch has a server, an ACR, a
                # pull identity and its AcrPull -- so every check above passed and prereq was skipped
                # as "already current". But the private-SQL half had never run: no 'id-pim-sql-<token>',
                # no private endpoint, and the Entra admin still the DEPLOY SPN. INFRA then threw
                #     the SQL admin identity was not published by the prereq step
                # from three scripts down, about a step the plan had just called current. Measured at
                # a customer on 2026-09-11; it is the same §45.1 rule the header above cites -- a
                # probe that cannot observe the thing it gates is not a probe.
                # 🪤 The admin is checked by SID, not by existence. A server whose admin is the deploy
                # SPN looks identically "administered" to one whose admin is the identity, and only
                # the second one can be reached from inside the VNet.
                if ($SqlPrivateEndpoint) {
                    $sqlUamiName = "id-pim-sql-$PrereqToken"
                    $sqlUamiOid  = az identity show @azSubArgs -g $ResourceGroup -n $sqlUamiName --query principalId -o tsv 2>$null
                    if (-not "$sqlUamiOid".Trim()) {
                        Write-Host "  prereq: -SqlPrivateEndpoint is set but the SQL admin identity '$sqlUamiName' does NOT exist -- nothing inside the environment could create its database users; re-running PREREQ." -ForegroundColor Yellow
                        return $false
                    }
                    $curAdmin = az sql server ad-admin list @azSubArgs -g $ResourceGroup -s $srv --query "[0].sid" -o tsv 2>$null
                    if ("$curAdmin".Trim() -ne "$sqlUamiOid".Trim()) {
                        Write-Host "  prereq: the Entra admin on '$srv' is '$curAdmin', not '$sqlUamiName' -- the in-cloud bootstrap would authenticate as an identity with no rights; re-running PREREQ." -ForegroundColor Yellow
                        return $false
                    }
                    $pe = az network private-endpoint show @azSubArgs -g $ResourceGroup -n "pe-$srv" --query id -o tsv 2>$null
                    if (-not "$pe".Trim()) {
                        Write-Host "  prereq: no private endpoint 'pe-$srv' -- with its public endpoint disabled the server is reachable from NOWHERE; re-running PREREQ." -ForegroundColor Yellow
                        return $false
                    }
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
        # 🔴 ASK "WHICH TAGS EXIST", NOT "SHOW ME THIS ONE".
        # `az acr repository show --image repo:tag` ERRORS when the tag is absent, and absent is the
        # NORMAL answer here -- this runs before the image for a new version has been built. So the
        # very first thing a customer saw on every deploy was:
        #     az exit 3: ERROR: ... the specified tag does not exist. Correlation ID: ...
        # printed by a probe whose job is to ask a question, on a deploy that then proceeded
        # perfectly. An error message that appears during correct operation teaches the reader to
        # ignore error messages.
        # Listing the tags and matching in PowerShell asks the same question with no error, and
        # keeps the JMESPath free of characters cmd.exe would eat.
        $tags = @(az acr repository show-tags @azSubArgs -n $AcrName --repository $ImageRepo -o tsv 2>$null) |
                Where-Object { "$_".Trim() }
        return ([bool](@($tags) -contains "$tag".Trim()))
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
        $e = az containerapp env show @azSubArgs -g $ResourceGroup -n $EnvName --query "name" -o tsv 2>$null
        if (-not "$e".Trim()) { return $false }
        # The environment exists. Now the part that actually matters: does the MANAGER app exist?
        $m = az containerapp show @azSubArgs -g $ResourceGroup -n $ManagerApp --query "name" -o tsv 2>$null
        if (-not "$m".Trim()) {
            Write-Host "  infra: ACA environment '$EnvName' exists but app '$ManagerApp' does NOT -- half-built; re-running INFRA." -ForegroundColor Yellow
            return $false
        }
        # 🔴 EXISTING IS NOT PROVISIONED, AND THAT DISTINCTION COST A WHOLE DEPLOY.
        # An app whose creation FAILED still answers `containerapp show` with its name -- so this
        # probe said "already current" about an app in provisioningState=Failed with ZERO revisions
        # and no ingress FQDN. Every re-run then skipped INFRA, the only step that could repair it,
        # and the deploy died four steps later in easyauth with
        #     no ingress FQDN on ca-pim-manager -- is ingress enabled?
        # which points at ingress configuration and is nothing to do with it.
        # 🔑 THE CAUSE IS WORTH KNOWING because it will recur on every greenfield: the app is created
        # seconds after its identity is granted AcrPull, and AZURE RBAC HAS NOT PROPAGATED YET --
        #     unable to pull image using Managed identity id-pim-<token> for registry acrpim<token>
        # The grant is correct; it is simply not effective yet. Re-running INFRA once the assignment
        # has landed creates the app cleanly, which is exactly what this probe must allow to happen.
        # Same §45.1 rule as the comments above: a repair gated on a condition that cannot observe
        # the thing being repaired is not a repair.
        $mState = az containerapp show @azSubArgs -g $ResourceGroup -n $ManagerApp --query "properties.provisioningState" -o tsv 2>$null
        $mFqdn  = az containerapp show @azSubArgs -g $ResourceGroup -n $ManagerApp --query "properties.configuration.ingress.fqdn" -o tsv 2>$null
        if ("$mState".Trim() -and "$mState".Trim() -notmatch '(?i)^Succeeded$') {
            Write-Host "  infra: app '$ManagerApp' exists but provisioningState='$mState' (not Succeeded) -- it never came up; re-running INFRA." -ForegroundColor Yellow
            Write-Host "         On a greenfield this is usually AcrPull RBAC that had not propagated when the app was first created." -ForegroundColor DarkGray
            return $false
        }
        if (-not "$mFqdn".Trim()) {
            Write-Host "  infra: app '$ManagerApp' has NO ingress FQDN -- Easy Auth and every client need one; re-running INFRA." -ForegroundColor Yellow
            return $false
        }
        # 🔴 WITH PRIVATE SQL, INFRA IS THE ONLY THING THAT CAN APPLY MANAGER ACCESS -- so if the
        # bootstrap job does not carry the CURRENT SuperAdmin list, infra is NOT current.
        # The `access` step cannot write to a private store itself; it hands the work to the
        # bootstrap job, and only INFRA stamps the list onto that job and runs it. Once an
        # environment converged, infra was skipped, the job kept whatever list it had (or none), and
        # `access` reported success against a job that had never been told. Measured at a customer
        # 2026-09-12: a green end-to-end deploy, and no SuperAdmin in the Manager.
        # 🪤 Being wrong here costs one idempotent re-run of infra. Being wrong the other way costs
        # the environment its administrators, silently -- the same asymmetry as the BUG-49/51 checks
        # above, which is why this belongs in the probe and not in a warning.
        if ($SqlPrivateEndpoint -and "$ManagerSuperAdmins".Trim()) {
            $wantSa = @("$ManagerSuperAdmins" -split '[,;]+' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
            $jobEnv = az containerapp job show @azSubArgs -g $ResourceGroup -n $DbInitJobName `
                        --query "properties.template.containers[0].env[?name=='PIM_DBINIT_MANAGER_ACCESS'].value" -o tsv 2>$null
            $haveSa = @()
            if ("$jobEnv".Trim()) {
                try { $haveSa = @(("$jobEnv".Trim() | ConvertFrom-Json) | ForEach-Object { "$($_.identity)".Trim().ToLowerInvariant() }) } catch { $haveSa = @() }
            }
            $missSa = @($wantSa | Where-Object { $haveSa -notcontains $_ })
            if ($missSa.Count) {
                Write-Host "  infra: the bootstrap job '$DbInitJobName' does not carry $($missSa.Count) of the requested SuperAdmin(s) -- nobody could administer this environment; re-running INFRA." -ForegroundColor Yellow
                return $false
            }
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
            $peerState = az network vnet peering show @azSubArgs -g $VnetResourceGroup --vnet-name $VnetName -n "$spokeShort-to-$hubShort" --query peeringState -o tsv 2>$null
            if ("$peerState".Trim() -ne 'Connected') {
                Write-Host "  infra: spoke VNet '$VnetName' is NOT peered to '$HubVnetName' (state='$peerState') -- the Manager has no route from any client; re-running INFRA." -ForegroundColor Yellow
                return $false
            }
        }
        # ARM rights on the identity that actually reconciles: the tick Job in cron mode, the
        # Manager otherwise. Zero role assignments = PIM's Azure half is blind (BUG-51).
        if (-not $SkipAzureRbac -and "$SubscriptionId".Trim()) {
            # BUG-215: --subscription on both -- a bare call read whatever subscription was the default.
            $rbacOid = $(if ($WorkerMode -eq 'cron') { az containerapp job show @azSubArgs -g $ResourceGroup -n $TickJobName --query "identity.principalId" -o tsv 2>$null }
                         else { az containerapp show @azSubArgs -g $ResourceGroup -n $ManagerApp --query "identity.principalId" -o tsv 2>$null })
            if ("$rbacOid".Trim()) {
                $armRoles = @(az role assignment list @azSubArgs --assignee "$rbacOid".Trim() --scope "/subscriptions/$SubscriptionId" --query "[].id" -o tsv 2>$null | Where-Object { "$_".Trim() }).Count
                if ("$armRoles".Trim() -and [int]"$armRoles".Trim() -eq 0) {
                    Write-Host "  infra: workload identity holds NO Azure role assignment on /subscriptions/$SubscriptionId -- PIM's Azure half is blind (azure-scopes=0); re-running INFRA." -ForegroundColor Yellow
                    return $false
                }
            }
        }

        # always-on mode: the worker apps are the workload and the Manager standing means the loop
        # ran. cron mode: the tick Job is the workload, so keep going.
        if ($WorkerMode -ne 'cron') { return $true }
        $jobOid = az containerapp job show @azSubArgs -g $ResourceGroup -n $TickJobName --query "identity.principalId" -o tsv 2>$null
        if (-not "$jobOid".Trim()) {
            Write-Host "  infra: tick Job '$TickJobName' is missing (or has no identity) -- half-built; re-running INFRA." -ForegroundColor Yellow
            return $false
        }
        # The Job exists. Its GRANTS are the step's real output -- and they are what BUG-44 skipped.
        # BUG-215: read in -TenantId by name, not in whatever tenant the default az account is in.
        # Unreadable is "cannot tell" ($null -> NEEDED, the fail-safe), never "zero".
        $ra = Invoke-PimTenantGraphGet -Path "/servicePrincipals/$("$jobOid".Trim())/appRoleAssignments"
        if ($null -eq $ra) { return $null }
        $roles = @(@($ra.value) | Where-Object { $_ -and "$($_.id)".Trim() }).Count
        if ($roles -eq 0) {
            Write-Host "  infra: tick Job '$TickJobName' exists but its identity holds NO Graph app-roles -- the grant step never completed; re-running INFRA." -ForegroundColor Yellow
            return $false
        }
        return $true
    } catch { return $null }
}
$script:PimSqlHostResolvable = $null
function Test-PimSqlHostResolvable {
    # 🪤 BUG-249 (live E2E build, 2026-09-23): on a GREENFIELD tenant the SQL server does not exist
    # yet, and both DETECT probes below still ran Invoke-PimUpdate's column read -- one failed
    # connect ("No such host is known") PER TABLE, each with SqlClient's retries. The deploy sat
    # silent for many minutes before printing its plan, which reads exactly like a hang. A name that
    # does not resolve cannot answer either probe, so both return "unknown" (=> needed) at once.
    # Cached: asked once per run.
    if ($null -ne $script:PimSqlHostResolvable) { return $script:PimSqlHostResolvable }
    $h = "$SqlServerFqdn".Trim()
    if (-not $h -and "$SqlConnectionString" -match '(?i)(?:Server|Data Source)\s*=\s*(?:tcp:)?([^,;]+)') { $h = $Matches[1].Trim() }
    if (-not $h) { $script:PimSqlHostResolvable = $true; return $true }   # nothing to judge -- let the probe decide
    try { [void][System.Net.Dns]::GetHostAddresses($h); $script:PimSqlHostResolvable = $true }
    catch {
        $script:PimSqlHostResolvable = $false
        Write-Host "  sql: '$h' does not resolve (greenfield -- prereq creates it); schema + code probes skipped, both steps NEEDED." -ForegroundColor Yellow
    }
    return $script:PimSqlHostResolvable
}
function Test-SchemaConformant {
    # reuse Invoke-PimUpdate's SQL DETECT (it reads the deployed columns + builds the plan). We do
    # NOT duplicate that logic -- we call the detect-only path and read SqlUpdateRequired.
    if (-not "$SqlConnectionString".Trim()) { return $null }   # cannot read => run schema step
    # 🪤 A PRIVATE SQL SERVER CANNOT BE PROBED FROM HERE EITHER, and trying costs the full connect
    # timeout ON EVERY DEPLOY before answering "unknown" -- the same answer this line gives for
    # free. The schema step itself is owned by the in-cloud bootstrap in this topology.
    if ($SqlPrivateEndpoint) { return $null }
    if (-not (Test-PimSqlHostResolvable)) { return $null }
    try {
        $upd = Join-Path $here 'Invoke-PimUpdate.ps1'
        $det = & $upd -Source $Source @scenarioArgs @sqlAuthArgs -DetectOnly -SqlConnectionString $SqlConnectionString `
                    -ResourceGroup $ResourceGroup -ManagerApp $ManagerApp -ImageTag $ImageTag 6>$null
        $last = @($det) | Where-Object { $_ -and ($_.PSObject.Properties.Name -contains 'SqlUpdateRequired') } | Select-Object -Last 1
        if ($last) { return (-not [bool]$last.SqlUpdateRequired) }
        return $null
    } catch { return $null }
}
function Test-ManagerImageCurrent {
    # reuse Invoke-PimUpdate's GUI DETECT (pulled content hash vs running image). Same as above:
    # detect-only, read GuiUpdateRequired. Unknown => run the code step.
    if (-not (Test-PimSqlHostResolvable)) { return $null }   # BUG-249 -- greenfield: nothing to compare against
    try {
        $upd = Join-Path $here 'Invoke-PimUpdate.ps1'
        $det = & $upd -Source $Source @scenarioArgs @sqlAuthArgs -DetectOnly -SqlConnectionString $SqlConnectionString `
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
# Pass the CORRECTED value whenever anything corrected it -- a descriptor, or the -Scenario rule
# above. Without this the plan re-derives hosted from the update source and silently disagrees with
# the steps that already ran against the corrected value.
if ($Descriptor -or $Scenario -or $NotHosted) { $planArgs['HostedOverride'] = $hosted }
$plan = Get-PimDeployAllPlan -Source $Source -Facts $facts -Apply:$applyGate -ValidateOnly:$ValidateOnly @planArgs

Write-Host ""
Write-Host "  DEPLOY-ALL PLAN ($(if($plan.whatIf){'WHATIF'}else{'APPLY'}); hosted=$($plan.hosted)):" -ForegroundColor Cyan
$i = 0
foreach ($s in $plan.steps) { $i++; Write-Host ("    {0}. {1,-8} [{2,-20}] {3}" -f $i, $s.key, $s.action, $s.reason) }
Write-Host ""

# =================================================================================================
# 🔴 IMP-49 t -- THE SETUP-HOST FIREWALL WINDOW: opened for this run, closed at its end.
# Host-side SQL steps connect from THIS host's public IP. Prereq used to create 'AllowSetupHost' and
# nothing ever removed it -- a standing hole for whichever machine last deployed. Now the run records
# what it found, opens the window only if it has to, and removes at the end what IT created (a rule
# that pre-dates the run belongs to another window -- the MSP build's -- and is left alone).
# =================================================================================================
$script:PimSetupHostWindow = $null
function Get-PimSetupHostWindowPlan {
    # PURE. What this run does with 'AllowSetupHost', decided from what exists when it starts.
    param([bool]$Applicable, [bool]$ServerExists, [bool]$RuleExists, [bool]$Keep)
    if (-not $Applicable) { return @{ open = $false; closeAtEnd = $false; reason = 'not applicable (not a hosted apply against a public SQL server)' } }
    if ($ServerExists -and $RuleExists) { return @{ open = $false; closeAtEnd = $false; reason = "'AllowSetupHost' already existed when this run started -- another window owns it, so it is left exactly as found" } }
    $closeWhy = $(if ($Keep) { 'kept at the end (-KeepSetupHostRule: the caller owns the window and closes it)' } else { 'removed at the end of this run' })
    if ($ServerExists) { return @{ open = $true; closeAtEnd = (-not $Keep); reason = "this host is not allowed yet -- opened for this run, $closeWhy" } }
    return @{ open = $false; closeAtEnd = (-not $Keep); reason = "the SQL server does not exist yet -- prereq creates it with this host allowed; that rule is this run's and is $closeWhy" }
}
function Get-PimSetupHostSqlTarget {
    # The server's subscription + resource group, or $null when this identity cannot see it.
    $srv = ("$SqlServerFqdn".Trim() -split '\.')[0]
    $sqlSub = $(if ("$SqlSubscriptionId".Trim()) { "$SqlSubscriptionId".Trim() } else { "$SubscriptionId".Trim() })
    if (-not $srv -or -not $sqlSub) { return $null }
    $rg = "$(@(az sql server list --subscription $sqlSub --query "[?name=='$srv'].resourceGroup" -o tsv 2>$null) | Select-Object -First 1)".Trim()
    $global:LASTEXITCODE = 0
    if (-not $rg) { return @{ server = $srv; sub = $sqlSub; rg = ''; exists = $false } }
    return @{ server = $srv; sub = $sqlSub; rg = $rg; exists = $true }
}
function Get-PimSetupHostRuleIp([hashtable]$T) {
    $ip = "$(@(az sql server firewall-rule list --subscription $T.sub -g $T.rg -s $T.server --query "[?name=='AllowSetupHost'].startIpAddress" -o tsv 2>$null) | Select-Object -First 1)".Trim()
    $global:LASTEXITCODE = 0
    return $ip
}
function Open-PimSetupHostWindow {
    $applicable = [bool]($hosted -and $applyGate -and -not $ValidateOnly -and -not $StepRunner -and "$SqlServerFqdn".Trim() -and
                         -not $SqlPrivateEndpoint -and -not $PrereqSkipSql -and (Have 'az'))
    $t = $(if ($applicable) { Get-PimSetupHostSqlTarget } else { $null })
    if ($applicable -and -not $t) { $applicable = $false }
    $ruleIp = $(if ($t -and $t.exists) { Get-PimSetupHostRuleIp $t } else { '' })
    $p = Get-PimSetupHostWindowPlan -Applicable $applicable -ServerExists ([bool]($t -and $t.exists)) -RuleExists ([bool]$ruleIp) -Keep ([bool]$KeepSetupHostRule)
    $script:PimSetupHostWindow = @{ plan = $p; target = $t; opened = $false }
    if (-not $applicable) { return }
    Info "sql setup-host window: $($p.reason)"
    if (-not $p.open) { return }
    $ip = "$SetupHostIp".Trim()
    if (-not $ip) {
        # Stated every time: the deploy asks a THIRD-PARTY web service for this host's public address.
        try { $ip = "$((Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec 20).ip)".Trim() } catch { $ip = '' }
        Info "  this host's public IP: '$ip' -- read from https://api.ipify.org (a third-party service; pass -SetupHostIp to skip the lookup)"
    } else { Info "  this host's public IP: $ip (from -SetupHostIp; no external lookup)" }
    if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
        Warn "sql setup-host window NOT opened: this host's public IP could not be determined ('$ip'). Host-side SQL steps will be refused by the firewall; pass -SetupHostIp."
        return
    }
    az sql server firewall-rule create --subscription $t.sub -g $t.rg -s $t.server -n AllowSetupHost --start-ip-address $ip --end-ip-address $ip -o none 2>$null
    $global:LASTEXITCODE = 0
    if ((Get-PimSetupHostRuleIp $t) -ne $ip) {
        Warn "sql setup-host window NOT opened: 'AllowSetupHost' for $ip did not read back on $($t.server). Host-side SQL steps will be refused by the firewall."
        return
    }
    $script:PimSetupHostWindow.opened = $true
    Info "  OPENED: 'AllowSetupHost' = $ip on $($t.server) (read back; waiting 30s for the firewall to apply)"
    Start-Sleep -Seconds 30
}
function Close-PimSetupHostWindow {
    $w = $script:PimSetupHostWindow
    if (-not $w -or -not $w.plan.closeAtEnd) { return }
    $script:PimSetupHostWindow = $null           # once, whichever exit path gets here first
    $t = $(if ($w.target -and $w.target.exists) { $w.target } else { Get-PimSetupHostSqlTarget })
    if (-not $t -or -not $t.exists) { return }
    if (-not (Get-PimSetupHostRuleIp $t)) { Info "sql setup-host window: nothing to close ('AllowSetupHost' is not on $($t.server))"; return }
    az sql server firewall-rule delete --subscription $t.sub -g $t.rg -s $t.server -n AllowSetupHost -o none 2>$null
    $global:LASTEXITCODE = 0
    if (Get-PimSetupHostRuleIp $t) {
        Warn "sql setup-host window NOT CLOSED: 'AllowSetupHost' is still on $($t.server) -- this host keeps SQL network access until it is removed:"
        Warn "  az sql server firewall-rule delete --subscription $($t.sub) -g $($t.rg) -s $($t.server) -n AllowSetupHost"
    } else { Info "sql setup-host window CLOSED: 'AllowSetupHost' removed from $($t.server) and read back" }
}

# 🔴 SEC-44 -- WHO MAY SIGN IN IS DECIDED AT THE FRONT DOOR, for a Manager that does not exist yet.
# Without an answer the Easy Auth step refuses (it never again defaults to "every account in the
# tenant, guests included"), and on a NEW environment that refusal would arrive after the
# infrastructure had been built. So ask first. An EXISTING Manager is left to the step itself, which
# keeps an application that is already assignment-required and refuses anything else.
$easyAuthPlanned = @($plan.steps | Where-Object { "$($_.key)" -eq 'easyauth' -and $_.do }).Count -gt 0
# §79.11 (community install proof, 2026-09-25): the PLAN said nothing about this, so the first -Apply of the README command
# was refused -- after the operator had reviewed a clean plan. Say it in the plan too.
$easyAuthInPlan = @($plan.steps | Where-Object { "$($_.key)" -eq 'easyauth' -and "$($_.action)" -ne 'skip-current' }).Count -gt 0
if ($plan.whatIf -and $easyAuthInPlan -and -not $StepRunner -and
    -not @($EasyAuthAllowedPrincipals | Where-Object { "$_".Trim() }).Count -and -not $EasyAuthAllowAllTenantUsers) {
    Warn ("sign-in: on -Apply a NEW Manager is REFUSED until you say who may sign in -- add -EasyAuthAllowedPrincipals " +
          "<upn-or-group>[,...] (recommended), or -EasyAuthAllowAllTenantUsers to admit every member account.")
}
if ($easyAuthPlanned -and -not $plan.whatIf -and -not $StepRunner -and
    -not @($EasyAuthAllowedPrincipals | Where-Object { "$_".Trim() }).Count -and -not $EasyAuthAllowAllTenantUsers) {
    $mgrExistsNow = ''
    if ((Have 'az') -and "$ResourceGroup".Trim()) { $mgrExistsNow = "$(az containerapp show @azSubArgs -g $ResourceGroup -n $ManagerApp --query name -o tsv 2>$null)".Trim() }
    $global:LASTEXITCODE = 0
    if (-not $mgrExistsNow) {
        throw ("REFUSED before any deploy step ran: say who may sign in to the Manager. Pass -EasyAuthAllowedPrincipals " +
               "<upn-or-group>[,...] to admit exactly those, or -EasyAuthAllowAllTenantUsers to admit every member account " +
               "(guests are never admitted by that). A new Manager is not deployed open to every account in the tenant.")
    }
    Info "sign-in: no -EasyAuthAllowedPrincipals / -EasyAuthAllowAllTenantUsers -- the existing Manager's restriction is kept if it has one; the easyauth step refuses otherwise."
}

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
function Get-PimEasyAuthFailureAction {
    <#
      PURE (SEC-31). The Easy Auth step failed -- what happens to the Manager's ingress?
        'already-closed'            the closing access restriction is on it (a NEW Manager): leave it.
        'close'                     no working Easy Auth in front of it (disabled, or UNREADABLE -- could
                                    not tell is not "protected"): close it now.
        'keep-behind-existing-auth' Easy Auth is enabled from an earlier run: it keeps serving behind it.
    #>
    param([string]$AuthEnabled, $GatePresent)
    if ($GatePresent -eq $true) { return 'already-closed' }
    if ("$AuthEnabled".Trim() -match '(?i)^true$') { return 'keep-behind-existing-auth' }
    return 'close'
}
function Close-PimManagerAfterEasyAuthFailure {
    # SEC-31 -- the easyauth step failed: make sure the Manager is not left open. Returns one sentence
    # for the step's detail; every branch is stated, none is silent.
    param([string]$EaScript, [hashtable]$EaArgs)
    $enabled = "$(@(az containerapp auth show @azSubArgs -g $ResourceGroup -n $ManagerApp --query platform.enabled -o tsv 2>$null) | Select-Object -First 1)".Trim()
    $gateJson = (@(az containerapp ingress access-restriction list @azSubArgs -g $ResourceGroup -n $ManagerApp -o json 2>$null) -join "`n")
    $global:LASTEXITCODE = 0
    $gatePresent = $null
    # PS 5.1: ConvertFrom-Json emits an array as ONE object -- assign first, then enumerate.
    if ("$gateJson".Trim()) { try { $gateRules = ConvertFrom-Json -InputObject $gateJson; $gatePresent = [bool](@($gateRules) | Where-Object { "$($_.name)" -eq 'pim-closed-until-easyauth' }) } catch { $gatePresent = $null } }
    switch (Get-PimEasyAuthFailureAction -AuthEnabled $enabled -GatePresent $gatePresent) {
        'already-closed'            { return 'The Manager stays CLOSED: it still carries the closing access restriction, which only a successful Easy Auth run removes.' }
        'keep-behind-existing-auth' { return "The Manager keeps serving behind the Easy Auth configuration it ALREADY had (platform.enabled=$enabled); it was not closed, because that would take a protected console offline over a failed re-run." }
        default {
            $closeArgs = @{ App = $ManagerApp; ResourceGroup = $ResourceGroup; TenantId = $TenantId; CloseIngressOnly = $true }
            if ("$SubscriptionId".Trim()) { $closeArgs['SubscriptionId'] = $SubscriptionId }
            try { & $EaScript @closeArgs | Out-Host; return "The Manager had NO working Easy Auth (platform.enabled='$enabled'), so it was CLOSED now (access restriction applied and read back)." }
            catch {
                Warn "COULD NOT CLOSE the Manager: $($_.Exception.Message)"
                Warn "  Lock it down by hand NOW: az containerapp ingress update --subscription $SubscriptionId -g $ResourceGroup -n $ManagerApp --type internal"
                return "The Manager has NO working Easy Auth and could NOT be closed ($($_.Exception.Message)) -- lock it down by hand: az containerapp ingress update --subscription $SubscriptionId -g $ResourceGroup -n $ManagerApp --type internal"
            }
        }
    }
}

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
            # An address plan is required, but it can come from EITHER source. A customer with
            # their own IP range must not be made to invent an estate index whose value is then
            # discarded -- that is how a meaningless number ends up copied between customers.
            $haveCidr = ("$PrereqVnetAddressPrefix".Trim() -and "$PrereqSubnetAddressPrefix".Trim())
            if (-not $haveCidr -and $PrereqIndex -lt 0) {
                # Still not defaulted, for the original reason: the address range picks the VNet
                # CIDR, and two environments silently sharing one is unrecoverable once anything
                # is peered -- so a wrong guess here is far worse than a refusal.
                return @{ ok=$false; ran=$true; detail=('PREREQ needs an address plan: either -PrereqVnetAddressPrefix + ' +
                    '-PrereqSubnetAddressPrefix (the customer''s own range, any addresses they like) or -PrereqIndex ' +
                    '(the estate scheme, <AddressBase>.<Index*8>.0/21). Refusing to guess: two environments sharing a ' +
                    'CIDR cannot be un-peered.') }
            }
            # 🔴 THE SPLIT-BRAIN GUARD. The prereq script derives names from the token; this
            # orchestrator was given them explicitly. If they disagree, prereq would create a
            # COMPLETE, correct-looking set of resources that infra never touches -- and both
            # halves would report success. Prove agreement BEFORE creating anything.
            # §38.1b -- THE GUARD NOW COMPARES EFFECTIVE NAMES, AND THE OVERRIDES ARE FORWARDED.
            # It used to re-derive the names from the token and refuse anything else, which made
            # an explicit -ResourceGroup structurally unusable: a customer with their own naming
            # standard could not be onboarded at all. The guard's PURPOSE is unchanged and still
            # load-bearing -- prereq must never provision under names infra will not read -- but
            # the way to satisfy it is to give prereq the SAME names infra uses, not to force
            # everyone onto the estate's.
            $derived = @{
                ResourceGroup = "rg-automateit-$PrereqToken"
                AcrName       = ("acrpim$PrereqToken" -replace '[^a-z0-9]','').ToLowerInvariant()
                VnetName      = "vnet-pim-$PrereqToken"
            }
            $eff = @{
                ResourceGroup = $(if ("$ResourceGroup".Trim()) { "$ResourceGroup".Trim() } else { $derived.ResourceGroup })
                AcrName       = $(if ("$AcrName".Trim())       { "$AcrName".Trim() }       else { $derived.AcrName })
                VnetName      = $(if ("$VnetName".Trim())      { "$VnetName".Trim() }      else { $derived.VnetName })
            }
            # The VNet may live in its own RG (an existing customer hub/spoke); prereq is told
            # which RG to build the VNet in, so a -VnetResourceGroup that points elsewhere means
            # prereq would create a VNet the deploy never uses. That IS still a split brain.
            if ("$VnetResourceGroup".Trim() -and "$VnetResourceGroup".Trim() -ne $eff.ResourceGroup) {
                return @{ ok=$false; ran=$true; detail=("PREREQ would create the VNet in '$($eff.ResourceGroup)' but this deploy reads it from " +
                    "'$VnetResourceGroup'. Refusing -- provisioning under names INFRA never reads is a silent half-deploy. " +
                    "Either point -VnetResourceGroup at the deploy RG, or pre-create the VNet and skip the prereq step.") }
            }
            if ($PSCmdlet.ShouldProcess($eff.ResourceGroup, 'create hosting prerequisites (RG, VNet, ACR, Log Analytics, SQL, AcrPull identity)')) {
                $prqId = @{}
                if ($UseSignedInAccount)              { $prqId['UseSignedInAccount'] = $true }
                elseif ($AdminAppId -and $AdminCertPem)   { $prqId['AdminAppId'] = $AdminAppId; $prqId['AdminCertPem'] = $AdminCertPem }
                elseif ($AdminAppId -and $AdminSecret){ $prqId['AdminAppId'] = $AdminAppId; $prqId['AdminSecret']  = $AdminSecret }
                else {
                    # This script REQUIRES one of the two (-AdminAppId is Mandatory and it throws
                    # without a credential), so say so here rather than let it throw from inside.
                    return @{ ok=$false; ran=$true; detail='PREREQ needs a deploy identity: -AdminAppId plus -AdminCertPem (production) or -AdminSecret.' }
                }
                # §38.1a/b -- forward the EFFECTIVE names and the network shape. Splatted so an
                # unsupplied value is genuinely absent and prereq falls back to its own derived
                # default: passing '' would override the default WITH emptiness.
                $prqShape = @{
                    ResourceGroupName = $eff.ResourceGroup
                    AcrName           = $eff.AcrName
                    VnetName          = $eff.VnetName
                }
                if ("$PrereqSubnetName".Trim())           { $prqShape['SubnetName']          = "$PrereqSubnetName".Trim() }
                if ("$PrereqVnetAddressPrefix".Trim())    { $prqShape['VnetAddressPrefix']   = "$PrereqVnetAddressPrefix".Trim() }
                if ("$PrereqSubnetAddressPrefix".Trim())  { $prqShape['SubnetAddressPrefix'] = "$PrereqSubnetAddressPrefix".Trim() }
                if ("$LogAnalyticsWorkspaceName".Trim())  { $prqShape['LogAnalyticsName']    = "$LogAnalyticsWorkspaceName".Trim() }
                # The orchestrator carries the SQL server as an FQDN; prereq creates a server by
                # NAME. Take the first label rather than making the caller pass the same thing twice.
                if ("$SqlServerFqdn".Trim())              { $prqShape['SqlServerName']       = ("$SqlServerFqdn".Trim() -split '\.')[0] }
                if ("$SqlAdminGroupName".Trim())          { $prqShape['SqlAdminGroupName']   = "$SqlAdminGroupName".Trim() }
                if ("$TroubleshootingAppId".Trim())       { $prqShape['TroubleshootingAppId'] = "$TroubleshootingAppId".Trim() }
                if ("$SetupHostIp".Trim())                { $prqShape['SetupHostIp']         = "$SetupHostIp".Trim() }   # IMP-49 t: no external lookup
                $global:LASTEXITCODE = 0
                try {
                & $prq @prqId @prqShape -TenantId $TenantId -SubscriptionId $SubscriptionId -Token $PrereqToken `
                    -Index $PrereqIndex -Location $Location -AddressBase $PrereqAddressBase `
                    -SkipSql:$PrereqSkipSql -SqlConnectionPolicy $SqlConnectionPolicy `
                    -AcrSku $AcrSku -AcrPublicAccess $AcrPublicAccess `
                    -PrivateEndpointSubnetName $PrivateEndpointSubnetName `
                    -PrivateEndpointSubnetAddressPrefix $PrivateEndpointSubnetAddressPrefix `
                    -AcrAgentPoolName $AcrAgentPoolName `
                    -SqlPrivateEndpoint:$SqlPrivateEndpoint `
                    -PrivateDnsResourceGroup $PrivateDnsResourceGroup | Out-Host
                } finally { Restore-PimCallerAzContext }
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
                # A registry with no public access can only be built through an agent pool inside
                # the VNet -- otherwise the build works or fails depending on WHERE it is run, which
                # is not reproducible.
                if ("$AcrAgentPoolName".Trim()) { $bldId['AcrAgentPool'] = "$AcrAgentPoolName".Trim() }
                try {
                & $bld @bldId -Source $Source -TenantId $TenantId -AcrName $AcrName -ImageRepo $ImageRepo `
                    -ImageTag (Get-EffectiveImageTag) | Out-Host
                } finally { Restore-PimCallerAzContext }
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                # 🪤 DO NOT NAME AN ACR IMAGE THAT WAS NEVER PUSHED. This line reported
                #     built acrpim<token>/pim-manager:2.4.324
                # even when the builder had taken its LOCAL-PACKAGE path and pushed nothing, so the
                # deploy log said the image existed and infra then failed with "the specified tag
                # does not exist" -- two lines apart, contradicting each other. The builder
                # publishes the digest it actually produced; if there is none, say what happened
                # instead of claiming a registry reference.
                $builtRef = "$($global:PIM_LastBuiltDigest)".Trim()
                $detail = if ($builtRef -match '^sha256:') { "built $AcrName/$ImageRepo`:$(Get-EffectiveImageTag) ($builtRef)" }
                          else { "build step ran but NO image reached '$AcrName' -- a local package is not a registry image" }
                return @{ ok=$ok; ran=$true; detail=$detail }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'infra' {
            # Build the SQL-admin credential splat once. Fail here, before any Azure call, if the
            # caller gave neither -- "missing mandatory parameters" thrown from three scripts deep
            # is the least useful place to learn that a credential was not supplied.
            $sqlAdminCred = @{}
            if ($UseSignedInAccount) {
                $sqlAdminCred['UseSignedInAccount'] = $true
                $why = Confirm-PimSignedInSqlAccess
                if ($why) { return @{ ok=$false; ran=$true; detail="INFRA: $why" } }
            }
            elseif ($SqlAdminCertThumbprint) { $sqlAdminCred['SqlAdminCertThumbprint'] = $SqlAdminCertThumbprint }
            elseif ($SqlAdminClientSecret) { $sqlAdminCred['SqlAdminClientSecret'] = $SqlAdminClientSecret }
            elseif ($hosted) {
                return @{ ok=$false; ran=$true; detail='INFRA needs a SQL Entra admin: pass -SqlAdminClientId plus -SqlAdminCertThumbprint (production) or -SqlAdminClientSecret.' }
            }
            # Declared support access (§64.7b): forwarded only when set, so an unset value stays ABSENT.
            if ("$SupportDbAppId".Trim()) {
                $sqlAdminCred['SupportDbAppId']    = "$SupportDbAppId".Trim()
                $sqlAdminCred['SupportDbUserName'] = $SupportDbUserName
            }
            # 🔴 THE PULL IDENTITY MUST REACH INFRA EVEN WHEN NOBODY TYPED IT -- the BUG-46 class
            # again, and it stopped a customer deploy dead on 2026-09-11:
            #     Registry 'acrpim<token>' has no admin credentials (admin account not enabled), and
            #     -RegistryIdentityResourceId was not supplied. ... Refusing to create container apps
            #     that cannot pull.
            # The refusal is right; the gap is that this orchestrator ALREADY KNOWS the identity.
            # New-PimHostingPrerequisites creates it as 'id-pim-<token>' and $PrereqIdentityName is
            # derived from exactly that convention a few hundred lines up -- the value was simply
            # never forwarded, so every deploy had to pass by hand a resource id the front door could
            # compute. Worse, it is unforwardable in practice: a resource id typed into Git Bash is
            # rewritten to a local path by MSYS (see Setup-PimContainers' guard), so the manual
            # workaround has its own trap.
            # 🪤 RESOLVED, NOT CONSTRUCTED. Building the id from strings would hand Setup-PimContainers
            # a well-formed id for an identity that may not exist, turning a clear refusal into an
            # opaque ACA failure at app-create time. If the read comes back empty we forward nothing
            # and the existing refusal stands, naming the real problem.
            if (-not "$RegistryIdentityResourceId".Trim() -and "$PrereqIdentityName".Trim() -and "$ResourceGroup".Trim() -and (Have 'az')) {
                $derivedPull = az identity show @azSubArgs -g $ResourceGroup -n $PrereqIdentityName --query id -o tsv 2>$null
                if ("$derivedPull".Trim() -match '^/subscriptions/') {
                    $RegistryIdentityResourceId = "$derivedPull".Trim()
                    Write-Host "    pull identity: $PrereqIdentityName (resolved -- no -RegistryIdentityResourceId needed)" -ForegroundColor DarkGray
                }
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
            if ($SkipPeering)                { $reach['SkipPeering']                = $true }
            if ($SkipSqlNetworkAccess)       { $reach['SkipSqlNetworkAccess']       = $true }
            if ($DnsServer)                  { $reach['DnsServer']                  = $DnsServer }
            if ($AzureRbacRoles)             { $reach['AzureRbacRoles']             = $AzureRbacRoles }
            if ($AzureRbacManagementGroupId) { $reach['AzureRbacManagementGroupId'] = $AzureRbacManagementGroupId }
            if ($SkipAzureRbac)              { $reach['SkipAzureRbac']              = $true }
            if ($RequireAzureRbac)           { $reach['RequireAzureRbac']           = $true }
            # 71.40 -- the Manager's baseline trust + document URL (absent unless set, so nothing changes for anyone else).
            if (@($BaselineTrustedKeys | Where-Object { "$_".Trim() }).Count) { $reach['BaselineTrustedKeys'] = @($BaselineTrustedKeys | Where-Object { "$_".Trim() }) }
            if ("$BaselineDocUrl".Trim())    { $reach['BaselineDocUrl']             = "$BaselineDocUrl".Trim() }
            # §38.2a -- the BUG-49 warning is about an ISOLATED VNet, so it only applies when the
            # environment is internal-only. Firing it on an external-capable deploy would be
            # false: that Manager is reachable without any peering, which is the whole point of
            # asking for external. A warning that is wrong half the time gets ignored the other half.
            if ($hosted -and $Exposure -eq 'internal' -and -not ($HubVnetName -and $HubVnetResourceGroup)) {
                # Say it at the FRONT DOOR, before anything is created -- not three scripts deep
                # where it reads as a detail of the container setup.
                Warn ("no -HubVnetName/-HubVnetResourceGroup: the PIM spoke VNet will be left ISOLATED and the " +
                      "Manager unreachable from any client. The deploy will still report success (BUG-49). " +
                      "If this environment is meant to be reachable without peering, deploy it with " +
                      "-Exposure external -- that choice is IMMUTABLE after the environment is created.")
            }
            if ($hosted -and $Exposure -eq 'external') {
                Warn ("-Exposure external -- the Container Apps environment will have PUBLIC ingress. " +
                      "Easy Auth must be in front of the Manager, and consider " +
                      "'az containerapp ingress access-restriction set' to allowlist client IPs. " +
                      "The environment's exposure cannot be changed later; the APP's ingress can.")
            }
            if ($hosted) {
                $setup = Join-Path $here 'Setup-PimContainers.ps1'
                if (-not (Test-Path $setup)) { return @{ ok=$false; ran=$true; detail="setup not found: $setup" } }
                if ($PSCmdlet.ShouldProcess($ResourceGroup, 'stand up / refresh ACA infra')) {
                    $global:LASTEXITCODE = 0
                    # §34.2c: pass the deploy identity so INFRA signs itself in to an isolated
                    # AZURE_CONFIG_DIR like every other step, instead of inheriting the ambient
                    # context. Splatted so an omitted identity keeps the previous behaviour.
                    # 🔴 §38.1a -- INFRA MUST USE THE SUBNET PREREQ ACTUALLY CREATED. Setup-PimContainers
                    # carries its own defaults (snet-pim-aca / 10.100.40.0/23), and those were being used
                    # while prereq had just built the customer's real subnet from -PrereqSubnetName /
                    # -PrereqSubnetAddressPrefix. The two halves then disagreed and ACA refused with
                    # NetcfgSubnetRangeOutsideVnet -- the estate default range is not inside a customer's
                    # VNet. Measured at a live customer 2026-09-08: prereq created snet-pim-manager
                    # 10.200.12.0/26 inside 10.200.12.0/24, infra asked for snet-pim-aca 10.100.40.0/23.
                    # Same split-brain the name guard above exists to prevent, one level down: forward
                    # the SAME values to both, never let each side default independently.
                    $infraSubnet = @{}
                    if ("$PrereqSubnetName".Trim())          { $infraSubnet['SubnetName']   = "$PrereqSubnetName".Trim() }
                    if ("$PrereqSubnetAddressPrefix".Trim()) { $infraSubnet['SubnetPrefix'] = "$PrereqSubnetAddressPrefix".Trim() }
                    # 🔑 WHO CREATES THE DATABASE USERS. With a PRIVATE SQL server this host has no
                    # route to it at all, so the users are created by a one-shot job inside the
                    # environment, as the identity prereq made the server's Entra admin. Prereq
                    # publishes that identity rather than this step re-deriving its name -- the two
                    # halves disagreeing about which identity administers the database would be a
                    # deploy that looks complete and a Manager that cannot log in.
                    $dbInit = @{}
                    if ($SqlPrivateEndpoint) {
                        $dbInit['UseInCloudDbInit'] = $true
                        # The same list the host-side `features` step would have used -- forwarded
                        # rather than re-defaulted, so both topologies enable the same features.
                        if (@($FeatureGates).Count)        { $dbInit['FeatureGates']        = @($FeatureGates) }
                        if (@($FeatureGatesDisable).Count) { $dbInit['FeatureGatesDisable'] = @($FeatureGatesDisable) }
                        # Same list the host-side `access` step would have written.
                        $saList = @("$ManagerSuperAdmins" -split '[,;]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                        if ($saList.Count) { $dbInit['ManagerSuperAdmins'] = $saList }
                        if ("$($global:PIM_SqlAdminIdentityResourceId)".Trim()) { $dbInit['SqlAdminIdentityResourceId'] = "$($global:PIM_SqlAdminIdentityResourceId)".Trim() }
                        if ("$($global:PIM_SqlAdminIdentityClientId)".Trim())   { $dbInit['SqlAdminIdentityClientId']   = "$($global:PIM_SqlAdminIdentityClientId)".Trim() }
                        # 🔴 PUBLISHED *OR* RESOLVED -- AND "PREREQ IS CURRENT" IS THE COMMON CASE.
                        # The globals above are only set when prereq RUNS. Once an environment is
                        # fully built, prereq correctly reports current and is skipped, so a second
                        # deploy of an unchanged environment reached this throw:
                        #     the SQL admin identity was not published by the prereq step
                        # -- about a step the plan had just, correctly, called current. Measured at a
                        # customer 2026-09-11, on the very next run after the probe was taught to see
                        # the private-SQL artefacts. The pull identity had the identical defect and was
                        # fixed an hour earlier; fixing one half of a symmetry and not the other is how
                        # this class keeps coming back.
                        # 🪤 RESOLVED FROM AZURE, NEVER CONSTRUCTED FROM STRINGS. Building the client
                        # id would be impossible anyway, but even the resource id must be READ: handing
                        # the bootstrap job a well-formed id for an identity that does not exist turns
                        # this clear refusal into a container that starts and cannot authenticate.
                        if (-not $dbInit.ContainsKey('SqlAdminIdentityClientId') -and "$PrereqToken".Trim() -and "$ResourceGroup".Trim() -and (Have 'az')) {
                            $sqlIdName = "id-pim-sql-$PrereqToken"
                            $sqlIdRes  = az identity show @azSubArgs -g $ResourceGroup -n $sqlIdName --query id -o tsv 2>$null
                            $sqlIdCid  = az identity show @azSubArgs -g $ResourceGroup -n $sqlIdName --query clientId -o tsv 2>$null
                            if ("$sqlIdRes".Trim() -match '^/subscriptions/' -and "$sqlIdCid".Trim()) {
                                $dbInit['SqlAdminIdentityResourceId'] = "$sqlIdRes".Trim()
                                $dbInit['SqlAdminIdentityClientId']   = "$sqlIdCid".Trim()
                                Write-Host "    sql admin identity: $sqlIdName (resolved -- prereq was already current)" -ForegroundColor DarkGray
                            }
                        }
                        if (-not $dbInit.ContainsKey('SqlAdminIdentityClientId')) {
                            throw ('-SqlPrivateEndpoint is set, so the database users must be created from inside the ' +
                                   "environment -- but the SQL admin identity 'id-pim-sql-$PrereqToken' could not be found " +
                                   "in '$ResourceGroup', and prereq did not publish one. Run prereq in the same " +
                                   'invocation, or pass the identity explicitly. Refusing to create a bootstrap job ' +
                                   'that would authenticate as the wrong identity.')
                        }
                    }
                    $deployId = @{}
                    if ($AdminAppId -and ($AdminSecret -or $AdminCertPem)) {
                        $deployId['AdminAppId'] = $AdminAppId
                        if ($AdminCertPem) { $deployId['AdminCertPem'] = $AdminCertPem } else { $deployId['AdminSecret'] = $AdminSecret }
                    }
                    try {
                    & $setup @deployId -SubscriptionId $SubscriptionId -TenantId $TenantId -Location $Location `
                        -ResourceGroup $ResourceGroup -VnetName $VnetName -VnetResourceGroup $VnetResourceGroup `
                        @infraSubnet `
                        -EnvName $EnvName -AcrName $AcrName -ImageRepo $ImageRepo -ImageTag (Get-EffectiveImageTag) `
                        -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase `
                        -WorkerMode $WorkerMode -ManagerMinReplicas $ManagerMinReplicas -TickCron $TickCron `
                        -TickJobName $TickJobName -MailSender $MailSender `
                        -EngineClientId $EngineClientId -EngineCertThumbprint $EngineCertThumbprint -EngineClientSecret $EngineClientSecret `
                        -Exposure $Exposure `
                        @dbInit @ringGateArgs @pendingRingArgs -UpdateJobName $UpdateJobName `
                        -SqlAdminClientId $SqlAdminClientId @sqlAdminCred @registryIdentity @reach | Out-Host
                    } finally { Restore-PimCallerAzContext }
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
                # 🪤 Initialize-PimMailSender takes -MailboxName + -MailDomain, NOT -MailSender. Passing
                # the address straight through threw "A parameter cannot be found that matches parameter
                # name 'MailSender'" on EVERY deploy that supplied -MailSender (measured 2026-09-26, env 27).
                if ("$MailSender".Trim()) {
                    $mailParts = "$MailSender".Trim() -split '@', 2
                    if ($mailParts[0]) { $mailArgs['MailboxName'] = $mailParts[0] }
                    if ($mailParts.Count -eq 2 -and $mailParts[1]) { $mailArgs['MailDomain'] = $mailParts[1] }
                }
                # Without this the script THROWS on its own first line -- "one of -AdminSecret /
                # -AdminCertThumbprint is required" -- and this step's deliberate
                # non-fatality turned that into "MAIL SENDER NOT PROVISIONED" on every deploy,
                # which reads like an Exchange provisioning delay. It was a missing argument.
                # 🔴 SKIP, DO NOT INVOKE, WHEN THERE IS NO IDENTITY -- because -AdminAppId is a
                # MANDATORY parameter over there, and PowerShell's answer to a missing mandatory
                # parameter is to PROMPT:
                #     cmdlet Initialize-PimMailSender.ps1 at command pipeline position 1
                #     Supply values for the following parameters:
                #     AdminAppId:
                # An unattended deploy then waits there forever. Measured at a live customer
                # 2026-09-08: the deploy ran cleanly through the schema and stopped dead on a
                # prompt nobody was there to answer. A missing argument that THROWS is a bug; a
                # missing argument that PROMPTS is a hang, and a hang in a nightly job is
                # indistinguishable from a network outage until someone reads the console.
                if ($UseSignedInAccount) {
                    # 71.33 -- Initialize-PimMailSender provisions Exchange with an APPLICATION identity (app-only Exchange
                    # token, a directory role for that app). A signed-in user's az token carries no Exchange scope, so this
                    # step cannot run here. Loud and not fatal, exactly like the no-identity case below.
                    Warn 'mail sender: NOT RUN -- a signed-in deploy has no application identity, and Exchange provisioning needs one.'
                    Warn '  This environment is MAIL-MUTE until Initialize-PimMailSender.ps1 is run with an identity that holds Exchange Administrator,'
                    Warn '  or the shared sender mailbox + scoped send right are created by an Exchange administrator by hand.'
                    return @{ ok=$true; ran=$false; detail='DEGRADED: mail sender not run (signed-in deploy) -- environment is mail-mute' }
                }
                if (-not $storeAdminArgs.Count) {
                    Warn 'mail sender: SKIPPED -- no SQL admin identity was supplied, and this step cannot authenticate without one.'
                    Warn '  Pass -SqlAdminClientId with -SqlAdminCertThumbprint (or -SqlAdminClientSecret), or run Initialize-PimMailSender.ps1 yourself afterwards.'
                    Warn '  This environment is MAIL-MUTE until then: TAPs will be minted and delivered nowhere.'
                    return @{ ok=$true; ran=$false; detail='DEGRADED: mail sender skipped (no admin identity) -- environment is mail-mute' }
                }
                $mailArgs += $storeAdminArgs
                # -EngineAppId is the SPN that RECEIVES the scoped Mail.Send -- a different identity
                # from the admin that performs the grant, and without it the script gets as far as
                # resolving the sender and then stops:
                #   RESULT: FAILED -- no -EngineAppId, and no -KeyVaultName/-BootstrapAppId/
                #   -BootstrapThumbprint to read Modern-AppId from
                # Measured at a live customer 2026-09-08. The S1 driver's own 'mail' phase has
                # always passed it; this step, which does the same job inside the deploy, did not.
                # 🔴 AN MI-ONLY ENVIRONMENT HAS NO ENGINE APP REGISTRATION, AND THAT IS THE DESIGN.
                # -EngineClientId is legitimately empty there, so this warned and the step failed --
                # leaving the environment MAIL-MUTE, which looks like a working "create admin" right
                # up until the person never receives their TAP. The engine identity IS the Manager's
                # managed identity; infra resolved its appId while granting it SQL, and now publishes
                # it. Measured at a customer 2026-09-11.
                # 🪤 Resolve it here too, for the case where infra was SKIPPED as already-current --
                # the same gap that broke the pull identity and the SQL admin identity today. An
                # environment whose infra is up is exactly when this step still has work to do.
                $engineForMail = "$EngineClientId".Trim()
                if (-not $engineForMail) { $engineForMail = "$($global:PIM_ManagerMiAppId)".Trim() }
                if (-not $engineForMail -and "$ResourceGroup".Trim() -and (Have 'az')) {
                    $mgrOid = az containerapp show @azSubArgs -g $ResourceGroup -n $ManagerApp --query identity.principalId -o tsv 2>$null
                    if ("$mgrOid".Trim()) {
                        # BUG-215: tenant-pinned (az ad reads the DEFAULT account's directory).
                        $mgrApp = "$((Invoke-PimTenantGraphGet -Path "/servicePrincipals/$("$mgrOid".Trim())").appId)"
                        if ("$mgrApp".Trim() -match '^[0-9a-fA-F-]{36}$') {
                            $engineForMail = "$mgrApp".Trim()
                            Write-Host "    mail: scoping the send right to the Manager's managed identity $engineForMail (no engine app registration in this environment)" -ForegroundColor DarkGray
                        }
                    }
                }
                if ($engineForMail) { $mailArgs['EngineAppId'] = $engineForMail }
                # 🔒 REQUIREMENTS 65.11 (operator decision 2026-09-13): the HOSTED engine sends as its
                # MANAGED IDENTITY, so the scoped Exchange assignment must name that identity -- the tick
                # job's (engine mail: TAP delivery, reminders, alerts) and the Manager's (its alert
                # notices). Picked by the same rule the token call uses (PIM_ManagedIdentityClientId ->
                # that user-assigned identity, else system-assigned), in _PimMailSenderPlan.ps1.
                $mailMiOids = @()
                if ("$ResourceGroup".Trim() -and (Have 'az')) {
                    . (Join-Path $here '_PimMailSenderPlan.ps1')
                    $senderResources = @()
                    if ($WorkerMode -eq 'cron') { $senderResources += @{ what = "tick job '$TickJobName'"; json = (az containerapp job show @azSubArgs -g $ResourceGroup -n $TickJobName -o json 2>$null) } }
                    $senderResources += @{ what = "Manager '$ManagerApp'"; json = (az containerapp show @azSubArgs -g $ResourceGroup -n $ManagerApp -o json 2>$null) }
                    foreach ($res in $senderResources) {
                        if (-not "$($res.json)".Trim()) { continue }
                        $pick = $null
                        try { $pick = Get-PimJobManagedIdentityPrincipalId -Job ((@($res.json) -join "`n") | ConvertFrom-Json) } catch { $pick = $null }
                        if ($pick -and $pick.principalId) {
                            if ($mailMiOids -notcontains $pick.principalId) { $mailMiOids += $pick.principalId }
                            Write-Host "    mail: $($res.what) sends as its $($pick.kind)-assigned managed identity $($pick.principalId)" -ForegroundColor DarkGray
                        } elseif ($pick) { Warn "mail sender: $($res.what): $($pick.reason)" }
                    }
                }
                if ($mailMiOids.Count) { $mailArgs['ManagedIdentityObjectId'] = $mailMiOids }
                if (-not $engineForMail -and -not $mailMiOids.Count) { Warn 'mail sender: no engine identity could be resolved (no -EngineClientId, and neither the tick job nor the Manager has a managed identity) -- this step will not be able to finish.' }
                & $init @mailArgs | Out-Host
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                # 🪤 Not fatal to the deploy, and deliberately so: a tenant whose Exchange org is
                # still provisioning (the measured 'Substrate Only Agent' case) would otherwise
                # block infra that is otherwise fine. But it MUST be loud -- a silent mail-mute
                # environment is exactly the failure this step was added to end.
                # 🪤 §52.3 -- "once Exchange is ready" NAMES THE WRONG CAUSE, AND IT WAS MEASURED.
                # The live run failed with "could not assign Exchange Administrator to the onboarding
                # SPN: 403 (Forbidden)" -- the SPN cannot grant itself a directory role, and the
                # fallback (the signed-in az context) is the same SPN. That is a PERMISSION the
                # tenant has to grant once, not a provisioning delay that will clear on its own, so
                # an operator who believes this message waits for something that will never happen.
                if (-not $ok) {
                    Warn 'MAIL SENDER NOT PROVISIONED -- this environment is MAIL-MUTE: TAPs will be minted and delivered nowhere.'
                    Warn '  If the failure above was 403/Forbidden assigning "Exchange Administrator": an SPN cannot grant'
                    Warn '  itself a directory role. Have a Privileged Role Administrator assign Exchange Administrator to'
                    Warn '  the onboarding SPN once, then re-run Initialize-PimMailSender.ps1 -- it will NOT clear by waiting.'
                    Warn '  If it was a missing Exchange plan or a mailbox still provisioning, THAT one does clear -- re-run later.'
                }
                return @{ ok=$true; ran=$true; detail=$(if ($ok) { 'sender mailbox + send right ensured' } else { 'DEGRADED: mail sender not provisioned (see warning) -- deploy continued' }) }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'features' {
            # Onboarding step 8 (IMP-07). A disabled gate makes the engine a no-op that logs
            # ok=True, so this is the difference between "deployed" and "running".
            $fb = Join-Path $here 'Set-PimFeatureBaseline.ps1'
            if (-not (Test-Path $fb)) { return @{ ok=$false; ran=$true; detail="feature baseline not found: $fb" } }
            # 🔴 PRIVATE SQL: THIS HOST HAS NO ROUTE, AND THIS STEP HALTS THE DEPLOY.
            # The schema step above defers to the in-cloud bootstrap for exactly this reason; so
            # must this one. Measured at a customer 2026-09-11 -- the users and schema were created
            # in-cloud, the deploy walked past a DEGRADED mail sender, and then died here on
            #     could not read existing FeatureGates: ... A network-related or instance-specific
            #     error occurred while establishing a connection
            # which reads like a database problem and is a routing one. The gates are applied by the
            # bootstrap job, on the connection it already holds, and verified there before the
            # deploy was allowed past infra.
            if ($SqlPrivateEndpoint) {
                return @{ ok=$true; ran=$false; detail=(
                    'feature gates applied IN-CLOUD by the bootstrap job (private SQL -- this host has no route). ' +
                    'The job merged them over what was persisted and read them back before the deploy continued.') }
            }
            if ($PSCmdlet.ShouldProcess($SqlDatabase, 'turn the shipped feature gates ON')) {
                $global:LASTEXITCODE = 0
                if (-not $storeAdminArgs.Count) {
                    return @{ ok=$false; ran=$true; detail=(
                        "the feature baseline needs an identity that can write the store, and none was supplied. " +
                        "Pass -SqlAdminClientId with -SqlAdminCertThumbprint (or -SqlAdminClientSecret). Refusing " +
                        "rather than running a step that can only answer 'supply -AdminSecret or -AdminCertThumbprint'.") }
                }
                $why = Confirm-PimSignedInSqlAccess
                if ($why) { return @{ ok=$false; ran=$true; detail="features: $why" } }
                $fbGates = @{}
                if (@($FeatureGates).Count)        { $fbGates['Gates']   = @($FeatureGates) }
                if (@($FeatureGatesDisable).Count) { $fbGates['Disable'] = @($FeatureGatesDisable) }
                & $fb -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId @storeAdminArgs @fbGates | Out-Host
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                return @{ ok=$ok; ran=$true; detail='feature gates enabled + verified' }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'sqlaccess' {
            # §52.10. Always runs (no 'current' fact) -- see the catalog comment in PIM-DeployAll.ps1.
            $sqlNet = Join-Path $here 'Set-PimSqlNetworkAccess.ps1'
            if (-not (Test-Path $sqlNet)) { return @{ ok=$false; ran=$true; detail="SQL network-access script not found: $sqlNet" } }
            if ($SkipSqlNetworkAccess) {
                Warn 'SQL network access: SKIPPED (-SkipSqlNetworkAccess). Unless the store is reached over a private endpoint, the Manager will crash at boot being refused by the SQL firewall.'
                return @{ ok=$true; ran=$false; detail='skipped by -SkipSqlNetworkAccess' }
            }
            if (-not "$SqlServerFqdn".Trim()) { return @{ ok=$true; ran=$false; detail='no -SqlServerFqdn -- nothing to grant access to' }
            }
            if ($PSCmdlet.ShouldProcess($SqlServerFqdn, 'grant this environment network access to the SQL server')) {
                $global:LASTEXITCODE = 0
                # The subnet is READ FROM THE ACA ENVIRONMENT by the script itself; the parameter
                # trio is only its fallback. §38.1a is why: the subnet NAME has already been wrong
                # in this area once, and the environment is the only authority on its own subnet.
                $netArgs = @{ SubscriptionId = $SubscriptionId; SqlServerFqdn = $SqlServerFqdn
                              ResourceGroup = $ResourceGroup; EnvName = $EnvName; VnetName = $VnetName }
                if ("$VnetResourceGroup".Trim()) { $netArgs['VnetResourceGroup'] = $VnetResourceGroup }
                if ("$PrereqSubnetName".Trim())  { $netArgs['SubnetName']        = $PrereqSubnetName }
                if ("$SqlSubscriptionId".Trim()) { $netArgs['SqlSubscriptionId'] = $SqlSubscriptionId }
                # 🔴 READ THE RESULT OBJECT, NOT $LASTEXITCODE. This script's job is a series of
                # az PROBES -- `vnet-rule show` on a rule that does not exist yet exits NON-ZERO by
                # design, and so does `firewall-rule show`. Judging the step by the last exit code
                # would therefore fail a step that did its work perfectly, halt the deploy, and
                # roll back a good build. The script returns { ok; vnetRule; firewallRule; reason },
                # which is the actual verdict.
                # 🪤 Same class as §51.2: ask for the fact, do not infer it from a side channel.
                $netRes = & $sqlNet @netArgs 4>&1 5>&1 | ForEach-Object {
                    if ($_ -is [System.Collections.IDictionary] -and $_.Contains('ok')) { $_ } else { $_ | Out-Host }
                } | Select-Object -Last 1
                $global:LASTEXITCODE = 0
                if (-not $netRes) { return @{ ok=$false; ran=$true; detail='SQL network access: the step returned no verdict' } }
                $detail = "vnet-rule=$($netRes.vnetRule) firewall=$($netRes.firewallRule) endpoint=$($netRes.serviceEndpoint)"
                # A store this deploy cannot SEE (central/shared, another subscription) is not a
                # failure -- nothing tried to configure it before this step existed either. Halting
                # here would invent a new failure mode for a topology that works.
                if ($netRes.notApplicable) {
                    Warn "SQL network access: NOT CONFIGURED -- $($netRes.reason)."
                    Warn '  If the Manager cannot reach the store, add a VNet rule for its subnet on that server yourself.'
                    return @{ ok=$true; ran=$false; detail="not applicable: $($netRes.reason)" }
                }
                if (-not $netRes.ok) {
                    return @{ ok=$false; ran=$true; detail=(
                        "nothing grants this environment network access to $SqlServerFqdn ($detail). The Manager " +
                        "WILL crash at boot being refused by the SQL firewall. The deploy identity needs SQL Server " +
                        "Contributor on the server's resource group, or pass -SkipSqlNetworkAccess for a " +
                        "private-endpoint store. $($netRes.reason)") }
                }
                return @{ ok=$true; ran=$true; detail="SQL network access ensured + verified ($detail)" }
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
                # 🔴 WITH A PRIVATE SQL SERVER THIS HOST CANNOT APPLY THE SCHEMA, AND MUST NOT TRY.
                # -SqlPrivateEndpoint means the server has no public endpoint, so the connection
                # below cannot be opened from here at all -- it hangs for the connect timeout and
                # then fails in a way that reads like a credential problem. The INFRA step above
                # already applied the shipped schema from INSIDE the environment, on the same
                # bootstrap job that created the contained users (PIM_DBINIT_SCHEMA), and that job's
                # result GATES the deploy -- so by the time this step is reached the store is either
                # created and verified, or the deploy has already stopped.
                # 🪤 This is a SKIP, not a silent pass: say which component owns the work, because a
                # step that prints nothing is indistinguishable from a step that did nothing (the
                # BUG-50 lesson this very step exists to carry).
                if ($SqlPrivateEndpoint) {
                    return @{ ok=$true; ran=$false; detail=(
                        'schema applied IN-CLOUD by the bootstrap job (private SQL -- this host has no route). ' +
                        'The job verified the pim schema before the deploy was allowed to continue.') }
                }
                if (-not "$SqlConnectionString".Trim()) {
                    if ($hosted) {
                        return @{ ok=$false; ran=$true; detail=(
                            "no -SqlConnectionString, so the SQL schema CANNOT be applied -- the updater would only " +
                            "PRINT the DDL while reporting success. Pass -SqlConnectionString for " +
                            "$SqlServerFqdn/$SqlDatabase, or apply sql/platform-schema.sql " +
                            "with your SQL deploy identity. Refusing to report a schema upgrade that did not happen.") }
                    }
                    Write-Host "  schema: no -SqlConnectionString and not hosted -- DDL plan only." -ForegroundColor Yellow
                }
                # 🔴 THE CONNECTION STRING WITHOUT THE IDENTITY IS HALF A PASSTHROUGH.
                # Azure SQL here is Entra-only, so the string deliberately carries no credential --
                # the updater has to mint a token, and until this splat existed it had nothing to
                # mint one WITH on a deploy host. The infra step above sets this very identity as
                # the server's Entra admin, then this step opened the connection as nobody:
                # "Login failed for user ''", measured at a live customer 2026-09-08 on the first
                # deploy that ever got this far. The same missing-passthrough class as -AcrName and
                # -Apps above -- third time in this one step.
                # 🔴 §52.12 -- -SchemaOnly. Without it this step ran the updater's WHOLE
                # detect->build->deploy chain: it BUILT the image and ROLLED the apps, and then the
                # `code` step below did both again. One deploy, THREE builds of identical source and
                # TWO rolls of the same version -- about four minutes wasted on every deploy,
                # measured at a live customer 2026-09-09. -AcrName/-Apps stay because the updater
                # still validates them, but they are no longer feeding a build that should not run.
                $why = Confirm-PimSignedInSqlAccess
                if ($why) { return @{ ok=$false; ran=$true; detail="schema: $why" } }
                & $upd -Source $Source @scenarioArgs -Apply -SqlConnectionString $SqlConnectionString `
                    -ResourceGroup $ResourceGroup -ManagerApp $ManagerApp -ImageTag (Get-EffectiveImageTag) `
                    -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps @sqlAuthArgs `
                    -SchemaOnly -SkipVerify -SkipNotify | Out-Host
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                return @{ ok=$ok; ran=$true; detail='schema upgrade applied (preflight->apply->re-preflight)' }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'easyauth' {
            # §44.5 / §47.3. Fatal on a hosted deploy, deliberately: the alternative is finishing
            # "successfully" with an unauthenticated privileged-access console on the public
            # internet, which is the failure this step exists to make impossible. -EasyAuthClientId
            # lets an operator front it with a registration they already control instead.
            $ea = Join-Path $here 'Set-PimManagerEasyAuth.ps1'
            if (-not (Test-Path $ea)) { return @{ ok=$false; ran=$true; detail="Easy Auth setup not found: $ea" } }
            if ($PSCmdlet.ShouldProcess($ManagerApp, 'put Easy Auth in front of the Manager')) {
                $global:LASTEXITCODE = 0
                $eaArgs = @{ App = $ManagerApp; ResourceGroup = $ResourceGroup; TenantId = $TenantId }
                if ("$SubscriptionId".Trim())      { $eaArgs['SubscriptionId'] = $SubscriptionId }
                if ("$EasyAuthClientId".Trim())    { $eaArgs['ClientId']       = $EasyAuthClientId }
                if ($EasyAuthAllowedPrincipals.Count) { $eaArgs['AllowedPrincipals'] = @($EasyAuthAllowedPrincipals) }
                if ($EasyAuthAllowAllTenantUsers)     { $eaArgs['AllowAllTenantUsers'] = $true }
                # 🪤 A THROW IS A FAILURE TOO. Set-PimManagerEasyAuth reports most refusals by throwing, and
                # an unhandled throw here escaped the runner before the Manager could be closed below.
                $eaWhy = ''
                try { & $ea @eaArgs | Out-Host } catch { $eaWhy = "$($_.Exception.Message)" }
                $ok = (-not $eaWhy) -and ((-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0))
                if (-not $ok) {
                    # 🔴 SEC-31 -- LEAVE IT CLOSED, AND SAY WHICH. A NEW Manager still carries the closing
                    # restriction (only a successful run of that script removes it). A Manager with NO Easy
                    # Auth in front of it (an environment built before this safeguard) is closed NOW. One
                    # that already had Easy Auth keeps serving behind it: closing a working, protected
                    # console over a failed re-run (a transient consent read, say) would be an outage.
                    $closed = Close-PimManagerAfterEasyAuthFailure -EaScript $ea -EaArgs $eaArgs
                    return @{ ok=$false; ran=$true; detail=(
                        "Easy Auth could not be configured$(if ($eaWhy) { ": $eaWhy" } else { '' }). $closed " +
                        'This halts the deploy rather than leaving a privileged console open. Re-run, or pass ' +
                        '-EasyAuthClientId to use an app registration you already control.') }
                }
                return @{ ok=$true; ran=$true; detail='Easy Auth configured + verified (sign-in required and restricted), then the Manager was opened' }
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
                # 🪤 THE AGENT POOL, or this rebuild is refused by the registry's own firewall while
                # the deploy's `image` step (which DOES pass it) succeeded minutes earlier on the
                # very same source. Splatted so an environment without a pool is unaffected.
                $whyC = Confirm-PimSignedInSqlAccess
                if ($whyC) { return @{ ok=$false; ran=$true; detail="code: $whyC" } }
                $updPool = @{}
                if ("$AcrAgentPoolName".Trim()) { $updPool['AcrAgentPool'] = "$AcrAgentPoolName".Trim() }
                # Invoke-PimUpdate expresses the gate opt-out as -SkipVerify (it maps it onto the
                # roller's -SkipSmoke). Say it loudly here too: the deploy summary is what an
                # operator reads, and a gate that did not run must not look like one that passed.
                if ($SkipHostedSmoke) {
                    $updPool['SkipVerify'] = $true
                    Warn '  -SkipHostedSmoke: the post-deploy GUI smoke gate will NOT run. This is NOT a pass --'
                    Warn '  nothing has confirmed the hosted Manager actually works. Verify it from inside the VNet.'
                }
                & $upd -Source $Source @scenarioArgs -Apply -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo `
                    -ManagerApp $ManagerApp -Apps $Apps -ImageTag (Get-EffectiveImageTag) -TickJobName $TickJobName `
                    -SqlConnectionString $SqlConnectionString @sqlAuthArgs @updPool @ringGateArgs @pendingRingArgs -UpdateJobName $UpdateJobName -SkipNotify | Out-Host
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                return @{ ok=$ok; ran=$true; detail='code built + deployed' }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'updater' {
            # §53. Installs the nightly Container Apps Job that rolls this environment. Runs after
            # `code`, so the image it points at is the one just built.
            $upj = Join-Path $here 'Deploy-PimUpdateJob.ps1'
            if (-not (Test-Path $upj)) { return @{ ok=$false; ran=$true; detail="update-job deployer not found: $upj" } }
            # BUG-156: decided by the pure core, so a community install without a feed skips
            # cleanly instead of failing the step and rolling back a working environment.
            switch (Get-PimUpdaterStepDecision -Scenario "$Scenario" -SourceUrlTemplate "$UpdateSourceUrlTemplate" -SkipUpdater:$SkipUpdater) {
                'skip-flag'      { return @{ ok=$true; ran=$false; detail='skipped by -SkipUpdater -- this environment will NOT update itself' } }
                'skip-community' { return @{ ok=$true; ran=$false; detail="community edition ($Scenario): no published update feed, so no in-cloud updater -- update with tools\setup\Update-PimCommunity.ps1 -Apply (it runs 'git pull' and re-runs this same command with the parameters saved by this deploy -- a re-run is the updater)" } }
            }
            if (-not "$AcrName".Trim() -or -not "$EnvName".Trim()) {
                return @{ ok=$true; ran=$false; detail='no -AcrName/-EnvName -- nightly updater not installed (environment will not update itself)' }
            }
            if ($PSCmdlet.ShouldProcess($UpdateJobName, 'install the nightly updater job')) {
                $global:LASTEXITCODE = 0
                $tag = Get-EffectiveImageTag
                $upArgs = @{ SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup; EnvName = $EnvName
                             AcrName = $AcrName; ImageRepo = $ImageRepo; ImageTag = $tag
                             JobName = $UpdateJobName; ManagerApp = $ManagerApp; TickJobName = $TickJobName
                             Cron = $UpdateCron }
                # Without this the nightly build is refused by a private registry's firewall -- the
                # one failure in this deploy that nobody would be awake to see.
                if ("$AcrAgentPoolName".Trim()) { $upArgs['AcrAgentPoolName'] = "$AcrAgentPoolName".Trim() }
                # The environment it was just deployed to IS the approved target until an operator
                # publishes a newer one, so the job starts armed and consistent rather than idle.
                $upArgs['TargetImage'] = "$AcrName.azurecr.io/$ImageRepo" + ':' + $tag
                # 🔴 §55 -- WITHOUT A SOURCE, A NEW DEPLOYMENT INSTALLS A ROLLER, NOT AN UPDATER.
                # 🔒 2026-09-13: and a ring without a source is a ring the updater IGNORES. Deploy-
                # PimUpdateJob now REFUSES that (it resolves -SourceUrlTemplate, then
                # $env:PIM_UPDATE_SOURCE_URL, then the source the job already carries) -- the old
                # "degrade to a roller" branch is gone, because a roller does not honour a ring.
                if ("$UpdateSourceUrlTemplate".Trim()) { $upArgs['SourceUrlTemplate'] = "$UpdateSourceUrlTemplate".Trim() }
                $upArgs['TargetVersion']    = $tag
                # This deploy just rolled the environment onto $tag, so that IS what it last built: its
                # first nightly run rolls instead of rebuilding the same version.
                $upArgs['LastBuiltVersion'] = $tag
                # Forwarded ONLY when the operator passed it: an unpassed -UpdateRing must not overwrite
                # the ring an existing environment already follows.
                # BUG-162: read the SCRIPT-scope answer. $PSBoundParameters here is this FUNCTION's, and
                # it can never contain UpdateRing -- see the capture at the top of this file.
                if ($script:PimDeployRingExplicit) { $upArgs['UpdateRing'] = $UpdateRing }
                if ("$RegistryIdentityResourceId".Trim()) { $upArgs['RegistryIdentityResourceId'] = $RegistryIdentityResourceId }
                # 2026-09-13 -- the updater copies the Manager's PIM_SqlServer / PIM_SqlDatabase, and its
                # identity needs a contained database user for the schema step: the same SQL-admin SPN
                # and the same private-SQL route (the in-cloud bootstrap job) the INFRA step uses.
                if ("$TenantId".Trim())               { $upArgs['TenantId']               = "$TenantId".Trim() }
                if ("$SqlAdminClientId".Trim())       { $upArgs['SqlAdminClientId']       = "$SqlAdminClientId".Trim() }
                if ("$SqlAdminCertThumbprint".Trim()) { $upArgs['SqlAdminCertThumbprint'] = "$SqlAdminCertThumbprint".Trim() }
                elseif ("$SqlAdminClientSecret".Trim()) { $upArgs['SqlAdminClientSecret'] = $SqlAdminClientSecret }
                if ($UseSignedInAccount) {
                    $upArgs['UseSignedInAccount'] = $true
                    $why = Confirm-PimSignedInSqlAccess
                    if ($why) { return @{ ok=$false; ran=$true; detail="updater: $why" } }
                }
                if ($SqlPrivateEndpoint)              { $upArgs['SqlPrivate']             = $true }
                if ("$DbInitJobName".Trim())          { $upArgs['DbInitJobName']          = "$DbInitJobName".Trim() }
                try { & $upj @upArgs | Out-Host }
                catch { return @{ ok=$false; ran=$true; detail="nightly updater NOT installed: $($_.Exception.Message)" } }
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                $ringTxt = if ($script:PimDeployRingExplicit) { "ring $UpdateRing (as configured)" } else { 'ring kept (or the DEFAULT ring 2 on a new updater -- pass -UpdateRing to decide it)' }
                return @{ ok=$ok; ran=$true; detail="nightly updater '$UpdateJobName' installed ($UpdateCron UTC) -- builds its own images, $ringTxt" }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'access' {
            # §57 -- the environment must have somebody who can administer it.
            $acc = Join-Path $here 'Set-PimManagerAccess.ps1'
            if (-not (Test-Path $acc)) { return @{ ok=$false; ran=$true; detail="manager-access tool not found: $acc" } }
            $who = @("$ManagerSuperAdmins" -split '[,;]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if (-not $who.Count) {
                # 🪤 NOT AN ERROR, AND NOT SILENCE. An operator who did not name one gets an
                # environment that fails closed -- which is correct security and a terrible
                # surprise. Say exactly what to run, rather than leaving it to be discovered as a
                # 403 in the GUI later.
                return @{ ok=$true; ran=$false; detail=("no -ManagerSuperAdmins given -- NOBODY can administer this environment yet. " +
                          "Grant one with tools/setup/Set-PimManagerAccess.ps1 -AccessJson '{`"managerAccess`":[{`"identity`":`"<upn>`",`"role`":`"SuperAdmin`"}]}'") }
            }
            if (-not "$SqlServerFqdn".Trim()) { return @{ ok=$true; ran=$false; detail='no -SqlServerFqdn -- manager access not written' } }
            # 🔴 PRIVATE SQL -- THIS HOST HAS NO ROUTE, and "not applied" here means nobody can
            # administer the environment at all. Fourth step in this deploy to need moving inside,
            # after the users, the schema and the feature gates; the bootstrap job wrote it on the
            # connection it already holds, refused to leave the model without a SuperAdmin, and read
            # it back before the deploy was allowed past infra.
            # 🔴 AND IT MUST VERIFY THAT, NOT ASSERT IT. This used to return "applied IN-CLOUD by the
            # bootstrap job" unconditionally -- a claim about a DIFFERENT component, made without
            # looking. The bootstrap job only runs inside INFRA, and INFRA is correctly skipped the
            # moment an environment is converged, so on every re-run this step reported success while
            # nothing wrote anything. Measured at a customer 2026-09-12: the deploy said
            #     -> ok=True ran=False Manager SuperAdmin applied IN-CLOUD by the bootstrap job
            # and the job did not even CARRY the list (PIM_DBINIT_MANAGER_ACCESS was unset, last run
            # predating the feature). The operator signed in and had no SuperAdmin -- on an
            # environment whose deploy had just reported success end to end.
            # 🔑 "Another component did it" is the one claim a step can never make from the outside.
            # Read the job back: if it carries the CURRENT list, say so; if it does not, say plainly
            # that access has NOT been applied and how to apply it, rather than reporting success.
            if ($SqlPrivateEndpoint) {
                $jobHasIt = $false
                if ((Have 'az') -and "$ResourceGroup".Trim()) {
                    $jobEnv = az containerapp job show @azSubArgs -g $ResourceGroup -n $DbInitJobName `
                                --query "properties.template.containers[0].env[?name=='PIM_DBINIT_MANAGER_ACCESS'].value" -o tsv 2>$null
                    if ("$jobEnv".Trim()) {
                        $parsed = $null
                        try { $parsed = "$jobEnv".Trim() | ConvertFrom-Json } catch { }
                        # 🪤 PARSE IT. A value mangled by cmd.exe quote-stripping is present and
                        # useless -- the job dies in ConvertFrom-Json and the deploy would still have
                        # called it applied. Measured the same day, twice.
                        if ($parsed) {
                            $have = @(@($parsed) | ForEach-Object { "$($_.identity)".Trim().ToLowerInvariant() } | Where-Object { $_ })
                            $want = @($who | ForEach-Object { "$_".Trim().ToLowerInvariant() })
                            $missing = @($want | Where-Object { $have -notcontains $_ })
                            $jobHasIt = (-not $missing.Count)
                        }
                    }
                }
                if ($jobHasIt) {
                    return @{ ok=$true; ran=$false; detail=(
                        "Manager SuperAdmin applied IN-CLOUD by the bootstrap job, verified on the job (private SQL -- this host has no route): " +
                        ($who -join ', ')) }
                }
                return @{ ok=$false; ran=$true; detail=(
                    "Manager access has NOT been applied. SQL is private so this host cannot write it, and the " +
                    "bootstrap job '$DbInitJobName' does not carry the current SuperAdmin list -- so NOBODY can " +
                    "administer this environment. Re-run with the INFRA step (it stamps the list onto the job and " +
                    "runs it), or set PIM_DBINIT_MANAGER_ACCESS on that job and start it.") }
            }
            if (-not "$SqlAdminClientId".Trim() -and -not $UseSignedInAccount) {
                return @{ ok=$true; ran=$false; detail='no -SqlAdminClientId -- cannot write pim.Settings ManagerAccess; grant it by hand' }
            }
            $json = '{"managerAccess":[' + (($who | ForEach-Object { '{"identity":"' + $_ + '","role":"SuperAdmin"}' }) -join ',') + ']}'
            if ($PSCmdlet.ShouldProcess(($who -join ', '), 'grant Manager SuperAdmin')) {
                $global:LASTEXITCODE = 0
                if ($UseSignedInAccount) {
                    $whyA = Confirm-PimSignedInSqlAccess
                    if ($whyA) { return @{ ok=$false; ran=$true; detail="access: $whyA" } }
                    $accArgs = @{ TenantId = $TenantId; SqlServerFqdn = $SqlServerFqdn; SqlDatabase = $SqlDatabase; UseSignedInAccount = $true; AccessJson = $json }
                } else {
                $accArgs = @{ TenantId = $TenantId; SqlServerFqdn = $SqlServerFqdn; SqlDatabase = $SqlDatabase
                              AdminAppId = $SqlAdminClientId; AccessJson = $json }
                if ("$SqlAdminCertThumbprint".Trim()) { $accArgs['AdminCertThumbprint'] = $SqlAdminCertThumbprint }
                elseif ("$SqlAdminClientSecret".Trim()) { $accArgs['AdminSecret'] = $SqlAdminClientSecret }
                }
                & $acc @accArgs | Out-Host
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                return @{ ok=$ok; ran=$true; detail="Manager SuperAdmin: $($who -join ', ')" }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'verify' {
            return (Invoke-DeployValidation)
        }
    }
    return @{ ok=$false; ran=$true; detail="unknown step '$Key'" }
}


# ---- §79.11 COMMUNITY VERIFY -- the check a PUBLIC install can run ------------------------------
# The public edition ships without tests/ (SEC-20), so the hosted smoke and the deploy-validation tests do not exist
# there. The verify step then had NOTHING to run and -- "a skip is not a pass" -- reported every community install as
# FAILED (env 10 proof, 2026-09-25). This small check ships with the product instead: the Manager app is provisioned and
# its latest revision is the ready one, the page is SERVED (Entra sign-in answers 401/302 -- never a 5xx or no answer),
# and the engine's tick job exists. It proves the install came up; it is not the full smoke, and says so.
function Get-PimCommunityVerifyVerdict {
    # PURE. -Facts: @{ appState; latestRevision; readyRevision; httpStatus (int, 0 = no answer); tickState }.
    # Returns @{ exit (0 pass / 1 fail); checks = [ @{ name; ok; detail } ] }.
    param([Parameter(Mandatory)][hashtable]$Facts)
    $c = New-Object System.Collections.Generic.List[object]
    $add = { param($n, $ok, $d) $c.Add([pscustomobject]@{ name = $n; ok = [bool]$ok; detail = $d }) | Out-Null }
    & $add 'manager provisioned' ("$($Facts.appState)" -eq 'Succeeded') "provisioningState=$($Facts.appState)"
    & $add 'latest revision is ready' ("$($Facts.latestRevision)".Trim() -and "$($Facts.latestRevision)" -eq "$($Facts.readyRevision)") "latest=$($Facts.latestRevision) ready=$($Facts.readyRevision)"
    $h = [int]$Facts.httpStatus
    & $add 'page served behind sign-in' ($h -in @(200, 302, 401, 403)) $(if ($h) { "HTTP $h" } else { 'no answer' })
    & $add 'engine tick job exists' ("$($Facts.tickState)" -eq 'Succeeded') "provisioningState=$($Facts.tickState)"
    return @{ exit = $(if (@($c | Where-Object { -not $_.ok }).Count) { 1 } else { 0 }); checks = @($c.ToArray()) }
}
function Invoke-PimCommunityVerify {
    $f = @{ appState = ''; latestRevision = ''; readyRevision = ''; httpStatus = 0; tickState = '' }
    try {
        $app = az containerapp show @azSubArgs -g $ResourceGroup -n $ManagerApp -o json 2>$null | ConvertFrom-Json
        if ($app) {
            $f.appState = "$($app.properties.provisioningState)"; $f.latestRevision = "$($app.properties.latestRevisionName)"; $f.readyRevision = "$($app.properties.latestReadyRevisionName)"
            $fqdn = "$($app.properties.configuration.ingress.fqdn)".Trim()
            if ($fqdn) {
                # min replicas 0: the first request wakes the app -- give it up to ~3 minutes.
                # HttpClient with redirects OFF: pwsh 7.6's Invoke-WebRequest -MaximumRedirection 0 THROWS on the very 302
                # that proves the sign-in is there ("Operation is not valid due to the current state of the object").
                $h = New-Object System.Net.Http.HttpClientHandler; $h.AllowAutoRedirect = $false
                $hc = New-Object System.Net.Http.HttpClient($h); $hc.Timeout = [TimeSpan]::FromSeconds(60)
                try {
                    for ($i = 0; $i -lt 12 -and -not $f.httpStatus; $i++) {
                        try {
                            $code = [int]$hc.GetAsync("https://$fqdn/").GetAwaiter().GetResult().StatusCode
                            if ($code -ge 500) { Start-Sleep -Seconds 15 } else { $f.httpStatus = $code }
                        } catch { Start-Sleep -Seconds 15 }
                    }
                } finally { $hc.Dispose() }
            }
        }
    } catch { }
    try { $f.tickState = "$(az containerapp job show @azSubArgs -g $ResourceGroup -n $TickJobName --query properties.provisioningState -o tsv 2>$null)".Trim() } catch { }
    $global:LASTEXITCODE = 0
    $v = Get-PimCommunityVerifyVerdict -Facts $f
    foreach ($ch in $v.checks) { if ($ch.ok) { Info "verify (community): PASS $($ch.name) -- $($ch.detail)" } else { Warn "verify (community): FAIL $($ch.name) -- $($ch.detail)" } }
    return $v.exit
}

# ---- VERIFY: hosted smoke + deploy-validation tests (the test-tenant validation) ----
$script:smokeExit = 0
$script:validationExit = 0
function Invoke-DeployValidation {
    $smokeExit = -1; $valExit = -1            # -1 = did not run (self-skip), not a fail
    $smoke = Join-Path $solRoot 'tests\live\Test-PimManagerHostedSmoke.ps1'
    # 🔴 -SkipHostedSmoke MUST REACH HERE TOO. It was wired only into the `code` step's updater, so
    # a deploy that correctly skipped the gate mid-flight then ran it again at the END and rolled
    # the whole environment back -- an opt-out that half-worked is worse than none, because the
    # deploy gets all the way to the last step before failing. Measured at a customer 2026-09-11.
    # 🪤 It suppresses the SMOKE ONLY. The deploy-validation tests below do not need a route to the
    # Manager, so they still run and still count: skipping what cannot run must not become skipping
    # what can.
    if ($SkipHostedSmoke) {
        Warn 'verify: hosted smoke SKIPPED by -SkipHostedSmoke -- this is NOT a pass. Nothing has'
        Warn '  confirmed the hosted Manager works; verify it from inside the VNet or a peered client.'
        $smokeExit = -1
    }
    elseif ($hosted -and (Test-Path $smoke)) {
        Info 'verify: hosted smoke (Test-PimManagerHostedSmoke.ps1)'
        if ($PSCmdlet.ShouldProcess($ManagerApp, 'run hosted smoke')) {
            # 🔴 THE GATE WAS GIVEN THE APP AND NOTHING ELSE, AND THEN BELIEVED.
            # The smoke takes its evidence from TWO places: the app's boot logs in Log Analytics
            # (which is where "[store] SQL mode" -- the assertion that matters most -- can be
            # read at all) and live HTTP behind Easy Auth. Both need inputs this step held and
            # did not pass: the workspace id, the subscription, the Easy Auth audience. Without
            # them the smoke SELF-SKIPS those layers and exits 0, and `$smokeExit -le 0` below
            # reads that as a pass. So `verify ok=True` could mean "everything checked out" or
            # "nothing was checked", with no way to tell them apart -- which is precisely the
            # §7a rule ("a skip is not a pass") being broken by the step that enforces it.
            # Update-PimContainers already forwards all of this to the same script (DOC-06(b));
            # this step, the one whose verdict decides the deploy, did not.
            $env:PIM_HOSTED_APP = $ManagerApp
            if ("$ResourceGroup".Trim())   { $env:PIM_HOSTED_RG = $ResourceGroup }
            if ("$SubscriptionId".Trim())  { $env:PIM_SUBSCRIPTION_ID = $SubscriptionId }
            if ("$LogAnalyticsWorkspaceId".Trim()) { $env:PIM_HOSTED_LA_WORKSPACE = $LogAnalyticsWorkspaceId }
            # 🔴 §52.13b -- DERIVE WHAT THE ROLLER ALREADY DERIVES, instead of running blind.
            # This step warned "the smoke will run PARTIALLY BLIND -- live HTTP (no
            # -EasyAuthAudience): the served page CANNOT be checked" on the live run, while
            # Update-PimContainers' own gate, minutes earlier, had derived that audience from the
            # app's own auth config and checked the served page with it. The FINAL verdict was
            # therefore weaker than the gate that ran inside the roll -- the same DOC-06(b) shape
            # as §44.3: this step, whose result decides the deploy, was given less than its
            # sibling. Ask the app, exactly as the roller does.
            if (-not "$EasyAuthAudience".Trim() -and $hosted -and "$ResourceGroup".Trim()) {
                try {
                    $derivedAud = @(az containerapp auth show -n $ManagerApp -g $ResourceGroup @azSubArgs `
                                      --query "identityProviders.azureActiveDirectory.validation.allowedAudiences" -o tsv 2>$null) |
                                  Where-Object { "$_".Trim() } | Select-Object -First 1
                    if ("$derivedAud".Trim()) {
                        $EasyAuthAudience = "$derivedAud".Trim()
                        Info "verify: derived the Easy Auth audience from the app's own auth config"
                    }
                } catch { }
            }
            if ("$EasyAuthAudience".Trim()) { $env:PIM_HOSTED_EASYAUTH_AUD = $EasyAuthAudience }
            # What it could NOT be given is named out loud, so a skip is visible as a gap in
            # coverage rather than disguised as a clean run.
            $blind = @()
            # 🪤 NOT BLIND JUST BECAUSE THE CALLER DID NOT PASS IT. The gate DERIVES the workspace
            # from the Container Apps environment itself -- it prints "workspace derived from the
            # Container Apps environment (authoritative)" and then checks all six boot-log
            # assertions. Warning "render mode SQL-vs-static CANNOT be checked" immediately before
            # the run that checks it is simply false, and a false warning on every deploy is how
            # the true one gets ignored. Only claim blindness when the environment cannot answer.
            $envSubnetProbe = ''
            if (-not "$LogAnalyticsWorkspaceId".Trim() -and $hosted -and "$ResourceGroup".Trim()) {
                try {
                    $envId = az containerapp show @azSubArgs -n $ManagerApp -g $ResourceGroup --query properties.environmentId -o tsv 2>$null
                    if ("$envId".Trim()) {
                        $envSubnetProbe = "$(az containerapp env show @azSubArgs --ids "$("$envId".Trim())" --query properties.appLogsConfiguration.logAnalyticsConfiguration.customerId -o tsv 2>$null)".Trim()
                    }
                } catch { }
            }
            if (-not "$LogAnalyticsWorkspaceId".Trim() -and -not $envSubnetProbe) { $blind += 'boot-log evidence: no -LogAnalyticsWorkspaceId and the environment does not name a workspace, so render mode SQL-vs-static CANNOT be checked' }
            if (-not "$EasyAuthAudience".Trim())        { $blind += 'live HTTP (no -EasyAuthAudience): the served page CANNOT be checked' }
            if ($blind.Count) {
                Warn 'verify: the smoke will run PARTIALLY BLIND --'
                $blind | ForEach-Object { Warn "  - $_" }
                Warn '  A pass from a partially-blind gate is not evidence the GUI works.'
            }
            # BUG-25: `| Out-Host` -- a native child's stdout is SUCCESS-stream output too, so
            # without it the smoke's console text becomes part of this function's return value.
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $smoke | Out-Host
            $smokeExit = $LASTEXITCODE
            # BUG-216: the smoke's contract is 0 = passed, 1 = failed, 2 = SKIPPED checks (not a pass).
            if ($smokeExit -eq 2) { Warn 'verify: the hosted smoke SKIPPED checks (exit 2) -- UNVERIFIED, not a pass; nothing is rolled back for it.' }
        }
    } elseif ($hosted -and -not (Test-Path $smoke) -and (Have 'az') -and "$ResourceGroup".Trim()) {
        # §79.11: the public edition (no tests/) -- run the check that ships with it, as the smoke layer.
        Info 'verify: the hosted smoke is not part of this edition -- running the community verify (Manager up, page served, engine job present)'
        if ($PSCmdlet.ShouldProcess($ManagerApp, 'community verify')) { $smokeExit = Invoke-PimCommunityVerify }
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
            # 🔴 §52.13 -- A WRONG PESTER VERSION ROLLED BACK A VERIFIED-GOOD DEPLOYMENT.
            # `-Output Minimal` is Pester 5 syntax. On the Pester 3.x that ships with Windows it is
            # ambiguous (-OutputXml / -OutputFile / -OutputFormat), so the call THREW, the catch
            # below set validation=1, `verify` failed, and the deploy tried to roll back a Manager
            # whose GUI smoke gate had just passed 11/0. Measured at a live customer 2026-09-09.
            # It only did no damage by luck: the prior revision had already been purged, so the
            # rollback found nothing to activate. Had it succeeded it would have put the customer
            # back on the revision that could not reach SQL.
            # 🪤 A TEST RUNNER THAT CANNOT START IS NOT A FAILING TEST. The catch made "Pester is
            # the wrong version on this host" indistinguishable from "the deployed system is
            # broken", and only one of those should ever trigger a rollback. -1 means "did not
            # run", which the verdict below already treats as UNVERIFIED rather than failed --
            # loudly, because an unverified deploy still is not a verified one (§7a).
            $pesterMajor = 0
            try { $pesterMajor = [int](@(Get-Module -ListAvailable Pester | Sort-Object Version -Descending | Select-Object -First 1).Version.Major) } catch { }
            # 🪤 THE FIRST FIX FOR THIS CHANGED THE PARAMETERS AND MISSED THE REAL CONSTRAINT.
            # It detected Pester 3 and called it with 3.x-safe arguments -- and the call then ran
            # and FAILED, because the TEST FILE is Pester 5 (`BeforeDiscovery`), which Pester 3
            # cannot even parse:
            #     CommandNotFoundException: The term 'BeforeDiscovery' is not recognized
            #     Passed: 0 Failed: 1   ->  validation=1  ->  ROLLBACK
            # So the second attempt rolled back a verified-good deployment for exactly the reason
            # the first one did. Measured at a live customer 2026-09-09, twice in one morning.
            # 🔑 The constraint is not "which arguments does this Pester accept", it is "can this
            # Pester run THESE TESTS AT ALL". Pester 5 or the layer does not run -- and not running
            # is UNVERIFIED, never a deployment failure.
            # 🔴 THE TESTS NEED AN IDENTITY TO QUERY LIVE PIM, AND THIS STEP NEVER GAVE THEM ONE.
            #     RuntimeException: Tenant identity not set (PIM_TenantId + PIM_ClientId/cert)
            #     -- cannot query live PIM.
            # They read it from the ENVIRONMENT (PIM_TenantId / PIM_ClientId / PIM_CertThumbprint /
            # PIM_SqlServer / PIM_SqlDatabase), and this orchestrator holds every one of those --
            # it just never exported them, so `verify` failed on a deployment whose GUI smoke had
            # just passed 11/0. Measured rebuilding a customer master 2026-09-11: 12 of 13 steps
            # green and the release gate red for want of five variables the caller already had.
            # Same missing-passthrough class as the pull identity, the SQL admin identity, the
            # agent pool and the engine identity for mail -- the fifth in one deploy.
            # 🪤 SET, DO NOT OVERWRITE A CALLER'S. An operator who exported these deliberately
            # (pointing the validation at a different tenant) must win over our defaults.
            $prevEnv = @{}
            $valEnv = @{}
            if ("$TenantId".Trim())         { $valEnv['PIM_TenantId']      = "$TenantId".Trim() }
            if ("$EngineClientId".Trim())   { $valEnv['PIM_ClientId']      = "$EngineClientId".Trim() }
            elseif ("$AdminAppId".Trim())   { $valEnv['PIM_ClientId']      = "$AdminAppId".Trim() }
            if ("$EngineCertThumbprint".Trim()) { $valEnv['PIM_CertThumbprint'] = "$EngineCertThumbprint".Trim() }
            if ("$SqlServerFqdn".Trim())    { $valEnv['PIM_SqlServer']     = "$SqlServerFqdn".Trim() }
            if ("$SqlDatabase".Trim())      { $valEnv['PIM_SqlDatabase']   = "$SqlDatabase".Trim() }
            foreach ($k in $valEnv.Keys) {
                $prevEnv[$k] = [Environment]::GetEnvironmentVariable($k)
                if (-not "$($prevEnv[$k])".Trim()) { [Environment]::SetEnvironmentVariable($k, $valEnv[$k]) }
            }
            try {
                if ($pesterMajor -ge 5) {
                    $r = Invoke-Pester -Path $val -PassThru -Output Minimal
                    $valExit = if ($r.FailedCount -gt 0) { 1 } else { 0 }
                } else {
                    $found = if ($pesterMajor -gt 0) { "Pester $pesterMajor.x" } else { 'no Pester module' }
                    Warn "deploy-validation tests SKIPPED -- they need Pester 5, and this host has $found."
                    Warn '  Install-Module Pester -MinimumVersion 5.0 -Scope AllUsers -Force   (then re-run to enable them)'
                    Warn '  This layer is UNVERIFIED. It is NOT a deployment failure and does NOT roll anything back --'
                    Warn '  the post-deploy GUI gate above is what proves the Manager works.'
                    $valExit = -1
                }
            } catch {
                # Distinguish a runner that could not start from tests that ran and failed.
                Warn "deploy-validation tests COULD NOT RUN: $($_.Exception.Message)"
                Warn "  Pester major version on this host: $pesterMajor. This is a TOOLING problem, not a"
                Warn '  deployment failure -- it is recorded as UNVERIFIED and does NOT trigger a rollback.'
                Warn '  A rollback here would replace a Manager whose smoke gate passed with an older revision.'
                $valExit = -1
            } finally {
                # Put the environment back exactly as it was. $env: is process-wide, and this
                # script is often dot-sourced or called from a longer session -- leaking a tenant
                # id into a later step is the same class of defect as the AZURE_CONFIG_DIR leak.
                foreach ($k in $valEnv.Keys) {
                    if (-not "$($prevEnv[$k])".Trim()) { [Environment]::SetEnvironmentVariable($k, $null) }
                }
            }
        }
    } else { Info 'verify: deploy-validation tests not found -- UNVERIFIED' }

    $script:smokeExit = $smokeExit
    $script:validationExit = $valExit
    $v = Get-PimDeployValidationStepVerdict -SmokeExit $smokeExit -ValidationExit $valExit
    if (-not $v.ok -and $v.unverified) {
        Warn "verify: NOT VERIFIED -- $($v.detail)."
        Warn '  A skip is not a pass: this deploy is reported as FAILED (verify), and nothing is rolled back for it.'
    }
    return @{ ok=$v.ok; ran=$true; detail=$v.detail }
}
function Get-PimDeployValidationStepVerdict {
    <#
      PURE (BUG-216). The verify STEP's own verdict. -1 = "did not run" (a self-skip / opted out / no
      runner), 0 = passed, >0 = ran and failed.
      🔴 It used to be ok=($smoke -le 0 -and $val -le 0) -- so -SkipHostedSmoke on a host without Pester 5
      made verify ok=True with NOTHING checked, and the deploy exited 0 as a success.
      Now: any layer that RAN and failed -> not ok; NEITHER layer ran -> not ok, and flagged UNVERIFIED
      (the summary then reports the deploy failed, while the rollback verdict -- computed from the exit
      codes -- still does not roll back a deploy nobody proved broken). One layer passing is evidence.
    #>
    param([int]$SmokeExit = -1, [int]$ValidationExit = -1)
    # The smoke exits 2 when it SKIPPED checks: that is neither a pass nor a failure -- UNVERIFIED.
    $smokeSkipped = ($SmokeExit -eq 2)
    $ranAny = ($SmokeExit -ge 0) -or ($ValidationExit -ge 0)
    $failed = (($SmokeExit -gt 0) -and -not $smokeSkipped) -or ($ValidationExit -gt 0)
    if ($failed)       { return @{ ok = $false; unverified = $false; detail = "smoke=$SmokeExit validation=$ValidationExit (a layer that ran FAILED)" } }
    if ($smokeSkipped) { return @{ ok = $false; unverified = $true;  detail = "smoke=$SmokeExit validation=$ValidationExit -- UNVERIFIED: the hosted smoke skipped checks (exit 2), and a skip is not a pass" } }
    if (-not $ranAny)  { return @{ ok = $false; unverified = $true;  detail = "smoke=$SmokeExit validation=$ValidationExit -- UNVERIFIED: neither layer ran, and a skip is not a pass" } }
    return @{ ok = $true; unverified = $false; detail = "smoke=$SmokeExit validation=$ValidationExit" }
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
$prevImage = ''
if (-not $StepRunner -and $hosted -and -not $ValidateOnly -and (Have 'az') -and "$ResourceGroup".Trim()) {
    # 🔴 NO PIPE IN A JMESPath ON WINDOWS. `az` is az.cmd, and cmd.exe treats the `|` inside
    # "[?properties.active].name | [0]" as a SHELL PIPE: it splits the command there and dies with
    # "-o was unexpected at this time" (exit 255). The read then returns nothing, the rollback
    # target prints "(unknown)", and the deploy carries on with NO REVISION TO ROLL BACK TO --
    # silently, because the call swallowed its own stderr. Measured at a live customer 2026-09-08;
    # it only became visible when Invoke-PimAz started reporting az failures instead of hiding them.
    # 🪤 This is the third instance tonight of cmd.exe mangling an az argument (the cost-management
    # --query, the `az rest` JSON body, and now this). The rule: keep JMESPath free of cmd
    # metacharacters -- | & < > ^ -- and do the list-picking in PowerShell, which never re-parses.
    try {
        $prevRev = @(az containerapp revision list @azSubArgs -g $ResourceGroup -n $ManagerApp `
                        --query "[?properties.active].name" -o tsv 2>$null |
                     Where-Object { "$_".Trim() }) | Select-Object -First 1
    } catch { Write-Verbose "active-revision read failed: $($_.Exception.Message)" }
    if (-not "$prevRev".Trim()) { try { $prevRev = az containerapp revision list @azSubArgs -g $ResourceGroup -n $ManagerApp --query "[0].name" -o tsv 2>$null } catch { Write-Verbose "fallback-revision read failed: $($_.Exception.Message)" } }
    Info "pre-deploy revision (rollback target): $(if($prevRev){$prevRev}else{'(unknown)'})"
    # §53.6 -- capture the IMAGE too, because the revision may not survive to be rolled back to.
    # Container Apps garbage-collects inactive revisions; on the internal environment 2026-09-10
    # the captured target was already gone by the time the rollback ran, and the safety net told
    # the operator to roll back by hand during a failed deploy. The image is the durable anchor.
    try {
        $prevImage = "$(az containerapp show @azSubArgs -g $ResourceGroup -n $ManagerApp --query 'properties.template.containers[0].image' -o tsv 2>$null)".Trim()
    } catch { Write-Verbose "pre-deploy image read failed: $($_.Exception.Message)" }
    Info "pre-deploy image (rollback fallback): $(if($prevImage){$prevImage}else{'(unknown)'})"
}

Open-PimSetupHostWindow

# BUG-170 (via agent C1): the host-side ring gate now REFUSES to roll a deployed environment that carries
# no PIM_UPDATE_RING. The order here is infra -> code -> updater, so on a first install the code step (and
# a re-run of infra) would be refused for want of the ring the updater step installs a moment later. When
# that updater step WILL run in this same run with an explicit -UpdateRing, the gate is told the pending
# ring (and its source) and judges the roll by it -- exactly as if it were already there. An existing ring
# always wins inside the gate; without an explicit ring nothing is passed and the gate's refusal stands.
$pendingRingArgs = @{}
$updaterPlanned = @($plan.steps | Where-Object { "$($_.key)" -eq 'updater' -and $_.do }).Count -gt 0
if ($script:PimDeployRingExplicit -and $updaterPlanned -and "$AcrName".Trim() -and "$EnvName".Trim() -and
    (Get-PimUpdaterStepDecision -Scenario "$Scenario" -SourceUrlTemplate "$UpdateSourceUrlTemplate" -SkipUpdater:$SkipUpdater) -eq 'install') {
    $pendingRingArgs['PendingUpdateRing']      = $UpdateRing
    $pendingRingArgs['PendingUpdateSourceUrl'] = "$UpdateSourceUrlTemplate".Trim()
    Info "ring gate: this run installs the updater on ring $UpdateRing -- infra/code are judged by that ring where the environment has none yet"
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
# BUG-216: only a verdict that FAILED rolls back. UNVERIFIED (the smoke exited 2 -- it skipped checks) is
# not healthy and is reported as such, but nothing proved the deploy broken, so nothing is rolled back.
$needRollback = $halted -or ($verdict -and "$($verdict.State)" -eq 'failed')
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
            } elseif (-not "$prevRev".Trim() -and -not "$prevImage".Trim()) {
                # §53.6: EITHER anchor is enough. Only when both are missing is there nothing to do.
                Warn "AUTO-ROLLBACK COULD NOT RUN: neither the pre-deploy revision nor its image was captured, so there is no target at all. ROLL BACK BY HAND: az containerapp revision list -n $ManagerApp -g $ResourceGroup"
            } else {
                try {
                    if ($PSCmdlet.ShouldProcess($ManagerApp, "rollback to $($a.detail)")) {
                        $global:LASTEXITCODE = 0
                        $rbArgs = @{}
                        if ("$prevImage".Trim()) { $rbArgs['RollbackImage'] = "$prevImage".Trim() }
                        # An empty -Rollback is legal here: with no surviving revision name, the
                        # roller goes straight to the image anchor.
                        & $roller -Rollback ("$prevRev".Trim()) -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps -SkipSmoke @rbArgs | Out-Host
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

# =============================================================================
# WHAT TO DO NEXT -- the address, and the commands.
# 🔴 A DEPLOY THAT DOES NOT TELL YOU THE URL IS NOT FINISHED. The operator's words:
# "I have no way to find the url to access pim manager gui". Every ingredient was already in this
# process -- the app name, the resource group, an authenticated az -- and the deploy ended with a
# step table instead. Whoever runs this then goes hunting in the portal for something the script
# knew all along.
if ($hosted -and -not $WhatIfPreference -and $summary.status -eq 'success') {
    $mgrFqdn = ''
    try {
        $mgrFqdn = "$(az containerapp show @azSubArgs -n $ManagerApp -g $ResourceGroup --query properties.configuration.ingress.fqdn -o tsv 2>$null)".Trim()
    } catch { }
    Write-Host ''
    Write-Host '=============================================================================' -ForegroundColor Cyan
    Write-Host ' PIM4EntraPS is deployed. What you need next:' -ForegroundColor Cyan
    Write-Host '============================================================================='  -ForegroundColor Cyan
    if ($mgrFqdn) {
        Write-Host ''
        Write-Host '  OPEN THE MANAGER' -ForegroundColor Green
        Write-Host "      https://$mgrFqdn" -ForegroundColor White
        Write-Host '      (sign-in required; use a browser -- the API is not reachable from a script)' -ForegroundColor DarkGray
    } else {
        Write-Host '  Manager URL: could not read the ingress FQDN. Get it with:' -ForegroundColor Yellow
        Write-Host "      az containerapp show -g $ResourceGroup -n $ManagerApp --query properties.configuration.ingress.fqdn -o tsv" -ForegroundColor White
    }
    Write-Host ''
    Write-Host '  IMPORT YOUR CSV DATA (v1 file names are taken as they are; nothing to rename)' -ForegroundColor Green
    Write-Host '      $global:PIM_TenantId          = ''' -NoNewline -ForegroundColor White; Write-Host "$TenantId'" -ForegroundColor White
    if ("$SqlAdminClientId".Trim()) {
        Write-Host '      $global:PIM_SqlClientId       = ''' -NoNewline -ForegroundColor White; Write-Host "$SqlAdminClientId'" -ForegroundColor White
    }
    if ("$SqlAdminCertThumbprint".Trim()) {
        Write-Host '      $global:PIM_SqlCertThumbprint = ''' -NoNewline -ForegroundColor White; Write-Host "$SqlAdminCertThumbprint'" -ForegroundColor White
    }
    Write-Host "      $solRoot\setup\Migrate-PimToSql.ps1 ``" -ForegroundColor White
    Write-Host '          -ConfigDir <folder with your CSV files> `' -ForegroundColor White
    Write-Host ("          -ConnectionString `"{0}`" -WhatIf" -f $(if ("$SqlConnectionString".Trim()) { $SqlConnectionString } else { "Server=tcp:$SqlServerFqdn,1433;Initial Catalog=$SqlDatabase;Encrypt=True;TrustServerCertificate=False;Connection Timeout=60;" })) -ForegroundColor White
    Write-Host '      Run it with -WhatIf first: it prints the row count per entity, and it REPLACES' -ForegroundColor DarkGray
    Write-Host '      the full set of rows for every entity it imports. Drop -WhatIf to apply.' -ForegroundColor DarkGray
    # 2026-09-26 -- KEEPING IT CURRENT IS ONE COMMAND. Save the parameters this successful run used (never a secret), so
    # Update-PimCommunity.ps1 can pull the latest release and re-run exactly this deploy.
    if ($Apply -and "$TenantId".Trim() -and "$ResourceGroup".Trim()) {
        try {
            . (Join-Path $PSScriptRoot '_PimDeployProfile.ps1')
            $verFile = Join-Path $solRoot 'VERSION'
            $ver = if (Test-Path $verFile) { "$(Get-Content $verFile -Raw)".Trim() } else { '' }
            $saved = Save-PimDeployProfile -Bound $script:PimDeployBound -TenantId $TenantId -ResourceGroup $ResourceGroup -Version $ver
            Write-Host ''
            Write-Host '  KEEP IT UP TO DATE' -ForegroundColor Green
            Write-Host "      $PSScriptRoot\Update-PimCommunity.ps1 -Apply" -ForegroundColor White
            Write-Host "      (pulls the latest release and re-runs this deploy with the parameters saved in $($saved.path))" -ForegroundColor DarkGray
            if (@($saved.omitted).Count) { Write-Host "      not saved, because they carry a secret: $(@($saved.omitted) -join ', ') -- pass them to the updater yourself" -ForegroundColor Yellow }
        } catch { Warn "could not save the deploy profile for Update-PimCommunity.ps1: $($_.Exception.Message)" }
    }
    Write-Host ''
    Write-Host '  WHO CAN SIGN IN' -ForegroundColor Green
    if (@($EasyAuthAllowedPrincipals | Where-Object { "$_".Trim() }).Count) { Write-Host "      the named principal(s): $(@($EasyAuthAllowedPrincipals) -join ', ')" -ForegroundColor White }
    if ($EasyAuthAllowAllTenantUsers) { Write-Host '      every member account in the tenant (guests are not admitted)' -ForegroundColor White }
    if (-not @($EasyAuthAllowedPrincipals | Where-Object { "$_".Trim() }).Count -and -not $EasyAuthAllowAllTenantUsers) {
        Write-Host "      unchanged: the Manager's existing assignments (the application is assignment-required)" -ForegroundColor White
    }
    Write-Host ''
}

# The normal-completion path. The trap and the exiting event cover failure and interrupt; this
# covers success, which is the case that would otherwise leave the key sitting there after a run
# that looked perfect.
Restore-PimCallerAzContext
Close-PimSetupHostWindow        # IMP-49 t -- in the CALLER's az context, where the window was opened
Clear-PimEphemeralPem

$summary
# BUG-216: 'unverified' is not success either -- a deploy nothing verified must not exit 0.
if ($summary.status -eq 'failed' -or $summary.status -eq 'rolledback' -or $summary.status -eq 'unverified') { exit 1 }
