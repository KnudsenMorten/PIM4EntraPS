#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS -- FULL update-lifecycle automation: after PIM code is pulled, one coherent flow
    of detect -> build -> deploy -> verify -> notify -> ensure health monitoring.
    REQUIREMENTS.md sec.1 (Hosting/Runtime) + sec.2 (Containers) + sec.5 (SQL/Data) + sec.20.

.DESCRIPTION
    ONE script handles updates from BOTH pull paths:

      * COMMUNITY git pull (-Source git-pull): local/VM; store SQLEXPRESS or Azure SQL; local
        Manager. Build = local build/package + relaunch.
      * sync-automateit pull (-Source sync-automateit, hosted): Azure SQL + Container Apps. Build =
        az acr build; deploy = roll the ACA revision to the freshly-built image.

    The six steps (the orchestrator EXECUTES; the pure core in engine/_shared/PIM-UpdateLifecycle.ps1
    DECIDES -- every risky decision is unit-tested offline):

      1. DETECT  -- does the pulled update need a SQL/schema upgrade (vs the deployed DB, via the
                    locked-schema column audit + Test-PimBaselineDoc-style preflight) and/or a
                    Manager web-GUI update (content hash / VERSION over tools/pim-manager/* vs the
                    running image)?
      2. BUILD   -- when a GUI update is needed, rebuild the Manager image FROM THE PULLED CODE
                    (Build-PimManagerImage.ps1: az acr build hosted / local build community). This
                    is the gap: sync-automateit / Update-PimContainers -SkipBuild only ROLL a
                    pre-built image.
      3. DEPLOY  -- roll the Container App to the FRESHLY-BUILT image (Update-PimContainers.ps1, NOT
                    -SkipBuild) and/or apply the idempotent SQL schema upgrade
                    (preflight -> apply -> re-preflight; never destructive).
      4. VERIFY  -- run the hosted smoke (tests/live/Test-PimManagerHostedSmoke.ps1); AUTO-ROLLBACK
                    on failure (prior revision; SQL preflight gate before apply).
      5. NOTIFY  -- email the update outcome (success/failure, what was built/deployed/upgraded) to
                    the owner, reusing the EXISTING mailer (Send-PimNotifyMail -- the same mail path
                    as the synthetic-monitor work). Does NOT reinvent a mailer.
      6. ENSURE  -- make sure the deployable health monitor with mail-notify (the synthetic monitor:
        MONITOR   checks Manager + CEH health every ~5-15 min, emails the owner on failure,
                    debounced) is in place/refreshed after the update; deploy/refresh it if missing.
                    REUSES the synthetic monitor (feat/synthetic-monitor) -- never duplicates it.

    MODES:
      -DetectOnly (default, safe): report { SqlUpdateRequired; GuiUpdateRequired; details }, make NO
                  changes. This is the default so a bare run never mutates anything.
      -Apply    : build + deploy + schema + notify + ensure-monitor, gated, rollback on fail.

    Idempotent. PS 5.1-safe. REST/cert + MI only via az (no PowerShell modules). Azure SQL single
    store. West Europe / Denmark East only. ACA via Update-PimContainers (--yaml for workers).

    NOTE (synthetic-monitor dependency): the mailer is reused by INTERFACE (Send-PimNotifyMail). The
    monitor deploy script is reused by interface too: -MonitorDeployScript points at the
    feat/synthetic-monitor deploy entry. If that branch is not yet on main, step 6 reports the
    wire-up it WOULD run and self-skips (it never fabricates a monitor). Wire-up: once
    feat/synthetic-monitor lands, set -MonitorDeployScript to its deploy entry (default path tried:
    tools/setup/Deploy-PimSyntheticMonitor.ps1).

.PARAMETER Source
    'git-pull' (community/local/VM) or 'sync-automateit' (hosted ACA + Azure SQL).

.PARAMETER DetectOnly
    Report only; make no changes. THE DEFAULT (also implied when neither -DetectOnly nor -Apply set).

.PARAMETER Apply
    Actually build/deploy/upgrade/notify/ensure-monitor (gated). Rollback on verify failure.

.EXAMPLE
    .\Invoke-PimUpdate.ps1 -Source sync-automateit
    Detect-only (default): report whether the hosted deployment needs a GUI rebuild and/or a SQL upgrade.

.EXAMPLE
    .\Invoke-PimUpdate.ps1 -Source sync-automateit -Apply
    Hosted: build (if GUI changed) -> roll -> SQL upgrade (if needed) -> verify -> notify -> ensure monitor.

.EXAMPLE
    .\Invoke-PimUpdate.ps1 -Source git-pull -Apply
    Community: local build/package + relaunch + local SQL upgrade + notify + ensure monitor.

.NOTES
    Foldable into sync-automateit (PR #24) + a git post-merge hook. Decisions in the pure core
    (engine/_shared/PIM-UpdateLifecycle.ps1) are offline-unit-tested (tests/Test-PimUpdateLifecycle.ps1).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('git-pull','sync-automateit','from-master')][string]$Source = 'sync-automateit',
    # s31: resolve the update source + hosting from a deployment SCENARIO (S1..S6). When set, the
    # scenario's resolved updateSource (git-pull | sync-automateit | from-master) and managedHosting
    # (central|local) OVERRIDE -Source -- so one knob drives the whole update path.
    [ValidateSet('S1','S2','S3','S4','S5','S6')][string]$Scenario,
    [ValidateSet('central','local')][string]$ManagedHosting,   # only used for from-master (S5=central, S6=local); auto-set from -Scenario
    [switch]$DetectOnly,
    [switch]$Apply,
    # hosted deploy targets (passthrough to the existing roller / smoke).
    # 🔒 BUG-28 / SEC-02 PATTERN: these used to default to the OPERATOR'S OWN resource
    # group, registry and mailbox -- real infrastructure names, hard-coded in a file that
    # SHIPS TO CUSTOMERS. A customer who ran the sync-driven deploy without supplying them
    # would have aimed at the operator's estate. They now come from the environment, and
    # the hosted deploy path FAILS LOUDLY if they are missing (see Assert-PimDeployTarget
    # below) rather than silently substituting somebody else's infrastructure.
    # ImageRepo/ManagerApp/Apps keep their defaults deliberately: they are PRODUCT names
    # (what the containers are called), identical in every install, not customer facts.
    [string]$ResourceGroup = "$($env:PIM_ResourceGroup)",
    [string]$AcrName       = "$($env:PIM_AcrName)",
    # 🔴 A PRIVATE REGISTRY CANNOT BE BUILT INTO FROM A SHARED ACR AGENT, AND THIS PATH HAD NO WAY
    # TO SAY SO. `az acr build` runs on ACR's build fleet wherever the command is issued, so with
    # -AcrPublicAccess false the build agent is refused by the registry's own firewall:
    #     denied: client with IP '172.211.120.63' is not allowed
    # New-PimHostingPrerequisites creates a dedicated agent pool inside the VNet for exactly this,
    # Build-PimManagerImage has accepted -AcrAgentPool all along, and the deploy's `image` step
    # passes it -- but this script, which the `code` step and the NIGHTLY IN-CLOUD UPDATER both go
    # through, had no parameter for it. Measured at a customer 2026-09-11: the deploy's own build
    # succeeded and the update's rebuild of the same source failed minutes later.
    # 🪤 THE UNATTENDED PATH IS THE ONE THAT MATTERS. Every internal-only customer's 03:00 self-update
    # would fail this way, with nobody watching -- so the env default exists for the update job,
    # which has no command line to receive it on.
    [string]$AcrAgentPool  = "$($env:PIM_ACR_AGENT_POOL)",
    [string]$ImageRepo     = 'pim-manager',
    [string]$ManagerApp    = 'ca-pim-manager',
    [string[]]$Apps        = # empty = DISCOVER (Update-PimContainers.ps1 enumerates the resource group).
    # The hard-coded six-app list was wrong for every real topology -- only ca-pim-manager
    # exists -- and it was copy-pasted into FOUR entry points, so fixing one changed nothing.
    @(),
    # BUG-48: the scheduled tick Job is rolled by Update-PimContainers along with the apps, off the
    # same resolved digest. Threaded explicitly rather than left to the roller's default -- the
    # default is correct today, and BUG-46 was a value that was correct at the top of a script and
    # simply never reached the call.
    [string]$TickJobName   = 'ca-pim-tick',
    # §53.4 -- the in-cloud updater whose PIN this script advances after a successful build+roll.
    # A product name like ManagerApp/TickJobName, identical in every install, so it defaults.
    [string]$UpdateJobName = 'ca-pim-update',
    [switch]$SkipPinAdvance,                              # leave the updater pinned where it is
    # --- 2026-09-13: THE RING (operator: "nothing releases to ring 2 without my approve") ----------
    # The environment's updater carries PIM_UPDATE_RING. On ring >= 2 this script REFUSES to build-and-
    # roll anything other than what channel.json approves for that ring (-OverrideRingGate -Reason is
    # the audited way past). On ring 0/1 -- internal and the operator's test estate, which get every
    # build BY DESIGN -- it rolls as before and, after a VERIFIED roll, step 4b advances ringN in
    # channel.json so the cloud job (whose ring wins over its pin) does not roll it back next night.
    # Ring 2 and above are NEVER written automatically.
    [switch]$OverrideRingGate,
    [string]$Reason,
    # 🔴 BUG-228 (measured 2026-09-20 rolling internal to 2.4.382). Update-PimContainers carries the
    # BUG-55 desired-state gate: an image whose policy baseline differs from the one RECORDED on the
    # app is refused, because within one tick it starts converging every managed scope onto the new
    # baseline. Its refusal names -AcceptBaselineChange as the way past -- and this script, which the
    # `code` step and the NIGHTLY IN-CLOUD UPDATER both go through, had no such parameter, so there
    # was NO way to answer the gate from here. A blocked environment stays blocked forever.
    # 🪤 The recording can also go stale on its own: on internal the tag still read the pre-2.4.380
    # fingerprint while the store, the tree and the RUNNING image all agreed on the current one -- so
    # the gate refused a roll that carried no desired-state change at all. Accepting then re-records
    # the fingerprint, which is what makes the next roll honest again.
    # 🔒 Forwarded, never defaulted: the whole point of the gate is that a human says yes.
    [switch]$AcceptBaselineChange,
    # BUG-170: an environment with NO ring is refused (it predates the ring). When the SAME deploy run
    # installs the updater afterwards (Invoke-PimDeployAll with an explicit -UpdateRing), it passes that
    # ring here and the gate judges the roll by it -- ring 0/1 get every build, ring >= 2 only what
    # channel.json approves. -1 = none. Forwarded to Update-PimContainers.
    [ValidateRange(-1,3)][int]$PendingUpdateRing = -1,
    [string]$PendingUpdateSourceUrl = '',
    # Where channel.json lives is derived from the updater's own PIM_UPDATE_SOURCE_URL. WRITING it needs
    # that storage account's key, from its subscription -- often NOT the environment's (an estate host
    # is signed in to the environment's tenant). Optional isolated az profile for that one call.
    # Without -ChannelSubscriptionId the advance is SKIPPED with a warning, never failed.
    [string]$ChannelSubscriptionId = "$($env:PIM_CHANNEL_SUBSCRIPTION_ID)",
    [string]$ChannelAzureConfigDir = "$($env:PIM_CHANNEL_AZURE_CONFIG_DIR)",
    # 🪤 -SubscriptionId ALREADY EXISTS -- it is declared further down with the SQL-admin inputs
    # (BUG-102, "every az call must name its subscription"). Step 4b uses that one. A second
    # declaration here was a PARSE ERROR ("Duplicate parameter"), i.e. the script could not run at
    # all, and it was added because two comments in this file say the script has no such parameter:
    # the smoke call in step 4 ("this script has no such parameter"), and Register-PimSyncSchedule's
    # ("Invoke-PimUpdate.ps1 has no such parameter (checked)"). Both were true when written and both
    # outlived the fact. The parameter list is the only authority on what a script accepts.
    [string]$ImageTag,                                    # override the build/deploy tag (default = pulled VERSION)
    # SQL detection inputs (hosted = Azure SQL; community = SQLEXPRESS/Azure SQL).
    [string]$SqlConnectionString,                         # if set, the orchestrator reads deployed columns to detect drift
    # THE IDENTITY THAT OPENS THAT CONNECTION. Azure SQL here is Entra-only, so the connection
    # string carries no credential by design and a token must be minted for it. Without these the
    # only candidates are the engine SPN's own globals (which do not exist on a deploy host) and
    # the ambient `az` context (which is whoever ran the deploy, not necessarily the server's Entra
    # admin) -- and an unauthenticated open fails with the useless "Login failed for user ''".
    # This is the SAME identity the infra step sets as the server's Entra admin, so passing it here
    # is what makes the schema step able to use the admin rights the infra step just granted.
    # BUG-102: every az call must name its subscription. This script had no such parameter, and the
    # hygiene gate could not see the omission because it never scanned plain assignments -- which is
    # how nearly every read in here is written. Explicit wins; the deploy's own env var is the
    # fallback; empty keeps the previous (ambient-context) behaviour for existing callers.
    [string]$SubscriptionId = $(if ($env:PIM_SUBSCRIPTION_ID) { $env:PIM_SUBSCRIPTION_ID } else { '' }),
    [string]$SqlAdminClientId,
    [string]$SqlAdminCertThumbprint,                      # preferred: cert in LocalMachine\My / CurrentUser\My
    [string]$SqlAdminClientSecret,                        # lab fallback only
    [string]$TenantId,                                    # the tenant that admin lives in
    # notify + monitor reuse.
    # BUG-28: was an operator mailbox. A missing recipient SKIPS the notification (it is
    # not the deploy) rather than failing it -- but it never falls back to someone else's.
    [string]$Recipient          = "$($env:PIM_NotifyRecipient)",
    [string]$MonitorDeployScript,                         # feat/synthetic-monitor deploy entry (reused by interface)
    [int]$MonitorIntervalMinutes = 10,
    [switch]$SkipVerify,                                  # only for a registry with no live hosted Manager
    [switch]$SkipNotify,
    # 🔴 §52.12 -- APPLY THE SQL HALF AND NOTHING ELSE.
    # `Invoke-PimDeployAll`'s `schema` step only wants the schema upgrade, but this script has
    # always run its WHOLE detect->build->deploy chain, so that step BUILT the image and ROLLED the
    # apps -- and then the `code` step, two steps later, did both again. Measured at a live customer
    # 2026-09-09: ONE deploy produced THREE builds of identical source (three different digests)
    # and TWO rolls of the same version, about four wasted minutes on every single deploy,
    # including every debugging cycle.
    # 🪤 The existing workaround was to pass this step -AcrName/-Apps so the build it should never
    # have been doing would at least not fail (see the comments in Invoke-PimDeployAll's schema
    # step). Feeding a step the arguments for work it should not do is not the same as stopping it.
    [switch]$SchemaOnly
)
$ErrorActionPreference = 'Stop'
$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
# Guarded `az` shadow -- see _PimAz.ps1. Must precede the first az call (step 1 DETECT).
. "$here\_PimAz.ps1"
$solRoot = Split-Path -Parent (Split-Path -Parent $here)            # SOLUTIONS/PIM4EntraPS
# Splatted into every az call in this script. Named "...Sub..." because that is the codebase's
# scoping convention and the hygiene gate recognises a scoped call by it.
$azSubArgs = @()
if ("$SubscriptionId".Trim()) { $azSubArgs = @('--subscription', "$SubscriptionId".Trim()) }
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Info($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }
function Have($cmd){ [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# ---- load the pure decision core + dependencies (REUSE, never re-implement) ----
# 🔴 THE NOTIFY STEP COULD NEVER SEND. Step 5 is gated on `Get-Command Send-PimNotifyMail`, and
# this file never loaded PIM-Notify.ps1 -- so every unattended update reported
#     "Send-PimNotifyMail not available ... outcome NOT emailed"
# and the ONLY signal an operator gets about a nightly update was never sent, in any deployment,
# since the step was written. Same class as the five inert scheduler jobs and the policy-baseline
# gate: a capability gate on a function nothing loads is a switch with no wire behind it.
# Found by the structural audit (Test-PimCodeAudit), not by reading -- it reports honestly, which
# is exactly why nobody chased it.
. (Join-Path $solRoot 'engine\_shared\PIM-Notify.ps1')                # Send-PimNotifyMail (step 5)
. (Join-Path $solRoot 'engine\_shared\PIM-SyncAutomateIT.ps1')        # semver/sync/health/rollback
. (Join-Path $solRoot 'engine\_shared\PIM-SchemaConformance.ps1')     # locked-schema + per-table plan
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateLifecycle.ps1')       # detect/build/notify/monitor core
. (Join-Path $solRoot 'engine\_shared\PIM-ScenarioProfile.ps1')       # s31 scenario -> knob resolver
# 🔴 LOADED AT SCRIPT SCOPE, DELIBERATELY. Get-DeployedColumns used to dot-source this INSIDE
# itself -- which loads Get-PimRestToken into that FUNCTION's scope and nowhere else. So the DETECT
# path could mint a SQL token and the APPLY path, a few hundred lines below, could not: its
# `Get-Command Get-PimRestToken` found nothing, minted no token, and opened an unauthenticated
# connection that died with "Login failed for user ''" -- at a live customer, on the first deploy
# that ever reached the apply step. A dot-source inside a function is not a dependency, it is a
# local variable.
. (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1')                  # Get-PimRestToken (SQL/Graph tokens)
. (Join-Path $solRoot 'engine\_shared\PIM-ChangeQueue.ps1')           # Get-PimChangeQueueDdl -- Initialize-PimSqlStore CALLS it
. (Join-Path $solRoot 'engine\_shared\PIM-SqlStore.ps1')              # Initialize-PimSqlStore (core tables)
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateSource.ps1')          # Get-PimSchemaFileApplyPlan -- the SAME guard update-job-entry uses
. (Join-Path $here '_PimUpdateRing.ps1')                               # ring gate + channel advance (2026-09-13)
# the mailer (same path as the synthetic-monitor work). Loading PIM-Notify pulls in Send-PimNotifyMail.
$notifyLib = Join-Path $solRoot 'engine\_shared\PIM-Notify.ps1'
if (Test-Path $notifyLib) { . $notifyLib }

# default-safe: if neither switch is given, DetectOnly wins.
if (-not $Apply) { $DetectOnly = $true }
if ($DetectOnly -and $Apply) { throw "Pass either -DetectOnly or -Apply, not both." }

# ---- s31: a -Scenario resolves the update source + managed hosting, overriding -Source ----
# The build/roll SUB-scripts (Build-PimManagerImage / Update-PimContainers) only know git-pull |
# sync-automateit, so from-master is mapped to a build source by managed hosting: central => the
# ACR-build/ACA-roll path (sync-automateit), local => the local build/relaunch path (git-pull).
$buildSource = $Source
if ($Scenario) {
    $plan = Get-PimScenarioEntryPlan -Scenario $Scenario
    $Source = $plan.updateSource
    if (-not "$ManagedHosting".Trim() -and "$($plan.managedHosting)".Trim()) { $ManagedHosting = $plan.managedHosting }
    Write-Host ("[scenario] {0} -> updateSource={1} managedHosting={2} edition={3} hosting={4} spn={5}" -f `
        $plan.id, $plan.updateSource, $plan.managedHosting, $plan.activeEdition, $plan.hostingLocation, $plan.spnModel) -ForegroundColor Cyan
}
if (-not "$ManagedHosting".Trim()) { $ManagedHosting = 'local' }
# Resolve the build-source the sub-scripts understand.
if ($Source -eq 'from-master') { $buildSource = if ($ManagedHosting -eq 'central') { 'sync-automateit' } else { 'git-pull' } }
else { $buildSource = $Source }

$profile = Get-PimUpdateSourceProfile -Source $Source -ManagedHosting $ManagedHosting

# 🔴 BUG-67, THE SECOND SITE. Invoke-PimDeployAll already corrects this and says why at length:
# Get-PimUpdateSourceProfile keys isHosted off the UPDATE SOURCE, and for S5/S6 that resolves to
# 'git-pull' (from-master + managedHosting=local) -> isHosted=$false. But "local" carries two
# unrelated meanings -- MSP topology (the customer's own tenant) and hosting flavour (a VM with a
# local build) -- and a managed/slave tenant is routinely topology-local AND hosting-hosted.
# 🪤 THE ORCHESTRATOR LEARNED THIS; THIS SCRIPT DID NOT. It re-derives its own $profile from the
# source, so the correction made one layer up never reached here. Measured rebuilding a managed
# slave 2026-09-12: hosted=False on an environment running a container app, an ACA job, a managed
# environment and its own registry -- which skipped "ensure the store core tables", so pim.Settings
# was never created and the next step died with
#     RESULT: FAILED -- could not read existing FeatureGates: Invalid object name 'pim.Settings'
# while the schema step two lines earlier had reported "SQL upgrade applied + re-preflight clean".
# Same shape as the three other fixes this session: a rule that lives in one script does not protect
# the next one.
# S1..S6 are all Container Apps deployments. 🪤 This script has no -NotHosted of its own (the
# orchestrator owns that switch and simply does not pass -Scenario for a genuine VM install), so
# the correction is keyed on -Scenario alone rather than on a variable that does not exist here --
# an undefined $NotHosted would read as $null today and throw the moment anyone adds Set-StrictMode.
if ($Scenario -and -not $profile.isHosted) {
    Write-Host (("[scenario] hosting: False -> True (-Scenario {0} is a Container Apps deployment; the update " +
                 "source '{1}' describes where UPDATES come from, not what compute runs them)") -f $Scenario, $Source) -ForegroundColor Yellow
    $profile = $profile.PSObject.Copy()
    $profile.isHosted = $true
}

Write-Host "=== PIM4EntraPS UPDATE-LIFECYCLE ($Source; $(if($DetectOnly){'DETECT-ONLY'}else{'APPLY'})) ===" -ForegroundColor Cyan
Info "build mode: $($profile.buildMode); deploy mode: $($profile.deployMode); hosted: $($profile.isHosted)"
# 🔴 IMP-43 -- A RUNTIME v2 DOES NOT SUPPORT IS REFUSED, NOT HALF-RUN. The local/VM path (local build +
# relaunch, SQLEXPRESS) has no v2 runtime; applied to a hosted environment it built an image, rolled
# NOTHING ("community: ... Build relaunched it") and reported deployed=True. Detect-only still reads.
# Checked against the FINAL profile, after the -Scenario correction above.
if ($Apply) { Assert-PimUpdateRuntimeSupported -UpdateProfile $profile -Caller 'Invoke-PimUpdate' }
elseif (-not $profile.isHosted) { Warn "note: $($profile.unsupportedReason) -- detection only; -Apply will refuse." }
# BUG-170: an override lets exactly ONE named version through. Without -ImageTag the version would be
# whatever the pulled tree says tonight -- a standing override, which is no gate at all.
if ($OverrideRingGate -and -not "$ImageTag".Trim()) {
    throw "Invoke-PimUpdate: -OverrideRingGate needs -ImageTag <version> -- an override names the one version it lets through, never 'whatever the pulled tree says'."
}

# =============================================================================
# helpers to GATHER FACTS (the side-effecting reads; the decisions stay pure)
# =============================================================================
function Get-PulledVersion {
    $vf = Join-Path $solRoot 'VERSION'
    if (Test-Path $vf) { return (Get-Content -LiteralPath $vf -Raw).Trim() }
    return ''
}
function Get-PulledManagerContentHash {
    # 🔴 MUST HASH EXACTLY WHAT Build-PimManagerImage HASHES, AND FOR THE SAME REASON.
    # This hashed `tools/pim-manager` only, while the Dockerfile copies the WHOLE solution -- so a
    # change to engine/_shared (which the Manager runs) left this hash IDENTICAL, the detector
    # reported "no GUI update", and the fix was never built or rolled. Measured 2026-09-12: a
    # SEC-01 lockout fix in engine/_shared/PIM-HostedAuth.ps1 could not reach ANY environment,
    # including through the nightly in-cloud updater -- a self-updating system blind to its own
    # engine change is not self-updating.
    # 🪤 AND THE COPIES MUST AGREE. The detector decides whether to build; the builder stamps the
    # hash onto the image and the roller stamps it onto the app, where this detector reads it back.
    # 🔴 BUG-174: "a deliberate duplicate" of the walk was the bug -- the ROLLER's copy hashed
    # tools\pim-manager only, so the running hash never matched and every update rebuilt an identical
    # image. All three now call the ONE definition (PIM-UpdateLifecycle.ps1).
    Get-PimSolutionContentHash -SolutionRoot $solRoot
}
function Get-RunningManagerInfo {
    # hosted: read the running image tag + its baked-in content hash label via az (best-effort).
    # community: read the local package marker if present. Blank hash => detection treats as needs-update.
    $info = @{ version = ''; contentHash = '' }
    if ($profile.isHosted -and (Have 'az')) {
        try {
            $img = az containerapp show @azSubArgs -g $ResourceGroup -n $ManagerApp --query "properties.template.containers[0].image" -o tsv 2>$null
            if ("$img".Trim()) { $info.version = ("$img" -split ':')[-1] }
            # content hash is published as an image env/label; read the app env var if present.
            $h = @(az containerapp show @azSubArgs -g $ResourceGroup -n $ManagerApp --query "properties.template.containers[0].env[?name=='PIM_MANAGER_CONTENT_HASH'].value" -o tsv 2>$null) | Select-Object -First 1
            if ("$h".Trim()) { $info.contentHash = "$h".Trim() }
        } catch {}
    } else {
        $pkg = Join-Path $solRoot 'output\manager-package\manager-package.json'
        if (Test-Path $pkg) { try { $m = Get-Content $pkg -Raw | ConvertFrom-Json; $info.version = "$($m.imageTag)"; $info.contentHash = "$($m.contentHash)" } catch {} }
    }
    return $info
}
# 🔴 THE APPLY PATH DID NOT AUTHENTICATE, WHILE THE DETECT PATH DID.
# Get-DeployedColumns below mints an Entra token and sets $conn.AccessToken -- its own comment
# documents the exact symptom, "Login failed for user ''". The schema APPLY a few hundred lines
# down did none of that: it called `Invoke-Sqlcmd -ConnectionString $SqlConnectionString`, and the
# connection string deliberately carries NO credentials (Authentication= cannot be used, since the
# code path is System.Data.SqlClient). So detect read the drift happily and apply died with the
# very error the detect path had already been fixed for. Measured at a live customer 2026-09-08 --
# the first deploy ever to reach the apply step, because the gate had always thrown before it.
# 🪤 One defect, two call sites, one of them fixed: the same shape as the missing passthroughs.
# Fixing a connection bug in the function you were debugging is not fixing it in the product.
# This helper is now the ONLY way this script executes DDL, so the two cannot diverge again.
# It also removes the dependency on the SqlServer module's Invoke-Sqlcmd.
# ONE token source for BOTH the detect read and the apply write. They had two, and only one of
# them worked. The order is deliberate:
#   1. the SQL admin identity passed in -- the identity the infra step made the server's Entra
#      admin, so it is the one that is actually authorised. Explicit beats ambient.
#   2. the engine SPN globals -- correct when this runs on an installed engine host.
#   3. the signed-in `az` context -- correct on a deploy host where the operator signed in as
#      someone with admin rights, and the only candidate that needs no configuration at all.
# A connection string that already carries its own credential is left alone.
function Get-PimSqlAccessToken {
    param([string]$ConnString)
    if ("$ConnString" -match '(?i)Authentication\s*=|Integrated Security|Trusted_Connection|User Id\s*=') { return $null }
    $res = 'https://database.windows.net'
    if ("$SqlAdminClientId".Trim() -and ("$SqlAdminCertThumbprint".Trim() -or "$SqlAdminClientSecret".Trim())) {
        $a = @{ Resource = $res; ClientId = $SqlAdminClientId }
        if ("$TenantId".Trim()) { $a['TenantId'] = $TenantId }
        if ("$SqlAdminCertThumbprint".Trim()) { $a['CertThumbprint'] = $SqlAdminCertThumbprint }
        else                                  { $a['ClientSecret']   = $SqlAdminClientSecret }
        try { $t = Get-PimRestToken @a; if ("$t".Trim()) { Info 'SQL token: the supplied SQL admin identity'; return $t } }
        catch { Warn "the supplied SQL admin identity could not mint a SQL token: $($_.Exception.Message)" }
    }
    try {
        if ($global:PIM_ClientId -and (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) {
            $t = Get-PimRestToken -Resource $res
            if ("$t".Trim()) { Info 'SQL token: the configured engine identity'; return $t }
        }
    } catch { Warn "the engine identity could not mint a SQL token: $($_.Exception.Message)" }
    if (Have 'az') {
        try {
            $t = az account get-access-token @azSubArgs --resource $res --query accessToken -o tsv 2>$null
            if ("$t".Trim()) { Info 'SQL token: the signed-in az context'; return "$t".Trim() }
        } catch { Warn "the signed-in az context could not mint a SQL token: $($_.Exception.Message)" }
    }
    return $null
}

function Invoke-PimSqlDdl {
    param([Parameter(Mandatory)][string]$ConnString, [Parameter(Mandatory)][string]$Sql)
    $tok = Get-PimSqlAccessToken -ConnString $ConnString
    # 🔴 REFUSE, rather than open a connection that cannot possibly succeed. Without this the run
    # reaches the server with no credential and the server answers "Login failed for user ''" --
    # which reads like a permissions problem on the SQL side and sent a live deploy hunting there,
    # when the real fact is that no token was ever minted on this side.
    if (-not $tok -and "$ConnString" -notmatch '(?i)Authentication\s*=|Integrated Security|Trusted_Connection|User Id\s*=') {
        throw ("the SQL schema upgrade has no way to authenticate: the connection string carries no credential " +
               "and no access token could be minted. Pass -SqlAdminClientId with -SqlAdminCertThumbprint (the " +
               "identity the deploy set as the server's Entra admin), or sign in with 'az login' as an account " +
               "that is a SQL Entra admin before running the deploy.")
    }
    $conn = New-Object System.Data.SqlClient.SqlConnection $ConnString
    if ($tok) { $conn.AccessToken = $tok }
    $conn.Open()
    try {
        # Split on GO so a shipped .sql batch separator does not reach the server as a keyword.
        foreach ($batch in ($Sql -split '(?im)^\s*GO\s*$')) {
            if (-not "$batch".Trim()) { continue }
            $cmd = New-Object System.Data.SqlClient.SqlCommand $batch, $conn
            $cmd.CommandTimeout = 300
            [void]$cmd.ExecuteNonQuery()
        }
    } finally { $conn.Close() }
}

# The COL_LENGTH probe the base-schema guard asks, over the SAME token path as Invoke-PimSqlDdl.
# THROWS when it cannot answer -- Get-PimSchemaFileApplyPlan reads a throw as "unknown" and refuses.
function Test-PimSqlColumnExists {
    param([Parameter(Mandatory)][string]$ConnString, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$Column)
    $tok = Get-PimSqlAccessToken -ConnString $ConnString
    $conn = New-Object System.Data.SqlClient.SqlConnection $ConnString
    if ($tok) { $conn.AccessToken = $tok }
    $conn.Open()
    try {
        $cmd = New-Object System.Data.SqlClient.SqlCommand 'SELECT CASE WHEN COL_LENGTH(@t, @c) IS NULL THEN 0 ELSE 1 END', $conn
        [void]$cmd.Parameters.AddWithValue('@t', $Table)
        [void]$cmd.Parameters.AddWithValue('@c', $Column)
        $cmd.CommandTimeout = 60
        return ([int]$cmd.ExecuteScalar() -eq 1)
    } finally { $conn.Close() }
}

# 🔴 2026-09-18 (IMP-46) -- THE SHIPPED BASE SCHEMA, ON EVERY APPLY RUN, BEHIND THE STORE-AWARE GUARD.
# This used to run only when a LOCKED table was absent -- and the only locked table was the dead
# pim.LocalAdmins. It now mirrors update-job-entry exactly (2026-09-15): every file is checked by
# Get-PimSchemaFileApplyPlan BEFORE any of them runs (a refusal applies nothing), and then applied.
# Idempotent (every object is IF OBJECT_ID/SCHEMA_ID ... IS NULL) and non-destructive (no DROP TABLE /
# TRUNCATE / DELETE / UPDATE; a DROP COLUMN only when guarded AND the column is absent here -- inert),
# so running it on a populated store is a no-op, and guarded additions reach existing stores.
# Returns the relative paths applied, in order. Throws on a missing file, a refusal or a SQL error.
$script:PimBaseSchemaFiles = @('sql\platform-schema.sql')
function Invoke-PimBaseSchemaApply {
    param([Parameter(Mandatory)][string]$ConnString, [Parameter(Mandatory)][string]$SolutionRoot)
    $colProbe = { param([string]$Table, [string]$Column) Test-PimSqlColumnExists -ConnString $ConnString -Table $Table -Column $Column }
    $files = @()
    foreach ($rel in @($script:PimBaseSchemaFiles)) {
        $sf = Join-Path $SolutionRoot $rel
        if (-not (Test-Path -LiteralPath $sf)) {
            throw "the base schema file '$rel' is missing from this payload -- the store cannot be created."
        }
        $sqlText = [IO.File]::ReadAllText($sf)
        $fPlan = Get-PimSchemaFileApplyPlan -Sql $sqlText -Name $rel -ColumnExists $colProbe
        if (-not $fPlan.ok) {
            throw ("shipped schema file '$rel' REFUSED for unattended apply: " + (@($fPlan.violations) -join '; ') +
                   '. Nothing from the schema files was applied.')
        }
        $files += @{ rel = $rel; sql = $sqlText; drops = @($fPlan.guardedDrops) }
    }
    $applied = @()
    foreach ($s in $files) {
        Invoke-PimSqlDdl -ConnString $ConnString -Sql $s.sql
        $inert = @($s.drops | ForEach-Object { "$($_.table).$($_.column)" })
        Info ("  applied $($s.rel) (idempotent; guarded additions reach existing stores$(if ($inert.Count) { "; inert guarded drops: $($inert -join ', ')" }))")
        $applied += $s.rel
    }
    return ,$applied
}

function Get-DeployedColumns {
    # Read each locked-SQL table's actual columns from the deployed DB to detect drift. Requires a
    # connection string + sqlcmd/Invoke-Sqlcmd; returns @{} (unknown) when neither is available
    # (then detection conservatively flags create-needed for absent tables only). REST/cert + MI.
    param([string]$ConnString)
    $cols = @{}
    if (-not "$ConnString".Trim()) { return $cols }
    $schema = Get-PimLockedSqlSchema

    # BUG-24, part 1 -- AUTHENTICATE THE WAY THE PRODUCT DOES.
    # This used to hand the connection string straight to Invoke-Sqlcmd with no access
    # token, so an Azure SQL server with Entra-only auth answered
    #     Login failed for user ''                       (no auth in the string), or
    #     Login failed for user '<token-identified principal>'   (whatever the ambient
    #                                                             credential chain picked)
    # and the engine's configured SPN + certificate -- the identity that IS the server's
    # Entra admin -- was never used. Mint the token explicitly and set it on the
    # connection, exactly as New-PimSqlConnection does for the engine.
    # Same helper as the APPLY path -- one token source, so the two cannot diverge again. This used
    # to dot-source PIM-Rest.ps1 into its own function scope and mint its own token, which is
    # exactly how detect ended up working while apply did not.
    $sqlToken = Get-PimSqlAccessToken -ConnString $ConnString

    foreach ($table in @($schema.Keys)) {
        $parts = $table -split '\.'; $sch = $parts[0]; $tbl = $parts[-1]
        $q = "SET NOCOUNT ON; SELECT c.name FROM sys.columns c JOIN sys.objects o ON c.object_id=o.object_id JOIN sys.schemas s ON o.schema_id=s.schema_id WHERE s.name='$sch' AND o.name='$tbl';"
        $names = @()
        $readOk = $false
        try {
            $conn = New-Object System.Data.SqlClient.SqlConnection $ConnString
            if ($sqlToken) { $conn.AccessToken = $sqlToken }
            $conn.Open()
            try {
                $cmd = New-Object System.Data.SqlClient.SqlCommand $q, $conn
                $cmd.CommandTimeout = 60
                $rdr = $cmd.ExecuteReader()
                while ($rdr.Read()) { $names += "$($rdr.GetValue(0))" }
                $rdr.Close()
                $readOk = $true          # the QUERY ran: an empty result really means "no such table"
            } finally { $conn.Close() }
        } catch {
            Warn "could not read columns for $table : $($_.Exception.Message)"
        }
        # BUG-24, part 2 -- and the one that actually misled the operator:
        # a table we could NOT READ is UNKNOWN, not ABSENT. Reporting the login failure
        # above as "missing table(s) need create: pim.LocalAdmins" sent the deploy off to
        # create a table that already existed, then halted the whole roll with
        # "still reports drift after upgrade" -- while the real problem was authentication.
        # Marking it unknown keeps a connectivity failure from masquerading as schema drift.
        if ($readOk) { $cols[$table] = $names }        # may legitimately be empty = absent
        else         { $cols[$table] = $null }         # unknown -- caller must not call this "missing"
    }
    return $cols
}
function Test-MonitorDeployed {
    # Is the synthetic health monitor deployed? Best-effort: hosted = an ACA job named *monitor*;
    # community = a scheduled task. Returns $false (treat as needs-deploy) when it can't tell.
    if ($profile.isHosted -and (Have 'az')) {
        try { $j = @(az containerapp job list @azSubArgs -g $ResourceGroup --query "[].name" -o tsv 2>$null) | Where-Object { "$_" -like "*monitor*" } | Select-Object -First 1; if ("$j".Trim()) { return $true } } catch {}
        return $false
    }
    try { $t = Get-ScheduledTask -TaskName 'PIM-SyntheticMonitor' -ErrorAction SilentlyContinue; if ($t) { return $true } } catch {}
    return $false
}

# =============================================================================
# STEP 1 -- DETECT (always runs; the only step a detect-only run performs)
# =============================================================================
Step '1. DETECT'
$pulledVersion = if ("$ImageTag".Trim()) { $ImageTag } else { Get-PulledVersion }
$pulledHash    = Get-PulledManagerContentHash
$running       = Get-RunningManagerInfo
Info "pulled VERSION: $pulledVersion; running VERSION: $($running.version)"
Info "pulled GUI content hash: $pulledHash"
Info "running GUI content hash: $($running.contentHash)"

$guiPlan = Get-PimGuiUpdatePlan -PulledContentHash $pulledHash -RunningContentHash $running.contentHash `
            -PulledVersion $pulledVersion -RunningVersion $running.version
$deployedCols = Get-DeployedColumns -ConnString $SqlConnectionString
$sqlPlan = Get-PimSqlUpdatePlan -DeployedColumns $deployedCols -LockedSqlSchema (Get-PimLockedSqlSchema) `
            -DeployedSchemaVersion $running.version -PulledSchemaVersion $pulledVersion
$detection = Get-PimUpdateDetection -GuiPlan $guiPlan -SqlPlan $sqlPlan

Write-Host ""
Write-Host "  DETECTION:" -ForegroundColor Cyan
Write-Host ("    GuiUpdateRequired = {0}  ({1})" -f $detection.GuiUpdateRequired, $guiPlan.reason)
Write-Host ("    SqlUpdateRequired = {0}  ({1})" -f $detection.SqlUpdateRequired, $sqlPlan.reason)
Write-Host ""

$buildPlan = Get-PimBuildPlan -GuiUpdateRequired $detection.GuiUpdateRequired -Source $Source -ImageTag $pulledVersion -ImageRepo $ImageRepo -ManagedHosting $ManagedHosting
$monitorInPlace = Test-MonitorDeployed
$applyPlan = Get-PimUpdateApplyPlan -Detection $detection -BuildPlan $buildPlan -Source $Source -Apply:$Apply -MonitorInPlace $monitorInPlace -ManagedHosting $ManagedHosting

Write-Host "  PLAN:" -ForegroundColor Cyan
foreach ($s in $applyPlan.steps) { Write-Host ("    {0}. {1,-15} [{2}] {3}" -f $s.step, $s.name, $s.action, $s.detail) }
Write-Host ""

if ($DetectOnly) {
    Step 'DETECT-ONLY -- no changes made. Re-run with -Apply to act on the plan above.'
    # emit the machine-readable detect payload (the documented -DetectOnly contract).
    [pscustomobject]@{ SqlUpdateRequired = $detection.SqlUpdateRequired; GuiUpdateRequired = $detection.GuiUpdateRequired; details = $detection.details }
    return
}

if (-not $detection.AnyUpdateRequired -and $monitorInPlace) {
    Step 'Nothing to do (no GUI/SQL update + monitor already in place).'
    if (-not $SkipNotify) { Step '5. NOTIFY (noop -- suppressed: nothing changed)' }
    return
}

# =============================================================================
# APPLY path -- run each 'do' step; capture rollback target; rollback + notify on failure.
# =============================================================================
# 🔴 $verifyHealthy STARTS 'not-run', NOT $true. It used to be initialised TRUE, so any run that
# ended before the verify step -- an exception in build or deploy, a policy denial, anything --
# still printed `verifyHealthy=True` in its final summary. Measured at a live customer 2026-09-08:
# the post-deploy gate reported `RESULT: 0 pass, 3 fail`, Update-PimContainers threw, and the
# closing line read
#     outcome=failure (built=True deployed=False schemaUpgraded=False verifyHealthy=True)
# -- "verifyHealthy=True" over a gate that had just failed three assertions.
# That is BUG-130 exactly: a default that says "fine" when nothing looked. It is worse here than in
# the gate itself, because this line is what the notify mail quotes and what an operator reads last.
# 🪤 The honest value is a THIRD state, not $false: "did not run" and "ran and failed" are different
# facts, and collapsing them would make a legitimate no-op run look broken. Never initialise a
# health field to a healthy value.
$built = $false; $deployed = $false; $schemaUpgraded = $false; $verifyHealthy = 'not-run'
$prevRev = ''
$prevImage = ''
$outcome = 'success'; $errDetail = ''

try {
    # ---- BUG-28: refuse to aim a hosted deploy at nothing ---------------------
    # Checked HERE, not at parameter-bind time, because the detect-only and community/VM
    # paths need none of these -- failing them for a value they never use would be a
    # regression. This is the first point at which a missing target would matter.
    #
    # 🔒 An EMPTY resource group or registry is not "use the default": az would either
    # error obscurely or, with the old hard-coded values, quietly aim at the OPERATOR'S
    # estate. Fail with the parameter name and the env var that supplies it.
    if ($profile.isHosted) {
        $missing = @()
        if (-not "$ResourceGroup".Trim()) { $missing += '-ResourceGroup (or $env:PIM_ResourceGroup)' }
        if (-not "$AcrName".Trim())       { $missing += '-AcrName (or $env:PIM_AcrName)' }
        if ($missing.Count) {
            throw ("hosted deploy target not configured: supply " + ($missing -join ' and ') + ". " +
                   'These are per-customer infrastructure names and have NO default -- a default would ' +
                   "point at somebody else's estate (docs/REQUIREMENTS.md sec.33 BUG-28). On the " +
                   'sync-driven path they come from the customer manifest Args (PLAT-02).')
        }
    }

    # ---- capture pre-update revision (rollback target) BEFORE any change -----
    if ($profile.isHosted -and (Have 'az')) {
        try { $prevRev = @(az containerapp revision list @azSubArgs -g $ResourceGroup -n $ManagerApp --query "[?properties.active].name" -o tsv 2>$null) | Select-Object -First 1 } catch {}
        if (-not "$prevRev".Trim()) { try { $prevRev = az containerapp revision list @azSubArgs -g $ResourceGroup -n $ManagerApp --query "[0].name" -o tsv 2>$null } catch {} }
        Info "pre-update revision (rollback target): $(if($prevRev){$prevRev}else{'(unknown)'})"
        # 🔴 §53.6 -- AND THE IMAGE, because Container Apps garbage-collects inactive revisions.
        # This is the NIGHTLY, UNATTENDED path: by the time a rollback is needed, nobody is
        # watching, and the revision captured hours earlier may no longer exist. Measured on the
        # internal environment 2026-09-10 (only one revision survived), where the safety net could
        # only say "ROLL BACK BY HAND". The image is still in ACR and cannot be pruned away.
        try {
            $prevImage = "$(az containerapp show @azSubArgs -g $ResourceGroup -n $ManagerApp --query 'properties.template.containers[0].image' -o tsv 2>$null)".Trim()
        } catch { Write-Verbose "pre-update image read failed: $($_.Exception.Message)" }
        Info "pre-update image (rollback fallback): $(if($prevImage){$prevImage}else{'(unknown)'})"
    }

    # ---- 2026-09-13: THE RING GATE, before a build that could only be refused at the roll ------------
    # Ring >= 2: the version about to be built must be exactly what channel.json approves for the ring,
    # or this run stops HERE (outcome failure, notified) and nothing is built or rolled. Ring 0/1 and
    # environments with no ring pass. Checked again by the roller for callers that go there directly.
    # An override is audited to pim.AuditEvents when this run has the SQL connection.
    if ($profile.isHosted -and -not $SchemaOnly -and $detection.GuiUpdateRequired) {
        Step "   RING GATE: may $ResourceGroup take $($buildPlan.imageTag)?"
        [void](Assert-PimRollRingGate -ResourceGroup $ResourceGroup -SubscriptionArgs $azSubArgs -TargetVersion "$($buildPlan.imageTag)" `
                  -UpdateJobName $UpdateJobName -OverrideRingGate:$OverrideRingGate -Reason $Reason -Caller 'Invoke-PimUpdate' `
                  -SqlConnectionString $SqlConnectionString -PendingUpdateRing $PendingUpdateRing -PendingUpdateSourceUrl $PendingUpdateSourceUrl)
    }

    # ---- STEP 2 -- BUILD (only if GUI update needed) -------------------------
    if ($SchemaOnly) { Step '2. BUILD [skip -- -SchemaOnly: the caller wants the SQL half only]' }
    elseif (($applyPlan.steps | Where-Object { $_.name -eq 'build' }).do) {
        Step "2. BUILD ($($buildPlan.buildMode)) -> $ImageRepo`:$($buildPlan.imageTag)"
        $builder = Join-Path $here 'Build-PimManagerImage.ps1'
        if ($PSCmdlet.ShouldProcess("$ImageRepo`:$($buildPlan.imageTag)", 'build from pulled code')) {
            # BUG-128: $LASTEXITCODE is process-wide and reflects the last NATIVE command, not this
            # PowerShell script. Clear it first so a stale code from an earlier step cannot be read
            # back as "the build failed".
            $bldPool = @{}
            if ("$AcrAgentPool".Trim()) { $bldPool['AcrAgentPool'] = "$AcrAgentPool".Trim() }
            # 🔴 BUG-227 (measured 2026-09-20 rolling internal to 2.4.382): -SubscriptionId reached the ring
            # gate, the smoke, the rollback and the pin -- and NOT the build. `az acr build` therefore ran
            # against whatever subscription was ambient and failed as
            #     ERROR: The resource with name 'acrpimmfnpr' ... could not be found in subscription
            #            'sg-visualstudio 2 (DEMO) (7e867037-...)'
            # which names a missing REGISTRY and reads as "the registry is gone", when the registry was fine
            # and the context was wrong -- the exact misreading Connect-PimTenantAz.ps1 exists to prevent.
            # Both sides already had the parameter (Build-PimManagerImage scopes `az acr build` with it and
            # deliberately does NOT mutate the machine context); only the call was missing it. Same shape as
            # the AcrAgentPool gap above and as BUG-46: a value correct at the top of a script that never
            # reached the call.
            # 🪤 THE UNATTENDED PATH IS THE ONE THAT MATTERS: the nightly in-cloud updater goes through here
            # with no command line and no one watching, so on any host whose ambient context is another
            # subscription every 03:00 rebuild failed this way.
            if ("$SubscriptionId".Trim()) { $bldPool['SubscriptionId'] = "$SubscriptionId".Trim() }
            # 🔒 The clear stays IMMEDIATELY before the call on purpose (Test-PimUpdateContainers asserts
            # the proximity): anything between them is another chance for a stale native exit code to be
            # read back as "the build failed". Argument-building belongs above it, not between.
            $global:LASTEXITCODE = 0
            & $builder -ImageTag $buildPlan.imageTag -Source $buildSource -AcrName $AcrName -ImageRepo $ImageRepo @bldPool
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "Build-PimManagerImage.ps1 failed (exit $LASTEXITCODE)." }
            $built = $true
        }
    } else { Step '2. BUILD [skip -- no GUI update]' }

    # ---- STEP 3 -- DEPLOY: roll freshly-built image AND/OR apply SQL upgrade --
    Step '3. DEPLOY'
    if ($SchemaOnly -and $detection.GuiUpdateRequired) {
        Info 'roll SKIPPED -- -SchemaOnly. The caller rolls the code in its own step; rolling here would'
        Info '  deploy the SAME version twice in one run.'
    }
    if ($detection.GuiUpdateRequired -and -not $SchemaOnly) {
        $roller = Join-Path $here 'Update-PimContainers.ps1'
        if ($profile.isHosted) {
            Info "roll ACA to the freshly-built image $($buildPlan.imageTag) (NOT -SkipBuild -- the image is already built this run, so roll only)"
            # 🔴 FIRST-DEPLOY DEADLOCK. This step rolls the image and THEN applies the SQL schema
            # (see the SqlUpdateRequired block below). Update-PimContainers runs the post-deploy GUI
            # smoke gate at the end of its roll and THROWS on failure -- so on a first deploy into an
            # EMPTY database the sequence was:
            #   roll -> Manager boots with NO TABLES -> falls back to static/local store ->
            #   gate asserts "[store] SQL mode" -> FAILS -> throws -> the schema block below is
            #   NEVER REACHED -> re-running repeats it identically, forever.
            # Measured at a live customer 2026-09-08: "FAIL boot log shows [store] SQL mode",
            # "FAIL active instance is 'sql:<db>' (NOT local)", on a database whose schema had not
            # been created yet because this very step never got to create it.
            # 🔑 The caller already said not to verify here. Invoke-PimDeployAll invokes this script
            # with -SkipVerify precisely because ITS own order is schema -> code -> verify, and it
            # gates at its separate 'verify' step AFTER the schema exists. -SkipVerify was only
            # skipping step 4, while the roller kept gating inside step 3. Honour the caller's
            # intent and pass it down: no gate mid-schema-step, and the real gate still runs later.
            # 🔒 This does NOT weaken verification. Without -SkipVerify (a direct, unattended update
            # of an already-schema'd environment) the roller gates exactly as before.
            $rollGate = @{}
            if ($SkipVerify) { $rollGate['SkipSmoke'] = $true }
            # The roller re-checks the ring; forward the operator's override (and its reason) so an
            # audited override here is not refused one level down.
            if ($OverrideRingGate) { $rollGate['OverrideRingGate'] = $true; $rollGate['Reason'] = $Reason }
            if ($PendingUpdateRing -ge 0) { $rollGate['PendingUpdateRing'] = $PendingUpdateRing; $rollGate['PendingUpdateSourceUrl'] = $PendingUpdateSourceUrl }
            if ("$SubscriptionId".Trim()) { $rollGate['SubscriptionId'] = "$SubscriptionId".Trim() }
            if ("$UpdateJobName".Trim()) { $rollGate['UpdateJobName'] = $UpdateJobName }
            # BUG-228: the operator's answer to the BUG-55 desired-state gate, forwarded so the gate
            # can be answered from the path the `code` step and the nightly updater actually use.
            if ($AcceptBaselineChange) { $rollGate['AcceptBaselineChange'] = $true }
            if ($PSCmdlet.ShouldProcess("$($Apps -join ', ')", "roll -> $($buildPlan.imageTag)")) {
                & $roller @rollGate -ImageTag $buildPlan.imageTag -SkipBuild -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps -TickJobName $TickJobName
                if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "Update-PimContainers.ps1 (roll) failed (exit $LASTEXITCODE)." }
                $deployed = $true
            }
        } else {
            Info 'community: the freshly-built/packaged Manager is the local deploy (Build relaunched it).'
            $deployed = $true
        }
    } else { Info 'no GUI update -- no image roll.' }

    # 🔴 THE STORE'S OWN CORE TABLES ARE A THIRD SCHEMA SOURCE, AND NOTHING IN THE DEPLOY CALLED IT.
    # `pim.Rows`, `pim.Settings` and `pim.AuditEvents` are created by `Initialize-PimSqlStore`
    # (PIM-SqlStore.ps1) -- not by either shipped .sql file, and not by the conformance plan, whose
    # locked schema does not list them. So a first install ended up with the tables from
    # the shipped .sql files and NONE of these, and the next step died with
    #     Invalid object name 'pim.Settings'
    # Measured at a live customer 2026-09-08, one step past the base-schema fix.
    # 🪤 THIS RUNS OUTSIDE the SqlUpdateRequired branch, deliberately. That branch is driven by the
    # LOCKED schema, which does not contain these tables -- so on an environment whose locked tables
    # are already conformant it does not execute at all, and the store tables would stay missing
    # forever. The condition that gates a repair must be able to observe the thing being repaired.
    # Idempotent (every object is IF OBJECT_ID ... IS NULL), so it is cheap to run on every apply.
    if ($profile.isHosted -and "$SqlConnectionString".Trim()) {
        Step '   ensure the store core tables (pim.Rows / pim.Settings / pim.AuditEvents)'
        try {
            # The store mints its SQL token from the engine globals, exactly as Set-PimFeatureBaseline
            # does -- so give it the SAME identity this script already authenticates with, rather
            # than letting it fall through to an ambient credential that does not exist on a deploy
            # host. This is the one place the two token paths have to agree.
            if ("$SqlAdminClientId".Trim()) {
                $global:PIM_ClientId = "$SqlAdminClientId".Trim()
                if ("$TenantId".Trim()) { $global:PIM_TenantId = "$TenantId".Trim() }
                if     ("$SqlAdminCertThumbprint".Trim()) { $global:PIM_CertThumbprint = "$SqlAdminCertThumbprint".Trim() }
                elseif ("$SqlAdminClientSecret".Trim())   { $global:PIM_ClientSecret   = "$SqlAdminClientSecret".Trim() }
            }
            Initialize-PimSqlStore -ConnectionString $SqlConnectionString
            Info 'store core tables present.'
        } catch {
            throw ("could not create the store's core tables (pim.Rows / pim.Settings / pim.AuditEvents): " +
                   "$($_.Exception.Message) -- every later step that reads settings will fail with " +
                   "`"Invalid object name 'pim.Settings'`" until this succeeds.")
        }
    }

    # ---- BASE SCHEMA (sql/platform-schema.sql) -- every apply run that has a store ---------------
    # 🔴 2026-09-18 (IMP-46). Mirrors update-job-entry: the core tables first (above), then the shipped
    # file(s) behind Get-PimSchemaFileApplyPlan, then re-plan against what is REALLY there. OUTSIDE the
    # SqlUpdateRequired branch for the same reason as the core tables: a repair must not be gated on a
    # condition that cannot observe it (2.4.360 lost a guarded ADD on every existing store that way).
    # The locked schema is every table this file creates, so a store that had none of them is a FIRST
    # INSTALL -- which is what drives the Manager restart further down.
    $createdBaseSchema = $false
    if ("$SqlConnectionString".Trim()) {
        Step '   apply the shipped base schema (sql/platform-schema.sql; idempotent, store-aware guard)'
        if ($PSCmdlet.ShouldProcess('deployed DB', 'apply the shipped base schema')) {
            $absentBefore = @($sqlPlan.tables | Where-Object { $_.exists -eq $false })
            if ($absentBefore.Count) {
                Info ("base schema: {0} table(s) absent ({1}) -- this store is being CREATED" -f
                      $absentBefore.Count, (@($absentBefore | ForEach-Object { $_.table }) -join ', '))
            }
            [void](Invoke-PimBaseSchemaApply -ConnString $SqlConnectionString -SolutionRoot $solRoot)
            # Re-read and re-plan: the conformance pass below must run against what is now really in
            # the database, not against the emptiness it was planned from.
            $deployedCols = Get-DeployedColumns -ConnString $SqlConnectionString
            $sqlPlan = Get-PimSqlUpdatePlan -DeployedColumns $deployedCols -LockedSqlSchema (Get-PimLockedSqlSchema) `
                            -PulledSchemaVersion $pulledVersion -DeployedSchemaVersion $pulledVersion
            $stillAbsent = @($sqlPlan.tables | Where-Object { $_.exists -eq $false })
            if ($stillAbsent.Count) {
                throw ("the base schema was applied but these tables are still absent: " +
                       (@($stillAbsent | ForEach-Object { $_.table }) -join ', ') +
                       " -- the identity applying the schema may lack CREATE TABLE on this database.")
            }
            if ($absentBefore.Count) { $createdBaseSchema = $true }
        }
    }

    if ($detection.SqlUpdateRequired) {
        Step '   SQL schema upgrade (preflight -> apply -> re-preflight; idempotent, never destructive)'
        if (-not "$SqlConnectionString".Trim()) {
            Warn 'SqlUpdateRequired but no -SqlConnectionString -- emitting the guarded DDL plan only (apply it with your SQL deploy identity).'
            foreach ($tp in @($sqlPlan.tables | Where-Object { -not $_.conformant })) {
                if ($tp.exists) {
                    $cols = if ($deployedCols.ContainsKey($tp.table)) { @($deployedCols[$tp.table]) } else { @() }
                    $ddl = New-PimSqlConformanceDdl -Table $tp.table -Spec (Get-PimLockedSqlSchema)[$tp.table] -ActualColumns $cols
                    Write-Host $ddl.ddl
                } else { Warn "table $($tp.table) needs CREATE -- apply sql/platform-schema.sql with your SQL deploy identity." }
            }
            $schemaUpgraded = $false
        } else {
            # No longer gated on Invoke-Sqlcmd: Invoke-PimSqlDdl uses System.Data.SqlClient directly,
            # so the SqlServer module is not required and -- crucially -- the DDL is executed on a
            # connection carrying the SAME Entra access token the detect path uses.
            if ($PSCmdlet.ShouldProcess('deployed DB', 'apply idempotent schema upgrade')) {
                # 🔴 CREATE BEFORE ALTER. Nothing in the deploy path had ever applied the SHIPPED
                # base schema: this step only knew how to bring an EXISTING table into conformance,
                # and a missing table was merely *reported*. On a first install -- the only case where
                # it matters -- there is no operator standing by to run it, so the deploy failed at the
                # first ALTER. Measured at a live customer 2026-09-08: "Cannot find the object
                # pim.LocalAdmins". The CREATE now happens in the BASE SCHEMA step above
                # (Invoke-PimBaseSchemaApply), on every apply run, before this conformance pass --
                # and that step already re-planned $sqlPlan against what is really there.
                foreach ($tp in @($sqlPlan.tables | Where-Object { $_.exists -and -not $_.conformant })) {
                    $cols = @($deployedCols[$tp.table])
                    $ddl = New-PimSqlConformanceDdl -Table $tp.table -Spec (Get-PimLockedSqlSchema)[$tp.table] -ActualColumns $cols
                    # 🔴 §56.3a -- AN UNATTENDED UPDATE MUST NOT DESTROY DATA.
                    # The conformance builder emits `ALTER TABLE ... DROP COLUMN` for anything the
                    # locked spec lists as `deprecated`, and this path applied it verbatim. So
                    # adding one name to that list would drop the column -- and its data -- in
                    # EVERY customer, at 03:00, with nobody watching.
                    # 🪤 AND NO ROLLBACK COULD UNDO IT. Image rollback is safe precisely because
                    # schema change is additive: an older container simply ignores columns it does
                    # not know. A drop breaks that property and turns the nightly update into a
                    # one-way door -- the single thing this design cannot afford.
                    # 🔒 So refuse, name the columns, and stop. A destructive migration is an
                    # ATTENDED operation (the cutover ceremony owns that, with backups and an
                    # abort), and "nobody has written a deprecation yet" is not a safety mechanism.
                    if (@($ddl.plan.ToDrop).Count) {
                        throw ("SQL upgrade for $($tp.table) would DROP column(s): " +
                               (@($ddl.plan.ToDrop) -join ', ') +
                               ". An unattended update never destroys data -- no rollback could restore it. " +
                               "Apply this through the attended cutover ceremony, or remove the deprecation.")
                    }
                    Invoke-PimSqlDdl -ConnString $SqlConnectionString -Sql $ddl.ddl
                }
                # re-preflight: re-read columns and confirm conformant.
                $reCols = Get-DeployedColumns -ConnString $SqlConnectionString
                $rePlan = Get-PimSqlUpdatePlan -DeployedColumns $reCols -LockedSqlSchema (Get-PimLockedSqlSchema) -PulledSchemaVersion $pulledVersion -DeployedSchemaVersion $pulledVersion
                if ($rePlan.SqlUpdateRequired) { throw "SQL re-preflight still reports drift after upgrade: $($rePlan.reason)" }
                $schemaUpgraded = $true
                Info 'SQL upgrade applied + re-preflight clean.'
                # 🔴 THE MANAGER IS ALREADY RUNNING, AND IT BOOTED BEFORE THIS EXISTED.
                # Order within this script is build -> ROLL -> schema, so on a first install the
                # container starts against a database with no tables, resolves its store at
                # startup, finds nothing usable and comes up in STATIC (read-only) mode. Creating
                # the tables a few seconds later does not change a decision that was already made.
                # Nothing re-rolls it either: the 'code' step after this one compares the GUI
                # content hash, finds it identical to what is now running, and correctly does
                # nothing. So the deploy finishes with a Manager serving static content over a
                # perfectly good store -- HTTP 200, healthy to every resource-level check, and
                # wrong. That is the §42.2 fallback wearing the costume of a successful deploy.
                # Restarting the active revision is the whole fix: the app holds no state of its
                # own, so a restart is cheap and safe, and it is the only way the store decision
                # gets made again.
                if ($createdBaseSchema -and $profile.isHosted -and (Have 'az')) {
                    Step '   restart the Manager so it re-resolves its store (it booted before the schema existed)'
                    $active = @(az containerapp revision list @azSubArgs -g $ResourceGroup -n $ManagerApp `
                                    --query "[?properties.active].name" -o tsv 2>$null |
                                Where-Object { "$_".Trim() }) | Select-Object -First 1
                    if ("$active".Trim()) {
                        az containerapp revision restart @azSubArgs -g $ResourceGroup -n $ManagerApp --revision "$active".Trim() -o none 2>$null
                        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
                            Warn "could not restart $ManagerApp revision '$active' -- it may still be serving STATIC content over the new schema. Restart it before using the GUI."
                        } else {
                            Info "restarted $ManagerApp revision $active"
                        }
                    } else {
                        Warn "could not read the active revision of $ManagerApp -- restart it manually so it picks up the new schema."
                    }
                }
            }
        }
    } else { Info 'no SQL update needed.' }

    # ---- STEP 4 -- VERIFY: hosted smoke; auto-rollback on failure -----------
    if ($deployed -and -not $SkipVerify) {
        Step '4. VERIFY (hosted smoke: Test-PimManagerHostedSmoke.ps1)'
        $smoke = Join-Path $solRoot 'tests\live\Test-PimManagerHostedSmoke.ps1'
        $code = 0
        if (Test-Path $smoke) {
            # 🔴 BUG-130 -- THE SIXTH INSTANCE OF THE MISSING-PASSTHROUGH DEFECT, and the one that
            # made this summary line lie. This call passed NOTHING: no app, no resource group, no
            # subscription. The smoke's own defaults for those are EMPTY, so it ran
            # `az webapp show --resource-group` with no value, got "expected one argument" twice,
            # could obtain neither a live nor a boot-log reading, SKIPPED all three checks, and
            # exited 0 -- which Get-PimVerifyVerdict reads as Healthy. Every nightly run therefore
            # reported `verifyHealthy=True` off a gate that asserted NOTHING, and mailed that word
            # to the operator. Measured identically on mfnpr, EFIF and RIDE, 2026-09-07:
            #     RESULT: 0 pass, 0 fail, 3 skip, 0 n/a  ->  verify healthy=True (smoke exit 0)
            #
            # 🪤 The deploys were NOT unverified -- Update-PimContainers runs the SAME gate properly
            # a few steps earlier ("gate inputs: rg=... / PASSED (all probes ran)"). That is exactly
            # what made this so quiet: the real gate passed loudly, and this blind second one agreed
            # with it for no reason. A redundant check that always says yes is worse than none,
            # because it launders an absence of evidence into a green word in an email.
            #
            # Deliberately NOT adding -AsReleaseGate here: the roller already gates with it, and
            # making a skip fatal at this point would auto-roll-back a HEALTHY deploy whenever the
            # gate could not run for an environmental reason -- the BUG-102 failure, in reverse.
            # BUG-172: -SubscriptionId IS passed now -- the parameter exists (BUG-102, declared above), and
            # an unscoped smoke on mgmt1 reads another company's subscription. So is the version this
            # run rolled: the gate checks the app serves THAT, not whatever the working tree says.
            # 🔑 The smoke now exits 2 for "skipped -- NOT a pass" (it used to exit 0, which read as
            # Healthy). Still no -AsReleaseGate here, for the reason above: a skip is reported as
            # UNVERIFIED and never called healthy, but it does not roll back a roll the roller's own
            # release gate already passed.
            $smokeArgs = @('-App', $ManagerApp)
            if ("$ResourceGroup".Trim())  { $smokeArgs += @('-ResourceGroup', "$ResourceGroup".Trim()) }
            if ("$SubscriptionId".Trim()) { $smokeArgs += @('-SubscriptionId', "$SubscriptionId".Trim()) }
            if ("$($buildPlan.imageTag)".Trim() -match '^\d+\.\d+\.\d+') { $smokeArgs += @('-ExpectedVersion', "$($buildPlan.imageTag)".Trim()) }
            Info ("verify inputs: app={0} rg={1}" -f $ManagerApp, $(if ("$ResourceGroup".Trim()) { $ResourceGroup } else { '(NONE -- the gate cannot read the app)' }))
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $smoke @smokeArgs
            $code = $LASTEXITCODE
        } else {
            # 🔴 BUG-160 -- A MISSING GATE IS UNVERIFIED, NOT UNHEALTHY. This said "treating as
            # UNVERIFIED" and then set exit 1, which the verdict reads as a FAILED health check -- so it
            # auto-rolled-back a Manager that had just rolled fine. The public community edition ships
            # without tests/ (operator decision 2026-09-14), so EVERY public deploy hit it: measured on
            # the first public-edition install (S2 proof), which rolled back 2.4.359 for no reason.
            # Invoke-PimDeployAll and Update-PimContainers already treat an absent smoke as "not run".
            Warn "hosted smoke not found at $smoke -- UNVERIFIED (not a failure, no rollback). Verify the Manager in a browser."
            $code = $null
        }
        if ($null -eq $code) {
            $verifyHealthy = 'unverified'
            Info 'verify: UNVERIFIED (hosted smoke not present) -- the deploy stands'
        } else {
        $verdict = Get-PimVerifyVerdict -ExitCode $code -PreviousRevision $prevRev
        $verifyHealthy = $verdict.Healthy
        if ($verdict.State -eq 'unverified') {
            # BUG-172: exit 2 -- the smoke skipped a check. NOT a pass, and never reported as healthy.
            $verifyHealthy = 'unverified'
            Warn "verify: UNVERIFIED (smoke exit 2 -- a check was SKIPPED; a skip is not a pass). Not rolled back: the roll passed the roller's release gate. Verify the Manager before trusting this run."
        } else {
            Info "verify healthy=$verifyHealthy (smoke exit $code)"
        }
        }
        # 'unverified' (a string) is truthy, so a skipped smoke never takes the rollback branch below.
        if (($null -ne $code) -and -not $verifyHealthy) {
            $outcome = 'rolledback'; $errDetail = "post-deploy verification failed (smoke exit $code)"
            if ($verdict.rollback.action -eq 'rollback' -and $profile.isHosted) {
                Warn $verdict.rollback.reason
                Step "   AUTO-ROLLBACK -> $($verdict.rollback.revision)"
                $roller = Join-Path $here 'Update-PimContainers.ps1'
                if ($PSCmdlet.ShouldProcess($ManagerApp, "rollback to $($verdict.rollback.revision)")) {
                    # §53.6: the image anchor rides along, and is used only if the revision is gone.
                    $rbArgs = @{}; if ("$prevImage".Trim()) { $rbArgs['RollbackImage'] = "$prevImage".Trim() }; if ("$SubscriptionId".Trim()) { $rbArgs['SubscriptionId'] = "$SubscriptionId".Trim() }
                    & $roller -Rollback $verdict.rollback.revision -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps @rbArgs
                }
            } else {
                $errDetail += " -- NO rollback target captured; MANUAL rollback required"
            }
        }
    } elseif ($SkipVerify) { Step '4. VERIFY [skip -- -SkipVerify]' }
    else { Step '4. VERIFY [skip -- nothing deployed]' }
}
catch {
    $outcome = 'failure'; $errDetail = "$($_.Exception.Message)"
    Warn "UPDATE FAILED: $errDetail"
    # best-effort auto-rollback if we had captured a revision and deployed.
    # §53.6: EITHER anchor is enough to attempt a rollback -- the revision may already be gone.
    if ($deployed -and $profile.isHosted -and ("$prevRev".Trim() -or "$prevImage".Trim())) {
        Warn "attempting auto-rollback to $(if ("$prevRev".Trim()) { $prevRev } else { $prevImage })"
        try {
            $roller = Join-Path $here 'Update-PimContainers.ps1'
            $rbArgs = @{}; if ("$prevImage".Trim()) { $rbArgs['RollbackImage'] = "$prevImage".Trim() }; if ("$SubscriptionId".Trim()) { $rbArgs['SubscriptionId'] = "$SubscriptionId".Trim() }
            & $roller -Rollback "$prevRev".Trim() -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps @rbArgs
            $outcome = 'rolledback'
        } catch { Warn "auto-rollback also failed: $($_.Exception.Message)" }
    }
}

# =============================================================================
# STEP 4b -- ADVANCE THE IN-CLOUD UPDATER'S PIN (§53.4)
# =============================================================================
# 🔴 WITHOUT THIS, THIS SCRIPT AND THE IN-CLOUD UPDATER FIGHT EACH OTHER EVERY NIGHT, AN HOUR APART.
# `ca-pim-update` (§53) rolls its environment to a PINNED image -- a ring decision, deliberately not
# "whatever is newest". This script is the other half: it PULLS, BUILDS a new tag, and rolls forward.
# Both were armed on internal/EFIF/RIDE on 2026-09-10, at 03:00-03:40 and 04:00-04:40 respectively,
# which produces this, starting the first night after any release:
#     04:00  this script builds 2.4.31x and rolls the environment forward
#     03:00  next day, the cloud job rolls it BACK to the pinned 2.4.302
#     04:00  this script sees the content hash differ, REBUILDS, and rolls forward again
# -- a one-hour downgrade window and a wasted ACR build, every night, indefinitely.
#
# 🔑 The root cause is that the cloud job is a ROLLER, not a builder, so it can never learn about a
# version on its own. Disabling it is not the fix either (then nothing updates when this VM is gone,
# which is the entire point of §53); nor is teaching it to chase "newest tag", which would dissolve
# the ring pin it exists to honour. The builder is the only party that KNOWS a new image is approved,
# so the builder advances the pin. The pin can then never lag the last successful build, and the
# oscillation is gone by construction rather than by scheduling luck.
#
# 🔒 ONLY ON AN UNAMBIGUOUS SUCCESS. A pin advanced after a rollback would point the nightly job at
# the exact image this run just proved bad, and the cloud job would faithfully redeploy it at 03:00
# with nobody watching. `$outcome -eq 'success'` excludes both 'failure' and 'rolledback'; `$deployed`
# excludes a detect-only or no-change run, which must leave an existing pin exactly where it is.
if ($Apply -and $profile.isHosted -and $deployed -and $outcome -eq 'success' -and -not $SkipPinAdvance) {
    $pinImage = "$AcrName.azurecr.io/$ImageRepo" + ':' + "$($buildPlan.imageTag)".Trim()
    Step "4b. ADVANCE THE UPDATER PIN ($UpdateJobName -> $pinImage)"
    $pinSub = @(); if ("$SubscriptionId".Trim()) { $pinSub = @('--subscription', "$SubscriptionId".Trim()) }
    if (-not "$SubscriptionId".Trim()) {
        Info 'no -SubscriptionId / $env:PIM_SubscriptionId -- using the ambient az context for the pin only.'
    }
    try {
        # 🪤 LIST, NOT SHOW. `job show` on an absent job ERRORS, and "this environment has no
        # in-cloud updater yet" is the normal answer almost everywhere -- the same trap the §53
        # installer and the deploy path's image probe both had to learn.
        $hasJob = @(az containerapp job list @pinSub -g $ResourceGroup --query "[].name" -o tsv 2>$null) |
                  Where-Object { "$_".Trim() -eq $UpdateJobName }
        if (-not $hasJob) {
            Info "no '$UpdateJobName' in $ResourceGroup -- nothing to pin (this environment has no in-cloud updater)."
        }
        elseif ($PSCmdlet.ShouldProcess($UpdateJobName, "pin PIM_UPDATE_TARGET_IMAGE -> $pinImage")) {
            # 🔴 AN ARM OPERATION ALREADY IN FLIGHT IS A WAIT, NOT A FAILURE -- and this step runs
            # immediately after a roll, which is exactly when one is in flight. Measured on a live
            # host 2026-09-10: `job identity assign` spun for minutes and ended
            # "ERROR: Failed to provision revision ... Operation expired." Same bounded-backoff
            # shape the §53 installer uses, for the same reason.
            $deadline = (Get-Date).AddMinutes(5)
            while ((Get-Date) -lt $deadline) {
                $st = "$(az containerapp job show @pinSub -g $ResourceGroup -n $UpdateJobName --query properties.provisioningState -o tsv 2>$null)".Trim()
                if (-not $st -or $st -notmatch '(?i)InProgress|Deleting|Waiting') { break }
                Info "  an operation is still in progress ($st) -- waiting"
                Start-Sleep -Seconds 10
            }
            $pinned = $false
            foreach ($wait in @(0, 15, 30)) {
                if ($wait) { Info "  retrying in ${wait}s"; Start-Sleep -Seconds $wait }
                $global:LASTEXITCODE = 0
                # --set-env-vars ADDS OR UPDATES the named variable and leaves the rest alone.
                # --replace-env-vars would wipe PIM_SubscriptionId / PIM_ManagerApp / PIM_TickJobName
                # and leave a job that starts, reads nothing, and exits 2 every night.
                az containerapp job update @pinSub -g $ResourceGroup -n $UpdateJobName `
                    --container-name $UpdateJobName `
                    --set-env-vars "PIM_UPDATE_TARGET_IMAGE=$pinImage" -o none 2>$null
                if ($LASTEXITCODE -eq 0) { $pinned = $true; break }
            }
            # 🪤 READ IT BACK. A pin that silently did not take is INVISIBLE until 03:00 the next
            # night, when the job rolls the environment back to the old image and reports success at
            # having done so. An exit code is not evidence; the stored value is.
            # No `| [0]` in the JMESPath -- cmd.exe eats the pipe (az is az.cmd). Parse in PowerShell.
            $seen = ''
            try {
                $cj = az containerapp job show @pinSub -g $ResourceGroup -n $UpdateJobName `
                        --query "properties.template.containers" -o json 2>$null
                if ($cj) {
                    foreach ($c in (@($cj) -join '' | ConvertFrom-Json)) {
                        foreach ($v in @($c.env)) { if ($v.name -eq 'PIM_UPDATE_TARGET_IMAGE') { $seen = "$($v.value)".Trim() } }
                    }
                }
            } catch { }
            if ($seen -eq $pinImage) { Info "pin advanced + verified: $UpdateJobName -> $seen" }
            else {
                Warn "THE PIN DID NOT TAKE (job now reads '$(if($seen){$seen}else{'<none>'})', expected '$pinImage')."
                Warn "  '$UpdateJobName' will roll this environment BACK to that image on its next scheduled run."
                Warn "  Re-arm it with: tools/setup/Deploy-PimUpdateJob.ps1 -TargetImage $pinImage ..."
            }
        }
    } catch {
        # A failed pin must never fail an update that already built, rolled and verified -- but it
        # must be LOUD, because the consequence lands unattended, in the middle of the night.
        Warn "pin advance FAILED: $($_.Exception.Message)"
        Warn "  '$UpdateJobName' may roll this environment back on its next scheduled run -- re-arm it by hand."
    }

    # ---- 4b (ring). ADVANCE THE RING, FOR RINGS 0 AND 1 ONLY -------------------------------------
    # 🔴 THE PIN IS NOT ENOUGH ANY MORE. An updater with PIM_UPDATE_RING takes its target from
    # channel.json, NOT from the pin -- the ring wins (update-job-entry.ps1). EFIF and RIDE carry ring 1
    # since 2026-09-13, so without this the cloud job would roll them BACK to ring1.version the night
    # after this script built something newer: the exact oscillation 2.4.303 removed, reintroduced by
    # the ring. Ring 0/1 get every build by design, so the builder that just VERIFIED a version is the
    # party that approves it for that ring -- forward-only, read back.
    # 🔒 RING 2 AND ABOVE ARE NEVER WRITTEN HERE, OR ANYWHERE AUTOMATIC. Only the operator moves them.
    try {
        $ringEnv = Get-PimEnvironmentUpdaterEnv -ResourceGroup $ResourceGroup -SubscriptionArgs $pinSub -UpdateJobName $UpdateJobName
        $ringRaw = if ($ringEnv.ok -and $ringEnv.found -and $ringEnv.env.Contains('PIM_UPDATE_RING')) { "$($ringEnv.env['PIM_UPDATE_RING'])".Trim() } else { '' }
        # IMP-36: the ONE ring parser (_PimUpdateRing.ps1), not a local copy of the range.
        $ringNum = ConvertTo-PimUpdateRingNumber $ringRaw
        if (-not $ringEnv.ok) { Warn "ring advance: could not read '$UpdateJobName' ($($ringEnv.reason)) -- channel.json NOT touched." }
        elseif (-not $ringRaw) { Info 'ring advance: this environment follows no ring -- channel.json not touched.' }
        elseif ($null -eq $ringNum) { Warn "ring advance: PIM_UPDATE_RING='$ringRaw' is not a ring -- channel.json NOT touched." }
        elseif ($ringNum -ge 2) {
            Info "ring advance: ring $ringNum -- channel.json is NOT touched. Only the operator moves ring 2 and above."
        } else {
            $ringN = $ringNum
            $srcTpl = if ($ringEnv.env.Contains('PIM_UPDATE_SOURCE_URL')) { "$($ringEnv.env['PIM_UPDATE_SOURCE_URL'])".Trim() } else { '' }
            if (-not $srcTpl) { Warn "ring advance: ring $ringN but no PIM_UPDATE_SOURCE_URL on '$UpdateJobName' -- channel.json location unknown, NOT advanced." }
            elseif ($PSCmdlet.ShouldProcess("channel.json ring$ringN", "advance -> $($buildPlan.imageTag)")) {
                $adv = Update-PimRingChannelVersion -SourceUrlTemplate $srcTpl -Ring $ringN -VerifiedVersion "$($buildPlan.imageTag)" `
                           -SubscriptionId $ChannelSubscriptionId -AzureConfigDir $ChannelAzureConfigDir
                if ($adv.ok) { Info "ring advance: $($adv.action) -- $($adv.reason)" }
                else {
                    Warn "ring advance NOT done ($($adv.action)): $($adv.reason)"
                    Warn "  '$UpdateJobName' follows ring $ringN and will roll this environment to ring$ringN.version on its next run."
                    Warn ("  Advance it: set ring{0}.version in pim-src/channel.json to {1} (the version this run verified)." -f $ringN, $buildPlan.imageTag)
                }
            }
        }
    } catch {
        Warn "ring advance FAILED: $($_.Exception.Message)"
    }
}
elseif ($Apply -and $profile.isHosted -and $deployed -and $outcome -ne 'success') {
    Info "pin NOT advanced -- outcome '$outcome'. The updater keeps its previous target, deliberately:"
    Info '  advancing it now would point tonight''s unattended run at the image this run just rejected.'
}

# =============================================================================
# STEP 5 -- NOTIFY (always email the outcome -- success OR failure -- reuse mailer)
# =============================================================================
Step "5. NOTIFY (email outcome '$outcome' to $(if("$Recipient".Trim()){$Recipient}else{'<no recipient configured>'}) via Send-PimNotifyMail)"
$notifyPlan = Get-PimNotifyPlan -Outcome $outcome -Source $buildSource -Detection $detection `
                -Built $built -Deployed $deployed -SchemaUpgraded $schemaUpgraded `
                -ImageTag $buildPlan.imageTag -Recipient $Recipient -ErrorDetail $errDetail
Info "subject: $($notifyPlan.subject)"
if ($SkipNotify) { Warn 'notify SKIPPED (-SkipNotify).' }
# BUG-28: no recipient => SKIP. Notification is not the deploy, so this must not fail a
# healthy update -- but it must never fall back to an operator mailbox either, which is
# what the old hard-coded default did.
elseif (-not "$Recipient".Trim()) {
    Warn 'notify SKIPPED -- no recipient. Set -Recipient or $env:PIM_NotifyRecipient. (There is deliberately no default: a default would email somebody else.)'
}
elseif (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) {
    Warn 'Send-PimNotifyMail not available (PIM-Notify.ps1 not loaded / no Graph context) -- outcome NOT emailed.'
    Info 'WIRE-UP: this reuses the synthetic-monitor mail path (Send-PimNotifyMail). Configure $global:PIM_MailSender + Graph app-only Mail.Send.'
} else {
    if ($PSCmdlet.ShouldProcess($notifyPlan.recipient, "send '$($notifyPlan.type)' mail")) {
        $r = Send-PimNotifyMail -Type $notifyPlan.type -Tokens $notifyPlan.tokens -Recipient $notifyPlan.recipient
        Info ("mail sent={0} recipient={1} reason={2}" -f $r.sent, $r.recipient, $r.reason)
    }
}

# =============================================================================
# STEP 6 -- ENSURE HEALTH MONITORING (reuse the synthetic monitor; refresh if stale/missing)
# =============================================================================
Step '6. ENSURE HEALTH MONITORING (synthetic monitor: Manager+CEH health, mail-notify, debounced)'
$monPlan = Get-PimMonitorEnsurePlan -MonitorDeployed $monitorInPlace -IntervalMinutes $MonitorIntervalMinutes
Info "monitor action: $($monPlan.action) -- $($monPlan.reason) (interval $($monPlan.intervalMinutes)m)"
if ($monPlan.action -eq 'noop') {
    Info 'health monitor already in place + fresh -- nothing to do.'
} else {
    # reuse the synthetic-monitor deploy entry by INTERFACE. Default path tried if not supplied.
    $monScript = if ("$MonitorDeployScript".Trim()) { $MonitorDeployScript } else { Join-Path $here 'Deploy-PimSyntheticMonitor.ps1' }
    if (Test-Path $monScript) {
        Step "   $($monPlan.action) synthetic monitor via $monScript"
        if ($PSCmdlet.ShouldProcess($monScript, $monPlan.action)) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $monScript -IntervalMinutes $monPlan.intervalMinutes -Recipient $Recipient
        }
    } else {
        Warn "synthetic-monitor deploy script not found ($monScript)."
        Info 'WIRE-UP: this REUSES feat/synthetic-monitor (do NOT duplicate the monitor). Once that branch is on main,'
        Info "         pass -MonitorDeployScript <its deploy entry> (default tried: tools/setup/Deploy-PimSyntheticMonitor.ps1)."
        Info "         It deploys the monitor that checks Manager + CEH health every 5-15m and emails $Recipient on failure (debounced)."
    }
}

Write-Host ""
Step "DONE. outcome=$outcome (built=$built deployed=$deployed schemaUpgraded=$schemaUpgraded verifyHealthy=$verifyHealthy)"
if ($outcome -eq 'failure' -or $outcome -eq 'rolledback') { exit 1 }
# BUG-25: SAY SO EXPLICITLY ON SUCCESS.
# This used to just fall off the end, leaving $LASTEXITCODE at whatever the last native
# command in this script happened to set -- typically a best-effort `az ... 2>$null` probe
# that legitimately returned non-zero. Invoke-PimDeployAll infers the step's verdict from
# exactly that variable, so a COMPLETELY SUCCESSFUL update was read as a failed step:
#     outcome=success (built=True deployed=True verifyHealthy=True)
#     -> ok=False ran=True
#     step 'code' FAILED -- halting the deploy.
#     ROLLBACK: code -> reactivate prior ACA revision ...
# It then tried to ROLL BACK A HEALTHY FLEET, and only a missing-parameter bug in the
# rollback path stopped it. An explicit 0 makes success unambiguous for every caller.
exit 0
