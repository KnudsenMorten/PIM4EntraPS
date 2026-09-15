#Requires -Version 5.1
<#
.SYNOPSIS
    Open the PIM4EntraPS graph mapper (v0.2 -- editor).

.DESCRIPTION
    Serves the PIM4EntraPS Manager: reads the desired state (the 14 Definition +
    Assignment entities) from the SQL store (pim.Rows), transforms it into a
    node/edge JSON model, and serves it through an HTTP API to the single-page
    editor.

    🔒 SQL-ONLY (operator, 2026-09-12). The Manager has no file store: no CSV
    data, no settings/access files, no static HTML export. It REFUSES TO START
    without a reachable SQL store, in every mode -- set PIM_SqlServer +
    PIM_SqlDatabase, or PIM_SqlConnectionString, or the Key Vault pointer.

    Run modes:

      -Server (default)
          Starts a localhost-only HttpListener on a random free port,
          serves the SPA, exposes REST endpoints for grid editing and
          save-back. The server lives only while the browser tab is open
          (heartbeat timeout) and only accepts requests carrying a
          per-session bearer token generated at launch.

      -Hosted
          24/7 behind Easy Auth (App Service / Container Apps).

      -RefreshTenantLists
          Refresh the tenant-list cache and exit.

    All writes go to SQL (pim.Rows / pim.Settings) through the review flow.

.PARAMETER Server
    Default. Start the local editor server.

.PARAMETER NoLaunch
    Don't open the browser. Print the URL to stdout. Useful for headless /
    smoke tests.

.PARAMETER Port
    Force a specific port instead of picking a random free one. The
    server still binds to 127.0.0.1 only. Optional.

.EXAMPLE
    $env:PIM_SqlServer = '<server>'; $env:PIM_SqlDatabase = '<db>'
    .\Open-PimManager.ps1
    # Default: server mode on the SQL store, random port, opens browser.

.NOTES
    Security model (server mode):
      * Listener binds 127.0.0.1 only -- never reachable from another host.
      * A random per-session bearer token (new GUID at every start) is
        embedded in the served HTML and required on every /api/* call.
        Without the token, the API returns 401.
      * Server self-terminates after 30 seconds without a /api/heartbeat
        ping -- closing the browser tab kills the process.
      * No third-party deps; pure .NET HttpListener + System.IO.

    PowerShell 5.1 compatible. Cytoscape + dagre are CDN-loaded by the HTML
    (same as v0.1).
#>[CmdletBinding(DefaultParameterSetName='Server')]
param(
    [Parameter(ParameterSetName='Server')]
    [switch]$Server,

    [switch]$NoLaunch,

    [Parameter(ParameterSetName='Server')]
    [int]$Port = 0,

    # HOSTED mode (24/7 on App Service for Containers / Container Apps). Binds all
    # interfaces (http://+:<PORT>), never self-exits, and trusts the App Service
    # Easy Auth principal header (X-MS-CLIENT-PRINCIPAL-NAME) for identity instead
    # of the Windows user. The per-session token is STILL required on /api (kept as
    # a second factor). Only enable behind Easy Auth + private inbound -- the app
    # manages tier-0. Also enabled by env PIM_HOSTED=1; port from PORT/WEBSITES_PORT.
    [Parameter(ParameterSetName='Server')]
    [switch]$Hosted,

    # CLI mode: refresh the tenant-list cache (entra-roles, AUs, PIM groups,
    # azure scopes) by calling Microsoft Graph + Az with the engine SPN, then
    # exit. Does NOT start the server or open a browser. Use this in a
    # scheduled task or from a customer bootstrap before launching the UI.
    [Parameter(ParameterSetName='Refresh')]
    [switch]$RefreshTenantLists,

    # SQL database to bind at startup, as 'sql:<db>' (see /api/instances). Instances are SQL databases
    # on the configured server only -- the folder instances (instances.custom.json, -ConfigRoot) are
    # gone with the file store (2026-09-12). Extra databases are listed in $env:PIM_SqlDatabases.
    [string]$Instance,
    # Bootstrap the AutomateITPS platform connection (bootstrap cert -> Key
    # Vault -> Modern SPN -> Graph + Az app-only) in THIS process before
    # starting, so the Revoke tab + tenant-list refresh work without running a
    # baseline engine first. Requires FUNCTIONS\AutomateITPS in the repo and a
    # bootstrap/platform-config.json (the standard mgmt-box setup).
    [switch]$ConnectPlatform
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Paths + constants
# ---------------------------------------------------------------------------

$solutionRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)  # ...\PIM4EntraPS
$template     = Join-Path $PSScriptRoot 'pim-manager.html'
$tenantSync   = Join-Path $PSScriptRoot '_tenantSync.ps1'
$validator    = Join-Path $PSScriptRoot '_validator.ps1'


# Shared date-expression resolver (engine/_shared/PIM-DateExpression.ps1) --
# powers the /api/resolve-date live preview; the validator dot-sources the
# same file so GUI, validator and engine agree.
$_dateExprLib = Join-Path $solutionRoot 'engine\_shared\PIM-DateExpression.ps1'
if (Test-Path -LiteralPath $_dateExprLib) { . $_dateExprLib }

# IMP-03: the ONE visible way to swallow a non-fatal error. Loaded early so every
# decision path below (auth, gating, store reads) can report instead of vanishing.
$_swallowLib = Join-Path $solutionRoot 'engine\_shared\PIM-Swallow.ps1'
if (Test-Path -LiteralPath $_swallowLib) { . $_swallowLib }

# HOSTED principal authentication (engine/_shared/PIM-HostedAuth.ps1) -- SEC-01.
# Verifies that a request's identity actually came from the auth edge instead of
# trusting the X-MS-CLIENT-PRINCIPAL-NAME header on sight. Pure decision functions;
# see REQUIREMENTS §33.3 SEC-01 and docs/TESTS.md.
$_hostedAuthLib = Join-Path $solutionRoot 'engine\_shared\PIM-HostedAuth.ps1'
if (Test-Path -LiteralPath $_hostedAuthLib) { . $_hostedAuthLib }

# Offline Pro licensing (engine/_shared/PIM-License.ps1) -- powers the
# Governance license panel (/api/license). Core Manager features never gate.
$_licenseLib = Join-Path $solutionRoot 'engine\_shared\PIM-License.ps1'
if (Test-Path -LiteralPath $_licenseLib) { . $_licenseLib }

# Locked-schema + data conformance (engine/_shared/PIM-SchemaConformance.ps1) --
# the instance-load preflight conforms migrated CSV data to the locked structure
# (drops deprecated columns like TierLevel, migrates TierLevel->Purpose first).
$_schemaConfLib = Join-Path $solutionRoot 'engine\_shared\PIM-SchemaConformance.ps1'
if (Test-Path -LiteralPath $_schemaConfLib) { . $_schemaConfLib }

# Delegated portal-admin scoping + permission-wizard auto-derivation
# (engine/_shared/PIM-PortalAccess.ps1, PIM-PermissionWizard.ps1) -- power
# /api/portal-access and /api/wizard/derive. Self-contained; dot-sourced standalone.
$_portalLib = Join-Path $solutionRoot 'engine\_shared\PIM-PortalAccess.ps1'
if (Test-Path -LiteralPath $_portalLib) { . $_portalLib }
$_wizardLib = Join-Path $solutionRoot 'engine\_shared\PIM-PermissionWizard.ps1'
if (Test-Path -LiteralPath $_wizardLib) { . $_wizardLib }
# §17 naming helpers (engine/_shared/PIM-Naming.ps1) -- Resolve-PimAdminName +
# the admin-type prefix / environment suffix resolvers the admin-name derivation
# (/api/wizard/derive target=admin) and the engine create-admin path share.
$_namingLib = Join-Path $solutionRoot 'engine\_shared\PIM-Naming.ps1'
if (Test-Path -LiteralPath $_namingLib) { . $_namingLib }
# Manager authoring helpers (bulk-attach / clone / AU / admin-import / admin-move /
# multi-delete / role-permission / LA-audit) -- power /api/authoring/*. Standalone.
$_authoringLib = Join-Path $solutionRoot 'engine\_shared\PIM-Authoring.ps1'
if (Test-Path -LiteralPath $_authoringLib) { . $_authoringLib }

# Approvals + delegation DEPTH (engine/_shared/PIM-Approvals.ps1 +
# PIM-DelegationDepth.ps1) -- power the two-approval split preview, local
# self-delegation gate and reachability-by-classification in the portal endpoints.
# Approvals must load before DelegationDepth (the latter builds on it). Both are
# pure decision libs; dot-sourced standalone so the endpoints work without SQL.
$_approvalsLib = Join-Path $solutionRoot 'engine\_shared\PIM-Approvals.ps1'
if (Test-Path -LiteralPath $_approvalsLib) { . $_approvalsLib }
$_delegLib = Join-Path $solutionRoot 'engine\_shared\PIM-DelegationDepth.ps1'
if (Test-Path -LiteralPath $_delegLib) { . $_delegLib }

# Standalone sign-in-session revoke guard (engine/_shared/PIM-SessionRevoke.ps1,
# REQUIREMENTS §35.2) -- the PURE verdict behind POST /api/admin-sessions/revoke.
# Loaded AFTER PIM-Approvals/ApprovalGate so the real Test-PimRowIsBreakGlass is
# already defined and the lib's guarded fallback does not shadow it. The lib
# fails CLOSED if that predicate is missing, so a load-order regression refuses
# revokes rather than performing unguarded ones.
$_sessionRevokeLib = Join-Path $solutionRoot 'engine\_shared\PIM-SessionRevoke.ps1'
if (Test-Path -LiteralPath $_sessionRevokeLib) { . $_sessionRevokeLib }

# Directory-people lookup (engine/_shared/PIM-DirectorySearch.ps1, REQUIREMENTS
# §35.8) -- the PURE query builder + escaping behind GET /api/directory/people.
# The data source every people-picker in the Manager needs and none of them had.
$_dirSearchLib = Join-Path $solutionRoot 'engine\_shared\PIM-DirectorySearch.ps1'
if (Test-Path -LiteralPath $_dirSearchLib) { . $_dirSearchLib }

# Delegation Map risk overlay + search-result builder (engine/_shared/PIM-MapRisk.ps1,
# REQUIREMENTS §28 [M8]) -- pure functions over the SAME graph model the Map
# renders. Power /api/map-risk + /api/map-search. Dot-sourced standalone (no SQL).
$_mapRiskLib = Join-Path $solutionRoot 'engine\_shared\PIM-MapRisk.ps1'
if (Test-Path -LiteralPath $_mapRiskLib) { . $_mapRiskLib }

# Tier-impact report (engine/_shared/PIM-TierImpact.ps1, REQUIREMENTS §23 /
# ROADMAP #24) -- pure function over the SAME graph model the Map renders:
# every user with ANY path (incl. indirect via nested groups) to a Tier-0/Tier-1
# target. Powers /api/tier-impact. Dot-sourced standalone (no SQL); reuses the
# PIM-MapRisk reach helpers loaded above.
$_tierImpactLib = Join-Path $solutionRoot 'engine\_shared\PIM-TierImpact.ps1'
if (Test-Path -LiteralPath $_tierImpactLib) { . $_tierImpactLib }

# Workload live-crawl map + reconciliation (engine/_shared/PIM-WorkloadMap.ps1) --
# the engine/scheduler writes a per-instance crawl-map cache; the GUI reads it +
# reconciles each desired PIM-Assignments-Workloads row (mapped|missing|exempted)
# for the Delegation Map's workload-target chips. Pure on the read path (no SQL,
# no network); the crawl WRITER is called only by the discovery/scheduler sweep.
$_workloadMapLib = Join-Path $solutionRoot 'engine\_shared\PIM-WorkloadMap.ps1'
if (Test-Path -LiteralPath $_workloadMapLib) { . $_workloadMapLib }

# Pure-REST token core (engine/_shared/PIM-Rest.ps1) -- dot-sourced into THIS
# (script) scope so the MI/SQL token mint runs in the same scope as the storage
# block + New-PimSqlConnection (and, on Windows headless, the Write-Host shim).
$_restLib = Join-Path $solutionRoot 'engine\_shared\PIM-Rest.ps1'
if (Test-Path -LiteralPath $_restLib) { . $_restLib }

# SQL-only data layer (engine/_shared/PIM-SqlStore.ps1 + its change-queue dep) --
# powers the SQL storage backend. Raw ADO.NET; connection string resolved from
# KV / in-memory, never a file.
$_queueLib = Join-Path $solutionRoot 'engine\_shared\PIM-ChangeQueue.ps1'
if (Test-Path -LiteralPath $_queueLib) { . $_queueLib }
$_sqlLib = Join-Path $solutionRoot 'engine\_shared\PIM-SqlStore.ps1'
if (Test-Path -LiteralPath $_sqlLib) { . $_sqlLib }
# Readable change-queue entries ("need real names", 2026-09-12) -- pure formatters for /api/queue
# and the names stored on a queued action at enqueue time.
$_queueDisplayLib = Join-Path $solutionRoot 'engine\_shared\PIM-QueueDisplay.ps1'
if (Test-Path -LiteralPath $_queueDisplayLib) { . $_queueDisplayLib }
# PIM policy templates live in SQL (pim.Settings 'PolicyTemplates'), seeded once from the shipped
# templates on a fresh store (never overwritten -- BUG-55). The validator reads that store.
$_policyTplStoreLib = Join-Path $solutionRoot 'engine\_shared\PIM-PolicyTemplateStore.ps1'
if (Test-Path -LiteralPath $_policyTplStoreLib) { . $_policyTplStoreLib }
$_policyBaselineLib = Join-Path $solutionRoot 'engine\_shared\PIM-PolicyBaseline.ps1'
if (Test-Path -LiteralPath $_policyBaselineLib) { . $_policyBaselineLib }

# Safe, reversible commits for Review & Save (engine/_shared/PIM-CommitBackup.ps1,
# REQUIREMENTS.md s28 [M1]) -- timestamped backup before every commit, all-or-
# nothing transactional apply with rollback-on-failure, and operator undo. Depends
# on PIM-SqlStore.ps1 (above) for the SQL backup adapter. Powers /api/backups/*.
$_backupLib = Join-Path $solutionRoot 'engine\_shared\PIM-CommitBackup.ps1'
if (Test-Path -LiteralPath $_backupLib) { . $_backupLib }

# Onboarding convenience flows (engine/_shared/PIM-Onboarding.ps1) -- guest invite
# INTO the delegation model + self-service consultant enable/disable. Both produce
# change-queue records for Review & Save (engine stays the only writer); depends on
# PIM-ChangeQueue.ps1 (above) + PIM-PortalAccess.ps1. Power /api/onboarding/*.
$_onboardLib = Join-Path $solutionRoot 'engine\_shared\PIM-Onboarding.ps1'
if (Test-Path -LiteralPath $_onboardLib) { . $_onboardLib }

# Lifecycle / Governance pure helpers (engine/_shared/PIM-Governance.ps1) -- the
# shared, KV-backed break-glass verify (constant-time + lockout + TTL clamp) and
# the lifecycle-calendar / access-review decision helpers the GUI surfaces.
$_govLib = Join-Path $solutionRoot 'engine\_shared\PIM-Governance.ps1'
if (Test-Path -LiteralPath $_govLib) { . $_govLib }

# Permission health (engine/_shared/PIM-PermissionHealth.ps1) -- the PURE verdict behind
# /api/permissions-health and the portal's "Verify permissions" button. A missing Graph app-role
# never announces itself: Graph answers 403, a provider swallows it, and the operator sees a DOMAIN
# sentence ("no member policy for '<group>'") that reads like a data problem while the deploy and
# every tick report success. This compares what the RUNTIME identity holds against what the code
# needs, so the portal can say so out loud. (REQUIREMENTS §63.6.)
$_permLib = Join-Path $solutionRoot 'engine\_shared\PIM-PermissionHealth.ps1'
if (Test-Path -LiteralPath $_permLib) { . $_permLib }

# Approval-gated offboarding + revoke control plane (engine/_shared/PIM-ApprovalGate.ps1)
# -- the MAKER/CHECKER approval queue (REQUIREMENTS §13/§27 H3/H4). Powers the new
# Approvals tab + endpoints: New-/Add-/Get-PimApprovalRequest (maker), Set-PimApprovalDecision
# (checker), Test-PimApprovalSeparationOk (maker≠checker), Get-PimOffboardSequencePlan (the
# guided offboard plan shown before approval). PURE decision functions + a thin persistence
# adapter that prefers Get-/Set-PimSetting -> SQL pim.Settings (we provide the shim below so
# approvals persist through the SAME store the Manager uses), JSON-file + in-memory fallback.
# Dot-sourced standalone so the endpoints work without SQL. NO auto-execute path lives here:
# this GUI is the approval gate -- offboarding/revoke NEVER fire automatically.
$_approvalGateLib = Join-Path $solutionRoot 'engine\_shared\PIM-ApprovalGate.ps1'
if (Test-Path -LiteralPath $_approvalGateLib) { . $_approvalGateLib }

# Maker/checker SECOND-PERSON approval on SENSITIVE authoring/onboarding
# (engine/_shared/PIM-SensitiveAuthoring.ps1, REQUIREMENTS s28 [M4]). PURE classifier
# (Get-PimAuthoringSensitivity: privileged-role attach / guest-into-privileged-group /
# disable+offboard) + COMMIT gate (Test-PimAuthoringCommitAllowed) layered on the SAME
# ApprovalGate machinery above (an 'authoring' approval request; maker!=checker enforced;
# once-only latch). Powers /api/authoring/sensitivity. Loads after PIM-ApprovalGate.ps1
# (it calls Test-PimApprovalApprovedFor) and after PIM-Authoring.ps1.
$_sensAuthLib = Join-Path $solutionRoot 'engine\_shared\PIM-SensitiveAuthoring.ps1'
if (Test-Path -LiteralPath $_sensAuthLib) { . $_sensAuthLib }

# Server-side WRITE GUARDS (engine/_shared/PIM-ManagerWriteGuards.ps1, Batch 1:
# server-side enforcement + safety guards). PURE decision helpers the write paths
# call so the GUI is never the only enforcement boundary:
#   * Test-PimPortalRowsInScope -- re-validate EVERY affected/removed row against
#     the caller's portal tier/level/service/scope (stops delete-by-omission of an
#     out-of-scope row); SuperAdmin bypasses scope (as everywhere).
#   * Test-PimCommitDeltaGuard  -- empty-set / large-delta safety net on commit +
#     restore (mirrors the engine disable-guard; the 53-user mass-disable precondition).
# Loads AFTER PIM-PortalAccess.ps1 (it calls Get-PimGroupFacets / Test-PimPortalCan*).
$_writeGuardLib = Join-Path $solutionRoot 'engine\_shared\PIM-ManagerWriteGuards.ps1'
if (Test-Path -LiteralPath $_writeGuardLib) { . $_writeGuardLib }

# Alert FEED + recorded-send proof (engine/_shared/PIM-AlertFeed.ps1, REQUIREMENTS
# §26c / §28 [H2] + the [M5] residual). The PUSH side of the dashboard: every fired
# alert is recorded (when / which event / who was notified / whether delivery was
# recorded), so a break-glass "owners notified" claim is verifiable. Pure core +
# JSONL file adapter; dot-sourced standalone so the feed works without SQL.
$_alertFeedLib = Join-Path $solutionRoot 'engine\_shared\PIM-AlertFeed.ps1'
if (Test-Path -LiteralPath $_alertFeedLib) { . $_alertFeedLib }
# ALERT-01: the job-failure alert layer. Loaded here so Invoke-PimJobRunAlert exists
# in-process and resolves to Send-PimManagerAlert -- the full path (per-event toggles,
# debounce, outbound webhook, audit event, recorded-send feed) rather than the lean
# scheduler sender. Whichever process records the run raises the alert.
$_jobAlertLib = Join-Path $solutionRoot 'engine\_shared\PIM-JobAlert.ps1'
if (Test-Path -LiteralPath $_jobAlertLib) { . $_jobAlertLib }

# Outbound alert CHANNELS (engine/_shared/PIM-AlertChannels.ps1, REQUIREMENTS §26c
# "Alerting (email / Teams)" + §28 [H2] residual). A SECOND delivery channel beside
# email: an outbound webhook (Microsoft Teams Incoming Webhook / generic JSON). Pure
# render + URL safety here; the HTTPS POST is Send-PimWebhookAlert below. A configured
# webhook fires IN ADDITION to mail and its outcome is recorded in the same feed.
$_alertChanLib = Join-Path $solutionRoot 'engine\_shared\PIM-AlertChannels.ps1'
if (Test-Path -LiteralPath $_alertChanLib) { . $_alertChanLib }

# Bridge the ApprovalGate persistence chain (Get-/Set-PimSetting) onto the Manager's own
# settings store (Get-/Set-PimManagerSetting -> SQL pim.Settings when active, else the
# per-instance manager-settings.custom.json), so an approval raised/decided in the Manager
# is persisted in the SAME store the scheduler/engine read. Defined only if the engine
# didn't already provide Get-/Set-PimSetting (idempotent; never clobbers a real host).
if (-not (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) {
    function Get-PimSetting { param([Parameter(Mandatory)][string]$Name) Get-PimManagerSetting -Name $Name }
}
if (-not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) {
    function Set-PimSetting { param([Parameter(Mandatory)][string]$Name, [object]$Value) Set-PimManagerSetting -Name $Name -Value $Value }
}

# DB cutover ceremony + on-demand recalc change-detector + persistent-SQL / health
# guards (engine/_shared/PIM-Cutover.ps1). Gated CSV->SQL cutover ('/api/cutover'),
# the SQL change-detector that drives on-demand recalc, and the resilient /health
# state machine. Depends on PIM-SqlStore + PIM-SchemaConformance (loaded above).
$_cutoverLib = Join-Path $solutionRoot 'engine\_shared\PIM-Cutover.ps1'
if (Test-Path -LiteralPath $_cutoverLib) { . $_cutoverLib }

# Scheduler / job-runner read model (engine/_shared/PIM-Scheduler.ps1) -- the GUI
# Jobs tab reads the REAL scheduler job registry + run history through this lib
# (Get-PimJobsStatus / Get-PimJobRunLog). READ-ONLY here: the Manager never runs a
# job; it joins the configured schedule, persisted scheduler state (last/next run)
# and the bounded run-history ring the scheduler writes (shared store: SQL settings
# -> JSON sibling of the scheduler-state file -> in-memory). Powers /api/jobs[/log].
$_schedLib = Join-Path $solutionRoot 'engine\_shared\PIM-Scheduler.ps1'
if (Test-Path -LiteralPath $_schedLib) { . $_schedLib }

# Notifications / mailer (engine/_shared/PIM-Notify.ps1) -- the SAME render+send
# path the engine uses (Send-PimNotifyMail -> Graph Mail.Send, gated on
# $global:PIM_MailSender). Powers Home/Settings ALERTING (REQUIREMENTS §27 H2):
# Send-PimManagerAlert renders the 'alert-notice' template and fans it out to the
# configured recipients. Self-contained REST sender; with no sender it renders
# only (honest "configure to enable" state), never a fake send.
$_notifyLib = Join-Path $solutionRoot 'engine\_shared\PIM-Notify.ps1'
if (Test-Path -LiteralPath $_notifyLib) { . $_notifyLib }

# Classified engine item failures (engine/_shared/PIM-FailureCatalog.ps1) -- the SAME catalog the engine
# writes with, so the Manager shows exactly the cause/remedy/fixes the engine recorded.
$_failLib = Join-Path $solutionRoot 'engine\_shared\PIM-FailureCatalog.ps1'
if (Test-Path -LiteralPath $_failLib) { . $_failLib }

# MSP downlink surface (engine/_shared/PIM-DownlinkManager.ps1) -- powers the
# MSP Downlink tab: /api/downlink (per-relationship plan), /api/downlink/policy
# (the per-relationship projection rules) and /api/downlink/run (dry-run + apply).
# It COMPOSES the pure core (Get-PimDownlinkPlan over the SIGNED baseline) and never
# decides anything itself, so the preview and the apply cannot disagree about who
# ends up holding privilege in a managed tenant.
$_downlinkLib = Join-Path $solutionRoot 'engine\_shared\PIM-DownlinkManager.ps1'
if (Test-Path -LiteralPath $_downlinkLib) { . $_downlinkLib }

# Operational-policy settings (engine/_shared/PIM-OperationalPolicy.ps1) -- the
# PURE normalize/validate/clamp helpers behind the Settings config surface
# (REQUIREMENTS [M7]): expiry-policy defaults, MFA-on-activation toggle, and
# connection-sanity config. Persisted to the SAME pim.Settings store the engine
# + jobs read (Get-/Set-PimOperationalPolicy below), so a GUI edit == runtime.
$_opPolicyLib = Join-Path $solutionRoot 'engine\_shared\PIM-OperationalPolicy.ps1'
if (Test-Path -LiteralPath $_opPolicyLib) { . $_opPolicyLib }

# Feature-flag registry (engine/_shared/PIM-FeatureFlags.ps1) -- the PURE catalog
# + resolver behind the "turn any Manager surface on/off in Settings" gradual-
# rollout feature. Persisted to the SAME pim.Settings store the GUI reads at boot
# (Get-/Set-PimFeatureFlags below), so GUI nav state == the persisted flag set.
$_featureFlagsLib = Join-Path $solutionRoot 'engine\_shared\PIM-FeatureFlags.ps1'
if (Test-Path -LiteralPath $_featureFlagsLib) { . $_featureFlagsLib }

# Governance PREVIEW gate (engine/_shared/PIM-GovernancePreview.ps1) -- "show the
# surface, safely OFF". The two security-sensitive governance surfaces (s27
# approval-gated offboarding/revoke; s28 [L2] exemption register on Template
# Rollout) render VISIBLE but disabled+inert by DEFAULT, so the surface can be
# reviewed without acting. Persisted under pim.Settings 'GovernancePreview' via the
# SAME Get-/Set-PimManagerSetting chokepoint, so the boot-injected GUI value == the
# value the endpoint guard reads (GUI state == actual behaviour). Distinct from the
# feature-flag registry, which HIDES a disabled surface; this one keeps it shown.
$_govPreviewLib = Join-Path $solutionRoot 'engine\_shared\PIM-GovernancePreview.ps1'
if (Test-Path -LiteralPath $_govPreviewLib) { . $_govPreviewLib }

# Feature catalog + gates (engine/_shared/PIM-FeatureCatalog.ps1, REQUIREMENTS s29/
# s30) -- the SINGLE source of truth for customizable capabilities (tier core|
# advanced, license free|pro, group/chapter, kill switch, dependsOn) and the gate
# functions (Test-PimFeatureEnabled/Licensed/Available) the engine + jobs + this GUI
# all read. Persisted under pim.Settings 'FeatureGates' + 'Edition' via the same
# Get-/Set-PimManagerSetting chokepoint, so GUI state == the gates the engine honours.
$_featureCatalogLib = Join-Path $solutionRoot 'engine\_shared\PIM-FeatureCatalog.ps1'
if (Test-Path -LiteralPath $_featureCatalogLib) { . $_featureCatalogLib }

# Deployment-scenario descriptor + resolvers (engine/_shared/PIM-ScenarioProfile.ps1,
# REQUIREMENTS §31). The SINGLE source of truth for the six supported topologies
# (S1-S6) and the pure resolvers that map a scenario onto the runtime knobs
# (hosting / SPN model / sync-file location + edition). Powers the Settings
# "Deployment scenario" card + GET/PUT /api/settings/scenario (persisted under
# pim.Settings 'Scenario' via the same Get-/Set-PimManagerSetting chokepoint).
$_scenarioProfileLib = Join-Path $solutionRoot 'engine\_shared\PIM-ScenarioProfile.ps1'
if (Test-Path -LiteralPath $_scenarioProfileLib) { . $_scenarioProfileLib }

# Discovery layer (engine/_shared/PIM-Discovery.ps1) -- REST enumerators + pure
# planners. Powers the Settings "Import departments from Entra" action
# (Import-PimEntraDepartments / Get-PimEntraDepartmentImportPlan); REST-only via
# PIM-Rest (loaded above), engine stays the writer for the persisted dept list.
$_discoveryLib = Join-Path $solutionRoot 'engine\_shared\PIM-Discovery.ps1'
if (Test-Path -LiteralPath $_discoveryLib) { . $_discoveryLib }

# Audit-trail query core (engine/_shared/PIM-AuditQuery.ps1, REQUIREMENTS s28 [H6]
# "Audit you can defend"). PURE, dependency-free helpers shared by GET /api/audit
# and GET /api/audit/export so the on-screen view and the export resolve the trail
# IDENTICALLY: full history (not the old ~3-month cap), a human before/after `change`
# per event, and an RFC-4180 CSV of the WHOLE filtered trail (not just the page).
# Read-only -- the audit FILE is the source of truth, nothing here writes.
$_auditQueryLib = Join-Path $solutionRoot 'engine\_shared\PIM-AuditQuery.ps1'
if (Test-Path -LiteralPath $_auditQueryLib) { . $_auditQueryLib }

# One id per Manager session -- groups this session's audit events (phase 6).
$script:PimManagerSessionId = [guid]::NewGuid().ToString('N')

# Identities already login-audited this session (one 'manager.login' per identity
# per server lifetime, so a page refresh doesn't spam the trail). Makes the
# Audit tab's Logins category real instead of a dead filter.
$script:PimLoginAudited = @{}

# Hosted (24/7 App Service) vs local (loopback) mode. In hosted mode identity is
# the per-request Easy Auth principal; locally it's the Windows user.
$script:PimHosted = [bool]$Hosted -or ("$env:PIM_HOSTED" -in @('1','true','yes'))
# SEC-15 / §36.3 phase 2 -- the engine libs are dot-sourced into this process and cannot see
# $script: scope, so the hosted fact is published globally. Read-PimPortalProfiles uses it to
# refuse the filesystem fallback for AUTHORIZATION data. Set from the SAME expression above, not
# re-derived, so the Manager and the libs can never disagree about whether this is hosted.
$global:PIM_Hosted = $script:PimHosted
$script:CurrentRequestPrincipal = $null

function Get-PimEntraJwks {
    # Fetch + cache the tenant's signing keys for LAYER 2 (signed-token verification).
    # Cached for an hour; a fetch failure returns the cached copy when we have one and
    # $null otherwise -- and $null makes Resolve-PimHostedPrincipal fail CLOSED in strict
    # mode, which is the correct outcome (never trust a token we cannot verify).
    [CmdletBinding()] param()
    $now = [datetime]::UtcNow
    if ($script:PimJwksCache -and $script:PimJwksFetchedUtc -and ($now -lt $script:PimJwksFetchedUtc.AddHours(1))) {
        return $script:PimJwksCache
    }
    $tenant = "$env:PIM_HOSTED_AUTH_TENANT".Trim()
    if (-not $tenant) { $tenant = "$($global:PIM_TenantId)".Trim() }
    if (-not $tenant) { $tenant = 'common' }
    $uri = "https://login.microsoftonline.com/$tenant/discovery/v2.0/keys"
    try {
        $jwks = Invoke-RestMethod -Method GET -Uri $uri -TimeoutSec 15 -ErrorAction Stop
        if ($jwks -and $jwks.keys) {
            $script:PimJwksCache = $jwks
            $script:PimJwksFetchedUtc = $now
            return $jwks
        }
    } catch {
        Write-Warning "JWKS fetch from $uri failed: $($_.Exception.Message)"
    }
    if ($script:PimJwksCache) { return $script:PimJwksCache }   # stale beats nothing
    return $null
}

function Get-PimEasyAuthPrincipal {
    # The Entra-authenticated caller, VERIFIED -- not merely asserted by a header (SEC-01).
    #
    # The old behaviour returned X-MS-CLIENT-PRINCIPAL-NAME on sight, so any client that
    # could reach this app could name itself a SuperAdmin from PIM_SuperAdmins. Identity
    # now goes through Resolve-PimHostedPrincipal:
    #   LAYER 1 (always) -- the auth-edge headers must be internally consistent; a name
    #     header without its companion X-MS-CLIENT-PRINCIPAL blob is a spoof signature.
    #   LAYER 2 (PIM_HOSTED_REQUIRE_SIGNED_TOKEN=1) -- the signed Entra token is verified
    #     (RS256 signature against the tenant JWKS + issuer/audience/expiry) and identity
    #     is taken from the VERIFIED token.
    # Returns '' for anything not positively trusted -- callers already fail closed on ''.
    param([Parameter(Mandatory)][System.Net.HttpListenerRequest]$Request)
    if (-not $script:PimHosted) { return '' }
    if (-not (Get-Command Resolve-PimHostedPrincipal -ErrorAction SilentlyContinue)) {
        # The auth lib is the enforcement boundary -- without it, fail CLOSED rather than
        # silently reverting to trusting the header.
        Write-Warning 'PIM-HostedAuth.ps1 not loaded -- refusing to resolve a hosted principal (failing closed).'
        return ''
    }
    $strict = Test-PimHostedSignedTokenRequired
    $jwks = $null
    if ($strict) { $jwks = Get-PimEntraJwks }
    $issuers = @("$env:PIM_HOSTED_AUTH_ISSUERS" -split '[,;]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $auds    = @("$env:PIM_HOSTED_EASYAUTH_AUD" -split '[,;]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $d = Resolve-PimHostedPrincipal `
            -PrincipalName "$($Request.Headers['X-MS-CLIENT-PRINCIPAL-NAME'])" `
            -PrincipalBlob "$($Request.Headers['X-MS-CLIENT-PRINCIPAL'])" `
            -SignedToken   "$($Request.Headers['X-MS-TOKEN-AAD-ID-TOKEN'])" `
            -Jwks $jwks -ExpectedIssuers $issuers -ExpectedAudiences $auds
    if ($d.trusted) { return "$($d.identity)" }
    # Rejections are security events -- never silent (BUG-01 lesson: a guard that trips
    # without telling anyone reads as a clean run).
    Write-Host ("  [auth] REJECTED principal [{0}] -- {1}" -f $d.layer, $d.reason) -ForegroundColor Red
    return ''
}

# ---------------------------------------------------------------------------
# Manager RBAC (LIFECYCLE-GOVERNANCE phase 7) -- Reader / Delegated / Admin / SuperAdmin.
# Identity = the Easy Auth principal (hosted) or the Windows user (local loopback).
# 🔒 SQL-ONLY (operator, 2026-09-12: "we dont use settings files anymore, sql only").
# The access model lives in pim.Settings['ManagerAccess'] = {"managerAccess":[{identity,role}]},
# written by tools/setup/Set-PimManagerAccess.ps1 or the Governance "Manage delegation" panel.
# Resolution, identical in EVERY mode:
#   1. SQL ManagerAccess (case-insensitive identity match; malformed JSON DENIES)
#   2. env PIM_SuperAdmins / PIM_Admins / PIM_DelegatedAdmins / PIM_HostedDefaultRole
#   3. otherwise Reader -- fail closed.
# 🪤 There used to be a local chain that read config/manager-access.custom.json, where a MISSING
# file made the launcher SuperAdmin. That turned "nobody configured access" into "everybody who can
# start the process is SuperAdmin", from a file no SQL audit sees. It is gone; a fresh store with no
# ManagerAccess is bootstrapped with PIM_SuperAdmins or Set-PimManagerAccess.ps1, and the GUI banner
# says so (Get-PimManagerAccessBootstrapState).
# The server is the enforcement boundary; the GUI only hides what the role cannot do.
# ---------------------------------------------------------------------------

function Get-PimManagerRole {
    # Hosted: the Easy Auth principal captured for THIS request. Local: Windows user.
    $who = if ($script:PimHosted -and "$script:CurrentRequestPrincipal".Trim()) { "$script:CurrentRequestPrincipal" }
           else { try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME } }
    if ($script:PimHosted -and -not "$who".Trim()) {
        # hosted with no authenticated principal = no Easy Auth in front -> deny.
        return @{ role = 'Reader'; identity = '<unauthenticated>'; source = 'hosted: no Easy Auth principal (fail closed)' }
    }
    $whoLc  = "$who".ToLowerInvariant()
    # 🔒 SEC-15 / §36.3 phase 2 -- SQL is the AUTHORITATIVE home for Manager RBAC, in every mode.
    # 📌 Env still works and is checked next, because ~every existing hosted deployment is
    # configured that way -- and it is the bootstrap for a fresh store with no ManagerAccess yet.
    try {
        $maRaw = $null
        # Live read when a SQL store is bound, so a grant written by Set-PimManagerAccess.ps1 while the
        # Manager runs applies within seconds -- cached briefly because this runs on every gate check.
        if ($script:PimSqlCs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
            $nowUtc = [datetime]::UtcNow
            if (-not $script:PimManagerAccessCache -or ($nowUtc - $script:PimManagerAccessCache.at).TotalSeconds -gt 15) {
                $live = Get-PimSqlSetting -ConnectionString $script:PimSqlCs -Name 'ManagerAccess'
                $script:PimManagerAccessCache = @{ at = $nowUtc; value = $live }
                if (-not ($global:PIM_NamingConventions -is [hashtable])) { $global:PIM_NamingConventions = @{} }
                if ($null -ne $live) { $global:PIM_NamingConventions['ManagerAccess'] = $live }
                elseif ($global:PIM_NamingConventions.ContainsKey('ManagerAccess')) { [void]$global:PIM_NamingConventions.Remove('ManagerAccess') }
            }
            $maRaw = $script:PimManagerAccessCache.value
        } elseif ($global:PIM_NamingConventions -is [hashtable] -and $global:PIM_NamingConventions.ContainsKey('ManagerAccess')) {
            $maRaw = $global:PIM_NamingConventions['ManagerAccess']
        }
        # 🔴 B1 (2026-09-10) -- A SUPERADMIN HELD IN SQL WAS TOLD THEY WERE A READER.
        # The boot hydration (Get-PimAllSqlSettings) returns every setting ALREADY JSON-PARSED.
        # This block then parsed it a SECOND time. ConvertFrom-Json on a PSCustomObject
        # stringifies it to `@{managerAccess=System.Object[]}` -- not JSON -- so the parse THREW
        # and the catch denied the caller as "INVALID", for EVERY identity, on every hosted
        # deployment that had used the supported Set-PimManagerAccess.ps1. Writing the access
        # model the correct way was what broke it, which is why it read as unexplainable.
        # 🔑 Parse only what is still TEXT. Same defect, same fix, at the portal profiles
        # (PIM-PortalAccess.ps1) and the persisted job scope (PIM-Scheduler.ps1).
        $ma = $null
        if ($null -ne $maRaw -and -not ($maRaw -is [string])) { $ma = $maRaw }
        elseif ("$maRaw".Trim()) {
            try { $ma = "$maRaw" | ConvertFrom-Json } catch {
                # Malformed authorization JSON DENIES; it does not degrade to env.
                Write-Warning "  [rbac] SQL 'ManagerAccess' is not valid JSON -- denying rather than falling back: $($_.Exception.Message)"
                return @{ role = 'Reader'; identity = $who; source = 'sql ManagerAccess INVALID (fail closed)' }
            }
        }
        if ($null -eq $ma) {
            # 🔑 SAY SO. A skipped authoritative source that falls through in silence is the
            # degrade-without-telling-anyone shape: the operator cannot tell "SQL said Reader" from
            # "SQL was never consulted".
            Write-Host '  [rbac] SQL ManagerAccess is absent/empty -- falling through to env vars.' -ForegroundColor DarkYellow
        } else {
            $entries = @(if ($ma.PSObject.Properties['managerAccess']) { $ma.managerAccess } else { $ma })
            foreach ($e in $entries) {
                if (-not "$($e.identity)".Trim()) { continue }
                if ("$($e.identity)".Trim().ToLowerInvariant() -eq $whoLc) {
                    $r = "$($e.role)".Trim()
                    if ($r -notin @('Reader','Admin','SuperAdmin','Delegated')) { $r = 'Reader' }
                    return @{ role = $r; identity = $who; source = 'sql ManagerAccess' }
                }
            }
            Write-Host ("  [rbac] SQL ManagerAccess holds {0} entr(y/ies); '{1}' is not one of them -- trying env vars." -f @($entries).Count, $who) -ForegroundColor DarkYellow
        }
    } catch { Write-Warning "  [rbac] SQL 'ManagerAccess' read failed: $($_.Exception.Message)" }
    $supers = @("$env:PIM_SuperAdmins" -split '[,;]+' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    $admins = @("$env:PIM_Admins"      -split '[,;]+' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    if ($supers -contains $whoLc) { return @{ role = 'SuperAdmin'; identity = $who; source = 'env PIM_SuperAdmins' } }
    if ($admins -contains $whoLc) { return @{ role = 'Admin';      identity = $who; source = 'env PIM_Admins' } }
    # Delegated (workload owner): sees ONLY the groups they own. Identity match here;
    # the data layer (Read-PimRows) scopes rows to groups whose Owners include them.
    $delegs = @("$env:PIM_DelegatedAdmins" -split '[,;]+' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    if ($delegs -contains $whoLc) { return @{ role = 'Delegated'; identity = $who; source = 'env PIM_DelegatedAdmins' } }
    if ("$env:PIM_HostedDefaultRole".Trim()) {
        $dr = "$env:PIM_HostedDefaultRole".Trim(); if ($dr -notin @('Reader','Admin','SuperAdmin')) { $dr = 'Reader' }
        return @{ role = $dr; identity = $who; source = 'env PIM_HostedDefaultRole' }
    }
    # 🔒 EVERY MODE STOPS HERE. No file is consulted, on any deployment shape: a file on a
    # filesystem deciding who is SuperAdmin is exactly SEC-15. Unknown principal == Reader.
    if ($script:PimHosted) {
        return @{ role = 'Reader'; identity = $who; source = 'hosted: not in SQL ManagerAccess or env (fail closed)' }
    }
    return @{ role = 'Reader'; identity = $who; source = 'not in SQL ManagerAccess or env (fail closed)' }
}

function Get-PimManagerAccessBootstrapState {
    <#
      Is ANY Manager access configured? Drives the GUI banner on a fresh store: an environment
      where SQL ManagerAccess is empty and no PIM_SuperAdmins/PIM_Admins env var is set has
      nobody who can save a change, and that must be said on screen with the remedy -- not
      discovered from a 403 on a change somebody already composed.
    #>
    $entries = 0
    try {
        $raw = $null
        if ($script:PimSqlCs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
            $raw = Get-PimSqlSetting -ConnectionString $script:PimSqlCs -Name 'ManagerAccess'
        } elseif ($global:PIM_NamingConventions -is [hashtable] -and $global:PIM_NamingConventions.ContainsKey('ManagerAccess')) {
            $raw = $global:PIM_NamingConventions['ManagerAccess']
        }
        if ($raw -is [string] -and "$raw".Trim()) { try { $raw = "$raw" | ConvertFrom-Json } catch { $raw = $null } }
        if ($null -ne $raw) {
            $list = @(if ($raw.PSObject.Properties['managerAccess']) { $raw.managerAccess } else { $raw })
            $entries = @($list | Where-Object { $_ -and "$($_.identity)".Trim() }).Count
        }
    } catch { $entries = 0 }
    $envAdmins = [bool]("$env:PIM_SuperAdmins".Trim() -or "$env:PIM_Admins".Trim())
    [ordered]@{
        sqlEntries = [int]$entries
        envAdmins  = $envAdmins
        configured = [bool]($entries -gt 0 -or $envAdmins)
        fixHint    = ('No Manager access is configured yet, so every sign-in is a Reader and nobody can save a change. ' +
                      'Grant the first SuperAdmin with tools/setup/Set-PimManagerAccess.ps1 ' +
                      '(stored in SQL, pim.Settings ManagerAccess), or set PIM_SuperAdmins to your identity and restart the Manager.')
    }
}

function Get-PimAccessFixHint {
    <#
      What to actually DO about a role denial, for THIS deployment shape.

      🪤 The 403 used to say "See config/manager-access.custom.json" on every deployment -- including
      hosted ones, where Get-PimManagerRole deliberately NEVER READS THAT FILE (it stops at "not in
      SQL ManagerAccess or env (fail closed)", SEC-15, because a file on an ephemeral container
      filesystem must not decide who is SuperAdmin). So a locked-out operator on a SQL-backed
      deployment was pointed at a file that does not exist, is not read, and would not help --
      reported 2026-09-10 as "i dont understand this msg, as we dont handle config files - we use
      pure sql".
      A message that names the wrong remedy costs more than one that names none.
    #>
    if ($script:PimHosted) {
        # 🪤 SINGLE-QUOTED. The first cut wrote the JSON example with C-style \" escapes inside a
        # double-quoted PowerShell string, which is not an escape in PowerShell at all -- it ended
        # the string early and produced EIGHT parse errors. The file then could not parse, so the
        # Manager container CrashLoopBackOff'd on every start while the app still reported
        # "Running" (the Easy Auth sidecar was fine, so TCP connected and HTTP simply never
        # answered). Shipped as 2.4.314 and caught only by rebuilding a live environment.
        return ('Manager access is stored in SQL (pim.Settings ManagerAccess). Grant yourself with ' +
                'tools/setup/Set-PimManagerAccess.ps1 -AccessJson ' +
                '''{"managerAccess":[{"identity":"<you>","role":"SuperAdmin"}]}''' +
                ' -- or set PIM_SuperAdmins on the container app.')
    }
    'Roles are stored in SQL -- ask a SuperAdmin to grant you access.'
}

function Test-PimManagerRoleAtLeast {
    param([Parameter(Mandatory)][ValidateSet('Reader', 'Admin', 'SuperAdmin')][string]$Minimum)
    # Delegated ranks as Reader for write-gates (read-only); its scope filter limits what
    # it sees. Elevating Delegated to manage its own groups is a later epic phase.
    $rank = @{ Reader = 0; Delegated = 0; Admin = 1; SuperAdmin = 2 }
    $rank[(Get-PimManagerRole).role] -ge $rank[$Minimum]
}

function Get-PimManagerCallerScope {
    # Resolve THIS request's enforcement context once, so every write path gates
    # uniformly: @{ isSuperAdmin; profile; identity }. SuperAdmin -> profile $null
    # (bypasses scope, as everywhere). A non-super caller's portal-admin profile (or
    # $null when they have none) is resolved from the SAME store the read path uses.
    # Best-effort: any resolution failure returns a non-super, no-profile context so
    # the flat role gate + write guards stay in force (never silently elevates).
    $isSuper = $false
    try { $isSuper = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin') } catch { $isSuper = $false }
    $who = ''
    try { $who = "$((Get-PimManagerRole).identity)" } catch { $who = '' }
    $prof = $null
    if (-not $isSuper -and (Get-Command Read-PimPortalProfiles -ErrorAction SilentlyContinue) -and (Get-Command Get-PimPortalProfile -ErrorAction SilentlyContinue)) {
        try { $prof = Get-PimPortalProfile -Profiles (Read-PimPortalProfiles) -Identity "$who" } catch { $prof = $null }
    }
    return @{ isSuperAdmin = $isSuper; profile = $prof; identity = $who }
}

function Test-PimManagerHostedDeployment {
    # ONE answer to "is this the hosted app?", shared by the audit writer, the reader and the
    # month count. It used to be re-derived inline in the WRITER only, so the read side could not
    # act on it at all -- and §36.3 phase 1b turns entirely on all three agreeing.
    $hosted = $false
    try { $hosted = [bool]$script:PimHosted } catch { }
    if (-not $hosted) { try { $hosted = [bool]("$env:PIM_HOSTED" -match '(?i)^(1|true|yes)$') } catch { } }
    return $hosted
}

function Write-PimManagerAuditEvent {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        # 🔴 -Before was passed by three save endpoints but NOT DECLARED here, so each threw "A parameter
        # cannot be found that matches parameter name 'Before'" -- AFTER its write had already succeeded --
        # and the operator saw "Save failed" for a save that happened (2026-09-12).
        # Write-PimSqlAuditEvent already stores a before-image; it just never got one.
        [object]$Before = $null,
        [object]$After = $null,
        [string]$Result = 'ok'
    )
    # 🔴 SEC-16 (§36.2) -- this function had TWO defects, fixed together 2026-08-31.
    #
    # (a) IT NAMED THE WRONG ACTOR. It used [WindowsIdentity]::GetCurrent().Name, which on a Linux
    #     container is the PROCESS user -- so every entry read "manager:<container account>" no
    #     matter who signed in, and the trail could record WHAT happened but never WHO did it. An
    #     audit trail that cannot attribute is a log. The signed-in identity was already resolved
    #     on the same request by every RBAC gate; it simply was not passed in.
    # (b) IT DID NOT SURVIVE A DEPLOY. It appended to output/audit/*.jsonl and the hosted app
    #     mounts NO persistent volume (measured: volumes=null, mounts=null), so every revision
    #     roll destroyed the whole trail.
    #
    # 📌 Audit is a STANDARD feature of every topology (operator, 2026-08-31: "audit exist also for
    # single tenant ... it is a standard feature for all scenarios"), so the table lives in the
    # per-deployment `pim` schema next to pim.Rows/pim.Settings -- NOT in the MSP-only `platform`
    # schema. Single-tenant, community and MSP deployments all get it from the same DDL.
    $who = ''
    $whoSource = ''
    try {
        $r = Get-PimManagerRole
        if ($r -and "$($r.identity)".Trim()) { $who = "$($r.identity)".Trim(); $whoSource = "$($r.source)" }
    } catch { }
    if (-not $who) {
        # Fall back to the process identity, but SAY SO. Recording it unlabelled is how (a) hid.
        $who = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
        $whoSource = 'process-identity (NO signed-in principal resolved)'
    }

    $evt = [ordered]@{
        ts = [datetime]::UtcNow.ToString('o'); runId = "$($script:PimManagerSessionId)"; correlationId = ''
        actor = $who; actorSource = $whoSource; action = $Action; target = $Target
        before = $Before; after = $After; result = $Result; whatIf = $false
    }

    # SQL first, wherever a store is configured -- that is every supported topology.
    $wroteSql = $false
    $sqlErr = ''
    try {
        $cs = $null
        if (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) {
            try { $cs = Get-PimSqlConnectionString } catch { $cs = $null }
        }
        if ($cs -and (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue)) {
            Write-PimSqlAuditEvent -ConnectionString $cs -Actor $who -ActorSource $whoSource `
                -Action $Action -Target $Target -Before $Before -After $After -Result $Result `
                -RunId "$($script:PimManagerSessionId)"
            $wroteSql = $true
        }
    } catch { $sqlErr = "$($_.Exception.Message)" }

    if ($wroteSql) { return }

    # 🔴 No SQL audit == the trail is being lost. That must be LOUD. It used to be a
    # Write-Warning either way, so a privileged action whose audit failed still succeeded silently
    # -- and on the hosted app the file it fell back to does not survive the next deploy anyway.
    # 2026-09-13 (SQL-only): the local/dev pim-audit-*.jsonl fallback is gone too, so there is no
    # filesystem trail on ANY host. §36.3 phase 1b already stopped writing it when hosted, because it
    # looked like a safety net and was not: no persistence on a container, it made the failure look
    # handled, and it was a second trail nothing reads (Get-PimManagerAuditEvents refuses the file).
    # The action is still ALLOWED to succeed (§36.3 phase 0 item 2) -- but nothing claims the audit
    # was recorded somewhere it can be found. A pre-v2 local trail is carried into SQL once with
    # tools/pim-manager/Import-PimAuditFileTrail.ps1.
    # NOTE: the READ side is Get-PimManagerAuditEvents below -- writer and reader agree: SQL only.
    Write-Error ("AUDIT NOT RECORDED for '$Action' on '$Target' by '$who'. " +
                 "PIM v2 records the audit trail in SQL only (pim.AuditEvents) and has no filesystem fallback. " +
                 "SQL audit error: " + $(if ($sqlErr) { $sqlErr } else { 'no SQL store resolved' }))
}

# ---------------------------------------------------------------------------
# Validate-tab "Overrule / Acknowledge" writer (REQUIREMENTS §11). The GUI
# Overrule button POSTs here; we APPEND one entry to the override store
# (SQL pim.Settings['WarningOverrides']) -- the SAME shape the engine
# post-filter (engine/_shared/PIM-WarningOverrides.ps1) reads. The next
# preflight then downgrades the matched finding to 'acknowledged' so the active
# warning/info count drops.
# ---------------------------------------------------------------------------
function Get-PimManagerAuditEvents {
    <#
      SEC-16 (§36.2) -- the READ side of the audit trail, mirroring the writer: SQL only.

      🔑 Returns events in the SAME shape the jsonl reader produces, and stamps `category` and
      `change` the same way, so Select-PimAuditEvents / ConvertTo-PimAuditCsv and the Audit tab
      work unchanged. Moving the store is not a licence to rewrite the query layer.
    #>
    param([int]$Months = 0)
    $cs = $null
    if (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) {
        try { $cs = Get-PimSqlConnectionString } catch { $cs = $null }
    }
    if ($cs -and (Get-Command Get-PimSqlAuditEvents -ErrorAction SilentlyContinue)) {
        try {
            $args = @{ ConnectionString = $cs }
            # Months is a WINDOW, not a page size: N months back from now, 0 = full history.
            if ($Months -gt 0) { $args['FromUtc'] = [datetime]::UtcNow.AddMonths(-$Months) }
            $evts = @(Get-PimSqlAuditEvents @args)
            foreach ($e in $evts) {
                try { $e | Add-Member -NotePropertyName category -NotePropertyValue (Resolve-PimAuditCategory -Action "$($e.action)" -Target "$($e.target)") -Force } catch {}
                try { $e | Add-Member -NotePropertyName change   -NotePropertyValue (Get-PimAuditChangeSummary -Before $e.before -After $e.after) -Force } catch {}
            }
            return @($evts)
        } catch {
            # Do NOT silently fall through to the file: on a hosted deployment that file is a
            # different (and shorter-lived) trail, so quietly showing it would present partial
            # history as complete -- the failure mode this whole chapter is about.
            Write-Warning "audit read from SQL failed: $($_.Exception.Message)"
            throw
        }
    }
    # No store: say so rather than rendering a file trail. PIM v2 has no filesystem audit trail on any
    # host (2026-09-13); any pim-audit-*.jsonl left on disk is a fragment of a pre-v2 trail, and showing
    # it as "the audit trail" is the same lie the SQL-failure branch above refuses to tell.
    throw ("No SQL audit store is configured, so there is no readable audit trail. PIM v2 keeps the " +
           "audit trail in SQL only (pim.AuditEvents); configure the store. A pre-v2 local file trail is " +
           "imported once with tools/pim-manager/Import-PimAuditFileTrail.ps1.")
}

function Get-PimEmergencyOverrideStoreName { 'EmergencyOverride' }

function Get-PimManagerEmergencyOverride {
    <#
      §36.3 phase 3 -- read the break-glass override from the store the ENGINE reads.
      🪤 Deliberately does NOT call the engine's Get-PimEmergencyOverride: PIM-Functions.psm1 is
      imported LAZILY here (by design, "so the Manager works without the engine"), so depending on
      it at request time silently returns nothing when it happens not to be loaded -- which would
      make the break-glass tile read "inactive" while an override was live. Caught by
      Test-PimHomeOverview before it shipped.
      The two implementations share the SETTING NAME, and a test asserts they agree on it.
    #>
    try {
        if ((Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) -and
            (Get-Command Get-PimSqlSetting          -ErrorAction SilentlyContinue)) {
            $cs = $null
            try { $cs = Get-PimSqlConnectionString } catch { $cs = $null }
            if ($cs) {
                $v = Get-PimSqlSetting -ConnectionString $cs -Name (Get-PimEmergencyOverrideStoreName)
                if ($v) {
                    if ($v -is [string]) { try { $v = $v | ConvertFrom-Json } catch { $v = $null } }
                    if ($v) { return $v }
                }
            }
        }
    } catch { Write-Warning "  [emergency] SQL override read failed: $($_.Exception.Message)" }
    $f = Join-Path $script:configRoot 'emergency-override.custom.json'
    if (-not (Test-Path -LiteralPath $f)) { return $null }
    try { return (Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}

function Set-PimManagerEmergencyOverride {
    # Returns 'sql' or 'file'. THROWS if a configured SQL store rejects the write -- an
    # activation the engine cannot see must fail loudly, not fall back to a file the engine
    # will never read.
    param([Parameter(Mandatory)][object]$Override)
    try {
        if ((Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) -and
            (Get-Command Set-PimSqlSetting          -ErrorAction SilentlyContinue)) {
            $cs = $null
            try { $cs = Get-PimSqlConnectionString } catch { $cs = $null }
            if ($cs) {
                Set-PimSqlSetting -ConnectionString $cs -Name (Get-PimEmergencyOverrideStoreName) -Value $Override
                return 'sql'
            }
        }
    } catch {
        Write-Warning "  [emergency] SQL override write FAILED -- the engine will NOT see this override: $($_.Exception.Message)"
        throw
    }
    $f = Join-Path $script:configRoot 'emergency-override.custom.json'
    ($Override | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $f -Encoding UTF8
    return 'file'
}

function Get-PimManagerAuditMonthCount {
    <#
      SEC-16 -- how many months of history exist, asked of whichever store is answering.
      The file reader counted monthly FILES; with SQL there are none, so counting files would
      report "0 months" for a populated trail and the Audit tab's window selector would say the
      history is empty. Same source-agreement rule as the reader above.
    #>
    $cs = $null
    if (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) {
        try { $cs = Get-PimSqlConnectionString } catch { $cs = $null }
    }
    if ($cs -and (Get-Command Get-PimSqlAuditMonthCount -ErrorAction SilentlyContinue)) {
        # A query failure used to `return 0` silently, which reports "no history" for a populated
        # trail -- precisely the failure this function's own note says counting files would cause.
        # Keep returning 0 so the window selector still renders, but do not stay quiet about it.
        try { return [int](Get-PimSqlAuditMonthCount -ConnectionString $cs) }
        catch { Write-Warning "audit month count from SQL failed: $($_.Exception.Message)"; return 0 }
    }
    # No store: never count FILES (SQL-only, 2026-09-13). Same source rule as the reader -- a count
    # of pim-audit-*.jsonl files could only describe a dead pre-v2 fragment the reader refuses to load.
    Write-Warning 'audit month count: no SQL audit store is configured (PIM v2 keeps the audit trail in SQL only)'
    return 0
}

# ---------------------------------------------------------------------------
# 36.3 phase 3 -- the last two Manager-owned stores that were files.
#
# Both follow the break-glass shape above: SQL first, file only as the local/dev
# fallback, and a write against a CONFIGURED SQL store that fails THROWS rather
# than quietly landing in a file. The hosted app mounts no persistent volume, so
# "the write succeeded" against the container filesystem is not persistence --
# the next revision roll takes it.
#
# LOCK: these two differ from break-glass in WHICH DIRECTION they fail, and that
# is why they ranked lower -- not because they are cosmetic. Break-glass failed
# OPEN: a lost override left approval disabled. These fail SAFE: a lost warning
# override or exemption means a suppressed finding comes BACK. Losing them is
# noisy rather than dangerous -- but it is still silent data loss, and an
# operator who acknowledged a finding is entitled to have that stick.
# ---------------------------------------------------------------------------
function Get-PimWarningOverrideStoreName      { 'WarningOverrides' }
function Get-PimConformanceExemptionStoreName { 'ConformanceExemptions' }

function Get-PimManagerSettingCs {
    # The connection string for the two stores below. THROWS when there is none: PIM v2 is SQL-only,
    # so "no store" is an error to report, never a cue to read or write a config file instead.
    if (-not ((Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) -and
              (Get-Command Get-PimSqlSetting          -ErrorAction SilentlyContinue))) {
        throw 'no SQL store is wired in this host (PIM v2 is SQL-only -- configure the store)'
    }
    $cs = $null
    try { $cs = Get-PimSqlConnectionString } catch { throw "no SQL store could be resolved (PIM v2 is SQL-only): $($_.Exception.Message)" }
    if (-not $cs) { throw 'no SQL store is configured (PIM v2 is SQL-only -- configure the store)' }
    return $cs
}

function Get-PimManagerSettingObject {
    # Shared read for both stores: pull one pim.Settings value and normalize it to
    # an object. A value can come back as a JSON string or already parsed depending
    # on which writer stored it, so handle both -- same as the break-glass reader.
    # $null = the setting is absent. THROWS when there is no store.
    param([Parameter(Mandatory)][string]$Name)
    $cs = Get-PimManagerSettingCs
    $v = Get-PimSqlSetting -ConnectionString $cs -Name $Name
    if (-not $v) { return $null }
    if ($v -is [string]) { try { $v = $v | ConvertFrom-Json } catch { throw "pim.Settings['$Name'] is not valid JSON: $($_.Exception.Message)" } }
    return $v
}

function Set-PimManagerSettingObject {
    # Shared write. THROWS when there is no store or the store rejects the write -- there is no file
    # to demote to, and an operator must never believe something persisted that did not.
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][object]$Value)
    $cs = Get-PimManagerSettingCs
    Set-PimSqlSetting -ConnectionString $cs -Name $Name -Value $Value
}

function Get-PimManagerWarningOverrides {
    <#
      Read the override store pim.Settings['WarningOverrides']. Returns the RAW container
      object (@{ overrides = @(...) }) so it can be handed straight to the engine's
      Read-PimWarningOverrideConfig -Config. $null when nothing has been acknowledged yet.
      THROWS when there is no SQL store (there is no override file in v2).
    #>
    return (Get-PimManagerSettingObject -Name (Get-PimWarningOverrideStoreName))
}

function Set-PimManagerWarningOverrides {
    # Returns 'sql'. THROWS when the store is missing or rejects the write.
    param([Parameter(Mandatory)][object]$Store)
    try {
        Set-PimManagerSettingObject -Name (Get-PimWarningOverrideStoreName) -Value $Store
        return 'sql'
    } catch {
        Write-Warning "  [overrides] SQL write FAILED -- the acknowledgement was NOT saved: $($_.Exception.Message)"
        throw
    }
}

function Get-PimManagerConformanceExemptions {
    <#
      SEC-17 -- the conformance waiver register, SQL pim.Settings['ConformanceExemptions'] only.

      TRAP: there is deliberately NO sample fallback here, and removing it IS the
      fix. This reader used to fall through to config/exemptions.sample.json when
      the per-instance file was absent -- and that sample is COMMITTED and NOT
      EMPTY. It carries a real-shaped waiver (defender-xdr-roles /
      role:Security Administrator) whose expiresUtc had not yet passed, so it was
      a live waiver that shipped in the box. The POST handler then seeded its list
      from this same reader before writing the real file, which PROMOTED the
      sample row into live state the first time anyone added an exemption.

      KEY: no exemptions is the SAFE answer -- every desired binding stays a Gap
      and re-surfaces on the next deploy. A waiver must be something a human
      explicitly granted, never a default. exemptions.sample.json stays on disk as
      documentation of the shape; nothing reads it at runtime. Same resolution
      SEC-15 reached for portal-admins.sample.json.
    #>
    # SQL only (pim.Settings['ConformanceExemptions']). No store THROWS (Get-PimManagerSettingObject);
    # the per-instance exemptions.json it used to fall back to is gone with the other v2 file stores.
    $v = Get-PimManagerSettingObject -Name (Get-PimConformanceExemptionStoreName)
    if (-not $v) { return @() }
    $inner = $null
    if ($v -is [System.Collections.IDictionary]) {
        if ($v.Contains('exemptions')) { $inner = $v['exemptions'] }
    } elseif ($v.PSObject -and $v.PSObject.Properties['exemptions']) {
        $inner = $v.exemptions
    }
    if ($null -eq $inner) { return @() }
    return @($inner)
}

function Set-PimManagerConformanceExemptions {
    # Returns 'sql'. THROWS when the store is missing or rejects the write.
    param([object[]]$Exemptions = @())
    $store = @{ exemptions = @($Exemptions) }
    try {
        Set-PimManagerSettingObject -Name (Get-PimConformanceExemptionStoreName) -Value $store
        return 'sql'
    } catch {
        Write-Warning "  [exemptions] SQL write FAILED -- the exemption was NOT saved: $($_.Exception.Message)"
        throw
    }
}

function Add-PimWarningOverrideEntry {
    <#
      Append one override entry to the merged store, after validating it against
      the engine contract (Test-PimWarningOverrideValid: mandatory code + reason
      + expiresOn-unless-noExpiry). Errors are never acknowledgeable. Returns the
      new total override count. Throws on a bad entry / missing store path.
    #>
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Reason,
        [string]$ExpiresOn,
        [bool]$NoExpiry = $false,
        [string]$Subject,
        [string]$Target,
        [string]$CreatedBy
    )
    # 36.3 phase 3: this used to demand a config folder and refuse outright in SQL
    # mode ("overrides are a CSV-mode feature"). The hosted Manager DOES have a
    # configRoot -- the container's own copy -- so the refusal did not actually
    # fire there; the acknowledgement was written to an ephemeral filesystem
    # instead, and the next revision roll silently un-acknowledged every finding
    # an operator had reviewed. SQL first now; the folder is only the local path.
    if ("$Code" -ieq '' ) { throw 'code is required.' }
    # Build the entry in the canonical contract shape. A subject/target scope is
    # added only when present so a code-only acknowledgement stays code-wide.
    $entry = [ordered]@{ code = "$Code".Trim(); reason = "$Reason".Trim() }
    if ($CreatedBy) { $entry.createdBy = "$CreatedBy".Trim() }
    if ($NoExpiry) { $entry.noExpiry = $true } else { $entry.expiresOn = "$ExpiresOn".Trim() }
    $subj = "$Subject".Trim(); $tgt = "$Target".Trim()
    if ($subj -or $tgt) {
        $scope = [ordered]@{}
        if ($subj) { $scope.subject = $subj }
        if ($tgt)  { $scope.target  = $tgt }
        $entry.scope = $scope
    }
    # Validate against the engine contract BEFORE persisting (single source of
    # truth -- never write something the post-filter would reject as invalid).
    if (Get-Command Test-PimWarningOverrideValid -ErrorAction SilentlyContinue) {
        $norm = [pscustomobject]@{
            code = $entry.code; reason = $entry.reason
            expiresOn = $(if ($NoExpiry) { '' } else { "$ExpiresOn".Trim() }); noExpiry = $NoExpiry
        }
        $v = Test-PimWarningOverrideValid -Override $norm
        if (-not $v.Valid) { throw "override rejected: $($v.Reason)" }
    } else {
        if (-not $entry.reason) { throw 'override rejected: missing mandatory reason' }
        if (-not $NoExpiry -and -not $entry.expiresOn) { throw 'override rejected: missing mandatory expiresOn (and noExpiry is not set)' }
    }

    # Read the existing store from wherever it lives, append, write it back there.
    $existing = New-Object System.Collections.ArrayList
    $cur = Get-PimManagerWarningOverrides
    if ($cur) {
        $ovr = $null
        if ($cur -is [System.Collections.IDictionary]) {
            if ($cur.Contains('overrides')) { $ovr = $cur['overrides'] }
        } elseif ($cur.PSObject -and $cur.PSObject.Properties['overrides']) {
            $ovr = $cur.overrides
        }
        if ($ovr) { foreach ($o in @($ovr)) { [void]$existing.Add($o) } }
    }
    [void]$existing.Add($entry)
    [void](Set-PimManagerWarningOverrides -Store @{ overrides = $existing.ToArray() })
    return $existing.Count
}

# ---------------------------------------------------------------------------
# Audit category resolver (Audit tab filters). Maps a raw audit action string
# (e.g. 'account.create', 'membership.drift.remove', 'cutover.finalize') to one
# of a small, stable set of human categories the Audit tab filters on. Driven
# by action PREFIX so new engine actions fall into a sensible bucket without
# code changes; anything unrecognised lands in 'other'. The same category list
# is mirrored in the HTML filter chips (renderAudit) -- keep them in sync.
# ---------------------------------------------------------------------------
function Get-PimAuditCategory {
    param([string]$Action, [string]$Target = '')
    $a = "$Action".Trim().ToLowerInvariant()
    if (-not $a) { return 'other' }
    # §70.14 (operator 2026-09-13: "it shows 0 in delegations, which is wrong"). A commit is ONE action
    # name for every entity, so the ENTITY decides: assignments ARE delegations, admin accounts are accounts.
    if ($a -in @('config.save', 'config.csv.save')) {
        $t = "$Target".Trim()
        if ($t -match '^(?i)PIM-Assignments-') { return 'delegations' }
        if ($t -match '^(?i)Account-Definitions-') { return 'accounts' }
    }
    switch -Regex ($a) {
        '^(manager\.login|login)'           { return 'logins' }
        '^emergency\.'                      { return 'emergency' }
        '^approval\.'                       { return 'approvals' }
        '^(account\.|tap\.)'                { return 'accounts' }
        # §70.15 LOG-01/LOG-14: the engine's own change events (Write-PimEngineChangeAudit) -- a membership or
        # role assignment the engine MADE is a delegation; an account change is an account; the rest is engine.
        '^engine\.(groupmembers|adminmembers|entraroles|rolesaus|entrarolesdirect|azres|groupowners|administrativeunitmembers|workloadconnectors|defenderxdrroles|intuneroles|entraapprole)\.' { return 'delegations' }
        '^queue\.action\.(entra-role-revoke|group-assignment-revoke|azure-rbac-revoke)\.' { return 'delegations' }
        '^queue\.action\.' { return 'accounts' }
        '^engine\.(admins|admintap|adminoffboarding)\.' { return 'accounts' }
        '^(membership\.|group\.|local\.apply|msp\.fanout|cutover\.|revoke\.)' { return 'delegations' }
        '^(engine\.|policy\.|resource\.|config\.|settings\.|mail\.send|license\.|schedule\.|azres\.policy\.)' { return 'engine' }
        default                             { return 'other' }
    }
}

# ---------------------------------------------------------------------------
# Login capture (Audit tab "Logins" category). Records a single 'manager.login'
# audit event the first time an identity loads the Manager in this server
# session -- deduped via $script:PimLoginAudited so a refresh doesn't repeat it.
# Best-effort; a logging failure must never block serving the page.
# ---------------------------------------------------------------------------
function Write-PimManagerLoginAudit {
    try {
        $r = Get-PimManagerRole
        $who = "$($r.identity)"
        if (-not $who) { $who = '<unknown>' }
        $key = "$who|$($r.role)"
        if ($script:PimLoginAudited.ContainsKey($key)) { return }
        $script:PimLoginAudited[$key] = $true
        $mode = if ($script:PimHosted) { 'hosted' } else { 'local' }
        Write-PimManagerAuditEvent -Action 'manager.login' -Target $who -After @{
            role = "$($r.role)"; source = "$($r.source)"; mode = $mode
        } -Result 'ok'
    } catch { Write-Warning "login audit skipped: $($_.Exception.Message)" }
}

# Emergency override state (phase 8). The passcode is verified against a
# SHA256 hash in config/emergency.custom.ps1 ($global:PIM_EmergencyPasscodeHash
# = lowercase hex of SHA256(passcode)) -- generate with:
#   [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes('passphrase'))).Replace('-','').ToLower()
# Key-Vault-backed verification is a documented follow-up.
$script:EmergencyAttempts = @()

function Test-PimEmergencyPasscode {
    param([Parameter(Mandatory)][string]$Passcode)
    # Delegates to the shared, KV-backed governance helpers (PIM-Governance.ps1):
    # expected hash from KV PIM-EmergencyPasscode (set $global:PIM_EmergencyVault)
    # else the local config/emergency.custom.ps1 hash; constant-time compare;
    # 5-failures-in-15-min lockout. Falls back to an inline verify if the shared
    # module is somehow unavailable, so the endpoint never hard-fails.
    $now = [datetime]::UtcNow

    # SQL-only product (2026-09-12): the expected hash comes from the key vault (PIM-EmergencyPasscode,
    # $global:PIM_EmergencyVault) or an in-memory $global:PIM_EmergencyPasscodeHash set by the host --
    # never from a config/emergency.custom.ps1 file.

    if ((Get-Command Resolve-PimEmergencyVerification -ErrorAction SilentlyContinue) -and (Get-Command Resolve-PimEmergencyExpectedHash -ErrorAction SilentlyContinue)) {
        $expected = (Resolve-PimEmergencyExpectedHash).hash
        $v = Resolve-PimEmergencyVerification -Passcode $Passcode -ExpectedHashHex $expected -NowUtc $now -Failures @($script:EmergencyAttempts)
        $script:EmergencyAttempts = @($v.recentFailures)
        if (-not $v.ok -and $v.error -eq 'invalid passcode') {
            Write-PimManagerAuditEvent -Action 'emergency.passcode.failed' -Target 'emergency-override' -Result 'denied'
        }
        if ($v.ok) { return @{ ok = $true } } else { return @{ ok = $false; error = $v.error } }
    }

    # --- fallback (shared module missing) ---
    $cutoff = $now.AddMinutes(-15)
    $script:EmergencyAttempts = @($script:EmergencyAttempts | Where-Object { $_ -gt $cutoff })
    if ($script:EmergencyAttempts.Count -ge 5) { return @{ ok = $false; error = 'locked: too many failed attempts -- wait 15 minutes' } }
    $expected = $global:PIM_EmergencyPasscodeHash
    # 🔴 R3 -- this string is RETURNED TO THE GUI, so on a hosted (pure-SQL) deployment it told the
    # operator to edit a config file that does not exist there and is never read. Same defect as
    # the 403 bodies: a message naming the wrong remedy costs more than one naming none.
    # Hosted resolves the passphrase from the key vault; only a LOCAL install has the file.
    if (-not $expected) {
        # SQL-only product: there is no local config file to point at on ANY deployment shape.
        $hint = 'store the emergency passphrase in your key vault (secret PIM-EmergencyPasscode)'
        return @{ ok = $false; error = "no emergency passcode configured -- $hint" }
    }
    $actual = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Passcode))).Replace('-', '').ToLowerInvariant()
    $exp = "$expected".ToLowerInvariant()
    $diff = $actual.Length -bxor $exp.Length
    for ($i = 0; $i -lt [Math]::Min($actual.Length, $exp.Length); $i++) { $diff = $diff -bor ([int][char]$actual[$i] -bxor [int][char]$exp[$i]) }
    if ($diff -ne 0) {
        $script:EmergencyAttempts += $now
        Write-PimManagerAuditEvent -Action 'emergency.passcode.failed' -Target 'emergency-override' -Result 'denied'
        return @{ ok = $false; error = 'invalid passcode' }
    }
    @{ ok = $true }
}

# ---------------------------------------------------------------------------
# STORE + INSTANCES -- SQL ONLY (operator, 2026-09-12: "we dont use settings files anymore, sql
# only" / "when have you migrated all files off so we use pure sql").
#
# 🔒 The Manager has ONE store: SQL. There is no CSV default, no -ConfigRoot folder instance, no
# instances.custom.json registry, no -StaticHtml export and no settings/access file. A Manager that
# cannot reach its SQL store REFUSES TO START -- in every mode, local included -- because serving
# anything else shows an administrator data that is not the live store while every check reports
# healthy (section 42.2a / 51.1).
#
# An "instance" is now a SQL database: 'sql:<db>' for the configured database plus any extra names
# in $env:PIM_SqlDatabases (same server; the GUI dropdown switches between them).
# $script:configRoot / $script:outputRoot still point at the solution's config/ and output/ folders
# for the shipped, locked inputs and the not-yet-migrated caches (tenant lists, scheduler state) --
# never for desired state, settings or access.
# ---------------------------------------------------------------------------

function Get-PimSolutionVersion {
    # Reads SOLUTIONS/PIM4EntraPS/VERSION for the header badge (same pill the
    # PIM Activator shows). Best-effort: 'v?' when the file is missing.
    $vf = Join-Path $solutionRoot 'VERSION'
    if (Test-Path -LiteralPath $vf) {
        try { return ('v' + ([System.IO.File]::ReadAllText($vf).Trim())) } catch { }
    }
    return 'v?'
}

function Get-PimManagerInstances {
    # Returns array of @{ name = 'sql:<db>'; configRoot; outputRoot; sqlDatabase }. SQL databases only.
    $list = New-Object System.Collections.ArrayList
    $dbs = New-Object System.Collections.Generic.List[string]
    if ("$($global:PIM_SqlDatabase)".Trim()) { $dbs.Add("$($global:PIM_SqlDatabase)".Trim()) }
    foreach ($d in ("$env:PIM_SqlDatabases" -split '[,; ]+' | Where-Object { $_ })) { if ($dbs -notcontains $d) { $dbs.Add($d) } }
    foreach ($db in $dbs) {
        [void]$list.Add(@{ name = "sql:$db"; configRoot = (Join-Path $solutionRoot 'config'); outputRoot = (Join-Path $solutionRoot 'output'); sqlDatabase = $db })
    }
    return ,$list.ToArray()
}

function Get-PimManagerStoreRequiredMessage {
    param([string]$Reason)
    return ("[store] PIM Manager refused to start: {0} The Manager is SQL-only -- it has no file store and never " +
            "serves anything but the live SQL store. Configure the store, then start it again: set " +
            "PIM_SqlServer + PIM_SqlDatabase (Azure SQL FQDN, or a named on-prem/hybrid instance), or " +
            "PIM_SqlConnectionString, or the Key Vault pointer `$global:PIM_SqlConnStringVault + " +
            "`$global:PIM_SqlConnStringSecret. (Environment variables or the matching `$global:PIM_* " +
            "variables; hosted: the container app's settings.)") -f $Reason
}

function Initialize-PimManagerStore {
    # Resolve, open and initialise the SQL store; hydrate settings. THROWS when there is no store.
    $script:PimStorageMode = $null; $script:PimSqlCs = $null
    # Container-friendly: surface the SQL env vars (app settings) as the globals the resolver reads.
    if (-not $global:PIM_SqlServer   -and $env:PIM_SqlServer)   { $global:PIM_SqlServer   = $env:PIM_SqlServer }
    if (-not $global:PIM_SqlDatabase -and $env:PIM_SqlDatabase) { $global:PIM_SqlDatabase = $env:PIM_SqlDatabase }
    if ($env:PIM_SqlConnectionString -and -not $global:PIM_SqlConnectionString) { $global:PIM_SqlConnectionString = $env:PIM_SqlConnectionString }
    # 🔴 section 42.2a -- if the resolver is not loaded (a dot-source order change, a module that failed
    # to import) the store selection cannot run at all. Say it is a LOAD-ORDER defect, not configuration.
    if (-not (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue)) {
        throw (Get-PimManagerStoreRequiredMessage -Reason 'Get-PimSqlConnectionString is NOT LOADED, so the store selection never ran -- this is a load-order defect, not a configuration one.')
    }
    $hasSig = [bool]($global:PIM_SqlConnectionString -or $global:PIM_SqlConnStringVault -or $global:PIM_SqlServer)
    Write-Host ("  [store] SQL-only; signal={0} server='{1}' db='{2}' hosted={3}" -f $hasSig, "$($global:PIM_SqlServer)", "$($global:PIM_SqlDatabase)", [bool]$script:PimHosted) -ForegroundColor DarkCyan
    Write-Host ("  [mi-env] IDENTITY_ENDPOINT={0} IDENTITY_HEADER={1} interactive={2}" -f [bool]$env:IDENTITY_ENDPOINT, [bool]$env:IDENTITY_HEADER, [bool]($global:PIM_Interactive -or $global:PIM_SqlInteractive)) -ForegroundColor DarkCyan
    if (-not $hasSig) {
        throw (Get-PimManagerStoreRequiredMessage -Reason 'no SQL store is configured.')
    }
    $cs = $null
    try { $cs = Get-PimSqlConnectionString } catch { throw (Get-PimManagerStoreRequiredMessage -Reason "the connection string could not be built: $($_.Exception.Message).") }
    if (-not $cs) { throw (Get-PimManagerStoreRequiredMessage -Reason "no connection string resolved (server='$($global:PIM_SqlServer)' db='$($global:PIM_SqlDatabase)').") }
    # Direct open so the REAL failure (driver load / MI token / TLS / auth / network) surfaces,
    # instead of a swallowed false.
    try {
        $__tc = New-PimSqlConnection -ConnectionString $cs
        $__tc.Open(); $__tc.Close()
        Write-Host "  [store] SQL connect test OK" -ForegroundColor DarkCyan
    } catch {
        $__inner = if ($_.Exception.InnerException) { " | inner: $($_.Exception.InnerException.Message)" } else { '' }
        throw (Get-PimManagerStoreRequiredMessage -Reason "the SQL store could not be reached [$($_.Exception.GetType().Name)]: $($_.Exception.Message)$__inner.")
    }
    Initialize-PimSqlStore -ConnectionString $cs
    if ($global:PIM_NamingConventions -is [hashtable]) { [void](Import-PimSettingsSeed -ConnectionString $cs -Seed $global:PIM_NamingConventions) }
    Initialize-PimManagerPolicyTemplates -ConnectionString $cs
    Initialize-PimManagerMailTemplates -ConnectionString $cs
    $sqlSettings = Get-PimAllSqlSettings -ConnectionString $cs
    if (-not ($global:PIM_NamingConventions -is [hashtable])) { $global:PIM_NamingConventions = @{} }
    foreach ($k in @($sqlSettings.Keys)) { $global:PIM_NamingConventions[$k] = $sqlSettings[$k] }
    $script:PimSqlCs = $cs; $script:PimStorageMode = 'sql'
    # The DB name is needed for the 'sql:<db>' instance label. When the connection arrived as a full
    # connection string / KV pointer, $global:PIM_SqlDatabase is unset -- parse it out of the CS.
    if (-not "$($global:PIM_SqlDatabase)".Trim()) {
        if ("$cs" -match '(?i)(?:Initial\s+Catalog|Database)\s*=\s*([^;]+)') { $global:PIM_SqlDatabase = $Matches[1].Trim() }
    }
    Write-Host "  [store] SQL mode (SQL-only; no file store exists)" -ForegroundColor Cyan
}

function Initialize-PimManagerPolicyTemplates {
    # Seed pim.Settings 'PolicyTemplates' from the shipped templates on a fresh store; on an existing one,
    # upgrade UNMODIFIED templates to the shipped version and keep + flag CUSTOMISED ones
    # (Update-PimPolicyTemplateStore, BUG-55 semantics). A failure is REPORTED, not fatal: the Manager still serves, and the validator and
    # engine then say plainly that no templates are stored.
    param([Parameter(Mandatory)][string]$ConnectionString)
    if (-not (Get-Command Initialize-PimPolicyTemplateStore -ErrorAction SilentlyContinue)) { return }
    try {
        $pt = Initialize-PimPolicyTemplateStore -ConnectionString $ConnectionString -TemplateDir (Join-Path $solutionRoot 'templates\policy')
        Write-Host ("  [store] policy templates: {0} in SQL ({1}; fingerprint {2})" -f $pt.count, $pt.reason, $pt.fingerprint) -ForegroundColor DarkCyan
    } catch { Write-Warning "  [store] policy templates could NOT be seeded into SQL: $($_.Exception.Message)" }
}

function Initialize-PimManagerMailTemplates {
    # The ONE mail template store (SQL pim.Settings['MailTemplates']): seed from the shipped templates,
    # follow a newer shipped body for entries still unedited, keep edited ones, and merge the retired
    # MailTemplateOverrides setting in ONCE (additive, audited). Reported, not fatal.
    param([Parameter(Mandatory)][string]$ConnectionString)
    if (-not (Get-Command Update-PimMailTemplateStore -ErrorAction SilentlyContinue)) {
        Write-Warning '  [store] mail templates: PIM-MailTemplateStore.ps1 is not loaded -- the template store was NOT seeded (load-order defect)'
        return
    }
    try {
        $mt = Update-PimMailTemplateStore -ConnectionString $ConnectionString -TemplateDir (Join-Path $solutionRoot 'templates\mail') -Actor 'manager'
        Write-Host ("  [store] mail templates: {0} in SQL ({1})" -f $mt.count, $mt.reason) -ForegroundColor DarkCyan
    } catch { Write-Warning "  [store] mail templates could NOT be seeded into SQL: $($_.Exception.Message)" }
}
function Set-PimManagerInstance {
    # Switch the active SQL database on the same server (MI token is server-scoped, so it works
    # across DBs; the MI must be a contained user in each target DB). Reloads settings from the new
    # DB and clears every per-instance server-side cache. Throws on an unknown name.
    param([Parameter(Mandatory)][string]$Name)
    $inst = $null
    foreach ($i in (Get-PimManagerInstances)) { if ($i.name -eq $Name) { $inst = $i; break } }
    if (-not $inst) { throw "Unknown instance '$Name'. Instances are SQL databases on the configured server ('sql:<db>'); add more with PIM_SqlDatabases." }
    $global:PIM_SqlDatabase = "$($inst.sqlDatabase)"
    $cs = Get-PimSqlConnectionString
    $tc = New-PimSqlConnection -ConnectionString $cs; $tc.Open(); $tc.Close()
    Initialize-PimSqlStore -ConnectionString $cs
    Initialize-PimManagerPolicyTemplates -ConnectionString $cs
    Initialize-PimManagerMailTemplates -ConnectionString $cs
    $sqlSettings = Get-PimAllSqlSettings -ConnectionString $cs
    if (-not ($global:PIM_NamingConventions -is [hashtable])) { $global:PIM_NamingConventions = @{} }
    foreach ($k in @($sqlSettings.Keys)) { $global:PIM_NamingConventions[$k] = $sqlSettings[$k] }
    $script:PimSqlCs = $cs; $script:PimStorageMode = 'sql'; $script:PimInstanceName = $inst.name
    # Per-instance state must not leak across databases.
    # (The active-assignments snapshot is a row in THIS database's pim.TenantCache, read per request -- §70.1b
    # option 2 -- so there is no in-process copy to clear.)
    $script:PimManager_LookupCachesLoaded      = $false
    $script:PimManagerAccessCache              = $null
    Write-Host "  [store] switched SQL database -> $($global:PIM_SqlDatabase)" -ForegroundColor Cyan
}

# Startup: the SQL store is REQUIRED (throws with the env vars to set), then bind the active
# instance -- -Instance 'sql:<db>' when given, else the configured database.
$script:configRoot  = Join-Path $solutionRoot 'config'
$script:outputRoot  = Join-Path $solutionRoot 'output'
if (-not (Test-Path -LiteralPath $script:outputRoot)) { New-Item -ItemType Directory -Path $script:outputRoot -Force | Out-Null }
$script:mutationLog = Join-Path $script:outputRoot 'pim-manager-mutations.log'
Initialize-PimManagerStore
$script:PimInstanceName = "sql:$($global:PIM_SqlDatabase)"
if ($Instance -and $Instance -ne $script:PimInstanceName) {
    Set-PimManagerInstance -Name $Instance
} else {
    Write-Host ("  [store] hosted/SQL default -> active instance '{0}'" -f $script:PimInstanceName) -ForegroundColor Cyan
}

if (-not (Test-Path -LiteralPath $template))   { throw "Template not found: $template" }
if (Test-Path -LiteralPath $tenantSync) { . $tenantSync }
# §70.1b option 2: tenant-connection + principal/role lookup helpers and the active-assignments SNAPSHOT
# reader (engine/_shared/PIM-ActiveAssignments.ps1). The live read in that file is the SCHEDULER's job; this
# process never registers its handler (Register-PimActiveAssignmentsSnapshotHandler) and never calls it.
$_activeAssignLib = Join-Path $solutionRoot 'engine\_shared\PIM-ActiveAssignments.ps1'
if (Test-Path -LiteralPath $_activeAssignLib) { . $_activeAssignLib }
# Drift page (2026-09-14): the drift SNAPSHOT reader (engine/_shared/PIM-DriftSnapshot.ps1). The plan itself runs ONLY in
# the scheduler (job 'drift-snapshot'); this process reads pim.TenantCache 'drift' and queues a refresh -- it never
# registers the handler (Register-PimDriftSnapshotHandler) and never calls Invoke-PimDriftSnapshot.
$_driftSnapLib = Join-Path $solutionRoot 'engine\_shared\PIM-DriftSnapshot.ps1'
if (Test-Path -LiteralPath $_driftSnapLib) { . $_driftSnapLib }
if (Test-Path -LiteralPath $validator)  { . $validator }

# ---------------------------------------------------------------------------
# Hosted tenant-auth context (no -ConnectPlatform / no mgmt box / no bootstrap).
#
# In the hosted container the engine SPN credentials arrive as ENV / app
# settings (PIM_ClientId + PIM_CertThumbprint + PIM_TenantId) OR the runtime is
# the container's managed identity. The Manager's tenant-read paths used to need
# the SDK-style $global:HighPriv_Modern_* globals (set only by -ConnectPlatform
# or a baseline engine run) -- absent in the container, so every tenant-backed
# endpoint 500'd ("requires the engine SPN context ... Missing ...").
#
# Mirror the engine's config resolution here (env -> $global:PIM_*), then BRIDGE
# those (or MI) into the globals _tenantSync/active-assignments check, so app-only
# tenant reads work with zero bootstrap. PIM-Rest.ps1 (dot-sourced above) mints
# the actual Graph/ARM tokens from the same PIM_* cert / MI -- no Graph/Az module.
function Set-PimManagerCfgFromEnv {
    param([Parameter(Mandatory)][string]$Global, [Parameter(Mandatory)][string]$Env)
    $cur = Get-Variable -Name $Global -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if (-not $cur -and (Test-Path "Env:\$Env")) { Set-Variable -Name $Global -Scope Global -Value (Get-Item "Env:\$Env").Value }
}
Set-PimManagerCfgFromEnv 'PIM_ClientId'       'PIM_ClientId'
Set-PimManagerCfgFromEnv 'PIM_CertThumbprint' 'PIM_CertThumbprint'
Set-PimManagerCfgFromEnv 'PIM_TenantId'       'PIM_TenantId'
Set-PimManagerCfgFromEnv 'PIM_ClientSecret'   'PIM_ClientSecret'

# True when this process has NO Graph/Az PowerShell SDK and must do all tenant
# reads over REST (PIM-Rest.ps1). The hosted container ships zero PS modules.
$script:PimRestOnly = -not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)

# Detect a usable managed identity (App Service / Functions / IMDS).
$script:PimHasManagedIdentity = [bool]($env:IDENTITY_ENDPOINT -or $env:MSI_ENDPOINT -or $global:PIM_UseManagedIdentity)

# Bridge: make the SDK-style context checks (Assert-PimTenantConnectionContext)
# pass from the engine SPN / MI credentials. We do NOT connect any module here;
# the REST data plane authenticates lazily per call from PIM_* / MI.
if ($script:PimHosted -or $script:PimRestOnly -or $global:PIM_ClientId -or $script:PimHasManagedIdentity) {
    if ($global:PIM_TenantId -and -not $global:AzureTenantID) { $global:AzureTenantID = "$($global:PIM_TenantId)" }
    if ($global:AzureTenantID -and -not $global:PIM_TenantId) { $global:PIM_TenantId = "$($global:AzureTenantID)" }
    if ($global:PIM_ClientId -and -not $global:HighPriv_Modern_ApplicationID_Azure) { $global:HighPriv_Modern_ApplicationID_Azure = "$($global:PIM_ClientId)" }
    if ($global:PIM_CertThumbprint -and -not $global:HighPriv_Modern_CertificateThumbprint_Azure) { $global:HighPriv_Modern_CertificateThumbprint_Azure = "$($global:PIM_CertThumbprint)" }
    if ($global:PIM_ClientSecret -and -not $global:HighPriv_Modern_Secret_Azure) { $global:HighPriv_Modern_Secret_Azure = "$($global:PIM_ClientSecret)" }
    if ($script:PimHasManagedIdentity) { $global:PIM_UseManagedIdentity = $true }
    $script:PimTenantAuthLabel =
        if ($script:PimHasManagedIdentity -and -not $global:PIM_ClientId) { 'managed identity' }
        elseif ($global:PIM_ClientId -and $global:PIM_CertThumbprint)     { "SPN $($global:PIM_ClientId) (cert)" }
        elseif ($global:PIM_ClientId -and $global:PIM_ClientSecret)       { "SPN $($global:PIM_ClientId) (secret)" }
        elseif ($global:HighPriv_Modern_ApplicationID_Azure)             { "SPN $($global:HighPriv_Modern_ApplicationID_Azure)" }
        else { 'none (tenant reads will fail until configured)' }
    Write-Host ("  [tenant-auth] rest-only={0} mi={1} tenant={2} auth={3}" -f $script:PimRestOnly, $script:PimHasManagedIdentity, "$($global:PIM_TenantId)", $script:PimTenantAuthLabel) -ForegroundColor DarkCyan
}

if ($ConnectPlatform) {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $solutionRoot)   # ...\AutomateIT
    $psd1 = Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'
    if (-not (Test-Path -LiteralPath $psd1)) { throw "-ConnectPlatform: AutomateITPS module not found at $psd1" }
    Write-Host "Connecting platform (AutomateITPS bootstrap -> Modern SPN, app-only) ..." -ForegroundColor Cyan
    Import-Module $psd1 -Global -Force -WarningAction SilentlyContinue
    $null = Connect-Platform
    Write-Host ("  connected: tenant {0}" -f $global:AzureTenantID) -ForegroundColor Green
}

# The 14 CSV bases the mapper edits, in stable UI order, with their default
# headers used when creating a brand-new .custom.csv.
$script:PimCsvBases = @(
    # ForwardMailsToContact / MailForwardAddress retired 2026-08-12 -- notification + TAP mail is
    # sent FROM the shared mailbox the engine SPN is scoped to, so an admin needs no mailbox and
    # no Exchange licence, and there is nothing to forward. Recipient is ManagerEmail.
    # 🔴 BUG-139 -- EIGHT FIELDS THE ENGINE READS HAD NO COLUMN, SO THEY COULD NOT BE SET OR SEEN.
    # In SQL mode this defaultHeader IS the grid's header (Read-PimRows returns $spec.defaultHeader
    # verbatim -- it is NOT derived from the rows), so a field missing here is invisible and
    # uneditable in All records no matter what the row actually carries.
    # Missing were: AdminType, ManagerEmail, AccountStatus, OffboardDate, ManagementMode, Company,
    # Environment, TAPLifetimeHours -- every one of which /api/admin-accounts, /api/admin-tap and
    # the engine's Admins/AdminTap providers already read.
    # 🔑 THE USER-VISIBLE EFFECT, reported 2026-09-12: "admin is different types including internal
    # admins ... where are they" / "we have internal admins, external admins (consultants + guest)"
    # / "the admins must include ALL". AdminType is the column that distinguishes
    # internal-adminuser from external-adminuser ('x-') from external-guest (PIM-Naming.ps1
    # AdminTypePrefixes) and it was simply not offered -- so every admin silently took
    # AdminTypeDefault, and a consultant or guest could not be expressed at all. ManagerEmail is
    # the only address a TAP is ever mailed to, and its absence is why rows report
    # "no ManagerEmail on the row" and cannot be fixed from the grid.
    # 🪤 Unlike the JobSchedule case (BUG-136), this one DOES reach every environment on an image
    # roll: the header is shipped in code and never persisted per-deployment. No migration needed.
    [ordered]@{ base = 'Account-Definitions-Admins';      group = 'Definitions';  defaultHeader = @('FirstName','LastName','Initials','Purpose','TargetUsage','TargetPlatform','UserType','AdminType','UserName','DisplayName','UserPrincipalName','UsageLocation','Company','Department','ManagerEmail','Environment','ForwardMailsToContact','MailForwardAddress','CreateTAP','TAPStartDate','TAPLifetimeHours','AccountStatus','OffboardDate','ManagementMode','Ring','Target') },
    # 🔴 BUG-139 (same class) -- THE ACCOUNTABLE-OWNER FIELDS HAD NO COLUMN ON *ROLES*.
    # DESIGN.md §1268/§1502 defines the owner chain as: `Owners` (pipe-joined UPNs) -> `SponsorUpn`
    # (Roles) -> the group's **Department** contact. The ENGINE implements all three
    # (New-PimRoleGroupOwnerUpns / Get-PimDelegationApprovalPlan / PIM-DelegationDepth.ps1) and the
    # validator already fails a role with no accountable owner (PIM-ROLE-OWNER-001). But this
    # header -- which IS the grid's header in SQL mode -- offered none of Owners / SponsorUpn /
    # Department, so the operator had no way to SET the thing the engine and validator demand.
    # Note PIM-Definitions-Tasks and -Services already carry `Owners`; Roles was the outlier.
    # 🔑 Operator, 2026-09-12: "sponsor is missing, who is the manager of a person" /
    # "it should be linked to dept as sponsor" / "it is already in the docs" -- correct on all
    # three counts. The design and the engine were right; only the column was absent.
    # PolicyTemplate + ReviewCycle are read by the same provider block and were missing too;
    # SponsorNotes is the v2 companion field recorded in REQUIREMENTS §1451.
    [ordered]@{ base = 'PIM-Definitions-Roles';           group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform','IsRoleAssignable','Owners','SponsorUpn','SponsorNotes','Department','Organisation','Project','Team','BusinessUnit','PolicyTemplate','ReviewCycle') },
    [ordered]@{ base = 'PIM-Definitions-Tasks';           group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-Services';        group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-Processes';       group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-Resources';       group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    # 🔴 BUG-140 -- THE SPONSOR-BY-DEPARTMENT MODEL WAS DEAD, because its KEY COLUMN was missing.
    # Get-PimDepartmentOwnerIndex (PIM-EngineProviders.ps1:551) builds Department -> Owners by
    # reading `Department` / `DepartmentName` / `Name` off each PIM-Definitions-Departments row.
    # This header offered NONE of those three, and in SQL mode the header IS the grid (Read-PimRows
    # returns $spec.defaultHeader verbatim). So `$dept` was always blank, the index was ALWAYS
    # EMPTY, and the third link of the owner chain -- Owners -> SponsorUpn -> **Department
    # contact** (DESIGN.md §1268/§1502) -- could never resolve for anyone.
    # 🔑 WHY THAT MATTERS MORE THAN A MISSING FIELD (operator, 2026-09-12): "we dont add a manager
    # on the person ... as we add a sponsor (dept) ... and whoever is the actual manager of the
    # dept gets the emails, apprvals etc ... otherwise you are vulnerable for org changes."
    # Routing through the DEPARTMENT is deliberate and is the whole point: a named person pinned
    # onto an account goes stale at the next reorg or leaver, silently breaking approvals and mail
    # for a privileged account. Routing to "whoever currently owns the department" survives that.
    # With the key column absent, the estate silently fell back to per-person routing -- exactly
    # the fragile model the design rejects.
    # `Department` leads the header because Get-PimStoreRowKey also keys Departments on it
    # (falling back to GroupTag only when it is blank).
    [ordered]@{ base = 'PIM-Definitions-Departments';     group = 'Definitions';  defaultHeader = @('Department','GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-Organization';    group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    # Direct-group types Project (PROJ-, AU PIM-PROJECTS) and Cross-org (CORG-, AU PIM-CROSSORG) --
    # operator, 2026-09-12: "where is the project and cross-org direct group".
    [ordered]@{ base = 'PIM-Definitions-Projects';        group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-CrossOrg';        group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-AU';              group = 'Definitions';  defaultHeader = @('AUDisplayName','AUDescription','AdministrativeUnitTag','Workload','Level','TierLevel','Visibility') },
    [ordered]@{ base = 'PIM-Assignments-Admins';          group = 'Assignments';  defaultHeader = @('Username','GroupTag','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform') },
    [ordered]@{ base = 'PIM-Assignments-Groups';          group = 'Assignments';  defaultHeader = @('TargetGroupTag','SourceGroupTag','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform') },
    [ordered]@{ base = 'PIM-Assignments-Roles-Groups';    group = 'Assignments';  defaultHeader = @('GroupTag','RoleDefinitionName','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform') },
    [ordered]@{ base = 'PIM-Assignments-Roles-AUs';       group = 'Assignments';  defaultHeader = @('GroupTag','AdministrativeUnitTag','RoleDefinitionName','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform') },
    [ordered]@{ base = 'PIM-Assignments-Azure-Resources'; group = 'Assignments';  defaultHeader = @('GroupTag','AzScope','AzScopePermission','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform') },
    [ordered]@{ base = 'PIM-Assignments-Workloads';       group = 'Assignments';  defaultHeader = @('Workload','RoleName','GroupTag','Scope','Action','Notes') }
)

# ---------------------------------------------------------------------------
# CSV I/O helpers
# ---------------------------------------------------------------------------

function Get-PimCsvBases {
    return ,$script:PimCsvBases
}

function Get-PimCsvSpec {
    param([Parameter(Mandatory)][string]$BaseName)
    foreach ($spec in $script:PimCsvBases) {
        if ($spec.base -eq $BaseName) { return $spec }
    }
    return $null
}

# --- Delegated (workload-owner) visibility scoping --------------------------------
# A 'Delegated' Manager user sees ONLY the groups they own (their identity in the
# definition's Owners/SponsorUpn) plus the assignment rows that reference those groups
# (by GroupTag / Target/SourceGroupTag). SuperAdmin/Admin/Reader are unscoped.
function Get-PimCell { param($Row, [string]$Col)
    if ($null -eq $Row) { return '' }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Col)) { return "$($Row[$Col])" }; return '' }
    $p = $Row.PSObject.Properties[$Col]; if ($p) { return "$($p.Value)" }; return ''
}
function Get-PimDelegatedOwnedScope {
    param([string]$Identity)
    if (-not "$Identity".Trim()) { return $null }
    if ($script:PimDelegScopeFor -eq $Identity -and $script:PimDelegScope) { return $script:PimDelegScope }
    $idLc = $Identity.ToLowerInvariant(); $tags = @{}; $names = @{}
    # Department -> owner UPNs, so ownership inherited via a group's Department resolves the
    # same way the engine does (Owners/SponsorUpn direct, else the dept contact).
    $deptOwners = @{}
    foreach ($dr in @((Read-PimRows -BaseName 'PIM-Definitions-Departments' -NoScope).rows)) {
        $dn = (Get-PimCell $dr 'Department'); if (-not $dn) { $dn = (Get-PimCell $dr 'DepartmentName') }
        $do = (Get-PimCell $dr 'Owners'); if (-not $do) { $do = (Get-PimCell $dr 'ManagerEmail') }
        if ($dn) { $deptOwners[$dn.ToLowerInvariant()] = @($do -split '[|;,]' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ }) }
    }
    foreach ($e in @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization', 'PIM-Definitions-Tasks')) {
        $res = Read-PimRows -BaseName $e -NoScope
        foreach ($r in @($res.rows)) {
            $own = (Get-PimCell $r 'Owners'); $sp = (Get-PimCell $r 'SponsorUpn')
            $owns = @("$own|$sp" -split '[|;,]' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
            $isOwner = ($owns -contains $idLc)
            if (-not $isOwner) {
                $dept = (Get-PimCell $r 'Department'); if ($dept -and $deptOwners.ContainsKey($dept.ToLowerInvariant())) { $isOwner = ($deptOwners[$dept.ToLowerInvariant()] -contains $idLc) }
            }
            if ($isOwner) {
                $gn = (Get-PimCell $r 'GroupName'); if ($gn) { $names[$gn.ToLowerInvariant()] = $true }
                $gt = (Get-PimCell $r 'GroupTag');  if ($gt) { $tags[$gt.ToLowerInvariant()] = $true }
            }
        }
    }
    $script:PimDelegScopeFor = $Identity; $script:PimDelegScope = @{ tags = $tags; names = $names }
    return $script:PimDelegScope
}
function Test-PimRowInScope {
    param($Row, $Scope)
    $gn = (Get-PimCell $Row 'GroupName'); if ($gn -and $Scope.names.ContainsKey($gn.ToLowerInvariant())) { return $true }
    foreach ($c in @('GroupTag', 'TargetGroupTag', 'SourceGroupTag')) { $v = (Get-PimCell $Row $c); if ($v -and $Scope.tags.ContainsKey($v.ToLowerInvariant())) { return $true } }
    return $false
}
function Limit-PimRowsToScope {
    param([hashtable]$Result, [string]$BaseName, [switch]$NoScope)
    if ($NoScope) { return $Result }
    $role = Get-PimManagerRole
    if ("$($role.role)" -ne 'Delegated') { return $Result }
    $scope = Get-PimDelegatedOwnedScope -Identity "$($role.identity)"
    if (-not $scope) { $Result.rows = @(); return $Result }
    $Result.rows = @(@($Result.rows) | Where-Object { Test-PimRowInScope -Row $_ -Scope $scope })
    return $Result
}

function Read-PimRows {
    # Returns hashtable: @{ header = string[]; rows = object[]; source = 'sql'; path = 'sql:<entity>' }
    # -NoScope bypasses Delegated visibility scoping (used internally to build the scope).
    # 🔒 SQL-ONLY: the single chokepoint every caller -- the page model, diff, validate, commit --
    # reads through. There is no CSV branch; a Manager without its store never got this far.
    param([Parameter(Mandatory)][string]$BaseName, [switch]$NoScope)
    if (-not $script:PimSqlCs -or -not (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue)) {
        throw "Read-PimRows '$BaseName': the SQL store is not initialised (the Manager is SQL-only)."
    }
    $spec = Get-PimCsvSpec -BaseName $BaseName
    $hdr  = if ($spec) { @($spec.defaultHeader) } else { @() }
    $sqlRows = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $BaseName)
    if (($hdr.Count -eq 0) -and $sqlRows.Count -gt 0) { $hdr = @($sqlRows[0].PSObject.Properties.Name) }
    return (Limit-PimRowsToScope -Result @{ header = $hdr; rows = $sqlRows; source = 'sql'; path = "sql:$BaseName" } -BaseName $BaseName -NoScope:$NoScope)
}
function Compare-PimRowSets {
    # Per-row diff between two row arrays for the Review & Save preview.
    # Returns @{ adds = [...]; removes = [...]; modifies = [{ before, after, diffCols }]; unchanged = N }.
    #
    # KEYED diff (M2): rows are matched by their STABLE per-entity key (the same
    # natural key the store uses -- Get-PimStoreRowKey -Base $Base) instead of by
    # position. So a pure REORDER of identical rows is correctly seen as ZERO
    # change; same key + different field values = a modify; key only in After = an
    # add; key only in Before = a remove. This stops a reordered row (very common
    # after an Excel round-trip or an authoring move) from showing as a misleading
    # modify/remove.
    #
    # Graceful fallback: rows whose key is blank (no derivable natural key) OR that
    # COLLIDE on a key (the same key appears more than once on one side) cannot be
    # matched safely by key, so they are diffed by the legacy content-then-position
    # method (full-row-content match for unchanged; leftover adds/removes paired
    # positionally into modifies). $Base is optional -- with no $Base (or when the
    # key helper isn't loaded) the whole comparison uses the legacy method, so old
    # callers keep their exact prior behaviour.
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Before,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$After,
        [string]$Base = ''
    )

    # Full-row content fingerprint (order-independent over columns). Two rows with
    # the same fingerprint are byte-for-byte equal in content.
    function _RowKey([object]$row) {
        if ($null -eq $row) { return '' }
        $kvs = @()
        if ($row -is [System.Collections.IDictionary]) {
            foreach ($k in ($row.Keys | Sort-Object)) {
                $kvs += "$k=$($row[$k])"
            }
        } else {
            foreach ($p in ($row.PSObject.Properties | Sort-Object Name)) {
                $kvs += "$($p.Name)=$($p.Value)"
            }
        }
        return ($kvs -join ([char]1))
    }

    # Natural (stable) key for a row, reusing the store's own key derivation so we
    # never invent a parallel keying scheme. Returns '' when unavailable.
    function _NaturalKey([string]$baseName, [object]$row) {
        if ($null -eq $row) { return '' }
        if (-not "$baseName".Trim()) { return '' }
        if (-not (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue)) { return '' }
        try { return "$(Get-PimStoreRowKey -Base $baseName -Row $row)" } catch { return '' }
    }

    # Column-level field comparison between two rows -> array of differing columns.
    function _DiffCols([object]$beforeRow, [object]$afterRow) {
        $cols = New-Object System.Collections.ArrayList
        $allCols = @()
        if ($beforeRow -is [System.Collections.IDictionary]) { $allCols += @($beforeRow.Keys) } else { $allCols += @($beforeRow.PSObject.Properties.Name) }
        if ($afterRow  -is [System.Collections.IDictionary]) { $allCols += @($afterRow.Keys)  } else { $allCols += @($afterRow.PSObject.Properties.Name) }
        $allCols = $allCols | Select-Object -Unique
        foreach ($c in $allCols) {
            $bv = if ($beforeRow -is [System.Collections.IDictionary]) { "$($beforeRow[$c])" } else { "$($beforeRow.PSObject.Properties[$c].Value)" }
            $av = if ($afterRow  -is [System.Collections.IDictionary]) { "$($afterRow[$c])"  } else { "$($afterRow.PSObject.Properties[$c].Value)" }
            if ($bv -ne $av) { [void]$cols.Add($c) }
        }
        return $cols.ToArray()
    }

    $unchanged = 0
    $adds = New-Object System.Collections.ArrayList
    $removes = New-Object System.Collections.ArrayList
    # NOTE: avoid local variable names $before / $after -- they case-insensitively
    # shadow the typed params $Before / $After ([object[]]), and PowerShell would
    # coerce any subsequent assignment back to [object[]], wrapping an
    # OrderedDictionary into a 1-element array. Use $beforeRow / $afterRow.
    $modifies = New-Object System.Collections.ArrayList

    # ---- Phase 1: keyed match by natural key -------------------------------
    # Bucket each side by natural key. A key is "usable" only when it is non-blank
    # AND occurs exactly once on EACH side it appears in (no collision). Anything
    # else falls through to the legacy content/positional phase below.
    $beforeByKey = @{}
    foreach ($r in $Before) {
        $nk = _NaturalKey $Base $r
        if (-not $nk) { continue }
        if (-not $beforeByKey.ContainsKey($nk)) { $beforeByKey[$nk] = New-Object System.Collections.ArrayList }
        [void]$beforeByKey[$nk].Add($r)
    }
    $afterByKey = @{}
    foreach ($r in $After) {
        $nk = _NaturalKey $Base $r
        if (-not $nk) { continue }
        if (-not $afterByKey.ContainsKey($nk)) { $afterByKey[$nk] = New-Object System.Collections.ArrayList }
        [void]$afterByKey[$nk].Add($r)
    }

    # Which keys are safe to resolve by key (unique on each side they appear in).
    $keyedHandled = @{}
    $allKeys = @{}
    foreach ($k in $beforeByKey.Keys) { $allKeys[$k] = $true }
    foreach ($k in $afterByKey.Keys)  { $allKeys[$k] = $true }
    foreach ($k in @($allKeys.Keys)) {
        $bCount = if ($beforeByKey.ContainsKey($k)) { $beforeByKey[$k].Count } else { 0 }
        $aCount = if ($afterByKey.ContainsKey($k))  { $afterByKey[$k].Count }  else { 0 }
        if ($bCount -gt 1 -or $aCount -gt 1) { continue }  # collision -> legacy fallback
        $keyedHandled[$k] = $true
        if ($bCount -eq 1 -and $aCount -eq 1) {
            $beforeRow = $beforeByKey[$k][0]
            $afterRow  = $afterByKey[$k][0]
            $cols = _DiffCols $beforeRow $afterRow
            if (@($cols).Count -eq 0) {
                $unchanged++            # same key, same values (reorder is invisible)
            } else {
                [void]$modifies.Add([ordered]@{ before = $beforeRow; after = $afterRow; diffCols = $cols })
            }
        } elseif ($aCount -eq 1) {
            [void]$adds.Add($afterByKey[$k][0])         # key only in After
        } else {
            [void]$removes.Add($beforeByKey[$k][0])     # key only in Before
        }
    }

    # ---- Phase 2: legacy content/positional for everything left ------------
    # The leftovers are: rows with a blank natural key, plus rows on a colliding
    # key. Diff them by full content (unchanged) then pair positionally (modifies).
    $beforeLeft = New-Object System.Collections.ArrayList
    foreach ($r in $Before) {
        $nk = _NaturalKey $Base $r
        if ($nk -and $keyedHandled.ContainsKey($nk)) { continue }
        [void]$beforeLeft.Add($r)
    }
    $afterLeft = New-Object System.Collections.ArrayList
    foreach ($r in $After) {
        $nk = _NaturalKey $Base $r
        if ($nk -and $keyedHandled.ContainsKey($nk)) { continue }
        [void]$afterLeft.Add($r)
    }

    $beforeMap = @{}
    foreach ($r in $beforeLeft) {
        $k = _RowKey $r
        if (-not $beforeMap.ContainsKey($k)) { $beforeMap[$k] = New-Object System.Collections.ArrayList }
        [void]$beforeMap[$k].Add($r)
    }

    $legacyAdds = New-Object System.Collections.ArrayList
    $legacyRemoves = New-Object System.Collections.ArrayList
    foreach ($r in $afterLeft) {
        $k = _RowKey $r
        if ($beforeMap.ContainsKey($k) -and $beforeMap[$k].Count -gt 0) {
            $beforeMap[$k].RemoveAt(0)
            $unchanged++
        } else {
            [void]$legacyAdds.Add($r)
        }
    }
    foreach ($k in $beforeMap.Keys) {
        foreach ($r in $beforeMap[$k]) { [void]$legacyRemoves.Add($r) }
    }

    # Pair leftover adds + removes positionally to surface column-level modifies.
    $pairs = [Math]::Min($legacyAdds.Count, $legacyRemoves.Count)
    for ($i = 0; $i -lt $pairs; $i++) {
        $beforeRow = $legacyRemoves[0]
        $afterRow  = $legacyAdds[0]
        $legacyRemoves.RemoveAt(0); $legacyAdds.RemoveAt(0)
        [void]$modifies.Add([ordered]@{ before = $beforeRow; after = $afterRow; diffCols = (_DiffCols $beforeRow $afterRow) })
    }
    foreach ($r in $legacyAdds)    { [void]$adds.Add($r) }
    foreach ($r in $legacyRemoves) { [void]$removes.Add($r) }

    return @{
        adds      = $adds.ToArray()
        removes   = $removes.ToArray()
        modifies  = $modifies.ToArray()
        unchanged = $unchanged
    }
}

function Write-PimMutationLog {
    param(
        [Parameter(Mandatory)][string]$BaseName,
        [Parameter(Mandatory)][int]$Adds,
        [Parameter(Mandatory)][int]$Removes,
        [Parameter(Mandatory)][int]$Modifies,
        [Parameter(Mandatory)][int]$NewRowCount,
        # §70.14 -- the keyed diff, so the audit row says WHO got WHAT, WHERE (not just counts).
        [object]$Diff = $null,
        [string]$Summary = ''
    )
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = "$ts`t$BaseName`t$Adds`t$Removes`t$Modifies`t$NewRowCount"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    # AppendAllText creates the file if missing, no BOM, UTF-8.
    [System.IO.File]::AppendAllText($mutationLog, ($line + "`r`n"), $utf8NoBom)

    # 🔴 SEC-16 (second writer, found 2026-08-31). This block used to be a SECOND, INLINE audit
    # writer: its own jsonl append, its own actor. Two consequences, both bad:
    #   * it recorded [WindowsIdentity]::GetCurrent().Name -- the CONTAINER's process user on a
    #     hosted deployment. Its own comment said "the Windows identity driving the localhost
    #     session", which was true for a local single-operator install and false here;
    #   * it was file-only, so `config.csv.save` -- the record that SOMEBODY COMMITTED A CHANGE TO
    #     DESIRED STATE, arguably the most consequential event this product emits -- never reached
    #     SQL and died with the container on the next revision roll.
    # 🔑 The first SEC-16 fix repaired the OTHER writer and left this one. Two implementations of
    # "write an audit event" is the defect; there is now ONE, and this calls it.
    # §70.14 (operator 2026-09-13): "it mentions .csv. we dont support csv anymore, only sql" and "log is
    # useless, as I cannot see ... who did delegate what to whom". The action is `config.save` (PIM v2 is
    # SQL-only), and the event carries one readable sentence per added / removed / changed row. The counts
    # stay for the daily-summary notification, which reads them.
    try {
        $after = [ordered]@{
            summary  = $(if ("$Summary".Trim()) { "$Summary" } else { "$Adds added, $Removes removed, $Modifies changed ($NewRowCount rows now)" })
            adds = $Adds; removes = $Removes; modifies = $Modifies; rowCount = $NewRowCount
        }
        if ($null -ne $Diff -and (Get-Command Get-PimAuditCommitChangeLines -ErrorAction SilentlyContinue)) {
            try {
                # §70.22: name groups by their REAL name (PIM-Entra-ID-...), not the tag an assignment row carries.
                $nameByTag = $null
                if ("$BaseName" -match '^(?i)PIM-Assignments-') {
                    $nameByTag = @{}
                    foreach ($defEnt in @('PIM-Definitions-Roles','PIM-Definitions-Departments','PIM-Definitions-Organization','PIM-Definitions-Projects','PIM-Definitions-CrossOrg','PIM-Definitions-Tasks','PIM-Definitions-Services','PIM-Definitions-Processes','PIM-Definitions-Resources')) {
                        try { foreach ($dr in @((Read-PimRows $defEnt -NoScope).rows)) { $tg = "$($dr.GroupTag)".Trim(); $gn = "$($dr.GroupName)".Trim(); if ($tg -and $gn) { $nameByTag[$tg.ToLowerInvariant()] = $gn } } } catch { }
                    }
                }
                $cl = Get-PimAuditCommitChangeLines -Base $BaseName -Diff $Diff -GroupNameByTag $nameByTag
                $after['changes'] = @($cl.lines)
                if ($cl.omitted -gt 0) { $after['changesOmitted'] = [int]$cl.omitted }
            } catch { $after['changes'] = @("(the row details could not be described: $($_.Exception.Message))") }
        }
        Write-PimManagerAuditEvent -Action 'config.save' -Target $BaseName -After $after
    } catch {
        Write-Warning "audit write failed (save NOT blocked): $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# §70.21 START THE ENGINE NOW (operator 2026-09-13: "i want to have a run now to start a tick immediately. we need
# things as fast as possible"). A commit or a "Run now" used to wait for the next 5-minute cron start of the tick job.
# The Manager still never runs the engine itself (§22): it asks Container Apps to start ONE execution of the tick job
# (ARM POST .../jobs/<tick>/start), and that execution drains the trigger / queue entry exactly like a cron start.
#   * Needs 'Container Apps Jobs Operator' for this Manager's managed identity, scoped to the tick job only, and the
#     job's resource id in env PIM_TickJobId or pim.Settings 'SchedulerTickJobId'. Without either it degrades to the
#     old behaviour (the next cron start) and says so -- it never fails the commit.
#   * Not while a tick holds the lease: that run picks the work up between its jobs, and a second execution would
#     only find the lease taken and exit.
#   * Debounced (45 s), so a multi-entity commit starts one execution, not one per entity.
# ---------------------------------------------------------------------------
$script:PimTickKickAt = $null
function Get-PimManagerAdminTypeFromName {
    # PURE. The admin type an account name implies when its row has no AdminType (see the admin grid).
    param([string]$Name)
    $n = "$Name".Trim().ToLowerInvariant()
    if (-not $n) { return '' }
    if ($n.StartsWith('x-')) { return 'external-adminuser' }
    if ($n.StartsWith('g-')) { return 'external-guest' }
    return 'internal-adminuser'
}
function Get-PimManagerTickJobId {
    $id = "$($env:PIM_TickJobId)".Trim()
    if (-not $id -and (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) {
        try { $id = "$(Get-PimSetting -Name 'SchedulerTickJobId')".Trim().Trim('"') } catch { $id = '' }
    }
    if ($id -notmatch '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.App/jobs/[^/]+$') { return '' }
    return $id
}
function Start-PimManagerTickNow {
    param([string]$Reason = 'manager', [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $nextCron = 'the next scheduled start (within about 5 minutes)'
    if (-not $script:PimHosted -and -not "$($env:PIM_TickJobId)".Trim()) {
        return [pscustomobject]@{ started = $false; reason = 'not-hosted'; detail = "runs on $nextCron" }
    }
    if ($script:PimTickKickAt -and ($now - $script:PimTickKickAt).TotalSeconds -lt 45) {
        return [pscustomobject]@{ started = $true; reason = 'recent'; detail = 'the engine was started moments ago; that run picks this up' }
    }
    if (Get-Command Get-PimSchedulerLeaseRaw -ErrorAction SilentlyContinue) {
        try {
            $l = (Get-PimSchedulerLeaseRaw).Lease
            if ($l -and "$($l.owner)".Trim() -and "$($l.expiresUtc)".Trim()) {
                $exp = [datetime]::MinValue
                $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
                if ([datetime]::TryParse("$($l.expiresUtc)", [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$exp) -and $exp.ToUniversalTime() -gt $now) {
                    return [pscustomobject]@{ started = $false; reason = 'running'; detail = 'an engine run is in progress; it picks this up as soon as its current step finishes' }
                }
            }
        } catch { }
    }
    $id = Get-PimManagerTickJobId
    if (-not $id) {
        return [pscustomobject]@{ started = $false; reason = 'not-configured'; detail = "runs on $nextCron (immediate start is not configured: set pim.Settings SchedulerTickJobId)" }
    }
    if (-not (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ started = $false; reason = 'no-arm'; detail = "runs on $nextCron" }
    }
    try {
        $r = Invoke-PimArm -Method POST -Path "$id/start" -ApiVersion '2024-03-01' -Body @{}
        $script:PimTickKickAt = $now
        $exec = if ($r -and $r.PSObject.Properties['name']) { "$($r.name)" } else { '' }
        Write-Host "[manager] started the engine tick now ($Reason)$(if ($exec) { " execution $exec" })" -ForegroundColor Cyan
        return [pscustomobject]@{ started = $true; reason = 'started'; execution = $exec; detail = 'the engine was started now' }
    } catch {
        $m = "$($_.Exception.Message)"
        Write-Warning "[manager] could not start the engine tick now ($Reason): $m"
        $why = if ($m -match '(?i)\b403\b|AuthorizationFailed|forbidden') { "the Manager identity lacks 'Container Apps Jobs Operator' on the tick job" } else { $m.Substring(0, [Math]::Min(160, $m.Length)) }
        return [pscustomobject]@{ started = $false; reason = 'error'; detail = "runs on $nextCron ($why)" }
    }
}

# ---------------------------------------------------------------------------
# Safe, reversible commits (REQUIREMENTS.md s28 [M1]) -- the Manager-side glue
# that wires the pure PIM-CommitBackup.ps1 core to whichever store is active.
# Timestamped backup BEFORE every commit; the apply is all-or-nothing; an
# operator can undo (restore the snapshot) from the Review & Save tab.
# ---------------------------------------------------------------------------

# How many snapshots to keep per entity (oldest beyond this are pruned each commit).
$script:PimBackupKeep = 10

function Invoke-PimManagerSafeCommit {
    # The [M1] commit: snapshot -> transactional apply -> rollback-on-failure ->
    # prune. Used by PUT /api/csv/<base>. Returns the Invoke-PimCommitTransaction
    # result (ok/snapshotId/applied/restored/error). Throws (with a clear message)
    # on failure -- the store is left exactly as before.
    param(
        [Parameter(Mandatory)][string]$Base,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$NewRows,
        [Parameter(Mandatory)][hashtable]$Current,   # @{ rows; header } pre-commit state
        [bool]$SqlMode
    )
    # SEC-16(b) -- the snapshot's `By` is evidence ("who committed this change"), so it must be the
    # signed-in principal, not the container's process user. Same defect as the audit writer.
    $who = try { $r = Get-PimManagerRole; if ("$($r.identity)".Trim()) { "$($r.identity)" } else { throw } }
           catch { try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME } }
    $snapshot = New-PimCommitSnapshot -Entity $Base -Base $Base -Rows @($Current.rows) -Header @($Current.header) -By "$who" -Reason 'review-and-save commit'

    # SQL-only: the snapshot store, the apply and the restore are all SQL (no file branch).
    $null = $SqlMode
    if ($true) {
        try { Initialize-PimBackupStore -ConnectionString $script:PimSqlCs } catch { Write-Warning "  [backup] init store failed (non-fatal): $($_.Exception.Message)" }
        $save    = { param($s) Save-PimSqlBackupSnapshot -ConnectionString $script:PimSqlCs -Snapshot $s }
        # 🔒 -AllowEmpty IS DELIBERATE ON EXACTLY THESE TWO PATHS, AND NOWHERE ELSE.
        # The store now refuses a full-set replace that submits nothing against a non-empty entity,
        # because that is nearly always a failed upstream read rather than an intent to clear
        # (see Set-PimSqlEntityRowsTransactional). Two callers genuinely do mean it:
        #   * this COMMIT -- a human staged the deletions, saw the count on Review & Save, and a
        #     backup snapshot of the pre-commit state is written immediately before this runs; and
        #   * this RESTORE -- rolling back to a snapshot that legitimately held no rows.
        # Both are human-initiated and both are reversible from the backup store, which is what
        # separates them from an importer handing over an empty array it did not mean to produce.
        $apply   = { Set-PimSqlEntityRowsTransactional -ConnectionString $script:PimSqlCs -Entity $Base -Base $Base -Rows $NewRows -AllowEmpty }
        $restore = { param($s) $plan = Get-PimSnapshotRestorePlan -Snapshot $s; Set-PimSqlEntityRowsTransactional -ConnectionString $script:PimSqlCs -Entity $plan.entity -Base $plan.base -Rows @($plan.rows) -AllowEmpty }
        $prune   = { [void](Invoke-PimSqlBackupRetention -ConnectionString $script:PimSqlCs -Entity $Base -Keep $script:PimBackupKeep) }
    }

    return (Invoke-PimCommitTransaction -Snapshot $snapshot -ApplyScript $apply -RestoreScript $restore -SaveSnapshotScript $save -PruneScript $prune)
}

function Get-PimManagerBackupList {
    param([string]$Entity)
    try { Initialize-PimBackupStore -ConnectionString $script:PimSqlCs } catch { }
    return @(Get-PimSqlBackupSnapshots -ConnectionString $script:PimSqlCs -Entity $Entity)
}

function Invoke-PimManagerBackupRestore {
    # Operator UNDO: replay a stored snapshot back over its entity (full-set replace,
    # transactional). Returns @{ ok; entity; rowCount; preRestoreSnapshotId } or throws.
    #
    # [Fix 5] A restore is itself a destructive write (it REPLACES the live set with the
    # snapshot's set, so it can drop rows that exist now). It now (a) takes a PRE-RESTORE
    # snapshot first, so a restore is itself undoable (it previously took none), and (b)
    # runs the SAME empty-set / large-delta guard the commit path uses -- refusing to
    # roll back to an empty / much-smaller set unless $Confirm is set.
    param([Parameter(Mandatory)][string]$Id, [switch]$Confirm)
    try { Initialize-PimBackupStore -ConnectionString $script:PimSqlCs } catch { }
    $snap = Get-PimSqlBackupSnapshot -ConnectionString $script:PimSqlCs -Id $Id
    if (-not $snap) { throw "snapshot '$Id' not found" }
    $plan = Get-PimSnapshotRestorePlan -Snapshot $snap

    # Current live rows for this entity (the 'before' of the restore).
    $curRows = @()
    try {
        $curRows = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $plan.entity)
    } catch { $curRows = @() }

    # [Fix 5] empty-set / large-delta guard on the restore (restore is a full-set
    # replace; rows in the live set but not in the snapshot are removed).
    if (Get-Command Test-PimCommitDeltaGuard -ErrorAction SilentlyContinue) {
        $restoreCount = @($plan.rows).Count
        $removed = [Math]::Max(0, (@($curRows).Count) - $restoreCount)
        $g = Test-PimCommitDeltaGuard -BeforeCount (@($curRows).Count) -AfterCount $restoreCount -RemoveCount $removed -Confirm:$Confirm
        if (-not $g.allowed) {
            throw "restore refused: $($g.reason)"
        }
    }

    # [Fix 5] PRE-RESTORE snapshot so the restore is itself undoable.
    $preId = ''
    try {
        # SEC-16(b) -- "who restored" is evidence too.
        $who = try { $r = Get-PimManagerRole; if ("$($r.identity)".Trim()) { "$($r.identity)" } else { throw } }
               catch { try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME } }
        $curHeader = @()
        $spec = Get-PimCsvSpec -BaseName $plan.entity; if ($spec) { $curHeader = @($spec.defaultHeader) }
        $preSnap = New-PimCommitSnapshot -Entity $plan.entity -Base $plan.base -Rows @($curRows) -Header @($curHeader) -By "$who" -Reason ("pre-restore of snapshot $Id")
        Save-PimSqlBackupSnapshot -ConnectionString $script:PimSqlCs -Snapshot $preSnap | Out-Null
        $preId = "$($preSnap.snapshotId)"
    } catch { Write-Warning "  [restore] pre-restore snapshot failed (non-fatal): $($_.Exception.Message)" }

    if ($true) {
        # 🔴 -AllowEmpty, for the same reason as the commit's own restore script (Invoke-PimManagerSafeCommit):
        # restoring a snapshot that legitimately held NO rows is an operator UNDO, already gated by the
        # delta guard above (it refuses unless $Confirm) and preceded by a pre-restore snapshot. Without
        # it the store refused every restore-to-empty with a 500 -- BUG-05's shape on the SQL store, found
        # 2026-09-12 when Test-PimManagerEndpoints' FIX5 block first ran against a populated SQL entity
        # (on the old file store that block had silently skipped).
        [void](Set-PimSqlEntityRowsTransactional -ConnectionString $script:PimSqlCs -Entity $plan.entity -Base $plan.base -Rows @($plan.rows) -AllowEmpty)
    }
    return @{ ok = $true; entity = $plan.entity; rowCount = @($plan.rows).Count; preRestoreSnapshotId = $preId }
}

# ---------------------------------------------------------------------------
# Naming conventions (shipped .locked defaults overlaid by the SQL store, so the UI
# sees what the engines would see). Best-effort: returns defaults if the locked file
# can't be sourced (e.g. running outside the repo layout). No .custom.ps1 (SQL-only).
# ---------------------------------------------------------------------------

function Get-PimNamingConventions {
    $defaults = @{
        # Admin name = {AdminTypePrefix} + 'Admin-{Owner}' + {EnvironmentSuffix} (§17).
        AdminAccountPattern           = '{AdminTypePrefix}Admin-{Owner}{EnvironmentSuffix}'
        AdminAccountPatternHighPriv   = '{AdminTypePrefix}Admin-{Owner}-L0-T0{EnvironmentSuffix}'
        AdminTypePrefixes             = [ordered]@{ 'internal-adminuser' = ''; 'external-adminuser' = 'x-'; 'external-guest' = 'g-' }
        AdminTypeDefault              = 'internal-adminuser'
        EnvironmentSuffixes           = [ordered]@{ 'entra' = '-ID'; 'ad' = '-AD' }
        EnvironmentDefault            = 'entra'
        AdminAccountUpnSuffix         = $null
        PimGroupPattern               = 'PIM-{Role}-{Department}'
        PimGroupAuPattern             = 'PIM-{Role}-AU-{AdminUnit}'
        ResourceGroupPattern          = 'rg-pim-{Tier}'
        AdminAccountDisplayNameSuffix = ' (Admin)'
    }
    # 1) the SHIPPED defaults (.locked.ps1 -- code, not customer data). Sourced with the global map
    #    saved and restored: the file assigns $global:PIM_NamingConventions wholesale, and doing that
    #    on every call used to wipe whatever the store had hydrated into this process.
    # 2) the customer's values from SQL pim.Settings['NamingConventions'] (what Settings edits).
    # 🔒 SQL-ONLY (2026-09-13): PIM4EntraPS.NamingConventions.custom.ps1 is NOT read here any more.
    $locked = Join-Path $configRoot 'PIM4EntraPS.NamingConventions.locked.ps1'
    if (Test-Path -LiteralPath $locked) {
        $prevNc = $global:PIM_NamingConventions
        try {
            $global:PIM_NamingConventions = $null
            . $locked
            if ($global:PIM_NamingConventions -is [System.Collections.IDictionary]) {
                foreach ($k in @($global:PIM_NamingConventions.Keys)) { $defaults[$k] = $global:PIM_NamingConventions[$k] }
            }
        } catch { Write-Warning "  failed to source $locked : $($_.Exception.Message)" }
        finally { $global:PIM_NamingConventions = $prevNc }
    }
    $stored = $null
    try { if ($script:PimSqlCs) { $stored = Get-PimManagerSetting -Name 'NamingConventions' } } catch { Write-Warning "  naming conventions: SQL read failed: $($_.Exception.Message)" }
    if ($stored) {
        $sh = ConvertTo-PimPlainHashtable $stored
        foreach ($k in @($sh.Keys)) { $defaults[$k] = $sh[$k] }
    }
    return $defaults
}

# ---------------------------------------------------------------------------
# Settings admin area (REQUIREMENTS §11) -- naming conventions, filters,
# departments(+owners) and approvers/owners managed THROUGH THE STORE the
# engine uses (SQL pim.Settings -- the only store; never a file).
#
# Hard requirement: NamingConventions + Filters must NEVER be empty. On first
# read we fall back to a shipped sensible default and PERSIST it, so a fresh
# install always has a working convention/filter that an admin can then edit.
#
# Single chokepoint:
#   Get-PimManagerSetting  <Name>            -> parsed object | $null
#   Set-PimManagerSetting  <Name> <Value>    -> persists (SQL or file)
# Higher-level wrappers add the default-seeding + shape normalisation.
# ---------------------------------------------------------------------------

function Get-PimManagerSetting {
    # Read a single named setting from the store (SQL pim.Settings). Returns the parsed object (or $null).
    # 🔒 SQL-ONLY: there is no settings file; a missing store is an error, never an empty answer.
    param([Parameter(Mandatory)][string]$Name)
    if (-not $script:PimSqlCs -or -not (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
        throw "Get-PimManagerSetting '$Name': the SQL store is not initialised (the Manager is SQL-only)."
    }
    return (Get-PimSqlSetting -ConnectionString $script:PimSqlCs -Name $Name)
}

function Set-PimManagerSetting {
    # Persist a single named setting to the store (SQL pim.Settings).
    param([Parameter(Mandatory)][string]$Name, [object]$Value)
    if (-not $script:PimSqlCs -or -not (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) {
        throw "Set-PimManagerSetting '$Name': the SQL store is not initialised (the Manager is SQL-only)."
    }
    Set-PimSqlSetting -ConnectionString $script:PimSqlCs -Name $Name -Value $Value
}
# ---------------------------------------------------------------------------
# Alerting configuration (REQUIREMENTS §27 H2). Persisted in the SAME store as
# every other Manager setting (SQL pim.Settings when hosted, else the per-
# instance JSON file) under the 'Alerting' key. Defines WHO gets alerted and
# WHICH events fire. Delivery rides the EXISTING notify path (Send-PimNotifyMail
# -> Graph Mail.Send), gated on $global:PIM_MailSender exactly like every other
# PIM mail -- so when no sender is configured the alert renders but is NOT sent
# (an honest "configure to enable" state, never a fake send).
# ---------------------------------------------------------------------------
$script:PimAlertEventCatalog = @('engine-failure','drift','expiring-access','break-glass')

function Get-PimAlertingConfig {
    # Returns the normalized alerting config (defaults applied), shape:
    #   @{ recipients=[..]; events=@{ 'engine-failure'=$true; ... }; enabled=$bool }
    $raw = $null
    try { $raw = Get-PimManagerSetting -Name 'Alerting' } catch {}
    $recipients = @()
    # Optional per-report lists (PIM-Notifications.ps1 Get-PimNotificationRecipients): the daily digest
    # and the tier report go to these when set, else to 'recipients'.
    $digestRecipients = @(); $tierReportRecipients = @()
    $events = @{}
    foreach ($e in $script:PimAlertEventCatalog) { $events[$e] = $true }   # default: all events ON
    if ($raw) {
        $r = $raw
        if ($r -is [string]) { try { $r = $r | ConvertFrom-Json } catch { $r = $null } }
        if ($r) {
            # The stored value may be a [hashtable]/[ordered] dict (in-process / file
            # round-trip) or a PSCustomObject (JSON). Read both shapes -- PSObject.Properties
            # does NOT see dictionary keys, so check IDictionary first.
            $getProp = {
                param($obj, $key)
                if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($key)) { return $obj[$key] } return $null }
                $p = $obj.PSObject.Properties[$key]; if ($p) { return $p.Value } return $null
            }
            $recProp = & $getProp $r 'recipients'
            if ($recProp) { $recipients = @($recProp | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
            $dgProp = & $getProp $r 'digestRecipients'
            if ($dgProp) { $digestRecipients = @($dgProp | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
            $trProp = & $getProp $r 'tierReportRecipients'
            if ($trProp) { $tierReportRecipients = @($trProp | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
            $evProp = & $getProp $r 'events'
            if ($evProp) {
                foreach ($e in $script:PimAlertEventCatalog) {
                    $val = $null
                    if ($evProp -is [System.Collections.IDictionary]) { if ($evProp.Contains($e)) { $val = $evProp[$e] } }
                    elseif ($evProp.PSObject.Properties[$e]) { $val = $evProp.PSObject.Properties[$e].Value }
                    if ($null -ne $val) { $events[$e] = [bool]$val }
                }
            }
        }
    }
    # Outbound webhook channel (Teams / generic JSON) -- normalised from the SAME
    # stored 'Alerting' value via the shared pure core. A bad/unsafe URL leaves the
    # channel disabled (never silently posts). This is a SECOND channel beside mail.
    $chan = $null
    if (Get-Command Get-PimAlertChannelConfig -ErrorAction SilentlyContinue) {
        try { $chan = Get-PimAlertChannelConfig -Raw $raw } catch {}
    }
    if (-not $chan) { $chan = [ordered]@{ webhookUrl = ''; webhookKind = 'generic'; webhookEnabled = $false; webhookValid = $false; webhookReason = '' } }
    # Alerting is "enabled" only when there is at least one DELIVERY channel: a
    # configured sender mailbox (with a recipient) OR a valid outbound webhook --
    # otherwise it is a render-only "configure to enable" state.
    $hasSender = [bool]("$($global:PIM_MailSender)".Trim())
    $mailReady = ($recipients.Count -gt 0 -and $hasSender)
    [ordered]@{
        recipients     = @($recipients)
        digestRecipients     = @($digestRecipients)
        tierReportRecipients = @($tierReportRecipients)
        events         = $events
        eventCatalog   = @($script:PimAlertEventCatalog)
        senderSet      = $hasSender
        webhookUrl     = $chan.webhookUrl
        webhookKind    = $chan.webhookKind
        webhookEnabled = $chan.webhookEnabled
        webhookValid   = $chan.webhookValid
        webhookReason  = $chan.webhookReason
        enabled        = ($mailReady -or [bool]$chan.webhookEnabled)
    }
}

function Set-PimAlertingConfig {
    # -DigestRecipients / -TierReportRecipients: when NOT passed, the stored lists are KEPT. A save
    # from an older page (which knows nothing of them) used to rewrite 'Alerting' without them and
    # silently send the digest and the tier report back to the general list.
    param([string[]]$Recipients, [hashtable]$Events, [string]$WebhookUrl, [string]$WebhookKind,
          [string[]]$DigestRecipients, [string[]]$TierReportRecipients)
    $cleanList = {
        param($list)
        $o = @()
        foreach ($r in @($list)) {
            $s = "$r".Trim()
            # Keep only plausible email addresses; drop blanks/garbage so we never mail nonsense.
            if ($s -and $s -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { $o += $s }
        }
        $o   # unrolled on purpose: every caller wraps it in @(), and ,$o would nest the list
    }
    $clean = @(& $cleanList $Recipients)
    $prior = $null
    if (-not $PSBoundParameters.ContainsKey('DigestRecipients') -or -not $PSBoundParameters.ContainsKey('TierReportRecipients')) { $prior = Get-PimAlertingConfig }
    $digest = if ($PSBoundParameters.ContainsKey('DigestRecipients')) { @(& $cleanList $DigestRecipients) } else { @($prior.digestRecipients) }
    $tier   = if ($PSBoundParameters.ContainsKey('TierReportRecipients')) { @(& $cleanList $TierReportRecipients) } else { @($prior.tierReportRecipients) }
    $ev = @{}
    foreach ($e in $script:PimAlertEventCatalog) {
        if ($Events -and $Events.ContainsKey($e)) { $ev[$e] = [bool]$Events[$e] } else { $ev[$e] = $true }
    }
    # Outbound webhook channel. The URL is stored verbatim (so an operator can read
    # it back / clear it) but VALIDATED at config-read + send time; a blank URL
    # disables the channel. The kind is normalised (teams|generic; auto-detected
    # from a Teams webhook host when left blank).
    $url = "$WebhookUrl".Trim()
    $kind = ''
    if (Get-Command Resolve-PimWebhookKind -ErrorAction SilentlyContinue) { $kind = Resolve-PimWebhookKind -Url $url -Kind $WebhookKind }
    else { $kind = "$WebhookKind".Trim().ToLowerInvariant(); if ($kind -ne 'teams' -and $kind -ne 'generic') { $kind = 'generic' } }
    Set-PimManagerSetting -Name 'Alerting' -Value ([ordered]@{ recipients = @($clean); digestRecipients = @($digest); tierReportRecipients = @($tier); events = $ev; webhookUrl = $url; webhookKind = $kind })
    return (Get-PimAlertingConfig)
}

function Send-PimWebhookAlert {
    # Outbound webhook delivery for ONE alert (the channel-layer I/O for the Teams /
    # generic webhook channel -- mirrors what Send-PimNotifyMail is for the mail
    # channel). Builds the payload with the pure core, then POSTs it over HTTPS.
    # Returns @{ attempted; sent; kind; reason }. NEVER throws.
    param(
        [Parameter(Mandatory)][string]$Event,
        [string]$Title,
        [string]$Detail,
        [string]$LinkTab,
        [object]$Config,
        [switch]$WhatIf
    )
    $res = [ordered]@{ attempted = $false; sent = $false; kind = ''; reason = '' }
    $cfg = $Config; if (-not $cfg) { $cfg = Get-PimAlertingConfig }
    if (-not [bool]$cfg.webhookEnabled) { $res.reason = $(if ("$($cfg.webhookReason)".Trim()) { "$($cfg.webhookReason)" } else { 'no webhook configured' }); return $res }
    if (-not (Get-Command New-PimWebhookPayload -ErrorAction SilentlyContinue)) { $res.reason = 'channel core not loaded'; return $res }
    $kind = "$($cfg.webhookKind)"; if (-not $kind) { $kind = 'generic' }
    $res.kind = $kind
    $res.attempted = $true
    $tenantCtx = try { Get-PimManagerTenantContext } catch { @{ tenantName = '' } }
    $payload = $null
    try {
        $payload = New-PimWebhookPayload -Event $Event -Title $Title -Detail $Detail -LinkTab $LinkTab -TenantName "$($tenantCtx.tenantName)" -Instance "$($script:PimInstanceName)" -Kind $kind
    } catch { $res.reason = "payload build failed: $($_.Exception.Message)"; return $res }
    if ($WhatIf) { $res.reason = 'rendered only (whatif)'; return $res }
    try {
        $json = $payload | ConvertTo-Json -Depth 8 -Compress
        # Re-check the URL right before posting (defence-in-depth against a value that
        # changed shape in the store). Use Invoke-RestMethod (REST-only, no modules).
        $check = Test-PimWebhookUrlAllowed -Url $cfg.webhookUrl
        if (-not [bool]$check.allowed) { $res.reason = "blocked: $($check.reason)"; return $res }
        Invoke-RestMethod -Method Post -Uri $cfg.webhookUrl -ContentType 'application/json; charset=utf-8' -Body $json -TimeoutSec 20 | Out-Null
        $res.sent = $true
    } catch {
        $res.reason = "webhook POST failed: $($_.Exception.Message)"
    }
    return $res
}

# The recorded-alert FEED (the durable send-proof) lives in SQL pim.Settings['AlertFeed'] only.
# The output/alerts/pim-alerts.jsonl file it used to fall back to on local/dev is gone (SQL-only,
# 2026-09-13): reader and writer agree on ONE store, so the Home tile and the tab cannot disagree.
function Get-PimManagerAlertFeed {
    # Read the recorded alert feed (newest-first). Never throws -- a feed read that takes down the
    # Home tile would be worse than a short feed -- but a missing store is WARNED, never read from disk.
    $cs = Get-PimManagerAlertFeedSqlCs
    if ($cs -and (Get-Command Read-PimAlertFeedSql -ErrorAction SilentlyContinue)) {
        try { return @(Read-PimAlertFeedSql -ConnectionString $cs) }
        catch { Write-Warning "  [alerts] SQL feed read failed: $($_.Exception.Message)"; return @() }
    }
    Write-Warning '  [alerts] no SQL store is configured, so there is no alert feed to read (PIM v2 is SQL-only)'
    return @()
}

function Get-PimManagerAlertFeedSqlCs {
    # The connection string, or $null when this instance has no SQL store (local/dev).
    if (-not ((Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) -and
              (Get-Command Get-PimSqlSetting          -ErrorAction SilentlyContinue))) { return $null }
    try { return (Get-PimSqlConnectionString) } catch { return $null }
}

function Write-PimManagerAlertFeedRecord {
    # Persist one recorded-send record to SQL. Returns 'sql', or 'none' when it could not be recorded.
    # Unlike the authorization stores, a failure here must NOT throw: this is called from the
    # alert path AFTER the mail has already been sent, so throwing would turn "we notified you
    # but could not file the proof" into an error on the operation that triggered the alert.
    # It warns loudly instead -- losing the proof is bad, losing the alert is worse.
    param([Parameter(Mandatory)][object]$Record)
    $cs = Get-PimManagerAlertFeedSqlCs
    if ($cs -and (Get-Command Write-PimAlertFeedSql -ErrorAction SilentlyContinue)) {
        try { [void](Write-PimAlertFeedSql -ConnectionString $cs -Record $Record); return 'sql' }
        catch { Write-Warning "  [alerts] SQL feed write FAILED -- the send-proof was NOT recorded: $($_.Exception.Message)" }
        return 'none'
    }
    Write-Warning '  [alerts] no SQL store is configured -- the send-proof was NOT recorded (PIM v2 is SQL-only; there is no feed file)'
    return 'none'
}


# ===========================================================================
# ACCOUNTS & TAP -- read the live TAP state, and re-issue one on request.
#
# 🔴 WHY THIS EXISTS (BUG-66, measured live on the master tenant 2026-08-13).
# An account whose TAP has EXPIRED can never get another one from the engine.
# The AdminTap scope counts ANY temporaryAccessPassMethods entry as "this
# account has a TAP" and its Equal is hardcoded $true, so an expired, unusable
# TAP classifies the account as satisfied: the scope reported ok=True on six
# consecutive runs while minting nothing, and the admin had no way to obtain a
# credential ever again. Deleting the dead method by hand re-armed it and the
# next tick minted a usable TAP within seconds.
#
# 🔑 Entra allows exactly ONE TAP per user, so "reset" is necessarily
# DELETE-then-CREATE. That is what was done by hand to recover the master; this
# is that recovery, made a first-class, audited, one-click operation.
#
# 📌 A BUTTON, NOT AN AUTO-REMINT -- and that distinction is the whole design.
# BUG-66's fix shape was held for an operator decision because re-minting on
# expiry would make a tenant that CANNOT SEND MAIL mint a fresh undeliverable
# credential on every cycle. A human pressing a button is a deliberate,
# one-at-a-time re-issue, so it carries none of that risk.
# ===========================================================================

# 📌 Test-PimTapMailReady MOVED to engine/_shared/PIM-Notify.ps1 (2026-08-20), which this file
# already dot-sources above. It is now shared with the ENGINE's AdminTap provider, which needs the
# identical refuse-before-minting decision. Two copies of a guard that decides whether a CREDENTIAL
# is issued would drift, and the drift would be invisible until one of them minted something
# undeliverable.

function Get-PimAdminTapRecipient {
    <#
      WHERE A TAP IS DELIVERED, in one place so the reader, the issuer and the pre-check cannot
      disagree about it.

      An admin account is a SEPARATE privileged identity with no mailbox of its own -- which is
      exactly why the row carries ForwardMailsToContact + MailForwardAddress. The TAP therefore
      belongs to the person who owns the account, at their forwarding address.

      ManagerEmail is a FALLBACK only, for rows that predate the forwarding fields. It is not the
      preferred target: mailing a "manager" delivers a time-boxed credential for someone else's
      privileged account to a third party.
    #>
    param([Parameter(Mandatory)][object]$Row)
    # 🔴 DELEGATES TO THE ENGINE'S RULE (Get-PimAdminMailRecipient, engine/_shared/PIM-Rest.ps1).
    # This used to carry its own copy, which IGNORED ForwardMailsToContact -- and the engine mailed
    # ManagerEmail regardless -- so "Sends to" on this screen named an address the engine never
    # used (operator, 2026-09-12). One function now answers for both, so they cannot drift again.
    # 🪤 AN ADDRESS MUST LOOK LIKE ONE: live v1 rows hold 'FALSE'/'true' in MailForwardAddress; the
    # shared rule treats those as no recipient, and the caller refuses and says so.
    if (-not (Get-Command Get-PimAdminMailRecipient -ErrorAction SilentlyContinue)) {
        Write-Warning 'Get-PimAdminTapRecipient: engine/_shared/PIM-Rest.ps1 is not loaded -- no recipient can be resolved, so TAP delivery is refused.'
        return ''
    }
    return (Get-PimAdminMailRecipient -Row $Row)
}
function Test-PimManagerAdminTapWanted {
    # Mirror of the engine's Test-PimAdminTapWanted (PIM-EngineProviders.ps1), which the Manager does not
    # load at boot. Operator 2026-09-13: TAP is enforced for every admin; AD-only admins cannot hold one.
    param([object]$Row)
    if ($null -eq $Row) { return $false }
    return -not ("$($Row.TargetPlatform)".Trim() -ieq 'AD')
}
function Get-PimManagerCentralAdminRows {
    # 68.6 row 35: on an MSP slave, the central admins the downlink imported live in their own entity
    # (PIM-Downlink.ps1 Invoke-PimDownlinkAdminApply). The Manager shows them, labelled 'central', and
    # never edits them -- they are governed by the master. Empty everywhere else.
    try { return @((Read-PimRows 'Account-Definitions-Admins-Central').rows) } catch { return @() }
}
function Get-PimManagerKnownTenantTags {
    # 68.6 row 35: the tenant tags an admin's Target can name -- the MSP master registry's
    # platform.Tenants.Tags. Returns @{ known; tags }: known=$false when there is no registry to read
    # (single tenant, a slave, or a read failure), so a caller can say "not checked" instead of guessing.
    $cs = $null; try { $cs = Get-PimManagerStoreCs } catch { $cs = $null }
    if (-not $cs -or -not (Get-Command Invoke-PimSqlQuery -ErrorAction SilentlyContinue)) { return @{ known = $false; tags = @() } }
    try {
        $rows = @(Invoke-PimSqlQuery -ConnectionString $cs -Sql "IF OBJECT_ID('platform.Tenants') IS NULL OR COL_LENGTH('platform.Tenants','Tags') IS NULL SELECT CAST(NULL AS nvarchar(max)) AS Tags WHERE 1=0 ELSE SELECT Tags FROM platform.Tenants WHERE Enabled = 1")
        $seen = @{}; $out = New-Object System.Collections.Generic.List[string]
        foreach ($r in $rows) {
            foreach ($t in @("$($r.Tags)" -split '[;,]')) {
                $v = "$t".Trim(); if (-not $v) { continue }
                if (-not $seen.ContainsKey($v.ToLowerInvariant())) { $seen[$v.ToLowerInvariant()] = $true; $out.Add($v) }
            }
        }
        $hasRegistry = [bool](@(Invoke-PimSqlQuery -ConnectionString $cs -Sql "SELECT CASE WHEN OBJECT_ID('platform.Tenants') IS NULL THEN 0 ELSE 1 END AS n")[0].n)
        return @{ known = $hasRegistry; tags = @($out.ToArray() | Sort-Object) }
    } catch { return @{ known = $false; tags = @() } }
}
function Get-PimAdminTapState {
    <#
      Every Entra admin row (TAP is enforced for all admins; AD-only excluded), with the LIVE state
      of its TAP read from Graph.

      status is one of:
        usable   -- a TAP exists and Entra reports it usable
        expired  -- a TAP exists but is NOT usable (the BUG-66 case: the engine
                    treats this as satisfied and will never replace it)
        none     -- no TAP exists; the engine will mint one on its next run
        unknown  -- Graph could not be read for this account. NOT the same as
                    'none', and it must never be shown as one: acting on a
                    guess here either double-issues or hides a dead credential.
    #>
    # 🔴 DO NOT ENUMERATE EVERY ADMIN'S TAP ON PAGE LOAD (operator, 2026-09-12: "no need to enum all
    # admins tap status. we do it per admin if needed").
    # Reading TAP state costs 2 Graph calls PER ADMIN, sequentially, and the page waited for all of
    # them before showing anything -- measured at a 120s timeout on internal. The list itself comes
    # from the store and is instant; only the LIVE pass state needs Graph.
    # 🔑 -Upn narrows it to one account, which is how the GUI now asks: render the grid from the
    # store, then fetch the live state for the row the operator actually cares about.
    param([string]$Upn)

    $rows = @()
    try { $rows = @((Read-PimRows 'Account-Definitions-Admins').rows) } catch { $rows = @() }
    $wanted = @($rows | Where-Object { Test-PimManagerAdminTapWanted -Row $_ })
    $liveCheck = [bool]"$Upn".Trim()
    if ($liveCheck) {
        $wanted = @($wanted | Where-Object { "$($_.UserPrincipalName)".Trim() -ieq "$Upn".Trim() })
    }

    $canGraph = [bool](Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $wanted) {
        $upn = "$($r.UserPrincipalName)".Trim()
        if (-not $upn) { continue }
        # 🔴 THE TAP GOES TO THE ADMIN'S FORWARDING ADDRESS, NOT TO A MANAGER (operator,
        # 2026-09-12: "it should not send to a manager email but his fowarding email").
        # An admin account is a separate privileged identity with NO mailbox of its own -- that is
        # why the row carries ForwardMailsToContact + MailForwardAddress. Mailing a "manager"
        # sends a time-boxed credential for MY account to SOMEONE ELSE; the forwarding address is
        # the person who owns the account and is the only correct recipient.
        # ManagerEmail stays as a fallback so rows that only have it keep working.
        $mgr = Get-PimAdminTapRecipient -Row $r
        $hrs = 0; [void][int]::TryParse("$($r.TAPLifetimeHours)", [ref]$hrs); if ($hrs -le 0) { $hrs = 4 }

        # THE FULL MAIL CHECK IS PER ADMIN, ON DEMAND -- NOT IN THE LIST (2026-09-12). Run for every admin it
        # re-read email controls from SQL and rendered the template in a WhatIf send; the Manager serves
        # one request at a time, so once two admins had a real recipient the TAP list hung and an
        # Edit > Save and the Departments load queued behind it. The list checks only what is free;
        # the per-admin Check ($liveCheck) runs the full readiness probe.
        $mailChk = if ($liveCheck) { Test-PimTapMailReady -Recipient $mgr }
                   elseif (-not "$mgr".Trim()) { @{ ok = $false; reason = 'no office user email (forwarding TRUE + address) and no ManagerEmail -- there is nowhere to deliver a TAP; set it with Edit on the admin above' } }
                   else { @{ ok = $true; reason = '' } }
        $status = 'unknown'; $detail = ''; $created = ''
        if (-not $liveCheck) {
            # The LIST: no Graph at all. 'unchecked' is its own state -- it is neither 'none' nor
            # 'usable', and the GUI refuses a write on it until the operator checks that one row.
            $status = 'unchecked'; $detail = ''
        } elseif ($canGraph) {
            try {
                $uid = (Invoke-PimGraph -Path "/users/$upn`?`$select=id").id
                if (-not "$uid".Trim()) {
                    $status = 'unknown'; $detail = 'account not found in the directory (not yet created?)'
                } else {
                    # -All is LOAD-BEARING here for the same reason as in the engine
                    # provider (BUG-51): without it this returns the response WRAPPER,
                    # and @(wrapper).Count is 1 even when the user has NO TAP.
                    $taps = @(Invoke-PimGraph -All -Path "/users/$uid/authentication/temporaryAccessPassMethods")
                    if (-not $taps.Count) {
                        $status = 'none'; $detail = 'no TAP -- the engine mints one on its next run'
                    } else {
                        $t = $taps[0]
                        $created = "$($t.createdDateTime)"
                        # isUsable is the field BUG-66 turned on: an EXISTING TAP is not
                        # the same as a USABLE one, and the engine cannot tell them apart.
                        if ("$($t.isUsable)" -match '(?i)true') {
                            $status = 'usable'; $detail = 'active'
                        } else {
                            $status = 'expired'
                            $detail = "$($t.methodUsabilityReason)"
                            if (-not $detail) { $detail = 'not usable' }
                        }
                    }
                }
            } catch {
                $status = 'unknown'; $detail = "Graph read failed: $($_.Exception.Message)"
            }
        } else {
            $detail = 'no Graph client in this runtime'
        }

        [void]$out.Add([ordered]@{
            userPrincipalName = $upn
            displayName       = "$($r.DisplayName)"
            managerEmail      = $mgr
            tapLifetimeHours  = $hrs
            status            = $status
            detail            = $detail
            createdDateTime   = $created
            # Surfaced per-row so the UI can disable the button and SAY WHY, rather
            # than letting the operator press it and collect a 409 they must decode.
            mailReady         = $mailChk.ok
            mailReason        = $mailChk.reason
        })
    }
    return $out.ToArray()
}
function Send-PimManagerAlert {
    # Fan an alert out to every configured recipient for ONE event type, through the
    # existing Send-PimNotifyMail path (the 'alert-notice' template). Honours the
    # per-event toggle, debounces identical repeats within a window, and RECORDS the
    # outcome to the durable feed (the recorded-send proof -- closes the [M5] residual).
    # Returns @{ event; fired; sent; recipients; reason; recorded; debounced }.
    # NEVER throws -- alerting must not take the Manager down.
    param(
        [Parameter(Mandatory)][string]$Event,
        [string]$Title,
        [string]$Detail,
        [string]$LinkTab,
        [int]$DebounceMinutes = 60,
        [switch]$WhatIf
    )
    $cfg = Get-PimAlertingConfig
    $webhookOn = [bool]$cfg.webhookEnabled
    $result = [ordered]@{ event = $Event; fired = $false; sent = 0; recipients = @($cfg.recipients); reason = ''; recorded = $false; debounced = $false; webhookKind = "$($cfg.webhookKind)"; webhookSent = $false }
    if (-not ($cfg.events.ContainsKey($Event) -and $cfg.events[$Event])) { $result.reason = 'event disabled'; return $result }
    $mailPossible = (@($cfg.recipients).Count -gt 0 -and (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue))
    # The alert can deliver via mail and/or the outbound webhook. Only bail when
    # NEITHER channel is configured (no recipients/notify path AND no webhook).
    if (-not $mailPossible -and -not $webhookOn) {
        $result.reason = $(if (@($cfg.recipients).Count -eq 0) { 'no recipients configured' } else { 'notify path not loaded' })
        return $result
    }
    # Debounce an identical (same event/title/detail) alert fired recently, so a
    # recurring condition (e.g. the same drift every reconcile) does not spam.
    if ($DebounceMinutes -gt 0 -and (Get-Command Test-PimAlertDebounced -ErrorAction SilentlyContinue)) {
        try {
            $key = Get-PimAlertDedupeKey -Event $Event -Title $Title -Detail $Detail
            if (Test-PimAlertDebounced -Feed (Get-PimManagerAlertFeed) -DedupeKey $key -DebounceMinutes $DebounceMinutes) {
                $result.debounced = $true; $result.reason = "debounced (identical alert within $DebounceMinutes min)"; return $result
            }
        } catch {}
    }
    $result.fired = $true
    $tenantCtx = try { Get-PimManagerTenantContext } catch { @{ tenantName = ''; tenantId = '' } }
    $tokens = @{
        AlertTitle  = $(if ("$Title".Trim()) { $Title } else { $Event })
        AlertEvent  = $Event
        AlertDetail = "$Detail"
        AlertTab    = "$LinkTab"
        TenantName  = "$($tenantCtx.tenantName)"
        Instance    = "$($script:PimInstanceName)"
        WhenUtc     = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
    }
    $sent = 0; $lastReason = ''
    if ($mailPossible) {
        foreach ($rcpt in $cfg.recipients) {
            try {
                $r = if ($WhatIf) { Send-PimNotifyMail -Type 'alert-notice' -Tokens $tokens -Recipient $rcpt -WhatIf } else { Send-PimNotifyMail -Type 'alert-notice' -Tokens $tokens -Recipient $rcpt }
                if ($r.sent) { $sent++ } elseif ($r.reason) { $lastReason = "$($r.reason)" }
            } catch { $lastReason = "$($_.Exception.Message)" }
        }
    }
    $result.sent = $sent
    # SECOND channel: fire the outbound webhook (Teams / generic JSON) when configured.
    # Independent of mail -- a webhook-only alert is valid. Its outcome folds into the
    # recorded proof (sent count includes a delivered webhook so the feed reflects it).
    $webhookState = ''
    if ($webhookOn -and (Get-Command Send-PimWebhookAlert -ErrorAction SilentlyContinue)) {
        try {
            $wr = Send-PimWebhookAlert -Event $Event -Title $Title -Detail $Detail -LinkTab $LinkTab -Config $cfg -WhatIf:$WhatIf
            if ($wr.attempted) {
                if ([bool]$wr.sent) { $result.webhookSent = $true; $result.sent = [int]$result.sent + 1; $webhookState = 'delivered' }
                else { $webhookState = $(if ($WhatIf) { 'rendered' } else { 'failed' }); if (-not $lastReason -and "$($wr.reason)".Trim()) { $lastReason = "$($wr.reason)" } }
            }
        } catch { if (-not $lastReason) { $lastReason = "webhook: $($_.Exception.Message)" } }
    }
    if ($result.sent -eq 0 -and -not $result.reason) { $result.reason = $(if ($lastReason) { $lastReason } else { 'rendered only (no sender / whatif)' }) }
    # A clean human note covering BOTH channels for the feed's reason line.
    if ($webhookOn -and (Get-Command Get-PimChannelDedupeNote -ErrorAction SilentlyContinue)) {
        try { $result.reason = (Get-PimChannelDedupeNote -MailSent $sent -WebhookKind "$($cfg.webhookKind)" -WebhookState $webhookState) + $(if ("$($result.reason)".Trim() -and $result.sent -eq 0) { " ($($result.reason))" } else { '' }) } catch {}
    }
    try { Write-PimManagerAuditEvent -Action 'alert.send' -Target "event:$Event" -After ([ordered]@{ fired = $result.fired; sent = $result.sent; recipients = @($cfg.recipients).Count; webhook = "$($cfg.webhookKind)"; webhookSent = [bool]$result.webhookSent; reason = "$($result.reason)" }) -Result $(if ($result.sent -gt 0) { 'ok' } else { 'noop' }) } catch {}
    # Record the recorded-send PROOF to the durable feed (the [M5] residual fix): a
    # break-glass "owners notified" claim is now backed by a feed entry showing
    # exactly who was notified and whether delivery was recorded.
    if (Get-Command New-PimAlertRecord -ErrorAction SilentlyContinue) {
        try {
            $tenantCtx2 = try { Get-PimManagerTenantContext } catch { @{ tenantName = '' } }
            $rec = New-PimAlertRecord -Event $Event -Title $Title -Detail $Detail -LinkTab $LinkTab -SendResult $result -TenantName "$($tenantCtx2.tenantName)" -Instance "$($script:PimInstanceName)" -WhatIf:$WhatIf
            [void](Write-PimManagerAlertFeedRecord -Record $rec)
            $result.recorded = $true
        } catch {
            # The alert was SENT; only the feed record failed. Not fatal -- but an alert that fired
            # and was never recorded leaves the Alerts tab disagreeing with what actually happened,
            # which is the audit trail this product exists to keep.
            Write-Warning "[manager] alert '$Event' was sent but NOT recorded in the feed ($($_.Exception.Message))."
        }
    }
    return $result
}

# ---------------------------------------------------------------------------
# Operational-policy config (REQUIREMENTS [M7]). Persisted under the single
# 'OperationalPolicy' key in the SAME store every other Manager setting uses
# (SQL pim.Settings when hosted, else the per-instance JSON file) -- so the
# engine + scheduler/jobs that read pim.Settings see exactly what the GUI saved.
# The normalize/validate/clamp logic lives in the shared engine lib
# (PIM-OperationalPolicy.ps1) so the engine and the GUI agree on the value.
# Covers ONLY the three knobs that did not already exist: expiry-policy defaults,
# MFA-on-activation toggle, connection-sanity config. (Notification/alert config
# is the separate, already-shipped Alerting surface above.)
# ---------------------------------------------------------------------------
function Get-PimOperationalPolicy {
    # Returns @{ value=<ordered policy>; warnings=<string[]>; catalogs=@{..} }.
    # Always fully populated (defaults applied) even on an empty store.
    $raw = $null
    try { $raw = Get-PimManagerSetting -Name 'OperationalPolicy' } catch {}
    $norm = ConvertTo-PimNormalizedOperationalPolicy -Raw $raw
    return [ordered]@{
        value    = $norm.value
        warnings = @($norm.warnings)
        catalogs = [ordered]@{
            activationDuration  = @(Get-PimActivationDurationCatalog)
            eligibilityDuration = @(Get-PimEligibilityDurationCatalog)
        }
    }
}

function Set-PimOperationalPolicy {
    # Persist a (possibly partial) policy object. Normalize+clamp FIRST, then
    # store the normalized value -- the store never holds garbage. Returns the
    # same shape as Get-PimOperationalPolicy.
    param([object]$Policy)
    $norm = ConvertTo-PimNormalizedOperationalPolicy -Raw $Policy
    Set-PimManagerSetting -Name 'OperationalPolicy' -Value $norm.value
    return (Get-PimOperationalPolicy)
}

# ---------------------------------------------------------------------------
# Feature flags -- the "turn any Manager surface on/off in Settings" gradual-
# rollout registry. Persisted under the 'FeatureFlags' key in the SAME store
# every other Manager setting uses (SQL pim.Settings when hosted, else the
# per-instance JSON file). The catalog + merge/always-on-guard live in the
# shared engine lib (PIM-FeatureFlags.ps1) so the GUI nav render (which reads the
# boot-injected effective flags) and any server-side gate resolve one identical
# value. Read at page boot so a toggle takes effect on the next reload.
# ---------------------------------------------------------------------------
function Get-PimFeatureFlags {
    # Returns @{ flags=<id->bool>; effective=<id->object>; catalog=<...>; warnings=<...> }.
    # Always fully populated (defaults applied) even on an empty store.
    $raw = $null
    try { $raw = Get-PimManagerSetting -Name 'FeatureFlags' } catch {}
    $res = Resolve-PimFeatureFlags -Raw $raw
    return [ordered]@{
        flags     = $res.flags
        effective = $res.effective
        catalog   = @(Get-PimFeatureFlagCatalog)
        warnings  = @($res.warnings)
    }
}

function Set-PimFeatureFlags {
    # Persist a (possibly partial / full) flag map. Reduce to the MINIMAL override
    # set (only flags differing from default, never always-on) FIRST, then store
    # under { flags = ... } -- the store never holds always-on or redundant values.
    # Returns the same shape as Get-PimFeatureFlags.
    param([object]$Flags)
    $overrides = ConvertTo-PimFeatureFlagOverrides -Raw $Flags
    Set-PimManagerSetting -Name 'FeatureFlags' -Value ([ordered]@{ flags = $overrides })
    return (Get-PimFeatureFlags)
}

# ---------------------------------------------------------------------------
# Governance PREVIEW gate -- the "show the surface, safely OFF" map for the two
# security-sensitive governance surfaces. Persisted under pim.Settings
# 'GovernancePreview' through the SAME store every other setting uses, so the
# boot-injected GUI value == the value the endpoint guard reads. Default OFF for
# both (Resolve-PimGovernancePreview applies the shipped defaults on an empty
# store). Read at page boot so a Settings toggle takes effect on the next reload.
# ---------------------------------------------------------------------------
function Get-PimGovernancePreview {
    # Returns @{ flags=<id->bool>; enabled=<...>; catalog=<...>; anyEnabled=<bool>; warnings=<...> }.
    # Always fully populated (defaults OFF applied) even on an empty store.
    $raw = $null
    try { $raw = Get-PimManagerSetting -Name 'GovernancePreview' } catch {}
    return (Resolve-PimGovernancePreview -Raw $raw)
}

function Set-PimGovernancePreview {
    # Persist a (partial/full) preview map. Reduce to the MINIMAL override set
    # (only flags differing from the OFF default) FIRST, then store under { flags }.
    # A default install persists {} (stays OFF). Returns the same shape as Get-.
    param([object]$Flags)
    $overrides = ConvertTo-PimGovernancePreviewOverrides -Raw $Flags
    Set-PimManagerSetting -Name 'GovernancePreview' -Value ([ordered]@{ flags = $overrides })
    return (Get-PimGovernancePreview)
}

# ---------------------------------------------------------------------------
# Feature CUSTOMIZATION + LICENSE (REQUIREMENTS s29/s30). The catalog of
# customizable CAPABILITIES (tier core|advanced, license free|pro, group/chapter,
# kill switch, dependsOn) + the active EDITION. Persisted in the SAME pim.Settings
# store the engine + scheduled jobs read at runtime ('FeatureGates' + 'Edition'),
# so the GUI toggle == the gate the engine/jobs honour. The pure catalog + gates
# live in the shared engine lib (PIM-FeatureCatalog.ps1).
# ---------------------------------------------------------------------------
function Get-PimFeatureGates {
    # Returns @{ gates; effective; catalog; edition; editions; dependencyIssues;
    # warnings }. The 'effective' map per feature carries enabled + licensed +
    # available + tier/license/group so the GUI renders dimmed/locked affordances.
    $raw = $null
    try { $raw = Get-PimManagerSetting -Name 'FeatureGates' } catch {}
    $res = Resolve-PimFeatureGate -Raw $raw
    $edition = Get-PimActiveEdition
    $catalog = @(Get-PimFeatureCatalog)
    # Is the Pro gate actually ENFORCED this session? It ships OFF -- Pro is free, with no
    # nag and no block -- and only an internal harness turns it on. The GUI used to ignore
    # this entirely and lock every Pro row on EDITION alone, so an admin saw a "Requires
    # Pro" padlock, with the toggle DISABLED, on features the backend would have run
    # happily. The lock was not merely cosmetic: it prevented enabling a working feature.
    $licenseEnforced = $false
    if (Get-Command Test-PimProLicenseEnforced -ErrorAction SilentlyContinue) {
        try { $licenseEnforced = [bool](Test-PimProLicenseEnforced) } catch { $licenseEnforced = $false }
    }
    $effective = [ordered]@{}
    $catByKey = @{}; foreach ($c in $catalog) { $catByKey["$($c.key)"] = $c }
    foreach ($k in $res.effective.Keys) {
        $e = $res.effective[$k]
        # autoEnableWhenData (v1 parity): a feature nobody stored a value for is EFFECTIVELY on while its
        # entities hold rows -- the engine's Test-PimFeatureEnabled rule. The card used to show the stored
        # toggle only, so a working workload connector read "Disabled". Surface what the engine does.
        $autoEnts = @(); if ($catByKey.ContainsKey("$k")) { $autoEnts = @(@($catByKey["$k"].autoEnableWhenData) | Where-Object { "$_".Trim() }) }
        $isExplicit = ($res.explicit -is [hashtable]) -and $res.explicit.ContainsKey("$k")
        $autoRows = 0; $autoEnabled = $false
        if ($autoEnts.Count -and -not $isExplicit -and -not [bool]$e.enabled) {
            $autoRows = Get-PimFeatureDataRowCount -Entities $autoEnts
            $autoEnabled = ($autoRows -gt 0)
        }
        # When enforcement is OFF, every feature is licensed -- that IS the shipped policy,
        # and it now matches Test-PimFeatureAllowed, which returns true for everything.
        $licensed = (-not $licenseEnforced) -or (Test-PimEditionCoversLicense -License "$($e.license)" -Edition $edition)
        $available = ([bool]$e.enabled -and $licensed) -or ("$($e.tier)" -eq 'core')
        $effective[$k] = [ordered]@{
            key=$e.key; label=$e.label; group=$e.group; tier=$e.tier; license=$e.license
            defaultEnabled=$e.defaultEnabled; dependsOn=@($e.dependsOn)
            enabled=[bool]$e.enabled; licensed=[bool]$licensed; available=[bool]($available -or ($autoEnabled -and $licensed))
            autoEnableWhenData=@($autoEnts); autoEnabled=[bool]$autoEnabled; autoRows=[int]$autoRows; explicit=[bool]$isExplicit
            effectiveEnabled=[bool]([bool]$e.enabled -or $autoEnabled -or ("$($e.tier)" -eq 'core'))
        }
    }
    return [ordered]@{
        gates            = $res.gates
        effective        = $effective
        catalog          = $catalog
        edition          = $edition
        # Surfaced so the GUI can stop inventing a restriction the engine does not apply.
        licenseEnforced  = [bool]$licenseEnforced
        editions         = @($script:PimEditionNames)
        dependencyIssues = @(Get-PimFeatureDependencyIssues -GateState $res -Edition $edition)
        warnings         = @($res.warnings)
    }
}

function Get-PimFeatureDataRowCount {
    # How many desired-state rows the given entities hold (pim.Rows). 0 when there is no store or the
    # read fails -- the same "cannot tell = off" direction as Test-PimFeatureDataPresent.
    param([string[]]$Entities = @())
    $ents = @($Entities | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if (-not $ents.Count -or -not $script:PimSqlCs -or -not (Get-Command Invoke-PimSqlScalar -ErrorAction SilentlyContinue)) { return 0 }
    try {
        $p = @{}; $names = @()
        for ($i = 0; $i -lt $ents.Count; $i++) { $p["e$i"] = $ents[$i]; $names += "@e$i" }
        $v = Invoke-PimSqlScalar -ConnectionString $script:PimSqlCs -Sql ("SELECT COUNT(*) FROM pim.Rows WHERE Entity IN ({0})" -f ($names -join ',')) -Parameters $p
        return [int]"$v"
    } catch { return 0 }
}

function Set-PimFeatureGates {
    # Persist a (partial/full) kill-switch map. Reduce to the MINIMAL override set
    # (only advanced features differing from default; core never stored) then store
    # under { gates = ... }. Returns the same shape as Get-PimFeatureGates.
    param([object]$Gates)
    $overrides = ConvertTo-PimFeatureGateOverrides -Raw $Gates
    Set-PimManagerSetting -Name 'FeatureGates' -Value ([ordered]@{ gates = $overrides })
    return (Get-PimFeatureGates)
}

function Get-PimEditionConfig {
    # The active edition + recorded grant basis/note (license backend, s30).
    $raw = $null
    try { $raw = Get-PimManagerSetting -Name 'Edition' } catch {}
    $r = Resolve-PimEdition -Raw $raw
    # When nothing is persisted, surface the offline-license-derived active edition.
    if (-not ($raw)) { $r.edition = Get-PimActiveEdition }
    return [ordered]@{ edition=$r.edition; grantBasis=$r.grantBasis; note=$r.note; editions=@($script:PimEditionNames) }
}

function Set-PimEditionConfig {
    # Persist the active edition + grant basis (paid|design-partner). Validated/
    # normalised by Resolve-PimEdition. Returns the same shape as Get-PimEditionConfig.
    param([object]$Config)
    $r = Resolve-PimEdition -Raw $Config
    Set-PimManagerSetting -Name 'Edition' -Value ([ordered]@{ edition=$r.edition; grantBasis=$r.grantBasis; note=$r.note })
    return (Get-PimEditionConfig)
}

function Get-PimScenarioConfig {
    # The active DEPLOYMENT SCENARIO (REQUIREMENTS §31) + its resolved runtime knobs,
    # for the Settings "Deployment scenario" card. READ-ONLY summary: the card shows
    # the active topology + what each knob resolves to (hosting / SPN / sync-file /
    # update-source / edition); it NEVER silently changes behaviour. Persisted under
    # pim.Settings 'Scenario' (mirrors the Edition backend). Returns the active id +
    # the full descriptor, the resolved entry-plan, and the catalog (for the picker).
    $active = $null
    if (Get-Command Get-PimActiveScenario -ErrorAction SilentlyContinue) {
        try { $active = Get-PimActiveScenario } catch {}
    }
    if (-not $active) { return [ordered]@{ mode = $null; active = ''; scenario = $null; resolved = $null; catalog = @() } }
    $plan = $null
    try { $plan = Get-PimScenarioEntryPlan -Scenario $active } catch {}
    $catalog = @()
    try { $catalog = @(Get-PimScenarioCatalog | ForEach-Object {
        $ml = ''; try { $ml = "$((Get-PimTenantModeLabel -Scenario $_).label)" } catch { }
        [ordered]@{ id = "$($_.id)"; label = "$($_.label)"; modeLabel = $ml; role = "$($_.role)"; summary = "$($_.summary)" } }) } catch {}
    # 68.6 row 36 -- the tenant's MODE, by role and hosting. The master's name on a slave (pim.Settings
    # 'MspMasterName', or $env:PIM_MspMasterName), the slave count on a master (platform.Tenants).
    $mode = $null
    try {
        $masterName = ''; $slaveCount = -1
        if ("$($active.role)" -eq 'msp-managed') {
            try { $mn = Get-PimManagerSetting -Name 'MspMasterName'; if ($mn -is [string]) { $masterName = $mn } elseif ($mn) { $masterName = "$($mn.name)" } } catch { }
            if (-not "$masterName".Trim() -and $env:PIM_MspMasterName) { $masterName = "$env:PIM_MspMasterName" }
        } elseif ("$($active.role)" -eq 'msp-master' -and (Get-Command Get-PimManagerDownlinkTenants -ErrorAction SilentlyContinue)) {
            try { $cs = Get-PimManagerStoreCs; if ($cs) { $slaveCount = @(Get-PimManagerDownlinkTenants -ConnectionString $cs).Count } } catch { $slaveCount = -1 }
        }
        $m = Get-PimTenantModeLabel -Scenario $active -MasterName $masterName -SlaveCount $slaveCount
        $mode = [ordered]@{ key = $m.key; label = $m.label; hosting = $m.hosting; masterName = $m.masterName; slaveCount = $m.slaveCount; detail = $m.detail }
    } catch { $mode = $null }
    return [ordered]@{
        mode     = $mode
        active   = "$($active.id)"
        scenario = [ordered]@{
            id = "$($active.id)"; label = "$($active.label)"; role = "$($active.role)"
            edition = "$($active.edition)"; updateSource = "$($active.updateSource)"
            hostingLocation = "$($active.hostingLocation)"; spnModel = "$($active.spnModel)"
            syncFileLocation = "$($active.syncFileLocation)"; syncModel = "$($active.syncModel)"
            licenseTier = "$($active.licenseTier)"; summary = "$($active.summary)"
        }
        resolved = $(if ($plan) { [ordered]@{
            updateSource = "$($plan.updateSource)"; managedHosting = "$($plan.managedHosting)"
            configVariant = "$($plan.configVariant)"; ringGated = [bool]$plan.ringGated
            hostingLocation = "$($plan.hostingLocation)"; spnModel = "$($plan.spnModel)"
            syncFileLocation = "$($plan.syncFileLocation)"; syncAdminsPermissions = [bool]$plan.syncAdminsPermissions
            activeEdition = "$($plan.activeEdition)"; grantBasis = "$($plan.grantBasis)"
        } } else { $null })
        catalog  = @($catalog)
    }
}

function Set-PimScenarioConfig {
    # Persist the active deployment scenario id (S1-S6) under pim.Settings 'Scenario'
    # + mirror it to $global:PIM_ActiveScenario for THIS process so the resolvers read
    # it live. Validated against the catalog (unknown id is rejected, not silently
    # stored). Returns the same shape as Get-PimScenarioConfig.
    param([object]$Config)
    $id = ''
    if ($Config -is [string]) { $id = "$Config".Trim() }
    else { $id = "$(Get-PimFeatureCatalogValue -Object $Config -Key 'scenario')".Trim(); if (-not $id) { $id = "$(Get-PimFeatureCatalogValue -Object $Config -Key 'id')".Trim() } }
    $scn = $null
    if ($id) { $scn = Get-PimScenario -Id $id }
    if (-not $scn) { throw "Unknown deployment scenario '$id'. Expected one of: $((Get-PimScenarioCatalog | ForEach-Object { $_.id }) -join ', ')." }
    Set-PimManagerSetting -Name 'Scenario' -Value ([ordered]@{ scenario = "$($scn.id)" })
    $global:PIM_ActiveScenario = "$($scn.id)"
    return (Get-PimScenarioConfig)
}

function Get-PimManagerEffectiveSchedule {
    # The EFFECTIVE job schedule the GUI Jobs tab + the per-job controls act on:
    # the shipped default catalog (Get-PimDefaultJobSchedule) with the stored
    # per-name overrides ('JobSchedule' setting -> enabled / intervalMinutes)
    # applied. This is the SAME merge as GET /api/job-schedule, factored out so
    # /api/jobs, /api/jobs/state and /api/jobs/run all resolve one job's live
    # enabled+cadence identically (no drift between the read view and the controls).
    $sched = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Scheduler.ps1'
    if (-not (Get-Command Get-PimDefaultJobSchedule -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $sched)) {
        try { . $sched } catch { }
    }
    $defaults = @()
    if (Get-Command Get-PimDefaultJobSchedule -ErrorAction SilentlyContinue) { $defaults = @(Get-PimDefaultJobSchedule) }
    $stored = Get-PimManagerSetting -Name 'JobSchedule'
    $overrideByName = @{}
    foreach ($o in @($stored)) { if ("$($o.name)".Trim()) { $overrideByName["$($o.name)"] = $o } }
    $jobs = New-Object System.Collections.ArrayList
    foreach ($d in $defaults) {
        $en = $true; if ($d.PSObject.Properties['enabled']) { $en = [bool]$d.enabled }
        $iv = 60;    if ($d.PSObject.Properties['intervalMinutes']) { $iv = [int]$d.intervalMinutes }
        if ($overrideByName.ContainsKey("$($d.name)")) {
            $ov = $overrideByName["$($d.name)"]
            if ($ov.PSObject.Properties['enabled'])         { $en = [bool]$ov.enabled }
            if ($ov.PSObject.Properties['intervalMinutes']) { $iv = [int]$ov.intervalMinutes }
        }
        $entry = [pscustomobject]@{ name = "$($d.name)"; type = "$($d.type)"; enabled = $en; intervalMinutes = $iv }
        if ($d.PSObject.Properties['scope']) { $entry | Add-Member -NotePropertyName scope -NotePropertyValue "$($d.scope)" -Force }
        [void]$jobs.Add($entry)
    }
    return @($jobs.ToArray())
}

function ConvertTo-PimPlainHashtable {
    # PSCustomObject (from ConvertFrom-Json) -> hashtable, one level deep is
    # enough for the naming-convention map (all scalar values).
    param([object]$Object)
    if ($null -eq $Object) { return @{} }
    if ($Object -is [hashtable]) { return $Object }
    $h = @{}
    if ($Object -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = $p.Value }
    }
    return $h
}

function Get-PimDefaultManagerFilters {
    # Store-friendly representation of the engine's selection filters: each
    # filter is a NAME + description + a set of like-patterns / markers an admin
    # can edit (the engine's scriptblock defaults in
    # config/PIM4EntraPS.Filters.locked.ps1 remain the code fallback). These
    # mirror those documented defaults.
    return @(
        [ordered]@{ key = 'Admins';                 label = 'Admins';                        patterns = @('Admin-*', 'x-Admin*', 'g-Admin*'); requireAll = @('*-ID*'); description = "User principal name starts with an admin prefix (internal / external-adminuser / external-guest) AND carries the Entra/Identity environment marker." }
        [ordered]@{ key = 'PimGroup';               label = 'PIM-managed groups (all)';      patterns = @('PIM-*');                requireAll = @();          description = "Security groups whose display name starts with the PIM- prefix." }
        [ordered]@{ key = 'PimGroupResourceSyncAD'; label = 'PIM resource groups (AD-sync)'; patterns = @('PIM-RES*');             requireAll = @('*-S_AD');  description = "AD-synced resource-scope groups (nested-group PIM design)." }
        [ordered]@{ key = 'PimGroupServiceSyncAD';  label = 'PIM service groups (AD-sync)';   patterns = @('PIM-SERV*');            requireAll = @('*-S_AD');  description = "AD-synced service groups." }
    )
}

function Get-PimManagerNamingSettings {
    # Naming conventions THROUGH THE STORE, with default-seeding. If the store
    # has nothing, seed from the shipped naming defaults (Get-PimNamingConventions
    # reads the locked defaults; no custom file) and PERSIST so naming is never
    # empty. Returns @{ value = <hashtable>; seeded = <bool> }.
    $stored = Get-PimManagerSetting -Name 'NamingConventions'
    $h = ConvertTo-PimPlainHashtable $stored
    $seeded = $false
    if ($h.Count -eq 0) {
        $h = ConvertTo-PimPlainHashtable (Get-PimNamingConventions)
        Set-PimManagerSetting -Name 'NamingConventions' -Value $h
        $seeded = $true
    }
    # Keep the live engine map in sync for this process.
    if (-not ($global:PIM_NamingConventions -is [hashtable])) { $global:PIM_NamingConventions = @{} }
    foreach ($k in @($h.Keys)) { $global:PIM_NamingConventions[$k] = $h[$k] }
    return @{ value = $h; seeded = $seeded }
}

function Get-PimManagerFilterSettings {
    # Filters THROUGH THE STORE, with default-seeding. Never empty.
    # Returns @{ value = <object[]>; seeded = <bool> }.
    $stored = Get-PimManagerSetting -Name 'Filters'
    $arr = @()
    if ($null -ne $stored) { $arr = @($stored) }
    $seeded = $false
    if ($arr.Count -eq 0) {
        $arr = @(Get-PimDefaultManagerFilters)
        Set-PimManagerSetting -Name 'Filters' -Value $arr
        $seeded = $true
    }
    return @{ value = $arr; seeded = $seeded }
}

function Get-PimManagerDepartments {
    <#
      Departments(+owners). Optional -- empty is allowed (no auto-seed). Each:
      @{ name; owners = string[]; contact; notes }. Source the delegation-approval workflow uses to
      resolve dept -> owner.

      🔴 BUG-142 -- TWO DISJOINT DEPARTMENT STORES. This read the SETTING `Departments`, while the
      engine's owner chain (Get-PimDepartmentOwnerIndex) and the Manager's own portal-scope
      resolution read the ENTITY `PIM-Definitions-Departments`. Each half worked; they were simply
      not the same data, so a department entered in Settings never reached the engine and one
      defined for the engine never reached the approval workflow.

      🔑 THE ENTITY IS AUTHORITATIVE (§62.4's recorded fix shape). It is the desired-state store --
      "everything SQL" -- it is what the engine actually applies, and it is the half that survives a
      sync. The setting is read ONLY as a fallback, so an existing store whose departments live
      there keeps working until they are reconciled.

      🪤 THE MERGE IS NOT SYMMETRIC, AND THAT IS DELIBERATE. Where both stores describe the same
      department, the ENTITY wins -- silently preferring the setting would re-route approvals for
      privileged access to whatever an older screen happened to save. A setting-only department is
      surfaced (so nothing disappears from the approval workflow the day this ships) and marked with
      its source, so the reconciliation can be seen rather than guessed at.
    #>
    $byName = [ordered]@{}

    # 1. The entity -- authoritative.
    try {
        foreach ($r in @((Read-PimRows -BaseName 'PIM-Definitions-Departments' -NoScope).rows)) {
            $n = ''
            foreach ($k in @('Department','DepartmentName','Name')) {
                $v = "$($r.$k)".Trim(); if ($v) { $n = $v; break }
            }
            if (-not $n) { continue }
            $ownRaw = ''
            foreach ($k in @('Owners','DeptOwner','DepartmentOwner','ManagerEmail')) {
                $v = "$($r.$k)".Trim(); if ($v) { $ownRaw = $v; break }
            }
            # Owners are pipe-joined per the Manager UX; ; and , accepted for safety (Split-PimOwners).
            $owners = @($ownRaw -split '[|;,]' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
            $byName[$n.ToLowerInvariant()] = [ordered]@{
                name = $n; owners = $owners
                contact = "$($r.Contact)".Trim(); notes = "$($r.Notes)".Trim(); source = 'entity'
            }
        }
    } catch {
        # 🪤 A FAILED READ IS NOT AN EMPTY SET. Falling through to the setting on an unreadable
        # entity would quietly hand approvals back to the stale store -- the swallow this whole
        # audit exists to end. Say so and let the setting fill in, marked as degraded.
        Write-Warning "  [departments] the entity PIM-Definitions-Departments could not be read ($($_.Exception.Message)) -- falling back to the 'Departments' setting."
    }

    # 2. The setting -- fallback only, and never overrides an entity row.
    $stored = Get-PimManagerSetting -Name 'Departments'
    foreach ($d in @($stored)) {
        if ($null -eq $d) { continue }
        $n = "$($d.name)".Trim(); if (-not $n) { $n = "$($d.Name)".Trim() }
        if (-not $n) { continue }
        $k = $n.ToLowerInvariant()
        if ($byName.Contains($k)) { continue }   # the entity wins
        $byName[$k] = [ordered]@{
            name = $n; owners = @($d.owners | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
            contact = "$($d.contact)".Trim(); notes = "$($d.notes)".Trim(); source = 'setting'
        }
    }
    return @($byName.Values)
}

function Get-PimManagerActor {
    # WHO IS ACTING, for the queue's attribution (section 65.7: "so i can also see who did it").
    # $global:PIM_CurrentUser and $env:USERNAME are BOTH EMPTY in the container, so every queued
    # entry was written with By='' -- measured live 2026-09-12 on two real revokes. The Manager
    # already knows the caller: Get-PimManagerRole resolves the Easy Auth principal.
    try { $r = Get-PimManagerRole; if ("$($r.identity)".Trim()) { return "$($r.identity)".Trim() } } catch { }
    if ("$($global:PIM_CurrentUser)".Trim()) { return "$($global:PIM_CurrentUser)".Trim() }
    if ("$env:USERNAME".Trim()) { return "$env:USERNAME" }
    return 'unknown'
}
function Get-PimManagerStoreCs {
    # The Manager settles its store ONCE at boot into $script:PimSqlCs. Endpoints added in §65 read
    # $global:PIM_SqlConnectionString instead and got $null on a correctly-configured SQL Manager,
    # so the queue, the revokes, TAP and modify all reported "no SQL store is wired in this host"
    # on a host that had one. One resolver, so they cannot disagree again.
    # 🪤 IT MUST NOT RE-RESOLVE. An earlier version of this ended up calling ITSELF (a blanket
    # replace rewrote its own fallback), so every store-touching request recursed until the client
    # timed out -- a save that never returns, which is worse than one that refuses.
    if ("$($script:PimSqlCs)".Trim()) { return "$($script:PimSqlCs)".Trim() }
    return "$($global:PIM_SqlConnectionString)".Trim()
}
function Save-PimManagerDepartments {
    <#
      🔴 BUG-142 -- THE ONE WRITER. Three separate places used to write the SETTING 'Departments'
      (the settings PUT and two "import from Entra" paths), and the engine read the ENTITY, so none
      of them reached it. One writer, so they cannot drift again -- the same reasoning as §61.4's
      catalog/store merge and §63.3's two role lists.

      Returns @{ ok; count; error }. Never writes an empty set: departments carry the owner chain
      for privileged-access approvals, so a full-set delete has to be deliberate and done in the
      grid, not a side effect of an import that happened to return nothing.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Departments)

    $rows = @($Departments | ForEach-Object {
        if ($null -eq $_) { return }
        $n = "$($_.name)".Trim(); if (-not $n) { $n = "$($_.Name)".Trim() }
        if (-not $n) { return }
        [pscustomobject]@{
            Department = $n
            Owners     = (@($_.owners | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) -join '|')
            Contact    = "$($_.contact)".Trim()
            Notes      = "$($_.notes)".Trim()
        }
    } | Where-Object { $_ })

    if (@($rows).Count -eq 0) {
        return @{ ok = $false; count = 0; error = 'no department with a name was supplied -- refusing to write an empty department set (it carries the approval owner chain).' }
    }
    # 🔒 SQL ONLY -- PIM v2 has no file mode, and the ENTITY is what the engine reads, so that is
    # where departments belong (BUG-142).
    #
    # 🪤 BUT A SAVE MUST NOT LOSE THE OPERATOR'S INPUT. This screen has worked for months; making
    # the entity write a HARD requirement turned any store hiccup into "your departments are gone",
    # which is a worse failure than the divergence being fixed. So the entity write is attempted
    # first and the setting is always written too -- and because Get-PimManagerDepartments reads the
    # ENTITY FIRST and only falls back to the setting, the two cannot diverge in the direction that
    # mattered: a stale setting can never override a real entity row or re-route an approval owner.
    # The result says which stores actually took the write, so a degraded save is visible.
    $cs = (Get-PimManagerStoreCs)
    $entityOk = $false
    $entityErr = ''
    if ($cs -and (Get-Command Set-PimSqlEntityRows -ErrorAction SilentlyContinue)) {
        try {
            Set-PimSqlEntityRows -ConnectionString $cs -Entity 'PIM-Definitions-Departments' `
                -Base 'PIM-Definitions-Departments' -Rows $rows
            $entityOk = $true
        } catch { $entityErr = "$($_.Exception.Message)" }
    } else {
        $entityErr = 'no SQL store is wired in this host (PIM v2 is SQL-only -- configure the store)'
    }
    try { Set-PimManagerSetting -Name 'Departments' -Value @($Departments) }
    catch {
        if (-not $entityOk) {
            return @{ ok = $false; count = 0; error = "departments could not be saved to either store: $entityErr / $($_.Exception.Message)" }
        }
    }
    if (-not $entityOk) {
        Write-Warning "  [departments] saved, but NOT to PIM-Definitions-Departments ($entityErr) -- the engine reads that entity, so the owner chain will not see these until the store is reachable."
    }
    return @{ ok = $true; count = @($rows).Count; error = ''
              entityWritten = $entityOk; entityError = $entityErr
              note = $(if ($entityOk) { 'Saved to PIM-Definitions-Departments (the store the engine reads).' }
                       else { "Saved, but NOT to the engine's store: $entityErr" }) }
}

function Get-PimManagerApprovers {
    # Approvers / owners directory. Optional -- empty is allowed. Each:
    # @{ identity; displayName; role; notes }.
    $stored = Get-PimManagerSetting -Name 'Approvers'
    if ($null -eq $stored) { return @() }
    return @($stored)
}

function Get-PimManagerDepartmentImportPattern {
    # Naming pattern (glob) for the "Import departments from Entra" action.
    # Default 'ORG-*' -- every Entra group whose displayName starts with the
    # pattern's literal prefix becomes a department. Configurable in Settings.
    $stored = Get-PimManagerSetting -Name 'DepartmentImportPattern'
    $p = "$stored".Trim()
    if (-not $p) { return 'ORG-*' }
    return $p
}

function Get-PimManagerSettingsBundle {
    # Everything the Settings tab needs in one call, with naming + filters
    # default-seeded so the response is never empty.
    $naming = Get-PimManagerNamingSettings
    $filt   = Get-PimManagerFilterSettings
    return [ordered]@{
        storageMode  = "$($script:PimStorageMode)"
        instance     = "$($script:PimInstanceName)"
        naming       = $naming.value
        namingSeeded = $naming.seeded
        filters      = @($filt.value)
        filtersSeeded= $filt.seeded
        departments  = @(Get-PimManagerDepartments)
        deptImportPattern = (Get-PimManagerDepartmentImportPattern)
        approvers    = @(Get-PimManagerApprovers)
        operationalPolicy = (Get-PimOperationalPolicy)
    }
}

# ---------------------------------------------------------------------------
# Graph builder (same shape as v0.1, freshly recomputed each call)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Connected-tenant context for the header banner (REAL data, never hardcoded).
#   tenantId   -- the tenant the Manager is actually pointed at, from the same
#                 globals every tenant-read path uses ($global:PIM_TenantId /
#                 $global:AzureTenantID, set by the instance/env wiring above).
#   tenantName -- the tenant's Entra organisation displayName. Resolved
#                 best-effort: a prior resolution cached per-instance
#                 (SQL pim.TenantCache kind 'tenant-org') is reused first; when a
#                 live tenant connection is available we ask Graph /organization
#                 and refresh the cache. NEVER throws and NEVER blocks render --
#                 if the name can't be resolved we return $null and the GUI
#                 falls back to showing the GUID.
# ---------------------------------------------------------------------------
function Get-PimManagerTenantContext {
    $tenantId =
        if ($global:PIM_TenantId)      { "$($global:PIM_TenantId)" }
        elseif ($global:AzureTenantID) { "$($global:AzureTenantID)" }
        else { $null }

    if (-not $tenantId) { return [ordered]@{ tenantId = $null; tenantName = $null } }

    $haveCache = [bool](Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue)

    # 1. Reuse a cached resolution for THIS tenant (SQL pim.TenantCache kind 'tenant-org'), so a
    #    request without a live connection still shows the name a prior serve/refresh resolved.
    $cachedName = $null
    if ($haveCache) {
        try {
            $c = Get-PimTenantCacheEntry -Kind 'tenant-org'
            if ($c -and "$($c.tenantId)" -eq $tenantId -and $c.tenantName) { $cachedName = "$($c.tenantName)" }
        } catch { $cachedName = $null }
    }

    # 2. When a live tenant connection is available, ask Graph for the org name
    #    and refresh the cache. Best-effort: any failure leaves $cachedName.
    $canQuery = $script:PimManagerTenantConnected -or
                ((Get-Command Test-PimRestTenantAuthAvailable -ErrorAction SilentlyContinue) -and (Test-PimRestTenantAuthAvailable))
    if ($canQuery -and (Get-Command Invoke-PimGraphGetAll -ErrorAction SilentlyContinue)) {
        try {
            $orgs = @(Invoke-PimGraphGetAll -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName')
            $org  = $orgs | Select-Object -First 1
            $name = if ($org) { "$($org.displayName)" } else { $null }
            if ($name) {
                $cachedName = $name
                if ($haveCache -and $name -ne "$($c.tenantName)") {
                    try {
                        [void](Set-PimTenantCacheEntry -Kind 'tenant-org' -Value ([ordered]@{
                            tenantId     = $tenantId
                            tenantName   = $name
                            refreshedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                        }))
                    } catch { Write-Verbose "tenant-name cache write skipped: $($_.Exception.Message)" }
                }
            }
        } catch { Write-Verbose "tenant-name resolve skipped: $($_.Exception.Message)" }
    }

    return [ordered]@{ tenantId = $tenantId; tenantName = $cachedName }
}

function Build-PimGraphData {
    $admins        = (Read-PimRows 'Account-Definitions-Admins').rows

    $defRoles      = (Read-PimRows 'PIM-Definitions-Roles').rows
    $defTasks      = (Read-PimRows 'PIM-Definitions-Tasks').rows
    $defServices   = (Read-PimRows 'PIM-Definitions-Services').rows
    $defProcesses  = (Read-PimRows 'PIM-Definitions-Processes').rows
    $defResources  = (Read-PimRows 'PIM-Definitions-Resources').rows
    $defDepts      = (Read-PimRows 'PIM-Definitions-Departments').rows
    $defAUs        = (Read-PimRows 'PIM-Definitions-AU').rows
    $defOrg        = (Read-PimRows 'PIM-Definitions-Organization').rows
    $defProjects   = (Read-PimRows 'PIM-Definitions-Projects').rows
    $defCrossOrg   = (Read-PimRows 'PIM-Definitions-CrossOrg').rows

    $asgnAdmins    = (Read-PimRows 'PIM-Assignments-Admins').rows
    $asgnGroups    = (Read-PimRows 'PIM-Assignments-Groups').rows
    $asgnRolesGrp  = (Read-PimRows 'PIM-Assignments-Roles-Groups').rows
    $asgnRolesAU   = (Read-PimRows 'PIM-Assignments-Roles-AUs').rows
    $asgnAzRes     = (Read-PimRows 'PIM-Assignments-Azure-Resources').rows
    $asgnWorkloads = (Read-PimRows 'PIM-Assignments-Workloads').rows

    # Friendly workload names come from the connector catalog (id -> name), so the
    # map shows "Microsoft Defender XDR" not the bare "defender-xdr" connector id.
    # Built once per build; missing dir / parse error => empty map (id used as-is).
    $workloadNames = @{}
    try {
        $connDir = Join-Path $solutionRoot 'workloads\connectors'
        if (Get-Command Read-PimWorkloadConnectors -ErrorAction SilentlyContinue) {
            foreach ($c in @(Read-PimWorkloadConnectors -ConnectorsDir $connDir)) {
                if ("$($c.id)".Trim()) { $workloadNames["$($c.id)".Trim().ToLowerInvariant()] = "$($c.name)" }
            }
        }
    } catch { $workloadNames = @{} }

    # Live-crawl reconciliation map (written by the workload-crawl sweep into the
    # instance cache dir). GUI reads it to badge each desired workload-target as
    # mapped / missing / exempted. Best-effort: absent/parse-error => no badges.
    $workloadCrawl = $null
    try {
        if (Get-Command Read-PimWorkloadCrawlMap -ErrorAction SilentlyContinue) {
            $workloadCrawl = Read-PimWorkloadCrawlMap
        }
    } catch { $workloadCrawl = $null }
    $workloadExempt = $null
    try {
        if (Get-Command Read-PimWorkloadExemptions -ErrorAction SilentlyContinue) {
            $workloadExempt = Read-PimWorkloadExemptions -ConfigRoot $configRoot
        }
    } catch { $workloadExempt = $null }

    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList

    foreach ($a in $admins) {
        if (-not $a.UserPrincipalName) { continue }
        # v2.4.171: Purpose (Day2Day | HighPriv) replaces the per-admin
        # TierLevel column. Explicit Purpose wins; blank falls back to the
        # UserName -L0-T0- marker check; legacy TierLevel kept as last resort
        # for the map's tier coloring on not-yet-upgraded CSVs.
        $purposeVal = if ($a.PSObject.Properties.Name -contains 'Purpose' -and "$($a.Purpose)".Trim()) { "$($a.Purpose)".Trim() }
                      elseif ("$($a.UserName)" -match '(?i)(^|[-_.])(L0|T0)([-_.]|$)') { 'HighPriv' }
                      else { 'Day2Day' }
        [void]$nodes.Add([ordered]@{
            id       = $a.UserPrincipalName
            label    = $a.DisplayName
            kind     = 'admin'
            purpose  = $purposeVal
            tier     = $(if ($a.PSObject.Properties.Name -contains 'TierLevel') { $a.TierLevel } else { '' })
            platform = $a.TargetPlatform
            source   = 'Account-Definitions-Admins'
        })
    }

    $groupSources = @(
        # 🔴 §70.22 (operator 2026-09-14: "dept and organization are direct groups and not permission delegations"):
        # Departments / Organization / Projects / Cross-org are DIRECT groups (§66: admins are assigned to them; they are
        # nested INTO permission groups), exactly like Roles -- column 2 of the Access map ("job roles, departments, org
        # -- assigned directly"). They were emitted as permission groups, so the map put them in the bundle column where
        # their nestings into bundles were same-column hops and were dropped: a selected department showed nothing.
        @{ list = $defRoles;     kind = 'role-group';       source = 'PIM-Definitions-Roles' },
        @{ list = $defDepts;     kind = 'role-group';       source = 'PIM-Definitions-Departments' },
        @{ list = $defOrg;       kind = 'role-group';       source = 'PIM-Definitions-Organization' },
        @{ list = $defProjects;  kind = 'role-group';       source = 'PIM-Definitions-Projects' },
        @{ list = $defCrossOrg;  kind = 'role-group';       source = 'PIM-Definitions-CrossOrg' },
        @{ list = $defTasks;     kind = 'permission-group'; source = 'PIM-Definitions-Tasks' },
        @{ list = $defServices;  kind = 'permission-group'; source = 'PIM-Definitions-Services' },
        @{ list = $defProcesses; kind = 'permission-group'; source = 'PIM-Definitions-Processes' },
        @{ list = $defResources; kind = 'permission-group'; source = 'PIM-Definitions-Resources' }
    )
    foreach ($src in $groupSources) {
        foreach ($g in $src.list) {
            if (-not $g.GroupTag) { continue }
            [void]$nodes.Add([ordered]@{
                id          = "group:$($g.GroupTag)"
                label       = $g.GroupName
                kind        = $src.kind
                tier        = $g.TierLevel
                level       = $g.Level
                description = $g.GroupDescription
                source      = $src.source
                groupTag    = $g.GroupTag
                # §70.19: the wizards need it -- Entra refuses an ACTIVE group nesting into a role-assignable group.
                roleAssignable = ("$($g.IsRoleAssignable)".Trim() -ieq 'TRUE')
            })
        }
    }

    foreach ($au in $defAUs) {
        $tag = $null
        if ($au.AdministrativeUnitTag) { $tag = $au.AdministrativeUnitTag }
        elseif ($au.AUTag) { $tag = $au.AUTag }
        elseif ($au.Tag)   { $tag = $au.Tag }
        if (-not $tag) { continue }
        [void]$nodes.Add([ordered]@{
            id          = "au:$tag"
            label       = if ($au.AUDisplayName) { $au.AUDisplayName } else { $tag }
            kind        = 'au'
            description = $au.AUDescription
            source      = 'PIM-Definitions-AU'
            auTag       = $tag
        })
    }

    $syntheticTargets = @{}
    # $Extra carries the structured fields the Delegation Map's PERMISSIONS &
    # TARGETS column needs to show a short label + a full tooltip / expand:
    #   entra-role      -> roleName
    #   au-role         -> roleName, auTag
    #   az-resource     -> roleName, scopePath (FULL ARM/path), scopeType, scopeShort
    #   workload-target -> workloadId, workloadName, roleName, scopePath, scopeType,
    #                      scopeShort  (+ recon: status mapped|missing|exempted)
    $addSyn = {
        param($Id, $Label, $Kind, $Source, $Extra)
        if ($syntheticTargets.ContainsKey($Id)) { return }
        $node = [ordered]@{ id = $Id; label = $Label; kind = $Kind; source = $Source }
        if ($Extra) { foreach ($k in $Extra.Keys) { $node[$k] = $Extra[$k] } }
        $syntheticTargets[$Id] = $node
    }
    # Humanise an Azure scope path into a (type, short-name) pair so the map can
    # show "Owner @ mg-platform" with the full "/providers/.../mg-platform" in a
    # tooltip. Also recognises non-ARM workload scopes (Power BI workspaces,
    # Azure DevOps projects) that customers store in the AzScope column.
    $azScopeMeta = {
        param($Scope)
        $s = "$Scope".Trim()
        if (-not $s) { return @{ scopeType = 'scope'; scopeShort = '' } }
        if ($s -match '/managementGroups/([^/]+)')        { return @{ scopeType = 'Management group'; scopeShort = $Matches[1] } }
        if ($s -match '/resourceGroups/([^/]+)')          { return @{ scopeType = 'Resource group';   scopeShort = $Matches[1] } }
        if ($s -match '/subscriptions/([^/]+)/?$')         { return @{ scopeType = 'Subscription';      scopeShort = $Matches[1] } }
        if ($s -match '/subscriptions/[^/]+/.*/([^/]+)$')  { return @{ scopeType = 'Resource';          scopeShort = $Matches[1] } }
        if ($s -match '(?i)app\.powerbi\.com|powerbi|/groups/([0-9a-f-]{36})') { return @{ scopeType = 'Power BI workspace'; scopeShort = (($s -split '/') | Where-Object { $_ } | Select-Object -Last 1) } }
        if ($s -match '(?i)dev\.azure\.com|visualstudio\.com|/_project|/project/') { return @{ scopeType = 'Azure DevOps project'; scopeShort = (($s -split '/') | Where-Object { $_ } | Select-Object -Last 1) } }
        return @{ scopeType = 'scope'; scopeShort = (($s -split '/') | Where-Object { $_ } | Select-Object -Last 1) }
    }

    # Humanise a workload scope value. Workload scopes are heterogeneous (ARM
    # paths, Power BI workspace/env ids, BC tenant/environment, DevOps org, or a
    # tenant-wide "/"). Reuse the ARM humaniser where it applies; otherwise label
    # by connector kind and show the trailing segment. No live lookup (cheap):
    # the id is shown as-is when nothing better is known.
    $workloadScopeMeta = {
        param($Scope, $WorkloadId)
        $s = "$Scope".Trim()
        if (-not $s -or $s -eq '/') { return @{ scopeType = 'Tenant-wide'; scopeShort = 'tenant' } }
        $arm = & $azScopeMeta $s
        if ($arm.scopeType -ne 'scope') { return $arm }
        $wid = "$WorkloadId".Trim().ToLowerInvariant()
        $kind = switch -Wildcard ($wid) {
            'power*bi*'          { 'Power BI workspace' }
            'power-platform'     { 'Power Platform environment' }
            'business-central'   { 'Business Central environment' }
            'azure-devops'       { 'Azure DevOps scope' }
            'dataverse'          { 'Dataverse environment' }
            'intune'             { 'Intune scope' }
            'defender*'          { 'Defender scope' }
            default              { 'Workload scope' }
        }
        return @{ scopeType = $kind; scopeShort = (($s -split '/') | Where-Object { $_ } | Select-Object -Last 1) }
    }

    foreach ($r in $asgnAdmins) {
        if (-not $r.Username -or -not $r.GroupTag) { continue }
        [void]$edges.Add([ordered]@{
            source = $r.Username
            target = "group:$($r.GroupTag)"
            type   = $r.AssignmentType
            kind   = 'admin-to-group'
            source_csv = 'PIM-Assignments-Admins'
            match = [ordered]@{ Username = $r.Username; GroupTag = $r.GroupTag; AssignmentType = $r.AssignmentType }
        })
    }
    foreach ($r in $asgnGroups) {
        if (-not $r.SourceGroupTag -or -not $r.TargetGroupTag) { continue }
        [void]$edges.Add([ordered]@{
            source = "group:$($r.TargetGroupTag)"
            target = "group:$($r.SourceGroupTag)"
            type   = $r.AssignmentType
            kind   = 'group-to-group'
            source_csv = 'PIM-Assignments-Groups'
            match = [ordered]@{ TargetGroupTag = $r.TargetGroupTag; SourceGroupTag = $r.SourceGroupTag; AssignmentType = $r.AssignmentType }
        })
    }
    foreach ($r in $asgnRolesGrp) {
        if (-not $r.GroupTag -or -not $r.RoleDefinitionName) { continue }
        $targetId = "entra-role:$($r.RoleDefinitionName)"
        & $addSyn $targetId $r.RoleDefinitionName 'entra-role' 'PIM-Assignments-Roles-Groups' @{ roleName = "$($r.RoleDefinitionName)" }
        [void]$edges.Add([ordered]@{
            source = "group:$($r.GroupTag)"
            target = $targetId
            type   = $r.AssignmentType
            kind   = 'group-to-entra-role'
            source_csv = 'PIM-Assignments-Roles-Groups'
            match = [ordered]@{ GroupTag = $r.GroupTag; RoleDefinitionName = $r.RoleDefinitionName; AssignmentType = $r.AssignmentType }
        })
    }
    foreach ($r in $asgnRolesAU) {
        if (-not $r.GroupTag -or -not $r.RoleDefinitionName -or -not $r.AdministrativeUnitTag) { continue }
        $targetId = "au-role:$($r.AdministrativeUnitTag):$($r.RoleDefinitionName)"
        $label    = "$($r.RoleDefinitionName) @ AU:$($r.AdministrativeUnitTag)"
        & $addSyn $targetId $label 'au-role' 'PIM-Assignments-Roles-AUs' @{ roleName = "$($r.RoleDefinitionName)"; auTag = "$($r.AdministrativeUnitTag)" }
        [void]$edges.Add([ordered]@{
            source = "group:$($r.GroupTag)"
            target = $targetId
            type   = $r.AssignmentType
            kind   = 'group-to-au-role'
            source_csv = 'PIM-Assignments-Roles-AUs'
            match = [ordered]@{ GroupTag = $r.GroupTag; AdministrativeUnitTag = $r.AdministrativeUnitTag; RoleDefinitionName = $r.RoleDefinitionName; AssignmentType = $r.AssignmentType }
        })
        [void]$edges.Add([ordered]@{
            source = "au:$($r.AdministrativeUnitTag)"
            target = $targetId
            type   = ''
            kind   = 'au-to-au-role'
            source_csv = 'PIM-Assignments-Roles-AUs'
            match = [ordered]@{ GroupTag = $r.GroupTag; AdministrativeUnitTag = $r.AdministrativeUnitTag; RoleDefinitionName = $r.RoleDefinitionName }
            cosmetic = $true
        })
    }
    foreach ($r in $asgnAzRes) {
        if (-not $r.GroupTag -or -not $r.AzScope -or -not $r.AzScopePermission) { continue }
        $targetId = "az-res:$($r.AzScope):$($r.AzScopePermission)"
        $meta = & $azScopeMeta $r.AzScope
        $shortScope = if ("$($meta.scopeShort)".Trim()) { $meta.scopeShort } else { ($r.AzScope -split '/') | Select-Object -Last 1 }
        $label    = "$($r.AzScopePermission) @ $shortScope"
        & $addSyn $targetId $label 'az-resource' 'PIM-Assignments-Azure-Resources' @{ roleName = "$($r.AzScopePermission)"; scopePath = "$($r.AzScope)"; scopeType = "$($meta.scopeType)"; scopeShort = "$shortScope" }
        [void]$edges.Add([ordered]@{
            source = "group:$($r.GroupTag)"
            target = $targetId
            type   = $r.AssignmentType
            kind   = 'group-to-az-resource'
            source_csv = 'PIM-Assignments-Azure-Resources'
            match = [ordered]@{ GroupTag = $r.GroupTag; AzScope = $r.AzScope; AzScopePermission = $r.AzScopePermission; AssignmentType = $r.AssignmentType }
        })
    }

    # --- Workload roles & scopes (PIM-Assignments-Workloads) -----------------
    # The 4th target kind on the Delegation Map: a PIM group bound to a workload
    # RBAC role at a scope (Defender XDR / Intune / Power BI / Power Platform /
    # Business Central / Azure DevOps / Dataverse / app-roles). Sourced ONLY from
    # the desired CSV (never from group names). Edge: capability bundle ->
    # workload-target, mirroring the az-resource pattern. When a live-crawl map is
    # present, each target is reconciled (mapped | missing | exempted) for a badge.
    foreach ($r in $asgnWorkloads) {
        if (-not $r.Workload -or -not $r.RoleName -or -not $r.GroupTag) { continue }
        $wid       = "$($r.Workload)".Trim()
        $widLc     = $wid.ToLowerInvariant()
        $wName     = if ($workloadNames.ContainsKey($widLc)) { $workloadNames[$widLc] } else { $wid }
        $wScope    = "$($r.Scope)".Trim()
        $meta      = & $workloadScopeMeta $wScope $wid
        $shortScope= if ("$($meta.scopeShort)".Trim()) { "$($meta.scopeShort)" } else { 'tenant' }
        $targetId  = "workload:$widLc`:$($r.RoleName):$wScope"
        $label     = "$($r.RoleName) @ $wName"
        $extra     = @{
            workloadId   = $wid
            workloadName = "$wName"
            roleName     = "$($r.RoleName)"
            scopePath    = $wScope
            scopeType    = "$($meta.scopeType)"
            scopeShort   = "$shortScope"
        }
        # Reconciliation status from the live-crawl map + exemptions, per group.
        if (Get-Command Get-PimWorkloadReconStatus -ErrorAction SilentlyContinue) {
            try {
                $recon = Get-PimWorkloadReconStatus -Row $r -CrawlMap $workloadCrawl -Exemptions $workloadExempt
                if ($recon) {
                    $extra.reconStatus = "$($recon.status)"
                    if ("$($recon.reason)".Trim())  { $extra.reconReason  = "$($recon.reason)" }
                    if ("$($recon.crawledUtc)".Trim()) { $extra.reconCrawledUtc = "$($recon.crawledUtc)" }
                }
            } catch { }
        }
        & $addSyn $targetId $label 'workload-target' 'PIM-Assignments-Workloads' $extra
        [void]$edges.Add([ordered]@{
            source = "group:$($r.GroupTag)"
            target = $targetId
            type   = $r.Action
            kind   = 'group-to-workload'
            source_csv = 'PIM-Assignments-Workloads'
            match = [ordered]@{ GroupTag = $r.GroupTag; Workload = $wid; RoleName = $r.RoleName; Scope = $wScope; Action = $r.Action }
        })
    }

    foreach ($t in $syntheticTargets.Values) { [void]$nodes.Add($t) }

    # ─────────────────────────────────────────────────────────────────────────
    # 🔴 CANONICALISE EVERY EDGE ENDPOINT TO ITS NODE'S EXACT ID (case-insensitively).
    #
    # A node's id is the value from the DEFINITION csv -- an admin's
    # `UserPrincipalName`, a group's `GroupTag`. An edge's endpoint is the value from the
    # ASSIGNMENT csv -- `Username`, `GroupTag`. The browser resolves an edge with `byId[e.source]`,
    # which is an exact, CASE-SENSITIVE object-key lookup, so the two only meet when the operator
    # happened to type the same case in two different files.
    #
    # 🪤 AND WHEN THEY DO NOT, NOTHING SAYS SO. `colOf(undefined)` returns -1 and the reach edge is
    # dropped in silence: the Access board renders the person with EVERY column empty, which looks
    # exactly like "this admin has no permissions" rather than "these two rows did not join".
    # Measured at a live customer 2026-09-10:
    #     Account-Definitions-Admins.UserPrincipalName : Admin-Brian-L0-T0-ID@<domain>
    #     PIM-Assignments-Admins.Username              : admin-brian-l0-t0-id@<domain>
    # -- the same account, written in two cases, in two files. Same defect on GroupTags in the same
    # data: `ROLE-ITSupport-EXT-FellowMind` defined, `ROLE-ITSUPPORT-EXT-FELLOWMIND` assigned.
    #
    # 🔒 UPNs and group names are CASE-INSENSITIVE identifiers -- Entra treats them so, and this
    # repo's own validator has always compared them with ToLowerInvariant (PIM-FK-001/002), which
    # is why the validator reported these rows as FINE while the board showed nothing. Two parts of
    # the same product disagreeing on whether a name is case-sensitive is the actual bug.
    #
    # Done ONCE over every edge rather than at each of the seven places an edge is built: a rule
    # applied at named call sites protects those call sites, not the next one added.
    $idByLower = @{}
    foreach ($n in $nodes) {
        $k = "$($n.id)".ToLowerInvariant()
        if (-not $idByLower.ContainsKey($k)) { $idByLower[$k] = $n.id }
    }
    $edgeCaseFixed = 0
    $danglingEdges = New-Object System.Collections.Generic.List[string]
    foreach ($e in $edges) {
        foreach ($end in @('source','target')) {
            $v = "$($e[$end])"
            if (-not $v) { continue }
            $k = $v.ToLowerInvariant()
            if ($idByLower.ContainsKey($k)) {
                # -cne: a CASE-SENSITIVE comparison, deliberately. -ne would call these equal and
                # rewrite nothing, which is the very assumption that produced the defect.
                if ($idByLower[$k] -cne $v) { $e[$end] = $idByLower[$k]; $edgeCaseFixed++ }
            } else {
                [void]$danglingEdges.Add($v)
            }
        }
    }
    if ($edgeCaseFixed) {
        Write-Host "  [map] matched $edgeCaseFixed edge endpoint(s) to their node by name, ignoring case" -ForegroundColor DarkGray
    }
    if ($danglingEdges.Count) {
        # NOT silently dropped. These are the genuinely-undefined principals and tags (the
        # PIM-FK-002 / PIM-FK-001 class) -- an assignment naming something no definition csv
        # declares. The validator reports them properly; saying how many here means an empty
        # column is never mistaken for an empty answer.
        $uniq = @($danglingEdges | Sort-Object -Unique)
        Write-Host ("  [map] {0} edge endpoint(s) name something no definition declares: {1}" -f `
                    $uniq.Count, (($uniq | Select-Object -First 8) -join ', ')) -ForegroundColor DarkYellow
    }

    $summary = [ordered]@{
        nodes  = $nodes.Count
        edges  = $edges.Count
        admins = @($nodes | Where-Object { $_.kind -eq 'admin' }).Count
        roleGroups       = @($nodes | Where-Object { $_.kind -eq 'role-group' }).Count
        permissionGroups = @($nodes | Where-Object { $_.kind -eq 'permission-group' }).Count
        targets          = @($nodes | Where-Object { $_.kind -in @('entra-role','au-role','az-resource','workload-target') }).Count
        workloadTargets  = @($nodes | Where-Object { $_.kind -eq 'workload-target' }).Count
    }

    # Report the ACTUAL source the rows came from. In SQL mode the model is
    # read from the SQL store (pim.* via Get-PimSqlRows in Read-PimRows), NOT
    # from the on-disk config files, so the banner must say SQL -- not the
    # config path. CSV/local mode keeps reporting $configRoot.
    $sourceRoot = if ($script:PimStorageMode -eq 'sql') {
        $db = if ($global:PIM_SqlDatabase) { $global:PIM_SqlDatabase } else { 'pim' }
        "SQL: $db"
    } else { $configRoot }

    # Connected-tenant context for the header banner (name + GUID, REAL data).
    $tenantCtx = Get-PimManagerTenantContext

    return [ordered]@{
        generatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        sourceRoot   = $sourceRoot
        storageMode  = 'sql'
        tenantId     = $tenantCtx.tenantId
        tenantName   = $tenantCtx.tenantName
        nodes        = $nodes.ToArray()
        edges        = $edges.ToArray()
        summary      = $summary
        csvBases     = @($script:PimCsvBases | ForEach-Object { @{ base = $_.base; group = $_.group } })
    }
}

# ---------------------------------------------------------------------------
# Home / Overview aggregation (REQUIREMENTS §26a/§27 H2).
# ONE read that correlates the EXISTING engine/validator/scheduler/audit
# sources into the landing-page tiles. Every section is wrapped in its own
# try/catch so one unavailable source degrades to an honest empty/error
# state for THAT tile only -- the page never goes dead. No source is faked:
#   - delegation tiers / gaps / orphans  <- Build-PimGraphData (the live model)
#   - engine & jobs health               <- Get-PimJobsStatus (scheduler)
#   - validation errors/warnings         <- Invoke-PimPreflightValidation
#   - break-glass                        <- pim.Settings['EmergencyOverride'] (file only local/dev; §36.3 phase 3)
#   - access reviews                      <- Get-PimAccessReviewOverview/seed
#   - expiring active assignments         <- Get-PimActiveAssignmentsCached (the scheduler's SQL snapshot, §70.1b)
# Heavy/live sources (active-assignments, access-reviews) only run when the
# caller asks for them (?include=heavy) so the default Home load stays fast.
# ---------------------------------------------------------------------------
function Get-PimDelegationTierLevel {
    # Resolve a delegation group's LEVEL (L0..L5) from the richest real signal:
    # explicit Level/TierLevel field, else parse the -L<n>- / -T<n>- marker out of
    # the GroupTag / GroupName / label produced by the naming convention. Returns
    # an integer 0..5 or $null (untiered). PS 5.1-safe.
    param([object]$Node)
    if (-not $Node) { return $null }
    $cand = @()
    foreach ($k in 'level','tier') {
        $v = $null
        if ($Node -is [System.Collections.IDictionary]) { if ($Node.Contains($k)) { $v = $Node[$k] } }
        elseif ($Node.PSObject.Properties[$k]) { $v = $Node.PSObject.Properties[$k].Value }
        if ($null -ne $v -and "$v".Trim()) { $cand += "$v" }
    }
    foreach ($k in 'groupTag','label','id') {
        $v = $null
        if ($Node -is [System.Collections.IDictionary]) { if ($Node.Contains($k)) { $v = $Node[$k] } }
        elseif ($Node.PSObject.Properties[$k]) { $v = $Node.PSObject.Properties[$k].Value }
        if ($null -ne $v -and "$v".Trim()) { $cand += "$v" }
    }
    foreach ($c in $cand) {
        $s = "$c"
        if ($s -match '(?i)(^|[-_.\s])L([0-5])([-_.\s]|$)') { return [int]$Matches[2] }
        if ($s -match '(?i)(^|[-_.\s])T([0-5])([-_.\s]|$)') { return [int]$Matches[2] }
        if ($s -match '^\s*([0-5])\s*$')                     { return [int]$Matches[1] }
    }
    return $null
}

function Get-PimHomeOverview {
    [CmdletBinding()]
    param([switch]$IncludeHeavy)

    $now = [datetime]::UtcNow
    $tiles = [ordered]@{}

    # ---- 1. Delegation estate: per-level (L0-L5) + gaps/orphans/unmanaged -----
    # Sourced from the live graph model the Delegation Map renders (Build-PimGraphData):
    #   - tiers   = delegation groups (role/permission) bucketed by their level
    #   - orphans = groups with NO inbound/outbound edge (defined but unwired)
    #   - gaps    = admins with NO group membership edge (a person who reaches nothing)
    #   - unmanaged = synthetic targets (Entra role / AU / Azure scope) reached by NO group
    try {
        $g = Build-PimGraphData
        $nodes = @($g.nodes); $edges = @($g.edges)
        $byLevel = [ordered]@{ 'L0'=0;'L1'=0;'L2'=0;'L3'=0;'L4'=0;'L5'=0;'untiered'=0 }
        $delegationGroups = @($nodes | Where-Object { $_.kind -eq 'role-group' -or $_.kind -eq 'permission-group' })
        foreach ($n in $delegationGroups) {
            $lvl = Get-PimDelegationTierLevel -Node $n
            if ($null -ne $lvl) { $byLevel["L$lvl"] = [int]$byLevel["L$lvl"] + 1 } else { $byLevel['untiered'] = [int]$byLevel['untiered'] + 1 }
        }
        # Edge endpoints (source + target) -> the set of wired node ids. Nodes/edges
        # are [ordered] dictionaries (from Build-PimGraphData) -- dot-access reads the
        # entries; PSObject.Properties does NOT see dictionary keys, so use dot/Contains.
        $wired = New-Object System.Collections.Generic.HashSet[string]
        foreach ($e in $edges) {
            if ("$($e.source)".Trim()) { [void]$wired.Add("$($e.source)") }
            if ("$($e.target)".Trim()) { [void]$wired.Add("$($e.target)") }
        }
        $orphanGroups = @($delegationGroups | Where-Object { -not $wired.Contains("$($_.id)") })
        $admins       = @($nodes | Where-Object { $_.kind -eq 'admin' })
        $gapAdmins    = @($admins | Where-Object { -not $wired.Contains("$($_.id)") })
        $targets      = @($nodes | Where-Object { $_.kind -eq 'entra-role' -or $_.kind -eq 'au-role' -or $_.kind -eq 'az-resource' })
        $unmanaged    = @($targets | Where-Object { -not $wired.Contains("$($_.id)") })
        $tiles.tiers = [ordered]@{
            ok            = $true
            byLevel       = $byLevel
            totalGroups   = $delegationGroups.Count
            admins        = $admins.Count
            generatedUtc  = "$($g.generatedUtc)"
        }
        $tiles.gaps = [ordered]@{
            ok               = $true
            orphanGroups     = $orphanGroups.Count       # groups defined but reach/are-reached-by nothing
            gapAdmins        = $gapAdmins.Count           # admins with no group membership (reach nothing)
            unmanagedTargets = $unmanaged.Count           # roles/AUs/azure scopes no group reaches
            orphanGroupTags  = @($orphanGroups | ForEach-Object { "$($_.label)" } | Select-Object -First 12)
            gapAdminNames    = @($gapAdmins   | ForEach-Object { "$($_.label)" } | Select-Object -First 12)
        }
    } catch {
        $tiles.tiers = [ordered]@{ ok = $false; error = "$($_.Exception.Message)" }
        $tiles.gaps  = [ordered]@{ ok = $false; error = "$($_.Exception.Message)" }
    }

    # ---- 2. Engine & jobs health (scheduler) ---------------------------------
    # last run / result / FAILED jobs / next run / running, red-green.
    try {
        if (Get-Command Get-PimJobsStatus -ErrorAction SilentlyContinue) {
            $eff = @(Get-PimManagerEffectiveSchedule)
            $vm  = if ($eff.Count -gt 0) { Get-PimJobsStatus -Jobs $eff } else { Get-PimJobsStatus }
            $jobs = @($vm.jobs)
            $histCount = 0
            try { if (Get-Command Get-PimJobRunHistory -ErrorAction SilentlyContinue) { $histCount = @(Get-PimJobRunHistory).Count } } catch {}
            # BUG-113: the SAME split the Jobs view makes, made here too. A last run of
            # 'no-handler-registered' says this worker has no implementation for the job type --
            # a deployment/scope question. Counting it in the Overview's FAILED JOBS tile turns
            # one deployment fact into a red headline the operator cannot act on, and the two
            # surfaces would then disagree about the same job.
            $failed     = @($jobs | Where-Object { $_.lastOk -eq $false -and "$($_.lastResult)" -notmatch '^no-handler' })
            $unrunnable = @($jobs | Where-Object { $_.lastOk -eq $false -and "$($_.lastResult)" -match '^no-handler' })
            $running = @($jobs | Where-Object { $_.inProgress })
            # The most recent completed run across all jobs (for "last run" headline).
            $lastRunJob = @($jobs | Where-Object { "$($_.lastRunUtc)".Trim() } | Sort-Object { "$($_.lastRunUtc)" } -Descending) | Select-Object -First 1
            # Next scheduled run across all enabled jobs.
            $nextRunJob = @($jobs | Where-Object { $_.enabled -and "$($_.nextRunUtc)".Trim() } | Sort-Object { "$($_.nextRunUtc)" }) | Select-Object -First 1
            # Drift signal (REQUIREMENTS §26b "...next run / drift"). An engine reconcile
            # job whose LAST run *applied* changes (lastRan = $true) means the live estate
            # had drifted from the desired set and was corrected on that pass. A clean
            # delta run (lastRan = $false) means live == desired = no drift. We report the
            # most-recent engine reconcile run's outcome; non-engine jobs (discovery,
            # tenant-cache, mail) never carry a drift signal.
            $engineJobs = @($jobs | Where-Object { "$($_.type)" -match '(?i)^engine' -and "$($_.lastRunUtc)".Trim() })
            $lastEngine = @($engineJobs | Sort-Object { "$($_.lastRunUtc)" } -Descending) | Select-Object -First 1
            $drift = $null
            if ($lastEngine) {
                $drifted = ($lastEngine.lastOk -ne $false -and [bool]$lastEngine.lastRan)
                $drift = [ordered]@{
                    ok        = $true
                    drifted   = [bool]$drifted          # last reconcile applied changes -> the estate had drifted
                    job       = "$($lastEngine.name)"
                    scope     = "$($lastEngine.scope)"
                    whenUtc   = "$($lastEngine.lastRunUtc)"
                    detail    = "$($lastEngine.lastResult)"
                    knownOk   = ($lastEngine.lastOk -ne $false)   # a failed reconcile can't assert "no drift"
                }
            }
            $status = if ($failed.Count -gt 0) { 'red' } elseif ($histCount -eq 0) { 'unknown' } else { 'green' }
            $tiles.jobs = [ordered]@{
                ok            = $true
                status        = $status
                total         = [int]$vm.total
                enabled       = @($jobs | Where-Object { $_.enabled }).Count
                runningCount  = [int]$vm.runningCount
                failedCount   = $failed.Count
                # BUG-92: jobs this worker is deliberately NOT scoped to run are reported
                # separately from failures. They used to be counted as failed -- six job types
                # permanently red on a healthy deployment, servicenow-intake among them for a
                # customer with no ServiceNow.
                # BUG-113: "this worker has no handler for it" -- reported, but never as a failure.
                unrunnableCount = $unrunnable.Count
                unrunnableJobs  = @($unrunnable | ForEach-Object { [ordered]@{ name = "$($_.name)"; type = "$($_.type)"; detail = "$($_.lastResult)" } } | Select-Object -First 12)
                skippedCount  = @($jobs | Where-Object { "$($_.lastStatus)" -eq 'skipped' }).Count
                skippedJobs   = @($jobs | Where-Object { "$($_.lastStatus)" -eq 'skipped' } | ForEach-Object { [ordered]@{ name = "$($_.name)"; type = "$($_.type)"; detail = "$($_.lastResult)" } } | Select-Object -First 12)
                neverRunCount = @($jobs | Where-Object { $_.neverRun }).Count
                historyCount  = [int]$histCount
                failedJobs    = @($failed  | ForEach-Object { [ordered]@{ name = "$($_.name)"; type = "$($_.type)"; scope = "$($_.scope)"; lastRunUtc = "$($_.lastRunUtc)"; detail = "$($_.lastResult)"; runId = "$($_.lastRunId)" } } | Select-Object -First 12)
                runningJobs   = @($running | ForEach-Object { [ordered]@{ name = "$($_.name)"; type = "$($_.type)"; scope = "$($_.scope)"; runId = "$($_.runningRunId)" } } | Select-Object -First 12)
                lastRun       = $(if ($lastRunJob) { [ordered]@{ name = "$($lastRunJob.name)"; whenUtc = "$($lastRunJob.lastRunUtc)"; ok = [bool]$lastRunJob.lastOk; detail = "$($lastRunJob.lastResult)" } } else { $null })
                nextRun       = $(if ($nextRunJob) { [ordered]@{ name = "$($nextRunJob.name)"; whenUtc = "$($nextRunJob.nextRunUtc)"; synthesized = [bool]$nextRunJob.nextRunSynthesized } } else { $null })
                drift         = $drift
            }
        } else {
            $tiles.jobs = [ordered]@{ ok = $false; status = 'unknown'; note = 'scheduler library not loaded'; total = 0; failedCount = 0 }
        }
    } catch {
        $tiles.jobs = [ordered]@{ ok = $false; status = 'unknown'; error = "$($_.Exception.Message)"; total = 0; failedCount = 0 }
    }

    # ---- 3. Validation errors/warnings (preflight) ---------------------------
    try {
        if (Get-Command Invoke-PimPreflightValidation -ErrorAction SilentlyContinue) {
            $report = if ($script:PimPreflightCacheReport) { $script:PimPreflightCacheReport } else { Invoke-PimPreflightValidation }
            $sum = $report.summary
            $errs = [int]$sum.errors; $warns = [int]$sum.warnings
            $tiles.validation = [ordered]@{
                ok       = $true
                status   = $(if ($errs -gt 0) { 'red' } elseif ($warns -gt 0) { 'amber' } else { 'green' })
                errors   = $errs
                warnings = $warns
                infos    = [int]$sum.infos
                ranAtUtc = "$($report.ranAt)"
            }
        } else {
            $tiles.validation = [ordered]@{ ok = $false; note = 'validator not loaded'; errors = 0; warnings = 0 }
        }
    } catch {
        $tiles.validation = [ordered]@{ ok = $false; error = "$($_.Exception.Message)"; errors = 0; warnings = 0 }
    }

    # ---- 4. Break-glass (emergency override) ---------------------------------
    try {
        # §36.3 phase 3 -- read the SHARED store, so the tile shows the override the ENGINE will
        # actually act on. Reading this container's own file would show a different answer.
        $ov = Get-PimManagerEmergencyOverride
        if ($ov) {
            $expired = $true
            try { $expired = ($now -ge ([datetime]$ov.expiresAtUtc).ToUniversalTime()) } catch {}
            $tiles.breakGlass = [ordered]@{
                ok          = $true
                active      = [bool]($ov.active -and -not $expired)
                activatedBy = "$($ov.activatedBy)"
                expiresAtUtc= "$($ov.expiresAtUtc)"
                reason      = "$($ov.reason)"
                scope       = @($ov.scopeGroupTags)
            }
        } else {
            $tiles.breakGlass = [ordered]@{ ok = $true; active = $false }
        }
    } catch {
        $tiles.breakGlass = [ordered]@{ ok = $false; active = $false; error = "$($_.Exception.Message)" }
    }

    # ---- 4b. Pending approvals (maker/checker queue) -- FAST (local/SQL store).
    # The approval queue lives in the settings store (no live tenant call), so it
    # loads on the fast path. Counts Pending requests awaiting a checker; deep-links
    # to the Approvals tab. (REQUIREMENTS §13/§27 H3/H4.)
    try {
        if (Get-Command Get-PimApprovalRequests -ErrorAction SilentlyContinue) {
            $pend = @(Get-PimApprovalRequests -Status 'Pending')
            $tiles.approvals = [ordered]@{ ok = $true; pending = @($pend).Count; offboards = @($pend | Where-Object { (Test-PimApprovalAction -Action "$($_.action)") -eq 'offboard' }).Count; revokes = @($pend | Where-Object { (Test-PimApprovalAction -Action "$($_.action)") -eq 'revoke' }).Count }
        } else {
            $tiles.approvals = [ordered]@{ ok = $false; pending = 0; error = 'approval-gate library not loaded' }
        }
    } catch {
        $tiles.approvals = [ordered]@{ ok = $false; pending = 0; error = "$($_.Exception.Message)" }
    }

    # ---- 4c. Recent alerts (the PUSH feed) -- FAST (local JSONL feed). ----------
    # Surfaces what the alerting layer actually pushed out: total recent alerts, how
    # many had a RECORDED delivery vs rendered-only (the proof headline), and the
    # latest one. Deep-links to the Home/Settings alerting panel. (§26c / §28 [H2].)
    try {
        if (Get-Command Get-PimAlertFeedSummary -ErrorAction SilentlyContinue) {
            $feed = Get-PimManagerAlertFeed
            $sum = Get-PimAlertFeedSummary -Feed $feed -NowUtc $now -WindowHours 168
            $tiles.alerts = [ordered]@{
                ok          = $true
                total       = [int]$sum.total
                sent        = [int]$sum.sent
                unsent      = [int]$sum.unsent
                windowHours = [int]$sum.windowHours
                byEvent     = $sum.byEvent
                latest      = $sum.latest
            }
        } else {
            $tiles.alerts = [ordered]@{ ok = $false; total = 0; note = 'alert-feed library not loaded' }
        }
    } catch {
        $tiles.alerts = [ordered]@{ ok = $false; total = 0; error = "$($_.Exception.Message)" }
    }

    # ---- 5. Access reviews (pending) -- heavy/live, opt-in -------------------
    if ($IncludeHeavy) {
        try {
            if ($PSScriptRoot -and -not (Get-Command Get-PimAccessReviewOverview -ErrorAction SilentlyContinue)) {
                $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
                if (Test-Path -LiteralPath $shared) { Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue }
            }
            $rows = @(); $arSource = 'seed'
            if (Get-Command Get-PimAccessReviewOverview -ErrorAction SilentlyContinue) {
                try { Initialize-PimManagerTenantConnection; $rows = @(Get-PimAccessReviewOverview -IncludeDecisionCounts); if ($rows.Count -gt 0) { $arSource = 'live' } } catch {}
            }
            if ($rows.Count -eq 0 -and (Get-Command Get-PimAccessReviewSeedRows -ErrorAction SilentlyContinue)) { $rows = @(Get-PimAccessReviewSeedRows); $arSource = 'seed' }
            $pending = @($rows | Where-Object { "$($_.Status)" -match '(?i)progress|pending|active|inprogress' })
            $tiles.accessReviews = [ordered]@{ ok = $true; source = $arSource; total = $rows.Count; pending = $pending.Count }
        } catch {
            $tiles.accessReviews = [ordered]@{ ok = $false; error = "$($_.Exception.Message)"; pending = 0 }
        }

        # ---- 6. Expiring active assignments -- heavy/live, opt-in ------------
        try {
            if (Get-Command Get-PimActiveAssignmentsCached -ErrorAction SilentlyContinue) {
                # §70.1b option 2: a 14-day expiry tile does not need minute-fresh data, and a live read blocks
                # the whole Manager for minutes -- so it reads the scheduler's stored snapshot, never the tenant.
                $aa = Get-PimActiveAssignmentsCached -Reason 'home'
                $rows = @($aa.rows)
                $soon = $now.AddDays(14)
                $expiring = @($rows | Where-Object {
                    $end = $null
                    if ("$($_.end)".Trim()) { try { $end = ([datetime]$_.end).ToUniversalTime() } catch {} }
                    $end -and $end -ge $now -and $end -le $soon
                })
                $tiles.expiring = [ordered]@{
                    ok          = [bool]$aa.ok
                    windowDays  = 14
                    total       = $rows.Count
                    expiring    = $expiring.Count
                    items       = @($expiring | Sort-Object { try { [datetime]$_.end } catch { $now } } | Select-Object -First 12 | ForEach-Object { [ordered]@{ principal = "$($_.principal)"; role = "$($_.role)"; endUtc = "$($_.end)"; type = "$($_.type)" } })
                    note        = "$($aa.error)"
                    # "as of" facts from the snapshot, so the tile never passes an old or absent read off as live.
                    asOfUtc         = $aa.refreshedUtc
                    ageSeconds      = $aa.ageSeconds
                    snapshotMissing = [bool]$aa.snapshotMissing
                    refreshQueued   = [bool]$aa.refreshQueued
                    stale           = [bool]$aa.stale
                    hint            = "$($aa.hint)"
                }
                # Alerting (REQUIREMENTS §26c / §28 [H2]): the 'expiring-access' event was
                # in the catalog but nothing dispatched it. Fire it (debounced) when the
                # live read found expiring access, through the existing notify path. The
                # pure decision lives in Get-PimExpiringAccessAlert; this only dispatches.
                if ([bool]$aa.ok -and (Get-Command Get-PimExpiringAccessAlert -ErrorAction SilentlyContinue) -and (Get-Command Send-PimManagerAlert -ErrorAction SilentlyContinue)) {
                    try {
                        $ea = Get-PimExpiringAccessAlert -Rows $rows -NowUtc $now -WindowDays 14
                        if ($ea.fire) {
                            # debounce daily so the same expiring set does not re-alert on every Home load
                            Send-PimManagerAlert -Event 'expiring-access' -Title 'Active access expiring soon' -Detail "$($ea.detail)" -LinkTab 'home' -DebounceMinutes 1440 | Out-Null
                        }
                    } catch {}
                }
            } else {
                $tiles.expiring = [ordered]@{ ok = $false; note = 'active-assignments reader not loaded'; expiring = 0 }
            }
        } catch {
            $tiles.expiring = [ordered]@{ ok = $false; error = "$($_.Exception.Message)"; expiring = 0 }
        }
    } else {
        # Default (fast) load: signal the heavy tiles are deferred (GUI lazy-loads them).
        $tiles.accessReviews = [ordered]@{ ok = $true; deferred = $true; pending = $null }
        $tiles.expiring      = [ordered]@{ ok = $true; deferred = $true; expiring = $null }
    }

    return [ordered]@{
        generatedUtc = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
        includeHeavy = [bool]$IncludeHeavy
        tiles        = $tiles
    }
}

# ===========================================================================
# Support / diagnostics (REQUIREMENTS §28 [M9]).
# First-line self-check an admin can run, plus a SANITIZED handoff bundle.
# This wrapper does the LIVE, best-effort probes (SQL connect / Graph org read /
# ARM read) and feeds the OUTCOME into the PURE, unit-tested cores in
# engine/_shared/PIM-AuthDiagnostics.ps1 (Get-PimConnectivityCheck /
# Get-PimSupportHealthSummary / New-PimDiagnosticsBundle). Every probe is guarded
# so a diagnostics run never throws -- it explains failures, it must not cause one.
# ===========================================================================
function Get-PimSupportDiagnostics {
    [CmdletBinding()]
    param([switch]$IncludeBundle)

    # ---- 1. Connectivity + permission checks (live probes -> pure classifier) ----
    $checks = New-Object System.Collections.Generic.List[object]

    # SQL: try a cheap connectivity probe when a SQL store is configured.
    $sqlConfigured = ($script:PimStorageMode -eq 'sql' -and $script:PimSqlCs)
    if ($sqlConfigured) {
        $sqlReach = $false; $sqlErr = ''
        try {
            if (Get-Command Test-PimSqlConnectivity -ErrorAction SilentlyContinue) {
                $sqlReach = [bool](Test-PimSqlConnectivity -ConnectionString $script:PimSqlCs)
            }
        } catch { $sqlErr = "$($_.Exception.Message)" }
        $checks.Add((Get-PimConnectivityCheck -Surface 'sql' -Reachable $sqlReach -ErrorMessage $sqlErr -Configured $true))
    } else {
        $checks.Add((Get-PimConnectivityCheck -Surface 'sql' -Configured $false))
    }

    # Graph: a tiny org read proves reachability + the engine SPN's directory read.
    $graphReach = $false; $graphStatus = 0; $graphErr = ''; $graphPath = '/v1.0/organization'
    try {
        Initialize-PimManagerTenantConnection
        if (Get-Command Invoke-PimGraphGetAll -ErrorAction SilentlyContinue) {
            $null = @(Invoke-PimGraphGetAll -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id')
            $graphReach = $true; $graphStatus = 200
        } else {
            $graphErr = 'Graph client (Invoke-PimGraphGetAll) not available in this runtime.'
        }
    } catch {
        $graphErr = "$($_.Exception.Message)"
        if ($graphErr -match '(?i)\b(401|403)\b' -or (Test-PimIsAuthForbidden -ErrorBody $graphErr)) { $graphStatus = 403; $graphReach = $true } else { $graphReach = $false }
    }
    $checks.Add((Get-PimConnectivityCheck -Surface 'graph' -Reachable $graphReach -StatusCode $graphStatus -ErrorMessage $graphErr -ProbePath $graphPath -Configured $true))

    # ARM: only when an Azure scope is in play for this instance.
    $armConfigured = $false
    try {
        if (Get-Command Build-PimGraphData -ErrorAction SilentlyContinue) {
            $g = Build-PimGraphData
            $armConfigured = [bool](@($g.nodes | Where-Object { $_.kind -eq 'az-resource' }).Count -gt 0)
        }
    } catch {}
    if ($armConfigured) {
        $armReach = $false; $armStatus = 0; $armErr = ''
        try {
            if (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue) {
                $null = Invoke-PimArm -Method GET -Uri 'https://management.azure.com/subscriptions?api-version=2020-01-01'
                $armReach = $true; $armStatus = 200
            } else { $armErr = 'ARM client (Invoke-PimArm) not available in this runtime.' }
        } catch {
            $armErr = "$($_.Exception.Message)"
            if (Test-PimIsAuthForbidden -ErrorBody $armErr) { $armStatus = 403; $armReach = $true }
        }
        $checks.Add((Get-PimConnectivityCheck -Surface 'arm' -Reachable $armReach -StatusCode $armStatus -ErrorMessage $armErr -ProbePath '/subscriptions' -Configured $true))
    } else {
        $checks.Add((Get-PimConnectivityCheck -Surface 'arm' -Configured $false))
    }

    # ---- 2. Health summary (injected state -> pure summary) ----------------------
    $freshness = @{}
    try { if (Get-Command Get-PimCacheFreshness -ErrorAction SilentlyContinue) { $freshness = Get-PimCacheFreshness } } catch {}
    $lastRun = $null
    try {
        if (Get-Command Get-PimJobsStatus -ErrorAction SilentlyContinue) {
            $eff = @(Get-PimManagerEffectiveSchedule)
            $vm  = if ($eff.Count -gt 0) { Get-PimJobsStatus -Jobs $eff } else { Get-PimJobsStatus }
            $jobs = @($vm.jobs)
            $lrj = @($jobs | Where-Object { "$($_.lastRunUtc)".Trim() } | Sort-Object { "$($_.lastRunUtc)" } -Descending) | Select-Object -First 1
            if ($lrj) { $lastRun = @{ name = "$($lrj.name)"; whenUtc = "$($lrj.lastRunUtc)"; ok = [bool]$lrj.lastOk; detail = "$($lrj.lastResult)" } }
        }
    } catch {}
    $health = Get-PimSupportHealthSummary -StorageMode $script:PimStorageMode -CacheFreshness $freshness `
        -LastRun $lastRun -InstanceName $script:PimInstanceName -ManagerVersion (Get-PimSolutionVersion)

    $result = [ordered]@{
        generatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        checks       = @($checks.ToArray())
        health       = $health
        overall      = $(if (@($checks | Where-Object { $_.status -eq 'fail' }).Count -gt 0) { 'fail' } elseif (@($checks | Where-Object { $_.status -eq 'pass' }).Count -gt 0) { 'pass' } else { 'unknown' })
    }

    # ---- 3. Sanitized bundle (opt-in -- the download path) -----------------------
    if ($IncludeBundle) {
        $tenantCtx = try { Get-PimManagerTenantContext } catch { @{ tenantId = ''; tenantName = '' } }
        $versions = [ordered]@{
            manager    = "$(Get-PimSolutionVersion)"
            powershell = "$($PSVersionTable.PSVersion)"
            dotnet     = "$([System.Environment]::Version)"
            os         = "$([System.Environment]::OSVersion.VersionString)"
        }
        # Non-secret config only. Tenant name is fine; tenant id is masked by the
        # bundle redactor (kept only as first-8 for correlation).
        $config = [ordered]@{
            storageMode   = "$($script:PimStorageMode)"
            instance      = "$($script:PimInstanceName)"
            tenantName    = "$($tenantCtx.tenantName)"
            tenantId      = "$($tenantCtx.tenantId)"
            sqlConfigured = [bool]$sqlConfigured
            armConfigured = [bool]$armConfigured
        }
        $recent = @()
        if ($lastRun) { $recent = @($lastRun) }
        $result.bundle = New-PimDiagnosticsBundle -Versions $versions -Checks @($checks.ToArray()) -Health $health -Config $config -RecentRuns $recent
    }

    return $result
}

# ===========================================================================
# Visibility & reporting (REQUIREMENTS §26a) -- ALL engine/SQL-backed.
# These read the SAME live delegation model the Delegation Map renders
# (Build-PimGraphData over pim.* / the desired store), so every report row
# and search hit traces to real data the engine produces. No hardcoded data.
#
#   Get-PimAccessGraphModel  -- the shared node/edge model (one read).
#   Get-PimReachableTargets  -- forward "who can do what": person -> targets.
#   Get-PimRoleReachers      -- reverse: a role/target -> who can activate it.
#   Get-PimGlobalSearch      -- one box over people/groups/roles/scopes/tags.
#
# Every target a person reaches is reported WITH its activation path
# (admin -> group -> [nested group] -> target) so the result is auditable
# evidence, not just a flat list.
# ===========================================================================

function Get-PimAccessGraphModel {
    # One read of the live delegation model. Returns the node/edge arrays plus
    # fast lookups the traversal needs. Build-PimGraphData is the single source
    # of truth (SQL in hosted mode, the desired store otherwise).
    [CmdletBinding()] param()
    $g = Build-PimGraphData
    $nodes = @($g.nodes)
    $edges = @($g.edges)
    $byId = @{}
    foreach ($n in $nodes) { if ($n.id) { $byId["$($n.id)"] = $n } }
    # Column of a node on the delegation board -- the reachability LAYER (mirrors
    # the Delegation Map's buildMapModel colOf): admin=0, role-group=1,
    # permission-group=2, target(entra-role/au-role/az-resource)=3. This is what
    # lets us ORIENT a group nesting edge correctly (below).
    $colOf = {
        param($Id)
        $n = $null; if ($byId.ContainsKey("$Id")) { $n = $byId["$Id"] }
        if (-not $n) { return -1 }
        $k = Get-PimNodeField -Node $n -Name 'kind'
        switch ($k) {
            'admin'            { 0 }
            'role-group'       { 1 }
            'permission-group' { 2 }
            'entra-role'       { 3 }
            'au-role'          { 3 }
            'az-resource'      { 3 }
            default            { -1 }
        }
    }
    # Build the NORMALISED reach-edge set. Most edges flow source -> target as
    # emitted (admin->group, group->entra-role/au-role/az-resource). A group
    # NESTING edge (group-to-group) is emitted source=container, target=member,
    # but a MEMBER inherits the CONTAINER's grants -- so reach must flow
    # member -> container. We orient by COLUMN (lower -> higher), exactly like the
    # Delegation Map: a same-column nesting is NOT a reach hop (it would let a
    # parent role group inherit an unrelated nested role group's grants -- the map
    # over-reach bug), so we drop it. Cosmetic edges (au-to-au-role) are excluded.
    $reach = New-Object System.Collections.ArrayList
    foreach ($e in $edges) {
        if ($e.cosmetic -or $e.kind -eq 'au-to-au-role') { continue }
        $s = "$($e.source)"; $t = "$($e.target)"
        if (-not $s -or -not $t) { continue }
        if ($e.kind -eq 'group-to-group') {
            $cs = & $colOf $s; $ct = & $colOf $t
            if ($cs -lt 0 -or $ct -lt 0) { continue }
            if ($cs -eq $ct) { continue }                 # same-column nesting is not a reach hop
            if ($cs -gt $ct) { $s2 = $t; $t = $s; $s = $s2 } # flip so reach flows low-col -> high-col
        }
        # Re-stamp source/target on a shallow copy so the walk reads the oriented
        # form (works whether the edge is a PSCustomObject or an ordered hashtable).
        $re = [ordered]@{}
        if ($e -is [System.Collections.IDictionary]) { foreach ($k in $e.Keys) { $re[$k] = $e[$k] } }
        else { foreach ($p in $e.PSObject.Properties) { $re[$p.Name] = $p.Value } }
        $re['source'] = $s; $re['target'] = $t
        [void]$reach.Add($re)
    }
    $out = @{}
    $incoming = @{}
    foreach ($e in $reach) {
        $s = "$($e['source'])"; $t = "$($e['target'])"
        if (-not $out.ContainsKey($s)) { $out[$s] = New-Object System.Collections.ArrayList }
        [void]$out[$s].Add($e)
        if (-not $incoming.ContainsKey($t)) { $incoming[$t] = New-Object System.Collections.ArrayList }
        [void]$incoming[$t].Add($e)
    }
    return [ordered]@{
        nodes      = $nodes
        edges      = $edges
        byId       = $byId
        outgoing   = $out
        incoming   = $incoming
        tenantId   = $g.tenantId
        tenantName = $g.tenantName
        sourceRoot = $g.sourceRoot
        storageMode = $g.storageMode
    }
}

function Get-PimNodeLabel {
    param($Node, [string]$Id)
    if ($Node) {
        $lbl = $null
        if ($Node -is [System.Collections.IDictionary]) { if ($Node.Contains('label')) { $lbl = $Node['label'] } }
        elseif ($Node.PSObject.Properties['label']) { $lbl = $Node.PSObject.Properties['label'].Value }
        if ("$lbl".Trim()) { return "$lbl" }
    }
    return "$Id"
}

function Get-PimNodeField {
    # Read a field from a node that may be an ordered hashtable OR a PSCustomObject.
    # Returns '' when absent (PS 5.1-safe; never throws on a missing prop).
    param($Node, [string]$Name)
    if (-not $Node) { return '' }
    if ($Node -is [System.Collections.IDictionary]) {
        if ($Node.Contains($Name)) { return "$($Node[$Name])" }
        return ''
    }
    if ($Node.PSObject.Properties[$Name]) { return "$($Node.PSObject.Properties[$Name].Value)" }
    return ''
}

function Get-PimReachableTargets {
    # Forward "who can do what": from a person (UserPrincipalName) walk the live
    # delegation graph (admin -> group(s) -> nested group(s) -> target) and return
    # every reachable target WITH the exact path that grants it. Cycle-safe (a
    # visited set), depth-bounded. Targets = Entra roles, AU-scoped roles, Azure
    # RBAC @ scope. PS 5.1-safe (no ?./??).
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Person, $Model)
    if (-not $Model) { $Model = Get-PimAccessGraphModel }
    $personId = "$Person".Trim()
    $personNode = $null
    if ($Model.byId.ContainsKey($personId)) { $personNode = $Model.byId[$personId] }
    $targets = New-Object System.Collections.ArrayList
    $seen = @{}                 # targetId|pathKey -> already recorded
    $targetKinds = @('entra-role','au-role','az-resource')
    # BFS over outgoing edges. Each queue item carries the running path (the chain
    # of {viaGroup,assignmentType} hops) so the result shows HOW access is granted.
    $queue = New-Object System.Collections.Queue
    $start = [ordered]@{ id = $personId; path = @(); visited = @{ "$personId" = $true } }
    $queue.Enqueue($start)
    $hops = 0
    while ($queue.Count -gt 0 -and $hops -lt 5000) {
        $hops++
        $cur = $queue.Dequeue()
        if (-not $Model.outgoing.ContainsKey($cur.id)) { continue }
        foreach ($e in $Model.outgoing[$cur.id]) {
            $tid = "$($e.target)"
            if (-not $tid) { continue }
            $tnode = $null; if ($Model.byId.ContainsKey($tid)) { $tnode = $Model.byId[$tid] }
            $tkind = Get-PimNodeField -Node $tnode -Name 'kind'
            # Record the hop in the path.
            $hop = [ordered]@{
                via          = $tid
                viaLabel     = (Get-PimNodeLabel -Node $tnode -Id $tid)
                viaKind      = $tkind
                assignment   = "$($e.type)"
                edgeKind     = "$($e.kind)"
                sourceCsv    = "$($e.source_csv)"
            }
            $newPath = @($cur.path) + $hop
            if ($targetKinds -contains $tkind) {
                # A terminal target -- record it with its activation path.
                $pathKey = ($newPath | ForEach-Object { "$($_.via)" }) -join '>'
                $dedupeKey = "$tid|$pathKey"
                if (-not $seen.ContainsKey($dedupeKey)) {
                    $seen[$dedupeKey] = $true
                    [void]$targets.Add([ordered]@{
                        targetId   = $tid
                        targetKind = $tkind
                        label      = (Get-PimNodeLabel -Node $tnode -Id $tid)
                        roleName   = (Get-PimNodeField -Node $tnode -Name 'roleName')
                        auTag      = (Get-PimNodeField -Node $tnode -Name 'auTag')
                        scopePath  = (Get-PimNodeField -Node $tnode -Name 'scopePath')
                        scopeType  = (Get-PimNodeField -Node $tnode -Name 'scopeType')
                        scopeShort = (Get-PimNodeField -Node $tnode -Name 'scopeShort')
                        assignment = "$($e.type)"
                        path       = $newPath
                        pathText   = (($newPath | ForEach-Object { $_.viaLabel }) -join ' -> ')
                    })
                }
            } else {
                # Intermediate node (a group / AU) -- keep walking, cycle-safe.
                if (-not $cur.visited.ContainsKey($tid)) {
                    $nv = @{}; foreach ($k in $cur.visited.Keys) { $nv[$k] = $true }; $nv[$tid] = $true
                    $queue.Enqueue([ordered]@{ id = $tid; path = $newPath; visited = $nv })
                }
            }
        }
    }
    $sorted = @($targets | Sort-Object @{ e = { "$($_.targetKind)" } }, @{ e = { "$($_.label)" } })
    return [ordered]@{
        person      = $personId
        found       = [bool]$personNode
        displayName = (Get-PimNodeLabel -Node $personNode -Id $personId)
        count       = @($sorted).Count
        targets     = @($sorted)
        tenantId    = $Model.tenantId
        tenantName  = $Model.tenantName
        generatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
}

function Get-PimRoleReachers {
    # Reverse "who can activate this": given a role/target (an Entra role name, an
    # AU-scoped role, or an Azure RBAC role @ scope -- by node id OR a role-name
    # match) walk the graph BACKWARDS (incoming edges) to every PERSON who can
    # reach it, with the path. PS 5.1-safe.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Role, $Model, [string]$Kind)
    if (-not $Model) { $Model = Get-PimAccessGraphModel }
    $needle = "$Role".Trim()
    $targetKinds = @('entra-role','au-role','az-resource')
    # Resolve which target node(s) the caller means: exact id, else role-name match.
    $matchTargets = New-Object System.Collections.ArrayList
    foreach ($n in $Model.nodes) {
        $nk = Get-PimNodeField -Node $n -Name 'kind'
        if ($targetKinds -notcontains $nk) { continue }
        $nid = Get-PimNodeField -Node $n -Name 'id'
        if ($Kind -and $Kind -ne $nk) { continue }
        $roleName = Get-PimNodeField -Node $n -Name 'roleName'
        $lbl = Get-PimNodeLabel -Node $n -Id $nid
        if ($nid -eq $needle -or "$roleName" -ieq $needle -or "$lbl" -ieq $needle) {
            [void]$matchTargets.Add($n)
        }
    }
    $reachers = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($tn in $matchTargets) {
        $tid = Get-PimNodeField -Node $tn -Name 'id'
        # Walk incoming edges backwards to find admins that reach this target.
        $queue = New-Object System.Collections.Queue
        $queue.Enqueue([ordered]@{ id = $tid; path = @(); visited = @{ "$tid" = $true } })
        $hops = 0
        while ($queue.Count -gt 0 -and $hops -lt 5000) {
            $hops++
            $cur = $queue.Dequeue()
            if (-not $Model.incoming.ContainsKey($cur.id)) { continue }
            foreach ($e in $Model.incoming[$cur.id]) {
                $sid = "$($e.source)"
                if (-not $sid) { continue }
                $snode = $null; if ($Model.byId.ContainsKey($sid)) { $snode = $Model.byId[$sid] }
                $skind = Get-PimNodeField -Node $snode -Name 'kind'
                $hop = [ordered]@{
                    via        = $sid
                    viaLabel   = (Get-PimNodeLabel -Node $snode -Id $sid)
                    viaKind    = $skind
                    assignment = "$($e.type)"
                    sourceCsv  = "$($e.source_csv)"
                }
                # The full path person->...->target reads source-to-target, so we
                # build the chain in walk order then it already reads person-first.
                $newPath = ,$hop + @($cur.path)
                if ($skind -eq 'admin') {
                    $pathKey = ($newPath | ForEach-Object { "$($_.via)" }) -join '>'
                    $dk = "$tid|$sid|$pathKey"
                    if (-not $seen.ContainsKey($dk)) {
                        $seen[$dk] = $true
                        $purpose = Get-PimNodeField -Node $snode -Name 'purpose'
                        [void]$reachers.Add([ordered]@{
                            person      = $sid
                            displayName = (Get-PimNodeLabel -Node $snode -Id $sid)
                            purpose     = $purpose
                            targetId    = $tid
                            targetLabel = (Get-PimNodeLabel -Node $tn -Id $tid)
                            assignment  = "$($newPath[0].assignment)"
                            path        = $newPath
                            pathText    = (($newPath | ForEach-Object { $_.viaLabel }) -join ' -> ')
                        })
                    }
                } else {
                    if (-not $cur.visited.ContainsKey($sid)) {
                        $nv = @{}; foreach ($k in $cur.visited.Keys) { $nv[$k] = $true }; $nv[$sid] = $true
                        $queue.Enqueue([ordered]@{ id = $sid; path = $newPath; visited = $nv })
                    }
                }
            }
        }
    }
    $sorted = @($reachers | Sort-Object @{ e = { "$($_.displayName)" } })
    return [ordered]@{
        role        = $needle
        resolved    = @($matchTargets).Count
        count       = @($sorted).Count
        reachers    = @($sorted)
        tenantId    = $Model.tenantId
        tenantName  = $Model.tenantName
        generatedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
}

function Get-PimTierImpactReportLive {
    # Thin Manager wrapper over the pure tier-impact core (PIM-TierImpact.ps1):
    # read ONE live delegation model (Build-PimGraphData -- SQL in hosted mode, the
    # desired store otherwise) and compute, for every user, whether they have ANY
    # path (incl. indirect via nested groups) to a Tier-0/Tier-1 target. No logic
    # here -- the engine lib does the reach analysis; this just feeds it the model.
    [CmdletBinding()]
    param([int]$HighTierMax = 1)
    $g = Build-PimGraphData
    return Get-PimTierImpactReport -Data $g -HighTierMax $HighTierMax
}

function Get-PimGlobalSearch {
    # One search box across people / groups / roles / scopes / tags. Matches the
    # live graph-model nodes (the SAME engine/SQL-backed model) by label / id /
    # groupTag / roleName / scopePath / AU tag. Returns typed hits each carrying
    # the "jump" coordinates the GUI uses to open the owning object (map focus +
    # the report it feeds). Case-insensitive substring. PS 5.1-safe.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query, $Model, [int]$Limit = 50)
    if (-not $Model) { $Model = Get-PimAccessGraphModel }
    $q = "$Query".Trim().ToLowerInvariant()
    if (-not $q) {
        return [ordered]@{ query = ''; count = 0; hits = @(); truncated = $false }
    }
    $hits = New-Object System.Collections.ArrayList
    # Map a node kind to the search "type" + the tab the GUI jumps to.
    $typeFor = {
        param($Kind)
        switch ($Kind) {
            'admin'            { @{ type = 'person'; tab = 'map' } }
            'role-group'       { @{ type = 'group';  tab = 'map' } }
            'permission-group' { @{ type = 'group';  tab = 'map' } }
            'au'               { @{ type = 'scope';  tab = 'map' } }
            'entra-role'       { @{ type = 'role';   tab = 'map' } }
            'au-role'          { @{ type = 'role';   tab = 'map' } }
            'az-resource'      { @{ type = 'scope';  tab = 'map' } }
            default            { @{ type = 'other';  tab = 'map' } }
        }
    }
    foreach ($n in $Model.nodes) {
        $nk  = Get-PimNodeField -Node $n -Name 'kind'
        $nid = Get-PimNodeField -Node $n -Name 'id'
        # Collect every searchable field present on this node.
        $fields = New-Object System.Collections.ArrayList
        foreach ($k in 'label','id','groupTag','roleName','scopePath','scopeShort','auTag','description','tier','level','purpose') {
            $v = Get-PimNodeField -Node $n -Name $k
            if ("$v".Trim()) { [void]$fields.Add("$v") }
        }
        $matched = $false
        $matchField = ''
        foreach ($f in $fields) {
            if ("$f".ToLowerInvariant().Contains($q)) { $matched = $true; $matchField = "$f"; break }
        }
        if (-not $matched) { continue }
        $tspec = & $typeFor $nk
        [void]$hits.Add([ordered]@{
            id        = $nid
            type      = $tspec.type
            kind      = $nk
            label     = (Get-PimNodeLabel -Node $n -Id $nid)
            matched   = $matchField
            tab       = $tspec.tab
        })
    }
    # Tags are a derived facet: surface distinct GroupTag / AU tag values that match
    # (so "search by tag" returns the tag itself, not only the objects carrying it).
    $tagSeen = @{}
    foreach ($n in $Model.nodes) {
        foreach ($k in 'groupTag','auTag') {
            $v = Get-PimNodeField -Node $n -Name $k
            if ("$v".Trim() -and "$v".ToLowerInvariant().Contains($q)) {
                $tagId = "tag:$v"
                if (-not $tagSeen.ContainsKey($tagId)) {
                    $tagSeen[$tagId] = $true
                    [void]$hits.Add([ordered]@{ id = $tagId; type = 'tag'; kind = 'tag'; label = "$v"; matched = "$v"; tab = 'map' })
                }
            }
        }
    }
    # Type order: person, group, role, scope, tag, other. Then by label.
    $typeRank = @{ person = 0; group = 1; role = 2; scope = 3; tag = 4; other = 5 }
    $sorted = @($hits | Sort-Object @{ e = { [int]$typeRank["$($_.type)"] } }, @{ e = { "$($_.label)" } })
    $total = @($sorted).Count
    $page = if ($total -gt $Limit) { @($sorted | Select-Object -First $Limit) } else { $sorted }
    return [ordered]@{
        query     = "$Query".Trim()
        count     = $total
        truncated = ($total -gt $Limit)
        hits      = @($page)
    }
}

function Get-PimRoleCatalogNames {
    # The corpus of known role NAMES for typo-tolerant Role-Lookup matching
    # (REQUIREMENTS §28 [H9]). Union of (1) the tenant-list cache's entraRoles
    # display names and (2) every role-name on the live delegation model's target
    # nodes (entra-role / au-role / az-resource). Works even when there is NO live
    # Graph connection -- so a typo always yields "did you mean..." candidates
    # instead of a 503. De-duplicated, case-preserving. PS 5.1-safe (never throws).
    [CmdletBinding()] param($Model)
    $names = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    $add = {
        param($Value)
        $s = "$Value".Trim()
        if (-not $s) { return }
        $lk = $s.ToLowerInvariant()
        if ($seen.ContainsKey($lk)) { return }
        $seen[$lk] = $true
        $names.Add($s)
    }
    # (1) tenant-list cache (the picker's source) -- best-effort.
    try {
        if (Get-Command Read-PimTenantListCache -ErrorAction SilentlyContinue) {
            $lists = Read-PimTenantListCache
            $er = $null
            if ($lists -is [System.Collections.IDictionary]) { if ($lists.Contains('entraRoles')) { $er = $lists['entraRoles'] } }
            elseif ($lists -and $lists.PSObject.Properties['entraRoles']) { $er = $lists.PSObject.Properties['entraRoles'].Value }
            if ($er) {
                $items = $null
                if ($er -is [System.Collections.IDictionary]) { if ($er.Contains('items')) { $items = $er['items'] } }
                elseif ($er.PSObject.Properties['items']) { $items = $er.PSObject.Properties['items'].Value }
                foreach ($it in @($items)) {
                    if ($it -is [string]) { & $add $it }
                    else {
                        $dn = Get-PimNodeField -Node $it -Name 'displayName'
                        if (-not "$dn".Trim()) { $dn = Get-PimNodeField -Node $it -Name 'name' }
                        & $add $dn
                    }
                }
            }
        }
    } catch { }
    # (2) live delegation-model target nodes.
    try {
        if (-not $Model) { $Model = Get-PimAccessGraphModel }
        foreach ($n in @($Model.nodes)) {
            $nk = Get-PimNodeField -Node $n -Name 'kind'
            if ('entra-role','au-role','az-resource' -notcontains $nk) { continue }
            $rn = Get-PimNodeField -Node $n -Name 'roleName'
            if (-not "$rn".Trim()) { $rn = Get-PimNodeLabel -Node $n -Id (Get-PimNodeField -Node $n -Name 'id') }
            & $add $rn
        }
    } catch { }
    return @($names.ToArray())
}

# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

function Get-FreeTcpPort {
    $l = New-Object System.Net.Sockets.TcpListener ([System.Net.IPAddress]::Loopback), 0
    $l.Start()
    $p = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port
    $l.Stop()
    return $p
}

# ---------------------------------------------------------------------------
# Fast JSON serializer. PS 5.1's ConvertTo-Json needs ~10s for a 300KB
# payload (measured on the /api/preflight report) and the server is
# single-threaded -- every second spent serializing blocks ALL other
# requests, and queued requests die with 'specified network name is no
# longer available'. JavaScriptSerializer does the same payload in <0.5s.
# ---------------------------------------------------------------------------

# Compiled normalizer + serializer -- Windows PowerShell 5.1 ONLY. 5.1's
# ConvertTo-Json needs seconds for 300-400KB payloads, so we compile a C#
# walk + JavaScriptSerializer (System.Web.Extensions). Both are .NET
# Framework-only: on PowerShell 7 the Add-Type fails with CS0012 (mscorlib
# not referenced) -- and pwsh's built-in ConvertTo-Json is already fast, so
# ConvertTo-PimJson simply falls back to it there.
$script:PimUseCompiledJson = ($PSVersionTable.PSEdition -eq 'Desktop')
if ($script:PimUseCompiledJson) {
Add-Type -AssemblyName System.Web.Extensions -ErrorAction SilentlyContinue

if (-not ('PimManager.Json' -as [type])) {
    Add-Type -ReferencedAssemblies @('System.Web.Extensions', [System.Management.Automation.PSObject].Assembly.Location) -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation;
using System.Web.Script.Serialization;

namespace PimManager {
    public static class Json {
        public static string Serialize(object value) {
            var ser = new JavaScriptSerializer();
            ser.MaxJsonLength = 268435456;
            ser.RecursionLimit = 64;
            return ser.Serialize(Normalize(value, 0));
        }
        public static object Normalize(object value, int depth) {
            if (value == null || depth > 24) return null;
            var pso = value as PSObject;
            if (pso != null) {
                var baseObj = pso.BaseObject;
                if (baseObj is PSCustomObject) {
                    var d = new Dictionary<string, object>();
                    foreach (var p in pso.Properties) {
                        object pv;
                        try { pv = p.Value; } catch { pv = null; }
                        d[p.Name] = Normalize(pv, depth + 1);
                    }
                    return d;
                }
                return Normalize(baseObj, depth);
            }
            if (value is string || value is bool || value is int || value is long ||
                value is double || value is decimal || value is float ||
                value is byte || value is short || value is uint || value is ulong || value is ushort) return value;
            if (value is DateTime) return ((DateTime)value).ToUniversalTime().ToString("o");
            if (value is Guid || value is Uri || value is char || value is TimeSpan || value.GetType().IsEnum) return value.ToString();
            var dict = value as IDictionary;
            if (dict != null) {
                var d = new Dictionary<string, object>();
                foreach (DictionaryEntry e in dict) d[Convert.ToString(e.Key)] = Normalize(e.Value, depth + 1);
                return d;
            }
            var en = value as IEnumerable;
            if (en != null) {
                var list = new List<object>();
                foreach (var item in en) list.Add(Normalize(item, depth + 1));
                return list;
            }
            // Arbitrary .NET object (e.g. PSCustomObject reached without PSObject
            // wrapper): walk its PSObject properties via a fresh wrap.
            var wrapped = PSObject.AsPSObject(value);
            var dd = new Dictionary<string, object>();
            foreach (var p in wrapped.Properties) {
                object pv;
                try { pv = p.Value; } catch { pv = null; }
                dd[p.Name] = Normalize(pv, depth + 1);
            }
            if (dd.Count > 0) return dd;
            return value.ToString();
        }
    }
}
'@ -ErrorAction Stop
}
}

function ConvertTo-PimJson {
    param([Parameter(Mandatory)][AllowNull()][object]$Body)
    if ($script:PimUseCompiledJson -and ('PimManager.Json' -as [type])) {
        try {
            return [PimManager.Json]::Serialize($Body)
        } catch { }
    }
    # PowerShell 7 (fast native ConvertTo-Json), or 5.1 compile/serialize failure.
    return ($Body | ConvertTo-Json -Depth 12 -Compress)
}

function Write-JsonResponse {
    param(
        [Parameter(Mandatory)][System.Net.HttpListenerResponse]$Response,
        [Parameter(Mandatory)][int]$Status,
        [Parameter(Mandatory)][object]$Body
    )
    $json = ConvertTo-PimJson -Body $Body
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    # Client-abort tolerance: a browser that gave up (tab closed, fetch
    # timeout) makes OutputStream.Write throw. Swallow + log instead of
    # cascading into a second Write-JsonResponse call on the same response
    # ('This operation cannot be performed after the response has been
    # submitted').
    try {
        $Response.StatusCode = $Status
        $Response.ContentType = 'application/json; charset=utf-8'
        $Response.ContentLength64 = $bytes.LongLength
        $Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $Response.OutputStream.Close()
    } catch {
        Write-Host ("  [net] client gone before response could be written ({0} bytes, status {1}): {2}" -f $bytes.Length, $Status, $_.Exception.Message) -ForegroundColor DarkGray
    }
}

# Governance-preview server-side guard. The two security-sensitive governance
# surfaces are OFF BY DEFAULT (pim.Settings 'GovernancePreview'); while a surface
# is in preview-disabled state, its MUTATING endpoints must SHORT-CIRCUIT (do
# nothing, return a 409 "preview disabled" marker) so the GUI-disabled state ==
# actual behaviour. This is a belt-and-braces backstop in case a request reaches a
# mutating endpoint despite the GUI banner. Returns $true (and writes the response)
# when the call is blocked; $false when the surface is enabled and may proceed.
function Test-PimGovernancePreviewBlocked {
    param(
        [Parameter(Mandatory)][System.Net.HttpListenerResponse]$Response,
        [Parameter(Mandatory)][ValidateSet('approvalsPreview','conformancePreview')][string]$FlagId,
        [string]$Surface = ''
    )
    if (-not (Get-Command Resolve-PimGovernancePreview -ErrorAction SilentlyContinue)) { return $false }
    $prev = $null
    try { $prev = Get-PimGovernancePreview } catch { return $false }
    if (Test-PimGovernancePreviewEnabled -Resolved $prev -Id $FlagId) { return $false }   # enabled -> proceed
    $what = if ($Surface) { $Surface } else { $FlagId }
    Write-JsonResponse -Response $Response -Status 409 -Body ([ordered]@{
        ok = $false; previewDisabled = $true; flag = $FlagId
        error = "This governance surface ($what) is in PREVIEW and is disabled by default. No action was taken. Enable it under Settings -> Governance preview to use it."
    })
    return $true
}

function Write-HtmlResponse {
    param(
        [Parameter(Mandatory)][System.Net.HttpListenerResponse]$Response,
        [Parameter(Mandatory)][string]$Html
    )
    try {
        $Response.StatusCode = 200
        $Response.ContentType = 'text/html; charset=utf-8'
        # The Manager is a single-page app whose menus/JS are inline in this HTML
        # shell. Without an explicit no-cache directive the browser (and any proxy)
        # caches the shell, so after a deploy users keep seeing the OLD menus until
        # a hard refresh. Force a revalidate so every load gets the deployed build.
        try {
            $Response.Headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            $Response.Headers['Pragma'] = 'no-cache'
            $Response.Headers['Expires'] = '0'
        } catch { Write-Verbose "could not set no-cache headers: $($_.Exception.Message)" }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Html)
        $Response.ContentLength64 = $bytes.LongLength
        $Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $Response.OutputStream.Close()
    } catch {
        Write-Host ("  [net] client gone before HTML response could be written: {0}" -f $_.Exception.Message) -ForegroundColor DarkGray
    }
}

function Read-RequestJson {
    param([Parameter(Mandatory)][System.Net.HttpListenerRequest]$Request)
    if (-not $Request.HasEntityBody) { return $null }
    $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
    try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return ($text | ConvertFrom-Json)
}

function ConvertTo-OrderedRow {
    # Accepts a PSCustomObject (from ConvertFrom-Json) and returns an ordered hashtable.
    param([Parameter(Mandatory)][AllowNull()][object]$Row)
    if ($null -eq $Row) { return $null }
    $d = [ordered]@{}
    if ($Row -is [System.Collections.IDictionary]) {
        foreach ($k in $Row.Keys) { $d[$k] = "$($Row[$k])" }
    } else {
        foreach ($p in $Row.PSObject.Properties) { $d[$p.Name] = "$($p.Value)" }
    }
    return $d
}

# ---------------------------------------------------------------------------
# v2.4.2 Revoke tab -- bulk-revoke of active PIM assignments.
#
# §70.1b option 2 (2026-09-13): the tenant-connection helper, the principal / role / AU lookup caches
# (Initialize-PimManagerTenantConnection, Get-PimManagerLookupCaches, Resolve-PimManager*) and the live
# active-assignments read now live in engine/_shared/PIM-ActiveAssignments.ps1, dot-sourced next to
# _tenantSync.ps1 below. The live read (Invoke-PimActiveAssignmentsSnapshot) runs ONLY in the scheduler, as
# job 'active-assignments-snapshot'; this process reads the stored snapshot (Get-PimActiveAssignmentsCached).
# ---------------------------------------------------------------------------

function Initialize-PimManagerTenantCache {
    # Auto-populate the per-instance tenant-list cache (entra-roles, AUs,
    # PIM groups, azure scopes, azure RBAC roles) when it is empty/stale, so the
    # role-name freshness badge + the autocomplete pickers work in HOSTED mode
    # WITHOUT a manual -RefreshTenantLists run (the container has no operator to
    # run that). Best-effort + non-fatal: if there is no usable tenant auth, or
    # Graph/ARM is unreachable, the Manager still serves the SQL data; the badge
    # just shows "skipped" until auth/permissions are fixed. Driven from startup
    # (hosted) and lazily on first /api/tenant-lists when the cache is missing.
    param([switch]$Force, [int]$MaxAgeHours = 24)
    if (-not (Get-Command Invoke-PimTenantListRefresh -ErrorAction SilentlyContinue)) { return $false }
    if (-not (Get-Command Assert-PimTenantConnectionContext -ErrorAction SilentlyContinue)) { return $false }

    if (-not $Force) {
        # Skip when entra-roles is present AND fresh (the canonical freshness signal).
        try {
            $lists = Read-PimTenantListCache
            $er = $lists.entraRoles
            if ($er -and @($er.items).Count -gt 0 -and "$($er.refreshedUtc)".Trim()) {
                $ageH = ([datetime]::UtcNow - ([datetime]$er.refreshedUtc).ToUniversalTime()).TotalHours
                if ($ageH -lt $MaxAgeHours) { return $true }   # already fresh
            }
        } catch { }
    }

    # Verify auth context is even possible before attempting -- avoids a noisy
    # throw on every startup when the container has no SPN/MI configured yet.
    try { [void](Assert-PimTenantConnectionContext) }
    catch {
        Write-Host ("  [tenant-cache] not populated -- no tenant auth context: {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
        return $false
    }
    try {
        Write-Host "  [tenant-cache] populating (hosted auto-refresh) ..." -ForegroundColor Cyan
        $r = Invoke-PimTenantListRefresh -Quiet
        if ($r.ok) { Write-Host "  [tenant-cache] populated." -ForegroundColor Green; return $true }
        Write-Host ("  [tenant-cache] refresh did not complete: {0}" -f ($r.reason | Out-String).Trim()) -ForegroundColor DarkYellow
        return $false
    } catch {
        Write-Host ("  [tenant-cache] refresh failed (non-fatal): {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
        return $false
    }
}

function Get-PimActiveAssignmentsSnapshotCadenceMinutes {
    # The EFFECTIVE cadence of job 'active-assignments-snapshot' (the Jobs page can change it), for the "as of /
    # refreshes every N min" text. A store read of the schedule setting; never Graph. Falls back to the default.
    $cad = 0
    try {
        $j = @(Get-PimManagerEffectiveSchedule | Where-Object { "$($_.type)" -eq 'active-assignments-snapshot' }) | Select-Object -First 1
        if ($j -and [int]$j.intervalMinutes -gt 0) { $cad = [int]$j.intervalMinutes }
    } catch { }
    return $cad
}

function Get-PimActiveAssignmentsCached {
    # 🔴 §70.1b option 2 (2026-09-13) -- THIS NO LONGER READS THE TENANT. IT READS THE SCHEDULER'S SNAPSHOT.
    # It used to run the live Entra-role / Azure-RBAC / PIM-for-Groups read on the Manager's ONE request loop:
    # 140-170 s on internal, during which every other user waited ("Jobs / Engine runs pages take forever").
    # A 5-minute in-process cache only moved the freeze to whoever arrived after it expired.
    # 🔒 The read now runs ONLY in the scheduler (job 'active-assignments-snapshot', default every 120 min,
    # editable on the Jobs page) and lands in SQL pim.TenantCache kind 'active-assignments'. This function reads
    # that row and nothing else -- no Graph, no ARM, no lookup caches, no compute. Operator, 2026-09-13: a delay
    # of a few hours is acceptable; the Manager must never compute it inline.
    # -QueueRefresh (Refresh button / ?refresh=1) and a MISSING snapshot queue a trigger for the scheduler and
    # return straight away with refreshQueued=$true; the page never waits for the read.
    # Response keeps ok / rows / loadedUtc / counts / surfaceErrors / cacheHit and adds refreshedUtc, ageSeconds,
    # cadenceMinutes, stale, snapshotMissing, refreshQueued, hint.
    param([switch]$QueueRefresh, [string]$Reason = 'manager', [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Get-Command ConvertTo-PimActiveAssignmentsSnapshotView -ErrorAction SilentlyContinue)) {
        throw 'engine/_shared/PIM-ActiveAssignments.ps1 is not loaded -- the active-assignments snapshot cannot be read.'
    }
    $entry = $null
    if (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue) {
        $entry = Get-PimTenantCacheEntry -Kind 'active-assignments'
    }
    $queued = $false; $qErr = ''
    if ($QueueRefresh -or $null -eq $entry) {
        $why = if ($null -eq $entry -and -not $QueueRefresh) { "$Reason`:snapshot-missing" } else { $Reason }
        $q = Request-PimActiveAssignmentsSnapshotRefresh -Reason $why
        $queued = [bool]$q.queued; $qErr = "$($q.error)"
    }
    return (ConvertTo-PimActiveAssignmentsSnapshotView -Entry $entry -NowUtc $NowUtc `
                -CadenceMinutes (Get-PimActiveAssignmentsSnapshotCadenceMinutes) -RefreshQueued $queued -QueueError $qErr)
}

function Get-PimDriftSnapshotCadenceMinutes {
    # The EFFECTIVE cadence of job 'drift-snapshot' (editable on the Jobs page) for "checked every N min". Store read only.
    $cad = 0
    try {
        $j = @(Get-PimManagerEffectiveSchedule | Where-Object { "$($_.type)" -eq 'drift-snapshot' }) | Select-Object -First 1
        if ($j -and [int]$j.intervalMinutes -gt 0) { $cad = [int]$j.intervalMinutes }
    } catch { }
    return $cad
}

function Get-PimDriftCached {
    # 🔴 Drift page (operator, 2026-09-14). GET /api/drift used to run Invoke-PimEngine -Scope All -Mode Full -Prune -WhatIf
    # on this process's ONE request loop -- minutes during which every page froze for every user.
    # 🔒 The plan now runs ONLY in the scheduler (job 'drift-snapshot', default every 240 min) and lands in SQL
    # pim.TenantCache kind 'drift'. This reads that row and nothing else. -QueueRefresh queues a trigger and returns at once.
    param([switch]$QueueRefresh, [string]$Reason = 'manager', [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Get-Command ConvertTo-PimDriftSnapshotView -ErrorAction SilentlyContinue)) {
        throw 'engine/_shared/PIM-DriftSnapshot.ps1 is not loaded -- the drift snapshot cannot be read.'
    }
    $entry = $null
    if (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue) { $entry = Get-PimTenantCacheEntry -Kind 'drift' }
    $queued = $false; $qErr = ''
    if ($QueueRefresh) {
        $q = Request-PimDriftSnapshotRefresh -Reason $Reason
        $queued = [bool]$q.queued; $qErr = "$($q.error)"
    }
    return (ConvertTo-PimDriftSnapshotView -Entry $entry -NowUtc $NowUtc -CadenceMinutes (Get-PimDriftSnapshotCadenceMinutes) -RefreshQueued $queued -QueueError $qErr)
}

# ---------------------------------------------------------------------------
# Maintenance bulk-revoke SAFETY NET (interim, incident-driven). The Revoke
# tab can select-all and fire adminRemove against EVERY active assignment with
# nothing but a justification + one confirm. That has no what-if, writes no
# audit, and can revoke break-glass/emergency accounts -- the exact opposite of
# what those accounts are for. This minimal guard (NOT the full approval flow,
# which is a recorded requirement) mirrors the engine circuit-breaker for the
# revoke surface:
#   (a) every revoke is audited (who/what/when/justification) -- handled in the
#       /api/revoke handler via Write-PimManagerAuditEvent;
#   (b) break-glass / emergency accounts are EXCLUDED (skipped + reported);
#   (c) batches over a small threshold require an explicit count-confirmation;
#   (d) a what-if/preview lists exactly what will be revoked before commit.
# (b)/(c)/(d) are computed by the PURE helper below so they are unit-testable
# offline (no tenant, no HTTP).
# ---------------------------------------------------------------------------

# Break-glass / emergency principals to NEVER auto-revoke. Identifiers may be
# UPNs and/or object (principal) ids; matching is case-insensitive. Sourced from
# $global:PIM_BreakGlassAccounts (string[] or ';'/',' separated string). Returns
# a lowercase string[] (possibly empty).
function Get-PimBreakGlassIdentifiers {
    $raw = $global:PIM_BreakGlassAccounts
    if (-not $raw -and "$env:PIM_BREAKGLASS_ACCOUNTS") { $raw = "$env:PIM_BREAKGLASS_ACCOUNTS" }
    if (-not $raw) { return @() }
    $list = if ($raw -is [string]) { $raw -split '[;,]' } else { @($raw) }
    return @($list | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
}

# Decide whether a single revoke row targets a protected break-glass principal.
# Matches the row's principalId (object id) OR principal label (UPN) against the
# configured identifier set, case-insensitively.
function Test-PimRowIsBreakGlass {
    param([Parameter(Mandatory)]$Row, [string[]]$Identifiers)
    if (-not $Identifiers -or $Identifiers.Count -eq 0) { return $false }
    $cand = @()
    foreach ($k in 'principalId','principal','principalUpn','principalName') {
        $p = $Row.PSObject.Properties[$k]
        if ($p -and "$($p.Value)".Trim()) { $cand += "$($p.Value)".Trim().ToLowerInvariant() }
    }
    foreach ($c in $cand) { if ($Identifiers -contains $c) { return $true } }
    return $false
}

# Pure what-if planner for a bulk revoke. Splits the requested rows into
# {toRevoke, skipped(break-glass)}, and reports whether an explicit
# count-confirmation is required (batch over the threshold) and whether the
# supplied -ConfirmCount satisfies it. No side effects -- safe to call for the
# /api/revoke preview AND as the pre-commit gate.
function Get-PimRevokeGuardPlan {
    param(
        [object[]]$Rows = @(),
        [int]$ConfirmThreshold = 5,
        [Nullable[int]]$ConfirmCount = $null
    )
    if ($ConfirmThreshold -lt 1) { $ConfirmThreshold = 1 }
    $bg = Get-PimBreakGlassIdentifiers
    $toRevoke = New-Object System.Collections.ArrayList
    $skipped  = New-Object System.Collections.ArrayList
    foreach ($r in $Rows) {
        if (-not $r) { continue }
        if (Test-PimRowIsBreakGlass -Row $r -Identifiers $bg) {
            [void]$skipped.Add([ordered]@{
                id        = "$($r.id)"
                principal = "$($r.principal)"
                type      = "$($r.type)"
                reason    = 'break-glass account (protected)'
            })
        } else {
            [void]$toRevoke.Add($r)
        }
    }
    $count = $toRevoke.Count
    $confirmRequired = ($count -gt $ConfirmThreshold)
    # Confirmation is satisfied only when the caller echoes the EXACT to-revoke
    # count (after break-glass exclusion). $null = not supplied.
    $confirmSatisfied = if (-not $confirmRequired) { $true }
                        elseif ($null -eq $ConfirmCount) { $false }
                        else { [int]$ConfirmCount -eq $count }
    return [ordered]@{
        total            = @($Rows | Where-Object { $_ }).Count
        toRevoke         = $toRevoke.ToArray()
        toRevokeCount    = $count
        skipped          = $skipped.ToArray()
        skippedCount     = $skipped.Count
        confirmThreshold = $ConfirmThreshold
        confirmRequired  = $confirmRequired
        confirmSatisfied = $confirmSatisfied
    }
}

# ---------------------------------------------------------------------------
# READABLE QUEUE NAMES FOR OLD ENTRIES (2026-09-12, "need real names").
# Entries queued before names were stored carry only ids. /api/queue resolves those ids here:
#   1. a short per-process cache (10 min), then the Manager's tenant lookup caches
#      (users / groups / Entra role definitions / BUG-98's by-id resolver);
#   2. whatever is still unknown goes to Graph in ONE $batch request for the WHOLE queue read --
#      /directoryObjects/getByIds for principals + groups, and the role-definition list for
#      Entra roles. Never one call per row (section 67 N+1).
#   3. a failed lookup is remembered for 60 s so a broken Graph path cannot slow every queue read,
#      and the entry says "(name not found)" instead of pretending.
# $script:PimQueueGraphBatch is the single seam to Graph, so a test can inject a fake.
# ---------------------------------------------------------------------------
$script:PimQueueNameCache = @{}
$script:PimQueueNameLookupFailedUtc = $null
$script:PimQueueGraphBatch = {
    param([object[]]$Requests)
    Invoke-PimGraph -Method POST -Path 'https://graph.microsoft.com/v1.0/$batch' -Body @{ requests = @($Requests) }
}

function Get-PimQueueDisplayNameMap {
    param([object[]]$Entries = @())
    $names = @{}
    if (-not (Get-Command Get-PimQueueEntryLookupIds -ErrorAction SilentlyContinue)) { return $names }
    $objIds = New-Object System.Collections.Generic.HashSet[string]
    $roleIds = New-Object System.Collections.Generic.HashSet[string]
    foreach ($e in @($Entries)) {
        if (-not $e) { continue }
        try {
            $need = Get-PimQueueEntryLookupIds -Entry $e
            foreach ($i in @($need.objects)) { if ("$i".Trim()) { [void]$objIds.Add("$i") } }
            foreach ($i in @($need.roles))   { if ("$i".Trim()) { [void]$roleIds.Add("$i") } }
        } catch { }
    }
    if (($objIds.Count + $roleIds.Count) -eq 0) { return $names }

    $now = [datetime]::UtcNow
    $missObj = New-Object System.Collections.Generic.List[string]
    $missRole = New-Object System.Collections.Generic.List[string]
    foreach ($id in $objIds) {
        $c = $script:PimQueueNameCache[$id]
        if ($c -and ($now - $c.at).TotalMinutes -lt 10) { $names[$id] = $c.name; continue }
        $n = ''
        if ($script:PimManager_UserById -and $script:PimManager_UserById.ContainsKey($id)) {
            $u = $script:PimManager_UserById[$id]; $n = Format-PimQueuePrincipalName -DisplayName "$($u.DisplayName)" -Upn "$($u.UserPrincipalName)"
        } elseif ($script:PimManager_GroupById -and $script:PimManager_GroupById.ContainsKey($id)) {
            $n = "$($script:PimManager_GroupById[$id].DisplayName)"
        } elseif ($script:PimManager_ResolvedById -and $script:PimManager_ResolvedById.ContainsKey($id) -and "$($script:PimManager_ResolvedById[$id].kind)" -ne 'deleted') {
            $n = "$($script:PimManager_ResolvedById[$id].label)"
        }
        if ($n) { $names[$id] = $n; $script:PimQueueNameCache[$id] = @{ name = $n; at = $now } } else { $missObj.Add($id) }
    }
    foreach ($id in $roleIds) {
        $c = $script:PimQueueNameCache[$id]
        if ($c -and ($now - $c.at).TotalMinutes -lt 10) { $names[$id] = $c.name; continue }
        $n = ''
        if ($script:PimManager_RoleById -and $script:PimManager_RoleById.ContainsKey($id)) { $n = "$($script:PimManager_RoleById[$id].DisplayName)" }
        if ($n) { $names[$id] = $n; $script:PimQueueNameCache[$id] = @{ name = $n; at = $now } } else { $missRole.Add($id) }
    }
    if (($missObj.Count + $missRole.Count) -eq 0) { return $names }
    if ($script:PimQueueNameLookupFailedUtc -and ($now - $script:PimQueueNameLookupFailedUtc).TotalSeconds -lt 60) { return $names }

    $requests = New-Object System.Collections.Generic.List[object]
    if ($missObj.Count) {
        $requests.Add(@{ id = 'objects'; method = 'POST'; url = '/directoryObjects/getByIds'
            headers = @{ 'Content-Type' = 'application/json' }
            body = @{ ids = @($missObj | Select-Object -First 1000); types = @('user', 'group', 'servicePrincipal') } })
    }
    if ($missRole.Count) {
        $requests.Add(@{ id = 'roles'; method = 'GET'; url = '/roleManagement/directory/roleDefinitions?$select=id,displayName' })
    }
    try {
        $resp = & $script:PimQueueGraphBatch @($requests.ToArray())
        foreach ($sub in @($resp.responses)) {
            if (-not $sub -or [int]"$($sub.status)" -ge 300) { continue }
            foreach ($o in @($sub.body.value)) {
                if (-not $o -or -not $o.id) { continue }
                $oid = "$($o.id)"
                $label = if ("$($sub.id)" -eq 'roles') { "$($o.displayName)" } else { Format-PimQueuePrincipalName -DisplayName "$($o.displayName)" -Upn "$($o.userPrincipalName)" }
                if (-not $label) { continue }
                if ($objIds.Contains($oid) -or $roleIds.Contains($oid)) {
                    $names[$oid] = $label
                    $script:PimQueueNameCache[$oid] = @{ name = $label; at = $now }
                }
            }
        }
    } catch {
        $script:PimQueueNameLookupFailedUtc = $now
        Write-Host ("  [queue] name lookup failed ({0}) -- unresolved entries show their id with '(name not found)'." -f $_.Exception.Message) -ForegroundColor DarkYellow
    }
    return $names
}

function Invoke-PimActiveAssignmentRevokeBatch {
    # 🔒 §65 -- THE MANAGER NO LONGER REVOKES. IT ENQUEUES, AND THE ENGINE REVOKES.
    #
    # Operator, 2026-09-12: *"remember to reduce the pim manager permissions to read only"* /
    # *"as the engine/queue must do the actual change"*. This function used to issue three
    # different directory writes itself (Graph adminRemove for entra-role, an ARM PUT for
    # azure-rbac, Graph adminRemove for pim-for-groups). All three now become ACTION entries on
    # pim.ChangeQueue; engine/_shared/PIM-QueueActions.ps1 applies them with the engine's identity,
    # verifies the effect, and retries what fails (§65.8).
    #
    # 🔑 THE RETURN SHAPE IS UNCHANGED -- an array of { id; ok; error? } in the SAME ORDER as
    # $Rows -- so the caller's audit loop and the break-glass accounting keep working. What changed
    # is the MEANING of ok: it now means "accepted onto the queue", not "removed from the
    # directory", and each result carries queued=$true + the queue id so the caller can say so
    # rather than claiming a revoke that has not happened yet.
    #
    # 🪤 SECURITY SEMANTICS CHANGED, DELIBERATELY (§65.0): a revoke is no longer immediate -- it
    # applies when an operator COMMITS the entry and the next engine tick drains it. That was the
    # operator's decision, and it is recorded rather than buried here.
    param(
        [Parameter(Mandatory)][object[]]$Rows,
        [Parameter(Mandatory)][string]$Justification,
        # Who asked. Carried onto the queue entry so the review surface can say who did it (§65.7).
        [string]$By = ''
    )

    $results = New-Object System.Collections.ArrayList

    # 🔴 NO STORE, NO QUEUE, NO SILENT FALLBACK. Refusing loudly is the whole point: quietly
    # reverting to a direct Graph write would re-create exactly the privilege this change removes,
    # and it would do it invisibly. Every row is failed with the same reason so the caller reports
    # it per row instead of throwing away the batch.
    $cs = (Get-PimManagerStoreCs)
    if (-not $cs -or -not (Get-Command Add-PimSqlQueueChange -ErrorAction SilentlyContinue)) {
        foreach ($r in $Rows) {
            [void]$results.Add([ordered]@{ id = $(if ($r -and $r.id) { [string]$r.id } else { $null }); ok = $false
                error = 'no SQL store is wired in this host, so the revoke cannot be queued -- and the Manager is not permitted to change the directory itself. Configure the store, then retry.' })
        }
        return $results.ToArray()
    }

    $who = if ("$By".Trim()) { "$By" } else { "$(Get-PimManagerActor)" }

    foreach ($r in $Rows) {
        if (-not $r) {
            [void]$results.Add([ordered]@{ id = $null; ok = $false; error = 'null row' })
            continue
        }
        $rowId = if ($r.id) { [string]$r.id } else { '' }
        $type  = if ($r.type) { [string]$r.type } else { '' }
        try {
            # Each branch builds the payload the engine's applier expects. The mapping from the
            # GUI's row type to the queue's action type is explicit and total -- an unknown type
            # throws here rather than enqueuing something no applier serves, which is BUG-134's
            # lesson applied to this seam.
            $payload = $null
            $actionType = ''
            # ACTIVE vs ELIGIBLE (68.6 row 27 a): the engine's queue action removes an ELIGIBLE assignment
            # when the payload says assignmentType='Eligible' (PIM-QueueActions.ps1 Invoke-PimQueueEligibleRevoke);
            # absent = active, exactly as before. The value comes from the row being revoked.
            $rowAssignType = "$($r.assignmentType)".Trim()
            if (-not $rowAssignType -and "$($r.memberType)".Trim()) { $rowAssignType = "$($r.memberType)".Trim() }
            $isEligible = ($rowAssignType -ieq 'Eligible' -or $rowAssignType -ieq 'Eligibility')
            switch ($type) {
                'entra-role' {
                    # Trim a possible roleDefinitions/<guid> prefix that the original schedule
                    # object carries -- the request expects the bare GUID.
                    $roleDefId = [string]$r.roleDefinitionId
                    if ($roleDefId -and $roleDefId.Contains('/')) {
                        $roleDefId = $roleDefId.Substring($roleDefId.LastIndexOf('/') + 1)
                    }
                    $actionType = 'entra-role-revoke'
                    $payload = [ordered]@{
                        type             = $actionType
                        principalId      = [string]$r.principalId
                        roleDefinitionId = $roleDefId
                        directoryScopeId = $(if ($r.directoryScopeId) { [string]$r.directoryScopeId } else { '/' })
                        principal        = "$($r.principal)"
                    }
                }
                'azure-rbac' {
                    $scope = "$($r.scope)".TrimEnd('/')
                    if ($isEligible) {
                        # An ELIGIBLE Azure assignment has no role-assignment resource id to delete: the engine
                        # issues an AdminRemove eligibility request addressed by principal + roleDefinitionId +
                        # scope. Requiring roleAssignmentId here is what made every eligible Azure row THROW
                        # before it was queued.
                        if (-not "$($r.roleDefinitionId)".Trim() -or -not $scope) { throw "eligible azure-rbac row needs roleDefinitionId and scope -- cannot address the eligibility to remove" }
                        $actionType = 'azure-rbac-revoke'
                        $payload = [ordered]@{
                            type             = $actionType
                            principalId      = [string]$r.principalId
                            roleDefinitionId = "$($r.roleDefinitionId)".Trim()
                            scope            = $scope
                            principal        = "$($r.principal)"
                        }
                        break
                    }
                    # ACTIVE: the engine deletes by the assignment's own resource id, so resolve it here
                    # where the row still has both halves.
                    $raId  = "$($r.roleAssignmentId)".Trim()
                    if (-not $raId -and $scope -and "$($r.roleAssignmentName)".Trim()) {
                        $raId = "$scope/providers/Microsoft.Authorization/roleAssignments/$($r.roleAssignmentName)"
                    }
                    if (-not $raId) { throw "azure-rbac row has neither roleAssignmentId nor scope+roleAssignmentName -- cannot address the assignment to remove" }
                    $actionType = 'azure-rbac-revoke'
                    $payload = [ordered]@{
                        type             = $actionType
                        roleAssignmentId = $raId
                        principalId      = [string]$r.principalId
                        scope            = $scope
                        principal        = "$($r.principal)"
                    }
                    if ("$($r.roleDefinitionId)".Trim()) { $payload['roleDefinitionId'] = "$($r.roleDefinitionId)".Trim() }
                }
                'pim-for-groups' {
                    $actionType = 'group-assignment-revoke'
                    $payload = [ordered]@{
                        type        = $actionType
                        principalId = [string]$r.principalId
                        groupId     = [string]$r.groupId
                        accessId    = $(if ($r.accessId) { [string]$r.accessId } else { 'member' })
                        principal   = "$($r.principal)"
                    }
                }
                default {
                    throw "unknown row type: '$type' (expected entra-role | azure-rbac | pim-for-groups)"
                }
            }

            # READABLE NAMES for the review surface (operator, 2026-09-12: "need real names" -- the
            # queue showed only '<guid>|pim-for-groups|<guid>'). Taken from the row the GUI already
            # sent plus the Manager's user cache; NEVER a blocking lookup -- a failure here stores what
            # we have and the read side resolves the rest by id.
            try {
                $pdn = ''; $pupn = ''
                $prinId = [string]$r.principalId
                if ($prinId -and $script:PimManager_UserById -and $script:PimManager_UserById.ContainsKey($prinId)) {
                    $cu = $script:PimManager_UserById[$prinId]; $pdn = "$($cu.DisplayName)"; $pupn = "$($cu.UserPrincipalName)"
                }
                if (Get-Command New-PimQueueActionNames -ErrorAction SilentlyContinue) {
                    $nm = New-PimQueueActionNames -Row $r -ActionType $actionType -PrincipalDisplayName $pdn -PrincipalUpn $pupn
                    foreach ($nk in @($nm.Keys)) { $payload[$nk] = $nm[$nk] }
                }
            } catch { Write-Host ("  [revoke] readable names not captured (queued with ids only): {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow }
            # The engine selects the ACTIVE or ELIGIBLE removal from this field -- set it from the row
            # AFTER the names merge so nothing can blank it.
            $payload['assignmentType'] = $(if ($isEligible) { 'Eligible' } elseif ($rowAssignType) { $rowAssignType } else { 'Active' })

            # Entity/key are the queue's natural addressing. The key identifies WHAT is being
            # revoked so two operators queuing the same revoke are visibly the same target.
            $key = "$($payload.principalId)|$type|$(if ($payload.roleAssignmentId) { $payload.roleAssignmentId } elseif ($payload.roleDefinitionId) { $payload.roleDefinitionId } else { $payload.groupId })"
            if ($isEligible) { $key += "|eligible$(if ($payload.scope) { '|' + $payload.scope })" }
            $change = New-PimChange -Entity 'PIM-Action-Revoke' -Key $key -Op 'Remove' `
                        -Payload ([pscustomobject]$payload) -By $who `
                        -Kind 'Action' -Origin 'Authorised' -Justification $Justification
            Add-PimSqlQueueChange -ConnectionString $cs -Change $change

            [void]$results.Add([ordered]@{ id = $rowId; ok = $true; queued = $true; queueId = "$($change.id)"; actionType = $actionType })
            Write-Host ("  [revoke][{0}] QUEUED -- principal {1} (awaiting commit)" -f $type, $r.principalId) -ForegroundColor DarkGray
        } catch {
            $msg = "$($_.Exception.Message)"
            [void]$results.Add([ordered]@{ id = $rowId; ok = $false; error = $msg })
            Write-Warning ("  [revoke][{0}] QUEUE FAIL -- {1}" -f $type, $msg)
        }
    }

    return $results.ToArray()
}

function Find-PimManagerOffboardAdminRow {
    # PURE. The ONE Account-Definitions-Admins row an approved offboard target names (UPN or UserName,
    # case-insensitive). Zero or several matches return an error, never a guess.
    param([AllowEmptyString()][string]$Target, [object[]]$Rows = @())
    $t = "$Target".Trim()
    if (-not $t) { return [pscustomobject]@{ row = $null; error = 'the approved request has no target' } }
    $match = @(@($Rows) | Where-Object { $_ -and ("$($_.UserPrincipalName)".Trim() -ieq $t -or "$($_.UserName)".Trim() -ieq $t) })
    if ($match.Count -eq 1) { return [pscustomobject]@{ row = $match[0]; error = '' } }
    $err = $(if ($match.Count -eq 0) { "no Account-Definitions-Admins row for '$t' -- nothing to mark for offboarding (v2 queues ONE admin per approval)" } else { "$($match.Count) admin rows match '$t' -- refusing to guess which one to offboard" })
    return [pscustomobject]@{ row = $null; error = $err }
}

function New-PimManagerOffboardQueueInvoker {
    <#
      v2 OFFBOARD EXECUTION -- the Manager stays READ-ONLY (2026-09-12).

      The approval gate's default action invoker called v1 account-status functions the REST engine
      does not load, so "Execute offboard" failed or did nothing in v2. The v2 path is the engine's
      AdminOffboarding provider (disable, sessions, memberships, notice mail, delete after N days;
      progress in SQL), which acts on admin rows whose OffboardDate has passed
      (Get-PimAdminOffboardCandidate / Test-PimAdminOffboarded).

      So the invoker performs NO directory write: on the first step it stages ONE desired-state
      change on pim.ChangeQueue -- the admin's Account-Definitions-Admins row with OffboardDate = now
      -- which an operator commits in Pending changes; the engine performs the offboarding on its next
      run. Every later step of the guided plan reports that it is performed by the engine.
      Injectable seams: -ReadRows { param($entity) }, -Enqueue { param($change) }.
    #>
    param(
        [Parameter(Mandatory)][string]$RequestId,
        [string]$By = '',
        [scriptblock]$ReadRows = { param($entity) @(Get-PimSqlRows -ConnectionString (Get-PimManagerStoreCs) -Entity $entity) },
        [scriptblock]$Enqueue  = { param($change) Add-PimSqlQueueChange -ConnectionString (Get-PimManagerStoreCs) -Change $change },
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    # 🪤 NOT a .GetNewClosure(): a closure runs in a fresh module scope that cannot see this script's
    # functions (Get-PimStoreRowKey, New-PimChange, ...). The context lives in script scope instead;
    # the Manager is single-threaded, so one approval executes at a time.
    $state = @{ queued = $false; queueId = ''; error = '' }
    $script:PimOffboardQueueCtx = @{ RequestId = $RequestId; By = $By; ReadRows = $ReadRows; Enqueue = $Enqueue; NowUtc = $NowUtc; State = $state }
    $invoker = {
        param($Step, $Target)
        $ctxQ = $script:PimOffboardQueueCtx; $state = $ctxQ.State; $ReadRows = $ctxQ.ReadRows; $Enqueue = $ctxQ.Enqueue
        $NowUtc = $ctxQ.NowUtc; $By = $ctxQ.By; $RequestId = $ctxQ.RequestId
        if ($state.error) { return [pscustomobject]@{ ok = $false; detail = "not queued: $($state.error)" } }
        if ($state.queued) { return [pscustomobject]@{ ok = $true; detail = "step '$($Step.step)' is performed by the engine (AdminOffboarding) on its next run after the queued change is committed" } }
        $t = "$Target".Trim()
        $found = Find-PimManagerOffboardAdminRow -Target $t -Rows @(& $ReadRows 'Account-Definitions-Admins')
        if (-not $found.row) {
            $state.error = "$($found.error)"
            return [pscustomobject]@{ ok = $false; detail = $state.error }
        }
        $row = [ordered]@{}
        foreach ($p in $found.row.PSObject.Properties) { $row[$p.Name] = $p.Value }
        $row['OffboardDate'] = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $key = Get-PimStoreRowKey -Base 'Account-Definitions-Admins' -Row ([pscustomobject]$row)
        if (-not $key) { $state.error = "the admin row for '$t' has no UserName -- it cannot be addressed in the store"; return [pscustomobject]@{ ok = $false; detail = $state.error } }
        $change = New-PimChange -Entity 'Account-Definitions-Admins' -Key $key -Op 'Update' -Payload ([pscustomobject]$row) `
                    -By $(if ("$By".Trim()) { "$By" } else { 'unknown' }) -Kind 'DesiredState' -Origin 'Authorised' `
                    -Justification "approved offboard (approval request $RequestId): mark $t for offboarding"
        & $Enqueue $change
        $state.queued = $true; $state.queueId = "$($change.id)"
        return [pscustomobject]@{ ok = $true; detail = "queued: OffboardDate set on the admin row (queue entry $($change.id)) -- commit it in Pending changes; the engine offboards on its next run" }
    }
    return [pscustomobject]@{ Invoker = $invoker; State = $state }
}

function Invoke-Server {
    param([int]$DesiredPort = 0)

    Write-Host "PIM4EntraPS Mapper -- starting local editor server ..." -ForegroundColor Cyan
    # Deterministic boot-log version line. The post-deploy hosted smoke
    # (tests/live/Test-PimManagerHostedSmoke.ps1) asserts the LIVE Manager is
    # serving the EXPECTED version (SOLUTIONS/PIM4EntraPS/VERSION) by matching
    # this exact phrasing in ContainerAppConsoleLogs_CL -- it is the reliable
    # signal behind Easy Auth (the served HTML #versionBadge needs an edge token).
    # Stale here == a deploy that didn't actually roll the image (the "stuck on
    # 2.4.222" case) and is a HARD FAIL in the smoke.
    Write-Host ("  [version] PIM Manager {0} (from VERSION)" -f (Get-PimSolutionVersion)) -ForegroundColor Cyan

    # SEC-01 -- state the AUTHENTICATION POSTURE at boot, loudly, so which layer is
    # actually protecting this Manager is never a guess. The hosted smoke greps this
    # line. 'EDGE-CONSISTENCY ONLY' is a real warning, not decoration: it means the app
    # still assumes the auth edge is in front of it.
    if (Get-Command Test-PimHostedAuthPosture -ErrorAction SilentlyContinue) {
        $posture = Test-PimHostedAuthPosture -Hosted ([bool]$script:PimHosted)
        $pc = 'Green'; if (-not $posture.ok) { $pc = 'Yellow' }
        Write-Host ("  [auth] posture={0}" -f $posture.level) -ForegroundColor $pc
        foreach ($ln in ("$($posture.message)" -split "`r?`n")) { Write-Host ("  [auth] " + $ln) -ForegroundColor $pc }
    } elseif ($script:PimHosted) {
        Write-Host "  [auth] posture=UNKNOWN -- PIM-HostedAuth.ps1 not loaded; hosted principals will be REFUSED (failing closed)." -ForegroundColor Red
    }
    $token = [Guid]::NewGuid().ToString('N')

    $listener = $null
    $port = 0
    if ($script:PimHosted -and "$env:HTTP_PLATFORM_PORT" -match '^\d+$') {
        # HOSTED on a NATIVE Windows App Service (no container). httpPlatformHandler
        # launches this PS process and reverse-proxies inbound to the port it picks
        # in %HTTP_PLATFORM_PORT%. We MUST bind loopback (not http://+:) -- binding
        # all-interfaces needs a URL-ACL/admin we don't have; the handler only ever
        # forwards to localhost. Easy Auth + private inbound sit in front of the
        # handler; the token is still required on /api.
        $port = [int]$env:HTTP_PLATFORM_PORT
        $l = New-Object System.Net.HttpListener
        $l.Prefixes.Add("http://localhost:$port/")
        $l.Start(); $listener = $l
        Write-Host ("  [HOSTED/native] App Service (httpPlatformHandler) listening on http://localhost:{0}/ (Easy Auth identity; token required on /api)" -f $port) -ForegroundColor Green
    } elseif ($script:PimHosted) {
        # HOSTED (24/7 business edition, container): bind all interfaces on the
        # container port (App Service sets WEBSITES_PORT/PORT). Easy Auth + private
        # inbound sit in front; the token is still required on /api.
        $port = if ("$env:WEBSITES_PORT" -match '^\d+$') { [int]$env:WEBSITES_PORT } elseif ("$env:PORT" -match '^\d+$') { [int]$env:PORT } elseif ($DesiredPort -gt 0) { $DesiredPort } else { 8080 }
        $l = New-Object System.Net.HttpListener
        $l.Prefixes.Add("http://+:$port/")
        $l.Start(); $listener = $l
        Write-Host ("  [HOSTED] 24/7 business edition listening on http://+:{0}/ (Easy Auth identity; token required on /api)" -f $port) -ForegroundColor Green
    } else {
        # LOCAL (loopback) edition -- the sanctioned BREAK-GLASS / EMERGENCY path:
        # run on the box (SuperAdmin) when the hosted app / Easy Auth / network is
        # unavailable. Pick a free port (DesiredPort first, then random).
        $maxAttempts = 10
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            if ($DesiredPort -gt 0 -and $attempt -eq 1) { $candidate = $DesiredPort } else { $candidate = Get-FreeTcpPort }
            try {
                $l = New-Object System.Net.HttpListener
                $l.Prefixes.Add("http://127.0.0.1:$candidate/")
                $l.Start(); $listener = $l; $port = $candidate; break
            } catch [System.Net.HttpListenerException] {
                Write-Warning ("  port {0} unavailable ({1}); retrying ..." -f $candidate, $_.Exception.Message); continue
            }
        }
        if (-not $listener) { throw "Failed to bind a localhost port after $maxAttempts attempts." }
        # section 9 MFA-gated Manager login (LOCAL/loopback only). Hosted is gated by Easy Auth
        # at the edge (the gate is a no-op there -- never touch Easy Auth). OPT-IN so the
        # backward-compatible single-operator install is unaffected: enable with
        # $global:PIM_RequireMfaLogin = $true (config/manager-access.custom.* or env
        # PIM_RequireMfaLogin=1). When on, an MFA-proven Entra token is required before
        # the loopback server is exposed -- a stolen script can't be replayed without a
        # fresh MFA sign-in. SuperAdmins are never auto-locked out: a sign-in failure
        # explains exactly what to do, it never silently bricks the break-glass path.
        $requireMfa = ($global:PIM_RequireMfaLogin -eq $true) -or ("$env:PIM_RequireMfaLogin" -in @('1','true','yes'))
        if ($requireMfa -and (Get-Command Assert-PimManagerMfa -ErrorAction SilentlyContinue)) {
            try {
                $tok = $null
                if (Get-Command Get-PimInteractiveToken -ErrorAction SilentlyContinue) {
                    Write-Host "  [mfa-gate] MFA login required -- opening Edge sign-in (PKCE loopback; never device-code)." -ForegroundColor Yellow
                    $tr = Get-PimInteractiveToken -Audience 'graph' -ForceFreshAccount
                    $tok = $tr.token
                }
                $decision = Assert-PimManagerMfa -Token "$tok" -RequireMfa $true
                if (-not $decision.Allowed) {
                    Write-Host ("  [mfa-gate] DENIED: {0}" -f $decision.Source) -ForegroundColor Red
                    if ($decision.Hint) { Write-Host ("  [mfa-gate] {0}" -f $decision.Hint) -ForegroundColor Yellow }
                    try { $listener.Stop(); $listener.Close() } catch {}
                    throw "MFA-gated Manager login failed -- $($decision.Source)."
                }
                Write-Host ("  [mfa-gate] OK ({0}{1})" -f $decision.Source, $(if ($decision.Upn) { " as $($decision.Upn)" } else { '' })) -ForegroundColor Green
            } catch {
                if ("$($_.Exception.Message)" -match 'MFA-gated Manager login failed') { throw }
                Write-Host ("  [mfa-gate] sign-in error: {0}" -f $_.Exception.Message) -ForegroundColor Red
                try { $listener.Stop(); $listener.Close() } catch {}
                throw "MFA-gated Manager login could not complete -- $($_.Exception.Message)"
            }
        }
        Write-Host ("  [LOCAL/emergency] loopback listening on http://127.0.0.1:{0}/" -f $port) -ForegroundColor Green
        Write-Host ("  session token: {0}" -f $token) -ForegroundColor DarkGray
        Write-Host "  press Ctrl-C to stop (or close the browser tab; server self-exits after 30s of silence)." -ForegroundColor DarkGray
    }

    $url = if ($script:PimHosted) { "http://localhost:$port/?token=$token" } else { "http://127.0.0.1:$port/?token=$token" }
    if (-not $NoLaunch -and -not $script:PimHosted) {
        Write-Host "  launching default browser ..." -ForegroundColor Cyan
        Start-Process $url | Out-Null
    } elseif (-not $script:PimHosted) {
        Write-Host ("  URL: {0}" -f $url) -ForegroundColor Yellow
    }

    # Heartbeat tracker -- updated by /api/heartbeat, watched by the dispatch loop.
    $script:lastHeartbeat = Get-Date
    $heartbeatTimeoutSeconds = 30
    $heartbeatGraceSeconds   = 15  # extra grace at startup before the browser pings

    # HOSTED startup: auto-populate the tenant-list cache (entra-roles freshness
    # badge + pickers) so the operator never has to run -RefreshTenantLists by
    # hand on a 24/7 container. Best-effort + non-fatal -- the server is already
    # bound + listening, so a slow/failed Graph call only delays the first cache,
    # never the server. (Local emergency edition skips this -- the operator can
    # refresh from the UI.)
    if ($script:PimHosted -and (Get-Command Initialize-PimManagerTenantCache -ErrorAction SilentlyContinue)) {
        try { [void](Initialize-PimManagerTenantCache) } catch { Write-Host ("  [tenant-cache] startup populate skipped: {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow }
    }

    # Begin first async accept; we process synchronously then re-arm.
    $stop = $false
    $contextResult = $listener.BeginGetContext($null, $null)
    while (-not $stop -and $listener.IsListening) {
        # Wait for context with a 1-second cap so we can check heartbeat regularly.
        if ($contextResult.AsyncWaitHandle.WaitOne(1000)) {
            try { $ctx = $listener.EndGetContext($contextResult) }
            catch { break }
            # Re-arm immediately so subsequent requests don't queue forever.
            $contextResult = $listener.BeginGetContext($null, $null)

            $started = Get-Date
            $status = 500
            # Hosted: capture THIS request's Easy Auth principal for role resolution.
            if ($script:PimHosted) { try { $script:CurrentRequestPrincipal = Get-PimEasyAuthPrincipal -Request $ctx.Request } catch { $script:CurrentRequestPrincipal = $null } }
            try {
                $status = Handle-Request -Context $ctx -ExpectedToken $token
            } catch {
                Write-Host ("  ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
                try {
                    Write-JsonResponse -Response $ctx.Response -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                } catch { }
                $status = 500
            }
            $ts = $started.ToString('HH:mm:ss')
            Write-Host ("  [{0}] {1,-6} {2,-40} -> {3}" -f $ts, $ctx.Request.HttpMethod, $ctx.Request.Url.PathAndQuery, $status) -ForegroundColor DarkGray
            # A served request IS client activity. Long-running endpoints
            # (active-assignments took 90s on a real tenant) block the
            # single-threaded loop, so the browser's 10s heartbeats queue
            # unprocessed -- without this, the server reaped itself right
            # after answering the slow request.
            $script:lastHeartbeat = Get-Date
        }

        # Heartbeat self-exit -- LOCAL/emergency only. Hosted runs 24/7 (never self-exits).
        if (-not $script:PimHosted) {
            $idleSeconds = (Get-Date) - $script:lastHeartbeat
            if ($idleSeconds.TotalSeconds -gt ($heartbeatTimeoutSeconds + $heartbeatGraceSeconds)) {
                Write-Host ("  heartbeat timeout ({0:N0}s with no client ping) -- shutting down." -f $idleSeconds.TotalSeconds) -ForegroundColor Yellow
                $stop = $true
            }
        }
    }

    try { $listener.Stop() } catch { }
    try { $listener.Close() } catch { }
    Write-Host "  server stopped." -ForegroundColor Cyan
}

function Handle-Request {
    param(
        [Parameter(Mandatory)][System.Net.HttpListenerContext]$Context,
        [Parameter(Mandatory)][string]$ExpectedToken
    )
    $req  = $Context.Request
    $resp = $Context.Response
    $path = $req.Url.AbsolutePath
    $method = $req.HttpMethod

    # GET / -- serve the SPA. The token is embedded in a <meta> tag so the
    # JS can read it without exposing it on the URL after the first hop.
    if ($path -eq '/' -and $method -eq 'GET') {
        # SEC-01: this page bakes the /api bearer token into its HTML, so serving it
        # unauthenticated made that token public -- two requests (GET / for the token,
        # then any /api call with a forged principal header) reached SuperAdmin. In
        # HOSTED mode the caller must therefore be a positively-trusted principal
        # before the page (and with it the token) is handed over. LOCAL mode is
        # unchanged: the listener binds to loopback and identity is the Windows user.
        if ($script:PimHosted -and -not "$script:CurrentRequestPrincipal".Trim()) {
            Write-Host "  [auth] DENIED GET / -- no trusted principal (hosted)" -ForegroundColor Red
            Write-JsonResponse -Response $resp -Status 401 -Body @{
                error = 'unauthorized'
                detail = 'no authenticated principal -- this app must be reached through its authentication edge'
            }
            return 401
        }
        $data = Build-PimGraphData
        $json = ConvertTo-PimJson -Body $data
        # Settings admin area (§11): default-seed naming + filters at first page
        # render so a fresh install always has a working convention/filter
        # persisted in the store (never empty). Best-effort -- never block render.
        try { [void](Get-PimManagerNamingSettings); [void](Get-PimManagerFilterSettings) } catch { Write-Warning "settings seed skipped: $($_.Exception.Message)" }
        $naming = Get-PimNamingConventions
        $namingJson = ConvertTo-PimJson -Body $naming
        $tenantLists = Read-PimTenantListCache
        $tenantJson  = ConvertTo-PimJson -Body $tenantLists
        # NB: foreach statement, not pipeline -- Get-PimManagerInstances returns a
        # comma-wrapped array, and piping that sends the WHOLE array as one item
        # (member enumeration then collapses .name into a string[]).
        $instList = New-Object System.Collections.ArrayList
        foreach ($i in (Get-PimManagerInstances)) { [void]$instList.Add([ordered]@{ name = $i.name; configRoot = $i.configRoot }) }
        $instJson = ConvertTo-PimJson -Body ([ordered]@{
            active    = $script:PimInstanceName
            instances = $instList.ToArray()
        })
        $html = [System.IO.File]::ReadAllText($template, [System.Text.UTF8Encoding]::new($true))
        # The role PLUS whether any access is configured at all, so a fresh store renders the
        # "nobody can save yet -- here is how to grant the first SuperAdmin" banner before first paint.
        $roleBoot = Get-PimManagerRole
        try { $roleBoot['accessBootstrap'] = (Get-PimManagerAccessBootstrapState) } catch { }
        $roleJson = ($roleBoot | ConvertTo-Json -Compress -Depth 4)
        # Feature flags baked at boot so the nav/tab render gates BEFORE first paint
        # (a toggle takes effect on reload). Best-effort -- on any failure fall back
        # to an empty object so the resolver applies pure defaults (never nav-less).
        $featureFlagsJson = '{}'
        try { $featureFlagsJson = ConvertTo-PimJson -Body (Get-PimFeatureFlags) } catch { Write-Warning "feature-flags boot skipped: $($_.Exception.Message)" }
        # Governance preview gate baked at boot so each surface renders its disabled/
        # preview banner BEFORE first paint, from the SAME store the endpoint guard
        # reads. Best-effort -> {} so the resolver applies the OFF defaults.
        $govPreviewJson = '{}'
        try { $govPreviewJson = ConvertTo-PimJson -Body (Get-PimGovernancePreview) } catch { Write-Warning "governance-preview boot skipped: $($_.Exception.Message)" }
        # SQL-only: the page is always served from the SQL store.
        $modeLabel = "SQL: $($global:PIM_SqlDatabase)"
        $html = $html.Replace('__PIM_DATA__', $json).Replace('__PIM_TOKEN__', $ExpectedToken).Replace('__PIM_MODE__', $modeLabel).Replace('__PIM_NAMING__', $namingJson).Replace('__PIM_TENANT_LISTS__', $tenantJson).Replace('__PIM_INSTANCES__', $instJson).Replace('__PIM_VERSION__', (Get-PimSolutionVersion)).Replace('__PIM_ROLE__', $roleJson).Replace('__PIM_FEATUREFLAGS__', $featureFlagsJson).Replace('__PIM_GOVPREVIEW__', $govPreviewJson)
        Write-HtmlResponse -Response $resp -Html $html
        # Record a login the first time this identity opens the Manager (Audit tab
        # "Logins" category). Deduped per identity per session; best-effort.
        Write-PimManagerLoginAudit
        $script:lastHeartbeat = Get-Date
        return 200
    }

    if ($path -eq '/favicon.ico') {
        $resp.StatusCode = 204
        $resp.OutputStream.Close()
        return 204
    }

    # GET /health -- UNAUTHENTICATED liveness/readiness probe for the App Service /
    # Container App health check. RESILIENT to a transient SQL blip: a single failed
    # ping is reported 'degraded' but STILL serves 200 (so the platform doesn't kill /
    # de-route a Manager over one hiccup); only a SUSTAINED outage (>= threshold
    # consecutive failures) returns 503. In CSV/local mode there is no SQL to probe,
    # so it is always healthy. Persistent-SQL (auto-pause disabled) is what keeps the
    # probe from cold-starting in the first place -- see Test-PimSqlPersistentCompute.
    if ($path -eq '/health' -and ($method -eq 'GET' -or $method -eq 'HEAD')) {
        $probeOk = $true
        if ($script:PimStorageMode -eq 'sql' -and $script:PimSqlCs -and (Get-Command Test-PimSqlConnectivity -ErrorAction SilentlyContinue)) {
            try { $probeOk = [bool](Test-PimSqlConnectivity -ConnectionString $script:PimSqlCs) } catch { $probeOk = $false }
        }
        $hs = if (Get-Command Get-PimHealthState -ErrorAction SilentlyContinue) {
            Get-PimHealthState -ProbeOk $probeOk -ConsecutiveFailures ([int]$script:PimHealthFailures) -Threshold 3
        } else { @{ status = $(if ($probeOk) { 'healthy' } else { 'unhealthy' }); httpStatus = $(if ($probeOk) { 200 } else { 503 }); consecutiveFailures = 0 } }
        $script:PimHealthFailures = [int]$hs.consecutiveFailures
        if ($method -eq 'HEAD') { $resp.StatusCode = [int]$hs.httpStatus; $resp.OutputStream.Close(); return [int]$hs.httpStatus }
        Write-JsonResponse -Response $resp -Status ([int]$hs.httpStatus) -Body ([ordered]@{
            status      = $hs.status
            store       = 'sql'
            sqlOk       = $probeOk
            consecutiveFailures = [int]$hs.consecutiveFailures
            ts          = (Get-Date).ToUniversalTime().ToString('o')
        })
        return [int]$hs.httpStatus
    }

    # All /api/* paths require Authorization: Bearer <token>.
    if ($path -like '/api/*') {
        $authHeader = $req.Headers['Authorization']
        if (-not $authHeader -or $authHeader -ne "Bearer $ExpectedToken") {
            Write-JsonResponse -Response $resp -Status 401 -Body @{ error = 'unauthorized' }
            return 401
        }

        if ($path -eq '/api/heartbeat' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; ts = (Get-Date).ToUniversalTime().ToString('o') }
            return 200
        }

        if ($path -eq '/api/config' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $data = Build-PimGraphData
            Write-JsonResponse -Response $resp -Status 200 -Body $data
            return 200
        }

        if ($path -match '^/api/(?:csv|data)/([\w\.-]+)$') {
            $base = $Matches[1]
            $spec = Get-PimCsvSpec -BaseName $base
            if (-not $spec) {
                Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown entity: $base" }
                return 404
            }
            $script:lastHeartbeat = Get-Date
            $sqlMode = $true   # SQL-only (2026-09-12): kept as a name for the commit call below

            if ($method -eq 'GET') {
                $rows = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $base)
                $payload = [ordered]@{ path = 'sql'; source = 'sql'; header = @($spec.defaultHeader) }
                # Portal-admin read scoping: a delegated GUI-manager (non-super,
                # with a portal-admins profile) sees only the rows their tier/
                # level/service/scope allows. Super-admins + users with no portal
                # profile see everything (unchanged).
                $portalFiltered = $false
                if ((Get-Command Test-PimManagerRoleAtLeast -ErrorAction SilentlyContinue) -and -not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin') -and (Get-Command Read-PimPortalProfiles -ErrorAction SilentlyContinue)) {
                    $who = (Get-PimManagerRole).identity
                    $prof = Get-PimPortalProfile -Profiles (Read-PimPortalProfiles) -Identity "$who"
                    if ($prof) { $rows = @(Select-PimPortalVisibleRows -Profile $prof -Rows $rows -Base $base); $portalFiltered = $true }
                }
                $body = [ordered]@{
                    base   = $base
                    path   = $payload.path
                    source = $payload.source
                    header = $payload.header
                    rows   = $rows
                    portalFiltered = $portalFiltered
                }
                Write-JsonResponse -Response $resp -Status 200 -Body $body
                return 200
            }
            if ($method -eq 'PUT') {
                if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                    Write-JsonResponse -Response $resp -Status 403 -Body @{ error = "Your Manager role is Reader -- saving changes requires Admin. $(Get-PimAccessFixHint)" }
                    return 403
                }
                $body = Read-RequestJson -Request $req
                $rowsRaw = @()
                if ($body -and $body.rows) { $rowsRaw = @($body.rows) }
                $rowsOrdered = @($rowsRaw | ForEach-Object { ConvertTo-OrderedRow $_ } | Where-Object { $_ -ne $null })
                # Explicit operator acknowledgement for the empty-set / large-delta guard.
                $confirmDestructive = $false
                if ($body -and ($null -ne $body.confirm) -and ("$($body.confirm)" -ieq 'true' -or "$($body.confirm)" -eq '1' -or $body.confirm -eq $true)) { $confirmDestructive = $true }

                # Diff against current state (SQL or CSV) for the audit log AND the
                # pre-commit snapshot ([M1]). Capture header too, so an undo restores
                # the exact column layout (file mode preserves separator/blank rows).
                $spec = Get-PimCsvSpec -BaseName $base
                $current = @{ rows = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $base); header = $(if ($spec) { @($spec.defaultHeader) } else { @() }) }
                $diff = Compare-PimRowSets -Before $current.rows -After $rowsOrdered -Base $base

                # -------------------------------------------------------------------
                # SERVER-SIDE ENFORCEMENT (Batch 1) -- the GUI is NOT the only gate.
                # The plain Review & Save / Create-wizard / Onboarding PUT is the SAME
                # write path the authoring endpoints only PREVIEW; gate it here too.
                # -------------------------------------------------------------------
                # [Fix 1] MAKER/CHECKER on the general commit path: re-run the SAME gate
                # the /api/authoring/* endpoints use, so a sensitive change committed via
                # the plain PUT (bypassing the GUI's sensitivity check) is still blocked
                # unless a second admin approved it. Non-sensitive -> allowed (idempotent;
                # safe if the GUI already checked). The keyed diff's removes/adds drive the
                # classification (a privileged-row removal/attach is sensitive).
                if (Get-Command Test-PimAuthoringCommitAllowed -ErrorAction SilentlyContinue) {
                    $gateRows = @()
                    try { if (Get-Command Get-PimWriteAffectedRows -ErrorAction SilentlyContinue) { $gateRows = @(Get-PimWriteAffectedRows -Diff $diff) } } catch { $gateRows = @() }
                    if (@($gateRows).Count -eq 0) { $gateRows = @($rowsOrdered) }
                    $reqs = @()
                    if (Get-Command Get-PimApprovalRequests -ErrorAction SilentlyContinue) { try { $reqs = @(Get-PimApprovalRequests) } catch {} }
                    $mc = Test-PimAuthoringCommitAllowed -Action 'review-save' -Base $base -Rows $gateRows -Requests $reqs
                    if (-not $mc.allowed) {
                        Write-JsonResponse -Response $resp -Status 409 -Body ([ordered]@{
                            ok = $false; base = $base; gate = "$($mc.gate)"; error = "$($mc.reason)"
                            approvalRequired = $true; target = "$($mc.target)"; reasons = @($mc.reasons)
                        })
                        return 409
                    }
                }

                # [Fix 2] PORTAL SCOPE on writes: a non-SuperAdmin delegated caller may
                # only create/change/REMOVE rows inside their tier/level/service/scope.
                # We validate EVERY affected row -- including removes (delete-by-omission
                # of an out-of-scope row the caller can't see is rejected here).
                $callerScope = Get-PimManagerCallerScope
                if (-not $callerScope.isSuperAdmin -and $callerScope.profile -and (Get-Command Test-PimPortalRowsInScope -ErrorAction SilentlyContinue)) {
                    $affected = @()
                    try { if (Get-Command Get-PimWriteAffectedRows -ErrorAction SilentlyContinue) { $affected = @(Get-PimWriteAffectedRows -Diff $diff) } } catch { $affected = @() }
                    $scopeCheck = Test-PimPortalRowsInScope -Profile $callerScope.profile -Rows $affected -Base $base -RequireManage
                    if (-not $scopeCheck.allowed) {
                        Write-JsonResponse -Response $resp -Status 403 -Body ([ordered]@{
                            ok = $false; base = $base; error = "$($scopeCheck.reason)"; denied = @($scopeCheck.denied)
                        })
                        return 403
                    }
                    # Bound the after-set to what the caller may SEE so a scoped caller can
                    # never silently introduce/keep rows outside their delegation.
                    if (Get-Command Select-PimPortalVisibleRows -ErrorAction SilentlyContinue) {
                        $rowsOrdered = @(Select-PimPortalVisibleRows -Profile $callerScope.profile -Rows $rowsOrdered -Base $base)
                    }
                }

                # [Fix 5] EMPTY-SET / LARGE-DELTA guard (mirrors the engine disable-guard;
                # the 53-user mass-disable precondition was an empty/over-broad desired set).
                # Refuse a commit that empties the entity or removes more than the safety
                # threshold of current rows, UNLESS the operator passed confirm=true.
                if (Get-Command Test-PimCommitDeltaGuard -ErrorAction SilentlyContinue) {
                    $deltaGuard = Test-PimCommitDeltaGuard -BeforeCount (@($current.rows).Count) -AfterCount (@($rowsOrdered).Count) -RemoveCount (@($diff.removes).Count) -Confirm:$confirmDestructive
                    if (-not $deltaGuard.allowed) {
                        Write-JsonResponse -Response $resp -Status 409 -Body ([ordered]@{
                            ok = $false; base = $base; gate = "$($deltaGuard.rule)"; error = "$($deltaGuard.reason)"
                            confirmRequired = $true; removeCount = [int]$deltaGuard.removeCount; beforeCount = (@($current.rows).Count); afterCount = (@($rowsOrdered).Count)
                        })
                        return 409
                    }
                }

                # [M1] SAFE COMMIT: timestamped backup BEFORE the apply, all-or-nothing
                # transactional apply, automatic rollback-to-snapshot on any failure.
                try {
                    $commitRes = Invoke-PimManagerSafeCommit -Base $base -NewRows $rowsOrdered -Current $current -SqlMode:$sqlMode
                } catch {
                    # The store was left exactly as before (snapshot restored). Surface
                    # the clear error so the operator sees the commit was reversed.
                    Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; base = $base; error = "$($_.Exception.Message)" }
                    return 500
                }
                $writtenPath = 'sql'
                Write-PimMutationLog -BaseName $base -Adds $diff.adds.Count -Removes $diff.removes.Count -Modifies $diff.modifies.Count -NewRowCount $rowsOrdered.Count -Diff $diff
                # §70.21: start the engine now (debounced, so a multi-entity commit starts one run; the container takes
                # longer to start than the remaining entity writes, and a running tick re-checks between its jobs).
                if (($diff.adds.Count + $diff.removes.Count + $diff.modifies.Count) -gt 0) { try { [void](Start-PimManagerTickNow -Reason "commit:$base") } catch { } }

                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok         = $true
                    base       = $base
                    path       = $writtenPath
                    rowCount   = $rowsOrdered.Count
                    adds       = $diff.adds.Count
                    removes    = $diff.removes.Count
                    modifies   = $diff.modifies.Count
                    snapshotId = "$($commitRes.snapshotId)"
                })
                return 200
            }
            if ($method -eq 'POST' -and $path -match '^/api/(?:csv|data)/[\w\.-]+$') {
                Write-JsonResponse -Response $resp -Status 405 -Body @{ error = 'method not allowed (did you mean /api/diff/<base>?)' }
                return 405
            }
        }

        if ($path -eq '/api/tenant-lists' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            # Lazy hosted populate: if the cache is empty/stale (e.g. auth came
            # online after startup, or the operator never ran -RefreshTenantLists),
            # populate once on read. Non-fatal -- always serves what's on disk.
            if ($script:PimHosted -and (Get-Command Initialize-PimManagerTenantCache -ErrorAction SilentlyContinue)) {
                try { [void](Initialize-PimManagerTenantCache) } catch { }
            }
            $tenantLists = Read-PimTenantListCache
            Write-JsonResponse -Response $resp -Status 200 -Body $tenantLists
            return 200
        }

        if ($path -eq '/api/refresh-tenant-lists' -and $method -eq 'POST') {
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command Invoke-PimTenantListRefresh -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = '_tenantSync.ps1 was not loaded -- file missing next to Open-PimManager.ps1' }
                return 500
            }
            try {
                $result = Invoke-PimTenantListRefresh
                $tenantLists = Read-PimTenantListCache
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok      = $result.ok
                    reason  = $result.reason
                    results = $result.results
                    lists   = $tenantLists
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/naming-conventions' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimNamingConventions)
            return 200
        }

        # -------------------------------------------------------------------
        # Settings admin area (REQUIREMENTS §11) -- naming conventions,
        # filters, departments(+owners), approvers/owners. Read = any role;
        # write = SuperAdmin only (the settings drive tenant-wide routing /
        # provisioning naming). Persisted through the active store (SQL
        # pim.Settings or the per-instance JSON). Naming + filters are
        # default-seeded on read so they are never empty.
        # -------------------------------------------------------------------
        if ($path -eq '/api/settings' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimManagerSettingsBundle)
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -match '^/api/settings/(naming|filters|departments|approvers)$' -and $method -eq 'PUT') {
            $section = $Matches[1]
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to edit settings. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            $body = Read-RequestJson -Request $req
            try {
                switch ($section) {
                    'naming' {
                        $payload = if ($body -and $body.PSObject.Properties['value']) { $body.value } else { $body }
                        $h = ConvertTo-PimPlainHashtable $payload
                        if ($h.Count -eq 0) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'naming convention cannot be empty -- supply at least one key (e.g. PimGroupPattern).' }; return 400 }
                        Set-PimManagerSetting -Name 'NamingConventions' -Value $h
                        if (-not ($global:PIM_NamingConventions -is [hashtable])) { $global:PIM_NamingConventions = @{} }
                        foreach ($k in @($h.Keys)) { $global:PIM_NamingConventions[$k] = $h[$k] }
                    }
                    'filters' {
                        $arr = if ($body -and $body.PSObject.Properties['value']) { @($body.value) } else { @($body) }
                        if ($arr.Count -eq 0) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'filters cannot be empty -- at least one filter is required.' }; return 400 }
                        Set-PimManagerSetting -Name 'Filters' -Value $arr
                    }
                    'departments' {
                        # 🔴 BUG-142 -- WRITE THE STORE THE ENGINE READS. This used to write only the
                        # SETTING 'Departments', which the engine's owner chain never reads
                        # (Get-PimDepartmentOwnerIndex reads the ENTITY PIM-Definitions-Departments),
                        # so a department entered here never reached the engine. §62.4's recorded fix
                        # shape: the ENTITY is authoritative and this screen writes it, through the
                        # ONE writer that every department path now shares.
                        $arr = if ($body -and $body.PSObject.Properties['value']) { @($body.value) } else { @($body) }
                        # 🪤 An empty array here would be a full-set DELETE of every department --
                        # and departments carry the owner chain for privileged-access approvals.
                        # Refused, like 'filters'. Clearing is done deliberately in the grid.
                        if (@($arr).Count -eq 0) {
                            Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'departments cannot be saved empty -- that would remove every department and the approval owner chain with it. Remove them individually in the Advanced grid if that is really the intent.' }
                            return 400
                        }
                        $dsave = Save-PimManagerDepartments -Departments $arr
                        if (-not $dsave.ok) {
                            Write-JsonResponse -Response $resp -Status 503 -Body @{ error = "departments were NOT saved: $($dsave.error)" }
                            return 503
                        }
                    }
                    'approvers' {
                        $arr = if ($body -and $body.PSObject.Properties['value']) { @($body.value) } else { @($body) }
                        Set-PimManagerSetting -Name 'Approvers' -Value $arr
                    }
                }
                Write-PimManagerAuditEvent -Action "settings.$section.save" -Target "settings:$section" -Result 'ok'
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimManagerSettingsBundle)
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # -------------------------------------------------------------------
        # Import departments from Entra (REQUIREMENTS §8/§11). Pull Entra groups
        # whose displayName matches a configurable name pattern (default ORG-*)
        # into the PIM departments used for delegation-approval routing. Engine
        # stays the writer: Import-PimEntraDepartments discovers (LIVE Graph,
        # server-side $filter) + the PURE planner computes an idempotent upsert
        # (re-import updates, never duplicates; manual depts preserved), then we
        # persist the merged list. SuperAdmin only. Returns created/updated/skipped.
        # -------------------------------------------------------------------
        if ($path -eq '/api/settings/departments/import' -and $method -eq 'POST') {
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to import departments. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command Import-PimEntraDepartments -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = 'discovery library not loaded (Import-PimEntraDepartments missing).' }
                return 500
            }
            $body = Read-RequestJson -Request $req
            $pattern = if ($body -and $body.PSObject.Properties['pattern'] -and "$($body.pattern)".Trim()) { "$($body.pattern)".Trim() } else { (Get-PimManagerDepartmentImportPattern) }
            try {
                $existing = @(Get-PimManagerDepartments)
                $plan = Import-PimEntraDepartments -Existing $existing -Pattern $pattern
                # Persist the chosen pattern + the merged department list (engine is the writer).
                Set-PimManagerSetting -Name 'DepartmentImportPattern' -Value $pattern
                # BUG-142: through the ONE writer, so an import reaches the engine's store too.
                $dsave = Save-PimManagerDepartments -Departments @($plan.departments)
                if (-not $dsave.ok) { Write-JsonResponse -Response $resp -Status 503 -Body @{ error = "departments were NOT saved: $($dsave.error)" }; return 503 }
                Write-PimManagerAuditEvent -Action 'settings.departments.import' -Target "pattern:$pattern" -Result 'ok' -After $plan.summary
                Write-JsonResponse -Response $resp -Status 200 -Body @{
                    ok       = $true
                    pattern  = $pattern
                    summary  = $plan.summary
                    created  = @($plan.created)
                    updated  = @($plan.updated)
                    skipped  = @($plan.skipped)
                    settings = (Get-PimManagerSettingsBundle)
                }
                return 200
            } catch {
                Write-PimManagerAuditEvent -Action 'settings.departments.import' -Target "pattern:$pattern" -Result 'error' -After @{ error = "$($_.Exception.Message)" }
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # -------------------------------------------------------------------
        # Import approvers/owners from CSV (REQUIREMENTS §11). Bulk-assign
        # approvers/owners to departments from an uploaded CSV
        # (Department;GroupName;approver1,approver2,...), with an optional
        # RENAME of the department (NewName / 4th column). Engine stays the
        # writer: Import-PimApproversFromCsv parses (PURE) + the planner computes
        # an idempotent apply (CSV is authoritative for the rows it carries;
        # departments not named in the CSV are preserved), then we persist the
        # merged list. SuperAdmin only. Returns created/updated/renamed.
        # -------------------------------------------------------------------
        if ($path -eq '/api/settings/approvers/import' -and $method -eq 'POST') {
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to import approvers. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command Import-PimApproversFromCsv -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = 'discovery library not loaded (Import-PimApproversFromCsv missing).' }
                return 500
            }
            $body = Read-RequestJson -Request $req
            $csv  = if ($body -and $body.PSObject.Properties['csv']) { "$($body.csv)" } else { '' }
            if (-not "$csv".Trim()) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = 'csv body is empty -- upload a CSV (Department;GroupName;approver1,approver2,...).' }
                return 400
            }
            try {
                $existing = @(Get-PimManagerDepartments)
                $plan = Import-PimApproversFromCsv -Csv $csv -Existing $existing
                # BUG-142: through the ONE writer, so an import reaches the engine's store too.
                $dsave = Save-PimManagerDepartments -Departments @($plan.departments)
                if (-not $dsave.ok) { Write-JsonResponse -Response $resp -Status 503 -Body @{ error = "departments were NOT saved: $($dsave.error)" }; return 503 }
                Write-PimManagerAuditEvent -Action 'settings.approvers.import' -Target 'csv' -Result 'ok' -After $plan.summary
                Write-JsonResponse -Response $resp -Status 200 -Body @{
                    ok       = $true
                    summary  = $plan.summary
                    created  = @($plan.created)
                    updated  = @($plan.updated)
                    renamed  = @($plan.renamed)
                    settings = (Get-PimManagerSettingsBundle)
                }
                return 200
            } catch {
                Write-PimManagerAuditEvent -Action 'settings.approvers.import' -Target 'csv' -Result 'error' -After @{ error = "$($_.Exception.Message)" }
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # -------------------------------------------------------------------
        # Admin templates (LIFECYCLE-GOVERNANCE phase 2) -- prestaged admin
        # settings for the onboarding wizard. SHIPPED *.admintemplate.json only --
        # no customer file overrides (operator decision 2026-09-12).
        # -------------------------------------------------------------------
        if ($path -eq '/api/admin-templates' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $tplDir = Join-Path $solutionRoot 'templates\admin'
            $byId = @{}
            if (Test-Path -LiteralPath $tplDir) {
                $files = @(Get-ChildItem -LiteralPath $tplDir -Filter '*.admintemplate.json' -ErrorAction SilentlyContinue)
                foreach ($f in $files) {
                    try {
                        $tpl = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                        if ($tpl.id) { $byId[$tpl.id] = $tpl }
                    } catch {
                        Write-Warning "admin template '$($f.Name)' unreadable: $($_.Exception.Message)"
                    }
                }
            }
            Write-JsonResponse -Response $resp -Status 200 -Body @{ templates = @($byId.Values | Sort-Object { $_.name }) }
            return 200
        }

        # -------------------------------------------------------------------
        # Governance endpoints (LIFECYCLE-GOVERNANCE phases 7+8)
        # -------------------------------------------------------------------
        if ($path -eq '/api/access' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimManagerRole)
            return 200
        }

        if ($path -eq '/api/license' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            if (Get-Command Get-PimLicense -ErrorAction SilentlyContinue) {
                $lic = Get-PimLicense -Refresh
                Write-JsonResponse -Response $resp -Status 200 -Body @{
                    status     = $lic.Status
                    statusText = (Get-PimLicenseStatusText)
                    customer   = $lic.Customer
                    sku        = $lic.Sku
                    features   = @($lic.Features)
                    tenantIds  = @($lic.TenantIds)
                    validTo    = $(if ($lic.ValidTo) { $lic.ValidTo.ToString('yyyy-MM-dd') } else { '' })
                    graceUntil = $(if ($lic.GraceUntil) { $lic.GraceUntil.ToString('yyyy-MM-dd') } else { '' })
                    reason     = $lic.Reason
                }
            } else {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ status = 'Missing'; statusText = 'Core (free)'; reason = 'license library not loaded' }
            }
            return 200
        }

        if ($path -eq '/api/audit' -and $method -eq 'GET') {
            # Read-only view over the append-only audit trail (output/audit/
            # pim-audit-<yyyyMM>.jsonl). Powers the Audit tab: server-side
            # category filter + free-text search + date-range + paging, newest
            # first. The file is the source of truth (this never writes).
            #
            # [H6] "Audit you can defend": the window is no longer hard-capped at
            # 3 months -- ?months=N selects the most-recent N months, ?months=all
            # (or 0) reads the WHOLE history; each event carries a before/after
            # `change` summary. All resolved via the shared PIM-AuditQuery core so
            # the view + the CSV export (GET /api/audit/export) agree exactly.
            # [Fix 4] GATE: the audit trail is sensitive (who did what across the whole
            # tenant) -- require at least Admin (it previously had NO gate, only Bearer).
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to view the audit trail. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            $q = @{}
            foreach ($pair in ("$($req.Url.Query)".TrimStart('?') -split '&')) {
                if ($pair -match '^([^=]+)=(.*)$') { $q[[uri]::UnescapeDataString($Matches[1])] = [uri]::UnescapeDataString($Matches[2]) }
            }
            $category = if ($q.ContainsKey('category')) { "$($q['category'])".Trim().ToLowerInvariant() } else { '' }
            if ($category -eq 'all') { $category = '' }
            $search   = if ($q.ContainsKey('q')) { "$($q['q'])".Trim() } else { '' }
            $fromUtc  = if ($q.ContainsKey('from')) { "$($q['from'])".Trim() } else { '' }
            $toUtc    = if ($q.ContainsKey('to'))   { "$($q['to'])".Trim() }   else { '' }
            $page     = if ($q.ContainsKey('page')) { [Math]::Max(1, [int]$q['page']) } else { 1 }
            $pageSize = if ($q.ContainsKey('pageSize')) { [Math]::Min(500, [Math]::Max(1, [int]$q['pageSize'])) } else { 50 }
            # Back-compat: a bare ?limit=N (old Governance call) acts as pageSize.
            if ($q.ContainsKey('limit')) { $pageSize = [Math]::Min(2000, [Math]::Max(1, [int]$q['limit'])) }
            # Window: default = 3 months (back-compat with the old behaviour);
            # 'all' / 0 = full history; N = the N most-recent months.
            $months = 3
            if ($q.ContainsKey('months')) {
                $mv = "$($q['months'])".Trim().ToLowerInvariant()
                if ($mv -eq 'all' -or $mv -eq '0') { $months = 0 } else { $months = [Math]::Max(0, [int]$mv) }
            }

            $events = @(Get-PimManagerAuditEvents -Months $months)
            # Category counts BEFORE search/category filtering (chips show totals).
            $counts = @{}
            foreach ($e in $events) { $c = "$($e.category)"; if ($c) { $counts[$c] = ([int]$counts[$c]) + 1 } }

            $sorted = @(Select-PimAuditEvents -Events $events -Category $category -Search $search -FromUtc $fromUtc -ToUtc $toUtc)
            $matchCount = $sorted.Count
            $skip = ($page - 1) * $pageSize
            $pageItems = @($sorted | Select-Object -Skip $skip -First $pageSize)
            $monthsTotalCount = [int](Get-PimManagerAuditMonthCount)
            Write-JsonResponse -Response $resp -Status 200 -Body @{
                events       = $pageItems
                total        = $events.Count        # all events in the loaded window
                matchCount   = $matchCount          # after filter/search/date
                page         = $page
                pageSize     = $pageSize
                pageCount    = [Math]::Max(1, [Math]::Ceiling($matchCount / [double]$pageSize))
                category     = $category
                counts       = $counts
                months       = $months              # 0 = full history
                monthsLoaded = if ($months -eq 0) { $monthsTotalCount } else { [Math]::Min($months, $monthsTotalCount) }
                monthsTotal  = $monthsTotalCount   # months of history in whichever store answered (SEC-16)
            }
            return 200
        }

        if ($path -eq '/api/audit/export' -and $method -eq 'GET') {
            # [H6]/[H5] Full-trail CSV export: stream the WHOLE filtered audit trail
            # (every matching event, NOT just the page on screen) as a CSV download
            # -- including the before/after Change column. Honours the SAME
            # category/search/date/months filter the Audit tab is showing, so the
            # export equals "what I'm looking at, in full". Read-only.
            # [Fix 4] GATE: full-trail export is sensitive -- require at least Admin
            # (it previously had NO gate, only the Bearer token).
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to export the audit trail. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            $q = @{}
            foreach ($pair in ("$($req.Url.Query)".TrimStart('?') -split '&')) {
                if ($pair -match '^([^=]+)=(.*)$') { $q[[uri]::UnescapeDataString($Matches[1])] = [uri]::UnescapeDataString($Matches[2]) }
            }
            $category = if ($q.ContainsKey('category')) { "$($q['category'])".Trim().ToLowerInvariant() } else { '' }
            if ($category -eq 'all') { $category = '' }
            $search  = if ($q.ContainsKey('q'))    { "$($q['q'])".Trim() }    else { '' }
            $fromUtc = if ($q.ContainsKey('from')) { "$($q['from'])".Trim() } else { '' }
            $toUtc   = if ($q.ContainsKey('to'))   { "$($q['to'])".Trim() }   else { '' }
            # Export defaults to the FULL history unless the caller narrows it.
            $months = 0
            if ($q.ContainsKey('months')) {
                $mv = "$($q['months'])".Trim().ToLowerInvariant()
                if ($mv -ne 'all' -and $mv -ne '0') { $months = [Math]::Max(0, [int]$mv) }
            }
            $events = @(Get-PimManagerAuditEvents -Months $months)
            $filtered = @(Select-PimAuditEvents -Events $events -Category $category -Search $search -FromUtc $fromUtc -ToUtc $toUtc)
            $csv = ConvertTo-PimAuditCsv -Events $filtered
            $stamp = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
            $fname = "pim-audit-$stamp.csv"
            try {
                $resp.StatusCode  = 200
                $resp.ContentType = 'text/csv; charset=utf-8'
                $resp.AddHeader('Content-Disposition', "attachment; filename=`"$fname`"")
                # UTF-8 BOM so Excel renders non-ASCII correctly (matches the GUI's blob path).
                $bom = [byte[]](0xEF,0xBB,0xBF)
                $body = [System.Text.Encoding]::UTF8.GetBytes($csv)
                $resp.ContentLength64 = ($bom.Length + $body.Length)
                $resp.OutputStream.Write($bom, 0, $bom.Length)
                $resp.OutputStream.Write($body, 0, $body.Length)
                $resp.OutputStream.Close()
            } catch {
                Write-Host ("  [net] audit export client gone before response written: {0}" -f $_.Exception.Message) -ForegroundColor DarkGray
            }
            return 200
        }

        # =====================================================================
        # APPROVALS tab (maker/checker queue) -- REQUIREMENTS §13 / §27 H3/H4.
        # Surfaces the engine control plane (engine/_shared/PIM-ApprovalGate.ps1):
        # a human REQUESTS a destructive identity action (offboard | revoke |
        # disable), a DIFFERENT human APPROVES/denies it, and only an Approved
        # request may ever drive a controlled, scoped, audited execution. This GUI
        # IS the approval gate -- there is NO auto-execute path here: offboarding /
        # revoke never fire automatically. Approvals persist via the SAME settings
        # store the scheduler/engine use (Get-/Set-PimSetting shim -> SQL pim.Settings
        # / per-instance JSON), so a request raised here is visible everywhere.
        # =====================================================================

        # GET /api/approvals -- list the approval queue (pending + decided), newest
        # first, optional ?status= / ?action= filter. Each offboard item also carries
        # the engine-derived guided sequence plan (Get-PimOffboardSequencePlan: disable
        # -> revoke active -> SCHEDULED delete) so the checker sees exactly what an
        # approval would authorise BEFORE deciding. Read-only.
        if ($path -eq '/api/approvals' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command Get-PimApprovalRequests -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $false; requests = @(); total = 0; note = 'approval-gate library not loaded'; canDecide = $false }
                return 200
            }
            $statusFilter = ''
            $actionFilter = ''
            try {
                $q = $req.Url.Query
                if ($q) {
                    if ($q -match 'status=([A-Za-z]+)') { $statusFilter = $Matches[1] }
                    if ($q -match 'action=([A-Za-z]+)') { $actionFilter = $Matches[1] }
                }
            } catch {}
            try {
                $all = @(Get-PimApprovalRequests -Status $statusFilter -Action $actionFilter)
                $me  = (Get-PimManagerRole).identity
                $now = [datetime]::UtcNow
                $out = New-Object System.Collections.Generic.List[object]
                foreach ($r in $all) {
                    $expired = $false
                    try { if (Get-Command Test-PimApprovalRequestExpired -ErrorAction SilentlyContinue) { $expired = [bool](Test-PimApprovalRequestExpired -Request $r -NowUtc $now) } } catch {}
                    $plan = @()
                    if ((Test-PimApprovalAction -Action "$($r.action)") -eq 'offboard' -and (Get-Command Get-PimOffboardSequencePlan -ErrorAction SilentlyContinue)) {
                        try { $plan = @(Get-PimOffboardSequencePlan -Target "$($r.target)" -NowUtc $now) } catch {}
                    }
                    # Maker != checker: this caller may decide a Pending request only if
                    # they are NOT the requestor (unless self-approve is explicitly allowed).
                    $isRequestor = ("$($r.requestor)".Trim().ToLowerInvariant() -eq "$me".Trim().ToLowerInvariant())
                    $sepOk = $true
                    try { $sepOk = [bool](Test-PimApprovalSeparationOk -Requestor "$($r.requestor)" -Approver "$me") } catch {}
                    $out.Add([ordered]@{
                        id            = "$($r.id)"
                        requestor     = "$($r.requestor)"
                        action        = "$($r.action)"
                        target        = "$($r.target)"
                        justification = "$($r.justification)"
                        ticket        = "$($r.ticket)"
                        requestedUtc  = "$($r.requestedUtc)"
                        status        = "$($r.status)"
                        approver      = "$($r.approver)"
                        decidedUtc    = "$($r.decidedUtc)"
                        decisionNote  = "$($r.decisionNote)"
                        executedUtc   = "$($r.executedUtc)"
                        expired       = $expired
                        sequencePlan  = @($plan)
                        # Per-item: can THIS caller decide it (Pending + separation-of-duties)?
                        canDecideThis = ([bool](Test-PimManagerRoleAtLeast -Minimum 'Admin') -and "$($r.status)" -eq 'Pending' -and $sepOk)
                        isRequestor   = $isRequestor
                    })
                }
                $pendCount = @($all | Where-Object { "$($_.status)" -eq 'Pending' }).Count
                # @() over a List[object] throws ArgumentException ("Argument types do not match")
                # -- use .ToArray(). CORRECTED 2026-09-12: this is NOT 5.1-only and has nothing to
                # do with the PSCustomObject contents. It happens on pwsh 7 too, empty or not, and
                # is decided by the declared ELEMENT TYPE: List[object] throws, List[string] /
                # [int] / [psobject] / [hashtable] do not. Guarded by tests/Test-PimListWrapTrap.ps1.
                $outArr = $out.ToArray()
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok           = $true
                    me           = "$me"
                    canDecide    = [bool](Test-PimManagerRoleAtLeast -Minimum 'Admin')
                    canCreate    = [bool](Test-PimManagerRoleAtLeast -Minimum 'Admin')
                    pendingCount = [int]$pendCount
                    total        = [int]$outArr.Count
                    requests     = $outArr
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # POST /api/approvals -- raise (maker) a new approval request for a destructive
        # identity action. Admin+ (the requestor is the authenticated Manager identity).
        # Body: { action: offboard|revoke|disable, target, justification, ticket }.
        # This NEVER executes anything -- it only enqueues a Pending request that a
        # DIFFERENT human must approve before any controlled execution is possible.
        if ($path -eq '/api/approvals' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (Test-PimGovernancePreviewBlocked -Response $resp -FlagId 'approvalsPreview' -Surface 'Approvals') { return 409 }
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to raise an approval request.' }
                return 403
            }
            if (-not (Get-Command Add-PimApprovalRequest -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = 'approval-gate library not loaded' }
                return 500
            }
            $body = Read-RequestJson -Request $req
            $action = "$($body.action)".Trim()
            $target = "$($body.target)".Trim()
            $just   = "$($body.justification)".Trim()
            $ticket = "$($body.ticket)".Trim()
            if (-not (Test-PimApprovalAction -Action $action)) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "action must be one of offboard|revoke|disable (got '$action')" }
                return 400
            }
            if (-not $target) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'target is required' }; return 400 }
            if (-not $just)   { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'justification is required (every destructive request must be justified)' }; return 400 }
            try {
                $me  = (Get-PimManagerRole).identity
                $rec = Add-PimApprovalRequest -Requestor "$me" -Action $action -Target $target -Justification $just -Ticket $ticket
                Write-PimManagerAuditEvent -Action 'approval.request.created' -Target $target -After @{ id = "$($rec.id)"; action = "$($rec.action)"; requestor = "$me" }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; id = "$($rec.id)"; status = "$($rec.status)"; note = 'Approval request raised (Pending). A different administrator must approve it before any controlled execution is possible. Nothing executes automatically.' })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # POST /api/approvals/decide -- approve/deny a Pending request (checker).
        # Admin+ AND maker != checker (the approver must differ from the requestor unless
        # $global:PIM_AllowSelfApprove). Body: { id, decision: approve|deny, note }.
        # Idempotent (re-deciding a decided request returns the prior outcome). Approving
        # does NOT execute anything -- it only marks the request Approved so a controlled,
        # scoped, audited execution becomes possible later (still gated, never automatic).
        if ($path -eq '/api/approvals/decide' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (Test-PimGovernancePreviewBlocked -Response $resp -FlagId 'approvalsPreview' -Surface 'Approvals') { return 409 }
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to approve or deny a request.' }
                return 403
            }
            if (-not (Get-Command Set-PimApprovalDecision -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = 'approval-gate library not loaded' }
                return 500
            }
            $body = Read-RequestJson -Request $req
            $apprId   = "$($body.id)".Trim()
            $decision = "$($body.decision)".Trim().ToLowerInvariant()
            $note     = "$($body.note)".Trim()
            if (-not $apprId) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'id is required' }; return 400 }
            if ($decision -notin @('approve','deny')) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "decision must be 'approve' or 'deny' (got '$decision')" }
                return 400
            }
            try {
                $me  = (Get-PimManagerRole).identity
                $res = Set-PimApprovalDecision -Id $apprId -Approver "$me" -Decision $decision -Note $note
                if (-not $res.request) {
                    Write-JsonResponse -Response $resp -Status 404 -Body @{ ok = $false; error = "$($res.reason)" }
                    return 404
                }
                if (-not $res.ok) {
                    # Not a transition (already decided, expired, or separation-of-duties blocked).
                    $code = if ("$($res.reason)" -match 'separation of duties') { 403 } else { 409 }
                    Write-JsonResponse -Response $resp -Status $code -Body @{ ok = $false; status = "$($res.status)"; reason = "$($res.reason)" }
                    return $code
                }
                Write-PimManagerAuditEvent -Action ("approval.request." + $res.status.ToLowerInvariant()) -Target "$($res.request.target)" -After @{ id = "$($res.request.id)"; approver = "$me"; action = "$($res.request.action)"; decision = $decision }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; id = "$($res.request.id)"; status = "$($res.status)"; reason = "$($res.reason)" })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # POST /api/approvals/execute -- EXECUTE an APPROVED offboard request (§27 [H4]).
        # Admin+. Body: { id, confirmBulk?:bool }. This is the request -> approve -> EXECUTE
        # step: it drives the APPROVED offboard sequence through the EXISTING account-status
        # pipeline (disable -> revoke-active -> SCHEDULED delete) via Invoke-PimOffboardExecution.
        # It NEVER runs automatically and NEVER bypasses a gate -- the engine function re-checks
        # the approval, refuses an empty/bulk target without confirmation, composes the
        # DisableGuard breaker + break-glass exclusion, and latches the request once-only so it
        # can never run twice. A blocked execution returns 409 with the gate that refused it.
        if ($path -eq '/api/approvals/execute' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (Test-PimGovernancePreviewBlocked -Response $resp -FlagId 'approvalsPreview' -Surface 'Approvals') { return 409 }
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to execute an approved offboard.' }
                return 403
            }
            if (-not (Get-Command Invoke-PimOffboardExecution -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = 'approval-gate library not loaded' }
                return 500
            }
            $body = Read-RequestJson -Request $req
            $apprId      = "$($body.id)".Trim()
            $confirmBulk = [bool]($body.confirmBulk)
            if (-not $apprId) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'id is required' }; return 400 }
            try {
                # Resolve the desired set so the DisableGuard composite is positively
                # satisfied for a real, deliberate single-target offboard (the breaker
                # exists to stop a mass/empty-desired pass, not a one-by-one approved run).
                $desired = @()
                try { if (Get-Command Get-PimDesiredRows -ErrorAction SilentlyContinue) { $desired = @(Get-PimDesiredRows) } } catch {}
                # v2: the Manager does NOT change the directory. The approved offboard is staged as ONE
                # desired-state change (the admin row's OffboardDate) for an operator to commit; the
                # engine's AdminOffboarding provider performs it on its next run.
                if (-not (Get-PimManagerStoreCs) -or -not (Get-Command Add-PimSqlQueueChange -ErrorAction SilentlyContinue)) {
                    Write-JsonResponse -Response $resp -Status 503 -Body @{ error = 'no SQL store is wired in this host, so the offboard cannot be queued -- and the Manager is not permitted to change the directory itself.' }
                    return 503
                }
                # Resolve the admin row BEFORE the gate latches the request once-only: a target with no
                # (or an ambiguous) admin row must not burn the approval on a change that cannot be queued.
                $apprRec = $null
                try { $apprRec = @(Get-PimApprovalRequests) | Where-Object { "$($_.id)" -eq $apprId } | Select-Object -First 1 } catch {}
                if ($apprRec -and "$($apprRec.action)" -ieq 'offboard' -and "$($apprRec.status)" -ieq 'Approved') {
                    $pre = Find-PimManagerOffboardAdminRow -Target "$($apprRec.target)" -Rows @(Get-PimSqlRows -ConnectionString (Get-PimManagerStoreCs) -Entity 'Account-Definitions-Admins')
                    if (-not $pre.row) {
                        Write-JsonResponse -Response $resp -Status 409 -Body ([ordered]@{ ok = $false; gate = 'no-admin-row'; reason = "$($pre.error)"; queued = $false })
                        return 409
                    }
                }
                $qInv = New-PimManagerOffboardQueueInvoker -RequestId $apprId -By "$(Get-PimManagerActor)"
                $res = Invoke-PimOffboardExecution -RequestId $apprId -ConfirmBulk:$confirmBulk -ActionInvoker $qInv.Invoker `
                         -Desired $desired -DesiredResolved $true -ToDisable 1 -Scanned ([Math]::Max(1, @($desired).Count))
                if (-not $res.request) {
                    Write-JsonResponse -Response $resp -Status 404 -Body @{ ok = $false; error = "$($res.reason)" }
                    return 404
                }
                if (-not $res.executed) {
                    # A gate refused it (no-approval / bulk-unconfirmed / empty / break-glass /
                    # disable-guard / automatic / already-executed). 409 with the gate.
                    Write-JsonResponse -Response $resp -Status 409 -Body ([ordered]@{ ok = $false; gate = "$($res.gate)"; reason = "$($res.reason)" })
                    return 409
                }
                Write-PimManagerAuditEvent -Action 'approval.request.executed' -Target "$($res.target)" -Result $(if ($res.ok) { 'ok' } else { 'partial' }) -After @{ id = "$($res.request.id)"; approver = "$($res.approval.approver)"; steps = @($res.results).Count; queued = [bool]$qInv.State.queued; queueId = "$($qInv.State.queueId)" }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = [bool]$res.ok; gate = "$($res.gate)"; target = "$($res.target)"; reason = "$($res.reason)"; results = @($res.results)
                    queued = [bool]$qInv.State.queued; queueId = "$($qInv.State.queueId)"
                    note = $(if ($qInv.State.queued) { 'Queued: the admin is marked for offboarding in Pending changes. After you commit it, the engine performs the offboarding (disable, sessions, memberships, notice, scheduled delete) on its next run.' } else { "Not queued: $($qInv.State.error)" }) })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # POST /api/access-reviews/decision -- record ONE attestation decision (Approve /
        # Deny / DontKnow) against a Graph accessReview instance decision item (§H7).
        # Admin+, audited, mandatory justification, one decision at a time (NO bulk
        # auto-approve). DEGRADES GRACEFULLY: recording a decision needs
        # AccessReview.ReadWrite.All on the Manager MI, which is NOT yet granted -- a 403
        # on the PATCH is surfaced as an honest "permission not granted yet" state (HTTP
        # 200 with ok=$false + permissionMissing=$true), never a crash.
        if ($path -eq '/api/access-reviews/decision' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to record an access-review decision.' }
                return 403
            }
            $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
            if (-not (Get-Command Set-PimAccessReviewDecision -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $shared)) {
                Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            }
            if (-not (Get-Command Set-PimAccessReviewDecision -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = 'access-review library not loaded' }
                return 500
            }
            $body = Read-RequestJson -Request $req
            $defId  = "$($body.definitionId)".Trim()
            $instId = "$($body.instanceId)".Trim()
            $decId  = "$($body.decisionId)".Trim()
            $outcome= "$($body.outcome)".Trim()
            $just   = "$($body.justification)".Trim()
            if (-not $defId -or -not $instId -or -not $decId) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'definitionId, instanceId and decisionId are all required' }
                return 400
            }
            if (-not $outcome) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'outcome (Approve|Deny|DontKnow) is required' }; return 400 }
            if (-not $just)    { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'justification is required (attestations must be justified)' }; return 400 }
            try {
                $me  = (Get-PimManagerRole).identity
                Initialize-PimManagerTenantConnection
                $r = Set-PimAccessReviewDecision -DefinitionId $defId -InstanceId $instId -DecisionId $decId -Outcome $outcome -Justification $just -DecidedBy "$me"
                Write-PimManagerAuditEvent -Action 'access-review.decision' -Target "$defId/$instId/$decId" -After @{ outcome = "$($r.decision)"; status = "$($r.status)"; decidedBy = "$me" }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; status = "$($r.status)"; decision = "$($r.decision)"; decisionId = "$($r.decisionId)" })
                return 200
            } catch {
                $msg = "$($_.Exception.Message)"
                # AccessReview.ReadWrite.All not granted yet -> honest, non-crashing state.
                $permMissing = ($msg -match '(?i)403|forbidden|AccessReview|Authorization_RequestDenied|insufficient|privileg')
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok = $false
                    permissionMissing = [bool]$permMissing
                    error = $msg
                    note  = $(if ($permMissing) { 'Recording access-review decisions needs AccessReview.ReadWrite.All on the Manager identity, which is not granted yet. Grant it (setup/Grant-PimGraphAppRoles.ps1) to enable Approve/Deny here.' } else { $msg })
                })
                return 200
            }
        }

        # POST /api/access-reviews/reviewers -- assign / replace the reviewer scope of an
        # access-review DEFINITION (who is asked to attest) (§H7). Admin+, audited.
        # DEGRADES GRACEFULLY: needs AccessReview.ReadWrite.All on the Manager MI -- a 403
        # is surfaced as an honest "permission not granted yet" state (200, ok=$false).
        if ($path -eq '/api/access-reviews/reviewers' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to assign access-review reviewers.' }
                return 403
            }
            $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
            if (-not (Get-Command Set-PimAccessReviewReviewers -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $shared)) {
                Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            }
            if (-not (Get-Command Set-PimAccessReviewReviewers -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = 'access-review library not loaded' }
                return 500
            }
            $body = Read-RequestJson -Request $req
            $defId = "$($body.definitionId)".Trim()
            $reviewers = @(@($body.reviewers) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
            if (-not $defId) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'definitionId is required' }; return 400 }
            if ($reviewers.Count -eq 0) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'at least one reviewer is required (a review with no reviewer can never be completed)' }; return 400 }
            try {
                $me = (Get-PimManagerRole).identity
                Initialize-PimManagerTenantConnection
                $r = Set-PimAccessReviewReviewers -DefinitionId $defId -Reviewers $reviewers -AssignedBy "$me"
                Write-PimManagerAuditEvent -Action 'access-review.assign-reviewers' -Target "$defId" -After @{ reviewers = @($r.reviewers); count = [int]$r.count; status = "$($r.status)"; assignedBy = "$me" }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; status = "$($r.status)"; count = [int]$r.count; reviewers = @($r.reviewers) })
                return 200
            } catch {
                $msg = "$($_.Exception.Message)"
                $permMissing = ($msg -match '(?i)403|forbidden|AccessReview|Authorization_RequestDenied|insufficient|privileg')
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok = $false; permissionMissing = [bool]$permMissing; error = $msg
                    note = $(if ($permMissing) { 'Assigning access-review reviewers needs AccessReview.ReadWrite.All on the Manager identity, which is not granted yet. Grant it (setup/Grant-PimGraphAppRoles.ps1).' } else { $msg })
                })
                return 200
            }
        }

        # POST /api/access-reviews/reminders -- send a reminder mail to the reviewers of
        # every review instance that is DUE for one (overdue/due-soon + pending, repeat
        # window respected) (§H7). Admin+, audited. Reuses the existing mail sender.
        # ?preview=1 (or no mail sender) -> dry-run (renders/decides, sends nothing).
        # Falls back to the seeded reminder preview offline so the button is never dead.
        if ($path -eq '/api/access-reviews/reminders' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to send access-review reminders.' }
                return 403
            }
            $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
            if (-not (Get-Command Send-PimAccessReviewReminders -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $shared)) {
                Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            }
            $body = Read-RequestJson -Request $req
            $preview = $false
            try { if ("$($body.preview)" -match '(?i)^(1|true|yes)$') { $preview = $true } } catch {}
            $pimOnly = $false
            try { if ("$($body.pimManagedOnly)" -match '(?i)^(1|true|yes)$') { $pimOnly = $true } } catch {}
            $rows = @(); $source = 'seed'; $note = ''
            if (Get-Command Send-PimAccessReviewReminders -ErrorAction SilentlyContinue) {
                try {
                    $me = (Get-PimManagerRole).identity
                    Initialize-PimManagerTenantConnection
                    if ($preview) { $rows = @(Send-PimAccessReviewReminders -PimManagedOnly:$pimOnly -WhatIf) }
                    else          { $rows = @(Send-PimAccessReviewReminders -PimManagedOnly:$pimOnly) }
                    if (@($rows).Count -gt 0) {
                        $source = 'live'
                        foreach ($row in @($rows | Where-Object { $_.sent })) {
                            Write-PimManagerAuditEvent -Action 'access-review.reminder' -Target "$($row.definitionId)/$($row.instanceId)" -After @{ recipients = @($row.recipients); window = "$($row.window)"; sentBy = "$me" }
                        }
                    }
                } catch { $note = "live reminder send unavailable: $($_.Exception.Message)" }
            }
            if (@($rows).Count -eq 0 -and (Get-Command Get-PimAccessReviewAttestationSeed -ErrorAction SilentlyContinue)) {
                try { $seed = Get-PimAccessReviewAttestationSeed; $rows = @($seed.Reminders); $source = 'seed'; if (-not $note) { $note = 'Showing seeded sample reminder preview (grant AccessReview.Read.All / set a mail sender to send for real).' } } catch {}
            }
            $dueCount = @($rows | Where-Object { $_.due -or $_.sent }).Count
            $sentCount = @($rows | Where-Object { $_.sent }).Count
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; source = $source; note = $note; preview = [bool]$preview; total = @($rows).Count; dueCount = [int]$dueCount; sentCount = [int]$sentCount; rows = @($rows) })
            return 200
        }

        # GET /api/access-reviews/overdue -- read-only "needs attention" list (overdue /
        # due-soon access-review instances). Falls back to the seeded attestation rows
        # (real shaper) when the live read is unavailable, so the badge is never dead.
        if ($path -eq '/api/access-reviews/overdue' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
            if (-not (Get-Command Get-PimAccessReviewOverdue -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $shared)) {
                Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            }
            $pimOnly = $false
            try { if ($req.Url.Query -and $req.Url.Query.IndexOf('pimManagedOnly=1') -ge 0) { $pimOnly = $true } } catch {}
            $rows = @(); $source = 'seed'; $note = ''
            if (Get-Command Get-PimAccessReviewOverdue -ErrorAction SilentlyContinue) {
                try {
                    Initialize-PimManagerTenantConnection
                    $rows = @(Get-PimAccessReviewOverdue -PimManagedOnly:$pimOnly)
                    if (@($rows).Count -gt 0) { $source = 'live' }
                } catch { $note = "live overdue read unavailable: $($_.Exception.Message)" }
            }
            if (@($rows).Count -eq 0 -and (Get-Command Get-PimAccessReviewAttestationSeed -ErrorAction SilentlyContinue)) {
                try { $seed = Get-PimAccessReviewAttestationSeed; $rows = @($seed.Overdue); $source = 'seed'; if (-not $note) { $note = 'Showing seeded sample data (grant AccessReview.Read.All or create reviews).' } } catch {}
            }
            $overdueCount = @($rows | Where-Object { $_.IsOverdue }).Count
            $dueSoonCount = @($rows | Where-Object { $_.IsDueSoon }).Count
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ source = $source; note = $note; total = @($rows).Count; overdueCount = [int]$overdueCount; dueSoonCount = [int]$dueSoonCount; rows = @($rows) })
            return 200
        }

        # GET /api/access-reviews/evidence?definitionId=&instanceId= -- the exportable
        # evidence package for one review instance (header + per-principal decisions +
        # tally). Read-only. Seed fallback so the export is never empty offline.
        if ($path -eq '/api/access-reviews/evidence' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
            if (-not (Get-Command Get-PimAccessReviewEvidence -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $shared)) {
                Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            }
            $defId = ''; $instId = ''
            try {
                $q = $req.Url.Query
                if ($q -match 'definitionId=([^&]+)') { $defId  = [System.Uri]::UnescapeDataString($Matches[1]) }
                if ($q -match 'instanceId=([^&]+)')   { $instId = [System.Uri]::UnescapeDataString($Matches[1]) }
            } catch {}
            $pkg = $null; $source = 'seed'; $note = ''
            if ($defId -and (Get-Command Get-PimAccessReviewEvidence -ErrorAction SilentlyContinue)) {
                try {
                    Initialize-PimManagerTenantConnection
                    $pkg = Get-PimAccessReviewEvidence -DefinitionId $defId -InstanceId $instId
                    if ($pkg) { $source = 'live' }
                } catch { $note = "live evidence read unavailable: $($_.Exception.Message)" }
            }
            if (-not $pkg -and (Get-Command Get-PimAccessReviewAttestationSeed -ErrorAction SilentlyContinue)) {
                try { $seed = Get-PimAccessReviewAttestationSeed; $pkg = $seed.Evidence; $source = 'seed'; if (-not $note) { $note = 'Showing seeded sample evidence (grant AccessReview.Read.All or create reviews).' } } catch {}
            }
            if (-not $pkg) { Write-JsonResponse -Response $resp -Status 404 -Body @{ error = 'no evidence available (definitionId required for a live read)'; note = $note }; return 404 }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ source = $source; note = $note; evidence = $pkg })
            return 200
        }

        # Access Review overview (read-only). Surfaces the engine's access-review
        # data layer (engine/_shared/PIM-AccessReviews.ps1 -> Get-PimAccessReviewOverview)
        # for the "Access Review" GUI tab: review name, scope/target, reviewers,
        # recurrence, current-instance status + due date, pending/approved/denied
        # counts. Strictly read-only (no decisions recorded). When the live call
        # returns nothing (AccessReview.Read.All not granted yet, no reviews, or no
        # live connection) the endpoint falls back to seeded rows produced by the
        # REAL normalizer (Get-PimAccessReviewSeedRows) so the tab is never dead;
        # `source` tells the GUI whether it is showing live or seeded data.
        if ($path -eq '/api/access-reviews' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
            if (-not (Get-Command Get-PimAccessReviewOverview -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $shared)) {
                Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            }
            $pimOnly = $false
            $withCounts = $true
            $forceSeed = $false
            try {
                $q = $req.Url.Query
                if ($q) {
                    if ($q.IndexOf('pimManagedOnly=1') -ge 0) { $pimOnly = $true }
                    if ($q.IndexOf('counts=0') -ge 0)         { $withCounts = $false }
                    if ($q.IndexOf('seed=1') -ge 0)           { $forceSeed = $true }
                }
            } catch { }

            $rows   = @()
            $source = 'seed'
            $note   = ''
            if (-not $forceSeed -and (Get-Command Get-PimAccessReviewOverview -ErrorAction SilentlyContinue)) {
                try {
                    Initialize-PimManagerTenantConnection
                    $rows = @(Get-PimAccessReviewOverview -PimManagedOnly:$pimOnly -IncludeDecisionCounts:$withCounts)
                    if (@($rows).Count -gt 0) { $source = 'live' }
                } catch {
                    $note = "live access-review read unavailable: $($_.Exception.Message)"
                }
            }
            if (@($rows).Count -eq 0 -and (Get-Command Get-PimAccessReviewSeedRows -ErrorAction SilentlyContinue)) {
                $rows = @(Get-PimAccessReviewSeedRows)
                if ($pimOnly) { $rows = @($rows | Where-Object { $_.IsPimManaged }) }
                $source = 'seed'
                if (-not $note) { $note = 'No access reviews returned from the tenant (grant AccessReview.Read.All or create reviews). Showing seeded sample data.' }
            }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                source = $source
                note   = $note
                total  = @($rows).Count
                rows   = @($rows)
            })
            return 200
        }

        # ----- Jobs tab: scheduled + recent jobs (read-only) -------------------
        # Joins the REAL scheduler job registry (Get-PimJobSchedule), the persisted
        # scheduler state (last/next run) and the run-history ring the scheduler writes.
        # The Manager NEVER runs a job here -- this is a pure read. The scheduler shares
        # its state/history with this process via SQL pim.Settings when SQL is wired
        # (hosted), otherwise via a JSON file under the instance output dir.
        if ($path -eq '/api/jobs' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command Get-PimJobsStatus -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ jobs = @(); total = 0; runningCount = 0; note = 'scheduler library not loaded' }
                return 200
            }
            # The scheduler read model reads SQL pim.Settings (SchedulerState / JobRunHistory) -- no state file.
            try {
                # Drive the read model with the EFFECTIVE schedule (defaults + stored
                # per-job enabled/cadence overrides) so inline edits via /api/jobs/state
                # show up here immediately, in this Manager instance, without waiting for
                # the scheduler to rewrite its state file.
                $effective = @(Get-PimManagerEffectiveSchedule)
                $vm = if ($effective.Count -gt 0) { Get-PimJobsStatus -Jobs $effective } else { Get-PimJobsStatus }
                # Has the scheduler ever recorded a run we can join to? When the history
                # ring is empty (fresh deployment, or the scheduler has not ticked / is
                # not co-located), every row is "never run" -- the GUI shows an explicit
                # "no runs yet" banner instead of looking dead. canRun gates the per-row
                # "Run now" + edit controls to Admin+.
                $histCount = 0
                try { if (Get-Command Get-PimJobRunHistory -ErrorAction SilentlyContinue) { $histCount = @(Get-PimJobRunHistory).Count } } catch {}
                $body = [ordered]@{
                    jobs         = @($vm.jobs)
                    total        = [int]$vm.total
                    runningCount = [int]$vm.runningCount
                    overdueCount = $(if ($vm.PSObject.Properties['overdueCount']) { [int]$vm.overdueCount } else { 0 })
                    failingCount = $(if ($vm.PSObject.Properties['failingCount']) { [int]$vm.failingCount } else { 0 })
                    generatedUtc = "$($vm.generatedUtc)"
                    historyCount = [int]$histCount
                    canRun       = [bool](Test-PimManagerRoleAtLeast -Minimum 'Admin')
                }
                if ($histCount -eq 0) { $body.note = 'no runs recorded yet -- the scheduler has not run any job, or its run history is not shared with this instance. Next-run times are computed from each job''s cadence. Use "Run now" to execute a job immediately.' }
                Write-JsonResponse -Response $resp -Status 200 -Body $body
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # ----- Jobs tab: per-job state (enable/disable + cadence) inline -------
        # PUT one job's enabled flag and/or intervalMinutes. Persists to the SAME
        # 'JobSchedule' store the real scheduler reads (Set-PimManagerSetting +
        # $global:PIM_JobSchedule mirror), so the change is honoured by the in-process
        # runner and a freshly-booted scheduler alike. Admin+ only; unknown job names
        # rejected (the catalog is fixed by the engine). Mirrors /api/job-schedule's
        # merge but scoped to a single row so the Jobs tab can edit inline.
        if ($path -eq '/api/jobs/state' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to change a job''s schedule or state.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $name = "$($body.name)".Trim()
            if (-not $name) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'name is required' }; return 400 }
            # Resolve the effective schedule, find the row, apply the requested changes.
            $eff = @(Get-PimManagerEffectiveSchedule)
            $row = @($eff | Where-Object { "$($_.name)" -eq $name }) | Select-Object -First 1
            if (-not $row) { Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown job '$name'" }; return 404 }
            $en = [bool]$row.enabled
            $iv = [int]$row.intervalMinutes
            if ($body.PSObject.Properties['enabled'])         { $en = [bool]$body.enabled }
            if ($body.PSObject.Properties['intervalMinutes'] -and "$($body.intervalMinutes)".Trim()) {
                $iv = [Math]::Max(1, [Math]::Min(43200, [int]$body.intervalMinutes))   # 1 min .. 30 days
            }
            # Rebuild the full stored override set (every job carries enabled+cadence) so
            # the store is a complete, self-describing schedule the scheduler can load.
            $merged = New-Object System.Collections.ArrayList
            foreach ($j in $eff) {
                $jEn = [bool]$j.enabled; $jIv = [int]$j.intervalMinutes
                if ("$($j.name)" -eq $name) { $jEn = $en; $jIv = $iv }
                $entry = [ordered]@{ name = "$($j.name)"; type = "$($j.type)"; enabled = $jEn; intervalMinutes = $jIv }
                if ($j.PSObject.Properties['scope'] -and "$($j.scope)".Trim()) { $entry.scope = "$($j.scope)" }
                [void]$merged.Add([pscustomobject]$entry)
            }
            Set-PimManagerSetting -Name 'JobSchedule' -Value @($merged.ToArray())
            $global:PIM_JobSchedule = @($merged.ToArray())   # live in-process runner picks it up
            Write-PimManagerAuditEvent -Action 'schedule.job.state' -Target "job:$name" -After @{ enabled = $en; intervalMinutes = $iv } -Result 'ok'
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; name = $name; enabled = $en; intervalMinutes = $iv })
            return 200
        }

        # ----- Jobs tab: FORCE-START a job now ("Run now") --------------------
        # POST { name } -> run that job immediately through the REAL scheduler
        # (Invoke-PimJobForceStart): writes an in-progress record then the finished
        # record to the same run-history ring /api/jobs + /api/jobs/log read, so the
        # operator sees the job move running -> completed with its log. Admin+ only.
        # The Manager dispatches via the handlers registered in THIS process; an
        # unregistered job type records a clear no-handler run (never crashes).
        if ($path -eq '/api/jobs/run' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to run a job.' }
                return 403
            }
            if (-not (Get-Command Invoke-PimJobForceStart -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $false; note = 'scheduler library not loaded' }
                return 200
            }
            $body = Read-RequestJson -Request $req
            $name = "$($body.name)".Trim()
            if (-not $name) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'name is required' }; return 400 }
            # Resolve the job from the effective schedule so it carries the live cadence/scope.
            $eff = @(Get-PimManagerEffectiveSchedule)
            $job = @($eff | Where-Object { "$($_.name)" -eq $name }) | Select-Object -First 1
            if (-not $job) { Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown job '$name'" }; return 404 }

            # 🔴 BUG-114 (second half, 2026-08-31). "Run now" dispatches through the handlers
            # registered in THIS process, and the Manager registers NONE for the engine job
            # types -- the real engine handler is wired by tools/pim-scheduler/Start-PimScheduler.ps1
            # (the tick / VisualCron), not here. So clicking Run now on full-reconcile could only
            # ever write a run that did nothing, and then report it.
            # 🔑 REFUSE, rather than run-and-report-honestly. This is not the Manager being
            # cautious -- it is §22: THE ENGINE IS THE ONLY WRITER. Registering the real engine
            # handler in the web process to "make the button work" would turn the Manager into an
            # engine writer and put tenant writes on an HTTP request thread. The button is the
            # thing that is wrong, not the reporting.
            $_engineTypes = @('engine-delta','engine-full','msp-pull') + @('active-assignments-snapshot') + @('drift-snapshot') + @('verify-convergence','discovery')
            # 🔒 2026-09-14 (operator: Run now on verify-convergence recorded "not implemented" and turned the job red): every
            # type whose real handler only Start-PimScheduler registers is queued -- verify-convergence and discovery too.
            # The scheduler's own list (Get-PimTickOnlyJobTypes) wins when it names more, so the two cannot drift apart.
            if (Get-Command Get-PimTickOnlyJobTypes -ErrorAction SilentlyContinue) { $_engineTypes = @(@($_engineTypes) + @(Get-PimTickOnlyJobTypes) | Select-Object -Unique) }
            # 🔒 Drift page (2026-09-14): 'drift-snapshot' is a full engine plan over every scope -- queued, never run here.
            # 🔒 §70.1b option 2: 'active-assignments-snapshot' is queued for the same reason -- run here it would
            # be a 140-170 s live Graph/ARM read on this process's ONE request loop, the exact freeze it exists to
            # remove. (Its real handler is only registered by Start-PimScheduler anyway.)
            # 🔴 §70.19 (2026-09-13, measured on internal): the refusal above keyed on
            # `Get-Command Invoke-PimEngine` -- and the HOSTED Manager DOES load Invoke-PimEngine (for
            # the drift WhatIf). So the guard passed, the run went to the placeholder handler, and the
            # operator's "Run now" on delta-pim-azure and delta-groups-deploy recorded
            # `completed` / `unimplemented ... no real handler registered on this worker` -- green,
            # having done nothing, while the operator waited for a group that was never created.
            # 🔑 The Manager still never runs the engine (§22). "Run now" on an engine job now QUEUES it
            # for the scheduler: a persisted trigger (pim.Settings['SchedulerTriggers']) that the next
            # tick drains as `trigger:<type>:<scope>` -- the same path a commit uses. Honest status:
            # queued, not completed.
            if ("$($job.type)" -in $_engineTypes) {
                $jobScope = if ($job.PSObject.Properties['scope'] -and "$($job.scope)".Trim()) { "$($job.scope)" } else { 'All' }
                $queued = $false; $qErr = ''
                if (Get-Command Add-PimJobTrigger -ErrorAction SilentlyContinue) {
                    # (who pressed it is on the audit event below; the trigger only needs the job)
                    try { [void](Add-PimJobTrigger -Type "$($job.type)" -Scope $jobScope -Reason "run-now:$name"); $queued = $true }
                    catch { $qErr = "$($_.Exception.Message)" }
                } else { $qErr = 'scheduler trigger queue not loaded' }
                Write-PimManagerAuditEvent -Action 'schedule.job.run.queued' -Target "job:$name" -After @{ type = "$($job.type)"; scope = $jobScope; queued = $queued; error = $qErr } -Result $(if ($queued) { 'ok' } else { 'error' })
                if (-not $queued) {
                    Write-JsonResponse -Response $resp -Status 503 -Body @{ error = "Could not queue '$name' for the scheduler: $qErr"; code = 'not-queued' }
                    return 503
                }
                # §70.21: and start the tick job now instead of waiting for its next cron start.
                $kick = Start-PimManagerTickNow -Reason "run-now:$name"
                Write-JsonResponse -Response $resp -Status 202 -Body ([ordered]@{
                    ok     = $true
                    name   = $name
                    runId  = ''
                    status = 'queued'
                    started = [bool]$kick.started
                    detail = $(if ($kick.started) { "queued as trigger:$($job.type):$jobScope and $($kick.detail) -- it starts within about a minute. The Manager never runs the engine itself." } else { "queued as trigger:$($job.type):$jobScope -- $($kick.detail). The Manager never runs the engine itself." })
                })
                return 202
            }

            try {
                $r = Invoke-PimJobForceStart -Name $name -Job $job
                Write-PimManagerAuditEvent -Action 'schedule.job.run' -Target "job:$name" -After @{ runId = "$($r.runId)"; status = "$($r.status)" } -Result $(if ($r.ok) { 'ok' } else { 'error' })
                # ALERT-01: engine-failure used to be fired HERE, and ONLY here -- which is
                # exactly why it never fired for a scheduled run. It now fires from the two
                # real run-completion points in PIM-Scheduler.ps1, including the force-start
                # this handler just invoked. Re-adding a call here would double-alert: the
                # alert is a property of the RUN, not of the endpoint that launched it.
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok     = [bool]$r.ok
                    name   = $name
                    runId  = "$($r.runId)"
                    status = "$($r.status)"
                    detail = "$($r.detail)"
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # ----- Jobs tab: read one run's log by runId ---------------------------
        if ($path -eq '/api/jobs/log' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $runId = ''
            if ($req.Url.Query -match '(\?|&)runId=([\w\-]+)') { $runId = "$($Matches[2])" }
            if (-not "$runId".Trim()) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'runId query parameter is required' }
                return 400
            }
            if (-not (Get-Command Get-PimJobRunLog -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ runId = $runId; log = ''; note = 'scheduler library not loaded' }
                return 200
            }
            try {
                $rec = Get-PimJobRunLog -RunId $runId
                if (-not $rec) {
                    Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "no run found for runId '$runId'" }
                    return 404
                }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    runId       = "$($rec.runId)"
                    name        = "$($rec.name)"
                    type        = "$($rec.type)"
                    status      = "$($rec.status)"
                    ok          = [bool]$rec.ok
                    startedUtc  = "$($rec.startedUtc)"
                    finishedUtc = "$($rec.finishedUtc)"
                    log         = "$($rec.log)"
                    # 2026-09-14: the lines the run printed are part of `log`; this says how many (0 = summary only).
                    outputLines = $(if ($rec.PSObject.Properties['outputLines']) { [int]$rec.outputLines } else { 0 })
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # ----- Jobs tab [M6]: failure history (recent runs + pass/fail/when) ----
        # GET /api/jobs/history?name=<job>[&take=N] -> the recent finished runs for one
        # job, newest-first, each flagged ok/failed + acknowledged, with the failed subset
        # surfaced. Read-only (the scheduler owns the records). Powers the per-job "History"
        # drill-down + the failure list so an admin can tell whether a run FAILED or never
        # fired. (REQUIREMENTS.md §28 [M6].)
        if ($path -eq '/api/jobs/history' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $name = ''
            if ($req.Url.Query -match '(\?|&)name=([^&]+)') { $name = [System.Uri]::UnescapeDataString("$($Matches[2])") }
            $take = 10
            if ($req.Url.Query -match '(\?|&)take=(\d+)') { $take = [Math]::Max(1, [Math]::Min(50, [int]$Matches[2])) }
            if (-not (Get-Command Get-PimJobFailureHistory -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ runs = @(); failures = @(); total = 0; note = 'scheduler library not loaded' }
                return 200
            }
            try {
                $fh = Get-PimJobFailureHistory -Name $name -Take $take
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    name            = "$name"
                    runs            = @($fh.runs)
                    failures        = @($fh.failures)
                    failureCount    = [int]$fh.failureCount
                    unackedFailures = [int]$fh.unackedFailures
                    total           = [int]$fh.total
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # ----- Jobs tab [M6]: acknowledge / clear a run --------------------------
        # POST { runId; clear? } -> mute (or un-mute with clear:true) a failed/overdue run
        # so the operator can clear the signal once a failure is understood/handled. The
        # run RECORD is never deleted (audit stays intact); only its failure/overdue badge
        # is suppressed. Admin+ only. (REQUIREMENTS.md §28 [M6].)
        # ----- Engine logs & errors: the CURRENTLY FAILING items, classified ------
        # GET /api/engine-failures -> every item the engine failed to apply on its last run of each
        # scope, with code/title/cause/remedy/fixes and first-seen/last-seen/count. Read-only: a fix is
        # staged client-side into Pending changes and committed by an operator (§65 -- the Manager
        # never writes the directory, and never writes desired state without a commit).
        if ($path -eq '/api/engine-failures' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command Get-PimEngineItemFailures -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ readable = $false; items = @(); error = 'the failure catalog (PIM-FailureCatalog.ps1) is not loaded in this host' }
                return 200
            }
            $items = @(Get-PimEngineItemFailures)
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                readable = $true
                total    = $items.Count
                items    = @($items)
            })
            return 200
        }

        # ----- Azure policy MASS-CHANGE HOLD (BUG-55 breaker): read + approve ONE plan -------------
        # The engine HOLDS (writes nothing) when a run would change too many Azure resource PIM policies
        # or weaken them, and records the hold in SQL (pim.Settings 'AzResPolicyMassHold'). An Admin
        # reviews the plan here and approves EXACTLY that plan hash; the next engine run applies it only
        # if the hash is unchanged. The engine functions live in PIM-EngineProviders.ps1, which the
        # Manager does not load at boot -- it is dot-sourced into an ISOLATED child scope per call, so no
        # engine function can shadow a Manager one. Get-/Set-PimSetting resolve to the Manager's SQL bridge.
        if (($path -eq '/api/engine/azres-policy-hold' -and $method -eq 'GET') -or ($path -eq '/api/engine/azres-policy-approve' -and $method -eq 'POST')) {
            $script:lastHeartbeat = Get-Date
            $engLib = Join-Path $solutionRoot 'engine\_shared\PIM-EngineProviders.ps1'
            if ($method -eq 'GET') {
                try {
                    $hold = & { if (-not (Get-Command Get-PimAzResPolicyMassHold -ErrorAction SilentlyContinue)) { . $engLib }; Get-PimAzResPolicyMassHold }
                } catch {
                    Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "could not read the Azure policy hold: $($_.Exception.Message)" }
                    return 500
                }
                if (-not $hold) { $resp.StatusCode = 204; $resp.OutputStream.Close(); return 204 }
                Write-JsonResponse -Response $resp -Status 200 -Body $hold
                return 200
            }
            # POST approve -- Admin+, audited with the hold (Before) and the approval record (After).
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to approve an Azure policy change set.' }
                return 403
            }
            $bodyIn = Read-RequestJson -Request $req
            $planHash = "$($bodyIn.planHash)".Trim()
            if (-not $planHash) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'planHash is required' }; return 400 }
            $who = "$(Get-PimManagerActor)"
            $holdBefore = $null
            try {
                $out = & {
                    param($h, $by)
                    if (-not (Get-Command Approve-PimAzResPolicyMassChange -ErrorAction SilentlyContinue)) { . $engLib }
                    $before = Get-PimAzResPolicyMassHold
                    $current = [bool]($before -and "$($before.planHash)".Trim().ToLowerInvariant() -eq "$h".Trim().ToLowerInvariant())
                    $rec = $null
                    if ($current) { $rec = Approve-PimAzResPolicyMassChange -PlanHash $h -By $by }
                    [pscustomobject]@{ before = $before; current = $current; record = $rec }
                } $planHash $who
            } catch {
                Write-PimManagerAuditEvent -Action 'azres.policy.masschange.approve' -Target 'AzResPolicies' -Result 'error' -After @{ planHash = $planHash; error = "$($_.Exception.Message)" }
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
            $holdBefore = $out.before
            if (-not $out.current) {
                Write-PimManagerAuditEvent -Action 'azres.policy.masschange.approve' -Target 'AzResPolicies' -Result 'denied' `
                    -Before $(if ($holdBefore) { [ordered]@{ planHash = "$($holdBefore.planHash)"; changes = $holdBefore.changes; weakening = $holdBefore.weakening } } else { $null }) `
                    -After @{ planHash = $planHash; reason = 'not the current hold' }
                Write-JsonResponse -Response $resp -Status 409 -Body ([ordered]@{ ok = $false; error = 'This plan hash is not the current Azure policy hold -- the plan changed or the hold was cleared. Reload and review the current plan.'; currentPlanHash = $(if ($holdBefore) { "$($holdBefore.planHash)" } else { $null }) })
                return 409
            }
            Write-PimManagerAuditEvent -Action 'azres.policy.masschange.approve' -Target 'AzResPolicies' -Result 'ok' `
                -Before ([ordered]@{ planHash = "$($holdBefore.planHash)"; changes = $holdBefore.changes; checked = $holdBefore.checked; weakening = $holdBefore.weakening; tripped = @($holdBefore.tripped) }) `
                -After $out.record
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; approval = $out.record })
            return 200
        }

        # ----- Graph policy MASS-CHANGE HOLD (GroupsPolicies / EntraRolePolicies; operator 2026-09-13) -------
        # Same breaker and the same contract as the Azure one above, one hold + one approval record PER
        # PROVIDER (an approval of one provider's plan never covers another's). GET ?provider=<name> returns
        # that provider's current hold or 204; POST { provider, planHash } is Admin+, audited, 409 on a hash
        # that is not that provider's current hold.
        if (($path -eq '/api/engine/policy-hold' -and $method -eq 'GET') -or ($path -eq '/api/engine/policy-approve' -and $method -eq 'POST')) {
            $script:lastHeartbeat = Get-Date
            $engLib = Join-Path $solutionRoot 'engine\_shared\PIM-EngineProviders.ps1'
            $graphProviders = @('GroupsPolicies', 'EntraRolePolicies')
            if ($method -eq 'GET') {
                $prov = "$($req.QueryString['provider'])".Trim()
                $prov = @($graphProviders | Where-Object { $_ -ieq $prov })[0]
                if (-not $prov) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "provider must be one of: $($graphProviders -join ', ')" }; return 400 }
                try {
                    $hold = & { param($p) if (-not (Get-Command Get-PimPolicyMassHold -ErrorAction SilentlyContinue)) { . $engLib }; Get-PimPolicyMassHold -Provider $p } $prov
                } catch {
                    Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "could not read the $prov policy hold: $($_.Exception.Message)" }
                    return 500
                }
                if (-not $hold) { $resp.StatusCode = 204; $resp.OutputStream.Close(); return 204 }
                Write-JsonResponse -Response $resp -Status 200 -Body $hold
                return 200
            }
            # POST approve -- Admin+, audited with the hold (Before) and the approval record (After).
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to approve a policy change set.' }
                return 403
            }
            $bodyIn = Read-RequestJson -Request $req
            $prov = @($graphProviders | Where-Object { $_ -ieq "$($bodyIn.provider)".Trim() })[0]
            if (-not $prov) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "provider must be one of: $($graphProviders -join ', ')" }; return 400 }
            $planHash = "$($bodyIn.planHash)".Trim()
            if (-not $planHash) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'planHash is required' }; return 400 }
            $auditAction = if ($prov -eq 'GroupsPolicies') { 'groups.policy.masschange.approve' } else { 'entrarole.policy.masschange.approve' }
            $who = "$(Get-PimManagerActor)"
            try {
                $out = & {
                    param($p, $h, $by)
                    if (-not (Get-Command Approve-PimPolicyMassChange -ErrorAction SilentlyContinue)) { . $engLib }
                    $before = Get-PimPolicyMassHold -Provider $p
                    $current = [bool]($before -and "$($before.planHash)".Trim().ToLowerInvariant() -eq "$h".Trim().ToLowerInvariant())
                    $rec = $null
                    if ($current) { $rec = Approve-PimPolicyMassChange -Provider $p -PlanHash $h -By $by }
                    [pscustomobject]@{ before = $before; current = $current; record = $rec }
                } $prov $planHash $who
            } catch {
                Write-PimManagerAuditEvent -Action $auditAction -Target $prov -Result 'error' -After @{ planHash = $planHash; error = "$($_.Exception.Message)" }
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
            $holdBefore = $out.before
            if (-not $out.current) {
                Write-PimManagerAuditEvent -Action $auditAction -Target $prov -Result 'denied' `
                    -Before $(if ($holdBefore) { [ordered]@{ planHash = "$($holdBefore.planHash)"; changes = $holdBefore.changes; weakening = $holdBefore.weakening } } else { $null }) `
                    -After @{ planHash = $planHash; reason = 'not the current hold' }
                Write-JsonResponse -Response $resp -Status 409 -Body ([ordered]@{ ok = $false; error = "This plan hash is not the current $prov policy hold -- the plan changed or the hold was cleared. Reload and review the current plan."; currentPlanHash = $(if ($holdBefore) { "$($holdBefore.planHash)" } else { $null }) })
                return 409
            }
            Write-PimManagerAuditEvent -Action $auditAction -Target $prov -Result 'ok' `
                -Before ([ordered]@{ planHash = "$($holdBefore.planHash)"; changes = $holdBefore.changes; checked = $holdBefore.checked; weakening = $holdBefore.weakening; tripped = @($holdBefore.tripped) }) `
                -After $out.record
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; approval = $out.record })
            return 200
        }

        if ($path -eq '/api/jobs/ack' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to acknowledge a job run.' }
                return 403
            }
            if (-not (Get-Command Set-PimRunAcknowledged -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $false; note = 'scheduler library not loaded' }
                return 200
            }
            $body = Read-RequestJson -Request $req
            $runId = "$($body.runId)".Trim()
            if (-not $runId) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'runId is required' }; return 400 }
            $clear = $false; if ($body.PSObject.Properties['clear']) { $clear = [bool]$body.clear }
            try {
                $r = Set-PimRunAcknowledged -RunId $runId -Clear:$clear
                Write-PimManagerAuditEvent -Action 'schedule.job.ack' -Target "run:$runId" -After @{ acknowledged = [bool]$r.acknowledged } -Result $(if ($r.ok) { 'ok' } else { 'error' })
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok           = [bool]$r.ok
                    runId        = "$($r.runId)"
                    acknowledged = [bool]$r.acknowledged
                    changed      = [bool]$r.changed
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # ----- Home / Overview tab: one aggregated read (REQUIREMENTS §26a/§27 H2) -----
        # Correlates the EXISTING engine/validator/scheduler/audit sources into the
        # landing-page tiles. ?include=heavy adds the live active-assignments + access
        # reviews tiles (the GUI lazy-loads those after the fast tiles render). Every
        # tile is real-data-or-honest-empty; one bad source never blanks the page.
        if ($path -eq '/api/home' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $heavy = $false
            try { if ("$($req.Url.Query)".IndexOf('include=heavy') -ge 0) { $heavy = $true } } catch {}
            try {
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimHomeOverview -IncludeHeavy:$heavy)
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # =====================================================================
        # Visibility & reporting (REQUIREMENTS §26a). All three read endpoints
        # below are engine/SQL-backed (Build-PimGraphData -> the live delegation
        # model). Read-only; no writes. Reader role is sufficient (the visibility
        # scoping in Read-PimRows already limits a Delegated reader's view).
        # =====================================================================

        # "Who can do what" -- forward: a person -> everything they can reach,
        # WITH the activation path. ?person=<UserPrincipalName>.
        if ($path -eq '/api/access-report/who-can' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $person = ''
            if ($req.Url.Query -match '(\?|&)person=([^&]+)') { $person = [uri]::UnescapeDataString($Matches[2]) }
            if (-not "$person".Trim()) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'person query parameter is required' }
                return 400
            }
            try {
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimReachableTargets -Person "$person")
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # Reverse: a role/target -> who can activate it. ?role=<name or node id>
        # (optional &kind=entra-role|au-role|az-resource to disambiguate).
        if ($path -eq '/api/access-report/who-has' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $role = ''; $kind = ''
            if ($req.Url.Query -match '(\?|&)role=([^&]+)') { $role = [uri]::UnescapeDataString($Matches[2]) }
            if ($req.Url.Query -match '(\?|&)kind=([^&]+)') { $kind = [uri]::UnescapeDataString($Matches[2]) }
            if (-not "$role".Trim()) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'role query parameter is required' }
                return 400
            }
            try {
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimRoleReachers -Role "$role" -Kind "$kind")
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # Tier-impact report (REQUIREMENTS §23 / ROADMAP #24): every user with ANY
        # path (incl. indirect via nested groups) to a Tier-0/Tier-1 target.
        # Optional &tier=0 narrows to Tier-0 only (default = Tier-0 OR Tier-1).
        if ($path -eq '/api/tier-impact' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $hiMax = 1
            if ($req.Url.Query -match '(\?|&)tier=([0-5])') { $hiMax = [int]$Matches[2] }
            try {
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimTierImpactReportLive -HighTierMax $hiMax)
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # Global search across people / groups / roles / scopes / tags. ?q=<text>
        if ($path -eq '/api/search' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $q = ''
            if ($req.Url.Query -match '(\?|&)q=([^&]+)') { $q = [uri]::UnescapeDataString($Matches[2]) }
            if (-not "$q".Trim()) {
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ query = ''; count = 0; hits = @(); truncated = $false })
                return 200
            }
            try {
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimGlobalSearch -Query "$q")
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # Delegation Map risk overlay (REQUIREMENTS §28 [M8]) -- per-node orphan /
        # stale / over-privileged classification computed from the SAME live graph
        # model the Map renders (Build-PimGraphData). Read-only.
        if ($path -eq '/api/map-risk' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                $data = Build-PimGraphData
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimMapRiskOverlay -Data $data)
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # Delegation Map search -> ordered result LIST the operator clicks to JUMP
        # (center + select) a node. ?q=<text>. Same graph model as the Map.
        if ($path -eq '/api/map-search' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $q = ''
            if ($req.Url.Query -match '(\?|&)q=([^&]+)') { $q = [uri]::UnescapeDataString($Matches[2]) }
            try {
                $data = Build-PimGraphData
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimMapSearchResults -Data $data -Query "$q")
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # ----- Alerting config (REQUIREMENTS §27 H2): recipients + which events fire ---
        if ($path -eq '/api/alerting' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimAlertingConfig)
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/alerting' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to change alerting. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $recips = @()
            if ($body -and $body.PSObject.Properties['recipients']) { $recips = @($body.recipients | ForEach-Object { "$_" }) }
            $events = @{}
            if ($body -and $body.PSObject.Properties['events']) {
                $ev = $body.events
                foreach ($e in $script:PimAlertEventCatalog) {
                    if ($ev.PSObject.Properties[$e]) { $events[$e] = [bool]$ev.PSObject.Properties[$e].Value }
                }
            }
            $webhookUrl = ''; $webhookKind = ''
            if ($body -and $body.PSObject.Properties['webhookUrl'])  { $webhookUrl  = "$($body.webhookUrl)" }
            if ($body -and $body.PSObject.Properties['webhookKind']) { $webhookKind = "$($body.webhookKind)" }
            $alertArgs = @{ Recipients = $recips; Events = $events; WebhookUrl = $webhookUrl; WebhookKind = $webhookKind }
            if ($body -and $body.PSObject.Properties['digestRecipients'])     { $alertArgs['DigestRecipients']     = @(@($body.digestRecipients) | Where-Object { $null -ne $_ } | ForEach-Object { "$_" }) }
            if ($body -and $body.PSObject.Properties['tierReportRecipients']) { $alertArgs['TierReportRecipients'] = @(@($body.tierReportRecipients) | Where-Object { $null -ne $_ } | ForEach-Object { "$_" }) }
            try {
                $alertBefore = $null; try { $b0 = Get-PimAlertingConfig; $alertBefore = [ordered]@{ recipients = @($b0.recipients).Count; digestRecipients = @($b0.digestRecipients); tierReportRecipients = @($b0.tierReportRecipients) } } catch {}
                $cfg = Set-PimAlertingConfig @alertArgs
                Write-PimManagerAuditEvent -Action 'alerting.save' -Target 'settings:alerting' -Before $alertBefore -After ([ordered]@{ recipients = @($cfg.recipients).Count; digestRecipients = @($cfg.digestRecipients); tierReportRecipients = @($cfg.tierReportRecipients); enabled = [bool]$cfg.enabled; webhook = "$($cfg.webhookKind)"; webhookEnabled = [bool]$cfg.webhookEnabled }) -Result 'ok'
                Write-JsonResponse -Response $resp -Status 200 -Body $cfg
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # Send a TEST alert through the real notify path so an admin can confirm the
        # wiring (or see the honest "configure a sender to enable" reason). Admin+.
        if ($path -eq '/api/alerting/test' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to send a test alert.' }
                return 403
            }
            try {
                # The test alert intentionally bypasses debounce so an operator always
                # sees a fresh result (and a fresh recorded-send-proof feed entry).
                $r = Send-PimManagerAlert -Event 'engine-failure' -Title 'PIM Manager test alert' -Detail 'This is a test alert sent from the Home/Settings alerting panel to confirm delivery.' -LinkTab 'home' -DebounceMinutes 0
                $ok = ($r.sent -gt 0)
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok         = $ok
                    fired      = [bool]$r.fired
                    sent       = [int]$r.sent
                    recipients = @($r.recipients)
                    reason     = "$($r.reason)"
                    recorded   = [bool]$r.recorded
                    note       = $(if ($ok) { "Test alert sent to $([int]$r.sent) recipient(s)." } else { "Not sent: $($r.reason). Configure a sender mailbox (`$global:PIM_MailSender`) and at least one recipient to enable delivery." })
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # ----- Alerts FEED (REQUIREMENTS §26c / §28 [H2] + [M5] residual): the durable,
        # queryable record of WHAT alerts fired -- when, which event, who was notified,
        # and whether delivery was recorded (the recorded-send proof). Read-only; any
        # authenticated viewer may read the feed (it carries no secrets). Optional
        # filters: ?event=<type> & ?sentOnly=1 & ?take=<n>.
        if ($path -eq '/api/alerts' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                $feed = Get-PimManagerAlertFeed
                $evFilter = "$($req.QueryString['event'])".Trim()
                $sentOnly = ("$($req.QueryString['sentOnly'])".Trim() -in @('1','true','yes'))
                $take = 100; if ("$($req.QueryString['take'])".Trim() -match '^\d+$') { $take = [int]$req.QueryString['take'] }
                $rows = if (Get-Command Select-PimAlertFeed -ErrorAction SilentlyContinue) {
                    Select-PimAlertFeed -Feed $feed -Event $evFilter -SentOnly:$sentOnly -Take $take
                } else { @() }
                $summary = if (Get-Command Get-PimAlertFeedSummary -ErrorAction SilentlyContinue) { Get-PimAlertFeedSummary -Feed $feed } else { [ordered]@{ total = @($feed).Count } }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok        = $true
                    summary   = $summary
                    alerts    = @($rows)
                    catalog   = @($script:PimAlertEventCatalog)
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # -------------------------------------------------------------------
        # Operational-policy config (REQUIREMENTS [M7]): expiry-policy defaults,
        # MFA-on-activation toggle, connection-sanity config. Persisted to the
        # SAME pim.Settings store the engine + jobs read. GET is read-anyone;
        # PUT is SuperAdmin (core operational policy). Invalid values are
        # rejected/clamped by the shared normalizer, not silently dropped --
        # the response carries the warnings so the GUI can show them.
        # -------------------------------------------------------------------
        if ($path -eq '/api/settings/operational-policy' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimOperationalPolicy)
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/settings/operational-policy' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to edit operational policy. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $payload = if ($body -and $body.PSObject.Properties['value']) { $body.value } else { $body }
            try {
                $cfg = Set-PimOperationalPolicy -Policy $payload
                Write-PimManagerAuditEvent -Action 'settings.operational-policy.save' -Target 'settings:operational-policy' -After ([ordered]@{
                    defaultActivationDuration = "$($cfg.value.expiry.defaultActivationDuration)"
                    maxActivationDuration     = "$($cfg.value.expiry.maxActivationDuration)"
                    maxEligibilityDuration    = "$($cfg.value.expiry.maxEligibilityDuration)"
                    mfaOnActivation           = [bool]$cfg.value.mfaOnActivation
                }) -Result 'ok'
                Write-JsonResponse -Response $resp -Status 200 -Body $cfg
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # -------------------------------------------------------------------
        # Feature flags -- the gradual-rollout registry. GET returns the
        # effective flag map (defaults + persisted overrides + always-on guard)
        # plus the catalog so the Settings "Features" panel can render every
        # toggle. PUT is SuperAdmin (it changes which surfaces are visible). The
        # boot-injected effective flags (PIM_FEATUREFLAGS_BOOT) gate the nav at
        # page load; this read/write keeps GUI state == the persisted store.
        # -------------------------------------------------------------------
        if ($path -eq '/api/settings/feature-flags' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimFeatureFlags)
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/settings/feature-flags' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to change feature flags. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            # Accept { value: { flags: {...} } } or { flags: {...} } or a flat id->bool map.
            $payload = if ($body -and $body.PSObject.Properties['value']) { $body.value } else { $body }
            try {
                $cfg = Set-PimFeatureFlags -Flags $payload
                $enabledIds = @()
                foreach ($k in $cfg.flags.Keys) { if ([bool]$cfg.flags[$k]) { $enabledIds += "$k" } }
                Write-PimManagerAuditEvent -Action 'settings.feature-flags.save' -Target 'settings:feature-flags' -After ([ordered]@{
                    enabled = ($enabledIds -join ',')
                }) -Result 'ok'
                Write-JsonResponse -Response $resp -Status 200 -Body $cfg
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # Governance PREVIEW gate -- the "show the surface, safely OFF" toggle for the
        # two security-sensitive governance surfaces. Default OFF for both. SAME store
        # the boot value + endpoint guard read, so a toggle here flips the GUI banner
        # AND un-gates the endpoints on the next reload (GUI state == behaviour).
        if ($path -eq '/api/settings/governance-preview' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimGovernancePreview)
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/settings/governance-preview' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to change the governance preview.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $payload = if ($body -and $body.PSObject.Properties['value']) { $body.value } else { $body }
            try {
                $cfg = Set-PimGovernancePreview -Flags $payload
                $enabledIds = @()
                foreach ($k in $cfg.flags.Keys) { if ([bool]$cfg.flags[$k]) { $enabledIds += "$k" } }
                Write-PimManagerAuditEvent -Action 'settings.governance-preview.save' -Target 'settings:governance-preview' -After ([ordered]@{
                    enabled = ($enabledIds -join ',')
                }) -Result 'ok'
                Write-JsonResponse -Response $resp -Status 200 -Body $cfg
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # -------------------------------------------------------------------
        # Feature customization (REQUIREMENTS s29) -- the per-feature kill switch
        # over the unified capability catalog. GET returns the effective gate map
        # (defaults + persisted overrides) + the catalog grouped by chapter + the
        # active edition + dependency issues so the Settings "Feature customization"
        # card can render every advanced toggle, dim disabled ones, and lock
        # unlicensed ones. PUT is SuperAdmin (it changes engine/job behaviour). The
        # SAME persisted state ('FeatureGates') is read by the engine + scheduler at
        # runtime, so a toggle here makes a disabled feature inert everywhere.
        # -------------------------------------------------------------------
        if ($path -eq '/api/settings/feature-gates' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try { Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimFeatureGates); return 200 }
            catch { Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }; return 500 }
        }

        if ($path -eq '/api/settings/feature-gates' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to change feature customization. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $payload = if ($body -and $body.PSObject.Properties['value']) { $body.value } else { $body }
            try {
                $cfg = Set-PimFeatureGates -Gates $payload
                $enabled = @(); foreach ($k in $cfg.gates.Keys) { if ([bool]$cfg.gates[$k]) { $enabled += "$k" } }
                Write-PimManagerAuditEvent -Action 'settings.feature-gates.save' -Target 'settings:feature-gates' -After ([ordered]@{ enabled = ($enabled -join ',') }) -Result 'ok'
                Write-JsonResponse -Response $resp -Status 200 -Body $cfg
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # -------------------------------------------------------------------
        # License backend (REQUIREMENTS s30) -- set/read the active EDITION
        # (Core | Pro | Pro-DesignPartner) per tenant + the recorded grant basis
        # (paid | design-partner). Honoured by the same gates as the kill switch:
        # a 'pro' feature is only available when the edition covers it. SuperAdmin
        # on the write. GET is reachable to any signed-in role so the GUI can show
        # which features the current edition unlocks.
        # -------------------------------------------------------------------
        if ($path -eq '/api/settings/edition' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try { Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimEditionConfig); return 200 }
            catch { Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }; return 500 }
        }

        if ($path -eq '/api/settings/edition' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to set the edition. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $payload = if ($body -and $body.PSObject.Properties['value']) { $body.value } else { $body }
            try {
                $cfg = Set-PimEditionConfig -Config $payload
                Write-PimManagerAuditEvent -Action 'settings.edition.save' -Target 'settings:edition' -After ([ordered]@{ edition = "$($cfg.edition)"; grantBasis = "$($cfg.grantBasis)" }) -Result 'ok'
                Write-JsonResponse -Response $resp -Status 200 -Body $cfg
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # -------------------------------------------------------------------
        # Deployment scenario backend (REQUIREMENTS §31.3 c) -- read/set the active
        # deployment TOPOLOGY (S1-S6) the engine + jobs + this GUI all resolve their
        # runtime knobs (hosting / SPN model / sync-file location + edition) from.
        # Mirrors /api/settings/edition: GET is reachable to any signed-in role so the
        # Settings card can show the active topology + resolved knobs; PUT is
        # SuperAdmin-only and persists the active scenario to pim.Settings 'Scenario'.
        # The card is a READ-ONLY summary of the resolved topology -- persisting a new
        # scenario never silently re-runs anything; it only changes what subsequent
        # resolutions read (the deploy/engine paths apply it on their next run).
        # -------------------------------------------------------------------
        # 68.6 row 35 -- the tenant tags an admin's "sync to slaves" picker offers (MSP master registry).
        if ($path -eq '/api/msp/tenant-tags' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $kt = Get-PimManagerKnownTenantTags
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ known = [bool]$kt.known; tags = @($kt.tags) })
            return 200
        }

        if ($path -eq '/api/settings/scenario' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try { Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimScenarioConfig); return 200 }
            catch { Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }; return 500 }
        }

        if ($path -eq '/api/settings/scenario' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to set the deployment scenario. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $payload = if ($body -and $body.PSObject.Properties['value']) { $body.value } else { $body }
            try {
                $cfg = Set-PimScenarioConfig -Config $payload
                Write-PimManagerAuditEvent -Action 'settings.scenario.save' -Target 'settings:scenario' -After ([ordered]@{ scenario = "$($cfg.active)" }) -Result 'ok'
                Write-JsonResponse -Response $resp -Status 200 -Body $cfg
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # -------------------------------------------------------------------
        # Email controls (REQUIREMENTS s29) -- global kill switch + redirect/override
        # target + allowlist. Surfaced as gateable settings honoured by the notify
        # path (Send-PimNotifyMail reads $global:PIM_MailKillSwitch / *RedirectAllTo
        # / *MailAllowlist). Persisted under pim.Settings 'EmailControls' and mirrored
        # to the globals so the same process's notify path picks them up live.
        # -------------------------------------------------------------------
        if ($path -eq '/api/settings/email-controls' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                $raw = $null; try { $raw = Get-PimManagerSetting -Name 'EmailControls' } catch {}
                $kill = $false; $redirect = ''; $allow = @()
                if ($raw) {
                    $kv = if ($raw -is [System.Collections.IDictionary]) { $raw } else { $raw }
                    $k = Get-PimFeatureCatalogValue -Object $kv -Key 'killSwitch'; if ($null -ne $k) { $kill = [bool]$k }
                    $rd = Get-PimFeatureCatalogValue -Object $kv -Key 'redirectAllTo'; if ($null -ne $rd) { $redirect = "$rd".Trim() }
                    $al = Get-PimFeatureCatalogValue -Object $kv -Key 'allowlist'; if ($null -ne $al) { $allow = @($al | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
                }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ killSwitch=$kill; redirectAllTo=$redirect; allowlist=@($allow) })
                return 200
            } catch { Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }; return 500 }
        }

        if ($path -eq '/api/settings/email-controls' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to change email controls.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $payload = if ($body -and $body.PSObject.Properties['value']) { $body.value } else { $body }
            try {
                $kill = [bool](Get-PimFeatureCatalogValue -Object $payload -Key 'killSwitch')
                $redirect = "$(Get-PimFeatureCatalogValue -Object $payload -Key 'redirectAllTo')".Trim()
                $allowRaw = Get-PimFeatureCatalogValue -Object $payload -Key 'allowlist'
                $allow = @(); if ($allowRaw) { $allow = @($allowRaw | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
                $val = [ordered]@{ killSwitch=$kill; redirectAllTo=$redirect; allowlist=@($allow) }
                Set-PimManagerSetting -Name 'EmailControls' -Value $val
                # Mirror to the globals the notify path reads live.
                $global:PIM_MailKillSwitch = $kill
                $global:PIM_MailAllowlist = @($allow)
                if ($redirect) { $global:PIM_MailRedirectAllTo = $redirect }
                Write-PimManagerAuditEvent -Action 'settings.email-controls.save' -Target 'settings:email-controls' -After ([ordered]@{ killSwitch=$kill; redirect=$redirect; allowlistCount=$allow.Count }) -Result 'ok'
                Write-JsonResponse -Response $resp -Status 200 -Body $val
                return 200
            } catch { Write-JsonResponse -Response $resp -Status 500 -Body @{ ok=$false; error = "$($_.Exception.Message)" }; return 500 }
        }

        # -------------------------------------------------------------------
        # Mail templates: ONE store in SQL (operator decision 2026-09-13).
        # pim.Settings['MailTemplates'] holds every template once -- seeded from the shipped
        # templates/mail/<type>.mailtemplate.html (Update-PimMailTemplateStore at boot), edited
        # here, and read by the engine at send time (PIM-MailTemplateStore.ps1). There is no
        # separate MailTemplateOverrides layer and no .custom.html file any more; legacy override
        # values were merged into the store once, additively and audited.
        #   GET    /api/mail-templates          -> [{ type, customized, source, subject }]      (any role)
        #   GET    /api/mail-template?type=<t>  -> { type, body(effective), shipped, source }   (any role)
        #   PUT    /api/mail-template { type, body }  -> save an edit into the store            (Admin+)
        #   DELETE /api/mail-template?type=<t>        -> reset the entry to the shipped default (Admin+)
        # 'source' stays 'store' (edited) | 'shipped' so the GUI contract is unchanged.
        # -------------------------------------------------------------------
        if ($path -eq '/api/mail-templates' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $mailDir = Join-Path $solutionRoot 'templates\mail'
            $doc = Get-PimMailTemplateStoreDocument
            $shippedAll = Read-PimShippedMailTemplates -TemplateDir $mailDir
            $types = @(@($shippedAll.Keys) + @($doc.templates.Keys) | Select-Object -Unique)
            $items = @()
            foreach ($tt in $types) {
                $e = Get-PimMailTemplateEffective -Type $tt -Document $doc -TemplateDir $mailDir
                if (-not $e) { continue }
                $subject = ''
                if ("$($e.text)" -match '<!--\s*subject:\s*(.+?)\s*-->') { $subject = $Matches[1] }
                $items += @{ type = $tt; customized = [bool]$e.customized; source = $(if ($e.customized) { 'store' } else { 'shipped' }); subject = $subject }
            }
            Write-JsonResponse -Response $resp -Status 200 -Body @{ templates = @($items | Sort-Object { $_.type }) }
            return 200
        }

        if ($path -eq '/api/mail-template' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $type = "$($req.QueryString['type'])".Trim()
            if (-not $type -or $type -notmatch '^[A-Za-z0-9_-]+$') { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'valid ?type= required' }; return 400 }
            $mailDir = Join-Path $solutionRoot 'templates\mail'
            $shippedPath = Join-Path $mailDir "$type.mailtemplate.html"
            if (-not (Test-Path -LiteralPath $shippedPath)) { Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown template '$type'" }; return 404 }
            $e = Get-PimMailTemplateEffective -Type $type -TemplateDir $mailDir
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ type = $type; body = "$($e.text)"; shipped = "$($e.shipped)"; source = $(if ($e.customized) { 'store' } else { 'shipped' }) })
            return 200
        }

        if ($path -eq '/api/mail-template' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) { Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to customize a mail template.' }; return 403 }
            $b = Read-RequestJson -Request $req
            $type = "$($b.type)".Trim()
            if (-not $type -or $type -notmatch '^[A-Za-z0-9_-]+$') { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'valid type required' }; return 400 }
            $mailDir = Join-Path $solutionRoot 'templates\mail'
            if (-not (Test-Path -LiteralPath (Join-Path $mailDir "$type.mailtemplate.html"))) { Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown template '$type'" }; return 404 }
            $newBody = "$($b.body)"
            if (-not $newBody.Trim()) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'body cannot be empty (use DELETE to reset to default)' }; return 400 }
            $by = ''; try { $by = "$((Get-PimManagerRole).identity)" } catch { }
            Set-PimMailTemplateStoreEntry -Type $type -Body $newBody -By $by -TemplateDir $mailDir
            Write-PimManagerAuditEvent -Action 'mailtemplate.save' -Target $type -After @{ type = $type; bytes = $newBody.Length } -Result 'ok'
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; type = $type; source = 'store' })
            return 200
        }

        if ($path -eq '/api/mail-template' -and $method -eq 'DELETE') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) { Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to reset a mail template.' }; return 403 }
            $type = "$($req.QueryString['type'])".Trim()
            if (-not $type -or $type -notmatch '^[A-Za-z0-9_-]+$') { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'valid ?type= required' }; return 400 }
            $mailDir = Join-Path $solutionRoot 'templates\mail'
            $by = ''; try { $by = "$((Get-PimManagerRole).identity)" } catch { }
            $removed = [bool](Reset-PimMailTemplateStoreEntry -Type $type -By $by -TemplateDir $mailDir)
            Write-PimManagerAuditEvent -Action 'mailtemplate.reset' -Target $type -After @{ type = $type; removedStoreOverride = $removed } -Result 'ok'
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; type = $type; removedStoreOverride = $removed })
            return 200
        }
        # ---- Permission health: the "Verify permissions" button ---------------------------
        # 🔴 REQUIREMENTS §63.6. This exists because a permission failure is INVISIBLE: Graph
        # answers 403, the provider catches it, and the operator reads a domain sentence while the
        # deploy and every tick report success. Measured on internal 2026-09-12: 218 occurrences of
        # `GroupsPolicies: no member policy` in two hours, caused by ONE missing app-role on the
        # container managed identity -- with nothing anywhere saying "you are missing a permission".
        # 🔑 It checks the RUNTIME identity (this process's own managed identity), not the SPN named
        # in config. Those are different principals, and conflating them cost most of a day: the SPN
        # held every required role while the MI that actually executes held 9 of 17.
        # Reader-gated: it discloses no secret, only which permissions are absent -- and an operator
        # who cannot see that is the person this whole feature exists to help.
        if ($path -eq '/api/permissions-health' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command Get-PimPermissionHealth -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 501 -Body @{ error = 'permission-health module not loaded'; hint = 'engine/_shared/PIM-PermissionHealth.ps1 is missing from this build' }
                return 501
            }
            $identityName = 'the engine identity'; $granted = @(); $readable = $false; $azScopes = @(); $oid = ''
            try {
                # WHO AM I: resolve this process's own service principal from the token it uses, so
                # the answer is about the principal that really runs -- never a configured name.
                $me = Invoke-PimGraph -Path '/servicePrincipals?$select=id,displayName&$top=1' -ErrorAction SilentlyContinue
                $whoAmI = $null
                try { $whoAmI = Invoke-PimGraph -Path "/me" -ErrorAction SilentlyContinue } catch { }
                $appId = "$($global:PIM_RuntimeAppId)"
                if (-not $appId) { $appId = "$($env:AZURE_CLIENT_ID)" }
                if ($appId) {
                    $sp = Invoke-PimGraph -Path ("/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,displayName" -f $appId)
                    if ($sp.value) { $oid = "$($sp.value[0].id)"; $identityName = "$($sp.value[0].displayName)" }
                }
                if ($oid) {
                    $graphSp = Invoke-PimGraph -Path "/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles"
                    $gid = "$($graphSp.value[0].id)"
                    $roleById = @{}; foreach ($r in $graphSp.value[0].appRoles) { $roleById["$($r.id)"] = "$($r.value)" }
                    $asg = @(Invoke-PimGraph -All -Path "/servicePrincipals/$oid/appRoleAssignments")
                    $granted = @($asg | Where-Object { "$($_.resourceId)" -eq $gid } | ForEach-Object { $roleById["$($_.appRoleId)"] } | Where-Object { $_ })
                    $readable = $true
                }
            } catch {
                # 🪤 UNREADABLE IS NOT HEALTHY. Leaving $readable=$false makes the verdict say the
                # CHECK failed -- the one thing this endpoint must never report as a clean bill.
                $readable = $false
            }
            # Azure: can it manage role assignments anywhere? Any scope will do for the verdict.
            try {
                if ($global:PIM_AzureScopes) { $azScopes = @($global:PIM_AzureScopes) }
            } catch { }
            $mailSender = "$($global:PIM_MailSender)".Trim()
            $health = Get-PimPermissionHealth -GrantedGraphRoles $granted -AzureRoleScopes $azScopes `
                        -IdentityName $identityName -GraphReadable $readable -MailSender $mailSender -MailSendOk $null
            $identities = @()
            if ($oid) {
                $identities += (New-PimIdentityRecord -Name $identityName -Kind ManagedIdentity -ObjectId $oid `
                                  -Purpose 'Runs this Manager (GUI) and calls Graph on its behalf' -IsRuntime $true -Health $health)
            }
            # 🔴 §70.18 / §70.19 (operator 2026-09-13: "why have you not told me that you are missing permissions --
            # fundamentally an issue"). This check reads THIS process's identity -- the Manager's. The ENGINE runs as
            # a different managed identity (the scheduled job), and on internal that identity lacked
            # RoleManagement.ReadWrite.Directory: every new role-assignable group got HTTP 403 while this banner
            # stayed green. The engine's own refusals are the ground truth, so they now decide the banner first.
            $engineDenied = @()
            if (Get-Command Get-PimEngineItemFailures -ErrorAction SilentlyContinue) {
                try { $engineDenied = @(@(Get-PimEngineItemFailures) | Where-Object { $_ -and "$($_.code)" -eq 'PERMISSION-DENIED' }) } catch { $engineDenied = @() }
            }
            $hOk = [bool]$health.ok; $hSev = "$($health.severity)"; $hHead = "$($health.headline)"; $hDetail = "$($health.detail)"
            if ($engineDenied.Count) {
                $hOk = $false; $hSev = 'error'
                $hHead = "The ENGINE was refused a permission on $($engineDenied.Count) item(s) -- those changes are NOT being deployed."
                $ex = @($engineDenied | Select-Object -First 3 | ForEach-Object {
                    $what = if ("$($_.label)".Trim()) { "$($_.label)" } else { "$($_.scope) $($_.key)" }
                    "$what [$($_.scope)]: $("$($_.message)".Substring(0, [Math]::Min(180, "$($_.message)".Length)))" })
                $hDetail = "The scheduled engine job's managed identity (not this Manager's) was denied by Graph/Azure: " + ($ex -join ' | ') +
                           ". Grant the missing permission to the engine identity; a new grant can take up to ~30 minutes to reach its token. " +
                           "Jobs > Engine logs & errors lists every item. (Manager identity check: $($health.headline))"
            }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                ok         = $hOk
                severity   = $hSev
                headline   = $hHead
                detail     = $hDetail
                engineDenied = @($engineDenied | ForEach-Object { [ordered]@{ scope = "$($_.scope)"; key = "$($_.key)"; label = "$($_.label)"; message = "$($_.message)"; lastSeenUtc = "$($_.lastSeenUtc)"; count = $_.count } })
                identity   = "$($health.identity)"
                objectId   = "$oid"
                grantedCount = @($granted).Count
                missingRequired = @($health.missingRequired)
                missingOptional = @($health.missingOptional)
                unavailableConnectors = @($health.unavailableConnectors)
                azureOk    = $health.azureOk
                mail       = $health.mail
                identities = @($identities)
                connectors = @(Get-PimWorkloadConnectorRequirements | ForEach-Object { [ordered]@{ connector="$($_.connector)"; surface="$($_.surface)"; model="$($_.model)"; tier="$($_.tier)"; grant="$($_.grant)" } })
                checkedUtc = (Get-Date).ToUniversalTime().ToString('o')
            })
            return 200
        }

        if ($path -eq '/api/admin-tap' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            # Read-only view of who holds a usable TAP, a dead one, or none. Gated at
            # Reader like the other read surfaces -- it exposes no credential, only state.
            $rows = @()
            # ?upn=<one admin> reads that account's live pass from Graph; without it the list comes
            # from the store only, so the page never waits on N admins' worth of Graph calls.
            try { $rows = @(Get-PimAdminTapState -Upn ("$($req.QueryString['upn'])".Trim())) } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "could not read admin TAP state: $($_.Exception.Message)" }
                return 500
            }
            Write-JsonResponse -Response $resp -Status 200 -Body @{
                ok        = $true
                admins    = $rows
                canReset  = (Test-PimManagerRoleAtLeast -Minimum 'Admin')
                mailSender = "$($global:PIM_MailSender)".Trim()
            }
            return 200
        }

        if ($path -eq '/api/admin-tap/reset' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            # Operator decision 2026-08-19: gated at ADMIN. A TAP is time-boxed and is
            # delivered ONLY to the ManagerEmail recorded on the admin row, so the blast
            # radius is bounded; routine "my TAP expired" recovery should not need the
            # break-glass role. The gate is SERVER-SIDE because that is the only side that
            # counts -- the button is also hidden client-side, but hiding is not enforcing.
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to re-issue a Temporary Access Pass' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $upn  = "$($body.userPrincipalName)".Trim()
            if (-not $upn) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'userPrincipalName is required' }
                return 400
            }

            # The row is the AUTHORITY for who may be issued a TAP and where it goes.
            # Never take the recipient from the request body: that would turn this into
            # "mail a credential for any admin to any address I name".
            # 68.6 row 35: a central admin's TAP is governed by the MSP master, not re-issued here.
            if (@(Get-PimManagerCentralAdminRows | Where-Object { "$($_.UserPrincipalName)".Trim() -ieq $upn }).Count) {
                Write-JsonResponse -Response $resp -Status 409 -Body @{ error = "'$upn' is a CENTRAL admin managed by the MSP master -- its TAP is governed there, not re-issued on this tenant." }
                return 409
            }
            $row = @(Get-PimAdminTapState | Where-Object { $_.userPrincipalName -eq $upn })
            if (-not $row.Count) {
                Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "'$upn' is not a managed Entra admin row (unknown account, or TargetPlatform=AD, which cannot hold a TAP) -- refusing to issue a TAP" }
                return 404
            }
            $row = $row[0]
            $mgr = "$($row.managerEmail)".Trim()

            # 🔴 REFUSE BEFORE MINTING when the mail cannot be delivered (operator decision
            # 2026-08-19, and BUG-66's own words: "a re-issue that cannot be delivered should
            # probably be REFUSED and REPORTED, not repeated"). Minting first and failing to
            # send leaves a LIVE credential that nobody received and nobody knows exists --
            # strictly worse than the expired TAP it replaced, which at least did nothing.
            $mailChk = Test-PimTapMailReady -Recipient $mgr
            if (-not $mailChk.ok) {
                Write-PimManagerAuditEvent -Action 'tap.reset.refused' -Target $upn -After @{ reason = $mailChk.reason }
                Write-JsonResponse -Response $resp -Status 409 -Body @{
                    error = "refusing to issue a TAP that cannot be delivered: $($mailChk.reason)"
                    hint  = 'Nothing was changed -- the existing TAP (if any) is untouched. Fix mail delivery, then retry.'
                }
                return 409
            }

            if (-not (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ error = 'no Graph client in this runtime -- cannot issue a TAP' }
                return 503
            }

            try {
                # 🔒 §65 -- THE MANAGER NO LONGER ISSUES THE TAP. IT QUEUES THE REQUEST.
                # Operator, 2026-09-12: *"as the engine/queue must do the actual change"*. The
                # delete-then-create pair (BUG-66) and the mail now happen in the ENGINE
                # (PIM-QueueActions.ps1 'tap-reset'), under the engine's identity.
                #
                # 🔑 NOTHING USER-VISIBLE IS LOST. The code was ALREADY mail-only -- it was never
                # returned to the browser (see the note below, which predates this change). So the
                # only difference is WHEN the mail arrives: on the next engine tick after an
                # operator commits the entry, rather than during this request.
                #
                # 🪤 THE MAIL PRE-CHECK STAYS, AND STAYS HERE. Refusing up-front is what stops us
                # destroying a working TAP for a mailbox we cannot reach. Checking it at enqueue
                # time gives the operator the refusal while they are still looking at the screen;
                # the engine re-checks at apply time because readiness can change in between.
                $uid = (Invoke-PimGraph -Path "/users/$upn`?`$select=id").id
                if (-not "$uid".Trim()) { throw "account '$upn' not found in the directory" }

                $cs = (Get-PimManagerStoreCs)
                if (-not $cs -or -not (Get-Command Add-PimSqlQueueChange -ErrorAction SilentlyContinue)) {
                    # No silent fallback to a direct write -- see Invoke-PimActiveAssignmentRevokeBatch.
                    Write-JsonResponse -Response $resp -Status 503 -Body @{
                        error = 'no SQL store is wired in this host, so the TAP reset cannot be queued -- and the Manager is not permitted to change the directory itself. Configure the store, then retry.'
                        hint  = 'Nothing was changed -- the existing TAP (if any) is untouched.' }
                    return 503
                }

                $hrs = [int]$row.tapLifetimeHours; if ($hrs -le 0) { $hrs = 4 }
                $who = "$(Get-PimManagerActor)"
                $change = New-PimChange -Entity 'PIM-Action-Tap' -Key "$upn" -Op 'Update' `
                            -Payload ([pscustomobject]@{
                                type          = 'tap-reset'
                                userId        = "$uid"
                                userPrincipalName = "$upn"
                                lifetimeHours = $hrs
                                recipient     = "$mgr"
                                # readable fields for the review surface (never a lookup)
                                principalName = $(if (Get-Command Format-PimQueuePrincipalName -ErrorAction SilentlyContinue) { Format-PimQueuePrincipalName -DisplayName "$($row.displayName)" -Upn "$upn" } else { "$upn" })
                                targetKind    = 'Temporary Access Pass'
                            }) -By $who -Kind 'Action' -Origin 'Authorised' `
                            -Justification "TAP re-issue requested for $upn"
                Add-PimSqlQueueChange -ConnectionString $cs -Change $change

                Write-PimManagerAuditEvent -Action 'tap.reset.queued' -Target $upn -After @{
                    queueId       = "$($change.id)"
                    lifetimeHours = $hrs
                    recipient     = $mgr
                    requestedBy   = $who
                }

                # 🔒 The TAP CODE ITSELF IS NEVER RETURNED. It goes to the recorded
                # ManagerEmail and nowhere else -- not to the browser, not to the response,
                # not into the audit record. A credential in an HTTP response is a credential
                # in a proxy log, a screenshot and a session history.
                # 202, not 200: the work is ACCEPTED, not done. Reporting "done" for something that
                # has not happened yet is the failure class §61-§63 exist to end.
                Write-JsonResponse -Response $resp -Status 202 -Body @{
                    ok                = $true
                    queued            = $true
                    queueId           = "$($change.id)"
                    userPrincipalName = $upn
                    lifetimeHours     = $hrs
                    recipient         = $mgr
                    note              = "The TAP re-issue is queued. It applies once committed in the Queue tab and the next engine run completes -- the new code is mailed to $mgr and never shown here. The existing TAP is untouched until then."
                }
                return 202
            } catch {
                Write-PimManagerAuditEvent -Action 'tap.reset.failed' -Target $upn -After @{ error = "$($_.Exception.Message)" }
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "TAP re-issue could not be queued: $($_.Exception.Message)" }
                return 500
            }
        }

        # ------------------------------------------------------------------
        # §62.8 / §35.2 -- MODIFY AN ADMIN. The verb the six-verb grid was missing entirely:
        # *"i must be able to rename an admin, update display name, create when, governance, etc"*.
        # Until now the only path was All records -> edit the row -> Review & commit.
        #
        # 🔑 THIS WRITES DESIRED STATE, NOT THE DIRECTORY, so it is unaffected by the Manager being
        # read-only (§65): the row lands in the store and the engine's Admins provider applies it on
        # the next tick, exactly as a create does. No Graph call is made here.
        #
        # 🔒 THE ROW IS THE AUTHORITY, NOT THE REQUEST -- the same rule as TAP reset and session
        # revoke. An arbitrary UPN in the body is refused; only an admin this caller may manage can
        # be modified, and the scope filter (§35.3) decides that where a portal profile exists.
        # ------------------------------------------------------------------
        if ($path -eq '/api/admin-accounts/modify' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to modify an admin account.' }
                return 403
            }
            $bodyIn = Read-RequestJson -Request $req
            $upn = "$($bodyIn.userPrincipalName)".Trim()
            if (-not $upn) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'userPrincipalName is required.' }; return 400 }

            $rows = @()
            try { $rows = @((Read-PimRows 'Account-Definitions-Admins').rows) } catch { $rows = @() }
            $row = @($rows | Where-Object { "$($_.UserPrincipalName)".Trim() -ieq $upn })[0]
            if (-not $row) {
                # 68.6 row 35: a CENTRAL admin (imported from the MSP master) is governed at its source.
                if (@(Get-PimManagerCentralAdminRows | Where-Object { "$($_.UserPrincipalName)".Trim() -ieq $upn }).Count) {
                    Write-JsonResponse -Response $resp -Status 409 -Body @{ error = "'$upn' is a CENTRAL admin managed by the MSP master -- it is read-only here. Change it on the master's admin row; the next sync brings the change down." }
                    return 409
                }
                Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "'$upn' is not a managed admin account in this store." }
                return 404
            }
            # §35.3 -- an admin the caller may not manage must not be reachable by naming them.
            $role = Get-PimManagerRole
            $isSuper = ("$($role.role)" -eq 'SuperAdmin')
            if (Get-Command Test-PimPortalCanManageAdmin -ErrorAction SilentlyContinue) {
                $prof = $null
                if (Get-Command Read-PimPortalProfiles -ErrorAction SilentlyContinue) {
                    try { $prof = Get-PimPortalProfile -Profiles (Read-PimPortalProfiles) -Identity "$($role.identity)" } catch { $prof = $null }
                }
                if (-not (Test-PimPortalCanManageAdmin -Profile $prof -AdminName $upn -IsSuperAdmin:$isSuper)) {
                    # 404, not 403: the same answer an unmanaged account gets, so this cannot be
                    # used to enumerate which admins exist outside the caller's scope.
                    Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "'$upn' is not a managed admin account in this store." }
                    return 404
                }
            }

            # 🔒 THE UPN IS NOT EDITABLE HERE, AND THAT IS A DECISION, NOT AN OMISSION.
            # UserPrincipalName is the row's natural KEY and every assignment row references the
            # admin by it. Changing it in place would silently orphan those assignments -- the
            # delegation would still exist against a principal nobody is bound to, which is
            # precisely the class of "each half is correct and nothing joins them" that §61 was.
            # A genuine rename is create-new + offboard-old, which is the approval-gated path.
            if ("$($bodyIn.newUserPrincipalName)".Trim()) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{
                    error = 'the UserPrincipalName cannot be changed here -- it is the key every assignment row references, so renaming it in place would orphan them.'
                    hint  = 'To rename: create the new admin account, move the assignments, then offboard the old one (the approval-gated path). To change only how the person is displayed, set displayName.'
                }
                return 400
            }

            # The fields a modify may touch. Everything else on the row is derived, a key, or
            # governed elsewhere (TAP lifetime by the TAP verb, AccountStatus by enable/disable,
            # OffboardDate by the offboarding ceremony) -- an allow-list, so a new column is not
            # silently made editable by adding it to the entity.
            $editable = @{
                displayName          = 'DisplayName'
                company              = 'Company'
                department           = 'Department'
                managerEmail         = 'ManagerEmail'
                usageLocation        = 'UsageLocation'
                environment          = 'Environment'
                purpose              = 'Purpose'
                targetUsage          = 'TargetUsage'
                forwardMailsToContact= 'ForwardMailsToContact'
                mailForwardAddress   = 'MailForwardAddress'
                # 68.6 row 35 -- the MSP downlink definition, set where the admin is defined.
                managementMode       = 'ManagementMode'
                ring                 = 'Ring'
                target               = 'Target'
            }
            $changes = [ordered]@{}
            $before  = [ordered]@{}
            foreach ($k in $editable.Keys) {
                if (-not ($bodyIn.PSObject.Properties[$k])) { continue }   # not submitted = not touched
                $col = $editable[$k]
                $new = "$($bodyIn.$k)".Trim()
                $old = "$($row.$col)".Trim()
                # The flag is a boolean column: store it in ONE spelling, so 'true' vs 'TRUE' is not a change.
                if ($col -eq 'ForwardMailsToContact' -and $new) {
                    if ($new -match '(?i)^(true|yes|1)$')      { $new = 'TRUE' }
                    elseif ($new -match '(?i)^(false|no|0)$') { $new = 'FALSE' }
                }
                if ($new -ceq $old) { continue }
                $changes[$col] = $new
                $before[$col]  = $old
            }
            # 🔴 VALIDATE AT THE POINT OF ENTRY (operator, 2026-09-12: the edit form showed "true" in the
            # forwarding-email field). The fields were free text, so a flag's value was accepted as an
            # ADDRESS and stored -- and Get-PimAdminTapRecipient then correctly found no recipient, far
            # from the screen that caused it. Refuse it here, where the operator can fix it.
            $badField = $null
            $mailRx = '^[^@\s]+@[^@\s]+\.[^@\s]+$'
            if ($changes.Contains('ForwardMailsToContact') -and "$($changes['ForwardMailsToContact'])" -and
                "$($changes['ForwardMailsToContact'])" -notin @('TRUE','FALSE')) {
                $badField = "ForwardMailsToContact must be TRUE or FALSE (got '$($changes['ForwardMailsToContact'])')."
            }
            foreach ($mc in @('MailForwardAddress','ManagerEmail')) {
                if (-not $badField -and $changes.Contains($mc) -and "$($changes[$mc])" -and "$($changes[$mc])" -notmatch $mailRx) {
                    $badField = "$mc must be an email address (got '$($changes[$mc])')."
                }
            }
            if (-not $badField -and $changes.Contains('Department') -and "$($changes['Department'])") {
                # A department decides who approves and who is mailed, so it must be one the owner
                # chain can resolve. Only enforced when departments are defined at all.
                $known = @()
                try { $known = @(Get-PimManagerDepartments | ForEach-Object { "$($_.name)".Trim() } | Where-Object { $_ }) } catch { }
                if ($known.Count -and -not ($known | Where-Object { $_ -ieq "$($changes['Department'])" })) {
                    $badField = "Department '$($changes['Department'])' is not defined. Add it under Access -> Departments & owners, or pick an existing one."
                }
            }
            # 68.6 row 35: the downlink definition. Mode is local|msp, Ring is blank or a ring number,
            # Target uses the downlink's own grammar and may only name tags the MSP registry knows.
            if (-not $badField -and $changes.Contains('ManagementMode')) {
                $mv = "$($changes['ManagementMode'])".Trim().ToLowerInvariant()
                if ($mv -and $mv -notin @('local','msp')) { $badField = "ManagementMode must be local or msp (got '$($changes['ManagementMode'])')." }
                else { $changes['ManagementMode'] = $mv }
            }
            if (-not $badField -and $changes.Contains('Ring') -and "$($changes['Ring'])" -and "$($changes['Ring'])" -notin @('0','1','2')) {
                $badField = "Ring must be blank, 0, 1 or 2 (got '$($changes['Ring'])')."
            }
            if (-not $badField -and $changes.Contains('Target') -and "$($changes['Target'])" -and (Get-Command Test-PimAdminTargetSelector -ErrorAction SilentlyContinue)) {
                $kt = Get-PimManagerKnownTenantTags
                $sel = Test-PimAdminTargetSelector -Target "$($changes['Target'])" -KnownTags @($kt.tags) -TagsKnown:([bool]$kt.known)
                if (@($sel.malformed).Count) { $badField = "Target has malformed entries: $(@($sel.malformed) -join ', ') (use tag:<name>, tenant:<id>, all or none)." }
                elseif (@($sel.unknownTags).Count) { $badField = "Target names tag(s) no managed tenant carries: $(@($sel.unknownTags) -join ', '). Known tags: $(if (@($kt.tags).Count) { @($kt.tags) -join ', ' } else { '(none)' })." }
                else { $changes['Target'] = $sel.normalized }
            }
            if ($badField) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = $badField }
                return 400
            }
            if ($changes.Count -eq 0) {
                # Reporting "saved" for a no-op teaches operators the button lies.
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; changed = 0; note = 'nothing to change -- every submitted field already holds that value.' }
                return 200
            }
            # A mail-forward address that is set while forwarding is off (or vice versa) is the kind
            # of half-configured state that reads as a bug later. Say it now, at the point of entry.
            if ($changes.Contains('MailForwardAddress') -and "$($changes['MailForwardAddress'])".Trim()) {
                $fwd = if ($changes.Contains('ForwardMailsToContact')) { "$($changes['ForwardMailsToContact'])" } else { "$($row.ForwardMailsToContact)" }
                if ($fwd -notmatch '(?i)^\s*(true|yes|1)\s*$') {
                    Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'a MailForwardAddress was set but ForwardMailsToContact is not TRUE -- the address would be stored and never used. Set both, or neither.' }
                    return 400
                }
            }

            $cs = (Get-PimManagerStoreCs)
            if (-not $cs -or -not (Get-Command Set-PimSqlRow -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ error = 'no SQL store is wired in this host, so the admin row cannot be updated.' }
                return 503
            }
            $data = [ordered]@{}
            foreach ($p in $row.PSObject.Properties) { $data[$p.Name] = $p.Value }
            foreach ($c in $changes.Keys) { $data[$c] = $changes[$c] }
            try {
                $key = Get-PimStoreRowKey -Base 'Account-Definitions-Admins' -Row ([pscustomobject]$data)
                if (-not "$key".Trim()) { throw "could not derive the row key for '$upn'" }
                Set-PimSqlRow -ConnectionString $cs -Entity 'Account-Definitions-Admins' -Key $key -Data ([pscustomobject]$data)
            } catch {
                Write-PimManagerAuditEvent -Action 'admin.modify.failed' -Target $upn -Result 'failed' -After @{ error = "$($_.Exception.Message)" }
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "the admin row could not be updated: $($_.Exception.Message)" }
                return 500
            }
            Write-PimManagerAuditEvent -Action 'admin.modify' -Target $upn -Result 'ok' `
                -Before ([ordered]@{ fields = $before }) -After ([ordered]@{ fields = $changes; by = "$($role.identity)" })
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                ok      = $true
                changed = $changes.Count
                fields  = @($changes.Keys)
                note    = 'Saved to the desired state. The engine applies it to the directory on its next run.'
            })
            return 200
        }

        if ($path -eq '/api/admin-accounts' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            # REQUIREMENTS §35.2 -- the account-operations grid's data source. ONE row per admin
            # this caller may act on, plus what each verb can do FOR THAT ROW, so the GUI renders
            # honestly instead of showing a button it will then refuse.
            #
            # 🔒 §35.3 IS ENFORCED HERE, NOT IN THE GRID. An admin the caller cannot manage is not
            # returned at all -- so it cannot appear in the table, and cannot be reached by a
            # "select all". A grid makes bulk selection trivial, which is exactly the shape of the
            # 2026-06-15 incident that disabled 53 accounts; the narrowing has to happen where the
            # data is produced, not where it is drawn.
            $role    = Get-PimManagerRole
            $isSuper = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')
            $isAdmin = [bool](Test-PimManagerRoleAtLeast -Minimum 'Admin')
            $prof    = $null
            if (Get-Command Read-PimPortalProfiles -ErrorAction SilentlyContinue) {
                try { $prof = Get-PimPortalProfile -Profiles (Read-PimPortalProfiles) -Identity "$($role.identity)" } catch { $prof = $null }
            }

            $rows = @()
            try { $rows = @((Read-PimRows 'Account-Definitions-Admins').rows) } catch { $rows = @() }
            # 68.6 row 35: a slave's own admins, then the central admins the MSP master governs (read-only here).
            $localNames = @{}
            foreach ($lr in $rows) { $n = "$($lr.UserPrincipalName)".Trim().ToLowerInvariant(); if ($n) { $localNames[$n] = $true } }
            $centralRows = @(Get-PimManagerCentralAdminRows | Where-Object { -not $localNames.ContainsKey("$($_.UserPrincipalName)".Trim().ToLowerInvariant()) })
            $centralSet = @{}
            foreach ($cr in $centralRows) { $centralSet["$($cr.UserPrincipalName)".Trim().ToLowerInvariant()] = $true }
            $rows = @($rows) + @($centralRows)

            $out = New-Object System.Collections.Generic.List[object]
            $hidden = 0
            foreach ($r in $rows) {
                $upn = "$($r.UserPrincipalName)".Trim()
                if (-not $upn) { continue }
                $isCentral = $centralSet.ContainsKey($upn.ToLowerInvariant())
                $mayManage = $true
                if (Get-Command Test-PimPortalCanManageAdmin -ErrorAction SilentlyContinue) {
                    $mayManage = [bool](Test-PimPortalCanManageAdmin -Profile $prof -AdminName $upn -IsSuperAdmin:$isSuper)
                }
                if (-not $mayManage) { $hidden++; continue }

                $status = "$($r.AccountStatus)".Trim()
                $tapWanted = Test-PimManagerAdminTapWanted -Row $r
                # 🔴 THE TAP GOES TO THE ADMIN'S FORWARDING ADDRESS, NOT TO A MANAGER (operator,
        # 2026-09-12: "it should not send to a manager email but his fowarding email").
        # An admin account is a separate privileged identity with NO mailbox of its own -- that is
        # why the row carries ForwardMailsToContact + MailForwardAddress. Mailing a "manager"
        # sends a time-boxed credential for MY account to SOMEONE ELSE; the forwarding address is
        # the person who owns the account and is the only correct recipient.
        # ManagerEmail stays as a fallback so rows that only have it keep working.
        $mgr = Get-PimAdminTapRecipient -Row $r
                $offboard = "$($r.OffboardDate)".Trim()
                $out.Add([pscustomobject]@{
                    userPrincipalName = $upn
                    displayName       = "$($r.DisplayName)".Trim()
                    userName          = "$($r.UserName)".Trim()
                    # §70.21 (operator 2026-09-13: "type internal-adminuser is missing for internal admins ... it exist
                    # for externs"): rows created before AdminType was written carry no value. The UPN prefix is what
                    # the type decides (internal = none, x- = external-adminuser, g- = external-guest), so derive it.
                    adminType         = $(if ("$($r.AdminType)".Trim()) { "$($r.AdminType)".Trim() } else { Get-PimManagerAdminTypeFromName -Name $(if ("$($r.UserName)".Trim()) { "$($r.UserName)" } else { $upn }) })
                    environment       = "$($r.Environment)".Trim()
                    company           = "$($r.Company)".Trim()
                    # 🔴 managerEmail is the ManagerEmail COLUMN, never the resolved recipient. It carried
                    # $mgr, so once an office-user email was set the grid's Manager column showed that
                    # same address -- and the Edit form pre-fills Manager from this field, so the next
                    # save would have WRITTEN the office email into ManagerEmail (operator, 2026-09-12:
                    # "dont set manager field to same mail as well"). The recipient has its own field.
                    managerEmail      = "$($r.ManagerEmail)".Trim()
                    mailRecipient     = $mgr
                    accountStatus     = $(if ($status) { $status } else { 'Enabled' })
                    createTAP         = $tapWanted
                    offboardDate      = $offboard
                    # 🔑 The forwarding address is where a TAP is actually delivered (an admin
                    # account has no mailbox of its own), so the grid's inline editor has to be able
                    # to read it back and set it. Without these the operator could see
                    # "nowhere to deliver the TAP" and had no field anywhere to fix it.
                    mailForwardAddress    = "$($r.MailForwardAddress)".Trim()
                    forwardMailsToContact = "$($r.ForwardMailsToContact)".Trim()
                    managementMode    = "$($r.ManagementMode)".Trim()
                    ring              = "$($r.Ring)".Trim()
                    target            = "$($r.Target)".Trim()
                    # 68.6 row 35: where this admin is governed. 'central' = imported from the MSP master,
                    # read-only on this tenant; every change happens on the master's row.
                    source            = $(if ($isCentral) { 'central' } else { 'local' })
                    readOnly          = [bool]$isCentral
                    readOnlyWhy       = $(if ($isCentral) { 'central admin -- governed by the MSP master' } else { '' })
                    # Per-row, per-verb. A verb the row itself cannot support is reported with a
                    # REASON, so the GUI can disable it and say why instead of failing on click.
                    canResetTap       = [bool]($isAdmin -and $tapWanted -and $mgr -and -not $isCentral)
                    resetTapWhy       = $(if ($isCentral) { 'central admin -- its TAP is governed by the MSP master' } elseif (-not $isAdmin) { 'Admin role required' } elseif (-not $tapWanted) { 'TargetPlatform=AD -- a TAP is an Entra credential and cannot exist for an AD-only admin' } elseif (-not $mgr) { 'no ManagerEmail on the row -- a TAP is only ever mailed to that address' } else { '' })
                    canRevokeSessions = [bool]($isAdmin -and -not $isCentral)
                    alreadyFlagged    = [bool]$offboard
                })
            }

            # 🪤 `.ToArray()`, NOT `@($out)`. Wrapping a System.Collections.Generic.List in @()
            # throws ArgumentException "Argument types do not match" -- the THIRD time this trap
            # has been hit in this solution (PIM-SqlStore.ps1 Get-PimSqlAuditEvents, and the
            # /api/approvals endpoint above, both carry the same note). Here it took out the
            # WHOLE "Admin accounts" screen: GET /api/admin-accounts -> 500 "Argument types do not
            # match", reported live on 2.4.324 (operator, 2026-09-12: "i see this admin accounts
            # under daily optionals but it fails").
            # 🔑 It is invisible offline because the endpoint tests assert the SHAPE of the body,
            # and the throw happens before the body is ever built -- so a suite that never calls
            # this endpoint against a non-empty store cannot see it. Guarded now by
            # tests/Test-PimListWrapTrap.ps1, which scans for the pattern across the solution.
            $adminsArr = $out.ToArray()
            Write-JsonResponse -Response $resp -Status 200 -Body @{
                admins      = $adminsArr
                count       = $adminsArr.Count
                # Honest about narrowing: the operator should know the list is scoped, not short.
                hiddenByScope = $hidden
                scoped      = [bool]($hidden -gt 0)
                canRevokeSessions = [bool]$isAdmin
                canFlagDelete     = [bool]$isAdmin
                canCreate         = [bool]$isAdmin
                role              = "$($role.role)"
            }
            return 200
        }

        if ($path -eq '/api/directory/people' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            # REQUIREMENTS §35.8. The directory-people lookup every people-picker needs.
            # Gated at ADMIN: this ENUMERATES PEOPLE, which is a disclosure surface, and
            # the fields that consume it (Settings -> Approvers / Departments) are already
            # Admin-edited. Widening a gate later is safe; narrowing one breaks callers.
            # ◻ When the §35.1 wizard's principal picker lands it may need Delegated
            # access -- that is a deliberate decision to take THEN, with §35.3's scoping,
            # not a default to drift into now.
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to search the directory' }
                return 403
            }

            # $path is $req.Url.AbsolutePath and never carries the query string, so the
            # parameters come off $req.Url.Query -- the same shape the other
            # query-bearing handlers in this file use.
            $qs = @{}
            try {
                foreach ($pair in ("$($req.Url.Query)".TrimStart('?') -split '&')) {
                    if (-not $pair) { continue }
                    $kv = $pair -split '=', 2
                    $qs[[uri]::UnescapeDataString($kv[0])] = if ($kv.Count -gt 1) { [uri]::UnescapeDataString($kv[1]) } else { '' }
                }
            } catch {}

            $q = Resolve-PimDirectoryQuery -Query $qs['q'] -Top $qs['top']
            if (-not $q.ok) {
                $st = Get-PimDirectorySearchHttpStatus -Code $q.code
                Write-JsonResponse -Response $resp -Status $st -Body @{ error = $q.reason; code = $q.code }
                return $st
            }

            if (-not (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) {
                # 🔴 An unavailable directory must NOT render as "no people found". An
                # empty list looks like a definitive answer, and the operator would
                # conclude the person does not exist. Say the lookup could not run.
                Write-JsonResponse -Response $resp -Status 503 -Body @{
                    error = 'no Graph client in this runtime -- the directory could not be searched'
                    code  = 'graph-unavailable'
                    hint  = 'This is NOT "no matches" -- the lookup did not run.'
                }
                return 503
            }

            # PRIMARY: $search (matches tokens WITHIN a name, so a surname finds the
            # person). FALLBACK: $filter/startswith (prefix-only) when $search is not
            # served. The response reports WHICH mode answered, so a degraded result is
            # visible rather than silently narrower than the operator expects.
            $mode = 'search'; $users = $null; $searchErr = ''
            try {
                $users = @(Invoke-PimGraph -Path (Get-PimDirectoryPeopleSearchPath -Term $q.term -Top $q.top) -Headers (Get-PimDirectorySearchHeaders) -All)
            } catch {
                $searchErr = "$($_.Exception.Message)"
                $users = $null
            }
            if ($null -eq $users) {
                $mode = 'startswith'
                try {
                    $users = @(Invoke-PimGraph -Path (Get-PimDirectoryPeopleFilterPath -Term $q.term -Top $q.top) -All)
                } catch {
                    Write-JsonResponse -Response $resp -Status 502 -Body @{
                        error = "directory search failed: $($_.Exception.Message)"
                        code  = 'graph-error'
                        hint  = 'This is NOT "no matches" -- the lookup failed. Both the search and the startswith query errored.'
                        searchError = $searchErr
                    }
                    return 502
                }
            }

            $shaped = @(@($users) | ForEach-Object { ConvertTo-PimDirectoryPerson -User $_ } | Where-Object { $null -ne $_ })
            $page   = Select-PimDirectoryPeoplePage -People $shaped -Top $q.top

            Write-JsonResponse -Response $resp -Status 200 -Body @{
                query     = $q.term
                matchMode = $mode
                count     = @($page.people).Count
                truncated = [bool]$page.truncated
                people    = @($page.people)
                note      = if ($mode -eq 'startswith') { 'Prefix match only -- the tenant did not serve a full search, so a surname may not match.' } else { '' }
            }
            return 200
        }

        if ($path -eq '/api/admin-sessions/revoke' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            # REQUIREMENTS §35.2. Revoking sign-in sessions is destructive but
            # RECOVERABLE -- the account survives and the user re-authenticates -- so
            # it deliberately does NOT carry offboarding's approval ceremony. Gated at
            # ADMIN, same as the TAP re-issue, and SERVER-SIDE because that is the only
            # side that counts.
            #
            # 🔑 WHY THIS ENDPOINT EXISTS AT ALL: until now this Graph call lived ONLY
            # inside the offboarding sequence, so the only way to kill a compromised
            # admin's live tokens was to offboard them. That left the proportionate
            # response to a suspected token theft unavailable and the irreversible one
            # as the only option.
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to revoke sign-in sessions' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $upn  = "$($body.userPrincipalName)".Trim()

            # The PURE guard decides. It is the same verdict the §35.2 grid's bulk path
            # will use, so the two cannot diverge about who may be revoked.
            $adminRows = @()
            try { $adminRows = @((Read-PimRows 'Account-Definitions-Admins').rows) } catch { $adminRows = @() }
            # §35.3 -- LEVEL SCOPING. Admin alone is not enough: the caller must be permitted to
            # act on THIS admin's account (manage-account + managedAdmins). Checked BEFORE the
            # revoke guard so an out-of-scope caller learns nothing about whether the target is
            # even a managed row -- a 404-vs-403 difference is an enumeration oracle.
            if (Get-Command Test-PimPortalCanManageAdmin -ErrorAction SilentlyContinue) {
                $isSuper = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')
                $prof    = $null
                if (Get-Command Read-PimPortalProfiles -ErrorAction SilentlyContinue) {
                    try { $prof = Get-PimPortalProfile -Profiles (Read-PimPortalProfiles) -Identity "$((Get-PimManagerRole).identity)" } catch { $prof = $null }
                }
                if ($upn -and -not (Test-PimPortalCanManageAdmin -Profile $prof -AdminName $upn -IsSuperAdmin:$isSuper)) {
                    Write-PimManagerAuditEvent -Action 'sessions.revoke.refused' -Target $upn -After @{ code = 'out-of-scope'; reason = 'caller lacks manage-account for this admin' }
                    Write-JsonResponse -Response $resp -Status 403 -Body @{
                        error = "not permitted: the manage-account capability for '$upn' is required (or SuperAdmin)"
                        code  = 'out-of-scope'
                    }
                    return 403
                }
            }

            # 68.6 row 35: a central admin is governed by the MSP master (after the scope check above,
            # so an out-of-scope caller still learns nothing).
            if ($upn -and @(Get-PimManagerCentralAdminRows | Where-Object { "$($_.UserPrincipalName)".Trim() -ieq $upn }).Count -and
                -not @($adminRows | Where-Object { "$($_.UserPrincipalName)".Trim() -ieq $upn }).Count) {
                Write-PimManagerAuditEvent -Action 'sessions.revoke.refused' -Target $upn -After @{ code = 'central-admin'; reason = 'governed by the MSP master' }
                Write-JsonResponse -Response $resp -Status 409 -Body @{ error = "'$upn' is a CENTRAL admin managed by the MSP master -- revoke it on the master."; code = 'central-admin' }
                return 409
            }
            $decision = Get-PimSessionRevokeDecision -UserPrincipalName $upn -AdminRows $adminRows
            if (-not $decision.allowed) {
                $st = Get-PimSessionRevokeHttpStatus -Code $decision.code
                Write-PimManagerAuditEvent -Action 'sessions.revoke.refused' -Target $upn -After @{ code = $decision.code; reason = $decision.reason }
                Write-JsonResponse -Response $resp -Status $st -Body @{ error = $decision.reason; code = $decision.code }
                return $st
            }

            if (-not (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ error = 'no Graph client in this runtime -- cannot revoke sessions' }
                return 503
            }

            try {
                $uid = (Invoke-PimGraph -Path "/users/$upn`?`$select=id").id
                if (-not "$uid".Trim()) { throw "account '$upn' not found in the directory" }

                # 🔒 §65 -- QUEUED, NOT ISSUED HERE. The Manager is read-only; the engine performs
                # the revoke (PIM-QueueActions.ps1 'session-revoke') under its own identity.
                #
                # ⚠️ THIS IS THE ONE WHERE THE LATENCY GENUINELY COSTS SOMETHING, AND IT IS SAID
                # PLAINLY RATHER THAN GLOSSED. Revoking sessions is what an operator reaches for
                # when they believe an account is compromised, and it is now effective on the next
                # engine tick instead of immediately. The operator accepted that trade for the
                # read-only Manager (§65.0); the response says so, so nobody assumes the tokens are
                # already dead. For an account believed actively compromised, DISABLE it -- that
                # path has its own gate and is the stronger action anyway.
                $cs = (Get-PimManagerStoreCs)
                if (-not $cs -or -not (Get-Command Add-PimSqlQueueChange -ErrorAction SilentlyContinue)) {
                    Write-JsonResponse -Response $resp -Status 503 -Body @{
                        error = 'no SQL store is wired in this host, so the session revoke cannot be queued -- and the Manager is not permitted to change the directory itself. Configure the store, then retry.' }
                    return 503
                }
                $who = "$(Get-PimManagerActor)"
                $change = New-PimChange -Entity 'PIM-Action-Sessions' -Key "$upn" -Op 'Update' `
                            -Payload ([pscustomobject]@{ type = 'session-revoke'; userId = "$uid"; userPrincipalName = "$upn"; principalName = "$upn"; targetKind = 'Sign-in sessions' }) `
                            -By $who -Kind 'Action' -Origin 'Authorised' `
                            -Justification "sign-in session revoke requested for $upn"
                Add-PimSqlQueueChange -ConnectionString $cs -Change $change

                Write-PimManagerAuditEvent -Action 'sessions.revoke.queued' -Target $upn -After @{ userId = "$uid"; queueId = "$($change.id)"; requestedBy = $who }
                try { Send-PimManagerAlert -Event 'sessions-revoked' -Title 'Sign-in session revoke QUEUED' -Detail ("$upn -- queued; refresh tokens are invalidated when the engine applies it") -LinkTab 'accounts' | Out-Null } catch {}

                Write-JsonResponse -Response $resp -Status 202 -Body @{
                    ok                = $true
                    queued            = $true
                    queueId           = "$($change.id)"
                    userPrincipalName = $upn
                    note              = "Session revoke QUEUED for $upn. It is NOT yet in effect -- existing refresh tokens stay valid until the entry is committed in the Queue tab and the next engine run applies it. The account is NOT disabled and nothing else was changed."
                }
                return 202
            } catch {
                Write-PimManagerAuditEvent -Action 'sessions.revoke.failed' -Target $upn -After @{ error = "$($_.Exception.Message)" }
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "session revoke failed: $($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/emergency-status' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            # §36.3 phase 3 -- the SHARED store, so this endpoint answers about the override the
            # engine will act on rather than about a file only this container can see.
            $ov = Get-PimManagerEmergencyOverride
            if (-not $ov) {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ active = $false }
                return 200
            }
            try {
                $expired = $true
                try { $expired = ([datetime]::UtcNow -ge ([datetime]$ov.expiresAtUtc).ToUniversalTime()) } catch {}
                Write-JsonResponse -Response $resp -Status 200 -Body @{
                    active = [bool]($ov.active -and -not $expired); expired = $expired
                    activatedBy = "$($ov.activatedBy)"; activatedAtUtc = "$($ov.activatedAtUtc)"; expiresAtUtc = "$($ov.expiresAtUtc)"
                    reason = "$($ov.reason)"; scopeGroupTags = @($ov.scopeGroupTags); appliedGroups = @($ov.appliedGroups)
                }
            } catch {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ active = $false; error = "$($_.Exception.Message)" }
            }
            return 200
        }

        if ($path -eq '/api/emergency' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required for the emergency override' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $check = Test-PimEmergencyPasscode -Passcode "$($body.passcode)"
            if (-not $check.ok) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = $check.error }
                return 403
            }
            $hours = 4
            if ($body.hours) { $hours = [Math]::Min(24, [Math]::Max(1, [int]$body.hours)) }
            $who = (Get-PimManagerRole).identity
            $ov = [ordered]@{
                active         = $true
                scopeGroupTags = @($body.scopeGroupTags | Where-Object { $_ })
                activatedBy    = $who
                activatedAtUtc = [datetime]::UtcNow.ToString('o')
                expiresAtUtc   = [datetime]::UtcNow.AddHours($hours).ToString('o')
                reason         = "$($body.reason)"
                appliedGroups  = @()
            }
            # 🔴 §36.3 phase 3 -- write where the ENGINE can read it. This used to write a file
            # into the Manager's own config dir; on a hosted deployment the engine runs elsewhere
            # (VisualCron on mgmt1, ca-pim-tick) and would never see it -- so break-glass silently
            # did nothing at the one moment somebody was relying on it.
            $ovWhere = 'file'
            try { $ovWhere = Set-PimManagerEmergencyOverride -Override $ov }
            catch {
                # Activation that cannot reach the engine must FAIL, not report success. Telling
                # an operator break-glass is on when it is not is worse than refusing.
                Write-PimManagerAuditEvent -Action 'emergency.activate.failed' -Target (@($ov.scopeGroupTags) -join ',') -After @{ error = "$($_.Exception.Message)" } -Result 'error'
                Write-JsonResponse -Response $resp -Status 500 -Body @{
                    error = "could not record the emergency override: $($_.Exception.Message)"
                    hint  = 'Nothing was activated. The engine reads the override from the shared store; a write that does not reach it would leave break-glass inert while appearing active.'
                }
                return 500
            }
            Write-PimManagerAuditEvent -Action 'emergency.activate' -Target (@($ov.scopeGroupTags) -join ',') -After @{ hours = $hours; reason = "$($body.reason)"; expiresAtUtc = $ov.expiresAtUtc; store = $ovWhere }
            # Alerting (REQUIREMENTS §27 H2): break-glass use is a high-signal event ->
            # fire the break-glass alert through the existing notify path.
            try { Send-PimManagerAlert -Event 'break-glass' -Title 'Break-glass (emergency override) ACTIVATED' -Detail ("Activated by $who; scope=$((@($ov.scopeGroupTags) -join ', ')); expires $($ov.expiresAtUtc); reason: $($body.reason)") -LinkTab 'settings' | Out-Null } catch {}
            Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; expiresAtUtc = $ov.expiresAtUtc; note = 'The engine disables approval on the scoped groups on its next run (run it now for immediate effect) and auto-restores normal policy at expiry.' }
            return 200
        }

        if ($path -eq '/api/emergency-restore' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required' }
                return 403
            }
            # §36.3 phase 3 -- expire it in the SHARED store, for the same reason as activate: the
            # ENGINE is what restores normal policy, and it reads the override from the store, not
            # from this container's filesystem.
            # 🔒 A failure here is NOT swallowed. It used to be `catch {}`, which reported "the
            # engine re-applies normal policy on its next run" whether or not anything had been
            # written -- telling an operator that emergency access had been wound back when it had
            # not is the worst possible thing to be wrong about on this endpoint.
            try {
                $ov = Get-PimManagerEmergencyOverride
                if ($ov) {
                    $ov.expiresAtUtc = [datetime]::UtcNow.ToString('o')   # expire NOW; engine restores on next run
                    $w = Set-PimManagerEmergencyOverride -Override $ov
                    Write-PimManagerAuditEvent -Action 'emergency.restore.requested' -Target (@($ov.scopeGroupTags) -join ',') -After @{ store = $w }
                }
            } catch {
                Write-PimManagerAuditEvent -Action 'emergency.restore.requested.failed' -Target '' -After @{ error = "$($_.Exception.Message)" } -Result 'error'
                Write-JsonResponse -Response $resp -Status 500 -Body @{
                    error = "could not expire the emergency override: $($_.Exception.Message)"
                    hint  = 'The override is UNCHANGED and may still be ACTIVE. Do not assume normal policy was restored.'
                }
                return 500
            }
            Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; note = 'Override expired; the engine re-applies the normal approval policy on its next run.' }
            return 200
        }

        # -------------------------------------------------------------------
        # Resource auto-discovery (LIFECYCLE-GOVERNANCE phase 9, Portal mode)
        # Diffs the _tenantSync caches (azure scopes + entra roles) against
        # cache/<instance>/discovery-baseline.json. Acknowledge = snapshot
        # the current state as the new baseline.
        # -------------------------------------------------------------------
        if ($path -eq '/api/discovered-resources' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $cacheDir = Join-Path $PSScriptRoot ("cache\{0}" -f $script:PimInstanceName)
            $baseFile = Join-Path $cacheDir 'discovery-baseline.json'
            $readItems = {
                param($file)
                try {
                    if (Test-Path -LiteralPath $file) { @((Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json).items) } else { @() }
                } catch { @() }
            }
            $scopes = & $readItems (Join-Path $cacheDir 'azure-scopes.json')
            $roles  = & $readItems (Join-Path $cacheDir 'entra-roles.json')
            if (-not (Test-Path -LiteralPath $baseFile)) {
                Write-JsonResponse -Response $resp -Status 200 -Body @{
                    baselineMissing = $true
                    currentCounts   = @{ azureScopes = $scopes.Count; entraRoles = $roles.Count }
                    newItems        = @()
                }
                return 200
            }
            $baseline = $null
            try { $baseline = Get-Content -LiteralPath $baseFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
            $knownScopes = @($baseline.azureScopeIds | Where-Object { $_ })
            $knownRoles  = @($baseline.entraRoleIds | Where-Object { $_ })
            $newItems = @()
            foreach ($s in $scopes) { if ($knownScopes -notcontains "$($s.id)") { $newItems += @{ kind = "azure-$($s.type)"; id = "$($s.id)"; displayName = "$($s.displayName)"; scopePath = "$($s.scopePath)" } } }
            foreach ($r2 in $roles)  { if ($knownRoles -notcontains "$($r2.id)")  { $newItems += @{ kind = 'entra-role'; id = "$($r2.id)"; displayName = "$($r2.displayName)" } } }
            Write-JsonResponse -Response $resp -Status 200 -Body @{
                baselineMissing = $false
                baselineAtUtc   = "$($baseline.savedAtUtc)"
                newItems        = $newItems
            }
            return 200
        }

        if ($path -eq '/api/discovery-baseline' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to acknowledge discovered resources.' }
                return 403
            }
            $cacheDir = Join-Path $PSScriptRoot ("cache\{0}" -f $script:PimInstanceName)
            $readItems = {
                param($file)
                try {
                    if (Test-Path -LiteralPath $file) { @((Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json).items) } else { @() }
                } catch { @() }
            }
            $scopes = & $readItems (Join-Path $cacheDir 'azure-scopes.json')
            $roles  = & $readItems (Join-Path $cacheDir 'entra-roles.json')
            $baseline = [ordered]@{
                savedAtUtc    = [datetime]::UtcNow.ToString('o')
                azureScopeIds = @($scopes | ForEach-Object { "$($_.id)" })
                entraRoleIds  = @($roles | ForEach-Object { "$($_.id)" })
            }
            if (-not (Test-Path -LiteralPath $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }
            ($baseline | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath (Join-Path $cacheDir 'discovery-baseline.json') -Encoding UTF8
            Write-PimManagerAuditEvent -Action 'resource.baseline' -Target $script:PimInstanceName -After @{ azureScopes = @($baseline.azureScopeIds).Count; entraRoles = @($baseline.entraRoleIds).Count }
            Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; savedAtUtc = $baseline.savedAtUtc }
            return 200
        }

        # -------------------------------------------------------------------
        # Governance: Manager role/delegation MAP (Reader/Delegated/Admin/
        # SuperAdmin -> identity). The Governance "Your access" panel reads it
        # here (GET) and a SuperAdmin edits it (PUT). 🔒 SQL-ONLY: the map IS
        # pim.Settings['ManagerAccess'] -- the SAME value Get-PimManagerRole
        # enforces on every request and Set-PimManagerAccess.ps1 writes -- so the
        # edit is REAL. Env-var role config (PIM_SuperAdmins/...) still grants on
        # top and is reported as envManaged. GET = any role; PUT = SuperAdmin only.
        # -------------------------------------------------------------------
        if ($path -eq '/api/access-map' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $entries = New-Object System.Collections.ArrayList
            $readError = $null
            try {
                $raw = Get-PimManagerSetting -Name 'ManagerAccess'
                if ($raw -is [string] -and "$raw".Trim()) { $raw = "$raw" | ConvertFrom-Json }
                if ($null -ne $raw) {
                    $list = @(if ($raw.PSObject.Properties['managerAccess']) { $raw.managerAccess } else { $raw })
                    foreach ($e in $list) {
                        $eid = "$($e.identity)".Trim(); if (-not $eid) { continue }
                        $r = "$($e.role)"; if ($r -notin @('Reader','Delegated','Admin','SuperAdmin')) { $r = 'Reader' }
                        [void]$entries.Add(@{ identity = $eid; role = $r })
                    }
                }
            } catch { $readError = "$($_.Exception.Message)" }
            $envManaged = [bool]("$env:PIM_SuperAdmins".Trim() -or "$env:PIM_Admins".Trim() -or "$env:PIM_DelegatedAdmins".Trim() -or "$env:PIM_HostedDefaultRole".Trim())
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                entries     = @($entries.ToArray())
                roles       = @('Reader','Delegated','Admin','SuperAdmin')
                store       = 'sql'
                setting     = 'ManagerAccess'
                envManaged  = $envManaged
                readError   = $readError
                bootstrap   = (Get-PimManagerAccessBootstrapState)
                you         = (Get-PimManagerRole)
            })
            return 200
        }

        if ($path -eq '/api/access-map' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to edit the delegation map. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $raw = if ($body -and $body.PSObject.Properties['entries']) { @($body.entries) } else { @($body) }
            $clean = New-Object System.Collections.ArrayList
            $valid = @('Reader','Delegated','Admin','SuperAdmin')
            $sawSuper = $false
            foreach ($e in $raw) {
                $id = "$($e.identity)".Trim(); if (-not $id) { continue }
                $r = "$($e.role)".Trim(); if ($r -notin $valid) { $r = 'Reader' }
                if ($r -eq 'SuperAdmin') { $sawSuper = $true }
                [void]$clean.Add([pscustomobject]@{ identity = $id; role = $r })
            }
            # Lock-out guard: never let the map end with zero SuperAdmins (that would orphan the
            # instance -- nobody could edit it back). An EMPTY map is refused too: it is almost
            # always a failed read upstream, and it would silently strip every SQL grant.
            if (-not $sawSuper) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'At least one SuperAdmin is required -- saving this map would lock everyone out.' }
                return 400
            }
            $arr = @($clean.ToArray())
            $value = [pscustomobject]@{ managerAccess = @($arr) }
            try {
                Set-PimManagerSetting -Name 'ManagerAccess' -Value $value
                # Read back: an authorization write that did not land must not report success.
                $back = Get-PimManagerSetting -Name 'ManagerAccess'
                $backList = @(if ($back -and $back.PSObject.Properties['managerAccess']) { $back.managerAccess } else { @() })
                if (@($backList).Count -ne $arr.Count) { throw "read-back mismatch: wrote $($arr.Count) entr(y/ies), store holds $(@($backList).Count)" }
            } catch {
                Write-PimManagerAuditEvent -Action 'access.map.save' -Target "entries:$($arr.Count)" -After @{ count = $arr.Count; error = "$($_.Exception.Message)" } -Result 'error'
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "Manager access was NOT saved to SQL: $($_.Exception.Message)" }
                return 500
            }
            # The very next role check must see the new map, not a 15-second-old cache.
            $script:PimManagerAccessCache = $null
            if (-not ($global:PIM_NamingConventions -is [hashtable])) { $global:PIM_NamingConventions = @{} }
            $global:PIM_NamingConventions['ManagerAccess'] = $value
            Write-PimManagerAuditEvent -Action 'access.map.save' -Target "entries:$($arr.Count)" -After @{ count = $arr.Count; store = 'sql' } -Result 'ok'
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; store = 'sql'; entries = @($arr); you = (Get-PimManagerRole) })
            return 200
        }

        # -------------------------------------------------------------------
        # Governance: DISCOVERED-RESOURCE auto-create POLICY (per type).
        # Drives the REAL engine layer ($global:PIM_DiscoveryAutoCreate read by
        # Get-PimDiscoveryAutoCreatePolicy / Resolve-PimDiscoveryPolicyPlan in
        # PIM-Discovery.ps1): per resource type, 'flag' (log only, default) |
        # 'pending' (stage a desired definition row for review) | 'auto' (queue
        # a create via the normal change flow). Persisted via Set-PimManagerSetting
        # (SQL pim.Settings 'DiscoveryAutoCreate' when active, else the per-instance
        # JSON) AND mirrored into the live $global so the same process's engine
        # picks it up; the scheduler/engine hydrate it from SQL settings at boot.
        # GET = any role; PUT = SuperAdmin only.
        # -------------------------------------------------------------------
        # -------------------------------------------------------------------
        # MSP DOWNLINK (control #1/#2, framework MSP-2).
        #   GET  /api/downlink         -- per-relationship plan: projected / excluded /
        #                                 unresolved / groups, straight off the PURE core.
        #   PUT  /api/downlink/policy  -- edit the per-relationship projection policy
        #                                 (SuperAdmin, audited). Master registry rows.
        #   POST /api/downlink/run     -- dry-run or apply (SuperAdmin for apply, audited).
        #
        # 🔒 THE DECISION IS THE ENGINE'S, NOT THE GUI'S. Every one of these composes
        # Get-PimDownlinkPlan over the SIGNED baseline. The GUI renders what comes back.
        # A second opinion computed in the browser could disagree with what the apply
        # then writes -- and the subject of the disagreement is privilege in someone
        # else's tenant.
        # -------------------------------------------------------------------
        if ($path -eq '/api/downlink' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                $dl = Get-PimManagerDownlinkOverview
                Write-JsonResponse -Response $resp -Status 200 -Body $dl
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "downlink overview failed: $($_.Exception.Message)" }
                return 500
            }
        }

        # MSP-4 -- THE REACH VIEW: the same data as /api/downlink, transposed by GROUP TAG so the
        # operator's actual question ("this role goes to only 5 of 28 tenants") is one request
        # instead of 28. Deliberately READ-ONLY and derived from the very same overview, so the
        # two views can never disagree: authoring still happens through /api/downlink/policy,
        # which is SuperAdmin-gated and audited. A second write path into a customer's privilege
        # is the last thing this surface needs.
        if ($path -eq '/api/downlink/reach' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                $dlo = Get-PimManagerDownlinkOverview
                $reach = Get-PimProjectionReach -Relationships @($dlo.relationships)
                Write-JsonResponse -Response $resp -Status 200 -Body @{
                    tags        = @($reach)
                    tenantCount = @($dlo.relationships).Count
                    baseline    = $dlo.baseline
                    # MSP-4 write half: the panel shows its authoring control only to a role that
                    # could actually use it. The GATE is still server-side on the PUT -- this only
                    # decides whether to render a button a reader would just bounce off.
                    canWrite    = [bool]$dlo.canWrite
                    reason      = "$($dlo.reason)"
                }
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "downlink reach failed: $($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/downlink/policy' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to change a projection policy.' }
                return 403
            }
            $body = Read-RequestJson -Request $req

            # ---- MSP-4, THE WRITE HALF: the same policy, authored along the TAG axis. ----
            # 🔒 ONE ROUTE, TWO AXES -- NOT TWO ROUTES. The reach panel edits "this role reaches
            # these N tenants"; the relationship panel edits "this tenant accepts these roles".
            # They are the same rows transposed, so they get the same SuperAdmin gate, the same
            # audit trail and the same writer. A second write path into a customer's privilege
            # is the thing this surface must never grow -- and it is what a `PUT /reach` would
            # have been, however convenient the URL.
            # 🔴 REFUSAL IS A 409, NOT A SILENT PARTIAL. Only the `policy` narrowing is writable
            # from here; a role held out by ring, targeting or a blocked capability cannot be let
            # in by a rule, and writing one anyway would commit cleanly, change nothing and
            # report success in a tenant the operator does not own.
            if ($body -and $body.PSObject.Properties['groupTag'] -and "$($body.groupTag)".Trim()) {
                $gTag = "$($body.groupTag)".Trim()
                $wantIds = @(@($body.tenantIds) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
                try {
                    $rr = Set-PimProjectionReach -GroupTag $gTag -TenantIds $wantIds
                } catch {
                    Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "reach edit failed: $($_.Exception.Message)" }
                    return 500
                }
                if (-not $rr.wrote -and @($rr.refusals).Count) {
                    Write-PimManagerAuditEvent -Action 'downlink.reach.refused' -Target $gTag `
                        -After @{ requested = @($wantIds); refusals = @($rr.refusals) } -Result 'refused'
                    Write-JsonResponse -Response $resp -Status 409 -Body $rr
                    return 409
                }
                # Audited with the MEASURED outcome, not the intent: `after` is read back off a
                # re-composed plan, so the trail records what the estate now does.
                Write-PimManagerAuditEvent -Action 'downlink.reach.save' -Target $gTag `
                    -Before @{ reach = "$($rr.before)" } `
                    -After  @{ reach = "$($rr.after)"; requested = @($wantIds); edited = @(@($rr.edits) | ForEach-Object { "$($_.tenantId)" }) } `
                    -Result $(if ($rr.ok) { 'ok' } else { 'failed' })
                Write-JsonResponse -Response $resp -Status $(if ($rr.ok) { 200 } else { 500 }) -Body $rr
                return $(if ($rr.ok) { 200 } else { 500 })
            }

            $tid = "$($body.tenantId)".Trim()
            if (-not $tid) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'tenantId or groupTag is required.' }; return 400 }
            $rules = @()
            foreach ($r in @($body.policy)) {
                $m = "$($r.Mode)".Trim().ToLowerInvariant()
                $t = "$($r.GroupTag)".Trim()
                # Fail CLOSED on a bad mode rather than coercing it: silently turning an
                # unknown mode into 'allow' would widen a projection nobody asked to widen.
                if ($m -notin @('allow','deny')) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "invalid Mode '$($r.Mode)' -- must be allow or deny." }; return 400 }
                if (-not $t) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'each rule needs a GroupTag.' }; return 400 }
                $rules += ,([ordered]@{ Mode = $m; GroupTag = $t })
            }
            try {
                $before = @(Get-PimManagerDownlinkPolicy -TenantId $tid)
                Set-PimManagerDownlinkPolicy -TenantId $tid -Rules $rules
                Write-PimManagerAuditEvent -Action 'downlink.policy.save' -Target $tid -Before @{ rules = $before } -After @{ rules = $rules } -Result 'ok'
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; tenantId = $tid; policy = $rules })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "could not save the policy: $($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/downlink/run' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            $body = Read-RequestJson -Request $req
            $tid = "$($body.tenantId)".Trim()
            $whatIf = $true
            if ($null -ne $body.whatIf) { $whatIf = [bool]$body.whatIf }
            if (-not $tid) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'tenantId is required.' }; return 400 }
            # A dry run is readable by any role (it changes nothing); an APPLY writes
            # privilege into a customer tenant and is SuperAdmin-only.
            if (-not $whatIf -and -not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to run a downlink sync.' }
                return 403
            }
            try {
                $r = Invoke-PimManagerDownlinkRun -TenantId $tid -WhatIfMode:$whatIf
                if (-not $whatIf) {
                    Write-PimManagerAuditEvent -Action 'downlink.sync.run' -Target $tid -After @{ detail = "$($r.detail)"; ok = [bool]$r.ok } -Result $(if ($r.ok) { 'ok' } else { 'failed' })
                }
                Write-JsonResponse -Response $resp -Status 200 -Body $r
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "downlink run failed: $($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/discovery-policy' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            # Known types the engine can classify (Resolve-PimDiscoveryResourceType)
            # plus PowerBIWorkspace. Default 'flag' for every type (safe).
            $types = @('AzureSubscription','ManagementGroup','ResourceGroup','PowerBIWorkspace','EntraRole')
            $stored = Get-PimManagerSetting -Name 'DiscoveryAutoCreate'
            $map = ConvertTo-PimPlainHashtable $stored
            $valid = @('flag','pending','auto')
            $policy = [ordered]@{}
            foreach ($t in $types) {
                $v = if ($map.ContainsKey($t)) { "$($map[$t])".Trim().ToLowerInvariant() } else { '' }
                if ($v -notin $valid) { $v = 'flag' }
                $policy[$t] = $v
            }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                policy   = $policy
                types    = @($types)
                values   = @($valid)
                default  = 'flag'
            })
            return 200
        }

        if ($path -eq '/api/discovery-policy' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to set the discovery auto-create policy.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $payload = if ($body -and $body.PSObject.Properties['policy']) { $body.policy } else { $body }
            $h = ConvertTo-PimPlainHashtable $payload
            $valid = @('flag','pending','auto')
            $clean = @{}
            foreach ($k in @($h.Keys)) {
                $v = "$($h[$k])".Trim().ToLowerInvariant()
                if ($v -notin $valid) { $v = 'flag' }
                # Only PERSIST non-default ('flag' is the implicit default) to keep the store lean (no-scaffolding default).
                if ($v -ne 'flag') { $clean["$k"] = $v }
            }
            Set-PimManagerSetting -Name 'DiscoveryAutoCreate' -Value $clean
            # Mirror into the live engine global so THIS process honours it immediately.
            $global:PIM_DiscoveryAutoCreate = $clean
            Write-PimManagerAuditEvent -Action 'discovery.policy.save' -Target ('types:' + (@($clean.Keys) -join ',')) -After $clean -Result 'ok'
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; policy = $clean })
            return 200
        }

        # -------------------------------------------------------------------
        # Governance: scheduled MAIL / job control. Drives the REAL scheduler
        # (PIM-Scheduler.ps1 Get-PimJobSchedule -> Get-PimPolicySetting 'JobSchedule'):
        # each job carries enabled + intervalMinutes. The Governance "Scheduled
        # mails & jobs" panel toggles the daily-summary / tier-report (and the
        # other governance-relevant jobs) on/off and adjusts cadence. Persisted
        # via Set-PimManagerSetting 'JobSchedule' (SQL pim.Settings / per-instance
        # JSON) AND mirrored into $global:PIM_JobSchedule so the in-process runner
        # and a freshly-booted scheduler (which hydrates SQL settings) both read it.
        # GET = any role; PUT = SuperAdmin only. Unknown job names rejected (the
        # set of job types is fixed by the engine).
        # -------------------------------------------------------------------
        if ($path -eq '/api/job-schedule' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $sched = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Scheduler.ps1'
            if (-not (Get-Command Get-PimDefaultJobSchedule -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $sched)) {
                try { . $sched } catch { }
            }
            $defaults = @()
            if (Get-Command Get-PimDefaultJobSchedule -ErrorAction SilentlyContinue) { $defaults = @(Get-PimDefaultJobSchedule) }
            $stored = Get-PimManagerSetting -Name 'JobSchedule'
            # Merge: defaults define the job catalog; stored overrides enabled/intervalMinutes per name.
            $overrideByName = @{}
            foreach ($o in @($stored)) { if ("$($o.name)".Trim()) { $overrideByName["$($o.name)"] = $o } }
            $jobs = New-Object System.Collections.ArrayList
            foreach ($d in $defaults) {
                $en = $true; if ($d.PSObject.Properties['enabled']) { $en = [bool]$d.enabled }
                $iv = 60;    if ($d.PSObject.Properties['intervalMinutes']) { $iv = [int]$d.intervalMinutes }
                if ($overrideByName.ContainsKey("$($d.name)")) {
                    $ov = $overrideByName["$($d.name)"]
                    if ($ov.PSObject.Properties['enabled'])         { $en = [bool]$ov.enabled }
                    if ($ov.PSObject.Properties['intervalMinutes']) { $iv = [int]$ov.intervalMinutes }
                }
                [void]$jobs.Add([ordered]@{
                    name = "$($d.name)"; type = "$($d.type)"
                    scope = $(if ($d.PSObject.Properties['scope']) { "$($d.scope)" } else { '' })
                    enabled = $en; intervalMinutes = $iv
                    isMail = [bool]("$($d.type)" -in @('daily-summary','tier-report','reminders','escalations'))
                })
            }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ jobs = @($jobs.ToArray()); customized = [bool]($stored) })
            return 200
        }

        if ($path -eq '/api/job-schedule' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to change the job/mail schedule.' }
                return 403
            }
            $sched = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Scheduler.ps1'
            if (-not (Get-Command Get-PimDefaultJobSchedule -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $sched)) {
                try { . $sched } catch { }
            }
            $catalog = @{}
            if (Get-Command Get-PimDefaultJobSchedule -ErrorAction SilentlyContinue) {
                foreach ($d in @(Get-PimDefaultJobSchedule)) { $catalog["$($d.name)"] = $d }
            }
            $body = Read-RequestJson -Request $req
            $raw = if ($body -and $body.PSObject.Properties['jobs']) { @($body.jobs) } else { @($body) }
            $merged = New-Object System.Collections.ArrayList
            foreach ($j in $raw) {
                $name = "$($j.name)".Trim()
                if (-not $name -or -not $catalog.ContainsKey($name)) { continue }   # fixed catalog -- ignore unknown
                $d = $catalog[$name]
                $entry = [ordered]@{ name = $name; type = "$($d.type)" }
                if ($d.PSObject.Properties['scope']) { $entry.scope = "$($d.scope)" }
                if ($j.PSObject.Properties['enabled']) { $entry.enabled = [bool]$j.enabled }
                else { $entry.enabled = $(if ($d.PSObject.Properties['enabled']) { [bool]$d.enabled } else { $true }) }
                $iv = $(if ($d.PSObject.Properties['intervalMinutes']) { [int]$d.intervalMinutes } else { 60 })
                if ($j.PSObject.Properties['intervalMinutes'] -and "$($j.intervalMinutes)".Trim()) {
                    $iv = [Math]::Max(1, [Math]::Min(43200, [int]$j.intervalMinutes))   # 1 min .. 30 days
                }
                $entry.intervalMinutes = $iv
                [void]$merged.Add([pscustomobject]$entry)
            }
            Set-PimManagerSetting -Name 'JobSchedule' -Value @($merged.ToArray())
            $global:PIM_JobSchedule = @($merged.ToArray())   # live in-process runner picks it up
            Write-PimManagerAuditEvent -Action 'schedule.save' -Target "jobs:$($merged.Count)" -After @{ count = $merged.Count } -Result 'ok'
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; count = $merged.Count })
            return 200
        }

        # -------------------------------------------------------------------
        # Governance: permission-template ACTIVE/DISABLED state. The /api/templates
        # diff (centrally-maintained delegation packs) lists every shipped template;
        # an operator can DISABLE a template they don't want surfaced for import.
        # State persisted via Set-PimManagerSetting 'TemplateState' (SQL/JSON); the
        # /api/templates response is annotated with `disabled` so the Governance
        # (and Create) views can hide disabled packs. GET = any; PUT = Admin+.
        # -------------------------------------------------------------------
        if ($path -eq '/api/template-state' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $stored = Get-PimManagerSetting -Name 'TemplateState'
            $h = ConvertTo-PimPlainHashtable $stored
            $out = [ordered]@{}
            foreach ($k in @($h.Keys)) { $out["$k"] = [bool]$h[$k] }   # id -> disabled(bool)
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ disabled = $out })
            return 200
        }

        if ($path -eq '/api/template-state' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to enable/disable a permission template.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $id = "$($body.id)".Trim()
            if (-not $id) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'id is required' }; return 400 }
            $disabled = [bool]$body.disabled
            $stored = Get-PimManagerSetting -Name 'TemplateState'
            $h = ConvertTo-PimPlainHashtable $stored
            if ($disabled) { $h[$id] = $true } else { if ($h.ContainsKey($id)) { [void]$h.Remove($id) } }
            Set-PimManagerSetting -Name 'TemplateState' -Value $h
            Write-PimManagerAuditEvent -Action 'template.state.save' -Target $id -After @{ disabled = $disabled } -Result 'ok'
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; id = $id; disabled = $disabled })
            return 200
        }

        # -------------------------------------------------------------------
        # Date-expression live preview (LIFECYCLE-GOVERNANCE phase 1) --
        # the onboarding wizard previews ProvisionDate / TAPStartDate while
        # the operator types ("resolves to Mon 2026-07-01 08:00 UTC").
        # -------------------------------------------------------------------
        if ($path -eq '/api/resolve-date' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $expr = $req.QueryString['expr']
            if (-not $expr -or -not (Get-Command Resolve-PimDateExpression -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $false; error = $(if ($expr) { 'resolver not loaded' } else { 'expr query parameter required' }) }
                return 200
            }
            try {
                $resolved = Resolve-PimDateExpression -Expression $expr
                Write-JsonResponse -Response $resp -Status 200 -Body @{
                    ok       = $true
                    utc      = $resolved.ToString('yyyy-MM-dd HH:mm')
                    display  = $resolved.ToLocalTime().ToString('ddd yyyy-MM-dd HH:mm') + ' (local)'
                }
            } catch {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
            }
            return 200
        }

        # -------------------------------------------------------------------
        # MSP multi-instance endpoints
        # -------------------------------------------------------------------
        # -------------------------------------------------------------------
        # Permission templates -- centrally maintained delegation packs
        # (templates/*.template.json ships with the repo; sync distributes).
        # The endpoint diffs each template against the ACTIVE instance and
        # reports the rows the instance doesn't have yet, so the UI can show
        # 'new permissions available to delegate' when a template grows.
        # -------------------------------------------------------------------
        if ($path -eq '/api/templates' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            function Get-PimTemplateRowKey {
                param([string]$Base, [object]$Row)
                $g = { param($p) $x = $Row.PSObject.Properties[$p]; if ($x -and $x.Value) { "$($x.Value)" } else { '' } }
                switch -Wildcard ($Base) {
                    'PIM-Definitions-AU'              { return (& $g 'AdministrativeUnitTag') }
                    'PIM-Definitions-*'               { return (& $g 'GroupTag') }
                    'Account-Definitions-Admins'      { return (& $g 'UserName') }
                    'PIM-Assignments-Admins'          { return ((& $g 'Username') + '|' + (& $g 'GroupTag')) }
                    'PIM-Assignments-Groups'          { return ((& $g 'TargetGroupTag') + '|' + (& $g 'SourceGroupTag')) }
                    'PIM-Assignments-Roles-Groups'    { return ((& $g 'GroupTag') + '|' + (& $g 'RoleDefinitionName')) }
                    'PIM-Assignments-Roles-AUs'       { return ((& $g 'GroupTag') + '|' + (& $g 'AdministrativeUnitTag') + '|' + (& $g 'RoleDefinitionName')) }
                    'PIM-Assignments-Azure-Resources' { return ((& $g 'GroupTag') + '|' + (& $g 'AzScope') + '|' + (& $g 'AzScopePermission')) }
                    default { return '' }
                }
            }
            $tplDir = Join-Path $solutionRoot 'templates'
            # Governance template active/disabled state (Set-PimManagerSetting 'TemplateState').
            $tplDisabled = ConvertTo-PimPlainHashtable (Get-PimManagerSetting -Name 'TemplateState')
            $outList = New-Object System.Collections.ArrayList
            if (Test-Path -LiteralPath $tplDir) {
                foreach ($f in (Get-ChildItem $tplDir -Filter '*.template.json' -File | Sort-Object Name)) {
                    try {
                        $raw = [System.IO.File]::ReadAllText($f.FullName, [System.Text.UTF8Encoding]::new($false))
                        if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
                        $tpl = $raw | ConvertFrom-Json
                        $missing = [ordered]@{}
                        $missingCount = 0
                        $totalCount = 0
                        $placeholderSkipped = 0
                        foreach ($baseProp in $tpl.rows.PSObject.Properties) {
                            $base = $baseProp.Name
                            if (-not (Get-PimCsvSpec -BaseName $base)) { continue }
                            $current = Read-PimRows -BaseName $base
                            $existing = @{}
                            foreach ($r in $current.rows) {
                                $k = Get-PimTemplateRowKey -Base $base -Row ([pscustomobject]$r)
                                if ($k -and $k -ne '|' ) { $existing[$k.ToLowerInvariant()] = $true }
                            }
                            $miss = New-Object System.Collections.ArrayList
                            foreach ($tr in @($baseProp.Value)) {
                                $totalCount++
                                # 🔴 §70.13 (operator 2026-09-13: "it makes no sense to have a sub with all 00000000", "why are
                                # they there"): azure-rbac.template.json ships rows with the all-zero subscription for the
                                # operator to fill in; offering them as "missing" imported them unchanged, and 4 such rows
                                # blocked every commit on internal. A placeholder row is never offered for import.
                                if ((@($tr.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join '|') -match '(?i)/subscriptions/0{8}-0{4}-0{4}-0{4}-0{12}') { $placeholderSkipped++; continue }
                                $k = Get-PimTemplateRowKey -Base $base -Row $tr
                                if ($k -and -not $existing.ContainsKey($k.ToLowerInvariant())) { [void]$miss.Add($tr) }
                            }
                            if ($miss.Count -gt 0) { $missing[$base] = $miss.ToArray(); $missingCount += $miss.Count }
                        }
                        [void]$outList.Add([ordered]@{
                            id = "$($tpl.id)"; name = "$($tpl.name)"; version = $tpl.version
                            description = "$($tpl.description)"
                            totalRows = $totalCount; missingCount = $missingCount; missing = $missing
                            placeholderRowsSkipped = $placeholderSkipped
                            disabled = [bool]($tplDisabled.ContainsKey("$($tpl.id)") -and $tplDisabled["$($tpl.id)"])
                        })
                    } catch {
                        [void]$outList.Add([ordered]@{ id = $f.Name; error = "$($_.Exception.Message)" })
                    }
                }
            }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ templates = $outList.ToArray() })
            return 200
        }

        # -------------------------------------------------------------------
        # Workload connectors (docs/WORKLOAD-CONNECTORS.md)
        # -------------------------------------------------------------------
        if ($path -eq '/api/workloads' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
            if (-not (Get-Command Read-PimWorkloadConnectors -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $shared)) {
                Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            }
            $dir = Join-Path $solutionRoot 'workloads\connectors'
            $list = New-Object System.Collections.ArrayList
            foreach ($c in @(Read-PimWorkloadConnectors -ConnectorsDir $dir)) {
                [void]$list.Add([ordered]@{ id = "$($c.id)"; name = "$($c.name)"; auth = "$($c.auth)"; permissionsNeeded = @($c.permissionsNeeded) })
            }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ workloads = $list.ToArray() })
            return 200
        }

        if ($path -eq '/api/workload-roles' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $wid = ''
            if ($req.Url.Query -match '(\?|&)id=([^&]+)') { $wid = [uri]::UnescapeDataString($Matches[2]) }
            if (-not $wid) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'id query parameter is required' }; return 400 }
            $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
            if (-not (Get-Command Get-PimWorkloadRoles -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $shared)) {
                Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            }
            $dir = Join-Path $solutionRoot 'workloads\connectors'
            $conn = @(Read-PimWorkloadConnectors -ConnectorsDir $dir) | Where-Object { "$($_.id)" -ieq $wid } | Select-Object -First 1
            if (-not $conn) { Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown workload connector: $wid" }; return 404 }
            try {
                # Live tenant call -- requires the app-only connection
                # (-ConnectPlatform / per-instance connection).
                Initialize-PimManagerTenantConnection
                $roles = @(Get-PimWorkloadRoles -Connector $conn)
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ id = $wid; roles = $roles })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 502 -Body @{ error = "$($_.Exception.Message)" }
                return 502
            }
        }

        # -------------------------------------------------------------------
        # Workload crawl map + reconciliation (Delegation Map workload-target).
        #   GET  /api/workload-crawl  -> the cached live-crawl map (engine writes
        #        it; GUI reads). Includes crawledUtc + per-connector ok/error.
        #   POST /api/workload-crawl  -> RUN the crawl sweep NOW (Admin+). The
        #        engine remains the writer; this just invokes that writer on
        #        demand (the scheduler/discovery does it on cadence).
        #   GET  /api/workload-recon  -> reconciliation summary (mapped/missing/
        #        exempted/unknown) over the desired PIM-Assignments-Workloads rows.
        # -------------------------------------------------------------------
        if ($path -eq '/api/workload-crawl' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $map = $null
            if (Get-Command Read-PimWorkloadCrawlMap -ErrorAction SilentlyContinue) {
                try { $map = Read-PimWorkloadCrawlMap } catch { $map = $null }
            }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ crawl = $map })
            return 200
        }
        if ($path -eq '/api/workload-crawl' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to run the workload crawl' }
                return 403
            }
            if (-not (Get-Command Update-PimWorkloadCrawlMap -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 501 -Body @{ error = 'workload crawl helper not loaded' }
                return 501
            }
            try {
                $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
                if (-not (Get-Command Read-PimWorkloadConnectors -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $shared)) {
                    Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                }
                Initialize-PimManagerTenantConnection
                $dir = Join-Path $solutionRoot 'workloads\connectors'
                $written = Update-PimWorkloadCrawlMap -ConnectorsDir $dir
                $map = Read-PimWorkloadCrawlMap
                Write-PimManagerAuditEvent -Action 'workload.crawl' -Target 'all-connectors' -After @{ crawledUtc = "$($map.crawledUtc)" }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; crawledUtc = "$($map.crawledUtc)"; crawl = $map })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 502 -Body @{ error = "$($_.Exception.Message)" }
                return 502
            }
        }
        if ($path -eq '/api/workload-recon' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $rows = @((Read-PimRows 'PIM-Assignments-Workloads').rows)
            $map = $null; $ex = @()
            if (Get-Command Read-PimWorkloadCrawlMap -ErrorAction SilentlyContinue) { try { $map = Read-PimWorkloadCrawlMap } catch { $map = $null } }
            if (Get-Command Read-PimWorkloadExemptions -ErrorAction SilentlyContinue) { try { $ex = @(Read-PimWorkloadExemptions -ConfigRoot $script:configRoot) } catch { $ex = @() } }
            $summary = $null
            if (Get-Command Get-PimWorkloadReconSummary -ErrorAction SilentlyContinue) {
                try { $summary = Get-PimWorkloadReconSummary -Rows $rows -CrawlMap $map -Exemptions $ex } catch { $summary = $null }
            }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ summary = $summary })
            return 200
        }

        # ----- Workload EXEMPTIONS (pim.Settings['WorkloadExemptions'], 2026-09-12) -----------------
        # They used to be settable only by editing a file on the server. GET: any signed-in role (the
        # recon view already shows 'exempted'). PUT: Admin+, the FULL list (add/remove happen in the
        # page), validated entry by entry -- a malformed entry refuses the whole save (400) instead of
        # being dropped quietly -- then stored through Save-PimWorkloadExemptions and audited.
        if ($path -eq '/api/workload-exemptions' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command Read-PimWorkloadExemptions -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = 'workload map library not loaded' }
                return 500
            }
            try {
                $now = [datetime]::UtcNow
                $list = @(Read-PimWorkloadExemptions | ForEach-Object {
                    $o = [ordered]@{}; foreach ($k in $_.Keys) { $o[$k] = $_[$k] }
                    $o['active'] = [bool](Test-PimWorkloadExemptionActive -Exemption ([pscustomobject]$_) -AsOf $now)
                    $o
                })
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ store = 'sql'; setting = 'WorkloadExemptions'; exemptions = @($list) })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }
        if ($path -eq '/api/workload-exemptions' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to change workload exemptions.' }
                return 403
            }
            if (-not (Get-Command Save-PimWorkloadExemptions -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = 'workload map library not loaded' }
                return 500
            }
            $body = Read-RequestJson -Request $req
            if (-not $body -or -not $body.PSObject.Properties['exemptions']) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'exemptions (the full list) is required' }
                return 400
            }
            $actor = "$(Get-PimManagerActor)"
            $rawList = @(@($body.exemptions) | Where-Object { $null -ne $_ })
            # An EMPTY list is a valid save (the last exemption removed). Not normalised: the reader treats a
            # document whose exemptions array is empty as a bare entry, which would then fail validation.
            $incoming = if ($rawList.Count) { @(Read-PimWorkloadExemptions -Config ([pscustomobject]@{ exemptions = $rawList })) } else { @() }
            $invalid = New-Object System.Collections.Generic.List[object]
            for ($i = 0; $i -lt $incoming.Count; $i++) {
                $x = $incoming[$i]; $why = @()
                if (-not $x.workload -and -not $x.role) { $why += 'a workload or a role is required (an exemption for everything is refused)' }
                if (-not $x.reason) { $why += 'a reason is required' }
                if (-not $x.noExpiry) {
                    if (-not $x.expiresOn) { $why += 'an expiry date is required (or tick No expiry)' }
                    elseif ($null -eq (Get-PimUtcStamp $x.expiresOn)) { $why += "expiry '$($x.expiresOn)' is not a date (use yyyy-MM-dd)" }
                }
                if ($why.Count) { [void]$invalid.Add([ordered]@{ index = $i; workload = "$($x.workload)"; role = "$($x.role)"; problems = @($why) }) }
                elseif (-not $x.createdBy) { $x['createdBy'] = $actor }
            }
            if ($invalid.Count) {
                Write-JsonResponse -Response $resp -Status 400 -Body ([ordered]@{ error = "$($invalid.Count) exemption(s) are incomplete -- nothing was saved"; invalid = @($invalid.ToArray()) })
                return 400
            }
            try {
                $before = @(); try { $before = @(Read-PimWorkloadExemptions) } catch {}
                $saved = @(Save-PimWorkloadExemptions -Exemptions $incoming)
                $after = @(Read-PimWorkloadExemptions)
                Write-PimManagerAuditEvent -Action 'workload.exemptions.save' -Target 'settings:WorkloadExemptions' -Before ([ordered]@{ count = $before.Count; exemptions = @($before) }) -After ([ordered]@{ count = $after.Count; exemptions = @($after) }) -Result 'ok'
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; store = 'sql'; saved = $saved.Count; exemptions = @($after) })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # -------------------------------------------------------------------
        # Delegated portal-admin access (admin-interface epic phase 2).
        # -------------------------------------------------------------------
        # ------------------------------------------------------------------
        # §65.7 -- THE QUEUE IS A SHARED REVIEW SURFACE.
        #
        # Operator, 2026-09-12: *"a queue must be visible for any concurrent member so i can also
        # see who did it"* and *"and i can select which entries in the queue to commit"*.
        #
        # 🔑 READ FROM THE STORE, NEVER FROM PROCESS STATE. Several admins use the Manager at once
        # (and the Manager's own token is minted per PROCESS), so a per-session queue would show
        # each person a different list -- which is the opposite of a review surface.
        # ------------------------------------------------------------------
        if ($path -eq '/api/queue' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $cs = (Get-PimManagerStoreCs)
            if (-not $cs -or -not (Get-Command Get-PimSqlQueue -ErrorAction SilentlyContinue)) {
                # 🪤 "Cannot read the queue" is NOT "the queue is empty". Reporting an unreadable
                # queue as [] would tell an operator their revoke vanished (§61.7, §63.6).
                Write-JsonResponse -Response $resp -Status 503 -Body @{ error = 'no SQL store is wired in this host, so the queue cannot be read'; readable = $false }
                return 503
            }
            # ?status= filters; empty/absent = every state, which is the default view. A queue that
            # hides its failures is not a review surface (§65.8: failed entries are RETAINED and
            # surfaced, never deleted).
            $st = "$($req.QueryString['status'])".Trim()
            try { $rows = @(Get-PimSqlQueue -ConnectionString $cs -Status $st) }
            catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "queue read failed: $($_.Exception.Message)"; readable = $false }
                return 500
            }
            $counts = @{}
            foreach ($g in @($rows | Group-Object status)) { $counts["$($g.Name)"] = [int]$g.Count }
            # OPEN work = everything not finished and not taken out of the queue. 'applied' is done;
            # 'discarded' was removed by an operator on purpose -- neither may keep the badge lit.
            $openRows = @($rows | Where-Object { "$($_.status)" -notin @('applied', 'discarded') })
            # Readable names for OLD entries (queued before names were stored): tenant caches first,
            # then ONE batched Graph call for the whole read -- see Get-PimQueueDisplayNameMap.
            $nameMap = @{}
            try { $nameMap = Get-PimQueueDisplayNameMap -Entries $rows } catch { $nameMap = @{} }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                ok       = $true
                readable = $true
                counts   = $counts
                openCount = $openRows.Count
                # Only a PENDING entry can be committed -- the GUI uses this to decide what is
                # selectable, rather than re-deriving the rule and drifting from the server.
                entries  = @($rows | ForEach-Object {
                    [ordered]@{
                        id            = "$($_.id)"
                        kind          = "$($_.kind)"
                        origin        = "$($_.origin)"
                        op            = "$($_.op)"
                        entity        = "$($_.entity)"
                        key           = "$($_.key)"
                        # One readable sentence ("Remove Jane Doe (jane@x) from Groups Administrator (Entra role)").
                        # The raw key stays alongside for audit; the GUI shows it small underneath.
                        display       = $(try { Format-PimQueueEntryDisplay -Entry $_ -Names $nameMap } catch { '(this entry could not be described -- see the key below)' })
                        status        = "$($_.status)"
                        by            = "$($_.by)"              # who did it (the operator's ask)
                        enqueuedUtc   = "$($_.enqueuedUtc)"
                        justification = "$($_.justification)"
                        committedBy   = "$($_.committedBy)"
                        committedUtc  = "$($_.committedUtc)"
                        attempts      = [int]$_.attempts
                        lastError     = "$($_.lastError)"
                        appliedUtc    = "$($_.appliedUtc)"
                        appliedBy     = "$($_.appliedBy)"
                        discardedBy   = "$($_.discardedBy)"
                        discardedUtc  = "$($_.discardedUtc)"
                        discardReason = "$($_.discardReason)"
                        committable   = ("$($_.status)" -eq 'pending')
                        # Discard is allowed for pending AND failed only -- never committed/applying/applied.
                        discardable   = ("$($_.status)" -in @('pending', 'failed'))
                    }
                })
            })
            return 200
        }

        if ($path -eq '/api/queue/commit' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            # Committing is what actually authorises a directory change, so it is an ADMIN act --
            # the same bar the direct revoke used to sit behind. A Reader can see the queue (above)
            # and commit nothing.
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to commit queue entries.' }
                return 403
            }
            $cs = (Get-PimManagerStoreCs)
            if (-not $cs -or -not (Get-Command Set-PimSqlQueueCommitted -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ error = 'no SQL store is wired in this host, so the queue cannot be committed' }
                return 503
            }
            $bodyIn = Read-RequestJson -Request $req
            $ids = @($bodyIn.ids | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
            if (-not $ids.Count) {
                # 🔒 NO "COMMIT EVERYTHING" DEFAULT. An empty selection is a mistake, not an
                # instruction to apply the whole queue -- the operator's requirement is that they
                # SELECT what to commit, and a convenience default here would quietly undo that.
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'select at least one entry to commit (no "commit all" default exists by design)' }
                return 400
            }
            $who = "$((Get-PimManagerRole).identity)"
            if (-not $who.Trim()) { $who = "$env:USERNAME" }
            try { $res = @(Set-PimSqlQueueCommitted -ConnectionString $cs -Ids $ids -By $who) }
            catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "commit failed: $($_.Exception.Message)" }
                return 500
            }
            $okN = @($res | Where-Object { $_.committed }).Count
            foreach ($r in $res) {
                Write-PimManagerAuditEvent -Action 'queue.commit' -Target "$($r.id)" `
                    -Result $(if ($r.committed) { 'ok' } else { 'skipped' }) `
                    -After ([ordered]@{ queueId = "$($r.id)"; state = "$($r.state)"; reason = "$($r.reason)"; committedBy = $who })
            }
            # §70.21: start the engine now so a committed action applies in about a minute, not at the next cron start.
            $kick = if ($okN -gt 0) { Start-PimManagerTickNow -Reason 'queue-commit' } else { $null }
            # 207-style honesty: a partial commit reports per-id, because "2 of 3" must not read as
            # complete success. Two admins committing at once is an expected case, not an error.
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                ok        = $true
                requested = $ids.Count
                committed = $okN
                skipped   = ($ids.Count - $okN)
                results   = @($res | ForEach-Object { [ordered]@{ id = "$($_.id)"; committed = [bool]$_.committed; state = "$($_.state)"; reason = "$($_.reason)" } })
                started   = [bool]($kick -and $kick.started)
                engine    = $(if ($kick) { "$($kick.detail)" } else { '' })
                note      = "Committed entries apply on the next engine run. Nothing is applied by this call itself."
            })
            return 200
        }

        # §70.21: the Pending changes page calls this ONCE after a configuration commit (all entities written), so the
        # engine starts now and applies the delta instead of waiting for the next cron start. Admin+ (same bar as Commit).
        if ($path -eq '/api/scheduler/kick' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to start the engine.' }
                return 403
            }
            $bodyIn = Read-RequestJson -Request $req
            $why = "$($bodyIn.reason)".Trim(); if (-not $why) { $why = 'commit' }
            if ($why.Length -gt 60) { $why = $why.Substring(0, 60) }
            $kick = Start-PimManagerTickNow -Reason $why
            Write-PimManagerAuditEvent -Action 'schedule.tick.start' -Target 'job:tick' -After ([ordered]@{ reason = $why; started = [bool]$kick.started; outcome = "$($kick.reason)"; detail = "$($kick.detail)" }) -Result $(if ($kick.started -or "$($kick.reason)" -eq 'running') { 'ok' } else { 'skipped' })
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; started = [bool]$kick.started; reason = "$($kick.reason)"; detail = "$($kick.detail)" })
            return 200
        }

        # ------------------------------------------------------------------
        # DISCARD selected queue entries (2026-09-12). A stale pending or FAILED entry -- e.g. a live
        # drain probe that failed -- could not be removed from the review surface at all.
        # 🔒 Admin+, pending/failed ONLY (enforced in SQL by Set-PimSqlQueueDiscarded), a REASON is
        # required, and the row is KEPT with DiscardedBy/Utc/Reason (section 65.8 retains history).
        # The drain only claims 'committed', so a discarded entry can never be applied.
        # ------------------------------------------------------------------
        if ($path -eq '/api/queue/discard' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to discard queue entries.' }
                return 403
            }
            $cs = (Get-PimManagerStoreCs)
            if (-not $cs -or -not (Get-Command Set-PimSqlQueueDiscarded -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ error = 'no SQL store is wired in this host, so the queue cannot be changed' }
                return 503
            }
            $bodyIn = Read-RequestJson -Request $req
            $ids = @($bodyIn.ids | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
            $reason = "$($bodyIn.reason)".Trim()
            if (-not $ids.Count) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'select at least one entry to discard' }
                return 400
            }
            if (-not $reason) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'a reason is required to discard queue entries (it is kept on the entry and in the audit trail)' }
                return 400
            }
            $who = "$(Get-PimManagerActor)"
            try { $res = @(Set-PimSqlQueueDiscarded -ConnectionString $cs -Ids $ids -By $who -Reason $reason) }
            catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "discard failed: $($_.Exception.Message)" }
                return 500
            }
            $okN = @($res | Where-Object { $_.discarded }).Count
            foreach ($r in $res) {
                Write-PimManagerAuditEvent -Action 'queue.discard' -Target "$($r.id)" `
                    -Result $(if ($r.discarded) { 'ok' } else { 'skipped' }) `
                    -After ([ordered]@{ queueId = "$($r.id)"; state = "$($r.state)"; reason = $reason; refused = "$($r.reason)"; discardedBy = $who })
            }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                ok        = $true
                requested = $ids.Count
                discarded = $okN
                skipped   = ($ids.Count - $okN)
                results   = @($res | ForEach-Object { [ordered]@{ id = "$($_.id)"; discarded = [bool]$_.discarded; state = "$($_.state)"; reason = "$($_.reason)" } })
            })
            return 200
        }

        if ($path -eq '/api/portal-access' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $role = Get-PimManagerRole
            $isSuper = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')
            $prof = $null
            if (Get-Command Read-PimPortalProfiles -ErrorAction SilentlyContinue) {
                $prof = Get-PimPortalProfile -Profiles (Read-PimPortalProfiles) -Identity "$($role.identity)"
            }
            $profOut = if ($prof) {
                [ordered]@{
                    displayName = "$($prof.displayName)"; services = @($prof.services)
                    tierMax = $prof.tierMax; levelMax = $prof.levelMax; scopes = @($prof.scopes)
                    capabilities = @($prof.capabilities); managedAdmins = @($prof.managedAdmins)
                }
            } else { $null }
            # §35.3 -- the wizard narrows its ROLE pickers to the caller's level ceiling, and it
            # needs the same role->level classification the engine derives from. Served from the
            # ENGINE's own functions rather than re-listed in JavaScript: a second copy of "which
            # roles are privileged" would drift, and it would drift in the direction of showing
            # Global Administrator to someone who may not have it.
            $privRoles = @(); $auRoles = @()
            try { if (Get-Command Get-PimPrivilegedEntraRoles -ErrorAction SilentlyContinue) { $privRoles = @(Get-PimPrivilegedEntraRoles) } } catch {}
            try { if (Get-Command Get-PimAuScopableRoles     -ErrorAction SilentlyContinue) { $auRoles   = @(Get-PimAuScopableRoles) } } catch {}
            # SEC-15 / §36.3 phase 2 -- report WHICH store answered. A silent fallback is the
            # defect; naming the source is what stops it being silent, and it makes
            # "why can this person suddenly do that?" an answerable question.
            $profSource = 'unknown'
            try { if (Get-Command Get-PimPortalProfileSource -ErrorAction SilentlyContinue) { $profSource = Get-PimPortalProfileSource } } catch {}
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                identity = "$($role.identity)"; managerRole = "$($role.role)"; isSuperAdmin = $isSuper
                portalProfile = $profOut
                profileSource = $profSource     # sql | sql-empty | sql-invalid (SQL is the only store)
                hosted        = [bool]$script:PimHosted
                # Level model, as the engine derives it: privileged = L0, AU-scopable = L2,
                # everything else = L1 (REQUIREMENTS §11 "Entra derives tier/level").
                roleLevels = [ordered]@{ privileged = @($privRoles); auScopable = @($auRoles) }
            })
            return 200
        }

        # Reversed permission-wizard auto-derivation (target -> source -> roles).
        if ($path -eq '/api/wizard/derive' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            $b = Read-RequestJson -Request $req
            $target = "$($b.target)".Trim().ToLowerInvariant()
            $roles = @(@($b.roles) | ForEach-Object { "$_" } | Where-Object { "$_".Trim() })
            try {
                if ($target -notin @('entra','azure','workload','admin')) { throw "unknown target '$target' (expected entra | azure | workload | admin)" }
                if ($target -eq 'admin') {
                    # Admin ACCOUNT name derivation: owner + admin-type (prefix) +
                    # environment (suffix) -> the resolved UserName (§17). No roles.
                    if (-not "$($b.owner)".Trim()) { throw 'owner is required for target admin' }
                    $hp = $false
                    if ($null -ne $b.highPriv) { $hp = [bool]$b.highPriv }
                    elseif ("$($b.purpose)".Trim().ToLowerInvariant() -eq 'highpriv') { $hp = $true }
                    $d = Get-PimWizardDerivation -Target 'admin' -Owner "$($b.owner)" `
                        -AdminType "$($b.adminType)" -Environment "$($b.environment)" -HighPriv:$hp
                    Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; derivation = $d })
                    return 200
                }
                if (-not $roles -or $roles.Count -eq 0) { throw 'at least one role is required' }
                $depth = if ("$($b.mgmtGroupDepth)".Trim()) { [int]$b.mgmtGroupDepth } else { 1 }
                $d = Get-PimWizardDerivation -Target $target -Roles $roles `
                    -AuScope "$($b.auScope)" `
                    -ScopeType "$($b.scopeType)" -ScopePath "$($b.scopePath)" -ScopeName "$($b.scopeName)" -ManagementGroupDepth $depth `
                    -Workload "$($b.workload)" -Scope "$($b.scope)" `
                    -BundleName "$($b.bundleName)"
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; derivation = $d })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "$($_.Exception.Message)" }
                return 400
            }
        }

        # -------------------------------------------------------------------
        # Onboarding convenience flows (engine/_shared/PIM-Onboarding.ps1).
        # Both COMPUTE artefacts (a guest invitation body + change-queue rows /
        # a single toggle change) the operator then saves through the normal
        # Review & Save flow -- the engine stays the only writer to Entra/Azure.
        # Gated by the delegated portal-admin capability (invite-guest /
        # enable-consultants); a SuperAdmin bypasses the portal scoping.
        # -------------------------------------------------------------------
        if ($path -like '/api/onboarding/*' -and $method -eq 'POST') {
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            $role    = Get-PimManagerRole
            $isSuper = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')
            $prof    = $null
            if (Get-Command Read-PimPortalProfiles -ErrorAction SilentlyContinue) {
                $prof = Get-PimPortalProfile -Profiles (Read-PimPortalProfiles) -Identity "$($role.identity)"
            }
            $b = Read-RequestJson -Request $req
            try {
                switch ($path) {
                    '/api/onboarding/guest-invite' {
                        if (-not (Test-PimPortalCanInviteGuest -Profile $prof -IsSuperAdmin:$isSuper)) {
                            Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'not permitted: the invite-guest capability is required (or SuperAdmin)' }; return 403
                        }
                        $days = if ("$($b.numOfDaysWhenExpire)".Trim()) { [int]$b.numOfDaysWhenExpire } else { 0 }
                        $atype = if ("$($b.assignmentType)".Trim()) { "$($b.assignmentType)" } else { 'Eligible' }
                        $cloud = if ($null -ne $b.cloud) { [bool]$b.cloud } else { $true }
                        $plan = New-PimGuestOnboardingPlan -Email "$($b.email)" -DisplayName "$($b.displayName)" `
                            -FirstName "$($b.firstName)" -LastName "$($b.lastName)" -Company "$($b.company)" `
                            -Department "$($b.department)" -Notes "$($b.notes)" -GroupTag "$($b.groupTag)" `
                            -AssignmentType $atype -NumOfDaysWhenExpire $days -Cloud $cloud `
                            -CustomMessage "$($b.customMessage)" -By "$($role.identity)"
                        $status = if ($plan.ok) { 200 } else { 400 }
                        Write-JsonResponse -Response $resp -Status $status -Body ([ordered]@{ ok = $plan.ok; mode = $plan.mode; invitation = $plan.invitation; changes = @($plan.changes); count = @($plan.changes).Count; reason = $plan.reason })
                        return $status
                    }
                    '/api/onboarding/self-service-toggle' {
                        $action = "$($b.action)".Trim().ToLowerInvariant()
                        if ($action -notin @('enable','disable')) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "action must be 'enable' or 'disable'" }; return 400 }
                        $res = Resolve-PimSelfServiceToggle -Profile $prof -AccountName "$($b.accountName)" -Action $action -IsSuperAdmin:$isSuper -By "$($role.identity)"
                        if (-not $res.allowed) { Write-JsonResponse -Response $resp -Status 403 -Body @{ error = $res.reason }; return 403 }
                        Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; change = $res.change; changes = @($res.change); count = 1; reason = $res.reason })
                        return 200
                    }
                    default { Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown onboarding endpoint '$path'" }; return 404 }
                }
            } catch {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "$($_.Exception.Message)" }
                return 400
            }
        }

        # -------------------------------------------------------------------
        # Manager authoring helpers (engine/_shared/PIM-Authoring.ps1). Each
        # endpoint COMPUTES a row set (preview); the operator saves it through
        # the normal /api/data/<base> PUT (Review & Save). They never write to
        # Entra/Azure -- the engine stays the only writer. Admin role required.
        # -------------------------------------------------------------------
        if ($path -like '/api/authoring/*' -and $method -eq 'POST') {
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            $b = Read-RequestJson -Request $req
            # [Fix 2] PORTAL SCOPE on authoring: a non-SuperAdmin delegated caller may
            # only author against rows inside their tier/level/service/scope. We re-check
            # the input rows a case operates on (clone source/template, the rows targeted
            # for delete) so a delegated caller can't COMPUTE an out-of-scope change set
            # to then save. SuperAdmin / no-profile bypass (the final write PUT re-checks
            # too -- this just stops the plan being built out of scope). Cases whose input
            # rows aren't derivable here are still gated at PUT.
            # SEC-04 (2026-08-06): if the rows CANNOT BE READ, this now returns 403 rather
            # than skipping the check. "Could not determine scope" is not "in scope".
            $authScope = Get-PimManagerCallerScope
            if (-not $authScope.isSuperAdmin -and $authScope.profile -and (Get-Command Test-PimPortalRowsInScope -ErrorAction SilentlyContinue)) {
                $authRows = New-Object System.Collections.ArrayList
                $authBase = "$($b.base)"
                # SEC-04: distinguishes "there is nothing to authorise" from "we could NOT
                # WORK OUT what to authorise". Only the second denies -- see below.
                $authScopeUnknown = $false
                $authScopeUnknownWhy = ''
                switch ($path) {
                    '/api/authoring/clone'            { if ($b.templateRow) { [void]$authRows.Add((ConvertTo-OrderedRow $b.templateRow)) } }
                    '/api/authoring/clone-azure-role' { if ($b.sourceRow)   { [void]$authRows.Add((ConvertTo-OrderedRow $b.sourceRow)) } }
                    '/api/authoring/delete-rows' {
                        $dbase = "$($b.base)"; $authBase = $dbase
                        if ($dbase -and (Get-PimCsvSpec -BaseName $dbase)) {
                            try {
                                $cur = @((Read-PimRows -BaseName $dbase).rows)
                                foreach ($ix in @(@($b.indexes) | ForEach-Object { [int]$_ })) { if ($ix -ge 0 -and $ix -lt $cur.Count) { [void]$authRows.Add($cur[$ix]) } }
                            } catch {
                                # SEC-04: this read failing used to leave $authRows EMPTY, which
                                # skipped the scope check below entirely -- it failed OPEN on a
                                # delegation boundary. It now fails CLOSED: we cannot tell whether
                                # the targeted rows are inside this caller's scope, and "don't know"
                                # must never read as "allowed" on a security boundary.
                                $authScopeUnknown = $true
                                $authScopeUnknownWhy = "could not read the target rows for '$dbase'"
                                if (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue) {
                                    Write-PimSwallowed -Scope 'portal-scope-rows-read' -ErrorRecord $_ `
                                        -Consequence ("could not read rows for '{0}' -- DENYING the request (403): scope cannot be verified" -f $dbase)
                                }
                            }
                        }
                    }
                    default { foreach ($rr in @(@($b.rows) | ForEach-Object { ConvertTo-OrderedRow $_ })) { if ($rr) { [void]$authRows.Add($rr) } } }
                }
                # SEC-04: fail CLOSED when the scope could not be determined at all. Note
                # this is NOT the same as an empty row set: a case with genuinely no rows
                # to authorise (nothing selected, a table that is legitimately empty) still
                # proceeds and is gated at PUT, exactly as before. Only an ERROR denies.
                if ($authScopeUnknown) {
                    Write-JsonResponse -Response $resp -Status 403 -Body ([ordered]@{
                        ok = $false
                        error = "portal scope could not be verified -- $authScopeUnknownWhy. Refusing rather than proceeding unchecked."
                        denied = @()
                    })
                    return 403
                }
                if ($authRows.Count -gt 0) {
                    $asr = Test-PimPortalRowsInScope -Profile $authScope.profile -Rows @($authRows.ToArray()) -Base $authBase -RequireManage
                    if (-not $asr.allowed) {
                        Write-JsonResponse -Response $resp -Status 403 -Body ([ordered]@{ ok = $false; error = "$($asr.reason)"; denied = @($asr.denied) })
                        return 403
                    }
                }
            }
            try {
                switch ($path) {
                    '/api/authoring/bulk-attach' {
                        $d = New-PimBulkAttachRows -GroupTag "$($b.groupTag)" `
                            -EntraRoles @(@($b.entraRoles) | ForEach-Object { "$_" }) `
                            -AzureScopes @($b.azureScopes) -AuScopes @($b.auScopes) `
                            -AssignmentType $(if ("$($b.assignmentType)".Trim()) { "$($b.assignmentType)" } else { 'Eligible' }) `
                            -NumOfDaysWhenExpire $(if ("$($b.numOfDaysWhenExpire)".Trim()) { [int]$b.numOfDaysWhenExpire } else { 0 })
                        Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; result = $d }); return 200
                    }
                    '/api/authoring/clone' {
                        $tpl = ConvertTo-OrderedRow $b.templateRow
                        $set = @{}; if ($b.setColumns) { foreach ($p in $b.setColumns.PSObject.Properties) { $set[$p.Name] = "$($p.Value)" } }
                        $rows = Copy-PimDefinitionRows -TemplateRow $tpl -NewTags @(@($b.newTags) | ForEach-Object { "$_" }) `
                            -TagColumn $(if ("$($b.tagColumn)".Trim()) { "$($b.tagColumn)" } else { 'GroupTag' }) -SetColumns $set
                        Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; rows = $rows; count = @($rows).Count }); return 200
                    }
                    '/api/authoring/clone-azure-role' {
                        $src = ConvertTo-OrderedRow $b.sourceRow
                        $rows = Copy-PimAzureRbacToRole -SourceRow $src -NewRoles @(@($b.newRoles) | ForEach-Object { "$_" })
                        Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; rows = $rows; count = @($rows).Count }); return 200
                    }
                    '/api/authoring/au' {
                        $d = New-PimAuRows -AuDisplayName "$($b.auDisplayName)" -AdministrativeUnitTag "$($b.auTag)" `
                            -AuDescription "$($b.auDescription)" -Workload "$($b.workload)" -Level "$($b.level)" `
                            -TierLevel "$($b.tierLevel)" -Visibility $(if ("$($b.visibility)".Trim()) { "$($b.visibility)" } else { 'Public' }) `
                            -RoleBindings @($b.roleBindings)
                        Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; result = $d }); return 200
                    }
                    '/api/authoring/import-admins' {
                        $people = if ($b.text) { ConvertFrom-PimAdminImportCsv -Text "$($b.text)" } else { @($b.people | ForEach-Object { ConvertTo-OrderedRow $_ }) }
                        $tpl = $null
                        if ("$($b.templateId)".Trim()) {
                            $tplDir = Join-Path $solutionRoot 'templates\admin'
                            $files = @(Get-ChildItem -LiteralPath $tplDir -Filter '*.admintemplate.json' -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\.custom\.' })
                            foreach ($f in $files) { try { $j = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json; if ("$($j.id)" -eq "$($b.templateId)") { $tpl = $j } } catch {} }
                        }
                        $rows = New-PimAdminRowsFromImport -People @($people) -Template $tpl
                        Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; rows = $rows; count = @($rows).Count; parsed = @($people).Count }); return 200
                    }
                    '/api/authoring/move-admin' {
                        $current = Read-PimRows -BaseName 'PIM-Assignments-Admins'
                        $d = New-PimAdminMovePlan -AssignmentRows @($current.rows) -Username "$($b.username)" -FromTag "$($b.fromTag)" -ToTag "$($b.toTag)"
                        Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; result = $d }); return 200
                    }
                    '/api/authoring/delete-rows' {
                        $base = "$($b.base)"
                        $spec = Get-PimCsvSpec -BaseName $base
                        if (-not $spec) { Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown csv base: $base" }; return 404 }
                        $current = Read-PimRows -BaseName $base
                        $d = Remove-PimRowsByIndex -Rows @($current.rows) -Indexes @(@($b.indexes) | ForEach-Object { [int]$_ })
                        Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; base = $base; rows = $d.rows; removedCount = $d.removedCount }); return 200
                    }
                    '/api/authoring/preview' {
                        # [M3] Inline preview/diff BEFORE commit for ANY authoring action.
                        # The GUI sends the action it is about to run + the rows it computed
                        # (the 'after' set). The server resolves the entity base + stage mode
                        # for that action, reads the CURRENT store rows as the 'before', and
                        # returns the KEYED add/modify/remove diff + a loud 'destructive' flag,
                        # so the operator sees EXACTLY what will change (incl. the otherwise
                        # hidden server ops: clone-azure-role / clone-au / delete-rows) and no
                        # row is silently dropped. Read-only -- computes, never writes.
                        $action = "$($b.action)".Trim()
                        if (-not $action) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "action is required" }; return 400 }
                        $shape = Get-PimAuthoringActionShape -Action $action -Base "$($b.base)"
                        $base = "$($shape.base)"
                        if (-not $base) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "could not resolve a base for action '$action' -- pass 'base'." }; return 400 }
                        if (-not (Get-PimCsvSpec -BaseName $base)) { Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown csv base: $base" }; return 404 }
                        $current = Read-PimRows -BaseName $base
                        $afterRows = @(@($b.rows) | ForEach-Object { ConvertTo-OrderedRow $_ })
                        $pv = Get-PimAuthoringPreview -Base $base -Before @($current.rows) -After $afterRows -Mode "$($shape.mode)" -Action $action
                        Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; preview = $pv }); return 200
                    }
                    '/api/authoring/sensitivity' {
                        # [M4] MAKER/CHECKER second-person approval gate on SENSITIVE
                        # authoring/onboarding. The GUI POSTs the action it is about to
                        # stage + the rows it computed; the server CLASSIFIES the change
                        # (privileged-role attach / guest-into-privileged-group /
                        # disable+offboard) and returns the COMMIT-GATE decision: a
                        # non-sensitive change is allowed (commit as before); a sensitive
                        # change is allowed ONLY when an Approved 'authoring' request for
                        # its target exists (a DIFFERENT admin approved it -- maker!=checker
                        # is enforced by the shared ApprovalGate). When blocked, the GUI
                        # routes the operator to raise that approval on the Approvals tab.
                        # Read-only -- classifies + checks; never writes.
                        $action = "$($b.action)".Trim()
                        if (-not $action) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "action is required" }; return 400 }
                        $shape = Get-PimAuthoringActionShape -Action $action -Base "$($b.base)"
                        $base = "$($shape.base)"; if (-not $base) { $base = "$($b.base)".Trim() }
                        $rows = @(@($b.rows) | ForEach-Object { ConvertTo-OrderedRow $_ })
                        if (-not (Get-Command Test-PimAuthoringCommitAllowed -ErrorAction SilentlyContinue)) {
                            # Library missing -> fail safe OPEN for non-sensitive shape only is unsafe;
                            # report not-loaded so the GUI does not silently bypass the gate.
                            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $false; note = 'sensitive-authoring library not loaded'; sensitive = $false; allowed = $true; gate = 'lib-missing' }); return 200
                        }
                        $reqs = @()
                        if (Get-Command Get-PimApprovalRequests -ErrorAction SilentlyContinue) { try { $reqs = @(Get-PimApprovalRequests) } catch {} }
                        $g = Test-PimAuthoringCommitAllowed -Action $action -Base $base -Rows $rows -Requests $reqs
                        Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                            ok        = $true
                            action    = $action
                            base      = $base
                            sensitive = [bool]$g.sensitive
                            allowed   = [bool]$g.allowed
                            gate      = "$($g.gate)"
                            reason    = "$($g.reason)"
                            reasons   = @($g.reasons)
                            target    = "$($g.target)"
                        }); return 200
                    }
                    '/api/authoring/map-removal' {
                        # [M8] residual -- STAGE A REMOVAL (revoke a grant) directly
                        # from the Delegation Map. The GUI sends ONE selection:
                        #   { mode:'edge', edgeKind, edgeBase?, match:{...} }  -- one grant
                        #   { mode:'node', nodeId }                            -- a flagged node
                        # The server resolves the row-level revocation plan against the
                        # LIVE graph model + current store rows (Resolve-PimMapRemovalPlan,
                        # pure), then -- per affected base -- runs the resulting after set
                        # through the SAME keyed preview (replace mode => the dropped grant
                        # shows as a keyed REMOVE + destructive flag) and classifies the
                        # REMOVED rows for the maker/checker gate. It RETURNS the plan +
                        # preview + sensitivity; it does NOT write. The GUI confirms the
                        # preview, passes the maker/checker gate, and stages the after set
                        # as a normal Review & Save change (engine stays the only writer;
                        # commit goes through backup/undo). Never a one-click destructive bypass.
                        $mode = "$($b.mode)".Trim().ToLowerInvariant()
                        if ($mode -ne 'edge' -and $mode -ne 'node') {
                            Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "mode must be 'edge' or 'node'" }; return 400
                        }
                        $data = Build-PimGraphData
                        # Current rows for every assignment base the plan can touch.
                        $assignBases = @('PIM-Assignments-Admins','PIM-Assignments-Groups','PIM-Assignments-Roles-Groups','PIM-Assignments-Roles-AUs','PIM-Assignments-Azure-Resources')
                        $current = @{}
                        foreach ($ab in $assignBases) { try { $current[$ab] = @((Read-PimRows -BaseName $ab).rows) } catch { $current[$ab] = @() } }
                        if ($mode -eq 'edge') {
                            $matchObj = ConvertTo-OrderedRow $b.match
                            $plan = Resolve-PimMapRemovalPlan -Data $data -CurrentRows $current -EdgeMatch $matchObj -EdgeKind "$($b.edgeKind)" -EdgeBase "$($b.edgeBase)"
                        } else {
                            $plan = Resolve-PimMapRemovalPlan -Data $data -CurrentRows $current -NodeId "$($b.nodeId)"
                        }
                        if (-not $plan.ok) {
                            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $false; plan = $plan; note = (@($plan.reasons) -join ' ') }); return 200
                        }
                        # Per-base keyed preview (replace mode) + collect every removed row
                        # for the single sensitivity decision (a removal of privileged rows
                        # is sensitive -- the [M4] maker/checker gate applies to removals too).
                        $previews = New-Object System.Collections.ArrayList
                        $allRemoved = New-Object System.Collections.ArrayList
                        foreach ($pl in @($plan.plans)) {
                            $pvBase = "$($pl.base)"
                            $pv = Get-PimAuthoringPreview -Base $pvBase -Before @($current[$pvBase]) -After @($pl.afterRows) -Mode 'replace' -Action 'delete-rows'
                            [void]$previews.Add([ordered]@{ base = $pvBase; preview = $pv })
                            foreach ($rr in @($pl.removedRows)) { [void]$allRemoved.Add($rr) }
                        }
                        # Sensitivity over the removed rows (use the first affected base for
                        # the gate's target key -- the GUI passes this through unchanged).
                        $gateBase = if (@($plan.plans).Count -gt 0) { "$(@($plan.plans)[0].base)" } else { '' }
                        $sens = [ordered]@{ sensitive = $false; allowed = $true; gate = 'lib-missing'; reasons = @(); target = '' }
                        if (Get-Command Test-PimAuthoringCommitAllowed -ErrorAction SilentlyContinue) {
                            $reqs = @()
                            if (Get-Command Get-PimApprovalRequests -ErrorAction SilentlyContinue) { try { $reqs = @(Get-PimApprovalRequests) } catch {} }
                            $g = Test-PimAuthoringCommitAllowed -Action 'delete-rows' -Base $gateBase -Rows @($allRemoved.ToArray()) -Requests $reqs
                            $sens = [ordered]@{ sensitive = [bool]$g.sensitive; allowed = [bool]$g.allowed; gate = "$($g.gate)"; reason = "$($g.reason)"; reasons = @($g.reasons); target = "$($g.target)" }
                        }
                        Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                            ok          = $true
                            plan        = $plan
                            previews    = @($previews.ToArray())
                            sensitivity = $sens
                            destructive = $true
                        }); return 200
                    }
                    default {
                        Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown authoring action: $path" }; return 404
                    }
                }
            } catch {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "$($_.Exception.Message)" }
                return 400
            }
        }

        # Role-permission drill-down (read-only): fetch a Graph roleDefinition's
        # concrete allowedResourceActions and return the grouped/flattened list.
        # ROADMAP #2/#25 + §28 [H9]. Live Graph read for the permission set; a
        # NEAR-MISS name no longer 503s -- it returns 200 with ranked
        # "did you mean..." candidates (Resolve-PimRoleQuery over the role
        # catalog), so a typo helps instead of erroring. A genuinely empty
        # catalog yields an empty candidate list, never a 5xx.
        if ($path -eq '/api/role-permissions' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $roleName = "$($req.QueryString['role'])".Trim()
            if (-not $roleName) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "role query parameter is required" }; return 400 }
            try {
                $def = $null
                # 🔴 §70.20 (operator 2026-09-13: Role lookup said "No role matches 'Exchange Administrator'"). This read
                # ran ONLY through the Graph PowerShell SDK (Invoke-MgGraphRequest), which the hosted container does not
                # ship (REST-only) -- so on every hosted Manager the live read was skipped and every role "did not match".
                # REST first (Invoke-PimGraph, the Manager's own app-only token), the SDK only where it exists.
                $esc = [uri]::EscapeDataString($roleName.Replace("'", "''"))
                $u = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq '$esc'"
                if (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue) {
                    Initialize-PimManagerTenantConnection
                    $r = Invoke-PimGraph -Method GET -Path $u
                    if ($r.value -and @($r.value).Count -gt 0) { $def = @($r.value)[0] }
                } elseif (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
                    $r = Invoke-MgGraphRequest -Method GET -Uri $u -ErrorAction Stop
                    if ($r.value -and @($r.value).Count -gt 0) { $def = @($r.value)[0] }
                }
                if ($def) {
                    $fmt = Format-PimRolePermissions -RoleDefinition $def
                    Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; matched = $true; role = $roleName; permissions = $fmt }); return 200
                }
                # Exact name didn't resolve (typo, or no Graph read available). Resolve
                # against the known role catalog and offer ranked candidates. 200, never 503.
                $catalog = @(Get-PimRoleCatalogNames)
                $res = Resolve-PimRoleQuery -Query $roleName -RoleNames $catalog
                $hasGraph = [bool](Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue) -or [bool](Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)
                $hint = if (@($res.candidates).Count -gt 0) {
                    "No directory role is named exactly '$roleName'. Pick one of the suggestions, or correct the spelling."
                } elseif (-not $hasGraph -and @($catalog).Count -eq 0) {
                    "Role names aren't available yet -- connect the Manager to the tenant (or refresh tenant lists), then retry."
                } else {
                    "No role matches '$roleName'."
                }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok = $true; matched = $false; role = $roleName
                    permissions = $null; candidates = @($res.candidates)
                    catalogSize = @($catalog).Count; graphConnected = $hasGraph; hint = $hint
                }); return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }; return 500
            }
        }

        # Search-by-action (§28 [H9a]): the INVERSE of the drill-down -- "which
        # directory roles grant operation X?" Fetches every roleDefinition with its
        # allowedResourceActions, runs the pure Find-PimRolesByAction matcher, and
        # returns the roles ranked LEAST-PRIVILEGE FIRST (fewest total actions) so
        # the operator finds the narrowest role for a least-privilege ticket. A
        # blank action -> 400; no live Graph / no match -> 200 with an empty list +
        # an honest hint (never a 5xx for a legitimate "nothing grants this").
        if ($path -eq '/api/role-permissions/by-action' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $action = "$($req.QueryString['action'])".Trim()
            if (-not $action) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "action query parameter is required" }; return 400 }
            try {
                $defs = New-Object System.Collections.ArrayList
                # §70.20: REST first -- the SDK-only read never ran on the hosted Manager (see /api/role-permissions).
                $hasRest = [bool](Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)
                $hasGraph = $hasRest -or [bool](Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)
                if ($hasGraph) {
                    # Page through every directory role definition WITH its permissions.
                    $u = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName,isBuiltIn,rolePermissions&`$top=200"
                    if ($hasRest) { Initialize-PimManagerTenantConnection }
                    $guard = 0
                    while ($u -and $guard -lt 50) {
                        $guard++
                        $r = if ($hasRest) { Invoke-PimGraph -Method GET -Path $u } else { Invoke-MgGraphRequest -Method GET -Uri $u -ErrorAction Stop }
                        foreach ($d in @($r.value)) { [void]$defs.Add($d) }
                        $u = if ($r.'@odata.nextLink') { "$($r.'@odata.nextLink')" } else { $null }
                    }
                }
                $res = Find-PimRolesByAction -Action $action -RoleDefinitions @($defs.ToArray())
                $hint = if (@($res.matches).Count -gt 0) {
                    "{0} role(s) grant '{1}'. The list is ranked least-privilege first -- prefer the narrowest role." -f @($res.matches).Count, $action
                } elseif (-not $hasGraph -or $defs.Count -eq 0) {
                    "Role permissions aren't available yet -- connect the Manager to the tenant (the engine SPN needs RoleManagement.Read.Directory), then retry."
                } else {
                    "No directory role grants '$action'. Check the action spelling (e.g. microsoft.directory/users/basic/update), or try a 'namespace/*' wildcard."
                }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok = $true; action = $action
                    matched = [bool]$res.matched
                    matches = @($res.matches)
                    matchCount = [int]$res.matchCount
                    rolesSearched = [int]$res.rolesSearched
                    graphConnected = $hasGraph
                    hint = $hint
                }); return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }; return 500
            }
        }

        # Reverse Role Lookup (§28 [H9]): "who has / who can activate this role" +
        # the path. Reuses Get-PimRoleReachers over the live delegation model. A
        # typo'd role name returns ranked candidates (200) instead of an empty/500.
        if ($path -eq '/api/role-lookup/reverse' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $roleName = "$($req.QueryString['role'])".Trim()
            $kind = "$($req.QueryString['kind'])".Trim()
            if (-not $roleName) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "role query parameter is required" }; return 400 }
            try {
                $model = Get-PimAccessGraphModel
                $rev = Get-PimRoleReachers -Role $roleName -Model $model -Kind $kind
                if ([int]$rev.resolved -ge 1) {
                    Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; matched = $true; result = $rev }); return 200
                }
                # No target node by that exact name -> offer ranked candidates.
                $catalog = @(Get-PimRoleCatalogNames -Model $model)
                $res = Resolve-PimRoleQuery -Query $roleName -RoleNames $catalog
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok = $true; matched = $false; role = $roleName
                    result = $rev; candidates = @($res.candidates)
                    hint = "No delegated role matches '$roleName' exactly."
                }); return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }; return 500
            }
        }

        # Role compare (§28 [H9]): pick two roles, return who/what each reaches --
        # overlap + each-only sets. Built on Get-PimRoleReachers + Compare-PimReachSets.
        if ($path -eq '/api/role-lookup/compare' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $roleA = "$($req.QueryString['roleA'])".Trim()
            $roleB = "$($req.QueryString['roleB'])".Trim()
            if (-not $roleA -or -not $roleB) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "roleA and roleB query parameters are required" }; return 400 }
            try {
                $model = Get-PimAccessGraphModel
                $revA = Get-PimRoleReachers -Role $roleA -Model $model
                $revB = Get-PimRoleReachers -Role $roleB -Model $model
                $cmp = Compare-PimReachSets -ReachersA @($revA.reachers) -ReachersB @($revB.reachers) -LabelA $roleA -LabelB $roleB
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok = $true
                    roleA = $roleA; roleB = $roleB
                    resolvedA = [int]$revA.resolved; resolvedB = [int]$revB.resolved
                    comparison = $cmp
                }); return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }; return 500
            }
        }

        # -------------------------------------------------------------------
        # Native template versioning + conformance (engine/_shared/PIM-Conformance.ps1).
        # Per-instance: ring = Get-PimTenantRing, applied version + exemptions are
        # keyed by the active instance. /api/conformance/* (distinct from the
        # CSV-template /api/templates above).
        # -------------------------------------------------------------------
        if ($path -like '/api/conformance*') {
            $script:lastHeartbeat = Get-Date
            $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
            if (-not (Get-Command Get-PimConformance -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $shared)) {
                Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            }
            $confTplDir = Join-Path $solutionRoot 'workloads\templates'
            # Applied-version stamps: SQL pim.Settings['ConformanceTemplateState'] (Get-/Set-PimTemplateState) -- no state file.
            $confTenant = "$script:PimInstanceName"
            $confRing   = Get-PimTenantRing
            # SEC-17: reads SQL pim.Settings['ConformanceExemptions'] only, and NEVER the
            # shipped sample. See Get-PimManagerConformanceExemptions for why the
            # sample fallback was a live waiver rather than a convenience.
            $readEx = { @(Get-PimManagerConformanceExemptions) }
            $findTplFile = {
                param($Id)
                if (-not (Test-Path -LiteralPath $confTplDir)) { return $null }
                foreach ($f in Get-ChildItem -LiteralPath $confTplDir -Filter '*.template.json' -File) {
                    try { $t = ConvertTo-PimTemplate -Json ([System.IO.File]::ReadAllText($f.FullName, [System.Text.UTF8Encoding]::new($false)))
                          if ("$($t.templateId)" -eq "$Id") { return $f.FullName } } catch {}
                }
                return $null
            }

            if ($path -eq '/api/conformance/templates' -and $method -eq 'GET') {
                $all = @(Read-PimApprovedTemplates -SourceDir $confTplDir -IncludeDrafts -WarningAction SilentlyContinue)
                $rows = New-Object System.Collections.ArrayList
                foreach ($t in $all) {
                    $st = Get-PimTemplateState -TenantId $confTenant -TemplateId "$($t.templateId)"
                    $applied = if ($st) { [int]("$($st.LastAppliedVersion)" -as [int]) } else { 0 }
                    [void]$rows.Add([ordered]@{
                        templateId = "$($t.templateId)"; workload = "$($t.workload)"
                        templateVersion = [int]("$($t.templateVersion)" -as [int]); status = "$($t.status)"
                        approved = [bool](Test-PimTemplateApproved -Template $t); entries = @($t.entries).Count
                        appliedVersion = $applied; behind = [math]::Max(0, [int]("$($t.templateVersion)" -as [int]) - $applied)
                    })
                }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ instance = $confTenant; tenantRing = $confRing; templates = $rows.ToArray() })
                return 200
            }

            if ($path -eq '/api/conformance' -and $method -eq 'GET') {
                $tid = ''
                if ($req.Url.Query -match '(\?|&)template=([^&]+)') { $tid = [uri]::UnescapeDataString($Matches[2]) }
                $tpl = @(Read-PimApprovedTemplates -SourceDir $confTplDir -IncludeDrafts -WarningAction SilentlyContinue | Where-Object { "$($_.templateId)" -eq "$tid" })
                if (-not $tid -or -not $tpl) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'unknown template' }; return 400 }
                $tpl = $tpl[0]
                $now = [datetime]::UtcNow
                $exKeys = Get-PimActiveExemptionKeys -Exemptions (& $readEx) -TenantId $confTenant -TemplateId "$tid" -NowUtc $now
                $st = Get-PimTemplateState -TenantId $confTenant -TemplateId "$tid"
                $applied = if ($st) { [int]("$($st.LastAppliedVersion)" -as [int]) } else { 0 }
                # Best-effort live catalog (the connector's live roles); skip if no connection.
                $liveCat = @()
                try {
                    $dir = Join-Path $solutionRoot 'workloads\connectors'
                    $conn = @(Read-PimWorkloadConnectors -ConnectorsDir $dir) | Where-Object { "$($_.id)" -ieq "$($tpl.workload)" } | Select-Object -First 1
                    if ($conn) { Initialize-PimManagerTenantConnection; $liveCat = @(Get-PimWorkloadRoles -Connector $conn | ForEach-Object { "$($_.name)" }) }
                } catch { $liveCat = @() }
                $c = Get-PimConformance -Template $tpl -TenantRing $confRing -TenantId $confTenant -ActiveExemptionKeys $exKeys -LiveCatalog $liveCat -AppliedVersion $applied
                $statusMap = [ordered]@{}
                foreach ($r in $c.Rows) { $statusMap["$($r.Key)"] = "$($r.Status)" }
                # Per-entry rollout ring (default 2) so the Template Rollout tab can render a
                # per-entry ring selector that drives POST /api/conformance/promote (no more
                # orphaned promote endpoint). Read straight from each template entry.
                $ringMap = [ordered]@{}
                foreach ($e in @($tpl.entries)) { $ringMap["$($e.key)"] = (Get-PimTemplateEntryRing -Entry $e) }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    templateId = "$($tpl.templateId)"; workload = "$($tpl.workload)"; templateVersion = $c.TemplateVersion
                    status = "$($tpl.status)"; tenantRing = $confRing; appliedVersion = $applied; behind = $c.Behind
                    keys = @(@($tpl.entries) | ForEach-Object { "$($_.key)" }); statuses = $statusMap; rings = $ringMap
                    counts = $c.Counts; catalogAhead = @($c.CatalogAhead | ForEach-Object { "$($_.Capability)" })
                })
                return 200
            }

            if ($path -eq '/api/conformance/exemptions' -and $method -eq 'POST') {
                # [Fix 4] GATE: ADD-exemption is a governance-bypass write and must require
                # the SAME role as its siblings (approve / promote / exemptions/revoke), all
                # SuperAdmin. It previously had NO role gate (only the preview-flag + Bearer).
                if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) { Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to add a conformance exemption.' }; return 403 }
                if (Test-PimGovernancePreviewBlocked -Response $resp -FlagId 'conformancePreview' -Surface 'Template Rollout') { return 409 }
                $b = Read-RequestJson -Request $req
                $cand = [pscustomobject]@{
                    tenantId = $confTenant; templateId = "$($b.templateId)"; itemKey = "$($b.itemKey)"
                    reason = "$($b.reason)"; approvedBy = "$($b.approvedBy)"
                    approvedUtc = ([datetime]::UtcNow).ToString('o'); expiresUtc = "$($b.expiresUtc)"
                }
                $v = Test-PimExemptionValid -Exemption $cand -NowUtc ([datetime]::UtcNow)
                if ($v.state -eq 'Invalid') { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = ("exemption rejected: {0}" -f $v.detail) }; return 400 }
                $list = New-Object System.Collections.Generic.List[object]
                foreach ($e in (& $readEx)) { $list.Add($e) }
                $list.Add($cand)
                [void](Set-PimManagerConformanceExemptions -Exemptions $list.ToArray())
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; state = $v.state; count = $list.Count }
                return 200
            }

            # REQUIREMENTS.md s28 [L2]: exemptions must be REVIEWABLE, not write-only.
            # The active-exemptions register -- every stored waiver for THIS instance with
            # its per-row state (Active/Expiring/Expired/Invalid), days-left and a stable
            # revoke key (Get-PimExemptionList). Optional ?template= scopes to one template.
            if ($path -eq '/api/conformance/exemptions' -and $method -eq 'GET') {
                $tidF = ''
                if ($req.Url.Query -match '(\?|&)template=([^&]+)') { $tidF = [uri]::UnescapeDataString($Matches[2]) }
                $now = [datetime]::UtcNow
                $list = @(Get-PimExemptionList -Exemptions (& $readEx) -TenantId $confTenant -TemplateId $tidF -NowUtc $now -WarningAction SilentlyContinue)
                $sum  = Get-PimExemptionSummary -List $list
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    instance = $confTenant; tenantRing = $confRing; template = $tidF
                    summary = $sum; exemptions = @($list)
                })
                return 200
            }

            # Revoke ONE exemption by its stable RevokeKey (no auto-expire wait). SuperAdmin
            # only -- same gate as approve. Pure Remove-PimExemptionEntry filters the set;
            # an unknown key is an idempotent no-op (Removed=0). Audited.
            if ($path -eq '/api/conformance/exemptions/revoke' -and $method -eq 'POST') {
                if (Test-PimGovernancePreviewBlocked -Response $resp -FlagId 'conformancePreview' -Surface 'Template Rollout') { return 409 }
                if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) { Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required' }; return 403 }
                $b = Read-RequestJson -Request $req
                $rk = "$($b.revokeKey)".Trim()
                if (-not $rk) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'revokeKey is required' }; return 400 }
                $r = Remove-PimExemptionEntry -Exemptions (& $readEx) -RevokeKey $rk
                if ($r.Removed -gt 0) {
                    [void](Set-PimManagerConformanceExemptions -Exemptions @($r.Kept))
                    if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
                        try { Write-PimAuditEvent -Action 'conformance.exemption.revoke' -Target $rk -After @{ instance = $confTenant; removed = $r.Removed } -Actor 'manager' -WarningAction SilentlyContinue | Out-Null } catch {}
                    }
                }
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; removed = $r.Removed; count = @($r.Kept).Count }
                return 200
            }

            if ($path -eq '/api/conformance/approve' -and $method -eq 'POST') {
                if (Test-PimGovernancePreviewBlocked -Response $resp -FlagId 'conformancePreview' -Surface 'Template Rollout') { return 409 }
                if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) { Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required' }; return 403 }
                $b = Read-RequestJson -Request $req
                $file = & $findTplFile "$($b.templateId)"
                if (-not $file) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'unknown template' }; return 400 }
                $tpl = ConvertTo-PimTemplate -Json ([System.IO.File]::ReadAllText($file, [System.Text.UTF8Encoding]::new($false)))
                $by = if ("$($b.approvedBy)".Trim()) { "$($b.approvedBy)" } else { 'manager' }
                $appr = Approve-PimTemplate -Template $tpl -ApprovedBy $by -NowUtc ([datetime]::UtcNow)
                $appr | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $file -Encoding UTF8
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; status = "$($appr.status)" }
                return 200
            }

            if ($path -eq '/api/conformance/promote' -and $method -eq 'POST') {
                if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) { Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required' }; return 403 }
                $b = Read-RequestJson -Request $req
                $file = & $findTplFile "$($b.templateId)"
                if (-not $file) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'unknown template' }; return 400 }
                try {
                    # BUG-06: edit the ring IN THE ORIGINAL TEXT rather than re-serializing the
                    # whole template. The old object round-trip kept every field, but it
                    # rewrote the entire file (1698 -> 2952 bytes under WinPS 5.1), collapsed
                    # the curated hand-aligned entry columns, and `Set-Content -Encoding UTF8`
                    # added a BOM to a file this codebase otherwise keeps BOM-less. On a
                    # customer install the template is not in git, so there was no undo.
                    $raw = [System.IO.File]::ReadAllText($file, [System.Text.UTF8Encoding]::new($false))
                    $out = Set-PimEntryRingInJson -Json $raw -Key "$($b.key)" -Ring ([int]$b.ring)
                    [System.IO.File]::WriteAllText($file, $out, (New-Object System.Text.UTF8Encoding($false)))
                    Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; key = "$($b.key)"; ring = [int]$b.ring }
                    return 200
                } catch { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "$($_.Exception.Message)" }; return 400 }
            }

            if ($path -eq '/api/conformance/deploy' -and $method -eq 'POST') {
                if (Test-PimGovernancePreviewBlocked -Response $resp -FlagId 'conformancePreview' -Surface 'Template Rollout') { return 409 }
                if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) { Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required' }; return 403 }
                $b = Read-RequestJson -Request $req
                $tpl = @(Read-PimApprovedTemplates -SourceDir $confTplDir -WarningAction SilentlyContinue | Where-Object { "$($_.templateId)" -eq "$($b.templateId)" })
                if (-not $tpl) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'unknown or unapproved template (only approved deploy)' }; return 400 }
                $tpl = $tpl[0]
                $whatIf = [bool]$b.whatIf
                try {
                    $rows = @(Get-PimRollForwardRows -Template $tpl -TenantRing $confRing -TenantId $confTenant -Exemptions (& $readEx) -NowUtc ([datetime]::UtcNow))
                    if (-not $rows.Count) { Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; whatIf = $whatIf; rows = @(); message = 'no in-scope, non-exempt entries for this ring' }; return 200 }
                    # 🔴 NOT $env:TEMP: this Manager runs in a LINUX container, where that variable
                    # is unset and Join-Path then throws "Cannot bind argument to parameter 'Path'
                    # because it is an empty string" -- inside a request handler, so it surfaces as
                    # a 500 with no hint that a temp directory was the problem.
                    $tmpCsv = Join-Path ([System.IO.Path]::GetTempPath()) ("pim-rollfwd-{0}.csv" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
                    $rows | Select-Object Workload,RoleName,GroupTag,Scope,Resource,Action | Export-Csv -LiteralPath $tmpCsv -NoTypeInformation -Delimiter ';' -Encoding UTF8
                    Initialize-PimManagerTenantConnection
                    $connDir = Join-Path $solutionRoot 'workloads\connectors'
                    $out = Apply-PimWorkloadAssignments -WorkloadsAssignmentFile $tmpCsv -ConnectorsDir $connDir -WhatIfMode:$whatIf *>&1 | Out-String
                    Remove-Item -LiteralPath $tmpCsv -Force -ErrorAction SilentlyContinue
                    if (-not $whatIf) {
                        Set-PimTemplateState -TenantId $confTenant -TemplateId "$($tpl.templateId)" -Version ([int]("$($tpl.templateVersion)" -as [int])) -NowUtc ([datetime]::UtcNow) | Out-Null
                        # Stamp THIS tenant's rollout ring in the state document so the fleet
                        # matrix ([H8]) can read the ring of an instance it is not the
                        # active one for. Best-effort; never blocks the deploy -- but not silent.
                        try { [void](Set-PimTemplateStateRing -TenantId $confTenant -Ring ([int]$confRing)) }
                        catch { Write-Warning "  [conformance] ring stamp NOT saved: $($_.Exception.Message)" }
                    }
                    Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; whatIf = $whatIf; rows = @($rows); log = "$out" })
                    return 200
                } catch { Write-JsonResponse -Response $resp -Status 502 -Body @{ error = "$($_.Exception.Message)" }; return 502 }
            }

            # --- FLEET conformance matrix (REQUIREMENTS.md s28 [H8]) -----------------
            # The single-tenant /api/conformance answers "how far behind is THIS tenant?".
            # An MSP needs the cross-fleet view: tenants x templates, behind-by-N, in one
            # place. Builds it from the template-state document (SQL pim.Settings['ConformanceTemplateState'])
            # (per-instance applied version + ring) and feeding them into the pure
            # Get-PimFleetConformance. The active instance contributes its LIVE ring
            # (Get-PimTenantRing); other instances use the ring stamped in the state document
            # (falling back to 0 / production when unstamped). No tenant write, read-only.
            if ($path -eq '/api/conformance/fleet' -and $method -eq 'GET') {
                $approved = @(Read-PimApprovedTemplates -SourceDir $confTplDir -WarningAction SilentlyContinue)
                # Build a tenant descriptor per managed instance.
                $fleetTenants = New-Object System.Collections.Generic.List[object]
                foreach ($inst in (Get-PimManagerInstances | Where-Object { "$($_.name)" -eq "$script:PimInstanceName" })) {
                    # SQL-only: the tenant is the ACTIVE SQL instance. Other 'sql:<db>' names share this
                    # host's output folder, so counting them would duplicate one state stamp as N tenants.
                    $iname = "$($inst.name)"


                    $st = Get-PimFleetStateForInstance -TenantId $iname   # SQL pim.Settings['ConformanceTemplateState']
                    $iring = $st.ring
                    if ($iname -eq "$script:PimInstanceName") { $iring = $confRing }   # active = live ring
                    if ($null -eq $iring) { $iring = 0 }
                    $fleetTenants.Add(@{ tenantId = $iname; ring = $iring; appliedVersions = $st.appliedVersions })
                }
                $fleet = Get-PimFleetConformance -Templates $approved -Tenants $fleetTenants.ToArray()
                # Serialise to plain ordered objects (Cells nested per tenant).
                $tenantRows = New-Object System.Collections.ArrayList
                foreach ($tr in $fleet.Tenants) {
                    $cellList = New-Object System.Collections.ArrayList
                    foreach ($c in $tr.Cells) {
                        [void]$cellList.Add([ordered]@{ templateId = "$($c.TemplateId)"; templateVersion = $c.TemplateVersion; appliedVersion = $c.AppliedVersion; behind = $c.Behind; status = "$($c.Status)" })
                    }
                    [void]$tenantRows.Add([ordered]@{
                        tenantId = "$($tr.TenantId)"; ring = $tr.Ring; current = [bool]$tr.Current
                        maxBehind = $tr.MaxBehind; behindCount = $tr.BehindCount; neverCount = $tr.NeverCount
                        upToDate = $tr.UpToDate; aheadCount = $tr.AheadCount; cells = $cellList.ToArray()
                    })
                }
                $colList = New-Object System.Collections.ArrayList
                foreach ($col in $fleet.Templates) { [void]$colList.Add([ordered]@{ templateId = "$($col.TemplateId)"; workload = "$($col.Workload)"; templateVersion = $col.TemplateVersion }) }
                $ptList = New-Object System.Collections.ArrayList
                foreach ($pt in $fleet.PerTemplate) {
                    [void]$ptList.Add([ordered]@{ templateId = "$($pt.TemplateId)"; workload = "$($pt.Workload)"; templateVersion = $pt.TemplateVersion; upToDate = $pt.UpToDate; behindCount = $pt.BehindCount; neverCount = $pt.NeverCount; aheadCount = $pt.AheadCount; maxBehind = $pt.MaxBehind; needsRollout = [bool]$pt.NeedsRollout })
                }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    activeInstance = $confTenant
                    totalTenants   = $fleet.TotalTenants; currentTenants = $fleet.CurrentTenants; behindTenants = $fleet.BehindTenants
                    templates      = $colList.ToArray(); perTemplate = $ptList.ToArray(); tenants = $tenantRows.ToArray()
                })
                return 200
            }

            # --- RING-WIDE rollout plan for ONE template (REQUIREMENTS.md s28 [H8]) --
            # The "ring-wide deploy" planning view: for a chosen approved template, which
            # tenants a wave to a ring band would reach and where each stands. Read-only
            # planning rollup (the actual per-tenant deploy still goes through the proven
            # ring-gated deploy path); ?template= selects the template.
            if ($path -eq '/api/conformance/ring-plan' -and $method -eq 'GET') {
                $tid = ''
                if ($req.Url.Query -match '(\?|&)template=([^&]+)') { $tid = [uri]::UnescapeDataString($Matches[2]) }
                $tpl = @(Read-PimApprovedTemplates -SourceDir $confTplDir -IncludeDrafts -WarningAction SilentlyContinue | Where-Object { "$($_.templateId)" -eq "$tid" })
                if (-not $tid -or -not $tpl) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'unknown template' }; return 400 }
                $tpl = $tpl[0]
                $fleetTenants = New-Object System.Collections.Generic.List[object]
                foreach ($inst in (Get-PimManagerInstances | Where-Object { "$($_.name)" -eq "$script:PimInstanceName" })) {
                    # SQL-only: the tenant is the ACTIVE SQL instance. Other 'sql:<db>' names share this
                    # host's output folder, so counting them would duplicate one state stamp as N tenants.
                    $iname = "$($inst.name)"

                    $st = Get-PimFleetStateForInstance -TenantId $iname   # SQL pim.Settings['ConformanceTemplateState']
                    $iring = $st.ring
                    if ($iname -eq "$script:PimInstanceName") { $iring = $confRing }
                    if ($null -eq $iring) { $iring = 0 }
                    $fleetTenants.Add(@{ tenantId = $iname; ring = $iring; appliedVersions = $st.appliedVersions })
                }
                $plan = Get-PimRingRolloutPlan -Template $tpl -Tenants $fleetTenants.ToArray()
                $bandList = New-Object System.Collections.ArrayList
                foreach ($b in $plan.Bands) {
                    $tl = New-Object System.Collections.ArrayList
                    foreach ($t in $b.Tenants) { [void]$tl.Add([ordered]@{ tenantId = "$($t.TenantId)"; ring = $t.Ring; appliedVersion = $t.AppliedVersion; behind = $t.Behind; status = "$($t.Status)" }) }
                    [void]$bandList.Add([ordered]@{ ring = $b.Ring; tenantCount = $b.TenantCount; behindCount = $b.BehindCount; neverCount = $b.NeverCount; needsRollout = [bool]$b.NeedsRollout; tenants = $tl.ToArray() })
                }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    templateId = "$($plan.TemplateId)"; workload = "$($plan.Workload)"; templateVersion = $plan.TemplateVersion
                    approved = [bool]$plan.Approved; totalTenants = $plan.TotalTenants; needsRolloutCount = $plan.NeedsRolloutCount
                    bands = $bandList.ToArray()
                })
                return 200
            }

            Write-JsonResponse -Response $resp -Status 404 -Body @{ error = ("not found: {0} {1}" -f $method, $path) }
            return 404
        }

        if ($path -eq '/api/instances' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            # foreach statement, not pipeline -- see the GET / handler note.
            $instList = New-Object System.Collections.ArrayList
            foreach ($i in (Get-PimManagerInstances)) { [void]$instList.Add([ordered]@{ name = $i.name; configRoot = $i.configRoot }) }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                active    = $script:PimInstanceName
                instances = $instList.ToArray()
            })
            return 200
        }

        if ($path -eq '/api/instance' -and $method -eq 'POST') {
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            $body = Read-RequestJson -Request $req
            $name = if ($body -and $body.name) { "$($body.name)" } else { '' }
            if (-not $name) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = 'instance name is required' }
                return 400
            }
            try {
                Set-PimManagerInstance -Name $name
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; active = $script:PimInstanceName })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 400
            }
        }

        # -------------------------------------------------------------------
        # SUPPORT / DIAGNOSTICS (REQUIREMENTS §28 [M9]).
        #   GET /api/support/diagnostics -> connectivity+permission checks + health
        #        summary (first-line self-check). Reader+ (read-only, no writes).
        #   GET /api/support/bundle      -> the SANITIZED downloadable handoff bundle
        #        (versions, checks, non-secret config, recent runs; secrets/certs/
        #        tokens/connection-strings/full GUIDs masked). Reader+ (already masked).
        # -------------------------------------------------------------------
        if ($path -eq '/api/support/diagnostics' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                $diag = Get-PimSupportDiagnostics
                Write-JsonResponse -Response $resp -Status 200 -Body $diag
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/support/bundle' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                $diag = Get-PimSupportDiagnostics -IncludeBundle
                # Return the already-sanitized bundle text + object; the GUI offers it
                # as a download (text/plain Blob built client-side). The bundle is
                # masked in New-PimDiagnosticsBundle, so this is safe to serve to any
                # role that can open the Support tab.
                $b = $diag.bundle
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok           = $true
                    generatedUtc = $diag.generatedUtc
                    filename     = ('pim-diagnostics-' + (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + '.json')
                    text         = "$($b.text)"
                    object       = $b.object
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # (The one-time CSV -> SQL "cutover ceremony" endpoints -- /api/cutover, /api/cutover/abort --
        # were REMOVED with the file store, operator decision 2026-09-12. A v1 -> v2 import is
        # setup/Migrate-PimToSql.ps1, run once by an operator; the Manager never reads files.)
        # BUG-106: POST /api/preflight validates the PENDING state -- the body carries
        # { pending: { '<entity>': [rows...] } } and the report describes what the store WOULD
        # look like after commit. The GET form (saved state only) is unchanged for callers that
        # want it, but it must never again be the thing that gates a commit: a pre-flight check
        # that validates the pre-flight state can only ever refuse the fix.
        # Deliberately NOT cached -- the cache key is the STORE's change signal, which does not
        # move when the operator edits pending rows, so a cached answer would be the same
        # deadlock wearing a different hat.
        if ($path -eq '/api/preflight' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command Invoke-PimPreflightValidation -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = 'the validator was not loaded on the server' }
                return 500
            }
            try {
                $body = Read-RequestJson -Request $req
                $pending = @{}
                if ($body -and $body.PSObject.Properties['pending'] -and $body.pending) {
                    foreach ($p in $body.pending.PSObject.Properties) {
                        $pending["$($p.Name)"] = @($p.Value)
                    }
                }
                $report = Invoke-PimPreflightValidation -PendingRows $pending
                $report | Add-Member -NotePropertyName validatedPending -NotePropertyValue @($pending.Keys) -Force
                Write-JsonResponse -Response $resp -Status 200 -Body $report
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }
        if ($path -eq '/api/preflight' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command Invoke-PimPreflightValidation -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = '_validator.ps1 was not loaded -- file missing next to Open-PimManager.ps1' }
                return 500
            }
            try {
                # Cache keyed on instance + the data's change signal: every page
                # load auto-runs preflight, and the validator costs seconds on
                # the single-threaded server. Unchanged inputs -> cached report.
                #   CSV mode -> the CSVs' LastWriteTimes.
                #   SQL mode -> MAX(UpdatedUtc) + row count over pim.Rows (the
                #     CSV files don't exist; a write-time stamp would never change
                #     and the cache would serve a stale report forever).
                $stamp = $script:PimInstanceName
                try {
                    $sig = Invoke-PimSqlQuery -ConnectionString $script:PimSqlCs -Sql "SELECT COUNT(*) AS c, CONVERT(VARCHAR(33), MAX(UpdatedUtc), 126) AS m FROM pim.Rows" | Select-Object -First 1
                    $stamp += "|sql:rows=$($sig.c):max=$($sig.m)"
                } catch { $stamp += "|sql:" + [datetime]::UtcNow.ToString('o') }  # fail-open: don't cache
                if ($script:PimPreflightCacheStamp -eq $stamp -and $script:PimPreflightCacheReport) {
                    Write-JsonResponse -Response $resp -Status 200 -Body $script:PimPreflightCacheReport
                    return 200
                }
                $report = Invoke-PimPreflightValidation
                $script:PimPreflightCacheStamp  = $stamp
                $script:PimPreflightCacheReport = $report
                Write-JsonResponse -Response $resp -Status 200 -Body $report
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # -------------------------------------------------------------------
        # Validate-tab Overrule / Acknowledge store (REQUIREMENTS §11).
        #   GET  -> current acknowledgement entries (so the GUI can show count).
        #   POST -> append one acknowledgement to the real merged override store;
        #           busts the preflight cache so the next Re-run downgrades the
        #           matched finding to 'acknowledged' and the active count drops.
        # -------------------------------------------------------------------
        if ($path -eq '/api/warning-overrides' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                $store   = Get-PimManagerWarningOverrides
                $entries = @()
                if (Get-Command Read-PimWarningOverrideConfig -ErrorAction SilentlyContinue) {
                    $entries = @(Read-PimWarningOverrideConfig -Config $store)
                }
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; supported = $true; count = @($entries).Count; overrides = @($entries) }
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/warning-overrides' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            # Acknowledging a finding is a data-affecting governance action -> Admin.
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to overrule validator findings. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $b = Read-RequestJson -Request $req
            if (-not $b) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'empty body' }; return 400 }
            $who = try { (Get-PimManagerRole).identity } catch { '' }
            try {
                $count = Add-PimWarningOverrideEntry `
                    -Code      "$($b.code)" `
                    -Reason    "$($b.reason)" `
                    -ExpiresOn "$($b.expiresOn)" `
                    -NoExpiry  ([bool]$b.noExpiry) `
                    -Subject   "$($b.subject)" `
                    -Target    "$($b.target)" `
                    -CreatedBy $(if ("$($b.createdBy)".Trim()) { "$($b.createdBy)" } else { $who })
                # Force the next /api/preflight to recompute (the store changed).
                $script:PimPreflightCacheStamp  = $null
                $script:PimPreflightCacheReport = $null
                Write-PimManagerAuditEvent -Action 'validate.warning.overrule' -Target "$($b.code)" -After ([ordered]@{ code = "$($b.code)"; subject = "$($b.subject)"; target = "$($b.target)"; expiresOn = "$($b.expiresOn)"; noExpiry = [bool]$b.noExpiry })
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; count = $count }
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 400
            }
        }

        # -------------------------------------------------------------------
        # v2.4.2 Revoke tab endpoints
        # -------------------------------------------------------------------
        if ($path -like '/api/active-assignments*' -and $method -eq 'GET') {
            # [Fix 3] GATE: this returns the WHOLE tenant's privileged active
            # assignments -- it must require at least Admin (it previously had NO
            # gate), and a non-SuperAdmin delegated caller must only see assignments
            # inside their scope. The cache stays tenant-wide; we filter on the way out.
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to view active assignments. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            # 🔒 §70.1b opt 2: serve the stored snapshot, never read the tenant; ?refresh=1 only queues a scheduler trigger.
            $queueRefresh = $false
            try {
                $qs = $req.Url.Query
                if ($qs -and $qs.IndexOf('refresh=1') -ge 0) { $queueRefresh = $true }
            } catch { }
            try {
                $body = Get-PimActiveAssignmentsCached -QueueRefresh:$queueRefresh -Reason $(if ($queueRefresh) { 'revoke-tab-refresh' } else { 'revoke-tab' })
                # Per-caller scope filter: a delegated (non-super) caller with a portal
                # profile sees only the rows whose (derivable) facets are in scope.
                # Principal-centric rows whose facets aren't derivable are KEPT (the
                # write-side revoke gate still re-checks); placeable-but-out-of-scope
                # rows are dropped here so a delegated caller never even enumerates them.
                $aaScope = Get-PimManagerCallerScope
                if (-not $aaScope.isSuperAdmin -and $aaScope.profile -and (Get-Command Test-PimPortalRowsInScope -ErrorAction SilentlyContinue)) {
                    $allRows = @($body.rows)
                    $kept = New-Object System.Collections.ArrayList
                    foreach ($row in $allRows) {
                        # (snapshot rows are PSCustomObjects from SQL; feed the guard the revoke POST row shape)
                        $rc =Test-PimPortalRowsInScope -Profile $aaScope.profile -Rows @(ConvertTo-OrderedRow $row) -Base 'revoke' -RequireManage -SkipUnscopableRows
                        if ($rc.allowed) { [void]$kept.Add($row) }
                    }
                    $body.rows = @($kept.ToArray())
                    $body['portalFiltered'] = $true
                }
                Write-JsonResponse -Response $resp -Status 200 -Body $body
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/revoke' -and $method -eq 'POST') {
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            $body = Read-RequestJson -Request $req
            $justification = $null
            $rowsIn = @()
            $preview = $false
            $confirmCount = $null
            $approvalTarget = ''
            if ($body) {
                if ($body.justification) { $justification = "$($body.justification)" }
                if ($body.rows)          { $rowsIn = @($body.rows) }
                if ($body.preview)       { $preview = [bool]$body.preview }
                if ($null -ne $body.confirmCount -and "$($body.confirmCount)" -match '^\d+$') { $confirmCount = [int]$body.confirmCount }
                # [H3] the batch label an over-threshold approval was raised for; defaults
                # to the stable scope label so the gate can match an Approved revoke request.
                if ($body.approvalTarget) { $approvalTarget = "$($body.approvalTarget)".Trim() }
            }
            if (-not $rowsIn -or $rowsIn.Count -eq 0) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = 'at least one row is required' }
                return 400
            }
            # [Fix 2] PORTAL SCOPE on revoke: a non-SuperAdmin delegated caller may only
            # revoke assignments whose target group is inside their tier/level/service/
            # scope. SuperAdmin bypasses (as everywhere). Applies to BOTH preview + commit
            # so a scoped caller cannot even enumerate out-of-scope revocations.
            $revokeScope = Get-PimManagerCallerScope
            if (-not $revokeScope.isSuperAdmin -and $revokeScope.profile -and (Get-Command Test-PimPortalRowsInScope -ErrorAction SilentlyContinue)) {
                $rowsForScope = @($rowsIn | ForEach-Object { ConvertTo-OrderedRow $_ } | Where-Object { $_ -ne $null })
                $rs = Test-PimPortalRowsInScope -Profile $revokeScope.profile -Rows $rowsForScope -Base 'revoke' -RequireManage -SkipUnscopableRows
                if (-not $rs.allowed) {
                    Write-JsonResponse -Response $resp -Status 403 -Body ([ordered]@{ ok = $false; error = "$($rs.reason)"; denied = @($rs.denied) })
                    return 403
                }
            }
            # Bulk-revoke SAFETY NET: compute the what-if plan (break-glass
            # excluded + large-batch count-confirmation) BEFORE doing anything.
            $plan = Get-PimRevokeGuardPlan -Rows $rowsIn -ConfirmCount $confirmCount

            # [H3] APPROVAL gate (the full approval-gated revoke, on top of the interim
            # #81 guard above): an over-threshold (post-break-glass) batch requires an
            # APPROVED maker/checker 'revoke' request for this batch label; at/below the
            # threshold the interim count-confirm guard suffices. We compute whether an
            # approval is REQUIRED (and, on commit, whether one EXISTS) without ever
            # bypassing Test-PimRevokeExecutionAllowed.
            $apprRequired = $false
            if (Get-Command Test-PimRevokeApprovalRequired -ErrorAction SilentlyContinue) {
                try { $apprRequired = [bool]((Test-PimRevokeApprovalRequired -Rows $rowsIn).required) } catch {}
            }

            # PREVIEW (what-if): never executes -- returns exactly what WOULD be
            # revoked, what is skipped (break-glass), whether a count confirmation is
            # required, AND whether a maker/checker approval is required ([H3]).
            # Justification is not required to preview.
            if ($preview) {
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok               = $true
                    preview          = $true
                    total            = $plan.total
                    toRevokeCount    = $plan.toRevokeCount
                    skipped          = $plan.skipped
                    skippedCount     = $plan.skippedCount
                    confirmThreshold = $plan.confirmThreshold
                    confirmRequired  = $plan.confirmRequired
                    approvalRequired = $apprRequired
                })
                return 200
            }

            # COMMIT path: justification is mandatory.
            if (-not $justification -or [string]::IsNullOrWhiteSpace($justification)) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = 'justification is required' }
                return 400
            }
            # Large-batch guard: require the caller to echo the exact (post
            # break-glass exclusion) to-revoke count.
            if ($plan.confirmRequired -and -not $plan.confirmSatisfied) {
                Write-JsonResponse -Response $resp -Status 409 -Body ([ordered]@{
                    ok               = $false
                    error            = ("This batch revokes {0} assignment(s), over the {1} safety threshold. Re-submit with confirmCount={0} to proceed." -f $plan.toRevokeCount, $plan.confirmThreshold)
                    confirmRequired  = $true
                    confirmThreshold = $plan.confirmThreshold
                    toRevokeCount    = $plan.toRevokeCount
                    skipped          = $plan.skipped
                    skippedCount     = $plan.skippedCount
                })
                return 409
            }
            # [H3] APPROVAL GATE -- an over-threshold (post-break-glass) batch may only
            # commit when an APPROVED maker/checker 'revoke' request exists for this batch
            # label. Composes (NEVER bypasses) Test-PimRevokeExecutionAllowed: break-glass
            # is always excluded, at/below-threshold runs under the interim guard, and an
            # over-threshold batch with no Approved request is blocked 409 "needs approval".
            # The batch label defaults to a stable scope token so the operator raises ONE
            # approval (action=revoke, target=that label) on the Approvals tab, then re-runs.
            if ($apprRequired -and (Get-Command Test-PimRevokeExecutionAllowed -ErrorAction SilentlyContinue)) {
                $batchLabel = if ("$approvalTarget".Trim()) { "$approvalTarget".Trim() } else { 'maintenance-bulk-revoke' }
                $reqs = @()
                if (Get-Command Get-PimApprovalRequests -ErrorAction SilentlyContinue) { try { $reqs = @(Get-PimApprovalRequests) } catch {} }
                $gate = Test-PimRevokeExecutionAllowed -Rows $rowsIn -Target $batchLabel -Requests $reqs
                if (-not $gate.allowed) {
                    Write-JsonResponse -Response $resp -Status 409 -Body ([ordered]@{
                        ok               = $false
                        gate             = "$($gate.gate)"
                        error            = ("This batch revokes {0} assignment(s), over the {1} approval threshold. Raise a 'revoke' approval request (Approvals tab) for batch '{2}', have a different administrator approve it, then re-submit." -f $gate.toRevokeCount, $gate.threshold, $batchLabel)
                        approvalRequired = $true
                        approvalTarget   = $batchLabel
                        toRevokeCount    = [int]$gate.toRevokeCount
                        threshold        = [int]$gate.threshold
                        skipped          = $plan.skipped
                        skippedCount     = $plan.skippedCount
                    })
                    return 409
                }
            }
            $rowsToRevoke = @($plan.toRevoke)
            if ($rowsToRevoke.Count -eq 0) {
                # Everything selected was a protected break-glass account.
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok           = $true
                    requested    = $rowsIn.Count
                    revoked      = 0
                    skipped      = $plan.skipped
                    skippedCount = $plan.skippedCount
                    results      = @()
                })
                return 200
            }
            try {
                $results = Invoke-PimActiveAssignmentRevokeBatch -Rows $rowsToRevoke -Justification $justification
                # AUDIT every revoke attempt (who/what/when/justification + outcome).
                for ($i = 0; $i -lt $rowsToRevoke.Count; $i++) {
                    $rr  = $rowsToRevoke[$i]
                    $res = if ($i -lt @($results).Count) { @($results)[$i] } else { $null }
                    $ok  = ($res -and $res.ok)
                    Write-PimManagerAuditEvent -Action 'revoke.active-assignment' `
                        -Target ("{0} | {1}" -f "$($rr.principal)", "$($rr.type)") `
                        -Result $(if ($ok) { 'ok' } else { 'failed' }) `
                        -After ([ordered]@{
                            principal     = "$($rr.principal)"
                            principalId   = "$($rr.principalId)"
                            type          = "$($rr.type)"
                            justification = $justification
                            error         = $(if ($ok) { $null } else { "$($res.error)" })
                        })
                }
                # Record the break-glass accounts we deliberately skipped.
                foreach ($sk in @($plan.skipped)) {
                    Write-PimManagerAuditEvent -Action 'revoke.skipped.break-glass' `
                        -Target ("{0} | {1}" -f "$($sk.principal)", "$($sk.type)") -Result 'skipped' `
                        -After ([ordered]@{ principal = "$($sk.principal)"; reason = "$($sk.reason)" })
                }
                # [H3] once-only latch: if this was an over-threshold, approval-driven
                # batch, mark the Approved 'revoke' request Executed so it can never drive
                # a second over-threshold run. (Best-effort; at/below-threshold batches
                # carry no approval to latch.)
                if ($apprRequired -and (Get-Command Set-PimApprovalRequestExecuted -ErrorAction SilentlyContinue)) {
                    try {
                        $batchLabel2 = if ("$approvalTarget".Trim()) { "$approvalTarget".Trim() } else { 'maintenance-bulk-revoke' }
                        if (Get-Command Test-PimApprovalApprovedFor -ErrorAction SilentlyContinue) {
                            $appr2 = Test-PimApprovalApprovedFor -Requests @(Get-PimApprovalRequests) -Action 'revoke' -Target $batchLabel2
                            if ($appr2) { Set-PimApprovalRequestExecuted -Id "$($appr2.id)" | Out-Null }
                        }
                    } catch {
                        # 🔴 An approval that is USED but never MARKED executed stays available:
                        # the same approval can authorise a second bulk revoke. Silence here is an
                        # approval-integrity hole, not a cosmetic miss.
                        Write-Warning "[manager] could not mark the approval executed ($($_.Exception.Message)) -- it may be re-usable for another bulk action."
                    }
                }
                # §70.1b option 2: there is no in-process active-assignments cache to invalidate any more. A revoke
                # here is only QUEUED; when queue-apply (scheduler) actually applies a revoke it queues a snapshot
                # refresh itself, so the Revoke tab catches up without this request reading the tenant. The GUI
                # marks the rows "revoke queued" meanwhile.
                # 🔒 FORCE THE ARRAY SHAPE ON BOTH COLLECTIONS. The client reads these with
                # Array.isArray() and silently substitutes an empty array for anything else, so any
                # shape drift here is reported to the operator as "0 ok, 0 failed" -- about work
                # that DID happen. Measured 2026-09-12: a revoke the server logged as
                #     [revoke][entra-role] OK -- principal ... role ...   POST /api/revoke -> 200
                # was shown in the GUI as "Revoke batch finished: 0 ok, 0 failed".
                # 🪤 PowerShell 7 does serialise a one-element array as [ ... ], so that alone was
                # NOT the cause here -- verified, rather than assumed. This is belt-and-braces on
                # the wire shape; the reporting itself is made non-lying on the client side, which
                # is where the empty-array substitution actually lives.
                $resultsOut = @($results)
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok           = $true
                    requested    = $rowsIn.Count
                    revoked      = $rowsToRevoke.Count
                    skipped      = @($plan.skipped)
                    skippedCount = $plan.skippedCount
                    results      = $resultsOut
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # [M1] Backups / undo. POST /api/backups/restore rolls an entity back to a
        # stored snapshot (operator undo) -- base + snapshot id come in the body.
        if ($path -eq '/api/backups/restore' -and $method -eq 'POST') {
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to roll back. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            $body = Read-RequestJson -Request $req
            $snapId = if ($body -and $body.id) { "$($body.id)" } else { '' }
            $base   = if ($body -and $body.base) { "$($body.base)" } else { '' }
            # [Fix 5] explicit operator acknowledgement for the restore delta guard.
            $confirmRestore = $false
            if ($body -and ($null -ne $body.confirm) -and ("$($body.confirm)" -ieq 'true' -or "$($body.confirm)" -eq '1' -or $body.confirm -eq $true)) { $confirmRestore = $true }
            if (-not "$snapId".Trim()) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = "missing snapshot 'id' in body" }
                return 400
            }
            try {
                $r = Invoke-PimManagerBackupRestore -Id $snapId -Confirm:$confirmRestore
                if (-not "$base".Trim()) { $base = "$($r.entity)" }
                # SEC-16(b) -- the `by` reported back to the caller must name the operator.
                $who = try { $ro = Get-PimManagerRole; if ("$($ro.identity)".Trim()) { "$($ro.identity)" } else { throw } }
                       catch { try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME } }
                Write-PimMutationLog -BaseName $base -Adds 0 -Removes 0 -Modifies 0 -NewRowCount ([int]$r.rowCount) -Summary "Restored from backup $snapId ($([int]$r.rowCount) rows now; a backup of the state before the restore was kept as $($r.preRestoreSnapshotId))"
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; base = $base; restoredFrom = $snapId; entity = "$($r.entity)"; rowCount = [int]$r.rowCount; preRestoreSnapshotId = "$($r.preRestoreSnapshotId)"; by = "$who" })
                return 200
            } catch {
                # [Fix 5] a guard refusal ("restore refused: ...") is a 409 confirm-required,
                # not a 500 (the store was untouched -- nothing failed, it was prevented).
                if ("$($_.Exception.Message)" -like 'restore refused:*') {
                    Write-JsonResponse -Response $resp -Status 409 -Body @{ ok = $false; base = $base; gate = 'delta-guard'; confirmRequired = $true; error = "$($_.Exception.Message)" }
                    return 409
                }
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; base = $base; error = "$($_.Exception.Message)" }
                return 500
            }
        }
        # GET /api/backups/<base> lists the timestamped pre-commit snapshots (newest first).
        if ($path -match '^/api/backups/([\w\.-]+)$' -and $method -eq 'GET') {
            $base = $Matches[1]
            $spec = Get-PimCsvSpec -BaseName $base
            if (-not $spec) {
                Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown csv base: $base" }
                return 404
            }
            $script:lastHeartbeat = Get-Date
            $list = @(Get-PimManagerBackupList -Entity $base)
            # newest first for the UI.
            [array]::Reverse($list)
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ base = $base; keep = $script:PimBackupKeep; backups = @($list) })
            return 200
        }

        # -------------------------------------------------------------------
        # DRIFT page (REQUIREMENTS §28 [M5]; own page + scheduler snapshot 2026-09-14).
        #   GET  /api/drift            -> serve the STORED drift snapshot (pim.TenantCache 'drift', written by the
        #                                 scheduler job 'drift-snapshot'). 🔒 NO engine run here any more: the plan
        #                                 used to run on this ONE request loop and froze every page for minutes.
        #                                 ?refresh=1 (Admin+) queues a 'drift-snapshot' trigger and starts the tick.
        #                                 snapshotMissing=true when the job has not run yet.
        #   POST /api/drift/remediate  -> Admin-gated "apply now": run the engine
        #                                 create/update path for ONLY the selected
        #                                 drift (Get-PimDriftRemediationPlan +
        #                                 Invoke-PimEngine -Changes). Destructive
        #                                 removal of an 'extra' needs explicit
        #                                 allowRemove (-> engine -Mode Full -Prune);
        #                                 never a single-click destructive bypass.
        # The 'drift' alert is raised by the scheduler job when it finds drift (Invoke-PimDriftSnapshotJob).
        # -------------------------------------------------------------------
        if ($path -eq '/api/drift' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command ConvertTo-PimDriftSnapshotView -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ ok = $false; supported = $false; error = 'the drift snapshot reader (engine/_shared/PIM-DriftSnapshot.ps1) is not loaded in this Manager.' }
                return 503
            }
            $driftRefresh = $false
            try { $qs = $req.Url.Query; if ($qs -and $qs.IndexOf('refresh=1') -ge 0) { $driftRefresh = $true } } catch { }
            if ($driftRefresh -and -not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to queue a new drift check. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            try {
                $body = Get-PimDriftCached -QueueRefresh:$driftRefresh -Reason 'manager-refresh'
                if ($driftRefresh -and $body.refreshQueued -and (Get-Command Start-PimManagerTickNow -ErrorAction SilentlyContinue)) {
                    $kick = $null
                    try { $kick = Start-PimManagerTickNow -Reason 'drift-refresh' } catch { $kick = $null }
                    if ($kick -and $kick.PSObject.Properties['detail']) { $body['tickStart'] = "$($kick.detail)" }
                }
                Write-JsonResponse -Response $resp -Status 200 -Body $body
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; supported = $true; error = "the stored drift check could not be read: $($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/drift/remediate' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            # Applying drift mutates the live estate -> Admin (same gate as revoke).
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to apply drift remediation. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            if (-not (Get-Command Invoke-PimEngine -ErrorAction SilentlyContinue) -or -not (Get-Command Get-PimDriftRemediationPlan -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ ok = $false; error = 'engine not loaded (remediation needs the hosted engine + a live tenant context).' }
                return 503
            }
            $b = Read-RequestJson -Request $req
            $selectKeys = @(); if ($b -and $b.selectKeys) { $selectKeys = @($b.selectKeys | ForEach-Object { "$_" }) }
            $selAll     = [bool]($b -and $b.all)
            $allowRemove = [bool]($b -and $b.allowRemove)
            try {
                # Recompute the CURRENT drift (plan-only) so we remediate against a
                # fresh view, then narrow to ONLY the selected drift.
                if (Get-Command Clear-PimEngineReadCaches -ErrorAction SilentlyContinue) { Clear-PimEngineReadCaches }   # §70.10
                $results = @(Invoke-PimEngine -Scope 'All' -Mode 'Full' -Prune -WhatIf)
                $scopeDiffs = New-Object System.Collections.Generic.List[object]
                foreach ($r in @($results)) {
                    $cre = New-Object System.Collections.Generic.List[object]
                    $upd = New-Object System.Collections.Generic.List[object]
                    $rem = New-Object System.Collections.Generic.List[object]
                    foreach ($pc in @($r.plan)) {
                        $item = [pscustomobject]@{ key = "$($pc.key)" }
                        switch ("$($pc.op)".ToLowerInvariant()) { 'create' { $cre.Add($item) } 'update' { $upd.Add($item) } 'remove' { $rem.Add($item) } }
                    }
                    $ent = if ($r.PSObject.Properties['entity'] -and "$($r.entity)".Trim()) { "$($r.entity)" } else { "$($r.scope)" }
                    $scopeDiffs.Add([pscustomobject]@{ scope = "$($r.scope)"; entity = $ent; create = @($cre.ToArray()); update = @($upd.ToArray()); remove = @($rem.ToArray()) })
                }
                $report = Get-PimDriftReport -ScopeDiffs @($scopeDiffs.ToArray())
                $plan = if ($selAll) { Get-PimDriftRemediationPlan -DriftReport $report -All -AllowRemove:$allowRemove }
                        else        { Get-PimDriftRemediationPlan -DriftReport $report -SelectKeys $selectKeys -AllowRemove:$allowRemove }

                if (@($plan.changes).Count -eq 0) {
                    Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; applied = 0; refused = @($plan.refused); detail = 'nothing to apply for the current selection (already remediated, or an extra was refused without allowRemove).' })
                    return 200
                }
                # Apply ONLY the selected drift through the EXISTING engine path.
                # requiresPrune (a selected 'extra') -> Full+Prune; else Delta
                # (create/update only). The plan already excluded any extra that
                # was not explicitly opted in, so a destructive remove can never
                # happen by accident here.
                $who = try { (Get-PimManagerRole).identity } catch { '' }
                $applyArgs = @{ Scope = 'All'; Changes = @($plan.changes) }
                if ($plan.requiresPrune) { $applyArgs['Mode'] = 'Full'; $applyArgs['Prune'] = $true } else { $applyArgs['Mode'] = 'Delta' }
                $applyRes = @(Invoke-PimEngine @applyArgs)
                $applied = 0; $errors = 0
                foreach ($ar in @($applyRes)) { $applied += [int]$ar.applied; $errors += [int]$ar.errors }
                Write-PimManagerAuditEvent -Action 'governance.drift.remediate' -Target ("selected={0} prune={1}" -f @($plan.changes).Count, [bool]$plan.requiresPrune) -After ([ordered]@{ counts = $plan.counts; mode = $applyArgs['Mode']; allowRemove = $allowRemove; by = $who }) -Result $(if ($errors) { 'error' } else { 'ok' })
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok       = ($errors -eq 0)
                    mode     = $applyArgs['Mode']
                    requiresPrune = [bool]$plan.requiresPrune
                    selected = $plan.counts.selected
                    applied  = $applied
                    errors   = $errors
                    refused  = @($plan.refused)
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "remediation failed: $($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -match '^/api/diff/([\w\.-]+)$' -and $method -eq 'POST') {
            $base = $Matches[1]
            $spec = Get-PimCsvSpec -BaseName $base
            if (-not $spec) {
                Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown csv base: $base" }
                return 404
            }
            $script:lastHeartbeat = Get-Date
            $body = Read-RequestJson -Request $req
            $rowsRaw = @()
            if ($body -and $body.rows) { $rowsRaw = @($body.rows) }
            $rowsOrdered = @($rowsRaw | ForEach-Object { ConvertTo-OrderedRow $_ } | Where-Object { $_ -ne $null })
            $current = Read-PimRows -BaseName $base
            $diff = Compare-PimRowSets -Before $current.rows -After $rowsOrdered -Base $base
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                base     = $base
                source   = $current.source
                adds     = $diff.adds
                removes  = $diff.removes
                modifies = $diff.modifies
                unchanged = $diff.unchanged
            })
            return 200
        }

        Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "not found: $method $path" }
        return 404
    }

    # Unknown / static path.
    Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "not found: $method $path" }
    return 404
}

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

switch ($PSCmdlet.ParameterSetName) {

    'Refresh' {
        Write-Host "PIM4EntraPS Mapper -- refreshing tenant lists ..." -ForegroundColor Cyan
        if (-not (Get-Command Invoke-PimTenantListRefresh -ErrorAction SilentlyContinue)) {
            throw "_tenantSync.ps1 was not loaded -- expected next to Open-PimManager.ps1 at: $tenantSync"
        }
        $r = Invoke-PimTenantListRefresh
        if ($r.ok) {
            Write-Host "  done." -ForegroundColor Green
        } else {
            Write-Warning ("  refresh did not complete: {0}" -f ($r.reason | Out-String))
        }
    }
    default {
        # Default = server mode (even without -Server explicitly set).
        Invoke-Server -DesiredPort $Port
    }
}
