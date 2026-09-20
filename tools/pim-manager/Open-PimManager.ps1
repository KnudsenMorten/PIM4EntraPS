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

    PowerShell 5.1 compatible. The map libraries (Cytoscape + dagre) are served inline in
    the HTML -- nothing is loaded from a CDN (DOC-17 i: this used to say "CDN-loaded").
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

# IMP-33: the engine's unmanaged-admin REPORT (pim.Settings 'UnmanagedAdmins') is read through the same file
# that writes it, so the tile's verdict and the engine's record cannot drift. Pure functions only.
# The tile's reader lives in THIS file (pure, no guard state) -- not in PIM-DisableGuard.ps1. The account-disable
# guard is NOT loaded here: since BUG-189 (§33.28) PIM-ApprovalGate.ps1 (loaded below) dot-sources it itself, so the
# offboard gate's GATE 3 is always evaluated (explicit-disable semantics), whatever the load order. Before BUG-189,
# whether some earlier file had happened to load the guard decided whether an approved offboard was refused as
# "account-disable is OFF" (measured by Test-PimManagerSql, 2026-09-18) -- which is why this line once warned about it.
$_unmanagedAdminsLib = Join-Path $solutionRoot 'engine\_shared\PIM-UnmanagedAdmins.ps1'
if (Test-Path -LiteralPath $_unmanagedAdminsLib) { . $_unmanagedAdminsLib }

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
# REQ-L: the read-only Policy templates page -- each stored template in plain words + which delegations use it
# (GET /api/policy-templates), and the per-type standard template the grid's PolicyTemplate picker shows for blank.
$_policyTplCatalogLib = Join-Path $solutionRoot 'engine\_shared\PIM-PolicyTemplateCatalog.ps1'
if (Test-Path -LiteralPath $_policyTplCatalogLib) { . $_policyTplCatalogLib }

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
# REQ-U (prereqs) -- the workload-prerequisite catalog + view (engine/_shared/PIM-WorkloadPrereqs.ps1): behind
# GET /api/workload-prereqs, the green / amber / red chips that show whether tools\setup\Initialize-PimWorkloadPrereqs.ps1
# has run for a workload. The same definitions the setup script and tests\Test-PimWorkloadPrereqs.ps1 use.
$_workloadPrereqLib = Join-Path $solutionRoot 'engine\_shared\PIM-WorkloadPrereqs.ps1'
. $_workloadPrereqLib
# REQ-X -- the permission-template pack planner (engine/_shared/PIM-TemplatePacks.ps1): GET /api/templates plans every
# pack with the SAME Get-PimTemplatePackPlan tools\setup\Import-PimPermissionTemplate.ps1 uses, so the GUI and the script
# offer the same rows and both ADOPT a group the store already defines.
$_templatePacksLib = Join-Path $solutionRoot 'engine\_shared\PIM-TemplatePacks.ps1'
. $_templatePacksLib

# Approval-gated offboarding + revoke control plane (engine/_shared/PIM-ApprovalGate.ps1)
# -- the MAKER/CHECKER approval queue (REQUIREMENTS §13/§27 H3/H4). Powers the new
# Approvals tab + endpoints: New-/Add-/Get-PimApprovalRequest (maker), Set-PimApprovalDecision
# (checker), Test-PimApprovalSeparationOk (maker≠checker), Get-PimOffboardSequencePlan (the
# guided offboard plan shown before approval). PURE decision functions + a thin persistence
# adapter that prefers Get-/Set-PimSetting -> SQL pim.Settings (we provide the shim below so
# approvals persist through the SAME store the Manager uses), JSON-file + in-memory fallback.
# Dot-sourced standalone so the endpoints work without SQL. NO auto-execute path lives here:
# this GUI is the approval gate -- offboarding/revoke NEVER fire automatically.
# IMP-39: the break-glass ACCOUNT list lives in SQL (pim.Settings 'BreakGlassAccounts', unioned with the legacy
# $global:PIM_BreakGlassAccounts / env PIM_BREAKGLASS_ACCOUNTS). Loaded BEFORE the approval gate + session-revoke
# libs so they resolve the same reader. The Manager's own Get-PimBreakGlassIdentifiers (below) delegates to it.
$_breakGlassLib = Join-Path $solutionRoot 'engine\_shared\PIM-BreakGlassAccounts.ps1'
if (Test-Path -LiteralPath $_breakGlassLib) { . $_breakGlassLib }
# Break-glass MAKER/CHECKER (operator 2026-09-19): a change to that list is a pending request a SECOND SuperAdmin
# approves (pim.Settings 'BreakGlassAccountsChange'). Only the Manager loads this; the engine reads the list alone.
$_breakGlassChangeLib = Join-Path $solutionRoot 'engine\_shared\PIM-BreakGlassChange.ps1'
. $_breakGlassChangeLib
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

# §71.43 -- UPDATE RING + update state (engine/_shared/PIM-UpdateState.ps1). The ring this environment
# is on is an environment variable on the UPDATE JOB (ca-pim-update), not on this container, so the
# Manager cannot read it directly and must never guess it. The nightly update job records ring,
# approved version, built version, outcome and timestamp into pim.Settings['UpdateState']; this lib
# holds the PURE verdict over that record (behind / held / failing / stale / not recorded yet) which
# powers the header ring badge and the Jobs > "Updates & ring" panel. READ-ONLY: nothing here, and no
# endpoint below, can change a ring -- a ring move is an operator act on the update job.
$_updStateLib = Join-Path $solutionRoot 'engine\_shared\PIM-UpdateState.ps1'
if (Test-Path -LiteralPath $_updStateLib) { . $_updStateLib }

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

# REQ-N -- the managed-tenant REGISTRY (engine/_shared/PIM-MspRegistry.ps1): the ONE writer of a platform.Tenants row,
# shared with tools/setup/Register-PimManagedTenant.ps1 (/api/msp/tenants). REQ-O -- the REPLICATION OVERVIEW
# (engine/_shared/PIM-ReplicationOverview.ps1): every replicable row and the tenants it reaches, laid out from the SAME
# reach preview the plan computes (/api/msp/replication/overview). Both are MSP-master surfaces.
$_mspRegistryLib = Join-Path $solutionRoot 'engine\_shared\PIM-MspRegistry.ps1'
if (Test-Path -LiteralPath $_mspRegistryLib) { . $_mspRegistryLib }
$_replOverviewLib = Join-Path $solutionRoot 'engine\_shared\PIM-ReplicationOverview.ps1'
if (Test-Path -LiteralPath $_replOverviewLib) { . $_replOverviewLib }

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

# The cadence of the two self-gated MSP jobs (the managed tenant's pull, the master's publish) -- the Job schedule page
# edits it, the jobs read it (engine/_shared/PIM-JobCadence.ps1). Pure; no I/O at load.
$_jobCadenceLib = Join-Path $solutionRoot 'engine\_shared\PIM-JobCadence.ps1'
if (Test-Path -LiteralPath $_jobCadenceLib) { . $_jobCadenceLib }

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
    # 🔴 SEC-28: WHICH layer is in front decides whether the headers mean anything at all. With no
    # auth edge (a VM, or any host that is not Container Apps / App Service, unless declared) they are
    # the caller's own words and every identity is refused -- see Get-PimHostedAuthLayer.
    $authLayer = 'easyauth'
    if (Get-Command Get-PimHostedAuthLayer -ErrorAction SilentlyContinue) { $authLayer = Get-PimHostedAuthLayer }
    $strict = ($authLayer -eq 'signed-token') -or (Test-PimHostedSignedTokenRequired)
    $jwks = $null
    if ($strict) { $jwks = Get-PimEntraJwks }
    $issuers = @("$env:PIM_HOSTED_AUTH_ISSUERS" -split '[,;]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($issuers.Count -eq 0 -and (Get-Command Get-PimHostedDefaultIssuers -ErrorAction SilentlyContinue)) {
        # Pin the issuer to THIS tenant when none is configured -- a signature check alone accepts a
        # token from any Entra tenant (the signing keys are shared).
        $tidPin = "$env:PIM_HOSTED_AUTH_TENANT".Trim(); if (-not $tidPin) { $tidPin = "$($global:PIM_TenantId)".Trim() }
        $issuers = @(Get-PimHostedDefaultIssuers -TenantId $tidPin)
    }
    $auds    = @("$env:PIM_HOSTED_EASYAUTH_AUD" -split '[,;]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $d = Resolve-PimHostedPrincipal `
            -PrincipalName "$($Request.Headers['X-MS-CLIENT-PRINCIPAL-NAME'])" `
            -PrincipalBlob "$($Request.Headers['X-MS-CLIENT-PRINCIPAL'])" `
            -SignedToken   "$($Request.Headers['X-MS-TOKEN-AAD-ID-TOKEN'])" `
            -Jwks $jwks -ExpectedIssuers $issuers -ExpectedAudiences $auds -AuthLayer $authLayer
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

function Get-PimManagerLocalIdentity {
    <#
      🔴 BUG-186 -- WHO a LOCAL (loopback) Manager acts as. The break-glass console (Start-PimEmergency.ps1)
      signs the operator in INTERACTIVELY and connects to SQL with that token; ManagerAccess, PIM_SuperAdmins
      and the audit trail are all keyed on the Entra UPN. Resolving the WINDOWS account name here
      ('MGMT1\mok') matched none of them, so the operator landed as a Reader in the one console meant for
      emergencies. When the process runs with an interactive SQL sign-in, the identity is the UPN in THAT
      token (the SQL connection authenticates as exactly this principal); otherwise the Windows account.
      The token is decoded, not trusted from a free-form setting, so nothing but the sign-in decides it.
    #>
    if (($global:PIM_SqlInteractive -or $global:PIM_Interactive) -and "$($global:PIM_SqlAccessToken)".Trim()) {
        $tok = "$($global:PIM_SqlAccessToken)"
        if ($script:PimLocalIdTok -eq $tok -and $script:PimLocalId) { return $script:PimLocalId }
        $upn = ''
        try {
            if (Get-Command Get-PimJwtParts -ErrorAction SilentlyContinue) {
                $jp = Get-PimJwtParts -Token $tok
                if ($jp) { foreach ($c in @('preferred_username', 'upn', 'unique_name', 'email')) { if ("$($jp.payload.$c)".Trim()) { $upn = "$($jp.payload.$c)".Trim(); break } } }
            }
        } catch { $upn = '' }
        if ($upn) { $script:PimLocalIdTok = $tok; $script:PimLocalId = $upn; return $upn }
    }
    try { return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { return "$env:USERNAME" }
}

function Get-PimManagerDelegatedCap {
    <#
      PURE. REQ-Y (operator 2026-09-20: "fix req-y 3 items"). What a RESOLVED Manager role becomes when the Pro
      feature 'access.delegated' -- delegated administration ceilings -- is not licensed for this environment.

      🔴 THE HOLE THIS CLOSES. 'Delegated' IS that Pro feature: a Delegated user is precisely "a Manager user
      limited by tier / level / service / scope with named capabilities". POST /api/manager-access already refused
      to CREATE one without a licence (Test-PimManagerProFeature -Key 'access.delegated', 403), but nothing checked
      when a role was RESOLVED -- so both remaining doors stood open:
        * env PIM_DelegatedAdmins granted Delegated with no licence check at all (the reported gap), and
        * an entry already stored in pim.Settings['ManagerAccess'] -- written before the gate shipped, or restored
          from a backup -- kept resolving to Delegated forever.
      A write-only gate on a role that outlives the write is not a gate. This caps at RESOLUTION, so both sources
      are covered by one rule and neither can drift from the other.

      🔒 DOWNWARD ONLY. The cap is Reader -- never Admin -- so an unlicensed environment loses the ceiling feature
      and grants NO extra authority. That is the same shape as the PIM_HostedDefaultRole cap a few lines below:
      a role this environment may not express is capped, loudly, and the source string says why.
      Returns @{ role; source; capped }.
    #>
    param([AllowEmptyString()][string]$Role, [AllowEmptyString()][string]$Source, [bool]$Licensed, [AllowEmptyString()][string]$Reason)
    $r = "$Role".Trim()
    if ($r -ne 'Delegated' -or $Licensed) { return @{ role = $r; source = "$Source"; capped = $false } }
    $why = if ("$Reason".Trim()) { "$Reason".Trim() } else { 'no Pro licence covers delegated administration' }
    return @{ role = 'Reader'; source = "$Source (Delegated capped at Reader -- $why)"; capped = $true }
}

function Limit-PimManagerRoleByLicence {
    <#
      REQ-Y. The LIVE half of Get-PimManagerDelegatedCap: verify 'access.delegated' for this environment and apply
      the cap to one resolved @{ role; identity; source }. A no-op for every role but Delegated.
      🪤 THE FAIL DIRECTION IS COPIED FROM Test-PimManagerProFeature ON PURPOSE, because the two gates must agree:
      the verifier NOT LOADED in this process = allow (a Manager without the licence module cannot verify anything,
      and locking it out would be a worse failure than the one being prevented); the verifier present but THROWING
      = refuse. A resolution gate that allowed where the write gate refuses would hand out a role the same session
      is then refused for using.
    #>
    param([Parameter(Mandatory)][hashtable]$Resolved)
    if ("$($Resolved.role)".Trim() -ne 'Delegated') { return $Resolved }
    if (-not (Get-Command Test-PimFeatureProLicence -ErrorAction SilentlyContinue)) { return $Resolved }
    $srv = "$($global:PIM_SqlServer)".Trim(); if (-not $srv) { $srv = "$env:PIM_SqlServer".Trim() }
    $pl = $null
    try { $pl = Test-PimFeatureProLicence -Key 'access.delegated' -TenantId "$($global:PIM_TenantId)".Trim() -SqlServer $srv } catch { $pl = $null }
    $licensed = [bool]($pl -and $pl.ok)
    $reason   = if ($pl) { "$($pl.reason)" } else { 'the licence check failed' }
    $cap = Get-PimManagerDelegatedCap -Role "$($Resolved.role)" -Source "$($Resolved.source)" -Licensed $licensed -Reason $reason
    if (-not $cap.capped) { return $Resolved }
    # Once per process: this is a deployment fact, not a per-request event, and one line per gate check would bury it.
    if (-not $script:PimDelegatedLicenceWarned) {
        $script:PimDelegatedLicenceWarned = $true
        Write-Warning ("  [rbac] Delegated administration is a Pro feature and is NOT licensed here -- every Delegated " +
                       "identity resolves as Reader until a licence is registered ($($cap.source)). Contact mok@mortenknudsen.net.")
    }
    return @{ role = $cap.role; identity = $Resolved.identity; source = $cap.source }
}

function Get-PimManagerRole {
    # Hosted: the Easy Auth principal captured for THIS request. Local: the interactive sign-in's UPN
    # (break-glass console) or the Windows user -- Get-PimManagerLocalIdentity.
    $who = if ($script:PimHosted -and "$script:CurrentRequestPrincipal".Trim()) { "$script:CurrentRequestPrincipal" }
           elseif ($script:PimHosted) { '' }
           else { Get-PimManagerLocalIdentity }
    if ($script:PimHosted -and -not "$who".Trim()) {
        # hosted with no authenticated principal = no Easy Auth in front -> deny.
        # 🔴 SEC-31: this used to be READER, so an external Manager without Easy Auth served Reader data to
        # anonymous callers. 'None' ranks below Reader (Test-PimManagerRoleAtLeast refuses every minimum),
        # and the /api gate in Handle-Request answers 401 before any handler runs.
        return @{ role = 'None'; identity = '<unauthenticated>'; source = 'hosted: no authenticated principal (fail closed -- 401)' }
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
                    # REQ-Y: a STORED Delegated entry is capped at Reader without a Pro licence, exactly as the env
                    # var below is -- the write gate on POST /api/manager-access cannot reach a row written earlier.
                    return (Limit-PimManagerRoleByLicence @{ role = $r; identity = $who; source = 'sql ManagerAccess' })
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
    # REQ-Y: capped at Reader without a Pro licence for 'access.delegated' -- this env var was the one door into
    # delegated administration that no licence check covered.
    if ($delegs -contains $whoLc) { return (Limit-PimManagerRoleByLicence @{ role = 'Delegated'; identity = $who; source = 'env PIM_DelegatedAdmins' }) }
    if ("$env:PIM_HostedDefaultRole".Trim()) {
        # 🔴 IMP-49 m: a DEFAULT role is what every signed-in tenant user (guests included, SEC-44) gets
        # without being named anywhere. It used to accept Admin/SuperAdmin, which turned one env var into
        # "the whole tenant may grant tier-0". A default can never elevate: anything but Reader is Reader,
        # and it says so. Elevation is granted per identity (SQL ManagerAccess / PIM_SuperAdmins / PIM_Admins).
        $drRaw = "$env:PIM_HostedDefaultRole".Trim()
        if ($drRaw -ne 'Reader') {
            if (-not $script:PimDefaultRoleWarned) {
                $script:PimDefaultRoleWarned = $true
                Write-Warning "  [rbac] PIM_HostedDefaultRole='$drRaw' is IGNORED above Reader -- a default role never elevates. Grant Admin/SuperAdmin per identity (Set-PimManagerAccess.ps1)."
            }
        }
        return @{ role = 'Reader'; identity = $who; source = $(if ($drRaw -eq 'Reader') { 'env PIM_HostedDefaultRole' } else { "env PIM_HostedDefaultRole ('$drRaw' capped at Reader)" }) }
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
    # IMP-42: no emergency-override.custom.json fallback. PIM v2 is SQL-only; a file only this container
    # can see is not an override the engine acts on, so reading one would report a state that is not real.
    return $null
}

function Set-PimManagerEmergencyOverride {
    # Returns 'sql'. THROWS when there is no SQL store or it rejects the write -- an activation the
    # engine cannot see must fail loudly. IMP-42: the file branch that used to follow is gone; it was
    # unreachable in a SQL-only Manager and, had it ever run, would have written an override nothing reads.
    param([Parameter(Mandatory)][object]$Override)
    $cs = $null
    if ((Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) -and
        (Get-Command Set-PimSqlSetting          -ErrorAction SilentlyContinue)) {
        try { $cs = Get-PimSqlConnectionString } catch { $cs = $null }
    }
    if (-not $cs) { throw 'no SQL store is configured -- the emergency override lives in pim.Settings (PIM v2 is SQL-only), so nothing was recorded' }
    try {
        Set-PimSqlSetting -ConnectionString $cs -Name (Get-PimEmergencyOverrideStoreName) -Value $Override
        return 'sql'
    } catch {
        Write-Warning "  [emergency] SQL override write FAILED -- the engine will NOT see this override: $($_.Exception.Message)"
        throw
    }
}

function Get-PimManagerReviewReminderMap {
    # BUG-219 -- the { instanceId -> lastRemindedUtc } map (pim.Settings 'AccessReviewReminders') that keeps the
    # access-review reminder repeat window across presses. Absent -> empty. A store that cannot be read THROWS:
    # "never reminded" read off a failed read would re-fire every reminder.
    $v = Get-PimManagerSettingObject -Name 'AccessReviewReminders'
    $m = @{}
    if ($null -eq $v) { return $m }
    if ($v -is [System.Collections.IDictionary]) { foreach ($k in @($v.Keys)) { $m["$k"] = "$($v[$k])" } }
    else { foreach ($p in @($v.PSObject.Properties)) { $m["$($p.Name)"] = "$($p.Value)" } }
    return $m
}

function Save-PimManagerReviewReminderMap {
    param([Parameter(Mandatory)][hashtable]$Map)
    Set-PimManagerSettingObject -Name 'AccessReviewReminders' -Value $Map
}

function Get-PimManagerDiscoveryCurrent {
    # BUG-193 -- the CURRENT tenant resources for "Newly discovered resources", from the SQL tenant cache
    # (pim.TenantCache kinds 'azure-scopes' / 'entra-roles', written by _tenantSync). Returns
    # @{ scopes; roles; missing } -- `missing` names every kind that has never been written, so the caller can
    # say "not refreshed yet" instead of presenting an unread cache as "nothing new".
    $out = @{ scopes = @(); roles = @(); missing = @() }
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($pair in @(@('azure-scopes', 'scopes'), @('entra-roles', 'roles'))) {
        $entry = $null
        if (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue) {
            try { $entry = Get-PimTenantCacheEntry -Kind $pair[0] } catch { $entry = $null }
        }
        if ($null -eq $entry) { [void]$missing.Add($pair[0]); continue }
        $out[$pair[1]] = @(@($entry.items) | Where-Object { $null -ne $_ })
    }
    $out.missing = @($missing.ToArray())
    return $out
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

# Emergency override state (phase 8). The passphrase is verified (SHA-256, constant time, 5 failures in 15 min
# lock it) against the key vault secret PIM-EmergencyPasscode in the vault named by PIM_EmergencyVault (REQ-F:
# tools/setup/Set-PimEmergencyPassphrase.ps1 provisions both). The secret may hold the passphrase or its SHA-256
# hex; the setup script stores the hex, so the clear passphrase is never in the vault.
$script:EmergencyAttempts = @()

function Get-PimManagerEmergencyPassphraseStatus {
    # REQ-F: { configured; source; vault; secretName; reason } for the Settings card -- NEVER the passphrase or its
    # hash. Cached 60 s (it reads the key vault); a failure is reported as "not configured", with the reason.
    $now = [datetime]::UtcNow
    if ($script:PimEmergencyPpCache -and ($now - $script:PimEmergencyPpCache.at).TotalSeconds -lt 60) { return $script:PimEmergencyPpCache.value }
    $st = $null
    try {
        if (Get-Command Get-PimEmergencyPassphraseStatus -ErrorAction SilentlyContinue) { $st = Get-PimEmergencyPassphraseStatus }
        else { $st = [pscustomobject]@{ configured = $false; source = 'none'; vault = "$($global:PIM_EmergencyVault)"; secretName = 'PIM-EmergencyPasscode'; reason = 'the governance library (PIM-Governance.ps1) is not loaded' } }
    } catch { $st = [pscustomobject]@{ configured = $false; source = 'none'; vault = "$($global:PIM_EmergencyVault)"; secretName = 'PIM-EmergencyPasscode'; reason = "$($_.Exception.Message)" } }
    $v = [ordered]@{
        configured = [bool]$st.configured; source = "$($st.source)"; vault = "$($st.vault)"; secretName = "$($st.secretName)"; reason = "$($st.reason)"
        setup = 'tools/setup/Set-PimEmergencyPassphrase.ps1 stores the passphrase (as its SHA-256) in this environment''s key vault as PIM-EmergencyPasscode, sets PIM_EmergencyVault on the Manager and grants the Manager''s identity read access to that secret.'
    }
    $script:PimEmergencyPpCache = @{ at = $now; value = $v }
    return $v
}

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
    Initialize-PimManagerPublishJobViews -ConnectionString $cs
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

function Initialize-PimManagerPublishJobViews {
    # REQ-Y: on a master whose publish job is deployed, re-apply pim.vw_PublishJobControl so it carries the 'License' row
    # the publish job's licence gate reads (Get-PimPublishJobControlViewRefreshSql -- a store without the view is left
    # alone). Runs at every Manager start, i.e. on every upgrade. Reported, not fatal: the publish job then reads no
    # licence through the old view and refuses, loudly.
    param([Parameter(Mandatory)][string]$ConnectionString)
    if (-not (Get-Command Get-PimPublishJobControlViewRefreshSql -ErrorAction SilentlyContinue)) { return }
    try { [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimPublishJobControlViewRefreshSql)) }
    catch { Write-Warning "  [store] the publish job's control view could NOT be refreshed (REQ-Y licence row): $($_.Exception.Message)" }
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
    Initialize-PimManagerPublishJobViews -ConnectionString $cs
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
# IMP-42: no $script:mutationLog -- the commit record is the SQL audit event (Write-PimMutationLog -> config.save).
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
# REQ-I + REQ-U (Coverage & gaps page): the coverage REPORT reader (engine/_shared/PIM-Coverage.ps1). The report is computed
# ONLY by the scheduler (job 'coverage'); this process reads pim.TenantCache 'coverage-report' and queues a refresh -- it never
# registers the handler and never calls Invoke-PimCoverageJob / Get-PimCoverageInputs.
$_coverageLib = Join-Path $solutionRoot 'engine\_shared\PIM-Coverage.ps1'
if (Test-Path -LiteralPath $_coverageLib) { . $_coverageLib }
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
# REQ-F (2026-09-19): the emergency passphrase's key vault. Resolve-PimEmergencyExpectedHash reads the GLOBAL, and
# nothing mapped the container's env var into it -- so even a Manager with PIM_EmergencyVault set found no passphrase.
# tools/setup/Set-PimEmergencyPassphrase.ps1 sets the env var; this is what makes the Manager see it.
Set-PimManagerCfgFromEnv 'PIM_EmergencyVault'          'PIM_EmergencyVault'
Set-PimManagerCfgFromEnv 'PIM_EmergencyPasscodeSecret' 'PIM_EmergencyPasscodeSecret'

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
    # Notification + TAP mail is sent FROM the shared mailbox the engine SPN is scoped to, so an admin
    # needs no mailbox of its own. DOC-17 g -- WHO receives it (§71.19, Get-PimAdminMailRecipientPlan):
    # 1) ForwardMailsToContact=TRUE + MailForwardAddress (the explicit per-admin override), else 2) the
    # owners of the admin's sponsor DEPARTMENT (PIM-Definitions-Departments.Owners), else 3) ManagerEmail
    # as a LEGACY fallback only. ManagerEmail is not "the recipient" any more.
    # 🔴 BUG-139 -- EIGHT FIELDS THE ENGINE READS HAD NO COLUMN, SO THEY COULD NOT BE SET OR SEEN.
    # In SQL mode this defaultHeader IS the grid's header (Read-PimRows returns $spec.defaultHeader
    # verbatim -- it is NOT derived from the rows), so a field missing here is invisible and
    # uneditable in All records no matter what the row actually carries.
    # Missing were: AdminType, ManagerEmail, AccountStatus, AutoDisableDate, ManagementMode, Company,
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
    [ordered]@{ base = 'Account-Definitions-Admins';      group = 'Definitions';  defaultHeader = @('FirstName','LastName','Initials','Purpose','TargetUsage','TargetPlatform','UserType','AdminType','UserName','DisplayName','UserPrincipalName','UsageLocation','Company','Department','ManagerEmail','Environment','ForwardMailsToContact','MailForwardAddress','CreateTAP','TAPStartDate','TAPLifetimeHours','AccountStatus','AutoDisableDate','ManagementMode','Ring','Target','Replicate') },
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
    [ordered]@{ base = 'PIM-Definitions-Roles';           group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform','IsRoleAssignable','Owners','SponsorUpn','SponsorNotes','Department','Organisation','Project','Team','BusinessUnit','PolicyTemplate','ReviewCycle','Replicate','Ring','Target') },
    [ordered]@{ base = 'PIM-Definitions-Tasks';           group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners','PolicyTemplate','Replicate','Ring','Target') },
    [ordered]@{ base = 'PIM-Definitions-Services';        group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners','PolicyTemplate','Replicate','Ring','Target') },
    [ordered]@{ base = 'PIM-Definitions-Processes';       group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners','PolicyTemplate','Replicate','Ring','Target') },
    [ordered]@{ base = 'PIM-Definitions-Resources';       group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners','PolicyTemplate','Replicate','Ring','Target') },
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
    # 2026-09-19 ("did you add selection in wizards and existing"): Departments / Organization / Projects / CrossOrg gain
    # PolicyTemplate -- the engine already reads it on these definitions (Get-PimGroupPolicyDefinitionRows), but the grid
    # could not show or change it. A header column never rewrites stored rows (Read-PimRows returns them as stored).
    [ordered]@{ base = 'PIM-Definitions-Departments';     group = 'Definitions';  defaultHeader = @('Department','GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners','PolicyTemplate','Replicate','Ring','Target') },
    [ordered]@{ base = 'PIM-Definitions-Organization';    group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners','PolicyTemplate','Replicate','Ring','Target') },
    # Direct-group types Project (PROJ-, AU PIM-PROJECTS) and Cross-org (CORG-, AU PIM-CROSSORG) --
    # operator, 2026-09-12: "where is the project and cross-org direct group".
    [ordered]@{ base = 'PIM-Definitions-Projects';        group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners','PolicyTemplate','Replicate','Ring','Target') },
    [ordered]@{ base = 'PIM-Definitions-CrossOrg';        group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners','PolicyTemplate','Replicate','Ring','Target') },
    [ordered]@{ base = 'PIM-Definitions-AU';              group = 'Definitions';  defaultHeader = @('AUDisplayName','AUDescription','AdministrativeUnitTag','Workload','Level','TierLevel','Visibility') },
    [ordered]@{ base = 'PIM-Assignments-Admins';          group = 'Assignments';  defaultHeader = @('Username','GroupTag','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform','Replicate','Ring','Target') },
    [ordered]@{ base = 'PIM-Assignments-Groups';          group = 'Assignments';  defaultHeader = @('TargetGroupTag','SourceGroupTag','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform','Replicate','Ring','Target') },
    # REQ-L / §68.6 #37(c): PolicyTemplate + ApproverUpns on the three role-assignment entities. The engine already READ
    # both (Get-PimManagedRolePolicyTargets, Get-PimAzResPolicyTargets) but no column offered them, so a delegation's policy
    # could not be switched in the grid, and an approval template on an Entra role had nowhere to name its approvers.
    # A header column never rewrites a stored row: Read-PimRows returns the rows as stored, and a row without the key
    # is read blank (= the type's standard template).
    [ordered]@{ base = 'PIM-Assignments-Roles-Groups';    group = 'Assignments';  defaultHeader = @('GroupTag','RoleDefinitionName','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform','PolicyTemplate','ApproverUpns','Replicate','Ring','Target') },
    [ordered]@{ base = 'PIM-Assignments-Roles-AUs';       group = 'Assignments';  defaultHeader = @('GroupTag','AdministrativeUnitTag','RoleDefinitionName','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform','PolicyTemplate','ApproverUpns','Replicate','Ring','Target') },
    [ordered]@{ base = 'PIM-Assignments-Azure-Resources'; group = 'Assignments';  defaultHeader = @('GroupTag','AzScope','AzScopePermission','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform','PolicyTemplate','ApproverUpns','Replicate','Ring','Target') },
    # REQ-U wave 2: Permissions + DataSources = a Defender XDR ROLE SPEC (allowedResourceActions / appScopeIds, ';'-separated,
    # DataSources blank = all). With Permissions the engine creates / patches the custom role named like the group and assigns
    # it with those data sources (DefenderXdrRoles); without, the row binds an existing role by name, as before.
    [ordered]@{ base = 'PIM-Assignments-Workloads';       group = 'Assignments';  defaultHeader = @('Workload','RoleName','GroupTag','Scope','Action','Notes','Permissions','DataSources','Replicate','Ring','Target') }
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

# ---------------------------------------------------------------------------
# SEC-43 / BUG-198 / BUG-200 -- the grid's read slice, the commit's merge, and the concurrency hash.
# ---------------------------------------------------------------------------
function ConvertTo-PimCanonicalJsonString {
    # PURE. A JSON string literal with deterministic escaping (same bytes on PS 5.1 and pwsh 7, whose
    # ConvertTo-Json escape differently -- a hash over those would differ by runtime).
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ($null -eq $Value) { return 'null' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $Value.ToCharArray()) {
        $c = [int]$ch
        if ($ch -eq '"') { [void]$sb.Append('\"') }
        elseif ($ch -eq '\') { [void]$sb.Append('\\') }
        elseif ($c -lt 0x20) { [void]$sb.Append(('\u{0:x4}' -f $c)) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Get-PimRowsHash {
    # PURE (BUG-200). SHA256 hex of the canonical JSON of a row set: every row as an object with its keys
    # sorted ordinally and every value as its string form, the rows sorted ordinally by that text, joined as
    # one JSON array. Order-independent (a reorder is not a change) and runtime-independent. The GET hashes
    # the FULL stored set before any scope filter; the PUT recomputes it from the store and compares.
    param([AllowNull()][AllowEmptyCollection()][object[]]$Rows = @())
    $items = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $names = @()
        if ($r -is [System.Collections.IDictionary]) { $names = @($r.Keys | ForEach-Object { "$_" }) }
        else { $names = @($r.PSObject.Properties | ForEach-Object { $_.Name }) }
        $sorted = [string[]]@($names)
        [System.Array]::Sort($sorted, [System.StringComparer]::Ordinal)
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($n in $sorted) {
            $v = if ($r -is [System.Collections.IDictionary]) { $r[$n] } else { $r.PSObject.Properties[$n].Value }
            $vs = if ($null -eq $v) { $null } else { "$v" }
            $parts.Add((ConvertTo-PimCanonicalJsonString $n) + ':' + (ConvertTo-PimCanonicalJsonString $vs))
        }
        $items.Add('{' + ($parts -join ',') + '}')
    }
    $arr = $items.ToArray()
    [System.Array]::Sort($arr, [System.StringComparer]::Ordinal)
    $json = '[' + ($arr -join ',') + ']'
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($json)) } finally { $sha.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-PimManagerRowIdentity {
    # The identity a merge matches rows on: the store's natural key, or -- for a row without one -- its full
    # content (such rows can only be matched as "the same row, unchanged").
    param([string]$Base, [object]$Row)
    $k = ''
    if (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue) { try { $k = "$(Get-PimStoreRowKey -Base $Base -Row $Row)".Trim() } catch { $k = '' } }
    if ($k) { return "key:" + $k.ToLowerInvariant() }
    return "content:" + (Get-PimRowsHash -Rows @($Row))
}

function Get-PimManagerVisibleSlice {
    <#
      SEC-43 / BUG-198. Split a FULL stored row set into what THIS caller may see and what they may not:
      @{ rows = visible; hidden = the rest; filtered = was anything withheld }.
        1. Delegated role -> only rows of the groups they own (the same scope Read-PimRows applies).
        2. A non-SuperAdmin with a portal-admin profile -> Select-PimPortalVisibleRows.
      SuperAdmin and callers with neither see everything (filtered = $false).
      The GET returns `rows`; the PUT keeps `hidden` untouched and merges the caller's submission beside it.
    #>
    param([Parameter(Mandatory)][string]$Base, [AllowEmptyCollection()][object[]]$Rows = @())
    $all = @($Rows)
    $visible = $all
    $filtered = $false
    $isSuper = $false
    try { $isSuper = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin') } catch { $isSuper = $false }
    if (-not $isSuper) {
        $role = $null
        try { $role = Get-PimManagerRole } catch { $role = $null }
        if ($role -and "$($role.role)" -eq 'Delegated') {
            $scope = Get-PimDelegatedOwnedScope -Identity "$($role.identity)"
            if (-not $scope) { $visible = @() } else { $visible = @($visible | Where-Object { Test-PimRowInScope -Row $_ -Scope $scope }) }
            $filtered = $true
        }
        if ((Get-Command Read-PimPortalProfiles -ErrorAction SilentlyContinue) -and (Get-Command Get-PimPortalProfile -ErrorAction SilentlyContinue) -and (Get-Command Select-PimPortalVisibleRows -ErrorAction SilentlyContinue)) {
            $prof = $null
            try { $prof = Get-PimPortalProfile -Profiles (Read-PimPortalProfiles) -Identity "$(if ($role) { $role.identity })" } catch { $prof = $null }
            if ($prof) { $visible = @(Select-PimPortalVisibleRows -Profile $prof -Rows $visible -Base $Base); $filtered = $true }
        }
    }
    if (-not $filtered) { return @{ rows = $all; hidden = @(); filtered = $false } }
    # Hidden = every stored row NOT in the visible slice (matched by identity, counted, so duplicates survive).
    $visCount = @{}
    foreach ($v in $visible) { $id = Get-PimManagerRowIdentity -Base $Base -Row $v; if ($visCount.ContainsKey($id)) { $visCount[$id]++ } else { $visCount[$id] = 1 } }
    $hidden = New-Object System.Collections.Generic.List[object]
    foreach ($r in $all) {
        $id = Get-PimManagerRowIdentity -Base $Base -Row $r
        if ($visCount.ContainsKey($id) -and $visCount[$id] -gt 0) { $visCount[$id]--; continue }
        $hidden.Add($r)
    }
    return @{ rows = @($visible); hidden = @($hidden.ToArray()); filtered = $true }
}

function Merge-PimManagerVisibleSlice {
    # PURE (BUG-198). The after-set of a scoped commit = the rows the caller cannot see (untouched) + what the
    # caller submitted. A submitted row whose natural KEY equals a hidden row's would overwrite a row outside
    # the caller's scope -- it is reported in `collisions` and the caller refuses the commit.
    param([Parameter(Mandatory)][string]$Base, [AllowEmptyCollection()][object[]]$Hidden = @(), [AllowEmptyCollection()][object[]]$Submitted = @())
    $hiddenKeys = @{}
    foreach ($h in @($Hidden)) { $id = Get-PimManagerRowIdentity -Base $Base -Row $h; if ($id -like 'key:*') { $hiddenKeys[$id] = $true } }
    $collisions = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($Submitted)) {
        $id = Get-PimManagerRowIdentity -Base $Base -Row $s
        if ($id -like 'key:*' -and $hiddenKeys.ContainsKey($id)) { $collisions.Add($id.Substring(4)) }
    }
    return @{ rows = @(@($Hidden) + @($Submitted)); collisions = @($collisions.ToArray()) }
}

function Get-PimRollForwardCommitPlan {
    <#
      PURE (BUG-180 / IMP-37). Merge template roll-forward rows into the current PIM-Assignments-Workloads rows as
      DESIRED STATE. Returns @{ rows = current + new; adds; present; conflicts }.
        * a binding already present (same workload + group + resource + scope + role) -> `present`, not duplicated;
        * a new binding -> appended (`adds`), every existing row kept untouched;
        * a new binding whose STORE KEY (Get-PimStoreRowKey) equals an existing row that is a DIFFERENT binding ->
          `conflicts`: writing it would overwrite that row, so the caller refuses rather than guess.
    #>
    param([AllowEmptyCollection()][object[]]$Current = @(), [AllowEmptyCollection()][object[]]$RollForward = @(), [string]$Base = 'PIM-Assignments-Workloads')
    $field = {
        param($r, $n)
        if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { return "$($r[$n])".Trim() } ; return '' }
        $p = $r.PSObject.Properties[$n]; if ($p) { return "$($p.Value)".Trim() }; return ''
    }
    $bindKey = { param($r) (@('Workload','GroupTag','Resource','Scope','RoleName') | ForEach-Object { (& $field $r $_).ToLowerInvariant() }) -join '|' }
    $storeKey = {
        param($r)
        if (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue) { try { return "$(Get-PimStoreRowKey -Base $Base -Row $r)".Trim().ToLowerInvariant() } catch { } }
        return ''
    }
    $haveBind = @{}; $haveStore = @{}
    foreach ($c in @($Current)) {
        if ($null -eq $c) { continue }
        $haveBind[(& $bindKey $c)] = $true
        $sk = & $storeKey $c
        if ($sk) { $haveStore[$sk] = (& $bindKey $c) }
    }
    $adds = New-Object System.Collections.Generic.List[object]
    $present = New-Object System.Collections.Generic.List[object]
    $conflicts = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($RollForward)) {
        if ($null -eq $r) { continue }
        $bk = & $bindKey $r
        if ($haveBind.ContainsKey($bk)) { $present.Add($r); continue }
        $sk = & $storeKey $r
        if ($sk -and $haveStore.ContainsKey($sk) -and $haveStore[$sk] -ne $bk) {
            $conflicts.Add([pscustomobject]@{ key = $sk; wanted = $bk; existing = $haveStore[$sk] }); continue
        }
        $row = [ordered]@{}
        foreach ($n in @('Workload','RoleName','GroupTag','Scope','Resource','Action')) { $row[$n] = (& $field $r $n) }
        if (-not $row['Action']) { $row['Action'] = 'Assign' }
        $adds.Add([pscustomobject]$row)
        $haveBind[$bk] = $true
        if ($sk) { $haveStore[$sk] = $bk }
    }
    return @{ rows = @(@($Current) + @($adds.ToArray())); adds = @($adds.ToArray()); present = @($present.ToArray()); conflicts = @($conflicts.ToArray()) }
}

function Get-PimManagerDiffTouchedRows {
    # PURE (BUG-198). Every row a Compare-PimRowSets diff touches: adds, the BEFORE and AFTER of every modify,
    # and removes. Reads a modify entry whether it is a dictionary ([ordered]@{ before; after }) or an object --
    # PSObject.Properties does not see dictionary keys, which is how the shared Get-PimWriteAffectedRows lost
    # every modify.
    param([Parameter(Mandatory)][object]$Diff)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($Diff.adds)) { if ($null -ne $a) { $out.Add($a) } }
    foreach ($m in @($Diff.modifies)) {
        if ($null -eq $m) { continue }
        foreach ($side in @('after', 'before')) {
            $v = $null
            if ($m -is [System.Collections.IDictionary]) { if ($m.Contains($side)) { $v = $m[$side] } }
            elseif ($m.PSObject.Properties[$side]) { $v = $m.PSObject.Properties[$side].Value }
            if ($null -ne $v) { $out.Add($v) }
        }
    }
    foreach ($r in @($Diff.removes)) { if ($null -ne $r) { $out.Add($r) } }
    return $out.ToArray()
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
        [string]$Summary = '',
        # BUG-200: whether the commit was checked against the caller's read ('checked' / 'NOT checked ...').
        [string]$Concurrency = '',
        # BUG-198: the caller's visible slice was merged into the full stored set.
        [switch]$ScopeMerged
    )
    # IMP-42: this used to APPEND a tab-separated line to output/pim-manager-mutations.log first -- a file state
    # left in a SQL-only v2 path: gone on every revision roll, read by nothing, and a second "record" beside the
    # SQL audit trail below. The audit event IS the record of a commit.

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
        if ("$Concurrency".Trim()) { $after['concurrency'] = "$Concurrency" }
        if ($ScopeMerged) { $after['scopeMerged'] = $true }
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
function Test-PimModifyAutoDisableImmediate {
    # PURE-ish (BUG-190). Does this AutoDisableDate disable the account on the NEXT engine run -- i.e. does it
    # resolve to a moment at or before now? Such a date is an offboard, not a future contract end. Blank = no.
    # An unreadable value is treated as immediate (fail closed: it must not bypass the approval gate by being
    # odd); the endpoint's own validation has already refused a value the engine cannot read.
    # ONE RULE: the decision lives in engine/_shared/PIM-SensitiveAuthoring.ps1 (Test-PimAdminDisablingValue), which the
    # Review & Save PUT and the maker/checker classifier use too. Without that library nothing can prove the date is in
    # the future, so a set date is treated as immediate (fail closed) -- blank still is not.
    param([string]$Value, [datetime]$NowUtc = [datetime]::UtcNow)
    $v = "$Value".Trim()
    if (-not $v) { return $false }
    if (-not (Get-Command Test-PimAdminDisablingValue -ErrorAction SilentlyContinue)) { return $true }
    return [bool](Test-PimAdminDisablingValue -Column 'AutoDisableDate' -Value $v -NowUtc $NowUtc)
}
function Request-PimManagerOffboardHold {
    # BUG-190 -- THE ONE "this write would disable an admin now" OUTCOME, shared by POST /api/admin-accounts/modify and
    # the Review & Save PUT of Account-Definitions-Admins. The disabling value was NOT written by the caller; this raises
    # the OFFBOARD approval request (maker) when a justification is supplied, so a DIFFERENT administrator approves and
    # executes it on the Approvals tab (which stages the disable for commit). Returns the ordered result both endpoints
    # hand back: approvalRequired / gate / approvalRaised / approvalId / note. Never throws.
    param(
        [Parameter(Mandatory)][string]$Upn,
        [Parameter(Mandatory)][string]$What,           # e.g. "An AutoDisableDate of '2026-09-01'", "AccountStatus 'Disabled'"
        [string]$Justification = '',
        [string]$Ticket = '',
        [string]$Requestor = '',
        [string]$Via = 'manager'
    )
    $res = [ordered]@{ approvalRequired = $true; gate = 'offboard-approval'; upn = $Upn; approvalRaised = $false; approvalId = ''; note = '' }
    $just = "$Justification".Trim()
    $previewOff = $false
    try { if (Get-Command Resolve-PimGovernancePreview -ErrorAction SilentlyContinue) { $previewOff = -not (Test-PimGovernancePreviewEnabled -Resolved (Get-PimGovernancePreview) -Id 'approvalsPreview') } } catch { $previewOff = $false }
    if (-not $just) {
        $res['note'] = "$What disables '$Upn' on the next engine run -- that is an OFFBOARD and needs a second administrator's approval. It was NOT saved. Re-send with a justification to raise the offboard approval request, or use the Offboard action."
    } elseif ($previewOff) {
        $res['note'] = "$What is an immediate OFFBOARD of '$Upn' and needs approval, but the Approvals surface is disabled (Settings -> Governance preview). It was NOT saved."
    } elseif (-not (Get-Command Add-PimApprovalRequest -ErrorAction SilentlyContinue)) {
        $res['note'] = "$What is an immediate OFFBOARD of '$Upn' and needs approval, but the approval-gate library is not loaded. It was NOT saved."
    } else {
        try {
            $apr = Add-PimApprovalRequest -Requestor "$Requestor" -Action 'offboard' -Target $Upn -Justification $just -Ticket "$Ticket".Trim()
            $res['approvalRaised'] = $true
            $res['approvalId'] = "$($apr.id)"
            $res['note'] = "$What is an immediate OFFBOARD of '$Upn', so it was NOT saved: offboard approval request $($apr.id) was raised instead. A different administrator approves and executes it on the Approvals tab; that stages the disable for commit."
            Write-PimManagerAuditEvent -Action 'approval.request.created' -Target $Upn -After @{ id = "$($apr.id)"; action = 'offboard'; requestor = "$Requestor"; via = $Via; held = $What }
        } catch {
            $res['note'] = "$What is an immediate OFFBOARD of '$Upn' and needs approval; raising the request failed ($($_.Exception.Message)). It was NOT saved."
        }
    }
    return $res
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

    $txResult = Invoke-PimCommitTransaction -Snapshot $snapshot -ApplyScript $apply -RestoreScript $restore -SaveSnapshotScript $save -PruneScript $prune
    # On a MASTER, a committed change to what the publisher ships requests a publish (Request-PimManagerPublishAfterCommit).
    # Here, not at each caller, so every commit path (grid, departments, conformance deploy) is covered. A commit that
    # changed nothing requests nothing (the order-independent row hash). Never fails the commit, which has already landed.
    try {
        $changed = $true
        if (Get-Command Get-PimRowsHash -ErrorAction SilentlyContinue) { $changed = ((Get-PimRowsHash -Rows @($Current.rows)) -ne (Get-PimRowsHash -Rows @($NewRows))) }
        if ($changed -and (Get-Command Request-PimManagerPublishAfterCommit -ErrorAction SilentlyContinue)) { [void](Request-PimManagerPublishAfterCommit -Base $Base) }
    } catch { Write-Warning "  [publish] the commit of $Base landed, but a publish could NOT be requested: $($_.Exception.Message) -- the publish job runs on its own cadence" }
    return $txResult
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
        # IMP-49 a: New-PimCommitSnapshot returns the id as `.id` (only Invoke-PimCommitTransaction's RESULT carries
        # `.snapshotId`), so this used to be blank -- the restore was undoable but never told anyone how.
        $preId = "$($preSnap.id)"
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
    # 2026-09-20: the shipped defaults come from CODE (Get-PimShippedNamingConventions). The
    # config\PIM4EntraPS.NamingConventions.locked.ps1 dot-source is gone -- it was a hand-synced copy of
    # the same values, and sourcing it assigned $global:PIM_NamingConventions wholesale, which is why it
    # needed the save/restore dance on every call. A fresh store is SEEDED with these defaults at
    # Initialize-PimSqlStore, so pim.Settings is the only per-customer home.
    if (Get-Command Get-PimShippedNamingConventions -ErrorAction SilentlyContinue) {
        try {
            $shipped = Get-PimShippedNamingConventions
            if ($shipped -is [System.Collections.IDictionary]) {
                foreach ($k in @($shipped.Keys)) { $defaults[$k] = $shipped[$k] }
            }
        } catch { Write-Warning "  shipped naming defaults unavailable: $($_.Exception.Message)" }
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
# BUG-194: 'sessions-revoked' is raised by POST /api/admin-sessions/revoke; it was missing here, so every such alert
# answered "event disabled" and never fired. A new event defaults ON like the others.
$script:PimAlertEventCatalog = @('engine-failure','drift','expiring-access','break-glass','sessions-revoked')
# REQ-I + REQ-U: NEW gaps / orphans / unmanaged privileged groups found by the scheduler's 'coverage' job (PIM-Coverage.ps1).
$script:PimAlertEventCatalog += 'coverage'

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

function Get-PimStoredAlertField {
    # PURE. One field of a stored alerting config, which is an [ordered] DICTIONARY (Get-PimAlertingConfig)
    # or, from other callers, an object. PSObject.Properties does not see dictionary keys, which made the
    # PUT's "keep the stored webhook" branch silently inert.
    param([AllowNull()]$Config, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Config) { return '' }
    if ($Config -is [System.Collections.IDictionary]) { if ($Config.Contains($Name)) { return "$($Config[$Name])" }; return '' }
    $p = $Config.PSObject.Properties[$Name]
    if ($p) { return "$($p.Value)" }
    return ''
}

function Hide-PimAlertingSecret {
    # PURE (SEC-42). The alerting config as a caller who may NOT change alerting sees it: the webhook
    # URL (a bearer credential for the channel) is removed; webhookSet + a scheme://host hint remain so
    # the screen can still say "a Teams webhook is configured".
    param([Parameter(Mandatory)][object]$Config)
    $out = [ordered]@{}
    foreach ($k in @($Config.Keys)) { $out[$k] = $Config[$k] }
    $u = "$($Config['webhookUrl'])".Trim()
    $hint = ''
    if ($u) { try { $uri = [uri]$u; $hint = "$($uri.Scheme)://$($uri.Host)/..." } catch { $hint = '(set)' } }
    $out['webhookUrl']        = ''
    $out['webhookSet']        = [bool]$u
    $out['webhookUrlHint']    = $hint
    $out['webhookUrlRedacted'] = $true
    return $out
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

      An admin account is a SEPARATE privileged identity with no mailbox of its own. DOC-17 g / §71.19:
      the TAP goes to (1) the per-admin forwarding override (ForwardMailsToContact=TRUE +
      MailForwardAddress) when the row states one, else (2) the owners of the admin's sponsor
      DEPARTMENT -- the department, not a named person, so it survives a reorg -- else (3) ManagerEmail
      as a LEGACY fallback that the screens flag for moving to the department.
    #>
    param([Parameter(Mandatory)][object]$Row)
    # 🔴 DELEGATES TO THE ENGINE'S RULE (Get-PimAdminMailRecipient, engine/_shared/PIM-Rest.ps1).
    # This used to carry its own copy, which IGNORED ForwardMailsToContact -- and the engine mailed
    # ManagerEmail regardless -- so "Sends to" on this screen named an address the engine never
    # used (operator, 2026-09-12). One function now answers for both, so they cannot drift again.
    # 🪤 AN ADDRESS MUST LOOK LIKE ONE: live v1 rows hold 'FALSE'/'true' in MailForwardAddress; the
    # shared rule treats those as no recipient, and the caller refuses and says so.
    if (-not (Get-Command Get-PimAdminMailRecipientPlan -ErrorAction SilentlyContinue)) {
        Write-Warning 'Get-PimAdminTapRecipient: engine/_shared/PIM-Rest.ps1 is not loaded -- no recipient can be resolved, so TAP delivery is refused.'
        return ''
    }
    # 71.19: the sponsor DEPARTMENT's owners, read from this Manager's own store (the engine's index is not loaded here).
    return ((@((Get-PimAdminTapRecipientPlan -Row $Row).recipients)) -join ';')
}

function Get-PimManagerDepartmentOwnerIndex {
    # 71.19: department (lower case) -> Owners string, from the SAME entity the engine reads
    # (PIM-Definitions-Departments; Owners, with the legacy DeptOwner/DepartmentOwner/ManagerEmail spellings).
    # Cached for the process; Reset-PimManagerDepartmentOwnerIndex clears it after a save.
    if ($script:PimMgrDeptOwners -is [hashtable]) { return $script:PimMgrDeptOwners }
    $h = @{}
    try {
        foreach ($r in @((Read-PimRows -BaseName 'PIM-Definitions-Departments' -NoScope).rows)) {
            $n = ''; foreach ($k in @('Department', 'DepartmentName', 'Name')) { $v = "$(Get-PimCell $r $k)".Trim(); if ($v) { $n = $v; break } }
            if (-not $n) { continue }
            $own = ''; foreach ($k in @('Owners', 'DeptOwner', 'DepartmentOwner', 'ManagerEmail')) { $v = "$(Get-PimCell $r $k)".Trim(); if ($v) { $own = $v; break } }
            $h[$n.ToLowerInvariant()] = $own
        }
    } catch { Write-Warning "  [tap] the department owner index could not be read ($($_.Exception.Message)) -- recipients fall back to the per-admin override / legacy ManagerEmail."; return $null }
    $script:PimMgrDeptOwners = $h
    return $h
}
function Reset-PimManagerDepartmentOwnerIndex { $script:PimMgrDeptOwners = $null }

function Get-PimAdminTapRecipientPlan {
    # 71.19: the full answer (recipients + source + why), so the screen can say WHERE it goes and WHY it does not.
    param([Parameter(Mandatory)][object]$Row)
    if (-not (Get-Command Get-PimAdminMailRecipientPlan -ErrorAction SilentlyContinue)) { return [ordered]@{ recipients = @(); recipient = ''; source = 'none'; reason = 'engine/_shared/PIM-Rest.ps1 is not loaded' } }
    $idx = Get-PimManagerDepartmentOwnerIndex
    if ($null -eq $idx) { return (Get-PimAdminMailRecipientPlan -Row $Row) }
    return (Get-PimAdminMailRecipientPlan -Row $Row -DepartmentOwners $idx)
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
function Test-PimManagerIsMspMaster {
    # §71.5 -- the Replication surface exists ONLY on the MSP master (managing tenant). A single tenant has
    # nothing to target and a managed tenant never edits targets (framework MSP-4 SURFACE item 1).
    # Fail CLOSED: an unresolvable scenario is "not the master", which hides and refuses the fields.
    if (Get-Variable -Name PIM_ManagerReplicationMasterOverride -Scope Global -ErrorAction SilentlyContinue) {
        return [bool]$global:PIM_ManagerReplicationMasterOverride
    }
    if (-not (Get-Command Get-PimActiveScenario -ErrorAction SilentlyContinue)) { return $false }
    try { $s = Get-PimActiveScenario; return ("$($s.role)" -eq 'msp-master') } catch { return $false }
}
# ---------------------------------------------------------------------------
# REQ-N / REQ-O (operator 2026-09-19) -- the MSP MASTER's two pages: the managed-tenant REGISTRY and the REPLICATION
# OVERVIEW. The routes (/api/msp/tenants, /api/msp/tenants/{id}, /api/msp/replication/overview) are thin; these
# functions hold the gates, so every path through them is master-only (fail closed, Test-PimManagerIsMspMaster) and
# every write is SuperAdmin-only, audited and read back (Set-PimManagedTenantRegistration, the ONE writer the setup
# script shares). Each returns @{ status; body }.
# ---------------------------------------------------------------------------
function Get-PimManagerMasterTenantId {
    # REQ-N: the tenant this Manager -- the MSP master -- runs in. The registry must never list it as a managed tenant.
    # '' when unknown; the writer then REFUSES (it cannot rule the master's own tenant out).
    $t = "$($global:PIM_TenantId)".Trim()
    if (-not $t) { $t = "$($global:AzureTenantID)".Trim() }
    return $t.ToLowerInvariant()
}
function Get-PimManagerMspTenantsResponse {
    # REQ-N: GET /api/msp/tenants -- every registered managed tenant (enabled and disabled), the master's COPY of its ring
    # (labelled so), its tags, and whether the master's last publish carries it (pim.Settings['PublishLastRun']).
    if (-not (Test-PimManagerIsMspMaster)) {
        return @{ status = 200; body = [ordered]@{ master = $false; available = $false; tenants = @(); reason = 'The managed-tenant registry exists only on the MSP master. This tenant is not the master.' } }
    }
    $lr = $null
    try {
        $key = 'PublishLastRun'
        if (Get-Command Get-PimJobCadenceDefinition -ErrorAction SilentlyContinue) { $key = "$((Get-PimJobCadenceDefinition -Job 'publish').lastRunKey)" }
        $raw = Get-PimManagerSetting -Name $key
        if (Get-Command ConvertFrom-PimJobCadenceJson -ErrorAction SilentlyContinue) { $cv = ConvertFrom-PimJobCadenceJson $raw; if ($cv.ok) { $lr = $cv.value } } else { $lr = $raw }
    } catch { $lr = $null }
    $canWrite = $false
    try { $canWrite = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin') } catch { $canWrite = $false }
    $view = Get-PimMspTenantRegistryView -ConnectionString (Get-PimManagerStoreCs) -LastRun $lr -CanWrite $canWrite -MasterTenantId (Get-PimManagerMasterTenantId)
    return @{ status = 200; body = $view }
}
function ConvertTo-PimManagerMspBool {
    # A JSON body's true/false as sent -- [bool]'false' is $true in PowerShell, so a string is read by its words.
    param([AllowNull()][object]$Value)
    if ($Value -is [bool]) { return $Value }
    return ("$Value".Trim() -match '^(?i:1|true|yes|on)$')
}
function Invoke-PimManagerMspTenantWrite {
    # REQ-N: POST /api/msp/tenants (-Mode Create) and PUT /api/msp/tenants/{id} (-Mode Update). A field the PUT body
    # leaves out keeps its stored value; a POST defaults to ring 2 (the pull job's default) and enabled.
    param([Parameter(Mandatory)][ValidateSet('Create', 'Update')][string]$Mode, [string]$TenantId, [object]$Body)
    if (-not (Test-PimManagerIsMspMaster)) {
        return @{ status = 403; body = [ordered]@{ ok = $false; error = 'The managed-tenant registry exists only on the MSP master. This tenant is not the master.' } }
    }
    if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
        return @{ status = 403; body = [ordered]@{ ok = $false; error = 'SuperAdmin role required to change the managed-tenant registry.' } }
    }
    $has = { param($n) ($null -ne $Body) -and [bool]$Body.PSObject.Properties[$n] }
    $cs = Get-PimManagerStoreCs
    $tid = if ($Mode -eq 'Update') { "$TenantId".Trim() } else { "$(if (& $has 'tenantId') { $Body.tenantId })".Trim() }
    $current = $null
    if ($Mode -eq 'Update') {
        $reg = Get-PimManagedTenantRegistry -ConnectionString $cs
        if ($reg.available) { $current = @(@($reg.tenants) | Where-Object { $_.tenantId -eq $tid.ToLowerInvariant() })[0] }
    }
    $name = if (& $has 'displayName') { "$($Body.displayName)" } elseif ($current) { "$($current.name)" } else { '' }
    $ringIn = if (& $has 'ring') { "$($Body.ring)".Trim() } elseif ($current -and $current.ringKnown) { "$($current.ring)" } else { '2' }
    if ($ringIn -notmatch '^\d{1,3}$') { return @{ status = 400; body = [ordered]@{ ok = $false; error = "Ring '$ringIn' is not a whole number (0, 1 or 2 -- the master's copy of the tenant's own ring)." } } }
    $tags = if (& $has 'tags') { $Body.tags } elseif ($current) { @($current.tags) } else { @() }
    $enabled = if (& $has 'enabled') { ConvertTo-PimManagerMspBool $Body.enabled } elseif ($current) { [bool]$current.enabled } else { $true }
    $wArgs = @{ ConnectionString = $cs; TenantId = $tid; DisplayName = $name; Ring = [int]$ringIn; Tags = $tags; Enabled = [bool]$enabled
                Mode = $Mode; MasterTenantId = (Get-PimManagerMasterTenantId) }
    if (& $has 'notes') { $wArgs['Notes'] = "$($Body.notes)" }
    $action = if ($Mode -eq 'Create') { 'msp.tenant.register' } else { 'msp.tenant.update' }
    $requested = [ordered]@{ tenantId = $tid; displayName = $name; ring = $ringIn; tags = $tags; enabled = [bool]$enabled }
    $w = Set-PimManagedTenantRegistration @wArgs
    if (-not $w.ok) {
        $res = if ([int]$w.status -ge 500) { 'failed' } else { 'refused' }
        try { Write-PimManagerAuditEvent -Action $action -Target $(if ($tid) { $tid } else { '(no tenant id)' }) -Before $w.before -After ([ordered]@{ requested = $requested; reason = "$($w.reason)" }) -Result $res } catch { Write-Warning "  [msp] audit of a refused registry write failed: $($_.Exception.Message)" }
        return @{ status = [int]$w.status; body = [ordered]@{ ok = $false; error = "$($w.reason)" } }
    }
    Write-PimManagerAuditEvent -Action $action -Target "$($w.parameters.tid)" -Before $w.before -After $w.after -Result 'ok'
    if (Get-Command Clear-PimReplicationOverviewCache -ErrorAction SilentlyContinue) { Clear-PimReplicationOverviewCache }
    # The tags (and Enabled) travel IN the signed bundle: a registry change requests a publish (never fails the save).
    $pub = $false
    try { $pub = [bool](Request-PimManagerPublishAfterCommit -Base 'platform.Tenants' -NotAnEntity) } catch { Write-Warning "  [publish] the registry was saved, but a publish could NOT be requested: $($_.Exception.Message)" }
    return @{ status = 200; body = [ordered]@{
        ok = $true; action = "$($w.action)"; tenant = $w.after; before = $w.before; publishRequested = $pub
        note = "Saved and read back. The tags reach the managed tenants in the next signed bundle$(if ($pub) { ' (a publish was requested; it runs within 5 minutes)' } else { '' }). The ring is only the master's copy: the tenant's own ring gates its pull." } }
}
function Get-PimManagerReplicationOverviewResponse {
    # REQ-O: GET /api/msp/replication/overview -- computed SERVER-SIDE by the plan every tenant runs
    # (Get-PimReplicationMasterModel + Get-PimReplicationPreview, laid out by Get-PimReplicationOverview), cached for 30
    # seconds per store (?refresh=1 recomputes). The browser only filters it.
    param([switch]$Refresh)
    if (-not (Test-PimManagerIsMspMaster)) {
        return @{ status = 200; body = [ordered]@{ master = $false; groups = @(); tenants = @(); reason = 'The replication overview exists only on the MSP master. This tenant is not the master.' } }
    }
    $cs = Get-PimManagerStoreCs
    $ov = Get-PimReplicationOverviewCached -CacheKey "$cs" -TtlSeconds 30 -Refresh:$Refresh -Loader {
        $m = Get-PimReplicationMasterModel -ConnectionString $cs
        Get-PimReplicationOverview -Model $m
    }
    return @{ status = 200; body = $ov }
}
function Get-PimManagerReplicationHeader {
    # §71.5 -- the grid header a tenant is shown for one entity. On the master: the full shipped header.
    # Anywhere else: Replicate, Ring and Target are removed on every replicable entity, and ManagementMode on the admin
    # entity (operator 2026-09-15: sync surfaces are MSP-master only). The engine spec is unchanged,
    # so Test-PimEntityFieldCoverage still sees every column the engine reads.
    param([Parameter(Mandatory)][string]$Base, [AllowEmptyCollection()][string[]]$Header = @(), [bool]$IsMaster)
    if ($IsMaster) { return @($Header) }
    if (-not (Get-Command Get-PimReplicationKindForEntity -ErrorAction SilentlyContinue)) { return @($Header) }
    $kind = Get-PimReplicationKindForEntity -Entity $Base
    if (-not $kind) { return @($Header) }
    # Operator 2026-09-15: "not relevant for single mode" -- off the master the admin's sync switch and ring go too.
    $drop = if ($kind -eq 'admin') { @('Replicate', 'Ring', 'Target', 'ManagementMode') } else { @('Replicate', 'Ring', 'Target') }
    return @(@($Header) | Where-Object { $drop -notcontains $_ })
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
        # DOC-17 g: the TAP recipient is the per-admin forwarding override, else the sponsor DEPARTMENT's owners, else legacy ManagerEmail (§71.19, Get-PimAdminTapRecipient).
        $mgr = Get-PimAdminTapRecipient -Row $r
        $hrs = 0; [void][int]::TryParse("$($r.TAPLifetimeHours)", [ref]$hrs); if ($hrs -le 0) { $hrs = 4 }

        # THE FULL MAIL CHECK IS PER ADMIN, ON DEMAND -- NOT IN THE LIST (2026-09-12). Run for every admin it
        # re-read email controls from SQL and rendered the template in a WhatIf send; the Manager serves
        # one request at a time, so once two admins had a real recipient the TAP list hung and an
        # Edit > Save and the Departments load queued behind it. The list checks only what is free;
        # the per-admin Check ($liveCheck) runs the full readiness probe.
        $__rp = Get-PimAdminTapRecipientPlan -Row $r      # 71.19: says WHERE it goes and WHY it does not
        $mailChk = if ($liveCheck) { Test-PimTapMailReady -Recipient $mgr -Reason "$($__rp.reason)" }
                   elseif (-not "$mgr".Trim()) { @{ ok = $false; reason = "$($__rp.reason) -- an admin's mail goes to its SPONSOR DEPARTMENT's owners: set the admin's Department and set Owners on that department (Definitions > Departments)" } }
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
            # 71.19: WHERE the mail goes and WHY -- 'department' (the rule), 'forward' (per-admin override) or
            # 'manager-legacy' (old data; the screen says to move it to the department).
            recipientSource   = "$($__rp.source)"
            recipientReason   = "$($__rp.reason)"
            department        = "$($r.Department)".Trim()
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
            # 🔴 71.25 -- THE POLICY TEMPLATES, so a wizard can OFFER them instead of asking an
            # operator to type an id (operator 2026-09-16: "i think we are missing the default policy
            # for a permission (indirect) delegation in the wizards. I need to be able to select from
            # the available templates for policies including Use default, approval policy template").
            # Same store the ENGINE reads (pim.Settings 'PolicyTemplates'), so the picker can never
            # offer a template the engine would then fail to find.
            # Guarded: this endpoint answers three unrelated questions, and a host where the catalog
            # helper is not loaded must still return the POLICY rather than 500 the whole settings
            # surface. The fallback is the same one the helper itself uses -- 'default' only, never an
            # empty list, because an empty picker reads as "this tenant has no templates".
            policyTemplate      = @(if (Get-Command Get-PimManagerPolicyTemplateCatalog -ErrorAction SilentlyContinue) { Get-PimManagerPolicyTemplateCatalog }
                                    else { [ordered]@{ id = 'Groups_Standard'; label = 'Use default'; hint = 'the tenant baseline'; approval = $false } })
            # REQ-L / §68.6 #37(c): what a BLANK PolicyTemplate resolves to per delegation type (the engine's rule), so the
            # grid can say "[standard settings (<id>)]" instead of "(blank)". Empty when the catalog lib is not loaded.
            # 2026-09-19 ("set default in settings"): resolved from pim.Settings['PolicyTemplateDefaults'] against the store,
            # exactly as the engine resolves it, so every wizard's "Use default (<id>)" names what the engine will apply.
            policyTemplateDefaults = $(if (Get-Command Get-PimManagerPolicyTemplateDefaults -ErrorAction SilentlyContinue) { Get-PimManagerPolicyTemplateDefaults }
                                       elseif (Get-Command Get-PimPolicyTemplateTypeDefaults -ErrorAction SilentlyContinue) { Get-PimPolicyTemplateTypeDefaults } else { [ordered]@{} })
        }
    }
}

function Get-PimManagerPolicyTemplateCatalog {
    <#
      71.25. The policy templates available to a definition row's PolicyTemplate column, as
      @( @{ id; label; hint; approval } ), 'default' first. Read from the SAME place the engine
      reads (pim.Settings 'PolicyTemplates'), never from the shipped files -- a customer may have
      customised or added templates, and offering the shipped set would be confidently wrong.
      `approval` says whether the template carries an Approval rule, so a surface can mark the
      approval-required one without hard-coding its id.
      An unreadable store returns JUST 'default': a picker that silently offers nothing would read
      as "this tenant has no templates", which is a different (and usually wrong) statement.
    #>
    [CmdletBinding()] param()
    $out = New-Object System.Collections.Generic.List[object]
    $map = @{}
    try {
        $raw = Get-PimManagerSetting -Name 'PolicyTemplates'
        if (Get-Command ConvertTo-PimPolicyTemplateMap -ErrorAction SilentlyContinue) { $map = ConvertTo-PimPolicyTemplateMap -Value $raw }
    } catch { $map = @{} }
    # 2026-09-19: the group default first (Groups_Standard, formerly 'default'); an unreadable store offers just it.
    $grpStd = if (Get-Command Resolve-PimPolicyTemplateKey -ErrorAction SilentlyContinue) { Resolve-PimPolicyTemplateKey -Map $map -Id 'Groups_Standard' } else { '' }
    if (-not $grpStd) { $grpStd = 'Groups_Standard' }
    $ids = @(@($map.Keys) | Sort-Object { if ("$_" -eq $grpStd) { 0 } else { 1 } }, { "$_" })
    if (-not $ids.Count) { $ids = @($grpStd) }
    foreach ($id in $ids) {
        $tpl = $map["$id"]
        $rules = $null
        if ($tpl -is [System.Collections.IDictionary]) { $rules = $tpl['rules'] } elseif ($tpl -and $tpl.PSObject.Properties['rules']) { $rules = $tpl.rules }
        $hasApproval = $false
        if ($rules -is [System.Collections.IDictionary]) { $hasApproval = $rules.Contains('Approval') }
        elseif ($rules -and $rules.PSObject.Properties['Approval']) { $hasApproval = $true }
        $desc = ''
        if ($tpl -is [System.Collections.IDictionary]) { $desc = "$($tpl['description'])" } elseif ($tpl -and $tpl.PSObject.Properties['description']) { $desc = "$($tpl.description)" }
        $label = if ("$id" -eq $grpStd) { 'Use default' } else { "$id" }
        $hint  = if ("$desc".Trim()) { "$desc".Trim() } elseif ("$id" -eq $grpStd) { 'the tenant baseline every managed group gets' } elseif ($hasApproval) { 'activation needs approval' } else { '' }
        # REQ-L: `kind` (group | directoryRole | azureRole) lets the grid's PolicyTemplate picker offer only the templates
        # written for the row's type; `name` is the template's own (editable) display name. Additive -- older wizards ignore both.
        $tplKind = ''
        if (Get-Command Get-PimPolicyTemplateKind -ErrorAction SilentlyContinue) { try { $tplKind = Get-PimPolicyTemplateKind -Map $map -Id "$id" } catch { $tplKind = '' } }
        $tplName = ''
        if ($tpl -is [System.Collections.IDictionary]) { $tplName = "$($tpl['name'])" } elseif ($tpl -and $tpl.PSObject.Properties['name']) { $tplName = "$($tpl.name)" }
        # 2026-09-19: the former ids that still resolve to this template ('default' -> Groups_Standard), so a row that
        # stores one shows as this template -- selected, not "not in this tenant's template store".
        $aliases = @(if (Get-Command Get-PimPolicyTemplateAliasNames -ErrorAction SilentlyContinue) { @(Get-PimPolicyTemplateAliasNames "$id") | Where-Object { -not $map.ContainsKey("$_") } })
        [void]$out.Add([ordered]@{ id = "$id"; label = $label; hint = $hint; approval = [bool]$hasApproval; kind = $tplKind; name = $tplName; aliases = @($aliases) })
    }
    return $out.ToArray()
}

function Get-PimManagerPolicyTemplateDefaults {
    <# 2026-09-19 ("set default in settings"): the per-kind DEFAULT template ids as the engine resolves them --
       pim.Settings['PolicyTemplateDefaults'] against the stored templates, else the built-in defaults. #>
    [CmdletBinding()] param()
    $map = @{}; $set = $null
    try { $map = ConvertTo-PimPolicyTemplateMap -Value (Get-PimManagerSetting -Name 'PolicyTemplates') } catch { $map = @{} }
    try { $set = Get-PimManagerSetting -Name 'PolicyTemplateDefaults' } catch { $set = $null }
    if (Get-Command Resolve-PimPolicyTemplateTypeDefaults -ErrorAction SilentlyContinue) {
        return (Resolve-PimPolicyTemplateTypeDefaults -Setting $set -Map $(if ($map.Count) { $map } else { $null })).defaults
    }
    return (Get-PimPolicyTemplateTypeDefaults)
}

function Get-PimManagerPolicyTemplatesPage {
    <#
      REQ-L (operator 2026-09-19: "i dont see the different policies anymore"): the model behind the read-only
      Policy templates page (GET /api/policy-templates). Every template in the tenant's store (pim.Settings
      'PolicyTemplates', the SAME value the engine reads) described in plain words, and which delegations use it.
      Rows are the CALLER's visible slice (Get-PimManagerVisibleSlice, the same slice the grid shows), so a
      Delegated user sees usage only over the groups they own -- `scoped` says so. An unreadable store or entity is
      reported as NOT CHECKED with its reason, never as "no templates" / "unused". Read-only: nothing is written.
    #>
    [CmdletBinding()] param()
    if (-not (Get-Command Get-PimPolicyTemplatesView -ErrorAction SilentlyContinue)) {
        return [ordered]@{ readable = $false; reason = 'The policy-template catalog library is not loaded in this Manager.'; templates = @(); unknownTemplates = @(); notChecked = @() }
    }
    $raw = $null; $storeErr = ''
    try { $raw = Get-PimManagerSetting -Name 'PolicyTemplates' } catch { $storeErr = "$($_.Exception.Message)" }
    $rowsByEntity = @{}; $readErrors = @{}; $scoped = $false
    foreach ($u in @(Get-PimPolicyTemplateUsageEntities)) {
        $e = "$($u.entity)"
        try {
            if (-not $script:PimSqlCs -or -not (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue)) { throw 'the SQL store is not initialised' }
            $stored = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $e)
            $slice = if (Get-Command Get-PimManagerVisibleSlice -ErrorAction SilentlyContinue) { Get-PimManagerVisibleSlice -Base $e -Rows $stored } else { @{ rows = $stored; filtered = $false } }
            if ($slice.filtered) { $scoped = $true }
            $rowsByEntity[$e] = @($slice.rows)
        } catch { $readErrors[$e] = "$($_.Exception.Message)" }
    }
    # 2026-09-19 ("set default in settings"): the per-kind defaults the engine applies to a BLANK PolicyTemplate.
    $defSet = $null
    try { $defSet = Get-PimManagerSetting -Name 'PolicyTemplateDefaults' } catch { }
    $view = Get-PimPolicyTemplatesView -Value $raw -StoreError $storeErr -RowsByEntity $rowsByEntity -ReadErrors $readErrors -DefaultsSetting $defSet
    $view['scoped'] = $scoped
    # Who may rename a template / set the per-kind defaults (SuperAdmin, like every other configuration write).
    $view['canEdit'] = $false
    try { $view['canEdit'] = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin') } catch { $view['canEdit'] = $false }
    # Where editing lives, said on the page (operator rule: every page says what it is for).
    $view['editing'] = 'A template''s RULES are not edited in the Manager. They are stored in this tenant''s SQL store (pim.Settings ''PolicyTemplates''), seeded from the shipped templates when the Manager or the db-init job starts; a shipped template nobody changed follows new versions automatically, and a customised one is kept and flagged here when a newer shipped version exists. A SuperAdmin can RENAME a template here (its display name only -- every delegation points at its id, which never changes, so nothing it governs moves) and choose, per kind of policy, the DEFAULT template a blank PolicyTemplate means. Which template a delegation uses is chosen per delegation: in the delegation wizards, and in the PolicyTemplate column of Delegations -- edit in a table (or All records).'
    return $view
}

function Set-PimManagerPolicyTemplateDefaults {
    <#
      2026-09-19 (operator: "set default in settings"). Persist pim.Settings['PolicyTemplateDefaults'] =
      { group; directoryRole; azureRole } -- the template a BLANK PolicyTemplate means, per kind of policy. Each value is
      '' (= the built-in default, today's behaviour) or a template that is IN the store AND written for that kind
      (Get-PimPolicyTemplateKind); anything else is refused and nothing is written. Stored as the template's ID (the
      immutable key), whatever the caller sent (an id, a name, a former id). Read back after the write.
      Returns @{ before; after; effective } -- effective = what the engine now resolves (setting, else built-in).
    #>
    param([Parameter(Mandatory)][object]$Value)
    $raw = Get-PimManagerSetting -Name 'PolicyTemplates'
    $map = ConvertTo-PimPolicyTemplateMap -Value $raw
    if (-not $map.Count) { throw 'the template store is empty or unreadable -- a default cannot be checked, so nothing was saved' }
    $before = $null; try { $before = Get-PimManagerSetting -Name 'PolicyTemplateDefaults' } catch { }
    $kindWords = @{ group = 'PIM for Groups'; directoryRole = 'Entra ID role'; azureRole = 'Azure resource role' }
    $new = [ordered]@{}
    foreach ($kind in @('group', 'directoryRole', 'azureRole')) {
        $v = ''
        if ($Value -is [System.Collections.IDictionary]) { if ($Value.Contains($kind)) { $v = "$($Value[$kind])".Trim() } }
        elseif ($Value -and $Value.PSObject.Properties[$kind]) { $v = "$($Value.$kind)".Trim() }
        if (-not $v) { $new[$kind] = ''; continue }
        $key = Resolve-PimPolicyTemplateKey -Map $map -Id $v
        if (-not $key) { throw "the $($kindWords[$kind]) default '$v' is not a template in this tenant's store" }
        $tk = Get-PimPolicyTemplateKind -Map $map -Id $key
        if ($tk -ne $kind) { throw "the $($kindWords[$kind]) default '$key' is written for $(Get-PimPolicyTemplateKindLabel $tk), not for $($kindWords[$kind]) policies" }
        $new[$kind] = $key
    }
    Set-PimManagerSetting -Name 'PolicyTemplateDefaults' -Value $new
    $back = Get-PimManagerSetting -Name 'PolicyTemplateDefaults'
    if ($back -is [string]) { $back = $back | ConvertFrom-Json }
    foreach ($kind in @($new.Keys)) {
        $bv = if ($back -is [System.Collections.IDictionary]) { "$($back[$kind])" } else { "$($back.$kind)" }
        if ($bv -ne "$($new[$kind])") { throw "read-back mismatch for the $($kindWords[$kind]) default (wrote '$($new[$kind])', the store holds '$bv')" }
    }
    # Hosted: the engine hydrates pim.Settings on its next run; this process sees it at once too.
    if ($global:PIM_NamingConventions -is [System.Collections.IDictionary]) { $global:PIM_NamingConventions['PolicyTemplateDefaults'] = $new }
    return [ordered]@{ before = $before; after = $new; effective = (Resolve-PimPolicyTemplateTypeDefaults -Setting $new -Map $map).defaults }
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
    # The Manager KNOWS the topology, so pass it: a surface that needs an MSP master resolves OFF and
    # unavailable on a single tenant, and the catalog says so instead of offering a live checkbox
    # (operator 2026-09-20: "should not be possible to select in single domain setup").
    $isMaster = $false
    try { $isMaster = [bool](Test-PimManagerIsMspMaster) } catch { $isMaster = $false }
    $res = Resolve-PimFeatureFlags -Raw $raw -IsMspMaster $isMaster
    $cat = @(Get-PimFeatureFlagCatalog)
    foreach ($c in $cat) {
        $e = $res.effective["$($c.id)"]
        $c['available']         = $(if ($e) { [bool]$e.available } else { $true })
        $c['unavailableReason'] = $(if ($e) { "$($e.unavailableReason)" } else { '' })
    }
    return [ordered]@{
        flags     = $res.flags
        effective = $res.effective
        catalog   = @($cat)
        warnings  = @($res.warnings)
    }
}

function Set-PimFeatureFlags {
    # Persist a (possibly partial / full) flag map. Reduce to the MINIMAL override
    # set (only flags differing from default, never always-on) FIRST, then store
    # under { flags = ... } -- the store never holds always-on or redundant values.
    # Returns the same shape as Get-PimFeatureFlags.
    param([object]$Flags)
    $isMaster = $false
    try { $isMaster = [bool](Test-PimManagerIsMspMaster) } catch { $isMaster = $false }
    $overrides = ConvertTo-PimFeatureFlagOverrides -Raw $Flags -IsMspMaster $isMaster
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

# ---------------------------------------------------------------------------
# THE MSP JOB CADENCE (operator 2026-09-18: "can the pull run every 30 min" ... "i need to be able to control cadence"
# ... "gui must be made to control"). Two jobs are NOT scheduler-tick jobs -- they are their own Container Apps jobs that
# fire every 5 minutes and gate themselves on a cadence stored HERE, in this tenant's own store (engine/_shared/
# PIM-JobCadence.ps1). The cadence is LOCAL, like rings: a managed tenant sets its own pull, a master its own publish.
#   * managed tenant (S6): 'msp-pull'          -> the Data Definition Updater (ca-pim-downlink-s6)
#   * master (msp-master): 'baseline-publish'  -> the signed-baseline publish (ca-pim-publish)
# Stored as DownlinkSchedule / PublishSchedule (NOT in 'JobSchedule': every Jobs-page save persists the tick catalog's
# msp-pull row as enabled=$false / 240 min, which would have switched the pull off). Nothing stored = daily, enabled.
# ---------------------------------------------------------------------------
function Get-PimManagerMspLicenseRole {
    # REQ-Y. 'Master' | 'Slave' | '' (single) -- from the active scenario's role, the same source as the header mode badge
    # (Get-PimScenarioConfig -> Get-PimTenantModeLabel). An unreadable scenario reads as single (S1, the resolver's default).
    $sc = $null
    try { if (Get-Command Get-PimActiveScenario -ErrorAction SilentlyContinue) { $sc = Get-PimActiveScenario } } catch { $sc = $null }
    if (-not $sc) { return '' }
    if ("$($sc.role)" -eq 'msp-master') { return 'Master' }
    if ("$($sc.role)" -eq 'msp-managed') { return 'Slave' }
    return ''
}
function Get-PimManagerLicenseBody {
    # REQ-Y. The GET /api/license body (Get-PimLicenseApiBody, engine/_shared/PIM-License.ps1) for this environment: its
    # tenant ($global:PIM_TenantId) and store server fill the register command. Never throws: a failure is a body with
    # the error, so the Settings section says what went wrong instead of spinning.
    $srv = "$($global:PIM_SqlServer)".Trim(); if (-not $srv) { $srv = "$env:PIM_SqlServer".Trim() }
    $role = Get-PimManagerMspLicenseRole
    # canWrite = may THIS caller register a licence here (PUT /api/license). The card shows the
    # in-GUI Register control only then, so a Reader is never offered a button that would 403.
    $canWrite = $false
    try { $canWrite = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin') } catch { $canWrite = $false }
    try {
        $b = Get-PimLicenseApiBody -MspRole $role -TenantId "$($global:PIM_TenantId)".Trim() -SqlServer $srv
        $b['canWrite'] = $canWrite
        return $b
    }
    catch {
        $why = "the licence could not be read ($($_.Exception.Message))"
        return [ordered]@{ status = 'Invalid'; statusText = $why; reason = $why; mspRequired = [bool]$role
            mspRole = $(if ($role -eq 'Slave') { 'slave' } elseif ($role) { 'master' } else { '' }); mspOk = (-not $role)
            mspState = $(if ($role) { 'refused' } else { 'none' }); mspReason = $(if ($role) { $why } else { '' })
            contact = 'mok@mortenknudsen.net'; canWrite = $canWrite
            command = 'pwsh -File tools\setup\Set-PimLicense.ps1 -LicensePath <file> -SqlServer <server>.database.windows.net -TenantId <tenant> -AdminAppId <app id> -AdminCertThumbprint <thumbprint>' }
    }
}

function Test-PimManagerProFeature {
    <#
      REQ-Y ("Hard, like MSP"). The Manager's refusal for a Pro-only ACTION: $true = licensed (or a free feature), go on.
      $false = it has ALREADY answered 403 { ok:false; pro:true; feature; error:<the licence line naming the contact and the
      register command>; contact; command } -- the caller returns 403. Same check as the engine and the jobs
      (Test-PimFeatureProLicence); never the global switch, no SuperAdmin bypass. Reads stay free: call this on writes.
    #>
    param([Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)]$Response)
    if (-not (Get-Command Test-PimFeatureProLicence -ErrorAction SilentlyContinue)) { return $true }
    $srv = "$($global:PIM_SqlServer)".Trim(); if (-not $srv) { $srv = "$env:PIM_SqlServer".Trim() }
    $pl = $null
    try { $pl = Test-PimFeatureProLicence -Key $Key -TenantId "$($global:PIM_TenantId)".Trim() -SqlServer $srv } catch { $pl = $null }
    if ($pl -and $pl.ok) { return $true }
    $msg = if ($pl) { "$($pl.message)" } else { "this action requires a PIM4EntraPS Pro licence -- the licence check failed. Contact mok@mortenknudsen.net for a licence." }
    try { Write-PimManagerAuditEvent -Action 'license.refused' -Target $Key -After @{ reason = $msg } -Result 'refused' } catch { }
    Write-JsonResponse -Response $Response -Status 403 -Body ([ordered]@{ ok = $false; pro = $true; feature = $Key; error = $msg
        contact = 'mok@mortenknudsen.net'; command = $(if ($pl) { "$($pl.command)" } else { '' }) })
    return $false
}

function Get-PimManagerCadenceJob {
    # '' | 'pull' | 'publish' -- which self-gated job this environment's Job schedule controls.
    $sc = $null
    try { if (Get-Command Get-PimActiveScenario -ErrorAction SilentlyContinue) { $sc = Get-PimActiveScenario } } catch { $sc = $null }
    if (-not $sc -or -not (Get-Command Get-PimJobCadenceDefinition -ErrorAction SilentlyContinue)) { return '' }
    if ("$($sc.id)" -eq 'S6') { return 'pull' }
    if ("$($sc.role)" -eq 'msp-master') { return 'publish' }
    return ''
}
function Get-PimManagerCadenceStatus {
    # What the Job schedule shows for the job: effective cadence + what the job recorded (last run) + next due + Run now.
    # A store that cannot be read is reported (error), never shown as "daily, never run".
    param([Parameter(Mandatory)][ValidateSet('pull', 'publish')][string]$Job)
    $def = Get-PimJobCadenceDefinition -Job $Job
    try {
        $s = Get-PimManagerSetting -Name $def.scheduleKey
        $l = Get-PimManagerSetting -Name $def.lastRunKey
        $r = Get-PimManagerSetting -Name $def.runNowKey
        $st = Get-PimJobCadenceStatus -Job $Job -Schedule $s -LastRun $l -RunNow $r
        $st['error'] = ''
        return $st
    } catch {
        return [ordered]@{ job = $Job; row = $def.row; label = $def.label; plain = $def.plain; jobName = $def.jobName; enabled = $true
                           intervalMinutes = 1440; minIntervalMinutes = 5; maxIntervalMinutes = 1440; triggerMinutes = 5; source = 'unknown'
                           lastRun = $null; nextDueText = ''; runNowPending = $false; error = "the cadence could not be read from the store: $($_.Exception.Message)" }
    }
}
function Get-PimManagerActorName {
    try { $r = Get-PimManagerRole; if ("$($r.identity)".Trim()) { return "$($r.identity)" } } catch { }
    return 'unknown'
}
function Request-PimManagerCadenceRun {
    # Set the job's Run now flag (the job runs on its next trigger, within 5 minutes). Returns the flag written.
    param([Parameter(Mandatory)][ValidateSet('pull', 'publish')][string]$Job, [string]$Reason = 'Run now', [string]$By = '')
    $def = Get-PimJobCadenceDefinition -Job $Job
    $v = New-PimJobCadenceRunNowValue -By $(if ("$By".Trim()) { $By } else { Get-PimManagerActorName }) -Reason $Reason
    Set-PimManagerSetting -Name $def.runNowKey -Value $v
    return $v
}
function Request-PimManagerPublishAfterCommit {
    <#
      On a MASTER, a commit that changed an entity the publisher ships (Get-PimBaselinePublishedEntities -- the producer's
      own list) requests a publish: the publish job then runs on its next trigger (within 5 minutes) instead of waiting for
      its cadence, so managed tenants get the change on THEIR next pull. It never publishes itself (the job signs + verifies),
      and it does nothing when publishing is DISABLED in the Job schedule -- disabled means disabled. Several commits
      inside one trigger window coalesce into one publish. Returns $true when the flag was set.
    #>
    param([Parameter(Mandatory)][string]$Base,
          # For a published input that is not a pim.Rows entity (the per-relationship projection policy).
          [switch]$NotAnEntity)
    if ((Get-PimManagerCadenceJob) -ne 'publish') { return $false }
    if (-not $NotAnEntity -and -not (Test-PimBaselinePublishedEntity -Entity $Base)) { return $false }
    $def = Get-PimJobCadenceDefinition -Job 'publish'
    $sched = Resolve-PimJobCadenceSchedule -Stored (Get-PimManagerSetting -Name $def.scheduleKey)
    if (-not $sched.enabled) { Write-Host "[manager] commit:$Base changes the published baseline, but publishing is DISABLED in the Job schedule -- no publish requested" -ForegroundColor Yellow; return $false }
    [void](Request-PimManagerCadenceRun -Job 'publish' -Reason "commit:$Base")
    Write-Host "[manager] commit:$Base changes the published baseline -- publish requested (the publish job runs within 5 minutes)" -ForegroundColor Cyan
    return $true
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
function Merge-PimManagerDepartmentRows {
    <#
      PURE (BUG-177). The department rows to store after a Settings save / import:
        * a supplied department that already has a row -> THAT row, with only Department / Owners / Contact /
          Notes replaced -- GroupName, GroupTag, AdministrativeUnitTag, IsRoleAssignable, Replicate, Ring,
          Target and every other column are carried over untouched;
        * a renamed department (-Renames @{from;to}) -> the FROM row carried over under the new name;
        * a new department -> a new row with the four fields (as before);
        * an existing department NOT supplied -> kept with -PreserveMissing (imports), dropped otherwise (the
          Settings list is the full list; removing one there deletes it). A renamed-from row is always dropped;
        * a row that has no department name at all is never touched (the Settings screen cannot see it).
      Matching is case-insensitive on Department / DepartmentName / Name, like Get-PimManagerDepartments.
    #>
    param(
        [AllowEmptyCollection()][object[]]$Current = @(),
        [AllowEmptyCollection()][object[]]$Departments = @(),
        [switch]$PreserveMissing,
        [AllowEmptyCollection()][object[]]$Renames = @()
    )
    $nameOf = {
        param($r)
        foreach ($k in @('Department', 'DepartmentName', 'Name')) {
            $v = ''
            if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($k)) { $v = "$($r[$k])".Trim() } }
            elseif ($r.PSObject.Properties[$k]) { $v = "$($r.PSObject.Properties[$k].Value)".Trim() }
            if ($v) { return $v }
        }
        return ''
    }
    $toOrdered = {
        param($r)
        $o = [ordered]@{}
        if ($r -is [System.Collections.IDictionary]) { foreach ($k in @($r.Keys)) { $o["$k"] = $r[$k] } }
        else { foreach ($p in $r.PSObject.Properties) { $o[$p.Name] = $p.Value } }
        return $o
    }
    $byName = [ordered]@{}
    $unnamed = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Current)) {
        if ($null -eq $r) { continue }
        $n = & $nameOf $r
        if (-not $n) { $unnamed.Add($r); continue }
        $k = $n.ToLowerInvariant()
        if (-not $byName.Contains($k)) { $byName[$k] = $r } else { $unnamed.Add($r) }   # a duplicate name is kept as-is
    }
    $renameFrom = @{}
    foreach ($rn in @($Renames)) {
        if ($null -eq $rn) { continue }
        $f = "$($rn.from)".Trim(); $t = "$($rn.to)".Trim()
        if ($f -and $t -and $f.ToLowerInvariant() -ne $t.ToLowerInvariant()) { $renameFrom[$t.ToLowerInvariant()] = $f.ToLowerInvariant() }
    }
    $used = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($d in @($Departments)) {
        if ($null -eq $d) { continue }
        $n = & $nameOf $d
        if (-not $n) { continue }
        $k = $n.ToLowerInvariant()
        $baseRow = $null
        if ($byName.Contains($k)) { $baseRow = $byName[$k]; $used[$k] = $true }
        elseif ($renameFrom.ContainsKey($k) -and $byName.Contains($renameFrom[$k])) { $baseRow = $byName[$renameFrom[$k]]; $used[$renameFrom[$k]] = $true }
        $row = if ($null -ne $baseRow) { & $toOrdered $baseRow } else { [ordered]@{} }
        $row['Department'] = $n
        foreach ($f in @('Owners', 'Contact', 'Notes')) {
            $v = ''
            if ($d -is [System.Collections.IDictionary]) { if ($d.Contains($f)) { $v = "$($d[$f])" } }
            elseif ($d.PSObject.Properties[$f]) { $v = "$($d.PSObject.Properties[$f].Value)" }
            $row[$f] = $v
        }
        $out.Add([pscustomobject]$row)
    }
    $renamedAway = @{}
    foreach ($t in @($renameFrom.Keys)) { $renamedAway[$renameFrom[$t]] = $true }
    if ($PreserveMissing) {
        foreach ($k in @($byName.Keys)) {
            if ($used.ContainsKey($k) -or $renamedAway.ContainsKey($k)) { continue }
            $out.Add($byName[$k])
        }
    }
    foreach ($u in $unnamed) { $out.Add($u) }
    return ,($out.ToArray())
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
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Departments,
        # Imports pass this: a department the import did not name is KEPT (the Settings screen's full-list save
        # does not -- removing a department there is how it is deleted).
        [switch]$PreserveMissing,
        # @{ from; to } pairs (Import-PimApproversFromCsv): the renamed department keeps its definition row.
        [object[]]$Renames = @(),
        # The operator's acknowledgement for the empty-set / large-delta guard.
        [switch]$Confirm
    )

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
    # 🔴 BUG-177 -- MERGE, DO NOT REPLACE. Departments are DIRECT GROUPS (§70.22): their definition rows carry
    # GroupName, GroupTag, AdministrativeUnitTag, IsRoleAssignable, ... Replicate, Ring and Target. This used to
    # full-set replace the entity with rows of only {Department, Owners, Contact, Notes}, so one Settings save
    # (or an import) silently stripped every definition column -- including the ring and the replication target
    # -- with no snapshot, no delta guard and no audit row. Now the four fields are merged into the EXISTING
    # rows (every other column preserved), and the write goes through the safe-commit path.
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
    $snapshotId = ''
    $deptBase = 'PIM-Definitions-Departments'
    if ($cs -and (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue) -and (Get-Command Set-PimSqlEntityRowsTransactional -ErrorAction SilentlyContinue)) {
        try {
            $curRows = @(Get-PimSqlRows -ConnectionString $cs -Entity $deptBase)
            # Assign, THEN wrap: the merger returns its array as ONE object (,$arr), so @(<call>) would nest it.
            $merged = Merge-PimManagerDepartmentRows -Current $curRows -Departments $rows -PreserveMissing:$PreserveMissing -Renames @($Renames)
            $merged = @($merged)
            $ddiff = Compare-PimRowSets -Before $curRows -After $merged -Base $deptBase
            if (Get-Command Test-PimCommitDeltaGuard -ErrorAction SilentlyContinue) {
                $dg = Test-PimCommitDeltaGuard -BeforeCount $curRows.Count -AfterCount $merged.Count -RemoveCount (@($ddiff.removes).Count) -Confirm:$Confirm
                if (-not $dg.allowed) {
                    # Nothing written to EITHER store: the guard's refusal must not be half-applied.
                    return @{ ok = $false; count = 0; confirmRequired = $true; gate = "$($dg.rule)"; removeCount = [int]$dg.removeCount
                              error = "departments were NOT saved: $($dg.reason)" }
                }
            }
            $dspec = Get-PimCsvSpec -BaseName $deptBase
            $prevCs = $script:PimSqlCs
            if (-not "$($script:PimSqlCs)".Trim()) { $script:PimSqlCs = $cs }
            try {
                $cres = Invoke-PimManagerSafeCommit -Base $deptBase -NewRows $merged -Current @{ rows = $curRows; header = $(if ($dspec) { @($dspec.defaultHeader) } else { @() }) } -SqlMode $true
            } finally { $script:PimSqlCs = $prevCs }
            $snapshotId = "$($cres.snapshotId)"
            $entityOk = $true
            Write-PimMutationLog -BaseName $deptBase -Adds @($ddiff.adds).Count -Removes @($ddiff.removes).Count -Modifies @($ddiff.modifies).Count `
                -NewRowCount $merged.Count -Diff $ddiff -Summary ("departments saved from Settings: {0} added, {1} removed, {2} changed (other definition columns preserved)" -f @($ddiff.adds).Count, @($ddiff.removes).Count, @($ddiff.modifies).Count)
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
              entityWritten = $entityOk; entityError = $entityErr; snapshotId = $snapshotId
              note = $(if ($entityOk) { 'Saved to PIM-Definitions-Departments (the store the engine reads).' }
                       else { "Saved, but NOT to the engine's store: $entityErr" }) }
}

function Get-PimManagerApprovers {
    # The RETIRED Approvers directory (REQ-D, 2026-09-19): READ-ONLY. Nothing consumed it; it is still returned so the
    # Departments & owners page can show the stored names once. PUT /api/settings/approvers answers 410.
    # Each: @{ identity; displayName; role; notes }.
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

# ---------------------------------------------------------------------------
# REQ-T (2.4.377) -- THIS TENANT'S VERIFIED DOMAINS, for the "Admin account domain" setting and the
# admin wizard's suffix. Same shape as the tenant name above: a live Graph /domains read when a tenant
# connection exists (refreshing pim.TenantCache kind 'tenant-domains'), else the cached list, else
# known=$false -- and the caller then REFUSES to save a domain it cannot verify, never guesses one.
# ---------------------------------------------------------------------------
function ConvertTo-PimTenantDomainList {
    # PURE. Graph hands the same list back in two shapes -- /domains rows (name in 'id', with an
    # 'isVerified' flag) and organization.verifiedDomains entries (name in 'name', verified by
    # definition) -- so normalise both to ONE shape here: lower-cased, de-duplicated, unverified
    # dropped, default first then alphabetical. No Graph, no store: this is the piece a test can drive.
    param([object[]]$Rows, [string]$NameProperty = 'id')
    $seen = @{}
    $out  = @()
    # 🪤 FLATTEN FIRST. A caller can hand us a row that is ITSELF a collection -- `/organization`
    # returns verifiedDomains as an array per organization, and that array does not always arrive
    # unrolled. PowerShell then MEMBER-ENUMERATES it: `$r.name` on an array yields EVERY name, and
    # "$(...)" joins them with spaces. The result is ONE entry called
    # "a.com b.com c.com ..." -- which is exactly what shipped in 2.4.382: the Settings page read
    # "1 verified domain read live from Entra ID" and offered the whole tenant as a single option.
    # Flattening one level costs nothing and makes the shape of the input irrelevant.
    $flat = New-Object System.Collections.Generic.List[object]
    foreach ($r0 in @($Rows)) {
        if ($null -eq $r0) { continue }
        if ($r0 -is [System.Collections.IEnumerable] -and $r0 -isnot [string] -and $r0 -isnot [System.Collections.IDictionary]) {
            foreach ($inner in $r0) { if ($null -ne $inner) { [void]$flat.Add($inner) } }
        } else { [void]$flat.Add($r0) }
    }
    foreach ($r in $flat) {
        if (-not $r) { continue }
        $n = "$($r.$NameProperty)".Trim().TrimStart('@').ToLowerInvariant()
        if (-not $n) { continue }
        # 🔒 A DNS name can never contain whitespace, so whitespace here is PROOF that a collection
        # collapsed into one string rather than a real domain. Drop it: a bad entry that is silently
        # kept becomes a selectable option that can never resolve, and (worse) the tenant's only one.
        if ($n -match '\s') { continue }
        # 'isVerified' exists on /domains only. Absent = verifiedDomains = verified. Never treat a
        # missing property as unverified -- that would silently empty the list for the /organization source.
        $hasVerified = if ($r -is [System.Collections.IDictionary]) { $r.Contains('isVerified') }
                       else { [bool]($r.PSObject.Properties['isVerified']) }
        if ($hasVerified -and -not $r.isVerified) { continue }
        if ($seen.ContainsKey($n)) { continue }
        $seen[$n] = $true
        $out += , ([ordered]@{ id = $n; isDefault = [bool]$r.isDefault; isInitial = [bool]$r.isInitial })
    }
    return @(@($out) | Sort-Object @{ Expression = { -not $_.isDefault } }, @{ Expression = { $_.id } })
}

function Get-PimTenantDefaultDomain {
    # PURE. THE one default domain of a list -- ALWAYS a single string, never a join and never $null.
    # 🪤 2026-09-20: "Admin account domain" rendered every domain run together, because the default was
    #    picked inline inside a "$(...)" and an array that got there interpolated as a space-joined string.
    #    The pick lives here now, once, and a caller cannot get a list back by mistake.
    # Entra marks exactly one domain default, but never depend on it: fall back to the .onmicrosoft.com
    # initial domain, then the first entry, so a list ALWAYS yields a usable answer.
    param([object[]]$Domains)
    $d = @(@($Domains) | Where-Object { $_ -and $_.isDefault }) | Select-Object -First 1
    if (-not $d) { $d = @(@($Domains) | Where-Object { $_ -and $_.isInitial }) | Select-Object -First 1 }
    if (-not $d) { $d = @(@($Domains) | Where-Object { $_ }) | Select-Object -First 1 }
    if (-not $d) { return '' }
    return "$($d.id)"
}

function Get-PimManagerTenantDomains {
    $haveCache = [bool](Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue)
    $reason = ''
    $canQuery = $script:PimManagerTenantConnected -or
                ((Get-Command Test-PimRestTenantAuthAvailable -ErrorAction SilentlyContinue) -and (Test-PimRestTenantAuthAvailable))
    if (-not $canQuery) { $reason = 'this Manager process has no tenant connection' }
    elseif (-not (Get-Command Invoke-PimGraphGetAll -ErrorAction SilentlyContinue)) { $reason = 'the Graph client is not loaded in this process' }
    if ($canQuery -and (Get-Command Invoke-PimGraphGetAll -ErrorAction SilentlyContinue)) {
        $list = @()
        # (a) /domains -- the whole list, but it needs Domain.Read.All.
        try {
            $rows = @(Invoke-PimGraphGetAll -Uri 'https://graph.microsoft.com/v1.0/domains?$select=id,isDefault,isInitial,isVerified')
            $list = @(ConvertTo-PimTenantDomainList -Rows $rows -NameProperty 'id')
            if (-not $list.Count) { $reason = 'Graph /domains returned no verified domain' }
        } catch { $reason = "Graph /domains: $($_.Exception.Message)"; Write-Verbose "tenant-domains /domains read skipped: $($_.Exception.Message)" }
        # (b) THE SAME LIST off the organization object -- verifiedDomains[] -- which the Manager already
        #     reads for the tenant name, so it works on the permissions we know this process has
        #     (Organization.Read.All / Directory.Read.All) rather than needing Domain.Read.All as well.
        #     🔴 Operator 2026-09-20 ("i must be able to select it ... from a list"): with only source (a),
        #     a tenant whose app is not consented Domain.Read.All got an EMPTY dropdown -- one option,
        #     "Tenant default domain", nothing to choose. A second source is the difference between a
        #     list and no list, and it costs one call that already succeeds elsewhere on this page.
        if (-not $list.Count) {
            try {
                $orgs = @(Invoke-PimGraphGetAll -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains')
                $vd   = @(@($orgs) | ForEach-Object { $_.verifiedDomains } | Where-Object { $_ })
                $list = @(ConvertTo-PimTenantDomainList -Rows $vd -NameProperty 'name')
                if ($list.Count) { $reason = '' } elseif (-not $reason) { $reason = 'Graph /organization carried no verifiedDomains' }
            } catch { if (-not $reason) { $reason = "Graph /organization: $($_.Exception.Message)" } }
        }
        if ($list.Count) {
            $val = [ordered]@{ domains = @($list); refreshedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
            if ($haveCache) { try { [void](Set-PimTenantCacheEntry -Kind 'tenant-domains' -Value $val) } catch { Write-Verbose "tenant-domains cache write skipped: $($_.Exception.Message)" } }
            return [ordered]@{ known = $true; source = 'live'; domains = @($list); refreshedUtc = $val.refreshedUtc; reason = '' }
        }
    }
    if ($haveCache) {
        try {
            $c = Get-PimTenantCacheEntry -Kind 'tenant-domains'
            $cv = if ($c -and $c.PSObject.Properties['value']) { $c.value } else { $c }
            if ($cv -and @($cv.domains).Count) {
                return [ordered]@{ known = $true; source = 'cache'; domains = @(ConvertTo-PimTenantDomainList -Rows @($cv.domains) -NameProperty 'id'); refreshedUtc = "$($cv.refreshedUtc)"; reason = '' }
            }
        } catch { if (-not $reason) { $reason = "the cached domain list could not be read: $($_.Exception.Message)" } }
    }
    return [ordered]@{ known = $false; source = 'none'; domains = @(); refreshedUtc = ''; reason = $(if ($reason) { $reason } else { 'no source returned a verified domain' }) }
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

    # ---- 1b. 🔴 IMP-33 -- privileged accounts in the directory with NO desired-state row --------
    # Measured on EFIF 2026-09-18: six real admin accounts were unmanaged (no TAP healing, reminders or review)
    # and nothing in the Manager said so. The ENGINE classifies them on every Admins pass and stores the result
    # (pim.Settings 'UnmanagedAdmins'); this tile only reads it -- no Graph call on the overview (§67).
    try {
        $uaRec = $null
        if ($script:PimSqlCs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
            $uaRec = Get-PimSqlSetting -ConnectionString $script:PimSqlCs -Name 'UnmanagedAdmins'
        }
        $tiles.unmanagedAdmins = if (Get-Command Get-PimUnmanagedAdminTile -ErrorAction SilentlyContinue) { Get-PimUnmanagedAdminTile -Record $uaRec }
                                 else { [ordered]@{ ok = $false; error = 'the unmanaged-admin report library (PIM-UnmanagedAdmins.ps1) is not loaded in this Manager' } }
    } catch { $tiles.unmanagedAdmins = [ordered]@{ ok = $false; error = "$($_.Exception.Message)" } }

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
            $status = if ($failed.Count -gt 0) { 'red' } elseif (@($jobs | Where-Object { $_.needsApproval }).Count -gt 0) { 'amber' } elseif ($histCount -eq 0) { 'unknown' } else { 'green' }
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
                # 71.13: a standing policy HOLD needs an approval -- amber attention, never counted as failed.
                heldCount     = @($jobs | Where-Object { $_.needsApproval }).Count
                heldJobs      = @($jobs | Where-Object { $_.needsApproval } | ForEach-Object { [ordered]@{ name = "$($_.name)"; type = "$($_.type)"; scope = "$($_.scope)"; detail = "$($_.heldDetail)"; runId = "$($_.lastRunId)" } } | Select-Object -First 12)
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

    # ---- 4a. Break-glass ACCOUNT list: a change awaiting a second SuperAdmin (maker/checker) -- FAST (one SQL row).
    # Shown whatever the approvalsPreview flag says: this gate is always on, and so is its visibility.
    try {
        if ("$($script:PimSqlCs)".Trim() -and (Get-Command Get-PimBreakGlassChangeRequest -ErrorAction SilentlyContinue)) {
            $bgv = Get-PimManagerBreakGlassRequestView
            if ($bgv -and $bgv.open) {
                $tiles.breakGlassChange = [ordered]@{ ok = $true; open = $true; maker = "$($bgv.maker)"; expiresUtc = "$($bgv.expiresUtc)"
                    added = @($bgv.added).Count; removed = @($bgv.removed).Count; isMaker = [bool]$bgv.isMaker; canApprove = [bool]$bgv.canApprove; onlySuperAdmin = [bool]$bgv.onlySuperAdmin }
            } else { $tiles.breakGlassChange = [ordered]@{ ok = $true; open = $false } }
        } else { $tiles.breakGlassChange = [ordered]@{ ok = $true; open = $false } }
    } catch {
        $tiles.breakGlassChange = [ordered]@{ ok = $false; open = $false; error = "$($_.Exception.Message)" }
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
            # 🔴 BUG-195: no SEEDED sample rows on a live environment. This tile used to count the seed's
            # "pending" reviews whenever the live read returned nothing, so a tenant with no reviews showed pending
            # work that did not exist. A failed read is now reported as a failed read; an empty tenant is zero.
            $rows = @(); $arSource = 'unavailable'; $arErr = ''
            if (Get-Command Get-PimAccessReviewOverview -ErrorAction SilentlyContinue) {
                try { Initialize-PimManagerTenantConnection; $rows = @(Get-PimAccessReviewOverview -IncludeDecisionCounts); $arSource = 'live' } catch { $arErr = "$($_.Exception.Message)" }
            } else { $arErr = 'access-review library not loaded' }
            $pending = @($rows | Where-Object { "$($_.Status)" -match '(?i)progress|pending|active|inprogress' })
            if ($arSource -eq 'live') { $tiles.accessReviews = [ordered]@{ ok = $true; source = 'live'; total = $rows.Count; pending = $pending.Count } }
            else { $tiles.accessReviews = [ordered]@{ ok = $false; source = 'unavailable'; total = 0; pending = 0; error = "access reviews could not be read: $arErr" } }
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

function ConvertTo-PimScriptSafeJson {
    # PURE (SEC-29). Make a JSON text safe to embed in an inline <script>: '<' '>' '&' and U+2028/U+2029
    # become \uXXXX escapes. In valid JSON those characters can only occur inside string literals, where
    # the escape means exactly the same character -- so the parsed value is identical, but the text can no
    # longer close the script element (`</script>`), open a comment (`<!--`) or end a JS line. Works the
    # same on Windows PowerShell 5.1 (no -EscapeHandling there) and pwsh 7.
    param([AllowNull()][AllowEmptyString()][string]$Json)
    if ($null -eq $Json -or -not "$Json".Trim()) { return 'null' }
    # The escapes are built as ('\' + 'u003c') so no editor or tool ever turns them back into the raw character.
    $bs = [string][char]92
    return $Json.Replace('<', ($bs + 'u003c')).Replace('>', ($bs + 'u003e')).Replace('&', ($bs + 'u0026')).Replace([string][char]0x2028, ($bs + 'u2028')).Replace([string][char]0x2029, ($bs + 'u2029'))
}

function Expand-PimBootTemplate {
    # PURE (SEC-29). Fill the __PIM_*__ placeholders in ONE regex pass. The old chained String.Replace
    # re-scanned text it had just inserted, so a stored value containing e.g. '__PIM_ROLE__' was itself
    # replaced by raw JSON -- inside a JS string literal, which breaks out of it. Unknown placeholders
    # (test-harness markers such as __PIM_AUTHORING_HELPERS_START__) are left exactly as they are.
    param([Parameter(Mandatory)][string]$Html, [Parameter(Mandatory)][hashtable]$Values)
    $vals = $Values
    $sb = {
        param($m)
        if ($vals.ContainsKey($m.Value)) { return "$($vals[$m.Value])" }
        return $m.Value
    }.GetNewClosure()
    $eval = [System.Text.RegularExpressions.MatchEvaluator]$sb
    return [regex]::Replace($Html, '__PIM_[A-Z_]+__', $eval)
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
# REQ-I + REQ-U -- the Coverage & gaps page. The report is computed ONLY by the scheduler (job 'coverage', default every
# 720 min) and stored in SQL pim.TenantCache kind 'coverage-report'; the Manager reads that row and nothing else.
# ---------------------------------------------------------------------------
function Get-PimCoverageCadenceMinutes {
    # The EFFECTIVE cadence of job 'coverage' (editable on the Jobs page). Store read only.
    $cad = 0
    try {
        $j = @(Get-PimManagerEffectiveSchedule | Where-Object { "$($_.type)" -eq 'coverage' }) | Select-Object -First 1
        if ($j -and [int]$j.intervalMinutes -gt 0) { $cad = [int]$j.intervalMinutes }
    } catch { }
    return $cad
}

function Get-PimCoverageCached {
    # GET /api/coverage: the stored report shaped for the page (ConvertTo-PimCoverageView). -QueueRefresh queues a 'coverage'
    # trigger (Request-PimCoverageRefresh, read back) and returns at once -- the Manager never computes the report.
    param([switch]$QueueRefresh, [string]$Reason = 'manager', [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Get-Command ConvertTo-PimCoverageView -ErrorAction SilentlyContinue)) {
        throw 'engine/_shared/PIM-Coverage.ps1 is not loaded -- the coverage report cannot be read.'
    }
    $entry = $null
    if (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue) { $entry = Get-PimTenantCacheEntry -Kind 'coverage-report' }
    $queued = $false; $qErr = ''
    if ($QueueRefresh) {
        $q = Request-PimCoverageRefresh -Reason $Reason
        $queued = [bool]$q.queued; $qErr = "$($q.error)"
    }
    return (ConvertTo-PimCoverageView -Entry $entry -NowUtc $NowUtc -CadenceMinutes (Get-PimCoverageCadenceMinutes) -RefreshQueued $queued -QueueError $qErr)
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

# ---------------------------------------------------------------------------
# Break-glass MAKER/CHECKER -- the Manager's view of the pending change request (PIM-BreakGlassChange.ps1).
# The IDENTITY decisions (maker != checker) are the library's; this adds what THIS caller may do and whether
# anybody else could approve at all -- counted from the SuperAdmins the Manager itself grants (SQL ManagerAccess
# + env PIM_SuperAdmins, the two sources Get-PimManagerRole reads).
# ---------------------------------------------------------------------------
function Get-PimManagerBreakGlassCheckers {
    param([string]$Maker)
    $ma = $null
    try {
        if ($script:PimSqlCs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) { $ma = Get-PimSqlSetting -ConnectionString $script:PimSqlCs -Name 'ManagerAccess' }
        elseif ($global:PIM_NamingConventions -is [hashtable] -and $global:PIM_NamingConventions.ContainsKey('ManagerAccess')) { $ma = $global:PIM_NamingConventions['ManagerAccess'] }
    } catch { $ma = $null }
    return @(Get-PimBreakGlassCheckerCandidates -AccessModel $ma -EnvSuperAdmins "$env:PIM_SuperAdmins" -Maker $Maker)
}

function ConvertTo-PimManagerBreakGlassRequestView {
    param([AllowNull()][object]$Request)
    if ($null -eq $Request) { return $null }
    $r = ConvertTo-PimBreakGlassChangeRecord -Value $Request
    $role = Get-PimManagerRole
    $me = "$($role.identity)"
    $isSuper = ("$($role.role)" -eq 'SuperAdmin')
    $open = [bool](Test-PimBreakGlassChangeOpen -Request $r)
    $isMaker = ((ConvertTo-PimBreakGlassIdentityKey -Identity $me) -eq (ConvertTo-PimBreakGlassIdentityKey -Identity $r.maker))
    $others = @()
    if ($open) { $others = @(Get-PimManagerBreakGlassCheckers -Maker $r.maker) }
    $only = [bool]($open -and $others.Count -eq 0)
    $onlyNote = ''
    if ($only) {
        $onlyNote = ('No other SuperAdmin is configured, so nobody can approve this request in the Manager. Grant a second SuperAdmin ' +
                     '(tools/setup/Set-PimManagerAccess.ps1), or use the out-of-band operator route on a host with store access: ' +
                     'tools/setup/Set-PimBreakGlassAccounts.ps1 (audited as setup). This request then expires unapproved.')
    }
    return [ordered]@{
        id = $r.id; status = $r.status; open = $open
        maker = $r.maker; justification = $r.justification; createdUtc = $r.createdUtc; expiresUtc = $r.expiresUtc
        added = @($r.added); removed = @($r.removed); proposed = @($r.proposed); snapshot = @($r.snapshot); confirmEmpty = [bool]$r.confirmEmpty
        checker = $r.checker; decidedUtc = $r.decidedUtc; closedBy = $r.closedBy; closedUtc = $r.closedUtc; closeNote = $r.closeNote; applied = @($r.applied)
        isMaker = [bool]$isMaker
        canApprove = [bool]($open -and $isSuper -and -not $isMaker)
        canReject  = [bool]($open -and $isSuper -and -not $isMaker)
        canCancel  = [bool]($open -and $isSuper -and $isMaker)
        otherSuperAdmins = [int]$others.Count
        onlySuperAdmin = $only; onlySuperAdminNote = $onlyNote
    }
}

function Get-PimManagerBreakGlassRequestView {
    # The current request (lazy expiry recorded + audited once), shaped for the GUI. THROWS on a store failure.
    $g = Get-PimBreakGlassChangeRequest -ConnectionString "$($script:PimSqlCs)"
    if ($g.expiredNow -and $g.request) {
        Write-PimManagerAuditEvent -Action 'settings.breakglass-accounts.expired' -Target 'settings:breakglass-accounts' `
            -After @{ requestId = "$($g.request.id)"; maker = "$($g.request.maker)"; expiresUtc = "$($g.request.expiresUtc)" } -Result 'ok'
    }
    return (ConvertTo-PimManagerBreakGlassRequestView -Request $g.request)
}

# Break-glass / emergency principals to NEVER auto-revoke. Identifiers may be
# UPNs and/or object (principal) ids; matching is case-insensitive. Returns a
# lowercase string[] (possibly empty).
# 🔴 IMP-39: sourced from SQL pim.Settings['BreakGlassAccounts'] (PIM-BreakGlassAccounts.ps1) UNIONED with the
# legacy $global:PIM_BreakGlassAccounts / env PIM_BREAKGLASS_ACCOUNTS, the same list the engine guards read -- so
# the Manager's revoke exclusion and the tick's disable/offboard guards can no longer disagree. A configured store
# that cannot be read FAILS SAFE: the unreadable marker is returned and Test-PimRowIsBreakGlass protects every row.
# This definition deliberately replaces the lib's (it is defined later in this script) only to bind THIS
# Manager's store; the decision is the lib's.
function Get-PimBreakGlassIdentifiers {
    if (Get-Command Get-PimBreakGlassAccountStatus -ErrorAction SilentlyContinue) {
        $s = Get-PimBreakGlassAccountStatus -ConnectionString "$($script:PimSqlCs)"
        if ($s.storeConfigured -and -not $s.storeOk) {
            Write-Warning ("  [break-glass] the break-glass account list is UNREADABLE ({0}) -- treating EVERY account as break-glass." -f $s.error)
            $marker = if (Get-Command Get-PimBreakGlassUnreadableMarker -ErrorAction SilentlyContinue) { Get-PimBreakGlassUnreadableMarker } else { '<break-glass-list-unreadable>' }
            return @(@($s.accounts) + @($marker))
        }
        return @($s.accounts)
    }
    $raw = $global:PIM_BreakGlassAccounts
    if (-not $raw -and "$env:PIM_BREAKGLASS_ACCOUNTS") { $raw = "$env:PIM_BREAKGLASS_ACCOUNTS" }
    if (-not $raw) { return @() }
    $list = if ($raw -is [string]) { $raw -split '[;,]' } else { @($raw) }
    return @($list | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
}

# Decide whether a single revoke row targets a protected break-glass principal.
# Matches the row's principalId (object id) OR principal label (UPN) against the
# configured identifier set, case-insensitively. IMP-39: an UNREADABLE list protects every row.
function Test-PimRowIsBreakGlass {
    param([Parameter(Mandatory)]$Row, [string[]]$Identifiers)
    if (-not $Identifiers -or $Identifiers.Count -eq 0) { return $false }
    if ($Identifiers -contains '<break-glass-list-unreadable>') { return $true }
    $cand = @()
    foreach ($k in 'principalId','principal','principalUpn','principalName','userPrincipalName','UserPrincipalName','Username') {
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
      AdminOffboarding provider (disable, sessions, memberships, notice mail -- never a delete, 71.21;
      progress in SQL), which acts on admin rows whose AutoDisableDate has passed
      (Get-PimAdminOffboardCandidate / Test-PimAdminOffboarded).

      So the invoker performs NO directory write: on the first step it stages ONE desired-state
      change on pim.ChangeQueue -- the admin's Account-Definitions-Admins row with AutoDisableDate = now
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
        $row['AutoDisableDate'] = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $key = Get-PimStoreRowKey -Base 'Account-Definitions-Admins' -Row ([pscustomobject]$row)
        if (-not $key) { $state.error = "the admin row for '$t' has no UserName -- it cannot be addressed in the store"; return [pscustomobject]@{ ok = $false; detail = $state.error } }
        $change = New-PimChange -Entity 'Account-Definitions-Admins' -Key $key -Op 'Update' -Payload ([pscustomobject]$row) `
                    -By $(if ("$By".Trim()) { "$By" } else { 'unknown' }) -Kind 'DesiredState' -Origin 'Authorised' `
                    -Justification "approved offboard (approval request $RequestId): mark $t for offboarding"
        & $Enqueue $change
        $state.queued = $true; $state.queueId = "$($change.id)"
        return [pscustomobject]@{ ok = $true; detail = "queued: AutoDisableDate set on the admin row (queue entry $($change.id)) -- commit it in Pending changes; the engine disables the account on its next run (PIM never deletes an account)" }
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
        # SEC-28: the posture names the layer the request path will actually use (env / platform).
        $bootLayer = ''
        if ($script:PimHosted -and (Get-Command Get-PimHostedAuthLayer -ErrorAction SilentlyContinue)) { $bootLayer = Get-PimHostedAuthLayer }
        $posture = Test-PimHostedAuthPosture -Hosted ([bool]$script:PimHosted) -AuthLayer $bootLayer
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
        # 🔴 SEC-29 -- STORED XSS THROUGH THE BOOT DATA. These values go into an inline <script> (and two
        # into HTML). pwsh 7's ConvertTo-Json does not escape '<', so a GroupName / DisplayName / AU or
        # tenant name of `</script><img src=x onerror=...>` closed the script block and ran in every
        # user's browser WITH the page's /api token. Every JSON value is made script-safe (< > & and the
        # two JS line separators as \uXXXX -- identical JSON, since those characters can only occur
        # inside JSON strings), the two HTML slots are HTML-encoded, and the placeholders are filled in
        # ONE pass, so a value that happens to contain a placeholder name is never re-expanded.
        $bootValues = @{
            '__PIM_DATA__'          = (ConvertTo-PimScriptSafeJson $json)
            '__PIM_TOKEN__'         = [System.Net.WebUtility]::HtmlEncode("$ExpectedToken")
            '__PIM_MODE__'          = [System.Net.WebUtility]::HtmlEncode("$modeLabel")
            '__PIM_NAMING__'        = (ConvertTo-PimScriptSafeJson $namingJson)
            '__PIM_TENANT_LISTS__'  = (ConvertTo-PimScriptSafeJson $tenantJson)
            '__PIM_INSTANCES__'     = (ConvertTo-PimScriptSafeJson $instJson)
            '__PIM_VERSION__'       = [System.Net.WebUtility]::HtmlEncode("$(Get-PimSolutionVersion)")
            '__PIM_ROLE__'          = (ConvertTo-PimScriptSafeJson $roleJson)
            '__PIM_FEATUREFLAGS__'  = (ConvertTo-PimScriptSafeJson $featureFlagsJson)
            '__PIM_GOVPREVIEW__'    = (ConvertTo-PimScriptSafeJson $govPreviewJson)
        }
        $html = Expand-PimBootTemplate -Html $html -Values $bootValues
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
        # 🔴 SEC-31 (server half): the page token is ONE per process, so holding it proves only that
        # somebody once opened the page. In hosted mode every /api call must ALSO carry a trusted
        # principal of its own; with none it is 401 -- never an anonymous Reader.
        if ($script:PimHosted -and -not "$script:CurrentRequestPrincipal".Trim()) {
            Write-JsonResponse -Response $resp -Status 401 -Body @{
                error  = 'unauthorized'
                detail = 'no authenticated principal on this request -- this app must be reached through its authentication edge'
            }
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
                $storedRows = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $base)
                # §71.5 -- the replication columns are the MSP master's alone; everywhere else they are
                # neither shown nor (see the PUT gate) accepted.
                $payload = [ordered]@{ path = 'sql'; source = 'sql'; header = @(Get-PimManagerReplicationHeader -Base $base -Header @($spec.defaultHeader) -IsMaster (Test-PimManagerIsMspMaster)) }
                # 🔴 SEC-43 -- ONLY THE CALLER'S VISIBLE SLICE. This read Get-PimSqlRows directly, so a Delegated
                # user (scope = the groups they own, Read-PimRows) saw every row through the grid, and a portal-
                # profile Admin's browser then held -- and sent back -- rows outside their scope (BUG-198). The slice
                # is the SAME one the PUT merges into (Get-PimManagerVisibleSlice): Delegated ownership scope, then
                # the portal profile. SuperAdmin and callers with neither see everything (unchanged).
                $slice = Get-PimManagerVisibleSlice -Base $base -Rows $storedRows
                $body = [ordered]@{
                    base   = $base
                    path   = $payload.path
                    source = $payload.source
                    header = $payload.header
                    rows   = @($slice.rows)
                    portalFiltered = [bool]$slice.filtered
                    # 🔴 BUG-200 -- optimistic concurrency. The hash of the FULL stored set (before any scope
                    # filter); the client sends it back as baseRowsHash and a commit against a set that has
                    # changed since is refused with 409 instead of silently replacing the other admin's rows.
                    rowsHash = (Get-PimRowsHash -Rows $storedRows)
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

                # 🔴 BUG-200 -- OPTIMISTIC CONCURRENCY. The GET handed out the hash of the full stored set; a commit
                # built on an older read would full-set-replace away whatever another admin committed in between.
                # baseRowsHash present + different -> 409, nothing written. Absent -> accepted (scripts, tests), and
                # the audit event says the commit was NOT concurrency-checked.
                $currentRowsHash = Get-PimRowsHash -Rows @($current.rows)
                $baseRowsHash = ''
                if ($body -and $body.PSObject.Properties['baseRowsHash']) { $baseRowsHash = "$($body.baseRowsHash)".Trim().ToLowerInvariant() }
                if ($baseRowsHash -and $baseRowsHash -ne $currentRowsHash) {
                    Write-JsonResponse -Response $resp -Status 409 -Body ([ordered]@{
                        ok = $false; base = $base; conflict = $true; gate = 'concurrency'
                        error = "$base has changed since you loaded it (another commit landed in between). Nothing was saved -- reload it, re-apply your change and commit again."
                        currentRowsHash = $currentRowsHash
                    })
                    return 409
                }
                $concurrencyNote = if ($baseRowsHash) { 'checked' } else { 'NOT checked (no baseRowsHash sent)' }

                # 🔴 BUG-198 -- MERGE THE CALLER'S VISIBLE SLICE INTO THE FULL STORED SET. A scoped caller only ever
                # sees (SEC-43) and sends their own slice; the old code diffed that slice against the WHOLE entity and
                # full-set-replaced it, deleting every row outside their scope, while the delta guard and the audit
                # described the pre-filter diff. Rows outside the slice are now preserved untouched, a submitted row
                # that would overwrite one of them is refused, and everything below -- the gates, the delta guard,
                # the commit and the audit -- works on the merged set and its REAL diff.
                $callerScope = Get-PimManagerCallerScope
                $slice = Get-PimManagerVisibleSlice -Base $base -Rows @($current.rows)
                if ($slice.filtered) {
                    $merge = Merge-PimManagerVisibleSlice -Base $base -Hidden @($slice.hidden) -Submitted @($rowsOrdered)
                    if (@($merge.collisions).Count -gt 0) {
                        Write-JsonResponse -Response $resp -Status 403 -Body ([ordered]@{
                            ok = $false; base = $base; gate = 'scope'
                            error = "$(@($merge.collisions).Count) submitted row(s) would overwrite a row outside your delegated scope -- refused, nothing was saved."
                            denied = @($merge.collisions)
                        })
                        return 403
                    }
                    $rowsOrdered = @($merge.rows)
                }
                # 🔴 BUG-204 (2.4.371) -- TWO ROWS, ONE STORE KEY, IN ONE COMMIT. The full-set replace upserts row by
                # row by Get-PimStoreRowKey, so rows sharing a key collapse and only the LAST survives -- a 2-role
                # workload delegation (key = GroupTag alone) kept one role and reported success. The diff cannot show
                # it either (Compare-PimRowSets falls back to content matching on a colliding key). Refuse, name the
                # key, write nothing.
                $dupKeys = @()
                if (Get-Command Get-PimDuplicateStoreKeys -ErrorAction SilentlyContinue) { $dupKeys = @(Get-PimDuplicateStoreKeys -Base $base -Rows @($rowsOrdered)) }
                if ($dupKeys.Count -gt 0) {
                    $dupTxt = (@($dupKeys | Select-Object -First 5 | ForEach-Object { "'$($_.key)' ($($_.count) rows)" }) -join ', ')
                    Write-JsonResponse -Response $resp -Status 400 -Body ([ordered]@{
                        ok = $false; base = $base; gate = 'duplicate-key'
                        error = "$($dupKeys.Count) store key(s) of $base are used by more than one row in this commit: $dupTxt. The store keeps ONE row per key, so all but the last would be silently lost. Nothing was saved -- make each row's key unique (for PIM-Assignments-Workloads: one role per delegation group)."
                        duplicateKeys = @($dupKeys)
                    })
                    return 400
                }
                $diff = Compare-PimRowSets -Before $current.rows -After $rowsOrdered -Base $base

                # 🔴 BUG-190 (adjacent path, operator decision 2026-09-18 for /modify, applied here as the SAME rule): an
                # admin row that would DISABLE the account on the next engine run -- AccountStatus Disabled/Revoked,
                # Lifecycle Retire, an AutoDisableDate/OffboardDate at or before now -- is an OFFBOARD. Review & Save wrote
                # it straight to pim.Rows, so one Admin could disable any in-scope admin with no second person. The
                # disabling value is now HELD (Get-PimAdminDisableHolds: a modified row keeps every other column; an added
                # row carrying one is held whole) and an offboard approval is raised per admin (Request-PimManagerOffboardHold,
                # the /modify outcome) when the body carries a justification. Every other change in the commit is kept.
                $offboardHolds = @()
                if ($base -eq 'Account-Definitions-Admins' -and (Get-Command Get-PimAdminDisableHolds -ErrorAction SilentlyContinue)) {
                    $adh = Get-PimAdminDisableHolds -Before @($current.rows) -After @($rowsOrdered) -Base $base
                    $offboardHolds = @($adh.holds)
                    if ($offboardHolds.Count -gt 0) {
                        # Scope first: a held row outside the caller's portal scope is refused exactly as a write would be,
                        # so no approval is ever raised against an admin the caller may not manage.
                        if (-not $callerScope.isSuperAdmin -and $callerScope.profile -and (Get-Command Test-PimPortalRowsInScope -ErrorAction SilentlyContinue)) {
                            $holdScope = Test-PimPortalRowsInScope -Profile $callerScope.profile -Rows @(Get-PimManagerDiffTouchedRows -Diff $diff) -Base $base -RequireManage
                            if (-not $holdScope.allowed) {
                                Write-JsonResponse -Response $resp -Status 403 -Body ([ordered]@{ ok = $false; base = $base; error = "$($holdScope.reason)"; denied = @($holdScope.denied) })
                                return 403
                            }
                        }
                        $rowsOrdered = @($adh.rows)
                        $diff = Compare-PimRowSets -Before $current.rows -After $rowsOrdered -Base $base
                    }
                }
                # Raises the approvals (once the rest of the commit is safe to land) and builds the per-admin result.
                $raiseOffboardHolds = {
                    $out = New-Object System.Collections.Generic.List[object]
                    $just = ''; $tick = ''
                    if ($body) {
                        if ($body.PSObject.Properties['justification']) { $just = "$($body.justification)".Trim() }
                        if ($body.PSObject.Properties['ticket'])        { $tick = "$($body.ticket)".Trim() }
                    }
                    foreach ($h in $offboardHolds) {
                        $what = (@($h.fields.Keys | ForEach-Object { "$_ '$($h.fields[$_])'" }) -join ', ')
                        if ($h.kind -eq 'add') {
                            $r = [ordered]@{ approvalRequired = $true; gate = 'offboard-approval'; upn = "$($h.upn)"; approvalRaised = $false; approvalId = ''
                                note = "'$($h.upn)' is a NEW admin row carrying $what, which would disable an existing account on the next engine run. The row was NOT saved: add the admin without it, then offboard it through the approval." }
                        } else {
                            $hUpn = $(if ("$($h.upn)".Trim()) { "$($h.upn)".Trim() } else { "$($h.key)" })   # the row key (UserName) when no UPN
                        $r = Request-PimManagerOffboardHold -Upn $hUpn -What $what -Justification $just -Ticket $tick -Requestor "$((Get-PimManagerRole).identity)" -Via "review-save $base"
                        }
                        $r['kind'] = "$($h.kind)"; $r['held'] = $h.fields
                        Write-PimManagerAuditEvent -Action 'admin.commit.offboard-held' -Target "$($h.upn)" -Result $(if ($r.approvalRaised) { 'ok' } else { 'denied' }) -After ([ordered]@{ held = $h.fields; kind = "$($h.kind)"; approvalRaised = [bool]$r.approvalRaised; approvalId = "$($r.approvalId)"; via = "review-save $base" })
                        $out.Add($r)
                    }
                    return ,($out.ToArray())
                }
                if ($offboardHolds.Count -gt 0 -and ($diff.adds.Count + $diff.removes.Count + $diff.modifies.Count) -eq 0) {
                    # Nothing else in this commit: nothing is written. 202 = every held admin has an offboard approval
                    # raised; 409 = at least one has not (no justification, surface off, a new row) -- say why, per admin.
                    $holdRes = & $raiseOffboardHolds
                    $allRaised = (@($holdRes | Where-Object { -not $_.approvalRaised }).Count -eq 0)
                    $st = if ($allRaised) { 202 } else { 409 }
                    $holdMsg = "Nothing else was saved: $(@($holdRes).Count) admin change(s) would disable the account on the next engine run, which is an OFFBOARD and needs a second administrator's approval. " + (@($holdRes | ForEach-Object { $_.note }) -join ' ')
                    $holdBody = [ordered]@{
                        ok = $allRaised; base = $base; changed = 0; adds = 0; removes = 0; modifies = 0; rowCount = @($rowsOrdered).Count
                        gate = 'offboard-approval'; approvalRequired = $true; offboardHeld = $true
                        approvalsRaised = @($holdRes | Where-Object { $_.approvalRaised } | ForEach-Object { "$($_.approvalId)" })
                        held = @($holdRes); note = $holdMsg; rowsHash = $currentRowsHash
                    }
                    if (-not $allRaised) { $holdBody['error'] = $holdMsg }
                    Write-JsonResponse -Response $resp -Status $st -Body $holdBody
                    return $st
                }

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
                $mc = $null
                if (Get-Command Test-PimAuthoringCommitAllowed -ErrorAction SilentlyContinue) {
                    # 🟠 §33.28 (lead follow-up, 2026-09-18): the INPUT to this gate is deliberately kept at what it
                    # has effectively been since it shipped -- the diff's ADDS + REMOVES, falling back to the whole
                    # after-set when there are none. Get-PimWriteAffectedRows now also returns both sides of every
                    # MODIFY (it used to drop them: [ordered] dictionaries), but feeding that here changes which
                    # commits need a second approver, and that switch is held until the approve path is usable
                    # end to end in the GUI: the Approvals raise form offers no 'authoring' action, POST
                    # /api/approvals sits behind the approvalsPreview flag (default OFF), and a blocked review-save
                    # names a target the operator has to type by hand. With the 'makerchecker' feature OFF (the
                    # default, BUG-107) this gate always allows, so nothing is blocked either way today.
                    $gateRows = New-Object System.Collections.Generic.List[object]
                    foreach ($ga in @($diff.adds))    { if ($null -ne $ga) { $gateRows.Add($ga) } }
                    foreach ($gr in @($diff.removes)) { if ($null -ne $gr) { $gateRows.Add($gr) } }
                    $gateRows = @($gateRows.ToArray())
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
                # We validate EVERY row the merged diff touches -- adds, BOTH sides of every
                # modify, and removes. (BUG-198: Get-PimWriteAffectedRows reads a modify's
                # before/after through PSObject.Properties, which a dictionary does not expose,
                # so modifies were never checked; Get-PimManagerDiffTouchedRows reads both shapes.)
                # A new row outside the caller's scope is REFUSED, no longer silently dropped.
                if (-not $callerScope.isSuperAdmin -and $callerScope.profile -and (Get-Command Test-PimPortalRowsInScope -ErrorAction SilentlyContinue)) {
                    $affected = @(Get-PimManagerDiffTouchedRows -Diff $diff)
                    $scopeCheck = Test-PimPortalRowsInScope -Profile $callerScope.profile -Rows $affected -Base $base -RequireManage
                    if (-not $scopeCheck.allowed) {
                        Write-JsonResponse -Response $resp -Status 403 -Body ([ordered]@{
                            ok = $false; base = $base; error = "$($scopeCheck.reason)"; denied = @($scopeCheck.denied)
                        })
                        return 403
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

                # §71.5 -- THE REPLICATION GATE, server-side, because the GUI is never the only gate. A
                # tenant that is not the MSP master may not introduce or change Replicate (or Ring/Target on
                # a non-admin entity); on the master every changed row must pass the same check the wizard
                # and the validator use -- a ManagementMode/Replicate disagreement, a bad Replicate value or
                # a malformed Target is refused before anything is written.
                if (Get-Command Test-PimReplicationWriteAllowed -ErrorAction SilentlyContinue) {
                    $repTags = @{ known = $false; tags = @() }
                    try { $repTags = Get-PimManagerKnownTenantTags } catch { }
                    $repGate = Test-PimReplicationWriteAllowed -Entity $base -Rows @($rowsOrdered) -CurrentRows @($current.rows) `
                                 -IsMaster (Test-PimManagerIsMspMaster) -KnownTags @($repTags.tags) -TagsKnown:([bool]$repTags.known)
                    if (-not $repGate.allowed) {
                        Write-JsonResponse -Response $resp -Status 409 -Body ([ordered]@{
                            ok = $false; base = $base; gate = 'replication'; error = "$($repGate.reason)"; refused = @($repGate.refused)
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
                # 🔴 §33.28: an 'authoring' approval that authorised THIS commit is consumed ONCE, as the design says
                # (Set-PimApprovalRequestExecuted). The PUT never latched it, so one approval stayed usable for every
                # later sensitive commit on the same entity until it expired.
                if ($mc -and "$($mc.gate)" -eq 'approved' -and $mc.approval -and (Get-Command Set-PimApprovalRequestExecuted -ErrorAction SilentlyContinue)) {
                    try { [void](Set-PimApprovalRequestExecuted -Id "$($mc.approval.id)") }
                    catch { Write-Warning "  [maker/checker] the approval $($mc.approval.id) that authorised this commit was NOT marked executed -- it could authorise another commit: $($_.Exception.Message)" }
                }
                Write-PimMutationLog -BaseName $base -Adds $diff.adds.Count -Removes $diff.removes.Count -Modifies $diff.modifies.Count -NewRowCount $rowsOrdered.Count -Diff $diff `
                    -Concurrency $concurrencyNote -ScopeMerged:([bool]$slice.filtered)
                # §70.21: start the engine now (debounced, so a multi-entity commit starts one run; the container takes
                # longer to start than the remaining entity writes, and a running tick re-checks between its jobs).
                if (($diff.adds.Count + $diff.removes.Count + $diff.modifies.Count) -gt 0) { try { [void](Start-PimManagerTickNow -Reason "commit:$base") } catch { } }

                # BUG-200: hand back the hash of what is stored NOW, so a follow-up commit from the same page is
                # checked against its own result rather than against the pre-commit read.
                $newRowsHash = ''
                try { $newRowsHash = Get-PimRowsHash -Rows @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $base) } catch { $newRowsHash = '' }
                $putOut = [ordered]@{
                    ok         = $true
                    base       = $base
                    path       = $writtenPath
                    rowCount   = $rowsOrdered.Count
                    adds       = $diff.adds.Count
                    removes    = $diff.removes.Count
                    modifies   = $diff.modifies.Count
                    snapshotId = "$($commitRes.snapshotId)"
                    rowsHash   = $newRowsHash
                    concurrency = $concurrencyNote
                }
                # BUG-190: the rest of the commit landed; the disabling value(s) were held for the offboard approval.
                # 202 (Accepted, not all applied) so no caller mistakes it for "everything I sent is now stored".
                $putStatus = 200
                if ($offboardHolds.Count -gt 0) {
                    $holdRes = & $raiseOffboardHolds
                    $putOut['gate'] = 'offboard-approval'; $putOut['approvalRequired'] = $true; $putOut['offboardHeld'] = $true
                    $putOut['approvalsRaised'] = @($holdRes | Where-Object { $_.approvalRaised } | ForEach-Object { "$($_.approvalId)" })
                    $putOut['held'] = @($holdRes)
                    $putOut['note'] = "Saved every other change. " + (@($holdRes | ForEach-Object { $_.note }) -join ' ')
                    $putStatus = 202
                }
                Write-JsonResponse -Response $resp -Status $putStatus -Body $putOut
                return $putStatus
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

        # REQ-D (2026-09-19): the 'Approvers' directory (pim.Settings 'Approvers') is RETIRED. Nothing ever read it --
        # approvals and mail resolve department -> owners (and a delegation's own ApproverUpns) -- so a save here changed
        # nothing anybody used. New writes are refused with 410 and a pointer; GET /api/settings still returns the stored
        # list, read-only, and the Departments & owners page shows those names once. Nothing is deleted from the store.
        if ($path -eq '/api/settings/approvers' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            Write-PimManagerAuditEvent -Action 'settings.approvers.save' -Target 'settings:approvers' -After @{ refused = 'gone'; reason = 'the Approvers directory is retired (REQ-D)' } -Result 'refused'
            Write-JsonResponse -Response $resp -Status 410 -Body @{
                ok = $false; gone = $true
                error = 'The Approvers directory is retired: nothing used it. Approvals and mail go to a department''s owners -- add the person as an owner of a department on Access > Departments & owners. The names already stored are kept and shown there once; nothing was changed.'
            }
            return 410
        }
        # -------------------------------------------------------------------
        # REQ-T (2.4.377) -- THE ADMIN ACCOUNT DOMAIN of THIS tenant (operator 2026-09-19: "maybe we need to define the
        # default domain logic per tenant somewhere in the settings as dropdown"). Stored as the naming key
        # AdminAccountUpnSuffix -- the key the engine, the downlink and the admin wizard all read -- so there is ONE
        # value, not a second copy. Blank = the tenant's default domain (the v1 behaviour).
        #   GET -- any role: the value, this tenant's verified domains, and the tenant mode (so the page can say that on
        #          a managed tenant this is also the domain replicated admins are created at).
        #   PUT -- SuperAdmin, audited. Only '' or one of THIS tenant's verified domains; unknown domains are refused.
        # -------------------------------------------------------------------
        if ($path -eq '/api/settings/admin-domain' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $cur = ''
            try { $cur = "$((Get-PimManagerNamingSettings).value['AdminAccountUpnSuffix'])".Trim() } catch { $cur = '' }
            $doms = Get-PimManagerTenantDomains
            $def = Get-PimTenantDefaultDomain -Domains @($doms.domains)   # ONE string, never a join
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                value = $cur; effective = $(if ($cur) { $cur.TrimStart('@') } else { $def }); defaultDomain = $def
                known = [bool]$doms.known; source = "$($doms.source)"; domains = @($doms.domains)
                reason = "$($doms.reason)"   # why the list is empty -- so the page can say it instead of just offering nothing
                canWrite = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')
            })
            return 200
        }
        if ($path -eq '/api/settings/admin-domain' -and $method -eq 'PUT') {
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to change the admin account domain.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            $body = Read-RequestJson -Request $req
            $want = if ($body -and $body.PSObject.Properties['value']) { "$($body.value)".Trim().TrimStart('@') } else { '' }
            if ($want) {
                $doms = Get-PimManagerTenantDomains
                if (-not $doms.known) {
                    Write-JsonResponse -Response $resp -Status 409 -Body @{ ok = $false; error = "This tenant's verified domains could not be read, so '$want' cannot be checked. Nothing was saved -- an unverified domain would create admins nobody can sign in as." }
                    return 409
                }
                if (-not (@($doms.domains) | Where-Object { "$($_.id)" -ieq $want })) {
                    Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = "'$want' is not a verified domain of this tenant. Add and verify it in Entra ID first, or pick one from the list." }
                    return 400
                }
            }
            try {
                $ns = Get-PimManagerNamingSettings
                $h = $ns.value
                $before = "$($h['AdminAccountUpnSuffix'])".Trim()
                $h['AdminAccountUpnSuffix'] = $(if ($want) { '@' + $want } else { $null })
                Set-PimManagerSetting -Name 'NamingConventions' -Value $h
                $global:PIM_NamingConventions['AdminAccountUpnSuffix'] = $h['AdminAccountUpnSuffix']
                Write-PimManagerAuditEvent -Action 'settings.admin-domain.save' -Target 'settings:AdminAccountUpnSuffix' -Before @{ value = $before } -After @{ value = "$($h['AdminAccountUpnSuffix'])" } -Result 'ok'
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; value = "$($h['AdminAccountUpnSuffix'])"
                    detail = $(if ($want) { "New admins are created as <name>@$want." } else { 'New admins are created at this tenant''s default domain.' }) }
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "admin account domain save failed: $($_.Exception.Message)" }
                return 500
            }
        }
        if ($path -match '^/api/settings/(naming|filters|departments)$' -and $method -eq 'PUT') {
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
                        # REQ-E (2026-09-19, "remove organisational dimension from settings too"): DirectGroupDimension
                        # only RE-WORDED the GUI ("role group" -> "department group" ...). It is superseded: dimensions are
                        # PARALLEL (§66) and departments / organisation / projects / cross-org are their own direct group
                        # types (§70.22). The wording is fixed to 'role'; a CHANGE is refused (410) with a pointer, and a
                        # value already stored is KEPT (never dropped by an unrelated naming save) and ignored by every reader.
                        $dimStored = ''
                        try { $curNaming = Get-PimManagerSetting -Name 'NamingConventions'; if ($curNaming -and $curNaming.PSObject.Properties['DirectGroupDimension']) { $dimStored = "$($curNaming.DirectGroupDimension)" } } catch { $dimStored = '' }
                        $dimKey = @($h.Keys | Where-Object { "$_" -eq 'DirectGroupDimension' }) | Select-Object -First 1
                        if ($dimKey) {
                            $dimNew = "$($h[$dimKey])".Trim().ToLowerInvariant()
                            $dimOld = "$dimStored".Trim().ToLowerInvariant()
                            if ($dimNew -ne $dimOld -and -not ($dimNew -eq 'role' -and -not $dimOld)) {
                                Write-PimManagerAuditEvent -Action 'settings.naming.save' -Target 'settings:naming' -After @{ refused = 'DirectGroupDimension'; requested = $dimNew } -Result 'refused'
                                Write-JsonResponse -Response $resp -Status 410 -Body @{ ok = $false; gone = $true
                                    error = 'The organisational dimension setting is retired: it only re-worded the Manager. Departments, organisation, projects and cross-org groups are their own group types now (Create access). The wording stays "role group"; nothing was saved.' }
                                return 410
                            }
                        } elseif ("$dimStored".Trim()) {
                            $h['DirectGroupDimension'] = $dimStored     # kept in the store, ignored by every reader
                        }
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
                        $deptConfirm = [bool]($body -and $body.PSObject.Properties['confirm'] -and ("$($body.confirm)" -match '(?i)^(true|1|yes)$'))
                        $dsave = Save-PimManagerDepartments -Departments $arr -Confirm:$deptConfirm
                        if (-not $dsave.ok) {
                            # BUG-177: the delta guard's refusal is a 409 the screen can confirm, not a store failure.
                            if ($dsave.confirmRequired) {
                                Write-JsonResponse -Response $resp -Status 409 -Body @{ ok = $false; confirmRequired = $true; gate = "$($dsave.gate)"; removeCount = [int]$dsave.removeCount; error = "$($dsave.error)" }
                                return 409
                            }
                            Write-JsonResponse -Response $resp -Status 503 -Body @{ error = "departments were NOT saved: $($dsave.error)" }
                            return 503
                        }
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
                # BUG-177: an import MERGES -- departments it did not name are kept, every definition column survives.
                $dsave = Save-PimManagerDepartments -Departments @($plan.departments) -PreserveMissing
                if (-not $dsave.ok) { Write-JsonResponse -Response $resp -Status $(if ($dsave.confirmRequired) { 409 } else { 503 }) -Body @{ error = "departments were NOT saved: $($dsave.error)"; confirmRequired = [bool]$dsave.confirmRequired }; return $(if ($dsave.confirmRequired) { 409 } else { 503 }) }
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
                # BUG-177: merge, keep unnamed departments, and carry a RENAMED department's definition row over.
                $dsave = Save-PimManagerDepartments -Departments @($plan.departments) -PreserveMissing -Renames @($plan.renamed)
                if (-not $dsave.ok) { Write-JsonResponse -Response $resp -Status $(if ($dsave.confirmRequired) { 409 } else { 503 }) -Body @{ error = "departments were NOT saved: $($dsave.error)"; confirmRequired = [bool]$dsave.confirmRequired }; return $(if ($dsave.confirmRequired) { 409 } else { 503 }) }
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
            if (Get-Command Get-PimLicenseApiBody -ErrorAction SilentlyContinue) {
                # REQ-Y: the licence in plain words + the MSP verdict for THIS environment (read-only). The MSP role is the
                # same answer the header mode badge shows (Get-PimActiveScenario -> role); single = no MSP requirement.
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimManagerLicenseBody)
            } else {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ status = 'Missing'; statusText = 'Core (free)'; reason = 'license library not loaded' }
            }
            return 200
        }

        # -------------------------------------------------------------------
        # REGISTER AN ISSUED LICENCE FROM THE GUI (operator 2026-09-20: "i dont get this, how can a
        # customer register a license when they dont have my admin cert").
        # The page told every customer to run Set-PimLicense.ps1 with -AdminAppId / -AdminCertThumbprint
        # -- credentials that reach the deployment's SQL store directly. Most customers do not have them
        # and should not need them: the licence is a document WE signed, and the store already refuses a
        # document that does not verify. So the supported path is: paste (or pick) the issued file here.
        #   * SuperAdmin only, and audited like every other settings write.
        #   * Set-PimLicense VERIFIES the signature BEFORE the store is written -- a tampered or
        #     foreign-signed document is refused and NOTHING is stored. That is the whole safety of
        #     letting a customer do this themselves; do not add a path that skips it.
        #   * The reply is the re-read licence body, so the card shows what the store now holds rather
        #     than what we hoped it would hold.
        # The command line stays available for an operator who prefers it (it is still shown on the card).
        # -------------------------------------------------------------------
        # PUT only -- one verb, the one the GUI calls. Accepting POST as an alias would add a second
        # entry point with no caller, which Test-PimGuiEngineAlignment correctly treats as an orphan.
        if ($path -eq '/api/license' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ ok = $false; error = 'SuperAdmin role required to register a licence.' }
                return 403
            }
            if (-not (Get-Command Set-PimLicense -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ ok = $false; error = 'the licence library is not loaded in this host, so nothing can be registered.' }
                return 503
            }
            $body = Read-RequestJson -Request $req
            $text = ''
            foreach ($k in @('text', 'license', 'licence', 'value')) {
                if ($body -and $body.PSObject.Properties[$k] -and "$($body.$k)".Trim()) { $text = "$($body.$k)"; break }
            }
            if (-not "$text".Trim()) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = 'No licence document was sent. Paste the whole contents of the issued .pimlicense / .aitlicense file, or pick the file.' }
                return 400
            }
            try {
                $chk = Set-PimLicense -LicenseText "$text"
            } catch {
                # A refusal is the NORMAL outcome for a wrong file -- say which document was rejected and
                # why, and be explicit that the store was not touched.
                Write-PimManagerAuditEvent -Action 'settings.license.register' -Target 'settings:License' -After ([ordered]@{ accepted = $false; reason = "$($_.Exception.Message)" }) -Result 'refused'
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = "$($_.Exception.Message)"; stored = $false }
                return 400
            }
            Write-PimManagerAuditEvent -Action 'settings.license.register' -Target 'settings:License' -After ([ordered]@{
                accepted = $true; customer = "$($chk.Customer)"; sku = "$($chk.Sku)"; status = "$($chk.Status)"
                validTo = $(if ($chk.ValidTo) { $chk.ValidTo.ToString('yyyy-MM-dd') } else { '' })
            }) -Result 'ok'
            $after = if (Get-Command Get-PimManagerLicenseBody -ErrorAction SilentlyContinue) { Get-PimManagerLicenseBody } else { $null }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                ok = $true; stored = $true
                detail = "Registered the licence for '$($chk.Customer)' ($($chk.Sku)) -- status $($chk.Status)."
                license = $after
            })
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
            # REQ-Y: the evidence / audit EXPORT is Pro (hard). The on-screen audit trail (/api/audit) stays free.
            if (-not (Test-PimManagerProFeature -Key 'reports.evidence' -Response $resp)) { return 403 }
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
        # -> revoke active; PIM never deletes an account, 71.21) so the checker sees exactly what an
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
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "action must be one of offboard|revoke|disable|authoring (got '$action')" }
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
        # pipeline (disable -> revoke-active; the account is never deleted -- 71.21) via Invoke-PimOffboardExecution.
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
                # desired-state change (the admin row's AutoDisableDate) for an operator to commit; the
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
                    note = $(if ($qInv.State.queued) { 'Queued: the admin is marked for offboarding in Pending changes. After you commit it, the engine performs the offboarding (disable, sessions, memberships, notice) on its next run. The account is disabled, never deleted.' } else { "Not queued: $($qInv.State.error)" }) })
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
            # REQ-Y: Pro (hard) -- 403 with the licence line when this environment has no Pro licence.
            if (-not (Test-PimManagerProFeature -Key 'reviews.campaigns' -Response $resp)) { return 403 }
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
            # REQ-Y: Pro (hard) -- 403 with the licence line when this environment has no Pro licence.
            if (-not (Test-PimManagerProFeature -Key 'reviews.campaigns' -Response $resp)) { return 403 }
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
            # REQ-Y: Pro (hard) -- 403 with the licence line when this environment has no Pro licence.
            if (-not (Test-PimManagerProFeature -Key 'reviews.campaigns' -Response $resp)) { return 403 }
            $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
            if (-not (Get-Command Send-PimAccessReviewReminders -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $shared)) {
                Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            }
            $body = Read-RequestJson -Request $req
            $preview = $false
            try { if ("$($body.preview)" -match '(?i)^(1|true|yes)$') { $preview = $true } } catch {}
            $pimOnly = $false
            try { if ("$($body.pimManagedOnly)" -match '(?i)^(1|true|yes)$') { $pimOnly = $true } } catch {}
            $rows = @(); $source = 'unavailable'; $note = ''
            if (Get-Command Send-PimAccessReviewReminders -ErrorAction SilentlyContinue) {
                try {
                    $me = (Get-PimManagerRole).identity
                    Initialize-PimManagerTenantConnection
                    # 🔴 BUG-219: pass the LAST-REMINDED map so the repeat window holds across presses. It was never
                    # passed, so every press re-fired a reminder to every reviewer of every due review. The map is
                    # kept in SQL (pim.Settings 'AccessReviewReminders') and updated only by a REAL send.
                    $lastMap = Get-PimManagerReviewReminderMap
                    if ($preview) { $rows = @(Send-PimAccessReviewReminders -PimManagedOnly:$pimOnly -LastReminded $lastMap -WhatIf) }
                    else          { $rows = @(Send-PimAccessReviewReminders -PimManagedOnly:$pimOnly -LastReminded $lastMap) }
                    $source = 'live'
                    $sentRows = @($rows | Where-Object { $_.sent })
                    foreach ($row in $sentRows) {
                        Write-PimManagerAuditEvent -Action 'access-review.reminder' -Target "$($row.definitionId)/$($row.instanceId)" -After @{ recipients = @($row.recipients); window = "$($row.window)"; sentBy = "$me" }
                    }
                    if (-not $preview -and $sentRows.Count -gt 0) {
                        try { Save-PimManagerReviewReminderMap -Map (Update-PimReviewReminderMap -Map $lastMap -Results $sentRows) }
                        catch { $note = "Reminders were sent, but the last-reminded record was NOT saved ($($_.Exception.Message)) -- the next press may remind the same reviewers again." }
                    }
                } catch { $note = "live reminder send unavailable: $($_.Exception.Message)" }
            } else { $note = 'access-review library not loaded' }
            # 🔴 BUG-195: no seeded sample preview on a live environment -- an unavailable read says so.
            $dueCount = @($rows | Where-Object { $_.due -or $_.sent }).Count
            $sentCount = @($rows | Where-Object { $_.sent }).Count
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = ($source -eq 'live'); source = $source; note = $note; preview = [bool]$preview; total = @($rows).Count; dueCount = [int]$dueCount; sentCount = [int]$sentCount; rows = @($rows) })
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
            $rows = @(); $source = 'unavailable'; $note = ''
            if (Get-Command Get-PimAccessReviewOverdue -ErrorAction SilentlyContinue) {
                try {
                    Initialize-PimManagerTenantConnection
                    $rows = @(Get-PimAccessReviewOverdue -PimManagedOnly:$pimOnly)
                    $source = 'live'
                } catch { $note = "live overdue read unavailable: $($_.Exception.Message)" }
            } else { $note = 'access-review library not loaded' }
            # 🔴 BUG-195: never the seeded sample on a live environment. Empty is empty; unreadable says so.
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
            # REQ-Y: Pro (hard) -- 403 with the licence line when this environment has no Pro licence.
            if (-not (Test-PimManagerProFeature -Key 'reports.evidence' -Response $resp)) { return 403 }
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
            $pkg = $null; $source = 'unavailable'; $note = ''
            if ($defId -and (Get-Command Get-PimAccessReviewEvidence -ErrorAction SilentlyContinue)) {
                try {
                    Initialize-PimManagerTenantConnection
                    $pkg = Get-PimAccessReviewEvidence -DefinitionId $defId -InstanceId $instId
                    if ($pkg) { $source = 'live' }
                } catch { $note = "live evidence read unavailable: $($_.Exception.Message)" }
            }
            # 🔴 BUG-195: no seeded sample evidence -- an evidence export of invented decisions is the worst kind of
            # sample data. No live package = 404 with the reason.
            if (-not $pkg) { Write-JsonResponse -Response $resp -Status 404 -Body @{ error = 'no evidence available (definitionId required for a live read)'; note = $note }; return 404 }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ source = $source; note = $note; evidence = $pkg })
            return 200
        }

        # Access Review overview (read-only). Surfaces the engine's access-review
        # data layer (engine/_shared/PIM-AccessReviews.ps1 -> Get-PimAccessReviewOverview)
        # for the "Access Review" GUI tab: review name, scope/target, reviewers,
        # recurrence, current-instance status + due date, pending/approved/denied
        # counts. Strictly read-only (no decisions recorded). BUG-195: an empty tenant is an
        # empty list and a failed read is reported as one (`source` = live | unavailable, plus
        # `note`) -- the seeded sample rows are never shown in a live Manager.
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
            $source = 'unavailable'
            $note   = ''
            # 🔴 BUG-195: ?seed=1 and the empty-result fallback both served SEEDED sample reviews on a live environment
            # ("no sample seeding"). Gone: live rows, an honest empty list, or an honest "could not read".
            if ($forceSeed) { $note = 'seed=1 is no longer supported -- sample data is never shown in a live Manager.' }
            if (Get-Command Get-PimAccessReviewOverview -ErrorAction SilentlyContinue) {
                try {
                    Initialize-PimManagerTenantConnection
                    $rows = @(Get-PimAccessReviewOverview -PimManagedOnly:$pimOnly -IncludeDecisionCounts:$withCounts)
                    $source = 'live'
                    if (@($rows).Count -eq 0 -and -not $note) { $note = 'No access reviews exist in this tenant (or none are PIM-managed).' }
                } catch {
                    $note = "live access-review read unavailable: $($_.Exception.Message)"
                }
            } else { $note = 'access-review library not loaded' }
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
                    heldCount    = $(if ($vm.PSObject.Properties['heldCount']) { [int]$vm.heldCount } else { 0 })   # 71.13 needs approval
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
            # On a managed tenant the pull is its own job with its own cadence (Get-PimManagerCadenceJob): editing the tick's
            # msp-pull placeholder here would change nothing the pull reads -- so say where it is set instead.
            if ($name -eq 'msp-pull' -and (Get-PimManagerCadenceJob) -eq 'pull') {
                Write-JsonResponse -Response $resp -Status 409 -Body @{ error = 'The managed-tenant pull is its own job (the Data Definition Updater). Set its cadence on the Job schedule page (Managed-tenant pull, SuperAdmin).' }
                return 409
            }
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
            # On a managed tenant the tick never pulls (its msp-pull handler records a skip): the pull's Run now is on the
            # Job schedule page, where it sets the pull job's own flag.
            if ($name -eq 'msp-pull' -and (Get-PimManagerCadenceJob) -eq 'pull') {
                Write-JsonResponse -Response $resp -Status 409 -Body @{ error = 'The managed-tenant pull is its own job, not a scheduler job. Use "Run pull now" on the Job schedule page (SuperAdmin); the pull then runs within 5 minutes.' }
                return 409
            }
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
            # REQ-Y: Pro (hard) -- 403 with the licence line when this environment has no Pro licence.
            if (-not (Test-PimManagerProFeature -Key 'reports.tier' -Response $resp)) { return 403 }
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
                $alertCfg = Get-PimAlertingConfig
                # 🔴 SEC-42: a Teams / generic incoming-webhook URL IS the credential -- whoever holds it can post
                # into the channel as the alert sender. Only a caller who may CHANGE alerting (Admin+) sees it;
                # everyone else gets whether one is set and a host-only hint.
                if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) { $alertCfg = Hide-PimAlertingSecret -Config $alertCfg }
                Write-JsonResponse -Response $resp -Status 200 -Body $alertCfg
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
            # An ABSENT webhookUrl/webhookKind keeps the stored value. Only a field that is present
            # (including an explicit '') changes it. Since SEC-42 a Reader's page never holds the
            # URL, so reading "absent" as "clear" would let any save of the other fields wipe the webhook.
            $webhookUrl = ''; $webhookKind = ''
            $hasUrl  = [bool]($body -and $body.PSObject.Properties['webhookUrl'])
            $hasKind = [bool]($body -and $body.PSObject.Properties['webhookKind'])
            if (-not ($hasUrl -and $hasKind)) {
                $stored = $null
                try { $stored = Get-PimAlertingConfig } catch {
                    Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "the stored webhook could not be read, so saving without it would clear it: $($_.Exception.Message)" }
                    return 500
                }
                # Get-PimAlertingConfig returns an [ordered] DICTIONARY. PSObject.Properties does not see its keys,
                # so read it through Get-PimStoredAlertField, which handles both a dictionary and an object.
                if ($stored) {
                    $webhookUrl  = Get-PimStoredAlertField -Config $stored -Name 'webhookUrl'
                    $webhookKind = Get-PimStoredAlertField -Config $stored -Name 'webhookKind'
                }
            }
            if ($hasUrl)  { $webhookUrl  = "$($body.webhookUrl)" }
            if ($hasKind) { $webhookKind = "$($body.webhookKind)" }
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
        # 🔴 IMP-39 -- BREAK-GLASS ACCOUNTS, defined in the GUI and stored in SQL (pim.Settings 'BreakGlassAccounts').
        # The accounts PIM must never disable, revoke or offboard came only from an env var set by hand on BOTH
        # containers, unaudited. Both containers now read this one row (PIM-BreakGlassAccounts.ps1); the legacy
        # global/env values are still unioned in so nothing configured today is lost.
        # BREAK-GLASS MAKER/CHECKER -- ENDPOINTS (operator 2026-09-19). The list EXEMPTS accounts from every
        # revoke / disable / offboard guard, so ONE SuperAdmin must not be able to change it alone. A change is a
        # PENDING request (pim.Settings 'BreakGlassAccountsChange', engine/_shared/PIM-BreakGlassChange.ps1) that a
        # SECOND SuperAdmin approves; only then is the list written (compare-and-set against the snapshot the maker saw).
        # 🔒 ALWAYS ON: none of these endpoints consults the 'makerchecker' feature flag or the 'approvalsPreview'
        # governance preview (both default off). This is the tier-0 exemption list itself -- a control a single
        # SuperAdmin could switch off would not be a second-person control. The out-of-band route for an environment
        # with ONE SuperAdmin is host-side: tools/setup/Set-PimBreakGlassAccounts.ps1 (store access, audited 'setup').
        #   GET  /api/settings/breakglass-accounts              (Reader+) the list + listHash + the current request
        #   PUT  /api/settings/breakglass-accounts              (SuperAdmin) { accounts, justification, confirmEmpty?, baseHash? }
        #                                                        -> 202 { pending, requestId, diff, expiresUtc } -- NOT applied
        #   GET  /api/settings/breakglass-accounts/request      (Reader+) the current request with its diff
        #   POST /api/settings/breakglass-accounts/request/approve (SuperAdmin, NOT the maker) { requestId, note? }
        #   POST /api/settings/breakglass-accounts/request/reject  (SuperAdmin, NOT the maker) { requestId, note? }
        #   POST /api/settings/breakglass-accounts/request/cancel  (the maker, still SuperAdmin) { requestId, note? }
        # Every outcome of every mutation is audited (settings.breakglass-accounts.*), refusals included.
        # -------------------------------------------------------------------
        if ($path -eq '/api/settings/breakglass-accounts' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Reader')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Reader role required.' }
                return 403
            }
            if (-not (Get-Command Get-PimBreakGlassAccountStatus -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ error = 'the break-glass account library (PIM-BreakGlassAccounts.ps1) is not loaded in this Manager' }
                return 503
            }
            $bgs = Get-PimBreakGlassAccountStatus -ConnectionString "$($script:PimSqlCs)" -NoCache
            $bgSource = if (-not $bgs.storeConfigured) { 'no-store' } elseif (-not $bgs.storeOk) { 'unreadable' } else { 'sql' }
            $bgReq = $null; $bgReqErr = ''
            if ("$($script:PimSqlCs)".Trim()) {
                try { $bgReq = Get-PimManagerBreakGlassRequestView } catch { $bgReqErr = "the pending break-glass change request could not be read: $($_.Exception.Message)" }
            }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                accounts          = @($bgs.storeAccounts)
                legacyAccounts    = @($bgs.legacyAccounts)
                effectiveAccounts = @($bgs.accounts)
                source            = $bgSource
                storeOk           = [bool]$bgs.storeOk
                error             = "$($bgs.error)"
                listHash          = $(if ($bgs.storeOk) { Get-PimBreakGlassListHash -Accounts @($bgs.storeAccounts) } else { '' })
                makerChecker      = $true
                me                = "$((Get-PimManagerRole).identity)"
                request           = $bgReq
                requestError      = $bgReqErr
                canRaise          = [bool]((Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin') -and -not ($bgReq -and $bgReq.open) -and -not $bgReqErr)
                note              = $(if (@($bgs.legacyAccounts).Count) { 'Some accounts come from the legacy environment setting PIM_BREAKGLASS_ACCOUNTS; they stay protected. Add them here so the list lives in one audited place.' } else { '' })
            })
            return 200
        }
        if ($path -eq '/api/settings/breakglass-accounts/request' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Reader')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Reader role required.' }
                return 403
            }
            if (-not "$($script:PimSqlCs)".Trim()) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ error = 'no SQL store is bound -- break-glass change requests live in pim.Settings (PIM v2 is SQL-only)' }
                return 503
            }
            try {
                $bgReq = Get-PimManagerBreakGlassRequestView
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; open = [bool]($bgReq -and $bgReq.open); request = $bgReq })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "the break-glass change request could not be read: $($_.Exception.Message)" }
                return 500
            }
        }
        if ($path -eq '/api/settings/breakglass-accounts' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to request a change to the break-glass accounts. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            if (-not (Get-Command New-PimBreakGlassChangeRequest -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ error = 'the break-glass maker/checker library (PIM-BreakGlassChange.ps1) is not loaded in this Manager -- nothing was requested' }
                return 503
            }
            if (-not "$($script:PimSqlCs)".Trim()) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ error = 'no SQL store is bound -- the break-glass list lives in pim.Settings (PIM v2 is SQL-only); nothing was requested' }
                return 503
            }
            $body = Read-RequestJson -Request $req
            $bgNew = @()
            if ($body -and $body.PSObject.Properties['accounts']) { $bgNew = @(@($body.accounts) | Where-Object { $null -ne $_ } | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
            $bgJust = if ($body -and $body.PSObject.Properties['justification']) { "$($body.justification)".Trim() } else { '' }
            $bgConfirmEmpty = [bool]($body -and $body.PSObject.Properties['confirmEmpty'] -and ("$($body.confirmEmpty)" -match '(?i)^(true|1|yes)$'))
            $bgBase = if ($body -and $body.PSObject.Properties['baseHash']) { "$($body.baseHash)".Trim() } else { '' }
            $bgMaker = "$((Get-PimManagerRole).identity)"
            try {
                $bgRes = New-PimBreakGlassChangeRequest -ConnectionString "$($script:PimSqlCs)" -Proposed $bgNew -Maker $bgMaker -Justification $bgJust -ConfirmEmpty:$bgConfirmEmpty -BaseHash $bgBase
            } catch {
                $bgMsg = "$($_.Exception.Message)"
                Write-PimManagerAuditEvent -Action 'settings.breakglass-accounts.request' -Target 'settings:breakglass-accounts' -After @{ requested = @($bgNew); justification = $bgJust; error = $bgMsg } -Result 'error'
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "the change request was NOT raised: $bgMsg" }
                return 500
            }
            if ($bgRes.expiredPrevious) {
                Write-PimManagerAuditEvent -Action 'settings.breakglass-accounts.expired' -Target 'settings:breakglass-accounts' `
                    -After @{ requestId = "$($bgRes.expiredPrevious.id)"; maker = "$($bgRes.expiredPrevious.maker)"; expiresUtc = "$($bgRes.expiredPrevious.expiresUtc)" } -Result 'ok'
            }
            if (-not $bgRes.ok) {
                $bgCode = switch ("$($bgRes.code)") { 'no-justification' { 400 } 'invalid' { 400 } 'no-maker' { 400 } 'no-change' { 400 } default { 409 } }
                $bgBody = [ordered]@{ ok = $false; code = "$($bgRes.code)"; error = "$($bgRes.reason)" }
                if ("$($bgRes.code)" -eq 'confirm-empty') { $bgBody['confirmRequired'] = $true }
                if ("$($bgRes.code)" -eq 'open-request' -and $bgRes.request) { $bgBody['openRequest'] = (ConvertTo-PimManagerBreakGlassRequestView -Request $bgRes.request); $bgBody['requestId'] = "$($bgRes.request.id)" }
                Write-PimManagerAuditEvent -Action 'settings.breakglass-accounts.request' -Target 'settings:breakglass-accounts' `
                    -After @{ requested = @($bgNew); justification = $bgJust; refused = "$($bgRes.code)"; reason = "$($bgRes.reason)" } -Result 'refused'
                Write-JsonResponse -Response $resp -Status $bgCode -Body $bgBody
                return $bgCode
            }
            $bgR = $bgRes.request
            Write-PimManagerAuditEvent -Action 'settings.breakglass-accounts.request' -Target 'settings:breakglass-accounts' `
                -Before @{ accounts = @($bgR.snapshot); snapshotHash = "$($bgR.snapshotHash)" } `
                -After @{ requestId = "$($bgR.id)"; proposed = @($bgR.proposed); added = @($bgR.added); removed = @($bgR.removed); maker = "$($bgR.maker)"; justification = "$($bgR.justification)"; expiresUtc = "$($bgR.expiresUtc)"; confirmEmpty = [bool]$bgR.confirmEmpty } -Result 'ok'
            $bgView = ConvertTo-PimManagerBreakGlassRequestView -Request $bgR
            Write-JsonResponse -Response $resp -Status 202 -Body ([ordered]@{
                ok = $true; pending = $true; requestId = "$($bgR.id)"
                diff = [ordered]@{ added = @($bgR.added); removed = @($bgR.removed) }
                expiresUtc = "$($bgR.expiresUtc)"; request = $bgView
                onlySuperAdmin = [bool]$bgView.onlySuperAdmin
                note = $(if ($bgView.onlySuperAdmin) { "Request raised -- NOT applied. $($bgView.onlySuperAdminNote)" } else { 'Request raised -- NOT applied. Another SuperAdmin must approve it before the list changes.' })
            })
            return 202
        }
        if ($path -match '^/api/settings/breakglass-accounts/request/(approve|reject|cancel)$' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            $bgAct = $Matches[1]     # approve | reject | cancel
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = "SuperAdmin role required to $bgAct a break-glass change request." }
                return 403
            }
            if (-not (Get-Command Invoke-PimBreakGlassChangeApproval -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ error = 'the break-glass maker/checker library (PIM-BreakGlassChange.ps1) is not loaded in this Manager -- nothing was decided' }
                return 503
            }
            if (-not "$($script:PimSqlCs)".Trim()) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ error = 'no SQL store is bound -- nothing was decided' }
                return 503
            }
            $body = Read-RequestJson -Request $req
            $bgId = if ($body -and $body.PSObject.Properties['requestId']) { "$($body.requestId)".Trim() } else { '' }
            $bgNote = if ($body -and $body.PSObject.Properties['note']) { "$($body.note)".Trim() } else { '' }
            if (-not $bgId) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'requestId is required' }; return 400 }
            $bgWho = "$((Get-PimManagerRole).identity)"
            try {
                if ($bgAct -eq 'approve') { $bgRes = Invoke-PimBreakGlassChangeApproval -ConnectionString "$($script:PimSqlCs)" -RequestId $bgId -Checker $bgWho -Note $bgNote }
                else { $bgRes = Close-PimBreakGlassChangeRequest -ConnectionString "$($script:PimSqlCs)" -RequestId $bgId -Actor $bgWho -Decision $bgAct -Note $bgNote }
            } catch {
                $bgMsg = "$($_.Exception.Message)"
                Write-PimManagerAuditEvent -Action "settings.breakglass-accounts.$bgAct" -Target 'settings:breakglass-accounts' -After @{ requestId = $bgId; error = $bgMsg } -Result 'error'
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "nothing was decided: $bgMsg" }
                return 500
            }
            $bgR = $bgRes.request
            $bgAudit = [ordered]@{ requestId = $bgId; maker = "$($bgR.maker)"; checker = $bgWho; added = @($bgR.added); removed = @($bgR.removed); justification = "$($bgR.justification)"; note = $bgNote; outcome = "$($bgRes.code)"; reason = "$($bgRes.reason)" }
            if ($bgRes.ok) {
                if ($bgAct -eq 'approve') {
                    $bgAudit['accounts'] = @($bgRes.accounts)
                    Write-PimManagerAuditEvent -Action 'settings.breakglass-accounts.applied' -Target 'settings:breakglass-accounts' -Before @{ accounts = @($bgR.snapshot) } -After $bgAudit -Result 'ok'
                } elseif ($bgAct -eq 'reject') {
                    Write-PimManagerAuditEvent -Action 'settings.breakglass-accounts.rejected' -Target 'settings:breakglass-accounts' -After $bgAudit -Result 'ok'
                } else {
                    $bgAudit.Remove('checker'); $bgAudit['cancelledBy'] = $bgWho
                    Write-PimManagerAuditEvent -Action 'settings.breakglass-accounts.cancelled' -Target 'settings:breakglass-accounts' -After $bgAudit -Result 'ok'
                }
                $bgAfter = Get-PimBreakGlassAccountStatus -ConnectionString "$($script:PimSqlCs)" -NoCache
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok = $true; status = "$($bgR.status)"; reason = "$($bgRes.reason)"; request = (ConvertTo-PimManagerBreakGlassRequestView -Request $bgR)
                    accounts = @($bgAfter.storeAccounts); effectiveAccounts = @($bgAfter.accounts)
                })
                return 200
            }
            # Refused or failed -- audited in every case. A STALE approval closes the request (the list changed since it
            # was made); an EXPIRED one likewise; the maker approving/rejecting their own request is refused (403).
            $bgEvt = switch ("$($bgRes.code)") { 'stale' { 'settings.breakglass-accounts.stale' } 'expired' { 'settings.breakglass-accounts.expired' } 'failed' { 'settings.breakglass-accounts.apply-failed' } default { "settings.breakglass-accounts.$bgAct" } }
            Write-PimManagerAuditEvent -Action $bgEvt -Target 'settings:breakglass-accounts' -After $bgAudit -Result $(if ("$($bgRes.code)" -eq 'failed') { 'error' } else { 'refused' })
            $bgCode = switch ("$($bgRes.code)") { 'same-person' { 403 } 'not-maker' { 403 } 'not-found' { 404 } 'failed' { 500 } default { 409 } }
            Write-JsonResponse -Response $resp -Status $bgCode -Body ([ordered]@{
                ok = $false; code = "$($bgRes.code)"; error = "$($bgRes.reason)"
                request = $(if ($bgR) { ConvertTo-PimManagerBreakGlassRequestView -Request $bgR } else { $null })
            })
            return $bgCode
        }
        # END BREAK-GLASS MAKER/CHECKER

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

        # REQ-L: the Policy templates page. GET read-anyone (like the catalog above); usage is counted over the caller's
        # visible slice. There is deliberately no PUT of a template: its RULES are not edited in the Manager.
        if ($path -eq '/api/policy-templates' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimManagerPolicyTemplatesPage)
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # 2026-09-19 (operator: "give policies an id so we can rename them"): RENAME a template -- its display NAME only.
        # Every delegation, 'extends' and per-kind default points at the template's ID, which never changes, so no
        # reference moves, no rule changes and the tenant is not touched (this is a pim.Settings write, like every
        # other configuration save; nothing is queued because nothing in the tenant changes). SuperAdmin; audited; read
        # back (Set-PimPolicyTemplateName) -- the response carries the store fingerprint before and after (equal).
        if ($path -eq '/api/policy-templates/rename' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to rename a policy template.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $rid = if ($body -and $body.PSObject.Properties['id']) { "$($body.id)".Trim() } else { '' }
            $rnm = if ($body -and $body.PSObject.Properties['name']) { "$($body.name)" } else { '' }
            if (-not $rid) { Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = 'id is required (rename by the template id, never by its name).' }; return 400 }
            try {
                $who = ''; try { $who = "$((Get-PimManagerRole).identity)" } catch { }
                $res = Set-PimPolicyTemplateName -ConnectionString $script:PimSqlCs -Id $rid -Name $rnm -Actor $(if ($who) { $who } else { 'manager' })
                # This process's hydrated copy (the validator reads it first) follows the store at once.
                if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains('PolicyTemplates')) {
                    try { $global:PIM_NamingConventions['PolicyTemplates'] = Get-PimManagerSetting -Name 'PolicyTemplates' } catch { }
                }
                Write-PimManagerAuditEvent -Action 'policy.template.rename' -Target "policytemplate:$($res.id)" -Before ([ordered]@{ name = "$($res.before)" }) -After ([ordered]@{ name = "$($res.after)"; fingerprintBefore = "$($res.fingerprintBefore)"; fingerprintAfter = "$($res.fingerprintAfter)" }) -Result 'ok'
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; id = $res.id; before = $res.before; after = $res.after; fingerprintBefore = $res.fingerprintBefore; fingerprintAfter = $res.fingerprintAfter })
                return 200
            } catch {
                $msg = "$($_.Exception.Message)"
                try { Write-PimManagerAuditEvent -Action 'policy.template.rename' -Target "policytemplate:$rid" -After ([ordered]@{ name = $rnm; error = $msg }) -Result 'refused' } catch { }
                $code = if ($msg -match 'no template with id|empty|characters|control character|already the id or name|former id') { 400 } else { 500 }
                Write-JsonResponse -Response $resp -Status $code -Body @{ ok = $false; error = $msg }
                return $code
            }
        }

        # 2026-09-19 (operator: "set default in settings"): the per-kind DEFAULT template -- what a BLANK PolicyTemplate
        # means for group / Entra role / Azure role policies (pim.Settings['PolicyTemplateDefaults'], read by the engine).
        # SuperAdmin; each value '' (built-in default) or a stored template of THAT kind; audited; read back.
        if ($path -eq '/api/settings/policy-template-defaults' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to change the default policy templates.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $payload = if ($body -and $body.PSObject.Properties['value']) { $body.value } else { $body }
            try {
                $res = Set-PimManagerPolicyTemplateDefaults -Value $payload
                Write-PimManagerAuditEvent -Action 'settings.policy-template-defaults.save' -Target 'settings:PolicyTemplateDefaults' -Before $res.before -After ([ordered]@{ stored = $res.after; effective = $res.effective }) -Result 'ok'
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; stored = $res.after; effective = $res.effective })
                return 200
            } catch {
                $msg = "$($_.Exception.Message)"
                $code = if ($msg -match 'not a template|written for|empty or unreadable') { 400 } else { 500 }
                Write-JsonResponse -Response $resp -Status $code -Body @{ ok = $false; error = $msg }
                return $code
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
            # REQ-Y: switching a Pro feature ON (off -> on) needs a Pro licence -- 403 with the licence line. A Pro
            # feature that is ALREADY on may be re-sent unchanged (the card saves the whole map), and turning one OFF is
            # always allowed.
            if (Get-Command Get-PimFeatureGateState -ErrorAction SilentlyContinue) {
                $curGates = $null; try { $curGates = (Get-PimFeatureGateState).gates } catch { $curGates = $null }
                $newGates = if ($payload -and $payload.PSObject.Properties['gates']) { $payload.gates } else { $payload }
                $turnOn = @()
                if ($newGates) {
                    $pairs = if ($newGates -is [System.Collections.IDictionary]) { @($newGates.Keys | ForEach-Object { @{ k = "$_"; v = $newGates[$_] } }) } else { @($newGates.PSObject.Properties | ForEach-Object { @{ k = "$($_.Name)"; v = $_.Value } }) }
                    foreach ($pr in $pairs) {
                        if (-not [bool]$pr.v) { continue }
                        $was = $false; if ($curGates -and $curGates.Contains($pr.k)) { $was = [bool]$curGates[$pr.k] }
                        if (-not $was) { $turnOn += $pr.k }
                    }
                }
                foreach ($k in $turnOn) { if (-not (Test-PimManagerProFeature -Key $k -Response $resp)) { return 403 } }
            }
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

        # -------------------------------------------------------------------
        # §71 -- MSP REPLICATION TARGETING (framework MSP-4 SURFACE).
        #   GET  /api/msp/replication/context -- is this the master, which tenants/tags a target can name
        #   POST /api/msp/replication/reach   -- "this will reach: N tenants", per row, plus the
        #                                        dependency warnings. Body: { draft: [{entity,row}] } for a
        #                                        wizard's unsaved row, and/or { pending: {entity: [rows]} }
        #                                        for the grid's pending set (replaces that entity's rows).
        # 🔒 MASTER ONLY. Anywhere else the context says master=false and the reach answers nothing -- the
        # GUI hides the surface and the PUT gate refuses the fields. Reach is COMPUTED BY THE PLAN every
        # managed tenant runs (Get-PimReplicationPreview), never estimated in the browser.
        # -------------------------------------------------------------------
        if ($path -eq '/api/msp/replication/context' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $isMaster = Test-PimManagerIsMspMaster
            $tenants = @(); $tags = @()
            if ($isMaster) {
                try {
                    $tenants = @(Get-PimManagerDownlinkTenants -ConnectionString (Get-PimManagerStoreCs) | ForEach-Object {
                        [ordered]@{ tenantId = "$($_.TenantId)"; name = "$($_.DisplayName)"; ring = [int]("0" + "$($_.Ring)"); tags = @("$($_.Tags)" -split '[;,]' | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
                    })
                } catch { $tenants = @() }
                try { $tags = @((Get-PimManagerKnownTenantTags).tags) } catch { $tags = @() }
            }
            $ents = [ordered]@{}
            if (Get-Command Get-PimReplicationEntities -ErrorAction SilentlyContinue) { foreach ($e in @(Get-PimReplicationEntities)) { $ents[$e] = Get-PimReplicationKindForEntity -Entity $e } }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ master = [bool]$isMaster; tenants = @($tenants); tags = @($tags); entities = $ents })
            return 200
        }
        if ($path -eq '/api/msp/replication/reach' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerIsMspMaster)) {
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ master = $false; reason = 'replication targeting exists only on the MSP master'; rows = @(); warnings = @() })
                return 200
            }
            try {
                $body = Read-RequestJson -Request $req
                $overlay = @{}
                if ($body -and $body.PSObject.Properties['pending'] -and $body.pending) { foreach ($p in $body.pending.PSObject.Properties) { $overlay["$($p.Name)"] = @($p.Value) } }
                $draft = @()
                if ($body -and $body.PSObject.Properties['draft'] -and $body.draft) { $draft = @($body.draft) }
                $model = Get-PimReplicationMasterModel -ConnectionString (Get-PimManagerStoreCs) -Overlay $overlay -Draft $draft
                $prev = Get-PimReplicationPreview -RegistryRows @($model.RegistryRows) -RegistryReplicate $model.RegistryReplicate -Entities $model.Entities -Tenants @($model.Tenants) -ProjectionPolicy $model.ProjectionPolicy
                $rowsOut = New-Object System.Collections.Generic.List[object]
                foreach ($d in $draft) {
                    $e = "$($d.entity)"; $r = [pscustomobject]$d.row
                    $one = Get-PimReplicationRowReach -Preview $prev -Entity $e -Row $r
                    $chk = Test-PimReplicationRowFields -Row $r -Entity $e -KnownTags @((Get-PimManagerKnownTenantTags).tags) -TagsKnown
                    $rowsOut.Add([ordered]@{ source = 'draft'; entity = $e; index = -1; id = $one.id; count = $one.count; tenantCount = $one.tenantCount; tenants = @($one.tenants); summary = $one.summary; warnings = @($one.warnings); errors = @($chk.errors); fieldWarnings = @($chk.warnings) }) | Out-Null
                }
                foreach ($e in $overlay.Keys) {
                    $i = 0
                    foreach ($r in @($overlay[$e])) {
                        $one = Get-PimReplicationRowReach -Preview $prev -Entity $e -Row $r
                        $rowsOut.Add([ordered]@{ source = 'pending'; entity = $e; index = $i; id = $one.id; count = $one.count; tenantCount = $one.tenantCount; tenants = @($one.tenants); summary = $one.summary; warnings = @($one.warnings) }) | Out-Null
                        $i++
                    }
                }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    master = $true; tenantCount = $prev.tenantCount; rows = @($rowsOut.ToArray()); warnings = @($prev.warnings)
                    notPublished = @($prev.notPublished); dependencyIncluded = @($prev.dependencyIncluded); errors = @($prev.errors)
                    # BUG-175 (GUI half, 2.4.371): the count above is computed with the MASTER'S COPY of each tenant's ring;
                    # the tenant's own local ring is authoritative. Carried so the page can say so, plus the tenants the
                    # master holds no readable ring for (previewed as ring 2).
                    ringSource = "$($prev.ringSource)"; ringNote = "$($prev.ringNote)"
                    ringUnknown = @(@($prev.tenants) | Where-Object { $_ -and -not $_.ringKnown } | ForEach-Object { "$($_.name)" })
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "replication reach failed: $($_.Exception.Message)" }
                return 500
            }
        }

        # -------------------------------------------------------------------
        # REQ-N / REQ-O (operator 2026-09-19) -- the MSP MASTER's registry page and replication overview.
        #   GET  /api/msp/tenants               -- the registry: name, id, the master's COPY of the ring, tags, enabled,
        #                                          and whether the last publish carries it
        #   POST /api/msp/tenants               -- register a managed tenant (SuperAdmin, audited, read back)
        #   PUT  /api/msp/tenants/{tenantId}    -- edit DisplayName / Ring copy / Tags / Enabled (SuperAdmin, audited, read back)
        #   GET  /api/msp/replication/overview  -- every replicable row, by kind, and the tenants it reaches (?refresh=1)
        # 🔒 The gates live in the functions (Get-PimManagerMspTenantsResponse, Invoke-PimManagerMspTenantWrite,
        # Get-PimManagerReplicationOverviewResponse): master-only, fail closed; writes SuperAdmin-only.
        # -------------------------------------------------------------------
        if ($path -eq '/api/msp/tenants' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try { $r = Get-PimManagerMspTenantsResponse }
            catch { $r = @{ status = 500; body = @{ error = "managed-tenant registry failed: $($_.Exception.Message)" } } }
            Write-JsonResponse -Response $resp -Status $r.status -Body $r.body
            return $r.status
        }
        if ($path -eq '/api/msp/tenants' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            try { $r = Invoke-PimManagerMspTenantWrite -Mode Create -Body (Read-RequestJson -Request $req) }
            catch { $r = @{ status = 500; body = @{ ok = $false; error = "registering the managed tenant failed: $($_.Exception.Message)" } } }
            Write-JsonResponse -Response $resp -Status $r.status -Body $r.body
            return $r.status
        }
        if ($path -match '^/api/msp/tenants/([0-9a-fA-F-]+)$' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            $mspTid = $Matches[1]
            try { $r = Invoke-PimManagerMspTenantWrite -Mode Update -TenantId $mspTid -Body (Read-RequestJson -Request $req) }
            catch { $r = @{ status = 500; body = @{ ok = $false; error = "editing the managed tenant failed: $($_.Exception.Message)" } } }
            Write-JsonResponse -Response $resp -Status $r.status -Body $r.body
            return $r.status
        }
        if ($path -eq '/api/msp/replication/overview' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $refresh = ("$($req.QueryString['refresh'])".Trim() -in @('1', 'true', 'yes'))
            try { $r = Get-PimManagerReplicationOverviewResponse -Refresh:$refresh }
            catch { $r = @{ status = 500; body = @{ error = "replication overview failed: $($_.Exception.Message)" } } }
            Write-JsonResponse -Response $resp -Status $r.status -Body $r.body
            return $r.status
        }

        # -------------------------------------------------------------------
        # §71.43 -- GET /api/update-ring. WHICH UPDATE RING IS THIS ENVIRONMENT ON?
        #
        # 🔴 THERE IS NO GET-THE-RING-FROM-AZURE HERE, AND THAT IS DELIBERATE. PIM_UPDATE_RING lives on
        # ca-pim-update; reading it would mean an ARM call per page load, with the Manager's identity
        # needing rights over a job it does not own, and it would still fail in every environment whose
        # updater is not deployed. The environment RECORDS its own state instead (the update job writes
        # pim.Settings['UpdateState'] on every run), and this endpoint reads that.
        #
        # 🔒 AN ENVIRONMENT THAT HAS NOT RECORDED ONE ANSWERS "not recorded yet". Never a default ring,
        # never the ring some other environment uses. A guessed ring is worse than a blank one, because
        # an operator would act on it.
        #
        # 🔒 READ-ONLY, PERMANENTLY. There is no PUT/POST counterpart and there must not be: moving an
        # environment between rings is an operator act, performed on the update job, in the operator's
        # own words. A button here would make a ring move a click.
        #
        # The version reported as RUNNING is this process's own (Get-PimSolutionVersion) -- the code
        # answering the request, which is the only version reading that needs no Azure call and cannot
        # be stale.
        # -------------------------------------------------------------------
        if ($path -eq '/api/update-ring' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                if (-not (Get-Command Get-PimUpdateStateVerdict -ErrorAction SilentlyContinue)) {
                    Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                        recorded = $false; readable = $false; ring = ''; ringLabel = 'not recorded'; state = 'unknown'
                        runningVersion = (Get-PimSolutionVersion)
                        message = 'This build of the Manager does not carry the update-state reader.'
                    })
                    return 200
                }
                $cs = ''
                try { $cs = Get-PimManagerStoreCs } catch { $cs = '' }
                # 🪤 "no store" and "no record" are DIFFERENT answers and must not collapse into one.
                # A Manager with no store cannot say anything about the ring; one with a store and no
                # record is telling the operator the updater has not reported yet. Both show as "not
                # recorded", but only the first says the store could not be read.
                $rec = $null
                if ("$cs".Trim()) { $rec = Read-PimUpdateState -ConnectionString $cs }
                $v = Get-PimUpdateStateVerdict -Record $rec -RunningVersion (Get-PimSolutionVersion)
                $body = [ordered]@{ readable = [bool]("$cs".Trim()); settingName = (Get-PimUpdateStateSettingName) }
                foreach ($p in $v.PSObject.Properties) { $body[$p.Name] = $p.Value }
                if (-not $body.readable -and -not $body.recorded) {
                    $body.message = 'The update state could not be read: this Manager has no SQL store wired, ' +
                                    'so the ring this environment is on is not known here.'
                }
                Write-JsonResponse -Response $resp -Status 200 -Body $body
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "update ring read failed: $($_.Exception.Message)" }
                return 500
            }
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
            # delivered ONLY to the recipient the admin row resolves to (DOC-17 g: forwarding override, else the sponsor department's owners), so the blast
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
                # recipient the row resolves to (DOC-17 g) and nowhere else -- not to the browser, not to the response,
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
            # AccountStatus by enable/disable) -- an allow-list, so a new column is not silently made
            # editable by adding it to the entity.
            # 🔴 71.23 -- AutoDisableDate IS editable here now (operator, 2026-09-16: "i need to have
            # this field on the admin overview so i cna devine an AutoDisableDate"). It was reachable
            # only through the approval-gated offboard ceremony, which is the right path for
            # "offboard this person NOW" but the wrong one for "this contract ends on the 30th".
            # Setting a FUTURE date changes nothing today; the engine acts when the date arrives, and
            # the only thing it does is DISABLE (PIM never deletes an account).
            $editable = @{
                autoDisableDate      = 'AutoDisableDate'
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
            # 🔴 71.23 -- an AutoDisableDate must be a date the ENGINE can read, checked here rather
            # than discovered by the sweep skipping the row weeks later. And writing it always CLEARS
            # the legacy OffboardDate: leaving both would create the exact conflict the engine refuses.
            if (-not $badField -and $changes.Contains('AutoDisableDate')) {
                $adv = "$($changes['AutoDisableDate'])".Trim()
                if ($adv) {
                    $parsed = $null
                    if (Get-Command Resolve-PimDateExpression -ErrorAction SilentlyContinue) { try { $parsed = Resolve-PimDateExpression -Expression $adv } catch { $parsed = $null } }
                    if (-not $parsed) { $parsed = Get-PimUtcStamp $adv }
                    if (-not $parsed) { $badField = "AutoDisableDate '$adv' is not a date the engine can read. Use yyyy-MM-dd (e.g. 2026-09-30) or a date expression such as FirstDayNextMonth." }
                }
                if (-not $badField -and "$($row.OffboardDate)".Trim()) {
                    $changes['OffboardDate'] = ''
                    $before['OffboardDate']  = "$($row.OffboardDate)".Trim()
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
            # DOC-16 a vs c (2.4.371): any WHOLE NUMBER is a ring -- the account editor offers a stored ring above 2 as
            # itself and the downlink publishes ^\d+$, so refusing 3+ here made saving such an admin fail.
            if (-not $badField -and $changes.Contains('Ring') -and "$($changes['Ring'])".Trim() -and "$($changes['Ring'])".Trim() -notmatch '^\d+$') {
                $badField = "Ring must be blank or a whole number (0, 1, 2, ...) (got '$($changes['Ring'])')."
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
            # 🔴 BUG-190 (operator decision 2026-09-18): an AutoDisableDate at or before NOW is not "this contract ends
            # on the 30th" -- it disables the account on the next tick, i.e. it IS an offboard. It used to be written
            # straight to pim.Rows, so one Admin could disable any in-scope admin with no snapshot, delta guard,
            # sensitive-change gate or second person. It now goes through the SAME approval gate as Offboard: the date
            # is NOT written; an offboard approval request is raised (maker) when a justification is supplied, and a
            # DIFFERENT administrator approves + executes it, which stages the disable for commit. A FUTURE date is
            # unchanged (it changes nothing today). Other fields in the same request are still saved.
            $modifyApproval = $null
            if ($changes.Contains('AutoDisableDate') -and (Test-PimModifyAutoDisableImmediate -Value "$($changes['AutoDisableDate'])")) {
                $heldDate = "$($changes['AutoDisableDate'])"
                [void]$changes.Remove('AutoDisableDate'); [void]$before.Remove('AutoDisableDate')
                if ($changes.Contains('OffboardDate')) { [void]$changes.Remove('OffboardDate'); [void]$before.Remove('OffboardDate') }
                # The SAME rule and outcome as the Review & Save PUT (Request-PimManagerOffboardHold).
                $modifyApproval = Request-PimManagerOffboardHold -Upn $upn -What "An AutoDisableDate of '$heldDate'" `
                                    -Justification "$($bodyIn.justification)" -Ticket "$($bodyIn.ticket)" -Requestor "$($role.identity)" -Via 'admin.modify autoDisableDate'
                $modifyApproval['heldAutoDisableDate'] = $heldDate
                Write-PimManagerAuditEvent -Action 'admin.modify.offboard-held' -Target $upn -Result $(if ($modifyApproval.approvalRaised) { 'ok' } else { 'denied' }) -After ([ordered]@{ heldAutoDisableDate = $heldDate; approvalRaised = [bool]$modifyApproval.approvalRaised; approvalId = "$($modifyApproval.approvalId)"; by = "$($role.identity)" })
                if ($changes.Count -eq 0) {
                    $st = if ($modifyApproval.approvalRaised) { 202 } else { 409 }
                    $outBody = [ordered]@{ ok = [bool]$modifyApproval.approvalRaised; changed = 0 }
                    foreach ($k in $modifyApproval.Keys) { $outBody[$k] = $modifyApproval[$k] }
                    Write-JsonResponse -Response $resp -Status $st -Body $outBody
                    return $st
                }
            }
            # Operator 2026-09-15: the MSP sync fields exist only on the MSP master. Refused, not ignored, so a caller that
            # bypasses the GUI (which hides them in Single and managed mode) is told why nothing changed.
            if (-not (Test-PimManagerIsMspMaster) -and @(@('ManagementMode', 'Ring', 'Target', 'Replicate') | Where-Object { $changes.Contains($_) }).Count) {
                Write-JsonResponse -Response $resp -Status 409 -Body @{ error = 'Sync to slaves (ManagementMode / Ring / Target) can only be set on the MSP master -- this tenant is not the master.'; code = 'not-msp-master' }
                return 409
            }
            # §71: a row that carries Replicate must keep AGREEING with ManagementMode (msp <-> Yes, local <-> No), or
            # the validator and the bundle refuse it. This editor has no Replicate field, so the switch flipped here
            # moves both, instead of leaving a contradiction for the next save to trip over.
            if ($changes.Contains('ManagementMode') -and "$($row.Replicate)".Trim()) {
                $before['Replicate'] = "$($row.Replicate)".Trim()
                $changes['Replicate'] = $(if ("$($changes['ManagementMode'])" -eq 'msp') { 'Yes' } else { 'No' })
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
            $modOut = [ordered]@{
                ok      = $true
                changed = $changes.Count
                fields  = @($changes.Keys)
                note    = 'Saved to the desired state. The engine applies it to the directory on its next run.'
            }
            if ($modifyApproval) {
                # BUG-190: the other fields were saved; the immediate AutoDisableDate was held for approval.
                foreach ($k in $modifyApproval.Keys) { if ($k -ne 'note') { $modOut[$k] = $modifyApproval[$k] } }
                $modOut['note'] = "Saved the other fields to the desired state. $($modifyApproval['note'])"
            }
            Write-JsonResponse -Response $resp -Status 200 -Body $modOut
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
            # 71.24: read the department -> owners index ONCE for the whole list, not per admin.
            # $null means "could not be read" and is carried through as "not checked" rather than
            # silently becoming "this department has no owners".
            $__deptIdx = $null
            if (Get-Command Get-PimManagerDepartmentOwnerIndex -ErrorAction SilentlyContinue) {
                try { $__deptIdx = Get-PimManagerDepartmentOwnerIndex } catch { $__deptIdx = $null }
            }
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
                # DOC-17 g: the TAP recipient is the per-admin forwarding override, else the sponsor DEPARTMENT's owners, else legacy ManagerEmail (§71.19, Get-PimAdminTapRecipient).
        $mgr = Get-PimAdminTapRecipient -Row $r
                # 🔴 71.23 -- AutoDisableDate (legacy name OffboardDate still read). The grid shows
                # the date, whether it came from the legacy column, and whether it has already passed,
                # so the operator can SEE what the engine will do and when.
                $offPlan = Get-PimAdminAutoDisableDate -Row $r
                $offboard = "$($offPlan.value)".Trim()
                $offUtc = if ($offboard) { Get-PimUtcStamp $offboard } else { $null }
                # 71.24: the sponsor department and ITS owners, from the same index the engine reads
                # (Get-PimManagerDepartmentOwnerIndex -> PIM-Definitions-Departments.Owners).
                # $__deptKnown is deliberately separate from "has owners": when the index cannot be
                # read at all, the screen must say "not checked", never "no owners" -- reporting a gap
                # that was never measured is how a screen trains people to ignore it.
                $__dept = "$($r.Department)".Trim()
                $__deptOwners = @()
                $__deptKnown = $false
                if ($__deptIdx -is [hashtable]) {
                    $__deptKnown = $true
                    if ($__dept -and $__deptIdx.ContainsKey($__dept.ToLowerInvariant())) {
                        # 🪤 Split-PimOwners lives in PIM-EngineProviders.ps1, which is NOT guaranteed to
                        # be dot-sourced in every Manager host. An unguarded call here would throw and take
                        # the WHOLE Admin accounts screen down with a 500 -- the exact failure mode this
                        # file already carries two notes about. Same separators as the engine: | ; ,
                        $__ownRaw = "$($__deptIdx[$__dept.ToLowerInvariant()])"
                        $__deptOwners = if (Get-Command Split-PimOwners -ErrorAction SilentlyContinue) {
                            @(Split-PimOwners -Value $__ownRaw)
                        } else {
                            @($__ownRaw -split '[|;,]' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
                        }
                    }
                }
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
                    # 🔴 §62 / 71.24 -- THE SPONSOR DEPARTMENT, ON THE OVERVIEW (operator 2026-09-16:
                    # "in the admin overview i need to see which sponsor dept an admin is linked to.
                    # this is considered the dept that sponsor him and define approval for example if
                    # he must be enabled/disabled"). The department is not decoration: it decides who
                    # approves for this admin and where its mail (including its TAP) goes. Both GAPS
                    # have to be visible, and they are DIFFERENT gaps -- "no department" is the admin's
                    # row, "department with no owners" is the department's row, and they are fixed in
                    # different places.
                    department        = $__dept
                    departmentOwners  = @($__deptOwners)
                    departmentKnown   = [bool]$__deptKnown
                    offboardDate      = $offboard      # kept for older cached pages
                    autoDisableDate   = $offboard
                    autoDisableSource = "$($offPlan.source)"          # auto | legacy | none
                    autoDisableLegacy = [bool]($offPlan.source -eq 'legacy')
                    autoDisableConflict = [bool]$offPlan.conflict
                    autoDisableWhy    = "$($offPlan.reason)"
                    # past  = the engine should already have disabled it (or is refusing to -- see the status)
                    # soon  = inside 14 days, so it is worth seeing before it happens
                    autoDisablePast   = [bool]($offUtc -and $offUtc -le [datetime]::UtcNow)
                    autoDisableSoon   = [bool]($offUtc -and $offUtc -gt [datetime]::UtcNow -and $offUtc -le [datetime]::UtcNow.AddDays(14))
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
                    resetTapWhy       = $(if ($isCentral) { 'central admin -- its TAP is governed by the MSP master' } elseif (-not $isAdmin) { 'Admin role required' } elseif (-not $tapWanted) { 'TargetPlatform=AD -- a TAP is an Entra credential and cannot exist for an AD-only admin' } elseif (-not $mgr) { 'no TAP recipient -- set the admin''s Department to one whose owners are defined (or a forwarding override); a TAP is only ever mailed to those people' } else { '' })
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
                # 71.21: the verb is "mark for manual removal" (retire), never "flag for deletion" --
                # PIM never deletes an account. canFlagDelete stays as an alias so a page cached from
                # an older version keeps working; both carry the same permission.
                canRetire         = [bool]$isAdmin
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
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Reader')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Reader role required.' }
                return 403
            }
            # REQ-F: whether a passphrase is configured (and where), so the card can say BEFORE an incident that an
            # activation would be refused. Never the passphrase, never its hash.
            $pp = Get-PimManagerEmergencyPassphraseStatus
            # §36.3 phase 3 -- the SHARED store, so this endpoint answers about the override the
            # engine will act on rather than about a file only this container can see.
            $ov = Get-PimManagerEmergencyOverride
            if (-not $ov) {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ active = $false; passphrase = $pp }
                return 200
            }
            try {
                $expired = $true
                try { $expired = ([datetime]::UtcNow -ge ([datetime]$ov.expiresAtUtc).ToUniversalTime()) } catch {}
                Write-JsonResponse -Response $resp -Status 200 -Body @{
                    active = [bool]($ov.active -and -not $expired); expired = $expired
                    activatedBy = "$($ov.activatedBy)"; activatedAtUtc = "$($ov.activatedAtUtc)"; expiresAtUtc = "$($ov.expiresAtUtc)"
                    reason = "$($ov.reason)"; scopeGroupTags = @($ov.scopeGroupTags); appliedGroups = @($ov.appliedGroups)
                    passphrase = $pp
                }
            } catch {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ active = $false; error = "$($_.Exception.Message)"; passphrase = $pp }
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
                # Every refused attempt is audited (a wrong passphrase is already audited inside Test-PimEmergencyPasscode
                # as emergency.passcode.failed; a lockout or a missing passphrase is audited here).
                if ("$($check.error)" -ne 'invalid passcode') {
                    Write-PimManagerAuditEvent -Action 'emergency.activate.refused' -Target 'emergency-override' -After @{ error = "$($check.error)" } -Result 'denied'
                }
                $ppErr = "$($check.error)"
                if ($ppErr -match '(?i)no emergency passcode configured') { $ppErr = 'no emergency passphrase is configured for this environment -- run tools/setup/Set-PimEmergencyPassphrase.ps1 (it stores PIM-EmergencyPasscode in the key vault and sets PIM_EmergencyVault on the Manager)' }
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = $ppErr }
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
            $ovWhere = ''
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
            # 🔴 BUG-185: say what is TRUE. The Manager only RECORDS the override (§65: it never writes the
            # directory); the ENGINE applies it -- approval off on the scoped groups -- and restores normal
            # policy at expiry (DESIGN §17.9). Nothing is in effect until that run, so the reply says QUEUED
            # and starts the engine now through the same mechanism a commit uses.
            $kick = $null
            try { $kick = Start-PimManagerTickNow -Reason 'emergency-override' } catch { $kick = $null }
            $kickDetail = if ($kick) { "$($kick.detail)" } else { 'on the next scheduled engine run' }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                ok            = $true
                queued        = $true
                inEffect      = $false
                store         = "$ovWhere"
                expiresAtUtc  = $ov.expiresAtUtc
                engineStarted = [bool]($kick -and $kick.started)
                note          = ("Emergency override RECORDED, not yet in effect. The engine applies it -- approval is switched off on the scoped groups -- " +
                                 "when it runs ($kickDetail), and restores the normal approval policy automatically at expiry. " +
                                 "Check Emergency status: 'appliedGroups' fills in once the engine has applied it.")
            })
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
            # BUG-185: the ENGINE restores the policy; start it now, same as activation, and say when it takes effect.
            $kickR = $null
            try { $kickR = Start-PimManagerTickNow -Reason 'emergency-restore' } catch { $kickR = $null }
            $kickRDetail = if ($kickR) { "$($kickR.detail)" } else { 'on the next scheduled engine run' }
            Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; queued = $true; engineStarted = [bool]($kickR -and $kickR.started)
                note = "Override expired in the store. The engine re-applies the normal approval policy when it runs ($kickRDetail) -- until then approval is still off on the groups it was lifted on." }
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
            # 🔴 BUG-193: this read cache/<instance>/*.json FILES, which _tenantSync stopped writing on 2026-09-13
            # (the caches are rows in pim.TenantCache now) -- so the list was always empty and looked like "nothing
            # new". It reads the SQL cache and the SQL baseline (pim.Settings 'DiscoveryBaseline'), and a cache that
            # has never been written is REPORTED, not shown as an empty result.
            $disc = Get-PimManagerDiscoveryCurrent
            $baseline = $null
            try { $baseline = Get-PimManagerSettingObject -Name 'DiscoveryBaseline' } catch {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ error = "discovery baseline could not be read: $($_.Exception.Message)" }
                return 503
            }
            $scopes = @($disc.scopes); $roles = @($disc.roles)
            if (-not $baseline) {
                Write-JsonResponse -Response $resp -Status 200 -Body @{
                    baselineMissing = $true
                    cacheMissing    = @($disc.missing)
                    currentCounts   = @{ azureScopes = $scopes.Count; entraRoles = $roles.Count }
                    newItems        = @()
                }
                return 200
            }
            $knownScopes = @($baseline.azureScopeIds | Where-Object { $_ })
            $knownRoles  = @($baseline.entraRoleIds | Where-Object { $_ })
            $newItems = @()
            foreach ($s in $scopes) { if ($knownScopes -notcontains "$($s.id)") { $newItems += @{ kind = "azure-$($s.type)"; id = "$($s.id)"; displayName = "$($s.displayName)"; scopePath = "$($s.scopePath)" } } }
            foreach ($r2 in $roles)  { if ($knownRoles -notcontains "$($r2.id)")  { $newItems += @{ kind = 'entra-role'; id = "$($r2.id)"; displayName = "$($r2.displayName)" } } }
            Write-JsonResponse -Response $resp -Status 200 -Body @{
                baselineMissing = $false
                baselineAtUtc   = "$($baseline.savedAtUtc)"
                cacheMissing    = @($disc.missing)
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
            # REQ-Y: Pro (hard) -- 403 with the licence line when this environment has no Pro licence.
            if (-not (Test-PimManagerProFeature -Key 'discovery.sweep' -Response $resp)) { return 403 }
            # BUG-193: acknowledge = snapshot the SQL tenant cache into pim.Settings 'DiscoveryBaseline' (it used to
            # write cache/<instance>/discovery-baseline.json on the container filesystem). A cache that was never
            # written is refused: acknowledging "nothing" would silently hide everything discovered later.
            $disc = Get-PimManagerDiscoveryCurrent
            if (@($disc.missing).Count -gt 0) {
                Write-JsonResponse -Response $resp -Status 409 -Body @{ ok = $false; cacheMissing = @($disc.missing)
                    error = "the tenant cache has never been refreshed for: $(@($disc.missing) -join ', ') -- refresh the tenant lists first, then acknowledge." }
                return 409
            }
            $scopes = @($disc.scopes); $roles = @($disc.roles)
            $baseline = [ordered]@{
                savedAtUtc    = [datetime]::UtcNow.ToString('o')
                azureScopeIds = @($scopes | ForEach-Object { "$($_.id)" })
                entraRoleIds  = @($roles | ForEach-Object { "$($_.id)" })
            }
            try { Set-PimManagerSettingObject -Name 'DiscoveryBaseline' -Value $baseline } catch {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ ok = $false; error = "the discovery baseline was NOT saved: $($_.Exception.Message)" }
                return 503
            }
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
            # REQ-Y: delegated administration (a SCOPED Manager user) is Pro (hard). Only a NEW or CHANGED 'Delegated'
            # grant is refused without a licence: every Reader / Admin / SuperAdmin edit, removing a Delegated user, and
            # re-saving an existing one unchanged all stay free -- nobody is locked out of their own access.
            $prevDelegated = @{}
            try {
                $prevMap = Get-PimManagerSetting -Name 'ManagerAccess'
                foreach ($pe in @(if ($prevMap -and $prevMap.PSObject.Properties['managerAccess']) { $prevMap.managerAccess } else { @() })) {
                    if ("$($pe.role)".Trim() -eq 'Delegated') { $prevDelegated["$($pe.identity)".Trim().ToLowerInvariant()] = $true }
                }
            } catch { }
            $newDelegated = @($clean | Where-Object { $_.role -eq 'Delegated' -and -not $prevDelegated.ContainsKey("$($_.identity)".ToLowerInvariant()) })
            if ($newDelegated.Count -and -not (Test-PimManagerProFeature -Key 'access.delegated' -Response $resp)) { return 403 }
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
                    # BUG-175 (GUI half, 2.4.371): the reach was planned with the master's copy of each ring.
                    ringSource  = "$($dlo.ringSource)"
                    ringNote    = "$($dlo.ringNote)"
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
                # The projection policy travels IN the signed bundle: a change requests a publish (master; never fails the save).
                try { [void](Request-PimManagerPublishAfterCommit -Base 'pim.TenantRoleProjection' -NotAnEntity) } catch { Write-Warning "  [publish] the projection policy was saved, but a publish could NOT be requested: $($_.Exception.Message)" }
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
            # REQ-Y: Pro (hard) -- 403 with the licence line when this environment has no Pro licence.
            if (-not (Test-PimManagerProFeature -Key 'discovery.sweep' -Response $resp)) { return 403 }
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
            # THE SELF-GATED MSP JOB (Get-PimManagerCadenceJob): on a managed tenant (S6) the 'msp-pull' row IS the pull's
            # cadence (DownlinkSchedule), not the tick catalog's placeholder; on a master a 'baseline-publish' row is added
            # (PublishSchedule). Each carries what the job recorded: last run + result, next due, a pending Run now.
            # Everywhere else the rows are exactly as before.
            $cadJob = Get-PimManagerCadenceJob
            $cadence = $null
            if ($cadJob) {
                $cadence = Get-PimManagerCadenceStatus -Job $cadJob
                $cdef = Get-PimJobCadenceDefinition -Job $cadJob
                $crow = [ordered]@{
                    name = "$($cdef.row)"; type = "$($cdef.type)"; scope = ''; label = "$($cdef.label)"; plain = "$($cdef.plain)"
                    enabled = [bool]$cadence.enabled; intervalMinutes = [int]$cadence.intervalMinutes; isMail = $false
                    selfGated = $true; minIntervalMinutes = [int]$cadence.minIntervalMinutes; maxIntervalMinutes = [int]$cadence.maxIntervalMinutes
                    cadence = $cadence
                }
                $idx = -1
                for ($i = 0; $i -lt $jobs.Count; $i++) { if ("$($jobs[$i].name)" -eq "$($cdef.row)") { $idx = $i; break } }
                if ($idx -ge 0) { $jobs[$idx] = $crow } else { [void]$jobs.Add($crow) }
            }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ jobs = @($jobs.ToArray()); customized = [bool]($stored)
                cadenceJob = "$cadJob"; cadence = $cadence; canRunNow = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin') })
            return 200
        }

        # ----- Run the self-gated MSP job now (the managed tenant's pull / the master's publish) -------------------
        # POST { name: 'msp-pull' | 'baseline-publish' }. Sets the job's Run-now flag in THIS tenant's store; the job runs
        # on its next trigger (every 5 minutes) -- even when it is disabled in the Job schedule, because this is an
        # explicit act. SuperAdmin only (the same role that sets the cadence), audited. Refused (409) where the job does
        # not run from this environment: a pull is a managed tenant's job, a publish is a master's.
        if ($path -eq '/api/job-schedule/run-now' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to run the pull / publish now.' }
                return 403
            }
            $body = Read-RequestJson -Request $req
            $name = "$($body.name)".Trim()
            $cadJob = Get-PimManagerCadenceJob
            if (-not $cadJob -or "$((Get-PimJobCadenceDefinition -Job $cadJob).row)" -ne $name) {
                $where = if ($name -eq 'msp-pull') { 'on a managed tenant (scenario S6) -- the pull runs in the managed tenant, not here' } elseif ($name -eq 'baseline-publish') { 'on the MSP master -- the publish runs there, not here' } else { 'for msp-pull (managed tenant) or baseline-publish (master)' }
                Write-JsonResponse -Response $resp -Status 409 -Body @{ error = "Run now for '$name' is only available $where." }
                return 409
            }
            $def = Get-PimJobCadenceDefinition -Job $cadJob
            try { $flag = Request-PimManagerCadenceRun -Job $cadJob -Reason 'Run now (Job schedule)' }
            catch {
                Write-PimManagerAuditEvent -Action 'schedule.cadence.runnow' -Target "job:$name" -Result 'error'
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "the Run-now flag could NOT be stored: $($_.Exception.Message)" }
                return 500
            }
            Write-PimManagerAuditEvent -Action 'schedule.cadence.runnow' -Target "job:$name" -After $flag -Result 'ok'
            $msg = "Requested: the $($def.verb) runs within $((Get-PimJobCadenceLimits).triggerMinutes) minutes (on the $($def.jobName) job's next trigger). Its result appears here when it has run."
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; name = $name; message = $msg; requested = $flag; cadence = (Get-PimManagerCadenceStatus -Job $cadJob) })
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
            # THE SELF-GATED MSP JOB's row (managed tenant: msp-pull; master: baseline-publish) is its own cadence
            # (DownlinkSchedule / PublishSchedule), validated 5-1440 min BEFORE anything is written, and never written into
            # 'JobSchedule' -- that is the tick's catalog, and its msp-pull row stays the tick's (disabled) placeholder.
            $cadJob = Get-PimManagerCadenceJob
            $cadDef = if ($cadJob) { Get-PimJobCadenceDefinition -Job $cadJob } else { $null }
            $cadIn = $null
            if ($cadDef) { $cadIn = @($raw | Where-Object { $_ -and "$($_.name)".Trim() -eq "$($cadDef.row)" }) | Select-Object -Last 1 }
            $cadNew = $null
            if ($cadIn) {
                $cur = Resolve-PimJobCadenceSchedule -Stored (Get-PimManagerSetting -Name $cadDef.scheduleKey)
                $cEn = [bool]$cur.enabled; $cIv = [int]$cur.intervalMinutes
                if ($cadIn.PSObject.Properties['enabled']) { $cEn = -not (Test-PimJobCadenceFalse $cadIn.enabled) }
                if ($cadIn.PSObject.Properties['intervalMinutes'] -and $null -ne $cadIn.intervalMinutes -and "$($cadIn.intervalMinutes)".Trim()) {
                    $vi = Test-PimJobCadenceInterval -Value $cadIn.intervalMinutes
                    if (-not $vi.ok) {
                        Write-JsonResponse -Response $resp -Status 400 -Body ([ordered]@{ ok = $false; name = "$($cadDef.row)"; error = "$($cadDef.label): $($vi.reason). Nothing was saved." })
                        return 400
                    }
                    $cIv = [int]$vi.value
                } elseif ($cadIn.PSObject.Properties['intervalMinutes']) {
                    Write-JsonResponse -Response $resp -Status 400 -Body ([ordered]@{ ok = $false; name = "$($cadDef.row)"; error = "$($cadDef.label): the interval is empty -- give 5-1440 minutes. Nothing was saved." })
                    return 400
                }
                # Only a CHANGE is stored: re-saving the page must not turn "nothing set (the daily default)" into a setting.
                if ($cEn -ne [bool]$cur.enabled -or $cIv -ne [int]$cur.intervalMinutes) {
                    $cadNew = [pscustomobject]@{ before = $cur; value = (New-PimJobCadenceScheduleValue -Enabled $cEn -IntervalMinutes $cIv -By (Get-PimManagerActorName)) }
                }
            }
            $merged = New-Object System.Collections.ArrayList
            foreach ($j in $raw) {
                $name = "$($j.name)".Trim()
                if ($cadDef -and $name -eq "$($cadDef.row)") { continue }   # the self-gated job's cadence is stored below, never in JobSchedule
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
            # 🪤 Only when the body carried catalog rows: a PUT of the cadence row alone must not wipe the tick's overrides.
            if ($merged.Count -gt 0 -or -not $cadIn) {
                Set-PimManagerSetting -Name 'JobSchedule' -Value @($merged.ToArray())
                $global:PIM_JobSchedule = @($merged.ToArray())   # live in-process runner picks it up
                Write-PimManagerAuditEvent -Action 'schedule.save' -Target "jobs:$($merged.Count)" -After @{ count = $merged.Count } -Result 'ok'
            }
            $cadOut = $null
            if ($cadNew) {
                Set-PimManagerSetting -Name $cadDef.scheduleKey -Value $cadNew.value
                Write-PimManagerAuditEvent -Action 'schedule.cadence.save' -Target "job:$($cadDef.row)" `
                    -Before @{ enabled = [bool]$cadNew.before.enabled; intervalMinutes = [int]$cadNew.before.intervalMinutes; source = "$($cadNew.before.source)" } `
                    -After @{ enabled = [bool]$cadNew.value.enabled; intervalMinutes = [int]$cadNew.value.intervalMinutes } -Result 'ok'
            }
            if ($cadJob) { $cadOut = Get-PimManagerCadenceStatus -Job $cadJob }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; count = $merged.Count; cadenceSaved = [bool]$cadNew; cadence = $cadOut })
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
        # -------------------------------------------------------------------
        # REQ-U (prereqs) -- GET /api/workload-prereqs (any role, read-only). Operator 2026-09-19: "refer to script in gui
        # and show with green if prereq has run". The last tools\setup\Initialize-PimWorkloadPrereqs.ps1 result per
        # workload (pim.Settings 'WorkloadPrereqs'), judged against NOW (older than 30 days = re-check), with the exact
        # command to run built from this environment's known values (placeholders for what the Manager cannot know --
        # never the operator's certificate). Only the script records a result, so there is no write endpoint.
        # A store that cannot be read is said as such -- never shown as "not run" (rule 7).
        # -------------------------------------------------------------------
        function Get-PimManagerWorkloadPrereqState {
            # The judged per-workload view + the store error; shared by /api/workload-prereqs and the /api/templates
            # assignment gate (REQ-W), so the chip and the held note can never disagree.
            $stored = $null; $storeErr = ''
            try { $stored = Get-PimManagerSettingObject -Name 'WorkloadPrereqs' } catch { $storeErr = "$($_.Exception.Message)" }
            $tick = "$env:PIM_TickJobId".Trim()
            if (-not $tick) { try { $tick = "$(Get-PimSetting -Name 'SchedulerTickJobId')".Trim().Trim('"') } catch { $tick = '' } }
            $tj = ConvertFrom-PimTickJobId -Id $tick
            $envVals = @{
                tenantId      = "$($global:PIM_TenantId)".Trim()
                sqlServerFqdn = $(if ("$($global:PIM_SqlServer)".Trim()) { "$($global:PIM_SqlServer)".Trim() } else { "$env:PIM_SqlServer".Trim() })
                sqlDatabase   = $(if ("$($global:PIM_SqlDatabase)".Trim()) { "$($global:PIM_SqlDatabase)".Trim() } else { "$env:PIM_SqlDatabase".Trim() })
            }
            if ($tj) { $envVals.subscriptionId = $tj.subscriptionId; $envVals.resourceGroup = $tj.resourceGroup; $envVals.tickJobName = $tj.jobName }
            $view = @(Get-PimWorkloadPrereqView -Stored $stored -Env $envVals -NowUtc ([datetime]::UtcNow) -StaleDays (Get-PimWorkloadPrereqStaleDays))
            if ($storeErr) { foreach ($v in $view) { $v.state = 'unreadable'; $v.chip = 'amber' } }
            return @{ view = $view; storeErr = $storeErr }
        }
        if ($path -eq '/api/workload-prereqs' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $__ps = Get-PimManagerWorkloadPrereqState
            $view = @($__ps.view); $storeErr = "$($__ps.storeErr)"
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                ok = (-not $storeErr); storeError = $storeErr; staleDays = (Get-PimWorkloadPrereqStaleDays)
                script = 'tools\setup\Initialize-PimWorkloadPrereqs.ps1'
                workloads = $view
                templateWorkloads = (Get-PimWorkloadPrereqTemplateMap)
                connectorWorkloads = (Get-PimWorkloadPrereqConnectorMap)
                # REQ-W: workloads whose assignment is never held (Entra), so the GUI's held note follows the server rule.
                ungatedWorkloads = @(Get-PimWorkloadPrereqUngated)
            })
            return 200
        }
        if ($path -eq '/api/templates' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            # REQ-X (2.4.381): the plan comes from engine\_shared\PIM-TemplatePacks.ps1 -- the SAME Get-PimTemplatePackPlan
            # tools\setup\Import-PimPermissionTemplate.ps1 uses -- so the GUI ADOPTS a pack group the store already defines
            # (same tag in another definition entity, or the same tenant GroupName under another tag) instead of offering a
            # second definition of it. Measured on internal 2026-09-19: the route's own copy offered 9 duplicate Intune
            # groups the script adopted. tests\Test-PimTemplateImport.ps1 B2 proves route == script for every shipped pack.
            # The tenant's group pattern as the Settings page stores it (pim.Settings['NamingConventions'] merged over
            # the shipped defaults) -- the Manager keeps it there, not flattened into $global:PIM_NamingConventions.
            $tenantGroupPattern = ''
            try { $__nc = Get-PimNamingConventions; if ($__nc) { $tenantGroupPattern = "$($__nc['PimGroupPattern'])" } } catch { $tenantGroupPattern = '' }
            $tplDir = Join-Path $solutionRoot 'templates'
            # Governance template active/disabled state (Set-PimManagerSetting 'TemplateState').
            $tplDisabled = ConvertTo-PimPlainHashtable (Get-PimManagerSetting -Name 'TemplateState')
            # REQ-W (2.4.380, operator 2026-09-19: "so enabling is per workload" / "but it should be possible to deploy
            # groups"): the v2.4.379 IMPORT gate is gone -- a pack is always stageable. What the server decides here is
            # which of the pack's workload ASSIGNMENTS the engine would hold (Get-PimTemplateAssignmentGate over the same
            # view the chips show); the GUI shows it as an amber note.
            $__ps = Get-PimManagerWorkloadPrereqState
            # The grid's entity list: a pack entity the grid does not know is skipped (Get-PimCsvSpec), as before.
            $__known = @(Get-PimTemplatePackKnownBases | Where-Object { Get-PimCsvSpec -BaseName $_ })
            # Each entity read at most once per request, shared by every pack (a pack only plans; nothing is written).
            $__rowsCache = @{}
            $__readBase = { param($b) if (-not $__rowsCache.ContainsKey($b)) { $__rowsCache[$b] = @((Read-PimRows -BaseName $b).rows) }; return $__rowsCache[$b] }
            # EVERY group definition entity, for ADOPTION -- exactly what the import script hands the plan.
            $__allDefs = New-Object System.Collections.Generic.List[object]
            foreach ($db in @($__known | Where-Object { "$_" -like 'PIM-Definitions-*' -and "$_" -ne 'PIM-Definitions-AU' })) {
                foreach ($r in @(& $__readBase $db)) { if ($null -ne $r) { $__allDefs.Add([pscustomobject]$r) } }
            }
            $outList = New-Object System.Collections.ArrayList
            if (Test-Path -LiteralPath $tplDir) {
                foreach ($f in (Get-ChildItem $tplDir -Filter '*.template.json' -File | Sort-Object Name)) {
                    try {
                        $tpl = Read-PimTemplatePack -Path $f.FullName
                        $current = @{}
                        foreach ($b in @(Get-PimTemplatePackBases -Pack $tpl -KnownBases $__known)) { $current[$b] = @(& $__readBase $b | ForEach-Object { [pscustomobject]$_ }) }
                        $plan = Get-PimTemplatePackPlan -Pack $tpl -CurrentRowsByBase $current -TenantGroupPattern $tenantGroupPattern -KnownBases $__known -ExistingDefinitionRows @($__allDefs.ToArray())
                        [void]$outList.Add([ordered]@{
                            id = "$($plan.id)"; name = "$($plan.name)"; version = $plan.version
                            description = "$($plan.description)"
                            totalRows = $plan.totalRows; missingCount = $plan.missingCount; missing = $plan.missing
                            # REQ-U wave 2 (design point 1): a group definition and its workload binding row(s) = ONE unit.
                            units = @($plan.units)
                            # §70.13: rows carrying the all-zero placeholder subscription are never offered.
                            placeholderRowsSkipped = $plan.placeholderSkipped
                            # Pack groups the store already defines; their rows were re-tagged to the store's tag.
                            adopted = @($plan.adopted)
                            disabled = [bool]($tplDisabled.ContainsKey("$($plan.id)") -and $tplDisabled["$($plan.id)"])
                            # REQ-W: which workload ASSIGNMENTS of this pack would be held -- never a refusal to stage.
                            assignmentGate = (Get-PimTemplateAssignmentGate -TemplateId "$($plan.id)" -View @($__ps.view) -StoreError "$($__ps.storeErr)")
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
                        # 🔴 BUG-203 (server half) -- guest onboarding was broken end to end: this returned the invitation
                        # BODY and nothing ever sent it (Send-PimGuestInvitation had no caller and used the Graph SDK),
                        # and the wizard "invited" the composed ADMIN name at the tenant's own domain. Now:
                        #   * the address must be an external mailbox -- not malformed, not in this tenant's own domain,
                        #     not an account the store already manages;
                        #   * the invitation is QUEUED as a 'guest-invite' ACTION (pending until committed in the Queue
                        #     tab; the ENGINE sends it -- the Manager never writes the directory, §65);
                        #   * the admin row + delegation are still returned as desired-state changes for Review & Save.
                        $giEmail = "$($b.email)".Trim()
                        $adminRowsGi = @()
                        try { $adminRowsGi = @((Read-PimRows 'Account-Definitions-Admins' -NoScope).rows) } catch { $adminRowsGi = @() }
                        $ownDomains = @($adminRowsGi | ForEach-Object { "$($_.UserPrincipalName)".Trim() } |
                                        Where-Object { $_ -match '@' -and $_ -notmatch '(?i)#EXT#' } | ForEach-Object { ($_ -split '@')[-1].ToLowerInvariant() } | Select-Object -Unique)
                        $extChk = Test-PimGuestEmailExternal -Email $giEmail -OwnDomains $ownDomains
                        if (-not $extChk.ok) { Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = "guest invitation refused: $($extChk.reason). Nothing was staged or queued." }; return 400 }
                        if (Resolve-PimManagedAccountRow -Rows $adminRowsGi -Account $giEmail) {
                            Write-JsonResponse -Response $resp -Status 409 -Body @{ ok = $false; error = "'$giEmail' is already a managed admin account in this store -- nothing was staged or queued." }; return 409
                        }
                        $plan = New-PimGuestOnboardingPlan -Email $giEmail -DisplayName "$($b.displayName)" `
                            -FirstName "$($b.firstName)" -LastName "$($b.lastName)" -Company "$($b.company)" `
                            -Department "$($b.department)" -Notes "$($b.notes)" -GroupTag "$($b.groupTag)" `
                            -AssignmentType $atype -NumOfDaysWhenExpire $days -Cloud $cloud `
                            -CustomMessage "$($b.customMessage)" -By "$($role.identity)"
                        if (-not $plan.ok) {
                            Write-JsonResponse -Response $resp -Status 400 -Body ([ordered]@{ ok = $false; mode = $plan.mode; invitation = $plan.invitation; changes = @(); count = 0; reason = $plan.reason; error = $plan.reason })
                            return 400
                        }
                        $inviteQueued = $false; $inviteQueueId = ''; $inviteNote = ''
                        $csGi = (Get-PimManagerStoreCs)
                        if ($csGi -and (Get-Command Add-PimSqlQueueChange -ErrorAction SilentlyContinue) -and (Get-Command New-PimGuestInviteAction -ErrorAction SilentlyContinue)) {
                            $act = New-PimGuestInviteAction -Invitation $plan.invitation -DisplayName "$($b.displayName)" -By "$(Get-PimManagerActor)"
                            Add-PimSqlQueueChange -ConnectionString $csGi -Change $act
                            $inviteQueued = $true; $inviteQueueId = "$($act.id)"
                            $inviteNote = "The invitation is QUEUED (not sent). It is sent by the engine after it is committed in the Queue tab. Save the staged account + delegation through Review & Save."
                            Write-PimManagerAuditEvent -Action 'onboarding.guest-invite.queued' -Target $giEmail -After @{ queueId = $inviteQueueId; groupTag = "$($b.groupTag)"; requestedBy = "$($role.identity)" }
                        } else {
                            $inviteNote = 'The invitation could NOT be queued (no SQL store / queue in this host) -- nothing will send it. The account + delegation changes are staged only.'
                        }
                        Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $plan.ok; mode = $plan.mode; invitation = $plan.invitation; changes = @($plan.changes); count = @($plan.changes).Count; reason = $plan.reason
                            inviteQueued = $inviteQueued; inviteQueueId = $inviteQueueId; note = $inviteNote })
                        return 200
                    }
                    '/api/onboarding/self-service-toggle' {
                        $action = "$($b.action)".Trim().ToLowerInvariant()
                        if ($action -notin @('enable','disable')) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "action must be 'enable' or 'disable'" }; return 400 }
                        # 🔴 BUG-202 (server half): resolve the named account (the picker sends the UPN) against the
                        # stored admin rows, so the change is keyed by the row's UserName and UPDATES it -- it used to be
                        # keyed by the UPN, match no row in the client, and stage a junk new account row.
                        $ssRows = @()
                        try { $ssRows = @((Read-PimRows 'Account-Definitions-Admins' -NoScope).rows) } catch {
                            Write-JsonResponse -Response $resp -Status 503 -Body @{ error = "the admin rows could not be read, so the account cannot be resolved: $($_.Exception.Message)" }; return 503
                        }
                        $res = Resolve-PimSelfServiceToggle -Profile $prof -AccountName "$($b.accountName)" -Action $action -IsSuperAdmin:$isSuper -By "$($role.identity)" -Rows $ssRows
                        if ($res.notFound) { Write-JsonResponse -Response $resp -Status 404 -Body @{ error = $res.reason }; return 404 }
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
        # Per-instance: ring = the template-catalog ring (BUG-179), applied version + exemptions are
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
            # 🔴 BUG-179 (operator decision 2026-09-18): the template-catalog ring is this environment's PLATFORM
            # UPDATE RING, inverted (tenantRing = 2 - updateRing; not recorded / invalid -> 0, most restrictive). It
            # used to be Get-PimTenantRing -- $global:PIM_TenantRing / pim.Settings['TenantRing'] -- which nothing
            # hosted sets, so every hosted Manager ran the catalog at ring 0 without saying why. Get-PimTenantRing is
            # left alone: it also drives the admin<->tenant ring filter, a different axis.
            $confRingInfo = $null
            if (Get-Command Get-PimTemplateCatalogRing -ErrorAction SilentlyContinue) {
                $updRec = $null
                if ((Get-Command Read-PimUpdateState -ErrorAction SilentlyContinue) -and "$($script:PimSqlCs)".Trim()) { $updRec = Read-PimUpdateState -ConnectionString $script:PimSqlCs }
                $confRingInfo = Get-PimTemplateCatalogRing -ConnectionString "$($script:PimSqlCs)" -UpdateStateRecord $updRec
            } else {
                $confRingInfo = [pscustomobject]@{ ring = 0; source = 'not recorded'; updateRing = ''; reason = 'the template-ring resolver is not loaded -- most restrictive template ring 0' }
            }
            $confRing = [int]$confRingInfo.ring
            $confRingSource = "$($confRingInfo.source)"
            $confRingReason = "$($confRingInfo.reason)"
            # SEC-17: reads SQL pim.Settings['ConformanceExemptions'] only, and NEVER the
            # shipped sample. See Get-PimManagerConformanceExemptions for why the
            # sample fallback was a live waiver rather than a convenience.
            $readEx = { @(Get-PimManagerConformanceExemptions) }
            # BUG-180 / IMP-37: the shipped template FILES are read-only (they ship with the image and are
            # replaced by every update). This finds one SHIPPED template by id -- approvals and ring promotions
            # are recorded over it in SQL (pim.Settings 'ConformanceTemplateOverlay'), never written back.
            $findShippedTpl = {
                param($Id)
                $hit = @(Read-PimApprovedTemplates -SourceDir $confTplDir -IncludeDrafts -NoOverlay -WarningAction SilentlyContinue | Where-Object { "$($_.templateId)" -eq "$Id" })
                if ($hit.Count) { return $hit[0] }
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
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ instance = $confTenant; tenantRing = $confRing; tenantRingSource = $confRingSource; tenantRingReason = $confRingReason; templates = $rows.ToArray() })
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
                    status = "$($tpl.status)"; tenantRing = $confRing; tenantRingSource = $confRingSource; tenantRingReason = $confRingReason; appliedVersion = $applied; behind = $c.Behind
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
                # BUG-180: approvedBy is WHO IS SIGNED IN, never a value the request body names -- a waiver's
                # approver is evidence, and a body field let anyone record anyone.
                $cand = [pscustomobject]@{
                    tenantId = $confTenant; templateId = "$($b.templateId)"; itemKey = "$($b.itemKey)"
                    reason = "$($b.reason)"; approvedBy = "$((Get-PimManagerRole).identity)"
                    approvedUtc = ([datetime]::UtcNow).ToString('o'); expiresUtc = "$($b.expiresUtc)"
                }
                $v = Test-PimExemptionValid -Exemption $cand -NowUtc ([datetime]::UtcNow)
                if ($v.state -eq 'Invalid') { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = ("exemption rejected: {0}" -f $v.detail) }; return 400 }
                $list = New-Object System.Collections.Generic.List[object]
                foreach ($e in (& $readEx)) { $list.Add($e) }
                $list.Add($cand)
                [void](Set-PimManagerConformanceExemptions -Exemptions $list.ToArray())
                Write-PimManagerAuditEvent -Action 'conformance.exemption.add' -Target ("{0}/{1}" -f $cand.templateId, $cand.itemKey) -After @{ instance = $confTenant; reason = "$($cand.reason)"; expiresUtc = "$($cand.expiresUtc)"; approvedBy = "$($cand.approvedBy)" }
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; state = $v.state; count = $list.Count; approvedBy = "$($cand.approvedBy)" }
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
                    instance = $confTenant; tenantRing = $confRing; tenantRingSource = $confRingSource; tenantRingReason = $confRingReason; template = $tidF
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
                $tpl = & $findShippedTpl "$($b.templateId)"
                if (-not $tpl) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'unknown template' }; return 400 }
                # 🔴 BUG-180: approve used to REWRITE the shipped template file (ephemeral in the container, gone on
                # the next update, and against the SQL-only rule) and took approvedBy from the request body. The
                # approval is now a SQL overlay bound to THIS template version, and the approver is the signed-in
                # identity -- nothing on the filesystem changes.
                $by = "$((Get-PimManagerRole).identity)".Trim()
                if (-not $by) { Write-JsonResponse -Response $resp -Status 401 -Body @{ error = 'no authenticated identity -- an approval must name its approver' }; return 401 }
                try { $appr = Set-PimTemplateOverlayApproval -Template $tpl -ApprovedBy $by -NowUtc ([datetime]::UtcNow) }
                catch { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "$($_.Exception.Message)" }; return 400 }
                Write-PimManagerAuditEvent -Action 'conformance.template.approve' -Target "$($tpl.templateId)" -After @{ templateVersion = [int]("$($tpl.templateVersion)" -as [int]); approvedBy = $by; store = 'sql' }
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; status = "$($appr.status)"; approvedBy = $by; templateVersion = [int]("$($tpl.templateVersion)" -as [int]) }
                return 200
            }

            if ($path -eq '/api/conformance/promote' -and $method -eq 'POST') {
                if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) { Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required' }; return 403 }
                $b = Read-RequestJson -Request $req
                $tpl = & $findShippedTpl "$($b.templateId)"
                if (-not $tpl) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'unknown template' }; return 400 }
                $ringIn = 0
                if (-not [int]::TryParse("$($b.ring)", [ref]$ringIn) -or $ringIn -lt 0 -or $ringIn -gt 9) {
                    Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "ring must be an integer 0..9 (got '$($b.ring)')" }; return 400
                }
                try {
                    # 🔴 BUG-180: a ring promotion is recorded in SQL (pim.Settings 'ConformanceTemplateOverlay') and
                    # merged over the shipped file on every read. It used to edit the shipped file in place (BUG-06's
                    # text-preserving edit), which on a container is gone on the next revision and is file state in a
                    # SQL-only product.
                    [void](Set-PimTemplateOverlayRing -Template $tpl -Key "$($b.key)" -Ring $ringIn)
                    Write-PimManagerAuditEvent -Action 'conformance.template.promote' -Target ("{0}/{1}" -f $tpl.templateId, $b.key) -After @{ ring = $ringIn; by = "$((Get-PimManagerRole).identity)"; store = 'sql' }
                    Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; key = "$($b.key)"; ring = $ringIn }
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
                # 🔴 BUG-180 / IMP-37 -- THE MANAGER DOES NOT WRITE THE DIRECTORY (§65). Deploy used to write a temp CSV
                # and call Apply-PimWorkloadAssignments -- a v1 function defined nowhere in v2, so every deploy was a
                # 502 -- i.e. it tried to run the engine inside the Manager. The roll-forward rows are now DESIRED
                # STATE: merged into PIM-Assignments-Workloads through the same safe-commit path as Review & Save
                # (snapshot, replication gate, delta guard, audit), and the engine's workload provider applies them
                # on its next run (started now, as a commit does).
                $wlBase = 'PIM-Assignments-Workloads'
                try {
                    $rows = @(Get-PimRollForwardRows -Template $tpl -TenantRing $confRing -TenantId $confTenant -Exemptions (& $readEx) -NowUtc ([datetime]::UtcNow))
                    if (-not $rows.Count) { Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; whatIf = $whatIf; rows = @(); message = 'no in-scope, non-exempt entries for this ring' }; return 200 }
                    $curWl = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $wlBase)
                    $plan = Get-PimRollForwardCommitPlan -Current $curWl -RollForward $rows -Base $wlBase
                    if (@($plan.conflicts).Count -gt 0) {
                        Write-JsonResponse -Response $resp -Status 409 -Body ([ordered]@{ ok = $false; gate = 'row-key-conflict'; conflicts = @($plan.conflicts)
                            error = "$(@($plan.conflicts).Count) roll-forward row(s) would overwrite a DIFFERENT existing workload binding stored under the same key -- nothing was written. Resolve them in the grid first." })
                        return 409
                    }
                    if ($whatIf) {
                        Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; whatIf = $true; rows = @($rows); adds = @($plan.adds).Count; alreadyPresent = @($plan.present).Count
                            message = 'Preview only -- nothing was written. Deploy commits the rows to the desired state; the engine applies them on its next run.' })
                        return 200
                    }
                    $tv = [int]("$($tpl.templateVersion)" -as [int])
                    $commitRes = $null; $wlDiff = $null
                    if (@($plan.adds).Count -gt 0) {
                        $newWl = @($plan.rows)
                        if (Get-Command Test-PimReplicationWriteAllowed -ErrorAction SilentlyContinue) {
                            $repTags = @{ known = $false; tags = @() }
                            try { $repTags = Get-PimManagerKnownTenantTags } catch { }
                            $repGate = Test-PimReplicationWriteAllowed -Entity $wlBase -Rows $newWl -CurrentRows $curWl -IsMaster (Test-PimManagerIsMspMaster) -KnownTags @($repTags.tags) -TagsKnown:([bool]$repTags.known)
                            if (-not $repGate.allowed) {
                                Write-JsonResponse -Response $resp -Status 409 -Body ([ordered]@{ ok = $false; gate = 'replication'; error = "$($repGate.reason)"; refused = @($repGate.refused) })
                                return 409
                            }
                        }
                        $wlDiff = Compare-PimRowSets -Before $curWl -After $newWl -Base $wlBase
                        $wlSpec = Get-PimCsvSpec -BaseName $wlBase
                        $commitRes = Invoke-PimManagerSafeCommit -Base $wlBase -NewRows $newWl -Current @{ rows = $curWl; header = $(if ($wlSpec) { @($wlSpec.defaultHeader) } else { @() }) } -SqlMode $true
                        Write-PimMutationLog -BaseName $wlBase -Adds @($wlDiff.adds).Count -Removes @($wlDiff.removes).Count -Modifies @($wlDiff.modifies).Count -NewRowCount $newWl.Count -Diff $wlDiff `
                            -Summary ("template '{0}' v{1} rolled forward (ring {2}): {3} binding(s) added to the desired state" -f $tpl.templateId, $tv, $confRing, @($plan.adds).Count)
                        try { [void](Start-PimManagerTickNow -Reason "conformance-deploy:$($tpl.templateId)") } catch { }
                    }
                    # The version stamp records what was COMMITTED as desired state (the engine applies it).
                    Set-PimTemplateState -TenantId $confTenant -TemplateId "$($tpl.templateId)" -Version $tv -AppliedBy "$((Get-PimManagerRole).identity)" -NowUtc ([datetime]::UtcNow) | Out-Null
                    # Stamp THIS tenant's rollout ring in the state document so the fleet
                    # matrix ([H8]) can read the ring of an instance it is not the
                    # active one for. Best-effort; never blocks the deploy -- but not silent.
                    try { [void](Set-PimTemplateStateRing -TenantId $confTenant -Ring ([int]$confRing)) }
                    catch { Write-Warning "  [conformance] ring stamp NOT saved: $($_.Exception.Message)" }
                    Write-PimManagerAuditEvent -Action 'conformance.template.deploy' -Target "$($tpl.templateId)" -After @{ templateVersion = $tv; tenantRing = $confRing; tenantRingSource = $confRingSource; tenantRingReason = $confRingReason; added = @($plan.adds).Count; alreadyPresent = @($plan.present).Count }
                    Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                        ok = $true; whatIf = $false; queued = $true; rows = @($rows)
                        added = @($plan.adds).Count; alreadyPresent = @($plan.present).Count
                        snapshotId = $(if ($commitRes) { "$($commitRes.snapshotId)" } else { '' })
                        note = $(if (@($plan.adds).Count) { "Committed $(@($plan.adds).Count) workload binding(s) to the desired state. The engine applies them on its next run -- nothing in the tenant has changed yet." } else { 'Every in-scope binding is already in the desired state; nothing to commit.' })
                    })
                    return 200
                } catch { Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }; return 500 }
            }

            # --- FLEET conformance matrix (REQUIREMENTS.md s28 [H8]) -----------------
            # The single-tenant /api/conformance answers "how far behind is THIS tenant?".
            # An MSP needs the cross-fleet view: tenants x templates, behind-by-N, in one
            # place. Builds it from the template-state document (SQL pim.Settings['ConformanceTemplateState'])
            # (per-instance applied version + ring) and feeding them into the pure
            # Get-PimFleetConformance. The active instance contributes its template-catalog ring (BUG-179)
            # (update ring inverted); other instances use the ring stamped in the state document
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
                    activeInstance = $confTenant; activeRing = $confRing; activeRingSource = $confRingSource; activeRingReason = $confRingReason
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
                    activeRing = $confRing; activeRingSource = $confRingSource; activeRingReason = $confRingReason
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
            if ($name -eq "$script:PimInstanceName") {
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; active = $script:PimInstanceName; changed = $false })
                return 200
            }
            # 🔴 IMP-49 l: the instance is PROCESS state -- switching it re-points the store for EVERY request this
            # process serves. On a hosted Manager that is every signed-in user at once: one SuperAdmin's dropdown
            # silently moved everyone else's grid, commits and audit onto another database mid-session. A hosted
            # Manager is bound to its configured database; switching is for the single-operator LOCAL console.
            if ($script:PimHosted) {
                Write-JsonResponse -Response $resp -Status 409 -Body @{ ok = $false; error = "A hosted Manager is bound to its configured database ($($script:PimInstanceName)) for every signed-in user; it cannot be switched from one session. Use the Manager deployed for '$name', or the local console." }
                return 409
            }
            try {
                $fromInst = "$script:PimInstanceName"
                Set-PimManagerInstance -Name $name
                Write-PimManagerAuditEvent -Action 'manager.instance.switch' -Target "$name" -Before @{ instance = $fromInst } -After @{ instance = "$script:PimInstanceName" }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; active = $script:PimInstanceName; changed = $true })
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
            # REQ-Y ("revoke is pro", hard): preview and commit both -- the current-delegations LIST stays free.
            if (-not (Test-PimManagerProFeature -Key 'revoke.current' -Response $resp)) { return 403 }
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

        # -------------------------------------------------------------------
        # REQ-I + REQ-U -- COVERAGE & GAPS page.
        #   GET  /api/coverage        -> the STORED coverage report (pim.TenantCache 'coverage-report', written by the scheduler
        #                                job 'coverage'). Any role: it lists roles / scopes / groups and their delegations.
        #   POST /api/coverage/check  -> Admin+: queue a 'coverage' trigger (read back) and start the tick. Audited. The
        #                                Manager NEVER computes the report (it reads Power BI / Graph in the scheduler).
        # Staging a proposal is the GUI's own pending-changes path (the normal review / commit), not an endpoint here.
        # -------------------------------------------------------------------
        if ($path -eq '/api/coverage' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command ConvertTo-PimCoverageView -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ ok = $false; supported = $false; error = 'the coverage report reader (engine/_shared/PIM-Coverage.ps1) is not loaded in this Manager.' }
                return 503
            }
            try {
                Write-JsonResponse -Response $resp -Status 200 -Body (Get-PimCoverageCached)
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; supported = $true; error = "the stored coverage report could not be read: $($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/coverage/check' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to queue a new coverage check. Roles are stored in SQL -- ask a SuperAdmin to grant you access.' }
                return 403
            }
            # REQ-Y: Coverage & gaps is Pro (hard) -- the coverage job is inert without a licence, so a check is refused here.
            if (-not (Test-PimManagerProFeature -Key 'coverage.gaps' -Response $resp)) { return 403 }
            if (-not (Get-Command Request-PimCoverageRefresh -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ ok = $false; queued = $false; error = 'the coverage report reader (engine/_shared/PIM-Coverage.ps1) is not loaded in this Manager.' }
                return 503
            }
            try {
                $body = Get-PimCoverageCached -QueueRefresh -Reason 'manager-check'
                try { Write-PimManagerAuditEvent -Action 'coverage.check.queued' -Target 'coverage' -After @{ queued = [bool]$body.refreshQueued; error = "$($body.refreshError)" } -Result $(if ($body.refreshQueued) { 'ok' } else { 'failed' }) } catch { Write-Warning "coverage check: the audit event could not be written: $($_.Exception.Message)" }
                if ($body.refreshQueued -and (Get-Command Start-PimManagerTickNow -ErrorAction SilentlyContinue)) {
                    $kick = $null
                    try { $kick = Start-PimManagerTickNow -Reason 'coverage-check' } catch { $kick = $null }
                    if ($kick -and $kick.PSObject.Properties['detail']) { $body['tickStart'] = "$($kick.detail)" }
                }
                $st = if ($body.refreshQueued) { 202 } else { 500 }
                Write-JsonResponse -Response $resp -Status $st -Body $body
                return $st
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; queued = $false; error = "the coverage check could not be queued: $($_.Exception.Message)" }
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
            # 🔴 BUG-205 -- THE MANAGER NEVER RUNS THE ENGINE (§22 / §65 / §70.1b). This handler used to call
            # Invoke-PimEngine twice INSIDE the web process -- a full WhatIf plan over every scope and then a real
            # apply -- which put tenant writes on the Manager's single request thread, and only worked at all when
            # an earlier page happened to lazy-import the engine (no provider is registered in the Manager, so it
            # was otherwise dead). "Apply now" now ROUTES THE WORK TO THE ENGINE, exactly like Run now: it queues
            # an engine reconcile trigger for the scheduler and starts the tick. The engine re-reads the desired
            # state and corrects create/update drift under its own identity. Removing an EXTRA is not something a
            # scheduled reconcile does (it never prunes), so a removal is refused here and pointed at the queued
            # revoke path instead of being silently dropped.
            # 🔒 Portal scope: the reconcile is tenant-wide, so a caller whose Manager access is SCOPED by a portal
            # profile (a delegated admin) may not start it -- it would act far outside their delegation.
            $callerScopeD = Get-PimManagerCallerScope
            if (-not $callerScopeD.isSuperAdmin -and $callerScopeD.profile) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ ok = $false; gate = 'scope'; error = 'Your Manager access is scoped to part of the estate; drift remediation reconciles the whole tenant, so it needs an unscoped Admin or a SuperAdmin.' }
                return 403
            }
            $b = Read-RequestJson -Request $req
            $selectKeys = @(); if ($b -and $b.selectKeys) { $selectKeys = @($b.selectKeys | ForEach-Object { "$_" }) }
            $selAll     = [bool]($b -and $b.all)
            $allowRemove = [bool]($b -and $b.allowRemove)
            if (-not $selAll -and $selectKeys.Count -eq 0) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = 'select at least one drift item (selectKeys) or all=true.' }
                return 400
            }
            if ($allowRemove) {
                Write-JsonResponse -Response $resp -Status 409 -Body @{ ok = $false; gate = 'no-prune'
                    error = 'Removing an EXTRA (live access with no desired row) is not done from the Drift page: the engine reconcile never prunes. Revoke it from Maintenance & Revoke (a queued, audited action), or add the missing desired row if it should stay. Nothing was queued.' }
                return 409
            }
            $who = try { (Get-PimManagerRole).identity } catch { '' }
            $queuedD = $false; $qErrD = ''
            if (Get-Command Add-PimJobTrigger -ErrorAction SilentlyContinue) {
                try { [void](Add-PimJobTrigger -Type 'engine-delta' -Scope 'All' -Reason "drift-remediate:$who"); $queuedD = $true } catch { $qErrD = "$($_.Exception.Message)" }
            } else { $qErrD = 'the scheduler trigger queue is not loaded in this Manager' }
            Write-PimManagerAuditEvent -Action 'governance.drift.remediate.queued' -Target $(if ($selAll) { 'all' } else { "selected=$($selectKeys.Count)" }) `
                -After ([ordered]@{ selectKeys = @($selectKeys); all = $selAll; queued = $queuedD; error = $qErrD; by = $who }) -Result $(if ($queuedD) { 'ok' } else { 'error' })
            if (-not $queuedD) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ ok = $false; error = "The engine reconcile could not be queued: $qErrD. Nothing was changed." }
                return 503
            }
            $kickD = $null
            try { $kickD = Start-PimManagerTickNow -Reason 'drift-remediate' } catch { $kickD = $null }
            Write-JsonResponse -Response $resp -Status 202 -Body ([ordered]@{
                ok = $true; queued = $true; status = 'queued'; mode = 'engine-delta'
                selected = $(if ($selAll) { 'all' } else { $selectKeys.Count })
                engineStarted = [bool]($kickD -and $kickD.started)
                detail = ("Queued an engine reconcile (trigger:engine-delta:All){0}. The engine re-applies the desired state -- which corrects the selected create/update drift -- under its own identity; refresh the drift check afterwards to confirm. The Manager never changes the tenant itself." -f $(if ($kickD) { " -- $($kickD.detail)" } else { '' }))
            })
            return 202
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
            # BUG-198: preview against the SAME slice the caller was given and the commit merges into -- diffing a
            # scoped caller's slice against the whole entity previewed every out-of-scope row as a removal.
            $current = @{ source = 'sql'; rows = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $base) }
            $current.rows = @((Get-PimManagerVisibleSlice -Base $base -Rows @($current.rows)).rows)
            $diff = Compare-PimRowSets -Before $current.rows -After $rowsOrdered -Base $base
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                base     = $base
                source   = $current.source
                adds     = $diff.adds
                removes  = $diff.removes
                modifies = $diff.modifies
                unchanged = $diff.unchanged
                # BUG-204 (2.4.371): the Review preview names the keys the commit will refuse (rows that would collapse).
                duplicateKeys = @($(if (Get-Command Get-PimDuplicateStoreKeys -ErrorAction SilentlyContinue) { @(Get-PimDuplicateStoreKeys -Base $base -Rows @($rowsOrdered)) }))
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
