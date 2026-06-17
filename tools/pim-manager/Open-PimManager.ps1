#Requires -Version 5.1
<#
.SYNOPSIS
    Open the PIM4EntraPS graph mapper (v0.2 -- editor).

.DESCRIPTION
    Reads the 14 Definition + Assignment CSVs under SOLUTIONS/PIM4EntraPS/config/,
    transforms them into a node/edge JSON model, and serves them through a
    local HTTP API to a small single-page editor.

    Two run modes:

      -Server (default)
          Starts a localhost-only HttpListener on a random free port,
          serves the SPA, exposes REST endpoints for grid editing and
          save-back. The server lives only while the browser tab is open
          (30-second heartbeat timeout) and only accepts requests carrying
          a per-session bearer token generated at launch.

      -StaticHtml
          Preserves the v0.1 behaviour: bakes the JSON into the HTML and
          writes it to a temp file (or -OutHtml). No server, no edit
          capability, no token. Useful for archival snapshots.

    All writes go to <base>.custom.csv (the customer-override file, gitignored).
    The shipped <base>.locked.csv is never touched.

.PARAMETER Server
    Default. Start the local editor server.

.PARAMETER StaticHtml
    Render the v0.1-style static HTML and open it (read-only viewer).

.PARAMETER OutHtml
    Only honoured under -StaticHtml. Optional path for the rendered HTML.
    Defaults to a temp file.

.PARAMETER NoLaunch
    Don't open the browser. Print the URL (server mode) or path (static
    mode) to stdout. Useful for headless / smoke tests.

.PARAMETER Port
    Force a specific port instead of picking a random free one. The
    server still binds to 127.0.0.1 only. Optional.

.EXAMPLE
    .\Open-PimManager.ps1
    # Default: server mode, random port, opens browser.

.EXAMPLE
    .\Open-PimManager.ps1 -StaticHtml -NoLaunch -OutHtml C:\temp\snap.html

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
#>
[CmdletBinding(DefaultParameterSetName='Server')]
param(
    [Parameter(ParameterSetName='Server')]
    [switch]$Server,

    [Parameter(ParameterSetName='Static')]
    [switch]$StaticHtml,

    [Parameter(ParameterSetName='Static')]
    [string]$OutHtml,

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

    # MSP / multi-instance support. An "instance" is one customer's PIM4EntraPS
    # data set: a config root (the 14 CSVs + NamingConventions files) and its
    # sibling output folder. Instances are declared in
    # tools/pim-manager/instances.custom.json (gitignored):
    #   { "instances": [ { "name": "customerA", "configRoot": "E:\\msp\\customerA\\PIM4EntraPS\\config" } ] }
    # The solution's own config/ folder is always available as instance 'local'.
    # -Instance picks the active instance at startup; the UI can switch at
    # runtime via the instance dropdown (server mode only).
    [string]$Instance,

    # Ad-hoc instance: point the Manager at any config folder directly without
    # declaring it in instances.custom.json. Wins over -Instance.
    [string]$ConfigRoot,

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
$instancesFile = Join-Path $PSScriptRoot 'instances.custom.json'

# Shared date-expression resolver (engine/_shared/PIM-DateExpression.ps1) --
# powers the /api/resolve-date live preview; the validator dot-sources the
# same file so GUI, validator and engine agree.
$_dateExprLib = Join-Path $solutionRoot 'engine\_shared\PIM-DateExpression.ps1'
if (Test-Path -LiteralPath $_dateExprLib) { . $_dateExprLib }

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

# Alert FEED + recorded-send proof (engine/_shared/PIM-AlertFeed.ps1, REQUIREMENTS
# §26c / §28 [H2] + the [M5] residual). The PUSH side of the dashboard: every fired
# alert is recorded (when / which event / who was notified / whether delivery was
# recorded), so a break-glass "owners notified" claim is verifiable. Pure core +
# JSONL file adapter; dot-sourced standalone so the feed works without SQL.
$_alertFeedLib = Join-Path $solutionRoot 'engine\_shared\PIM-AlertFeed.ps1'
if (Test-Path -LiteralPath $_alertFeedLib) { . $_alertFeedLib }

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
$script:CurrentRequestPrincipal = $null

function Get-PimEasyAuthPrincipal {
    # The Entra-authenticated caller from App Service Easy Auth. ONLY trusted in
    # hosted mode (App Service injects + strips these headers at the edge; trusting
    # them locally would let any client spoof identity). Returns '' when absent.
    param([Parameter(Mandatory)][System.Net.HttpListenerRequest]$Request)
    if (-not $script:PimHosted) { return '' }
    foreach ($h in 'X-MS-CLIENT-PRINCIPAL-NAME','X-MS-CLIENT-PRINCIPAL-IDP') {
        $v = $Request.Headers[$h]; if ("$v".Trim() -and $h -eq 'X-MS-CLIENT-PRINCIPAL-NAME') { return "$v".Trim() }
    }
    return ''
}

# ---------------------------------------------------------------------------
# Manager RBAC (LIFECYCLE-GOVERNANCE phase 7) -- Reader / Admin / SuperAdmin.
# Identity = the Windows user running the Manager (it binds to localhost).
# config/manager-access.custom.json: [ { "identity": "DOMAIN\\user", "role":
# "Reader|Admin|SuperAdmin" } ]. Missing file = the launcher is SuperAdmin
# (backward-compatible single-operator install); file present + identity not
# listed = Reader. The server is the enforcement boundary; the GUI only
# hides what the role cannot do.
# ---------------------------------------------------------------------------

function Get-PimManagerRole {
    # Hosted: the Easy Auth principal captured for THIS request. Local: Windows user.
    $who = if ($script:PimHosted -and "$script:CurrentRequestPrincipal".Trim()) { "$script:CurrentRequestPrincipal" }
           else { try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME } }
    if ($script:PimHosted -and -not "$who".Trim()) {
        # hosted with no authenticated principal = no Easy Auth in front -> deny.
        return @{ role = 'Reader'; identity = '<unauthenticated>'; source = 'hosted: no Easy Auth principal (fail closed)' }
    }
    # Hosted role config via env (SQL-only deployments ship NO manager-access file):
    #   PIM_SuperAdmins / PIM_Admins = comma list of identities (UPN/email)
    #   PIM_HostedDefaultRole        = role for any OTHER authenticated user (default: Reader)
    if ($script:PimHosted) {
        $whoLc  = "$who".ToLowerInvariant()
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
    }
    $f = Join-Path $script:configRoot 'manager-access.custom.json'
    if (-not (Test-Path -LiteralPath $f)) {
        # Local single-operator install -> SuperAdmin (backward-compatible). HOSTED
        # multi-user -> fail closed to Reader (an implicit SuperAdmin for every
        # authenticated business user would be a tenant-takeover hole).
        if ($script:PimHosted) { return @{ role = 'Reader'; identity = $who; source = 'hosted: not in manager-access.custom.json (fail closed)' } }
        return @{ role = 'SuperAdmin'; identity = $who; source = 'default (no manager-access.custom.json)' }
    }
    try {
        $list = Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($e in @($list)) {
            if ("$($e.identity)" -and ("$($e.identity)".ToLowerInvariant() -eq $who.ToLowerInvariant())) {
                $r = "$($e.role)"
                if ($r -notin @('Reader', 'Admin', 'SuperAdmin', 'Delegated')) { $r = 'Reader' }
                return @{ role = $r; identity = $who; source = 'manager-access.custom.json' }
            }
        }
    } catch {
        Write-Warning "manager-access.custom.json unreadable ($($_.Exception.Message)) -- failing CLOSED to Reader."
        return @{ role = 'Reader'; identity = $who; source = 'unreadable access file (fail closed)' }
    }
    @{ role = 'Reader'; identity = $who; source = 'not listed in manager-access.custom.json' }
}

function Test-PimManagerRoleAtLeast {
    param([Parameter(Mandatory)][ValidateSet('Reader', 'Admin', 'SuperAdmin')][string]$Minimum)
    # Delegated ranks as Reader for write-gates (read-only); its scope filter limits what
    # it sees. Elevating Delegated to manage its own groups is a later epic phase.
    $rank = @{ Reader = 0; Delegated = 0; Admin = 1; SuperAdmin = 2 }
    $rank[(Get-PimManagerRole).role] -ge $rank[$Minimum]
}

function Write-PimManagerAuditEvent {
    param(
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Target,
        [object]$After = $null,
        [string]$Result = 'ok'
    )
    try {
        $auditDir = Join-Path $script:outputRoot 'audit'
        if (-not (Test-Path -LiteralPath $auditDir)) { New-Item -ItemType Directory -Path $auditDir -Force | Out-Null }
        $auditFile = Join-Path $auditDir ("pim-audit-{0}.jsonl" -f [datetime]::UtcNow.ToString('yyyyMM'))
        $who = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
        $evt = [ordered]@{
            ts = [datetime]::UtcNow.ToString('o'); runId = "$($script:PimManagerSessionId)"; correlationId = ''
            actor = "manager:$who"; action = $Action; target = $Target
            before = $null; after = $After; result = $Result; whatIf = $false
        }
        [System.IO.File]::AppendAllText($auditFile, (($evt | ConvertTo-Json -Depth 5 -Compress) + "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    } catch { Write-Warning "audit write failed: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------------------
# Validate-tab "Overrule / Acknowledge" writer (REQUIREMENTS §11). The GUI
# Overrule button POSTs here; we APPEND one entry to the REAL merged override
# store (config/PIM-WarningOverrides.custom.json) -- the SAME shape the engine
# post-filter (engine/_shared/PIM-WarningOverrides.ps1) reads. The next
# preflight then downgrades the matched finding to 'acknowledged' so the active
# warning/info count drops. CSV-mode only (the override config lives next to the
# other config/*.custom.json); SQL mode has no customer config dir.
# ---------------------------------------------------------------------------
function Get-PimWarningOverrideStorePath {
    if (-not $script:configRoot) { return $null }
    if (Get-Command Resolve-PimWarningOverridesPath -ErrorAction SilentlyContinue) {
        return (Resolve-PimWarningOverridesPath -ConfigRoot $script:configRoot)
    }
    return (Join-Path $script:configRoot 'PIM-WarningOverrides.custom.json')
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
    $path = Get-PimWarningOverrideStorePath
    if (-not $path) { throw 'No config folder for this instance (overrides are a CSV-mode feature).' }
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

    # Read the existing store (tolerant of missing file / BOM), append, write.
    $existing = New-Object System.Collections.ArrayList
    if (Test-Path -LiteralPath $path) {
        try {
            $text = [System.IO.File]::ReadAllText($path, [System.Text.UTF8Encoding]::new($false))
            if ($text.Length -gt 0 -and [int][char]$text[0] -eq 0xFEFF) { $text = $text.Substring(1) }
            $cur = $text | ConvertFrom-Json
            $ovr = if ($cur -and $cur.PSObject.Properties['overrides']) { $cur.overrides } else { $null }
            if ($ovr) { foreach ($o in @($ovr)) { [void]$existing.Add($o) } }
        } catch { throw "existing override store is not valid JSON: $($_.Exception.Message)" }
    }
    [void]$existing.Add($entry)
    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    @{ overrides = $existing.ToArray() } | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $path -Encoding UTF8
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
    param([string]$Action)
    $a = "$Action".Trim().ToLowerInvariant()
    if (-not $a) { return 'other' }
    switch -Regex ($a) {
        '^(manager\.login|login)'           { return 'logins' }
        '^emergency\.'                      { return 'emergency' }
        '^approval\.'                       { return 'approvals' }
        '^(account\.|tap\.)'                { return 'accounts' }
        '^(membership\.|group\.|local\.apply|msp\.fanout|cutover\.)' { return 'delegations' }
        '^(policy\.|resource\.|config\.|settings\.|mail\.send|license\.)' { return 'engine' }
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

    # Load the local hash (config/emergency.custom.ps1) so the resolver sees it.
    $hashFile = Join-Path $script:configRoot 'emergency.custom.ps1'
    if (Test-Path -LiteralPath $hashFile) { try { . $hashFile } catch {} }

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
    if (-not $expected) { return @{ ok = $false; error = 'no emergency passcode configured (config/emergency.custom.ps1 must set $global:PIM_EmergencyPasscodeHash)' } }
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

# CSV schema auto-upgrade: customer installs predate the lifecycle columns.
# Append any missing ones (blank = default behavior = auto-approval) before
# the GUI loads the CSVs, so the grid shows the columns and the wizard's
# staged rows align. Mirrors the engine-run upgrade; idempotent.
function Invoke-PimManagerCsvSchemaUpgrade {
    param([Parameter(Mandatory)][string]$Dir)
    $additions = @{
        'Account-Definitions-Admins'   = @('ProvisionDate', 'TAPLifetimeHours', 'Template', 'OffboardDate', 'DeleteAfterDays')
        'PIM-Definitions-Roles'        = @('PolicyTemplate', 'Lifecycle')
        'PIM-Definitions-Tasks'        = @('PolicyTemplate', 'Lifecycle')
        'PIM-Definitions-Services'     = @('PolicyTemplate', 'Lifecycle')
        'PIM-Definitions-Processes'    = @('PolicyTemplate', 'Lifecycle')
        'PIM-Definitions-Resources'    = @('PolicyTemplate', 'Lifecycle')
        'PIM-Definitions-Departments'  = @('PolicyTemplate', 'Lifecycle')
        'PIM-Definitions-Organization' = @('PolicyTemplate', 'Lifecycle')
    }
    foreach ($base in @($additions.Keys)) {
        $path = Join-Path $Dir "$base.custom.csv"
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try {
            $lines = @(Get-Content -LiteralPath $path -Encoding UTF8)
            if ($lines.Count -eq 0) { continue }
            $headerCols = @($lines[0] -split ';' | ForEach-Object { $_.Trim().Trim('"') })
            $missing = @($additions[$base] | Where-Object { $headerCols -notcontains $_ })
            if ($missing.Count -eq 0) { continue }
            $parsed = @(Import-Csv -Path $path -Delimiter ';' -Encoding UTF8)
            $dataLines = @($lines | Select-Object -Skip 1 | Where-Object { "$_".Trim() })
            if ($parsed.Count -ne $dataLines.Count) {
                foreach ($r in $parsed) { foreach ($col in $missing) { $r | Add-Member -NotePropertyName $col -NotePropertyValue '' -Force } }
                $parsed | Export-Csv -Path $path -Delimiter ';' -Encoding UTF8 -NoTypeInformation
            } else {
                $pad = (';' * $missing.Count)
                $lines[0] = $lines[0] + ';' + ($missing -join ';')
                for ($i = 1; $i -lt $lines.Count; $i++) { if ($lines[$i].Trim()) { $lines[$i] = $lines[$i] + $pad } }
                Set-Content -LiteralPath $path -Value $lines -Encoding UTF8
            }
            Write-Host "  [Schema] $base.custom.csv upgraded: added $($missing -join ', ')" -ForegroundColor Cyan
        } catch {
            Write-Warning "  [Schema] upgrade of $base.custom.csv failed (file left untouched): $($_.Exception.Message)"
        }
    }
}

# ---------------------------------------------------------------------------
# Instances (MSP multi-customer support)
#
# An instance = one customer's data set. 'local' (the solution's own config/)
# always exists; more come from tools/pim-manager/instances.custom.json.
# All CSV / naming-convention / output / tenant-cache I/O resolves through
# $script:configRoot + $script:outputRoot + $script:PimInstanceName, which
# Set-PimManagerInstance swaps at runtime (UI dropdown -> POST /api/instance).
#
# SQL note: when instances move from per-customer CSV folders to per-customer
# SQL databases, Set-PimManagerInstance is the seam -- the registry entry
# grows a connection-string field and Read-PimRows/Write-PimCsvCustom get
# a SQL-backed implementation; nothing above this layer changes.
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
    # Returns array of @{ name; configRoot; outputRoot } -- 'local' first.
    $list = New-Object System.Collections.ArrayList
    [void]$list.Add(@{
        name       = 'local'
        configRoot = (Join-Path $solutionRoot 'config')
        outputRoot = (Join-Path $solutionRoot 'output')
    })
    if (Test-Path -LiteralPath $instancesFile) {
        try {
            $raw = [System.IO.File]::ReadAllText($instancesFile, [System.Text.UTF8Encoding]::new($false))
            if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
            $parsed = $raw | ConvertFrom-Json
            foreach ($e in @($parsed.instances)) {
                if (-not $e -or -not $e.name -or -not $e.configRoot) { continue }
                if ($e.name -eq 'local') { continue }  # reserved
                $cfg = [string]$e.configRoot
                $out = if ($e.outputRoot) { [string]$e.outputRoot } else {
                    # Default: sibling 'output' folder next to the config folder.
                    Join-Path (Split-Path -Parent $cfg) 'output'
                }
                [void]$list.Add(@{
                    name       = [string]$e.name
                    configRoot = $cfg
                    outputRoot = $out
                    # Optional per-tenant connection. Two credential shapes:
                    #   certThumbprint -- mgmt-box deployment (certs for every
                    #     tenant in the machine store).
                    #   keyVaultName + secretName -- central Key Vault holding
                    #     one client secret per tenant. This is the
                    #     cloud-portable shape: an Azure App Service port uses
                    #     Managed Identity -> the same vault -> the same
                    #     naming, with zero changes to this resolution logic.
                    # When tenantId is set, switching to this instance
                    # retargets the app-only Graph/Az connection so Active
                    # Assignments + tenant-cache refresh hit THIS tenant.
                    tenantId       = $(if ($e.tenantId)       { [string]$e.tenantId }       else { $null })
                    appId          = $(if ($e.appId)          { [string]$e.appId }          else { $null })
                    certThumbprint = $(if ($e.certThumbprint) { [string]$e.certThumbprint } else { $null })
                    keyVaultName   = $(if ($e.keyVaultName)   { [string]$e.keyVaultName }   else { $null })
                    secretName     = $(if ($e.secretName)     { [string]$e.secretName }     else { $null })
                })
            }
        } catch {
            Write-Warning "instances.custom.json could not be parsed: $($_.Exception.Message) -- only the 'local' instance is available."
        }
    }
    # SQL-mode: expose each configured SQL database as a selectable instance, so the
    # existing GUI instance dropdown doubles as the SQL-DB selector (MSP / multi-DB).
    # $env:PIM_SqlDatabases = comma list (the active $global:PIM_SqlDatabase is always
    # included). configRoot points at the solution config so existence checks pass;
    # the sqlDatabase field is what Set-PimManagerInstance switches.
    if ($script:PimStorageMode -eq 'sql') {
        $dbs = New-Object System.Collections.Generic.List[string]
        if ($global:PIM_SqlDatabase) { $dbs.Add("$($global:PIM_SqlDatabase)") }
        foreach ($d in ("$env:PIM_SqlDatabases" -split '[,; ]+' | Where-Object { $_ })) { if ($dbs -notcontains $d) { $dbs.Add($d) } }
        foreach ($db in $dbs) {
            [void]$list.Add(@{ name = "sql:$db"; configRoot = (Join-Path $solutionRoot 'config'); outputRoot = (Join-Path $solutionRoot 'output'); sqlDatabase = $db })
        }
    }
    return ,$list.ToArray()
}

function Set-PimManagerInstance {
    # Switch the active instance. Throws if the name is unknown or the config
    # folder is missing. Clears every per-instance server-side cache.
    param([Parameter(Mandatory)][string]$Name)
    $inst = $null
    foreach ($i in (Get-PimManagerInstances)) { if ($i.name -eq $Name) { $inst = $i; break } }
    if (-not $inst) { throw "Unknown instance '$Name'. Declare it in $instancesFile." }

    # SQL-DB switch: re-point the active database on the same server (MI token is
    # server-scoped, so it works across DBs; the MI must be a contained user in each
    # target DB). Reloads settings from the new DB and clears per-instance caches.
    if ($inst.sqlDatabase) {
        $global:PIM_SqlDatabase = "$($inst.sqlDatabase)"
        $script:PimSqlCs = Get-PimSqlConnectionString
        $tc = New-PimSqlConnection -ConnectionString $script:PimSqlCs; $tc.Open(); $tc.Close()
        Initialize-PimSqlStore -ConnectionString $script:PimSqlCs
        $sqlSettings = Get-PimAllSqlSettings -ConnectionString $script:PimSqlCs
        if (-not ($global:PIM_NamingConventions -is [hashtable])) { $global:PIM_NamingConventions = @{} }
        foreach ($k in @($sqlSettings.Keys)) { $global:PIM_NamingConventions[$k] = $sqlSettings[$k] }
        $script:PimStorageMode = 'sql'; $script:PimInstanceName = $inst.name
        $script:PimActiveAssignmentsCache = $null; $script:PimActiveAssignmentsCacheLoadedUtc = $null
        Write-Host "  [store] switched SQL database -> $($global:PIM_SqlDatabase)" -ForegroundColor Cyan
        return
    }
    if (-not (Test-Path -LiteralPath $inst.configRoot)) { throw "Instance '$Name': config folder not found: $($inst.configRoot)" }
    if (-not (Test-Path -LiteralPath $inst.outputRoot)) { New-Item -ItemType Directory -Path $inst.outputRoot -Force | Out-Null }

    $script:PimInstanceName = $inst.name
    $script:configRoot      = $inst.configRoot
    $script:outputRoot      = $inst.outputRoot
    $script:mutationLog     = Join-Path $inst.outputRoot 'pim-manager-mutations.log'

    # Lifecycle columns materialize on first open after an update (blank =
    # default behavior = auto-approval). Idempotent.
    Invoke-PimManagerCsvSchemaUpgrade -Dir $inst.configRoot

    # Locked-schema + data conformance: bring migrated customer data to the
    # current contract -- drop deprecated columns (TierLevel) + migrate their
    # data first (TierLevel->Purpose). Idempotent; safe to run every open.
    if (Get-Command Invoke-PimSchemaConformancePreflight -ErrorAction SilentlyContinue) {
        try { [void](Invoke-PimSchemaConformancePreflight -ConfigDir $inst.configRoot) }
        catch { Write-Warning "  [SchemaConf] preflight skipped: $($_.Exception.Message)" }
    }

    # Storage backend. SQL is EXPLICIT opt-in (config StorageBackend='sql' or an
    # explicit connection signal) -- never auto-switch off the bare SQLEXPRESS
    # default. In SQL mode, SETTINGS live in SQL (pim.Settings): the file seeds them
    # once, then SQL wins and is loaded over $global:PIM_NamingConventions so a
    # hacker reading the JSON learns nothing authoritative.
    $script:PimStorageMode = 'csv'; $script:PimSqlCs = $null
    # Container-friendly: surface the SQL env vars (set as App Service app settings) as
    # the globals the resolver below + Get-PimSqlConnectionString read.
    if (-not $global:PIM_SqlServer   -and $env:PIM_SqlServer)   { $global:PIM_SqlServer   = $env:PIM_SqlServer }
    if (-not $global:PIM_SqlDatabase -and $env:PIM_SqlDatabase) { $global:PIM_SqlDatabase = $env:PIM_SqlDatabase }
    if (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) {
        $backend = "$(Get-PimPolicySetting -Name 'StorageBackend' -Default 'csv')".ToLowerInvariant()
        $hasSig  = [bool]($global:PIM_SqlConnectionString -or $global:PIM_SqlConnStringVault -or $global:PIM_SqlServer -or $env:PIM_SqlConnectionString)
        Write-Host ("  [store] backend='{0}' hasSig={1} server='{2}' db='{3}'" -f $backend, $hasSig, "$($global:PIM_SqlServer)", "$($global:PIM_SqlDatabase)") -ForegroundColor DarkCyan
        Write-Host ("  [mi-env] IDENTITY_ENDPOINT={0} IDENTITY_HEADER={1} interactive={2}" -f [bool]$env:IDENTITY_ENDPOINT, [bool]$env:IDENTITY_HEADER, [bool]($global:PIM_Interactive -or $global:PIM_SqlInteractive)) -ForegroundColor DarkCyan
        # SQL-ONLY: no CSV fallback. When SQL is the backend (or signalled), a failure
        # to reach/init SQL is FATAL -- we throw with the reason rather than silently
        # serving empty config. (Hosted is always SQL.)
        $sqlRequired = ($backend -eq 'sql' -or $hasSig -or $script:PimHosted)
        if ($sqlRequired) {
            if ($env:PIM_SqlConnectionString -and -not $global:PIM_SqlConnectionString) { $global:PIM_SqlConnectionString = $env:PIM_SqlConnectionString }
            $cs = $null
            try { $cs = Get-PimSqlConnectionString } catch { throw "[store] SQL-only: connection-string build failed: $($_.Exception.Message)" }
            if (-not $cs) { throw "[store] SQL-only: no connection string resolved (server='$($global:PIM_SqlServer)' db='$($global:PIM_SqlDatabase)')." }
            # Direct open so the REAL failure (driver load / MI token / TLS / auth /
            # network) surfaces, instead of a swallowed false.
            try {
                $__tc = New-PimSqlConnection -ConnectionString $cs
                $__tc.Open(); $__tc.Close()
                Write-Host "  [store] SQL connect test OK" -ForegroundColor DarkCyan
            } catch {
                $__inner = if ($_.Exception.InnerException) { " | inner: $($_.Exception.InnerException.Message)" } else { '' }
                throw "[store] SQL-only: connect failed [$($_.Exception.GetType().Name)]: $($_.Exception.Message)$__inner"
            }
            Initialize-PimSqlStore -ConnectionString $cs
            if ($global:PIM_NamingConventions -is [hashtable]) { [void](Import-PimSettingsSeed -ConnectionString $cs -Seed $global:PIM_NamingConventions) }
            $sqlSettings = Get-PimAllSqlSettings -ConnectionString $cs
            if (-not ($global:PIM_NamingConventions -is [hashtable])) { $global:PIM_NamingConventions = @{} }
            foreach ($k in @($sqlSettings.Keys)) { $global:PIM_NamingConventions[$k] = $sqlSettings[$k] }
            $script:PimSqlCs = $cs; $script:PimStorageMode = 'sql'
            # The DB name is needed for the 'sql:<db>' instance label (hosted
            # default + GUI dropdown). When the connection arrived as a full
            # connection string / KV pointer (not PIM_SqlServer+PIM_SqlDatabase),
            # $global:PIM_SqlDatabase is unset -- parse it out of the CS so the
            # Manager binds to a NAMED SQL instance instead of the contextless
            # 'local'. (Initial Catalog / Database = <name>.)
            if (-not "$($global:PIM_SqlDatabase)".Trim()) {
                if ("$cs" -match '(?i)(?:Initial\s+Catalog|Database)\s*=\s*([^;]+)') { $global:PIM_SqlDatabase = $Matches[1].Trim() }
            }
            Write-Host "  [store] SQL mode (SQL-only; no CSV fallback)" -ForegroundColor Cyan
        }
    }

    # Per-instance state must not leak across customers.
    $script:PimActiveAssignmentsCache          = $null
    $script:PimActiveAssignmentsCacheLoadedUtc = $null
    $script:PimManager_LookupCachesLoaded      = $false

    # Per-tenant connection retargeting: when the registry entry carries
    # tenantId (+ optional appId / certThumbprint -- the mgmt box has the
    # certs for every tenant in its store), point the engine SPN globals at
    # THIS tenant and drop the current Graph session. The next Active
    # Assignments / tenant-cache call reconnects app-only to the right
    # tenant via _tenantSync's Connect-PimManagerGraph/Az.
    if ($inst.tenantId) {
        $global:AzureTenantID = $inst.tenantId
        if ($inst.appId) { $global:HighPriv_Modern_ApplicationID_Azure = $inst.appId }
        if ($inst.certThumbprint) {
            # Mgmt-box shape: per-tenant cert in the machine store.
            $global:HighPriv_Modern_CertificateThumbprint_Azure = $inst.certThumbprint
            # A secret from a previously-connected tenant must never be
            # replayed against this one.
            $global:HighPriv_Modern_Secret_Azure = $null
        } elseif ($inst.keyVaultName -and $inst.secretName) {
            # Central-Key-Vault shape (cloud-portable): one client secret per
            # tenant in one vault. Pulled with the CURRENT Az context (the
            # bootstrap connection from -ConnectPlatform on the mgmt box; a
            # Managed Identity on an Azure App Service port). Lazy failure is
            # fine -- _tenantSync throws a clear error on first tenant call.
            try {
                $sec = Get-AzKeyVaultSecret -VaultName $inst.keyVaultName -Name $inst.secretName -AsPlainText -ErrorAction Stop
                $global:HighPriv_Modern_Secret_Azure = $sec
                $global:HighPriv_Modern_CertificateThumbprint_Azure = $null
            } catch {
                Write-Warning ("instance '{0}': Key Vault secret {1}/{2} could not be read ({3}). Tenant-connected features will fail until resolved. Is the platform connected (-ConnectPlatform) and does this identity have get-secret on the vault?" -f $inst.name, $inst.keyVaultName, $inst.secretName, $_.Exception.Message)
            }
        }
        $script:PimManagerTenantConnected = $false
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Host ("  instance: {0}  (config: {1}, tenant: {2})" -f $inst.name, $inst.configRoot, $inst.tenantId) -ForegroundColor Cyan
    } else {
        Write-Host ("  instance: {0}  (config: {1})" -f $inst.name, $inst.configRoot) -ForegroundColor Cyan
    }
}

# Resolve the startup instance: -ConfigRoot (ad-hoc) > -Instance (registry) >
# the SQL instance (hosted/SQL) > 'local'.
#
# HOSTED/SQL default (one Manager = one active SQL; no multi-env switching):
# the 'local' instance has NO tenant context and is wrong as a hosted default.
# Set-PimManagerInstance -Name 'local' still runs the SQL init (because
# $sqlRequired includes $script:PimHosted), but it LABELS the active instance
# 'local'. After init, when SQL mode is actually active and the operator did
# not pin an explicit -Instance, re-label the active instance to 'sql:<db>' so
# the dropdown, the per-instance tenant cache, and the GUI header all agree the
# Manager is bound to the SQL store -- not the contextless 'local' folder.
if ($ConfigRoot) {
    if (-not (Test-Path -LiteralPath $ConfigRoot)) { throw "-ConfigRoot folder not found: $ConfigRoot" }
    $script:PimInstanceName = 'custom'
    $script:configRoot      = $ConfigRoot
    $script:outputRoot      = Join-Path (Split-Path -Parent $ConfigRoot) 'output'
    if (-not (Test-Path -LiteralPath $script:outputRoot)) { New-Item -ItemType Directory -Path $script:outputRoot -Force | Out-Null }
    $script:mutationLog     = Join-Path $script:outputRoot 'pim-manager-mutations.log'
    Invoke-PimManagerCsvSchemaUpgrade -Dir $ConfigRoot
    Write-Host ("  instance: custom (config: {0})" -f $ConfigRoot) -ForegroundColor Cyan
} else {
    Set-PimManagerInstance -Name $(if ($Instance) { $Instance } else { 'local' })
    if (-not $Instance -and $script:PimStorageMode -eq 'sql' -and "$($global:PIM_SqlDatabase)".Trim()) {
        # SQL became the active backend and no instance was pinned -> bind to the
        # SQL instance, not 'local'. Keeps the contextless 'local' folder out of
        # the hosted runtime (its config/cache would never carry tenant context).
        $script:PimInstanceName = "sql:$($global:PIM_SqlDatabase)"
        Write-Host ("  [store] hosted/SQL default -> active instance '{0}'" -f $script:PimInstanceName) -ForegroundColor Cyan
    }
}

if (-not (Test-Path -LiteralPath $template))   { throw "Template not found: $template" }
if (Test-Path -LiteralPath $tenantSync) { . $tenantSync }
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
    [ordered]@{ base = 'Account-Definitions-Admins';      group = 'Definitions';  defaultHeader = @('FirstName','LastName','Initials','Purpose','TargetUsage','TargetPlatform','UserType','UserName','DisplayName','UserPrincipalName','UsageLocation','ForwardMailsToContact','MailForwardAddress','CreateTAP','TAPStartDate','Ring') },
    [ordered]@{ base = 'PIM-Definitions-Roles';           group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform','IsRoleAssignable') },
    [ordered]@{ base = 'PIM-Definitions-Tasks';           group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-Services';        group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-Processes';       group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-Resources';       group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-Departments';     group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
    [ordered]@{ base = 'PIM-Definitions-Organization';    group = 'Definitions';  defaultHeader = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners') },
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

function Resolve-PimCsvPath {
    # Customer override (.custom.csv) wins; fall back to shipped default (.locked.csv).
    param([Parameter(Mandatory)][string]$BaseName)
    $custom = Join-Path $configRoot "$BaseName.custom.csv"
    $locked = Join-Path $configRoot "$BaseName.locked.csv"
    if (Test-Path -LiteralPath $custom) { return [pscustomobject]@{ Path = $custom; Source = 'custom' } }
    if (Test-Path -LiteralPath $locked) { return [pscustomobject]@{ Path = $locked; Source = 'locked' } }
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

function ConvertTo-PimNormalizedHeaderToken {
    # Normalise ONE CSV header cell so quoted / Excel-exported / BOM-prefixed
    # headers map to the same column name as a clean header. Excel exports wrap
    # every header in double quotes and the first cell can carry a UTF-8 BOM
    # (﻿). Manual edits add whitespace after the delimiter. Any of these
    # left the column name not matching ($r.PSObject.Properties[$col] failed),
    # so every field came back blank and the Delegation Map rendered empty.
    # Order matters: strip BOM -> trim -> strip ONE layer of surrounding quotes
    # (un-doubling internal "") -> trim again. Data values are NOT touched here;
    # this only builds the header->column map.
    param([string]$Token)
    $h = "$Token"
    # 1. Leading UTF-8 BOM on the very first header cell.
    if ($h.Length -gt 0 -and [int][char]$h[0] -eq 0xFEFF) { $h = $h.Substring(1) }
    # 2. Surrounding whitespace (e.g. '"UserName"; "RoleDefinitionName"').
    $h = $h.Trim()
    # 3. ONE layer of surrounding double quotes; un-double internal quotes.
    if ($h.Length -ge 2 -and $h[0] -eq '"' -and $h[$h.Length - 1] -eq '"') {
        $h = $h.Substring(1, $h.Length - 2).Replace('""', '"')
    }
    # 4. Trim again in case the quotes wrapped padded content.
    return $h.Trim()
}

function Read-PimRows {
    # Returns hashtable: @{ header = string[]; rows = ordered[]; source = 'custom'|'locked'|'none'|'sql'; path = string }
    # -NoScope bypasses Delegated visibility scoping (used internally to build the scope).
    param([Parameter(Mandatory)][string]$BaseName, [switch]$NoScope)
    # SQL-only mode (hosted): rows live in SQL, NOT in CSV files (the image ships no
    # customer CSVs). Make this the single chokepoint so EVERY caller -- the page
    # model, diff, validate, commit -- reads from SQL. Falls through to CSV only when
    # not in SQL mode (local/dev).
    if ($script:PimStorageMode -eq 'sql' -and $script:PimSqlCs -and (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue)) {
        $spec = Get-PimCsvSpec -BaseName $BaseName
        $hdr  = if ($spec) { @($spec.defaultHeader) } else { @() }
        $sqlRows = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $BaseName)
        if (($hdr.Count -eq 0) -and $sqlRows.Count -gt 0) { $hdr = @($sqlRows[0].PSObject.Properties.Name) }
        return (Limit-PimRowsToScope -Result @{ header = $hdr; rows = $sqlRows; source = 'sql'; path = "sql:$BaseName" } -BaseName $BaseName -NoScope:$NoScope)
    }
    $resolved = Resolve-PimCsvPath -BaseName $BaseName
    $spec = Get-PimCsvSpec -BaseName $BaseName
    if (-not $resolved) {
        $hdr = if ($spec) { $spec.defaultHeader } else { @() }
        return @{ header = $hdr; rows = @(); source = 'none'; path = (Join-Path $configRoot "$BaseName.custom.csv") }
    }
    # Read the raw file to recover the original header (Import-Csv mangles trailing empty columns).
    $raw = [System.IO.File]::ReadAllText($resolved.Path, [System.Text.UTF8Encoding]::new($true))
    # Strip BOM if present.
    if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
    $lines = $raw -split "(`r`n|`n|`r)" | Where-Object { $_ -and $_ -notmatch '^(\r\n|\n|\r)$' }
    if (-not $lines -or $lines.Count -eq 0) {
        $hdr = if ($spec) { $spec.defaultHeader } else { @() }
        return @{ header = $hdr; rows = @(); source = $resolved.Source; path = $resolved.Path }
    }
    $headerLine = $lines[0]
    $headerCols = $headerLine -split ';'
    # Excel saves CSVs with every header field wrapped in double quotes
    # ("UserPrincipalName";"DisplayName";...), the first cell can carry a UTF-8
    # BOM, and manual edits add whitespace after the delimiter. A raw -split
    # keeps all of that, but Import-Csv STRIPS quotes/BOM/whitespace -- so the
    # property lookup below ($r.PSObject.Properties[$col]) never matched and
    # EVERY field came back blank, which made Build-PimGraphData skip every admin
    # row and render the Delegation Map empty. Normalise each header token the
    # same way Import-Csv does (BOM + whitespace + one layer of surrounding
    # quotes) so quoted/BOM/Excel and clean CSVs parse identically. Only the
    # header map is normalised; quoted DATA values are untouched.
    $headerCols = @($headerCols | ForEach-Object { ConvertTo-PimNormalizedHeaderToken -Token "$_" })
    # Drop trailing empty header columns (matches what users actually edit).
    while ($headerCols.Count -gt 0 -and [string]::IsNullOrEmpty($headerCols[$headerCols.Count - 1])) {
        $headerCols = $headerCols[0..($headerCols.Count - 2)]
    }
    if ($headerCols.Count -eq 0 -and $spec) { $headerCols = $spec.defaultHeader }

    $rows = New-Object System.Collections.ArrayList
    foreach ($r in (Import-Csv -Path $resolved.Path -Delimiter ';' -Encoding UTF8)) {
        # KEEP blank rows (every column empty). Customers use ';;;;;' rows as
        # visual group separators in Excel; dropping them here meant every
        # Manager commit silently destroyed the hand-maintained layout
        # (observed: 53 raw rows -> 37 after one PUT round-trip). The engines
        # and the validator both skip blank rows themselves, and the grid
        # renders them as empty editable rows -- same as Excel does.
        # Build a normalised property map so a header token (already BOM/quote/
        # whitespace-stripped) resolves even on PowerShell builds where Import-Csv
        # leaves a BOM/quote on a data-row property name (the first column most
        # commonly). Without this the first column silently maps to '' and the
        # Delegation Map renders empty on a valid Excel export.
        $propMap = @{}
        foreach ($p in $r.PSObject.Properties) {
            $key = ConvertTo-PimNormalizedHeaderToken -Token "$($p.Name)"
            if (-not $propMap.ContainsKey($key)) { $propMap[$key] = $p.Value }
        }
        $obj = [ordered]@{}
        foreach ($col in $headerCols) {
            $val = $null
            $prop = $r.PSObject.Properties[$col]
            if ($prop) { $val = $prop.Value }
            elseif ($propMap.ContainsKey($col)) { $val = $propMap[$col] }
            if ($null -eq $val) { $val = '' }
            $obj[$col] = "$val"
        }
        [void]$rows.Add($obj)
    }
    return (Limit-PimRowsToScope -Result @{ header = $headerCols; rows = $rows.ToArray(); source = $resolved.Source; path = $resolved.Path } -BaseName $BaseName -NoScope:$NoScope)
}

function Write-PimCsvCustom {
    # Atomic write to <base>.custom.csv. Preserves header order; appends new columns at end.
    # Returns hashtable with path + counts.
    param(
        [Parameter(Mandatory)][string]$BaseName,
        [Parameter(Mandatory)][object[]]$Rows
    )
    $spec = Get-PimCsvSpec -BaseName $BaseName
    if (-not $spec) { throw "Unknown CSV base name: $BaseName" }
    $current = Read-PimRows -BaseName $BaseName
    $header = New-Object System.Collections.ArrayList
    foreach ($h in $current.header) { [void]$header.Add($h) }
    # Add any extra columns the client introduced, append at end (stable order from first occurrence).
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        $props = @()
        if ($row -is [System.Collections.IDictionary]) { $props = @($row.Keys) }
        else { $props = @($row.PSObject.Properties.Name) }
        foreach ($k in $props) {
            if (-not ($header -contains $k)) { [void]$header.Add($k) }
        }
    }

    # Build CSV text. Always ';' delimiter, UTF-8 no BOM. Quote any field
    # that contains ';', '"', CR or LF; double internal quotes.
    $sb = New-Object System.Text.StringBuilder
    $headerLine = ($header | ForEach-Object { Format-PimCsvField $_ }) -join ';'
    [void]$sb.AppendLine($headerLine)
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        $vals = New-Object System.Collections.ArrayList
        foreach ($col in $header) {
            $v = ''
            if ($row -is [System.Collections.IDictionary]) {
                if ($row.Contains($col)) { $v = "$($row[$col])" }
            } else {
                $p = $row.PSObject.Properties[$col]
                if ($p) { $v = "$($p.Value)" }
            }
            [void]$vals.Add((Format-PimCsvField $v))
        }
        [void]$sb.AppendLine(($vals -join ';'))
    }

    $finalPath = Join-Path $configRoot "$BaseName.custom.csv"
    $tmpPath   = "$finalPath.tmp"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    # Strip the trailing newline AppendLine introduces, then re-add a single
    # platform newline so the file ends with exactly one EOL.
    $text = $sb.ToString().TrimEnd("`r", "`n") + "`r`n"
    [System.IO.File]::WriteAllText($tmpPath, $text, $utf8NoBom)
    Move-Item -LiteralPath $tmpPath -Destination $finalPath -Force

    return @{ path = $finalPath; rowCount = $Rows.Count; header = $header.ToArray() }
}

function Format-PimCsvField {
    param([Parameter(Mandatory=$false)][AllowNull()][AllowEmptyString()][string]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -match '[;"\r\n]') {
        return '"' + ($Value -replace '"','""') + '"'
    }
    return $Value
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
        [Parameter(Mandatory)][int]$NewRowCount
    )
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = "$ts`t$BaseName`t$Adds`t$Removes`t$Modifies`t$NewRowCount"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    # AppendAllText creates the file if missing, no BOM, UTF-8.
    [System.IO.File]::AppendAllText($mutationLog, ($line + "`r`n"), $utf8NoBom)

    # Phase 6: same event also lands in the unified audit jsonl (one schema
    # for engine + Manager; actor records the Windows identity driving the
    # localhost session). Best-effort -- never blocks a save.
    try {
        $auditDir = Join-Path $script:outputRoot 'audit'
        if (-not (Test-Path -LiteralPath $auditDir)) { New-Item -ItemType Directory -Path $auditDir -Force | Out-Null }
        $auditFile = Join-Path $auditDir ("pim-audit-{0}.jsonl" -f [datetime]::UtcNow.ToString('yyyyMM'))
        $who = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
        $evt = [ordered]@{
            ts            = [datetime]::UtcNow.ToString('o')
            runId         = "$($script:PimManagerSessionId)"
            correlationId = ''
            actor         = "manager:$who"
            action        = 'config.csv.save'
            target        = $BaseName
            before        = $null
            after         = @{ adds = $Adds; removes = $Removes; modifies = $Modifies; rowCount = $NewRowCount; instance = "$($script:PimInstanceName)" }
            result        = 'ok'
            whatIf        = $false
        }
        [System.IO.File]::AppendAllText($auditFile, (($evt | ConvertTo-Json -Depth 5 -Compress) + "`r`n"), $utf8NoBom)
    } catch {
        Write-Warning "audit write failed (save NOT blocked): $($_.Exception.Message)"
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

function Get-PimManagerBackupDir {
    # File-mode (local/dev) snapshot store: <outputRoot>/backups. Created on demand.
    $dir = Join-Path $script:outputRoot 'backups'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    return $dir
}

function Save-PimFileBackupSnapshot {
    param([Parameter(Mandatory)][object]$Snapshot)
    $dir = Get-PimManagerBackupDir
    $path = Join-Path $dir ("$($Snapshot.id).json")
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, ($Snapshot | ConvertTo-Json -Depth 25), $utf8NoBom)
}

function Get-PimFileBackupSnapshots {
    # Metadata list (oldest -> newest by id) for an entity, from the file store.
    param([string]$Entity)
    $dir = Get-PimManagerBackupDir
    $out = New-Object System.Collections.ArrayList
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        try {
            $rec = [System.IO.File]::ReadAllText($f.FullName) | ConvertFrom-Json
            if ("$Entity".Trim() -and "$($rec.entity)" -ne "$Entity") { continue }
            [void]$out.Add([pscustomobject]@{ id = "$($rec.id)"; entity = "$($rec.entity)"; takenUtc = "$($rec.takenUtc)"; by = "$($rec.by)"; reason = "$($rec.reason)"; rowCount = [int]$rec.rowCount })
        } catch { }
    }
    return @($out.ToArray() | Sort-Object id)
}

function Get-PimFileBackupSnapshot {
    param([Parameter(Mandatory)][string]$Id)
    $path = Join-Path (Get-PimManagerBackupDir) ("$Id.json")
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $rec = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
    return [pscustomobject]@{ id = "$($rec.id)"; entity = "$($rec.entity)"; base = "$($rec.base)"; takenUtc = "$($rec.takenUtc)"; by = "$($rec.by)"; reason = "$($rec.reason)"; header = @($rec.header); rows = @($rec.rows); rowCount = [int]$rec.rowCount }
}

function Invoke-PimFileBackupRetention {
    param([Parameter(Mandatory)][string]$Entity, [int]$Keep = 10)
    $existing = @(Get-PimFileBackupSnapshots -Entity $Entity)
    $plan = Get-PimBackupRetentionPlan -Snapshots $existing -Keep $Keep
    foreach ($id in @($plan.prune)) { $p = Join-Path (Get-PimManagerBackupDir) ("$id.json"); if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } }
    return @($plan.prune)
}

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
    $who = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
    $snapshot = New-PimCommitSnapshot -Entity $Base -Base $Base -Rows @($Current.rows) -Header @($Current.header) -By "$who" -Reason 'review-and-save commit'

    if ($SqlMode) {
        try { Initialize-PimBackupStore -ConnectionString $script:PimSqlCs } catch { Write-Warning "  [backup] init store failed (non-fatal): $($_.Exception.Message)" }
        $save    = { param($s) Save-PimSqlBackupSnapshot -ConnectionString $script:PimSqlCs -Snapshot $s }
        $apply   = { Set-PimSqlEntityRowsTransactional -ConnectionString $script:PimSqlCs -Entity $Base -Base $Base -Rows $NewRows }
        $restore = { param($s) $plan = Get-PimSnapshotRestorePlan -Snapshot $s; Set-PimSqlEntityRowsTransactional -ConnectionString $script:PimSqlCs -Entity $plan.entity -Base $plan.base -Rows @($plan.rows) }
        $prune   = { [void](Invoke-PimSqlBackupRetention -ConnectionString $script:PimSqlCs -Entity $Base -Keep $script:PimBackupKeep) }
    } else {
        $save    = { param($s) Save-PimFileBackupSnapshot -Snapshot $s }
        $apply   = { $w = Write-PimCsvCustom -BaseName $Base -Rows $NewRows; @{ rowCount = $w.rowCount } }
        $restore = { param($s) $plan = Get-PimSnapshotRestorePlan -Snapshot $s; [void](Write-PimCsvCustom -BaseName $plan.base -Rows @($plan.rows)) }
        $prune   = { [void](Invoke-PimFileBackupRetention -Entity $Base -Keep $script:PimBackupKeep) }
    }

    return (Invoke-PimCommitTransaction -Snapshot $snapshot -ApplyScript $apply -RestoreScript $restore -SaveSnapshotScript $save -PruneScript $prune)
}

function Get-PimManagerBackupList {
    param([string]$Entity)
    if ($script:PimStorageMode -eq 'sql' -and $script:PimSqlCs) {
        try { Initialize-PimBackupStore -ConnectionString $script:PimSqlCs } catch { }
        return @(Get-PimSqlBackupSnapshots -ConnectionString $script:PimSqlCs -Entity $Entity)
    }
    return @(Get-PimFileBackupSnapshots -Entity $Entity)
}

function Invoke-PimManagerBackupRestore {
    # Operator UNDO: replay a stored snapshot back over its entity (full-set replace,
    # transactional). Returns @{ ok; entity; rowCount } or throws.
    param([Parameter(Mandatory)][string]$Id)
    if ($script:PimStorageMode -eq 'sql' -and $script:PimSqlCs) {
        try { Initialize-PimBackupStore -ConnectionString $script:PimSqlCs } catch { }
        $snap = Get-PimSqlBackupSnapshot -ConnectionString $script:PimSqlCs -Id $Id
        if (-not $snap) { throw "snapshot '$Id' not found" }
        $plan = Get-PimSnapshotRestorePlan -Snapshot $snap
        [void](Set-PimSqlEntityRowsTransactional -ConnectionString $script:PimSqlCs -Entity $plan.entity -Base $plan.base -Rows @($plan.rows))
        return @{ ok = $true; entity = $plan.entity; rowCount = @($plan.rows).Count }
    }
    $snap = Get-PimFileBackupSnapshot -Id $Id
    if (-not $snap) { throw "snapshot '$Id' not found" }
    $plan = Get-PimSnapshotRestorePlan -Snapshot $snap
    [void](Write-PimCsvCustom -BaseName $plan.base -Rows @($plan.rows))
    return @{ ok = $true; entity = $plan.entity; rowCount = @($plan.rows).Count }
}

# ---------------------------------------------------------------------------
# Naming conventions (read .locked then overlay .custom, so the UI sees what
# the engines would see). Best-effort: returns defaults if the files can't
# be sourced (e.g. running outside the repo layout).
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
    # Source .locked then .custom into a fresh scope so we don't pollute the
    # server runspace's $global state on every call.
    $files = @(
        (Join-Path $configRoot 'PIM4EntraPS.NamingConventions.locked.ps1'),
        (Join-Path $configRoot 'PIM4EntraPS.NamingConventions.custom.ps1')
    )
    foreach ($f in $files) {
        if (Test-Path -LiteralPath $f) {
            try { . $f } catch { Write-Warning "  failed to source $f : $($_.Exception.Message)" }
        }
    }
    if ($global:PIM_NamingConventions) {
        # Overlay any keys actually set, else fall back to defaults.
        foreach ($k in @($defaults.Keys)) {
            if ($global:PIM_NamingConventions.ContainsKey($k)) {
                $defaults[$k] = $global:PIM_NamingConventions[$k]
            }
        }
        foreach ($k in $global:PIM_NamingConventions.Keys) {
            if (-not $defaults.ContainsKey($k)) { $defaults[$k] = $global:PIM_NamingConventions[$k] }
        }
    }
    return $defaults
}

# ---------------------------------------------------------------------------
# Settings admin area (REQUIREMENTS §11) -- naming conventions, filters,
# departments(+owners) and approvers/owners managed THROUGH THE STORE the
# engine uses (SQL pim.Settings when SQL is active; else a single gitignored
# JSON file config/manager-settings.custom.json -- NOT the locked PS files).
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

$script:PimManagerSettingsFile = $null   # resolved per-instance below in the getters

function Get-PimManagerSettingsFilePath {
    # Per-instance JSON file (CSV/file mode only). Lives beside the other
    # *.custom.* files so the standard gitignore keeps it out of the repo.
    return (Join-Path $script:configRoot 'manager-settings.custom.json')
}

function Get-PimManagerSettingsFileBlob {
    $f = Get-PimManagerSettingsFilePath
    if (-not (Test-Path -LiteralPath $f)) { return @{} }
    try {
        $raw = [System.IO.File]::ReadAllText($f, [System.Text.UTF8Encoding]::new($true))
        if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
        if (-not "$raw".Trim()) { return @{} }
        $obj = $raw | ConvertFrom-Json
        $h = @{}
        foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = $p.Value }
        return $h
    } catch {
        Write-Warning "manager-settings.custom.json unreadable ($($_.Exception.Message)) -- treating as empty."
        return @{}
    }
}

function Set-PimManagerSettingsFileBlob {
    param([Parameter(Mandatory)][hashtable]$Blob)
    $f = Get-PimManagerSettingsFilePath
    $dir = Split-Path -Parent $f
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = ([pscustomobject]$Blob) | ConvertTo-Json -Depth 20
    $tmp  = "$f.tmp"
    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $f -Force
}

function Get-PimManagerSetting {
    # Read a single named setting from the active store. SQL when active, else
    # the per-instance JSON file. Returns the parsed object (or $null).
    param([Parameter(Mandatory)][string]$Name)
    if ($script:PimStorageMode -eq 'sql' -and $script:PimSqlCs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
        return (Get-PimSqlSetting -ConnectionString $script:PimSqlCs -Name $Name)
    }
    $blob = Get-PimManagerSettingsFileBlob
    if ($blob.ContainsKey($Name)) { return $blob[$Name] }
    return $null
}

function Set-PimManagerSetting {
    # Persist a single named setting to the active store. Also mirrors naming
    # into $global:PIM_NamingConventions so the same process's engine helpers
    # (Resolve-PimGroupName etc.) and the GET / page-render pick it up live.
    param([Parameter(Mandatory)][string]$Name, [object]$Value)
    if ($script:PimStorageMode -eq 'sql' -and $script:PimSqlCs -and (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) {
        Set-PimSqlSetting -ConnectionString $script:PimSqlCs -Name $Name -Value $Value
    } else {
        $blob = Get-PimManagerSettingsFileBlob
        $blob[$Name] = $Value
        Set-PimManagerSettingsFileBlob -Blob $blob
    }
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
    # Alerting is "enabled" only when there is at least one recipient AND a configured
    # sender mailbox -- otherwise it is a render-only "configure to enable" state.
    $hasSender = [bool]("$($global:PIM_MailSender)".Trim())
    [ordered]@{
        recipients   = @($recipients)
        events       = $events
        eventCatalog = @($script:PimAlertEventCatalog)
        senderSet    = $hasSender
        enabled      = ($recipients.Count -gt 0 -and $hasSender)
    }
}

function Set-PimAlertingConfig {
    param([string[]]$Recipients, [hashtable]$Events)
    $clean = @()
    foreach ($r in @($Recipients)) {
        $s = "$r".Trim()
        # Keep only plausible email addresses; drop blanks/garbage so we never mail nonsense.
        if ($s -and $s -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { $clean += $s }
    }
    $ev = @{}
    foreach ($e in $script:PimAlertEventCatalog) {
        if ($Events -and $Events.ContainsKey($e)) { $ev[$e] = [bool]$Events[$e] } else { $ev[$e] = $true }
    }
    Set-PimManagerSetting -Name 'Alerting' -Value ([ordered]@{ recipients = @($clean); events = $ev })
    return (Get-PimAlertingConfig)
}

# Where the recorded-alert FEED lives for the active instance (the durable
# send-proof store; JSONL under output/alerts, mirroring the audit JSONL).
function Get-PimManagerAlertFeedPath {
    $dir = Join-Path $script:outputRoot 'alerts'
    return (Join-Path $dir 'pim-alerts.jsonl')
}
function Get-PimManagerAlertFeed {
    # Read the recorded alert feed for the active instance (newest-first). Never throws.
    if (-not (Get-Command Read-PimAlertFeedFile -ErrorAction SilentlyContinue)) { return @() }
    try { return @(Read-PimAlertFeedFile -FeedFile (Get-PimManagerAlertFeedPath)) } catch { return @() }
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
    $result = [ordered]@{ event = $Event; fired = $false; sent = 0; recipients = @($cfg.recipients); reason = ''; recorded = $false; debounced = $false }
    if (-not ($cfg.events.ContainsKey($Event) -and $cfg.events[$Event])) { $result.reason = 'event disabled'; return $result }
    if (@($cfg.recipients).Count -eq 0) { $result.reason = 'no recipients configured'; return $result }
    if (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) { $result.reason = 'notify path not loaded'; return $result }
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
    foreach ($rcpt in $cfg.recipients) {
        try {
            $r = if ($WhatIf) { Send-PimNotifyMail -Type 'alert-notice' -Tokens $tokens -Recipient $rcpt -WhatIf } else { Send-PimNotifyMail -Type 'alert-notice' -Tokens $tokens -Recipient $rcpt }
            if ($r.sent) { $sent++ } elseif ($r.reason) { $lastReason = "$($r.reason)" }
        } catch { $lastReason = "$($_.Exception.Message)" }
    }
    $result.sent = $sent
    if ($sent -eq 0 -and -not $result.reason) { $result.reason = $(if ($lastReason) { $lastReason } else { 'rendered only (no sender / whatif)' }) }
    try { Write-PimManagerAuditEvent -Action 'alert.send' -Target "event:$Event" -After ([ordered]@{ fired = $result.fired; sent = $sent; recipients = @($cfg.recipients).Count; reason = "$($result.reason)" }) -Result $(if ($sent -gt 0) { 'ok' } else { 'noop' }) } catch {}
    # Record the recorded-send PROOF to the durable feed (the [M5] residual fix): a
    # break-glass "owners notified" claim is now backed by a feed entry showing
    # exactly who was notified and whether delivery was recorded.
    if (Get-Command New-PimAlertRecord -ErrorAction SilentlyContinue) {
        try {
            $tenantCtx2 = try { Get-PimManagerTenantContext } catch { @{ tenantName = '' } }
            $rec = New-PimAlertRecord -Event $Event -Title $Title -Detail $Detail -LinkTab $LinkTab -SendResult $result -TenantName "$($tenantCtx2.tenantName)" -Instance "$($script:PimInstanceName)" -WhatIf:$WhatIf
            Write-PimAlertFeedFile -FeedFile (Get-PimManagerAlertFeedPath) -Record $rec | Out-Null
            $result.recorded = $true
        } catch {}
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
    # already overlays the locked/custom PS files) and PERSIST so naming is never
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
    # Departments(+owners). Optional -- empty is allowed (no auto-seed). Each:
    # @{ name; owners = string[]; contact; notes }. Source the delegation-approval
    # workflow uses to resolve dept -> owner.
    $stored = Get-PimManagerSetting -Name 'Departments'
    if ($null -eq $stored) { return @() }
    return @($stored)
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
#                 (cache/<instance>/tenant-org.json) is reused first; when a
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

    $cacheFile = $null
    if (Get-Command Get-PimTenantCacheRoot -ErrorAction SilentlyContinue) {
        try { $cacheFile = Join-Path (Get-PimTenantCacheRoot) 'tenant-org.json' } catch { $cacheFile = $null }
    }

    # 1. Reuse a cached resolution for THIS tenant (so static mode -- which has no
    #    live connection -- still shows the name a prior serve/refresh resolved).
    $cachedName = $null
    if ($cacheFile -and (Test-Path -LiteralPath $cacheFile)) {
        try {
            $raw = [System.IO.File]::ReadAllText($cacheFile, [System.Text.UTF8Encoding]::new($false))
            if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
            $c = $raw | ConvertFrom-Json
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
                if ($cacheFile) {
                    try {
                        $body = [ordered]@{
                            tenantId     = $tenantId
                            tenantName   = $name
                            refreshedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                        } | ConvertTo-Json -Compress
                        $tmp = "$cacheFile.tmp"
                        [System.IO.File]::WriteAllText($tmp, $body, (New-Object System.Text.UTF8Encoding($false)))
                        Move-Item -LiteralPath $tmp -Destination $cacheFile -Force
                    } catch { }
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

    $asgnAdmins    = (Read-PimRows 'PIM-Assignments-Admins').rows
    $asgnGroups    = (Read-PimRows 'PIM-Assignments-Groups').rows
    $asgnRolesGrp  = (Read-PimRows 'PIM-Assignments-Roles-Groups').rows
    $asgnRolesAU   = (Read-PimRows 'PIM-Assignments-Roles-AUs').rows
    $asgnAzRes     = (Read-PimRows 'PIM-Assignments-Azure-Resources').rows

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
        @{ list = $defRoles;     kind = 'role-group';       source = 'PIM-Definitions-Roles' },
        @{ list = $defTasks;     kind = 'permission-group'; source = 'PIM-Definitions-Tasks' },
        @{ list = $defServices;  kind = 'permission-group'; source = 'PIM-Definitions-Services' },
        @{ list = $defProcesses; kind = 'permission-group'; source = 'PIM-Definitions-Processes' },
        @{ list = $defResources; kind = 'permission-group'; source = 'PIM-Definitions-Resources' },
        @{ list = $defDepts;     kind = 'permission-group'; source = 'PIM-Definitions-Departments' },
        @{ list = $defOrg;       kind = 'permission-group'; source = 'PIM-Definitions-Organization' }
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
    #   entra-role -> roleName
    #   au-role    -> roleName, auTag
    #   az-resource-> roleName, scopePath (FULL ARM/path), scopeType, scopeShort
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

    foreach ($t in $syntheticTargets.Values) { [void]$nodes.Add($t) }

    $summary = [ordered]@{
        nodes  = $nodes.Count
        edges  = $edges.Count
        admins = @($nodes | Where-Object { $_.kind -eq 'admin' }).Count
        roleGroups       = @($nodes | Where-Object { $_.kind -eq 'role-group' }).Count
        permissionGroups = @($nodes | Where-Object { $_.kind -eq 'permission-group' }).Count
        targets          = @($nodes | Where-Object { $_.kind -in @('entra-role','au-role','az-resource') }).Count
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
        storageMode  = $(if ($script:PimStorageMode -eq 'sql') { 'sql' } else { 'file' })
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
#   - break-glass                        <- emergency-override.custom.json
#   - access reviews                      <- Get-PimAccessReviewOverview/seed
#   - expiring active assignments         <- Get-PimActiveAssignmentsCached
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
            $schedDir = Join-Path $script:outputRoot 'scheduler'
            $global:PIM_SchedulerStatePath = Join-Path $schedDir 'pim-scheduler-state.json'
            $eff = @(Get-PimManagerEffectiveSchedule)
            $vm  = if ($eff.Count -gt 0) { Get-PimJobsStatus -Jobs $eff } else { Get-PimJobsStatus }
            $jobs = @($vm.jobs)
            $histCount = 0
            try { if (Get-Command Get-PimJobRunHistory -ErrorAction SilentlyContinue) { $histCount = @(Get-PimJobRunHistory).Count } } catch {}
            $failed  = @($jobs | Where-Object { $_.lastOk -eq $false })
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
        $ovFile = Join-Path $script:configRoot 'emergency-override.custom.json'
        if (Test-Path -LiteralPath $ovFile) {
            $ov = Get-Content -LiteralPath $ovFile -Raw -Encoding UTF8 | ConvertFrom-Json
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
                $aa = Get-PimActiveAssignmentsCached
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
            $schedDir = Join-Path $script:outputRoot 'scheduler'
            $global:PIM_SchedulerStatePath = Join-Path $schedDir 'pim-scheduler-state.json'
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
# Static HTML (v0.1 behaviour)
# ---------------------------------------------------------------------------

function Invoke-StaticHtml {
    param([string]$OutHtml)

    Write-Host "Loading PIM4EntraPS config from $configRoot ..." -ForegroundColor Cyan
    $data = Build-PimGraphData

    Write-Host ""
    Write-Host "Graph summary:" -ForegroundColor Cyan
    $data.summary.GetEnumerator() | ForEach-Object {
        Write-Host ("  {0,-18}: {1}" -f $_.Key, $_.Value) -ForegroundColor Gray
    }
    Write-Host ""

    $json = ConvertTo-PimJson -Body $data
    $naming = Get-PimNamingConventions
    $namingJson = ConvertTo-PimJson -Body $naming
    $tenantLists = Read-PimTenantListCache
    $tenantJson  = ConvertTo-PimJson -Body $tenantLists
    $instJson = ConvertTo-PimJson -Body ([ordered]@{ active = $script:PimInstanceName; instances = @() })
    # Feature flags: static mode has no settings store, so bake the pure defaults
    # (the resolver applies the catalog defaults + always-on guard on a null store).
    $featureFlagsJson = '{}'
    try { $featureFlagsJson = ConvertTo-PimJson -Body (Get-PimFeatureFlags) } catch { }
    $html = [System.IO.File]::ReadAllText($template, [System.Text.UTF8Encoding]::new($true))
    $html = $html.Replace('__PIM_DATA__', $json).Replace('__PIM_TOKEN__', '').Replace('__PIM_MODE__', 'static').Replace('__PIM_NAMING__', $namingJson).Replace('__PIM_TENANT_LISTS__', $tenantJson).Replace('__PIM_INSTANCES__', $instJson).Replace('__PIM_VERSION__', (Get-PimSolutionVersion)).Replace('__PIM_ROLE__', '{"role":"Reader","identity":"static","source":"static mode"}').Replace('__PIM_FEATUREFLAGS__', $featureFlagsJson)

    if (-not $OutHtml) {
        $OutHtml = Join-Path ([IO.Path]::GetTempPath()) ("pim-manager-{0}.html" -f ([Guid]::NewGuid().ToString('N').Substring(0,8)))
    }
    [System.IO.File]::WriteAllText($OutHtml, $html, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Rendered: $OutHtml" -ForegroundColor Green
    if (-not $NoLaunch) {
        Write-Host "Launching default browser ..." -ForegroundColor Cyan
        Start-Process $OutHtml
    }
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

function Write-HtmlResponse {
    param(
        [Parameter(Mandatory)][System.Net.HttpListenerResponse]$Response,
        [Parameter(Mandatory)][string]$Html
    )
    try {
        $Response.StatusCode = 200
        $Response.ContentType = 'text/html; charset=utf-8'
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
# Server-side cache lives 60s to avoid hammering Graph + ARG when the operator
# re-opens the tab. `Get-PimActiveAssignmentsCached -Force` bypasses the cache.
# Three sources are combined into a single row set:
#
#   * Entra-role active assignments:
#       Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All
#       (TODO v2.4.3 -- add Get-EntraRoleAssignmentsPreloaded helper to the
#        engine's _shared/PIM-Functions.psm1, mirroring the v2.4.0
#        Get-PimGroupSchedulesPreloaded pattern. For now we call directly.)
#
#   * Azure-RBAC active assignments:
#       Get-AzActiveRoleAssignmentsViaArg  (v2.4.0 helper, Search-AzGraph)
#
#   * PIM-for-Groups active assignments:
#       Get-PimGroupSchedulesPreloaded     (v2.4.0 helper, single Graph call)
#
# The Revoke tab in the Manager only acts on ACTIVE (Assigned) rows -- not
# Eligible -- because eligibility removal is a different operator workflow
# already handled by the Baseline engine. The engine PIM-Assignment-Revoker
# still supports both; the GUI is the bulk-revoke subset.
# ---------------------------------------------------------------------------

function Initialize-PimManagerTenantConnection {
    # Lazy-connect Graph + Az on first Revoke tab use. Reuses the
    # _tenantSync.ps1 helpers so we share the engine-SPN connection logic
    # (no interactive Connect-MgGraph / Connect-AzAccount ever).
    if ($script:PimManagerTenantConnected) { return }
    if (-not (Get-Command Assert-PimTenantConnectionContext -ErrorAction SilentlyContinue)) {
        throw "_tenantSync.ps1 helpers not loaded -- file missing next to Open-PimManager.ps1"
    }
    $tenantId = Assert-PimTenantConnectionContext
    Connect-PimManagerGraph -TenantId $tenantId
    Connect-PimManagerAz    -TenantId $tenantId
    $script:PimManagerTenantConnected = $true
}

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

function Get-PimManagerLookupCaches {
    # Populate $script:PimManager_Users / Groups / Roles for principal +
    # role-display-name resolution in the active-assignments row builder.
    # Pulled once per server start; refreshed only when -Force passed.
    param([switch]$Force)
    if (-not $Force -and $script:PimManager_LookupCachesLoaded) { return }

    Initialize-PimManagerTenantConnection

    Write-Host "  [revoke] loading principal + role lookup caches (one-shot per session) ..." -ForegroundColor DarkGray
    # REST-only (hosted container): no Graph SDK -> pull via PIM-Rest's
    # Invoke-PimGraph and re-shape to SDK casing (.Id/.DisplayName/.UPN) so the
    # row-builder + id indexes below are unchanged.
    $restGraph = (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue) -and -not (Get-Command Get-MgUser -ErrorAction SilentlyContinue)

    # Users. The admin filter (Get-PimAdminsFiltered) needs the engine module;
    # without it (REST-only) pull the admin-pattern users directly, else all.
    try {
        if ((-not $restGraph) -and (Get-Command Get-PimAdminsFiltered -ErrorAction SilentlyContinue)) {
            $script:PimManager_Users = @(Get-PimAdminsFiltered)
        } elseif ($restGraph) {
            $script:PimManager_Users = @(Invoke-PimGraph -Path "/users?`$select=id,displayName,userPrincipalName&`$top=999" -All | ConvertTo-PimSdkShape)
        } else {
            $script:PimManager_Users = @(Get-MgUser -All)
        }
    } catch {
        Write-Warning "  [revoke] user cache load failed: $($_.Exception.Message). Principal names may be blank."
        $script:PimManager_Users = @()
    }
    # Groups (PIM-prefix filter if naming-conventions present, else full set).
    try {
        if ((-not $restGraph) -and (Get-Command Get-PimGroupsFiltered -ErrorAction SilentlyContinue)) {
            $script:PimManager_Groups = @(Get-PimGroupsFiltered)
        } elseif ($restGraph) {
            $pfx = 'PIM-'
            try { if ($global:PIM_NamingConventions -and $global:PIM_NamingConventions.PimGroupPattern -and (Get-Command Get-PimNamePrefix -ErrorAction SilentlyContinue)) { $p = Get-PimNamePrefix -Pattern $global:PIM_NamingConventions.PimGroupPattern; if ($p -and $p.Length -ge 3) { $pfx = $p } } } catch {}
            $f = [uri]::EscapeDataString("startswith(displayName,'$pfx')")
            $script:PimManager_Groups = @(Invoke-PimGraph -Path "/groups?`$filter=$f&`$select=id,displayName,description&`$top=999" -All | ConvertTo-PimSdkShape)
        } else {
            $script:PimManager_Groups = @(Get-MgGroup -All)
        }
    } catch {
        Write-Warning "  [revoke] group cache load failed: $($_.Exception.Message). Group names may be blank."
        $script:PimManager_Groups = @()
    }
    # Entra role definitions (small, single call, no filtering).
    try {
        if ($restGraph) {
            $script:PimManager_EntraRoles = @(Invoke-PimGraph -Path "/roleManagement/directory/roleDefinitions?`$select=id,displayName,isBuiltIn,templateId" -All | ConvertTo-PimSdkShape)
        } else {
            $script:PimManager_EntraRoles = @(Get-MgRoleManagementDirectoryRoleDefinition -All)
        }
    } catch {
        Write-Warning "  [revoke] entra role-definition cache load failed: $($_.Exception.Message). Entra role names may be blank."
        $script:PimManager_EntraRoles = @()
    }
    # AU directory cache (for /administrativeUnits/<id> scope display).
    try {
        if ($restGraph) {
            $script:PimManager_AUs = @(Invoke-PimGraph -Path "/directory/administrativeUnits?`$select=id,displayName" -All | ConvertTo-PimSdkShape)
        } else {
            $script:PimManager_AUs = @(Get-MgDirectoryAdministrativeUnit -All)
        }
    } catch {
        $script:PimManager_AUs = @()
    }

    # Engine helpers (Resolve-PimGroupCached etc.) read $Global:Users_All_ID /
    # $Global:Groups_All_ID. Mirror our caches there so the v2.4.0 helpers
    # stay first-class.
    $Global:Users_All_ID  = $script:PimManager_Users
    $Global:Groups_All_ID = $script:PimManager_Groups

    # Id-keyed indexes: the row builder resolves principal/role/AU labels per
    # assignment row, and a linear scan per row is O(rows x principals) --
    # measurably seconds on a 944-row tenant. Hashtables make it O(rows).
    $script:PimManager_UserById  = @{}
    foreach ($u in $script:PimManager_Users)  { if ($u -and $u.Id)  { $script:PimManager_UserById["$($u.Id)"]  = $u } }
    $script:PimManager_GroupById = @{}
    foreach ($g in $script:PimManager_Groups) { if ($g -and $g.Id)  { $script:PimManager_GroupById["$($g.Id)"] = $g } }
    $script:PimManager_RoleById  = @{}
    foreach ($r in $script:PimManager_EntraRoles) { if ($r -and $r.Id) { $script:PimManager_RoleById["$($r.Id)"] = $r } }
    $script:PimManager_AuById    = @{}
    foreach ($a in $script:PimManager_AUs) { if ($a -and $a.Id) { $script:PimManager_AuById["$($a.Id)"] = $a } }

    $script:PimManager_LookupCachesLoaded = $true
}

function Resolve-PimManagerPrincipalLabel {
    # Try user UPN first, then group DisplayName, then bare id. Hashtable
    # lookups -- called once per assignment row (944 rows on a real tenant).
    param([Parameter(Mandatory)][AllowEmptyString()][string]$PrincipalId)
    if ([string]::IsNullOrWhiteSpace($PrincipalId)) { return '' }
    if ($script:PimManager_UserById -and $script:PimManager_UserById.ContainsKey($PrincipalId)) {
        $u = $script:PimManager_UserById[$PrincipalId]
        if ($u.UserPrincipalName) { return [string]$u.UserPrincipalName }
        if ($u.DisplayName)       { return [string]$u.DisplayName }
        return $PrincipalId
    }
    if ($script:PimManager_GroupById -and $script:PimManager_GroupById.ContainsKey($PrincipalId)) {
        $g = $script:PimManager_GroupById[$PrincipalId]
        if ($g.DisplayName) { return [string]$g.DisplayName }
        return $PrincipalId
    }
    return $PrincipalId
}

function Resolve-PimManagerEntraRoleName {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RoleDefinitionId)
    if ([string]::IsNullOrWhiteSpace($RoleDefinitionId)) { return '' }
    # Trim a possible /providers/.../roleDefinitions/<guid> prefix.
    $guid = $RoleDefinitionId
    $slash = $RoleDefinitionId.LastIndexOf('/')
    if ($slash -ge 0 -and $slash -lt ($RoleDefinitionId.Length - 1)) {
        $guid = $RoleDefinitionId.Substring($slash + 1)
    }
    if ($script:PimManager_RoleById -and $script:PimManager_RoleById.ContainsKey($guid)) {
        $r = $script:PimManager_RoleById[$guid]
        if ($r.DisplayName) { return [string]$r.DisplayName }
    }
    return $guid
}

function Resolve-PimManagerDirectoryScope {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$DirectoryScopeId)
    if ([string]::IsNullOrWhiteSpace($DirectoryScopeId)) { return '/ (tenant-wide)' }
    if ($DirectoryScopeId -eq '/')                       { return '/ (tenant-wide)' }
    if ($DirectoryScopeId -like '/administrativeUnits/*') {
        $auId = ($DirectoryScopeId -split '/')[-1]
        if ($script:PimManager_AuById -and $script:PimManager_AuById.ContainsKey($auId)) {
            return '/AdministrativeUnits/' + [string]$script:PimManager_AuById[$auId].DisplayName
        }
        return $DirectoryScopeId
    }
    return $DirectoryScopeId
}

function Get-PimActiveAssignmentSurfaceHint {
    # Map a failed active-assignments surface + its error text to an ACTIONABLE
    # remediation: which Graph app-role / Azure RBAC role is needed and the exact
    # setup/Grant-PimGraphAppRoles.ps1 invocation. Returns '' when the failure is
    # not a recognised auth/permission failure (transport/transient -> retry).
    param(
        [Parameter(Mandatory)][ValidateSet('entra-role','azure-rbac','pim-for-groups')][string]$Surface,
        [string]$ErrorMessage = ''
    )
    $em = "$ErrorMessage"
    # Recognise the permission-failure signatures (Graph 403 / ARM AuthorizationFailed).
    $isAuth = ($em -match '(?i)\b(401|403)\b' -or
               $em -match '(?i)Authorization_RequestDenied|InsufficientPrivileges|insufficient privileges|Forbidden|AuthorizationFailed|does not have authorization|Authentication_MissingOrMalformed')
    switch ($Surface) {
        'entra-role' {
            if (-not $isAuth) { return '' }
            return ("Engine SPN is missing the Graph app-role to read Entra-role active assignments " +
                    "(roleManagement/directory). Grant RoleManagement.Read.Directory (or RoleManagement.ReadWrite.Directory) " +
                    "via setup/Grant-PimGraphAppRoles.ps1 -TenantId <tid> -AdminClientId <mgmtSpn> -AdminCertThumbprint <thumb> -EngineAppId <engineSpn>.")
        }
        'pim-for-groups' {
            if (-not $isAuth) { return '' }
            return ("Engine SPN is missing the Graph app-role to read PIM-for-Groups active assignments " +
                    "(identityGovernance/privilegedAccess/group). Grant PrivilegedAccess.Read.AzureADGroup " +
                    "(or PrivilegedAccess.ReadWrite.AzureADGroup) via setup/Grant-PimGraphAppRoles.ps1.")
        }
        'azure-rbac' {
            return ("Engine SPN cannot read Azure-RBAC active assignments. Grant it at least Reader on the " +
                    "target subscription(s) (Azure RBAC, not a Graph app-role) so " +
                    "Microsoft.Authorization/roleAssignmentScheduleInstances can be enumerated.")
        }
    }
    return ''
}

function Get-PimActiveAssignmentsCached {
    # Returns hashtable: @{ ok; rows = [...]; loadedUtc; counts = @{...}; surfaceErrors; partial; error?; cacheHit }.
    param([switch]$Force)

    $maxAgeSeconds = 60
    if (-not $Force -and $script:PimActiveAssignmentsCache -and $script:PimActiveAssignmentsCacheLoadedUtc) {
        $age = ([DateTime]::UtcNow - $script:PimActiveAssignmentsCacheLoadedUtc).TotalSeconds
        if ($age -lt $maxAgeSeconds) {
            $cachedErrs = @()
            if ($script:PimActiveAssignmentsCache.surfaceErrors) { $cachedErrs = @($script:PimActiveAssignmentsCache.surfaceErrors) }
            return [ordered]@{
                ok            = (-not (@($script:PimActiveAssignmentsCache.rows).Count -eq 0 -and $cachedErrs.Count -gt 0))
                rows          = $script:PimActiveAssignmentsCache.rows
                loadedUtc     = $script:PimActiveAssignmentsCache.loadedUtc
                counts        = $script:PimActiveAssignmentsCache.counts
                surfaceErrors = $cachedErrs
                cacheHit      = $true
                ageSeconds    = [math]::Round($age, 0)
            }
        }
    }

    # Initial connect + lookup caches (idempotent).
    Initialize-PimManagerTenantConnection
    Get-PimManagerLookupCaches

    # The v2.4.0 helpers + Entra-role-direct call all live in the engine's
    # PIM-Functions.psm1. Import lazily so the Manager works without the
    # engine being imported separately.
    $shared = Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Functions.psm1'
    if (Test-Path -LiteralPath $shared) {
        Import-Module $shared -Global -Force -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.ArrayList

    # Per-surface failure ledger. Each entry: @{ surface; error; hint }.
    # When a surface FETCH fails (auth/permission/transport) we record it here
    # instead of silently swallowing to @(). This is what lets the endpoint and
    # GUI tell "genuinely no active assignments" apart from "we could not read
    # them" -- the old code returned ok=$true,total=0 for BOTH, which surfaced as
    # the misleading "Cache may be empty -- click Refresh." (root cause).
    $surfaceErrors = New-Object System.Collections.ArrayList

    # REST-only (hosted container): mint tokens + read Graph/ARM via PIM-Rest.ps1
    # -- the Graph/Az PowerShell SDK is not installed in the image.
    $restGraph = (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue) -and -not (Get-Command Get-MgRoleManagementDirectoryRoleAssignmentSchedule -ErrorAction SilentlyContinue)
    $restArm   = (Get-Command Invoke-PimArm   -ErrorAction SilentlyContinue) -and -not (Get-Command Get-AzActiveRoleAssignmentsViaArg -ErrorAction SilentlyContinue)

    # ---- Entra-role active assignments -------------------------------------
    # TODO v2.4.3: replace with Get-EntraRoleAssignmentsPreloaded helper once
    # ported into engine/_shared/PIM-Functions.psm1 (mirror of the
    # Get-PimGroupSchedulesPreloaded pattern). For now: direct -All call.
    $entraRows = @()
    try {
        if ($restGraph) {
            # REST: same collection, camelCase -> reshape to SDK casing so the
            # ScheduleInfo/Expiration nested fields below resolve unchanged.
            $entraRows = @(Invoke-PimGraph -Path '/roleManagement/directory/roleAssignmentSchedules' -All | ConvertTo-PimSdkShape)
        } else {
            $entraRows = @(Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ErrorAction Stop)
        }
    } catch {
        $em = "$($_.Exception.Message)"
        Write-Warning "  [revoke] entra-role assignment-schedules load failed: $em"
        [void]$surfaceErrors.Add([ordered]@{
            surface = 'entra-role'
            error   = $em
            hint    = (Get-PimActiveAssignmentSurfaceHint -Surface 'entra-role' -ErrorMessage $em)
        })
        $entraRows = @()
    }
    foreach ($e in $entraRows) {
        if (-not $e) { continue }
        $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId ([string]$e.PrincipalId)
        $roleLabel      = Resolve-PimManagerEntraRoleName -RoleDefinitionId ([string]$e.RoleDefinitionId)
        $scopeLabel     = Resolve-PimManagerDirectoryScope -DirectoryScopeId ([string]$e.DirectoryScopeId)
        # SDK objects expose PascalCase; REST returns camelCase nested objects
        # (ConvertTo-PimSdkShape only aliases the top level). Tolerate both.
        $si = if ($e.ScheduleInfo) { $e.ScheduleInfo } else { $e.scheduleInfo }
        $start = $null; $end = $null
        if ($si) {
            $sdt = if ($si.StartDateTime) { $si.StartDateTime } else { $si.startDateTime }
            if ($sdt) { try { $start = ([DateTime]$sdt).ToUniversalTime().ToString('o') } catch {} }
            $exp = if ($si.Expiration) { $si.Expiration } else { $si.expiration }
            if ($exp) {
                $edt = if ($exp.EndDateTime) { $exp.EndDateTime } else { $exp.endDateTime }
                if ($edt) { try { $end = ([DateTime]$edt).ToUniversalTime().ToString('o') } catch {} }
            }
        }
        [void]$rows.Add([ordered]@{
            id               = "entra-role:$($e.Id)"
            type             = 'entra-role'
            principal        = $principalLabel
            principalId      = [string]$e.PrincipalId
            role             = $roleLabel
            roleDefinitionId = [string]$e.RoleDefinitionId
            scope            = $scopeLabel
            directoryScopeId = [string]$e.DirectoryScopeId
            start            = $start
            end              = $end
            justification    = ''  # Entra role assignment schedules don't carry the original activation justification on the assignment object.
        })
    }

    # ---- Azure-RBAC active assignments -------------------------------------
    $azRows = @()
    if ($restArm) {
        # REST: enumerate active role-assignment-schedule-instances at each
        # subscription scope (ARM has no tenant-wide list). PrincipalNotFound /
        # auth errors per-sub are tolerated so one bad sub doesn't blank the tab.
        try {
            $subs = @(Invoke-PimArm -Path '/subscriptions' -ApiVersion '2020-01-01' -All)
            if ($subs.Count -eq 0) {
                Write-Warning "  [revoke] ARM returned 0 subscriptions for this identity -- Azure RBAC rows will be empty (engine SPN has no subscription scope / no Reader)."
                [void]$surfaceErrors.Add([ordered]@{
                    surface = 'azure-rbac'
                    error   = 'ARM returned 0 subscriptions visible to the engine identity.'
                    hint    = 'Grant the engine SPN at least Reader on the target subscription(s) so Azure-RBAC active assignments can be enumerated.'
                })
            }
            foreach ($s in $subs) {
                $scope = "/subscriptions/$($s.subscriptionId)"
                try {
                    foreach ($ri in @(Invoke-PimArm -Path "$scope/providers/Microsoft.Authorization/roleAssignmentScheduleInstances" -ApiVersion '2020-10-01-preview' -All)) {
                        $p = $ri.properties
                        $rdId = "$($p.roleDefinitionId)"
                        $azRows += [pscustomobject]@{
                            Id                 = "$($ri.id)"
                            PrincipalId        = "$($p.principalId)"
                            RoleDefinitionId   = $rdId
                            RoleDefinitionName = ($rdId -split '/' | Select-Object -Last 1)
                            Scope              = "$($p.scope)"
                        }
                    }
                } catch { Write-Warning ("  [revoke] ARM role-assignment instances for {0} failed: {1}" -f $scope, $_.Exception.Message) }
            }
        } catch {
            $em = "$($_.Exception.Message)"
            Write-Warning "  [revoke] ARM subscriptions enumeration failed: $em. Azure RBAC rows will be empty."
            [void]$surfaceErrors.Add([ordered]@{
                surface = 'azure-rbac'
                error   = $em
                hint    = (Get-PimActiveAssignmentSurfaceHint -Surface 'azure-rbac' -ErrorMessage $em)
            })
            $azRows = @()
        }
    } elseif (Get-Command Get-AzActiveRoleAssignmentsViaArg -ErrorAction SilentlyContinue) {
        try {
            $azRows = @(Get-AzActiveRoleAssignmentsViaArg)
        } catch {
            $em = "$($_.Exception.Message)"
            Write-Warning "  [revoke] Get-AzActiveRoleAssignmentsViaArg failed: $em"
            [void]$surfaceErrors.Add([ordered]@{
                surface = 'azure-rbac'
                error   = $em
                hint    = (Get-PimActiveAssignmentSurfaceHint -Surface 'azure-rbac' -ErrorMessage $em)
            })
            $azRows = @()
        }
    } else {
        $em = 'Azure-RBAC reader not available (no ARM REST helper Invoke-PimArm + no engine _shared/PIM-Functions.psm1 reader).'
        Write-Warning "  [revoke] $em Azure RBAC rows will be empty."
        [void]$surfaceErrors.Add([ordered]@{
            surface = 'azure-rbac'
            error   = $em
            hint    = 'Ensure engine/_shared/PIM-Rest.ps1 is dot-sourced (hosted) so Invoke-PimArm is available.'
        })
    }
    foreach ($a in $azRows) {
        if (-not $a) { continue }
        $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId ([string]$a.PrincipalId)
        $roleName       = if ($a.RoleDefinitionName) { [string]$a.RoleDefinitionName } else { [string]$a.RoleDefinitionId }
        [void]$rows.Add([ordered]@{
            id               = "azure-rbac:$($a.Id)"
            type             = 'azure-rbac'
            principal        = $principalLabel
            principalId      = [string]$a.PrincipalId
            role             = $roleName
            roleDefinitionId = [string]$a.RoleDefinitionId
            scope            = [string]$a.Scope
            directoryScopeId = ''
            start            = ''  # ARG row doesn't carry start/end for the assignment record.
            end              = ''
            justification    = ''
        })
    }

    # ---- PIM-for-Groups active assignments ---------------------------------
    # Graph REFUSES an unfiltered list on assignmentSchedules ('MissingParameters:
    # The required parameters GroupId or PrincipalId is missing') -- both the
    # engine's bulk preload and a naive -All call get BadRequest. The supported
    # shape is one filtered query per group. Two scale guards:
    #   1. Only PIM-convention groups qualify (the lookup cache can contain the
    #      whole tenant when the naming filter is broad; dynamic groups fail
    #      with ResourceTypeNotSupported anyway).
    #   2. Queries go through /v1.0/$batch, 20 per round-trip -- a per-group
    #      sequential loop took >4 minutes on a real tenant.
    $pimGroupRows = @()
    $pimPrefix = 'PIM-'
    try {
        if ((Get-Command Get-PimNamePrefix -ErrorAction SilentlyContinue) -and $global:PIM_NamingConventions -and $global:PIM_NamingConventions.PimGroupPattern) {
            $p = Get-PimNamePrefix -Pattern $global:PIM_NamingConventions.PimGroupPattern
            if ($p -and $p.Length -ge 3) { $pimPrefix = $p }
        }
    } catch { }
    $pimGroupsToQuery = @($script:PimManager_Groups | Where-Object { $_ -and $_.Id -and $_.DisplayName -and ([string]$_.DisplayName).StartsWith($pimPrefix, [System.StringComparison]::OrdinalIgnoreCase) })
    if ($pimGroupsToQuery.Count -gt 0) {
        $gFail = 0
        $gFirstErr = $null
        for ($ofs = 0; $ofs -lt $pimGroupsToQuery.Count; $ofs += 20) {
            $slice = $pimGroupsToQuery[$ofs..([Math]::Min($ofs + 19, $pimGroupsToQuery.Count - 1))]
            $requests = New-Object System.Collections.ArrayList
            for ($i = 0; $i -lt $slice.Count; $i++) {
                [void]$requests.Add(@{
                    id     = "$i"
                    method = 'GET'
                    url    = "/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$($slice[$i].Id)'"
                })
            }
            try {
                if ($restGraph) {
                    # REST: Invoke-PimGraph posts the JSON batch with its own app-only token.
                    $resp = Invoke-PimGraph -Method POST -Path 'https://graph.microsoft.com/v1.0/$batch' -Body @{ requests = $requests.ToArray() }
                } else {
                    $resp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/$batch' -Body (@{ requests = $requests.ToArray() } | ConvertTo-Json -Depth 6) -ContentType 'application/json' -ErrorAction Stop
                }
                foreach ($br in @($resp.responses)) {
                    if ($br.status -ge 200 -and $br.status -lt 300 -and $br.body -and $br.body.value) {
                        foreach ($v in @($br.body.value)) { $pimGroupRows += $v }
                    } elseif ($br.status -ge 400) {
                        $gFail++
                        $errCode = if ($br.body -and $br.body.error) { $br.body.error.code } else { $br.status }
                        $errMsg  = if ($br.body -and $br.body.error -and $br.body.error.message) { $br.body.error.message } else { "$errCode" }
                        if (-not $gFirstErr -and ($br.status -eq 401 -or $br.status -eq 403)) { $gFirstErr = "HTTP $($br.status) $errCode : $errMsg" }
                        if ($gFail -le 3) { Write-Warning ("  [revoke] assignmentSchedules for group '{0}' failed: {1}" -f $slice[[int]$br.id].DisplayName, $errCode) }
                    }
                }
            } catch {
                $gFail += $slice.Count
                if (-not $gFirstErr) { $gFirstErr = "$($_.Exception.Message)" }
                if ($gFail -le 25) { Write-Warning "  [revoke] `$batch round-trip failed: $($_.Exception.Message)" }
            }
        }
        if ($gFail -gt 3) { Write-Warning ("  [revoke] assignmentSchedules failed for {0} group(s) total (first 3 shown)." -f $gFail) }
        # Only a surface-level error when EVERY queried group failed AND we got
        # nothing back -- a few per-group failures (e.g. dynamic groups) are
        # tolerated and must not mask a partially-successful read.
        if ($pimGroupRows.Count -eq 0 -and $gFail -ge $pimGroupsToQuery.Count -and $gFirstErr) {
            [void]$surfaceErrors.Add([ordered]@{
                surface = 'pim-for-groups'
                error   = $gFirstErr
                hint    = (Get-PimActiveAssignmentSurfaceHint -Surface 'pim-for-groups' -ErrorMessage $gFirstErr)
            })
        }
        Write-Host ("  [revoke] pim-for-groups: {0} active assignment(s) across {1} PIM group(s) ({2} batch round-trips)" -f $pimGroupRows.Count, $pimGroupsToQuery.Count, [Math]::Ceiling($pimGroupsToQuery.Count / 20)) -ForegroundColor DarkGray
    } else {
        Write-Warning ("  [revoke] no '{0}'-prefixed groups in the lookup cache. PIM-for-Groups rows will be empty." -f $pimPrefix)
    }
    # Casing-tolerant property read: SDK objects are PascalCase, REST/$batch
    # bodies are camelCase. Returns the first present alias (or '').
    $pf = {
        param($Obj, [string[]]$Names)
        foreach ($n in $Names) { $pr = $Obj.PSObject.Properties[$n]; if ($pr -and $null -ne $pr.Value) { return $pr.Value } }
        return $null
    }
    foreach ($p in $pimGroupRows) {
        if (-not $p) { continue }
        $principalId = "$(& $pf $p @('PrincipalId','principalId'))"
        $groupId     = "$(& $pf $p @('GroupId','groupId'))"
        $itemId      = "$(& $pf $p @('Id','id'))"
        $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId $principalId
        # Group display name from cache, fall back to embedded Group.DisplayName.
        $groupLabel = ''
        if ($script:PimManager_Groups) {
            foreach ($g in $script:PimManager_Groups) {
                if ($g -and "$($g.Id)" -eq $groupId) { $groupLabel = [string]$g.DisplayName; break }
            }
        }
        $grp = & $pf $p @('Group','group')
        if (-not $groupLabel -and $grp) { $gdn = & $pf $grp @('DisplayName','displayName'); if ($gdn) { $groupLabel = [string]$gdn } }
        if (-not $groupLabel) { $groupLabel = $groupId }
        $si = & $pf $p @('ScheduleInfo','scheduleInfo')
        $start = $null; $end = $null
        if ($si) {
            $sdt = & $pf $si @('StartDateTime','startDateTime')
            if ($sdt) { try { $start = ([DateTime]$sdt).ToUniversalTime().ToString('o') } catch {} }
            $exp = & $pf $si @('Expiration','expiration')
            if ($exp) { $edt = & $pf $exp @('EndDateTime','endDateTime'); if ($edt) { try { $end = ([DateTime]$edt).ToUniversalTime().ToString('o') } catch {} } }
        }
        $access = "$(& $pf $p @('AccessId','accessId'))"; if (-not $access) { $access = 'member' }
        $just   = "$(& $pf $p @('Justification','justification'))"
        [void]$rows.Add([ordered]@{
            id               = "pim-for-groups:$itemId"
            type             = 'pim-for-groups'
            principal        = $principalLabel
            principalId      = $principalId
            role             = "$groupLabel ($access)"
            roleDefinitionId = ''
            scope            = $groupLabel
            directoryScopeId = ''
            groupId          = $groupId
            accessId         = $access
            start            = $start
            end              = $end
            justification    = $just
        })
    }

    $sw.Stop()
    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    $counts = [ordered]@{
        total           = $rows.Count
        'entra-role'    = @($rows | Where-Object { $_.type -eq 'entra-role' }).Count
        'azure-rbac'    = @($rows | Where-Object { $_.type -eq 'azure-rbac' }).Count
        'pim-for-groups' = @($rows | Where-Object { $_.type -eq 'pim-for-groups' }).Count
    }
    Write-Host ("  [revoke] active-assignments loaded: {0} total ({1}e + {2}a + {3}g) in {4}s" -f $counts.total, $counts['entra-role'], $counts['azure-rbac'], $counts['pim-for-groups'], $elapsed) -ForegroundColor DarkGray

    $errArr = $surfaceErrors.ToArray()
    if ($errArr.Count -gt 0) {
        Write-Warning ("  [revoke] {0} surface(s) could NOT be read: {1}" -f $errArr.Count, (($errArr | ForEach-Object { $_.surface }) -join ', '))
    }
    # A read is FULLY-FAILED (not "empty") when nothing came back AND at least one
    # surface raised an auth/permission/transport error. The endpoint flags that
    # so the GUI shows an actionable error instead of "Cache may be empty".
    $allFailedEmpty = ($rows.Count -eq 0 -and $errArr.Count -gt 0)

    $loadedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $payload = [ordered]@{
        ok            = (-not $allFailedEmpty)
        rows          = $rows.ToArray()
        counts        = $counts
        surfaceErrors = $errArr
        partial       = ($rows.Count -gt 0 -and $errArr.Count -gt 0)
        loadedUtc     = $loadedUtc
        cacheHit      = $false
        elapsedSec    = $elapsed
    }
    if ($allFailedEmpty) {
        $payload.error = "Active PIM assignments could not be read from any surface. " + (($errArr | ForEach-Object {
            $h = if ($_.hint) { " ($($_.hint))" } else { '' }
            "[$($_.surface)] $($_.error)$h"
        }) -join '  |  ')
    }
    $script:PimActiveAssignmentsCache = [ordered]@{
        rows          = $payload.rows
        counts        = $payload.counts
        surfaceErrors = $payload.surfaceErrors
        loadedUtc     = $payload.loadedUtc
    }
    $script:PimActiveAssignmentsCacheLoadedUtc = [DateTime]::UtcNow
    return $payload
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

function Invoke-PimActiveAssignmentRevokeBatch {
    # Returns an array of per-row { id, ok, error? } in the same order as $Rows.
    param(
        [Parameter(Mandatory)][object[]]$Rows,
        [Parameter(Mandatory)][string]$Justification
    )

    Initialize-PimManagerTenantConnection

    # REST-only (hosted container): issue the adminRemove requests over REST
    # (PIM-Rest.ps1) -- no Graph/Az SDK in the image.
    $restGraph = (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue) -and -not (Get-Command New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -ErrorAction SilentlyContinue)
    $restArm   = (Get-Command Invoke-PimArm   -ErrorAction SilentlyContinue) -and -not (Get-Command Invoke-AzRestMethod -ErrorAction SilentlyContinue)

    $results = New-Object System.Collections.ArrayList
    foreach ($r in $Rows) {
        if (-not $r) {
            [void]$results.Add([ordered]@{ id = $null; ok = $false; error = 'null row' })
            continue
        }
        $rowId = if ($r.id) { [string]$r.id } else { '' }
        $type  = if ($r.type) { [string]$r.type } else { '' }
        try {
            switch ($type) {
                'entra-role' {
                    # Trim a possible roleDefinitions/<guid> prefix that the
                    # original schedule object carries -- the BodyParameter
                    # expects the bare GUID.
                    $roleDefId = [string]$r.roleDefinitionId
                    if ($roleDefId -and $roleDefId.Contains('/')) {
                        $roleDefId = $roleDefId.Substring($roleDefId.LastIndexOf('/') + 1)
                    }
                    $directoryScopeId = if ($r.directoryScopeId) { [string]$r.directoryScopeId } else { '/' }
                    $params = @{
                        action           = 'adminRemove'
                        principalId      = [string]$r.principalId
                        roleDefinitionId = $roleDefId
                        directoryScopeId = $directoryScopeId
                        justification    = $Justification
                    }
                    if ($restGraph) {
                        $resp = Invoke-PimGraph -Method POST -Path '/roleManagement/directory/roleAssignmentScheduleRequests' -Body $params
                    } else {
                        $resp = New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop
                    }
                    [void]$results.Add([ordered]@{ id = $rowId; ok = $true; requestId = "$($resp.Id)$($resp.id)" })
                    Write-Host ("  [revoke][entra-role] OK -- principal {0} role {1}" -f $r.principalId, $roleDefId) -ForegroundColor DarkGray
                }
                'azure-rbac' {
                    $scope = [string]$r.scope
                    if ([string]::IsNullOrWhiteSpace($scope)) {
                        throw "missing scope for azure-rbac row"
                    }
                    $roleDefId = [string]$r.roleDefinitionId
                    if ($roleDefId -and $roleDefId.Contains('/')) {
                        $roleDefId = $roleDefId.Substring($roleDefId.LastIndexOf('/') + 1)
                    }
                    $newGuid = [Guid]::NewGuid().ToString()
                    $uri = $scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/' + $newGuid + '?api-version=2020-10-01'
                    $body = @{
                        properties = @{
                            principalId      = [string]$r.principalId
                            roleDefinitionId = "$scope/providers/Microsoft.Authorization/roleDefinitions/$roleDefId"
                            requestType      = 'AdminRemove'
                            justification    = $Justification
                        }
                    }
                    if ($restArm) {
                        # Invoke-PimArm throws on non-2xx with the API body in the message.
                        $resp = Invoke-PimArm -Method PUT -Path $uri -Body $body
                        [void]$results.Add([ordered]@{ id = $rowId; ok = $true; requestId = "$($resp.name)" })
                        Write-Host ("  [revoke][azure-rbac] OK -- principal {0} scope {1}" -f $r.principalId, $scope) -ForegroundColor DarkGray
                    } else {
                        $bodyJson = $body | ConvertTo-Json -Depth 10 -Compress
                        $resp = Invoke-AzRestMethod -Method PUT -Path $uri -Payload $bodyJson -ErrorAction Stop
                        if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) {
                            [void]$results.Add([ordered]@{ id = $rowId; ok = $true; statusCode = $resp.StatusCode })
                            Write-Host ("  [revoke][azure-rbac] OK ({0}) -- principal {1} scope {2}" -f $resp.StatusCode, $r.principalId, $scope) -ForegroundColor DarkGray
                        } else {
                            $errText = "HTTP $($resp.StatusCode): $($resp.Content)"
                            [void]$results.Add([ordered]@{ id = $rowId; ok = $false; error = $errText })
                            Write-Warning ("  [revoke][azure-rbac] FAIL -- {0}" -f $errText)
                        }
                    }
                }
                'pim-for-groups' {
                    $accessId = if ($r.accessId) { [string]$r.accessId } else { 'member' }
                    $params = @{
                        accessId      = $accessId
                        principalId   = [string]$r.principalId
                        groupId       = [string]$r.groupId
                        action        = 'adminRemove'
                        justification = $Justification
                    }
                    if ($restGraph) {
                        $resp = Invoke-PimGraph -Method POST -Path '/identityGovernance/privilegedAccess/group/assignmentScheduleRequests' -Body $params
                    } else {
                        $resp = New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter $params -ErrorAction Stop
                    }
                    [void]$results.Add([ordered]@{ id = $rowId; ok = $true; requestId = "$($resp.Id)$($resp.id)" })
                    Write-Host ("  [revoke][pim-for-groups] OK -- principal {0} group {1}" -f $r.principalId, $r.groupId) -ForegroundColor DarkGray
                }
                default {
                    throw "unknown row type: '$type' (expected entra-role | azure-rbac | pim-for-groups)"
                }
            }
        } catch {
            $msg = "$($_.Exception.Message)"
            [void]$results.Add([ordered]@{ id = $rowId; ok = $false; error = $msg })
            Write-Warning ("  [revoke][{0}] FAIL -- {1}" -f $type, $msg)
        }
    }

    return $results.ToArray()
}

function Invoke-Server {
    param([int]$DesiredPort = 0)

    Write-Host "PIM4EntraPS Mapper -- starting local editor server ..." -ForegroundColor Cyan
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
        $roleJson = (Get-PimManagerRole | ConvertTo-Json -Compress)
        # Feature flags baked at boot so the nav/tab render gates BEFORE first paint
        # (a toggle takes effect on reload). Best-effort -- on any failure fall back
        # to an empty object so the resolver applies pure defaults (never nav-less).
        $featureFlagsJson = '{}'
        try { $featureFlagsJson = ConvertTo-PimJson -Body (Get-PimFeatureFlags) } catch { Write-Warning "feature-flags boot skipped: $($_.Exception.Message)" }
        $modeLabel = if ($script:PimStorageMode -eq 'sql') { "SQL: $($global:PIM_SqlDatabase)" } else { 'server' }
        $html = $html.Replace('__PIM_DATA__', $json).Replace('__PIM_TOKEN__', $ExpectedToken).Replace('__PIM_MODE__', $modeLabel).Replace('__PIM_NAMING__', $namingJson).Replace('__PIM_TENANT_LISTS__', $tenantJson).Replace('__PIM_INSTANCES__', $instJson).Replace('__PIM_VERSION__', (Get-PimSolutionVersion)).Replace('__PIM_ROLE__', $roleJson).Replace('__PIM_FEATUREFLAGS__', $featureFlagsJson)
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
            store       = $(if ($script:PimStorageMode -eq 'sql') { 'sql' } else { 'file' })
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
            $sqlMode = ($script:PimStorageMode -eq 'sql' -and $script:PimSqlCs)

            if ($method -eq 'GET') {
                if ($sqlMode) {
                    $rows = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $base)
                    $payload = [ordered]@{ path = 'sql'; source = 'sql'; header = @($spec.defaultHeader) }
                } else {
                    $payload = Read-PimRows -BaseName $base
                    $rows = @($payload.rows)
                }
                # Portal-admin read scoping: a delegated GUI-manager (non-super,
                # with a portal-admins profile) sees only the rows their tier/
                # level/service/scope allows. Super-admins + users with no portal
                # profile see everything (unchanged).
                $portalFiltered = $false
                if ((Get-Command Test-PimManagerRoleAtLeast -ErrorAction SilentlyContinue) -and -not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin') -and (Get-Command Read-PimPortalProfiles -ErrorAction SilentlyContinue)) {
                    $who = (Get-PimManagerRole).identity
                    $prof = Get-PimPortalProfile -Profiles (Read-PimPortalProfiles -ConfigDir $script:configRoot) -Identity "$who"
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
                    Write-JsonResponse -Response $resp -Status 403 -Body @{ error = "Your Manager role is Reader -- saving changes requires Admin. See config/manager-access.custom.json." }
                    return 403
                }
                $body = Read-RequestJson -Request $req
                $rowsRaw = @()
                if ($body -and $body.rows) { $rowsRaw = @($body.rows) }
                $rowsOrdered = @($rowsRaw | ForEach-Object { ConvertTo-OrderedRow $_ } | Where-Object { $_ -ne $null })

                # Diff against current state (SQL or CSV) for the audit log AND the
                # pre-commit snapshot ([M1]). Capture header too, so an undo restores
                # the exact column layout (file mode preserves separator/blank rows).
                $current = if ($sqlMode) {
                    $spec = Get-PimCsvSpec -BaseName $base
                    @{ rows = @(Get-PimSqlRows -ConnectionString $script:PimSqlCs -Entity $base); header = $(if ($spec) { @($spec.defaultHeader) } else { @() }) }
                } else { Read-PimRows -BaseName $base }
                $diff = Compare-PimRowSets -Before $current.rows -After $rowsOrdered -Base $base

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
                $writtenPath = if ($sqlMode) { 'sql' } else { (Join-Path $script:configRoot "$base.custom.csv") }
                Write-PimMutationLog -BaseName $base -Adds $diff.adds.Count -Removes $diff.removes.Count -Modifies $diff.modifies.Count -NewRowCount $rowsOrdered.Count

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
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required. See config/manager-access.custom.json.' }
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
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to edit settings. See config/manager-access.custom.json.' }
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
                        $arr = if ($body -and $body.PSObject.Properties['value']) { @($body.value) } else { @($body) }
                        Set-PimManagerSetting -Name 'Departments' -Value $arr
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
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to import departments. See config/manager-access.custom.json.' }
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
                Set-PimManagerSetting -Name 'Departments' -Value @($plan.departments)
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
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to import approvers. See config/manager-access.custom.json.' }
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
                Set-PimManagerSetting -Name 'Departments' -Value @($plan.departments)
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
        # settings for the onboarding wizard. Shipped *.admintemplate.json +
        # customer *.admintemplate.custom.json (additive; same id in a custom
        # file overrides the shipped one).
        # -------------------------------------------------------------------
        if ($path -eq '/api/admin-templates' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $tplDir = Join-Path $solutionRoot 'templates\admin'
            $byId = @{}
            if (Test-Path -LiteralPath $tplDir) {
                $files = @(Get-ChildItem -LiteralPath $tplDir -Filter '*.admintemplate.json' -ErrorAction SilentlyContinue) +
                         @(Get-ChildItem -LiteralPath $tplDir -Filter '*.admintemplate.custom.json' -ErrorAction SilentlyContinue)
                foreach ($f in $files) {
                    try {
                        $tpl = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                        if ($tpl.id) { $byId[$tpl.id] = $tpl }   # custom files enumerate last -> same id wins
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

            $auditDir = Join-Path $script:outputRoot 'audit'
            $events = @(Read-PimAuditEvents -AuditDir $auditDir -Months $months)
            # Category counts BEFORE search/category filtering (chips show totals).
            $counts = @{}
            foreach ($e in $events) { $c = "$($e.category)"; if ($c) { $counts[$c] = ([int]$counts[$c]) + 1 } }

            $sorted = @(Select-PimAuditEvents -Events $events -Category $category -Search $search -FromUtc $fromUtc -ToUtc $toUtc)
            $matchCount = $sorted.Count
            $skip = ($page - 1) * $pageSize
            $pageItems = @($sorted | Select-Object -Skip $skip -First $pageSize)
            $monthsAvail = @(Get-PimAuditMonthList -AuditDir $auditDir)
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
                monthsLoaded = if ($months -eq 0) { $monthsAvail.Count } else { [Math]::Min($months, $monthsAvail.Count) }
                monthsTotal  = $monthsAvail.Count   # how many monthly files exist on disk
            }
            return 200
        }

        if ($path -eq '/api/audit/export' -and $method -eq 'GET') {
            # [H6]/[H5] Full-trail CSV export: stream the WHOLE filtered audit trail
            # (every matching event, NOT just the page on screen) as a CSV download
            # -- including the before/after Change column. Honours the SAME
            # category/search/date/months filter the Audit tab is showing, so the
            # export equals "what I'm looking at, in full". Read-only.
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
            $auditDir = Join-Path $script:outputRoot 'audit'
            $events = @(Read-PimAuditEvents -AuditDir $auditDir -Months $months)
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
                # PS 5.1: @() over a List[object] of PSCustomObjects throws ArgumentException
                # ("Argument types do not match") -- use .ToArray() (see memory: ps51_list_object_wrap).
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
                $res = Invoke-PimOffboardExecution -RequestId $apprId -ConfirmBulk:$confirmBulk `
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
                Write-PimManagerAuditEvent -Action 'approval.request.executed' -Target "$($res.target)" -Result $(if ($res.ok) { 'ok' } else { 'partial' }) -After @{ id = "$($res.request.id)"; approver = "$($res.approval.approver)"; steps = @($res.results).Count }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = [bool]$res.ok; gate = "$($res.gate)"; target = "$($res.target)"; reason = "$($res.reason)"; results = @($res.results) })
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
            # Point the scheduler read model at THIS instance's state file (sibling
            # run-history file resolves automatically). SQL-backed deployments override
            # this transparently via Get-PimSetting inside the lib.
            $schedDir = Join-Path $script:outputRoot 'scheduler'
            $global:PIM_SchedulerStatePath = Join-Path $schedDir 'pim-scheduler-state.json'
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
            $schedDir = Join-Path $script:outputRoot 'scheduler'
            if (-not (Test-Path -LiteralPath $schedDir)) { New-Item -ItemType Directory -Path $schedDir -Force | Out-Null }
            $global:PIM_SchedulerStatePath = Join-Path $schedDir 'pim-scheduler-state.json'
            # Resolve the job from the effective schedule so it carries the live cadence/scope.
            $eff = @(Get-PimManagerEffectiveSchedule)
            $job = @($eff | Where-Object { "$($_.name)" -eq $name }) | Select-Object -First 1
            if (-not $job) { Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown job '$name'" }; return 404 }
            try {
                $r = Invoke-PimJobForceStart -Name $name -Job $job
                Write-PimManagerAuditEvent -Action 'schedule.job.run' -Target "job:$name" -After @{ runId = "$($r.runId)"; status = "$($r.status)" } -Result $(if ($r.ok) { 'ok' } else { 'error' })
                # Alerting (REQUIREMENTS §27 H2): a job that finished NOT-ok is an
                # engine-run failure -> fire the engine-failure alert through the
                # existing notify path. No-op when alerting/sender unconfigured.
                if (-not $r.ok -and "$($r.status)" -ne 'running') {
                    try { Send-PimManagerAlert -Event 'engine-failure' -Title "Job '$name' FAILED" -Detail "$($r.detail)" -LinkTab 'jobs' | Out-Null } catch {}
                }
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
            $schedDir = Join-Path $script:outputRoot 'scheduler'
            $global:PIM_SchedulerStatePath = Join-Path $schedDir 'pim-scheduler-state.json'
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
            $schedDir = Join-Path $script:outputRoot 'scheduler'
            $global:PIM_SchedulerStatePath = Join-Path $schedDir 'pim-scheduler-state.json'
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
            $schedDir = Join-Path $script:outputRoot 'scheduler'
            $global:PIM_SchedulerStatePath = Join-Path $schedDir 'pim-scheduler-state.json'
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
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to change alerting. See config/manager-access.custom.json.' }
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
            try {
                $cfg = Set-PimAlertingConfig -Recipients $recips -Events $events
                Write-PimManagerAuditEvent -Action 'alerting.save' -Target 'settings:alerting' -After ([ordered]@{ recipients = @($cfg.recipients).Count; enabled = [bool]$cfg.enabled }) -Result 'ok'
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
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to edit operational policy. See config/manager-access.custom.json.' }
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
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to change feature flags. See config/manager-access.custom.json.' }
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

        if ($path -eq '/api/mail-templates' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $mailDir = Join-Path $solutionRoot 'templates\mail'
            $overrides = ConvertTo-PimPlainHashtable (Get-PimManagerSetting -Name 'MailTemplateOverrides')   # store wins
            $items = @()
            if (Test-Path -LiteralPath $mailDir) {
                foreach ($f in @(Get-ChildItem -LiteralPath $mailDir -Filter '*.mailtemplate.html')) {
                    $t = $f.Name -replace '\.mailtemplate\.html$', ''
                    $customPath = Join-Path $mailDir "$t.mailtemplate.custom.html"
                    # Source precedence: store override -> file .custom.html -> shipped.
                    $hasStore = ($overrides.ContainsKey($t) -and "$($overrides[$t])".Trim())
                    $hasFile  = (Test-Path -LiteralPath $customPath)
                    $source   = if ($hasStore) { 'store' } elseif ($hasFile) { 'file' } else { 'shipped' }
                    # Subject is read from the EFFECTIVE body (store value wins).
                    $subject = ''
                    try {
                        $head = if ($hasStore) { "$($overrides[$t])" } else { (Get-Content -LiteralPath $(if ($hasFile) { $customPath } else { $f.FullName }) -Raw -Encoding UTF8) }
                        if ($head -match '<!--\s*subject:\s*(.+?)\s*-->') { $subject = $Matches[1] }
                    } catch {}
                    $items += @{ type = $t; customized = [bool]($hasStore -or $hasFile); source = $source; subject = $subject }
                }
            }
            Write-JsonResponse -Response $resp -Status 200 -Body @{ templates = @($items | Sort-Object { $_.type }) }
            return 200
        }

        # -------------------------------------------------------------------
        # Governance: per-template mail CUSTOMIZATION (GUI-driven, persistent,
        # NO image rebuild). The effective body resolves store override ->
        # file .custom.html -> shipped default (same precedence the engine uses
        # in Get-PimNotifyTemplateText). The store override is persisted via
        # Set-PimManagerSetting 'MailTemplateOverrides' (SQL pim.Settings when
        # active, else the per-instance JSON) AND mirrored into the live globals
        # so the same process's engine picks it up immediately; a freshly-booted
        # engine/scheduler hydrates it from SQL settings.
        #   GET    /api/mail-template?type=<t>  -> { type, body(effective), shipped, source }  (any role)
        #   PUT    /api/mail-template { type, body }  -> save override  (Admin+)
        #   DELETE /api/mail-template?type=<t>        -> reset to default (Admin+)
        # -------------------------------------------------------------------
        if ($path -eq '/api/mail-template' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $type = "$($req.QueryString['type'])".Trim()
            if (-not $type -or $type -notmatch '^[A-Za-z0-9_-]+$') { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'valid ?type= required' }; return 400 }
            $mailDir = Join-Path $solutionRoot 'templates\mail'
            $shippedPath = Join-Path $mailDir "$type.mailtemplate.html"
            if (-not (Test-Path -LiteralPath $shippedPath)) { Write-JsonResponse -Response $resp -Status 404 -Body @{ error = "unknown template '$type'" }; return 404 }
            $shipped = Get-Content -LiteralPath $shippedPath -Raw -Encoding UTF8
            $overrides = ConvertTo-PimPlainHashtable (Get-PimManagerSetting -Name 'MailTemplateOverrides')
            $customPath = Join-Path $mailDir "$type.mailtemplate.custom.html"
            $body = $shipped; $source = 'shipped'
            if ($overrides.ContainsKey($type) -and "$($overrides[$type])".Trim()) { $body = "$($overrides[$type])"; $source = 'store' }
            elseif (Test-Path -LiteralPath $customPath) { $body = (Get-Content -LiteralPath $customPath -Raw -Encoding UTF8); $source = 'file' }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ type = $type; body = $body; shipped = $shipped; source = $source })
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
            $overrides = ConvertTo-PimPlainHashtable (Get-PimManagerSetting -Name 'MailTemplateOverrides')
            $overrides[$type] = $newBody
            Set-PimManagerSetting -Name 'MailTemplateOverrides' -Value $overrides
            # Mirror live so THIS process's engine reads the override immediately.
            if (-not ($global:PIM_NamingConventions -is [hashtable])) { $global:PIM_NamingConventions = @{} }
            $global:PIM_NamingConventions['MailTemplateOverrides'] = $overrides
            $global:PIM_MailTemplateOverrides = $overrides
            Write-PimManagerAuditEvent -Action 'mailtemplate.save' -Target $type -After @{ type = $type; bytes = $newBody.Length } -Result 'ok'
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; type = $type; source = 'store' })
            return 200
        }

        if ($path -eq '/api/mail-template' -and $method -eq 'DELETE') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) { Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to reset a mail template.' }; return 403 }
            $type = "$($req.QueryString['type'])".Trim()
            if (-not $type -or $type -notmatch '^[A-Za-z0-9_-]+$') { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'valid ?type= required' }; return 400 }
            $overrides = ConvertTo-PimPlainHashtable (Get-PimManagerSetting -Name 'MailTemplateOverrides')
            $removed = $overrides.ContainsKey($type)
            if ($removed) { $overrides.Remove($type) }
            Set-PimManagerSetting -Name 'MailTemplateOverrides' -Value $overrides
            if (-not ($global:PIM_NamingConventions -is [hashtable])) { $global:PIM_NamingConventions = @{} }
            $global:PIM_NamingConventions['MailTemplateOverrides'] = $overrides
            $global:PIM_MailTemplateOverrides = $overrides
            Write-PimManagerAuditEvent -Action 'mailtemplate.reset' -Target $type -After @{ type = $type; removedStoreOverride = [bool]$removed } -Result 'ok'
            # NOTE: a file-based .custom.html (if present) is intentionally left in place -- it is the
            # documented fallback; the GUI reports source='file' and the operator manages that file directly.
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; type = $type; removedStoreOverride = [bool]$removed })
            return 200
        }

        if ($path -eq '/api/emergency-status' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $ovFile = Join-Path $script:configRoot 'emergency-override.custom.json'
            if (-not (Test-Path -LiteralPath $ovFile)) {
                Write-JsonResponse -Response $resp -Status 200 -Body @{ active = $false }
                return 200
            }
            try {
                $ov = Get-Content -LiteralPath $ovFile -Raw -Encoding UTF8 | ConvertFrom-Json
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
            ($ov | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath (Join-Path $script:configRoot 'emergency-override.custom.json') -Encoding UTF8
            Write-PimManagerAuditEvent -Action 'emergency.activate' -Target (@($ov.scopeGroupTags) -join ',') -After @{ hours = $hours; reason = "$($body.reason)"; expiresAtUtc = $ov.expiresAtUtc }
            # Alerting (REQUIREMENTS §27 H2): break-glass use is a high-signal event ->
            # fire the break-glass alert through the existing notify path.
            try { Send-PimManagerAlert -Event 'break-glass' -Title 'Break-glass (emergency override) ACTIVATED' -Detail ("Activated by $who; scope=$((@($ov.scopeGroupTags) -join ', ')); expires $($ov.expiresAtUtc); reason: $($body.reason)") -LinkTab 'governance' | Out-Null } catch {}
            Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; expiresAtUtc = $ov.expiresAtUtc; note = 'The engine disables approval on the scoped groups on its next run (run it now for immediate effect) and auto-restores normal policy at expiry.' }
            return 200
        }

        if ($path -eq '/api/emergency-restore' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required' }
                return 403
            }
            $ovFile = Join-Path $script:configRoot 'emergency-override.custom.json'
            if (Test-Path -LiteralPath $ovFile) {
                try {
                    $ov = Get-Content -LiteralPath $ovFile -Raw -Encoding UTF8 | ConvertFrom-Json
                    $ov.expiresAtUtc = [datetime]::UtcNow.ToString('o')   # expire NOW; engine restores on next run
                    ($ov | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $ovFile -Encoding UTF8
                    Write-PimManagerAuditEvent -Action 'emergency.restore.requested' -Target (@($ov.scopeGroupTags) -join ',')
                } catch {}
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
        # here (GET) and a SuperAdmin edits it (PUT) instead of hand-editing
        # config/manager-access.custom.json. The SAME file Get-PimManagerRole
        # enforces on every request -- so the edit is REAL: change the map,
        # the next request's role resolution honours it. Hosted env-driven
        # role config (PIM_SuperAdmins/...) is reported read-only (the file is
        # not the source there). GET = any role; PUT = SuperAdmin only.
        # -------------------------------------------------------------------
        if ($path -eq '/api/access-map' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $f = Join-Path $script:configRoot 'manager-access.custom.json'
            $entries = New-Object System.Collections.ArrayList
            if (Test-Path -LiteralPath $f) {
                try {
                    $accList = Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json
                    foreach ($e in @($accList)) {
                        $eid = "$($e.identity)"
                        $r = "$($e.role)"; if ($r -notin @('Reader','Delegated','Admin','SuperAdmin')) { $r = 'Reader' }
                        [void]$entries.Add(@{ identity = $eid; role = $r })
                    }
                } catch { }
            }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                entries     = @($entries.ToArray())
                roles       = @('Reader','Delegated','Admin','SuperAdmin')
                envManaged  = [bool]$script:PimHosted
                fileExists  = [bool](Test-Path -LiteralPath $f)
                you         = (Get-PimManagerRole)
            })
            return 200
        }

        if ($path -eq '/api/access-map' -and $method -eq 'PUT') {
            $script:lastHeartbeat = Get-Date
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required to edit the delegation map. See config/manager-access.custom.json.' }
                return 403
            }
            if ($script:PimHosted) {
                Write-JsonResponse -Response $resp -Status 409 -Body @{ error = 'This deployment resolves roles from environment variables (PIM_SuperAdmins / PIM_Admins / PIM_DelegatedAdmins), not manager-access.custom.json. Edit those app settings instead.' }
                return 409
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
            # Lock-out guard: never let the map end with zero SuperAdmins (that
            # would orphan the instance -- nobody could edit it back).
            if ($clean.Count -gt 0 -and -not $sawSuper) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'At least one SuperAdmin is required -- saving this map would lock everyone out.' }
                return 400
            }
            $f = Join-Path $script:configRoot 'manager-access.custom.json'
            $dir = Split-Path -Parent $f
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            # Robust array serialisation (ConvertTo-Json drops the [] on a single object).
            $arr = @($clean.ToArray())
            if ($arr.Count -eq 0)      { $json = '[]' }
            elseif ($arr.Count -eq 1)  { $json = '[' + (ConvertTo-Json $arr[0] -Depth 4) + ']' }
            else                       { $json = ConvertTo-Json $arr -Depth 4 }
            [System.IO.File]::WriteAllText($f, $json, (New-Object System.Text.UTF8Encoding($false)))
            Write-PimManagerAuditEvent -Action 'access.map.save' -Target "entries:$($arr.Count)" -After @{ count = $arr.Count } -Result 'ok'
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; entries = @($arr); you = (Get-PimManagerRole) })
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
                                $k = Get-PimTemplateRowKey -Base $base -Row $tr
                                if ($k -and -not $existing.ContainsKey($k.ToLowerInvariant())) { [void]$miss.Add($tr) }
                            }
                            if ($miss.Count -gt 0) { $missing[$base] = $miss.ToArray(); $missingCount += $miss.Count }
                        }
                        [void]$outList.Add([ordered]@{
                            id = "$($tpl.id)"; name = "$($tpl.name)"; version = $tpl.version
                            description = "$($tpl.description)"
                            totalRows = $totalCount; missingCount = $missingCount; missing = $missing
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
        # Delegated portal-admin access (admin-interface epic phase 2).
        # -------------------------------------------------------------------
        if ($path -eq '/api/portal-access' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            $role = Get-PimManagerRole
            $isSuper = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')
            $prof = $null
            if (Get-Command Read-PimPortalProfiles -ErrorAction SilentlyContinue) {
                $prof = Get-PimPortalProfile -Profiles (Read-PimPortalProfiles -ConfigDir $script:configRoot) -Identity "$($role.identity)"
            }
            $profOut = if ($prof) {
                [ordered]@{
                    displayName = "$($prof.displayName)"; services = @($prof.services)
                    tierMax = $prof.tierMax; levelMax = $prof.levelMax; scopes = @($prof.scopes)
                    capabilities = @($prof.capabilities); managedAdmins = @($prof.managedAdmins)
                }
            } else { $null }
            Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                identity = "$($role.identity)"; managerRole = "$($role.role)"; isSuperAdmin = $isSuper
                portalProfile = $profOut
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
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required. See config/manager-access.custom.json.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            $role    = Get-PimManagerRole
            $isSuper = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')
            $prof    = $null
            if (Get-Command Read-PimPortalProfiles -ErrorAction SilentlyContinue) {
                $prof = Get-PimPortalProfile -Profiles (Read-PimPortalProfiles -ConfigDir $script:configRoot) -Identity "$($role.identity)"
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
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required. See config/manager-access.custom.json.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            $b = Read-RequestJson -Request $req
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
                            $files = @(Get-ChildItem -LiteralPath $tplDir -Filter '*.admintemplate*.json' -ErrorAction SilentlyContinue)
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
                if (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
                    $esc = [uri]::EscapeDataString($roleName)
                    $u = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq '$esc'"
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
                $hasGraph = [bool](Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)
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
                $hasGraph = [bool](Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)
                if ($hasGraph) {
                    # Page through every directory role definition WITH its permissions.
                    $u = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName,isBuiltIn,rolePermissions&`$top=200"
                    $guard = 0
                    while ($u -and $guard -lt 50) {
                        $guard++
                        $r = Invoke-MgGraphRequest -Method GET -Uri $u -ErrorAction Stop
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
            $confExFile = Join-Path $script:configRoot 'exemptions.json'
            $confState  = Join-Path $script:outputRoot 'state\template-state.json'
            $confTenant = "$script:PimInstanceName"
            $confRing   = Get-PimTenantRing
            $readEx = {
                $f = $confExFile
                if (-not (Test-Path -LiteralPath $f)) { $f = Join-Path $solutionRoot 'config\exemptions.sample.json' }
                if (-not (Test-Path -LiteralPath $f)) { return @() }
                try { return @((Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json).exemptions) } catch { return @() }
            }
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
                    $st = Get-PimTemplateState -StateFile $confState -TenantId $confTenant -TemplateId "$($t.templateId)"
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
                $st = Get-PimTemplateState -StateFile $confState -TenantId $confTenant -TemplateId "$tid"
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
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    templateId = "$($tpl.templateId)"; workload = "$($tpl.workload)"; templateVersion = $c.TemplateVersion
                    status = "$($tpl.status)"; tenantRing = $confRing; appliedVersion = $applied; behind = $c.Behind
                    keys = @(@($tpl.entries) | ForEach-Object { "$($_.key)" }); statuses = $statusMap
                    counts = $c.Counts; catalogAhead = @($c.CatalogAhead | ForEach-Object { "$($_.Capability)" })
                })
                return 200
            }

            if ($path -eq '/api/conformance/exemptions' -and $method -eq 'POST') {
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
                $dir = Split-Path -Parent $confExFile
                if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
                @{ exemptions = $list.ToArray() } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $confExFile -Encoding UTF8
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
                if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) { Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required' }; return 403 }
                $b = Read-RequestJson -Request $req
                $rk = "$($b.revokeKey)".Trim()
                if (-not $rk) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'revokeKey is required' }; return 400 }
                $r = Remove-PimExemptionEntry -Exemptions (& $readEx) -RevokeKey $rk
                if ($r.Removed -gt 0) {
                    $dir = Split-Path -Parent $confExFile
                    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
                    @{ exemptions = $r.Kept } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $confExFile -Encoding UTF8
                    if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
                        try { Write-PimAuditEvent -Action 'conformance.exemption.revoke' -Target $rk -After @{ instance = $confTenant; removed = $r.Removed } -Actor 'manager' -WarningAction SilentlyContinue | Out-Null } catch {}
                    }
                }
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; removed = $r.Removed; count = @($r.Kept).Count }
                return 200
            }

            if ($path -eq '/api/conformance/approve' -and $method -eq 'POST') {
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
                $tpl = ConvertTo-PimTemplate -Json ([System.IO.File]::ReadAllText($file, [System.Text.UTF8Encoding]::new($false)))
                try {
                    $pr = Set-PimEntryRing -Template $tpl -Key "$($b.key)" -Ring ([int]$b.ring)
                    $pr | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $file -Encoding UTF8
                    Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; key = "$($b.key)"; ring = [int]$b.ring }
                    return 200
                } catch { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = "$($_.Exception.Message)" }; return 400 }
            }

            if ($path -eq '/api/conformance/deploy' -and $method -eq 'POST') {
                if (-not (Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin')) { Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required' }; return 403 }
                $b = Read-RequestJson -Request $req
                $tpl = @(Read-PimApprovedTemplates -SourceDir $confTplDir -WarningAction SilentlyContinue | Where-Object { "$($_.templateId)" -eq "$($b.templateId)" })
                if (-not $tpl) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'unknown or unapproved template (only approved deploy)' }; return 400 }
                $tpl = $tpl[0]
                $whatIf = [bool]$b.whatIf
                try {
                    $rows = @(Get-PimRollForwardRows -Template $tpl -TenantRing $confRing -TenantId $confTenant -Exemptions (& $readEx) -NowUtc ([datetime]::UtcNow))
                    if (-not $rows.Count) { Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; whatIf = $whatIf; rows = @(); message = 'no in-scope, non-exempt entries for this ring' }; return 200 }
                    $tmpCsv = Join-Path $env:TEMP ("pim-rollfwd-{0}.csv" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
                    $rows | Select-Object Workload,RoleName,GroupTag,Scope,Resource,Action | Export-Csv -LiteralPath $tmpCsv -NoTypeInformation -Delimiter ';' -Encoding UTF8
                    Initialize-PimManagerTenantConnection
                    $connDir = Join-Path $solutionRoot 'workloads\connectors'
                    $out = Apply-PimWorkloadAssignments -WorkloadsAssignmentFile $tmpCsv -ConnectorsDir $connDir -WhatIfMode:$whatIf *>&1 | Out-String
                    Remove-Item -LiteralPath $tmpCsv -Force -ErrorAction SilentlyContinue
                    if (-not $whatIf) {
                        Set-PimTemplateState -StateFile $confState -TenantId $confTenant -TemplateId "$($tpl.templateId)" -Version ([int]("$($tpl.templateVersion)" -as [int])) -NowUtc ([datetime]::UtcNow) | Out-Null
                        # Stamp THIS tenant's rollout ring at the file root so the fleet
                        # matrix ([H8]) can read the ring of an instance it is not the
                        # active one for. Best-effort; never blocks the deploy.
                        try {
                            $sall = [pscustomobject]@{}
                            if (Test-Path -LiteralPath $confState) { try { $sall = Get-Content -LiteralPath $confState -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $sall = [pscustomobject]@{} } }
                            if (-not $sall.PSObject.Properties['fleetRingByTenant']) { Add-Member -InputObject $sall -NotePropertyName 'fleetRingByTenant' -NotePropertyValue ([pscustomobject]@{}) -Force }
                            Add-Member -InputObject $sall.fleetRingByTenant -NotePropertyName $confTenant -NotePropertyValue ([int]$confRing) -Force
                            $sall | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $confState -Encoding UTF8
                        } catch {}
                    }
                    Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; whatIf = $whatIf; rows = @($rows); log = "$out" })
                    return 200
                } catch { Write-JsonResponse -Response $resp -Status 502 -Body @{ error = "$($_.Exception.Message)" }; return 502 }
            }

            # --- FLEET conformance matrix (REQUIREMENTS.md s28 [H8]) -----------------
            # The single-tenant /api/conformance answers "how far behind is THIS tenant?".
            # An MSP needs the cross-fleet view: tenants x templates, behind-by-N, in one
            # place. Builds it by reading EVERY managed instance's local template-state stamp
            # (per-instance applied version + ring) and feeding them into the pure
            # Get-PimFleetConformance. The active instance contributes its LIVE ring
            # (Get-PimTenantRing); other instances use the ring stamped in their state file
            # (falling back to 0 / production when unstamped). No tenant write, read-only.
            if ($path -eq '/api/conformance/fleet' -and $method -eq 'GET') {
                $approved = @(Read-PimApprovedTemplates -SourceDir $confTplDir -WarningAction SilentlyContinue)
                # Build a tenant descriptor per managed instance.
                $fleetTenants = New-Object System.Collections.Generic.List[object]
                foreach ($inst in (Get-PimManagerInstances)) {
                    $iname = "$($inst.name)"
                    # SQL-DB pseudo-instances share the solution config/output; skip the
                    # 'sql:<db>' duplicates so a DB switch doesn't double-count a tenant.
                    if ($iname -like 'sql:*') { continue }
                    $iout = if ($inst.outputRoot) { "$($inst.outputRoot)" } else { Join-Path $solutionRoot 'output' }
                    $istate = Join-Path $iout 'state\template-state.json'
                    $st = Get-PimFleetStateForInstance -StateFile $istate -TenantId $iname
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
                foreach ($inst in (Get-PimManagerInstances)) {
                    $iname = "$($inst.name)"
                    if ($iname -like 'sql:*') { continue }
                    $iout = if ($inst.outputRoot) { "$($inst.outputRoot)" } else { Join-Path $solutionRoot 'output' }
                    $istate = Join-Path $iout 'state\template-state.json'
                    $st = Get-PimFleetStateForInstance -StateFile $istate -TenantId $iname
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
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'SuperAdmin role required. See config/manager-access.custom.json.' }
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

        # -------------------------------------------------------------------
        # DB CUTOVER CEREMONY (gated CSV -> SQL). GET = status; POST = run the
        # next/specified stage. Each stage is gated on the prior one (idempotent).
        # Stages: preflight -> upgrade -> import -> set-source -> re-preflight ->
        # finalize. Only Azure SQL may be FINALIZED as authoritative (SQLEXPRESS /
        # Integrated is dev-only -- never a production store). Admin role required to
        # run a stage. The CSV source is READ-ONLY (the import never writes back).
        # -------------------------------------------------------------------
        if ($path -eq '/api/cutover' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            try {
                $st = if ($script:PimSqlCs) { Get-PimCutoverState -ConnectionString $script:PimSqlCs } else { [pscustomobject]@{ completed = @(); final = $false; audit = @{}; updatedUtc = $null } }
                $cs = $script:PimSqlCs
                $kind = if ($cs) { Get-PimSqlStoreKind -ConnectionString $cs } else { @{ kind = 'none'; isProduction = $false } }
                $abortGate = Test-PimCutoverAbortAllowed -Completed @($st.completed) -Final ([bool]$st.final)
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    stages       = [string[]]@(Get-PimCutoverStages)
                    completed    = @($st.completed)
                    final        = [bool]$st.final
                    nextStage    = (Get-PimCutoverNextStage -Completed @($st.completed))
                    storageMode  = $script:PimStorageMode
                    storeKind    = $kind.kind
                    storeIsProduction = [bool]$kind.isProduction
                    audit        = $st.audit
                    humanAudit   = @(Format-PimCutoverAudit -Audit $st.audit)
                    canAbort     = [bool]$abortGate.allowed
                    abortReason  = "$($abortGate.reason)"
                    abortPlan    = @((Get-PimCutoverAbortPlan -Completed @($st.completed)).steps)
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ error = "$($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/cutover' -and $method -eq 'POST') {
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to run a cutover stage. See config/manager-access.custom.json.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            $body = Read-RequestJson -Request $req
            $reqStage = if ($body -and $body.stage) { "$($body.stage)" } else { '' }
            $whatIf   = [bool]($body -and $body.whatIf)
            $actor    = "manager:$((Get-PimManagerRole).identity)"

            # The cutover targets THIS instance's SQL store. A connection must be
            # resolvable; SQLEXPRESS / Integrated is allowed for the dry stages but the
            # FINALIZE stage refuses a non-production store.
            $cs = $script:PimSqlCs
            if (-not $cs -and (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue)) { try { $cs = Get-PimSqlConnectionString } catch { $cs = $null } }
            if (-not $cs) { Write-JsonResponse -Response $resp -Status 400 -Body @{ error = 'no SQL connection resolved -- configure the target SQL store first (PIM_SqlServer / connection / KV pointer).' }; return 400 }

            try {
                $state = Get-PimCutoverState -ConnectionString $cs
                if (-not $reqStage) { $reqStage = Get-PimCutoverNextStage -Completed @($state.completed) }
                if (-not $reqStage) { Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; done = $true; message = 'cutover already finalized'; completed = @($state.completed) }; return 200 }

                $gate = Test-PimCutoverStageAllowed -Stage $reqStage -Completed @($state.completed)
                if (-not $gate.allowed) { Write-JsonResponse -Response $resp -Status 409 -Body @{ ok = $false; stage = $reqStage; error = $gate.reason }; return 409 }

                $audit = $null
                switch ($reqStage) {
                    'preflight' {
                        # Read-only: conform-audit the SOURCE CSV headers vs the locked schema + connectivity.
                        $srcCols = @{}
                        if (Test-Path -LiteralPath $script:configRoot) {
                            foreach ($f in (Get-ChildItem -LiteralPath $script:configRoot -Filter '*.custom.csv' -File)) {
                                $b = $f.BaseName -replace '\.custom$',''
                                $hl = @(Get-Content -LiteralPath $f.FullName -TotalCount 1 -Encoding UTF8)
                                if ($hl.Count -gt 0) { $srcCols[$b] = @($hl[0] -split ';' | ForEach-Object { $_.Trim().Trim('"') }) }
                            }
                        }
                        $pf = Get-PimCutoverPreflightAudit -SourceColumns $srcCols
                        $audit = [ordered]@{ connectivity = (Test-PimSqlConnectivity -ConnectionString $cs); needsUpgrade = $pf.needsUpgrade; entities = $pf.entities }
                    }
                    'upgrade' {
                        # One-time idempotent schema CREATE/ALTER on the target.
                        Initialize-PimSqlStore -ConnectionString $cs
                        $audit = [ordered]@{ schemaInitialized = $true }
                    }
                    'import' {
                        # Transactional CSV -> pim.Rows (READ-ONLY source; all-or-nothing).
                        $imp = Invoke-PimCutoverImport -ConfigDir $script:configRoot -ConnectionString $cs -WhatIf:$whatIf
                        $audit = [ordered]@{ total = $imp.total; whatIf = $imp.whatIf; entities = $imp.entities }
                    }
                    'set-source' {
                        # Flip the persisted config source to SQL.
                        Set-PimSqlSetting -ConnectionString $cs -Name 'StorageBackend' -Value 'sql'
                        $audit = [ordered]@{ storageBackend = 'sql' }
                    }
                    're-preflight' {
                        # Re-run preflight against the NOW-populated SQL store (data signature + counts).
                        $sig = Get-PimSqlDataSignature -ConnectionString $cs
                        $rowCount = [int](Invoke-PimSqlScalar -ConnectionString $cs -Sql 'SELECT COUNT(*) FROM pim.Rows')
                        $audit = [ordered]@{ signature = $sig; rowCount = $rowCount; connectivity = (Test-PimSqlConnectivity -ConnectionString $cs) }
                    }
                    'finalize' {
                        # Explicit operator confirmation. Only Azure SQL may be authoritative.
                        $kind = Get-PimSqlStoreKind -ConnectionString $cs
                        if (-not $kind.isProduction) {
                            Write-JsonResponse -Response $resp -Status 409 -Body @{ ok = $false; stage = 'finalize'; error = "refusing to finalize: target store kind '$($kind.kind)' is NOT a production store. Azure SQL is the single authoritative store; SQLEXPRESS / Integrated is dev-only and never break-glass." }
                            return 409
                        }
                        # Audit every imported row count captured at the import stage.
                        $importAudit = $null
                        if ($state.audit -and $state.audit.PSObject.Properties['import']) { $importAudit = $state.audit.import }
                        elseif ($state.audit -is [hashtable] -and $state.audit.ContainsKey('import')) { $importAudit = $state.audit['import'] }
                        $audit = [ordered]@{ finalized = $true; storeKind = $kind.kind; importAudit = $importAudit }
                        if ((Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue)) {
                            try { Write-PimAuditEvent -Action 'cutover.finalize' -Target "sql:$($global:PIM_SqlDatabase)" -After $audit -Actor $actor } catch { }
                        }
                    }
                    default {
                        Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = "unknown stage '$reqStage'" }
                        return 400
                    }
                }

                $newState = Add-PimCutoverCompletedStage -State $state -Stage $reqStage -Audit $audit
                Set-PimCutoverState -ConnectionString $cs -State $newState
                if ((Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) -and $reqStage -ne 'finalize') {
                    try { Write-PimAuditEvent -Action "cutover.$reqStage" -Target "sql:$($global:PIM_SqlDatabase)" -After $audit -Actor $actor } catch { }
                }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok        = $true
                    stage     = $reqStage
                    completed = @($newState.completed)
                    nextStage = (Get-PimCutoverNextStage -Completed @($newState.completed))
                    final     = [bool]$newState.final
                    audit     = $audit
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; stage = $reqStage; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        # Abort / roll back a STARTED-but-not-finalized cutover (REQUIREMENTS.md s28 [L3]).
        # Reverts the StorageBackend flip (-> csv) when set-source ran, then clears the
        # ceremony state. Refused once finalized (finalize is the point of no return).
        # The CSV source was read-only throughout, so the prior store is intact.
        if ($path -eq '/api/cutover/abort' -and $method -eq 'POST') {
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to abort a cutover. See config/manager-access.custom.json.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            $actor = "manager:$((Get-PimManagerRole).identity)"
            $cs = $script:PimSqlCs
            if (-not $cs -and (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue)) { try { $cs = Get-PimSqlConnectionString } catch { $cs = $null } }
            if (-not $cs) { Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = 'no SQL connection resolved -- nothing to abort.' }; return 400 }
            try {
                $state = Get-PimCutoverState -ConnectionString $cs
                $gate  = Test-PimCutoverAbortAllowed -Completed @($state.completed) -Final ([bool]$state.final)
                if (-not $gate.allowed) { Write-JsonResponse -Response $resp -Status 409 -Body @{ ok = $false; error = $gate.reason }; return 409 }
                $result = Invoke-PimCutoverAbort -ConnectionString $cs
                if ((Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue)) {
                    try { Write-PimAuditEvent -Action 'cutover.abort' -Target "sql:$($global:PIM_SqlDatabase)" -After ([ordered]@{ revertedSource = $result.revertedSource; storageBackend = $result.storageBackend; abortedFrom = @($state.completed) }) -Actor $actor } catch { }
                }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok             = $true
                    revertedSource = [bool]$result.revertedSource
                    storageBackend = "$($result.storageBackend)"
                    completed      = @()
                    nextStage      = (Get-PimCutoverNextStage -Completed @())
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
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
                if ($script:PimStorageMode -eq 'sql' -and $script:PimSqlCs) {
                    try {
                        $sig = Invoke-PimSqlQuery -ConnectionString $script:PimSqlCs -Sql "SELECT COUNT(*) AS c, CONVERT(VARCHAR(33), MAX(UpdatedUtc), 126) AS m FROM pim.Rows" | Select-Object -First 1
                        $stamp += "|sql:rows=$($sig.c):max=$($sig.m)"
                    } catch { $stamp += "|sql:" + [datetime]::UtcNow.ToString('o') }  # fail-open: don't cache
                } else {
                    foreach ($spec in (Get-PimCsvBases)) {
                        $resolved = Resolve-PimCsvPath -BaseName $spec.base
                        if ($resolved) { $stamp += '|' + $spec.base + ':' + ([System.IO.File]::GetLastWriteTimeUtc($resolved.Path).Ticks) }
                    }
                }
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
                $p = Get-PimWarningOverrideStorePath
                $entries = @()
                if ($p -and (Get-Command Read-PimWarningOverrideConfig -ErrorAction SilentlyContinue)) {
                    $entries = @(Read-PimWarningOverrideConfig -Path $p)
                }
                Write-JsonResponse -Response $resp -Status 200 -Body @{ ok = $true; supported = [bool]$p; count = @($entries).Count; overrides = @($entries) }
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
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to overrule validator findings. See config/manager-access.custom.json.' }
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
            $script:lastHeartbeat = Get-Date
            $forceRefresh = $false
            try {
                $qs = $req.Url.Query
                if ($qs -and $qs.IndexOf('refresh=1') -ge 0) { $forceRefresh = $true }
            } catch { }
            try {
                $body = Get-PimActiveAssignmentsCached -Force:$forceRefresh
                Write-JsonResponse -Response $resp -Status 200 -Body $body
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; error = "$($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/revoke' -and $method -eq 'POST') {
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required. See config/manager-access.custom.json.' }
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
                    } catch {}
                }
                # Invalidate the active-assignments cache so the next GET re-fetches truth.
                $script:PimActiveAssignmentsCache          = $null
                $script:PimActiveAssignmentsCacheLoadedUtc = $null
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok           = $true
                    requested    = $rowsIn.Count
                    revoked      = $rowsToRevoke.Count
                    skipped      = $plan.skipped
                    skippedCount = $plan.skippedCount
                    results      = $results
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
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to roll back. See config/manager-access.custom.json.' }
                return 403
            }
            $script:lastHeartbeat = Get-Date
            $body = Read-RequestJson -Request $req
            $snapId = if ($body -and $body.id) { "$($body.id)" } else { '' }
            $base   = if ($body -and $body.base) { "$($body.base)" } else { '' }
            if (-not "$snapId".Trim()) {
                Write-JsonResponse -Response $resp -Status 400 -Body @{ ok = $false; error = "missing snapshot 'id' in body" }
                return 400
            }
            try {
                $r = Invoke-PimManagerBackupRestore -Id $snapId
                if (-not "$base".Trim()) { $base = "$($r.entity)" }
                $who = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
                Write-PimMutationLog -BaseName $base -Adds 0 -Removes 0 -Modifies 0 -NewRowCount ([int]$r.rowCount)
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{ ok = $true; base = $base; restoredFrom = $snapId; entity = "$($r.entity)"; rowCount = [int]$r.rowCount; by = "$who" })
                return 200
            } catch {
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
        # Governance DRIFT view + gated remediation (REQUIREMENTS §28 [M5]).
        #   GET  /api/drift            -> compute live-vs-desired drift by running
        #                                 the EXISTING engine in PLAN/WhatIf mode
        #                                 (NO writes), classified missing/changed/
        #                                 extra via Get-PimDriftReport.
        #   POST /api/drift/remediate  -> Admin-gated "apply now": run the engine
        #                                 create/update path for ONLY the selected
        #                                 drift (Get-PimDriftRemediationPlan +
        #                                 Invoke-PimEngine -Changes). Destructive
        #                                 removal of an 'extra' needs explicit
        #                                 allowRemove (-> engine -Mode Full -Prune);
        #                                 never a single-click destructive bypass.
        # The engine WhatIf reads LIVE from the tenant -- so this needs the hosted
        # engine context. Offline/static returns a clean "needs the server/engine"
        # body so the GUI degrades instead of showing a dead control.
        # -------------------------------------------------------------------
        if ($path -eq '/api/drift' -and $method -eq 'GET') {
            $script:lastHeartbeat = Get-Date
            if (-not (Get-Command Invoke-PimEngine -ErrorAction SilentlyContinue) -or -not (Get-Command Get-PimDriftReport -ErrorAction SilentlyContinue)) {
                Write-JsonResponse -Response $resp -Status 503 -Body @{ ok = $false; supported = $false; error = 'engine not loaded (drift needs the hosted engine + a live tenant context).' }
                return 503
            }
            try {
                # Plan-only (WhatIf) Full+Prune over every scope -> create/update/
                # remove diffs with NO writes. Each scope result carries a `plan`
                # of {entity;key;op}; bucket those into the shape Get-PimDriftReport
                # expects, then classify. Reuses the engine delta -- no re-impl.
                $results = @(Invoke-PimEngine -Scope 'All' -Mode 'Full' -Prune -WhatIf)
                $scopeDiffs = New-Object System.Collections.Generic.List[object]
                foreach ($r in @($results)) {
                    $cre = New-Object System.Collections.Generic.List[object]
                    $upd = New-Object System.Collections.Generic.List[object]
                    $rem = New-Object System.Collections.Generic.List[object]
                    foreach ($pc in @($r.plan)) {
                        $item = [pscustomobject]@{ key = "$($pc.key)" }
                        switch ("$($pc.op)".ToLowerInvariant()) {
                            'create' { $cre.Add($item) }
                            'update' { $upd.Add($item) }
                            'remove' { $rem.Add($item) }
                        }
                    }
                    $ent = if ($r.PSObject.Properties['entity'] -and "$($r.entity)".Trim()) { "$($r.entity)" } else { "$($r.scope)" }
                    $scopeDiffs.Add([pscustomobject]@{ scope = "$($r.scope)"; entity = $ent; create = @($cre.ToArray()); update = @($upd.ToArray()); remove = @($rem.ToArray()) })
                }
                $report = Get-PimDriftReport -ScopeDiffs @($scopeDiffs.ToArray())
                # Fire the 'drift' alert (debounced by the alerting layer) when the
                # estate has drifted, so it does not go unnoticed (§26c Alerting).
                if ($report.total -gt 0 -and (Get-Command Send-PimManagerAlert -ErrorAction SilentlyContinue)) {
                    try { Send-PimManagerAlert -Event 'drift' -Title 'Configuration drift detected' -Detail ("missing={0} changed={1} extra={2}" -f $report.counts.missing, $report.counts.changed, $report.counts.extra) -LinkTab 'governance' | Out-Null } catch {}
                }
                Write-JsonResponse -Response $resp -Status 200 -Body ([ordered]@{
                    ok           = $true
                    supported    = $true
                    generatedUtc = $report.generatedUtc
                    total        = $report.total
                    counts       = $report.counts
                    scopes       = $report.scopes
                    items        = $report.items
                })
                return 200
            } catch {
                Write-JsonResponse -Response $resp -Status 500 -Body @{ ok = $false; supported = $true; error = "drift read failed (live tenant unreachable?): $($_.Exception.Message)" }
                return 500
            }
        }

        if ($path -eq '/api/drift/remediate' -and $method -eq 'POST') {
            $script:lastHeartbeat = Get-Date
            # Applying drift mutates the live estate -> Admin (same gate as revoke).
            if (-not (Test-PimManagerRoleAtLeast -Minimum 'Admin')) {
                Write-JsonResponse -Response $resp -Status 403 -Body @{ error = 'Admin role required to apply drift remediation. See config/manager-access.custom.json.' }
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
    'Static'  { Invoke-StaticHtml -OutHtml $OutHtml }
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
