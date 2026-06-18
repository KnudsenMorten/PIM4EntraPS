#Requires -Version 5.1
<#
    Pester job for PIM4EntraPS -- reruns every offline flow + framework checks.
    Run:  Invoke-Pester -Path tests\PIM.Tests.ps1
    Or:   tests\Run-AllPimTests.ps1   (also drives this)
    The three functional suites are executed as child processes (clean assembly
    state) and asserted green; the workload-connector framework is tested in-proc.
#>
BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:Tests = $PSScriptRoot
    $global:PIM_ConfigVariant = 'test'
    Import-Module (Join-Path $Root 'engine\_shared\PIM-Functions.psm1') -Force -DisableNameChecking
    function Invoke-Suite([string]$name) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $script:Tests $name) | Out-Null
        $LASTEXITCODE
    }
}

Describe 'Functional suites (child-process, asserted green)' {
    It 'Test-PimFeatures.ps1 exits 0'          { Invoke-Suite 'Test-PimFeatures.ps1'         | Should -Be 0 }
    It 'Test-PimManagerEndpoints.ps1 exits 0'  { Invoke-Suite 'Test-PimManagerEndpoints.ps1' | Should -Be 0 }
    It 'Test-PimGuiEngineAlignment.ps1 exits 0' { Invoke-Suite 'Test-PimGuiEngineAlignment.ps1' | Should -Be 0 }  # GUI<->engine: no dead GUI buttons, no unwhitelisted orphan endpoints
    It 'Test-PimNamingTokenLegend.ps1 exits 0' { Invoke-Suite 'Test-PimNamingTokenLegend.ps1' | Should -Be 0 }  # §11 GUI shows supported variables/tokens: naming-token legend/picker == engine resolver (PIM-Naming.ps1) token set (no missing/invented), {Initial} preferred + {Owner} synonym, click-to-insert wired to the Value fields, mail-template editor renders a per-template token legend targeting #govMailBody
    It 'Test-PimManagerGuiPanels.ps1 exits 0'  { Invoke-Suite 'Test-PimManagerGuiPanels.ps1'  | Should -Be 0 }  # §11 Manager panels: Authoring/Onboarding/Role Lookup/Cutover exist + call their endpoints, role+server gated
    It 'Test-PimManagerSafety.ps1 exits 0'     { Invoke-Suite 'Test-PimManagerSafety.ps1'     | Should -Be 0 }  # H1 quoted-CSV map render + L1 Validate toast id (#valResults) + bulk-revoke guard (break-glass excluded, large-batch count-confirm, what-if preview, per-revoke audit)
    It 'Test-PimApprovalGate.ps1 exits 0'      { Invoke-Suite 'Test-PimApprovalGate.ps1'      | Should -Be 0 }  # §27 H3/H4 approval-gated offboarding+revoke: maker/checker request lifecycle, offboard executes only when Approved (never automatic), revoke>threshold needs approval, break-glass excluded, DisableGuard breaker not bypassed, once-only execution
    It 'Test-PimSensitiveAuthoring.ps1 exits 0' { Invoke-Suite 'Test-PimSensitiveAuthoring.ps1' | Should -Be 0 }  # §28 [M4] maker/checker SECOND-PERSON approval on SENSITIVE authoring/onboarding: classifies privileged-role attach / guest-into-privileged-group / disable+offboard as sensitive; commit gate requires a different approver (self-approve refused); non-sensitive change unaffected; approved -> commits, once-only latch. Reuses PIM-ApprovalGate (no parallel system)
    It 'Test-PimAuthoringDropdowns.ps1 exits 0' { Invoke-Suite 'Test-PimAuthoringDropdowns.ps1' | Should -Be 0 }  # Authoring tab: every group/role/tag/admin field is a dropdown/combobox from REAL catalog data (no raw free-text path); headless Node executor asserts option lists from a seeded catalog
    It 'Test-PimManagerGuiComprehensive.ps1 exits 0' { Invoke-Suite 'Test-PimManagerGuiComprehensive.ps1' | Should -Be 0 }  # COMPREHENSIVE post-deploy GUI gate: headless jsdom render of all 19 tabs (seeded + empty), no dead/blank panels, no JS errors, no dead controls, banner/dropdown/reach sanity. Self-skips if node/jsdom absent.
    It 'Test-PimMapPermissionsTargets.ps1 exits 0' { Invoke-Suite 'Test-PimMapPermissionsTargets.ps1' | Should -Be 0 }  # Delegation Map PERMISSIONS & TARGETS column: seeded render proves enriched Entra/AU/Azure targets (full scope path) populate from real rows
    It 'Test-PimMapReach.ps1 exits 0'          { Invoke-Suite 'Test-PimMapReach.ps1'         | Should -Be 0 }  # Delegation Map transitive reach: seeded render proves person->groups->bundles->targets reach is column-oriented (no over-reach via mis-nested groups, no AU-scope duplication)
    It 'Test-PimInactivitySweep.ps1 exits 0'   { Invoke-Suite 'Test-PimInactivitySweep.ps1'  | Should -Be 0 }  # §25c inactivity sweep: pure decision core (PIM-InactivitySweep.ps1) -- last-sign-in days math (string/datetime/null/future), per-unit/global threshold (0/blank = not swept), protected detection (break-glass/super-admin/pattern), plan classification (active/inactive/never-signed-in/not-swept/protected/already-disabled) + Report(flag, default) vs Enforce(disable) action; the Enforce verdict composes the REAL account-disable circuit breaker (G1 empty-desired / G2 mass-disable cap / G3 opt-in) so a sweep can NEVER mass-disable; a protected candidate is surfaced but never counted to disable; NO real destructive write (offline)
    It 'Test-PimManagerHostedSql.ps1 exits 0'  { Invoke-Suite 'Test-PimManagerHostedSql.ps1' | Should -Be 0 }  # hosted+SQL hardening (SQL part self-skips if no instance)
    It 'Test-PimSettingsAdmin.ps1 exits 0'     { Invoke-Suite 'Test-PimSettingsAdmin.ps1'    | Should -Be 0 }
    It 'Test-PimScenarios.ps1 exits 0'         { Invoke-Suite 'Test-PimScenarios.ps1'        | Should -Be 0 }
    It 'Test-PimCutover.ps1 exits 0'           { Invoke-Suite 'Test-PimCutover.ps1'          | Should -Be 0 }  # cutover ceremony + recalc + health (live SQL self-skips)
    It 'Test-PimCutoverEndpoints.ps1 exits 0'  { Invoke-Suite 'Test-PimCutoverEndpoints.ps1' | Should -Be 0 }  # /api/cutover + /health HTTP (self-skips if no SQL)
    It 'Test-PimCutoverAbort.ps1 exits 0'      { Invoke-Suite 'Test-PimCutoverAbort.ps1'     | Should -Be 0 }  # §28 [L3] cutover ABORT/rollback before finalize + human-readable stage audit (live SQL self-skips)
    It 'Test-PimCommitBackup.ps1 exits 0'      { Invoke-Suite 'Test-PimCommitBackup.ps1'     | Should -Be 0 }  # §28 [M1] safe/reversible Review & Save commit: backup-before-apply, transactional rollback-on-failure, undo, N-retention (offline; fake ADO.NET)
    It 'Test-PimAuthDiagnostics.ps1 exits 0'   { Invoke-Suite 'Test-PimAuthDiagnostics.ps1'  | Should -Be 0 }  # § 9 auth/identity diagnostics (offline)
    It 'Test-PimLicensing.ps1 exits 0'         { Invoke-Suite 'Test-PimLicensing.ps1'        | Should -Be 0 }  # § 15 Core/Pro split + offline signed-license verify (valid/invalid/tampered fixtures)
    It 'Test-PimNamingMigration.ps1 exits 0'   { Invoke-Suite 'Test-PimNamingMigration.ps1'  | Should -Be 0 }  # § 17 naming helpers/validation + § 18 v1->v2 migration (offline)
    It 'Test-PimScheduler.ps1 exits 0'         { Invoke-Suite 'Test-PimScheduler.ps1'        | Should -Be 0 }  # scheduler/job runner: due-calc, dispatch, lease, triggers + tenant-cache refresh job (offline)
    It 'Test-PimDiscoverySweep.ps1 exits 0'    { Invoke-Suite 'Test-PimDiscoverySweep.ps1'   | Should -Be 0 }  # §8 scheduled discovery job sweep (Azure/PowerBI scope + Entra role-catalog) + audit/opt-in-notify on each FRESH item (resource.discovered) + handled-set delta; scheduler wiring incl. the Entra -GetLiveRoles seam (offline, injected enumerators/audit/notify)
    It 'Test-PimSyncAutomateIT.ps1 exits 0'    { Invoke-Suite 'Test-PimSyncAutomateIT.ps1'   | Should -Be 0 }  # §1/§2/§6 sync-automateit auto-update decision core (offline)
    It 'Test-PimUpdateLifecycle.ps1 exits 0'   { Invoke-Suite 'Test-PimUpdateLifecycle.ps1'  | Should -Be 0 }  # §1/§2/§5/§20 full update-lifecycle decision core: detect/build/deploy/verify/notify/ensure-monitor (offline)
    It 'Test-PimScenarioProfile.ps1 exits 0'   { Invoke-Suite 'Test-PimScenarioProfile.ps1'  | Should -Be 0 }  # §31 deployment-topology descriptor/catalog/resolver (S1-S6) offline gate
    It 'Test-PimScenarioWiring.ps1 exits 0'    { Invoke-Suite 'Test-PimScenarioWiring.ps1'   | Should -Be 0 }  # §31.3 Phase-1: scenario -> entry-point knob mapping (update-source incl. from-master, hosting, SPN, license tier, sync-file) + per-scenario license gating + entry-point -Scenario param (offline)
    It 'Test-PimScenarioRuntime.ps1 exits 0'   { Invoke-Suite 'Test-PimScenarioRuntime.ps1'  | Should -Be 0 }  # §31.3 RUNTIME RESOLUTION (the remaining ◻ items): pure hosting/SPN/sync-root resolvers (S1-S6) + Get-PimSqlConnectionString hosting thread (default unchanged) + GUI Deployment-scenario card GET/PUT round-trip + static wiring (offline)
    It 'Test-PimDownlink.ps1 exits 0'          { Invoke-Suite 'Test-PimDownlink.ps1'         | Should -Be 0 }  # §31.3 Phase-2: master->managed admin/permission downlink + scenario-bound runner pure cores -- ring filter (admin.Ring<=slave.Ring), signed-baseline verify (valid/tampered/expired/rollback/wrong-key, ephemeral key, no RSA.ImportFromPem), sync-file path resolution (central-msp/local-slave/none), idempotency decision, downlink plan refuse-on-bad-sig, runner topology branch (single/master=engine-apply; managed=downlink-sync->engine-apply); capability-probe names the live matrix Get-Commands (offline)
    # Hosted-mode SIMULATION gate: source-contract assertions always run (no SQL); the
    # live-boot block self-skips (exit 0) when no SQL is reachable. Exit 0 either way unless
    # the hosted SQL runtime regresses (defaults to local / static / CSV / -ConnectPlatform gate).
    It 'Test-PimManagerHostedSim.ps1 exits 0'  { Invoke-Suite 'Test-PimManagerHostedSim.ps1' | Should -Be 0 }
    It 'Test-PimSetupHosting.ps1 exits 0'       { Invoke-Suite 'Test-PimSetupHosting.ps1'     | Should -Be 0 }  # setup/deploy family + hosting contract (offline)
    It 'Test-PimRestExoSetup.ps1 exits 0'       { Invoke-Suite 'Test-PimRestExoSetup.ps1'     | Should -Be 0 }  # §19 REST migration: EXO runtime path over REST + SDK setup scripts -> REST redirects (offline)
    It 'Test-PimAccessReviews.ps1 exits 0'      { Invoke-Suite 'Test-PimAccessReviews.ps1'    | Should -Be 0 }  # Access Review overview data layer: pure normalization (scope/reviewers/recurrence/decision counts -> table-ready row)
    It 'Test-PimWarningOverrides.ps1 exits 0'   { Invoke-Suite 'Test-PimWarningOverrides.ps1' | Should -Be 0 }  # §11 validator warning override/acknowledge post-filter: code/scope/pattern, mandatory reason, expiry resurfaces (offline)
    It 'Test-PimWorkloadMap.ps1 exits 0'        { Invoke-Suite 'Test-PimWorkloadMap.ps1' | Should -Be 0 }  # Delegation Map workload-target reconciliation: desired (PIM-Assignments-Workloads) vs live crawl map -> mapped/missing/exempted/unknown; exemption contract (mandatory reason+expiry, expired resurfaces, over-broad ignored); crawl-map cache writer/read round-trip via stubbed connector API (offline, pure)
    It 'Test-PimMailTemplates.ps1 exits 0'      { Invoke-Suite 'Test-PimMailTemplates.ps1'    | Should -Be 0 }  # Governance: GUI-driven mail-template customization -- store override (no rebuild) wins over .custom.html file/shipped; reset falls back (offline)
    It 'Test-PimHomeOverview.ps1 exits 0'       { Invoke-Suite 'Test-PimHomeOverview.ps1'     | Should -Be 0 }  # §26a/§27 H2 Home/Overview tab + Alerting: landing tab + clickable tiles wired to /api/home; aggregation reflects seeded engine/job/validation/audit/break-glass state (FAILED jobs, L0-L5, gaps/orphans); alerting config + send routing through the notify path; configure-to-enable state (offline)
    It 'Test-PimApprovalsGui.ps1 exits 0'       { Invoke-Suite 'Test-PimApprovalsGui.ps1'     | Should -Be 0 }  # §11/§13/§27 H3/H4 + §H7 Approvals GUI wiring: Approvals tab + GET/POST /api/approvals + decision endpoint; queue round-trips the real ApprovalGate (maker!=checker, offboard plan, once-only latch, NO auto-execute); access-review per-item Approve/Deny wired to /api/access-reviews/decision with graceful degrade when AccessReview.ReadWrite.All ungranted (offline)
    It 'Test-PimOperationalPolicy.ps1 exits 0'  { Invoke-Suite 'Test-PimOperationalPolicy.ps1' | Should -Be 0 }  # §28 [M7] Settings operational-policy config surface: expiry-policy defaults + MFA-on-activation + connection-sanity persist+read-back through the SAME pim.Settings store the engine/jobs read (GUI->store->read round-trip via real wrappers); defaults correct; invalid value rejected/clamped not silently dropped; GUI card + GET/PUT /api/settings/operational-policy wired, SuperAdmin-gated (offline)
    It 'Test-PimRoleLookup.ps1 exits 0'          { Invoke-Suite 'Test-PimRoleLookup.ps1'        | Should -Be 0 }  # §28 [H9] Role Lookup upgrade: pure typo-tolerant matching (Resolve-PimRoleQuery: exact resolves, a typo returns ranked did-you-mean candidates + NO throw/NO 503, empty/unknown -> empty list) + reverse lookup (Get-PimRoleReachers lists the right principals + paths) + role compare (Compare-PimReachSets overlap/each-only); GUI tab has 3 sub-modes wired to /api/role-permissions + /api/role-lookup/reverse + /api/role-lookup/compare, near-miss is 200-with-candidates not 503 (offline)
    It 'Test-PimTierImpact.ps1 exits 0'          { Invoke-Suite 'Test-PimTierImpact.ps1'       | Should -Be 0 }  # §23/ROADMAP #24 Tier-impact report: pure core (PIM-TierImpact.ps1 / Get-PimTierImpactReport) over the live graph reach model lists EVERY user with a path (incl. INDIRECT via nested groups) to a T0/T1 target -- highest tier, distinct high-tier target count, worst-target granting path, viaNested direct-vs-indirect flag; -HighTierMax 0 narrows to T0-only; honest empty when nothing reaches high tier; rows sort most-privileged-first. Reuses the PIM-MapRisk reach helpers (running min-group-level propagates a role group's tier down nested edges). GUI Reports tier-impact mode wired to GET /api/tier-impact[?tier=0] + wrapper Get-PimTierImpactReportLive (offline)
    It 'Test-PimDrift.ps1 exits 0'               { Invoke-Suite 'Test-PimDrift.ps1'            | Should -Be 0 }  # §28 [M5] Governance drift view + gated remediation: drift report reuses the engine delta (Compare-PimDesiredVsLive) classifying missing/changed/extra; remediation plan targets ONLY selected drift; NO destructive removal of an 'extra' without explicit opt-in (-AllowRemove -> engine -Prune); engine round-trip applies exactly the selected drift, WhatIf writes nothing (offline)
    It 'Test-PimAlertFeed.ps1 exits 0'           { Invoke-Suite 'Test-PimAlertFeed.ps1'        | Should -Be 0 }  # §26c/§28 [H2] + [M5] residual: alert FEED + recorded-send proof. New-PimAlertRecord folds the send result into a durable proof record (sendState sent/rendered/suppressed); stable dedupe key + debounce window suppresses identical repeats; feed prepend+clamp; filter by event/sentOnly/since + paging; Home summary rollup (total/sent/unsent/per-event); Get-PimExpiringAccessAlert fires only on rows expiring inside the window; JSONL adapter round-trips UTF8-no-BOM + retention clamp (offline)
    It 'Test-PimAuditQuery.ps1 exits 0'          { Invoke-Suite 'Test-PimAuditQuery.ps1'       | Should -Be 0 }  # §28 [H6]/§26c "Audit you can defend": pure audit-trail query core (PIM-AuditQuery.ps1). Full history (calendar-month window, NOT the old hard 3-month cap; months=0/all reads every monthly file) + a human before/after `change` per event (Get-PimAuditChangeSummary: old->new, create/remove, unchanged omitted) + RFC-4180 full-trail CSV (Change column, formula-injection guard, culture-independent ISO timestamps). Filter (category/search/date-range) + newest-first sort shared by /api/audit + /api/audit/export (offline)
    It 'Test-PimRolePermissionsExport.ps1 exits 0' { Invoke-Suite 'Test-PimRolePermissionsExport.ps1' | Should -Be 0 }  # §28 [L5]/[H5] Role Lookup export: pure CSV core (PIM-RolePermissionsExport.ps1) for all 4 read-only modes -- a role's concrete permissions for a least-privilege ticket (ConvertTo-PimRolePermissionsCsv: allowed/excluded resource+data actions, de-duped, namespace, role-stamped), which-roles-grant-action ranked least-priv-first w/ broad-wildcard flag (ConvertTo-PimRolesByActionCsv), who-can-activate-with-path (ConvertTo-PimRoleReachersCsv), and the both/only-A/only-B compare (ConvertTo-PimRoleCompareCsv). Spreadsheet formula-injection guard (= + - @ /tab -> quoted) + RFC-4180 + CRLF, identical to the audit export + GUI csvCell. Empty input -> header-only, never throws. PS 5.1-safe (.ToArray() not @() on List[object]) (offline)
    It 'Test-PimFeatureFlags.ps1 exits 0'        { Invoke-Suite 'Test-PimFeatureFlags.ps1'     | Should -Be 0 }  # GUI gradual rollout: turn any Manager feature on/off in Settings. Pure catalog + resolver (core ON / advanced OFF defaults; persisted override flips a flag; always-on Home/Audit/Settings can't be disabled; unknown flag ignored+warned; minimal-override reduction) + GUI->store->read round-trip through the SAME pim.Settings store the nav reads at boot (Get-/Set-PimFeatureFlags) + GUI/server wiring (Features card, GET/PUT /api/settings/feature-flags SuperAdmin-gated+audited, boot-injected flags gate the nav, disabled tabs/empty groups hidden) (offline)
    It 'Test-PimScenarioProfile.ps1 exits 0'     { Invoke-Suite 'Test-PimScenarioProfile.ps1'  | Should -Be 0 }  # §31 deployment-topology scenario descriptor + resolver: generic 8-dimension contract (reusable for SI/CEH), S1-S6 catalog, descriptor invariants, resolution onto existing knobs (configVariant/update-source/ring/edition/hosting/SPN/sync), active-scenario store-read + apply (offline)
    It 'Test-PimFleetConformance.ps1 exits 0'    { Invoke-Suite 'Test-PimFleetConformance.ps1' | Should -Be 0 }  # §28 [H8] FLEET template conformance: pure tenants×templates matrix (only approved templates are columns; per-cell status + behind-by-N; never-deployed=all-NeverApplied; tenant/per-template rollups + totals; worst-behind-first; hashtable OR PSCustomObject appliedVersions) + ring-wide rollout plan (exclusive ring bands, per-band behind/never, draft flagged not-approved) + Get-PimFleetStateForInstance reads applied versions + optional fleetRingByTenant ring stamp from a real state file, tolerates missing/garbage (offline)
    It 'Test-PimFleetEndpoints.ps1 exits 0'      { Invoke-Suite 'Test-PimFleetEndpoints.ps1'   | Should -Be 0 }  # §28 [H8] fleet endpoints (live boot): GET /api/conformance/fleet (401 w/o token; activeInstance+templates+tenants; local tenant present; never-applied cell + not-current; per-template rollup) + GET /api/conformance/ring-plan?template= (templateId echo, ring bands, local behind/never, unknown template -> 400); read-only, restores seeded state
}

Describe 'Workload-connector framework' {
    It 'Get-PimNestedProp reads dotted paths' {
        Get-PimNestedProp ([pscustomobject]@{ a = [pscustomobject]@{ b = [pscustomobject]@{ c = 'v' } } }) 'a.b.c' | Should -Be 'v'
        Get-PimNestedProp ([pscustomobject]@{ a = $null }) 'a.b' | Should -Be $null
    }
    It 'Get-PimWorkloadToken prefers the launcher-supplied token' {
        $global:PIM_WorkloadTokens = @{ arm = 'token-123' }
        Get-PimWorkloadToken -Connector ([pscustomobject]@{ id='t'; auth='arm'; api=[pscustomobject]@{ baseUrl='https://x' } }) | Should -Be 'token-123'
        $global:PIM_WorkloadTokens = $null
    }
    It 'Get-PimWorkloadToken throws for an unknown adapter with no override' {
        { Get-PimWorkloadToken -Connector ([pscustomobject]@{ id='t'; auth='mystery'; api=[pscustomobject]@{ baseUrl='https://x' } }) } | Should -Throw
    }
    It 'every connector JSON is valid + has required ops + known auth' {
        $knownAuth = 'graph','arm','powerbi','devops','businesscentral','dataverse','powerplatform'
        $files = Get-ChildItem (Join-Path $Root 'workloads\connectors') -Filter '*.connector.json'
        $files.Count | Should -BeGreaterThan 0
        foreach ($f in $files) {
            $c = Get-Content $f.FullName -Raw | ConvertFrom-Json   # throws -> It fails, which is the JSON-validity assertion
            $c.id   | Should -Not -BeNullOrEmpty
            $c.auth | Should -BeIn $knownAuth -Because "$($f.Name) auth must be a known adapter"
            $c.api.assign | Should -Not -BeNullOrEmpty -Because "$($f.Name) needs an assign op"
            $c.api.remove | Should -Not -BeNullOrEmpty -Because "$($f.Name) needs a remove op"
            # a connector must list roles via API or carry a static roles array
            ($null -ne $c.api.listRoles -or $null -ne $c.roles) | Should -BeTrue -Because "$($f.Name) needs listRoles or a static roles array"
        }
    }
    It 'Get-PimWorkloadRoles returns the static roles for a no-listRoles connector (powerbi)' {
        $pbi = Get-Content (Join-Path $Root 'workloads\connectors\powerbi.connector.json') -Raw | ConvertFrom-Json
        $roles = @(Get-PimWorkloadRoles -Connector $pbi)
        $roles.Count | Should -Be 4
        ($roles | ForEach-Object { $_.name }) | Should -Contain 'Member'
    }
    It 'nested-membership connectors declare resolveContainer + listContainerRoles' {
        $files = Get-ChildItem (Join-Path $Root 'workloads\connectors') -Filter '*.connector.json'
        foreach ($f in $files) {
            $c = Get-Content $f.FullName -Raw | ConvertFrom-Json
            if ($c.membershipModel) {
                $c.api.resolveContainer   | Should -Not -BeNullOrEmpty -Because "$($f.Name) is membershipModel -> needs resolveContainer"
                $c.api.listContainerRoles | Should -Not -BeNullOrEmpty -Because "$($f.Name) is membershipModel -> needs listContainerRoles"
            }
        }
    }
    It 'Get-PimWorkloadContainerId returns null when the connector has no resolveContainer' {
        Get-PimWorkloadContainerId -Connector ([pscustomobject]@{ api = [pscustomobject]@{} }) -Tokens @{ groupId = 'g' } | Should -Be $null
    }
    It 'membership tokens expand into Dataverse container paths + odata body' {
        $dv = Get-Content (Join-Path $Root 'workloads\connectors\dataverse.connector.json') -Raw | ConvertFrom-Json
        $tok = @{ groupId = 'GID'; container = 'TEAM1'; roleId = 'ROLE9'; resource = 'org.crm4.dynamics.com' }
        (Expand-PimWorkloadTokens -Text $dv.api.resolveContainer.path -Tokens $tok) | Should -BeLike '*azureactivedirectoryobjectid eq GID*'
        (Expand-PimWorkloadTokens -Text $dv.api.listContainerRoles.path -Tokens $tok) | Should -BeLike '*/teams(TEAM1)/teamroles_association*'
        $body = Expand-PimWorkloadTokens -Text ($dv.api.assign.body | ConvertTo-Json) -Tokens $tok
        ($body -like '*roles(ROLE9)*' -and $body -like '*org.crm4.dynamics.com*') | Should -BeTrue
    }

    # --- NEW per-workload connectors (batch) ---------------------------------
    It 'business-central + azure-devops + power-platform connectors are present' {
        foreach ($id in 'business-central','azure-devops','power-platform') {
            (Test-Path -LiteralPath (Join-Path $Root "workloads\connectors\$id.connector.json")) | Should -BeTrue
        }
    }
    It 'business-central is a membership connector (security group container -> permission sets) with token-expanding paths' {
        $bc = Get-Content (Join-Path $Root 'workloads\connectors\business-central.connector.json') -Raw | ConvertFrom-Json
        $bc.membershipModel | Should -BeTrue
        $bc.perRowResource  | Should -BeTrue
        $bc.auth | Should -Be 'businesscentral'
        $tok = @{ resource = 'TID/PROD'; company = 'CO1'; groupId = 'GID'; container = 'SG1'; roleId = 'PS9' }
        (Expand-PimWorkloadTokens -Text $bc.api.resolveContainer.path -Tokens $tok)   | Should -BeLike '*azureGroupId eq GID*'
        (Expand-PimWorkloadTokens -Text $bc.api.listContainerRoles.path -Tokens $tok) | Should -BeLike '*securityGroups(SG1)*'
        (Expand-PimWorkloadTokens -Text $bc.api.baseUrl -Tokens $tok)                 | Should -BeLike '*/v2.0/TID/PROD/api/*'
    }
    It 'azure-devops is a membership connector with a client-side originId match filter' {
        $ado = Get-Content (Join-Path $Root 'workloads\connectors\azure-devops.connector.json') -Raw | ConvertFrom-Json
        $ado.membershipModel | Should -BeTrue
        $ado.auth | Should -Be 'devops'
        $ado.api.resolveContainer.matchField | Should -Be 'originId'
        $ado.api.resolveContainer.matchToken | Should -Be 'groupId'
        $tok = @{ resource = 'contoso'; container = 'SUBJ'; roleId = 'GRP' }
        (Expand-PimWorkloadTokens -Text $ado.api.baseUrl -Tokens $tok)    | Should -BeLike '*vssps.dev.azure.com/contoso*'
        (Expand-PimWorkloadTokens -Text $ado.api.assign.path -Tokens $tok) | Should -BeLike '*/memberships/SUBJ/GRP*'
    }
    It 'power-platform is a flat connector with static Environment Admin/Maker roles' {
        $pp = Get-Content (Join-Path $Root 'workloads\connectors\power-platform.connector.json') -Raw | ConvertFrom-Json
        $pp.auth | Should -Be 'powerplatform'
        $pp.perRowResource | Should -BeTrue
        $roles = @(Get-PimWorkloadRoles -Connector $pp)
        ($roles | ForEach-Object { $_.name }) | Should -Contain 'Environment Admin'
        ($roles | ForEach-Object { $_.name }) | Should -Contain 'Environment Maker'
    }
    It 'Select-PimWorkloadContainerItem picks the originId match, else first item, else null' {
        $opMatch = [pscustomobject]@{ idField='descriptor'; matchField='originId'; matchToken='groupId' }
        $items = @([pscustomobject]@{ descriptor='A'; originId='x' }, [pscustomobject]@{ descriptor='B'; originId='y' })
        (Select-PimWorkloadContainerItem -Op $opMatch -Items $items -Tokens @{ groupId='y' }).descriptor | Should -Be 'B'
        $opPlain = [pscustomobject]@{ idField='teamid' }
        (Select-PimWorkloadContainerItem -Op $opPlain -Items @([pscustomobject]@{ teamid='1' },[pscustomobject]@{ teamid='2' }) -Tokens @{}).teamid | Should -Be '1'
        Select-PimWorkloadContainerItem -Op $opMatch -Items $items -Tokens @{ groupId='none' } | Should -Be $null
    }
    It 'new non-graph adapters (businesscentral / powerplatform) resolve a minted token' {
        $global:PIM_WorkloadTokens = @{ businesscentral='BC'; powerplatform='PP' }
        Get-PimWorkloadToken -Connector ([pscustomobject]@{ id='bc'; auth='businesscentral'; api=[pscustomobject]@{ baseUrl='x' } }) | Should -Be 'BC'
        Get-PimWorkloadToken -Connector ([pscustomobject]@{ id='pp'; auth='powerplatform'; api=[pscustomobject]@{ baseUrl='x' } }) | Should -Be 'PP'
        $global:PIM_WorkloadTokens = $null
    }
}

Describe 'Power Platform environment discovery (propose-don''t-auto-map)' {
    It 'derivation: production env -> PIM-PowerPlatform-*-L3-T1-WDP-RES' {
        $d = Get-PimPowerPlatformDerivation -DisplayName 'Sales' -EnvironmentType 'Production'
        $d.groupName | Should -BeLike 'PIM-PowerPlatform-*-L3-T1-WDP-RES'
        $d.tier | Should -Be 1
    }
    It 'reconcile: new env is create+pending; auto-import rule promotes to autoCreate' {
        $disc = @([pscustomobject]@{ environmentName='e1'; displayName='Dev'; environmentType='Sandbox' })
        (Get-PimPowerPlatformReconcilePlan -Discovered $disc -Existing @()).summary.autoCreate | Should -Be 0
        $rules = @(@{ environmentTypes=@('Sandbox') })
        (Get-PimPowerPlatformReconcilePlan -Discovered $disc -Existing @() -AutoImportRules $rules).summary.autoCreate | Should -Be 1
    }
    It 'reconcile: displayName drift on same env id -> rename, not orphan+create' {
        $disc = @([pscustomobject]@{ environmentName='e2'; displayName='Finance EU'; environmentType='Production' })
        $existing = @([pscustomobject]@{ environmentName='e2'; groupName='PIM-PowerPlatform-Finance-L3-T1-WDP-RES' })
        $plan = Get-PimPowerPlatformReconcilePlan -Discovered $disc -Existing $existing
        $plan.summary.rename | Should -Be 1
        $plan.summary.orphan | Should -Be 0
    }
    It 'queue: only auto-imports become Create; orphans only with -IncludeOrphanRemovals' {
        $disc = @([pscustomobject]@{ environmentName='e3'; displayName='Dev'; environmentType='Sandbox' })
        $plan = Get-PimPowerPlatformReconcilePlan -Discovered $disc -Existing @(([pscustomobject]@{ environmentName='gone'; groupName='PIM-PowerPlatform-Gone-L4-T1-WDP-RES' })) -AutoImportRules @(@{ environmentTypes=@('Sandbox') })
        @(ConvertTo-PimPowerPlatformQueueChanges -Plan $plan | Where-Object { $_.Op -eq 'Remove' }).Count | Should -Be 0
        @(ConvertTo-PimPowerPlatformQueueChanges -Plan $plan -IncludeOrphanRemovals | Where-Object { $_.Op -eq 'Remove' }).Count | Should -Be 1
    }
}

Describe 'Offline feature spot-checks (in-proc)' {
    It 'date expression resolves'      { (Resolve-PimDateExpression -Expression 'FirstWorkdayNextMonth@08:00') | Should -Not -BeNullOrEmpty }
    It 'license status resolves'       { (Get-PimLicense -Refresh).Status | Should -Not -BeNullOrEmpty }
    It 'edition is Community without a license; Pro is granted FREE (no nag, no block)' {
        (Get-PimEdition) | Should -Be 'Community'
        (Get-PimLicenseStatusText) | Should -BeLike 'Community*'
        # Pro is distributed free: by default the gate passes silently and the
        # advanced features are available with NO license + NO nag.
        (Test-PimProLicenseEnforced) | Should -BeFalse
        (Test-PimProFeature -Feature 'ApproverMatrix' -Quiet) | Should -BeTrue
        (Test-PimProFeature -Feature 'Conformance' -Quiet)   | Should -BeTrue
        # The gate STILL works when an internal harness enforces it -- and a
        # super-admin is never locked out.
        $global:PIM_EnforceProLicense = $true
        try {
            (Test-PimProFeature -Feature 'Conformance' -Quiet)             | Should -BeFalse
            (Test-PimProFeature -Feature 'Conformance' -SuperAdmin -Quiet) | Should -BeTrue
        } finally { Remove-Variable -Name PIM_EnforceProLicense -Scope Global -ErrorAction SilentlyContinue }
    }
    It 'PIM-Engine dispatcher exists + every -Scope target engine script is present' {
        $engineRoot = Join-Path $Root 'engine'
        (Test-Path -LiteralPath (Join-Path $engineRoot 'PIM-Engine\PIM-Engine.ps1')) | Should -BeTrue
        $targets = @{
            All='PIM-Baseline-Management-CSV'; Admins='PIM-Baseline-Management-CSV-AdminsOnly'
            EntraRoles='PIM-Baseline-Management-CSV-EntraIDRolesOnly'; AzRes='PIM-Baseline-Management-CSV-AzResOnly'
            AdministrativeUnits='PIM-Baseline-Management-CSV-AdministrativeUnitsOnly'
            GroupsAssignment='PIM-Baseline-Management-CSV-PIM4GroupsAssignmentOnly'
            GroupsPolicies='PIM-Baseline-Management-CSV-PIM4GroupsPoliciesOnly'
            GroupsCreateModifyPolicy='PIM-Baseline-Management-CSV-PIM4GroupsCreateModifyPolicyOnly'
            Export='PIM-Assignment-Exporter'
        }
        foreach ($d in $targets.Values) { (Test-Path -LiteralPath (Join-Path $engineRoot (Join-Path $d "$d.ps1"))) | Should -BeTrue -Because "$d.ps1 must exist for the dispatcher" }
    }
    It 'random password has 4 classes' { $p = New-PimRandomPassword; ($p -cmatch '[A-Z]' -and $p -cmatch '[a-z]' -and $p -match '\d') | Should -BeTrue }
    It 'HighPriv name matches marker'  { 'Admin-X-L0-T0-ID' -match '(?i)(^|[-_.])(L0|T0)([-_.]|$)' | Should -BeTrue }
    It 'Day2Day name does not match'   { 'Admin-X-ID' -match '(?i)(^|[-_.])(L0|T0)([-_.]|$)' | Should -BeFalse }
}

Describe 'PIM conformance engine (native template versioning + reconcile)' {
    BeforeAll {
        $script:Now = [datetime]::Parse('2026-06-13T12:00:00Z').ToUniversalTime()
        $script:Tpl = ConvertTo-PimTemplate -Json ([System.IO.File]::ReadAllText((Join-Path $Root 'workloads\templates\defender-xdr-roles.template.json'), [System.Text.UTF8Encoding]::new($false)))
        $script:Preview = 'role:Security Operator (preview)'
        $script:Ring0Keys = @('role:Security Reader','role:Security Operator','role:Security Administrator')
    }
    It 'shipped template validates + is approved' {
        (Test-PimTemplateDoc -Template $Tpl).valid | Should -BeTrue
        (Test-PimTemplateApproved -Template $Tpl) | Should -BeTrue
        (Test-PimTemplateApproved -Template ([pscustomobject]@{ status='draft' })) | Should -BeFalse
    }
    It 'ring scope: ring-0 tenant sees 3 roles, ring-2 sees all 4' {
        (Select-PimInScopeEntries -Template $Tpl -TenantRing 0).Count | Should -Be 3
        (Select-PimInScopeEntries -Template $Tpl -TenantRing 2).Count | Should -Be 4
    }
    It 'exemption: no-expiry Invalid, past Expired, future Active' {
        (Test-PimExemptionValid -Exemption ([pscustomobject]@{ reason='r' }) -NowUtc $Now).state | Should -Be 'Invalid'
        (Test-PimExemptionValid -Exemption ([pscustomobject]@{ reason='r'; expiresUtc='2026-01-01T00:00:00Z' }) -NowUtc $Now).state | Should -Be 'Expired'
        (Test-PimExemptionValid -Exemption ([pscustomobject]@{ reason='r'; expiresUtc='2026-12-01T00:00:00Z' }) -NowUtc $Now).active | Should -BeTrue
    }
    It 'reconcile: Gap / Exempt / OutOfRing / DriftExtra / Behind' {
        $g = Get-PimConformance -Template $Tpl -TenantRing 2 -TenantId 't2' -LiveKeys $Ring0Keys -AppliedVersion 7
        @($g.Rows | Where-Object { $_.Key -eq $Preview -and $_.Status -eq 'Gap' }).Count | Should -Be 1
        $g.Behind | Should -Be 1
        $e = Get-PimConformance -Template $Tpl -TenantRing 2 -TenantId 't2' -LiveKeys $Ring0Keys -ActiveExemptionKeys @($Preview) -AppliedVersion 8
        @($e.Rows | Where-Object { $_.Key -eq $Preview -and $_.Status -eq 'Exempt' }).Count | Should -Be 1
        $p = Get-PimConformance -Template $Tpl -TenantRing 0 -TenantId 'p0' -LiveKeys $Ring0Keys -AppliedVersion 8
        @($p.Rows | Where-Object { $_.Key -eq $Preview -and $_.Status -eq 'OutOfRing' }).Count | Should -Be 1
        $d = Get-PimConformance -Template $Tpl -TenantRing 0 -TenantId 'p0' -LiveKeys @($Ring0Keys + $Preview) -AppliedVersion 8
        @($d.Rows | Where-Object { $_.Key -eq $Preview -and $_.Status -eq 'DriftExtra' }).Count | Should -Be 1
    }
    It 'catalog-ahead flags an uncovered live capability' {
        $c = Get-PimConformance -Template $Tpl -TenantRing 2 -TenantId 't2' -LiveCatalog @('Security Reader','Custom Threat Hunter')
        @($c.CatalogAhead | Where-Object { $_.Capability -eq 'Custom Threat Hunter' }).Count | Should -Be 1
    }
    It 'draft + approve + promote are pure (clone, original untouched)' {
        $draft = New-PimTemplateDraft -Template $Tpl -Capabilities @('Custom Threat Hunter') -NowUtc $Now
        $draft.templateVersion | Should -Be 9
        "$($draft.status)" | Should -Be 'draft'
        $Tpl.templateVersion | Should -Be 8
        (Test-PimTemplateApproved -Template (Approve-PimTemplate -Template $draft -ApprovedBy 'mok' -NowUtc $Now)) | Should -BeTrue
        $promoted = Set-PimEntryRing -Template $Tpl -Key $Preview -Ring 0
        ((@($promoted.entries | Where-Object { "$($_.key)" -eq $Preview }) | ForEach-Object { Get-PimTemplateEntryRing -Entry $_ })) | Should -Be 0
        ((@($Tpl.entries | Where-Object { "$($_.key)" -eq $Preview }) | ForEach-Object { Get-PimTemplateEntryRing -Entry $_ })) | Should -Be 2
    }
    It 'roll-forward rows: approved, ring-gated, exemption-skipped; draft throws' {
        $ex = @([pscustomobject]@{ tenantId='t2'; templateId='defender-xdr-roles'; itemKey='role:Security Reader'; reason='held'; expiresUtc='2026-12-01T00:00:00Z' })
        $rows = @(Get-PimRollForwardRows -Template $Tpl -TenantRing 2 -TenantId 't2' -Exemptions $ex -NowUtc $Now)
        $rows.Count | Should -Be 3   # 4 in-scope minus 1 exempted
        ($rows | Where-Object { $_.RoleName -eq 'Security Reader' }).Count | Should -Be 0
        ($rows | Where-Object { $_.Workload -eq 'defender-xdr' }).Count | Should -Be 3
        $prod = @(Get-PimRollForwardRows -Template $Tpl -TenantRing 0 -TenantId 'p0' -NowUtc $Now)
        $prod.Count | Should -Be 3   # ring-2 preview excluded on a ring-0 tenant
        { Get-PimRollForwardRows -Template ([pscustomobject]@{ templateId='d'; workload='w'; status='draft'; entries=@() }) -TenantRing 2 -NowUtc $Now } | Should -Throw
    }
}

Describe 'Portal-admin scoping (delegated GUI managers)' {
    BeforeAll {
        $script:Profiles = @((Get-Content (Join-Path $Root 'config\portal-admins.sample.json') -Raw | ConvertFrom-Json).portalAdmins)
        $script:Helpdesk = Get-PimPortalProfile -Profiles $Profiles -Identity 'CONTOSO\helpdesk1'
        $script:AzDev    = Get-PimPortalProfile -Profiles $Profiles -Identity 'devlead@contoso.com'
        $script:Dept     = Get-PimPortalProfile -Profiles $Profiles -Identity 'deptowner@contoso.com'
    }
    It 'facets from a definition row (columns)' {
        $f = Get-PimGroupFacets -Row ([pscustomobject]@{ GroupName='PIM-Entra-ID-UserAdmin-L1-T0-CP-ID'; Workload='Entra-ID'; Level='L1'; TierLevel='T0'; Plane='CP'; GroupTag='Entra-ID-UserAdmin-L1' })
        $f.service | Should -Be 'entra'; $f.tier | Should -Be 0; $f.level | Should -Be 1; $f.kind | Should -Be 'indirect'
    }
    It 'facets fall back to parsing the group name' {
        $f = Get-PimGroupFacets -Row ([pscustomobject]@{ GroupName='PIM-Azure-Sub-Owner-L1-T1-WDP-RES'; GroupTag='Azure-Sub-Owner-L1' })
        $f.service | Should -Be 'azure'; $f.tier | Should -Be 1; $f.level | Should -Be 1; $f.plane | Should -Be 'WDP'
    }
    It 'helpdesk (entra, levelMax 2) sees L2+ entra but not L0/L1, not azure' {
        $see = { param($svc,$t,$l) Test-PimPortalCanSeeGroup -Profile $Helpdesk -Facets @{ service=$svc; tier=$t; level=$l; kind='indirect'; scope='' } }
        (& $see 'entra' 0 2) | Should -BeTrue
        (& $see 'entra' 0 1) | Should -BeFalse
        (& $see 'entra' 0 0) | Should -BeFalse
        (& $see 'azure' 1 3) | Should -BeFalse
    }
    It 'helpdesk can manage indirect (has cap) but not direct (no cap)' {
        (Test-PimPortalCanManageGroup -Profile $Helpdesk -Facets @{ service='entra'; tier=0; level=2; kind='indirect'; scope='' }) | Should -BeTrue
        (Test-PimPortalCanManageGroup -Profile $Helpdesk -Facets @{ service='entra'; tier=0; level=2; kind='direct'; scope='' }) | Should -BeFalse
    }
    It 'azure dev is scope-gated + tier-gated' {
        $base = @{ service='azure'; tier=1; level=1; kind='indirect' }
        (Test-PimPortalCanSeeGroup -Profile $AzDev -Facets ($base + @{ scope='/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg1' })) | Should -BeTrue
        (Test-PimPortalCanSeeGroup -Profile $AzDev -Facets ($base + @{ scope='/subscriptions/99999999-9999-9999-9999-999999999999' })) | Should -BeFalse
        (Test-PimPortalCanSeeGroup -Profile $AzDev -Facets @{ service='azure'; tier=0; level=0; kind='indirect'; scope='/subscriptions/11111111-1111-1111-1111-111111111111' }) | Should -BeFalse
        (Test-PimPortalCanSeeGroup -Profile $AzDev -Facets @{ service='entra'; tier=0; level=2; kind='indirect'; scope='' }) | Should -BeFalse
    }
    It 'dept owner: assign-only (no manage), assign-admin only for managed consultants, enable own consultants' {
        (Test-PimPortalCanManageGroup -Profile $Dept -Facets @{ service='entra'; tier=1; level=3; kind='indirect'; scope='' }) | Should -BeFalse
        (Test-PimPortalCanAssign -Profile $Dept) | Should -BeTrue
        (Test-PimPortalCanAssignAdmin -Profile $Dept -AdminName 'consultant1@contoso.com') | Should -BeTrue
        (Test-PimPortalCanAssignAdmin -Profile $Dept -AdminName 'someone-else@contoso.com') | Should -BeFalse
        (Test-PimPortalCanEnableConsultant -Profile $Dept -AdminName 'consultant2@contoso.com') | Should -BeTrue
        (Test-PimPortalCanEnableConsultant -Profile $Helpdesk -AdminName 'consultant2@contoso.com') | Should -BeFalse
    }
    It 'SuperAdmin bypasses all scoping' {
        (Test-PimPortalCanSeeGroup -Profile $null -Facets @{ service='entra'; tier=0; level=0; kind='indirect'; scope='' } -IsSuperAdmin) | Should -BeTrue
        (Test-PimPortalCanManageGroup -Profile $null -Facets @{ service='azure'; tier=0; level=0; kind='direct'; scope='' } -IsSuperAdmin) | Should -BeTrue
    }
    It 'PAW gate is OPT-IN (off by default); level rule when enabled' {
        $t0 = @{ service='entra'; tier=0; plane='CP'; level=1; kind='indirect'; scope='' }
        # DEFAULT (off): allowed regardless of PAW -- nobody locked out
        (Test-PimPawAllowed -Tier 0 -Plane 'CP' -Level 1 -RequestPawLevel $null) | Should -BeTrue
        (Test-PimPortalCanManageGroup -Profile $null -Facets $t0 -IsSuperAdmin -RequestPawLevel $null) | Should -BeTrue
        # ENABLED: tier-0 needs a PAW; PAW level must be <= group level
        (Test-PimPawAllowed -Tier 0 -Plane 'CP' -Level 1 -RequestPawLevel $null -Enforce $true) | Should -BeFalse
        (Test-PimPawAllowed -Tier 0 -Plane 'CP' -Level 1 -RequestPawLevel 0 -Enforce $true) | Should -BeTrue
        (Test-PimPawAllowed -Tier 0 -Plane 'CP' -Level 1 -RequestPawLevel 2 -Enforce $true) | Should -BeFalse   # helpdesk L2 can't do L1
    }
    It 'super-admin stays exempt from the PAW gate unless explicitly opted in' {
        $t0 = @{ service='entra'; tier=0; plane='CP'; level=0; kind='indirect'; scope='' }
        try {
            $global:PIM_PawEnforcement = $true
            (Test-PimPortalCanManageGroup -Profile $null -Facets $t0 -IsSuperAdmin -RequestPawLevel $null) | Should -BeTrue   # exempt by default
            (Test-PimPortalCanManageGroup -Profile $null -Facets $t0 -IsSuperAdmin -RequestPawLevel $null -EnforcePawForSuperAdmin $true) | Should -BeFalse
            (Test-PimPortalCanManageGroup -Profile $null -Facets $t0 -IsSuperAdmin -RequestPawLevel 0 -EnforcePawForSuperAdmin $true) | Should -BeTrue
        } finally { $global:PIM_PawEnforcement = $null }
    }
    It 'Resolve-PimDevicePawLevel: pluggable detection -> lowest level wins' {
        (Resolve-PimDevicePawLevel -Signals @{ pawLevel = 2 }) | Should -Be 2
        (Resolve-PimDevicePawLevel -Signals @{ deviceGroupPawL1 = $true; deviceGroupPawL2 = $true }) | Should -Be 1   # most-privileged wins
        ($null -eq (Resolve-PimDevicePawLevel -Signals @{ deviceGroupPawL1 = $false })) | Should -BeTrue
        try { $global:PIM_PawSignals = @('deviceGroupPawL0')   # only trust this signal
            ($null -eq (Resolve-PimDevicePawLevel -Signals @{ deviceGroupPawL2 = $true })) | Should -BeTrue
            (Resolve-PimDevicePawLevel -Signals @{ deviceGroupPawL0 = $true }) | Should -Be 0
        } finally { $global:PIM_PawSignals = $null }
    }
    It 'PAW device: per-level group body, tag body, level detection' {
        (Get-PimPawGroupName -Level 0) | Should -Be 'PIM-PAW-L0-Devices'
        $g = New-PimPawGroupBody -Level 1
        $g.securityEnabled | Should -BeTrue; $g.mailEnabled | Should -BeFalse; $g.displayName | Should -Be 'PIM-PAW-L1-Devices'
        (New-PimPawDeviceTagBody -ExtensionAttribute 5 -Value 'PAW-L0').extensionAttributes.extensionAttribute5 | Should -Be 'PAW-L0'
        # level by group membership (lowest wins)
        $dev = [pscustomobject]@{ id='d1'; transitiveMemberOf=@([pscustomobject]@{ id='g1' }, [pscustomobject]@{ id='g2' }) }
        (Get-PimDevicePawLevel -Device $dev -PawGroupIds @{ 0='g0'; 1='g1'; 2='g2' }) | Should -Be 1
        ($null -eq (Get-PimDevicePawLevel -Device ([pscustomobject]@{ id='x'; transitiveMemberOf=@() }) -PawGroupIds @{ 0='g0' })) | Should -BeTrue
        # level by extensionAttribute
        $devEa = [pscustomobject]@{ id='d3'; extensionAttributes=[pscustomobject]@{ extensionAttribute5='PAW-L2' } }
        (Get-PimDevicePawLevel -Device $devEa -ExtensionAttribute 5) | Should -Be 2
    }
    It 'PAW groups are protected by a restricted-management AU' {
        (New-PimPawAuBody).isMemberManagementRestricted | Should -BeTrue
    }
    It 'approvers/owners: ownership, approve routing, access review' {
        $res = [pscustomobject]@{ GroupTag='Entra-ID-A-L1'; Owners='owner1@contoso.com; owner2@contoso.com'; Workload='Entra-ID'; Level='L1'; TierLevel='T0'; Plane='CP' }
        @(Get-PimResourceOwners -Row $res).Count | Should -Be 2
        (Test-PimIsResourceOwner -Row $res -Identity 'OWNER1@contoso.com') | Should -BeTrue   # case-insensitive
        (Test-PimIsResourceOwner -Row $res -Identity 'nope@contoso.com') | Should -BeFalse
        # approve: owner yes; stranger no; super yes
        (Test-PimCanApprove -Identity 'owner1@contoso.com' -Row $res -Profile $null) | Should -BeTrue
        (Test-PimCanApprove -Identity 'stranger@contoso.com' -Row $res -Profile $null) | Should -BeFalse
        (Test-PimCanApprove -Identity 'x' -Row $res -Profile $null -IsSuperAdmin) | Should -BeTrue
        # decision: approve -> Create change; reject -> none; unauthorized -> ok=false
        $req = New-PimApprovalRequest -Requestor 'r' -TargetAdmin 'consultant1@contoso.com' -GroupTag 'Entra-ID-A-L1' -Justification 'project x'
        $ap = Resolve-PimApprovalDecision -Request $req -Approver 'owner1@contoso.com' -Decision approve -CanApprove $true
        $ap.ok | Should -BeTrue; $ap.status | Should -Be 'approved'; $ap.change.op | Should -Be 'Create'; $ap.change.key | Should -Be 'consultant1@contoso.com|Entra-ID-A-L1'
        (Resolve-PimApprovalDecision -Request $req -Approver 'owner1@contoso.com' -Decision reject -CanApprove $true).change | Should -BeNullOrEmpty
        (Resolve-PimApprovalDecision -Request $req -Approver 'stranger' -Decision approve -CanApprove $false).ok | Should -BeFalse
        # access review set: only assignments to owned resources
        $defs = @($res, [pscustomobject]@{ GroupTag='Entra-ID-B-L1'; Owners='someoneelse@contoso.com' })
        $asg  = @(
            [pscustomobject]@{ Username='c1@contoso.com'; GroupTag='Entra-ID-A-L1' }
            [pscustomobject]@{ Username='c2@contoso.com'; GroupTag='Entra-ID-B-L1' }
        )
        $rev = @(Get-PimAccessReviewSet -Assignments $asg -OwnerIdentity 'owner1@contoso.com' -Definitions $defs)
        $rev.Count | Should -Be 1; "$($rev[0].GroupTag)" | Should -Be 'Entra-ID-A-L1'
        (Resolve-PimAccessReviewDecision -Assignment $rev[0] -Decision remove).change.op | Should -Be 'Remove'
        (Resolve-PimAccessReviewDecision -Assignment $rev[0] -Decision keep).change | Should -BeNullOrEmpty
    }
    It 'approver matrix: dimensional routing (workload x tier x level) + escalation' {
        $matrix = @(
            [pscustomobject]@{ workload='Entra-ID'; tier=0; level=2; approvers=@('helpdeskmgr@contoso.com'); escalateTo=@('itmanager@contoso.com'); slaHours=24 }
            [pscustomobject]@{ workload='PowerBI'; tier=1; level=1; approvers=@('pbiowner@contoso.com'); escalateTo=@('itmanager@contoso.com') }
            [pscustomobject]@{ workload='*'; approvers=@('fallback@contoso.com') }
        )
        $entraL2 = @{ workload='Entra-ID'; service='entra'; tier=0; level=2; plane='CP' }
        $pbiL1   = @{ workload='PowerBI';  service='workload'; tier=1; level=1; plane='WDP' }
        @(Get-PimApproversForResource -Facets $entraL2 -Matrix $matrix) | Should -Be @('helpdeskmgr@contoso.com')
        @(Get-PimApproversForResource -Facets $pbiL1 -Matrix $matrix) | Should -Be @('pbiowner@contoso.com')
        # unmatched specific -> wildcard fallback
        @(Get-PimApproversForResource -Facets @{ workload='Intune'; service='workload'; tier=1; level=5; plane='WDP' } -Matrix $matrix) | Should -Be @('fallback@contoso.com')
        # escalation (next level = IT manager)
        @(Get-PimEscalationApprovers -Facets $entraL2 -Matrix $matrix) | Should -Be @('itmanager@contoso.com')
        # can-approve by matrix
        $row = [pscustomobject]@{ GroupTag='Entra-ID-A-L2'; Workload='Entra-ID'; Level='L2'; TierLevel='T0'; Plane='CP' }
        (Test-PimCanApprove -Identity 'helpdeskmgr@contoso.com' -Row $row -Facets $entraL2 -Matrix $matrix -Profile $null) | Should -BeTrue
        (Test-PimCanApprove -Identity 'pbiowner@contoso.com'   -Row $row -Facets $entraL2 -Matrix $matrix -Profile $null) | Should -BeFalse
        # SLA escalation due
        $req = New-PimApprovalRequest -Requestor 'r' -TargetAdmin 'c@contoso.com' -GroupTag 'Entra-ID-A-L2' -Justification 'x' -NowUtc ([datetime]'2026-06-13T00:00:00Z')
        (Test-PimApprovalEscalationDue -Request $req -NowUtc ([datetime]'2026-06-14T02:00:00Z') -SlaHours 24) | Should -BeTrue   # 26h
        (Test-PimApprovalEscalationDue -Request $req -NowUtc ([datetime]'2026-06-13T06:00:00Z') -SlaHours 24) | Should -BeFalse  # 6h
    }
    It 'layered approvers by scope (Defender servers-only vs all-assets) + escalation steps through layers' {
        $matrix = @(
            [pscustomobject]@{ workload='Defender'; scope='Servers'; approvers=@('serverteam@contoso.com') }   # specific (scope)
            [pscustomobject]@{ workload='Defender'; approvers=@('secserviceowner@contoso.com') }                # broad service owner
        )
        $srv = @{ workload='Defender'; service='workload'; tier=1; level=3; plane='WDP'; scope='Servers' }
        # primary (route) = most-specific scope layer; layered (allowed) = both
        @(Get-PimApproversForResource -Facets $srv -Matrix $matrix) | Should -Be @('serverteam@contoso.com')
        $all = @(Get-PimAllApproversForResource -Facets $srv -Matrix $matrix)
        ($all -contains 'serverteam@contoso.com' -and $all -contains 'secserviceowner@contoso.com') | Should -BeTrue
        (Test-PimCanApprove -Identity 'secserviceowner@contoso.com' -Row ([pscustomobject]@{ Workload='Defender'; Scope='Servers'; TierLevel='T1'; Level='L3'; Plane='WDP' }) -Facets $srv -Matrix $matrix -Profile $null) | Should -BeTrue
        # layers most-specific first
        $layers = @(Get-PimApproverLayers -Facets $srv -Matrix $matrix)
        $layers.Count | Should -Be 2
        $layers[0].approvers | Should -Contain 'serverteam@contoso.com'
        $layers[1].approvers | Should -Contain 'secserviceowner@contoso.com'
        # escalation steps: <24h -> layer 0; 24-48h -> layer 1 (escalated)
        $rq = New-PimApprovalRequest -Requestor 'r' -TargetAdmin 'c' -GroupTag 'Defender-Servers' -Justification 'x' -NowUtc ([datetime]'2026-06-13T00:00:00Z')
        (Get-PimEscalationTargetForRequest -Request $rq -Facets $srv -Matrix $matrix -NowUtc ([datetime]'2026-06-13T06:00:00Z') -SlaHours 24).layerIndex | Should -Be 0
        $esc = Get-PimEscalationTargetForRequest -Request $rq -Facets $srv -Matrix $matrix -NowUtc ([datetime]'2026-06-14T06:00:00Z') -SlaHours 24
        $esc.layerIndex | Should -Be 1; $esc.isEscalated | Should -BeTrue; $esc.approvers | Should -Contain 'secserviceowner@contoso.com'
    }
    It 'Defender scope parsed from the group name (no Scope column)' {
        # real naming: ...-Scope-Servers-L3... ; Scope column is blank
        $f = Get-PimGroupFacets -Row ([pscustomobject]@{ GroupName='PIM-Defender-XDR-SecurityOperations-Operator-Scope-Servers-L3-T1-MP-ID'; Workload='Defender-XDR'; Level='L3'; TierLevel='T1'; Plane='MP' })
        $f.scope | Should -Be 'Servers'
    }
    It 'support-function personas (@CISO / @ITManager / @HRManager) resolve from config' {
        try {
            $global:PIM_SupportFunctions = @{ CISO=@('ciso@contoso.com'); ITManager=@('itm@contoso.com'); HRManager=@('hrm@contoso.com') }
            $matrix = @(
                [pscustomobject]@{ workload='Dataverse'; approvers=@('@HRManager'); escalateTo=@('@ITManager','@CISO') }
            )
            $f = @{ workload='Dataverse'; service='workload'; tier=1; level=3; plane='WDP'; scope='' }
            @(Get-PimApproversForResource -Facets $f -Matrix $matrix) | Should -Be @('hrm@contoso.com')      # @HRManager expanded
            $escs = @(Get-PimEscalationApprovers -Facets $f -Matrix $matrix)
            ($escs -contains 'itm@contoso.com' -and $escs -contains 'ciso@contoso.com') | Should -BeTrue   # personas as top escalation
            (Test-PimCanApprove -Identity 'hrm@contoso.com' -Row ([pscustomobject]@{ Workload='Dataverse'; Level='L3'; TierLevel='T1'; Plane='WDP' }) -Facets $f -Matrix $matrix -Profile $null) | Should -BeTrue
        } finally { $global:PIM_SupportFunctions = $null }
    }
    It 'PAW policy: tier-0 + tier-1/MP need PAW; tier-1/WDP L3+ and tier-2 are whole-network' {
        (Get-PimRequiredPawLevel -Tier 0 -Plane 'CP' -Level 1) | Should -Be 1          # tier-0 -> PAW at group level
        (Get-PimRequiredPawLevel -Tier 1 -Plane 'MP' -Level 2) | Should -Be 2          # mgmt plane -> PAW
        ($null -eq (Get-PimRequiredPawLevel -Tier 1 -Plane 'WDP' -Level 3)) | Should -BeTrue   # workload-data plane -> whole network
        ($null -eq (Get-PimRequiredPawLevel -Tier 2 -Plane 'WDP' -Level 4)) | Should -BeTrue   # tier 2 -> whole network
        # enforcement off by default
        (Test-PimPawAllowed -Tier 0 -Plane 'CP' -Level 0 -RequestPawLevel $null) | Should -BeTrue
        # enabled: MP tier-1 needs a sufficient PAW
        (Test-PimPawAllowed -Tier 1 -Plane 'MP' -Level 1 -RequestPawLevel $null -Enforce $true) | Should -BeFalse
        (Test-PimPawAllowed -Tier 1 -Plane 'MP' -Level 1 -RequestPawLevel 0 -Enforce $true) | Should -BeTrue
        (Test-PimPawAllowed -Tier 1 -Plane 'WDP' -Level 3 -RequestPawLevel $null -Enforce $true) | Should -BeTrue   # WDP L3+ never gated
    }
    It 'Select-PimPortalVisibleRows filters a row set for the profile' {
        $rows = @(
            [pscustomobject]@{ GroupName='PIM-Entra-ID-GA-L0-T0-CP-ID'; Workload='Entra-ID'; Level='L0'; TierLevel='T0'; Plane='CP' }
            [pscustomobject]@{ GroupName='PIM-Entra-ID-UA-AU-Fin-L2-T0-CP-ID'; Workload='Entra-ID'; Level='L2'; TierLevel='T0'; Plane='CP' }
        )
        $vis = @(Select-PimPortalVisibleRows -Profile $Helpdesk -Rows $rows)
        $vis.Count | Should -Be 1
        "$($vis[0].GroupName)" | Should -BeLike '*-L2-*'
    }
}

Describe 'Delegation depth (self-delegation, two-approval split, reachability)' {
    # --- 1. LOCAL SELF-DELEGATION ---
    It 'local plane: any permission (incl. privileged) self-delegates with no MSP request' {
        $t0 = @{ service='entra'; tier=0; level=0; plane='CP'; groupTag='Entra-ID-GA-L0' }
        (Test-PimSelfDelegationAllowed -Facets $t0 -Plane 'local').allowed | Should -BeTrue   # privileged is fine on local
        $r = Test-PimSelfDelegationAllowed -Facets @{ service='azure'; tier=1; level=3; plane='WDP'; groupTag='Azure-X' } -Plane 'local'
        $r.allowed | Should -BeTrue
    }
    It 'msp plane: self-delegation refused (customer pulls baseline; no self-grant)' {
        $r = Test-PimSelfDelegationAllowed -Facets @{ service='entra'; tier=2; level=5; groupTag='X' } -Plane 'msp'
        $r.allowed | Should -BeFalse
        $r.reason  | Should -BeLike '*msp*'
    }
    It 'super-admin is never locked out (even on msp plane / enforced key)' {
        (Test-PimSelfDelegationAllowed -Facets @{ tier=0; groupTag='Entra-ID-GA-L0' } -Plane 'msp' -IsSuperAdmin).allowed | Should -BeTrue
        (Test-PimSelfDelegationAllowed -Facets @{ tier=0; groupTag='locked' } -Plane 'local' -EnforcedTags @('locked') -IsSuperAdmin).allowed | Should -BeTrue
    }
    It 'Enforced baseline keys block a local self-override (opt-in, default off)' {
        $f = @{ service='entra'; tier=0; level=0; groupTag='Entra-ID-GA-L0' }
        (Test-PimSelfDelegationAllowed -Facets $f -Plane 'local' -EnforcedTags @('Entra-ID-GA-L0')).allowed | Should -BeFalse   # case-insensitive tag match
        (Test-PimSelfDelegationAllowed -Facets $f -Plane 'local' -EnforcedTags @()).allowed | Should -BeTrue                    # default: nothing enforced
    }
    It 'plane defaults to local; PIM_DelegationPlane=msp flips it' {
        (Get-PimDelegationPlane) | Should -Be 'local'
        try { $global:PIM_DelegationPlane = 'msp'; (Get-PimDelegationPlane) | Should -Be 'msp' } finally { $global:PIM_DelegationPlane = $null }
    }
    It 'New-PimSelfDelegationChange emits a normal assignment Create (not a side-door)' {
        $c = New-PimSelfDelegationChange -Requestor 'localit@contoso.com' -GroupTag 'Entra-ID-A-L1' -Allowed $true
        $c.ok | Should -BeTrue; $c.change.op | Should -Be 'Create'; $c.change.entity | Should -Be 'PIM-Assignments-Admins'
        $c.change.key | Should -Be 'localit@contoso.com|Entra-ID-A-L1'
        (New-PimSelfDelegationChange -Requestor 'x' -GroupTag 'y' -Allowed $false).ok | Should -BeFalse
    }

    # --- 2. THE TWO-APPROVAL SPLIT (engine-owned delegation vs Entra-native activation) ---
    It 'delegation approval (#1) keeps department-derived people + layered escalation' {
        $matrix = @(
            [pscustomobject]@{ workload='Defender'; scope='Servers'; approvers=@('serverteam@contoso.com'); escalateTo=@('secmgr@contoso.com') }
            [pscustomobject]@{ workload='Defender'; approvers=@('secserviceowner@contoso.com') }
        )
        $srv = @{ workload='Defender'; service='workload'; tier=1; level=3; plane='WDP'; scope='Servers' }
        $row = [pscustomobject]@{ GroupTag='Defender-Servers'; Owners='deptowner@contoso.com'; Workload='Defender'; Scope='Servers'; TierLevel='T1'; Level='L3'; Plane='WDP' }
        $plan = Get-PimDelegationApprovalPlan -Facets $srv -Row $row -Matrix $matrix
        $plan.kind | Should -Be 'delegation'; $plan.owned_by | Should -Be 'engine'
        @($plan.layers).Count | Should -Be 2
        $plan.primary | Should -Contain 'serverteam@contoso.com'
        $plan.primary | Should -Contain 'deptowner@contoso.com'   # layer-0 includes resource Owners
        $plan.escalation | Should -Contain 'secmgr@contoso.com'
    }
    It 'activation approval (#2) is PEOPLE-ONLY: departments resolved to owners, raw dept dropped' {
        $deptIdx = @{ 'finance' = 'finmgr@contoso.com|finlead@contoso.com' }
        # mix of: a person, a department token, a 'dept:' marker, and an unresolvable dept
        $r = Get-PimActivationApprovalPeople -Approvers @('person@contoso.com','Finance','dept:Finance','NoSuchDept') -DeptIndex $deptIdx
        $r.people | Should -Contain 'person@contoso.com'
        $r.people | Should -Contain 'finmgr@contoso.com'
        $r.people | Should -Contain 'finlead@contoso.com'
        $r.ok | Should -BeTrue
        $r.unresolved | Should -Contain 'NoSuchDept'   # cannot reach the Entra policy
        # a raw department name never survives as an approver in the policy set
        ($r.people -contains 'Finance') | Should -BeFalse
    }
    It "activation: '@Persona' tokens expand to people via SupportFunctions" {
        try {
            $global:PIM_SupportFunctions = @{ CISO=@('ciso@contoso.com') }
            $r = Get-PimActivationApprovalPeople -Approvers @('@CISO') -DeptIndex @{}
            $r.people | Should -Contain 'ciso@contoso.com'; $r.ok | Should -BeTrue
            # a persona pointing at a bare department still resolves through the dept index
            $global:PIM_SupportFunctions = @{ Owners=@('Finance') }
            $r2 = Get-PimActivationApprovalPeople -Approvers @('@Owners') -DeptIndex @{ 'finance'='finmgr@contoso.com' }
            $r2.people | Should -Contain 'finmgr@contoso.com'
        } finally { $global:PIM_SupportFunctions = $null }
    }
    It 'activation: empty / dept-only set -> ok=$false (engine must refuse the policy)' {
        $r = Get-PimActivationApprovalPeople -Approvers @('UnknownDept') -DeptIndex @{}
        $r.ok | Should -BeFalse; @($r.people).Count | Should -Be 0; $r.unresolved | Should -Contain 'UnknownDept'
    }
    It 'Test-PimLooksLikePerson: upn/objectid yes; bare dept / persona token no' {
        (Test-PimLooksLikePerson -Value 'a@b.com') | Should -BeTrue
        (Test-PimLooksLikePerson -Value '11111111-1111-1111-1111-111111111111') | Should -BeTrue
        (Test-PimLooksLikePerson -Value 'Finance') | Should -BeFalse
        (Test-PimLooksLikePerson -Value '@CISO') | Should -BeFalse
    }
    It 'approval-model summary keeps the two surfaces distinct (dept ok in #1, people-only in #2)' {
        $matrix = @([pscustomobject]@{ workload='Dataverse'; approvers=@('Finance') })   # approver expressed as a department
        $f = @{ workload='Dataverse'; service='workload'; tier=1; level=3; plane='WDP'; scope='' }
        $row = [pscustomobject]@{ GroupTag='Dataverse-A'; Owners='deptowner@contoso.com'; Workload='Dataverse'; Level='L3'; TierLevel='T1'; Plane='WDP' }
        $s = Get-PimApprovalModelSummary -Facets $f -Row $row -Matrix $matrix -DeptIndex @{ 'finance'='finmgr@contoso.com' }
        # #1 delegation: the department token is allowed to remain in the routing layer
        ($s.delegation.layers[0].approvers -contains 'Finance' -or $s.delegation.primary -contains 'Finance') | Should -BeTrue
        # #2 activation: resolved to people; the dept name is gone, the owner+dept-people remain
        $s.activation.people | Should -Contain 'finmgr@contoso.com'
        $s.activation.people | Should -Contain 'deptowner@contoso.com'
        ($s.activation.people -contains 'Finance') | Should -BeFalse
        $s.activation.ok | Should -BeTrue
    }

    # --- 3. REACHABILITY-BY-CLASSIFICATION (PAW detection is OPT-IN, default OFF) ---
    It 'DEFAULT (PAW detection OFF): NO PAW restriction -- every classification is whole-network' {
        # No $global:PIM_PawDetection set -> opt-in OFF -> nothing is confined to paw-only.
        (Test-PimPawDetectionEnabled) | Should -BeFalse
        (Resolve-PimReachability -Tier 0 -Plane 'CP'  -Level 0) | Should -Be 'whole-network'   # T0 NOT paw-only by default
        (Resolve-PimReachability -Tier 1 -Plane 'MP'  -Level 1) | Should -Be 'whole-network'   # T1/MP NOT limited by default
        (Resolve-PimReachability -Tier 1 -Plane 'WDP' -Level 3) | Should -Be 'whole-network'
        (Resolve-PimReachability -Tier 2 -Plane 'WDP' -Level 5) | Should -Be 'whole-network'
    }
    It 'OPT-IN ON ($global:PIM_PawDetection): reach classes apply -- T0 paw-only, T1/MP limited, T1/WDP L3+ whole-network' {
        try {
            $global:PIM_PawDetection = $true
            (Test-PimPawDetectionEnabled) | Should -BeTrue
            (Resolve-PimReachability -Tier 0 -Plane 'CP' -Level 0) | Should -Be 'paw-only'
            (Resolve-PimReachability -Tier 1 -Plane 'MP' -Level 1) | Should -Be 'limited'
            (Resolve-PimReachability -Tier 1 -Plane 'WDP' -Level 3) | Should -Be 'whole-network'
            (Resolve-PimReachability -Tier 1 -Plane 'WDP' -Level 2) | Should -Be 'whole-network'   # below L3 -> default whole-network
            (Resolve-PimReachability -Tier 2 -Plane 'WDP' -Level 5) | Should -Be 'whole-network'   # least privileged -> default
        } finally { $global:PIM_PawDetection = $null }
    }
    It 'EnforcePaw is honoured as a synonym for PawDetection' {
        try {
            $global:PIM_EnforcePaw = $true
            (Test-PimPawDetectionEnabled) | Should -BeTrue
            (Resolve-PimReachability -Tier 0 -Plane 'CP' -Level 0) | Should -Be 'paw-only'
        } finally { $global:PIM_EnforcePaw = $null }
    }
    It 'reach policy is configurable (override via PIM_ReachPolicy) -- only when detection is ON' {
        try {
            $global:PIM_PawDetection = $true
            $global:PIM_ReachPolicy = @(@{ tier=1; plane='WDP'; reach='limited' })
            (Resolve-PimReachability -Tier 1 -Plane 'WDP' -Level 4) | Should -Be 'limited'
        } finally { $global:PIM_ReachPolicy = $null; $global:PIM_PawDetection = $null }
    }
    It 'Get-PimReachabilityForGroup reads straight from a definition row (OFF default -> whole-network; ON -> paw-only)' {
        # Default OFF: even a T0 row is whole-network (no PAW restriction).
        (Get-PimReachabilityForGroup -Row ([pscustomobject]@{ GroupName='PIM-Entra-ID-GA-L0-T0-CP-ID'; Workload='Entra-ID'; Level='L0'; TierLevel='T0'; Plane='CP' })) | Should -Be 'whole-network'
        # Forced ON via -PawDetection: the T0 row resolves to paw-only.
        (Get-PimReachabilityForGroup -Row ([pscustomobject]@{ GroupName='PIM-Entra-ID-GA-L0-T0-CP-ID'; Workload='Entra-ID'; Level='L0'; TierLevel='T0'; Plane='CP' }) -PawDetection $true) | Should -Be 'paw-only'
        (Get-PimReachabilityForGroup -Row ([pscustomobject]@{ GroupName='PIM-Azure-Sub-Owner-L4-T1-WDP-RES'; Workload='Azure'; Level='L4'; TierLevel='T1'; Plane='WDP' }) -PawDetection $true) | Should -Be 'whole-network'
    }
    It 'Test-PimReachAllowed: OFF (default) never restricts; ON enforces the segment ordering; super-admin never locked out' {
        # DEFAULT OFF -> no restriction even for a whole-network device against paw-only work.
        (Test-PimReachAllowed -RequiredReach 'paw-only' -RequestReach 'whole-network') | Should -BeTrue
        # OPT-IN ON -> the ordering applies.
        (Test-PimReachAllowed -RequiredReach 'paw-only' -RequestReach 'paw-only'      -PawDetection $true) | Should -BeTrue
        (Test-PimReachAllowed -RequiredReach 'paw-only' -RequestReach 'whole-network' -PawDetection $true) | Should -BeFalse   # whole-network device can't reach a paw-only classification
        (Test-PimReachAllowed -RequiredReach 'whole-network' -RequestReach 'paw-only' -PawDetection $true) | Should -BeTrue    # paw segment can reach less-restricted work
        (Test-PimReachAllowed -RequiredReach 'limited' -RequestReach 'limited'        -PawDetection $true) | Should -BeTrue
        (Test-PimReachAllowed -RequiredReach 'limited' -RequestReach 'whole-network'  -PawDetection $true) | Should -BeFalse
        # SUPER-ADMIN: never locked out, even with detection ON and a whole-network device against paw-only work.
        (Test-PimReachAllowed -RequiredReach 'paw-only' -RequestReach 'whole-network' -PawDetection $true -IsSuperAdmin) | Should -BeTrue
    }
}

Describe 'Permission-wizard auto-derivation (reversed create flow)' {
    It 'entra single privileged role -> service, L0/T0/CP/ID' {
        $d = Get-PimEntraDerivation -Roles @('Global Administrator')
        $d.kind | Should -Be 'permission-service'; $d.level | Should -Be 0; $d.tier | Should -Be 0; $d.plane | Should -Be 'CP'
        $d.groupName | Should -BeLike 'PIM-Entra-ID-*-L0-T0-CP-ID'
    }
    It 'entra single ordinary role -> L1; with AU scope -> L2 + AU segment' {
        (Get-PimEntraDerivation -Roles @('User Administrator')).level | Should -Be 1
        $au = Get-PimEntraDerivation -Roles @('User Administrator') -AuScope 'Finance'
        $au.level | Should -Be 2; $au.au | Should -Be 'Finance'; $au.groupName | Should -BeLike '*-AU-Finance-*'
    }
    It 'AU step only when ALL selected roles are AU-scopable' {
        (Test-PimRolesAuScopable -Roles @('User Administrator','Groups Administrator')) | Should -BeTrue
        (Test-PimRolesAuScopable -Roles @('User Administrator','Security Reader')) | Should -BeFalse
        # a non-AU-scopable role ignores AuScope -> stays L1
        (Get-PimEntraDerivation -Roles @('Security Reader') -AuScope 'Finance').level | Should -Be 1
    }
    It 'entra multiple roles -> bundle; any privileged -> L0' {
        $d = Get-PimEntraDerivation -Roles @('Global Administrator','User Administrator')
        $d.kind | Should -Be 'permission-bundle'; $d.level | Should -Be 0
    }
    It 'azure tenant root -> L0/T0/CP; sub LZ -> L1/T1/WDP' {
        $root = Get-PimAzureDerivation -ScopeType tenantRoot -Roles @('Owner') -ScopeName 'Tenant Root'
        $root.level | Should -Be 0; $root.tier | Should -Be 0; $root.plane | Should -Be 'CP'
        $lz = Get-PimAzureDerivation -ScopeType subscription -Roles @('Contributor') -ScopePath '/subscriptions/abc' -ScopeName 'lz-corp-prod'
        $lz.level | Should -Be 1; $lz.tier | Should -Be 1; $lz.plane | Should -Be 'WDP'
    }
    It 'azure plane heuristics + depth + data domain' {
        (Get-PimAzureDerivation -ScopeType managementGroup -Roles @('Reader') -ScopeName 'platform-management' -ManagementGroupDepth 1).plane | Should -Be 'MP'
        (Get-PimAzureDerivation -ScopeType resourceGroup -Roles @('Contributor') -ScopeName 'rg-app').level | Should -Be 2
        (Get-PimAzureDerivation -ScopeType resource -Roles @('Reader') -ScopeName 'sql-data-prod').domain | Should -Be 'DAT'
        $b = Get-PimAzureDerivation -ScopeType subscription -Roles @('Owner','Contributor') -ScopeName 'lz-x'
        $b.kind | Should -Be 'permission-bundle'
    }
    It 'workload derivation: defender single -> service, T1/WDP' {
        $d = Get-PimWorkloadDerivation -Workload 'Defender' -Roles @('Security Operator')
        $d.kind | Should -Be 'permission-service'; $d.tier | Should -Be 1; $d.plane | Should -Be 'WDP'
        $d.groupName | Should -BeLike 'PIM-Defender-*-T1-WDP-*'
    }
    It 'unified dispatch (Get-PimWizardDerivation) routes per target' {
        (Get-PimWizardDerivation -Target entra -Roles @('Global Administrator')).target | Should -Be 'entra'
        $az = Get-PimWizardDerivation -Target azure -Roles @('Owner') -ScopeType tenantRoot -ScopeName 'Tenant Root'
        $az.target | Should -Be 'azure'; $az.tier | Should -Be 0
        (Get-PimWizardDerivation -Target workload -Roles @('Security Operator') -Workload 'Defender').target | Should -Be 'workload'
        # parity: dispatch == direct call for the same inputs
        (Get-PimWizardDerivation -Target entra -Roles @('User Administrator') -AuScope 'Finance').groupName |
            Should -Be (Get-PimEntraDerivation -Roles @('User Administrator') -AuScope 'Finance').groupName
    }
    It 'unified dispatch validates target + missing required source' {
        { Get-PimWizardDerivation -Target azure -Roles @('Owner') } | Should -Throw   # ScopeType required
        { Get-PimWizardDerivation -Target workload -Roles @('X') } | Should -Throw     # Workload required
    }
    It 'admin target: admin-type PREFIX + Admin-{Initial} + environment SUFFIX (lower-cased)' {
        # internal Entra -> no prefix, -id suffix; rendered name is lower-cased
        $a = Get-PimWizardDerivation -Target admin -Owner 'JDO' -AdminType 'internal-adminuser' -Environment 'entra'
        $a.target | Should -Be 'admin'; $a.userName | Should -Be 'admin-jdo-id'; $a.prefix | Should -Be ''; $a.suffix | Should -Be '-ID'
        # external-adminuser AD -> x- prefix, -ad suffix (suffix is environment-driven)
        (Get-PimWizardDerivation -Target admin -Owner 'VND' -AdminType 'external-adminuser' -Environment 'ad').userName | Should -Be 'x-admin-vnd-ad'
        # external-guest, high-priv -> NO prefix (default) + L0-T0 markers
        $g = Get-PimWizardDerivation -Target admin -Owner 'GST' -AdminType 'external-guest' -Environment 'entra' -HighPriv
        $g.userName | Should -Be 'admin-gst-l0-t0-id'; $g.highPriv | Should -BeTrue
        # parity with the direct helper
        (Get-PimWizardDerivation -Target admin -Owner 'JDO').userName | Should -Be (Get-PimAdminDerivation -Owner 'JDO').userName
        # Owner is required for the admin target
        { Get-PimWizardDerivation -Target admin } | Should -Throw
    }
}

Describe 'Lifecycle calendar (expirations, escalation, auto-renew)' {
    BeforeAll { $script:Now = [datetime]::Parse('2026-06-13T12:00:00Z').ToUniversalTime() }
    It 'resolves expiry from candidate fields + days left' {
        $i = [pscustomobject]@{ UserName='a'; OffboardDate='2026-06-20T00:00:00Z' }
        (Get-PimDaysLeft -Item $i -NowUtc $Now) | Should -Be 6
        ($null -eq (Get-PimDaysLeft -Item ([pscustomobject]@{ UserName='b' }) -NowUtc $Now)) | Should -BeTrue
    }
    It 'upcoming expirations: horizon filter + soonest-first' {
        $items = @(
            [pscustomobject]@{ UserName='soon'; ExpiresUtc='2026-06-15T00:00:00Z' }   # 1 day
            [pscustomobject]@{ UserName='far';  ExpiresUtc='2026-09-01T00:00:00Z' }   # >30
            [pscustomobject]@{ UserName='mid';  ExpiresUtc='2026-06-25T00:00:00Z' }   # 11 days
        )
        $up = @(Get-PimUpcomingExpirations -Items $items -NowUtc $Now -HorizonDays 30)
        $up.Count | Should -Be 2
        "$($up[0].item.UserName)" | Should -Be 'soon'   # soonest first
    }
    It 'escalation: new stage fires; same stage waits for the reminder interval' {
        # DaysLeft 10 -> crossed 30 + 14, most-urgent = 14
        (Get-PimDueEscalation -DaysLeft 10 -NowUtc $Now -LastStageAtDays $null).stage | Should -Be 14
        # already notified at stage 14, 1 day ago -> not due (interval 3)
        ($null -eq (Get-PimDueEscalation -DaysLeft 10 -NowUtc $Now -LastStageAtDays 14 -LastNotifiedUtc $Now.AddDays(-1).ToString('o'))) | Should -BeTrue
        # 4 days since last notify -> reminder due
        (Get-PimDueEscalation -DaysLeft 10 -NowUtc $Now -LastStageAtDays 14 -LastNotifiedUtc $Now.AddDays(-4).ToString('o')).isReminder | Should -BeTrue
        # before any stage (DaysLeft 45) -> nothing due
        ($null -eq (Get-PimDueEscalation -DaysLeft 45 -NowUtc $Now -LastStageAtDays $null)) | Should -BeTrue
        # urgent: DaysLeft 1 -> stage 1, recipients include admin
        (Get-PimDueEscalation -DaysLeft 1 -NowUtc $Now -LastStageAtDays $null).recipients | Should -Contain 'admin'
    }
    It 'auto-renew only AutoExtend items within the window -> renewal change' {
        $r = Get-PimAutoRenewal -Item ([pscustomobject]@{ UserName='c'; ExpiresUtc='2026-06-17T00:00:00Z'; AutoExtend='true' }) -NowUtc $Now -RenewWithinDays 7 -ExtendDays 90
        $r.renew | Should -BeTrue
        ([datetime]$r.newExpiryUtc).ToUniversalTime() -gt $Now | Should -BeTrue
        ($null -eq (Get-PimAutoRenewal -Item ([pscustomobject]@{ ExpiresUtc='2026-06-17T00:00:00Z'; AutoExtend='false' }) -NowUtc $Now)) | Should -BeTrue   # not AutoExtend
        ($null -eq (Get-PimAutoRenewal -Item ([pscustomobject]@{ ExpiresUtc='2026-09-01T00:00:00Z'; AutoExtend='true' }) -NowUtc $Now -RenewWithinDays 7)) | Should -BeTrue   # too far
        (New-PimRenewalChange -Entity 'Account-Definitions-Admins' -Key 'c' -DateField 'ExpiresUtc' -NewExpiryUtc $r.newExpiryUtc).op | Should -Be 'Update'
    }
}

Describe 'Lifecycle / Governance (§13: scheduled creation+TAP, calendar, break-glass, access-review)' {
    BeforeAll { $script:Now = [datetime]::Parse('2026-06-14T12:00:00Z').ToUniversalTime() }

    It 'scheduled creation: future provision waits; due provision creates; TAP lead window vs deferred' {
        (Get-PimScheduledCreationDue -NowUtc $Now -ProvisionUtc $Now.AddDays(5)).createAccount | Should -BeFalse
        (Get-PimScheduledCreationDue -NowUtc $Now -ProvisionUtc $Now.AddHours(-1)).createAccount | Should -BeTrue
        (Get-PimScheduledCreationDue -NowUtc $Now -ProvisionUtc $Now.AddHours(-1) -TapStartUtc $Now.AddHours(2) -CreateTap $true -TapLeadHours 24).tapDue | Should -BeTrue
        (Get-PimScheduledCreationDue -NowUtc $Now -ProvisionUtc $Now.AddHours(-1) -TapStartUtc $Now.AddDays(10) -CreateTap $true -TapLeadHours 24).tapDue | Should -BeFalse
    }
    It 'scheduled creation: row scan resolves date expressions + skips already-provisioned' {
        $rows = @(
            [pscustomobject]@{ UserName='svc-now';  ProvisionDate='2026-06-13'; CreateTAP='true'; TAPStartDate='2026-06-14' }
            [pscustomobject]@{ UserName='svc-done'; ProvisionDate='2026-06-13'; Provisioned='true' }
            [pscustomobject]@{ UserName='svc-fut';  ProvisionDate='2026-06-20' }
        )
        $due = @(Get-PimDueScheduledCreations -Rows $rows -NowUtc $Now)
        @($due.row.UserName) | Should -Contain 'svc-now'
        @($due.row.UserName) | Should -Not -Contain 'svc-done'
        @($due.row.UserName) | Should -Not -Contain 'svc-fut'
    }
    It 'lifecycle calendar: folds upcoming + escalation + auto-renew into one plan' {
        $items = @(
            [pscustomobject]@{ UserName='a@x'; ExpiresUtc=$Now.AddDays(3).ToString('o'); AutoExtend='false' }
            [pscustomobject]@{ UserName='b@x'; ExpiresUtc=$Now.AddDays(5).ToString('o'); AutoExtend='true' }
            [pscustomobject]@{ UserName='c@x'; ExpiresUtc=$Now.AddDays(200).ToString('o') }
        )
        $cal = Build-PimLifecycleCalendar -Items $items -NowUtc $Now -HorizonDays 30 -RenewWithinDays 7 -ExtendDays 90
        @($cal.upcoming).Count | Should -Be 2
        @($cal.escalations.key) | Should -Contain 'a@x'
        @($cal.renewals).Count | Should -Be 1
        $cal.renewals[0].key | Should -Be 'b@x'
        @(Get-PimLifecycleRenewalChanges -Calendar $cal -Entity 'Account-Definitions-Admins' -DateField 'ExpiresUtc')[0].op | Should -Be 'Update'
    }
    It 'break-glass: constant-time hash verify + 5/15min lockout + TTL clamp' {
        $h = Get-PimSha256Hex -Text 'pass phrase'
        (Test-PimPasscodeHash -Passcode 'pass phrase' -ExpectedHashHex $h) | Should -BeTrue
        (Test-PimPasscodeHash -Passcode 'nope' -ExpectedHashHex $h) | Should -BeFalse
        (Get-PimEmergencyTtlHours -RequestedHours $null) | Should -Be 4
        (Get-PimEmergencyTtlHours -RequestedHours 99)    | Should -Be 24
        $fails = @($Now.AddMinutes(-1),$Now.AddMinutes(-2),$Now.AddMinutes(-3),$Now.AddMinutes(-4),$Now.AddMinutes(-5))
        (Test-PimLockout -Failures $fails -NowUtc $Now).locked | Should -BeTrue
        (Resolve-PimEmergencyVerification -Passcode 'pass phrase' -ExpectedHashHex $h -NowUtc $Now -Failures $fails).ok | Should -BeFalse  # locked even if correct
    }
    It 'access-review: AutoExtend skips owner gate; others need owner approval; Deny suppresses re-add' {
        (Get-PimAccessReviewDecision -Item ([pscustomobject]@{ UserName='s'; AutoExtend='true' })).action | Should -Be 'auto-extend'
        $g = Get-PimAccessReviewDecision -Item ([pscustomobject]@{ UserName='u'; Owners='o1@x|o2@x' })
        $g.action | Should -Be 'owner-approval'
        @($g.reviewers) | Should -Contain 'o2@x'
        $deny = New-PimReviewFeedbackRecord -Key 'u' -Outcome 'Deny' -NowUtc $Now
        (Test-PimReviewSuppressesReAdd -Key 'u' -Feedback @($deny)) | Should -BeTrue
        $appr = New-PimReviewFeedbackRecord -Key 'u' -Outcome 'Approve' -NowUtc $Now.AddMinutes(1)
        (Test-PimReviewSuppressesReAdd -Key 'u' -Feedback @($deny,$appr)) | Should -BeFalse   # latest wins
    }
}

Describe 'Change queue + full/delta run modes' {
    It 'Create then Remove on the same key cancels out' {
        $q = @(
            New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k1' -Op Create -Payload @{ v=1 } -EnqueuedUtc '2026-06-13T10:00:00Z'
            New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k1' -Op Remove -EnqueuedUtc '2026-06-13T10:01:00Z'
        )
        @(Get-PimQueueNetChanges -Queue $q).Count | Should -Be 0
    }
    It 'Create then Update folds to Create with the latest payload' {
        $q = @(
            New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k2' -Op Create -Payload @{ v=1 } -EnqueuedUtc '2026-06-13T10:00:00Z'
            New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k2' -Op Update -Payload @{ v=2 } -EnqueuedUtc '2026-06-13T10:05:00Z'
        )
        $net = @(Get-PimQueueNetChanges -Queue $q)
        $net.Count | Should -Be 1; $net[0].op | Should -Be 'Create'; $net[0].payload.v | Should -Be 2
    }
    It 'Update then Remove folds to Remove' {
        $q = @(
            New-PimChange -Entity 'PIM-Assignments-Admins' -Key 'a1' -Op Update -EnqueuedUtc '2026-06-13T10:00:00Z'
            New-PimChange -Entity 'PIM-Assignments-Admins' -Key 'a1' -Op Remove -EnqueuedUtc '2026-06-13T10:09:00Z'
        )
        $net = @(Get-PimQueueNetChanges -Queue $q)
        $net.Count | Should -Be 1; $net[0].op | Should -Be 'Remove'
    }
    It 'apply plan: definitions before assignments; removes after creates' {
        $q = @(
            New-PimChange -Entity 'PIM-Assignments-Admins' -Key 'a' -Op Create -EnqueuedUtc '2026-06-13T10:00:00Z'
            New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'd' -Op Create -EnqueuedUtc '2026-06-13T10:00:00Z'
            New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'x' -Op Remove -EnqueuedUtc '2026-06-13T10:00:00Z'
        )
        $plan = @(Get-PimQueueApplyPlan -Queue $q)
        "$($plan[0].entity)" | Should -BeLike '*Definitions*'   # definition create first
        $plan[0].op | Should -Be 'Create'
        $plan[-1].op | Should -Be 'Remove'                       # removes last
    }
    It 'Delta run = queue net plan; Full run = upsert all desired' {
        $q = @( New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k' -Op Create -EnqueuedUtc '2026-06-13T10:00:00Z' )
        @(Get-PimRunSet -Mode Delta -Queue $q).Count | Should -Be 1
        $desired = @(
            [pscustomobject]@{ entity='PIM-Definitions-Tasks'; key='a'; payload=@{} }
            [pscustomobject]@{ entity='PIM-Definitions-Tasks'; key='b'; payload=@{} }
        )
        $full = @(Get-PimRunSet -Mode Full -DesiredItems $desired)
        $full.Count | Should -Be 2; ($full | Where-Object op -ne 'Update').Count | Should -Be 0
    }
    It 'persistence: enqueue -> read -> clear round-trip' {
        $qf = Join-Path ([System.IO.Path]::GetTempPath()) ("pimq-" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.json')
        try {
            $c1 = New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k1' -Op Create
            Add-PimChangeToQueue -QueueFile $qf -Change $c1 | Should -Be 1
            Add-PimChangeToQueue -QueueFile $qf -Change (New-PimChange -Entity 'PIM-Definitions-Tasks' -Key 'k2' -Op Create) | Should -Be 2
            @(Read-PimChangeQueue -QueueFile $qf).Count | Should -Be 2
            Clear-PimChangeQueue -QueueFile $qf -KeepIds @("$($c1.id)") | Should -Be 1
            @(Read-PimChangeQueue -QueueFile $qf).Count | Should -Be 1
        } finally { Remove-Item -LiteralPath $qf -Force -ErrorAction SilentlyContinue }
    }
    It 'queue SQL DDL is emitted (Phase-6 readiness)' {
        (Get-PimChangeQueueDdl) | Should -BeLike '*CREATE TABLE pim.ChangeQueue*'
    }
}

Describe 'Azure auto-discovery + reconcile' {
    It 'stable key is move-invariant for a subscription' {
        (Get-PimAzureStableKey -ScopePath '/subscriptions/abc-123') | Should -Be 'sub:abc-123'
        # same sub, different MG parent in the path component is irrelevant -- key is the GUID
        (Get-PimAzureStableKey -ScopePath '/subscriptions/abc-123/resourceGroups/rg1') | Should -Be 'sub:abc-123/rg:rg1'
        (Get-PimAzureStableKey -ScopePath '/providers/Microsoft.Management/managementGroups/lz-corp') | Should -Be 'mg:lz-corp'
    }
    It 'new scope matching an auto-import rule -> create(autoImport=true)' {
        $disc = @([pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/new-1'; scopeName='lz-app-prod'; mgmtGroupDepth=1 })
        $rules = @(@{ scopeTypes=@('subscription'); minLevel=0; maxLevel=4 })
        $plan = Get-PimAzureReconcilePlan -Discovered $disc -Existing @() -AutoImportRules $rules
        @($plan.create).Count | Should -Be 1
        $plan.create[0].autoImport | Should -BeTrue
        "$($plan.create[0].expected.groupName)" | Should -BeLike 'PIM-Azure-LzAppProd-L1-T1-WDP-*'
    }
    It 'new scope with no matching rule -> create(autoImport=false) (pending decision)' {
        $disc = @([pscustomobject]@{ scopeType='managementGroup'; scopePath='/providers/Microsoft.Management/managementGroups/platform'; scopeName='platform'; mgmtGroupDepth=1 })
        $plan = Get-PimAzureReconcilePlan -Discovered $disc -Existing @() -AutoImportRules @(@{ scopeTypes=@('subscription') })
        $plan.create[0].autoImport | Should -BeFalse
    }
    It 'moved/renamed scope (same stable key, new expected name) -> rename' {
        $disc = @([pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/s1'; scopeName='lz-corp-prod'; mgmtGroupDepth=1 })
        $exist = @([pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/s1'; scopeName='old-name'; groupName='PIM-Azure-OldName-L1-T1-WDP-RES' })
        $plan = Get-PimAzureReconcilePlan -Discovered $disc -Existing $exist
        @($plan.rename).Count | Should -Be 1
        "$($plan.rename[0].from)" | Should -Be 'PIM-Azure-OldName-L1-T1-WDP-RES'
        "$($plan.rename[0].to)" | Should -BeLike 'PIM-Azure-LzCorpProd-*'
    }
    It 'definition whose scope is gone -> orphan; unchanged stays unchanged' {
        $disc = @([pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/keep'; scopeName='lz-keep'; mgmtGroupDepth=1 })
        $exp = Get-PimAzureScopeDerivation -ScopeType subscription -ScopePath '/subscriptions/keep' -ScopeName 'lz-keep'
        $exist = @(
            [pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/keep'; scopeName='lz-keep'; groupName="$($exp.groupName)" }
            [pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/gone'; scopeName='dead'; groupName='PIM-Azure-Dead-L1-T1-WDP-RES' }
        )
        $plan = Get-PimAzureReconcilePlan -Discovered $disc -Existing $exist
        @($plan.orphan).Count | Should -Be 1; "$($plan.orphan[0].groupName)" | Should -Be 'PIM-Azure-Dead-L1-T1-WDP-RES'
        @($plan.unchanged).Count | Should -Be 1
    }
    It 'reconcile plan -> change-queue records (auto-create + rename; orphans gated)' {
        $disc = @(
            [pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/n1'; scopeName='lz-new'; mgmtGroupDepth=1 }
            [pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/m1'; scopeName='lz-moved'; mgmtGroupDepth=1 }
        )
        $exist = @(
            [pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/m1'; scopeName='old'; groupName='PIM-Azure-Old-L1-T1-WDP-RES' }
            [pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/dead'; scopeName='dead'; groupName='PIM-Azure-Dead-L1-T1-WDP-RES' }
        )
        $plan = Get-PimAzureReconcilePlan -Discovered $disc -Existing $exist -AutoImportRules @(@{ scopeTypes=@('subscription'); maxLevel=4 })
        $changes = @(ConvertTo-PimReconcileQueueChanges -Plan $plan)
        @($changes | Where-Object op -eq 'Create').Count | Should -Be 1   # lz-new auto-created
        @($changes | Where-Object op -eq 'Update').Count | Should -Be 1   # m1 renamed
        @($changes | Where-Object op -eq 'Remove').Count | Should -Be 0   # orphan not removed without -IncludeOrphanRemovals
        $withOrphans = @(ConvertTo-PimReconcileQueueChanges -Plan $plan -IncludeOrphanRemovals)
        @($withOrphans | Where-Object op -eq 'Remove').Count | Should -Be 1
    }
}

Describe 'Discovery -- Power BI / service-roles / auto-map / delta (REQUIREMENTS §8)' {
    Context 'Power BI workspace derivation + reconcile' {
        It 'derives the WDP/DAT permission-group container name for a workspace' {
            $d = Get-PimPowerBiWorkspaceDerivation -WorkspaceName 'Finance Reporting' -WorkspaceId 'ws-1'
            $d.tier   | Should -Be 1
            $d.plane  | Should -Be 'WDP'
            $d.domain | Should -Be 'DAT'
            "$($d.groupName)" | Should -BeLike 'PIM-PowerBI-WS-FinanceReporting-L3-T1-WDP-DAT'
            $d.workspaceId | Should -Be 'ws-1'
        }
        It 'stable key is the workspace id (rename-invariant)' {
            (Get-PimPowerBiStableKey -WorkspaceId 'ABC-123') | Should -Be 'pbiws:abc-123'
        }
        It 'new workspace -> create; default is autoImport=false (propose, never auto-map)' {
            $disc = @([pscustomobject]@{ workspaceId='ws-new'; workspaceName='Marketing' })
            $plan = Get-PimPowerBiReconcilePlan -Discovered $disc -Existing @()
            @($plan.create).Count | Should -Be 1
            $plan.create[0].autoImport | Should -BeFalse
            "$($plan.create[0].expected.groupName)" | Should -BeLike 'PIM-PowerBI-WS-Marketing-*'
        }
        It '-AutoImport flips create candidates to autoImport=true' {
            $disc = @([pscustomobject]@{ workspaceId='ws-new'; workspaceName='Marketing' })
            $plan = Get-PimPowerBiReconcilePlan -Discovered $disc -Existing @() -AutoImport
            $plan.create[0].autoImport | Should -BeTrue
        }
        It 'renamed workspace (same id, new expected name) -> rename, not orphan+dup' {
            $disc  = @([pscustomobject]@{ workspaceId='ws-1'; workspaceName='Finance Reporting' })
            $exist = @([pscustomobject]@{ workspaceId='ws-1'; workspaceName='oldname'; groupName='PIM-PowerBI-WS-Oldname-L3-T1-WDP-DAT' })
            $plan = Get-PimPowerBiReconcilePlan -Discovered $disc -Existing $exist
            @($plan.rename).Count | Should -Be 1
            "$($plan.rename[0].to)" | Should -BeLike 'PIM-PowerBI-WS-FinanceReporting-*'
            @($plan.create).Count  | Should -Be 0
            @($plan.orphan).Count  | Should -Be 0
        }
        It 'workspace gone -> orphan; unchanged stays unchanged' {
            $exp = Get-PimPowerBiWorkspaceDerivation -WorkspaceName 'keep' -WorkspaceId 'ws-keep'
            $disc  = @([pscustomobject]@{ workspaceId='ws-keep'; workspaceName='keep' })
            $exist = @(
                [pscustomobject]@{ workspaceId='ws-keep'; workspaceName='keep'; groupName="$($exp.groupName)" }
                [pscustomobject]@{ workspaceId='ws-dead'; workspaceName='dead'; groupName='PIM-PowerBI-WS-Dead-L3-T1-WDP-DAT' }
            )
            $plan = Get-PimPowerBiReconcilePlan -Discovered $disc -Existing $exist
            @($plan.orphan).Count | Should -Be 1; "$($plan.orphan[0].groupName)" | Should -Be 'PIM-PowerBI-WS-Dead-L3-T1-WDP-DAT'
            @($plan.unchanged).Count | Should -Be 1
        }
        It 'reconcile plan -> change-queue records (auto-create + rename; orphans gated)' {
            $disc = @(
                [pscustomobject]@{ workspaceId='ws-new'; workspaceName='new-ws' }
                [pscustomobject]@{ workspaceId='ws-mv';  workspaceName='moved-ws' }
            )
            $exist = @(
                [pscustomobject]@{ workspaceId='ws-mv';   workspaceName='old';  groupName='PIM-PowerBI-WS-Old-L3-T1-WDP-DAT' }
                [pscustomobject]@{ workspaceId='ws-dead'; workspaceName='dead'; groupName='PIM-PowerBI-WS-Dead-L3-T1-WDP-DAT' }
            )
            $plan = Get-PimPowerBiReconcilePlan -Discovered $disc -Existing $exist -AutoImport
            $changes = @(ConvertTo-PimPowerBiQueueChanges -Plan $plan)
            @($changes | Where-Object op -eq 'Create').Count | Should -Be 1   # ws-new auto-created
            @($changes | Where-Object op -eq 'Update').Count | Should -Be 1   # ws-mv renamed
            @($changes | Where-Object op -eq 'Remove').Count | Should -Be 0   # orphan not removed without the flag
            @(ConvertTo-PimPowerBiQueueChanges -Plan $plan -IncludeOrphanRemovals | Where-Object op -eq 'Remove').Count | Should -Be 1
        }
    }

    Context 'Service / role catalog delta (new built-in roles)' {
        It 'surfaces only roles not yet in the catalog; second run with the same known set surfaces none' {
            $live  = @([pscustomobject]@{ id='r1'; name='Global Administrator' }, [pscustomobject]@{ id='r2'; name='User Administrator' })
            $known = @([pscustomobject]@{ id='r1'; name='Global Administrator' })
            $delta = @(Get-PimRoleCatalogDelta -Service 'entra' -Live $live -Known $known)
            $delta.Count | Should -Be 1; $delta[0].roleName | Should -Be 'User Administrator'
            # roll forward: known now includes both -> nothing new
            @(Get-PimRoleCatalogDelta -Service 'entra' -Live $live -Known $live).Count | Should -Be 0
        }
        It 'de-dups within the live set' {
            $live = @([pscustomobject]@{ id='r1'; name='X' }, [pscustomobject]@{ id='r1'; name='X' })
            @(Get-PimRoleCatalogDelta -Service 'entra' -Live $live -Known @()).Count | Should -Be 1
        }
    }


    Context 'Department import from Entra by naming convention (REQUIREMENTS §8/§11)' {
        It 'parses the pattern into the startswith() prefix' {
            (ConvertTo-PimDepartmentImportPrefix 'ORG-*')  | Should -Be 'ORG-'
            (ConvertTo-PimDepartmentImportPrefix 'DEPT-')  | Should -Be 'DEPT-'   # no wildcard -> whole literal
            (ConvertTo-PimDepartmentImportPrefix '*')      | Should -Be ''
            (ConvertTo-PimDepartmentImportPrefix '')       | Should -Be ''
        }
        It 'matches a group name against the pattern (prefix, case-insensitive)' {
            (Test-PimDepartmentImportMatch -Name 'ORG-Finance' -Pattern 'ORG-*') | Should -BeTrue
            (Test-PimDepartmentImportMatch -Name 'org-it'      -Pattern 'ORG-*') | Should -BeTrue
            (Test-PimDepartmentImportMatch -Name 'PIM-Helpdesk' -Pattern 'ORG-*') | Should -BeFalse
            (Test-PimDepartmentImportMatch -Name 'anything'    -Pattern '*')      | Should -BeTrue
            (Test-PimDepartmentImportMatch -Name ''            -Pattern 'ORG-*')  | Should -BeFalse
        }
        It 'derives the department name by stripping the pattern prefix' {
            (ConvertTo-PimDepartmentName -GroupName 'ORG-Finance' -Pattern 'ORG-*') | Should -Be 'Finance'
            (ConvertTo-PimDepartmentName -GroupName 'NoPrefix'    -Pattern 'ORG-*') | Should -Be 'NoPrefix'
        }
        It 'maps each matched group to a department record with owners + source linkage' {
            $disc = @(
                [pscustomobject]@{ id='g1'; displayName='ORG-Finance'; owners=@('a@x.com','b@x.com') }
                [pscustomobject]@{ id='g2'; displayName='ORG-IT';      owners=@('it@x.com') }
            )
            $plan = Get-PimEntraDepartmentImportPlan -Discovered $disc -Existing @() -Pattern 'ORG-*'
            @($plan.created).Count | Should -Be 2
            @($plan.departments).Count | Should -Be 2
            $fin = $plan.departments | Where-Object { $_.name -eq 'Finance' }
            @($fin.owners).Count | Should -Be 2
            "$($fin.source)"   | Should -Be 'entra-import'
            "$($fin.sourceId)" | Should -Be 'g1'
        }
        It 'idempotent upsert -- a second import with identical data SKIPS (no duplicates, no churn)' {
            $disc = @([pscustomobject]@{ id='g1'; displayName='ORG-Finance'; owners=@('a@x.com') })
            $first = Get-PimEntraDepartmentImportPlan -Discovered $disc -Existing @() -Pattern 'ORG-*'
            @($first.created).Count | Should -Be 1
            $second = Get-PimEntraDepartmentImportPlan -Discovered $disc -Existing $first.departments -Pattern 'ORG-*'
            @($second.created).Count | Should -Be 0
            @($second.updated).Count | Should -Be 0
            @($second.skipped).Count | Should -Be 1
            @($second.departments).Count | Should -Be 1   # not duplicated
        }
        It 're-import with changed owners UPDATES in place (no duplicate)' {
            $first = Get-PimEntraDepartmentImportPlan -Discovered @([pscustomobject]@{ id='g1'; displayName='ORG-Finance'; owners=@('a@x.com') }) -Existing @() -Pattern 'ORG-*'
            $disc2 = @([pscustomobject]@{ id='g1'; displayName='ORG-Finance'; owners=@('a@x.com','c@x.com') })
            $second = Get-PimEntraDepartmentImportPlan -Discovered $disc2 -Existing $first.departments -Pattern 'ORG-*'
            @($second.updated).Count | Should -Be 1
            @($second.departments).Count | Should -Be 1
            @(($second.departments | Where-Object { $_.name -eq 'Finance' }).owners).Count | Should -Be 2
        }
        It 'preserves a manually-added department (import never deletes it)' {
            $existing = @([pscustomobject]@{ name='HandMade'; owners=@('owner@x.com'); contact='c'; notes='n'; source=''; sourceId='' })
            $disc = @([pscustomobject]@{ id='g1'; displayName='ORG-Finance'; owners=@('a@x.com') })
            $plan = Get-PimEntraDepartmentImportPlan -Discovered $disc -Existing $existing -Pattern 'ORG-*'
            @($plan.created).Count | Should -Be 1
            @($plan.departments).Count | Should -Be 2
            $manual = $plan.departments | Where-Object { $_.name -eq 'HandMade' }
            $manual | Should -Not -BeNullOrEmpty
            "$($manual.owners)" | Should -Match 'owner@x.com'
        }

        # ----- ROOT-CAUSE regression: the LIVE fetcher must NOT combine -------
        # $count=true with $expand (Graph 400s) -- the old single call did, so it
        # always returned @() and ORG-* groups never imported. We now list groups
        # (advanced query: $count + eventual, NO $expand) then pull owners per group.
        Context 'live group fetch (Get-PimLiveEntraDepartmentGroups) -- regression for the silent-empty bug' {
            BeforeEach {
                $script:CapturedPaths = New-Object System.Collections.Generic.List[string]
            }
            It 'returns the operator''s ORG-* groups with owners resolved (two-phase fetch)' {
                # Mock Graph: phase-1 list returns 2 ORG groups (id+displayName only),
                # phase-2 per-group owners come back from /groups/{id}/owners.
                Mock -CommandName Invoke-PimGraph -ModuleName PIM-Functions -MockWith {
                    param($Method='GET',$Path,$Body,[switch]$All,[switch]$Beta,$Headers=@{})
                    $script:CapturedPaths.Add("$Path")
                    if ($Path -match '/groups\?\$filter=startswith') {
                        if ("$($Headers['ConsistencyLevel'])" -ne 'eventual') { throw 'startswith requires ConsistencyLevel: eventual' }
                        if ("$Path" -match '\$expand') { throw "Graph 400: 'count' is not currently supported with 'expand'." }
                        return @(
                            [pscustomobject]@{ id='g1'; displayName='ORG-Finance' }
                            [pscustomobject]@{ id='g2'; displayName='ORG-IT' }
                        )
                    }
                    if ($Path -match '/groups/g1/owners') { return @([pscustomobject]@{ id='u1'; userPrincipalName='fin1@x.com' }, [pscustomobject]@{ id='u2'; userPrincipalName='fin2@x.com' }) }
                    if ($Path -match '/groups/g2/owners') { return @([pscustomobject]@{ id='u3'; userPrincipalName='it1@x.com' }) }
                    return @()
                }
                $groups = @(Get-PimLiveEntraDepartmentGroups -Pattern 'ORG-*')
                @($groups).Count | Should -Be 2
                ($groups | Where-Object { $_.displayName -eq 'ORG-Finance' }).owners.Count | Should -Be 2
                ($groups | Where-Object { $_.displayName -eq 'ORG-IT' }).owners | Should -Contain 'it1@x.com'
            }
            It 'NEVER combines $count=true with $expand on the list call (the bug)' {
                Mock -CommandName Invoke-PimGraph -ModuleName PIM-Functions -MockWith {
                    param($Method='GET',$Path,$Body,[switch]$All,[switch]$Beta,$Headers=@{})
                    $script:CapturedPaths.Add("$Path")
                    if ($Path -match '/groups\?\$filter') { return @([pscustomobject]@{ id='g1'; displayName='ORG-Finance' }) }
                    return @()
                }
                [void](Get-PimLiveEntraDepartmentGroups -Pattern 'ORG-*')
                $listCall = $script:CapturedPaths | Where-Object { $_ -match '/groups\?\$filter=startswith' } | Select-Object -First 1
                $listCall | Should -Not -BeNullOrEmpty
                $listCall | Should -Match '\$count=true'      # advanced query for startswith
                $listCall | Should -Not -Match '\$expand'     # the 400-causing combination is gone
            }
            It 'end-to-end Import-PimEntraDepartments returns a real created-plan for ORG-* (was empty)' {
                Mock -CommandName Invoke-PimGraph -ModuleName PIM-Functions -MockWith {
                    param($Method='GET',$Path,$Body,[switch]$All,[switch]$Beta,$Headers=@{})
                    if ($Path -match '/groups\?\$filter=startswith') { return @([pscustomobject]@{ id='g1'; displayName='ORG-Finance' }) }
                    if ($Path -match '/groups/g1/owners') { return @([pscustomobject]@{ id='u1'; userPrincipalName='fin@x.com' }) }
                    return @()
                }
                $plan = Import-PimEntraDepartments -Existing @() -Pattern 'ORG-*'
                @($plan.created).Count | Should -Be 1
                $plan.created[0].name | Should -Be 'Finance'
            }
        }
    }

    Context 'Approver/owner import from CSV (REQUIREMENTS §11)' {
        It 'parses Department;GroupName;approver1,approver2 rows (header optional)' {
            $csv = "Department;GroupName;Approvers`nFinance;ORG-Finance;a@x.com,b@x.com`nIT;ORG-IT;it@x.com"
            $rows = @(ConvertFrom-PimApproverCsv -Text $csv)
            @($rows).Count | Should -Be 2
            $rows[0].department | Should -Be 'Finance'
            $rows[0].groupName  | Should -Be 'ORG-Finance'
            @($rows[0].approvers).Count | Should -Be 2
            $rows[0].approvers | Should -Contain 'b@x.com'
        }
        It 'headerless CSV + comma delimiter also parse' {
            $rows = @(ConvertFrom-PimApproverCsv -Text "Finance,ORG-Finance,a@x.com")
            @($rows).Count | Should -Be 1
            $rows[0].department | Should -Be 'Finance'
            $rows[0].approvers  | Should -Contain 'a@x.com'
        }
        It 'applies approvers to an existing department (owners REPLACED with the CSV list)' {
            $existing = @([pscustomobject]@{ name='Finance'; owners=@('old@x.com'); contact='c'; notes='n'; source='manual'; sourceId='' })
            $plan = Import-PimApproversFromCsv -Csv "Finance;ORG-Finance;new1@x.com,new2@x.com" -Existing $existing
            @($plan.updated).Count | Should -Be 1
            $fin = $plan.departments | Where-Object { $_.name -eq 'Finance' }
            @($fin.owners).Count | Should -Be 2
            $fin.owners | Should -Not -Contain 'old@x.com'
            "$($fin.contact)" | Should -Be 'c'   # untouched manual metadata preserved
        }
        It 'RENAMES a department via the 4th NewName column (and carries owners)' {
            $existing = @([pscustomobject]@{ name='Finance'; owners=@('a@x.com'); contact=''; notes=''; source=''; sourceId='' })
            $plan = Import-PimApproversFromCsv -Csv "Finance;ORG-Finance;a@x.com;Finance-EMEA" -Existing $existing
            @($plan.renamed).Count | Should -Be 1
            $plan.renamed[0].from | Should -Be 'Finance'
            $plan.renamed[0].to   | Should -Be 'Finance-EMEA'
            ($plan.departments | Where-Object { $_.name -eq 'Finance' })       | Should -BeNullOrEmpty
            ($plan.departments | Where-Object { $_.name -eq 'Finance-EMEA' })  | Should -Not -BeNullOrEmpty
        }
        It 'creates a department the CSV names but the store lacks' {
            $plan = Import-PimApproversFromCsv -Csv "HR;ORG-HR;hr@x.com" -Existing @()
            @($plan.created).Count | Should -Be 1
            ($plan.departments | Where-Object { $_.name -eq 'HR' }).source | Should -Be 'csv-import'
        }
        It 'preserves departments NOT named in the CSV (round-trip is non-destructive)' {
            $existing = @(
                [pscustomobject]@{ name='Finance'; owners=@('a@x.com'); contact=''; notes=''; source=''; sourceId='' }
                [pscustomobject]@{ name='Legal';   owners=@('l@x.com'); contact=''; notes=''; source=''; sourceId='' }
            )
            $plan = Import-PimApproversFromCsv -Csv "Finance;ORG-Finance;new@x.com" -Existing $existing
            @($plan.departments).Count | Should -Be 2
            ($plan.departments | Where-Object { $_.name -eq 'Legal' }).owners | Should -Contain 'l@x.com'
        }
    }

    Context 'Auto-map gate (never auto-map a principal)' {
        It 'auto-imports become definition containers; non-auto stay pending; assignments ALWAYS empty' {
            $disc = @(
                [pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/a'; scopeName='lz-app';      mgmtGroupDepth=1 }
                [pscustomobject]@{ scopeType='managementGroup'; scopePath='/providers/Microsoft.Management/managementGroups/platform'; scopeName='platform'; mgmtGroupDepth=1 }
            )
            $plan = Get-PimAzureReconcilePlan -Discovered $disc -Existing @() -AutoImportRules @(@{ scopeTypes=@('subscription'); maxLevel=4 })
            $mapped = Resolve-PimDiscoveryAutoMap -Plan $plan
            @($mapped.definitions).Count | Should -Be 1   # the auto-imported subscription
            @($mapped.pending).Count     | Should -Be 1   # the MG (no rule) awaits a human
            @($mapped.assignments).Count | Should -Be 0   # NEVER auto-map a principal
        }
        It 'works on a Power BI plan too (same shape)' {
            $disc = @([pscustomobject]@{ workspaceId='ws1'; workspaceName='Sales' })
            $mapped = Resolve-PimDiscoveryAutoMap -Plan (Get-PimPowerBiReconcilePlan -Discovered $disc -Existing @() -AutoImport) -DefinitionEntity 'PIM-Definitions-Services'
            @($mapped.definitions).Count | Should -Be 1
            @($mapped.assignments).Count | Should -Be 0
        }
    }

    Context 'Per-resource-type auto-create policy (flag|pending|auto; default flag)' {
        It 'unknown type / empty map / unknown value all default to flag (safe)' {
            (Get-PimDiscoveryAutoCreatePolicy -ResourceType 'AzureSubscription' -Map @{})                 | Should -Be 'flag'
            (Get-PimDiscoveryAutoCreatePolicy -ResourceType 'SomethingNew'     -Map @{ PowerBIWorkspace='auto' }) | Should -Be 'flag'
            (Get-PimDiscoveryAutoCreatePolicy -ResourceType 'AzureSubscription' -Map @{ AzureSubscription='bogus' }) | Should -Be 'flag'
            (Get-PimDiscoveryAutoCreatePolicy -ResourceType 'AzureSubscription' -Map $null)               | Should -Be 'flag'
        }
        It 'resolves the configured per-type policy, case-insensitively' {
            $map = @{ AzureSubscription='auto'; PowerBIWorkspace='pending' }
            (Get-PimDiscoveryAutoCreatePolicy -ResourceType 'azuresubscription' -Map $map) | Should -Be 'auto'
            (Get-PimDiscoveryAutoCreatePolicy -ResourceType 'PowerBIWorkspace'  -Map $map) | Should -Be 'pending'
        }
        It 'classifies a reconcile create-row to its canonical resource type' {
            (Resolve-PimDiscoveryResourceType -Create ([pscustomobject]@{ scopeType='subscription' }))    | Should -Be 'AzureSubscription'
            (Resolve-PimDiscoveryResourceType -Create ([pscustomobject]@{ scopeType='managementGroup' })) | Should -Be 'ManagementGroup'
            (Resolve-PimDiscoveryResourceType -Create ([pscustomobject]@{ scopeType='resourceGroup' }))   | Should -Be 'ResourceGroup'
            (Resolve-PimDiscoveryResourceType -Create ([pscustomobject]@{ workspaceId='ws-1' }))          | Should -Be 'PowerBIWorkspace'
        }
        It 'policy=flag (default): a new sub is FLAGGED only -- nothing staged/auto' {
            $disc = @([pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/a'; scopeName='lz-app'; mgmtGroupDepth=1 })
            $plan = Get-PimAzureReconcilePlan -Discovered $disc -Existing @()
            $r = Resolve-PimDiscoveryPolicyPlan -Plan $plan -PolicyMap @{}   # empty -> all flag
            @($r.flagged).Count | Should -Be 1
            @($r.pending).Count | Should -Be 0
            @($r.auto).Count    | Should -Be 0
            @($r.assignments).Count | Should -Be 0
            $r.flagged[0].resourceType | Should -Be 'AzureSubscription'
            "$($r.flagged[0].key)" | Should -BeLike 'PIM-Azure-*'   # name from the existing resolver
        }
        It 'policy=pending: a new sub generates a desired row (review), nothing auto' {
            $disc = @([pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/a'; scopeName='lz-app'; mgmtGroupDepth=1 })
            $plan = Get-PimAzureReconcilePlan -Discovered $disc -Existing @()
            $r = Resolve-PimDiscoveryPolicyPlan -Plan $plan -PolicyMap @{ AzureSubscription='pending' }
            @($r.pending).Count | Should -Be 1
            @($r.auto).Count    | Should -Be 0
            @($r.flagged).Count | Should -Be 0
            $r.pending[0].entity | Should -Be 'PIM-Definitions-Resources'
            $r.pending[0].policy | Should -Be 'pending'
        }
        It 'policy=auto: a new sub goes to the auto bucket (create flow), no assignment' {
            $disc = @([pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/a'; scopeName='lz-app'; mgmtGroupDepth=1 })
            $plan = Get-PimAzureReconcilePlan -Discovered $disc -Existing @()
            $r = Resolve-PimDiscoveryPolicyPlan -Plan $plan -PolicyMap @{ AzureSubscription='auto' }
            @($r.auto).Count    | Should -Be 1
            @($r.pending).Count | Should -Be 0
            @($r.assignments).Count | Should -Be 0
            $r.auto[0].policy | Should -Be 'auto'
        }
        It 'mixed map: each type follows its own policy in one plan' {
            $disc = @(
                [pscustomobject]@{ scopeType='subscription';    scopePath='/subscriptions/a'; scopeName='lz-app';  mgmtGroupDepth=1 }
                [pscustomobject]@{ scopeType='managementGroup'; scopePath='/providers/Microsoft.Management/managementGroups/platform'; scopeName='platform'; mgmtGroupDepth=1 }
            )
            $plan = Get-PimAzureReconcilePlan -Discovered $disc -Existing @()
            $r = Resolve-PimDiscoveryPolicyPlan -Plan $plan -PolicyMap @{ AzureSubscription='auto'; ManagementGroup='flag' }
            @($r.auto).Count    | Should -Be 1
            @($r.flagged).Count | Should -Be 1
            $r.auto[0].resourceType    | Should -Be 'AzureSubscription'
            $r.flagged[0].resourceType | Should -Be 'ManagementGroup'
        }
        It 'works on a Power BI plan with an explicit type override' {
            $disc = @([pscustomobject]@{ workspaceId='ws1'; workspaceName='Sales' })
            $plan = Get-PimPowerBiReconcilePlan -Discovered $disc -Existing @()
            $r = Resolve-PimDiscoveryPolicyPlan -Plan $plan -PolicyMap @{ PowerBIWorkspace='pending' } -ResourceType 'PowerBIWorkspace'
            @($r.pending).Count | Should -Be 1
            "$($r.pending[0].key)" | Should -BeLike 'PIM-PowerBI-WS-Sales-*'   # name from the resolver
        }
        It 'reuses the naming resolver -- the bucketed key equals expected.groupName' {
            $disc = @([pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/a'; scopeName='lz-app'; mgmtGroupDepth=1 })
            $plan = Get-PimAzureReconcilePlan -Discovered $disc -Existing @()
            $r = Resolve-PimDiscoveryPolicyPlan -Plan $plan -PolicyMap @{ AzureSubscription='auto' }
            "$($r.auto[0].key)" | Should -Be "$($plan.create[0].expected.groupName)"
        }
        It 'reads the policy from the global when no map is passed' {
            $disc = @([pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/a'; scopeName='lz-app'; mgmtGroupDepth=1 })
            $plan = Get-PimAzureReconcilePlan -Discovered $disc -Existing @()
            $global:PIM_DiscoveryAutoCreate = @{ AzureSubscription='auto' }
            try { $r = Resolve-PimDiscoveryPolicyPlan -Plan $plan } finally { $global:PIM_DiscoveryAutoCreate = $null }
            @($r.auto).Count | Should -Be 1
        }
        It 'Invoke-PimDiscoveryAutoCreate -WhatIf stages/commits NOTHING (plan only)' {
            $disc = @([pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/a'; scopeName='lz-app'; mgmtGroupDepth=1 })
            $plan = Get-PimAzureReconcilePlan -Discovered $disc -Existing @()
            $sum = Invoke-PimDiscoveryAutoCreate -Plan $plan -PolicyMap @{ AzureSubscription='auto' } -ConnectionString '' -WhatIf
            $sum.auto | Should -Be 1
            @($sum.committed).Count | Should -Be 0   # WhatIf -> nothing committed
        }
    }

    Context 'Delta refinement (handled items never reappear)' {
        It 'returns only not-yet-handled items and rolls the handled set forward' {
            $disc = @(
                [pscustomobject]@{ workspaceId='ws1'; workspaceName='A' }
                [pscustomobject]@{ workspaceId='ws2'; workspaceName='B' }
            )
            $plan = Get-PimPowerBiReconcilePlan -Discovered $disc -Existing @()
            $first = Get-PimDiscoveryDelta -Current $plan.create -Handled @()
            @($first.fresh).Count | Should -Be 2
            # second run, same snapshot, with the rolled-forward handled set -> nothing fresh
            $second = Get-PimDiscoveryDelta -Current $plan.create -Handled $first.handled
            @($second.fresh).Count | Should -Be 0
            # a brand-new workspace appears -> only IT surfaces
            $disc2 = $disc + @([pscustomobject]@{ workspaceId='ws3'; workspaceName='C' })
            $plan2 = Get-PimPowerBiReconcilePlan -Discovered $disc2 -Existing @()
            $third = Get-PimDiscoveryDelta -Current $plan2.create -Handled $second.handled
            @($third.fresh).Count | Should -Be 1
            "$($third.fresh[0].workspaceId)" | Should -Be 'ws3'
        }
        It 'ignores items without a stable key' {
            @((Get-PimDiscoveryDelta -Current @([pscustomobject]@{ foo='bar' }) -Handled @()).fresh).Count | Should -Be 0
        }
    }
}

Describe 'Connector role-definition import' {
    It 'entra import: existing skipped, new split into auto (policy) vs manual' {
        $ga = Get-PimEntraDerivation -Roles @('Global Administrator')
        $live = @([pscustomobject]@{ name='Global Administrator' }, [pscustomobject]@{ name='User Administrator' }, [pscustomobject]@{ name='Security Reader' })
        # policy auto-imports entra at tier0, level 1-2 (so L1 roles auto; L0 GA would be manual even if new)
        $policy = @(@{ serviceType='entra'; maxTierNum=0; minLevel=1; maxLevel=2 })
        $plan = Get-PimDefinitionImportPlan -ServiceType 'entra' -LiveRoles $live -ExistingGroupNames @("$($ga.groupName)") -Policy $policy
        @($plan.existing).Count | Should -Be 1                       # GA already defined
        @($plan.autoCreate | Where-Object role -eq 'User Administrator').Count | Should -Be 1   # L1 -> auto
        @($plan.autoCreate | Where-Object role -eq 'Security Reader').Count | Should -Be 1      # L1 -> auto
    }
    It 'entra L0 role is NOT auto-imported under an L1-2 policy (lands in manual)' {
        $live = @([pscustomobject]@{ name='Global Administrator' })
        $plan = Get-PimDefinitionImportPlan -ServiceType 'entra' -LiveRoles $live -Policy @(@{ serviceType='entra'; maxTierNum=0; minLevel=1; maxLevel=2 })
        @($plan.manual).Count | Should -Be 1; @($plan.autoCreate).Count | Should -Be 0
    }
    It 'workload import gated by workload allowlist' {
        $live = @([pscustomobject]@{ name='Security Operator' })
        $autoP = Get-PimDefinitionImportPlan -ServiceType 'workload' -Workload 'defender' -LiveRoles $live -Policy @(@{ serviceType='workload'; workloads=@('defender') })
        @($autoP.autoCreate).Count | Should -Be 1
        $noP = Get-PimDefinitionImportPlan -ServiceType 'workload' -Workload 'defender' -LiveRoles $live -Policy @(@{ serviceType='workload'; workloads=@('powerbi') })
        @($noP.manual).Count | Should -Be 1; @($noP.autoCreate).Count | Should -Be 0
    }
    It 'import plan -> queue changes (auto only; -IncludeManual adds the rest)' {
        $live = @([pscustomobject]@{ name='User Administrator' }, [pscustomobject]@{ name='Global Administrator' })
        $plan = Get-PimDefinitionImportPlan -ServiceType 'entra' -LiveRoles $live -Policy @(@{ serviceType='entra'; maxTierNum=0; minLevel=1; maxLevel=2 })
        @(ConvertTo-PimImportQueueChanges -Plan $plan).Count | Should -Be 1                 # only UA (auto)
        @(ConvertTo-PimImportQueueChanges -Plan $plan -IncludeManual).Count | Should -Be 2 # + GA (manual)
    }
}

Describe 'Onboarding modes + self-service consultant toggle' {
    It 'onboarding mode: guest invite is cloud-only' {
        (Resolve-PimOnboardingMode -Cloud $true  -External $true).mode  | Should -Be 'guest-invite'
        (Resolve-PimOnboardingMode -Cloud $false -External $true).mode  | Should -Be 'unsupported'
        (Resolve-PimOnboardingMode -Cloud $true  -External $false).mode | Should -Be 'cloud-user'
        (Resolve-PimOnboardingMode -Cloud $false -External $false).mode | Should -Be 'ad-user'
        (Resolve-PimOnboardingMode -Cloud $true  -External $false -RequestedType 'guest').mode | Should -Be 'guest-invite'
    }
    It 'guest invitation body has required fields + Guest type; throws without email' {
        $b = New-PimGuestInvitationBody -Email 'ext@partner.com' -DisplayName 'Ext User'
        $b.invitedUserEmailAddress | Should -Be 'ext@partner.com'
        $b.invitedUserType | Should -Be 'Guest'
        $b.inviteRedirectUrl | Should -Not -BeNullOrEmpty
        { New-PimGuestInvitationBody -Email '' } | Should -Throw
    }
    It 'UserType column drives external (Internal/Consultant/OperationPartner/MSP); name never consulted' {
        (Get-PimRowIsExternal -Row ([pscustomobject]@{ UserName='x'; UserType='Internal' })) | Should -BeFalse
        (Get-PimRowIsExternal -Row ([pscustomobject]@{ UserName='x'; UserType='Consultant' })) | Should -BeTrue
        (Get-PimRowIsExternal -Row ([pscustomobject]@{ UserName='x'; UserType='OperationPartner' })) | Should -BeTrue
        (Get-PimRowIsExternal -Row ([pscustomobject]@{ UserName='x'; UserType='MSP' })) | Should -BeTrue
        (Get-PimRowIsExternal -Row ([pscustomobject]@{ UserName='x' })) | Should -BeFalse   # blank -> internal
        # row + cloud -> mode
        (Resolve-PimOnboardingModeForRow -Row ([pscustomobject]@{ UserType='Consultant' }) -Cloud $true).mode | Should -Be 'guest-invite'
        (Resolve-PimOnboardingModeForRow -Row ([pscustomobject]@{ UserType='Internal' }) -Cloud $true).mode | Should -Be 'cloud-user'
        (Resolve-PimOnboardingModeForRow -Row ([pscustomobject]@{ UserType='MSP' }) -Cloud $false).mode | Should -Be 'unsupported'
    }
    It 'self-service toggle: allowed only for managed consultants -> queue change (AccountStatus column)' {
        $profiles = @((Get-Content (Join-Path $Root 'config\portal-admins.sample.json') -Raw | ConvertFrom-Json).portalAdmins)
        $dept = Get-PimPortalProfile -Profiles $profiles -Identity 'deptowner@contoso.com'
        $ok = Resolve-PimSelfServiceToggle -Profile $dept -AccountName 'consultant1@contoso.com' -Action disable
        $ok.allowed | Should -BeTrue; $ok.change.op | Should -Be 'Update'
        $ok.change.entity | Should -Be 'Account-Definitions-Admins'
        $ok.change.payload.AccountStatus | Should -Be 'Disabled'
        (Resolve-PimSelfServiceToggle -Profile $dept -AccountName 'consultant1@contoso.com' -Action enable).change.payload.AccountStatus | Should -Be 'Enabled'
        (Resolve-PimSelfServiceToggle -Profile $dept -AccountName 'someone-else@contoso.com' -Action enable).allowed | Should -BeFalse
    }
    It 'SuperAdmin can toggle any managed account' {
        (Resolve-PimSelfServiceToggle -Profile $null -AccountName 'anyone' -Action enable -IsSuperAdmin).allowed | Should -BeTrue
    }
    It 'invite-guest capability gate (portal profile vs SuperAdmin)' {
        $profiles = @((Get-Content (Join-Path $Root 'config\portal-admins.sample.json') -Raw | ConvertFrom-Json).portalAdmins)
        $dept = Get-PimPortalProfile -Profiles $profiles -Identity 'deptowner@contoso.com'
        # SuperAdmin always allowed; a $null profile (no delegation) is not.
        (Test-PimPortalCanInviteGuest -Profile $null -IsSuperAdmin) | Should -BeTrue
        (Test-PimPortalCanInviteGuest -Profile $null) | Should -BeFalse
        $withCap = [pscustomobject]@{ identity='x'; capabilities=@('invite-guest') }
        $without = [pscustomobject]@{ identity='y'; capabilities=@('manage-direct') }
        (Test-PimPortalCanInviteGuest -Profile $withCap) | Should -BeTrue
        (Test-PimPortalCanInviteGuest -Profile $without) | Should -BeFalse
    }
    It 'guest onboarding plan: cloud builds admin row + delegation; on-prem unsupported' {
        $plan = New-PimGuestOnboardingPlan -Email 'ext@partner.com' -FirstName 'Ext' -LastName 'Consultant' -GroupTag 'PIM-Entra-ID-Helpdesk-L2-T0' -Company 'PartnerCo'
        $plan.ok | Should -BeTrue
        $plan.mode | Should -Be 'guest-invite'
        $plan.invitation.invitedUserType | Should -Be 'Guest'
        @($plan.changes).Count | Should -Be 2
        # 1) the account-definition row (cloud guest = Consultant)
        $acct = @($plan.changes | Where-Object { $_.entity -eq 'Account-Definitions-Admins' })[0]
        $acct.op | Should -Be 'Create'
        $acct.payload.UserType | Should -Be 'Consultant'
        $acct.payload.TargetUsage | Should -Be 'Cloud'
        $acct.payload.Initials | Should -Be 'EC'
        $acct.payload.UserPrincipalName | Should -Be 'ext@partner.com'
        # 2) the delegation INTO the group (membership = delegation), eligible default
        $deleg = @($plan.changes | Where-Object { $_.entity -eq 'PIM-Assignments-Admins' })[0]
        $deleg.op | Should -Be 'Create'
        $deleg.payload.GroupTag | Should -Be 'PIM-Entra-ID-Helpdesk-L2-T0'
        $deleg.payload.AssignmentType | Should -Be 'Eligible'
        $deleg.key | Should -Be 'ext@partner.com|PIM-Entra-ID-Helpdesk-L2-T0'
        # on-prem guest is impossible -> unsupported, no changes
        $bad = New-PimGuestOnboardingPlan -Email 'ext@partner.com' -Cloud $false
        $bad.ok | Should -BeFalse
        $bad.mode | Should -Be 'unsupported'
        @($bad.changes).Count | Should -Be 0
    }
    It 'guest onboarding plan without a GroupTag = invite only (admin row, no delegation)' {
        $plan = New-PimGuestOnboardingPlan -Email 'lone@partner.com'
        $plan.ok | Should -BeTrue
        @($plan.changes).Count | Should -Be 1
        @($plan.changes)[0].entity | Should -Be 'Account-Definitions-Admins'
    }
}

Describe 'NEW REST engine (PIM-EngineCore + providers)' {
    BeforeAll {
        $eng = Join-Path $script:Root 'engine\_shared'
        . (Join-Path $eng 'PIM-Rest.ps1')
        . (Join-Path $eng 'PIM-ContextBuilder.ps1')
        . (Join-Path $eng 'PIM-EngineCore.ps1')
        . (Join-Path $eng 'PIM-DisableGuard.ps1')   # account-disable circuit breaker (incident 2026-06-15)
        . (Join-Path $eng 'PIM-HybridAd.ps1')
        . (Join-Path $eng 'PIM-EngineProviders.ps1')
        . (Join-Path $eng 'PIM-Conformance.ps1')
        $global:PIM_TemplateDir = Join-Path $script:Root 'templates\policy'
    }

    It 'Compare-PimDesiredVsLive classifies create/update/nochange/remove (Full prune)' {
        $desired = @([pscustomobject]@{ k='a'; v=1 }, [pscustomobject]@{ k='b'; v=2 }, [pscustomobject]@{ k='c'; v=3 })
        $live    = @([pscustomobject]@{ k='b'; v=2 }, [pscustomobject]@{ k='c'; v=9 }, [pscustomobject]@{ k='d'; v=4 })
        $diff = Compare-PimDesiredVsLive -Desired $desired -Live $live -KeyOf { param($r) $r.k } -Equal { param($d,$l) $d.v -eq $l.v } -Prune
        $diff.create.Count   | Should -Be 1   # a (new)
        $diff.update.Count   | Should -Be 1   # c (value differs)
        $diff.nochange.Count | Should -Be 1   # b (equal)
        $diff.remove.Count   | Should -Be 1   # d (live-only, pruned)
    }

    It 'Merge-PimCacheItem shapes (PascalCase) + de-dups, flat (cache-corruption regression guard)' {
        $c1 = Merge-PimCacheItem -Current @()  -Object ([pscustomobject]@{ id='g1'; displayName='UNIT-GRP-A' })
        $c2 = Merge-PimCacheItem -Current $c1  -Object ([pscustomobject]@{ id='g2'; displayName='UNIT-GRP-B' })
        $c3 = Merge-PimCacheItem -Current $c2  -Object ([pscustomobject]@{ id='g1'; displayName='UNIT-GRP-A' })   # duplicate id
        @($c3).Count | Should -Be 2                                                              # de-duped + flat (no nested array)
        @(@($c3) | Where-Object { $_.DisplayName -eq 'UNIT-GRP-A' }).Count | Should -Be 1        # shaped: PascalCase alias present, distinct
        @(@($c3) | Where-Object { $_.Id -eq 'g2' }).Count                  | Should -Be 1
    }

    It 'Resolve-PimGroupOwnerIds: pipe-joined Owners, then Department fallback' {
        $Global:Users_All_ID = @(
            [pscustomobject]@{ Id='u-mok'; UserPrincipalName='mok@x.com' },
            [pscustomobject]@{ Id='u-dep'; UserPrincipalName='dep@x.com' })
        $r1 = Resolve-PimGroupOwnerIds -Row ([pscustomobject]@{ GroupName='G'; Owners='mok@x.com|dep@x.com' }) -Ctx @{}
        ($r1 -contains 'u-mok' -and $r1 -contains 'u-dep') | Should -BeTrue
        # no direct owner -> inherit from the group's Department
        $global:PIM_DesiredRows = @{ 'PIM-Definitions-Departments' = @([pscustomobject]@{ Department='IT'; Owners='dep@x.com' }) }
        Set-Variable -Scope Script -Name '__pimDeptOwners' -Value $null -ErrorAction SilentlyContinue
        $r2 = Resolve-PimGroupOwnerIds -Row ([pscustomobject]@{ GroupName='G'; Department='IT' }) -Ctx @{}
        $r2 | Should -Contain 'u-dep'
        $global:PIM_DesiredRows = $null
    }

    It 'Policy templates: approval-required extends default, carries Approval + MFA enablement; default carries none' {
        $ar = Get-PimEnginePolicyTemplate -Id 'approval-required'
        $ar | Should -Not -BeNullOrEmpty
        $ar.rules.ContainsKey('Approval') | Should -BeTrue
        # MFA+Justification on the activation enablement (structured Enablement object, inherited from default)
        $ar.rules.ContainsKey('Enablement') | Should -BeTrue
        @($ar.rules['Enablement'].EndUser_Assignment) -contains 'MultiFactorAuthentication' | Should -BeTrue
        (Get-PimEnginePolicyTemplate -Id 'default').rules.ContainsKey('Approval') | Should -BeFalse
    }

    # v1 policy-parity (Custom-Policies.ps1 baseline): the SHIPPED templates must declare the
    # full Expiration + Enablement rule set so the engine brings EVERY managed group (not just
    # approval-required) to parity. These assert the templates as authored.
    It 'Shipped default template declares the full v1 Expiration + Enablement baseline' {
        $def = Get-PimEnginePolicyTemplate -Id 'default'
        $def | Should -Not -BeNullOrEmpty
        # Expiration: EndUser/activation P1D; Admin-Assignment P365D; Admin-Eligibility P365D; all required
        $def.rules.ContainsKey('Expiration') | Should -BeTrue
        $exp = $def.rules['Expiration']
        "$($exp.EndUser_Assignment.maximumDuration)"  | Should -Be 'P1D'
        "$($exp.Admin_Assignment.maximumDuration)"    | Should -Be 'P365D'
        "$($exp.Admin_Eligibility.maximumDuration)"   | Should -Be 'P365D'
        [bool]$exp.EndUser_Assignment.isExpirationRequired | Should -BeTrue
        [bool]$exp.Admin_Assignment.isExpirationRequired   | Should -BeTrue
        [bool]$exp.Admin_Eligibility.isExpirationRequired  | Should -BeTrue
        # Enablement: MFA+Justification on EndUser-Assignment AND Admin-Eligibility; none on Admin-Assignment
        $def.rules.ContainsKey('Enablement') | Should -BeTrue
        $en = $def.rules['Enablement']
        @($en.EndUser_Assignment) -contains 'MultiFactorAuthentication' | Should -BeTrue
        @($en.EndUser_Assignment) -contains 'Justification'             | Should -BeTrue
        @($en.Admin_Eligibility)  -contains 'MultiFactorAuthentication' | Should -BeTrue
        @($en.Admin_Eligibility)  -contains 'Justification'             | Should -BeTrue
        @($en.Admin_Assignment).Count | Should -Be 0
        # baseline is NOT gated on Approval — default carries no Approval rule
        $def.rules.ContainsKey('Approval') | Should -BeFalse
    }

    # v1->v2 parity: v1 PIM_Policy_Check_Update wrote Expiration + Notification PIM
    # rules; v2 originally wrote only Approval+Enablement. These assert the pure
    # rule-body builders that close the gap (offline; the PATCH plumbing is shared).
    It 'New-PimGroupExpirationRuleBody caps activation duration; blank -> null' {
        $b = New-PimGroupExpirationRuleBody -MaxDuration 'PT8H'
        $b.id                   | Should -Be 'Expiration_EndUser_Assignment'
        $b.isExpirationRequired | Should -BeTrue
        $b.maximumDuration      | Should -Be 'PT8H'
        $b.target.caller        | Should -Be 'EndUser'
        $b.target.level         | Should -Be 'Assignment'
        $b.'@odata.type'        | Should -Be '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'
        (New-PimGroupExpirationRuleBody -MaxDuration '')  | Should -BeNullOrEmpty
        (New-PimGroupExpirationRuleBody -MaxDuration '  ') | Should -BeNullOrEmpty
        # v1 parity: also builds the Admin/Assignment + Admin/Eligibility rules
        $ba = New-PimGroupExpirationRuleBody -MaxDuration 'P365D' -Caller 'Admin' -Level 'Assignment'
        $ba.id            | Should -Be 'Expiration_Admin_Assignment'
        $ba.target.caller | Should -Be 'Admin'
        $ba.target.level  | Should -Be 'Assignment'
        $be = New-PimGroupExpirationRuleBody -MaxDuration 'P365D' -Caller 'Admin' -Level 'Eligibility'
        $be.id            | Should -Be 'Expiration_Admin_Eligibility'
        $be.target.level  | Should -Be 'Eligibility'
        (New-PimGroupExpirationRuleBody -MaxDuration 'P1D' -IsExpirationRequired $false).isExpirationRequired | Should -BeFalse
    }

    # v1 policy-parity: the structured "Expiration" object on a template must materialise the
    # FULL three-rule set (EndUser P1D, Admin-Assignment P365D, Admin-Eligibility P365D).
    It 'ConvertTo-PimExpirationRuleBodies emits the full v1 expiration rule set (object form) + legacy string' {
        $obj = [pscustomobject]@{
            EndUser_Assignment = [pscustomobject]@{ maximumDuration='P1D';   isExpirationRequired=$true }
            Admin_Assignment   = [pscustomobject]@{ maximumDuration='P365D'; isExpirationRequired=$true }
            Admin_Eligibility  = [pscustomobject]@{ maximumDuration='P365D'; isExpirationRequired=$true }
        }
        $rules = @(ConvertTo-PimExpirationRuleBodies -Expiration $obj)
        $rules.Count | Should -Be 3
        ($rules | Where-Object { $_.id -eq 'Expiration_EndUser_Assignment' }).maximumDuration | Should -Be 'P1D'
        ($rules | Where-Object { $_.id -eq 'Expiration_Admin_Assignment' }).maximumDuration   | Should -Be 'P365D'
        ($rules | Where-Object { $_.id -eq 'Expiration_Admin_Eligibility' }).maximumDuration  | Should -Be 'P365D'
        @($rules | Where-Object { -not $_.isExpirationRequired }).Count | Should -Be 0
        # legacy string form -> just the EndUser/Assignment cap (back-compat)
        $legacy = @(ConvertTo-PimExpirationRuleBodies -Expiration 'PT4H')
        $legacy.Count | Should -Be 1
        $legacy[0].id | Should -Be 'Expiration_EndUser_Assignment'
        @(ConvertTo-PimExpirationRuleBodies -Expiration $null).Count | Should -Be 0
    }

    # v1 policy-parity: the structured "Enablement" object must materialise MFA+Justification on
    # EndUser-Assignment AND Admin-Eligibility, and an EMPTY rule on Admin-Assignment.
    It 'ConvertTo-PimEnablementRuleBodies emits the full v1 enablement rule set + legacy fallback' {
        $en = [pscustomobject]@{
            EndUser_Assignment = @('MultiFactorAuthentication','Justification')
            Admin_Eligibility  = @('MultiFactorAuthentication','Justification')
            Admin_Assignment   = @()
        }
        $rules = @(ConvertTo-PimEnablementRuleBodies -Enablement $en)
        $rules.Count | Should -Be 3
        $eu = $rules | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' }
        @($eu.enabledRules) -contains 'MultiFactorAuthentication' | Should -BeTrue
        @($eu.enabledRules) -contains 'Justification'             | Should -BeTrue
        $eu.target.caller | Should -Be 'EndUser'
        $ae = $rules | Where-Object { $_.id -eq 'Enablement_Admin_Eligibility' }
        @($ae.enabledRules) -contains 'MultiFactorAuthentication' | Should -BeTrue
        $ae.target.caller | Should -Be 'Admin'
        $ae.target.level  | Should -Be 'Eligibility'
        $aa = $rules | Where-Object { $_.id -eq 'Enablement_Admin_Assignment' }
        @($aa.enabledRules).Count | Should -Be 0           # Admin/Assignment carries no MFA/Justification
        # legacy single-key fallback maps to EndUser/Assignment only
        $leg = @(ConvertTo-PimEnablementRuleBodies -Enablement $null -LegacyEndUserAssignment @('MultiFactorAuthentication'))
        $leg.Count | Should -Be 1
        $leg[0].id | Should -Be 'Enablement_EndUser_Assignment'
    }

    It 'New-PimGroupNotificationRuleBody shapes one rule per recipient-type x event' {
        $b = New-PimGroupNotificationRuleBody -RecipientType 'Approver' -Level 'Assignment' -NotificationLevel 'Critical' -Recipients @('sec@x.com','')
        $b.id                          | Should -Be 'Notification_Approver_EndUser_Assignment'
        $b.recipientType               | Should -Be 'Approver'
        $b.notificationLevel           | Should -Be 'Critical'
        $b.target.level                | Should -Be 'Assignment'
        @($b.notificationRecipients).Count | Should -Be 1                # blank entry dropped
        $b.notificationRecipients[0]   | Should -Be 'sec@x.com'
        $b.'@odata.type'               | Should -Be '#microsoft.graph.unifiedRoleManagementPolicyNotificationRule'
        # default recipient-type x level shape
        (New-PimGroupNotificationRuleBody -RecipientType 'Admin' -Level 'Eligibility').id | Should -Be 'Notification_Admin_EndUser_Eligibility'
    }

    It 'GroupsPolicies GetDesired carries Expiration/Notification when the template declares them' {
        $realDir = Join-Path $script:Root 'templates\policy'
        $tmpDir  = (Join-Path $env:TEMP ("pimtpl-"+[guid]::NewGuid().ToString('N')))
        try {
            New-Item -ItemType Directory -Force $tmpDir | Out-Null
            Set-Content (Join-Path $tmpDir 'default.policytemplate.json') '{ "id":"default", "rules": {} }' -Encoding UTF8
            @'
{ "id":"capped", "extends":"default",
  "rules": { "Approval": { "mode":"Parallel", "approversSource":"Owners" },
             "Expiration": "PT4H",
             "Notification": [ { "recipientType":"Admin", "level":"Assignment", "recipients":["ops@x.com"] } ] } }
'@ | Set-Content (Join-Path $tmpDir 'capped.policytemplate.json') -Encoding UTF8
            $global:PIM_TemplateDir = $tmpDir
            $script:__pimTplCache = $null                                  # same scope the dot-sourced provider reads
            $global:PIM_DesiredRows = @{ 'PIM-Definitions-Roles' = @([pscustomobject]@{ GroupName='PIM-X-L1-T1-CP-ID'; GroupTag='X'; PolicyTemplate='capped'; Owners='o@x.com' }) }
            $prov = New-PimGroupsPoliciesProvider
            $desired = & $prov.GetDesired @{}
            $row = @($desired) | Where-Object { $_.GroupName -eq 'PIM-X-L1-T1-CP-ID' } | Select-Object -First 1
            $row                | Should -Not -BeNullOrEmpty
            "$($row.Expiration)" | Should -Be 'PT4H'
            @($row.Notification).Count | Should -Be 1
        } finally {
            # restore the REAL template dir + rebuild the cache so later tests see shipped templates
            $global:PIM_DesiredRows = $null
            $global:PIM_TemplateDir = $realDir
            $script:__pimTplCache = $null
            Remove-Item $tmpDir -Recurse -Force -EA SilentlyContinue 2>$null
        }
    }

    # v1 policy-parity gap fix: the baseline (Expiration + Enablement) must reach EVERY managed
    # group, including default-linked groups (blank PolicyTemplate). Previously GetDesired skipped
    # any template without an Approval rule, so default groups got no Expiration/Enablement at all.
    It 'GroupsPolicies GetDesired brings the v1 baseline to default-linked groups (no Approval)' {
        $realDir = Join-Path $script:Root 'templates\policy'
        try {
            $global:PIM_TemplateDir = $realDir                              # the SHIPPED templates
            $script:__pimTplCache = $null
            # one group on the SHIPPED default (blank PolicyTemplate), one on approval-required
            $global:PIM_DesiredRows = @{ 'PIM-Definitions-Roles' = @(
                [pscustomobject]@{ GroupName='PIM-D-L1-T1-CP-ID'; GroupTag='D'; PolicyTemplate=''; Owners='o@x.com' },
                [pscustomobject]@{ GroupName='PIM-A-L0-T0-CP-ID'; GroupTag='A'; PolicyTemplate='approval-required'; Owners='o@x.com' }) }
            $prov = New-PimGroupsPoliciesProvider
            $desired = @(& $prov.GetDesired @{})
            $dflt = $desired | Where-Object { $_.GroupName -eq 'PIM-D-L1-T1-CP-ID' } | Select-Object -First 1
            $dflt | Should -Not -BeNullOrEmpty                              # default group is NOT skipped
            $dflt.TemplateId | Should -Be 'default'
            $dflt.Approval   | Should -BeNullOrEmpty                        # no approval on default
            # full v1 expiration + enablement materialise from the desired row
            $exp = @(ConvertTo-PimExpirationRuleBodies -Expiration $dflt.Expiration)
            $exp.Count | Should -Be 3
            ($exp | Where-Object { $_.id -eq 'Expiration_EndUser_Assignment' }).maximumDuration | Should -Be 'P1D'
            ($exp | Where-Object { $_.id -eq 'Expiration_Admin_Assignment' }).maximumDuration   | Should -Be 'P365D'
            ($exp | Where-Object { $_.id -eq 'Expiration_Admin_Eligibility' }).maximumDuration  | Should -Be 'P365D'
            $en = @(ConvertTo-PimEnablementRuleBodies -Enablement $dflt.Enablement -LegacyEndUserAssignment $dflt.EnablementLegacy)
            @($en | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' }).Count | Should -Be 1
            @($en | Where-Object { $_.id -eq 'Enablement_Admin_Eligibility' }).Count  | Should -Be 1
            (($en | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' }).enabledRules) -contains 'MultiFactorAuthentication' | Should -BeTrue
            # approval-required group still carries its Approval rule
            $appr = $desired | Where-Object { $_.GroupName -eq 'PIM-A-L0-T0-CP-ID' } | Select-Object -First 1
            $appr.Approval | Should -Not -BeNullOrEmpty
        } finally {
            $global:PIM_DesiredRows = $null
            $global:PIM_TemplateDir = $realDir
            $script:__pimTplCache = $null
        }
    }

    # --- §7 Providers: GroupsCreateModifyPolicy -- FULL idempotent policy compare ---
    # The GroupsPolicies provider creates + MODIFIES a group's PIM member policy. To be
    # genuinely idempotent (no redundant PATCH when already matching) AND to repair drift
    # in ANY rule family (not just EndUser/Assignment), the diff must read back + compare
    # the whole managed rule set. These pin the pure facet builders + the compare.
    It 'Get-PimGroupPolicyDesiredFacets covers Approval + Expiration x3 + Enablement x3 + Notification' {
        $d = [pscustomobject]@{
            GroupName='G'; Owners=''; ApproverIds=@('u-a','u-b')
            Expiration=[pscustomobject]@{ EndUser_Assignment=[pscustomobject]@{maximumDuration='P1D';isExpirationRequired=$true}; Admin_Assignment=[pscustomobject]@{maximumDuration='P365D';isExpirationRequired=$true}; Admin_Eligibility=[pscustomobject]@{maximumDuration='P365D';isExpirationRequired=$true} }
            Enablement=[pscustomobject]@{ EndUser_Assignment=@('MultiFactorAuthentication','Justification'); Admin_Eligibility=@('MultiFactorAuthentication','Justification'); Admin_Assignment=@() }
            Notification=@([pscustomobject]@{recipientType='Admin';level='Assignment';recipients=@('ops@x.com')})
            Approval=[pscustomobject]@{ mode='SingleStage'; approversSource='Owners' }
        }
        $f = Get-PimGroupPolicyDesiredFacets -Desired $d
        $f.Count | Should -Be 8   # 3 expiration + 3 enablement + 1 notification + 1 approval
        $f['Expiration_EndUser_Assignment'] | Should -Be 'exp|dur=P1D|req=True'
        $f['Expiration_Admin_Assignment']   | Should -Be 'exp|dur=P365D|req=True'
        $f['Enablement_EndUser_Assignment'] | Should -Be 'en|rules=Justification,MultiFactorAuthentication'   # order-insensitive
        $f['Enablement_Admin_Assignment']   | Should -Be 'en|rules='                                          # cleared
        $f['Notification_Admin_EndUser_Assignment'] | Should -Be 'notify|lvl=All|def=True|recips=ops@x.com'
        $f['Approval_EndUser_Assignment']   | Should -Be 'appr|required=true|approvers=u-a,u-b'               # approver set part of the facet
    }
    It 'Get-PimGroupPolicyDesiredFacets carries no Approval/Notification facet when the template declares none' {
        $d = [pscustomobject]@{ GroupName='G'; Expiration='PT4H'; Enablement=$null; EnablementLegacy=$null; Notification=$null; Approval=$null; ApproverIds=@() }
        $f = Get-PimGroupPolicyDesiredFacets -Desired $d
        $f.ContainsKey('Approval_EndUser_Assignment') | Should -BeFalse
        @($f.Keys | Where-Object { $_ -like 'Notification_*' }).Count | Should -Be 0
        $f['Expiration_EndUser_Assignment'] | Should -Be 'exp|dur=PT4H|req=True'   # legacy string -> EndUser cap only
    }
    It 'Get-PimGroupPolicyLiveFacets normalises a live rules collection to the same shape (id and @odata.type routed)' {
        $rules = @(
            [pscustomobject]@{ id='Expiration_EndUser_Assignment'; maximumDuration='P1D'; isExpirationRequired=$true }
            [pscustomobject]@{ '@odata.type'='#microsoft.graph.unifiedRoleManagementPolicyEnablementRule'; id='Enablement_EndUser_Assignment'; enabledRules=@('Justification','MultiFactorAuthentication') }
            [pscustomobject]@{ id='Notification_Admin_EndUser_Assignment'; notificationLevel='All'; isDefaultRecipientsEnabled=$true; notificationRecipients=@('ops@x.com') }
            [pscustomobject]@{ id='Approval_EndUser_Assignment'; setting=[pscustomobject]@{ isApprovalRequired=$true; approvalStages=@([pscustomobject]@{ primaryApprovers=@([pscustomobject]@{ userId='u-b' },[pscustomobject]@{ userId='u-a' }) }) } }
        )
        $f = Get-PimGroupPolicyLiveFacets -Rules $rules
        $f['Expiration_EndUser_Assignment'] | Should -Be 'exp|dur=P1D|req=True'
        $f['Enablement_EndUser_Assignment'] | Should -Be 'en|rules=Justification,MultiFactorAuthentication'
        $f['Notification_Admin_EndUser_Assignment'] | Should -Be 'notify|lvl=All|def=True|recips=ops@x.com'
        $f['Approval_EndUser_Assignment']   | Should -Be 'appr|required=true|approvers=u-a,u-b'   # approver order-insensitive
    }
    It 'Test-PimGroupPolicyInSync: in-sync when all desired facets match; drift in ANY family -> not in sync' {
        $want = @{ 'Expiration_EndUser_Assignment'='exp|dur=P1D|req=True'; 'Expiration_Admin_Assignment'='exp|dur=P365D|req=True'; 'Enablement_EndUser_Assignment'='en|rules=Justification,MultiFactorAuthentication' }
        # exact match (+ an EXTRA unmanaged live rule the engine doesn't own) -> in sync
        $haveMatch = @{} + $want; $haveMatch['Some_Unmanaged']='x'
        Test-PimGroupPolicyInSync -Desired $want -Live $haveMatch | Should -BeTrue
        # Admin/Assignment expiration drifted (previously UNDETECTED -- only EndUser was compared)
        $haveDrift = @{} + $want; $haveDrift['Expiration_Admin_Assignment']='exp|dur=P30D|req=True'
        Test-PimGroupPolicyInSync -Desired $want -Live $haveDrift | Should -BeFalse
        # a desired facet missing live -> not in sync (needs the modify PATCH)
        $haveMissing = @{} + $want; $haveMissing.Remove('Enablement_EndUser_Assignment')
        Test-PimGroupPolicyInSync -Desired $want -Live $haveMissing | Should -BeFalse
        # empty live -> not in sync
        Test-PimGroupPolicyInSync -Desired $want -Live @{} | Should -BeFalse
    }
    It 'GroupsPolicies Equal: idempotent nochange when live already matches the full baseline, modify on drift' {
        $realDir = Join-Path $script:Root 'templates\policy'
        try {
            $global:PIM_TemplateDir = $realDir; $script:__pimTplCache = $null
            $global:PIM_DesiredRows = @{ 'PIM-Definitions-Roles' = @([pscustomobject]@{ GroupName='PIM-D-L1-T1-CP-ID'; GroupTag='D'; PolicyTemplate=''; Owners='o@x.com' }) }
            $prov = New-PimGroupsPoliciesProvider
            $d = @(& $prov.GetDesired @{}) | Where-Object { $_.GroupName -eq 'PIM-D-L1-T1-CP-ID' } | Select-Object -First 1
            $d | Should -Not -BeNullOrEmpty
            # synthesise the LIVE rules collection the provider's PATCHes would have written:
            $rules = @()
            foreach ($b in @(ConvertTo-PimExpirationRuleBodies -Expiration $d.Expiration)) { $rules += [pscustomobject]$b }
            foreach ($b in @(ConvertTo-PimEnablementRuleBodies -Enablement $d.Enablement -LegacyEndUserAssignment $d.EnablementLegacy)) { $rules += [pscustomobject]$b }
            $liveMatch = [pscustomobject]@{ GroupName='PIM-D-L1-T1-CP-ID'; Rules=$rules }
            (& $prov.Equal $d $liveMatch) | Should -BeTrue    # already at baseline -> nochange, no redundant PATCH
            # drift the Admin/Eligibility expiration cap -> Equal must report a modify is needed
            # (this facet was NEVER compared before -- the old Equal only checked EndUser/Assignment).
            $rulesDrift = @($rules | Where-Object { $_.id -ne 'Expiration_Admin_Eligibility' })
            $rulesDrift += [pscustomobject](New-PimGroupExpirationRuleBody -MaxDuration 'P30D' -Caller 'Admin' -Level 'Eligibility')
            $liveDrift = [pscustomobject]@{ GroupName='PIM-D-L1-T1-CP-ID'; Rules=$rulesDrift }
            (& $prov.Equal $d $liveDrift) | Should -BeFalse
            # a group with no readable policy (empty live) -> not equal (create/modify)
            (& $prov.Equal $d ([pscustomobject]@{ GroupName='PIM-D-L1-T1-CP-ID'; Rules=@() })) | Should -BeFalse
        } finally {
            $global:PIM_DesiredRows = $null; $global:PIM_TemplateDir = $realDir; $script:__pimTplCache = $null
        }
    }
    It 'GroupsPolicies provider registration: scope GroupsPolicies, entity PIM-Definitions, order 70 after assignment scopes' {
        Register-PimDefaultEngineProviders
        $p = Get-PimEngineProvider -Scope 'GroupsPolicies'
        $p | Should -Not -BeNullOrEmpty
        $p.entity | Should -Be 'PIM-Definitions'
        [int]$p.order | Should -Be 70
        $scopes = @(Get-PimEngineScopes)
        $scopes.IndexOf('Groups')        | Should -BeLessThan $scopes.IndexOf('GroupsPolicies')
        $scopes.IndexOf('AdminMembers')  | Should -BeLessThan $scopes.IndexOf('GroupsPolicies')
    }
    It 'ConvertTo-PimSortedList: order-insensitive, de-duped, blank-dropped, case-trimmed' {
        ConvertTo-PimSortedList @('b','a','a','') | Should -Be 'a,b'
        ConvertTo-PimSortedList @(' x ','y')      | Should -Be 'x,y'
        ConvertTo-PimSortedList @()               | Should -Be ''
    }

    # --- §6 Engine-core: PIM v1 DIRECT role assignment (principal = user, not group) ---
    It 'EntraRolesDirect provider is registered after the group-centric role scopes, before AdminMembers' {
        Register-PimDefaultEngineProviders
        $scopes = @(Get-PimEngineScopes)
        $scopes -contains 'EntraRolesDirect' | Should -BeTrue
        $scopes.IndexOf('EntraRoles')       | Should -BeLessThan $scopes.IndexOf('EntraRolesDirect')
        $scopes.IndexOf('EntraRolesDirect') | Should -BeLessThan $scopes.IndexOf('AdminMembers')
        (Get-PimEngineProvider -Scope 'EntraRolesDirect').entity | Should -Be 'PIM-Assignments-Roles-Direct'
    }
    It 'Get-PimDirectRoleKey keys a direct role by user|role|type (case-insensitive)' {
        $k1 = Get-PimDirectRoleKey -Row ([pscustomobject]@{ UserPrincipalName='A@x'; RoleDefinitionName='Global Administrator'; AssignmentType='Eligible' })
        $k2 = Get-PimDirectRoleKey -Row ([pscustomobject]@{ principalId='a@x'; RoleName='global administrator'; AssignmentType='eligible' })
        $k1 | Should -Be 'a@x|global administrator|eligible'
        $k1 | Should -Be $k2
    }
    It 'EntraRolesDirect GetDesired drops Action=Remove + rows without a user, and emits the deprecation nudge' {
        $global:PIM_DesiredRows = @{ 'PIM-Assignments-Roles-Direct' = @(
            [pscustomobject]@{ UserPrincipalName='bg@x'; RoleDefinitionName='Global Administrator'; AssignmentType='Eligible' },
            [pscustomobject]@{ UserPrincipalName='gone@x'; RoleDefinitionName='Helpdesk Administrator'; AssignmentType='Active'; Action='Remove' },
            [pscustomobject]@{ RoleDefinitionName='Reports Reader'; AssignmentType='Eligible' }) }   # no user -> dropped
        try {
            $prov = New-PimEntraRolesDirectProvider
            $desired = @(& $prov.GetDesired @{})
            $desired.Count | Should -Be 1
            (Get-PimRowProp -Row $desired[0] -Names @('UserPrincipalName')) | Should -Be 'bg@x'
        } finally { $global:PIM_DesiredRows = $null }
    }

    # --- §6 Engine-core: offboarding (remove an admin principal's delegations cleanly) ---
    It 'Test-PimAdminOffboarded flags Lifecycle=Retire and a past OffboardDate, not a future/blank one' {
        (Test-PimAdminOffboarded -Row ([pscustomobject]@{ Lifecycle='Retire' })).offboard       | Should -BeTrue
        (Test-PimAdminOffboarded -Row ([pscustomobject]@{ OffboardDate='2000-01-01' })).offboard | Should -BeTrue
        (Test-PimAdminOffboarded -Row ([pscustomobject]@{ OffboardDate='2999-01-01' })).offboard | Should -BeFalse
        (Test-PimAdminOffboarded -Row ([pscustomobject]@{ Lifecycle=''; OffboardDate='' })).offboard | Should -BeFalse
    }
    It 'Get-PimOffboardingPlan removes ALL memberships of flagged admins and NONE of an unflagged admin' {
        $admins = @(
            [pscustomobject]@{ UserPrincipalName='retire@x'; Lifecycle='Retire' },
            [pscustomobject]@{ UserPrincipalName='past@x';   OffboardDate='2000-01-01' },
            [pscustomobject]@{ UserPrincipalName='keep@x';   Lifecycle='' })
        $live = @{
            'id-retire' = @(@{ principalId='id-retire'; GroupTag='GA';  accessId='member'; AssignmentType='Eligible' },
                            @{ principalId='id-retire'; GroupTag='SVC'; accessId='member'; AssignmentType='Active'   })
            'id-past'   = @(@{ principalId='id-past';   GroupTag='HD';  accessId='member'; AssignmentType='Eligible' })
            'id-keep'   = @(@{ principalId='id-keep';   GroupTag='GA';  accessId='member'; AssignmentType='Eligible' }) }
        $u2i = @{ 'retire@x'='id-retire'; 'past@x'='id-past'; 'keep@x'='id-keep' }
        $plan = @(Get-PimOffboardingPlan -AdminRows $admins -LiveByPrincipal $live -UpnToId $u2i)
        $plan.Count | Should -Be 3                                                       # 2 (retire) + 1 (past), 0 (keep)
        @($plan | Where-Object { $_.UserPrincipalName -eq 'keep@x' }).Count | Should -Be 0
        @($plan | Where-Object { $_.UserPrincipalName -eq 'retire@x' }).Count | Should -Be 2
        ($plan | Where-Object { $_.GroupTag -eq 'SVC' }).AssignmentType | Should -Be 'Active'
    }
    It 'AdminOffboarding provider opts into empty-desired prune and removes ONLY under Full+Prune+Enforce' {
        Register-PimDefaultEngineProviders
        $prov = Get-PimEngineProvider -Scope 'AdminOffboarding'
        $prov.allowEmptyDesiredPrune | Should -BeTrue
        $prov.order | Should -Be 90
        # mock everything the provider touches; count Graph writes per gate
        $Global:PimContextBuiltAt = Get-Date
        $global:PIM_DesiredRows = @{ 'Account-Definitions-Admins' = @([pscustomobject]@{ UserPrincipalName='retire@x'; Lifecycle='Retire' }) }
        function Ensure-PimContextLoaded {}
        function Get-PimTagToGroupName { @{ 'ga'='PIM-GA' } }
        function Resolve-PimPrincipalId { param($u) 'id-' + ($u -replace '@.*','') }
        function Resolve-PimLiveGroupIdByName { param($n) 'gid-' + $n }
        function Get-PimLiveGroupMembership { param($GroupId,$GroupTag) @([pscustomobject]@{ principalId='id-retire'; accessId='member'; GroupTag=$GroupTag; AssignmentType='Eligible' }) }
        $script:__obWrites = 0
        function Invoke-PimGraph { param([string]$Method,[string]$Path,$Body) $script:__obWrites++ ; @{} }
        function Run($mode,$prune,$cm) { $global:PIM_OffboardCleanupMode=$cm; $script:__obWrites=0; Invoke-PimEngineScope -Scope 'AdminOffboarding' -Mode $mode -Prune:$prune | Out-Null; $script:__obWrites }
        try {
            # OPERATOR POLICY: automatic offboarding is OFF by default -- even Full+Prune+Enforce
            # writes NOTHING until $global:PIM_EnableAutomaticOffboarding is explicitly opted in.
            $global:PIM_EnableAutomaticOffboarding = $null
            (Run 'Full'  $true  'Enforce') | Should -Be 0     # NOT opted in -> no write (gate)
            # Now opt in and assert the existing -Mode/-Prune/-OffboardCleanupMode gates still apply.
            $global:PIM_EnableAutomaticOffboarding = $true
            (Run 'Delta' $false 'Enforce') | Should -Be 0     # no prune -> no removal
            (Run 'Full'  $true  'Report')  | Should -Be 0     # report only -> plan, no write
            (Run 'Full'  $true  'Off')     | Should -Be 0     # disabled -> no live, no write
            (Run 'Full'  $true  'Enforce') | Should -Be 1     # opted in + all gates -> removed
        } finally {
            $global:PIM_DesiredRows = $null; $global:PIM_OffboardCleanupMode = $null; $Global:PimContextBuiltAt = $null
            $global:PIM_EnableAutomaticOffboarding = $null
        }
    }

    # --- §6 Operator policy: automatic destructive actions OFF by default (mass-disable incident) ---
    # Every AUTOMATIC, whole-population destructive action must be disabled unless the
    # operator explicitly opts in. The CONTROLLED, naming-scoped, opt-in reconcile prune
    # (-Mode Full -Prune) is unaffected and must still work.
    It 'Test-PimAutoDestructiveEnabled is environment-aware: OFF by default in a protected tenant, ON in a test tenant, explicit opt-in always wins' {
        foreach ($n in @('PIM_EnableAutomaticOffboarding','PIM_EnableGroupRetirement','PIM_EnableMembershipDriftCleanup')) {
            Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue
        }
        $savedTid = $global:PIM_TestTenantIds; $savedConn = $global:PIM_TenantId
        try {
            $global:PIM_TestTenantIds = $null   # use the built-in test-tenant list
            # PROTECTED env (real internal tenant) -> default OFF for every feature
            $global:PIM_TenantId = 'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e'
            (Test-PimAutoDestructiveEnabled -Feature 'Offboarding')            | Should -BeFalse
            (Test-PimAutoDestructiveEnabled -Feature 'GroupRetirement')        | Should -BeFalse
            (Test-PimAutoDestructiveEnabled -Feature 'MembershipDriftCleanup') | Should -BeFalse
            (Test-PimAutoDestructiveEnabled -Feature 'UnknownFeature')         | Should -BeFalse
            # unknown/absent tenant -> protected (safe default OFF)
            $global:PIM_TenantId = $null
            (Test-PimAutoDestructiveEnabled -Feature 'GroupRetirement')        | Should -BeFalse
            # TEST env (PIM MSP test tenant) -> default ON for every feature
            $global:PIM_TenantId = '4ff34194-fb38-4949-8e2a-58dac8f096c2'      # PIM MSP test tenant
            (Test-PimAutoDestructiveEnabled -Feature 'Offboarding')            | Should -BeTrue
            (Test-PimAutoDestructiveEnabled -Feature 'GroupRetirement')        | Should -BeTrue
            (Test-PimAutoDestructiveEnabled -Feature 'MembershipDriftCleanup') | Should -BeTrue
            (Test-PimAutoDestructiveEnabled -Feature 'UnknownFeature')         | Should -BeFalse   # unknown feature is never enabled
            # explicit operator opt-in overrides the env default in BOTH directions
            $global:PIM_TenantId = 'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e'      # protected
            $global:PIM_EnableGroupRetirement = $true
            (Test-PimAutoDestructiveEnabled -Feature 'GroupRetirement')        | Should -BeTrue   # explicit ON beats protected default
            $global:PIM_EnableGroupRetirement = 'yes'
            (Test-PimAutoDestructiveEnabled -Feature 'GroupRetirement')        | Should -BeTrue
            $global:PIM_TenantId = '4ff34194-fb38-4949-8e2a-58dac8f096c2'      # test
            $global:PIM_EnableGroupRetirement = $false
            (Test-PimAutoDestructiveEnabled -Feature 'GroupRetirement')        | Should -BeFalse  # explicit OFF beats test default
            # an old 'Report' value is an EXPLICIT (non-empty) setting -> falsy, stays OFF even in test
            $global:PIM_EnableGroupRetirement = 'Report'
            (Test-PimAutoDestructiveEnabled -Feature 'GroupRetirement')        | Should -BeFalse
        } finally {
            foreach ($n in @('PIM_EnableAutomaticOffboarding','PIM_EnableGroupRetirement','PIM_EnableMembershipDriftCleanup')) {
                Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue
            }
            $global:PIM_TestTenantIds = $savedTid; $global:PIM_TenantId = $savedConn
        }
    }
    It 'Invoke-PimGroupRetirement returns the gate-SKIP message (and never proceeds) unless explicitly opted in' {
        Remove-Variable -Name PIM_EnableGroupRetirement -Scope Global -ErrorAction SilentlyContinue
        # The disabled path returns immediately with a single DISABLED message and NEVER
        # reaches the "retiring ..." work. Capture host output via 6>&1.
        $out = (Invoke-PimGroupRetirement 6>&1 | Out-String)
        $out | Should -Match 'DISABLED \(operator policy\)'
        $out | Should -Not -Match 'retiring'
        Remove-Variable -Name PIM_EnableGroupRetirement -Scope Global -ErrorAction SilentlyContinue
    }
    It 'Invoke-PimMembershipDriftCleanup returns the gate-SKIP message even with OffboardCleanupMode=Enforce, unless opted in' {
        Remove-Variable -Name PIM_EnableMembershipDriftCleanup -Scope Global -ErrorAction SilentlyContinue
        $global:PIM_OffboardCleanupMode = 'Enforce'   # even Enforce must not run while the master gate is OFF
        try {
            $out = (Invoke-PimMembershipDriftCleanup 6>&1 | Out-String)
            $out | Should -Match 'DISABLED \(operator policy\)'
            $out | Should -Not -Match 'Membership drift sweep'   # never reaches the actual sweep
        } finally {
            Remove-Variable -Name PIM_EnableMembershipDriftCleanup -Scope Global -ErrorAction SilentlyContinue
            $global:PIM_OffboardCleanupMode = $null
        }
    }

    # --- ACCOUNT-DISABLE CIRCUIT BREAKER (incident 2026-06-15) -----------------------
    # The 'Admins' provider disables accounts (accountEnabled=$false) for live users not
    # in the desired admin set, and its GetLive is the whole tenant -> an empty/wrong
    # desired set once disabled the entire scanned population. These prove the 3 guards.
    Context 'Account-disable circuit breaker (PIM-DisableGuard)' {
        It 'G3: account-disable feature is OFF by default and parses the opt-in' {
            $global:PIM_AccountDisableEnabled = $null
            Test-PimAccountDisableEnabled | Should -BeFalse
            Test-PimAccountDisableEnabled -Override $true | Should -BeTrue
            Test-PimAccountDisableEnabled -Override 'enabled' | Should -BeTrue
            Test-PimAccountDisableEnabled -Override 'no' | Should -BeFalse
        }
        It 'G1: empty / read-failed desired set is treated as unresolved (no disable)' {
            Test-PimDesiredSetResolved -Desired @() | Should -BeFalse
            Test-PimDesiredSetResolved -Desired @([pscustomobject]@{x=1}) -Resolved $false | Should -BeFalse
            Test-PimDesiredSetResolved -Desired @([pscustomobject]@{x=1}) -Resolved $true | Should -BeTrue
        }
        It 'G2: mass-disable breaker trips on absolute + percent caps (the 53/53 incident aborts)' {
            (Test-PimMassDisableSafe -ToDisable 3 -Scanned 100 -MaxCount 5 -MaxPercent 0).abort | Should -BeFalse
            (Test-PimMassDisableSafe -ToDisable 6 -Scanned 1000 -MaxCount 5 -MaxPercent 0).abort | Should -BeTrue
            (Test-PimMassDisableSafe -ToDisable 3 -Scanned 10 -MaxCount 100 -MaxPercent 10).abort | Should -BeTrue
            (Test-PimMassDisableSafe -ToDisable 53 -Scanned 53).abort | Should -BeTrue
        }
        It 'composite decision: allowed ONLY when opted-in AND resolved AND within blast radius' {
            (Test-PimDisablePassAllowed -ToDisable 1 -Scanned 100 -Desired @([pscustomobject]@{x=1}) -DesiredResolved $true -FeatureOverride $false).tripped | Should -Be 'feature-off'
            (Test-PimDisablePassAllowed -ToDisable 1 -Scanned 100 -Desired @() -DesiredResolved $false -FeatureOverride $true).tripped | Should -Be 'empty-desired'
            (Test-PimDisablePassAllowed -ToDisable 53 -Scanned 53 -Desired @([pscustomobject]@{x=1}) -DesiredResolved $true -FeatureOverride $true).tripped | Should -Be 'mass-disable'
            (Test-PimDisablePassAllowed -ToDisable 1 -Scanned 100 -Desired @([pscustomobject]@{x=1}) -DesiredResolved $true -FeatureOverride $true).allowed | Should -BeTrue
        }
        It 'the Admins provider is flagged isAccountDisable (routed through the breaker)' {
            Register-PimDefaultEngineProviders
            (Get-PimEngineProvider -Scope 'Admins').isAccountDisable | Should -BeTrue
        }
        It 'engine: reproduces the 06:00 condition (whole-tenant remove) and disables NOTHING' {
            $script:__disabled = 0
            $script:__bkTenant = @(1..53 | ForEach-Object { [pscustomobject]@{ upn=("u{0}@x" -f $_); enabled=$true } })
            function Register-BreakerProvider {
                param($Desired,$Resolved,$Feature)
                Register-PimEngineProvider -Provider @{
                    scope='AdminsBreakerTest'; entity='Account-Definitions-Admins'; isAccountDisable=$true; disableFeatureOverride=$Feature
                    GetDesired={ param($ctx) $Desired }.GetNewClosure(); GetLive={ param($ctx) $script:__bkTenant }
                    KeyOf={ param($r) "$($r.upn)" }; Equal={ param($d,$l) [bool]$l.enabled }
                    ApplyCreate={ param($i,$c) }; ApplyUpdate={ param($i,$c) }; ApplyRemove={ param($i,$c) $script:__disabled++ }
                }
                if ($null -eq $global:PIM_DesiredResolved -or -not ($global:PIM_DesiredResolved -is [hashtable])) { $global:PIM_DesiredResolved=@{} }
                $global:PIM_DesiredResolved['Account-Definitions-Admins']=$Resolved
            }
            # wrong/non-empty desired -> 53 would be disabled -> breaker aborts whole pass
            Register-BreakerProvider -Desired @([pscustomobject]@{ upn='other@x'; enabled=$true }) -Resolved $true -Feature $true
            $r = Invoke-PimEngineScope -Scope 'AdminsBreakerTest' -Mode Full -Prune
            $script:__disabled | Should -Be 0
            $r.disableAborted | Should -Be 'mass-disable'
            # feature OFF -> even a single legit removal disables nothing
            $script:__disabled = 0
            $desired52 = @($script:__bkTenant | Select-Object -First 52 | ForEach-Object { [pscustomobject]@{ upn=$_.upn; enabled=$true } })
            Register-BreakerProvider -Desired $desired52 -Resolved $true -Feature $false
            (Invoke-PimEngineScope -Scope 'AdminsBreakerTest' -Mode Full -Prune).disableAborted | Should -Be 'feature-off'
            $script:__disabled | Should -Be 0
            # feature ON + 1 genuinely-offboarded + within caps -> the legit path disables exactly 1
            $script:__disabled = 0
            Register-BreakerProvider -Desired $desired52 -Resolved $true -Feature $true
            $rok = Invoke-PimEngineScope -Scope 'AdminsBreakerTest' -Mode Full -Prune
            $script:__disabled | Should -Be 1
            $rok.disableAborted | Should -BeNullOrEmpty
            $global:PIM_DesiredResolved = $null; $global:PIM_AccountDisableEnabled = $null
        }
    }

    # --- §6 Engine-Core: Hybrid on-prem AD provisioning + gMSA/sMSA (PLANNER + seam) ---
    # The cloud engine is cloud-only at runtime; these test the PURE planner + the
    # execution seam (with a FAKE adapter). The real on-prem ActiveDirectory write is
    # hybrid-worker-only and is NOT exercised here (flagged in DESIGN/REQUIREMENTS).
    It 'Get-PimHybridAdRowKind + Get-PimHybridAdAccountName: gMSA/sMSA detected and $-suffixed idempotently' {
        (Get-PimHybridAdRowKind -Row ([pscustomobject]@{ UserName='svc-backup-gMSA' })) | Should -Be 'gmsa'
        (Get-PimHybridAdRowKind -Row ([pscustomobject]@{ UserName='legacy-sMSA-01' }))  | Should -Be 'smsa'
        (Get-PimHybridAdRowKind -Row ([pscustomobject]@{ UserName='Admin-ABC-AD' }))    | Should -Be 'standard'
        # explicit column wins over name heuristic
        (Get-PimHybridAdRowKind -Row ([pscustomobject]@{ UserName='svc-gMSA'; AdAccountKind='Standard' })) | Should -Be 'standard'
        # $ appended for managed accounts, idempotent; never for standard
        (Get-PimHybridAdAccountName -Row ([pscustomobject]@{ UserName='svc-x-gMSA' }))   | Should -Be 'svc-x-gMSA$'
        (Get-PimHybridAdAccountName -Row ([pscustomobject]@{ UserName='svc-y-gMSA$' }))  | Should -Be 'svc-y-gMSA$'
        (Get-PimHybridAdAccountName -Row ([pscustomobject]@{ UserName='Admin-ABC-AD' })) | Should -Be 'Admin-ABC-AD'
    }
    It 'Resolve-PimHybridAdTargetOu routes HighPriv/L0-T0 to PathAdminsL0T0, else PathAdmins; blank stays blank' {
        $pa='OU=Admins,DC=casa,DC=dk'; $pal='OU=T0,DC=casa,DC=dk'
        (Resolve-PimHybridAdTargetOu -Row ([pscustomobject]@{ UserName='Admin-ABC-AD'; Purpose='Day2Day' }) -PathAdmins $pa -PathAdminsL0T0 $pal) | Should -Be $pa
        (Resolve-PimHybridAdTargetOu -Row ([pscustomobject]@{ UserName='Admin-ABC-AD'; Purpose='HighPriv' }) -PathAdmins $pa -PathAdminsL0T0 $pal) | Should -Be $pal
        # blank Purpose -> L0/T0 name marker drives routing (legacy v2.4.171 fallback)
        (Resolve-PimHybridAdTargetOu -Row ([pscustomobject]@{ UserName='Admin-SKR-L0-T0-AD' }) -PathAdmins $pa -PathAdminsL0T0 $pal) | Should -Be $pal
        (Resolve-PimHybridAdTargetOu -Row ([pscustomobject]@{ UserName='Admin-NOOU-AD'; Purpose='Day2Day' }) -PathAdmins '' -PathAdminsL0T0 '') | Should -Be ''
    }
    It 'Get-PimHybridAdSearchRoot derives LDAP root from Domain / UPN suffix; explicit SearchRoot wins' {
        (Get-PimHybridAdSearchRoot -Row ([pscustomobject]@{}) -Domain 'casa.dk').searchRoot | Should -Be 'LDAP://DC=casa,DC=dk'
        (Get-PimHybridAdSearchRoot -Row ([pscustomobject]@{ UserPrincipalName='svc@corp.example.com' })).searchRoot | Should -Be 'LDAP://DC=corp,DC=example,DC=com'
        (Get-PimHybridAdSearchRoot -Row ([pscustomobject]@{ SearchRoot='LDAP://OU=svc,DC=x,DC=y' }) -Domain 'x.y').searchRoot | Should -Be 'LDAP://OU=svc,DC=x,DC=y'
    }
    It 'ConvertTo-PimHybridAdDesired only emits AD-platform, non-Remove rows; stamps kind/ou/managed-pw' {
        (ConvertTo-PimHybridAdDesired -Row ([pscustomobject]@{ UserName='Admin-CLOUD-ID'; TargetPlatform='ID' })) | Should -BeNullOrEmpty
        (ConvertTo-PimHybridAdDesired -Row ([pscustomobject]@{ UserName='Admin-X-AD'; TargetPlatform='AD'; Action='Remove' })) | Should -BeNullOrEmpty
        $d = ConvertTo-PimHybridAdDesired -Row ([pscustomobject]@{ UserName='svc-x-gMSA'; TargetPlatform='AD'; UserPrincipalName='svc@casa.dk'; Purpose='HighPriv' }) -PathAdmins 'OU=A,DC=casa,DC=dk' -PathAdminsL0T0 'OU=T0,DC=casa,DC=dk'
        $d.samAccountName | Should -Be 'svc-x-gMSA$'
        $d.accountKind    | Should -Be 'gmsa'
        $d.isHighPriv     | Should -BeTrue
        $d.targetOu       | Should -Be 'OU=T0,DC=casa,DC=dk'
        [bool]$d.requiresManagedPassword | Should -BeTrue
    }
    It 'Compare-PimHybridAdState is idempotent: create new, update changed, nochange identical; gMSA existence-only' {
        $desired = @(
            (ConvertTo-PimHybridAdDesired -Row ([pscustomobject]@{ UserName='Admin-NEW-AD'; TargetPlatform='AD'; UserPrincipalName='new@casa.dk' }) -PathAdmins 'OU=A,DC=casa,DC=dk'),
            (ConvertTo-PimHybridAdDesired -Row ([pscustomobject]@{ UserName='Admin-CHG-AD'; TargetPlatform='AD'; DisplayName='New'; UserPrincipalName='chg@casa.dk' }) -PathAdmins 'OU=A,DC=casa,DC=dk'),
            (ConvertTo-PimHybridAdDesired -Row ([pscustomobject]@{ UserName='Admin-SAME-AD'; TargetPlatform='AD'; DisplayName='Same'; UserPrincipalName='same@casa.dk' }) -PathAdmins 'OU=A,DC=casa,DC=dk'),
            (ConvertTo-PimHybridAdDesired -Row ([pscustomobject]@{ UserName='svc-gMSA'; TargetPlatform='AD'; DisplayName='whatever'; UserPrincipalName='svc@casa.dk' }) -PathAdmins 'OU=A,DC=casa,DC=dk')
        )
        $live = @(
            [pscustomobject]@{ SamAccountName='Admin-CHG-AD'; DisplayName='Old'; UserPrincipalName='chg@casa.dk' },
            [pscustomobject]@{ SamAccountName='Admin-SAME-AD'; DisplayName='Same'; UserPrincipalName='same@casa.dk' },
            [pscustomobject]@{ SamAccountName='svc-gMSA$'; DisplayName='ignored-attr-drift'; UserPrincipalName='other@casa.dk' }
        )
        $diff = Compare-PimHybridAdState -Desired $desired -Live $live
        @($diff.create).Count   | Should -Be 1   # Admin-NEW-AD
        @($diff.update).Count   | Should -Be 1   # Admin-CHG-AD
        @($diff.nochange).Count | Should -Be 2   # Admin-SAME-AD + the gMSA (existence-only, attr drift ignored)
    }
    It 'Get-PimHybridAdPlan: OU-less create becomes a Skip with a clear reason; summary counts' {
        $rows = @(
            [pscustomobject]@{ UserName='Admin-OK-AD'; TargetPlatform='AD'; UserPrincipalName='ok@casa.dk'; Purpose='Day2Day' },
            [pscustomobject]@{ UserName='Admin-NOOU-AD'; TargetPlatform='AD'; UserPrincipalName='no@casa.dk'; Purpose='Day2Day' }
        )
        # PathAdmins supplied so OK routes, but NOOU is identical Purpose -> both route to OU; make NOOU high-priv with no L0T0 path
        $rows[1] = [pscustomobject]@{ UserName='Admin-NOOU-AD'; TargetPlatform='AD'; UserPrincipalName='no@casa.dk'; Purpose='HighPriv' }
        $plan = Get-PimHybridAdPlan -AdminRows $rows -Live @() -PathAdmins 'OU=A,DC=casa,DC=dk' -PathAdminsL0T0 ''
        $plan.summary.desired | Should -Be 2
        @($plan.workItems | Where-Object { $_.op -eq 'Create' }).Count | Should -Be 1
        $skip = @($plan.workItems | Where-Object { $_.op -eq 'Skip' })
        $skip.Count | Should -Be 1
        $skip[0].samAccountName | Should -Be 'Admin-NOOU-AD'
        $skip[0].skipReason | Should -Match 'OU empty'
    }
    It 'Export/Import-PimHybridAdWorkPackage round-trips intent only (no secrets/live AD) as UTF8' {
        $plan = Get-PimHybridAdPlan -AdminRows @([pscustomobject]@{ UserName='Admin-PKG-AD'; TargetPlatform='AD'; UserPrincipalName='pkg@casa.dk' }) -Live @() -PathAdmins 'OU=A,DC=casa,DC=dk'
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pim-hybrid-pkg-" + [guid]::NewGuid().ToString('N') + ".json")
        try {
            Export-PimHybridAdWorkPackage -Plan $plan -Path $tmp | Out-Null
            $bytes = [System.IO.File]::ReadAllBytes($tmp)
            # not UTF-16 (no 0xFF 0xFE BOM, no interleaved nulls)
            ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) | Should -BeFalse
            $pkg = Import-PimHybridAdWorkPackage -Path $tmp
            $pkg.kind | Should -Be 'PimHybridAdWorkPackage'
            @($pkg.workItems).Count | Should -Be 1
            $pkg.workItems[0].samAccountName | Should -Be 'Admin-PKG-AD'
        } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
    }
    It 'Invoke-PimHybridAdApply: pure plan by default (no writes); with -Apply + fake adapter routes create/update/gMSA; no-cred = skip' {
        $rows = @(
            [pscustomobject]@{ UserName='Admin-NEW-AD'; TargetPlatform='AD'; UserPrincipalName='new@casa.dk'; Purpose='Day2Day' },
            [pscustomobject]@{ UserName='Admin-UPD-AD'; TargetPlatform='AD'; DisplayName='Changed'; UserPrincipalName='upd@casa.dk'; Purpose='Day2Day' },
            [pscustomobject]@{ UserName='svc-x-gMSA'; TargetPlatform='AD'; UserPrincipalName='svc@casa.dk'; Purpose='Day2Day' }
        )
        $live = @([pscustomobject]@{ SamAccountName='Admin-UPD-AD'; DisplayName='Old'; UserPrincipalName='upd@casa.dk' })
        $plan = Get-PimHybridAdPlan -AdminRows $rows -Live $live -PathAdmins 'OU=A,DC=casa,DC=dk'
        # default = pure plan, zero writes
        $script:adCalls = New-Object System.Collections.Generic.List[string]
        $preview = Invoke-PimHybridAdApply -Plan $plan
        $preview.applied | Should -BeFalse
        @($preview.results | Where-Object { $_.status -eq 'plan' }).Count | Should -Be 3
        $script:adCalls.Count | Should -Be 0
        # -Apply with fake adapter (the SEAM; no AD module needed)
        $fake = @{
            GetUser = { param($s,$c) if ($s -eq 'Admin-UPD-AD') { [pscustomobject]@{ SamAccountName=$s } } else { $null } }
            NewUser = { param($i,$c,$pw) $script:adCalls.Add('new:' + $i.samAccountName) }
            SetUser = { param($i,$l,$c) $script:adCalls.Add('set:' + $i.samAccountName) }
            GetManagedCredential = { param($i,$ctx) $script:adCalls.Add('gmsa:' + $i.samAccountName); [pscustomobject]@{ UserName=$i.samAccountName } }
        }
        $ss = New-Object System.Security.SecureString; 'x'.ToCharArray() | ForEach-Object { $ss.AppendChar($_) }
        $cred = New-Object System.Management.Automation.PSCredential('CASA\svc', $ss)
        $res = Invoke-PimHybridAdApply -Plan $plan -Apply -ActiveDirectoryAdapter $fake -Credential $cred -NewPassword { New-Object System.Security.SecureString }
        $res.applied | Should -BeTrue
        ($res.results | Where-Object { $_.samAccountName -eq 'Admin-NEW-AD' }).status | Should -Be 'created'
        ($res.results | Where-Object { $_.samAccountName -eq 'Admin-UPD-AD' }).status | Should -Be 'updated'
        ($res.results | Where-Object { $_.samAccountName -eq 'svc-x-gMSA$' }).status  | Should -Be 'resolved'
        ($script:adCalls -join ',') | Should -Match 'new:Admin-NEW-AD'
        ($script:adCalls -join ',') | Should -Match 'gmsa:svc-x-gMSA\$'
        # gMSA must NOT be created via New-ADUser
        ($script:adCalls -join ',') | Should -Not -Match 'new:svc-x-gMSA'
        # -Apply WITHOUT a credential -> skip the whole AD branch, never run as ambient SYSTEM
        $res2 = Invoke-PimHybridAdApply -Plan $plan -Apply -ActiveDirectoryAdapter $fake
        $res2.applied | Should -BeFalse
        @($res2.results | Where-Object { $_.status -eq 'skipped' }).Count | Should -Be @($plan.workItems).Count
    }
    It 'Invoke-PimHybridAdApply surfaces the REAL Get-ADUser error and does NOT cascade into a create' {
        $rows = @([pscustomobject]@{ UserName='Admin-ERR-AD'; TargetPlatform='AD'; UserPrincipalName='err@casa.dk'; Purpose='Day2Day' })
        $plan = Get-PimHybridAdPlan -AdminRows $rows -Live @() -PathAdmins 'OU=A,DC=casa,DC=dk'
        $script:createTried = $false
        $fake = @{
            GetUser = { param($s,$c) throw 'Cannot contact domain controller (kerberos)' }
            NewUser = { param($i,$c,$pw) $script:createTried = $true }
            SetUser = { param($i,$l,$c) }
            GetManagedCredential = { param($i,$ctx) }
        }
        $ss = New-Object System.Security.SecureString; 'x'.ToCharArray() | ForEach-Object { $ss.AppendChar($_) }
        $cred = New-Object System.Management.Automation.PSCredential('CASA\svc', $ss)
        $res = Invoke-PimHybridAdApply -Plan $plan -Apply -ActiveDirectoryAdapter $fake -Credential $cred
        ($res.results | Where-Object { $_.samAccountName -eq 'Admin-ERR-AD' }).status | Should -Be 'failed'
        ($res.results | Where-Object { $_.samAccountName -eq 'Admin-ERR-AD' }).reason | Should -Match 'domain controller'
        $script:createTried | Should -BeFalse   # failed read never cascades to New-ADUser
    }
    It 'HybridAdProvisioning provider: registers at order 95, gated Off by default, never writes AD (planner only)' {
        Register-PimDefaultEngineProviders
        $prov = Get-PimEngineProvider -Scope 'HybridAdProvisioning'
        $prov | Should -Not -BeNullOrEmpty
        $prov.order | Should -Be 95
        (New-PimHybridAdProvider).entity | Should -Be 'Account-Definitions-Admins'
        # Off (default) -> empty desired (no plan produced)
        $ctx = @{}
        $global:PIM_HybridAdMode = $null
        @(& $prov.GetDesired $ctx).Count | Should -Be 0
        # Plan mode -> desired AD records produced from the admin rows; GetLive is always empty
        $global:PIM_DesiredRows = @{ 'Account-Definitions-Admins' = @([pscustomobject]@{ UserName='Admin-P-AD'; TargetPlatform='AD'; UserPrincipalName='p@casa.dk'; Purpose='Day2Day' }) }
        $global:PIM_NamingConventions = @{ PathAdmins='OU=A,DC=casa,DC=dk'; PathAdminsL0T0='OU=T0,DC=casa,DC=dk' }
        $global:PIM_HybridAdMode = 'Plan'
        $ctx2 = @{}
        $des = @(& $prov.GetDesired $ctx2)
        $des.Count | Should -Be 1
        $des[0].samAccountName | Should -Be 'Admin-P-AD'
        @(& $prov.GetLive $ctx2).Count | Should -Be 0   # cloud engine has NO DC line-of-sight
        $ctx2['hybridAdPlan'] | Should -Not -BeNullOrEmpty
        $global:PIM_DesiredRows = $null; $global:PIM_NamingConventions = $null; $global:PIM_HybridAdMode = $null
    }

    # --- §7 Providers/Connectors: Defender XDR + Intune workload-RBAC providers ---
    It 'DefenderXdrRoles + IntuneRoles register after AzRes, before GroupsPolicies, with the right entities' {
        Register-PimDefaultEngineProviders
        $scopes = @(Get-PimEngineScopes)
        $scopes -contains 'DefenderXdrRoles' | Should -BeTrue
        $scopes -contains 'IntuneRoles'      | Should -BeTrue
        $scopes.IndexOf('AzRes')            | Should -BeLessThan $scopes.IndexOf('DefenderXdrRoles')
        $scopes.IndexOf('DefenderXdrRoles') | Should -BeLessThan $scopes.IndexOf('IntuneRoles')
        $scopes.IndexOf('IntuneRoles')      | Should -BeLessThan $scopes.IndexOf('GroupsPolicies')
        (Get-PimEngineProvider -Scope 'DefenderXdrRoles').entity | Should -Be 'PIM-Assignments-Defender'
        (Get-PimEngineProvider -Scope 'IntuneRoles').entity      | Should -Be 'PIM-Assignments-Intune'
        (New-PimDefenderXdrRolesProvider).order | Should -Be 62
        (New-PimIntuneRolesProvider).order      | Should -Be 64
    }
    It 'Get-PimDefenderRoleKey / Get-PimIntuneRoleKey key by group|role (case-insensitive, tag fallback)' {
        $kd1 = Get-PimDefenderRoleKey -Row ([pscustomobject]@{ principalId='G1'; RoleDefinitionName='Security Operator' })
        $kd2 = Get-PimDefenderRoleKey -Row ([pscustomobject]@{ principalId='g1'; RoleName='security operator' })
        $kd1 | Should -Be 'g1|security operator'
        $kd1 | Should -Be $kd2
        # desired (no principalId yet) falls back to the tag form -> won't match a live key -> create
        (Get-PimDefenderRoleKey -Row ([pscustomobject]@{ GroupTag='Defender-X'; RoleDefinitionName='Security Reader' })) | Should -Be 'tag:defender-x|security reader'
        $ki = Get-PimIntuneRoleKey -Row ([pscustomobject]@{ principalId='G2'; RoleDefinitionName='Help Desk Operator' })
        $ki | Should -Be 'g2|help desk operator'
    }
    It 'DefenderXdrRoles GetDesired drops Action=Remove + rows missing a group or role' {
        $global:PIM_DesiredRows = @{
            'PIM-Definitions-Services' = @([pscustomobject]@{ GroupName='PIM-Sec'; GroupTag='Defender-SecOp' })
            'PIM-Assignments-Defender' = @(
                [pscustomobject]@{ GroupTag='Defender-SecOp'; RoleDefinitionName='Security Operator'; AssignmentType='Active' },
                [pscustomobject]@{ GroupTag='Defender-SecOp'; RoleDefinitionName='Security Reader';   AssignmentType='Active'; Action='Remove' },
                [pscustomobject]@{ GroupTag='';               RoleDefinitionName='Security Reader';   AssignmentType='Active' },
                [pscustomobject]@{ GroupTag='Defender-SecOp'; RoleDefinitionName='';                  AssignmentType='Active' }) }
        try {
            $prov = New-PimDefenderXdrRolesProvider
            $desired = @(& $prov.GetDesired @{})
            $desired.Count | Should -Be 1
            (Get-PimRowProp -Row $desired[0] -Names @('RoleDefinitionName')) | Should -Be 'Security Operator'
        } finally { $global:PIM_DesiredRows = $null }
    }
    It 'IntuneRoles GetDesired drops Action=Remove + rows missing a group or role' {
        $global:PIM_DesiredRows = @{
            'PIM-Definitions-Services' = @([pscustomobject]@{ GroupName='PIM-Int'; GroupTag='Intune-HD' })
            'PIM-Assignments-Intune'   = @(
                [pscustomobject]@{ GroupTag='Intune-HD'; RoleDefinitionName='Help Desk Operator'; AssignmentType='Active' },
                [pscustomobject]@{ GroupTag='Intune-HD'; RoleDefinitionName='Application Manager'; AssignmentType='Active'; Action='Remove' },
                [pscustomobject]@{ GroupTag='';          RoleDefinitionName='Read Only Operator'; AssignmentType='Active' }) }
        try {
            $prov = New-PimIntuneRolesProvider
            $desired = @(& $prov.GetDesired @{})
            $desired.Count | Should -Be 1
            (Get-PimRowProp -Row $desired[0] -Names @('RoleDefinitionName')) | Should -Be 'Help Desk Operator'
        } finally { $global:PIM_DesiredRows = $null }
    }
    It 'Resolve-PimIntuneScopeTagIds maps names -> ids, passes numeric ids through, drops unknowns, blank -> empty' {
        $map = @{ 'default'='0'; 'production'='3' }
        @(Resolve-PimIntuneScopeTagIds -Raw 'Default|Production' -NameToId $map)            | Should -Be @('0','3')
        @(Resolve-PimIntuneScopeTagIds -Raw '5;Production'       -NameToId $map)            | Should -Be @('5','3')   # numeric passthrough
        @(Resolve-PimIntuneScopeTagIds -Raw 'Default|Nope'       -NameToId $map).Count      | Should -Be 1            # unknown dropped
        @(Resolve-PimIntuneScopeTagIds -Raw ''                   -NameToId $map).Count      | Should -Be 0
    }
    It 'DefenderXdrRoles is existence-based (Equal => nochange when the group already holds the role)' {
        $prov = New-PimDefenderXdrRolesProvider
        $desired = @([pscustomobject]@{ principalId='G1'; RoleDefinitionName='Security Operator' })
        $live    = @([pscustomobject]@{ principalId='G1'; RoleDefinitionName='Security Operator'; assignmentId='a1' })
        $diff = Compare-PimDesiredVsLive -Desired $desired -Live $live -KeyOf $prov.KeyOf -Equal $prov.Equal -Prune
        $diff.nochange.Count | Should -Be 1
        $diff.create.Count   | Should -Be 0
        $diff.remove.Count   | Should -Be 0
        # a live role NOT desired is pruned (Full+Prune)
        $live2 = @([pscustomobject]@{ principalId='G1'; RoleDefinitionName='Security Reader'; assignmentId='a2' })
        $diff2 = Compare-PimDesiredVsLive -Desired $desired -Live $live2 -KeyOf $prov.KeyOf -Equal $prov.Equal -Prune
        $diff2.create.Count | Should -Be 1   # Security Operator desired, absent live
        $diff2.remove.Count | Should -Be 1   # Security Reader live, not desired
    }
    It 'IntuneRoles ApplyCreate builds a deviceAndAppManagementRoleAssignment for the group with scope tags' {
        $prov = New-PimIntuneRolesProvider
        $captured = $null
        function Invoke-PimGraph { param([string]$Method,[string]$Path,$Body,[switch]$All,[switch]$Beta,[hashtable]$Headers) $script:__cap = @{ Method=$Method; Path=$Path; Body=$Body }; @{ id='new' } }
        $ctx = @{ intGid=@{ 'intune-hd'='GID-1' }; intRoleNameToId=@{ 'help desk operator'='RID-9' }; intScopeTagNameToId=@{ 'default'='0' } }
        $item = @{ key='gid-1|help desk operator'; desired=[pscustomobject]@{ GroupTag='Intune-HD'; RoleDefinitionName='Help Desk Operator'; ScopeTags='Default'; MemberScope='Tagged' } }
        & $prov.ApplyCreate $item $ctx | Out-Null
        $script:__cap.Method | Should -Be 'POST'
        $script:__cap.Path   | Should -Match '/deviceManagement/roleDefinitions/RID-9/roleAssignments'
        $script:__cap.Body.'@odata.type' | Should -Be '#microsoft.graph.deviceAndAppManagementRoleAssignment'
        @($script:__cap.Body.members) -contains 'GID-1' | Should -BeTrue
        @($script:__cap.Body.roleScopeTagIds) -contains '0' | Should -BeTrue
        $script:__cap.Body.scopeType | Should -Be 'resourceScope'
        Remove-Item function:Invoke-PimGraph -ErrorAction SilentlyContinue
    }
    It 'DefenderXdrRoles ApplyCreate posts a defender roleAssignment with the group as principal (beta)' {
        $prov = New-PimDefenderXdrRolesProvider
        function Invoke-PimGraph { param([string]$Method,[string]$Path,$Body,[switch]$All,[switch]$Beta,[hashtable]$Headers) $script:__capd = @{ Method=$Method; Path=$Path; Body=$Body; Beta=[bool]$Beta }; @{ id='new' } }
        $ctx = @{ defGid=@{ 'defender-secop'='GID-7' }; defRoleNameToId=@{ 'security operator'='RID-2' } }
        $item = @{ key='gid-7|security operator'; desired=[pscustomobject]@{ GroupTag='Defender-SecOp'; RoleDefinitionName='Security Operator' } }
        & $prov.ApplyCreate $item $ctx | Out-Null
        $script:__capd.Method | Should -Be 'POST'
        $script:__capd.Beta   | Should -BeTrue
        $script:__capd.Path   | Should -Match '/roleManagement/defender/roleAssignments'
        @($script:__capd.Body.principalIds) -contains 'GID-7' | Should -BeTrue
        $script:__capd.Body.roleDefinitionId | Should -Be 'RID-2'
        Remove-Item function:Invoke-PimGraph -ErrorAction SilentlyContinue
    }

    # --- §7 Providers/Connectors: generic enterprise-app app-role connector (entra-approle) ---
    It 'EntraAppRole registers after IntuneRoles, before GroupsPolicies, with the right entity + order' {
        Register-PimDefaultEngineProviders
        $scopes = @(Get-PimEngineScopes)
        $scopes -contains 'EntraAppRole' | Should -BeTrue
        $scopes.IndexOf('IntuneRoles')   | Should -BeLessThan $scopes.IndexOf('EntraAppRole')
        $scopes.IndexOf('EntraAppRole')  | Should -BeLessThan $scopes.IndexOf('GroupsPolicies')
        (Get-PimEngineProvider -Scope 'EntraAppRole').entity | Should -Be 'PIM-Assignments-AppRole'
        (New-PimEntraAppRoleProvider).order | Should -Be 66
    }
    It 'Get-PimAppRoleKey keys by group|app|approle (case-insensitive, tag + appId fallback, default-access normalises)' {
        # resolved form (principalId + resourceSpId + appRoleId)
        $k1 = Get-PimAppRoleKey -Row ([pscustomobject]@{ principalId='G1'; resourceSpId='SP1'; appRoleId='AR1' })
        $k2 = Get-PimAppRoleKey -Row ([pscustomobject]@{ principalId='g1'; resourceSpId='sp1'; appRoleId='ar1' })
        $k1 | Should -Be 'g1|sp1|ar1'
        $k1 | Should -Be $k2
        # desired (tag + appId + role value, no ids yet) -> tag/appid fallback (won't match a live key -> create)
        (Get-PimAppRoleKey -Row ([pscustomobject]@{ GroupTag='AppRole-X'; AppId='APPID-9'; AppRole='User' })) | Should -Be 'tag:approle-x|appid:appid-9|user'
        # blank / 'Default Access' role value -> the all-zeros default app-role id
        (Get-PimAppRoleKey -Row ([pscustomobject]@{ GroupTag='AppRole-X'; AppDisplayName='Contoso HR'; AppRole='' }))             | Should -Be 'tag:approle-x|app:contoso hr|00000000-0000-0000-0000-000000000000'
        (Get-PimAppRoleKey -Row ([pscustomobject]@{ GroupTag='AppRole-X'; AppDisplayName='Contoso HR'; AppRole='Default Access' })) | Should -Be 'tag:approle-x|app:contoso hr|00000000-0000-0000-0000-000000000000'
    }
    It 'Resolve-PimAppRoleId resolves by value + displayName (case-insensitive), default-access -> zeros, throws on unknown' {
        $appRoles = @(
            [pscustomobject]@{ id='AR-USER';  value='User';  displayName='Default user access' },
            [pscustomobject]@{ id='AR-ADMIN'; value='Admin'; displayName='Administrator' })
        (Resolve-PimAppRoleId -Value 'User'  -AppRoles $appRoles) | Should -Be 'AR-USER'
        (Resolve-PimAppRoleId -Value 'admin' -AppRoles $appRoles) | Should -Be 'AR-ADMIN'        # case-insensitive value
        (Resolve-PimAppRoleId -Value 'Administrator' -AppRoles $appRoles) | Should -Be 'AR-ADMIN' # displayName fallback
        (Resolve-PimAppRoleId -Value ''      -AppRoles $appRoles) | Should -Be '00000000-0000-0000-0000-000000000000'  # blank -> default
        (Resolve-PimAppRoleId -Value 'Default Access' -AppRoles $appRoles) | Should -Be '00000000-0000-0000-0000-000000000000'
        { Resolve-PimAppRoleId -Value 'Nope' -AppRoles $appRoles } | Should -Throw -ExpectedMessage '*app role*not found*'
    }
    It 'New-PimAppRoleAssignmentBody shapes the appRoleAssignedTo body (principal=group, resource=SP, appRoleId)' {
        $b = New-PimAppRoleAssignmentBody -PrincipalId 'GID' -ResourceSpId 'SPID' -AppRoleId 'ARID'
        $b.principalId | Should -Be 'GID'
        $b.resourceId  | Should -Be 'SPID'
        $b.appRoleId   | Should -Be 'ARID'
    }
    It 'EntraAppRole GetDesired drops Action=Remove + rows missing a group or any app identifier' {
        $global:PIM_DesiredRows = @{
            'PIM-Definitions-Services' = @([pscustomobject]@{ GroupName='PIM-App'; GroupTag='AppRole-HR' })
            'PIM-Assignments-AppRole'  = @(
                [pscustomobject]@{ GroupTag='AppRole-HR'; AppDisplayName='Contoso HR'; AppRole='User' },                 # valid (app by name)
                [pscustomobject]@{ GroupTag='AppRole-HR'; AppId='APPID-2';            AppRole='Admin'; Action='Remove' },# dropped (Remove)
                [pscustomobject]@{ GroupTag='';           AppDisplayName='Contoso HR'; AppRole='User' },                 # dropped (no group)
                [pscustomobject]@{ GroupTag='AppRole-HR'; AppRole='User' }) }                                            # dropped (no app id)
        try {
            $prov = New-PimEntraAppRoleProvider
            $desired = @(& $prov.GetDesired @{})
            $desired.Count | Should -Be 1
            (Get-PimRowProp -Row $desired[0] -Names @('AppDisplayName')) | Should -Be 'Contoso HR'
        } finally { $global:PIM_DesiredRows = $null }
    }
    It 'EntraAppRole is existence-based + idempotent (no duplicate assign; live-only pruned under Full+Prune)' {
        $prov = New-PimEntraAppRoleProvider
        $desired = @([pscustomobject]@{ principalId='G1'; resourceSpId='SP1'; appRoleId='AR1' })
        $live    = @([pscustomobject]@{ principalId='G1'; resourceSpId='SP1'; appRoleId='AR1'; assignmentId='x1' })
        $diff = Compare-PimDesiredVsLive -Desired $desired -Live $live -KeyOf $prov.KeyOf -Equal $prov.Equal -Prune
        $diff.nochange.Count | Should -Be 1   # already assigned -> NO duplicate POST
        $diff.create.Count   | Should -Be 0
        $diff.remove.Count   | Should -Be 0
        # a live app-role assignment not desired is pruned (Full+Prune)
        $live2 = @([pscustomobject]@{ principalId='G1'; resourceSpId='SP1'; appRoleId='AR-OTHER'; assignmentId='x2' })
        $diff2 = Compare-PimDesiredVsLive -Desired $desired -Live $live2 -KeyOf $prov.KeyOf -Equal $prov.Equal -Prune
        $diff2.create.Count | Should -Be 1   # AR1 desired, absent live
        $diff2.remove.Count | Should -Be 1   # AR-OTHER live, not desired
    }
    It 'EntraAppRole ApplyCreate POSTs appRoleAssignedTo with the group as principal + resolved app-role id' {
        $prov = New-PimEntraAppRoleProvider
        function Invoke-PimGraph { param([string]$Method,[string]$Path,$Body,[switch]$All,[switch]$Beta,[hashtable]$Headers) $script:__capa = @{ Method=$Method; Path=$Path; Body=$Body }; @{ id='new' } }
        $sp = [pscustomobject]@{ id='SP-7'; appId='APP-7'; displayName='Contoso HR'; appRoles=@([pscustomobject]@{ id='AR-USER'; value='User'; displayName='Default user access' }) }
        $ctx = @{ appRoleGid=@{ 'approle-hr'='GID-7' }; appRoleSp=@{ 'sp-7'=$sp } }
        $item = @{ key='gid-7|sp-7|ar-user'; desired=[pscustomobject]@{ GroupTag='AppRole-HR'; ServicePrincipalId='SP-7'; AppRole='User' } }
        & $prov.ApplyCreate $item $ctx | Out-Null
        $script:__capa.Method | Should -Be 'POST'
        $script:__capa.Path   | Should -Match '/servicePrincipals/SP-7/appRoleAssignedTo'
        $script:__capa.Body.principalId | Should -Be 'GID-7'
        $script:__capa.Body.resourceId  | Should -Be 'SP-7'
        $script:__capa.Body.appRoleId   | Should -Be 'AR-USER'
        Remove-Item function:Invoke-PimGraph -ErrorAction SilentlyContinue
    }
    It 'EntraAppRole ApplyCreate fails loud on an unknown app-role value' {
        $prov = New-PimEntraAppRoleProvider
        function Invoke-PimGraph { param([string]$Method,[string]$Path,$Body,[switch]$All,[switch]$Beta,[hashtable]$Headers) @{ id='new' } }
        $sp = [pscustomobject]@{ id='SP-7'; displayName='Contoso HR'; appRoles=@([pscustomobject]@{ id='AR-USER'; value='User'; displayName='Default user access' }) }
        $ctx = @{ appRoleGid=@{ 'approle-hr'='GID-7' }; appRoleSp=@{ 'sp-7'=$sp } }
        $item = @{ key='gid-7|sp-7|ghost'; desired=[pscustomobject]@{ GroupTag='AppRole-HR'; ServicePrincipalId='SP-7'; AppRole='GhostRole' } }
        { & $prov.ApplyCreate $item $ctx } | Should -Throw -ExpectedMessage '*app role*not found*'
        Remove-Item function:Invoke-PimGraph -ErrorAction SilentlyContinue
    }
    It 'EntraAppRole ApplyRemove DELETEs the appRoleAssignedTo edge by assignment id' {
        $prov = New-PimEntraAppRoleProvider
        function Invoke-PimGraph { param([string]$Method,[string]$Path,$Body,[switch]$All,[switch]$Beta,[hashtable]$Headers) $script:__capr = @{ Method=$Method; Path=$Path }; @{} }
        $item = @{ key='g1|sp1|ar1'; live=[pscustomobject]@{ principalId='G1'; resourceSpId='SP-7'; appRoleId='AR1'; assignmentId='ASG-9' } }
        & $prov.ApplyRemove $item @{} | Out-Null
        $script:__capr.Method | Should -Be 'DELETE'
        $script:__capr.Path   | Should -Be '/servicePrincipals/SP-7/appRoleAssignedTo/ASG-9'
        Remove-Item function:Invoke-PimGraph -ErrorAction SilentlyContinue
    }

    # --- §6 Engine-core: per-scope conformance versioning (desired vs applied template version) ---
    It 'Get-PimScopeConformance classifies UpToDate/Behind/Ahead/NeverApplied per scope' {
        $m = Get-PimScopeConformance -DesiredVersions @{ Groups=3; EntraRoles=2; AzRes=1; GroupsPolicies=4 } `
                                     -AppliedVersions @{ Groups=3; EntraRoles=1; GroupsPolicies=5 } -TenantId 't1'
        ($m.Rows | Where-Object Scope -eq 'Groups').Status         | Should -Be 'UpToDate'
        ($m.Rows | Where-Object Scope -eq 'EntraRoles').Status     | Should -Be 'Behind'
        ($m.Rows | Where-Object Scope -eq 'EntraRoles').Behind     | Should -Be 1
        ($m.Rows | Where-Object Scope -eq 'AzRes').Status          | Should -Be 'NeverApplied'
        ($m.Rows | Where-Object Scope -eq 'GroupsPolicies').Status | Should -Be 'Ahead'
        $m.Counts['UpToDate'] | Should -Be 1
        $m.Counts['Behind']   | Should -Be 1
    }
    It 'Set/Get-PimScopeAppliedVersion round-trips per scope and leaves the template stamp intact' {
        $sf = Join-Path $env:TEMP ('pimscope-' + [guid]::NewGuid().ToString('N') + '.json')
        try {
            # an existing per-template stamp must survive a per-scope write (same file)
            Set-PimTemplateState     -StateFile $sf -TenantId 't1' -TemplateId 'tpl-a' -Version 7 | Out-Null
            Set-PimScopeAppliedVersion -StateFile $sf -TenantId 't1' -Scope 'Groups' -Version 5 | Out-Null
            Set-PimScopeAppliedVersion -StateFile $sf -TenantId 't1' -Scope 'AzRes'  -Version 2 | Out-Null
            (Get-PimScopeAppliedVersion -StateFile $sf -TenantId 't1' -Scope 'Groups') | Should -Be 5
            (Get-PimScopeAppliedVersion -StateFile $sf -TenantId 't1' -Scope 'AzRes')  | Should -Be 2
            (Get-PimScopeAppliedVersion -StateFile $sf -TenantId 't1' -Scope 'Missing')| Should -Be 0   # absent -> 0
            (Get-PimTemplateState -StateFile $sf -TenantId 't1' -TemplateId 'tpl-a').LastAppliedVersion | Should -Be 7
        } finally { Remove-Item $sf -Force -ErrorAction SilentlyContinue }
    }

    It 'Scopes run in dependency order + commit-queue-fed delta applies ONLY queued (entity,key)' {
        Register-PimDefaultEngineProviders
        $scopes = @(Get-PimEngineScopes)
        $scopes.IndexOf('AdministrativeUnits') | Should -BeLessThan $scopes.IndexOf('Groups')
        $scopes.IndexOf('Groups')              | Should -BeLessThan $scopes.IndexOf('GroupOwners')
        Register-PimEngineProvider -Provider @{
            scope='UnitStub'; entity='Unit-Entity'
            GetDesired = { param($c) @([pscustomobject]@{ k='x' }, [pscustomobject]@{ k='y' }) }
            GetLive    = { param($c) @() }
            KeyOf = { param($r) $r.k }; Equal = { param($d,$l) $true }
            ApplyCreate = { param($i,$c) $true }
        }
        $res = Invoke-PimEngineScope -Scope 'UnitStub' -Mode Delta -WhatIf -Changes @(@{ Entity='Unit-Entity'; Key='x' })
        $res.create | Should -Be 1   # only the queued key 'x', not 'y'
    }
}

Describe 'Auth / Identity diagnostics (REQUIREMENTS § 9)' {

    Context 'Missing-role hint (don''t hard-fail a 403)' {
        It 'a non-403 status returns NO hint (real error must surface)' {
            Get-PimMissingRoleHint -Path '/groups' -StatusCode 500 -ErrorBody 'boom' | Should -BeNullOrEmpty
        }
        It 'Test-PimIsAuthForbidden recognises 403 + insufficient-privileges body' {
            Test-PimIsAuthForbidden -StatusCode 403 | Should -BeTrue
            Test-PimIsAuthForbidden -ErrorBody 'Authorization_RequestDenied: Insufficient privileges' | Should -BeTrue
            Test-PimIsAuthForbidden -StatusCode 500 -ErrorBody 'gateway' | Should -BeFalse
        }
        It 'app-only 403 on roleManagementPolicies names the PIM-for-Groups policy role + Grant script' {
            $h = Get-PimMissingRoleHint -Path "/policies/roleManagementPolicies('x')" -StatusCode 403 -AppOnly $true
            $h.IsAuthFailure | Should -BeTrue
            $h.AppRolesToGrant | Should -Contain 'RoleManagementPolicy.ReadWrite.AzureADGroup'
            $h.Hint | Should -Match 'Grant-PimGraphAppRoles'
        }
        It 'app-only 403 on /users -> User.ReadWrite.All; /groups -> Group.ReadWrite.All' {
            (Get-PimMissingRoleHint -Path '/users/abc' -StatusCode 403).AppRolesToGrant | Should -Contain 'User.ReadWrite.All'
            (Get-PimMissingRoleHint -Path '/groups' -StatusCode 403).AppRolesToGrant     | Should -Contain 'Group.ReadWrite.All'
        }
        It 'accessReviews 403 -> AccessReview.Read.All' {
            (Get-PimMissingRoleHint -Path '/identityGovernance/accessReviews/definitions' -StatusCode 403).AppRolesToGrant | Should -Contain 'AccessReview.Read.All'
        }
        It 'interactive (operator) hint names the PIM role to ACTIVATE, not the app-role to grant' {
            $h = Get-PimMissingRoleHint -Path '/roleManagement/directory/roleAssignmentScheduleRequests' -StatusCode 403 -AppOnly $false
            $h.PimRolesToActivate | Should -Contain 'Privileged Role Administrator'
            $h.Hint | Should -Match 'Activate in PIM'
        }
        It 'unknown path falls back to Directory.Read.All + Privileged Role Administrator' {
            $h = Get-PimMissingRoleHint -Path '/some/unmapped/endpoint' -StatusCode 403
            $h.AppRolesToGrant | Should -Contain 'Directory.Read.All'
        }
    }

    Context 'Account sign-in prompt clarity (never reuse a stale account silently)' {
        It 'default prompt is select_account; ForceFresh -> login' {
            ConvertTo-PimAuthCodePrompt | Should -Be 'select_account'
            ConvertTo-PimAuthCodePrompt -ForceFresh | Should -Be 'login'
        }
        It 'a known stale account forces a fresh login prompt' {
            ConvertTo-PimAuthCodePrompt -KnownStaleAccount 'old@contoso.com' | Should -Be 'login'
        }
        It 'no cached account -> picker (select_account), no mismatch' {
            $r = Get-PimAccountSignInHint -CachedAccount '' -ExpectedAccount 'a@b.com'
            $r.Mismatch | Should -BeFalse
            $r.Prompt | Should -Be 'select_account'
        }
        It 'cached account differs from expected -> mismatch + force login' {
            $r = Get-PimAccountSignInHint -CachedAccount 'old@b.com' -ExpectedAccount 'new@b.com'
            $r.Mismatch | Should -BeTrue
            $r.Prompt | Should -Be 'login'
            $r.Hint | Should -Match 'fresh sign-in'
        }
        It 'matching cached account -> no mismatch, still shows the picker' {
            $r = Get-PimAccountSignInHint -CachedAccount 'Same@b.com' -ExpectedAccount 'same@b.com'
            $r.Mismatch | Should -BeFalse
            $r.Prompt | Should -Be 'select_account'
        }
    }

    Context 'AD-failure diagnostics (identity / Kerberos / DC on failure)' {
        It 'SYSTEM + no credential + no DC -> flags both wrong-identity and unreachable-DC' {
            $d = Resolve-PimAdFailureDiagnostic -ProcessIdentity 'NT AUTHORITY\SYSTEM' -HasExplicitCredential $false -HasKerberosTickets $false -DiscoveredDc ''
            $d.LooksLikeSystem | Should -BeTrue
            ($d.Causes -join ' ') | Should -Match 'domain controller'
            ($d.Causes -join ' ') | Should -Match 'non-domain identity'
            $d.NextStep | Should -Not -BeNullOrEmpty
        }
        It 'machine account (trailing $) is treated as system-ish' {
            (Resolve-PimAdFailureDiagnostic -ProcessIdentity 'CONTOSO\MGMT1$' -DiscoveredDc 'dc1.contoso.com' -HasExplicitCredential $false).LooksLikeSystem | Should -BeTrue
        }
        It 'domain user + DC + tickets -> classified as an AUTHORIZATION (rights) problem' {
            $d = Resolve-PimAdFailureDiagnostic -ProcessIdentity 'CONTOSO\admin' -HasExplicitCredential $true -HasKerberosTickets $true -DiscoveredDc 'dc1.contoso.com' -ErrorMessage 'Access is denied'
            $d.LooksLikeSystem | Should -BeFalse
            ($d.Causes -join ' ') | Should -Match 'authorization'
        }
        It 'DC reachable but no tickets -> flags the missing Kerberos auth' {
            $d = Resolve-PimAdFailureDiagnostic -ProcessIdentity 'CONTOSO\admin' -HasExplicitCredential $true -HasKerberosTickets $false -DiscoveredDc 'dc1.contoso.com'
            ($d.Causes -join ' ') | Should -Match 'Kerberos'
        }
        It 'live wrapper Get-PimAdFailureDiagnostic returns a shaped object and never throws' {
            $d = Get-PimAdFailureDiagnostic -HasExplicitCredential $false -ErrorMessage 'x'
            $d.ProcessIdentity | Should -Not -BeNullOrEmpty
            $d.Causes | Should -Not -BeNullOrEmpty
        }
    }

    Context 'MFA-gated Manager login (amr proves MFA; Easy Auth no-op when hosted)' {
        BeforeAll {
            function script:New-PimJwt([hashtable]$Claims) {
                $b64 = {
                    param($o) $j = ($o | ConvertTo-Json -Compress)
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($j)
                    [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
                }
                ((& $b64 @{ alg='none'; typ='JWT' }) + '.' + (& $b64 $Claims) + '.sig')
            }
        }
        It 'ConvertFrom-PimJwtClaims decodes the payload; junk -> $null' {
            $tok = New-PimJwt @{ upn='a@b.com'; amr=@('pwd','mfa') }
            (ConvertFrom-PimJwtClaims -Token $tok).upn | Should -Be 'a@b.com'
            ConvertFrom-PimJwtClaims -Token 'not-a-jwt' | Should -BeNullOrEmpty
        }
        It 'Test-PimTokenHasMfa: amr containing mfa -> true; pwd-only -> false' {
            Test-PimTokenHasMfa -Token (New-PimJwt @{ amr=@('pwd','mfa') }) | Should -BeTrue
            Test-PimTokenHasMfa -Token (New-PimJwt @{ amr=@('pwd') })       | Should -BeFalse
        }
        It 'Test-PimTokenHasMfa accepts a strong second factor (fido) and acr=1; fails closed on absence' {
            Test-PimTokenHasMfa -Token (New-PimJwt @{ amr=@('fido') }) | Should -BeTrue
            Test-PimTokenHasMfa -Token (New-PimJwt @{ acr='1' })       | Should -BeTrue
            Test-PimTokenHasMfa -Token (New-PimJwt @{ sub='x' })       | Should -BeFalse
        }
        It 'hosted gate is a NO-OP (Easy Auth enforces MFA) -> Allowed' {
            $r = Assert-PimManagerMfa -Hosted
            $r.Allowed | Should -BeTrue
            $r.Source | Should -Match 'Easy Auth'
        }
        It 'local with an MFA token -> Allowed + UPN extracted' {
            $r = Assert-PimManagerMfa -Token (New-PimJwt @{ upn='ops@b.com'; amr=@('pwd','mfa') })
            $r.Allowed | Should -BeTrue
            $r.Upn | Should -Be 'ops@b.com'
        }
        It 'local with a non-MFA token -> denied + told to re-run the Edge sign-in' {
            $r = Assert-PimManagerMfa -Token (New-PimJwt @{ amr=@('pwd') })
            $r.Allowed | Should -BeFalse
            $r.NeedSignIn | Should -BeTrue
        }
        It 'local with no token -> denied + NeedSignIn (no device-code mentioned)' {
            $r = Assert-PimManagerMfa
            $r.Allowed | Should -BeFalse
            $r.NeedSignIn | Should -BeTrue
            $r.Hint | Should -Not -Match 'device'
        }
        It 'local with RequireMfa=$false -> Allowed (gate disabled by config)' {
            (Assert-PimManagerMfa -RequireMfa $false).Allowed | Should -BeTrue
        }
    }
}

# ---------------------------------------------------------------------------
# Shipped delegation template packs (templates/*.template.json)
# These are the central permission-template "packs" the Manager Create tab and
# the /api/templates endpoint consume. Each pack must parse and conform to the
# SAME schema the Manager loader (Get-PimTemplateRowKey + the PimCsvBases spec)
# expects: top-level id/name/version/description/rows, every rows base name is a
# known CSV entity, every row column is in that entity's header, and the key
# columns (the ones the Manager diffs on) are populated + unique per base. This
# guards the Defender-XDR pack plus the Sentinel / Intune / Exchange Online /
# Azure-RBAC / Entra-roles packs added in feat/pim-template-packs.
# ---------------------------------------------------------------------------
Describe 'Shipped delegation template packs (templates/*.template.json)' {
    BeforeAll {
        $script:TplDir = Join-Path $Root 'templates'
        # The canonical entity headers (mirror of $script:PimCsvBases in
        # Open-PimManager.ps1) + the key columns the Manager diffs each base on
        # (mirror of Get-PimTemplateRowKey). Kept here so the test is
        # self-contained and does not depend on the Manager host script.
        $script:EntityHeader = @{
            'PIM-Definitions-Services'        = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners')
            'PIM-Definitions-Tasks'           = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners')
            'PIM-Definitions-Organization'    = @('GroupName','GroupDescription','GroupTag','AdministrativeUnitTag','IsRoleAssignable','Workload','Level','TierLevel','Plane','CPPlatform','Owners')
            'PIM-Assignments-Roles-Groups'    = @('GroupTag','RoleDefinitionName','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform')
            'PIM-Assignments-Azure-Resources' = @('GroupTag','AzScope','AzScopePermission','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform')
        }
        # Key columns per base (must all be non-empty + the joined key unique).
        $script:EntityKey = @{
            'PIM-Definitions-Services'        = @('GroupTag')
            'PIM-Definitions-Tasks'           = @('GroupTag')
            'PIM-Definitions-Organization'    = @('GroupTag')
            'PIM-Assignments-Roles-Groups'    = @('GroupTag','RoleDefinitionName')
            'PIM-Assignments-Azure-Resources' = @('GroupTag','AzScope','AzScopePermission')
        }
        function Read-PimTemplateFile {
            param([string]$Path)
            $raw = [System.IO.File]::ReadAllText($Path, [System.Text.UTF8Encoding]::new($false))
            if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
            return ($raw | ConvertFrom-Json)
        }
        $script:TplFiles = @(Get-ChildItem -LiteralPath $script:TplDir -Filter '*.template.json' -File)
    }

    It 'the templates directory ships at least the 6 expected packs' {
        $ids = @($script:TplFiles | ForEach-Object { (Read-PimTemplateFile $_.FullName).id })
        foreach ($expected in 'defender-xdr','sentinel','intune','exchange-online','azure-rbac','entra-roles') {
            $ids | Should -Contain $expected -Because "pack '$expected' must ship in templates/"
        }
    }

    It 'every pack parses as JSON and carries id / name / version / rows' {
        $script:TplFiles.Count | Should -BeGreaterThan 0
        foreach ($f in $script:TplFiles) {
            $tpl = Read-PimTemplateFile $f.FullName   # throws -> fails the It (JSON-validity assertion)
            "$($tpl.id)"          | Should -Not -BeNullOrEmpty -Because "$($f.Name) needs an id"
            "$($tpl.name)"        | Should -Not -BeNullOrEmpty -Because "$($f.Name) needs a name"
            $tpl.version          | Should -BeGreaterThan 0     -Because "$($f.Name) needs a numeric version"
            "$($tpl.description)" | Should -Not -BeNullOrEmpty -Because "$($f.Name) needs a description"
            $tpl.rows             | Should -Not -BeNullOrEmpty -Because "$($f.Name) needs a rows object"
        }
    }

    It 'every pack conforms to the Manager CSV schema (known entity, valid columns, populated unique keys)' {
        foreach ($f in $script:TplFiles) {
            $tpl = Read-PimTemplateFile $f.FullName
            foreach ($baseProp in $tpl.rows.PSObject.Properties) {
                $base = $baseProp.Name
                $script:EntityHeader.ContainsKey($base) | Should -BeTrue -Because "$($f.Name): base '$base' must be a known CSV entity"
                $header = $script:EntityHeader[$base]
                $keyCols = $script:EntityKey[$base]
                $seen = @{}
                foreach ($row in @($baseProp.Value)) {
                    foreach ($p in $row.PSObject.Properties) {
                        $header | Should -Contain $p.Name -Because "$($f.Name): column '$($p.Name)' is not in the '$base' schema"
                    }
                    $keyParts = foreach ($k in $keyCols) {
                        $v = $row.PSObject.Properties[$k]
                        "$($v.Value)" | Should -Not -BeNullOrEmpty -Because "$($f.Name): key column '$k' must be populated"
                        "$($v.Value)"
                    }
                    $key = ($keyParts -join '|').ToLowerInvariant()
                    $seen.ContainsKey($key) | Should -BeFalse -Because "$($f.Name): duplicate row key '$key' in '$base'"
                    $seen[$key] = $true
                }
            }
        }
    }

    It 'definition group names follow the PIM naming convention and their tier/level columns agree with the name' {
        foreach ($f in $script:TplFiles) {
            $tpl = Read-PimTemplateFile $f.FullName
            foreach ($baseProp in $tpl.rows.PSObject.Properties) {
                if ($baseProp.Name -notlike 'PIM-Definitions-*') { continue }
                foreach ($row in @($baseProp.Value)) {
                    $gn = [string]$row.GroupName
                    $pat = '^PIM-.+-L([0-9])-T([0-2])-(CP|WDP|MP|APP|USER)-(ID|RES|DAT)$'
                    $matched = [System.Text.RegularExpressions.Regex]::Match($gn, $pat)
                    $isMatch = [bool]$matched.Success
                    $isMatch | Should -BeTrue -Because ($f.Name + " group " + $gn + " must match the naming convention")
                    # the L#/T# baked into the name must match the Level/TierLevel columns
                    if ($isMatch) {
                        $lvl  = 'L' + $matched.Groups[1].Value
                        $tier = 'T' + $matched.Groups[2].Value
                        $lvl  | Should -Be ([string]$row.Level)     -Because ($f.Name + " group " + $gn + " Level column must match the name")
                        $tier | Should -Be ([string]$row.TierLevel) -Because ($f.Name + " group " + $gn + " TierLevel column must match the name")
                    }
                }
            }
        }
    }

    It 'every assignment row references a GroupTag defined in the same pack (self-contained packs)' {
        foreach ($f in $script:TplFiles) {
            $tpl = Read-PimTemplateFile $f.FullName
            $defined = @{}
            foreach ($baseProp in $tpl.rows.PSObject.Properties) {
                if ($baseProp.Name -like 'PIM-Definitions-*') {
                    foreach ($row in @($baseProp.Value)) { $defined["$($row.GroupTag)".ToLowerInvariant()] = $true }
                }
            }
            foreach ($baseProp in $tpl.rows.PSObject.Properties) {
                if ($baseProp.Name -like 'PIM-Assignments-*') {
                    foreach ($row in @($baseProp.Value)) {
                        $defined.ContainsKey("$($row.GroupTag)".ToLowerInvariant()) | Should -BeTrue -Because "$($f.Name): assignment GroupTag '$($row.GroupTag)' has no matching definition group"
                    }
                }
            }
        }
    }

    It 'packs carry no secrets / tenant-or-subscription IDs / customer-looking values (public-safe content)' {
        # zero-GUID placeholders are explicitly allowed; any other real GUID is not.
        foreach ($f in $script:TplFiles) {
            $raw = [System.IO.File]::ReadAllText($f.FullName, [System.Text.UTF8Encoding]::new($false))
            $guids = [regex]::Matches($raw, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
            foreach ($m in $guids) {
                $m.Value | Should -Be '00000000-0000-0000-0000-000000000000' -Because "$($f.Name): only the zero-GUID placeholder is allowed, not a real ID"
            }
        }
    }
}

Describe 'MSP substrate / sync models / signed kill-switch (REQUIREMENTS § 4)' {

    Context 'Shared substrate -- Product-keyed registry (TenantManager reuse)' {
        It 'PIM and TenantManager both ride the substrate; an unknown Product does not' {
            Get-PimSubstrateProducts | Should -Contain 'PIM'
            Get-PimSubstrateProducts | Should -Contain 'TenantManager'
            Test-PimSubstrateProduct -Product 'PIM'           | Should -BeTrue
            Test-PimSubstrateProduct -Product 'TenantManager' | Should -BeTrue
            Test-PimSubstrateProduct -Product 'Bogus'         | Should -BeFalse
        }
        It 'Get-PimProductTenantQuery keys the SAME tables by Product (only the Product literal differs)' {
            $pim = Get-PimProductTenantQuery -Product 'PIM'
            $tm  = Get-PimProductTenantQuery -Product 'TenantManager'
            $pim | Should -Match "Product = 'PIM'"
            $tm  | Should -Match "Product = 'TenantManager'"
            $pim | Should -Match 'platform\.Tenants'
            $pim | Should -Match 'platform\.TenantApps'
            # same shape: identical apart from the Product literal
            ($pim -replace "'PIM'", "'TenantManager'") | Should -Be $tm
        }
        It 'Get-PimProductTenantQuery adds a tenant filter and is injection-safe' {
            $q = Get-PimProductTenantQuery -Product 'PIM' -TenantId "11111111-1111-1111-1111-111111111111"
            $q | Should -Match "TenantId = '11111111-1111-1111-1111-111111111111'"
            # a quote in the input is escaped, not interpolated raw
            $q2 = Get-PimProductTenantQuery -Product 'PIM' -TenantId "x' OR '1'='1"
            $q2 | Should -Match "x'' OR ''1''=''1"
        }
        It 'Get-PimProductTenantQuery rejects an unknown Product' {
            { Get-PimProductTenantQuery -Product 'NotAProduct' } | Should -Throw '*Unknown substrate Product*'
        }
        It 'Resolve-PimSubstrateContext normalizes a row uniformly + picks the auth profile' {
            $cert = Resolve-PimSubstrateContext -Row ([pscustomobject]@{ Product='PIM'; TenantId='t'; DisplayName='d'; Ring=1; AppId='a'; CertificateThumbprint='ABC'; AuthMode='Certificate' })
            $cert.AuthProfile | Should -Be 'cert'
            $cert.Ring        | Should -Be 1
            $sref = Resolve-PimSubstrateContext -Row ([pscustomobject]@{ Product='TenantManager'; TenantId='t'; AuthMode='SecretRef'; SecretName='kv-x' })
            $sref.AuthProfile | Should -Be 'secretref'
            $sref.Ring        | Should -Be 2   # default when absent
        }
    }

    Context 'Multiple sync models -- do not force one; invariants always hold' {
        It 'every supported model resolves with both hard invariants False' {
            $models = Get-PimSupportedSyncModels
            $models.Count | Should -BeGreaterThan 3
            foreach ($m in $models) {
                $p = Resolve-PimSyncModel -Model $m
                $p.MspWritesLocal | Should -BeFalse -Because "$m must never let the MSP write to a customer tenant"
                $p.DataLeaves     | Should -BeFalse -Because "$m must never let customer data leave the tenant"
                $p.Initiator      | Should -Be 'local' -Because "$m must be local-initiated (pull-not-push)"
            }
        }
        It 'an unknown / push-style model is rejected (fail closed)' {
            { Resolve-PimSyncModel -Model 'push-to-customer' } | Should -Throw '*Unsupported sync model*'
        }
        It 'Get-PimSyncModelPlan maps models to local scheduler jobs' {
            (Get-PimSyncModelPlan -Model 'template-pull').SchedulerJobs   | Should -Contain 'template-pull'
            (Get-PimSyncModelPlan -Model 'pull-baseline').SchedulerJobs   | Should -Contain 'baseline-pull'
            (Get-PimSyncModelPlan -Model 'sync-out-status').SchedulerJobs | Should -Contain 'status-rollup'
            @((Get-PimSyncModelPlan -Model 'local-reads-msp').SchedulerJobs).Count     | Should -Be 0
            @((Get-PimSyncModelPlan -Model 'msp-delegates-local').SchedulerJobs).Count | Should -Be 0
        }
    }

    Context 'Kill-switch -- revoke the signer thumbprint' {
        It 'a non-revoked signer is allowed; a revoked one (any separator/case) is not' {
            Test-PimBaselineSignerAllowed -Thumbprint 'AA:BB:CC' -Revoked @()           | Should -BeTrue
            Test-PimBaselineSignerAllowed -Thumbprint 'aabbcc'   -Revoked @('AA BB CC') | Should -BeFalse
            Test-PimBaselineSignerAllowed -Thumbprint ''         -Revoked @()           | Should -BeFalse  # no signer -> not allowed
        }
        It 'Set/Get-PimRevokedSigners round-trips + normalizes + de-dups' {
            $sf = Join-Path $env:TEMP ('pim-revoked-' + [guid]::NewGuid().ToString('N') + '.json')
            try {
                Set-PimRevokedSigners -Thumbprints @('aa:bb','AABB','cc dd') -StateFile $sf | Out-Null
                $r = Get-PimRevokedSigners -StateFile $sf
                $r | Should -Contain 'AABB'
                $r | Should -Contain 'CCDD'
                @($r).Count | Should -Be 2   # aa:bb and AABB collapse to one
            } finally { Remove-Item $sf -Force -ErrorAction SilentlyContinue }
        }
    }

    Context 'Central kill -- signed manifest -> AccountStatus flips (no new write path)' {
        BeforeAll {
            $script:KillCert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -eq 'CN=PIM4EntraPS-Baseline' -and $_.HasPrivateKey } | Select-Object -First 1
            function New-SignedKillDoc {
                param([object]$Payload, [object]$Cert)
                $pb  = [Text.Encoding]::UTF8.GetBytes(($Payload | ConvertTo-Json -Depth 6 -Compress))
                $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
                $sig = $rsa.SignData($pb, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
                [pscustomobject]@{ product='PIM4EntraPS'; payloadB64=[Convert]::ToBase64String($pb); signature=[Convert]::ToBase64String($sig); keyThumbprint=$Cert.Thumbprint }
            }
            $script:KillPayload = [ordered]@{
                product='PIM4EntraPS'; kind='central-kill'; version=9999999999
                validToUtc=(Get-Date).AddDays(1).ToUniversalTime().ToString('o')
                kills=@(@{ upn='leaver@x'; userName='Admin-LV-ID'; status='Revoked'; statusChangeCode='CISO-001'; reason='central kill' })
            }
        }
        It 'a valid signed manifest yields the AccountStatus rows the engine pipeline applies' {
            if (-not $script:KillCert) { Set-ItResult -Skipped -Because 'CN=PIM4EntraPS-Baseline signing cert not on this host'; return }
            $doc  = New-SignedKillDoc -Payload $script:KillPayload -Cert $script:KillCert
            $rows = @(Resolve-PimCentralKill -Doc $doc -Revoked @())
            $rows.Count | Should -Be 1
            $rows[0].AccountStatus     | Should -Be 'Revoked'
            $rows[0].UserPrincipalName | Should -Be 'leaver@x'
            $rows[0].StatusChangeCode  | Should -Be 'CISO-001'
        }
        It 'a tampered manifest is rejected (signature)' {
            if (-not $script:KillCert) { Set-ItResult -Skipped -Because 'no signing cert'; return }
            $doc = New-SignedKillDoc -Payload $script:KillPayload -Cert $script:KillCert
            $j   = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($doc.payloadB64)) -replace 'Revoked','Disabled'
            $doc.payloadB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))
            { Resolve-PimCentralKill -Doc $doc -Revoked @() } | Should -Throw '*SIGNATURE INVALID*'
        }
        It 'a manifest signed by a REVOKED key is refused (kill-switch beats kill manifest)' {
            if (-not $script:KillCert) { Set-ItResult -Skipped -Because 'no signing cert'; return }
            $doc = New-SignedKillDoc -Payload $script:KillPayload -Cert $script:KillCert
            { Resolve-PimCentralKill -Doc $doc -Revoked @($script:KillCert.Thumbprint) } | Should -Throw '*revoked*'
        }
        It 'a baseline bundle (wrong kind) is NOT accepted as a kill manifest' {
            if (-not $script:KillCert) { Set-ItResult -Skipped -Because 'no signing cert'; return }
            $blPayload = [ordered]@{ product='PIM4EntraPS'; kind='baseline'; version=1; validToUtc=(Get-Date).AddDays(1).ToUniversalTime().ToString('o'); rows=@() }
            $doc = New-SignedKillDoc -Payload $blPayload -Cert $script:KillCert
            { Resolve-PimCentralKill -Doc $doc -Revoked @() } | Should -Throw '*unexpected bundle kind*'
        }
    }

    Context 'az acr import -- mirror engine image MSP -> customer ACR' {
        It 'builds a cross-tenant token import (ACR token username + redactable password + force)' {
            $a = (Get-PimAcrImportArgs -TargetAcrName 'custacr' -SourceLoginServer 'mspacr.azurecr.io' -Repository 'pim4entraps/engine' -Tag '1.1.4' -SourceToken 'SECRET' -Force) -join ' '
            $a | Should -Match '--name custacr'
            $a | Should -Match '--source mspacr\.azurecr\.io/pim4entraps/engine:1\.1\.4'
            $a | Should -Match '--image pim4entraps/engine:1\.1\.4'
            $a | Should -Match '00000000-0000-0000-0000-000000000000'   # ACR token username convention
            $a | Should -Match 'SECRET'
            $a | Should -Match '--force'
        }
        It 'same-tenant import carries no credentials; resource-id form uses --registry' {
            $b = (Get-PimAcrImportArgs -TargetAcrName 'c' -SourceLoginServer 'm.azurecr.io' -Repository 'r' -Tag 't') -join ' '
            $b | Should -Not -Match '--password'
            $b | Should -Not -Match '--force'
            $c = (Get-PimAcrImportArgs -TargetAcrName 'c' -SourceLoginServer 'm.azurecr.io' -Repository 'r' -Tag 't' -SourceRegistryResourceId '/subscriptions/s/rg/m') -join ' '
            $c | Should -Match '--registry /subscriptions/s/rg/m'
        }
        It 'Invoke-PimAcrImport -WhatIf redacts the token and makes no az call' {
            $info = Invoke-PimAcrImport -TargetAcrName 'c' -SourceLoginServer 'm.azurecr.io' -Repository 'r' -Tag 't' -SourceToken 'TOPSECRET' -WhatIf -InformationAction Continue 6>&1
            $txt = ($info | Out-String)
            $txt | Should -Not -Match 'TOPSECRET'
            $txt | Should -Match '\*\*\*'
        }
    }
}
