/*
 * render-and-check.js -- headless DOM-level validator for the PIM Manager GUI.
 *
 * Loads tools/pim-manager/pim-manager.html into jsdom (NO browser, NO server),
 * substitutes the server-side boot placeholders with REPRESENTATIVE SEEDED data,
 * mocks every GET /api/* endpoint the GUI calls, then drives switchTab through
 * EVERY tab in two passes:
 *
 *   pass "seeded"  -- server mode + a fetch mock returning representative rows/
 *                     cards for every endpoint; asserts each tab shows REAL
 *                     content (a row/card/table), not a blank/dead panel, and
 *                     renders with no JS error.
 *   pass "empty"   -- server mode + a fetch mock returning EMPTY collections;
 *                     asserts each data-driven tab shows an EXPLICIT empty/error
 *                     state (the word "no"/"empty"/"none"/loading-cleared), not
 *                     a silently blank panel.
 *
 * It also performs banner LAYOUT-SANITY checks (tenant name+GUID grouped,
 * instance dropdown labelled, mode/source on one line) and a SELECTION-INPUT
 * check (group/role/tag/workload pickers must be <select>, not raw free-text),
 * and a DELEGATION-MAP REACH check (the reach badge must equal the true BFS
 * target count for a known seeded topology -- catches inflated reach).
 *
 * Emits a single JSON document on stdout:
 *   { ok, summary, findings:[ {id, severity, tab, message, pass} ] }
 * Exit code: 0 always (the PS wrapper decides pass/fail from findings); a
 * HARNESS error (jsdom missing / html missing) exits 2 with {harnessError}.
 *
 * Self-contained except for jsdom. If jsdom is not installed the PS wrapper
 * self-skips (absence != failure), mirroring the project's Live-test rule.
 */
'use strict';
const fs = require('fs');
const path = require('path');

function harnessFail(msg) {
  process.stdout.write(JSON.stringify({ harnessError: msg }) + '\n');
  process.exit(2);
}

let JSDOM, VirtualConsole;
try { ({ JSDOM, VirtualConsole } = require('jsdom')); }
catch (e) { harnessFail('jsdom not installed: ' + e.message); }

// Async renderers throw INSIDE the jsdom script context; jsdom surfaces those
// as uncaught exceptions that would otherwise kill the harness. Route them to
// the currently-active pass's error sink so they become FINDINGS, not a crash.
let CURRENT_ERR_SINK = null;
process.on('uncaughtException', (e) => {
  if (CURRENT_ERR_SINK) CURRENT_ERR_SINK.push('uncaughtException: ' + (e && e.stack || e));
  else { harnessFail('uncaught before sink: ' + (e && e.stack || e)); }
});
process.on('unhandledRejection', (e) => {
  if (CURRENT_ERR_SINK) CURRENT_ERR_SINK.push('unhandledRejection: ' + (e && e.stack || e));
});

const htmlPath = path.resolve(__dirname, '..', '..', 'tools', 'pim-manager', 'pim-manager.html');
if (!fs.existsSync(htmlPath)) harnessFail('pim-manager.html not found at ' + htmlPath);
const rawHtml = fs.readFileSync(htmlPath, 'utf8');

// ---------------------------------------------------------------------------
// The 19 tabs the operator sees, in lifecycle order, with the human label the
// validator reports. Each entry: data-tab, friendly name, panel container id,
// whether it is data-driven (needs the server / shows an empty state).
// ---------------------------------------------------------------------------
const TABS = [
  { tab: 'home',         name: 'Home',            panel: 'homeTab',         dataDriven: true  },
  { tab: 'new',          name: 'Create',          panel: 'newTab',          dataDriven: false },
  { tab: 'map',          name: 'Delegation Map',  panel: 'mapTab',          dataDriven: true  },
  { tab: 'validate',     name: 'Validate',        panel: 'validateTab',     dataDriven: true  },
  { tab: 'save',         name: 'Review & Save',   panel: 'saveTab',         dataDriven: true  },
  { tab: 'revoke',       name: 'Maintenance',     panel: 'revokeTab',       dataDriven: true  },
  { tab: 'approvals',    name: 'Approvals',       panel: 'approvalsTab',    dataDriven: true  },
  { tab: 'accessreview', name: 'Access Review',   panel: 'accessreviewTab', dataDriven: true  },
  { tab: 'grid',         name: 'Advanced View',   panel: 'gridTab',         dataDriven: true  },
  { tab: 'authoring',    name: 'Authoring',       panel: 'authoringTab',    dataDriven: true  },
  { tab: 'onboarding',   name: 'Onboarding',      panel: 'onboardingTab',   dataDriven: true  },
  { tab: 'roleperms',    name: 'Role Lookup',     panel: 'rolepermsTab',    dataDriven: true  },
  { tab: 'governance',   name: 'Governance',      panel: 'governanceTab',   dataDriven: true  },
  { tab: 'audit',        name: 'Audit',           panel: 'auditTab',        dataDriven: true  },
  { tab: 'conformance',  name: 'Template Rollout',panel: 'conformanceTab',  dataDriven: true  },
  { tab: 'cutover',      name: 'Cutover',         panel: 'cutoverTab',      dataDriven: true  },
  { tab: 'jobs',         name: 'Jobs',            panel: 'jobsTab',         dataDriven: true  },
  { tab: 'settings',     name: 'Settings',        panel: 'settingsTab',     dataDriven: true  },
  { tab: 'support',      name: 'Support',         panel: 'supportTab',      dataDriven: false },
];

// ---------------------------------------------------------------------------
// SEEDED PIM_DATA -- a small but COMPLETE delegation topology so the
// Delegation Map, grid, save and wizards all have real rows.
//
// Topology (for the reach assertion):
//   admin:alice  -> group:ROLE-HELP        (role group)
//   group:ROLE-HELP -> group:PERM-ENTRA    (permission group, bound to entra)
//   group:PERM-ENTRA -> entra:HelpdeskAdmin (target, col 3)
//   group:ROLE-HELP -> group:PERM-WL       (permission group, NO target = workload)
//   admin:bob   -> group:ROLE-AZ
//   group:ROLE-AZ -> group:PERM-AZ -> az:/subscriptions/.../rg1 (target, col 3)
// So alice reaches {entra:HelpdeskAdmin (target=1)} + {PERM-WL (workload=1)} = 2.
//    bob reaches {az target = 1} = 1.
// ---------------------------------------------------------------------------
const SEED_NODES = [
  { id: 'admin:alice@contoso.com', label: 'alice (Helpdesk)', kind: 'admin', tier: 'T1', purpose: 'day2day' },
  { id: 'admin:bob@contoso.com',   label: 'bob (Az Dev)',     kind: 'admin', tier: 'T0', purpose: 'highpriv' },
  { id: 'group:ROLE-HELP', label: 'Helpdesk Role',  kind: 'role-group',       groupTag: 'ROLE-HELP', source: 'PIM-Definitions-Roles' },
  { id: 'group:ROLE-AZ',   label: 'Az Dev Role',    kind: 'role-group',       groupTag: 'ROLE-AZ',   source: 'PIM-Definitions-Roles' },
  { id: 'group:PERM-ENTRA',label: 'Entra Perm',     kind: 'permission-group', groupTag: 'PERM-ENTRA',source: 'PIM-Definitions-Entra' },
  { id: 'group:PERM-WL',   label: 'Workload Perm',  kind: 'permission-group', groupTag: 'PERM-WL',   source: 'PIM-Definitions-Workloads' },
  { id: 'group:PERM-AZ',   label: 'Azure Perm',     kind: 'permission-group', groupTag: 'PERM-AZ',   source: 'PIM-Definitions-Azure' },
  { id: 'entra:HelpdeskAdmin', label: 'Helpdesk Administrator', kind: 'entra-role' },
  { id: 'az:/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg1',
    label: 'Contributor @ /subscriptions/1111/resourceGroups/rg1', kind: 'az-resource' },
];
const SEED_EDGES = [
  { source: 'admin:alice@contoso.com', target: 'group:ROLE-HELP', type: 'Eligible' },
  { source: 'admin:bob@contoso.com',   target: 'group:ROLE-AZ',   type: 'Eligible' },
  { source: 'group:ROLE-HELP', target: 'group:PERM-ENTRA', type: 'Member' },
  { source: 'group:ROLE-HELP', target: 'group:PERM-WL',    type: 'Member' },
  { source: 'group:ROLE-AZ',   target: 'group:PERM-AZ',    type: 'Member' },
  { source: 'group:PERM-ENTRA',target: 'entra:HelpdeskAdmin', type: 'Bound' },
  { source: 'group:PERM-AZ',   target: 'az:/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg1', type: 'Bound' },
];
const SEED_CSV_BASES = [
  { base: 'PIM-Definitions-Roles',      group: 'Definitions' },
  { base: 'PIM-Definitions-Entra',      group: 'Definitions' },
  { base: 'PIM-Definitions-Azure',      group: 'Definitions' },
  { base: 'PIM-Definitions-Workloads',  group: 'Definitions' },
  { base: 'PIM-Account-Definitions-Admins', group: 'Definitions' },
  { base: 'PIM-Assignments-Admins',     group: 'Assignments' },
  { base: 'PIM-Assignments-Groups',     group: 'Assignments' },
];
const SEED_PIM_DATA = {
  tenantName: 'Contoso (test)',
  tenantId: '11111111-2222-3333-4444-555555555555',
  sourceRoot: 'SQL: PimPlatform',
  generatedUtc: '2026-06-15T00:00:00Z',
  summary: { admins: 2, roleGroups: 2, permGroups: 3 },
  csvBases: SEED_CSV_BASES,
  nodes: SEED_NODES,
  edges: SEED_EDGES,
};

const SEED_NAMING = {
  AdminPattern: 'A-{Owner}-{Role}',
  GroupPattern: '{Tier}-{Role}',
  AdminTypePrefixes: { 'internal-adminuser': 'A', 'external-guest': 'g' },
  EnvironmentSuffixes: { 'prod': '-P', 'test': '-T' },
};
const SEED_INSTANCES = {
  active: 'contoso',
  instances: [
    { name: 'contoso', tenantId: '11111111-2222-3333-4444-555555555555', sourceRoot: 'SQL: PimPlatform' },
    { name: 'fabrikam', tenantId: '99999999-8888-7777-6666-555555555555', sourceRoot: 'SQL: PimPlatform2' },
  ],
};
const SEED_ROLE = { role: 'SuperAdmin', identity: 'tester@contoso.com', source: 'test-harness' };
const SEED_TENANT_LISTS = {
  entraRoles: [{ id: 'HelpdeskAdmin', displayName: 'Helpdesk Administrator' }],
  azScopes: [{ id: '/subscriptions/1111', displayName: 'Sub 1111' }],
  workloads: [{ id: 'mde', name: 'Defender XDR' }],
};

// ---------------------------------------------------------------------------
// Endpoint mock catalog. For each GET path the GUI calls, a "full" payload
// (representative rows/cards) and an "empty" payload (empty collections).
// Keyed by the path WITHOUT query string. POST/PUT/DELETE get a generic ok.
// ---------------------------------------------------------------------------
function endpointPayloads(empty) {
  const E = empty;
  return {
    '/api/access-map':   E ? { nodes: [], edges: [] } : { nodes: SEED_NODES, edges: SEED_EDGES },
    '/api/access-reviews': E
      ? { rows: [], source: 'live', note: '', total: 0 }
      : { source: 'live', note: '', total: 2, rows: [
          { DisplayName: 'Quarterly Tier0 review', GroupName: 'ROLE-AZ', ScopeTarget: 'PIM for Groups',
            Reviewers: ['alice@contoso.com'], Recurrence: 'quarterly', Status: 'InProgress', IsPimManaged: true,
            DecisionsPending: 3, DecisionsApproved: 1, DecisionsDenied: 0 },
          { DisplayName: 'Helpdesk review', GroupName: 'ROLE-HELP', ScopeTarget: 'PIM for Groups',
            Reviewers: ['bob@contoso.com'], Recurrence: 'monthly', Status: 'Completed', IsPimManaged: true,
            DecisionsPending: 0, DecisionsApproved: 5, DecisionsDenied: 1 } ] },
    '/api/admin-templates': E ? { templates: [] } : { templates: [{ id: 't1', name: 'Tier0 admin' }] },
    '/api/approvals': E
      ? { ok: true, me: 'tester@contoso.com', canDecide: true, canCreate: true, pendingCount: 0, total: 0, requests: [] }
      : { ok: true, me: 'tester@contoso.com', canDecide: true, canCreate: true, pendingCount: 2, total: 3, requests: [
          { id: 'apr-1', requestor: 'maker@contoso.com', action: 'offboard', target: 'jdoe@contoso.com',
            justification: 'left the company', ticket: 'INC-42', requestedUtc: '2026-06-15T08:00:00Z',
            status: 'Pending', approver: '', decidedUtc: '', decisionNote: '', executedUtc: '', expired: false,
            canDecideThis: true, isRequestor: false, sequencePlan: [
              { order: 1, step: 'disable', description: 'Set accountEnabled=false for jdoe@contoso.com (sign-out everywhere)' },
              { order: 2, step: 'revoke-active', description: 'Revoke every active/eligible PIM activation + direct group membership' },
              { order: 3, step: 'schedule-delete', description: 'Schedule object delete for 2026-07-15 (30 day(s) after offboard)' } ] },
          { id: 'apr-2', requestor: 'tester@contoso.com', action: 'revoke', target: 'batch:helpdesk',
            justification: 'over-broad batch', ticket: '', requestedUtc: '2026-06-15T07:00:00Z',
            status: 'Pending', approver: '', decidedUtc: '', decisionNote: '', executedUtc: '', expired: false,
            canDecideThis: false, isRequestor: true, sequencePlan: [] },
          { id: 'apr-3', requestor: 'maker@contoso.com', action: 'disable', target: 'svc-old@contoso.com',
            justification: 'decommissioned', ticket: '', requestedUtc: '2026-06-14T09:00:00Z',
            status: 'Approved', approver: 'checker@contoso.com', decidedUtc: '2026-06-14T10:00:00Z',
            decisionNote: 'ok', executedUtc: '', expired: false, canDecideThis: false, isRequestor: false, sequencePlan: [] } ] },
    '/api/access-reviews/overdue': E
      ? { source: 'seed', note: '', total: 0, overdueCount: 0, dueSoonCount: 0, rows: [] }
      : { source: 'seed', note: '', total: 2, overdueCount: 1, dueSoonCount: 1, rows: [
          { DefinitionId: 'seed-def-1', InstanceId: 'seed-inst-1', DisplayName: 'PIM4EntraPS review - X', Status: 'InProgress', DueInDays: -5, IsOverdue: true, IsDueSoon: false, Urgency: 'overdue', PendingCount: 2 },
          { DefinitionId: 'seed-def-2', InstanceId: 'seed-inst-2', DisplayName: 'PIM4EntraPS review - Y', Status: 'InProgress', DueInDays: 2, IsOverdue: false, IsDueSoon: true, Urgency: 'dueSoon', PendingCount: 1 } ] },
    '/api/access-reviews/evidence': E
      ? { source: 'seed', note: '', evidence: { Header: { DefinitionId: '', InstanceId: '', DisplayName: '' }, Items: [], Summary: { Total: 0, Approved: 0, Denied: 0, DontKnow: 0, Pending: 0 } } }
      : { source: 'seed', note: '', evidence: {
          Header: { DefinitionId: 'seed-def-1', InstanceId: 'seed-inst-1', DisplayName: 'PIM4EntraPS review - X', Status: 'InProgress' },
          Items: [
            { DecisionId: 'dec-1', PrincipalName: 'Alice Admin', PrincipalUpn: 'alice@contoso.test', Decision: 'Approve', Recommendation: 'Approve' },
            { DecisionId: 'dec-3', PrincipalName: 'Carol Coder', PrincipalUpn: 'carol@contoso.test', Decision: 'NotReviewed', Recommendation: 'Approve' } ],
          Summary: { Total: 2, Approved: 1, Denied: 0, DontKnow: 0, Pending: 1 } } },
    '/api/audit': E
      ? { counts: {}, total: 0, events: [], matchCount: 0, page: 1, pageCount: 1 }
      : { counts: { auth: 2, change: 3 }, total: 5, matchCount: 5, page: 1, pageCount: 1, events: [
          { ts: '2026-06-15T08:00:00Z', actor: 'tester@contoso.com', category: 'change', action: 'commit', target: 'PIM-Assignments-Admins', result: 'ok' },
          { ts: '2026-06-15T07:30:00Z', actor: 'tester@contoso.com', category: 'auth', action: 'login', target: 'manager', result: 'ok' } ] },
    '/api/config': E
      ? { instance: 'contoso', storageMode: 'SQL', filters: {} }
      : { instance: 'contoso', storageMode: 'SQL', filters: { tiers: ['T0', 'T1'] } },
    '/api/conformance/templates': E
      ? { templates: [], instance: 'contoso', tenantRing: 0 }
      : { instance: 'contoso', tenantRing: 1, templates: [
          { templateId: 'defender-xdr', templateVersion: 3, status: 'approved', behind: 1, approved: true } ] },
    '/api/conformance': E
      ? { rows: [], catalogAhead: [] }
      : { rows: [{ key: 'mde/SecurityReader', state: 'Gap' }], catalogAhead: ['NewRole'] },
    '/api/cutover': E
      ? { available: false, reason: 'already on SQL', stages: [] }
      : { available: true, current: 'preflight', stages: [
          { id: 'preflight', name: 'Preflight', state: 'ready' },
          { id: 'upgrade', name: 'Upgrade schema', state: 'pending' },
          { id: 'import', name: 'Import (dry-run)', state: 'pending' },
          { id: 'finalize', name: 'Finalize', state: 'pending' } ] },
    '/api/discovered-resources': E
      ? { baselineMissing: false, newItems: [] }
      : { baselineMissing: false, newItems: [{ kind: 'subscription', id: '/subscriptions/2222', name: 'New sub' }] },
    '/api/discovery-policy': E ? { autoCreate: false, rules: [] } : { autoCreate: true, rules: [{ match: 'rg-*', tier: 1 }] },
    '/api/emergency-status': E ? { active: false } : { active: false, lastRestoreUtc: '2026-06-01T00:00:00Z' },
    // Home/Overview aggregation. The query string (?include=heavy) is stripped by
    // the fetch mock, so one payload serves both the fast + heavy loads (it carries
    // the heavy tiles too, which the GUI tolerates on either call).
    '/api/home': E
      ? { generatedUtc: '2026-06-15T08:00:00Z', includeHeavy: true, tiles: {
          jobs: { ok: true, status: 'unknown', total: 0, failedCount: 0, runningCount: 0, historyCount: 0, failedJobs: [], runningJobs: [], lastRun: null, nextRun: null },
          validation: { ok: true, status: 'green', errors: 0, warnings: 0, infos: 0, ranAtUtc: '2026-06-15T08:00:00Z' },
          breakGlass: { ok: true, active: false },
          tiers: { ok: true, byLevel: { L0: 0, L1: 0, L2: 0, L3: 0, L4: 0, L5: 0, untiered: 0 }, totalGroups: 0, admins: 0 },
          gaps: { ok: true, orphanGroups: 0, gapAdmins: 0, unmanagedTargets: 0, orphanGroupTags: [], gapAdminNames: [] },
          approvals: { ok: true, pending: 0, offboards: 0, revokes: 0 },
          expiring: { ok: true, windowDays: 14, total: 0, expiring: 0, items: [] },
          accessReviews: { ok: true, source: 'seed', total: 0, pending: 0 } } }
      : { generatedUtc: '2026-06-15T08:00:00Z', includeHeavy: true, tiles: {
          jobs: { ok: true, status: 'red', total: 4, enabled: 3, runningCount: 1, failedCount: 1, neverRunCount: 1, historyCount: 6,
                  failedJobs: [{ name: 'discovery-azure', type: 'discovery', scope: 'Azure', lastRunUtc: '2026-06-14T22:00:00Z', detail: 'AuthorizationFailed', runId: 'r1' }],
                  runningJobs: [{ name: 'full-reconcile', type: 'engine-full', scope: 'All', runId: 'rx' }],
                  lastRun: { name: 'tenant-cache', whenUtc: '2026-06-15T06:00:00Z', ok: true, detail: 'ok' },
                  nextRun: { name: 'engine-delta', whenUtc: '2026-06-16T04:00:00Z', synthesized: false } },
          validation: { ok: true, status: 'red', errors: 2, warnings: 5, infos: 1, ranAtUtc: '2026-06-15T08:00:00Z' },
          breakGlass: { ok: true, active: true, activatedBy: 'sec@contoso.com', expiresAtUtc: '2026-06-15T12:00:00Z', reason: 'incident-42', scope: ['ROLE-Id'] },
          tiers: { ok: true, byLevel: { L0: 1, L1: 1, L2: 0, L3: 0, L4: 0, L5: 0, untiered: 1 }, totalGroups: 3, admins: 2 },
          gaps: { ok: true, orphanGroups: 1, gapAdmins: 1, unmanagedTargets: 1, orphanGroupTags: ['PIM-ORG-Sales'], gapAdminNames: ['Bob'] },
          approvals: { ok: true, pending: 2, offboards: 1, revokes: 1 },
          expiring: { ok: true, windowDays: 14, total: 3, expiring: 1, items: [{ principal: 'Alice', role: 'GA', endUtc: '2026-06-18T00:00:00Z', type: 'entra-role' }] },
          accessReviews: { ok: true, source: 'seed', total: 2, pending: 1 } } },
    '/api/alerting': E
      ? { recipients: [], events: { 'engine-failure': true, 'drift': true, 'expiring-access': true, 'break-glass': true }, eventCatalog: ['engine-failure', 'drift', 'expiring-access', 'break-glass'], senderSet: false, enabled: false }
      : { recipients: ['ops@contoso.com'], events: { 'engine-failure': true, 'drift': false, 'expiring-access': true, 'break-glass': true }, eventCatalog: ['engine-failure', 'drift', 'expiring-access', 'break-glass'], senderSet: true, enabled: true },
    '/api/jobs': E
      ? { jobs: [], runningCount: 0 }
      : { runningCount: 1, jobs: [
          { name: 'tenant-cache-refresh', type: 'maintenance', scope: 'all', cadence: 'every 6h', enabled: true,
            inProgress: false, lastResult: 'ok', lastRunUtc: '2026-06-15T06:00:00Z', nextRunUtc: '2026-06-15T12:00:00Z',
            lastDurationMs: 4200, lastRunId: 'r-100' },
          { name: 'engine-delta', type: 'engine', scope: 'contoso', cadence: 'daily 04:00', enabled: true,
            inProgress: true, runningRunId: 'r-201', lastRunUtc: null, nextRunUtc: '2026-06-16T04:00:00Z' } ] },
    '/api/jobs/log': E ? { log: '', status: 'completed' } : { log: 'started\ndone', status: 'completed' },
    '/api/job-schedule': E ? { jobs: [] } : { jobs: [{ name: 'engine-delta', cadence: 'daily 04:00', enabled: true }] },
    '/api/mail-templates': E ? { templates: [] } : { templates: [{ id: 'daily-summary', name: 'Daily summary' }] },
    '/api/portal-access': E
      ? { portalProfile: null }
      : { portalProfile: { services: ['entra'], tier: 1, level: 2, scopes: [], capabilities: ['see', 'manage'], managedAdmins: ['alice@contoso.com'] } },
    '/api/preflight': E
      ? { ranAt: '2026-06-15T08:00:00Z', violations: [], summary: { errors: 0, warnings: 0, infos: 0, acknowledged: 0 }, cacheFreshness: { entraRoles: 'live', aus: 'live', azureScopes: 'live' } }
      : { ranAt: '2026-06-15T08:00:00Z', cacheFreshness: { entraRoles: 'live', aus: 'live', azureScopes: 'live' },
          summary: { errors: 1, warnings: 1, infos: 1, acknowledged: 0 },
          violations: [
            { Severity: 'error',   Csv: 'PIM-Assignments-Admins', Code: 'PIM-DUP', Message: 'duplicate assignment', Target: 'alice@contoso.com' },
            { Severity: 'warning', Csv: 'PIM-Definitions-Roles',  Code: 'PIM-NAME', Message: 'name marker missing', Target: 'ROLE-HELP' },
            { Severity: 'info',    Csv: 'PIM-Definitions-Entra',  Code: 'PIM-INFO', Message: 'fyi', Target: 'PERM-ENTRA' } ] },
    '/api/role-permissions': E
      ? { role: 'HelpdeskAdmin', allowedResourceActions: [] }
      : { role: 'HelpdeskAdmin', displayName: 'Helpdesk Administrator', allowedResourceActions: ['microsoft.directory/users/basic/read'] },
    '/api/settings': E
      ? { storageMode: 'SQL', instance: 'contoso', naming: {}, namingSeeded: false, filters: [], departments: [], approvers: [] }
      : { storageMode: 'SQL', instance: 'contoso', namingSeeded: false, naming: SEED_NAMING,
          filters: [{ key: 'tier0', label: 'Tier 0', patterns: ['*-T0-*'], requireAll: [] }],
          departments: [{ name: 'IT', owner: 'alice@contoso.com' }],
          approvers: [{ upn: 'bob@contoso.com', role: 'approver' }] },
    '/api/templates': E
      ? { templates: [] }
      : { templates: [
          { id: 'defender-xdr', name: 'Defender XDR pack', version: 3, totalRows: 7, description: 'XDR roles', missingCount: 2, missing: { 'PIM-Definitions-Workloads': [{ GroupTag: 'PERM-NEW' }] }, disabled: false },
          { id: 'intune', name: 'Intune pack', version: 1, totalRows: 4, description: 'Intune roles', missingCount: 0, missing: {}, disabled: false } ] },
    '/api/tenant-lists': E ? { entraRoles: [], azScopes: [], workloads: [] } : SEED_TENANT_LISTS,
    '/api/workloads': E ? { workloads: [] } : { workloads: [{ id: 'mde', name: 'Defender XDR' }] },
    '/api/workload-roles': E ? { roles: [] } : { roles: [{ id: 'SecurityReader', name: 'Security Reader' }] },
    '/api/resolve-date': E ? { iso: '2026-07-01T00:00:00Z' } : { iso: '2026-07-01T00:00:00Z' },
    '/api/discovery-baseline': { ok: true },
    '/api/heartbeat': { ok: true },
  };
}

// CSV payloads for /api/csv/<base> (grid / save / wizards read these).
function csvPayload(base, empty) {
  if (empty) return { header: ['Username', 'GroupTag', 'AssignmentType'], rows: [] };
  if (/Account-Definitions-Admins$/.test(base)) {
    return { header: ['Username', 'AdminType', 'Environment', 'Tier'],
             rows: [{ Username: 'A-alice-HELP', AdminType: 'internal-adminuser', Environment: 'prod', Tier: 'T1' }] };
  }
  if (/Assignments-Admins$/.test(base)) {
    return { header: ['Username', 'GroupTag', 'AssignmentType'],
             rows: [{ Username: 'alice@contoso.com', GroupTag: 'ROLE-HELP', AssignmentType: 'Eligible' }] };
  }
  if (/Assignments-Groups$/.test(base)) {
    return { header: ['TargetGroupTag', 'SourceGroupTag', 'AssignmentType'],
             rows: [{ TargetGroupTag: 'ROLE-HELP', SourceGroupTag: 'PERM-ENTRA', AssignmentType: 'Member' }] };
  }
  return { header: ['GroupTag', 'Description'], rows: [{ GroupTag: 'PERM-ENTRA', Description: 'Entra perm' }] };
}

function makeFetch(empty, callLog) {
  const payloads = endpointPayloads(empty);
  return function fetchMock(url) {
    let p = String(url);
    const qix = p.indexOf('?'); if (qix >= 0) p = p.substring(0, qix);
    callLog.push(p);
    let body;
    if (p.indexOf('/api/csv/') === 0 || p.indexOf('/api/data/') === 0) {
      const base = decodeURIComponent(p.split('/').pop());
      body = csvPayload(base, empty);
    } else if (p.indexOf('/api/diff/') === 0) {
      body = { added: [], removed: [], changed: [] };
    } else if (Object.prototype.hasOwnProperty.call(payloads, p)) {
      body = payloads[p];
    } else {
      // POST/PUT and any unseeded path: generic ok so writes don't blow up.
      body = { ok: true };
    }
    const text = JSON.stringify(body);
    return Promise.resolve({
      ok: true, status: 200,
      text: () => Promise.resolve(text),
      json: () => Promise.resolve(body),
    });
  };
}

// ---------------------------------------------------------------------------
// Boot the DOM for one pass.
// ---------------------------------------------------------------------------
function bootDom(mode, empty) {
  let html = rawHtml;
  const sub = {
    '__PIM_TOKEN__': mode === 'server' ? 'test-bearer-token' : '',
    '__PIM_MODE__':  mode === 'server' ? 'server' : 'static',
    '__PIM_VERSION__': '2.4.221',
    '__PIM_DATA__': JSON.stringify(empty ? { tenantName: '', tenantId: '', sourceRoot: '', nodes: [], edges: [], csvBases: [] } : SEED_PIM_DATA),
    '__PIM_NAMING__': JSON.stringify(empty ? {} : SEED_NAMING),
    '__PIM_TENANT_LISTS__': JSON.stringify(empty ? {} : SEED_TENANT_LISTS),
    '__PIM_INSTANCES__': JSON.stringify(empty ? { active: 'local', instances: [] } : SEED_INSTANCES),
    '__PIM_ROLE__': JSON.stringify(SEED_ROLE),
  };
  for (const [k, v] of Object.entries(sub)) html = html.split(k).join(v);

  const errors = [];
  const callLog = [];
  CURRENT_ERR_SINK = errors;
  const vc = new VirtualConsole();
  vc.on('jsdomError', (e) => { errors.push('jsdomError: ' + (e && (e.detail && e.detail.stack || e.detail || e.message) || e)); });
  const dom = new JSDOM(html, {
    url: 'http://localhost/',
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    virtualConsole: vc,
    beforeParse(w) {
      w.onerror = (m, src, line, col, err) => { errors.push(String((err && err.stack) || m)); return true; };
      w.addEventListener('unhandledrejection', ev => { errors.push('unhandledrejection: ' + (ev.reason && ev.reason.message || ev.reason)); });
      w.fetch = mode === 'server'
        ? makeFetch(empty, callLog)
        : () => Promise.reject(new Error('static mode -- API not available'));
      // confirm/alert/prompt are no-ops in jsdom but define them to be safe.
      w.confirm = () => true; w.alert = () => {}; w.prompt = () => null;
    },
  });
  return { dom, errors, callLog };
}

// Allow microtasks (the async renderers await the fetch mock) to flush.
function flush(ms) { return new Promise(r => setTimeout(r, ms)); }

// Heuristic: does a panel show meaningful content (a table row / card / list
// item / labelled control), as opposed to just a "Loading..." stub or blank?
function hasRealContent(panel) {
  if (!panel) return false;
  if (panel.querySelector('table tbody tr, table tr td, .map-item, .wiz-card, .set-card, .auditChip, select, input, button')) return true;
  const txt = (panel.textContent || '').trim();
  return txt.length > 40 && !/^loading/i.test(txt);
}

const EMPTY_STATE_RE = /\b(no |none|empty|not (found|set|started|registered)|nothing|0 |static mode|read-only|need(s)? the server|up to date|no events|no jobs|no active|pick a|pick the|select a|choose a|click .* to|already on)\b/i;

async function runPass(mode, empty) {
  const passName = empty ? 'empty' : (mode === 'server' ? 'seeded' : 'static');
  const { dom, errors, callLog } = bootDom(mode, empty);
  const w = dom.window, doc = w.document;
  await flush(300); // boot (instance picker, heartbeat, default tab render)

  const findings = [];
  const add = (id, severity, tab, message) => findings.push({ id, severity, tab, message, pass: passName });

  // Boot-time errors (before any tab switch).
  if (errors.length) {
    for (const e of errors.splice(0)) add('boot-js-error', 'error', '(boot)', e.slice(0, 300));
  }

  for (const t of TABS) {
    const before = errors.length;
    try { w.switchTab(t.tab); } catch (e) { add('switchtab-throw', 'error', t.name, 'switchTab(' + t.tab + ') threw: ' + e.message); continue; }
    await flush(120); // let the async renderer + fetch mock resolve.

    // 1. reachable + panel present + becomes the active panel.
    const panel = doc.getElementById(t.panel);
    if (!panel) { add('panel-missing', 'error', t.name, 'panel container #' + t.panel + ' not found'); continue; }
    if (!panel.classList.contains('active')) add('panel-not-active', 'error', t.name, 'switchTab(' + t.tab + ') did not activate #' + t.panel);

    // 2. no JS error from rendering this tab.
    const newErrors = errors.slice(before);
    for (const e of newErrors) add('tab-js-error', 'error', t.name, e.slice(0, 300));

    // 3. content vs empty/dead. The STATIC pass only verifies reachability +
    //    no-JS-error (static mode legitimately shows "needs the server"); the
    //    content/empty-state assertions run in the SERVER passes.
    const content = hasRealContent(panel);
    const txt = (panel.textContent || '').trim();
    if (passName === 'static') {
      // nothing further -- reachability + JS-error already asserted above.
    } else if (empty) {
      if (t.dataDriven) {
        const explicit = EMPTY_STATE_RE.test(txt);
        if (!explicit && txt.length < 5) add('empty-blank-panel', 'error', t.name, 'with no data the panel is blank (no explicit empty/error state)');
        else if (!explicit) add('empty-no-explicit-state', 'warn', t.name, 'with no data the panel shows neither rows nor an explicit empty/error message: "' + txt.slice(0, 80) + '"');
      }
    } else {
      if (t.dataDriven && !content) add('seeded-dead-panel', 'error', t.name, 'with seeded data the panel renders no rows/cards/controls (feels dead): "' + txt.slice(0, 80) + '"');
      if (t.dataDriven && /^loading/i.test(txt)) add('seeded-stuck-loading', 'error', t.name, 'panel stuck on a Loading… stub after render');
    }
  }

  return { findings, callLog, window: w, document: doc, dom };
}

// ---------------------------------------------------------------------------
// Layout-sanity + selection-input + reach checks (seeded server pass).
// ---------------------------------------------------------------------------
function layoutAndInputChecks(doc, findings) {
  const add = (id, severity, tab, message) => findings.push({ id, severity, tab, message, pass: 'layout' });

  const brand = doc.getElementById('brand');
  if (!brand) { add('banner-no-brand', 'error', 'Banner', '#brand block missing'); }
  else {
    const tenantBanner = doc.getElementById('tenantBanner');
    if (!tenantBanner || !brand.contains(tenantBanner)) add('banner-tenant-ungrouped', 'error', 'Banner', 'tenant name+GUID (#tenantBanner) not grouped inside #brand');
    else {
      const bt = (tenantBanner.textContent || '').trim();
      if (bt && !/[·]|\b[0-9a-f]{8}-[0-9a-f]{4}/i.test(bt)) add('banner-tenant-format', 'warn', 'Banner', 'tenant banner not in "name · GUID" form: "' + bt + '"');
    }
    const lbl = doc.getElementById('instanceLabel');
    const pick = doc.getElementById('instancePick');
    if (!pick) add('banner-no-instance-picker', 'warn', 'Banner', 'instance dropdown (#instancePick) missing');
    if (pick && !lbl) add('banner-instance-unlabelled', 'error', 'Banner', 'instance dropdown has no label (#instanceLabel)');
  }

  const tabRight = doc.getElementById('tabRight');
  const modeLabel = doc.getElementById('modeLabel');
  const src = doc.getElementById('src');
  if (!tabRight) add('banner-no-tabright', 'warn', 'Banner', '#tabRight (mode|source line) missing');
  else {
    if (!modeLabel || !tabRight.contains(modeLabel)) add('banner-mode-misplaced', 'error', 'Banner', 'mode label not on the mode|source line');
    if (!src || !tabRight.contains(src)) add('banner-source-misplaced', 'error', 'Banner', 'source label not on the mode|source line');
  }
  // Within #brand, the title (h1) must come before the tenant banner (sub).
  if (brand) {
    const kids = [...brand.children];
    const h1ix = kids.findIndex(k => k.tagName === 'H1');
    const tbix = kids.findIndex(k => k.id === 'tenantBanner');
    if (h1ix >= 0 && tbix >= 0 && tbix < h1ix) add('banner-jumbled-order', 'error', 'Banner', 'tenant banner appears before the title (jumbled banner order)');
  }
}

function selectionInputChecks(doc, findings) {
  const add = (id, severity, tab, message) => findings.push({ id, severity, tab, message, pass: 'inputs' });
  const mustBeSelect = [
    { id: 'wlWorkload', label: 'workload picker (Maintenance)', tab: 'Maintenance' },
    { id: 'wlRole',     label: 'workload role picker (Maintenance)', tab: 'Maintenance' },
    { id: 'wlGroup',    label: 'PIM group picker (Maintenance)', tab: 'Maintenance' },
  ];
  for (const m of mustBeSelect) {
    const el = doc.getElementById(m.id);
    if (!el) { add('input-missing', 'warn', m.tab, m.label + ' (#' + m.id + ') not found'); continue; }
    if (el.tagName !== 'SELECT') add('input-freetext', 'error', m.tab, m.label + ' is <' + el.tagName.toLowerCase() + '>, expected a dropdown <select>');
  }
}

// ---------------------------------------------------------------------------
// CONSOLIDATED NAV WALK (REQUIREMENTS §26d).
// The Manager's ~20 flat tabs are folded into a small set of CISO-friendly
// menu GROUPS (NAV_GROUPS in pim-manager.html, built by buildNavGroups()).
// This walk proves the consolidation is honest:
//   - the grouped nav actually built (body.js-nav-grouped, >=1 group rendered);
//   - NO dropped item -- every NAV_GROUPS entry resolved to a real .tab
//     (buildNavGroups records typos in window.PIM_NAV_DROPPED);
//   - EVERY flat tab is reachable from exactly ONE menu item (no orphan/dead
//     menu, no view lost off the menu, no duplicate);
//   - clicking each menu item activates that tab's panel (every item is
//     engine-backed -- it routes to a real, rendering view);
//   - groups are keyboard-friendly (button[role=menuitem] + aria-haspopup).
// Runs in jsdom -- HEADLESS, no browser.
// ---------------------------------------------------------------------------
function navGroupChecks(win, doc, findings) {
  const add = (id, severity, tab, message) => findings.push({ id, severity, tab, message, pass: 'nav' });

  // The flat strip is the canonical set of views.
  const flatTabs = [...doc.querySelectorAll('#tabs .tab[data-tab]')].map(t => t.dataset.tab);
  if (!flatTabs.length) { add('nav-no-flat-tabs', 'error', 'Nav', 'no flat #tabs .tab[data-tab] found to consolidate'); return; }

  // 1. the grouped nav built.
  if (!doc.body.classList.contains('js-nav-grouped')) {
    add('nav-not-built', 'error', 'Nav', 'buildNavGroups() did not enable the consolidated nav (body.js-nav-grouped missing)');
    return;
  }
  const groups = [...doc.querySelectorAll('#navGroups .nav-group')];
  if (groups.length < 4 || groups.length > 7) {
    add('nav-group-count', 'warn', 'Nav', 'consolidated into ' + groups.length + ' groups (expected a SMALL set, ~5-6)');
  }

  // 2. no dropped items (a NAV_GROUPS entry that pointed at a non-existent tab).
  const dropped = win.PIM_NAV_DROPPED || [];
  if (dropped.length) add('nav-dropped-item', 'error', 'Nav', 'menu item(s) reference a non-existent tab (typo -> view hidden): ' + dropped.join(', '));

  // 3. every menu item maps to a real tab; collect the menu's coverage.
  const menuTabs = [];
  for (const g of groups) {
    const gid = g.dataset.group || '(group)';
    const btn = g.querySelector('.nav-group-btn');
    if (!btn) { add('nav-no-btn', 'error', 'Nav', 'group "' + gid + '" has no toggle button'); continue; }
    if (btn.getAttribute('aria-haspopup') !== 'true') add('nav-aria', 'warn', 'Nav', 'group "' + gid + '" button missing aria-haspopup');
    const items = [...g.querySelectorAll('.nav-group-item[data-tab]')];
    if (!items.length) { add('nav-empty-group', 'error', 'Nav', 'group "' + gid + '" has no items (dead menu)'); continue; }
    for (const it of items) {
      const tabKey = it.dataset.tab;
      menuTabs.push(tabKey);
      if (it.tagName !== 'BUTTON') add('nav-item-not-button', 'warn', 'Nav', 'menu item "' + tabKey + '" is <' + it.tagName.toLowerCase() + '>, expected a focusable <button>');
      if (it.getAttribute('role') !== 'menuitem') add('nav-item-role', 'warn', 'Nav', 'menu item "' + tabKey + '" missing role=menuitem');
      if (flatTabs.indexOf(tabKey) < 0) add('nav-item-orphan', 'error', 'Nav', 'menu item "' + tabKey + '" has no backing tab/view (dead control)');
    }
  }

  // 4. EVERY flat view is on the menu exactly once (no lost view, no dup).
  for (const ft of flatTabs) {
    const n = menuTabs.filter(x => x === ft).length;
    if (n === 0) add('nav-view-not-grouped', 'error', 'Nav', 'view "' + ft + '" exists but is on NO menu group (lost off the consolidated nav)');
    else if (n > 1) add('nav-view-duplicated', 'error', 'Nav', 'view "' + ft + '" appears on ' + n + ' menu items (should be exactly one)');
  }

  // 5. clicking each menu item routes to a real, ACTIVE panel (engine-backed view).
  for (const g of groups) {
    for (const it of g.querySelectorAll('.nav-group-item[data-tab]')) {
      const tabKey = it.dataset.tab;
      try { it.click(); } catch (e) { add('nav-item-click-throw', 'error', 'Nav', 'clicking "' + tabKey + '" threw: ' + e.message); continue; }
      const panel = doc.getElementById(tabKey + 'Tab');
      if (!panel) { add('nav-item-no-panel', 'error', 'Nav', 'menu item "' + tabKey + '" -> no panel #' + tabKey + 'Tab'); continue; }
      if (!panel.classList.contains('active')) add('nav-item-not-active', 'error', 'Nav', 'menu item "' + tabKey + '" did not activate its panel #' + tabKey + 'Tab');
      // the owning group should reflect the active selection.
      if (!g.classList.contains('active')) add('nav-group-not-active', 'warn', 'Nav', 'selecting "' + tabKey + '" did not mark its group active');
    }
  }
}

function reachCheck(win, findings) {
  const add = (id, severity, tab, message) => findings.push({ id, severity, tab, message, pass: 'reach' });
  try {
    win.switchTab('map');
    const m = win.buildMapModel ? win.buildMapModel() : null;
    if (!m || typeof win.mapReachCount !== 'function') { add('reach-no-model', 'warn', 'Delegation Map', 'buildMapModel/mapReachCount not exposed for verification'); return; }
    const aliceReach = win.mapReachCount(m, 'admin:alice@contoso.com');
    const bobReach = win.mapReachCount(m, 'admin:bob@contoso.com');
    if (aliceReach !== 2) add('reach-inflated-alice', 'error', 'Delegation Map', 'alice reach = ' + aliceReach + ', expected 2 (1 entra target + 1 workload group). Reach is wrong/inflated.');
    if (bobReach !== 1) add('reach-inflated-bob', 'error', 'Delegation Map', 'bob reach = ' + bobReach + ', expected 1 (1 azure target). Reach is wrong/inflated.');
  } catch (e) { add('reach-throw', 'warn', 'Delegation Map', 'reach verification threw: ' + e.message); }
}

(async function main() {
  try {
    const all = [];

    // Pass 1: STATIC mode (no token) -- panels reachable + no JS error.
    const staticPass = await runPass('static', false);
    all.push(...staticPass.findings);

    // Pass 2: SEEDED server mode -- real content, no dead panels.
    const seeded = await runPass('server', false);
    all.push(...seeded.findings);
    layoutAndInputChecks(seeded.document, all);
    selectionInputChecks(seeded.document, all);
    navGroupChecks(seeded.window, seeded.document, all);   // §26d consolidated nav walk
    reachCheck(seeded.window, all);

    // Pass 3: EMPTY server mode -- explicit empty/error states, no blank panels.
    const emptyPass = await runPass('server', true);
    all.push(...emptyPass.findings);

    const errors = all.filter(f => f.severity === 'error');
    const warns = all.filter(f => f.severity === 'warn');
    const out = {
      ok: errors.length === 0,
      summary: {
        tabsChecked: TABS.length,
        errors: errors.length,
        warnings: warns.length,
        endpointsCalled: [...new Set(seeded.callLog)].length,
      },
      // Every distinct /api/* path the GUI ACTUALLY called during the seeded
      // render (across all tabs). The PS wrapper verifies each resolves to a
      // real route handler -- a DOM-level no-dead-control check spanning every
      // tab, with no whitelist (only really-invoked endpoints are checked).
      endpointsCalled: [...new Set(seeded.callLog)].sort(),
      findings: all,
    };
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
    process.exit(0);
  } catch (e) {
    harnessFail('validator crashed: ' + (e && e.stack || e));
  }
})();
