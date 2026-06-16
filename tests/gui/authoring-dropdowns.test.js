// @ts-check
// Headless (no browser, no DOM) verification that the PIM Manager Authoring tab
// populates its dropdowns from REAL catalog data -- the "no dead views" rule.
//
// It extracts the PURE data-source helpers from pim-manager.html (between the
// __PIM_AUTHORING_HELPERS_START__ / _END__ markers), executes them against a
// SEEDED catalog (groups, Entra-role cache, admin assignments), and asserts the
// produced option lists. It also asserts the Authoring markup wires those
// sources into real controls (datalist / multi-select / select) and that no raw
// unvalidated free-text path remains for group / role / tag / admin selection.
//
// Run:  node tests/gui/authoring-dropdowns.test.js   (exit 0 green / 1 red)

'use strict';
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { console.log('  PASS ' + name); pass++; }
  else { console.log('  FAIL ' + name); fail++; }
}
function arrEq(a, b) { return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => x === b[i]); }

const htmlPath = path.join(__dirname, '..', '..', 'tools', 'pim-manager', 'pim-manager.html');
ok('pim-manager.html present', fs.existsSync(htmlPath));
const html = fs.readFileSync(htmlPath, 'utf8');

// --- 1. Extract + load the PURE helper functions ----------------------------
const startMark = html.indexOf('__PIM_AUTHORING_HELPERS_START__');
const endMark = html.indexOf('__PIM_AUTHORING_HELPERS_END__');
ok('authoring helper markers present', startMark > -1 && endMark > startMark);
// Slice on whole lines: begin AFTER the start-marker comment line, end BEFORE
// the end-marker comment line, so the marker comments themselves aren't included.
const start = html.indexOf('\n', startMark) + 1;
const end = html.lastIndexOf('\n', endMark);
const block = html.slice(start, end);
ok('extracted block defines collectAuthoringEntraRoles', /function collectAuthoringEntraRoles\(/.test(block));
ok('extracted block defines collectKnownAdmins', /function collectKnownAdmins\(/.test(block));
ok('extracted block defines collectAdminAssignedTags', /function collectAdminAssignedTags\(/.test(block));

// Build a sandbox: the helpers reference csvCache / pendingChanges / getCachedList
// as defaults; we inject seeded fakes so they read our catalog.
const SEED = {
  // Real Entra-role catalog (as the tenant-list cache shapes it).
  entraRoles: { items: [
    { displayName: 'User Administrator' },
    { displayName: 'Helpdesk Administrator' },
    { displayName: 'Global Reader' },
    { displayName: 'User Administrator' } // dup -> must be de-duped
  ] },
  // Cached CSVs (definition tags + admin assignments).
  csvCache: {
    'PIM-Definitions-Roles-Groups': { rows: [ { GroupTag: 'ROLE-USERADMIN' }, { GroupTag: 'ROLE-HELPDESK' } ] },
    'PIM-Assignments-Admins': { rows: [
      { Username: 'adm.jane', GroupTag: 'ROLE-USERADMIN' },
      { Username: 'adm.jane', GroupTag: 'ROLE-HELPDESK' },
      { Username: 'adm.bob',  GroupTag: 'ROLE-HELPDESK' }
    ] },
    'Account-Definitions-Admins': { rows: [
      { UserName: 'adm.jane' }, { UserName: 'adm.carol' } // carol defined, not yet assigned
    ] }
  },
  pendingChanges: {}
};
SEED.PIM_DATA = { csvBases: [
  { base: 'PIM-Definitions-Roles-Groups', group: 'Definitions' }
] };

const sandbox = {
  getCachedList: (key) => SEED[key] || { items: [] },
  csvCache: SEED.csvCache,
  pendingChanges: SEED.pendingChanges,
  PIM_DATA: SEED.PIM_DATA,
  collectKnownGroupTags: null // defined below by the extracted block dependency
};
// collectAuthoringEntraRoles is self-contained; collectKnownAdmins /
// collectAdminAssignedTags read csvCache+pendingChanges. None of the three
// need collectKnownGroupTags, so the block is loadable standalone.
const factory = new Function(
  'getCachedList', 'csvCache', 'pendingChanges', 'PIM_DATA',
  block + '\n; return { collectAuthoringEntraRoles, collectKnownAdmins, collectAdminAssignedTags };'
);
const H = factory(sandbox.getCachedList, sandbox.csvCache, sandbox.pendingChanges, sandbox.PIM_DATA);

// --- 2. Entra-role options come from the seeded role cache, de-duped+sorted --
const roles = H.collectAuthoringEntraRoles();
ok('entra-role options sourced from cache (de-duped + sorted)',
  arrEq(roles.map(r => r.value), ['Global Reader', 'Helpdesk Administrator', 'User Administrator']));
ok('entra-role options carry {value,label}', roles.length > 0 && roles.every(r => r.value && r.label));
ok('empty role cache -> empty options (no fabricated values)',
  arrEq(H.collectAuthoringEntraRoles((k) => ({ items: [] })).map(r => r.value), []));

// --- 3. Admin list comes from real assignment + definition rows -------------
const admins = H.collectKnownAdmins();
ok('admin options sourced from assignments + definitions (sorted, unique)',
  arrEq(admins, ['adm.bob', 'adm.carol', 'adm.jane']));

// pending-session edits are reflected (a freshly-imported admin shows up).
const pend = { 'PIM-Assignments-Admins': { rows: [ { Username: 'adm.new', GroupTag: 'ROLE-X' } ], deletes: new Set() } };
const adminsP = H.collectKnownAdmins(SEED.csvCache, pend);
ok('pending admin edits are reflected in the admin list', adminsP.includes('adm.new'));

// --- 4. "From" tags are the admin's CURRENT assignments only ----------------
ok('from-tags for adm.jane = her real assignments',
  arrEq(H.collectAdminAssignedTags('adm.jane'), ['ROLE-HELPDESK', 'ROLE-USERADMIN']));
ok('from-tags for adm.bob = his real assignment',
  arrEq(H.collectAdminAssignedTags('adm.bob'), ['ROLE-HELPDESK']));
ok('from-tags for unknown admin = empty (no guessing)',
  arrEq(H.collectAdminAssignedTags('adm.ghost'), []));
ok('from-tags case-insensitive on username',
  arrEq(H.collectAdminAssignedTags('ADM.BOB'), ['ROLE-HELPDESK']));

// --- 5. Markup wires the sources into real controls (no raw string fields) --
// Bulk-attach: GroupTag datalist (pick-or-type) + Entra-role MULTI-select.
ok('bulk-attach GroupTag is a datalist combobox', /id="aBaGroup"[^>]*list="aBaGroupList"/.test(html) && /<datalist id="aBaGroupList">/.test(html));
ok('bulk-attach roles is a multi-select (not free text)', /<select id="aBaRoles" multiple/.test(html));
ok('bulk-attach roles read from selectedOptions', /getElementById\('aBaRoles'\)\.selectedOptions/.test(html));
ok('bulk-attach NO raw text input for roles', !/id="aBaRoles" type="text"/.test(html));

// Move-admin: Admin select, From-tag select, To-tag datalist combobox.
ok('move-admin Admin is a <select>', /fieldRow\('Admin', '<select id="aMvUser">/.test(html));
ok('move-admin From-tag is a <select>', /fieldRow\('From tag \(current\)', '<select id="aMvFrom">/.test(html));
ok('move-admin To-tag is a datalist combobox', /id="aMvTo"[^>]*list="aMvToList"/.test(html) && /<datalist id="aMvToList">/.test(html));
ok('move-admin NO raw text input for user/from', !/id="aMvUser" type="text"/.test(html) && !/id="aMvFrom" type="text"/.test(html));

// Population functions wire the helpers into the controls.
ok('renderAuthoring fills pickers from collectAuthoringEntraRoles', /collectAuthoringEntraRoles\(\)/.test(html));
ok('renderAuthoring fills admin select from collectKnownAdmins', /collectKnownAdmins\(\)/.test(html));
ok('renderAuthoring fills from-tags from collectAdminAssignedTags', /collectAdminAssignedTags\(/.test(html));
ok('renderAuthoring preloads tenant role list', /ensureTenantLists\(\['entraRoles'\]\)/.test(html));
ok('renderAuthoring preloads admin-assignment CSV', /loadCsv\('PIM-Assignments-Admins'\)/.test(html));

console.log('\n RESULT: ' + pass + ' pass, ' + fail + ' fail');
process.exit(fail ? 1 : 0);
