// Offline behavioral test for the nested permission-group discovery logic in
// popup.js (two-tier PIM-for-Groups nesting -- DESIGN.md 3.1). It extracts
// listNestedForParent + discoverNestedRows from popup.js and runs them against a
// mocked Graph that models the PIM-v2 nesting diagram, so the row shape /
// active-state / member-filter / dedup behavior is regression-locked WITHOUT a
// browser. The live Graph round-trip (a real user selfActivate of a nested
// permission group) is verified separately on a tenant -- see REQUIREMENTS.md
// SS125 ("live-verification gate").
//
// Run:  node test-nested-perm-groups.js
'use strict'
const fs   = require('fs')
const vm   = require('vm')
const path = require('path')

// ---- Extract just the two nested-discovery functions from popup.js ----------
const popupPath = path.join(__dirname, '..', 'tools', 'pim-activator', 'popup.js')
const src = fs.readFileSync(popupPath, 'utf8')
const start = src.indexOf('async function listNestedForParent')
const end   = src.indexOf('async function activateGroup')
if (start < 0 || end < 0 || end <= start) {
  console.error('FAIL: could not locate listNestedForParent..activateGroup region in popup.js')
  process.exit(1)
}
const region = src.slice(start, end)

// ---- Mock Graph modeling the diagram --------------------------------------
// User is an ACTIVE member of role group 'role-ce' (PIM-ROLE-CloudEngineer).
// That role group is ELIGIBLE for AppAdmin + AzRes + PowerBI (+ an 'owner'
// access edge that must be ignored), and already ACTIVE in AzDevOps + AppAdmin.
const ELIG = {
  'role-ce': [
    { groupId: 'pg-appadmin',    accessId: 'member', endDateTime: null },
    { groupId: 'pg-azres',       accessId: 'member', endDateTime: null },
    { groupId: 'pg-powerbi',     accessId: 'member', endDateTime: null },
    { groupId: 'pg-owneraccess', accessId: 'owner' }              // non-member -> must be excluded
  ]
}
const ACTIVE = {
  // pg-appadmin is BOTH eligible AND currently active -> its row.isActive=true
  'role-ce': [ { groupId: 'pg-azdevops', accessId: 'member' }, { groupId: 'pg-appadmin', accessId: 'member' } ]
}
async function graph(token, method, urlPath) {
  const m = urlPath.match(/principalId%20eq%20'([^']+)'/) || urlPath.match(/principalId eq '([^']+)'/)
  const pid = m ? decodeURIComponent(m[1]) : ''
  if (urlPath.indexOf('eligibilityScheduleInstances') >= 0) return { value: ELIG[pid] || [] }
  if (urlPath.indexOf('assignmentScheduleInstances')  >= 0) return { value: ACTIVE[pid] || [] }
  return { value: [] }
}
async function hydrateGroupNames(token, ids) {
  const names = {
    'pg-appadmin': 'PIM-Entra-ID-ApplicationAdministrator-L1-T0-CP-ID',
    'pg-azres':    'PIM-AzRes-MP-Platform-Management-Owner-L3-T1-MP-ID',
    'pg-powerbi':  'PIM-PowerBI-WS-MyCompanyKPIs-Test-Admins-L3-T1-WDP-ID',
    'pg-azdevops': 'PIM-AzDevOps-TeamsContributors-L5-T1-WDP-ID'
  }
  const out = {}
  for (const id of ids) out[id] = names[id] || id
  return out
}

const sandbox = { graph, hydrateGroupNames, console, Set, encodeURIComponent, decodeURIComponent }
vm.createContext(sandbox)
vm.runInContext(region, sandbox)

// ---- Assertions ------------------------------------------------------------
let pass = 0, fail = 0
function ok(cond, msg) { if (cond) { pass++; console.log('  PASS ' + msg) } else { fail++; console.error('  FAIL ' + msg) } }

;(async () => {
  const rows = await sandbox.discoverNestedRows('tok', ['role-ce'])
  const byGid = {}
  rows.forEach(r => { byGid[r.groupId] = r })

  ok(rows.length === 3, `3 member eligibilities folded out (owner edge ignored) -> got ${rows.length}`)
  ok(byGid['pg-appadmin'] && byGid['pg-azres'] && byGid['pg-powerbi'], 'the three member permission groups present')
  ok(!byGid['pg-owneraccess'], 'non-member (owner) eligibility excluded')
  ok(rows.every(r => r.kind === 'group' && r.isNested === true && r.depth === 1), 'rows are kind=group, isNested, depth 1')
  ok(rows.every(r => r.parentGroupId === 'role-ce'), 'parentGroupId set to the role group')
  ok(rows.every(r => r.rowKey === 'nested:role-ce:' + r.groupId), 'rowKey is nested:parent:child (unique per pairing)')
  ok(rows.every(r => r.accessId === 'member' && r.checked === false), 'accessId=member, unchecked by default')
  ok(byGid['pg-appadmin'].isActive === true, 'pg-appadmin (eligible AND active) -> isActive true (not re-activatable)')
  ok(byGid['pg-azres'].isActive === false && byGid['pg-powerbi'].isActive === false, 'other nested groups -> isActive false (ready)')
  ok(rows.every(r => Array.isArray(r.previewEntraRoles) && r.previewEntraRoles.length === 0
                  && Array.isArray(r.previewAzureRoles) && r.previewAzureRoles.length === 0), 'previews [] (no "Loading roles" hang on nested rows)')
  ok(byGid['pg-azres'].displayName === 'PIM-AzRes-MP-Platform-Management-Owner-L3-T1-MP-ID', 'display name hydrated from Graph')

  const none = await sandbox.discoverNestedRows('tok', [])
  ok(none.length === 0, 'no active role groups -> no nested rows')

  const empty = await sandbox.discoverNestedRows('tok', ['role-none'])
  ok(empty.length === 0, 'role group with no nested eligibilities -> no nested rows')

  const deduped = await sandbox.discoverNestedRows('tok', ['role-ce', 'role-ce'])
  ok(deduped.length === 3, 'duplicate parent ids deduped -> still 3 rows')

  console.log(`\nNested perm-group discovery: ${pass} passed, ${fail} failed`)
  process.exit(fail ? 1 : 0)
})().catch(e => { console.error('FAIL (threw):', e && e.stack || e); process.exit(1) })
