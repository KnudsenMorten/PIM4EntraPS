#!/usr/bin/env node
/*
 * LOCK (operator 2026-06-25): the propagation watch (watchPropagation in popup.js) must stay
 * POLL-DRIVEN and stable — no churning the change-detection in future releases.
 *
 * The completion decision must come from what each 10s POLL observes, never from a hardcoded
 * elapsed-time settle timer, and must use the COMBINED signal (groups OR roles), not eligible
 * groups alone. This gate fails the build if any of the banned regressions reappears:
 *   - "settle the instant the count moves" (v1.6.66) — completing on the first change.
 *   - a fixed settle duration (settleAfterMs / settleConfirmMs / Date.now()-lastChangeAt >= N).
 *   - watching eligible groups only (missing role-granting activations).
 *
 * Pure Node, no deps. Exit 0 = clean, exit 1 = a banned pattern returned or a required one is gone.
 */
const fs = require('fs')
const path = require('path')

const src = fs.readFileSync(path.join(__dirname, '..', 'popup.js'), 'utf8')
const fails = []

// --- REQUIRED: poll-count settle (not a duration) ---
if (!/STABLE_POLLS/.test(src))
  fails.push('STABLE_POLLS missing — completion must settle on consecutive identical POLLS, not a timer.')
if (!/stablePolls\s*>=\s*STABLE_POLLS/.test(src))
  fails.push('settle condition `stablePolls >= STABLE_POLLS` missing — the poll-driven settle was removed.')
if (!/stablePolls\s*\+\+/.test(src))
  fails.push('`stablePolls++` missing — the watch no longer counts consecutive stable polls.')

// --- REQUIRED: COMBINED signal = groups + active assignments + active Entra roles ---
if (!/listActiveDirectEntraRolesForMe/.test(src))
  fails.push('listActiveDirectEntraRolesForMe missing from the watch — the signal must include ENTRA ROLES (PIM v1 role-to-admin).')
if (!/listActiveGroupAssignmentsForMe/.test(src))
  fails.push('listActiveGroupAssignmentsForMe missing from the watch — active group assignments must count.')
if (!/listActiveDirectAzureRbacForMe/.test(src))
  fails.push('listActiveDirectAzureRbacForMe missing from the watch — the signal must include AZURE RBAC (PIM v1 azure-role-to-admin).')

// --- REQUIRED: "Show Roles" enumerates the REAL role from the platform (LOCKED — has regressed before) ---
// The role preview must fan out BOTH directions through group nesting so a role granted via an
// up-the-chain role-assignable group (PIM v2) is found, and must query Azure ELIGIBLE too.
if (!/transitiveMembers/.test(src))
  fails.push('role preview must fan out DOWN via /groups/{id}/transitiveMembers — missing.')
if (!/transitiveMemberOf/.test(src))
  fails.push('role preview must fan out UP via /groups/{id}/transitiveMemberOf (where the granted role usually lives in PIM v2) — missing.')
if (!/transitiveRoleAssignments/.test(src))
  fails.push('role preview must use beta transitiveRoleAssignments — missing.')
if (!/roleeligibilityscheduleinstances/i.test(src))
  fails.push('Show Roles must include Azure ELIGIBLE assignments (roleeligibilityscheduleinstances) — missing.')

// --- REQUIRED: INDIRECT-group completion = ROLE-LANDED, not count growth (operator 2026-06-26) ---
// An indirect (leaf) group never grows the COMBINED count (it just flips eligible->active), so the
// watch must complete it on its ROLE landing, not on a count change that never comes. Guard the
// per-scope classification + Entra verification so this can't regress back to count-only.
if (!/classifyWatchedGroup/.test(src))
  fails.push('classifyWatchedGroup missing — the watch must classify DIRECT (fan-out) vs INDIRECT (leaf) scopes.')
if (!/transitiveMembers\/microsoft\.graph\.group/.test(src))
  fails.push('direct-vs-indirect discriminator missing — classify via /groups/{id}/transitiveMembers/microsoft.graph.group (does it nest child PIM groups?).')
if (!/listMyActiveEntraRoleDefIdsTransitive/.test(src))
  fails.push('listMyActiveEntraRoleDefIdsTransitive missing — an indirect group\'s Entra role must be VERIFIED assigned (transitive) before release.')
if (!/scopeDone/.test(src) || !/allScopesDone/.test(src))
  fails.push('per-scope completion (scopeDone / allScopesDone) missing — each scope must complete by ITS OWN rule so an indirect scope can\'t prematurely settle a direct role group.')

// --- BANNED: hardcoded settle timers / first-change completion ---
for (const [pat, why] of [
  [/settleAfterMs/,   'settleAfterMs (hardcoded settle timer) is banned — settle on polls, not elapsed ms.'],
  [/settleConfirmMs/, 'settleConfirmMs (hardcoded settle timer) is banned — settle on polls, not elapsed ms.'],
  [/lastChangeAt/,    'lastChangeAt-based settle is banned — completion must be poll-count driven.'],
]) {
  if (pat.test(src)) fails.push(why)
}

if (fails.length) {
  console.error('FAIL: watch poll-driven lock violated:\n  - ' + fails.join('\n  - '))
  process.exit(1)
}
console.log('OK: propagation watch is poll-driven (STABLE_POLLS), combined groups+roles signal, no hardcoded settle timer.')
