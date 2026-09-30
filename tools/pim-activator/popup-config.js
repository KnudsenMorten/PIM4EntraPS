// PIM Activator -- pure config helpers (no DOM, no chrome.* APIs).
//
// Extracted into its own module so the logic can be unit-tested under Node
// (`node --check` clean + importable without the browser runtime). popup.js
// imports these; keeping them here means there is ONE definition, no drift,
// and the mature popup render path is untouched.

// Default size of selection at/above which the bulk-activate button arms a
// "click again to confirm" guard. Admins can raise it (high-trust tenants
// that routinely activate many roles) or lower it (extra caution) via the
// managed catalog entry / managed config -- NOT via free-text user entry
// (confirm strength is an admin policy decision, not a user preference).
export const BULK_ACTIVATE_CONFIRM_THRESHOLD_DEFAULT = 5
export const BULK_ACTIVATE_CONFIRM_THRESHOLD_MIN = 1
export const BULK_ACTIVATE_CONFIRM_THRESHOLD_MAX = 100

// Resolve the effective bulk-activate confirm threshold from a raw policy /
// catalog value. Accepts a number or numeric string; clamps into the sane
// range; falls back to the default for anything missing / non-numeric / <= 0.
// Pure + side-effect-free so it is unit-testable.
// Per-DEVICE cap on AUTO-activation (operator 2026-09-23: a customer wants to limit auto-activate to
// e.g. 2-5 groups "so people dont activates 35 groups every day (least priv)"). Managed policy only
// (chrome.storage.managed 'autoActivateMaxGroups', pushed per device by Intune ADMX or the server
// scripts) -- never a user setting and never taken from the tenant catalog, so it cannot be loosened
// from anywhere but the device policy.
//   missing / blank / non-numeric / negative -> null  = NO LIMIT (unchanged behaviour)
//   0                                        -> 0     = auto-activation OFF on this device
//   N                                        -> N     = at most N groups, clamped to 100
export const AUTO_ACTIVATE_MAX_GROUPS_MAX = 100
export function resolveAutoActivateMaxGroups(raw) {
  if (raw == null) return null
  const s = String(raw).trim()
  if (s === '' || !/^-?\d+(\.\d+)?$/.test(s)) return null
  const n = Math.floor(Number(s))
  if (!isFinite(n) || n < 0) return null
  return Math.min(AUTO_ACTIVATE_MAX_GROUPS_MAX, n)
}
// Which ticked groups the on-open sweep may activate: the first `max` in the given order, the rest
// are skipped (reported, never activated). max === null means no limit.
export function selectAutoActivateTargets(candidates, max) {
  const list = Array.isArray(candidates) ? candidates : []
  if (max == null) return { run: list.slice(), skipped: [] }
  return { run: list.slice(0, max), skipped: list.slice(max) }
}
// Which rows the auto-activate sweep should start NOW: group rows that are ticked, listed, not already active and not
// attempted earlier in this popup session. Operator 2026-09-30 ("auto activate ... for sub-groups ... never starts the
// activation"): a sub-group (a permission group nested in a role group) is only LISTED once its parent is active, so the
// old once-per-session sweep had always run before it appeared -- a ticked sub-group could never auto-activate. The
// sweep now runs on every list load and skips only what it already tried.
export function pickAutoActivateCandidates(rows, isTicked, attempted) {
  const list = Array.isArray(rows) ? rows : []
  const tried = attempted instanceof Set ? attempted : new Set()
  const ticked = (typeof isTicked === 'function') ? isTicked : (() => false)
  return list.filter(r => r && r.kind === 'group' && !r.depth && !r.isActive && r.groupId &&
    ticked(r.rowKey || ('group:' + r.groupId)) && !tried.has(r.groupId))
}
// How many auto-activate slots of the per-device cap are IN USE: ticked groups that are active, plus groups this session
// already activated (or found pending) that do not show as active yet. Without the second half, a later sweep pass -- which
// now runs on every list load -- saw the just-activated groups as "not active", and could exceed autoActivateMaxGroups.
export function countAutoActivateInUse(rows, isTicked, started) {
  const ticked = (typeof isTicked === 'function') ? isTicked : (() => false)
  const ids = new Set()
  for (const r of (Array.isArray(rows) ? rows : [])) {
    if (r && r.kind === 'group' && r.groupId && r.isActive && ticked(r.rowKey || ('group:' + r.groupId))) ids.add(String(r.groupId).toLowerCase())
  }
  for (const id of (started instanceof Set ? started : [])) ids.add(String(id).toLowerCase())
  return ids.size
}
// The ticked groups that are NOT in the list at all -- sub-groups waiting for their parent group to be active (they
// surface in the eligibility list only then). `ticks` = the stored { rowKey: true } map.
export function tickedGroupIdsNotListed(ticks, rows) {
  const listed = new Set((Array.isArray(rows) ? rows : []).filter(r => r && r.groupId).map(r => String(r.groupId).toLowerCase()))
  return Object.keys(ticks && typeof ticks === 'object' ? ticks : {})
    .filter(k => ticks[k] && /^group:/i.test(k))
    .map(k => k.slice(6))
    .filter(id => id && !listed.has(id.toLowerCase()))
}
// Graph throttling (operator 2026-09-30: bulk deactivation -> "429: Too Many Requests" x3, nothing retried). How long to
// wait before retry `attempt` (1-based) of a request that answered `status`, or null = do not retry:
//   429           any method -- a throttled request was NOT processed, so even a POST is safe to repeat;
//   503 / 504     GET only   -- a write may already have been applied;
// Retry-After (seconds or an HTTP date) is honoured, capped at 60 s; otherwise 5 / 10 / 20 / 30 s. At most `maxRetries`.
export const GRAPH_RETRY_MAX = 4
export function graphRetryDelayMs(status, method, retryAfter, attempt, maxRetries = GRAPH_RETRY_MAX, nowMs = Date.now()) {
  const s = Number(status) || 0
  const m = String(method || 'GET').toUpperCase()
  const a = Number(attempt) || 1
  if (a > maxRetries) return null
  if (!(s === 429 || ((s === 503 || s === 504) && m === 'GET'))) return null
  const ra = retryAfter == null ? '' : String(retryAfter).trim()
  let ms = null
  if (/^\d+(\.\d+)?$/.test(ra)) ms = Math.round(Number(ra) * 1000)
  else if (ra) { const t = Date.parse(ra); if (!isNaN(t)) ms = Math.max(0, t - nowMs) }
  if (ms == null) ms = [5000, 10000, 20000, 30000][Math.min(a, 4) - 1]
  return Math.min(60000, Math.max(1000, ms))
}
// An activation answer that is NOT a failure (operator 2026-09-30: ticking 'auto' showed "Activation failed ... 400: There
// is already an existing pending Role assignment request"): 'pending' = a request for this assignment is already in flight
// (waiting for approval, or still being processed -- e.g. the auto sweep started it a moment earlier); 'active' = the
// assignment already exists. null = a real error. `err` = the Error graph() throws (status + message + body).
export function classifyActivationAnswer(err) {
  if (!err) return null
  const status = Number(err.status) || 0
  const code = String((err.body && err.body.error && err.body.error.code) || '')
  const text = code + ' ' + String(err.message || '')
  if (status !== 400 && status !== 409) return null
  if (/existing pending|pending role assignment request|PendingRoleAssignmentRequest|RoleAssignmentRequestExists/i.test(text)) return 'pending'
  if (/RoleAssignmentExists|assignment already exists|already (an )?active/i.test(text)) return 'active'
  return null
}
export function activationAnswerText(kind) {
  // 2026-09-30 correction: a pending request is almost always WAITING FOR APPROVAL -- it is never "activating", and must never
  // be followed by the propagation watch (that ran 20 min and ended "Still not propagated", operator screenshot).
  if (kind === 'pending') return 'Waiting for approval -- a request for this group is already open. It activates when an approver approves it; nothing more to do here.'
  if (kind === 'active') return 'Already active.'
  return ''
}
// The activation RESPONSE says the request waits for an approver (PIM policy "require approval") -- then nothing is
// provisioned yet: show it, do NOT watch propagation, do NOT wait for its sub-groups. Graph status values: PendingApproval,
// PendingAdminDecision (older).
export function isApprovalPendingStatus(status) {
  return /^(PendingApproval|PendingAdminDecision)$/i.test(String(status || '').trim())
}
export const APPROVAL_PENDING_TEXT = 'Submitted -- waiting for approval. It activates when an approver approves it.'
// May one more group be ticked 'auto'? `ticked` = how many are ticked now.
export function canTickAnotherAutoActivate(ticked, max) {
  if (max == null) return true
  return (Number(ticked) || 0) < max
}

export function resolveBulkActivateConfirmThreshold(raw) {
  const n = (typeof raw === 'number') ? raw : parseInt(String(raw == null ? '' : raw).trim(), 10)
  if (!isFinite(n) || isNaN(n) || n <= 0) return BULK_ACTIVATE_CONFIRM_THRESHOLD_DEFAULT
  return Math.max(
    BULK_ACTIVATE_CONFIRM_THRESHOLD_MIN,
    Math.min(BULK_ACTIVATE_CONFIRM_THRESHOLD_MAX, Math.floor(n))
  )
}
