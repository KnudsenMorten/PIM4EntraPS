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
