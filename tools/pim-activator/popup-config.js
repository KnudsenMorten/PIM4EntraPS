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
export function resolveBulkActivateConfirmThreshold(raw) {
  const n = (typeof raw === 'number') ? raw : parseInt(String(raw == null ? '' : raw).trim(), 10)
  if (!isFinite(n) || isNaN(n) || n <= 0) return BULK_ACTIVATE_CONFIRM_THRESHOLD_DEFAULT
  return Math.max(
    BULK_ACTIVATE_CONFIRM_THRESHOLD_MIN,
    Math.min(BULK_ACTIVATE_CONFIRM_THRESHOLD_MAX, Math.floor(n))
  )
}
