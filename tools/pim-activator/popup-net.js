// PIM Activator -- network resilience primitives (no DOM, no chrome.* APIs).
//
// Extracted into its own module so the timeout / watchdog logic can be
// unit-tested under Node (`node --check` clean + importable without the
// browser runtime), exactly like popup-config.js. popup.js imports these;
// keeping them here means ONE definition, no drift, and a hung Graph/token/ARM
// request can NEVER leave the popup stuck on "Loading..." forever.
//
// Background: a bare fetch() has no timeout. On a freshly-built PAW behind a
// proxy that black-holes the connection (or a Conditional-Access challenge
// that never returns, or a DNS hang), the awaiting code path neither resolves
// nor rejects -- the popup sits on "Loading your PIM delegations" forever.
// fetchWithTimeout() aborts after a budget and throws a recognisable error;
// withWatchdog() bounds a whole multi-call path as a belt-and-suspenders.

// Per-call budgets. Exported so popup.js and tests share the same numbers.
export const FETCH_TIMEOUT_MS = 30 * 1000        // per individual HTTP request
export const LOAD_WATCHDOG_MS = 75 * 1000        // whole "load my delegations" path
export const SOURCE_WATCHDOG_MS = 55 * 1000      // EACH eligibility source independently:
//   the load runs 6 sources in parallel and must NOT fail as a whole just because one
//   optional source (e.g. a sequential Azure-RBAC subscription sweep, or a throttled
//   Graph page) is slow. Bounding each source on its own lets a laggard degrade to an
//   empty result while the rest of the list still renders. Kept under LOAD_WATCHDOG_MS
//   so the parallel set settles well before the old whole-path bound.

// Run `p`, but if it doesn't settle within `ms`, resolve to a tagged failure instead
// of letting it block siblings. NEVER rejects -- returns { ok, value, error, timedOut }
// so a Promise.all over several of these always settles and partial results survive.
export async function settleWithin(p, ms, name) {
  try {
    const value = await withWatchdog(Promise.resolve().then(() => p), ms, name)
    return { ok: true, name, value, error: null, timedOut: false }
  } catch (e) {
    return { ok: false, name, value: undefined, error: e, timedOut: !!(e && e.timedOut) }
  }
}

export class TimeoutError extends Error {
  constructor(message) { super(message); this.name = 'TimeoutError'; this.timedOut = true }
}

// fetch() wrapper that aborts after `timeoutMs` and throws a TimeoutError the
// callers can recognise (err.timedOut === true). Honours any caller-supplied
// AbortSignal by chaining: if the caller's signal aborts, we abort too. A
// network-level failure (DNS/offline/blocked) is re-tagged err.networkError so
// the UI can distinguish "couldn't reach Microsoft" from "Microsoft was slow".
// `fetchImpl` is injectable for tests; defaults to the global fetch.
export async function fetchWithTimeout(url, opts = {}, timeoutMs = FETCH_TIMEOUT_MS, fetchImpl) {
  const doFetch = fetchImpl || (typeof fetch !== 'undefined' ? fetch : null)
  if (!doFetch) throw new Error('no fetch implementation available')
  const ctrl = new AbortController()
  const label = (opts && opts.method ? opts.method + ' ' : 'GET ') +
    String(url).replace(/[?#].*$/, '')   // strip query for the diagnostic label
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  if (opts && opts.signal) {
    if (opts.signal.aborted) ctrl.abort()
    else opts.signal.addEventListener('abort', () => ctrl.abort(), { once: true })
  }
  try {
    return await doFetch(url, Object.assign({}, opts, { signal: ctrl.signal }))
  } catch (e) {
    if (e && e.name === 'AbortError') {
      throw new TimeoutError(`Request timed out after ${Math.round(timeoutMs / 1000)}s: ${label}`)
    }
    if (e && e.name === 'TypeError') {
      const ne = new Error(`Network error (could not reach ${label}). Check connectivity / proxy / firewall.`)
      ne.networkError = true
      throw ne
    }
    throw e
  } finally {
    clearTimeout(timer)
  }
}

// Promise watchdog: reject if `p` doesn't settle within `ms`. Used to bound the
// whole multi-call delegation-load path so the popup can NEVER hang on
// "Loading..." even if some future code path forgets a per-fetch timeout.
export function withWatchdog(p, ms, what) {
  let timer
  const guard = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new TimeoutError(`${what} did not complete within ${Math.round(ms / 1000)}s.`)), ms)
  })
  return Promise.race([p, guard]).finally(() => clearTimeout(timer))
}
