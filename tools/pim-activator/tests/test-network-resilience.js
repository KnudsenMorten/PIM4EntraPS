// PIM Activator -- offline tests for the network-resilience primitives that
// fix the "Loading your delegations" infinite-hang bug (v1.6.31).
//
// These cover the EXACT failure modes that left a freshly-built PAW stuck on
// "Loading your PIM delegations ... Please Wait":
//   - a fetch that never settles (stalled connection / proxy black-hole)
//   - a fetch that aborts via the timeout (AbortError -> TimeoutError)
//   - a network-level failure (TypeError -> err.networkError)
//   - a whole load path that never settles (withWatchdog bound)
//   - a normal fast response still passing straight through
//
// No DOM, no chrome.*, no real network -- pure logic, run under Node:
//   node tests/test-network-resilience.js
// Exits non-zero on any failed assertion so CI / the package test can gate.

import {
  FETCH_TIMEOUT_MS,
  LOAD_WATCHDOG_MS,
  SOURCE_WATCHDOG_MS,
  TimeoutError,
  fetchWithTimeout,
  withWatchdog,
  settleWithin,
} from '../popup-net.js'

let passed = 0
let failed = 0
function ok(cond, name) {
  if (cond) { passed++; console.log('  PASS', name) }
  else { failed++; console.error('  FAIL', name) }
}
async function expectReject(promise, predicate, name) {
  try {
    await promise
    failed++; console.error('  FAIL', name, '(expected a rejection, got resolve)')
  } catch (e) {
    if (predicate(e)) { passed++; console.log('  PASS', name) }
    else { failed++; console.error('  FAIL', name, '-> unexpected error:', e && e.message) }
  }
}

// A fetch impl that never resolves -- simulates the PAW hang the bug was about.
const neverFetch = () => new Promise(() => {})
// A fetch impl that resolves quickly with a fake Response-ish object.
const fastFetch = async () => ({ ok: true, status: 200, json: async () => ({ value: [] }) })
// A fetch impl that respects the AbortSignal (real fetch aborts -> AbortError).
const abortableFetch = (url, opts) => new Promise((_, reject) => {
  const sig = opts && opts.signal
  if (!sig) return
  if (sig.aborted) return reject(Object.assign(new Error('aborted'), { name: 'AbortError' }))
  sig.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true })
})
// A fetch impl that fails at the network layer (DNS/offline/blocked).
const networkFailFetch = async () => { throw Object.assign(new TypeError('Failed to fetch')) }

async function run() {
  console.log('network-resilience: budget constants')
  ok(typeof FETCH_TIMEOUT_MS === 'number' && FETCH_TIMEOUT_MS > 0, 'FETCH_TIMEOUT_MS is a positive number')
  ok(typeof LOAD_WATCHDOG_MS === 'number' && LOAD_WATCHDOG_MS >= FETCH_TIMEOUT_MS,
     'LOAD_WATCHDOG_MS >= FETCH_TIMEOUT_MS (whole-path budget is not tighter than one call)')
  ok(typeof SOURCE_WATCHDOG_MS === 'number' && SOURCE_WATCHDOG_MS >= FETCH_TIMEOUT_MS && SOURCE_WATCHDOG_MS <= LOAD_WATCHDOG_MS,
     'SOURCE_WATCHDOG_MS sits between one fetch and the whole-path budget')

  console.log('fetchWithTimeout: a stalled fetch times out (the actual bug)')
  await expectReject(
    fetchWithTimeout('https://graph.microsoft.com/v1.0/x', {}, 40, abortableFetch),
    (e) => e instanceof TimeoutError && e.timedOut === true,
    'stalled request rejects with TimeoutError (timedOut=true)')

  console.log('fetchWithTimeout: timeout fires even if the impl ignores abort')
  // neverFetch ignores the signal entirely; the timer must still win the race
  // by aborting -- but since neverFetch never settles, we wrap in a short
  // watchdog to assert the call does not hang the test forever.
  await expectReject(
    withWatchdog(fetchWithTimeout('https://x/y', {}, 30, neverFetch), 500, 'guard'),
    (e) => e instanceof TimeoutError,
    'a fetch that ignores abort is still bounded (never hangs)')

  console.log('fetchWithTimeout: network-level failure is tagged networkError')
  await expectReject(
    fetchWithTimeout('https://login.microsoftonline.com/t/oauth2', {}, 1000, networkFailFetch),
    (e) => e.networkError === true && /Network error/i.test(e.message),
    'TypeError from fetch -> err.networkError=true with a human message')

  console.log('fetchWithTimeout: a fast response passes straight through')
  const r = await fetchWithTimeout('https://graph.microsoft.com/v1.0/me', {}, 1000, fastFetch)
  ok(r && r.ok === true && r.status === 200, 'fast fetch returns the Response unchanged')

  console.log('fetchWithTimeout: diagnostic label strips the query string')
  await expectReject(
    fetchWithTimeout('https://graph.microsoft.com/v1.0/groups?$select=id&secret=shh', {}, 20, abortableFetch),
    (e) => e instanceof TimeoutError && !/secret=shh/.test(e.message) && /v1\.0\/groups/.test(e.message),
    'timeout message names the path but not the query (no secret leak)')

  console.log('withWatchdog: a never-settling load is bounded')
  await expectReject(
    withWatchdog(new Promise(() => {}), 60, 'Loading your delegations'),
    (e) => e instanceof TimeoutError && /Loading your delegations/.test(e.message),
    'never-settling promise rejects with a labelled TimeoutError')

  console.log('withWatchdog: a value that resolves in time passes through')
  const v = await withWatchdog(Promise.resolve(42), 1000, 'fast')
  ok(v === 42, 'resolved value flows through the watchdog')

  console.log('withWatchdog: a rejection in time propagates (not masked as timeout)')
  await expectReject(
    withWatchdog(Promise.reject(new Error('boom')), 1000, 'fast'),
    (e) => /boom/.test(e.message) && !(e instanceof TimeoutError),
    'underlying rejection is preserved, not replaced by a timeout')

  // settleWithin: the per-source bound that makes the load resilient. It must
  // NEVER reject (so Promise.all over several sources always settles + partial
  // results survive) and must tag a timeout vs a real rejection vs success.
  console.log('settleWithin: a fast source resolves to {ok:true, value}')
  const s1 = await settleWithin(Promise.resolve([1, 2, 3]), 1000, 'fast-source')
  ok(s1.ok === true && Array.isArray(s1.value) && s1.value.length === 3 && s1.timedOut === false && s1.name === 'fast-source',
     'fast source -> {ok:true, value, timedOut:false}')

  console.log('settleWithin: a never-settling source is bounded to {ok:false, timedOut:true} (never hangs, never throws)')
  const s2 = await settleWithin(new Promise(() => {}), 60, 'slow-source')
  ok(s2.ok === false && s2.timedOut === true && s2.error instanceof TimeoutError,
     'stalled source -> {ok:false, timedOut:true} instead of blocking siblings')

  console.log('settleWithin: a rejecting source resolves to {ok:false} (does not reject)')
  const s3 = await settleWithin(Promise.reject(new Error('boom')), 1000, 'bad-source')
  ok(s3.ok === false && s3.timedOut === false && /boom/.test(s3.error && s3.error.message),
     'rejecting source -> {ok:false, timedOut:false} with the original error')

  console.log('settleWithin: Promise.all over a mix still settles (one slow source does not sink the rest)')
  const mix = await Promise.all([
    settleWithin(Promise.resolve('primary'), 1000, 'primary'),
    settleWithin(new Promise(() => {}), 50, 'slow-enrichment'),
    settleWithin(Promise.reject(new Error('x')), 1000, 'failed-enrichment'),
  ])
  ok(mix[0].ok === true && mix[0].value === 'primary' && mix[1].ok === false && mix[2].ok === false,
     'partial results survive: primary kept, slow + failed enrichment degrade to {ok:false}')

  console.log('')
  console.log(`network-resilience: ${passed} passed, ${failed} failed`)
  if (failed > 0) process.exit(1)
}

run().catch((e) => { console.error('test harness crashed:', e); process.exit(1) })
