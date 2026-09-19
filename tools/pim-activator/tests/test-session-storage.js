// PIM Activator -- offline tests for SEC-40 (sign-in tokens are SESSION-ONLY) and
// SEC-41 (the public "Report bug" text carries no customer identifiers).
//
// SEC-40: popup-storage.js must send every token key to chrome.storage.session
// and NEVER to chrome.storage.local, keep non-secret keys in local, and purge any
// token an earlier version left in local. Driven against a fake chrome.storage
// with the real callback API shape.
// SEC-41: popup-report.js must scrub GUIDs / UPNs / e-mails / tokens / tenant
// domains, and the report body must not carry a tenant id at all.
//
// No DOM, no real chrome.*, no network -- run under Node:
//   node tests/test-session-storage.js
// Exits non-zero on any failed assertion so the package test can gate.

import { makeStore, SESSION_ONLY_KEYS, isSessionOnlyKey, splitKeys } from '../popup-storage.js'
import { redactForPublicReport, buildPublicReportBody } from '../popup-report.js'

let passed = 0
let failed = 0
function ok(cond, name) {
  if (cond) { passed++; console.log('  PASS', name) }
  else { failed++; console.error('  FAIL', name) }
}

// A chrome.storage area with the callback API (get/set/remove), backed by a Map.
function fakeArea() {
  const data = new Map()
  return {
    data,
    get(keys, cb) {
      const out = {}
      const list = keys == null ? [...data.keys()] : (typeof keys === 'string' ? [keys] : keys)
      for (const k of list) if (data.has(k)) out[k] = data.get(k)
      setTimeout(() => cb(out), 0)
    },
    set(obj, cb) { for (const [k, v] of Object.entries(obj)) data.set(k, v); setTimeout(() => cb && cb(), 0) },
    remove(keys, cb) { for (const k of (typeof keys === 'string' ? [keys] : keys)) data.delete(k); setTimeout(() => cb && cb(), 0) },
  }
}

async function run() {
  console.log('SEC-40: key classification')
  for (const k of ['refreshToken', 'accessToken', 'accessTokenExpiry', 'armAccessToken', 'armAccessTokenExpiry', 'account', 'tenantTokens']) {
    ok(isSessionOnlyKey(k), `${k} is session-only`)
  }
  for (const k of ['tenantCatalog', 'activeTenantId', 'favorites', 'lastJustification', 'forceInteractive']) {
    ok(!isSessionOnlyKey(k), `${k} stays in local`)
  }
  const sp = splitKeys(['refreshToken', 'tenantCatalog', 'tenantTokens'])
  ok(sp.local.join() === 'tenantCatalog' && sp.session.join() === 'refreshToken,tenantTokens', 'splitKeys partitions a mixed key list')

  console.log('SEC-40: writes go to the right area')
  const local = fakeArea(), session = fakeArea()
  const store = makeStore({ storage: { local, session } })
  ok(store.sessionAvailable === true, 'storage.session detected')
  await store.set({
    refreshToken: 'RT', accessToken: 'AT', accessTokenExpiry: 1, account: { username: 'u' },
    tenantTokens: { t: { refreshToken: 'RT2' } }, activeTenantId: 'tid', favorites: ['x'],
  })
  for (const k of SESSION_ONLY_KEYS.filter(k => k !== 'armAccessToken' && k !== 'armAccessTokenExpiry')) {
    ok(session.data.has(k), `${k} written to storage.session`)
  }
  ok(SESSION_ONLY_KEYS.every(k => !local.data.has(k)), 'NO token key written to storage.local')
  ok(local.data.get('activeTenantId') === 'tid' && Array.isArray(local.data.get('favorites')), 'non-secret keys written to storage.local')

  console.log('SEC-40: reads merge both areas; a stale local token is never surfaced')
  local.data.set('refreshToken', 'STALE-LOCAL')          // as an old version would have left it
  const r = await store.get(['refreshToken', 'activeTenantId', 'tenantTokens'])
  ok(r.refreshToken === 'RT', 'refreshToken read from session, not the stale local copy')
  ok(r.activeTenantId === 'tid', 'activeTenantId read from local')
  ok(r.tenantTokens && r.tenantTokens.t.refreshToken === 'RT2', 'tenantTokens read from session')
  const all = await store.get(null)
  ok(all.refreshToken === 'RT', 'get(null) surfaces the session token, not the stale local one')

  console.log('SEC-40: migration purges tokens an earlier version left in local')
  local.data.set('accessToken', 'OLD-AT'); local.data.set('tenantTokens', { old: 1 }); local.data.set('account', { username: 'old' })
  const purged = await store.migrateTokensOutOfLocal()
  ok(purged.includes('refreshToken') && purged.includes('accessToken') && purged.includes('tenantTokens') && purged.includes('account'),
     'migrateTokensOutOfLocal reports what it removed')
  ok(SESSION_ONLY_KEYS.every(k => !local.data.has(k)), 'no token key remains in storage.local after migration')
  ok(local.data.get('activeTenantId') === 'tid' && local.data.has('favorites'), 'migration leaves preferences / catalog alone (user is not reset)')
  ok((await store.migrateTokensOutOfLocal()).length === 0, 'second run is a no-op')

  console.log('SEC-40: remove() clears both areas by key')
  await store.remove(['refreshToken', 'accessToken', 'activeTenantId'])
  ok(!session.data.has('refreshToken') && !session.data.has('accessToken') && !local.data.has('activeTenantId'), 'remove routes each key to its area')

  console.log('SEC-40: no storage.session -> memory only, NEVER local (fail closed)')
  const local2 = fakeArea()
  const store2 = makeStore({ storage: { local: local2 } })
  ok(store2.sessionAvailable === false, 'missing storage.session detected')
  await store2.set({ refreshToken: 'RT', favorites: ['a'] })
  ok(!local2.data.has('refreshToken'), 'token NOT written to local when session storage is missing')
  ok((await store2.get(['refreshToken'])).refreshToken === 'RT', 'token still usable for this popup (memory)')

  console.log('SEC-41: redaction of the public report')
  const tid = '3f2504e0-4f89-11d3-9a0c-0305e82c3301'
  const raw = `Graph 403 for tenant ${tid}: user admin@contoso.onmicrosoft.com lacks role; ` +
              `mail jane.doe@contoso.com; Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig; ` +
              `domain contoso.onmicrosoft.com; /subscriptions/${tid}/resourceGroups/rg-secret-prod/providers/Microsoft.Authorization/roleAssignments/x; ` +
              `Trace ID: 0a1b2c3d-1111-2222-3333-444455556666 Correlation ID: abc`
  const red = redactForPublicReport(raw)
  ok(!red.includes(tid), 'GUID (tenant id) removed')
  ok(!/contoso/i.test(red), 'tenant domain / UPN / e-mail removed')
  ok(!red.includes('eyJ'), 'JWT removed')
  ok(!red.includes('rg-secret-prod'), 'resource-group name removed')
  ok(red.includes('<id>') && red.includes('<upn>') && red.includes('<token>'), 'placeholders make the shape still readable')
  const body = buildPublicReportBody({ phase: 'graph', version: '1.6.127', error: raw })
  ok(!body.includes(tid) && !/tenant=/i.test(body), 'report body carries NO tenant id')
  ok(body.includes('phase=graph') && body.includes('v=1.6.127'), 'report body keeps phase + version')

  console.log('')
  console.log(`session-storage + report: ${passed} passed, ${failed} failed`)
  if (failed > 0) process.exit(1)
}

run().catch((e) => { console.error('test harness crashed:', e); process.exit(1) })
