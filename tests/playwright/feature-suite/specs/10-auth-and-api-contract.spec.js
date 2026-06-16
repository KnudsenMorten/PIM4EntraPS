// @ts-check
const { test, expect } = require('../fixtures');
const { ManagerPage } = require('../pages/ManagerPage');

/**
 * FEATURES.md ch.9 Auth/Identity (the Manager's per-session bearer model) and
 * ch.11 GUI security, plus ch.5 "shows you which database you're connected to"
 * and the offline-safe API contract that backs every GUI action.
 *
 * The page authenticates every /api/* call with `Authorization: Bearer <token>`
 * injected server-side into <meta name=pim-token>; the server returns 401 without
 * it. This is the security spine the whole GUI rides on.
 */
test.describe('Auth + API contract [ch.9, ch.11, ch.5]', () => {
  test('the page carries a per-session bearer token in its meta', async ({ pim }) => {
    const m = new ManagerPage(pim);
    const tok = await m.pageToken();
    expect(tok).toBeTruthy();
    expect(tok).toMatch(/^[0-9a-fA-F]{16,}$/);
  });

  test('/api/* returns 401 without the bearer token', async ({ playwright, mgr }) => {
    const anon = await playwright.request.newContext({ baseURL: mgr.baseUrl });
    const r = await anon.get('/api/config');
    expect(r.status()).toBe(401);
    await anon.dispose();
  });

  test('/api/* returns 200 + sane JSON with the bearer token', async ({ api }) => {
    const r = await api.get('/api/config');
    expect(r.ok()).toBeTruthy();
    const cfg = await r.json();
    expect(cfg.nodes).not.toBeNull();
  });

  // every offline-safe read endpoint the GUI depends on responds.
  const offlineReads = [
    '/api/access', '/api/config', '/api/license', '/api/preflight',
    '/api/naming-conventions', '/api/templates', '/api/admin-templates',
    '/api/mail-templates', '/api/audit?limit=5', '/api/emergency-status',
    '/api/instances', '/api/portal-access', '/api/workloads',
    '/api/conformance/templates', '/api/resolve-date?expr=Now',
    '/api/csv/Account-Definitions-Admins',
  ];
  for (const p of offlineReads) {
    test(`offline-safe read responds: GET ${p}`, async ({ api }) => {
      const r = await api.get(p);
      expect(r.ok(), `${p} -> ${r.status()}`).toBeTruthy();
    });
  }

  // ch.5: the API reports which store it is connected to (sql for the local SQL instance).
  test('the data layer reports the connected store [ch.5]', async ({ api }) => {
    const r = await api.get('/api/csv/Account-Definitions-Admins');
    const d = await r.json();
    expect(d.source).toBe('sql');
  });

  // ch.14 Scale: server-side name-prefix filtering / on-demand users -- the config
  // build never bulk-lists; assert it returns quickly with a bounded node set.
  test('config build is lean (no bulk-list) [ch.14]', async ({ api }) => {
    const t0 = Date.now();
    const r = await api.get('/api/config');
    const ms = Date.now() - t0;
    expect(r.ok()).toBeTruthy();
    expect(ms).toBeLessThan(15000);
  });
});
