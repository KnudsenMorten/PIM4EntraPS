// @ts-check
const { test, expect } = require('../fixtures');
const { ManagerPage } = require('../pages/ManagerPage');

/**
 * FEATURES.md ch.11 "GUI / Manager" -- the Home / Overview landing tab
 * (REQUIREMENTS §26a/§26b): a one-screen, engine-backed summary of the whole
 * privileged estate -- per-tier L0-L5 counts, gaps/orphans/unmanaged, engine &
 * jobs health (red-green, incl. drift), open validation findings, break-glass,
 * pending approvals -- plus a "what needs my attention" call-out and a tier/plane
 * legend.
 *
 * Every tile is engine-backed via GET /api/home (fast) + /api/home?include=heavy
 * (live). These run against the LOCAL SQL-seeded Manager (harness), headless --
 * never opening a browser on the user's desktop.
 */
test.describe('Home / Overview tab [ch.11 §26a/§26b]', () => {
  /** @type {ManagerPage} */ let m;
  test.beforeEach(async ({ pim }) => { m = new ManagerPage(pim); });

  test('Home is the landing tab and renders engine-backed tiles', async () => {
    // Home is the default-active tab; its body renders past the "Loading" state.
    await expect(m.tab('home')).toHaveClass(/active/);
    await expect(m.homeBody).toBeVisible();
    await expect(m.homeBody).toContainText('what needs your attention');
    // Tiles are real DOM (not the loading placeholder); at least the fast tiles.
    await expect.poll(async () => await m.homeTiles.count(), { timeout: 15000 })
      .toBeGreaterThan(3);
  });

  test('the estate-health tiles are present (tiers, gaps, validation, engine/jobs)', async () => {
    await m.openTab('home');
    await expect.poll(async () => await m.homeTiles.count(), { timeout: 15000 })
      .toBeGreaterThan(3);
    const body = m.homeBody;
    // Per-tier L0-L5 + gaps/orphans/unmanaged + engine/jobs + validation.
    await expect(body).toContainText(/L0–L5|by tier/i);
    await expect(body).toContainText(/Gaps, orphans/i);
    await expect(body).toContainText(/Validation/i);
    await expect(body).toContainText(/jobs|Engine/i);
    await expect(body).toContainText(/Break-glass/i);
  });

  test('the "what needs my attention" call-out renders (items or honest all-clear)', async () => {
    await m.openTab('home');
    await expect(m.homeAttnCallout).toBeVisible();
    // Either a prioritized list ("What needs your attention (N)") or the all-clear.
    await expect.poll(async () => (await m.homeAttnCallout.textContent()) || '', { timeout: 15000 })
      .toMatch(/What needs your attention|All clear/);
  });

  test('the tier/plane legend is available and documents L0-L5 + CP/MP/WDP', async () => {
    await m.openTab('home');
    const legend = m.homeBody.locator('details', { hasText: 'Tier & plane legend' });
    await expect(legend).toHaveCount(1);
    await legend.locator('summary').click();   // expand
    await expect(legend).toContainText('L0');
    await expect(legend).toContainText('CP');
    await expect(legend).toContainText('WDP');
  });

  test('GET /api/home returns engine-backed tiles incl. red-green job health [api effect]', async ({ api }) => {
    const r = await api.get('/api/home');
    expect(r.ok()).toBeTruthy();
    const d = await r.json();
    expect(d.tiles).toBeTruthy();
    // Engine & jobs health is present with a red/green/unknown status (§26b).
    expect(d.tiles.jobs).toBeTruthy();
    expect(['red', 'green', 'unknown', undefined]).toContain(d.tiles.jobs.status);
    // Per-tier estate model + gaps are engine-backed (from the seeded SQL store).
    expect(d.tiles.tiers).toBeTruthy();
    expect(d.tiles.tiers.byLevel).toBeTruthy();
    expect(d.tiles.gaps).toBeTruthy();
    // Validation tile present.
    expect(d.tiles.validation).toBeTruthy();
  });

  test('the heavy/live tiles lazy-load via include=heavy [api effect]', async ({ api }) => {
    const r = await api.get('/api/home?include=heavy');
    expect(r.ok()).toBeTruthy();
    const d = await r.json();
    expect(d.includeHeavy).toBeTruthy();
    // expiring-access + access-reviews tiles resolve (not deferred) on the heavy load.
    expect(d.tiles.expiring).toBeTruthy();
    expect(d.tiles.accessReviews).toBeTruthy();
  });

  test('every Home tile/call-out link points at a real tab', async () => {
    await m.openTab('home');
    await expect.poll(async () => await m.homeTiles.count(), { timeout: 15000 })
      .toBeGreaterThan(3);
    const known = new Set(['home', 'new', 'map', 'validate', 'save', 'revoke',
      'accessreview', 'grid', 'authoring', 'onboarding', 'roleperms', 'approvals',
      'governance', 'conformance', 'cutover', 'jobs', 'audit', 'settings', 'support']);
    const tabs = await m.homeBody.locator('[data-tab]').evaluateAll(
      els => els.map(e => e.getAttribute('data-tab')));
    expect(tabs.length).toBeGreaterThan(0);
    for (const tabName of tabs) {
      expect(known.has(tabName), `tile links to a real tab: ${tabName}`).toBeTruthy();
    }
  });
});
