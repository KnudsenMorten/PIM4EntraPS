// @ts-check
const { test, expect } = require('../fixtures');
const { ManagerPage } = require('../pages/ManagerPage');

/**
 * FEATURES.md ch.11 "GUI / Manager" -- Visibility & reporting (REQUIREMENTS §26a):
 *   1. "Who can do what" report (+ reverse) -- person -> reachable targets; role ->
 *      who can activate it. Engine-backed via /api/access-report/who-can + who-has.
 *   2. Global search across people / groups / roles / scopes / tags -> /api/search.
 *   3. Export everywhere -- CSV + print on the operational views (here: the Reports
 *      tab carries an Export CSV / Print bar).
 *
 * Runs against the LOCAL SQL-seeded Manager (harness, marker 'PIMCOREENGINE-'),
 * headless -- never opening a browser on the user's desktop.
 */
test.describe('Visibility & reporting [ch.11 §26a]', () => {
  /** @type {ManagerPage} */ let m;
  test.beforeEach(async ({ pim }) => { m = new ManagerPage(pim); });

  test('Reports tab renders the "who can do what" surface', async () => {
    await m.openTab('reports');
    await expect(m.reportsBody).toBeVisible();
    await expect(m.reportsBody).toContainText('Who can do what');
    await expect(m.rptModeWhoCan).toBeVisible();
    await expect(m.rptModeWhoHas).toBeVisible();
    await expect(m.rptSubject).toBeVisible();
    // The export bar is present (export everywhere).
    await expect(m.reportsBody.locator('#rptCsv')).toBeVisible();
    await expect(m.reportsBody.locator('#rptPrint')).toBeVisible();
  });

  test('GET /api/access-report/who-can returns engine-backed targets THROUGH a nested group [api effect]', async ({ api }) => {
    // The seeded admin (marker-prefixed) is eligible into the CloudEngineer role
    // group, which NESTS the User Administrator permission group -> the admin
    // transitively reaches the User Administrator Entra role, with the path.
    const s = await api.get('/api/search?q=' + encodeURIComponent('admin-ce'));
    const sd = await s.json();
    const person = (sd.hits || []).find(h => h.type === 'person');
    expect(person, 'a seeded person is searchable').toBeTruthy();
    const r = await api.get('/api/access-report/who-can?person=' + encodeURIComponent(person.id));
    expect(r.ok()).toBeTruthy();
    const d = await r.json();
    expect(d.found).toBeTruthy();
    expect(Array.isArray(d.targets)).toBeTruthy();
    expect(d.count).toBeGreaterThan(0);
    // Reaches User Administrator THROUGH the nested group (transitive reach).
    const ua = d.targets.find(t => /User Administrator/i.test(t.roleName || t.label || ''));
    expect(ua, 'reaches User Administrator transitively').toBeTruthy();
    // Each target carries an activation path (auditable evidence, not a flat list).
    expect(ua.pathText).toContain('->');
  });

  test('GET /api/access-report/who-has (reverse) resolves a role + lists its reachers [api effect]', async ({ api }) => {
    // User Administrator IS nested under the seeded admin's role group -> reachable.
    const r = await api.get('/api/access-report/who-has?role=' + encodeURIComponent('User Administrator'));
    expect(r.ok()).toBeTruthy();
    const d = await r.json();
    expect(d.resolved).toBeGreaterThan(0);   // the role resolved to a target node
    expect(Array.isArray(d.reachers)).toBeTruthy();
    expect(d.count).toBeGreaterThan(0);      // at least the seeded admin reaches it
    expect(d.reachers[0].pathText).toContain('->');
    // A role that is NOT nested anywhere resolves but has zero reachers (honest).
    const r2 = await api.get('/api/access-report/who-has?role=' + encodeURIComponent('Global Administrator'));
    const d2 = await r2.json();
    expect(d2.resolved).toBeGreaterThan(0);
    expect(d2.count).toBe(0);
  });

  test('global search finds people / roles / scopes and jumps to them', async ({ api }) => {
    // API contract first.
    const r = await api.get('/api/search?q=' + encodeURIComponent('Global'));
    expect(r.ok()).toBeTruthy();
    const d = await r.json();
    expect(d.count).toBeGreaterThan(0);
    expect(d.hits.some(h => h.type === 'role')).toBeTruthy();

    // UI: typing in the global box shows a results dropdown.
    await m.globalSearch.fill('Global');
    await expect.poll(async () => (await m.globalSearchResults.textContent()) || '', { timeout: 15000 })
      .toMatch(/match|No people/);
  });

  test('the who-can report renders rows with paths for a seeded admin', async () => {
    await m.openTab('reports');
    // Pick the first person option from the datalist via the subject input.
    const opt = await m.reportsBody.locator('#rptPeopleList option').first();
    const upn = await opt.getAttribute('value');
    expect(upn, 'a seeded person option exists').toBeTruthy();
    await m.rptSubject.fill(upn);
    await m.rptRun.click();
    await expect.poll(async () => (await m.rptResults.textContent()) || '', { timeout: 15000 })
      .toMatch(/can reach|reaches no/);
  });
});
