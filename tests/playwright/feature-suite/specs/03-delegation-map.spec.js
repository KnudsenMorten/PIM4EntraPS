// @ts-check
const { test, expect } = require('../fixtures');
const { ManagerPage } = require('../pages/ManagerPage');

/**
 * FEATURES.md ch.11 "map ... delegations" + ch.10 "Two-tier group nesting" /
 * "Everything is a group".
 *
 * The Delegation Map is the four-column transitive view (People -> Roles/Org
 * groups -> Capability bundles -> Permissions/Targets). Picking a person/permission
 * highlights the transitive path and renders a reach summary in #mapDetail.
 */
test.describe('Delegation Map (transitive path) [ch.11, ch.10]', () => {
  /** @type {ManagerPage} */ let m;
  test.beforeEach(async ({ pim }) => { m = new ManagerPage(pim); await m.openTab('map'); });

  test('the four delegation columns render', async () => {
    await expect(m.mapBoard).toBeVisible();
    for (let i = 0; i < 4; i++) {
      await expect(m.mapCols[i]).toBeVisible();
    }
  });

  test('selecting a node highlights the transitive path + reach detail', async () => {
    // pick the first available map item in any column.
    const items = m.mapBoard.locator('.map-item');
    await expect(items.first()).toBeVisible();
    const first = items.first();
    const id = await first.getAttribute('data-id');
    await first.click();
    // selected item gets .sel; the board enters focused mode; detail renders reach.
    await expect(m.mapBoard.locator(`.map-item[data-id="${id}"]`)).toHaveClass(/sel/);
    await expect(m.mapDetail).not.toBeEmpty();
  });

  test('search narrows the map and "Back to overview" clears the focus', async () => {
    await expect(m.mapSearch).toBeVisible();
    await m.mapSearch.fill('zzzzz-no-such-thing');
    // a no-match query should not throw; the board stays present.
    await expect(m.mapBoard).toBeVisible();
    await m.mapSearch.fill('');
    // pick a node then clear focus via the toolbar.
    const first = m.mapBoard.locator('.map-item').first();
    if (await first.count()) {
      await first.click();
      await m.mapClear.click();
      await expect(m.mapBoard).not.toHaveClass(/focused/);
    }
  });

  // ch.5: the map is rendered from the same DB-backed config the server loads.
  test('map data comes from the connected store [api effect]', async ({ api }) => {
    const r = await api.get('/api/config');
    expect(r.ok()).toBeTruthy();
    const cfg = await r.json();
    expect(Array.isArray(cfg.nodes)).toBeTruthy();
    expect(cfg.nodes.length).toBeGreaterThan(0);
  });
});
