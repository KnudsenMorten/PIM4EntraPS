// @ts-check
const { test, expect } = require('../fixtures');
const { ManagerPage } = require('../pages/ManagerPage');

/**
 * FEATURES.md ch.11 "browser grid" -- "bulk-edit" + inline edit + clone, and
 * ch.5 "reads and writes through a single database-aware layer".
 *
 * The Advanced View grid lists the CSV/entity bases in a rail; opening one shows
 * an editable table with inline contenteditable / dropdown cells, per-row clone
 * & delete, a tri-state select-all + a bulk action bar, and a Commit that writes
 * back through the data layer (PUT /api/csv/<base> -> SQL pim.Rows here).
 */
test.describe('Advanced View grid (inline + bulk edit) [ch.11, ch.5]', () => {
  /** @type {ManagerPage} */ let m;
  test.beforeEach(async ({ pim }) => { m = new ManagerPage(pim); await m.openTab('grid'); });

  test('the file/entity rail lists CSV bases', async () => {
    await expect(m.gridList).toBeVisible();
    await expect(m.gridList.locator('.item')).not.toHaveCount(0);
  });

  test('opening a seeded entity shows the editable grid table', async () => {
    await m.openGrid('Account-Definitions-Admins');
    await expect(m.gridTable).toBeVisible();
    // the seed put exactly one admin row -> at least one data row.
    await expect(m.gridTable.locator('tr[data-idx]')).not.toHaveCount(0);
    // toolbar add/reload present.
    await expect(m.btnAddRow).toBeVisible();
    await expect(m.btnReloadGrid).toBeVisible();
  });

  test('inline edit marks a row modified and dirties the Save badge', async () => {
    await m.openGrid('Account-Definitions-Admins');
    await m.editFirstCell('PIMGUI-edited');
    await expect(m.page.locator('tr.row-modified')).not.toHaveCount(0);
    await expect(m.gridDirtyBadge).toBeVisible();
    // do NOT commit -> teardown drops the DB; cancel via Reload to clean state.
    await m.btnReloadGrid.click();
  });

  test('add-row appends an editable row marked added', async () => {
    await m.openGrid('PIM-Definitions-Departments');
    const before = await m.gridTable.locator('tr[data-idx]').count();
    await m.btnAddRow.click();
    await expect(m.gridTable.locator('tr[data-idx]')).toHaveCount(before + 1);
    await expect(m.page.locator('tr.row-added')).not.toHaveCount(0);
    await m.btnReloadGrid.click();
  });

  test('bulk select activates the action bar and clear deselects', async () => {
    await m.openGrid('PIM-Definitions-Roles');
    // select-all checkbox.
    await expect(m.gridSelectAll).toBeVisible();
    await m.gridSelectAll.check();
    await expect(m.gridActionBar).toHaveClass(/active/);
    await expect(m.gabDelete).toBeVisible();
    await m.gabClear.click();
    await expect(m.gridActionBar).not.toHaveClass(/active/);
  });

  // ch.5 data layer: the grid reads through the single DB-aware /api/csv path and
  // reports source 'sql' for the SQL-backed local instance.
  test('grid data reads through the SQL data layer [api effect]', async ({ api }) => {
    const r = await api.get('/api/csv/Account-Definitions-Admins');
    expect(r.ok()).toBeTruthy();
    const d = await r.json();
    expect(d.base).toBe('Account-Definitions-Admins');
    expect(d.source).toBe('sql');
    expect(Array.isArray(d.rows)).toBeTruthy();
    expect(d.rows.length).toBeGreaterThan(0);
  });

  /**
   * NOTE on CSV export: the current GUI has NO CSV download/export control
   * (verified against the markup). Persistence is server-side via Commit
   * (PUT /api/csv/<base> writes <base>.custom.csv / SQL pim.Rows), not a browser
   * download. This test documents that contract so the coverage matrix is honest.
   */
  test('the grid itself has no client-side CSV export button (persistence is server-side commit)', async () => {
    // Note: read-only OPERATIONAL views (Reports / Audit / Access Review / Validate /
    // Delegation Map) DO offer Export CSV / Print (REQUIREMENTS §26a "export
    // everywhere"). That is reporting, not the grid's edit/commit data path -- so
    // this contract is scoped to the GRID panel, which still commits server-side.
    await m.openGrid('Account-Definitions-Admins');
    await expect(m.page.locator('#gridTab').locator('text=Export CSV')).toHaveCount(0);
    await expect(m.page.locator('#gridTab a[download]')).toHaveCount(0);
  });
});
