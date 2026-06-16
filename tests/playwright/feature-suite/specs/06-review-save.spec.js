// @ts-check
const { test, expect } = require('../fixtures');
const { ManagerPage } = require('../pages/ManagerPage');

/**
 * FEATURES.md ch.11 GUI "Review & Save" flow + ch.5 "writes through a single
 * database-aware layer".
 *
 * An edit in the grid stages a pending change; the Review & Save tab shows a
 * per-entity diff (add/remove/modify) and Commit writes it back through the data
 * layer. This spec performs a REAL round-trip: edit -> review -> commit -> re-read
 * via the API and assert the change persisted to the SQL store.
 */
test.describe('Review & Save commit round-trip [ch.11, ch.5]', () => {
  /** @type {ManagerPage} */ let m;
  test.beforeEach(async ({ pim }) => { m = new ManagerPage(pim); });

  test('Review & Save tab renders the commit controls', async () => {
    await m.openTab('save');
    await expect(m.btnCommit).toBeAttached();
    await expect(m.btnRefresh).toBeAttached();
  });

  test('edit -> review diff -> commit persists to the store [full round-trip]', async ({ api }) => {
    // 1. read the seeded admin entity (its rows align with its display header, so a
    //    cell edit is a real, round-trippable change through the data layer).
    const ent = 'Account-Definitions-Admins';
    let r = await api.get(`/api/csv/${ent}`);
    expect(r.ok()).toBeTruthy();
    const before = await r.json();
    test.skip(!before.rows || before.rows.length === 0, 'no seeded admin rows to edit');
    const row0 = before.rows[0];
    // pick a header column populated in row0 (FirstName for the seed).
    const col = (before.header || []).find(h => row0[h] !== undefined && `${row0[h]}` !== '') || 'FirstName';

    // 2. edit that column's cell in the grid.
    await m.openGrid(ent);
    const stamp = 'PIMGUI-' + Date.now();
    await m.editFirstCell(stamp, col);
    await expect(m.gridDirtyBadge).toBeVisible();

    // 3. go to Review & Save; the dirty entity card + diff should render.
    await m.openTab('save');
    await expect(m.saveCards.locator(`#save-card-${ent}`)).toBeVisible();

    // 4. Commit all.
    await m.btnCommit.click();
    // a confirm modal may appear; accept it if shown.
    if (await m.modalOk.isVisible().catch(() => false)) { await m.modalOk.click(); }
    // the status pane ends in the "ok" class on success (its text is transient).
    await expect(m.saveStatus).toHaveClass(/ok/, { timeout: 20000 });
    // dirty badge clears after a successful commit.
    await expect(m.gridDirtyBadge).toBeHidden();

    // 5. re-read via the API and assert the stamp persisted in the SQL store (the real proof).
    await expect.poll(async () => {
      const rr = await api.get(`/api/csv/${ent}`);
      const after = await rr.json();
      return JSON.stringify(after.rows);
    }, { timeout: 15000 }).toContain(stamp);
  });
});
