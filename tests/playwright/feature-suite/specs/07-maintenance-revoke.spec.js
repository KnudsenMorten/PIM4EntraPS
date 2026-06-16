// @ts-check
const { test, expect } = require('../fixtures');
const { ManagerPage } = require('../pages/ManagerPage');

/**
 * FEATURES.md ch.11 "revoke ... delegations" -- the Maintenance tab (active
 * assignments + revoke) and the workload delegation staging panel.
 *
 * The active-assignments list and revoke are LIVE-ONLY (need a real tenant), so
 * those bodies are tagged @live and skipped offline -- but the OFFLINE-safe shell
 * (toolbar, type chips, search, the disabled-by-default revoke button, the
 * workload staging panel) is asserted here, matching the PS "Live tests still get
 * an It but skip offline" rule.
 */
test.describe('Maintenance / Revoke [ch.11]', () => {
  /** @type {ManagerPage} */ let m;
  test.beforeEach(async ({ pim }) => { m = new ManagerPage(pim); await m.openTab('revoke'); });

  test('the Maintenance toolbar + active-assignment shell render', async () => {
    await expect(m.revBtnRefresh).toBeVisible();
    await expect(m.revResults).toBeAttached();
    await expect(m.revSearch).toBeVisible();
    // type filter chips.
    for (const t of ['all', 'entra-role', 'azure-rbac', 'pim-for-groups']) {
      await expect(m.page.locator(`.rev-type-chip[data-type="${t}"]`)).toBeVisible();
    }
  });

  test('the revoke button exists and is safe (disabled, in a hidden action bar until selection)', async () => {
    // The revoke control lives in #revActionBar which is display:none until a row
    // is selected -- so it is ATTACHED + DISABLED by default, never accidentally fireable.
    await expect(m.revBtnRevoke).toBeAttached();
    await expect(m.revBtnRevoke).toBeDisabled();
    await expect(m.page.locator('#revActionBar')).not.toHaveClass(/active/);
    await expect(m.revJustify).toBeAttached();
  });

  test('the workload delegation staging panel renders', async () => {
    await expect(m.wlPanel).toBeVisible();
    await expect(m.wlWorkload).toBeVisible();
  });

  // LIVE-ONLY: loading real active assignments needs a tenant.
  test('@live active assignments load from the tenant', async ({ api }) => {
    await m.revBtnRefresh.click();
    const r = await api.get('/api/active-assignments?refresh=1');
    expect(r.ok()).toBeTruthy();
    const d = await r.json();
    expect(Array.isArray(d) || Array.isArray(d.rows)).toBeTruthy();
  });
});
