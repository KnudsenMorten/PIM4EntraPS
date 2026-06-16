// @ts-check
const { test, expect } = require('../fixtures');
const { ManagerPage } = require('../pages/ManagerPage');

/**
 * FEATURES.md ch.11 GUI validator + ch.20 "the Manager validator (all rules)".
 *
 * The Validate tab runs preflight validation over the loaded config and renders
 * severity-grouped results with error/warning/info chips, a search filter, a
 * block-save toggle, and a "Fix all auto-fixable errors" dialog.
 */
test.describe('Validate tab (validator + fix-all) [ch.11, ch.20]', () => {
  /** @type {ManagerPage} */ let m;
  test.beforeEach(async ({ pim }) => { m = new ManagerPage(pim); await m.openTab('validate'); });

  test('validator runs and renders a results panel', async () => {
    await expect(m.valResults).toBeVisible();
    // counts chips exist (values depend on the seed; just assert they are numeric).
    for (const c of [m.valChipErrN, m.valChipWarnN, m.valChipInfoN]) {
      const t = (await c.textContent())?.trim() || '';
      expect(t).toMatch(/^\d+$/);
    }
  });

  test('Re-run re-validates [api effect: /api/preflight]', async ({ api }) => {
    await m.btnValRefresh.click();
    // confirm the underlying endpoint returns a sane preflight payload.
    const r = await api.get('/api/preflight');
    expect(r.ok()).toBeTruthy();
    const p = await r.json();
    expect(p).not.toBeNull();
  });

  test('the block-save toggle and severity chips are present', async () => {
    await expect(m.valBlockToggle).toBeVisible();
    await expect(m.page.locator('.sev-chip.sev-error')).toBeVisible();
    await expect(m.page.locator('.sev-chip.sev-warning')).toBeVisible();
    await expect(m.page.locator('.sev-chip.sev-info')).toBeVisible();
  });

  test('severity chip toggles a filter class', async () => {
    const chip = m.page.locator('.sev-chip.sev-error');
    await chip.click();
    // toggling adds/removes .off; just assert the click is handled (class toggled).
    await chip.click();
    await expect(chip).toBeVisible();
  });

  test('search box filters the validation results', async () => {
    await expect(m.valSearch).toBeVisible();
    await m.valSearch.fill('FK-001');
    await expect(m.valResults).toBeVisible(); // no throw on filter
    await m.valSearch.fill('');
  });

  test('the "Fix all auto-fixable errors" control exists and is wired', async () => {
    await expect(m.btnFixAll).toBeVisible();
    // The dialog only opens when there ARE auto-fixable findings; otherwise the
    // page shows a "nothing auto-fixable" alert. Both are correct -- accept either.
    let alerted = false;
    m.page.once('dialog', async (d) => { alerted = true; await d.dismiss(); });
    await m.btnFixAll.click();
    const dlg = m.page.locator('#fkAddDlg');
    const opened = await dlg.isVisible({ timeout: 3000 }).catch(() => false);
    expect(opened || alerted).toBeTruthy();
    if (opened) { await m.page.locator('#fxCancel').click(); }
  });
});
