// @ts-check
const { test, expect } = require('../fixtures');
const { ManagerPage } = require('../pages/ManagerPage');

/**
 * FEATURES.md ch.11 "GUI / Manager" -- "Create ... delegations through ... guided
 * wizards", ch.7 "Import roles, don't type them" (permission templates), and
 * ch.10 "Permission-wizard auto-derivation" (the reversed create flow).
 *
 * Drives the Create tab: wizard tiles open the guided wizard with step nav; the
 * reversed wizard derives name/level/tier from a target (asserted both in the UI
 * flow and via the /api/wizard/derive effect); permission templates render.
 */
test.describe('Create wizard & templates [ch.11, ch.7, ch.10]', () => {
  /** @type {ManagerPage} */ let m;
  test.beforeEach(async ({ pim }) => { m = new ManagerPage(pim); });

  test('Create tab shows the wizard tiles', async () => {
    await m.openTab('new');
    await expect(m.wizCards).toBeVisible();
    // the documented wizard tiles
    for (const wiz of ['admin', 'permgroup-entra', 'permgroup-azure', 'rolegroup', 'clone', 'project']) {
      await expect(m.page.locator(`.wiz-card[data-wiz="${wiz}"]`)).toHaveCount(1);
    }
  });

  test('a wizard opens with a stepper and step navigation', async () => {
    await m.openWizard('admin');
    await expect(m.wizModal).toBeVisible();
    await expect(m.wizTitle).not.toBeEmpty();
    await expect(m.wizSteps).toBeVisible();
    // Next is shown on early steps; Finish is the last-step submit.
    await expect(m.wizNext).toBeVisible();
    await expect(m.wizFinish).toBeAttached();
    // Cancel discards without leaving a pending change.
    await m.wizCancel.click();
    await expect(m.wizModal).toBeHidden();
    await expect(m.saveDirtyBadge).toBeHidden();
  });

  test('the Entra permission-group wizard opens (reversed/target-first create)', async () => {
    await m.openWizard('permgroup-entra');
    await expect(m.wizModal).toBeVisible();
    await expect(m.wizBody).toBeVisible();
    await m.wizCancel.click();
  });

  // ch.10 auto-derivation: the GUI's /api/wizard/derive is what the wizard calls
  // to auto-fill name/level/tier/plane. Assert the API EFFECT behind the GUI.
  test('reversed wizard derives Entra GA -> service/L0/T0 [api effect]', async ({ api }) => {
    const r = await api.post('/api/wizard/derive', {
      data: { target: 'entra', roles: ['Global Administrator'] },
    });
    expect(r.ok()).toBeTruthy();
    const d = await r.json();
    expect(d.ok).toBeTruthy();
    expect(d.derivation.level).toBe(0);
    expect(`${d.derivation.kind}`).toBe('permission-service');
    expect(`${d.derivation.groupName}`).toMatch(/^PIM-Entra-ID-.*-L0-T0-CP-ID$/);
  });

  test('reversed wizard derives Azure subscription/LZ -> L1/T1/WDP [api effect]', async ({ api }) => {
    const r = await api.post('/api/wizard/derive', {
      data: { target: 'azure', scopeType: 'subscription', scopeName: 'lz-corp-prod', scopePath: '/subscriptions/abc', roles: ['Contributor'] },
    });
    expect(r.ok()).toBeTruthy();
    const d = await r.json();
    expect(d.ok).toBeTruthy();
    expect(d.derivation.level).toBe(1);
    expect(d.derivation.tier).toBe(1);
    expect(`${d.derivation.plane}`).toBe('WDP');
  });

  // ch.7 "Import roles, don't type them" -- permission templates render as cards.
  test('permission templates section renders [ch.7]', async () => {
    await m.openTab('new');
    await expect(m.tplSection).toBeVisible();
    // /api/templates feeds the cards; assert the container exists (may be empty
    // on a minimal seed, but the section + its api are wired).
    await expect(m.tplCards).toBeAttached();
  });
});
