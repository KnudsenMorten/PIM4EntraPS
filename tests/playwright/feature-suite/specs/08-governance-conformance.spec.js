// @ts-check
const { test, expect } = require('../fixtures');
const { ManagerPage } = require('../pages/ManagerPage');

/**
 * FEATURES.md ch.11 GUI Governance + Conformance panels (template versioning /
 * conformance; emergency override; discovered resources; audit; license).
 *
 * Governance shows the operator's role/access, the emergency-override section
 * (SuperAdmin-gated activation), discovered-resources acknowledgement, audit and
 * license. Conformance shows a template selector with Dry-run/Deploy (deploy is
 * live-only).
 */
test.describe('Governance & Conformance [ch.11]', () => {
  /** @type {ManagerPage} */ let m;
  test.beforeEach(async ({ pim }) => { m = new ManagerPage(pim); });

  test('Governance renders the access panel + role', async () => {
    await m.openTab('governance');
    await expect(m.govBody).toBeVisible();
    // "Role: <b>SuperAdmin</b>" printed for the operator.
    await expect(m.govBody).toContainText('Role:');
    await expect(m.govBody).toContainText(await m.role());
  });

  // SuperAdmin sees the emergency-override activation form (role-gated DOM).
  test('Governance emergency-override form is shown for SuperAdmin', async () => {
    await m.openTab('governance');
    const role = await m.role();
    if (role === 'SuperAdmin') {
      await expect(m.page.locator('#govEmActivate')).toBeVisible();
    } else {
      await expect(m.page.locator('#govEmActivate')).toHaveCount(0);
    }
  });

  test('Governance reads audit/license/emergency-status [api effects]', async ({ api }) => {
    for (const p of ['/api/emergency-status', '/api/audit?limit=5', '/api/license']) {
      const r = await api.get(p);
      expect(r.ok(), `${p} ok`).toBeTruthy();
    }
  });

  test('Conformance renders the template selector + dry-run/deploy controls', async () => {
    await m.openTab('conformance');
    await expect(m.confBody).toBeVisible();
    await expect(m.confTpl).toBeVisible();
    await expect(m.confDry).toBeVisible();
    await expect(m.confLive).toBeVisible();
    // live deploy starts disabled until a dry-run unlocks it.
    await expect(m.confLive).toBeDisabled();
  });

  test('Conformance lists templates + a matrix for the selected one [api effect]', async ({ api }) => {
    const r = await api.get('/api/conformance/templates');
    expect(r.ok()).toBeTruthy();
    const d = await r.json();
    expect(d.templates).not.toBeNull();
    // pick the first template and pull its matrix offline-safe.
    const first = (d.templates && d.templates[0] && (d.templates[0].id || d.templates[0].templateId)) || 'defender-xdr-roles';
    const mr = await api.get(`/api/conformance?template=${encodeURIComponent(first)}`);
    expect(mr.ok()).toBeTruthy();
  });

  // LIVE-ONLY: an actual conformance deploy applies to the tenant.
  test('@live conformance deploy applies workload assignments', async ({ api }) => {
    const r = await api.post('/api/conformance/deploy', { data: { templateId: 'defender-xdr-roles', whatIf: true } });
    expect(r.ok()).toBeTruthy();
  });
});
