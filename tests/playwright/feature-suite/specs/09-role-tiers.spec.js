// @ts-check
const { test, expect } = require('../fixtures');
const { ManagerPage } = require('../pages/ManagerPage');

/**
 * FEATURES.md ch.11 "Role tiers with the right powers" + ch.10 "Scoped portal
 * admins" -- Reader / Admin / SuperAdmin / Delegated.
 *
 * The booted role is determined by the harness (PIM_GUI_ROLE env -> a
 * manager-access.custom.json, or default SuperAdmin). This spec asserts the
 * role-dependent contract for WHATEVER role was booted:
 *   - SuperAdmin: bypass + emergency activation form + can update schema (write).
 *   - Reader/Delegated: fail-closed read-only -> the server rejects writes (403).
 *   - the role surfaced by the page matches /api/portal-access (server is the
 *     source of truth; the UI only reflects it).
 *
 * Run all four roles via the runner (Run-PimGuiTests.ps1 -AllRoles) which boots
 * the suite once per role.
 */
test.describe('Role tiers [ch.11, ch.10]', () => {
  /** @type {ManagerPage} */ let m;
  test.beforeEach(async ({ pim }) => { m = new ManagerPage(pim); });

  test('the UI role matches the server (portal-access is the source of truth)', async ({ api }) => {
    const uiRole = await m.role();
    const r = await api.get('/api/portal-access');
    expect(r.ok()).toBeTruthy();
    const pa = await r.json();
    expect(`${pa.managerRole}`).toBe(uiRole);
  });

  test('write-capability matches the role (SuperAdmin/Admin write; Reader/Delegated fail closed)', async ({ api, mgr }) => {
    // probe a harmless idempotent PUT (re-write the same rows back) and read the
    // server's authorization decision. Reader/Delegated => 403; Admin/SuperAdmin => 200.
    const base = 'PIM-Definitions-Departments';
    const cur = await (await api.get(`/api/csv/${base}`)).json();
    const put = await api.put(`/api/csv/${base}`, { data: { header: cur.header, rows: cur.rows } });
    const role = mgr.role;
    if (role === 'Reader' || role === 'Delegated') {
      expect(put.status(), 'read-only role must be denied writes').toBe(403);
    } else {
      expect(put.ok(), `${role} should be allowed to write`).toBeTruthy();
    }
  });

  test('emergency-override activation form is SuperAdmin-only', async ({ mgr }) => {
    await m.openTab('governance');
    if (mgr.role === 'SuperAdmin') {
      await expect(m.page.locator('#govEmActivate')).toBeVisible();
    } else {
      await expect(m.page.locator('#govEmActivate')).toHaveCount(0);
    }
  });

  // ch.10: a Delegated workload-owner sees the scoped view note.
  test('Delegated role shows the scoped workload-owner view note', async ({ mgr }) => {
    test.skip(mgr.role !== 'Delegated', 'only meaningful for the Delegated role');
    await m.openTab('governance');
    await expect(m.govBody).toContainText(/Delegated/i);
  });

  // ch.11: "fails closed to read-only if a role can't be determined" -- when an
  // access file lists an unknown identity the server returns Reader (covered by
  // the server-side unit tests; here we assert the live role is a known tier).
  test('the resolved role is a known tier', async ({ mgr }) => {
    expect(['Reader', 'Admin', 'SuperAdmin', 'Delegated']).toContain(mgr.role);
  });
});
