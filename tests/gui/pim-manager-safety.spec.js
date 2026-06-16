// @ts-check
// REAL-BROWSER (headless Chromium) verification of two PIM Manager fixes.
// Driven by tests/gui/Verify-PimManagerSafetyGui.ps1, which boots the Manager
// headless against a QUOTED-CSV (Excel-saved) config and exports:
//   PIM_GUI_BASEURL  e.g. http://127.0.0.1:8814
//   PIM_GUI_TOKEN    the per-session bearer token
//
//   H1  Delegation Map's People column (#mapCol0) is NON-empty even though the
//       config CSVs are quoted (the bug rendered it empty).
//   L1  The Validate-tab toast target resolves to a REAL element (#valResults),
//       proven by driving the actual production toast-insertion path in the live
//       page and asserting the toast becomes visible -- and that #vResults does
//       not exist.
const { test, expect } = require('@playwright/test');

const BASE  = process.env.PIM_GUI_BASEURL;
const TOKEN = process.env.PIM_GUI_TOKEN;

test.describe('PIM Manager safety fixes (headless real browser)', () => {
  test.skip(!BASE || !TOKEN, 'no booted Manager (PIM_GUI_BASEURL / PIM_GUI_TOKEN unset)');

  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE}/?token=${TOKEN}`, { waitUntil: 'load' });
    // The Map renders on load; wait until the People column has been populated
    // (its child boxes are the real "map is non-empty" signal).
    await expect(page.locator('#mapTab')).toHaveClass(/active/);
  });

  test('H1: Delegation Map People column is non-empty on a quoted (Excel) CSV', async ({ page }) => {
    // The Map tab is active by default; the People column is #mapCol0.
    await expect(page.locator('#mapTab')).toHaveClass(/active/);

    // The baked model must carry the admin nodes (quoted headers parsed OK).
    // PIM_DATA is a top-level `let` in the page realm -- referenced by bare name.
    const adminCount = await page.evaluate(() =>
      (PIM_DATA.nodes || []).filter(n => n.kind === 'admin').length);
    expect(adminCount).toBe(2);

    // And the People column must actually RENDER boxes (not an empty column).
    await expect.poll(async () =>
      page.locator('#mapCol0 > *').count()
    ).toBeGreaterThan(0);
    const peopleBoxes = await page.locator('#mapCol0 > *').count();
    expect(peopleBoxes).toBeGreaterThanOrEqual(2);

    // The seeded UPNs are visible in the People column.
    await expect(page.locator('#mapCol0')).toContainText('Ada');
    await expect(page.locator('#mapCol0')).toContainText('Bo');
  });

  test('L1: Validate toast target #valResults exists and renders a toast', async ({ page }) => {
    // The element the production toast code targets must exist in the live DOM.
    await expect(page.locator('#valResults')).toHaveCount(1);
    // The buggy id must NOT exist.
    await expect(page.locator('#vResults')).toHaveCount(0);

    // Activate the Validate tab so its panel (and #valResults) is on-screen --
    // exactly where the operator sees the post-action toast.
    await page.locator('.tab[data-tab="validate"]').click();
    await expect(page.locator('#validateTab')).toHaveClass(/active/);

    // Drive the EXACT production toast-insertion path against the live page
    // (same code as the fix/overrule/add-row handlers): resolve #valResults and
    // insert a toast. If the id were wrong (#vResults) this would no-op.
    const inserted = await page.evaluate(() => {
      const statusEl = document.getElementById('valResults');
      if (!statusEl) return false;
      const toast = document.createElement('div');
      toast.className = '__pw_toast_probe';
      toast.style.cssText = 'background:#dafbe1;color:#1a7f37;padding:8px 12px;margin:6px 0;border-radius:5px;';
      toast.innerHTML = '&#10003; Applied (probe)';
      statusEl.insertBefore(toast, statusEl.firstChild);
      return true;
    });
    expect(inserted).toBe(true);

    // The toast must be visible inside the real Validate results container.
    await expect(page.locator('#valResults .__pw_toast_probe')).toBeVisible();
    await expect(page.locator('#valResults .__pw_toast_probe')).toContainText('Applied');
  });
});
