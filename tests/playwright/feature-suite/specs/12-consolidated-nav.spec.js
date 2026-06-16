// @ts-check
const { test, expect } = require('../fixtures');
const { ManagerPage } = require('../pages/ManagerPage');

/**
 * REQUIREMENTS §26d -- "Consolidate the Manager navigation into fewer,
 * CISO-friendly menus."
 *
 * The Manager's ~20 flat top-level tabs are folded into a small set of named
 * menu GROUPS (NAV_GROUPS in pim-manager.html, built by buildNavGroups()).
 * This is a pure information-architecture overlay: the flat #tabs strip stays
 * the source of truth (hidden) and every existing engine-backed view is
 * preserved -- nothing is removed.
 *
 * *** The menu-group NAMES are a PROPOSAL pending operator sign-off. ***
 *
 * Walks the consolidated nav HEADLESSLY (Playwright headless browser):
 *   - the grouped menubar is built + shown; the flat strip is hidden;
 *   - every flat view appears under exactly one group (no lost view, no dup);
 *   - opening a group + clicking an item activates that view's panel;
 *   - groups are collapsible (one open at a time) + keyboard-accessible.
 */
test.describe('Consolidated CISO-friendly navigation [§26d] (group names PROPOSED)', () => {
  /** @type {ManagerPage} */ let m;
  test.beforeEach(async ({ pim }) => { m = new ManagerPage(pim); });

  test('the grouped menubar builds and the flat strip is hidden', async () => {
    await expect(m.page.locator('body.js-nav-grouped')).toHaveCount(1);
    await expect(m.navGroups).toBeVisible();
    // the flat strip stays in the DOM (source of truth) but is visually hidden.
    await expect(m.tabs).toBeHidden();
    const groups = m.page.locator('#navGroups .nav-group');
    const n = await groups.count();
    expect(n).toBeGreaterThanOrEqual(4);
    expect(n).toBeLessThanOrEqual(7); // a SMALL, CISO-friendly set
    // nothing was dropped (a NAV_GROUPS typo would hide a real view).
    const dropped = await m.page.evaluate(() => window.PIM_NAV_DROPPED || ['(undefined)']);
    expect(dropped).toEqual([]);
  });

  test('every flat view is reachable from exactly one menu item', async () => {
    const { flat, menu } = await m.page.evaluate(() => ({
      flat: [...document.querySelectorAll('#tabs .tab[data-tab]')].map(t => t.dataset.tab),
      menu: [...document.querySelectorAll('#navGroups .nav-group-item[data-tab]')].map(i => i.dataset.tab),
    }));
    for (const v of flat) {
      const count = menu.filter(x => x === v).length;
      expect(count, `view "${v}" should be on exactly one menu item`).toBe(1);
    }
    // and no menu item points at a non-existent view.
    for (const v of menu) expect(flat, `menu item "${v}" must back a real view`).toContain(v);
  });

  // The proposed groups + the views nested under each. Update if operator renames.
  const PROPOSED = [
    ['overview',   ['home']],
    ['access',     ['new', 'map', 'roleperms', 'authoring', 'onboarding', 'grid']],
    ['change',     ['validate', 'save', 'cutover']],
    ['operations', ['revoke', 'approvals', 'jobs']],
    ['governance', ['governance', 'accessreview', 'conformance', 'reports']],
    ['audit',      ['audit', 'settings', 'support']],
  ];
  for (const [groupId, items] of PROPOSED) {
    for (const tabKey of items) {
      test(`group "${groupId}" -> "${tabKey}" opens its live panel`, async () => {
        await m.openViaNav(groupId, tabKey);
        await expect(m.panel(tabKey)).toBeVisible();
        await expect(m.panel(tabKey)).toHaveClass(/active/);
        // the owning group reflects the active selection.
        await expect(m.navGroup(groupId)).toHaveClass(/active/);
      });
    }
  }

  test('groups are collapsible -- only one dropdown open at a time', async () => {
    await m.navGroupBtn('access').click();
    await expect(m.navGroup('access')).toHaveClass(/open/);
    await m.navGroupBtn('governance').click();
    await expect(m.navGroup('governance')).toHaveClass(/open/);
    await expect(m.navGroup('access')).not.toHaveClass(/open/);
  });

  test('group buttons are keyboard-accessible (focusable button + aria-haspopup)', async () => {
    const btn = m.navGroupBtn('access');
    await expect(btn).toHaveAttribute('aria-haspopup', 'true');
    await btn.focus();
    await m.page.keyboard.press('ArrowDown'); // opens + focuses first item
    await expect(m.navGroup('access')).toHaveClass(/open/);
    await m.page.keyboard.press('Escape');
    await expect(m.navGroup('access')).not.toHaveClass(/open/);
  });
});
