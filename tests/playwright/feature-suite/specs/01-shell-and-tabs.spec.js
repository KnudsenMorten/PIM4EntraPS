// @ts-check
const { test, expect } = require('../fixtures');
const { ManagerPage } = require('../pages/ManagerPage');

/**
 * FEATURES.md ch.11 "GUI / Manager" -- browser-based delegation editor, the tab
 * shell, and the SQL/storage-mode banner (ch.5 "One consistent data path ... shows
 * you which database you're connected to").
 *
 * Covers: every top-level tab navigates + renders; the storage-mode banner is
 * read-write (server), not static; version + source shown.
 */
test.describe('GUI shell, tabs & storage-mode banner [ch.11, ch.5]', () => {
  /** @type {ManagerPage} */ let m;
  test.beforeEach(async ({ pim }) => { m = new ManagerPage(pim); });

  test('the SPA boots with a navigation surface and a default active tab', async () => {
    // The Manager consolidated the flat tab strip into CISO-friendly menu groups
    // (§26d): when the grouped nav is active the flat #tabs strip stays in the DOM
    // (canonical switchTab/badge surface) but is hidden, and #navGroups is shown.
    // Assert whichever nav surface the build chose is visible.
    const grouped = await m.page.locator('body.js-nav-grouped').count();
    if (grouped) await expect(m.navGroups).toBeVisible();
    else await expect(m.tabs).toBeVisible();
    // The flat strip is always the source of truth for the active tab (hidden or not).
    await expect(m.page.locator('#tabs .tab.active')).toHaveCount(1);
    // Home is the default-active LANDING tab in the markup.
    await expect(m.tab('home')).toHaveClass(/active/);
  });

  // ch.11: "Create, map, delete, bulk-edit, revoke and clone delegations through a browser grid"
  // Every top-level tab currently shipped in pim-manager.html (data-tab -> "<name>Tab"
  // panel id). Keep in sync with the markup: the Manager has gained Home (landing),
  // Access Review, Authoring, Onboarding, Role Lookup, Approvals, Cutover, Jobs, Audit,
  // Settings and Support since this suite's first cut.
  const tabs = [
    ['home', 'homeTab'],
    ['new', 'newTab'],
    ['map', 'mapTab'],
    ['validate', 'validateTab'],
    ['save', 'saveTab'],
    ['revoke', 'revokeTab'],
    ['accessreview', 'accessreviewTab'],
    ['grid', 'gridTab'],
    ['authoring', 'authoringTab'],
    ['onboarding', 'onboardingTab'],
    ['roleperms', 'rolepermsTab'],
    ['approvals', 'approvalsTab'],
    ['governance', 'governanceTab'],
    ['conformance', 'conformanceTab'],
    ['cutover', 'cutoverTab'],
    ['jobs', 'jobsTab'],
    ['audit', 'auditTab'],
    ['settings', 'settingsTab'],
    ['support', 'supportTab'],
  ];
  for (const [name, panelId] of tabs) {
    test(`tab "${name}" navigates and shows panel #${panelId}`, async () => {
      await m.openTab(name);
      await expect(m.tab(name)).toHaveClass(/active/);
      await expect(m.page.locator(`#${panelId}`)).toBeVisible();
    });
  }

  // ch.5: storage-mode banner is read-write (not static) and names the live store.
  // Regression guard for the SQL-mode read-only bug: when the Manager is SQL-backed
  // the banner shows "SQL: <db>" yet the GUI MUST stay read-write (isServer true).
  test('storage-mode banner shows read-write mode and names the store, not static', async () => {
    await expect(m.modeLabel).toBeVisible();
    // never the static label; never the static (amber) class.
    await expect(m.modeLabel).not.toHaveText('static (read-only)');
    await expect(m.modeLabel).not.toHaveClass(/modeStatic/);
    expect(await m.isServerMode()).toBeTruthy();
    // The read-write GATE the SPA reads is `pim-mode !== 'static'` (isServer). The
    // server renders pim-mode as the storage LABEL itself: 'server' (CSV-backed) or
    // 'SQL: <db>' (SQL-backed) -- both are read-write; only the static HTML export
    // emits 'static'. Assert the gate is a serving label, never 'static'.
    const gate = await m.page.evaluate(() => document.querySelector('meta[name=pim-mode]').content);
    expect(gate).not.toBe('static');
    expect(gate).toMatch(/^(server|SQL: )/);
    // the banner label names the store (e.g. 'SQL: <db>' for the local SQL instance, or 'server').
    const label = (await m.modeLabel.textContent())?.trim() || '';
    expect(label.length).toBeGreaterThan(0);
    expect(label).not.toBe('static (read-only)');
    // source label is populated (sourceRoot of the data).
    await expect(m.srcLabel).not.toBeEmpty();
  });

  // ch.21 Docs / branding: the version badge is rendered.
  test('version badge is present', async () => {
    await expect(m.versionBadge).toBeVisible();
  });
});
