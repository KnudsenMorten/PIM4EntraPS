// @ts-check
/**
 * Page object for the PIM Manager SPA (tools/pim-manager/pim-manager.html).
 * Selectors are taken verbatim from the HTML so specs stay readable and a
 * markup change only needs editing here.
 */
class ManagerPage {
  /** @param {import('@playwright/test').Page} page */
  constructor(page) {
    this.page = page;

    // Tab strip + storage-mode indicator
    this.tabs = page.locator('#tabs');
    // Consolidated CISO-friendly nav (REQUIREMENTS §26d)
    this.navGroups = page.locator('#navGroups');
    this.modeLabel = page.locator('#modeLabel');
    this.srcLabel = page.locator('#src');
    this.versionBadge = page.locator('#versionBadge');

    // Home / Overview (landing)
    this.homeBody = page.locator('#homeBody');
    this.homeAttnBadge = page.locator('#homeAttnBadge');
    this.homeAttnCallout = page.locator('#homeAttnCallout');
    this.homeRefresh = page.locator('#homeRefresh');
    this.homeTiles = page.locator('#homeBody .home-tile');

    // Tab badges
    this.validateErrBadge = page.locator('#validateErrBadge');
    this.saveDirtyBadge = page.locator('#saveDirtyBadge');
    this.revokeCountBadge = page.locator('#revokeCountBadge');
    this.gridDirtyBadge = page.locator('#gridDirtyBadge');
    this.govEmergencyBadge = page.locator('#govEmergencyBadge');

    // Create wizard
    this.wizCards = page.locator('#wizCards');
    this.wizBg = page.locator('#wizBg');
    this.wizModal = page.locator('#wizModal');
    this.wizTitle = page.locator('#wizTitle');
    this.wizSteps = page.locator('#wizSteps');
    this.wizBody = page.locator('#wizBody');
    this.wizBack = page.locator('#wizBack');
    this.wizNext = page.locator('#wizNext');
    this.wizFinish = page.locator('#wizFinish');
    this.wizCancel = page.locator('#wizCancel');
    this.tplSection = page.locator('#tplSection');
    this.tplCards = page.locator('#tplCards');

    // Delegation Map
    this.mapSearch = page.locator('#mapSearch');
    this.mapBoard = page.locator('#mapBoard');
    this.mapDetail = page.locator('#mapDetail');
    this.mapClear = page.locator('#mapClear');
    this.mapFocusToggle = page.locator('#mapFocusToggle');
    this.mapCols = [
      page.locator('#mapCol0'), page.locator('#mapCol1'),
      page.locator('#mapCol2'), page.locator('#mapCol3'),
    ];

    // Validate
    this.btnValRefresh = page.locator('#btnValRefresh');
    this.btnFixAll = page.locator('#btnFixAll');
    this.valSearch = page.locator('#valSearch');
    this.valResults = page.locator('#valResults');
    this.valBlockToggle = page.locator('#valBlockToggle');
    this.valChipErrN = page.locator('#valChipErrN');
    this.valChipWarnN = page.locator('#valChipWarnN');
    this.valChipInfoN = page.locator('#valChipInfoN');
    this.valCountErr = page.locator('#valCountErr');

    // Review & Save
    this.btnCommit = page.locator('#btnCommit');
    this.btnRefresh = page.locator('#btnRefresh');
    this.btnCancelSave = page.locator('#btnCancel');
    this.saveStatus = page.locator('#saveStatus');
    this.saveCards = page.locator('#saveCards');

    // Maintenance (Revoke)
    this.revBtnRefresh = page.locator('#revBtnRefresh');
    this.revResults = page.locator('#revResults');
    this.revSearch = page.locator('#revSearch');
    this.revBtnRevoke = page.locator('#revBtnRevoke');
    this.revJustify = page.locator('#revJustify');
    this.wlPanel = page.locator('#wlPanel');
    this.wlWorkload = page.locator('#wlWorkload');

    // Advanced View (grid)
    this.gridList = page.locator('#gridList');
    this.gridMain = page.locator('#gridMain');
    this.btnAddRow = page.locator('#btnAddRow');
    this.btnReloadGrid = page.locator('#btnReloadGrid');
    this.gridTable = page.locator('#gridMain table.grid');
    this.gridSelectAll = page.locator('#gridSelectAll');
    this.gridActionBar = page.locator('#gridActionBar');
    this.gabDelete = page.locator('#gabDelete');
    this.gabClear = page.locator('#gabClear');

    // Reports ("who can do what" + reverse) + global search (REQUIREMENTS §26a)
    this.reportsBody = page.locator('#reportsBody');
    this.rptSubject = page.locator('#rptSubject');
    this.rptRun = page.locator('#rptRun');
    this.rptResults = page.locator('#rptResults');
    this.rptModeWhoCan = page.locator('#rptModeWhoCan');
    this.rptModeWhoHas = page.locator('#rptModeWhoHas');
    this.globalSearch = page.locator('#globalSearch');
    this.globalSearchResults = page.locator('#globalSearchResults');

    // Governance
    this.govBody = page.locator('#govBody');

    // Conformance
    this.confBody = page.locator('#confBody');
    this.confTpl = page.locator('#confTpl');
    this.confReload = page.locator('#confReload');
    this.confDry = page.locator('#confDry');
    this.confLive = page.locator('#confLive');

    // Shared confirm modal
    this.modalBg = page.locator('#modalBg');
    this.modalOk = page.locator('#modalOk');
    this.modalCancel = page.locator('#modalCancel');
  }

  tab(name) { return this.page.locator(`#tabs .tab[data-tab="${name}"]`); }
  panel(name) { return this.page.locator(`#${name}Tab`); }

  // --- Consolidated nav (§26d) helpers ---------------------------------------
  navGroup(id) { return this.page.locator(`#navGroups .nav-group[data-group="${id}"]`); }
  navGroupBtn(id) { return this.navGroup(id).locator('.nav-group-btn'); }
  navItem(tabKey) { return this.page.locator(`#navGroups .nav-group-item[data-tab="${tabKey}"]`); }
  /** Open a group's dropdown, then click the item that routes to `tabKey`. */
  async openViaNav(groupId, tabKey) {
    await this.navGroupBtn(groupId).click();
    await this.navItem(tabKey).waitFor({ state: 'visible' });
    await this.navItem(tabKey).click();
    await this.panel(tabKey).waitFor({ state: 'visible' });
    await this.page.locator(`#${tabKey}Tab.active`).waitFor();
  }

  /**
   * Switch to a tab and wait for its panel to become active.
   * The Manager consolidated its flat tab strip into CISO-friendly menu groups
   * (§26d): when the grouped nav is active the flat #tabs strip is hidden, so we
   * drive the tab through its menu item; otherwise we click the flat tab. Either
   * path routes through the same switchTab() and activates the same panel.
   */
  async openTab(name) {
    const grouped = await this.page.locator('body.js-nav-grouped').count();
    if (grouped) {
      const item = this.navItem(name);
      // open the owning group's dropdown so the item is actionable, then click it.
      const group = this.page.locator(`#navGroups .nav-group:has(.nav-group-item[data-tab="${name}"])`);
      await group.locator('.nav-group-btn').click();
      await item.waitFor({ state: 'visible' });
      await item.click();
    } else {
      await this.tab(name).click();
    }
    await this.panel(name).waitFor({ state: 'visible' });
    await this.page.locator(`#${name}Tab.active`).waitFor();
  }

  /** True when the page is in server (read-write) mode (not static). */
  async isServerMode() {
    const cls = await this.modeLabel.getAttribute('class');
    return !(cls && cls.includes('modeStatic'));
  }

  /** Current role from the injected boot object. */
  async role() {
    return await this.page.evaluate(() => (window.PIM_ROLE_BOOT && window.PIM_ROLE_BOOT.role) || 'Reader');
  }

  /** The bearer token the page actually uses (from the injected meta). */
  async pageToken() {
    return await this.page.evaluate(() => {
      const m = document.querySelector('meta[name=pim-token]');
      return m ? m.getAttribute('content') : null;
    });
  }

  /** Open a Create wizard tile by its data-wiz value. */
  async openWizard(wiz) {
    await this.openTab('new');
    await this.page.locator(`.wiz-card[data-wiz="${wiz}"]`).click();
    await this.wizModal.waitFor({ state: 'visible' });
  }

  /** Open a grid file (CSV base) in Advanced View. */
  async openGrid(base) {
    await this.openTab('grid');
    await this.gridList.locator('.item').filter({ hasText: base }).first().click();
    await this.gridTable.waitFor({ state: 'visible' });
  }

  /**
   * Edit an editable (contenteditable) cell of the first data row and commit it
   * via blur (the grid's blur handler reads td.textContent). If `col` is given,
   * edits that named column (data-col); otherwise the first editable cell.
   * Returns the value written. The page rebuilds the table on each edit.
   */
  async editFirstCell(value, col) {
    const sel = col
      ? `tr[data-idx] td[contenteditable="true"][data-col="${col}"]`
      : 'tr[data-idx] td[contenteditable="true"]';
    const cell = this.gridTable.locator(sel).first();
    await cell.waitFor({ state: 'visible' });
    await cell.click();
    // select-all + replace, then blur via Tab so the blur handler fires.
    await this.page.keyboard.press('Control+A');
    await this.page.keyboard.type(value);
    await this.page.keyboard.press('Tab');
    return value;
  }
}

module.exports = { ManagerPage };
