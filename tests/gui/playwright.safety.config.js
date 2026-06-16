// Minimal Playwright config for the standalone Manager safety GUI spec
// (tests/gui/pim-manager-safety.spec.js). No globalSetup -- the Manager is
// booted separately by Verify-PimManagerSafetyGui.ps1, which exports
// PIM_GUI_BASEURL / PIM_GUI_TOKEN. Kept apart from the SQL scenario config
// (tests/scenario/gui/playwright.config.js) so it never boots the SQL manager.
const { defineConfig, devices } = require('@playwright/test');
const path = require('path');

module.exports = defineConfig({
  testDir: __dirname,
  testMatch: 'pim-manager-safety.spec.js',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  use: {
    headless: true,
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    trace: 'off',
    screenshot: 'off',
    video: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
