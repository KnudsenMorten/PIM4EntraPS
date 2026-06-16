// @ts-check
const { defineConfig, devices } = require('@playwright/test');
const path = require('path');

/**
 * Playwright config for the PIM4EntraPS Manager GUI suite.
 *
 * Harness model (see harness/Start-PimManagerForGui.ps1 and global-setup.js):
 *   - PRIMARY (local instance): global-setup boots a LOCAL Manager
 *     (Open-PimManager.ps1 -Server -NoLaunch) in SQL mode against a throwaway
 *     local SQLEXPRESS pim.Rows DB, captures the per-session bearer token, and
 *     writes baseURL + token into a sidecar. Every test attaches
 *     `Authorization: Bearer <token>` so the page's /api/* calls succeed. This
 *     exercises the real GUI + real backend end-to-end without the Entra wall.
 *   - OPTIONAL (live smoke): set PIM_GUI_LIVE_URL + PIM_GUI_LIVE_TOKEN to point
 *     at the hosted ca-pim-manager with an injected Easy-Auth/API token; setup
 *     skips the local boot and uses those instead. @live-tagged specs run there.
 *
 * Self-skip: if Node/Playwright deps or SQLEXPRESS are unavailable the harness
 * writes { skip:true } and global-setup marks the run skipped so the suite is a
 * clean no-op on a box without the prerequisites (mirrors the PS Live-test rule).
 */

const SIDE = process.env.PIM_GUI_SIDECAR || path.join(__dirname, 'harness', '.manager.json');

module.exports = defineConfig({
  testDir: path.join(__dirname, 'specs'),
  // baseURL/extraHTTPHeaders are injected per-worker from the sidecar in the
  // `pim` fixture (fixtures.js) -- they are not known until global-setup runs.
  fullyParallel: false,          // single local Manager instance; keep ordering deterministic
  workers: 1,                    // one HttpListener -> one worker
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [
    ['list'],
    ['json', { outputFile: path.join(__dirname, 'test-results', 'results.json') }],
    ['html', { outputFolder: path.join(__dirname, 'playwright-report'), open: 'never' }],
  ],
  timeout: 60_000,
  expect: { timeout: 10_000 },
  // @live specs need a real tenant (active-assignments, revoke, conformance deploy).
  // They are excluded by default (offline gate) unless PIM_GUI_LIVE is truthy --
  // mirrors the PowerShell "Live tests skip unless PIM_LIVE_TESTS" rule.
  grepInvert: process.env.PIM_GUI_LIVE ? undefined : /@live/,
  globalSetup: require.resolve('./harness/global-setup.js'),
  globalTeardown: require.resolve('./harness/global-teardown.js'),
  use: {
    headless: true,
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  metadata: { sidecar: SIDE },
});
