// Playwright config for the PIM4EntraPS engine+GUI scenario simulation (REQUIREMENTS §20).
// The Manager is booted (loopback, SQL mode, rich scenario seed) by global-setup.js and
// stopped by global-teardown.js; specs read the sidecar (.manager.json) for baseUrl+token.
const { defineConfig, devices } = require('@playwright/test');
const path = require('path');

module.exports = defineConfig({
  testDir: path.join(__dirname, 'specs'),
  fullyParallel: false,
  workers: 1,                     // one loopback Manager -> one worker
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
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
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
