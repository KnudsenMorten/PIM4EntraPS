import { defineConfig, devices } from '@playwright/test';

/**
 * Real-browser (chromium, HEADLESS) GUI validation for the PIM4EntraPS Manager.
 *
 * Headless on purpose: the gate runs unattended (CI / post-deploy) and must NOT
 * pop a visible browser window — but it is a REAL browser engine (real CSS,
 * layout, paint), which is the whole point versus the jsdom structural check.
 *
 * The server is started + torn down by tools/Run-PimGuiValidation.ps1, which
 * passes the tokenised URL in PIM_MGR_URL. We do NOT use Playwright's webServer
 * because the Manager is a PowerShell 5.1 HttpListener with a token handshake.
 *
 * The Manager is a desktop SPA (wide tab strip), so the default viewport is a
 * desktop one; a narrow project is also defined to catch wrap/overflow at a
 * laptop-tab width.
 */
export default defineConfig({
    testDir: '.',
    timeout: 120_000,
    expect: { timeout: 8_000 },
    fullyParallel: false,
    workers: 1,
    reporter: [
        ['html', { open: 'never', outputFolder: 'playwright-report' }],
        ['list'],
    ],
    use: {
        headless: true,
        actionTimeout: 12_000,
        trace: 'retain-on-failure',
        screenshot: 'on',
        video: 'retain-on-failure',
        ignoreHTTPSErrors: true,
    },
    outputDir: 'test-results',
    projects: [
        {
            name: 'desktop',
            use: { ...devices['Desktop Chrome'], viewport: { width: 1366, height: 900 } },
        },
        {
            name: 'narrow-laptop',
            use: { ...devices['Desktop Chrome'], viewport: { width: 1024, height: 768 } },
        },
    ],
});
