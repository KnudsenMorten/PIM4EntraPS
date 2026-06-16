// @ts-check
const base = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const SIDE = process.env.PIM_GUI_SIDECAR || path.join(__dirname, 'harness', '.manager.json');

function readSidecar() {
  try { return JSON.parse(fs.readFileSync(SIDE, 'utf8').replace(/^﻿/, '')); } catch { return { skip: true, reason: 'no sidecar' }; }
}
const SIDECAR = readSidecar();

/**
 * Custom fixtures:
 *   - `mgr`     : the sidecar info ({ baseUrl, token, role, ... }).
 *   - `pim`     : a Page already navigated to the Manager (token in URL -> the
 *                 server injects it into <meta name=pim-token>, so the page's
 *                 own /api fetches are authenticated). A heartbeat keeps the
 *                 loopback server alive (it self-exits after 30s of silence).
 *   - `api`     : an APIRequestContext pre-loaded with `Authorization: Bearer`
 *                 for asserting the API EFFECT of a GUI action directly.
 *
 * Self-skip: when the harness reported skip:true (no SQLEXPRESS / no boot), the
 * whole suite skips cleanly -- mirrors the PS Live-test rule (absence != failure).
 */
const test = base.test.extend({
  mgr: [async ({}, use, testInfo) => {
    if (SIDECAR.skip) {
      testInfo.skip(true, `GUI harness unavailable: ${SIDECAR.reason || 'prerequisites missing'}`);
    }
    await use(SIDECAR);
  }, { auto: false }],

  // APIRequestContext with the bearer header -- for asserting API effects.
  api: async ({ playwright, mgr }, use) => {
    const ctx = await playwright.request.newContext({
      baseURL: mgr.baseUrl,
      extraHTTPHeaders: { Authorization: `Bearer ${mgr.token}` },
    });
    await use(ctx);
    await ctx.dispose();
  },

  // A Page on the Manager, authenticated, with a heartbeat keep-alive.
  pim: async ({ page, mgr }, use) => {
    // keep the loopback server alive: it self-exits after ~30s of no requests.
    const beat = setInterval(() => {
      fetch(`${mgr.baseUrl}/api/heartbeat`, {
        method: 'POST', headers: { Authorization: `Bearer ${mgr.token}` },
      }).catch(() => {});
    }, 8000);
    // token travels in the URL on first hop; the server injects it into the page meta.
    await page.goto(`${mgr.baseUrl}/?token=${mgr.token}`, { waitUntil: 'domcontentloaded' });
    // Wait until the SPA has booted (a tab is active in the DOM). Use state:'attached',
    // NOT visibility: the flat #tabs strip is the canonical tab/switchTab surface but
    // it is HIDDEN once the consolidated CISO-friendly nav builds (§26d), so a
    // visibility wait on '#tabs .tab.active' would never resolve. Attachment is the
    // correct readiness signal regardless of which nav surface is shown.
    await page.waitForSelector('#tabs .tab.active', { state: 'attached', timeout: 20000 });
    await use(page);
    clearInterval(beat);
  },
});

const expect = base.expect;
module.exports = { test, expect, SIDECAR };
