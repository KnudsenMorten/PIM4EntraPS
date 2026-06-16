import { test, expect } from '@playwright/test';
import {
    openManager, inspectTab, bannerProblems, collectPageErrors, TabSpec,
} from './support/manager';

/**
 * PIM4EntraPS Manager — REAL-BROWSER GUI VALIDATION  (@gui)
 * ========================================================
 * Drives the Manager in headless chromium against a LIVE local server (seeded
 * CSV data, isServer === true). For EVERY tab it asserts, in a real layout/paint
 * engine:
 *   1. the tab activates and its panel renders VISIBLE, non-trivial content
 *      (real data OR an honest empty/error state — never blank/dead, never the
 *      "Static mode" short-circuit that means the panel mis-detected the server);
 *   2. no console.error / pageerror fires while the tab is open;
 *   3. layout/visual sanity — no horizontal overflow, no control clipped off the
 *      right edge, no empty <select> rendering as a dead dropdown;
 *   4. (data tabs) a content marker is present.
 * A screenshot of every tab is captured for triage (test-results/screens/).
 *
 * This is the gate the jsdom structural check (Test-PimManagerGuiPanels.ps1)
 * cannot be: jsdom has no CSS/layout engine and never runs the live-server render
 * path. Findings are collected per tab so ONE run names every broken spot.
 */

// Every tab on the Manager strip, in display order. markers are env-neutral
// content the panel renders when healthy on seeded data.
const TABS: TabSpec[] = [
    { tab: 'new',         label: 'Create',            panelId: 'newTab',         markers: ['create', 'admin', 'wizard', 'next', 'name'] },
    { tab: 'map',         label: 'Delegation Map',    panelId: 'mapTab',         markers: ['delegation', 'group', 'role', 'scope', 'admin'] },
    { tab: 'validate',    label: 'Validate',          panelId: 'validateTab',    markers: ['validat', 'finding', 'pass', 'warning', 'preflight'] },
    { tab: 'save',        label: 'Review & Save',     panelId: 'saveTab',        markers: ['review', 'save', 'change', 'pending', 'commit'] },
    { tab: 'revoke',      label: 'Maintenance',       panelId: 'revokeTab',      markers: ['active', 'assignment', 'revoke', 'maintenance'] },
    { tab: 'accessreview',label: 'Access Review',     panelId: 'accessreviewTab',markers: ['access review', 'reviewer', 'decision', 'campaign'] },
    { tab: 'grid',        label: 'Advanced View',     panelId: 'gridTab',        markers: ['grid', 'column', 'row', 'definitions', 'assignments'] },
    { tab: 'authoring',   label: 'Authoring',         panelId: 'authoringTab',   markers: ['authoring', 'bulk', 'clone', 'attach', 'import'] },
    { tab: 'onboarding',  label: 'Onboarding',        panelId: 'onboardingTab',  markers: ['onboard', 'guest', 'invite', 'self-service', 'consultant'] },
    { tab: 'roleperms',   label: 'Role Lookup',       panelId: 'rolepermsTab',   markers: ['role', 'permission', 'lookup', 'definition'] },
    { tab: 'governance',  label: 'Governance',        panelId: 'governanceTab',  markers: ['governance', 'break-glass', 'emergency', 'license', 'lifecycle'] },
    { tab: 'audit',       label: 'Audit',             panelId: 'auditTab',       markers: ['audit', 'action', 'category', 'login', 'trail'] },
    { tab: 'conformance', label: 'Template Rollout',  panelId: 'conformanceTab', markers: ['template', 'rollout', 'tenant', 'ring', 'conform'] },
    { tab: 'cutover',     label: 'Cutover',           panelId: 'cutoverTab',     markers: ['cutover', 'stage', 'preflight', 'finalize', 'sql'] },
    { tab: 'jobs',        label: 'Jobs',              panelId: 'jobsTab',        markers: ['job', 'schedule', 'run', 'next', 'last'] },
    { tab: 'settings',    label: 'Settings',          panelId: 'settingsTab',    markers: ['settings', 'naming', 'prefix', 'suffix', 'filter'] },
    { tab: 'support',     label: 'Support',           panelId: 'supportTab',     markers: ['support', 'version', 'mode', 'help', 'diagnostic'] },
];

test.describe('@gui PIM Manager — real-browser per-tab validation', () => {
    // One page, swept across every tab, so findings accumulate into one report.
    test('every tab renders, paints, and is layout-sane on a live server', async ({ page }, testInfo) => {
        test.setTimeout(180_000);
        const errs = collectPageErrors(page);
        const allProblems: string[] = [];

        await openManager(page);

        // Confirm we are genuinely on a live server (not a static render) — if not,
        // EVERY tab would falsely "pass" its static short-circuit. This is a guard
        // on the gate itself.
        const mode = await page.locator('meta[name=pim-mode]').getAttribute('content');
        if (!mode || mode === 'static') {
            allProblems.push(`GATE: page loaded in mode="${mode}" — expected a live server (server|SQL:*). The validator must drive Open-PimManager.ps1 -Server, not a static render.`);
        }

        // Banner / tab-strip sanity (once).
        allProblems.push(...(await bannerProblems(page)));
        await page.screenshot({ path: testInfo.outputPath('screens/00-banner.png'), fullPage: true }).catch(() => {});

        // Per-tab sweep.
        let i = 1;
        for (const t of TABS) {
            const probs = await inspectTab(page, t);
            const num = String(i).padStart(2, '0');
            await page.screenshot({ path: testInfo.outputPath(`screens/${num}-${t.tab}.png`), fullPage: true }).catch(() => {});
            if (probs.length) {
                allProblems.push(...probs);
                await testInfo.attach(`${t.label} screenshot`, {
                    path: testInfo.outputPath(`screens/${num}-${t.tab}.png`),
                    contentType: 'image/png',
                }).catch(() => {});
            }
            i++;
        }

        // Page-global JS errors observed across the whole sweep.
        if (errs.length) allProblems.push(...errs.map((e) => `PAGE: ${e}`));

        // Emit a single, human-readable list of every broken spot.
        if (allProblems.length) {
            const report = ['', `FOUND ${allProblems.length} GUI problem(s):`, ...allProblems.map((p) => `  • ${p}`), ''].join('\n');
            console.error(report);
        }
        expect(allProblems, '\n' + allProblems.join('\n') + '\n').toEqual([]);
    });
});
