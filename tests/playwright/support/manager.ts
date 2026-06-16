import { test, expect, Page } from '@playwright/test';

/**
 * Shared harness for the PIM4EntraPS Manager GUI validator (REAL browser).
 *
 * Unlike the jsdom structural check (tests/Test-PimManagerGuiPanels.ps1), this
 * drives the Manager in a real chromium engine (headless) so it exercises actual
 * CSS layout, paint, and the per-tab render*() JS against a LIVE server (so
 * `isServer === true` and the panels render real data instead of the
 * "Static mode -- needs the server" short-circuit). That live path is exactly
 * what jsdom could not see.
 *
 * The base URL (incl. ?token=...) is provided by the launcher
 * (tools/Run-PimGuiValidation.ps1) via PIM_MGR_URL. There is no login flow:
 * the Manager binds loopback and embeds a per-session token in a <meta> tag,
 * which the page reads itself; we just navigate to the tokenised URL.
 */

export const BASE = process.env.PIM_MGR_URL ?? 'http://127.0.0.1:8899/';

/** The Manager is a single-page app: every "tab" is a div.tab-panel toggled by
 *  switchTab(name); there are no routes. dataset.tab -> "<name>Tab" container. */
export interface TabSpec {
    /** data-tab value on the clickable .tab chip (== switchTab arg). */
    tab: string;
    /** Human label shown in the report. */
    label: string;
    /** id of the .tab-panel container that becomes .active. */
    panelId: string;
    /** Optional: substrings, any one of which proves the panel rendered real
     *  content. An honest empty/error state also passes (see EMPTY_STATE). */
    markers?: string[];
}

/** Honest empty/error states still count as "alive" (the panel rendered SOMETHING
 *  explaining itself) -- a blank/dead panel does not. NOTE: the literal
 *  "static mode" copy is deliberately NOT here: against a live server it would be
 *  a real defect (the panel wrongly thinks it has no server), so we flag it. */
const EMPTY_STATE =
    /no .* (yet|found|match|configured|available)|nothing (here|to show)|not (active|available|found|configured)|empty|coming soon|no data|loading|failed|error|unavailable|require|needs? (admin|the server|a)/i;

/** Attach a console.error / pageerror collector. Returns the (mutated) array.
 *  Benign network noise (favicon, aborted heartbeat on teardown) is filtered so
 *  a non-empty array means a genuine script/render error. */
export function collectPageErrors(page: Page): string[] {
    const errors: string[] = [];
    const benign = /favicon|net::ERR_ABORTED.*heartbeat|ERR_BLOCKED/i;
    // The Maintenance tab's active-assignments fetch needs a live engine-SPN /
    // tenant context, which a local seeded run does not have -> a 500 by design,
    // surfaced as an honest "Refresh failed" in the panel. Not a GUI defect.
    // Set PIM_MGR_REQUIRE_TENANT=1 to treat it as a failure (e.g. hosted run).
    const expectTenant = process.env.PIM_MGR_REQUIRE_TENANT === '1';
    const envOnly = /active-assignments|engine SPN context|500 \(Internal Server Error\)|status of 500/i;
    page.on('console', (m) => {
        if (m.type() !== 'error') return;
        const txt = m.text();
        if (benign.test(txt)) return;
        if (!expectTenant && envOnly.test(txt)) return; // expected offline (no tenant)
        errors.push(`console.error: ${txt}`);
    });
    page.on('pageerror', (e) => {
        const s = String(e && (e.message ?? e));
        if (benign.test(s)) return;
        if (!expectTenant && envOnly.test(s)) return;
        errors.push(`pageerror: ${s}`);
    });
    return errors;
}

/** Navigate to the Manager root (tokenised) and wait for the SPA shell + initial
 *  data render. The default tab is "Delegation Map"; we wait for its panel to be
 *  active and for the tab strip to exist. */
export async function openManager(page: Page): Promise<void> {
    await page.goto(BASE, { waitUntil: 'domcontentloaded' });
    // The shell is server-rendered; the tab strip is always present.
    await expect(page.locator('.tab[data-tab]')).not.toHaveCount(0, { timeout: 15_000 });
    // Give the boot JS a beat to run switchTab/initial render + first heartbeat.
    await page.waitForTimeout(400);
}

/** Click a tab chip and wait for its panel to become the active one. Returns the
 *  panel locator. Throws (caught by caller) if the chip/panel never activates --
 *  itself a finding (dead tab). */
export async function gotoTab(page: Page, t: TabSpec) {
    const chip = page.locator(`.tab[data-tab="${t.tab}"]`);
    await expect(chip, `tab chip [data-tab=${t.tab}] missing`).toBeVisible({ timeout: 5_000 });
    await chip.click();
    const panel = page.locator(`#${t.panelId}`);
    await expect(panel, `panel #${t.panelId} did not activate`).toHaveClass(/active/, { timeout: 8_000 });
    // Renderers are async (fetch -> innerHTML); let the panel settle.
    await page.waitForTimeout(700);
    return panel;
}

/** The full per-tab health battery, run inside the REAL browser against a LIVE
 *  server. Returns problems[] (empty == healthy). Collects ALL problems so one
 *  run names every breakage on a tab, not just the first.
 */
export async function inspectTab(page: Page, t: TabSpec): Promise<string[]> {
    const problems: string[] = [];

    let panel;
    try {
        panel = await gotoTab(page, t);
    } catch (e) {
        return [`${t.label}: could not activate tab/panel (${String(e).split('\n')[0]})`];
    }

    // ---- 1. The panel rendered VISIBLE, non-trivial content -----------------
    const m = await panel.evaluate((el: Element) => {
        const h = el as HTMLElement;
        const text = (h.innerText ?? '').replace(/\s+/g, ' ').trim();
        const r = h.getBoundingClientRect();
        return {
            text,
            textLen: text.length,
            visible: r.width > 0 && r.height > 0 && getComputedStyle(h).display !== 'none',
            height: Math.round(r.height),
        };
    });
    if (!m.visible)         problems.push(`${t.label}: active panel is not visible (display:none / zero box)`);
    if (m.textLen < 15)     problems.push(`${t.label}: panel has only ${m.textLen} chars of text (blank/dead panel?)`);

    // A live-server panel that says "static mode" is broken: it wrongly thinks
    // there is no server even though we drove a real one.
    if (/static mode/i.test(m.text)) {
        problems.push(`${t.label}: shows "Static mode" copy against a LIVE server (panel mis-detected isServer)`);
    }

    // STUCK LOADER: the panel is still showing only a "Loading…" placeholder long
    // after its async renderer should have settled -> the renderer threw and never
    // replaced the spinner (the live-data render path is broken). A short trimmed
    // body that is essentially just the loading text is the tell.
    const trimmed = m.text.replace(/\s+/g, ' ').trim();
    if (/^(loading|loading\b.*)$/i.test(trimmed) || (/loading/i.test(trimmed) && trimmed.length < 40)) {
        problems.push(`${t.label}: stuck on a "${trimmed.slice(0, 40)}" placeholder (async renderer threw / never resolved)`);
    }

    // ---- 2. Content marker OR honest empty/error state ----------------------
    if (t.markers && t.markers.length) {
        const body = m.text.toLowerCase();
        const hasMarker = t.markers.some((x) => body.includes(x.toLowerCase()));
        if (!hasMarker && !EMPTY_STATE.test(m.text)) {
            problems.push(`${t.label}: none of [${t.markers.join(', ')}] present and no honest empty/error state`);
        }
    }

    // ---- 3. Layout / visual sanity -----------------------------------------
    problems.push(...(await layoutProblems(page, t.label, t.panelId)));

    return problems;
}

/** Real-CSS layout checks against the active panel + the global banner. These are
 *  the checks jsdom structurally cannot do (it has no layout engine). */
export async function layoutProblems(page: Page, label: string, panelId: string): Promise<string[]> {
    const out: string[] = [];
    const data = await page.evaluate((pid: string) => {
        const root = document.documentElement;
        const vw = root.clientWidth;
        const panel = document.getElementById(pid) as HTMLElement | null;
        const probs: string[] = [];

        // NOTE: whole-document horizontal overflow is a banner-level concern
        // (the shared tab strip / header), checked ONCE in bannerProblems so it
        // is not reported 17x. Here we only check the per-tab PANEL.

        if (panel) {
            // (b) The panel itself must not overflow the viewport to the right.
            const pr = panel.getBoundingClientRect();
            if (pr.right > vw + 2) {
                probs.push(`panel right edge ${Math.round(pr.right)}px exceeds viewport ${vw}px (cut off)`);
            }
            // (c) No descendant element is clipped off the right edge of the
            //     viewport (a control the operator cannot reach/click).
            const cut: string[] = [];
            panel.querySelectorAll<HTMLElement>('button, select, input, a, .tab, th, .toolbar > *').forEach((el) => {
                const r = el.getBoundingClientRect();
                const cs = getComputedStyle(el);
                if (cs.display === 'none' || cs.visibility === 'hidden' || r.width === 0) return;
                if (r.left > vw + 2 || r.right > vw + 60) {
                    const t = (el.innerText || el.getAttribute('id') || el.tagName).trim().slice(0, 24);
                    cut.push(`${el.tagName.toLowerCase()}"${t}"@${Math.round(r.right)}px`);
                }
            });
            if (cut.length) probs.push(`controls cut off past the right edge: ${cut.slice(0, 6).join(', ')}`);

            // (d) Dropdowns must be real <select>s, not raw text where a select
            //     was intended. Heuristic: a label/cell containing "▾"/"▾"
            //     glyph or the word "dropdown" with no nearby <select> is suspect.
            //     (Cheap + low-false-positive: flag visible <select> with zero
            //     options, which renders as an empty unusable control.)
            panel.querySelectorAll<HTMLSelectElement>('select').forEach((sel) => {
                if (getComputedStyle(sel).display === 'none') return;
                if (sel.options.length === 0) {
                    probs.push(`empty <select> (no options) id="${sel.id || '?'}" -- renders as a dead dropdown`);
                }
            });
        } else {
            probs.push(`panel #${pid} not found in DOM`);
        }
        return probs;
    }, panelId);
    return data.map((p) => `${label}: ${p}`);
}

/** Banner / header sanity (run once): the top banner controls must be in a single
 *  row (not wrapped mid-token) and the version/mode badges must be present. */
export async function bannerProblems(page: Page): Promise<string[]> {
    return await page.evaluate(() => {
        const probs: string[] = [];
        const root = document.documentElement;
        const vw = root.clientWidth;

        // (1) Whole-document horizontal overflow (the shared shell / tab strip).
        if (root.scrollWidth > vw + 2) {
            probs.push(`banner: document overflows horizontally -- ${root.scrollWidth}px content on a ${vw}px viewport (shell/tab-strip does not fit; right-side controls sit past the edge)`);
        }

        // (2) The tab strip: every chip visible and within the viewport, all on
        //     one row (a wrapped strip means tabs spill onto a second line).
        const chips = Array.from(document.querySelectorAll<HTMLElement>('.tab[data-tab]'));
        if (chips.length === 0) { probs.push('banner: no tab chips found'); return probs; }
        const tops = new Set<number>();
        chips.forEach((c) => {
            const r = c.getBoundingClientRect();
            tops.add(Math.round(r.top / 5) * 5); // bucket rows
            if (r.right > vw + 2) {
                probs.push(`banner: tab "${(c.innerText || '').trim().slice(0, 20)}" overflows the viewport right edge (${Math.round(r.right)}px > ${vw}px)`);
            }
        });
        if (tops.size > 1) {
            probs.push(`banner: tab strip wraps onto ${tops.size} rows (tabs do not fit on one line at ${vw}px)`);
        }

        // (3) The right-side mode/source status box must not sit past the edge.
        const right = document.getElementById('tabRight');
        if (right) {
            const rr = right.getBoundingClientRect();
            if (rr.right > vw + 2) {
                probs.push(`banner: #tabRight (mode/source status) overflows to ${Math.round(rr.right)}px past the ${vw}px viewport`);
            }
        }
        return probs;
    });
}
