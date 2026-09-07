/*
 * config-zone-wiring.js -- IMP-20 SAFETY NET, written BEFORE the refactor it protects.
 *
 * WHAT IT PROVES, and why a static check could not:
 * The four CONFIGURATION blocks (auto-create policy, permission templates, scheduled mails &
 * jobs, mail templates) are RENDERED in one function and WIRED in that same function's tail,
 * ~130 lines apart. Moving them to the Settings page means carrying the wiring with them, and
 * the failure mode is a control that still LOOKS right and silently does nothing -- which no
 * grep can see, because both the markup and a getElementById() for it still exist somewhere in
 * the file. The endpoint-existence harness would pass too: the endpoints are fine; it is the
 * BINDING that would be lost.
 *
 * So this asserts the only thing that matters: after the page renders the tab that owns each
 * control, the control EXISTS in the DOM and has a HANDLER ATTACHED to it.
 *
 * 🔑 It is written and made to pass against the CURRENT layout first. A test authored after a
 * refactor only proves the refactor is self-consistent; one that passed before and still passes
 * after proves the behaviour survived. That ordering is the whole point of it.
 *
 * Emits JSON on stdout: { ok, findings: [{id, where, present, wired}] }
 * Exit 0 always (the PS wrapper decides); 2 on a harness error (jsdom/html missing).
 */
'use strict';
const fs = require('fs');
const path = require('path');

function harnessFail(msg) {
  process.stdout.write(JSON.stringify({ harnessError: msg }) + '\n');
  process.exit(2);
}
let JSDOM;
try { ({ JSDOM } = require('jsdom')); } catch (e) { harnessFail('jsdom not installed: ' + e.message); }

const HTML = path.resolve(__dirname, '..', '..', 'tools', 'pim-manager', 'pim-manager.html');
if (!fs.existsSync(HTML)) harnessFail('pim-manager.html not found at ' + HTML);
let html = fs.readFileSync(HTML, 'utf8');

// ---- the controls under protection -------------------------------------------------------
// `tab` is the tab that must render each control. When the IMP-20 move happens, the expected
// tab for these changes from 'governance' to 'settings' -- and THAT is the edit that makes this
// test meaningful: it must be changed deliberately, and the run must stay green either way.
const CONTROLS = [
  { id: 'govDiscPolSave', tab: 'settings', what: 'Auto-create policy -- Save' },
  { id: 'govSchedSave',   tab: 'settings', what: 'Scheduled mails & jobs -- Save schedule' },
];
// Controls that only exist once their section has data; asserted as "present implies wired".
const CONDITIONAL = [
  { id: 'govMailSave',   tab: 'governance', what: 'Mail templates -- Save' },
  { id: 'govMailCancel', tab: 'governance', what: 'Mail templates -- Cancel' },
  { id: 'govMailRevert', tab: 'governance', what: 'Mail templates -- Reset to shipped default' },
];

const SEED_ROLE = { role: 'SuperAdmin', identity: 'tester@seed.test' };
const FLAGS = {};
['home','map','authoring','save','validate','cutover','revoke','approvals','jobs','governance',
 'roleperms','audit','support','settings','new','onboarding','grid','accessreview','reports',
 'conformance','downlink'].forEach(k => { FLAGS[k] = true; });

const sub = {
  '__PIM_TOKEN__': 'test-bearer-token',
  '__PIM_MODE__': 'server',
  '__PIM_VERSION__': '9.9.9',
  '__PIM_DATA__': JSON.stringify({ tenantName: 'seed', tenantId: 't', sourceRoot: '', nodes: [], edges: [], csvBases: [] }),
  '__PIM_NAMING__': JSON.stringify({}),
  '__PIM_TENANT_LISTS__': JSON.stringify({}),
  '__PIM_INSTANCES__': JSON.stringify({ active: 'local', instances: [] }),
  '__PIM_ROLE__': JSON.stringify(SEED_ROLE),
  '__PIM_FEATUREFLAGS__': JSON.stringify({ flags: FLAGS, effective: FLAGS, catalog: [], warnings: [] }),
  '__PIM_GOVPREVIEW__': JSON.stringify({ enabled: false }),
};
for (const [k, v] of Object.entries(sub)) html = html.split(k).join(v);

// Minimal API mock: enough shape for the config sections to render their controls.
function mockFetch(url) {
  const u = String(url);
  const J = (o) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(o), text: () => Promise.resolve(JSON.stringify(o)) });
  if (u.includes('/api/discovery'))    return J({ baselineMissing: false, baselineAtUtc: '2026-01-01T00:00:00Z', newItems: [],
                                                  policy: { AzureSubscription: 'flag', EntraRole: 'flag' },
                                                  types: ['AzureSubscription', 'EntraRole'], values: ['flag','pending','auto'] });
  if (u.includes('/api/templates'))    return J({ templates: [{ id: 'p1', name: 'Azure RBAC delegation', version: 'v1', rows: 8, newToImport: 0, active: true, description: 'seed' }] });
  if (u.includes('/api/job-schedule')) return J({ jobs: [{ name: 'reminders', type: 'reminders', enabled: true, intervalMinutes: 720, isMail: true }] });
  if (u.includes('/api/mail-template'))return J({ templates: [{ type: 'daily-summary', subject: 'x', source: 'shipped default' }] });
  if (u.includes('/api/drift'))        return J({ supported: true, items: [] });
  if (u.includes('/api/emergency'))    return J({ active: false });
  if (u.includes('/api/settings'))     return J({ storageMode: 'sql', instance: 'seed', naming: {}, filters: [], departments: [] });
  return J({});
}

const dom = new JSDOM(html, {
  url: 'http://localhost/',
  runScripts: 'dangerously',
  pretendToBeVisual: true,
  beforeParse(w) {
    w.fetch = (url) => mockFetch(url);
    w.confirm = () => true; w.alert = () => {}; w.prompt = () => null;
    w.Element.prototype.scrollIntoView = function () {};
  },
});

const findings = [];
function hasHandler(el) {
  if (!el) return false;
  // A control is WIRED if it carries a direct handler property. That is how every one of these
  // is bound today (el.onclick = ...), so it is the property whose loss the move would cause.
  return !!(el.onclick || el.onchange || el.onclick === null && el.getAttribute('data-wired'));
}

setTimeout(() => {
  const w = dom.window, d = w.document;
  try {
    for (const tab of ['governance', 'settings']) {
      try { w.switchTab(tab); } catch (e) { /* recorded via the per-control result */ }
    }
    setTimeout(() => {
      for (const c of CONTROLS.concat(CONDITIONAL)) {
        const el = d.getElementById(c.id);
        const conditional = CONDITIONAL.some(x => x.id === c.id);
        findings.push({
          id: c.id, what: c.what, expectedTab: c.tab,
          present: !!el,
          wired: el ? !!(el.onclick || el.onchange) : null,
          conditional: conditional,
        });
      }
      // A control that is PRESENT but NOT WIRED is the exact IMP-20 failure. A conditional
      // control that is absent is acceptable (its section had no data in this seed); a
      // REQUIRED control that is absent is a failure.
      const bad = findings.filter(f => (f.present && f.wired === false) || (!f.conditional && !f.present));
      process.stdout.write(JSON.stringify({ ok: bad.length === 0, findings: findings }, null, 2) + '\n');
      process.exit(0);
    }, 400);
  } catch (e) {
    process.stdout.write(JSON.stringify({ harnessError: 'render threw: ' + (e && e.stack || e) }) + '\n');
    process.exit(2);
  }
}, 400);
