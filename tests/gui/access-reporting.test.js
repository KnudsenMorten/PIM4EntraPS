// @ts-check
// Headless (no browser, no DOM) verification of the Visibility & reporting slice
// (REQUIREMENTS §26a):
//   1. The shared EXPORT helpers (csvCell / rowsToCsv) are INJECTION-SAFE and
//      produce correct CSV -- extracted from pim-manager.html + executed here.
//   2. The Manager markup wires the new surfaces (Reports tab, global search box,
//      and the Export CSV / Print bars on the operational views) -- "no dead view".
//
// Run:  node tests/gui/access-reporting.test.js   (exit 0 green / 1 red)

'use strict';
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
function ok(name, cond) {
  if (cond) { console.log('  PASS ' + name); pass++; }
  else { console.log('  FAIL ' + name); fail++; }
}

const htmlPath = path.join(__dirname, '..', '..', 'tools', 'pim-manager', 'pim-manager.html');
ok('pim-manager.html present', fs.existsSync(htmlPath));
const html = fs.readFileSync(htmlPath, 'utf8');

// --- 1. Extract + load the pure export helpers ------------------------------
const startMark = html.indexOf('__PIM_EXPORT_HELPERS_START__');
const endMark = html.indexOf('__PIM_EXPORT_HELPERS_END__');
ok('export helper markers present', startMark > -1 && endMark > startMark);
const start = html.indexOf('\n', startMark) + 1;
const end = html.lastIndexOf('\n', endMark);
const block = html.slice(start, end);
ok('block defines csvCell', /function csvCell\(/.test(block));
ok('block defines rowsToCsv', /function rowsToCsv\(/.test(block));

let csvCell, rowsToCsv;
try {
  const mod = new Function(block + '\n;return { csvCell: csvCell, rowsToCsv: rowsToCsv };')();
  csvCell = mod.csvCell; rowsToCsv = mod.rowsToCsv;
  ok('helpers loaded', typeof csvCell === 'function' && typeof rowsToCsv === 'function');
} catch (e) {
  ok('helpers loaded', false);
  console.log('    load error: ' + e.message);
}

if (csvCell) {
  // --- CSV injection safety (the hard rule: export must be safe) ------------
  ok('= formula is neutralised', csvCell('=1+1').startsWith("'="));
  ok('+ formula is neutralised', csvCell('+SUM(A1)').startsWith("'+"));
  ok('- formula is neutralised', csvCell('-2+3').startsWith("'-"));
  ok('@ formula is neutralised', csvCell('@cmd').startsWith("'@"));
  ok('tab-led value is neutralised', csvCell('\tx').startsWith("'"));
  ok('a plain value is untouched', csvCell('Global Administrator') === 'Global Administrator');
  ok('a value with comma is quoted', csvCell('a,b') === '"a,b"');
  ok('an embedded quote is doubled', csvCell('say "hi"') === '"say ""hi"""');
  ok('a newline value is quoted', /^".*"$/s.test(csvCell('line1\nline2')));
  ok('null becomes empty', csvCell(null) === '');

  // --- rowsToCsv shape ------------------------------------------------------
  const csv = rowsToCsv(['Target', 'Type'], [['Global Administrator', 'entra-role'], ['=evil', 'x']]);
  const lines = csv.split('\r\n');
  ok('header row present', lines[0] === 'Target,Type');
  ok('data row present', lines[1] === 'Global Administrator,entra-role');
  ok('injection row neutralised in output', lines[2].startsWith("'="));
  ok('CRLF line endings', csv.indexOf('\r\n') > -1);
}

// --- 2. Static markup / wiring (no dead views) ------------------------------
ok('Reports tab declared in nav', /data-tab="reports"/.test(html));
ok('Reports panel container present', /id="reportsTab"/.test(html));
ok('switchTab routes reports -> renderReports', /name === 'reports'\)\s*renderReports/.test(html));
ok('renderReports defined', /async function renderReports\(/.test(html));
ok('runReport defined', /async function runReport\(/.test(html));
ok('reports calls who-can endpoint', /\/api\/access-report\/who-can\?person=/.test(html));
ok('reports calls who-has endpoint', /\/api\/access-report\/who-has\?role=/.test(html));

ok('global search box present', /id="globalSearch"/.test(html));
ok('global search results host present', /id="globalSearchResults"/.test(html));
ok('initGlobalSearch defined', /function initGlobalSearch\(/.test(html));
ok('initGlobalSearch called at boot', /initGlobalSearch\(\);/.test(html));
ok('global search calls /api/search', /\/api\/search\?q=/.test(html));

// Export everywhere -- the shared bar wired into the operational views.
ok('exportBarHtml defined', /function exportBarHtml\(/.test(html));
ok('wireExportBar defined', /function wireExportBar\(/.test(html));
ok('downloadCsv defined', /function downloadCsv\(/.test(html));
ok('printTable defined', /function printTable\(/.test(html));
ok('reports view wires its export bar', /wireExportBar\('rpt'/.test(html));
ok('audit view wires its export bar', /wireExportBar\('audit'/.test(html));
ok('access-review view wires its export bar', /wireExportBar\('ar'/.test(html));
ok('validate view wires its export bar', /wireExportBar\('val'/.test(html));
ok('delegation map wires its export bar', /wireExportBar\('map'/.test(html));

// Role Lookup export ([L5]/[H5]) -- all four read-only modes now export their
// who-has-what / role-permission result for a least-privilege ticket / auditor trail.
ok('role-lookup permissions view wires export', /wireExportBar\('rpPerm'/.test(html));
ok('role-lookup by-action view wires export', /wireExportBar\('baMatch'/.test(html));
ok('role-lookup reverse view wires export', /wireExportBar\('rvReach'/.test(html));
ok('role-lookup compare view wires export', /wireExportBar\('cmpCmp'/.test(html));

// Maintenance / active-assignments export ([H5]) -- the "who has what is active" extract.
ok('active-assignments export bar present', /id="revExportBar"/.test(html));
ok('active-assignments export wired (csv)', /revExpCsv/.test(html) && /downloadCsv\(d\.filename/.test(html));
ok('active-assignments export wired (print)', /revExpPrint/.test(html) && /printTable\(d\.title/.test(html));

// [H5] residual evidence-producing read views now export too: Jobs run/failure
// history, Governance -> Drift, and the Template Rollout fleet-conformance matrix.
ok('jobs view wires its export bar', /wireExportBar\('jobs'/.test(html));
ok('jobs export bar offered in the jobs header', /exportBarHtml\('jobs'\)/.test(html));
ok('governance drift wires its export bar', /wireExportBar\('govDrift'/.test(html));
ok('governance drift export bar offered', /exportBarHtml\('govDrift'\)/.test(html));
ok('fleet conformance wires its export bar', /wireExportBar\('confFleet'/.test(html));
ok('fleet conformance export bar offered', /exportBarHtml\('confFleet'\)/.test(html));

// --- summary ----------------------------------------------------------------
console.log('\n  RESULT: ' + pass + ' pass, ' + fail + ' fail');
process.exit(fail ? 1 : 0);
