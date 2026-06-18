#!/usr/bin/env node
/*
 * Regression gate for the v1.6.31-1.6.34 class of bug:
 *   `BULK_ACTIVATE_CONFIRM_THRESHOLD_DEFAULT` was EXPORTED by popup-config.js but
 *   never IMPORTED into popup.js, so a bare reference threw `ReferenceError:
 *   ... is not defined` at runtime and crashed the popup boot on every machine.
 *   `node --check` (syntax only) cannot catch this; this test does.
 *
 * What it checks: every UPPER_SNAKE_CASE identifier *used* in popup.js (after
 * stripping comments + string/template literals) must be either declared in
 * popup.js or imported by it. A used-but-undeclared constant fails the build.
 *
 * Pure Node, no deps. Exit 0 = clean, exit 1 = at least one undefined constant.
 */
const fs = require('fs')
const path = require('path')

const file = path.join(__dirname, '..', 'popup.js')
let src = fs.readFileSync(file, 'utf8')

// 1) collect imported names BEFORE stripping (imports are real refs)
const imported = new Set()
for (const m of src.matchAll(/import\s*\{([^}]*)\}\s*from/g)) {
  for (const raw of m[1].split(',')) {
    const name = raw.trim().split(/\s+as\s+/).pop().trim()
    if (name) imported.add(name)
  }
}

// 2) strip block comments, line comments, then string/template literals so we
//    only scan actual code tokens (avoids matching 'POST'/'GET'/etc. in strings).
// Strip ONLY comments (block then line). We deliberately do NOT strip string /
// template / regex literals: the "used" detector below requires an UNDERSCORE
// (CONST_CASE), so it never matches ordinary string literals like 'POST' / URLs
// anyway, and trying to strip strings/regex with a regex is unsafe -- a regex
// literal that contains a quote (the escapeHtml `/[&<>"']/g`) makes a naive
// string-stripper treat that quote as a delimiter and swallow code across many
// lines, which false-positived the gate on valid JS (reporting real const
// declarations as "undeclared", 2026-06-18). Comment-stripping has no such
// hazard. (A CONST_CASE token embedded in a string literal would be a rare false
// positive; none exist in popup.js and the declared-set still absorbs them.)
let code = src
  .replace(/\/\*[\s\S]*?\*\//g, ' ')
  .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ')   // // comments (not URLs like http://)

// 3) collect declared identifiers (const/let/var/function/class), anywhere.
const declared = new Set()
for (const m of code.matchAll(/\b(?:const|let|var|function|class)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g)) {
  declared.add(m[1])
}
// destructured declarations: const { A, B } = ... / const [A,B] = ...
for (const m of code.matchAll(/\b(?:const|let|var)\s*[\{\[]([^}\]]*)[\}\]]\s*=/g)) {
  for (const raw of m[1].split(',')) {
    const name = raw.trim().split(/[:=\s]/)[0].trim()
    if (name) declared.add(name)
  }
}

// 4) UPPER_SNAKE_CASE constants that are USED. >=4 chars, must contain an
//    underscore OR be all-caps length>=5, to avoid acronyms like "GET".
const KNOWN_GLOBALS = new Set(['NaN', 'JSON', 'Math', 'URL', 'Promise', 'Set', 'Map', 'Date', 'Array', 'Object'])
const used = new Set()
for (const m of code.matchAll(/\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b/g)) {
  used.add(m[1])   // requires at least one underscore -> CONST_CASE
}

const missing = []
for (const name of used) {
  if (imported.has(name) || declared.has(name) || KNOWN_GLOBALS.has(name)) continue
  missing.push(name)
}

if (missing.length) {
  console.error('FAIL: popup.js references CONST_CASE identifier(s) that are neither declared nor imported:')
  for (const n of missing) {
    const line = src.split('\n').findIndex(l => new RegExp('\\b' + n + '\\b').test(l)) + 1
    console.error('  - ' + n + '  (first seen ~popup.js:' + line + ')')
  }
  console.error('Fix: import it from popup-config.js / popup-net.js, or define it. (This is the v1.6.31-34 ReferenceError class.)')
  process.exit(1)
}
console.log('OK: all ' + used.size + ' CONST_CASE identifiers used in popup.js are declared or imported.')
process.exit(0)
