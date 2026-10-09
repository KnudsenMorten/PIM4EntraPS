// PIM Activator -- scrub text before it leaves the device in a "Report bug" request
// (no DOM, no chrome.* APIs -- unit-testable under Node like popup-config.js).
//
// SEC-41 (2026-09-18): the "Report bug" link used to open a public issue
// pre-filled with the customer's TENANT ID and the raw error text -- which carries
// object ids, UPNs, e-mail addresses and domain names straight from Graph / Entra.
// Now the report text is (1) built WITHOUT the tenant id, (2) passed through
// redactForPublicReport(), and (3) shown to the user for review before anything
// is copied -- they send exactly what they saw. Since 1.6.137 it is copied for a
// request on the PIM Manager support portal instead of a public issue.

const RULES = [
  // Bearer / JWT-shaped tokens first (they contain dots that the domain rule would eat).
  [/\bBearer\s+[A-Za-z0-9._~+\/=-]+/gi, 'Bearer <token>'],
  [/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(?:\.[A-Za-z0-9_-]*)?/g, '<token>'],
  // GUIDs: tenant / object / subscription / correlation ids.
  [/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<id>'],
  // E-mail addresses and UPNs.
  [/\b[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '<upn>'],
  // Tenant domains (x.onmicrosoft.com and friends) that survive without an '@'.
  [/\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.onmicrosoft\.(?:com|us|de|cn)\b/gi, '<tenant-domain>'],
  // Azure resource paths keep their shape but lose their names.
  [/(\/(?:resourceGroups|providers\/[^/\s]+\/[^/\s]+|managementGroups|administrativeUnits|groups|users)\/)[^/\s'"?&]+/gi, '$1<name>'],
  // Entra trace / correlation lines.
  [/\b(Trace ID|Correlation ID|Timestamp):\s*[^\s,;]+/gi, '$1: <redacted>'],
]

export function redactForPublicReport(text) {
  let s = String(text == null ? '' : text)
  for (const [re, rep] of RULES) s = s.replace(re, rep)
  return s
}

// The issue body the user reviews. NO tenant id, by construction.
export function buildPublicReportBody({ phase, version, error }) {
  return (
    'What happened: your PIM assignments did not load.\n\n' +
    'Diagnostic (identifiers replaced with placeholders -- review before submitting):\n' +
    `phase=${redactForPublicReport(phase)}; v=${redactForPublicReport(version)}; error=${redactForPublicReport(error)}\n\n` +
    'Steps to reproduce / notes:\n'
  )
}
