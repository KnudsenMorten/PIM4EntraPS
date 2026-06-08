// PIM Activator -- MV3 service worker.
//
// Sole purpose: resolve a customer tenant's PIM Activator app-reg clientId
// from the user's email domain, with zero OAuth prompts, zero per-tenant
// app-registration plumbing on our side, and zero per-machine deploy.
//
// Architecture (v1.5.11+ -- well-known URI discovery):
//   1. popup sends { cmd: 'start-discovery', email } via chrome.runtime.sendMessage
//   2. service worker extracts the email's domain (e.g. nunagreen.gl)
//   3. service worker GETs https://<domain>/.well-known/pim-activator.json
//      (and a small fallback list of common subdomains)
//   4. on 200 + valid JSON, writes { tenantId, clientId, ...optional defaults }
//      to chrome.storage.local under 'discoveryResult' so the popup can pre-fill
//      the wizard fields
//   5. on any failure (404 / network / invalid JSON / unrecognized shape),
//      writes 'discoveryError' so the popup falls back to manual entry
//
// What's in the JSON (admin publishes once on the corporate web domain):
//   {
//     "tenantId":             "00000000-0000-0000-0000-000000000000",
//     "clientId":             "00000000-0000-0000-0000-000000000000",
//     "defaultJustification": "Change in infrastructure",       // optional
//     "defaultDurationHours": 8,                                 // optional
//     "groupNameFilter":      "^PIM-",                           // optional regex; PIM-* only
//     "entraGroupRegex":      "Entra",                           // optional regex
//     "azureGroupRegex":      "(AzRes|Azure)"                    // optional regex
//   }
//
// Why this is safe to publish on a public URL:
//   - tenantId is already public -- the unauthenticated OIDC discovery
//     endpoint at login.microsoftonline.com/<domain>/.well-known/openid-configuration
//     resolves any email domain to its tenant GUID. Microsoft, not us, chose
//     to make this discoverable.
//   - clientId is public by OAuth2 spec -- it appears in every authorize URL
//     query string the browser sends, in browser dev-tools network panels,
//     and in every captured HAR file. It is NOT a credential. The actual
//     credential is the user's auth (PKCE / WAM / cookies), which is not
//     in the JSON.

const WELL_KNOWN_PATH = '/.well-known/pim-activator.json'

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.cmd === 'start-discovery') {
    const email = (msg.email || '').trim()
    chrome.storage.local.remove(['discoveryResult', 'discoveryError'], () => {
      chrome.storage.local.set({ discoveryStatus: 'Resolving config from your corporate domain...' }, () => {
        runDiscovery(email)
          .then(result => chrome.storage.local.set({ discoveryResult: result, discoveryStatus: 'Done' }))
          .catch(err   => chrome.storage.local.set({ discoveryError:  err.message || String(err), discoveryStatus: 'Failed' }))
      })
    })
    sendResponse({ started: true })
    return true
  }
})

async function runDiscovery(email) {
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    throw new Error('Enter your work email so we can resolve your corporate domain.')
  }
  const domain = email.split('@')[1].toLowerCase()

  // Try the email's domain first, then a small set of common variants
  // (some customers publish under www., some under the bare domain). The
  // first 2xx with a parseable {tenantId, clientId} wins.
  const candidates = [
    `https://${domain}${WELL_KNOWN_PATH}`,
    `https://www.${domain}${WELL_KNOWN_PATH}`,
  ]

  const errors = []
  for (const url of candidates) {
    await setStatus(`Fetching ${url}...`)
    try {
      const resp = await fetch(url, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
        // Don't send cookies -- this endpoint is intentionally public,
        // and credentials: 'include' would trip CORS on most setups.
        credentials: 'omit',
        cache: 'no-store',
      })
      if (!resp.ok) {
        errors.push(`${url}: HTTP ${resp.status}`)
        continue
      }
      const body = await resp.json()
      const tenantId = String(body.tenantId || '').trim()
      const clientId = String(body.clientId || '').trim()
      if (!isGuid(tenantId)) { errors.push(`${url}: tenantId missing or not a GUID`); continue }
      if (!isGuid(clientId)) { errors.push(`${url}: clientId missing or not a GUID`); continue }
      // Defaults are optional; pass through whatever the JSON has and let
      // the popup decide if it wants to honor them.
      return {
        source: url,
        tenantId,
        clientId,
        defaultJustification: typeof body.defaultJustification === 'string' ? body.defaultJustification : null,
        defaultDurationHours: typeof body.defaultDurationHours === 'number' ? body.defaultDurationHours : null,
        groupNameFilter:      typeof body.groupNameFilter      === 'string' ? body.groupNameFilter      : null,
        entraGroupRegex:      typeof body.entraGroupRegex      === 'string' ? body.entraGroupRegex      : null,
        azureGroupRegex:      typeof body.azureGroupRegex      === 'string' ? body.azureGroupRegex      : null,
      }
    } catch (e) {
      errors.push(`${url}: ${e.message || String(e)}`)
    }
  }

  throw new Error(
    `No /.well-known/pim-activator.json found on ${domain} or www.${domain}. ` +
    `Have your admin publish a JSON file at ${candidates[0]} with at least ` +
    `tenantId + clientId GUIDs. Details: ${errors.join(' | ')}`
  )
}

function isGuid(s) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s || '')
}

function setStatus(s) {
  return new Promise(r => chrome.storage.local.set({ discoveryStatus: s }, r))
}
