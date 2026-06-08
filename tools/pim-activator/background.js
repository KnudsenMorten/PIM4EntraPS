// PIM Activator -- MV3 service worker.
//
// Sole purpose: run the first-run discovery sign-in flow OUTSIDE the popup
// so it survives popup death (extension popups close the moment they lose
// focus; any callback firing into a dead popup would otherwise vanish).
//
// Architecture (v1.5.10+ -- device-code flow, replaces launchWebAuthFlow):
//   1. popup sends { cmd: 'start-discovery', email } via chrome.runtime.sendMessage
//   2. service worker resolves tenant GUID via OIDC discovery on email's domain
//   3. service worker requests a device code from Entra (no redirect URI
//      registration required on the bootstrap app -- this is why we can
//      use Microsoft Graph CLI as bootstrap; launchWebAuthFlow required a
//      pre-registered chromiumapp.org redirect URI that Microsoft owns
//      and we can't add)
//   4. service worker writes { userCode, verificationUri, expiresAt } to
//      chrome.storage.local under 'discoveryDeviceCode' so the popup can
//      render the "Go to microsoft.com/devicelogin and enter ABC-XYZ" UX
//   5. service worker polls the token endpoint; on success queries
//      /servicePrincipals?$search="displayName:PIM Activator" and writes
//      { tenantId, apps } to chrome.storage.local under 'discoveryResult'
//   6. popup polls chrome.storage.local every ~1.5s -- if it died and the
//      user reopens, the next poll finds the result and finishes the wizard

// Microsoft Graph Command Line Tools -- a Microsoft-owned multi-tenant FOCI
// client that already exists as a service principal in EVERY Entra tenant
// by default. We use it ONLY for the bootstrap discovery sign-in (just
// enough Application.Read.All / User.Read to query the tenant for any SPN
// whose displayName contains "PIM Activator"). After discovery, the user
// saves the discovered tenant-local PIM Activator clientId and every
// subsequent runtime sign-in uses THAT clientId via launchWebAuthFlow
// (the per-tenant PIM Activator app DOES have chromiumapp.org registered
// as a redirect URI -- Deploy-PimActivatorBackend.ps1 adds it).
//
// Why device code (vs launchWebAuthFlow): MS Graph CLI is a multi-tenant
// app Microsoft owns; we cannot add chrome-extension chromiumapp.org URIs
// to its registered redirect URIs, so launchWebAuthFlow returns AADSTS50011
// "redirect URI does not match". Device code doesn't use a redirect URI
// at all -- the user authorizes via a separate browser tab and we poll
// for the token.
const BOOTSTRAP_CLIENT_ID = '14d82eec-204b-4c2f-b7e8-296a70dab67e'

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.cmd === 'start-discovery') {
    const email = (msg.email || '').trim()
    // Clear any prior result so the popup's poll can distinguish "old"
    // from "this run".
    chrome.storage.local.remove(['discoveryResult', 'discoveryError', 'discoveryDeviceCode'], () => {
      chrome.storage.local.set({ discoveryStatus: 'Resolving tenant from email...' }, () => {
        runDiscovery(email)
          .then(result => chrome.storage.local.set({ discoveryResult: result, discoveryStatus: 'Done', discoveryDeviceCode: null }))
          .catch(err   => chrome.storage.local.set({ discoveryError:  err.message || String(err), discoveryStatus: 'Failed', discoveryDeviceCode: null }))
      })
    })
    sendResponse({ started: true })
    return true
  }
})

async function runDiscovery(email) {
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    throw new Error('Enter your work email so we can resolve your tenant.')
  }

  // 1) Resolve email -> tenant GUID via Microsoft's OpenID Connect discovery
  //    endpoint. Accepts a domain and returns an `issuer` field of the shape
  //    https://login.microsoftonline.com/{tenant-guid}/v2.0 -- the GUID is
  //    what the tenant-specific token + devicecode endpoints need.
  await setStatus('Resolving tenant from email...')
  const domain = email.split('@')[1]
  const oidcUrl = `https://login.microsoftonline.com/${encodeURIComponent(domain)}/v2.0/.well-known/openid-configuration`
  const oidcResp = await fetch(oidcUrl, { headers: { 'Accept': 'application/json' } })
  if (!oidcResp.ok) {
    throw new Error(`Could not resolve tenant for ${domain} (HTTP ${oidcResp.status}). Is this a work / school domain?`)
  }
  const oidc = await oidcResp.json()
  const issuer = oidc.issuer || ''
  const guidMatch = issuer.match(/\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\//i)
  const tenantId = guidMatch && guidMatch[1]
  if (!tenantId) {
    throw new Error(`Tenant GUID not in issuer URL for ${domain}: ${issuer}`)
  }

  // 2) Request a device code from the tenant-specific devicecode endpoint.
  //    Scope: only what we need to enumerate SPNs (User.Read +
  //    Application.Read.All + openid + profile). The runtime sign-in (popup.js
  //    after the user saves the discovered clientId) will request the full
  //    PrivilegedAccess / Group / RoleManagement scope set against the
  //    customer's PIM Activator app reg, which is where those scopes are
  //    actually consented.
  await setStatus('Requesting device code from Entra...')
  const dcResp = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/devicecode`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:    new URLSearchParams({
      client_id: BOOTSTRAP_CLIENT_ID,
      scope:     [
        'https://graph.microsoft.com/User.Read',
        'https://graph.microsoft.com/Application.Read.All',
        'openid', 'profile',
      ].join(' '),
    }),
  })
  const dc = await dcResp.json()
  if (!dcResp.ok || !dc.device_code) {
    throw new Error(dc.error_description || dc.error || `device code request failed (HTTP ${dcResp.status})`)
  }

  // 3) Show user the device code + verification URL via chrome.storage.local
  //    so the popup can render it. Popup polls this key on every tick.
  const expiresAt = Date.now() + ((Number(dc.expires_in) || 900) * 1000)
  await new Promise(r => chrome.storage.local.set({
    discoveryDeviceCode: {
      userCode:         dc.user_code,
      verificationUri:  dc.verification_uri,
      verificationUriComplete: dc.verification_uri_complete || null,
      expiresAt,
      message:          dc.message || `Go to ${dc.verification_uri} and enter code ${dc.user_code}`,
    },
    discoveryStatus: `Go to ${dc.verification_uri} and enter code ${dc.user_code}`,
  }, r))

  // 4) Poll the token endpoint with the device code. Entra returns
  //    authorization_pending while user hasn't completed; we retry every
  //    `interval` seconds (server-suggested, default 5). Slow_down response
  //    bumps interval by 5s per RFC8628.
  const intervalMs = (Number(dc.interval) || 5) * 1000
  let pollInterval = intervalMs
  let token = null
  while (Date.now() < expiresAt) {
    await sleep(pollInterval)
    const tResp = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:    new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id:  BOOTSTRAP_CLIENT_ID,
        device_code: dc.device_code,
      }),
    })
    const tBody = await tResp.json()
    if (tResp.ok && tBody.access_token) {
      token = tBody
      break
    }
    // Expected pending / slow-down / declined error codes per RFC8628.
    if (tBody.error === 'authorization_pending') {
      continue
    }
    if (tBody.error === 'slow_down') {
      pollInterval += 5000
      continue
    }
    if (tBody.error === 'expired_token' || tBody.error === 'authorization_declined' || tBody.error === 'bad_verification_code') {
      throw new Error(tBody.error_description || tBody.error)
    }
    // Any other error -- surface it.
    throw new Error(tBody.error_description || tBody.error || `token poll failed (HTTP ${tResp.status})`)
  }
  if (!token) {
    throw new Error('Device-code sign-in timed out -- click "Sign in to auto-discover" to try again.')
  }

  // Clear the device code key now that sign-in completed.
  await new Promise(r => chrome.storage.local.remove(['discoveryDeviceCode'], r))

  // Extract tenant id from id_token (unverified -- we only need claims for UX).
  let tid = tenantId
  try {
    if (token.id_token) {
      const payload = JSON.parse(atob(token.id_token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')))
      tid = payload.tid || tenantId
    }
  } catch { /* fall through with the OIDC-resolved tenantId */ }

  await setStatus('Looking up service principals whose displayName contains "PIM Activator"...')

  // Search service principals (not applications) by displayName SUBSTRING --
  // so the customer can rename the SPN to e.g. "ACME PIM Activator", "PIM
  // Activator (prod)", "Contoso-PIM-Activator-Workload" and discovery still
  // finds it. Graph requires advanced query parameters for $search on
  // directory objects: ConsistencyLevel: eventual header + $count=true.
  const searchUrl =
    'https://graph.microsoft.com/v1.0/servicePrincipals' +
    '?$search=' + encodeURIComponent('"displayName:PIM Activator"') +
    '&$select=appId,displayName,id' +
    '&$count=true' +
    '&$top=25'
  const appsResp = await fetch(searchUrl, {
    headers: {
      Authorization:    'Bearer ' + token.access_token,
      ConsistencyLevel: 'eventual',
    },
  })
  const appsBody = await appsResp.json()
  if (!appsResp.ok) {
    const msg = appsBody.error?.message || appsBody.error || 'SPN lookup failed'
    throw new Error(`Tenant detected (${tid}). Service-principal lookup failed: ${msg}. Paste the client id manually below.`)
  }
  // Defensive: only keep SPNs whose displayName actually contains the phrase.
  const needle = 'pim activator'
  const apps = (appsBody.value || [])
    .filter(a => a && a.appId && (a.displayName || '').toLowerCase().includes(needle))

  // NOTE: we intentionally do NOT persist this bootstrap refresh/access
  // token to the runtime keys. The bootstrap signed in against the Microsoft
  // Graph CLI client and only holds User.Read + Application.Read.All --
  // nowhere near enough for the runtime activation calls
  // (PrivilegedAccess.ReadWrite.AzureADGroup, etc). After the user saves
  // the discovered customer-tenant clientId, popup.js reloads and the next
  // sign-in fires against THAT clientId via launchWebAuthFlow with the
  // full runtime scope set.

  return { tenantId: tid, apps }
}

function setStatus(s) {
  return new Promise(r => chrome.storage.local.set({ discoveryStatus: s }, r))
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms))
}
