// PIM Activator -- MV3 service worker.
//
// Sole purpose right now: run the first-run discovery sign-in flow OUTSIDE
// the popup so it survives popup death. Browser extension popups close (and
// kill their JS context) the moment they lose focus, which happens the
// instant chrome.identity.launchWebAuthFlow opens the Microsoft sign-in
// window. The callback then fires into a dead popup and the user sees
// "Sign-in did not complete".
//
// Architecture:
//   1. popup sends { cmd: 'start-discovery' } via chrome.runtime.sendMessage
//   2. service worker runs launchWebAuthFlow + the PKCE exchange + the
//      Graph call to enumerate "PIM Activator" app registrations
//   3. service worker writes the result to chrome.storage.local under
//      'discoveryResult' (success) or 'discoveryError' (failure)
//   4. popup polls chrome.storage.local every ~1.5s -- if it died and the
//      user reopens, the next poll finds the result and finishes the wizard

// Microsoft Graph Command Line Tools -- a Microsoft-owned multi-tenant FOCI
// client that already exists as a service principal in EVERY Entra tenant
// by default. We use it ONLY for the bootstrap discovery sign-in (just
// enough Application.Read.All / User.Read to query the tenant for any SPN
// whose displayName contains "PIM Activator"). After discovery, the user
// saves the discovered tenant-local PIM Activator clientId and every
// subsequent runtime sign-in uses THAT clientId (with the full scope set
// the customer's per-tenant app reg has admin-consented).
//
// Why this is necessary: bundling a single-tenant app-reg clientId from
// any one tenant returns AADSTS700016 "Application not found in directory"
// the moment a customer in some other tenant tries to sign in -- the
// app reg simply doesn't exist there. The Microsoft Graph CLI app does,
// in every tenant.
const BOOTSTRAP_CLIENT_ID = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
const REDIRECT_URI        = chrome.identity.getRedirectURL()

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.cmd === 'start-discovery') {
    const email = (msg.email || '').trim()
    // Clear any prior result so the popup's poll can distinguish "old"
    // from "this run". Status is updated as the flow progresses so the
    // popup can render a live progress line.
    chrome.storage.local.remove(['discoveryResult', 'discoveryError'], () => {
      chrome.storage.local.set({ discoveryStatus: 'Resolving tenant from email...' }, () => {
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
    throw new Error('Enter your work email so we can resolve your tenant.')
  }

  // 1) Resolve email -> tenant GUID via Microsoft's OpenID Connect discovery
  //    endpoint. The legacy /common/userrealm endpoint returns the domain
  //    name but NOT the tenant GUID (bit me in v1.1.6/1.1.7 -- silently
  //    fell through to /common-style auth and triggered AADSTS50194 for the
  //    single-tenant PIM Activator app reg). The OIDC discovery URL accepts
  //    a domain (e.g. "contoso.com") and returns an `issuer` field of the
  //    shape https://login.microsoftonline.com/{tenant-guid}/v2.0 -- which
  //    is the GUID we need for the tenant-specific authorize URL below.
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
  // PKCE -- same shape as the existing main-flow sign-in.
  const verifier  = base64UrlEncode(crypto.getRandomValues(new Uint8Array(64)))
  const challenge = base64UrlEncode(new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))))

  // Tenant-specific authorize endpoint -- /{tenantId} not /common, because
  // the bootstrap clientId here is the per-tenant PIM Activator app reg
  // (single-tenant). login_hint=email skips the account picker for the
  // user who just typed their email.
  const authUrl = new URL(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`)
  authUrl.searchParams.set('client_id',     BOOTSTRAP_CLIENT_ID)
  authUrl.searchParams.set('response_type', 'code')
  authUrl.searchParams.set('redirect_uri',  REDIRECT_URI)
  authUrl.searchParams.set('response_mode', 'query')
  // Discovery-only scopes -- just enough to enumerate SPNs in the tenant.
  // The runtime sign-in (popup.js, after the user saves the discovered
  // clientId) will request the full PrivilegedAccess / Group / RoleManagement
  // scope set against the customer's PIM Activator app reg, which is where
  // those scopes are actually consented.
  authUrl.searchParams.set('scope', [
    'https://graph.microsoft.com/User.Read',
    'https://graph.microsoft.com/Application.Read.All',
    'openid', 'profile', 'offline_access',
  ].join(' '))
  // NO prompt=select_account: the account picker is hosted on /common/SAS,
  // which makes Entra evaluate the request against /common rules -- and
  // single-tenant apps fail there with AADSTS50194. login_hint=email is
  // enough to pre-pick the account; the user does NOT need a picker
  // because they already typed which account they want.
  authUrl.searchParams.set('login_hint',    email)
  authUrl.searchParams.set('code_challenge', challenge)
  authUrl.searchParams.set('code_challenge_method', 'S256')

  await setStatus('Sign in in the new browser window...')

  const redirected = await new Promise((resolve, reject) => {
    chrome.identity.launchWebAuthFlow(
      { url: authUrl.toString(), interactive: true },
      (responseUrl) => {
        if (chrome.runtime.lastError || !responseUrl) {
          reject(new Error(chrome.runtime.lastError?.message || 'sign-in cancelled'))
          return
        }
        resolve(responseUrl)
      })
  })

  const url  = new URL(redirected)
  const code = url.searchParams.get('code')
  const err  = url.searchParams.get('error_description') || url.searchParams.get('error')
  if (!code) throw new Error(err || 'no auth code returned')

  await setStatus('Exchanging code for token...')

  const tResp = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:    new URLSearchParams({
      grant_type:    'authorization_code',
      client_id:     BOOTSTRAP_CLIENT_ID,
      code,
      redirect_uri:  REDIRECT_URI,
      code_verifier: verifier,
    }),
  })
  const token = await tResp.json()
  if (!tResp.ok || !token.access_token) {
    throw new Error(token.error_description || token.error || 'token exchange failed')
  }

  // Extract tenant id from id_token (unverified -- we only need claims for UX).
  let tid = null
  try {
    const payload = JSON.parse(atob(token.id_token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')))
    tid = payload.tid || null
  } catch { /* fall through */ }
  if (!tid) throw new Error('id_token missing tenant id claim.')

  await setStatus('Looking up service principals whose displayName contains "PIM Activator"...')

  // Search service principals (not applications) by displayName SUBSTRING --
  // so the customer can rename the SPN to e.g. "ACME PIM Activator", "PIM
  // Activator (prod)", "Contoso-PIM-Activator-Workload" and the discovery
  // still finds it. Graph requires the advanced query parameters for
  // $search on directory objects: `ConsistencyLevel: eventual` header +
  // `$count=true`. The $search syntax `"displayName:PIM Activator"`
  // matches any SPN whose displayName CONTAINS that string (case-insensitive,
  // word-boundary-aware tokenizer Graph applies to displayName).
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
  // Defensive: only keep SPNs whose displayName actually contains the phrase
  // (the Graph tokenizer is generous and can occasionally surface near-matches
  // when the query is broad).
  const needle = 'pim activator'
  const apps = (appsBody.value || [])
    .filter(a => a && a.appId && (a.displayName || '').toLowerCase().includes(needle))

  // NOTE: we intentionally do NOT persist this bootstrap refresh/access
  // token to the runtime keys (refreshToken / accessToken / account). The
  // bootstrap signed in against the Microsoft Graph CLI client and only
  // holds User.Read + Application.Read.All -- nowhere near enough for the
  // runtime activation calls (PrivilegedAccess.ReadWrite.AzureADGroup, etc).
  // After the user saves the discovered customer-tenant clientId, popup.js
  // reloads and the next sign-in fires against THAT clientId with the full
  // runtime scope set already admin-consented on the customer's PIM
  // Activator app reg.

  return { tenantId: tid, apps }
}

function setStatus(s) {
  return new Promise(r => chrome.storage.local.set({ discoveryStatus: s }, r))
}

function base64UrlEncode(bytes) {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')
}
