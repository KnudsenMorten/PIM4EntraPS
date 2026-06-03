// PIM Activator -- popup logic
//
// Flow:
//   1. chrome.identity.launchWebAuthFlow + PKCE sign-in (delegated
//      PrivilegedAccess.ReadWrite.AzureADGroup + Group.Read.All + User.Read).
//      No third-party libraries -- vanilla JS + Web Crypto for the SHA-256.
//   2. GET eligibility schedule instances for the current user via filterByCurrentUser
//      (one tenant-side call, no per-group iteration needed for the SELF case).
//   3. Hydrate displayName via /groups/{id}?$select=displayName
//      (single $batch call, 20 ids per sub-request).
//   4. Multi-select + bulk POST assignmentScheduleRequests with the same
//      justification + duration.
//
// Persisted in chrome.storage.local:
//   - refreshToken         (Entra-issued, used for silent reauth)
//   - accessToken          (last access token; kept only until it expires)
//   - accessTokenExpiry    (epoch ms; we refresh 60s before this)
//   - account              ({ username, localAccountId, tenantId })
//   - lastJustification    (per user)
//   - lastDurationHours    (per user)
//   - selectedIds          (group ids the user typically activates -- pre-checked on load)

// Config resolution order:
//   1. chrome.storage.managed (Intune / Group Policy push -- preferred for enterprise rollout)
//   2. window.PIM_CONFIG from config.js (developer-mode / manual install)
async function loadConfig() {
  const managed = await new Promise(r => chrome.storage.managed.get(null, x => r(x || {})))
  const local   = window.PIM_CONFIG || {}
  // Managed wins per-key (so an admin can push only tenant+client and let users keep local defaults).
  const merged = { ...local, ...Object.fromEntries(Object.entries(managed).filter(([_, v]) => v != null && v !== '')) }
  return merged
}

const cfg = await loadConfig()
if (!cfg.tenantId || String(cfg.tenantId).startsWith('00000000') || !cfg.clientId || String(cfg.clientId).startsWith('00000000')) {
  document.getElementById('status-bar').textContent = 'Not configured. Admin must set tenantId + clientId via policy.'
  document.getElementById('status-bar').classList.add('err')
  throw new Error('config not set')
}

const SCOPES = [
  'https://graph.microsoft.com/PrivilegedAccess.ReadWrite.AzureADGroup',
  'https://graph.microsoft.com/Group.Read.All',
  'https://graph.microsoft.com/User.Read',
  // RoleManagement.Read.Directory powers the "My Access" tab's resolution of
  // Entra role assignments attached to the active PIM-for-Groups memberships
  // (via roleManagement/directory/roleAssignments + roleDefinitions). Admin
  // consent required -- re-run Deploy-PimActivatorBackend.ps1 -GrantConsent
  // after upgrading the extension.
  'https://graph.microsoft.com/RoleManagement.Read.Directory',
  // AdministrativeUnit.Read.All resolves AU displayNames (otherwise the My
  // Access tab shows "N Administrative Units" without names because the role
  // assignment exposes the AU id but reading the AU object requires this
  // separate scope). Admin consent required.
  'https://graph.microsoft.com/AdministrativeUnit.Read.All',
  // offline_access is required to receive a refresh_token from Entra v2.
  // The refresh_token is then used to mint a SEPARATE Azure Resource Manager
  // token (different audience: management.azure.com) for the Azure RBAC
  // queries on the My Access tab. Without offline_access we'd have to do
  // two interactive sign-ins to get both Graph + ARM tokens.
  'offline_access',
  // openid is required to receive an id_token (we decode it for account info).
  'openid',
  'profile'
]

const AUTHORITY    = `https://login.microsoftonline.com/${cfg.tenantId}`
const AUTH_URL     = `${AUTHORITY}/oauth2/v2.0/authorize`
const TOKEN_URL    = `${AUTHORITY}/oauth2/v2.0/token`
const REDIRECT_URI = chrome.identity.getRedirectURL()  // https://<extId>.chromiumapp.org/

// ---------- UI elements ----------
const $ = (id) => document.getElementById(id)
const els = {
  signIn: $('sign-in'), signOut: $('sign-out'),
  me: $('me'), status: $('status-bar'),
  list: $('list'), footer: $('footer'), toolbar: $('toolbar'),
  search: $('search'), selectAll: $('select-all'), selectNone: $('select-none'), refresh: $('refresh'),
  just: $('justification'), dur: $('duration'), count: $('count'), activate: $('activate'),
  // Tabs
  tabs: $('tabs'),
  tabBtnActivate: $('tab-btn-activate'),
  tabBtnMyAccess: $('tab-btn-myaccess'),
  badgeActivate: $('badge-activate'),
  badgeMyAccess: $('badge-myaccess'),
  panelActivate: $('panel-activate'),
  panelMyAccess: $('panel-myaccess'),
  // My Access
  myAccessStatus: $('myaccess-status'),
  myAccessList: $('myaccess-list'),
  myAccessRefresh: $('myaccess-refresh'),
  myAccessAutofix: $('myaccess-autofix'),
  myAccessScopeStatus: $('myaccess-scope-status')
}

let currentAccount = null
let eligibleRows = []        // [{ id (instanceId), groupId, displayName, accessId, endDateTime }]

// My Access tab cache
const MYACCESS_CACHE_MS = 30 * 1000
let myAccessCache = null      // { ts: epochMs, rows: [...] }
let myAccessLoading = false
let myAccessLoadedOnce = false

// ---------- Persisted state ----------
async function getStored(keys) { return new Promise(r => chrome.storage.local.get(keys, r)) }
async function setStored(obj)  { return new Promise(r => chrome.storage.local.set(obj, r)) }
async function clearStored(keys) { return new Promise(r => chrome.storage.local.remove(keys, r)) }

// ---------- Token self-heal ----------
// Required short-name Graph scopes (the `scp` claim contains short names,
// not the full https://graph.microsoft.com/... URIs). Keep in sync with
// SCOPES above + Deploy-PimActivatorBackend.ps1.
const REQUIRED_GRAPH_SCOPES = [
  'PrivilegedAccess.ReadWrite.AzureADGroup',
  'Group.Read.All',
  'User.Read',
  'RoleManagement.Read.Directory',
  'AdministrativeUnit.Read.All'
]

// decodeJwtPayload: parse an access token, return its payload object (or null).
// base64UrlDecode already returns a UTF-8-decoded string; wrapping the result
// in TextDecoder().decode() throws ("provided value cannot be converted to a
// sequence of bytes") which the try/catch silently swallows, making every
// token look like it has zero scopes -> infinite self-heal loop.
function decodeJwtPayload(token) {
  try {
    const parts = String(token || '').split('.')
    if (parts.length < 2) return null
    return JSON.parse(base64UrlDecode(parts[1]))
  } catch { return null }
}

// getTokenScopes: returns the array of short-name scopes from the JWT `scp` claim.
function getTokenScopes(token) {
  const p = decodeJwtPayload(token)
  if (!p || typeof p.scp !== 'string') return []
  return p.scp.split(/\s+/).filter(Boolean)
}

// missingScopes: returns required scopes not present in the token. Empty = healthy.
function missingScopes(token) {
  const have = new Set(getTokenScopes(token))
  return REQUIRED_GRAPH_SCOPES.filter(s => !have.has(s))
}

// triggerInteractiveReauth: wipe cached tokens + force a fresh interactive
// sign-in. Use this when the existing token is missing scopes (admin re-
// consented new perms), is rejected by Graph (401/403), or when the user
// switched browsers / tenants.
//
// Shows a visible banner explaining what's happening + why -- the popup
// reloads after a short delay so the user has time to read it.
async function triggerInteractiveReauth(reason) {
  console.log('[PIM Activator] triggerInteractiveReauth:', reason)
  // Show a full-popup banner so the user understands why the page is reloading
  // + why they'll be prompted to sign in again.
  const overlay = document.createElement('div')
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(13,17,23,0.95);color:#e6edf3;padding:20px 22px;display:flex;flex-direction:column;justify-content:center;align-items:flex-start;font-family:inherit;font-size:13px;line-height:1.5;'
  overlay.innerHTML = `
    <div style="color:#58a6ff;font-weight:600;font-size:14px;margin-bottom:10px;">Self-healing your session...</div>
    <div style="color:#e6edf3;margin-bottom:10px;">${escapeHtmlSafe(reason)}</div>
    <div style="color:#7d8590;margin-bottom:6px;">Your access token doesn't match the currently-granted permissions. This usually happens after:</div>
    <ul style="color:#7d8590;margin:0 0 12px 18px;padding:0;">
      <li>Admin re-consented new scopes (e.g. RoleManagement.Read.Directory)</li>
      <li>You switched browser (Edge -> Chrome or vice versa)</li>
      <li>Token expired or was revoked</li>
    </ul>
    <div style="color:#3fb950;">Refreshing in a moment -- you'll be prompted to sign in once more. After that, everything works.</div>
  `
  document.body.appendChild(overlay)
  // Wipe Graph + ARM tokens. Setting forceInteractive: true tells the next
  // popup-load to AUTOMATICALLY launch interactiveAuth (consent prompt) instead
  // of leaving the user staring at a Sign in button. Without this flag, user
  // clicks Re-sign in -> overlay -> reload -> Sign in screen -> they have to
  // click Sign in again to actually trigger the OAuth + consent flow. Two
  // clicks = bad UX, especially for an action labelled "Re-sign in".
  await clearStored(['refreshToken', 'accessToken', 'accessTokenExpiry', 'account', 'armAccessToken', 'armAccessTokenExpiry'])
  await setStored({ forceInteractive: true })
  // 2.5s pause so the user can read the banner before the popup reloads.
  await new Promise(r => setTimeout(r, 2500))
  window.location.reload()
}

// Local copy of escapeHtml (defined further down) for use before render() is reachable.
function escapeHtmlSafe(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))
}

// ---------- PKCE helpers ----------
function base64UrlEncode(bytes) {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64UrlDecode(str) {
  // Pad to multiple of 4, swap URL-safe chars back.
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4))
  const b64 = (str + pad).replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return new TextDecoder().decode(bytes)
}

function randomUrlSafe(byteLen) {
  const bytes = new Uint8Array(byteLen)
  crypto.getRandomValues(bytes)
  return base64UrlEncode(bytes)
}

function newGuid() {
  // RFC 4122 v4 from crypto.getRandomValues.
  const b = new Uint8Array(16)
  crypto.getRandomValues(b)
  b[6] = (b[6] & 0x0f) | 0x40
  b[8] = (b[8] & 0x3f) | 0x80
  const hex = [...b].map(x => x.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20,32)}`
}

async function sha256(text) {
  const enc = new TextEncoder().encode(text)
  const buf = await crypto.subtle.digest('SHA-256', enc)
  return new Uint8Array(buf)
}

async function pkcePair() {
  // 43-128 char URL-safe verifier; 64 bytes -> 86 base64url chars (within spec).
  const verifier = randomUrlSafe(64)
  const challenge = base64UrlEncode(await sha256(verifier))
  return { verifier, challenge }
}

function decodeIdToken(idToken) {
  // Header.Payload.Signature -- we only need the payload, and we trust it
  // because Entra issued it directly via our PKCE handshake (not user-supplied).
  const parts = String(idToken || '').split('.')
  if (parts.length < 2) return {}
  try { return JSON.parse(base64UrlDecode(parts[1])) } catch { return {} }
}

function buildAccount(claims) {
  return {
    username:       claims.preferred_username || claims.upn || claims.email || claims.sub || '',
    localAccountId: claims.oid || claims.sub || '',
    tenantId:       claims.tid || cfg.tenantId
  }
}

// ---------- Auth core ----------
async function exchangeToken(form) {
  // form is a URLSearchParams or plain object of token-endpoint parameters.
  const body = form instanceof URLSearchParams ? form : new URLSearchParams(form)
  const r = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
    body: body.toString()
  })
  const text = await r.text()
  let json = null
  try { json = text ? JSON.parse(text) : null } catch {}
  if (!r.ok) {
    const msg = json?.error_description || json?.error || text || r.statusText
    const err = new Error(`token endpoint -> ${r.status}: ${msg}`)
    err.status = r.status
    err.body = json
    err.code = json?.error
    throw err
  }
  return json
}

async function persistTokens(tok) {
  const claims = decodeIdToken(tok.id_token)
  const account = buildAccount(claims)
  // Entra's `expires_in` is seconds; refresh ~60s before to absorb clock skew.
  const expiry = Date.now() + (Number(tok.expires_in || 3600) - 60) * 1000
  await setStored({
    refreshToken:       tok.refresh_token || null,
    accessToken:        tok.access_token,
    accessTokenExpiry:  expiry,
    account
  })
  return { accessToken: tok.access_token, account }
}

async function tryRefresh() {
  const stored = await getStored(['refreshToken', 'accessToken', 'accessTokenExpiry', 'account'])
  if (stored.accessToken && stored.accessTokenExpiry && Date.now() < stored.accessTokenExpiry) {
    return { accessToken: stored.accessToken, account: stored.account || null }
  }
  if (!stored.refreshToken) return null
  try {
    const tok = await exchangeToken({
      client_id:     cfg.clientId,
      grant_type:    'refresh_token',
      refresh_token: stored.refreshToken,
      scope:         SCOPES.join(' '),
      redirect_uri:  REDIRECT_URI
    })
    return await persistTokens(tok)
  } catch (e) {
    // invalid_grant / interaction_required / consent_required -> drop cache, force interactive.
    await clearStored(['refreshToken', 'accessToken', 'accessTokenExpiry'])
    return null
  }
}

async function interactiveAuth(scopes) {
  const { verifier, challenge } = await pkcePair()
  const state = newGuid()
  const nonce = newGuid()

  const params = new URLSearchParams({
    client_id:             cfg.clientId,
    response_type:         'code',
    response_mode:         'query',
    redirect_uri:          REDIRECT_URI,
    scope:                 scopes.join(' '),
    code_challenge:        challenge,
    code_challenge_method: 'S256',
    state,
    nonce,
    prompt:                'select_account'
  })

  const redirected = await new Promise((resolve, reject) => {
    chrome.identity.launchWebAuthFlow(
      { url: `${AUTH_URL}?${params.toString()}`, interactive: true },
      (resp) => {
        if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message))
        if (!resp) return reject(new Error('Sign-in cancelled.'))
        resolve(resp)
      }
    )
  })

  // launchWebAuthFlow returns the full redirect URL (or Entra error appended as query).
  const parsed = new URL(redirected)
  const err = parsed.searchParams.get('error')
  if (err) {
    throw new Error(`${err}: ${parsed.searchParams.get('error_description') || 'sign-in failed'}`)
  }
  const code         = parsed.searchParams.get('code')
  const returnedState = parsed.searchParams.get('state')
  if (!code) throw new Error('No authorization code returned from Entra.')
  if (returnedState !== state) throw new Error('OAuth state mismatch -- possible CSRF, aborting.')

  const tok = await exchangeToken({
    client_id:     cfg.clientId,
    grant_type:    'authorization_code',
    code,
    redirect_uri:  REDIRECT_URI,
    code_verifier: verifier,
    scope:         scopes.join(' ')
  })
  return await persistTokens(tok)
}

// Public auth entry point.
//   { interactive: false } -> silent only; returns null if no valid token.
//   { interactive: true  } -> silent first, then launch interactive flow.
async function acquireGraphToken({ interactive = false, scopes = SCOPES } = {}) {
  const silent = await tryRefresh()
  if (silent) return silent
  if (!interactive) return null
  return await interactiveAuth(scopes)
}

async function signOut() {
  await clearStored(['refreshToken', 'accessToken', 'accessTokenExpiry', 'account'])
  currentAccount = null
  window.location.reload()
}

// ---------- Graph ----------
async function graph(token, method, url, body) {
  const r = await fetch(`https://graph.microsoft.com/v1.0${url}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  })
  const text = await r.text()
  let json = null
  try { json = text ? JSON.parse(text) : null } catch {}
  if (!r.ok) {
    const msg = json?.error?.message || text || r.statusText
    const err = new Error(`${method} ${url} -> ${r.status}: ${msg}`)
    err.status = r.status
    err.body = json
    // Self-heal: 401 InvalidAuthenticationToken / 403 with the
    // "AccessDenied" code on a delegated scope path usually means the
    // token is stale (admin re-consented after sign-in, or token signed
    // before scope was added). Force a reauth — the new token will pick
    // up the latest consented scope set.
    const errCode = json?.error?.code || ''
    const looksStale = r.status === 401 ||
        (r.status === 403 && /Authorization_RequestDenied|InvalidAuthenticationToken|TokenNotFound|MissingClaim|InsufficientScopes?/i.test(errCode + ' ' + msg))
    if (looksStale) {
      err.stale = true
    }
    throw err
  }
  return json
}

async function listEligibleForMe(token) {
  // Single call: returns ALL eligible PIM-for-Groups instances for the signed-in user.
  // No per-group iteration needed for the self case.
  const url = "/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances/filterByCurrentUser(on='principal')"
  const out = []
  let next = url
  while (next) {
    const res = await graph(token, 'GET', next)
    out.push(...(res.value || []))
    next = res['@odata.nextLink'] ? res['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0', '') : null
  }
  return out
}

async function hydrateGroupNames(token, groupIds) {
  // $batch up to 20 GET /groups/{id}?$select=id,displayName per call.
  const out = {}
  for (let i = 0; i < groupIds.length; i += 20) {
    const slice = groupIds.slice(i, i + 20)
    const reqs = slice.map((gid, idx) => ({
      id: String(idx),
      method: 'GET',
      url: `/groups/${gid}?$select=id,displayName`
    }))
    const res = await graph(token, 'POST', '/$batch', { requests: reqs })
    for (const resp of (res.responses || [])) {
      if (resp.status === 200 && resp.body) out[resp.body.id] = resp.body.displayName
    }
  }
  return out
}

async function activateGroup(token, groupId, justification, durationHours) {
  // POST assignmentScheduleRequest -- selfActivate, member access, after-MFA per CA policy.
  const totalMin = Math.round(durationHours * 60)
  const h = Math.floor(totalMin / 60)
  const m = totalMin % 60
  const duration = `PT${h}H${m}M`
  const body = {
    accessId: 'member',
    principalId: currentAccount.localAccountId,
    groupId: groupId,
    action: 'selfActivate',
    justification: justification,
    scheduleInfo: {
      startDateTime: new Date().toISOString(),
      expiration: { type: 'afterDuration', duration }
    }
  }
  return graph(token, 'POST', '/identityGovernance/privilegedAccess/group/assignmentScheduleRequests', body)
}

// ---------- My Access (active assignments) ----------
//
// Lists what the signed-in user CURRENTLY has active in this tenant:
//   1. Active PIM-for-Groups memberships (assignmentScheduleInstances filtered by principalId)
//   2. Entra role assignments attached to each active group
//      (roleManagement/directory/roleAssignments?$filter=principalId eq '<gid>')
//   3. (Deferred) Azure RBAC assignments -- shown as a static "see Azure portal" line
//
// Strategy:
//   - Fetch instances once.
//   - Hydrate group displayNames via $batch (reuse hydrateGroupNames).
//   - Pre-fetch the entire roleDefinitions table (one cached call -- ~120 rows in
//     a typical tenant; cheap, avoids N lookups).
//   - For each active group, query role assignments and resolve scope.
//   - Each lookup is wrapped in try/catch -- a 403 on the role assignment call
//     (typical when admin hasn't re-consented yet) renders inline rather than
//     killing the whole tab.

let roleDefinitionsCache = null     // { idToName: { roleDefId: displayName } }
let auNameCache = {}                // { auId: displayName | null (lookup failed) }

// Hydrate AU name cache from chrome.storage.local on popup load so we don't
// re-look-up the same AUs every time the popup opens. AU names rarely change;
// stale entries get re-validated lazily as the popup queries each AU and
// overwrites the cache entry. 24-hour TTL on individual entries to age out
// renamed/deleted AUs.
const AU_CACHE_TTL_MS = 24 * 60 * 60 * 1000   // 24h
;(async () => {
  try {
    const stored = await getStored(['auNameCache'])
    if (stored?.auNameCache && typeof stored.auNameCache === 'object') {
      const now = Date.now()
      for (const [id, entry] of Object.entries(stored.auNameCache)) {
        // Entry can be either raw name string (legacy v2.4.x) or { name, ts }
        if (typeof entry === 'string' || entry === null) {
          auNameCache[id] = entry   // legacy format
        } else if (entry?.ts && (now - entry.ts) < AU_CACHE_TTL_MS) {
          auNameCache[id] = entry.name
        }
      }
    }
  } catch { /* missing or corrupt cache; start fresh */ }
})()

// Activation history: per-group counter + last-activated timestamp, persisted
// in chrome.storage.local. Used to sort the Activate tab so the user's most-
// used groups bubble to the top of each bucket. Recency wins over raw count
// (a group activated yesterday ranks higher than one activated 50 times last
// year). Set in recordActivation() on every successful activation; loaded at
// boot into the in-memory `activationHistory` map.
let activationHistory = {}   // { groupId: { count, lastActivated: epochMs } }

;(async () => {
  try {
    const stored = await getStored(['activationHistory'])
    if (stored?.activationHistory && typeof stored.activationHistory === 'object') {
      activationHistory = stored.activationHistory
    }
  } catch { /* missing or corrupt; start fresh */ }
})()

function recordActivation(groupId) {
  if (!groupId) return
  const e = activationHistory[groupId] || { count: 0, lastActivated: 0 }
  e.count++
  e.lastActivated = Date.now()
  activationHistory[groupId] = e
  // Fire-and-forget persistence
  setStored({ activationHistory }).catch(() => {})
}

// Composite sort score: recency dominates, count tiebreaks. Returns higher =
// "more frequent / recent" so we use it with descending sort.
function activationRank(groupId) {
  const e = activationHistory[groupId]
  if (!e) return 0
  // Recency component: 1.0 for "right now", decays linearly to 0 over 30 days.
  const ageMs = Date.now() - (e.lastActivated || 0)
  const days = ageMs / (1000 * 60 * 60 * 24)
  const recencyScore = Math.max(0, 1 - days / 30)   // 0..1
  // Count component, capped so 50+ activations don't completely outrank
  // a recent one-off.
  const countScore = Math.min(e.count, 20) / 20      // 0..1
  // Weighted blend: recency twice as influential as raw count.
  return recencyScore * 2 + countScore
}

// Persist the cache after each successful lookup so the data outlives the popup.
async function persistAuCache() {
  try {
    const wrapped = {}
    for (const [id, name] of Object.entries(auNameCache)) {
      wrapped[id] = { name, ts: Date.now() }
    }
    await setStored({ auNameCache: wrapped })
  } catch { /* storage quota or shutdown; ignore */ }
}

async function listActiveGroupAssignmentsForMe(token) {
  if (!currentAccount?.localAccountId) return []
  const principalId = currentAccount.localAccountId
  // assignmentScheduleInstances supports $filter on principalId.
  const url = `/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?$filter=principalId eq '${principalId}'`
  const out = []
  let next = url
  while (next) {
    const res = await graph(token, 'GET', next)
    out.push(...(res.value || []))
    next = res['@odata.nextLink'] ? res['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0', '') : null
  }
  // Match the activation flow -- show member access only.
  return out.filter(x => x.accessId === 'member')
}

async function loadRoleDefinitions(token) {
  if (roleDefinitionsCache) return roleDefinitionsCache
  const idToName = {}
  let next = '/roleManagement/directory/roleDefinitions?$select=id,displayName'
  while (next) {
    const res = await graph(token, 'GET', next)
    for (const rd of (res.value || [])) idToName[rd.id] = rd.displayName
    next = res['@odata.nextLink'] ? res['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0', '') : null
  }
  roleDefinitionsCache = { idToName }
  return roleDefinitionsCache
}

async function listRoleAssignmentsForGroup(token, groupId) {
  // Both active (roleAssignments) and eligible-via-group entries arrive via
  // roleAssignments because the group's PIM-for-Groups membership makes the
  // user effectively a member, and any roleAssignment whose principalId is the
  // group's object id grants the role to current members.
  const url = `/roleManagement/directory/roleAssignments?$filter=principalId eq '${groupId}'`
  const out = []
  let next = url
  while (next) {
    const res = await graph(token, 'GET', next)
    out.push(...(res.value || []))
    next = res['@odata.nextLink'] ? res['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0', '') : null
  }
  return out
}

// Turn a list of { kind, name, auId, raw } scope descriptors into ONE
// human-readable summary string. Replaces the v2.4.15 behaviour that printed
// raw AU GUIDs (which end-users can't act on) and one row per identical entry.
function summariseScopes(scopes) {
  if (!scopes || !scopes.length) return ''
  if (scopes.some(s => s.kind === 'tenant')) return '(tenant-wide)'
  const namedAus    = scopes.filter(s => s.kind === 'au' && s.name).map(s => s.name)
  const unnamedAus  = scopes.filter(s => s.kind === 'au' && !s.name).length
  const others      = scopes.filter(s => s.kind === 'other').length
  const unique      = [...new Set(namedAus)].sort((a, b) => a.localeCompare(b))
  const parts = []
  if (unique.length) {
    // Show up to 4 names inline; cap the rest with "+N more"
    const head = unique.slice(0, 4).map(n => `'${n}'`).join(', ')
    const tail = unique.length > 4 ? ` + ${unique.length - 4} more` : ''
    parts.push(`in AU ${head}${tail}`)
  }
  if (unnamedAus) parts.push(`scoped to ${unnamedAus} Administrative Unit${unnamedAus === 1 ? '' : 's'} (admin must grant AdministrativeUnit.Read.All to show names)`)
  if (others)     parts.push(`${others} other scope${others === 1 ? '' : 's'}`)
  if (!parts.length) return '(scope unavailable)'
  return parts.join(' + ')
}

// ---------- Azure RBAC (ARM) ----------
//
// Azure RBAC lives in ARM (management.azure.com), NOT in Microsoft Graph. We
// mint a separate token with the ARM audience by exchanging the same
// refresh_token we already have (works because the user granted us
// offline_access at sign-in). The ARM token is cached separately so we don't
// re-mint on every popup open.

const ARM_SCOPE = 'https://management.azure.com/user_impersonation'

async function getArmToken() {
  const stored = await getStored(['refreshToken', 'armAccessToken', 'armAccessTokenExpiry'])
  if (stored.armAccessToken && stored.armAccessTokenExpiry && Date.now() < stored.armAccessTokenExpiry) {
    return stored.armAccessToken
  }
  if (!stored.refreshToken) return null
  try {
    const tok = await exchangeToken({
      client_id:     cfg.clientId,
      grant_type:    'refresh_token',
      refresh_token: stored.refreshToken,
      scope:         `${ARM_SCOPE} offline_access`,
      redirect_uri:  REDIRECT_URI
    })
    const expiry = Date.now() + (Number(tok.expires_in || 3600) - 60) * 1000
    await setStored({
      armAccessToken:       tok.access_token,
      armAccessTokenExpiry: expiry,
      // Entra rotates refresh_tokens on each redeem; persist the new one.
      ...(tok.refresh_token ? { refreshToken: tok.refresh_token } : {})
    })
    return tok.access_token
  } catch (e) {
    console.warn('[PIM Activator] ARM token acquisition failed:', e?.message || e)
    return null
  }
}

// Cache of subscriptions the user can read (populated on first ARM query)
let armSubscriptionsCache = null
async function listUserSubscriptions(armToken) {
  if (armSubscriptionsCache) return armSubscriptionsCache
  try {
    const res = await fetch('https://management.azure.com/subscriptions?api-version=2022-12-01', {
      headers: { Authorization: `Bearer ${armToken}` }
    })
    if (!res.ok) {
      armSubscriptionsCache = []   // 403 or similar -> empty
      return armSubscriptionsCache
    }
    const j = await res.json()
    armSubscriptionsCache = (j.value || []).map(s => ({ id: s.subscriptionId, name: s.displayName }))
    return armSubscriptionsCache
  } catch {
    armSubscriptionsCache = []
    return armSubscriptionsCache
  }
}

async function listAzureRoleAssignmentsForGroup(armToken, groupId) {
  // Querying at tenant root (/providers/Microsoft.Authorization/...) requires
  // the caller to have read permission at tenant root scope, which most users
  // DO NOT have (you'd need to be Global Admin with elevated access, or have
  // a role at tenant root). For everyone else that returns 403 AuthorizationFailed.
  //
  // Workaround: enumerate the subscriptions the user can read, then query
  // roleAssignments at each subscription scope (which the user CAN read if
  // they have at least Reader on that subscription). Aggregate + dedupe by
  // assignment id. Misses tenant-root and management-group assignments for
  // users who aren't tenant-level readers, but catches every assignment in
  // the subscriptions they actually touch.

  const subs = await listUserSubscriptions(armToken)
  if (!subs.length) {
    // Fallback: try the tenant-root query anyway in case the user IS a
    // tenant-level reader. If that 403s, surface a cleaner message.
    const url = `https://management.azure.com/providers/Microsoft.Authorization/roleAssignments?$filter=principalId+eq+%27${groupId}%27&api-version=2022-04-01`
    const res = await fetch(url, { headers: { Authorization: `Bearer ${armToken}` } })
    if (!res.ok) {
      const err = new Error('Account lacks Azure read permission at tenant root scope')
      err.status = res.status
      throw err
    }
    const j = await res.json()
    return j.value || []
  }

  const seen = new Set()
  const out  = []
  for (const sub of subs) {
    const url = `https://management.azure.com/subscriptions/${sub.id}/providers/Microsoft.Authorization/roleAssignments?$filter=principalId+eq+%27${groupId}%27&api-version=2022-04-01`
    try {
      const res = await fetch(url, { headers: { Authorization: `Bearer ${armToken}` } })
      if (!res.ok) continue   // skip subs the user can't list roleAssignments in
      const j = await res.json()
      for (const a of (j.value || [])) {
        if (seen.has(a.id)) continue
        seen.add(a.id)
        // Stash the subscription display name so the renderer can show it
        a._subscriptionName = sub.name
        out.push(a)
      }
    } catch {
      // ignore per-sub failures; aggregate what we can
    }
  }
  return out
}

let armRoleNameCache = {}   // { fullRoleDefinitionId: displayName }
async function resolveArmRoleName(armToken, roleDefinitionId) {
  if (!roleDefinitionId) return '(unknown role)'
  if (roleDefinitionId in armRoleNameCache) return armRoleNameCache[roleDefinitionId]
  try {
    const url = `https://management.azure.com${roleDefinitionId}?api-version=2022-04-01`
    const res = await fetch(url, { headers: { Authorization: `Bearer ${armToken}` } })
    if (res.ok) {
      const j = await res.json()
      armRoleNameCache[roleDefinitionId] = j?.properties?.roleName || roleDefinitionId
    } else {
      armRoleNameCache[roleDefinitionId] = roleDefinitionId.split('/').pop()   // GUID fallback
    }
  } catch {
    armRoleNameCache[roleDefinitionId] = '(lookup failed)'
  }
  return armRoleNameCache[roleDefinitionId]
}

// Turn /subscriptions/<sub>/resourceGroups/<rg>/providers/... -> human-readable
function describeArmScope(scopeStr, subNameById) {
  if (!scopeStr || scopeStr === '/')                  return '(tenant root)'
  if (scopeStr.startsWith('/providers/Microsoft.Management/managementGroups/')) {
    return `Management Group '${scopeStr.split('/').pop()}'`
  }
  // Show subscription friendly name when available
  const subMatch = scopeStr.match(/^\/subscriptions\/([^/]+)$/)
  if (subMatch) {
    const name = subNameById ? subNameById[subMatch[1]] : null
    return name ? `Subscription '${name}'` : `Subscription '${subMatch[1]}'`
  }
  const rg = scopeStr.match(/^\/subscriptions\/([^/]+)\/resourceGroups\/([^/]+)$/)
  if (rg) {
    const subName = subNameById ? subNameById[rg[1]] : null
    return subName ? `Resource group '${rg[2]}' in '${subName}'` : `Resource group '${rg[2]}'`
  }
  return scopeStr   // resource-scoped or something unusual; show raw
}

async function resolveAuDisplayName(token, auId) {
  if (auId in auNameCache) return auNameCache[auId]
  try {
    const res = await graph(token, 'GET', `/directory/administrativeUnits/${auId}?$select=id,displayName`)
    auNameCache[auId] = res?.displayName || null
  } catch (e) {
    // 404 (stale) or 403 (insufficient consent) -> cache the failure as null
    // so the renderer can degrade to a friendly "N Administrative Units"
    // label instead of showing a GUID or "__err".
    auNameCache[auId] = null
  }
  // Fire-and-forget persistence so subsequent popup-opens reuse the cached
  // names without round-tripping to Graph.
  persistAuCache()
  return auNameCache[auId]
}

// Returns structured scope info so the renderer can group/summarise instead of
// showing raw GUIDs (which end-users cannot act on or interpret).
async function describeDirectoryScope(token, directoryScopeId) {
  if (!directoryScopeId)         return { kind: 'unknown' }
  if (directoryScopeId === '/')  return { kind: 'tenant' }
  const auMatch = directoryScopeId.match(/^\/administrativeUnits\/([0-9a-fA-F-]{36})$/)
  if (auMatch) {
    const name = await resolveAuDisplayName(token, auMatch[1])
    return { kind: 'au', auId: auMatch[1], name }   // name is null when lookup fails
  }
  return { kind: 'other', raw: directoryScopeId }
}

async function loadMyAccessTab(token, { force = false } = {}) {
  if (myAccessLoading) return
  // Cache hit?
  if (!force && myAccessCache && (Date.now() - myAccessCache.ts) < MYACCESS_CACHE_MS) {
    renderMyAccess(myAccessCache.rows)
    return
  }

  myAccessLoading = true
  els.myAccessStatus.textContent = 'Loading active assignments...'
  els.myAccessStatus.classList.remove('err')
  els.myAccessList.innerHTML = ''

  try {
    // 1. Active PIM-for-Groups memberships.
    const instances = await listActiveGroupAssignmentsForMe(token)

    if (!instances.length) {
      myAccessCache = { ts: Date.now(), rows: [] }
      els.myAccessStatus.textContent = ''
      els.myAccessList.innerHTML = '<div class="empty">No active PIM-for-Groups memberships right now. Activate one from the Activate tab.</div>'
      updateBadges()
      myAccessLoadedOnce = true
      return
    }

    // 2. Hydrate group names + role definitions in parallel.
    const groupIds = [...new Set(instances.map(x => x.groupId))]
    let names = {}
    let roleDefs = { idToName: {} }
    try {
      [names, roleDefs] = await Promise.all([
        hydrateGroupNames(token, groupIds),
        loadRoleDefinitions(token).catch(e => {
          console.warn('roleDefinitions load failed:', e)
          return { idToName: {} }
        })
      ])
    } catch (e) {
      console.warn('myAccess preload failed:', e)
    }

    // 3. Build rows (no per-group role lookup yet -- defer to render so each
    //    row can show a per-group loading state + per-group error).
    const rows = instances.map(x => ({
      groupId: x.groupId,
      displayName: names[x.groupId] || x.groupId,
      startDateTime: x.startDateTime,
      endDateTime: x.endDateTime,
      accessId: x.accessId,
      roles: null,            // Entra: null = not loaded yet
      rolesError: null,
      azureRoles: null,       // Azure RBAC: null = not loaded yet
      azureRolesError: null
    })).sort((a, b) => {
      // Newest activation first -- user sees what they just activated at the
      // top, long-standing eligibilities (months-old memberships) at the
      // bottom. Prevents the "mix of active permissions" confusion where
      // recent activations got buried alphabetically.
      const ta = a.startDateTime ? Date.parse(a.startDateTime) : 0
      const tb = b.startDateTime ? Date.parse(b.startDateTime) : 0
      return tb - ta
    })

    myAccessCache = { ts: Date.now(), rows }
    els.myAccessStatus.textContent = `${rows.length} active group membership(s).`
    renderMyAccess(rows)
    updateBadges()
    myAccessLoadedOnce = true

    // 4. Acquire Azure RBAC token once (separate audience from Graph). May
    //    return null if user hasn't consented to user_impersonation yet --
    //    each row's Azure section will then show a friendly hint.
    const armToken = await getArmToken()

    // 5. Lazy-load Entra + Azure role assignments per group, updating the DOM
    //    as each resolves. Sequential to be gentle on Graph/ARM throttling.
    for (const r of rows) {
      // --- Entra roles (Microsoft Graph) -------------------------------
      try {
        const assignments = await listRoleAssignmentsForGroup(token, r.groupId)
        const resolved = []
        for (const a of assignments) {
          const roleName = roleDefs.idToName[a.roleDefinitionId] || a.roleDefinitionId
          const scope    = await describeDirectoryScope(token, a.directoryScopeId)
          resolved.push({ roleName, scope })
        }
        r.roles = resolved
        r.rolesError = null
      } catch (e) {
        console.warn(`role assignments lookup failed for group ${r.groupId}:`, e)
        r.roles = []
        r.rolesError = e.message
      }

      // --- Azure RBAC roles (ARM) --------------------------------------
      if (!armToken) {
        r.azureRoles = []
        r.azureRolesError = null
        r.azureRolesNeedConsent = true   // suppresses per-row error; renderer shows one banner at the top of the tab instead
      } else {
        try {
          const armAssignments = await listAzureRoleAssignmentsForGroup(armToken, r.groupId)
          // Build subId -> name map for the scope describer (subscriptions
          // were already cached by listAzureRoleAssignmentsForGroup).
          const subNameById = Object.fromEntries((armSubscriptionsCache || []).map(s => [s.id, s.name]))
          const resolvedArm = []
          for (const a of armAssignments) {
            const roleName = await resolveArmRoleName(armToken, a?.properties?.roleDefinitionId)
            const scope    = describeArmScope(a?.properties?.scope, subNameById)
            resolvedArm.push({ roleName, scope })
          }
          r.azureRoles = resolvedArm
          r.azureRolesError = null
        } catch (e) {
          console.warn(`Azure RBAC lookup failed for group ${r.groupId}:`, e)
          r.azureRoles = []
          // Friendly error: don't dump raw ARM JSON in the popup; condense
          // common cases to one short, actionable line.
          let msg = e.message
          if (msg.includes('AuthorizationFailed') || msg.includes('does not have authorization')) {
            msg = "your account can't read Azure role assignments at this scope (needs Reader/Owner on subscription)"
          }
          r.azureRolesError = msg
        }
      }

      updateMyAccessRoleSlot(r)
    }

    // All per-row data is loaded -- re-render to switch from the single
    // "Active memberships -- loading details..." section to the 3-category
    // view (Entra admin roles / Azure RBAC / Workload access).
    renderMyAccess(rows)
  } catch (e) {
    console.error('My Access load failed:', e)
    els.myAccessStatus.textContent = `Failed to load: ${e.message}`
    els.myAccessStatus.classList.add('err')
  } finally {
    myAccessLoading = false
  }
}

// Categorise a group by its NAME (cheap, instant, predictable -- the
// customer owns the naming convention). Doesn't depend on Graph data so
// section headers + group rows render immediately. Each customer's naming
// convention is different (2linkit uses PIM-Entra-* / PIM-AzRes-*, others
// might use AAD-Admins-* / Az-RBAC-*, etc.), so the patterns are
// configurable via chrome.storage.managed:
//
//   entraGroupRegex   -- match for the "Entra" bucket   (default ^PIM-Entra-)
//   azureGroupRegex   -- match for the "Azure" bucket   (default ^PIM-AzRes-)
//
// Groups that match neither pattern land in the "PIM for Groups (workload)"
// bucket. Both patterns are case-insensitive.
let __cachedCategoriseRegexes = null
function getCategoriseRegexes() {
  if (__cachedCategoriseRegexes) return __cachedCategoriseRegexes
  function tryCompile(pattern, fallback) {
    try { return new RegExp(pattern, 'i') }
    catch (e) {
      console.warn(`[PIM Activator] invalid regex "${pattern}", using default "${fallback}"`)
      return new RegExp(fallback, 'i')
    }
  }
  // Defaults match common naming patterns from real tenants:
  //   "Entra"  -- substring, case-insensitive (covers PIM-Entra-*, MyOrg-Entra-Admins, etc.)
  //   "AzRes|Azure" -- substring, case-insensitive (covers PIM-AzRes-*, *-Azure-*, etc.)
  // Customers without these substrings in their group names can override the
  // regex via chrome.storage.managed (entraGroupRegex / azureGroupRegex).
  __cachedCategoriseRegexes = {
    entra: tryCompile(cfg.entraGroupRegex || 'Entra', 'Entra'),
    azure: tryCompile(cfg.azureGroupRegex || '(AzRes|Azure)', '(AzRes|Azure)')
  }
  return __cachedCategoriseRegexes
}

// Categorise a row -- prefers naming convention (instant, customer-configured
// regex), falls back to role data (accurate but requires Graph calls). Pass
// the full row when available so the fallback can inspect roles/azureRoles;
// pass just the name string from the Activate tab where role data isn't
// queried.
function categoriseGroupByName(nameOrRow) {
  const row  = (typeof nameOrRow === 'object' && nameOrRow) ? nameOrRow : null
  const name = row ? row.displayName : nameOrRow
  const n = String(name || '')
  const r = getCategoriseRegexes()
  if (r.entra.test(n)) return 'entra'
  if (r.azure.test(n)) return 'azure'
  // Fallback: customer without a naming convention -- use whatever role data
  // we have for the row to make a best-effort placement. If no role data yet
  // (still loading, or Activate tab where we don't query roles), default to
  // workload.
  if (row) {
    if (row.azureRoles && row.azureRoles.length > 0) return 'azure'
    if (row.roles      && row.roles.length      > 0) return 'entra'
  }
  return 'workload'   // Defender, Intune, PowerBI, custom apps, or unknown.
}

function renderMyAccess(rows) {
  els.myAccessList.innerHTML = ''
  if (!rows.length) {
    els.myAccessList.innerHTML = '<div class="empty">No active PIM-for-Groups memberships right now. Activate one from the Activate tab.</div>'
    return
  }

  // Global banner when Azure RBAC consent is missing -- replaces per-row
  // "needs user_impersonation consent" repetition. Also calls out the
  // 1-3 min propagation delay that catches users between "consent accepted"
  // and "ARM actually returns role assignments instead of 403".
  if (rows.some(r => r.azureRolesNeedConsent)) {
    const banner = document.createElement('div')
    banner.style.cssText = 'background:#fff8c5;border:1px solid #d4a72c;border-radius:6px;padding:10px 12px;margin:6px 0 10px 0;font-size:12.5px;color:#633c01;line-height:1.45;'
    banner.innerHTML = `
      <div style="font-weight:600;margin-bottom:4px;">Azure RBAC roles not visible yet.</div>
      Admin consent for <code>user_impersonation</code> (Azure Service Management API) is required to show Azure roles per group.
      <ol style="margin:6px 0 6px 18px;padding:0;">
        <li>Click <strong>Re-sign in</strong> (top-left) and accept the Microsoft consent prompt.</li>
        <li><strong>Wait 1-3 minutes</strong> for Azure to propagate the new permission across regions (this is an Azure platform delay, not the popup).</li>
        <li>Click <strong>Refresh</strong> (top-right) -- Azure roles should now show per group.</li>
      </ol>
      Tenant-wide one-time action. Other users in your tenant won't see any prompt.
    `
    els.myAccessList.appendChild(banner)
  }

  // Categorise by NAME (instant, no Graph wait). Each group lands in exactly
  // ONE section based on its PIM-* prefix. Per-row Entra + Azure role data
  // still loads lazily underneath each row.
  const entraGroups    = rows.filter(r => categoriseGroupByName(r.displayName) === 'entra')
  const azureGroups    = rows.filter(r => categoriseGroupByName(r.displayName) === 'azure')
  const workloadGroups = rows.filter(r => categoriseGroupByName(r.displayName) === 'workload')

  const sectionHelp = {
    entra:    'PIM-Entra-* groups -- typically grant Entra (M365) admin roles. Roles listed under each row.',
    azure:    'PIM-AzRes-* groups -- typically grant Azure RBAC roles. Roles listed under each row.',
    workload: 'Everything else -- workload access (Defender XDR, Intune, Power BI workspaces, custom apps). Group membership itself IS the permission.'
  }

  function renderSection(title, help, members) {
    if (!members.length) return
    const sec = document.createElement('div')
    sec.className = 'ma-section'
    sec.innerHTML = `${escapeHtml(title)} (${members.length}) <span style="font-weight:400;color:#7d8590;font-size:11px;">&mdash; ${escapeHtml(help)}</span>`
    els.myAccessList.appendChild(sec)
    for (const r of members) renderOneMyAccessRow(r)
  }

  renderSection('Entra (PIM-Entra-*)',           sectionHelp.entra,    entraGroups)
  renderSection('Azure RBAC (PIM-AzRes-*)',      sectionHelp.azure,    azureGroups)
  renderSection('PIM for Groups (workload)',     sectionHelp.workload, workloadGroups)
}

function renderOneMyAccessRow(r) {
  // Drop the "member since X . expires Y" labels (noisy + "member" is always
  // the same string for PIM-for-Groups). Show the same info with arrow:
  // "<start> -> <end>" with date+time for both. Empty -> "permanent".
  const fmt = (iso) => iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' }) : null
  const start = fmt(r.startDateTime)
  const end   = fmt(r.endDateTime) || 'permanent'
  const times = start ? `${start} &rarr; ${end}` : `ends ${end}`
  const row = document.createElement('div')
  row.className = 'ma-row'
  row.dataset.gid = r.groupId
  row.innerHTML = `
    <div class="ma-head">
      <div class="ma-name">${escapeHtml(r.displayName || r.groupId)}</div>
      <div class="ma-times">${times}</div>
    </div>
    <div class="ma-roles" data-roles-for="${escapeHtml(r.groupId)}"></div>
  `
  els.myAccessList.appendChild(row)
  updateMyAccessRoleSlot(r)
}

function updateMyAccessRoleSlot(r) {
  // A group can appear in TWO sections (Entra + Azure) once renderMyAccess
  // switches to the 3-category view, so update every matching slot.
  const slots = els.myAccessList.querySelectorAll(`[data-roles-for="${CSS.escape(r.groupId)}"]`)
  if (!slots.length) return
  for (const slot of slots) updateOneMyAccessRoleSlot(r, slot)
}

function updateOneMyAccessRoleSlot(r, slot) {
  if (!slot) return
  slot.innerHTML = ''
  if (r.roles === null) {
    const d = document.createElement('div')
    d.className = 'ma-role ma-loading'
    d.textContent = 'Loading role assignments...'
    slot.appendChild(d)
    return
  }
  if (r.rolesError) {
    const d = document.createElement('div')
    d.className = 'ma-role ma-err'
    d.textContent = `(could not load Entra roles: ${r.rolesError})`
    slot.appendChild(d)
  } else if (!r.roles.length) {
    // Skip rendering -- user explicitly asked to not show "no X assigned"
    // lines. Three permission types in this popup: PIM-for-Groups (the
    // parent row itself), Entra roles (this section), Azure RBAC (next).
    // If a section has nothing, the cleanest UX is silence.
  } else {
    // Collapse 8 "Groups Administrator AU <guid>" rows into one tidy row.
    // Group by roleName, summarise scopes. Then if there are MORE than 3
    // distinct role names (PIM-Entra-ID-Bundle-* groups can have 80+ roles),
    // default-collapse the list behind a "Show all N Entra roles" toggle so
    // the popup is readable.
    const byRole = new Map()
    for (const role of r.roles) {
      if (!byRole.has(role.roleName)) byRole.set(role.roleName, [])
      byRole.get(role.roleName).push(role.scope)
    }
    const roleEntries = [...byRole]
    const COLLAPSE_THRESHOLD = 3

    if (roleEntries.length > COLLAPSE_THRESHOLD) {
      // Collapsed summary line
      const summary = document.createElement('div')
      summary.className = 'ma-role ma-collapsed'
      summary.style.cursor = 'pointer'
      summary.innerHTML = `&#x21B3; <strong>${roleEntries.length} Entra roles granted by this group</strong> <span class="ma-scope">(click to expand)</span>`
      slot.appendChild(summary)

      const detail = document.createElement('div')
      detail.style.display = 'none'
      detail.style.marginLeft = '0'
      for (const [roleName, scopes] of roleEntries) {
        const s = summariseScopes(scopes)
        const d = document.createElement('div')
        d.className = 'ma-role'
        d.innerHTML = `&#x21B3; Entra role: <strong>${escapeHtml(roleName)}</strong> <span class="ma-scope">${escapeHtml(s)}</span>`
        detail.appendChild(d)
      }
      slot.appendChild(detail)

      summary.addEventListener('click', () => {
        const isOpen = detail.style.display !== 'none'
        detail.style.display = isOpen ? 'none' : 'block'
        summary.innerHTML = isOpen
          ? `&#x21B3; <strong>${roleEntries.length} Entra roles granted by this group</strong> <span class="ma-scope">(click to expand)</span>`
          : `&#x21B3; <strong>${roleEntries.length} Entra roles granted by this group</strong> <span class="ma-scope">(click to collapse)</span>`
      })
    } else {
      for (const [roleName, scopes] of roleEntries) {
        const summary = summariseScopes(scopes)
        const d = document.createElement('div')
        d.className = 'ma-role'
        d.innerHTML = `&#x21B3; Entra role: <strong>${escapeHtml(roleName)}</strong> <span class="ma-scope">${escapeHtml(summary)}</span>`
        slot.appendChild(d)
      }
    }
  }
  // Azure RBAC roles -- v2.4.18 onwards we actually query ARM for these.
  if (r.azureRoles === null) {
    const d = document.createElement('div')
    d.className = 'ma-role ma-loading'
    d.textContent = 'Loading Azure RBAC...'
    slot.appendChild(d)
  } else if (r.azureRolesNeedConsent) {
    // Suppress per-row consent message; one global banner at top of My Access
    // tab covers this (see renderMyAccess). Showing it per-row was spammy
    // when user hadn't yet consented to user_impersonation.
  } else if (r.azureRolesError) {
    const d = document.createElement('div')
    d.className = 'ma-role ma-err'
    d.innerHTML = `&#x21B3; Azure RBAC: <span class="ma-scope">${escapeHtml(r.azureRolesError)}</span>`
    slot.appendChild(d)
  } else if (!r.azureRoles.length) {
    // Skip rendering -- same rationale as the Entra section above. If this
    // group doesn't grant any Azure roles, just don't say anything.
  } else {
    // Group by Azure role name + scope summary
    const byRole = new Map()
    for (const role of r.azureRoles) {
      if (!byRole.has(role.roleName)) byRole.set(role.roleName, [])
      byRole.get(role.roleName).push(role.scope)
    }
    for (const [roleName, scopes] of byRole) {
      const unique = [...new Set(scopes)]
      const summary = unique.length === 1 ? unique[0] : `${unique.length} scopes (${unique.slice(0,3).join(', ')}${unique.length > 3 ? '...' : ''})`
      const d = document.createElement('div')
      d.className = 'ma-role ma-rbac'
      d.innerHTML = `&#x21B3; Azure RBAC: <strong>${escapeHtml(roleName)}</strong> <span class="ma-scope">at ${escapeHtml(summary)}</span>`
      slot.appendChild(d)
    }
  }
}

// ---------- Tabs ----------
function setActiveTab(name) {
  const isActivate = name === 'activate'
  els.tabBtnActivate.classList.toggle('active', isActivate)
  els.tabBtnMyAccess.classList.toggle('active', !isActivate)
  els.panelActivate.hidden = !isActivate
  els.panelMyAccess.hidden = isActivate
}

function updateBadges() {
  els.badgeActivate.textContent = String(eligibleRows.length || 0)
  const n = myAccessCache?.rows?.length ?? 0
  els.badgeMyAccess.textContent = String(n)
}

// ---------- Render ----------
function render() {
  els.list.innerHTML = ''
  const filter = els.search.value.trim().toLowerCase()

  // Apply free-text filter first, then bucket by naming convention so the
  // 3 section headers (Entra / Azure / PIM for Groups) show counts of
  // FILTERED rows, not the unfiltered total.
  const filtered = eligibleRows.filter(r =>
    !filter || (r.displayName || '').toLowerCase().includes(filter) || r.groupId.includes(filter)
  )

  if (!filtered.length) {
    els.list.innerHTML = `<div class="empty">${eligibleRows.length ? 'No groups match the filter.' : 'No eligible PIM groups for your account.'}</div>`
    updateCount()
    return
  }

  const buckets = {
    entra:    filtered.filter(r => categoriseGroupByName(r.displayName) === 'entra'),
    azure:    filtered.filter(r => categoriseGroupByName(r.displayName) === 'azure'),
    workload: filtered.filter(r => categoriseGroupByName(r.displayName) === 'workload')
  }

  function renderActivateRow(r) {
    const row = document.createElement('div')
    row.className = r.isActive ? 'row row-active-already' : 'row'
    if (r.isActive) row.style.cssText = 'opacity:0.55;background:#f6f8fa;'
    const activeBadge = r.isActive
      ? ' <span style="background:#dafbe1;color:#1a7f37;padding:1px 6px;border-radius:8px;font-size:10.5px;font-weight:600;margin-left:6px;">already active</span>'
      : ''
    // Activate tab: just show "ends <date+time>" -- accessId is always
    // "member" for PIM-for-Groups so it's noise. Date+time so the user
    // sees activation expiry to the minute, not just the day.
    const endLabel = r.endDateTime
      ? new Date(r.endDateTime).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })
      : 'permanent'
    row.innerHTML = `
      <input type="checkbox" data-gid="${r.groupId}" ${r.checked ? 'checked' : ''} ${r.isActive ? 'disabled' : ''}>
      <div class="body">
        <div class="name" title="${escapeHtml(r.displayName || r.groupId)}">${escapeHtml(r.displayName || r.groupId)}${activeBadge}</div>
        <div class="meta">ends ${escapeHtml(endLabel)}</div>
        <div class="status" data-gid-status="${r.groupId}"></div>
      </div>
    `
    if (!r.isActive) {
      row.querySelector('input').onchange = (e) => { r.checked = e.target.checked; updateCount() }
    }
    els.list.appendChild(row)
  }

  function renderActivateSection(title, members) {
    if (!members.length) return
    const sec = document.createElement('div')
    sec.style.cssText = 'background:#f6f8fa;color:#0969da;padding:6px 10px;font-size:11.5px;font-weight:600;border-top:1px solid #d0d7de;border-bottom:1px solid #d0d7de;margin-top:8px;letter-spacing:0.3px;'
    sec.textContent = `${title} (${members.length})`
    els.list.appendChild(sec)
    // Within each section: ready-to-activate first, then already-active at
    // the bottom. Within the "ready" rows, sort by activation history -- the
    // groups the user activates most recently/frequently bubble to the top
    // (so daily-use groups stay reachable, never-used ones fall to the bottom
    // of the bucket but stay above any already-active rows). Within "ready
    // rows with zero history", alphabetical.
    const sorted = members.slice().sort((a, b) => {
      if (!!a.isActive !== !!b.isActive) return a.isActive ? 1 : -1
      const rank = activationRank(b.groupId) - activationRank(a.groupId)
      if (rank !== 0) return rank
      return (a.displayName || '').localeCompare(b.displayName || '')
    })
    for (const r of sorted) renderActivateRow(r)
  }

  renderActivateSection('Entra (M365) roles',        buckets.entra)
  renderActivateSection('Azure RBAC',                buckets.azure)
  renderActivateSection('PIM for Groups (workload)', buckets.workload)

  updateCount()
}
function updateCount() {
  const n = eligibleRows.filter(r => r.checked).length
  els.count.textContent = n ? `${n} selected` : 'Select one or more groups'
  els.activate.disabled = n === 0
}
function setStatus(groupId, text, cls) {
  const el = document.querySelector(`[data-gid-status="${CSS.escape(groupId)}"]`)
  if (!el) return
  el.textContent = text
  el.className = `status ${cls}`
}
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))
}

// ---------- Boot ----------
async function boot() {
  // Honour the forceInteractive flag set by triggerInteractiveReauth so the
  // "Re-sign in" button triggers OAuth + consent prompt automatically instead
  // of leaving the user on the Sign in screen needing a second click.
  const stored = await getStored(['forceInteractive'])
  const forceInteractive = !!stored?.forceInteractive
  if (forceInteractive) {
    await clearStored(['forceInteractive'])
  }

  let result = forceInteractive ? null : await acquireGraphToken({ interactive: false })
  if (!result) {
    if (forceInteractive) {
      // Auto-launch the interactive flow (consent prompt for any newly-added
      // scopes lands here).
      els.signIn.style.display = 'none'
      els.status.textContent = 'Signing in...'
      try {
        result = await acquireGraphToken({ interactive: true })
      } catch (e) {
        els.signIn.style.display = ''
        els.status.textContent = `Sign-in failed: ${e.message}`
        els.status.classList.add('err')
        els.signIn.onclick = async () => { window.location.reload() }
        return
      }
      currentAccount = result.account
      await loaded(result.accessToken)
      return
    }

    els.signIn.style.display = ''
    els.status.textContent = 'Sign in to load your eligible PIM groups.'
    els.signIn.onclick = async () => {
      try {
        result = await acquireGraphToken({ interactive: true })
      } catch (e) {
        els.status.textContent = e.message
        els.status.classList.add('err')
        return
      }
      currentAccount = result.account
      await loaded(result.accessToken)
    }
    return
  }
  currentAccount = result.account
  await loaded(result.accessToken)
}

async function loaded(token) {
  els.signIn.style.display = 'none'
  els.signOut.style.display = ''
  els.signOut.onclick = signOut
  els.me.textContent = currentAccount?.username || ''
  els.status.textContent = 'Loading your PIM delegations ... Please Wait'

  // Show extension version in the header so support knows what the user runs.
  // Read from chrome.runtime.getManifest() -- always matches the running build.
  try {
    const verEl = document.getElementById('version-badge')
    const m = chrome.runtime.getManifest()
    if (verEl && m) {
      verEl.textContent = `v${m.version}`
      verEl.title = `Extension ID: ${chrome.runtime.id}\nManifest version: ${m.manifest_version}\nName: ${m.name}`
    }
    console.log(`[PIM Activator] v${m.version} (id ${chrome.runtime.id})`)
  } catch (e) { /* manifest read shouldn't fail in extension context */ }

  // Self-heal: if the cached token is missing required scopes (admin re-
  // consented new perms after the user last signed in), force a reauth
  // before doing anything else. Avoids mysterious 403s later.
  const miss = missingScopes(token)
  if (miss.length) {
    els.status.textContent = `Token is missing ${miss.length} scope(s); refreshing sign-in...`
    return triggerInteractiveReauth(`Missing scopes: ${miss.join(', ')}`)
  }

  // Parallel: eligibilities + currently-active memberships. The active list
  // lets us hide rows the user already activated (they show in My Access).
  let raw, activeRows
  try {
    [raw, activeRows] = await Promise.all([
      listEligibleForMe(token),
      listActiveGroupAssignmentsForMe(token).catch(() => [])
    ])
  } catch (e) {
    if (e.stale) {
      els.status.textContent = `Token rejected by Graph; refreshing sign-in...`
      return triggerInteractiveReauth(`Graph error: ${e.message}`)
    }
    els.status.textContent = `Failed to list eligible groups: ${e.message}`
    els.status.classList.add('err')
    return
  }

  if (!raw.length) {
    els.status.textContent = 'No eligible PIM-for-Groups assignments for your account.'
    return
  }

  // Build "active key" set so we can hide already-active eligibilities.
  const activeKeys = new Set(
    (activeRows || [])
      .filter(a => a.accessId === 'member')
      .map(a => `${a.groupId}|${a.accessId}`)
  )

  const uniqueGroupIds = [...new Set(raw.map(x => x.groupId))]
  const names = await hydrateGroupNames(token, uniqueGroupIds)

  const filterRe = cfg.groupNameFilter ? new RegExp(cfg.groupNameFilter, 'i') : null
  const stored = await getStored(['selectedIds', 'lastJustification', 'lastDurationHours'])
  const preSelected = new Set(stored.selectedIds || [])

  const allMapped = raw.map(x => ({
    id: x.id,
    groupId: x.groupId,
    displayName: names[x.groupId] || x.groupId,
    accessId: x.accessId,
    endDateTime: x.endDateTime,
    // isActive = the user is already in this group; row gets greyed out at
    // the bottom of the list + the checkbox is disabled (no re-activation
    // path; user goes to My Access tab to see/extend it).
    isActive: activeKeys.has(`${x.groupId}|${x.accessId}`),
    checked: preSelected.has(x.groupId) && !activeKeys.has(`${x.groupId}|${x.accessId}`)
  }))
  const afterNameFilter = allMapped.filter(r => !filterRe || filterRe.test(r.displayName))
  // Sort: inactive (ready-to-activate) first, alphabetical; then active rows
  // at the bottom, also alphabetical. Lets the user see "what I already have"
  // without burying the actionable rows.
  eligibleRows = afterNameFilter.sort((a, b) => {
    if (!!a.isActive !== !!b.isActive) return a.isActive ? 1 : -1
    return (a.displayName || '').localeCompare(b.displayName || '')
  })

  els.just.value = stored.lastJustification ?? (cfg.defaultJustification || '')
  els.dur.value  = stored.lastDurationHours ?? (cfg.defaultDurationHours || 1)

  const readyCount  = eligibleRows.filter(r => !r.isActive).length
  const activeCount = eligibleRows.filter(r =>  r.isActive).length
  const activeNote  = activeCount > 0 ? ` (${activeCount} already active -- shown at bottom)` : ''
  els.status.textContent = `${readyCount} ready to activate${activeNote}.`
  els.toolbar.style.display = 'flex'
  els.footer.style.display = ''
  els.tabs.style.display = 'flex'
  updateBadges()
  render()

  // Tab switching -- lazy-load My Access on first click, then re-render from cache.
  els.tabBtnActivate.onclick = () => setActiveTab('activate')
  els.tabBtnMyAccess.onclick = async () => {
    setActiveTab('myaccess')
    // Lazy first-load; subsequent toggles served from cache (until expiry / refresh).
    const fresh = await acquireGraphToken({ interactive: false })
    const tk = fresh?.accessToken || token
    await loadMyAccessTab(tk)
  }
  // Re-sign in button: unconditionally trigger a fresh interactive sign-in.
  // Previously labelled "Auto-fix permissions" which confused end users (sounds
  // like file/ACL repair). Renamed to "Re-sign in" -- describes the action,
  // not the implementation detail (scope validation).
  if (els.myAccessAutofix) {
    els.myAccessAutofix.onclick = async () => {
      const fresh = await acquireGraphToken({ interactive: false })
      const tk = fresh?.accessToken || token
      const miss = missingScopes(tk)
      if (miss.length === 0) {
        // Token is healthy -- user clicked anyway. Force a fresh sign-in so
        // they can switch accounts or pick up admin-consented updates.
        els.myAccessScopeStatus.textContent = 'Signing you out + back in to refresh permissions...'
        els.myAccessScopeStatus.style.color = '#0969da'
        return triggerInteractiveReauth('User requested re-sign-in')
      } else {
        els.myAccessScopeStatus.textContent = 'Permissions out of date - refreshing sign-in...'
        els.myAccessScopeStatus.style.color = '#cf222e'
        return triggerInteractiveReauth(`Token missing: ${miss.join(', ')}`)
      }
    }
    // Initial scope status: keep the label SHORT + hide it entirely when fine.
    // Old "4/4 scopes" leaked developer-speak; users don't know what a scope
    // is. Only surface a message when something needs attention.
    const initialMiss = missingScopes(token)
    if (initialMiss.length === 0) {
      els.myAccessScopeStatus.textContent = ''   // healthy: silent
    } else {
      els.myAccessScopeStatus.textContent = `Permissions out of date - click Re-sign in`
      els.myAccessScopeStatus.style.color = '#9a6700'
    }
  }

  els.myAccessRefresh.onclick = async () => {
    const fresh = await acquireGraphToken({ interactive: false })
    const tk = fresh?.accessToken || token
    await loadMyAccessTab(tk, { force: true })
  }

  els.search.oninput  = render
  els.selectAll.onclick  = () => { eligibleRows.forEach(r => { if (!r.isActive) r.checked = true }); render() }
  els.selectNone.onclick = () => { eligibleRows.forEach(r => r.checked = false); render() }
  els.refresh.onclick = () => window.location.reload()

  els.activate.onclick = async () => {
    const just = els.just.value.trim()
    const dur  = parseFloat(els.dur.value)
    if (!just) { alert('Justification required.'); return }
    if (!(dur > 0)) { alert('Duration must be > 0.'); return }

    const selected = eligibleRows.filter(r => r.checked)
    await setStored({
      selectedIds: selected.map(r => r.groupId),
      lastJustification: just,
      lastDurationHours: dur
    })

    els.activate.disabled = true
    selected.forEach(r => setStatus(r.groupId, 'queued...', 'pending'))

    let anySucceeded = false

    // Activate sequentially to be gentle on PIM throttling.
    for (const r of selected) {
      setStatus(r.groupId, 'activating...', 'pending')
      try {
        // Re-acquire token per round in case the previous one expired mid-loop.
        const fresh = await acquireGraphToken({ interactive: false })
        const tk = fresh?.accessToken || token
        const res = await activateGroup(tk, r.groupId, just, dur)
        if (res?.status === 'Provisioned' || res?.status === 'Granted') {
          setStatus(r.groupId, `active for ${dur}h - see My Access tab`, 'ok')
          r.checked = false   // uncheck on success so re-opening popup is clean
          anySucceeded = true
          recordActivation(r.groupId)
        } else {
          // Most PIM-for-Groups activations land in PendingProvisioning for a
          // few seconds before flipping to Provisioned. Tell the user that's
          // normal + where to see the final state instead of leaking the API
          // status string verbatim.
          setStatus(r.groupId, `submitted - check My Access tab in a few seconds`, 'pending')
          r.checked = false   // uncheck on submit too -- activation request accepted
          anySucceeded = true
          recordActivation(r.groupId)
        }
      } catch (e) {
        setStatus(r.groupId, e.message, 'err')
        // leave r.checked = true so user can retry
      }
    }
    els.activate.disabled = false

    // Invalidate My Access cache so the badge + tab content reflect the new
    // active memberships on next view (or immediately if the tab is open).
    if (anySucceeded) {
      myAccessCache = null
      // Persist the cleared selection so a popup re-open doesn't re-check the
      // groups we just activated.
      await setStored({ selectedIds: eligibleRows.filter(r => r.checked).map(r => r.groupId) })
      render()   // refresh checkbox state + "N selected" footer count
      // Auto-switch to My Access tab so the user immediately sees the result
      // (active groups + the Entra roles they generated) instead of having to
      // hunt for it. Brief delay lets PendingProvisioning flip to Provisioned
      // before we query.
      setActiveTab('myaccess')
      els.myAccessStatus.textContent = 'Waiting for activation(s) to provision...'
      await new Promise(r => setTimeout(r, 2500))
      const fresh = await acquireGraphToken({ interactive: false })
      const tk = fresh?.accessToken || token
      await loadMyAccessTab(tk, { force: true })
    }
  }
}

boot()
