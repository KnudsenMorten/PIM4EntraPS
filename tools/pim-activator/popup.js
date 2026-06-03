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
  // offline_access is required to receive a refresh_token from Entra v2.
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
  'RoleManagement.Read.Directory'
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
  await clearStored(['refreshToken', 'accessToken', 'accessTokenExpiry', 'account'])
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
let auNameCache = {}                // { auId: displayName | null (404) | '__err' (other) }

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
  if (unnamedAus) parts.push(`${unnamedAus} restricted scope${unnamedAus === 1 ? '' : 's'}`)
  if (others)     parts.push(`${others} other scope${others === 1 ? '' : 's'}`)
  if (!parts.length) return '(scope unavailable)'
  return parts.join(' + ')
}

async function resolveAuDisplayName(token, auId) {
  if (auId in auNameCache) return auNameCache[auId]
  try {
    const res = await graph(token, 'GET', `/directory/administrativeUnits/${auId}?$select=id,displayName`)
    auNameCache[auId] = res?.displayName || null
    return auNameCache[auId]
  } catch (e) {
    // 404 (stale) or 403 (insufficient consent) -> cache the failure as null
    // so the renderer can degrade to a friendly "restricted scope" label
    // instead of showing a meaningless GUID or "__err" to the end-user.
    auNameCache[auId] = null
    return null
  }
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
      roles: null,        // null = not loaded yet
      rolesError: null
    })).sort((a, b) => (a.displayName || '').localeCompare(b.displayName || ''))

    myAccessCache = { ts: Date.now(), rows }
    els.myAccessStatus.textContent = `${rows.length} active group membership(s).`
    renderMyAccess(rows)
    updateBadges()
    myAccessLoadedOnce = true

    // 4. Lazy-load role assignments per group, updating the DOM as each resolves.
    //    Sequential to be gentle on Graph throttling.
    for (const r of rows) {
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
      updateMyAccessRoleSlot(r)
    }
  } catch (e) {
    console.error('My Access load failed:', e)
    els.myAccessStatus.textContent = `Failed to load: ${e.message}`
    els.myAccessStatus.classList.add('err')
  } finally {
    myAccessLoading = false
  }
}

function renderMyAccess(rows) {
  els.myAccessList.innerHTML = ''
  if (!rows.length) {
    els.myAccessList.innerHTML = '<div class="empty">No active PIM-for-Groups memberships right now. Activate one from the Activate tab.</div>'
    return
  }
  const sec = document.createElement('div')
  sec.className = 'ma-section'
  sec.textContent = `Active PIM-for-Groups memberships (${rows.length})`
  els.myAccessList.appendChild(sec)

  for (const r of rows) {
    const start = r.startDateTime ? new Date(r.startDateTime).toLocaleString() : '?'
    const end   = r.endDateTime   ? new Date(r.endDateTime).toLocaleString()   : 'permanent'
    const row = document.createElement('div')
    row.className = 'ma-row'
    row.dataset.gid = r.groupId
    row.innerHTML = `
      <div class="ma-head">
        <div class="ma-name">${escapeHtml(r.displayName || r.groupId)}</div>
        <div class="ma-times">member since ${escapeHtml(start)} &middot; expires ${escapeHtml(end)}</div>
      </div>
      <div class="ma-roles" data-roles-for="${escapeHtml(r.groupId)}"></div>
    `
    els.myAccessList.appendChild(row)
    updateMyAccessRoleSlot(r)
  }
}

function updateMyAccessRoleSlot(r) {
  const slot = els.myAccessList.querySelector(`[data-roles-for="${CSS.escape(r.groupId)}"]`)
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
    d.textContent = `(could not load roles for this group: ${r.rolesError})`
    slot.appendChild(d)
  } else if (!r.roles.length) {
    const d = document.createElement('div')
    d.className = 'ma-role'
    d.innerHTML = '&#x21B3; <span class="ma-scope">(no Entra role assignments granted by this group)</span>'
    slot.appendChild(d)
  } else {
    // Collapse 8 "Groups Administrator AU <guid>" rows into one tidy row:
    //   "Groups Administrator -- in AU 'Marketing', 'Sales' + 6 more"
    // Group by roleName, summarise scopes. End-users can't act on GUIDs and
    // they make the popup unreadable, so we drop them entirely.
    const byRole = new Map()
    for (const role of r.roles) {
      if (!byRole.has(role.roleName)) byRole.set(role.roleName, [])
      byRole.get(role.roleName).push(role.scope)
    }
    for (const [roleName, scopes] of byRole) {
      const summary = summariseScopes(scopes)
      const d = document.createElement('div')
      d.className = 'ma-role'
      d.innerHTML = `&#x21B3; Entra role: <strong>${escapeHtml(roleName)}</strong> <span class="ma-scope">${escapeHtml(summary)}</span>`
      slot.appendChild(d)
    }
  }
  // Azure RBAC deferred-to-future-release placeholder, always shown.
  const rbac = document.createElement('div')
  rbac.className = 'ma-role ma-rbac'
  rbac.innerHTML = '&#x21B3; Azure RBAC assignments granted by this group: see Azure portal (Azure RM API access deferred to a future release)'
  slot.appendChild(rbac)
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
  let visible = 0
  for (const r of eligibleRows) {
    if (filter && !((r.displayName || '').toLowerCase().includes(filter) || r.groupId.includes(filter))) continue
    visible++
    const row = document.createElement('div')
    row.className = 'row'
    row.innerHTML = `
      <input type="checkbox" data-gid="${r.groupId}" ${r.checked ? 'checked' : ''}>
      <div class="body">
        <div class="name" title="${escapeHtml(r.displayName || r.groupId)}">${escapeHtml(r.displayName || r.groupId)}</div>
        <div class="meta">${escapeHtml(r.accessId)} &middot; ends ${r.endDateTime ? new Date(r.endDateTime).toLocaleDateString() : 'permanent'}</div>
        <div class="status" data-gid-status="${r.groupId}"></div>
      </div>
    `
    row.querySelector('input').onchange = (e) => { r.checked = e.target.checked; updateCount() }
    els.list.appendChild(row)
  }
  if (!visible) {
    els.list.innerHTML = `<div class="empty">${eligibleRows.length ? 'No groups match the filter.' : 'No eligible PIM groups for your account.'}</div>`
  }
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
  let result = await acquireGraphToken({ interactive: false })
  if (!result) {
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
  els.status.textContent = 'Loading eligible groups...'

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
    checked: preSelected.has(x.groupId)
  }))
  const afterNameFilter = allMapped.filter(r => !filterRe || filterRe.test(r.displayName))
  // Hide rows already active (they appear in My Access tab instead).
  const hiddenAsActive = afterNameFilter.filter(r => activeKeys.has(`${r.groupId}|${r.accessId}`)).length
  eligibleRows = afterNameFilter
    .filter(r => !activeKeys.has(`${r.groupId}|${r.accessId}`))
    .sort((a, b) => (a.displayName || '').localeCompare(b.displayName || ''))

  els.just.value = stored.lastJustification ?? (cfg.defaultJustification || '')
  els.dur.value  = stored.lastDurationHours ?? (cfg.defaultDurationHours || 1)

  const hiddenNote = hiddenAsActive > 0 ? ` (${hiddenAsActive} already active -> My Access)` : ''
  els.status.textContent = `${eligibleRows.length} eligible group(s)${hiddenNote}.`
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
  els.selectAll.onclick = () => { eligibleRows.forEach(r => r.checked = true);  render() }
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
        } else {
          // Most PIM-for-Groups activations land in PendingProvisioning for a
          // few seconds before flipping to Provisioned. Tell the user that's
          // normal + where to see the final state instead of leaking the API
          // status string verbatim.
          setStatus(r.groupId, `submitted - check My Access tab in a few seconds`, 'pending')
          r.checked = false   // uncheck on submit too -- activation request accepted
          anySucceeded = true
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
