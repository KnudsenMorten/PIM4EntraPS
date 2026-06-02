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
  document.getElementById('status-bar').textContent = 'Extension not configured. Admin must push tenantId + clientId via Intune (or copy config.template.js -> config.js). See README.md.'
  document.getElementById('status-bar').classList.add('err')
  throw new Error('config not set')
}

const SCOPES = [
  'https://graph.microsoft.com/PrivilegedAccess.ReadWrite.AzureADGroup',
  'https://graph.microsoft.com/Group.Read.All',
  'https://graph.microsoft.com/User.Read',
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
  just: $('justification'), dur: $('duration'), count: $('count'), activate: $('activate')
}

let currentAccount = null
let eligibleRows = []        // [{ id (instanceId), groupId, displayName, accessId, endDateTime }]

// ---------- Persisted state ----------
async function getStored(keys) { return new Promise(r => chrome.storage.local.get(keys, r)) }
async function setStored(obj)  { return new Promise(r => chrome.storage.local.set(obj, r)) }
async function clearStored(keys) { return new Promise(r => chrome.storage.local.remove(keys, r)) }

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

  let raw
  try {
    raw = await listEligibleForMe(token)
  } catch (e) {
    els.status.textContent = `Failed to list eligible groups: ${e.message}`
    els.status.classList.add('err')
    return
  }

  if (!raw.length) {
    els.status.textContent = 'No eligible PIM-for-Groups assignments for your account.'
    return
  }

  const uniqueGroupIds = [...new Set(raw.map(x => x.groupId))]
  const names = await hydrateGroupNames(token, uniqueGroupIds)

  const filterRe = cfg.groupNameFilter ? new RegExp(cfg.groupNameFilter, 'i') : null
  const stored = await getStored(['selectedIds', 'lastJustification', 'lastDurationHours'])
  const preSelected = new Set(stored.selectedIds || [])

  eligibleRows = raw
    .map(x => ({
      id: x.id,
      groupId: x.groupId,
      displayName: names[x.groupId] || x.groupId,
      accessId: x.accessId,
      endDateTime: x.endDateTime,
      checked: preSelected.has(x.groupId)
    }))
    .filter(r => !filterRe || filterRe.test(r.displayName))
    .sort((a, b) => (a.displayName || '').localeCompare(b.displayName || ''))

  els.just.value = stored.lastJustification ?? (cfg.defaultJustification || '')
  els.dur.value  = stored.lastDurationHours ?? (cfg.defaultDurationHours || 1)

  els.status.textContent = `${eligibleRows.length} eligible group(s).`
  els.toolbar.style.display = 'flex'
  els.footer.style.display = ''
  render()

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

    // Activate sequentially to be gentle on PIM throttling.
    for (const r of selected) {
      setStatus(r.groupId, 'activating...', 'pending')
      try {
        // Re-acquire token per round in case the previous one expired mid-loop.
        const fresh = await acquireGraphToken({ interactive: false })
        const tk = fresh?.accessToken || token
        const res = await activateGroup(tk, r.groupId, just, dur)
        if (res?.status === 'Provisioned' || res?.status === 'Granted') {
          setStatus(r.groupId, `activated for +${dur}h`, 'ok')
        } else {
          setStatus(r.groupId, `submitted (${res?.status || 'pending'})`, 'pending')
        }
      } catch (e) {
        setStatus(r.groupId, e.message, 'err')
      }
    }
    els.activate.disabled = false
  }
}

boot()
