// PIM Activator -- WHERE each persisted key lives (no DOM; `chrome` is injected).
//
// Extracted into its own module so the split can be unit-tested under Node with a
// fake chrome.storage (`node --check` clean + importable without the browser
// runtime), exactly like popup-config.js / popup-net.js. popup.js routes EVERY
// read/write of its persisted state through makeStore(); there is one definition
// of which key goes where, so a new token key cannot quietly land on disk.
//
// 🔒 SEC-40 (operator decision 2026-09-18): SIGN-IN TOKENS ARE SESSION-ONLY.
// chrome.storage.local is an unencrypted LevelDB under the browser profile
// (<profile>\Local Extension Settings\<id>) -- a refresh token there is a
// long-lived credential for every customer tenant the admin ever signed in to,
// readable by anything that can read the profile folder, surviving reboots.
// chrome.storage.session lives in memory only and is cleared when the browser
// closes. So:
//   * the keys in SESSION_ONLY_KEYS go to chrome.storage.session, NEVER to local;
//   * everything else (catalog, active tenant, preferences, favourites, ...) stays
//     in chrome.storage.local -- none of it is a secret;
//   * on every popup load migrateTokensOutOfLocal() deletes any token a previous
//     version left in local (the first run of this version purges them; later
//     runs find nothing and are a no-op).
// Cost, accepted by the operator: the admin signs in once per browser session.
//
// Access level: chrome.storage.session defaults to TRUSTED_CONTEXTS (extension
// pages + the service worker). The popup is an extension page, and the extension
// has NO content scripts, so we deliberately do NOT call setAccessLevel -- widening
// it to TRUSTED_AND_UNTRUSTED_CONTEXTS would expose the tokens to content scripts.
//
// No storage.session (a browser older than Chromium 102): tokens are kept in
// memory for the life of the popup only -- never written to local. Signing in on
// every popup open is the price of failing closed.

export const SESSION_ONLY_KEYS = Object.freeze([
  'refreshToken',          // Entra refresh token (the long-lived credential)
  'accessToken',           // Graph access token
  'accessTokenExpiry',
  'armAccessToken',        // ARM access token
  'armAccessTokenExpiry',
  'account',               // who is signed in -- belongs to the sign-in session
  'tenantTokens',          // per-tenant cache of all of the above
])

const SESSION_SET = new Set(SESSION_ONLY_KEYS)

export function isSessionOnlyKey(key) {
  return SESSION_SET.has(String(key))
}

// Split a keys argument (string | string[] | object-of-defaults) into the local
// and session halves. Returns { local: string[], session: string[] }.
export function splitKeys(keys) {
  let list
  if (keys == null) list = null
  else if (typeof keys === 'string') list = [keys]
  else if (Array.isArray(keys)) list = keys.map(String)
  else if (typeof keys === 'object') list = Object.keys(keys)
  else list = [String(keys)]
  if (list === null) return { local: null, session: null }   // "everything"
  return {
    local:   list.filter(k => !SESSION_SET.has(k)),
    session: list.filter(k =>  SESSION_SET.has(k)),
  }
}

function areaCall(area, method, arg) {
  return new Promise((resolve) => {
    try {
      area[method](arg, (v) => resolve(v || {}))
    } catch (_) { resolve({}) }
  })
}

// makeStore(chromeLike) -> { get, set, remove, migrateTokensOutOfLocal, sessionAvailable }
export function makeStore(chromeLike) {
  const storage = chromeLike && chromeLike.storage ? chromeLike.storage : null
  const local   = storage && storage.local ? storage.local : null
  const session = storage && storage.session ? storage.session : null
  const mem = {}   // fallback for session-only keys when storage.session is missing

  async function get(keys) {
    const { local: lk, session: sk } = splitKeys(keys)
    const out = {}
    if (local && (lk === null || lk.length)) Object.assign(out, await areaCall(local, 'get', lk))
    if (lk === null) for (const k of SESSION_ONLY_KEYS) delete out[k]   // never surface a stale local token
    if (sk === null || sk.length) {
      if (session) {
        Object.assign(out, await areaCall(session, 'get', sk))
      } else {
        for (const k of (sk === null ? SESSION_ONLY_KEYS : sk)) if (k in mem) out[k] = mem[k]
      }
    }
    return out
  }

  async function set(obj) {
    const loc = {}, ses = {}
    for (const [k, v] of Object.entries(obj || {})) {
      if (SESSION_SET.has(k)) ses[k] = v; else loc[k] = v
    }
    if (Object.keys(loc).length && local) await areaCall(local, 'set', loc)
    if (Object.keys(ses).length) {
      if (session) await areaCall(session, 'set', ses)
      else Object.assign(mem, ses)
    }
  }

  async function remove(keys) {
    const { local: lk, session: sk } = splitKeys(keys)
    if (lk && lk.length && local) await areaCall(local, 'remove', lk)
    if (sk && sk.length) {
      if (session) await areaCall(session, 'remove', sk)
      for (const k of sk) delete mem[k]
    }
  }

  // Delete every session-only key a previous version left in chrome.storage.local.
  // Returns the names it found (and removed) so the caller can log the migration.
  async function migrateTokensOutOfLocal() {
    if (!local) return []
    const found = await areaCall(local, 'get', [...SESSION_ONLY_KEYS])
    const present = Object.keys(found).filter(k => SESSION_SET.has(k))
    if (present.length) await areaCall(local, 'remove', present)
    return present
  }

  return { get, set, remove, migrateTokensOutOfLocal, sessionAvailable: !!session }
}
