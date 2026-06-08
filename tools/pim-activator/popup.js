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

// Config is per-browser-profile only. The user runs the in-popup onboarding
// wizard once per profile (sign in once, tenant + app reg auto-discovered),
// and the resulting tenantId / clientId / defaultJustification /
// defaultDurationHours land in chrome.storage.local. v1.2.0 retired the
// legacy paths (window.PIM_CONFIG from config.js + chrome.storage.managed
// from Intune / GPO push) so there is exactly ONE source of truth and no
// silent override surprises.
// Obsolete sentinel (kept empty for back-compat with all the call sites
// that reference it). In v1.5.8 we listed the dev-tenant clientId here so
// stale chrome.storage.local entries from v1.4.x onboarding (which had a
// bug that saved the dev's clientId into customer tenants) were auto-
// purged. The v1.6+ catalog model binds tenantId+clientId together per
// entry, so the same clientId is legitimately valid in the tenant that
// owns it -- a global ban filters it out everywhere, which is wrong.
// Empty array keeps all the call-sites (loadConfig, readMergedCatalog,
// onboarding-save) running as no-ops. Add a GUID here only if a new
// global-ban scenario emerges.
const KNOWN_BAD_LEGACY_CLIENTIDS = []

// v1.6.0+ multi-tenant catalog support.
// Catalog entry shape:
//   {
//     name:                  "Contoso",
//     tenantId:              "<GUID>",
//     clientId:              "<GUID>",
//     defaultJustification:  "Change in infrastructure",   // optional
//     defaultDurationHours:  8,                            // optional
//     // ----- Naming-convention shortcuts (v1.6.1+, admin-friendly) -----
//     // prefix / entraPrefix / azurePrefix accept either a literal string
//     // or a string[] of literal alternatives. Internally we escape the
//     // literals + wrap them as a regex. Pick whichever matches your
//     // tenant's naming convention; the regex fields below are advanced
//     // power-user overrides.
//     prefix:                "PIM-",                       // -> groupNameFilter = "^PIM-"
//     entraPrefix:           ["PIM-Entra","PIM-AAD"],      // -> entraGroupRegex = "(PIM-Entra|PIM-AAD)"
//     azurePrefix:           ["PIM-Azure","PIM-AzRes"],    // -> azureGroupRegex = "(PIM-Azure|PIM-AzRes)"
//     // ----- Advanced regex overrides (raw, win over the prefix shortcuts) -----
//     groupNameFilter:       "^PIM-",                      // optional regex; overrides `prefix`
//     entraGroupRegex:       "Entra",                      // optional regex
//     azureGroupRegex:       "(AzRes|Azure)"               // optional regex
//   }

// Build a regex string from either a literal prefix string OR a string[] of
// literals. Returns '' if input is empty/invalid.
function _prefixToRegex(p, anchorStart) {
  if (!p) return ''
  const arr = Array.isArray(p) ? p : [String(p)]
  const escaped = arr
    .map(s => String(s || '').trim())
    .filter(s => s.length > 0)
    .map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  if (escaped.length === 0) return ''
  const body = escaped.length === 1 ? escaped[0] : '(' + escaped.join('|') + ')'
  return anchorStart ? '^' + body : body
}
//
// Sources, merged in order (later overrides earlier on the same tenantId):
//   1. chrome.storage.managed.tenantCatalog  (Intune / GPO / HKLM-pushed,
//      string of JSON-encoded array per Chromium policy schema)
//   2. chrome.storage.local.tenantCatalog    (manually imported via wizard,
//      array directly -- we control the writer)
//
// Active selection: chrome.storage.local.activeTenantId (tenantId of the
// currently-active entry). Set by the header dropdown / wizard picker.
//
// Per-customer token cache: chrome.storage.local.tenantTokens (object,
// keyed by tenantId) -- holds { refreshToken, accessToken, accessTokenExpiry,
// armAccessToken, armAccessTokenExpiry, account } per customer so switching
// back to a customer signed in earlier in the session is sub-second.
async function readMergedCatalog() {
  let managed = []
  let local   = []
  let managedErr = null
  try {
    const m = await new Promise(r => chrome.storage.managed.get(['tenantCatalog'], r))
    if (m && m.tenantCatalog) {
      const parsed = (typeof m.tenantCatalog === 'string')
        ? JSON.parse(m.tenantCatalog)
        : m.tenantCatalog
      if (Array.isArray(parsed)) managed = parsed
    }
  } catch (e) {
    managedErr = e.message || String(e)
    console.warn('[PIM Activator] managed catalog read/parse failed:', managedErr)
  }
  try {
    const l = await new Promise(r => chrome.storage.local.get(['tenantCatalog'], r))
    if (Array.isArray(l.tenantCatalog)) local = l.tenantCatalog
  } catch (e) { /* ignore */ }
  const merged = []
  const seen = new Set()
  for (const entry of [...managed, ...local]) {
    if (!entry || typeof entry !== 'object') continue
    const tid = String(entry.tenantId || '').trim().toLowerCase()
    const cid = String(entry.clientId || '').trim().toLowerCase()
    if (!isGuidStr(tid) || !isGuidStr(cid)) continue
    if (KNOWN_BAD_LEGACY_CLIENTIDS.includes(cid)) continue
    if (seen.has(tid)) {
      const idx = merged.findIndex(e => String(e.tenantId).toLowerCase() === tid)
      if (idx >= 0) merged[idx] = entry
      continue
    }
    seen.add(tid)
    merged.push(entry)
  }
  // Stash source breakdown for the onboarding wizard "where did this come from?"
  // status line. Read by renderOnboarding without re-querying storage.
  merged._sources = {
    managedRaw: managed.length,
    localRaw:   local.length,
    managedErr
  }
  return merged
}

function isGuidStr(s) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s || '')
}

function emptyConfig() {
  return { tenantId: '', clientId: '', defaultJustification: '', defaultDurationHours: 0,
           groupNameFilter: '', entraGroupRegex: '', azureGroupRegex: '',
           catalog: [], activeTenantId: '', tenantName: '' }
}

async function loadConfig() {
  const u = await new Promise(r => chrome.storage.local.get(
    ['userTenantId','userClientId','userDefaultJustification','userDefaultDurationHours',
     'userGroupNameFilter','userEntraGroupRegex','userAzureGroupRegex',
     'activeTenantId','tenantTokens'], r))

  // Defensive purge of the known-bad legacy upstream clientId (see comment
  // on KNOWN_BAD_LEGACY_CLIENTIDS above).
  if (u.userClientId && KNOWN_BAD_LEGACY_CLIENTIDS.includes(String(u.userClientId).toLowerCase())) {
    console.warn('[PIM Activator] purging legacy bad userClientId ' + u.userClientId + ' from chrome.storage.local + reloading extension to evict stale MV3 service worker')
    await new Promise(r => chrome.storage.local.remove([
      'userTenantId','userClientId',
      'refreshToken','accessToken','accessTokenExpiry',
      'armAccessToken','armAccessTokenExpiry','account'
    ], r))
    try { chrome.runtime.reload() } catch (e) { /* fall through */ }
    return emptyConfig()
  }

  const catalog = await readMergedCatalog()

  // ----- v1.6.0+ catalog path ------------------------------------------------
  if (catalog.length > 0) {
    let activeId = String(u.activeTenantId || '').trim().toLowerCase()
    let active = catalog.find(e => String(e.tenantId).toLowerCase() === activeId)
    // If no active selection (or stale selection), auto-pick the first entry
    // when there's only one. With many entries we fall through and let the
    // wizard render the picker.
    if (!active && catalog.length === 1) {
      active = catalog[0]
      activeId = String(active.tenantId).toLowerCase()
      await new Promise(r => chrome.storage.local.set({ activeTenantId: activeId }, r))
    }
    if (active) {
      // Resolve admin-friendly prefix shortcuts into the existing regex fields
      // (advanced regex always wins). Mutates a shallow copy of `active`.
      active = Object.assign({}, active)
      if (!active.groupNameFilter && active.prefix)      active.groupNameFilter = _prefixToRegex(active.prefix, true)
      if (!active.entraGroupRegex && active.entraPrefix) active.entraGroupRegex = _prefixToRegex(active.entraPrefix, false)
      if (!active.azureGroupRegex && active.azurePrefix) active.azureGroupRegex = _prefixToRegex(active.azurePrefix, false)

      // Restore this customer's cached token bundle into the legacy keys the
      // rest of popup.js already reads. Switching customers replaces these.
      const tokens = (u.tenantTokens && typeof u.tenantTokens === 'object')
        ? u.tenantTokens[String(active.tenantId).toLowerCase()] : null
      if (tokens) {
        await new Promise(r => chrome.storage.local.set({
          refreshToken:         tokens.refreshToken         || null,
          accessToken:          tokens.accessToken          || null,
          accessTokenExpiry:    tokens.accessTokenExpiry    || 0,
          armAccessToken:       tokens.armAccessToken       || null,
          armAccessTokenExpiry: tokens.armAccessTokenExpiry || 0,
          account:              tokens.account              || null,
        }, r))
      } else {
        // No cached tokens for this customer -- clear stale ones from a
        // different customer's session so the sign-in flow runs cleanly.
        await new Promise(r => chrome.storage.local.remove(
          ['refreshToken','accessToken','accessTokenExpiry',
           'armAccessToken','armAccessTokenExpiry','account'], r))
      }
      return {
        tenantId:             active.tenantId,
        clientId:             active.clientId,
        defaultJustification: active.defaultJustification || '',
        defaultDurationHours: active.defaultDurationHours || 0,
        groupNameFilter:      active.groupNameFilter      || '',
        entraGroupRegex:      active.entraGroupRegex      || '',
        azureGroupRegex:      active.azureGroupRegex      || '',
        catalog,
        activeTenantId:     String(active.tenantId).toLowerCase(),
        tenantName:         active.name || active.tenantId,
      }
    }
    // Catalog exists but no active selection -- caller renders picker.
    return Object.assign(emptyConfig(), { catalog })
  }

  // ----- Legacy single-tenant path (pre-v1.6.0) ------------------------------
  return {
    tenantId:             u.userTenantId             || '',
    clientId:             u.userClientId             || '',
    defaultJustification: u.userDefaultJustification || '',
    defaultDurationHours: u.userDefaultDurationHours || 0,
    groupNameFilter:      u.userGroupNameFilter      || '',
    entraGroupRegex:      u.userEntraGroupRegex      || '',
    azureGroupRegex:      u.userAzureGroupRegex      || '',
    catalog:              [],
    activeTenantId:     '',
    tenantName:         '',
  }
}

const cfg = await loadConfig()
if (!cfg.tenantId || String(cfg.tenantId).startsWith('00000000') || !cfg.clientId || String(cfg.clientId).startsWith('00000000')) {
  // No active customer config. If the catalog has entries, render the
  // customer-picker first (v1.6.0+ MSP path). Otherwise render the
  // empty-catalog onboarding wizard which offers "import catalog" + the
  // legacy single-customer manual-entry path.
  renderOnboarding(cfg)
  await new Promise(() => {}) // park the rest of boot until reload
}

/**
 * Inline first-run wizard. Auto-discovers tenant + PIM Activator app reg
 * via the email-driven OIDC-discovery + service-worker sign-in flow, then
 * lets the user confirm default justification + duration and saves to
 * chrome.storage.local. Single source of truth (v1.2.0+).
 */
function renderOnboarding(currentCfg) {
  // Hide the main UI so the wizard is the only thing visible.
  for (const id of ['tabs', 'panel-activate', 'panel-myaccess']) {
    const el = document.getElementById(id)
    if (el) el.style.display = 'none'
  }
  const sb = document.getElementById('status-bar')
  if (sb) { sb.textContent = ''; sb.style.display = 'none' }

  const ob = document.getElementById('onboarding')
  if (!ob) return
  ob.style.display = ''

  // ----- v1.6.0+ catalog UI -------------------------------------------------
  // Injected at the TOP of the onboarding div, above the legacy auto-discover
  // + manual-entry panels. Two modes:
  //   A) catalog has entries -> render customer picker; user selects active
  //   B) catalog empty       -> render "Import catalog (paste JSON)" + a tip
  // Existing legacy single-customer wizard remains visible BELOW the catalog
  // panel as the fallback path -- still works for single-tenant deployments.
  const catalog = Array.isArray(currentCfg.catalog) ? currentCfg.catalog : []
  const sources = (catalog && catalog._sources) || { managedRaw: 0, localRaw: 0, managedErr: null }
  let catalogPanel = document.getElementById('ob-catalog')
  if (!catalogPanel) {
    catalogPanel = document.createElement('div')
    catalogPanel.id = 'ob-catalog'
    catalogPanel.style.cssText = 'margin-bottom:14px;padding:10px;background:#f0fdf4;border:1px solid #86efac;border-radius:6px;'
    // Insert AFTER the Welcome heading + subtitle (the first 2 children of
    // #onboarding) so the order is: Welcome -> Catalog panel -> Manual entry.
    // The Welcome block is the page title -> catalog is the first action ->
    // manual entry is the fallback.
    const afterEl = ob.children.length >= 2 ? ob.children[1].nextSibling : ob.firstChild
    if (afterEl) ob.insertBefore(catalogPanel, afterEl)
    else         ob.appendChild(catalogPanel)
  }
  // Source-detection panel -- three labeled rows so the operator can tell at
  // a glance whether the Intune managed config landed, whether locally-
  // imported entries are present, and the total entries in catalog. Critical
  // for trouble-shooting "did my Intune policy land?" on a managed device.
  const _statusLine = (function () {
    const _row = function (label, ok, detail, errColor) {
      const icon = ok ? '<span style="color:#15803d;font-weight:700;">&#10003;</span>' :
                        '<span style="color:' + (errColor || '#9a3412') + ';font-weight:700;">&#10007;</span>'
      const value = ok ? '<span style="color:#15803d;font-weight:600;">' + detail + '</span>' :
                         '<span style="color:' + (errColor || '#9a3412') + ';">' + detail + '</span>'
      return '<div style="display:flex;align-items:baseline;gap:6px;font-size:10.5px;">' +
               '<span style="color:#57606a;flex:0 0 180px;">' + label + '</span>' +
               icon + ' ' + value +
             '</div>'
    }
    const managedOk = sources.managedRaw > 0 && !sources.managedErr
    const localOk   = sources.localRaw   > 0
    const total     = catalog.length
    const managedDetail = sources.managedErr
      ? 'READ FAILED: ' + escapeHtmlSafe(sources.managedErr)
      : (sources.managedRaw > 0 ? sources.managedRaw + ' entries (chrome.storage.managed.tenantCatalog)' : 'NOT DETECTED (chrome.storage.managed.tenantCatalog is empty)')
    const localDetail = sources.localRaw > 0
      ? sources.localRaw + ' entries (chrome.storage.local.tenantCatalog)'
      : 'none imported in this browser profile'
    const totalDetail = total > 0 ? total + ' tenant(s) available' : 'no tenants available yet'
    return _row('Intune managed config:', managedOk, managedDetail, sources.managedErr ? '#cf222e' : '#9a3412') +
           _row('Local imported config:', localOk,   localDetail) +
           _row('Total in catalog:',      total > 0, totalDetail)
  })()
  if (catalog.length > 0) {
    catalogPanel.innerHTML =
      '<div style="font-size:12.5px;color:#166534;font-weight:600;margin-bottom:4px;">Pick a tenant (' + catalog.length + ' in catalog)</div>' +
      '<div style="font-size:10.5px;margin-bottom:6px;line-height:1.4;">' + _statusLine + '</div>' +
      '<div style="font-size:11px;color:#15803d;margin-bottom:8px;line-height:1.45;">Pick the tenant to activate now -- you can switch anytime from the header dropdown.</div>' +
      '<select id="ob-catalog-pick" style="width:100%;padding:6px 7px;font-size:12px;background:#ffffff;border:1px solid #86efac;border-radius:5px;margin-bottom:8px;">' +
        catalog.map(c => '<option value="' + escapeHtmlSafe(c.tenantId) + '">' + escapeHtmlSafe(c.name || c.tenantId) + ' (' + escapeHtmlSafe(c.tenantId) + ')</option>').join('') +
      '</select>' +
      '<button id="ob-catalog-go" class="primary" style="font-size:12px;">Use this tenant</button>' +
      '<button id="ob-catalog-clear" style="font-size:11px;margin-left:8px;padding:5px 10px;border:1px solid #d0d7de;border-radius:4px;background:#ffffff;cursor:pointer;">Clear local catalog</button>'
    document.getElementById('ob-catalog-go').onclick = async () => {
      const sel = document.getElementById('ob-catalog-pick')
      const tid = (sel && sel.value || '').toLowerCase()
      if (!tid) return
      await new Promise(r => chrome.storage.local.set({ activeTenantId: tid }, r))
      // Clear stale tokens from a different customer's session.
      await new Promise(r => chrome.storage.local.remove(
        ['refreshToken','accessToken','accessTokenExpiry','armAccessToken','armAccessTokenExpiry','account'], r))
      window.location.reload()
    }
    document.getElementById('ob-catalog-clear').onclick = async () => {
      if (!confirm('Clear the LOCAL customer catalog from this browser profile? Intune-pushed entries will be restored on next popup load.')) return
      await new Promise(r => chrome.storage.local.remove(['tenantCatalog','activeTenantId','tenantTokens'], r))
      window.location.reload()
    }
  } else {
    catalogPanel.innerHTML =
      '<div style="font-size:12.5px;color:#166534;font-weight:600;margin-bottom:4px;">Import tenant catalog (MSP / multi-tenant)</div>' +
      '<div style="font-size:10.5px;margin-bottom:8px;line-height:1.4;">' + _statusLine + '</div>' +
      '<div style="font-size:11px;color:#15803d;margin-bottom:8px;line-height:1.45;">' +
        'Paste a JSON array of tenants below to bulk-onboard. Each entry: ' +
        '<code style="background:#ffffff;padding:1px 3px;border-radius:3px;">{name, tenantId, clientId, defaultJustification?, defaultDurationHours?, prefix?, entraPrefix?, azurePrefix?}</code>. ' +
        'Prefix fields accept a string OR string[]. ' +
        'After import the picker appears above. ' +
        '<strong>Tip:</strong> Intune admins can push the same catalog machine-wide via Settings Catalog -> Configure managed extensions -> key <code style="background:#ffffff;padding:1px 3px;border-radius:3px;">tenantCatalog</code>.' +
      '</div>' +
      '<textarea id="ob-catalog-json" rows="6" placeholder=\'[{"name":"Contoso","tenantId":"00000000-0000-0000-0000-000000000000","clientId":"00000000-0000-0000-0000-000000000000","prefix":"PIM-","entraPrefix":["PIM-Entra","PIM-AAD"],"azurePrefix":["PIM-Azure","PIM-AzRes"]}]\' style="width:100%;box-sizing:border-box;font-family:monospace;font-size:11px;background:#ffffff;border:1px solid #86efac;border-radius:5px;padding:6px 7px;margin-bottom:8px;"></textarea>' +
      '<button id="ob-catalog-import" class="primary" style="font-size:12px;">Import tenant catalog</button>'
    document.getElementById('ob-catalog-import').onclick = async () => {
      const ta = document.getElementById('ob-catalog-json')
      const raw = (ta && ta.value || '').trim()
      if (!raw) { showErr('Paste a JSON array first.'); ta && ta.focus(); return }
      let parsed
      try { parsed = JSON.parse(raw) }
      catch (e) { showErr('JSON parse failed: ' + e.message); return }
      if (!Array.isArray(parsed) || parsed.length === 0) { showErr('JSON must be a non-empty array of customer objects.'); return }
      const cleaned = []
      for (const entry of parsed) {
        if (!entry || typeof entry !== 'object') continue
        const tid = String(entry.tenantId || '').trim().toLowerCase()
        const cid = String(entry.clientId || '').trim().toLowerCase()
        if (!isGuidStr(tid) || !isGuidStr(cid)) { showErr('Entry "' + (entry.name || tid) + '" has invalid tenantId or clientId.'); return }
        if (KNOWN_BAD_LEGACY_CLIENTIDS.includes(cid)) { showErr('Entry "' + (entry.name || tid) + '" uses the known-bad upstream-dev clientId. Replace with your customer-tenant PIM Activator app reg appId.'); return }
        const _strOrArr = (v) => (typeof v === 'string' || Array.isArray(v)) ? v : undefined
        cleaned.push({
          name:                 String(entry.name || '').trim() || tid,
          tenantId:             tid,
          clientId:             cid,
          defaultJustification: typeof entry.defaultJustification === 'string' ? entry.defaultJustification : undefined,
          defaultDurationHours: typeof entry.defaultDurationHours === 'number' ? entry.defaultDurationHours : undefined,
          // Admin-friendly prefix shortcuts (v1.6.1+)
          prefix:               _strOrArr(entry.prefix),
          entraPrefix:          _strOrArr(entry.entraPrefix),
          azurePrefix:          _strOrArr(entry.azurePrefix),
          // Advanced raw-regex overrides
          groupNameFilter:      typeof entry.groupNameFilter      === 'string' ? entry.groupNameFilter      : undefined,
          entraGroupRegex:      typeof entry.entraGroupRegex      === 'string' ? entry.entraGroupRegex      : undefined,
          azureGroupRegex:      typeof entry.azureGroupRegex      === 'string' ? entry.azureGroupRegex      : undefined,
        })
      }
      await new Promise(r => chrome.storage.local.set({
        tenantCatalog: cleaned,
        activeTenantId: cleaned.length === 1 ? cleaned[0].tenantId : ''
      }, r))
      window.location.reload()
    }
  }

  // Pre-fill any non-placeholder values we DID find (e.g. tenantId from
  // managed but clientId blank).
  const tenantInput = document.getElementById('ob-tenant')
  const clientInput = document.getElementById('ob-client')
  const justInput   = document.getElementById('ob-justification')
  const durInput    = document.getElementById('ob-duration')
  if (currentCfg.tenantId && !String(currentCfg.tenantId).startsWith('00000000')) {
    tenantInput.value = currentCfg.tenantId
  }
  if (currentCfg.clientId && !String(currentCfg.clientId).startsWith('00000000')) {
    clientInput.value = currentCfg.clientId
  }
  if (currentCfg.defaultJustification) justInput.value = currentCfg.defaultJustification
  if (currentCfg.defaultDurationHours) durInput.value  = currentCfg.defaultDurationHours

  const errBox = document.getElementById('onboarding-error')
  const showErr = (msg) => {
    if (!errBox) return
    errBox.textContent = msg
    errBox.style.display = msg ? '' : 'none'
  }

  const isGuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test((s || '').trim())

  // v1.6.4+: auto-discover / well-known URI flow removed -- replaced by the
  // catalog model. The single-tenant manual-entry path below remains for
  // non-MSP deployments. Reads/writes only chrome.storage.local; no
  // background.js sign-in / discovery dependency.

  document.getElementById('onboarding-save').onclick = async () => {
    showErr('')
    const tenantId = (tenantInput.value || '').trim()
    const clientId = (clientInput.value || '').trim()
    const justification = (justInput.value || '').trim() || 'Change in infrastructure'
    const durationHours = Math.max(0.5, Math.min(24, Number(durInput.value) || 8))

    if (!isGuid(tenantId)) { showErr('Tenant id must be a GUID (e.g. f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e).'); tenantInput.focus(); return }
    if (!isGuid(clientId)) { showErr('Client id must be a GUID. This is the Application (client) id of the PIM Activator app registration in your tenant.'); clientInput.focus(); return }

    await new Promise(r => chrome.storage.local.set({
      userTenantId:             tenantId,
      userClientId:             clientId,
      userDefaultJustification: justification,
      userDefaultDurationHours: durationHours,
      // The naming-convention regex fields default empty in the single-tenant
      // manual flow; admins who want them should use the catalog (which lets
      // them set prefix / entraPrefix / azurePrefix per entry).
      userGroupNameFilter:      '',
      userEntraGroupRegex:      '',
      userAzureGroupRegex:      '',
    }, r))
    // Wipe any half-baked sign-in artifacts from a previous attempt so the
    // next boot signs in cleanly against the freshly-saved config.
    await new Promise(r => chrome.storage.local.remove(['refreshToken','accessToken','accessTokenExpiry','armAccessToken','armAccessTokenExpiry','account'], r))
    window.location.reload()
  }
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
  // RoleManagement.ReadWrite.Directory (v1.3.0+) -- activates DIRECT Entra
  // role assignments (role granted directly to the user, no PIM group in
  // between). POSTs roleAssignmentScheduleRequests with action=selfActivate.
  // Admin consent required.
  'https://graph.microsoft.com/RoleManagement.ReadWrite.Directory',
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

// Populate the footer with the configured tenant id (the only source of
// truth in v1.2.0+). The "Reset" link wipes per-profile config so the user
// can re-run the onboarding wizard (e.g. when migrating profiles between
// tenants).
;(() => {
  const el = document.getElementById('footer-tenant')
  if (!el || !cfg.tenantId) return
  const tenantLabelPrefix = cfg.tenantName ? `${escapeHtmlSafe(cfg.tenantName)} ` : ''
  el.innerHTML = `${tenantLabelPrefix}Tenant: <strong>${escapeHtmlSafe(cfg.tenantId)}</strong> <a href="#" id="reset-config" style="color:#0969da;text-decoration:none;margin-left:6px;">(reset)</a>`
  el.title = `Tenant: ${cfg.tenantName || '(legacy single-tenant install)'}\nTenant id: ${cfg.tenantId}\nClient id: ${cfg.clientId}\n\nClick 'reset' to clear this browser profile's saved config and re-run the wizard.`
  const link = document.getElementById('reset-config')
  if (link) link.onclick = async (e) => {
    e.preventDefault()
    if (!confirm('Clear PIM Activator config for THIS browser profile and start over? (Catalog + per-customer token cache will also be cleared.)')) return
    await new Promise(r => chrome.storage.local.remove([
      'userTenantId','userClientId','userDefaultJustification','userDefaultDurationHours',
      'userGroupNameFilter','userEntraGroupRegex','userAzureGroupRegex',
      'tenantCatalog','activeTenantId','tenantTokens',
      'refreshToken','accessToken','accessTokenExpiry','armAccessToken','armAccessTokenExpiry','account'
    ], r))
    window.location.reload()
  }
})()

// v1.6.0+ header customer-switcher. Visible only when catalog has >=2
// entries. Picking an entry sets activeTenantId, snapshots current
// tokens into tenantTokens[oldId], and reloads the popup.
;(() => {
  const sel = document.getElementById('customer-switcher')
  if (!sel) return
  const catalog = Array.isArray(cfg.catalog) ? cfg.catalog : []
  if (catalog.length < 2) return
  sel.innerHTML = catalog
    .map(c => {
      const tid = String(c.tenantId).toLowerCase()
      const sel = tid === cfg.activeTenantId ? ' selected' : ''
      return `<option value="${escapeHtmlSafe(tid)}"${sel}>${escapeHtmlSafe(c.name || tid)}</option>`
    })
    .join('')
  sel.style.display = ''
  sel.onchange = async () => {
    const newTid = (sel.value || '').toLowerCase()
    if (!newTid || newTid === cfg.activeTenantId) return
    // Snapshot current active customer's tokens into the per-customer cache
    // so switching back is instant. persistTokens already writes after every
    // sign-in, but in-memory token mutations between sign-ins live in the
    // legacy keys -- copy the latest state.
    const cur = await getStored(['refreshToken','accessToken','accessTokenExpiry','armAccessToken','armAccessTokenExpiry','account','tenantTokens'])
    const cache = (cur.tenantTokens && typeof cur.tenantTokens === 'object') ? cur.tenantTokens : {}
    if (cfg.activeTenantId) {
      cache[cfg.activeTenantId] = {
        refreshToken:         cur.refreshToken,
        accessToken:          cur.accessToken,
        accessTokenExpiry:    cur.accessTokenExpiry,
        armAccessToken:       cur.armAccessToken,
        armAccessTokenExpiry: cur.armAccessTokenExpiry,
        account:              cur.account,
      }
    }
    await setStored({ tenantTokens: cache, activeTenantId: newTid })
    // Clear in-flight token state; loadConfig on reload will restore the
    // new customer's cached tokens (or trigger sign-in if none).
    await clearStored(['refreshToken','accessToken','accessTokenExpiry','armAccessToken','armAccessTokenExpiry','account'])
    window.location.reload()
  }
})()

// Populate the version badge in the header banner at popup-load (independent
// of sign-in state, so it's visible on the Sign in screen too). Read from
// the running manifest so the badge always matches the actual installed
// extension version, not whatever was hard-coded at build time.
;(() => {
  try {
    const verEl = document.getElementById('version-badge')
    const m = chrome.runtime.getManifest()
    if (verEl && m) {
      verEl.textContent = `v${m.version}`
      verEl.title = `Extension ID: ${chrome.runtime.id}\nManifest version: ${m.manifest_version}\nName: ${m.name}`
    }
    console.log(`[PIM Activator] v${m.version} (id ${chrome.runtime.id})`)
  } catch { /* manifest read shouldn't fail in extension context */ }
})()
const AUTH_URL     = `${AUTHORITY}/oauth2/v2.0/authorize`
const TOKEN_URL    = `${AUTHORITY}/oauth2/v2.0/token`
const REDIRECT_URI = chrome.identity.getRedirectURL()  // https://<extId>.chromiumapp.org/

// ---------- UI elements ----------
const $ = (id) => document.getElementById(id)
const els = {
  signIn: $('sign-in'), signOut: $('sign-out'),
  me: $('me'), status: $('status-bar'),
  list: $('list'), footer: $('footer'), toolbar: $('toolbar'),
  search: $('search'), selectAll: $('select-all'), selectNone: $('select-none'), collapseAll: $('collapse-all'), expandAll: $('expand-all'), refresh: $('refresh'),
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
  myAccessScopeStatus: $('myaccess-scope-status'),
  myAccessSelectAll:  $('myaccess-select-all'),
  myAccessSelectNone: $('myaccess-select-none'),
  myAccessDeactivateSelected: $('myaccess-deactivate-selected')
}

let currentAccount = null
let eligibleRows = []        // [{ id (instanceId), groupId, displayName, accessId, endDateTime }]

// My Access tab cache
const MYACCESS_CACHE_MS = 30 * 1000
let myAccessCache = null      // { ts: epochMs, rows: [...] }
let myAccessLoading = false
let myAccessLoadedOnce = false

// Tick state for the My Access tab's bulk deactivate. Set of groupIds.
let myAccessSelected = new Set()
function updateBulkDeactivateButton() {
  const n = myAccessSelected.size
  if (els.myAccessDeactivateSelected) {
    els.myAccessDeactivateSelected.textContent = `Deactivate selected (${n})`
    els.myAccessDeactivateSelected.disabled = n === 0
  }
}

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
  'RoleManagement.ReadWrite.Directory',
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
  // v1.6.0+ catalog: also stash into per-customer token cache keyed by
  // active tenantId, so switching back to this customer later (via the
  // header switcher) restores tokens without re-running launchWebAuthFlow.
  if (cfg.activeTenantId) {
    const stored = await getStored(['tenantTokens'])
    const cache = (stored.tenantTokens && typeof stored.tenantTokens === 'object') ? stored.tenantTokens : {}
    cache[cfg.activeTenantId] = {
      refreshToken:      tok.refresh_token || null,
      accessToken:       tok.access_token,
      accessTokenExpiry: expiry,
      account
    }
    await setStored({ tenantTokens: cache })
  }
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

// Self-deactivate: user voluntarily drops an active PIM-for-Groups membership
// early (before its scheduled expiry). Uses the same assignmentScheduleRequests
// endpoint with action=selfDeactivate. No scheduleInfo required (Entra applies
// "deactivate now"). The user can always do this for their OWN active
// memberships -- admin/elevated roles aren't required because it's "self"
// (the principalId on the body must match the signed-in user).
async function deactivateGroup(token, groupId, justification) {
  const body = {
    accessId: 'member',
    principalId: currentAccount.localAccountId,
    groupId: groupId,
    action: 'selfDeactivate',
    justification: justification || 'User-initiated deactivation from PIM Activator'
  }
  return graph(token, 'POST', '/identityGovernance/privilegedAccess/group/assignmentScheduleRequests', body)
}

// ---------- Direct (PIM v1) Entra role eligibilities ----------
// Lists eligible Entra DIRECTORY roles that are assigned to the user
// DIRECTLY (not via a PIM-for-Groups membership). These are the "PIM v1"
// assignments many tenants still use alongside PIM-for-Groups (v2).
// Requires RoleManagement.Read.Directory (read) + RoleManagement.ReadWrite.Directory
// (activate).
async function listEligibleDirectEntraRolesForMe(token) {
  if (!currentAccount?.localAccountId) return []
  // $expand=roleDefinition to get the displayName in one round trip; saves us
  // the per-id /roleDefinitions/{id} call.
  const filter = encodeURIComponent(`principalId eq '${currentAccount.localAccountId}'`)
  const url = `/roleManagement/directory/roleEligibilityScheduleInstances?$filter=${filter}&$expand=roleDefinition($select=id,displayName)`
  const out = []
  let next = url
  while (next) {
    const res = await graph(token, 'GET', next)
    out.push(...(res.value || []))
    next = res['@odata.nextLink'] ? res['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0', '') : null
  }
  return out
}

// List CURRENTLY-ACTIVE direct Entra role assignments (the user already
// activated this role) so we can grey-out the Activate row and surface it
// on My Access. Mirrors listActiveGroupAssignmentsForMe for the v1 path.
async function listActiveDirectEntraRolesForMe(token) {
  if (!currentAccount?.localAccountId) return []
  const filter = encodeURIComponent(`principalId eq '${currentAccount.localAccountId}' and assignmentType eq 'Activated'`)
  const url = `/roleManagement/directory/roleAssignmentScheduleInstances?$filter=${filter}&$expand=roleDefinition($select=id,displayName)`
  const out = []
  let next = url
  while (next) {
    const res = await graph(token, 'GET', next)
    out.push(...(res.value || []))
    next = res['@odata.nextLink'] ? res['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0', '') : null
  }
  return out
}

async function activateDirectEntraRole(token, roleDefinitionId, directoryScopeId, justification, durationHours) {
  const totalMin = Math.round(durationHours * 60)
  const h = Math.floor(totalMin / 60)
  const m = totalMin % 60
  const duration = `PT${h}H${m}M`
  const body = {
    action: 'selfActivate',
    principalId: currentAccount.localAccountId,
    roleDefinitionId,
    directoryScopeId: directoryScopeId || '/',
    justification,
    scheduleInfo: {
      startDateTime: new Date().toISOString(),
      expiration: { type: 'afterDuration', duration }
    }
  }
  return graph(token, 'POST', '/roleManagement/directory/roleAssignmentScheduleRequests', body)
}

async function deactivateDirectEntraRole(token, roleDefinitionId, directoryScopeId, justification) {
  const body = {
    action: 'selfDeactivate',
    principalId: currentAccount.localAccountId,
    roleDefinitionId,
    directoryScopeId: directoryScopeId || '/',
    justification: justification || 'User-initiated deactivation from PIM Activator'
  }
  return graph(token, 'POST', '/roleManagement/directory/roleAssignmentScheduleRequests', body)
}

// ---------- Direct (PIM v1) Azure RBAC eligibilities ----------
// Lists eligible Azure RBAC role assignments via ARM. Iterates subscriptions
// the caller can see (asTarget() filter scopes to "for me"). Each subscription
// is hit independently so a 403 on one (CA restrictions, sub deleted) does
// not abort the whole list.
async function listEligibleDirectAzureRbacForMe(armToken) {
  if (!armToken) return []
  // 1) List all subscriptions visible to caller
  let subs = []
  try {
    const subsResp = await fetch('https://management.azure.com/subscriptions?api-version=2020-01-01', {
      headers: { Authorization: 'Bearer ' + armToken }
    })
    if (subsResp.ok) {
      const j = await subsResp.json()
      subs = (j.value || []).map(s => s.subscriptionId).filter(Boolean)
    }
  } catch { /* no subs -> no rbac eligibilities */ }
  const out = []
  // 2) Per-subscription eligibility query
  const apiVersion = '2020-10-01'
  for (const subId of subs) {
    try {
      const url = `https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=${apiVersion}&$filter=asTarget()`
      const r = await fetch(url, { headers: { Authorization: 'Bearer ' + armToken } })
      if (!r.ok) continue
      const j = await r.json()
      for (const inst of (j.value || [])) {
        out.push({ ...inst, _subscriptionId: subId })
      }
    } catch { /* skip subscription on failure */ }
  }
  return out
}

async function listActiveDirectAzureRbacForMe(armToken) {
  if (!armToken) return []
  let subs = []
  try {
    const subsResp = await fetch('https://management.azure.com/subscriptions?api-version=2020-01-01', {
      headers: { Authorization: 'Bearer ' + armToken }
    })
    if (subsResp.ok) {
      const j = await subsResp.json()
      subs = (j.value || []).map(s => s.subscriptionId).filter(Boolean)
    }
  } catch { /* */ }
  const out = []
  const apiVersion = '2020-10-01'
  for (const subId of subs) {
    try {
      const url = `https://management.azure.com/subscriptions/${subId}/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=${apiVersion}&$filter=asTarget()`
      const r = await fetch(url, { headers: { Authorization: 'Bearer ' + armToken } })
      if (!r.ok) continue
      const j = await r.json()
      for (const inst of (j.value || [])) {
        // Only count ACTIVATED rows (PIM "Activated" assignmentType). Permanent
        // assignments show up too and would clutter the UI.
        const at = inst.properties?.assignmentType || ''
        if (at.toLowerCase() === 'activated') out.push({ ...inst, _subscriptionId: subId })
      }
    } catch { /* */ }
  }
  return out
}

async function activateDirectAzureRbac(armToken, scope, roleDefinitionId, principalId, justification, durationHours) {
  // ARM uses PUT with a client-generated GUID for the request id (the
  // server side dedups via that id; resending the same GUID is a retry).
  const guid = ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c/4).toString(16))
  const totalMin = Math.round(durationHours * 60)
  const h = Math.floor(totalMin / 60)
  const m = totalMin % 60
  const duration = `PT${h}H${m}M`
  const url = `https://management.azure.com${scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/${guid}?api-version=2020-10-01`
  const body = {
    properties: {
      principalId,
      roleDefinitionId, // full ARM resource id e.g. /providers/Microsoft.Authorization/roleDefinitions/{guid}
      requestType: 'SelfActivate',
      justification,
      scheduleInfo: {
        startDateTime: new Date().toISOString(),
        expiration: { type: 'AfterDuration', duration }
      }
    }
  }
  const resp = await fetch(url, {
    method: 'PUT',
    headers: { Authorization: 'Bearer ' + armToken, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  })
  if (!resp.ok) {
    const err = await resp.text().catch(() => '')
    throw new Error(`ARM activate failed (${resp.status}): ${err.slice(0, 300)}`)
  }
  return resp.json()
}

async function deactivateDirectAzureRbac(armToken, scope, roleDefinitionId, principalId, justification) {
  const guid = ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c/4).toString(16))
  const url = `https://management.azure.com${scope}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/${guid}?api-version=2020-10-01`
  const body = {
    properties: {
      principalId,
      roleDefinitionId,
      requestType: 'SelfDeactivate',
      justification: justification || 'User-initiated deactivation from PIM Activator'
    }
  }
  const resp = await fetch(url, {
    method: 'PUT',
    headers: { Authorization: 'Bearer ' + armToken, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  })
  if (!resp.ok) {
    const err = await resp.text().catch(() => '')
    throw new Error(`ARM deactivate failed (${resp.status}): ${err.slice(0, 300)}`)
  }
  return resp.json()
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

// User-pinned favorite rows on the Activate tab. Keyed by rowKey (covers
// group rows + direct Entra rows + direct Azure RBAC rows uniformly).
// Persisted to chrome.storage.local so the choice survives popup close +
// Edge restart. Favorites sort to the TOP of their section (above the
// recency/frequency sort below) so the user's "daily click" rows are
// always one click away.
let favorites = {}   // { rowKey: true }

// Per-row collapse state for the transitive-role preview under each group row.
// Session-only (not persisted) -- the preview default is expanded, the user
// clicks the toggle to hide a busy row's role list. Keyed by rowKey so the
// state survives a re-render (favourite toggle, sort change, etc.).
let collapsedRows = new Set()

;(async () => {
  try {
    const stored = await getStored(['favorites'])
    if (stored?.favorites && typeof stored.favorites === 'object') {
      favorites = stored.favorites
    }
  } catch { /* missing or corrupt; start fresh */ }
})()

function isFavorite(rowKey) { return !!(rowKey && favorites[rowKey]) }
function toggleFavorite(rowKey) {
  if (!rowKey) return
  if (favorites[rowKey]) delete favorites[rowKey]
  else favorites[rowKey] = true
  setStored({ favorites }).catch(() => {})
}

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

// Bulk Entra role assignments. Fires ONE Graph call per group, in parallel
// via Promise.all (~50 concurrent requests; browser fetch queues + drains
// without blocking the UI). Uses `transitiveRoleAssignments` per group so
// nested-group inheritance is included (Group A member of Group B -> Group
// B's roles flow through).
//
// Why per-group + parallel instead of $filter=principalId in (...): the
// roleAssignments + transitiveRoleAssignments endpoints have restricted
// $filter support; `in` is not a documented operator there. `eq` works,
// and 50 parallel `eq` queries complete in roughly the time of one batched
// call thanks to HTTP/2 multiplexing.
//
// Progress callback fires per completed query so the popup can show a
// progress bar. Returns Map<groupId, [{ roleDefinitionId, directoryScopeId }]>.
async function bulkLoadEntraRolesForGroups(token, groupIds, onProgress) {
  const out = new Map()
  if (!groupIds || !groupIds.length) return out
  let done = 0
  const total = groupIds.length

  async function fetchOne(gid) {
    // Use the TRANSITIVE /roleAssignments endpoint by design. PIM4EntraPS
    // architecture nests role groups inside many task groups, and each
    // task group carries the actual role assignment. Activating one
    // role group ("Cloud Engineer") gives the user the union of role
    // grants from every nested task group beneath it -- the user must
    // see that union here, otherwise the preview underreports what the
    // activation will actually grant. v1.4.4 mistakenly dropped this
    // endpoint; v1.4.5 restores it. Fall back to direct /roleAssignments
    // when transitive returns 4xx (some tenants restrict it for
    // non-privileged users).
    const tryUrl = async (endpoint, needHeaders) => {
      const url = `https://graph.microsoft.com/v1.0${endpoint}?$filter=principalId eq '${gid}'&$top=999${needHeaders ? '&$count=true' : ''}`
      const headers = { Authorization: `Bearer ${token}` }
      if (needHeaders) headers['ConsistencyLevel'] = 'eventual'
      const r = await fetch(url, { headers })
      if (!r.ok) return null
      return await r.json()
    }
    let j = null
    try {
      j = await tryUrl('/roleManagement/directory/transitiveRoleAssignments', true)
      if (!j) j = await tryUrl('/roleManagement/directory/roleAssignments', false)
    } catch (e) {
      console.warn(`[PIM Activator] role fetch failed for ${gid}:`, e?.message || e)
    }
    const items = (j?.value || []).map(a => ({
      roleDefinitionId: a.roleDefinitionId,
      directoryScopeId: a.directoryScopeId
    }))
    out.set(gid, items)
    done++
    if (onProgress) onProgress(done, total, 'entra')
  }

  await Promise.all(groupIds.map(fetchOne))
  return out
}

// Bulk Azure RBAC via Azure Resource Graph. One KQL query, all subscriptions
// the user can read, filtered by principalId. Joins roleDefinitions inline so
// the role NAME comes back with the result -- no per-role lookup needed.
// Returns Map<groupId, [{ roleName, scope }]>.
async function bulkLoadAzureRolesForGroups(armToken, groupIds) {
  const out = new Map()
  if (!armToken || !groupIds || !groupIds.length) return out
  const inList = groupIds.map(g => `'${g}'`).join(',')
  const query = `
    authorizationresources
    | where type =~ "microsoft.authorization/roleassignments"
    | extend principalId = tostring(properties.principalId)
    | extend roleDefinitionId = tostring(properties.roleDefinitionId)
    | extend scope = tostring(properties.scope)
    | where principalId in (${inList})
    | join kind=leftouter (
        authorizationresources
        | where type =~ "microsoft.authorization/roledefinitions"
        | extend roleName = tostring(properties.roleName)
        | project roleDefId = id, roleName
      ) on $left.roleDefinitionId == $right.roleDefId
    | project principalId, roleName, scope
  `.trim()

  try {
    const res = await fetch('https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01', {
      method: 'POST',
      headers: { Authorization: `Bearer ${armToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, options: { resultFormat: 'objectArray' } })
    })
    if (!res.ok) {
      const t = await res.text()
      console.warn(`[PIM Activator] Azure Resource Graph query failed: ${res.status} ${t.substring(0, 300)}`)
      return out
    }
    const j = await res.json()
    for (const row of (j.data || [])) {
      const arr = out.get(row.principalId) || []
      arr.push({ roleName: row.roleName || '(unknown)', scope: row.scope || '/' })
      out.set(row.principalId, arr)
    }
  } catch (e) {
    console.warn('[PIM Activator] Azure Resource Graph call failed:', e?.message || e)
  }
  return out
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

// Synchronous variant for the bulk-fetch path -- uses whatever's already in
// auNameCache (populated lazily as the user opens popups over time). AU
// names that aren't cached yet return name=null and the renderer degrades
// gracefully to "scoped to N Administrative Units".
function parseDirectoryScopeSync(directoryScopeId) {
  if (!directoryScopeId)         return { kind: 'unknown' }
  if (directoryScopeId === '/')  return { kind: 'tenant' }
  const m = directoryScopeId.match(/^\/administrativeUnits\/([0-9a-fA-F-]{36})$/)
  if (m) return { kind: 'au', auId: m[1], name: (m[1] in auNameCache ? auNameCache[m[1]] : null) }
  return { kind: 'other', raw: directoryScopeId }
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

  // Show the My Access progress bar in INDETERMINATE mode straight away --
  // gives the user a visible "we're working" cue during the initial Graph
  // call (paginated assignmentScheduleInstances + name hydration) before we
  // know totals. Mode flips to determinate once the per-group role fetch
  // starts (handled lower down by tickMyAccessProgress).
  const maBp     = document.getElementById('myaccess-progress')
  const maBpLbl  = document.getElementById('myaccess-progress-label')
  const maBpCnt  = document.getElementById('myaccess-progress-count')
  const maBpBar  = document.getElementById('myaccess-progress-bar')
  if (maBp) maBp.style.display = ''
  if (maBpLbl) maBpLbl.textContent = 'Loading active PIM memberships...'
  if (maBpCnt) maBpCnt.textContent = ''
  if (maBpBar) maBpBar.classList.add('indeterminate')

  try {
    // 1. Active PIM-for-Groups memberships + active direct (PIM v1) Entra
    //    roles + active direct Azure RBAC roles. All three fetched in
    //    parallel; each has its own catch so a permission or 404 on one
    //    surface can't blank the whole tab.
    let armTokenEarly = null
    try { armTokenEarly = await getArmToken() } catch { /* ARM optional */ }

    const [instances, directEntraActive, directAzureActive] = await Promise.all([
      listActiveGroupAssignmentsForMe(token).catch(() => []),
      listActiveDirectEntraRolesForMe(token).catch(() => []),
      armTokenEarly ? listActiveDirectAzureRbacForMe(armTokenEarly).catch(() => []) : Promise.resolve([]),
    ])

    if (!instances.length && !directEntraActive.length && !directAzureActive.length) {
      myAccessCache = { ts: Date.now(), rows: [] }
      els.myAccessStatus.textContent = ''
      els.myAccessList.innerHTML = '<div class="empty">No active PIM assignments right now. Activate one from the Activate tab.</div>'
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
    //    row can show a per-group loading state + per-group error). Three
    //    kinds: 'group' (existing PIM v2 path), 'entraDirect' (PIM v1
    //    direct Entra role), 'azureDirect' (PIM v1 direct Azure RBAC).
    const groupRows = instances.map(x => ({
      kind: 'group',
      rowKey: `group:${x.groupId}`,
      groupId: x.groupId,
      displayName: names[x.groupId] || x.groupId,
      startDateTime: x.startDateTime,
      endDateTime: x.endDateTime,
      accessId: x.accessId,
      roles: null,            // Entra: null = not loaded yet
      rolesError: null,
      azureRoles: null,       // Azure RBAC: null = not loaded yet
      azureRolesError: null
    }))

    const entraDirectRows = (directEntraActive || []).map(x => ({
      kind: 'entraDirect',
      rowKey: `entraDirect:${x.roleDefinitionId}:${x.directoryScopeId || '/'}`,
      roleDefinitionId: x.roleDefinitionId,
      directoryScopeId: x.directoryScopeId || '/',
      displayName: x.roleDefinition?.displayName || x.roleDefinitionId,
      startDateTime: x.startDateTime,
      endDateTime: x.endDateTime,
    }))

    // Pre-resolve AU display names referenced by direct (PIM v1) Entra rows so
    // the scope label renders as the AU name instead of a raw GUID. Mirrors the
    // same pattern in the Activate tab loader.
    {
      const auIds = new Set()
      const auRe  = /^\/administrativeUnits\/([0-9a-fA-F-]{36})$/
      for (const r of entraDirectRows) {
        const m = (r.directoryScopeId || '').match(auRe)
        if (m && !(m[1] in auNameCache)) auIds.add(m[1])
      }
      if (auIds.size) {
        await Promise.all([...auIds].map(id => resolveAuDisplayName(token, id).catch(() => null)))
      }
    }

    const azureDirectRows = (directAzureActive || []).map(x => {
      const p = x.properties || {}
      const scope = p.scope || `/subscriptions/${x._subscriptionId}`
      const roleName = p.expandedProperties?.roleDefinition?.displayName
        || p.roleDefinitionId?.split('/').pop()
        || '(unknown role)'
      const scopeName = p.expandedProperties?.scope?.displayName || scope
      return {
        kind: 'azureDirect',
        rowKey: `azureDirect:${p.roleDefinitionId}:${scope}`,
        roleDefinitionId: p.roleDefinitionId,
        armScope: scope,
        principalId: p.principalId || currentAccount.localAccountId,
        displayName: `${roleName} @ ${scopeName}`,
        startDateTime: p.startDateTime,
        endDateTime: p.endDateTime,
      }
    })

    const rows = [...groupRows, ...entraDirectRows, ...azureDirectRows].sort((a, b) => {
      // Newest activation first -- user sees what they just activated at the
      // top, long-standing eligibilities (months-old memberships) at the
      // bottom. Prevents the "mix of active permissions" confusion where
      // recent activations got buried alphabetically.
      const ta = a.startDateTime ? Date.parse(a.startDateTime) : 0
      const tb = b.startDateTime ? Date.parse(b.startDateTime) : 0
      return tb - ta
    })

    myAccessCache = { ts: Date.now(), rows }
    const cntGroups = rows.filter(r => r.kind === 'group').length
    const cntED     = rows.filter(r => r.kind === 'entraDirect').length
    const cntAD     = rows.filter(r => r.kind === 'azureDirect').length
    const parts = []
    if (cntGroups) parts.push(`${cntGroups} group membership${cntGroups === 1 ? '' : 's'}`)
    if (cntED)     parts.push(`${cntED} direct Entra role${cntED === 1 ? '' : 's'}`)
    if (cntAD)     parts.push(`${cntAD} direct Azure RBAC role${cntAD === 1 ? '' : 's'}`)
    els.myAccessStatus.textContent = parts.length ? `Active: ${parts.join(', ')}.` : ''
    renderMyAccess(rows)
    updateBadges()
    myAccessLoadedOnce = true

    // 4. Bulk role fetch. ONE Graph $filter-in call (chunked + parallel) for
    //    Entra; ONE Azure Resource Graph KQL for Azure RBAC. Both fire at
    //    the same time + render independently as each completes -- user sees
    //    Entra roles first (faster), Azure roles arrive seconds later.
    //    Replaces v2.4.27's per-row sequential loop (1 call per group per
    //    type = 30+ Graph calls for 15 groups; now 2-3 total).
    // (groupIds already declared at the top of this function from instances.)
    const armToken = await getArmToken()

    function attachEntra(bulkEntra) {
      // Only group rows need bulk-Entra hydration (the "this group grants
      // these Entra roles" data). Direct rows ARE the role and skip this.
      for (const r of rows) {
        if (r.kind !== 'group') continue
        const entra = bulkEntra.get(r.groupId) || []
        r.roles = entra.map(a => ({
          roleName: roleDefs.idToName[a.roleDefinitionId] || a.roleDefinitionId,
          // For My Access we keep the structured scope descriptor (for the
          // "in AU X" grouping etc.) -- it's resolved synchronously off the
          // already-populated auNameCache and directoryScopeId string match.
          scope: parseDirectoryScopeSync(a.directoryScopeId)
        }))
        r.rolesError = null
      }
      renderMyAccess(rows)
    }
    function attachAzure(bulkAzure) {
      const subNameById = Object.fromEntries((armSubscriptionsCache || []).map(s => [s.id, s.name]))
      for (const r of rows) {
        if (r.kind !== 'group') continue
        const azure = bulkAzure.get(r.groupId) || []
        r.azureRoles = azure.map(a => ({
          roleName: a.roleName,
          scope:    describeArmScope(a.scope, subNameById)
        }))
        r.azureRolesError = null
      }
      renderMyAccess(rows)
    }

    if (!armToken) {
      for (const r of rows) {
        if (r.kind !== 'group') continue
        r.azureRoles = []
        r.azureRolesNeedConsent = true
      }
    }

    // Progress bar -- same UX as the Activate tab. N per-group Entra calls
    // plus 1 ARG call (or 0 if no ARM token). Counters tracked separately
    // so an Azure tick can never get overwritten by a later Entra callback.
    const maProgressTotal = groupIds.length + (armToken ? 1 : 0)
    let maEntraDone = 0
    let maAzureDone = 0
    const mbp      = document.getElementById('myaccess-progress')
    const mbpLabel = document.getElementById('myaccess-progress-label')
    const mbpCount = document.getElementById('myaccess-progress-count')
    const mbpBar   = document.getElementById('myaccess-progress-bar')
    const mbpShownAt = Date.now()
    function tickMyAccessProgress(label) {
      if (!mbp) return
      mbp.style.display = ''
      if (mbpBar) mbpBar.classList.remove('indeterminate')
      const done = maEntraDone + maAzureDone
      const pct = maProgressTotal ? Math.round((done / maProgressTotal) * 100) : 0
      if (mbpLabel) mbpLabel.textContent = label ? `${label} ${pct}%` : `Fetching role assignments... ${pct}%`
      if (mbpCount) mbpCount.textContent = `${done} / ${maProgressTotal}`
      if (mbpBar)   mbpBar.style.width   = `${pct}%`
      if (done >= maProgressTotal) {
        const elapsed = Date.now() - mbpShownAt
        const hideDelay = Math.max(800, 1500 - elapsed)
        setTimeout(() => { if (mbp) mbp.style.display = 'none' }, hideDelay)
      }
    }
    tickMyAccessProgress('Fetching role assignments...')

    const tasks = []
    tasks.push((async () => {
      try {
        const be = await bulkLoadEntraRolesForGroups(token, groupIds, (done) => {
          maEntraDone = done
          tickMyAccessProgress('Fetching Entra roles...')
        })
        attachEntra(be)
      } catch (e) { console.warn('bulk Entra (my access):', e?.message || e) }
    })())
    if (armToken) {
      tasks.push((async () => {
        try {
          const ba = await bulkLoadAzureRolesForGroups(armToken, groupIds)
          attachAzure(ba)
        } catch (e) { console.warn('bulk Azure (my access):', e?.message || e) }
        finally { maAzureDone = 1; tickMyAccessProgress('Fetching Azure RBAC...') }
      })())
    }
    await Promise.all(tasks)
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
// convention is different; customisation is on the roadmap (would extend
// the onboarding wizard's saved config):
//
//   entraGroupRegex   -- match for the "Entra" bucket   (default: "Entra")
//   azureGroupRegex   -- match for the "Azure" bucket   (default: "AzRes|Azure")
//
// Groups that match neither pattern land in the "PIM for Groups (Workload
// RBAC delegations)" bucket. Both patterns are case-insensitive.
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
  //   "Entra"        -- substring match, case-insensitive
  //   "AzRes|Azure"  -- substring match, case-insensitive
  // Customers without these substrings get the defaults; per-tenant regex
  // overrides are future work (would be added to the onboarding wizard).
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
    banner.style.cssText = 'background:#fff8c5;border:1px solid #d4a72c;border-radius:6px;padding:8px 10px;margin:6px 0 10px 0;font-size:12px;color:#633c01;line-height:1.4;'
    banner.innerHTML = `
      Azure RBAC roles not visible yet. Click <strong>Re-sign in</strong>, wait 1-3 min for Azure to propagate, then <strong>Refresh</strong>.
    `
    els.myAccessList.appendChild(banner)
  }

  // Pull starred rows into a top-level Favorites section spanning every
  // category -- mirrors the Activate tab. Favorites are keyed by rowKey,
  // which is shared between tabs (group:{gid} / entraDirect:... /
  // azureDirect:...), so starring a row anywhere highlights it everywhere.
  const favs           = rows.filter(r => isFavorite(r.rowKey || r.groupId))
  const nonFavs        = rows.filter(r => !isFavorite(r.rowKey || r.groupId))

  // Categorise. Direct (PIM v1) rows know their surface directly from the
  // API; group rows (PIM v2) fall back to regex-by-name categorisation.
  const entraDirect    = nonFavs.filter(r => r.kind === 'entraDirect')
  const azureDirect    = nonFavs.filter(r => r.kind === 'azureDirect')
  const entraGroups    = nonFavs.filter(r => r.kind === 'group' && categoriseGroupByName(r.displayName) === 'entra')
  const azureGroups    = nonFavs.filter(r => r.kind === 'group' && categoriseGroupByName(r.displayName) === 'azure')
  const workloadGroups = nonFavs.filter(r => r.kind === 'group' && categoriseGroupByName(r.displayName) === 'workload')

  const sectionHelp = {
    entraDirect: 'Role assigned directly to the user (no PIM group in between).',
    azureDirect: 'Azure RBAC role assigned directly to the user at the listed scope.',
    entra:       'Groups that grant Entra admin roles. Roles listed under each row.',
    azure:       'Groups that grant Azure RBAC roles. Roles listed under each row.',
    workload:    'Group membership itself IS the permission (Defender XDR, Intune, Power BI workspaces, etc.).'
  }

  function renderSection(title, help, members) {
    if (!members.length) return
    const sec = document.createElement('div')
    sec.className = 'ma-section'
    sec.innerHTML = `${escapeHtml(title)} (${members.length}) <span style="font-weight:400;color:#7d8590;font-size:11px;">&mdash; ${escapeHtml(help)}</span>`
    els.myAccessList.appendChild(sec)
    for (const r of members) renderOneMyAccessRow(r)
  }

  // Favorites first (spans all categories). Bottom divider for visual break.
  renderSection('\u2605 Favorites',                            'Starred from the Activate tab. Click \u2605 to unfavorite.', favs)
  if (favs.length) {
    const div = document.createElement('div')
    div.style.cssText = 'border-top:3px double #d0d7de;margin:6px 0 0 0;'
    els.myAccessList.appendChild(div)
  }
  renderSection('Entra roles (direct)',                       sectionHelp.entraDirect, entraDirect)
  renderSection('Azure RBAC (direct)',                        sectionHelp.azureDirect, azureDirect)
  renderSection('Entra (via PIM group)',                      sectionHelp.entra,       entraGroups)
  renderSection('Azure RBAC (via PIM group)',                 sectionHelp.azure,       azureGroups)
  renderSection('PIM for Groups (Workload RBAC delegations)', sectionHelp.workload,    workloadGroups)
}

function renderOneMyAccessRow(r) {
  const fmt = (iso) => iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' }) : null
  const start = fmt(r.startDateTime)
  const end   = fmt(r.endDateTime) || 'permanent'
  const times = start ? `${start} &rarr; ${end}` : `ends ${end}`
  const row = document.createElement('div')
  row.className = 'ma-row'
  const rk = r.rowKey || r.groupId
  row.dataset.rk = rk
  const ticked = myAccessSelected.has(rk) ? 'checked' : ''
  const isFav = isFavorite(rk)
  const starColor = isFav ? '#d4a72c' : '#bbb'
  const starChar  = isFav ? '\u2605' : '\u2606'
  row.innerHTML = `
    <div class="ma-head" style="display:flex;align-items:flex-start;gap:8px;">
      <input type="checkbox" class="ma-pick" data-pick-rk="${escapeHtml(rk)}" ${ticked} title="Tick to include in bulk deactivate." style="margin-top:3px;flex-shrink:0;">
      <span class="ma-fav-toggle" data-fav-rk="${escapeHtml(rk)}" title="${isFav ? 'Unfavorite' : 'Favorite -- pins this row to the top'}" style="cursor:pointer;color:${starColor};font-size:15px;line-height:1;margin-top:2px;flex-shrink:0;user-select:none;">${starChar}</span>
      <div style="flex:1;min-width:0;">
        <div class="ma-name">${escapeHtml(r.displayName || rk)}</div>
        <div class="ma-times">${times}</div>
      </div>
      <button class="ma-deactivate" data-deact-rk="${escapeHtml(rk)}" title="Drop this assignment early -- you'll lose access immediately. Confirm prompt before it runs."
        style="background:#ffffff;color:#cf222e;border:1px solid #cf222e;border-radius:4px;padding:3px 10px;font-size:11px;font-weight:600;cursor:pointer;flex-shrink:0;">Deactivate</button>
    </div>
    <div class="ma-roles" data-roles-for="${escapeHtml(rk)}"></div>
  `
  els.myAccessList.appendChild(row)
  const star = row.querySelector('.ma-fav-toggle')
  if (star) star.onclick = (e) => {
    e.stopPropagation()
    toggleFavorite(rk)
    if (myAccessCache?.rows) renderMyAccess(myAccessCache.rows)
  }
  // Wire the tick checkbox
  const pick = row.querySelector('.ma-pick')
  if (pick) {
    pick.addEventListener('change', (e) => {
      if (e.target.checked) myAccessSelected.add(rk)
      else myAccessSelected.delete(rk)
      updateBulkDeactivateButton()
    })
  }
  // Wire the deactivate button (single row) -- two-click confirm because
  // window.confirm() is silently suppressed inside MV3 action popups.
  const btn = row.querySelector('.ma-deactivate')
  if (btn) {
    let armed = false
    let armTimer = null
    const originalText = btn.textContent
    const originalStyle = btn.style.cssText
    btn.addEventListener('click', async (e) => {
      e.stopPropagation()
      if (!armed) {
        armed = true
        btn.textContent = 'Click again to confirm'
        btn.style.cssText = `${originalStyle};background:#cf222e;color:#ffffff;border-color:#cf222e;`
        armTimer = setTimeout(() => {
          armed = false
          btn.textContent = originalText
          btn.style.cssText = originalStyle
        }, 5000)
        return
      }
      if (armTimer) { clearTimeout(armTimer); armTimer = null }
      armed = false
      btn.style.cssText = originalStyle
      btn.disabled = true
      btn.textContent = 'Deactivating...'
      try {
        const fresh = await acquireGraphToken({ interactive: false })
        const tk = fresh?.accessToken
        if (!tk) throw new Error('Not signed in')
        if (r.kind === 'entraDirect') {
          await deactivateDirectEntraRole(tk, r.roleDefinitionId, r.directoryScopeId, 'User-initiated deactivation from PIM Activator')
        } else if (r.kind === 'azureDirect') {
          const arm = await getArmToken().catch(() => null)
          if (!arm) throw new Error('Azure RBAC deactivate needs an ARM token; re-sign in.')
          await deactivateDirectAzureRbac(arm, r.armScope, r.roleDefinitionId, r.principalId, 'User-initiated deactivation from PIM Activator')
        } else {
          await deactivateGroup(tk, r.groupId, 'User-initiated deactivation from PIM Activator')
        }
        btn.textContent = 'Deactivated'
        btn.style.background = '#dafbe1'
        btn.style.color = '#1a7f37'
        btn.style.borderColor = '#1a7f37'
        // Refresh My Access in a moment so the row drops out of the list
        setTimeout(async () => {
          myAccessCache = null
          const fr = await acquireGraphToken({ interactive: false })
          await loadMyAccessTab(fr?.accessToken, { force: true })
        }, 1200)
      } catch (err) {
        btn.disabled = false
        btn.textContent = 'Deactivate'
        alert(`Deactivation failed: ${err?.message || err}`)
      }
    })
  }
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
    // distinct role names (bundle groups can have 80+ roles),
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
  // My Access count is meaningful only AFTER the tab has been loaded at
  // least once (cache is populated). Until then, show no number rather than
  // a misleading "0" -- the user opens the tab, sees the real count, and
  // the badge stays accurate from then on.
  if (myAccessCache?.rows) {
    els.badgeMyAccess.textContent = String(myAccessCache.rows.length)
    els.badgeMyAccess.style.display = ''
  } else {
    els.badgeMyAccess.textContent = ''
    els.badgeMyAccess.style.display = 'none'
  }
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
    els.list.innerHTML = `<div class="empty">${eligibleRows.length ? 'No rows match the filter.' : 'No eligible PIM assignments for your account.'}</div>`
    updateCount()
    return
  }

  // Pull starred rows out into a top-level "Favorites" section that spans
  // ALL categories. Inside the per-category sections below, favorites are
  // skipped (they already appear at the top) so the same row doesn't show
  // twice. v1.4.2+ -- replaces the per-section favorites pinning that the
  // earlier 1.4.0 ship used.
  const favRows    = filtered.filter(r => isFavorite(r.rowKey || r.groupId))
  const nonFavRows = filtered.filter(r => !isFavorite(r.rowKey || r.groupId))

  // Direct (PIM v1) rows are categorised by their own .kind -- no regex
  // needed because the API tells us directly which surface they came from.
  // Group rows (PIM v2) keep the regex-driven categorisation since the only
  // signal we have is the displayName.
  const buckets = {
    favorites:   favRows,
    entraDirect: nonFavRows.filter(r => r.kind === 'entraDirect'),
    azureDirect: nonFavRows.filter(r => r.kind === 'azureDirect'),
    entra:       nonFavRows.filter(r => r.kind === 'group' && categoriseGroupByName(r.displayName) === 'entra'),
    azure:       nonFavRows.filter(r => r.kind === 'group' && categoriseGroupByName(r.displayName) === 'azure'),
    workload:    nonFavRows.filter(r => r.kind === 'group' && categoriseGroupByName(r.displayName) === 'workload')
  }

  function renderActivateRow(r) {
    const row = document.createElement('div')
    row.className = r.isActive ? 'row row-active-already' : 'row'
    if (r.isActive) row.style.cssText = 'opacity:0.55;background:#f6f8fa;'
    const activeBadge = r.isActive
      ? ' <span style="background:#dafbe1;color:#1a7f37;padding:1px 6px;border-radius:8px;font-size:10.5px;font-weight:600;margin-left:6px;">already active</span>'
      : ''
    // Only show "ends ..." for rows that are CURRENTLY ACTIVE -- that timer
    // is the activation expiry the user can extend or surrender. For ELIGIBLE
    // (not-yet-activated) rows, r.endDateTime is the eligibility expiry (when
    // PIM removes the entitlement entirely -- typically months/years out and
    // irrelevant to the activation decision). Showing it misled users into
    // thinking they were already activated.
    const endLabel = r.isActive
      ? (r.endDateTime
          ? new Date(r.endDateTime).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })
          : 'permanent')
      : null
    // Role preview: lines render once bulk pre-fetch attaches the data.
    // null = bulk fetch hasn't completed; show no line yet (silent loading).
    // [] = fetch done, group grants no roles of that type; skip.
    // v1.4.6+: show ALL roles + scopes per group, no roll-up. Role groups
    // in PIM4EntraPS routinely have 10-30+ nested task-group grants and
    // the operator needs to see every line to evaluate the activation.
    const entraPreview = (r.previewEntraRoles || [])
    const entraExtra   = 0
    const azurePreview = (r.previewAzureRoles || [])
    const azureExtra   = 0

    function roleLines(items, extra, label, color) {
      if (!items.length) return ''
      const lines = items.map(x => `<div style="color:${color};font-size:11px;line-height:1.4;">&#x21B3; ${escapeHtml(label)}: <strong>${escapeHtml(x.roleName)}</strong> <span style="color:#7d8590;">${escapeHtml(typeof x.scope === 'string' ? x.scope : '')}</span></div>`)
      if (extra > 0) lines.push(`<div style="color:#7d8590;font-size:11px;">&#x21B3; +${extra} more</div>`)
      return lines.join('')
    }

    // Show "Loading roles..." while bulk fetch is in progress so the user
    // can tell "background fetch happening" vs "this group genuinely has no
    // roles". Bulk fetch sets previewEntraRoles + previewAzureRoles to an
    // array (possibly empty) when it completes; both undefined means the
    // fetch hasn't fired yet for this row.
    // Direct (PIM v1) rows ARE the role -- no preview lines needed (those
    // were a "this group grants these roles" hint, irrelevant when the row
    // is the role itself). Group rows keep the bulk-fetched preview.
    const idAttr = r.rowKey || `group:${r.groupId}`
    let rolesHtml = ''
    if (r.kind === 'group') {
      const stillFetching = r.previewEntraRoles === undefined && r.previewAzureRoles === undefined
      if (stillFetching) {
        rolesHtml = `<div style="color:#7d8590;font-size:11px;font-style:italic;">&#x21B3; Loading roles...</div>`
      } else {
        const totalLines = entraPreview.length + azurePreview.length
        const isCollapsed = collapsedRows.has(idAttr)
        if (totalLines === 0) {
          rolesHtml = ''
        } else if (isCollapsed) {
          rolesHtml = `<div class="role-toggle" data-toggle-rk="${escapeHtml(idAttr)}" style="color:#0969da;font-size:11px;line-height:1.4;cursor:pointer;user-select:none;" title="Show the transitive roles this group grants.">&#x25B6; <strong>${totalLines} transitive role${totalLines === 1 ? '' : 's'}</strong> <span style="color:#7d8590;">(click to expand)</span></div>`
        } else {
          const toggle = `<div class="role-toggle" data-toggle-rk="${escapeHtml(idAttr)}" style="color:#0969da;font-size:11px;line-height:1.4;cursor:pointer;user-select:none;" title="Hide the transitive role list.">&#x25BC; <span style="color:#7d8590;">hide ${totalLines} transitive role${totalLines === 1 ? '' : 's'}</span></div>`
          rolesHtml = toggle +
            roleLines(entraPreview, entraExtra, 'Entra',      '#0969da') +
            roleLines(azurePreview, azureExtra, 'Azure RBAC', '#0969da')
        }
      }
    } else if (r.kind === 'entraDirect' && r.directoryScopeId && r.directoryScopeId !== '/') {
      // Resolve "/administrativeUnits/{guid}" to the AU display name when the
      // pre-resolve pass populated auNameCache. Falls back to the raw scope
      // when the lookup failed (e.g. permission denied on Directory.Read.All
      // for that AU) so the operator can still see what scope the eligibility
      // targets even if we can't name it.
      const scopeObj = parseDirectoryScopeSync(r.directoryScopeId)
      const scopeLabel = summariseScopes([scopeObj])
      rolesHtml = `<div style="color:#7d8590;font-size:11px;line-height:1.4;">&#x21B3; scope: <strong>${escapeHtml(scopeLabel)}</strong></div>`
    }

    const isFav = isFavorite(idAttr)
    // Filled star = favorite, outline star = not. Clicking toggles + persists.
    // Sort uses isFavorite() so favorited rows pin to the top of their section.
    const starColor = isFav ? '#d4a72c' : '#bbb'
    const starChar  = isFav ? '\u2605' : '\u2606'
    row.innerHTML = `
      <input type="checkbox" data-rk="${escapeHtml(idAttr)}" ${r.checked ? 'checked' : ''} ${r.isActive ? 'disabled' : ''}>
      <span class="fav-toggle" data-fav-rk="${escapeHtml(idAttr)}" title="${isFav ? 'Unfavorite' : 'Favorite -- pins this row to the top of its section'}" style="cursor:pointer;color:${starColor};font-size:15px;line-height:1;margin:1px 4px 0 0;user-select:none;">${starChar}</span>
      <div class="body">
        <div class="name" title="${escapeHtml(r.displayName || idAttr)}">${escapeHtml(r.displayName || idAttr)}${activeBadge}</div>
        ${endLabel ? `<div class="meta">ends ${escapeHtml(endLabel)}</div>` : ''}
        ${rolesHtml}
        <div class="status" data-rk-status="${escapeHtml(idAttr)}"></div>
      </div>
    `
    if (!r.isActive) {
      row.querySelector('input').onchange = (e) => { r.checked = e.target.checked; updateCount() }
    }
    const star = row.querySelector('.fav-toggle')
    if (star) star.onclick = (e) => {
      e.stopPropagation()
      toggleFavorite(idAttr)
      render() // re-render so the row jumps to the top of its section
    }
    const tog = row.querySelector('.role-toggle')
    if (tog) tog.onclick = (e) => {
      e.stopPropagation()
      const rk = tog.dataset.toggleRk
      if (collapsedRows.has(rk)) collapsedRows.delete(rk); else collapsedRows.add(rk)
      render()
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
      // 1) Active rows sink to the bottom (existing behaviour).
      if (!!a.isActive !== !!b.isActive) return a.isActive ? 1 : -1
      // 2) Recency/frequency. Direct rows have no groupId; rank by rowKey
      //    so the same sort still works without throwing on undefined.
      //    (Favorites no longer pin per-section -- they live in their own
      //    top-level "Favorites" section spanning every category.)
      const rank = activationRank(b.groupId || b.rowKey) - activationRank(a.groupId || a.rowKey)
      if (rank !== 0) return rank
      return (a.displayName || '').localeCompare(b.displayName || '')
    })
    for (const r of sorted) renderActivateRow(r)
  }

  // Favorites first -- single section spanning every category. Visually
  // separated from the rest by the existing section-header band. A bottom
  // divider is added below to make the break extra clear.
  renderActivateSection('\u2605 Favorites',                              buckets.favorites)
  if (buckets.favorites.length) {
    const div = document.createElement('div')
    div.style.cssText = 'border-top:3px double #d0d7de;margin:6px 0 0 0;'
    els.list.appendChild(div)
  }
  renderActivateSection('Entra roles (direct)',                          buckets.entraDirect)
  renderActivateSection('Azure RBAC (direct)',                           buckets.azureDirect)
  renderActivateSection('Entra roles (via PIM Group)',                   buckets.entra)
  renderActivateSection('Azure RBAC (via PIM Group)',                    buckets.azure)
  renderActivateSection('PIM for Groups (Workload RBAC delegations)',    buckets.workload)

  updateCount()
}
function updateCount() {
  const n = eligibleRows.filter(r => r.checked).length
  els.count.textContent = n ? `${n} selected` : 'Select one or more groups'
  els.activate.disabled = n === 0
}
function setStatus(rowKey, text, cls) {
  // v1.3.0+: rows render with data-rk-status (rowKey) instead of the
  // group-only data-gid-status. Accept either so callers that still pass a
  // bare groupId resolve correctly when given a "group:{gid}:member" rowKey.
  const el = document.querySelector(`[data-rk-status="${CSS.escape(rowKey)}"]`)
                || document.querySelector(`[data-gid-status="${CSS.escape(rowKey)}"]`)
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

  // Boot-phase progress bar -- indeterminate striped animation until we know
  // total groups. Hidden once the list renders (or on early-return error).
  const bootBp = document.getElementById('activate-boot-progress')
  const bootLabel = document.getElementById('activate-boot-progress-label')
  if (bootBp) bootBp.style.display = ''
  function setBootLabel(t) { if (bootLabel) bootLabel.textContent = t }
  function hideBootProgress() { if (bootBp) bootBp.style.display = 'none' }

  // Version badge is populated at popup-load now (top of file) so it's
  // visible on the sign-in screen too, not just after loaded() runs.

  // Self-heal: if the cached token is missing required scopes (admin re-
  // consented new perms after the user last signed in), force a reauth
  // before doing anything else. Avoids mysterious 403s later.
  const miss = missingScopes(token)
  if (miss.length) {
    els.status.textContent = `Token is missing ${miss.length} scope(s); refreshing sign-in...`
    hideBootProgress()
    return triggerInteractiveReauth(`Missing scopes: ${miss.join(', ')}`)
  }

  // Parallel: PIM-for-Groups eligibilities + currently-active memberships +
  // direct (PIM v1) Entra eligibilities + active direct Entra + Azure RBAC
  // eligibilities + active Azure RBAC. Some sources may 403 / 404 (tenant
  // doesn't use that path, or permission still propagating); each gets its
  // own catch so a single failure cannot wipe the whole list.
  setBootLabel('Loading eligible PIM delegations from Microsoft Graph + ARM...')
  let raw, activeRows, directEntra, activeDirectEntra, directAzure, activeDirectAzure
  let armTok = null
  try { armTok = await getArmToken() } catch { /* ARM optional -- Entra still works */ }
  try {
    [raw, activeRows, directEntra, activeDirectEntra, directAzure, activeDirectAzure] = await Promise.all([
      listEligibleForMe(token),
      listActiveGroupAssignmentsForMe(token).catch(() => []),
      listEligibleDirectEntraRolesForMe(token).catch(() => []),
      listActiveDirectEntraRolesForMe(token).catch(() => []),
      armTok ? listEligibleDirectAzureRbacForMe(armTok).catch(() => []) : Promise.resolve([]),
      armTok ? listActiveDirectAzureRbacForMe(armTok).catch(() => [])   : Promise.resolve([]),
    ])
  } catch (e) {
    hideBootProgress()
    if (e.stale) {
      els.status.textContent = `Token rejected by Graph; refreshing sign-in...`
      return triggerInteractiveReauth(`Graph error: ${e.message}`)
    }
    els.status.textContent = `Failed to list eligible groups: ${e.message}`
    els.status.classList.add('err')
    return
  }

  // Only early-return when ALL three sources are empty -- a user who has
  // zero PIM-for-Groups eligibilities (raw) might still have direct
  // (PIM v1) Entra or Azure RBAC eligibilities to display.
  if (!raw.length && !directEntra.length && !directAzure.length) {
    hideBootProgress()
    els.status.textContent = 'No eligible PIM assignments for your account.'
    return
  }

  // Build "active key" set so we can hide already-active eligibilities.
  const activeKeys = new Set(
    (activeRows || [])
      .filter(a => a.accessId === 'member')
      .map(a => `${a.groupId}|${a.accessId}`)
  )

  const uniqueGroupIds = [...new Set(raw.map(x => x.groupId))]
  setBootLabel(`Resolving ${uniqueGroupIds.length} group name(s)...`)
  const names = await hydrateGroupNames(token, uniqueGroupIds)

  const filterRe = cfg.groupNameFilter ? new RegExp(cfg.groupNameFilter, 'i') : null
  const stored = await getStored(['selectedIds', 'lastJustification', 'lastDurationHours', 'justificationHistory'])
  const preSelected = new Set(stored.selectedIds || [])

  // Populate the justification datalist (dropdown autocomplete) with the
  // user's most-recent reasons. Newest at the top -- the input itself is
  // pre-filled with the last one used so a single Enter re-uses it.
  const history = Array.isArray(stored.justificationHistory) ? stored.justificationHistory : []
  const dlist = document.getElementById('justification-history')
  if (dlist) {
    dlist.innerHTML = ''
    for (const h of history) {
      const opt = document.createElement('option')
      opt.value = h
      dlist.appendChild(opt)
    }
  }

  const groupRows = raw.map(x => ({
    kind: 'group',
    id: x.id,
    // rowKey deliberately drops accessId so favorites match the same row on
    // the My Access tab (which uses "group:{groupId}" too). In practice
    // PIM-for-Groups eligibilities are always accessId=member.
    rowKey: `group:${x.groupId}`,
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

  // Direct (PIM v1) Entra role eligibilities. Each row carries the role
  // definition id + the scope id we need for activation; the displayName is
  // the role's displayName (e.g. "Global Reader") so the bucket already has
  // a meaningful name without a regex pass.
  const activeDirectEntraKeys = new Set(
    (activeDirectEntra || []).map(a => `${a.roleDefinitionId}|${a.directoryScopeId || '/'}`)
  )
  const directEntraRows = (directEntra || []).map(x => ({
    kind: 'entraDirect',
    id: x.id,
    rowKey: `entraDirect:${x.roleDefinitionId}:${x.directoryScopeId || '/'}`,
    roleDefinitionId: x.roleDefinitionId,
    directoryScopeId: x.directoryScopeId || '/',
    displayName: x.roleDefinition?.displayName || x.roleDefinitionId,
    endDateTime: x.endDateTime,
    isActive: activeDirectEntraKeys.has(`${x.roleDefinitionId}|${x.directoryScopeId || '/'}`),
    checked: false
  }))

  // Pre-resolve any AU display names referenced by direct (PIM v1) Entra rows
  // -- otherwise the scope line renders as a raw "/administrativeUnits/{guid}"
  // path. Resolved names land in auNameCache; the render path picks them up
  // synchronously via parseDirectoryScopeSync.
  {
    const auIds = new Set()
    const auRe  = /^\/administrativeUnits\/([0-9a-fA-F-]{36})$/
    for (const r of [...directEntraRows, ...(directEntra || []).map(x => ({ directoryScopeId: x.directoryScopeId }))]) {
      const m = (r.directoryScopeId || '').match(auRe)
      if (m && !(m[1] in auNameCache)) auIds.add(m[1])
    }
    if (auIds.size) {
      await Promise.all([...auIds].map(id => resolveAuDisplayName(token, id).catch(() => null)))
    }
  }

  // Direct Azure RBAC role eligibilities. Each row carries the ARM scope +
  // role definition id (ARM-style fully-qualified ids). principalId comes
  // from the eligibility instance itself, not from currentAccount, because
  // the same eligibility might be granted to a group the user is in (group-
  // eligibility) -- the activate body wants the eligibility's principalId.
  const activeDirectAzureKeys = new Set(
    (activeDirectAzure || []).map(a => `${a.properties?.roleDefinitionId}|${a.properties?.scope || a._subscriptionId}`)
  )
  const directAzureRows = (directAzure || []).map(x => {
    const p = x.properties || {}
    const scope = p.scope || `/subscriptions/${x._subscriptionId}`
    const roleName = p.expandedProperties?.roleDefinition?.displayName
      || p.roleDefinitionId?.split('/').pop()
      || '(unknown role)'
    const scopeName = p.expandedProperties?.scope?.displayName || scope
    return {
      kind: 'azureDirect',
      id: x.name || x.id,
      rowKey: `azureDirect:${p.roleDefinitionId}:${scope}`,
      roleDefinitionId: p.roleDefinitionId,
      armScope: scope,
      principalId: p.principalId || currentAccount.localAccountId,
      displayName: `${roleName} @ ${scopeName}`,
      endDateTime: p.endDateTime,
      isActive: activeDirectAzureKeys.has(`${p.roleDefinitionId}|${scope}`),
      checked: false
    }
  })

  const allMapped = [...groupRows, ...directEntraRows, ...directAzureRows]
  const afterNameFilter = allMapped.filter(r => !filterRe || filterRe.test(r.displayName))
  // Sort: inactive (ready-to-activate) first, alphabetical; then active rows
  // at the bottom, also alphabetical. Lets the user see "what I already have"
  // without burying the actionable rows.
  eligibleRows = afterNameFilter.sort((a, b) => {
    if (!!a.isActive !== !!b.isActive) return a.isActive ? 1 : -1
    return (a.displayName || '').localeCompare(b.displayName || '')
  })

  els.just.value = stored.lastJustification ?? (cfg.defaultJustification || '')
  els.dur.value  = stored.lastDurationHours ?? (cfg.defaultDurationHours || 8)

  const readyCount  = eligibleRows.filter(r => !r.isActive).length
  const activeCount = eligibleRows.filter(r =>  r.isActive).length
  const activeNote  = activeCount > 0 ? ` (${activeCount} already active -- shown at bottom)` : ''
  els.status.textContent = `${readyCount} ready to activate${activeNote}.`
  els.toolbar.style.display = 'flex'
  els.footer.style.display = ''
  els.tabs.style.display = 'flex'
  hideBootProgress()   // group list is now visible; footer bulk-fetch bar takes over
  updateBadges()
  render()

  // ---- Background bulk fetch: roles for every eligible group ----------
  // UI is immediately interactive; rows re-render with role lines as data
  // arrives. Entra + Azure fetched IN PARALLEL with each other AND each
  // re-renders independently as soon as its data lands -- user sees Entra
  // lines first (faster Graph call), then Azure lines appear as ARG returns.
  //
  // Cache hit (1h TTL) shows everything instantly with zero network calls.
  ;(async () => {
    const groupIds = eligibleRows.map(r => r.groupId)
    if (!groupIds.length) return

    const cacheKey = `bulkRoles_v4_${currentAccount?.localAccountId || 'anon'}`
    const cached = await getStored([cacheKey])
    const fresh  = cached?.[cacheKey]?.ts && (Date.now() - cached[cacheKey].ts) < 60 * 60 * 1000

    // Convert raw role-assignment items to display rows -- ONE row per
    // (role, scope) pair so the user sees the FULL list of permissions the
    // group transitively grants, not a rolled-up summary. PIM4EntraPS role
    // groups commonly resolve to 10+ nested task groups, each scoped to a
    // different AU; the user needs every one of those visible to evaluate
    // "is this the right activation". Dedup identical (role, scope) pairs
    // so the same assignment surfacing through two transitive paths only
    // shows once.
    function buildEntraPreview(items, roleDefsMap) {
      const seen = new Set()
      const out = []
      for (const a of items) {
        const roleName = roleDefsMap[a.roleDefinitionId] || a.roleDefinitionId
        const scopeObj = parseDirectoryScopeSync(a.directoryScopeId)
        const scopeKey = scopeObj.kind === 'au'     ? `au:${scopeObj.auId}` :
                         scopeObj.kind === 'tenant' ? 'tenant' :
                         scopeObj.kind === 'other'  ? `other:${scopeObj.raw}` : 'unknown'
        const k = `${roleName}|${scopeKey}`
        if (seen.has(k)) continue
        seen.add(k)
        out.push({ roleName, scope: summariseScopes([scopeObj]) })
      }
      // Stable display order: alphabetical by role, then by scope label.
      out.sort((a, b) => (a.roleName || '').localeCompare(b.roleName || '')
                       || (a.scope || '').localeCompare(b.scope || ''))
      return out
    }
    async function attachEntra(bulkEntra, roleDefsMap) {
      // Pre-resolve any unknown AU display names so the preview can render
      // friendly labels instead of "scoped to N Administrative Units".
      if (token) {
        const auIds = new Set()
        for (const items of bulkEntra.values()) {
          for (const a of (items || [])) {
            const m = a.directoryScopeId?.match(/^\/administrativeUnits\/([0-9a-fA-F-]{36})$/)
            if (m && !(m[1] in auNameCache)) auIds.add(m[1])
          }
        }
        if (auIds.size) {
          await Promise.all([...auIds].map(id => resolveAuDisplayName(token, id).catch(() => null)))
        }
      }
      for (const r of eligibleRows) {
        const entra = bulkEntra.get(r.groupId) || []
        r.previewEntraRoles = buildEntraPreview(entra, roleDefsMap)
      }
      render()
    }
    // v1.4.7+: same one-line-per-(role,scope) treatment as Entra. Dedup
    // identical pairs (same role hit through 2 transitive paths). Format
    // the ARM scope through describeArmScope() so the user sees
    // "sub 'ACME Prod' / rg 'rg-platform-l1'" instead of a raw GUID path.
    function buildAzurePreview(items, subNameById) {
      const seen = new Set()
      const out = []
      for (const a of (items || [])) {
        const roleName = a.roleName || '(unknown role)'
        const rawScope = a.scope || '/'
        const k = `${roleName}|${rawScope}`
        if (seen.has(k)) continue
        seen.add(k)
        out.push({ roleName, scope: describeArmScope(rawScope, subNameById) })
      }
      out.sort((a, b) => (a.roleName || '').localeCompare(b.roleName || '')
                       || (a.scope || '').localeCompare(b.scope || ''))
      return out
    }
    function attachAzure(bulkAzure) {
      const subNameById = Object.fromEntries((armSubscriptionsCache || []).map(s => [s.id, s.name]))
      for (const r of eligibleRows) {
        r.previewAzureRoles = buildAzurePreview(bulkAzure.get(r.groupId) || [], subNameById)
      }
      render()
    }

    if (fresh) {
      // Cache hit: render both immediately, no network calls.
      attachEntra(new Map(cached[cacheKey].entra), cached[cacheKey].roleDefs || {})
      attachAzure(new Map(cached[cacheKey].azure))
      return
    }

    // Cache miss / stale: fire both in parallel; render each as it lands.
    let freshEntra = null, freshAzure = null, freshRoleDefs = null

    // Wire the progress bar -- visible at the top of the Activate panel
    // until both Entra + Azure complete.
    const totalUnits = groupIds.length + 1   // N per-group Entra calls + 1 ARG call
    // Track Entra + Azure counters separately and SUM them on every tick.
    // The Entra callback sets entraDone = done (overwrites); if we shared a
    // single doneUnits then Azure's "++" would be wiped by the next Entra
    // callback, leaving the bar stuck at 50/51 forever. Separate counters
    // make the order of completion irrelevant.
    let entraDone = 0
    let azureDone = 0
    const bp = document.getElementById('bulk-progress')
    const bpLabel = document.getElementById('bulk-progress-label')
    const bpCount = document.getElementById('bulk-progress-count')
    const bpBar   = document.getElementById('bulk-progress-bar')
    const bpShownAt = Date.now()
    function tickProgress(label) {
      if (!bp) return
      bp.style.display = ''
      const doneUnits = entraDone + azureDone
      const pct = totalUnits ? Math.round((doneUnits / totalUnits) * 100) : 0
      if (bpLabel) bpLabel.textContent = label ? `${label} ${pct}%` : `Fetching role assignments... ${pct}%`
      if (bpCount) bpCount.textContent = `${doneUnits} / ${totalUnits}`
      if (bpBar)   bpBar.style.width   = `${pct}%`
      if (doneUnits >= totalUnits) {
        // Keep the bar visible at 100% for at least 1.5s after first appearance
        // so the user actually SEES it (parallel fetches can finish in
        // ~300ms on small tenants -- a flash they'd miss).
        const elapsed = Date.now() - bpShownAt
        const hideDelay = Math.max(800, 1500 - elapsed)
        setTimeout(() => { if (bp) bp.style.display = 'none' }, hideDelay)
      }
    }
    tickProgress('Fetching role assignments...')

    const entraTask = (async () => {
      try {
        const [be, rd] = await Promise.all([
          bulkLoadEntraRolesForGroups(token, groupIds, (done, total) => {
            entraDone = done
            tickProgress('Fetching Entra roles...')
          }),
          loadRoleDefinitions(token).catch(() => ({ idToName: {} }))
        ])
        freshEntra    = be
        freshRoleDefs = rd.idToName || {}
        attachEntra(be, freshRoleDefs)
      } catch (e) { console.warn('[PIM Activator] bulk Entra fetch failed:', e?.message || e) }
    })()

    const azureTask = (async () => {
      try {
        const armToken = await getArmToken().catch(() => null)
        const ba = await bulkLoadAzureRolesForGroups(armToken, groupIds)
        freshAzure = ba
        attachAzure(ba)
      } catch (e) { console.warn('[PIM Activator] bulk Azure fetch failed:', e?.message || e) }
      finally { azureDone = 1; tickProgress('Fetching Azure RBAC...') }
    })()

    await Promise.all([entraTask, azureTask])

    // Persist combined snapshot (skip if either failed entirely)
    if (freshEntra && freshAzure) {
      try {
        await setStored({
          [cacheKey]: {
            ts: Date.now(),
            entra:    [...freshEntra],
            azure:    [...freshAzure],
            roleDefs: freshRoleDefs || {}
          }
        })
      } catch { /* storage quota or shutdown; ignore */ }
    }
  })()

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

  // ---- My Access bulk deactivate -----------------------------------------
  if (els.myAccessSelectAll) {
    els.myAccessSelectAll.onclick = () => {
      const rows = myAccessCache?.rows || []
      // Use rowKey (covers all kinds); fall back to groupId for older cache.
      for (const r of rows) myAccessSelected.add(r.rowKey || r.groupId)
      for (const cb of document.querySelectorAll('.ma-pick')) cb.checked = true
      updateBulkDeactivateButton()
    }
  }
  if (els.myAccessSelectNone) {
    els.myAccessSelectNone.onclick = () => {
      myAccessSelected.clear()
      for (const cb of document.querySelectorAll('.ma-pick')) cb.checked = false
      updateBulkDeactivateButton()
    }
  }
  if (els.myAccessDeactivateSelected) {
    // Two-click confirm (no native confirm() -- Chromium silently suppresses
    // window.confirm() in MV3 action popups, which made the button feel dead).
    // First click flips the label to "Click again to confirm"; second click
    // within 5s runs the bulk deactivate. Click outside / 5s timeout reverts.
    let bulkArmed = false
    let bulkArmTimer = null
    const bulkOriginalStyle = els.myAccessDeactivateSelected.style.cssText
    function disarmBulk() {
      bulkArmed = false
      if (bulkArmTimer) { clearTimeout(bulkArmTimer); bulkArmTimer = null }
      updateBulkDeactivateButton()
      els.myAccessDeactivateSelected.style.cssText = bulkOriginalStyle
    }
    els.myAccessDeactivateSelected.onclick = async () => {
      if (myAccessSelected.size === 0) return
      const rows = (myAccessCache?.rows || []).filter(r => myAccessSelected.has(r.rowKey || r.groupId))
      if (!bulkArmed) {
        bulkArmed = true
        els.myAccessDeactivateSelected.textContent = `Click again to confirm (${rows.length})`
        els.myAccessDeactivateSelected.style.cssText = `${bulkOriginalStyle};background:#cf222e;color:#ffffff;border-color:#cf222e;`
        bulkArmTimer = setTimeout(disarmBulk, 5000)
        return
      }
      if (bulkArmTimer) { clearTimeout(bulkArmTimer); bulkArmTimer = null }
      bulkArmed = false
      els.myAccessDeactivateSelected.style.cssText = bulkOriginalStyle
      els.myAccessDeactivateSelected.disabled = true
      els.myAccessDeactivateSelected.textContent = `Deactivating ${rows.length}...`
      let ok2 = 0, failed = 0
      for (const r of rows) {
        // Reflect per-row status on the button by writing the row name in the toolbar.
        try {
          const fresh = await acquireGraphToken({ interactive: false })
          const tk = fresh?.accessToken
          if (!tk) throw new Error('Not signed in')
          if (r.kind === 'entraDirect') {
            await deactivateDirectEntraRole(tk, r.roleDefinitionId, r.directoryScopeId, 'User-initiated bulk deactivation from PIM Activator')
          } else if (r.kind === 'azureDirect') {
            const arm = await getArmToken().catch(() => null)
            if (!arm) throw new Error('Azure RBAC deactivate needs an ARM token')
            await deactivateDirectAzureRbac(arm, r.armScope, r.roleDefinitionId, r.principalId, 'User-initiated bulk deactivation from PIM Activator')
          } else {
            await deactivateGroup(tk, r.groupId, 'User-initiated bulk deactivation from PIM Activator')
          }
          ok2++
          // Mark the row's per-row button as deactivated for visual feedback.
          // v1.3.0 changed the attribute from data-deact-gid (group only) to
          // data-deact-rk (rowKey) so direct rows also get visual feedback.
          const rk = r.rowKey || r.groupId
          const btn = document.querySelector(`button.ma-deactivate[data-deact-rk="${CSS.escape(rk)}"]`)
          if (btn) {
            btn.textContent = 'Deactivated'
            btn.disabled = true
            btn.style.background = '#dafbe1'
            btn.style.color = '#1a7f37'
            btn.style.borderColor = '#1a7f37'
          }
        } catch (e) {
          failed++
          console.warn(`bulk deactivate failed for ${r.groupId}:`, e?.message || e)
        }
      }
      els.myAccessDeactivateSelected.textContent = `${ok2} deactivated${failed ? `, ${failed} failed` : ''}`
      // Refresh the tab after a short delay so deactivated rows drop out.
      setTimeout(async () => {
        myAccessSelected.clear()
        myAccessCache = null
        const fr = await acquireGraphToken({ interactive: false })
        await loadMyAccessTab(fr?.accessToken, { force: true })
        updateBulkDeactivateButton()
      }, 1500)
    }
  }

  els.search.oninput  = render
  els.selectAll.onclick  = () => { eligibleRows.forEach(r => { if (!r.isActive) r.checked = true }); render() }
  els.selectNone.onclick = () => { eligibleRows.forEach(r => r.checked = false); render() }
  els.collapseAll.onclick = () => {
    // Add every group row's rowKey to the collapsed set. Per-row toggle keeps
    // working afterwards -- this is a bulk preset, not an exclusive mode.
    for (const r of eligibleRows) {
      if (r.kind === 'group') collapsedRows.add(r.rowKey || `group:${r.groupId}`)
    }
    render()
  }
  els.expandAll.onclick = () => { collapsedRows.clear(); render() }
  els.refresh.onclick = () => window.location.reload()

  els.activate.onclick = async () => {
    const just = els.just.value.trim()
    const dur  = parseFloat(els.dur.value)
    if (!just) { alert('Justification required.'); return }
    if (!(dur > 0)) { alert('Duration must be > 0.'); return }

    const selected = eligibleRows.filter(r => r.checked)
    // Push this justification to the top of the history (dedupe, max 10).
    // Datalist hydrates from this on next popup open.
    const histPrev = await getStored(['justificationHistory'])
    const prior = Array.isArray(histPrev.justificationHistory) ? histPrev.justificationHistory : []
    const nextHistory = [just, ...prior.filter(x => x && x !== just)].slice(0, 10)
    await setStored({
      selectedIds: selected.map(r => r.groupId),
      lastJustification: just,
      lastDurationHours: dur,
      justificationHistory: nextHistory
    })
    // Refresh the dropdown live so a second activation in the same session
    // sees the updated list without reopening the popup.
    const dlist2 = document.getElementById('justification-history')
    if (dlist2) {
      dlist2.innerHTML = ''
      for (const h of nextHistory) {
        const opt = document.createElement('option')
        opt.value = h
        dlist2.appendChild(opt)
      }
    }

    els.activate.disabled = true
    selected.forEach(r => setStatus(r.rowKey || r.groupId, 'queued...', 'pending'))

    let anySucceeded = false

    // Activate sequentially to be gentle on PIM / ARM throttling. The
    // dispatcher switches on r.kind:
    //   group       -> Graph POST assignmentScheduleRequests (PIM-for-Groups, v2)
    //   entraDirect -> Graph POST roleAssignmentScheduleRequests (PIM v1 direct)
    //   azureDirect -> ARM   PUT  roleAssignmentScheduleRequests/{guid} (PIM v1 direct Azure RBAC)
    for (const r of selected) {
      const rk = r.rowKey || r.groupId
      setStatus(rk, 'activating...', 'pending')
      try {
        // Re-acquire token per round in case the previous one expired mid-loop.
        const fresh = await acquireGraphToken({ interactive: false })
        const tk = fresh?.accessToken || token

        let res, statusOk, statusPending
        if (r.kind === 'entraDirect') {
          res = await activateDirectEntraRole(tk, r.roleDefinitionId, r.directoryScopeId, just, dur)
          statusOk      = res?.status === 'Provisioned' || res?.status === 'Granted'
          statusPending = !statusOk
        } else if (r.kind === 'azureDirect') {
          const arm = await getArmToken().catch(() => null)
          if (!arm) throw new Error('Azure RBAC activation needs an ARM token; re-sign in.')
          res = await activateDirectAzureRbac(arm, r.armScope, r.roleDefinitionId, r.principalId, just, dur)
          statusOk      = res?.properties?.status === 'Provisioned'
          statusPending = !statusOk
        } else {
          res = await activateGroup(tk, r.groupId, just, dur)
          statusOk      = res?.status === 'Provisioned' || res?.status === 'Granted'
          statusPending = !statusOk
        }

        if (statusOk) {
          setStatus(rk, `active for ${dur}h - see My Access tab`, 'ok')
        } else {
          setStatus(rk, `submitted - check My Access tab in a few seconds`, 'pending')
        }
        r.checked = false
        anySucceeded = true
        // Group activations recorded against groupId; direct activations
        // recorded against rowKey so the activation-history sort still works
        // (groups vs direct rows live in different buckets, no key collision).
        recordActivation(r.kind === 'group' ? r.groupId : rk)
      } catch (e) {
        setStatus(rk, e.message, 'err')
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
      await setStored({ selectedIds: eligibleRows.filter(r => r.checked && r.groupId).map(r => r.groupId) })
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
