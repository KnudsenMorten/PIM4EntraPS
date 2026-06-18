#Requires -Version 5.1
<#
.SYNOPSIS
    Static assertion that the PIM Manager front-end PANELS for the previously
    pending-GUI endpoints exist and call their backing endpoints (REQUIREMENTS.md
    s11). Complements Test-PimGuiEngineAlignment.ps1 (which proves no dead GUI /
    no un-whitelisted orphan): this pins the specific panels + their api() calls
    so a future edit can't silently drop a panel while still passing alignment.

    Static analysis only -- no live tenant, no server boot. Run standalone
    (exits 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$mgrDir   = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\pim-manager'
$htmlPath = Join-Path $mgrDir 'pim-manager.html'
T 'pim-manager.html present' (Test-Path -LiteralPath $htmlPath)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
$html = [System.IO.File]::ReadAllText($htmlPath)

# --- Tabs are declared -------------------------------------------------------
foreach ($tab in 'authoring','onboarding','roleperms','cutover') {
    T "tab declared: $tab" ($html -match ("data-tab=`"$tab`""))
    T "panel container present: ${tab}Tab" ($html -match ("id=`"${tab}Tab`""))
}

# --- Tab routing wires each panel renderer -----------------------------------
T "switchTab routes authoring -> renderAuthoring"  ($html -match "name === 'authoring'\s*\)\s*renderAuthoring")
T "switchTab routes onboarding -> renderOnboarding" ($html -match "name === 'onboarding'\s*\)\s*renderOnboarding")
T "switchTab routes roleperms -> renderRolePerms"   ($html -match "name === 'roleperms'\s*\)\s*renderRolePerms")
T "switchTab routes cutover -> renderCutover"       ($html -match "name === 'cutover'\s*\)\s*renderCutover")

# --- Each renderer exists ----------------------------------------------------
foreach ($fn in 'renderAuthoring','renderOnboarding','renderRolePerms','renderCutover') {
    T "renderer defined: $fn" ($html -match ("async function $fn\("))
}

# --- Each panel actually calls its backing endpoint(s) -----------------------
# Authoring (POST /api/authoring/*)
foreach ($ep in '/api/authoring/bulk-attach','/api/authoring/clone','/api/authoring/import-admins','/api/authoring/move-admin') {
    T "authoring calls $ep" ($html -match ("api\('POST',\s*'" + [regex]::Escape($ep)))
}
# Onboarding (POST /api/onboarding/*)
foreach ($ep in '/api/onboarding/guest-invite','/api/onboarding/self-service-toggle') {
    T "onboarding calls $ep" ($html -match ("api\('POST',\s*'" + [regex]::Escape($ep)))
}
# Role lookup (§28 [H9]). The permissions sub-mode calls GET /api/role-permissions;
# a near-miss now returns 200 with ranked candidates (no 503), so the GUI uses the
# api() helper and renders "did you mean..." instead of a not-connected panel.
T "role lookup calls GET /api/role-permissions" ($html -match "/api/role-permissions\?role=")
# Cutover (GET + POST /api/cutover)
T "cutover calls GET /api/cutover"  ($html -match "api\('GET',\s*'/api/cutover'")
T "cutover calls POST /api/cutover" ($html -match "api\('POST',\s*'/api/cutover'")

# --- Read-write + role gating: write panels are server+role gated -------------
# Each write renderer must short-circuit in static mode and gate on role.
T "authoring gated on isServer"   ($html -match "renderAuthoring[\s\S]{0,400}if \(!isServer\)")
T "authoring gated on role"       ($html -match "renderAuthoring[\s\S]{0,800}roleAtLeast\('Admin'\)")
T "onboarding gated on role"      ($html -match "renderOnboarding[\s\S]{0,800}roleAtLeast\('Admin'\)")
T "cutover gated on isServer"     ($html -match "renderCutover[\s\S]{0,400}if \(!isServer\)")
T "roleAtLeast helper present"    ($html -match "function roleAtLeast\(")

# --- Cutover ceremony: shows the gated stage flow ----------------------------
foreach ($stage in 'preflight','upgrade','import','set-source','re-preflight','finalize') {
    # The stage names come from the server (st.stages); the panel must reference
    # the ceremony's special-cased stages (import dry-run, finalize warning).
}
T "cutover surfaces the stage list (st.stages)" ($html -match "st\.stages")
T "cutover runs the next gated stage"           ($html -match "stage: next")
T "cutover finalize carries a danger confirm"   ($html -match "finalize[\s\S]{0,200}point of no return")

# --- Admin-naming rework (§17 / §11): AdminType + Environment selectors --------
# Create-admin wizard exposes BOTH selectors and stamps them on the staged row.
T "admin wizard has AdminType selector (wf-atype)"      ($html -match "id:'wf-atype'")
T "admin wizard has Environment selector (wf-env)"      ($html -match "id:'wf-env'")
T "admin wizard offers external-adminuser (x- prefix)"  ($html -match "external-adminuser")
T "admin wizard offers external-guest (g- prefix)"      ($html -match "external-guest")
T "admin wizard stages AdminType on the row"            ($html -match "AdminType:\s*s\.adminType")
T "admin wizard stages Environment on the row"          ($html -match "Environment:\s*s\.environment")
# Live derivation: name builder applies the admin-type prefix + environment suffix.
T "name builder reads adminTypePrefix"   ($html -match "function adminTypePrefix\(")
T "name builder reads environmentSuffix" ($html -match "function environmentSuffix\(")
T "live preview shows the prefix + suffix" (($html -match "Prefix \(from Admin type\)") -and ($html -match "Suffix \(from Environment\)"))
# Advanced View grid dropdowns for AdminType + Environment on the admins entity.
T "grid dropdown for AdminType on Account-Definitions-Admins"   ($html -match "col === 'AdminType' && base === 'Account-Definitions-Admins'")
T "grid dropdown for Environment on Account-Definitions-Admins" ($html -match "col === 'Environment' && base === 'Account-Definitions-Admins'")
# Settings naming panel manages the per-type prefixes + env suffixes.
T "settings has the admin-type prefix table (setAdminTypeTbl)" ($html -match "id=`"setAdminTypeTbl`"|setAdminTypeTbl")
T "settings has the environment suffix table (setEnvTbl)"      ($html -match "setEnvTbl")
T "settings saves prefixes & suffixes (setAdminNamingSave)"    ($html -match "setAdminNamingSave")
# "candidates" is gone from the ADMIN-naming UI copy (the unrelated graph
# assign-mode "candidates" link-target concept is left untouched).
T "no admin-candidate text remains" (-not ($html -match '[Aa]dmin[ -]?candidate'))

# --- Audit tab (read-only audit trail view) ----------------------------------
T "tab declared: audit"            ($html -match 'data-tab="audit"')
T "panel container present: auditTab" ($html -match 'id="auditTab"')
T "switchTab routes audit -> renderAudit" ($html -match "name === 'audit'\s*\)\s*renderAudit")
T "renderer defined: renderAudit"  ($html -match 'async function renderAudit\(')
T "audit calls GET /api/audit"     ($html -match "api\('GET',\s*'/api/audit")
T "audit gated on isServer"        ($html -match "renderAudit[\s\S]{0,400}if \(!isServer\)")
# Category filter chips mirror the server categories (no dead filter).
foreach ($cat in 'logins','delegations','accounts','approvals','engine','emergency') {
    T "audit category chip: $cat" ($html -match ("key:\s*'$cat'"))
}
# Free-text search + paging controls present.
T "audit has free-text search box (auditSearch)" ($html -match 'auditSearch')
T "audit has pager (auditPrev/auditNext)"        (($html -match 'auditPrev') -and ($html -match 'auditNext'))
T "audit sends category + q + page params"       ($html -match 'category=\$\{encodeURIComponent\(auditState\.category\)\}')

# --- Login capture makes the Logins category real (server side) --------------
$mgrPs = Join-Path $mgrDir 'Open-PimManager.ps1'
T 'Open-PimManager.ps1 present' (Test-Path -LiteralPath $mgrPs)
$ps = [System.IO.File]::ReadAllText($mgrPs)
T "server has Get-PimAuditCategory resolver" ($ps -match 'function Get-PimAuditCategory')
T "server has login-capture helper"          ($ps -match 'function Write-PimManagerLoginAudit')
T "server writes manager.login action"       ($ps -match "Action 'manager\.login'")
T "GET / calls login capture"                ($ps -match 'Write-PimManagerLoginAudit')
T "/api/audit supports category filter"      ($ps -match "\`$category")
T "/api/audit supports paging"               (($ps -match 'pageSize') -and ($ps -match 'pageCount'))

# --- Top banner: tenant identity + instance switcher laid out in order --------
# The right-hand banner cluster groups the connected tenant (NAME + GUID under a
# "Tenant" caption) and the instance switcher (under its own caption), filled
# from REAL data (PIM_DATA.tenantName / .tenantId). Assert the DOM STRUCTURE and
# the wiring so a future edit can't jumble or hardcode it.
T "banner right cluster present (brandRight)"        ($html -match 'id="brandRight"')
T "banner tenant group present (tenantGroup)"        ($html -match 'id="tenantGroup"')
T "banner tenant caption is 'Tenant'"                ($html -match '<span class="brand-cap">Tenant</span>')
T "banner has tenant NAME slot (tenantName)"         ($html -match 'id="tenantName"')
T "banner has tenant GUID slot (tenantGuid)"         ($html -match 'id="tenantGuid"')
# DOM ORDER inside the tenant group: caption -> NAME -> GUID (name before guid).
T "banner tenant order: Tenant caption -> name -> guid" `
    ($html -match 'brand-cap">Tenant</span>[\s\S]{0,120}id="tenantName"[\s\S]{0,80}id="tenantGuid"')
# Instance switcher sits in its own captioned group (labelled, not bare).
T "banner instance group present (instanceGroup)"    ($html -match 'id="instanceGroup"')
T "banner instance caption present (instanceLabel)"  ($html -match 'id="instanceLabel"')
T "banner instance switcher present (instancePick)"  ($html -match 'id="instancePick"')
# Tenant name + GUID are bound to REAL PIM_DATA fields (never hardcoded).
T "banner binds PIM_DATA.tenantName"                 ($html -match 'PIM_DATA\.tenantName')
T "banner binds PIM_DATA.tenantId"                   ($html -match 'PIM_DATA\.tenantId')
# Name+GUID together, GUID-only fallback, and hide-when-empty are all handled.
T "banner fills name+guid when both present"          ($html -match 'nmEl\.textContent = nm;\s*idEl\.textContent = id;')
T "banner falls back to GUID-only"                    ($html -match 'GUID only -> name slot')
T "banner hides tenant group when no context"         ($html -match "grp\.style\.display = 'none'")
# mode | source | generated stays one tidy non-wrapping line.
T "tabRight status line is nowrap"                    ($html -match '#tabRight\s*\{[^}]*white-space:nowrap')

# --- Role Lookup (§28 [H9]): three sub-modes + typo tolerance + reverse/compare ---
# (a) The upgraded tab offers what-a-role-can-do, who-can-activate, and compare.
T "role lookup has three sub-modes"                  ($html -match 'id="rlModePerms"' -and $html -match 'id="rlModeReverse"' -and $html -match 'id="rlModeCompare"')
T "role lookup names allowedResourceActions"          ($html -match 'allowedResourceActions')
T "role lookup states it is read-only"               ($html -match 'renderRolePerms[\s\S]{0,1400}read-only')
# (b) Typo tolerance: a near-miss is handled as ranked "did you mean..." candidates
#     (matched===false), NOT a 503/not-connected error panel.
T "role lookup renders did-you-mean candidates"      ($html -match 'function didYouMean\(')
T "role lookup handles matched===false gracefully"   ($html -match 'data\.matched === false')
T "role lookup candidate chips are clickable"        ($html -match "class=.rlCand")
# (c) Reverse lookup (who can activate) + role compare are wired to their endpoints.
T "role lookup reverse calls /api/role-lookup/reverse" ($html -match '/api/role-lookup/reverse\?role=')
T "role lookup compare calls /api/role-lookup/compare" ($html -match '/api/role-lookup/compare\?roleA=')
T "role lookup reverse shows the activation path"     ($html -match 'rc\.pathText')
# (d) The resolved (matched) path still renders the grouped/flat actions.
T "role lookup renders resolved permissions"          ($html -match 'data && data\.permissions')

# --- Governance: Audit teaser REMOVED (dedicated Audit tab owns it) ----------
# The Governance tab must no longer render its own audit section/teaser. The
# dedicated Audit tab (renderAudit) is untouched -- only the redundant
# Governance copy is gone. Pin both: renderGovernance has no audit fetch/teaser,
# while the dedicated Audit tab still exists.
$govBlock = ''
# From the start of renderGovernance up to the next top-level function definition.
if ($html -match 'async function renderGovernance\([\s\S]*?(?=\n\s*//[^\n]*\n\s*async function |\n\s*async function |\n\s*function )') { $govBlock = $Matches[0] }
T 'governance block extracted'                       ($govBlock.Length -gt 0)
T 'governance no longer fetches /api/audit'          (-not ($govBlock -match "api\('GET',\s*'/api/audit"))
T 'governance no longer renders an Audit trail teaser' (-not ($govBlock -match '>Audit trail<'))
T 'governance no longer has an Open-the-Audit-tab button' (-not ($govBlock -match 'govOpenAudit'))
# Dedicated Audit tab still present + wired (must NOT be removed).
T 'dedicated Audit tab still declared'               ($html -match 'data-tab="audit"')
T 'dedicated renderAudit still defined'              ($html -match 'async function renderAudit\(')

# --- Governance: GUI-driven mail-template customization (no rebuild) ----------
# Mail templates section lets an Admin view/edit/reset the .custom override in the
# GUI, persisted to the store the engine reads. Pin the panel + its endpoints.
T 'governance mail section still present'             ($html -match '>Mail templates<')
T 'mail panel has an inline editor container'        ($html -match 'id="govMailEditor"')
T 'mail panel renders per-template Edit buttons'     ($html -match 'class="govMailEdit"')
T 'mail panel renders Reset buttons'                 ($html -match 'class="govMailReset"')
T 'mail edit is Admin-gated in the GUI'              ($html -match "canMailEdit\s*=\s*roleAtLeast\('Admin'\)")
T 'mail GET one calls /api/mail-template?type='      ($html -match "api\('GET',\s*'/api/mail-template\?type=")
T 'mail SAVE calls PUT /api/mail-template'           ($html -match "api\('PUT',\s*'/api/mail-template'")
T 'mail RESET calls DELETE /api/mail-template'       ($html -match "api\('DELETE',\s*'/api/mail-template\?type=")
T 'mail editor offers a Save override button'        ($html -match 'id="govMailSave"')
T 'mail editor offers load-shipped-default'          ($html -match 'id="govMailRevert"')
# Server side: the three verbs + the store-backed persistence + the source field.
T "server has GET /api/mail-template handler"        ($ps -match "'/api/mail-template'\s+-and\s+\`$method\s+-eq\s+'GET'")
T "server has PUT /api/mail-template handler"        ($ps -match "'/api/mail-template'\s+-and\s+\`$method\s+-eq\s+'PUT'")
T "server has DELETE /api/mail-template handler"     ($ps -match "'/api/mail-template'\s+-and\s+\`$method\s+-eq\s+'DELETE'")
T "server persists override to the store"            ($ps -match "Set-PimManagerSetting -Name 'MailTemplateOverrides'")
T "server lists templates with a source field"       ($ps -match 'source\s*=\s*\$source')
T "server mirrors override into the live engine global" ($ps -match "PIM_NamingConventions\['MailTemplateOverrides'\]")

# --- Settings tab: imports, AD OU placement, TagPrefixToCsv removal (§11) -----
# Import departments from Entra (existing) + the NEW import approvers/owners from
# CSV (button + endpoint), AD OU placement card (PathAdmins/PathAdminsL0T0), and
# the removal of TagPrefixToCsv from the Settings editor.
T "settings: import departments button (setDeptsImport)"        ($html -match 'id="setDeptsImport"')
T "settings: dept import calls POST /api/settings/departments/import" ($html -match "api\('POST',\s*'/api/settings/departments/import'")
T "settings: import approvers CSV button (setApprCsvImport)"     ($html -match 'id="setApprCsvImport"')
T "settings: approver CSV file input (setApprCsvFile)"          ($html -match 'id="setApprCsvFile"')
T "settings: approver import calls POST /api/settings/approvers/import" ($html -match "api\('POST',\s*'/api/settings/approvers/import'")
T "settings: AD OU placement card has PathAdmins input"         ($html -match 'id="setOuPathAdmins"')
T "settings: AD OU placement card has PathAdminsL0T0 input"     ($html -match 'id="setOuPathAdminsL0T0"')
T "settings: AD OU placement save button (setOuSave)"           ($html -match 'id="setOuSave"')
# Owner vs Initial clarification copy is present in the Settings tab.
T "settings: clarifies {Owner} token = initials"               ($html -match "owner's <u>initials</u>")
# TagPrefixToCsv is hidden from the Settings naming editor (still allowed elsewhere
# in the Authoring panel). The Settings editor must declare it in its hide list.
T "settings: TagPrefixToCsv hidden from naming editor"         ($html -match "NAMING_HIDE_KEYS[\s\S]{0,120}TagPrefixToCsv")
# Server: the new approver-CSV import endpoint + engine apply are wired.
T "server: /api/settings/approvers/import endpoint"            ($ps -match "/api/settings/approvers/import")
T "server: calls Import-PimApproversFromCsv"                   ($ps -match 'Import-PimApproversFromCsv')

# --- In-context guidance + consistent empty/loading/error states (s28d) -------
# A thin, consistent UX layer over the existing tabs: every major tab gets a
# collapsible "what-this-is + how-to" guidance banner, and renderers use shared
# loading/empty/error helpers so a panel is never blank or shows a raw error.
# GUI-only -- no new endpoints (Test-PimGuiEngineAlignment stays green).
# CSS hooks for the guidance banner + the three consistent states are present.
T "css: .tab-guide guidance banner styled"        ($html -match '\.tab-guide\s*\{')
T "css: .pim-state base block styled"             ($html -match '\.pim-state\s*\{')
T "css: .pim-state.loading variant"               ($html -match '\.pim-state\.loading\s*\{')
T "css: .pim-state.empty variant"                 ($html -match '\.pim-state\.empty\s*\{')
T "css: .pim-state.error variant"                 ($html -match '\.pim-state\.error\s*\{')
# The guidance registry + the helpers exist.
T "guidance registry present (TAB_GUIDANCE)"      ($html -match 'var TAB_GUIDANCE\s*=')
T "guidance builder present (tabGuidanceHtml)"    ($html -match 'function tabGuidanceHtml\(')
T "guidance injector present (injectTabGuidance)" ($html -match 'function injectTabGuidance\(')
T "state helper: stateLoading"                    ($html -match 'function stateLoading\(')
T "state helper: stateEmpty"                      ($html -match 'function stateEmpty\(')
T "state helper: stateError"                      ($html -match 'function stateError\(')
# switchTab injects the guidance banner (so every tab carries it).
T "switchTab calls injectTabGuidance"             ($html -match 'function switchTab\([\s\S]{0,400}injectTabGuidance\(name\)')
# Injection is idempotent (re-entering a tab won't duplicate the banner) and is
# prepended as the panel's first child (survives renderer body rewrites).
T "injection guards against duplicates"           ($html -match "injectTabGuidance\([\s\S]{0,400}querySelector\(':scope > \.tab-guide'\)")
T "injection prepends into the panel"             ($html -match 'insertBefore\(node, panel\.firstChild\)')
# The banner is a collapsible <details> with the what + how-to copy.
T "banner is a collapsible <details>"             ($html -match "class=`"tab-guide`"")
T "banner carries a 'what' line (tg-what)"        ($html -match "class='tg-what'|tg-what")
T "banner carries 'how-to' steps (tg-how)"        ($html -match 'tg-how')
# Every major tab has a guidance entry in the registry (each is what+how).
foreach ($tab in 'home','map','new','validate','save','revoke','approvals','accessreview','grid','authoring','onboarding','roleperms','governance','audit','reports','conformance','cutover','jobs','settings','support') {
    T "guidance entry for tab: $tab" ($html -match ("\b" + [regex]::Escape($tab) + ":\s*\{\s*title:"))
}
# Tier/plane legend is reused inside guidance for the tabs that use that
# vocabulary (Map, Role Lookup, Reports) via the shared homeLegendHtml().
T "guidance reuses the tier/plane legend"         ($html -match "g\.legend && typeof homeLegendHtml === 'function'")
T "map guidance flags the legend"                 ($html -match "map:\s*\{[\s\S]{0,400}legend:\s*true")
T "roleperms guidance flags the legend"           ($html -match "roleperms:\s*\{[\s\S]{0,400}legend:\s*true")
T "reports guidance flags the legend"             ($html -match "reports:\s*\{[\s\S]{0,400}legend:\s*true")
# Major renderers route their top-level load failure through the shared
# stateError() helper (consistent error rendering, no raw error string).
foreach ($who in 'Failed to load overview','Failed to load templates','Failed to load settings','Could not load approvals','Could not load access reviews','Could not load audit trail','Failed to load cutover state','Failed to load jobs') {
    T "stateError used for: $who" ($html -match ("stateError\('" + [regex]::Escape($who) + "'"))
}
# No retrofitted renderer still emits the old raw-coloured error div for these.
T "no raw error div left for overview"            (-not ($html -match "color:#cf222e`">Failed to load overview"))
T "no raw error div left for audit trail"         (-not ($html -match "color:#cf222e`">Could not load audit trail"))

# --- FLEET conformance view (REQUIREMENTS.md s28 [H8]) -------------------------
# The Template Rollout tab gains a 'This tenant' / 'Fleet (all tenants)' toggle and a
# tenants x templates matrix + ring-wide rollout view, engine-backed via the two new
# endpoints. Assert the renderers + their wiring exist (no dead control).
T "fleet: renderFleetConformance defined"         ($html -match 'function renderFleetConformance')
T "fleet: confView toggle helper defined"         ($html -match 'function confViewToggle')
T "fleet: view toggle is wired"                   ($html -match 'function wireConfViewToggle')
T "fleet: tenant view renders the toggle"         ($html -match "confViewToggle\('tenant'\)")
T "fleet: matrix calls /api/conformance/fleet"    ($html -match "api\('GET',\s*'/api/conformance/fleet'\)")
T "fleet: ring plan calls /api/conformance/ring-plan" ($html -match "/api/conformance/ring-plan\?template=")
T "fleet: matrix load error via stateError"       ($html -match "stateError\('Failed to load the fleet matrix'")
T "fleet: ring-plan renderer defined"             ($html -match 'function loadFleetRingPlan')

# --- Per-entry ring control (REQUIREMENTS.md s11) ------------------------------
# The Template Rollout per-entry matrix gains a SuperAdmin ring <select> that
# drives POST /api/conformance/promote (-> Set-PimEntryRing). Assert the widget,
# the SuperAdmin gate, the promote call + the revert-on-failure exist (no dead /
# ungated control, no orphan endpoint).
T "ring: confPromote defined"                     ($html -match 'function confPromote')
T "ring: confPromote calls /api/conformance/promote" ($html -match "api\('POST',\s*'/api/conformance/promote'")
T "ring: matrix has a per-entry ring <select>"    ($html -match "class=`"confRing`"")
T "ring: ring control SuperAdmin-gated"           ($html -match "roleAtLeast\('SuperAdmin'\)" -and $html -match 'canPromote')
T "ring: matrix has a Ring column header"          ($html -match '>Ring<')
T "ring: ring <select> change is wired to confPromote" ($html -match "\.confRing'\)\.forEach\(sel => sel\.onchange")
T "ring: confPromote reverts dropdown on failure"  ($html -match 'sel\.value = String\(prev\)')

# --- §26d UX polish: a tooltip on EVERY nav tab + responsive nav --------------
# Every top-level nav tab in the flat #tabs strip must carry a title= tooltip so
# the control explains itself; the grouped nav copies the flat tab's title onto
# its menu item (buildNavGroups: `if (tabEl.title) item.title = tabEl.title`), so
# one tooltip per flat tab covers both navigations. Extract each
# `<div class="tab" ...>` element and assert it has a non-empty title=.
$allTabs = 'home','new','map','validate','save','revoke','approvals','accessreview','grid','authoring','onboarding','roleperms','governance','audit','reports','conformance','cutover','jobs','settings','support'
foreach ($tab in $allTabs) {
    # The tab <div> for this data-tab, up to its closing '>'. Order of attributes
    # varies (active/title before or after data-tab), so match the whole opening tag.
    $tagMatch = [regex]::Match($html, '<div class="tab[^"]*"[^>]*data-tab="' + [regex]::Escape($tab) + '"[^>]*>')
    if (-not $tagMatch.Success) {
        # active tab puts class="tab active"; data-tab may precede title -> also try the generic per-line grab.
        $tagMatch = [regex]::Match($html, '<div class="tab[^>]*data-tab="' + [regex]::Escape($tab) + '"[^>]*>')
    }
    $hasTitle = $tagMatch.Success -and ($tagMatch.Value -match 'title="[^"]{8,}"')
    T "nav tab has a tooltip: $tab" $hasTitle
}
# The grouped nav mirrors the flat tab's tooltip onto its dropdown item.
T "grouped nav copies the flat tab's tooltip" ($html -match 'if \(tabEl\.title\) item\.title = tabEl\.title')
# Responsive nav: progressive compaction down to phone width. The flat strip and
# the grouped nav both carry media-query steps; the grouped nav wraps to an
# accordion at narrow widths and there is an explicit phone (~560px) breakpoint.
T "responsive: flat strip compacts at <=900px"        ($html -match '@media \(max-width:900px\)')
T "responsive: grouped nav wraps to accordion <=880px" ($html -match '@media \(max-width:880px\)[\s\S]{0,200}#navGroups \{ flex-wrap:wrap')
T "responsive: explicit phone breakpoint (<=560px)"   ($html -match '@media \(max-width:560px\)')
T "responsive: phone nav stacks groups full-width"    ($html -match '@media \(max-width:560px\)[\s\S]{0,400}\.nav-group \{ flex:1 1 100%')
T "responsive: phone status line wraps (not clipped)" ($html -match '@media \(max-width:560px\)[\s\S]{0,500}#tabRight \{[^}]*white-space:normal')

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
