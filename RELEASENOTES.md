# Release notes for PIM4EntraPS

## v2.4.27

Latest 30 commits touching SOLUTIONS/PIM4EntraPS/ in the upstream monorepo monorepo:

- release: PIM4EntraPS v2.4.27 - Activate tab smart sort (recency 2x + count 1x, decays linearly over 30d, cap at 20 activations); persisted in chrome.storage.local (594490bf)
- release: PIM4EntraPS v2.4.26 - drop 'member' word + show date+time for activation expiry on both tabs (d7f95cfc)
- release: PIM4EntraPS v2.4.25 - 3-bucket categorisation on both Activate + My Access tabs, configurable per customer via entraGroupRegex/azureGroupRegex (chrome.storage.managed) (adaa201b)
- release: PIM4EntraPS v2.4.24 - already-active groups sorted to bottom of Activate tab (greyed + badge + disabled checkbox) (2c1e982c)
- release: PIM4EntraPS v2.4.23 - loading message 'Loading your PIM delegations ... Please Wait' (was 'Loading eligible groups...') (7d4f6383)
- release: PIM4EntraPS v2.4.22 - Azure RBAC iterates user subscriptions instead of tenant-root (fixes 403 AuthorizationFailed) (5a5817ea)
- release: PIM4EntraPS v2.4.21 - popup width 980px -> 800px (980 exceeded Chromium popup max, hid Sign in button offscreen) (bb8585b7)
- release: PIM4EntraPS v2.4.20 - wider popup (980px) + Re-sign in auto-launches OAuth + Azure RBAC consent banner with 1-3 min propagation note (3c6ab56b)
- fix(PIM4EntraPS): Update-PimActivatorDev.ps1 drops `ConvertFrom-Json -Depth` (PS 5.1 incompatible) (9ae24485)
- release: PIM4EntraPS v2.4.19 - skip empty subsections + 3-category grouping in My Access tab (Entra / Azure / Workload) (0c799e60)
- release: PIM4EntraPS v2.4.18 - Azure RBAC visible in My Access tab + collapse for long Entra role lists (1f7def50)
- release: PIM4EntraPS v2.4.17 - AU names resolve via AdministrativeUnit.Read.All + sort by activation time DESC + persistent AU cache + Update-PimActivatorDev.ps1 helper (b502f337)
- release: PIM4EntraPS v2.4.16 - popup UX: hide AU GUIDs + group identical roles + 'Re-sign in' instead of 'Auto-fix permissions' + auto-switch to My Access + auto-uncheck activated rows (5f7a664a)
- release: PIM4EntraPS v2.4.15 - CRITICAL FIX popup JWT decode bug caused infinite "missing scopes" reauth loop + Set-PimActivatorPolicy-Intune.ps1 Platform Script (66f07cfe)
- release: PIM4EntraPS v2.4.14 - popup light theme (white+blue) + simplified not-configured text + ext v0.3.0->0.4.0 + correct Intune deployment guidance (b024bd79)
- release: PIM4EntraPS v2.4.13 - CRX bundles placeholder config.js (no maintainer-tenant leak into customer installs) + ext ver 0.2.0 -> 0.3.0 (b3d55092)
- release: PIM4EntraPS v2.4.12 - Intune-first deployment (-PrintIntuneConfig mode + HKCU-default -PushPolicyScope) (d65821df)
- release: PIM4EntraPS v2.4.11 - Activator popup: My Access tab + token self-heal + Auto-fix button + hide-already-active (db8893b1)
- release: PIM4EntraPS v2.4.10 - Activator popup: My Access tab + token self-heal + Auto-fix button + hide-already-active (96b0c313)
- release: PIM4EntraPS v2.4.9 - switch CRX hosting to GitHub Pages + Chrome support + Install->Deploy renames + SPA URI fix (E2E proven) (5e263602)
- release: PIM4EntraPS v2.4.8 - all-in-one Azure CRX hosting in Setup-PimActivator.ps1 + manifest schema fix + Test-PimActivatorFlow.ps1 (5adbd277)
- release: PIM4EntraPS v2.4.7 - finish wiring v2.4.4's 4-method auth into community launchers + README catch-up (95a1ab25)
- release: PIM4EntraPS v2.4.6 - fully-unattended activator deployment via bootstrap SPN (Intune-friendly) (6841d152)
- release: PIM4EntraPS v2.4.5 - turnkey PIM Activator install: one-command orchestrator + pinned extension identity + icons (4a26958d)
- release: PIM4EntraPS v2.4.4 - port SI's 4-mode launcher auth + solution-wide config + new Grant-PimEngineAdminConsent helper (41e64c94)
- release: PIM4EntraPS v2.4.3 - docs: README full feature inventory (41 bullets with shipped/partial/roadmap badges) (0016c32c)
- release: PIM4EntraPS v2.4.2 - new Revoke tab in PIM Manager GUI for bulk-revoke of active activations (5c71b61e)
- release: PIM4EntraPS v2.4.1 - wire PIM-for-Groups preload into Baseline + swap per-row eligibility-lookup call-sites (31cdfe5a)
- release: PIM4EntraPS v2.4.0 - perf overhaul: cached group resolution + tenant-wide preload helpers + Azure token reuse (ea55e28f)
- release: PIM4EntraPS v2.3.2 - perf + logging hotfix from function audit (Graph + Azure) (d40b311c)

---

# Release notes -- PIM4EntraPS

> **Curated changelog.** The publish workflow auto-prepends recent monorepo commits as a raw activity log; this file is the human-friendly narrative on top.

---

## v2.4.27 -- Activate tab learns your habits: most-recent / most-frequent activations bubble to the top of each bucket

The popup now tracks every successful activation in `chrome.storage.local` (`activationHistory: { groupId: { count, lastActivated } }`). The Activate tab uses a composite score (recency dominates, count tiebreaks) to sort within each of the 3 buckets, so the groups you activate every morning stay at the top of each section. Groups you've never activated stay alphabetical, falling to the bottom of the "ready" rows.

Implementation notes:
- Recency component decays linearly to zero over 30 days; a group activated today scores 2.0, one activated 15 days ago scores 1.0, 30+ days ago scores 0.
- Count component caps at 20 activations -- a long-tail "activated 200 times last year" group can't completely outrank a fresh one-off; recent wins.
- Already-active rows still go at the bottom (greyed + badge from v2.4.24); the new sort only reorders the "ready to activate" rows within each bucket.
- No UI changes -- the smart sort is invisible. Users just notice the popup "remembers" their habits.

Manifest 0.4.12 -> 0.4.13.

---

## v2.4.26 -- Drop redundant "member" word; show date+time for activation expiry

Two text cleanups:

- **Activate tab** row meta line was `member . ends 3/9/2027`. Dropped "member" (always the same word for PIM-for-Groups, pure noise) and switched from `toLocaleDateString()` to `toLocaleString({dateStyle:'short', timeStyle:'short'})` so the user sees exactly when their activation expires (e.g. `ends 3/9/27, 11:30 PM`).
- **My Access tab** row times line was `member since 5/22/2026, 11:30:43 PM . expires 5/22/2027, 11:30:42 PM`. Compacted to `5/22/26, 11:30 PM -> 5/22/27, 11:30 PM` (start arrow end). Same data, half the width, no redundant labels.

Manifest 0.4.11 -> 0.4.12.

---

## v2.4.25 -- Activate + My Access tabs both use 3-bucket categorisation by name (configurable per customer via chrome.storage.managed)

Both tabs now group memberships into three sections:

1. **Entra (M365) roles** -- default regex `Entra` matches PIM-Entra-*, MyOrg-Entra-Admins, etc.
2. **Azure RBAC** -- default regex `(AzRes|Azure)` matches PIM-AzRes-*, *-Azure-*, etc.
3. **PIM for Groups (workload)** -- everything else (Defender XDR, Intune, Power BI workspaces, custom apps, etc.)

Categorisation happens INSTANTLY (regex on group displayName) -- no waiting for Graph queries. Previously the My Access tab (v2.4.19) waited for all per-row role queries to complete before showing section headers; with 15+ groups that took 5-10 seconds.

### Configurable per customer

Different customers use different naming conventions (2linkit uses `PIM-Entra-*` / `PIM-AzRes-*`; others might use `AAD-Admin-*` / `Az-RBAC-*`; some have no convention at all). Two new optional `chrome.storage.managed` fields control the bucketing:

- `entraGroupRegex` -- regex (case-insensitive) for the Entra bucket. Default `Entra`.
- `azureGroupRegex` -- regex (case-insensitive) for the Azure bucket. Default `(AzRes|Azure)`.

Pushed via the same Intune Custom Configuration Profile / Platform Script that already carries tenantId + clientId. `managed_schema.json` declares both as optional strings; `Set-PimActivatorPolicy-Intune.ps1` accepts two new variables ($EntraGroupRegex / $AzureGroupRegex) that customers can edit per-tenant before uploading the script.

### Role-data fallback for customers with no naming convention

If a group's name doesn't match EITHER regex, the popup falls back to inspecting whatever role data has been loaded for that row on the My Access tab:
- has Azure RBAC roles -> Azure bucket
- has Entra roles -> Entra bucket
- has neither (or not loaded yet) -> PIM for Groups bucket

On the Activate tab we don't query per-group roles (would be 30+ Graph calls per popup-open), so unmatched groups default to PIM for Groups. Customers with arbitrary naming should set the regexes to match their convention.

Manifest 0.4.10 -> 0.4.11.

---

## v2.4.24 -- Already-active groups sorted to bottom of Activate tab (greyed-out with "already active" badge) instead of hidden

v2.4.10 introduced "hide already-active eligibilities". Customer feedback: hiding lost visibility of "what do I already have". v2.4.24 changes the behavior to:

- Show ALL eligibilities (no hiding)
- Sort: ready-to-activate rows first (alphabetical), then already-active rows at the bottom (also alphabetical)
- Already-active rows render with opacity 0.55, light grey background, "already active" green pill badge after the group name, and a disabled checkbox -- no accidental re-activate, but still visible for context
- Select All button skips already-active rows
- Status line: "26 ready to activate (12 already active -- shown at bottom)" instead of the old "(N already active -> My Access)"

Manifest 0.4.9 -> 0.4.10.

---

## v2.4.23 -- Loading message: "Loading your PIM delegations ... Please Wait" (was "Loading eligible groups...")

Per customer request. Friendlier copy for end-users who don't think of their access in API terms ("eligible groups" sounds technical; "PIM delegations" matches how customers actually talk about it).

Manifest 0.4.8 -> 0.4.9.

---

## v2.4.22 -- Azure RBAC query iterates user's subscriptions instead of tenant-root (was 403 for non-tenant-readers)

v2.4.20 / .21 queried Azure RBAC at tenant-root scope (`https://management.azure.com/providers/Microsoft.Authorization/roleAssignments`). That endpoint requires the caller to have read permission at TENANT ROOT scope, which most users never have -- only Global Admin with "elevated access" toggled on, or someone explicitly assigned a role at tenant scope. Every regular user (including admins scoped to subscriptions) got HTTP 403 `AuthorizationFailed`, and v2.4.20 dumped the raw ARM JSON error into the per-row UI.

v2.4.22 rewrites the strategy:

1. List subscriptions the user can read: `GET https://management.azure.com/subscriptions?api-version=2022-12-01`. Cached in `armSubscriptionsCache` so we hit ARM once per popup session.
2. For each subscription, query `GET /subscriptions/<id>/providers/Microsoft.Authorization/roleAssignments?$filter=principalId eq '<gid>'`. Anyone with at least Reader on a subscription can list role assignments in that subscription.
3. Aggregate results, dedupe by assignment id. The subscription name is captured at query time so the renderer can show "Resource group 'X' in 'Production-Sub'" instead of bare GUIDs.
4. Friendly error fallback: parses ARM `AuthorizationFailed` into "your account can't read Azure role assignments at this scope (needs Reader/Owner on subscription)" instead of dumping raw JSON.

Tradeoff: misses tenant-root + management-group assignments for users who aren't tenant-level readers. For Global Admins with elevated access this still works because the subscription enumeration will include all subs and the root query is also still attempted as a fallback when the user has zero readable subscriptions.

Manifest 0.4.7 -> 0.4.8.

---

## v2.4.21 -- Popup width 980px -> 800px (980 exceeded Chromium popup max, hiding the Sign in button)

v2.4.20 widened the popup to 980px which exceeds Chromium's effective popup max width (~800px depending on OS/screen). Result: popup got a horizontal scrollbar and the Sign in button -- positioned to the right of the header -- ended up offscreen, making it impossible to sign in. 800px is the safe width on every Chromium version. No other code changes.

Manifest 0.4.6 -> 0.4.7.

---

## v2.4.20 -- Wider popup (980px), Re-sign in auto-launches OAuth, Azure RBAC consent banner

Three UX fixes after v2.4.19 went out:

### 1. Popup width 780px -> 980px

Long PIM group names + role columns wrapped awkwardly at 780px (visible in user screenshots where rows overflowed the right edge). 980px is the new max; still well within Chromium's popup limit (~1024px). Padding/columns reflow automatically.

### 2. Re-sign in actually re-signs in

Pre-v2.4.20 click flow: Re-sign in -> overlay -> reload -> Sign in screen. User then had to click Sign in AGAIN to trigger OAuth + consent. Two clicks for an action labelled "Re-sign in" is bad UX.

v2.4.20 sets a `forceInteractive: true` flag in `chrome.storage.local` before reload; on next boot, the popup detects the flag and immediately launches `acquireGraphToken({ interactive: true })` instead of waiting for a button click. Result: one click goes straight to the Microsoft consent dialog (for any newly-added scope), then back to a populated popup.

If the interactive flow fails (cancelled, network error, etc.), popup falls back to showing the Sign in button + reload button so the user can recover.

### 3. Azure RBAC consent banner instead of per-row error

Pre-v2.4.20: every group in the My Access list got a red "Azure RBAC: Azure RBAC needs user_impersonation consent - click Re-sign in" sub-row when ARM consent was missing. With 12+ groups that's 12 identical error lines.

v2.4.20: one global yellow banner at the top of My Access:

> **Azure RBAC roles not visible yet.** Admin consent for `user_impersonation` is required to show Azure roles per group. Click **Re-sign in** (top-left) to grant it. Tenant-wide one-time action.

Per-row Azure subsection is suppressed when consent is missing (cleaner). When consent IS granted, Azure RBAC rows render as before.

### Customer action

End-users on Edge/Chrome auto-update or run `Update-PimActivatorDev.ps1`. Manifest 0.4.5 -> 0.4.6. No new scopes.

---

## v2.4.19 -- Skip empty sub-sections; three permission types now clearly distinguished

Per direct customer feedback after v2.4.18, the popup no longer prints "(no Entra role assignments granted by this group)" or "(no Azure RBAC assignments granted by this group)" lines. If a group doesn't grant either, those sub-rows are omitted entirely. Same data, less noise.

### The three permission types visible in My Access

| Type | What it is | Where it comes from | Where rendered |
|---|---|---|---|
| 1. Workload access via group membership | Defender XDR, Intune, Power BI workspaces, custom apps, etc. -- whatever role the group's owning workload defines for its members | The group membership itself; whoever owns the group decides what the membership means | Parent row (group name + member-since + expires) |
| 2. Entra (M365) roles | Helpdesk Administrator, Authentication Administrator, Global Reader, etc. | Entra role assignments where the group is the principal (`/roleManagement/directory/roleAssignments?$filter=principalId eq '<gid>'`) | "Entra role: X (scope)" sub-row, only when present |
| 3. Azure RBAC roles | Owner, Contributor, Reader, etc. on subscriptions/RGs/resources | Azure RBAC role assignments where the group is the principal (`https://management.azure.com/providers/Microsoft.Authorization/roleAssignments?$filter=principalId eq '<gid>'`) | "Azure RBAC: X at scope" sub-row, only when present |

Most PIM-for-Groups groups in the wild grant ONE of these (just workload access via membership; e.g., a "PIM-Defender-XDR-SecurityOperations" group). v2.4.19 makes that the silent default -- only Entra + Azure rows surface when there's actually something to show. Bundle groups that DO have many roles use the collapse-by-default UX shipped in v2.4.18.

### Customer action

End-users on Edge/Chrome auto-update or run `Update-PimActivatorDev.ps1` (maintainer-only). Manifest 0.4.4 -> 0.4.5. No new permissions vs v2.4.18.

---

## v2.4.18 -- Azure RBAC visible in My Access tab + collapse for long Entra role lists

Two improvements:

### A. Azure RBAC support (new)

The "Azure RBAC ... deferred to a future release" placeholder is gone. v2.4.18 now queries Azure Resource Manager directly for each active PIM-for-Groups membership and shows the actual Azure roles + scopes granted by that group, in the same tidy format used for Entra roles.

### What it queries

For each active group on the My Access tab, the popup hits:

```
GET https://management.azure.com/providers/Microsoft.Authorization/roleAssignments
  ?$filter=principalId eq '<groupId>'
  &api-version=2022-04-01
```

Then resolves each `roleDefinitionId` to a friendly name via:

```
GET https://management.azure.com<roleDefinitionId>?api-version=2022-04-01
```

Both `roleName` and the scope path are de-GUIDed for end-users. Scope rendering:
- `/`                            -> `(tenant root)`
- `/providers/.../managementGroups/X`  -> `Management Group 'X'`
- `/subscriptions/<id>`          -> `Subscription '<id>'`
- `/subscriptions/.../resourceGroups/X`  -> `Resource group 'X'`
- anything more specific stays raw (resource-scoped assignments are usually narrow enough that the path is the most informative thing).

Multiple assignments under the same role name collapse to one line: "Azure RBAC: Owner at 3 scopes ('Subscription A', 'Resource group B', ...)". Same UX pattern as the Entra role grouping shipped in v2.4.16.

### Token acquisition

Azure RBAC lives in ARM (audience `https://management.azure.com`), not in Microsoft Graph. v2.4.18 reuses the **same refresh_token** the popup already has (granted via `offline_access`) to mint a separate ARM-audience access token. No second interactive sign-in required. The ARM token is cached in `chrome.storage.local` with its own expiry; subsequent popup opens hit the cache, not Entra.

### One-time consent

On first popup-open after upgrading to v0.4.4, the popup will request the new scope `https://management.azure.com/user_impersonation`. This scope is not pre-consented in most app registrations -- the user (or admin) needs to consent once.

If the consent prompt doesn't auto-appear (silent refresh path), click **Re-sign in** in the popup. Tenant admins can pre-consent by adding "Azure Service Management -> user_impersonation" to the PIM Activator app registration's API permissions and granting tenant-wide consent (Entra portal -> App registrations -> PIM Activator -> API permissions).

Until consent is granted, the Azure RBAC line shows "Azure RBAC needs user_impersonation consent - click Re-sign in" instead of the deferred placeholder.

### B. Collapse for long Entra role lists

PIM-Entra-ID-Bundle-* groups can carry 50+ Entra role assignments. In v2.4.17 every one was rendered as a separate row, making the My Access tab unreadable for users in admin bundles. v2.4.18 collapses any group with MORE than 3 distinct Entra role names behind a "N Entra roles granted by this group (click to expand)" toggle. Click to expand, click again to collapse.

Verified against a real tenant: a bundle group with 82 active roleAssignments + 50 PIM eligibilities now shows ONE summary row by default; click expands to the full list. The 82 active assignments are direct (granted immediately when group is activated -- no per-role activation needed). The 50 eligibilities require per-role PIM activation and will be added in v2.4.19 (separate "Eligible roles via this group" subsection + per-row Activate button).

### Customer action

End-users on Edge/Chrome auto-update or run `Update-PimActivatorDev.ps1` (maintainer-only). One-time consent prompt for `user_impersonation` at next sign-in. Manifest 0.4.3 -> 0.4.4.

---

## v2.4.17 -- Popup: AU names resolve (AdministrativeUnit.Read.All added), My Access sorted by activation time, persistent AU cache, Update-PimActivatorDev.ps1 helper

Four improvements based on direct customer feedback after v2.4.16:

### 1. AdministrativeUnit.Read.All added to required Graph scopes

After v2.4.16 collapsed N AU GUID rows into "Groups Administrator -- 5 restricted scopes", the next question was: what ARE those scopes? Answer: regular Administrative Units. The popup just couldn't read their names because `RoleManagement.Read.Directory` only exposes the AU id; reading the AU object itself requires `AdministrativeUnit.Read.All`. Verified against a real tenant: 12/12 AU lookups returned HTTP 403 with the old scope set.

v2.4.17 adds `AdministrativeUnit.Read.All` to:
- `popup.js` SCOPES + REQUIRED_GRAPH_SCOPES
- `Deploy-PimActivatorBackend.ps1` `$needed` array and .NOTES

After upgrading, end-users will see the consent prompt one more time (or admin can pre-consent by re-running `Deploy-PimActivatorBackend.ps1 -GrantConsent`). Then AU names render properly: "Groups Administrator -- in AU 'Marketing', 'Sales', 'HR', 'Engineering' + 4 more".

If consent has NOT been granted, the popup degrades gracefully with explicit text: "scoped to 10 Administrative Units (admin must grant AdministrativeUnit.Read.All to show names)" -- replacing the previous vague "restricted scopes" label that customers found confusing.

### 2. My Access sorted by activation time, newest first

Previously the My Access tab sorted rows alphabetically by displayName. After activating a new group, it got buried among long-standing eligibilities (months-old memberships sorted to the top). v2.4.17 sorts by `startDateTime` DESC -- whatever you just activated appears at the top, oldest memberships at the bottom.

### 3. Persistent AU name cache (chrome.storage.local, 24h TTL)

The `auNameCache` was in-memory only, meaning every popup-open re-queried every AU from Graph. v2.4.17 hydrates the cache from `chrome.storage.local` at popup load and persists after each successful lookup. Re-opening the popup is now near-instant for any AU we've already seen. 24-hour TTL ages out renamed/deleted AUs. Foundation for the broader "fetch in background, cache" pattern that v2.5.0 will expand to all popup data via a service worker.

### 4. Update-PimActivatorDev.ps1 dev-loop helper (NEW)

Hand-written companion script for rapid dev iterations. Two modes:

- **default**: kills browsers, scrubs `Extensions/<id>` + `Local Extension Settings/<id>` + Preferences/Secure Preferences entries (including HMAC integrity hashes in `protection.macs.extensions.settings`), restarts browser -> forcelist re-pulls latest CRX.
- **`-Repack`**: also auto-bumps the manifest patch version, repacks the CRX with placeholder config, pushes to gh-pages, then flushes.

Built specifically for the maintainer's managed Edge that has `DeveloperToolsAvailability=2` (no Update button on force-installed extensions). One command replaces the entire dance of Task Manager + manual cache hunt + manual git commit + manual force-reinstall. Customer rollout is unaffected -- this is a maintainer-only script.

### Customer action

End-users: same auto-update path as v2.4.16, plus a one-time consent prompt for `AdministrativeUnit.Read.All` (admin can pre-consent via `Deploy-PimActivatorBackend.ps1 -GrantConsent`). Manifest 0.4.2 -> 0.4.3.

---

## v2.4.16 -- Popup UX cleanup: hide GUIDs, group identical roles, "Re-sign in" instead of "Auto-fix permissions", auto-switch to My Access after activation

Three end-user-facing improvements driven by direct customer feedback after the v2.4.15 unblock:

### 1. My Access tab: no more GUIDs in role rows

v2.4.15 (and earlier) rendered Entra role assignments as raw rows:

```
Entra role: Groups Administrator AU 06e389b6-3a01-4ead-9671-2174c67492d3
Entra role: Groups Administrator AU 1c61e150-a6a9-478a-82ed-399807c6dd9f
Entra role: Groups Administrator AU 4cf31b96-1d2d-46d8-896b-fdf9de888c85
Entra role: Groups Administrator AU 4e0c2a94-2f20-402f-a10a-ef7e68b7ff5d
... (and 4 more)
Entra role: Authentication Administrator AU '_err'
Entra role: Authentication Administrator AU '_err'
```

End-users can't act on GUIDs and the "_err" placeholder (from a failed admin-unit lookup) was confusing. v2.4.16 collapses identical (role, scope) entries into ONE row and replaces GUIDs with friendly names or a count:

```
Entra role: Groups Administrator      in AU 'Marketing', 'Sales', 'HR', 'Engineering' + 4 more
Entra role: Authentication Administrator    4 restricted scopes
```

`describeDirectoryScope` now returns structured `{ kind, name?, auId?, raw? }` descriptors instead of pre-formatted strings, and the renderer groups by role name + summarises scopes via a new `summariseScopes` helper. AU lookups that fail (403 / 404) cache `null` instead of `"__err"` so the rendering can degrade gracefully to "N restricted scope(s)".

### 2. "Auto-fix permissions" button -> "Re-sign in"

The button label confused users -- "permissions" sounded like file ACLs and "Auto-fix" implied a repair tool. Renamed to **Re-sign in** with a tooltip describing actual usage ("Use this if the popup looks broken, if an admin just granted you new permissions, or if you switched between Edge and Chrome"). The button now always triggers a fresh interactive sign-in regardless of token state -- if your token is healthy and you click anyway, you can swap accounts or pick up updated admin-consent.

The "4/4 scopes" status line next to it is hidden when the token is healthy (silent success); it only surfaces when something needs attention ("Permissions out of date - click Re-sign in").

### 3. Activate tab: auto-switch to My Access after activation + auto-uncheck activated rows

Previously, after activating one or more groups, the popup left you on the Activate tab with cryptic status text like "submitted (PendingProvisioning)" and no way to see what roles were actually granted -- you had to manually switch to My Access and click Refresh. v2.4.16 auto-switches to My Access, waits ~2.5s for PendingProvisioning to flip to Provisioned, then reloads the tab so you immediately see your new active memberships + the Entra roles they generated.

Per-row status text also softened: "submitted - check My Access tab in a few seconds" instead of "submitted (PendingProvisioning)".

Successfully-activated rows are now **automatically unchecked** -- re-opening the popup no longer shows stale selections that could trigger an accidental re-activation. Rows that failed activation stay checked so the user can retry. The persisted `selectedIds` storage entry is rewritten to match.

### Customer action

End-users: same auto-update path as v2.4.15. Force-update via `edge://extensions` -> Developer mode ON -> Update, OR wait ~30 min for Chromium to poll `updates.xml`. Manifest bumped 0.4.1 -> 0.4.2.

No admin / Intune changes needed.

---

## v2.4.15 -- CRITICAL FIX: popup JWT decode bug caused infinite "missing scopes" reauth loop

The popup self-heal logic introduced in v2.4.10 (`decodeJwtPayload` -> `getTokenScopes` -> `missingScopes`) had a latent bug that surfaced for every user after the v2.4.10 release: a double-decode in the JWT payload parser silently swallowed every token, making it appear as if the token contained zero Graph scopes. The self-heal then triggered a full reauth + page reload, the new token was also "missing all scopes", and the popup looped indefinitely on the "Self-healing your session..." overlay.

Symptom in the field: clicking the PIM Activator icon shows a brief sign-in screen, then a dark overlay flashes "Missing scopes: PrivilegedAccess.ReadWrite.AzureADGroup, Group.Read.All, User.Read, RoleManagement.Read.Directory", then the popup reloads back to sign-in. Forever. Even after `chrome.identity.clearAllCachedAuthTokens`, even after a clean OAuth round-trip with admin-consented all-scopes tokens.

### Root cause

`popup.js` line 117:

```javascript
const json = new TextDecoder().decode(base64UrlDecode(parts[1]))
```

`base64UrlDecode()` (line 178) already returns a UTF-8-decoded string -- not a Uint8Array. Wrapping the string in `TextDecoder().decode(...)` throws `"The provided value cannot be converted to a sequence of bytes"` in V8/Blink. The surrounding `try/catch` in `decodeJwtPayload` swallows the throw and returns `null`. From there:

```
decodeJwtPayload  -> null
getTokenScopes    -> []  (no scp claim found)
missingScopes     -> [all 4 required scopes]
triggerInteractiveReauth -> overlay + reload -> loop
```

Verified by dumping the JWT directly from `chrome.storage.local` LevelDB on disk: the cached access tokens contained ALL 4 required scopes (`Group.Read.All PrivilegedAccess.ReadWrite.AzureADGroup RoleManagement.Read.Directory User.Read`), correct audience (`https://graph.microsoft.com`), correct tenant, correct app id. The bug was purely in the popup's parser, not in the OAuth flow / app registration / consent.

### Fix

One-line in `popup.js`:

```javascript
return JSON.parse(base64UrlDecode(parts[1]))   // string -> JSON.parse direct
```

`base64UrlDecode` already does the UTF-8 decode internally. The extra `TextDecoder().decode()` was redundant + broken.

### Customer action

End-users on Edge/Chrome with the extension installed:
- Auto-update kicks in within ~30 min (Chromium polls `updates.xml` periodically). After the v0.4.1 CRX lands, restart Edge/Chrome -> the popup signs in cleanly.
- To force the update immediately: `edge://extensions` -> toggle Developer mode on -> click **Update**. Same on `chrome://extensions`.

No admin/Intune changes needed. Same forcelist + managed-storage values from v2.4.14 carry forward.

### Extension version

Manifest bumped 0.4.0 -> 0.4.1 so Chromium recognises the update via `updates.xml`.

---

## v2.4.14 -- Popup light theme (white + blue) + simplified "not configured" message + extension ver 0.3.0 -> 0.4.0 + correct Intune deployment guidance

Two UX wins + one important correction to the deployment story:

### Popup switched to light theme

Previous dark theme (`#0e1116` near-black background) was hard to read in normal office lighting. v2.4.14 ships a clean light theme:

- Background: white (`#ffffff`)
- Body text: near-black (`#1a1a1a`)
- Group / title accents: GitHub-style blue (`#0969da`)
- Borders: light grey (`#d0d7de`)
- Header / footer / section headers: subtle off-white (`#f6f8fa`)
- Status colors: green (success) / amber (pending) / red (error) — WCAG-comfortable on white
- Tab active state: blue underline + blue text
- Primary button: blue (`#0969da`) + white text

### Simplified "not configured" text

Old: `Extension not configured. Admin must push tenantId + clientId via Intune (or copy config.template.js -> config.js). See README.md.`

New: `Not configured. Admin must set tenantId + clientId via policy.`

Removed "Intune" specifically because policy can come from Group Policy / Intune / Chrome Browser Cloud Management / Workspace ONE / etc. -- the popup shouldn't presume the management channel.

### Important correction to the Intune deployment story (the `managed_storage` myth)

v2.4.12 / 2.4.13 incorrectly told customers to push tenantId/clientId via an Intune `ExtensionSettings` JSON with a `managed_storage` block. **That property is NOT in the Chromium ExtensionSettings schema.** Edge / Chrome reject the JSON with `Schema validation error: Unknown property: managed_storage`. The forcelist install still works, but tenantId/clientId never propagate -- popup correctly shows the "Not configured" error (now in clearer wording).

**The three correct ways to push `chrome.storage.managed` values via Intune:**

1. **Per-customer CRX (simplest at scale)** -- each customer fork-publishes a gh-pages with their own `config.js` baked in; one CRX per customer. The maintainer's `Setup-PimActivator.ps1 -PublishToGitHubPages` can be re-run by each customer admin against their own repo.

2. **PowerShell script via Intune** -- deploy `Deploy-PimActivatorClient.ps1` (which already writes the right registry keys) as a Windows 10/11 Platform Script in Intune Admin Center -> Devices -> Scripts and remediations. Pass tenantId + clientId as script parameters per customer assignment.

3. **Custom OMA-URI Configuration Profile** -- 5 OMA-URI entries per browser (10 total for Edge + Chrome), one per managed-schema field, writing to `./Device/Vendor/MSFT/Registry/HKLM/SOFTWARE/Policies/Microsoft/Edge/3rdparty/extensions/<id>/policy/<key>` (and Chrome equivalent).

The next release (v2.4.15) will update `Setup-PimActivator.ps1 -PrintIntuneConfig` to print the OMA-URI table + a copy-pasteable PowerShell parameter set for method 2 -- AND will REMOVE the bogus `managed_storage` JSON from the printed ExtensionSettings (so customers don't keep hitting the same schema-validation error).

### manifest.json version 0.3.0 -> 0.4.0

Forces Edge / Chrome auto-update polls to actually fetch the new CRX (otherwise version match -> skip download). All existing customer installs auto-upgrade on next ~5h poll.

### Files changed

- `tools/pim-activator/popup.html` -- full CSS palette swap (white/blue light theme)
- `tools/pim-activator/popup.js` -- one-line error text replacement
- `tools/pim-activator/manifest.json` -- version 0.3.0 -> 0.4.0

CRX v0.4.0 published to https://knudsenmorten.github.io/PIM4EntraPS/pim-activator.crx; extension ID `eheocihmlppcophaeakmdenhgcookkab` unchanged.

---

## v2.4.13 -- CRX packaged with placeholder config.js (no maintainer-tenant leak into customer installs) + ext version bump 0.2.0 -> 0.3.0

Closes the last multi-tenant safety hole. Previously the packed CRX bundled the maintainer's `config.js` containing the maintainer's `tenantId` + `clientId`. If a customer admin installed the CRX via Intune but forgot to push the `ExtensionSettings` JSON with managed_storage (or pushed it incorrectly), end-users would silently sign into the MAINTAINER'S tenant. Now the bundled CRX ships with placeholder zeros, so misconfiguration shows a loud error instead of a silent cross-tenant signin.

### `Setup-PimActivator.ps1` change

New helper `Invoke-MsedgePackWithPlaceholder` wraps every `msedge.exe --pack-extension` call (3 sites: initial pack, no-key keygen pack, re-pack after manifest sync). Flow:

1. Save the current `config.js` content (the maintainer's real tenantId+clientId)
2. Copy `config.template.js` (placeholder zeros) over `config.js`
3. Run `msedge.exe --pack-extension` -- CRX now bundles placeholder
4. **`finally`**: restore the maintainer's real `config.js` (so sideload-dev still works on the maintainer's box)

The maintainer's `config.js` on disk is unchanged for local dev use; only the CRX-bundled copy is the placeholder.

### Customer-side behaviour

When a customer admin installs the CRX without pushing the Intune `ExtensionSettings` JSON:
- `popup.js`'s `loadConfig()` reads `chrome.storage.managed.get(null)` -> returns empty
- Falls back to bundled `config.js` -> finds `tenantId: "00000000-..."`, `clientId: "00000000-..."`
- Existing validator (since v2.4.10) catches the placeholder zeros and shows: `Extension not configured. Admin must push tenantId + clientId via Intune (or copy config.template.js -> config.js). See README.md.`
- No silent cross-tenant signin. Customer admin gets a clear "you missed a setup step" prompt.

When a customer admin correctly pushes the `ExtensionSettings` JSON via Intune:
- `chrome.storage.managed.get(null)` returns their tenantId + clientId
- Merges over the empty fallback
- popup signs into THEIR tenant, not the maintainer's

### Extension version bump 0.2.0 -> 0.3.0

Forces Edge / Chrome auto-update polls to actually fetch the new CRX (otherwise version match -> skip download). All existing customer installs auto-upgrade on next ~5h poll cycle.

### Verification

Run end-to-end on the maintainer's box:
- `Setup-PimActivator.ps1 -PublishToGitHubPages` published CRX v0.3.0 to https://knudsenmorten.github.io/PIM4EntraPS/pim-activator.crx
- Local `tools/pim-activator/config.js` still contains the maintainer's real values (sideload dev still works)
- The CRX in the gh-pages branch bundles `config.js` with placeholder zeros (verified via unzip + cat)
- Existing customer popups that already have Intune managed_storage configured: no behaviour change

### Files changed

- `tools/pim-activator/Setup-PimActivator.ps1`: new `Invoke-MsedgePackWithPlaceholder` helper, 3 call-sites updated
- `tools/pim-activator/manifest.json`: version 0.2.0 -> 0.3.0

---

## v2.4.12 -- Intune-first deployment: -PrintIntuneConfig mode + HKCU-default -PushPolicyScope (drops HKLM conflict with Intune)

Production rollouts in customer environments use Intune as the authoritative ExtensionInstallForcelist policy source. Previous `-PushPolicy` writes to HKLM directly conflicted with Intune (last-writer-wins races on every policy refresh). v2.4.12 makes Intune the primary path.

### Three rollout modes (per Setup-PimActivator.ps1)

| Mode | What it does | Registry writes |
|---|---|---|
| **Default** (no flag) | Publish CRX + create app reg + print URLs at end | None |
| **`-PrintIntuneConfig`** (NEW, PRIMARY PROD PATH) | Default + emits exact copy-pasteable strings for Intune Admin Center (ExtensionInstallForcelist value + ExtensionSettings JSON in canonical Chromium shape) + step-by-step Settings Catalog navigation for both Edge and Chrome | None |
| **`-PushPolicy -PushPolicyScope User`** (NEW DEFAULT scope) | Dev-box testing only. HKCU writes. No admin, no Intune conflict, easy revert. | HKCU only |
| **`-PushPolicy -PushPolicyScope Machine`** | Backward-compat. HKLM writes. CONFLICTS with Intune. Emits loud warning + advises use only on isolated test machines. | HKLM (warns) |

### Setup-PimActivator.ps1 changes (322 -> 914 lines net through v2.4.x)

- Added `-PrintIntuneConfig` switch
- Added `-PushPolicyScope` param (defaults to User)
- Step 6 rewritten into 3 branches (push-policy / print-intune / default)
- Up-front warning when `-PushPolicyScope Machine` is selected
- Note when both `-PushPolicy` and `-PrintIntuneConfig` supplied (does both with advisory rather than erroring)
- `-PrintIntuneConfig` requires `-CrxUpdateUrl` OR `-PublishToGitHubPages` (so the printed forcelist value has a real URL)
- Summary footer now reports `Policy push` (with scope) and `Intune config` lines

### Deploy-PimActivatorClient.ps1 changes (186 -> 274 lines)

- `-Scope` param default flipped from `Machine` to `User`
- Loud yellow warning at install time when Machine scope selected; green note when User
- HKCU forcelist + managed-storage paths confirmed (`HKCU:\SOFTWARE\Policies\Microsoft\Edge\...` + Chrome equivalent)
- New `.EXAMPLE` for HKCU default; retained Machine example for backward compat

### Intune-config printout shape (the exact `ExtensionSettings` JSON the script emits)

```json
{"<extensionId>":{"installation_mode":"force_installed","update_url":"<updatesXmlUrl>","managed_storage":{"tenantId":"<tid>","clientId":"<cid>","groupNameFilter":"^PIM-","defaultDurationHours":1,"defaultJustification":"Daily ops"}}}
```

This is the canonical Chromium `ExtensionSettings` shape that the Intune Admin Center "Configure extension management settings" setting accepts. The `managed_storage` block is what `popup.js`'s `loadConfig()` reads via `chrome.storage.managed.get(null)` -- already wired in v2.4.10. Result: customer admins push per-tenant tenantId/clientId via this single JSON, and one canonical CRX serves every customer.

### Multi-tenant rollout architecture (the "beautiful" path)

```
[your dev box]
  Setup-PimActivator.ps1 -PublishToGitHubPages
    -> CRX published to https://knudsenmorten.github.io/PIM4EntraPS/

[customer admin -- each tenant]
  Deploy-PimActivatorBackend.ps1 -GrantConsent
    -> creates "PIM Activator" app reg in customer's tenant
    -> outputs their own clientId

  Intune Admin Center:
    1. ExtensionInstallForcelist: <extId>;<your-gh-pages-url>
    2. ExtensionSettings JSON with their tenantId + their clientId
    3. Assign to device/user group -> Edge auto-installs + uses their tenant
```

One CRX file, infinite customers, each pinned to their own tenant via Intune managed-storage.

### Customer admin action required after upgrade

If a customer is already running v2.4.10/2.4.11 with managed-storage already configured via Intune: no action; this release is backward-compat.

If a customer is on v2.4.9 or earlier (no managed-storage in Intune yet): also push the new ExtensionSettings JSON via Intune (alongside the existing ExtensionInstallForcelist value). The `Setup-PimActivator.ps1 -PrintIntuneConfig` mode emits the exact JSON to paste.

---

## v2.4.11 -- PIM Activator popup: version badge in header + extension version bump (0.1.0 -> 0.2.0) + brighter color contrast

Three small UX wins to support customer-facing rollouts:

1. **Manifest version bumped 0.1.0 -> 0.2.0** -- forces Edge / Chrome to actually pick up the v2.4.10 CRX (the previous publish had the same `0.1.0` version so Edge's auto-update check skipped the download). From v2.4.11 onward, every publish bumps the version so users actually get the new build on auto-update.
2. **Version badge in the popup header** -- shows `v0.2.0` next to "PIM Activator". Hover tooltip shows extension ID + manifest version + name. Sourced from `chrome.runtime.getManifest()` so it always matches the running build (no risk of stale hardcoded constants). Also logged to the popup's console on every open: `[PIM Activator] v0.2.0 (id eheocihmlppcophaeakmdenhgcookkab)`. Support can now ask "what version do you see in the header?" instead of guessing.
3. **Brighter color contrast** -- secondary/meta text bumped from `#7d8590` (medium grey, low contrast on the near-black `#0e1116` background) to `#b1bac4` (brighter grey, WCAG-comfortable). Group display name bolder + brighter (`#f0f6fc`). Row hover background slightly lighter (`#1c2128` vs `#161b22`). Borders softened (`#2d333b` vs `#21262d`). Net: easier to scan a long eligibility list under normal office lighting.

### Customer auto-update path

Edge / Chrome poll `https://knudsenmorten.github.io/PIM4EntraPS/updates.xml` every ~5 hours + on browser startup. The bumped `0.2.0` version triggers an auto-download + install on next poll. End-users see no prompt -- the new build appears next time they open the popup.

For impatient testing: `edge://extensions/` -> toggle Developer mode ON (top-right) -> big **Update** button appears -> click. Force-polls all extension update URLs immediately.

### Files changed

- `tools/pim-activator/manifest.json` -- `version: 0.1.0 -> 0.2.0`
- `tools/pim-activator/popup.html` -- version badge span in header, brighter palette throughout (single global `#7d8590 -> #b1bac4` swap + targeted row/name brighten)
- `tools/pim-activator/popup.js` -- `loaded()` populates the version badge + console-logs the version

### Follow-up roadmap

- Auto-bump manifest version on every `Setup-PimActivator.ps1 -PublishToGitHubPages` run so the maintainer never forgets again (v2.4.12 candidate)

---

## v2.4.10 -- PIM Activator popup: "My Access" tab + token self-heal + Auto-fix button + hide-already-active

Three popup UX wins, one new Graph scope, fully tested E2E:

### 1. New "My Access" tab

Sibling to the existing "Activate" tab (toggleable via tab strip at the top). Shows what the signed-in user CURRENTLY has active in this tenant:

- All currently-active PIM-for-Groups memberships (filtered to `accessId='member'`)
- Per group: start/end timestamps (when activation went live + when it expires)
- Per group: the Entra role assignments attached to that group (role display name + scope description: "(tenant-wide)" or "AU 'EMEA-Helpdesk'")
- Per group: a placeholder for Azure RBAC scope view (deferred to v2.4.11 -- needs a separate ARM token flow)

Tabs each have a badge counter: `Activate (N)` shows the count of eligibilities the user CAN activate; `My Access (M)` shows the count CURRENTLY active. Both badges auto-update after activations land.

Lazy load + 30 s in-memory cache. In-panel **Refresh** button bypasses the cache.

### 2. Token self-heal (the "switch browsers / admin re-consented" fix)

The cached access token is issued by Entra with a fixed scope set at sign-in time. If admin grants new scopes server-side AFTER the user signed in, the user's cached token still doesn't see them. Same problem when switching browsers (Edge -> Chrome): each browser has its own extension instance + own token cache; activations performed in Edge aren't reflected in Chrome's stale token.

**Three self-heal trigger points** in `popup.js`:

a. **On every `loaded()` call**: decode the cached token's JWT `scp` claim, compare against `REQUIRED_GRAPH_SCOPES` (PrivilegedAccess.ReadWrite.AzureADGroup + Group.Read.All + User.Read + the new RoleManagement.Read.Directory). If any missing -> trigger reauth.
b. **On 401 / 403 from Graph**: if response code matches `InvalidAuthenticationToken / AccessDenied / Authorization_RequestDenied / TokenNotFound / MissingClaim / InsufficientScopes`, wrap the error as `stale=true` and reauth.
c. **Manual button**: Auto-fix permissions in the My Access tab toolbar (see below).

When reauth fires, the popup shows a **full-popup overlay banner** explaining what's happening + why ("Admin re-consented new scopes / switched browser / token expired"), waits 2.5 seconds so the user can read it, then reloads. The user signs in once; Entra issues a fresh token with the current scope set; everything continues. Old mysterious 403s replaced by a transparent re-sign-in.

### 3. Auto-fix button

In the My Access tab toolbar. Click -> validates `scp` claim against required scopes. If all present, shows green `Token healthy -- all 4 scope(s) present.` If any missing, shows the missing list + immediately triggers the self-heal flow.

Also shows a live diagnostic next to the button (`4/4 scopes` in green, or `Missing: <list> (click Auto-fix)` in amber) so users can see token health at a glance.

### 4. Hide-already-active in the Activate tab

The Activate tab used to show EVERY eligibility, even ones the user had already activated -- confusing because re-activating already-active groups bounces with `AssignmentExists`. v2.4.10 now also fetches `assignmentScheduleInstances` in parallel with eligibilities and filters out rows already active. The status bar shows the count of hidden rows: `15 eligible group(s) (3 already active -> My Access).`

### Files changed

- `popup.html`: tab strip + new `#panel-myaccess` panel + Auto-fix button + scope-diagnostic line
- `popup.js`: `RoleManagement.Read.Directory` added to `SCOPES`; new helpers `decodeJwtPayload` / `getTokenScopes` / `missingScopes` / `triggerInteractiveReauth`; `graph()` flags `stale=true` on auth-related errors; `loaded()` does parallel eligibility + active fetches, filters out already-active, triggers self-heal if scopes missing; Auto-fix button wired
- `Deploy-PimActivatorBackend.ps1`: `RoleManagement.Read.Directory` added to `$needed` scope list; doc-comment updated
- `Setup-PimActivator.ps1` (no change, runs the updated backend automatically)

### Customer admin action required after upgrade

Re-run `Setup-PimActivator.ps1 -PublishToGitHubPages` (with `-PushPolicy` if also pushing Edge/Chrome policy). The script's Step 4 calls Deploy-PimActivatorBackend which automatically re-grants admin consent for the new scope. Existing customers' end-users will hit the self-heal flow on first popup open after upgrade -- transparent, one click to re-sign-in.

### E2E verification (2026-06-03)

- Setup-PimActivator -PublishToGitHubPages run: SUCCESS, new CRX with extension ID `eheocihmlppcophaeakmdenhgcookkab` pushed to GitHub Pages, scope `RoleManagement.Read.Directory` (id `741c54c3-0c1e-44a1-818b-3f97ab4e8c83`) added + admin-consented
- popup.js + Deploy-PimActivatorBackend.ps1 parse-clean (node --check + Parser::ParseFile)

---

## v2.4.9 -- Switch CRX hosting to GitHub Pages + Chrome browser support + role-clarifying renames + SPA-redirect-URI fix (E2E proven)

Tested end-to-end on the maintainer's box: Edge installed the extension via HKLM ExtensionInstallForcelist policy pointing at GitHub Pages, OAuth flow succeeded (PKCE + chrome-extension:// SPA URI), popup correctly rendered the empty-state for an account with no PIM-for-Groups eligibilities.

### CRX hosting moved from Azure Storage to GitHub Pages

- **`-DeployAzureCrxHost` mode removed** (along with `-AzSubscriptionId / -AzResourceGroup / -AzLocation / -AzStorageAccountName / -AzStorageContainerName / -AzKeyVaultName / -AzKeyVaultSecretName` params). All Az.Storage / Az.KeyVault dependencies dropped from `Setup-PimActivator.ps1`.
- **`-PublishToGitHubPages` mode added.** Composes with both Interactive and Unattended auth. Verifies `gh` CLI + auth, clones the `gh-pages` branch shallowly (creates as orphan if missing), packs the CRX via `msedge.exe --pack-extension`, extracts SPKI from the CRX header (no .NET PEM parsing needed -- bypasses the PS 5.1 `ExportPkcs8PrivateKey` gap), syncs `manifest.json.key` only on drift then re-packs to keep the embedded manifest consistent, generates `updates.xml`, drops `.nojekyll`, commits + pushes. Empty-diff push detected + reported as "already up-to-date".
- **Auto-derives `-CrxUpdateUrl`** for `-PushPolicy` from the just-published `https://<owner>.github.io/<repo>/updates.xml`.
- **Local signing key** lives at `$env:USERPROFILE\.pim-activator\signing-key.pem` (maintainer's secret -- script prints a loud 6-line "BACK THIS UP" notice on first generation). Outside any repo so it can't accidentally commit.
- **Cost: $0/month** (was ~$5/month Azure Storage Standard_LRS). No Azure subscription needed.

### Chrome support in `Deploy-PimActivatorClient.ps1`

New `-Browser` param: `Edge | Chrome | Both` (default `Both`). When `Both`, writes HKLM keys under BOTH `SOFTWARE\Policies\Microsoft\Edge` AND `SOFTWARE\Policies\Google\Chrome` -- identical key names + structure under each root (ExtensionInstallForcelist + 3rdparty\extensions\<id>\policy). `-Uninstall` honours `-Browser`. Setup-PimActivator forwards a new `-TargetBrowser` param.

### Role-clarifying renames (the "what does this script do" fix)

| Old name | New name | Role |
|---|---|---|
| `Install-PimActivatorAppRegistration.ps1` | **`Deploy-PimActivatorBackend.ps1`** | Backend -- creates the tenant Entra app reg + admin consent. Runs ONCE per customer tenant. |
| `Install-PimActivator.ps1` | **`Deploy-PimActivatorClient.ps1`** | Client -- pushes HKLM Edge/Chrome ExtensionInstallForcelist + managed-storage policy to a single device. Runs ON every user device (Intune). |
| `Setup-PimActivator.ps1` | `Setup-PimActivator.ps1` | Orchestrator -- calls backend, publishes CRX to GitHub Pages, then calls client. |
| `Test-PimActivatorFlow.ps1` | unchanged | Diagnostic. |

Cascade-rename across 8 source files (Setup script, both Deploy scripts, both READMEs, DESIGN.md, extension-identity.txt, Install-PimEngineAppRegistration.ps1). RELEASENOTES historical references left intact (don't rewrite history).

### SPA-redirect-URI fix (the AADSTS9002326 fix)

Modern Edge / Chrome MV3 extension popups send `Origin: chrome-extension://<id>` headers from their `fetch()` to `/oauth2/v2.0/token`. Entra's SPA flow validates the `Origin` header against registered SPA redirect URIs. Previously the script registered ONLY `https://<id>.chromiumapp.org/` -- which is needed for the auth-code redirect, but NOT for the cross-origin token redemption. Result: every customer hit `AADSTS9002326: Cross-origin token redemption is permitted only for the 'Single-Page Application' client-type. Request origin: 'chrome-extension://<id>'` on first sign-in.

**Fix in `Deploy-PimActivatorBackend.ps1`:** register BOTH URIs as SPA type:
- `https://<id>.chromiumapp.org/` -- for `chrome.identity.launchWebAuthFlow` redirect
- `chrome-extension://<id>/` -- to satisfy SPA-flow Origin check during token redemption

Bonus: dropped the legacy `-PublicClient` + `-IsFallbackPublicClient:$true` registration that the old script wrote. Confirmed via `Update-MgApplication`: Microsoft Graph accepts `chrome-extension://` as a SPA URI (even though the Entra portal UI rejects them with a "must start with https://" validation).

### Files changed (v2.4.9 net)

- `Setup-PimActivator.ps1` (322 -> ~750 lines)
- `Deploy-PimActivatorClient.ps1` (was Install-PimActivator.ps1; renamed + Chrome support; 186 -> 239 lines)
- `Deploy-PimActivatorBackend.ps1` (was Install-PimActivatorAppRegistration.ps1; renamed + SPA URI fix)
- `README.md` + `tools/pim-activator/README.md` + `docs/DESIGN.md` + `extension-identity.txt` + `setup/Install-PimEngineAppRegistration.ps1` -- cascade-rename references
- All PS 5.1 parse-clean

### Verification

End-to-end run on the maintainer's machine (2026-06-03):
- Setup-PimActivator with `-PublishToGitHubPages -PushPolicy -TargetBrowser Both` -> SUCCESS
- CRX live at https://knudsenmorten.github.io/PIM4EntraPS/pim-activator.crx
- Edge auto-installed extension on restart, popup signed in (after the SPA URI fix), correctly displayed empty-state for an account with no PIM-for-Groups eligibilities (matches `Test-PimActivatorFlow.ps1` finding)

---

## v2.4.8 -- All-in-one Azure CRX hosting in Setup-PimActivator.ps1 + manifest schema fix + Test-PimActivatorFlow.ps1

Single re-runnable command now does **everything** needed to host the activator extension from your own Azure subscription: resource group, signing key in Key Vault, manifest key sync, storage account, blob container, CRX packaging via msedge.exe, updates.xml generation, blob upload, and optional Edge policy push -- all idempotent.

### `Setup-PimActivator.ps1` extension (322 -> 655 lines)

New `-DeployAzureCrxHost` switch composes with both `Interactive` and `Unattended` auth modes. When set, a new **Step 1.5** runs BEFORE the Graph half:

1. **Az preflight** -- requires existing `Connect-AzAccount` session; switches sub if `-AzSubscriptionId` given; verifies tenant matches `-TenantId`.
2. **Ensure RG** -- gets-or-creates `$AzResourceGroup` (default `rg-pim-activator`).
3. **Validate KV** -- mandatory `-AzKeyVaultName` (the user's existing KV; script does NOT create vaults).
4. **Get-or-create signing key** -- looks up the PKCS#8 PEM secret in KV; if missing generates RSA 2048 + writes back as KV secret. Same secret across re-runs -> deterministic extension ID.
5. **Sync manifest.json `key`** -- recomputes the public-key SPKI DER from the PEM, overwrites `manifest.json.key` if drift detected. The extension ID derived from this is logged.
6. **Ensure storage account** -- default name `stpim` + first 10 hex of `sha256(tenantId)` (auto-derived; pass `-AzStorageAccountName` to override). Created with `Standard_LRS / StorageV2 / AllowBlobPublicAccess=true / HTTPS-only / TLS 1.2`.
7. **Ensure container** -- default `pim-activator` with `-Permission Blob` (public read on individual blobs, no listing).
8. **Pack CRX** -- writes the PEM to a temp path, runs `msedge.exe --pack-extension --pack-extension-key`, output `tools/pim-activator.crx`, temp PEM deleted in a `finally` block (no private key left on disk).
9. **Generate `updates.xml`** -- Chromium auto-update manifest pointing at the public CRX URL.
10. **Upload both blobs** -- CRX (`application/x-chrome-extension`) + updates.xml (`application/xml`), public read, overwriting any prior versions.
11. **Auto-derive `-CrxUpdateUrl`** -- when `-PushPolicy` is set without an explicit `-CrxUpdateUrl`, the script uses the just-uploaded updates.xml URL.

### `Test-PimActivatorFlow.ps1` (new, ~150 lines)

Verifies the PIM-for-Groups bulk-activation flow WITHOUT loading the extension. Same Graph endpoints + delegated scopes as `popup.js`:
- `Connect-MgGraph -Scopes 'PrivilegedAccess.ReadWrite.AzureADGroup', 'Group.Read.All', 'User.Read'` (interactive browser)
- Lists the caller's `identityGovernance/privilegedAccess/group/eligibilityScheduleInstances`
- Resolves each `groupId` -> `displayName`, applies `^PIM-` regex filter
- Interactive multi-select prompt
- POSTs `selfActivate` `assignmentScheduleRequests` per selected group with `justification` + `PT{N}H` duration
- Per-row pass/fail report

Useful for: validating the activator app reg's delegated grants work, validating the calling user has any eligibilities at all, debugging from the same PS session as the engine.

### `managed_schema.json` fix (the "Failed to load extension" blocker)

Edge's managed-schema validator only accepts `minimum`/`maximum` on `type: integer`, not `type: number`. Old schema had `defaultDurationHours: { type: 'number', minimum: 0.5, maximum: 24 }` -> Edge rejected with `Only integers can have minimum and maximum`. Fixed: `type: integer, minimum: 1, maximum: 24`. Trade-off: admin-policy-pushed defaults are now whole hours; the `Setup-PimActivator.ps1 -DefaultDurationHours` flag still accepts decimals (it writes to config.js, not the managed schema).

### Prerequisites to use `-DeployAzureCrxHost`

1. Az modules: `Install-Module Az.Accounts, Az.Resources, Az.Storage, Az.KeyVault -Scope CurrentUser`.
2. `Connect-AzAccount` before invocation (interactive on dev, SPN on Intune).
3. KV must already exist (script doesn't create vaults -- you control which one).
4. Calling identity needs: **Contributor** on the sub + **Key Vault Secrets Officer** on the KV (RBAC) OR Get+Set on the access policy (legacy mode).
5. Graph identity (same Connect-MgGraph flow as before) needs: `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All`.
6. Edge installed (msedge.exe used for CRX packaging).

### Example

```powershell
.\Setup-PimActivator.ps1 -TenantId 'f0fa27a0-...' `
    -DeployAzureCrxHost `
    -AzSubscriptionId '54468121-...' `
    -AzKeyVaultName 'kv-2linkit-automation-p' `
    -PushPolicy
```

One command: deploys storage + KV signing key + CRX + updates.xml + Edge policy. Re-run to refresh anything that drifted.

---

## v2.4.7 -- Finish wiring v2.4.4's 4-method auth into the community launchers + README catch-up

v2.4.4 shipped the SI-style helpers (`Connect-PimLauncherAuth`, the solution-wide `config\PIM4EntraPS.custom.sample.ps1`, the 4-method auth schema in `LauncherConfig.custom.sample.ps1`) but did NOT actually rewire the 42 `launcher.community-{vm,azure}.ps1` files to CALL the new helper. They were still using the old `LauncherConfigPath` + raw `$global:SpnClientSecret` flow, so the new auth methods were declarable but not honoured at runtime. v2.4.7 closes the loop.

### Files updated (43 net-new diffs)

- **42 community launchers** rewired: each `launcher.community-vm.ps1` + `launcher.community-azure.ps1` across all 21 engines (Check-PIM-Groups-IsRoleAssignable, Custom-Policies, Custom-Repository, Fix_PIM_MFA_Auth_Policy, GetNumberOfROles, PIM-Assignment-Exporter (+ CSV-Only), PIM-Assignment-Revoker, PIM-Assignment-Wizard, PIM-Baseline-Management-CSV (+ 6 narrowed variants + SQL), PIM-SQL-import-export-CSV, PIM-extra, SQL-Connect). Each now dot-sources `Initialize-LauncherConfig` (layered defaults -> solution-wide custom -> per-engine custom) and calls `Connect-PimLauncherAuth` instead of the old raw connect.
- **README.md** Prerequisites section: lists all 4 auth methods and points operators at `config\PIM4EntraPS.custom.sample.ps1`.

### Auth-method-detection priority (now actually honoured at runtime)

1. `$global:UseManagedIdentity -eq $true` → Managed Identity
2. `$global:SpnKeyVaultName + $global:SpnSecretName` set → SPN + KV-stored secret (fetched at launch)
3. `$global:SpnCertificateThumbprint` set → SPN + certificate (cert presence + non-expiry validated BEFORE Connect-AzAccount/Connect-MgGraph; warns when only `Cert:\CurrentUser\My` is found rather than `LocalMachine`)
4. `$global:SpnClientSecret + $global:SpnClientId` set → SPN + plaintext (emits `TESTING ONLY` warning)
5. None of the above → throws with copy-pasteable "set one of these 4 method blocks" message

### Pre-existing concern flagged (NOT introduced by this release)

`Initialize-LauncherConfig` dot-sources every `config/*.locked.ps1` it finds. Two of those locked files (`Fix_PIM_MFA_Auth_Policy.locked.ps1`, `PIM-SQL-import-export-CSV.locked.ps1`) are FULL ENGINE scripts that auto-`Connect-AzAccount` + run Graph operations at load time. Loading the layered config currently triggers those side effects whether the operator wanted them or not. Pre-dates v2.4.x — flagging for awareness; cleanup is a v2.4.8 candidate (move those two files out of `config/`).

### Internal launchers untouched

`launcher.internal-vm.ps1` / `.internal-azure.ps1` continue using the AutomateIT bootstrap as before. Only community launchers got the SI-style 4-method auth wiring.

Parse-clean on PS 5.1: all 42 launchers.

---

## v2.4.6 -- Fully-unattended activator deployment via bootstrap SPN (Intune-friendly)

v2.4.5 still required an interactive Microsoft Graph sign-in inside `Setup-PimActivator.ps1` step 3. That's fine for a dev box, fatal for Intune / scheduled-task / Azure Function rollouts. v2.4.6 adds an app-only auth path using a pre-staged "bootstrap" SPN — no browser, no device code, fully scriptable.

### New params on `Setup-PimActivator.ps1`

- `-BootstrapSpnAppId <guid>` (mandatory in unattended mode)
- `-BootstrapSpnCertificateThumbprint <40-hex>` (preferred — cert auth)
- `-BootstrapSpnClientSecret <string>` (fallback — plaintext secret)

When any of the `-BootstrapSpn*` params is supplied the script uses ParameterSet `Unattended`: skips browser/device-code entirely, connects to Graph app-only, and runs the rest of the flow (app reg create+consent, config.js write, optional policy push) as the bootstrap SPN. `-TenantId` is mandatory in this mode (we need to know which customer tenant to target).

### Bootstrap SPN requirements

The bootstrap SPN must have these 3 Microsoft Graph **application** permissions admin-consented in the **target customer tenant**:

| Permission | Why |
|---|---|
| `Application.ReadWrite.All` | Create/update the `PIM Activator` app reg |
| `AppRoleAssignment.ReadWrite.All` | Grant tenant-wide admin consent to delegated scopes |
| `DelegatedPermissionGrant.ReadWrite.All` | Write the `oauth2PermissionGrants` entries |

For multi-customer MSP rollouts: register the bootstrap SPN as **multi-tenant**, send each customer admin a one-click admin-consent URL (`https://login.microsoftonline.com/<tenantId>/adminconsent?client_id=<spnAppId>`), then run Setup-PimActivator with that tenant's id from Intune. Per-tenant: one consent click, then fully unattended forever.

Cert auth is the security best practice — the cert thumbprint goes in clear (it's not a secret), the private key never leaves the host's cert store. Plaintext secret is supported as a fallback for quick tests but emits a "consider rotating to a certificate" warning.

### Example -- Intune deployment

```powershell
.\Setup-PimActivator.ps1 -TenantId 'f0fa27a0-...' `
    -BootstrapSpnAppId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
    -BootstrapSpnCertificateThumbprint 'ABCDEF0123456789ABCDEF0123456789ABCDEF01' `
    -PushPolicy `
    -CrxUpdateUrl 'https://stcorp.blob.core.windows.net/pim-activator/updates.xml'
```

Zero interactive steps. Cert must be installed in `Cert:\LocalMachine\My` on the Intune-managed host (Intune can deploy the PFX as a Win32 dependency).

### Extension end-user first run unchanged

The Edge extension's first-launch interactive sign-in (admin clicks the popup, gets an Entra OAuth tab, completes once, refresh token cached in `chrome.storage.local`) is the right behaviour for user-context delegated auth and was never the target of this release. Only the DEPLOYMENT side (creating the app reg, pushing Edge policy keys) is now fully scriptable.

### Re-runnability + safety

Same as v2.4.5: idempotent app reg update, `config.js` overwrite, policy keys are no-op writes. Re-running with the same `-BootstrapSpn*` creds against the same tenant is a clean no-op.

Parse-clean on PS 5.1.

---

## v2.4.5 -- Turnkey PIM Activator install: one-command orchestrator + pinned extension identity + auto-generated icons

Eliminates the multi-step manual install for the PIM Activator Edge extension. One `Setup-PimActivator.ps1` call now does what previously required: generate icons, sideload the extension to discover its ID, copy `config.template.js` to `config.js`, run `Install-PimActivatorAppRegistration.ps1` with the discovered ID, paste the resulting clientId into `config.js`. All automated.

### New artefacts in `tools/pim-activator/`

- **`Setup-PimActivator.ps1`** -- one-command orchestrator. 6 steps, fully idempotent:
  1. Ensures icons exist (generates 4 placeholder PNGs if `icons/` is empty)
  2. Computes deterministic extension ID from manifest.json's `key` field
  3. Connects to Microsoft Graph (browser flow by default; `-UseDeviceCode` for headless hosts) -- reuses existing session if scopes match
  4. Runs `Install-PimActivatorAppRegistration.ps1` with the computed ID + `-GrantConsent`
  5. Writes `config.js` with the resulting tenantId + clientId + sane defaults
  6. (Optional, `-PushPolicy`) Writes Edge ExtensionInstallForcelist HKLM registry keys via `Install-PimActivator.ps1` so Edge auto-installs on next launch (no manual "Load unpacked")
- **`extension-identity.txt`** -- documents the fixed extension ID `hkdglhgahonnjbfindmgplekkcngmcck` and explains why it's deterministic.
- **`icons/icon-16.png` / `icon-32.png` / `icon-48.png` / `icon-128.png`** -- 4 placeholder icons (blue background + white "PIM" text). Generated programmatically; safe to overwrite with a designer-built set later. Without these, Edge "Load unpacked" rejected the manifest (`Could not load icon ... for action`).

### Why the extension ID is now deterministic

In v2.4.4 the `key` field was added to `manifest.json` containing a fixed 2048-bit RSA public key (SPKI DER, base64). Chromium derives the extension ID from `SHA256(publicKey)[:16]` mapped to a-p, so the ID is the same on every install on every computer in every customer tenant. Operator benefits:
- One canonical redirect URI for the app reg (`https://hkdglhgahonnjbfindmgplekkcngmcck.chromiumapp.org/`) -- never changes
- Same Intune `ExtensionInstallForcelist` entry deployable to every customer
- `Setup-PimActivator.ps1` doesn't need the operator to first sideload to discover the ID

### Usage

**Developer workstation (sideload manually after script finishes):**
```powershell
.\Setup-PimActivator.ps1 -TenantId 'f0fa27a0-...'
# then in Edge: edge://extensions/ -> Developer mode ON -> Load unpacked -> select tools\pim-activator\
```

**Production rollout (Edge auto-installs via policy registry; requires admin shell):**
```powershell
.\Setup-PimActivator.ps1 -TenantId 'f0fa27a0-...' -PushPolicy `
    -CrxUpdateUrl 'https://stcorp.blob.core.windows.net/pim-activator/updates.xml'
```

Re-running the same command in the same tenant is safe -- the underlying `Install-PimActivatorAppRegistration.ps1` updates the existing app reg in place; `config.js` is overwritten with the same values; policy keys are no-op writes.

### Constraints

- One interactive sign-in is still required per tenant (creating an app reg in someone else's tenant requires admin auth -- Microsoft enforces this). The orchestrator funnels this into a single Connect-MgGraph call up front; everything else is automatic.
- Cross-tenant deploy: re-run the script with each customer tenant's id. Same extension ID + extension code; per-tenant app reg + per-tenant `config.js`.

Parse-clean on PS 5.1: `Setup-PimActivator.ps1` (~7 KB).

---

## v2.4.4 -- Port SecurityInsight's 4-mode launcher auth + solution-wide config + new Grant-PimEngineAdminConsent helper

Mirrors the SecurityInsight (SI) launcher auth model into PIM4EntraPS so customers running both solutions use one mental model. SI ships a layered config (defaults -> solution-wide -> per-engine -> CLI) and supports 4 auth methods (Managed Identity / SPN+KV / SPN+cert / SPN+plaintext) selected by which globals are populated. v2.4.4 brings PIM4EntraPS into line.

### New config + helper files

- **`config/PIM4EntraPS.custom.sample.ps1`** (new, solution-wide template) -- mirrors `SecurityInsight.custom.sample.ps1`. Single place for auth + shared overrides covering every engine. Customers who already manage SI will recognize the layout. The `.gitignore` already excludes `config\*.custom.ps1`, so the populated copy stays local.
- **`launcher/_lib/Connect-PimLauncherAuth.ps1`** (new shared helper) -- encapsulates the 4-mode connect flow. Both `launcher.community-vm.ps1` and `launcher.community-azure.ps1` consume it, eliminating the per-flavour duplication.
- **`setup/Grant-PimEngineAdminConsent.ps1`** (new, idempotent) -- companion to `Install-PimEngineAppRegistration.ps1`. Adds tenant-wide admin-consent app-role assignments to an EXISTING engine SPN (handy when the engine app reg was created by another process and just needs catch-up perms). Skips already-granted entries; only writes the missing ones. Device-code by default so it works on hosts without a default browser.

### Updated launcher files (21 LauncherConfig.custom.sample.ps1 + 2 _lib)

Every `launcher/<task>/LauncherConfig.custom.sample.ps1` (21 of them across all engines) now documents the 4 auth methods as commented blocks the operator uncomments. Variable names match SI verbatim:

- `$global:UseManagedIdentity = $true` + `$global:SpnTenantId` -- **Method 1: MI** (recommended for Azure VMs / Arc / Functions)
- `$global:SpnTenantId` + `$global:SpnClientId` + `$global:SpnKeyVaultName` + `$global:SpnSecretName` -- **Method 2: SPN + KV-stored secret** (production-recommended for non-Azure-hosted)
- `$global:SpnTenantId` + `$global:SpnClientId` + `$global:SpnCertificateThumbprint` -- **Method 3: SPN + certificate** (security best practice for VM runs)
- `$global:SpnTenantId` + `$global:SpnClientId` + `$global:SpnClientSecret` -- **Method 4: SPN + plaintext secret** (testing only)

Auth-method-detection priority (matches SI): MI first, then KV, then cert, then plaintext. First method whose globals are populated wins.

`launcher/_lib/Initialize-LauncherConfig.ps1` + `PIM4EntraPS.shared-defaults.ps1` updated to load the new solution-wide config layer before per-engine config, then call `Connect-PimLauncherAuth` to do the connect.

### Internal launchers untouched

`launcher.internal-vm.ps1` / `.internal-azure.ps1` use the AutomateIT bootstrap which already handles cert auth from the customer KV. Left alone -- internal customers keep using the AutomateIT high-priv SPN. Only community launchers + the new solution-wide config get the SI-style auth model.

### tools/pim-activator/manifest.json -- pinned extension identity (preview)

Added a `key` field to `manifest.json`. This makes the Edge extension ID deterministic on every install of every customer on every computer. The ID resolved from the key is `hkdglhgahonnjbfindmgplekkcngmcck`. See v2.4.5 for the turnkey installer that consumes it.

### Engine call-sites + parse-check

All 29 touched PS files parse-clean on Windows PowerShell 5.1. The engine `Connect-AzAccount` / `Connect-MgGraph` paths now branch on `$global:SpnAuthMode` (set by `Connect-PimLauncherAuth`) for the right auth flavour.

---

## v2.4.3 -- README: full feature inventory (41 bullets, shipped / partial / roadmap badges)

Pure docs release; no code changes. README adds a new `## Features` section placed between "The core idea: 3-tier group nesting" and "Quick start", with **41 bullets** covering every shipped capability + every roadmap item -- each tagged with one of:

- `[shipped vX.Y.Z]` -- in the codebase as of v2.4.2 (18 bullets)
- `[partial]` -- partially shipped, e.g. data-flow only + enforcement is roadmap (2 bullets)
- `[roadmap]` -- in `docs/ROADMAP.md`, not yet shipped (21 bullets)

Voice preserved from the user's spec (direct, slightly informal, "ability to X" pattern); obvious typos cleaned (orhaned -> orphaned, enterprisesa -> enterprises, proces -> process). Cross-references to RELEASENOTES + ROADMAP for deeper detail. README line count: 402 -> 455 (+53).

The Features section makes "what does PIM4EntraPS do today vs what's coming" a one-page lookup -- previously this required cross-referencing RELEASENOTES (curated, what shipped) + ROADMAP (sized backlog) + the engine README sections.

---

## v2.4.2 -- New Revoke tab in PIM Manager GUI: bulk-revoke active activations from one place

The PIM Manager (`tools/pim-manager/Open-PimManager.ps1` + `pim-manager.html`) gets a 6th tab -- **Revoke** -- that ports the `PIM-Assignment-Revoker` engine's bulk-revoke functionality into the browser GUI. Reuses the v2.2.0 multi-select action-bar pattern + v2.4.0 preload helpers, so the active-assignments list loads in 1-3 s instead of fanning out N per-row Graph round-trips.

### Revoke tab UX

- **Single sortable/filterable table** of every currently-active PIM activation across all three surfaces: Entra ID directory roles, Azure RBAC role assignments, PIM-for-Groups (member + owner).
- **Filters**: 4 chip-toggles (All / Entra-role / Azure-RBAC / PIM-for-Groups) + free-text search box (matches principal UPN, role name, scope, group name).
- **Multi-select**: per-row checkbox + sticky bottom action bar showing `[Selection: N rows] [Justification: <input>] [⚠ Revoke selected] [Clear]`.
- **Justification is mandatory** (PIM API requires it); Revoke button stays greyed-out until non-empty -- matches Entra portal behaviour.
- **Confirmation modal** before commit ("Revoke N active assignments? Cannot be undone. Principals must re-activate via PIM if they need access.") -- reuses the existing `showConfirm(...)` modal from v2.2.0's Delete flow.
- **Per-row results pane** after submit: each row shows pass/fail with the Graph/ARM error message inline if it failed -- batch never aborts on a single-row failure.

### Server endpoints (in `Open-PimManager.ps1`)

Two new bearer-token-authed endpoints:

- `GET /api/active-assignments[?refresh=1]` -- returns merged list from all 3 sources. 60s server-side cache (avoid hammering Graph + ARG on repeated tab clicks); `?refresh=1` forces re-fetch. Response includes `cacheHit` + `elapsedSec` so the operator sees data freshness in the UI.
- `POST /api/revoke` -- body `{ justification, rows: [{id, type, principalId, roleDefinitionId, scope, groupId}] }`. Per-row Try/Catch dispatches the right revoke shape:
  - **Entra role**: `New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter @{ action='adminRemove'; ... justification=... }`
  - **Azure RBAC**: `Invoke-AzRestMethod -Method PUT` to `roleAssignmentScheduleRequests/<new-guid>?api-version=2020-10-01` with `requestType=AdminRemove` (this is what the ARM API actually accepts -- there is no DELETE on the scheduleRequests endpoint, per the engine's working pattern)
  - **PIM-for-Groups**: `New-MgIdentityGovernancePrivilegedAccessGroupAssignmentScheduleRequest -BodyParameter @{ action='adminRemove'; ... }`
  - Returns per-row `{ id, ok: $true/$false, error?, requestId?, statusCode? }`; cache invalidated on completion.

### Implementation notes

- All new CSS classes / IDs prefixed `rev-` / `revoke...` to avoid collisions with existing tabs.
- New JS helpers (`loadActiveAssignments` / `renderRevokeTable` / `applyRevokeFilter` / `submitRevoke` / etc.) live in a module-scoped `REV` state singleton -- no globals leaked.
- Tenant connection re-uses the existing `Assert-PimTenantConnectionContext` + `Connect-PimManagerGraph` + `Connect-PimManagerAz` helpers from `_tenantSync.ps1` -- no new auth flow, no SDK import churn.
- Lookup caches (Users / Groups / Entra-role-defs / AUs) load lazily on first `/api/active-assignments` call; result mirrored into `$Global:Users_All_ID` / `$Global:Groups_All_ID` so the v2.4.0 helpers stay first-class if invoked subsequently in the same session.
- **One known limitation (TODO v2.4.3)**: there is no v2.4.0 `Get-EntraRoleSchedulesPreloaded` helper yet, so the Entra-role active leg of `/api/active-assignments` calls `Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All` directly. v2.4.3 introduces the helper + the Manager will swap to it (single tenant-wide preload instead of an in-line call).

### Files changed

- `tools/pim-manager/pim-manager.html` -- new tab markup, ~75 lines CSS, ~290 lines JS
- `tools/pim-manager/Open-PimManager.ps1` -- 2 endpoints, 5 helper functions, ~365 lines

Parse-clean: `Open-PimManager.ps1` (PS 5.1) + both inline `<script>` blocks (`node --check`).

---

## v2.4.1 -- Wire PIM-for-Groups preload into Baseline + swap per-row eligibility-lookup call-sites

Activates two of the v2.4.0 helpers in the live engine flow. The Exporter slim-down that was planned for this release was **reverted before ship** because the agent's draft dropped the Entra-role + Azure-active snapshots from the hourly Exporter without compensating live-preload calls in Baseline -- which would have caused the engine to issue duplicate `AdminAssign` requests against rows it couldn't see (cryptic downstream `RoleAssignmentExists` errors). The Exporter slim-down is re-sequenced into v2.4.3 once the missing `Get-EntraRoleSchedulesPreloaded` helper exists + the `Get-AzActiveRoleAssignmentsViaArg` call is wired into Baseline startup.

Changes shipped in v2.4.1:

- **`engine/PIM-Baseline-Management-CSV/PIM-Baseline-Management-CSV.ps1`** + `-SQL` sibling: added a new step `[ 03 / 12 ] Pre-loading PIM-for-Groups schedules tenant-wide` immediately after the existing `Get-PimAdminsFiltered` / `Get-PimGroupsFiltered` block at engine startup. Calls `Get-PimGroupSchedulesPreloaded` (v2.4.0), which fires one paged Graph call instead of ~1000 per-row `-Filter "groupId eq..."` round-trips. `$MaxSteps` bumped 11 -> 12 in both blocks of both engines.
- **`engine/_shared/PIM-Functions.psm1`** lines 4272 + 5128 (`Assign-PIMForGroups-From-file-CSV` -- two paired call-sites with different variable shapes): swapped `Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -Filter "..." -EA SilentlyContinue` (the per-row Graph fallback) for `Get-PimGroupSchedule -GroupId -PrincipalId -AssignmentType Eligible -AccessId member`. The v2.3.2 Try/Catch wrappers were dropped (the v2.4.0 helper handles failure internally and returns `$null` on miss); existing `If ($GraphCheck) {...}` branch logic preserved verbatim.

Live `Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule` caller-sites remaining in PSM1: **0** (the 3 remaining textual references are inside `Get-PimGroupSchedulesPreloaded`'s own implementation + docstring/warning text).

**Customer-facing perf at scale**: when the snapshot is fresh, the v2.4.1 path is equivalent to v2.4.0 (snapshot still authoritative). When the snapshot is stale (typical hourly cron miss), v2.4.1 saves the ~6 minutes the per-row Graph fallback used to burn -- one paged call replaces ~1000 single-group lookups.

Parse-clean on PS 5.1: PIM-Functions.psm1 (635 KB), PIM-Baseline-Management-CSV.ps1, PIM-Baseline-Management-SQL.ps1.

### v2.4.3 carry-over (Exporter slim-down)

The reverted Exporter slim-down needs these prerequisites before re-attempt:
1. New helper `Get-EntraRoleSchedulesPreloaded` (mirror of `Get-PimGroupSchedulesPreloaded` for `roleEligibilitySchedule` + `roleAssignmentSchedule` on the `roleManagement/directory` endpoint)
2. Call `Get-EntraRoleSchedulesPreloaded` + `Get-AzActiveRoleAssignmentsViaArg` at Baseline startup (parallel to the v2.4.1 PIM-for-Groups preload)
3. Rewire the `$CurrentAssignments_EntraIDRoles` consumer (PSM1 lines ~2569 / 2977 / 3305) + the AzRes active-side consumer (PSM1 line ~3785) to read from the live preloads instead of the now-empty Exporter CSV
4. THEN drop the Entra-role + AzRes-active reads from the Exporter and slim it to ~430 lines

---

## v2.4.0 -- Perf overhaul: cached group resolution + tenant-wide preload helpers + Azure token reuse

The structural perf wins surfaced by the v2.3.2 function audit. **Estimated total saved per Baseline run at customer scale (200 admins × 500 PIM-for-Groups × 30 role groups): ~10-15 minutes**, depending on whether snapshot is fresh. v2.4.0 lands the helpers; v2.4.1 will swap the per-row engine call-sites to consume them; v2.4.2 ports the Revoker engine into the PIM Manager GUI on top of the new live-preload contract.

Pure-additive at the helper layer. Existing engine call-sites are NOT yet refactored to consume the new preload helpers (that's v2.4.1) -- the exception is `Resolve-PimGroupCached`, whose 17 in-PSM1 call-sites WERE swapped in this release (the audit's biggest win). Existing on-disk snapshots + engine contracts unchanged.

### Item #1 -- `Resolve-PimGroupCached` helper + 17-site refactor

New `Resolve-PimGroupCached -DisplayName <name> [-NoCache]` helper (PSM1 line ~9737). Drop-in replacement for `Get-MgGroup -Filter "DisplayName eq '<name>'" -ErrorAction SilentlyContinue` used in per-row CSV loops. Serves the lookup from `$Global:Groups_All_ID` (already preloaded by `Get-PimGroupsFiltered` at engine startup) via a case-insensitive script-scoped hashtable; on miss, falls back to a single Graph call with proper `''`-escaping + adds the result to the cache so subsequent same-run lookups hit. `-NoCache` switch bypasses for post-create re-fetches.

17 call-sites refactored across PSM1 (Create-PIM-Group-Role, Assign-PIM-Group-Resource, CreateUpdate-PIM-PAG-Group, Assign-PIM-Group-Group, CreateUpdate-PIM-for-Groups-From-file-CSV / -SQL, EntraID-Role AU-scoped assignment paths, PIM4Groups create-with-role paths, Azure-Resources group create). 4 of those use `-NoCache` for post-create re-fetches. **Eliminates ~700 Graph round-trips per Baseline run; ~3-5 min saved.**

### Item #3 -- Graph PIM-for-Groups schedule preload

New `Get-PimGroupSchedulesPreloaded` (PSM1 line ~10070) does ONE paged tenant-wide call against `Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -All` + same for `...AssignmentSchedule -All`. Each typically returns 500-2000 rows in 1-3s -- vs the current per-row fallback path that fires ~1000 single-group `-Filter "groupId eq..."` calls at ~600ms each. Cached in `$script:PimGroupEligibilityByGroupId` + `...AssignmentByGroupId` hashtables (5-minute MaxAgeMinutes default).

Companion `Get-PimGroupSchedule -GroupId -PrincipalId -AssignmentType [-AccessId]` (line ~10185) is the per-row lookup helper. Auto-triggers the preload on first call. Will be wired into `Assign-PIMForGroups-From-file-CSV` lines 4125 + 4984 in v2.4.1. **~6 min saved when the snapshot is stale.**

### Item #4 -- Azure RBAC active-assignment preload via ARG

New `Get-AzActiveRoleAssignmentsViaArg` (PSM1 line ~10255) replaces per-scope `Get-AzRoleAssignment -Scope` loops with one `Search-AzGraph -UseTenantScope` query against the `AuthorizationResources` table. Confirmed via Microsoft Learn 2026-06: `microsoft.authorization/roleassignments` IS in the ARG `AuthorizationResources` table -- so the active-assignments side gets a single 1-2s query covering the whole tenant (subject to SPN visibility). Auto-paginates with `-SkipToken`. Role definition names resolved client-side with a memoised `Get-AzRoleDefinition -Id` cache (20-40 unique role defs per tenant vs hundreds of assignments).

**Important constraint preserved**: Azure RBAC ELIGIBILITY schedules are NOT in ARG (`roleEligibilitySchedules` is not yet indexed). The exporter's per-scope ARM walk for eligibility schedules stays for now -- v2.4.1 slims the exporter to that single remaining job, drops the Graph-side enumeration (those move to live preload at Baseline-engine start).

### Item #5 -- ARM bearer-token caching

New `Get-AzPimTokenCached [-ExpiryBufferSeconds 300] [-Force] [-RefreshOn401]` helper (PSM1 line 163). ARM tokens valid 60-90 min, but per-scope and per-policy-rule loops were re-minting the same token dozens of times per execution (50ms × N = pure overhead). Helper holds the last-issued token in `$script:AzPimTokenCache` + refreshes when within 5 min of expiry or on explicit force/401. Handles both modern `PSAccessToken` (Az.Accounts 2.13+, string `.Token` + `DateTimeOffset .ExpiresOn`) and legacy SecureString-shaped tokens.

15 call-sites swapped from `Get-AzAccessTokenManagement` to `Get-AzPimTokenCached`: function-entries + per-scope loops in `Assign-AzResources-Groups-From-file-CSV`, `CreateUpdate-Policies-PIM-AzResources-File-CSV` / `-SQL`, and the 5 worst offenders inside `PIM_Policy_Check_Update`'s per-rule PATCH loop. **~10-25s saved per Exporter / heavy-policy run.**

**Resilience bonus**: `Invoke-AzPimPatch` (line 7941) now has a one-shot 401-retry hook -- on HTTP 401 it calls `Get-AzPimTokenCached -RefreshOn401`, replaces the in-flight header, and retries once. Recovers automatically if MSAL ever evicts the cache mid-loop instead of failing.

### Carry-over to next releases

- **v2.4.1 -- Exporter slim-down + call-site swap to preload helpers**: drop Graph-side enumeration from the hourly Exporter (PIM-for-Groups + Entra role schedules); add live preload to Baseline-engine startup; swap `Assign-PIMForGroups-From-file-CSV` lines 4125 + 4984 to consume `Get-PimGroupSchedule`; swap the per-scope `Get-AzRoleAssignment` fan-out to `Get-AzActiveRoleAssignmentsViaArg`. Single source of truth: live Graph; only AzRes-eligibility is "up to 1h stale".
- **v2.4.2 -- Revoker tab in PIM Manager GUI**: new "Revoke" tab in `pim-manager.html` (sibling to Validate). Uses the v2.4.0 preload helpers to list active assignments at near-zero cost; multi-select + justification field + confirmation modal + batch-revoke. Reuses the v2.2.0 multi-select action-bar pattern.

### Metrics after v2.4.0

- PSM1: 72 function definitions (was 67 in v2.3.2). +5 helpers landed.
- Get-MgGroup -Filter DisplayName eq live call-sites: **0** (all 17 swapped; 7 occurrences remain in comments / dead-code blocks / docstrings).
- `Get-AzAccessTokenManagement` live `$Headers=` assignments: **0** (all 15 swapped).
- Parse-clean on Windows PowerShell 5.1 (635 KB, 9162 lines).

---

## v2.3.2 -- Perf + logging hotfix: ~70s + 30-60s off every run, plus actionable warnings on silent Graph failures

Low-risk perf + observability fixes surfaced by a function-by-function audit of `PIM-Functions.psm1` (Graph eligibility reads) and the three Azure-side engine scripts (Exporter / Exporter-CSV-Only / Revoker). Bigger structural wins (`Resolve-PimGroupCached` 18-site refactor + slim-down of the hourly exporter to AzRes-eligibility-only) are sequenced into v2.4.0; this release ships the safe deletes + logging.

**Azure-side perf (~70s shaved per Exporter / Revoker run):**
- Deleted dead `AzRoleAssignments-Query-AzARG | Query-AzResourceGraph` call in `PIM-Assignment-Exporter.ps1:269` and `PIM-Assignment-Revoker.ps1:264`. The variable they assigned to was overwritten with `@()` on the very next line -- pure dead code costing 1-3 s per run. (`PIM-Assignment-Exporter-CSV-Only.ps1` keeps its ARG call because the result IS used on the following line to populate `$Global:Role_Group_Definitions_ID`.)
- Deleted `Start-Sleep -Seconds 1` between the per-scope `roleEligibilitySchedules` and `roleAssignmentSchedules` REST calls in `PIM-Assignment-Exporter.ps1:282`. Pure idle wait, no throttle reason (ARM read budget is 12000/hr/sub; 60 sequential calls is nowhere near the ceiling). At ~60 sub+MG scopes that's **~60 s** of pointless sleep gone.

**Graph-side perf (~30-60s on large tenants):**
- Replaced `Get-MgGroup -all:$true | where-Object DisplayName -like 'PIM-*'` in `PIM_Policy_Check_Update` (line 6897) with the v2.1.3 `Get-PimGroupsFiltered` server-side `$filter=startswith(displayName,...)`. On a 30k-group tenant this drops from "fetch all 30k, client-filter to ~200 PIM-* groups" to "fetch ~200 PIM-* groups directly". The combined SecurityEnabled / GroupTypes / OnPremisesSyncEnabled local filters are folded into one `Where-Object` block.

**Logging gaps (the silent failures that produce mysterious downstream crashes):**
- `Assign-PIMForGroups-From-file-CSV` lines 4118 + 4972: the `Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -ErrorAction SilentlyContinue` lookup now uses `-ErrorAction Stop` wrapped in `Try/Catch` + `Write-Warning` with the principal UPN + group display name in the message. Previously a Graph 5xx / throttle silently returned `$null`, the engine concluded "no existing assignment", issued a duplicate `AdminAssign`, and crashed downstream with a cryptic `RoleAssignmentExists` 30 lines later. Now the operator sees: `[PIM4Groups] eligibility lookup failed for principal '<upn>' on group '<group>': <message> -- treating as MISSING; may produce duplicate-assign error downstream.`
- `Create-PIM-Group-Role` line 679: same shape. Previously, if `Get-MgGroup` failed due to throttle/perm, `$Group=$null`, function went into the create branch, and `New-MgGroup` failed with a cryptic `UniqueValueViolated` because the group really existed. Now the operator sees a `[Create-PIM-Group-Role]` warning naming the group.
- Module init (lines 8409 / 8412 / 8421 / 8424): added `[INFO] PIM-Functions: loaded <path>` on successful dot-source of `PIM4EntraPS.NamingConventions.{locked,custom}.ps1` + `PIM4EntraPS.NotificationChannels.{locked,custom}.ps1`, so operators can tell from the transcript whether locked or custom won, instead of debugging a later NRE when `$global:PIM_NotificationChannels` is unexpectedly empty.

**Sequenced into v2.4.0** (riskier, needs regression testing):
- `Resolve-PimGroupCached` helper + refactor of the ~18 sites that fire one `Get-MgGroup -Filter "DisplayName eq..."` per CSV row. Estimated ~3-5 min off every Baseline run at customer scale.
- Slim the hourly Exporter down to **only** the slow leg (Azure RBAC eligibility schedules per-scope walk; the only remaining read with no tenant-wide alternative). The Graph-side enumerations (PIM-for-Groups + Entra role eligibility/active schedules) move to live preload at the start of each Baseline run -- ~10 s per engine run vs ~6 min when the snapshot is stale. Single source of truth: live Graph; only AzRes eligibility is "up to 1h stale" (and that one changes slowly anyway).
- Active Azure RBAC role assignments move from the per-scope ARM walk to a single `Search-AzGraph -UseTenantScope` query (confirmed: `roleAssignments` IS in the `AuthorizationResources` ARG table; `roleEligibilitySchedules` is NOT, so they stay per-scope).
- Token-header caching across the PSM1's ~10 `Get-AzAccessTokenManagement` call-sites (reuse for ~60-90 min instead of re-minting per scope-loop iteration).

---

## v2.3.1 -- README rewrite: full v2.x feature catalog + dedicated PIM Manager (GUI) section

Pure documentation release; no code changes. README brought up to date with everything that landed between v2.0.0 and v2.3.0:

- **Removed all `.locked.csv` references** (obsolete since v2.3.0 dropped them).
- **New "PIM Manager (GUI)" section** — full per-tab breakdown (Graph / Grid / New & clone / Save / Validate), `-NoLaunch` / `-StaticHtml` / `-RefreshTenantLists` mode invocations, per-role permission drill-down explanation, full server-mode endpoint list, the 16-rule validator catalog.
- **New "Notifications & scheduled TAP" section** — `Send-PimAdminTap` (SMTP / Teams / Slack) + `Resolve-PimTapStartDateTime` (relative `+2d 8:00` / `tomorrow 9am` / `next monday 10:00` etc.) with the full supported-input list.
- **New "Naming conventions" section** — how `PIM4EntraPS.NamingConventions.custom.ps1` feeds engine perf (Get-PimAdminsFiltered server-side `$filter`), Manager wizard name suggestions, and validator name-drift rules.
- **New "MSP variant" section** — `config-msp/`, `Sync-PimMspConfig` git source, the CISO opt-in via customer Key Vault for centrally-issued disable/revoke (`Test-PimAccountStatusChangeAuthorized`).
- **Updated Prerequisites** — added Graph perms required by v2.2.0+ features (UserAuthenticationMethod.ReadWrite.All for TAP, Directory.Read.All for Manager tenant cache).
- **Updated Repo layout** — `tools/pim-manager/{_validator.ps1, _tenantSync.ps1, cache/}`, `setup/Install-PimEngineAppRegistration.ps1`, `docs/ROADMAP.md` + `docs/MANAGER-UX-AUDIT.md`.
- **Mentioned the 500-role-assignable-groups Entra tenant cap** in the "Why nest" rationale — heavy permission/role-group reuse is what keeps you under the ceiling.
- **Setup snippet** now uses a one-liner loop that bootstraps every `*.custom.sample.*` into `*.custom.*` at once instead of itemising files.

402 lines total (was 277).

---

## v2.3.0 -- Drop `.locked.csv` baselines: PIM4EntraPS is custom-only from day one

The `.locked.csv` / `.custom.csv` dual-file pattern made sense for solutions like SecurityInsight where Anthropic / 2linkit ships a baseline (detection rules, role-tier mappings) that every customer extends. **It never made sense for PIM4EntraPS**: every customer's admin set, role topology, AU layout, and assignments are unique -- there is no shared baseline to ship -- so the `.locked.csv` files were either empty stubs (useless) or had to be overwritten on day one (confusing). In v2.2.0 + v2.2.1, the dual-file pattern also caused a maintainer-tenant data leak when the maintainer's own data accidentally shipped in the .locked.csv role of the project.

v2.3.0 simplifies the model: **only `.custom.sample.csv` ships** (as schema documentation + worked example rows that operators copy from). Customers always own their config as `.custom.csv` (gitignored) from day one.

Changes:
- **Removed all 14 `config/*.locked.csv` files** from the shipped repo. The `.gitignore` already excluded `.custom.csv`, so nothing the operator owns leaves their VM.
- **`config/*.custom.sample.csv` templates rewritten** with 2-4 realistic generic example rows per file (no customer-specific data). `PIM-Assignments-Roles-Groups.custom.sample.csv` now ships as a **catalog of ~20 common built-in Entra roles** distributed across a representative set of role-group tags (`ROLE-IdentityAdmin`, `ROLE-Helpdesk`, `ROLE-SecurityOps`, `ROLE-Compliance`, etc.) -- operators get a working starting point instead of an empty header.
- **`Get-PimConfigCsv` refactored** to read `.custom.csv` only. Pre-v2.3.0 backward-compat: if a customer still has a `<name>.locked.csv` file lying around from an old install, the engine reads it but emits a one-time `Write-Warning` per file pointing the operator at the migration step ("rename/copy to .custom.csv"). The fallback exists only to smooth one upgrade hop -- it will be removed in v2.4.0.
- **Upgrade path for existing customers**: on first launch after pulling v2.3.0, if any `<name>.custom.csv` is missing but `<name>.locked.csv` exists, just rename `.locked.csv` to `.custom.csv` (or copy + edit if you want to keep a backup of the old shipped baseline). One-shot helper script: `Get-ChildItem .\config\*.locked.csv | ForEach-Object { Move-Item $_.FullName ($_.FullName -replace '\.locked\.csv$', '.custom.csv') -WhatIf }` (remove `-WhatIf` after reviewing the rename plan).
- Customers who never had data in `.locked.csv` (greenfield deploys, or who already migrated to `.custom.csv` in v2.2.1+): nothing to do, engine reads `.custom.csv` as before.

---

## v2.2.1 -- Hotfix: scrub maintainer-tenant data from shipped `.locked.csv` baselines + sample-file cleanup

v2.2.0 inadvertently shipped the maintainer's own admin / role rows in `config\Account-Definitions-Admins.locked.csv` and `config\PIM-Definitions-Roles.locked.csv` -- both files reached the public mirror via the publish workflow. The intent of `.locked.csv` is **shipped baseline that every customer extends**; customer-specific data belongs in `.custom.csv` (gitignored). This release scrubs the leak and ships header-only baselines from now on. v2.2.1 is **non-functional for any customer already running a `.custom.csv`** -- the engine's `Get-PimConfigCsv` fallback prefers `.custom.csv` and only reads `.locked.csv` when `.custom.csv` is missing, so existing deployments see no behaviour change. Customers with no `.custom.csv` who were relying on the shipped `.locked.csv` content as their actual config should copy `.locked.csv` -> `.custom.csv` before upgrading.

Scrubs applied:
- `config\Account-Definitions-Admins.locked.csv` -- replaced with header-only (21 columns). Use `Account-Definitions-Admins.custom.sample.csv` for an annotated example row.
- `config\PIM-Definitions-Roles.locked.csv` -- replaced with header-only (12 columns).
- `config\PIM4EntraPS.NotificationChannels.custom.sample.ps1` -- KV-name example changed from real-looking `kv-2linkit-pim-p` to generic `kv-contoso-pim-p`.
- `config\PIM4EntraPS.NamingConventions.custom.sample.ps1` -- "Customer A (current 2linkit default)" relabelled to "Customer A (Admin- / X-Admin- with tier suffix)"; example initials `MOK` / owner `morten` generalised to `ABC` / `john`. Pre-existing pre-v2.2.0 wording -- scrubbed in this hotfix as part of the same sweep.
- `docs\ROADMAP.md` -- items #1, #2, #6, #7, #11, #12, #25, #28 now annotated `[SHIPPED v2.2.0]` (#25 + #28 also note what is deferred).

Note: the leaked content remains visible in the v2.2.0 tag's commit history on the public mirror until / unless that history is rewritten. v2.2.1 only stops the leak from re-publishing; it does not retroactively scrub git history. Rewriting public-mirror history is a destructive operation and is left to the maintainer's discretion.

---

## v2.2.0 -- Theme 1: Manager UX polish + Theme 2: TAP flow

First slice of the v2.2.x roadmap (`docs/ROADMAP.md` Theme 1 + the first two bullets of Theme 2). Pure-additive schema + helper additions -- pre-v2.2.0 customer CSVs keep working unchanged because the engine reads every new column defensively (PSObject.Properties.Name check, default to empty string when missing).

- **Roadmap #1 -- optional admin metadata columns on `Account-Definitions-Admins`.** Four new columns between `MailForwardAddress` and `CreateTAP`: `Company` (pushed to Entra `-CompanyName` on create when non-empty), `Notes` (max 1024 chars, written as a comment in `output/admin-passwords-<date>.txt` -- Entra has no good native long-text field), `ManagerEmail` (resolved to a Graph user id and linked via `manager@odata.bind` after the user is created; silently skipped when the manager UPN can't be resolved in the tenant), `StartDate` (informational only -- use `TAPStartDate` + roadmap #12 for actual scheduled-credential issuance). The PIM Manager exposes the four fields as a collapsible "More fields..." section in the admin wizard (see `docs/MANAGER-UX-AUDIT.md`).
- **Roadmap #28 -- role sponsor / owner column on `PIM-Definitions-Roles`.** Two new trailing columns: `SponsorUpn` (UPN of the role's audit / renewal owner) and `SponsorNotes` (free-text justification, e.g. "renewal due Q3 2026"). v2.2.0 lets the data flow but does not enforce anything yet; v2.3.x will wire Access Review delegation and audit-report sponsor lookup (roadmap #28 + #32).
- **Roadmap #2 / #25 -- per-role permission drill-down in the Manager Graph tab.** Clicking an `entra-role` or `au-role` node now expands the right detail panel with the actual delegated permissions for that directory role: a one-line "N resource actions / M data actions" count in the key/value block plus a collapsible "Permissions granted (N)" section (auto-expanded for ≤20 actions) showing the role description, allowed/excluded resource actions, and allowed/excluded data actions -- each action in a monospace list with `+` / `-` prefixes and `(D)` for data-plane. Custom roles get a "(custom)" title prefix. Data is pulled from the existing `cache/entra-roles.json` tenant cache, which now persists the `rolePermissions[]` field straight from `GET /roleManagement/directory/roleDefinitions`; first-time use after upgrade requires a tenant-list refresh (badge in the toolbar, or the inline "↻ Refresh tenant lists" button shown when a role isn't in cache) to backfill `rolePermissions` into the existing cache file.
- **Roadmap #11 -- send TAP via email / Teams / Slack.** New `Send-PimAdminTap` helper in `engine/_shared/PIM-Functions.psm1` fans the freshly-minted TAP code out to every configured notification channel best-effort. SMTP uses `Send-MailMessage` (PS 5.1 native, with `-WarningAction SilentlyContinue` to mute MS's deprecation warning); Teams posts an Adaptive Card 1.4 payload via Workflows / connector webhook; Slack posts a plain `{ text }`. Channel matrix configured per-customer in a new `config/PIM4EntraPS.NotificationChannels.custom.ps1` (gitignored) using the schema doc'd in `.custom.sample.ps1`. Defaults to an empty hashtable in the shipped `.locked.ps1` -- no per-tenant infra leaks into the repo. WhatIfMode-aware: when set, helper logs `[WHATIF] would send TAP to ... via <channel>` and produces zero network traffic. Wired into `CreateUpdate-Accounts-From-file-CSV` immediately after `Write-PimAdminTap`; delivery failure NEVER blocks account creation (entire call is `Try {} Catch {}`-wrapped). Recipient for SMTP defaults to the admin row's `ManagerEmail` column (roadmap #1); Teams / Slack target the configured webhook URL.
- **Roadmap #12 -- scheduled TAP start time.** New `Resolve-PimTapStartDateTime` helper recognizes relative natural-ish expressions in the `TAPStartDate` CSV column in addition to the ISO 8601 / culture-specific shapes v2.1.x already supported. Supported forms (case-insensitive, all coerce to UTC): `+2d 8:00`, `+3 days at 8am`, `in 2 days at 9am`, `2 hours` (N hours from now), `tomorrow`, `today 14:30`, `next monday 10:00`, full ISO `2026-06-04T08:00:00Z`, plus anything `CorrelateDateTimeLanguage` or `[datetime]::Parse` can handle as a last resort. Defaults for relative expressions: hour=09, minute=00 ("next business-day morning" handover convention). `New-PimTemporaryAccessPass` calls the resolver first and falls back to the legacy direct `[datetime]` cast for max backward compat; on total parse failure it omits `startDateTime` from the Graph body (TAP starts immediately) with a `Write-Warning` -- never crashes the engine.

---

## v2.1.7 -- Roadmap + sequencing for v2.2.x / v3.0

New `docs/ROADMAP.md` captures the ~34 customer-driven feature requests with sizing (S/M/L/XL), dependencies, themes (Manager UX / TAP / per-row policy / discovery / webhooks / governance / SQL backend), and a release-by-release sequencing recommendation. Includes the one big architectural decision -- CSV vs Azure Blob vs SQL backend -- with a "stay on CSV through v2.2.x, revisit at v3.0" recommendation and explicit triggers for when to flip.

Pure docs release; no code changes.

---

## v2.1.6 -- Hotfix: Ensure-DateTime null-safe (kills the persistent engine crash at line 1196)

Root cause of the engine crash `Assign-Groups-Accounts-From-file-CSV : Cannot bind argument to parameter 'InputObject' because it is null` that survived v2.0.0/v2.1.x hardening:

1. `CorrelateDateTimeLanguage -DateInput $ValueChk` returns `$null` when it can't parse the date (e.g. `'09/14/2026 10:44:37'` -- US format on a da-DK locale; only emits `Write-Warning`).
2. That `$null` flows into `(Ensure-DateTime $ExpirationDate)` at 6 different call-sites in `PIM-Functions.psm1`.
3. `Ensure-DateTime`'s `$InputObject` param was `[Parameter(Mandatory = $true)] [object]` -- PowerShell's parameter binder rejects a null Mandatory positional argument with the exact `InputObject is null` message we kept seeing.

Fix: `Ensure-DateTime` is now null-safe. Removes `Mandatory = $true` from the param, returns a far-future date (`Get-Date + 99 years`) when input is null / empty / whitespace. Downstream `New-TimeSpan -End ...` gets a valid DateTime, the "is this expiring in <30 days?" check is just false, the row is treated as "not expiring" -- safe no-op instead of engine crash.

No call-site changes needed (single helper hardens all 6 patterns at once).

Verification: this is the same crash signature reported across smoke tests since v2.0.0; re-run the engine to confirm the row that produced `WARNING: Unable to parse datetime: '09/14/2026 10:44:37'` now continues past it instead of crashing the function.

---

## v2.1.5 -- Hotfix: visible feedback on "Remove this assignment row" button

The FK-001 quick-fix "Remove this assignment row" button (v2.1.2) staged the deletion into `pendingChanges` correctly, but gave no visible feedback -- the Validate tab still showed the violation (because the validator reads on-disk CSVs, not the pending pool), and the toast at the top of `vResults` was off-screen if the operator had scrolled down. Users reported "nothing happens when I click Remove".

Fix: the button itself now shows immediate status -- disabled + "Working..." while the underlying `loadCsv` + `ensurePending` resolves, then "✓ Staged for delete (commit on Save tab)" in green when it lands in the pending pool. Idempotent against double-click (busy flag).

---

## v2.1.4 -- Hotfix: PIM-Functions auto-loads naming-conventions at module init

v2.1.3 shipped the `Get-PimAdminsFiltered` / `Get-PimGroupsFiltered` perf helpers but missed a load step: the engine launcher (`launcher.internal-vm.ps1` / `.community-vm.ps1`) never dot-sources `config/PIM4EntraPS.NamingConventions.{locked,custom}.ps1`, so `$global:PIM_NamingConventions` was `$null` at engine runtime and the new helpers would have warned + fallen back to unfiltered (no perf win).

Fix: `engine/_shared/PIM-Functions.psm1` now auto-loads both files at module-init time (`. $configRoot\PIM4EntraPS.NamingConventions.locked.ps1` then `. $configRoot\PIM4EntraPS.NamingConventions.custom.ps1` if present). Single block, idempotent, swallows + warns on failure.

Verified end-to-end on the customer VM: `[perf] Get-PimAdminsFiltered: $filter=startswith(userPrincipalName,'Admin-') or startswith(userPrincipalName,'X-Admin-')` + `[perf] Get-PimGroupsFiltered: $filter=startswith(displayName,'PIM-')` both fire on engine boot.

---

## v2.1.3 -- Server-side Graph filtering + customer-naming-aware wizards + naming-convention schema

Three changes that all hinge on the same thing: **the customer's naming convention is the source of truth**, both for engine performance and for the Manager's wizards. Stops the engine from fetching 514,000 users / 30,000 groups when it only needs 30 admins / 200 PIM-* groups, and stops the Manager from guessing `PIM-` prefixes that don't match what the customer actually uses.

### 1. Server-side Graph filtering (the 514k user fix)

Two new helpers in `engine/_shared/PIM-Functions.psm1`:

- **`Get-PimAdminsFiltered`** -- replaces `Get-MgUser -All` in engine hot paths. Derives the admin name prefix(es) from `$global:PIM_NamingConventions.AdminAccountPatterns` (or legacy `AdminAccountPattern`) and passes them as `$filter=startswith(userPrincipalName, '...')` to the Graph query. On a 514,000-user tenant this returns ~30 admins instead of all 514,000.
- **`Get-PimGroupsFiltered`** -- same idea for `Get-MgGroup -All`. Derives the prefix from `$global:PIM_NamingConventions.PimGroupPattern` (plus `PimGroupAuPattern` if it differs). Returns ~hundreds of `PIM-*` groups instead of all 30,000.
- **`Get-PimNamePrefix`** -- helper that extracts the literal prefix (everything before the first `{Token}` placeholder) from any naming-convention pattern. Honours every customer's prefix shape (`PIM-`, `PIM_`, `grp-e-pim-`, etc.).

**Fallback**: if no prefix is configured / prefix is shorter than 3 chars, both helpers warn loudly + fall back to unfiltered. Engines never silently regress.

Applied across 13 engines (every `Get-MgUser -all:$true` / `Get-MgGroup -all:$true` call-site):

- `PIM-Baseline-Management-CSV` (+ 6 narrowed variants)
- `PIM-Baseline-Management-SQL`
- `PIM-Assignment-Exporter` / `-CSV-Only`
- `PIM-Assignment-Wizard` / `-Revoker`

Customer requirement to benefit from the optimization: set `AdminAccountPatterns` + `PimGroupPattern` in `config/PIM4EntraPS.NamingConventions.custom.ps1` to match the actual tenant naming. The schema doc has a worked example per customer naming style.

### 2. Manager: data-driven Re-add-definition wizard

The "Re-add definition for `<tag>`" dialog now learns the right CSV + the right GroupName format from the customer's own existing data instead of guessing:

- **Layer 1** -- if the customer set `TagPrefixToCsv` in their naming-conventions `.custom.ps1`, longest-prefix wins.
- **Layer 2** -- otherwise scan all 7 `PIM-Definitions-*.csv` files: which CSV holds the most tags sharing a prefix with the missing tag? That's the default. Also copies an existing matching row's `GroupName` and substitutes the tag (so a customer with `grp-e-pim-{tag}` groups gets `grp-e-pim-<new-tag>` suggested, not the assumed `PIM-<new-tag>`).
- **Layer 3** -- fallback to the literal prefix of `PimGroupPattern` (`pat.split('{')[0]`).
- **Layer 4** -- if nothing matches, leave the field blank and let the operator fill in their convention manually. No `PIM-` assumption.

### 3. Naming-convention schema doc (v2 of the .locked.ps1 + .custom.sample.ps1)

`config/PIM4EntraPS.NamingConventions.custom.sample.ps1` rewritten as the formal schema doc -- every supported key, what consumes it, examples from real customers (Customer A: `Admin-{Initials}-L{Level}-T{Tier}-{Platform}`, Customer B: `adm{Initials}`, Customer C: `a-{Owner}`). New keys:

- **`AdminAccountPatterns`** -- hashtable mapping `UserType` (Internal / External / Guest) to per-type name template. Lets a customer use `Admin-{Initials}` for internals and `X-Admin-{Initials}` or `extadm{Initials}` for externals in the same tenant. Legacy `AdminAccountPattern` (single string) still honoured as fallback.
- **`PimGroupTagRegex`** -- optional strict regex for `GroupTag` validation. Default null (Manager accepts any alphanumeric tag).
- **`TagPrefixToCsv`** -- hashtable mapping tag prefixes to `PIM-Definitions-*.csv` files (longest match wins). Drives the Manager's Re-add wizard CSV picker.
- **Performance optimization section** -- documents how the literal-prefix extraction feeds both the engine's `Get-PimAdminsFiltered` / `Get-PimGroupsFiltered` and the Filters scriptblocks.

### Migration

- **Customers**: copy `config/PIM4EntraPS.NamingConventions.custom.sample.ps1` to `.custom.ps1` (if you haven't already), uncomment + set `AdminAccountPatterns` and `PimGroupPattern` to match your tenant. Without this, the engine helpers warn + fall back to unfiltered (same speed as before, no regression).
- **No CSV schema change**. No launcher change. No engine API change beyond the swap from `Get-MgUser -All` to `Get-PimAdminsFiltered`.

### Verification

- All 13 engine `.ps1` files + the shared `.psm1` parse-clean under PowerShell 5.1.
- `Get-PimNamePrefix` validated against patterns: `PIM-{Service}` -> `PIM-`, `PIM_{Role}_{Department}` -> `PIM_`, `grp-e-pim-{Role}` -> `grp-e-pim-`, `Admin-{Initials}` -> `Admin-`.

### Known gap (v2.1.4 backlog)

- The customer's shipped `PimGroupPattern` default is `PIM_{Role}_{Department}` (with underscore). But real customer data uses `PIM-` (hyphen). Until they override in `.custom.ps1`, the helpers will derive `PIM_` as the prefix and return 0 matches -- triggering the warn-and-fall-back path. Either set the override, or v2.1.4 will change the shipped default to the canonical hyphen-shape PIM-{Service}-{Name}-L{Level}-T{Tier}-{Code}-{Domain}.

---

## v2.1.2 -- PIM Manager v0.3: pre-flight validator + bulk Fix-all + multi-step wizards + tenant cache + dropdown pickers

The Manager went from "spreadsheet replacement that catches errors at engine runtime" to "spreadsheet replacement that **stops you before you make the mistakes**". Five large landings (three sub-agents + targeted patches):

### 1. Pre-flight validator (new `Validate` tab)

`tools/pim-manager/_validator.ps1` (~870 lines) ships 16 rule codes, ran in <1 s against the production 538-node / 789-edge real-customer config, found **19 errors + 527 warnings + 161 infos** -- including the exact `Entra-ID-CostBillingReader-L1` orphan that crashed the smoke test at line 1196.

Rules:
- `PIM-FK-001/002/003` -- foreign-key checks (GroupTag / Username / AdministrativeUnitTag referenced but not defined).
- `PIM-RA-001/002` -- role-assignable group constraints (must be Role-Assignable when terminating in an Entra ID role; only Eligible assignments to such groups).
- `PIM-TIER-001/002` -- tier-crossing + admin/group tier mismatch.
- `PIM-NAME-001/002` -- naming-convention regex on tags + admin UPNs.
- `PIM-ORPHAN-001/002/003` -- admins / groups with no assignments.
- `PIM-DUP-001` -- same admin reaches same target via 2+ paths.
- `PIM-STALE-001/002` -- role display name or AU tag not in tenant cache (Microsoft renames / removes catch).
- `PIM-STATUS-001` -- AccountStatus Disabled/Revoked but StatusChangeCode empty in MSP variant.
- `PIM-DOMAIN-001` / `PIM-TAP-001` -- minor data-quality checks.

UI: new Validate tab between Save and the right-side meta. Severity chips, CSV filter, regex search, "Open in Grid" jumps to the offending cell. Auto-runs on page load, after every commit, and when the tab is opened. **Save tab Commit-all is gated** when error-severity violations exist (toggle the "Block Save on errors" off to override).

### 2. Bulk "Fix all auto-fixable errors" + per-error quick-fix buttons

- Top-of-Validate button **Fix all auto-fixable errors&hellip;** opens a one-screen modal with three dropdowns: orphan FK-001s (default: add empty definitions), stale Entra roles STALE-001 (default: delete assignments -- Microsoft renamed/removed the role), Active-on-role-assignable RA-002 (default: change to Eligible). One Apply click stages every change into pendingChanges; auto-re-runs validator.
- Per `PIM-FK-001` card: inline **Remove this assignment row** + **Re-add definition for &quot;X&quot;** buttons. The Re-add opens a small dialog with CSV picker (Tasks / Services / Processes / Resources / Departments / Organization / Roles), GroupTag pre-filled from the violation, GroupName + Description inputs, IsRoleAssignable default FALSE.
- Grid tab rows that have an active FK-001 violation get a **red outline + ⚠ marker** so you can't miss them when you bounce to the Grid.

### 3. Multi-step wizards in the New &amp; clone tab

Six wizards, rewritten as multi-step flows with the 10 easy-UX rules from `docs/MANAGER-UX-AUDIT.md`:

1. **New admin account** -- 5 steps (Person / Tier &amp; platform / Lifecycle / Role groups / Review). Auto-composes UPN + DisplayName + UserName.
2. **New permission group (Entra ID role)** -- 5 steps. "What kind of capability?" dropdown maps to the right `PIM-Definitions-*.csv`.
3. **New permission group (Azure resource)** -- 4 steps. Uses cached `azureScopes` picker.
4. **New role group** -- 4 steps. Distinct from perm-group wizard (was incorrectly aliased before).
5. **Clone an existing group** -- 3 steps. Right-click on graph opens it pre-populated with the source node.
6. **Project lifecycle (time-boxed)** -- 4 steps. Default 90-day, AutoExtend=FALSE.

Every wizard: plain-English labels + CSV column name as sub-label, "Why these fields?" collapsible per step, inline `e.g.` examples, sensible defaults (T1/L3/Cloud/ID/Eligible/365d), back-button + step pills, live "you'll get" preview, plain-English summary on Review, Cancel-and-discard with confirm.

**Focus-preservation bugfix** in `_wizRenderStep` -- typing in a wizard field no longer loses focus on every keystroke (was rerendering the whole step body, clobbering active element + caret).

### 4. Tenant cache + dropdown pickers

- `Open-PimManager.ps1 -RefreshTenantLists` -- new CLI mode (server-side spawnable via `POST /api/refresh-tenant-lists`). Uses the engine SPN to pull Entra ID roles, AUs, current PIM-* groups, Azure scopes; caches to `tools/pim-manager/cache/*.json`.
- New REST endpoints: `GET /api/tenant-lists`, `POST /api/refresh-tenant-lists`, `GET /api/naming-conventions`.
- Grid tab cells become `<select>` dropdowns for `RoleDefinitionName`, `AdministrativeUnitTag`, `AzScope`, `GroupTag` (when the cache is populated). "Custom value..." escape hatch on every dropdown for stale-cache / one-off cases.
- Cache-age badges next to each dropdown (live / stale / none).
- `cache/` folder gitignored so tenant-specific role / AU / sub names never accidentally commit.

### 5. Smaller patches

- **Cytoscape-dagre registration** -- explicit `cytoscape.use(window.cytoscapeDagre)` before first layout call. Without this the graph rendered as a single vertical line (the plugin's UMD doesn't auto-register reliably). Plus a `breadthfirst` fallback if dagre throws.
- **Naming-convention regex broadened** -- was rejecting legitimate role-group / dept-group / AD-synced tags (`ROLE-Helpdesk`, `ORG-IT`, `AD-ClientDevicesMgmt-Scoped-L2`). Default now accepts any alphanumeric tag; the strict permission-group shape is the OPT-IN regex via `$global:PIM_NamingConventions.PimGroupTagRegex` in `.custom.ps1`.
- **Naming-convention violations** -- now WARNINGS not blocks. Confirm dialog with "Commit anyway?" instead of refusing the commit.
- **showConfirm function header repair** -- a parallel linter had dropped a brace; restored.

### Migration

- **Customers**: pull this release, refresh tenant cache once on first run: `& 'tools\pim-manager\Open-PimManager.ps1' -RefreshTenantLists` (then open normally for the dropdowns to be live).
- **Existing tenant-list cache files**: none yet -- the `cache/` folder is new in this release.
- **No engine changes**. Engines + their launchers + the configs are unchanged from v2.1.1.

### Known gaps (v2.1.3 backlog)

- Legacy single-page wizard bodies still in `pim-manager.html` as dead code (`_wizardAdminLegacy` etc., ~700 lines) -- left for diff readability; strip in v2.1.3 cleanup.
- Engine CSV auto-extend (so a customer running v1 CSV format gets the new v2 columns -- `CreateTAP`, `MailForwardAddress`, `AccountStatus`, `StatusChangeCode` -- added on first read) -- queued.
- Engine null-guard at line 1196 of `PIM-Baseline-Management-CSV.ps1` -- the same crash class as the v2.0.0 ForEach null-guard but in a different code path; smoke test still hits it after the first 19 FK-001 errors are resolved.
- v2.2.0 sub-agents (Live tenant overlay, Admin reach explorer, One-click engine run from GUI) -- deliberately deferred; pre-flight + Fix-all is the single biggest UX win, ship those after this iteration settles.

### Verification

- `_validator.ps1` + `_tenantSync.ps1` + `Open-PimManager.ps1` parse-clean under PS 5.1.
- HTML inline JS parse-clean (`node --check` on the extracted block).
- `Open-PimManager.ps1` boots, serves the SPA, REST endpoints accept the bearer token (smoke-tested standalone with curl).
- Validator returns 19 errors / 527 warnings / 161 infos against real customer data in <1 s.

---

## v2.1.1 -- rename `pim-mapper` -> `pim-manager` + field-by-field UX audit + wizard scaffolding

The tool is no longer just a mapper -- it creates, edits, deletes, and now (in flight) gains wizards + dropdowns + a tenant cache. Renaming so the name describes what the tool does:

- `tools/pim-mapper/` -> `tools/pim-manager/`
- `Open-PimMapper.ps1` -> `Open-PimManager.ps1`
- `pim-mapper.html` -> `pim-manager.html`
- `pim-mapper-mutations.log` -> `pim-manager-mutations.log`
- HTML title + h1: "PIM4EntraPS Mapper" -> "PIM4EntraPS Manager"
- All references in `README.md`, `docs/DESIGN.md`, `RELEASENOTES.md`, the tool's own `README.md`.

### New: field-by-field UX audit (`docs/MANAGER-UX-AUDIT.md`)

Maps every column across all 14 CSVs to an input strategy (dropdown / autocomplete / tenant cache / cross-CSV / inherited / auto-derived / freeform). Used as the spec for the wizards + dropdowns landing in v2.1.2. Key rules:

- No typed GUIDs or ARM paths anywhere -- always picker.
- No typed Entra role display names -- always cache-backed dropdown.
- Selecting a `GroupTag` inherits 5 downstream columns (CPPlatform / Plane / TierLevel / PermissionScope / SyncPlatform) read-only with an override toggle.
- Naming convention auto-applies (operator never assembles `PIM-<Service>-<Name>-L<Level>-T<Tier>-<Code>-<Domain>` manually).
- Live preview of auto-derived fields while operator types upstream inputs.
- "Custom..." escape hatch on every dropdown for stale-cache / one-off cases.
- Tenant cache auto-refreshes on launch when stale (>24h) or missing.

### New: wizard scaffolding (in flight, ships in v2.1.2)

- `Open-PimManager.ps1` gains a new `-RefreshTenantLists` CLI mode (parses clean in v2.1.1; full functional implementation in v2.1.2). Pulls Entra ID roles, AUs, current PIM-* groups, Azure scopes via the engine SPN, caches to `tools/pim-manager/cache/*.json`.
- New helper file: `tools/pim-manager/_tenantSync.ps1` (dot-sourced by Open-PimManager.ps1).
- Wizards planned in v2.1.2: New admin, New permission group (Entra ID role variant), New permission group (Azure resource variant), Project lifecycle (PIM-PROJECT-* pattern), Clone permission group with new tag.

### Migration

- **Customers**: pull this release, your old `tools/pim-mapper/` path stops working. Replace any scripts/scheduled tasks that called `Open-PimMapper.ps1` with the same args against `Open-PimManager.ps1`.
- **Public mirror**: the rename propagates on the next publish workflow run (tag `PIM4EntraPS-v2.1.1`).

### Verification

- All renamed `.ps1` files parse-clean under PowerShell 5.1.
- HTML title + h1 updated.
- No remaining `pim-mapper` references in any tracked file (grep-verified).

---

## v2.1.0 -- MSP variant + AccountStatus kill-switch (CISO-controlled per-admin KV codes)

Scaffolds the "two engines per tenant" MSP topology: the same engine binary runs twice (once for local-owned admins, once for MSP-owned admins pulled from a central source), and a new `AccountStatus` CSV column lets the MSP centrally **Disable** or **Revoke** any admin across every tenant on the next pull -- but only if the customer's CISO has pre-authorized that admin via a per-admin code stored in the customer's own Key Vault.

### Defense-in-depth model

The kill-switch flow:

1. **Customer CISO** writes a per-admin secret to the customer's KV (named `pim-status-<slug>` where `<slug>` is the UPN lower-cased with `@` and `.` replaced by `-`). The value is any string the CISO chooses.
2. CISO tells the MSP the agreed code out-of-band (1Password / encrypted mail / phone).
3. **MSP** edits the central CSV: `AccountStatus = Disabled` or `Revoked`, `StatusChangeCode = <agreed code>`. Commits to the central source.
4. On every tenant's next cron tick, `Sync-PimMspConfig` pulls the updated CSV, and the engine reads the row.
5. `Test-PimAccountStatusChangeAuthorized` fetches the secret from THIS customer's KV and compares (constant-time) to the CSV-supplied code. Mismatch / missing secret / no code in CSV -> **refuse + log a security event** to `output/msp/status-change-DENIED-<yyyyMMdd>.csv`. Match -> proceed.
6. `Invoke-PimAccountStatusChange` dispatches to `Invoke-PimAccountDisable` (soft) or `Invoke-PimAccountRevoke` (hard: cancel every PIM-for-Groups eligibility / activation, remove from every direct group membership, then AccountEnabled=$false).

**Default-deny**: no KV secret = central status changes off for that admin. CISO opts in per admin.

An MSP-side compromise (attacker pushes malicious `AccountStatus=Revoked`) is contained: the attacker doesn't have the per-tenant KV secrets, so every tenant refuses the change.

### What's new

**Variant-aware path helpers** (`engine/_shared/PIM-Functions.psm1`)

- `Get-PimSolutionRoot` -- new, factored out.
- `Get-PimConfigDir` -- new. Routes to `config-<variant>/` when `$global:PIM_ConfigVariant` is set; otherwise to `config/` (back-compat, single-tenancy unchanged).
- `Get-PimConfigCsv`, `Get-PimCustomScript`, `Get-PimOutputDir`, `Get-PimOutputPath` -- rewired through `Get-PimConfigDir` so MSP runs read from `config-msp/`, write state to `output/msp/`, and never collide with local-variant snapshots.

**New helpers in PIM-Functions.psm1**

- `Sync-PimMspConfig` -- on `-ConfigVariant msp`, pull central config from the source declared in `config-msp/msp.source.json`. v2.1.0 supports `sourceType = "git"` (shallow clone, optional PAT auth via env var, whitelist of allowed file patterns, atomic per-file stage via `Move-Item -Force`, sync log at `output/msp/msp-sync-<utc>.log`). `blob` + `https` source types are scaffolded for v2.2.x.
- `Test-PimAccountStatusChangeAuthorized` -- the per-admin KV-secret check. Default-deny. Constant-time comparison. Mismatch -> alert to `output/.../status-change-DENIED-<yyyyMMdd>.csv` with a SHA-256 prefix of the provided code (not the code itself).
- `Invoke-PimAccountStatusChange` -- single entry point the engine calls for any non-`Enabled` status. Branches to Disable / Revoke and gates with `Test-PimAccountStatusChangeAuthorized` when variant=msp.
- `Invoke-PimAccountDisable` -- soft kill: `Update-MgUser -AccountEnabled:$false`. Leaves PIM assignments intact so reversal is fast.
- `Invoke-PimAccountRevoke` -- hard kill: cancel every eligible + active PIM-for-Groups schedule for the principal, remove from every direct group membership, set `AccountEnabled=$false`. WhatIfMode-aware. Writes one audit row per revocation to `output/<variant>/revoke-events-<yyyyMMdd>.csv` with prior memberships + cancelled schedule counts. **v2.1.0 limitation**: PIM Entra ID role schedule cancellation (`directoryRoleEligibilityScheduleRequest` / `directoryRoleAssignmentScheduleRequest`) detected + warned but NOT auto-cancelled; the operator must clear those in the PIM blade manually. Auto-cancel lands in v2.1.1.

**Engine wiring (`CreateUpdate-Accounts-From-file-CSV`)**

- Reads `AccountStatus` and `StatusChangeCode` columns from each row (back-compat: defaults to `Enabled` / empty when columns missing).
- When status != `Enabled`: dispatches to `Invoke-PimAccountStatusChange` and `continue`s -- a Disabled / Revoked admin stays in the state we just put them in (no create / update on the same row).

**CSV schema** -- additive (back-compat)

- `Account-Definitions-Admins.locked.csv` + `.custom.sample.csv` gain two columns: `AccountStatus` (default `Enabled`) + `StatusChangeCode` (required when variant=msp and status != Enabled).

**`config-local/` + `config-msp/` folder scaffolding**

- `config-local/README.md` -- documents the local-variant layout, bootstrap (copy `*.custom.sample.*` -> `*.custom.*`), foreign-admin isolation pattern (Filters scriptblock excludes `Admin-MSP-*`).
- `config-msp/README.md` -- documents the MSP-variant model (pulled, not edited), the CISO opt-in KV procedure, the two-scheduled-tasks-staggered-30min recommendation.
- `config-msp/msp.source.sample.json` -- template for the `msp.source.json` manifest (gitignored). Schema: `sourceType`, `url`, `branch`, `subPath`, `auth.{method, patEnvVar}`.
- `.gitignore` extended to cover both new folders with the same `*.sample.* / *.locked.* / README.md` exception pattern as `config/`.

**Launcher param** (4 flavours for `PIM-Baseline-Management-CSV`)

- New `-ConfigVariant local | msp | <empty>` switch. Empty = single-tenancy back-compat (engine reads from `config/`, writes to `output/`). `local` routes to `config-local/` + `output/local/`. `msp` routes to `config-msp/` + `output/msp/` AND triggers `Sync-PimMspConfig` before the engine runs.
- The 6 narrowed engine variants + SQL + Wizard + Revoker launchers do NOT yet carry `-ConfigVariant` in v2.1.0 -- only the main `PIM-Baseline-Management-CSV` launchers. Roll the same 2-edit pattern out to the others in v2.1.1 once the MSP customer's data shape is validated end-to-end.

**`repository.custom.sample.ps1`**

- Documents `$global:PIM_StatusChange_KeyVaultName` (the customer's KV holding the per-admin codes). Line stays commented out so single-tenancy customers don't need to set anything.

### Migration notes

- **Single-tenancy customers (no MSP)**: no action required. `-ConfigVariant` defaults to empty, helpers route to `config/` as before, `Account-Definitions-Admins.csv` additive columns default to `Enabled` so existing behaviour is preserved.
- **Adopting MSP variant for the first time**: see `config-msp/README.md` for the 4-step setup (copy `msp.source.sample.json` -> `msp.source.json`, fill in central source, optionally set PAT env var, schedule `-ConfigVariant msp`).
- **Adopting kill-switch**: CISO sets `$global:PIM_StatusChange_KeyVaultName` in `config/repository.custom.ps1` (or `config-msp/repository.custom.ps1`), then writes one `pim-status-<slug>` secret to that KV per admin they want central kill-switching for.

### Known gaps (v2.1.1 backlog)

- `Invoke-PimAccountRevoke` doesn't yet auto-cancel PIM Entra ID role schedules (only PIM-for-Groups). Detect + warn only.
- `Sync-PimMspConfig` supports `sourceType = "git"` only. Blob + https sources scaffolded but not implemented.
- `-ConfigVariant` lives only on the 4 `PIM-Baseline-Management-CSV` launchers; narrowed variants + SQL/Wizard/Revoker launchers still single-tenancy.
- No signature verification on the synced central config files. Operator currently relies on the central source's own integrity guarantees (git auth + branch protection + signed commits).
- Webhook on revoke (Slack/Teams/PagerDuty) deferred.

### Verification

- `PIM-Functions.psm1` + all 4 patched launchers parse-clean under PowerShell 5.1.
- `Get-PimConfigDir` correctly routes for empty / `local` / `msp` variants (manually exercised).
- CSV column add doesn't break existing engine read (the back-compat defaults trigger when the columns are absent).

---

## v2.0.0 -- PIM v2 framework complete: engine modernization + two companion tools (Mapper, Activator) + full design docs + one-shot SPN installer

This is the release where PIM4EntraPS becomes the full "PIM v2" toolkit from the WPNinja NO 2025 talk -- not just the baseline engine, but the GUI mapper that lets you see and edit the model, the Edge activator that lets admins bulk-activate without portal clicks, and the design + setup docs that make the whole thing onboardable in a new tenant in an afternoon.

### Why this is a major bump

Three structural changes that break the v1.x contract:

1. **CSV schema add**: `Account-Definitions-Admins.csv` gained two columns at the end -- `CreateTAP` + `TAPStartDate`. Additive (existing rows default to FALSE / empty), but existing customer CSVs need re-saving from the new template if they want column alignment. Customers using `Import-Csv` against the file get the new columns automatically.
2. **Internal function signature breaks**: `CreateUpdate-Accounts-From-file-CSV` and `CreateUpdate-Accounts-From-SQL` no longer accept `-DefaultPassword`. Each newly-created account now gets its own random password from `New-PimRandomPassword` (logged to `output/admin-passwords-<yyyyMMdd>.txt` for retrieval). Anyone calling these functions directly with the old signature needs to drop the parameter.
3. **Engine SPN permission add**: the engine now needs the application-level Graph permission `UserAuthenticationMethod.ReadWrite.All` to issue Temporary Access Passes when `CreateTAP=TRUE`. The new `setup/Install-PimEngineAppRegistration.ps1` requests it by default. If you're using TAP=FALSE everywhere, the permission is unused but still requested; admin consent is still required for the engine to start.

### What's new

**Engine modernization (`engine/_shared/PIM-Functions.psm1`)**

- `New-PimRandomPassword` -- crypto-random 24-char password with guaranteed class coverage (upper/lower/digit/symbol), shuffled cryptographically. Replaces the legacy "one shared KV password" pattern.
- `Write-PimAdminPassword` / `Write-PimAdminTap` -- append per-account credentials to `output/admin-passwords-<yyyyMMdd>.txt` and echo to console in cyan / yellow for one-time pickup.
- `New-PimTemporaryAccessPass` -- issues a TAP via Graph (`UserAuthenticationMethod.ReadWrite.All`) for freshly-created accounts when `CreateTAP=TRUE` in the admin CSV. Default lifetime 60 min, single-use.
- `Get-PimCustomScript` / `Get-PimConfigCsv` / `Get-PimOutputDir` / `Get-PimOutputPath` -- four small resolvers that replace the legacy `$global:PathScripts\...` lookups; engines now read from `config/*.custom.csv` (with `.locked.csv` fallback) and stage state under `output/` (gitignored, auto-created).
- `Manage-Powershell-Module` -- consolidated into the canonical module (the legacy `PIM-LegacyShims.ps1` is gone). Lazy module install + import for `AzResourceGraphPS`, `MicrosoftGraphPS`, `ExchangeOnlineManagement`.
- PowerShell 5.1 PSModulePath now strips `\PowerShell\7\` entries on import so `ExchangeOnlineManagement` doesn't hit the stale `fullclr\Microsoft.PackageManagement.dll` path.
- 8 legacy `"$($global:PathScripts)\OUTPUT\PIM"` literals replaced with `Get-PimOutputDir` calls; downstream `Import-Csv`s now guard with `Test-Path` (first-run = empty array, no crash).
- Null-guard the missing-`GroupTag` path in `Assign-Groups-Accounts-From-file-CSV`: previous behaviour was to log an error then crash on the next `Where-Object` because `$GroupName` was `$null`; now logs `"... skipping row"` + `continue`s. Two ForEach loops fixed.
- `PAG` -> `PIM` in 21 user-facing strings (error messages + step banners). Variable names like `$PAG_Groups_Definitions` left alone (internal, breaking-internal-only rename deferred).

**Engine launchers** (13 baseline engines)

- KV fetch of `AdminAccountsInitialPassword` removed everywhere. Engines that previously called `Get-AzKeyVaultSecret -Name "AdminAccountsInitialPassword"` now just don't.
- `WhatIfMode` guards added on the destructive Account create call sites in `PIM-Baseline-Management-CSV`, `PIM-Baseline-Management-CSV-AdminsOnly`, and `PIM-Baseline-Management-SQL`. `-WhatIfMode` now reliably skips the account create/modify path; reads still proceed.

**Config layout**

- `config/Custom-Repository.locked.ps1` -> `config/repository.custom.ps1` (gitignored on customer VMs) + `config/repository.custom.sample.ps1` (tracked template). Same content, rewired through the new helpers so paths derive from the solution root, not `$global:PathScripts`.
- `config/Custom-Policies.locked.ps1` -> `config/policies.custom.ps1` + `config/policies.custom.sample.ps1`. Same pattern.
- `config/Account-Definitions-Admins.locked.csv` -- added `CreateTAP` + `TAPStartDate` columns.

**New tool: `tools/pim-manager/`** (interactive graph viewer + grid editor)

- `Open-PimManager.ps1` -- default `-Server` mode binds a localhost-only `HttpListener` on a random free port, serves the SPA, exposes REST endpoints for GET/PUT each of the 14 CSVs + diff preview + heartbeat. Bearer-token auth (random GUID per session). Auto-terminates 30 s after the browser tab closes. `-StaticHtml` reverts to the v0.1 read-only baked-HTML viewer.
- `pim-manager.html` -- three-tab SPA (Graph | Grid | Save).
  - **Graph tab**: cytoscape.js DAG (admin -> role group -> permission group -> target), dagre L-to-R layout, layer + edge-type filters, regex search, click-to-highlight neighbourhood, side panel with FK chain.
  - **Grid tab**: pick any of the 14 CSVs, edit cells like a spreadsheet (`<table contenteditable>`, no third-party grid lib). Add row / delete row. Pending changes tracked per CSV.
  - **Save tab**: per-CSV diff preview (adds green, removes red, modifies yellow) before commit. One "Commit all" button writes `*.custom.csv` atomically (temp + `Move-Item -Force`, UTF-8 no-BOM, `;`-delimited).
  - Graph-tab delete button on any selected node/edge: removes the matching row(s) across affected CSVs into the pending-changes pool (commit via Save tab).
- All writes go to `<base>.custom.csv` only -- never `<base>.locked.csv`. Mutation log appended to `output/pim-manager-mutations.log`.

**New tool: `tools/pim-activator/`** (Edge browser extension for bulk PIM-for-Groups activation)

- Manifest V3 extension. Admin clicks the toolbar icon -> popup lists every eligible PIM-for-Groups assignment they have (filtered by `^PIM-` naming-convention regex by default) -> multi-select -> enter justification + duration -> **Activate**. Sequential POSTs to `/identityGovernance/privilegedAccess/group/assignmentScheduleRequests` with per-row status updates.
- Auth: `chrome.identity.launchWebAuthFlow` + PKCE (vanilla JS + Web Crypto SHA-256). No third-party libraries. Refresh token cached in `chrome.storage.local` for silent reauth.
- `Install-PimActivatorAppRegistration.ps1` -- one-time tenant setup. Creates the app reg as **PublicClient** redirect URI (not SPA -- avoids `AADSTS9002326` when the token endpoint is called from the extension's fetch context with no Origin header), wires delegated perms (`PrivilegedAccess.ReadWrite.AzureADGroup`, `Group.Read.All`, `User.Read`), optionally grants tenant-wide admin consent.
- `Install-PimActivator.ps1` -- per-PAW install. Writes Edge enterprise policy keys (`ExtensionInstallForcelist` + `3rdparty\extensions\<id>\policy` managed-storage payload). Intune-deployable as a Win32 app or via Settings Catalog. Bonus: `-Uninstall` mode removes both.
- `managed_schema.json` -- declares the keys admins can push via Intune (tenantId, clientId, groupNameFilter, defaultDurationHours, defaultJustification). `popup.js` reads `chrome.storage.managed` in preference to `config.js` so enterprise pushes always win.
- `README.md` -- documents the two-stage rollout (Stage 1 tenant setup, Stage 2 PAW install) + the dev-mode fallback path.

**New tool: `setup/Install-PimEngineAppRegistration.ps1`** (one-shot engine SPN installer)

- Creates / updates the engine app registration with **application** (not delegated) Graph permissions: `RoleManagement.ReadWrite.Directory`, `Group.ReadWrite.All`, `User.ReadWrite.All`, `Directory.Read.All`, `AdministrativeUnit.ReadWrite.All`, `PrivilegedAccess.ReadWrite.AzureADGroup`, `UserAuthenticationMethod.ReadWrite.All`.
- `-IncludeExchange` adds the Office 365 Exchange Online `Exchange.ManageAsApp` app role + assigns the Exchange Administrator directory role to the SP.
- `-GrantConsent` writes the per-permission `appRoleAssignments` so the engine doesn't need anyone to click "Grant admin consent" in the portal.
- `-AzureRbac` assigns User Access Administrator at the root management group via Az.Accounts + Az.Resources (so the engine can manage Azure RBAC PIM).
- Self-signed cert (`CN=PIM4EntraPS-Engine`, 2-year validity) generated by default; `-ExistingThumbprint` opts in to a pre-issued cert. `-ExportPfxPath` exports the cert+key for moving to the engine host.
- Output is the exact 5 `$global:` lines (TenantID, ApplicationID_Azure, CertificateThumbprint_Azure, ApplicationID_O365, CertificateThumbprint_O365) you paste into your launcher's `LauncherConfig.custom.ps1`.

**Docs**

- `README.md` -- full rewrite. Landing page narrative, 3-tier nesting diagram, quick-start, engine inventory table (15 engines), tools section (mapper + activator), repo layout, versioning, support. No internal launcher references (community-vm / community-azure only on the public face).
- `docs/DESIGN.md` -- 18-section architecture deep dive. Covers: PIM v1 -> v2 evolution, the 3-tier nesting pattern + role-assignable group constraint, direct vs indirect delegation, the naming convention with `<Code>` / `<Domain>` enumerations, tier acronyms (CP / WDP / MP / APP / USER) + level-to-tier mapping (L0-L2 = T0, L3-L9 = T1), lifecycle stages (Initial / Pilot1-3 / Prod), the as-code pattern, customer override convention (`.locked` / `.custom` / `.custom.sample`), engine taxonomy, launcher flavors, companion tools, project-based delegations (`PIM-PROJECT-*`), common pitfalls / lessons learned, PIM for AD architecture (separate companion project), companion projects (EntraPolicySuite, PIM-Role-Advisor, PIM4ActiveDirectoryPS), trade-offs / known gaps.

### Migration notes (for existing v1.x customers)

- **Re-create the engine SPN** with the new installer if you want TAP support: `setup\Install-PimEngineAppRegistration.ps1 -GrantConsent -IncludeExchange -AzureRbac -ExportPfxPath C:\TMP\pim-engine.pfx`. The new permission (`UserAuthenticationMethod.ReadWrite.All`) needs admin consent. Output gives you the 5 `$global:` lines for your `LauncherConfig.custom.ps1`.
- **Rename your customer config files**: `config\Custom-Repository.locked.ps1` -> `config\repository.custom.ps1` and `config\Custom-Policies.locked.ps1` -> `config\policies.custom.ps1`. Both are now gitignored (live only on the customer VM); the `.custom.sample.ps1` siblings are the tracked templates new installs copy from.
- **Re-save `Account-Definitions-Admins.custom.csv`** to pick up the new `CreateTAP` + `TAPStartDate` columns. Default them to `FALSE` / empty unless you actively want TAP issuance.
- **Drop `-DefaultPassword` from any custom callers** of `CreateUpdate-Accounts-From-file-CSV` / `CreateUpdate-Accounts-From-SQL`. The engine ones are already updated.
- **Remove the KV secret `AdminAccountsInitialPassword`** -- it's no longer read by any engine. (Optional; harmless to leave.)

### Verification

- All 13 engines + the shared module parse-clean under PowerShell 5.1.
- Smoke test (`PIM-Baseline-Management-CSV -WhatIfMode`) runs end-to-end against a real tenant: 11/11 list builds, 16 AUs processed, ExchangeOnline loaded via shim, accounts section skipped under WhatIfMode, PIM-for-Groups policy processing reaches every assigned group, null-guard correctly skips rows referencing missing `GroupTag`s.
- New SPN installer tested end-to-end (cert generated, app reg + SP created, 7 Graph app roles + Exchange.ManageAsApp + Exchange Administrator role + Azure RBAC at root MG all granted, PFX exported).
- Mapper v0.2 server boots, serves the SPA, REST endpoints accept the bearer token, atomic CSV writes verified.
- Activator extension files parse-clean; full end-to-end browser test still pending (requires the tenant-side app reg from `Install-PimActivatorAppRegistration.ps1`).

---

## v1.0.2 -- SecurityInsight launcher naming alignment + publish workflow now strips internal-azure launchers (not just internal-vm); engine path resolution rewired for new layout.

### Why

Two issues found after v1.0.1 shipped:

1. **`launcher.internal-azure.template.ps1` leaked to the public mirror.** The publish workflow's flat-layout strip rule was `*.internal-vm.*` only -- caught vm flavours but not azure. Internal-only Azure-Function launchers therefore made it to the public repo. This is the same risk as the v1.0.0 `.locked.csv` bug: missing exclusion pattern.

2. **Engine path resolution in launchers was broken.** v1.0.0 moved engines from `SCRIPTS/<Name>.ps1` to `engine/<Name>/<Name>.ps1`, but the 84 launcher files still walked the legacy `SCRIPTS/` + `scripts/` fallback chain. Any launcher invocation would have thrown "engine not found".

### What changed

**Publish workflow (`.github/workflows/publish.yml`)**
- Flat-layout internal-strip rule now matches both `*.internal-vm.*` AND `*.internal-azure.*` via a single regex (`\.internal-(vm|azure)\.`). Catches all current and future internal launcher flavours.

**Launcher filenames (all 21 task folders)**
- Dropped `.template` suffix: `launcher.<flavour>.template.ps1` -> `launcher.<flavour>.ps1`. Matches SecurityInsight convention.
- `LauncherConfig.sample.ps1` -> `LauncherConfig.custom.sample.ps1` (matches SI's `.custom.sample.ps1` template-for-customer naming).
- Added empty `LauncherConfig.defaults.ps1` placeholder per launcher folder (ships from repo; customers override via `.custom.ps1`).

**Launcher engine path resolution**
- Old: `foreach ($case in 'SCRIPTS','scripts') { $candidate = Join-Path $engineOwner (Join-Path $case '<Name>.ps1') ... }`
- New: `$solutionRoot = Split-Path -Parent (Split-Path -Parent $launcherDir); $engine = Join-Path $solutionRoot 'engine\<TaskName>\<TaskName>.ps1'`
- All 60 engine-bearing launcher files patched. The 24 config-only launcher files (Custom-Policies, Custom-Repository, Fix_PIM_MFA_Auth_Policy, PIM-extra, PIM-SQL-import-export-CSV, SQL-Connect) had no engine block to patch.

**Launcher config path references**
- All references to `LauncherConfig.ps1` (the customer's actual file) updated to `LauncherConfig.custom.ps1`.
- All references to `LauncherConfig.sample.ps1` (the template) updated to `LauncherConfig.custom.sample.ps1`.
- Customer-facing error messages updated accordingly.

### Migration notes

- **Customers with an existing `LauncherConfig.ps1`** in any launcher folder need to rename it to `LauncherConfig.custom.ps1`. Suggested one-liner per VM:
  `Get-ChildItem -Recurse -File -Filter 'LauncherConfig.ps1' | Rename-Item -NewName 'LauncherConfig.custom.ps1'`
- **No engine-script or engine-folder renames** in this release. PIM-Baseline-Management-CSV.ps1 is still PIM-Baseline-Management-CSV.ps1. Aligning engine names to SI's `Invoke-<Verb-Noun>.ps1` convention is a customer-facing breaking change and is deferred to a separate, explicit decision.

### Verification

- All 130 PS files in `launcher/` parse-clean.
- Public mirror at `KnudsenMorten/PIM4EntraPS` should now show no `*.internal-*.ps1` files after the v1.0.2 publish workflow runs.

---

## v1.0.1 -- Hotfix: 14 `.locked.csv` data files were silently ignored by the monorepo `.gitignore` and never reached the public mirror in v1.0.0.

### Why

`SOLUTIONS/**/config/*` rule in the monorepo `.gitignore` had an exception for `*.sample.*` (so `.custom.sample.csv` files shipped) but no exception for `*.locked.*`. The `.locked.ps1` files in v1.0.0 were unaffected because they were renamed from already-tracked `CUSTOMSCRIPTS/` files (`git mv` preserves tracked status); the 14 `.locked.csv` files were newly copied with `cp` and got silently ignored.

### What changed

- Added `!SOLUTIONS/**/config/*.locked.*` exception to the monorepo `.gitignore`.
- Staged + committed the 14 `.locked.csv` files that were missing from v1.0.0.
- No engine, launcher, or helper-file changes.

### Verification

Public mirror `config/` should now show 14 `.locked.csv` files in addition to the 14 `.custom.sample.csv` and 8 `.locked.ps1` / `.custom.sample.ps1` files that shipped in v1.0.0.

---

## v1.0.0 -- Solution restructure to match SecurityInsight conventions; logging, .locked/.custom split, and customer naming/filter extension points.

### Why

PIM4EntraPS was a flat layout of SCRIPTS/, CUSTOMSCRIPTS/, and LAUNCHERS/. As the solution grew (15+ engines, 20+ launcher tasks, 14 CSV data files) the conventions used by SecurityInsight became the right model: per-engine folders, per-task launchers with 4-flavour templates, shared init lib, .locked/.custom split for customer-overridable artifacts, and runtime log + output folders.

### What changed

**Layout (mirror of SecurityInsight)**

- `SCRIPTS/*.ps1` -> `engine/<task>/<task>.ps1` (one folder per engine).
- `LAUNCHERS/<task>/` -> `launcher/<task>/` (subfolder names preserved; 4-flavour templates + manifest + LauncherConfig.sample unchanged).
- `CUSTOMSCRIPTS/<x>.ps1` -> `config/<x>.locked.ps1` (these were policy + helper PS sourced by launchers; now ship as `.locked` so the .custom pattern applies).

**New: shared module**

- `engine/_shared/PIM-Functions.psm1` -- the canonical function library (~542 KB). All engines import this module instead of relying on the legacy 2LINKIT-Functions.psm1. Customer + community editions ship the same module.

**New: config/ folder with .locked / .custom split**

For every CSV (14 files) and PS1 (6 files) that ships from the repo:
- `<name>.locked.<ext>` -- bundled defaults from the repo (authoritative). Engine reads this if no .custom override exists.
- `<name>.custom.sample.<ext>` -- header-only (CSV) or stub (PS1) template a customer copies to `<name>.custom.<ext>`.
- `<name>.custom.<ext>` -- gitignored. Lives only on the customer's VM. Engine prefers this over `.locked` when present.

**New: customer naming + filter extension points**

Two new declarative customization layers in `config/`:

- `PIM4EntraPS.NamingConventions.locked.ps1` (+ `.custom.sample.ps1`) -- name patterns for admin accounts, PIM groups, resource groups, etc. Customers override patterns without forking engine code.
- `PIM4EntraPS.Filters.locked.ps1` (+ `.custom.sample.ps1`) -- scriptblocks that filter which users/groups/roles become PIM candidates. Locked file ships 5 filter kinds matching what the engines have historically done inline: `AdminCandidate`, `PimGroup`, `PimGroupResourceSyncAD`, `PimGroupServiceSyncAD`, `AURoleAllowed`, plus `AzureSubscription` for scope.

**New: generic context builder** (`engine/_shared/PIM-ContextBuilder.ps1`)

Removes the duplicated `Get-MgUser` + `Get-MgGroup` + `Where-Object` blocks from engine scripts. Two functions:

- `Build-PimContext [-Refresh] [-CacheSeconds 300]` -- fetches raw Entra lists once, applies every `$global:PIM_Filters` scriptblock, assigns results to the legacy `$Global:*_Definitions_ID` variable names (backward compatible with current engines). Cached 5min by default; re-call within window is a no-op.
- `Get-PimList -Kind <name>` -- convenience accessor (`Admins`, `PimGroups`, `AURoles`, etc). Auto-triggers `Build-PimContext` on first call.

Engines that adopt this pattern collapse 50+ lines of duplicated Graph-fetch-plus-filter to two lines. The pattern is additive in v1.0.0 -- existing engines keep working unchanged; rewire happens in a follow-up release.

Plus the launcher escape hatch:
- `launcher/<task>/launcher.custom.<flavour>.ps1` -- gitignored. Customer drops a fully replaced launcher here when neither config-driven naming nor filters are enough.

**New: launcher/_lib/ shared init**

- `PIM4EntraPS.shared-defaults.ps1` -- solution-wide default variables (Layer 0).
- `Initialize-LauncherConfig.ps1` -- layered config loader: shared defaults -> .locked PS -> .custom PS -> LauncherConfig.defaults -> LauncherConfig.custom. Final layer wins.
- `Start-LauncherTranscript.ps1` -- creates `logs/<engine>_<flavour>_<utcStamp>.log` on launcher entry.
- `Stop-LauncherTranscript.ps1` -- prunes logs older than `$global:PIM_LogRetentionDays` (default 30).

**New: runtime folders**

- `logs/` -- transcript output, gitignored.
- `output/` -- engine CSV/JSON exports, gitignored.

**New: top-level metadata**

- `VERSION` -- starts at `1.0.0`.
- `.gitignore` -- protects `*.custom.*`, runtime folders, and customer launcher overrides from public publish.

### Migration notes

- **Engines not yet rewired to use new helpers.** The file moves preserve git history (used `git mv`) but engine scripts still source paths via their old launchers; engines will be updated in a follow-up to: (a) import `engine/_shared/PIM-Functions.psm1`, (b) read `.custom.csv` with `.locked.csv` fallback, (c) call `Resolve-AdminName` / `Test-AdminCandidate` helpers instead of hardcoded patterns.
- **Existing customer overrides**: any customer-private files that were previously sitting outside the repo continue to be respected. The new `.custom.*` naming is for new installs; existing customers can rename their override files when convenient.
- **Publish workflow unchanged**: `launcher.internal-*.template.ps1` and folders named `internal/` are still stripped by `.github/workflows/publish.yml`. The new `engine/`, `launcher/`, and `config/` folders all ship to the public mirror.

### GUI mapper design notes (Phase 2, not in v1.0.0)

The CSVs model a 3-tier group-nesting design:

```
Admin                Role group              Permission groups          Target
ADMIN-MOK-ID  --E->  PIM-ROLE-CloudEngineer  --E--> PIM-Entra-ID-AppAdmin-L1-T0-CP-ID --E--> Entra ID role
                                             --A--> PIM-AzDevOps-TeamsContrib-...     --A--> AzDevOps
                                             --E--> PIM-AzRes-MP-Platform-...         --E--> Azure SQL VM / Cosmos
                                             --E--> PIM-PowerBI-WS-MyKPIs-...         --E--> Power BI

Edge labels: E = Eligible, A = Active (PIM activation type)
```

CSV mapping:
- `PIM-Assignments-Admins.csv` = tier 1 edges (admin -> role group, Eligible/Active)
- `PIM-Assignments-Groups.csv` = tier 2 nesting (role group -> permission group)
- `PIM-Assignments-Roles-Groups.csv` / `-Roles-AUs.csv` / `-Azure-Resources.csv` = tier 3 (permission group -> target)

Permission-group names follow `PIM-<Service>-<Name>-L<Level>-T<Tier>-<Code>-<Domain>`, generated from `$global:PIM_NamingConventions.PimGroupPattern`.

The Phase 2 GUI is therefore a **graph editor**, not a flat CSV grid:

1. Tree/sankey view of admin -> role group -> permission groups -> targets.
2. New-admin / new-permission / refactor-role workflows; names auto-generated from the naming-conventions pattern.
3. FK validation: every assignment target must exist in the matching Definitions CSV; naming-pattern match before save.
4. Save semantics: writes `.custom.csv` only (never `.locked.csv`), with diff preview before commit.

### Verification

- `git status` shows all moves as renames (history preserved).
- `engine/` contains 15 task folders + `_shared/PIM-Functions.psm1`.
- `launcher/` contains 21 task folders + `_lib/` (4 lib files).
- `config/` contains 28 CSVs (14 .locked + 14 .custom.sample) + 6 .locked.ps1 (from CUSTOMSCRIPTS) + 2 .locked + 2 .custom.sample (naming + filters).
- `logs/` and `output/` exist with `.gitignore` blocking content.

