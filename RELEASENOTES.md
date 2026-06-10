# Release notes for PIM4EntraPS

## v2.4.113

Latest 30 commits touching SOLUTIONS/PIM4EntraPS/ in the upstream monorepo monorepo:

- release: PIM4EntraPS v2.4.113 - README PIM Activator section rewritten to today's deploy architecture (docs-only) (df162df9)
- release: PIM4EntraPS v2.4.112 + extension v1.6.25 - popup manual single-tenant entry wins over managed catalog (fixes Save->onboarding loop on contaminated boxes) (b5ab0aa7)
- release: PIM4EntraPS v2.4.111 - Deploy-PimActivatorClient.ps1 stops defaulting to sibling discovered-tenant-catalog.json (cross-tenant leak); auto-discovers from live Entra instead (34a1f1c8)
- release: PIM4EntraPS v2.4.110 - Deploy-PimActivatorIntune.ps1 auto-skips Forcelist defValues when existing policy owns slot (avoids IME slot-cycling under -Force) (1771e06b)
- release: PIM4EntraPS v2.4.109 - PIM4EntraPS.PimActivator.admx removes unused <using> namespace dependency (strict tenants rejected upload as NamespaceMissing:Microsoft.Policies.Windows) (91c3e488)
- release: PIM4EntraPS v2.4.108 - Deploy-PimActivatorIntune.ps1 drops defaultLanguageCode from ADMX upload payload (Intune 400 ADMXDefaultLanguageCodeNotNull) (a17463d2)
- release: PIM4EntraPS v2.4.107 - Deploy-PimActivatorIntune.ps1 ADMX payload now has explicit @odata.type (fixes silent field null-out on strict tenants) (ab4a8d34)
- release: PIM4EntraPS v2.4.106 - Deploy-PimActivatorIntune.ps1 dumps full ADMX upload-failure detail (uploadInfo:null was hiding everything) (23320078)
- release: PIM4EntraPS v2.4.105 + extension v1.6.24 - fix popup pre-sign-in tabpanel bleed + fix Update script silently aborting gh-pages publish (097fba84)
- release: PIM4EntraPS v2.4.104 + extension v1.6.22 - -Repack works on PS 5.1 (mgmt1's runtime); guard moved from PEM input to produced CRX output bytes (6cdfd661)
- release: PIM4EntraPS v2.4.103 - Update-PimActivator-Extension.ps1 scrubs stale Secure Preferences UNCONDITIONALLY (v2.4.100 only scrubbed when binary present, missed the actual trap shape) (41fd4236)
- release: PIM4EntraPS v2.4.102 - Deploy-PimActivatorIntune.ps1 pre-flight scan for conflicting ExtensionInstallForcelist policies (prevents IME slot-cycling silent failure) (7e7de5d7)
- add Audit-ChromeForcelistInIntune.ps1 - read-only diagnostic that scans every Intune configuration policy (Settings Catalog + Administrative Templates + custom device configs) for Chrome ExtensionInstallForcelist values, flags malformed entries (empty string, invalid ext id, missing update URL). Used to pin down which Intune profile is shipping the bad forcelist entry that's blocking all extension installs. (bd371bf3)
- release: PIM4EntraPS v2.4.101 + extension v1.6.20 - popup CSS revert (v1.6.19 flex-column broke Edge) (709005f7)
- release: PIM4EntraPS v2.4.100 - Update-PimActivator-Extension.ps1 flush now scrubs stale Secure Preferences registration alongside cached CRX (prevents DISABLE_CORRUPTED trap) (3a9de353)
- release: PIM4EntraPS v2.4.99 - Deploy-PimActivatorIntune.ps1 catalog auto-discover (hotfix over v2.4.98) (785ff800)
- release: PIM4EntraPS v2.4.98 + extension v1.6.19 - unified Intune deploy + critical fix for ExtensionSettings schema bug that froze fleet at old versions + popup CSS no longer overflows Chromium popup cap (508f6eab)
- release: PIM4EntraPS v2.4.97 - Update-PimActivator-Extension.ps1 SAFETY FIX (no more profile wipes) + faster update trigger via --extensions-update-frequency=30 (cdc2c7cb)
- release: extension v1.6.16 - revert v1.6.13's footer-collapse experiment; restore 2-row footer layout (row 1: title + repo + GitHub + Report bug | tenant ID; row 2: dev attribution | tenant name + reset) (7018f592)
- release: extension v1.6.15 - wizard ALWAYS shows mode-selector on fresh deploy (removed auto-pick for single-tenant catalog that was silently skipping the picker); catalogPanel now carries BOTH picker + import sub-divs so 'Use centrally deployed' (multi) and 'Import JSON' modes can toggle independently regardless of current catalog state (a3885a4a)
- release: extension v1.6.14 - (a) new 3-card mode selector on first-run/reset wizard: 'Use centrally deployed' / 'Import JSON catalog' / 'Add single tenant'; each mode shows only its relevant section + a Back link to return to the picker (b) fix signOut: clear tenantTokens[activeTenantId] (was leaving the per-tenant token cache so loadConfig silently restored tokens after sign-out) + open login.microsoftonline.com/common/oauth2/v2.0/logout in a new tab to kill the Edge-side session cookies (c1d17a33)
- release: extension v1.6.13 - footer collapsed to single compact row (left: title + repo + dev attribution + GitHub/Report icons; right: tenant short-name + abbreviated ID + reset). Uses flex-wrap so right side drops to second line only when needed instead of getting clipped. Test-PushTenantCatalog.ps1 now seeds defaultJustification + defaultDurationHours in the auto-generated catalog. (5b308334)
- release: extension v1.6.12 - footer row 1 now carries GitHub + Report bug chips next to title; row 2 only shows developer attribution + tenant name (fb0a3d86)
- release: extension v1.6.11 - footer 2-row flex layout (title left + tenant ID right on row 1; dev attribution left + tenant name right on row 2) (3bee8363)
- release: extension v1.6.10 - footer split into 3 stacked rows (title / tenant info / dev attribution) so tenant name is on its own line + Developed by moves below; tenant name rendered prominent (bold sans-serif) with monospaced GUID after (34f0511f)
- release: extension v1.6.9 - popup.js readMergedCatalog wraps single-object catalog as 1-element array (defense against pre-v2.4.96 PS 5.1 unwrap bug pushed by old Intune profiles); Verify-PimActivatorIntunePolicy.ps1 shows tenantCatalog shape ARRAY vs OBJECT clearly (52e05f16)
- release: PIM4EntraPS v2.4.96 + extension v1.6.8 - TWO bugs blocking chrome.storage.managed: (a) manifest now declares storage.managed_schema -> managed-schema.json (without this Chromium returns empty from chrome.storage.managed regardless of registry) + (b) all 3 Intune push scripts now use ConvertTo-Json -InputObject @($catalog) to preserve array brackets on single-element catalogs (PS 5.1 + 7 compatible, prevents single-tenant catalog from being serialized as {object} instead of [array]) (4693e4cb)
- release: PIM4EntraPS v2.4.95 + extension v1.6.7 - popup max-height bumped 600->800px (Chromium's hard cap) + catalog import textarea shrunk from 6 to 3 rows (resize:vertical retained), so Save and continue button no longer disappears on first-run (a2c1331e)
- fix Verify-PimActivatorIntunePolicy.ps1: PS 5.1 doesn't accept 'if (...) {...} else {...}' as an expression inside Write-Host -ForegroundColor argument; lift the choice into a separate $summaryColor variable (9e0c5644)
- add Verify-PimActivatorIntunePolicy.ps1 - portable HKLM registry verifier for the 6 PIM Activator Intune policies, runs on any Windows endpoint with PS 5.1+ (no Graph dep) (8bf15a34)

---

# Release notes -- PIM4EntraPS

> **Curated changelog.** The publish workflow auto-prepends recent monorepo commits as a raw activity log; this file is the human-friendly narrative on top.

---

## v2.4.113 -- README: PIM Activator section rewritten to reflect today's deploy architecture (v2.4.103-v2.4.112 cumulative)

Replaces the outdated v1.1.x Activator section -- which still documented `-CreateIntuneRemediation`, `-GenerateLocalInstaller` paths and 1-hour duration defaults -- with the current architecture:

- Three deployment scripts described by use case (Intune-managed / non-Intune / maintainer repack), each with its tenant-discovery source explicitly noted (live Entra via Connect-MgGraph for both `Deploy-PimActivator{Intune,Client}.ps1`; master signing key in `~/.pim-activator/signing-key.pem` for `Update-PimActivator-Extension.ps1`).
- Two recovery scripts (`Fix-PimActivatorStuck.ps1`, `Reset-CorruptedExtensions.ps1`) called out for the DISABLE_CORRUPTED state Chromium gets into when the extension binary is removed but Secure Preferences keeps the registration entry.
- The four-policy ADMX profile shape (Forcelist + Sources + ExtensionSettings with `runtime_allowed_hosts: ['<all_urls>']` + Tenant catalog) documented per browser.
- The v2.4.110 conflict-aware `-Force` behaviour (skips Forcelist defValues when an upstream Settings Catalog policy already owns the slot).
- The v2.4.111 live-Entra auto-discover for `Deploy-PimActivatorClient.ps1` + the explicit `catalog source: ...` log line.
- The v1.6.25 manual-entry-wins logic that prevents stale managed catalog from shadowing an explicit manual save.
- Three-layer tenant config model (manual single-tenant > managed catalog) with a table of catalog-size behaviours.

Pure documentation -- no script behaviour changes.

---

## v2.4.112 + extension v1.6.25 -- popup manual single-tenant entry now always wins over managed catalog (fixes "Save and continue" looping back to onboarding)

Same v2.4.111 cross-tenant-leak incident exposed a second compounding bug: when `chrome.storage.managed.tenantCatalog` (registry-pushed) and the manual single-tenant entry (`chrome.storage.local.userTenantId / userClientId`) BOTH exist, the popup's `loadConfig()` always preferred the managed catalog. So on a box where the bad 2linkIT catalog was still in registry, the user could type Nunagreen's tenant + clientId in the manual form, click "Save and continue", and:

1. The save succeeded (`userTenantId = Nunagreen` written to `chrome.storage.local`).
2. The popup reloaded.
3. `loadConfig()` saw the managed catalog (2linkIT) first, picked the catalog branch, found no `activeTenantId` matching, returned an empty config -- triggering `renderOnboarding()` to fire AGAIN.
4. From the user's perspective: "I saved but it goes back to onboarding -- save isn't working."

**Fix.** `popup.js` `loadConfig()` now checks for an explicitly saved manual single-tenant config (both userTenantId AND userClientId being non-zero GUIDs) BEFORE the catalog branch. When manual is set, the returned config uses manual values + `tenantName: '(manual entry)'`. Catalog still populates so the switcher chip can render if the user wants to swap. This means once you click "Save and continue" with valid GUIDs, your manual config sticks across reloads regardless of what's in managed storage.

Note: this is a popup-level fix. The underlying registry leak should still be cleaned up by re-running `Deploy-PimActivatorClient.ps1` (v2.4.111+, which auto-discovers from live Entra) on the affected box -- that overwrites the bad `tenantCatalog` registry value with the correct one. The v1.6.25 popup change just prevents the symptom that "Save doesn't work" while the leak persists.

---

## v2.4.111 -- Deploy-PimActivatorClient.ps1 stops defaulting to the sibling `discovered-tenant-catalog.json` (cross-tenant leak); auto-discovers from live Entra instead

**Incident.** A customer deploy ran `Deploy-PimActivatorClient.ps1` on a Nunagreen-tenant box. The script's `-CatalogJsonPath` parameter defaulted to `(scriptDir)\discovered-tenant-catalog.json` -- a sibling file pattern that "worked out of the box on the maintainer's repo layout". That file was untracked but PRESENT on the box (likely transferred along with the script folder from an earlier setup on a 2linkIT-tenant box). The script silently picked it up and wrote **2linkIT's** tenantId + clientId into the customer's `chrome.storage.managed.tenantCatalog` registry path -- cross-tenant data leak. No log line called it out because the file existed and the script saw nothing to warn about.

**Fix.** Three parts:

1. `Deploy-PimActivatorClient.ps1`: removed the sibling-file default. When `-CatalogJsonPath` is omitted (the common case), the script now **auto-discovers from the LIVE Microsoft Graph context on the box** -- same logic Deploy-PimActivatorIntune.ps1 uses: `/organization` for tenant id + display name, `/applications?$filter=startswith(displayName,'PIM Activator')` for the per-tenant client id. Connect-MgGraph runs interactively if not already connected. The catalog source is now ALWAYS the tenant the operator is currently signed into -- never a stale file from somewhere else.

2. `.gitignore` (PIM4EntraPS-level): added `tools/pim-activator/discovered-tenant-catalog.json`. Defense-in-depth so an accidentally-committed catalog file from a maintainer's working dir can never propagate to other tenants' boxes via `git pull`.

3. Each catalog-source path now logs a clear line: `catalog source: -CatalogJsonPath '...'` or `catalog source: live Entra auto-discover  (tenant 'X' / <tenantId>  clientId <appId>)`. The operator sees on every run which tenant's data is about to be written, so a cross-tenant mismatch is impossible to miss.

**Recovery on a contaminated box.** Re-run `Deploy-PimActivatorClient.ps1` after `git pull`. With v2.4.111, it discovers the box's actual tenant and overwrites the bad `tenantCatalog` registry value with the correct one. Verify with `Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\eheocihmlppcophaeakmdenhgcookkab\policy' -Name tenantCatalog` -- the JSON should contain the box's own tenant id, not 2linkIT's `f0fa27a0-...`.

---

## v2.4.110 -- Deploy-PimActivatorIntune.ps1 auto-skips Forcelist defValues when an existing policy already owns the slot (avoids IME slot-cycling even under `-Force`)

Earlier today's incident: on a tenant where the operator already had a Settings Catalog policy pushing the PIM Activator forcelist, running this script with `-Force` re-wrote a competing forcelist definition value into the ADMX profile -- re-creating the exact IME slot-cycling problem the v2.4.102 pre-flight scan was meant to prevent. `-Force` was meant to override the *abort* on conflict, not to push a known-conflicting write.

Fix: when the pre-flight scan finds a conflict AND `-Force` is supplied, the script now:

1. Prints an `ACTION REQUIRED` block naming each conflicting policy + the exact `<extId>;<updateUrl>` row the operator must paste into those policy's extension lists.
2. Sets `$script:SkipForcelistDueToConflict = $true`.
3. **Skips the Forcelist policy entirely** in the resolution loop (no Forcelist definition lookup attempt) and writes only `Sources`, `Settings`, `Catalog` (3 per browser, 6 total).
4. The write loop logs `[SKIP] $b Forcelist not written -- existing policy in tenant owns this registry slot. Add '<extId>;<updateUrl>' there.` per browser, making the residual operator-side task crystal clear.

When no conflict exists, behaviour is unchanged: 8 definition values get written (Forcelist + Sources + Settings + Catalog x Edge + Chrome).

Verified end-to-end on mgmt1 against 2linkit (which has the existing Settings Catalog policy in play): script printed the conflict, the ACTION REQUIRED block, then wrote only the 6 non-forcelist definition values + 2 `[SKIP]` lines naming the row to add upstream.

---

## v2.4.109 -- PIM4EntraPS.PimActivator.admx removed unused `<using>` namespace dependency (strict Intune tenants rejected the upload as `NamespaceMissing`)

Customer-tenant deploy surfaced the actual root cause via the portal's "Import ADMX" workflow (which gave the clear error the Graph endpoint hid):

> `ADMX file referenced not found NamespaceMissing:Microsoft.Policies.Windows. Please upload it first.`

The ADMX declared `<using prefix="windows" namespace="Microsoft.Policies.Windows" />` but never actually referenced the `windows:` prefix anywhere -- pure dead code. Strict Intune tenants check that every `<using>` target is pre-loaded and reject when it isn't (Nunagreen 2026-06-10). Tolerant tenants (2linkit) skipped the check and the ADMX uploaded fine -- which is why this file shipped for months with the latent bug.

Fix: removed the `<using>` declaration. Our ADMX is now fully self-contained -- zero external namespace dependencies -- works on every tenant strictness level.

Verified end-to-end on mgmt1 against the 2linkit tenant (which had been freshly cleaned of all prior ADMX rows): upload succeeded with `status: available` on the first try; subsequent policy-resolution loop found all 4 policies per browser (Forcelist, Sources, Settings, Tenant catalog); all 8 definition values set on `[PimActivator] client settings`; tenant catalog pushed for both Edge + Chrome.

(Note: the v2.4.107 `@odata.type` discriminators stay -- still needed by strict tenants for proper deserialization. v2.4.108's `defaultLanguageCode` removal also stays -- Intune still requires that field absent. v2.4.109 is the final piece of the strict-tenant compatibility set.)

---

## v2.4.108 -- Deploy-PimActivatorIntune.ps1 drops `defaultLanguageCode` from ADMX payload (Intune requires it absent; v2.4.107 wrongly added it)

v2.4.107 added `defaultLanguageCode = 'en-US'` to the upload body, thinking it would help on strict tenants. Intune is explicit: `400 Bad Request -- ADMX DefaultLanguageCode needs to be null, it will taken from ADML file` (CustomApiErrorPhrase `ADMXDefaultLanguageCodeNotNull`). The service derives this field from the first ADML's `languageCode` and rejects any payload that tries to set it. v2.4.108 removes the field; the v2.4.107 `@odata.type` discriminators (which ARE required by strict tenants) stay.

Net: v2.4.107 fixed the silent null-out by adding @odata.type AND broke the upload by also adding defaultLanguageCode. v2.4.108 keeps the first fix, removes the second.

---

## v2.4.107 -- Deploy-PimActivatorIntune.ps1 sets explicit @odata.type on the ADMX upload payload (fixes silent null-out on strict tenants)

v2.4.106's full-response diagnostics surfaced the actual rejection: customer tenant accepted the POST and created the `groupPolicyUploadedDefinitionFiles` row, but every field we sent (`targetNamespace`, `targetPrefix`, `content`, `revision`, `languageCodes`, the entire `groupPolicyUploadedLanguageFiles` collection) came back as `null` or `[]`. Only `fileName` and `defaultLanguageCode` stuck. Classic symptom of a Graph beta endpoint with strict type discrimination -- without an explicit `@odata.type` on the entity, Intune's deserializer couldn't bind any of the typed properties, but didn't reject the request either; just silently emitted an empty row + `status=uploadFailed`.

Fix: payload now carries `'@odata.type' = '#microsoft.graph.groupPolicyUploadedDefinitionFile'` on the outer body and `'@odata.type' = '#microsoft.graph.groupPolicyUploadedLanguageFile'` on each inner collection item. Other tenants (2linkit, where v2.4.98-v2.4.106 worked) tolerated the missing type discriminator because the endpoint version they hit had a default type fallback. Now we always set the type so the deploy survives whichever tenant strictness level Intune routes through.

Also added an explicit `defaultLanguageCode = 'en-US'` on the outer body (was being auto-populated by Intune on tolerant tenants but missing from the body on strict ones).

---

## v2.4.106 -- Deploy-PimActivatorIntune.ps1 dumps full ADMX upload-failure detail (status=uploadFailed previously surfaced only as `uploadInfo: null`)

Customer-tenant rollout hit `status: uploadFailed` on the custom ADMX upload step with no further detail (`uploadInfo: null`), making diagnosis impossible. Intune's `groupPolicyUploadedDefinitionFiles` endpoint sometimes carries the actual rejection reason in a sub-collection (`groupPolicyOperations`) or in fields the previous code didn't print -- the old throw line only stringified `uploadInfo`, so any other field with the real error went unseen. Now on `uploadFailed` / `removalFailed` the script prints the full Graph row JSON (depth 8) and then fetches + prints every `groupPolicyOperations` entry (`operationType`, `status`, `errorCode`, `errorMessage`, `statusDetails`) before throwing. Next failure will give us real signal to act on rather than `null`.

The throw message itself now lists the three most-common causes (tenant ADMX cap, stale-row contention, Intune service-side transient) with the right next-step for each.

---

## v2.4.105 + extension v1.6.24 -- popup pre-sign-in showed both tabpanels bleeding together; gh-pages publish silently aborted on git stderr

**Popup fix (extension v1.6.23/v1.6.24).** Pre-sign-in the popup showed the Activate-tab sign-in prompt AND the My Access-tab toolbar (`Re-sign in | all | none | Deactivate selected (0)` + `Loading...`) at the same time. The tab strip itself is intentionally hidden before sign-in completes; both tabpanels carry inline `style="display:flex; flex-direction:column"` for their post-sign-in layout; and the `[role=tabpanel][hidden] { display:none; }` CSS rule that's supposed to suppress the inactive panel was being **overridden by the inline `display:flex`** (inline style beats external CSS without `!important`). Result: `panel-myaccess` had the `hidden` attribute set but rendered anyway. Fix: `[role=tabpanel][hidden] { display:none !important; }` -- now `hidden` always wins, tab toggling still works (JS removes the attribute when switching tabs, inline display:flex takes over).

**Publish-step fix (script).** `Update-PimActivator-Extension.ps1`'s `-Repack` / `-PackOnly` was silently aborting the gh-pages push step on a CLEAN run. Root cause: git writes informational lines (`Cloning into...`, `From <repo>`, etc.) to stderr even on success. The previous `2>&1 | Out-Null` pipeline routed those into PowerShell's error stream, which the script-wide `$ErrorActionPreference = 'Stop'` then treated as terminating errors. The CRX got packed + validated, but never pushed -- gh-pages stayed on the previous version while the script reported success. Switched to `2>$null 1>$null` + explicit `$LASTEXITCODE` checks so only real git failures abort the step. Also replaced `git pull` with `git fetch + git reset --hard origin/gh-pages` to dodge the shallow-clone "reference already exists" quirk that sometimes corrupts the local ref database.

Verified end-to-end on mgmt1: extension v1.6.24 is live on gh-pages (commit d1b165e), and the popup pre-sign-in screen now shows only the header + sign-in prompt + credit footer (no My Access bleed-through).

---

## v2.4.104 + extension v1.6.22 -- Update-PimActivator-Extension.ps1 -Repack / -PackOnly works on PS 5.1 (v2.4.98 PEM-based pre-pack guard required PS 7+)

**Reason.** v2.4.98 added a pre-pack signing-key guard that derives the extension id from `signing-key.pem` via `[System.Security.Cryptography.RSA]::Create().ImportFromPem()`. That API is .NET Core 3.0+ / PS 7+ only -- PS 5.1's `RSACryptoServiceProvider` doesn't have it. On mgmt1 (the master signing-key host, which runs PS 5.1 by default), the guard threw `Method invocation failed because [System.Security.Cryptography.RSACryptoServiceProvider] does not contain a method named 'ImportFromPem'` and aborted every repack attempt. v1.6.20 (popup CSS revert) could never reach gh-pages, leaving the fleet stuck on v1.6.19's broken flex-column popup.

**Fix.** Pre-pack guard is now best-effort: tries `ImportFromPem`, on any failure prints a `Skipping PEM-based pre-pack check` warning and falls through. A new POST-pack guard then derives the canonical extension id from the freshly-packed CRX's protobuf v3 header (`SHA256(first AsymmetricKeyProof.public_key)` -> first 16 bytes -> remapped 0-15 -> 'a'-'p') using only basic byte operations -- works identically on PS 5.1 and PS 7+. If derived id doesn't match the policy-registered EXT_ID, the local CRX is deleted before any `git push origin gh-pages` runs. End result: wrong-key protection survives on every PS version, and `-Repack` / `-PackOnly` now produce + publish a CRX on PS 5.1 as well as PS 7+.

Verified on mgmt1: clean PackOnly run produced + pushed extension v1.6.22 CRX with `derived id eheocihmlppcophaeakmdenhgcookkab matches policy id` confirmation. The pre-pack PEM check still runs and succeeds when invoked from a PS 7+ console, providing an earlier abort if the wrong key is detected.

(Pattern note for future scripts: any PEM-key-validation guard should validate the produced output bytes, not the input PEM. PEM parsing in pure .NET Framework 4.x / PS 5.1 is painful -- whereas reading bytes from a produced artifact and parsing protobuf / DER / etc with integer math works on every PS version.)

---

## v2.4.103 -- Update-PimActivator-Extension.ps1 scrubs stale Secure Preferences UNCONDITIONALLY (v2.4.100 only scrubbed when binary present)

v2.4.100 added Secure Preferences scrub to the flush step but **gated it on binary deletion** -- `if ($deletedThisProfile)`. The actual trap is the opposite: when Chrome self-removes a corrupted extension folder but keeps the `extensions.settings.<id>` registration entry with `disable_reasons = 1024 (DISABLE_CORRUPTED)`, the profile reports "no Extensions\<id> folder yet" -- looks like nothing to do, but it's exactly the profile blocked from forcelist install. On a 36-Chrome-profile laptop, v2.4.100 ran clean ("removed cache from 0, registration entries scrubbed: 0") but the laptop stayed broken across all 36 profiles because the stale registrations were never touched.

`Fix-PimActivatorStuck.ps1` always scrubbed unconditionally and pulled the laptop out of the trap in one run (17 stale entries across 4 profiles -- the ones that had been broken). v2.4.103 brings the Update script's flush in line: the Secure Preferences + Preferences scrub now runs on every profile every time, with or without a cached binary present. Result reported in the same "registration entries scrubbed: N" line as before, but now N reflects all stale entries found, not just the ones in cache-deleted profiles.

---

## v2.4.102 -- Deploy-PimActivatorIntune.ps1 pre-flight scan for conflicting ExtensionInstallForcelist policies

**Reason.** A 2-laptop customer deploy hit a silent failure that took an hour to root-cause: the tenant already had a Settings Catalog profile (`Browser Extensions Silently Installed (Google Chrome + Edge)`) pushing Google Docs Offline + Dashlane to the same HKLM forcelist key our ADMX-backed `[PimActivator] client settings` profile writes to. Intune Management Extension does NOT merge ExtensionInstallForcelist writes across mechanisms -- Settings Catalog wins, ADMX-backed loses, and our PIM Activator entry got overwritten on every sync cycle. Intune reported "green" on both policies (because each one successfully wrote ITS values), but the laptops ended up with PIM Activator missing from HKLM and `chrome://policy` showing a stale or absent forcelist entry. Recovery required adding our extension id to the customer's existing Settings Catalog policy manually.

**Fix.** `Deploy-PimActivatorIntune.ps1` now runs a pre-flight Graph scan BEFORE creating / updating its ADMX profile. The scan walks:

- `deviceManagement/configurationPolicies` (Settings Catalog)
- `deviceManagement/groupPolicyConfigurations` (Administrative Templates / ADMX-backed)

and reports any policy (other than our own `$DisplayName`) that already manages Chrome / Edge `ExtensionInstallForcelist`. Per matching policy it prints type (SettingsCatalog vs AdminTemplate), display name, and current forcelist entries. If a conflict is found:

- By default the script **aborts** with the exact `extension_id;update_url` row the operator should add to the existing Intune policy instead -- preserving the customer's existing forcelist setup and avoiding the IME slot-cycling problem.
- Pass `-Force` to push the ADMX profile anyway -- useful when the operator has verified the existing policy is unassigned, scoped to a non-conflicting group, or otherwise safe.

The other settings the ADMX profile carries (`ExtensionInstallSources`, `ExtensionSettings`, `TenantCatalog`) don't contest any Settings Catalog policy, so even when the operator splits the deploy (forcelist via existing Settings Catalog + everything else via this ADMX profile) the architecture works cleanly.

---

## v2.4.101 + extension v1.6.20 -- popup CSS revert (v1.6.19's flex-column layout broke on Edge)

v1.6.19 switched `popup.html` from natural-flow + `max-height:800px` to fixed `height:800px; display:flex; flex-direction:column;` so the role list could grow / shrink to fill the popup. On Edge that combination rendered the popup with NO tab strip (it's hidden until sign-in, but the flex layout collapsed surrounding wrapping too) and BOTH tabpanels visible at once -- top half showing My Roles' sign-in prompt, bottom half showing My Access' bulk controls -- with no Justification / Duration / Activate row or credit footer anywhere. Reproduced on a maintainer Edge install; same broken render on Chrome wherever the extension actually loads.

Reverted to the pre-v1.6.19 natural-flow layout (`max-height` on body, fixed `max-height:260px` on the lists, body itself scrolls if total content exceeds cap) at slightly smaller dimensions per maintainer ask: width 680px (was 720), body cap 700px (was 800), list cap 260px (was 300). Smaller popup, simpler CSS, no Edge incompatibility.

The flex-column experiment is documented in the file header so it doesn't get re-tried -- the simple `max-height` + body-scroll pattern is the right shape for Chromium extension popups.

---

## v2.4.100 -- Update-PimActivator-Extension.ps1 flush now scrubs stale Secure Preferences registration alongside the cached CRX (prevents DISABLE_CORRUPTED trap)

**Critical follow-up to v2.4.98's flush hardening.** The v2.4.98 flush step deleted the cached extension binary on every profile but left the `extensions.settings.<id>` registration intact in `Preferences` + `Secure Preferences`. On the next browser launch, Chromium saw a registration claiming "installed" while the files on disk were gone -- the content-verification subsystem then marked the entry with `disable_reasons` bit 1024 (`DISABLE_CORRUPTED`) and refused to retry the forcelist install. End result: the flush ran "successfully" on N profiles but a subset (typically the ones browsing actively at the moment Chrome was killed) wound up with the extension permanently unable to reinstall until the operator surgically scrubbed those Secure Preferences entries.

Reproduced on a maintainer laptop with 36 Chrome profiles: 4 profiles (`Default`, `Profile 1`, `Profile 45`, `Profile 56`) were left in the DISABLE_CORRUPTED-trap state after a v2.4.98 flush run. The extension showed missing in those profiles indefinitely; the other 32 profiles installed v1.6.19 normally on next launch.

**Fix.** The flush loop in `Update-PimActivator-Extension.ps1` now does both halves of the cleanup in lockstep, profile-by-profile:

1. Delete the cached binary at `<UserData>\<profile>\Extensions\<EXT_ID>` (unchanged).
2. **NEW**: surgically remove the `"<EXT_ID>": {...}` entry from `<UserData>\<profile>\Preferences` AND `<UserData>\<profile>\Secure Preferences` using the same pure-text brace-counting JSON-property removal pattern as `Fix-PimActivatorStuck.ps1` / `Reset-CorruptedExtensions.ps1`. No PS 5.1 `ConvertTo-Json` round-trip (which is what bricked profiles in the 2026-06-09 incident; see v2.4.97 release notes). A timestamped `.bak.<ts>` is written next to each modified file before any rewrite.

Final summary line now reports both numbers: `cached extension folders deleted: N, registration entries scrubbed: M`. The two should generally track 1:1 (one delete typically scrubs 2 JSON entries -- one in `Preferences` and one in `Secure Preferences`).

**`Reset-CorruptedExtensions.ps1` (shipped in v2.4.98) remains useful as a one-off recovery script for laptops that already hit the v2.4.98 trap before this release lands** -- it scans every Chrome + Edge profile for entries with `disable_reasons` matching a configurable bitmask (default 1024 = `DISABLE_CORRUPTED`) and removes them. Pair with `-DryRun` to detect first. The v2.4.100 Update-PimActivator-Extension.ps1 fix is the prevention story; Reset-CorruptedExtensions.ps1 is the cure for already-affected devices.

---

## v2.4.99 -- Deploy-PimActivatorIntune.ps1 catalog auto-discover (HOTFIX over v2.4.98)

**Hotfix.** `Deploy-PimActivatorIntune.ps1` in v2.4.98 made `-CatalogJsonPath` mandatory, which broke customer deploys at sites where the operator hadn't hand-crafted a JSON catalog yet (script just prompted at the param input and didn't proceed). This release demotes the parameter to optional and adds two ways to ship a catalog without supplying a file:

- **Default: auto-discover from Entra.** Zero-arg invocation now queries `/organization` for tenant id + display name AND `/applications?$filter=startswith(displayName,'PIM Activator')` for the per-tenant app registration (the SPN that `Deploy-PimActivatorBackend.ps1` creates earlier in the deploy sequence). Catalog is built in-memory from those facts and pushed through the ADMX template into `chrome.storage.managed.tenantCatalog`. `startswith` (not `eq`) so renamed variants like `'[2linkIT] PIM Activator'` or `'PIM Activator (prod)'` still match -- same lookup the popup's onboarding wizard uses.
- **Manual override with `-ClientId <guid>`.** Skips the `/applications` round-trip when the operator already knows the app's appId from their backend deploy. Tenant id + name still auto-resolved from `/organization`.
- **`-CatalogJsonPath`** still honored, takes precedence over both flags.

**Required Graph scopes** widened to include `Application.Read.All` and `Organization.Read.All` for the auto-discover path. Connect-MgGraph adds them transparently to the existing session; operators don't need to do anything extra.

---

## v2.4.98 + extension v1.6.19 -- unified Intune deploy + critical fix for `ExtensionSettings` schema bug that froze the fleet + popup layout no longer needs outer scroll

**Extension v1.6.19 layout fix (popup).** `popup.html` switched from a hardcoded `max-height:300px` on the role list + `max-height:800px` on the body (which together overflowed Chromium's 800px popup cap and forced an OUTER scrollbar over the credit footer + Activate button) to a flex-column layout where the role list grows / shrinks to fill whatever vertical space is left after the fixed UI. End result: the popup fits Chromium's 800px cap exactly, the role list is the ONLY scrollable region, and the Justification / Duration / Activate button + the two-row credit footer stay anchored at the bottom always-visible. Same fix applies to the My Access tab.

**Critical fix.** Fleet across multiple customer tenants was stuck at whichever extension version each device last consented to (some on v1.1.1, others on v1.6.14, etc.), with no path forward via the forcelist alone. Two compounding bugs:

1. `Deploy-PimActivatorClient.ps1` wrote the `ExtensionSettings` registry policy in the wrong shape. On Windows, Chromium expects: registry value NAME = the extension id, value DATA = bare per-extension settings dict. The script was writing value NAME = `*` + value DATA = `{"<id>":{...}}` -- producing the shape `{"*":{"<id>":{...}}}` that Chromium's schema validator rejects with `Error at ExtensionSettings.*: Schema validation error: Unknown property: <id>`. Silently dropped policy, no permission-expansion bypass.
2. Without that bypass, every device that auto-updated past extension v1.5.11 hit Chrome's permission-expansion gate. v1.5.11 added `https://*/*` to `host_permissions` for the `/.well-known/pim-activator.json` discover feature; Chrome treats that as a broader-permission upgrade and silently disables the install until the user clicks "Enable" in `chrome://extensions`. With managed Chrome's `DeveloperToolsAvailability=2` baseline the Enable button is hidden -- so devices stayed pinned to the last consented version forever.

Both fixed:

- `Deploy-PimActivatorClient.ps1` writes `ExtensionSettings` with the correct shape now.
- `Deploy-PimActivatorIntune.ps1` pushes `ExtensionSettings` as part of the unified profile (the Intune ADMX path was never affected by the registry shape bug -- it just didn't include `ExtensionSettings` at all until this release).

**Consolidated Intune deployment to a single script.** `Deploy-PimActivatorIntune.ps1` is now the only Intune script the operator runs. It auto-uploads the custom ADMX if missing, then creates / updates the `[PimActivator] client settings` profile carrying all four policies per browser:

1. `ExtensionInstallForcelist` -- force-install from the gh-pages CRX
2. `ExtensionInstallSources` -- whitelist gh-pages as a CRX install source
3. `ExtensionSettings` -- pre-grants `<all_urls>` runtime hosts so the permission-expansion gate never fires
4. `TenantCatalog` -- pushes the tenant catalog JSON for `chrome.storage.managed`

The older scripts (`Setup-PimActivatorIntune.ps1`, `Push-PimActivatorADMXToIntune.ps1`, `Push-PimActivatorTenantCatalogIntune.ps1`, `Push-PimActivatorTenantCatalogProfile.ps1`) are deleted. The ADMX upload step is inlined and idempotent -- it skips silently when the ADMX is already ingested.

**`Deploy-PimActivatorClient.ps1` dropped `ExtensionInstallAllowlist` from the default write set.** On some Chromium versions an Allowlist with a single id is interpreted as "deny every other extension" even without a `*` blocklist in play -- so operators on those builds couldn't install any other extension after running the script. Forcelist already overrides the blocklist for the listed id, so the Allowlist write was always defensive belt-and-braces, never load-bearing. Now opt-in only behind `-WriteAllowlist`.

**`Deploy-PimActivatorClient.ps1` now pushes the tenant catalog.** Earlier client-deploy ran stopped at the install policies and required manual catalog import from the popup. The script now writes the catalog JSON under `…\3rdparty\extensions\<id>\policy\tenantCatalog`, the same path the ADMX template eventually writes to. Default catalog is the sibling `discovered-tenant-catalog.json`; pass `-CatalogJsonPath` to override or `-SkipTenantCatalog` to skip.

**New `Fix-PimActivatorStuck.ps1` -- one-time per-device recovery for laptops already stuck.** Run on any device whose Chrome shows the old version OR an `ERR_FILE_NOT_FOUND` icon. The script surgically removes the stale `extensions.settings.<id>` registration (plus its HMAC and any `pinned_extensions` reference) from `<UserData>\Default\Preferences` and `<UserData>\Default\Secure Preferences` across every profile folder, then exits. Pure string-surgery with brace counting -- no PS 5.1 `ConvertTo-Json` round-trip, so the 2026-06-09 profile-corruption footgun cannot fire. Reopen the browser and the forcelist installer runs fresh on a clean state.

**`Update-PimActivator-Extension.ps1` hardened against a fresh batch of failure modes discovered while debugging the fleet freeze:**

- Pre-flight compliance check at the top of every run. Reports whether the `ExtensionInstallForcelist` registry value is present, whether the gh-pages updates.xml is reachable, what version it advertises, and -- when missing -- the exact `New-ItemProperty` one-liner to write the policy. Failures are warnings, not hard aborts.
- Pre-pack signing-key guard. Computes the extension id the local `signing-key.pem` will produce; if it doesn't match the registered policy id, the pack step throws BEFORE running `msedge --pack-extension`. The fleet got bricked once already by a CRX packed with a regenerated key from the wrong machine; this guard makes that incident unreproducible.
- Post-pack / pre-flush gh-pages CRX validation. Downloads the live CRX, derives its canonical extension id via proper protobuf parsing of the v3 header (`SHA256(public_key)` from the first `AsymmetricKeyProof`, first 16 bytes, remapped 0..15 -> 'a'..'p'). If the derived id doesn't match the policy id, the flush step refuses to proceed -- prevents a future wrong-key CRX from bricking installed instances by deleting their cached binary with no working replacement to install.
- Defense-in-depth `Local State` backup. Every run writes a timestamped `Local State.bak.<ts>` next to the live file BEFORE touching any extension folder. Two profile-loss incidents in two days showed even the now-opt-in destructive paths weren't the whole story; surrounding Chromium subsystems can also reset `Local State` during a force-killed-mid-write race. The auto-backup is the undo file -- 30-second recovery by copying the `.bak` over the live file.
- Graceful close + force-kill only stragglers. Replaces the previous bare `Stop-Process -Force`. Browser processes get a `CloseMainWindow()` first, then we wait up to 10 seconds for the original PID set to exit, then force-kill anything still running. Gives Chrome time to flush its in-flight `Local State` write -- which was the most plausible root cause of the 2026-06-10 profile-registry reset.
- Multi-profile awareness in the flush + verification phases. Previous versions hardcoded `Default`. A maintainer's laptop had 59 Chrome profiles, only some with the extension installed; flushing only `Default` produced a misleading "no cached extension" while every `Profile NN\` folder still had a stuck old install. The script enumerates every `Default` and `Profile NN\` folder under each browser's User Data root and operates on all of them. Post-relaunch verification reports per-profile installed version vs the gh-pages-advertised version, so per-profile drift is visible.
- ASCII labels replace emoji output. Windows Server consoles render Chromium emoji glyphs as garbled multi-byte sequences. `[OK]` / `[FAIL]` / `[WARN]` / `[REUSE]` / `[SCOPE]` / `[FORCE]` / `[DRY-RUN]` / `[TRIGGER]` / `[DEVICES]` / `[START]` / `[SUMMARY]` are used everywhere. Same information, readable on every Windows host.

---

## v2.4.97 -- Update-PimActivator-Extension.ps1 SAFETY FIX: stop destroying browser profiles, trigger updates via --extensions-update-frequency=30

**Critical fix.** Earlier versions of `Update-PimActivator-Extension.ps1` ran two destructive actions on every "flush" invocation:

1. **JSON-rewrite of `<UserData>\Preferences` + `<UserData>\Secure Preferences`** -- PowerShell 5.1's `ConvertFrom-Json | ConvertTo-Json -Depth 100 -Compress` round-trip is unreliable for the Chromium Preferences shape (Unicode, deep nesting, integer/number type drift). The corruption produced a file Edge/Chrome could not parse on next launch, and Chromium **silently reset the entire profile to defaults** -- losing bookmarks, history, saved tabs, signed-in accounts.
2. **Wholesale delete of `<UserData>\Service Worker`** -- evicted SW registrations for ALL extensions and sites in that profile, not just PIM Activator.

At least one device lost its entire Edge profile this way. Both destructive paths are now **opt-in behind explicit switches** (`-DangerouslyPatchPreferences`, `-DangerouslyWipeServiceWorker`) and the safe default path does not touch profile data at all.

**Core purpose of the script restored to a safe, fast path:**

The script's job is to make Edge / Chrome pick up the latest CRX from GitHub Pages **now** instead of waiting Chromium's default ~5-hour update poll. The new safe flow:

1. Kill the browser process.
2. Delete the cached CRX folder at `<UserData>\Extensions\<EXT_ID>` (no profile data here -- just the unpacked extension binary the forcelist policy will re-download).
3. Delete secondary extension caches (`Local Extension Settings\<id>`, `Sync Extension Settings\<id>`, `Extension State\<id>`, `Extension Scripts\<id>`, `Extension Rules\<id>`) -- all scoped to PIM Activator's extension ID; no shared state touched.
4. Relaunch browser with `--extensions-update-frequency=30` so the `ExtensionInstallForcelist` policy polls the update_url within ~30 seconds (default is 5 hours). Within ~30s the new CRX lands.

**No more profile loss is possible from a casual re-run.** The destructive switches still exist for the rare dev-iteration case where you specifically need to scrub `extensions.settings.<id>` HMACs from a corrupted profile, but they are now opt-in and create a `.bak.<timestamp>` sidecar before any rewrite.

Header `.WARNING (2026-06-09 incident)` block in the script documents the failure mode so future maintainers don't reintroduce it.

---

## v2.4.94 -- Setup-PimActivatorIntune.ps1: one-click ADMX-backed Intune profile (forcelist + sources + tenant catalog in a single Configuration Profile)

Single-script unified Intune setup. After the ADMX is ingested (`Push-PimActivatorADMXToIntune.ps1`, one-time per tenant), this script creates ONE `groupPolicyConfigurations` profile carrying 6 definitionValues:

| Browser | Definition | Source ADMX | Value |
|---|---|---|---|
| Edge | "Control which extensions are installed silently" (`ExtensionInstallForcelist`) | Microsoft Edge ADMX | `<extId>;<updateUrl>` |
| Edge | "Configure extension and user script install sources" (`ExtensionInstallSources`) | Microsoft Edge ADMX | `https://knudsenmorten.github.io/*` |
| Edge | "Tenant catalog -- Microsoft Edge" | Our `PIM4EntraPS.PimActivator.admx` | tenantCatalog JSON (one-line) |
| Chrome | "Configure the list of force-installed apps and extensions" | Google Chrome ADMX | `<extId>;<updateUrl>` |
| Chrome | "Configure extension, app, and user script install sources" | Google Chrome ADMX | `https://knudsenmorten.github.io/*` |
| Chrome | "Tenant catalog -- Google Chrome" | Our `PIM4EntraPS.PimActivator.admx` | tenantCatalog JSON (one-line) |

**One profile -- one assignment.** Customer endpoints sync, install the extension, allow the gh-pages source, and the popup auto-detects the Intune-pushed catalog via `chrome.storage.managed.tenantCatalog`. Zero further touch.

Idempotent: lookup by display name, wipe + re-write definition values in place when re-running.

**Per-tenant ID resolution at runtime:** the Edge + Chrome ADMX policy IDs are auto-assigned per-tenant when Intune ingests them. Script resolves by `categoryPath` + machine-class `displayName` lookup (`/groupPolicyDefinitions?$filter=categoryPath eq '\Microsoft Edge\Extensions'`) -- no hardcoded GUIDs that drift between tenants.

**Helper functions:**
- `Find-PolicyDef` -- displayName + categoryPath lookup, machine-class only
- `Get-Presentations` -- separate call for each definition's `/presentations` collection (Graph `$expand` depth-limited)
- `New-DefValue` -- emits the right body shape for either Text (single string) OR List (string[] wrapped as `{name, value}` pairs, slot-numbered)

Tested end-to-end against 2linkIT tenant: 6 definition values written, profile `33da37a0-1d7e-4e4a-a505-3990cad5d8e9` created. Only remaining manual step: assign to a device group in the portal.

**Customer flow simplified to 3 commands:**
```powershell
# 1. one-time per tenant
Push-PimActivatorADMXToIntune.ps1

# 2. one-time discovery (auto-finds your PIM Activator app reg)
Test-PushTenantCatalog.ps1   # writes discovered-tenant-catalog.json

# 3. one-time setup of the unified profile
Setup-PimActivatorIntune.ps1 -CatalogJsonPath .\discovered-tenant-catalog.json -AssignToGroupId <group-id>
```

After that: customer endpoints get the policy on next Intune sync, end users see the populated tenant switcher in the popup, no further intervention needed.

---

## v2.4.93 -- PIM Activator extension v1.6.5 + Push-PimActivatorTenantCatalogIntune.ps1 rewritten as PowerShell remediation (was failing 0x87d1fde8 via Registry CSP)

**Customer report (v2.4.90):** the Custom Configuration Profile created via Registry CSP failed on every Intune-managed device with error `0x87d1fde8` (signed `-2016281112`). Root cause: Microsoft restricts Registry CSP from writing under `SOFTWARE\Policies\Microsoft\Edge\*` because Edge owns that namespace via its ADMX. Same restriction applies to Google\Chrome paths.

**Industry-standard ways to push per-extension chrome.storage.managed data on Windows:**
| Approach | Works? | Notes |
|---|---|---|
| Registry CSP / Custom OMA-URI Configuration Profile | NO -- `0x87d1fde8` on Edge/Chrome 3rdparty paths | Microsoft blocks |
| **PowerShell remediation script via Intune Devices > Scripts** | **YES** (this release) | Runs as SYSTEM, no CSP restrictions |
| Custom ADMX template ingested into Intune | YES | Proper "by policy" UX (Settings Catalog entry); needs ADMX/ADML pair maintained per release; this is what Rhindon Cyber's extension docs prescribe |

**`Push-PimActivatorTenantCatalogIntune.ps1` rewritten** to POST a `deviceManagementScripts` policy instead of a `deviceConfigurations` Custom profile. The script body runs as SYSTEM on every targeted device, does:

```powershell
foreach ($p in @('HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<id>\policy',
                 'HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<id>\policy')) {
    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
    New-ItemProperty -Path $p -Name 'tenantCatalog' -Value $catalogJsonString -PropertyType String -Force | Out-Null
}
```

Idempotent: lookup by display name, PATCH if found, POST if new.

**New `-RemoveLegacyOmaUriProfile` switch** -- when migrating from v2.4.90's failed Registry-CSP profile, also deletes the old `[PimActivator] Tenant catalog (chrome.storage.managed)` Custom Configuration Profile so the failing OMA-URI doesn't keep producing `0x87d1fde8` errors in the Intune device-status panel.

**Migration command for customers who already ran v2.4.90:**
```powershell
Push-PimActivatorTenantCatalogIntune.ps1 -CatalogJsonPath .\my-tenants.json -RemoveLegacyOmaUriProfile
```

**v1.6.5 extension changes** (popup-only, no functional regression):
- Catalog panel now displays a **source-detection status line**: `Detected N entries from Intune managed config (chrome.storage.managed.tenantCatalog)` (green check) when Intune push landed, OR `No Intune managed config detected ... and no local catalog imported yet` (gray) for first-time empty state, OR `Intune managed config read FAILED: <reason>` (red) when the read errored. Critical for "did my Intune policy land?" trouble-shooting on managed devices -- no need to dig into chrome.storage.managed via DevTools.
- Catalog panel position: moved BELOW the Welcome heading (was above). Order is now Welcome -> Catalog -> Manual entry.

---

## v2.4.92 -- PIM Activator extension v1.6.4: strip the auto-discover panel + retire well-known URI flow + background.js gutted

User report: the v1.6.3 onboarding wizard still showed the leftover "Auto-discover (recommended)" panel from v1.5.11 referencing `https://<your-domain>/.well-known/pim-activator.json` and "Discovery did not complete" errors. That flow was retired by the catalog model -- the panel was dead UI.

**Removed:**
- The entire `#ob-auto` blue panel + `ob-auto-email` input + `ob-auto-start` button + `ob-auto-device` status div from `popup.html`.
- `processDiscoveryResult`, `startPolling`, `renderDeviceCode`, the `_lastDiscovery` stash, the on-load discovery-resume IIFE, and the `startBtn.onclick` -> `sendMessage cmd:start-discovery` handler from `popup.js` (~120 lines).
- `background.js` runDiscovery, well-known fetch, OIDC tenant resolution, all of it. The file now contains a single comment block stating the SW has nothing to do -- the manifest still references it because Chromium MV3 requires a service_worker entry, but no listeners register.

**Layout reordered as catalog -> Welcome -> manual entry:**
- Top: green "Import tenant catalog" panel (injected by popup.js when no catalog yet, or "Pick a tenant" picker when catalog has entries)
- Middle: "Welcome to PIM Activator" heading + new subtitle "Either import a tenant catalog above (MSP / multi-tenant), OR fill in a single tenant manually below and click Save and continue."
- Bottom: "Single tenant -- manual entry" header + 4-input grid (tenantId / clientId / justification / duration)

`onboarding-save` handler simplified -- no more `_lastDiscovery` dependency, regex fields default empty for the single-tenant path (catalog entries carry their own prefix/regex per-entry).

Net: the wizard now has exactly two paths and no dead code.

---

## v2.4.91 -- PIM Activator extension v1.6.3: retire the global `KNOWN_BAD_LEGACY_CLIENTIDS` ban

v1.5.8 added a global sentinel that filtered out clientId `e96afaa6-1c00-4320-9a4c-334558138e09` from chrome.storage on every popup load, plus from catalog imports and the onboarding-save handler. The intent was right (stale v1.4.x onboarding had saved that GUID into customer chrome.storage where it didn't belong, producing AADSTS700016). The implementation was wrong.

That GUID is the **legitimate PIM Activator app reg in the dev tenant that owns it** (2linkIT). In a v1.6 catalog where each entry binds `tenantId + clientId` together, the same GUID IS valid in the tenant that hosts it -- a global ban filters legitimate entries out everywhere.

**Emptied the `KNOWN_BAD_LEGACY_CLIENTIDS` array** (kept as `[]` for back-compat with all the existing call sites, which become no-ops). The catalog model itself prevents the original v1.4.x bug: you can't accidentally onboard "customer tenant X with the dev's clientId" because each entry is one tenant+client pair, validated against each other implicitly when the runtime sign-in fires.

If a new global-ban scenario emerges later, add a GUID to the array and all three call sites resume behaving as before.

---

## v2.4.90 -- Push-PimActivatorTenantCatalogIntune.ps1: native Intune Custom Configuration Profile (OMA-URI + Registry CSP) for tenant catalog push

There is **no built-in Settings Catalog template** for arbitrary self-hosted Edge extensions' `chrome.storage.managed` data -- Microsoft only exposes 3rd-party extension policies for Edge Add-ons Store-published extensions. For PIM Activator (self-hosted CRX) the standard ways to push the registry value `chrome.storage.managed.tenantCatalog` reads from are:

| Path | "Standard" | Native Intune | Continuously enforced |
|---|---|---|---|
| Custom Configuration Profile + OMA-URI + Registry CSP (this script) | Yes | Yes | Yes |
| PowerShell remediation script | Less | Sort of | No (runs on schedule) |
| Custom ADMX ingestion | Most | Yes | Yes (heavy to author) |

Picked the OMA-URI / Registry CSP path -- creates a single `windows10CustomConfiguration` with one OMA-URI line per browser (Edge + Chrome by default), value = JSON-encoded tenant catalog. Intune writes the registry value on every device sync and re-enforces if anything overwrites it.

**Idempotent:** lookup by display name, PATCH if exists, POST if new. Re-running with an updated catalog file replaces the value in place.

**Use:**
```powershell
Push-PimActivatorTenantCatalogIntune.ps1 -CatalogJsonPath .\my-tenants.json
```
A `sample-tenant-catalog.json` ships alongside as a fill-in template.

**Schema** (each array element):
```json
{
  "name":        "Contoso",
  "tenantId":    "<GUID>",
  "clientId":    "<GUID>",
  "prefix":      "PIM-",
  "entraPrefix": ["PIM-Entra","PIM-AAD"],
  "azurePrefix": ["PIM-Azure","PIM-AzRes"]
}
```

The extension reads `chrome.storage.managed.tenantCatalog` on every popup load, merges with `chrome.storage.local.tenantCatalog` (manually-imported entries), and renders the header tenant-switcher dropdown.

**Verify on a target device after Intune sync:**
```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\eheocihmlppcophaeakmdenhgcookkab\policy' -Name tenantCatalog
```

---

## v2.4.89 -- PIM Activator extension v1.6.2: admin-friendly prefix shortcuts (`prefix`/`entraPrefix`/`azurePrefix`) in catalog entries

v1.6.0 required raw regex (`groupNameFilter`, `entraGroupRegex`, `azureGroupRegex`) in catalog entries -- error-prone for admins who think in literal prefixes.

**Added three optional literal-prefix fields** (each accepts a string OR string[]):

| Catalog field | Internal regex it builds | Wins when |
|---|---|---|
| `prefix: "PIM-"` | `^PIM-` (anchored start) | No explicit `groupNameFilter` |
| `entraPrefix: ["PIM-Entra","PIM-AAD"]` | `(PIM-Entra\|PIM-AAD)` | No explicit `entraGroupRegex` |
| `azurePrefix: ["PIM-Azure","PIM-AzRes"]` | `(PIM-Azure\|PIM-AzRes)` | No explicit `azureGroupRegex` |

Literals are regex-escaped (`.*+?^${}()|[\]\\`) before wrapping. Explicit `*Regex` fields still win when both are present (advanced override).

Wizard placeholder + import-help text updated to show the new shorter shape. Backward compatible -- v1.6.0 catalogs with raw `groupNameFilter` etc. still work.

Sample example string in the wizard placeholder switched from a real customer name to `Contoso` (per "no customer names in docs / code samples" rule).

---

## v2.4.88 -- PIM Activator extension v1.6.0: tenant catalog + header switcher for MSP / multi-tenant admins

After exhausting every auto-discovery path (OAuth bootstrap = 700016 in customer tenants / Microsoft Graph CLI bootstrap = 50011 redirect URI / device code = CA-blocked / multi-tenant publisher app = ruled out / well-known URI = publicly enumerable / native messaging WAM = wrong context for an MSP connecting to 100 tenants from one machine), the right architecture for one-admin-multiple-tenants is **catalog + context switcher**, not discovery.

**New storage model:**

| Key | Source | Purpose |
|---|---|---|
| `chrome.storage.managed.tenantCatalog` | Intune Settings Catalog "Configure managed extensions" (JSON-encoded string) | Admin pushes the same catalog to all MSP machines |
| `chrome.storage.local.tenantCatalog` | Manually imported via wizard | Per-Edge-profile additions / overrides |
| `chrome.storage.local.activeTenantId` | Picked by user via header switcher | Which catalog entry is "now" |
| `chrome.storage.local.tenantTokens` | Written after every sign-in, keyed by `tenantId` | Per-tenant refresh + access token cache; switching back is sub-second |

**Catalog entry schema:**

```json
{
  "name":                 "Contoso",
  "tenantId":             "00000000-0000-0000-0000-000000000000",
  "clientId":             "00000000-0000-0000-0000-000000000000",
  "defaultJustification": "Change in infrastructure",
  "defaultDurationHours": 8,
  "groupNameFilter":      "^PIM-",
  "entraGroupRegex":      "Entra",
  "azureGroupRegex":      "(AzRes|Azure)"
}
```

**Onboarding wizard (renderOnboarding) now branches three ways:**
1. **Catalog has entries + no active selection**: shows a green "Pick a tenant" picker (dropdown of all catalog entries with their tenantId), with "Use this tenant" and "Clear local catalog" buttons.
2. **Catalog empty**: shows "Import tenant catalog (MSP / multi-tenant)" with a textarea for pasting the JSON array + an Intune-tip box pointing at the same Settings Catalog key. Auto-discover legacy wizard remains below as a fallback for single-tenant deployments.
3. **Catalog populated + active selection** (boot path): main UI loads with the active tenant's config.

**Header tenant switcher** appears when catalog has >=2 entries. Picking a new entry:
- Snapshots the current tenant's tokens into `tenantTokens[oldTid]`
- Sets `activeTenantId = newTid`
- Clears the in-flight token state
- Reloads the popup -> loadConfig restores the new tenant's cached tokens (or triggers sign-in if none)

**persistTokens** now ALSO writes into `tenantTokens[activeTenantId]` after every successful sign-in / refresh so switching back is instant.

**Reset handler** wipes catalog + per-tenant tokens + legacy keys on confirm.

**Footer** shows `{tenantName} Tenant: {tenantId} (reset)` -- the friendly customer name (from catalog) is prefixed if available, falls back to bare tenantId for legacy single-tenant installs.

**For Intune-managed MSP fleets:** push the catalog once via Intune Settings Catalog -> Microsoft Edge -> Extensions -> Configure managed extensions -> key `tenantCatalog`, value = JSON-encoded string of the array. All your machines pick it up on next Intune sync (~8h, force from device for faster). Per-tenant active selection still happens locally via the header switcher (per-session).

**Single-tenant deployments:** unchanged. If you don't import a catalog, the legacy wizard fields work as before. Existing `userTenantId` / `userClientId` etc. in chrome.storage.local are honored.

**For your dev test (mortenknudsen.net + Contoso):**

1. Edge auto-fetches v1.6.0 from gh-pages within ~5 min after restart (or run `Update-PimActivator-Extension.ps1` to force).
2. Click PIM Activator icon -> onboarding wizard appears.
3. Paste a 2-entry catalog into the green "Import tenant catalog" textarea:
   ```json
   [
     {"name":"mortenknudsen.net","tenantId":"<your-dev-tenant-GUID>","clientId":"<your-PIM-Activator-appId>","groupNameFilter":"^PIM-"},
     {"name":"Contoso","tenantId":"<Contoso-tenant-GUID>","clientId":"<Contoso-PIM-Activator-appId>","groupNameFilter":"^PIM-"}
   ]
   ```
4. Click "Import tenant catalog" -> picker appears -> pick a tenant -> "Use this tenant" -> runtime sign-in fires against THAT tenant's PIM Activator app reg (which has chromiumapp.org registered per Deploy-PimActivatorBackend.ps1).
5. Switch tenants anytime via the header dropdown -- tokens cached per tenant, sub-second switch when both already signed in.

**Removed:** well-known URI fetch path in popup.js / background.js (kept the background.js file as the SW host, but the worker is now thin -- no discovery flow needed).

**`Deploy-PimActivatorIntune.ps1` unchanged.** Re-running it just updates the existing forcelist profile (lookup by DisplayName, PATCH if exists). For Intune-push of the tenant catalog itself, use the standard Intune Settings Catalog flow described above; full automation of THAT push deferred to a future release.

---

## v2.4.87 -- PIM Activator extension v1.5.11: auto-discover via well-known URI on corporate domain (replaces device code, which CA-blocks in most tenants)

Device-code flow shipped in v1.5.10 was blocked by Conditional Access in most production tenants (CA's AiTM-phishing protection covers device code). All OAuth-based bootstrap paths now ruled out (700016 with single-tenant clientId / 50011 with Microsoft Graph CLI / CA-blocked device code / multi-tenant publisher app explicitly off the table / manual paste explicitly off the table).

Replaced the bootstrap entirely with a **well-known URI lookup on the corporate web domain**:

1. User enters work email in the wizard.
2. Service worker GETs `https://<email-domain>/.well-known/pim-activator.json` (with a `www.` fallback).
3. JSON contains `tenantId` + `clientId` + optional per-customer config; popup pre-fills the wizard.
4. User clicks Save -> runtime sign-in fires against the discovered clientId via `launchWebAuthFlow` (the customer's own PIM Activator app reg has `chromiumapp.org` registered per `Deploy-PimActivatorBackend.ps1`).

**JSON schema** (admin publishes once on the corporate domain):

```json
{
  "tenantId":             "<tenant GUID>",
  "clientId":             "<PIM Activator app appId>",
  "defaultJustification": "Change in infrastructure",
  "defaultDurationHours": 8,
  "groupNameFilter":      "^PIM-",
  "entraGroupRegex":      "Entra",
  "azureGroupRegex":      "(AzRes|Azure)"
}
```

The last three fields are per-customer naming-convention regexes that were already supported by the extension (`cfg.groupNameFilter` at `popup.js:2405` + `cfg.entraGroupRegex`/`azureGroupRegex` at `1732-1733`) but never persisted by the wizard before -- now they ride in the JSON and are saved to chrome.storage.local as `userGroupNameFilter` / `userEntraGroupRegex` / `userAzureGroupRegex`. Each customer's `PIM-` (or `Admin-`, or whatever they use) prefix flows through without code changes on our side.

**Why publishing the JSON publicly is safe** (covered the discussion at length, repeating the short form):

- `tenantId` is already public via the unauthenticated OIDC discovery endpoint Microsoft hosts at `login.microsoftonline.com/<domain>/.well-known/openid-configuration` -- you cannot hide it.
- `clientId` is public by OAuth2 spec; it appears in every authorize URL the browser sends. It is NOT a credential.

**Removed in this release:**
- `background.js` device-code grant + token polling.
- `popup.js` device-code panel + copy-button rendering.
- Bootstrap clientId constant (no bootstrap sign-in needed anymore -- discovery is a plain HTTPS fetch).
- popup.js `discoveryDeviceCode` chrome.storage.local key + boot pickup logic.

**Added:**
- `host_permissions: "https://*/*"` in manifest -- needed for the well-known fetch to arbitrary corporate domains. Edge for Business managed installs can pre-approve.
- The 3 regex keys in `loadConfig` / `processDiscoveryResult` / `onboarding-save` / reset handler.

---

## v2.4.86 -- PIM Activator extension v1.5.10: auto-discover via OAuth2 device-code flow (fixes AADSTS50011 redirect-URI mismatch)

v1.5.0 swapped the bootstrap clientId from a single-tenant upstream-dev app (`e96afaa6-...`, fails `AADSTS700016` in every other tenant) to Microsoft Graph Command Line Tools (`14d82eec-...`, exists in every tenant). That fixed 700016, but uncovered the next layer: the chrome-extension OAuth path `chrome.identity.launchWebAuthFlow` requires `https://<extId>.chromiumapp.org/` to be pre-registered as a redirect URI on the app reg -- and Microsoft owns the Graph CLI app, so we can't add URIs to it. Customer sign-in now failed with `AADSTS50011 The redirect URI does not match the redirect URIs configured for the application`.

**Refactored the bootstrap to OAuth2 device-code flow (RFC 8628).** Device code grant does not use a redirect URI at all -- Entra returns a `user_code` + `verification_uri`, the user authorizes in a separate tab, and the service worker polls the token endpoint until a token is issued (or expiry). This works against Microsoft Graph CLI without any tenant-side or app-reg-side setup.

**New flow (background.js):**
1. Resolve tenant GUID via OIDC discovery on the email's domain (unchanged).
2. POST `{tenant}/oauth2/v2.0/devicecode` with `client_id=14d82eec` + discovery scopes -> `{ device_code, user_code, verification_uri, expires_in, interval }`.
3. Write `{ userCode, verificationUri, expiresAt, message }` to `chrome.storage.local.discoveryDeviceCode` so the popup can render the "Open URL, enter code XXXX" panel.
4. Poll `{tenant}/oauth2/v2.0/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code` every `interval` seconds. Handle `authorization_pending` (retry), `slow_down` (bump interval +5s per spec), `expired_token` / `authorization_declined` / `bad_verification_code` (surface as error).
5. On success: query `/servicePrincipals?$search="displayName:PIM Activator"&$count=true` with `ConsistencyLevel: eventual` (unchanged) and return matched apps to the popup for picker rendering.

**New device-code panel (popup.js):**
- Big blue callout with 3 numbered steps: open URL, enter code, sign in.
- The `user_code` is shown in a monospace pill (font-size 14, letter-spacing 1.5) with an inline `copy` button that uses `navigator.clipboard.writeText` and flips the button text to `copied` for 1.5s.
- The verification URI is a real `<a target="_blank">` so a single click opens a new tab.
- "Waiting for sign-in to complete..." status line below.
- Panel re-renders on popup re-open if the device-code flow is still in flight, so a customer who closed the popup mid-auth doesn't lose the code.

Side effects:
- Discovery timeout extended from 600s (10 min) to 900s (15 min) to match Entra's typical `expires_in` for device codes.
- `discoveryDeviceCode` chrome.storage.local key is cleared on success, error, and timeout paths.
- Bootstrap-side `launchWebAuthFlow` callsite + the PKCE helpers removed -- device code is the sole bootstrap path now.

Net effect: auto-discover now works in any Entra tenant with zero per-customer app-registration setup. UX cost is one extra click (open the verification tab) vs the prior popup-based sign-in; in exchange the architecture stops depending on us owning an app reg in every tenant.

---

## v2.4.85 -- PIM Activator extension v1.5.9: hard-evict stale MV3 service worker on legacy-clientId detect

v1.5.8's chrome.storage purge fired (popup.js code-side guard), but customers continued to see `client_id=e96afaa6` in OAuth URLs. Root cause: **MV3 split-personality cache.** Chrome MV3 keeps two completely separate update tracks:

- **Popup files** (`popup.html` + `popup.js`) re-read from disk on every popup click. They updated to v1.5.8 cleanly.
- **Service worker** (`background.js`) persists in `Service Worker\Database\` LevelDB *until idle for ~5 min* OR browser fully restarted. Customer's SW was still v1.4.x with `BOOTSTRAP_CLIENT_ID = 'e96afaa6'`. The popup-side purge of `userClientId` was fine, but the bootstrap sign-in that runs in the SW still went to the bad clientId.

**Two-layer fix (so this becomes truly self-healing on every customer):**

1. **`popup.js` purge handler now also calls `chrome.runtime.reload()`** -- hard-restarts the entire extension including the MV3 service worker, swapping in the new background.js immediately. Without this, the popup would purge storage but the bootstrap sign-in (which runs in the stale SW) would still use the bad clientId on the very next click.

2. **`Update-PimActivator-Extension.ps1` now nukes `<UserData>\Service Worker\` dir** -- after the existing extension-binary + Local Extension Settings wipe, the script removes the entire profile-wide Service Worker registration cache (`Database\` + `ScriptCache\`). On next Edge launch, every extension + site re-registers its SW from scratch -- including PIM Activator, which picks up the freshly-installed background.js. Brute-force but reliable.

Operationally for stuck customers: `pwsh Update-PimActivator-Extension.ps1` once is now guaranteed to land them on the latest SW. After that, the v1.5.9 popup guard handles every future case automatically.

---

## v2.4.84 -- popup.js comment hygiene around the legacy-clientId sentinel

Pure comment-noise reduction around `KNOWN_BAD_LEGACY_CLIENTIDS`. Previously the explanatory paragraph repeated the literal `e96afaa6-...` GUID three times to walk through the failure mode -- meaning a quick `grep e96af` on the extension folder lit up multiple unrelated lines and made it look like the bad value was still being used. Trimmed the comment to one sentence + one fact ("the literal GUID below is required for the equality check, NOT a live reference") so future greps surface ONLY the single sentinel-array entry that the load + save guards key off.

No behaviour change. Extension version unchanged at v1.5.8.

---

## v2.4.83 -- PIM Activator extension v1.5.8: auto-purge legacy bad `userClientId` from chrome.storage

Customer report: even after wiping `Local Extension Settings\<id>\` via `Update-PimActivator-Extension.ps1`, the AADSTS700016 with `client_id=e96afaa6-1c00-4320-9a4c-334558138e09` would come back. Root cause traced: that GUID is the upstream dev's PIM Activator app reg appId -- in v1.4.x the bootstrap signed into the dev's tenant and discovery returned that app, which got saved as the user's `userClientId` in chrome.storage.local. Any later wipe followed by an Edge profile sync would restore it from cloud, and the runtime would happily use it (resulting in AADSTS700016 against the customer tenant where that app reg does NOT exist).

**Two-layer defense added:**

1. **`loadConfig()` purge guard** -- on every popup load, if `userClientId` matches the known-bad upstream GUID, all auth artifacts (`userTenantId`, `userClientId`, `refreshToken`, `accessToken*`, `armAccessToken*`, `account`) are removed from chrome.storage.local and `loadConfig` returns empty config -- triggering the onboarding wizard to re-run and discover the CUSTOMER tenant's actual PIM Activator SPN.
2. **`onboarding-save` write guard** -- the Save handler refuses to write the known-bad GUID and shows a clear error: "That clientId is the upstream dev's app reg and does NOT exist in your tenant. Click 'Sign in to auto-discover' and pick the SPN whose displayName contains 'PIM Activator' in YOUR tenant."

Both guards key off a single `KNOWN_BAD_LEGACY_CLIENTIDS` array at the top of popup.js so adding more known-bad values in future requires a single-line change.

---

## v2.4.82 -- PIM Activator extension v1.5.7: version badge actually renders (was hidden by onboarding park)

The header version badge has been declared in popup.html for several releases, but never actually rendered for users who weren't onboarded yet. Root cause:

```js
// popup.js lines 41-48
const cfg = await loadConfig()
if (!cfg.tenantId || ... || !cfg.clientId || ...) {
  renderOnboarding(cfg)
  await new Promise(() => {}) // <-- parks forever during onboarding
}
// ... 250 lines later ...
;(() => { /* populate version-badge */ })()  // <-- NEVER REACHED on first-run popups
```

The IIFE that populated `#version-badge` was at the bottom of popup.js -- well past the `await new Promise(() => {})` that intentionally parks execution during the onboarding wizard. First-run popups (no saved tenant/client) therefore showed an empty badge slot forever.

**Fix:** moved the badge-population logic into a dedicated `version-badge.js` loaded synchronously from popup.html BEFORE the popup.js module. The badge now populates during HTML parse, independent of whether popup.js completes its boot. (MV3 CSP forbids inline `<script>` blocks, hence the separate file.)

Also:
- Default badge text `v?` in the HTML so the pill placeholder is visible even if `chrome.runtime.getManifest()` fails for any reason.
- `document.title` now stamps as `PIM Activator v1.5.7` -- visible in the Windows taskbar tooltip + alt-tab title row.
- Badge pill tightened: brighter border (`0.55` alpha), brighter background fill (`0.25` alpha), slightly more padding for readability against the blue header.

---

## v2.4.81 -- PIM Activator extension v1.5.6: nuke last `e96af` trace from code/comments

Purely a cleanup release. The bad upstream clientId `e96afaa6-...-334558138e09` was replaced as an executable constant back in v1.5.0 (-> Microsoft Graph CLI `14d82eec-...`), but the GUID still survived as a literal string inside an explanatory comment in `background.js`. Any `strings(1)` / grep of the packed CRX would surface it and cause "why is this id still in the binary?" confusion during incident review.

Rewrote the comment to use a generic phrasing ("a single-tenant app-reg clientId from any one tenant") instead of the specific historical GUID. The only places `e96af` survives in the entire monorepo now are this RELEASENOTES file and the v2.4.76 entry that documented the original fix.

Republished CRX + updates.xml to gh-pages as v1.5.6.

---

## v2.4.80 -- PIM Activator extension v1.5.5: single-line footer with all attribution + chips, blue MVP

Consolidated three quick iterations (v1.5.3 -> v1.5.4 -> v1.5.5) into the final footer:

> **PIM ACTIVATOR**, part of **PIM4EntraPS** -- Developed by **Morten Knudsen**, **Microsoft MVP** | &#128279; **GitHub** | &#128027; **Report bug**

**Changes vs v1.5.2:**

- **Footer collapsed from 2 rows to 1.** GitHub + Report bug chips moved up onto the same row as the attribution line (`flex-wrap` so it gracefully reflows on narrow popups).
- **Removed:** YouTube chip, `mailto:` email, blog link (`mortenknudsen.net`).
- **"Microsoft MVP" recoloured** from Red (`#cf222e`) -> Blue (`#0969da`, same as the other footer links). Square brackets dropped: `[Microsoft MVP]` -> `, Microsoft MVP`.
- **GitHub link** now points to the repo (`https://github.com/KnudsenMorten/PIM4EntraPS`), not the user profile (`https://github.com/KnudsenMorten`).
- **`manifest.json` `author`** dropped the email -> `"Morten Knudsen (Microsoft MVP)"`.
- **`manifest.json` `homepage_url`** -> `https://github.com/KnudsenMorten/PIM4EntraPS` (was the blog URL); `chrome://extensions` "Visit website" now lands on the repo.

Republished CRX + updates.xml to gh-pages -- customer browsers will fetch v1.5.5 within Chromium's normal auto-update window (~5 min after launch, then every ~5h).

---

## v2.4.79 -- Deploy-PimActivatorClient.ps1: belt-and-braces auto-update policies + gh-pages republish of extension v1.5.2

Two related fixes for the "extension on my server is 2 versions behind" problem:

**1. gh-pages refresh**

The customer-facing extension is fetched from `https://knudsenmorten.github.io/PIM4EntraPS/updates.xml`, which lives on the `gh-pages` branch -- a separate publish step from the monorepo `main` commits. v1.5.0 / v1.5.1 / v1.5.2 changes landed on `main` but `gh-pages/updates.xml` was still advertising v1.4.9, so customer browsers polled the update URL and saw "you already have the latest" -- nothing to download. Republished gh-pages so `updates.xml` now advertises v1.5.2 and `pim-activator.crx` matches. GitHub Pages CDN takes ~1-5 min to fully propagate after a push; after that, every customer's next Edge / Chrome launch will fetch v1.5.2 within Chromium's normal auto-update window (~5 minutes after launch, then every ~5 hours).

**2. Deploy-PimActivatorClient.ps1 now writes 3 policies, not 1**

For each targeted browser (Edge / Chrome) under each scope root (HKLM / HKCU), the install path writes:

| Subkey | Value | Why |
|---|---|---|
| `ExtensionInstallForcelist` | `<id>;<update_url>` | "Install + keep installed" -- the core force-install directive (unchanged). |
| `ExtensionInstallAllowlist` | `<id>` | Defensive -- explicitly allows this id even if the admin has set `ExtensionInstallBlocklist=*`. No-op when no blocklist is in play. |
| `ExtensionInstallSources` | `<scheme>://<host>/*` from `$UpdateUrl` | Defensive -- whitelists the host serving the CRX so hardened baselines that restrict `ExtensionInstallSources` don't silently block the download. Derived from `$UpdateUrl` so customers who self-host get the right pattern instead of a stale `knudsenmorten.github.io` one. |

All three use the same deterministic slot number (`(hash(id) % 9000) + 1000`) so re-runs are idempotent and never collide with other policy-installed extensions in the same forcelist / allowlist / sources entries.

`-Uninstall` was extended to remove the same slot from all three subkeys.

---

## v2.4.78 -- PIM Activator extension v1.5.2: manifest homepage_url points to the GitHub repo

`chrome://extensions` "Visit website" link now lands on the source repo (`https://github.com/KnudsenMorten/PIM4EntraPS`) instead of the blog -- admins reviewing the extension can jump straight to the source / issues / release notes.

---

## v2.4.77 -- PIM Activator extension v1.5.1: developer / contact info surfaced in extension + popup

Two surfaces where the extension previously hid the developer + support channels:

**1. `manifest.json` -- now declares `author` + `homepage_url`**

```json
"author":       "Morten Knudsen (Microsoft MVP) <mok@mortenknudsen.net>",
"homepage_url": "https://mortenknudsen.net"
```

Chrome's `chrome://extensions` detail page surfaces both fields; admins doing extension inventory / supply-chain review can now see who owns the code and where to file issues without unpacking the package.

**2. Popup footer expanded -- 2 lines, all contact channels one click away**

Line 1 (unchanged shape, two new chips):
- Author link (`aka.ms/morten`)
- **Microsoft MVP** badge (Red, tooltip "Microsoft Most Valuable Professional")
- `part of PIM4EntraPS` (links to repo)

Line 2 (new):
- Direct email: `mok@mortenknudsen.net`
- Blog: `mortenknudsen.net`
- GitHub: `KnudsenMorten`
- YouTube: `@KnudsenMorten`
- Bug report: `PIM4EntraPS/issues`

Visual: matches the same `#0969da` link color the rest of the popup already uses; separators are pale-gray `|`. Total footer height bump is one ~14px row -- still fits the popup window without scrollbar reflow.

---

## v2.4.76 -- PIM Activator extension v1.5.0: tenant-portable bootstrap + SPN substring discovery + Deploy-PimActivatorClient defaults to HKLM

**1. Extension v1.5.0 -- bootstrap sign-in now works in any tenant**

Previously the bootstrap sign-in used a hardcoded clientId (`e96afaa6-1c00-4320-9a4c-334558138e09`) that was actually the upstream dev's single-tenant app reg. The moment a customer in any other tenant clicked "Sign in to auto-discover", Microsoft returned:

```
AADSTS700016: Application with identifier 'e96afaa6-...' was not found in the directory '<customer>'.
```

Switched the bootstrap clientId to Microsoft's own **Microsoft Graph Command Line Tools** multi-tenant app (`14d82eec-204b-4c2f-b7e8-296a70dab67e`) -- Microsoft pre-provisions this service principal in every Entra tenant by default (it's the same SPN `Connect-MgGraph` uses). Works in every tenant with no per-customer setup. Bootstrap scope narrowed to `User.Read + Application.Read.All + openid + profile + offline_access` (discovery-only). The runtime sign-in (after the user saves the discovered customer-tenant clientId) does its own sign-in against THAT clientId with the full PrivilegedAccess / Group / RoleManagement scope set.

Dropped the bootstrap-token persistence -- those tokens only carry discovery scopes and would never satisfy a runtime activation call.

**2. SPN lookup: servicePrincipals (not applications) + substring (not startsWith)**

Discovery query rewritten to `/v1.0/servicePrincipals?$search="displayName:PIM Activator"&$count=true&$top=25` with `ConsistencyLevel: eventual`. A customer can rename the SPN to `ACME PIM Activator (prod)`, `Contoso-PIM-Activator-Workload`, etc. and discovery still finds it because the match is now substring-based. Defensive client-side `.toLowerCase().includes('pim activator')` filter still drops near-match noise from the Graph tokenizer. Multi-match path (`apps.length > 1`) already shows a picker list -- unchanged.

**3. Deploy-PimActivatorClient.ps1 defaults `-Scope` to `Machine` (HKLM)**

Most operators running this script want force-install for every user on the box. The User-scope (HKCU) install was the default but only covers the running user's profile, which surprised people on shared / RDS / VM hosts.

- Default flipped to `-Scope Machine` -> writes to `HKLM:\SOFTWARE\Policies\Microsoft\Edge|Google\Chrome\ExtensionInstallForcelist`.
- Added an early elevation check so `-Scope Machine` without admin fails fast with a clear message instead of letting `New-Item` throw an opaque registry-permission error mid-write.
- Reworded the warning banner from the multi-line Yellow Intune-conflict block to a single Cyan default-mode line + a DarkGray reminder that on Intune-managed devices the Intune policy will overwrite this on next sync (use `Deploy-PimActivatorIntune.ps1` there).
- `.EXAMPLE` block reordered: zero-arg call now shown first as "Default per-machine install"; `-Scope User` retained as the opt-out for HKCU.

Re-run with `-Scope User` for the old behavior.

---

## v2.4.75 -- Engine fixes: PIM policy rule PATCH, schedule preload, generic datetime parser, "expires in 36159 days"

Four customer-reported regressions from a single launcher run:

**1. `Update-MgPolicyRoleManagementPolicyRule` crashed on every role**

Five call sites in `Update-PIMPolicy` (lines 8192/8268/8345/8466/8556) used a double-backtick (`` `` ``) where a single backtick (`` ` ``) line-continuation was intended. PowerShell saw `` ` `` as a positional argument and threw `A positional parameter cannot be found that accepts argument '`'` -- so every policy rule PATCH failed. Fixed all five sites.

**2. `Get-MgIdentityGovernancePrivilegedAccessGroup{Eligibility,Assignment}Schedule -All` started throwing `MissingParameters`**

Recent Microsoft.Graph SDK build rejects `-All` without `-GroupId` or `-PrincipalId` (parameter-set validation regression). The preload at `Get-PimGroupSchedulesPreloaded` swapped the cmdlet calls for a direct paged `Invoke-MgGraphRequest` against `https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/{eligibility,assignment}Schedules?$top=999` with manual `@odata.nextLink` pagination -- same shape, no SDK validation, no tenant-wide enumeration error.

**3. `Unable to parse datetime: '07/13/2026 13:53:47'`**

`CorrelateDateTimeLanguage` had a fixed list of `ParseExact` formats and missed the 24-hour `MM/dd/yyyy HH:mm:ss` shape Graph sometimes returns. Rewrote the function to:
- try `[datetime]::TryParse` with **InvariantCulture + en-US + en-GB + da-DK + CurrentCulture** under three styles (`AssumeUniversal|AdjustToUniversal`, `AssumeLocal`, `None`),
- then fall through to the explicit `ParseExact` format list as a safety net,
- and finally Write-Warning only if nothing parses.

Verified on both **PS 5.1** and **pwsh 7**: parses `07/13/2026 13:53:47`, `13/07/2026 13:53:47`, `13.07.2026 13:53:47`, `2026-07-13T13:53:47Z`, RFC1123, ISO-date-only -- and still returns `$null` (with warning) for genuinely garbage input.

**4. `Existing Assignment found ... skipping (expires in 36159 days)`**

When an assignment's `ScheduleExpirationEndDateTime` was empty or unparseable, the code fell through to `Ensure-DateTime $null` which defensively returns `(Get-Date).AddYears(99)` -- yielding the absurd "36159 days" figure (= 99 years). Added explicit `IsNullOrWhiteSpace` + post-parse null guards to four code paths (Group-eligibility, Role-direct, Role-PAG-group, and the Role-direct duplicate at 4327); each now logs either `OK - Permanent exists: <role> -> <principal>` (empty) or `OK - Exists (unparseable expiry 'X'): <role> -> <principal>` (parse-fail) and keeps `PIMAction = "NoAction"` without computing bogus day-counts.

**5. Skip-line wording: include role + principal**

All four `"Existing Assignment found ... skipping (expires in N days)"` lines reformatted to the same `OK - Exists: <role> -> <principal> (expires in N days, skipping)` tag the AdminAssign/EXTEND/UPDATE lines already use, so every skipped assignment in a run is greppable to a specific role/principal pair instead of an opaque "something was skipped".

---

## v2.4.74 -- Deploy-PimActivatorIntune.ps1: correct Settings Catalog body shape (parent CHOICE + child collection)

v2.4.72 shipped the Intune script with stale Settings Catalog setting IDs and the wrong body shape -- a flat `SimpleSettingCollectionInstance` referencing the old `microsoft_edgev106` / `google~googlechrome~policy` IDs that Microsoft has since renamed. The POST returned `400 Bad Request: Setting Id is not found in the Settings Catalog Database`.

Live-queried `/beta/deviceManagement/configurationSettings` for the actual current IDs + schema; both Edge and Chrome use a **parent CHOICE setting** (Enabled/Disabled) with a **child SimpleSettingCollection** holding the extension-id list. Corrected IDs:

| Browser | Parent (CHOICE) ID |
|---|---|
| Edge | `device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~extensions_extensioninstallforcelist` |
| Chrome | `device_vendor_msft_policy_config_chromeintunev1~policy~googlechrome~extensions_extensioninstallforcelist` |

Body builder rewritten to nest the child collection inside `choiceSettingValue.children` with the `_extensioninstallforcelistdesc` child setting holding the actual `<extension-id>;<update-url>` value. Idempotent PUT path uses the same shape.

Verified the JSON shape against the live Graph schema response (both settings are `deviceManagementConfigurationChoiceSettingDefinition`; child is `deviceManagementConfigurationSimpleSettingCollectionDefinition`).

---

## v2.4.73 -- Engine log lines: tagged single-line PIM actions + auto-interactive Connect-MgGraph in deploy scripts

**1. Engine log lines collapsed + tagged with PIM action**

Every PIM-action code path used to emit a 2-3 line block with separate `Mode: X` status:

```
Existing Assignment will be updated with assignment details
Mode: AdminUpdate

Existing Assignment will expire in 18 days
Mode: AdminExtend

Existing Assignment found ... skipping (expires in 32 days)
Mode: NoAction

Assignment was found .... removing
Mode: AdminRemove

Assignment was NOT found .... creating
Mode: AdminAssign

Existing Assignment found via Graph (API confirmed) ... skipping
```

Now collapsed into one tagged + coloured line per case with role + principal context:

```
UPDATE: User Administrator -> PIM-Entra-ID-UserAdministrator-L1 (refreshing assignment details)        [Yellow]
EXTEND: User Administrator -> PIM-Entra-ID-UserAdministrator-L1 (expires in 18 days)                  [Yellow]
OK - Exists: User Administrator -> PIM-Entra-ID-UserAdministrator-L1 (expires in 32 days, skipping)   [Green]
REMOVE: User Administrator -> PIM-Entra-ID-UserAdministrator-L1                                        [Red]
ASSIGN: User Administrator -> PIM-Entra-ID-UserAdministrator-L1 (new assignment)                       [Cyan]
OK - Exists: User Administrator -> PIM-Entra-ID-UserAdministrator-L1 (Graph confirmed, skipping)       [Green]
```

3 lines -> 1 line per assignment processed. With 100+ assignments per run that's a 300+ line reduction. Operator can grep the colour tag (UPDATE / EXTEND / REMOVE / ASSIGN / OK) to find what actually changed vs what was a no-op.

**2. Deploy-PimActivator{Backend,Intune}.ps1 auto-launch Connect-MgGraph if no context exists**

Previous behaviour: hard-throw `"Connect-MgGraph required."` if `Get-MgContext` returned null. Operator had to know the exact scopes string, run `Connect-MgGraph -Scopes '...'` themselves, then re-run the deploy script.

New behaviour: if `Get-MgContext` is null OR missing required scopes, the script auto-launches `Connect-MgGraph -Scopes <required-scopes> -NoWelcome` interactively (browser flow). Operator signs in once and the script continues without re-launch.

Required scopes per script:

| Script | Scopes auto-requested |
|---|---|
| `Deploy-PimActivatorBackend.ps1` | `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All` |
| `Deploy-PimActivatorIntune.ps1` | `DeviceManagementConfiguration.ReadWrite.All`, `Group.Read.All` |

Pre-connecting yourself still works (useful for `-TenantId` pinning when scripting); the auto-connect only fires when context is missing.

Other ps1 in `tools\pim-activator\`:
- `Deploy-PimActivatorClient.ps1` -- no Graph, registry only (no change)
- `Update-PimActivator-Extension.ps1` -- no Graph (no change)
- `Test-PimActivatorFlow.ps1` -- already does interactive Connect-MgGraph unconditionally (no change)

---

## v2.4.72 -- Deploy-PimActivatorIntune.ps1 re-added + shorter engine log lines + client output cleanup

Three operator-facing changes.

**1. `Deploy-PimActivatorIntune.ps1` is back**

Re-introduces the Intune deployment script that was removed in the v1.2.0 activator overhaul. Same defaults as `Deploy-PimActivatorClient.ps1` -- a zero-arg invocation creates a Settings Catalog configuration policy that force-installs the extension on Edge + Chrome:

```powershell
Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All','Group.Read.All'
.\Deploy-PimActivatorIntune.ps1
# Optional auto-assign to a target group:
.\Deploy-PimActivatorIntune.ps1 -AssignToGroupId <group-id>
# Cleanup:
.\Deploy-PimActivatorIntune.ps1 -Remove
```

Default profile DisplayName + Description both lead with `[PimActivator]` so the profile is filter-friendly in the Intune portal (Configuration profiles list filter on `[PimActivator]` finds it in one click). Idempotent -- re-running with the same DisplayName PATCHes the existing profile in place, no duplicates / accumulation. Different-named existing profiles co-exist; Intune unions ExtensionInstallForcelist values across applicable profiles per extension id, so the customer's other extensions and ours all force-install without conflict.

Uses the BETA Graph endpoint (`/beta/deviceManagement/configurationPolicies`) for Settings Catalog v2 (still beta despite years of "promised GA").

**2. Engine log lines for existing-assignment cases shortened**

`PIM-Functions.psm1` was emitting verbose contextless lines:

```
Existing Assignment found via Graph (not in snapshot) ... treating as existing
Existing permanent Assignment found ... skipping
Mode: NoAction
```

Now collapsed + context-tagged:

```
OK - Exists: User Administrator -> PIM-Entra-ID-UserAdministrator-L1
OK - Permanent exists: User Administrator -> PIM-Entra-ID-UserAdministrator-L1 (skipping)
```

Two-line output instead of three, role + principal embedded, `OK -` prefix consistent with the engine's other "OK" status lines.

**3. `Deploy-PimActivatorClient.ps1` stops echoing baked-in defaults**

v2.4.57 made `-ExtensionId` and `-UpdateUrl` defaultable, but the script kept printing them as `ExtensionId : eheoc... / UpdateUrl : https://...` -- which made operators think they had to supply them. Now those lines only print when the operator explicitly overrode (with a Yellow note showing the default value). Zero-arg run is now visually silent on those parameters.

---

## v2.4.71 -- SI parity: launcher transcript to logs/ + banner format matches SecurityInsight

Two layout-consistency fixes -- the operator should not be able to tell PIM4EntraPS launchers apart from SI launchers at run start.

**1. Auto-transcript to `SOLUTIONS\PIM4EntraPS\logs\`**

New shared helper `launcher\_lib\Start-PimLauncherTranscript.ps1`, mirrors the SI `Start-LauncherTranscript.ps1` exactly:

- Writes to `<repoRoot>\SOLUTIONS\PIM4EntraPS\logs\<engine>_<flavour>_<utcStamp>.log`
- One folder per repo (grep-friendly)
- UTC stamp: `yyyyMMddTHHmmssZ` (sortable)
- Retention: prune > 30 days (`$global:PIM_LogRetentionDays` to override)
- Opt-out: `$global:PIM_DisableTranscript = $true` for lab / CI runs

All 21 `launcher.internal-vm.ps1` files batch-patched to dot-source the helper + call `Start-PimLauncherTranscript -Engine $engineFolderName -Flavour 'internal-vm' -RepoRoot $InstallPath` right after the banner. Transcript path is echoed back as a Cyan `[INFO]   transcript:` line so the operator can find the file even if they didn't notice the folder.

**2. Banner format aligned 1:1 with SI's `Write-Banner`**

Previous PIM banner emitted a `[INFO] PIM4EntraPS <engine> launcher (<flavour>) v<X>` line in a custom delimited block. Now identical to SI:

```
========================================================================================
  PIM4EntraPS -- PIM-Baseline-Management-CSV    [internal-vm]   v2.4.71

  Developed by Morten Knudsen -- Microsoft MVP
  Blog:    https://mortenknudsen.net   (aka.ms/morten)
  GitHub:  https://github.com/KnudsenMorten
  Support: GitHub Issues on the public repo, or mok@mortenknudsen.net (internal)
========================================================================================
```

Same 88-character delimiter, same indentation, same colour, same dev/support credits as SI. Engine-name + flavour still auto-detected from `$PSCommandPath` so each launcher.ps1 keeps the two-line invocation.

**3. Engine module-load line also re-aligned with SI**

`PIM-Functions.psm1` module-load previously emitted a 3-line Cyan boxed `[INFO]` block. Now a single line mirroring SI's `Write-Info` style at engine startup:

```
  [INFO] PIM4EntraPS PIM-Baseline-Management-CSV engine v2.4.71 (<full path>)
```

vs SI's

```
[INFO] SecurityInsight RiskAnalysis engine v2.2.387 (<full path>)
```

Identical shape.

Scope deferred (will follow once these settle): same treatment for `internal-azure`, `community-vm`, `community-azure` launcher flavours -- internal-vm is what operators run interactively. The shared helpers are flavour-agnostic; only the two-line invocation needs adding to the other launchers.

---

## v2.4.70 -- AdminAccountPatterns accepts string[] form + Admin- / X-Admin defaults

Two related changes for admin-account naming-convention handling.

**1. AdminAccountPatterns now accepts a plain string array**

Previously `Get-PimAdminsFiltered` only recognised `$global:PIM_NamingConventions.AdminAccountPatterns` as a **hashtable** (UserType -> template). If a customer set it to a **string array** (the simpler form for "I just want to widen the prefix list for filtering"), the engine silently ignored it and the filter fell back to the singular `AdminAccountPattern`.

Now `AdminAccountPatterns` is accepted in three shapes -- engine picks the right path:

```powershell
# Form A: hashtable (per-UserType templates)
$global:PIM_NamingConventions.AdminAccountPatterns = @{
    Internal = 'Admin-{Initials}-L{Level}-T{Tier}-{Platform}'
    External = 'X-Admin-{Initials}-L{Level}-T{Tier}-{Platform}'
}

# Form B: string array (simple prefix list -- new in v2.4.70)
$global:PIM_NamingConventions.AdminAccountPatterns = @('Admin-', 'X-Admin')

# Form C: single string (rare; equivalent to AdminAccountPattern)
$global:PIM_NamingConventions.AdminAccountPatterns = 'Admin-'
```

Use whichever fits the tenant's mental model. The sample (`.custom.sample.ps1`) now shows both Forms A and B with worked examples.

**2. Locked defaults: Admin- / X-Admin (instead of adm_)**

`PIM4EntraPS.NamingConventions.locked.ps1` defaults changed:

```powershell
AdminAccountPattern   = 'adm_{Owner}'        ->  'Admin-{Owner}'
AdminAccountPatterns  = (not set)            ->  @('Admin-', 'X-Admin')
```

Reflects what every production tenant we've seen actually uses for tier-N admin UPNs (`Admin-Brian-L0-T0-ID@…`, `x-Admin-MOK-L0-T0-ID@…`). The legacy `adm_` default was wrong for everyone -- it caused `Get-PimAdminsFiltered` to query `startswith(userPrincipalName, 'adm_')` and return zero results on every customer, which then cascaded into the cache-miss → false "Owner UPN not found" warning emitted by the engine at every group-owners pass.

Tenants that genuinely use `adm_` (none observed so far) can override in `PIM4EntraPS.NamingConventions.custom.ps1`:

```powershell
$global:PIM_NamingConventions.AdminAccountPattern  = 'adm_{Owner}'
$global:PIM_NamingConventions.AdminAccountPatterns = @('adm_')
```

---

## v2.4.69 -- CRITICAL: stop duplicate-group creation + rename PAG->Group + fix locked naming convention

**1. Critical duplicate-create bug FIXED**

`CreateUpdate-PIM-Group` (was `CreateUpdate-PIM-PAG-Group` -- see point 2) had a defective "does the group already exist?" check at line 1178:

```powershell
$Group = $Global:Groups_All_ID | where-object { $_.DisplayName -eq $GroupName }
```

This only checked the in-memory cache populated by `Get-PimGroupsFiltered` at engine startup. If the cache was empty -- which happens whenever the customer's `PimGroupPattern` naming-convention prefix doesn't match what's actually in the tenant -- the lookup returned `$null`, the engine concluded the group didn't exist, and it created a **duplicate** for every group in the CSV on every single run.

Two customers hit this in production before we caught it -- the trigger was the locked default `PimGroupPattern = 'PIM_{Role}_{Department}'` (underscore) not matching real-world groups named `PIM-DEPT-Finance` / `PIM-ROLE-Internal-IT` (hyphen). Get-PimGroupsFiltered ran with `startswith(displayName,'PIM_')` and returned zero rows.

Fix: line 1178 now uses `Resolve-PimGroupCached` (which has Graph fallback when cache misses), aligned with the other three create-group sites in the same module that were already correct. Even if the cache is mis-populated for any reason, the Graph fallback catches existing groups.

**Cleanup for affected customers** -- remove the empty duplicate groups created by pre-v2.4.69 runs. Easiest path: list every PIM-* group sorted by createdDateTime, identify pairs with identical DisplayName, delete the newer one (older = real, newer = duplicate). The newly-created duplicates have empty membership lists, so they're identifiable that way too:

```powershell
$dupes = Get-MgGroup -Filter "startswith(displayName,'PIM-')" -All -Property Id,DisplayName,CreatedDateTime |
    Group-Object DisplayName | Where-Object Count -gt 1
foreach ($g in $dupes) {
    $newest = $g.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1
    Write-Host "DUPLICATE: $($g.Name) -- delete $($newest.Id) (created $($newest.CreatedDateTime))"
    # Remove-MgGroup -GroupId $newest.Id -Confirm:$false   # uncomment after eyeballing the list
}
```

**2. `CreateUpdate-PIM-PAG-Group` renamed -> `CreateUpdate-PIM-Group`**

"PAG" was the old "Privileged Access Group" label; the product is just called "PIM group" now. Back-compat alias `Set-Alias CreateUpdate-PIM-PAG-Group CreateUpdate-PIM-Group` ships in PIM-Functions.psm1 so any out-of-tree caller still works during the transition.

In-tree call sites updated:
- `PIM-Baseline-Management-CSV/PIM-Baseline-Management-CSV.ps1`
- `PIM-Baseline-Management-CSV-PIM4GroupsCreateModifyPolicyOnly/...`
- 2 internal call sites in `PIM-Functions.psm1`

**3. Locked naming-convention defaults: `PIM_` -> `PIM-`**

`PIM4EntraPS.NamingConventions.locked.ps1` changed:

```powershell
PimGroupPattern   = 'PIM_{Role}_{Department}'      ->  'PIM-{Role}-{Department}'
PimGroupAuPattern = 'PIM_{Role}_AU_{AdminUnit}'    ->  'PIM-{Role}-AU-{AdminUnit}'
```

Reflects what every real-world customer uses (no one was on underscores). `AdminAccountPattern` stays at `adm_{Owner}` -- admin UPNs DO use underscore there. If your tenant is somehow on the legacy underscore convention for PIM groups, override in `PIM4EntraPS.NamingConventions.custom.ps1`.

---

## v2.4.68 -- Two real fixes: V1 EXO permission docs + Entra propagation retry

Documenting what actually unblocked customer onboarding, plus a related
post-group-create race fix.

**1. `Exchange.ManageAsApp` (V1) is the actually-needed permission, NOT V2**

The EXO V3 connect error `Module could not be correctly formed. Please run Connect-ExchangeOnline again.` is misleading. EXO V3's connect sequence is:

  1. OAuth token acquire (cert + AppId)
  2. Open REST session to Exchange Online
  3. Enumerate cmdlets the authenticated identity has rights to call
  4. Build a dynamic PowerShell module from those cmdlets

When step 3 returns zero cmdlets (no Exchange-related directory role AND/OR wrong API permission), step 4 emits `Module could not be correctly formed` because there's literally nothing to form.

Earlier docs (v2.4.62 onward) recommended granting `Exchange.ManageAsAppV2`. That sounds newer + better, but cmdlet-set authorization for the EXO V3 module is actually consulted against `Exchange.ManageAsApp` (V1). Granting only V2 produces the misleading error.

Updated:
- PIM-Functions.psm1 Connect-ExchangeOnline failure message now says V1
  with an inline explanation of the V1-vs-V2 trap
- New-PlatformModernCert.ps1 final summary block now ends with an
  explicit "TWO MANUAL ENTRA STEPS REMAINING" call-out (yellow) listing
  V1 permission + Exchange Recipient Administrator role with the
  V1-vs-V2 footnote

Wasted-effort retrospective for the v2.4.66 EXO retry + v2.4.67 full
module-reset code: kept in place (cheap defensive code), but the real
fix for "Module could not be correctly formed" is the V1 perm. If you
hit it on a fresh tenant, grant V1 first; only investigate runspace /
EDR / Defender if V1 doesn't unblock you.

**2. Resolve-PimGroupCached retry-with-backoff when `-NoCache` is set**

After a freshly-created group, the engine called Resolve-PimGroupCached -NoCache and Graph returned 0 results because the new group hadn't propagated to the search index yet (typical Entra lag: 3-30s, sometimes longer). The single-shot Graph query gave $null, the caller passed empty string to Add-AdministrativeUnit-Member -ObjectId, which threw "Cannot bind argument to parameter 'ObjectId' because it is an empty string."

When `-NoCache` is used (signalling "I just created this object"), Resolve-PimGroupCached now retries up to 6 times with 5s backoff (~30s total wait) before giving up. Single-shot behavior preserved when `-NoCache` is NOT used (cache hits are still O(1)).

A loud `Write-Warning` fires only when all retries are exhausted and the group really isn't visible -- the caller still gets `$null` and still throws the bind error, but at least the operator sees WHY before the misleading parameter-binding stack trace.

---

## v2.4.67 -- Modern auth: cert preferred over secret + EXO V3 full module reset

Two related changes shipped together.

**1. Connect-PlatformModern now prefers cert over secret**

`AutomateITPS.Connect-PlatformModern` reads `Modern-Thumbprint` from KV at startup; if both the KV secret exists AND a matching cert is in `Cert:\LocalMachine\My` / `CurrentUser\My` (not expired), the Modern SPN authenticates via cert for BOTH Az and Graph. The Modern secret is not fetched in that case (`$global:HighPriv_Modern_Secret_Azure` stays `$null`, so engines that read it can tell "secret was not needed").

Fallback: if KV has no thumbprint OR the cert isn't locally present, the v2.3 secret path runs as before (no behavior change for tenants that haven't provisioned the Modern cert yet via `New-PlatformModernCert.ps1`).

A new global tracks which path was used:

```powershell
$global:HighPriv_Modern_AuthMethod   # 'Cert' or 'Secret'
```

The PIM-Baseline-Management-CSV engine's `[OK] Platform connected ...` line now reads this global and prints `auth=cert` or `auth=secret` -- previously printed a misleading `cert+secret` whenever both globals happened to be populated.

**2. EXO V3 'Module could not be correctly formed' -- full module reset**

v2.4.66's retry (`Disconnect + Remove-Module + Import-Module`) was insufficient on PowerShell 7.5+ -- the bug persists across the simple reset. New `Reset-ExoModuleState` helper in `PIM-Functions.psm1` runs the full Microsoft Q&A workaround chain:

1. `Disconnect-ExchangeOnline` (any prior session)
2. Remove dynamic proxy modules: `CreateExoPSSession*` AND `tmp_*` (these are auto-generated by EXO V3 and retain bad state across `Remove-Module ExchangeOnlineManagement` alone)
3. `Remove-Module ExchangeOnlineManagement -Force`
4. `Import-Module ExchangeOnlineManagement -Force -DisableNameChecking` (skips `Get-Verb` noise that triggers a different module-loading path in PS 7.5)
5. Sleep 3s (was 2s) before retry

If the V3 quirk still persists after the full reset on a second attempt, the real exception bubbles up so the operator can see the underlying cause (vs the V3 symptom). If you keep hitting this even with the full reset, the next escalation is pinning EXO module to a known-good version (`Install-Module ExchangeOnlineManagement -RequiredVersion 3.5.1 -Force`) -- documented as a separate Microsoft issue for PS 7.5.

---

## v2.4.66 -- EXO V3 retry + verbose bootstrap + launcher / engine version banners

Three operator-facing fixes shipped together.

**1. Exchange Online V3 'Module could not be correctly formed' retry**

Connect-ExchangeOnline V3 has a documented runspace-state bug where the first attempt errors with `Module could not be correctly formed. Please run Connect-ExchangeOnline again.` even when the auth inputs are valid. PIM-Baseline-Management-CSV used to bubble this up as a hard fail. Now the engine:

1. Disconnects any prior EXO session
2. Removes + force-reimports the `ExchangeOnlineManagement` module
3. Calls `Connect-ExchangeOnline`
4. On a `Module could not be correctly formed` / `forming the session` error, repeats steps 1-3 once and retries

If the retry succeeds, the run continues normally. If both attempts fail, the second exception bubbles up with the real cause -- not the misleading V3 quirk symptom.

**2. Verbose bootstrap output**

The `Initialize-PlatformAutomationFramework` call was silent (`$null = ...` consumed all output). Operators saw a few seconds of mystery delay between the engine title banner and `[ 01 / 12 ]`. The engine now prints:

```
[STEP]  Resolving AutomateIT repo root
[OK]    repo root: D:\AutomateIT
[STEP]  Importing AutomateITPS module
[OK]    AutomateITPS loaded
[STEP]  Initialize-PlatformAutomationFramework (bootstrap SPN -> KV -> Modern SPN -> populate $global:HighPriv_* / $global:Context)
[OK]    Platform connected in 4.2s -- tenant c2738ae6-..., KV kv-ng-automateit-p, Modern AppId c3689610-..., cert+secret
```

The trailing token (`cert+secret` / `secret-only` / `(none -- check KV)`) is a quick health probe -- if it says `(none -- check KV)`, KV is missing `Modern-AppId` or `Modern-Secret` and the subsequent engine work is going to fail.

**3. Launcher + engine version banners (SI parity)**

Three layers of the stack now print their version, each on a clearly bounded Cyan block:

- **Launcher** (`launcher.internal-vm.ps1`):
  ```
  =================================================================================
   [INFO] PIM4EntraPS PIM-Baseline-Management-CSV launcher (internal-vm) v2.4.66
   [INFO]   launcher : D:\AutomateIT\SOLUTIONS\PIM4EntraPS\launcher\...
  =================================================================================
  ```
- **Engine module load** (`PIM-Functions.psm1`):
  ```
  =================================================================================
   [INFO] PIM4EntraPS PIM-Baseline-Management-CSV engine v2.4.66 (D:\AutomateIT\SOLUTIONS\PIM4EntraPS\engine\PIM-Baseline-Management-CSV\PIM-Baseline-Management-CSV.ps1)
  =================================================================================
  ```
- **Solution version** stamped from `SOLUTIONS\PIM4EntraPS\VERSION` -- the same file the launcher banner reads.

Cyan + boxed delimiters so the version line doesn't blend with the gray `loaded ...` lines like v2.4.65's did. Engine-name detection uses `Get-PSCallStack` so it auto-fills with whichever engine `Import-Module PIM-Functions` was called from.

Note: this release wires the launcher banner for `PIM-Baseline-Management-CSV/launcher.internal-vm.ps1` as the template. Other PIM launchers (PIM-Assignment-Exporter, Check-PIM-Groups-IsRoleAssignable, etc.) get the same banner by copying the 14-line block; will propagate them in a follow-up release once the pattern stabilises.

---

## v2.4.65 -- Modern SPN cert provisioner + version stamp + corrected EXO error

Three small but operator-facing fixes:

1. **`New-PlatformModernCert.ps1`** -- new script under
   `SOLUTIONS\PlatformConfiguration\INTERNAL\Provision\`. Mirrors the
   Bootstrap pattern but for the operational Modern SPN. One elevated
   run on a freshly-onboarded host:
     - Generates a self-signed cert (`CN=AutomateIT-HighPriv-<COMPUTERNAME>`)
     - Installs in `Cert:\LocalMachine\My`
     - Registers it as a credential on the Modern SPN in Entra via Graph
     - Writes the thumbprint to KV as `Modern-Thumbprint`
   Idempotent -- no-op if KV already has the secret AND the cert is on
   this host. Use `-Force` to add a host-specific credential on
   additional hosts (each gets its own cert; SPN accepts many).

2. **Version stamp at PIM-Functions module load.** Every engine now
   prints `[INFO] PIM4EntraPS solution v<VERSION>` from the `VERSION`
   file at startup -- same SI pattern, scannable, ties the run log to
   a specific release. The previous `Sync-AutomateIT` -> wrong-version
   issue (drift between solutions on the host) becomes obvious in the
   log: PIM4EntraPS line shows what was actually loaded.

3. **EXO cert-missing error message rewritten.** v2.4.62 told the operator
   to "upload the AutomateIT bootstrap cert as additional credential on the
   Modern SPN" -- that was reverted in v2.4.64 (Bootstrap and Modern get
   distinct certs) but the error text in `PIM-Functions.psm1` still showed
   the old guidance. Now it points at `New-PlatformModernCert.ps1` and the
   correct workflow.

---

## v2.4.64 -- Modern SPN gets its OWN cert (don't mix with Bootstrap)

Correcting v2.4.62's "reuse the Bootstrap cert on the Modern SPN" guidance. That was sloppy -- the Bootstrap and HighPriv (Modern) identities are intentionally separate SPNs with intentionally separate roles, and sharing crypto material between them collapses the boundary. **Each SPN gets its own cert.**

What changed in `AutomateITPS.Connect-PlatformModern`:

- Removed the `BootstrapThumbprint` read from `platform-config.json` (introduced in v2.4.62)
- Added a new `-ModernThumbprintSecretName` parameter (default: `Modern-Thumbprint`) that reads the Modern SPN's cert thumbprint from KV alongside `Modern-AppId` + `Modern-Secret`
- `$global:HighPriv_Modern_CertificateThumbprint_Azure` is populated only when BOTH the KV secret exists AND the matching cert is installed locally + still valid
- Loud `Write-Warning` if KV has the thumbprint but the cert isn't in `Cert:\` (typical "I added the KV secret but forgot to install the cert on this host" misconfig)

**Customer one-time setup** (per tenant, replaces the v2.4.62 instructions):

1. Create a NEW cert for the Modern SPN. Self-signed is fine:
   ```powershell
   $cert = New-SelfSignedCertificate -Subject 'CN=AutomateIT-Modern-Cert' -CertStoreLocation 'Cert:\LocalMachine\My' -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)
   Export-Certificate -Cert $cert -FilePath C:\TMP\automateit-modern.cer
   ```

2. Upload `automateit-modern.cer` to the HighPriv Modern SPN in Entra (App registrations → HighPriv SPN → Certificates & secrets → Upload certificate). **Do NOT reuse the Bootstrap cert.**

3. Store the thumbprint in KV alongside the existing `Modern-AppId` + `Modern-Secret`:
   ```powershell
   Set-AzKeyVaultSecret -VaultName <kv-name> -Name Modern-Thumbprint -SecretValue (ConvertTo-SecureString $cert.Thumbprint -AsPlainText -Force)
   ```

4. Install the cert (with private key) on every host that runs operational engines that need cert-app-only auth. Same `.pfx` import to `Cert:\LocalMachine\My`.

5. Modern SPN still needs the API perm + directory role from v2.4.62:
   - **Office 365 Exchange Online → Exchange.ManageAsAppV2** (Application, admin-consented)
   - **Exchange Recipient Administrator** directory role

**Recovery for tenants that already followed v2.4.62's reuse-the-Bootstrap-cert path:** the simplest path is to remove the Bootstrap cert credential from the Modern SPN (Entra → App registrations → Modern SPN → Certificates & secrets → delete) and follow steps 1-4 above with a fresh Modern-specific cert. If you'd rather keep what's already in place, you can short-circuit by writing the Bootstrap thumbprint into the `Modern-Thumbprint` KV secret -- the engine then works, but the SPN isolation that the rest of the design relies on is gone.

---

## v2.4.63 -- EXO auto-resolves -Organization from MgGraph when unset

Hot follow-up to v2.4.62. The new cert-based `Connect-ExchangeOnline` path requires `-Organization <tenant>.onmicrosoft.com`; the old interactive path did not. Customers whose `repository.custom.ps1` never set `$TenantNameOrganization` (common on cold installs -- the variable wasn't even mentioned in the sample) tripped on `OperationStopped: Value cannot be null. (Parameter 'Organization cannot be null for certificate based connections.')` immediately after the v2.4.62 success log line.

`PIM-Functions.psm1` Connect-ExchangeOnline call now auto-resolves the value from `Get-MgOrganization` (we're already MgGraph-connected via `Initialize-PlatformAutomationFramework`) -- picks the verified domain where `IsInitial = true`. If the operator has explicitly set `$TenantNameOrganization` in `repository.custom.ps1`, that value wins; only empty/whitespace falls through to auto-resolve. A `[info]` log line documents the resolved value so the operator can spot it in the run log.

Hard throw with an explicit "set `$TenantNameOrganization` in `repository.custom.ps1`" pointer if Graph itself can't return an org (genuine misconfig, not a missing customer setting).

No customer action needed -- just `Sync-AutomateIT` and re-run.

---

## v2.4.62 -- One auth stack: Exchange Online now uses the HighPriv (Modern) SPN

The CSV baseline engine (`PIM-Baseline-Management-CSV`) used to call `Connect-ExchangeOnline -CertificateThumbprint $HighPriv_Modern_CertificateThumbprint_O365 -AppId $HighPriv_Modern_ApplicationID_O365 ...`. Those `_O365`-suffixed globals are v1-era legacy slots that v2.3 `Connect-PlatformAutomationFramework` no longer populates -- the chain only sets `_Azure`. Result: both args resolved to `$null`, `Connect-ExchangeOnline` silently fell back to interactive browser auth, and on a headless box you'd get an `OperationCanceledException` from `DefaultOSBrowser.HttpListenerInterceptor` after the OAuth listener never received a redirect.

This release codifies the principle the AutomateIT platform has been moving toward: **one auth stack per solution that's on AutomateIT, no legacy SPN straddling**. v2.4.61 took a wrong turn here -- it routed cert auth through the Bootstrap SPN, which is by design min-privilege (KV-read-only). This release walks that back: cert reuse stays, but the operational identity is the HighPriv (Modern) SPN, which is where API permissions belong.

What changed:

1. **`AutomateITPS.Connect-PlatformModern`** now exposes the cert thumbprint as `$global:HighPriv_Modern_CertificateThumbprint_Azure` -- previously hard-set to `$null` ("v2.3 = secret only"). The thumbprint is sourced from `platform-config.json` `BootstrapThumbprint` (the same cert file is reused on both Bootstrap and Modern SPNs) and is populated only when the cert is actually installed locally (`Cert:\LocalMachine\My` or `Cert:\CurrentUser\My`) AND not expired. So `if ($global:HighPriv_Modern_CertificateThumbprint_Azure)` is the "can the Modern SPN do cert-app-only?" probe.

2. **`PIM-Functions.psm1` Connect-ExchangeOnline call** now reads from `$global:HighPriv_Modern_ApplicationID_Azure` + `$global:HighPriv_Modern_CertificateThumbprint_Azure`. No `_O365` fallback -- if the Modern cert isn't usable, the engine throws with an actionable error that tells the operator exactly what to do.

3. **v2.4.61's `$global:HighPriv_Bootstrap_*` globals are reverted** -- the bootstrap identity stays unexposed, restoring the original min-privilege boundary. `Disconnect-Platform` no longer references them.

**One-time per tenant**, on the **HighPriv (Modern) SPN** (the operational identity -- `AutomateIT-HighPrivileged-Tier0-vm-automation-p` or equivalent in your tenant):

| Type | What | Where |
|---|---|---|
| Credential | Upload the AutomateIT bootstrap `.cer` as an additional certificate credential (same cert file, second SPN registration). The cert stays in `Cert:\LocalMachine\My` from the bootstrap install -- no new cert provisioning. | Entra ID -> App registrations -> HighPriv SPN -> Certificates & secrets -> Upload certificate |
| API permission | **Office 365 Exchange Online -> Exchange.ManageAsAppV2** (Application, admin-consented) | Entra ID -> App registrations -> HighPriv SPN -> API permissions |
| Directory role | **Exchange Recipient Administrator** (or Exchange Administrator if you need broader EXO ops) | Entra ID -> Roles and administrators -> Exchange Recipient Administrator -> Add assignments |

After granting, the next run of `PIM-Baseline-Management-CSV` will reach `Connect-ExchangeOnline` and authenticate as the HighPriv SPN via cert -- no browser, no interactive fallback. The legacy v1 `_O365` SPN can be deprovisioned.

---

## v2.4.61 -- SUPERSEDED by v2.4.62

Initial pass at the EXO cert-auth fix wired permissions through the Bootstrap SPN. Architecturally wrong -- Bootstrap must stay min-privilege. **See v2.4.62 above for the corrected design (cert is reused on the HighPriv Modern SPN).** v2.4.61's `$global:HighPriv_Bootstrap_*` globals are removed in v2.4.62.

---

## v2.4.60 -- Pre-v2.0 config files auto-rename into the v2 .custom slot

A customer migrating from PIM4EntraPS v1.x typically had filenames like `PIM-Definitions-Roles.csv` (no suffix). Copying those into the v2 `config/` folder used to do nothing — the engine looks for `<name>.custom.csv` and silently ignored the unsuffixed file. Combined with the v2.4.56 sample auto-bootstrap added two releases ago, the result was that v1 files sat untouched while the engine quietly created `<name>.custom.csv` from the example sample on top — overwriting nothing, but ignoring the customer's actual rows.

`Get-PimCustomScript` and `Get-PimConfigCsv` now detect the unsuffixed pre-v2.0 file (`<name>.csv` / `<name>.ps1`) and `Move-Item` it into the `<name>.custom.csv` / `<name>.custom.ps1` slot before the sample bootstrap would fire. The move is in-place — your content is preserved, only the filename suffix changes. A loud `Write-Warning` notes the migration so the operator can confirm.

Resolution priority (CSV; PS1 is the same minus the legacy step):

| Step | What's checked | Action |
|---|---|---|
| 1 | `<name>.custom.csv` exists | Return as-is |
| 2 | `<name>.csv` (v1, unsuffixed) | **Rename to `.custom.csv`**, warn, return (NEW in v2.4.60) |
| 3 | `<name>.locked.csv` (pre-v2.3.0 shipped baseline) | Return with legacy warning (unchanged) |
| 4 | `<name>.custom.sample.csv` exists | Copy to `.custom.csv`, warn, return (added in v2.4.56) |
| 5 | None of the above | Throw |

The order matters: customer data (v1 rename) wins over shipped templates (sample bootstrap), so a customer who copied their v1 export over never silently runs the engine against placeholder rows.

If you've already let v2.4.56 auto-bootstrap a sample into `.custom.csv` on top of an existing v1 file, delete the unwanted `.custom.csv` and re-run -- step 2 will now pick the v1 file up cleanly.

---

## v2.4.58 -- Deploy-PimActivatorBackend now grants consent by default

Tiny but high-impact polish on the activator setup flow. `Deploy-PimActivatorBackend.ps1` no longer needs `-GrantConsent` to do the obviously-right thing:

```powershell
# Before (v2.4.57 and earlier):
.\Deploy-PimActivatorBackend.ps1 -GrantConsent

# Now:
.\Deploy-PimActivatorBackend.ps1
```

Why default-on: without admin consent, every user that opens the extension's onboarding wizard hits a per-user consent dialog they likely can't approve themselves -- and almost nobody actually wanted that outcome. The old default forced operators to remember `-GrantConsent` or end up with a half-deployed app reg.

Skip the consent step (rare -- e.g. you don't hold Privileged Role Administrator and consent will land later via the Enterprise apps blade) with `-GrantConsent:$false`.

---

## v2.4.57 -- Activator deploy scripts default the constants

`Deploy-PimActivatorBackend.ps1` and `Deploy-PimActivatorClient.ps1` no longer make you re-type values that are the same on every install of the upstream distribution:

- `-ExtensionId` defaults to `eheocihmlppcophaeakmdenhgcookkab` (derived from the manifest `key` field, identical everywhere)
- `-UpdateUrl` defaults to `https://knudsenmorten.github.io/PIM4EntraPS/updates.xml`

So a fresh tenant is now just:

```powershell
Connect-MgGraph -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All'
.\Deploy-PimActivatorBackend.ps1                # backend (combined with v2.4.58 = no args needed)
.\Deploy-PimActivatorClient.ps1 -Scope Machine  # forcelist on un-managed servers
```

Override only if you fork the extension under your own signing key or self-host the CRX mirror -- that combination is the only case where the constants change.

---

## v2.4.56 -- First-run bootstrap: missing .custom files auto-copy from samples

A cold install of PIM4EntraPS on a new customer used to fail on the first launcher invocation with "Get-PimConfigCsv: 'PIM-Definitions-Departments.custom.csv' not found. Copy '...custom.sample.csv' to '...custom.csv' and edit it." -- once for each missing file. Ten-plus CSVs + a few `.ps1` scripts = a tedious manual copy chain before the engine would even start.

`Get-PimCustomScript` and `Get-PimConfigCsv` (engine/_shared/PIM-Functions.psm1) now bootstrap a missing `.custom.*` from its `.custom.sample.*` sibling on first miss, emit a loud `Write-Warning`, and continue. The warning explicitly says the sample is template/example data, not production rows -- so operators know they MUST review the freshly-bootstrapped files before relying on subsequent runs.

If no sample exists alongside, behavior is unchanged: hard throw with the missing-file path. The legacy `.locked.csv` pre-v2.3.0 fallback (with its existing one-time warning) still wins over the sample bootstrap.

---

## v2.4.55 -- Release notes rewrite for readability

Consolidated the recent release-notes entries into a more reader-friendly narrative. Specifically:

- **v2.4.45 → v2.4.50** were six small follow-up patches on top of the v2.4.44 Intune deployer; folded into a single "Polishing the Intune deployer" entry that walks through the five common failure modes the patches addressed
- **v2.4.54** was a doc-only catch-up on the v2.4.53 restyle; merged into the v2.4.53 entry as a single brand-makeover story
- The remaining entries (v2.4.51 default-duration bump, v2.4.52 extension-ID fix, v2.4.53 PIM Manager restyle, v2.4.44 multi-tenant + Intune Remediations) were rewritten to lead with what changed for **you**, not the implementation detail -- recovery commands stay where they help, hex codes and module noise dropped

No code, script, or extension changes -- pure release-notes restructuring. Extension stays at v1.1.1.

---

## v2.4.53 / v2.4.54 -- PIM Manager gets the brand makeover

The local PIM Manager (the editor you open with `Open-PimManager.ps1`) had been stuck on the old dark theme since v0.1, while the browser extension switched to a clean light brand back in v1.0.0. With this release, the two finally match.

What you'll notice when you open it next:

- **White background, dark text, blue accents** -- friendly on the eyes when you're working in the editor for half an hour
- **Big blue banner** across the top: **PIM MANAGER** in white uppercase, with a subtitle that names the tool ("PIM4EntraPS · configuration editor")
- **A 2px blue frame** around the whole window so the tool stands out when you have a stack of admin windows open
- **The "New & clone" cards** (where you pick which kind of thing to create) are now solid blue tiles with white text -- scan-them-in-a-second readable
- **The graph view's coloured nodes are unchanged** on purpose. The purple / lavender / orange swatches in the legend have to match the nodes themselves, so they're part of the contract, not the theme

No behavior changes anywhere -- pure visual restyle. The Activator extension is still at v1.1.1. (v2.4.54 was a doc-only follow-up that brought the two READMEs in sync with the restyle.)

---

## v2.4.52 -- Recovering from a documented-but-wrong extension ID

Embarrassing one to write up, but worth being transparent about.

Back at v2.4.43, the extension signing key was regenerated and the new ID (`hkdg...`) got recorded in `extension-identity.txt` and every install command in the docs. What **didn't** happen: actually swapping the signing key in `Update-PimActivatorDev.ps1`. So for nine releases, the docs said one ID, the published CRX used a different one (`ehec...`), and every customer who copy-pasted the documented install command wrote tenant config to a registry path the running extension was never reading.

The symptom: extension installs fine, popup opens, but shows **"Not configured. Admin must set tenantId + clientId (or a Tenants array) via policy."** -- even when the registry actually had the right values, just at the wrong path.

Fixed in this release:
- `extension-identity.txt` now states the **actual** ID, with a History block explaining what happened
- `Deploy-PimActivatorIntune.ps1`'s default `-ExtensionId` parameter points at the right ID
- Every install / sample command in both READMEs corrected

**If you ran an install during v2.4.43–v2.4.51 and the popup says "Not configured"**, re-run `Deploy-PimActivatorClient.ps1` with the right ID and restart Edge + Chrome:

```powershell
.\Deploy-PimActivatorClient.ps1 `
    -ExtensionId 'eheocihmlppcophaeakmdenhgcookkab' `
    -UpdateUrl   'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml' `
    -TenantsCsv  .\tenants.csv `
    -Scope       User
```

Cleaning up the stale registry entries at the old ID is optional -- the new install just overwrites the path the extension actually reads, so the popup starts working immediately.

No extension code changes; the CRX has been v1.1.1 since v2.4.51 and that's still what's on gh-pages.

---

## v2.4.51 -- Default activation duration is 8 hours, not 1 (extension v1.1.1)

Small change with a real quality-of-life payoff. The popup used to default the duration field to **1 hour**, which forced every user to retype "8" on every activation. One hour is the minimum the API will accept; it's not a realistic admin session.

New default everywhere is **8 hours** (one workday). Touched all five places that ship a default value -- the bundled extension code, the developer-mode config placeholder, the Setup-PimActivator config.js generator, and both deployment scripts. The ADMX path was already at 8.

**Existing customer installs that pinned 1h via Intune managed-storage are unchanged** -- managed config always wins over the bundled default. The new 8h kicks in for fresh installs and for users who haven't activated anything yet. (The popup also remembers the last duration the user picked, per profile, so once anyone clicks Activate with a non-default value, that becomes their personal default.)

To pick a value other than 8h at install time: pass `-DefaultDurationHours 2` (or whatever) to the install script. Direct registry edit also works for tweaks after the fact.

Extension manifest 1.1.0 → **1.1.1**.

---

## v2.4.45 – v2.4.50 -- Polishing the Intune deployer

Six small releases over a couple of days, all chipping away at rough edges in the `Deploy-PimActivatorIntune.ps1` flow that v2.4.44 introduced. Together they answer "I tried it and it didn't work because…" for the five most common failure modes.

### Optional `-GroupId` (v2.4.45)

Was mandatory; many admins prefer to create the remediation in Intune via Graph, then assign it manually in the Intune Admin Center UI so they can stage a pilot before broad rollout. Now optional -- omit it and the remediation is created **unassigned**, with the script printing the exact UI navigation path to finish the assignment.

### New mode: `-GenerateLocalInstaller` (v2.4.45)

For environments without Intune -- AD GPO domains, file share rollouts, SCCM, manual installs on a handful of laptops -- a CSV-driven generator that emits a fully self-contained `Install-PimActivator.ps1` (plus matching Uninstall + a README explaining each rollout path). The tenant JSON is baked into the installer at generation time, so no run-time parameters and no CSV dependency on the target machine. Two scopes:

- `-LocalInstallerScope User` -- HKCU, no admin needed. Ideal for GPO Logon Scripts or a folder on a file share that admins click into.
- `-LocalInstallerScope Machine` -- HKLM, elevated. Ideal for GPO Startup Scripts on shared admin servers. The installer self-checks elevation and fails loud if you forgot to right-click → Run as administrator.

| Environment | Recommended path |
|---|---|
| Intune-managed | `Deploy-PimActivatorIntune.ps1 -CreateIntuneRemediation` (hourly self-heal) |
| AD-only / on-prem | `Deploy-PimActivatorIntune.ps1 -GenerateLocalInstaller` + GPO Startup or Logon Script |
| File share + manual | `Deploy-PimActivatorIntune.ps1 -GenerateLocalInstaller` -- drop on `\\srv\sw\PimActivator\` |
| SCCM | `Deploy-PimActivatorIntune.ps1 -GenerateLocalInstaller` packaged as a Script Application |
| Single test box | `Deploy-PimActivatorClient.ps1 -Tenants @(...)` direct registry write |

### Right Graph scope (v2.4.46)

`-CreateIntuneRemediation` was asking for `DeviceManagementConfiguration.ReadWrite.All` but the `deviceHealthScripts` endpoint actually wants `DeviceManagementScripts.ReadWrite.All` (different noun). Hit HTTP 403 for everyone on first try. Fixed, plus the script now auto-disconnects and reconnects when your cached Graph token is missing any required scope -- so you don't have to manually `Disconnect-MgGraph` after every script update.

### `-UseDeviceCode` + post-connect scope verification (v2.4.47)

The default Microsoft.Graph SDK auth flow silently returns "success" even when the user closes the browser tab before consenting -- the next Graph call then fails with a cryptic "The server has not found anything matching the requested URI". Two improvements:

- **Post-connect verification** -- the script reads `Get-MgContext` right after `Connect-MgGraph` and confirms every required scope is actually present. If not, you get an actionable error instead of a misleading 404.
- **`-UseDeviceCode` switch** -- skips the embedded browser entirely, prints a code + URL you paste on any device. Much more reliable over RDP, on hardened workstations, or anywhere the SDK's localhost redirect URI can't bind.

### Bring-your-own Graph session (v2.4.48)

Some tenants block device code AND have a flaky interactive browser experience (Conditional Access, blocked localhost redirects, etc.). Solution: just let admins establish the Graph session themselves first, then run the deployer. The script now checks `Get-MgContext` -- if you've already connected with the right scopes, it skips its own `Connect-MgGraph` entirely.

```powershell
# Step 1 -- use whatever auth flow your tenant accepts
Connect-MgGraph -Scopes 'DeviceManagementScripts.ReadWrite.All','DeviceManagementConfiguration.ReadWrite.All','Group.Read.All'

# Step 2 -- run the deployer
& Deploy-PimActivatorIntune.ps1 -CreateIntuneRemediation -TenantsCsv .\tenants.csv
# -> "Reusing existing Graph session: admin@tenant.com"
```

### Server install path documented (v2.4.49)

Both READMEs gained a "Server install" section covering admin jump boxes, PAWs, and shared Windows Servers. Three paths depending on machine type: **User scope** for personal PAWs (one admin, HKCU, no elevation), **Machine scope** for shared servers (HKLM, elevated, covers every RDP user in one install), and **AD GPO Startup Script** for domain-joined server fleets (runs as SYSTEM at boot, every server in the OU converges).

### `-TenantsCsv` works on its own (v2.4.50)

PowerShell parameter-set bug -- `-TenantsCsv` and `-Tenants` were in the same set with `-Tenants` marked mandatory, so passing only `-TenantsCsv` prompted you for `Tenants[0]:`. Split into two distinct parameter sets so each input mode is independently usable. Single-tenant CSV install now works clean:

```powershell
.\Deploy-PimActivatorClient.ps1 -ExtensionId <id> -UpdateUrl <url> -TenantsCsv .\tenants.csv -Scope User
```

(Legacy singleton path `-TenantId` + `-ClientId` was never broken; only the multi-tenant CSV input had the bug.)

---

## v2.4.44 -- Multi-tenant support + Intune rollout (extension v1.1.0)

The big release for consultants and MSPs: **one extension install can now serve multiple Entra tenants on the same Windows user**. Each browser profile picks its own tenant; the choice sticks per-profile thanks to `chrome.storage.local`.

### What you see in the popup (extension v1.0.0 → v1.1.0)

- **A `Tenants` managed-config field** -- a JSON array of `{ Name, TenantId, ClientId }` entries. When 2+ entries are present, the popup shows a clean tenant picker on first open per Chromium profile. When exactly 1 entry is present, the picker is silent. When the array is missing, the old `tenantId`/`clientId` singleton fields still drive the extension -- so existing v1.0 installs continue working untouched.
- **Per-profile selection cached** -- pick your tenant once per profile and the popup remembers it next time. Switch to a different Edge profile and you get the picker fresh, ready to pick a different tenant.
- **Friendly tenant name in the footer** -- replaces the GUID with the human label you chose ("Tenant: ACME Production") plus a (switch) link to change selection.
- **Clean OAuth boundaries** -- sign-in artifacts and refresh tokens are wiped on every tenant switch so the popup never carries a token from the previous tenant into the new one.

### New helper: `Deploy-PimActivatorIntune.ps1`

A CSV-driven Intune Remediation deployer. One `tenants.csv` (columns: `Name,TenantId,ClientId`) drives the whole story:

| Mode | Purpose |
|---|---|
| `-GenerateScripts` | Emit `Detection.ps1` + `Remediation.ps1` to disk for manual upload via the Intune UI |
| `-CreateIntuneRemediation` | Push it to Intune via Microsoft Graph, schedule hourly, optionally assign to a group, print the remediation ID |
| `-UpdateIntuneRemediation` | Re-read the CSV and overwrite an existing remediation in place -- the "add a tenant" command |

Schedule defaults to **hourly**, so adding a tenant to the CSV propagates to all assigned devices within an hour.

### Direct registry write: new `-Tenants` parameter

`Deploy-PimActivatorClient.ps1` gains a `-Tenants` parameter set (and `-TenantsCsv` alternative) for direct HKCU / HKLM writes -- useful for dev boxes and one-off test machines without going through Intune. The singleton `-TenantId` + `-ClientId` style still works for legacy / single-tenant installs.

### How the layers fit together

```
tenants.csv                                          <- you edit this
     |
     v
Deploy-PimActivatorIntune.ps1 -UpdateIntuneRemediation
     |
     v
Intune Remediation                                   <- hourly silent run, no UI
     |
     v
HKCU\...\3rdparty\extensions\<id>\policy\Tenants     <- JSON array
     |
     v
chrome.storage.managed.Tenants                       <- browser reads
     |
     v
popup.js picker UI                                   <- user sees on extension click
     |
     v
chrome.storage.local.selectedTenantId                <- per profile, sticks
```

Intune Remediations are silent registry pushes -- they don't show a UI. The picker the user sees lives inside the extension popup, not Intune. Two independent layers: Intune keeps the registry healthy; the extension popup handles user-facing choice.

Extension manifest 1.0.0 → **1.1.0**.

---

## v2.4.43 -- PIM Activator extension graduates to **v1.0.0** (production)

Milestone release: the browser extension leaves the `0.4.x` beta numbering and ships as **v1.0.0**. Same MV3 CRX, same code that's been iterated on in production for weeks -- just a version statement that the feature set is stable enough to recommend to customers without "dev preview" caveats.

### What you actually get on v1.0.0

End-to-end PIM-for-Groups self-service in two tabs inside Edge or Chrome:

- **Activate tab** -- one-click bulk activation of every eligible PIM-for-Groups membership. Justification + duration entered once, applied to every ticked row. New: dropdown of the last 10 reasons used (datalist autocomplete), so a returning user can pick "Daily ops" or "Incident response" instead of retyping.
- **My Access tab** -- every currently-active membership in one place, with per-row Deactivate AND multi-select "Deactivate selected (N)" for surrendering early. Two-click confirm pattern on both buttons (Chromium silently suppresses `window.confirm()` in MV3 popups, so the previous native-dialog approach looked broken).
- **Role preview** -- each eligible group row shows the Entra roles and Azure RBAC roles you'll inherit when you activate, including roles granted via nested group membership. Administrative Unit scopes resolved to friendly names (`in AU 'Tier0-Devices'`) instead of raw GUIDs.
- **Progress bars** -- indeterminate striped bar during the post-sign-in load (no totals yet), then a determinate 0-100% bar in the Activate footer + My Access toolbar while per-group roles stream in. Separate counters for the Entra + Azure tasks so a race between the two can never strand the bar at 50/51.
- **Multi-tenant aware** -- tenant ID surfaced in the popup footer so admins managing multiple Entra tenants see at a glance which one they're hitting.

### Manifest + tooling

- Extension manifest pinned to **1.0.0** (no more auto-bump landing on `0.4.x`)
- `Update-PimActivatorDev.ps1` gains `-Version <ver>` to pin an exact manifest version for milestone releases; default behaviour (auto-bump patch) unchanged

Manifest 0.4.34 -> **1.0.0**.

---

## v2.4.37 -- Popup ACTUALLY shrinks on sign-in screen + version badge visible pre-sign-in

Two real fixes:

1. **Popup size**: the v2.4.34 + v2.4.36 attempts used `body { display:flex; flex-direction:column }` with `flex:1` on the tab panel + `min-height:0` on the list. `flex:1` made the panel WANT to grow, so even with empty content the popup hit max-height (~600px). Swapped to a simple block layout: body sizes to content; only the lists get `max-height:380px; overflow-y:auto`. Now the sign-in screen is genuinely compact (~130px including header + status + footer).

2. **Version badge in header**: was populated inside `loaded()` which only runs AFTER sign-in. Moved to a top-level IIFE so the version (`v0.4.29`) is visible immediately on the sign-in screen too.

Manifest 0.4.28 -> 0.4.29.

---

## v2.4.36 -- Popup shrinks to content on sign-in screen (no more big empty box)

`body { height:600px }` from v2.4.34 made the popup fixed-height even on the sign-in screen, leaving a huge empty white area below the "Sign in to load..." text. Swapped to `min-height:180px; max-height:600px`. The popup now sizes naturally to content -- compact when only sign-in is shown, expands up to 600px when there's a full group list to render, then the list area scrolls within.

Manifest 0.4.27 -> 0.4.28.

---

## v2.4.35 -- Role preview ACTUALLY works now (per-group `eq` queries + progress bar)

Root cause of "no roles shown" complaint across v2.4.28 - v2.4.34: the bulk fetch used `$filter=principalId in ('g1','g2',...)` on `/roleManagement/directory/roleAssignments`. The `in` operator is NOT documented as supported on that endpoint; Graph silently returned empty results for every chunk. Also added `$count=true` to the direct query in v2.4.33 without the matching `ConsistencyLevel: eventual` header -- HTTP 400 from Graph, fallback failed too.

v2.4.35 throws out the in-clause approach entirely. Replaced with:
- **One Graph call per group**, fired in parallel via Promise.all -- 50 concurrent fetches; browsers handle via HTTP/2 multiplexing in roughly the time of one batched call
- Per-group call uses `transitiveRoleAssignments?$filter=principalId eq '<gid>'` with `ConsistencyLevel: eventual` -- the `eq` operator IS supported, and transitive covers nested-group inheritance
- If transitive 4xx's for a group (some tenants restrict it), automatic fallback to direct `roleAssignments?$filter=principalId eq '<gid>'`
- Cache key bumped to v4 to invalidate every prior bulk-fetch result (which was always empty due to the in-clause bug)

### Progress bar

Per user request: while bulk fetch runs, popup shows a thin blue progress bar at the top of the Activate tab:

```
Fetching Entra roles... 47%
17 / 36
[==========                ]
```

Ticks per completed Entra group fetch + once when Azure RBAC ARG completes. Auto-hides 600ms after reaching 100%.

Manifest 0.4.24 -> 0.4.27.

---

## v2.4.34 -- Footer always visible; only the group list scrolls inside the popup

Previously the entire popup body scrolled, so users had to scroll past the activation footer (Justification + Duration + Activate selected) and past 30+ rows just to reach the bottom attribution footer (Developed by Morten Knudsen + Tenant id). The footer was effectively hidden on first open.

Fix: `body { display:flex; flex-direction:column; height:600px; }` + `#list { flex:1; overflow-y:auto; }`. Now:
- Header bar pinned at top (blue brand banner).
- Tab strip + filter + status pinned just below header.
- Group list scrolls inside its own area only.
- Activate / Justification / Duration controls pinned just above the footer.
- "Developed by Morten Knudsen ... Tenant: ..." footer always visible at the bottom.

Used `:not([hidden])` selectors on `#panel-activate` / `#panel-myaccess` so the `hidden` attribute (used to swap tabs) still suppresses display correctly despite the new `display:flex` rule.

Manifest 0.4.23 -> 0.4.24.

---

## v2.4.33 -- Role preview now covers nested groups (transitiveRoleAssignments) -- "fold out the underlying permissions linked to the group"

Activate + My Access tab role preview now uses `transitiveRoleAssignments` in addition to direct `roleAssignments`. If Group A is a MEMBER of Group B and Group B has the Entra role, activating Group A still gets the role -- and the popup now surfaces that nested chain inline.

Implementation:
- For each chunk of up to 15 group ids, fire BOTH endpoints in parallel:
  - `GET /roleManagement/directory/transitiveRoleAssignments?$count=true&$filter=principalId in (...)` with `ConsistencyLevel: eventual` (Graph requires both for transitive queries).
  - `GET /roleManagement/directory/roleAssignments?$filter=principalId in (...)` as a fallback (transitive can be flaky in some tenants).
- Dedupe by `(principalId, roleDefinitionId, directoryScopeId)` -- the same role assignment shows up in both endpoints; we don't render it twice.

Tested for the App Admin / User Admin groups in the maintainer tenant -- direct only returned 1-2 rows; transitive picks up the nested-group inheritances as well.

Caveat: `transitiveRoleAssignments` returns ALL effective assignments (including direct). When transitive succeeds, the direct fallback is redundant; cost is one extra HTTP round-trip per chunk (parallel, so doesn't slow down the user). If transitive 4xx's, the direct fallback still populates the preview.

Manifest 0.4.22 -> 0.4.23.

---

## v2.4.32 -- Popup width 800 -> 720; no more horizontal scrollbar by default

Reduced width from 800px to 720px so the popup fits comfortably inside Chromium's effective popup max (the textarea resize handle + scrollbar were pushing 800px-wide content past the popup's available width, triggering a horizontal scrollbar at the bottom). Plus belt-and-braces:

```css
*, *::before, *::after { box-sizing:border-box; max-width:100%; }
```

means every element is bounded to its parent's width regardless of content. `textarea` resize locked to `vertical` only so the user-drag handle can't widen it.

Visible result: no horizontal scrollbar in default state.

Manifest 0.4.21 -> 0.4.22.

---

## v2.4.31 -- Self-deactivate (single + bulk) on My Access + blue popup frame + horizontal-scroll fix

Three feature/UX additions:

### A. Self-deactivate active memberships (single and bulk)

Each row on the My Access tab now has a red "Deactivate" button to the right of the group name. Click -> confirm prompt -> the popup calls `assignmentScheduleRequests` with `action: 'selfDeactivate'` -> the membership is dropped immediately (well before its scheduled expiry). The user can always do this for their OWN memberships -- no admin role required, because it's a "self" action (principalId on the request body must match the signed-in user).

Multi-select bulk:
- New checkbox to the left of each row
- New toolbar: **all** / **none** quick-pickers + **Deactivate selected (N)** button
- Bulk handler iterates sequentially with confirm prompt listing all picked groups, marks each row's status individually, refreshes the tab after success

For shared admin accounts that activate 5+ groups every morning and want to wipe everything at end-of-day, this is one click instead of N.

### B. Blue frame around the popup

Chromium popups blend into white pages behind them, making it hard to tell where the popup ends and the page begins. v2.4.31 adds `border: 2px solid #0969da` (the GitHub blue accent we already use for active tab + group names) around the body. Distinct without being loud.

### C. Horizontal scroll fix

v0.4.14+ added role preview lines under each Activate row. Some scopes contain long unbreakable strings (`/subscriptions/<guid>/resourceGroups/<long-name>`) that pushed the row width past 800px, triggering a horizontal scrollbar in Chrome/Edge popup. Fix: `overflow-x: hidden` on the popup body + `overflow-wrap: anywhere; word-break: break-word` on the role-line divs so long tokens break inside instead of overflowing.

### D. Header banner restyled + attribution footer

- Title is now UPPERCASE bold ("PIM ACTIVATOR") at 17px with 0.5px letter-spacing.
- Header bar uses blue background (`#0969da`) with white text + translucent white sign-out button -- distinct brand strip vs the white content area below.
- Discreet footer at the bottom: "Developed by **Morten Knudsen** · part of [PIM4EntraPS](https://github.com/KnudsenMorten/PIM4EntraPS)" (link opens in a new tab).
- Translucent white version-badge sits next to the title; same info, no longer competing for attention.

Manifest 0.4.17 -> 0.4.20 (four patch bumps in the dev-helper auto-bump path).

---

## v2.4.30 -- Drop "(M365)" label; bump bulk-cache key; inline "Loading roles..." while bulk fetch runs

Three small fixes:

1. **Section headers**: "Entra (M365) roles" -> "Entra roles" everywhere. M365 was redundant.
2. **Bulk cache key bumped**: `bulkRoles_` -> `bulkRoles_v2_`. v0.4.14's SyntaxError may have left empty/partial data behind under the old key; bumping invalidates all caches so fresh bulk fetch runs immediately. (One-time cost for existing users.)
3. **Inline "Loading roles..." placeholder**: each Activate row shows a faint italic "Loading roles..." while bulk fetch is in progress, so the user can tell "background fetch happening" vs "this group has no roles". Disappears as soon as the per-row data lands.

v2.4.31 will add `roleEligibilityScheduleInstances` bulk fetch (for groups granting PIM-eligible roles) + `transitiveRoleAssignments` (for nested groups where Group A is a member of Group B and Group B has the roles).

Manifest 0.4.15 -> 0.4.17 (one extra patch bump in the dev-helper's auto-bump path).

---

## v2.4.29 -- HOTFIX: duplicate `const groupIds` in loadMyAccessTab broke the entire popup ("just says loading..., nothing happens")

v2.4.28 refactor to bulk role fetch declared `const groupIds` twice in the same function scope -- once at the top (`groupIds = [...new Set(instances.map(...))]`) and again in the new bulk-fetch block (`groupIds = rows.map(...)`). Result: `SyntaxError: Identifier 'groupIds' has already been declared` at parse time, popup.js never loads, popup hangs forever on the "Loading your PIM delegations ..." status line. Verified via `node --input-type=module --check`.

Fix: drop the redeclaration; reuse the existing `groupIds`. Same data (rows are built 1:1 from instances).

Added syntax-check step to the dev-loop helper (mental note) so future popup.js edits get caught before pack instead of after deploy.

Manifest 0.4.14 -> 0.4.15.

---

## v2.4.28 -- BIG perf overhaul: bulk role fetch + Azure Resource Graph + parallel rendering on BOTH tabs

End-user-visible: popup is much faster + role lines now appear under every eligible row on the Activate tab (not just My Access).

### What changed under the hood

Old (v2.4.27 and earlier, My Access only):
- For each active group: 1 Graph call for Entra roles + 1 ARM call per subscription for Azure roles
- Sequential per group; 15 groups = 30+ HTTP requests, 5-10 seconds
- Activate tab showed no role info at all (would have been even worse)

New (v2.4.28, both tabs):
- ONE Graph call with `$filter=principalId in (g1,g2,...)` per chunk of 15 group ids -- parallel via `Promise.all` -- typically 2-3 total Graph calls for 50 groups
- ONE Azure Resource Graph KQL query against `authorizationresources` joined with `roledefinitions` -- returns Entra-scope role assignments + role names across ALL visible subscriptions in a single ARM call
- Cached in `chrome.storage.local` with 1-hour TTL keyed by signed-in user -- cache hits render with zero network calls
- Entra + Azure fetches fire in PARALLEL; popup re-renders each set as it arrives so user sees Entra rows first (Graph is fast) and Azure rows seconds later (ARG slightly slower)
- Same path on both tabs: My Access reuses `bulkLoadEntraRolesForGroups` / `bulkLoadAzureRolesForGroups`, no more sequential per-group loops

### Why Azure Resource Graph (ARG)

ARG (`POST https://management.azure.com/providers/Microsoft.ResourceGraph/resources`) accepts a KQL query that joins `authorizationresources` (all role assignments visible to caller across all subs) with the same table filtered to `roledefinitions` (role names) and returns just the rows we want. No per-subscription iteration, no per-role lookup. Replaces v2.4.22's "iterate subscriptions, fetch roleAssignments per sub, then fetch each roleDefinition" with one POST.

### Activate tab now shows role preview per row

Under each eligible row's "ends X" line, up to 5 Entra and 5 Azure roles appear as `↳ Entra: <RoleName> <scope>` and `↳ Azure RBAC: <RoleName> at <scope>`. Anything beyond 5 collapses to `↳ +N more`. Lets the user see what an activation would grant BEFORE clicking the checkbox.

### Threading note

JavaScript in extensions is single-threaded but `fetch()` is fully async I/O. Promise.all over chunks gives effectively concurrent I/O without Web Workers. Web Workers would only help with CPU-bound work (we don't have that).

Manifest 0.4.13 -> 0.4.14. No new permissions.

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

