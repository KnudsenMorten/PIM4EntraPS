# Release notes for PIM4EntraPS

## v2.1.1

Latest 30 commits touching SOLUTIONS/PIM4EntraPS/ in the upstream monorepo monorepo:

- release: PIM4EntraPS v2.1.1 - rename pim-mapper -> pim-manager (does more than map) + field-by-field UX audit spec + wizard scaffolding (42fe18e1)
- release: PIM4EntraPS v2.1.0 - MSP variant + AccountStatus kill-switch with CISO-controlled per-admin KV codes (d1979fe8)
- release: PIM4EntraPS v2.0.0 - full PIM v2 framework: engine modernization + Mapper (graph viewer + grid editor + save) + Activator (Edge extension + Intune install) + one-shot engine SPN installer + 18-section DESIGN.md + README rewrite (0118ecf8)
- release: PIM4EntraPS v1.0.2 - SI launcher naming alignment + fix internal-azure leak in publish workflow + rewire engine path resolution for new engine/<task>/ layout (2ff8ebb1)
- release: PIM4EntraPS v1.0.1 - hotfix: 14 .locked.csv data files were silently ignored by monorepo .gitignore (SOLUTIONS/**/config/* rule had no exception for *.locked.*) and missing from v1.0.0 public mirror (0fe0d6d5)
- release: PIM4EntraPS v1.0.0 - restructure to SecurityInsight conventions + .locked/.custom split + customer naming/filter extension points + generic Build-PimContext helper (additive, no engine rewire yet) (12616959)
- port: v1 -> v2 on 14 user-selected solutions (67 engines) (fbe39214)
- rename: SOLUTIONS/PlatformOnboarding -> SOLUTIONS/PlatformConfiguration (368f422e)
- Merge remote-tracking branch 'origin/dev' into HEAD (b8556ec1)
- launchers: fix 4 template bugs preventing internal-vm engine invocation (de585260)
- move Update-Platform.ps1 into SOLUTIONS/PlatformOnboarding/INTERNAL/ (b4a46912)
- chore: standardize PS headers, port Setup-CSA, INTERNAL tooling, README (a060047e)
- feat: portable launcher paths + bundled dependencies in published releases (ccb4b679)
- chore: strip 'AutomateIT' branding from user-facing launcher + doc content (653bac5f)
- rename: TestVariables -> LauncherConfig across the repo (b60390f0)
- restructure: Phase 4a -- launcher renames legacy->vm, cloud->azure (64578bad)
- restructure: Phase 3 -- discovery-based publish workflow + solution.publish.json (f612c18e)
- restructure: Phase 2 -- rewrite all path references to SOLUTIONS layout (d62d155a)
- restructure: Phase 1 -- mechanical move to SOLUTIONS/<X>/<TYPE>/ (3557ece1)

---

# Release notes -- PIM4EntraPS

> **Curated changelog.** The publish workflow auto-prepends recent monorepo commits as a raw activity log; this file is the human-friendly narrative on top.

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

