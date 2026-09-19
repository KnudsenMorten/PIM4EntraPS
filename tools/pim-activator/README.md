# PIM Activator (browser extension)

Companion **Manifest V3** browser extension to the **PIM4EntraPS** PowerShell
module — bulk-activate every PIM assignment you're eligible for from a single
toolbar popup, instead of clicking through the Entra portal one role at a
time.

- Works in **Microsoft Edge** and **Google Chrome** (both Chromium MV3)
- Activates **all four PIM surfaces**:
  - Direct Entra role assignments
  - Direct Azure RBAC role assignments
  - PIM for Groups → Entra role grants
  - PIM for Groups → Azure RBAC grants
  - PIM for Groups → workload RBAC delegations (Defender XDR, Intune, Power BI workspaces, custom apps)
- ★ **Favorites** — star the rows you click daily; they pin to the top of every section
- **My Access** tab — see what's active right now, one-click deactivate
- **Tenant catalog** pushed centrally (Intune / GPO / registry policy) or imported per browser profile
- **Sign-in is kept for the browser session only** — tokens live in `chrome.storage.session` (memory), never on disk
- **Talks only to** `login.microsoftonline.com`, `graph.microsoft.com`, `management.azure.com` and the update feed — those are its only host permissions

Published CRX is auto-updated from
`https://knudsenmorten.github.io/PIM4EntraPS/updates.xml`.
Deterministic extension id: `eheocihmlppcophaeakmdenhgcookkab`.

---

## Quick start

```
┌──────────────────────────────────────────────────────────────────────┐
│ 1. Tenant admin (once per tenant): run Deploy-PimActivatorBackend.ps1│
│    -> creates the PIM Activator Entra app reg + grants admin consent │
│                                                                      │
│ 2. Per machine: run Deploy-PimActivatorClient.ps1                    │
│    -> writes the ExtensionInstallForcelist HKCU/HKLM policy so the   │
│       browser auto-installs the extension on next launch             │
│                                                                      │
│ 3. Per browser profile (the user, first popup open):                 │
│    -> setup wizard: use the centrally deployed catalog, import a     │
│       JSON catalog, or type tenant id + client id -> sign in -> go   │
└──────────────────────────────────────────────────────────────────────┘
```

After step 3 a typical activation is **3 clicks**: open popup, tick the
groups/roles you want, click **Activate selected**. The first activation
of a starred row drops to **1 click** on subsequent days because favorites
sit at the top and the last-used justification + duration are remembered.

---

## Scripts in this folder

| Script | Audience | Purpose |
|---|---|---|
| `Deploy-PimActivatorBackend.ps1` | Tenant admin | One-time per tenant — create the Entra app reg + grant delegated permissions |
| `Deploy-PimActivatorClient.ps1`  | Endpoint admin | Per machine — write the force-install policies + the tenant catalog into HKLM / HKCU |
| `Deploy-PimActivatorIntune.ps1`  | Endpoint admin | Intune — the same client policies + tenant catalog as a configuration profile (ADMX-backed) |
| `Deploy-PimActivatorHybrid.ps1`  | Endpoint admin | Without Intune — the same client policies as a domain GPO, local machine policy, or a JSON artifact |
| `Update-PimActivator-Extension.ps1` | Extension maintainer | Dev loop — pack new CRX, push to `gh-pages`, flush local browser |
| `Test-PimActivatorFlow.ps1`      | QA / smoke test | Headless verification of the end-to-end activation path |

The tenant catalog reaches the extension through `chrome.storage.managed`
(`managed-schema.json` documents the keys; `intune/` holds the ADMX/ADML the
Intune profile uses), or is imported / typed per browser profile in the setup
wizard. Removed long ago and not coming back: `config.js`,
`config.template.js`, `Setup-PimActivator.ps1`,
`Set-PimActivatorPolicy-Intune.ps1`, `Deploy-PimActivatorPolicy-Admx.ps1`.

---

## `Deploy-PimActivatorBackend.ps1` — tenant app registration

Run once per Entra tenant, signed in as a user who can create app
registrations and grant admin consent (Application Administrator + Cloud
Application Administrator, or Global Administrator).

All parameters have sensible defaults — the **zero-arg invocation** creates
the `PIM Activator` app reg with the canonical extension id and tenant-wide
admin consent already granted:

```powershell
# Zero-arg -- creates "PIM Activator" app reg + grants admin consent:
.\Deploy-PimActivatorBackend.ps1

# Custom display name:
.\Deploy-PimActivatorBackend.ps1 -DisplayName 'PIM Activator (prod)'

# Different extension id (only if you've forked the extension under your
# own signing key -- never needed for the upstream distribution):
.\Deploy-PimActivatorBackend.ps1 -ExtensionId 'abcdefghijklmnopabcdefghijklmnop'

# Skip admin consent (rare -- e.g. caller isn't Privileged Role Admin and
# consent will land later via Enterprise apps blade):
.\Deploy-PimActivatorBackend.ps1 -GrantConsent:$false
```

Defaults wired into the script (since v2.4.57 / v2.4.58):

| Parameter | Default | Override when |
|---|---|---|
| `-ExtensionId` | `eheocihmlppcophaeakmdenhgcookkab` | Only if forking the extension under a different key |
| `-Channel` | `Released` | `Both` also registers the TEST build's redirect URIs — internal/dev tenant only, never a customer tenant (the app holds tenant-wide `RoleManagement.ReadWrite.Directory` consent) |
| `-DisplayName` | `PIM Activator` | You want a per-env suffix (prod / staging / etc.) |
| `-GrantConsent` | `$true` | Pass `:$false` to skip tenant-wide consent |
| `-TenantId` | Active `Get-MgContext` tenant | Cross-check guard if you want a hard-fail on wrong tenant |

What it does:

1. Resolves the IDs of the required delegated permissions on Microsoft Graph
   + Azure Service Management.
2. Creates the app reg (or updates the existing one with the same display
   name) with SPA redirect URIs `https://<ext-id>.chromiumapp.org/` and
   `chrome-extension://<ext-id>/`.
3. Creates the Enterprise Application (service principal) in your tenant.
4. When `-GrantConsent` is on (default), writes the tenant-wide OAuth2
   grants so users do not see consent prompts at first sign-in.

Required delegated permissions (auto-resolved + auto-consented by `-GrantConsent`):

| API | Permission | Purpose |
|---|---|---|
| Microsoft Graph | `PrivilegedAccess.ReadWrite.AzureADGroup` | Activate / deactivate PIM-for-Groups memberships |
| Microsoft Graph | `Group.Read.All` | List + name eligible groups |
| Microsoft Graph | `User.Read` | id_token claims (signed-in user) |
| Microsoft Graph | `RoleManagement.Read.Directory` | My Access — resolve Entra role assignments per group |
| Microsoft Graph | `RoleManagement.ReadWrite.Directory` | Activate / deactivate direct Entra role assignments |
| Microsoft Graph | `AdministrativeUnit.Read.All` | My Access — resolve AU displayNames |
| Microsoft Graph | `Application.Read.All` | Still registered + consented by the script, but NOT used by the current popup (it served the retired auto-discover wizard) |
| Azure Service Management | `user_impersonation` | Mint ARM token for Azure RBAC eligibility + activation |

Script prints the resulting `tenantId` + `clientId` — the pair that goes into
the tenant catalog (the client deploy scripts can also look the app up by its
exact display name, or take `-ClientId`).

---

## `Deploy-PimActivatorClient.ps1` — force-install on user machines

Writes the Chromium enterprise policies (`ExtensionInstallForcelist`,
`ExtensionInstallSources`, `ExtensionSettings`) plus the tenant catalog so the
browser auto-installs the extension on next launch. Designed for unattended
rollout via GPO / Configuration Manager (use `Deploy-PimActivatorIntune.ps1` on
Intune-managed devices).

**Your organisation's own extension policies are never overwritten.** Our
forcelist / sources rows go into the slot that already holds our extension id,
otherwise the lowest free slot; our `ExtensionSettings` entry is merged into the
existing dictionary (the `'*'` defaults and every other extension's entry are
kept). An `ExtensionSettings` value that is not valid JSON stops the run before
anything is written. `Deploy-PimActivatorHybrid.ps1 -Target LocalGpo` uses the
same code (`_PimActivatorHybridPolicy.ps1`, which must sit next to the script).

Both the extension id and the update URL are pre-baked into the script
(since v2.4.57) — vanilla invocation Just Works:

```powershell
# Per-machine (HKLM, admin required) -- the default:
.\Deploy-PimActivatorClient.ps1

# Current user only (HKCU, no admin):
.\Deploy-PimActivatorClient.ps1 -Scope User

# Edge only (skip Chrome):
.\Deploy-PimActivatorClient.ps1 -Browser Edge

# Pick the app registration explicitly (else: the one app named exactly 'PIM Activator'):
.\Deploy-PimActivatorClient.ps1 -ClientId '00000000-0000-0000-0000-000000000000'

# Uninstall (removes ONLY our rows + our ExtensionSettings entry + our catalog):
.\Deploy-PimActivatorClient.ps1 -Uninstall

# Forked the extension under your own key + own gh-pages mirror:
.\Deploy-PimActivatorClient.ps1 `
    -ExtensionId 'abcdefghijklmnopabcdefghijklmnop' `
    -UpdateUrl   'https://your-fork.example.com/updates.xml'
```

Defaults wired into the script:

| Parameter | Default | Override when |
|---|---|---|
| `-ExtensionId` | `eheocihmlppcophaeakmdenhgcookkab` | Forking under a different signing key |
| `-UpdateUrl` | `https://knudsenmorten.github.io/PIM4EntraPS/updates.xml` | Self-hosting your own CRX mirror |
| `-Scope` | `Machine` (HKLM) | `User` (HKCU) for a single user without admin rights |
| `-Channel` | `Released` | `Test` for the side-by-side TEST build (internal only) |
| `-Browser` | `Both` | `Edge` or `Chrome` to skip the other |

### Override the org's activation defaults at deploy time (all deploy paths)

The popup pre-fills the Activate form's **justification** and **activation
length** from the managed tenant catalog. An MSP can set the org's defaults at
deploy time — opt-in, on **every** tenant entry written — with two parameters
that work the same way on **all three** deploy scripts
(`Deploy-PimActivatorClient.ps1`, `Deploy-PimActivatorHybrid.ps1`,
`Deploy-PimActivatorIntune.ps1`):

| Parameter | Effect |
|---|---|
| `-DefaultJustification <text>` | Overwrites `defaultJustification` on every tenant entry written |
| `-DefaultDurationHours <1..24>` | Overwrites `defaultDurationHours` (whole hours) on every tenant entry |

Both are **additive + opt-in**: omit them and each tenant entry keeps its own
value (from the catalog file or the auto-discover fallback). When supplied, the
override is applied to **every** tenant in the catalog — including all up-to-25
tenants in a multi-tenant Hybrid UNC config — and the script prints the override
it applied.

```powershell
# Set the org default justification + 4h activation length across every tenant:
.\Deploy-PimActivatorHybrid.ps1 -ConfigUncPath \\fs01\pim\tenants.json -Target LocalGpo `
    -DefaultJustification 'Approved change / incident work' -DefaultDurationHours 4

.\Deploy-PimActivatorIntune.ps1 -CatalogJsonPath .\catalog.json `
    -DefaultJustification 'Approved change / incident work' -DefaultDurationHours 4
```

### Intune managed-policy equivalent (no script)

Microsoft Edge → **Configuration profile** → **Settings catalog** →
**Extensions** → **Configure which extensions are installed silently**.
Add a single entry:

```
eheocihmlppcophaeakmdenhgcookkab;https://knudsenmorten.github.io/PIM4EntraPS/updates.xml
```

Same effect as running `Deploy-PimActivatorClient.ps1 -Scope Machine`
fleet-wide.

---

## First-run user experience

On the **first** time a user opens the popup in a given browser profile,
the **setup wizard** offers three ways to configure it:

1. **Use centrally deployed** — the tenant catalog pushed by Intune / GPO /
   the client deploy scripts (`chrome.storage.managed.tenantCatalog`). With
   several tenants a picker appears.
2. **Import JSON catalog** — paste a JSON array of tenants (MSP / multi-tenant).
3. **Add single tenant** — type the tenant id + the PIM Activator app's client id.

The user then signs in with a normal Microsoft sign-in window
(`chrome.identity.launchWebAuthFlow` + PKCE, run from the popup). The chosen
catalog / tenant and the user's preferences persist in `chrome.storage.local`
for this browser profile; the **sign-in tokens are kept in
`chrome.storage.session` only** — in memory, cleared when the browser closes —
so the user signs in once per browser session. (Versions before this change
kept the tokens in `chrome.storage.local`; the first popup open of the new
version deletes them from there.)

From then on, the popup boots straight to the **Activate** tab.

The footer of every popup shows the configured tenant id and a `(reset)`
link that wipes the per-profile config so the wizard can be re-run (useful
when migrating profiles between tenants).

---

## Activate tab

```
+-----------------------------------+
| Activate (53)   My Access         |
| -------------------------------- |
|  ★ Favorites                  (2) |
|  ☐ ★ Global Reader   ↳ Entra: ... |
|  ☐ ★ PIM-Helpdesk-L1              |
| ================================= |
|  Entra roles (direct)         (4) |
|  ☐ ☆ Application Administrator    |
|  ...                              |
|  Azure RBAC (direct)          (2) |
|  Entra roles (via PIM Group) (37) |
|  Azure RBAC (via PIM Group)   (2) |
|  PIM for Groups (workload)    (8) |
| -------------------------------- |
| Justification: Change in infra... |
| Duration:      8                  |
|              [Activate selected]  |
+-----------------------------------+
```

- Star (★ / ☆) any row to **favorite** it; favorites pin to the very top
  across every category. Persisted per browser profile.
- **Multi-select** with checkboxes; **Activate selected** dispatches one
  request per ticked row, with status pills updating live.
- Recency / frequency sort keeps yesterday's clicks within easy reach
  even if you haven't starred them.

## My Access tab

Shows everything currently active for the signed-in user, in the same
5-section layout (plus the ★ Favorites section at top). Per-row
**Deactivate** button — drops the assignment early; bulk **Deactivate
selected** in the toolbar for multi-row teardown.

---

## `Update-PimActivator-Extension.ps1` — maintainer dev loop

Maintainer-only — repacks the CRX, pushes it to the `gh-pages` branch of
the PIM4EntraPS repo, and flushes the local Edge cache so the next popup
open downloads the fresh build.

```powershell
# Just flush the local browser (gh-pages is already up-to-date):
.\Update-PimActivator-Extension.ps1

# Bump patch version, repack, push to gh-pages, flush local browser:
.\Update-PimActivator-Extension.ps1 -Repack

# Pin an exact version (e.g. milestone release):
.\Update-PimActivator-Extension.ps1 -Repack -Version 1.5.0

# CI / unattended: pack + push gh-pages, don't touch the running browser:
.\Update-PimActivator-Extension.ps1 -PackOnly
```

Safety rails on the flush:

- **Signing-key gate** — before any browser is closed, the CRX each flushed id
  would re-download is fetched and its id derived; a mismatch **or a check that
  cannot run** aborts the flush (evicting the cached binary behind a wrong-key
  CRX bricks the installed extension). `-SkipCrxKeyCheck` overrides the
  "could not verify" case only.
- **Extension storage is kept** — `Local Extension Settings\<id>` (the
  extension's saved catalog + preferences) is no longer deleted;
  `-DangerouslyWipeExtensionStorage` opts in for a broken profile.
- **Local State is backed up** before Edge is closed for `-Repack` / the flush,
  and restored if the profile list regressed.

Prereqs (one-time per dev box):

- Edge installed (used as the CRX packer via `msedge.exe --pack-extension`).
- The signing key at `%USERPROFILE%\.pim-activator\signing-key.pem` (generated
  the first time `Edge` packs the extension; commit-protected, do NOT share).
- Git access to the `gh-pages` branch of `KnudsenMorten/PIM4EntraPS`.

---

## `Test-PimActivatorFlow.ps1` — smoke test

Headless verification of the end-to-end activation path. Useful in CI to
catch regressions in the Graph + ARM contracts before publishing a CRX.

```powershell
.\Test-PimActivatorFlow.ps1 -TenantId '<guid>' -ClientId '<guid>'
```

---

## Architecture / how config flows

```
┌──────────────────────────┐   one-time per tenant
│Deploy-PimActivatorBackend│ -------------------------> Entra app reg
│       .ps1               │                            + admin consent
└──────────────────────────┘

┌──────────────────────────┐   one-time per machine / fleet
│Deploy-PimActivatorClient │ -------------------------> force-install policies
│ / -Intune / -Hybrid .ps1 │                            + tenantCatalog (managed
└──────────────────────────┘                            storage) in HKLM / HKCU
                                                            |
                                                            v
                                                    Edge / Chrome auto-installs
                                                    extension on next launch

┌──────────────────────────┐   per browser profile
│  In-popup setup wizard   │ -------------------------> chrome.storage.local
│  (popup.js)              │                            catalog choice + prefs
└──────────────────────────┘                            (no secrets)
                                                            |
                                                            v
                                                    popup.js merges the managed
                                                    catalog with any local one
                                                    on every popup open; sign-in
                                                    tokens -> chrome.storage.session
                                                    (memory, this browser session)
```

The managed catalog (`chrome.storage.managed.tenantCatalog`) and a catalog
imported in the popup are merged, so an MSP admin can hold many tenants in
one browser profile and switch between them from the header.

---

## Files in this folder

| File | Type | Purpose |
|---|---|---|
| `manifest.json`   | extension | MV3 manifest (version, permissions, host permissions, service-worker registration) |
| `popup.html`      | extension | Popup UI (Activate tab, My Access tab, setup wizard) |
| `popup.js`        | extension | Popup logic (sign-in, list, activate, deactivate, render) |
| `popup-storage.js` | extension | Which key lives where: tokens -> `chrome.storage.session`, the rest -> `chrome.storage.local` |
| `popup-report.js` | extension | Scrubs ids / e-mails / tokens out of the public "Report bug" text |
| `popup-config.js`, `popup-net.js`, `version-badge.js` | extension | Pure config helpers, fetch timeouts/watchdogs, version badge |
| `background.js`   | extension | MV3 service worker — intentionally empty (sign-in runs in the popup) |
| `managed-schema.json`, `intune/` | extension / policy | Managed-storage schema + the ADMX/ADML for the tenant catalog |
| `_PimActivatorHybridPolicy.ps1` | endpoint setup | Shared slot / ExtensionSettings-merge logic of the Client + Hybrid deploys |
| `icons/`          | extension | 16/32/128 px toolbar icons |
| `extension-identity.txt` | extension | Public key + deterministic extension id |
| `Deploy-PimActivatorBackend.ps1`     | tenant setup | App reg + admin consent |
| `Deploy-PimActivatorClient.ps1`      | endpoint setup | ExtensionInstallForcelist policy |
| `Update-PimActivator-Extension.ps1`  | maintainer dev loop | Pack + push CRX, flush local browser |
| `Test-PimActivatorFlow.ps1`          | QA | Smoke-test the activation path |
| `README.md`       | docs | This file |
