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
- **No tenant config push** — each browser profile signs in once via the in-popup wizard

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
│    -> on-screen wizard: type work email -> sign in once -> tenant    │
│       + app reg auto-discovered -> Save -> ready to activate         │
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
| `Deploy-PimActivatorClient.ps1`  | Endpoint admin | Per-machine or per-fleet — push `ExtensionInstallForcelist` so the extension auto-installs |
| `Update-PimActivator-Extension.ps1` | Extension maintainer | Dev loop — pack new CRX, push to `gh-pages`, flush local browser |
| `Test-PimActivatorFlow.ps1`      | QA / smoke test | Headless verification of the end-to-end activation path |

Files that USE to exist but have been removed in v1.2.0+ (config now lives
in the browser profile, not in the Windows registry):
`config.js`, `config.template.js`, `managed_schema.json`, `admx/`,
`Setup-PimActivator.ps1`, `Deploy-PimActivatorIntune.ps1`,
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
| Microsoft Graph | `Application.Read.All` | Onboarding wizard — discover the per-tenant app reg by display name |
| Azure Service Management | `user_impersonation` | Mint ARM token for Azure RBAC eligibility + activation |

Script prints the resulting `tenantId` + `clientId`. You only need them if
you want to pre-fill the onboarding wizard for users; otherwise the wizard
discovers them automatically.

---

## `Deploy-PimActivatorClient.ps1` — force-install on user machines

Writes the `ExtensionInstallForcelist` Chromium enterprise policy so the
browser auto-installs the extension on next launch. Designed for unattended
rollout via Intune / GPO / Configuration Manager.

Both the extension id and the update URL are pre-baked into the script
(since v2.4.57) — vanilla invocation Just Works:

```powershell
# Dev box, current user only, no admin required (default):
.\Deploy-PimActivatorClient.ps1

# Per-machine (HKLM) on an isolated test machine or un-managed server
# (admin required; do NOT use on Intune-managed devices -- HKLM conflicts
# with Intune-pushed ExtensionInstallForcelist):
.\Deploy-PimActivatorClient.ps1 -Scope Machine

# Edge only (skip Chrome):
.\Deploy-PimActivatorClient.ps1 -Browser Edge

# Uninstall (removes the forcelist entry):
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
| `-Scope` | `User` (HKCU) | `Machine` for un-managed servers / kiosk boxes |
| `-Browser` | `Both` | `Edge` or `Chrome` to skip the other |

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
the **onboarding wizard** appears:

1. **Welcome card** — *Let's set this up.*
2. **Email field** — user types their work email (e.g.
   `admin@contoso.com`). Used solely to look up the tenant id via
   Microsoft's OpenID Connect discovery (`/{domain}/.well-known/openid-configuration`).
3. **Sign in to auto-discover** — opens a normal Microsoft sign-in window
   against the tenant-specific authorize endpoint. The sign-in flow runs
   in the extension's MV3 service worker so it survives the popup losing
   focus.
4. **App registration auto-detected** — the extension queries Graph
   `/applications?$filter=startswith(displayName,'PIM Activator')` and
   pre-fills the client id. If multiple app regs match, a picker appears.
5. **Defaults pre-filled** — Justification: *Change in infrastructure*,
   Duration: *8h*. Editable.
6. **Save and continue** — values persist to `chrome.storage.local` for
   this browser profile.

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
│Deploy-PimActivatorClient │ -------------------------> ExtensionInstallForcelist
│       .ps1               │                            policy in HKCU / HKLM
└──────────────────────────┘                                |
                                                            v
                                                    Edge / Chrome auto-installs
                                                    extension on next launch

┌──────────────────────────┐   one-time per browser profile
│  In-popup onboarding     │ -------------------------> chrome.storage.local
│  wizard (popup.js +      │                            (this browser profile only)
│  background.js)          │
└──────────────────────────┘                                |
                                                            v
                                                    popup.js reads tenantId +
                                                    clientId + defaults from
                                                    chrome.storage.local on
                                                    every popup open
```

No registry-backed Group Policy / Intune managed-storage push is involved
in the runtime config — every browser profile holds its own tenant id +
client id locally. This is intentional for the MSP scenario where one
Windows user has many Edge profiles each signed in to a different
customer tenant.

---

## Files in this folder

| File | Type | Purpose |
|---|---|---|
| `manifest.json`   | extension | MV3 manifest (version, permissions, service-worker registration) |
| `popup.html`      | extension | Popup UI (Activate tab, My Access tab, onboarding wizard) |
| `popup.js`        | extension | Popup logic (sign-in, list, activate, deactivate, render) |
| `background.js`   | extension | MV3 service worker (onboarding sign-in flow that survives popup death) |
| `icons/`          | extension | 16/32/128 px toolbar icons |
| `extension-identity.txt` | extension | Public key + deterministic extension id |
| `Deploy-PimActivatorBackend.ps1`     | tenant setup | App reg + admin consent |
| `Deploy-PimActivatorClient.ps1`      | endpoint setup | ExtensionInstallForcelist policy |
| `Update-PimActivator-Extension.ps1`  | maintainer dev loop | Pack + push CRX, flush local browser |
| `Test-PimActivatorFlow.ps1`          | QA | Smoke-test the activation path |
| `README.md`       | docs | This file |
