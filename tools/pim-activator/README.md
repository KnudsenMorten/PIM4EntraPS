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
| `Deploy-PimActivatorHybrid.ps1`  | Endpoint admin | Without Intune — the same client policies as a domain GPO, local machine policy, or a JSON artifact |
| `intune-remediation\*.ps1` + `Publish-PimActivatorRemediation.ps1` | Endpoint admin | **Recommended for Edge.** One plain Intune Remediation pair: the extension's settings (no ADMX) + repair when a user or admin sets the RepairStuck flag; the helper uploads it to Intune. Pair them with an Edge management service policy that installs the extension. See [Deploy with the Edge management service + a Remediation](#deploy-with-the-edge-management-service--a-remediation-recommended-for-edge) |
| `Update-PimActivator-Extension.ps1` | Extension maintainer | Dev loop — pack new CRX, push to `gh-pages`, flush local browser |
| `Test-PimActivatorFlow.ps1`      | QA / smoke test | Headless verification of the end-to-end activation path |

The tenant catalog reaches the extension through `chrome.storage.managed`
(`managed-schema.json` documents the keys; on Intune-managed Edge the
Remediation in `intune-remediation\` writes them), or is imported / typed per browser profile in the setup
wizard. Removed long ago and not coming back: `config.js`,
`config.template.js`, `Setup-PimActivator.ps1`,
`Set-PimActivatorPolicy-Intune.ps1`, `Deploy-PimActivatorPolicy-Admx.ps1`,
and (2026-09-28) the ADMX/Intune-profile delivery: `Deploy-PimActivatorIntune.ps1`,
`intune/` (ADMX/ADML), `Inspect-PimActivatorAdmxProfile.ps1`,
`Get-PimActivatorTenantSettings.ps1`, `Test-PushTenantCatalog.ps1`.

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
rollout via GPO / Configuration Manager (on Intune-managed Edge use the Edge
management service + the Intune Remediation instead).

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
that work the same way on **both** deploy scripts
(`Deploy-PimActivatorClient.ps1`, `Deploy-PimActivatorHybrid.ps1`; on the Intune
Remediation, set the values in `$TenantCatalog` directly):

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

## Deploy with the Edge management service + a Remediation (recommended for Edge)

Intune configuration profiles do not merge: when global IT force-installs some extensions and a department
force-installs others, the same setting sits in two profiles, Intune reports a conflict and only one list applies.
The Microsoft Edge management service (Microsoft 365 admin center → Settings → Microsoft Edge) holds the install
instead, as a cloud policy per group, and a small script delivers the extension's own settings. No ADMX is imported,
so a new setting in a later extension version needs no re-import.

### Prerequisites — two settings in the Edge management service policy

The extension is installed by the Microsoft Edge management service with a **Cloud** configuration policy assigned to
the user group. It needs these two settings — without them the extension is not installed, or an old copy never updates.

> **One policy per AUDIENCE, not per channel.** The Edge management service does **not merge** the extension list
> across policies: when a user gets two policies that both force-install extensions, only the highest-priority policy's
> list applies (observed 2026-09-30: with separate "PROD" and "TEST" policies only the production Activator installed).
> So, when test users should get both channels and everyone else only production:
> - a policy with **both** entries (released + test), assigned to the **test users only**, at the **higher** priority;
> - a policy with the **released** entry only, assigned to everyone, at a lower priority.
>
> Test users then get "PIM Activator" and "PIM Activator (TEST)" side by side (they have different ids and names);
> everyone else gets production only. A tenant-wide policy that also force-installs extensions (e.g. "Global
> Extensions") must either carry the Activator entries too or not set that list, or it replaces them for everyone.

| # | Where in the policy | Setting | Value |
|---|---|---|---|
| 1 | **Settings** → Add setting | **ExtensionInstallSources** ("Configure extension and user script install sources") | `https://knudsenmorten.github.io/*` |
| 2 | **Managed extensions** → Add extension → *External extension* → the extension id → select it (the "Manage extension" dialog) | **Installation setting** | **Force** |
|   |   | **Update URL** | the channel's update URL (table below) |
|   |   | **Use this update URL for all extension updates** | ticked (this is `override_update_url`) |
|   |   | **Minimum version** | `1.6.126` |

| Channel | Extension id | Update URL |
|---|---|---|
| Released (PROD) | `eheocihmlppcophaeakmdenhgcookkab` | `https://knudsenmorten.github.io/PIM4EntraPS/updates.xml` |
| Test | `glldnbmjpdkjemcnficagdhgienfdpoo` | `https://knudsenmorten.github.io/PIM4EntraPS/updates-test.xml` |

Why each one:
- **ExtensionInstallSources** — the extension is self-hosted (not in a store), so its download location must be an
  allowed install source.
- **Force + update URL** — installs the extension and keeps it installed.
- **Use this update URL for all extension updates** — Edge also *updates* the extension from that URL. Versions before
  1.6.126 carry no update address of their own and stay stuck on their version without it.
- **Minimum version 1.6.126** — an older copy is disabled until it has updated.

The same as ExtensionSettings JSON (e.g. for **Import JSON** on the Managed extensions tab):
`{ "<extension id>": { "installation_mode": "force_installed", "update_url": "<update URL>", "override_update_url": true, "minimum_version_required": "1.6.126" } }`.
A device policy set by Intune or Group Policy for the same Edge setting wins over the cloud policy — do not also set
these through an Intune profile for these users.

### The Intune Remediation — settings + repair on request

`intune-remediation\Detect-PimActivator.ps1` + `Remediate-PimActivator.ps1`. **Every run** it writes the extension's
settings for **Microsoft Edge and Google Chrome** (only the extension's own registry key per browser — see
[Managed settings reference](#managed-settings-reference); it never touches the browsers themselves). **Only when
someone asks** (the registry value below) it also repairs the extension. Both scripts start with the same **SETTINGS**
block — every option is explained line by line in `Remediate-PimActivator.ps1`:

| Setting | Values | Meaning |
|---|---|---|
| `$Channel` | `'Released'` / `'Test'` | which extension (production or test id — the same id in Edge and Chrome) |
| `$Browsers` | `@('Edge', 'Chrome')` (default) / `@('Edge')` / `@('Chrome')` | which browsers get the settings (and the repair); a browser left out is not touched |
| `$TenantCatalog` | JSON list of tenants | `name`, `tenantId`, `clientId` required; optional fields in [Managed settings reference](#managed-settings-reference) |
| `$AutoActivateMaxGroups` | `$null` / `0` / `1`–`100` | no limit / auto-activation OFF / at most N groups ticked "auto" (needs 1.6.128+) |
| `$BulkActivateConfirmThreshold` | `$null` / `1`–`100` | default 5 / Activate asks for a 2nd click at N roles |
| `$CloseEdge` | `$false` / `$true` | a requested repair while the browser is open: wait until it is closed / close it — covers Edge **and** Chrome (name kept for existing copies) |

**The registry value that requests a repair ("flush")**

| | |
|---|---|
| Key (user) | `HKCU\Software\PIM4EntraPS\PimActivator` — the user can set it, **no admin rights needed** |
| Key (device) | `HKLM\SOFTWARE\PIM4EntraPS\PimActivator` — an admin, for every user on the device |
| Value name | `RepairStuck` |
| Type / data | `REG_DWORD` = `1` |
| Set it | `reg add HKCU\Software\PIM4EntraPS\PimActivator /v RepairStuck /t REG_DWORD /d 1 /f` (user) — or the HKLM line as admin |
| What happens | On the next Remediation run with **the browser closed**: PIM Activator's registration is cut out of every Edge / Chrome profile's `Preferences` / `Secure Preferences` (the browsers in `$Browsers`; text only — every other byte of the file is kept; each file backed up as `<file>.bak-<date-time>`) and its program files are deleted. The browser's install policy installs the current version fresh on the next start. |
| Afterwards | The value is **deleted** automatically (in HKCU and HKLM). |
| Browser open | Nothing in the browser is changed, the value is kept, and the next run tries again (schedule the Remediation e.g. every hour) — unless `$CloseEdge = $true`. |
| The user notices | PIM Activator is reinstalled: the user signs in to it again, and its own saved data (favorites, "auto" ticks) may be gone. Bookmarks, passwords, history, other extensions and sync are not touched. |

Why text-only: on 2026-06-09 a PowerShell JSON read/re-write of `Preferences` corrupted the file under Windows
PowerShell 5.1 and Edge reset the whole profile. The repair therefore never re-serialises the file — it cuts the
extension's blocks out of the text, checks the result is still one balanced JSON object, and leaves any file it does
not recognise untouched.

**Create the Remediation.** Copy both scripts, edit the SETTINGS block **identically in both**, then in Intune →
**Devices → Scripts and remediations → Create**: detection script = `Detect-PimActivator.ps1`, remediation script =
`Remediate-PimActivator.ps1`, **Run this script using the logged-on credentials = No** (runs as SYSTEM),
**Enforce script signature check = No**, **Run script in 64-bit PowerShell = Yes**; assign it to the same group as the
Edge policy (a user group runs it on that user's devices) and schedule it — **every hour** is a good choice. One
Remediation per channel and set of values, e.g. `PIM Activator settings (PROD)` and `PIM Activator settings (TEST)`.
Edge picks up new settings on its next policy refresh; `edge://policy` → **Reload policies** shows them at once (Chrome:
`chrome://policy` → **Reload policies**). The Remediation does not install the extension in Chrome — Chrome needs its own
`ExtensionInstallForcelist` policy with the same id and update URL.

**Or upload it with `Publish-PimActivatorRemediation.ps1`** — creates the Remediation, or updates it in place when one
with the same name exists (its assignments are kept), and reads it back:

```powershell
Connect-MgGraph -Scopes DeviceManagementScripts.ReadWrite.All
.\Publish-PimActivatorRemediation.ps1 -Name 'PIM Activator settings (PROD)' `
    -DetectScript .\Detect-PimActivator-PROD.ps1 -RemediateScript .\Remediate-PimActivator-PROD.ps1 `
    -AssignToGroupId <group-id> -EveryHours 1
```

| Parameter | Required | Meaning |
|---|---|---|
| `-Name` | yes | the Remediation's name in Intune; an existing one with this exact name is updated in place |
| `-DetectScript` | yes | path to your edited `Detect-PimActivator.ps1` |
| `-RemediateScript` | yes | path to your edited `Remediate-PimActivator.ps1` |
| `-Description` | no | text shown in Intune |
| `-AssignToGroupId` | no | Entra group id (user or device group) to assign it to — **replaces** its current assignments; left out = assignments unchanged |
| `-EveryHours` | no | with `-AssignToGroupId`: run every N hours (1–23), e.g. `1` = hourly |
| `-DailyTime` | no | with `-AssignToGroupId` and no `-EveryHours`: run daily at `HH:mm` (default `09:00`) |

It always uploads with *run as SYSTEM*, *64-bit*, *no signature check*.

**Good to know.** To change a value later, edit the SETTINGS block in both scripts and upload again; a value set back
to `$null` is removed from the devices. If an older Intune profile still pushes the **Tenant catalog** settings from the
imported PIM Activator ADMX, set those to *Not configured* for these users (two writers of the same value undo each
other). Remediations need a Windows Enterprise E3/E5 (or equivalent) licence. Keep department groups that get
*different* values from overlapping — a device in two groups runs both and the last one wins.

## Managed settings reference

Everything the extension reads from policy (`chrome.storage.managed`, declared in `managed-schema.json`). On Windows
the values live under:

```
HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<extension id>\policy     (Edge)
HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<extension id>\policy      (Chrome)
```

`<extension id>` is `eheocihmlppcophaeakmdenhgcookkab` (released) or `glldnbmjpdkjemcnficagdhgienfdpoo` (test). These
keys belong to the extension alone, so they never conflict with any other extension policy.

| Value | Type | What it does | Default when not set |
|---|---|---|---|
| `tenantCatalog` | REG_SZ (JSON array) | The tenants users can sign in to — see the entry fields below. Required for a zero-setup experience; without it users run the setup wizard. | Empty: the setup wizard is shown |
| `bulkActivateConfirmThreshold` | REG_DWORD 1–100 | When a user selects at least this many roles, **Activate** asks for a second click to confirm. A per-tenant value in the catalog overrides it. | 5 |
| `autoActivateMaxGroups` | REG_DWORD 0–100 | Per-device cap on groups a user may mark **auto** (activated when the popup opens). `0` turns auto-activation off on the device; `N` allows at most N. Device policy only — never read from the catalog. | No limit |

**Tenant catalog entry fields** (one JSON object per tenant):

| Field | Required | Meaning |
|---|---|---|
| `name` | No | Display name in the tenant switcher (defaults to the tenant id). |
| `tenantId` | **Yes** | Entra tenant id (GUID). |
| `clientId` | **Yes** | Application id of the PIM Activator app registration in that tenant (GUID). |
| `defaultJustification` | No | Pre-filled justification on the Activate form (default `Change in infrastructure`). |
| `defaultDurationHours` | No | Pre-filled activation duration in hours (default 8; capped by each role's PIM policy). |
| `prefix` | No | Only list groups whose name **starts with** this text (or any of a list of texts), e.g. `"PIM-"`. |
| `entraPrefix` | No | Text (or list) that puts a group in the **Entra** section, e.g. `["PIM-Entra","PIM-AAD"]`. |
| `azurePrefix` | No | Text (or list) that puts a group in the **Azure** section, e.g. `["PIM-Azure","PIM-AzRes"]`. |
| `groupNameFilter` | No | Advanced: a regular expression instead of `prefix` (wins over it). An invalid pattern shows all groups and says so. |
| `entraGroupRegex` | No | Advanced: a regular expression instead of `entraPrefix` (default `Entra`). |
| `azureGroupRegex` | No | Advanced: a regular expression instead of `azurePrefix` (default `AzRes\|Azure`). |
| `bulkActivateConfirmThreshold` | No | Per-tenant override of the tenant-wide confirm threshold above. |

Groups that match neither the Entra nor the Azure pattern are listed under *PIM for Groups*. Example catalog with two
tenants (paste it into `$TenantCatalog` in the SETTINGS block):

```json
[
  { "name": "Contoso", "tenantId": "<tenant-guid>", "clientId": "<app-id>",
    "defaultJustification": "Approved change", "defaultDurationHours": 4, "prefix": "PIM-" },
  { "name": "Fabrikam", "tenantId": "<tenant-guid>", "clientId": "<app-id>",
    "entraPrefix": ["PIM-Entra"], "azurePrefix": ["PIM-Azure"], "bulkActivateConfirmThreshold": 10 }
]
```

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
| `managed-schema.json` | extension / policy | Managed-storage schema (the keys the Remediation / Client / Hybrid write) |
| `_PimActivatorHybridPolicy.ps1` | endpoint setup | Shared slot / ExtensionSettings-merge logic of the Client + Hybrid deploys |
| `icons/`          | extension | 16/32/128 px toolbar icons |
| `extension-identity.txt` | extension | Public key + deterministic extension id |
| `Deploy-PimActivatorBackend.ps1`     | tenant setup | App reg + admin consent |
| `Deploy-PimActivatorClient.ps1`      | endpoint setup | ExtensionInstallForcelist policy |
| `Update-PimActivator-Extension.ps1`  | maintainer dev loop | Pack + push CRX, flush local browser |
| `Test-PimActivatorFlow.ps1`          | QA | Smoke-test the activation path |
| `README.md`       | docs | This file |
