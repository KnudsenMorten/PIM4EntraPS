# PIM4EntraPS

> **Privileged-access governance for Microsoft Entra, as code.**
> Model your privileged delegation as nested groups, apply the right PIM
> policies, and keep everything in sync from a single source of truth —
> without ever standing up a public endpoint or leaving credentials lying
> around.

PIM4EntraPS turns a sprawling, click-driven PIM model into a declarative
model that an engine reads, diffs against the tenant, and applies. A
typical 30-admin / 200-permission-group tenant becomes a model that a
single engine run keeps in sync, a browser-based **PIM Manager** GUI to
edit + validate it, and a **PIM Activator** browser extension the admins
bulk-activate from.

The engine is **REST-only** (it talks directly to Microsoft's APIs — no
heavy PowerShell modules to install or keep updated) and reads its model
from **SQL** (configuration, rules and delegation profiles live in the
database, not in scattered files). It runs on a plain VM or in a
lightweight container, and never needs a public IP.

---

## Why this exists

Managing PIM at any non-trivial scale through the Entra portal is painful:

- Per-admin onboarding is **N clicks** (one per role / scope / AU).
- "Add a new permission to the Cloud Engineer role" is **M clicks** (one
  per admin who has that role).
- Drift is invisible: nobody knows what's *actually* assigned vs what was
  documented last quarter.
- Audit asks "who can do X" — answering means clicking through every PIM
  blade and Azure RBAC scope.

**PIM4EntraPS replaces the clicks with a declarative model.** The model
lives in SQL as a small set of related tables — one source of truth instead
of scattered spreadsheets:

| Table | Says |
|---|---|
| Admin definitions | Who the admin accounts are |
| Role-group definitions | What *role groups* exist (job functions) |
| Permission-group definitions (tasks / services / resources / …) | What *permission groups* exist (atomic capabilities) |
| Admin assignments | Which admins are in which role groups (eligible / active) |
| Group assignments | Which permission groups nest inside which role groups |
| Entra-role assignments | What Entra ID roles each permission group grants |
| AU-role assignments | What AU-scoped Entra roles each permission group grants |
| Azure-resource assignments | What Azure RBAC scopes each permission group grants |

Run the engine → the tenant matches the model. Edit a row → run again → the
delta is applied. History is tracked. (A CSV import path exists as a
read-only migration source for getting an existing model into SQL.)

---

## The core idea: group nesting

Don't assign Entra/Azure roles directly to admins. Assign them to
**permission groups** (atomic capabilities). Nest permission groups into
**role groups** (job functions). Assign admins to role groups via PIM:

```
Admin                 Role Group              Permission Groups               Target
(the user)            (the job function)      (atomic capability)             (Entra / Azure / AU)

Admin-ABC-ID        --E->  PIM-ROLE-           --E--> PIM-Entra-ID-              --E--> "Application Administrator"
                           CloudEngineer              AppAdmin-L1-T0-CP-ID                   (Entra ID role)
                                                --A--> PIM-AzDevOps-               --A--> "Build Administrator"
                                                       TeamsContrib-L2-T1-...                 (Azure DevOps role)
                                                --E--> PIM-AzRes-MP-               --E--> Owner on /subscriptions/{...}
                                                       Platform-L3-T1-...                     (Azure RBAC)
                                                --E--> PIM-PowerBI-WS-             --E--> Workspace contributor
                                                       ExampleWS-L4-T2-...                    (Power BI)
```

`--E->` = Eligible (PIM activation required) · `--A->` = Active (always on)

**Why nest:**

- Onboarding a new Cloud Engineer = **one** assignment, not 20.
- Refactor a permission group's targets → every role group using it gets
  the change for free.
- Removing an admin = one deletion; their entire access surface collapses.
- The graph (admin → role → permission → target) *is* the audit answer to
  *"who can do X?"* — see the **[PIM Manager](#pim-manager-gui)**.
- Entra enforces a hard cap of **500 role-assignable groups per tenant**.
  Heavy reuse of permission groups + role groups across many admins keeps
  you well under the ceiling.

See **[docs/DESIGN.md](docs/DESIGN.md)** for the full philosophy: direct
vs indirect delegation, naming convention, tier model, lifecycle states,
the as-code pattern, customer overrides.

---

## Features

The sections below summarize every delivered feature **area**. For the
full, customer-friendly catalog of what's built and verified, see
**[docs/FEATURES.md](docs/FEATURES.md)** — these chapters mirror its
structure. Items still in progress or planned are tracked in
**[docs/REQUIREMENTS.md](docs/REQUIREMENTS.md)**; per-release detail lives
in **[RELEASENOTES.md](RELEASENOTES.md)**.

### 1. Hosting / runtime
Run it where it fits you: the Manager runs centrally for the whole team, or
locally on an admin's PC straight against the database — no central web
server required. A loopback **break-glass** edition runs on a client PC for
when a hosted plan is unavailable, so senior admins are never locked out.
No public IP is ever required.

### 2. Containers
One configurable engine image runs as manager, scheduler, engine,
connector, queue worker or discovery job — you tell each instance which
roles to take on. Workers are scoped to their assigned job types, run a
single pass on demand, or preview changes without applying them. Headless
and safe by default: managed-identity auth, no interactive prompts, no
secrets baked into the image.

### 3. Setup / deploy
Repeatable, script-driven setup (container, VM and MSP variants) so every
environment comes out the same way. Managed-identity database access is
wired up passwordless automatically, and each worker identity is granted
the exact directory permissions the engine needs so it works on first run.

### 4. MSP
**Pull, never push.** In a managed-service setup the provider never reaches
into or writes to your tenant — each tenant pulls a signed baseline into
its own local database. Your data never leaves your tenant, per-tenant
isolation means no cross-customer visibility, and local IT keeps full
autonomy. (See [MSP variant](#msp-variant) below.)

### 5. SQL / data
**Single source of truth in SQL** — configuration, settings, access rules
and delegation profiles all live in the database, not in scattered files
or shares. Cloud databases use Entra/managed-identity authentication only
(no SQL logins or stored passwords); on-prem uses integrated Windows auth.
The Manager reads and writes through one database-aware layer and lets you
switch between databases from a dropdown.

### 6. Engine — core
A modern, dependency-free engine that talks directly to Microsoft's APIs
and the database. **Fast incremental runs** queue changes and apply only
what actually changed, scoped to the area you ask for (full reprocessing
still available on demand). From one run the engine creates the groups,
delegations, org-group access, time-limited access passes, admin schedules
and notification emails. Logs are clear and tagged (assign / update /
extend / remove / OK), errors name the actual resource, and Global-Admin-
style delegation is automatically configured to require approval.

### 7. Engine — providers / connectors
Connectors translate one PIM group into the right access across **Entra
roles, Azure RBAC, Power BI / Fabric, gallery enterprise apps** (SAP,
ServiceNow, etc.) and **Dataverse / Dynamics 365** — each connector turns
on its own access prerequisite. The engine covers administrative units,
groups + owners, admins + their time-limited access passes, Entra roles
and AU-scoped roles, memberships, Azure resources, group policies and
access reviews — all via direct API calls. Roles are imported from the
live service list so you pick real roles instead of risking typos.

### 9. Auth / identity
**100% direct API, no modules** — runs on a clean VM or container with
nothing pre-installed. Certificate-based app auth (not a shared secret),
defaulting to the machine certificate store. No secrets in configuration:
access uses a managed identity or a Key Vault pointer, and seed files never
carry secrets.

### 10. Delegation model
**Two-tier group nesting at the core.** Admins go into direct groups (by
role, task, process, cross-org or department) which nest into permission
groups holding the actual roles and scopes. **Everything is a group** — AUs
and Azure scopes are only the *where*, never the *who*. Every group has an
owner, resolved automatically from the assignment, sponsor, or
department-to-owner mapping. **Scoped portal admins** see only the groups
they own, with the most privileged tiers filtered out; super-admins bypass
the scoping. Cloud-only guest invite and self-service consultant
enable/disable are included.

### 11. GUI / Manager
A browser-based delegation editor — **PIM Manager** — to create, map,
delete, bulk-edit, revoke and clone delegations through a grid with guided
wizards. Role tiers (Reader / Admin / Super-Admin / Delegated) with the
right powers; the system fails closed to read-only if a role can't be
determined. (See [PIM Manager](#pim-manager-gui) below.)

### 12. Notifications / email
Built-in, template-driven email — new admin, new role, new permission and
time-limited-access-pass delivery — rendered from customizable HTML
templates with simple placeholder tokens. A lab redirect option keeps test
mail out of real inboxes, and rendering is separated from sending so you
can preview output. (See [Notifications & scheduled TAP](#notifications--scheduled-tap) below.)

### 14. Scale / performance
Built for large tenants: the solution never bulk-lists hundreds of
thousands of users or groups — it looks users up on demand and queries only
the PIM-managed groups by name prefix server-side, so context builds in
seconds. Tenant-wide role schedules are read once and indexed. Validate-
and-skip with smart retries (over-long durations retried shorter down to
permanent; disallowed nesting skipped cleanly). No artificial caps —
scaling is empirical.

### 16. PIM Activator (browser extension)
A Manifest V3 extension for **Edge and Chrome** for **one-click bulk
activation**: the admin picks the PIM groups they need from a checkbox
list, enters a justification + duration, and activates them all at once.
PKCE sign-in (no MSAL bundle), an onboarding wizard, single + bulk
self-deactivate with expiry countdown, and managed deployment via Intune or
direct registry. (See [PIM Activator](#pim-activator-browser-extension)
below.)

### 17. Naming
All admin, group and resource naming patterns live in configuration with
per-tenant overrides, using simple tokens for initials, level, tier and
platform — so you can match your own conventions without touching code.
(See [Naming conventions](#naming-conventions) below.)

### 19. REST migration
The core runs entirely on direct API calls, with robust handling of large,
paged result sets — no reliance on module-specific behavior.

### 20. Testing / validation
Tested for real, never faked: validation runs against real test tenants —
actually creating groups, delegations, org-group access, emails,
time-limited passes and schedules, then verifying and cleaning them up.
Test data lives in the database under a dedicated marker, so test objects
never touch production groups. A rerunnable offline suite covers the engine
and Manager flows.

> Full detail per chapter: **[docs/FEATURES.md](docs/FEATURES.md)**.

---

## Quick start

### Prerequisites

- Windows PowerShell 5.1 (PS7 also works for the engines that don't touch
  on-prem AD).
- An Entra app registration (service principal) with:
  - `PrivilegedAccess.ReadWrite.AzureADGroup` (application, admin-consented)
  - `RoleManagement.ReadWrite.Directory`
  - `Group.ReadWrite.All`, `User.ReadWrite.All`
  - `UserAuthenticationMethod.ReadWrite.All` (TAP creation, optional)
  - `Directory.Read.All` (PIM Manager tenant-list refresh)
  - For AD-syncing engines: domain credentials on the calling host.
- An authentication method for that SPN. The community launchers support
  three methods (set in `config\PIM4EntraPS.custom.ps1` — copy the sample
  next door first — or in any per-engine `LauncherConfig.custom.ps1`):
  1. **Managed Identity** (`$global:UseManagedIdentity = $true`) —
     recommended for Azure VMs / Arc / Function / Container Apps Job.
  2. **SPN + certificate** (`$global:SpnCertificateThumbprint` in
     `Cert:\LocalMachine\My` or `Cert:\CurrentUser\My`) — the engine's
     default app-auth method.
  3. **SPN + Key Vault secret** (`$global:SpnKeyVaultName` + `$global:SpnSecretName`)
     — the calling identity needs `Key Vault Secret User` on that vault.
- For TAP delivery (optional): SMTP relay / Teams webhook / Slack webhook —
  see `config\PIM4EntraPS.NotificationChannels.custom.sample.ps1`.

See `config\PIM4EntraPS.custom.sample.ps1` for a copy-pasteable template.

One-shot SPN installer (creates + permissions + admin-consents):
`setup\Install-PimEngineAppRegistration.ps1 -DisplayName "PIM4EntraPS-Engine"`.

### One-time setup

```powershell
# 1. Clone the repo on your management VM.
git clone https://github.com/KnudsenMorten/PIM4EntraPS.git
cd PIM4EntraPS

# 2. Copy each *.custom.sample.* you want to customise to *.custom.* and edit.
#    Everything *.custom.* is gitignored (customer-owned, never leaves the VM).
foreach ($sample in Get-ChildItem .\config\*.custom.sample.*) {
    $target = $sample.FullName -replace '\.custom\.sample\.', '.custom.'
    if (-not (Test-Path $target)) { Copy-Item $sample.FullName $target }
}

# 3. Edit launcher\<task>\LauncherConfig.custom.sample.ps1 -> LauncherConfig.custom.ps1
#    with your tenant id, app id, KV name.
```

The shipped `config\` templates include documented samples with worked
example rows — including a catalog of common Entra built-in roles — to give
you a working starting point instead of an empty schema. CSV is supported
only as a **read-only migration source**; the running model lives in SQL.

### Run the engine

Pick the launcher flavor matching your host:

| Flavor | Where it runs |
|---|---|
| `community-vm.ps1` | Any VM, no internal dependencies (recommended starting point) |
| `community-azure.ps1` | Azure Function / Logic App / Container Apps Job, public modules only |
| `internal-vm.ps1` | Customer VM with internal bootstrap libs |
| `internal-azure.ps1` | Customer Azure host with internal bootstrap libs |

The REST + SQL engine is driven by scope and mode — run only the area you
need, full or incremental:

```powershell
# WhatIf -- read-only, prints what *would* change:
.\launcher\PIM-Baseline-Management\launcher.community-vm.ps1 -WhatIfMode

# Apply a full pass:
.\launcher\PIM-Baseline-Management\launcher.community-vm.ps1

# Apply only the changed delta for one scope:
.\launcher\PIM-Baseline-Management\launcher.community-vm.ps1 -Scope EntraRoles -Mode Delta
```

Transcript logs land in `logs/`; engine output (state snapshots,
delegation exports) lands in `output/`. Both are gitignored.

### How a run works

The engine entry point is `tools/pim-engine/Invoke-PimEngineCore.ps1`
(`-Scope All|<name> -Mode Full|Delta [-FromQueue]`). Identity and targets
come from the environment / launcher globals — nothing is hardcoded. The
core is a pure diff (desired-vs-live) plus an orchestrator: each **scope is
a provider** that knows how to read the desired state (from SQL), read the
live state (tenant REST), key + compare, and apply Create / Update /
Remove. Providers run in a fixed dependency order, and a provider can
request a directory-cache refresh before it runs — so an assignment scope
sees the groups an earlier scope just created.

**Run modes:**

- **Full** — whole-scope reconcile (create / update). **Prune (removal of
  live items not in the desired set) is opt-in:** Full alone never deletes;
  you must add `-Prune`. This is a destructive-safety guard — a partial or
  non-authoritative desired set must never silently disable real admins. A
  second guard applies even with `-Prune`: a scope whose desired set is
  empty is never pruned (an empty desired almost always means "this scope
  wasn't loaded", not "delete everything live"), and the refusal is logged.
- **Delta** — create / update everything that differs (no prune).
- **Delta + `-FromQueue`** — apply only the pending commit-queue changes. A
  Manager commit enqueues the `(entity, key)` pairs it touched and the
  engine applies just those.

**Fail-hard preflight.** Before any provider runs, the entry point verifies
the inputs are real and refuses to proceed otherwise, so a wrong / empty
store or a bad credential can never silently mass-create (or, in
Full + Prune, mass-delete) against a live tenant: the desired store must be
reachable and hold at least one definition / admin row, and a Graph token
must be minted and the organization resolve. A wrong identity fails here,
not after a half-applied run.

### Providers / connectors

Each scope is a provider — read desired / read live / key + compare /
apply. They run in a fixed dependency order so dependent objects exist
before they're referenced:

| Order | Provider | Creates / binds |
|---|---|---|
| 10 | Administrative units | AUs (scope containers only) |
| 20 | Groups | the PIM groups (+ owners, AU attach) |
| 30 | Admins | admin accounts |
| 35 | Admin TAP | Temporary Access Pass for new admins |
| 40 | Entra roles | directory role → group (tenant scope) |
| 45 | Roles in AUs | directory role → group, scoped to an AU |
| 50 | Admin members | admin → eligible / active member of a group |
| 55 | Group members | group → member of a group (the nesting) |
| 60 | Azure resources | Azure RBAC role → group, at an Azure scope |
| 70 | Group policies | per-group PIM policy (approval, MFA, justification) |

Beyond the built-ins, connectors translate one PIM group into the right
access across **Power BI / Fabric, gallery enterprise apps** (SAP,
ServiceNow, etc.) and **Dataverse / Dynamics 365** — each connector turns
on its own access prerequisite. Roles are imported from the live service
list so you pick real roles instead of risking typos.

**Owners are mandatory.** A group is never created without an owner. Owners
resolve in order: the definition's `Owners` column → the role's sponsor →
the group's department contact (department → owner mapping). If none
resolve, the engine refuses to create the group — surfacing the data gap
instead of leaving an orphan. Owners are also the approvers for
approval-required policy templates.

> The earlier **module-based reference engines** (a full pipeline plus
> narrowed single-dimension variants, and the exporter / wizard /
> diagnostic helpers) are retained for reference and incremental retirement
> — see [docs/DESIGN.md §5](docs/DESIGN.md) for the engine taxonomy. New
> deployments use the REST + SQL engine above.

---

## Hosting & containers

Run it where it fits. The Manager can run centrally for the whole team, or
locally on an admin's PC straight against the database — no central web
server required. A loopback **break-glass** edition runs on a client PC for
when a hosted plan is unavailable, so senior admins are never locked out. No
public IP is ever required.

For unattended runs, one configurable engine image runs as manager,
scheduler, engine, connector, queue worker or discovery job — you tell each
instance which roles to take on. It is headless and safe by default:
managed-identity auth, no interactive prompts, no secrets baked into the
image, and `-WhatIf`-by-default so a misconfigured job plans instead of
applies.

What the container does per run:

1. Acquire a Microsoft Graph token for the per-tenant identity.
2. (MSP mode) pull + verify the signed baseline over a private endpoint —
   RSA-SHA256 against the embedded public cert, plus expiry + anti-rollback.
3. Read the tenant's own local store (optional).
4. Merge and create / maintain the accounts and delegations in this tenant.

Identity is one of **Managed Identity** (recommended — no secret to
manage), **Certificate** (the entry point builds a client-assertion JWT),
or **Client Secret** (simplest; rotate regularly), selected by an
environment variable. The identical entry-point logic also runs on a plain
Windows VM — same code, different host. Container = zero-VM cloud-native
option; VM = on-prem option; both first-class.

See **[docs/DESIGN.md §11–12](docs/DESIGN.md)** for the full hosting and
container topology (two-plane network model, scheduled vs on-demand jobs,
Container Apps Job cron, on-prem VMware shape).

---

## PIM Manager (GUI)

`tools/pim-manager/Open-PimManager.ps1` reads the model from the database
and serves a five-tab single-page app in your default browser. The Manager
UI is on the same light palette as the PIM Activator extension, with a
branded blue `PIM MANAGER` banner above the tab bar. Cytoscape node-kind
colours (purple role groups, lavender Azure resources, orange Entra roles)
are preserved on purpose — they're the legend-to-node contract.

| Tab | What it does |
|---|---|
| **Graph** | Interactive directed graph: admin → role group → permission group → target. Click-to-highlight neighbourhood, layer + edge filters, regex search. Cytoscape.js + dagre layout. ~500 nodes / ~800 edges render in <2s. |
| **Grid** | Spreadsheet-style editor per table. Add / edit / delete rows, multi-select with a sticky action bar, bulk-set `AccountStatus` (Enabled / Disabled / Revoked) or bulk-delete in one click. |
| **New & clone** | Multi-step wizards for the common "create new" flows (admin, role, task, process, service, resource group). Customer-naming-aware: derives the right name prefix from your naming convention so wizard suggestions match it. Includes a data-driven Re-add wizard that scans existing rows for the tag-prefix → table mapping. |
| **Save** | Per-table diff preview before commit, with per-row staging so you can review then cancel-all without losing other in-progress edits. |
| **Validate** | Pre-flight rule engine with **16 rule codes** (PIM-FK-001/002/003, PIM-RA-001/002, PIM-TIER-001/002, PIM-NAME-001/002, PIM-ORPHAN-001/002/003, PIM-DUP-001, PIM-STALE-001/002, PIM-STATUS-001, PIM-DOMAIN-001, PIM-TAP-001). One-click **Bulk Fix-all** dialog plus per-violation inline fixes. |

```powershell
.\tools\pim-manager\Open-PimManager.ps1            # server mode + auto-launch browser
.\tools\pim-manager\Open-PimManager.ps1 -NoLaunch  # serve only, no browser
.\tools\pim-manager\Open-PimManager.ps1 -StaticHtml -OutFile pim.html  # offline export
.\tools\pim-manager\Open-PimManager.ps1 -RefreshTenantLists           # backfill tenant cache
```

**Per-role permission drill-down:** clicking an `entra-role` / `au-role`
node in the Graph tab expands the side panel with the actual delegated
permissions for that directory role (resource actions + data actions, +/-
prefixes, `(D)` marker for data plane) — so the graph doubles as the audit
answer to *"what can this role actually do?"*.

Server-mode endpoints are all bearer-token authed (`/api/config`,
`/api/diff/<table>`, `/api/heartbeat`, `/api/preflight`,
`/api/tenant-lists`, `/api/refresh-tenant-lists`, `/api/naming-conventions`).
Role tiers (Reader / Admin / Super-Admin / Delegated) gate what each
operator can do; the system fails closed to read-only if a role can't be
determined.

See **[tools/pim-manager/README.md](tools/pim-manager/README.md)** for the
full Manager docs and **[docs/DESIGN.md §11](docs/DESIGN.md)** for the
per-field UX model and delegated-visibility design.

---

## PIM Activator (browser extension)

`tools/pim-activator/` is a Manifest V3 browser extension for **Edge and
Chrome**. The admin clicks the toolbar icon, picks the PIM groups they
need from a checkbox list, enters a justification + duration, and clicks
**Activate** — one click instead of N portal navigations.

Auth uses `chrome.identity.launchWebAuthFlow` + PKCE (no MSAL bundle). The
extension is hosted on GitHub Pages
(`https://knudsenmorten.github.io/PIM4EntraPS/updates.xml`); the canonical
extension id is `eheocihmlppcophaeakmdenhgcookkab` (derived from the
manifest's `key` field — the same id on every fleet, every tenant).

### Deployment scripts at a glance

The activator ships its deploy scripts in `tools/pim-activator/`. Pick by
deployment target — the architecture decisions inside each are already made
for you (single source of truth per registry slot, no slot-cycling,
auto-discover from live Entra, ASCII output for Windows Server consoles).

| Script | Use when | Discovers tenant from |
|---|---|---|
| `Deploy-PimActivatorIntune.ps1` | Intune-managed estate (the common case). | Live Entra via `Connect-MgGraph`. |
| `Deploy-PimActivatorClient.ps1` | Non-Intune box (PAW, jump box, dev box). | Live Entra via `Connect-MgGraph`. |
| `Update-PimActivator-Extension.ps1` | Maintainer's machine. Repacks the CRX from `manifest.json` and publishes to GitHub Pages. | The master signing key (held only on the maintainer's machine). |

Two recovery scripts also live alongside, for the rare case Chrome marks
the extension `DISABLE_CORRUPTED` (binary deleted but Secure Preferences
registration stuck):

| Script | What it does |
|---|---|
| `Fix-PimActivatorStuck.ps1` | One-time, surgical: scrubs the stale `extensions.settings.<id>` + HMAC entries from `Preferences` + `Secure Preferences` across every Chrome / Edge profile on the box. Pure string-surgery brace counting — no fragile JSON round-trip, can't brick a profile. |
| `Reset-CorruptedExtensions.ps1` | Generic auto-heal. Scans every profile for entries flagged DISABLE_CORRUPTED and removes them. Schedule as a logon task for a self-healing fleet. |

### Intune deploy (`Deploy-PimActivatorIntune.ps1`)

The Intune deploy creates / updates a Group Policy Configuration profile
carrying **four policies per browser**:

1. **`ExtensionInstallForcelist`** — force-install from the GitHub Pages CRX.
2. **`ExtensionInstallSources`** — whitelist the GitHub Pages origin as a
   CRX install source.
3. **`ExtensionSettings`** — pre-grants `<all_urls>` runtime hosts so the
   permission-expansion gate never fires
   (`{installation_mode: force_installed, update_url, runtime_allowed_hosts: ['<all_urls>']}`).
4. **Tenant catalog** — pushes the tenant JSON into
   `chrome.storage.managed.tenantCatalog` so the popup's *Use centrally
   deployed* tile lights up on first open.

The script also auto-uploads a self-contained custom ADMX the first time it
runs in a tenant (idempotent — skips on subsequent runs), so it lands
cleanly on both permissive and strict Intune tenants.

```powershell
.\Deploy-PimActivatorIntune.ps1
# Connects Graph (interactive if not connected),
# reads tenant displayName + tenantId from /organization,
# resolves the PIM Activator app registration via
#   /applications?$filter=startswith(displayName,'PIM Activator')
# (use a -ClientId override or -CatalogJsonPath if displayName isn't
#  the standard "PIM Activator")
```

**Conflict awareness.** Before creating the profile, the script scans
Settings Catalog + Administrative Templates for any OTHER policy already
managing `ExtensionInstallForcelist`. If one exists it aborts by default
(printing the exact `<extId>;<updateUrl>` line to add to the existing
policy), because mixing forcelist-write mechanisms causes the entry to
cycle on/off on every sync. `-Force` proceeds but skips the forcelist
values and prints an `[ACTION REQUIRED]` block instead.

Required Graph scopes:

```
DeviceManagementConfiguration.ReadWrite.All
Application.Read.All
Organization.Read.All
Group.Read.All     # only when -AssignToGroupId is supplied
```

### Non-Intune deploy (`Deploy-PimActivatorClient.ps1`)

For PAWs, admin jump boxes, dev workstations, and any other box that isn't
Intune-managed. Writes directly to the Chromium policy keys:

```
HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist
HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallSources
HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<id>\policy\tenantCatalog
HKLM:\SOFTWARE\Policies\Google\Chrome\...   (same structure)
```

`-Scope Machine` (default, HKLM, requires admin) covers every user on the
box. `-Scope User` writes to HKCU for the current-user only (no admin
required). When `-CatalogJsonPath` is omitted (the common case) the script
auto-discovers the tenant + PIM Activator app registration from the live
Graph context — the same logic as the Intune deploy — and logs which source
it used so it's impossible to silently write a different tenant's data.

Common server scenarios:

- **Shared admin server (multiple RDPs)** — `-Scope Machine`, run once as
  admin. Every RDP user gets the extension on next browser launch.
- **Personal PAW (one admin)** — `-Scope User`, run from the admin's own
  RDP session. No admin rights needed.
- **AD-joined fleet via GPO Startup Script** — call with `-Scope Machine`
  from a `Computer Configuration → ... → Scripts → Startup` GPO script.

### Multi-tenant model

The popup reads its tenant config from two layers, in order:

1. **Manual single-tenant entry** — `chrome.storage.local` values written
   by the popup's onboarding *Add single tenant* tile. This always wins,
   even when a managed catalog is present.
2. **Managed catalog** — `chrome.storage.managed.tenantCatalog`, pushed by
   either deploy script. A JSON array of
   `{name, tenantId, clientId, defaultJustification, defaultDurationHours, prefix, entraPrefix, azurePrefix}`.

| Catalog size | Popup behaviour |
|---|---|
| 0 entries | Onboarding wizard: *Add single tenant* (manual) or *Import JSON* tiles. |
| 1 entry | Used silently; tenant chip in the header shows the friendly name. |
| 2+ entries | Header shows a tenant switcher dropdown, cached per browser profile. |

```
+-------------------------------+      +---------------------------+      +------------------+
| Deploy-PimActivatorIntune.ps1 | -->  | Chromium policy registry  | -->  | Extension popup  |
| (ADMX-backed Intune profile)  |      | (HKLM ...\3rdparty\       |      | popup.html +     |
+-------------------------------+      |  extensions\<id>\policy\  |      | popup.js         |
| Deploy-PimActivatorClient.ps1 | -->  |  tenantCatalog JSON)      |      |                  |
| (direct HKLM/HKCU)            |      +---------------------------+      | -> single tenant |
+-------------------------------+                                         |    (silent)      |
                                                                          | -> 2+ tenants    |
       silent push                   managed_storage payload              |    (picker)      |
                                                                          | -> 0 tenants OR  |
                                                                          |    wizard        |
                                                                          +------------------+
```

**Activation duration.** Fresh installs default activations to **8 hours**
(one workday). Precedence at popup-open time: the user's last picked value
(per profile) > managed `defaultDurationHours` (registry) > built-in
fallback. Override per box via either deploy script's parameter, or for a
single profile directly in the registry `policy` key.

See **[tools/pim-activator/README.md](tools/pim-activator/README.md)** for
the full deployment matrix, Intune ADMX rollout, conflict handling, and
backend (app registration) setup.

---

## Notifications & scheduled TAP

`Send-PimAdminTap` fans new-admin Temporary Access Pass codes out to any
combination of SMTP / Teams / Slack via
`PIM4EntraPS.NotificationChannels.custom.ps1`:

```powershell
$global:PIM_NotificationChannels = @{
    Smtp  = @{ Server='<smtp-relay-host>'; Port=587; UseSsl=$true;
               From='<pim-noreply@your-domain>'; Credential=$smtpCred }
    Teams = @{ WebhookUrl='<your-teams-incoming-webhook-url>' }
    Slack = @{ WebhookUrl='<your-slack-incoming-webhook-url>' }
}
```

It defaults to an empty hashtable (no channels = no fan-out; account
creation still proceeds). Delivery failures **never** block account
creation (the whole call is `try {} catch {}`-wrapped), and `-WhatIfMode`
logs intent (`[WHATIF] would send TAP to … via <Channel>`) with zero
network traffic.

**Scheduled TAP start time:** `Resolve-PimTapStartDateTime` recognises
relative phrases in the `TAPStartDate` column in addition to ISO 8601 /
culture-specific shapes:

- `+2d 8:00`, `+3 days at 8am`, `in 2 days at 9am`, `2 hours`
- `tomorrow`, `today 14:30`, `next monday 10:00`
- Full ISO `2026-06-04T08:00:00Z`

All resolved to UTC; relative expressions default to 09:00 ("next
business-day morning" handover convention).

---

## Naming conventions

Customer naming styles vary widely (`Admin-` / `X-Admin-` / `adm` / `extadm`
/ `a-{owner}` / `grp-e-pim-` etc.). `PIM4EntraPS.NamingConventions.custom.ps1`
captures your convention in one place and feeds it to:

1. **Engine perf** — the filtered context helpers extract the literal
   prefix and pass it to Graph `$filter=startswith(...)`, shrinking
   large-tenant fetches to the handful of PIM-managed objects.
2. **PIM Manager wizards** — suggest correctly-prefixed names when creating
   new admin / role / permission groups.
3. **Validator rules** — `PIM-NAME-001` / `PIM-NAME-002` warn on
   convention drift.

Sample patterns + `AdminAccountPatterns` per UserType (Internal / External
/ Guest) are documented in
`config\PIM4EntraPS.NamingConventions.custom.sample.ps1`.

---

## MSP variant

For consultancies managing many customer tenants: each customer tenant
**pulls** a signed baseline into its own local database — the provider
never writes to the customer tenant, and customer data never leaves it.
Set the MSP config variant in the launcher and PIM4EntraPS reads from
`config-msp/` instead of `config/`. The MSP keeps only the central
template; each customer has its own isolated data store with no
cross-customer visibility.

**The acting identity is always local.** Each customer tenant has its own
engine app + non-exportable certificate, so the customer owns its
Conditional Access, its audit attribution (actions log as a named app in
*their* tenant), lifecycle, and instant revocation. There is no GDAP and no
foreign multi-tenant identity — which is what makes this work for EA/MCA
enterprises that GDAP can't cover at all, and avoids the "who is this GUID
from the partner tenant?" audit problem.

**Signed, not encrypted; no secret at the receiver.** The baseline (and the
license) are signed with a private key held only on the MSP host and
verified against a public certificate embedded in the product. The customer
side needs no secret key — it only verifies — and because bundles are
signed rather than encrypted, the customer can read exactly what the MSP
ships. Tamper, forge, roll-back and replay are all rejected (RSA-SHA256
signature, version-monotonic check, validity-window check).

**CISO opt-in for status changes:** the MSP variant gates centrally-issued
`Disable` / `Revoke` actions behind a per-admin secret in the **customer's**
Key Vault (not the MSP's). No match = refuse + warn. Defense in depth
against MSP-tenant access misuse.

See **[docs/DESIGN.md §13](docs/DESIGN.md)** for the full MSP architecture
(two-DB model, pull-not-push transport, signed-baseline + kill-switch,
ring-based rollout, why-not-GDAP).

---

## Repo layout

```
PIM4EntraPS/
  engine/
    _shared/PIM-EngineCore.ps1                  # REST + SQL engine core
    _shared/PIM-EngineProviders.ps1             # per-scope appliers (connectors)
    _shared/PIM-Functions.psm1                  # shared function library
  tools/
    pim-engine/Invoke-PimEngineCore.ps1         # engine entry (-Scope / -Mode)
    pim-manager/                                # browser-based 5-tab SPA editor
      Open-PimManager.ps1                       # HttpListener server + static export
      _validator.ps1                            # 16-rule pre-flight engine
      README.md
    pim-activator/                              # Edge/Chrome MV3 extension (bulk activation)
      Deploy-PimActivator*.ps1                  # Intune / client deploy + recovery
      README.md
  launcher/
    <task>/launcher.<flavour>.ps1               # community/internal × vm/azure
    <task>/LauncherConfig.*.ps1                 # layered config (defaults/locked/custom)
    _lib/                                        # shared launcher helpers
  config/        *.custom.sample.* templates (worked rows); *.custom.* gitignored
  config-msp/    MSP per-customer config + template-pull
  setup/         Install-PimEngineAppRegistration.ps1, setup-script family
  sql/           idempotent schema (CREATE + ALTER) + seed
  infra/         container / hosting deployment
  legacy/        module-based reference engines (incremental retirement)
  docs/          FEATURES.md · ROADMAP.md · DESIGN.md (public) · REQUIREMENTS.md · TESTS.md (internal)
  CLAUDE.md      router + working agreement (auto-loaded)
  VERSION
  README.md
  RELEASENOTES.md
```

---

## Documentation

The doc set (public unless marked internal):

- **[docs/FEATURES.md](docs/FEATURES.md)** — public, customer-facing
  catalog of delivered + verified features, grouped per chapter. The
  "Features" section above mirrors its structure.
- **[docs/ROADMAP.md](docs/ROADMAP.md)** — public, high-level planned /
  upcoming features (auto-generated from the backlog; no bug fixes).
- **[docs/DESIGN.md](docs/DESIGN.md)** — architectural deep dive: nesting,
  delegation, naming, tier model, hosting, MSP, SQL data model, connectors,
  lifecycle/governance.
- **[RELEASENOTES.md](RELEASENOTES.md)** — curated changelog (what changed
  each release + migration notes).
- **Internal (not published):** `REQUIREMENTS.md` (open backlog), `TESTS.md`
  (test suites + results), `CLAUDE.md` (working agreement + router).
- **[tools/pim-manager/README.md](tools/pim-manager/README.md)** /
  **[tools/pim-activator/README.md](tools/pim-activator/README.md)** —
  per-tool deployment docs.

---

## Versioning

Semver-ish: `MAJOR.MINOR.PATCH`.

- `MAJOR` — breaking layout / schema / launcher contract change.
- `MINOR` — additive engine or tool.
- `PATCH` — fix / doc / workflow polish.

Each release is tagged twice on the monorepo: `PIM4EntraPS-<x>` (private)
and `PIM4EntraPS-v<x>` (public — fires the publish workflow to the mirror).

---

## Support / contributing

Issues + PRs welcome on GitHub. For production-deployment help (PAW
rollout, AD trust setup, multi-tenant), contact the maintainer.

Author: see the project's GitHub repository.
