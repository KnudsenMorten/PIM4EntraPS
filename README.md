# PIM4EntraPS

> **Privileged Identity Management for Entra ID, as code.**
> Declare your admin model in CSV; let PowerShell + Microsoft Graph apply it.
> Nest groups properly. Activate in bulk. Visualize the whole thing.

PIM4EntraPS turns a sprawling, click-driven PIM model into a small set of
CSV files that an engine reads, diffs against the tenant, and applies.
A typical 30-admin / 200-permission-group tenant becomes a 14-CSV repo
that a single engine run keeps in sync, a browser-based **PIM Manager**
GUI to edit + validate the model, and a single Edge extension to let
the admins bulk-activate from.

---

## Why this exists

Managing PIM at any non-trivial scale through the Entra portal is painful:

- Per-admin onboarding is **N clicks** (one per role / scope / AU).
- "Add a new permission to the Cloud Engineer role" is **M clicks** (one
  per admin who has that role).
- Drift is invisible: nobody knows what's *actually* assigned vs what was
  documented in a spreadsheet last quarter.
- Audit asks "who can do X" — answering means clicking through every PIM
  blade and Azure RBAC scope.

**PIM4EntraPS replaces the clicks with a declarative model**:

| File | Says |
|---|---|
| `Account-Definitions-Admins.custom.csv` | Who the admin accounts are |
| `PIM-Definitions-Roles.custom.csv` | What *role groups* exist (job functions) |
| `PIM-Definitions-Tasks/Services/Resources/...custom.csv` | What *permission groups* exist (atomic capabilities) |
| `PIM-Assignments-Admins.custom.csv` | Which admins are in which role groups (eligible/active) |
| `PIM-Assignments-Groups.custom.csv` | Which permission groups nest inside which role groups |
| `PIM-Assignments-Roles-Groups.custom.csv` | What Entra ID roles each permission group grants |
| `PIM-Assignments-Roles-AUs.custom.csv` | What AU-scoped Entra roles each permission group grants |
| `PIM-Assignments-Azure-Resources.custom.csv` | What Azure RBAC scopes each permission group grants |

Run the engine → tenant matches the CSV. Edit a row → run again → delta
applied. Git tracks the history.

---

## The core idea: 3-tier group nesting

Don't assign Entra/Azure roles directly to admins. Assign them to
**permission groups**. Nest permission groups into **role groups** (which
represent a job function). Assign admins to role groups via PIM:

```
Admin                 Role Group              Permission Groups               Target
(the user)            (the job function)      (atomic capability)             (Entra / Azure / AU)

Admin-ABC-L1-T1-ID  --E->  PIM-ROLE-           --E--> PIM-Entra-ID-              --E--> "Application Administrator"
                           CloudEngineer              AppAdmin-L1-T0-CP-ID                   (Entra ID role)
                                                --A--> PIM-AzDevOps-               --A--> "Build Administrator"
                                                       TeamsContrib-L2-T1-...                 (AzDevOps role)
                                                --E--> PIM-AzRes-MP-               --E--> Owner on /subscriptions/{...}
                                                       Platform-L3-T1-...                     (Azure RBAC)
                                                --E--> PIM-PowerBI-WS-             --E--> Workspace contributor
                                                       ExampleWS-L4-T2-...                    (Power BI)
```

`--E->` = Eligible (PIM activation required) · `--A->` = Active (always on)

**Why nest:**

- Onboarding a new Cloud Engineer = **one** assignment row, not 20.
- Refactor a permission group's targets → every role group using it gets
  the change for free.
- Removing an admin = one row deletion; their entire access surface
  collapses.
- The graph (admin → role → permission → target) is the audit answer to
  *"who can do X?"* — see the **[PIM Manager](#pim-manager-gui)**.
- Entra ID enforces a hard cap of **500 role-assignable groups per
  tenant**. Heavy reuse of permission groups + role groups across many
  admins keeps you well under the ceiling.

See **[docs/DESIGN.md](docs/DESIGN.md)** for the full philosophy:
direct vs indirect delegation, naming convention, tier model, lifecycle
states, the as-code pattern, customer overrides.

---

## Features

Comprehensive feature inventory below. Status badges show `[shipped vX.Y.Z]` /
`[roadmap]` / `[partial]`. Roadmap items + sizing + dependencies live in
[docs/ROADMAP.md](docs/ROADMAP.md); per-release detail lives in
[RELEASENOTES.md](RELEASENOTES.md).

* browser-based PIM Manager GUI with 5 tabs (Graph / Grid / New & clone / Save / Validate) for editing the whole model without touching CSVs directly **[shipped v2.0.0]** (refined through v2.2.0 and v2.4.2)
* PIM Activator Edge extension for bulk activation -- pick N PIM groups from a checkbox list, enter justification + duration, one click activates them all **[shipped v2.1.x]**
* new Revoke tab in PIM Manager for bulk-revoke of active activations **[shipped v2.4.2]**
* server-side Graph filtering for engine perf (`Get-PimAdminsFiltered` / `Get-PimGroupsFiltered`) -- fetches ~30 admins instead of all 514k on a large tenant **[shipped v2.1.3]**
* customer-naming-aware Manager wizards driven by per-customer `PIM4EntraPS.NamingConventions.custom.ps1` so suggested names always match the local convention **[shipped v2.1.3]**
* tenant-wide preload helpers + ARG-based active-assignment fetch to cut per-engine round-trips **[shipped v2.4.0]**
* `Get-AzPimTokenCached` for token reuse across loops, avoids re-auth churn during long engine runs **[shipped v2.4.0]**
* MSP variant with `config-msp/` + `Sync-PimMspConfig` for consultancies managing many customer tenants from one engine instance, plus CISO opt-in (per-admin secret in the customer's own Key Vault) gating centrally-issued Disable/Revoke status changes **[shipped earlier v2.x]**
* `.locked.csv` -> `.custom.csv` consolidation -- single-file customer model, no more dual-file split **[shipped v2.3.0]**
* validator pre-flight rule engine with 16 rule codes (FK, RA, TIER, NAME, ORPHAN, DUP, STALE, STATUS, DOMAIN, TAP) plus one-click Bulk Fix-all dialog **[shipped v2.0.x+]**
* notification-channels config + `Send-PimAdminTap` fan-out across SMTP / Teams / Slack **[shipped v2.2.0]**
* optional fields to allow extra metadata per admin during creation, like company field or notes field **[shipped v2.2.0]** (Company / Notes / ManagerEmail / StartDate columns)
* ability to send tap password **[shipped v2.2.0]**
* ability to define tap password start time like in 2 days at 8am **[shipped v2.2.0]** (`+2d 8:00`, `tomorrow`, `next monday 10:00`, full ISO, etc.)
* ability to show more info behind a role to see actual permissions being delegated **[shipped v2.2.0]** (Manager Graph drill-down; standalone CSV export still roadmap)
* ability to clone a role **[shipped v2.0.x]** (Clone wizard in Manager)
* ability to add-detect new subscriptions and management groups in azure to setup pim permissions with fx contribution (define in a custom file). engine must automatically add them into definition + assignment files -- but don't automatically map new subs/MGs to anyone by default **[roadmap]** (ROADMAP #16)
* ability to multiselect permissions like 10 entra roles and 10 azure permissions to a role/org/task/process type so we can easily setup new permissions **[roadmap]** (ROADMAP #4)
* ability to clone azure subscription role delegations on an existing scope -- but with another role. maybe ability to clone to N new roles **[roadmap]** (ROADMAP #5)
* ability to enumerate existing services like intune to detect new built-in roles that should be added. support defender xdr, entra id, intune **[roadmap]** (ROADMAP #18)
* ability to add new administrative units via wizard **[roadmap]** (ROADMAP #8)
* ability to delete via multiselect existing pim assignments/delegations **[shipped v2.2.0]** (ROADMAP #7)
* ability to autodetect new power platform workspaces and create pim groups **[roadmap]** (ROADMAP #17)
* ability to send a request to a webhook (or other inbound api) fx from servicenow so it can create a delegation for fx. a consultant, either as mapping to existing role or create a new role (fx new external company) **[roadmap]** (ROADMAP #21)
* ability to send daily summary emails of pim changes (new admins, new delegations, removals, etc) **[roadmap]** (ROADMAP #23)
* ability to send delegations based on tier model and show all users with tier 0/1 permissions including level permissions **[roadmap]** (ROADMAP #24)
* ability to support different policies for entra id activations, so some roles require approvals whereas others don't require approval. same with activations, where it should send emails for activations and delegations, typically high-privileged roles (tier 0). these settings must be controllable in a custom file per row. proposed extra columns in the config definitions enforce approval and notifications per row. if possible the approval should be parallel-based so a request is sent to multiple emails at the same time and any one can approve. approvals should be defined on the actual assignment like global admin role -- not on activating the role **[roadmap]** (ROADMAP #14 + #15)
* ability to validate a minimum set of authentication methods is defined for existing admins like mfa authenticator **[roadmap]** (ROADMAP #13)
* ability to disable/enable admins using multi-select **[shipped v2.2.0]** (ROADMAP #6)
* ability to import admins based on csv file (first name, last name, initials) and link to template for admins **[roadmap]** (ROADMAP #9)
* define an admin template, so we have a rule for tap creation, naming, etc. like one for internal admins and another for externals/consultants **[roadmap]** (ROADMAP #10)
* ability to clean-up pim groups that haven't been activated in N days -- remove in entra + config files **[roadmap]** (ROADMAP #20)
* ability to validate pim assignments pointing at orphaned azure scopes that don't exist anymore **[roadmap]** (ROADMAP #19)
* maintenance job that fixes orphaned azure scopes, orphaned roles (delete assignments + delete groups) **[roadmap]** (ROADMAP #30 + #19)
* should we change into using another platform than CSV, like an azure storage account or sql server -- to avoid issues with multiple people modifying the csv files; can 3 people run the pim manager gui and modify files at the same time? it must scale to enterprises and we must protect the data very much. if yes, then allow import/migration of existing customers into v2 format in database **[partial]** (SQL backend already exists via the `PIM-Baseline-Management-SQL` engine; multi-writer concurrency on CSV is ROADMAP #33/#34)
* ability to send info to users in groups/roles, in case they have been assigned new permissions (or changes) **[roadmap]** (ROADMAP #29)
* ability to move an admin from one role to another role (where it removes old permissions) -- replace-mode **[roadmap]** (ROADMAP #27)
* ability to log any pim changes in loganalytics + log file for audit compliance purpose **[roadmap]** (ROADMAP #26)
* ability to define a sponsor/owner of a role for validation/audit/renewal purpose **[partial]** -- shipped v2.2.0 data-flow only; enforcement queued (ROADMAP #28)
* ability to setup access package in entra and delegate to pim group (extra column) -- yes it works, uses `EntitlementManagement.ReadWrite.All` **[roadmap]** (ROADMAP #31)
* ability to setup access review for pim group/role (extra column) so owners automatically must approve extensions, except for permissions where auto-extension has been defined **[roadmap]** (ROADMAP #32)

See [RELEASENOTES.md](RELEASENOTES.md) for per-release detail and [docs/ROADMAP.md](docs/ROADMAP.md) for sizing + sequencing of the roadmap items.

---

## Quick start

### Prerequisites

- Windows PowerShell 5.1 (PS7 also works for the engines that don't
  touch on-prem AD).
- An Entra app registration (service principal) with:
  - `PrivilegedAccess.ReadWrite.AzureADGroup` (application, admin-consented)
  - `RoleManagement.ReadWrite.Directory`
  - `Group.ReadWrite.All`, `User.ReadWrite.All`
  - `UserAuthenticationMethod.ReadWrite.All` (TAP creation, optional)
  - `Directory.Read.All` (PIM Manager tenant-list refresh)
  - For AD-syncing engines: domain credentials on the calling host.
- An authentication method for that SPN. The community launchers support
  four methods (set in `config\PIM4EntraPS.custom.ps1` — copy the sample
  next door first — or in any per-engine `LauncherConfig.custom.ps1`):
  1. **Managed Identity** (`$global:UseManagedIdentity = $true`) —
     recommended for Azure VMs / Arc / Function / Container Apps Job.
  2. **SPN + Key Vault secret** (`$global:SpnKeyVaultName` + `$global:SpnSecretName`)
     — the calling identity needs `Key Vault Secret User` on that vault.
  3. **SPN + certificate** (`$global:SpnCertificateThumbprint` in
     `Cert:\LocalMachine\My` or `Cert:\CurrentUser\My`).
  4. **SPN + plaintext secret** (`$global:SpnClientSecret`) — **TESTING ONLY**.
- For TAP delivery (optional, v2.2.0+): SMTP relay / Teams webhook /
  Slack webhook — see `config\PIM4EntraPS.NotificationChannels.custom.sample.ps1`.

See `config\PIM4EntraPS.custom.sample.ps1` for a copy-pasteable template
covering all four methods.

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

The 14 `*.custom.sample.csv` files in `config\` are documented templates
with worked example rows — including a catalog of ~20 common Entra
built-in roles in `PIM-Assignments-Roles-Groups.custom.sample.csv` to
give you a working starting point instead of an empty schema.

### Run an engine

Every engine has 4 launcher flavors — pick the one matching your host:

| Flavor | Where it runs |
|---|---|
| `community-vm.ps1` | Any VM, no internal dependencies (recommended starting point) |
| `community-azure.ps1` | Azure Function / Logic App, public modules only |
| `internal-vm.ps1` | Customer VM with internal bootstrap libs |
| `internal-azure.ps1` | Customer Azure host with internal bootstrap libs |

```powershell
# WhatIf -- read-only, prints what *would* change:
.\launcher\PIM-Baseline-Management-CSV\launcher.community-vm.ps1 -WhatIfMode

# Apply:
.\launcher\PIM-Baseline-Management-CSV\launcher.community-vm.ps1
```

Transcript log lands in `logs/`. Engine output (LastApplied snapshots,
delegation exports) lands in `output/`. Both gitignored.

---

## Engines (15)

The full pipeline ships as one big engine plus six narrowed variants for
faster iteration on a single dimension. Pick the smallest one that does
what you need:

| Engine | Scope |
|---|---|
| **PIM-Baseline-Management-CSV** | Full pipeline: admins, AUs, role groups, permission groups, assignments, policies |
| PIM-Baseline-Management-CSV-AdminsOnly | Admin accounts only (no group / role processing) |
| PIM-Baseline-Management-CSV-AdministrativeUnitsOnly | AU definitions + role assignments only |
| PIM-Baseline-Management-CSV-EntraIDRolesOnly | Permission group → Entra ID role bindings only |
| PIM-Baseline-Management-CSV-AzResOnly | Permission group → Azure RBAC bindings only |
| PIM-Baseline-Management-CSV-PIM4GroupsAssignmentOnly | Admin → role group PIM assignments only |
| PIM-Baseline-Management-CSV-PIM4GroupsCreateModifyPolicyOnly | Create / modify PIM-for-Groups policies only |
| PIM-Baseline-Management-CSV-PIM4GroupsPoliciesOnly | Apply policies to existing PIM-for-Groups only |
| **PIM-Baseline-Management-SQL** | Same as CSV variant but reads from Azure SQL instead of files |
| **PIM-Assignment-Exporter** | Dumps current tenant PIM state to CSV (delegation snapshots) |
| PIM-Assignment-Exporter-CSV-Only | Faster exporter variant (skip the JSON/HTML outputs) |
| **PIM-Assignment-Wizard** | Interactive: walk an admin through assigning themselves |
| **PIM-Assignment-Revoker** | Bulk-revoke active activations |
| Check-PIM-Groups-IsRoleAssignable | Diagnostic: list groups that are/aren't role-assignable |
| GetNumberOfROles | Diagnostic: count effective Entra role reach per admin |

**Perf:** v2.1.3 added server-side Graph `$filter` for `Get-PimAdminsFiltered`
+ `Get-PimGroupsFiltered`. On a 514k-user tenant the engine now fetches ~30
admins instead of all 514k (and ~hundreds of `PIM-*` groups instead of all
30k) by deriving the literal prefix from `PIM4EntraPS.NamingConventions.custom.ps1`
and passing `startswith(...)` to Graph.

---

## PIM Manager (GUI)

`tools/pim-manager/Open-PimManager.ps1` reads all `*.custom.csv` files and
serves a five-tab SPA in your default browser:

| Tab | What it does |
|---|---|
| **Graph** | Interactive directed graph: admin → role group → permission group → target. Click-to-highlight neighbourhood. Layer + edge filters. Regex search. Cytoscape.js + dagre layout. ~500 nodes / ~800 edges renders in <2s. |
| **Grid** | Spreadsheet-style editor per CSV. Add / edit / delete rows. **v2.2.0:** multi-select checkbox per row + sticky action bar; bulk-set `AccountStatus` (Enabled / Disabled / Revoked) or bulk-delete in one click. |
| **New & clone** | Six multi-step wizards covering the common "create new" flows (admin, role, task, process, service, resource group). Customer-naming-aware: derives the right name prefix from `PIM4EntraPS.NamingConventions.custom.ps1` so wizard suggestions match your convention (`PIM-` / `PIM_` / `grp-e-pim-` etc.). Includes a data-driven Re-add wizard that scans existing rows for the tag prefix → CSV mapping. |
| **Save** | Per-CSV diff preview before commit. Writes always land in `<base>.custom.csv`. Per-row staging means you can review, then cancel-all without losing other in-progress edits. |
| **Validate** | Pre-flight rule engine with **16 rule codes** (PIM-FK-001/002/003, PIM-RA-001/002, PIM-TIER-001/002, PIM-NAME-001/002, PIM-ORPHAN-001/002/003, PIM-DUP-001, PIM-STALE-001/002, PIM-STATUS-001, PIM-DOMAIN-001, PIM-TAP-001). One-click **Bulk Fix-all** dialog covers FK-001 / STALE-001 / RA-002. Per-violation inline buttons for FK-001 (Remove + Re-add definition). |

```powershell
.\tools\pim-manager\Open-PimManager.ps1            # server mode + auto-launch browser
.\tools\pim-manager\Open-PimManager.ps1 -NoLaunch  # serve only, no browser
.\tools\pim-manager\Open-PimManager.ps1 -StaticHtml -OutFile pim.html  # offline export
.\tools\pim-manager\Open-PimManager.ps1 -RefreshTenantLists           # backfill cache/
```

**Per-role permission drill-down (v2.2.0):** clicking an `entra-role` /
`au-role` node in the Graph tab expands the side panel with the actual
delegated permissions for that directory role (resource actions + data
actions, +/- prefixes, `(D)` marker for data plane). Pulled from
`cache/entra-roles.json` (refresh via toolbar button or the inline CTA
shown when a role isn't in cache yet).

Server-mode endpoints (all bearer-token authed):
`/api/config`, `/api/csv/<base>`, `/api/diff/<base>`, `/api/heartbeat`,
`/api/preflight`, `/api/tenant-lists`, `/api/refresh-tenant-lists`,
`/api/naming-conventions`.

---

## PIM Activator (browser extension)

`tools/pim-activator/` is a Manifest V3 browser extension for **Edge and
Chrome**. Admin clicks the toolbar icon, picks the PIM groups they need
from a checkbox list, enters a justification + duration, clicks
**Activate**. One Graph round-trip per group (the API requires it), but
the admin sees one click instead of N portal navigations.

Auth uses `chrome.identity.launchWebAuthFlow` + PKCE (no MSAL bundle).
Extension is hosted on GitHub Pages
(`https://knudsenmorten.github.io/PIM4EntraPS/updates.xml`); the
deterministic extension id is `eheocihmlppcophaeakmdenhgcookkab`.

### v1.1.1 -- 8-hour default activation duration

Fresh installs now default the activation duration to **8 hours** (one
workday) instead of 1 hour. Existing managed-storage values are
untouched -- managed wins -- so this only affects new profiles / new
installs. Precedence at popup-open time:

`chrome.storage.local.lastDurationHours` (user's last picked value,
per profile) > managed `defaultDurationHours` > `config.js` bundled
default > popup.js fallback.

To override the 8h default at install time:

| Where | How |
|---|---|
| `Deploy-PimActivatorClient.ps1` | `... -DefaultDurationHours 2` |
| `Deploy-PimActivatorIntune.ps1` | `... -DefaultDurationHours 2` |
| Direct registry | `Set-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<id>\policy' -Name defaultDurationHours -Value 2 -Force` |

### v1.1.0 -- multi-tenant support

The managed-policy schema now accepts a `Tenants` array; each entry is
`{ Name, TenantId, ClientId }`. Behaviour:

- 0 tenants -- popup says "not configured".
- 1 tenant -- used silently (same as v1.0).
- 2+ tenants -- popup shows a tenant picker on first run; the choice is
  cached per browser profile in `chrome.storage.local`. Footer shows the
  friendly name + a `(switch)` link to clear the cached pick.

Backwards compatible: the v1.0 singleton `tenantId` / `clientId` keys
still work as a fallback when no `Tenants` array is present.

### Three rollout paths

| Path | Script | Use when |
|---|---|---|
| Intune Remediation | `Deploy-PimActivatorIntune.ps1 -CreateIntuneRemediation` | Intune-managed estate. Hourly self-heal of policy keys. `-GroupId` is optional -- assign manually in the UI if omitted. |
| AD GPO / file share / SCCM | `Deploy-PimActivatorIntune.ps1 -GenerateLocalInstaller` | Non-Intune estates. Emits self-contained `Install-PimActivator.ps1` + `Uninstall-PimActivator.ps1` + README with the tenant JSON baked in. `-LocalInstallerScope User` (HKCU, GPO Logon Script) or `Machine` (HKLM, GPO Startup Script). |
| Direct local registry write | `Deploy-PimActivatorClient.ps1 -Tenants @(...)` | Dev box / single-machine testing. |

CSV format throughout: `Name,TenantId,ClientId`, one row per tenant.

**Adding a tenant later:** edit `tenants.csv`, then either
`-UpdateIntuneRemediation -RemediationId <guid>` (Intune clients converge
within ~1h) or re-run `-GenerateLocalInstaller` and redeploy the
installer via your existing channel.

### Server install (Windows Server / admin jump box / PAW)

The activator runs in Edge / Chrome on Windows Server hosts just as it
does on workstations. Typical targets:

- **Admin jump boxes** — the box admins RDP into to reach customer / prod
  estates.
- **PAWs** (privileged access workstations) — locked-down dedicated admin
  devices.
- **Shared admin Windows Servers** — single host where multiple admins
  RDP in and each needs the extension available in their session.

#### Scope choice for servers

- `-LocalInstallerScope User` (HKCU) — single-admin server / personal
  PAW. Each admin runs `Install-PimActivator.ps1` once for their own
  profile. No admin rights needed. Best when one person owns the box.
- `-LocalInstallerScope Machine` (HKLM) — shared admin server where
  multiple admins RDP in. One install (elevated) covers every RDP user.
  Recommended for shared jump boxes.

#### Generating the Machine-scope installer

```powershell
.\Deploy-PimActivatorIntune.ps1 -GenerateLocalInstaller `
    -TenantsCsv .\tenants.csv `
    -LocalInstallerOutputDir .\out-server-machine `
    -LocalInstallerScope Machine
```

#### Deploying to the server (Machine scope)

1. Copy the generated folder to the server (RDP file transfer, SMB share,
   or PsExec).
2. Open PowerShell **as Administrator** on the server.
3. Run:
   `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Install\PimActivator-Server\Install-PimActivator.ps1`
4. Restart Edge and Chrome on the server (close all browser windows,
   including any in RDP sessions).
5. Each subsequent RDP session sees the extension auto-installed in their
   browser within ~30s.
6. Each admin signs in to the popup with their own admin account; if the
   `Tenants` array has 2+ entries, each admin picks their own tenant per
   browser profile (cached in `chrome.storage.local` per Chromium
   profile).

#### Domain-joined servers via AD GPO Startup Script

- Generate the Machine-scope installer.
- Push to GPO **Computer Configuration -> Policies -> Windows Settings
  -> Scripts -> Startup**.
- Add `Install-PimActivator.ps1` as a PowerShell startup script.
- Runs as `SYSTEM` at boot, writes the HKLM policy keys, every RDP user
  on the box gets the extension.

#### The User-scope alternative (one-admin server)

- Copy the existing User-scope installer folder.
- Each admin runs it once in a non-elevated PowerShell from their RDP
  session.
- Only that admin's RDP sessions get the extension (their HKCU only).

### Mental model

The picker and the deployment layer are independent. Policy push
(Intune / GPO / direct registry) silently lands the `Tenants` array in
`chrome.storage.managed`. The picker UI lives inside the extension HTML
and only reacts to whatever is in managed storage at popup-open time.
Add or remove tenants by changing the source CSV; clients re-render the
picker automatically when the cached choice disappears.

```
+-----------------------+      +---------------------------+      +-----------------+
| Deploy-PimActivator   | -->  | Chromium policy registry  | -->  | Extension popup |
| Intune (remediation)  |      | (HKCU/HKLM ...\policy\    |      | (popup.html +   |
| LocalInstaller (GPO)  |      |  Tenants JSON)            |      |  popup.js)      |
| Client (direct write) |      |                           |      | -> picker if 2+ |
+-----------------------+      +---------------------------+      +-----------------+
       silent push                managed_storage payload            user-facing UI
```

See `tools/pim-activator/README.md` for the full deployment matrix +
backend (app registration) setup.

---

## Notifications & scheduled TAP (v2.2.0)

`Send-PimAdminTap` fans new admin Temporary Access Pass codes out to any
combination of SMTP / Teams / Slack via `PIM4EntraPS.NotificationChannels.custom.ps1`:

```powershell
$global:PIM_NotificationChannels = @{
    Smtp  = @{ Server='smtp.office365.com'; Port=587; UseSsl=$true;
               From='pim-noreply@contoso.com'; Credential=$smtpCred }
    Teams = @{ WebhookUrl='https://contoso.webhook.office.com/...' }
    Slack = @{ WebhookUrl='https://hooks.slack.com/services/T01.../B01.../...' }
}
```

Defaults to an empty hashtable (no channels = no fan-out, account
creation still proceeds). WhatIfMode-aware: logs `[WHATIF] would send TAP
to ... via <Channel>` with zero network traffic. Delivery failures
**never** block account creation (entire call is `Try {} Catch {}`-wrapped).

**Scheduled TAP start time:** `Resolve-PimTapStartDateTime` recognises
relative phrases in the `TAPStartDate` CSV column in addition to ISO 8601
/ culture-specific shapes:

- `+2d 8:00`, `+3 days at 8am`, `in 2 days at 9am`, `2 hours`
- `tomorrow`, `today 14:30`, `next monday 10:00`
- Full ISO `2026-06-04T08:00:00Z`
- Anything `CorrelateDateTimeLanguage` / `[datetime]::Parse` handles as last resort

All resolved to UTC. Defaults for relative expressions: hour=09 minute=00
("next business-day morning" handover convention).

---

## Naming conventions

Customer naming styles vary widely (`Admin-` / `X-Admin-` / `adm` / `extadm`
/ `a-{owner}` / `grp-e-pim-` etc.). `PIM4EntraPS.NamingConventions.custom.ps1`
captures your convention in one place and feeds it to:

1. **Engine perf** — `Get-PimAdminsFiltered` / `Get-PimGroupsFiltered`
   extract the literal prefix and pass it to Graph `$filter=startswith(...)`,
   shrinking 514k-user tenant fetches to ~30 admins.
2. **PIM Manager wizards** — suggest correctly-prefixed names when
   creating new admin / role / permission groups.
3. **Validator rules** — `PIM-NAME-001` / `PIM-NAME-002` warn on
   convention drift.

Sample patterns + `AdminAccountPatterns` per-UserType (Internal /
External / Guest) are documented in
`config\PIM4EntraPS.NamingConventions.custom.sample.ps1`.

---

## MSP variant

For consultancies managing many customer tenants from a single
engine instance: set `$global:PIM_ConfigVariant = 'msp'` in the launcher
and PIM4EntraPS reads from `config-msp/` instead of `config/`. `Sync-PimMspConfig`
pulls per-tenant config snapshots from a git source you control
(`config-msp/msp.source.json`), so the engine runs against an
always-fresh customer-of-record baseline.

**CISO opt-in for status changes:** the MSP variant gates centrally-issued
`Disable` / `Revoke` actions behind a per-admin secret in the **customer's**
Key Vault (not the MSP's). `Test-PimAccountStatusChangeAuthorized` reads
`$global:PIM_StatusChange_KeyVaultName` + `secretName=pim4entraps-statuschange-<initials>`
and compares to the `StatusChangeCode` column in the CSV row. No match =
refuse + warn. Defense in depth against MSP-tenant access misuse.

---

## Repo layout

```
PIM4EntraPS/
  engine/
    <task-name>/<task-name>.ps1                 # 15 engines, one folder each
    _shared/PIM-Functions.psm1                  # canonical function library (~9000 lines)
    _shared/PIM-ContextBuilder.ps1              # Build-PimContext / Get-PimList helpers
  launcher/
    <task-name>/
      launcher.community-vm.ps1                 # 4 flavors per task
      launcher.community-azure.ps1
      launcher.internal-vm.ps1
      launcher.internal-azure.ps1
      LauncherConfig.defaults.ps1               # shipped defaults
      LauncherConfig.custom.sample.ps1          # template for customer override
      launcher.manifest.json
    _lib/
      Initialize-LauncherConfig.ps1
      Start-LauncherTranscript.ps1
      Stop-LauncherTranscript.ps1
      PIM4EntraPS.shared-defaults.ps1
  config/
    *.custom.sample.csv                         # shipped templates w/ worked example rows
    *.custom.csv                                # gitignored: customer's actual data
    repository.custom.sample.ps1                # path mappings template
    policies.custom.sample.ps1                  # PIM policy defaults template
    PIM4EntraPS.NamingConventions.locked.ps1    # schema definition + defaults
    PIM4EntraPS.NamingConventions.custom.sample.ps1
    PIM4EntraPS.NotificationChannels.locked.ps1 # empty hashtable, customer fills custom
    PIM4EntraPS.NotificationChannels.custom.sample.ps1
    PIM4EntraPS.Filters.locked.ps1              # default include/exclude filter functions
    PIM4EntraPS.Filters.custom.sample.ps1
  tools/
    pim-manager/                                # browser-based 5-tab SPA editor
      Open-PimManager.ps1                       # HttpListener server + static export
      pim-manager.html                          # single-file SPA (Cytoscape.js, dagre)
      _validator.ps1                            # 16-rule pre-flight engine
      _tenantSync.ps1                           # tenant-list cache refresh
      cache/                                    # gitignored: per-tenant Graph caches
    pim-activator/                              # Edge MV3 extension (bulk activation)
  setup/
    Install-PimEngineAppRegistration.ps1        # one-shot SPN installer
  docs/
    DESIGN.md                                   # architecture deep dive
    ROADMAP.md                                  # ~34 customer-driven features sized + sequenced
    MANAGER-UX-AUDIT.md                         # per-field UX audit of every CSV column
  logs/                                         # gitignored: transcript output
  output/                                       # gitignored: engine state + delegation dumps
  VERSION
  README.md
  RELEASENOTES.md                               # curated changelog
```

---

## Documentation

- **[docs/DESIGN.md](docs/DESIGN.md)** — architectural deep dive: nesting,
  direct vs indirect delegation, naming convention, tier model, lifecycle,
  customer overrides.
- **[docs/ROADMAP.md](docs/ROADMAP.md)** — sized + sequenced feature
  backlog with `[SHIPPED]` annotations.
- **[docs/MANAGER-UX-AUDIT.md](docs/MANAGER-UX-AUDIT.md)** — per-field UX
  audit of every CSV column (dropdown vs free-text, validation rules,
  wizard exposure).
- **[RELEASENOTES.md](RELEASENOTES.md)** — curated changelog (what changed
  each release + migration notes).
- **[tools/pim-manager/README.md](tools/pim-manager/README.md)** — Manager
  GUI docs (if present; otherwise see the PIM Manager section above).
- **[tools/pim-activator/README.md](tools/pim-activator/README.md)** —
  activator extension docs incl. Intune rollout.

---

## Versioning

Semver-ish: `MAJOR.MINOR.PATCH`.

- `MAJOR` — breaking layout / CSV schema / launcher contract change.
- `MINOR` — additive engine or tool.
- `PATCH` — fix / doc / workflow polish.

Each release is tagged twice on the monorepo: `PIM4EntraPS-<x>` (private)
and `PIM4EntraPS-v<x>` (public — fires the publish workflow to this
mirror).

---

## Support / contributing

Issues + PRs welcome on GitHub. For production-deployment help (PAW
rollout, AD trust setup, multi-tenant), contact the maintainer.

Author: Morten Knudsen ([@KnudsenMorten](https://github.com/KnudsenMorten))
