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
- A Key Vault holding the SP certificate (or use the bootstrap pattern
  documented in your wrapping project).
- For TAP delivery (optional, v2.2.0+): SMTP relay / Teams webhook /
  Slack webhook — see `config\PIM4EntraPS.NotificationChannels.custom.sample.ps1`.

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

## PIM Activator (Edge extension)

`tools/pim-activator/` is an Edge MV3 browser extension. Admin clicks the
toolbar icon, picks the PIM groups they need from a checkbox list, enters
a justification + duration, clicks **Activate**. One Graph round-trip per
group (the API requires it), but the admin sees one click instead of N
portal navigations.

Auth uses `chrome.identity.launchWebAuthFlow` + PKCE (no MSAL bundle).
Intune-deployable: a single `Install-PimActivator.ps1` writes the Edge
policy keys for force-install + per-tenant config; companion
`Install-PimActivatorAppRegistration.ps1` creates the SPA app reg + redirect
URIs. See `tools/pim-activator/README.md` for the two-stage rollout.

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
