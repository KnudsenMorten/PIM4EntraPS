# PIM4EntraPS

> **Privileged Identity Management for Entra ID, as code.**
> Declare your admin model in CSV; let PowerShell + Microsoft Graph apply it.
> Nest groups properly. Activate in bulk. Visualize the whole thing.

PIM4EntraPS turns a sprawling, click-driven PIM model into a small set of
CSV files that an engine reads, diffs against the tenant, and applies.
A typical 30-admin / 200-permission-group tenant becomes a 14-CSV repo
that a single engine run keeps in sync, and a single Edge extension lets
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
| `Account-Definitions-Admins.csv` | Who the admin accounts are |
| `PIM-Definitions-Roles.csv` | What *role groups* exist (job functions) |
| `PIM-Definitions-Tasks/Services/Resources/...csv` | What *permission groups* exist (atomic capabilities) |
| `PIM-Assignments-Admins.csv` | Which admins are in which role groups (eligible/active) |
| `PIM-Assignments-Groups.csv` | Which permission groups nest inside which role groups |
| `PIM-Assignments-Roles-Groups.csv` | What Entra ID roles each permission group grants |
| `PIM-Assignments-Roles-AUs.csv` | What AU-scoped Entra roles each permission group grants |
| `PIM-Assignments-Azure-Resources.csv` | What Azure RBAC scopes each permission group grants |

Run the engine → tenant matches the CSV. Edit a row → run again → delta
applied. Git tracks the history.

---

## The core idea: 3-tier group nesting

Don't assign Entra/Azure roles directly to admins. Assign them to
**permission groups**. Nest permission groups into **role groups** (which
represent a job function). Assign admins to role groups via PIM:

```
Admin                Role Group              Permission Groups               Target
(the user)           (the job function)      (atomic capability)             (Entra / Azure / AU)

ADMIN-MOK-ID  --E->  PIM-ROLE-               --E--> PIM-Entra-ID-              --E--> "Application Administrator"
                     CloudEngineer                  AppAdmin-L1-T0-CP-ID                   (Entra ID role)
                                             --A--> PIM-AzDevOps-               --A--> "Build Administrator"
                                                    TeamsContrib-L2-T1-...                 (AzDevOps role)
                                             --E--> PIM-AzRes-MP-               --E--> Owner on /subscriptions/{...}
                                                    Platform-L3-T1-...                     (Azure RBAC)
                                             --E--> PIM-PowerBI-WS-             --E--> Workspace contributor
                                                    MyKPIs-L4-T2-...                       (Power BI)
```

`--E->` = Eligible (PIM activation required) · `--A->` = Active (always on)

**Why nest:**

- Onboarding a new Cloud Engineer = **one** assignment row, not 20.
- Refactor a permission group's targets → every role group using it gets
  the change for free.
- Removing an admin = one row deletion; their entire access surface
  collapses.
- The graph (admin → role → permission → target) is the audit answer to
  *"who can do X?"* — see the [Mapper](#tools).

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
  - `RoleManagement.ReadWrite.Directory` (application)
  - `Group.ReadWrite.All`, `User.ReadWrite.All`
  - For AD-syncing engines: domain credentials on the calling host.
- A Key Vault holding the SP certificate (or use the bootstrap pattern
  documented in your wrapping project).

### One-time setup

```powershell
# 1. Clone the repo on your management VM.
git clone https://github.com/KnudsenMorten/PIM4EntraPS.git
cd PIM4EntraPS

# 2. Create your customer-specific config files from the .custom.sample.* templates.
Copy-Item config\repository.custom.sample.ps1   config\repository.custom.ps1
Copy-Item config\policies.custom.sample.ps1     config\policies.custom.ps1
Copy-Item config\PIM4EntraPS.NamingConventions.custom.sample.ps1  config\PIM4EntraPS.NamingConventions.custom.ps1
Copy-Item config\PIM4EntraPS.Filters.custom.sample.ps1            config\PIM4EntraPS.Filters.custom.ps1

# 3. Optionally override any of the 14 data CSVs the same way:
Copy-Item config\PIM-Definitions-Roles.locked.csv   config\PIM-Definitions-Roles.custom.csv
# ... etc. Engine reads .custom first, falls back to .locked.

# 4. Edit launcher\<task>\LauncherConfig.custom.sample.ps1 -> LauncherConfig.custom.ps1
#    with your tenant id, app id, KV name.
```

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

---

## Tools

### Mapper — visualize the model

`tools/pim-mapper/Open-PimMapper.ps1` reads all 14 CSVs and renders an
interactive directed-graph view (admin → role group → permission group →
target) in your default browser. Click a node to see incoming/outgoing
edges + the source CSV row. Filter by layer or by edge type (Eligible /
Active). Regex search.

```powershell
.\tools\pim-mapper\Open-PimMapper.ps1
```

A 30-admin / 200-permission-group repo renders in <2 seconds, ~500
nodes, ~800 edges.

### Activator — bulk-activate from Edge

`tools/pim-activator/` is an Edge browser extension. Admin clicks the
toolbar icon, picks the PIM groups they need from a checkbox list,
enters a justification + duration, clicks **Activate**. One Graph
round-trip per group (the API requires it), but the admin sees one
click instead of N portal navigations.

Intune-deployable: a single `Install-PimActivator.ps1` writes the Edge
policy keys for force-install + per-tenant config. See
`tools/pim-activator/README.md` for the two-stage rollout.

---

## Repo layout

```
PIM4EntraPS/
  engine/
    <task-name>/<task-name>.ps1            # 15 engines, one folder each
    _shared/PIM-Functions.psm1             # canonical function library
    _shared/PIM-ContextBuilder.ps1         # Build-PimContext / Get-PimList helpers
  launcher/
    <task-name>/
      launcher.community-vm.ps1            # 4 flavors per task
      launcher.community-azure.ps1
      launcher.internal-vm.ps1
      launcher.internal-azure.ps1
      LauncherConfig.defaults.ps1          # shipped defaults
      LauncherConfig.custom.sample.ps1     # template for customer override
      launcher.manifest.json
    _lib/
      Initialize-LauncherConfig.ps1
      Start-LauncherTranscript.ps1
      Stop-LauncherTranscript.ps1
      PIM4EntraPS.shared-defaults.ps1
  config/
    *.locked.csv                           # shipped defaults (data files)
    *.custom.sample.csv                    # header-only templates
    *.custom.csv                           # gitignored: customer's actual data
    repository.custom.sample.ps1           # path mappings template
    policies.custom.sample.ps1             # PIM policy defaults template
    PIM4EntraPS.NamingConventions.locked.ps1
    PIM4EntraPS.Filters.locked.ps1
  tools/
    pim-mapper/                            # browser-based graph viewer
    pim-activator/                         # Edge extension for bulk-activate
  docs/
    DESIGN.md                              # architecture deep dive
  logs/                                    # gitignored: transcript output
  output/                                  # gitignored: engine state + delegation dumps
  VERSION
  README.md
  RELEASENOTES.md                          # curated changelog
```

---

## Documentation

- **[docs/DESIGN.md](docs/DESIGN.md)** — architectural deep dive: nesting,
  direct vs indirect delegation, naming convention, tier model, lifecycle,
  customer overrides.
- **[RELEASENOTES.md](RELEASENOTES.md)** — curated changelog (what changed
  each release + migration notes).
- **[tools/pim-mapper/](tools/pim-mapper/)** — mapper docs.
- **[tools/pim-activator/README.md](tools/pim-activator/README.md)** —
  activator extension docs (incl. Intune rollout).

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
