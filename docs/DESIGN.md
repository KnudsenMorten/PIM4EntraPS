# PIM4EntraPS — design

A walkthrough of *why* the model looks the way it does. If the README is
"what it is and how to run it", this is the "why this specific shape and
not a flatter one".

> Distilled from years of running PIM at customer scale, the **WPNinja
> NO 2025** talk "Privileged Access Strategy — Best Practices and Common
> Mistakes when Tiering Cloud and AD", and Microsoft's [RApid
> Modernization Plan
> (RAMP)](https://learn.microsoft.com/en-us/security/privileged-access-workstations/security-rapid-modernization-plan)
> + [Enterprise Access
> Model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model).
> Anything that looks opinionated here is a position taken because the
> alternative was found to fail in practice.

---

## 0. From PIM v1 to PIM v2

**PIM v1** (the early pattern): admin activates one big "Job-role" bundle
in the morning and inherits dozens of permissions at once.

```
PIM v1 -- Bundles / Compromise
"Activate Job-role in the morning and get bundles of permissions"

Admin-<Init>-ID  --Eligible-->  PIM-ROLE-IT-CloudArchitects  --Active-->  Conditional Access Administrator
                                                          --Active-->  Authentication Administrator
                                                          --Active-->  Cloud Application Administrator

Admin-<Init>-ID  --Eligible-->  PIM-DEPT-IT-Operation        --Active-->  User Administrator
```

Problems v1 was forced into:

- **Over-privilege**: activating the bundle gave permissions the admin
  didn't need *right now*.
- **Tenant-wide scope**: missing AU support / RBAC limits → "all users
  or none".
- **No project lifecycle**: consultants got the same bundle as employees,
  with no path to step them down when the project ended.
- **Hard to audit**: "who has Cond. Access Admin?" required walking
  every role-group.

**PIM v2** (this project): admin activates *only* the role group for
their current job function. That role group nests permission groups, each
of which holds **one atomic capability** scoped tightly (single Entra
role, single AU, single Azure subscription, single Power BI workspace).
The admin keeps the same "one click" daily UX, but the principle of
least privilege actually holds because the activation is granular under
the surface.

```
PIM v2 -- "Just Enough, Just In Time"
On-demand activation of the permission you need for the task you're doing.

Admin-<Init>-ID  --Eligible-->  PIM-ROLE-CloudEngineer  --Eligible-->  PIM-Entra-ID-ApplicationAdministrator-L1-T0-CP-ID  --Active-->  Entra ID role
                                                     --Active---->  PIM-AzDevOps-TeamsContributors-L5-T1-WDP-ID         --Active-->  AzDevOps role
                                                     --Eligible-->  PIM-AzRes-MP-Platform-Owner-L3-T1-MP-ID             --Active-->  Azure subscription
                                                     --Eligible-->  PIM-PowerBI-WS-<workspace>-Admins-L3-T1-WDP-ID      --Active-->  Power BI workspace
```

The rest of this document explains how the moving parts get you from v1
to v2 without burning down the world.

---

## 1. The problem

A real customer running Entra ID + Azure at scale typically has:

- **20–100 admin accounts** (separate from primary user accounts, named
  e.g. `Admin-<Init>-<Tier>-<Platform>`).
- **50+ distinct Entra ID roles** they care about (Global Admin, Auth
  Admin, App Admin, Helpdesk, etc.) — many AU-scoped to limit blast
  radius.
- **5–500 Azure subscriptions** with thousands of resource scopes.
- **PIM eligible** as the default for everything risky, so the daily
  surface is small but activation is one click away.

Doing this through the Entra portal **fails at scale** because:

| Failure mode | Why |
|---|---|
| Onboarding takes hours per admin | One PIM blade click per role × per scope. Easy to miss one. |
| Refactors are infeasible | "Add Sharepoint Admin to the SecOps role" = touch every SecOps admin individually. |
| Drift is invisible | The "intended" model lives in a spreadsheet that nobody updates. |
| Audit can't answer "who can do X?" | Requires per-scope enumeration. |
| Offboarding leaks privilege | One missed assignment = lingering access. |

PIM4EntraPS reframes the model as **declarative configuration** (CSVs) +
**imperative engine** (PowerShell) — the same pattern that turned manual
server config into Terraform.

---

## 2. The 3-tier nesting pattern

The single biggest design choice is: **admins never get assigned to
Entra ID roles or Azure RBAC scopes directly. Always through 2 layers
of groups.**

```
Tier 1: Admin                   Tier 2: Role Group            Tier 3: Permission Group              Target
        (the user)                      (job function)                (atomic capability)                   (Entra / Azure)

ADMIN-<Init>-ID  --Eligible-->  PIM-ROLE-CloudEngineer  --Eligible--> PIM-Entra-ID-AppAdmin-L1-T0-CP-ID         --Eligible--> "Application Administrator" (Entra)
                                                        --Active---->  PIM-AzDevOps-Contributors-L5-T1-WDP-ID    --Active--->  "Build Administrator" (AzDevOps)
                                                        --Eligible-->  PIM-AzRes-MP-Platform-L3-T1-MP-ID         --Eligible--> Owner on /subscriptions/{sub-id}
                                                        --Eligible-->  PIM-PowerBI-WS-<workspace>-L4-T2-USER-ID  --Eligible--> Workspace contributor
```

### Why this exact shape

| Layer | Lifecycle owner | Velocity of change |
|---|---|---|
| Tier 1 — Admin | HR / IAM team. | High: onboards / offboards monthly. |
| Tier 2 — Role group | Manager + architect. | Medium: new job function quarterly. |
| Tier 3 — Permission group | Architect. | Low: new service yearly. |
| Target | Microsoft (Entra/Azure). | Low: GA cadence. |

Each layer changes at a **different rate** and is owned by a **different
person**. Nesting separates them so a fast-changing layer (admins) doesn't
churn the slow-changing layers (permissions, targets).

### The compounding payoff

Suppose 10 Cloud Engineers each need 20 Entra roles + 5 Azure RBAC roles
across 3 management groups.

- **Direct model**: 10 × (20 + 15) = **350 PIM assignments** to maintain.
  Add a new permission → 10 edits. Offboard one engineer → 35 deletions.
- **Nested model**: 10 admin→role-group assignments + 25 role-group→
  permission-group nestings + 25 permission-group→target bindings = **60
  total**. Add a permission → 1 edit. Offboard one engineer → 1 deletion.

The ratio gets worse (in favor of nesting) as the org grows.

### Role-assignable group constraint (Entra rule, not project rule)

When the chain reaches an **Entra ID role**, the permission group on the
last hop **must** be created as a **Role-Assignable Group** (the "isAssignableToRole"
flag, set once at group creation). Within that constraint, Entra imposes
a second rule that drives the whole nested model:

> **Admins can only have an *Eligible* assignment to a role-assignable
> group. Active PIM assignments directly onto a role-assignable group
> are NOT SUPPORTED.**

This is a structural Entra limitation, not something PIM4EntraPS chooses.
Concretely, the supported and unsupported shapes are:

```
SUPPORTED:
Named Admin  --Eligible/Active-->  Entra ID Group         --Active (MemberOf)-->  Role-Assignable Group  --Eligible/Active (PIM)-->  Entra ID Role

NOT SUPPORTED:
Named Admin  --Active------------>  Role-Assignable Group  --Eligible/Active-->  Entra ID Role
```

Implications for the model:

- The Tier-2 → Tier-3 hop (role group → permission group) is always
  **Eligible** when the permission group is role-assignable. The admin
  activates the role group, which makes them an eligible member of the
  permission group, which is in turn eligibly assigned to the Entra role.
- For permission groups that target **non-Entra** resources (Azure RBAC,
  Power BI, Intune, Defender, AzDevOps), the role-assignable flag is
  not required and Active-on-the-permission-group nesting is fine.
- Once a group is created without the role-assignable flag, you cannot
  add it later — you must recreate the group. The baseline engine sets
  the flag at create time based on the CSV intent.

Don't try to design around this — every workaround ends up either
violating the constraint or duplicating groups.

---

## 3. Direct vs indirect delegation

**Direct delegation**: principal (user) has an assignment to a resource
(Entra role or Azure scope) recorded directly against that resource.

**Indirect delegation**: principal is a member of a group; the group has
the assignment; member inherits via group membership transitively.

PIM4EntraPS is **indirect-by-design** with one exception:

| Use case | Delegation type | Why |
|---|---|---|
| Daily admin work | Indirect (always) | Refactorable, auditable, offboard-safe. |
| **Break-glass accounts** | Direct (1–2 total) | Must work when Graph/PIM is unavailable. Recovery path. |

The break-glass exception is treated as a separate concern — those
accounts live in a small dedicated `Account-Definitions-BreakGlass.csv`
and are wired by the launcher / bootstrap, not by the baseline engine.
Their existence is intentional design, not an exception to debate.

### Why not direct for normal admins?

| Problem with direct | Indirect handles it how |
|---|---|
| Refactoring requires touching every admin | Edit the permission group once; all admins inherit. |
| Audit ("who has Owner on sub X?") needs full graph traversal anyway | Same lookup, but in CSV — fast and visible. |
| Offboarding scope unbounded | Delete admin row → all reach disappears in one step. |
| Permission drift between admins doing the "same job" | Membership in the role group is the source of truth. |
| AU-scoped roles can't be group-nested in old Entra | **Solved** in 2023+; PIM4EntraPS uses the modern API. |

---

## 4. Naming convention

Permission group names encode their **scope + tier + service** so you can
read intent off the name without opening any CSV:

```
PIM-<Service>-<Name>-L<Level>-T<Tier>-<Code>-<Domain>[-S_AD]

PIM-Entra-ID-AppAdmin-L1-T0-CP-ID
    └────┬────┘ └──┬──┘ ┬  ┬  ┬   ┬
         │        │   │  │  │   │
         │        │   │  │  │   └── Domain: ID (Identity) / RES (Resource) / DAT (Data)
         │        │   │  │  └── Code:   CP / WDP / MP / APP / USER  (see § 5.1)
         │        │   │  └── Tier:   T0/T1/T2 (Microsoft Enterprise Access Model)
         │        │   └── Level:  L0-L9 (maps to tier — see § 5.2)
         │        └── Capability name (free-form, human-readable)
         └── Microsoft service the perm targets
```

`<Code>` is one of `CP` (Control Plane), `WDP` (Workload / Data Plane),
`MP` (Management Plane), `APP` (App Access), `USER` (User Access). The
tier↔code pairings are fixed — see § 5.1.

`<Domain>` is one of:
- `ID` — Identity-plane perms (Entra ID roles, Intune RBAC, etc.).
- `RES` — Resource-plane perms (Azure RBAC on subscriptions / management
  groups / resource groups).
- `DAT` — Data-plane perms (Power BI workspace contents, SharePoint
  sites, etc.).

**`-S_AD` suffix**: appended *after* `<Domain>` when the permission
group is synced down to on-prem AD by the PIM4ActiveDirectoryPS companion
(see Section 14). Example: `PIM-AD-DomainAdministrators-L1-T0-CP-ID-S_AD`.
The suffix is the contract the AD-side script keys off — same group
name on both sides of the sync.

Generated from `$global:PIM_NamingConventions.PimGroupPattern` in
`config/PIM4EntraPS.NamingConventions.locked.ps1`. Customers override the
pattern via the `.custom.ps1` sibling.

### Why bake the pattern into the name

The Mapper can color-code by tier without a separate lookup. KQL/Log
Analytics queries against sign-in / PIM audit logs can `parse displayName`
to bucket by tier/service/domain. Onboarding new admins, you derive the
group name from a worksheet — no creative-naming required, no name
collisions.

---

## 5. Tier model (Microsoft Enterprise Access Model)

Aligned with [Microsoft's Enterprise Access
Model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model).

### 5.1 Tier acronyms (planes)

The tier is one of three values; the **acronym** (the `<Code>` part of
the permission-group name) tells you *which plane within that tier* the
group lives in:

| Tiering | Acronym | Plane | Purpose |
|---|---|---|---|
| **T0** | `T0-CP` | Control Plane | Global roles + services like Conditional Access. |
| **T1** | `T1-WDP` | Workload / Data Plane | Business data or application. |
| **T1** | `T1-MP` | Management Plane | Management platform (logging, security, identity, connectivity). Cross-platform. |
| **T2** | `T2-APP` | App Access | Read/write specific data — e.g. partner integration. |
| **T2** | `T2-USER` | User Access | User access to a service — e.g. Power BI platform. |

`<Code>` in the naming convention (Section 4) enumerates exactly
`CP / WDP / MP / APP / USER` (uppercase in the group-name string; the
CSV `<Code>` column stores the title-case form `CP / WDP / MP / App /
User`). Any other value is a typo.

### 5.2 Delegation levels (L0–L9 map deterministically to a tier)

Levels are **not** an independent axis. The level number determines the
tier:

| Level | Tier | Name | What sits here | Example (generic) |
|---|---|---|---|---|
| **L0** | T0 | High Privileged Global Role | The single most-powerful role per directory. | Entra ID **Global Administrator**; AD **Forest Administrator**. |
| **L1** | T0 | Global Role Admins | All other directory-wide roles. | All ~100 Entra tenant roles except GA (Auth Admin, Cond. Access Admin, Power Platform Admin, etc.); AD **Domain Administrator**. |
| **L2** | T0 | Scoped Role Admins | The same global roles, but scoped to an Administrative Unit / OU instead of tenant-wide. | Entra User Admin scoped to AU `<scope>`; AD permissions delegated to OU `<scope>`. |
| **L3–L9** | T1 | Service Admins | Workload- and data-plane roles inside individual services (their **native** RBAC). | Intune RBAC role; Defender XDR RBAC role; Power BI workspace admin; Azure DevOps project admin; Azure resource Owner / Contributor on a management group, subscription, or resource group. |

The L3–L9 range exists so one service can have several rungs on the
ladder (`L3 = Functions/Tasks Admin`, `L4 = User Support`, `L5 = Reader`,
etc. inside the same service) without colliding with another service's
levels. Picking which sub-level a given role lives at is a per-service
decision documented alongside the service in the model.

T2 levels (App Access / User Access) are also expressed as L-numbers
inside the T1 range when a service exposes both an admin plane and an
end-user data plane — see e.g. Power BI master-data Build / Read / Share
delegations that ship at `L4-T2-USER-ID`.

### 5.3 Where the tier surfaces

- The permission-group name (`-T0-CP-` / `-T1-MP-` / `-T1-WDP-` /
  `-T2-APP-` / `-T2-USER-`).
- The admin account name (`Admin-<Init>-<Tier>-<Platform>`).
- The CSV column `TierLevel` on definitions and assignments.

**Enforcement (planned, not in v1.0)**: the Mapper's **tier-safety lint**
flags any nesting where a T0 admin reaches a T1 asset (or worse, the
other direction), and any level↔tier mismatch (e.g. an `L1` group tagged
`T1`). The engine doesn't currently block tier crossings — the convention
is "you'll see them in the lint, then fix the CSV".

---

## 6. Lifecycle states (Initial → Pilot → Prod)

PIM-for-Groups policies, Conditional Access policies, and (optionally)
group-membership rollout follow a 5-stage progression:

```
Initial   →   Pilot1   →   Pilot2   →   Pilot3   →   Prod
(no users)    (1 admin)    (small)      (large)      (everyone)
```

The convention uses **policy name prefix** to distinguish stages:

```
CA006-Initial-Global-AllApps-AnyPlatform-HighUserRisk-Block
CA006-Pilot1-...
CA006-Pilot2-...
CA006-Pilot3-...
CA006-Prod-...
```

The engine + CSVs support per-stage policy targeting. The same `CA006`
intent ships as 5 parallel policies; you migrate users between them as
you gain confidence. When you're happy, decommission the Initial / Pilot
policies and keep only `Prod`.

PIM4EntraPS doesn't dictate the lifecycle states — your governance
process does. The tool just supports them by *not* assuming a flat name.

---

## 7. The "as-code" pattern

```
┌──────────────┐        ┌──────────────┐
│  CSV files   │   ─→   │   Engine     │   ─→   Microsoft Graph
│ (desired)    │        │ (imperative) │        Microsoft Azure RBAC
└──────────────┘        └──────┬───────┘        Microsoft Exchange Online
                               │
                               ▼
                        ┌──────────────┐
                        │  output/     │
                        │ *_LastApplied│
                        │ *_Delta      │
                        └──────────────┘
```

**Desired state**: 14 CSVs under `config/`. Customer-owned, version-controlled.

**Imperative engine**: reads CSVs, queries the tenant for current state,
computes the delta (per-row: add / update / remove / no-action), applies
each via Graph / RBAC / Exchange.

**LastApplied snapshot**: after a successful run, the engine writes
`output/<csv-base>_LastApplied.csv` — a copy of what *was* applied.
Used by:
- Next run's delta detection (skip rows that haven't changed).
- The Mapper's **diff vs LastApplied** view (planned).
- Audit (git-able if you want to track changes outside the repo).

**Delta files**: `<csv-base>_Delta.csv` records what changed in each run
for after-the-fact review.

### Idempotency

Every operation is "**check exists → if same, skip; if different, modify;
if missing, create**". A run that produces zero changes prints "Mode:
NoAction" for every row and exits clean. Re-runnable, safe to schedule.

### `-WhatIfMode`

Every launcher accepts `-WhatIfMode`. Engines respect it for *destructive*
operations (account create, PIM assignment create/delete, group nesting
change). Read-only operations (list users / groups / roles, snapshot
current state) always run.

---

## 8. Customer override pattern (`.locked` / `.custom` / `.custom.sample`)

Every shipped artifact follows a 3-file pattern:

```
config/PIM-Definitions-Roles.locked.csv         ← ships in repo (the baseline)
config/PIM-Definitions-Roles.custom.csv         ← gitignored (customer's data)
config/PIM-Definitions-Roles.custom.sample.csv  ← header-only template for new installs
```

**At runtime**: the engine prefers `.custom.csv` if it exists, falls back
to `.locked.csv` otherwise. So:

- **No override**: customer uses the baseline as-is.
- **Light tweak**: customer copies `.custom.sample.csv` → `.custom.csv`,
  fills in their own rows. Baseline `.locked.csv` is ignored entirely.
- **Heavy customization**: same as light, just bigger.

The `.custom.csv` is **gitignored** — it lives only on the customer's VM
and is never accidentally pushed. The `.custom.sample.csv` is **tracked**
in the repo so future installs always have a template to copy from.

Special files (helpers, not data tables): `repository.custom.ps1` and
`policies.custom.ps1` follow the same pattern but without a `.locked.*`
default — they're customer-specific by nature (CSV path overrides, PIM
policy values).

### Why not just one editable file?

- Customer can `git pull` the repo for engine updates without merge
  conflicts on their data.
- Defaults stay visible (read `.locked` when in doubt about what the
  baseline does).
- New CSVs added in a release get a `.custom.sample` template — no
  silent gaps when an upgrade adds a column.

---

## 9. Engine taxonomy

| Engine | Reads | Writes | Frequency |
|---|---|---|---|
| `PIM-Baseline-Management-CSV` | All 14 CSVs | Tenant PIM state (full sync) | Hourly / daily |
| `PIM-Baseline-Management-CSV-<X>Only` | Subset of CSVs | Subset of tenant (faster iteration) | Ad-hoc |
| `PIM-Baseline-Management-SQL` | Azure SQL tables | Tenant PIM state | Same as CSV variant |
| `PIM-Assignment-Exporter` | Tenant | CSV snapshot under `output/` | Daily |
| `PIM-Assignment-Wizard` | CSV + interactive prompts | Tenant | Manual |
| `PIM-Assignment-Revoker` | Tenant | Active activations (revoke) | Incident response |
| `Check-PIM-Groups-IsRoleAssignable` | Tenant | (diagnostic stdout) | Ad-hoc |
| `GetNumberOfROles` | Tenant | (diagnostic stdout) | Ad-hoc |

The `*-Only` variants exist for **fast iteration during model development**:
when you're adding 5 new permission groups, you don't need to run the
full 11-step pipeline + AU update + account create + every role
binding — you run `PIM-Baseline-Management-CSV-EntraIDRolesOnly` and
loop.

---

## 10. Launcher flavors (the 4-up matrix)

Every engine is wrapped in 4 launchers:

| | VM (long-running host) | Azure (serverless) |
|---|---|---|
| **Internal** | `launcher.internal-vm.ps1` | `launcher.internal-azure.ps1` |
| **Community** | `launcher.community-vm.ps1` | `launcher.community-azure.ps1` |

- **Internal vs Community**: internal launchers may depend on a
  vendor's bootstrap library (Key Vault wiring, gMSA handling). Community
  launchers use only public Microsoft modules — installable from PSGallery
  by anyone.
- **VM vs Azure**: VM launchers do interactive console + transcript log
  to `logs/`. Azure launchers use managed identity, log to App Insights,
  and skip anything that needs on-prem AD.

The public repo (this mirror) ships only the **community** launchers
(internal-* files are stripped by the publish workflow). The engine code
itself is identical across flavors.

---

## 11. Companion tools

### Mapper (`tools/pim-mapper/`)

Read-only graph viewer for the 14-CSV model. Loads in any browser,
no server required, no install on the customer's VM beyond `git pull`.

Roadmap:

- **v0.1 (now)**: read-only DAG viewer with side panel.
- **v0.2**: edit + save (`.custom.csv` only, diff preview before commit).
- **v0.3**: pre-flight validator (missing GroupTag detector, stale Entra
  role detector, tier-safety lint).
- **v0.4**: live tenant overlay (CSV vs tenant drift).
- **v0.5**: new-admin wizard + tag global-rename.
- **v0.6**: one-click engine run from GUI.

See [tools/pim-mapper/](../tools/pim-mapper/) for the current state.

### Activator (`tools/pim-activator/`)

Edge browser extension. Admin clicks the toolbar icon → list of eligible
PIM-for-Groups assignments → multi-select → enter justification + duration
→ **Activate**. Replaces clicking through the PIM portal one role at a
time.

Two-stage rollout:

1. **One-time per tenant**: `Install-PimActivatorAppRegistration.ps1`
   creates the app registration with the right delegated permissions.
2. **Per PAW**: `Install-PimActivator.ps1` writes Edge enterprise policy
   keys (force-install + per-tenant config). Intune-deployable
   unattended.

See [tools/pim-activator/README.md](../tools/pim-activator/README.md).

---

## 12. Project-based delegations (`PIM-PROJECT-*`)

External consultants and developers come and go. Their access should be
**visibly temporary** in the model itself, so an offboarding review can
find and remove it without guesswork.

The convention: any permission group that exists to serve a specific,
time-bounded project gets a `PIM-PROJECT-` prefix in the name. Same
naming convention otherwise:

```
PIM-PROJECT-AzRes-LZ-mg-<scope>-Owner-L5-T1-WDP-ID   ← project-scoped (Active during engagement)
PIM-AzRes-LZ-mg-<scope>-Owner-L5-T1-WDP-ID           ← maintenance equivalent (Eligible after engagement)
```

The two-group pattern is intentional. During the project the developer
needs **Active** standing access (constant deploys, debugging, on-call):

```
ADMIN-<Init>-ID  --Eligible-->  PIM-ROLE-Developer-IT  --Active-->  PIM-PROJECT-AzRes-LZ-mg-<scope>-Owner-L5-T1-WDP-ID  --Active-->  Owner on /subscriptions/{...}
```

When the project ends, the lifecycle step downgrades them to the
maintenance group with an **Eligible** assignment — they keep the
ability to step into the scope for a hotfix, but no longer carry the
permission by default:

```
ADMIN-<Init>-ID  --Eligible-->  PIM-ROLE-Developer-IT  --Eligible-->  PIM-AzRes-LZ-mg-<scope>-Owner-L5-T1-WDP-ID  --Active-->  Owner on /subscriptions/{...}
```

Why this matters:

- The `PIM-PROJECT-` prefix is greppable. "Show me every project
  assignment older than 6 months" is one CSV filter.
- Revocation at project end is a single row delete (the
  `PIM-PROJECT-...` row) — the maintenance group continues to serve
  whoever is still on the team.
- The active vs eligible split makes the *intent* of "they're working
  on this right now" vs "they might need to look at it later" visible
  to auditors without reading code.

The naming rule is firm: **only the project-scoped group carries the
`PROJECT` infix**. The maintenance equivalent uses the plain name. Don't
ship a `PIM-PROJECT-...-Maintenance` group — that defeats the lifecycle
filter.

---

## 13. Common pitfalls / lessons learned

Collected from years of running PIM at customer scale (and from watching
PIM v1 designs grow into PIM v2 the hard way). Each entry is one or two
sentences on *what goes wrong*, then one sentence on *what PIM4EntraPS
does about it*.

### Over-privilege

- **Tenant-wide perms when AU / RBAC scoping would do.** Granting a
  helpdesk admin tenant-wide User Administrator because "AU support
  felt new" — they now reset passwords on Global Admins by accident.
  *PIM4EntraPS bakes AU and RBAC scoping into the permission-group
  definition; the L2 (Scoped Role Admin) tier exists for exactly this.*
- **PIM v1 bundles instead of v2 atomic activation.** A "Cloud
  Architect" bundle that lights up 10 Entra roles in one click — the
  admin needs one of them at any given time.
  *PIM4EntraPS nests one role group over many single-capability
  permission groups; the admin activates only what the task needs.*

### Missing service-level RBACs

- **Defaulting to Entra ID roles instead of the service's own RBAC.**
  Granting "Intune Administrator" tenant-wide instead of the Intune
  RBAC role scoped to a device group; granting "Power BI Administrator"
  instead of a workspace role; same story for Defender RBAC, Azure
  DevOps RBAC, SharePoint, Exchange, etc.
  *Each modern service has a richer per-service RBAC than its Entra-wide
  equivalent. PIM4EntraPS ships definitions and engines for the
  service-native RBACs (see Section 9), so the default path is the
  fine-grained one.*

### Usage documentation gaps

- **Nobody can answer "what does activating PIM-ROLE-X actually let me
  do?"** The Admin → Role group → Permission group → Service chain is
  documented nowhere; new joiners learn by guessing.
  *The Mapper (`tools/pim-mapper`) is the answer — it reads the CSVs and
  shows the full chain visually, with a tier-coloured DAG.*

### Role-group misuse

- **Same role group for internals and consultants.** Once a consultant
  inherits "PIM-ROLE-CloudArchitects", offboarding them takes a careful
  audit of everything the role nests — easy to miss a cascading perm.
  *Project work uses the `PIM-PROJECT-*` pattern from Section 12;
  internals and externals never share a role group.*
- **No Tier-0 vs Tier-1 separation.** Day-to-day admin work runs out of
  a Global Administrator account.
  *The naming and tier model (Section 5) make Tier-0 visibly separate;
  the convention is one Tier-0 admin account per person, used only for
  L0/L1/L2 tasks.*

### Scaling

- **Ignoring legacy AD.** All the effort goes into cloud PIM; on-prem
  Domain Admin remains a permanent assignment because "AD doesn't do
  PIM".
  *PIM4ActiveDirectoryPS (Section 14) plugs that gap by using Entra PIM
  as the session initiator and the Windows Server 2016+ TTL feature on
  the AD side.*
- **Not designing for 1:N / multi-cloud.** The model assumes a single
  Entra tenant and a single Azure subscription tree.
  *The CSV schema carries tenant ID and subscription ID per row;
  multi-tenant rollout is per-CSV, not per-engine-rewrite.*
- **"Island" directories.** Services with their own user store (some
  partner platforms, some SaaS) get ignored by the central model.
  *The naming convention's `<Service>` slot is open — the model
  accommodates an island as soon as someone writes the engine binding
  for it.*

### Lifecycle

- **No offboarding review.** Eligible assignments that survived the
  person leaving.
  *The Exporter + Mapper together let you diff "current eligible
  assignments" against "current admins" on demand; the project-prefix
  convention narrows the review to a known subset.*
- **Admin accounts losing license → mail-dependent automation breaks.**
  PIM activation requires no mailbox, but downstream approval flows,
  break-glass notifications, and access reviews all do.
  *Account definitions carry an explicit `LicenseSku` column; the
  baseline engine reports drift.*
- **Per-service rollout incomplete.** PIM is deployed on Entra and
  Azure but never on Power BI / Defender / Intune / AzDevOps.
  *PIM4EntraPS treats every service as a peer in the engine taxonomy;
  the same CSV pattern + same engine shape covers all of them.*
- **Group confusion (synced vs cloud-only).** A group named
  identically in on-prem AD and in Entra; someone assigns a PIM role
  to the wrong one.
  *The `-S_AD` suffix in the naming convention makes the synced
  groups visibly different from cloud-only ones.*

---

## 14. PIM for AD (companion: PIM4ActiveDirectoryPS)

PIM for Entra ID is well-supported by Microsoft. PIM for **on-prem
Active Directory** is not — there is no Microsoft-shipped equivalent.
The PIM4ActiveDirectoryPS companion project closes that gap by using
Entra PIM as the **session initiator** and propagating the activation
into AD with a time-to-live.

### Architecture

```
Active Directory                                Entra ID
Admin-<Init>-AD       <-- no sync, either way -->     Admin-<Init>-ID
                       (admin OUs excluded from
                        Entra Connect; no
                        writeback ID → AD)

PIM-AD-...-S_AD       <-- groups created                PIM-AD-...-S_AD
  (local AD group)        identically-named on             (Entra ID group)
                          both sides
                                                            ▲
                                                            │  Read groups (*-S_AD)
                                                            │  Read PIM sessions (WHO, TTL)
                                                            │
                                                     ┌──────┴───────┐
                                                     │  PIM for AD  │
                                                     │  (PS script) │
                                                     │ continuously │
                                                     │     loops    │
                                                     └──────┬───────┘
                                                            │
                            5: Modify AD group membership   │
                               (Add/Remove with TTL)        │
                                                            ▼
                                       Add-ADGroupMember -MemberTimeToLive ...
```

Concretely:

1. **Separate accounts.** Each person has a distinct AD admin account
   (`Admin-<Init>-AD`) and an Entra admin account (`Admin-<Init>-ID`).
   Same human, two identities — no shared password, no synced object.
2. **No directory sync.** The OUs containing admin accounts are
   excluded from Entra Connect. There is no writeback from Entra ID to
   AD. Groups and accounts on each side are local-only.
3. **Identically-named groups on both sides.** A group like
   `PIM-AD-DomainAdministrators-L1-T0-CP-ID-S_AD` exists once in Entra
   (as a PIM-eligible role group) and once in AD (as a real Domain
   Admins-nested group). The `-S_AD` suffix marks both.
4. **Continuously-looping PowerShell script.** On a domain-joined host
   with AD admin creds, the script:
   - Reads all `PIM-AD-*-S_AD` groups in Entra ID.
   - Reads currently **active** PIM sessions for each group (member +
     remaining TTL).
   - Identifies the corresponding AD account (`Admin-<Init>-AD`) from
     the naming convention.
   - Adds the AD account to the matching AD group with
     `Add-ADGroupMember -MemberTimeToLive <span>` so AD itself enforces
     the expiry.
5. **Auto-correction loop.** If TTL drift exceeds **±2 minutes** (the
   AD-side TTL has drifted vs the Entra session's remaining time), the
   script re-aligns by removing and re-adding with the corrected TTL.
   If the user manually deactivates their Entra PIM session, the next
   loop iteration removes the AD group membership.

### Forest requirements

PIM-style TTL on AD group membership uses the **Privileged Access
Management** optional feature, introduced at the Windows Server 2016
forest functional level. Supported DC OS: Windows Server 2016, 2019,
2022.

Verify:

```powershell
Get-ADOptionalFeature -filter "name -eq 'privileged access management feature'"
```

Enable (once per forest, irreversible):

```powershell
Enable-ADOptionalFeature 'Privileged Access Management Feature' `
    -Scope ForestOrConfigurationSet `
    -Target <domain>
```

### Why a separate project (not part of PIM4EntraPS)

- **Runtime profile is different.** PIM for AD needs a long-running
  service on a domain controller or domain-joined management host with
  AD admin credentials cached at the process. PIM4EntraPS is a stateless
  engine that runs from any host with Graph access (Function App, Logic
  App, scheduled VM job, ad-hoc laptop).
- **Customer scope is different.** Many PIM4EntraPS customers run
  cloud-only or are aggressively retiring on-prem AD. Forcing them to
  deploy AD components they don't need would be wrong.
- **Failure modes are different.** PIM4EntraPS failures are CSV-vs-tenant
  drift, fixable by re-running the engine. PIM for AD failures can
  leave a person without TTL'd membership at 3am — the operational
  posture (monitoring, alerting, restart) is closer to a service than
  to a batch job.

Repository: <https://github.com/KnudsenMorten/PIM4ActiveDirectoryPS>.

---

## 15. Companion projects

A small ecosystem of related open-source projects, all owned by the
same author (Morten Knudsen) and designed to be combinable:

- **[PIM4ActiveDirectoryPS](https://github.com/KnudsenMorten/PIM4ActiveDirectoryPS)**
  — automation of PIM for on-prem AD; uses Entra PIM as the session
  initiator and propagates time-bounded membership into AD via the
  Windows Server 2016+ PAM feature. See Section 14 for the architecture.
- **[EntraPolicySuite](https://github.com/KnudsenMorten/EntraPolicySuite)**
  — CLI management of Entra Conditional Access policies, named
  locations, and authentication strengths; ships with 120+ curated CA
  policies. The natural pair for PIM4EntraPS because CA is what gates
  PIM activation.
- **[PIM-Role-Advisor](https://github.com/KnudsenMorten/PIM-Role-Advisor)**
  — given a task the admin wants to perform, recommends the smallest
  PIM role / permission group that grants it. Closes the "which group
  do I activate?" gap that the Mapper diagnoses structurally.

---

## 16. What PIM4EntraPS is *not*

- **Not a replacement for Conditional Access**. PIM activation is gated
  by CA policy at the tenant level. PIM4EntraPS doesn't configure CA.
- **Not a replacement for Privileged Access Workstations**. The model
  assumes admins use PAWs; PIM4EntraPS doesn't deploy them.
- **Not a SIEM / detection tool**. It builds and maintains the *intended*
  PIM model. Detecting misuse is downstream (Microsoft Sentinel, Defender
  for Identity).
- **Not a self-service portal**. The Activator extension is for admins
  who already have eligible assignments; PIM4EntraPS doesn't grant new
  eligibility on user request — that's an approvals workflow problem
  better solved by Entra ID Governance access packages.

---

## 17. Trade-offs / known gaps

| Trade-off | Why we accepted it |
|---|---|
| Per-group Graph calls for PIM-for-Groups (no tenant-wide list endpoint) | Microsoft Graph still requires `$filter=groupId eq …` per call. Cached via the Exporter → CSV pattern; `$batch` to 20-up is the throttle ceiling. |
| Azure RBAC eligible state isn't in Azure Resource Graph | ARG only exposes permanent + active assignments. Eligible must come from ARM REST per-scope. Same cache pattern. |
| Engine doesn't gate every destructive op on `-WhatIfMode` (some legacy paths) | Being incrementally hardened. New code added under the WhatIf guard pattern from day one. |
| 14 CSVs feels like a lot | Each is small (10–500 rows typically) and represents one clean concept. Merging two would couple their schemas. |
| No web UI for editing CSVs (yet) | The Mapper v0.2 closes this. Until then, Excel or VS Code's CSV preview. |

---

## 18. Where to read next

- **[../README.md](../README.md)** — landing / quick start.
- **[../RELEASENOTES.md](../RELEASENOTES.md)** — what changed each release.
- **[../tools/pim-mapper/](../tools/pim-mapper/)** — graph viewer.
- **[../tools/pim-activator/README.md](../tools/pim-activator/README.md)** — Edge extension + Intune rollout.
- Companion projects (see Section 15):
  [PIM4ActiveDirectoryPS](https://github.com/KnudsenMorten/PIM4ActiveDirectoryPS)
  · [EntraPolicySuite](https://github.com/KnudsenMorten/EntraPolicySuite)
  · [PIM-Role-Advisor](https://github.com/KnudsenMorten/PIM-Role-Advisor)
- Microsoft Learn: [Enterprise Access
  Model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
  · [PIM for Groups (preview → GA
  history)](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/concept-pim-for-groups)
  · [Conditional Access + PIM
  integration](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings)
- [Rapid Modernization Plan
  (RAMP)](https://learn.microsoft.com/en-us/security/privileged-access-workstations/security-rapid-modernization-plan).
