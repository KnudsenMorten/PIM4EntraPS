# PIM4EntraPS — design

This is the **single design document** for PIM4EntraPS: the architecture and how
the **built** system works (the model, the engine, providers, identity/auth,
delegation, scale, hosting/runtime, containers, the MSP edition, the SQL/data
model, workload connectors, lifecycle/governance, the Manager GUI + UX,
licensing, the Entra group/app catalog, notifications, and the activation
use-cases). It absorbs what used to live across ten separate topic docs. The
**backlog / requirements** (every want, idea, constraint, out-of-scope item, and
its `◻`/`🟡`/`✅` status) lives in `REQUIREMENTS.md` — *not here*. **Test
procedures and the test-suite inventory** live in `TESTS.md` — this doc only
points at them. Anything that looks opinionated here is a position taken because
the alternative was found to fail in practice.

> Distilled from years of running PIM at customer scale, the **WPNinja NO 2025**
> talk "Privileged Access Strategy — Best Practices and Common Mistakes when
> Tiering Cloud and AD", and Microsoft's [Rapid Modernization Plan
> (RAMP)](https://learn.microsoft.com/en-us/security/privileged-access-workstations/security-rapid-modernization-plan)
> + [Enterprise Access
> Model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model).

---

## Table of contents

1. [From PIM v1 to PIM v2](#1-from-pim-v1-to-pim-v2)
2. [The problem](#2-the-problem)
3. [Core model — nesting, delegation, naming, tiers, lifecycle states](#3-core-model)
4. [The "as-code" pattern + customer override files](#4-the-as-code-pattern--customer-override-files)
5. [Engine core & pipeline](#5-engine-core--pipeline)
6. [Providers (per-scope appliers)](#6-providers-per-scope-appliers)
7. [Identity, auth & engine configuration](#7-identity-auth--engine-configuration)
8. [Scale, performance & resilience (lean context)](#8-scale-performance--resilience-lean-context)
9. [Delegation model — group-centric, portal-admins, personas](#9-delegation-model)
10. [Notifications](#10-notifications)
11. [Hosting & runtime (single-tenant, two-plane topology, execution model)](#11-hosting--runtime)
12. [Containers](#12-containers)
13. [MSP architecture (two planes, signed courier, profiles)](#13-msp-architecture)
14. [SQL / data model](#14-sql--data-model)
15. [Workload connectors](#15-workload-connectors)
16. [Entra group / app catalog](#16-entra-group--app-catalog)
17. [Lifecycle & governance](#17-lifecycle--governance)
18. [Manager / GUI + UX](#18-manager--gui--ux)
19. [Licensing — Core (free) + Pro (offline)](#19-licensing)
20. [Launcher flavors](#20-launcher-flavors)
21. [Companion tools & projects](#21-companion-tools--projects); [PIM for AD](#211-pim-for-ad-companion-pim4activedirectoryps)
22. [Activation use-cases](#22-activation-use-cases)
23. [What PIM4EntraPS is not](#23-what-pim4entraps-is-not)
24. [Trade-offs / known gaps](#24-trade-offs--known-gaps)
25. [Testing strategy](#25-testing-strategy)
26. [Where to read next](#26-where-to-read-next)

---

## 1. From PIM v1 to PIM v2

**PIM v1** (the early pattern): admin activates one big "Job-role" bundle in the
morning and inherits dozens of permissions at once.

```
PIM v1 -- Bundles / Compromise
"Activate Job-role in the morning and get bundles of permissions"

Admin-<Init>-ID  --Eligible-->  PIM-ROLE-IT-CloudArchitects  --Active-->  Conditional Access Administrator
                                                          --Active-->  Authentication Administrator
                                                          --Active-->  Cloud Application Administrator

Admin-<Init>-ID  --Eligible-->  PIM-DEPT-IT-Operation        --Active-->  User Administrator
```

Problems v1 was forced into:

- **Over-privilege**: activating the bundle gave permissions the admin didn't
  need *right now*.
- **Tenant-wide scope**: missing AU support / RBAC limits → "all users or none".
- **No project lifecycle**: consultants got the same bundle as employees, with
  no path to step them down when the project ended.
- **Hard to audit**: "who has Cond. Access Admin?" required walking every
  role-group.

**PIM v2** (this project): admin activates *only* the role group for their
current job function. That role group nests permission groups, each of which
holds **one atomic capability** scoped tightly (single Entra role, single AU,
single Azure subscription, single Power BI workspace). The admin keeps the same
"one click" daily UX, but least privilege actually holds because the activation
is granular under the surface.

```
PIM v2 -- "Just Enough, Just In Time"
On-demand activation of the permission you need for the task you're doing.

Admin-<Init>-ID  --Eligible-->  PIM-ROLE-CloudEngineer  --Eligible-->  PIM-Entra-ID-ApplicationAdministrator-L1-T0-CP-ID  --Active-->  Entra ID role
                                                     --Active---->  PIM-AzDevOps-TeamsContributors-L5-T1-WDP-ID         --Active-->  AzDevOps role
                                                     --Eligible-->  PIM-AzRes-MP-Platform-Owner-L3-T1-MP-ID             --Active-->  Azure subscription
                                                     --Eligible-->  PIM-PowerBI-WS-<workspace>-Admins-L3-T1-WDP-ID      --Active-->  Power BI workspace
```

---

## 2. The problem

A real customer running Entra ID + Azure at scale typically has:

- **20–100 admin accounts** (separate from primary user accounts, named e.g.
  `Admin-<Init>-<Tier>-<Platform>`).
- **50+ distinct Entra ID roles** they care about — many AU-scoped to limit blast
  radius.
- **5–500 Azure subscriptions** with thousands of resource scopes.
- **PIM eligible** as the default for everything risky, so the daily surface is
  small but activation is one click away.

Doing this through the Entra portal **fails at scale**:

| Failure mode | Why |
|---|---|
| Onboarding takes hours per admin | One PIM blade click per role × per scope. Easy to miss one. |
| Refactors are infeasible | "Add Sharepoint Admin to the SecOps role" = touch every SecOps admin individually. |
| Drift is invisible | The "intended" model lives in a spreadsheet that nobody updates. |
| Audit can't answer "who can do X?" | Requires per-scope enumeration. |
| Offboarding leaks privilege | One missed assignment = lingering access. |

PIM4EntraPS reframes the model as **declarative configuration** (CSVs, or SQL —
see §14) + **imperative engine** (PowerShell) — the same pattern that turned
manual server config into Terraform.

---

## 3. Core model

### 3.1 The 3-tier nesting pattern

The single biggest design choice: **admins never get assigned to Entra ID roles
or Azure RBAC scopes directly. Always through 2 layers of groups.**

```
Tier 1: Admin                   Tier 2: Role Group            Tier 3: Permission Group              Target
        (the user)                      (job function)                (atomic capability)                   (Entra / Azure)

ADMIN-<Init>-ID  --Eligible-->  PIM-ROLE-CloudEngineer  --Eligible--> PIM-Entra-ID-AppAdmin-L1-T0-CP-ID         --Eligible--> "Application Administrator" (Entra)
                                                        --Active---->  PIM-AzDevOps-Contributors-L5-T1-WDP-ID    --Active--->  "Build Administrator" (AzDevOps)
                                                        --Eligible-->  PIM-AzRes-MP-Platform-L3-T1-MP-ID         --Eligible--> Owner on /subscriptions/{sub-id}
                                                        --Eligible-->  PIM-PowerBI-WS-<workspace>-L4-T2-USER-ID  --Eligible--> Workspace contributor
```

**Why this exact shape** — each layer changes at a different rate and is owned by
a different person, so a fast-changing layer doesn't churn the slow-changing
ones:

| Layer | Lifecycle owner | Velocity of change |
|---|---|---|
| Tier 1 — Admin | HR / IAM team. | High: onboards / offboards monthly. |
| Tier 2 — Role group | Manager + architect. | Medium: new job function quarterly. |
| Tier 3 — Permission group | Architect. | Low: new service yearly. |
| Target | Microsoft (Entra/Azure). | Low: GA cadence. |

**The compounding payoff.** Suppose 10 Cloud Engineers each need 20 Entra roles +
5 Azure RBAC roles across 3 management groups.

- **Direct model**: 10 × (20 + 15) = **350 PIM assignments**. Add a permission →
  10 edits. Offboard one engineer → 35 deletions.
- **Nested model**: 10 admin→role-group + 25 role-group→permission-group + 25
  permission-group→target = **60 total**. Add a permission → 1 edit. Offboard one
  engineer → 1 deletion.

The ratio gets worse (in favor of nesting) as the org grows.

#### Role-assignable group constraint (Entra rule, not project rule)

When the chain reaches an **Entra ID role**, the permission group on the last hop
**must** be a **Role-Assignable Group** (the `isAssignableToRole` flag, set once
at group creation). Within that constraint Entra imposes a second rule that drives
the whole nested model:

> **Admins can only have an *Eligible* assignment to a role-assignable group.
> Active PIM assignments directly onto a role-assignable group are NOT
> SUPPORTED.**

```
SUPPORTED:
Named Admin  --Eligible/Active-->  Entra ID Group         --Active (MemberOf)-->  Role-Assignable Group  --Eligible/Active (PIM)-->  Entra ID Role

NOT SUPPORTED:
Named Admin  --Active------------>  Role-Assignable Group  --Eligible/Active-->  Entra ID Role
```

Implications:

- The Tier-2 → Tier-3 hop is always **Eligible** when the permission group is
  role-assignable. The admin activates the role group, which makes them an
  eligible member of the permission group, which is in turn eligibly assigned to
  the Entra role.
- For permission groups targeting **non-Entra** resources (Azure RBAC, Power BI,
  Intune, Defender, AzDevOps), the role-assignable flag isn't required and
  Active-on-the-permission-group nesting is fine.
- The flag can't be added later — recreate the group. The engine sets it at
  create time from CSV intent.

Don't design around this — every workaround ends up either violating the
constraint or duplicating groups.

### 3.2 Direct vs indirect delegation

**Direct**: principal has an assignment recorded directly against the resource.
**Indirect**: principal is a member of a group; the group has the assignment;
member inherits via transitive membership.

PIM4EntraPS is **indirect-by-design** with one exception:

| Use case | Delegation type | Why |
|---|---|---|
| Daily admin work | Indirect (always) | Refactorable, auditable, offboard-safe. |
| **Break-glass accounts** | Direct (1–2 total) | Must work when Graph/PIM is unavailable. Recovery path. |

Break-glass accounts live in a small dedicated `Account-Definitions-BreakGlass.csv`
and are wired by the launcher / bootstrap, not the baseline engine. Their
existence is intentional design.

Why not direct for normal admins:

| Problem with direct | Indirect handles it how |
|---|---|
| Refactoring requires touching every admin | Edit the permission group once; all admins inherit. |
| Audit needs full graph traversal anyway | Same lookup, but in CSV/SQL — fast and visible. |
| Offboarding scope unbounded | Delete admin row → all reach disappears in one step. |
| Permission drift between admins "doing the same job" | Membership in the role group is the source of truth. |
| AU-scoped roles can't be group-nested in old Entra | **Solved** in 2023+; the modern API is used. |

### 3.3 Naming convention

Permission-group names encode **scope + tier + service** so intent reads off the
name with no CSV lookup:

```
PIM-<Service>-<Name>-L<Level>-T<Tier>-<Code>-<Domain>[-S_AD]

PIM-Entra-ID-AppAdmin-L1-T0-CP-ID
    └────┬────┘ └──┬──┘ ┬  ┬  ┬   ┬
         │        │   │  │  │   └── Domain: ID (Identity) / RES (Resource) / DAT (Data)
         │        │   │  │  └── Code:   CP / WDP / MP / APP / USER  (see § 3.4)
         │        │   │  └── Tier:   T0/T1/T2 (Microsoft Enterprise Access Model)
         │        │   └── Level:  L0-L9 (maps to tier — see § 3.4)
         │        └── Capability name (free-form, human-readable)
         └── Microsoft service the perm targets
```

`<Code>`: `CP` (Control Plane) / `WDP` (Workload-Data Plane) / `MP` (Management
Plane) / `APP` (App Access) / `USER` (User Access). `<Domain>`: `ID` (identity
plane — Entra roles, Intune RBAC) / `RES` (resource plane — Azure RBAC on
MG/sub/RG) / `DAT` (data plane — Power BI contents, SharePoint sites).

**`-S_AD` suffix**: appended *after* `<Domain>` when the permission group is
synced down to on-prem AD by the PIM4ActiveDirectoryPS companion (§21.1). The
suffix is the contract the AD-side script keys off — same group name on both
sides. Example: `PIM-AD-DomainAdministrators-L1-T0-CP-ID-S_AD`.

Generated from `$global:PIM_NamingConventions.PimGroupPattern` in
`config/PIM4EntraPS.NamingConventions.locked.ps1`; customers override via the
`.custom.ps1` sibling.

**Why bake the pattern into the name**: the Manager can color-code by tier
without a separate lookup; KQL/Log Analytics can `parse displayName` to bucket by
tier/service/domain; onboarding derives the group name from a worksheet (no
creative naming, no collisions).

### 3.4 Tier model (Microsoft Enterprise Access Model)

The tier is one of three values; the **acronym** (`<Code>`) tells you *which
plane within that tier* the group lives in:

| Tiering | Acronym | Plane | Purpose |
|---|---|---|---|
| **T0** | `T0-CP` | Control Plane | Global roles + services like Conditional Access. |
| **T1** | `T1-WDP` | Workload / Data Plane | Business data or application. |
| **T1** | `T1-MP` | Management Plane | Management platform (logging, security, identity, connectivity). Cross-platform. |
| **T2** | `T2-APP` | App Access | Read/write specific data — e.g. partner integration. |
| **T2** | `T2-USER` | User Access | User access to a service — e.g. Power BI platform. |

In the group-name string `<Code>` is uppercase (`CP/WDP/MP/APP/USER`); the CSV
`<Code>` column stores title-case (`CP/WDP/MP/App/User`).

**Delegation levels (L0–L9) map deterministically to a tier** — level is not an
independent axis:

| Level | Tier | Name | What sits here | Example |
|---|---|---|---|---|
| **L0** | T0 | High Privileged Global Role | The single most-powerful role per directory. | Entra **Global Administrator**; AD **Forest Administrator**. |
| **L1** | T0 | Global Role Admins | All other directory-wide roles. | All ~100 Entra tenant roles except GA; AD **Domain Administrator**. |
| **L2** | T0 | Scoped Role Admins | The same global roles scoped to an AU / OU instead of tenant-wide. | Entra User Admin scoped to AU `<scope>`; AD perms delegated to OU `<scope>`. |
| **L3–L9** | T1 | Service Admins | Workload/data-plane roles inside individual services (their **native** RBAC). | Intune RBAC; Defender XDR RBAC; Power BI workspace admin; AzDevOps project admin; Azure Owner/Contributor on MG/sub/RG. |

L3–L9 lets one service have several rungs (`L3 = Functions/Tasks Admin`,
`L4 = User Support`, `L5 = Reader`, …) without colliding with another service.
Picking a sub-level per role is a per-service decision. T2 levels (App/User
Access) are expressed as L-numbers inside the T1 range when a service exposes both
an admin plane and an end-user data plane (e.g. Power BI master-data
Build/Read/Share at `L4-T2-USER-ID`).

The tier surfaces in: the permission-group name; the admin account name
(`Admin-<Init>-<Tier>-<Platform>`); the CSV column `TierLevel`. **Enforcement**
(tier-safety lint flagging T0-admin→T1-asset crossings and level↔tier mismatch)
is the Manager validator's job (§18); the engine doesn't currently block tier
crossings.

### 3.5 Lifecycle states (Initial → Pilot → Prod)

PIM-for-Groups policies, CA policies, and (optionally) group-membership rollout
follow a 5-stage progression, distinguished by **policy name prefix**:

```
Initial   →   Pilot1   →   Pilot2   →   Pilot3   →   Prod
(no users)    (1 admin)    (small)      (large)      (everyone)

CA006-Initial-Global-AllApps-AnyPlatform-HighUserRisk-Block
CA006-Pilot1-... / CA006-Pilot2-... / CA006-Pilot3-... / CA006-Prod-...
```

The same `CA006` intent ships as 5 parallel policies; migrate users between them
as confidence grows, then decommission Initial/Pilot. The tool supports the
stages by *not* assuming a flat name; the governance process dictates them.

### 3.6 Project-based delegations (`PIM-PROJECT-*`)

External consultants/developers come and go; their access should be **visibly
temporary** in the model. Any permission group serving a time-bounded project
gets a `PIM-PROJECT-` prefix (same naming convention otherwise). The two-group
pattern is intentional:

```
PIM-PROJECT-AzRes-LZ-mg-<scope>-Owner-L5-T1-WDP-ID   ← project-scoped (Active during engagement)
PIM-AzRes-LZ-mg-<scope>-Owner-L5-T1-WDP-ID           ← maintenance equivalent (Eligible after engagement)
```

During the project the developer holds **Active** standing access; when it ends,
the lifecycle step downgrades them to the maintenance group with an **Eligible**
assignment (they keep step-in ability for a hotfix, but no default permission):

```
ADMIN-<Init>-ID --Eligible--> PIM-ROLE-Developer-IT --Active--> PIM-PROJECT-AzRes-...-Owner-... --Active--> Owner on /subscriptions/{...}
                                                     --Eligible--> PIM-AzRes-...-Owner-...        --Active--> Owner on /subscriptions/{...}
```

The `PIM-PROJECT-` prefix is greppable ("every project assignment older than 6
months" = one filter); revocation at project end is a single row delete; the
active-vs-eligible split makes "working on this now" vs "might look later" visible
to auditors. **Only** the project-scoped group carries the `PROJECT` infix — the
maintenance equivalent uses the plain name (never ship `...-Maintenance`, it
defeats the filter).

---

## 4. The "as-code" pattern + customer override files

```
┌──────────────┐        ┌──────────────┐
│  CSV / SQL   │   ─→   │   Engine     │   ─→   Microsoft Graph
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

**Desired state**: the configuration tables under `config/` (the CSV model;
SQL-backed under the v3.0 store, §14). Customer-owned, version-controlled.

**Imperative engine**: reads desired state, queries the tenant for current state,
computes the per-row delta (add / update / remove / no-action), applies each via
Graph / RBAC / Exchange.

**LastApplied snapshot**: after a successful run, `output/<csv-base>_LastApplied.csv`
records what was applied — feeds next run's delta detection, the Manager's diff
view, and audit. **Delta files** (`<csv-base>_Delta.csv`) record what changed
each run.

**Idempotency**: every operation is "check exists → if same, skip; if different,
modify; if missing, create". A zero-change run prints "Mode: NoAction" for every
row and exits clean. Re-runnable, safe to schedule.

**`-WhatIfMode`**: every launcher accepts it; engines respect it for *destructive*
operations (account create, PIM assignment create/delete, group nesting change).
Read-only operations always run.

### Customer override pattern (`.locked` / `.custom` / `.custom.sample`)

Every shipped artifact follows a 3-file pattern:

```
config/PIM-Definitions-Roles.locked.csv         ← ships in repo (the baseline)
config/PIM-Definitions-Roles.custom.csv         ← gitignored (customer's data)
config/PIM-Definitions-Roles.custom.sample.csv  ← header-only template for new installs
```

At runtime the engine prefers `.custom.csv`, falls back to `.locked.csv`. No
override → baseline as-is; any customization → copy `.custom.sample.csv` →
`.custom.csv` and fill in rows (the `.locked.csv` is then ignored entirely). The
`.custom.csv` is **gitignored** (lives only on the customer VM); the
`.custom.sample.csv` is **tracked** so future installs always have a template.
Customers `git pull` engine updates without merge conflicts on their data;
defaults stay visible; new CSVs in a release get a `.custom.sample` template (no
silent gaps).

Special helper files: `repository.custom.ps1` and `policies.custom.ps1` follow the
same pattern but without a `.locked.*` default — customer-specific by nature.

---

## 5. Engine core & pipeline

### 5.1 Engine taxonomy (module-based reference engines)

The original `PIM-Baseline-Management-*` engines are **module-based** (Graph/Az
PowerShell SDK, interactive sign-in) and remain the reference for *behaviour*:

| Engine | Reads | Writes | Frequency |
|---|---|---|---|
| `PIM-Baseline-Management-CSV` | All config CSVs | Tenant PIM state (full sync) | Hourly / daily |
| `PIM-Baseline-Management-CSV-<X>Only` | Subset of CSVs | Subset of tenant (faster iteration) | Ad-hoc |
| `PIM-Baseline-Management-SQL` | Azure SQL tables | Tenant PIM state | Same as CSV variant |
| `PIM-Assignment-Exporter` | Tenant | CSV snapshot under `output/` | Daily |
| `PIM-Assignment-Wizard` | CSV + interactive prompts | Tenant | Manual |
| `PIM-Assignment-Revoker` | Tenant | Active activations (revoke) | Incident response |
| `Check-PIM-Groups-IsRoleAssignable` | Tenant | (diagnostic stdout) | Ad-hoc |
| `GetNumberOfROles` | Tenant | (diagnostic stdout) | Ad-hoc |

The `*-Only` variants exist for **fast iteration during model development** — add
5 permission groups and run only `...-EntraIDRolesOnly` instead of the whole
pipeline.

### 5.2 The REST + SQL engine (current)

The hosted/container product runs a **new engine** that is **REST-only (no
modules), SQL-backed, app-only**, so it runs headless on a VM, in a Linux
container, or from the scheduler with no `Connect-*` step.

- **Entry point**: `tools/pim-engine/Invoke-PimEngineCore.ps1`
  (`-Scope All|<name> -Mode Full|Delta [-FromQueue]`). Identity + targets come
  from env / launcher globals — nothing hardcoded. Same module chain the
  scheduler loads (`engine/_shared/PIM-*.ps1`).
- **Core**: a pure diff (`Compare-PimDesiredVsLive`) + an orchestrator
  (`Invoke-PimEngineScope`). Each **scope is a provider** that knows how to read
  DESIRED (from SQL `pim.Rows`), read LIVE (tenant REST), key + compare, and
  apply Create/Update/Remove. Providers run in a fixed dependency order; a
  provider may request a directory-cache refresh before it runs (so an assignment
  scope sees groups an earlier scope just created). See §6.

**Run modes** (`Invoke-PimEngine`):
- **Full** — whole-scope reconcile (create/update). **Prune (removal of live items not in
  desired) is opt-in:** Full alone does NOT delete; you must add **`-Prune`**. This is a
  destructive-safety guard — a partial or non-authoritative desired set (e.g. only a few
  rows seeded) must never silently disable real admins. A second guard applies even with
  `-Prune`: a scope whose **desired set is empty is never pruned** (an empty desired almost
  always means "this scope wasn't loaded", not "delete everything live") — the engine logs
  the refusal and skips the prune.
- **Delta** — create/update everything that differs (no prune).
- **Delta + `-FromQueue` / `-Changes`** — apply **only** the pending commit-queue
  `(entity,key)` pairs. A Manager commit enqueues changes; the engine applies just
  those. *(This is "the engine also runs delta when a new change is added to
  SQL.")*

**Precondition guard (fail-hard preflight).** Before any provider runs, the entrypoint
(`Invoke-PimEngineCore.ps1`) verifies the inputs are real and refuses to proceed otherwise —
so a wrong/empty store or a bad credential can never silently mass-create (or, in Full+Prune,
mass-delete) against a live tenant: (1) the desired store is reachable AND has at least one
definition/admin row (an empty desired set against a live tenant is rejected), and (2) a Graph
token is minted and the organization resolves (a wrong/missing identity fails here, not after a
half-applied run). Bypass only deliberately with `$env:PIM_SkipPreflight=1`.

**Desired store — two first-class shapes (`Get-PimSqlConnectionString`):**
- **Azure SQL** — `PIM_SqlServer` is an FQDN (`…database.windows.net`); auth is a managed
  identity / SPN access token. The hosted product path.
- **Local SQL** — `PIM_SqlServer` is a local instance (e.g. `.\SQLEXPRESS`, the default when
  no server is set) reached with **Integrated** auth. This is the management-server / on-prem
  / dev / break-glass path: the running identity is itself a DB user, so there is **no
  cross-tenant token problem and no "MI is not a DB user" blocker** — the engine reads its
  desired set directly. Only the database *name* (`PIM_SqlDatabase`) is mandatory.

### Design tenet — no fragile module dependencies (pure REST)

Both the engine and the hosted container deliberately avoid PowerShell modules
that break / must be constantly updated (Microsoft.Graph, Az). All Entra / Azure /
Power BI access goes through `engine/_shared/PIM-Rest.ps1` (token via Managed
Identity / SPN secret / SPN cert / az; data via `Invoke-PimGraph|Arm|PowerBI`),
so the engine runs identically on PS 5.1, PS 7, a VM, or Linux with **nothing to
`Install-Module`** and no version drift. The only non-REST dependency is the SQL
driver — a **stable .NET assembly** (`Microsoft.Data.SqlClient` on Linux/PS7;
in-box `System.Data.SqlClient` on Windows PS 5.1), pinned and stable. There is no
practical REST data-plane for Azure SQL/TDS, so a driver is unavoidable —
consistent with the principle.

---

## 6. Providers (per-scope appliers)

Each scope is a provider implementing read-DESIRED / read-LIVE / key+compare /
apply. They run in a fixed dependency **order**:

| Order | Provider | Entity | Creates / binds |
|---|---|---|---|
| 10 | AdministrativeUnits | `PIM-Definitions-AU` | AUs (scope containers only) |
| 20 | Groups | `PIM-Definitions-{Roles,Services,Organization,Tasks}` | the PIM groups (+ owners, AU attach) |
| 30 | Admins | `Account-Definitions-Admins` | admin accounts |
| 35 | AdminTap | `Account-Definitions-Admins` (CreateTAP) | Temporary Access Pass |
| 40 | EntraRoles | `PIM-Assignments-Roles-Groups` | directory role → **group** (tenant scope) |
| 45 | RolesAUs | `PIM-Assignments-Roles-AUs` | directory role → **group**, scoped to an AU |
| 50 | AdminMembers | `PIM-Assignments-Admins` | admin → **eligible/active member of a group** |
| 55 | GroupMembers | `PIM-Assignments-Groups` | group → member of a group (nesting) |
| 60 | AzRes | `PIM-Assignments-Azure-Resources` | Azure RBAC role → **group**, at an Azure scope |
| 70 | GroupsPolicies | definition `PolicyTemplate` | per-group PIM policy (approval, MFA/justification) |

A dedicated `GroupOwners` scope (replication-safe, re-runnable) repairs missing
owners on existing groups; `Groups` itself is existence-nochange (see §8).

### Owners are mandatory (dept → owner)

A group is **never created without an owner**. Owners resolve in order: definition
`Owners` column (pipe-joined UPNs) → `SponsorUpn` (Roles) → the group's
**department contact** (`PIM-Definitions-Departments`: `Department → Owners`). If
none resolve the engine **refuses to create the group**
(`$global:PIM_RequireGroupOwners`, default on) — surfacing the data gap instead of
leaving an orphan. Owners are also the **approvers** for approval-required policy
templates.

### Policy templates

`templates/policy/*.policytemplate.json` (+ `*.policytemplate.custom.json`, custom
id wins), single-level `extends` merge. A definition's `PolicyTemplate` column
selects one; **blank = `default`** (every group is linked). Ships ≥2: `default`
(baseline, no overrides — the engine never touches an approval rule it didn't set)
and `approval-required` (activation needs MFA + justification + an approval;
approvers = the group's Owners; Serial = escalate owner[1]→[2]…). See §17.7 for
the full template/approval mechanics.

---

## 7. Identity, auth & engine configuration

- **App-only, certificate auth.** The engine signs in as the **PIM4EntraPS-Engine
  SPN** (or the AutomateIT high-priv SPN) using a **certificate thumbprint**
  (`$global:PIM_CertThumbprint` / `PIM_CERT_THUMBPRINT`), resolved from the local
  cert store — **no client secret, no device code, no modules**. In a container it
  falls back to **managed identity**. **Never create a new SPN** for a run; reuse
  the engine SPN. Stale/duplicate engine certs are removed from the host.
- **Required Graph app-roles** on the engine SPN: `Directory.Read.All`,
  `User.ReadWrite.All`, `Group.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`,
  `PrivilegedAccess.ReadWrite.AzureADGroup`, **`RoleManagementPolicy.ReadWrite.Directory`
  + `RoleManagementPolicy.ReadWrite.AzureADGroup`** (both required for the GroupsPolicies
  approval rule — without the AzureADGroup variant `Get-PimGroupMemberPolicyId` 403s and the
  apply surfaces as "no member policy"), `AdministrativeUnit.ReadWrite.All`, `Mail.Send`, and
  **`AccessReview.Read.All`** (the AccessReviews provider 403s without it — handled gracefully
  but a no-op until granted). **Azure RBAC**: the SPN needs **Owner / User Access
  Administrator** on each ARM scope used by `AzRes`. Grant/top-up the full set idempotently,
  certificate-only (no device code, no Graph SDK), with `setup/Grant-PimGraphAppRoles.ps1`.
- **Deleting** a provisioned admin *account* (test cleanup / offboarding) needs more than the
  Graph app roles above — user delete is a privileged directory operation requiring an
  appropriate directory role (e.g. the management SPN's GA membership). The engine *creates*
  accounts under `User.ReadWrite.All`; account deletion is intentionally a higher-privilege,
  separate action.
- **SQL is MI-only** (contained DB user; SID from the MI **appId**). No SQL
  login/secret, no CSV fallback. On a dev box an AAD admin can add a human as a
  contained `db_owner` for testing without changing the server admin.
- **Nothing environment-specific is hardcoded** — SPN appId, cert thumbprint,
  tenant id, SQL FQDN, mail sender all come from env / launcher globals / config.

(Container-specific identity modes — ManagedIdentity / Certificate / ClientSecret
— are in §12.)

---

## 8. Scale, performance & resilience (lean context)

A production tenant can hold **500k+ users and 150k+ groups**; the engine must
never bulk-enumerate the directory to manage a few hundred PIM groups + admins.

- **Lean context** (`$global:PIM_LeanContext`, default on): `Build-PimContext`
  **never bulk-lists users** — they resolve **on-demand** by UPN
  (`Resolve-PimPrincipalId` → `/users/{upn}`) and cache. **Groups** are fetched
  with a **server-side `$filter=startswith(displayName,'<prefix>')`**
  (`$global:PIM_GroupNamePrefix`, default `PIM`) + `ConsistencyLevel: eventual` —
  not the whole directory. **AUs + role definitions** stay bulk (bounded). Context
  build drops from "list the tenant" to a few seconds.
- **On-demand resolvers**: `Resolve-PimLiveGroupIdByName` /
  `Resolve-PimPrincipalId` hit the cache first, then a targeted Graph lookup on a
  miss, caching the result.
- **Incremental cache**: each create is appended to the in-memory cache
  (`Add-PimContextObject` → pure `Merge-PimCacheItem`: PascalCase-shape + de-dup,
  flatten-on-read so it can't nest). No `Build-PimContext -Refresh` between
  scopes.
- **Tenant-wide schedule preload**: directory-role schedules are bulk-read once
  (indexed by principal) for the diff. NB: the PIM-for-Groups schedule list
  endpoints **require a `groupId`/`principalId` filter** (an unfiltered list 400s
  `MissingParameters`), so group membership is read per-group (cached per run).
- **Validate-and-skip**: an apply that returns *already-exists* / conflict is
  counted as **skipped**, not an error (idempotent re-runs). Entra *"no nesting
  into a role-assignable group"* is a skip (data constraint, not a fault).
- **Duration-ladder**: PIM policies cap max assignment duration; on
  `ExpirationRule … greater than maximum allowed`, the engine retries with shorter
  `afterDuration` (180/90/30) then `noExpiration`, so a too-long data duration
  lands at the policy cap instead of failing.
- **Replication-safe owners**: a just-created group isn't instantly writable; the
  dedicated `GroupOwners` scope retries on replication and is re-runnable.
- **Run shapes**: a fresh full create is bounded by the write POSTs (~minutes); a
  **delta re-run is near-idempotent** (bulk reads + skips, ~no writes).

---

## 9. Delegation model

### 9.1 Group-centric delegation (invariant)

**Everything is groups. The principal of every assignment is a PIM group — never
an AU, never a person.** An AU or an Azure scope is only *where* a group's role
applies; it is never a delegation target.

- Tenant role, AU-scoped role, Azure landing-zone (L5) role → all assigned to a
  **group** (`EntraRoles` / `RolesAUs` / `AzRes`). e.g. an L5 Azure LZ is a
  **group** holding `Owner` on a management group — a group, not an AU.
- **Delegation = group membership only** (`AdminMembers` / `GroupMembers`). An
  admin never receives a role or an AU directly; they join a group.

### 9.2 Delegated visibility & portal-admins (Manager)

A Manager user can have role **`Delegated`** (`PIM_DelegatedAdmins` env, or
`manager-access.custom.json role=Delegated`). A Delegated user is a **workload
owner**: the data layer (`Read-PimRows`) scopes every grid to **only the groups
they own** (their identity in the group's Owners/SponsorUpn) plus the assignment
rows referencing those groups (by `GroupTag` / `Target` / `SourceGroupTag`) — so
they see their group's tenant/AU/Azure bindings *through the group*, and nothing
else. Reader/Admin/SuperAdmin are unscoped. Visibility keys on **groups only**,
never on `AdministrativeUnitTag`.

The **portal-admin** model goes finer than the simple `Delegated` role: a portal
profile (`config/portal-admins.json`, or SQL) carries `services`
(entra/azure/workload/*), `tierMax`, `levelMax`, Azure `scopes`, `capabilities`
(`manage-direct` / `manage-indirect` / `assign` / `assign-admin` /
`enable-consultants` / `invite-guest` / `approve-assignment` / `access-review`)
and `managedAdmins`. The gates live in `PIM-PortalAccess.ps1`
(`Get-PimGroupFacets`, `Test-PimPortalCanSeeGroup`, `...CanManageGroup`,
`...CanAssignAdmin`, `...CanEnableConsultant`). Facets derive from definition
columns, falling back to **parsing the group name** (the locked naming grammar) —
so scoping works even before SQL columns are filled. Tier/level ceilings:
`group.tier >= profile.tierMax`, `group.level >= profile.levelMax` (T0/L0 = most
privileged = 0). SuperAdmin bypasses all.

### 9.3 Dev-mode "switch admin" (auth off) + the 4 personas

For GUI testing, when auth is off (local / not hosted) the Manager exposes a
**switch-admin** control to impersonate a portal identity (a dev-only override of
the request principal; refused when hosted). This drives the delegation model
end-to-end without standing up Easy Auth. Reference personas:

| Persona | Profile shape | Sees / can do |
|---|---|---|
| **SuperAdmin** | bypass | everything, unscoped |
| **Admin (L1 and down)** | `services:*`, `levelMax:1`, full caps | L1+ groups across services; not L0 |
| **Helpdesk (L2 and down)** | `services:[entra]`, `levelMax:2`, `manage-indirect`+`assign` | L2+ Entra groups via membership; not L0/L1, not Azure, not direct roles |
| **Business workload owner** | `services:*`, owns specific groups, `assign`+`assign-admin`+`enable-consultants` for `managedAdmins` | only owned groups; assign/enable own consultants; no global manage |

Manager RBAC roles (Reader / Admin / SuperAdmin) and their per-endpoint gates are
in §17.12.

---

## 10. Notifications

`PIM-Notify.ps1` renders `templates/mail/*.mailtemplate.html` (+ `.custom`) with
`{{token}}` substitution and sends via Graph `/users/<sender>/sendMail` (app-only,
`Mail.Send`). `$global:PIM_MailSender` is the shared from-mailbox;
`$global:PIM_MailRedirectAllTo` routes every mail to one inbox for lab/test
visibility. Render is split from send (unit-testable). The engine fires
**new-admin** (on account create) and **tap-delivery** (with the TAP) to the
admin's manager; approval/escalation/lifecycle templates exist for the scheduler.

A single `Send-PimTemplatedMail -Type <type> -To <addr> -Tokens <hashtable>`
resolves custom-over-locked and routes through `$global:PIM_NotificationChannels`.
Mail-template types, token list, subject-line convention, and the
contacts/email-flow routing layer are detailed in §17.6 / §17.17.

---

## 11. Hosting & runtime

Cheap (B1 App Service ~$13/mo + Basic SQL ~$5/mo), **never publicly exposed**
(private endpoint inbound, `publicNetworkAccess=Disabled`), management access from
trusted subnets only.

### 11.1 Single-tenant topology

```
   INTERNET ─────────────► ✖  no public endpoint  (publicNetworkAccess = Disabled)

 ┌──────────────────────── Entra ID  (customer tenant) ───────────────────────────┐
 │  • Easy Auth (interactive sign-in)   • App reg / SPN (app-only, cert in KV)      │
 │  • the PIM roles, groups, AUs this manager governs                               │
 └────────────────▲───────────────────────────────────────────▲────────────────────┘
        user sign-in │ (Easy Auth)              Graph/ARM REST  │ (app-only, PIM-Rest, no modules)
                     │                                          │
 ┌───────────────────┴──── VNet  vnet-platform 10.100.0.0/16 ───┴────────────────────┐
 │   ADMIN ACCESS BY LEVEL (private, from trusted subnets only)                        │
 │   ┌───────────────────────────────────────────────┐                                │
 │   │ PAW-tier0  10.100.8.0/24   L0/T0  ─ SuperAdmin │─┐                              │
 │   │ SAW-tier1  10.100.9.0/24   L1     ─ Admin      │ │  resolve private DNS         │
 │   │ mgmt       10.100.2.0/24   L2     ─ Reader/    │ ├──► pe-pim-manager ──► App     │
 │   │ (helpdesk)                          portal-adm │ │   (inbound PE)        Service │
 │   └───────────────────────────────────────────────┘ │                       B1      │
 │     remote admin ─ VPN / Bastion into the VNet ──────┘                       (Linux  │
 │                                                          App identity:        container)│
 │                                                          • system MI (passwordless)   │
 │                                                          • Easy Auth principal → RBAC  │
 │                                                            SuperAdmin/Admin/Reader     │
 │                                                            + portal-admins scoped      │
 │                                                                 │ VNet integration     │
 │                                                                 ▼ (outbound, route-all)│
 │                                   pe-pim-sql ──────► Azure SQL Basic  (PimPlatform)    │
 │                                                       • AAD-only, public disabled      │
 │                                                       • MI = contained DB user         │
 │                                                       • pim.Rows / pim.Settings /      │
 │                                                         pim.ChangeQueue                │
 │                                   pe-pim-baseline ─► Storage (run staging)             │
 │   Private DNS: azurewebsites.net · database.windows.net · blob.core.windows.net        │
 └────────────────────────────────────────────────────────────────────────────────────┘
        ACR (container image, MI pull)        Key Vault (app-only cert/secret, MI-read)
```

**Access levels (defense in depth, all private):**
1. **Network** — only the mgmt / PAW-tier0 / SAW-tier1 subnets (or VPN/Bastion)
   can reach the app's private endpoint; the internet cannot.
2. **Identity** — Easy Auth (Entra) forces sign-in; unauthenticated → redirect to
   login.
3. **Authorization** — the manager maps the signed-in principal to SuperAdmin /
   Admin / Reader, and **portal-admins** are delegated managers scoped by tier,
   level, service and scope (helpdesk L2 sees only its AU-scoped groups).
   Fail-closed: unknown principal → Reader.
4. **Data** — the app reaches SQL only over the private endpoint via its managed
   identity (no password); SQL itself has no public access.

### 11.2 Two-plane network topology — admin plane vs self-service plane

The Manager/SQL and the self-service portal occupy **two separate network
planes**, matching their trust levels (on-prem and Azure alike):

**Admin plane (tight)** — operators only:
- PIM **Manager + SQL co-located** so the interface can be clamped to a narrow
  source list (jumphosts / PAWs).
- Both **private-endpoint-only, public network access disabled**. SQL is
  **Entra-only auth** (no SQL logins). Manager↔SQL traffic stays within the
  private-endpoint subnet. Manager inbound restricted to admin source ranges.

**Self-service plane (broad)** — business users:
- A **separate** app, reachable from the whole internal range, also
  **private-endpoint-only (never public)**.
- **No Graph write permission and no write path to the authoritative tables.** It
  (a) reads a curated catalog of what each delegation unit may request, and (b)
  writes **signed requests** only. The admin-plane intake processor pulls and
  validates them (§17.15). Data flow is one-directional:
  `self-service → request store → (pull) → admin plane → engine → Entra`. Even
  fully compromised, it can only *request* template-shaped, in-scope changes that
  still pass approval.

**Built reference (this environment, westeurope):** admin Manager host = App
Service (`publicNetworkAccess=Disabled`), private endpoint in `vnet-platform/pim-pe`
(10.100.20.0/24), inbound access-restricted to 10.100.2.0/24 (management) +
10.100.8.0/24 (PAW) + 10.100.9.0/24 (SAW) + implicit deny-all. Registry SQL =
serverless GP_S_Gen5_1, **Entra-only**, **public disabled**, private endpoint in
the same `pim-pe` subnet; `privatelink.database.windows.net` zone linked to the
VNet. Self-service app = a second App Service (private endpoint in a dedicated
`pim-selfservice-pe` subnet, broad internal allow) — built with the §17.18
delegation work.

**DNS caveat (private endpoints):** a VNet using **custom DNS** (e.g. domain
controllers `10.100.1.4/.5`) does not resolve the Azure `privatelink.*` zones.
Production fix = a **conditional forwarder** (or **Azure DNS Private Resolver**) on
the DCs sending `database.windows.net` / `azurewebsites.net` to `168.63.129.16` so
the private zones resolve VNet-wide. Until then, the management host uses
**hosts-file entries** to the private-endpoint IPs for bootstrap/testing.

### 11.3 Execution model — scheduled vs on-demand jobs

**Method: an in-container scheduler.** The App Service container is already
always-on (B1, Always On) and is the *only* component with all three things a job
needs — the full engine code, VNet integration to reach the private SQL/Graph, and
a managed identity. Recurring jobs run as a lightweight timer loop **inside that
same container** (schedules + last-run/next-run persisted in SQL `pim.Settings`;
idempotent; single B1 worker = no double-run, a SQL lease guards if ever scaled).
On-demand actions come through the **manager API** (admin acts in the GUI → writes
to the change queue).

Implementation: `engine/_shared/PIM-Scheduler.ps1` (pure due-calc + handler
registry + tick + loop + on-demand triggers + change watermark) and the entrypoint
`tools/pim-scheduler/Start-PimScheduler.ps1` (runs on a VM *or* in a container,
REST-only). The job *logic* it drives already existed (`PIM-Lifecycle`,
`PIM-ChangeQueue`, `PIM-Approvals`).

Key semantics:
- **Phase-split delta** — one job per engine `-Scope` (admins, groups-assign,
  groups-deploy, policies, pim-entra, pim-azure, pim-au, workloads), each with its
  own cadence, so a change commits fast without a whole-tenant pass.
- **Discovery = 3 jobs** — `discovery` scoped to **Entra**, **Azure**, **PowerBI**.
- **Commit-only trigger** — `Request-PimCommit` (and the SQL change **watermark**)
  enqueue an immediate recompute+reconcile. **Queuing a change triggers nothing.**
- **VM + container** — same code; `-IntervalSeconds` / `$env:PIM_SCHED_INTERVAL`,
  `-Once` for an external cron, single-runner SQL lease.

| Job | Trigger | How |
|---|---|---|
| Manager GUI / API (interactive; **commit to queue**) | **on-demand** | the always-on container (HTTP) |
| **Apply** change queue (dry-run → apply) | on-demand (admin) **+** scheduled sweep of approved items | in-container scheduler |
| Engine **Delta** run (changed rows) | scheduled (frequent) | in-container scheduler |
| Engine **Full** run (whole-tenant reconcile) | scheduled (periodic) | in-container scheduler |
| **MSP pull** (templates MSP→local, by ring) | scheduled **+** on-demand | local container pulls from MSP DB |
| **Reminders** (upcoming expirations / renewals) | scheduled (daily) | scheduler → mail via Graph `sendMail` / SMTP (REST) |
| **Escalations** (approvals aging past SLA) | scheduled (hourly) | scheduler → next approver layer + mail |
| **Connectors** (workload role discover/apply) | invoked *by* the engine runs | in-process via PIM-Rest (not a separate scheduler) |
| Azure auto-discovery / reconcile | scheduled | in-container scheduler |

**Why not the alternatives (each breaks a constraint):**
- **Azure Functions** — reaching the *private* SQL needs VNet integration = the
  Premium (EP) plan = expensive, plus cold starts and another component with its
  own deps. Fails "cheap" + "no fragile deps".
- **Webhooks** — inbound, event-driven; a *trigger*, not a scheduler. (One private
  webhook on the manager can optionally let an external system request an
  on-demand apply — not the core mechanism.)
- **Logic Apps** — Consumption can't reach private endpoints; Standard (VNet) is
  expensive. Fails "cheap" + "private-only".
- **App Service WebJobs** — Windows-only; we run a **Linux** container.

**Optional external scheduler (fallback, not default):** the same engine
entrypoints can be invoked by a **cron / scheduled task on the management VM** or
an **Azure Automation runbook** for shops that prefer scheduling outside the app.

---

## 12. Containers

The engine can run as a **scheduled container** inside the customer's own VNet —
no VM to build or patch. Files: `engine/container/Dockerfile`,
`engine/container/Start-PimEngineContainer.ps1`. (Proven 2026-06-12: a container
in the customer VNet resolved the MSP storage to the cross-tenant private-endpoint
IP, pulled the **signed** baseline while storage was public-disabled, verified the
signature, and **created accounts** in the customer's Entra —
`SIGNATURE_VALID=True`, `CREATED Admin-CONTAINER-ID`.)

### What the container does (per run)
1. Acquire a Microsoft Graph token for the per-tenant identity.
2. **Pull + verify** the MSP signed baseline over the (cross-tenant) private
   endpoint — RSA-SHA256 against the embedded public cert, plus expiry +
   anti-rollback.
3. Read the customer's own local store (`Owner=Local` rows) — optional.
4. **Merge** baseline (`Owner=MSP`) + local and create/maintain the accounts in
   this tenant.

It is REST-based (no Graph SDK / SqlServer module) to stay small and avoid the
Azure.Core assembly conflict.

### Identity (pick one, via `PIM_AUTH_MODE`)
- **ManagedIdentity** (recommended) — ACI/Container Apps system-assigned MI,
  granted the engine Graph app roles + Storage Blob Data Reader + (if used) SQL
  `db_datareader`. No secret to manage.
- **Certificate** — `PIM_CERT_PFX_B64` + `PIM_CERT_PFX_PWD`; the entrypoint builds
  a client-assertion JWT. The per-tenant app trusts the cert.
- **ClientSecret** — `PIM_CLIENT_SECRET` (inject as secure env / Key Vault
  reference). Simplest; rotate regularly.

### Environment variables
| Var | Meaning |
|---|---|
| `PIM_TENANT_ID` / `PIM_CLIENT_ID` | customer tenant + per-tenant engine app id |
| `PIM_AUTH_MODE` | `ManagedIdentity` \| `Certificate` \| `ClientSecret` |
| `PIM_BASELINE_URL` | HTTPS URL of `baseline-latest.json` (resolves to the PE in-VNet) |
| `PIM_BASELINE_PUBCERT` | base64 of the MSP baseline public cert (verification) |
| `PIM_DEFAULT_DOMAIN` | tenant default domain for UPNs |
| `PIM_WHATIF` | `true` (default, plan only) \| `false` (create) |
| `PIM_LOCAL_SQL_SERVER` / `PIM_LOCAL_SQL_DB` | optional local store (default DB `PimLocal`) |

### Build + push
```
docker build -t <acr>.azurecr.io/pim-engine:latest -f engine/container/Dockerfile .
docker push <acr>.azurecr.io/pim-engine:latest
```

### Run as ACI in the customer VNet (proven shape)
- Deploy into a subnet delegated to `Microsoft.ContainerInstance/containerGroups`.
- Customer private DNS zone `privatelink.blob.core.windows.net` resolves the
  baseline storage FQDN to the cross-tenant PE IP, so the pull stays on the
  Microsoft backbone (no internet).
- `RestartPolicy=Never` for a one-shot job.

### Scheduling
- **Container Apps Job** with a cron trigger (cleanest managed scheduler), or
- **ACI** started by a Logic App / Automation timer, or
- An on-prem scheduler invoking `az container start`.

### On-prem (VMware) customers
The identical `Start-PimEngineContainer.ps1` logic runs on a Windows VM instead —
same code, different host. Container = zero-VM cloud-native option; VM = on-prem
option. Both first-class.

### Security
- Storage stays `publicNetworkAccess=Disabled`; the container reaches it only via
  the approved cross-tenant private endpoint (or a customer-hosted copy).
- The baseline is **signed, not encrypted** — the container verifies with the
  **public** cert (no secret at the receiver); tampering is rejected.
- The container's identity lives in the **customer** tenant → customer-owned
  Conditional Access, attribution, and revocation. The MSP never reaches into the
  customer.

---

## 13. MSP architecture

The MSP edition lets one operator manage privileged access across many customer
tenants without the customer giving up control of their own data, identities,
logs, or Conditional Access. Design principle: **vary the edges, never the core.**
Status: proof-of-concept built + tested on real cross-tenant infrastructure
(2026-06-12).

### 13.1 The two planes

| Plane | Who | Stores | Network posture |
|---|---|---|---|
| **Admin plane (MSP)** | MSP operators | Central registry SQL + signing keys | Private-endpoint only; inbound clamped to jumphost/PAW/SAW IPs |
| **Local plane (per customer)** | the customer's local IT | The customer's own local SQL store | In the customer's own tenant/VNet; reached privately by the local engine |

The two planes are **separate networks that never see each other.** Only **signed
artifacts** cross the boundary (baseline bundle one way, status summary the
other). No SQL-to-SQL link, no MSP standing connection into a customer, no foreign
acting identity in the customer tenant. There is **no single shared multi-tenant
DB** — DB #1 = MSP DB (master templates / desired baseline + rings + fleet/version
metadata), DB #2 = the customer's LOCAL DB (that tenant's actual config + run
state). Both Basic (~$5/mo each).

### 13.2 Components

**Admin plane (MSP tenant):**
- `Central registry SQL` — `platform.Tenants`, `platform.TenantApps`,
  `pim.CentralAdmins` (Owner=MSP baseline), `platform.AuditEvents`,
  `pim.vw_AdminTenantTargets`. Entra-only auth, public disabled, private endpoint.
- `Baseline blob storage` — holds the signed baseline bundles. Public disabled,
  private endpoint.
- `Signing keys` (non-exportable, machine cert store, never distributed):
  `CN=PIM4EntraPS-Licensing` (signs `.pimlicense`, Pro entitlement);
  `CN=PIM4EntraPS-Baseline` (signs baseline bundles).
- `setup/New-PimBaselineBundle.ps1` — **producer**: reads Owner=MSP rows → signs →
  uploads.
- `setup/Invoke-PimMspFanout.ps1` — registry-driven multi-tenant account fan-out
  (Pro).
- `Manager (admin)` — App Service, private-endpoint only, inbound = admin IPs.

**Local plane (each customer tenant):**
- `Local store SQL` (`PimLocal`) — `pim.LocalAdmins` (Owner=Local),
  `pim.LocalResources`. Entra-only, in the customer's own subscription.
- `Per-tenant engine SPN` + **certificate** — the acting identity, registered **in
  the customer tenant** (Model B). Customer owns its CA, attribution, revocation.
- `setup/Invoke-PimLocalApply.ps1` — **local engine apply**: reads the local
  store, provisions accounts into the tenant.
- `engine/_shared/PIM-Baseline.ps1` — **consumer**: pulls + verifies the signed
  bundle (embedded PUBLIC baseline cert).
- `engine/_shared/PIM-License.ps1` — offline Pro gate (embedded PUBLIC licensing
  cert).
- `engine/_shared/PIM-Functions.psm1` — the declarative engine
  (`CreateUpdate-Accounts-From-file-CSV`, merge, audit).

**Shared contract (one core, pluggable edges):** auth profile = per-tenant cert
(default) | GDAP (CSP niche) | on-prem gMSA; storage profile = CSV | local SQL |
central partition.

### 13.3 Layers

```
  L4  Identity / RBAC : per-tenant SPN+cert (local) · signing keys (MSP) · customer CA
  L3  Application     : Manager (admin) · engine apply (local) · producer/consumer (courier)
  L2  Data            : central registry SQL (MSP) | local store SQL (customer)  -- NEVER linked
  L1  Transport       : signed artifacts only (bundle in / summary out) over HTTPS
  L0  Network         : private endpoints; separate VNets; no cross-tenant DB path
```

The `Owner` tag (`Owner=MSP` | `Owner=Local`) is **provenance, not a permission
gate**: MSP rows are refreshed on each baseline pull (so not hand-edited locally —
overwrite-avoidance, not forbidden); local rows are the customer's, fully
autonomous (any Purpose incl. privileged, no MSP request, no MSP approval).
**Optional** (off by default): a customer/MSP can mark baseline entries `Enforced`
so the engine refuses a local override of those specific keys — a deliberate
opt-in, not the default. (An earlier hard `CK_LocalAdmins_NoHighPriv` data-layer
constraint was removed in v2.4.177 as over-reach.)

### 13.4 Architecture diagram

```
        MSP TENANT (admin plane)                       CUSTOMER TENANT (local plane)
   ┌───────────────────────────────────┐         ┌────────────────────────────────────┐
   │  Central registry SQL  (Owner=MSP) │         │  Local store SQL  (Owner=Local)     │
   │   private endpoint, Entra-only     │         │   in customer's own sub, Entra-only │
   │            │ read Owner=MSP rows   │         │            ▲ read local rows        │
   │            ▼                       │         │            │                        │
   │  New-PimBaselineBundle.ps1         │         │  Invoke-PimLocalApply.ps1           │
   │   • build payload (versioned)      │         │   • read local store (child proc)   │
   │   • SIGN  (private baseline key)   │         │   • Connect-MgGraph (per-tenant SPN)│
   │            ▼                       │         │   • MERGE: baseline + local         │
   │  Baseline blob (private endpoint,  │         │   • create accounts IN THIS TENANT  │
   │   public disabled) — signed bundle │         │            ▲ verified rows          │
   │            │                       │         │  PIM-Baseline.ps1 (consumer)        │
   └────────────┼───────────────────────┘         │   • HTTPS GET signed bundle         │
                │                                  │   • VERIFY (embedded PUBLIC key)    │
                │   LOCAL PULLS the signed bundle  │   • expiry + anti-rollback check    │
                ◀──────────── HTTPS GET ───────────┤            ▼                        │
                  (private door, or public+signed) │     Entra ID / Azure RBAC (tenant)  │
                  MSP only hosts+signs; never       │     ← accounts, groups, scopes      │
                  writes into / connects to cust.   └────────────────────────────────────┘
                                  ▲
                  status summary  │  (signed, counts only — local → MSP fleet view,
                                  │   ideally via the customer's own Log Analytics)
```

### 13.5 Flow A — MSP baseline distribution (build + sign + publish + pull + verify)

1. MSP edits Owner=MSP baseline in the central registry (naming, rings, standard
   templates).
2. `New-PimBaselineBundle.ps1` reads `pim.CentralAdmins WHERE Owner='MSP'`, builds
   a versioned payload (`version`, `generatedAtUtc`, `validToUtc`, `rows`).
3. It **signs** the payload bytes RSA-SHA256 with the non-exportable
   `CN=PIM4EntraPS-Baseline` private key → `{ payloadB64, signature, keyThumbprint }`.
4. It uploads `baseline-v<ts>.json` + `baseline-latest.json` to the baseline blob
   (private endpoint, public disabled).
5. The bundle reaches the customer's network via one of the §13.7 transports.
6. The local engine's `PIM-Baseline.ps1` does an **HTTPS GET** of the bundle (over
   the customer's private endpoint).
7. It **verifies**: signature against the embedded PUBLIC baseline cert;
   `product/kind`; not expired; version ≥ last-applied (**anti-rollback**). Any
   tamper → rejected, nothing applied.
8. On success it returns the Owner=MSP rows for the merge, and records the applied
   version.

### 13.6 Flow B — local apply (true env: local store → real accounts)

1. `Invoke-PimLocalApply.ps1` runs for one tenant with that tenant's engine SPN
   (cert).
2. It reads `pim.LocalAdmins` from the local store **in a child process**
   (SqlServer's Azure.Core would otherwise break Graph app-only).
3. It `Connect-MgGraph` app-only as the per-tenant SPN and resolves the tenant
   default domain.
4. It **merges** the pulled-down MSP baseline (Flow A) with the Owner=Local rows.
5. It runs the engine (`CreateUpdate-Accounts-From-file-CSV -OnlyID`) to **create
   the accounts in this tenant** — both the MSP central admins (from the baseline)
   and the local admins. Replication-404 on the post-create PATCH is retried.
6. Every change is audited (`local.apply`) in the customer's own tenant.

The **MSP central admins are created IN the local tenant** — there is no central
directory of admin objects; every admin materializes in the tenant it serves.

### 13.7 Transport — LOCAL PULLS MSP (one direction, always)

**The model is fixed: the local engine PULLS the signed bundle from the MSP. The
MSP never writes into, or opens a connection into, the customer tenant.** The MSP
only hosts a signed file; the customer reaches out and reads it. (An earlier "MSP
writes into the customer's storage" idea is explicitly rejected — it would give
the MSP reach into the customer.) The only choice is the **path the local pull
takes**:

1. **Private door (cross-tenant Private Endpoint by approval).** The customer
   creates a PE in *their* VNet targeting the MSP storage's resource id; the MSP
   **approves** the pending connection (the only thing the MSP does; it grants the
   MSP nothing in the customer tenant). The pull then rides the Microsoft backbone
   — no internet. Revoke = customer deletes the PE.
2. **Public-but-signed + IP allowlist.** The MSP file is reachable over HTTPS,
   firewalled to the customer's egress IP; the local engine pulls over the
   internet. Safe because the **signature**, not the network, establishes trust.

Optionally the local engine **caches its own copy** of the pulled bundle in the
customer's own storage — still a local-pull. Either way: customer reads, MSP never
writes. The integrity guarantee is always the **signature**; the private endpoint
only removes public surface.

#### Cross-tenant Private Endpoint by approval (detail)

```
  CUSTOMER TENANT  (local engine)                       MSP TENANT  (owns storage)
  ┌─────────────────────────────────────┐              ┌────────────────────────────────┐
  │  Local engine                        │              │  Baseline blob storage         │
  │    │ resolves <acct>.privatelink     │              │   = Private Link RESOURCE      │
  │    ▼ .blob.core.windows.net          │              │   publicNetworkAccess=Disabled │
  │  Private Endpoint NIC ● 10.<cust>.x  │              │            ▲ (data plane)       │
  │   (targets MSP storage by RESOURCE   │              │            │                   │
  │    ID, subresource = blob)           │              │            │                   │
  └─────────┬────────────────────────────┘              └───────────┼────────────────────┘
            │                                                        │
   (1) customer CREATES the PE ─────────────────────────────────────▶ connection = PENDING
   (2) MSP APPROVES ("by trust") ◀──────────────────────────────────  owner accepts this customer
   (3) PRIVATE path over the Microsoft backbone:
       local engine ─▶ PE NIC (customer VNet) ═══ Azure backbone ═══▶ MSP storage
            (no public internet either side; MSP storage stays public-disabled)
```

Steps: (1) the customer creates the PE in *their* VNet with
`PrivateLinkServiceId=<MSP storage resourceId>`, `GroupId=blob` — cross-tenant →
status **Pending**; (2) the **MSP approves** (`Approve-AzPrivateEndpointConnection`)
and grants the customer SPN `Storage Blob Data Reader` — the approval *is* the
trust handshake; (3) the customer's `privatelink.blob.core.windows.net` resolves to
the PE in their own VNet and traffic rides the backbone. Revoke: customer deletes
the PE, or MSP rejects / pulls RBAC. Content is signed regardless.

### 13.8 Flow C — status rollup (local → MSP)

The local engine emits a **signed summary** (drift/compliance counts, never raw
privileged data) — ideally into the customer's **own Log Analytics** (via
`AzLogDcrIngestPS`), which the MSP reads. One-directional; MSP never reaches in.

### 13.9 Credential & trust model

- **Acting identity is local.** Each customer tenant has its own engine SPN +
  non-exportable cert (Model B). The customer owns its Conditional Access,
  attribution (actions log as a named app in *their* tenant), lifecycle, and
  instant revocation. No GDAP, no foreign multi-tenant identity (EA/MCA-friendly).
- **Asymmetric signing, no secret at the receiver.** Baseline + license use a
  private key on the MSP host and a PUBLIC verification cert embedded in the
  product. Local needs **no secret key** — it only verifies. Bundles are **signed,
  not encrypted** (transparency: the customer reads exactly what the MSP ships).
- **Two approval types, kept separate:** delegation-time approval is ours
  (Manager/declarative); **activation approval is native Entra PIM policy** (which
  the engine *configures*, e.g. `approval-required`, but does not mediate) — the
  Manager is not in the activation path.

### 13.10 Security properties (what each control buys)

| Threat | Control |
|---|---|
| Tamper with bundle in transit / at rest / on the distribution point | RSA-SHA256 signature → verify with embedded public key → rejected |
| Forge a bundle | Impossible without the MSP private key (non-exportable, machine store) |
| Roll back to an old baseline | Version-monotonic check (`baseline-state.json`) |
| Replay an expired baseline | `validToUtc` check |
| Hacker reaches the SQL | Private endpoint / public-disabled + Entra-only (no SQL logins) + (cross-tenant) firewall to known IP |
| MSP over-reach into customer data | No standing connection; only signed artifacts cross; acting identity is customer-owned |
| Local self-service abuse | Out of scope by design — activation stays behind native PIM MFA + approval |

### 13.11 Why not GDAP as the primary model

GDAP + a multi-tenant partner app is disqualified for the primary target market
and is at best a niche profile:

- **EA/MCA exclusion**: GDAP only covers CSP-licensed customers. EA/MCA
  enterprises — the primary market — can't use it at all.
- **No log attribution**: GDAP actions land in the customer's logs as object ids
  from the *partner* tenant; the customer must ask the MSP "who is this GUID?" to
  audit their own environment.
- **Weaker Conditional Access**: the acting identity is foreign (lives in the
  partner tenant), so the customer can't natively enforce its own MFA / device /
  location policy on it.

All three share one root cause: a **foreign acting identity**. The fix is to keep
the acting identity **local to the customer tenant**.

### 13.12 The rule: vary the edges, never the core

- **One core (single implementation, profile-independent):** the declarative
  engine, the Owner-tag merge, the signed-baseline courier, the validator, the
  Manager. None of it knows which auth or storage profile is underneath.
- **Two pluggable edges:** an **auth profile** ("get a token for tenant X") and a
  **storage profile** ("read/write these rows"). Both deliberately *thin* — if a
  model can't be expressed behind those two contracts, it's trying to fork the
  core and is rejected.

**Auth profiles:**

| Profile | Identity | Customer control | Use |
|---|---|---|---|
| **B — per-tenant cert (default)** | single-tenant app + **non-exportable cert, one per tenant**, registered in the customer tenant | full: native CA, attribution, lifecycle, instant revocation | EA/MCA enterprises (primary) |
| **A — GDAP (option)** | multi-tenant partner app + GDAP relationship | indirect (cross-tenant trust); no local attribution | CSP-managed SMBs only |
| **On-prem — Windows/gMSA** | domain service account / gMSA | AD/Kerberos + host/network controls | classic hybrid AD |

**Storage profiles:** `Csv` (small installs), **local SQL in the customer's own
Azure** (enterprise default), or a central SQL partition — behind one repository
contract (`Get-PimRows` / `Save-PimRows`, `$global:PIM_DataStore`). `Csv` stays
supported indefinitely.

**Per-profile capability / tradeoff table (kept honest):**

| Capability | B (per-tenant cert) | A (GDAP) | On-prem gMSA |
|---|---|---|---|
| EA/MCA customers | ✅ | ❌ CSP only | n/a (on-prem) |
| Human attribution in the customer's own log | ✅ via local audit + Log Analytics | ❌ partner-tenant object ids | ✅ local |
| Customer-owned Conditional Access | ✅ (CA for workload identities; Premium for IP-lock) | ⚠️ indirect (cross-tenant trust) | AD/Kerberos + network |
| Customer revocation | ✅ disable the local app | end the GDAP relationship | disable the gMSA |
| Credential sprawl | N certs — **lifecycle automation required** | none (no stored secret) | gMSA-managed |
| Setup friction | per-tenant onboarding | low (one consent) | domain join |

The customer-owned-control-plane benefits are **Model B properties**, not
universal — docs/sales must say so per profile. Cert lifecycle is first-class to
Model B: one cert **per tenant** (never shared — that would make the
per-tenant-identity security claim false), with the registry tracking thumbprint +
expiry, an auto-renewal job, and expiry alerting.

### 13.13 Engine runtime — cloud-native container or VM

The local engine does **not** need a VM in the customer's environment — it can run
as a scheduled container inside the customer's VNet (§12) or as the identical code
on an on-prem Windows VM. Container = zero-VM cloud-native option; VM = on-prem
option. Both first-class.

### 13.14 Same design for TenantManager

The platform registry is shared (`platform.Tenants` / `platform.TenantApps`,
distinguished by `Product`). TenantManager reuses the identical core, the same
auth/storage profiles, the same signed-courier and Owner-tag split — it is simply
another `Product` value on the same substrate.

---

## 14. SQL / data model

The configuration model is a set of logical tables (15 with the workload
configuration file). They live as CSVs by default and migrate to SQL under the
v3.0 store. **SQL is Core, never licensed.**

### 14.1 The logical tables

**Definition CSVs** (the desired model):
- `Account-Definitions-Admins` — admin accounts.
- `Account-Definitions-BreakGlass.csv` — the 1–2 directly-assigned break-glass
  accounts (separate concern; §3.2).
- `PIM-Definitions-Roles` — role groups (Tier-2).
- `PIM-Definitions-{Tasks, Services, Processes, Resources, Departments,
  Organization}` — permission groups (Tier-3).
- `PIM-Definitions-AU` — administrative units (scope containers only).
- `PIM-Definitions-Departments` — `Department → Owners` (owner fallback chain,
  §6).
- `PIM-Definitions-Contacts.custom.csv` — people directory for mail routing
  (§17.17).
- `PIM-Definitions-DelegationUnits.custom.csv` — self-service delegation envelopes
  (§17.18).

**Assignment CSVs** (the desired bindings):
- `PIM-Assignments-Admins` — admin → role-group (eligible/active member).
- `PIM-Assignments-Groups` — role-group nests permission-group (group → group).
- `PIM-Assignments-Roles-Groups` — permission-group → Entra ID role (tenant
  scope).
- `PIM-Assignments-Roles-AUs` — permission-group → AU-scoped Entra ID role.
- `PIM-Assignments-Azure-Resources` — permission-group → Azure RBAC at a scope.
- `PIM-Assignments-Workloads.custom.csv` — the 15th file; group → workload role
  (§15).
- `PIM-Assignments-FromIntake.custom.csv` — verified intake overlay (§17.15).

Per-column input strategies for every table are catalogued in §18 (Manager UX).

### 14.2 SQL data store (v3.0)

The original decision (stay CSV, revisit at v3.0) predates multiple writers
(Manager + engine + intake processor), state layers, RBAC, and audit. Decision:
SQL becomes the primary store, with **cloud AND on-prem/hybrid SQL both
first-class**. The repository layer takes a connection profile
(`$global:PIM_SqlConnection = @{ Server; Database; AuthMode }`), TLS enforced, and
**no credential ever lives in config**:

| Deployment | Operator (Manager) auth | Engine auth | MFA at the DB door |
|---|---|---|---|
| Azure SQL Database / Managed Instance | Entra interactive (`AuthMode=EntraInteractive`) — MFA + CA enforced by Entra | SPN / Managed Identity (`EntraSpn`) | yes (Entra) |
| On-prem / hybrid SQL Server (classic AD) | Windows Integrated / Kerberos (`WindowsIntegrated`) — domain identity, no SQL logins | gMSA or AD service account | no — MFA comes from the Manager's Entra sign-in gate (app layer) + host/network controls |
| SQL Server 2022+ Arc-enabled (hybrid, optional) | Entra auth on-prem via Azure Arc | SPN | yes (Entra) |

SQL logins are disabled in every mode — there is never a SQL password to steal. DB
roles mirror Reader/Admin/SuperAdmin in all deployments. For classic on-prem AD
customers the documented guidance is: app-layer MFA (the Manager's Entra sign-in)
is the MFA boundary, and the SQL Server should only be reachable from the
automation/management subnet.

In the hosted topology the platform DB exposes `pim.Rows` / `pim.Settings` /
`pim.ChangeQueue` (engine desired state, scheduler state, commit queue).

**Migration path:**
1. **Repository abstraction first**: `Get-PimRows -Table X` / `Save-PimRows` with
   `$global:PIM_DataStore = 'Csv' | 'Sql'`; Manager, engine and validator route
   through it — both stores work during transition, and `Csv` stays supported
   indefinitely for small installs.
2. **Schema** mirrors the existing model: the 15 logical tables + state
   (tap/policy/offboard/review-tombstones) + the audit log (jsonl → append-only
   table, finally queryable) + intake requests.
3. **`Invoke-PimCsvToDbMigration`**: idempotent per-instance importer — validator
   runs first, rows load, counts verify, CSVs are archived (never deleted).
4. **Safety nets**: nightly CSV snapshot export from the DB (git-diffability + the
   Excel escape hatch preserved).

---

## 15. Workload connectors

Binding PIM groups to each workload's own RBAC (Defender XDR Unified RBAC, Intune's
14+ built-in roles, Power BI workspace roles, Dataverse/Dynamics security roles,
Business Central permission sets, Azure-hosted AI services) is the LAST mile of the
model. The Manager + engine do it via connectors.

**Principles:** (1) **GUI stages, engine applies** — the Manager never writes to
workloads directly; operators stage desired state, the tenant's engine applies it
on its normal pull cycle with its own SPN. (2) **Everything maintainable as text
files** — new workload / endpoint / role mapping = edit JSON / CSV, never code (as
long as the auth adapter exists). (3) **SQL-ready** — desired state is row-shaped;
connectors are documents.

### 15.1 Layer 1 — connector definitions (maintainer-curated, shipped via repo)

`workloads/connectors/<id>.connector.json` describes HOW to talk to one workload:
which auth adapter, which endpoints, how to list roles, how to assign/remove a
group.

```json
{
  "id": "defender-xdr",
  "name": "Microsoft Defender XDR (Unified RBAC)",
  "auth": "graph",
  "permissionsNeeded": ["RoleManagement.ReadWrite.Defender"],
  "api": {
    "baseUrl": "https://graph.microsoft.com/beta",
    "listRoles": {
      "method": "GET", "path": "/roleManagement/defender/roleDefinitions",
      "itemsPath": "value", "roleId": "id", "roleName": "displayName"
    },
    "listAssignments": {
      "method": "GET", "path": "/roleManagement/defender/roleAssignments",
      "itemsPath": "value", "principalIds": "principalIds", "roleId": "roleDefinitionId"
    },
    "assign": {
      "method": "POST", "path": "/roleManagement/defender/roleAssignments",
      "body": {
        "displayName": "PIM4EntraPS: {groupTag} -> {roleName}",
        "roleDefinitionId": "{roleId}",
        "principalIds": ["{groupId}"],
        "directoryScopeIds": ["{scope|/}"]
      }
    },
    "remove": { "method": "DELETE", "path": "/roleManagement/defender/roleAssignments/{assignmentId}" }
  }
}
```

`{tokens}` are substituted by the engine: `{groupId}` (resolved from GroupTag via
the group cache), `{roleId}` (resolved live from listRoles by name),
`{scope|default}`, `{assignmentId}` (from the diff). Roles are never hardcoded —
they load live, so when Microsoft adds roles, pickers and validation see them with
zero maintenance. For workloads without a role-listing API the connector may carry
a static `"roles": [...]` array instead (same JSON file, still no code).

### 15.2 Layer 2 — desired state (per tenant, operator-edited)

`config/PIM-Assignments-Workloads.custom.csv` — the 15th configuration file, same
lifecycle as the other 14 (Manager grid + Delegation Map staging + Review & Save +
MSP sync + ring-independent, since these are group-level):

```
Workload;RoleName;GroupTag;Scope;Action;Notes
defender-xdr;Security operator;Defender-XDR-SecurityOperations-Operator-L3;/;Assign;
intune;Help Desk Operator;Intune-Helpdesk-L3;;Assign;
powerbi;Admin;PowerBI-Workspace-Finance-Admin-L2;{workspaceId};Assign;Finance workspace
```

Manager UX: the **Maintenance** tab has a Workload Delegation panel — pick workload
(from connectors) → roles load LIVE via the connector → pick PIM group (groups
cache) → stage the row. No typed role names.

### 15.3 Layer 3 — engine applier

`Apply-PimWorkloadAssignments` (PIM-Functions.psm1) runs as a launcher step:
1. Read desired rows; resolve GroupTag → group objectId (cached).
2. Per workload: acquire token via the auth adapter, list roles, list current
   assignments, **diff** desired vs actual.
3. Apply: POST missing assigns, DELETE rows marked `Action=Remove`. Idempotent;
   honors `-WhatIfMode` (prints the plan); logs one line per change.

### 15.4 Auth adapters (the only code; small, stable)

| Adapter | Token | Used by |
|---|---|---|
| `graph` | existing app-only Graph session (Modern SPN) | Defender XDR (`/roleManagement/defender/*`, perm `RoleManagement.ReadWrite.Defender`), Intune (`/deviceManagement/roleDefinitions` + `/roleAssignments`, perm `DeviceManagementRBAC.ReadWrite.All`), Entra-adjacent workloads |
| `arm` | Az token | Azure-hosted AI (Azure OpenAI / AI Foundry / Cognitive Services) — PLAIN ARM RBAC, largely already covered by `PIM-Assignments-Azure-Resources` (e.g. "Cognitive Services OpenAI User" at resource scope); a connector only adds role-name pickers |
| `powerbi` | resource `https://analysis.windows.net/powerbi/api` (SP must be allowed in Power BI tenant settings) | Workspace roles via `POST /v1.0/myorg/groups/{workspaceId}/users` with `groupUserAccessRight` Admin/Member/Contributor/Viewer and the PIM group as principal |
| `dataverse` | per-environment resource (`https://{org}.crm.dynamics.com`) + app user | Dynamics CRM/CE: create/ensure an **Entra group team** bound to the PIM group, then associate Dataverse **security roles** to that team (`/api/data/v9.2/teams`, `teamroles_association`) |
| `businesscentral` | BC service-to-service (admin + automation APIs) | BC supports Entra **security groups**: assign permission sets to the group via the automation API (`/api/microsoft/automation/v2.0/.../securityGroups`) |

### 15.5 Discovery companions (same framework)

Connectors may declare a `discover` endpoint (Power BI `GET /v1.0/myorg/groups` for
workspaces; ARM for new subscriptions / management groups). Discovery results stage
PROPOSED definition rows ("new workspace 'Finance' found — create PIM groups +
workload assignment?") into pending, so new resources become delegable minutes
after they exist. (Ties into the resource auto-discovery in §17.13.)

### 15.6 Phasing & maintenance hooks (design)

- **Phase 1 (SHIPPED v2.4.142):** connector schema + `defender-xdr` + `intune`
  (both pure Graph); `PIM-Assignments-Workloads` CSV + engine applier
  (`-WhatIfMode`); Manager panel with live role pickers.
- **Phase 2:** `powerbi` adapter + workspace discovery.
- **Phase 3:** `dataverse` (group teams) + `businesscentral` (security groups);
  both need per-environment app users.
- **Phase 4:** drift report — engine compares desired vs actual per workload; the
  Validate tab shows workload-side drift like any other finding.
- **Right-sizing from activation stats:** pull PIM activation history (Graph audit
  logs / `roleAssignmentScheduleInstances`) per group+role; surface "0 activations
  in N days" on the Validate tab with one-click stage-for-removal — least privilege
  by subtraction.
- **Deleted-resource auto-cleanup:** when discovery sees an Azure scope / Power BI
  workspace referenced by rows that no longer exists, stage removal AND mark the
  backing PIM groups + workload delegations for backend cleanup (engine deletes the
  Entra groups it created once nothing references them).
- **Orphaned PIM-group detection:** tenant-side groups matching the naming
  convention with no Definitions row (or vice versa) — reported as drift with
  stage-to-adopt / stage-to-delete.

---

## 16. Entra group / app catalog

Catalog of Microsoft-native workloads and common third-party apps that consume
**Entra security groups** for access/RBAC, classified by the *mechanism* — because
that determines whether PIM4EntraPS reaches them via a **workload connector**
(queryable role API) or via **standard Entra** (enterprise-app app-role assignment,
SCIM provisioning, group claims, or group-based licensing).

**Integration mechanisms (legend):**
- **RBAC-API** — the app exposes a role API where a group is assigned to a role →
  a **PIM4EntraPS workload connector** applies (build a `*.connector.json`).
- **AppRole** — assign the group to an enterprise-app *app role* (Graph
  `appRoleAssignedTo`) → generic; one connector pattern fits all.
- **SCIM** — Entra provisions the group + members into the app (SCIM 2.0) →
  governed by the provisioning job, not a role API.
- **Claim** — the app reads group membership from the token (groups/role claim) →
  assignment = add to the group.
- **License** — group-based licensing drives access.

### 16.1 Microsoft native workloads (RBAC-API / role-based)

`✅ connector built · ◑ connector-eligible (RBAC-API, not yet built) · ○ standard
Entra`:

Entra ID directory roles ◑ (`/roleManagement/directory`) · Azure RBAC
(MG/sub/RG/resource) ◑ (ARM; needs ARM auth adapter) · Intune ✅ (`intune`) ·
Defender XDR (Unified RBAC) ✅ (`defender-xdr`) · Defender for Cloud ◑ (Azure
RBAC) · Sentinel ◑ (Azure RBAC) · Purview (compliance/DLP/eDiscovery) ◑ · MDCA ◑ ·
Defender for Identity ◑ · Defender for Endpoint ◑ (device-group scoping) · Power BI
/ Fabric (workspace roles + admin) ◑ (Power BI auth adapter) · Power Platform
(environment roles, admin) ◑ · Power Apps / Power Automate ◑ · Dynamics 365
(security roles) ◑ (Dataverse) · Dataverse (security roles / teams) ◑ (per-env app
user) · Business Central (permission sets / security groups) ◑ (per-env) · Azure
DevOps (org/project security groups) ◑ (vssps auth adapter) · Exchange Online (RBAC
role groups) ◑ (EXO management) · SharePoint Online ○ AppRole/Claim + Entra role ·
Teams (admin roles = Entra roles; team membership) ○ Claim · M365 admin roles ◑
(Entra directory roles) · Azure SQL / SQL MI (Entra-only, group logins) ○ Claim ·
AKS (Entra group RBAC) ○ Claim (k8s RoleBinding) · Key Vault / Storage / App Config
◑ (Azure RBAC) · Windows 365 / Cloud PC ○ License/Claim · Entra Permissions
Management ◑ · Viva (Engage/Insights/Learning admin) ○ Claim · Stream / Forms /
Bookings / Planner / Project / Visio ○ License · Autopilot / device groups ○ Claim
· Conditional Access targeting (group-scoped) ○ Claim.

### 16.2 Microsoft 365 group-driven access (License/Claim)

M365 group-based licensing · SharePoint sites · OneDrive · Teams membership · Viva
Engage (Yammer) · Planner · Loop · Whiteboard · Stream · Bookings · Forms · Copilot
for M365 (licensing) · Outlook/EXO shared mailboxes · To Do / Lists · Project for
the web · Power Pages · Clipchamp · Places · Viva Goals · Viva Learning.

### 16.3 Common third-party SaaS (AppRole / SCIM / Claim)

~70 apps spanning Salesforce, ServiceNow, Workday, SAP (SuccessFactors / Cloud
Identity / Concur / Ariba), Slack, Zoom, Webex, Atlassian (Jira / Confluence /
Bitbucket), GitHub Enterprise, GitLab, Box, Dropbox, Google Workspace, AWS IAM
Identity Center, Okta, Adobe (Creative / Document), Zscaler (ZIA / ZPA), Cisco (Duo
/ Umbrella), CrowdStrike, Snowflake, Databricks, Tableau, Zendesk, Freshservice,
DocuSign, Smartsheet, Asana, monday.com, Notion, Miro, Figma, Lucid, Workplace,
Cornerstone, Pluralsight, LinkedIn Learning, Udemy Business, Citrix Cloud, VMware
Workspace ONE, Jamf Pro, Mimecast, Proofpoint, PagerDuty, Opsgenie, Datadog,
Splunk, Grafana, New Relic, 1Password, CyberArk, SailPoint, Saviynt, HashiCorp
Vault / Terraform Cloud, Snyk, ServiceTitan, NetSuite, HubSpot, Marketo, Qualtrics,
Airtable, ClickUp, Calendly — each tagged SCIM / AppRole / Claim per app.

### 16.4 What PIM4EntraPS does per mechanism

- **RBAC-API (✅/◑)** — a workload connector lists the app's roles and assigns the
  PIM group idempotently (`Apply-PimWorkloadAssignments`). Built: Intune, Defender
  XDR. Eligible-but-need-an-auth-adapter: Azure RBAC (ARM), Power BI,
  Dataverse/Dynamics, Business Central, Azure DevOps, Exchange Online. Graph-native
  ones (Entra directory roles, Purview, MDCA, Defender for *) drop in as new
  `*.connector.json` with the existing Graph adapter.
- **AppRole (○)** — one generic pattern: assign the PIM/Entra group to the
  enterprise app's app role via Graph `servicePrincipals/{id}/appRoleAssignedTo`. A
  single `entra-approle` connector covers every gallery app.
- **SCIM (○)** — assignment = add the group to the enterprise app's *Users and
  groups*; Entra's provisioning job pushes it. No per-app connector.
- **Claim / License (○)** — assignment = group membership; the app reads the token
  claim or the license follows the group. No connector needed.

So "100+ apps" reduce to **a handful of connector patterns**: per-workload RBAC
connectors (build as needed) + one generic `entra-approle` connector + standard
SCIM/claim/licensing (no code).

**Build order for connectors (by demand):** entra-roles (Graph, existing adapter) →
entra-approle (Graph) → azure-rbac (needs ARM adapter) → powerbi (needs Power BI
adapter) → exchange-online / dataverse-dynamics / business-central / azure-devops
(per-workload adapters, on demand).

---

## 17. Lifecycle & governance

Thirteen features across the Manager GUI, the CSV model, the engine, and the policy
layer. House rules that shaped the design: CSV stays the storage layer (until the
v3.0 SQL store, §14); the Manager stages / the engine applies; PS 5.1 compatibility
everywhere.

### 17.1 Date expressions — the shared foundation

Several features (scheduled creation, TAP windows, templates, offboarding) need "a
date, possibly relative". One resolver serves them all.

```
<expr> := Now
        | <anchor>[<offset>][@<time>]
        | <ISO date>[@<time>]            # 2026-07-01@08:00
<anchor> := FirstDayNextMonth | FirstWorkdayNextMonth | FirstDayNextWeek | FirstWorkdayNextWeek
<offset> := +<n>d | -<n>d                # calendar days
<time>   := HH:mm                        # tenant-local; omitted = 00:00
```

| Expression | Meaning |
|---|---|
| `Now` | apply on the next engine run |
| `FirstWorkdayNextMonth@08:00` | TAP valid 08:00 on the first workday of next month |
| `FirstWorkdayNextMonth-3d` | provision three days before the first workday of next month |
| `2026-06-28` | fixed date |

- `Resolve-PimDateExpression -Expression <string> [-ReferenceDate <datetime>]` in
  `engine/_shared/PIM-Functions.psm1`. Pure function. Returns `[datetime]` or
  throws with the grammar in the message.
- The Manager calls it via `GET /api/resolve-date?expr=...` so the GUI can
  live-preview ("resolves to Mon 2026-07-01 08:00").
- Validator **PIM-SCHED-001** — every date-expression column must parse.
- Workday = Mon–Fri. Holiday calendars out of scope (documented limitation).

### 17.2 Scheduled admin creation

New column on `Account-Definitions-Admins`: **`ProvisionDate`** (date expression;
blank = `Now`, backward compatible). Engine
(`CreateUpdate-Accounts-From-file-CSV`): rows with
`Resolve-PimDateExpression(ProvisionDate) > now` are **skipped with a log line**
(`SCHEDULED: <upn> provisions at <resolved>`); the row stays and materializes on
the first run at/after the resolved time. `StartDate` keeps its informational
meaning; `ProvisionDate` is *when the engine acts*. Validator **PIM-SCHED-002**
(warning) — `TAPStartDate` earlier than `ProvisionDate`.

*Why:* customer provisions the person's normal account a week early; the admin row
is staged with `ProvisionDate`, `ForwardMailsToContact=TRUE`, `MailForwardAddress`,
`CreateTAP=TRUE`, `TAPStartDate`, `TAPLifetimeHours`. The engine creates the admin
+ forwarding on the provision date; the TAP mail lands in the already-live mailbox;
the TAP itself only works in its window.

### 17.3 Scheduled TAP window

- `TAPStartDate` feeds `New-PimTemporaryAccessPass -StartDateTime`; now accepts
  date expressions.
- New column **`TAPLifetimeHours`** → `lifetimeInMinutes` on the Graph TAP body
  (Graph allows 10–43200 min; validator **PIM-TAP-002** range-checks). Blank =
  tenant default (60 min).
- **TAP creation is deferred to the engine run nearest the start date**: Graph
  rejects far-future `startDateTime` on some tenants and a long-pending TAP is a
  standing credential. When `TAPStartDate` resolves more than
  `$global:PIM_TapCreateLeadHours` (default 48) ahead, the engine logs
  `TAP DEFERRED` and creates it on a later run inside the lead window — so the TAP
  mail sends close to when the recipient can use it.
- **GUI**: `CreateTAP`, `TAPStartDate` (live resolve preview), `TAPLifetimeHours`
  group into one **"Temporary Access Pass"** fieldset; `UsageLocation` moves out to
  the identity/locale group.

### 17.4 Admin templates

Prestage admin settings as named templates, same file pattern as permission
templates:

```
templates/admin/<id>.admintemplate.json        # shipped (locked)
templates/admin/<id>.admintemplate.custom.json # customer-defined (gitignored)
```

```json
{
  "id": "new-employee-next-month",
  "name": "New Employee Next Month",
  "prefill": {
    "TierLevel": "L1", "TargetUsage": "Cloud", "TargetPlatform": "ID", "UserType": "Member",
    "UsageLocation": "DK", "Ring": "2",
    "ForwardMailsToContact": "TRUE", "CreateTAP": "TRUE",
    "ProvisionDate": "FirstWorkdayNextMonth-3d",
    "TAPStartDate": "FirstWorkdayNextMonth@08:00", "TAPLifetimeHours": "8"
  },
  "assignments": [ { "GroupTag": "<role-group-tag>", "AssignmentType": "Eligible" } ]
}
```

Two shipped templates: **`consultant`** (time-boxed, `NumOfDaysWhenExpire`
prefilled, TAP `Now`) and **`new-employee-next-month`** (above). The onboarding
wizard gains a template picker; choosing one prefills fields (all editable before
staging). The materialized row gets a **`Template`** column value for traceability;
templates are *prestage only* (later edits don't retro-apply). `GET
/api/admin-templates` mirrors `/api/templates`.

### 17.5 Ring moves in the Manager

The `Ring` column is editable in the Advanced grid; first-class affordances:
Delegation Map admin-card action **"Move to ring…"**; Advanced-grid bulk-select +
"Set ring". Validator **PIM-RING-001** (value); **PIM-RING-002** (info) when a
ring is *lowered* (promotes earlier deployment).

### 17.6 Mail templates

Every engine-sent mail is a customizable template:

```
templates/mail/<type>.mailtemplate.html         # shipped default (locked)
templates/mail/<type>.mailtemplate.custom.html  # customer override (gitignored, wins)
```

Types: `new-admin`, `tap-delivery`, `new-role`, `new-permission`,
`approval-request`, `approval-escalation`, `offboarding-notice`. Subject = first
line as an HTML comment (`<!-- subject: ... -->`). Token substitution (straight
string replace): `{{DisplayName}} {{UserPrincipalName}} {{TapCode}} {{TapStart}}
{{TapLifetimeHours}} {{RoleName}} {{GroupName}} {{GroupTag}} {{Sponsor}}
{{ManagerEmail}} {{Company}} {{TenantName}} {{Date}}` — unknown tokens render empty
+ a warning. `Send-PimTemplatedMail -Type <type> -To <addr> -Tokens <hashtable>`
resolves custom-over-locked and routes through `$global:PIM_NotificationChannels`;
the current hardcoded bodies become the shipped defaults. Manager: a read-only
"Mail templates" listing on the Governance tab (editing happens in files).

### 17.7 Policy templates per role

Bundle the existing `$global:<Role>_<Rule>_..._<Setting>` policy variables into
named, linkable templates:

```
templates/policy/default.policytemplate.json            # MFA + justification on enablement, expirations, notifications
templates/policy/approval-required.policytemplate.json  # default + ApprovalRule (GA groups, tenant-root owner groups, PRA)
```

```json
{
  "id": "approval-required",
  "extends": "default",
  "rules": {
    "Enablement_EndUser_Assignment_enabledRules": ["MultiFactorAuthentication", "Justification"],
    "Approval": { "mode": "Serial", "approversSource": "Owners", "escalationHours": 4 }
  }
}
```

**Linking**: column **`PolicyTemplate`** on the definition CSVs. Blank = `default`.
Validator **PIM-POL-001**: referenced template must exist. **Engine re-apply**: the
engine computes a content hash per template; `output/state/policy-state.json` maps
`GroupTag → {templateId, appliedHash, appliedAt}`. When the linked template's hash
differs, the engine re-materializes the unifiedRoleManagementPolicy rules for that
group. Unchanged = NoChange, idempotent. `extends` is single-level only.

### 17.8 Approvals — parallel and serial

Entra PIM's native `ApprovalRule` supports a primary-approver set where any one
approval wins (= parallel). **Serial is not native** — the engine implements it as
timed escalation:

| Mode | Mechanism |
|---|---|
| `None` | no ApprovalRule (auto-approved) |
| `Parallel` | native ApprovalRule, `primaryApprovers` = all resolved owners; first approval wins |
| `Serial` | native ApprovalRule with **owner[1] only**; the engine's escalation sweep finds activation requests `status=PendingApproval` older than `escalationHours` and rewrites the policy's approver to owner[2] (then [3]…), emailing `approval-escalation` to the new approver. Order = the `Owners` column order. |

Approvers resolve via the **same chain as group ownership** —
`Owners` column → `SponsorUpn` → the group's **Department contact**
(`Resolve-PimGroupOwnerIds`). This matters because a service/permission group almost always
has a *blank* `Owners` column and inherits its department's owners; resolving only the literal
`Owners` column would leave an approval-required group with **zero approvers**, which Graph
rejects (`InvalidPolicy`, HTTP 400). The engine therefore throws a clear error if approval is
required but no approver resolves (set Owners/SponsorUpn or a Department contact). Validator
**PIM-APR-001**: a definition linked to an approval-mode template must have ≥1 resolvable
approver (≥2 for Serial). Two live-PATCH gotchas the engine guards against (both surface as
`InvalidPolicy`): a `singleUser` approver must carry **only** `@odata.type` + `userId` (a
`description` property is rejected); and a single-stage approval must not enable escalation
(`isEscalationEnabled`) unless it actually has escalation approvers — so escalation is on only
when Serial **and** at least one escalation approver resolves. The escalation sweep is part of
the normal engine run (latency bounded by run frequency; schedule hourly on Serial tenants).
Manager: role/permission cards show an approval chip (`Auto` / `Parallel (n)` /
`Serial (n, esc. 4h)`). **Live-verified 2026-06-14** against a real PIM-for-Groups member
policy on a marker-fenced lab group (approver inherited from the group's department).

### 17.9 Emergency override (break-glass)

For GA / PRA / tenant-root-owner groups protected by `approval-required`:
- **Activation**: Manager Governance tab → "Emergency override" (SuperAdmin only)
  → operator enters the **emergency passphrase**, verified server-side against the
  per-instance Key Vault secret `PIM-EmergencyPasscode` (never stored locally;
  in-memory comparison). On success the server writes
  `config/emergency-override.custom.json`:
  `{ active, scopeGroupTags[], activatedBy, activatedAt, expiresAt }` and
  immediately applies: ApprovalRule **disabled** on the scoped groups.
- **Auto-restore**: TTL default 4h (max 24h). Every engine run checks the file;
  expired → re-apply the linked policy template (the §17.7 hash mechanism makes
  this free) and archive the override to `output/audit/`.
- **Audit**: activation, every policy change it caused, and restoration are all
  audit events — plus an immediate notice mail to all owners of the scoped groups.
- Wrong passphrase: constant-time compare, 5 attempts → endpoint locks 15 min,
  audit either way.

### 17.10 Offboarding

Three levels, all engine-applied and audited:
1. **Admin offboarding** — new columns **`OffboardDate`** (date expression) and
   **`DeleteAfterDays`** (blank = never delete). At/after OffboardDate the engine:
   disables the account → removes ALL its PIM group memberships + eligibilities →
   revokes active sessions → after `DeleteAfterDays` more days, deletes the
   account. Each step a separate audited transaction; `AccountStatus` reflects
   progress (`Offboarding` → `Offboarded`).
2. **Role / permission-group offboarding** — assignment CSVs support
   `Action=Remove`; additionally a definition row with **`Lifecycle=Retire`** makes
   the engine remove the group's role assignments, then memberships, then (only if
   the engine created it — displayName-prefix guard) the group itself.
3. **Drift cleanup** — `$global:PIM_OffboardCleanupMode = 'Off' | 'Report' |
   'Enforce'` (default `Report`): the engine diffs live memberships of
   engine-managed groups against the CSVs; `Report` lists orphans, `Enforce`
   removes them.

### 17.11 Audit — one schema, append-only

All engine and Manager transactions converge on
**`output/audit/pim-audit-<yyyyMM>.jsonl`** (one JSON object per line, append-only,
monthly):

```json
{ "ts": "2026-06-12T10:55:01Z", "runId": "…", "correlationId": "…",
  "actor": "engine | manager:<upn> | emergency:<upn>",
  "action": "account.create | account.disable | tap.create | assignment.add | assignment.remove | policy.apply | approval.escalate | emergency.activate | emergency.restore | mail.send | resource.discovered | …",
  "target": "<upn | GroupTag | scope>", "before": { }, "after": { }, "result": "ok | error:<msg>" }
```

Existing logs stay (passwords/TAPs files are delivery channels, not audit) but
every event ALSO emits a jsonl line; `pim-manager-mutations.log` events fold into
the same schema (`actor: manager:<upn>`). Optional sink: a sample uploader using
AzLogDcrIngestPS to a Log Analytics custom table (config-gated, off by default).
Manager Governance tab: filterable audit viewer (Reader role may view).

### 17.12 Manager RBAC — Reader / Admin / SuperAdmin

- **Identity**: the Manager binds to localhost; the acting identity is the Windows
  user that launched it
  (`[Security.Principal.WindowsIdentity]::GetCurrent()`), recorded on every
  mutation. (Under the v3.0 MFA work, §17.16, the identity becomes the Entra UPN.)
- **Mapping**: `config/manager-access.custom.json`:
  `[ { "identity": "DOMAIN\\user | upn", "role": "Reader|Admin|SuperAdmin" } ]`.
  File missing → launcher is SuperAdmin (backward compatible). File present and
  launcher unlisted → Reader.
- **Gates** (server-side per endpoint; the GUI also hides what the role can't do):

| Capability | Reader | Admin | SuperAdmin |
|---|---|---|---|
| View map/grid/validate/audit | ✔ | ✔ | ✔ |
| Stage + commit CSV edits, revoke, ring moves | | ✔ | ✔ |
| Instance switching, template/policy editing, refresh caches | | | ✔ |
| Emergency override, manager-access editing, maintenance | | | ✔ |

New tab: **Governance** — audit viewer, mail-template status, emergency override,
discovered resources, access list. Tab visibility role-gated. (The finer-grained
`Delegated` / portal-admin model layers on top — §9.2.)

### 17.13 Resource auto-discovery

`_tenantSync.ps1` snapshots Entra roles, AUs, Azure scopes, and PIM groups.
Discovery = diff current vs previous snapshot
(`cache/<instance>/discovery-baseline.json`): new Azure subscriptions / management
groups, new built-in Entra roles, and (via connector live role listing) new
workload resources such as Power BI workspaces surface as **discovered items**. Per
resource type, `config/resource-discovery.custom.json` selects handling:
`"Off" | "Portal" | "Engine"`. **Portal**: the Governance tab lists items; one
click stages naming-convention-generated definition + assignment rows into pending.
**Engine**: the engine auto-generates and applies the same rows on its run (zero
touch), emitting `resource.discovered` + `resource.onboarded` audit events and a
`new-permission` mail. Row generation reuses the naming-conventions module.

### 17.14 Access reviews — business-driven extend/remove (design)

**The circularity problem**: Entra Access Review auto-apply removes a member in
Entra, but the CSV is the source of truth — the engine re-delegates on the next run
(and drift cleanup actively enforces CSV-wins). Native auto-apply is fundamentally
incompatible with a declarative engine. **Decision: hybrid.** Entra Access Reviews
provide the reviewer UX (MyAccess portal, reminders, delegation); the engine owns
both the review lifecycle and the application of decisions. Reviews NEVER touch
Entra directly.

1. **Engine creates + maintains review schedule definitions**
   (`accessReviewScheduleDefinitions`) for opt-in groups — `ReviewCycle` carried by
   the policy template or a per-row column. Reviewers = the row's **Owners**.
   **Auto-apply = OFF** on every review the engine creates; it warns about (and
   refuses to manage) reviews with auto-apply ON against engine-managed groups.
2. **Decision sweep** (`Invoke-PimAccessReviewSync`, every run): pulls completed
   instances' decisions. **Approve** → keep; optionally re-stamp expiry
   (`NumOfDaysWhenExpire` restarts) — the consultant-extension scenario. **Deny** →
   write a **tombstone** `(principal, GroupTag, reviewId, decidedAt)` to the
   engine-owned suppression layer `output/state/review-tombstones.json` (the engine
   does NOT edit customer CSVs).
3. **Tombstone layer**: the assignment step treats a tombstoned pair as
   `Action=Remove` regardless of the CSV. Validator **PIM-REV-001** flags the row.
   The human reconciles the CSV at their own pace.
4. Everything audited (`review.created`, `review.decision`,
   `review.tombstone.applied`) + notice mail to the denied principal's manager.

### 17.15 External request intake — ServiceNow et al. (design)

**Constraints**: pull-not-push; NO inbound endpoint, webhook, function, or
internet-exposed storage; a compromised workflow must never create an admin or
activate a role. **Direction**: requests flow FROM ServiceNow INTO the Manager —
the Manager owns ingestion; the engine never reads external input (it stays purely
declarative). Zero attack surface added to the engine.

**Transport (primary, fully internal)**: ServiceNow workflow → **ServiceNow MID
Server** (the customer's existing internal broker, outbound-only to SNOW cloud) →
drops a signed request file into an **internal inbox directory** (SMB share /
folder reachable from the Manager box). Directory ACL: the MID service account has
**create-only** rights (cannot read/modify/delete queued files); the Manager's
account owns the folder and moves every file to `processed/` or
`rejected/<reason>/` after verification. No service listens anywhere; delivery is
decoupled from the Manager's lifetime. Processing is two-tier, routed per request
type by `config/intake-routing.custom.json` (`Approve` = default | `Auto`):

- **`Invoke-PimIntakeProcessor`** — a small headless scheduled task (~10 min; same
  verification code the Manager uses; NOT a listener). `Auto`-routed verified
  requests become rows in a dedicated **intake overlay CSV**
  (`PIM-Assignments-FromIntake.custom.csv`) + audit + confirmation; the engine's
  assignment step unions the overlay with the main CSVs — the engine still never
  reads raw external input, only this verified artifact, and the overlay avoids
  write-races with an open Manager session. `Approve`-routed requests stay queued
  and trigger a "N requests awaiting approval" operator mail.
- **The Manager GUI** is the attended path: the Governance tab shows the queue;
  operator approval stages rows through pending → Review & Save into the main CSVs.
  Overlay rows render with a provenance badge ("from ServiceNow REQ0012345").

*(Fallback for customers without MID servers: an Azure Storage queue in the
customer subscription, SNOW writing with a single-container-scoped SP — still
outbound-only both sides, drained by the same processor.)*

**Security layers (defense in depth, each Key-Vault-rotatable):**
1. **Payload signing**: SNOW signs `type + payload + timestamp + nonce`
   (HMAC-SHA256 shared secret, or RSA with the public key in KV). The engine
   verifies, rejects timestamps older than ~15 min, keeps a processed-nonce ledger
   — file-drop access alone yields nothing; replay fails.
2. **Typed allow-list**: `assignment.add`, `assignment.remove`, `admin.onboard`
   only. `admin.onboard` may ONLY reference a shipped/customer **admin template
   id** — SNOW instantiates pre-approved shapes, never arbitrary accounts.
3. **High-priv hard deny**: any group whose `PolicyTemplate = approval-required`
   (GA, PRA, tenant-root owners) is NOT requestable through the intake, ever.
4. **Activation out of scope by design**: the intake manages
   assignments/onboarding only. Activating a role stays exclusively behind PIM's
   MFA + approval policies.
5. **Human in the loop by default, auto only where explicitly routed**: either way
   the change reaches Entra only through the declarative CSV layer.
6. **Full audit**: `request.received` / `request.rejected` (with reason) /
   `request.applied` in the jsonl.

### 17.16 Manager MFA + remote operation (design, v3.0)

**Manager MFA**: on startup the Manager requires an interactive Entra sign-in
(reusing the Edge PKCE loopback flow from the activator backend), verifies the
token's `amr` claim includes MFA, and maps RBAC to the **Entra UPN** instead of the
Windows identity — which also activates everything Conditional Access can add
(compliant device, sign-in frequency). Honest scope: this protects USE of the
Manager and its tenant connections; it cannot protect the files on the automation
server from an attacker who already has code execution there — host hardening (PAW,
JIT) remains its own discipline. **Remote operation today**: `-ConfigRoot
\\server\share` over SMB works now but is a workaround (ACLs, duplicate module
installs, no concurrency); the SQL store (§14) is the real answer. (Both converge
with the SQL data store onto one v3.0 architecture.)

### 17.17 Email routing & people directory — no per-admin manager maintenance

**Problem**: `ManagerEmail` per admin row is hard to maintain at fleet scale, and a
leaver's address lingers in many places. **Where an email is needed**: TAP-delivery
+ new-admin lifecycle mails; approval/owner mails (already group-scoped via Owners
— stays); serial-approval escalation + offboarding notices; access-review reviewers
+ intake nudges.

**Design — three layers, deterministic resolution order:**
1. **Department link instead of person link**: `Account-Definitions-Admins` gains a
   `Department` column; a new **`config/PIM-Definitions-Contacts.custom.csv`** (the
   people directory) holds one row per department/function:
   `Department;ManagerEmail;DeputyEmails;Mode(Serial|Parallel)`. Manager churn =
   one row edit.
2. **Central override**: `config/mail-routing.custom.json` —
   `{ "AdminLifecycleRecipients": [...], "Mode": "Parallel|Serial",
   "PerAdminWins": true|false }`. With `PerAdminWins=true` (default) a filled
   per-admin `ManagerEmail` still wins; `false` forces the central route.
3. **Per-admin `ManagerEmail`** becomes an optional override.

Resolution: per-admin (if set AND PerAdminWins) → department contact row → central
AdminLifecycleRecipients → skip-with-audit if nothing resolves. Manager GUI —
"Contacts & email flow" (new Governance sub-tab): edit the directory + routing with
live "who would get the TAP mail for admin X?" preview; **"Person left" sweep**
(enter an email → scan EVERY reference → stage a replace-all-with-successor through
pending → Review & Save, audited `contact.replaced`). Approvals stay EXPLICIT on
the specific high-priv groups — this section changes who gets *notified/escalated
to*, never *what requires approval*.

### 17.18 Self-service delegation layers (design, exploratory)

**Ask**: let business units self-manage a bounded slice (create/enable their own
admins, auto-disable after N days without sign-in, delegate a scoped permission
subset) without giving them the Manager or the engine. **Verdict: feasible as a
LAYER — the delegation boundary is data, not new privilege machinery:**

1. **Delegation units**: `config/PIM-Definitions-DelegationUnits.custom.csv`:
   `UnitTag;Department;AllowedAdminTemplates;AllowedGroupTags;AllowedAzScopePrefix;MaxAdmins;InactivityDisableDays;ApproverContact`.
   A unit = (who may ask) × (which admin templates) × (which group tags / Azure
   scope prefixes) × (quotas). Example: `BU-Finance` may onboard `consultant`-
   template admins and assign only `ROLE-Finance-*` groups and Azure scopes under
   `/providers/Microsoft.Management/managementGroups/mg-finance`.
2. **Self-service front end = the §17.15 intake, not a new trust path**: requests
   land as signed intake requests and materialize ONLY through the declarative CSV
   layer with the §17.15 guardrails. The delegation unit is the authorization
   filter the intake processor enforces per requester.
3. **The permanently-running web service**: a small internal-only site (Entra
   sign-in + MFA, RBAC by delegation unit, runs as a low-priv identity with NO
   Graph write permissions — it can only write signed intake files). Even fully
   compromised it can request nothing outside its unit's envelope; high-priv is
   structurally unreachable. **Hosting options, both zero public ingress**:
   **Azure private-endpoint deployment (PREFERRED)** — App Service / Container Apps
   with `publicNetworkAccess=Disabled` + a Private Endpoint into the corp VNet; its
   intake drop lands on Azure Files/Blob behind a private endpoint, pulled by the
   on-prem intake processor (pull-not-push preserved). MI holds storage-write only.
   **On-prem IIS/Kestrel** on the automation subnet (fallback).
4. **Inactivity auto-disable**: engine-side sweep (no service needed) —
   `signInActivity.lastSignInDateTime` vs `InactivityDisableDays` per unit; expired
   admins get `AccountStatus=Disabled` staged (Report) or applied (Enforce) + audit
   + notice mail. Also benefits non-delegated admins as general hygiene.
5. **Azure scope slicing**: already native; the unit's `AllowedAzScopePrefix`
   confines self-service rows to subscriptions under the unit's management group.

Build order when scheduled: §17.17 (contacts/routing) → intake processor
(§17.15) → delegation-unit filter → inactivity sweep → portal front end last.

### 17.19 Phasing summary

Date-expression resolver + ProvisionDate/TAPLifetimeHours + TAP deferral + TAP GUI
grouping + ring-move UI + validators; admin templates + mail templates + policy
templates + hash re-apply; approvals (parallel native + serial escalation, Owners
functional); offboarding + drift cleanup; unified jsonl audit; Manager RBAC +
Governance tab; emergency override — all built across the v2.4.15x line. Access
reviews, external intake, and the Manager-MFA + SQL data store (the v3.0 line) are
agreed design, not yet built. (Exact per-phase status lives in `REQUIREMENTS.md`.)

### Out of scope / known limitations (this area)

- Holiday-aware workday calculation (Mon–Fri only).
- Serial-approval escalation latency bounded by engine run frequency.
- Mail-template GUI editor (file-based editing first).

---

## 18. Manager / GUI + UX

### 18.1 What the Manager is

Interactive graph viewer + grid editor for the configuration model. It ships a
multi-tab SPA (Graph / Grid / Save / Maintenance / Governance) backed by a
localhost-only HttpListener; an earlier static read-only HTML is still available
via `-StaticHtml`. Loads in any browser, no install beyond `git pull`. In the
hosted topology it runs in the always-on App Service container behind Easy Auth and
private endpoints (§11). It is the answer to "what does activating PIM-ROLE-X
actually let me do?" — it reads the model and shows the Admin → Role group →
Permission group → Service chain visually, with a tier-coloured DAG.

### 18.2 UX goal — zero memorization

The operator opens the Manager every few weeks at most. Each input that demands
they remember the schema (GUIDs, ARM paths, role display names, naming-convention
slugs) is friction. Every column across the configuration tables maps to an input
strategy: **dropdown** (fixed small enum), **autocomplete** (type-ahead, medium
cardinality, "type custom" on miss), **tenant cache** (from
`tools/pim-manager/cache/*.json`, refreshed via `Open-PimManager.ps1
-RefreshTenantLists`, auto-runs when stale/missing), **cross-CSV** (from another
loaded CSV), **inherited** (read-only auto-fill from another selected value, with
an "override" toggle), **auto-derived** (computed from naming-convention pattern +
other inputs, live-previewed).

### 18.3 Per-table input strategy (the field-by-field audit)

#### Account-Definitions-Admins

| Column | Input | Source / default | Notes |
|---|---|---|---|
| FirstName / LastName | text | required | |
| Initials | auto-derived | First[0]+Last[0..1] uppercased | editable |
| TierLevel | dropdown T0/T1/T2 | T1 | |
| TargetUsage | dropdown Cloud/Legacy/Both | Cloud | |
| TargetPlatform | dropdown ID/AD/Both | ID | controls whether AD-side rows are generated |
| UserType | dropdown Internal/External/Guest | Internal | |
| UserName | auto-derived | `Admin-<Init>-T<Tier>-<Platform>` | editable; live preview |
| DisplayName | auto-derived | `<First> <Last> (Admin, <Usage>, <Platform>, L<Lvl>, T<Tier>)` | editable |
| UserPrincipalName | auto-derived | `<UserName>@<DefaultDomainUPN>` | dropdown if multiple domains |
| UsageLocation | dropdown ISO 3166-1 alpha-2 | tenant default | |
| ForwardMailsToContact | checkbox → TRUE/FALSE | FALSE | |
| MailForwardAddress | autocomplete tenant users | — | only shown when Forward=TRUE |
| Company | text | empty | pushed to Entra `-CompanyName` only when non-empty |
| Notes | textarea | empty | max 1024 chars; logged as a comment, NOT pushed to Entra |
| ManagerEmail | autocomplete tenant users | empty | resolved to Graph user id + `manager@odata.bind` after create; silently skips if unresolved |
| StartDate | date picker | empty | informational only |
| CreateTAP | checkbox | TRUE for Cloud/ID admins | |
| TAPStartDate | date picker | empty (= immediate) | |
| AccountStatus | dropdown Enabled/Disabled/Revoked | Enabled | gated by StatusChangeCode in MSP variant |
| StatusChangeCode | text + KV-validation status | — | only shown when status != Enabled; shows "verified vs KV" inline |

(Plus the lifecycle columns from §17: `ProvisionDate`, `TAPLifetimeHours`,
`Template`, `OffboardDate`, `DeleteAfterDays`, `Department`, `Ring`.)

#### PIM-Definitions-Roles (role groups)

| Column | Input | Source / default |
|---|---|---|
| GroupName | auto-derived | naming pattern, editable, live preview |
| GroupDescription | text | required, plain-English |
| GroupTag | auto-derived | naming-pattern suffix; unique across all definition CSVs (validated) |
| AdministrativeUnitTag | autocomplete cross-CSV from `PIM-Definitions-AU` | optional |
| CPPlatform | dropdown CP/WDP/MP/APP/USER | CP |
| Plane | dropdown ID/RES/DAT | ID |
| TierLevel | dropdown T0/T1/T2 | T0 (role groups usually T0) |
| PermissionScope | dropdown Global/Scoped | Global |
| SyncPlatform | dropdown AD/none | none |
| IsRoleAssignable | checkbox | TRUE | warning if FALSE + a role-assignment row references this tag |
| SponsorUpn | autocomplete tenant users | empty | role's audit/renewal owner; engine reads, doesn't enforce yet |
| SponsorNotes | text | empty | free-text justification |

#### PIM-Definitions-{Tasks, Services, Processes, Resources, Departments, Organization}

Same shape; permission groups instead of role groups. Wizard B picks which file the
row goes into via a single "What kind of capability?" dropdown.

| Column | Input | Source / default |
|---|---|---|
| GroupName | auto-derived | naming pattern |
| GroupDescription | text | required |
| GroupTag | auto-derived | unique-globally validated |
| AdministrativeUnitTag | autocomplete cross-CSV | optional |
| IsRoleAssignable | checkbox | depends on Entra-role assignment intent |
| Workload | dropdown | enum from naming convention |
| Level | dropdown L0..L9 | inherited from Tier per §3.4 |
| TierLevel | dropdown T0/T1/T2 | T1 |
| Plane | dropdown ID/RES/DAT | ID |
| CPPlatform | dropdown CP/WDP/MP/APP/USER | WDP |
| Owners | autocomplete tenant users (multi-select) | empty | upn list joined with `\|`; type 3 chars |
| PolicyTemplate | dropdown of template ids | blank = default |

#### PIM-Definitions-AU

| Column | Input | Source / default |
|---|---|---|
| AUDisplayName / AUDescription | text | required |
| AdministrativeUnitTag | auto-derived | from AUDisplayName slug |
| Workload | dropdown | enum |
| Level / TierLevel | dropdowns | |
| Visibility | dropdown Public/HiddenMembership | Public |

#### Assignment CSVs (shared dropdown columns + per-file keys)

All assignment files share: `AssignmentType` (Eligible/Active),
`Action` (Assign/Remove), `UpdateExisting` (TRUE/FALSE),
`AutoExtend` (TRUE/FALSE, default TRUE), `NumOfDaysWhenExpire`
(90/180/365/Custom…, default 365), `Permanent` (TRUE/FALSE), and the inherited
columns `CPPlatform / Plane / TierLevel / PermissionScope / SyncPlatform` (each
with an override toggle).

- **PIM-Assignments-Admins** (admin → role-group): `Username` autocomplete from
  `Account-Definitions-Admins` UPN; `GroupTag` autocomplete from
  `PIM-Definitions-Roles`, FK-validated; `AssignmentType` default Eligible.
- **PIM-Assignments-Groups** (role-group nests permission-group): `TargetGroupTag`
  (container) from `PIM-Definitions-Roles`; `SourceGroupTag` (member) from the
  union of the permission-group definition CSVs, FK-validated; `AssignmentType`
  default Active.
- **PIM-Assignments-Roles-Groups** (permission-group → Entra ID role): `GroupTag`
  from definition CSVs; `RoleDefinitionName` **dropdown from
  `cache/entra-roles.json`**.
- **PIM-Assignments-Roles-AUs** (permission-group → AU-scoped Entra role):
  `GroupTag`; `AdministrativeUnitTag` **dropdown from `cache/aus.json`** + cross-CSV;
  `RoleDefinitionName` dropdown filtered to AU-supported roles.
- **PIM-Assignments-Azure-Resources** (permission-group → Azure RBAC): `GroupTag`;
  `AzScope` **tree picker** (MG → sub → RG → resource) backed by
  `cache/azure-scopes.json`, full ARM path resolved on selection;
  `AzScopePermission` dropdown "Common roles" (Owner / Contributor / Reader / User
  Access Administrator / Storage Blob Data Reader) + "Custom…" (full per-scope role
  enumeration is a later increment).

### 18.4 Cross-cutting UX rules

1. No typed GUIDs / no typed ARM paths — always a picker.
2. No typed role display names — always cache-backed dropdown.
3. Inheritance saves typing — selecting a `GroupTag` populates 5 downstream
   columns; "override" toggle reveals the underlying cell.
4. Naming convention auto-applied — the wizard composes `GroupName`/`GroupTag` from
   semantic inputs (Service, Capability, Level, Tier).
5. Live previews everywhere — auto-derived fields show their computed value next to
   the inputs that feed them.
6. "Custom…" escape hatch on every dropdown — never trap the operator on a stale
   cache or one-off value.
7. TRUE/FALSE strings rendered as checkboxes, serialized as `TRUE`/`FALSE` (stable
   diff).
8. Tenant cache auto-refreshes on launch when stale (>24h) or missing.
9. Owners columns are multi-select autocomplete (type 3 chars → `displayName
   <upn>`).
10. Sticky defaults — last-picked `NumOfDaysWhenExpire` / `AssignmentType` /
    `AutoExtend` become the next default in the session.

### 18.5 Manager features by area

- **Graph/DAG viewer** with side panel; tier-coloured.
- **Grid editor + Review & Save**: edits `.custom.csv` only, diff preview before
  commit.
- **Validator**: missing-GroupTag detector, stale Entra-role detector, tier-safety
  lint, plus the PIM-* validator rules across the lifecycle features (§17).
- **Maintenance tab**: Workload Delegation panel (§15.2).
- **Governance tab** (role-gated): audit viewer, mail-template status, emergency
  override, discovered resources, access list, contacts/email-flow (§17.11–17.17).
- **Wizards**: new-admin onboarding (template picker, TAP fieldset), capability
  wizard ("what kind of capability?"), tag global-rename.
- **Live tenant overlay** (CSV vs tenant drift on the graph) and the Azure RBAC
  per-scope role dropdown are later increments.

---

## 19. Licensing

### Model

- **Core is free** and fully functional: the single-tenant declarative engine, all
  configuration CSVs, the PIM Manager (grid, wizards, map, validator, Review &
  Save), admin lifecycle (create/TAP/offboard), policy templates, owners-as-
  approvers, audit — **and the SQL data store** (SQL is Core, never licensed).
- **Pro features require a license file**: MSP multi-tenant (registry + ring
  fan-out), workload connectors, external intake (ServiceNow), access reviews,
  self-service delegation, contacts/email-flow routing. Gate names: `MspFanout`,
  `WorkloadConnectors`, `Intake`, `AccessReviews`, `SelfService`,
  `ContactsRouting`.

### The license is 100% offline

Customers receive a `.pimlicense` file and drop it into `config\`. Nothing phones
home; no public endpoint, no activation server, no internet needed. Verification is
an RSA-SHA256 signature check against the **public** certificate embedded in
`engine/_shared/PIM-License.ps1` (PS 5.1-safe: raw-bytes `X509Certificate2`, no PEM
parsing). The signing **private key is a non-exportable machine-store certificate
on the maintainer's management host** (`CN=PIM4EntraPS-Licensing`) — same trust
model as the Activator and baseline signing keys. Licenses are issued with the
internal-only `INTERNAL\pim-licensing\New-PimLicense.ps1`, which never ships.

```json
{ "product": "PIM4EntraPS", "payloadB64": "<base64 payload JSON>", "signature": "<base64 RSA-SHA256>" }
```

Payload: `licenseId, customer, sku, features[] ('*' = all), tenantIds[], validFrom,
validTo, graceDays`. The signature covers the exact payload bytes — any edit
invalidates the file.

### Semantics

| Aspect | Behavior |
|---|---|
| Tenant binding | `tenantIds` non-empty → the connected tenant must be listed. MSP fan-out checks per tenant and **skips** unlicensed ones (the rest of the fleet still deploys). Empty list = any tenant (evaluations). |
| Expiry | After `validTo`, a grace window (`graceDays`, default 30) keeps Pro working with a renew warning. After grace, Pro disables. **Core is never affected — an expired license can never break a tenant.** |
| Visibility | Manager Governance tab shows a License panel; engine runs print one status line; blocked gates emit one operator message + a `license.blocked` audit event. |
| Enforcement honesty | PowerShell is source-distributed — the in-product gate is a compliance/UX mechanism, not DRM. The real boundary is distribution: Pro feature code ships from a private channel; Core stays public. The license file makes entitlement provable offline. |

### Gating a feature (pattern)

```powershell
if (-not (Test-PimProFeature 'MspFanout')) { return }                    # whole feature
if (-not (Test-PimProFeature 'MspFanout' -TenantId $t.TenantId)) { ... } # per tenant
```

`Get-PimLicense` (cached, `-Refresh`), `Test-PimProFeature`,
`Get-PimLicenseStatusText` live in `engine/_shared/PIM-License.ps1`, dot-sourced by
the engine module and the Manager. `*.pimlicense` is gitignored everywhere —
customer licenses never enter the repo.

---

## 20. Launcher flavors

Every engine is wrapped in 4 launchers:

| | VM (long-running host) | Azure (serverless) |
|---|---|---|
| **Internal** | `launcher.internal-vm.ps1` | `launcher.internal-azure.ps1` |
| **Community** | `launcher.community-vm.ps1` | `launcher.community-azure.ps1` |

- **Internal vs Community**: internal launchers may depend on a vendor's bootstrap
  library (Key Vault wiring, gMSA handling). Community launchers use only public
  Microsoft modules — installable from PSGallery by anyone.
- **VM vs Azure**: VM launchers do interactive console + transcript log to
  `logs/`. Azure launchers use managed identity, log to App Insights, and skip
  anything that needs on-prem AD.

The public repo (the mirror) ships only the **community** launchers (internal-*
files are stripped by the publish workflow). The engine code itself is identical
across flavors.

---

## 21. Companion tools & projects

### Activator (`tools/pim-activator/`)

Edge browser extension. Admin clicks the toolbar icon → list of eligible
PIM-for-Groups assignments → multi-select → enter justification + duration →
**Activate**. Replaces clicking through the PIM portal one role at a time.
Two-stage rollout: (1) one-time per tenant —
`Deploy-PimActivatorBackend.ps1` creates the app registration with the right
delegated permissions; (2) per PAW — `Deploy-PimActivatorClient.ps1` writes Edge
enterprise policy keys (force-install + per-tenant config), Intune-deployable
unattended.

### Companion projects (combinable, same author)

- **PIM4ActiveDirectoryPS** — automation of PIM for on-prem AD; uses Entra PIM as
  the session initiator and propagates time-bounded membership into AD via the
  Windows Server 2016+ PAM feature. See §21.1.
- **EntraPolicySuite** — CLI management of Entra Conditional Access policies, named
  locations, and authentication strengths; 120+ curated CA policies. The natural
  pair for PIM4EntraPS because CA is what gates PIM activation.
- **PIM-Role-Advisor** — given a task the admin wants to perform, recommends the
  smallest PIM role / permission group that grants it. Closes the "which group do I
  activate?" gap that the Manager diagnoses structurally.

### 21.1 PIM for AD (companion: PIM4ActiveDirectoryPS)

PIM for Entra ID is well-supported by Microsoft; PIM for **on-prem Active
Directory** is not. The companion closes the gap by using Entra PIM as the
**session initiator** and propagating the activation into AD with a time-to-live.

```
Active Directory                                Entra ID
Admin-<Init>-AD       <-- no sync, either way -->     Admin-<Init>-ID
                       (admin OUs excluded from Entra Connect; no writeback ID → AD)

PIM-AD-...-S_AD       <-- groups created identically-named on both sides -->  PIM-AD-...-S_AD
  (local AD group)                                          (Entra ID group)
                                                            ▲ Read groups (*-S_AD), PIM sessions (WHO, TTL)
                                                     ┌──────┴───────┐
                                                     │  PIM for AD  │  continuously loops
                                                     └──────┬───────┘
                            Modify AD group membership      │
                               (Add/Remove with TTL)        ▼
                                       Add-ADGroupMember -MemberTimeToLive ...
```

1. **Separate accounts.** Each person has `Admin-<Init>-AD` and `Admin-<Init>-ID`.
   Same human, two identities — no shared password, no synced object.
2. **No directory sync.** Admin OUs are excluded from Entra Connect; no writeback
   from Entra ID to AD.
3. **Identically-named groups on both sides** (the `-S_AD` suffix marks both).
4. **Continuously-looping PowerShell** on a domain-joined host with AD admin creds:
   reads all `PIM-AD-*-S_AD` groups in Entra, reads currently **active** PIM
   sessions (member + remaining TTL), identifies the AD account from the naming
   convention, and `Add-ADGroupMember -MemberTimeToLive <span>` so AD enforces
   expiry.
5. **Auto-correction loop.** If TTL drift exceeds **±2 minutes** the script
   re-aligns by removing and re-adding with the corrected TTL. If the user
   deactivates their Entra session, the next loop removes the AD membership.

**Forest requirements**: the **Privileged Access Management** optional feature
(Windows Server 2016 forest functional level; supported DC OS 2016/2019/2022).
Verify with `Get-ADOptionalFeature -filter "name -eq 'privileged access management
feature'"`; enable once per forest (irreversible) with `Enable-ADOptionalFeature
'Privileged Access Management Feature' -Scope ForestOrConfigurationSet -Target
<domain>`.

**Why a separate project**: different runtime profile (a long-running service on a
DC / domain-joined host with cached AD creds, vs the stateless cloud engine);
different customer scope (many PIM4EntraPS customers are cloud-only / retiring AD);
different failure modes (PIM-for-AD failure can leave a person without TTL'd
membership at 3am — closer to a service than a batch job). Repository:
<https://github.com/KnudsenMorten/PIM4ActiveDirectoryPS>.

---

## 22. Activation use-cases

The full catalog of 100 just-in-time, approval-gated, audited scenarios lives in
this section's source spirit; the pattern for every entry: a persona needs a
**sensitive action** in a workload, so they **activate** an eligible PIM group
(time-boxed, optionally approval-required, fully audited) that grants the workload
role; access expires automatically afterward. The group → workload-role binding is
what the workload connectors maintain (§15); native Entra PIM governs the
activation + approval at use time. Domains spanned: Finance/ERP (Business Central,
D365 Finance), HR/People (D365 HR, Workday, SuccessFactors), Security operations
(Defender XDR, Sentinel, MDCA), Endpoint management (Intune), Identity (Entra
directory roles), Azure infrastructure (Azure RBAC), Data & BI (Power BI / Fabric),
Collaboration (Exchange, SharePoint, Teams, Purview), DevOps & engineering (Azure
DevOps, GitHub), and third-party SaaS (Salesforce, ServiceNow, AWS, Snowflake,
Databricks, etc., via SCIM/app-role group activation).

Representative examples:
- **Finance**: edit the chart of accounts → activate BC `G/L Setup Manager`; modify
  vendor bank details → activate BC `AP Manager` (approval); open a closed period →
  BC `Period Control` (approval).
- **Security ops**: isolate a device → Defender `Security Operations Operator`;
  change Defender settings → `Auth & Settings Admin` (approval).
- **Identity**: reset MFA for a VIP → `Authentication Administrator` (approval);
  break-glass tenant action → `Global Administrator` (approval + short TTL).
- **Azure**: deploy to prod → `Contributor` @ sub (approval); Owner at tenant root
  for a fix → `Owner` @ root MG (approval + short TTL).
- **Third-party**: ServiceNow business rule → `SNOW Admin` (approval); AWS prod
  role → `AWS Admin` permission set (approval).

Common thread: each is **eligible** (not standing), activated **just-in-time** with
**approval** on the high-impact ones, bounded by a **short TTL**, and **audited**
end to end.

---

## 23. What PIM4EntraPS is not

- **Not a replacement for Conditional Access.** PIM activation is gated by CA at the
  tenant level; PIM4EntraPS doesn't configure CA (EntraPolicySuite does).
- **Not a replacement for Privileged Access Workstations.** The model assumes
  admins use PAWs; PIM4EntraPS doesn't deploy them.
- **Not a SIEM / detection tool.** It builds and maintains the *intended* PIM
  model. Detecting misuse is downstream (Sentinel, Defender for Identity).
- **Not a self-service portal at the core.** The Activator is for admins who
  already have eligible assignments; the engine doesn't grant new eligibility on
  user request — that's an approvals workflow (Entra ID Governance access packages,
  or the §17.15/§17.18 intake layer on top).

### Common pitfalls the model addresses

Over-privilege (tenant-wide perms when AU/RBAC scoping would do; PIM v1 bundles vs
v2 atomic activation); missing service-level RBACs (defaulting to Entra roles
instead of the service's native RBAC); usage-documentation gaps (the Manager shows
the chain); role-group misuse (sharing role groups between internals and
consultants — use `PIM-PROJECT-*`; no T0/T1 separation — the tier model makes it
visible); scaling (ignoring legacy AD — PIM4ActiveDirectoryPS; not designing for
1:N / multi-cloud — tenant + subscription id per row; island directories — the
open `<Service>` slot); lifecycle (no offboarding review — Exporter + diff;
license-loss breaking mail automation — `LicenseSku` drift report; incomplete
per-service rollout — every service is a peer in the taxonomy; synced-vs-cloud
group confusion — the `-S_AD` suffix).

---

## 24. Trade-offs / known gaps

| Trade-off | Why we accepted it |
|---|---|
| Per-group Graph calls for PIM-for-Groups (no tenant-wide list endpoint) | Graph requires `$filter=groupId eq …` per call. Cached via the Exporter → CSV pattern; `$batch` to 20-up is the throttle ceiling. |
| Azure RBAC eligible state isn't in Azure Resource Graph | ARG only exposes permanent + active. Eligible must come from ARM REST per-scope. Same cache pattern. |
| Engine doesn't gate every destructive op on `-WhatIfMode` (some legacy paths) | Incrementally hardened; new code added under the WhatIf guard from day one. |
| 14+ CSVs feels like a lot | Each is small (10–500 rows) and one clean concept; merging two would couple their schemas. |
| No web UI for editing CSVs (historically) | The Manager grid + Review & Save closes this. |
| Holiday-aware workday calculation | Out of scope (Mon–Fri only). |
| Serial-approval escalation latency | Bounded by engine run frequency (schedule hourly on Serial tenants). |

---

## 25. Testing strategy

PIM4EntraPS ships rerunnable offline test suites (validator semantics,
PIM-DUP/TAP/SCHED rules, scheduler due-calc, REST-no-modules checks) and a live
delegation lab (provision → assert delegation/REST → cleanup). The engine, the MSP
courier (producer sign → private-endpoint blob → consumer pull/verify/tamper-
reject), offline Pro licensing, per-tenant cert auth, and the cloud-native
container were live-validated on real cross-tenant infrastructure. **All test
procedures, the suite inventory, how to run them, and current pass counts live in
`TESTS.md`** — refer there for anything operational. Mark a feature "done" only
after a real live test (engine run / API check), never a parse-check (see
`REQUIREMENTS.md` for status).

---

## 26. Where to read next

- **`REQUIREMENTS.md`** — the single backlog (every want/idea/constraint + status).
- **`TESTS.md`** — test procedures and suite inventory.
- **`../README.md`** — landing / quick start. **`../RELEASENOTES.md`** — per-release
  changes.
- **`../tools/pim-manager/`** — graph viewer. **`../tools/pim-activator/README.md`**
  — Edge extension + Intune rollout.
- Companion projects:
  [PIM4ActiveDirectoryPS](https://github.com/KnudsenMorten/PIM4ActiveDirectoryPS) ·
  [EntraPolicySuite](https://github.com/KnudsenMorten/EntraPolicySuite) ·
  [PIM-Role-Advisor](https://github.com/KnudsenMorten/PIM-Role-Advisor).
- Microsoft Learn: [Enterprise Access
  Model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
  · [PIM for
  Groups](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/concept-pim-for-groups)
  · [CA + PIM
  integration](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings)
  · [RAMP](https://learn.microsoft.com/en-us/security/privileged-access-workstations/security-rapid-modernization-plan).
