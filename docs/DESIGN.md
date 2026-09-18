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
11. [Hosting & runtime (single-tenant, two-plane topology, execution model, install guide, update lifecycle, deployment scenarios S1–S6)](#11-hosting--runtime)
12. [Containers](#12-containers)
13. [MSP architecture (two planes, signed courier, profiles, ring model)](#13-msp-architecture)
14. [SQL / data model](#14-sql--data-model)
15. [Workload connectors](#15-workload-connectors)
16. [Entra group / app catalog](#16-entra-group--app-catalog)
17. [Lifecycle & governance](#17-lifecycle--governance)
18. [Manager / GUI + UX](#18-manager--gui--ux)
19. [Editions](#19-editions)
20. [Launcher flavors](#20-launcher-flavors)
21. [Companion tools & projects](#21-companion-tools--projects); [PIM for AD](#211-pim-for-ad-companion-pim4activedirectoryps)
22. [Activation use-cases](#22-activation-use-cases)
23. [What PIM4EntraPS is not](#23-what-pim4entraps-is-not)
24. [Trade-offs / known gaps](#24-trade-offs--known-gaps)
25. [Testing strategy](#25-testing-strategy)
26. [Where to read next](#26-where-to-read-next)
27. [Identity, credentials and self-healing](#27-identity-credentials-and-self-healing)

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

> **A membership in a role-assignable group can only be *Eligible*. Entra
> refuses an *Active* PIM membership of a group (or an admin) in a
> role-assignable group.**

```
SUPPORTED:
Named Admin  --Eligible/Active-->  Entra ID Group         --Eligible (PIM)-->  Role-Assignable Group  --Eligible/Active (PIM)-->  Entra ID Role

NOT SUPPORTED:
Named Admin  --Active------------>  Role-Assignable Group  --Eligible/Active-->  Entra ID Role
Entra ID Group --Active---------->  Role-Assignable Group  (refused by Entra; the delegation never reaches the tenant)
```

Implications:

- The Tier-2 → Tier-3 hop is always **Eligible** when the permission group is
  role-assignable. The admin activates the role group, which makes them an
  eligible member of the permission group, which is in turn eligibly assigned to
  the Entra role.
- **Enforced in the product, not left to the data.** Every wizard (role, project and
  permission-group) writes a group-into-group nesting whose target is role-assignable
  as `Eligible`, whatever else is selected, and a nesting chosen as Eligible is written
  Eligible to every row it produces. The validator reports an existing `Active`
  nesting into a role-assignable group as an **error** with a one-click
  **Set to Eligible** fix (staged to the Pending changes queue, §18.1f), and the
  engine lists such a row under Engine logs & errors (§11.3a) instead of skipping it
  silently.
- For permission groups targeting **non-Entra** resources (Azure RBAC, Power BI,
  Intune, Defender, AzDevOps), the role-assignable flag isn't required and
  Active-on-the-permission-group nesting is fine.
- The flag can't be added later — recreate the group. The engine sets it at
  create time from the definition row. Creating a role-assignable group needs
  `RoleManagement.ReadWrite.Directory` on the engine identity; `Group.ReadWrite.All`
  alone is refused.

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

#### Supported substitution tokens + the GUI legend

The name patterns are `{Token}` templates expanded by `Expand-PimNamePattern`
(`engine/_shared/PIM-Naming.ps1`) — case-insensitive, unknown tokens left
unchanged. The full supported set the resolvers honour:

| Token | Used by | Meaning |
|---|---|---|
| `{Initial}` *(preferred)* | admin account | owner's initials / short owner identifier |
| `{Owner}` *(synonym)* | admin account | backward-compat alias for `{Initial}` (still honoured) |
| `{AdminTypePrefix}` | admin account | prefix by admin-type (internal = none, external-adminuser = `x-`) |
| `{Platform}` ≡ `{EnvironmentSuffix}` | admin account | environment suffix (Entra = `-ID`, AD = `-AD`) |
| `{Role}` / `{Department}` / `{AdminUnit}` | group | role/service, owning department, AU subset |
| `{Workload}` / `{Scope}` / `{Permission}` / `{Level}` / `{Tier}` / `{Plane}` | resource group | Azure workload, scope, permission/role, level, tier, plane code |

`Resolve-PimAdminName` wires `{Owner}` and `{Platform}` as synonyms in code
(both map to the same value as `{Initial}` / `{EnvironmentSuffix}`), so legacy
customer patterns keep working.

The Manager **shows** this set so operators never guess: the
Settings → Naming card renders a collapsible legend from an authoritative JS
catalog (`PIM_NAMING_TOKENS` in `pim-manager.html`) — each token with a one-line
meaning + example and a **click-to-insert** chip that drops the token at the caret
of the focused naming **Value** field. The catalog is a 1:1 mirror of the resolver;
`tests/Test-PimNamingTokenLegend.ps1` fails the build if the two ever drift. The
Settings → Mail templates editor shows a **per-template** legend derived from the
shipped body's `{{…}}` placeholders (see §10). Both legends are plain static HTML
(readable with JS off); the click-to-insert is a JS-only progressive enhancement
and adds no endpoint.

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

> **Where desired state lives today.** The REST + SQL engine and the Manager read and write
> desired state **only in SQL** (`pim.Rows`, `pim.Settings`; §14). Neither falls back to a file,
> and the Manager refuses to start without its database. The CSV shapes and the
> `.locked` / `.custom` / `.custom.sample` pattern below describe the *file* form of the same
> model: the shipped samples and templates, the module-based reference engines (§5.1), and the
> input of the one-time import that brings a file-based installation into SQL
> (`setup/Migrate-PimToSql.ps1`, §5.3). The declarative-desired-state / imperative-engine split
> is identical in both.

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
- **Account-disable circuit breaker** (`PIM-DisableGuard.ps1`). A provider whose remove path
  *disables Entra accounts* (`accountEnabled=$false`) is the highest-blast-radius operation in
  the engine: the `Admins` provider's LIVE set is the **whole tenant user population**, so a
  wrong or unresolved desired set would turn every scanned user into a "remove" → a mass
  account disable. Such a provider is flagged `isAccountDisable`, and the orchestrator routes
  its removals through three independent guards *before any disable runs*:
  1. **Positively-resolved desired set required** — if the desired set is empty, null, or its
     read could not be confirmed (the SQL read errored), the disable pass **aborts** (a disable
     requires a desired set we are *sure* about, not merely "0 rows came back").
  2. **Mass-disable cap** — if a run would disable more than a small absolute count
     (`PIM_DisableMaxCount`, default 5) **or** more than a small percentage of the scanned
     population (`PIM_DisableMaxPercent`, default 10%), the **whole** disable pass aborts and
     **nothing** is disabled (never a partial mass-disable). It logs loudly + raises an alert.
  3. **Off by default** — the account-disable capability is disabled unless the persisted
     opt-in `PIM_AccountDisableEnabled` is explicitly set; with it off, zero accounts are ever
     disabled. (Defence-in-depth: the `Admins` provider's `ApplyRemove` re-checks this opt-in,
     so even a direct call cannot disable when the feature is off.)
- **Delta** — create/update everything that differs (no prune).
- **Delta + `-FromQueue` / `-Changes`** — apply **only** the pending commit-queue
  `(entity,key)` pairs. A Manager commit enqueues changes; the engine applies just
  those. *(This is "the engine also runs delta when a new change is added to
  SQL.")*

**Drift: live vs desired — a scheduled snapshot + gated remediation (`PIM-DriftSnapshot.ps1`,
`PIM-Governance.ps1`).** A general "is the live estate still what we intended?" view layered **on
top of the engine delta — it does NOT reimplement reconciliation.**

- **The check runs in the scheduler, never in the Manager.** Scheduler job `drift-snapshot`
  (default every **240 min**, editable on the Job schedule page) runs the engine in plan/WhatIf
  mode over every scope (`-Scope All -Mode Full -Prune -WhatIf` — **no writes**). Each scope's
  diff (`Compare-PimDesiredVsLive`) is normalised by the pure `Get-PimDriftReport` into one flat,
  classified list — `create → missing`, `update → changed`, `remove → extra` (an `extra` only
  appears because the plan was computed with prune ON). `Add-PimDriftPayloadNames` resolves each
  item's principal and group to display names (a principal the directory no longer knows becomes
  `unresolved principal <id>`), and the result is stored as ONE document in SQL
  `pim.TenantCache` kind `drift`, with per-scope desired / live / in-sync counts.
- **The page reads the stored document.** `GET /api/drift` serves the latest snapshot instantly
  (with its timestamp, cadence and a stale flag when older than two cadences); `?refresh=1`
  (Admin+, the page's **Check now**) queues a `drift-snapshot` trigger (`Add-PimJobTrigger`,
  deduplicated by type + scope) and asks for an immediate tick start (§11.3). The page
  (**Reviews & controls › Drift: live vs desired**) renders one expandable row per scope.
- **"Apply now" is the gated remediation.** `Get-PimDriftRemediationPlan` (pure) narrows the
  report to ONLY the selected drift and returns the `(entity,key)` change list, which is applied
  through the engine's change-restricted path via `-Changes` — `-Mode Delta` for the selected
  missing/changed, and **`-Mode Full -Prune` only when a selected `extra` was explicitly opted
  in** (`-AllowRemove`; an explicitly-selected extra without the opt-in is *refused*, never
  silently dropped or removed). Remediation therefore inherits all the destructive-safety guards
  above (empty-desired prune refusal, the account-disable circuit breaker, the approval gate), and
  a single click can never destructively remove a live delegation. Wired as
  `POST /api/drift/remediate` (Admin-gated, audited as `governance.drift.remediate`); detected
  drift also raises the `drift` Manager alert.

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
- **Local SQL** — `PIM_SqlServer` names a local/hybrid SQL instance, reached with
  **Integrated** auth. There is **no default** — with no store configured the engine REFUSES rather
  than connecting to whatever database happens to exist. This is the **development / management-
  server inner-loop** path: the running identity is itself a DB user, so there is **no
  cross-tenant token problem and no "MI is not a DB user" blocker** — the engine reads its
  desired set directly. Both the server and the database *name* (`PIM_SqlDatabase`) must be set
  explicitly. **It is a
  dev convenience, NOT a production or break-glass store** — Azure SQL is the single
  authoritative store in ALL modes, and **break-glass = a client PC connecting DIRECT to the
  same Azure SQL** (never a local copy).

### 5.3 One-time import, scoped on-demand recalc & resilient health (`PIM-Cutover.ps1`)

**SQL-only; the file store and its cutover ceremony are gone.** The Manager and engine have no
file store to migrate from at run time, so the former in-Manager cutover ceremony (`/api/cutover`,
`/api/cutover/abort`) was removed together with the file store. Moving a file-based (v1-shaped)
installation onto SQL is a **one-time import run during migration**: `setup/Migrate-PimToSql.ps1`.

- It reads each `<base>.custom.csv` **read-only** (never written back), maps it to `pim.Rows`
  under the entity's natural key, and writes each file's rows over **one connection inside one
  transaction** — a file that fails is rolled back whole, named in the result, and makes the
  import end as a failure (never "Migration complete" over a partly refused import).
- It seeds `pim.Settings` from the naming-convention configuration, and carries over the runtime
  state the file-based edition kept beside it (alerts, scheduler state, template state, audit
  history, workload exemptions, `<type>.mailtemplate.custom.html` overrides). An existing store
  value for exemptions is never overwritten.
- `-WhatIf` reports what would migrate; `-ListOnly` reports which files would be imported or
  ignored without touching SQL. Re-running is safe (full-set replace per entity).

**On-demand recalc on SQL change — scoped to the entities that changed.** A cheap
change-detector (`Invoke-PimSqlChangeDetector`, wired into `Invoke-PimSchedulerTick`) reads a SQL
**data signature** — `COUNT(*)` + `MAX(UpdatedUtc)` over `pim.Rows` (`Get-PimSqlDataSignature`) —
and compares it to the last acted-on signature (`pim.Settings` `RecalcSignature`). On a change it
also reads a **per-entity signature map** and compares it with the stored one
(`RecalcEntitySignatures`, `Get-PimChangedEntities`), then resolves the changed entities to the
engine scopes that consume them (`Resolve-PimEngineScopesForEntities` over the explicit
`Get-PimEntityScopeMap`, resolved in provider order):

| Changed entity | Engine scopes triggered |
|---|---|
| `Account-Definitions-Admins` (+ `-Central`) | `Admins`, `AdminTap`, `AdminMembers` |
| `PIM-Assignments-Admins` | `AdminMembers` |
| `PIM-Assignments-Groups` | `GroupMembers` |
| `PIM-Assignments-Roles-Groups` | `EntraRoles`, `EntraRolePolicies` |
| `PIM-Assignments-Roles-AUs` | `RolesAUs`, `EntraRolePolicies` |
| `PIM-Assignments-Azure-Resources`, `PIM-Definitions-Resources` | `AzResPolicies`, `AzRes` |
| `PIM-Definitions-AU` | `AdministrativeUnits`, `AdministrativeUnitMembers`, `RolesAUs` |
| any other `PIM-Definitions-*` (group definitions) | `Groups`, `AdministrativeUnitMembers`, `GroupOwners`, `GroupsPolicies` |
| an entity the map does not name | `All` |

The result is one `engine-delta` trigger whose scope is the comma-separated list (e.g.
`AdminMembers,AzResPolicies,AzRes,GroupMembers`), drained by the scheduler (§11.3). The map is
**conservative by construction**: an unmapped entity widens the trigger to `All`, so a gap costs a
slower run, never a missed apply. The first change after an update has no stored entity map yet and
runs `All` once. Daily / destructive / plan-only scopes (offboarding, group retirement, access
reviews, hybrid AD) are deliberately not reached from here — they run on their own jobs.

This catches **out-of-band** writes too — another MSP node, a direct SQL edit, the one-time import
— that never passed through the Manager. It is fail-open (a read error yields a unique signature so
a recalc is never silently skipped) and idempotent (no change → no trigger). Signatures are
persisted *before* the trigger fires, so a crash mid-trigger can't loop forever — a redundant recalc
is safe (the engine is idempotent), a missed one is not; if the entity map cannot be advanced, the
next change arms `All`.

**Persistent SQL compute + resilient `/health`.** The hosted SQL compute MUST run persistent
(serverless **auto-pause disabled** / provisioned) so neither the health probe nor the first
post-idle request cold-starts; `Test-PimSqlPersistentCompute` is the validator (a serverless
SKU — name carries `serverless` or the `_S_` family marker — with an auto-pause delay ≥ 0 is
**flagged**; `-1` or a provisioned tier is **persistent**). The Manager `/health` endpoint is
**unauthenticated** (App Service / Container App probe) and **resilient to a transient SQL
blip** via `Get-PimHealthState`: a sub-threshold consecutive failure stays **HTTP 200**
("degraded") so the platform doesn't flap the Manager over one hiccup; only a **sustained**
outage (≥ 3 consecutive failures) returns **503** ("unhealthy").

### 5.4 Safe, reversible Review & Save commits (`PIM-CommitBackup.ps1`)

![Pending changes — the one queue of configuration edits and queued directory actions](img/manager-pending-changes.png)
*Pending changes: the keyed diff and the commit gate this section describes, beside the queued directory actions (§18.1f). (Synthetic demo data.)*

The Review & Save commit (`PUT /api/csv/<base>`) is **backup-first, all-or-nothing, and
reversible**. The logic lives in a pure, injectable core
(`engine/_shared/PIM-CommitBackup.ps1`) so it is unit-testable offline without a live store:

- **Snapshot before apply.** `New-PimCommitSnapshot` captures the entity's CURRENT rows + header
  (the same pre-commit rows the diff already read) into an immutable record keyed by a
  timestamp-sortable id (`New-PimBackupId`: `yyyyMMddTHHmmssfffZ-<entity>-<rand>`). The snapshot
  is persisted **before** any write, so a crash still leaves a restorable point.
- **All-or-nothing apply.** `Invoke-PimCommitTransaction` is the seam: persist snapshot →
  `ApplyScript` → on ANY failure run `RestoreScript` (restore the snapshot) and rethrow a clear
  error → on success `PruneScript`. A failed backup write REFUSES the commit (apply never runs).
  The actual SQL write is `Set-PimSqlEntityRowsTransactional` — the identical full-set-replace
  semantics as `Set-PimSqlEntityRows` but every upsert + delete runs inside **one `SqlTransaction`
  on one connection**, so a mid-loop failure rolls the whole batch back and `pim.Rows` is left
  exactly as before (the half-apply defect). There is no file mode: the Manager is SQL-only.
- **Undo / rollback.** `Get-PimSnapshotRestorePlan` turns a stored snapshot into a full-set replace
  that perfectly reproduces the pre-commit state — including rows the bad commit had deleted. The
  operator triggers it from the Review & Save **Backups / Undo** view (`GET /api/backups/<base>`
  lists snapshots newest-first; `POST /api/backups/restore {base,id}` replays one, Admin-gated).
- **Retention.** `Get-PimBackupRetentionPlan` (pure) keeps the newest N per entity (default 10) and
  prunes the oldest; applied after each commit. Snapshots live in `pim.Backups`.

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

**Write paths follow the same tenet (REST migration).** The setup/deploy *write*
scripts are being moved off the Graph/Az SDK onto the same `PIM-Rest` data plane.
The **PIM Activator backend deploy** (`tools/pim-activator/Deploy-PimActivatorBackend.ps1`,
which provisions the extension's Entra app registration + service principal +
tenant-wide OAuth2 admin-consent grants) now routes every Graph write through a
single seam, `Invoke-PaGraph` (in `tools/pim-activator/_PimActivatorBackend.ps1`):
by default it calls the module-free `Invoke-PimGraph`, and only falls back to the
SDK's `Invoke-MgGraphRequest` when `$global:PIM_UseGraphSdk` is set (the same opt-in
toggle the engine/ContextBuilder honour). The REST request *shapes* are built by
small pure functions (`Resolve-PaGraphScopeIds`, `New-PaRequiredResourceAccess`,
`New-PaAppRegistrationBody`, `New-PaConsentScopeString`, `Set-PaOauth2Grant`,
`Get-PaProp`) that are unit-tested offline with no network and no modules. The
result: an **app-only (certificate) backend deploy is fully module-free** — PIM-Rest
mints the cert-signed app-only token (no Graph SDK, no MSAL, PS 5.1-safe). The
interactive *break-glass* human sign-in keeps the existing Edge-loopback + PKCE
flow (delegated session via `Connect-MgGraph -AccessToken`), and no device-code
flow is introduced anywhere (the package validator's NODEVCODE check still holds).
The same conversion is pending for the remaining setup/EXO/Intune write scripts
(tracked in the backlog).

**Exchange Online over REST.** The one Exchange need — setting a new admin
account's mailbox forwarding — also goes through `PIM-Rest.ps1` (the `exo`
audience) rather than the Exchange Online PowerShell module. It calls the
Exchange admin REST endpoint (`/adminapi/beta/<org>/InvokeCommand`, the same
endpoint the module's REST-backed cmdlets use) app-only with the engine SPN's
certificate, so there is no `Connect-ExchangeOnline` session and no module to
install. The setup/installer family is equally module-free: the engine
app-registration installer and the admin-consent grant are REST + certificate
(no Microsoft.Graph SDK, **no device-code** — which managed Conditional Access
blocks), and the MSP fan-out authenticates per-tenant and reads the tenant's
default domain over REST.

**Admin-account writes over REST.** Creating and updating cloud admin accounts —
the part the MSP fan-out and the local apply actually drive — runs on the same
pure-REST data plane. A dedicated account writer creates/updates the directory
user (enable, names, mail nickname, job title, usage location, company), sets the
password policy with a short replication-lag retry, links the manager, and
applies mail forwarding through the Exchange REST path above — all app-only with
the engine certificate, no Graph/Exchange modules. It is idempotent (look up by
user principal name → create if absent, otherwise update). The fan-out and local
apply launchers use this writer by default and fall back to the legacy
module-based engine only when explicitly opted in. The signed-baseline courier
likewise uploads its bundle over the storage REST API (no storage module), and
the CSV→SQL migration is a SQL-data-plane operation with no directory SDK at all.
The on-prem Active Directory account branch (hybrid, explicit credential) stays
on its native module by design; remaining account lifecycle bits (temporary
access pass issue, status changes) are tracked for the same migration.

---

## 6. Providers (per-scope appliers)

Each scope is a provider implementing read-DESIRED / read-LIVE / key+compare /
apply. They run in a fixed dependency **order**:

| Order | Provider | Entity | Creates / binds |
|---|---|---|---|
| 10 | AdministrativeUnits | `PIM-Definitions-AU` | AUs (scope containers only) |
| 20 | Groups | `PIM-Definitions-*` (group definitions) | the PIM groups (role-assignable where the definition says so) |
| 22 | AdministrativeUnitMembers | `PIM-Definitions-*` | a group's membership of the AU its type/definition names |
| 25 | GroupOwners | `PIM-Definitions-*` | missing owners on existing groups (replication-safe) |
| 30 | Admins | `Account-Definitions-Admins` | admin accounts (created when due; disabled/revoked kept disabled; §17.10) |
| 35 | AdminTap | `Account-Definitions-Admins` (CreateTAP) | Temporary Access Pass |
| 40 | EntraRoles | `PIM-Assignments-Roles-Groups` | directory role → **group** (tenant scope) |
| 45 | RolesAUs | `PIM-Assignments-Roles-AUs` | directory role → **group**, scoped to an AU |
| 48 | EntraRolesDirect | `PIM-Assignments-Roles-Direct` | directory role → **user** (PIM v1 direct; see §6.1) |
| 50 | AdminMembers | `PIM-Assignments-Admins` | admin → **eligible/active member of a group** |
| 55 | GroupMembers | `PIM-Assignments-Groups` | group → member of a group (nesting; always Eligible into a role-assignable group, §3.1) |
| 58 | AzResPolicies | `PIM-Assignments-Azure-Resources` | Azure resource role PIM policy at each managed scope, from the policy template (§17.7) |
| 60 | AzRes | `PIM-Assignments-Azure-Resources` | Azure RBAC role → **group**, at an Azure scope |
| 62 | DefenderXdrRoles | `PIM-Assignments-Defender` | Defender XDR (Unified RBAC) role → **group** (see §6.4) |
| 64 | IntuneRoles | `PIM-Assignments-Intune` | Intune RBAC role (+ scope tags) → **group** (see §6.4) |
| 66 | EntraAppRole | `PIM-Assignments-AppRole` | **any** enterprise-app app role → **group**, via `appRoleAssignedTo` (generic; see §6.4) |
| 67 | WorkloadConnectors | `PIM-Assignments-Workloads` | the remaining workload roles through the connector framework (§15) |
| 70 | GroupsPolicies | definition `PolicyTemplate` | per-group PIM for Groups **member and owner** policy (approval, MFA/justification, durations, notifications) |
| 75 | EntraRolePolicies | `PIM-Assignments-Roles-{Groups,AUs}` | directory-role PIM policy from the policy template |
| 80 | AccessReviews | definition `ReviewCycle` | per-group access-review schedule (reviewers = owners) |
| 90 | AdminOffboarding | `Account-Definitions-Admins` | auto-disable on its own schedule: disable, revoke sessions, remove delegations, notify — and stop. The account is never deleted (see §6.2, §17.10) |
| 92 | GroupRetirement | `PIM-Definitions-*` | retires a group whose definition is marked for retirement |
| 95 | HybridAdProvisioning | `Account-Definitions-Admins` (AD platform) | **PLANS** on-prem AD accounts + gMSA/sMSA; on-prem write is hybrid-worker-only (see §6.5) |


#### `AdminTap` (order 35) — the issuance contract
The scope hands a new admin a time-boxed Temporary Access Pass so they can sign in once and
register their own MFA. Every cloud admin receives one (on-premises AD admins cannot hold a pass);
the pass honours the row's start date and the tenant's own TAP policy (`PIM-TapPolicy.ps1`, e.g.
one-time use), and is mailed to the account owner's address (`Get-PimAdminMailRecipient`, §10).
Four properties define it, and each exists because its absence was a real defect:
1. **The live set is the USABLE passes, not the existing ones.** `GetLive` filters on Entra's own
   `isUsable`, so an **expired** pass leaves the account out of the live set and it becomes a
   create candidate. Counting "has a pass" instead classified a dead pass as satisfied — the
   admin had no route back in and the scope reported success. The read passes **`-All`**, because
   without it `Invoke-PimRest` returns the response WRAPPER and `@(wrapper).Count` is 1 even for
   an account with no pass at all.
2. **An UNREADABLE probe counts as SATISFIED** — deliberately the opposite of every other probe
   here. Elsewhere "cannot tell" means re-run; here it would mint a fresh credential on every
   tick for as long as a Graph read kept failing. Failing closed costs a delayed re-issue;
   failing open mails credentials in a loop.
3. **Refuse before minting, and refuse before DELETING.** `Test-PimTapMailReady` — the same guard
   the Manager's re-issue button uses, so the two paths cannot disagree — runs first. Reversed,
   a tenant that cannot send mail would destroy the existing pass and then decline to replace it,
   which is strictly worse than doing nothing. Delete-then-create is not a choice: Entra allows
   exactly **one** pass per user, so without the delete the POST fails on precisely the accounts
   the scope exists to rescue.
4. **The send RESULT is inspected.** `Send-PimNotifyMail` never throws for a *refused* send — it
   returns `sent=$false`. Discarding that (the original `| Out-Null`) meant a mint whose mail
   failed still reported `applied=1 / ok=True`, over a live credential nobody received, with the
   old pass already gone. The guard answers *may we issue?*; this answers *did it arrive?* It
   cannot be undone at that point, so a not-sent mint warns loudly and names the account.

📌 `Equal` is hardcoded `$true` **on purpose**: once a pass is usable there is nothing to compare,
and the entire replace decision lives in `GetLive`. Proven live 2026-08-21 — a healed account
reads back as `nochange` on the next plan, so the scope does not re-mint.
A dedicated `GroupOwners` scope (replication-safe, re-runnable) repairs missing
owners on existing groups; `Groups` itself is existence-nochange (see §8).

### 6.1 PIM v1 direct role assignment (`EntraRolesDirect`)

v2 is **group-centric** — the principal of a PIM assignment is always a PIM group,
and an admin gets a role by being a member of the group that holds it. Some tenants
still need a directory role assigned **directly to a user** (a "v1 direct"
assignment) — typically break-glass accounts that must not depend on the group
fabric. The `EntraRolesDirect` provider supports this: desired rows
(`PIM-Assignments-Roles-Direct`: `UserPrincipalName` + `RoleDefinitionName` +
`AssignmentType` Eligible/Active + `Permanent`/`NumOfDaysWhenExpire`) become Graph
PIM directory-role schedule requests with the **user's** object id as principal,
tenant scope (`/`). It reuses the same `New-PimRoleScheduleBody` /
`Invoke-PimScheduleCreate` plumbing as the group path. The provider runs **after**
the group-centric role scopes (order 48) and prints a one-line **deprecation
nudge** each run it finds direct rows, steering the data owner toward the group
model. Existence-based (idempotent); `Action=Remove` rows and user-less rows are
dropped from desired.

### 6.2 Auto-disable — per admin, on its own schedule (`AdminOffboarding`)

> 🔴 **PIM never deletes a user account, and never disables one for being absent.** Two things this
> sweep used to do, it no longer does anywhere in the product:
> * **It does not delete.** There is no code path that deletes a user — not in a single tenant, not
>   on an MSP master, not on a managed tenant, and not behind a setting. An offboarded admin ends as
>   a **disabled account that stays in the directory**, with no sessions, no memberships and no
>   eligibilities, until a person deletes it by hand. The retention field (`DeleteAfterDays`) is
>   **removed and not supported** — no column, no parameter, no setting, no validator finding and no
>   disabled switch; a row that still carries the value is accepted in silence and the schema preflight
>   drops the column (dropping, rather than blanking, is what keeps re-adding it later a one-line change
>   with no data to reconcile). `tests/Test-PimNoAccountDelete.ps1` fails the suite if a user-object
>   delete — or the retention field — reappears.
> * **It does not disable an account merely for being missing from the desired set.** That was a
>   third disable flow (the "unmanaged admin" removal in the `Admins` provider); it is removed, with
>   its setting. The run still **reports** every live admin account that is not in the definitions —
>   seeing them is useful, acting on them is a decision taken on the row.
>   `tests/Test-PimNoUnmanagedDisable.ps1` keeps the path out.

When an admin is due — `Account-Definitions-Admins` carries an `AutoDisableDate`
(date expression / ISO) that has been reached, or `Lifecycle=Retire`, which means the **same
disable-only path** — the REST engine works
through the **whole sequence for that admin**, in v1's order, not only the delegation
half: disable the account, revoke sign-in sessions, cancel PIM schedules and remove every
PIM-for-Groups membership (eligible + active), mail the `offboarding-notice` to the account
owner's address (§10) — and stop. The account itself is kept.
An admin with `AccountStatus=Revoked` but no auto-disable date gets the membership half
(the `Admins` provider disables it and revokes its sessions). Each step is audited
(`account.offboard.*`).

It is modelled **per admin, not per membership, and needs no `-Prune`**: `GetDesired` is the set
of admin rows the sweep acts on, `GetLive` is one record per such admin describing which steps are
still owed (read from the tenant plus a SQL progress record), `Equal` means nothing is owed, and
the update performs the owed steps. Progress is persisted after each step, so an interrupted run
**resumes** where it stopped instead of repeating finished steps; a membership removal that keeps
failing is retried a bounded number of times and then recorded for manual review.

**The date column, and how an old one migrates.** `AutoDisableDate` replaced `OffboardDate`, because
the old name promised removal and the sweep only disables. One shared resolver decides which column
supplies the value, and every surface — the engine, the Manager and the validator — uses it:
* the new name wins; the **old name is still read**, so no existing row breaks;
* the schema preflight copies `OffboardDate` into `AutoDisableDate` and then drops the old column,
  idempotently — one pass migrates a whole store;
* a row carrying **both names with different dates** is **refused, not guessed**: that admin is
  skipped entirely, the run says so naming both dates, and the Manager shows an error. Silently
  picking one is how an account gets disabled on a date nobody chose. Both names set to the *same*
  date is not a conflict — there is nothing to guess.
* the MSP baseline carries `AutoDisableDate` only, never both, so a managed tenant can never be the
  one that has to guess.

**Access → Admin accounts also shows the SPONSOR DEPARTMENT** (§62: the sponsor is a department, not a
person). Its own column, with the department's owners on hover — the same `PIM-Definitions-Departments.Owners`
the engine resolves, read once per list. Three states, deliberately distinct because the two gaps are
fixed in different places: **no department** (red, fix the admin's row), **a department with no owners**
(red, fix the department under Access → Departments & owners), and **the owner index could not be read**
→ *owners not checked*, never *no owners*. Reporting a gap that was never measured is how a screen gets
ignored.

The auto-disable date is visible and editable on the same screen: its own column showing the date,
whether it has already passed, whether it falls inside the next 14 days, and whether the row still
uses the old column name — and an editable field per admin whose help text states the effect
(disable, never delete). Saving it clears the old column, so an edit cannot create a conflict.

It runs on its own scheduler job (`admin-offboarding`, every 30 min) rather than only inside a
daily prune. Gates, decided for the whole pass before anything is written:
1. automatic offboarding is enabled for the environment (v1's gate);
2. `OffboardCleanupMode` = `Off` (skip) | `Report` (plan only) | `Enforce` (apply; the default);
3. the offboarding progress store is reachable (otherwise fail closed);
4. break-glass accounts are excluded;
5. the removal budget over admins with destructive steps, and the account-disable circuit breaker
   (§5.2) over the disables.

In a protected environment with the opt-in unset the job processes nothing and says so.

### 6.3 Per-scope conformance versioning

Beyond the per-template version stamp (§ workload conformance), the engine tracks
the **desired-vs-applied template version per scope** so the Manager conformance
heatmap can show, for one tenant, exactly which provider areas are at the current
template version and which are **Behind / Ahead / NeverApplied**. The pure matrix
builder `Get-PimScopeConformance` takes the desired versions (per scope) + the
applied versions and returns one annotated row per scope; `Set`/
`Get-PimScopeAppliedVersion` persist the applied version per `<tenant>|<scope>` in
the **same local state file** as the template stamp (under a distinct
`scopeVersions` map — the per-template stamp is left intact). The version stays
**local** (consistent with the ring-rollout model).

### 6.3b Fleet conformance — tenants × templates, behind-by-N, ring-wide rollout

The single-tenant cores above answer *"how far behind is **this** tenant?"*. A
managed-service provider runs **many** tenants against **one** central set of
approved templates and needs the cross-fleet view, so template conformance can be
**seen and driven across the whole fleet from one place** instead of one tenant at a
time. Three pure cores in `PIM-Conformance.ps1` provide this; the Manager wraps them
thinly:

- **`Get-PimFleetConformance`** (pure) takes the approved templates + a list of
  tenant descriptors (`@{ tenantId; ring; appliedVersions = @{ '<templateId>' = <int> } }`)
  and returns a **tenants × templates matrix**. Only **approved** templates form
  columns (a draft is never deployable, so never a column); each cell carries a
  status (`UpToDate` / `Behind` / `NeverApplied` / `Ahead`) and **behind-by-N**
  (`max(0, templateVersion − appliedVersion)`). It rolls up per tenant (current vs
  behind/never/ahead, `MaxBehind`), per template (how many tenants up-to-date /
  behind / never), and a fleet total; tenants sort **worst-behind first** so what
  needs attention is at the top.
- **`Get-PimRingRolloutPlan`** (pure) takes one template + the tenant descriptors and
  groups the tenants into **exclusive ring bands** (ascending ring), each with its
  members' standing for that template and per-band behind/never counts — the planning
  rollup behind a "roll v_N to ring R and below" wave (a deploy to ring R reaches
  every band with ring ≥ R; the GUI sums them).
- **`Get-PimFleetStateForInstance`** (one read) resolves a single instance's standing
  from its **local** `state/template-state.json`: every `<tenant>|<templateId>`
  applied-version stamp, plus an optional root **`fleetRingByTenant`** ring stamp the
  deploy writes (so the matrix knows the ring of an instance it is not the active one
  for). It tolerates a missing/garbage file (empty maps, no throw), so a
  never-deployed tenant is still a valid all-`NeverApplied` row.

The Manager exposes two **read-only** routes (no tenant write): `GET
/api/conformance/fleet` (the matrix — built by reading **every** managed instance's
local state file; the active instance contributes its **live** ring via
`Get-PimTenantRing`, others use their stamped ring, defaulting to 0/production) and
`GET /api/conformance/ring-plan?template=` (the ring bands). The single-tenant
`deploy` handler now also stamps the active tenant's ring into `fleetRingByTenant` so
later fleet reads have it. The **actual** per-tenant deploy is unchanged — it still
goes through the proven, ring-gated `Get-PimRollForwardRows` +
`Apply-PimWorkloadAssignments` path; the fleet view is the bird's-eye planner, never
a second apply path. The Template Rollout tab carries a **This tenant / Fleet (all
tenants)** toggle; the Fleet view renders the matrix + the ring-wide rollout picker.

### 6.3a Exemption register — reviewable waivers with revoke

An exemption is a deliberate, time-boxed waiver that turns one missing template
binding from a **Gap** into **Exempt** until it expires (expiry is mandatory — an
exemption always lapses, then the item is re-checked; see § workload conformance).
Waivers are persisted per Manager instance in the exemptions store (a JSON file
under the instance config root, falling back to the shipped sample). The same pure
helpers that the reconcile uses now also drive a **reviewable register**, so waivers
are no longer write-only:

- **`Get-PimExemptionList`** (pure, clock injected via `NowUtc`) reads the stored
  waivers, optionally scoped by `TenantId`/`TemplateId`, and returns one annotated
  row per waiver: item key, reason, approver, normalised expiry, **days-left**, a
  per-row **state** — `Active`, `Expiring` (still active but inside the warn window,
  default 30 days, configurable via `ExpiringWithinDays`), `Expired`, or `Invalid`
  (a malformed/no-expiry row, surfaced so it can be cleaned up — it never suppressed
  a Gap), and a **stable revoke key** (`tenant|template|item|expiry`, so a re-issued
  waiver with a new expiry is a distinct row). Rows sort **soonest-to-lapse first**,
  with `Invalid` rows last.
- **`Get-PimExemptionSummary`** rolls the list up to `{Total, Active, Expiring,
  Expired, Invalid}` (an `Expiring` row counts in both `Active` and `Expiring`).
- **`Remove-PimExemptionEntry`** removes exactly the row matching a revoke key and
  returns the kept set for the caller to persist. It **never mutates the input**, is
  **idempotent** (an unknown key is a no-op, `Removed=0`), and **refuses an empty
  key** so a blank request can never wipe the store.

The Manager wires these as `GET /api/conformance/exemptions` (the register; the
existing `POST` still grants) and `POST /api/conformance/exemptions/revoke`
(SuperAdmin-gated, audited via `conformance.exemption.revoke`; a revoke that removes
nothing writes nothing). The Template Rollout tab renders the register under the
conformance matrix with per-row state colouring and a **Revoke** button; revoking a
waiver reloads the matrix so the affected item re-shows as a Gap.

### 6.3b Per-entry ring control — promote a template item to a different rollout wave

Each template entry carries a `ring` (default 2, range 0–9; `Get-PimTemplateEntryRing`),
and an entry deploys to a tenant only when `entryRing <= tenantRing`
(`Test-PimRingInScope`). `Set-PimEntryRing` (pure — clones the template, sets the
named entry's `ring`, throws on an unknown key) is the engine primitive; the Manager
exposes it as `POST /api/conformance/promote` (`{ templateId, key, ring }`,
SuperAdmin-gated, writes the updated template file, `400` on an unknown entry). To
make the endpoint observable + drivable from the GUI (the "no dead functionality /
GUI↔engine alignment" rule), the per-tenant conformance matrix endpoint
(`GET /api/conformance`) now also returns a `rings` map (entry key → current ring),
and the **Template Rollout** per-entry grid renders a **Ring** column: a SuperAdmin
gets a `0–9` `<select>` per row (`confPromote` → `POST /api/conformance/promote`,
re-reads the matrix on success and snaps the dropdown back to its prior value on
failure so the GUI never drifts from the saved template); a non-SuperAdmin sees the
ring read-only. This is distinct from the **admin** ring (per-administrator rollout
ring, §17.5) — this one is the **template-entry** rollout wave.

### 6.4 Workload-RBAC providers — Defender XDR & Intune

Two native REST providers delegate a **workload's own RBAC role** to a PIM group,
extending the group-centric model from Entra/Azure into the security and device
workloads. Both follow the same provider contract as `EntraRoles`/`AzRes`
(GetDesired / GetLive / KeyOf / existence-based Equal / ApplyCreate / ApplyRemove),
are **idempotent** (existence-based — the group already holding the role is a
nochange), **REST-only over Microsoft Graph** (cert app-only), and **read-only at
collection** (nothing is written unless a create/remove is applied). `-Mode Full`
reconciles create/update only; removing a live-not-desired assignment needs `-Prune`.

- **`DefenderXdrRoles`** (order 62, entity `PIM-Assignments-Defender`) — assigns a
  Microsoft Defender XDR (Microsoft 365 Defender **Unified RBAC**) role to a PIM
  group via the Graph `roleManagement/defender` surface (beta). Desired rows carry
  `GroupTag` + `RoleDefinitionName` (resolved live to the role-definition id). The
  group is the assignment's principal. **RBAC prerequisite:** Defender Unified RBAC
  must be **activated** in the security portal and the engine app granted the
  Defender role-management scope; until then the role list is empty and a clear
  message is surfaced (no crash).
- **`IntuneRoles`** (order 64, entity `PIM-Assignments-Intune`) — assigns an Intune
  (`deviceManagement`) RBAC role to a PIM group, optionally bounded by Intune
  **scope tags**. Desired rows carry `GroupTag` + `RoleDefinitionName` + optional
  `ScopeTags` (pipe/`;`/`,`-joined tag **names** or numeric ids, resolved live to
  ids; unknown names are dropped with a warning; blank → the default scope tag `0`)
  + optional `MemberScope` (`All` = org-wide, else `Tagged`/resource-scoped). The
  create body is a `deviceAndAppManagementRoleAssignment` with the group in
  `members`. **RBAC prerequisite:** the engine app granted
  `DeviceManagementRBAC.ReadWrite.All`.
- **`EntraAppRole`** (order 66, entity `PIM-Assignments-AppRole`) — the **generic
  enterprise-app app-role connector**: one pattern that assigns a PIM group to an app
  role of *any* enterprise application, so gallery and line-of-business apps need no
  per-app connector. Desired rows carry `GroupTag` + a **target-app** identifier (one
  of `AppDisplayName`, `AppId` (the application/client id), or `ServicePrincipalId`
  (the SP object id)) + an **app role** (`AppRole`/`AppRoleValue`/`AppRoleName`/
  `AppRoleDisplayName`). The target SP is resolved once per run (and its `appRoles`
  cached); the desired app-role value is resolved to its id from that SP's `appRoles`
  by `value` then `displayName` (case-insensitive). A **blank value or `Default
  Access`** maps to Graph's implicit all-zeros app-role id; a value the app does **not**
  expose **throws** (fail-loud, matching the other connectors). Live + apply go through
  `servicePrincipals/{resourceSpId}/appRoleAssignedTo` (`POST` to create, `DELETE
  /{assignmentId}` to remove). It is **existence-based + idempotent** — the diff key is
  `group|app|appRole`, so a group that already holds the app role is `nochange` (no
  duplicate POST), and a live app-role grant not in desired is removed only under
  `-Mode Full -Prune`. **RBAC prerequisite:** the engine app granted
  `AppRoleAssignment.ReadWrite.All` (or made an **owner** of each target application)
  to read/POST/DELETE `appRoleAssignedTo`.

All three resolve `GroupTag → live group id` through the shared tag→name→id chain
(`Resolve-PimGroupIdByTag`), so a workload role binds to the same PIM groups the
rest of the engine manages. The pure key + value-resolution + body builders
(`Get-PimDefenderRoleKey`, `Get-PimIntuneRoleKey`, `Resolve-PimIntuneScopeTagIds`,
`Get-PimAppRoleKey`, `Get-PimAppRoleTargetKey`, `Resolve-PimAppRoleId`,
`New-PimAppRoleAssignmentBody`) are unit-tested offline.

> **Live tenant run is the delivery gate for `EntraAppRole`.** Offline unit tests
> prove the builders, role-value→id resolution, idempotent existence check, create
> body, remove path and registration order. The connector is **not** live-verified
> until it runs against a real enterprise app with the engine SPN granted
> `AppRoleAssignment.ReadWrite.All` (or app owner) and the POST/idempotent-re-run/prune
> cycle is confirmed end-to-end.

### 6.5 Hybrid on-prem AD provisioning + gMSA/sMSA (planner + hybrid-worker seam)

Some tenants still provision **on-prem AD** admin accounts (and legacy **gMSA/sMSA**
service accounts) alongside the cloud admins. The new engine is **cloud-only at
runtime** — it runs headless in a Linux container / serverless host with **no domain
controller line-of-sight and no `ActiveDirectory` module**. So on-prem AD writes
**cannot** run from the cloud engine; they must run on a **hybrid worker** (a
domain-joined Windows host with RSAT-AD and an explicit high-priv credential or a
gMSA). The model splits this cleanly into a pure planner and an execution seam
(`engine/_shared/PIM-HybridAd.ps1`):

**Planner (pure, offline-unit-testable, runs anywhere — cloud engine included).**
`Get-PimHybridAdPlan` reads the `Account-Definitions-Admins` rows whose
`TargetPlatform = AD` (non-`Remove`) and produces, per row, a normalised desired-state
record: `Get-PimHybridAdRowKind` classifies `standard | gmsa | smsa` (an explicit
`AdAccountKind`/`AccountKind` column wins over the `*gMSA*`/`*sMSA*` name heuristic);
`Get-PimHybridAdAccountName` appends a trailing `$` to managed accounts idempotently;
`Resolve-PimHybridAdTargetOu` routes the OU (`Purpose=HighPriv` → `PathAdminsL0T0`,
blank Purpose falls back to the `-L0-/-T0-` UserName marker, else `PathAdmins`);
`Get-PimHybridAdSearchRoot` derives the LDAP searchroot/domain (explicit
`SearchRoot`/`Domain` column → supplied domain → UPN suffix). `Compare-PimHybridAdState`
is an **idempotent** diff against whatever live AD set the worker supplies (create /
update / nochange — gMSA/sMSA are **existence-only**, attribute drift ignored); a CREATE
with no resolvable OU is demoted to a **Skip** with a clear reason (never invent an OU).
The cloud engine calls the planner with `Live = @()` to log a "what we want" preview.

**Execution seam (the interface a hybrid worker calls).** The cloud engine (or the
Manager) emits a **work package** (`Export-PimHybridAdWorkPackage` → a UTF-8 JSON file
carrying **only** desired-state intent + the plan — **no passwords, no secrets, no live
AD data**). A hybrid worker imports it (`Import-PimHybridAdWorkPackage`), reads LIVE AD,
and calls `Invoke-PimHybridAdApply`:

- **default (no `-Apply`)** — pure plan/preview, writes nothing (safe in the cloud
  engine, CI, and unit tests);
- **`-Apply`** — routes Create/Update through an **injectable
  `-ActiveDirectoryAdapter`** (the only on-prem-bound code; a fake adapter makes the
  orchestration fully testable), **requires an explicit `-Credential`** (mirrors the
  legacy contract — without one it skips the AD branch and says so, **never** runs as
  ambient SYSTEM), **surfaces the real `Get-ADUser` error** without it cascading into a
  create, and resolves gMSA/sMSA **managed passwords on the worker** (`adapter.GetManagedCredential`
  → `AutomateITPS.AD\Get-GMSACredential`, reading `msDS-ManagedPassword` from the DC) —
  managed accounts are existence-only and are **never** created via `New-ADUser`.

**◻ Flagged on-prem execution.** `Get-PimDefaultActiveDirectoryAdapter` returns the real
`ActiveDirectory`-module adapter and is **hybrid-worker-only** — it **throws** off a
non-domain-joined host, so the cloud engine can never accidentally write AD. The
`HybridAdProvisioning` provider (order 95, gated `$global:PIM_HybridAdMode` =
`Off` default | `Plan`) plugs into the registry as a **planner**: `GetLive` is always
`@()` (no DC from the cloud), `ApplyCreate`/`ApplyUpdate` only **log** the planned
on-prem action and best-effort write the work package to
`output/state/hybrid-ad-workpackage.json` — they do not touch AD. The actual on-prem
`New-ADUser`/`Set-ADUser`/managed-password read is **deferred to the hybrid worker**
(still on the backlog) and is the hybrid-worker contract above.

### 6.6 Access Review overview (read-only data layer)

Separate from the `AccessReviews` *provider* (order 80, which **creates** one
review schedule per opted-in group), the **overview** is a **read-only data/provider
layer** that enumerates the access reviews relevant to the PIM estate and returns a
**normalized, table-ready list** for the Manager's Access Reviews GUI tab (the tab
itself is queued separately — this layer renders nothing). It lives in
`engine/_shared/PIM-AccessReviews.ps1` and is **list/get only** — it never records or
applies a review decision, never POSTs/PATCHes/DELETEs. It is REST-only via
`Invoke-PimGraph` (cert app-only; honours the `$global:PIM_UseGraphSdk` opt-in inside
PIM-Rest), and needs **`AccessReview.Read.All`** on the engine SPN — without it the
LIVE call 403s and returns an **empty list with a warning** (graceful no-op, never a
crash; the grant ships in `setup/Grant-PimGraphAppRoles.ps1`).

- **Live wrapper** — `Get-PimAccessReviewOverview [-PimManagedOnly] [-IncludeDecisionCounts]`
  lists `identityGovernance/accessReviews/definitions`, fetches each definition's most
  recent **instance** (for live status + start/due dates) and — when
  `-IncludeDecisionCounts` is set — that instance's **decision items** (for the
  pending/approved/denied tally), then feeds each definition through the pure
  normalizer. `-PimManagedOnly` filters to engine-created reviews (displayName
  contract `PIM4EntraPS review - <group>`).
- **Pure normalizer** — `ConvertTo-PimAccessReviewOverviewRow` (offline-unit-tested,
  no network/clock) maps a Graph `accessReview` definition (+ optional instance +
  decisions) to **one flat row**, with small pure helpers for the harder fields
  (`Get-PimAccessReviewScopeTarget`, `Get-PimAccessReviewReviewers`,
  `Get-PimAccessReviewRecurrence`, `Get-PimAccessReviewDecisionCounts`).

**Normalized row shape** (stable, direct table render — no further reshaping needed):

| Field | Type | Meaning |
|---|---|---|
| `Id` | string | Access-review definition id. |
| `DisplayName` | string | Review name as shown in Entra. |
| `IsPimManaged` | bool | True when the engine created it (`PIM4EntraPS review - *`). |
| `GroupName` | string | The PIM group under review (engine-managed reviews only; else blank). |
| `ScopeKind` | string | `group` / `role` / `other` / `unknown` — what the review targets. |
| `ScopeId` | string | Group id or role-definition id when resolvable. |
| `ScopeTarget` | string | Human-readable scope (e.g. `Group: <id>`). |
| `Reviewers` | string[] | Reviewer ids / descriptors (`group:<id>`, self placeholder). |
| `ReviewerCount` | int | Count of `Reviewers`. |
| `IsRecurring` | bool | Recurring vs one-time. |
| `Recurrence` | string | Friendly cadence (`Monthly` / `Quarterly` / `Annually` / `One-time`…). |
| `Status` | string | Current instance status (`InProgress` / `Completed` / `NotStarted`…). |
| `StartDate` / `DueDate` | string | Current instance start / end (ISO). |
| `AutoApply` | bool | Whether the review auto-applies decisions (engine reviews = false). |
| `DecisionsTotal` / `DecisionsPending` / `DecisionsApproved` / `DecisionsDenied` / `DecisionsDontKnow` | int | Decision tally for the current instance (zero unless `-IncludeDecisionCounts`). |

Caching wiring (sharing the tenant cache) is a follow-on — the function is exposed
standalone for the GUI to call directly.

**Manager "Access Review" tab + read endpoint (2026-06-15).** The read-only GUI
surface is delivered: `GET /api/access-reviews` in `tools/pim-manager/Open-PimManager.ps1`
lazily imports the shared module, connects (`Initialize-PimManagerTenantConnection`),
calls `Get-PimAccessReviewOverview` and returns `{ source, note, total, rows }`. The
**"Access Review"** tab in `pim-manager.html` (`renderAccessReviews`) renders the rows
as a filterable/searchable table (search across name/group/scope/reviewer, status
filter, PIM-managed-only toggle) with summary cards (reviews / in-progress / pending /
approved / denied) and per-row status pills + decision counts. **No dead view:** when
the live wrapper returns no rows (grant missing / no reviews / no live connection) the
endpoint falls back to `Get-PimAccessReviewSeedRows` — a PURE seed set produced by the
**same normalizer** (`ConvertTo-PimAccessReviewOverviewRow`) over Graph-shaped
fixtures, so the seeded rows have the identical schema and pass through identical
scope/reviewer/recurrence/decision logic as live data (not a hand-built stub). The
response `source` field (`live` | `seed`) drives a UI badge so the operator always
knows which they are viewing. Query params: `pimManagedOnly=1`, `counts=0`, `seed=1`.

**Access-review ATTESTATION (decisions / overdue / evidence) wired into the tab (2026-06-15).**
Three endpoints extend the read-only overview into a working attestation surface:
`POST /api/access-reviews/decision` (Admin-gated, audit-logged → `Set-PimAccessReviewDecision`,
recording one Approve/Deny/DontKnow with a mandatory justification at a time — no bulk
auto-approve), `GET /api/access-reviews/overdue` (→ `Get-PimAccessReviewOverdue`) and
`GET /api/access-reviews/evidence?definitionId=&instanceId=` (→ `Get-PimAccessReviewEvidence`),
both with the same seed fallback so the surfaces are never dead. The tab renders an
overdue/due-soon "needs attention" banner + badge, and a per-review **Review items** expander
that lazy-loads the evidence package and shows per-principal **Approve / Deny / DontKnow**
buttons (justification prompt). **Graceful degrade (the key design point):** recording a
decision needs **`AccessReview.ReadWrite.All`** on the Manager identity, which is **not yet
granted**; the decision endpoint catches the 403 and returns HTTP 200 with
`{ ok:false, permissionMissing:true, note }` so the UI shows an honest "permission not granted
yet" message instead of a crash. The grant lives in `setup/Grant-PimGraphAppRoles.ps1`.

**Reviewer assignment + reminders complete the actionable surface (2026-06-17).**
Two further endpoints close out the gap, built on the SAME read-only overview + decision
wiring (no parallel review system):
- `POST /api/access-reviews/reviewers` (Admin-gated, audited → `Set-PimAccessReviewReviewers`)
  **assigns / replaces the reviewer scope** of a review *definition* — who is asked to attest. The
  pure core is `ConvertTo-PimReviewerScopeEntry` (a spec → a Graph `accessReviewReviewerScope`:
  a UPN/object-id → `/users/…`, `group:<id>` → `/groups/…`, `manager`/`self`/`lastReviewer` → the
  managed special) + `New-PimReviewerAssignmentPatch` (de-dups, builds the exact
  `{ reviewers:[{query,queryType}] }` PATCH body, **fail-closed on an empty set**, and emits an
  audit record). The Review-items expander shows the current reviewers + an **Assign reviewers**
  control (Admin only).
- `POST /api/access-reviews/reminders` (Admin-gated, audited → `Send-PimAccessReviewReminders`)
  **chases reviewers** of every current instance that is **due** for a reminder. The pure
  due-computation is `Get-PimReviewReminderState` (clock-injected): a reminder is due only when the
  instance is **not completed**, is **overdue or within the reminder window**, has **pending**
  decisions, and **hasn't been reminded inside the repeat window** (no spam). The send **reuses the
  existing mail path** (`Send-PimNotifyMail`) + a new shipped template
  `templates/mail/access-review-reminder.mailtemplate.html` (store/file/shipped override precedence
  like every other PIM mail). The endpoint supports a **preview/dry-run** (`{preview:1}` →
  `-WhatIf`, decides recipients, sends nothing) so the GUI confirms exactly who would be contacted
  before sending. The **Send reminders** toolbar button (Admin only) previews → confirms → sends.
Both endpoints **degrade gracefully** (a 403 for the missing `AccessReview.ReadWrite.All` →
`{ok:false,permissionMissing:true}`, HTTP 200) and **fall back to the seeded preview offline** so
the controls are never dead. Evidence export (already shipped) supplies the auditor artefact —
who attested what, when. Pure cores live in `engine/_shared/PIM-AccessReviews.ps1`, PS 5.1-safe,
covered by `tests/Test-PimAccessReviews.ps1` (114 offline assertions) and the GUI↔engine
alignment check. The hosted/SQL Manager GUI smoke is the live gate.

### Approvals tab — maker/checker control plane (2026-06-15)

The **Approvals** tab is the human control plane over `engine/_shared/PIM-ApprovalGate.ps1`. Destructive identity actions (offboard / revoke / disable) are
raised here and must be approved by a **different** administrator before any controlled
execution is possible — **nothing executes automatically; this GUI introduces no auto-execute
path**. Endpoints (`tools/pim-manager/Open-PimManager.ps1`): `GET /api/approvals` (the queue,
newest first; each offboard item carries the engine-derived `Get-PimOffboardSequencePlan` —
disable → revoke active → SCHEDULED delete — shown before approval; per-item `canDecideThis`
encodes Admin-role + Pending + separation-of-duties), `POST /api/approvals` (raise — maker,
Admin+, requestor = the authenticated Manager identity), `POST /api/approvals/decide` (approve/
deny by id — checker, Admin+, **maker≠checker** mapped to 403, idempotent via the gate's
once-Pending transition). The gate library is dot-sourced at boot and a `Get-/Set-PimSetting`
shim bridges its persistence onto the Manager's own settings store (SQL `pim.Settings`), so a request raised in the
Manager is the same record the scheduler/engine see. A Home **pending-approvals** tile (fast
load, no live call) deep-links here. **Name collision — ENDED (2026-09-10):** the gate and the
older portal lib both exported `New-PimApprovalRequest` / `Resolve-PimApprovalDecision` with
different signatures, so which one a caller reached depended on which lib the host loaded last —
and the two hosts disagreed, resolving the same name to different functions. The earlier hardening
gave the gate's internal callers private names, which protected the queue but left the public
names colliding for anyone using the documented name. The portal pair is now named for what it is
— `New-PimPortalApprovalRequest` / `Resolve-PimPortalApprovalDecision` — so the two contracts have
two names and neither can shadow the other in any load order.

### Maker/checker on sensitive authoring/onboarding (2026-06-16)

Sensitive **Authoring / Onboarding** commits get a second-person approval gate **layered on the
same control plane above** — there is no second approval system.
`engine/_shared/PIM-SensitiveAuthoring.ps1` adds two pure, PS 5.1-safe pieces:

1. **Classification** — `Get-PimAuthoringSensitivity` (+ predicate `Test-PimAuthoringActionSensitive`)
   marks a proposed change SENSITIVE when ANY of these conditions hold: a **privileged-role
   attach** (`Test-PimRowIsPrivileged`: control/management plane, Tier-0/1, a well-known privileged
   role name such as Global Administrator / Privileged Role Administrator / Azure Owner, or a
   privileged GroupTag marker), a **guest/external account into a privileged group**
   (`Test-PimRowIsGuest` AND the row is privileged), or a **disable / offboard** action. It accepts
   the action's computed rows and/or a `Get-PimAuthoringPreview` result, so it classifies exactly
   what will be staged. Ordinary, non-privileged authoring is NOT sensitive.
2. **Commit gate** — `Test-PimAuthoringCommitAllowed` returns *allowed* for a non-sensitive change
   (`gate=not-sensitive`), and for a sensitive change requires an **Approved, in-window, un-executed
   `authoring` approval request** keyed to the change's stable target
   (`Get-PimSensitiveAuthoringTarget` → `authoring:<action>:<base>`) via the existing
   `Test-PimApprovalApprovedFor`. The `authoring` action was added to the gate's action set, so the
   maker raises it with `Add-PimApprovalRequest`, a **different** checker approves it
   (`Set-PimApprovalDecision`; maker≠checker enforced by `Test-PimApprovalSeparationOk`), and the
   approval is consumed once on commit (`Set-PimApprovalRequestExecuted`).

The Manager exposes this as `POST /api/authoring/sensitivity` (Admin-gated, read-only — classifies +
checks, never writes) and the Authoring **preview/confirm** flow calls it before staging: a sensitive
change with no approval is blocked client-side and the operator is routed to the Approvals tab to
raise the request. **Hardening done here:** the approval store's JSON fallback round-trips
`requestedUtc`/`decidedUtc` back into `DateTime` objects whose default string form did NOT re-parse,
which silently made fresh persisted requests look *expired*; a shared `ConvertTo-PimGateUtc`
(round-trip/invariant/assume-UTC, accepts a `DateTime` directly) now normalises both timestamps in
`Test-PimApprovalRequestExpired` and `Test-PimApprovalApprovedFor`. Covered offline by
`tests/Test-PimSensitiveAuthoring.ps1` (34/34) + the GUI↔engine alignment check; the hosted/SQL
Manager GUI smoke remains the live gate.

### Approval-gated offboarding executor — request → approve → EXECUTE (2026-06-17)

The maker/checker queue above decides *whether* a destructive action may run; the offboarding
**executor** is the missing wiring that actually *runs* an approved offboard through the **existing**
account-status-change pipeline. `engine/_shared/PIM-ApprovalGate.ps1` adds
`Invoke-PimOffboardExecution`, a small PS 5.1-safe state-machine driver that resolves an Approved
request by id and then refuses unless **every** existing gate allows it — it implements **no new
gate**:

1. **Target shape** — `Test-PimOffboardTargetIsBulk` classifies the request target: an **empty**
   target never runs (there is no population to resolve, even with confirmation); a **bulk /
   multi-principal / wildcard** target (`,` `;` newline, a run of whitespace, `*`, or an
   `all`/`everyone` keyword) runs only with an explicit `-ConfirmBulk`. A normal single UPN passes.
2. **Composite execution gate** — it calls the existing `Test-PimOffboardExecutionAllowed`, which
   refuses an `-Automatic` invocation outright (automatic offboarding stays prohibited), requires an
   `Approved`, in-window, un-executed `offboard` request, excludes break-glass accounts, and composes
   the always-on DisableGuard breaker + env-aware gate. None of these is bypassed by an approval.
3. **Once-only latch** — it claims the request via `Set-PimApprovalRequestExecuted` **before**
   executing, so a concurrent or replayed call cannot double-run; an already-`Executed` request is
   refused at the latch.

Only then does it run the guided sequence from `Get-PimOffboardSequencePlan` (disable → revoke-active
→ **scheduled** delete) through an **injectable** action invoker. The default invoker
(`Get-PimDefaultOffboardActionInvoker`) routes the disable step to `Invoke-PimAccountStatusChange
-AccountStatus Disabled` and the revoke-active step to `…Revoked` (the same pipeline the MSP
kill-switch uses) and records the delete step as a scheduled intent — it never deletes immediately.
The offline tests inject a **mock** invoker instead, so the full request→approve→execute path is
proven without ever touching a tenant. The Manager exposes this as `POST /api/approvals/execute`
(Admin-gated; resolves the desired set so the breaker is satisfied for a deliberate single-target
run; a refused gate returns 409 with the gate name) and the Approvals tab shows an **Execute**
button on Approved offboard requests (single-target = one confirm; bulk = type-EXECUTE confirm).
Covered offline by `tests/PIM.OffboardExecution.Tests.ps1` (9/9, mocked pipeline) + the GUI↔engine
alignment check; the hosted/SQL Manager GUI smoke remains the live gate.

### Approval-gated bulk-revoke executor — preview → approve → EXECUTE (2026-06-17)

The Maintenance bulk-revoke surface was previously raw/immediate: an over-threshold batch could fire
the moment the operator echoed the count, with no recorded approval. `engine/_shared/PIM-ApprovalGate.ps1`
closes that gap with `Invoke-PimRevokeExecution` — the **exact mirror** of the offboard executor for the
revoke surface. It implements **no new gate**; it composes the existing ones:

1. **What-if + break-glass split** — the shared, pure `Get-PimRevokeGuardPlan` splits the requested rows
   into the post-break-glass `toRevoke` set and the protected `skipped` set. Break-glass / emergency
   principals are **always** dropped from the executed set — with or without an approval.
2. **Approval-required decision** — it calls the existing `Test-PimRevokeExecutionAllowed`: a batch
   **at/below** the threshold (`$global:PIM_RevokeApprovalThreshold`, default 5) runs under the interim
   count-confirm guard (`gate=interim-guard`); a batch **above** it requires an `Approved`, in-window,
   un-executed `revoke` request for the batch label (`gate=approved`) and is otherwise refused
   (`gate=no-approval`). A blank justification is refused outright (`gate=no-justification`) — every
   revoke is attributed.
3. **Once-only latch** — on the approval-driven (over-threshold) path it claims the Approved request via
   `Set-PimApprovalRequestExecuted` **before** executing, so the same approval can never drive a second
   over-threshold batch (`gate=already-executed` on a replay).

Only then does it run the post-break-glass rows through an **injectable** revoke invoker. The default
(`Get-PimDefaultRevokeInvoker`) routes to the Manager's existing `Invoke-PimActiveAssignmentRevokeBatch`
(the same REST adminRemove path the Revoke tab already used); the offline tests inject a **mock** so the
full preview→approve→execute path is proven without ever revoking a real assignment. The Manager wires
this into the **existing** `POST /api/revoke` commit handler (additive, no route reorder): the what-if
`preview` now reports `approvalRequired`, and an over-threshold commit without an Approved request is
blocked **409** with `gate=no-approval` and instructions to raise a `revoke` approval on the Approvals
tab; on a successful over-threshold commit the Approved request is latched Executed. The **Maintenance**
tab is renamed **Maintenance & Revoke** with a destructive tooltip + in-context guidance (today the screen is **Review standing access**, §18.1g). Covered
offline by `tests/PIM.RevokeExecution.Tests.ps1` (6/6, mocked pipeline) + live-HTTP asserts in
`tests/Test-PimManagerEndpoints.ps1` + the GUI↔engine alignment check; the hosted/SQL Manager GUI smoke
remains the live gate.

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
selects one; **blank = `default`** for groups, **blank = `EntraIDRoles_Standard`**
for directory roles. Four ship today, in two families:

| family | templates | approval | `Admin_Eligibility` |
|---|---|---|---|
| **standard** | `default` (groups), `EntraIDRoles_Standard` (directory roles) | none | *empty* |
| **approval** | `approval-required`, `EntraIDRoles_RequireApproval` | required | `Justification` |

**Activation always requires MFA + justification** — that is the control that
protects the privilege at the point of use, and it is untouched by everything
below.

**Which rows get to choose one (§71.25).** The policy provider reads `PolicyTemplate` from every
group-definition row — Roles, Services, Tasks, Processes, and now also `PIM-Definitions-Resources`
(`Get-PimGroupPolicyDefinitionRows`). Resources is excluded from the group-**creation** source on
purpose, because discovery auto-create writes every discovered Azure/Power BI resource there; that
reason is about creating groups and says nothing about policy, so reading it here changes behaviour
for exactly one kind of row — a Resources row whose template is **set**. A blank template still
resolves to `default`, which is the same policy the baseline sweep already applies to a managed group
with no definition row, so every existing row is unchanged.

**Choosing one in the Manager.** Both permission-group wizards offer a picker built from the
tenant's OWN template store (`catalogs.policyTemplate` on `/api/settings/operational-policy`, read
from `pim.Settings['PolicyTemplates']` — never from the shipped files, so a customised or added
template is offered and a template the engine could not find never is). **"Use default" is first and
its value is empty**, which is what keeps a wizard run that does not touch the field byte-for-byte
identical to before. A template is marked as needing approval from its own `Approval` rule, so no id
is hard-coded in the page. An Azure permission group has no definition row of its own, so choosing a
non-default template there stages a minimal `PIM-Definitions-Resources` row carrying the identity and
the template — only when a non-default template was chosen.

**Why `Admin_Eligibility` is empty on the standard family.** That rule governs what
an admin must present when *granting* eligibility, and on a standard scope the
"admin" is the engine's own app-only service principal, whose token can never carry
an MFA claim. Requiring MFA there is unsatisfiable by anyone and blocks the
delegation path the product exists to run. A justification rule is no better as a
control: a grant that omits one is still accepted on the app-only path. On an
approval scope a human is in the loop by definition, so the rule is enforced and
earns its place.

### Switching approval off, and policies that stop accepting changes (2026-08-11)

A policy template that declares **no** `Approval` block means *approval must be off*, not
*leave whatever is there*. Moving a scope to a standard template therefore clears a live
approval requirement, on directory roles and group policies alike. Previously the engine only
ever wrote an approval rule its template asked for, so approval was **one-way**: it could be
switched on and never off.

Two mechanics are worth knowing, because neither is guessable:

- **The "approval off" body must be complete.** Sending only `isApprovalRequired = false` is
  rejected; the directory wants the whole setting, including a stage carrying an empty approver
  list.
- ⚠️ **An explicit recipient list on the *approver notification* rule write-locks the entire
  policy.** The directory treats that list as the policy's approvers, so once it is set, every
  later per-rule update is rejected — including updates unrelated to approval, and including the
  one that would remove the list. The write that causes it is accepted silently. The single
  supported route back is a whole-policy update that sets the list empty, and the list cannot be
  put back afterwards: restoring it locks the policy again. The engine detects this state,
  recovers from it, and names the recipients it had to drop.

  This is why the approval-required template does **not** name the approvers as notification
  recipients — the stronger guarantee (who-gets-told cannot diverge from who-can-approve) is not
  available, so the rule keeps the directory's default approver routing instead.

**Three policy surfaces, one template model, one safety brake.** The same templates drive the
PIM for Groups policies (`GroupsPolicies`, member **and** owner), the directory-role policies
(`EntraRolePolicies`) and the Azure resource role policies (`AzResPolicies`). The shipped standard
values equal v1's rule for rule (a standing test parses v1's definitions and compares every rule),
and stored templates receive new settings automatically without overwriting customised values. All
three providers plan their policy changes first and pass the plan through the **mass-change safety
brake** before writing anything; see §17.7.

See §17.7 for the full template/approval mechanics.

---

## 7. Identity, auth & engine configuration

- **Which identity the engine runs as depends on where it runs** (full model: §27).
  - **Hosted (Container Apps).** The scheduled engine (the tick job), the Manager, the nightly
    updater and the downlink authenticate to Graph, ARM, SQL and Log Analytics as their
    **system-assigned managed identities** — no stored credential. The token core
    (`Get-PimRestToken`) takes the managed-identity branch when `IDENTITY_ENDPOINT` is present
    **and no client id is configured**; a hosted job therefore carries no `PIM_ClientId` (a client
    id with no usable credential would suppress the MI and authenticate as nothing).
  - **Server / VM / community.** The engine signs in app-only as the **engine application**
    (service principal) with a **certificate** (`$global:PIM_CertThumbprint` /
    `PIM_CERT_THUMBPRINT`) resolved from the machine certificate store. Reuse the one engine
    application; never create a new one per run, and remove stale duplicate certificates.
  - **Across tenants.** A managed identity lives in one directory, so an MSP master acting *into*
    a managed tenant (S5) uses a multi-tenant application with a credential (§27.4).
  - Certificates or managed identity are the default everywhere. A **client secret** is accepted
    only where a platform requires one — the Manager's Easy Auth sign-in registration (it grants
    sign-in only), or a container engine deliberately configured to act as a named application.
- **Two permission sets, granted by setup, never widened by a re-run**
  (`tools/setup/_PimSetupShared.ps1`: `Get-PimGraphAppRoleMap -RoleSet Engine|Manager`, applied by
  `Grant-PimMiGraph`, which **throws** on a refused assignment rather than warning).
  - **Engine** (the tick job's identity): `Directory.Read.All`, `User.ReadWrite.All`,
    `Group.ReadWrite.All`, `RoleManagement.ReadWrite.Directory` (required to create role-assignable
    groups and manage their members/owners), the schedule roles
    `RoleEligibilitySchedule.ReadWrite.Directory` / `RoleAssignmentSchedule.ReadWrite.Directory`
    and their `.Remove.Directory` counterparts, `RoleManagement.Read.All`,
    `PrivilegedAccess.ReadWrite.AzureADGroup`, `PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup`
    / `PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup` and their `.Remove.AzureADGroup`
    counterparts (Graph app-roles do not imply one another, and revoke is a separate permission),
    `RoleManagementPolicy.ReadWrite.Directory` + `RoleManagementPolicy.ReadWrite.AzureADGroup`
    (+ the matching `.Read.` roles), `AdministrativeUnit.ReadWrite.All`,
    `UserAuthenticationMethod.ReadWrite.All`, `AccessReview.Read.All`, `AppRoleAssignment.ReadWrite.All`
    + `Application.Read.All` (EntraAppRole), `RoleManagement.ReadWrite.Defender` (Defender XDR),
    `DeviceManagementRBAC.ReadWrite.All` (Intune), `Domain.Read.All` (the downlink's default domain)
    and `Policy.Read.All` (the tenant TAP policy). **Azure RBAC**: the engine identity needs the Azure
    role(s) that allow PIM assignment and policy management on each ARM scope used by `AzRes` /
    `AzResPolicies`.
  - **Manager** (read-only, deliberately): directory, group, user, AU, application, access-review,
    role-management, policy and schedule **`.Read.`** roles only. Every Manager action that changes
    the tenant — revoke, TAP re-issue, session revoke — is **queued** and applied by the engine
    (§18.1f), so the web process never needs a write permission. A standing test asserts that no
    `ReadWrite`/`Remove` role is ever added to the Manager set.
- 🔒 **`Mail.Send` is in neither Graph set.** Sending is granted by the **scoped Exchange RBAC
  assignment** that `tools/setup/Initialize-PimMailSender.ps1` creates — `New-ServicePrincipal` +
  `New-ManagementScope` (pinned to the one sender mailbox) + `New-ManagementRoleAssignment -App …
  -Role 'Application Mail.Send' -CustomResourceScope …` — for the environment's managed identities
  (the deploy passes the tick job's and the Manager's principal ids) or, on a server engine, for the
  engine application. Exchange RBAC for Applications does **not restrict** a tenant-wide Graph
  consent; it **grants** scoped access in its own right, and a tenant-wide consent sitting beside it
  keeps winning — measured against an out-of-scope mailbox, tenant-wide `Mail.Send` allowed sending
  as ANY mailbox while the scoped assignment alone refused it. So granting Graph `Mail.Send` would
  not add capability; it would remove the restriction.
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
- **Batched reads** (`Invoke-PimGraphBatchGet`, Graph `$batch`): group memberships and group
  policies are read in batches, and Azure role assignments come from a single query rather than
  one per scope.
- **One-shot throttle handling.** Sub-requests of a batch that come back throttled (`429`), failed
  server-side (`5xx`) or missing are collected; the batch reader waits the largest `Retry-After`
  **once** (capped) and resends the collected items together as a batch (bounded attempts), instead
  of re-running each one immediately as its own request. Every slow or throttled read logs how many
  requests it sent, in how many round-trips, and how many were throttled.
- **Cached lookups.** A group's member/owner PIM policy id never changes for the life of the group,
  so a found id is kept in the process for 12 hours **and** persisted in `pim.Settings`
  `GroupPolicyIdMap`, so a fresh tick process starts with every known id (a miss is never cached,
  and a stale id is dropped and looked up again). Membership reads are cached for the length of a
  run. A revoke and the drift snapshot always work from fresh reads.
- **Narrowed membership reads, confirmed per group.** In `-Mode Delta` with no prune possible,
  `AdminMembers` and `GroupMembers` read the PIM-for-Groups schedules **by principal** for the
  admins/groups the desired rows name (`principalId eq '<id>'`), instead of one `groupId eq`
  request per managed group (Graph refuses multi-group filters). Because Graph's by-principal list
  **omits some schedules** the by-group list returns (observed for older nestings, not a paging
  issue), every desired row that read did not answer — and every `Remove` row — is **confirmed by a
  per-group read** (`Add-PimConfirmedGroupMemberships`), and any failure of the narrowed read falls
  back to the full read. Kill switches: `NarrowDeltaMembershipReads` (both) and
  `NarrowDeltaGroupMembersReads` (GroupMembers alone). The engine line's `live=` counts only what
  was read.
- **Shared SQL connection pool** (`PIM-SqlStore.ps1`): every call reuses one pool per access token
  instead of opening a new session, so a heavy Manager page costs a handful of sessions rather than
  exhausting the database's session allowance; the access token refreshes on schedule even under
  constant use.
- **Low write load.** Settings are written only when their value changes, and the job run history
  is stored compactly (§11.3a), which matters on small database tiers with a log-rate cap.
- **Validate-and-skip**: an apply that returns *already-exists* / conflict is
  counted as **skipped**, not an error (idempotent re-runs). An *Active* nesting into a
  role-assignable group is not skipped silently: it is reported as a failing item with its fix
  (§3.1, §11.3a).
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
`role=Delegated` in the `ManagerAccess` model in `pim.Settings`, §17.12). A Delegated user is a **workload
owner**: the data layer (`Read-PimRows`) scopes every grid to **only the groups
they own** (their identity in the group's Owners/SponsorUpn) plus the assignment
rows referencing those groups (by `GroupTag` / `Target` / `SourceGroupTag`) — so
they see their group's tenant/AU/Azure bindings *through the group*, and nothing
else. Reader/Admin/SuperAdmin are unscoped. Visibility keys on **groups only**,
never on `AdministrativeUnitTag`.

The **portal-admin** model goes finer than the simple `Delegated` role: a portal
profile (stored in SQL `pim.Settings`; written by `Set-PimPortalAdmins`) carries `services`
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

### 9.4 Delegation depth: self-delegation, two-approval split, reachability

`PIM-DelegationDepth.ps1` adds three pure (offline-testable) decision layers on
top of §9.2/§9.3. None of it sends mail or writes to Entra/Azure — it produces
decisions the engine/Manager consume.

**Local self-delegation.** Local IT on the **local plane** self-delegates *any*
permission (including privileged) with no MSP request — full local autonomy; the
Owner tag is provenance, not a gate. The only gate is the **deployment plane**
(`Get-PimDelegationPlane`, config `DelegationPlane`/`PIM_DelegationPlane`): `local`
(default) allows it; `msp` refuses (a customer pulls its baseline; an MSP admin
does not self-grant into a customer tenant). An opt-in **Enforced baseline** set
(`EnforcedBaselineTags`, default empty) lets a customer/MSP mark specific group
tags so even a local admin cannot self-override them. Super-admins are never
locked out (break-glass). `Test-PimSelfDelegationAllowed` returns `{allowed,
reason}`; `New-PimSelfDelegationChange` materialises the grant as a **normal**
`PIM-Assignments-Admins` Create — the same row the approval workflow writes — so
audit/offboarding treat self-delegated access identically (no privileged side door).

**The two-approval split (kept strictly distinct).**
1. **Delegation/assignment approval — engine-owned, group-owned.** When an admin
   is *assigned* to a group and that needs approval, the engine/GUI routes the
   request. The approval is owned by the GROUP, whose owner is **either a
   department or a person**; a department is enumerated to its owner
   (Owners→SponsorUpn→Department contact). `Get-PimDelegationApprovalPlan` returns
   the ordered approver **layers** + escalation chain (built on §13's approver
   matrix + resource Owners). This is our workflow — it can escalate, remind, time
   out.
2. **Activation approval — Entra-PIM-native.** Enforced 100% by the Entra PIM
   service at activation per the role-management policy. Entra PIM does **not**
   accept a department as approver — it must be **specific PEOPLE**.
   `Get-PimActivationApprovalPeople` produces the people-only set the engine writes
   into the policy: it expands `@Persona` tokens, resolves any department token to
   its owner people, and **drops** anything that still isn't a person (returned in
   `.unresolved`); an empty people set yields `ok=$false` so the engine refuses to
   ship an empty activation approval rule (mirrors `GroupsPolicies`' existing "NO
   approver resolved" throw). **The engine never mediates activation and never
   sends an activation email.** `Get-PimApprovalModelSummary` returns both surfaces
   side-by-side so a caller can never confuse them.

**Reachability-by-classification (PAW detection is opt-in, OFF by default).**
PAW detection and the reachability-restriction it drives **default to OFF** — they
are an opt-in maturity toggle, never enforced unless explicitly enabled
("security tight but customizable to maturity; tight is NOT the default"). With
detection OFF (the default), `Resolve-PimReachability` returns `whole-network` for
**every** classification (incl. T0): nothing is confined to the PAW segment and
`Test-PimReachAllowed` never blocks — the permissive default-maturity path, so a
tenant without PAW/SAW segmentation is never stranded. A customer opts in with a
single flag (`PIM_PawDetection`, synonym `PIM_EnforcePaw`); only then does the
segmentation policy apply: `Resolve-PimReachability` maps a group's classification
to a network reach class — **T0 → `paw-only`**, **T1/MP → `limited`**, **T1/WDP/L3+
→ `whole-network`** (and unmatched/less-privileged → `whole-network`), fully
overridable via `ReachPolicy`/`PIM_ReachPolicy`. This pairs with the PAW gate
(§9.3): PAW says *from which device*, reachability says *to how much of the
network*. When ON, `Test-PimReachAllowed` orders the classes
`paw-only < limited < whole-network` — a request from a more-restricted segment may
reach anything; a less-restricted segment may not reach a more-restricted
classification (the same "more-privileged may manage less" direction as the PAW
level rule). **Super-admins are never locked out** (break-glass): `Test-PimReachAllowed`
short-circuits to allow for a super-admin even with detection ON, so a blank or
misdetected segment can never strand them. The flag is a permanent maturity toggle,
not a debug/stopgap knob.

### 9.5 Onboarding convenience flows (guest invite + self-service toggle)

`PIM-Onboarding.ps1` adds two pure (offline-testable) convenience flows on top of
§9.2's portal capabilities. Like everything else in the delegation layer they
produce **change-queue records for Review & Save** — the engine stays the only
writer to Entra/Azure, and the one live side effect (the B2B invitation POST) is a
separate, explicitly-confirmed step.

**Guest invite into the delegation model.** Inviting an external consultant is not
just a B2B invitation — the consultant must land *inside* the group-centric model.
`New-PimGuestOnboardingPlan` (cloud-only; on-prem returns `mode=unsupported` with
no changes, since you cannot invite a guest into on-prem AD) composes three
artefacts: (a) the Graph `/invitations` body (`New-PimGuestInvitationBody`, also
the input to the live `Send-PimGuestInvitation` wrapper); (b) an
`Account-Definitions-Admins` **Create** for the guest as a cloud `Consultant`
(`New-PimGuestAdminRow` — derives Initials/DisplayName when not supplied, UPN =
the invited email); and, when a target group tag is supplied, (c) a
`PIM-Assignments-Admins` **Create** that places the guest into that direct
delegation group as `Eligible` by default (`New-PimGuestDelegationChange` —
membership *is* the delegation). The gate is the portal capability **`invite-guest`**
(`Test-PimPortalCanInviteGuest`; super-admin bypasses).

**Self-service consultant enable/disable.** A department/service owner toggles one
of *their own* managed consultants on or off. `Resolve-PimSelfServiceToggle` gates
on **`enable-consultants`** + `managedAdmins` (`Test-PimPortalCanEnableConsultant`;
super-admin/`*` bypass) and, when allowed, returns a single
`Account-Definitions-Admins` **Update** carrying the canonical `AccountStatus`
column (`Enabled`/`Disabled`) via `New-PimAccountToggleChange` — the engine flips
the Entra `accountEnabled` bit and audits it.

Both are dot-sourced into the Manager (`PIM-ChangeQueue.ps1` + `PIM-PortalAccess.ps1`
deps loaded first) and exposed as `POST /api/onboarding/guest-invite` and
`POST /api/onboarding/self-service-toggle` (Admin role required; the per-flow
capability gate runs inside, super-admin bypass). The reversed-wizard endpoint
shares the same module pattern: `Get-PimWizardDerivation` is the single dispatch
over the three per-target derivation functions (§17.x) behind `POST /api/wizard/derive`.

---

## 10. Notifications

`PIM-Notify.ps1` renders the effective mail body resolved by
`Get-PimNotifyTemplateText` from the **one template store** (SQL `pim.Settings['MailTemplates']`,
`PIM-MailTemplateStore.ps1`), falling back to the shipped `templates/mail/*.mailtemplate.html`
only for a type the store has not been seeded with yet (see §17.6), with `{{token}}` substitution,
and sends via Graph `/users/<sender>/sendMail`. `$global:PIM_MailSender` is the shared
from-mailbox; `$global:PIM_MailRedirectAllTo` routes every mail to one inbox for lab/test
visibility. Render is split from send (unit-testable).

**Who sends** (`Resolve-PimMailSendIdentity`). On a hosted environment (the platform exposes
`IDENTITY_ENDPOINT` / `MSI_ENDPOINT`) mail is sent as the host's **managed identity**, even when an
engine application is also configured, because the scoped Exchange `Application Mail.Send`
assignment (§7) is made for that identity; elsewhere it is the engine application's certificate
identity. A refused send is turned into a message that names the identity, the sender mailbox and
the exact grant to add (`Initialize-PimMailSender.ps1 -ManagedIdentityObjectId …` or
`-EngineAppId …`) — never advice to grant tenant-wide `Mail.Send`.

**Who receives mail about an admin account** (`Get-PimAdminMailRecipient`, shared by the engine
and the Manager so the admin screen's "Sends to" is exactly what the engine mails). An admin account
normally has no mailbox of its own, so its mail goes to the account **owner's office address**:

| Row state | Recipient |
|---|---|
| `ForwardMailsToContact = TRUE` and `MailForwardAddress` is a real address | `MailForwardAddress` |
| otherwise `ManagerEmail`, if it is a real address | `ManagerEmail` |
| otherwise | *(none)* — the caller refuses |

"A real address" is the shared `Test-PimMailForwardAddressIsReal` predicate: the schema's sentinel
values (`FALSE`, `no`, `0`, `none`, `n/a`, blank, `true`) are not addresses. The engine fires
**new-admin** (on account create), **tap-delivery** (with the TAP) and **offboarding-notice** to
that recipient, and the AD admin provider mails an on-premises admin's initial password the same
way (the password is never stored or logged). `Test-PimTapMailReady` refuses a pass issue — before
the existing pass is touched — when no valid recipient, no sender or no mail path exists. Where the
admin account does have a mailbox, the engine can also set Exchange forwarding to the owner's
address (off by default). Approval/escalation/lifecycle templates exist for the scheduler.

A single `Send-PimTemplatedMail -Type <type> -To <addr> -Tokens <hashtable>`
resolves custom-over-locked and routes through `$global:PIM_NotificationChannels`.
Mail-template types, token list, subject-line convention, and the
contacts/email-flow routing layer are detailed in §17.6 / §17.17.

**GUI mail-template editor — supported-tokens legend.** When an
operator edits a template in Settings → Mail templates, the editor renders a
**per-template** legend of the `{{token}}` placeholders that template type provides
at send time. The list is derived (`mailTemplateTokens` in `pim-manager.html`) from
the **shipped** body returned by `GET /api/mail-template?type=` (and any token
already in the effective body) — so it is factual per type, never an invented
superset; tokens the engine isn't given for that mail render empty. Each token is a
click-to-insert chip that drops `{{Token}}` at the caret of the body textarea. No
new endpoint — the editor's existing GET already returns the shipped body.

### 10.1 Notification batch (`PIM-Notifications.ps1`)

The §12 batch lives in `PIM-Notifications.ps1` (dot-sourced by `PIM-Functions.psm1`
and by `PIM-Notify.ps1`). Every function is a **pure transform** (events/rows/now →
tokens / decision / store record) with no network, so the whole batch is offline
unit-testable; the actual send is the existing channel layer, wired from the
scheduler handlers. All four honour the **two-approval model** — the engine notifies
on delegation/assignment lifecycle only and **never** sends an activation email.

1. **Daily summary** — `Get-PimDailySummary` folds audit events (the SQL audit trail,
   `pim.AuditEvents`, §17.11) over a 24-h window into new-admin / delegation / removal
   buckets; activation, `whatIf`, non-`ok`, and out-of-window events are dropped.
   `ConvertTo-PimDailySummaryTokens` produces the `daily-summary` template tokens.
   Scheduler job `daily-summary` (daily) reads the audit, renders, and sends to
   `$global:PIM_DigestRecipients`.
2. **Tier 0/1 report** — `Get-PimTierZeroOneReport` reduces assignment rows to the set
   of users holding T0/T1 (tier from an explicit field or a `T#` name marker), keeping
   each user's highest tier + the privilege levels seen. `ConvertTo-PimTierReportTokens`
   feeds the `tier-report` template. Scheduler job `tier-report` (daily).
3. **Approval escalation / reminders** — `Get-PimApprovalEscalationTargets` decides who
   to notify NOW for a pending *delegation* approval: **serial** steps one owner at a
   time (`owners[floor(elapsed/escalationHours)]`, clamped, `isEscalated` once past
   owner 0, idempotent via `lastNotifiedStep`); **parallel** notifies all owners at once
   (any-one approves) and re-fires as a reminder each interval. Reuses the existing
   `approval-request` / `approval-escalation` templates via `ConvertTo-PimEscalationTokens`.
4. **Secure ServiceNow → Manager intake** — inbound, store-and-forward, no internet-facing
   webhook: the external workflow drops a record into a one-way JSONL store; the Manager
   **polls** it (`Invoke-PimIntakePoll`, scheduler job `servicenow-intake`) when up, so it
   works even after downtime. `ConvertTo-PimIntakeRecord` sanitises to a fixed field
   allowlist (crafted extra fields dropped) and stamps `status=received`. Security gate
   `Test-PimIntakeAccepted` rejects activation requests (Entra-native) and self-targeting
   (no self-create / self-elevate). `Resolve-PimIntakeRouting` routes to `reject` /
   `approve` / `auto-apply` — **Tier 0/1 always `approve`**, and only an explicit
   allowlist of non-privileged types may `auto-apply` (secure default: allowlist empty →
   everything needs a human approve; activation is never auto-applied). The poll never
   mutates — the caller turns an `approve` into a `New-PimApprovalRequest` + mail and an
   `auto-apply` into a change-queue entry. Threat-model background in §17.15.

---

## 11. Hosting & runtime

Cheap, and **never reachable without authentication**. Two exposure shapes are supported and
chosen at deploy time (`Invoke-PimDeployAll -Exposure external|internal`, default `external` for
new deployments; §11.4):

- **External (default)** — the Manager is reachable over the internet, always behind Entra sign-in
  (Easy Auth), which the installation creates, enables and reads back before it completes. An
  optional allow-list (`-EasyAuthAllowedPrincipals`) assigns named people/groups and switches the
  app to *assignment required*. The container registry defaults to Basic.
- **Internal (private-only)** — the Manager is reachable only from the VNet and peered/GSA clients;
  SQL gets a private endpoint by default and the registry defaults to Premium (Basic has no network
  controls). Sign-in is still required.

An environment's exposure cannot be changed in place (it is a property of the Container Apps
environment); moving between them is a rebuild (`Rebuild-PimEnvExternal.ps1`, §27.7). The diagram
below is the **private-only** reference topology.

### 11.1 Single-tenant topology

```
   INTERNET ─────────────► ✖  private-only variant: no public endpoint (publicNetworkAccess = Disabled)

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

**Tenant reads in the hosted container (no PowerShell modules).** The container
image ships **zero** Graph/Az PowerShell modules — every tenant read/write goes
over REST via the shared token core (the same one the engine uses). The Manager
mints app-only Graph/ARM tokens from either the **engine SPN** (client id +
certificate thumbprint + tenant id, supplied as app settings) or the **container
managed identity** — with **no `-ConnectPlatform`, no bootstrap, and no
baseline-engine run** required first. The connect-context check accepts an SPN or
an MI directly (and fails closed when neither is present), so the tenant-backed
tabs (Active Assignments / Revoke, the tenant-list pickers, workload connectors,
conformance deploy) work the moment the app starts. The legacy SDK code paths
remain as a fallback for the local (on-box) edition where the modules exist.

**Active PIM assignments — a scheduled snapshot, read across three surfaces, with honest error
surfacing.** The live read takes minutes in a large tenant, so it never runs in the Manager's
request loop. Scheduler job `active-assignments-snapshot` (default every **120 min**, editable on the
Job schedule page; `PIM-ActiveAssignments.ps1`) performs the read and stores the result in SQL
`pim.TenantCache` kind `active-assignments` with its timestamp. **Review standing access**, the
revoke list and the Home expiring-access tile (`GET /api/active-assignments` →
`Get-PimActiveAssignmentsCached`) serve that stored snapshot instantly, showing "as of" and flagging
it stale when older than two cadences. **Refresh** queues an `active-assignments-snapshot` trigger
and asks for an immediate tick start (§11.3); a `queue-apply` run that applied revokes queues one
automatically, and a revoked row stays marked **revoke queued** until a snapshot no longer contains
it. Rows held by principals the directory no longer knows are hidden by default and listed on
request (with a filter for bulk revoke). The snapshot enumerates *active* PIM assignments from three
independent surfaces: **entra-role** (Graph `roleManagement/directory`
assignment schedules), **pim-for-groups** (Graph
`identityGovernance/privilegedAccess/group` assignment schedules, queried one
filtered request per PIM-prefixed group via `$batch`), and **azure-rbac** (ARM
`Microsoft.Authorization/roleAssignmentScheduleInstances` per visible
subscription). Each surface is read independently so one failing surface never
blanks the others. Crucially, a surface that **fails** (a 403 missing Graph
app-role, no Azure subscription scope, a transport error) is recorded in a
per-surface error ledger — it is **not** silently flattened to zero rows. The
endpoint distinguishes *"fetch succeeded → genuinely no active assignments"*
(`ok=true`, empty) from *"fetch failed → we could not read them"* (`ok=false` with
`surfaceErrors` + an actionable `error`). When a Graph surface 403s, the error
names the exact app-role to grant via `setup/Grant-PimGraphAppRoles.ps1`
(entra-role → `RoleManagement.Read.Directory`; pim-for-groups →
`PrivilegedAccess.Read.AzureADGroup`); when Azure RBAC can't be read, it asks for
**Reader** on the target subscription(s). The GUI's empty state renders that
actionable error instead of a misleading "cache may be empty — click Refresh",
so a permission gap is diagnosable from the screen rather than mistaken for an
empty tenant. (This corrected an earlier bug where every surface's failure was
swallowed and the endpoint returned a silent `ok=true,total=0`.)

**One Manager = one active SQL store.** A hosted Manager binds to a single SQL
database; on startup it defaults its active instance to that SQL store
(`sql:<database>`), never the contextless `local` config folder. The database
name is taken from `PIM_SqlDatabase` or parsed from the resolved connection
string / Key Vault pointer when only a full connection string is supplied.

**Tenant-list cache auto-populates in hosted mode.** The per-instance tenant
cache (Entra roles, AUs, PIM groups, Azure scopes, Azure RBAC roles — powering
the freshness badge + the autocomplete/dropdown pickers) is populated
automatically on hosted startup, and lazily on first read if auth came online
later — so a 24/7 container never needs a manual `-RefreshTenantLists`. It is
best-effort and non-fatal: if there is no usable tenant auth or Graph/ARM is
unreachable, the Manager still serves the SQL-backed configuration and the badge
shows the cache as not-yet-populated.

**Authoring tab — catalog-driven pickers, no free-text guessing.** Every
Authoring operation selects its group / role / tag / admin from REAL data rather
than a hand-typed string (a typo there silently stages a wrong or empty row).
The pickers are built by three pure (DOM-free) helpers off the data the Manager
already loads — no new endpoint:
- `collectAuthoringEntraRoles()` reads the live Entra-role tenant-list cache
  (`getCachedList('entraRoles')`), de-duped + sorted → the bulk-attach role
  **multi-select**.
- `collectKnownGroupTags()` (existing) feeds the bulk-attach **target GroupTag**
  and the move **To-tag** as pick-or-type comboboxes (a not-yet-created tag can
  still be typed).
- `collectKnownAdmins()` (union of `PIM-Assignments-Admins.Username` +
  `Account-Definitions-Admins.UserName`, plus same-session pending edits) feeds
  the move **Admin** select; `collectAdminAssignedTags(username)` scopes the
  move **From-tag** select to that admin's *current* assignments only.
The tab preloads the role tenant-list (`ensureTenantLists`) and the definition +
admin CSVs so no picker renders empty, then re-fills once the data lands. The
staging/commit path is unchanged — the dropdowns only constrain the inputs to
the same `/api/authoring/*` row-compute calls. Genuinely-free inputs stay free:
clone's new-tag values and the import-admins CSV paste box. The helpers being
pure lets the headless test (`tests/gui/authoring-dropdowns.test.js`) execute
them against a seeded catalog and assert the option lists without a browser.

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

**Method: a scheduler tick, with the engine as the only writer.** On the hosted (Container Apps)
topology the scheduler runs as a **Container Apps Job** (`ca-pim-tick` by default) started on a cron
(default every 5 minutes); each execution is one **tick** that decides what is due, runs it and exits.
It uses the same image as the Manager, its own system-assigned managed identity, and persists
schedules, last/next run, triggers and run history in SQL `pim.Settings`. A **SQL lease** guarantees
one tick at a time; a tick renews its lease while it works (so a long job keeps its turn) and stops
making changes if another run has taken the lease over. On a server/VM the same code runs as a timer
loop (`-IntervalSeconds`) or once per external cron start (`-Once`). The Manager never runs the
engine: on-demand actions come through the **Manager API** as queue entries and triggers that the
tick drains.

Implementation: `engine/_shared/PIM-Scheduler.ps1` (pure due-calc + handler
registry + tick + loop + on-demand triggers + change watermark) and the entrypoint
`tools/pim-scheduler/Start-PimScheduler.ps1` (runs on a VM *or* in a container,
REST-only). The job *logic* it drives already existed (`PIM-Lifecycle`,
`PIM-ChangeQueue`, `PIM-Approvals`).

Key semantics:
- **Phase-split delta** — one job per engine `-Scope` (admins, admin TAP, groups-assign,
  groups-deploy, policies, pim-entra, pim-azure, pim-azure-policies, pim-au, workloads,
  admin-offboarding), each with its own cadence, plus the daily `full-reconcile`, so routine
  convergence never needs a whole-tenant pass.
- **Scoped commit triggers** — a committed change arms one `engine-delta` trigger whose scope is
  only the providers that read the changed entities (§5.3), e.g.
  `trigger:engine-delta:AdminMembers,AzResPolicies,AzRes,GroupMembers`; unknown entities widen it to
  `All`. `engine-delta` is create/update only; `All` names the scope set, not a destructive mode.
- **Immediate start where permitted** — on a configuration commit, a queue commit and **Run now**
  the Manager asks Container Apps to start one execution of the tick job
  (`Start-PimManagerTickNow` → ARM `POST …/jobs/<tick>/start`; also `POST /api/scheduler/kick`,
  Admin-gated, audited `schedule.tick.start`). It is **conditional**: it needs the job's resource id
  (env `PIM_TickJobId` or `pim.Settings` `SchedulerTickJobId`) **and** the *Container Apps Jobs
  Operator* role for the Manager's managed identity, scoped to the tick job only. Without either it
  degrades to the next cron start and says so in the response. It never starts a second execution
  while a tick holds the lease, is debounced (45 s) so a multi-entity commit starts one execution,
  and never fails the commit.
- **In-tick pickup** — after each scheduled job a running tick repeats the cheap part of its start:
  the SQL change detector, a check for committed queue actions (`queue-apply`) and the trigger
  drain, so new work waits for the current job, not for the whole tick and the next cron start.
- **Queue actions between engine scopes** — inside a multi-scope engine job the engine calls
  `$global:PIM_BetweenScopesHook` after each scope; the tick sets it to apply newly committed queue
  actions (TAP re-issue, session revoke, revoke — each entry at most once per tick, never a nested
  engine run) and clears it when the tick ends.
- **Snapshot jobs** — `active-assignments-snapshot` (120 min) and `drift-snapshot` (240 min) perform
  the slow live reads and plans and store them in `pim.TenantCache` (§11.1, §5.2); the Manager only
  reads the stored rows, and a refresh is a queued trigger.
- **Discovery = 3 jobs** — `discovery` scoped to **Entra**, **Azure**, **PowerBI**.
  The scheduled sweep body is `Invoke-PimDiscoveryJobSweep` (`PIM-Discovery.ps1`):
  a pure, injectable core that (1) enumerates the live items for a scope, (2)
  reconciles them against the current definitions (`Get-PimAzureReconcilePlan` /
  `Get-PimPowerBiReconcilePlan`), (3) applies the handled-set **delta**
  (`Get-PimDiscoveryDelta`) so an item that was already proposed never reappears —
  the rolled-forward handled set persists per scope under
  `output/state/discovery-handled-<scope>.json` (`Get-`/`Save-PimDiscoveryHandledSet`),
  and (4) enqueues **only the fresh items** onto the same change queue `queue-apply`
  drains (auto-imports → Create, renames → Update). A scheduled run is
  **propose-don't-auto-map, never auto-delete**: it can only ever create empty
  permission-group containers (where an auto-import rule applies) and rename in
  place; orphans are *surfaced* in the result but **never removed** automatically
  (destructive deletes stay a deliberate human action). `-WhatIf` computes and
  reports but writes nothing (no enqueue, no handled-set write). The real handler is
  wired into the scheduler via `Register-PimDiscoveryHandler` (the launcher supplies
  the live-enumerator / existing-rows / enqueue seams); until it is wired, the
  `discovery` job degrades to a clearly-logged no-op rather than silently doing
  nothing. An `Entra`-scope job (built-in-role catalog) degrades to an explicit
  "scope not wired" no-op for now (the catalog-delta seam is separate).
- **Commit trigger** — a configuration commit (and the SQL change detector, for out-of-band
  writes) arms a scoped `engine-delta` trigger; a committed queue action is picked up by
  `queue-apply`. A change that is only *staged* in the browser triggers nothing.
- **Run now queues** — `POST /api/jobs/run` on any job whose real handler only the scheduler
  registers (`Get-PimTickOnlyJobTypes`: `engine-delta`, `engine-full`, `msp-pull`,
  `active-assignments-snapshot`, `drift-snapshot`, `verify-convergence`, `discovery`) persists a
  trigger (`pim.Settings` `SchedulerTriggers`, audited `schedule.job.run.queued`) and answers
  **202 queued**, then asks for an immediate tick start. A request made while a tick is busy is kept
  for its next drain.
- **VM + container** — same code; `-IntervalSeconds` / `$env:PIM_SCHED_INTERVAL`,
  `-Once` for an external cron, single-runner SQL lease.

| Job | Trigger | How |
|---|---|---|
| Manager GUI / API (interactive; **commit to queue**) | **on-demand** | the Manager container (HTTP); never runs the engine |
| **Apply** change queue (`queue-apply`: revoke, TAP re-issue, session revoke) | on commit (in-tick pickup + between engine scopes) **+** scheduled sweep | scheduler tick |
| Engine **Delta** run (changed rows / scoped trigger) | scheduled (per-scope cadence) **+** commit trigger | scheduler tick |
| Engine **Full** run (whole-tenant reconcile) | scheduled (daily) | scheduler tick |
| **Snapshots** (active assignments 120 min, drift 240 min) | scheduled **+** queued refresh | scheduler tick → `pim.TenantCache` |
| **Verify convergence** (live vs desired, writes nothing) | scheduled (30 min) | scheduler tick |
| **MSP pull** (templates MSP→local, by ring) | scheduled **+** on-demand | local scheduler pulls from the MSP store |
| **Reminders** (upcoming expirations / renewals) | scheduled (12 h) | scheduler → templated mail |
| **Escalations** (approvals aging past SLA) | scheduled (hourly) | scheduler → next approver layer + mail |
| **Connectors** (workload role discover/apply) | invoked *by* the engine runs | in-process via PIM-Rest (not a separate scheduler) |
| Azure / Entra / Power BI discovery | scheduled (daily) | scheduler tick |
| **Update** (fetch approved version → build → schema → roll → verify → rollback) | **nightly, per environment, by release ring** | **NOT the engine/scheduler.** A separate Container Apps Job (`ca-pim-update` by default) rolls the environment over ARM; a host-side `Invoke-PimUpdate.ps1` run obeys the same ring. See §11.6.0. |

**Why not the alternatives (each breaks a constraint):**
- **Azure Functions** — reaching the *private* SQL needs VNet integration = the
  Premium (EP) plan = expensive, plus cold starts and another component with its
  own deps. Fails "cheap" + "no fragile deps".
- **Updates are not a scheduler job.** The tick never updates code, schema or the Manager: a
  container cannot safely roll the environment it runs in. Hosted environments update through their
  own **in-cloud nightly updater** job, which moves only to the version the environment's release
  ring approves, builds that version in the environment's own registry, brings the schema up to date
  first, rolls every component running the product, verifies and rolls back (§11.6.0). That job
  needs a published source feed (a read-only link to the approved version's source archive and the
  ring channel). A **community** installation from the public repository has no such feed: it
  updates by `git pull` and re-running the idempotent one-shot deploy (§11.6, §11.7).
- **Webhooks** — inbound, event-driven; a *trigger*, not a scheduler. (One private
  webhook on the manager can optionally let an external system request an
  on-demand apply — not the core mechanism.)
- **Logic Apps** — Consumption can't reach private endpoints; Standard (VNet) is
  expensive. Fails "cheap" + "private-only".
- **App Service WebJobs** — Windows-only; we run a **Linux** container.

**Optional external scheduler (fallback, not default):** the same engine
entrypoints can be invoked by a **cron / scheduled task on the management VM** or
an **Azure Automation runbook** for shops that prefer scheduling outside the app.

### 11.3a Run history + the Manager Jobs tab (read model)

So an operator can *see* what the scheduler is doing, the tick persists a bounded
**run-history ring** alongside the existing scheduler state. Each scheduled or
triggered run is recorded by `Write-PimJobRunRecord` → `Add-PimJobRunRecord` as a
record `{ runId, name, type, scope, ok, ran, status(running|completed|failed),
detail, startedUtc, finishedUtc, durationMs, log }`. The summary log is synthesised from the
dispatch result (`detail` + the handler's inner `ran`/`whatIf`/`detail` and any
`log` lines) by `ConvertTo-PimRunLogText`. History persists in SQL `pim.Settings`
(`JobRunHistory`, a compact single-encoded array; no file) — so the **Manager and scheduler
processes share it**; an in-memory copy serves only a process with no store (offline tests). The
ring is trimmed to the **10 most recent runs per job** (`$script:PimRunHistoryMax`), because the
whole ring is one setting rewritten on every run and a larger ring measurably slowed every save on a
small database tier; full engine output lives in the per-run output below and in Log Analytics.

**The run's own output** (`Save-PimJobRunOutput` / `Get-PimJobRunOutput`). `Invoke-PimScheduledJob`
captures everything the handler prints (host lines, warnings, errors) and stores it per job name in
`pim.Settings` `JobRunOutput:<job>`: the newest **3** runs, each capped (first 200 + last 1,800 lines,
long lines truncated). While a run is still going the capture is **flushed every 30 s**, so the Logs
view's live tail shows progress. `Get-PimJobRunLog` returns the summary followed by that output.
Echoing the captured output back to the console can never fail a run: only valid console colours are
re-emitted (`Test-PimConsoleColorValue`), because a container console has none.

`Get-PimJobsStatus` is the GUI view model: one row per configured job, joined to its
latest run and the persisted last/next-run state. **In-progress runs** (a `running`
record with no `finishedUtc`) sort to the **top**; the rest follow by most-recent
activity. Each row carries cadence (`Format-PimCadence`), enabled state, last
run/result/ok, next run, and the `runId`s the GUI needs for the log button.

The Manager surfaces this via these endpoints in `Open-PimManager.ps1`
(it dot-sources `PIM-Scheduler.ps1` and reads the same `pim.Settings` values through
`Get-PimSetting`):
- `GET /api/jobs` → `Get-PimJobsStatus` over the **effective schedule**
  (`Get-PimManagerEffectiveSchedule` = default catalog + stored per-job
  enabled/cadence overrides), so inline edits show up immediately. The response
  also carries `historyCount` (0 ⇒ the GUI shows an explicit "no runs yet" banner)
  and `canRun` (Admin+ ⇒ the per-row controls are live).
- `GET /api/jobs/log?runId=` → `Get-PimJobRunLog` (one run's log; 400 without
  `runId`, 404 for an unknown one).
- `PUT /api/jobs/state` (Admin+) → enable/disable a job and/or change its cadence.
  Persists the **full** override set to the `JobSchedule` store
  (`Set-PimManagerSetting` + `$global:PIM_JobSchedule` mirror) — the same store the
  real scheduler reads via `Get-PimJobSchedule`, so the in-process runner and a
  freshly-booted scheduler both honour it. Unknown job names → 404 (fixed catalog).
- `POST /api/jobs/run` (Admin+) → "Run now". For every scheduler-only job type (engine jobs,
  snapshots, convergence check, discovery; §11.3) it **queues** a trigger for the tick, answers
  `202` with the queued state and requests an immediate tick start — the web process never runs the
  engine. For the remaining light job types `Invoke-PimJobForceStart` writes an in-progress
  placeholder, dispatches the handler registered in the Manager, and replaces the placeholder with the
  finished record **under the same `runId`**.
- `GET /api/engine-failures` → every item the engine failed to apply on the last run of each scope,
  from the failure store (`pim.Settings` `EngineItemFailures`) classified by
  `engine/_shared/PIM-FailureCatalog.ps1`; `GET/POST /api/engine/policy-hold` · `policy-approve`
  (and the Azure-resource pair) read and approve a held policy plan (§17.7).

**Dead-view fix.** A job with no run-history record AND no persisted `lastRunUtc` is
flagged `neverRun=true` and gets a **synthesized** `nextRunUtc` (now + cadence,
`nextRunSynthesized=true`) so the row shows "next run <t>" instead of a blank "—" for
both last and next. This is the normal state before the scheduler has ticked (or when
its history isn't co-located with the Manager); the tab no longer looks dead.

**Failure history, overdue detection + acknowledge.** Three pure cores extend
the read model without a new scheduler:
- `Get-PimRunFailureHistory` (and the store-backed `Get-PimJobFailureHistory`) returns
  a job's recent **finished** runs newest-first with a normalised `{ok; failed; status;
  startedUtc; …; acknowledged}` shape and the failed subset surfaced — so an admin sees
  whether failures are a one-off or a pattern. Surfaced at `GET /api/jobs/history?name=&take=`.
- `Get-PimJobOverdueState` decides per-job whether the job **missed its fire window**:
  it compares `now` against the **expected** fire time (the persisted `nextRunUtc`, else
  last-run + interval) plus a grace margin (`max(1 cadence, 5 min)`). It returns *not
  overdue* for a fresh, running, disabled, on-demand (interval ≤ 0) or **never-run** job —
  a never-fired job is distinct from an overdue one. `Get-PimJobsStatus` joins this onto
  every row (`overdue`/`overdueByMinutes`/`expectedRunUtc`) and adds `overdueCount` +
  `failingCount` summaries. A job counts as **failing** only while it has a **standing**
  unacknowledged failure: failures followed by a completed clean run are **recovered**
  (`recoveredFailureCount`, shown as "failed earlier, recovered" and listed under History), and a
  next-run time that the job's own last run has already passed is recomputed rather than reported
  overdue. Because the
  Manager drives the read model with the *effective* schedule (which carries no run
  stamps), `Get-PimJobsStatus` falls back to the **persisted scheduler-state** stamps by
  job name for the last/next-run basis.
- **Acknowledge/clear** mutes a known failure without losing the record: a bounded set of
  acknowledged `runId`s persists in `pim.Settings 'JobAcknowledgements'`.
  `Set-PimRunAcknowledged` (idempotent, `-Clear` to un-ack) is exposed at
  `POST /api/jobs/ack {runId; clear?}` (Admin+, audited); **Ack** in the GUI clears every standing
  failure of the job at once (`unackedFailureRunIds`). An acknowledged run still appears in history
  (audit intact); only its failure/overdue **signal** is suppressed.

**Three Jobs pages** (`pim-manager.html`):
- **Jobs & status** (`renderJobs()`) — in-progress jobs first, a top **"needs attention"** banner
  (overdue/failing counts), an overdue badge + recent-failure count per row, a **History** modal
  (recent runs with pass/fail/when, each linking to its log), a per-row **Logs** modal with a
  **live tail** that re-polls an in-progress run's log every 2 s (auto-scrolling) until it finishes,
  and for Admin+ an **enabled** toggle, an inline **cadence** editor (`PUT /api/jobs/state`), **Run
  now** and **Ack**. Never-run rows show "no runs yet" with a computed next-run.
- **Engine logs & errors** — every recent run across all jobs (failures-only filter), each run's
  full log one click away, and a **Failing now** section built from `/api/engine-failures`: each
  failing item named in domain terms (group, role, scope, assignment type, or the policy and its
  template — never an empty group or an object id), grouped **by cause** with what to do, how long
  and for how many runs it has failed, and a portal link to the scope's PIM settings. Where the row
  itself is the problem the item offers a **one-click fix** (e.g. remove the row, make it Eligible)
  that is staged into Pending changes (§18.1f), never applied directly. A held policy plan is shown
  here with its counts and can be approved (§17.7).
- **Job schedule** — which job runs when, the area (scope) each covers, the mail jobs and their
  on/off state and cadence, visible by default with a plain-language explanation of every column.

`tools/pim-scheduler/Seed-PimSchedulerRuns.ps1` writes a representative state + history (incl. one
in-progress run) so the pages are also pre-populated in a fresh/offline environment.

![Engine logs & errors — failures grouped by cause, and a run's own log output](img/manager-jobs-logs.png)
*Engine logs & errors: failing items grouped by cause with a one-click fix, and a run's own output in the log view. (Synthetic demo data.)*

> PS 5.1 note: history is read via `$tmp = $raw | ConvertFrom-Json; @($tmp)` — wrapping
> the pipeline directly (`@(... | ConvertFrom-Json)`) collapses a JSON array into a
> single element on Windows PowerShell.

### 11.4 Setup / deploy family — one script per hosting shape

Deployment runs through a small, idempotent, re-runnable script family (no manual
portal steps), all sharing one helper library so the hard-won lessons live in one
place:

- **Containers** — stands up the internal Azure Container Apps environment, the
  config-driven worker matrix (one parameterised image; an env var selects which job
  types each worker runs), the managed-identity → SQL contained-DB-user grants
  (mapped by the MI's *appId*, not objectId), the registry pull identity, the engine
  directory app-roles (the engine set for the tick job, the read-only set for the Manager; §7), and
  the Manager DNS record. The web Manager always uses `--ingress external`: on an **external**
  environment (the default for new deployments) that is an internet-reachable endpoint behind Easy
  Auth sign-in; on an **internal-only** environment it is a static **private** IP, the one ingress
  reachable from peered/hub-VNet clients. Either way no request reaches the Manager unauthenticated.
  Workers deploy via a YAML spec (not multi-token CLI args). It also asserts the
  hosted SQL is **persistent** (serverless auto-pause disabled) so neither the health
  probe nor the first post-idle request cold-starts.
- **VM** — runs the Manager + scheduler natively on a Windows VM as two restart-on-fail
  scheduled tasks under a service account, sets the machine environment, opens the
  firewall port, and (optionally) grants the VM's managed identity as a SQL
  contained-DB-user — same MI-only, passwordless model as the container path.
- **MSP** — deploys the container topology into the customer tenant, **imports the
  centrally-built image into the customer registry** (build-once / import-per-customer;
  the identity, SQL, license and config all stay local), and wires the ring-based
  **pull-not-push** template sync onto the customer scheduler.
- **Engine app registration** — a REST + certificate installer (no PowerShell Graph/Az
  modules required) that creates/updates the engine app + service principal, issues or
  reuses a self-signed certificate in the machine store, grants the engine Graph roles
  + (optionally) Exchange app-only + Azure RBAC at the management-group root, and
  writes the resolved identity into the engine launcher config.

**Shared deploy library.** Every script prints a version banner (PowerShell / .NET /
Azure CLI) up front, **refuses any region outside its EU allow-list** (West Europe, Denmark East,
Sweden Central; France is explicitly denied for data residency), and
ends by printing **exactly which DNS and private-link zones to add** for Entra Global
Secure Access (Private Access) so cloud-only users reach the internal Manager without
a VPN — the SQL `database.windows.net` zone, the App Service `azurewebsites.net` zone,
the storage `blob.core.windows.net` and Key Vault `vaultcore.azure.net` zones, the
GSA Private-Access app definition, and the conditional-forwarder needed when on-prem
domain controllers are the VNet DNS. No real tenant, subscription, registry, SQL or
customer values are baked into the scripts — every environment value is a parameter.

### 11.5 Install & implementation guide (community + subscription)

PIM4EntraPS deploys in one of **two modes**. They share one engine (REST-only,
no PowerShell modules), one SQL data model, and one identity model: **managed identity**
where the engine is hosted in Azure, an **engine application authenticating with a
certificate** elsewhere (§7, §27) — never device-code; a client secret only where a platform
requires one (the Easy Auth sign-in registration). The mode only changes *where it runs* and
*how it is wired up*.

| | Community mode (S2, this edition) | Subscription mode |
|---|---|---|
| Audience | Running it for your own tenant, installed and updated from GitHub | A hosted platform delivered and kept current by the maintainer (single-tenant or MSP) |
| Code source | Your clone of the public repository, updated with `git pull` | The maintainer's release channel |
| Host | Azure Container Apps in **your** subscription: a scale-to-zero Manager + one scheduled engine job | The same shape, plus the in-cloud nightly updater (§11.6.0) |
| Identity | Container **managed identities** for the engine and Manager; a certificate-based **deploy identity** for installs and updates | The same; an engine application only where a tenant must be crossed (S5) |
| Store | Azure SQL, managed-identity contained users only | Azure SQL, managed-identity contained users only |
| Manager auth | Easy Auth (Entra) sign-in, always on; external ingress by default, private-only optional | The same |
| Updates | `git pull` + re-run the one-shot deploy (a re-run **is** the updater) | Release rings + in-cloud updater (§11.6.0) |
> **Real environment values never live in the published docs.** This guide uses
> **placeholders** (`<tenant-id>`, `<sub-id>`, `<rg>`, `<acr>`, `<server>`,
> `<kv>`, …) throughout. The actual tenant / subscription / resource-group / Key
> Vault / SQL server / engine-SPN values for a given deployment live only in
> your own gitignored configuration (the `*.custom.*` files that never enter git)
> or in your Key Vault — never in README / DESIGN / FEATURES.

#### 11.5.0 Shared prerequisites (both modes)

1. **PowerShell 5.1** on the management host (PS7 also works; the engine and
   setup scripts are 5.1-safe). The hosted container ships its own runtime.
2. **Engine app registration (SPN) + certificate.** Run the one-shot installer
   from a host authenticated as Global Administrator / Privileged Role
   Administrator:

   ```powershell
   az login
   .\tools\setup\Install-PimEngineAppRegistration.ps1 `
       -DisplayName "PIM4EntraPS Engine" -GrantConsent
   ```

   It is **pure REST + certificate** (no Graph/Az PowerShell modules, no
   device-code — which managed Conditional Access blocks). It mints (or reuses,
   to avoid orphaned-cert drift) a self-signed cert in `Cert:\LocalMachine\My`,
   creates/updates the app + service principal with the engine Graph app-roles
   (`RoleEligibilitySchedule.ReadWrite.Directory`, `RoleAssignmentSchedule.ReadWrite.Directory`,
   `Group.ReadWrite.All`, `User.ReadWrite.All`, `Directory.Read.All`,
   `AdministrativeUnit.ReadWrite.All`, `PrivilegedAccess.ReadWrite.AzureADGroup`,
   `RoleManagementPolicy.ReadWrite.Directory`, `UserAuthenticationMethod.ReadWrite.All`,
   `Policy.Read.All`, `Domain.Read.All` — no Graph `Mail.Send`; sending is a scoped Exchange
   assignment, §7), optionally Exchange `Exchange.ManageAsApp`, assigns **User Access
   Administrator** at the root management group for Azure RBAC (to the runtime managed identity
   when `-RuntimeMiObjectId` is given, which is the hosted case), and writes the
   resolved tenant id / client id / cert thumbprint into the launcher config.
   Add `-IncludeExchange` if the engine must set mailbox forwarding on new admin
   accounts. *(A deprecated shim at `setup/Install-PimEngineAppRegistration.ps1`
   forwards to this script for backward compatibility — use the `tools/setup/`
   one for new work.)*
3. **A SQL store for the model.** **Azure SQL** (Entra/managed-identity auth
   only — SQL logins disabled) is the single authoritative store in *every*
   mode and for break-glass. A file-based installation is brought in once with the
   one-time import (§5.3).

The engine entrypoint (`tools/pim-engine/Invoke-PimEngineCore.ps1
-Scope All|<name> -Mode Full|Delta`) reads its identity + SQL coordinates from
env / launcher globals: `PIM_TenantId`, `PIM_ClientId`, `PIM_CertThumbprint`,
`PIM_SqlServer` (FQDN for Azure SQL, or a local instance), `PIM_SqlDatabase`.
With no client id present and an MI available, auth falls back to managed
identity.

#### 11.5.1 Community mode (S2) — full deploy

The community edition installs the **same hosted shape** as a subscription environment,
from your clone, with one command. The steps below are the ones proven end to end from a
freshly staged copy of the public repository into an empty tenant.

**Host:** Windows with PowerShell 7 (elevated — the deploy identity's certificate is placed in
`Cert:\LocalMachine\My`), Azure CLI and git. **Sign-in for step 2 only:** Global Administrator
(or Privileged Role Administrator + Application Administrator) and Owner of the subscription.

1. **Get the code.**

   ```powershell
   git clone https://github.com/KnudsenMorten/PIM4EntraPS.git
   cd PIM4EntraPS
   ```

   The repository is the solution folder at its own root. The image build detects this
   layout and stages the build context itself (it recreates the path the Dockerfile
   copies, carries only committed files, and never includes `*.custom.*` files, licences,
   keys or caches).

2. **Create the deploy identity.**

   ```powershell
   az login --tenant <tenant-id>
   az account set --subscription <sub-id>
   $id = .\tools\setup\New-PimDeployIdentity.ps1 -TenantId <tenant-id> -SubscriptionId <sub-id> -GrantGraph -Apply
   ```

   An app registration with a **certificate** (never a secret), **Owner** on the
   subscription, and — with `-GrantGraph` — the three Microsoft Graph application roles the
   deploy itself calls: `Directory.Read.All` (resolve the managed identities),
   `AppRoleAssignment.ReadWrite.All` (grant them their Graph roles) and
   `Application.Read.All`. Owner is an Azure role and grants nothing in Graph, which is why the
   Graph roles are explicit. The script retries through directory replication, proves the
   identity signs in and can read the directory, and is idempotent.

3. **Deploy everything** (`Invoke-PimDeployAll.ps1`, §11.7). Run without `-Apply` first to
   print the plan.

   ```powershell
   .\tools\setup\Invoke-PimDeployAll.ps1 -Scenario S2 -Apply `
       -TenantId <tenant-id> -SubscriptionId <sub-id> -Location swedencentral `
       -AdminAppId $id.AppId -AdminCertPem $id.PemPath `
       -SqlAdminClientId $id.AppId -SqlAdminCertThumbprint $id.Thumbprint `
       -PrereqToken <short> -PrereqVnetAddressPrefix <10.x.y.0/22> -PrereqSubnetAddressPrefix <10.x.y.0/23> `
       -ResourceGroup <rg> -VnetName <vnet> -VnetResourceGroup <rg> `
       -AcrName <acr> -EnvName cae-pim -LogAnalyticsWorkspaceName <law> `
       -SqlServerFqdn <server>.database.windows.net -SqlDatabase PimPlatform `
       -SqlConnectionString 'Server=tcp:<server>.database.windows.net,1433;Initial Catalog=PimPlatform;Encrypt=True;TrustServerCertificate=False;Connection Timeout=60;' `
       -Exposure external -WorkerMode cron -ManagerMinReplicas 0 -AcrSku Basic `
       -ManagerSuperAdmins <upn> -SkipAppReg
   ```

   `-SkipAppReg`: the hosted engine uses its container's managed identity, so no separate
   engine application is needed. The **updater** step is skipped automatically for S2/S4
   without a published release feed — it reports how to update instead of failing (§11.6.2).
   Optional: `-EasyAuthAllowedPrincipals` (assignment-required sign-in), `-Exposure internal`
   (immutable once the environment exists), `-AzureRbacRoles 'User Access Administrator'`,
   `-MailSender`.

4. **Verify.** Open the Manager address the deploy prints and sign in: the header shows the
   SQL store and the deployed version; **Jobs › Engine logs & errors** shows the engine job's
   runs completing; **Support › Run checks** is green. The repository's automated live smoke
   and deploy-validation suites are maintainer tools and are not part of the public
   repository, so the deploy's own verify step reports them as *unverified* — never as a
   failure, and never as a reason to roll back.

A `-Descriptor` file is part of the maintainer's framework and is not used by the community
edition; pass the values as parameters as shown.
#### 11.5.2 Internal mode — full deploy (setup-script family)

The setup scripts are **idempotent, re-runnable, parameter-driven** (no portal
clicking), share one helper library (`tools/setup/_PimSetupShared.ps1`), print a
version banner, and **refuse any region outside the EU allow-list** (West Europe, Denmark East,
Sweden Central).

**A. App registration** — §11.5.0 step 2 (`Install-PimEngineAppRegistration.ps1`).

**B. Containers (primary path) — `Setup-PimContainers.ps1`.** Stands up an
**internal-only, workload-profile Azure Container Apps environment** in a spoke
VNet peered to the hub, and the **config-driven worker matrix** (one
parameterised image; an env var picks which job types each worker runs —
manager, scheduler, engine-delta/full, connector, delta-queue, discovery):

```powershell
.\tools\setup\Setup-PimContainers.ps1 `
    -SubscriptionId <sub-id> -TenantId <tenant-id> -Location westeurope `
    -ResourceGroup <rg> -VnetName <vnet> -VnetResourceGroup <vnet-rg> `
    -SubnetName snet-pim-aca -EnvName cae-pim `
    -AcrName <acr> -ImageRepo pim-manager -ImageTag <tag> `
    -SqlServerFqdn <server>.database.windows.net -SqlDatabase PimPlatform `
    -SqlAdminClientId <aad-admin-spn> -SqlAdminClientSecret <secret> `
    -DnsServer <ad-dns-host>
```

What it wires:
- **`--ingress external`** → on an **external** environment (the default) the Manager is
  internet-reachable behind Easy Auth sign-in; on an **internal-only** environment it gets a
  **private static IP** — the one ingress reachable from peered/hub/GSA clients.
  (`--ingress internal` is app-to-app only and would be unreachable from VNet clients — a
  multi-hour lesson baked into the script.)
- **MI-only SQL** (`Grant-PimMiSql`): each worker's system-assigned managed
  identity becomes a **contained DB user**, with the SID derived from the MI's
  **appId** (not objectId), `TYPE=E`, `db_datareader`/`datawriter`/`ddladmin`.
  The supplied `-SqlAdminClientId/-Secret` AAD-admin SPN is used **only** to
  create those users and is never stored in the apps. No SQL login, no
  Directory-Reader requirement.
- **AcrPull** — after first create, each app pulls its image via its own managed
  identity (no registry credentials at update time).
- **Engine Graph app-roles** on the workers that touch Entra/PIM (`Grant-PimMiGraph`).
- **Persistent SQL** — disables serverless auto-pause so neither `/health` nor the
  first post-idle request cold-starts (skip with `-SkipPersistentSqlCheck`).
- **DNS** — registers the Manager FQDN → the env's static private IP on
  `-DnsServer`, and prints the **GSA / private-link** checklist (next paragraph).

**C. VM host (alternative) — `Setup-PimVM.ps1`.** Runs the Manager + scheduler
natively on a Windows VM as two restart-on-fail scheduled tasks under a service
account, sets the machine environment (`PIM_HOSTED=1`, `PIM_StorageBackend=sql`,
SQL coordinates, `PIM_UseManagedIdentity=1` for the VM IMDS MI), opens the
firewall port, and (with `-GrantSql -VmMiAppId … -SqlAdminClientId/-Secret`)
grants the VM's MI as a contained DB user — the same passwordless model as the
container path. Reachable directly on its IP:port from hub/peered/GSA clients —
no ACA ingress quirks.

```powershell
.\tools\setup\Setup-PimVM.ps1 `
    -SqlServerFqdn <server>.database.windows.net -SqlDatabase PimPlatform `
    -TenantId <tenant-id> -Port 8080
```

**D. MSP (per customer) — `Setup-PimMsp.ps1`.** Deploys the container topology
**into the customer tenant** (it calls `Setup-PimContainers.ps1`), **imports the
centrally-built image into the customer registry** (`az acr import`,
build-once / import-per-customer; skip with `-SkipAcrImport`), and wires the
ring-based **pull-not-push** template sync (the customer scheduler pulls only its
ring's template rows from the MSP template DB — `-MspTemplateConn` stored as a
container secret, `-Ring canary|broad|stable`). Identity, SQL, license and config
all stay local to the customer; customer data never leaves the customer tenant.

```powershell
.\tools\setup\Setup-PimMsp.ps1 -CustomerName <slug> `
    -SubscriptionId <sub-id> -TenantId <customer-tenant-id> -Location westeurope `
    -ResourceGroup <rg> -VnetName <vnet> -VnetResourceGroup <vnet-rg> `
    -AcrName <customer-acr> -ImageRepo pim-manager -ImageTag <tag> `
    -SqlServerFqdn <customer-server>.database.windows.net -SqlDatabase PimPlatform `
    -SqlAdminClientId <aad-admin-spn> -SqlAdminClientSecret <secret> `
    -MspTemplateConn "<read-only conn string to MSP template DB>" -Ring stable
```

**E. Identity & access (Easy Auth, always; private-only optional).** The Manager is always
behind **Easy Auth** (Entra interactive sign-in): the deploy's `easyauth` step creates (or reuses)
the sign-in registration, wires it to the app, turns authentication on and **reads the
configuration back**, failing the deploy rather than completing with an unprotected console. An
optional `-EasyAuthAllowedPrincipals` list assigns the named users/groups, verifies the assignments,
and only then sets *assignment required*, so the order can never lock everyone out; without it the
deploy states that anyone in the organisation can open the Manager. For a **private-only**
deployment additionally keep public network access disabled, the private endpoint inbound only,
and inbound access restricted to the management / PAW / SAW subnets (the defense-in-depth layers of
§11.1). The authenticated principal maps to Reader / Admin / SuperAdmin / Delegated (`ManagerAccess`
in `pim.Settings`, §17.12); unknown principals fail closed to Reader.

**The hosted Manager VERIFIES that principal — it does not simply trust the
header** (`engine/_shared/PIM-HostedAuth.ps1`, added 2026-08-05). Two layers:

- **Layer 1 — edge consistency (always on).** A genuine auth edge injects
  `X-MS-CLIENT-PRINCIPAL-NAME` *and* the `X-MS-CLIENT-PRINCIPAL` claims blob
  together and consistently. A name header arriving **without** the companion
  blob, with a blob that is not valid base64/JSON, or with a blob whose name
  **disagrees** with the header, is a spoof signature a working edge can never
  produce → rejected, caller treated as unauthenticated. This layer cannot lock
  out a correctly-fronted deployment.
- **Layer 2 — signed token (opt-in, `PIM_HOSTED_REQUIRE_SIGNED_TOKEN=1`).**
  `X-MS-TOKEN-AAD-ID-TOKEN` is verified properly — RS256 signature against the
  tenant JWKS (fetched and cached hourly), plus issuer, audience, `exp`/`nbf`
  — and identity is taken from the **verified token**, not from any header.
  `alg:none` and HMAC alg-confusion are refused; a missing token or an
  unavailable JWKS **fails closed**. Opt-in because it requires the auth edge to
  store tokens; enabling it without that would lock the Manager out.

Be precise about what each layer buys: the `X-MS-CLIENT-PRINCIPAL*` headers
carry no signature and **cannot** be cryptographically verified by the app —
they are trustworthy only because the edge strips inbound copies. Layer 1
therefore blocks spoofing but still *assumes* the edge is in front. Layer 2 is
what makes spoofing cryptographically impossible. The Manager prints which layer
is active at startup (`[auth] posture=edge-consistency|signed-token|local`).

**`GET /` requires a trusted principal in hosted mode.** The SPA page embeds the
`/api` bearer token in its HTML, so serving it unauthenticated made that token
public — the token was never an independent second factor, and two requests
(`GET /` for the token, then any `/api` call with a forged principal header)
reached SuperAdmin. `/health` stays unauthenticated by design so the platform
liveness probe is unaffected. Local/loopback mode is unchanged: identity is the
Windows user and the listener binds to loopback.

**A swallowed error on a decision path is reported, not erased**
(`engine/_shared/PIM-Swallow.ps1`, added 2026-08-05). Much of the codebase
deliberately does not rethrow: an audit-write failure must not undo the approval
it was recording, and a `Dispose()` failure must not change an auth verdict.
That is correct — the problem was that the error then left no trace, so a
decision taken on **fallback data** was indistinguishable from the same decision
taken on real data. `Write-PimSwallowed -Scope -Consequence -ErrorRecord` writes
one line to the host and the warning stream and appends to a bounded (200-entry)
in-process ring readable via `Get-PimSwallowedErrors`. It never throws and never
alters control flow — the caller's fallback runs exactly as before; this is
observability, not behaviour. `-Consequence` carries the operator-useful half:
*"falling back to built-in defaults, so a persisted toggle is NOT in effect this
run"* rather than a stack trace.

It is wired to **decision paths only** — feature-gate and edition store reads,
the approval store's reads/writes/audit events, the disable-abort alert
(the disable breaker's own signal), and the Manager's pre-PUT portal-scope row read — never
swept across all 218 `catch {}` sites, because a warning on every best-effort
nicety is how real warnings get ignored. In the two multi-channel readers
(`Get-PimFeatureStoreValue`, `Get-PimApprovalRequests`) a throw is **remembered,
not reported**: falling through to a channel that works is normal and stays
silent, and it reports only when the whole chain then yields nothing — the one
case where the caller silently proceeds on fallback data. Gate:
`tests/Test-PimSwallow.ps1` (41), which asserts both the reporting and that no
fallback moved.

**F. DNS / GSA / private-link.** Each setup script ends by printing **exactly
which zones to add** so cloud-only admins reach the internal Manager without a
VPN, via **Entra Global Secure Access (Private Access)**: the SQL
`privatelink.database.windows.net` zone, the App Service
`privatelink.azurewebsites.net` zone, the storage
`privatelink.blob.core.windows.net` and Key Vault `privatelink.vaultcore.azure.net`
zones, the GSA Private-Access app definition, and the **conditional forwarder**
needed when on-prem domain controllers are the VNet DNS (a custom-DNS VNet does
not resolve the Azure `privatelink.*` zones — forward `database.windows.net` /
`azurewebsites.net` to `168.63.129.16`). For the ACA internal env the Manager is
a **static private IP** behind an AD DNS A record (registered by `-DnsServer`),
not a privatelink zone.

#### 11.5.3 Verify the deploy

- **Community / VM:** the engine prints a tagged per-row log (assign / update /
  extend / remove / OK) and a transcript under `logs/`; a `-WhatIf` re-run should
  show all `NoAction`. The Manager serves the model from SQL.
- **Hosted:** the **hosted smoke** (`tests/live/Test-PimManagerHostedSmoke.ps1`)
  is the release gate — render mode = **SQL** (not static/read-only),
  `GET /api/active-assignments` = **200**, tenant cache populated, GUI read-write
  for admin, store = SQL, startup resolves the SQL instance. `/health` is
  unauthenticated, stays **200** through a transient SQL blip, and only returns
  **503** on a sustained outage.
- **First-time deploy-validation** (`tests/live/PIM.DeployValidation.Tests.ps1`)
  reads the desired set straight from SQL and confirms every group, AU, role
  assignment, admin delegation and approval policy was actually created in the
  live tenant.

### 11.6 Update lifecycle runbook

Updates run through a single, controlled lifecycle so a running deployment can be
kept on the **latest released** engine/Manager/schema **without** an open "always
take whatever is newest" risk. The flow is the same shape in both modes —
**detect → build → deploy → verify → notify → ensure-monitor** — and the risky
decisions live in a **pure, unit-tested core** (`engine/_shared/PIM-SyncAutomateIT.ps1`);
the orchestrator only gathers facts and acts on the plan the core returns.

> **Two entry points, one lifecycle.** A hosted environment updates itself through its
> **in-cloud nightly updater** (a Container Apps Job, gated by its release ring — §11.6.0).
> **`Invoke-PimUpdate.ps1`** is the **standalone host-side** entry for the same flow, and it
> obeys the same ring. Either way the update is **separate from the PIM engine and the job
> scheduler**: the engine + scheduler run engine jobs and the managed-tenant data downlink only;
> they never trigger or run a code/schema/GUI update. The host-side entry is invoked
> **out-of-band** — by VisualCron / Task Scheduler
> (`tools/setup/Register-PimSyncSchedule.ps1`), or fired automatically by the bootstrap
> **post-sync deploy hook** (`sync/_SyncDeploy.ps1`) after a `sync-automateit` pull.
> Its building blocks: `tools/setup/Build-PimManagerImage.ps1` (build the image from the
> pulled code), `tools/setup/Invoke-PimSyncAutomateIT.ps1` (internal roll + auto-rollback),
> `tools/setup/Update-PimContainers.ps1` (zero-downtime roll / rollback). `Invoke-PimUpdate.ps1`
> folds these behind one cert-auth, unattended, idempotent entry.

#### 11.6.0 Release rings for hosted (container) environments

Every hosted environment runs its own in-cloud updater job (`ca-pim-update`). Which version it may move to
is decided by its **release ring**, never by "newest available":

| Ring | Who | Moves when |
|---|---|---|
| **0** | development source | every commit |
| **1** | the maintainer's own release-testing environments | every build that has been built, rolled and verified |
| **2** | customer environments (design partners) | only when a version is explicitly approved for ring 2 |

- **One channel document per feed.** `channel.json` sits beside the published source archives and names the
  approved version per ring (`ring1`, `ring2`, …). Releasing to a ring is editing that one entry; nothing is
  pushed to environments.
- **The updater reads its ring each night** (`PIM_UPDATE_RING`) through the same read-only link it uses for
  the source archive, and moves only to that ring's version. A missing or unreadable channel, or a ring with
  no approved version, means **no move** — never a fallback to a local pin or to "latest". A version below the
  ring's `minFrom` floor is not jumped. Moves are forward-only.
- **Forward-only is ENFORCED in the job, not assumed** (2026-09-18, §33.4 BUG-162). The ring gate answers
  *"may this environment move?"*; it never answered *"is this even forward?"*, and a channel held at an old
  version rolled a freshly-built environment 42 versions backward, unattended, breaking a component that only
  the newer version contains. `Get-PimUpdateDowngradeDecision` (+ `ConvertTo-PimUpdateVersion`, pure, in
  `engine/_shared/PIM-UpdateSource.ps1`) is called from `update-job-entry.ps1` **before the build, before the
  schema step and before any roll**. It compares the ring's target with the HIGHEST comparable version the
  environment is known to have reached — the running Manager image tag, `PIM_UPDATE_LAST_BUILT` and
  `PIM_UPDATE_LAST_GOOD` — and REFUSES (exit 1, `Outcome=failed`, carried in telemetry) a target that is
  behind it, or a target that is not a version at all while a comparable one exists. The refusal names both
  versions, the ring that proposed the target and the two ways out. A deliberate rollback stays possible via
  `PIM_UPDATE_ALLOW_DOWNGRADE=1` on the update job — **off by default**, and reported loudly when used.
  Forward rolls and the same-version no-op are unchanged. The host-side rollers stay unguarded on purpose:
  they are attended, and `Get-PimUpdateRingChannelReport` already prints `BACKWARD` there.
- **Then the normal lifecycle:** already running that version → nothing to roll; otherwise fetch that exact
  version's source archive, build it in the environment's **own** registry (no build machine, no credential
  shipped between environments — only a read-only link to the archive), apply additive schema changes first (the
  shipped schema files run on every store, every time — each object is guarded, so an existing store gains what a
  release adds; a statement that would remove data, including a drop of a column the store still has, refuses the run)
  (never dropping a column on an unattended run), roll **every** Container App and Job running the product's
  image (discovered from the resource group; anything else is skipped and reported), verify health, and roll
  back to the recorded previous version on a failed verify — confirmed against what is actually running. A
  component left behind fails the update. An updater that cannot verify the database schema refuses a
  version change. If the updater itself carries no database settings, it takes them from the running Manager
  for that run and records them on itself (§27.10); if its identity cannot sign in to the database, the
  refusal names that identity and the SQL admin group to add it to.
- **One status record per run.** Each nightly run writes one short record (from-version, to-version, what it
  did, duration, error) to a write-only central store, so "is this site stuck?" and "is this release failing
  everywhere?" are both answerable. It carries nothing that identifies a person or a credential, and a failed
  status write never affects the update.
- **The same run is also recorded into the environment's OWN store, so the Manager can show the ring**
  (2026-09-18, §71.43). The central telemetry above is **write-only from the environment's side** — it
  answers the vendor's fleet question and nothing the environment can read back — and `ca-pim-manager`
  does not carry `PIM_UPDATE_RING` at all, so the GUI had no honest way to say which ring it is on.
  `engine/_shared/PIM-UpdateState.ps1` adds the record (`New-PimUpdateStateRecord`), a **pure** verdict
  (`Get-PimUpdateStateVerdict` → ring, running, approved, built, last run + outcome, last **success**,
  held, behind, stale, malformed, not-recorded) and a never-throwing store read/write. It is **one bounded
  JSON document in `pim.Settings['UpdateState']`** — same shape as `CutoverState` / `FeatureGates`, **no
  file anywhere** (v2 is SQL-only). Semver parsing is duplicated locally rather than reaching into the
  updater's library, per isolation-beats-DRY. `update-job-entry.ps1` writes it from the single
  `Send-PimUpdateOutcome` helper every exit path already calls, best-effort in exactly the telemetry
  direction: it can never fail, delay or refuse an update. The store env→globals copy became
  `Use-PimUpdaterStoreEnv` (`PIM-UpdateSource.ps1`) and is now called **at the top of the job as well**,
  because the refusals *above* the schema phase — no resource group, a ring with no source, nothing
  approved, a refused downgrade — are exactly the runs an operator needs to see, and they previously ran
  with no store resolved.
- **`GET /api/update-ring` is read-only, and there is deliberately no writing counterpart.** It feeds the
  header badge (`ring N` beside the Mode badge, with a `behind` / `held` / `failed` chip only when not
  healthy) and the **Jobs → "Updates & ring"** panel. "Running now" is the Manager process's own version,
  so the endpoint makes **no ARM call** to answer. Two rules it keeps: an environment that has recorded no
  run shows **"not recorded"** and no ring number — never a guess; and a stale record is never presented
  as current (everything is stamped with when it was recorded, with a banner past 48h). A ring move stays
  an operator act on the update job; the panel says so, there is no write endpoint, and a test fails if
  one appears.
- **Where a feed is needed.** The in-cloud updater requires a published source feed (archives + `channel.json`).
  A community installation from the public repository has none and updates by `git pull` plus re-running the
  one-shot deploy (§11.7).
- **Deploys set the ring** (`-UpdateRing`, default 2 for a new environment; an existing ring is kept on
  redeploy) together with the source link, written through ARM read-modify-write and read back.
  The question *"was a ring asked for?"* is decided **once, at script scope**
  (`$script:PimDeployRingExplicit`, set right after `Invoke-PimDeployAll.ps1`'s param block) — it used to be
  asked with `$PSBoundParameters.ContainsKey('UpdateRing')` *inside* `Invoke-DefaultStepRunner`, whose own
  parameters are `($Key, $Ctx)`, so the answer was always **false** and the configured ring was never
  forwarded (§33.4 BUG-162). The MSP plan resolves the ring through the pure `Get-PimMspBuildUpdateRing`
  instead of `[int](& $V 'updater.ring')`, because that cast turned a config with **no** ring into ring 0 —
  the ring that takes every build; it now returns the documented default with a stated reason and **throws**
  on a malformed value. The default is stated rather than silent (a WARNING from `Deploy-PimUpdateJob` and a
  line in the step report). Finally, `Deploy-PimUpdateJob.ps1` **re-reads `PIM_UPDATE_RING` off the deployed
  job over ARM and fails the step** when it is not the ring the run decided, or is absent.
- **Host-side tools obey the ring.** `Invoke-PimUpdate`, `Update-PimContainers` and the deploy roll step refuse
  a version that a ring ≥ 2 environment's channel has not approved, unless an operator passes
  `-OverrideRingGate -Reason`, which is audited. A verified host-side roll of a ring 0/1 environment advances
  that ring in the channel, so the cloud job and the host task can never move an environment in opposite
  directions; ring ≥ 2 is never written automatically.

#### 11.6.1 The flow

| Step | What happens |
|---|---|
| **detect** | Read the currently-deployed version and the newest released version; decide with a **numeric semantic-version** compare (so `…218` beats `…99`), pre-release < release, an unparseable tag is **never** treated as newer, and the tag already deployed is never re-rolled. A `-PinnedTag` makes the target explicit (still applied only if newer). Also detects whether a **SQL/schema** and/or **GUI** update is required (below). |
| **build** | Internal: build the new image (`az acr build`) unless rolling to an existing tag. Community: nothing to build server-side beyond pulling the new code. |
| **deploy** | Internal: roll every Container App to the new tag through the **zero-downtime** roller (new revision, traffic shift, min-1 replica; apps pull via their AcrPull MI). Community: the new code is in place after the pull; rebuild the local Manager process. |
| **verify** | Run the **hosted smoke** (`tests/live/Test-PimManagerHostedSmoke.ps1`) as the health check (community: the offline suite + a local Manager start). |
| **notify** | Mail the operators the outcome (rolled to `<tag>`, healthy / rolled-back). |
| **ensure-monitor** | Confirm the always-on health probe + the **standalone** update schedule (the VisualCron / Task-Scheduler task, or the post-sync deploy hook) are in place so the next cycle is covered. |

**`-DetectOnly` vs `-Apply`:** the lifecycle is **dry-run by default** —
`-DetectOnly` reports the decision (what's deployed, what's newest, whether a
schema/GUI change is needed) and changes nothing. **`-Apply`** is the explicit
gate that actually rolls; the same gate is opened on a cadence by the scheduled
maintenance window.

#### 11.6.2 Community path

```powershell
# 1. Pull the latest community edition.
git pull
# 2. Re-run the SAME one-shot deploy (§11.5.1 step 3). Without -Apply it prints the plan.
.\tools\setup\Invoke-PimDeployAll.ps1 -Scenario S2 -Apply ...
```

- Every step that is already current is a clean skip, so a re-run **is** the updater: the
  image is rebuilt from the pulled code only when its content changed, the schema step
  applies the **idempotent, additive CREATE/ALTER** before the new revision rolls, and a
  failed verify rolls the Manager back to the captured previous revision.
- The in-cloud nightly updater (§11.6.0) needs a published source archive and release channel,
  which a GitHub install does not have; for S2/S4 without `-UpdateSourceUrlTemplate` the
  deploy skips that step on purpose and says so.
#### 11.6.3 Internal path

```powershell
# Dry-run: decide only (newest released vs deployed; schema/GUI deltas).
.\tools\setup\Invoke-PimUpdate.ps1 -DetectOnly
# Apply: sync-automateit pull -> build image -> roll Container App -> schema
#        upgrade -> hosted smoke -> rollback-on-fail -> mail-notify.
.\tools\setup\Invoke-PimUpdate.ps1 -Apply
```

1. **`sync-automateit` pull / detect** — resolve the newest valid released tag
   vs the deployed tag (numeric semver; idempotent no-op if already newest).
2. **build image** — `az acr build` for the new tag (skip when rolling an
   existing tag). The build reports the **digest** the tag now points at, because
   the tag alone does not identify what was built.
3. **roll Container App** — capture the manager's current revision as the
   rollback target, then roll every app via `Update-PimContainers.ps1 -SkipBuild`
   (zero-downtime; AcrPull MI, no registry creds at roll time).

   **Deploys are DIGEST-PINNED, not tag-based.** A tag is a mutable pointer:
   rebuilding `pim-manager:<tag>` moves it to new content while the container's
   image *field* stays byte-identical — so ARM sees no change, creates no
   revision, and the platform keeps serving the image it already pulled. Both
   deploy paths therefore resolve the tag to its digest at deploy time and set
   `<registry>/<repo>@sha256:…`, so new content is a genuinely changed field.
   Afterwards each app (and the scheduled tick Job) is read back and the run
   **fails** unless the running reference carries that digest. A matching *tag*
   is explicitly not accepted as that evidence — on a rebuilt tag the requested
   and running tags are the same string while the content is stale, which is how
   a roll once verified itself green while continuing to run the previous build.
   The decision logic is the pure `engine/_shared/PIM-ImageRef.ps1`; the registry
   lookup is `Resolve-PimAcrImageDigest`, which refuses to fall back to the tag
   (an unresolvable tag means the image is not in the registry, so a tag deploy
   would fail later and blame the wrong step).

   **The scheduled tick Job is rolled by the same step, off the same digest.** It
   is a Container Apps *Job*, not an app, and it used to be stamped earlier in the
   run — before the code step rebuilt the tag it was resolved from — so a single
   deploy could leave the interface current and the reconciling engine one build
   behind, durably. The roller now stamps the Job with the identical digest
   reference the apps were verified on and verifies it the same way. A missing Job
   is a skip (an always-on deployment has none) and says so; a failed stamp fails
   the deploy and names it as skewed. A rollback reactivates app *revisions*, which
   a Job does not have, so that path warns rather than pretending the Job came back
   with them.

   **A roll that changes DESIRED STATE is refused unless it is asked for.** The
   image carries the shipped policy templates, so an update meant to change how the
   product *works* can also change what it *wants* — and the engine then converges
   every managed scope onto that new baseline within one scheduled run. Before
   rolling, the shipped templates are fingerprinted
   (`engine/_shared/PIM-PolicyBaseline.ps1`) and compared against the fingerprint
   recorded on the deployed resource as the `pim-policy-baseline` tag; a difference
   **throws**, naming the templates that moved, unless `-AcceptBaselineChange` is
   passed. The fingerprint parses each template and drops `_`-prefixed annotations
   and `description`, so comment, key-order and line-ending churn are not baseline
   changes — a gate that fires on documentation would be routed around. Nothing
   recorded yet (a first deploy) warns and proceeds rather than blocking, and the
   fingerprint is written only *after* the roll verifies, so a failed deploy cannot
   advance the recorded baseline past what was actually shipped.
4. **schema upgrade** — apply the idempotent CREATE/ALTER if the release needs
   it; additive and re-runnable.
5. **smoke** — run `tests/live/Test-PimManagerHostedSmoke.ps1`. Healthy = exit 0,
   zero failures.
6. **rollback-on-fail** — on a real smoke failure, **auto-roll-back** to the
   captured pre-update revision (`Update-PimContainers.ps1 -Rollback` — an instant
   revision reactivate) and fail loudly.
7. **mail-notify** — mail the operators the result.

**Scheduling (standalone — NOT the engine/scheduler).** The update is **never** an
in-container scheduler job (a design correction removed the former
`sync-automateit` scheduler job + its handler so the engine/scheduler can never
trigger the update). Two standalone triggers drive the cadence instead:
- **VisualCron / Windows Task Scheduler** — `Register-PimSyncSchedule.ps1` registers a
  task (default 03:00 local) that runs `Invoke-PimUpdate.ps1 -Apply` (full lifecycle:
  schema + GUI build/roll + verify) for the internal or community edition; the exported
  task XML imports into VisualCron unchanged. `-UpdateMode RollOnly` drives the lighter
  image-roll path; `-LocalPull` runs a customer pull script on a pure-VM (no-ACA) host.
- **Post-sync deploy hook** — on the internal edition the bootstrap `sync-automateit` pull
  fires `Invoke-PimUpdate.ps1 -Apply` automatically after the code is pulled (the
  per-solution `Deploy` block in `sync/Sync-AutomateIT.json`), so the pull *is* the trigger.

Either way the apply only happens inside the maintenance window or on an explicit `-Apply`,
and it runs cert-auth + unattended (no prompts).

#### 11.6.4 When is a SQL/schema and/or GUI update required, and how

- **Schema update** — required whenever a release adds or changes a logical
  column / table (new provider scope, new lifecycle column, audit/intake table).
  Applied as a **one-time idempotent schema CREATE/ALTER** (`Initialize-PimSqlStore`)
  — additive, re-runnable, transactional where it imports, and it never writes
  back to or modifies your existing `*.custom.*` source data. (The first move
  *onto* SQL is the separate one-time import, §5.3; routine version-to-
  version schema bumps are just the schema step.)
- **GUI update** — required whenever the Manager changes. **Community:** the new
  Manager code arrives with the `git pull`; restart `Open-PimManager.ps1`.
  **Internal:** the Manager is part of the rolled image, so the zero-downtime roll
  *is* the GUI update — no separate step.
- **Neither** — most engine-only patch releases need no schema or GUI change; the
  detect step reports "code only" and the apply just rolls the image (internal) or
  is a no-op beyond the pull (community).

#### 11.6.5 Surviving an unattended host — the two guards the flow above depends on

The lifecycle in 11.6.1 is only as good as the host it runs on at 4am with nobody
watching. Two properties of that host, neither visible from an interactive console,
are handled explicitly.

**a) A native tool's warning must never be read as a failure.** The scheduled task runs
under **Windows PowerShell 5.1**, and 5.1 turns *any* write to a native command's
standard-error stream into a terminating error when `$ErrorActionPreference` is `Stop`
— which the update path uses. The Azure CLI writes ordinary, harmless warnings there
routinely (extension notices, interpreter hints), so a warning that changes nothing can
abort a deploy **after** the image has been built and pushed. PowerShell 7 does not
behave this way, so the fault is invisible on a developer machine.

Every Azure-CLI call in the setup/deploy family therefore goes through one guarded
invocation (`tools/setup/_PimAz.ps1`), which each entry point loads **before its first
CLI call**. The guard neutralises the error preference around the native call, restores
it afterwards, and decides success by the **exit code alone** — so a genuine failure is
still a failure, and its captured error output is printed in full rather than swallowed.
Redirection alone (`2>$null`) does not achieve this: it changes where the text goes, not
whether the record is fatal.

> 🪤 The same environment can pass and fail with identical code, because whether the CLI
> warns at all depends on its **configuration directory** — an isolated profile with no
> extensions installed stays silent, a shared profile with extensions does not. A green
> result on one deployment is not evidence about the next one.

**b) Two deployments must never build from the same tree at once.** One automation host
commonly updates several deployments, and each of them **pulls into the same synced tree**
before building an image from it. Two overlapping runs would let one build read a
directory the other is halfway through rewriting — and it would not fail cleanly, it would
ship a half-written tree. The scheduler's own "do not run this task twice" setting does not
help, because these are *different* tasks.

`Register-PimSyncSchedule.ps1` addresses this in two layers:

| layer | what it is | why both |
|---|---|---|
| **stagger** | `-AtHour` + `-AtMinute` so several deployments can share an hour without sharing a minute | the plan: with a full build-and-roll measured at 8–10 minutes, 20-minute spacing has real headroom |
| **run lock** | the generated wrapper takes an **exclusive lock on the shared tree** before the pull, and **skips the run** (distinct exit code) if it cannot get it | the guarantee: a stagger only works while every run finishes inside its slot |

The lock is keyed on the **puller's directory**, so deployments sharing a tree serialise
while one pulling into a different tree is unaffected. It is an exclusive file handle
rather than a named mutex: it needs no special privilege, works across accounts, and the
operating system releases it if the process dies — so an interrupted run cannot wedge every
following night. A run that skips **says so in its log**; it never proceeds quietly.

> 🔒 **A per-deployment auto-deploy hook is for a single-deployment host.** The post-sync
> hook (11.6.1) takes its arguments from the local sync manifest, and those arguments name
> **one** deployment's infrastructure. On a host that updates several, the hook can only ever
> be right for one of them, so the scheduled task — which carries its own target, credential
> profile and subscription assertion per deployment — is the correct mechanism there.

### 11.7 One-shot "deploy everything" + validation

Standing up — or updating — a whole environment is a SINGLE entry,
`tools/setup/Invoke-PimDeployAll.ps1`, that **orchestrates the existing setup family
in the right order** rather than re-implementing any of it. Like the update lifecycle,
the risky logic lives in a **pure, offline-unit-tested core**
(`engine/_shared/PIM-DeployAll.ps1`); the orchestrator only gathers facts and runs each
step's runner.

**Ordered steps (load-bearing order):**

| # | Step | What it does | Skipped when |
|---|------|--------------|--------------|
| 1 | `appreg` | Engine app registration + grants (`Install-PimEngineAppRegistration.ps1`) | it exists, or `-SkipAppReg` (hosted engines use managed identity) |
| 2 | `prereq` | Resource group, VNet + delegated subnet, Log Analytics, container registry, Entra-only SQL server, AcrPull identity (`New-PimHostingPrerequisites.ps1`) | all present |
| 3 | `image` | Build the Manager/engine image from the pulled code into the registry (`Build-PimManagerImage.ps1`; flat public layout supported) | the image for this content already exists |
| 4 | `infra` | Container Apps environment, the Manager app and the scheduled engine job; identities, Graph and Azure grants (`Setup-PimContainers.ps1`) | the environment is current |
| 5 | `sqlaccess` | Network access from the environment to SQL, verified | already granted |
| 6 | `schema` | Idempotent, non-destructive schema upgrade | the database already conforms |
| 7 | `mailsender` | Shared sender mailbox with a scoped send right (needs Exchange Online) | not configured / not licensed |
| 8 | `features` | Feature baseline (scheduler, alerting, downlink gates) | already set |
| 9 | `easyauth` | Entra sign-in in front of the Manager, optionally assignment-required, read back | already configured |
| 10 | `code` | Roll the Manager and engine job to the built image (the only rollbackable step) | already running it |
| 11 | `updater` | In-cloud nightly updater job | `-SkipUpdater`, or S2/S4 without a release feed |
| 12 | `access` | Manager administrators written to the database | already present |
| 13 | `verify` | Hosted smoke + deploy validation; auto-rollback of `code` on failure | `-SkipVerify` |
**Decisions in the pure core** (`PIM-DeployAll.ps1`):
- `Get-PimDeployStepCatalog` — the fixed ordered step list; only the **code** step is
  flagged rollbackable.
- `Get-PimDeployStepDecision` / `Get-PimDeployAllPlan` — per-step gate/skip: a step runs
  only when **needed** (target missing / drifted) **and** `-Apply`. An already-current step
  is a clean `skip-current` (this is what makes a re-run the updater). An **absent/unknown**
  fact is treated as NEEDED (fail-safe — never silently skip a real change). `-WhatIf`
  (default) → every step `plan` only; `-ValidateOnly` → only the verify step runs.
- `Get-PimDeployVerifyVerdict` — combines the smoke + validation exit codes into healthy /
  unhealthy; a **self-skip** (exit `< 0`, e.g. no `az` / not logged in) is *UNVERIFIED, not
  a fail*; reuses `Get-PimVerifyVerdict` for the rollback math.
- `Get-PimDeployRollbackPlan` — on a failed verify (or a failed step that halts the run),
  rolls back **only the code step**, in reverse run order, to the captured pre-deploy ACA
  revision. Schema upgrades are idempotent + non-destructive and are **never** auto-reverted;
  app-reg/infra stand-up is additive and left in place.
- `Get-PimDeploySummary` — classifies the run as `planned` / `success` / `unverified` /
  `rolledback` / `failed`.

The per-step runners are **injectable** (`-StepRunner`) so the entire orchestration — order,
halt-on-failure, rollback, `-WhatIf` no-writes, idempotent no-op, `-ValidateOnly` — is
exercised offline without touching Azure/SQL (`tests/PIM.DeployAll.Tests.ps1`). The script is
parameterised for any tenant (no baked-in tenant/sub/SQL/RG/KV; cert-auth, unattended). The
**live deploy + validate against a real test tenant is the release gate** — the offline suite
is necessary but not sufficient.

### 11.8 Deployment scenarios — the six supported topologies (S1–S6)

PIM4EntraPS supports a fixed, named set of **deployment topologies**: the
combination of *who runs it* (a single tenant, an MSP master, or an MSP-managed
customer tenant), *which distribution edition* it is (Internal/AutomateIT vs the
public Community edition), *where the update comes from*, *where the GUI + SQL
live*, *which SPN model* authenticates, and *what license tier* the feature
catalog (§19) gates on. Capturing these as one explicit catalog means the GUI,
the engine, the update/sync paths, and the deploy scripts all resolve the same
topology rather than each guessing from ambient signals.

**Status (honest).** The scenario **catalog + the resolver** that maps a scenario
onto the existing knobs (config variant, update-source profile, ring gating,
active license edition, hosting location, SPN model) are **built and
offline-verified**, and the update-source selector + license-tier gating are wired
end-to-end through the entry points (`-Scenario S1..S6` on `Invoke-PimUpdate` /
`Invoke-PimDeployAll` / `Build-PimManagerImage`). The **MSP-managed downlink/sync
runtime (S5/S6)** — the ring-gated pull of the signed baseline *from the master*,
the master→managed admin/permission sync, hosting-location branching, and SPN-model
branching — is **plan-surfaced but not yet wired live**. None of S1–S6 is
"delivered" in the §19 sense until it is verified against a live deployment; a
**3-tenant materialization** (one master, two managed test tenants) is the
release gate. The diagrams below mark every not-yet-live element with `⧗ pending`.

#### Scenario overview

The scenario is a single descriptor: every scenario sets exactly one value per
dimension. The dimensions are deliberately **solution-agnostic** (a sibling
solution can reuse the same descriptor and supply only its own bindings); only the
*bindings* are PIM-specific.

| Id | Role | Edition (distribution) | Update source | Hosting (GUI+SQL) | Identity model | Sync (master→managed) | License |
|----|------|------------------------|---------------|-------------------|-----------|-----------------------|--------------|
| **S1** | single tenant | Internal/AutomateIT | internal AutomateIT | in tenant | managed identity (hosted) | — | single tenant |
| **S2** | single tenant | Community | GitHub | in tenant | managed identity (hosted) / certificate | — | single tenant — community edition is **free** |
| **S3** | MSP **master** | Internal/AutomateIT | internal AutomateIT | in master tenant | managed identity (hosted) | — | MSP — paid (Pro) edition, details to follow |
| **S4** | MSP **master** | Community | GitHub | in master tenant | managed identity (hosted) / certificate | — | MSP — paid (Pro) edition, details to follow |
| **S5** | MSP **managed** | Internal/AutomateIT | **from master, ring-gated** | **central** (MSP tenant) | **multi-tenant application** (crosses tenants) | admins + permissions | MSP — paid (Pro) edition, details to follow |
| **S6** | MSP **managed** | Internal/AutomateIT | **from master, ring-gated** | **local** (managed tenant) | managed identity (hosted) | admins + permissions | MSP — paid (Pro) edition, details to follow |

**Say the NAME, not the id.** Outside the scripts that still take `-Scenario`, a setup is named by
**role + hosting**, because that is what actually differs and because `S5`/`S6` are both *managed*
tenants (the provider is `S3`/`S4`) — a distinction the ids hide:

| Name to use | Id(s) | What varies |
|---|---|---|
| **Single (tenant, local-hosted)** | S1, S2 | distribution edition only |
| **Provider / master (MSP, local-hosted)** | S3, S4 | distribution edition only |
| **Managed / slave (MSP, central-hosted)** | **S5** | portal + SQL live in the **provider's** tenant; multi-tenant application |
| **Managed / slave (MSP, local-hosted)** | **S6** | portal + SQL live in the **managed** tenant; local identity |

*local-hosted* = portal + SQL live in that tenant itself; *central-hosted* = they live in the
provider's tenant. Single and provider are always local-hosted, so their hosting is stated rather
than chosen. **The public docs carry no ids at all** — README describes the same six by role and
hosting.

Two distinct axes are easy to conflate and are kept separate on purpose:
- **Distribution edition** (`Internal/AutomateIT` vs `Community`) — branding +
  *where updates originate* (the internal AutomateIT source vs public GitHub).
- **License** — the commercial basis. Single-tenant use (S1/S2) is the single-tenant
  edition, and single-tenant use of the community edition (S2) is free. The MSP scenarios
  (S3–S6: a managing master tenant and the managed tenants it looks after) will be part of
  the paid (Pro) edition; licensing details will be published. Licence **enforcement is
  currently switched off** (§19a), so no scenario is restricted today.

How each generic dimension resolves onto the engine's existing knobs:

```
   scenario  ──► resolver ──► existing knobs the rest of the system already uses
   ─────────     ────────     ──────────────────────────────────────────────────
   edition    ─────────────►  distribution-edition flag        (branding/origin)
   licenseTier ────────────►  active edition the §19 catalog gates on
   updateSource ───────────►  update-source profile:
                                internal-automateit → sync-automateit (ACR build → ACA roll)
                                github              → git-pull        (local build/relaunch)
                                from-master-by-rings→ from-master     (ring-gated; central⇒ACA roll, local⇒relaunch)
   role / syncModel ───────►  config variant (msp vs local); managed also runs the
                                master→managed admin+permission sync (pull-not-push)
   hostingLocation ────────►  SQL + web resolution (central MSP store vs local store vs in-tenant)
   spnModel ───────────────►  cert-SPN auth target (multi-tenant SPN for S5; local SPN otherwise)
   syncFileLocation ───────►  where master→managed sync files are staged (central vs local folders)
```

#### Topology — single tenant (S1 / S2)

The simple case: GUI, SQL, engine and the governed tenant are all **one tenant**.
S1 vs S2 differ only in **distribution edition + update source + license tier** —
the *topology is identical*. No master, no cross-tenant anything.

```
   INTERNET ──► Entra sign-in (Easy Auth, always on) ──► Manager
                (external ingress by default · private-only ingress optional)

 ┌──────────────────────── ONE tenant (S1 internal / S2 community) ──────────────────┐
 │   ┌───────────────────────────┐        Graph / ARM REST (read-only Manager set)     │
 │   │  PIM Manager (GUI)         │───────────────────────────────────────┐            │
 │   │   Easy Auth sign-in        │                                        ▼            │
 │   │   external or private      │                              Entra ID / Azure RBAC  │
 │   └─────────────┬─────────────┘                              (this tenant's PIM)     │
 │                 │ managed identity                                    ▲              │
 │                 ▼                                                     │ writes       │
 │            SQL store (in tenant)  ◄─── engine reads desired / writes run state        │
 │                 ▲                                                     │              │
 │            engine (scheduler tick): system-assigned managed identity ─┘              │
 │            (certificate app identity when the engine runs on a server)               │
 └──────────────────────────────────────────────────────────────────────────────────┘
        UPDATE: S1 ◄── internal AutomateIT source   |   S2 ◄── public GitHub
        LICENSE: single tenant                      |   S2 community edition = free
```

#### Topology — MSP master (S3 / S4)

The **master** tenant holds the central authoritative baseline (the templates,
rings, fleet/version metadata) and the MSP operator's own Manager + SQL. It is, in
effect, an S1/S2 deployment *plus* the master-side authoring + signing + rollout
control. S3 vs S4 again differ only in edition/update-source/license; the master
**hosts and signs** — it never reaches into a managed tenant (that boundary is the
managed-tenant pull, below).

```
 ┌──────────────────────── MSP MASTER tenant (S3 internal / S4 community) ─────────────┐
 │   ┌───────────────────────────┐                                                      │
 │   │  PIM Manager (master GUI)  │   authoring: templates · rings · fleet/version       │
 │   │   Easy Auth; ext. or priv. │                                                      │
 │   └─────────────┬─────────────┘                                                      │
 │                 │ MI                                                                  │
 │                 ▼                                                                     │
 │        Central registry SQL  (Owner=MSP baseline + rings + version metadata)          │
 │                 │                                                                      │
 │                 ▼  build + SIGN (private baseline key)                                 │
 │        Signed baseline bundle  ──► staged for managed tenants to PULL (S5/S6)          │
 │                                     (the downlink itself lives in the next diagram)    │
 └──────────────────────────────────────────────────────────────────────────────────┘
        UPDATE: S3 ◄── internal AutomateIT source  |  S4 ◄── public GitHub
        LICENSE: S3 / S4 = MSP scenario — paid (Pro) edition, details to follow
        managed identity (hosted) in the master tenant; master HOSTS + SIGNS, never writes downstream.
```

#### Topology — MSP managed, CENTRAL hosted, multi-tenant SPN (S5)

A managed/slave customer tenant whose **GUI + SQL live centrally in the MSP
tenant** and whose acting identity is a **multi-tenant SPN** that authenticates
*into* the managed tenant. Updates and the admin/permission set are **pulled from
the master, ring-gated**. Sync files are staged in **central** per-tenant folders
on the MSP automation server. The pull and the engine apply are the *only* things
that touch the managed tenant — and that traffic is **private over a cross-tenant
VNet** (see the hard constraint below).

```
   MSP (central) tenant                            MANAGED / slave tenant
 ┌──────────────────────────────────┐            ┌──────────────────────────────────┐
 │  Central GUI + SQL for THIS       │            │  (no local GUI / SQL — central)    │
 │  managed tenant  (separate store) │            │                                    │
 │        ▲                          │            │   Entra ID / Azure RBAC            │
 │        │ MI                       │  apply via │   (the governed PIM here)          │
 │  Engine (central)  ──────────────────────────────►  ▲                              │
 │        ▲   multi-tenant SPN + cert │  PRIVATE  │     │ accounts · groups · scopes   │
 │        │   (authenticates INTO     │  x-tenant │     │  created from master baseline│
 │        │    the managed tenant) ⧗  │   VNet    │     │  + ring-approved version     │
 │  Sync files (CENTRAL folders) ⧗   │            │   └──────────────────────────────┘
 │  Ring-gated pull FROM master ⧗    │◄═══ private cross-tenant VNet only (never internet)
 └──────────────────────────────────┘
   UPDATE: from master, ring-gated  ·  LICENSE: MSP scenario — paid (Pro) edition
   ⧗ pending = central-hosting / multi-tenant-SPN / sync-file / downlink runtime not yet wired live
```

#### Topology — MSP managed, LOCAL hosted, local SPN (S6)

Same managed-tenant *intent* as S5 — updates + admins/permissions pulled from the
master, ring-gated — but the **GUI + SQL live locally in the managed tenant** and a
**local single-tenant SPN** is the acting identity. Sync files stage in **local**
folders on the automation server *at the managed tenant*. This is the closest
managed-tenant shape to the §13 "local plane" model.

```
   MSP MASTER tenant                               MANAGED / slave tenant (LOCAL hosted)
 ┌──────────────────────────────┐                ┌──────────────────────────────────────┐
 │  Central registry SQL         │                │   ┌──────────────────────────────┐    │
 │  (Owner=MSP baseline + rings) │                │   │ PIM Manager (local GUI)       │    │
 │        │ build + SIGN         │                │   │  Easy Auth; external/private  │    │
 │        ▼                      │                │   └───────────────┬──────────────┘    │
 │  Signed baseline (per ring)   │                │       MI          │                    │
 │        │                      │                │                   ▼                    │
 └────────┼──────────────────────┘                │            Local SQL store (in tenant) │
          │                                        │                   ▲                    │
          │  ring-gated PULL ⧗  (managed reads;    │      managed identity (hosted)         │
          ▼  master never writes downstream)       │                   │ apply              │
   ═══ PRIVATE cross-tenant VNet only ════════════►│                   ▼                    │
       (never the public internet)                 │       Entra ID / Azure RBAC (this tenant)│
   Sync files: LOCAL folders ⧗  at the managed     │       ← MSP admins created HERE         │
   tenant's automation server                      └──────────────────────────────────────┘
   UPDATE: from master, ring-gated  ·  LICENSE: MSP scenario — paid (Pro) edition
   ⧗ pending = local-hosting branch / sync-file resolution / downlink runtime not yet wired live
```

> 🚩 **Hard constraint — cross-tenant sync is PRIVATE, never public internet.**
> For S5 and S6, *every byte* that crosses between the master and a managed tenant —
> the ring-gated signed-baseline pull, the master→managed admin/permission sync, and
> the staged sync files — MUST travel over **private cross-tenant VNet connectivity**
> (VNet peering / private endpoints, internal addresses only). There is **no
> publicly-reachable storage account, webhook, function, queue, or blob URL** in the
> sync-data path (`publicNetworkAccess=Disabled` throughout). The RSA signature on the
> baseline guarantees *integrity*; the **private VNet is the only transport channel**.
> (SPN auth to Graph/ARM still uses Microsoft's public service endpoints — that is the
> identity plane, not our sync-*data* plane; the constraint is that the sync **data**
> never transits a public-exposed surface of ours.) This extends the standing MSP
> tenet of *no exposed storage/webhook/function*, and — unlike the general §13.7
> transport, which permits a *"public-but-signed + IP allowlist"* option for the
> open-source MSP edition — the **scenario downlink (S5/S6) is private-only**.

#### Process — UPDATE / SYNC flow (detect → build → roll → verify → rollback)

Every scenario updates through the **same controlled lifecycle** (§11.6) —
*detect → build → deploy → verify → notify → ensure-monitor*, dry-run by default,
auto-rollback on a failed verify. The scenario only selects the **source** and the
**build/roll shape**:

```
                         ┌──────────────── pick update SOURCE by scenario ───────────────┐
                         │                                                                │
   S1 / S3  ── internal AutomateIT ──►  sync-automateit:  az acr build ──► roll ACA revision
   S2 / S4  ── public GitHub ────────►  git-pull:         local build / package ──► relaunch
   S5 / S6  ── from master (ring) ⧗ ──► from-master:      central ⇒ ACA roll · local ⇒ relaunch
                         │                                  (never above the tenant's ring)
                         └────────────────────────────┬───────────────────────────────────┘
                                                       ▼
   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐
   │ 1 DETECT │──►│ 2 BUILD  │──►│ 3 DEPLOY │──►│ 4 VERIFY │──►│ 5 NOTIFY │──►│ 6 ENSURE-MON │
   │ newer?   │   │ from the │   │ roll +   │   │ hosted   │   │ outcome  │   │ health probe │
   │ schema/  │   │ pulled   │   │ guarded  │   │ smoke    │   │ mail     │   │ in place +   │
   │ GUI delta│   │ code     │   │ SQL DDL  │   │ check    │   │          │   │ fresh        │
   └──────────┘   └──────────┘   └────┬─────┘   └────┬─────┘   └──────────┘   └──────────────┘
                                  capture pre-roll    │ healthy ──► keep
                                  revision (rollback  │ UNHEALTHY ─► AUTO-ROLLBACK to captured
                                  target)             ▼              pre-roll revision + alert
                                                  (self-skip of the live smoke = UNVERIFIED,
                                                   NOT a pass — the gate did not run)
```

Dry-run is the default (a bare run only decides + reports); `-Apply` is the gated
path. An unparseable or older tag is **never** treated as newer, so a deployment
never rolls onto a tag it can't reason about and never re-rolls the tag it is
already on. The hosted-smoke verify is a **release gate**: a
self-skip (no `az` / not logged in / app unreachable) is UNVERIFIED, not green.

#### Process — master → managed DOWNLINK SYNC (S5 / S6, pull-not-push) ⧗ pending

The managed tenant **pulls** the ring-approved, signed baseline from the master,
verifies the signature, stages the sync files, and the **engine creates the MSP
admins + permission rows in the managed tenant**. The master **never** writes into,
or opens a connection into, the managed tenant — it only hosts + signs; the managed
side reaches out. The whole transport is **private cross-tenant VNet** (the 🚩
constraint above). This runtime is **plan-surfaced but not yet wired live** —
marked `⧗ pending` — and the live 3-tenant materialization is the gate.

```
   MSP MASTER (admin plane)                              MANAGED tenant (initiates the pull)
 ┌──────────────────────────────┐                      ┌────────────────────────────────────┐
 │ 1  Author Owner=MSP baseline  │                      │                                      │
 │    + assign rollout RING      │                      │                                      │
 │ 2  Build versioned payload    │                      │                                      │
 │ 3  SIGN (private baseline key)│                      │                                      │
 │ 4  Stage signed bundle +      │                      │                                      │
 │    per-tenant sync files      │                      │                                      │
 │    (central S5 / pull-staged) │                      │                                      │
 └───────────────┬──────────────┘                      └───────────────┬────────────────────┘
                 │                                                      │ 5  ring filter: never
                 │   ══════ PRIVATE cross-tenant VNet only ══════       │     pull a version above
                 │           (no public internet, ever)                 │     THIS tenant's ring
                 │                                                      ▼
                 └───────────────  managed PULLS  ◄──────────  6  GET signed bundle (private)
                    (master never pushes)                       7  VERIFY signature (embedded
                                                                   PUBLIC key) · product/kind ·
                                                                   not expired · anti-rollback
                                                                8  stage sync files (central S5 /
                                                                   local S6 folder root)
                                                                9  ENGINE APPLY in this tenant:
                                                                   create MSP admins + permission
                                                                   rows (Owner=MSP); local-owned
                                                                   rows untouched
                                                               10  audit locally · emit signed
                                                                   status summary (counts only)
```

Provenance, not a permission gate: master-originated rows (Owner=MSP) are refreshed
on each pull; rows the managed tenant owns locally (Owner=Local) stay autonomous.
Tamper / forge / roll-back / replay are all rejected by the signature + version +
expiry checks (§13.10). The managed tenant owns nothing it didn't get from the
master *for the synced rows* — but keeps full autonomy over its local rows.

#### Process — deploy / stand-up flow (per scenario)

Standing up any scenario runs the **same ordered deploy** (§11.7,
`Invoke-PimDeployAll -Scenario S1..S6`); the scenario selects the hosting shape and
the per-step bindings:

```
   Invoke-PimDeployAll -Scenario S1..S6
        │  (resolver maps the scenario → config variant · update source · hosting · SPN · license)
        ▼
   ┌────────────────┐  ┌────────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────┐
   │ 1 App-reg +    │─►│ 2 Infra / host │─►│ 3 SQL schema │─►│ 4 Build +    │─►│ 5 VERIFY │
   │   Graph/Az     │  │   S1–S4: in-   │  │   idempotent │  │   deploy code│  │  hosted  │
   │   grants       │  │   tenant       │  │   guarded DDL│  │   (roll ACA  │  │  smoke + │
   │                │  │   S5: central  │  │   (non-      │  │   or relaunch│  │  deploy  │
   │                │  │   S6: local ⧗  │  │   destructive)│ │   per source)│  │  valid.  │
   └────────────────┘  └────────────────┘  └──────────────┘  └──────────────┘  └────┬─────┘
        each step runs only when NEEDED (missing/drifted) AND -Apply;                 │
        an already-current step is a clean skip → a re-run IS the updater.       healthy?─► keep
        -WhatIf (default) plans only; a failed verify rolls back the CODE step.  no ─► rollback
```

The deploy script is parameterised for any tenant (no baked-in tenant / subscription
/ SQL / RG / KV; cert-auth, unattended). For S5/S6 the infra step resolves to the
central MSP store (S5) vs the local managed-tenant store (S6); that hosting-location
branch is `⧗ pending` live-wiring. As everywhere, the **live deploy + validate
against a real test tenant is the release gate**.

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

### Controlled auto-update (`sync-automateit`)

A single, controlled path keeps a running deployment on the **latest released**
engine/manager image without an open "always take whatever is newest" risk. The
risky decisions live in a **pure, unit-tested core** (`engine/_shared/PIM-SyncAutomateIT.ps1`);
the orchestrator (`tools/setup/Invoke-PimSyncAutomateIT.ps1`) only gathers the facts
and acts on the plan the core returns.

- **Version check (only update when newer).** The orchestrator reads the
  currently-deployed image tag off the manager Container App and the newest released
  tag in the registry, then asks the core. The compare is a **numeric** semantic-version
  compare (so a higher patch like `…218` beats `…99`, which a string compare gets
  wrong), pre-release < release, and an **unparseable tag is never treated as newer** —
  so the deployment never rolls onto a tag it can't reason about, and never re-rolls the
  tag it is already on. A `-PinnedTag` makes the target an explicit, deliberate version
  (still only applied if it is newer than what is deployed).
- **Gated / scheduled (standalone — not the engine/scheduler).** By default the
  orchestrator is **dry-run** (decide + report only). It rolls only when the gate is
  open — `-Apply` on demand, or the scheduled maintenance window. The cadence comes
  from a **standalone** host, never the in-container scheduler: a VisualCron / Windows
  Task-Scheduler task (`tools/setup/Register-PimSyncSchedule.ps1`, `-UpdateMode RollOnly`
  for this roll-only path), or — on the internal edition — the bootstrap post-sync deploy
  hook firing the full `Invoke-PimUpdate.ps1` after the pull. (The former in-container
  `sync-automateit` scheduler job was removed 2026-06-18 so the engine/scheduler can never
  trigger the update.)
- **Safe roll (reuse).** When an update is due, the orchestrator captures the manager's
  current revision (the rollback target), then rolls every app to the new tag through
  the existing **zero-downtime** roller (`Update-PimContainers.ps1 -SkipBuild`) — ACA
  creates a new revision and shifts traffic with a min-1 replica; apps pull via their
  AcrPull managed identity (no registry creds at update time).
- **Post-update health check + auto-rollback.** After the roll it runs the existing
  **hosted smoke** (`tests/live/Test-PimManagerHostedSmoke.ps1`) as the health check.
  Healthy = exit 0 with zero failures. On a real failure it **auto-rolls-back** to the
  captured pre-update revision (`Update-PimContainers.ps1 -Rollback`) — an instant
  revision reactivate — and fails loudly so the operator is alerted.

REST/cert + MI throughout (the orchestrator only shells `az`); PS 5.1-safe; EU allow-list
region (West Europe, Denmark East, Sweden Central; inherited from the deployment); ACA workers via `--yaml`
(through the reused roller / setup script).

### Full update-lifecycle (`Invoke-PimUpdate.ps1`)

`sync-automateit` keeps a deployment on the newest **already-built** image, but it
does not build, it does not touch the SQL schema, and it does not notify or check
that ongoing health monitoring is in place. The **update-lifecycle** is the
superset that runs after PIM code is pulled and turns a fresh pull into a safe,
verified, observed deployment — one coherent flow over **both** pull paths:

- **community `git pull`** — local/VM; store is Azure SQL; the Manager
  runs locally. Build = local docker/podman build, or (no engine) package the pulled
  `tools/pim-manager/` tree for a direct relaunch.
- **`sync-automateit` pull** — hosted; store is Azure SQL; the Manager runs on
  Container Apps. Build = `az acr build`; deploy = roll the ACA revision.

The two paths are normalized by `Get-PimUpdateSourceProfile` into a `{buildMode;
deployMode; isHosted}` profile, so the orchestrator branches in one place.

As with `sync-automateit`, every risky decision lives in a **pure, unit-tested core**
(`engine/_shared/PIM-UpdateLifecycle.ps1`); the orchestrator
(`tools/setup/Invoke-PimUpdate.ps1`) only gathers facts and acts on the returned
plans. It **reuses** the sync core (semver compare, health verdict, rollback plan),
the schema-conformance core (per-table add/drop/migrate + idempotent guarded DDL),
the zero-downtime roller, the hosted smoke, and the existing mailer — it adds the
glue, not new copies. The six steps:

1. **Detect.** `Get-PimGuiUpdatePlan` compares a **content hash** over the pulled
   `tools/pim-manager/*` (a stable, order-independent SHA-256 of per-file digests —
   the image is stamped with it at build time via a `PIM_MANAGER_CONTENT_HASH` build
   arg/env) against the running image's hash, and also honours a strictly-newer
   VERSION. This catches GUI edits that never bumped a version. `Get-PimSqlUpdatePlan`
   reads the deployed DB's actual columns per locked-SQL table, runs them through
   `Get-PimSchemaConformancePlan`, and also forces an upgrade on a strictly-newer
   schema-version marker (data-only migrations the column scan can't see). The
   combined result is the `-DetectOnly` contract: `{SqlUpdateRequired;
   GuiUpdateRequired; details}`.
2. **Build (the gap).** When a GUI update is needed, `Build-PimManagerImage.ps1`
   builds a fresh Manager image **from the pulled code** — `az acr build` (hosted) or
   a local build/package (community). `sync-automateit` / `Update-PimContainers
   -SkipBuild` only *roll* a pre-built image; this is what produces the image they
   roll.
3. **Deploy.** Roll the Container App to the **freshly-built** image
   (`Update-PimContainers.ps1`) and/or apply the **idempotent** SQL schema upgrade
   (`New-PimSqlConformanceDdl`) with a preflight → apply → **re-preflight** gate that
   throws if drift remains. Never destructive; SQL-only updates skip the image roll,
   GUI-only updates skip the schema apply.
4. **Verify.** Run the hosted smoke; `Get-PimVerifyVerdict` (reusing the sync core)
   turns the result into healthy/unhealthy and, on failure, **auto-rolls-back** to the
   pre-update revision captured before any change.
5. **Notify.** `Get-PimNotifyPlan` composes the outcome message (success / failure /
   rolled-back, with what was built/deployed/upgraded) and sends it through the
   **existing mailer** `Send-PimNotifyMail` (the same Graph app-only `sendMail` path
   the notifications + synthetic-monitor work uses), rendering
   `templates/mail/update-outcome.mailtemplate.html`. No new mailer.
6. **Ensure health monitoring.** `Get-PimMonitorEnsurePlan` checks whether the
   deployable synthetic health monitor (Manager + CEH health every ~5-15 min, mail on
   failure, debounced) is in place + fresh, and deploys/refreshes it if missing/stale
   — **reusing** the `feat/synthetic-monitor` monitor + its deploy entry, never a
   duplicate.

**Modes.** `-DetectOnly` (the default — a bare run never mutates anything) reports the
detection payload + the step plan and stops. `-Apply` is the gated path: it captures
the rollback target, runs each needed step in order, rolls back on a failed verify,
and **always notifies** the outcome (success or failure). Idempotent: a second run
with nothing changed and the monitor in place is a no-op. It is foldable into
`sync-automateit` and a git post-merge hook. REST/cert + MI throughout; PS 5.1-safe;
Azure SQL single store; EU allow-list regions (West Europe, Denmark East, Sweden Central).

> **Dependency note (mailer + monitor).** The update-lifecycle depends on the
> synthetic-monitor work (`feat/synthetic-monitor`) by **interface**: the mailer via
> `Send-PimNotifyMail`, and the monitor via its deploy entry (`-MonitorDeployScript`,
> default `tools/setup/Deploy-PimSyntheticMonitor.ps1`). Until that branch lands on
> main, step 5 falls back to "rendered, not sent" with a wire-up note and step 6
> reports the deploy it *would* run and self-skips — it never fabricates a mailer or a
> monitor.

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
- `setup/Invoke-PimMspFanout.ps1` — registry-driven multi-tenant account fan-out.
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
- `engine/_shared/PIM-License.ps1` — offline signed-file verification helper
  (embedded PUBLIC cert only; never signs).
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

### 13.5a Replication targeting — which master rows reach which managed tenants (2.4.360, verified offline)

The MSP master decides, **per row**, whether and where a row replicates. Managed tenants never edit this; they pull
the one signed bundle and evaluate it for themselves.

**Fields.** Every replicable row carries `Replicate` (`No` / `Yes` / `Follow`), `Ring` and `Target`:
admins (`Account-Definitions-Admins`, `pim.CentralAdmins`), admin → direct group memberships
(`PIM-Assignments-Admins`), direct groups (role, organisation, department, project, cross-org), indirect permission
groups (tasks, services, processes), nestings (`PIM-Assignments-Groups`), Entra role bindings, and the tenant-scoped
resource bindings (AU-scoped roles, Azure resources, workloads).
`Target` is blank (every tenant the ring admits) or a comma list of `tag:<key:value>` (any-of), `tag:a+b` (the tenant
must carry all) and `tenant:<id>`. Tenant tags are free `key:value` labels on the master's tenant registry, so a
hierarchy is expressed as tags (`region:eu`, `region:eu-north`).

**Blank = the behaviour before this feature.** An admin replicates when `ManagementMode=msp` (and must agree with
`Replicate`); memberships, groups, nestings and Entra role bindings default to `Follow` — they travel when a replicated
row needs them. Tenant-scoped resource bindings default to not replicated, because the AU, subscription scope or
workspace they name exists in one tenant; an explicit `Follow` or `Yes` carries them.

**Reach rule.** Tenant T receives row R when `Replicate` is not `No` **and** R's ring admits T's ring (`R.Ring ≤ T.Ring`;
a group-model row with no ring is not narrowed) **and** R's `Target` is blank or matches T. Ring and target combine with
AND, never OR. The master's registry view `pim.vw_AdminTenantTargets` applies the same rule.

**Dependencies are auto-included, with a warning.** When a row that reaches T needs another row there — a membership
needs its group, a nesting needs both groups, a binding needs its group — the needed row is included for T even if its
own fields would exclude it, and the plan records a warning naming the row, the dependent and the tenant.

**Producer.** `New-PimBaselineBundle.ps1` selects the bundle content through one pure function: the published admins,
their memberships, `Yes` seeds, and the dependency closure (walked to a fixpoint) from every entity the engine builds
groups from. `No`/`none` rows that nothing depends on are **not** put in the signed payload; the ones carried as a
dependency are reported. With blank fields the payload is byte-identical to the previous producer's.

**Per tenant.** `Get-PimDownlinkPlan` evaluates the rule for its own tenant, computes its own closure, reports
`autoIncluded` and `notReplicated`, and still never retracts. The apply writes only rows the MSP owns, never takes over a
customer row with the same key, and strips the replication fields (they mean nothing inside a managed tenant).
**Retraction is report-first:** a synced row that no longer reaches the tenant is reported as "would remove" (and in the
acceptance record) and is removed only with `-AllowRetraction`, inside the removal budget. The scheduled pull job carries
the opt-in only when its environment sets `PIM_DOWNLINK_ALLOW_RETRACTION=true` (`Deploy-PimDownlinkJob.ps1
-AllowRetraction`); the entry reads it fail-closed (only an explicit true value allows, a mistyped value is reported and
treated as off) and passes it through the scenario runner to the orchestrator.

**Admin lifecycle follows the source.** A published admin carries, besides its status and offboarding date, the master
definition's provisioning date, TAP start date and delete-after-offboarding days — each only when the master set it, so
an older row ships unchanged. The managed tenant stores them on the central admin row (falling back to its previous
defaults when absent) and keeps dates as ISO-8601 text whatever the JSON parser made of them. A slave's own
status-change code is never published.

**A TAP is enforced for every Entra admin.** Single tenant, MSP master and managed tenant alike: the TAP scope issues one
to every Entra admin (never to an AD-only one), and nothing keyed on the "create TAP" column can switch it off — the
column is not published in the bundle, a managed tenant stores it as on, the fan-out ignores a registry "no", the
scheduled-creation report treats the TAP as due, and the validator reports a "no" as having no effect (with a one-click
fix). An admin still gets no TAP when there is nowhere to deliver it: the engine refuses to mint a credential nobody
receives, and the readiness check requires a delivery address for every Entra admin.

**One-shot MSP build.** `tools/setup/Invoke-PimMspBuild.ps1` builds an MSP master or a managed tenant from a
machine-local file of ids and names (a file carrying anything resembling a credential is refused). The pure planner
(`engine/_shared/PIM-MspBuild.ps1`) orders the steps:
- **Both roles:** the tenant vault grant; hosting (`Invoke-PimDeployAll`, managed identity only); the SQL admin group,
  with the scheduler and Manager identities; hosting access (the Engine and read-only Manager Graph sets, and the Manager's
  right to start the scheduler); the scenario.
- **Master:** the registry schema, the storage service endpoint on its own Container Apps subnet, the baseline store made
  public-but-signed (§13.7 implementation notes), registering each managed tenant together with the storage network rule
  for its subnet, the Key Vault signing key (the build prints its key id for the managed tenants to pin), the daily publish
  job, and a first publish that waits for that job to succeed.
- **Managed tenant:** the storage service endpoint on its own Container Apps subnet (the build prints the subnet id for
  the master) and the pull job, which reads a plain blob address and verifies the signature against the master signing key(s) it pins. No link, no credential
  from the master, nothing to renew.

Values only known at run time — managed identity object ids, the signed-in user's object id — are placeholders that
the runner resolves; an unresolved placeholder stops the build. Each step runs in its own process on the host it needs,
with its arguments passed in a file inside a per-run directory that only SYSTEM, Administrators and the running account
can read, removed when the run ends.

**Who the build runs as** is decided by the config alone. Without a deploy identity it runs as the administrator signed
in with `az login`: before anything is touched it asserts that the account is a person (not an application) in the
config's tenant for the named subscription, and that no environment variable would make a step authenticate as someone
else; every step then receives no application identity at all, and the store-writing steps connect to SQL as that
person, who is made a member of the SQL admin group first. With a deploy identity (the MSP management host) it logs in
by certificate into the per-run directory. A step that cannot run under the chosen identity — the unattended daily
re-publish on a person's sign-in — is shown as not run and the build ends "incomplete" rather than "complete". The build
stops at the first failure with the resume command, and ends by printing the steps that need a person. The first policy
mass-change approval is one of them, and is deliberately not automated.

**Manager (MSP master only).** Every MSP sync surface follows the tenant mode the header shows (Single, MSP Master,
Slave): on the master it is shown and editable; on a managed tenant only a read-only "received from the MSP master"
indicator appears on the Accounts list; in Single mode it is absent — including the admin's "Sync to slaves" column,
its management mode, ring and slave-tag fields, and the grid's admin Ring / Target columns. Every Create wizard has a Replication section on its Review step (Replicate, Ring, tag
chips with an all-of switch, a tenant picker, "This will reach: N of M tenant(s)" with names, and the dependency
warnings); the grid shows `Replicate`/`Ring` pickers, a `Target` picker with a grammar check and a Reach count per row.
Reach is computed by the server: it builds the bundle with the producer's selection, signs it with a throwaway key and
runs the same plan every managed tenant runs, once per registered tenant. On a single tenant or a managed tenant the
columns are removed from the grid, the section never renders, and the Manager refuses a save that introduces or changes
the fields. The validator refuses a `Replicate` value that is not `No`/`Yes`/`Follow` or that disagrees with the admin's
`ManagementMode`.

**Verified on a live master / managed pair (2026-09-15).** A sample model on the master — admins targeted by one tag,
by two tags together, by tenant id, one not replicated and one targeted at a tag the managed tenant does not carry, a
role group (`Yes`), an organisation group (`No`) that a replicated membership needs, and two permission groups with
nestings and an Entra role binding — was published, pulled by the managed tenant's scheduled job and applied: exactly
the three reaching admins, the four groups (the organisation group auto-included with its warning in the job log), the
memberships, nestings and role binding arrived and were created in the managed directory, the non-reaching admins did
not, and the managed tenant's own row was untouched. Re-targeting one admin away from the tenant reported its
membership as "would remove" and removed nothing from the directory.

**The pull job's identity.** On a locally hosted managed tenant the scheduled pull job runs its work as its own
system-assigned managed identity — the scheduler job's shape. The deploy grants that identity the engine's directory
permissions and membership of the SQL admin group; the user-assigned identity stays attached only to pull the first
container image. No client secret is needed.

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

#### Implementation note (2026-09-17) — public-but-signed is what the one-shot MSP build sets up

An interim implementation handed each managed tenant a read-only SAS link to the bundle blob, renewed by a weekly
scheduled task that needed a certificate identity in BOTH tenants. It expired, it put a master credential on the
managed tenant's side, and it could not be deployed by a managed tenant's own administrator. It is removed from the
build. The build now implements transport 2 above, with the network half made precise:

- **Trust = the signature.** Every pull verifies the RSA signature against the public certificate embedded in the
  product and refuses a bundle that does not verify, before anything is applied. The network never establishes trust.
- **Access = the master storage firewall.** The bundle container allows anonymous read of **blobs only** (no
  listing); the storage account's firewall default action is **Deny**; one allow rule names each reader:
  - a **virtual network rule** for the managed tenant's Container Apps subnet — the default. Azure accepts a subnet
    from any subscription in any Microsoft Entra tenant (by fully qualified subnet id; not selectable in the portal).
    The subnet carries a storage service endpoint: `Microsoft.Storage` reaches accounts in the same region,
    `Microsoft.Storage.Global` any region, and a subnet holds only one of the two. The managed tenant's build adds it
    and prints the subnet id; that id is the only thing exchanged.
  - an **IP rule** only for a reader with a fixed public egress address in **another region**: storage IP rules have
    no effect on requests from the same Azure region as the account, and traffic from a subnet with a storage service
    endpoint no longer arrives from a public address at all.
  - the **publishing host** is named the same way, or Deny locks out the publish itself.
- **Nothing expires in the access path.** No SAS, no stored access policy, no account key. A rule is set once per
  managed tenant and removed when that tenant stops receiving. The bundle's own validity window (content freshness) is
  unchanged and is renewed by the master's scheduled publish.
- **Transport 1 (private endpoint by approval)** remains the alternative when a service endpoint cannot be used on the
  managed tenant's subnet, or when the storage account must have no public endpoint at all.

#### Implementation note (2026-09-17) — the master publishes from a cloud job, signed by a Key Vault key

The bundle is no longer produced on a management host. The master runs a **Container Apps job** on its own environment
(daily, and on demand) as its **system-assigned managed identity**. It holds no certificate, secret, SAS or account key:

- **Read and build.** It reads the master store as a member of the SQL admin group and builds the payload with the same
  producer function the host script uses, so what a managed tenant receives does not depend on the publisher.
- **Sign.** It signs through the Key Vault `sign` operation with a **non-exportable RSA key** (HSM-protected on a premium
  vault, software-protected on a standard vault; key operations limited to sign and verify). `RS256` is RSASSA-PKCS1-v1_5
  with SHA-256 over the digest — the same primitive, byte for byte, as the certificate signature, so the verifier's
  cryptography is unchanged. The identity may use only that key, and write only to the bundle container.
- **Prove before and after.** Before uploading, it verifies the signature with the managed tenants' own verifier. After
  uploading, it reads the bundle back **anonymously from its own subnet** — the managed tenants' read path — and verifies
  it again. The execution succeeds only if all of that happened.
- **Trust anchor.** A Key Vault signed bundle carries its public key, and that key is **not** what makes it trusted: each
  managed tenant pins the key's RFC 7638 thumbprint in its own configuration, taken from the master's build output and never
  from the bundle store. Several keys may be pinned at once, so a key roll is: give the new key id to every managed tenant,
  then switch the job to the new key. A bundle signed by a key the tenant does not pin is refused; a bundle without a
  carried key is verified against the embedded product certificate exactly as before, so certificate-signed bundles keep
  working during a migration.
- **Network.** The master's Container Apps subnet carries the storage service endpoint, and the store's firewall rule for
  that subnet is created before the firewall's default action becomes Deny. The machine that runs the build is not an
  allowed network and does not need to be.

#### Implementation note (2026-09-17) — private-only pairs use transport 1, and the build sets it up

When the master's and the managed tenant's private networks are **connected** (global VNet peering, created by the
operators — a per-tenant deploy identity cannot authorise one), the build selects transport 1 instead of transport 2:

- **One private endpoint, in the master's own network**, targeting the bundle store's blob subresource; the store's
  public network access is **Disabled**, so the file has no public surface at all. The store name is published in the
  master's `privatelink.blob` private DNS zone.
- **Each managed tenant publishes the same name in ITS OWN zone**, as an address record for the private endpoint's
  address. A private DNS zone cannot be linked across tenants, so each side resolves the name for itself; nothing in
  one tenant is granted rights in the other.
- **Anonymous blob read stays on** — a managed tenant's identity cannot be authorised cross-tenant, and a shared-access
  signature is refused by design (it expires and it is a credential). Confidentiality of the baseline comes from the
  network being private; integrity and authenticity come from the signature, exactly as in transport 2.
- **The application environment may be network-internal** on either side. The hosted GUI smoke can then only SKIP from
  outside that network — and a skip is never a pass.
- **The database gets no private endpoint.** Measured: the `privatelink` name for the database does not resolve from a
  machine outside the network, so a build run from such a machine fails outright. The server admits the environment's
  own subnet, and the build **opens a time-boxed window** for the deploying machine's address and closes it again as a
  final step.

Transport 2 (public-but-signed) is unchanged and remains the default for managed tenants whose network is not connected
to the master's. The trust anchor is the same in both: the bundle's signature and the pinned signing key.

#### Implementation note (2026-09-17) — the one-shot MSP build, deployed by certificate or by a signed-in administrator

The master and each managed tenant are built by one command per side, from a configuration file that carries
identifiers only (a credential in the file is refused). The identity mode is decided by the file, not a switch:

- **Certificate mode** — the file names a deployment application; the build signs in with its certificate into an
  isolated profile for the run.
- **Signed-in mode** — the file names no deployment identity. Before anything is touched the build asserts that the
  current sign-in is a **user** of the configured tenant for the configured subscription, and that no application
  credential (client secret, certificate path, federated token, managed-identity endpoint) is present in the session.
  Every token minted from that sign-in is decoded and checked the same way. Steps receive no application identity; the
  database steps make the signed-in user a member of the SQL administrators group before they connect.

**Order of a new pair.** Each side needs one value the other side creates: the master's store rule names the managed
tenant's subnet, and the managed tenant's pull job pins the master's signing key identifier. A new pair is therefore
prepared with two single steps before the two builds — the managed tenant puts the storage service endpoint on its
subnet and prints the subnet identifier; the master creates its signing key and prints the key identifier — and every
step converges, so the full builds repeat them as no-ops. The two values travel between administrators, never through
the bundle store.

#### Implementation note (2026-09-17) — the provider's Manager verifies the bundle the way a managed tenant does

The MSP view in the master's Manager plans against a signed bundle. Its banner verdict uses the managed tenant's
verifier with the trusted key identifiers read from the same configuration value the pull job reads: a bundle carrying a
Key Vault key verifies only when that key is trusted there, a certificate-signed bundle verifies against the embedded
certificate as before, and an expired bundle is not verified. The verdict carries the signer, the key identifier and the
reason for a refusal, so "not verified" distinguishes an untrusted key from a tampered or expired bundle.

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
| Forge a bundle | Impossible without the MSP private key (non-exportable: a Key Vault key, or the legacy machine-store certificate); a key the managed tenant does not pin is refused even with a valid signature |
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

### 13.15 Shared substrate contract (Product-keyed) — built

`engine/_shared/PIM-Substrate.ps1` makes "shared substrate" a concrete code
contract rather than just a schema note. `Get-PimSubstrateProducts` /
`Test-PimSubstrateProduct` are the allow-list of products that ride the registry
(`PIM`, `TenantManager`). `Get-PimProductTenantQuery -Product <p> [-TenantId]`
emits the **same** read-only `platform.Tenants ⋈ platform.TenantApps` lookup for
any product — the two queries are byte-identical apart from the `Product` literal
(asserted in tests), which is exactly what "TenantManager is just another Product"
means; the literal is validated against the allow-list and single-quote-escaped
(injection-safe). `Resolve-PimSubstrateContext` normalizes a registry row into one
uniform per-tenant shape (`Product/TenantId/Ring/AppId/CertificateThumbprint/
AuthMode/AuthProfile`) so the core never branches on which tool it serves — it only
asks the resolved `AuthProfile` (`cert` | `secretref`) for "a token for tenant X".

### 13.16 Multiple sync models (don't force one) — built

The deployment is not hard-wired to one managed-service shape. `PIM-Substrate.ps1`
describes each sync model by its **invariants**, not its plumbing:
`pull-baseline` (local pulls the signed baseline), `template-pull` (ring-versioned
template MSP→local), `local-reads-msp` (read-only at run time), `sync-out-status`
(signed counts-only summary local→MSP, Flow C), `msp-delegates-local` (autonomous).
`Resolve-PimSyncModel` validates the requested model and **fails closed** on an
unknown model OR any model whose declared invariants would break the rules
(`MspWritesLocal`/`DataLeaves` must both be false; every model is `Initiator=local`
— pull-not-push). `Get-PimSyncModelPlan` maps the model to the concrete LOCAL
scheduler job tokens (`baseline-pull` / `template-pull` / `status-rollup` / none),
and `Setup-PimMsp.ps1 -SyncModel` wires exactly those jobs + `PIM_SyncModel`,
skipping the MSP-template-conn secret for models that never read the MSP DB.

### 13.17 Kill-switch + signed central kill — built

Two layers, both verified with the **embedded public baseline cert** (no secret at
the receiver), reusing the baseline crypto (`Test-PimBaselineDoc`, now
`-AllowedKind`):

1. **Revoke the signer (kill-switch).** `Set/Get-PimRevokedSigners` persist a local
   revoked-thumbprint list; `Test-PimBaselineSignerAllowed` makes the consumer
   reject **any** bundle whose signer thumbprint is revoked (separator/case
   insensitive). Revoking the key is the off-switch for everything it signed.
2. **Signed central kill (MSP-wide).** `Resolve-PimCentralKill` verifies a signed
   `kind='central-kill'` manifest (signature, product, expiry, **and** a
   revoked-signer refusal so a compromised key can't issue kills), then translates
   each entry into the `AccountStatus=Disabled|Revoked` + `StatusChangeCode` rows
   the **existing** engine kill-switch pipeline already authorizes
   (`Test-PimAccountStatusChangeAuthorized`) and applies locally
   (`Invoke-PimAccountStatusChange`). It is **signed desired-state**, not a new
   write path — the local engine remains the only writer into the tenant, so the
   "MSP never writes to a customer tenant" invariant holds even for an emergency
   fleet-wide disable.

### 13.18 Image distribution — `az acr import` (built)

The engine image is built once centrally and **mirrored** into the customer ACR
with `az acr import` (server-side registry-to-registry blob copy — no local
pull/push, no secrets/customer data in the image). `Get-PimAcrImportArgs` is the
pure, unit-tested argument builder: it emits the cross-tenant **token** form (ACR
token convention — username = the all-zero GUID, password = the source token), the
same-AAD **`--registry <resourceId>`** form, or a plain same-tenant import by login
server. `Invoke-PimAcrImport` wraps it (honours `-WhatIf`, **redacts the token** in
all output), and `Setup-PimMsp.ps1 -MspSourceAcr` runs the import **before** the
container deploy so the destination ACR has the image when the workers start.

### 13.19 Ring model — three axes, and which one the framework owns

⚠️ **"Ring" means three different things around PIM.** They are easy to conflate and
conflating them produces wrong fixes, so they are named here once. (Not to be confused with
§13.1's *two planes*, which is about network separation — admin plane vs local plane.)

| # | Axis | Who decides | Selects | Where it lives |
|---|---|---|---|---|
| 1 | **Code-version ring** | the **framework operator** | which **version of the solution's code** a customer receives | the framework's central release map; resolved by the sync engine |
| 2 | **Template-version ring** | a **PIM MSP master** | which **signed baseline/template version** its managed tenants may pull | the MSP master's own store |
| 3 | **Admin↔tenant ring** | the **MSP master's data** | which **admins reach which tenants** — *no version at all* | `pim.CentralAdmins.Ring` ≤ `platform.Tenants.Ring` (`pim.vw_AdminTenantTargets`) |

**Axis 1 is not PIM's.** It belongs to the **AutomateIT framework layer**, which implements ring +
capability gating **generically** so every solution shares one mechanism rather than each growing its
own. The framework layer *is* AutomateIT itself; PIM is an ordinary solution on top of it. The
decision is made *before PIM's code is even on disk*, so PIM never participates at runtime — it only
**declares** what it can do, in `solution.deploy.json`.

**The three-owner spine** (the reason it is shaped this way): the **solution** decides *how* (which
capabilities exist — ships with the code, so changing a deploy contract never touches a customer);
the **operator** decides *when* (which version + which capabilities are approved for a ring —
central, one-line promotion); the **customer** decides *whether* (which solutions, and which
**optional** capabilities). A capability runs only when **all three agree**. Rollout timing and
product choice are different questions with different owners, so they are two independent gates and
neither substitutes for the other. PIM declares ten capabilities — `code` and `schema` **required**,
and `prereq` / `image` / `infra` / `appreg` / `msp-downlink` / `msp-admins` / `msp-roles` /
`msp-groups` optional. A customer blocking a *required* one is **refused and reported**, never
obeyed, because honouring it would leave a broken install.

**The three `msp-*` class capabilities are the CUSTOMER's half of the MSP accept gate.** Blocking
`msp-downlink` declines the managed downlink outright; the class capabilities are finer, so a
customer can decline one *kind* of arriving change and still take the rest — `msp-roles` in
particular is the veto over a projection that could carry Global Administrator into their tenant
unattended. They are read from the customer's **own** `bootstrap\Sync-AutomateIT.json`, the same file
and the same `blockCapabilities` key the platform sync already honours: their file, their choice, and
deliberately **not** a PIM-private consent store, which would be a second place to say the same thing
and would drift. A blocked class is reported `Held` on the plan with the capability named, never
silently absent — *"the customer declined roles"* and *"the master published none"* must not produce
the same report. `msp-policies` is intentionally **not declared**: the downlink does not carry policy
artifacts, and declaring a capability that gates nothing would advertise a control that does not
exist.

**Axis 2 uses the same mechanism as axis 1, deliberately as a separate instance.** A PIM customer
acting as an MSP master runs its **own** downstream fleet; its rollout waves are its business, not
the AutomateIT operator's, so the two maps are owned by different parties and neither dictates the
other. What PIM does *not* do is re-implement the decision: `engine/_shared/PIM-RingGate.ps1` is a
**vendored copy of the platform's pure core**, so plane 2 behaves identically to plane 1 by
construction. Vendored — not dot-sourced — because the platform core is read from the downloaded
snapshot **in memory** and never written to a customer's disk, so it does not exist to be imported at
PIM runtime. The copy is held honest by `tests/Test-PimDeployContract.ps1`, which diffs PIM's verdicts
against the real platform core whenever it is reachable, and asserts the load-bearing invariants
directly when it is not.

**Axis 3 is genuinely PIM's and is unchanged.** It scopes *assignments*, not versions: a ring-0 admin
is broad and reaches every tenant; a ring-2 admin reaches only ring ≥ 2 tenants. The framework's
ring gate does not replace it — it is the "master-store assignment provider" the framework expects
PIM to supply.

**Four outcomes, deliberately distinct.** `Run` · `Held` (the operator has not promoted this) ·
`Blocked` (the customer opted out) · `Refused` (a block on a required capability, ignored and
surfaced). `Held` and `Blocked` must never collapse, or a stalled rollout becomes indistinguishable
from a healthy opt-out. Likewise "no ring restriction" and "nothing approved" are different operator
intents and are represented differently.

🔒 **The non-breaking rule, inherited and applied twice.** An unassigned target is `track-current` —
it behaves exactly as it did before ring gating existed. Absence is *not* the broadest ring and is
*not* an error. PIM applies the same rule inside itself: the managed downlink's version gate is
**opt-in**, so a caller that supplies no ring plan gets precisely today's behaviour.

#### 13.19a What the PUBLIC docs say about rings, and why (2026-09-18)

README and `FEATURES.md` describe **two** of the three axes, deliberately:

- **the software ring** (axis 1) — which product version an environment runs, in §11.6.0's terms:
  approval per ring, the environment *asks* rather than being pushed to, forward-only as of
  2.4.368, no approved version ⇒ no move, a held environment does not move.
- **the replication ring** (axis 3) — which managed tenants a definition row reaches. Stated as the
  full predicate, never as ring alone: `Replicate != No` **AND** `row.Ring <= tenant.Ring` **AND**
  `Target` matches (`Test-PimReplicationReach`, `engine/_shared/PIM-Downlink.ps1`) — *ring AND
  target, never OR* — plus target semantics (blank ⇒ every admitted tenant; a named tenant; tags
  OR-ed across a list and AND-ed within one `+` term; `none` ⇒ never leaves the master), tenant tags
  travelling **inside the signed bundle** so a tenant cannot re-tag itself into scope, the
  dependency auto-include with its warning, and **withheld ≠ retracted** (`retracts = $false` on
  every plan; retraction is a separate, opt-in, report-first, budgeted act).

**Axis 2 (the template-version ring) is NOT in the public docs, on purpose.** It is implemented but
**inert unless a ring map is supplied**, and the containerised scheduled downlink job carries no
`-TemplateRingMap*` parameter at all — it is reachable only from the hand-run
`setup/Invoke-PimDownlinkSync.ps1` / `Invoke-PimScenarioRun.ps1`. Documenting an opt-in gate that
the scheduled path cannot even reach is exactly the failure BUG-29 already caused once. It goes in
the public docs when the scheduled job can use it.

🪤 **The conflation hazard the public text is written around:** the same digits run in **opposite
directions** on the two axes it does describe. Update ring **2** is the most conservative
environment and gets the *least*; replication tenant ring **2** admits *everything* (`Ring <= 2`).
So README states plainly that the two are independent, that neither implies the other, and that
they are **not the same scale** — rather than showing both number lines side by side and inviting
the reader to map one onto the other.

### 13.20 Per-admin sync to managed tenants + the tenant mode badge — built

**The master's admin row decides whether an admin is synced** (`engine/_shared/PIM-Downlink.ps1`).
On the master, `Get-PimCentralAdminsFromDefinitions` reads the master's own
`Account-Definitions-Admins` rows and publishes as central admins only those with
`ManagementMode = msp`; `Ring` selects which managed tenants may receive the admin and `Target`
(tags) optionally narrows that ring (blank = every managed tenant in the ring). Names are taken
from the row exactly as the customer's naming produced them. Every row that is **not** published is
returned with its reason (not MSP-managed, MSP-managed without a ring, AD-only), so "not synced" is
always explained. Synced rows carry the governance fields that must flow down from the source
(`AccountStatus`, `OffboardDate`).

On the managed side `Test-PimDownlinkAdminSynced` applies the same decision to the arriving row:
`ManagementMode = msp` syncs; blank or `local` does not. A row with no `ManagementMode` field at all
is a legacy central-registry row, which only ever held MSP admins, and is treated as synced so an
update never retracts existing MSP admins. Managed tenants keep their **own** local admins
separately (rows owned locally are never touched by the downlink), and a central admin is governed
by the master. Before staging, the downlink also refuses admins whose names do not match the managed
tenant's admin naming prefixes — its engine would not see them and would recreate them each tick —
and names the fix (add the MSP's prefix to that tenant's naming configuration, or rename).

**Tenant mode badge.** The Manager header renders a **Mode** badge (`renderTenantModeBadge()`)
from `GET /api/settings/scenario`: the resolved deployment scenario's label (single tenant, MSP
master, MSP managed …) with its detail as a tooltip, so an operator can see whether this tenant's
changes are local or arrive from a master. It is hidden when no scenario is resolved.

---

## 14. SQL / data model

The configuration model is a set of logical tables (15 with the workload
configuration table). In the running product they live **only in SQL** — each logical table is an
*entity* in `pim.Rows`; the CSV names below are the entity names and the shape of the shipped
samples and of the one-time import input (§5.3). **The SQL data store is part of the solution at no
cost.**

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

The platform DB exposes `pim.Rows` (desired state), `pim.Settings` (settings, scheduler state,
triggers, run history and output, access model, feature gates, mail templates, policy-id map,
safety-brake holds and approvals), `pim.ChangeQueue` (queued directory actions), `pim.TenantCache`
(tenant lists and the active-assignments / drift snapshots), `pim.AuditEvents` (the append-only
audit trail, §17.11) and `pim.Backups` (pre-commit snapshots, §5.4).

**SQL-only — the outcome of the migration.** The earlier dual-store transition (a repository layer
switching between CSV and SQL) has ended: the Manager, engine, scheduler and validator read and
write SQL only, the Manager refuses to start without its database, and no component falls back to
files for settings, access, templates, audit, scheduler state or tenant caches. A file-based
installation is brought in once with `setup/Migrate-PimToSql.ps1` (§5.3); its source files are read,
never modified. Rows are stored as JSON keyed by column name, so there is no CSV header parsing in
the running product.

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
| `businesscentral` | BC service-to-service (admin + automation APIs) | BC supports Entra **security groups**: assign permission sets to the group via the automation API (`/api/microsoft/automation/v2.0/.../securityGroups`). Built as a **membership-model** connector (`business-central`): resolveContainer finds the BC security group by `azureGroupId == groupId`, permission sets attach to it. Per-row `Resource = tenantId/environment`. |
| `devops` | Azure DevOps resource (`499b84ac-1321-427f-aa17-267ca6975798`) | Azure DevOps grants access by **nesting** the Entra group into an org/project security group (not a flat role). Built as a **membership-model** connector (`azure-devops`) using the Graph API: resolveContainer = the Entra group's subject descriptor (client-side `originId == groupId` match), `roles` = the org/project security groups, assign = `PUT memberships/{group}/{subject}`. Per-row `Resource = org`. |
| `powerplatform` | `https://service.powerapps.com/` (BAP admin) | Power Platform **environment roles** (Environment Admin / Maker): flat `roleAssignments` on the BAP admin environment scope with the PIM group as principal. Built as a flat connector (`power-platform`) with static roles + per-row `Resource = environment id`. Pairs with `PIM-PowerPlatformDiscovery.ps1` (environment auto-detect → proposed PIM groups). |

### 15.5 Discovery companions (same framework)

Connectors may declare a `discover` endpoint (Power BI `GET /v1.0/myorg/groups` for
workspaces; ARM for new subscriptions / management groups). Discovery results stage
PROPOSED definition rows ("new workspace 'Finance' found — create PIM groups +
workload assignment?") into pending, so new resources become delegable minutes
after they exist. (Ties into the resource auto-discovery in §17.13.)

### 15.5a Department import from Entra by naming convention (SHIPPED 2026-06-15)

Organizers maintain **departments** (the dept → owner routing the delegation-approval
workflow enumerates; see §3 and §14 `PIM-Definitions-Departments`). Rather than retype
them, an admin imports departments straight from Entra groups that already follow a
naming convention (e.g. `ORG-*`).

- **Pattern → server-side filter.** The pattern is a glob with a leading literal prefix
  and a trailing `*` (`ORG-*` → prefix `ORG-`; a pattern with no `*` is a literal prefix;
  `*`/empty matches all).
- **Two-phase live fetch (root-cause fix, 2026-06-15).** The enumerator is **two calls**:
  (1) **list** matching groups — `GET /groups?$filter=startswith(displayName,'<prefix>')`
  with `$count=true` + `ConsistencyLevel: eventual` and **`$select=id,displayName` only**
  (`startswith` on `displayName` is an *advanced query* that REQUIRES `$count`+eventual) —
  **server-side filtered, never a bulk directory list** (lean-context tenet, §8); then
  (2) **resolve owners** per matched group via `GET /groups/{id}/owners`. The two are split
  because Microsoft Graph **rejects `$count=true` together with `$expand`** (HTTP 400). The
  earlier single call combined `startswith`+`$count`+`$expand=owners`, so it **always 400'd,
  the error was swallowed to Verbose, and the enumerator returned `@()`** — every import
  (including the operator's `ORG-*` groups) silently produced an empty plan. Owners resolve
  to UPN (fallback mail → displayName → id); a group with no readable owners is still emitted
  so the admin can fill owners in manually.
- **Map.** Each matched group becomes a department record `{ name; owners[]; contact;
  notes; source='entra-import'; sourceId=<groupId> }`. The department **name** strips the
  pattern prefix (`ORG-Finance` → `Finance`) for a friendlier label; owners are normalised
  to a sorted, de-duplicated list.
- **Idempotent upsert.** The pure planner keys depts by name (case-insensitive). A
  re-import with identical owners + source linkage is a **skip** (no churn); changed owners
  **update in place** (manual contact/notes preserved); a brand-new match is a **create**.
  **Manual departments — those with no matching imported group — are carried through
  untouched; import never deletes a dept.**
- **Engine is the writer.** The Manager endpoint `POST /api/settings/departments/import`
  (SuperAdmin-gated) reads the current dept list, runs the import (live discover + pure
  upsert plan), then persists the merged list + the chosen pattern (`DepartmentImportPattern`,
  surfaced in the settings bundle as `deptImportPattern`) through the active settings store.
  The Settings → Departments GUI exposes a pattern input + an **Import departments from
  Entra** button that shows a created/updated/skipped result.
- **Code:** `ConvertTo-PimDepartmentImportPrefix` / `Test-PimDepartmentImportMatch` /
  `ConvertTo-PimDepartmentName` / `Get-PimEntraDepartmentImportPlan` (pure) +
  `Get-PimLiveEntraDepartmentGroups` / `Resolve-PimGroupOwnerUpn` / `Import-PimEntraDepartments`
  (live) in `engine/_shared/PIM-Discovery.ps1`. (REST/cert, PS 5.1-safe.)

### 15.5b Approver/owner import from CSV + department rename (SHIPPED 2026-06-15)

A bulk companion to §15.5a: instead of (or after) importing departments from Entra, an
admin uploads a **CSV** to assign approvers/owners per department and optionally **rename**
a department.

- **CSV shape.** One row per department: `Department;GroupName;approver1,approver2,...` with
  an optional 4th column `NewName` that **renames** the department. The parser is
  delimiter-flexible (`;` preferred, then `,`, then tab), the header row (`Department;…`) is
  optional, and the owners cell may itself be comma/pipe/semicolon separated.
- **Apply semantics (pure planner).** For each row: match the department by name
  (case-insensitive). The CSV is **authoritative for the rows it carries** — the department's
  owners/approvers are **replaced** with the CSV list (manual `contact`/`notes` preserved). A
  `NewName` renames the department in place (and merges into the target if it already exists);
  a department the CSV names but the store lacks is **created** (`source='csv-import'`).
  Departments **not** named in the CSV are **preserved untouched** (non-destructive round-trip).
- **Engine is the writer.** `POST /api/settings/approvers/import` (SuperAdmin-gated) takes the
  CSV **text** (the GUI reads the chosen file in-browser and posts its text), runs the pure
  parse+apply plan against the current dept list, then persists the merged list. Returns a
  created/updated/renamed summary. Surfaced in Settings → Departments as an **Import approvers
  from CSV** file picker + button.
- **Code:** `ConvertFrom-PimApproverCsv` / `Get-PimApproverImportPlan` (pure) +
  `Import-PimApproversFromCsv` (orchestration) in `engine/_shared/PIM-Discovery.ps1`.

### 15.5c AD OU placement surfaced in Settings (SHIPPED 2026-06-15)

The on-prem AD OUs new admin accounts are created in (`New-ADUser -Path <DN>`) are the
naming-convention keys **`PathAdmins`** (general admins) and **`PathAdminsL0T0`** (high-priv
admins whose UserName carries the `L0`/`T0` marker). The Settings tab now surfaces them in a
dedicated **AD OU placement** card that reads them from the naming map and writes them back
through `PUT /api/settings/naming` (same store the engine reads). They **degrade gracefully**:
absent/`$null` keys render as blank inputs and are written on first edit. The Settings naming
key/value editor **hides** `PathAdmins`/`PathAdminsL0T0` (edited in the dedicated card) and
`TagPrefixToCsv` (an authoring-only mapping, not a name pattern) while carrying both through
unchanged on a flat-table save. Owner-vs-Initial help text now clarifies that the naming token
`{Owner}` is the admin owner's **initials**, distinct from the **people** (UPNs) listed as
department/approver Owners.

### 15.6 Phasing & maintenance hooks (design)

- **Phase 1 (SHIPPED v2.4.142):** connector schema + `defender-xdr` + `intune`
  (both pure Graph); `PIM-Assignments-Workloads` CSV + engine applier
  (`-WhatIfMode`); Manager panel with live role pickers.
- **Phase 2:** `powerbi` adapter + workspace discovery.
- **Phase 3 (STRUCTURE BUILT):** `dataverse` (group teams) + `business-central`
  (security groups) + `azure-devops` (group nesting via the membership adapter) +
  `power-platform` (environment roles) + `PIM-PowerPlatformDiscovery.ps1` (environment
  auto-detect → proposed PIM groups). All schema-validated + unit-tested offline; each
  needs a per-environment/per-org app user + live validation before it moves to FEATURES.md.
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
/ Fabric (workspace roles + admin) ✅ structure (`powerbi`; live-pending) · Power Platform
(environment roles, admin) ✅ structure (`power-platform` + `PIM-PowerPlatformDiscovery.ps1`
environment auto-detect; live-pending) · Power Apps / Power Automate ✅ structure (covered by
`power-platform` environment roles) · Dynamics 365
(security roles) ✅ structure (`dataverse`) · Dataverse (security roles / teams) ✅ structure
(`dataverse`; per-env app user, live-pending) · Business Central (permission sets / security
groups) ✅ structure (`business-central`; per-env security-group membership, live-pending) · Azure
DevOps (org/project security groups) ✅ structure (`azure-devops`; group nesting via the membership
adapter, live-pending) · Exchange Online (RBAC
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

Every engine-sent mail is a customizable template, held in **one template store**:
SQL `pim.Settings['MailTemplates']` (`engine/_shared/PIM-MailTemplateStore.ps1`), resolved by
`Get-PimNotifyTemplateText` (in `PIM-Notify.ps1`) through `Get-PimMailTemplateEffective`:

```
1. the store's body for the type          # GUI-edited; NO file, NO image rebuild  <- wins
2. templates/mail/<type>.mailtemplate.html  # shipped default, only for a type the store
                                            # has not been seeded with yet
```

**GUI-driven, no rebuild.** An administrator (Admin+) edits a template body in
**Settings → Mail templates** and clicks **Save**. The body is written to the store, so the
customization **travels with the environment** and survives restarts and updates with **no image
rebuild and no file copy**; the engine reads the same store. **Reset** (DELETE) returns the type to
the shipped default. There is no file override layer: `<type>.mailtemplate.custom.html` files and
the former `MailTemplateOverrides` setting are not read at run time — a file-based installation's
overrides are brought into the store once by the one-time import (§5.3).

Endpoints: `GET /api/mail-templates` (list, with `source` showing customized vs shipped),
`GET /api/mail-template?type=<t>` (effective body + shipped reference),
`PUT /api/mail-template {type,body}` (save override, Admin+),
`DELETE /api/mail-template?type=<t>` (reset, Admin+).

Types: `new-admin`, `tap-delivery`, `new-role`, `new-permission`,
`approval-request`, `approval-escalation`, `offboarding-notice`,
`daily-summary`, `tier-report`, `emergency-override`. Subject = first line as an
HTML comment (`<!-- subject: ... -->`). Token substitution (straight string
replace): `{{DisplayName}} {{UserPrincipalName}} {{TapCode}} {{TapStart}}
{{TapLifetimeHours}} {{RoleName}} {{GroupName}} {{GroupTag}} {{Sponsor}}
{{ManagerEmail}} {{Company}} {{TenantName}} {{Date}}` — unknown tokens render empty
+ a warning.

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

**Linking**: column **`PolicyTemplate`** on the definition rows. Blank = `default`.
Validator **PIM-POL-001**: referenced template must exist. **Engine re-apply**: the REST
providers do not trust a stored "last applied" marker — they read the live policy and compare every
managed rule against the template (below), so a policy changed in the portal is repaired and an
unchanged one is NoChange (idempotent). (The module-based reference engine keeps a per-group
applied-hash file for the same purpose.) Templates are stored in SQL and upgraded automatically when
a release adds settings, without overwriting customised values. `extends` is single-level only.

**GroupsCreateModifyPolicy — full create+modify reconcile (idempotent over the whole
rule set).** The `GroupsPolicies` provider both *creates* (first apply) and *modifies*
(drift repair) a group's PIM **member** activation policy, and its diff compares **every
rule family it PATCHes** — Approval, the three Expiration targets (EndUser/Assignment,
Admin/Assignment, Admin/Eligibility), the three Enablement targets, and each declared
Notification rule. The provider's `GetLive` reads the live policy back with
`?$expand=rules` and carries the whole rules collection; `Equal` then normalises both
sides into a per-rule-id *facet map* — desired via `Get-PimGroupPolicyDesiredFacets`,
live via `Get-PimGroupPolicyLiveFacets` (routed by rule id **and** `@odata.type`) — and
`Test-PimGroupPolicyInSync` returns NoChange only when **every** desired facet is present
live with a matching normalised value. String-set fields (Enablement `enabledRules`,
notification recipients, the resolved approver-id set) are compared order-insensitively
via `ConvertTo-PimSortedList`, so reordering never causes a false drift, while a genuinely
changed approver, duration, or MFA requirement does. The engine only owns what the
template declares: a facet absent from the template is absent from the desired map (never
demanded live), and an extra rule the policy already carries that the engine doesn't
manage never forces an update. Net effect: re-running issues **zero PATCHes** when the
policy already matches, and a single targeted modify when any managed setting (including
the formerly-uncompared Admin-Assignment / Admin-Eligibility expiration caps and the
notification recipients) has drifted in the portal. These facet builders + the compare
are **pure** (no Graph) and unit-tested offline; the PATCH plumbing is the existing
`New-PimGroup*RuleBody` / `ConvertTo-Pim*RuleBodies` set. **Only drifted rules are sent**: a policy
that differs on one rule gets one rule PATCH, not a rewrite of every rule. The same provider manages
the group's **owner** policy as well as the member policy, and applies the full notification rule
set. **RBAC prerequisite**: the engine identity needs `RoleManagementPolicy.ReadWrite.AzureADGroup`
(+ `…Directory`); a refused policy read is reported as a **missing permission** naming it, never as
"no member policy".

**Azure resource role policies (`AzResPolicies`, order 58).** For every Azure scope/role the desired
rows name, the provider reads the ARM `roleManagementPolicies` assignment for that role at that
scope and aligns it with the template: maximum activation and assignment durations, MFA and
justification on activation, notifications, and approval where the template asks for it. A policy
that was only partly configured is repaired **rule by rule**; approval that is already on is never
removed. It runs on its own scheduler job (`delta-pim-azure-policies`, 30 min) and on the scoped
commit trigger for Azure delegations (§5.3). `EntraRolePolicies` (order 75) does the same for
directory-role policies. The shipped standard values for all three surfaces equal v1's.

**The mass-change safety brake (all three providers).** Before writing, each provider builds its
plan — the set of policy changes, how many policies it checked, and how many changes **weaken**
protection (e.g. removing MFA on activation; `Get-PimAzResPolicyWeakening`) — and passes it to the
pure `Test-PimPolicyBreaker`. The brake **trips** when changes N > `MaxChanges` (default 25), or
N / checked > `MaxPercent` (default 25 %, only once at least 8 policies were checked), or weakening
changes W > `MaxWeakening` (default 3); thresholds are overridable per provider in `pim.Settings`
(`<prefix>Breaker`). A trip is a **hold**: the run writes nothing for that provider, records the
hold (`<prefix>MassHold`, with a SHA-256 plan hash, `Get-PimPolicyPlanHash`), raises an engine item
failure, writes a `…masschange.held` audit event and mails the alert recipient. An administrator
approves on **Jobs › Engine logs & errors** (`POST /api/engine/policy-approve`,
`…/azres-policy-approve`); `Approve-PimPolicyMassChange` refuses unless the supplied hash equals the
**current** hold's hash, and records `{planHash, approvedBy, approvedUtc, expiresUtc}` (default 24 h).
The next run applies the plan only if its hash is still exactly the approved one, then clears the
approval — an approval never covers a different change set. Applying a template to a brand-new
group's **untouched Microsoft default** policy is not counted as weakening, so creating delegations
does not trip the brake; ordinary drift below the thresholds is corrected straight away. On the
batched group-policy read path the plan is built and held exactly like the per-item path.

**A hold is its own job outcome: `held` (needs approval).** `Get-PimEngineRunOutcome` classifies a run's per-scope
results: when every error is an approval hold (`GROUP-` / `ENTRA-` / `AZ-POLICY-MASS-HOLD`) the outcome is `held`, with
the provider, the plan hash, the change count and the exact approve command; any other error — or an error it cannot
attribute — makes it `failed`. The scheduler's engine handler returns a held result instead of throwing, the run record
gets `status = held` (ok and ran true), the job alert fires titled "HELD — needs approval", and the Jobs view marks the
job `needsApproval` (amber pill and badge, counted in the needs-attention banner and on Home) until a later completed run
clears it — never green, never red. The same rule runs on a managed tenant's pull: the engine summary carries the
outcome, the scenario step stays ok, and the job logs "downlink JOB HELD" and exits 0.

**Policy changes are audited rule by rule.** Every applied policy change writes an audit event per
changed rule with its value before and after, the template, and whether an approved mass-change plan
applied it (§17.11).

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
- **Activation**: Manager **Settings → Emergency override (break-glass)** (SuperAdmin only)
  → the administrator enters the **emergency passphrase**, verified server-side against the
  per-instance Key Vault secret `PIM-EmergencyPasscode` (never stored locally;
  in-memory comparison). On success the server writes the override to the shared store,
  `pim.Settings['EmergencyOverride']`:
  `{ active, scopeGroupTags[], activatedBy, activatedAt, expiresAt }` (a failed SQL write
  throws — it never falls back to a file the engine would not see) and the engine
  applies: ApprovalRule **disabled** on the scoped groups.
- **Auto-restore**: TTL default 4h (max 24h). Every engine run reads the override;
  expired → re-apply the linked policy template (the §17.7 live compare makes
  this free) and record the restore in the audit trail.
- **Audit**: activation, every policy change it caused, and restoration are all
  audit events — plus an immediate notice mail to all owners of the scoped groups.
- Wrong passphrase: constant-time compare, 5 attempts → endpoint locks 15 min,
  audit either way.
- **Shared verify (pure, KV-backed).** The verify is extracted into
  `engine/_shared/PIM-Governance.ps1` so the Manager *and* any client-PC
  break-glass path use the identical logic. `Resolve-PimEmergencyExpectedHash`
  resolves the expected hash **KV-first** (`PIM-EmergencyPasscode` via the
  existing KV REST reader — the secret value may be the passphrase, which is
  hashed, or a 64-char SHA256 hex, used as-is) then the local
  `$global:PIM_EmergencyPasscodeHash` fallback (so it still works from a client
  PC when KV is the source of truth). `Resolve-PimEmergencyVerification` composes
  the pure pieces: `Test-PimLockout` (5-in-15-min) → `Test-PimPasscodeHash`
  (`Test-PimConstantTimeEqual`) → record a failure on miss; `Get-PimEmergencyTtlHours`
  clamps the requested TTL to 1–24h (default 4). All injected-time, no I/O in the
  core, fully offline-tested (`tests/Test-PimGovernance.ps1`).

### 17.9a Lifecycle calendar & governance decision helpers (shared, pure)

`engine/_shared/PIM-Governance.ps1` holds the cross-cutting, **pure** governance
decisions so the engine, the scheduler, the validator and the Manager all answer
them identically (PS 5.1, time + inputs injected, no Graph/SQL/file I/O in the
core). It builds on the already-tested `PIM-Lifecycle.ps1` due/escalation/renew
primitives.

- **Scheduled creation + TAP** — `Get-PimScheduledCreationDue` decides, for a
  resolved `ProvisionDate`/`TAPStartDate`, whether the account is due to be
  created now and whether the TAP is inside its lead window (else *deferred*, or
  *waits for the account*). `Get-PimDueScheduledCreations` scans the admin rows
  (resolving the date expressions via `Resolve-PimDateExpression`), skips rows
  already provisioned, and returns the due set with its decision. The
  `scheduled-creation` scheduler job runs this each tick; the container/launcher
  registers the real create handler (the pure layer never touches a tenant).
- **Lifecycle calendar** — `Build-PimLifecycleCalendar` folds the primitives into
  one pass: `upcoming` (horizon, soonest-first), `escalations` (the stage due now
  per item, honouring a per-item notify log so reminders respect the cadence) and
  `renewals` (AutoExtend items in the window). `Get-PimLifecycleRenewalChanges`
  turns renewals into change-queue `Update` records (so renewal flows through the
  normal commit/apply path); `Send-PimLifecycleEscalations` renders + sends the
  reminders via the existing templated mail, resolving symbolic
  `owner`/`manager`/`admin` recipients through a caller resolver (WhatIf-safe).
  The `reminders` and `escalations` scheduler jobs now drive these instead of the
  former stubs.
- **Access-review feedback loop** — `Get-PimAccessReviewDecision` routes each
  assignment to `auto-extend` (the opt-in `AutoExtend` column — owners gate
  skipped) or `owner-approval` (owners parsed pipe-joined from `Owners`, falling
  back to `Department`). `New-PimReviewFeedbackRecord` records the outcome
  (`Deny` → `suppressReAdd=$true`, no new expiry; `Approve` → new expiry) and
  `Test-PimReviewSuppressesReAdd` is the engine guard that stops a denied user
  being silently re-added on reconcile (latest decision wins) — the same intent
  as the §13 tombstone layer, expressed as a pure decision the assignment step
  can call.

### 17.10 Offboarding

The admin lifecycle follows the rule that **moving from v1 must never leave an environment worse
off**: everything v1 enforced is on by default (same settings source), never opt-in.

1. **Admin auto-disable** — column **`AutoDisableDate`** (date expression; was `OffboardDate`, still
   read, see §6.2). At/after that date the `AdminOffboarding` provider (§6.2) runs v1's sequence on
   its own job: disable the account → revoke sessions → remove ALL its PIM group memberships +
   eligibilities → notice mail → **stop**. Each step is audited and recorded in a SQL progress record
   (`pim.Settings['AdminOffboardState']`), so an interrupted run resumes.
   🔴 The v1 retention-delete step and its `DeleteAfterDays` column are **removed from the product**:
   PIM never deletes a user account, and the field is not supported (see §6.2).
2. **Disabled and revoked stay disabled.** The `Admins` provider disables an account whose
   `AccountStatus` is `Disabled` or `Revoked`, or that is past its `AutoDisableDate` (revoking its
   sessions when revoked), and never re-enables it; the auto-disable sweep adds the membership
   half for a revoked admin.
3. **Accounts created when due.** A row with a future provisioning date is held back until due;
   name, job title, company and usage location are set and kept in step. Every cloud admin gets
   a TAP (§6 `AdminTap`) honouring the TAP start date; on-premises AD admins get none.
4. **On-premises AD admins as in v1.** Rows whose platform is AD are created and updated in Active
   Directory (on a hybrid worker, job `hybrid-ad-apply`), in the OU and with the names the
   environment's naming settings produce; the generated initial password is mailed to the owner's
   address (§10) and never stored or logged. They are never touched in Entra ID and raise no
   cloud-only warnings.
5. **Remove rows revoke.** An assignment row marked `Action=Remove` is revoked (eligible and
   active) and the row is then deleted from the store so nothing re-applies it; a removal that is
   held (bulk removals are held for review) or fails keeps its row. Switching a row between
   eligible and active replaces the old type, and a changed duration updates the schedule;
   `AutoExtend` rows are extended before they expire.
6. **Both assignment types are kept unless asked.** When a principal holds a schedule as both
   eligible and active and the row names only one type, the other type is **not** removed unless
   the `RemoveTypeLeftovers` setting is turned on (v1 kept both).
7. **Role / permission-group retirement** — a definition row with **`Lifecycle=Retire`** makes
   the engine (`GroupRetirement`) remove the group's role assignments, then memberships, then
   (only if the engine created it — displayName-prefix guard) the group itself.
8. **Drift cleanup** — `OffboardCleanupMode = 'Off' | 'Report' | 'Enforce'` governs whether
   removals are planned only or applied; prune of live items not in the desired set remains the
   explicit `-Prune` opt-in (§5.2).

### 17.11 Audit — one schema, append-only

All engine and Manager transactions converge on **one append-only SQL table,
`pim.AuditEvents`** (`Write-PimAuditEvent` in the engine, the Manager's audit writer, both through
`Write-PimSqlAuditEvent`). There is no audit file: a trail written to a container's local disk
disappears with the revision, and two trails in two places cannot answer "who granted this access?"
without first knowing which component did it. Each event carries:

```json
{ "ts": "2026-06-12T10:55:01Z", "runId": "…", "correlationId": "…",
  "actor": "engine | manager:<upn> | emergency:<upn>", "actorSource": "engine | manager",
  "action": "account.create | account.disable | account.offboard.revoke | tap.create | policy.apply | revoke.executed | approval.escalate | emergency.activate | config.save | …",
  "target": "<upn | group | role @ scope>", "before": { }, "after": { }, "result": "ok | error:<msg>", "whatIf": false }
```

Times are stored and filtered in UTC, so the view is correct on any
server time zone.

**The engine audits its own changes.** Every membership, role assignment and account change the
engine makes — or fails to make — is recorded with the real person, group, role and scope (names,
not ids), and `runId` is the **job run id**, so an audit entry leads to that run's log (§11.3a).
**Policy changes are audited rule by rule** (before/after per rule, the template, and whether an
approved mass-change plan applied it; §17.7). Queued directory actions — revoke, TAP reset, session
revoke — are audited **when applied**, not only when requested: who asked, what was done to whom, how
it was verified, and the outcome. These engine events count under *Delegations* and *Accounts* in the
Manager's audit categories. A configuration commit is recorded as one readable sentence per changed
row, resolving assignment tags to the real group name. Generated initial passwords and TAP codes never
appear in an event or a log.

Optional sink: events can additionally be forwarded to a Log Analytics custom table
(config-gated, off by default; §18.8). Manager: **Audit & Settings → Audit trail**, a filterable,
exportable read-only viewer (Reader role may view; §18.11).

### 17.12 Manager RBAC — Reader / Admin / SuperAdmin

- **Identity**: hosted, the acting identity is the Easy Auth principal of the request (verified,
  §11.5.2 E); local/loopback, it is the Windows user that launched the Manager
  (`[Security.Principal.WindowsIdentity]::GetCurrent()`). It is recorded on every mutation.
  Hosted with no authenticated principal → Reader (fail closed).
- **Mapping**: the access model lives in SQL, **`pim.Settings['ManagerAccess']`**:
  `{ "managerAccess": [ { "identity": "DOMAIN\\user | upn", "role": "Reader|Admin|SuperAdmin|Delegated" } ] }`,
  read live (cached ~15 s, so a grant applies within seconds) and consulted first; environment
  settings are the bootstrap for a fresh store. It is written by the deploy's `access` step (the
  named SuperAdmins) or `tools/setup/Set-PimManagerAccess.ps1`, which refuses to overwrite an access
  model it could not read and reads the result back, and is shown in **Settings → Manager access &
  roles**. An identity in no source is Reader; a stored model that cannot be parsed is refused, never
  waved through.
- **Gates** (server-side per endpoint; the GUI also hides what the role can't do):

| Capability | Reader | Admin | SuperAdmin |
|---|---|---|---|
| View map/grid/validate/audit | ✔ | ✔ | ✔ |
| Stage + commit CSV edits, revoke, ring moves | | ✔ | ✔ |
| Instance switching, template/policy editing, refresh caches | | | ✔ |
| Emergency override, manager-access editing, maintenance | | | ✔ |

Where these live in the Manager: the audit viewer under **Audit & Settings → Audit trail**; mail
templates, the emergency override and the access list as **Settings** sections; discovered
resources on **Audit & Settings → Newly discovered resources** (§18.1d). The former Governance tab
is gone. Visibility is role-gated. (The finer-grained `Delegated` / portal-admin model layers on
top — §9.2.)

### 17.13 Resource auto-discovery

`_tenantSync.ps1` snapshots Entra roles, AUs, Azure scopes, and PIM groups.
Discovery = diff current vs previous snapshot
(`cache/<instance>/discovery-baseline.json`): new Azure subscriptions / management
groups, new built-in Entra roles, and (via connector live role listing) new
workload resources such as Power BI workspaces surface as **discovered items**. Per
resource type, `config/resource-discovery.custom.json` selects handling:
`"Off" | "Portal" | "Engine"`. **Portal**: the Newly discovered resources page lists items; one
click stages naming-convention-generated definition + assignment rows into pending.
**Engine**: the engine auto-generates and applies the same rows on its run (zero
touch), emitting `resource.discovered` + `resource.onboarded` audit events and a
`new-permission` mail. Row generation reuses the naming-conventions module.

**REST engine discovery layer (`engine/_shared/PIM-Discovery.ps1`).** The new
module-free engine carries its own discovery, alongside the Azure scope reconcile
planner (`PIM-AzureDiscovery.ps1`). It splits cleanly into pure planners (offline,
unit-tested) and thin REST enumerators (the only side-effecting parts):

- **Live enumerators (REST-only via `PIM-Rest`, best-effort → empty on failure):**
  `Get-PimLiveAzureScopes` lists ARM subscriptions and management groups,
  `Get-PimLivePowerBiWorkspaces` lists Power BI / Fabric workspaces (admin API,
  falling back to the per-principal list), and `Get-PimLiveServiceRoles` lists the
  built-in role definitions of a Graph-native service (Entra / Defender / Intune).
  Each normalises to the shape its planner consumes, so a missing permission or
  unavailable adapter degrades to "nothing discovered" rather than failing a run.
- **Power BI workspace planner** mirrors the Azure scope planner exactly: a stable
  key (the workspace GUID) makes a rename a *rename in place* (not orphan + dup),
  and `Get-PimPowerBiReconcilePlan` classifies create / rename / orphan / unchanged.
  Each new workspace derives a correctly-classified container group
  (`PIM-PowerBI-WS-<name>-L3-T1-WDP-DAT`) via the shared naming module.
- **Auto-map gate (`Resolve-PimDiscoveryAutoMap`)** is the single chokepoint for the
  "propose, never auto-map" rule: it turns a reconcile plan's CREATE candidates into
  empty permission-group **container definitions** (only the auto-imported ones; the
  rest stay *pending* for a human) and returns an **always-empty assignment list** —
  discovery never grants a principal access.
- **Role catalog delta (`Get-PimRoleCatalogDelta`)** folds live service roles against
  the previously-catalogued set so only genuinely new built-in roles surface.
- **Delta refinement (`Get-PimDiscoveryDelta`)** returns only stable keys not in the
  handled set and rolls that set forward, so a handled item never reappears (the
  array-index delta pattern), with the handled set persisted per scope under
  `output/state/`.

Reconcile plans convert to change-queue records the same way for both Azure and
Power BI (`ConvertTo-PimReconcileQueueChanges` / `ConvertTo-PimPowerBiQueueChanges`):
auto-imports → Create, renames → Update (carrying from/to), orphans → Remove only
behind `-IncludeOrphanRemovals` (deletion is never automatic).

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
- **The Manager GUI** is the attended path: the Manager shows the queue;
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

### 17.16a Auth / identity diagnostics (built — `engine/_shared/PIM-AuthDiagnostics.ps1`)

A single shared, dependency-free helper file (dot-sourced by `PIM-Functions.psm1`
right after `PIM-Rest.ps1`, so the engine, Manager and validator all see it; PS 5.1 +
7 safe, no Graph/Az/MSAL). Each helper separates a **pure decision** from any
network/host call so the whole layer is offline-testable. Four capabilities:

1. **Missing-role hint** — `Get-PimMissingRoleHint` maps a Graph/ARM 403 (detected by
   `Test-PimIsAuthForbidden`: HTTP 401/403 or an `Authorization_RequestDenied` /
   "Insufficient privileges" / `AuthorizationFailed` body) to the EXACT remediation. An
   ordered path→role table turns the failing API path into the precise Graph
   **application role** the engine SPN is missing (e.g. `roleManagementPolicies` →
   `RoleManagementPolicy.ReadWrite.AzureADGroup`, `/users` → `User.ReadWrite.All`,
   `accessReviews` → `AccessReview.Read.All`) plus the `setup/Grant-PimGraphAppRoles.ps1`
   command to add it; in **interactive** context it instead names the directory role to
   ACTIVATE in PIM (Privileged Role Administrator, etc.). A non-403 returns `$null` so the
   real error is never masked. `Invoke-PimRest` appends the hint (` >> …`) to the thrown
   message on a 403, so every Graph/ARM call in the solution self-explains a permission gap.
   **ARM plane + connector coverage (✅ 2026-06-17):** table entries now carry a `plane`
   flag. An **ARM** path (`management.azure.com`, `/subscriptions/…`,
   `providers/Microsoft.Authorization/roleAssignments|roleManagementPolicies|roleEligibilitySchedules`)
   resolves to `Plane='arm'` and the hint is worded as a missing **Azure RBAC role at the
   scope** (User Access Administrator for the role-assignment paths, Reader/Contributor for
   a general scope) — explicitly NOT a Graph app-role / `Grant-PimGraphAppRoles` consent, so
   an `AuthorizationFailed` is no longer mis-hinted toward the wrong fix. The newer workload
   connectors also have entries — `appRoleAssignedTo` → `AppRoleAssignment.ReadWrite.All`
   (ordered before the generic `servicePrincipals/`), `deviceManagement/role*` → the Intune
   RBAC role, `roleManagement/defender` → the Defender Unified-RBAC role. The returned object
   carries a `Plane` field (`graph`/`arm`) so callers can branch on the plane.
2. **Account sign-in prompt clarity** — `ConvertTo-PimAuthCodePrompt` resolves the OAuth
   `prompt` (`select_account` by default so the picker is always shown; `login` when a fresh
   sign-in is forced or a stale account is known). `Get-PimInteractiveToken` (the Edge PKCE
   loopback) gained `-ForceFreshAccount` + `-ExpectedAccount` (adds `login_hint`), and
   `Get-PimAccountSignInHint` reports a cached≠expected mismatch — a stale cached account is
   never reused silently.
3. **AD-failure diagnostics** — `Resolve-PimAdFailureDiagnostic` (pure) classifies a hybrid-AD
   failure from facts: is the running identity SYSTEM / a machine account (`…$`) rather than a
   domain user, was a `-Credential` supplied, are Kerberos tickets present, was a DC
   discovered — emitting an ordered cause list + the single most useful next step (fix the
   credential vs the DC/DNS vs the target ACL). `Get-PimAdFailureDiagnostic` is the
   best-effort live wrapper (reads `WindowsIdentity`, `klist`, `nltest /dsgetdc`) and never
   throws. The CSV engine's `Get-ADUser` failure branch now prints this diagnostic instead
   of a bare module error.
4. **MFA-gated Manager login** — `ConvertFrom-PimJwtClaims` decodes a token's claims with no
   library (base64url, after the token already arrived over TLS — not a trust anchor);
   `Test-PimTokenHasMfa` proves MFA from the `amr` claim (`mfa`/`fido`/`hwk`/`otp`/… or
   `acr=1`), failing **closed** when absent. `Assert-PimManagerMfa` is the decision: **hosted
   → no-op** (App Service Easy Auth + CA already enforced MFA at the edge — the gate must
   never break Easy Auth), **local/loopback → require an MFA-proven token** obtained via the
   Edge PKCE loopback (never device-code, never the system browser). `Open-PimManager.ps1`
   wires it on the local edition only, **opt-in** via `$global:PIM_RequireMfaLogin` /
   `PIM_RequireMfaLogin=1` (backward-compatible single-operator installs are unaffected);
   a denial explains what to do and never silently bricks the break-glass path.
4a. **Proactive token-claims role pre-flight (✅ 2026-06-17)** — the missing-role hint above
   is *reactive* (fires after a 403). The pre-flight is *proactive*: before an interactive
   operator performs a privileged change, `Test-PimOperationRolePreflight` reads the
   operator's token claims and decides whether the directory role the action needs is
   **already active**, so the operator is told to "activate it in PIM" up front instead of
   driving to a 403. Pure (claims in → decision out; the token already arrived over TLS via
   the Edge PKCE loopback — claims are a UX signal, never a trust anchor; Entra still enforces
   at the call). Pieces: `Resolve-PimActiveDirectoryRoleTemplateIds` extracts the `wids`
   claim (the well-known directory-role **template ids that are ACTIVE** for the user — an
   eligible-but-not-activated PIM role is absent, which is exactly the "must activate" signal),
   lower-cased + empty-dropped. `Resolve-PimRequiredRolesForOperation` maps an operation —
   a canonical name (`pim-policy`, `access-review`, `app-role-assignment`, `administrative-unit`,
   `user-write`, …) **or** the Graph/ARM path about to be called — to the acceptable role(s)
   (any one suffices; Global Administrator always satisfies). `$script:PimWidsByRoleName` is
   the stable Microsoft template-id constants table. `Test-PimOperationRolePreflight` returns
   `{Operation, Required, Allowed, RequiredRoles, ActiveRoleTemplateIds, MatchedRole, Source,
   Hint}`: an unknown/benign op → `Required=$false, Allowed=$true` (never blocks a benign
   call); a matching active `wids` → `Allowed=$true` + `MatchedRole`; none active (or an
   absent/unreadable `wids`) on a privileged op → `Allowed=$false` + an up-front activate
   hint (**fail closed** — never a silent pass). An **app-only engine context** has no
   interactive `wids`, so `-AppOnly $true` makes it a no-op (`Allowed=$true`) — the engine SPN
   uses app-roles, handled by the reactive hint above. Super-admin/break-glass paths are never
   blocked (the gate is advisory; callers keep their existing override).
5. **Support / diagnostics** — three more pure cores in the same
   file, all probe-INJECTABLE so they are unit-tested without a tenant. `Get-PimConnectivityCheck`
   classifies ONE injected probe outcome (`sql` / `graph` / `arm`) into `pass` / `fail` /
   `skipped` with an actionable hint — Graph/ARM permission failures reuse `Get-PimMissingRoleHint`
   (so the diagnostics surface names the SAME missing app-role the engine does), SQL auth failures
   emit the contained-DB-user grant recipe, and unreachable cases emit a connectivity hint;
   `arm` is `skipped` unless the instance has an Azure scope. `Get-PimSupportHealthSummary` folds
   injected state (store mode, per-kind tenant-cache freshness from `Get-PimCacheFreshness`, the
   last engine/job run from `Get-PimJobsStatus`, the instance identity) into one summary with a
   worst-case cache verdict and a green/red/unknown last-run status. `New-PimDiagnosticsBundle`
   assembles versions + checks + health + non-secret config + recent runs and runs the whole
   serialized form through `Protect-PimDiagnosticsText`, which masks PEM key/cert blocks, Bearer/JWT
   tokens, connection-string credential fields (`Password`/`User ID`/`AccountKey`/SAS `sig=`),
   generic `secret`/`key`/`token`-shaped key=value pairs, 40-hex cert thumbprints, and every GUID
   (keeping the first 8 chars for correlation, masking the tail) — so the downloadable bundle can
   never carry a secret / cert / token / connection-string / full tenant+subscription GUID. The
   Manager wrapper `Get-PimSupportDiagnostics` (in `Open-PimManager.ps1`) does the best-effort LIVE
   probes (each guarded — diagnostics never throw) and feeds the outcomes into these pure cores;
   `GET /api/support/diagnostics` (checks + health) and `GET /api/support/bundle` (the sanitized
   download text + object) back the **Support** tab's "Run checks" + "Download diagnostics bundle"
   controls. The hosted/SQL Manager GUI smoke remains the live gate.

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
   **Decision core (delivered):** `engine/_shared/PIM-InactivitySweep.ps1` is a PURE,
   offline-testable core that does NO I/O and NO destructive write. `Get-PimAdminLastSignInDays`
   converts a sign-in stamp (ISO string / `[datetime]` / `$null`) into whole days since
   (a `$null` = never/unknown, a future stamp clamps to 0); `Resolve-PimInactivityThreshold`
   resolves the per-row/per-unit `InactivityDisableDays` (→ global `$PIM_InactivityDisableDays`
   → caller default), where `0`/blank means *not swept* (the feature is opt-in per unit);
   `Test-PimAdminSweepProtected` marks break-glass / emergency / super-admin / explicitly-flagged
   accounts as never-auto-disable. `Get-PimInactivitySweepPlan` classifies each admin
   (active / inactive / never-signed-in / not-swept / protected / already-disabled) and assigns an
   action per mode — **Report (default) → `flag`** (surface for a human, disable nothing),
   **Enforce → `disable`** for non-protected candidates. `Get-PimInactivitySweepDecision` then
   composes the EXISTING account-disable circuit breaker (`Test-PimDisablePassAllowed` —
   G1 positively-resolved desired set, G2 mass-disable blast-radius cap, G3 env-aware opt-in)
   so an Enforce sweep can **never mass-disable**: it fails closed if the guard lib isn't loaded,
   is blocked when opted-out / desired-unresolved / over-cap, and only reports `willDisable > 0`
   within all three limits. The lib returns the plan + the verdict; the **already-built,
   approval-gated account-status path is the only thing that performs a disable** (this lib never
   writes). Offline proof: `tests/Test-PimInactivitySweep.ps1` (37 assertions). *Remaining:* the
   scheduler `inactivity-sweep` job + launcher glue that feeds live `signInActivity`
   (Graph `AuditLog.Read.All`) into the plan and routes Enforce through the approval-gated
   executor, a read-only Manager surface for the Report rows, and the live tenant run; Enforce
   stays OFF in a protected tenant (§13 operator policy) until those exist.
5. **Azure scope slicing**: already native; the unit's `AllowedAzScopePrefix`
   confines self-service rows to subscriptions under the unit's management group.

Build order when scheduled: §17.17 (contacts/routing) → intake processor
(§17.15) → delegation-unit filter → inactivity sweep → portal front end last.

### 17.19 Phasing summary

Date-expression resolver + ProvisionDate/TAPLifetimeHours + TAP deferral + TAP GUI
grouping + ring-move UI + validators; admin templates + mail templates + policy
templates + hash re-apply; approvals (parallel native + serial escalation, Owners
functional); offboarding + drift cleanup; unified jsonl audit; Manager RBAC;
emergency override — all built across the v2.4.15x line. Access
reviews, external intake, and the Manager-MFA + SQL data store (the v3.0 line) are
agreed design, not yet built. (Exact per-phase status lives in `REQUIREMENTS.md`.)

### Out of scope / known limitations (this area)

- Holiday-aware workday calculation (Mon–Fri only).
- Serial-approval escalation latency bounded by engine run frequency.
- Mail-template GUI editor (file-based editing first).

---

## 18. Manager / GUI + UX

![PIM Manager — Home / Overview dashboard](img/manager-home.png)
*Home / Overview, the attention dashboard the Manager opens on (§18.1b). (Synthetic demo data.)*

![The six-menu navigation with a dropdown open](img/manager-nav.png)
*The six top-level menus with one-line descriptions and attention counts (§18.1d). (Synthetic demo data.)*

### 18.1 What the Manager is

Interactive map + grid editor + review/commit queue for the configuration model: a single-page
app served by `Open-PimManager.ps1` (an HttpListener bound to loopback locally). Loads in any
browser, no install beyond the code. In the hosted topology it runs as a Container App behind
Easy Auth sign-in (§11), reading and writing SQL only, with a read-only directory identity — every
tenant change is queued for the engine. It is the answer to "what does activating PIM-ROLE-X
actually let me do?" — it reads the model and shows the Admin → Role group →
Permission group → Service chain visually, with a tier-coloured board.

### 18.1a Access map (formerly Delegation Map) — the node/edge model and the PERMISSIONS & TARGETS column

![Access map — admin to direct group to permission group to target, with the risk overlay on](img/manager-access-map.png)
*The four-column Access map with the risk overlay enabled. (Synthetic demo data.)*

**Direct groups sit together.** `Build-PimGraphData` emits Roles **and** Departments, Organization,
Projects and Cross-org definitions as `role-group` nodes (direct groups — "what people are assigned
to") in column 2, so their nestings into permission groups are real cross-column edges and selecting a
department shows the permissions it is linked to. (Emitting them as permission groups put them in the
bundle column, where their nestings became same-column hops and were dropped.) Names are joined
case-insensitively for every connection kind, and a name that matches nothing is reported rather than
silently dropped. The Workload recon control appears only when the board has workload targets.

The Delegation Map is a four-column flow board: **People** (admins) → **Roles &
Org Groups** → **Capability Bundles** (permission groups) → **Permissions &
Targets**. `Build-PimGraphData` (`tools/pim-manager/Open-PimManager.ps1`)
recomputes the node/edge model on every page render from the live store (SQL via
`Read-PimRows`/`Get-PimSqlRows`, or the config files in local/dev mode).

**Rows come from SQL, not CSV.** The Map is built from `pim.Rows`, where every record is stored as
JSON keyed by its column names, so there is no header line to parse and the quoted / BOM-prefixed /
Excel-export header problem that once blanked the Map cannot occur in the Manager. Converting a v1
(file-based) CSV installation is a one-time import (`setup/Migrate-PimToSql.ps1`).
Columns 1–3 are *definition* nodes (admins, role/org groups, permission groups).
Column 4 nodes are **synthetic targets** — they don't exist as definition rows;
they are derived from the *assignment* rows that bind a group to a permission:

| Target kind | Built from | id shape | Enriched fields (for the GUI) |
|---|---|---|---|
| `entra-role` | `PIM-Assignments-Roles-Groups` | `entra-role:<RoleName>` | `roleName` |
| `au-role` | `PIM-Assignments-Roles-AUs` | `au-role:<AUTag>:<RoleName>` | `roleName`, `auTag` |
| `az-resource` | `PIM-Assignments-Azure-Resources` | `az-res:<AzScope>:<Perm>` | `roleName`, `scopePath` (full), `scopeType`, `scopeShort` |
| `workload-target` | `PIM-Assignments-Workloads` | `workload:<id>:<RoleName>:<Scope>` | `workloadId`, `workloadName`, `roleName`, `scopePath`, `scopeType`, `scopeShort` (+ recon `reconStatus`/`reconReason`/`reconCrawledUtc`) |

`scopeType` is humanised from the ARM/path scope by `$azScopeMeta`: a
`/managementGroups/<x>` path → *Management group*, `/resourceGroups/<x>` →
*Resource group*, a bare `/subscriptions/<x>` → *Subscription*, a deeper resource
path → *Resource*, and non-ARM workload scopes are recognised as *Power BI
workspace* / *Azure DevOps project*. `scopeShort` is the human leaf name used in
the short label; `scopePath` keeps the full original for the tooltip/expand.

The GUI (`pim-manager.html`) renders these in column 4 (`#mapCol3`) grouped under
ENTRA ID ROLES / AU-SCOPED ROLES / AZURE RBAC @ SCOPE. When an operator selects a
capability bundle or role group, `mapRenderDetail` calls `mapTargetBreakdown`,
which walks the down-BFS reachable set, collects the column-4 targets, and renders
a grouped **chip list**: each chip shows the short label (`<role> @ <scopeShort>`),
carries the full detail in `data-full` + a `title` tooltip, and toggles a
click-to-expand (`.exp`) that swaps the short label for the full scope path / AU /
workspace / project. This is the answer to "this bundle — what does it actually
grant, and where?" without leaving the map. The column was previously populated as
bare `<perm> @ <last-segment>` labels with a count-only detail panel (the
user-reported "empty" state); the enrichment + breakdown make the real grant
legible. Edits are confined to the PERMISSIONS & TARGETS column so the shared
`pim-manager.html` stays union-mergeable across the Manager agents.

**Workload targets + live-crawl reconciliation.** The fourth target kind,
`workload-target`, is the same node/edge pattern over `PIM-Assignments-Workloads`
(workload connector role bindings: Defender XDR / Intune / Power BI / Power
Platform / Business Central / Azure DevOps / Dataverse / app-roles). The workload
friendly name is resolved from the connector catalog (`Read-PimWorkloadConnectors`,
id→name); the scope is humanised by `$workloadScopeMeta` (ARM paths reuse
`$azScopeMeta`; otherwise labelled by connector kind, with `/`→*Tenant-wide*).
Because the desired CSV alone can't say whether a binding is actually live, a
separate **crawl-map** layer (`engine/_shared/PIM-WorkloadMap.ps1`) closes the
loop: the engine/scheduler runs `Update-PimWorkloadCrawlMap` (the WRITER) which
calls every connector's `listAssignments`, normalises role+scope+principalIds, and
persists the result in the SQL settings store as `pim.Settings['WorkloadCrawlMap']`
(stamped `crawledUtc`; each connector best-effort `{ok,error}`; there is no crawl
file, so the map survives a revision roll). At map-build time the GUI reads that
map (`Read-PimWorkloadCrawlMap`) plus the exemption store
(`Read-PimWorkloadExemptions`, `pim.Settings['WorkloadExemptions']`; contract
mirroring `PIM-WarningOverrides`: mandatory reason + expiry, or `noExpiry`) and stamps
each `workload-target` with a PURE reconciliation verdict (`Get-PimWorkloadReconStatus`,
no network): **mapped** (live = desired), **missing** (desired, not live — a
candidate to push via the connector `assign`), **exempted** (an active exemption
covers it), or **unknown** (the workload wasn't crawled / its crawl errored — never
a false *missing*). The verdict drives the col-3 board badge + chip badge + the
"Workload recon" summary (`GET /api/workload-recon`); admins can trigger a fresh
sweep with `POST /api/workload-crawl`. The engine remains the only writer; the GUI
read path is side-effect-free. `GET /api/workload-crawl` is a server-authoritative
parity read of the raw crawl map (tooling/tests/scheduler), the same pattern as
`/api/map-risk`.

Exemptions are edited in **Settings → Workload exemptions** (`GET/PUT
/api/workload-exemptions`): everyone can read the list with its active/expired state;
Admin+ adds and removes. A save sends the full list; an incomplete entry (no workload
or role, no reason, no or unreadable expiry) refuses the whole save instead of being
dropped, and a valid save is stored through `Save-PimWorkloadExemptions` and audited
with before and after. A one-time import (`setup/Migrate-PimToSql.ps1`) takes a v1
exemptions file into the same setting when the store holds none. The **Feature
customization** card shows the connector's *effective* state: with no stored value,
`connectors.workload` is on while workload assignment rows exist
(`autoEnableWhenData`), and the card says *On: N workload rows* while the toggle keeps
showing the stored value, so saving the card does not pin the feature on.

### 18.1b Home / Overview tab + Alerting

The Manager's **landing tab is Home** (`#homeTab`, `data-tab="home"` is first and
carries `class="tab active"`; the Delegation Map is no longer the default panel).
Home is a "what needs my attention" dashboard rendered by `renderHome()` from a
single aggregation endpoint.

**`GET /api/home` → `Get-PimHomeOverview`** correlates the EXISTING data sources
into a tile payload — it adds no new data store, it reads what the other tabs
already read:

| Tile | Source (function / file) |
|---|---|
| Delegation by tier (L0–L5) + admin count | `Build-PimGraphData` nodes; level via `Get-PimDelegationTierLevel` (explicit `Level`/`tier`, else `-L#-`/`-T#-` parsed from the GroupTag/label) |
| Gaps / orphans / unmanaged | `Build-PimGraphData` nodes+edges: groups/admins/targets whose id is in no edge endpoint |
| Engine & jobs health + **FAILED jobs** + running + last/next run + **drift** | `Get-PimJobsStatus` over `Get-PimManagerEffectiveSchedule` (a job with `lastOk -eq $false` = failed); red when any failed. **Drift** (`tiles.jobs.drift`) = the most-recent **engine** reconcile run (type `^engine`) that *applied* changes (`lastRan = $true`) ⇒ the live estate had drifted from desired and was corrected; a clean delta = no drift; a failed reconcile can't assert "no drift" (`knownOk`). Non-engine jobs never carry a drift signal. |
| Validation errors/warnings | `Invoke-PimPreflightValidation` `.summary` (re-uses the cached report when present) |
| Break-glass active | `pim.Settings['EmergencyOverride']` (active && not expired) |
| Expiring access (14d) | the `active-assignments-snapshot` rows (`Get-PimActiveAssignmentsCached`, §11.1) with `end` within the window, stamped with the snapshot time |
| Permission banner | refusals recorded by the **scheduled engine** as well as the Manager's own identity; turns **red** and names the refused permission when the engine was refused |
| Pending access reviews | `Get-PimAccessReviewOverview` (live) → `Get-PimAccessReviewSeedRows` (seed) |

Each tile section is wrapped in its own `try/catch`, so an unavailable source
degrades to an honest empty/error state for THAT tile only — the page never goes
dead (the "no dead views" invariant). The expiring-access tile reads the stored snapshot, so it never
performs a live tenant read; the pending-access-reviews tile is still a live read, so it runs only when
an admin clicks **Load live data (slow)** (`GET /api/home?include=heavy`), never on page open. Every tile is a `.home-tile-link` that
`switchTab`s to the tab owning its detail; a red badge on the Home tab sums the
attention items.

**"What needs my attention" call-out.** Above the tiles,
`renderHome()` renders a consolidated, prioritized call-out (`#homeAttnCallout`,
`homeCalloutHtml()`). As each tile is computed it pushes any attention-worthy signal
via `homeAddAttn(sev, text, tab)` into a single list drawn from the SAME tile data
(so the call-out can never disagree with the tiles): FAILED jobs + drift (engine/jobs
tile), validation errors, gaps/orphans/unmanaged, active break-glass, pending
approvals, and — folded in after the heavy load — expiring access + pending access
reviews. The list renders red items first, then amber, each row a `.home-attn-link`
that deep-links to its tab; when nothing needs attention it renders an honest
all-clear state (never blank). `homeWireLinks()` wires both `.home-tile-link` and
`.home-attn-link` on first paint and again after the heavy tiles + call-out refresh.

**Tier / plane legend.** A collapsible legend (`homeLegendHtml()`,
a `<details>` below the tiles) gives a plain-language key for the **L0–L5** tiers and
the **CP / MP / WDP** planes the estate is organized by, so the tab stays
understandable and trustworthy even when the seeded/live data is sparse. It is static
content (no data dependency).

> Implementation note: nodes/edges from `Build-PimGraphData` are `[ordered]`
> dictionaries — `$obj.PSObject.Properties[$key]` does NOT see dictionary keys, so
> the aggregator reads endpoints by dot-access. The alerting config reader handles
> both dictionary (in-process / file round-trip) and PSCustomObject (JSON) shapes.

**Alerting (`Get-/Set-PimAlertingConfig`, `Send-PimManagerAlert`).** The config
(recipients + per-event on/off) is persisted under the `Alerting` key in the SAME
store as every other Manager setting (`Set-PimManagerSetting` → SQL `pim.Settings`
hosted, else the per-instance JSON file). Events: `engine-failure`, `drift`,
`expiring-access`, `break-glass` (all default ON). Delivery rides the EXISTING
notify path — `Send-PimManagerAlert` renders the shipped `alert-notice` mail
template via `Send-PimNotifyMail` (Graph `Mail.Send`, gated on
`$global:PIM_MailSender`) and fans out to every recipient; with no sender it renders
only (the honest "configure to enable" state, `enabled=$false`), never a fake send.
The Manager dot-sources `engine/_shared/PIM-Notify.ps1` at boot for this. Endpoints:
`GET/PUT /api/alerting` (PUT Admin+) and `POST /api/alerting/test` (Admin+, sends a
test through the real path). Alerts FIRE from real engine/audit events: a job that
finishes not-ok in `POST /api/jobs/run` raises `engine-failure`; activating the
emergency override (`POST /api/emergency`) raises `break-glass`; a non-empty drift
report on `GET /api/drift` raises `drift`; and the Home heavy path raises
`expiring-access` when the live active-assignment read finds access lapsing inside the
window. The alerting card lives in the Settings tab (`renderAlertingCard`, Admin+
editable, independent of the SuperAdmin gate on the rest of Settings) and is
deep-linked from Home.

**Alert FEED + recorded-send proof (`engine/_shared/PIM-AlertFeed.ps1`).** The PUSH
side's durable record — closes the residual gap ("a break-glass 'owners notified'
claim is unverifiable with no send/proof subsystem"). The pure, offline-testable core
is storage-agnostic: `New-PimAlertRecord` folds a `Send-PimManagerAlert` result into a
proof record (`id`, `ts`, `event`, `title`, `detail`, `recipients`, `sent`,
`sendState` ∈ `sent`|`rendered`|`suppressed`, `whatIf`, tenant/instance);
`Get-PimAlertDedupeKey` + `Test-PimAlertDebounced` debounce identical repeats within a
window (event+normalised title+detail, not the timestamp); `Add-PimAlertToFeed`
prepends newest-first and clamps to a cap; `Select-PimAlertFeed` filters
(event/sentOnly/since) + pages; `Get-PimAlertFeedSummary` rolls the feed into the Home
tile (total/sent/unsent/per-event/latest, window-bounded); `Get-PimExpiringAccessAlert`
is the PURE fire decision for the expiring-access event (rows + now + window →
`{fire;count;detail;items}`). The only I/O is the SQL adapter (`Read-`/`Write-PimAlertFeedSql`:
one bounded document in the settings store, clamped to the cap); there is no feed file —
the product keeps no data in files. `Send-PimManagerAlert` now (a)
debounces via the feed before fanning out (`DebounceMinutes`, default 60; the test
endpoint passes 0; expiring-access uses 1440 so the same expiring set re-alerts at most
daily), and (b) records the outcome of every fire to the feed — so the feed is the
durable WOULD-SEND/DID-SEND proof; it never sends anything itself. Read endpoint:
`GET /api/alerts` (`?event=`/`?sentOnly=1`/`?take=`) returns the filtered feed +
summary + catalog; it is wired into the alerting card's "Recent alerts" view
(`renderAlertFeed`) and a Home "Recent alerts" tile (`tiles.alerts`). The feed
lives in SQL `pim.Settings['AlertFeed']` only (reader and writer share one store). The Manager dot-sources `PIM-AlertFeed.ps1` at boot. No real mail is ever sent
at test time (no `$global:PIM_MailSender` offline → rendered-only).

**Outbound alert CHANNELS — Teams / generic webhook (`engine/_shared/PIM-AlertChannels.ps1`).**
A SECOND delivery channel beside email, channel-agnostic behind the same
`Send-PimManagerAlert`. The pure, offline core:
`Test-PimWebhookUrlAllowed` is the SSRF guard — only an **https** URL with a public host
is accepted; http, loopback/`localhost`, private (10/172.16-31/192.168), link-local
(169.254, fe80::/10), unique-local (fc00::/7), unspecified, and bare dot-less hostnames
are rejected with a reason. `Resolve-PimWebhookKind` classifies a URL `teams` (when the
host is a `*.webhook.office.com` / `office.com` / `logic.azure.com` endpoint) vs
`generic`, with an explicit override winning. `New-PimWebhookPayload` renders ONE alert
into the channel body: a legacy **Teams MessageCard** (theme colour by severity —
break-glass/engine-failure red, drift amber, expiring-access blue — title, detail,
Event/Tenant/Instance/When facts, and an `OpenUri` deep-link back to the Manager tab) or
a flat **generic JSON** object (`source`/`event`/`title`/`detail`/`severity`/tenant/
instance/link/`whenUtc`). `Get-PimAlertChannelConfig` normalises the stored value (the
same dual hashtable/PSObject/JSON-string tolerance as the rest of the settings) and keeps
a URL only when it passes the safety check — a bad URL leaves the channel disabled (kept
verbatim so the operator can read/clear it). The only I/O is the Manager's
`Send-PimWebhookAlert` (`Open-PimManager.ps1`): it builds the payload, re-checks the URL,
and `Invoke-RestMethod` POSTs it (REST-only, 20s timeout) — never throws. The webhook
config rides the SAME `Alerting` settings key (`webhookUrl`, `webhookKind`) and
`Get-/Set-PimAlertingConfig` + `GET/PUT /api/alerting` carry it. `Send-PimManagerAlert`
fires the webhook IN ADDITION to mail (and can fire webhook-only when no mailbox is
configured), counts a delivered webhook into the result `sent` so the same feed record
reflects it, and writes a two-channel reason line (`Get-PimChannelDedupeNote`, e.g.
`mail: 2 sent; webhook(teams): delivered`). The Settings alerting card adds the webhook
URL + format selector (Admin+). No real outbound POST happens at test time (offline tests
exercise only the pure render/safety + the config round-trip).

**Operational policy (`Get-/Set-PimOperationalPolicy`).** A second Settings config
surface covers the three operational knobs that the Alerting surface does NOT:
**expiry-policy defaults** (default/max activation duration, max eligibility
duration), the **MFA-on-activation** toggle, and **connection-sanity** config (SQL /
Graph probe timeouts + required-checks). All three persist under a single
`OperationalPolicy` key through the SAME chokepoint as every other Manager setting
(`Set-PimManagerSetting` → SQL `pim.Settings` hosted, else the per-instance JSON
file) — so the engine and scheduler/jobs that read `pim.Settings` see exactly what
the GUI saved (GUI state == runtime behavior). The normalize/validate/**clamp** logic
is a PURE shared lib, `engine/_shared/PIM-OperationalPolicy.ps1`
(`ConvertTo-PimNormalizedOperationalPolicy`), dot-sourced into the Manager at boot, so
the engine and GUI agree on the value: durations are validated against an allowed ISO-
8601 catalog (out-of-list → kept-default + warning), timeouts are clamped to 1–300s,
and a default activation longer than the configured max is clamped down — invalid
input is **rejected/clamped with a surfaced warning, never silently dropped**. The
store always reads fully-populated, secure defaults (MFA on, `PT8H`/`P1D`/`P365D`,
15/30s probe timeouts) even when empty. Endpoints: `GET/PUT
/api/settings/operational-policy` (PUT SuperAdmin-gated, like the rest of Settings);
the value is also folded into `GET /api/settings`. The card lives in the Settings tab
(`renderOpPolicyCard`). Persisting + exposing the config is the in-scope deliverable;
applying MFA/expiry to live activation policies remains the template-driven engine
path (PIM-for-Groups policy parity), and alert SENDING rides the existing notify seam.

### 18.1c Visibility & reporting — "who can do what", global search, export everywhere

![Reports — "who can do what", showing a person's reachable targets and the exact granting path](img/manager-reports.png)
*The Reports surface: a person's reachable targets with the exact granting path. (Synthetic demo data.)*

Three read-only, engine-backed surfaces answer the access-audit questions an admin
runs day to day. All read the **same live delegation model** the Delegation Map
renders, so a report row or search hit always traces to real desired-state data
(SQL in hosted mode, the desired store otherwise) — never a separate or cached copy.

**Shared model.** `Get-PimAccessGraphModel` (in `Open-PimManager.ps1`) calls
`Build-PimGraphData` once and builds fast lookups for traversal: a node index plus
**normalized reach edges**. Most edges flow source→target as emitted
(admin→group, group→Entra-role/AU-role/Azure-RBAC target). A **group nesting**
edge (`group-to-group`) is emitted container→member but a member inherits the
container's grants, so the model **orients it by board column** (admin=0, role
group=1, permission group=2, target=3): reach flows low-column→high-column, and a
same-column nesting is dropped (the same rule the Delegation Map's `buildMapModel`
uses to avoid over-reach). Cosmetic (`au-to-au-role`) edges are excluded.

**"Who can do what" (forward + reverse).**
- Forward — `Get-PimReachableTargets -Person <UPN>` BFS-walks outgoing reach edges
  from the person, recording every terminal target (Entra role / AU-scoped role /
  Azure RBAC @ scope) **with the activation path** (the chain of groups it came
  through). Cycle-safe (per-branch visited set), depth-bounded. Endpoint:
  `GET /api/access-report/who-can?person=`.
- Reverse — `Get-PimRoleReachers -Role <name|id> [-Kind …]` resolves the role/target
  node(s) (by id, role name or label), then BFS-walks **incoming** edges to every
  person who can reach it, again with the path. Honest zero when nothing grants it.
  Endpoint: `GET /api/access-report/who-has?role=`.
The **Reports** tab (`renderReports()`/`runReport()`/`renderReportResult()`) drives
both, with a person/role datalist sourced from the live nodes and a printable +
CSV-exportable result table.

**Global search.** `Get-PimGlobalSearch -Query` matches the live nodes by label /
id / groupTag / roleName / scopePath / scopeShort / AU tag (+ a derived **tag**
facet) and returns typed hits (person / group / role / scope / tag), type-ordered.
Endpoint: `GET /api/search?q=`. The header box (`initGlobalSearch()`) debounces,
renders a results dropdown, and on click jumps to the owning surface — a person or
role opens the matching report; a group, scope or tag focuses the Delegation Map.

**Export everywhere.** Shared client helpers (`csvCell`/`rowsToCsv`/`downloadCsv`
and `printTable`, exposed as an `exportBarHtml`/`wireExportBar` pair) add **Export
CSV** + **Print** to the Reports, Delegation Map, Validate, Access Review and Audit
views. CSV is **injection-safe**: a cell beginning with `= + - @` or a control char
is prefixed with a single quote so a spreadsheet never evaluates it as a formula,
delimiters/quotes/newlines are RFC-quoted, and a UTF-8 BOM is prepended for Excel.
Print renders a clean, titled, tenant-stamped (name + GUID, date, row count) table
in a hidden iframe — a deliberate, button-initiated print, never an auto-opened
render file. Exports reflect exactly the rows the operator currently sees (the
caller passes its rendered/filtered set; no separate fetch).

The same `exportBarHtml`/`wireExportBar` pair was extended to the
**Role Lookup** tab — all four modes (what-a-role-can-do, find-roles-by-action,
who-can-activate, compare-two-roles) — and the **Maintenance** active-assignments
list, so a "who has what" / role-permission extract is one click for a
least-privilege ticket or auditor trail. The Role Lookup flattening has a pure,
PS-5.1-safe parity core — `engine/_shared/PIM-RolePermissionsExport.ps1` —
mirroring the GUI `csvCell`/`rowsToCsv` (and the audit export's
`ConvertTo-PimAuditCsvCell` formula-injection guard): `Get-PimRolePermResourceActions`
flattens a Graph `roleDefinition`'s allowed/excluded resource+data actions
(de-duped, order-preserving, namespace-derived); `ConvertTo-PimRolePermissionsCsv`
(Role/Permission/Namespace/Action), `ConvertTo-PimRolesByActionCsv`
(Rank/Role/TotalActions/Broad/MatchedActions), `ConvertTo-PimRoleReachersCsv`
(Role/Who/Purpose/Path) and `ConvertTo-PimRoleCompareCsv` (Bucket/Who) emit the
RFC-4180 CSV. Like the Reports/Map exports, the GUI computes these client-side from
the data already on screen; the PS core is the offline-unit-testable definition (so
any tooling/test resolves an export identically to the screen) and is **PS-5.1-safe**
— it returns `List[object].ToArray()` (never `@($list)`, which throws the enumerable
binder's "Argument types do not match") and avoids nested-function calls inside a
`foreach (x in (fn ...))`. Residual views still without export (Jobs, Drift, Fleet
conformance, Support, grid snapshot) are tracked in the backlog.

**Tier-impact report — who can reach Tier-0 / Tier-1 (§23 / ROADMAP #24).** A
fourth Reports mode answers the question a security review opens with: *which users
can reach a Tier-0 / Tier-1 target — including reach inherited through nested
groups?* It is a **pure, offline-testable** library, `engine/_shared/PIM-TierImpact.ps1`,
over the *same* node/edge model and the *same* column-oriented reach semantics as
`Get-PimAccessGraphModel` / `PIM-MapRisk.ps1` (it reuses the MapRisk
`ConvertTo-PimMapReach` / `Get-PimMapNodeField` / `Get-PimMapColumn` helpers when
loaded, with self-contained fallbacks so it stands alone in a test):
- `Get-PimTierImpactReport -Data <model> [-HighTierMax <0..5>]` BFS-walks forward
  from **every** admin, carrying the running **most-privileged (minimum) group level**
  seen on each path. A synthetic target node carries no tier of its own, so its
  effective tier is **inherited from the groups that grant it** — the lowest level
  on the path (a role/permission group carries `Level`/`Tier` via the naming
  convention, resolved by the same `-L<n>-`/`-T<n>-` marker logic the Home tile uses).
  This is exactly why the report sees reach a flat per-admin role list misses: a
  target reached only through a nested permission group still inherits the role
  group's level on that path.
- It returns one row per admin who reaches any target at level ≤ `HighTierMax`
  (default 1 = Tier-0 **or** Tier-1; `0` = Tier-0 only), with the **highest tier**
  reached, the **count** of distinct high-tier targets, the granting **path** to the
  worst (most privileged) target — tie-broken to surface the **nested/indirect**
  path — and a `viaNested` flag. Rows sort most-privileged-first; the summary carries
  `scannedAdmins` / `impactedCount` / `tier0Count` / `tier1Count`. An honest empty
  result when nothing reaches high tier (no fabricated rows); cycle-safe + bounded.
- The thin Manager wrapper `Get-PimTierImpactReportLive` reads one live model
  (`Build-PimGraphData`) and calls the core. Endpoint `GET /api/tier-impact[?tier=0]`.
  The Reports tab (`rptModeTierImpact`) renders the estate-wide table (printable +
  CSV-exportable through the same shared export bar). 

**Delegation Map search-result list + jump, and the risk overlay.** The
Map's search box used to only *dim* non-matching boxes. It now also builds a
**typed, ordered result list** the operator clicks to **jump** (centre + select) a
node. The classification is a **pure, offline-testable** library —
`engine/_shared/PIM-MapRisk.ps1` — that operates over the *same* node/edge model
(`Build-PimGraphData` output) with the *same* column-oriented reach semantics as
`buildMapModel` / `Get-PimAccessGraphModel` (group nests oriented low-column→high,
same-column nests dropped, cosmetic edges excluded):
- `Get-PimMapSearchResults -Data <model> -Query` → type-ranked hits
  (person→group→role→scope→other, then label) each carrying the node **id** the GUI
  jumps to. Endpoint `GET /api/map-search?q=`.
- `Get-PimMapRiskOverlay -Data <model>` → per-node flags: **orphan** (a role /
  permission group with no admin path into it via reverse BFS — dead delegation — or
  a target nothing reaches), **stale** (only when the node carries a real
  `lastReviewedUtc` + `reviewDays` signal and is past horizon — never invented),
  **over-privileged** (reaches a Tier-0/Tier-1 node, OR reaches more targets than an
  **empirical** threshold = *mean + 1 sample-stddev* over the actual non-zero
  reach-count distribution — **no hardcoded cap**; with <2 data points the count
  signal is disabled and only the tier signal flags). Endpoint `GET /api/map-risk`.
The browser mirrors the same logic client-side (`computeMapRisk` / `mapSearchResults`
/ `mapJumpTo` / `mapApplyRisk` in `pim-manager.html`) so the **static render** and the
server agree; a board-level `risk-on` toggle shows orphan/stale/over-priv styling +
per-box reason tooltips. Offline proof: `tests/Test-PimMapRisk.ps1` (23 assertions,
seeded model). The **hosted-GUI smoke remains the live gate** (§1a) before this is
treated as fully delivered end-to-end.

**Stage a removal (revoke a grant) from the Map.** The Map could
already *stage adds* (`mapTryStage` → `PIM-Assignments-Admins` / `-Groups` rows); the
residual was staging a *removal*. The pure core `Resolve-PimMapRemovalPlan` (in the
same `engine/_shared/PIM-MapRisk.ps1`) turns a map selection into a row-level
revocation plan over the SAME `Build-PimGraphData` model + the current store rows:
- **EDGE** selection (one concrete grant) — the graph builder already stamps each
  edge with `source_csv` (the owning base) and a `match` dict (its source row's
  natural-key fields). `Resolve-PimMapRemovalPlan -EdgeMatch -EdgeKind` removes every
  row in that base whose key fields equal the match (`Test-PimMapRowMatchesEdge`,
  comparing only the key fields, so differing AssignmentType/expiry never blocks a
  revoke; a blank match value is refused so it can never match everything).
- **NODE** selection (a flagged node) — `-NodeId` walks every non-cosmetic edge that
  references the node id on either end (`Test-PimMapEdgeTouchesNode`), maps each via
  `Get-PimMapEdgeBase` to its assignment base, and drops the matching store row(s),
  de-duped by reference so a node touched by two edges removes its row once.
The plan returns, per affected base, the **after** row set (current minus the matched
rows — a whole-base *replace*) plus the removed rows; `destructive` is **always true**
and a zero-match selection returns `ok=$false` (never an empty/over-broad plan). The
endpoint `POST /api/authoring/map-removal` (in the existing `/api/authoring/*` block,
Admin-gated) resolves the plan, then runs each base's after set through the SAME
`Get-PimAuthoringPreview` (replace mode → the dropped grant shows as a keyed
**remove** + destructive flag) and classifies the **removed** rows through the maker/checker
maker/checker gate (`Test-PimAuthoringCommitAllowed` with action `delete-rows`), so a
privileged revoke needs a different administrator's approval. The GUI (`mapStageRemoval`
+ a red **Stage removal** button on the selected-node detail) confirms the preview,
honours the gate, and stages each after set as a whole-base replace (exactly like
`stageMoveAdminResult`) — so commit goes through Review & Save + backup/undo (§5.4).
Nothing on this path writes to Entra/Azure: the engine stays the only writer. Offline
proof: `tests/PIM.MapRemovalStaging.Tests.ps1` (14 assertions) drives the pure core +
the REAL keyed diff (`Compare-PimRowSets`) + the REAL sensitivity gate over a seeded
model. The **hosted-GUI smoke remains the live gate** (§1a).

### 18.1d Six-menu navigation

The Manager grew to ~20 flat top-level tabs (`#tabs .tab[data-tab]`). They are folded
into six named, collapsible menu **groups** a security leader (or a first-time admin) can scan
in seconds. The grouping is an **information-architecture layer**: it does not change any
endpoint or the `switchTab(name)` router.

**The six menus** (`NAV_GROUPS` in `pim-manager.html`; each entry carries a one-line description of
what the screen does, and an entry may deep-link to a *section* of a tab via `anchor`):

| Menu | Entries |
|---|---|
| **Overview** | Home |
| **Access** | Access map · Look up a role · Create access · Change existing access · Admin accounts & TAP · Invite a guest or consultant · Departments & owners (Settings section) · **Delegations — edit in a table** (§71.26: the records table scoped to the assignment entities) · All records (the raw view) |
| **Pending changes** | Check for problems · Review & commit queue (§18.1f) |
| **Jobs** | Jobs & status · Engine logs & errors · Job schedule (§11.3a) |
| **Reviews & controls** | Review standing access · Approvals · Drift: live vs desired (§5.2) · Access reviews · Tenant conformance · Reports · Managed tenants |
| **Audit & Settings** | Audit trail · Settings · Newly discovered resources · Manager access & roles, Emergency override (break-glass), Mail templates (Settings sections) · Support |

The former *Daily operations* menu is folded into Reviews & controls, and the former *Governance*
("Access & drift") tab is gone: drift became its own page, discovered resources moved to **Newly
discovered resources** (the discovery baseline, new items and the auto-create policy), the job
schedule moved to Jobs, and the access list, emergency override, permission template packs and mail
templates became Settings sections, visible by default with a plain-language explainer of every
column. Deep links and alert links that pointed at the old tab resolve to the drift page. The page
`<title>` is "PIM Manager (PIM4EntraPS)", which is what a bookmark shows.

**How it is built.** A declarative `NAV_GROUPS` array in `pim-manager.html` maps
each group → an ordered list of existing `data-tab` keys. At boot, `buildNavGroups()`
reads the live flat `#tabs` strip and, for each group, renders a `.nav-group` with a
`.nav-group-btn` toggle and a `.nav-group-menu` dropdown of `.nav-group-item`
buttons. Each item's label is taken from the flat tab (minus its badge); clicking an
item calls the unchanged `switchTab(tabKey)`. The flat strip stays in the DOM as the
**canonical** tab/badge/`switchTab` surface and is hidden via the `body.js-nav-grouped`
class — which is added **only after a successful build**, so if the build wires
nothing the flat strip stays visible (the Manager is never left navigation-less).

**Badge + active mirroring.** `syncNavGroups(activeTab)` mirrors the flat strip onto
the grouped nav: it marks the owning group + item active, and reflects each tab's
badge (a group shows a red **attention dot** when any child carries a visible badge;
the item shows the count). It runs from `switchTab` and from a `MutationObserver` on
`#tabs` (badges are set by many render functions, so observing the strip avoids
hooking each one). Groups are **collapsible** (one open at a time; outside-click and
`Esc` close them) and **keyboard-accessible** (`button[role=menuitem]` +
`aria-haspopup`/`aria-expanded`; `ArrowDown` opens + focuses the first item,
`Arrow`/`Esc` navigate). The bar is **responsive** — it compacts like the flat strip
and stacks into a vertical accordion under ~880px.

**No dead/orphan menu (integrity).** `buildNavGroups()` records any `NAV_GROUPS`
entry whose `data-tab` does not exist in `window.PIM_NAV_DROPPED`, so a typo can never
silently hide a view. The headless validator's nav-walk asserts the complementary
invariants: the grouped nav built, nothing dropped, **every flat view is on exactly
one menu item** (no lost view, no duplicate, no orphan/dead menu), and **clicking each
item activates its real engine-backed panel** (see TESTS §nav-walk).

> Group names and entries live only in `NAV_GROUPS` + the headless nav spec, so they rename in one
> place.

### 18.1e In-context guidance + consistent panel states

Like the consolidated nav, this is a **thin, additive presentation layer** over the
existing tabs: it adds NO endpoint, touches NO renderer's data flow, and leaves
`switchTab(name)` routing unchanged. Two things ship together.

**1. In-context guidance banner.** A declarative `TAB_GUIDANCE` map in
`pim-manager.html` keys each `data-tab` → `{ title, what, how[], legend? }` (a one-line
"what this is" + a short "how to use it" list, in plain admin language). `switchTab()`
calls `injectTabGuidance(name)`, which builds a collapsible `<details class="tab-guide">`
(via `tabGuidanceHtml`) and **prepends it as the panel's first child** (`#<name>Tab`).
Prepending into the panel — not the panel's body — means the banner **survives each
renderer rewriting its own `innerHTML`**, with no change to the renderers. Injection is
**idempotent** (it no-ops if a `:scope > .tab-guide` already exists), so re-entering a
tab never duplicates the banner. The banner is collapsible so an experienced operator
can fold it away.

**2. Consistent loading / empty / error states.** Three shared helpers —
`stateLoading(msg)`, `stateEmpty(title, sub)`, `stateError(title, detail)` — render the
same `.pim-state{.loading|.empty|.error}` block everywhere, so a panel is **never blank**,
an empty result is **explicit** (not silence), and a failure is a **tidy, escaped
message** (never a raw error). The major tab renderers route their top-level load
failures through `stateError(...)`.

**3. Tier / plane legend where the vocabulary is used.** The tabs that speak in tiers /
planes (Delegation Map, Role Lookup, Reports) set `legend: true`, and `tabGuidanceHtml`
reuses the existing **`homeLegendHtml()`** inline in the guidance banner — one legend
definition, shown where it's needed (Home keeps rendering its own legend in `renderHome`,
so it does not double up).

**Verification.** Static-structure assertions in `tests/Test-PimManagerGuiPanels.ps1`
pin the registry, helpers, `switchTab` wiring, idempotency guard, per-tab entries, legend
reuse and the `stateError` retrofit. The **headless render harness**
(`tests/gui-headless/render-and-check.js`, run by `Test-PimManagerGuiComprehensive.ps1`)
drives `switchTab` through every tab in jsdom and asserts each panel carries **exactly one**
well-formed guidance banner (collapsible `<summary>` + a "what" line) as its first child,
with no dead/blank panels and no JS error. `Test-PimGuiEngineAlignment.ps1` stays green
(no new endpoints). Offline + headless-render green is necessary but not sufficient; every release
is also gated on the hosted-GUI smoke against a live deployment (§11.5.3).

### 18.1f Pending changes — one queue for configuration edits and directory actions

![Pending changes — the one queue of configuration edits and queued directory actions](img/manager-pending-changes.png)
*Pending changes: staged configuration edits and queued revokes and pass re-issues in one list, with one commit. (Synthetic demo data.)*

**One queue, one menu entry.** Everything that has not reached the tenant is reviewed and committed
on **Pending changes → Review & commit queue**: staged **configuration edits** (the keyed Review &
Save diff, §5.4) and **queued directory actions** — revoke, TAP re-issue, sign-in session revoke —
held in `pim.ChangeQueue` (`PIM-ChangeQueue.ps1`, `PIM-QueueActions.ps1`). The Manager's identity is
read-only (§7), so these actions can only be carried out by the engine's `queue-apply` job (§11.3).
Queue entries move `pending → committed → applying → applied | failed`, or `discarded`.

- **Ordering and badge.** The list sorts pending → failed → committed → applying → applied →
  discarded, newest first within a state. The menu badge is **red** for what needs the operator
  (pending + failed) and **blue** when only committed/applying entries wait for the engine; it
  updates as soon as something is queued and picks up other administrators' queue changes within a
  minute. Entries show resolved names (person, group, role), not object ids.
- **Commit all** commits staged configuration edits **and** pending queued actions (confirming
  first), so a queue holding only a TAP re-issue is never "Nothing to commit".
- **Staged edits survive a reload or restart.** Until committed, staged configuration edits exist
  only in the page; they are therefore persisted in the browser's local storage and re-applied on top
  of the freshly loaded data after a reload (a colleague's commit made in the meantime is kept). The
  page warns before unloading with uncommitted edits, and the restart notice says staged changes are
  kept. Nothing is ever committed automatically.
- **The default view is queue AND recent commits, in one table** (2026-09-18, §33.26 BUG-168). A
  configuration commit and a directory action take **two different paths**: a configuration/delegation
  edit committed with *Commit all* goes `PUT /api/csv/<base>` → `Invoke-PimManagerSafeCommit` → the
  desired-state rows in SQL, audited as `config.save`, and **never becomes a `ChangeQueue` entry at
  all**; only a directory action does. `queueView` defaulted to `'open'`, which renders queue entries
  only — so the one screen an operator reaches after a successful configuration commit listed unrelated
  older directory actions, under a counter describing *those*, beside *"No configuration edits
  waiting"*. Every element was individually true and the whole read as *"my change vanished"*.
  `queueView` now defaults to `'all'`: both kinds in one list, ranked the §70.22 way, with a **state**
  column — `pending` / `failed` / `committed` / `applying` / `applied` / `discarded` for a directory
  action, **`saved`** (at the same rank as `applied`) for a configuration commit, whose Result cell
  reads *"saved to desired state · the engine applies it on its next run"*. A configuration commit
  carries **no checkbox** — it is history, not work. One fetch helper (`fetchRecentCommitRows`) feeds
  both the merged view and the `recent-*` filters, so the two cannot drift.
- **The counter is computed from the rendered rows**, not from the server's queue counts, and names
  what it hides: *"Showing 3: 1 applied · 2 saved · 1 discarded hidden"*. A count that disagrees with
  the list under it is worse than no count.
- **The commit's own report is sticky.** `renderSaveTab()` blanks `#saveStatus` whenever no
  configuration edit is pending — which is precisely the state a successful commit leaves behind, so
  the success line erased itself (BUG-111's mechanism a second time, in the place it costs most). The
  commit now reports the per-entity numbers `PUT /api/csv/<base>` returns (`rowCount`, `adds`,
  `removes`, `modifies`), names the destination and the next step, and survives the re-render;
  **Refresh** *appends* *"Reloaded from the server and re-checked."* instead of overwriting it. The
  empty-state line separates **"Nothing is waiting to be committed"** from *what was just committed is
  already saved to desired state and listed below*. 🔑 The product rule was never at fault — the
  Manager does not change the directory; the engine applies desired state on its next run. The defect
  was that the GUI did not say so at the moment it was needed.
- **Show filter.** *Open queue*, or *Recent commits* of configuration (from the `config.save` audit
  events), of directory actions (committed/applied/failed entries), or both. Discarded entries are
  hidden unless **Show discarded (N)** is ticked, which shows who discarded each and why.
- **A refused commit explains itself in place.** Before refusing, the commit re-runs validation
  against the **pending** state (`POST /api/preflight` with the staged rows), so a fix just staged is
  taken into account. If blocking errors remain the page stays on Pending changes and lists each
  error with the rows it concerns and a link to its fix. Info-only findings are a quiet one-line note
  that can be hidden per browser until the warning count changes; errors can never be hidden.
- **One-click fixes land here.** Fixes offered by validation (e.g. **Set to Eligible**, §3.1) and by
  **Engine logs & errors** (§11.3a) stage rows into this queue; nothing is applied until an
  administrator commits.

### 18.1g Review standing access and the Drift page

![Review standing access — active assignments from the snapshot, with the revoke-queued marker](img/manager-standing-access.png)
*Review standing access, served from the scheduler's active-assignments snapshot, with queued revokes marked. (Synthetic demo data.)*

**Review standing access** (Reviews & controls) renders the stored active-assignments snapshot
(§11.1): the snapshot time and cadence, one row per active Entra role / Azure / PIM for Groups
assignment, and the approval-gated bulk revoke (§6 approvals). Rows held by principals the directory
no longer resolves are hidden by default; **show deleted principals (N)** reveals them and a
*deleted* chip selects only them for a bulk revoke (unticking removes them from the selection). A
revoke is queued (§18.1f); the row shows **revoke queued** until a later snapshot no longer contains
it, and a completed revoke queues a fresh snapshot.

**The revoke click stages under an explicit field contract, and can never be silent** (2026-09-18,
§33.24 BUG-165). The page used to build the `POST /api/revoke` body from a hand-written nine-field
subset of the snapshot row, which dropped `roleAssignmentId` / `roleAssignmentName` (the only way an
**active azure-rbac** assignment can be addressed — `Open-PimManager.ps1` refuses without it) and
`role` (so every `entra-role` queue entry reached `New-PimQueueActionNames` with no target name). The
whole row is now posted through a declared contract (`REV_PAYLOAD_FIELDS`), and:

- Each selected row is **pre-checked before anything is posted**. A row that cannot be addressed — an
  `azure-rbac` row with neither `roleAssignmentId` nor `scope`+`roleAssignmentName`, a row with no
  `principalId`, an `entra-role` row with no `roleDefinitionId`, a `pim-for-groups` row with no
  `groupId`, an unknown `type` — is **refused individually with its reason** while the addressable rows
  still stage. Nothing is posted at all when no row can be addressed.
- `submitRevokeInner` reports on **every** exit (7 exits, 0 silent — asserted statically by the suite,
  scoped to that one function body rather than the whole page, §37.3); the outer `submitRevoke` wraps it in `try/catch` so a
  throw inside an `async` handler cannot vanish as an unhandled promise rejection. The status element
  `#revActionStatus` lives **in the action bar beside the button**, not in the results pane below a
  978-row scroller, and carries busy / staged *N* / refused *N* / the named error.
- `wireRevokeTab()` is a **named, idempotent** function called at load **and** from `openRevokeTab()`,
  so a tab whose page-load wiring was lost re-arms on open — the "red, enabled, handler-less button"
  shape that produces a click with no request, no error and no toast.
- The confirm dialog states that the rows are **staged as pending changes** and nothing is revoked
  until committed, instead of claiming it fires irreversible admin-remove calls — which has not been
  what the button does since §65.

![Drift: live vs desired — one row per area, expanded to named differences](img/manager-drift.png)
*Drift: live vs desired, one row per engine scope with desired, live and in-sync counts, expanded to the named items. (Synthetic demo data.)*

**Drift: live vs desired** (Reviews & controls) auto-loads the stored drift snapshot (§5.2) and
renders one expandable row per engine scope with desired / live / in-sync counts; each item is
labelled with names (e.g. `admin → member of group X (Eligible)`, `group A → member of group B`) and
shows the technical key only when it adds something. **Check now** (Admin+) queues a fresh check and
reports when a new result lands; **Apply now** applies the selected items through the gated
remediation path.

**Wizard helpers that prevent duplicates.** The Entra role picker hides roles that already have a
delegation group in the role-assignment entities, with a toggle that shows and marks them. The shared
suggestion list (workloads, domains, short codes) **browses every value in use when clicked** and
narrows only as the user types; the Workload field reads the definitions' `Workload` column. New
direct groups carry a **type** (role, organisation, department, process, project, cross-org) that
selects the entity they are stored in; the permission-group wizard no longer offers Department or
Organization. Every onclick handler the page references is checked to exist by a static guard.

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
| ForwardMailsToContact | dropdown TRUE/FALSE | FALSE | un-retired 2026-09-12 — see below |
| MailForwardAddress | email (the owner's office user) | empty | un-retired 2026-09-12 — see below |
| Company | text | empty | pushed to Entra `-CompanyName` only when non-empty |
| Notes | textarea | empty | max 1024 chars; logged as a comment, NOT pushed to Entra |
| ManagerEmail | autocomplete tenant users | empty | resolved to Graph user id + `manager@odata.bind` after create; silently skips if unresolved |
| StartDate | date picker | empty | informational only |
| CreateTAP | checkbox | TRUE for Cloud/ID admins | |
| TAPStartDate | date picker | empty (= immediate) | |
| AccountStatus | dropdown Enabled/Disabled/Revoked | Enabled | gated by StatusChangeCode in MSP variant |
| StatusChangeCode | text + KV-validation status | — | only shown when status != Enabled; shows "verified vs KV" inline |

(Plus the lifecycle columns from §17: `ProvisionDate`, `TAPLifetimeHours`,
`Template`, `AutoDisableDate`, `Department`, `Ring`.)

> **🔄 Current meaning (2026-09-12).** The pair names the admin
> **owner's office user**. (1) Mail PIM sends about the admin (`new-admin`, `tap-delivery`) goes to
> `MailForwardAddress` when `ForwardMailsToContact=TRUE` and the value is a real address, otherwise to
> `ManagerEmail`, otherwise it is refused — one rule, `Get-PimAdminMailRecipient`, used by the engine
> and by the Manager's "Sends to" so the two cannot disagree. A flag value in the address column
> (`FALSE`/`true`) is not an address. (2) **Where the admin account has a mailbox**, the engine also sets
> Exchange forwarding to that address (forward only) or clears it when the flag is off — best-effort,
> never failing the admin apply, skipped silently for an account with no mailbox, and **gated OFF by
> default** (`PIM_AdminMailboxForwarding`) because it needs an Exchange application permission.
> The shared-mailbox sending model below is unchanged. The history that follows is kept for context.
>
> **🔒 (history) `ForwardMailsToContact` / `MailForwardAddress` were retired for a period (2026-08-12).**
> They made the engine call EXO `Set-Mailbox -ForwardingSmtpAddress` on the newly-created admin,
> which only works if **that admin account itself holds an Exchange licence** — a per-admin cost for
> what is only a notification. The design now sends notification and TAP mail **from a single shared
> mailbox that the engine SPN has scoped send rights on**, so an admin account needs **no mailbox and
> no licence at all**.
> **The recipient is `ManagerEmail`** — the only column the notify path reads
> (`PIM-EngineProviders.ps1` `new-admin` and `tap-delivery` sends).
> Removed from: the authoring header (`PIM-Authoring.ps1`), the Manager grid + onboarding wizard,
> both shipped admin templates, the onboarding defaults, the sample CSV, and the forwarding branch of
> `New-PimRestAdminAccount`.
> **Kept deliberately:** `Set-PimMailboxForwarding` / `Test-PimMailForwardAddressIsReal` in
> `PIM-Rest.ps1` — the **v1 legacy edition** still calls them; this retirement is scoped to v2.
> **Validator rule PIM-DOMAIN-001 (since 2026-09-12):** fires on a HALF-configured pair only — a real
> address with the flag not TRUE (the address is stored and never used), or the flag TRUE with no real
> address (mail falls back to `ManagerEmail`). Both-set and both-off are consistent and silent.

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

![Role Lookup — what a role can do, find roles by action, who can activate it, compare two](img/manager-role-lookup.png)
*Role Lookup: what a role can do, roles by action, who can activate a role, and two roles compared. (Synthetic demo data.)*

- **Access map** with side panel; tier-coloured.
- **Grid editor + Review & Save** (on Pending changes): edits the SQL entity rows, diff preview
  before commit.
  - **Keyed (not positional) diff.** `Compare-PimRowSets` (the function behind both
    `POST /api/diff/<base>` preview and the `PUT /api/data/<base>` audit log) matches
    desired-vs-current rows by their **stable natural key**, derived with the store's own
    `Get-PimStoreRowKey -Base <entity>` — the *same* keying the SQL store uses to identify a
    `pim.Rows` row (e.g. `GroupTag` for definitions, `Department` for Departments,
    `AdministrativeUnitTag` for AUs, `GroupTag|RoleDefinitionName` /
    `GroupTag|AzScope|AzScopePermission` for assignments). Classification: same key + identical
    field values = **unchanged** (a pure reorder is invisible); same key + differing values =
    **modify** (with the changed columns); key only in desired = **add**; key only in current =
    **remove**. This replaced the old position-by-position comparison that reported a reordered
    row (common after an Excel round-trip or an authoring move) as a misleading modify/remove.
    **Graceful fallback**: rows whose natural key is blank, or that **collide** (the same key
    appears more than once on one side), can't be matched safely by key, so they drop to the
    legacy content-fingerprint match (full-row equality for unchanged; leftover adds/removes
    paired positionally into modifies). `-Base` is optional — with no base (or if the key
    helper isn't loaded) the whole comparison uses the legacy path, so the function never
    crashes on an unkeyable shape.
  - **Authoring inline preview/diff before commit.** Every Authoring action computes a row
    set; before it is staged (let alone committed) the operator sees exactly what it will change.
    `Get-PimAuthoringPreview -Base <entity> -Before <current> -After <computed> -Mode replace|append`
    (in `engine/_shared/PIM-Authoring.ps1`, pure/offline) returns a **keyed** add/modify/remove diff
    using the *same* natural key as the Review & Save diff and the SQL store — `Get-PimAuthoringRowKey`
    defers to `Get-PimStoreRowKey` when loaded and otherwise mirrors its per-base key map, so a pure
    reorder is never a change and rows with a blank/colliding key fall back to a content fingerprint
    (never crashes). `Get-PimAuthoringActionShape` maps each action to its target base + stage mode +
    a `destructiveByDesign` hint: **replace**-mode actions (move-admin, delete-rows) can surface
    **removes** (a key present in the current set but absent from the computed set), so the result
    carries a loud `destructive` flag and lists the removed rows; **append**-mode actions (clone,
    clone-azure-role, clone-au, bulk-attach, import-admins) only ever add, so a current row missing
    from the small computed set is treated as untouched, not deleted. The Manager exposes this via
    **`POST /api/authoring/preview`** (resolves the base, reads the current store rows as the
    *before*, returns the diff — read-only, never writes); the GUI routes every authoring button
    through `previewAuthoringAndConfirm`, which shows the diff in a confirm modal and stages nothing
    on Cancel. **Move admin can no longer silently drop rows:** `New-PimAdminMovePlan` re-points only
    the matched `(admin → FromTag)` rows to `ToTag` and carries every other row through verbatim, then
    asserts the output row count equals the input count (throwing rather than emitting a lossy plan)
    and reports `preservedCount` — closing the wholesale-replace gap that motivated it.
- **Validator**: missing-GroupTag detector, stale Entra-role detector, tier-safety
  lint, plus the PIM-* validator rules across the lifecycle features (§17).
- **Review standing access**: active assignments + approval-gated revoke (§18.1g); Workload
  Delegation panel (§15.2).
- **Audit & Settings** (role-gated): audit trail, Settings sections for mail templates, emergency
  override and Manager access, Newly discovered resources, contacts/email-flow (§17.11–17.17).
- **Wizards**: new-admin onboarding (template picker, TAP fieldset), capability
  wizard ("what kind of capability?"), tag global-rename.
- **Settings tab** (SuperAdmin-gated; read-only for lower roles): the config that
  was moved out of the JSON/PS config files into the store — see §18.6.
- **Live tenant overlay** (CSV vs tenant drift on the graph) and the Azure RBAC
  per-scope role dropdown are later increments.

### 18.6 Authoring helpers (bulk-attach / clone / AU / import / move / delete)

The Manager's high-leverage authoring actions are **pure row-set builders** in
`engine/_shared/PIM-Authoring.ps1` — the same "no I/O, fully testable" pattern as
`PIM-PermissionWizard.ps1`. They are dot-sourced both by the engine module and
standalone by `Open-PimManager.ps1`, and surfaced over `POST /api/authoring/*`
(Admin role required). **Each endpoint only COMPUTES rows** (a preview); the
operator commits them through the normal `/api/data/<base>` PUT (Review & Save), so
the engine remains the single writer to Entra/Azure — the authoring layer never
connects to a tenant.

| Helper | Endpoint | What it builds |
|---|---|---|
| `New-PimBulkAttachRows` | `/api/authoring/bulk-attach` | Fans N directory roles + N Azure scopes + N AU-scoped roles onto one GroupTag → rows for `PIM-Assignments-Roles-Groups` / `-Azure-Resources` / `-Roles-AUs`. |
| `Copy-PimDefinitionRows` | `/api/authoring/clone` | Clones a template row to N new tags (GroupName follows the tag; `SetColumns` overrides per clone); works for definition + assignment rows (cross-entity). |
| `Copy-PimAzureRbacToRole` | `/api/authoring/clone-azure-role` | Clones an Azure-RBAC row to a different RBAC role (or to N roles) at the SAME `AzScope`. |
| `New-PimAuRows` | `/api/authoring/au` | Builds a `PIM-Definitions-AU` row + optional `PIM-Assignments-Roles-AUs` bindings. |
| `ConvertFrom-PimAdminImportCsv` + `New-PimAdminRowsFromImport` | `/api/authoring/import-admins` | Parses pasted/uploaded people (`;`/`,`/tab delimited), derives Initials + DisplayName, applies a chosen admin template's `prefill`, carries Department through → `Account-Definitions-Admins` rows. |
| `New-PimAdminMovePlan` | `/api/authoring/move-admin` | Replace-mode move: removes every `(admin → FromTag)` row and adds the matching `(admin → ToTag)` rows in ONE returned row set (all-or-nothing within the single Commit). |
| `Remove-PimRowsByIndex` | `/api/authoring/delete-rows` | Multi-select delete by 0-based index (bounds-safe, idempotent). |
| `Format-PimRolePermissions` | `GET /api/role-permissions?role=` | Flattens a Graph `roleDefinition.rolePermissions[].allowedResourceActions` to a de-duped, namespace-grouped list for the drill-down side panel + export (the live Graph fetch is the only non-pure part; the shaping is unit-tested). |
| `Find-PimRolesByAction` (+ `Test-PimActionPatternMatch`, `Get-PimRoleActionMatches`) | `GET /api/role-permissions/by-action?action=` | **Search-by-action** — the inverse of the drill-down: over the directory role-definition corpus, returns every role that grants a queried `resourceAction`, **ranked least-privilege first** (fewest total actions; a role granting it only via a `*`/`ns/*` wildcard is flagged `viaWildcard` and ranked last). `Test-PimActionPatternMatch` implements Entra's `/`-segment wildcard semantics symmetrically (a granted `ns/*` covers a concrete query; a `ns/*` query matches granted concretes). Pure; the live Graph fetch of the corpus is the endpoint's only non-pure part. |
| `Get-PimStringSimilarity` | (Role Lookup matching) | Case-insensitive Levenshtein ratio in [0,1] — the ranking primitive for typo-tolerant role matching. Pure. |
| `Resolve-PimRoleQuery` | `GET /api/role-permissions?role=` + `/api/role-lookup/reverse` | Typo-tolerant role resolution over a name catalog: exact (case-insensitive) → `matched`; otherwise ranked substring/fuzzy candidates ("did you mean…"); empty/unknown → empty list. **Never throws / never 5xx** — a near-miss is data, not an error. Pure. |
| `Compare-PimReachSets` | `GET /api/role-lookup/compare?roleA=&roleB=` | Set-compare two reacher result sets (from `Get-PimRoleReachers`) → overlap (`both`) + each-only (`onlyA`/`onlyB`); identity = principal UPN/id, case-insensitive. Pure. |
| `ConvertTo-PimLaAuditRecord` | (engine sink) | Shapes a PIM audit event into the flat record AzLogDcrIngestPS posts to a DCR/Log Analytics table (CollectionTime stamping; `after` flattened to a compact JSON `Details` column). |

#### Front-end panels for the convenience endpoints (2026-06-15)

The previously API-only convenience endpoints now have dedicated Manager tabs in
`pim-manager.html`, each gated on `isServer` (no static-mode writes) and the JS
`roleAtLeast()` rank helper (mirroring the server's `Test-PimManagerRoleAtLeast`;
the server is still the real enforcer):

- **Authoring** (`renderAuthoring`, Admin+) — bulk-attach, clone, import-admins and
  move-admin forms. `bulk-attach` stages the three returned row sets to their
  matching assignments CSVs; `move-admin` **replaces** the `PIM-Assignments-Admins`
  pending set (it returns a full replacement); the rest **append** computed rows.
  Everything lands in `pendingChanges` and finishes on Review & Save.
- **Onboarding** (`renderOnboarding`, Admin+ plus the portal capability the server
  checks) — guest-invite + self-service-toggle. The returned change-queue records
  (`{ entity, key, op, payload }`) are folded into pending: a `Create` appends the
  payload row; an `Update` (self-service toggle) merges into the existing row matched
  by `UserName`/`Username` so a toggle never duplicates the admin. The B2B invitation
  body is shown for the separate confirmed send.
- **Role Lookup** (`renderRolePerms`, any role, read-only) — a four-mode tab:
  - *What a role can do* — calls `GET /api/role-permissions?role=` and renders the
    `byNamespace` grouping. **Typo-tolerant:** when the exact name doesn't resolve, the
    endpoint no longer returns a 503 — it returns `200 { matched:false, candidates:[…] }`
    where the candidates come from `Resolve-PimRoleQuery` over the role catalog
    (`Get-PimRoleCatalogNames` = the tenant-list cache's role display names ∪ the live
    delegation model's target role-names, so suggestions work even with no live Graph
    read). The GUI renders these as clickable "did you mean…" chips; a genuine empty
    result is an empty candidate list, never a 5xx.
  - *Find roles by action* (`renderByActionPanel`) — calls
    `GET /api/role-permissions/by-action?action=`, which pages the directory
    role-definition corpus from Graph (selecting `rolePermissions`) and runs the pure
    `Find-PimRolesByAction` matcher. The result table lists each granting role
    least-privilege-first with its total-action count and the matched action(s); a
    wildcard grant is badged "broad — wildcard" and sorted last. A blank action → 400;
    no Graph / no match → `200 { matched:false, matches:[], hint:… }` (never a 5xx).
  - *Who can activate a role* — `GET /api/role-lookup/reverse?role=` reuses
    `Get-PimRoleReachers` over the live delegation model (the same reverse walk the
    Reports tab uses) and lists each principal **with the activation path**; an exact-name
    miss falls back to the same ranked-candidate response.
  - *Compare two roles* — `GET /api/role-lookup/compare?roleA=&roleB=` runs
    `Get-PimRoleReachers` for each, then `Compare-PimReachSets` returns the overlap +
    each-only principal sets (identity = the principal's UPN/id, case-insensitive).
  The matching/compare logic lives in pure helpers in `engine/_shared/PIM-Authoring.ps1`
  (`Get-PimStringSimilarity` = case-insensitive Levenshtein ratio; `Resolve-PimRoleQuery`;
  `Compare-PimReachSets`) so it is fully unit-testable offline.

A shared `stageComputedRows(base, rows)` helper merges server-computed rows into
`pendingChanges` (header union + dirty badges), the same contract the template-import
path uses. A static GUI-panel test (`tests/Test-PimManagerGuiPanels.ps1`) pins the
tabs, routing, renderers, endpoint calls and gating so a future edit can't silently
drop a panel.

### 18.7 Governance validator rules (added)

`tools/pim-manager/_validator.ps1` gained four governance rules. All **degrade
gracefully** — a rule whose live-data dependency (auth-method cache, azure-scopes
cache, activity cache) is absent emits a single info "skipped" finding or simply
does nothing, never a false positive:

| Rule | Severity | Fires when | Live-data dependency |
|---|---|---|---|
| `PIM-ROLE-OWNER-001` | info | a role / organisation / task definition row has empty Owners AND SponsorUpn AND Department (nobody to recertify it) | none (pure CSV) |
| `PIM-AUTH-001` / `-002` | error | an admin has none of the required strong methods (001) or only weak methods like sms/voice (002); the required set is `$global:PIM_RequiredAuthMethods` | optional `auth-methods` tenant cache (`UserAuthenticationMethod.Read.All`); absent → one info "skipped" |
| `PIM-AZ-PLACEHOLDER-001` | error | an `AzScope` is a template placeholder, not a real scope: an all-zero or non-GUID subscription id, or the all-zero management-group id. The row can never be applied | none (a property of the value) |
| `PIM-ORPHAN-AZ-001` | error | an `AzScope` is not present in (and is not a parent/child of) any scope in a **fresh** `azure-scopes` tenant cache; the message names the item count and the time the cache was read | requires a fresh (< 24 h) `azure-scopes` cache; stale or absent → one info "not checked", no row judged |
| `PIM-STALE-001` | error | a `RoleDefinitionName` is not an Entra role in a **fresh** `entra-roles` cache (with a did-you-mean) | fresh `entra-roles` cache; stale or absent → one info "not checked" |
| `PIM-STALE-002` | error / info | the AU tag is resolved the way the engine resolves it (tag → AU definition → display name). **Error** when an AU definition has no display name (it can never be created or found); **info** when a defined AU does not exist yet in a fresh `aus` cache — the engine creates it on its next run. An assignment tag with no AU definition is `PIM-FK-003` | fresh `aus` cache; stale or absent → one info "not checked" |
| `PIM-STALE-003` | info | a PIM group has never been activated, or not within `$global:PIM_StaleGroupDays` (default 90) | optional `pim-activity` tenant cache; absent → skip |

### 18.7a Warning override / acknowledgement (validator post-filter)

The operator can **overrule (acknowledge)** legitimate-but-noisy validator
WARNINGs — primarily the multi-path `PIM-DUP-001` ("admin reaches target via N
role-group paths") and `PIM-ORPHAN-001` — without changing the rules that emit
them. This is implemented as a **POST-FILTER**, not a validator-core change:
`engine/_shared/PIM-WarningOverrides.ps1` exposes `Apply-PimWarningOverrides`,
which `tools/pim-manager/_validator.ps1` calls at its **single return point**.
Matched findings are **downgraded to severity `acknowledged`** (kept in the set
and annotated — `OriginalSeverity`, `AckReason`, `AckBy`, `AckExpiresOn`), never
silently dropped, so the acknowledgement is fully auditable. Errors are hard
gates and are never acknowledgeable.

**Stable identity.** Every finding carries a stable `Code` plus a stable
per-instance key = `Code` + `Subject` + `Target`. The two rules operators
overrule most (`PIM-DUP-001`, `PIM-ORPHAN-001`) stamp `Subject`/`Target` on the
finding; other rules scope by the `Csv`/`Row` structural anchor.

**Override config contract** (the future GUI "Overrule" button writes this exact
shape). Customer-specific, **gitignored** (`config/PIM-WarningOverrides.custom.json`,
covered by the `config/*.custom.json` ignore); only a `.custom.sample.json`
ships. Each entry:

| Field | Required | Meaning |
|---|---|---|
| `code` | **yes** | stable rule code (e.g. `PIM-DUP-001`) |
| `scope` | no | `{subject,target,csv,row}` — all supplied keys must match (AND); omit = all findings of `code` |
| `pattern` | no | wildcard (`-like`) tested against subject \| target \| message (any-of); ANDs with `scope` |
| `reason` | **yes** | mandatory justification (an entry without it is ignored + reported) |
| `createdBy` | no | audit trail |
| `expiresOn` | **yes** unless `noExpiry` | follows the **exemptions model** — never indefinite by default |
| `noExpiry` | no | explicit opt-out of expiry (the only way to suppress forever) |

**Expiry is enforced, not advisory.** An override whose `expiresOn` is in the
past (or unparseable — fail-safe) **stops suppressing**: the finding resurfaces
as an active warning and is counted as `expiredToActive`. The validator's
`summary` now reports `warnings`, `acknowledged`, and `expiredToActive`
alongside the existing counts, so the Validate tab can render
"warnings 552 → N active, M acknowledged (K expired → active)".

**GUI "Overrule" writer (delivered 2026-06-15).** The Validate tab puts an
**Overrule** button on every active warning/info row (server mode only; errors
are never acknowledgeable). It opens a dialog pre-scoped to the finding's
`code` + `subject`/`target`, requires a reason + an expiry (or an explicit
no-expiry), and `POST /api/warning-overrides` appends one entry — in this exact
contract shape — to `config/PIM-WarningOverrides.custom.json`. The handler
(`Add-PimWarningOverrideEntry`) validates against `Test-PimWarningOverrideValid`
before persisting, requires the Admin role, audit-logs the action
(`validate.warning.overrule`), and busts the preflight cache so the next
`GET /api/preflight` recomputes; the matched finding then comes back as
`acknowledged` and the active count drops. The acknowledged rows render in a
dedicated `acknowledged` severity bucket (with reason/by/expiry), and the
severity chips (now including **all** + **acknowledged**) compose with the CSV
dropdown and search through one filter path. `GET /api/warning-overrides` is a
read-only listing for tooling/tests. A SQL-mode override store (read from
`pim.Settings`) remains the last piece (tracked in the backlog).

### 18.8 Optional Log Analytics audit sink

`Write-PimAuditEvent` always writes the event to the SQL audit trail `pim.AuditEvents` first
(source of truth, §17.11). When `$global:PIM_AuditLogAnalytics`
is set (off by default), it additionally pushes each event — shaped by
`ConvertTo-PimLaAuditRecord` — to Log Analytics via either a host-supplied
`Send-PimLaAuditRecord` hook or the user's `AzLogDcrIngestPS` module directly. The
push is best-effort: a failure is warned and never blocks the engine or the SQL
audit.

### 18.9 Settings admin area (config moved out of the files into the store)

![Settings — naming conventions and operational policy](img/manager-settings.png)
*Settings: naming conventions with a preview of the names they produce and operational-policy defaults, stored where the engine reads them. (Synthetic demo data.)*

A **SuperAdmin-only "Settings" tab** lets an administrator view/edit the configuration
that previously lived only in `config/*.ps1` / `config/*.json` — now managed
**through the same store the engine uses** (no file editing, persisted + auditable).
Besides the sections below it hosts Manager access & roles, the emergency override, permission
template packs, mail templates, workload exemptions, feature customization and alerting. **Naming
preview:** each naming pattern shows the name it produces for a sample, including the configurable
admin word ("Admin", "adm", …), which does not loosen name validation. The core sections:

- **Naming conventions** — the `{Owner}`/`{Role}`/`{Department}`/`{Tier}` patterns
  for admin, group and resource names (a key/value editor over the
  `NamingConventions` map).
- **Filters** — the name-marker / routing filters, in a **store-friendly shape**:
  each filter is `key` + `label` + `patterns` (any-of like-patterns) +
  `requireAll` (markers every match must also contain). The engine's scriptblock
  defaults in `config/PIM4EntraPS.Filters.locked.ps1` remain the code fallback;
  the editable representation here is what an admin maintains.
- **Departments (+owners)** — the source the delegation-approval workflow uses to
  resolve **department → owner(s)**.
- **Approvers / owners** — directory of people who can approve assignments / own
  resources.

**Storage seam (one store, never a parallel one).** Reads/writes go through a
single chokepoint — `Get-PimManagerSetting` / `Set-PimManagerSetting`:

- **Always SQL** → `pim.Settings` (the protected key/value table; the same one the boot seed +
  `Get-PimAllSqlSettings` use). A reader of the shipped defaults learns nothing authoritative — the
  store is the source of truth. There is no settings file fallback: the Manager requires its
  database to start, and settings are written only when their value changes.

**Default-seeding (hard requirement: naming/filter is never empty).** On first page
render (`GET /`) and on the first `GET /api/settings`, if the store has no
`NamingConventions` and/or no `Filters`, the Manager **falls back to a shipped
sensible default and persists it** (naming from the overlaid locked/custom defaults;
filters from `Get-PimDefaultManagerFilters`, which mirrors the documented locked
filters). The response flags `namingSeeded` / `filtersSeeded` so the UI can show a
"default seeded" badge. Departments + approvers are optional and are **not**
auto-seeded (empty is valid).

**APIs + gating** (server is the enforcement boundary; the GUI only hides what the
role can't do):

| Method + path | Role | Effect |
|---|---|---|
| `GET /api/settings` | any | bundle: naming, filters, departments, approvers + seeded flags + storage mode/instance (auto-seeds naming/filters if empty) |
| `PUT /api/settings/naming` | SuperAdmin | replace the naming map (rejects an **empty** map → 400); mirrors into `$global:PIM_NamingConventions` so the same process's `Resolve-Pim*Name` helpers see it live |
| `PUT /api/settings/filters` | SuperAdmin | replace the filter list (rejects an **empty** list → 400) |
| `PUT /api/settings/departments` | SuperAdmin | replace the department(+owner) list (empty allowed) |
| `PUT /api/settings/approvers` | SuperAdmin | replace the approver/owner list (empty allowed) |
| `POST /api/settings/departments/import` | SuperAdmin | import departments from Entra groups matching a pattern (§15.5a); persists the merged dept list + chosen pattern; returns created/updated/skipped |
| `POST /api/settings/approvers/import` | SuperAdmin | apply approvers/owners per department + rename from an uploaded CSV (§15.5b); persists the merged dept list; returns created/updated/renamed (rejects empty CSV → 400) |

Every write emits a `settings.<section>.save` audit event (imports emit
`settings.departments.import` / `settings.approvers.import`). The AD OU placement
keys `PathAdmins` / `PathAdminsL0T0` are written through `PUT /api/settings/naming`
(§15.5c). The "one Manager = one
active SQL" rule is respected — settings live in the active instance's store and the
instance switcher (`Set-PimManagerInstance`) is the only place the active store
changes.

### 18.9b Feature flags (gradual rollout — turn any Manager surface on/off)

Every Manager surface (tab / major panel) is **toggleable** so an operator rolls
features out one at a time. The on/off decision lives in the **same one store** as
the rest of Settings (`pim.Settings` key `FeatureFlags`), so the navigation render and any
server-side gate resolve one identical value — GUI state == actual behaviour.

**Pure core (`engine/_shared/PIM-FeatureFlags.ps1`).** No I/O; takes a raw stored
value and returns the effective map.
- `Get-PimFeatureFlagCatalog` — the declarative catalog. Each entry: `id` (**equals
  the GUI `data-tab` key** so the nav gates directly on it), `label`, `default` (core
  surfaces ON, newer/advanced OFF — gradual rollout), `alwaysOn` (Home / Audit /
  Settings can never be disabled — no lock-out). Returns a defensive copy.
- `Resolve-PimFeatureFlags` — the merge: start from each flag's `default`, apply a
  persisted override for a **known** id, force always-on flags ON regardless of the
  override (with a warning), and **ignore unknown ids** (with a warning — never
  invents a surface). Accepts a `{flags:{…}}` wrapper, a flat `id->bool` map, an
  in-process hashtable, a JSON string, or a JSON-parsed PSCustomObject (the
  IDictionary-vs-PSObject dual read). Returns `{flags, effective, warnings}`.
- `ConvertTo-PimFeatureFlagOverrides` — reduces a selection to the MINIMAL override
  set (only flags differing from default, never always-on) so the store stays small
  and a future default change still flows through to any flag the operator never
  explicitly touched.

**Wrappers + endpoints (`Open-PimManager.ps1`).** `Get-/Set-PimFeatureFlags` persist
through the same `Get-/Set-PimManagerSetting` chokepoint. `GET /api/settings/feature-flags`
returns `{flags, effective, catalog, warnings}`; `PUT` is **SuperAdmin-gated**,
normalises to the minimal override set, and emits a `settings.feature-flags.save`
audit event.

**Boot-time gating (read at render so a toggle takes effect on reload).** The
effective flags are baked into the page (`__PIM_FEATUREFLAGS__` →
`window.PIM_FEATUREFLAGS_BOOT`). At boot `applyFeatureFlagsToTabs()` hides the flat
tab for any disabled surface (so it's unreachable via the flat strip / deep-link too),
then `buildNavGroups()` omits disabled items and **hides a nav-group whose children
are all off** (no empty dropdown). `isFeatureEnabled(tabKey)` treats an
uncatalogued tab as enabled (adding a new view is never silently hidden by this gate).
The **Features** card in Settings (`renderFeaturesCard`) lists every flag with an
on/off toggle (always-on flags shown locked-on) and saves via the PUT; a "reload to
apply" affordance follows a successful save.

### 18.10 Shipped delegation template packs (`templates/*.template.json`)

The Create tab offers centrally-maintained **delegation packs**: curated, ready-to-adopt
sets of permission rows for a Microsoft service, shipped as data under `templates/` and
distributed by the normal sync. The Manager auto-discovers every `*.template.json` in that
directory (`GET /api/templates`), so adding a pack is a content-only change — no code edit.
Each pack is one JSON document:

```jsonc
{
  "id": "sentinel", "name": "Microsoft Sentinel delegation", "version": 1,
  "description": "...",
  "rows": {
    "PIM-Definitions-Services":        [ /* rows keyed exactly like the CSV entity */ ],
    "PIM-Assignments-Azure-Resources": [ /* optional: the role->group bindings    */ ]
  }
}
```

- **`rows` is keyed by CSV base name**; each row carries the **same columns** as that
  entity's header (the `$script:PimCsvBases` schema). The endpoint diffs each row against
  the active instance using the entity's natural key (`Get-PimTemplateRowKey` — `GroupTag`
  for definitions, `GroupTag|RoleDefinitionName` for role assignments,
  `GroupTag|AzScope|AzScopePermission` for Azure) and returns only the rows the instance is
  **missing**, so a pack that grows later surfaces just its new additions ("new permissions
  available to delegate"). Adopting a pack stages those rows into the pending list; the
  engine remains the only writer to the tenant.
- **Two pack shapes**, mirroring the providers:
  - **Workload-group packs** (Defender XDR, Sentinel, Intune, Exchange Online) ship only
    `PIM-Definitions-Services` rows — the workload assigns its **own** RBAC role directly to
    the Entra group (no Entra directory role and no separate assignment row needed), exactly
    like the Defender XDR v2 pack.
  - **Binding packs** (Azure RBAC, Entra ID roles) ship the definition rows **plus** the
    matching assignment rows (`PIM-Assignments-Azure-Resources` /
    `PIM-Assignments-Roles-Groups`), so adopting the pack is complete end-to-end. The Entra
    pack's groups are **role-assignable** (`IsRoleAssignable=TRUE`) and the role is bound
    Eligible (the supported standing for a role-assignable group, §3.1). The Azure pack's
    `AzScope` values are zero-GUID **placeholders** the operator replaces with the real
    scope.
- **Naming + tier are baked in.** Every group name conforms to the
  `PIM-<Service>-<Name>-L<level>-T<tier>-<plane>-<domain>` convention (§3.3) and the
  `Level`/`TierLevel` columns agree with the name — asserted by the offline pack test (§25).
- **Public-safe content.** Packs ship no secrets, tenant/subscription IDs or customer names
  (the only GUID allowed is the zero-GUID placeholder) — they are part of the published set.

Shipped packs: `defender-xdr`, `sentinel`, `intune`, `exchange-online`, `azure-rbac`,
`entra-roles`.

### 18.11 Audit tab (read-only view over the append-only trail)

The **Audit** tab is the operator-facing window onto the unified append-only audit
trail, written by both the engine `Write-PimAuditEvent` and the Manager
`Write-PimManagerAuditEvent`.

> **Where the trail lives.** The store is the database table `pim.AuditEvents`, created
> by the common store initialiser alongside the desired-state tables — audit is a
> standard feature of every topology, not an add-on for the largest one. It is
> append-only by intent: there is a writer and a reader and deliberately no update or
> delete helper. There is no audit file in any mode (SQL-only). A file-based installation
> that moves to the database carries its existing history across with
> `Import-PimAuditFileTrail.ps1`, which preserves each event's original timestamp and
> archives the file it imported so a second run cannot duplicate the trail.
>
> The read path resolves the trail through one pair of functions
> (`Get-PimManagerAuditEvents` / `Get-PimManagerAuditMonthCount`) so the view and the
> export always agree on which store answered. A failed read **reports the failure**; it
> never quietly falls back to a different and shorter trail, because presenting partial
> history as if it were complete is worse than showing none.

It promotes what used to be a fixed "latest N events"
preview into a full, filterable, paged view (**Audit & Settings → Audit trail**).

**Read path.** `GET /api/audit` returns the selected window newest-first. It is strictly
read-only — it never writes the trail. Both stores return events in the **same shape**, so
everything downstream of the read is identical either way: moving the store was not a
licence to rewrite the query layer. The read, the filter, the before/after diff and the
CSV serialisation all live in
ONE pure, dependency-free, PS-5.1-safe library — `engine/_shared/PIM-AuditQuery.ps1` —
so the on-screen view (`/api/audit`) and the export (`/api/audit/export`, below) resolve
the trail identically. Query parameters:

| Param | Meaning |
|---|---|
| `category` | one of `logins`/`delegations`/`accounts`/`approvals`/`engine`/`emergency`/`other` (or `all`) |
| `q` | free-text substring matched against `actor`/`action`/`target`/`result`/`change` (case-insensitive) |
| `months` | window: `3` (default, ≈ a rolling quarter — back-compat), `12`, or `all`/`0` = **full history**. N = the last N CALENDAR months (wall-clock window, intersected with the files that exist) |
| `from`, `to` | optional inclusive date range (`yyyy-MM-dd` or ISO) on the event `ts` (a date-only `to` covers the whole day) |
| `page`, `pageSize` | 1-based paging; `pageSize` clamped to 1..500 (default 50) |
| `limit` | back-compat alias for `pageSize` (the old Governance call used `?limit=N`) |

The response carries `events` (the page — each stamped with a `category` and a human
`change` before/after summary), `total` (events in the loaded window), `matchCount`
(after filter/search/date), `page`/`pageCount`, `counts` (per-category totals for the
chip badges), and `months`/`monthsLoaded`/`monthsTotal` (the window in effect vs how many
months of history the store actually holds — counted from the audit table; there are no
monthly audit files).

**Audit history, before/after, full-trail export ("Audit you can defend").** The
window is no longer hard-capped at three months: the trail is read from the audit table,
and a positive `months=N` is a wall-clock window of the last N months (so `months=all`/`0`
reads the whole history). Each event gains a `change` string via `Get-PimAuditChangeSummary`,
which flattens the event's `before`/`after` objects (`ConvertTo-PimAuditFlatMap`) and
renders only the fields that differ as `field: old -> new` (create = `(none) -> x`,
removal = `x -> (removed)`, unchanged fields omitted). `Select-PimAuditEvents` applies
the category/search/date-range filter and the newest-first sort, shared by both the view
and the export. **`GET /api/audit/export`** streams the WHOLE filtered trail (every match
across the window, default `months=all`, NOT just the page) as a `text/csv` attachment via
`ConvertTo-PimAuditCsv` — columns `When (UTC), Actor, Category, Action, Target, Result,
Change, WhatIf, CorrelationId, RunId`, RFC-4180 quoting + a CSV formula-injection guard
(`'` prefix on a leading `= + - @`), culture-independent ISO timestamps, and a UTF-8 BOM
for Excel. The Audit tab exposes a window selector (3 / 12 / all), From/To date inputs, a
Change column, and an **Export full trail (CSV)** button (client `fetch` → blob download)
alongside the existing per-page Export/Print.

**Category resolver.** `Get-PimAuditCategory` maps a raw `action` string to a stable
category by **prefix** (e.g. `account.*`/`tap.*` → accounts; `membership.*`/`group.*`/
`local.apply`/`msp.fanout`/`cutover.*` → delegations; `policy.*`/`resource.*`/
`config.*`/`settings.*`/`mail.send`/`license.*` → engine; `approval.*` → approvals;
`emergency.*` → emergency; `manager.login` → logins). Unknown actions fall to `other`,
so a new engine action is never dropped — it just lands in a sensible bucket without a
code change. The HTML chip list mirrors this set (kept in sync; covered by a static
test).

**Login capture (makes the Logins filter real, not dead).** The Manager records a
`manager.login` audit event the first time an identity loads the SPA in a given server
session — `Write-PimManagerLoginAudit`, called from the `GET /` handler, deduped per
`identity|role` via `$script:PimLoginAudited` so a page refresh does not spam the
trail. It records the resolved role, the role source, and `local`/`hosted` mode. Like
all audit writes it is best-effort and never blocks serving the page.

---

## 19. Editions

**Today every capability is available — licence enforcement is switched off.** The full solution
(the declarative engine, all configuration, the PIM Manager with its grid/wizards/map/validator,
admin lifecycle, policy templates, owners-as-approvers, audit, the SQL data store, MSP multi-tenant
fan-out, workload connectors, external intake, access reviews, self-service delegation and email
routing) ships ready to use. The product never phones home, shows no upgrade prompts, and with
enforcement off never blocks or degrades a feature based on entitlement.

**Licensing.** Licensing details for the Pro edition will be published soon. Single-tenant use of the
community edition (scenario S2) is free. The MSP scenarios — a managing (master) tenant and the
managed customer tenants it looks after (S3–S6, §11.8) — will be part of the paid (Pro) edition;
details will follow.

The solution is fully offline and self-contained: no activation server, no licensing endpoint, and
no internet connection is required for licensing to work (a licence is a signed file verified
offline, §19a).

### 19a. Feature-customization & license framework

The framework lets a senior administrator decide, **per customer/tenant**, exactly
which optional capabilities run — and gates them in the engine + jobs, not just the
GUI, so an off feature is genuinely inert.

**One catalog = source of truth.** `engine/_shared/PIM-FeatureCatalog.ps1` declares
every customizable capability as a single entry: a stable `key`, display `label`,
feature `group` (the GUI chapter), `tier` (`core` | `advanced`), `license`
(`free` | `pro`), `defaultEnabled` (advanced default off), `dependsOn` (other
keys), and an optional `proFeature` mapping to the existing offline-license Pro
catalog. **Core** entries are listed (so the GUI can show them) but are never gated.
The framework **builds on** the two pre-existing layers rather than replacing them:
`PIM-FeatureFlags.ps1` (GUI surface visibility / gradual rollout) and
`PIM-License.ps1` (the offline signed Core/Pro edition model).

**Two pure gate functions + a combined one.** `Test-PimFeatureEnabled -Key` reads
the persisted kill switch (merged over the catalog default); `Test-PimFeatureLicensed
-Key [-Edition]` compares the feature's license tier to the active edition;
`Test-PimFeatureAvailable -Key` = enabled **and** licensed (what side-effecting code
calls). Core always returns available; an unknown key is fail-safe off. All
PS 5.1-safe, no modules.

**One persisted state drives GUI + engine + jobs.** The kill switches live in the SQL
settings store under `pim.Settings` key `FeatureGates` (`{ gates: { key: bool } }`,
only non-default advanced overrides stored); the active edition under key `Edition`
(`{ edition, grantBasis, note }`). A small reader seam (`Get-PimFeatureStoreValue`)
resolves state from an in-process hydrated bag, then the Manager's `Get-PimSetting`
bridge, then a direct SQL read against `$global:PIM_EngineSqlCs` — so the engine and
scheduler (which have no Manager bridge) read the same persisted state the GUI writes.

**Gates wired everywhere.** A provider that maps to a capability carries a `feature`
key; `Invoke-PimEngineScope` checks `Test-PimFeatureAvailable` right after resolving
the provider and **no-ops the whole scope** (no `GetDesired`/`GetLive`, no diff, no
apply) when off — covering Full/Delta/queue triggers identically. The discovery sweep
(`Invoke-PimEngineDiscoverySweep`) is gated by `discovery.sweep`, with Power BI gated
separately by `connectors.powerbi`. The scheduler gates at the central
`Invoke-PimScheduledJob` dispatch: a master `scheduler.jobs` switch plus a per-type
map (`Get-PimJobFeatureKey`) so a disabled feature's job never invokes its handler.
The notify path (`Send-PimNotifyMail`) honours a global email kill switch
(`$global:PIM_MailKillSwitch`), the `alerting.email` feature gate, a redirect target
and an allowlist at the one send chokepoint — so every alert/digest/job send is
covered.

**Editions.** `Get-PimActiveEdition` returns the persisted edition when set, else the
offline-license-derived edition (`Get-PimEdition`), else `Core`. `Pro` and
`Pro-DesignPartner` both cover `pro` features; they differ only in the recorded
`grantBasis`. The Manager exposes it read-write via `GET/PUT /api/settings/edition`,
the kill switches via `GET/PUT /api/settings/feature-gates`, and email controls via
`GET/PUT /api/settings/email-controls` (writes SuperAdmin-gated + audited). The
Settings surface renders the catalog grouped into chapters; a disabled feature is
dimmed + labelled “Disabled”, an unlicensed one shows a “Requires Pro” lock — never
hidden. Dependency cross-references are surfaced (`Get-PimFeatureDependencyIssues`).

#### 19a.1 The commercial shape, and what the code actually enforces (2026-09-18)

The **commercial** split and the **technical** gate are two different things, and the public docs
now say so explicitly rather than implying the second from the first.

| | Commercially | In this release's code |
|---|---|---|
| **Free** — the community edition for a **single tenant**: the full portal, eligible time-boxed access with approval and audit, delegation by group, drift detection, reviews and reports, admin accounts + first-time access passes, self-updating from the public release, community support | free | not gated |
| **Paid** — everything in free **plus the multi-tenant half**: define once and target tenants by tag and wave, signed definition sets verified on arrival, visibility of what reaches each tenant and what is withheld, per-customer rules, a read-only preview of what a tenant would receive, fleet conformance, rollout waves, central accounts whose lifecycle flows down, removals that stay the tenant's call, controlled release rings, the provider-hosted option, support with an agreed response time | paid | **not gated** |

🔒 **Licence enforcement is switched OFF in the product.** `Test-PimFeatureLicensed` exists and is
wired, but with no licence file present `Get-PimActiveEdition` reports `Core` and nothing is
degraded, blocked or hidden. **The public docs must not imply a technical gate that does not
exist** — README's "Editions" section and `FEATURES.md` §29 both state the enforcement status in
the same paragraph as the split, deliberately. The call to action for the licensed edition is a
single mail address (`mok@mortenknudsen.net`) and nothing else: no phone number, no company
internal domain, no tenant name. The sanitization gate accepts that address; it is the one
deliberate contact detail in the public set.

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

**Bulk-activate confirm guard.** Activating many eligible roles in one click is
powerful, and the list arrives partly pre-checked, so a fat-finger could elevate
far more than intended. When the selection reaches the threshold, the first
**Activate** click *arms* a confirm state — the button turns amber and reads
"Activate N roles — click again to confirm" — instead of firing. A second click
within a short window (auto-disarms after a few seconds) proceeds. Any change to
the selection (toggling a row, select-none, re-render) disarms it so the second
click always reflects the current selection. Small selections (below the
threshold) activate immediately — no change to the common 1–3 role case. This
mirrors the existing My-Access bulk-**deactivate** "click again to confirm" UX.

The threshold is **policy-configurable** (default 5, clamped 1–100). Resolution
order: a per-entry `bulkActivateConfirmThreshold` on the active tenant's catalog
entry wins; else a tenant-wide `bulkActivateConfirmThreshold` managed-config key;
else the built-in default. The resolution is a pure, side-effect-free function in
`popup-config.js` (imported by `popup.js`, single definition — no inline drift)
so it is Node-unit-testable; `loadConfig` stamps the resolved number onto `cfg`,
and the guard reads `cfg.bulkActivateConfirmThreshold`. It is **never** user-
enterable (confirm strength is an admin policy decision); the key is declared in
`managed-schema.json` and pushable per browser via the custom ADMX/ADML
(`BulkThreshold_Edge` / `BulkThreshold_Chrome`, valueName `bulkActivateConfirmThreshold`).

**First-run getting-started tip.** The first time a freshly-onboarded user lands
on a populated Activate list, a one-time dismissible note (`maybeShowGettingStartedTip`)
is injected directly above the group list, pointing at bulk-activate and the My
Access tab. It is fully self-contained (builds its own node + handlers, no coupling
to `render()` internals), wrapped in try/catch so it can never break the popup, and
sets `gettingStartedTipDismissed` in `chrome.storage.local` on dismiss so it shows
exactly once. Deliberately additive, leaving the mature render path untouched.

**Propagation watch — poll-driven, never a timer.** PIM returns no completion
reply: the activation POST is accepted immediately and the nested/transitive
groups and roles land asynchronously, typically flat for 1–8 minutes and then in
one jump. `watchPropagation` (in `popup.js`) therefore decides completion purely
from what each 10-second poll **observes**. The signal is a COMBINED count —
eligible PIM groups + active group assignments + active direct Entra roles —
because a role group can carry 40+ transitive assignments; watching eligible
groups only is wrong. Completion is decided per watched scope from its shape
`{ nesting, entraRoleIds }`:

| Scope shape | Release condition (activate) |
|---|---|
| Detectable Entra role on the group | the role is verified **assigned** to the user (beta `transitiveRoleAssignments?$filter=principalId eq '{me}'`, advanced query), re-checked each poll |
| `nesting` fan-out group, no enumerable role | count-settle — identical COMBINED count across `STABLE_POLLS` consecutive polls after it moved, or the learned target reached |
| true leaf, no detectable role | as soon as the user is a member (the grant follows shortly, out of band) |

`nesting` means the group takes part in a group-in-group chain in **either**
direction — it contains child PIM groups (`transitiveMembers`, DOWN) **or** is a
member of role-bearing groups (`transitiveMemberOf`, UP). Down-only is wrong: in
a live tenant the role groups fan out *upward*. It is derived from the Show-Roles
fan-out's related set with a direct up+down probe as fallback, defaulting to
`true` on uncertainty so a fan-out is never released early. **Deactivation is
deliberately asymmetric**: Entra role *removal* propagates over minutes, so once
membership is dropped the watch releases immediately and never re-verifies role
removal; nesting groups still use the falling count-settle. The only time bound
anywhere is an 8-minute safety backstop against a stuck watch — not a normal-path
delay. Banned reintroductions (all previously shipped as regressions): settling
the instant the count moves, any fixed settle duration, completing on the direct
group alone, watching eligible groups only. Guarded by
`tools/pim-activator/tests/test-watch-poll-driven.js`. 

**"Show Roles" preview — all planes, both directions, eligible + active.** Beta
`transitiveRoleAssignments` on a *group* principal does not traverse the groups
that group is a member of, so the preview fans out **DOWN** (`transitiveMembers`)
**and UP** (`transitiveMemberOf`) and merges/dedups the results with the group's
own roles. Coverage: Entra directory roles — active via `roleAssignments` +
`transitiveRoleAssignments` + `roleAssignmentScheduleInstances`, eligible via
`roleEligibilityScheduleInstances`; Azure RBAC via Resource Graph
(`microsoft.authorization/roleassignments` +
`…/roleeligibilityscheduleinstances`) for the group and its nested groups;
workload roles (Defender XDR, Power BI, AzDevOps) arrive through the nested
fan-out. The fan-out runs **always**, not only when the group's own query is
empty. `deriveRoleFromGroupName` is a last-resort fallback only — beta
`transitiveRoleAssignments` needs no extra read permission, so a missing role is
never an excuse to name-guess. The one legitimate name-guess case is Azure: Azure
RBAC read is gated on the signed-in account's own Azure permissions (unlike Entra
roles), so a tenant-root or otherwise unreadable scope genuinely returns nothing.
Per-endpoint, per-direction diagnostics are emitted on every expand so an empty
result is explainable from one snapshot.

**Extension identity is a public contract.** The extension id
`eheocihmlppcophaeakmdenhgcookkab` is deterministic from the public `key` in
`manifest.json` (Chromium: first 16 bytes of `SHA-256(DER pubkey)`, each nibble
mapped `0–15 → a–p`). The id appears in the app-registration redirect URI, the
managed force-install policy and the published CRX, so it must never drift. Only
the **machine holding the master signing key** reproduces that id; a repack is
valid from that machine alone, never from another.

**Package validator (`Test-PimActivatorPackage.ps1`).** A pure, offline,
PS 5.1-safe linter for the extension *source* — it does **not** sign or repack.
It is dot-sourceable (functions only) and also runnable as a CI/preflight gate
(non-zero exit on failure). Checks: **MANIFEST** (parses, MV3, version
well-formed), **IDLOCK** (re-derives the id from the manifest `key` and asserts it
still equals the canonical id — catches accidental key drift before signing),
**VERSION** (popup version badge is wired to `chrome.runtime.getManifest().version`
so it can't lie), **NODEVCODE** (no device-code grant anywhere — MS blocks it via
managed CA; the supported path is Edge PKCE loopback), **PKCE** (`launchWebAuthFlow`
+ `code_challenge` present), **BRANDING** (name + attribution footer), and
**NOSECRET** (no real tenant/subscription GUIDs baked into shipped files — now also
scanning `popup-config.js`; all-zero and single-repeat placeholder GUIDs are
allowed). It is now **wired as a hard preflight** inside the `-Repack`/`-PackOnly`
path of `Update-PimActivator-Extension.ps1`: the script dot-sources the validator
and runs it (alongside the Node `popup.js` syntax check) **before** bumping the
version and **strictly before** the master-key `--pack-extension` sign step; any
Error-severity finding throws and aborts, so a drifted id or a leaked GUID blocks
the build before signing. Covered by `tests/PIM.Activator.Tests.ps1` (offline, 29
assertions across 7 Describe blocks: validator + gate wiring/ordering +
configurable threshold + getting-started tip).

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
reject), offline signed-file verification, per-tenant cert auth, and the cloud-native
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

---

## 27. Identity, credentials and self-healing

> **The rule: a deployed environment holds no credential it can avoid holding.** Everything the
> product *calls out to* runs on a managed identity. The only credential that remains is the one
> Azure gives no alternative for — and it authenticates sign-in, nothing else.

### 27.1 Who is who

| # | Who | Identity | Credential | Where it lives |
|---|---|---|---|---|
| 1 | Manager, tick, update, downlink → Graph, ARM, SQL, Log Analytics | **system-assigned managed identity** | **none** | nowhere |
| 2 | Container image pull from ACR | **user-assigned MI** (`id-pim-<token>`) | **none** | nowhere |
| 3 | **Sign-in** (Container Apps built-in auth) | app registration | **client secret** | ACA secret, referenced by name |
| 4 | **Operator troubleshooting** | SPN | **client secret** | the customer's Key Vault |
| 5 | Deploy / onboarding | SPN | **client secret** | the customer's Key Vault |

Rows 1–2 are the product at rest. Rows 4–5 are humans, and exist only on the machine driving a
deployment — never inside the environment.

### 27.2 Why row 3 is a secret and not a managed identity

Container Apps' Microsoft Entra provider does not accept a managed identity; neither the
authentication article nor its Entra sub-page offers one. The secret **is** optional — omitting it
selects **implicit flow**, returning only an ID token — but Microsoft documents implicit as
*"avoid … you should only use this flow when other more secure flows aren't viable."*

Removing a stored secret by adopting a weaker OAuth flow is not a net gain, so the secret stays.
What makes it acceptable is how little it can do: it authenticates **sign-in only**. It grants
nothing in Azure, nothing in Graph, no access to SQL or the store. Stolen, it lets someone
impersonate the app in a login redirect — not read a single row.

### 27.3 Why a managed identity is enough for everything else

`Setup-PimContainers` grants the Graph app-roles to the container app's and the jobs' managed
identities via `Grant-PimMiGraph`, which **throws** on a failed assignment rather than warning. A
deploy that returns therefore cannot have left an identity short. The tick job receives the
**engine** set and the Manager the **read-only** set (§7), so a re-run can never quietly widen the
Manager.

This is how hosted environments run in production: the tick job carries no secret and no
`PIM_ClientId`, and its managed identity holds the engine set listed in §7.

🪤 **Setting `PIM_ClientId` without a usable credential is worse than setting nothing.**
`Get-PimRestToken` takes the managed-identity branch only when `IDENTITY_ENDPOINT` is set **and
there is no client id**. A client id with no secret therefore suppresses MI *and* cannot
authenticate — the container authenticates as nothing, and the deploy is still green.

### 27.4 The one thing a managed identity cannot do

**Cross tenants.** A managed identity exists in one directory. An MSP *master* acting into a
*managed* tenant needs a multi-tenant app registration with a credential — `S5`
(`spnModel = multi-tenant-spn`). Every other shape (`S1`, `S3`, `S6`) acts only inside its own
tenant, so managed identity covers them completely.

### 27.5 System-assigned, and why that is the right choice here

A system-assigned identity dies with the resource; a user-assigned one survives. That difference
only matters when an app is **deleted and recreated**, which in production never happens: the
nightly update rolls images with `containerapp update --image`, creating a new **revision** of an
existing app. The identity is a property of the app, not the revision, so every SQL contained user
and role assignment keyed to it keeps working indefinitely.

The single exception is the internal→external migration (`Rebuild-PimEnvExternal`), because an
environment's exposure is immutable. That path regenerates the identities, and
`Get-PimIdentityRepairPlan` exists to repair what they were keyed to — see §27.7.

### 27.6 What self-heals

* **The nightly update**: detect → build → roll → idempotent schema upgrade → verify →
  **auto-rollback on a failed verify** → notify.
* **A failed deploy** leaves its marker stale, so the next sync retries rather than needing a human.
* **Sign-in secret rotation** (§27.8) — renewed before expiry by the update job itself.
* **Identity-keyed state after a rebuild** (§27.7).

### 27.7 Identity repair after a rebuild

Recreating a container app mints a new system-assigned identity, and everything keyed to the old
principal silently stops matching: the **SQL contained users** (whose SID is the old identity's
*appId*) and every **Azure role assignment**. Neither is configuration, so a configuration diff
cannot see either one — the restore reports a faithful match and the Manager then crash-loops on
`Login failed for user '<token-identified principal>'`.

`Rebuild-PimEnvExternal` records both **before** the delete (afterwards the principal is
unresolvable and its assignments are already gone), and repairs them after the restore and
**before** exposure, verifying every SID by reading it back.

### 27.8 Sign-in secret rotation, unattended

The sign-in secret is the only thing in the design that fails on a timer, and a warning is a memory
rather than a mechanism. The update job already runs nightly on a managed identity, so it renews the
secret itself:

1. read the days remaining on the credential the app's auth provider references
2. inside the threshold → mint a **new** secret with `--append`, leaving the existing one valid
3. write it to the ACA secret and restart the active revision
4. verify the app still challenges unauthenticated callers

**The old credential is never revoked automatically** (by design). Both are valid at once,
so there is no window in which sign-in is broken, and no reliance on the rotation's own verification
being perfect. Revocation is a separate, deliberate act.

The enabling permission is `Application.ReadWrite.OwnedBy`, granted to the update job's identity and
scoped to that **one** app registration — not tenant-wide.

🪤 **An ACA secret change neither restarts the app nor creates a revision.** The auth sidecar keeps
using the previous value, so a rotation that is never rolled looks applied and is not.

### 27.9 What does not self-heal, by choice

The **operator** and **deploy** credentials (rows 4–5). A credential that rotates itself unattended
is a way to lock yourself out of the environment you rotate it in. Those are reported by
`Test-PimCredentialExpiry.ps1` and renewed deliberately.

### 27.10 The SQL admin group — who administers the database

Azure SQL has exactly **one** Microsoft Entra admin. When that slot holds a single principal, every other
identity that must administer the database needs a contained user created by that one principal — and an
environment whose admin cannot be used unattended can then never be fixed unattended. So the admin is a
**security group** (default `grp-pim-sql-admins`) and membership is the access:

| Member | Why |
|---|---|
| the nightly updater's managed identity (`ca-pim-update`) | applies additive schema changes before a roll |
| the environment's user-assigned identity (`id-pim-<token>`) | the environment's own standing identity |
| the in-network SQL identity (`id-pim-sql-<token>`), private SQL only | the in-cloud database bootstrap runs as it |
| the deploy identity | creates contained users and applies the schema from the deploy host on public SQL |
| the troubleshooting identity, when given | support access, used only for troubleshooting |
| whoever was admin before converging | converging never takes access away |

Entra-only authentication stays on. Contained users that already exist keep working.

**Converging** is one idempotent step, `tools/setup/Initialize-PimSqlAdminGroup.ps1` (the logic lives in
`tools/setup/_PimSqlAdminGroup.ps1`): read the group, its members, the current admin and Entra-only; plan;
create the group if absent; add missing members; make the group the admin; then read all of it back. A second
run reports no changes. Certificate or signed-in (certificate) context only — the step has no secret parameter.
`-PlanOnly` shows the plan; `-MembersOnly` only adds members, and only when the group already is the admin.

* **New environments:** `New-PimHostingPrerequisites.ps1` converges on the group for public and private SQL.
  If Microsoft Graph refuses the deploy identity the group rights, the earlier single-principal admin is kept
  and the command to converge later is printed; a group admin is never moved back to a single identity.
* **Every updater deploy:** `Deploy-PimUpdateJob.ps1` adds the updater's identity to the group in
  members-only mode — it never creates the group or moves an admin, so an environment still on a
  single-principal admin is left as it is and keeps using its contained user.
* **The updater itself** needs nothing but its managed identity. With no database settings of its own it
  takes the Manager's server and database for the run and records them on its job (written, read back, and
  never allowed to fail the update). A secret or vault pointer is never copied — that case, and an unreadable
  Manager, still refuse a version change. When sign-in fails, the refusal names the identity's object id
  (read from the token the database refused) and the group to add it to.

Directory behaviours the step handles: reading a group's members without a type filter can omit service
principals under app-only auth, so membership is read per type; adding a member that is already present
returns an "already exist" error, which is success; setting the SQL admin is asynchronous, so the new admin
is polled for; and the group is never added as a member of itself.
