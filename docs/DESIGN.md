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
11. [Hosting & runtime (single-tenant, two-plane topology, execution model, install guide, update lifecycle)](#11-hosting--runtime)
12. [Containers](#12-containers)
13. [MSP architecture (two planes, signed courier, profiles)](#13-msp-architecture)
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

**Governance drift view + gated remediation (`PIM-Governance.ps1` §5, REQUIREMENTS §28 [M5]).**
A general "is the live estate still what we intended?" view layered **on top of the engine
delta — it does NOT reimplement reconciliation.** The Manager runs the engine in plan/WhatIf
mode (`Invoke-PimEngine -Scope All -Mode Full -Prune -WhatIf` — **no writes**); each scope's
diff (`Compare-PimDesiredVsLive`) is normalised by the pure `Get-PimDriftReport` into one flat,
classified list — `create → missing`, `update → changed`, `remove → extra` (an `extra` only
appears because the plan was computed with prune ON). "Apply now" is the gated remediation:
`Get-PimDriftRemediationPlan` (pure) narrows the report to ONLY the selected drift and returns
the `(entity,key)` change list, which the Manager feeds straight back to the engine via
`-Changes` — `-Mode Delta` for the selected missing/changed, and **`-Mode Full -Prune` only
when a selected `extra` was explicitly opted in** (`-AllowRemove`; an explicitly-selected extra
without the opt-in is *refused*, never silently dropped or removed). So remediation reuses the
same change-restricted apply path as a commit-queue delta, inherits all the destructive-safety
guards above (empty-desired prune refusal, the account-disable circuit breaker, the approval
gate), and a single click can never destructively remove a live delegation. Wired into the
Governance tab via `GET /api/drift` (plan/WhatIf, Reader-visible) + `POST /api/drift/remediate`
(Admin-gated, audited as `governance.drift.remediate`); detected drift also raises the `drift`
Manager alert. The drift read needs the hosted engine + a live tenant context — offline/static
returns a clean "needs the server" body so the control degrades rather than dying.

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
  no server is set) reached with **Integrated** auth. This is the **development / management-
  server inner-loop** path: the running identity is itself a DB user, so there is **no
  cross-tenant token problem and no "MI is not a DB user" blocker** — the engine reads its
  desired set directly. Only the database *name* (`PIM_SqlDatabase`) is mandatory. **It is a
  dev convenience, NOT a production or break-glass store** — Azure SQL is the single
  authoritative store in ALL modes, and **break-glass = a client PC connecting DIRECT to the
  same Azure SQL** (never a local copy). The cutover ceremony enforces this: it refuses to
  *finalize* a cutover whose target is a local/Integrated store (`Get-PimSqlStoreKind` →
  `dev-local`, see §5.3).

### 5.3 DB cutover ceremony, on-demand recalc & resilient health (`PIM-Cutover.ps1`)

Moving an existing instance onto SQL is a **gated ceremony**, not a one-shot switch — driven
by the Manager (`/api/cutover`: GET = status, POST = run the next/named stage). Six ordered
stages, each gated on the prior (`Test-PimCutoverStageAllowed` / `Get-PimCutoverNextStage`),
idempotent, with the state + per-stage audit persisted in `pim.Settings` (`CutoverState`) and
mirrored to the append-only audit (`Write-PimAuditEvent`, `cutover.<stage>`):

1. **preflight** — read-only: SQL connectivity + a locked-schema audit of the SOURCE CSV
   headers (`Get-PimCutoverPreflightAudit` over `Get-PimLockedSchema`) reporting exactly what
   the upgrade will drop/add/migrate (e.g. `TierLevel → Purpose`).
2. **upgrade** — one-time idempotent schema CREATE/ALTER (`Initialize-PimSqlStore`).
3. **import** — **transactional** CSV → `pim.Rows` (`Invoke-PimCutoverImport`): the
   `*.custom.csv` source is read **READ-ONLY** (never written back) and full-set-replaced into
   `pim.Rows` inside **one transaction** — any failure rolls the whole import back, leaving the
   store exactly as it was. Every entity + row count is captured for the audit.
4. **set-source** — flip the persisted config source to SQL (`pim.Settings` `StorageBackend=sql`).
5. **re-preflight** — re-run the checks against the now-populated SQL store (data signature +
   row count + connectivity).
6. **finalize** — **explicit operator confirmation**. Refuses any non-Azure-SQL target
   (`Get-PimSqlStoreKind.isProduction`): only Azure SQL may become authoritative; SQLEXPRESS /
   Integrated (`dev-local`) is rejected.

**On-demand recalc on SQL change.** A cheap change-detector (`Invoke-PimSqlChangeDetector`)
reads a SQL **data signature** — `COUNT(*)` + `MAX(UpdatedUtc)` over `pim.Rows`
(`Get-PimSqlDataSignature`) — compares it to the last acted-on signature (`pim.Settings`
`RecalcSignature`), and on a change enqueues an `engine-delta` trigger (`Add-PimJobTrigger`)
that the scheduler drains on its next tick. This catches **out-of-band** writes — another MSP
node, a direct SQL edit, the cutover import — that never bumped the Manager's in-process
watermark. It is wired into `Invoke-PimSchedulerTick` (step *a-sql*), is fail-open (a read
error yields a unique signature so a recalc is never silently skipped), and is idempotent (no
change → no trigger). The signature is persisted *before* the trigger fires, so a crash
mid-trigger can't loop forever — a redundant recalc is safe (the engine is idempotent), a
missed one is not.

**Persistent SQL compute + resilient `/health`.** The hosted SQL compute MUST run persistent
(serverless **auto-pause disabled** / provisioned) so neither the health probe nor the first
post-idle request cold-starts; `Test-PimSqlPersistentCompute` is the validator (a serverless
SKU — name carries `serverless` or the `_S_` family marker — with an auto-pause delay ≥ 0 is
**flagged**; `-1` or a provisioned tier is **persistent**). The Manager `/health` endpoint is
**unauthenticated** (App Service / Container App probe) and **resilient to a transient SQL
blip** via `Get-PimHealthState`: a sub-threshold consecutive failure stays **HTTP 200**
("degraded") so the platform doesn't flap the Manager over one hiccup; only a **sustained**
outage (≥ 3 consecutive failures) returns **503** ("unhealthy"). In CSV/local mode there is no
SQL to probe, so it is always healthy.

### 5.4 Safe, reversible Review & Save commits (`PIM-CommitBackup.ps1`)

The Review & Save commit (`PUT /api/csv/<base>`) is **backup-first, all-or-nothing, and
reversible** (REQUIREMENTS.md §28 [M1]). The logic lives in a pure, injectable core
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
  exactly as before (the [M1] half-apply defect). File mode reuses the atomic `Write-PimCsvCustom`.
- **Undo / rollback.** `Get-PimSnapshotRestorePlan` turns a stored snapshot into a full-set replace
  that perfectly reproduces the pre-commit state — including rows the bad commit had deleted. The
  operator triggers it from the Review & Save **Backups / Undo** view (`GET /api/backups/<base>`
  lists snapshots newest-first; `POST /api/backups/restore {base,id}` replays one, Admin-gated).
- **Retention.** `Get-PimBackupRetentionPlan` (pure) keeps the newest N per entity (default 10) and
  prunes the oldest; applied after each commit. Snapshots live in `pim.Backups` (SQL mode) or
  `<output>/backups/*.json` (file/dev mode); both stores share the pure planner.

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
(see REQUIREMENTS §19).

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
| 20 | Groups | `PIM-Definitions-{Roles,Services,Organization,Tasks}` | the PIM groups (+ owners, AU attach) |
| 30 | Admins | `Account-Definitions-Admins` | admin accounts |
| 35 | AdminTap | `Account-Definitions-Admins` (CreateTAP) | Temporary Access Pass |
| 40 | EntraRoles | `PIM-Assignments-Roles-Groups` | directory role → **group** (tenant scope) |
| 45 | RolesAUs | `PIM-Assignments-Roles-AUs` | directory role → **group**, scoped to an AU |
| 48 | EntraRolesDirect | `PIM-Assignments-Roles-Direct` | directory role → **user** (PIM v1 direct; see §6.1) |
| 50 | AdminMembers | `PIM-Assignments-Admins` | admin → **eligible/active member of a group** |
| 55 | GroupMembers | `PIM-Assignments-Groups` | group → member of a group (nesting) |
| 60 | AzRes | `PIM-Assignments-Azure-Resources` | Azure RBAC role → **group**, at an Azure scope |
| 62 | DefenderXdrRoles | `PIM-Assignments-Defender` | Defender XDR (Unified RBAC) role → **group** (see §6.4) |
| 64 | IntuneRoles | `PIM-Assignments-Intune` | Intune RBAC role (+ scope tags) → **group** (see §6.4) |
| 66 | EntraAppRole | `PIM-Assignments-AppRole` | **any** enterprise-app app role → **group**, via `appRoleAssignedTo` (generic; see §6.4) |
| 70 | GroupsPolicies | definition `PolicyTemplate` | per-group PIM policy (approval, MFA/justification) |
| 80 | AccessReviews | definition `ReviewCycle` | per-group access-review schedule (reviewers = owners) |
| 90 | AdminOffboarding | `Account-Definitions-Admins` | **removes** an offboarded admin's delegations (see §6.2) |
| 95 | HybridAdProvisioning | `Account-Definitions-Admins` (AD platform) | **PLANS** on-prem AD accounts + gMSA/sMSA; on-prem write is hybrid-worker-only (see §6.5) |

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

### 6.2 Offboarding — clean delegation removal (`AdminOffboarding`)

When an admin is **retired** — `Account-Definitions-Admins` carries
`Lifecycle=Retire`, or an `OffboardDate` (date expression / ISO) that has been
reached — the REST engine strips **every PIM-for-Groups membership** (eligible +
active) that admin holds across the managed groups, so no lingering privileged
reach survives the offboarding. (Account *revoke + delete* is the legacy CSV
engine's separate, higher-privilege step; this scope handles the **delegation**
half over REST.)

It is built as a **remove-only** scope: `GetDesired` is intentionally empty (the
desired end-state for an offboarded admin's delegations is *none*) and `GetLive`
returns **only** the memberships held by explicitly-offboarded admins — a
non-offboarded admin never contributes a live row, so the diff can only ever remove
the right rows. Because empty-desired is authoritative here, the provider sets
`allowEmptyDesiredPrune=$true` to opt out of the engine's "0 desired = wrong store"
prune guard (every other scope keeps that guard).

Triple-gated, like every destructive path:
1. only under **`-Mode Full -Prune`** (the engine's standard destructive gate);
2. **`$global:PIM_OffboardCleanupMode`** = `Off` (skip) | `Report` (plan only — the
   default; logs *would-offboard* lines, writes nothing) | `Enforce` (apply the
   `adminRemove` schedule requests).

The pure planner `Get-PimOffboardingPlan` (admin rows × a *principal → live
memberships* map → the removal plan) and the `Test-PimAdminOffboarded` predicate
are fully unit-tested offline.

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
(the `◻` in REQUIREMENTS § 6) and is the hybrid-worker contract above.

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

### Approvals tab — maker/checker control plane (2026-06-15)

The **Approvals** tab is the human control plane over `engine/_shared/PIM-ApprovalGate.ps1`
(REQUIREMENTS §13/§27 H3/H4). Destructive identity actions (offboard / revoke / disable) are
raised here and must be approved by a **different** administrator before any controlled
execution is possible — **nothing executes automatically; this GUI introduces no auto-execute
path**. Endpoints (`tools/pim-manager/Open-PimManager.ps1`): `GET /api/approvals` (the queue,
newest first; each offboard item carries the engine-derived `Get-PimOffboardSequencePlan` —
disable → revoke active → SCHEDULED delete — shown before approval; per-item `canDecideThis`
encodes Admin-role + Pending + separation-of-duties), `POST /api/approvals` (raise — maker,
Admin+, requestor = the authenticated Manager identity), `POST /api/approvals/decide` (approve/
deny by id — checker, Admin+, **maker≠checker** mapped to 403, idempotent via the gate's
once-Pending transition). The gate library is dot-sourced at boot and a `Get-/Set-PimSetting`
shim bridges its persistence chain onto the Manager's own settings store (SQL `pim.Settings`
when active, else the per-instance `manager-settings.custom.json`), so a request raised in the
Manager is the same record the scheduler/engine see. A Home **pending-approvals** tile (fast
load, no live call) deep-links here. **Name-collision hardening:** `PIM-ApprovalGate.ps1` and the
older portal lib `PIM-Approvals.ps1` both export `New-PimApprovalRequest` /
`Resolve-PimApprovalDecision` with different signatures; the gate's internal callers use private
`New-PimGateApprovalRequest` / `Resolve-PimGateApprovalDecision` (public aliases retained) so an
`Import-Module -Force` re-loading both libs can no longer shadow-break the queue.

### Maker/checker on sensitive authoring/onboarding ([M4], 2026-06-16)

Sensitive **Authoring / Onboarding** commits get a second-person approval gate **layered on the
same control plane above** (REQUIREMENTS §28 [M4]) — there is no second approval system.
`engine/_shared/PIM-SensitiveAuthoring.ps1` adds two pure, PS 5.1-safe pieces:

1. **Classification** — `Get-PimAuthoringSensitivity` (+ predicate `Test-PimAuthoringActionSensitive`)
   marks a proposed change SENSITIVE when ANY of the [M4] conditions hold: a **privileged-role
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
`Get-PimNotifyTemplateText` (persistent-store override → file `.custom.html` →
shipped `templates/mail/*.mailtemplate.html`; see §17.6) with
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

### 10.1 Notification batch (`PIM-Notifications.ps1`)

The §12 batch lives in `PIM-Notifications.ps1` (dot-sourced by `PIM-Functions.psm1`
and by `PIM-Notify.ps1`). Every function is a **pure transform** (events/rows/now →
tokens / decision / store record) with no network, so the whole batch is offline
unit-testable; the actual send is the existing channel layer, wired from the
scheduler handlers. All four honour the **two-approval model** — the engine notifies
on delegation/assignment lifecycle only and **never** sends an activation email.

1. **Daily summary** — `Get-PimDailySummary` folds audit events (`output/audit/
   pim-audit-<yyyyMM>.jsonl`) over a 24-h window into new-admin / delegation / removal
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

**Active PIM assignments — read across three surfaces, with honest error
surfacing.** The Revoke / Workload-delegation view (`GET /api/active-assignments`
→ `Get-PimActiveAssignmentsCached`) enumerates *active* PIM assignments from three
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
| **sync-automateit** (controlled image auto-update) | scheduled (opt-in) **+** on-demand `-Apply` | in-container scheduler job / VM scheduled task → version-check → zero-downtime roll → hosted-smoke health check → auto-rollback |

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

### 11.3a Run history + the Manager Jobs tab (read model)

So an operator can *see* what the scheduler is doing, the tick persists a bounded
**run-history ring** alongside the existing scheduler state. Each scheduled or
triggered run is recorded by `Write-PimJobRunRecord` → `Add-PimJobRunRecord` as a
record `{ runId, name, type, scope, ok, ran, status(running|completed|failed),
detail, startedUtc, finishedUtc, durationMs, log }`. The log is synthesised from the
dispatch result (`detail` + the handler's inner `ran`/`whatIf`/`detail` and any
`log` lines) by `ConvertTo-PimRunLogText`. History persists through the **same store
chain as scheduler state** — SQL `pim.Settings` (`JobRunHistory`) when SQL is wired,
else a JSON sibling of the scheduler-state file (`output/scheduler/pim-scheduler-runs.json`),
else in-memory — so the **Manager and scheduler processes share it**. The ring is
trimmed per job (`$script:PimRunHistoryMax`, default 50).

`Get-PimJobsStatus` is the GUI view model: one row per configured job, joined to its
latest run and the persisted last/next-run state. **In-progress runs** (a `running`
record with no `finishedUtc`) sort to the **top**; the rest follow by most-recent
activity. Each row carries cadence (`Format-PimCadence`), enabled state, last
run/result/ok, next run, and the `runId`s the GUI needs for the log button.

The Manager surfaces this via four endpoints in `Open-PimManager.ps1`
(it dot-sources `PIM-Scheduler.ps1` and points `$global:PIM_SchedulerStatePath` at
the active instance's `output/scheduler/` before reading; SQL deployments override
transparently via `Get-PimSetting`):
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
- `POST /api/jobs/run` (Admin+) → **force-start** ("Run now"). `Invoke-PimJobForceStart`
  writes an in-progress placeholder, dispatches the registered handler, then replaces
  the placeholder with the finished record **under the same `runId`** — so the run
  appears in `/api/jobs` (running → completed) and is readable via `/api/jobs/log`.

**Dead-view fix.** A job with no run-history record AND no persisted `lastRunUtc` is
flagged `neverRun=true` and gets a **synthesized** `nextRunUtc` (now + cadence,
`nextRunSynthesized=true`) so the row shows "next run <t>" instead of a blank "—" for
both last and next. This is the normal state before the scheduler has ticked (or when
its history isn't co-located with the Manager); the tab no longer looks dead.

**Failure history, overdue detection + acknowledge ([M6]).** Three pure cores extend
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
  `failingCount` (rows with an **unacknowledged** failed run) summaries. Because the
  Manager drives the read model with the *effective* schedule (which carries no run
  stamps), `Get-PimJobsStatus` falls back to the **persisted scheduler-state** stamps by
  job name for the last/next-run basis.
- **Acknowledge/clear** mutes a known failure without losing the record: a bounded set of
  acknowledged `runId`s persists via the same store chain as the run history
  (`pim.Settings 'JobAcknowledgements'` → JSON sibling → memory). `Set-PimRunAcknowledged`
  (idempotent, `-Clear` to un-ack) is exposed at `POST /api/jobs/ack {runId; clear?}`
  (Admin+, audited). An acknowledged run still appears in history (audit intact); only its
  failure/overdue **signal** is suppressed (`acknowledged=true`, dropped from
  `unackedFailureCount`/`failingCount`). **Re-run** reuses the existing force-start path.
The Jobs tab renders a top **"needs attention"** banner (overdue/failing counts), an
overdue badge + recent-failure count per row, a **History** modal (recent runs with
pass/fail/when, each linking to its log), and **Ack** / **Run now** actions.

The **Jobs** tab (`pim-manager.html`, `renderJobs()`) renders the table with
in-progress jobs first, a per-row **Logs** modal, optional 5s auto-refresh, and a
**live tail** that re-polls an in-progress run's log every 2s until it finishes. For
Admin+ each row also exposes an **enabled** toggle, an inline **cadence** editor
(`saveJobState` → `PUT /api/jobs/state`) and a **Run now** button (`runJobNow` →
`POST /api/jobs/run`, which then opens the new run's log). Never-run rows show
"no runs yet" with a computed next-run; an empty history shows a banner.
`tools/pim-scheduler/Seed-PimSchedulerRuns.ps1` writes a representative state +
history (incl. one in-progress run) so the tab is also pre-populated in a
fresh/offline environment.

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
  directory app-roles, and the Manager DNS record. The web Manager uses
  `--ingress external` on an **internal-only** environment — a static **private** IP
  with no public exposure, the one ingress reachable from peered/hub-VNet clients.
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
Azure CLI) up front, **refuses any region outside West Europe / Denmark East**, and
ends by printing **exactly which DNS and private-link zones to add** for Entra Global
Secure Access (Private Access) so cloud-only users reach the internal Manager without
a VPN — the SQL `database.windows.net` zone, the App Service `azurewebsites.net` zone,
the storage `blob.core.windows.net` and Key Vault `vaultcore.azure.net` zones, the
GSA Private-Access app definition, and the conditional-forwarder needed when on-prem
domain controllers are the VNet DNS. No real tenant, subscription, registry, SQL or
customer values are baked into the scripts — every environment value is a parameter.

### 11.5 Install & implementation guide (community + internal)

PIM4EntraPS deploys in one of **two modes**. They share one engine (REST-only,
no PowerShell modules), one SQL data model, and one identity model (an **engine
SPN authenticating with a certificate** — never a client secret, never
device-code). The mode only changes *where it runs* and *how it is wired up*.

| | Community mode | Internal mode |
|---|---|---|
| Audience | Running it for your own tenant; smallest footprint | A 24/7 hosted platform (single-tenant or MSP) |
| Code source | Public **community edition**, updated via `git pull` | The setup-script family (`Setup-PimContainers`/`Setup-PimVM`/`Setup-PimMsp`) |
| Host | A management VM (or your own container) you already run | Azure Container Apps, a Windows VM, or per-customer containers |
| Identity | Engine SPN + cert (`Cert:\…\My`); MI when run in an Azure container/VM | Worker **managed identity** (passwordless) + engine SPN + cert |
| Store | Azure SQL (SQLEXPRESS for dev only) | Azure SQL, MI-only contained DB users |
| Manager auth | Local (loopback) / dev switch-admin | Easy Auth (Entra) behind private ingress |

> **Real environment values never live in the published docs.** This guide uses
> **placeholders** (`<tenant-id>`, `<sub-id>`, `<rg>`, `<acr>`, `<server>`,
> `<kv>`, …) throughout. The actual tenant / subscription / resource-group / Key
> Vault / SQL server / engine-SPN values for a given deployment live only in the
> repo's `internal/` folder (gitignored where customer-specific, and stripped from
> every public publish) or in Key Vault — never in README / DESIGN / FEATURES.

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
   (`Directory.Read.All`, `User.ReadWrite.All`, `Group.ReadWrite.All`,
   `RoleManagement.ReadWrite.Directory`, `PrivilegedAccess.ReadWrite.AzureADGroup`,
   `RoleManagementPolicy.ReadWrite.Directory` + `…AzureADGroup`,
   `AdministrativeUnit.ReadWrite.All`, `Mail.Send`, `AccessReview.Read.All`,
   `UserAuthenticationMethod.ReadWrite.All`), assigns **User Access
   Administrator** at the root management group for Azure RBAC, and writes the
   resolved tenant id / client id / cert thumbprint into the launcher config.
   Add `-IncludeExchange` if the engine must set mailbox forwarding on new admin
   accounts. *(A deprecated shim at `setup/Install-PimEngineAppRegistration.ps1`
   forwards to this script for backward compatibility — use the `tools/setup/`
   one for new work.)*
3. **A SQL store for the model.** **Azure SQL** (Entra/managed-identity auth
   only — SQL logins disabled) is the single authoritative store in *every*
   mode and for break-glass. A local **SQLEXPRESS** instance (Integrated auth)
   is a **development convenience only** — the cutover ceremony (§5.3) refuses
   to *finalize* onto a local/Integrated store.

The engine entrypoint (`tools/pim-engine/Invoke-PimEngineCore.ps1
-Scope All|<name> -Mode Full|Delta`) reads its identity + SQL coordinates from
env / launcher globals: `PIM_TenantId`, `PIM_ClientId`, `PIM_CertThumbprint`,
`PIM_SqlServer` (FQDN for Azure SQL, or a local instance), `PIM_SqlDatabase`.
With no client id present and an MI available, auth falls back to managed
identity.

#### 11.5.1 Community mode — full deploy

1. **Get the code.** Clone the community edition; later updates are `git pull`:

   ```powershell
   git clone https://github.com/KnudsenMorten/PIM4EntraPS.git
   cd PIM4EntraPS
   ```

2. **Create the engine SPN + cert** (§11.5.0 step 2).

3. **Configure via the gitignored `*.custom.*` files.** Everything `*.custom.*`
   stays on the box and never enters git (the `.locked`/`.custom`/`.custom.sample`
   pattern, §4):

   ```powershell
   foreach ($sample in Get-ChildItem .\config\*.custom.sample.*) {
       $target = $sample.FullName -replace '\.custom\.sample\.', '.custom.'
       if (-not (Test-Path $target)) { Copy-Item $sample.FullName $target }
   }
   ```

   Set the engine identity (tenant id / client id / cert thumbprint) and the SQL
   coordinates (`PIM_SqlServer` FQDN + `PIM_SqlDatabase`; or `.\SQLEXPRESS` for a
   dev inner loop) in the launcher's `LauncherConfig.custom.ps1`. The shipped
   `config\` templates carry worked example rows (incl. a catalog of common Entra
   built-in roles) so you start from a working model, not an empty schema.

4. **Run the engine** — REST + SQL, scope + mode. **Always dry-run first.**
   `Full` reconciles create/update only; removal needs an explicit `-Prune`, and
   an empty desired set is never pruned (the destructive-safety guards of §5.2,
   plus the fail-hard preflight that refuses to run against a wrong/empty store
   or a bad credential):

   ```powershell
   .\tools\pim-engine\Invoke-PimEngineCore.ps1 -Scope All -Mode Full -WhatIf
   .\tools\pim-engine\Invoke-PimEngineCore.ps1 -Scope All -Mode Full
   .\tools\pim-engine\Invoke-PimEngineCore.ps1 -Scope EntraRoles -Mode Delta
   ```

5. **Run the local Manager** — the browser editor against the same database:

   ```powershell
   .\tools\pim-manager\Open-PimManager.ps1            # serve + open browser
   .\tools\pim-manager\Open-PimManager.ps1 -NoLaunch  # serve only (headless)
   ```

   Server mode binds `127.0.0.1` only with a per-session bearer token. Commits
   from the Manager enqueue a change-queue delta the engine applies.

Community launchers depend only on public Microsoft modules; the published
mirror ships the `community-*` launcher flavours (the `internal-*` ones are
stripped). The engine code is identical across flavours.

#### 11.5.2 Internal mode — full deploy (setup-script family)

The setup scripts are **idempotent, re-runnable, parameter-driven** (no portal
clicking), share one helper library (`tools/setup/_PimSetupShared.ps1`), print a
version banner, and **refuse any region outside West Europe / Denmark East**.

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
- **`--ingress external` on an internal-only environment** → the Manager gets a
  **private static IP, never a public endpoint** — the one ingress reachable from
  peered/hub/GSA clients. (`--ingress internal` is app-to-app only and would be
  unreachable from VNet clients — a multi-hour lesson baked into the script.)
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

**E. Identity & access (Easy Auth + private-only).** Put the Manager behind
**Easy Auth** (Entra interactive sign-in) — the hosted Manager
(`Open-PimManager.ps1 -Hosted`, or `PIM_HOSTED=1`) trusts the Easy Auth
principal header for identity and still requires a per-session token on `/api`.
Keep `publicNetworkAccess=Disabled`, the private endpoint inbound only, and
inbound access-restricted to the management / PAW / SAW subnets (the
defense-in-depth layers of §11.1). The Easy Auth principal maps to
Reader / Admin / SuperAdmin / Delegated; unknown principals fail closed to
Reader.

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

> **`Invoke-PimUpdate.ps1`** is the single operator-facing wrapper for this flow.
> It is being built on the `feat/pim-update-lifecycle` branch; the **intended
> usage** is documented here so the runbook is ready when it lands. Until then,
> the same flow is available through its building blocks:
> `tools/setup/Invoke-PimSyncAutomateIT.ps1` (internal roll + auto-rollback),
> `tools/setup/Update-PimContainers.ps1` (zero-downtime roll / rollback),
> `tools/setup/Register-PimSyncSchedule.ps1` (VM scheduled task), and the
> `sync-automateit` in-container scheduler job. When `Invoke-PimUpdate.ps1` is
> merged, update this section to fold those calls behind it.

#### 11.6.1 The flow

| Step | What happens |
|---|---|
| **detect** | Read the currently-deployed version and the newest released version; decide with a **numeric semantic-version** compare (so `…218` beats `…99`), pre-release < release, an unparseable tag is **never** treated as newer, and the tag already deployed is never re-rolled. A `-PinnedTag` makes the target explicit (still applied only if newer). Also detects whether a **SQL/schema** and/or **GUI** update is required (below). |
| **build** | Internal: build the new image (`az acr build`) unless rolling to an existing tag. Community: nothing to build server-side beyond pulling the new code. |
| **deploy** | Internal: roll every Container App to the new tag through the **zero-downtime** roller (new revision, traffic shift, min-1 replica; apps pull via their AcrPull MI). Community: the new code is in place after the pull; rebuild the local Manager process. |
| **verify** | Run the **hosted smoke** (`tests/live/Test-PimManagerHostedSmoke.ps1`) as the health check (community: the offline suite + a local Manager start). |
| **notify** | Mail the operators the outcome (rolled to `<tag>`, healthy / rolled-back). |
| **ensure-monitor** | Confirm the always-on health probe + the scheduled `sync-automateit` job/task are in place so the next cycle is covered. |

**`-DetectOnly` vs `-Apply`:** the lifecycle is **dry-run by default** —
`-DetectOnly` reports the decision (what's deployed, what's newest, whether a
schema/GUI change is needed) and changes nothing. **`-Apply`** is the explicit
gate that actually rolls; the same gate is opened on a cadence by the scheduled
maintenance window.

#### 11.6.2 Community path

```powershell
# 1. Pull the latest community edition.
git pull
# 2. Run the update check (dry-run): what changed, is a schema/GUI update needed?
.\tools\setup\Invoke-PimUpdate.ps1 -DetectOnly        # (intended wrapper)
# 3. Apply: schema upgrade (if needed) + rebuild/restart the local Manager.
.\tools\setup\Invoke-PimUpdate.ps1 -Apply
```

- A **SQL/schema** upgrade is applied as the **one-time idempotent
  CREATE/ALTER** (`Initialize-PimSqlStore`, the same `upgrade` stage as the
  cutover ceremony, §5.3) — safe to re-run, additive (adds missing fields,
  retires obsolete ones) and never touches your `*.custom.*` data.
- A **GUI** update is just the new Manager code from the pull — restart
  `Open-PimManager.ps1` to pick it up.

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
   existing tag).
3. **roll Container App** — capture the manager's current revision as the
   rollback target, then roll every app via `Update-PimContainers.ps1 -SkipBuild`
   (zero-downtime; AcrPull MI, no registry creds at roll time).
4. **schema upgrade** — apply the idempotent CREATE/ALTER if the release needs
   it; additive and re-runnable.
5. **smoke** — run `tests/live/Test-PimManagerHostedSmoke.ps1`. Healthy = exit 0,
   zero failures.
6. **rollback-on-fail** — on a real smoke failure, **auto-roll-back** to the
   captured pre-update revision (`Update-PimContainers.ps1 -Rollback` — an instant
   revision reactivate) and fail loudly.
7. **mail-notify** — mail the operators the result.

**Scheduling.** The in-container scheduler exposes a `sync-automateit` job
(disabled by default, opt-in) so the always-on container drives the cycle on a
cadence; on a VM host the same cadence comes from a scheduled task
(`Register-PimSyncSchedule.ps1`, default 03:00 local), which can drive the
Container Apps roll or run a local pull on a pure-VM (no-ACA) host. Either way
the apply only happens inside the maintenance window or on an explicit `-Apply`.

#### 11.6.4 When is a SQL/schema and/or GUI update required, and how

- **Schema update** — required whenever a release adds or changes a logical
  column / table (new provider scope, new lifecycle column, audit/intake table).
  Applied as a **one-time idempotent schema CREATE/ALTER** (`Initialize-PimSqlStore`)
  — additive, re-runnable, transactional where it imports, and it never writes
  back to or modifies your existing `*.custom.*` source data. (The first move
  *onto* SQL is the separate guided **cutover ceremony**, §5.3; routine version-to-
  version schema bumps are just the `upgrade` step.)
- **GUI update** — required whenever the Manager changes. **Community:** the new
  Manager code arrives with the `git pull`; restart `Open-PimManager.ps1`.
  **Internal:** the Manager is part of the rolled image, so the zero-downtime roll
  *is* the GUI update — no separate step.
- **Neither** — most engine-only patch releases need no schema or GUI change; the
  detect step reports "code only" and the apply just rolls the image (internal) or
  is a no-op beyond the pull (community).

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
- **Gated / scheduled.** By default the orchestrator is **dry-run** (decide + report
  only). It rolls only when the gate is open — `-Apply` on demand, or the scheduled
  maintenance window. The in-container scheduler exposes a `sync-automateit` job
  (disabled by default, opt-in) so the always-on container can drive it on a cadence;
  on a VM host the same cadence comes from a scheduled task
  (`tools/setup/Register-PimSyncSchedule.ps1`), which can either drive the Container
  Apps roll or run a local pull on a pure-VM (no-ACA) host.
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

REST/cert + MI throughout (the orchestrator only shells `az`); PS 5.1-safe; West
Europe / Denmark East (inherited from the deployment); ACA workers via `--yaml`
(through the reused roller / setup script).

### Full update-lifecycle (`Invoke-PimUpdate.ps1`)

`sync-automateit` keeps a deployment on the newest **already-built** image, but it
does not build, it does not touch the SQL schema, and it does not notify or check
that ongoing health monitoring is in place. The **update-lifecycle** is the
superset that runs after PIM code is pulled and turns a fresh pull into a safe,
verified, observed deployment — one coherent flow over **both** pull paths:

- **community `git pull`** — local/VM; store is SQLEXPRESS or Azure SQL; the Manager
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
Azure SQL single store; West Europe / Denmark East.

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

---

## 14. SQL / data model

The configuration model is a set of logical tables (15 with the workload
configuration file). They live as CSVs by default and migrate to SQL under the
v3.0 store. **The SQL data store is part of the solution at no cost.**

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

Every engine-sent mail is a customizable template. There are **three sources**,
resolved in precedence order by `Get-PimNotifyTemplateText` (in `PIM-Notify.ps1`):

```
1. persistent-store override   # GUI-saved; NO file, NO image rebuild  <- wins
2. templates/mail/<type>.mailtemplate.custom.html   # file override (gitignored)
3. templates/mail/<type>.mailtemplate.html          # shipped default (locked)
```

**Store override (GUI-driven, no rebuild).** An operator (Admin+) edits a
template body in the Manager's Governance tab → **Mail templates** and clicks
**Save**. The body is persisted via `Set-PimManagerSetting 'MailTemplateOverrides'`
(a `{ <type>: <html-body> }` map) — to **SQL `pim.Settings`** when SQL is the
backend (hosted/container), else to the per-instance gitignored
`manager-settings.custom.json`. SQL settings hydrate into
`$global:PIM_NamingConventions` at engine/scheduler boot, so the engine reads the
override the same way it reads any tuned setting — the customization **travels
with the instance** and survives restarts/updates with **no image rebuild and no
file copy**. The Manager also mirrors the new value into the live globals so the
same process picks it up immediately. **Reset** (DELETE) removes the store key,
falling back to the file override (if any) or the shipped default.

The file-based `.custom.html` path still works as a documented fallback (used
only when there is no store override) for environments that prefer baking the
customization into the image.

Endpoints: `GET /api/mail-templates` (list, with `source` = `store`/`file`/`shipped`),
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

**Linking**: column **`PolicyTemplate`** on the definition CSVs. Blank = `default`.
Validator **PIM-POL-001**: referenced template must exist. **Engine re-apply**: the
engine computes a content hash per template; `output/state/policy-state.json` maps
`GroupTag → {templateId, appliedHash, appliedAt}`. When the linked template's hash
differs, the engine re-materializes the unifiedRoleManagementPolicy rules for that
group. Unchanged = NoChange, idempotent. `extends` is single-level only.

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
`New-PimGroup*RuleBody` / `ConvertTo-Pim*RuleBodies` set. **RBAC prerequisite**: the
engine SPN needs `RoleManagementPolicy.ReadWrite.AzureADGroup` (+ `…Directory`) — without
the AzureADGroup variant `Get-PimGroupMemberPolicyId` 403s and the policy read/PATCH
surfaces as "no member policy". **Live tenant run is the delivery gate** (offline +
fake-tenant idempotency proven; a real deploy + read-back confirmation is pending).

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
5. **Support / diagnostics (REQUIREMENTS §28 [M9])** — three more pure cores in the same
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

### 18.1a Delegation Map — the node/edge model and the PERMISSIONS & TARGETS column

The Delegation Map is a four-column flow board: **People** (admins) → **Roles &
Org Groups** → **Capability Bundles** (permission groups) → **Permissions &
Targets**. `Build-PimGraphData` (`tools/pim-manager/Open-PimManager.ps1`)
recomputes the node/edge model on every page render from the live store (SQL via
`Read-PimRows`/`Get-PimSqlRows`, or the config files in local/dev mode).

**CSV header normalisation (why a quoted/Excel export no longer renders an empty map).**
In local/dev (CSV) mode `Read-PimRows` parses the header line itself (to recover the
original column order Import-Csv mangles). Excel "CSV (semicolon)" exports wrap every
header cell in double quotes, the first cell can carry a UTF-8 BOM, and manual edits add
whitespace after the delimiter — any of which left a column name that did not match the
data-row property, so every field read back blank and the Map rendered empty. A small
helper, `ConvertTo-PimNormalizedHeaderToken`, now normalises each header cell in this
order — strip a leading BOM → trim whitespace → strip ONE layer of surrounding double
quotes (un-doubling internal `""`) → trim again — and the data-row lookup also falls back
to a BOM/quote-normalised property map. Only the header→column map is normalised; quoted
DATA values (including values that contain the delimiter) are left untouched, so quoted,
BOM-prefixed, Excel-exported and clean CSVs all parse identically.

Columns 1–3 are *definition* nodes (admins, role/org groups, permission groups).
Column 4 nodes are **synthetic targets** — they don't exist as definition rows;
they are derived from the *assignment* rows that bind a group to a permission:

| Target kind | Built from | id shape | Enriched fields (for the GUI) |
|---|---|---|---|
| `entra-role` | `PIM-Assignments-Roles-Groups` | `entra-role:<RoleName>` | `roleName` |
| `au-role` | `PIM-Assignments-Roles-AUs` | `au-role:<AUTag>:<RoleName>` | `roleName`, `auTag` |
| `az-resource` | `PIM-Assignments-Azure-Resources` | `az-res:<AzScope>:<Perm>` | `roleName`, `scopePath` (full), `scopeType`, `scopeShort` |

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
| Break-glass active | `config/emergency-override.custom.json` (active && not expired) |
| Expiring access (14d) | `Get-PimActiveAssignmentsCached` rows with `end` within the window |
| Pending access reviews | `Get-PimAccessReviewOverview` (live) → `Get-PimAccessReviewSeedRows` (seed) |

Each tile section is wrapped in its own `try/catch`, so an unavailable source
degrades to an honest empty/error state for THAT tile only — the page never goes
dead (the "no dead views" invariant). The two **live/heavy** tiles (active
assignments, access reviews) only run under `?include=heavy`; `renderHome()` paints
the fast tiles first, then lazy-loads `GET /api/home?include=heavy` to fill the
expiring-access + access-reviews tiles. Every tile is a `.home-tile-link` that
`switchTab`s to the tab owning its detail; a red badge on the Home tab sums the
attention items.

**"What needs my attention" call-out (REQUIREMENTS §26a).** Above the tiles,
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

**Tier / plane legend (REQUIREMENTS §26d).** A collapsible legend (`homeLegendHtml()`,
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
emergency override (`POST /api/emergency`) raises `break-glass`. The alerting card
lives in the Settings tab (`renderAlertingCard`, Admin+ editable, independent of the
SuperAdmin gate on the rest of Settings) and is deep-linked from Home.

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

**Delegation Map search-result list + jump, and the risk overlay (§28 [M8]).** The
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

### 18.1d Consolidated CISO-friendly navigation (REQUIREMENTS §26d — names PROPOSED)

The Manager grew to ~20 flat top-level tabs (`#tabs .tab[data-tab]`). §26d folds
them into a small set of named, collapsible menu **groups** a security leader (or a
first-time admin) can scan in seconds. This is a **pure information-architecture
overlay — additive and reversible**: it does NOT touch any panel, endpoint or the
`switchTab(name)` router, and removes no view.

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

> **Group names — confirmed by operator 2026-06-16.** They live only in `NAV_GROUPS`
> + the specs, so they rename in one place. **Overview** (Home) · **Provisioning &
> Access** (Create, Delegation Map, Role Lookup, Authoring, Onboarding, Advanced
> View) · **Change Control** (Validate, Review & Save, Cutover) · **Operations**
> (Maintenance, Approvals, Jobs) · **Governance** (Governance, Access Review, Template
> Rollout, Reports) · **Audit & Settings** (Audit, Settings, Support).

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
  - **Authoring inline preview/diff before commit ([M3]).** Every Authoring action computes a row
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
    and reports `preservedCount` — closing the wholesale-replace gap that motivated [M3].
- **Validator**: missing-GroupTag detector, stale Entra-role detector, tier-safety
  lint, plus the PIM-* validator rules across the lifecycle features (§17).
- **Maintenance tab**: Workload Delegation panel (§15.2).
- **Governance tab** (role-gated): audit viewer, mail-template status, emergency
  override, discovered resources, access list, contacts/email-flow (§17.11–17.17).
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
- **Role Lookup** (`renderRolePerms`, any role, read-only) — a three-mode tab:
  - *What a role can do* — calls `GET /api/role-permissions?role=` and renders the
    `byNamespace` grouping. **Typo-tolerant:** when the exact name doesn't resolve, the
    endpoint no longer returns a 503 — it returns `200 { matched:false, candidates:[…] }`
    where the candidates come from `Resolve-PimRoleQuery` over the role catalog
    (`Get-PimRoleCatalogNames` = the tenant-list cache's role display names ∪ the live
    delegation model's target role-names, so suggestions work even with no live Graph
    read). The GUI renders these as clickable "did you mean…" chips; a genuine empty
    result is an empty candidate list, never a 5xx.
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
- **Cutover** (`renderCutover`) — reads `GET /api/cutover` and draws the six gated
  stages as a progress list (done / next / pending) with the store kind + production
  flag; the run button (Admin+) POSTs the next stage with a confirmation, an optional
  WhatIf for `import`/`finalize`, and a danger-confirm on `finalize` (which the server
  refuses on a non-production store).

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
| `PIM-ORPHAN-AZ-001` | warning | an `AzScope` is not present in (and is not a parent/child of) any scope in the `azure-scopes` tenant cache | requires the `azure-scopes` cache; absent → skip |
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
`pim.Settings`) remains the last piece (REQUIREMENTS §11).

### 18.8 Optional Log Analytics audit sink

`Write-PimAuditEvent` always writes the local append-only `output/audit/pim-audit-
<yyyyMM>.jsonl` file first (source of truth). When `$global:PIM_AuditLogAnalytics`
is set (off by default), it additionally pushes each event — shaped by
`ConvertTo-PimLaAuditRecord` — to Log Analytics via either a host-supplied
`Send-PimLaAuditRecord` hook or the user's `AzLogDcrIngestPS` module directly. The
push is best-effort: a failure is warned and never blocks the engine or the file
audit.

### 18.9 Settings admin area (config moved out of the files into the store)

A **SuperAdmin-only "Settings" tab** lets an operator view/edit the configuration
that previously lived only in `config/*.ps1` / `config/*.json` — now managed
**through the same store the engine uses** (no file editing, persisted + auditable).
Four sections:

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

- **SQL active** → `pim.Settings` (the existing protected key/value table; the
  same one the boot seed + `Get-PimAllSqlSettings` already use). A hacker reading
  the shipped JSON learns nothing authoritative — the store is the source of truth.
- **No SQL (local/dev)** → a single gitignored `config/manager-settings.custom.json`
  beside the other `*.custom.*` files (the standard `.custom.*` ignore keeps it out
  of the repo). It is **not** one of the `.locked.ps1` files — those stay the
  shipped read-only defaults.

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
the rest of Settings (`pim.Settings` key `FeatureFlags` when SQL is active, else the
gitignored `config/manager-settings.custom.json`), so the navigation render and any
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
trail (`output/audit/pim-audit-<yyyyMM>.jsonl`, §18.8 — the file is the source of
truth, written by both the engine `Write-PimAuditEvent` and the Manager
`Write-PimManagerAuditEvent`). It promotes what used to be a fixed "latest N events"
preview in the Governance tab into a full, filterable, paged view; the Governance tab
now shows only a 5-row teaser with a link to the Audit tab.

**Read path.** `GET /api/audit` reads the last **three** monthly files (≈ a rolling
quarter), parses one JSON object per line, and returns newest-first. It is strictly
read-only — it never writes the trail. Query parameters:

| Param | Meaning |
|---|---|
| `category` | one of `logins`/`delegations`/`accounts`/`approvals`/`engine`/`emergency`/`other` (or `all`) |
| `q` | free-text substring matched against `actor`/`action`/`target`/`result` (case-insensitive) |
| `page`, `pageSize` | 1-based paging; `pageSize` clamped to 1..500 (default 50) |
| `limit` | back-compat alias for `pageSize` (the old Governance call used `?limit=N`) |

The response carries `events` (the page), `total` (events in the window),
`matchCount` (after filter/search), `page`/`pageCount`, and `counts` (per-category
totals over the unfiltered window, for the chip badges).

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

**Every capability is available to you — there is nothing to buy, unlock, or
activate.** The full solution (the declarative engine, all configuration, the PIM
Manager with its grid/wizards/map/validator, admin lifecycle, policy templates,
owners-as-approvers, audit, the SQL data store, MSP multi-tenant fan-out, workload
connectors, external intake, access reviews, self-service delegation and email
routing) ships ready to use. The product never phones home, shows no upgrade
prompts, and never blocks or degrades a feature based on entitlement.

The solution is fully offline and self-contained: no activation server, no public
endpoint, and no internet connection is required for any feature to work.

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

**Extension identity is a public contract.** The extension id
`eheocihmlppcophaeakmdenhgcookkab` is deterministic from the public `key` in
`manifest.json` (Chromium: first 16 bytes of `SHA-256(DER pubkey)`, each nibble
mapped `0–15 → a–p`). The id appears in the app-registration redirect URI, the
managed force-install policy and the published CRX, so it must never drift. Only
the **master signing key on mgmt1** reproduces that id; a repack is valid from
there alone, never from another machine.

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
