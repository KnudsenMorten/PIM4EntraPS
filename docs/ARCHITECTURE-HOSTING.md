# PIM Manager — hosting architecture (single-tenant & MSP)

Cheap (B1 App Service ~$13/mo + Basic SQL ~$5/mo), **never publicly exposed**
(private endpoint inbound, `publicNetworkAccess=Disabled`), management access from
trusted subnets only, and an MSP variant that manages many tenants from one app.

---

## 1) Single-tenant

```
   INTERNET ─────────────► ✖  no public endpoint  (publicNetworkAccess = Disabled)

 ┌──────────────────────── Entra ID  (customer tenant) ───────────────────────────┐
 │  • Easy Auth (interactive sign-in)   • App reg / SPN (app-only, cert in KV)      │
 │  • the PIM roles, groups, AUs this manager governs                               │
 └────────────────▲───────────────────────────────────────────▲────────────────────┘
        user sign-in │ (Easy Auth)              Graph/ARM REST  │ (app-only, PIM-Rest, no modules)
                     │                                          │
 ┌───────────────────┴──── VNet  vnet-platform 10.100.0.0/16 ───┴────────────────────┐
 │                                                                                     │
 │   ADMIN ACCESS BY LEVEL (private, from trusted subnets only)                        │
 │   ┌───────────────────────────────────────────────┐                                │
 │   │ PAW-tier0  10.100.8.0/24   L0/T0  ─ SuperAdmin │─┐                              │
 │   │ SAW-tier1  10.100.9.0/24   L1     ─ Admin      │ │  resolve private DNS         │
 │   │ mgmt       10.100.2.0/24   L2     ─ Reader/    │ ├──► pe-pim-manager ──► App     │
 │   │ (helpdesk)                          portal-adm │ │   (inbound PE)        Service │
 │   └───────────────────────────────────────────────┘ │                       B1      │
 │     remote admin ─ VPN / Bastion into the VNet ──────┘                       (Linux  │
 │                                                                              container)│
 │                                                          App identity:               │
 │                                                          • system MI (passwordless)   │
 │                                                          • Easy Auth principal → RBAC  │
 │                                                            SuperAdmin / Admin / Reader │
 │                                                            + portal-admins scoped by   │
 │                                                            tier / level / service /    │
 │                                                            scope (delegated managers)  │
 │                                                                 │ VNet integration     │
 │                                                                 ▼ (outbound, route-all)│
 │                                   pe-pim-sql ──────► Azure SQL Basic  (PimPlatform)    │
 │                                                       • AAD-only, public disabled      │
 │                                                       • MI = contained DB user         │
 │                                                       • pim.Rows / pim.Settings /      │
 │                                                         pim.ChangeQueue                │
 │                                   pe-pim-baseline ─► Storage (run staging)             │
 │                                                                                        │
 │   Private DNS: azurewebsites.net · database.windows.net · blob.core.windows.net        │
 └────────────────────────────────────────────────────────────────────────────────────┘
        ACR (container image, MI pull)        Key Vault (app-only cert/secret, MI-read)
```

**Access levels (defense in depth, all private):**
1. **Network** — only the mgmt / PAW-tier0 / SAW-tier1 subnets (or VPN/Bastion) can
   reach the app's private endpoint; the internet cannot (no public endpoint).
2. **Identity** — Easy Auth (Entra) forces sign-in; unauthenticated → redirect to login.
3. **Authorization** — the manager maps the signed-in principal to SuperAdmin / Admin /
   Reader, and on top, **portal-admins** are delegated managers scoped by tier, level,
   service and scope (e.g. helpdesk L2 sees only its AU-scoped groups). Fail-closed:
   unknown principal → Reader.
4. **Data** — the app reaches SQL only over the private endpoint via its managed
   identity (no password); SQL itself has no public access.

---

## 2) MSP — central template DB + per-customer LOCAL DB (pull, not push)

```
  MSP operators (curate templates)        Customer admins (manage their own tenant)
            │ (private)                              │ (private)
            ▼                                        ▼
 ┌────────── MSP tenant ───────────────┐   ┌────────── Customer tenant = LOCAL ──────────┐
 │  MSP Manager app (B1, private)      │   │  Local PIM Manager (B1, private, §1 design) │
 │  ┌────────────────────────────────┐ │   │  ┌────────────────────────────────────────┐ │
 │  │ MSP SQL DB  (Basic)  ──── #1 ── │ │   │  │ LOCAL SQL DB  (Basic)  ──── #2 ──        │ │
 │  │  • master TEMPLATES / desired  │ │   │  │  • THIS customer's config + run STATE   │ │
 │  │    baseline                    │ │   │  │  • pim.Rows / pim.Settings / ChangeQueue│ │
 │  │  • rings (who gets which ver)  │ │   │  │  Local engine applies to THIS tenant    │ │
 │  │  • fleet / version metadata    │ │   │  │  (Graph/ARM REST, no modules)           │ │
 │  └───────────────▲────────────────┘ │   │  └───────────────┬────────────────────────┘ │
 └──────────────────│──────────────────┘   └──────────────────│──────────────────────────┘
                    │                                          │
                    └──────────────  PULL  (pull-not-push) ────┘
       desired baseline / templates flow DOWN  MSP ─► local, per the customer's RING.
       Customer config, state, secrets + run history NEVER leave the customer tenant.

   Per-customer flow (all LOCAL to the customer):
      1. PULL  the entitled template/desired baseline from the MSP DB (by ring)
      2. DIFF  vs the local desired+state in the LOCAL DB
      3. QUEUE deltas (pim.ChangeQueue, dry-run gated)
      4. APPLY to the customer tenant (Graph/ARM REST)  ·  5. STAMP CollectionTime in LOCAL DB
```

**MSP design notes:**
- **Two SQL DBs (both Basic, ~$5/mo each)** — DB **#1 = MSP DB** holds the master
  templates / desired baseline + rings + fleet/version metadata ("what should be");
  DB **#2 = the customer's LOCAL DB** holds that tenant's actual config + run state.
  There is **no single shared multi-tenant DB**.
- **Pull, not push** (the AutomateIT invariant) — each customer's local deployment
  **pulls** the template/desired baseline it's entitled to **from the MSP DB**, by ring.
  The MSP never pushes into customer environments. Same model as the sync-automateit
  download path.
- **Customer data stays local** — only templates/desired baseline flow DOWN (MSP→local).
  The customer's PIM config, run state, secrets and history **never leave** the customer
  tenant.
- **Rings drive rollout** — the MSP DB's ring assignment decides which template version a
  customer pulls (ties to the TenantManager §7 ring model).
- **Per-customer credentials stay in the customer's LOCAL Key Vault** — the local engine
  is app-only REST against its own tenant; the MSP holds no customer secrets.
- **Each customer deployment IS the single-tenant design from §1** — MSP only adds the
  central template DB they pull from, and an MSP curation app over DB #1.

---

## 3) Execution model — scheduled vs on-demand jobs

> **Build status: BUILT.** `engine/_shared/PIM-Scheduler.ps1` (pure due-calc +
> handler registry + tick + loop + on-demand triggers + change watermark) and the
> entrypoint `tools/pim-scheduler/Start-PimScheduler.ps1` (runs on a VM *or* in a
> container, REST-only). Tests: `tests/Test-PimScheduler.ps1` 27/27. The job *logic*
> it drives already existed (`PIM-Lifecycle`, `PIM-ChangeQueue`, `PIM-Approvals`).
>
> Key semantics:
> - **Phase-split delta** — one job per engine `-Scope` (admins, groups-assign,
>   groups-deploy, policies, pim-entra, pim-azure, pim-au, workloads), each with its own
>   cadence, so a change commits fast without a whole-tenant pass.
> - **Discovery = 3 jobs** — `discovery` scoped to **Entra**, **Azure**, **PowerBI**.
> - **Commit-only trigger** — `Request-PimCommit` (and the SQL change **watermark**)
>   enqueue an immediate recompute+reconcile. **Queuing a change triggers nothing.**
> - **VM + container** — same code; `-IntervalSeconds`/`$env:PIM_SCHED_INTERVAL`,
>   `-Once` for an external cron, single-runner SQL lease.

**Method: an in-container scheduler.** The App Service container is already always-on
(B1, Always On) and is the *only* component that has all three things a job needs — the
full engine code, VNet integration to reach the private SQL/Graph, and a managed
identity. So recurring jobs run as a lightweight timer loop **inside that same
container** (schedules + last-run/next-run persisted in SQL `pim.Settings`; idempotent;
single B1 worker = no double-run, a SQL lease guards if ever scaled). On-demand actions
come through the **manager API** (admin acts in the GUI → writes to the change queue).

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

**Why not the alternatives (they each break a constraint):**
- **Azure Functions** — to reach the *private* SQL it needs VNet integration, which on
  Functions means the **Premium (EP) plan = expensive**, plus cold starts and another
  component with its own deps. Fails "cheap" + "no fragile deps".
- **Webhooks** — inbound, event-driven; they are a *trigger*, not a scheduler. (We can
  optionally expose one private webhook on the manager so an external system requests an
  on-demand apply — but it is not the core mechanism.)
- **Logic Apps** — Consumption can't reach private endpoints; Standard (VNet) is
  expensive. Fails "cheap" + "private-only".
- **App Service WebJobs** — Windows-only; we run a **Linux** container.

**Optional external scheduler (kept as a fallback, not the default):** the same engine
entrypoints can be invoked by a **cron/scheduled task on the management VM** or an
**Azure Automation runbook** for shops that prefer scheduling outside the app — but the
default cheap/private design keeps everything in the always-on container.

---

## Design tenet: no fragile module dependencies — pure REST

Both designs deliberately avoid PowerShell modules that break / must be constantly
updated (Microsoft.Graph, Az). All Entra/Azure/Power BI access goes through
`engine/_shared/PIM-Rest.ps1` (token via Managed Identity / SPN secret / SPN cert /
az; data via `Invoke-PimGraph|Arm|PowerBI`), so the engine and the hosted container
run identically on PS 5.1, PS 7, a VM, or Linux with **nothing to `Install-Module`**
and no version drift. The only non-REST dependency is the SQL driver — and that is a
**stable .NET assembly** (`Microsoft.Data.SqlClient`, used on Linux/PS7;
`System.Data.SqlClient` in-box on Windows PS 5.1), not an auto-updating gallery module.
There is no practical REST data-plane for Azure SQL/TDS, so a driver is unavoidable —
but it is pinned and stable, consistent with the "no fragile dependencies" principle.
