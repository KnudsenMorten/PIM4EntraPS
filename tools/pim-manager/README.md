# PIM4EntraPS Manager

A local, zero-install editor for the **15-CSV PIM4EntraPS model**. Runs on
the customer's VM (nothing beyond `git pull`), binds to localhost only,
and writes exclusively to `<name>.custom.csv` overrides. Supports a single
local instance and MSP multi-instance setups (one Manager, many customers'
data sets, per-instance tenant connections).

```
SOLUTIONS/PIM4EntraPS/tools/pim-manager/
├── Open-PimManager.ps1            ← entry point: local HTTP server + REST API
├── pim-manager.html               ← single-file SPA (6 tabs, see below)
├── _validator.ps1                 ← pre-flight validation rules (PIM-FK-*, PIM-RA-*, PIM-WL-*, ...)
├── _tenantSync.ps1                ← tenant-list cache (entra roles, AUs, PIM groups, azure scopes)
├── instances.custom.sample.json   ← MSP instance registry template
├── cache/                         ← tenant-list cache (per instance: cache/<name>/)
└── README.md                      ← this file
```

## What it edits

The Manager covers all 15 configuration CSVs:

| Group | CSVs |
|---|---|
| Definitions | `Account-Definitions-Admins`, `PIM-Definitions-{Roles,Tasks,Services,Processes,Resources,Departments,Organization,AU}` |
| Assignments | `PIM-Assignments-{Admins,Groups,Roles-Groups,Roles-AUs,Azure-Resources,Workloads}` |

`PIM-Assignments-Workloads` (v2.4.142+) binds PIM groups to **workload
RBAC roles** (Defender XDR, Intune, any connector under
`workloads/connectors/*.connector.json`); the CSV engine applies the rows
as its final step (v2.4.143+, opt-in — the step self-skips when the
custom CSV is absent). See `../../docs/WORKLOAD-CONNECTORS.md`.

## Quick start

```powershell
cd C:\path\to\AutomateIT\SOLUTIONS\PIM4EntraPS\tools\pim-manager
.\Open-PimManager.ps1                    # plain editor
.\Open-PimManager.ps1 -ConnectPlatform   # + live tabs (Active Assignments, cache refresh, workload roles)
```

Starts a local HTTP server on a random free port and opens your default
browser. Closing the browser tab self-terminates the server after ~30
seconds (heartbeat).

## Switches

| Switch | Purpose |
|---|---|
| *(none)* / `-Server` | Read + edit mode. Saves to `<name>.custom.csv`. |
| `-NoLaunch` | Don't open the browser; print URL + session token to stdout. |
| `-Port <n>` | Force a port (default: random free). |
| `-Instance <name>` | Start with a named instance from `instances.custom.json`. |
| `-ConfigRoot <path>` | Ad-hoc instance: point at any config folder without registering it. |
| `-RefreshTenantLists` | CLI-only cache refresh via the engine SPN, then exit (for scheduled tasks). |
| `-ConnectPlatform` | Bootstrap the AutomateITPS platform connection (bootstrap cert → Key Vault → Modern SPN, app-only Graph + Az) in the server process. Required by the Active Assignments tab, tenant-cache refresh, and the live workload-role loader. |
| `-StaticHtml` | DEPRECATED (kept for back-compat; the snapshot has no API since the Graph view was removed in v2.4.133). |

## Instances (MSP multi-customer support)

An **instance** is one customer's data set: a config root (the 15 CSVs +
NamingConventions) and a sibling output folder. The solution's own
`config/` is always available as the built-in instance **local**. More
instances come from `tools/pim-manager/instances.custom.json` (gitignored —
copy the `.sample.json`):

```json
{
  "instances": [
    { "name": "customerA", "configRoot": "E:\\MSP\\customerA\\PIM4EntraPS\\config" }
  ]
}
```

Each entry can also carry the tenant **connection** (`tenantId` + `appId`
+ either `certThumbprint` for mgmt-box machine-store certs, or
`keyVaultName`/`secretName` for a central Key Vault with one client secret
per tenant — see the sample). With a connection declared, switching
instances retargets the app-only Graph/Az session too, so **Active
Assignments** and cache refresh hit the selected tenant. The Key Vault
shape is cloud-portable: an Azure App Service port reads the same vault
via Managed Identity.

With 2+ instances, the header shows the **Tenant dropdown**. Switching
swaps config/output roots and reloads (uncommitted changes prompt first).
Everything is per-instance: CSV reads/writes, the mutations log, the
tenant-list cache (`cache/<name>/*.json` — names/ids never bleed across
customers), the validator, and the Delegation Map.

SQL roadmap: when instances move from per-customer CSV folders to
per-customer SQL databases, the registry entry grows a connection-string
field and `Read-PimCsvRows` / `Write-PimCsvCustom` get a SQL-backed
implementation — the server API and the whole SPA sit above that seam.

## The six tabs (operator lifecycle order)

**1 Create** → **2 Delegation Map** → **3 Validate** → **4 Review & Save**
→ **5 Active Assignments** → **Advanced View** (grid) as the deliberate
last resort.

### Delegation Map (landing tab)

The PIM v2 model on one board, four columns left to right: **People**
(admins) → **Roles & Org Groups** (direct assignment: ROLE- / DEPT- /
ORG-) → **Capability Bundles** (permission groups, reached via group
nesting) → **Permissions & Targets** (Entra roles, AU-scoped roles, Azure
RBAC at scope, workload roles).

Click any item and its **complete path lights up in both directions**
(wires draw only for the selection — no spaghetti): click a person to see
everything they can reach; click a target to see every human who reaches
it and through which groups. Every box is a Definitions row and every wire
an Assignments row, with an "Open … in Configuration" jump in the detail
strip. Search dims non-matches. Active assignments draw amber, Eligible
blue. Permission groups with no Entra/Azure binding are marked **⬡ app
RBAC** — workload groups consumed by Power BI / Intune / Defender XDR /
any third-party app that supports Entra groups.

**Workload delegation panel** (v2.4.142+): pick a workload connector →
the role dropdown loads the workload's **live role list** through the
connector's Graph adapter (needs `-ConnectPlatform`) → pick a PIM group →
the panel stages a `PIM-Assignments-Workloads` row. The staged row commits
through Review & Save like any other change.

### Create (wizard templates)

A launcher tab with six wizard cards, designed for operators who only open
the tool every few weeks:

| Card | Purpose | CSV(s) touched |
|---|---|---|
| New admin account | Onboard a new privileged user | `Account-Definitions-Admins` + `PIM-Assignments-Admins` (per picked role group) |
| New permission group (Entra ID) | A capability bundle granting Entra ID role(s) | One of `PIM-Definitions-{Tasks,Services,Processes,Resources,Departments,Organization}` + `PIM-Assignments-Roles-Groups` + `PIM-Assignments-Groups` |
| New permission group (Azure resource) | An Azure RBAC role at a chosen scope | `PIM-Assignments-Azure-Resources` (+ `PIM-Assignments-Groups` for nesting) |
| New role group | A higher-level grouping that nests perm-groups | `PIM-Definitions-Roles` + `PIM-Assignments-Groups` + `PIM-Assignments-Admins` |
| Clone an existing group | Duplicate any role/permission group with a new tag | The source's Definitions CSV + all assignment CSVs that reference the old tag |
| Project lifecycle (time-boxed) | Short-lived role group, default 90-day expiry, `AutoExtend=FALSE` | `PIM-Definitions-Roles` + assignments with the chosen lifetime |

Wizard UX rules: plain-English labels (CSV column shown as help text),
sensible defaults (T1 / L3 / Cloud / ID / Eligible / 365-day lifetime),
inline examples, "Why these fields?" collapsibles, max ~5 fields per step,
live "you'll get" naming preview, a plain-English summary before the
row-level diff, the right CSV picked for you, and Cancel as the safe
default — nothing is written until **Commit all**.

### Validate

Runs the server-side pre-flight validator (`_validator.ps1`) against the
active instance. Errors can block the commit button (toggle on the tab);
many findings carry one-click or Fix-all repairs. Rule families:

| Family | Checks |
|---|---|
| `PIM-FK-*` | Referential integrity: every `GroupTag` referenced by any assignment CSV (incl. `PIM-Assignments-Workloads`) exists in a Definitions CSV (with did-you-mean suggestions); every assignment `Username` exists in `Account-Definitions-Admins`; AU references resolve. |
| `PIM-RA-*` | Role-assignability rules (groups bound to Entra roles must be role-assignable, etc.). |
| `PIM-TIER-*` | Tier-crossing warnings (e.g. a T2 admin reaching a T0 capability). |
| `PIM-NAME-*` | Naming-convention conformance (group tags, admin UPN pattern — both customer-overridable via NamingConventions). |
| `PIM-WL-*` | Workload rows: `PIM-WL-001` Workload must have a connector under `workloads/connectors/` (did-you-mean on typos); `PIM-WL-002` RoleName required; `PIM-WL-003` Action must be Assign / Remove / blank. |
| `PIM-RING-001` | `Ring` on `Account-Definitions-Admins` must be blank/0/1/2 — anything else is treated as 0 (ALL tenants) by the engine, so a typo silently over-grants. Fix-all repairs to Ring=2 (least privilege). |
| `PIM-TAP-001` | `CreateTAP=TRUE` with `TargetPlatform=AD` (TAP is Entra-only). |
| `PIM-DUP-*` / `PIM-ORPHAN-*` | Duplicate keys; defined-but-never-assigned / assigned-but-unreachable items. |
| `PIM-IO-*` / cache freshness | Missing/unreadable CSVs; stale tenant-list cache (>24 h) feeding the live-name checks. |

### Review & Save

Lists every file with pending changes: add / remove / modify counts and a
collapsible row-level diff per file.

- **Commit all** — PUTs each modified file to `/api/csv/<base>`; stops at
  the first failing file (no half-commits); blocked while the validator
  reports errors (if enabled).
- **Cancel all pending** — reverts in-memory state, no disk writes.
- **Refresh from server** — re-reads from disk (use after editing a CSV in
  Excel while the Manager was open).

### Active Assignments

Live view of currently-ACTIVE PIM assignments in the connected tenant —
three row types: entra-role, azure-rbac, and pim-for-groups (members AND
owners of PIM-onboarded groups) — with bulk revoke (select rows, type a
justification, **Revoke selected**). Requires `-ConnectPlatform`. First
load takes 1–2 minutes on a real tenant (Azure Resource Graph is the slow
leg); results are cached for 60 s.

### Advanced View (grid)

Left rail lists all 15 files (grouped Definitions / Assignments) with a
`mod` badge for pending changes. The main area is a vanilla
`contenteditable` table: edit a cell, Tab out, the change joins the
pending buffer. Per-row: **✕** delete (↺ to undo), **+1** clone, **+ Add
row**, **↻ Reload from disk** (this file only). No autosave — Review &
Save is the single commit point.

## Where edits land

**Always** in `<base>.custom.csv`; the shipped `<base>.locked.csv` is
never touched (customer-override pattern: `../../docs/DESIGN.md § 8`).

Writes are **atomic** (`.tmp` then `Move-Item -Force`), **UTF-8 without
BOM**, **`;`-delimited**, header order preserved (new columns append at
the end). Blank separator rows (`;;;;;` visual grouping in Excel) survive
the round-trip. Every successful write appends one tab-separated line to
`output/pim-manager-mutations.log`:

```
{utcIso}\t{base}\t{adds}\t{removes}\t{modifies}\t{newRowCount}
```

## Security model (server mode)

Single-user dev tool; the model is intentionally minimal:

- **Localhost-only bind** — `http://127.0.0.1:<port>/`; unreachable from
  the network.
- **Per-session bearer token** — fresh GUID per server start, required on
  every `/api/*` call, embedded in the served HTML only. Token-less
  requests get 401; restarting invalidates the old token.
- **Heartbeat lifecycle** — browser pings every 10 s; 30 s of silence
  self-terminates the server. No long-lived background process.

Not in scope: a user with shell access on the same machine can read the
token from process memory — the tool lives only while you're using it.

## Manual test plan

After a `git pull`, exercise these against your real CSVs:

1. **Server boot + auth:** `.\Open-PimManager.ps1`. DevTools → Network →
   every `/api/*` call carries `Authorization: Bearer <guid>`. A token-less
   `Invoke-WebRequest http://127.0.0.1:<port>/api/config` gets **401**.
2. **Grid edit:** Advanced View → `PIM-Definitions-Tasks` → edit a
   `GroupDescription` cell → Tab out → side-rail badge shows `mod`, tab
   badges count 1.
3. **Add + commit:** add a row with `GroupName` + `GroupTag`, Commit all.
   Verify `config\PIM-Definitions-Tasks.custom.csv` contains it as UTF-8
   without BOM and `output\pim-manager-mutations.log` grew one line.
4. **Delete row:** mark ✕, commit, verify the row left the `.custom.csv`
   and the log line shows `removes=1`.
5. **Delegation Map:** click an admin — the full path to every reachable
   target lights up; click an Azure scope — every human that reaches it
   lights up. "Open … in Configuration" jumps to the right grid row.
6. **Workload panel:** with `-ConnectPlatform`, pick `defender-xdr` — the
   role dropdown loads live role names; stage a row; the Review & Save diff
   shows a `PIM-Assignments-Workloads` add.
7. **Validator:** put a typo workload (`defnder-xdr`) and a bogus
   `GroupTag` into `PIM-Assignments-Workloads.custom.csv` → Validate shows
   `PIM-WL-001` (with did-you-mean) and `PIM-FK-001`. Remove the rows.
8. **Heartbeat reap:** `-NoLaunch`, don't open a browser → after ~45 s the
   server prints `heartbeat timeout` and exits.
9. **Reload from disk:** edit the same CSV in Notepad while the grid has
   pending changes → **↻ Reload from disk** discards pending for that file
   only.
10. **Engine compatibility:** after a commit, run the relevant baseline
    engine in `-WhatIfMode` and confirm it picks up your `.custom.csv`.

## Roadmap

- v0.3 (shipped): wizards, graph-mode delete + clone, plain-English review.
- v2.4.133 (shipped): Delegation Map replaced the free-form Graph view.
- v2.4.142–144 (shipped): workload connectors — live role loader panel,
  engine applier wiring, `PIM-WL-*` validator rules.
- Next: tenant overlay (live CSV vs live Entra drift detection) and
  one-click engine run from the GUI. See `../../docs/DESIGN.md § 11`.
