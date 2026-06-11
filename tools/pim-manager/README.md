# PIM4EntraPS Manager

A graph viewer + editor for the 14-CSV PIM4EntraPS model. Runs on
the customer's VM (no install beyond `git pull`), no external network
access required for editing. Supports a single local instance and MSP
multi-instance setups (one Manager, many customers' data sets).

```
SOLUTIONS/PIM4EntraPS/tools/pim-manager/
├── Open-PimManager.ps1            ← entry point (server / static / refresh modes)
├── pim-manager.html               ← single-file SPA (6 tabs: Graph / Grid / New & clone / Save / Validate / Revoke)
├── _validator.ps1                 ← pre-flight validation rules (PIM-FK-*, PIM-RA-*, PIM-TIER-*, ...)
├── _tenantSync.ps1                ← tenant-list cache (entra roles, AUs, PIM groups, azure scopes)
├── instances.custom.sample.json   ← MSP instance registry template
└── README.md                      ← this file
```

## Look and feel (v2.4.53)

The Manager editor was the last PIM4EntraPS surface still on the
GitHub-Primer dark theme while the Activator extension switched to a
light + branded palette back in v1.0.0. v2.4.53 brings the Manager into
alignment: light theme (`#ffffff` body, `#f6f8fa` panels, `#1a1a1a` text,
`#0969da` blue accents, `#57606a` muted), a 2px solid `#0969da` frame
around the app, a branded blue banner with a white uppercase
`PIM MANAGER` title at 18px above the tab bar, and solid-blue tile cards
on the New & clone tab (white text + white icons, blue shadow,
darker-blue hover).

Cytoscape node-kind identifier colours are kept as-is on purpose --
purple role groups, lavender Azure resources, orange Entra roles --
because they're the legend-to-node contract the operator reads the graph
through.

No code logic changed in this release; pure visual restyle. The
Activator extension stays at v1.1.1.

## Quick start

```powershell
cd C:\path\to\AutomateIT\SOLUTIONS\PIM4EntraPS\tools\pim-manager
.\Open-PimManager.ps1
```

This starts a local HTTP server on a random free port, opens your
default browser to it, and gives you a 3-tab editor (Graph / Grid /
Save). When you close the browser tab the server self-terminates after
~30 seconds.

## Modes

| Mode | Switch | Capability |
|---|---|---|
| **Server** (default) | `-Server` (or no switch) | Read + edit. Saves back to `<name>.custom.csv`. |
| **Static** | `-StaticHtml` | Read-only snapshot of the graph baked into a single HTML file. Same as v0.1. |

Other useful switches:

- `-NoLaunch` &mdash; don't open the browser. In server mode prints the URL +
  token to stdout; in static mode prints the rendered file path.
- `-Port <n>` &mdash; force a specific port (server mode). Otherwise a random
  free port is picked.
- `-OutHtml <path>` &mdash; (static mode only) write the snapshot to a chosen
  path instead of a temp file.
- `-Instance <name>` &mdash; start with a named instance from
  `instances.custom.json` active (see *Instances* below).
- `-ConfigRoot <path>` &mdash; ad-hoc instance: point the Manager at any
  config folder directly, without declaring it in the registry.
- `-RefreshTenantLists` &mdash; CLI-only: refresh the tenant-list cache via the
  engine SPN, then exit (no server, no browser). For scheduled tasks.

## Instances (MSP multi-customer support)

An **instance** is one customer's PIM4EntraPS data set: a config root
(the 14 CSVs + NamingConventions files) and a sibling output folder.
The solution's own `config/` is always available as the built-in
instance **local**. More instances come from
`tools/pim-manager/instances.custom.json` (gitignored &mdash; copy the
`.sample.json` next to it):

```json
{
  "instances": [
    { "name": "customerA", "configRoot": "E:\\MSP\\customerA\\PIM4EntraPS\\config" }
  ]
}
```

With two or more instances available, the Manager header shows an
**instance dropdown**. Switching tells the server to swap its config /
output roots and reloads the page; uncommitted changes prompt a confirm
before being discarded. Everything is per-instance:

- CSV reads/writes resolve against the active instance's config root.
- `output/pim-manager-mutations.log` lands in the instance's output folder.
- The tenant-list cache is partitioned per instance
  (`cache/<name>/*.json`) so role names / AU ids / subscription ids never
  bleed across customers (`local` keeps the flat `cache/` for back-compat).
- The pre-flight validator and the graph rebuild from the active instance.

SQL roadmap: when instances move from per-customer CSV folders to
per-customer SQL databases, the registry entry grows a connection-string
field and `Read-PimCsvRows` / `Write-PimCsvCustom` in
`Open-PimManager.ps1` get a SQL-backed implementation &mdash; the rest of
the server and the whole SPA sit above that seam and stay unchanged.

## The four tabs

### Graph

The v0.1 read-only DAG viewer, plus one editor addition: when you
select a node (admin / role group / permission group / AU) or an edge,
the right panel grows a **Delete** button. Clicking it shows a confirm
dialog listing every CSV row that would be removed, then records the
deletes as in-memory pending changes &mdash; nothing is written until you
go to the Save tab.

Drag-to-connect and right-click-to-delete graph editing is deferred to
v0.3.

### Grid

Left rail lists all 14 CSVs (grouped by Definitions / Assignments).
A `(mod)` badge marks any CSV with pending changes.

Main area is a vanilla `<table>` with `contenteditable` cells. Edit a
cell, hit Tab or click out, the change goes into the pending-changes
buffer. Per-row actions:

- **✕** &mdash; mark for deletion (greys the row out; ✕ becomes ↺ to undo)
- **+ Add row** &mdash; prepend a blank row
- **↻ Reload from disk** &mdash; discard pending changes for this CSV only

No autosave. The Save tab is the single commit point.

### New & clone (v0.3)

A launcher tab with six wizard cards, designed for operators who only
open the tool every few weeks:

| Card | Purpose | CSV(s) touched |
|---|---|---|
| New admin account | Onboard a new privileged user | `Account-Definitions-Admins` + `PIM-Assignments-Admins` (per picked role group) |
| New permission group (Entra ID) | A capability bundle granting Entra ID role(s) | One of `PIM-Definitions-{Tasks,Services,Processes,Resources,Departments,Organization}` + `PIM-Assignments-Roles-Groups` + `PIM-Assignments-Groups` |
| New permission group (Azure resource) | An Azure RBAC role at a chosen scope | `PIM-Assignments-Azure-Resources` (+ `PIM-Assignments-Groups` for nesting) |
| New role group | A higher-level grouping that nests perm-groups | `PIM-Definitions-Roles` + `PIM-Assignments-Groups` + `PIM-Assignments-Admins` |
| Clone an existing group | Duplicate any role/permission group with a new tag | The same Definitions CSV as the source + all assignment CSVs that reference the old tag |
| Project lifecycle (time-boxed) | Short-lived role group with default 90-day expiry, `AutoExtend=FALSE` | `PIM-Definitions-Roles` + assignments with the chosen lifetime |

Each wizard follows these UX rules so the operator never has to remember the naming convention or CSV layout:

1. **Plain-English labels** &mdash; the CSV column name is shown as small grey help text below the human-readable label.
2. **Sensible defaults** for every field (T1 / L3 / Cloud / ID / Eligible / 365-day lifetime).
3. **Inline examples** next to every input (`e.g. AppAdmin`, `e.g. AHA`).
4. **"Why these fields?"** collapsible at the top of every step.
5. **Multi-step layout** &mdash; max ~5 fields per screen, back-buttonable.
6. **Live "you'll get"** preview &mdash; the auto-composed `GroupName` / `GroupTag` / `UserPrincipalName` updates as you type.
7. **Plain-English review** &mdash; before the row-level diff, the final step shows a 1-paragraph summary of what will land where.
8. **Right CSV chosen for you** &mdash; the perm-group wizard's "What kind of capability?" dropdown maps the human choice (Task / Service / Process / Resource / Department / Organization) to the right `PIM-Definitions-*.csv` automatically.
9. **Cancel is the safe default** &mdash; closing the modal asks to discard any rows the wizard staged; nothing is written to disk until `Commit all`.
10. **Clone from graph** &mdash; right-clicking a role/permission group on the Graph tab opens the Clone wizard pre-populated with that node as the source.

### Save

Lists every CSV with pending changes. Each card shows add / remove /
modify counts (green / red / yellow) and a collapsible row-level diff.

- **Commit all** &mdash; PUTs each modified CSV to `/api/csv/<base>`. On
  success refreshes the graph. On failure stops at the failing CSV (no
  half-commits).
- **Cancel all pending** &mdash; reverts all in-memory state to the last
  loaded server data. No disk writes.
- **Refresh from server** &mdash; re-reads the graph + cached CSVs from
  disk. Use this if you (or someone else) edited a CSV in Excel while
  the mapper was open.

## Where edits land

**Always** in `<base>.custom.csv`. The shipped `<base>.locked.csv` is
never touched. The customer-override pattern is documented in
[../../docs/DESIGN.md § 8](../../docs/DESIGN.md).

Files are written **atomically** (write to `.tmp`, then `Move-Item -Force`),
**UTF-8 without BOM**, **`;` delimiter**. The original header order is
preserved; any column that exists in your pending state but not in the
on-disk file is appended at the end. Blank separator rows (`;;;;;` lines
used as visual grouping in Excel) **survive the round-trip** &mdash; they
load as empty grid rows and are written back unchanged.

Every successful write appends one tab-separated line to
`output/pim-manager-mutations.log`:

```
{utcIso}\t{base}\t{adds}\t{removes}\t{modifies}\t{newRowCount}
```

Use this for audit + debugging. The file is not gitignored automatically;
add it to `.gitignore` if you don't want to track it.

## Security model (server mode)

The editor is a single-user dev tool. The security model is intentionally
minimal:

- **Localhost-only bind.** The HttpListener binds `http://127.0.0.1:<port>/`.
  Other hosts on the network can never reach it; the OS routes
  `127.0.0.1` only to the same machine.
- **Per-session bearer token.** At every server start a fresh random
  `GUID` is generated and required on every `/api/*` request as
  `Authorization: Bearer <token>`. The token is embedded in a `<meta>`
  tag of the served HTML, so only the browser session that the launcher
  opened can call the API. A second browser tab opened by hand to the
  same URL won't have the token. Restarting the server invalidates the
  previous token.
- **Heartbeat lifecycle.** The browser pings `/api/heartbeat` every 10
  seconds. If 30 seconds pass with no ping (browser tab closed or
  network blip) the server self-terminates. No long-lived background
  process.

What this prevents:

- A malicious site you visit in another tab cannot read or modify your
  CSVs &mdash; CORS aside, it doesn't know the bearer token, and the API
  rejects token-less requests with 401.
- A colleague on your network cannot reach the editor &mdash; the listener
  is bound to the loopback interface only.
- A forgotten browser tab cannot leave an editable port open overnight
  &mdash; the heartbeat timeout reaps the server.

What this does **not** prevent (out of scope for this tool):

- A user with shell access on your own machine can read the token from
  process memory or the served HTML. The tool isn't a multi-tenant
  service; it lives only while you're using it.

## Manual test plan

After a `git pull`, exercise these against your real CSVs:

1. **Static viewer round-trip:** `.\Open-PimManager.ps1 -StaticHtml`.
   The browser should open and show the same graph as v0.1.

2. **Server boot + auth:** `.\Open-PimManager.ps1`. Browser opens at a
   random port. Open DevTools &rarr; Network &rarr; verify every `/api/*`
   call carries `Authorization: Bearer <guid>`. Try
   `Invoke-WebRequest http://127.0.0.1:<port>/api/config` from another
   PowerShell prompt without the token &mdash; should get **401**.

3. **Grid edit:** open the Grid tab, pick `PIM-Definitions-Tasks`, edit
   a `GroupDescription` cell, Tab out. Side rail badge should change to
   `(mod)`. Tab title badges (Grid / Save) show `1`.

4. **Add row:** click `+ Add row`, fill in `GroupName`, `GroupTag`, save.
   In another shell verify
   `Get-Item config\PIM-Definitions-Tasks.custom.csv` exists and the new
   row is in it as UTF-8 without BOM (`Get-Content -Encoding Byte -TotalCount 3`
   should not start `EF BB BF`).

5. **Delete row:** mark a row ✕, go to Save tab, click **Commit all**.
   Verify the row is gone from the `.custom.csv`. Verify
   `output\pim-manager-mutations.log` got a new line with
   `removes=1`.

6. **Graph-mode delete:** in Graph tab, click an edge between an admin
   and a role group. The right panel shows a "Delete this delegation"
   button. Click it, confirm. The Save tab now shows that one assignment
   row is pending removal in `PIM-Assignments-Admins`. Commit, verify
   `.custom.csv` updated.

7. **Node delete with cascade:** click an admin node, hit "Delete this
   node". The confirm dialog should list rows across
   `Account-Definitions-Admins` AND `PIM-Assignments-Admins`. Cancel
   (don't actually delete unless you mean to).

8. **Heartbeat reap:** start the server with `-NoLaunch`. Don't open the
   browser. After ~45 seconds the server should print
   `heartbeat timeout` and exit.

9. **Reload from disk:** open a CSV in the Grid tab. In another window
   edit the same `.custom.csv` in Notepad and save. Click
   **↻ Reload from disk** in the grid &mdash; your in-grid pending changes
   should be discarded for that CSV only.

10. **Engine compatibility:** after a commit, run the relevant baseline
    engine (e.g. `PIM-Baseline-Management-CSV-AdminsOnly`) in
    `-WhatIfMode` and confirm it picks up your `.custom.csv` (look for
    the file's path in the engine log).

## Future work (roadmap)

- v0.3 (shipped): graph-mode delete + clone, six wizards on the **New
  & clone** tab, "Why these fields?" help, live "you'll get" previews,
  plain-English summary on the review step.
- v0.4: tenant overlay (live CSV vs live Entra drift detection).
- v0.5: one-click engine run from the GUI.

See [../../docs/DESIGN.md § 11](../../docs/DESIGN.md) for the full
mapper roadmap.
