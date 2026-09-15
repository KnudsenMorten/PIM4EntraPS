# PIM4EntraPS Manager

The PIM4EntraPS v2 Manager: a browser GUI over the **SQL store** (`pim.Rows`, `pim.Settings`,
`pim.ChangeQueue`, `pim.AuditEvents`). It runs 24/7 behind Easy Auth (`-Hosted`) or locally on
loopback, and it is **SQL-only**: it has no file store, no CSV data, no settings or access files,
and it **refuses to start** without a reachable SQL database.

```
SOLUTIONS/PIM4EntraPS/tools/pim-manager/
├── Open-PimManager.ps1            ← entry point: HTTP server + REST API
├── pim-manager.html               ← single-file SPA
├── _validator.ps1                 ← pre-flight validation rules (PIM-FK-*, PIM-RA-*, PIM-WL-*, ...)
├── _tenantSync.ps1                ← tenant-list cache (entra roles, AUs, PIM groups, azure scopes)
├── cache/                         ← tenant-list cache (not yet migrated to SQL)
└── README.md                      ← this file
```

## What it edits

The desired state lives in `pim.Rows`, one row per record, grouped by entity:

| Group | Entities |
|---|---|
| Definitions | `Account-Definitions-Admins`, `PIM-Definitions-{Roles,Tasks,Services,Processes,Resources,Departments,Organization,AU}` |
| Assignments | `PIM-Assignments-{Admins,Groups,Roles-Groups,Roles-AUs,Azure-Resources,Workloads}` |

Settings (naming conventions, filters, departments, approvers, alerting, feature flags, Manager
access, portal admins, ...) live in `pim.Settings`. A one-time import from a v1 (file-based)
installation is `setup/Migrate-PimToSql.ps1`, run by an operator -- the Manager itself never reads
files.

## Quick start

```powershell
$env:PIM_SqlServer   = '<server>.database.windows.net'   # or a named on-prem/hybrid instance
$env:PIM_SqlDatabase = '<database>'
# (or $env:PIM_SqlConnectionString, or the Key Vault pointer $global:PIM_SqlConnStringVault + ...Secret)
cd C:\path\to\AutomateIT\SOLUTIONS\PIM4EntraPS\tools\pim-manager
.\Open-PimManager.ps1
```

Starts a loopback HTTP server on a random free port and opens your default browser. Closing the
browser tab self-terminates the server after the heartbeat timeout. Without a store it exits with
`[store] PIM Manager refused to start: ...` naming the settings above.

## Access

Roles (Reader / Delegated / Admin / SuperAdmin) come from SQL `pim.Settings['ManagerAccess']`, then
the env vars `PIM_SuperAdmins` / `PIM_Admins` / `PIM_DelegatedAdmins` / `PIM_HostedDefaultRole`;
anyone else is a **Reader** (fail closed, local and hosted alike). On a fresh store grant the first
SuperAdmin with `tools/setup/Set-PimManagerAccess.ps1` or `PIM_SuperAdmins`; the GUI shows a banner
until access is configured. SuperAdmins edit the map under Governance → "Manage delegation / role
mapping" (written to the same SQL setting). Delegated portal admins: `pim.Settings['PortalAdmins']`
(`tools/setup/Set-PimPortalAdmins.ps1`).

## Switches

| Switch | Purpose |
|---|---|
| *(none)* / `-Server` | Read + edit mode on the SQL store. |
| `-Hosted` | 24/7 hosted mode (Easy Auth principal, all interfaces, never self-exits). Also `PIM_HOSTED=1`. |
| `-NoLaunch` | Don't open the browser; print URL + session token to stdout. |
| `-Port <n>` | Force a port (default: random free). |
| `-Instance sql:<db>` | Bind a specific SQL database at startup (see Instances). |
| `-RefreshTenantLists` | CLI-only cache refresh via the engine SPN, then exit. |
| `-ConnectPlatform` | Bootstrap the AutomateITPS platform connection in the server process (mgmt box). |

## Instances

An instance is a **SQL database** on the configured server, named `sql:<db>`: the configured
database plus any extra names in `$env:PIM_SqlDatabases`. With two or more, the header dropdown
switches the active database (settings reload; per-instance caches clear). The former folder
instances (`instances.custom.json`, `-ConfigRoot`) and the static HTML export (`-StaticHtml`) were
removed with the file store (2026-09-12).

## Where edits land

Every change is staged, reviewed and committed through **Pending changes** (Review & Save):
`PUT /api/data/<entity>` runs the maker/checker, portal-scope and empty-set / large-delta guards,
takes a backup snapshot (`pim` backup store), applies the full set transactionally in SQL, and rolls
back on failure. Directory actions (revoke, TAP re-issue, session revoke) are queued on
`pim.ChangeQueue` and applied by the engine after an Admin commits them; stale pending or failed
entries can be **discarded** with a reason (kept for history, never applied).

## Security model (server mode)

- **Localhost-only bind** locally; hosted binds all interfaces behind Easy Auth + private inbound.
- **Per-session bearer token** — fresh GUID per server start, required on every `/api/*` call.
- **Heartbeat lifecycle** locally — silence self-terminates the server.
- **Fail-closed RBAC** — see Access.

## Tests

`tests/Test-PimManagerSql.ps1`, `tests/Test-PimManagerEndpoints.ps1` and the other Manager suites
boot the Manager on a throwaway SQL Express database through `tests/_shared/PimSqlTestHarness.ps1`
and never write the repo `config/` folder. See `docs/TESTS.md`.
