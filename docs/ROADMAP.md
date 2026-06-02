# PIM4EntraPS -- roadmap

Backlog captured from real-customer feature requests. Each item is sized
(**S** = days, **M** = a week, **L** = a couple of weeks, **XL** = a month+),
tagged with dependencies, and grouped into a release theme. Sequencing
recommendation at the bottom.

Sizing is rough -- "how big does this feel before we start" -- and routinely
wrong by 2x in either direction.

---

## ONE big architectural decision first: storage backend

> Several features below collapse or change shape depending on this answer.
> Decide before committing to the v2.2.x plan.

**Today:** 14 CSVs in `config/`, edited by hand or via PIM Manager. Single
operator at a time on a given customer VM. Atomic per-file write via
`.tmp` + `Move-Item -Force`. No locking. No history beyond git.

**Limits we'll hit:**

- **Multi-operator editing** -- two admins in the Manager UI at the same
  time can stomp each other's pending changes on commit.
- **Large customers** -- a tenant with 500 admins / 50 role groups / 5 000
  permission groups produces a 6 MB Account CSV that Excel still opens
  fine but the Manager's grid re-render slows.
- **Audit & compliance** -- "who changed row X on date Y" requires
  reading the git log; no per-cell history.
- **MSP scale** -- 50 customer tenants \* 14 CSVs each = 700 files on one
  MSP-central repo. Still tractable, but not great UX.

**Options:**

| Option | When it pays off | Cost to migrate |
|---|---|---|
| **A: Stay on CSV** | Single-operator orgs, <50 admins, MSPs OK with file-per-tenant | none |
| **B: Azure Blob + JSON** | Want central state but not relational queries; like the "everything is a file" model. | M -- swap I/O layer, keep schemas |
| **C: Azure SQL / Postgres** | Multi-operator concurrency, fine-grained audit, joins ("which admins have any direct path to T0 assets"), large customers | L -- schema design, migration tool, all engines rewired to read from SQL |
| **D: Hybrid** | CSV ships from repo as the baseline; customers opt into SQL via a flag. Both code paths supported. | XL -- everything in C plus parity testing |

**Recommendation: option A for v2.2.x, revisit at v3.0.** Reasons: most
customers are <30 admins; concurrency can be solved in the Manager with
optimistic locking ("commit failed -- someone else changed since you
loaded"); audit is git + the existing `output/pim-manager-mutations.log`;
the v2.2.x feature list doesn't require relational queries. Plan the SQL
migration as a separate, paid engagement when a customer hits the wall.

Items in this roadmap marked **(needs SQL)** are deferred until the
backend decision changes.

---

## Theme 1 -- Manager UX polish (high impact, mostly S/M)

| # | Feature | Size | Notes |
|---|---|---|---|
| 1 | Optional metadata columns on `Account-Definitions-Admins` (Company, Notes, Sponsor, ManagerEmail, StartDate) | S | Additive CSV change; Manager wizard exposes them as collapsible "More fields..." section -- **[SHIPPED v2.2.0]** |
| 2 | Show actual Entra ID permissions behind a role (drill-down from graph node) | M | Hover/click on permission-group node -> side panel lists every concrete permission (rolePermissions[].allowedResourceActions); pulled live from `cache/entra-roles.json` -- **[SHIPPED v2.2.0]** |
| 3 | Clone a role group / permission group / definition (multi-select target CSVs) | S | Extends today's Clone wizard to bulk + cross-CSV |
| 4 | Multi-select assign permissions in bulk: pick 10 Entra roles + 10 Azure scopes -> attach to a role/org/task | M | New wizard "Bulk attach"; generates row sets in `Roles-Groups` / `Roles-AUs` / `Azure-Resources` |
| 5 | Clone Azure subscription RBAC delegations to a different role at same scope (or to N new roles) | S | Extends Clone wizard with "and substitute the role" option |
| 6 | Disable/enable admins via Manager multi-select on the Grid tab | S | Reuses `AccountStatus` column shipped in v2.1.x -- **[SHIPPED v2.2.0]** |
| 7 | Multi-select delete of existing PIM assignments/delegations | S | Manager Grid tab; rows go to `pendingChanges.deletes` -- **[SHIPPED v2.2.0]** |
| 8 | Add new Administrative Units via Manager wizard | S | New wizard variant; writes to `PIM-Definitions-AU` + optional `PIM-Assignments-Roles-AUs` rows |
| 9 | Import admins via CSV upload (FirstName, LastName, Initials) + link to template | M | File-upload to Manager; rows mapped to selected admin template (see #11) |
| 10 | Admin templates (internal, external/consultant, contractor) | M | New `config/admin-templates.custom.ps1` with template definitions; Manager wizard offers them as a dropdown; rules for TAP / lifetime / role-group defaults per template |

## Theme 2 -- TAP + activation flow

| # | Feature | Size | Notes |
|---|---|---|---|
| 11 | Send TAP password via email / Teams / Slack | M | New PIM-Functions helper `Send-PimAdminTap`; pluggable channels via `$global:PIM_NotificationChannels` config -- **[SHIPPED v2.2.0]** |
| 12 | Schedule TAP start time (e.g. "in 2 days at 8am") | S | Extends `New-PimTemporaryAccessPass` to honour the existing `TAPStartDate` CSV column (currently passed-through but engine doesn't compute future times). Add `TAPStartTime` column -- **[SHIPPED v2.2.0]** |
| 13 | Validate minimum auth methods set per admin (MFA Authenticator, passkey, etc.) | M | New validator rule `PIM-AUTH-001` + `PIM-AUTH-002`; uses `userAuthenticationMethod.ReadWrite.All` perm already on engine SPN |

## Theme 3 -- Per-row policy + approval

| # | Feature | Size | Notes |
|---|---|---|---|
| 14 | Per-assignment approval requirement (extra CSV columns: `RequiresApproval`, `Approvers`) | L | Per-row override of the global `policies.custom.ps1`. Approvers as semicolon list; parallel approval (first-to-approve wins). Engine writes corresponding Entra PIM policy rule |
| 15 | Per-assignment notification overrides (`NotifyOnActivation`, `NotificationRecipients`) | S | Similar shape; engine pushes to PIM policy notification rules |

Notification + approval per-ROW (not per-role) is the right design: the
same Entra role assigned for different purposes can have different rules.

## Theme 4 -- Discovery + auto-detect (Azure + M365)

| # | Feature | Size | Notes |
|---|---|---|---|
| 16 | Auto-detect new Azure subscriptions + management groups | M | New engine `PIM-Discovery-AzureScopes`. Runs Search-AzGraph; appends to `PIM-Definitions-Resources.custom.csv` + `PIM-Assignments-Azure-Resources.custom.csv` -- but **does not auto-assign** any admins (only the row scaffolding). Operator decides who. |
| 17 | Auto-detect new Power Platform / Power BI workspaces -> create PIM groups | M | Same pattern as #16 but for Power Platform admin API |
| 18 | Enumerate built-in roles from Intune / Defender XDR / Entra ID; suggest definitions for newly-introduced roles | M | New engine `PIM-Discovery-BuiltInRoles`; diff against `PIM-Definitions-Tasks.custom.csv` |
| 19 | Detect orphaned Azure scopes (sub/RG/resource no longer exists) | S | New validator rule `PIM-ORPHAN-AZ-001` + Manager Fix-all bucket |
| 20 | Detect PIM groups never activated in N days -> suggest removal from Entra + CSVs | M | Reads `signInActivity` + PIM activation audit logs; surfaces in Manager Validate tab |

## Theme 5 -- Webhook / integration

| # | Feature | Size | Notes |
|---|---|---|---|
| 21 | Inbound webhook endpoint (from ServiceNow etc.) -> create new admin / delegation | L | New `engine/PIM-Webhook-Listener` service that binds an Azure Function / Logic App; mints a row + queues it as a pending change for human approval before engine apply |
| 22 | Outbound notifications: assignment created / removed / activated | M | New PIM-Functions helper `Send-PimAuditNotification`; channels: SMTP, Teams, Slack, generic webhook |
| 23 | Daily summary email of PIM changes (new admins, new delegations, removals) | M | Scheduled engine `PIM-Daily-Summary`; reads `output/pim-manager-mutations.log` + audit log diffs |

## Theme 6 -- Reporting + visibility

| # | Feature | Size | Notes |
|---|---|---|---|
| 24 | Tier-impact report: every user with any path to T0/T1 (including indirect via nested groups) | M | New engine + Manager view; reuses the graph reach analysis |
| 25 | Per-role drill-down: see actual permissions delegated | S | Same as #2 but as a report export, not just a graph hover -- **[SHIPPED v2.2.0]** (Manager Graph drill-down; CSV export still pending) |
| 26 | Log every PIM change to Log Analytics + audit log file | M | New PIM-Functions helper `Send-PimAuditToLogAnalytics`; uses your `AzLogDcrIngestPS` module |
| 27 | Replace-mode admin move (remove old assignments, add new) | M | Manager wizard; transactional (all-or-nothing within one Commit) |

## Theme 7 -- Lifecycle + governance

| # | Feature | Size | Notes |
|---|---|---|---|
| 28 | Role owner / sponsor column on `PIM-Definitions-Roles` for audit + renewal workflow | S | Additive CSV column; engine reads but doesn't enforce yet -- **[SHIPPED v2.2.0]** (data-flow only; v2.3.x will wire enforcement) |
| 29 | Notify members when their group/role assignment changes | S | Hooks into #22 |
| 30 | Maintenance job: orphaned scope cleanup (auto-delete assignments + groups for missing Azure scopes) | M | Risky -- gate behind explicit `-ApplyOrphanCleanup` flag + `WhatIfMode` confirmation diff |
| 31 | Setup Entra Access Package + delegate to PIM group | L | Yes it works; uses `EntitlementManagement.ReadWrite.All` Graph perm. New CSV: `PIM-Assignments-AccessPackages.locked.csv` mapping access packages to PIM groups |
| 32 | Setup Entra Access Review per PIM group/role (extra column `AccessReviewSchedule`) | M | Quarterly review with owners as reviewers; uses `AccessReview.ReadWrite.All` |

## Theme 8 -- Multi-operator / concurrency (needs SQL)

| # | Feature | Size | Notes |
|---|---|---|---|
| 33 | Three operators editing in the Manager simultaneously without stomp | **(needs SQL)** L | With CSV: optimistic-lock on commit (server returns 409 if file mtime changed since load; operator must reload + redo). With SQL: per-row locking + change feed |
| 34 | Per-cell history / who-changed-what | **(needs SQL)** L | Today: git log of CSV; works but coarse. SQL would give per-cell |

---

## Sequencing recommendation

**v2.2.0 (next sprint)** -- low-risk wins that compound:
- #1  Optional admin metadata columns (1 day)
- #6  Disable/enable via multi-select (1 day)
- #7  Multi-delete (1 day)
- #11 Send TAP via email (2-3 days)
- #12 Scheduled TAP start time (1 day)
- #25 Per-role drill-down report (1 day)
- #28 Role sponsor column (1 day)

Ship in a single release. ~1.5 weeks. Pure additive, no engine API
changes, no architectural decisions needed.

**v2.2.1 -- Manager-side bulk authoring:**
- #3  Clone any group (extended)
- #4  Multi-select bulk attach
- #5  Clone Azure delegations to different roles
- #8  AU wizard
- #10 Admin templates
- #9  Admin CSV import

~2 weeks.

**v2.2.2 -- Discovery loop:**
- #16 Auto-detect Azure subscriptions
- #17 Auto-detect Power Platform workspaces
- #18 Enumerate Microsoft built-in roles
- #19 Orphaned Azure scope detection

~2 weeks.

**v2.3.0 -- Per-row policy + notifications:**
- #14 Per-assignment approval rules
- #15 Per-assignment notification overrides
- #22 Outbound notifications (channels: SMTP/Teams)
- #23 Daily summary email
- #26 Log to Log Analytics

~3 weeks.

**v2.3.1 -- Governance:**
- #28 Sponsor/owner
- #31 Access Package integration
- #32 Access Review integration
- #27 Replace-mode admin move
- #2  Permission drill-down (deep)
- #24 Tier-impact report

~3 weeks.

**v2.4.0 -- Webhook + auth-method validation:**
- #21 Inbound webhook listener
- #13 Auth method validator
- #29 Notify members on assignment change

~2 weeks.

**v3.0.0 -- Storage backend re-platform (if needed):**
- #33 + #34: SQL move
- Plus migration tool from CSV -> SQL

~4-6 weeks. Skip unless customers hit the multi-operator wall.

---

## Items intentionally NOT on the roadmap

- **AI-assisted naming / role suggestions** -- adds vendor dependency,
  high-noise low-signal in this domain.
- **Mobile app** -- desktop browser via Manager + Activator extension
  covers it; mobile would duplicate logic.
- **Real-time graph collaboration cursors** -- nice but solving a
  problem nobody's reported.
- **Built-in chat / commenting** -- ServiceNow / Slack already do this;
  webhook integration (#21) bridges to them.
