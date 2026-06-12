# Admin Lifecycle & Governance — design

Operator-requested expansion (2026-06-12) covering thirteen features across the Manager GUI, the CSV model, the engine, and the policy layer. This document is the agreed architecture; implementation ships in phases (see § Phasing). House rule reminders that shaped the design: CSV stays the storage layer (ROADMAP.md Option A), the Manager stages / the engine applies (trust model from WORKLOAD-CONNECTORS.md), and PS 5.1 compatibility everywhere.

---

## 1. Date expressions — the shared foundation

Several features (scheduled creation, TAP windows, templates, offboarding) need "a date, possibly relative". One resolver serves them all.

### Token grammar

```
<expr> := Now
        | <anchor>[<offset>][@<time>]
        | <ISO date>[@<time>]            # 2026-07-01@08:00
<anchor> := FirstDayNextMonth | FirstWorkdayNextMonth | FirstDayNextWeek | FirstWorkdayNextWeek
<offset> := +<n>d | -<n>d                # calendar days
<time>   := HH:mm                        # tenant-local; omitted = 00:00
```

Examples from the operator's use cases:

| Expression | Meaning |
|---|---|
| `Now` | apply on the next engine run |
| `FirstWorkdayNextMonth@08:00` | TAP becomes valid 08:00 on the first workday of next month |
| `FirstWorkdayNextMonth-3d` | provision the admin three days before the first workday of next month |
| `2026-06-28` | fixed date |

### Implementation

- `Resolve-PimDateExpression -Expression <string> [-ReferenceDate <datetime>]` in `engine/_shared/PIM-Functions.psm1`. Pure function (`-ReferenceDate` for tests). Returns `[datetime]` or throws with the grammar in the message.
- The Manager calls it via a new `GET /api/resolve-date?expr=...` endpoint so the GUI can live-preview ("resolves to Mon 2026-07-01 08:00") while the operator types.
- Validator: **PIM-SCHED-001** — every date-expression column must parse; suggestion shows the grammar.
- Workday = Mon–Fri. Holiday calendars are out of scope for now (documented limitation).

## 2. Scheduled admin creation

New column on `Account-Definitions-Admins`: **`ProvisionDate`** (date expression; blank = `Now`, fully backward compatible).

- Engine (`CreateUpdate-Accounts-From-file-CSV`): rows with `Resolve-PimDateExpression(ProvisionDate) > now` are **skipped with a log line** (`SCHEDULED: <upn> provisions at <resolved>`); the row stays in the CSV and materializes on the first run at/after the resolved time. Idempotency is unchanged — once created, the date no longer matters.
- The existing `StartDate` column keeps its meaning (employment start, informational) — `ProvisionDate` is *when the engine acts*.
- Validator: **PIM-SCHED-002** (warning) — `TAPStartDate` resolves earlier than `ProvisionDate` (TAP would predate the account).

### The mail-dependency scenario (why this exists)

Customer provisions the person's normal account (e.g. `user@<customer>.tld`) a week early. The admin row is staged with `ProvisionDate=2026-06-28`, `ForwardMailsToContact=TRUE`, `MailForwardAddress=user@<customer>.tld`, `CreateTAP=TRUE`, `TAPStartDate=2026-07-01@08:00`, `TAPLifetimeHours=8`. On 28 June the engine creates the admin + forwarding; the TAP mail lands in the already-live normal mailbox; the TAP itself only works 1 July 08:00–16:00.

## 3. Scheduled TAP window

- `TAPStartDate` already exists and feeds `New-PimTemporaryAccessPass -StartDateTime`; it now accepts date expressions.
- New column **`TAPLifetimeHours`** → `lifetimeInMinutes` on the Graph TAP body (Graph allows 10–43200 minutes; validator **PIM-TAP-002** range-checks). Blank = tenant default (60 min).
- **TAP creation is deferred to the engine run nearest the start date**: Graph rejects `startDateTime` far in the future on some tenants and a long-pending TAP is a standing credential. Rule: when `TAPStartDate` resolves more than `$global:PIM_TapCreateLeadHours` (default 48) ahead, the engine logs `TAP DEFERRED` and creates it on a later run inside the lead window. The TAP mail therefore also sends inside the window — close to when the recipient can actually use it.

### GUI: one TAP group

In the Administrator Onboarding wizard, `CreateTAP`, `TAPStartDate` (with live resolve preview), and `TAPLifetimeHours` move into a single **"Temporary Access Pass"** fieldset; **`UsageLocation` moves out** to the identity/locale group (today it renders between the TAP fields). Same regrouping in the Advanced grid's column ordering for `Account-Definitions-Admins`.

## 4. Admin templates

Prestage admin settings as named templates, same file pattern as the existing permission templates:

```
templates/admin/<id>.admintemplate.json        # shipped (locked)
templates/admin/<id>.admintemplate.custom.json # customer-defined (gitignored)
```

```json
{
  "id": "new-employee-next-month",
  "name": "New Employee Next Month",
  "description": "Admin provisions 3 days before the first workday of next month; TAP valid 8h from 08:00 that workday; mail forwarded to the pre-provisioned normal account.",
  "prefill": {
    "TierLevel": "L1", "TargetUsage": "Cloud", "TargetPlatform": "ID", "UserType": "Member",
    "UsageLocation": "DK", "Ring": "2",
    "ForwardMailsToContact": "TRUE",
    "CreateTAP": "TRUE",
    "ProvisionDate": "FirstWorkdayNextMonth-3d",
    "TAPStartDate": "FirstWorkdayNextMonth@08:00",
    "TAPLifetimeHours": "8"
  },
  "assignments": [ { "GroupTag": "<role-group-tag>", "AssignmentType": "Eligible" } ]
}
```

- Two shipped templates: **`consultant`** (time-boxed, `NumOfDaysWhenExpire` prefilled, TAP `Now`) and **`new-employee-next-month`** (above).
- Manager: the onboarding wizard gains a template picker (top of the form); choosing one prefills the fields — everything stays editable before staging. The materialized row gets a **`Template`** column value for traceability/audit; templates are *prestage only* (later template edits do not retro-apply to existing admins — that is what policy templates are for, § 7).
- `GET /api/admin-templates` mirrors the existing `/api/templates` endpoint.

## 5. Ring moves in the Manager

The `Ring` column is already editable in the Advanced grid; this adds first-class affordances:

- Delegation Map: admin card context action **"Move to ring…"** (dropdown of known rings) staging the change into pending.
- Advanced grid: bulk-select + "Set ring" action in the action bar.
- Validator: existing **PIM-RING-001** covers the value; new **PIM-RING-002** (info) when an admin's ring is *lowered* (promotes earlier deployment — usually intentional, worth a visible note in Review & Save).

## 6. Mail templates

Every engine-sent mail becomes a customizable template:

```
templates/mail/<type>.mailtemplate.html         # shipped default (locked)
templates/mail/<type>.mailtemplate.custom.html  # customer override (gitignored, wins)
```

Types: `new-admin`, `tap-delivery`, `new-role`, `new-permission`, `approval-request`, `approval-escalation`, `offboarding-notice`. Subject line = first line of the file as an HTML comment (`<!-- subject: ... -->`).

Token substitution (straight string replace, no code execution): `{{DisplayName}} {{UserPrincipalName}} {{TapCode}} {{TapStart}} {{TapLifetimeHours}} {{RoleName}} {{GroupName}} {{GroupTag}} {{Sponsor}} {{ManagerEmail}} {{Company}} {{TenantName}} {{Date}}` — unknown tokens render empty plus a warning in the run log.

- Engine: a single `Send-PimTemplatedMail -Type <type> -To <addr> -Tokens <hashtable>` resolves custom-over-locked and routes through the existing notification channels (`$global:PIM_NotificationChannels`); current hardcoded bodies in `Send-PimAdminTap` and friends become the shipped defaults.
- Manager: a read-only "Mail templates" listing (which types are customized, custom vs default) on the Governance tab (§ 12); editing happens in the files — a GUI editor is a later increment.

## 7. Policy templates per role

Bundle the existing `$global:<Role>_<Rule>_..._<Setting>` policy variables (config/policies.custom.sample.ps1) into named, linkable templates:

```
templates/policy/default.policytemplate.json            # current engine custom policies: MFA + justification on enablement, expirations, notifications
templates/policy/approval-required.policytemplate.json  # default + ApprovalRule (for GA groups, tenant-root owner groups, PRA)
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

- **Linking**: new column **`PolicyTemplate`** on the definition CSVs (`PIM-Definitions-Roles`, `-Tasks`, `-Services`, `-Processes`, `-Resources`, `-Departments`, `-Organization`). Blank = `default`. Validator **PIM-POL-001**: referenced template file must exist (did-you-mean suggestions like PIM-WL-001).
- **Engine re-apply**: the engine computes a content hash per template; `output/state/policy-state.json` maps `GroupTag → {templateId, appliedHash, appliedAt}`. When the linked template's hash differs (template edited, or the link changed), the engine re-materializes the unifiedRoleManagementPolicy rules for that group via the existing `Update-MgPolicyRoleManagementPolicyRule` path. Unchanged = NoChange, fully idempotent.
- `extends` is single-level (a template may extend `default` only) — keeps merge semantics trivial.

## 8. Approvals — parallel and serial

Entra PIM's native `ApprovalRule` supports a primary-approver set where **any one approval wins** (= the parallel mode). **Serial approval is not native** — the engine implements it as timed escalation:

| Mode | Mechanism |
|---|---|
| `None` | no ApprovalRule (auto-approved) |
| `Parallel` | native ApprovalRule, `primaryApprovers` = all resolved owners; first approval wins |
| `Serial` | native ApprovalRule with **owner[1] only**; the engine's escalation sweep finds activation requests `status=PendingApproval` older than `escalationHours` and rewrites the policy's approver to owner[2] (then [3]…), emailing `approval-escalation` to the new approver. Order = the order in the `Owners` column. |

- **Approvers come from the existing `Owners` columns** in the definition CSVs (semicolon-separated UPNs) — this finally makes Owners functional. Validator **PIM-APR-001**: a definition linked to an approval-mode template must have ≥1 owner (≥2 for Serial).
- The escalation sweep is part of the normal engine run; escalation latency is therefore bounded by run frequency (documented: schedule the engine hourly on tenants using Serial; ROADMAP notes a lightweight escalation-only scheduled task as a later optimization).
- Manager: the Delegation Map's role/permission cards show an approval chip (`Auto` / `Parallel (n)` / `Serial (n, esc. 4h)`) resolved from the linked policy template + owners.

## 9. Emergency override (break-glass)

For GA / PRA / tenant-root-owner groups protected by `approval-required`:

- **Activation**: Manager Governance tab → "Emergency override" (SuperAdmin only, § 12) → operator enters the **emergency passphrase**, verified server-side against the per-instance Key Vault secret `PIM-EmergencyPasscode` (never stored locally; comparison in memory). On success the server writes `config/emergency-override.custom.json`: `{ active, scopeGroupTags[], activatedBy, activatedAt, expiresAt }` and immediately applies (engine function invoked in-process): ApprovalRule **disabled** on the scoped groups.
- **Auto-restore**: TTL default 4h (max 24h). Every engine run checks the file: expired → re-apply the linked policy template (the § 7 hash mechanism makes this free) and archive the override file to `output/audit/`.
- **Audit**: activation, every policy change it caused, and the restoration are all audit events (§ 11) — plus an immediate `offboarding-notice`-style notification mail to all owners of the scoped groups ("approval was disabled by <who> until <when>").
- Wrong passphrase: constant-time compare, 5 attempts → endpoint locks for 15 min, audit event either way.

## 10. Offboarding

Three levels, all engine-applied and audited:

1. **Admin offboarding** — new columns on `Account-Definitions-Admins`: **`OffboardDate`** (date expression) and **`DeleteAfterDays`** (blank = never delete). At/after OffboardDate the engine: disables the account (existing `Invoke-PimAccountStatusChange` path) → removes ALL its PIM group memberships + eligibilities → revokes active sessions → after `DeleteAfterDays` more days, deletes the account. Each step is a separate audited transaction; the row's `AccountStatus` reflects progress (`Offboarding` → `Offboarded`).
2. **Role / permission-group offboarding** — assignment CSVs already support `Action=Remove`; additionally a definition row with new column **`Lifecycle=Retire`** makes the engine remove the group's role assignments, then memberships, then (only if the engine created it — displayName-prefix guard like the workload applier) the group itself.
3. **Drift cleanup** — `$global:PIM_OffboardCleanupMode = 'Off' | 'Report' | 'Enforce'` (default `Report`): the engine diffs live memberships of engine-managed groups against the CSVs; `Report` lists orphans in the run log + audit, `Enforce` removes them.

## 11. Audit — one schema, append-only

All engine and Manager transactions converge on **`output/audit/pim-audit-<yyyyMM>.jsonl`** (one JSON object per line, append-only, monthly files):

```json
{ "ts": "2026-06-12T10:55:01Z", "runId": "…", "correlationId": "…",
  "actor": "engine | manager:<upn> | emergency:<upn>",
  "action": "account.create | account.disable | tap.create | assignment.add | assignment.remove | policy.apply | approval.escalate | emergency.activate | emergency.restore | mail.send | resource.discovered | …",
  "target": "<upn | GroupTag | scope>", "before": { }, "after": { }, "result": "ok | error:<msg>" }
```

- Existing logs stay (passwords/TAPs files are delivery channels, not audit) but every event ALSO emits a jsonl line; `pim-manager-mutations.log` events are folded into the same schema (`actor: manager:<upn>`).
- Optional sink: ship a sample uploader using AzLogDcrIngestPS to a Log Analytics custom table for tenants that want central retention — config-gated, off by default.
- Manager Governance tab: filterable audit viewer (reads the jsonl files; Reader role may view).

## 12. Manager RBAC — Reader / Admin / SuperAdmin

- **Identity**: the Manager binds to localhost; the acting identity is the Windows user that launched it (`[Security.Principal.WindowsIdentity]::GetCurrent()`), recorded on every mutation (`manager:<domain\user>` in audit).
- **Mapping**: `config/manager-access.custom.json`: `[ { "identity": "DOMAIN\\user | upn", "role": "Reader|Admin|SuperAdmin" } ]`. File missing → launcher is SuperAdmin (backward compatible single-operator install). File present and launcher unlisted → Reader.
- **Gates** (server-side, per endpoint — the GUI also hides what the role can't do):

| Capability | Reader | Admin | SuperAdmin |
|---|---|---|---|
| View map/grid/validate/audit | ✔ | ✔ | ✔ |
| Stage + commit CSV edits, revoke, ring moves | | ✔ | ✔ |
| Instance switching, template/policy editing, refresh caches | | | ✔ |
| Emergency override, manager-access editing, maintenance | | | ✔ |

- New tab: **Governance** — houses audit viewer, mail-template status, emergency override, discovered resources (§ 13), access list. Tab visibility is role-gated.

## 13. Resource auto-discovery

`_tenantSync.ps1` already snapshots Entra roles, AUs, Azure scopes, and PIM groups. Discovery = diff current snapshot vs the previous one (`cache/<instance>/discovery-baseline.json`):

- New Azure subscriptions / management groups, new built-in Entra roles, and (via the workload-connector live role listing) new workload resources such as Power BI workspaces surface as **discovered items**.
- Per resource type, `config/resource-discovery.custom.json` selects the handling: `"Off" | "Portal" | "Engine"`.
  - **Portal**: the Governance tab lists discovered items; one click stages naming-convention-generated definition + assignment rows into pending (operator reviews in Review & Save as usual).
  - **Engine**: the engine itself auto-generates and applies the same rows on its run (for fleets that want zero-touch), emitting `resource.discovered` + `resource.onboarded` audit events and a `new-permission` mail to the configured owners.
- Row generation reuses the naming conventions module so generated GroupName/GroupTag are indistinguishable from hand-staged ones.

---

## Phasing

| Phase | Scope | Ships |
|---|---|---|
| 1 | Date-expression resolver + `ProvisionDate`/`TAPLifetimeHours` + TAP deferral + TAP GUI grouping + ring-move UI + validators (SCHED/TAP-002) | **shipped v2.4.153** |
| 2 | Admin templates (2 shipped) + `Template` column + wizard picker; mail templates + `Send-PimTemplatedMail` | **shipped v2.4.154** |
| 3 | Policy templates + `PolicyTemplate` linking + hash-based re-apply | **shipped v2.4.155** |
| 4 | Approvals: parallel (native) + serial escalation sweep, Owners become functional (approval chips land with the Governance tab) | **shipped v2.4.155** |
| 5 | Offboarding: `OffboardDate`/`DeleteAfterDays`/`Lifecycle=Retire` + drift cleanup modes | **shipped v2.4.156** |
| 6 | Unified jsonl audit (viewer lands with the Governance tab; optional AzLogDcrIngestPS sink is a follow-up) | **shipped v2.4.157** |
| 7 | Manager RBAC + Governance tab (role banner, audit viewer, mail-template status, emergency panel) | **shipped v2.4.158** |
| 8 | Emergency override (passphrase-hash verification in config/emergency.custom.ps1; KV verification = follow-up) | **shipped v2.4.158** |
| 9 | Resource discovery: engine Notify sweep (audit `resource.discovered`) + Manager Portal surface/acknowledge; automatic ROW creation for discovered resources is the documented follow-up | **shipped v2.4.159** |
| 10 | Access reviews (§ 14): engine-owned Entra review schedules (auto-apply OFF), decision sweep, deny tombstones + PIM-REV-001 | design agreed |
| 11 | External request intake (§ 15): SNOW → MID-server file-drop inbox → MANAGER ingests + approval queue (engine never reads external input); signed typed requests, template-only onboarding, high-priv hard deny | design agreed |
| 12 | Manager Entra MFA sign-in + SQL data store (Azure SQL/MI **and** on-prem/hybrid SQL Server, Entra or Windows-Integrated auth — never SQL logins) + CSV→DB migration (§ 16) — the v3.0 line | design agreed |

Phase order optimizes for dependency flow (templates before policies before approvals before emergency) and for the operator's immediate scenario (scheduling + TAP windows first).

## 14. Access reviews — business-driven extend/remove (design, phase 10)

**The circularity problem**: Entra Access Review auto-apply removes a member in Entra, but the CSV is the source of truth — the engine re-delegates on the next run (and the phase-5 drift cleanup actively enforces CSV-wins). Native auto-apply is fundamentally incompatible with a declarative engine.

**Decision: hybrid.** Entra Access Reviews provide the reviewer UX (MyAccess portal, reminders, delegation — we will not rebuild that, and the Manager is operator-localhost-only); the engine owns both the review lifecycle and the application of decisions. Reviews NEVER touch Entra directly.

1. **Engine creates + maintains review schedule definitions** (Graph `accessReviewScheduleDefinitions`) for groups that opt in — `ReviewCycle` carried by the policy template (like approvals) or a per-row column. Reviewers = the row's **Owners**. **Auto-apply = OFF** on every review the engine creates; the engine warns about (and refuses to manage) reviews with auto-apply ON against engine-managed groups.
2. **Decision sweep** (`Invoke-PimAccessReviewSync`, every run): pulls completed instances' decisions.
   - **Approve** → keep; optionally re-stamp the assignment expiry (`NumOfDaysWhenExpire` window restarts) — the consultant-extension scenario.
   - **Deny** → write a **tombstone** `(principal, GroupTag, reviewId, decidedAt)` to the engine-owned suppression layer `output/state/review-tombstones.json`. The engine does NOT edit customer CSVs.
3. **Tombstone layer**: the assignment step treats a tombstoned pair as `Action=Remove` regardless of the CSV — membership is removed and never re-delegated. A validator rule (PIM-REV-001) flags the CSV row: "review-denied <date> — remove this row (or clear the tombstone) to acknowledge." The human reconciles the CSV at their own pace; the Manager-stages / engine-applies trust model stays intact.
4. Everything audited (`review.created`, `review.decision`, `review.tombstone.applied`) + `offboarding-notice`-style mail to the denied principal's manager.

## 15. External request intake — ServiceNow et al. (design, phase 11)

**Constraints**: pull-not-push (AutomateIT invariant); NO inbound endpoint, webhook, function, or internet-exposed storage; a compromised workflow must never be able to create an admin or activate a role.

**Direction**: requests flow FROM ServiceNow INTO the Manager — the Manager owns ingestion and the data structure; the engine never reads external input (it stays purely declarative, applying CSV state only). The intake therefore adds zero attack surface to the engine.

**Transport (primary, fully internal)**: ServiceNow workflow → **ServiceNow MID Server** (the customer's existing internal broker — runs inside the network, connects outbound-only to the SNOW cloud) → drops a signed request file into an **internal inbox directory** (SMB share / folder reachable from the Manager box). Directory ACL: the MID service account has **create-only** rights (cannot read, modify, or delete queued files — a compromised MID cannot tamper with requests in flight); the Manager's account owns the folder and moves every file to `processed/` or `rejected/<reason>/` after verification. No service listens anywhere. **Delivery is decoupled from the Manager's lifetime**: the MID server only writes files; a directory is durable, so requests queue with nothing running on our side. Processing is two-tier, routed per request type by `config/intake-routing.custom.json` (`Approve` = default | `Auto`):

- **`Invoke-PimIntakeProcessor`** — a small headless scheduled task (every ~10 min; same verification code the Manager uses; NOT a listener). `Auto`-routed verified requests become rows in a dedicated **intake overlay CSV** (`PIM-Assignments-FromIntake.custom.csv`) + audit + confirmation; the engine's assignment step unions the overlay with the main CSVs — the engine still never reads raw external input, only this verified artifact, and the overlay avoids write-races with an open Manager session. `Approve`-routed requests stay queued and trigger a "N requests awaiting approval" operator mail.
- **The Manager GUI** is the attended path: the Governance tab shows the queue; operator approval stages rows through the normal pending → Review & Save flow into the main CSVs. Overlay rows render with a provenance badge (e.g. "from ServiceNow REQ0012345") and can be promoted into the main CSV.
- Routing guardrails are non-negotiable regardless of configuration: `Auto` is refused for any group linked to `approval-required`, and `admin.onboard` only instantiates admin templates.

*(Fallback for customers without MID servers: an Azure Storage queue in the customer subscription, SNOW writing with a single-container-scoped SP — still outbound-only from both sides, drained by the same intake processor.)*

**Security layers (defense in depth, each independently rotatable via Key Vault)**:

1. **Payload signing**: SNOW signs `type + payload + timestamp + nonce` (HMAC-SHA256 shared secret in the SNOW credential store + customer KV, or RSA with the public key in KV). The engine verifies, rejects timestamps older than ~15 min, and keeps a processed-nonce ledger — file-drop access alone yields nothing, and replay of a captured legitimate request fails.
2. **Typed allow-list**: `assignment.add`, `assignment.remove`, `admin.onboard` only. `admin.onboard` may ONLY reference a shipped/customer **admin template id** — SNOW instantiates pre-approved shapes, never arbitrary accounts.
3. **High-priv hard deny**: any group whose `PolicyTemplate = approval-required` (GA, PRA, tenant-root owners) is NOT requestable through the intake, ever.
4. **Activation out of scope by design**: the intake manages assignments/onboarding only. Activating a role remains exclusively behind PIM's MFA + approval policies (+ the phase-4 owner approvals) — the "activate a role" attack path does not exist in this channel.
5. **Human in the loop by default, auto only where explicitly routed**: `Approve`-routed requests surface in the Manager's Governance tab and materialize via Review & Save; `Auto`-routed (low-priv, template-shaped only) materialize via the intake overlay CSV. Either way the change reaches Entra only through the declarative CSV layer — there is no path from a request to Entra that bypasses it.
6. **Full audit**: `request.received` / `request.rejected` (with reason) / `request.applied` in the jsonl.

Attack analysis: an attacker needs the SNOW signing key AND internal file-drop access, and even then can only *request* template-shaped low-priv changes that default to human approval — with every step in the audit trail.

## 16. Manager MFA + remote operation + SQL data store (design, phase 12 / v3.0)

Three operator asks that converge on one architecture:

**Manager MFA**: on startup the Manager requires an interactive Entra sign-in (reusing the Edge PKCE loopback flow from the activator backend), verifies the token's `amr` claim includes MFA, and maps RBAC (Reader/Admin/SuperAdmin) to the **Entra UPN** instead of the Windows identity -- which also activates everything Conditional Access can add (compliant device, sign-in frequency). Honest scope: this protects USE of the Manager and its tenant connections; it cannot protect the files on the automation server from an attacker who already has code execution there -- host hardening (PAW, JIT) remains its own discipline.

**Remote operation today**: `-ConfigRoot \\server\share` over SMB works now, but it is a workaround (ACLs, duplicate module installs, no concurrency).

**SQL data store (v3.0)**: the original ROADMAP decision (stay CSV, revisit at v3.0) predates multiple writers (Manager + engine + intake processor), state layers, RBAC, and audit. Decision: SQL becomes the primary store, with **cloud AND on-prem/hybrid SQL both first-class** -- the repository layer takes a connection profile (`$global:PIM_SqlConnection = @{ Server; Database; AuthMode }`), TLS enforced, and NO credential ever lives in config:

| Deployment | Operator (Manager) auth | Engine auth | MFA at the DB door |
|---|---|---|---|
| Azure SQL Database / Managed Instance | Entra interactive (`AuthMode=EntraInteractive`) -- MFA + Conditional Access enforced by Entra | SPN / Managed Identity (`EntraSpn`) | yes (Entra) |
| On-prem / hybrid SQL Server (classic AD) | Windows Integrated / Kerberos (`WindowsIntegrated`) -- domain identity, no SQL logins | gMSA or AD service account | no -- MFA comes from the Manager's Entra sign-in gate (app layer) + host/network controls |
| SQL Server 2022+ Arc-enabled (hybrid, optional) | Entra auth on-prem via Azure Arc | SPN | yes (Entra) |

SQL logins are disabled in every mode -- there is never a SQL password to steal. DB roles mirror Reader/Admin/SuperAdmin in all deployments. For classic on-prem AD customers the documented guidance is: app-layer MFA (the Manager's Entra sign-in) is the MFA boundary, and the SQL Server should only be reachable from the automation/management subnet.

Migration path:
1. **Repository abstraction first**: `Get-PimRows -Table X` / `Save-PimRows` with `$global:PIM_DataStore = 'Csv' | 'Sql'`; Manager, engine and validator route through it -- both stores work during transition, and `Csv` stays supported indefinitely for small installs.
2. **Schema** mirrors the existing model: the 15 logical tables + state (tap/policy/offboard/review-tombstones) + the audit log (jsonl -> append-only table, finally queryable) + intake requests.
3. **`Invoke-PimCsvToDbMigration`**: idempotent per-instance importer -- validator runs first, rows load, counts verify, CSVs are archived (never deleted).
4. **Safety nets**: nightly CSV snapshot export from the DB (git-diffability + the Excel escape hatch preserved).

## 17. Email routing & people directory — no per-admin manager maintenance (design)

**Problem**: `ManagerEmail` per admin row is hard/impossible to maintain at fleet scale, and a leaver's address lingers in many places (ManagerEmail rows, group Owners/approvers, future access-review reviewers, escalation contacts). When a manager leaves, the fix must be a few edits — not a hunt.

**Where an email is actually needed today** (so the design covers all of them):
- TAP-delivery + new-admin lifecycle mails (currently per-admin `ManagerEmail`)
- Approval/owner mails — already group-scoped via Owners on the approval-required groups (correct place; stays)
- Serial-approval escalation + offboarding notices
- Access-review reviewers (§ 14, phase 10) and intake nudges (§ 15)

**Design — three layers, deterministic resolution order (each step configurable):**

1. **Department link instead of person link**: `Account-Definitions-Admins` gains a `Department` column; a new **`config/PIM-Definitions-Contacts.custom.csv`** (the people directory) holds one row per department/function: `Department;ManagerEmail;DeputyEmails;Mode(Serial|Parallel)`. A consultant links to a department; the department's manager is defined ONCE. Manager churn = one row edit.
2. **Central override**: `config/mail-routing.custom.json` — `{ "AdminLifecycleRecipients": [...], "Mode": "Parallel|Serial", "PerAdminWins": true|false }`. With `PerAdminWins=true` (default) a filled per-admin `ManagerEmail` still wins; `false` forces the central route (lockdown mode).
3. **Per-admin `ManagerEmail`** becomes an optional override, no longer the primary mechanism.

Resolution: per-admin (if set AND PerAdminWins) → department contact row (via admin.Department) → central AdminLifecycleRecipients → skip-with-audit if nothing resolves. Serial mode walks the list with the existing phase-4 escalation machinery; Parallel sends to all.

**Manager GUI — "Contacts & email flow" area** (new Governance sub-tab):
- Edit the people directory + central routing config with live "who would get the TAP mail for admin X?" preview.
- **"Person left" sweep**: enter an email → the Manager scans EVERY reference (ManagerEmail columns, Department contacts, group Owners across all Definitions CSVs, mail-routing config, manager-access.custom.json RBAC entries) → shows the hit list → stages a replace-all-with-successor (or blank) through the normal pending → Review & Save flow, fully audited (`contact.replaced`).
- Approvals stay EXPLICIT on the specific high-priv groups (approval-required policy template + Owners) — this section changes who gets *notified/escalated to*, never *what requires approval*.

## 18. Self-service delegation layers (design, exploratory)

**Operator ask**: let business units self-manage a bounded slice — create/enable their own admins, auto-disable after N days without sign-in, and delegate a scoped permission subset (e.g. only subscriptions under one management group) — without giving them the Manager or the engine.

**Verdict: feasible, as a LAYER on the existing model — the delegation boundary is data, not new privilege machinery:**

1. **Delegation units**: a new `config/PIM-Definitions-DelegationUnits.custom.csv` groups what § 17 and the templates already model: `UnitTag;Department;AllowedAdminTemplates;AllowedGroupTags;AllowedAzScopePrefix;MaxAdmins;InactivityDisableDays;ApproverContact`. A unit = (who may ask) × (which admin templates they may instantiate) × (which group tags / Azure scope prefixes they may touch) × (quotas). Example: `BU-Finance` may onboard `consultant`-template admins and assign only `ROLE-Finance-*` groups and Azure scopes under `/providers/Microsoft.Management/managementGroups/mg-finance`.
2. **Self-service front end = the § 15 intake, not a new trust path**: requests from the business land as signed intake requests (ServiceNow catalog item, or a thin internal "self-service portal" page) and materialize ONLY through the declarative CSV layer with the § 15 guardrails (typed allow-list, template-only onboarding, approval-required groups hard-denied). The delegation unit is the authorization filter the intake processor enforces per requester.
3. **The permanently-running web service** (user-anticipated): a small internal-only site (same localhost-style security model grown up: Entra sign-in + MFA, RBAC by delegation unit, runs as a low-priv identity with NO Graph write permissions — it can only write signed intake files). Even fully compromised, it can request nothing outside its unit's template/scope envelope, and high-priv is structurally unreachable. The engine remains the only writer to Entra/Azure. **Hosting options**, both with zero public ingress:
   - **Azure private-endpoint deployment (PREFERRED — modern, zero public exposure)**: App Service / Container Apps with `publicNetworkAccess=Disabled` and a **Private Endpoint** into the corp VNet (reached via ExpressRoute / S2S VPN; name resolution via the `privatelink` DNS zone). The site is unreachable from the internet by construction; Entra auth + CA still apply on top. Its intake drop lands on Azure Files/Blob behind a private endpoint in the same VNet, which the on-prem intake processor pulls — preserving pull-not-push end to end. Managed Identity holds storage-write only; PaaS patching/scaling for free.
   - **On-prem IIS/Kestrel** on the automation/management subnet (fallback for customers without VNet connectivity).
4. **Inactivity auto-disable**: engine-side sweep (no service needed) — `signInActivity.lastSignInDateTime` from Graph vs `InactivityDisableDays` per delegation unit; expired admins get `AccountStatus=Disabled` staged (Report mode) or applied (Enforce mode) + audit + notice mail via § 17 routing. This also benefits non-delegated admins as a general hygiene feature.
5. **Azure scope slicing**: already native — Azure assignment rows take any scope; the delegation unit's `AllowedAzScopePrefix` confines self-service rows to subscriptions under the unit's management group.

Build order when scheduled: § 17 first (contacts/routing — self-service approvals depend on it) → intake processor (§ 15 phase 11) → delegation-unit filter → inactivity sweep → portal front end last.

## Out of scope / known limitations

- Holiday-aware workday calculation (Mon–Fri only).
- Serial-approval escalation latency is bounded by engine run frequency.
- Mail-template GUI editor (file-based editing first).
- SQL storage — everything above stays inside the CSV + JSON-template model per the ROADMAP storage decision.
