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
| 7 | Manager RBAC + Governance tab shell | manager |
| 8 | Emergency override (needs 3 + 7) | manager, engine |
| 9 | Resource auto-discovery (Portal mode first, Engine mode second) | manager, engine |

Phase order optimizes for dependency flow (templates before policies before approvals before emergency) and for the operator's immediate scenario (scheduling + TAP windows first).

## Out of scope / known limitations

- Holiday-aware workday calculation (Mon–Fri only).
- Serial-approval escalation latency is bounded by engine run frequency.
- Mail-template GUI editor (file-based editing first).
- SQL storage — everything above stays inside the CSV + JSON-template model per the ROADMAP storage decision.
