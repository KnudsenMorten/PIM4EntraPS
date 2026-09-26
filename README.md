# PIM4EntraPS

> **Privileged-access governance for Microsoft Entra, as code.**
> Model your privileged delegation as nested groups, apply the right PIM
> policies, and keep everything in sync from a single source of truth —
> with no unauthenticated endpoint and no credentials lying around.

**PIM4EntraPS** turns a sprawling, click-driven Entra PIM model into a
**declarative model** that an engine reads, diffs against your tenant, and
applies. It is for **IT admins, platform teams and CISOs** who manage
privileged access at any non-trivial scale. A typical 30-admin /
200-permission-group tenant becomes: one model kept in sync by a single
engine run, a browser-based **PIM Manager** GUI to edit and validate it, and a
**PIM Activator** browser extension admins bulk-activate from. The engine talks
directly to Microsoft over secure web calls — no heavy PowerShell modules to
install or keep updated — and reads its model from **one governed database**.
It runs in your own Azure subscription as a small set of Container Apps (a
Manager that scales to zero and a scheduled engine job) next to an Azure SQL
database. The Manager is always behind Microsoft Entra sign-in, and can be made
private-only if your network design calls for it.

![PIM Manager — Home / Overview dashboard](docs/img/manager-home.png)
*The PIM Manager opens on a Home / Overview dashboard — red/amber/green tiles
for engine and job health, validation findings, break-glass status,
delegation by tier and expiring access — every tile links to the screen that
owns the detail. (Screenshot uses synthetic demo data.)*

---

## Table of contents

- [Why PIM4EntraPS — what makes it different](#why-pim4entraps--what-makes-it-different)
- [Why this exists](#why-this-exists)
- [The core idea: group nesting](#the-core-idea-group-nesting)
- [What it does for you — feature by feature](#what-it-does-for-you--feature-by-feature)
  - [The single source of truth](#the-single-source-of-truth)
  - [The engine that keeps your tenant in sync](#the-engine-that-keeps-your-tenant-in-sync)
  - [One model, every workload](#one-model-every-workload)
  - [Automatic discovery of new resources](#automatic-discovery-of-new-resources)
  - [The delegation model — access done right](#the-delegation-model--access-done-right)
  - [Bringing in consultants and self-service](#bringing-in-consultants-and-self-service)
  - [Layered security and fail-closed access](#layered-security-and-fail-closed-access)
  - [Lifecycle, governance and approvals](#lifecycle-governance-and-approvals)
  - [Emergency break-glass](#emergency-break-glass)
  - [Notifications and email](#notifications-and-email)
  - [Naming that matches your organisation](#naming-that-matches-your-organisation)
  - [Built for very large tenants](#built-for-very-large-tenants)
  - [Tested for real, never faked](#tested-for-real-never-faked)
- [The PIM Manager (GUI)](#the-pim-manager-gui)
  - [One clear place to look — the Home dashboard](#one-clear-place-to-look--the-home-dashboard)
  - [Six menus, named for what you do](#six-menus-named-for-what-you-do)
  - [See who can reach what — the Access map](#see-who-can-reach-what--the-access-map)
  - [Create access the natural way round](#create-access-the-natural-way-round)
  - [Pending changes — one queue, reviewed before commit](#pending-changes--one-queue-reviewed-before-commit)
  - [Drift — is the tenant what PIM says it should be?](#drift--is-the-tenant-what-pim-says-it-should-be)
  - [Review current delegations](#review-current-delegations)
  - [Reports — "who can do what", and the reverse](#reports--who-can-do-what-and-the-reverse)
  - [Role Lookup — the questions every admin asks about roles](#role-lookup--the-questions-every-admin-asks-about-roles)
  - [Validate — catch problems before they ship](#validate--catch-problems-before-they-ship)
  - [Jobs and engine logs](#jobs-and-engine-logs)
  - [Audit and Support](#audit-and-support)
  - [Settings — your operational policy in one place](#settings--your-operational-policy-in-one-place)
  - [Export everywhere](#export-everywhere)
- [The PIM Activator (browser extension)](#the-pim-activator-browser-extension)
- [Supported setups — pick the shape that matches you](#supported-setups--pick-the-shape-that-matches-you)
- [How updates reach an environment — the two ring systems](#how-updates-reach-an-environment--the-two-ring-systems)
- [Editions — what is free and what is paid](#editions--what-is-free-and-what-is-paid)
  - [Free — the community edition, for a single tenant](#free--the-community-edition-for-a-single-tenant)
  - [Pro — licensed capabilities for a single tenant](#pro--licensed-capabilities-for-a-single-tenant)
  - [Pro — the multi-tenant half](#pro--the-multi-tenant-half)
  - [How licensing works](#how-licensing-works)
  - [Defaults in this release](#defaults-in-this-release)
  - [Getting a licence](#getting-a-licence)
- [Getting started — install the community edition](#getting-started--install-the-community-edition)
  - [What you need](#what-you-need)
  - [1. Get the code](#1-get-the-code)
  - [2. Create the deploy identity](#2-create-the-deploy-identity)
  - [3. Deploy everything with one command](#3-deploy-everything-with-one-command)
  - [4. Sign in and verify](#4-sign-in-and-verify)
  - [Keeping it up to date](#keeping-it-up-to-date)
  - [What it costs to run](#what-it-costs-to-run)
- [Hosting & containers](#hosting--containers)
- [MSP variant](#msp-variant)
- [By the numbers](#by-the-numbers)
- [Repo layout](#repo-layout)
- [Documentation](#documentation)
- [Versioning](#versioning)
- [Support / contributing](#support--contributing)

---

## Why PIM4EntraPS — what makes it different

Most privileged-access tools either drown you in portal clicks or hand you a
pile of spreadsheets to keep in sync by hand. PIM4EntraPS is built on four
ideas that set it apart. Each one is explained in plain language below; the
rest of this document then walks through every capability in detail.

### One governed database as the single source of truth — not CSV files

Everything that describes your privileged access — who the admins are, what
job functions exist, what each one can do, and where — lives in **one governed
database**. There are no scattered spreadsheets drifting out of sync, no "which
copy is the real one?", and no quarterly reconciliation exercise. You edit the
model in one place, the engine reads that same place, and the scheduled jobs
read it too — so what you see is always what the system actually does. (A
spreadsheet import exists, but only as a one-way migration route to *get* an
existing model *into* the database; once you're in, the database is the truth.)

### Layered security — privilege tiers, fail-closed access, MFA and approvals

Privilege is treated as something to be **layered and contained**, not granted
flat:

- **Privilege tiers and planes (L0–L5).** Every piece of delegated access is
  classified by how sensitive it is (tier) and which administrative plane it
  belongs to. The most privileged access is held to the strictest rules, and
  the model makes over-exposure visible instead of hiding it.
- **Fail-closed access.** If the system can't *prove* what an operator is
  allowed to do, it drops them to **read-only** rather than guessing generously.
  Safe-by-default is the default.
- **MFA on activation.** Activating privileged access can be required to be
  backed by a fresh multi-factor sign-in, so a copied script or a stale session
  can't quietly elevate.
- **Approval gates on sensitive changes.** The most powerful, Global-Admin-class
  delegation automatically requires approval at activation, with the approver
  resolved from the group's owners — a high-privilege group is never left with
  nobody able to grant it. Reconciliation is safe-by-default too: a normal run
  only creates and updates, and it refuses to wipe out real admins from a
  partial configuration.

### Delegation done right — admins → role groups → permission groups → targets

Access is never wired directly from a person to a role. Instead it flows
through **nested groups**: a person joins a **role group** (their job function),
which contains **permission groups** (atomic capabilities), which grant the
actual **targets** (Entra roles, Azure scopes, workloads). The payoff is huge:

- **Auditable** — the chain *is* the answer to "who can do what".
- **Refactorable** — change one permission group and every job function using it
  updates for free.
- **Offboard-safe** — removing a person is one deletion, and their entire access
  surface collapses with them.

### A modern, module-free engine

The engine connects **directly to Microsoft over secure web calls, using a
certificate to sign in** — never a shared secret, never a copy-pasted password,
never a fragile interactive prompt. There are **no PowerShell Graph or Azure
modules** to install, version-match or keep in lock-step, so it runs cleanly on
a plain VM or a lightweight container with nothing pre-installed.

### And two more standouts

- **Runs in your own tenant, at close to no cost.** The whole platform deploys
  into your own Azure subscription with one command: a Manager that scales to
  zero when nobody is using it, one scheduled engine job, and a small Azure SQL
  database. Nothing runs on anyone else's infrastructure, the Manager is always
  behind Microsoft Entra sign-in, and a private-only network design is supported.
- **MSP: pull, never push.** For consultancies managing many customer tenants,
  each tenant *pulls* a cryptographically signed baseline into its own database.
  The provider never reaches into the customer tenant, customer data never
  leaves it, and every action is attributed to a named app inside the customer's
  own tenant.

---

## Why this exists

Managing PIM at any non-trivial scale through the Entra portal is painful:

- Per-admin onboarding is **N clicks** (one per role / scope / AU).
- "Add a new permission to the Cloud Engineer role" is **M clicks** (one
  per admin who has that role).
- Drift is invisible: nobody knows what's *actually* assigned vs what was
  documented last quarter.
- Audit asks "who can do X" — answering means clicking through every PIM
  blade and Azure RBAC scope.

**PIM4EntraPS replaces the clicks with a declarative model.** The model
lives in one governed database as a small set of related tables — one source
of truth instead of scattered spreadsheets:

| The model holds | Which says |
|---|---|
| Admin definitions | Who the admin accounts are |
| Role-group definitions | What *role groups* exist (job functions) |
| Permission-group definitions | What *permission groups* exist (atomic capabilities) |
| Admin assignments | Which admins are in which role groups (eligible / active) |
| Group assignments | Which permission groups nest inside which role groups |
| Entra-role assignments | What Entra ID roles each permission group grants |
| AU-role assignments | What AU-scoped Entra roles each permission group grants |
| Azure-resource assignments | What Azure RBAC scopes each permission group grants |

Run the engine → the tenant matches the model. Edit a row → run again → the
delta is applied. History is tracked. A spreadsheet import path exists as a
read-only migration source for getting an existing model into the database.

---

## The core idea: group nesting

Don't assign Entra/Azure roles directly to admins. Assign them to
**permission groups** (atomic capabilities). Nest permission groups into
**role groups** (job functions). Assign admins to role groups via PIM:

```
Admin                 Role Group              Permission Groups               Target
(the user)            (the job function)      (atomic capability)             (Entra / Azure / AU)

Admin-ABC           --E->  Role-              --E--> Entra-ID-                  --E--> "Application Administrator"
                           CloudEngineer              AppAdmin                          (Entra ID role)
                                                --A--> AzDevOps-                  --A--> "Build Administrator"
                                                       TeamsContributor                  (Azure DevOps role)
                                                --E--> AzRes-                     --E--> Owner on a subscription
                                                       Platform                          (Azure RBAC)
                                                --E--> PowerBI-                   --E--> Workspace contributor
                                                       ExampleWorkspace                  (Power BI)
```

`--E->` = Eligible (PIM activation required) · `--A->` = Active (always on)

**Why nest:**

- Onboarding a new Cloud Engineer = **one** assignment, not 20.
- Refactor a permission group's targets → every role group using it gets
  the change for free.
- Removing an admin = one deletion; their entire access surface collapses.
- The graph (admin → role → permission → target) *is* the audit answer to
  *"who can do X?"* — see the **[PIM Manager](#the-pim-manager-gui)**.
- Entra enforces a hard cap of **500 role-assignable groups per tenant**.
  Heavy reuse of permission groups + role groups across many admins keeps
  you well under the ceiling.

![Access map — an admin traced through a role group and its permission groups to the roles they grant](docs/img/manager-access-map.png)
*The Access map renders the nesting as an interactive graph: pick a person and
the board collapses to their path — role group, permission groups, and the Entra
and Azure roles those grant. (Synthetic demo data.)*
Every option on the map is tested in a real browser before each release. Each kind of box must draw its whole
chain, with every line joining the right boxes.

Access-review decisions and reviewer changes are carried out by the engine, and checked once applied. The
Manager itself only reads.

See **[docs/DESIGN.md](docs/DESIGN.md)** for the full philosophy: direct
vs indirect delegation, naming convention, tier model, lifecycle states,
the as-code pattern, customer overrides.

---

## What it does for you — feature by feature

This section explains every delivered capability in plain language —
benefit-first, no jargon. For the complete customer-facing catalog, see
**[docs/FEATURES.md](docs/FEATURES.md)**; per-release detail is in
**[RELEASENOTES.md](RELEASENOTES.md)**.

### The single source of truth

Your entire privileged-access model — configuration, settings, access rules
and delegation profiles — lives in **one governed database**, not in files or
shares you have to keep in step. The Manager, the engine and the scheduled
jobs all read and write the same store, so there is never a question of which
copy is current. Settings, the audit trail, mail templates and scheduler state
live there too — there are no configuration files to keep in step. Sign-in to
the database is **passwordless**: the Manager and the engine use their managed
identities, so no database password is stored anywhere. Moving from the older
spreadsheet-based edition is a one-time import into the database.

The hosted database is kept **awake** so neither the health check nor the first
request after a quiet period suffers a cold start, and the health check
**tolerates a brief blip** — a single hiccup is reported as a transient warning
rather than taking the service down; only a sustained outage reports unhealthy.

### The engine that keeps your tenant in sync

The engine is the part that makes your tenant match your model. It is **modern
and dependency-free** — it talks directly to Microsoft and to the database with
no heavy PowerShell modules to install or keep updated — and it runs as a
scheduled job that wakes every few minutes, does what is due, and stops.

- **From one run, everything gets set up.** Groups, delegations, organisational
  group access, time-limited access passes, admin schedules and notification
  emails — all created in a single pass, with nothing wired up by hand.
- **A change runs only what it touches.** When you commit a change, the engine
  runs just the steps that change needs instead of a full sweep, and — where the
  Manager is permitted to start the job — it starts right away rather than
  waiting for the next scheduled tick. Queued actions such as a TAP re-issue or a
  session revoke are applied between engine steps, not after a long run.
- **PIM only touches what you define.** A group, admin, delegation or policy is
  PIM's only when a row in your model defines it. A group that merely *looks*
  like a PIM group keeps its members and policies, break-glass accounts are
  never touched, and an empty model changes nothing at all.
- **Your policies, identical to v1.** Entra role, Azure resource and PIM for
  Groups policies (including owner policies and the full notification set) follow
  your templates. A run that would change many policies at once, or weaken
  protection, is **held until an administrator approves the exact plan**.
- **Every change it makes is audited** with real names and the job run that made
  it; policy changes are recorded rule by rule, before and after.
- **Clear, readable logs.** Every action is one tagged line (assign / update /
  extend / remove / OK); errors name the actual resource or role, not an opaque
  ID; and a full transcript is kept for each run.
- **Safe by default.** A normal run only creates and updates. Removing live
  access that isn't in your configuration is a separate, explicit opt-in — and
  the engine refuses to "prune" an area whose desired set is empty, so a partial
  or half-loaded configuration can never wipe out real administrators. Before any
  run touches your tenant, it checks that the model is real and the identity is
  valid, and refuses to start otherwise — a wrong identity fails immediately, not
  half-way through.

### One model, every workload

A single PIM group can grant access across many Microsoft workloads — you model
it once and the engine translates it into the right access everywhere:

- **Entra ID roles** (tenant-wide or scoped to an administrative unit).
- **Azure RBAC** at any scope (management group, subscription, resource group,
  resource).
- **Power BI / Fabric** workspaces.
- **Microsoft Defender XDR** security roles (Unified RBAC).
- **Intune / device management** roles, optionally limited to specific scope
  tags.
- **Gallery enterprise apps** such as SAP or ServiceNow.
- **Dataverse / Dynamics 365.**

Admins get the workload access simply by being a member of the group.
Assignments are matched against what already exists, so re-running never
creates duplicates, and a role you no longer want is only removed when you
explicitly ask. Roles are **imported from the live service list** so you pick
from real, current roles instead of risking a typo.

### Automatic discovery of new resources

New resources become ready-to-delegate access groups **on their own**:

- **New Power BI workspaces, Azure subscriptions and management groups** are
  proposed as correctly-named, tier- and plane-classified access groups minutes
  after they appear — so a new resource is delegable almost immediately, with
  the same structure as everything else.
- **Renames are tracked, not duplicated.** A resource that is renamed or moved
  is matched by its stable identity and the existing group is renamed in place —
  you never end up with an orphan plus a duplicate.
- **It proposes, it never auto-grants.** Discovery creates the empty container;
  who actually gets in stays a human decision.
- **New built-in roles** (Entra, Defender, Intune) are catalogued automatically
  so you can pick them, and a role you've already handled never shows up as "new"
  again — each run surfaces only what you haven't dealt with yet.
- **Import your departments straight from Entra.** Point it at a group naming
  pattern (for example `ORG-*`) and one click pulls every matching group in as a
  department for approval routing, bringing each group's owners along as that
  department's approvers. Re-import any time — existing imports refresh in place,
  nothing is duplicated, and anything you added by hand is left alone.

### The delegation model — access done right

This is the heart of PIM4EntraPS. Admins are added to **direct groups** (by
role, task, process, cross-organisation or department), which nest into
**permission groups** that hold the actual roles and scopes. The result is
least-privilege access across many apps, by reuse rather than by hand.

- **Everything you grant is a group.** Administrative units and Azure scopes are
  only the *where*, never the *who* — delegation is simply group membership.
- **Every group has an owner, automatically.** A group is never created without
  one; the owner is resolved from the assignment, the role's sponsor, or the
  department-to-owner mapping. Owners are also the approvers for any
  approval-required policy.
- **Scoped portal admins.** A delegated admin sees only the groups they own, and
  even the admin list is filtered so they can't see the most privileged tiers.
  Super-admins bypass the scoping when they need to.
- **Two clearly separated approvals.** *Delegation approval* (who may join a
  group) is handled by the solution and routed to the responsible department.
  *Activation approval* (approving an activation in the moment) is handled
  natively by Microsoft Entra PIM. The two are never confused, and the solution
  turns any department or role persona into the actual named people before it
  configures a policy — and refuses to publish an approval rule that would end up
  with nobody able to approve.
- **Network-reach classification (opt-in, off by default).** Each delegation can
  carry a network-reach classification derived from its tier, plane and level —
  for example confining the most privileged tier to a privileged-workstation
  (PAW) segment. It is **off by default**, so a tenant that doesn't run
  privileged workstations is never blocked; turn it on with a single setting when
  you're ready, and emergency super-admin access is never locked out.

### Bringing in consultants and self-service

- **Invite an external consultant in one step.** Bring a consultant in as a
  cloud guest *and* place them into the right delegation group at the same time.
  The invitation, their admin record and their group membership are all staged
  for the normal Review & Save flow — nothing is granted until you confirm.
  Guest invitation is cloud-only and gated by a specific delegation right.
- **Self-service consultant enable/disable.** A department or service owner can
  switch one of *their own* managed consultants on or off without a central
  request — only for the consultants they manage, queued as a normal, audited
  account change.
- **Local self-service delegation.** When you run the solution for your own
  organisation, your local IT can self-grant any permission — full local
  autonomy. In a managed-service setup that self-grant path is closed instead,
  and specific privileged groups can be pinned as "enforced" so they can never be
  locally overridden. A self-delegation is always recorded as an ordinary
  assignment, so it is audited and offboarded like everything else.

### Layered security and fail-closed access

Security is layered through the whole product, not bolted on:

- **Privilege tiers and planes (L0–L5)** classify every delegation by how
  sensitive it is and which plane it lives on, so the most powerful access is
  held to the strictest rules and over-exposure is visible.
- **Fail-closed.** When the Manager can't determine what an operator is allowed
  to do, it drops to **read-only** rather than assuming the best, and a request
  with no signed-in user is refused outright. The role tiers
  (Reader / Admin / Super-Admin / Delegated) gate exactly what each operator can
  do. *(New in 2.4.370.)* A new hosted Manager stays closed until its sign-in is
  configured and verified. Names written into desired state are escaped before
  they reach the page. Two administrators editing the same data cannot overwrite
  each other, and a delegated administrator's commit can never remove rows outside
  their scope.
- **No stored passwords.** The hosted Manager and engine authenticate with their
  own managed identities — to Microsoft Graph, to Azure and to the database — and
  deployment tooling signs in with certificates. A client secret is used only where
  the platform itself requires one (the sign-in registration that fronts the
  Manager), and never lives in a configuration file.
- **It tells you exactly which permission is missing.** When a call is refused,
  you don't get a bare "access denied" — you get the precise permission to grant
  (for the automation identity) or the privileged role to activate (when you're
  signed in as yourself), and the one script that grants it.
- **It always shows the account picker** and forces a fresh sign-in if the cached
  account isn't the one you expected, so you can't accidentally act as the wrong
  identity. On-prem Active Directory failures are **explained** — the identity it
  ran as, whether it had a domain logon and Kerberos tickets, and whether a
  domain controller was reachable — so you know whether to fix the credential,
  the network, or the target.
- **MFA-gated admin console (optional).** The privileged Manager console can
  require a fresh multi-factor sign-in before it opens, so a copied script can't
  be replayed without you passing MFA. When the console runs centrally behind a
  sign-in gateway, that already enforces MFA and the local gate stays out of the
  way.

### Lifecycle, governance and approvals

PIM4EntraPS manages privileged access across its whole life, not just at
creation:

- **Scheduled account creation + time-limited access pass.** Admin accounts can
  be staged for a future date and time (plain or symbolic, e.g. "the first
  workday of next month"). The access pass is held back until just before it is
  needed, so a pass scheduled weeks out isn't issued early — and an account is
  never created twice.
- **Lifecycle calendar with reminders and auto-renewal.** A single pass produces
  a calendar of access expiring soon, sends escalating reminders to the right
  people as the deadline nears (paced so nobody is spammed), and automatically
  renews items explicitly marked for it before they lapse.
- **Access review with a feedback loop.** Owners approve continued access before
  it's extended. A removal decision is **remembered**, so the engine never
  silently re-adds someone an owner just removed — the most recent decision
  always wins.
- **Access reviews from a review cycle.** Give a group a review cycle and the
  engine creates a recurring review of its members, reviewed by its owners.
- **Rename a group or Administrative Unit, and keep the object.** Renaming in
  *All records* renames the existing group or AU in Entra ID, with its members
  and roles; every row that points at it is updated in the same change.
- **Held policy changes are approved under Approvals**, one change set at a
  time, each shown as current → new.
- **Daily checks that report, never act.** Every day PIM checks that the Azure
  resources and roles and the Entra roles your delegations name still exist, and
  reminds you of changes staged or queued more than a day ago that nobody
  committed — each mailed with a link to the page that fixes it.
- **Admin lifecycle with v1 parity.** Disabled and revoked admins stay disabled;
  offboarding runs on its own schedule and resumes if it is interrupted; a Remove
  row revokes access first; accounts are created when they are due; every cloud
  admin receives a Temporary Access Pass that honours its start date; and
  on-premises Active Directory admins are created in AD with an initial password
  that is mailed, never stored.
- **Optional audit to Log Analytics.** On top of the audit trail kept in the
  database, every change can optionally be forwarded to Azure Log Analytics (off
  by default, one setting to enable).

### Emergency break-glass

In a genuine emergency, an authorised super-admin can temporarily lift the
approval requirement on the affected access, gated by a passphrase. The
passphrase is verified against a secret in your key vault (with a local
fallback) using a timing-safe comparison, with a short lockout after repeated
wrong attempts and a bounded lifetime (defaults to 4 hours, capped at 24).
Every step is audited, owners are notified, and normal policy is restored
automatically when the window closes. Crucially, it **works from a client PC**,
so senior admins are never locked out even if the central console is down.

*(New in 2.4.370.)* The override is applied by the engine on its next run and
reverted by the engine when it expires. **Break-glass accounts** are managed in
**Settings**, stored in the database and read by both the Manager and the engine.
PIM never revokes, disables or offboards them. If the list cannot be read, every
account is protected until it can.

### Notifications and email

- **Built-in, template-driven email.** New admin, new role, new permission and
  access-pass delivery are all sent by rendering customisable HTML templates.
  Rendering is separated from sending so you can preview, and a lab redirect
  keeps test mail out of real inboxes. New-admin access-pass codes can be fanned
  out to any combination of email, Teams and Slack; a delivery failure never
  blocks account creation.
- **Mail is sent as the environment's own managed identity**, with send rights
  limited to the sender mailbox. Admin mail and access passes go to the owner's
  office address (the forwarding address if set, otherwise the manager), and are
  refused rather than sent somewhere wrong when no valid address exists.
- **Edit templates in the portal — no rebuild.** Open a template under
  Audit & Settings → Mail templates, change the wording, save — your version is stored
  centrally and takes effect immediately, surviving restarts and updates. The
  portal shows which templates are still the shipped default and which you've
  customised, with one-click **Reset** to the original.
- **Get told when something goes wrong.** Choose who is emailed and which events
  raise an alert — an engine/job run failure, configuration drift, access
  expiring soon, or break-glass use — from the Alerting panel. A test button
  confirms the wiring; if no sender mailbox is configured yet, the panel says so
  plainly rather than silently dropping the alert.

### Naming that matches your organisation

Customer naming styles vary widely. PIM4EntraPS captures **your** convention in
configuration — never hardcoded — using simple tokens for initials, level, tier
and platform, with per-tenant overrides. That one convention then drives three
things at once: the engine's large-tenant performance (it queries only your
PIM-managed objects by prefix), the Manager's wizards (which suggest correctly
named groups), and the validator (which warns on convention drift). You can
match your own style without touching code.

### Built for very large tenants

The solution is designed never to choke on scale. It **never bulk-lists**
hundreds of thousands of users or groups — it looks users up on demand and
queries only the PIM-managed groups by name prefix on the server side, so
context builds in seconds even in very large directories. Tenant-wide role
schedules are read once and indexed; anything that already exists is skipped;
access durations that are too long are retried shorter; and there are **no
artificial caps** — scaling is empirical (measure, adapt, prune), never
arbitrary "max N" limits that hide real problems.

### Tested for real, never faked

Validation runs against **real test tenants** — actually creating groups,
delegations, organisational group access, emails, time-limited passes and
schedules, then verifying and cleaning them up. Test data lives under a
dedicated marker so it never touches production groups, and a rerunnable offline
suite covers the engine and Manager flows. After a first-time deploy, an
automated suite reads the desired configuration straight from the database and
confirms — against the live tenant — that **every** group, administrative unit,
role assignment, admin delegation and approval policy was actually created.

---

## The PIM Manager (GUI)

The PIM Manager is a browser-based editor and dashboard for your whole
privileged-access model. It reads the model from the database and serves a
single-page app in your browser, on the same light palette as the PIM Activator
extension. You can run it centrally for the team or locally on your own PC
against the same database.

### One clear place to look — the Home dashboard

The Manager opens on a **Home / Overview** dashboard instead of dropping you
into a graph. It summarises the health of your privileged-access estate in clear
red/amber/green tiles, each of which jumps to the screen that owns the detail:

- **Failed jobs / engine health** — how many background jobs failed, what's
  running now, when the last run was and whether it succeeded, and when the next
  is due (so an overnight failure is visible the moment you log in).
- **Validation findings** — the current count of blocking errors and warnings.
- **Break-glass** — whether an emergency override is active right now, who
  activated it, and when it expires.
- **Delegation by tier (L0–L5)** — how your delegation groups spread across
  privilege levels.
- **Gaps, orphans & unmanaged** — groups that reach nothing, admins who reach
  nothing, and targets no group manages.
- **Expiring access (next 14 days)** and **pending access reviews** — what needs
  renewing, revoking or deciding soon.

Every tile is backed by real data with an honest empty state — there are no
decorative or dead tiles — and a red badge shows the total number of items
needing attention. (See the Home dashboard screenshot at the top of this page.)

### Six menus, named for what you do

The Manager folds its screens into **six top-level menus**, each item labelled
with a plain verb phrase and a one-line description of what it does — and what it
does not do.

![The six-menu navigation with the Access menu open](docs/img/manager-nav.png)
*Six top-level menus — Overview · Access · Pending changes · Jobs · Reviews &
controls · Audit & Settings — with the Access menu open and each item's
description. (Synthetic demo data.)*

| Menu | What lives under it |
|---|---|
| **Overview** | The Home dashboard and its attention tiles. |
| **Access** | The Access map, Look up a role, Create access (guided wizards), Change existing access, Admin accounts & TAP, Invite a guest or consultant, Departments & owners, and All records. |
| **Pending changes** | Check for problems (validation) and the Review & commit queue. |
| **Jobs** | Jobs & status, Engine logs & errors, and the Job schedule. |
| **Reviews & controls** | Review current delegations, Approvals, Drift: live vs desired, **Coverage & gaps** (what every workload has delegated and what it has not), Access reviews, Tenant conformance, Reports, Managed tenants, and on an MSP master the **Managed tenant registry** and **Replication overview**. |
| **Audit & Settings** | Audit trail, Settings, Newly discovered resources, Manager access & roles, Emergency access (break-glass), Mail templates, **Policy templates**, and Support. |

A **global search box** in the header jumps to any person, group, role, scope or
tag across the whole estate: a person or role opens its "who can do what" report;
a group, scope or tag focuses it on the Access map.

### See who can reach what — the Access map

The Access map renders your nesting as an interactive graph: admin → direct group
→ permission group → target (shown above in [The core idea](#the-core-idea-group-nesting)).
Pick a person and the board collapses to their transitive path. Beyond the
graph itself:

- **You can map from here, not only read.** Select the source — a person, a direct
  group or a permission group — then link it three ways, whichever suits you:
  **Ctrl+click** each target (⌘ on a Mac), **drag** one box onto another (only
  boxes that can accept it light up), or use the **➕ buttons in the toolbar**
  (*Give access*, *Add people*, *Add permissions*, *Give to a group*), which open
  a searchable list. Each pick adds one change and draws it as a dashed line, and
  nothing reaches the tenant until you commit on **Review & Save**. The map only
  ever adds — removing access lives on Maintenance & Revoke — and linking needs
  the Admin role.
- **The fourth column spells out the actual permissions.** Select any permission
  group or role group and **Permissions & Targets** shows exactly what it grants
  — Entra ID roles, AU-scoped roles and Azure RBAC at scope — with a short
  readable label and the full scope path on hover or click-to-expand.
- **Departments, organisation, project and cross-organisation groups** appear as
  direct groups on the map, alongside role and task groups.
- **Search gives a clickable result list and jumps you there.** People first,
  then groups, then roles and scopes; clicking a result centres and selects it so
  its full reach lights up.
- **A risk overlay shows what to clean up** — orphans, stale nodes and
  over-privileged principals, with the "unusually large" line learned from your
  own estate rather than a fixed number. Deleted principals are hidden by default.

### Create access the natural way round

The Manager turns "author a group by hand" into guided flows:

- **Target-first create wizard.** Pick **what** you delegate (an Entra service,
  an Azure scope, or a workload), then **where**, then the **roles**. The wizard
  derives the rest — the name, level, tier and plane — and previews exactly what
  your naming convention produces. Suggestion lists show every valid value on
  click, and the role picker hides roles that are already delegated.
- **Create an administrator** with a future creation date and a Temporary Access
  Pass start, or build a direct group of any type (role, task, process, project,
  cross-organisation, department).
- **Nesting follows Entra's rules.** A group nested into a role-assignable group is
  always **Eligible** (Entra refuses an Active membership there); an existing Active
  nesting of that kind is flagged with a one-click "Set to Eligible" fix.
- **Ready-made template packs** for Microsoft Defender XDR, Microsoft Sentinel,
  Intune, Exchange Online, Azure RBAC and common Entra ID roles — named and tiered
  correctly out of the box.
- **Change existing access** links, moves and removes people in groups and groups
  in permission groups, and the grid editors cover every record for power users.
  All of these only **prepare** changes — the engine remains the only thing that
  ever writes to your tenant.

### Pending changes — one queue, reviewed before commit

![Pending changes — a revoke, a TAP re-issue, an add and a change waiting for commit](docs/img/manager-pending-changes.png)
*Pending changes holds everything waiting to be committed — configuration
edits, revokes, TAP re-issues and session revokes — with who requested each
one and why. (Synthetic demo data.)*

- **One queue for everything.** Configuration edits, access revokes, TAP
  re-issues and session revokes all wait in the same place and are committed
  together or individually.
- **Nothing is lost on a reload.** Staged edits survive a page refresh and a
  Manager restart.
- **The badge counts only what needs you**, and a filter shows recent commits.
- **You land on the queue *and* your recent commits.** *(New in 2.4.369.)* A
  configuration or delegation change is saved the moment you commit it, but it is
  not a queued directory action — so the list used to show only the latter, and a
  successful commit looked like a lost one. The page now opens on both in one
  table with a **state** column: a committed configuration change reads **saved —
  the engine applies it on its next run**. The counter describes the rows in front
  of you and names anything it hides, and the commit's own report (added, removed,
  changed) stays on screen instead of being wiped by the next refresh.
- **A diff you can trust.** The preview is keyed by each row's natural identity,
  not its position — reordering rows correctly shows no change — and validation
  errors block the commit. A refused commit stays in the queue and lists the
  blocking errors in place.

### Drift — is the tenant what PIM says it should be?

![Drift — desired vs live per area, with missing, changed and extra items named](docs/img/manager-drift.png)
*Drift compares what PIM says should exist with what is live, per area — with
counts of missing, changed and extra items, each area expandable to the named
differences. (Synthetic demo data.)*

A background check compares the desired model with the live tenant every four
hours and stores the result, so the page opens instantly. Each area (admins,
groups, memberships, roles, administrative units, Azure) shows desired, live and
in-sync counts; expand a row to see each difference **by name** — for example an
admin who should be an eligible member of a group — rather than by object id. An
area that could not be checked says so instead of pretending to be clean. **Check
now** queues a fresh check.

### Review current delegations

![Review current delegations — the current assignments snapshot with its timestamp](docs/img/manager-standing-access.png)
*Review current delegations lists who holds privileged access right now — Entra
roles, Azure RBAC and PIM for Groups — from a snapshot stamped with its time.
(Synthetic demo data.)*

Standing access, the revoke view and the Home "expiring access" tile read from an
**active-assignments snapshot** refreshed every two hours, so they open instantly
even in a large tenant. **Refresh** queues a new read. Revoking is staged through
Pending changes and the row shows "revoke queued" until the engine has applied it;
break-glass accounts are protected and large batches require a second approver.

**Revoke selected says what it did.** *(New in 2.4.369.)* Every selected row is
checked before anything is staged; a row that genuinely cannot be addressed is
refused on its own, with the reason, while the rest still stage. A status line
beside the button is written on every outcome — working, staged *N*, refused *N*,
or the error in plain words — so the click can never end in silence, and the
confirmation says the rows are **staged**, not removed.

### Reports — "who can do what", and the reverse

The Reports view answers the two questions every access audit starts with,
instantly and with evidence to hand to auditors.

![Reports — "who can do what", showing a person's reachable targets and the exact granting path](docs/img/manager-reports.png)
*Reports answers "who can do what" (and the reverse): pick a person and see
every privileged target they can reach with the exact path that grants it
through the nested groups. Printable and CSV-exportable. (Synthetic demo data.)*

- **Pick a person → everything they can reach.** Every privileged target they
  can activate — Entra roles, AU-scoped roles and Azure resource roles — and, for
  each, the **exact path** that grants it through the nested groups.
- **Pick a role → who can activate it.** The reverse view lists everyone who can
  reach that role, again with the path, and honestly reports zero when nothing
  grants it.

### Role Lookup — the questions every admin asks about roles

![Role Lookup — who can activate a role, with the path that grants it](docs/img/manager-role-lookup.png)
*Role Lookup answers the role questions every admin asks — what a role can do,
which role to use for an action, who can activate a role, and how two roles
compare — typo-tolerant and read-only. (Synthetic demo data.)*

- **What a role can do** — a permission drill-down read live from the tenant,
  typo-tolerant ("did you mean…").
- **Find roles by action** — every role that grants an operation, **ranked
  least-privileged first**, with broad wildcards flagged and sorted last.
- **Who can activate a role** — every person, each with the exact granting path.
- **Compare two roles** — who can activate both versus only one, side by side.

### Validate — catch problems before they ship

**Check for problems** is a pre-flight rule engine: broken references,
tier/naming drift, orphans, stale or never-activated groups, missing owners,
admins without a phishing-resistant sign-in method, and Azure assignments pointing
at scopes that no longer exist. Every finding either has a one-click fix (or a
**Fix all**) or explains why it cannot be fixed automatically.

### Jobs and engine logs

![Jobs — engine logs and errors, with a failed run that later recovered and its log open](docs/img/manager-jobs-logs.png)
*Engine logs & errors lists every recent run newest first; a job that failed and
then ran cleanly shows as recovered, and each run's own log opens in place.
(Synthetic demo data.)*

- **Jobs & status** shows each scheduled job's cadence, last result and next run.
  **Run now** queues the job for the scheduler, so it runs with the same identity,
  lease and logging as a scheduled run.
- **Engine logs & errors** lists every recent run across all jobs: what is failing
  now and why, failures grouped by cause, and one-click fixes (such as "Remove this
  row" or "Make it Eligible") that are staged into Pending changes. A failure
  followed by a clean run is shown as **recovered** instead of failing, and
  acknowledging a job clears its standing failures.
- **The log is the run's own output** — the last three runs per job, with a live
  tail while a run is in progress.
- **Job schedule** explains, in plain words, when each job runs, which area it
  covers and whether it is on. The Home banner turns red when the engine itself is
  refused a permission.

### Audit and Support

- **Audit trail** — the full, searchable, append-only history: when, who, action,
  target, result, with before → after for changes. Engine actions are recorded with
  real group and role names and the job run that made them. Read-only and
  exportable.
- **Support** — a one-click self-check (database, Microsoft Graph and Azure, with a
  plain-language fix on each failure) plus a **sanitised diagnostics bundle** —
  secrets, certificates, tokens and full tenant/subscription ids are masked before
  the file is produced.

### Settings — your operational policy in one place

Settings keeps the operational defaults in one place, saved to the same database
the engine and jobs read — so what you see is what the system actually uses.

![Settings — Manager access and roles, emergency override and naming conventions](docs/img/manager-settings.png)
*Settings holds Manager access & roles, the emergency override, naming
conventions, feature customization, template packs and mail templates — all
stored in the database. (Synthetic demo data.)*

- **Manager access & roles** — who may read, change or administer the Manager.
- **Operational policy** — activation and eligibility durations, require-MFA on
  activation, and connection checks; invalid entries are rejected or clamped with
  an explanation, never silently dropped.
- **Naming conventions** with a live preview of what each pattern produces, and a
  configurable admin word.
- **Departments and approvers**, **AD OU placement**, **alerting**, **feature
  customization**, **template packs** and **mail templates**.

### Export everywhere

Reports, the Access map, Validate, Access reviews and the Audit trail each carry
**Export CSV** and **Print**. Exports are spreadsheet-safe — values that could be
read as formulas are neutralised — and print produces a clean, titled, date- and
tenant-stamped page.

See **[tools/pim-manager/README.md](tools/pim-manager/README.md)** for the full
Manager docs.

---

## The PIM Activator (browser extension)

The PIM Activator is a browser extension for **Edge and Chrome** that turns
activating your privileged access from N portal navigations into **one click**.
The admin clicks the toolbar icon, ticks the PIM groups they need from a
checkbox list, enters a justification and duration, and clicks **Activate** —
done.

- **One-click bulk activation.** It covers eligible Entra roles, Azure RBAC and
  group-based access, and **expands the nesting**: activating one role group folds
  out the permission groups inside it and everything they grant, so a single
  activation lights up the admin's whole job-function access surface.
- **See and manage what's active.** A **My Access** tab shows what's currently
  active with a live expiry countdown, favourites, and single or bulk
  self-deactivation — and it hides empty categories so you only ever see what you
  actually have.
- **A confirm step for large activations.** When you activate several roles at
  once, the button asks you to click again to confirm — a quick guard against an
  accidental over-elevation. Small selections activate straight away, and the
  threshold is an **administrator setting per tenant** (lower it for caution,
  raise it for power users), never left to individual users.
- **"Show roles" — see what a group actually grants before you activate it.**
  Expand any row and the real permissions behind it are read live from the
  platform: directory roles (tenant-wide as well as administrative-unit scoped),
  Azure resource roles, and workload permissions — both what you already hold and
  what you are eligible for. Because privileged access is usually packaged as a
  group inside a group, it follows those links in **both** directions — the groups
  nested inside the one you picked and the groups it is itself a member of — so
  nothing granted through nesting is hidden.
- **Activation reports "done" when the access is really there — never on a
  stopwatch.** Access does not arrive instantly: the request is accepted at once
  and the platform then fans the permissions out through nested groups, which can
  take anywhere from seconds to several minutes. The extension keeps checking what
  you actually hold and reports completion only once it has *observed* the access.
  A fast activation finishes fast, a repeat of a set you have used before finishes
  immediately, and a slow one is honestly reported as still in progress rather
  than declared done too early.
- **Deactivation is quick.** Once your membership is removed the access is already
  being torn down, so you are released immediately instead of waiting on the
  directory's slower cleanup — while a group that fans out to others still
  confirms those are gone first.
- **A one-time getting-started tip** points new users at bulk-activate and My
  Access, and never comes back once dismissed.
- **Simple, secure sign-in** uses the browser's built-in flow — no extra software
  to bundle — with a first-run onboarding wizard when nothing is configured yet.
- **Works for one tenant or many.** Point it at a single tenant for a silent
  experience, or publish a multi-tenant catalog centrally so admins get a tenant
  switcher.
- **Fleet-friendly deployment.** Ship it to managed devices through Intune, or
  straight to the browser policy on non-managed boxes (per-machine or per-user),
  with automatic updates from a published feed and self-healing recovery for the
  rare case a browser marks the extension corrupted.

See **[tools/pim-activator/README.md](tools/pim-activator/README.md)** for the
full deployment matrix (Intune, non-Intune client, multi-tenant catalog,
conflict handling and backend setup).

---

## Supported setups — pick the shape that matches you

PIM4EntraPS supports **six setups**. They differ in three things only: **who runs
it** (one organisation for itself, a service provider for the customers it looks
after, or a tenant that provider looks after), **where the platform itself runs**,
and **where its updates come from**. In every setup the portal, the engine and the
database run in a tenant you can point at, and the model they apply lives in that
environment's own database.

| Setup | Who runs it | Where the platform runs | Where updates come from |
|---|---|---|---|
| **Single tenant — on our release** | One organisation, for its own tenant | That tenant's own subscription | Our release channel — the environment updates itself, overnight |
| **Single tenant — community (free)** | One organisation, for its own tenant | That tenant's own subscription | The public repository — you pull the new version and re-run the one-command install |
| **Provider (managing tenant) — on our release** | A service provider, for the customers it looks after | The provider's own tenant | Our release channel |
| **Provider (managing tenant) — community** | A service provider, for the customers it looks after | The provider's own tenant | The public repository |
| **Managed tenant — hosted by the provider** | A customer a provider looks after | Portal and database in the **provider's** tenant, governing the customer's directory | From the provider, by replication ring |
| **Managed tenant — hosted in its own tenant** | A customer a provider looks after | Portal and database in the **customer's own** tenant | From the provider, by replication ring |

- **Single tenant** is the simplest shape: portal, engine, database and the
  directory being governed are all one tenant. There is no provider and nothing
  crosses a tenant boundary. This repository is the **community** one — free for a
  single tenant, installed and kept current by you.
- **Provider (managing tenant)** adds the provider half on top of a single-tenant
  installation: define once centrally, sign the definition set, and roll it out to
  customers in waves. The provider's own tenant is governed the same way as any
  other.
- **Decisions travel with the definitions.** Revoking a person's sign-in sessions on
  the provider can revoke them in every managed tenant too, and removing a replicated
  administrator asks whether to remove it in all managed tenants, the ones you pick,
  or none. Each tenant carries out only what names it, once, without a per-tenant
  approval — which matters most when someone leaves.
- **A managed tenant is a real environment, not a remote-control session.** It has
  its own engine, its own model and its own database, and it **pulls** the signed
  definition set from the provider — the provider never reaches into it and never
  pushes anything. The two hosting choices differ only in where the portal and the
  database live: in the provider's tenant (so the provider runs the infrastructure
  for the customer), or in the customer's own tenant (so the customer does).
- **You can start alone, be taken on later, and leave again.** A tenant that starts
  on its own can be brought under a provider afterwards, and a managed tenant can be
  detached at any time. Detaching removes the provider's synced administrators and
  nothing else: **the definitions stay in that tenant's own database**, so the
  environment keeps running and keeps governing exactly as before. Nothing has to be
  handed back, and nothing stops working.

See **[docs/DESIGN.md §11.8](docs/DESIGN.md)** for the per-setup topology and
process diagrams.

---

## How updates reach an environment — the two ring systems

PIM4EntraPS uses **rings** in two completely different places, and it is worth
keeping them apart. One decides **which version of the software** an environment
runs. The other decides **which definitions reach which managed tenants**.

> **They are independent.** A managed tenant's software version and the rings that
> decide which definitions reach it are separate controls, set separately and
> changed separately. Moving a tenant to a later software version does not change
> which definitions it receives, and moving a definition to a wider ring does not
> change any tenant's software version.

### The software ring — which version an environment runs

- **A version reaches a ring only when it is approved for that ring.** Approving is
  a deliberate act by whoever maintains the release. Building a version, publishing
  it, or approving it for one ring never moves it into another.
- **Nothing is pushed.** Each night the environment **asks** which version its own
  ring approves, fetches that version, builds it in its **own** container registry
  and rolls to it. Nothing connects into the environment from outside to update it.
- **An environment never moves backward.** *(New in 2.4.368.)* Before it builds
  anything, the environment compares the version its ring approves with the highest
  version it is known to have reached, and refuses to go backward — naming both
  versions and the ring that proposed the older one. A deliberate rollback has to be
  switched on for that environment, and a run that uses it says so.
- **It never moves to a version nobody approved.** If the release channel cannot be
  read, or the environment's ring names no version, the environment stays exactly
  where it is — it never falls back to "whatever is newest".
- **A held environment does not move at all.** Holding an environment is a supported
  state, not a failure, and it is reported as such.
- **The ring you configure is the ring you get.** *(New in 2.4.368.)* The ring is
  read back off the deployed environment and the installation fails if it is not the
  one that was asked for.
- **The Manager shows the ring the environment is on.** *(New in 2.4.369.)* The ring
  appears beside the mode badge in the header — flagged only when it is behind, held
  or the last update failed — with an **Updates & ring** panel under Jobs giving the
  version running now, the version the ring approves, the last run and the last
  success. Each update records its own run into the environment's database, so an
  environment that has not updated yet shows "not recorded yet" rather than a guess.
  The panel is read-only: moving a ring stays a deliberate act on the update job.

### The replication ring — which managed tenants a definition reaches

*This applies to a provider and the tenants it looks after. A single-tenant
installation has no replication ring.*

- **Three rings, in the same order as the software rings: 0 = dev, 1 = test, 2 = broad.**
  *(New in 2.4.388; the order used to be the reverse.)* Every managed tenant sets its
  own ring, and every definition row carries one. A row reaches the tenants whose ring
  is at or **below** its own: a new administrator starts on ring 0 and reaches the dev
  tenants only, is promoted to ring 1 to add the test tenants, and to ring 2 to reach
  every tenant. Existing rows and tenants were converted on upgrade, so each row
  still reaches exactly the tenants it reached before.
- **Tags belong to the ring, not to the row.** The provider names each ring and can
  narrow it with a tag rule — for example *test = only the tenants tagged
  `wave:pilot`* — once, on the ring. Tags joined into one term mean *all of these at
  once*. A tenant that set itself to a ring but does not match that ring's rule
  receives nothing ring-gated until it does. Tags live in the tenant record the
  provider keeps and travel inside the signed set, so a tenant cannot tag itself
  into scope.
- **The ring is never the whole answer.** A row reaches a tenant only when it is
  marked for replication at all **and** the ring admits the tenant. A row can also
  be marked as never leaving the provider at all. A per-row target set before
  2.4.388 still applies and is shown as one to move onto the ring.
- **A row the ring does not admit is withheld, not retracted.** The tenant simply
  does not receive it, and **whatever that tenant already holds is left exactly as it
  is**. Widening the ring later releases it; nothing is taken away in the meantime.
  Withdrawing access that a tenant already has is a separate, deliberate act that is
  **off by default**, reports what it would do before it does anything, and stops
  rather than exceeding a safety limit.
- **Nothing silently half-arrives.** If a row that *is* reaching a tenant depends on
  another row that the ring or the target would have excluded, the dependency is
  included anyway — and the run says so, naming the row, what needed it and which
  tenant.
- **You can see it before you send it.** The provider's Manager shows, per row, how
  many tenants it will reach and which ones, and per role which tenants it is
  **withheld** from and *why* — whether that is the ring, the target, the
  relationship policy or something the customer has switched off. The preview runs
  the same plan the managed tenant itself runs, so it is not a separate estimate.
- **This is how a provider rolls a change to one wave of customers before the rest**
  — and it is a separate control from the software ring above. Both now run in the
  same order (ring 0 first, ring 2 last and widest), but one never implies the other:
  a tenant's software ring and the ring it receives definitions on are set
  separately.

---

## Editions — what is free and what is paid

The line is simple: **the community edition is free for a single tenant**, and a **Pro licence** adds a
set of advanced single-tenant capabilities and the whole multi-tenant half. From v2.4.380 the product
**enforces** this: a Pro capability without a valid licence is switched off in the engine, the scheduled
jobs and the portal, and the portal says why. Everything in the free edition keeps working whatever the
licence state.

### Free — the community edition, for a single tenant

Everything an organisation needs to govern its own tenant:

- the full **portal** — model, review, commit, and see what changed;
- **eligible, time-boxed access** with approval and a complete audit trail;
- **Entra ID roles, PIM for Groups, administrative units and Azure RBAC**;
- **Intune and Defender XDR** role delegation, including Defender custom roles;
- **delegation by group** — permission groups and tiering, so access is granted by
  membership rather than by hand;
- **policy templates** — a Standard and a RequireApproval template per kind, renameable, with a default per kind;
- **drift detection** — what exists in the directory versus what your model says;
- **reports**, including standing access and expiring access, and the **current delegations** list;
- **administrator accounts and first-time access passes**, issued and tracked;
- **permission templates imported by script** (`Import-PimPermissionTemplate.ps1`) and tenant preparation from one
  configuration file (`Invoke-PimTenantPrep.ps1`);
- **self-updating from the public release**;
- **community support**.

### Pro — licensed capabilities for a single tenant

On top of the free edition, a Pro licence adds:

- **Coverage & gaps and discovery** — what is and is not delegated through PIM across every workload, and the
  scheduled jobs that find new roles, groups and resources;
- the **other workload connectors** — Power BI, Exchange Online, enterprise-app roles, Azure DevOps, Dataverse,
  Business Central and Power Platform;
- **revoking current delegations** from the portal (the list itself is free);
- **access reviews** — campaigns with decisions recorded and enforced;
- a **second approver** for sensitive changes (separation of duties);
- **delegated administration** — portal users limited to a tier, level, service or scope;
- the **tier-impact report** — everyone who can reach tier 0, including through nested groups;
- the **evidence export** — who may hold what, who held it, and who approved.

> ⚠️ Without a licence, the second approver is switched off too — sensitive changes then need one administrator,
> not two. Install the licence before you rely on it.

### Pro — the multi-tenant half

For a service provider, or any organisation running more than one tenant:

- **define once, target many** — target tenants by tag and by rollout wave rather
  than editing each tenant;
- **signed definition sets, verified on arrival** — a tenant applies a definition set
  only if it verifies against a key that tenant trusts;
- **see what reaches each tenant and what is held back**, per definition;
- **per-customer rules** where one customer must differ;
- **a read-only preview** of exactly what a tenant would receive, before it does;
- **fleet conformance** — which tenants are on which version of which definition set;
- **rollout waves** — reach one wave of customers before the rest;
- **central accounts whose lifecycle flows down** to the tenants they belong to;
- **removals remain the tenant's call** — the provider proposes, the tenant disposes;
- **controlled release rings** for the software itself;
- **the provider-hosted option** — the provider runs the portal and database for the
  customer;
- **support with an agreed response time**.

A managing (master) or managed (slave) tenant **requires** a Pro licence: without one, its publishing and
downlink jobs refuse to run and the portal shows a red banner on its MSP pages.

### How licensing works

- **A licence is one signed file.** It names you, the edition, the capabilities, the tenants it covers and the
  dates it runs between.
- **Verified offline.** The environment checks the signature against a key built into the product — no
  activation server, no call home, no internet needed.
- **Bound to your tenants.** A licence that names tenants is valid only there.
- **Gentle expiry.** After the end date a grace period keeps the licensed capabilities running with a warning;
  only afterwards do they switch off. The free capabilities are never affected.
- **Settings › Licence** in the portal shows the status, the customer, the valid-until date and the tenant it is
  bound to, and which Pro capabilities are on.

**Register a licence — in the portal.** **Settings › Licence › Register a licence**: pick the issued licence
file, or paste its contents, and save. It is checked against the signing certificate **before** anything is
stored, so a file that does not verify is refused, nothing is written and the page says so. Registering needs
the senior-administrator role and is recorded in the audit trail.

**Or from a shell**, if you hold the environment's own database credentials (the application id and certificate
below are **your** deployment's, not the vendor's). It is stored in the environment's database, verified first
and read back:

```powershell
pwsh -File tools\setup\Set-PimLicense.ps1 -LicensePath <file> -SqlServer <server>.database.windows.net `
     -TenantId <tenant> -AdminAppId <app id> -AdminCertThumbprint <thumbprint>
```

The running portal and jobs pick it up on their next start.

### Defaults in this release

What an environment does before anyone changes a setting (the full table is in
[DESIGN.md › Defaults in v2.4.380](docs/DESIGN.md#19b-defaults-in-v24380--what-an-environment-does-before-anyone-changes-a-setting)):

- **Always on (free):** the engine, the delegation map and Review & Save.
- **Off until you switch them on (free):** email alerts, Teams / webhook alerts; scheduled jobs are switched on by the
  hosted deploy.
- **Switch themselves on when you have rows for them:** the Intune + Defender XDR connectors (free) and the
  app-role / Azure DevOps / Dataverse / Business Central / Power Platform connectors (Pro).
- **Pro, on when licensed:** Coverage & gaps, revoke, access review campaigns, delegated administration, the
  tier-impact report and the evidence export. **Pro, off until switched on:** the second approver, discovery,
  Power BI, Exchange Online, and MSP.
- **Policy templates:** `Groups_Standard`, `EntraIDRoles_Standard` and `AzureRoles_Standard` are the defaults per kind.
- **Workload assignments:** groups are always created; a new Intune / Defender / Power BI / connector assignment waits
  until that workload's prerequisites are green; Azure waits only when a check found a problem.
- **Prerequisite results** are re-checked after 30 days (they keep working meanwhile); **licences** have a 30-day grace
  period unless the licence says otherwise.

### Getting a licence

**Mail [mok@mortenknudsen.net](mailto:mok@mortenknudsen.net) for a Pro licence** — for the advanced single-tenant
capabilities, or for the multi-tenant edition. The terms that apply to this code are in **[LICENSE](LICENSE)**.

---

## Getting started — install the community edition

The community edition installs **into your own Azure subscription** with one
command. What you end up with:

| Component | What it is | Why it is cheap |
|---|---|---|
| **PIM Manager** | an Azure Container App behind Microsoft Entra sign-in | scales to **zero** when nobody is using it |
| **Engine** | one scheduled Container Apps job (every 5 minutes) | runs for seconds, then stops |
| **Database** | Azure SQL (S0), passwordless (managed identities only) | the one always-on part |
| **Registry + logs** | Azure Container Registry (Basic) and a Log Analytics workspace | builds the image from your clone |

Everything is created in **one resource group** you name. To remove the
installation, first run `.\tools\setup\Remove-PimContainerStack.ps1 -SubscriptionId
<subscription-id> -ResourceGroup <rg> -Apply` — it removes the containers **and** the
subscription-level role assignments their identities were given, which a
resource-group delete alone leaves behind — then delete the resource group, and
finally the two app registrations (the Manager sign-in and the deploy identity).

### What you need

- A **Windows** machine with **PowerShell 7**, run **as Administrator** (the deploy
  identity's certificate is placed in the machine certificate store), plus
  **Azure CLI** and **git**.
- An Azure **subscription** in the tenant you want to govern.
- A sign-in that is **Global Administrator** (or Privileged Role Administrator +
  Application Administrator) in the tenant **and Owner** of the subscription. It is
  used once, in step 2, to create the deploy identity; everything after that runs
  as that identity with a certificate.
- The UPN of the person who should administer the Manager.

### 1. Get the code

```powershell
git clone https://github.com/KnudsenMorten/PIM4EntraPS.git
cd PIM4EntraPS
```

### 2. Create the deploy identity

```powershell
az login --tenant <tenant-id>
az account set --subscription <subscription-id>

$id = .\tools\setup\New-PimDeployIdentity.ps1 -TenantId <tenant-id> -SubscriptionId <subscription-id> -GrantGraph -Apply
```

This creates an app registration with a **certificate** (never a secret), gives it
Owner on the subscription, and — with `-GrantGraph` — the seven Microsoft Graph
application permissions the deploy needs: to grant the Manager and engine their own
permissions (`Directory.Read.All`, `AppRoleAssignment.ReadWrite.All`,
`Application.Read.All`), to create the database administrators group
(`Group.Create`, `GroupMember.ReadWrite.All`) and to consent the Manager's
sign-in (`DelegatedPermissionGrant.ReadWrite.All`), and to give itself a short,
time-bound Exchange Administrator role while it creates the notification mailbox
(`RoleManagement.ReadWrite.Directory`). It proves the identity can sign in and read the directory
before it returns. It is safe to run again.

### 3. Deploy everything with one command

```powershell
.\tools\setup\Invoke-PimDeployAll.ps1 -Scenario S2 -Apply `
    -TenantId <tenant-id> -SubscriptionId <subscription-id> -Location swedencentral `
    -AdminAppId $id.AppId -AdminCertPem $id.PemPath `
    -SqlAdminClientId $id.AppId -SqlAdminCertThumbprint $id.Thumbprint `
    -PrereqToken <short-name> -PrereqVnetAddressPrefix 10.231.0.0/22 -PrereqSubnetAddressPrefix 10.231.0.0/23 `
    -ResourceGroup rg-pim -VnetName vnet-pim -VnetResourceGroup rg-pim `
    -AcrName <globally-unique-acr-name> -EnvName cae-pim -LogAnalyticsWorkspaceName law-pim `
    -SqlServerFqdn <globally-unique-sql-name>.database.windows.net -SqlDatabase PimPlatform `
    -SqlConnectionString 'Server=tcp:<globally-unique-sql-name>.database.windows.net,1433;Initial Catalog=PimPlatform;Encrypt=True;TrustServerCertificate=False;Connection Timeout=60;' `
    -Exposure external -WorkerMode cron -ManagerMinReplicas 0 -AcrSku Basic `
    -ManagerSuperAdmins <your-upn> -EasyAuthAllowedPrincipals <your-upn> -SkipAppReg
```

Run it **without `-Apply`** first to see the plan — nothing is changed. With
`-Apply` it runs, in order and idempotently: hosting prerequisites (resource group,
network, registry, logs, SQL server), the Manager image build from your clone, the
Container Apps environment with the Manager and the engine job, database access
and schema, the feature baseline, Entra sign-in in front of the Manager, and the
Manager administrators. Allowed regions are West Europe, Denmark East and Sweden
Central.

**Who may sign in is required.** `-EasyAuthAllowedPrincipals <upn-or-group>[,...]`
admits exactly those accounts or groups (assignment required). A new Manager is
never deployed open to the whole tenant: without this parameter (or
`-EasyAuthAllowAllTenantUsers`, which admits every member account, never guests)
the deploy refuses before it builds anything, and the plan says so.

Optional additions:
- `-Exposure internal` builds a **private-only** environment instead; decide this on
  day one, because an environment's exposure cannot be changed after creation.
- `-AzureRbacRoles 'User Access Administrator'` lets the engine manage Azure
  resource PIM, not just read it.
- `-MailSender <shared-mailbox-upn>` sends notification mail and access passes
  (requires an Exchange Online plan).

### 4. Sign in and verify

The deploy prints the Manager's address. Open it, sign in with the administrator
you named, and check that:

- the header shows the **database (SQL) mode** and the version you deployed;
- **Jobs › Engine logs & errors** shows the engine job's runs completing;
- **Support › Run checks** is green for the database, Microsoft Graph and Azure.

Then build your model in the Manager (or import an existing one) and commit — the
engine applies it on its next run.

### Keeping it up to date

One command brings the installation to the latest release:

```powershell
.\tools\setup\Update-PimCommunity.ps1            # shows which version it would move to, and the plan
.\tools\setup\Update-PimCommunity.ps1 -Apply     # updates
```

A successful step 3 saves the parameters it ran with (never a secret) on the machine
that ran it, and prints where. The updater pulls the latest release from GitHub
(fast-forward only; a clone with local changes is left alone and the update stops),
then re-runs the deploy with those parameters. A re-run **is** the updater: every
step that is already current is skipped, and only what changed is rebuilt and rolled.

The database schema is upgraded additively before the new version rolls, and a
failed health check rolls the Manager back to the previous version. (The unattended
in-cloud updater used by subscription environments needs a published release feed,
so the community edition updates on your schedule, from GitHub.)

An environment that updates itself does so **only forward**: before it builds
anything it compares the version its release ring approves with the highest version
it is known to have reached, and refuses to move backward — naming both versions and
the ring that proposed the older one. A deliberate rollback has to be switched on for
that environment, and a run that uses it says so. And the release ring you configure
is the one you get: it is carried through to the update job, an installation that
names no ring is told which default it is getting, and the installation reads the
ring back off the deployed job and fails if it did not take.

### What it costs to run

The on-demand shape is deliberately small: the Manager costs nothing while idle
(scale to zero), and the five-minute engine job normally fits inside Azure Container
Apps' monthly free grant. The recurring cost is essentially the **Azure SQL S0
database** and the **Basic container registry** — a few tens of US dollars a month
at list price, depending on region, plus Log Analytics ingestion. Check current
prices for your region before you deploy.

---

## Hosting & containers

**One configurable image** runs as the Manager, the scheduled engine job and any
maintenance job — you tell each instance which role to take on. It is headless and
safe by default: managed-identity authentication, no interactive prompts, no
secrets baked into the image, and it carries no customer data (identity, database
and configuration are supplied at run time).

- **On-demand by default.** One scheduled engine job decides on each run what is
  due (incremental scopes, queued changes, reminders, discovery, the daily full
  reconcile), and a single-runner lease means an overrunning run is skipped, never
  doubled. A five-minute schedule reacts faster than an always-on worker would.
- **Exposure is your choice.** The Manager is always behind Microsoft Entra sign-in
  and the install verifies that before it finishes. It is internet-reachable by
  default so it can be opened from anywhere you sign in; an internal-only
  environment on your own network is supported for private designs.
- **Passwordless everywhere.** The Manager's and engine's managed identities are
  granted exactly the database, Microsoft Graph and Azure permissions they need by
  the deploy itself, and re-granted if an app is ever recreated.

See **[docs/DESIGN.md §11–12](docs/DESIGN.md)** for the full hosting and container
topology.

---

## MSP variant

For consultancies managing many customer tenants, the model is **pull, never
push** (the multi-tenant half is the paid edition — see
[Editions — what is free and what is paid](#editions--what-is-free-and-what-is-paid)):

- **Each customer pulls a signed baseline** into its own database — the provider
  never writes to the customer tenant, and customer data never leaves it.
- **The acting identity is always local.** Each customer tenant has its own
  identities, so the customer owns its Conditional Access, its audit attribution,
  its lifecycle and instant revocation. There is no GDAP and no foreign multi-tenant
  identity.
- **Signed, not encrypted; no secret at the receiver.** The provider signs each baseline with a
  non-exportable key in its own key vault, from a scheduled job in its own cloud environment — no
  management server, no certificate on disk. Each customer verifies the signature against the key
  identifier it has chosen to trust; tamper, forge, roll-back, replay and an untrusted key are
  rejected, and the customer can read exactly what is shipped.
- **Signed file, private where it can be, nothing expires.** Customers on a private network connected
  to the provider's read the baseline through a private endpoint (no public access); others read that
  one file anonymously from the networks the provider names. Trust comes from the signature, never the
  network, and there are no expiring links or shared credentials to renew.
- **Change keys without an outage.** A customer can trust several provider keys at once, so a key
  change is announced first and switched second.
- **Per-admin sync, tag-scoped.** Each provider administrator states whether, and
  to which tagged managed tenants, it is synced; the Manager shows each tenant's
  mode.
- **Instant kill-switch with CISO opt-in.** A separately signed central-kill
  instruction can disable a specific privileged account across every managed
  tenant — applied locally by the customer's own engine through the same audited
  path as any other change.
- **Deploy with a signed-in administrator.** The provider and each customer are built with one command
  each, either as a certificate-based deployment identity or as an administrator's own sign-in.

See **[docs/DESIGN.md §13](docs/DESIGN.md)** for the full MSP architecture.

---

## By the numbers

Counted for version 2.4.359, over the files that ship in this repository:

| | |
|---|---|
| Files in the repository | 490 |
| Lines of code (PowerShell, HTML, JavaScript, SQL, Bicep) | **152,330** |
| &nbsp;&nbsp;of which PowerShell | 127,224 lines in 338 files |
| Documentation (Markdown) | 10,752 lines |

| Area | Code files | Lines of code |
|---|---:|---:|
| Engine | 115 | 72,727 |
| PIM Manager | 7 | 32,010 |
| Setup, deploy and update | 55 | 20,770 |
| PIM Activator | 30 | 13,266 |
| v1-compatible launchers and reference engines | 92 | 7,467 |
| Configuration, templates, connectors and other | 30 | 3,160 |
| Bundled shared modules | 37 | 2,605 |
| Database schema | 4 | 325 |

The automated test suites that gate every release (232 test scripts) are maintained upstream and are not part of this repository.

---

## Repo layout

```
PIM4EntraPS/
  engine/
    _shared/                  # engine core, providers, scheduler, store, shared library
  tools/
    setup/                    # one-shot deploy (Invoke-PimDeployAll), deploy identity, hosting, updates
    pim-engine/               # engine and job entry points
    pim-manager/              # the Manager (browser SPA + server) and its container image
    pim-activator/            # Edge/Chrome extension (bulk activation) + deployment
    pim-scheduler/            # scheduler helpers
  setup/                      # engine app registration, v1 import, MSP baseline tooling
  config/  config-local/  config-msp/   # locked defaults + *.custom.sample.* templates
  sql/                        # idempotent schema
  templates/                  # admin, mail and policy templates
  workloads/                  # workload connector definitions
  launcher/  legacy/          # v1-compatible launchers and reference engines
  docs/                       # FEATURES.md · DESIGN.md · img/
  FUNCTIONS/                  # bundled shared PowerShell modules
  README.md  RELEASENOTES.md  LICENSE  VERSION
```

---

## Documentation

- **[docs/FEATURES.md](docs/FEATURES.md)** — the catalog of delivered features,
  grouped by area, in plain language.
- **[docs/DESIGN.md](docs/DESIGN.md)** — how it works: nesting, delegation, naming,
  tier model, hosting, MSP, data model, connectors, lifecycle and governance.
- **[RELEASENOTES.md](RELEASENOTES.md)** — what changed in each release, newest
  first, with upgrade notes.
- **[tools/pim-manager/README.md](tools/pim-manager/README.md)** /
  **[tools/pim-activator/README.md](tools/pim-activator/README.md)** — per-tool
  documentation.

---

## Versioning

Semver-ish: `MAJOR.MINOR.PATCH`.

- `MAJOR` — breaking layout / schema / contract change.
- `MINOR` — additive engine or tool.
- `PATCH` — fix / doc / workflow polish.

Each release of this repository carries a `vX.Y.Z` tag and a GitHub release with a
zip of the same content.

---

## Support / contributing

Issues and pull requests are welcome on GitHub. For production deployment help
(privileged-workstation rollout, AD trust setup, multi-tenant), contact the
maintainer.

Author: see the project's GitHub repository.
