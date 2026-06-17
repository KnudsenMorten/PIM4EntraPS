# PIM4EntraPS — delivered feature catalog

This is the delivered feature set of **PIM4EntraPS**, written in plain language for IT
admins and customers. Everything listed here is built and verified. It is grouped by
area and is safe to share publicly. (Status as of 2026-06-14.)

PIM4EntraPS is a privileged-access governance solution for Microsoft Entra. It models
your privileged delegation as nested groups, applies the right PIM policies, and keeps
everything in sync from a single source of truth — without ever standing up a public
endpoint or leaving credentials lying around.

---

## 1. Hosting / Runtime
- **Run it where it fits you.** The Manager can run centrally for the whole team, or
  locally on an admin's PC straight against the database — no central web server
  required. A break-glass loopback edition runs on a client PC for the times your
  hosted plan is unavailable, so senior admins are never locked out.

## 2. Containers
- **One image, many roles.** A single configurable engine image runs as manager,
  scheduler, engine, connector, queue worker or discovery job — you simply tell each
  instance which roles to take on. No separate images to build or keep in lock-step.
- **Each worker does only its assigned jobs.** You scope every running worker to the
  job types it should handle, run a single pass on demand, or preview changes without
  applying them.
- **Headless and safe by default.** Containers authenticate using a managed identity —
  no interactive prompts, no secrets baked into the image, and diagnostics that work in
  a fully unattended environment.

## 3. Setup / Deploy
- **One command to stand up — or update — the whole solution.** A single "deploy
  everything" entry brings up (or updates) the entire solution for an environment in the
  right order: it makes sure the engine identity and its permissions exist, stands up the
  hosting (containers or a server host), brings the database schema up to date safely, then
  builds and deploys the latest app — and finally proves the result with an automated
  validation. ✅ 2026-06-16
- **Safe to run again any time.** The same command is both the installer and the updater:
  anything already in the desired state is skipped, so re-running it only fixes what has
  drifted. A preview ("what would happen") mode is the default, so you always see the plan
  before anything changes.
- **Proves itself, and undoes a bad deploy.** After deploying, it runs a live check of the
  running app plus a tenant validation; if that fails, it automatically rolls the app back
  to the previous known-good version and reports exactly what happened. A validation-only
  mode re-checks an existing environment without changing anything.
- **Repeatable, script-driven setup.** Deployment runs through setup scripts (container,
  VM, and MSP variants) rather than manual clicking, so every environment comes out the
  same way.
- **Database access without passwords.** When using a managed identity against the
  database, setup wires up the correct passwordless access automatically.
- **Permissions granted for you.** Setup assigns each worker identity the exact directory
  permissions the engine needs, so it works on first run instead of failing on access.

## 4. MSP
- **Pull, never push.** In a managed-service setup, the provider never reaches into or
  writes to your tenant. Each tenant pulls a signed baseline into its own local database;
  your data never leaves your tenant and your local IT keeps full autonomy.
- **Per-tenant isolation.** Each customer has its own data store with no cross-customer
  visibility, while the provider keeps only the central template.
- **One engine image, mirrored into your own registry.** ✅ 2026-06-15 The engine container
  is built once by the provider and **mirrored directly into your own container registry** —
  a server-side registry-to-registry copy, so nothing is rebuilt per customer and no image
  bytes travel through an intermediate host. The image carries **no secrets and no customer
  data** (identity, database and configuration are all supplied locally at run time).
- **Choose the sync model that fits your governance.** ✅ 2026-06-15 You are not forced into a
  single managed-service shape. Pick how the central template reaches your tenant — pull a
  signed baseline, pull a versioned template by rollout ring, read the central template
  read-only at run time, emit a signed status summary back to the provider, or run fully
  autonomously with the provider delegating to your local IT. **Every** option is initiated
  by your own tenant (pull, never push), and the platform refuses any configuration that
  would let the provider write into your tenant or let your data leave it.
- **Signed baseline with an instant kill-switch.** ✅ 2026-06-15 The baseline you receive is
  cryptographically signed; your environment verifies the signature before applying anything,
  so a tampered or forged baseline is rejected. If a signing key is ever compromised, the
  provider **revokes it** and your environment immediately stops trusting anything signed by
  it. A separately **signed central-kill instruction** lets an authorized owner disable or
  revoke a specific privileged account across every managed tenant at once — applied locally
  by your own engine through the same audited, authorized path as any other change (never a
  back-door write from outside).
- **One shared platform for related tools.** ✅ 2026-06-15 The tenant/application registry is
  shared and **keyed by product**, so companion tooling (such as tenant management) reuses the
  exact same registry, authentication and storage model rather than a separate parallel
  system — fewer moving parts, one consistent security posture.

## 5. SQL / Data
- **Single source of truth in SQL.** Configuration, settings, access rules and delegation
  profiles all live in the database — no scattered files or shares to keep in sync.
- **Passwordless database auth.** Cloud databases use Entra/managed-identity authentication
  only (no SQL logins or stored passwords); on-prem uses integrated Windows auth.
- **One consistent data path for the app.** The Manager reads and writes through a single
  database-aware layer, shows you which database you're connected to, and lets you switch
  between databases from a dropdown.
- **Run against a local database with zero extra setup (development).** ✅ 2026-06-14 For
  development and management-server inner-loop work, the engine can read its desired
  configuration from a **local database** using the signed-in machine identity — no cloud
  connection, no separate database login, no token juggling; just point the engine at the
  local instance and run. (The single authoritative store in production — and for break-glass
  — is always the cloud database; the local instance is a developer convenience.)
- **Guided one-time database cutover.** ✅ 2026-06-14 Moving an existing instance onto the
  database is a **guided, step-by-step ceremony** in the Manager — never a risky one-shot
  switch. It runs in order: a read-only **pre-check** (connectivity + a report of exactly what
  the upgrade will change), a **one-time schema upgrade**, a **transactional import** of your
  existing configuration (all-or-nothing — a failure leaves the store exactly as it was), a
  flip of the configuration source to the database, a **re-check** against the now-populated
  store, and finally an **explicit "Finalize Cutover" confirmation**. Every imported entity
  and row count is recorded for audit, each step is gated on the previous one, and re-running a
  step is safe. The cutover **refuses to finalize onto a development/local database** — only
  the cloud database may become authoritative.
- **Your existing configuration migrates without being touched.** ✅ 2026-06-14 The migration
  reads your current configuration **read-only** and brings it up to the current shape on the
  way in (adding any missing fields, retiring obsolete ones) — your existing files are never
  modified or written back.
- **Changes recompute on their own.** ✅ 2026-06-14 When the configuration in the database
  changes — from the Manager, from another management node, or edited directly — the platform
  notices and **automatically schedules a recalculation** so the live environment reconciles to
  the new desired state without anyone kicking off a run.
- **Always-on database + resilient health checks.** ✅ 2026-06-14 The hosted database is
  configured to **stay awake** (no auto-pause), so neither the health probe nor the first
  request after an idle period suffers a cold start. The health endpoint **tolerates a brief
  database hiccup** (a single blip is reported as a transient warning but the service stays up)
  and only reports unhealthy on a **sustained** outage.

## 6. Engine — Core
- **Modern, dependency-free engine.** The engine talks directly to Microsoft's APIs and
  the database — no heavy PowerShell modules to install or keep updated — so it runs on a
  plain VM or in a lightweight container.
- **Fast incremental runs.** Instead of a one-to-two-hour full sweep every time, the
  engine queues changes and applies only what actually changed, scoped to the area you
  ask for. Full reprocessing is still available when you want it.
- **Sets everything up for you.** From one run the engine creates the groups, delegations,
  org-group access, time-limited access passes, admin schedules and notification emails —
  nothing has to be wired up by hand.
- **Clear, readable logs.** Every action is logged on one tagged line (assign / update /
  extend / remove / OK), errors name the actual resource or role instead of an opaque ID,
  and a full transcript is kept for each run.
- **Stricter policy for the most privileged roles.** ✅ 2026-06-14 Global-Administrator-style
  delegation is automatically configured to **require approval at activation** (verified live
  against a real PIM-for-Groups policy). The approver is resolved the same way ownership is —
  from the group's owners, sponsor, or its department contact — so a high-privilege group is
  never left requiring approval with nobody able to grant it.
- **Safe by default — reconciliation never deletes silently.** ✅ 2026-06-14 A normal run only
  creates and updates. Removing live access that isn't in your configuration is a separate,
  explicit opt-in, and the engine will refuse to "prune" an area whose desired set is empty —
  so a partial or half-loaded configuration can never wipe out real administrators.

## 7. Engine — Providers / Connectors
- **Map one PIM group to many workloads.** Connectors translate your PIM groups into the
  right access across Entra roles, Azure RBAC, Power BI / Fabric, gallery enterprise apps
  (such as SAP or ServiceNow), and Dataverse / Dynamics 365 — each connector turns on its
  own access prerequisite.
- **Defender XDR & Intune access from the same PIM groups.** ✅ 2026-06-14 — give a PIM group
  a Microsoft Defender XDR (Unified RBAC) security role, or an Intune (device-management) role
  optionally limited to specific Intune scope tags, exactly the way you grant Entra and Azure
  roles. Admins get the workload access by being a member of the group; assignments are
  matched by what already exists (so re-running never duplicates them), and the engine only
  reads at collection time — it makes changes solely when applying your desired configuration,
  and only removes a role you no longer want when you explicitly ask it to prune.
- **Any enterprise app, one connector.** ✅ 2026-06-16 — grant a PIM group an app role in *any*
  enterprise application — gallery apps (SAP, ServiceNow, Salesforce, …) or your own
  line-of-business apps — with a single generic pattern, so you don't need a separate connector
  per app. Name the target app (by its display name, application id, or service-principal id)
  and the app role you want (by the role's name, or leave it blank for the app's default
  access); the engine looks up the role on the app and assigns your group to it. Like every
  other connector it matches what already exists (re-running never creates a duplicate),
  reads-only at collection time, and removes an app-role grant only when you explicitly prune.
  If you name an app role the app doesn't expose, it fails clearly instead of guessing.
- **A group's activation policy is fully managed and self-correcting.** ✅ 2026-06-16 — the
  engine doesn't just set a PIM group's activation policy once; it keeps the whole policy in
  line with the template you chose — how long an activation lasts, whether multi-factor and a
  justification are required, whether activation needs approval (and who approves), and who is
  notified. On every run it reads the group's current policy back and compares the *entire* rule
  set: if nothing has drifted it changes nothing (re-running is safe and silent), and if anyone
  has altered a setting in the portal it puts it back to your intended policy. Adding or removing
  an approver is detected and corrected too. Existing settings the engine doesn't manage are left
  untouched.
- **Full set of building blocks.** The engine covers administrative units, groups and group
  owners, admins and their time-limited access passes, Entra roles and role-scoped
  administrative units, group and admin membership, Azure resources, group policies and
  access reviews — all through direct API calls.
- **Import roles, don't type them.** The Manager reads the live list of available roles for
  a service so you pick from real roles instead of risking typos, diffs them against what
  you already have, and lets a super-admin confirm before importing.

## 8. Discovery
- **New Power BI workspaces become ready-to-delegate access groups.** As workspaces appear,
  the solution proposes a correctly-named, tier- and plane-classified access group for each
  one — so a new workspace is delegable minutes after it exists, with the same naming and
  structure as everything else.
- **Renames are tracked, not duplicated.** A workspace, subscription or management group that
  is renamed or moved is matched by its stable identity and the existing access group is
  renamed in place — you never end up with an orphan plus a duplicate.
- **Propose, never auto-assign.** Discovery creates the empty access-group container for a new
  resource (when you opt in to auto-import) but never grants anyone access automatically —
  who gets in stays a human decision. Anything without an auto-import rule is simply listed
  for review.
- **New built-in roles are catalogued automatically.** When a service (Entra, Defender,
  Intune) gains a new built-in role, it is added to the catalog so you can pick it — and an
  already-catalogued role never shows up again as "new".
- **You only ever see what's new.** Each discovery run surfaces only the items you haven't
  handled yet; once an item is acted on it stops reappearing, so the review list stays short.
- **Import your departments straight from Entra.** ✅ 2026-06-15 — point the solution at a group
  naming convention (for example `ORG-*`) and one click pulls every matching Entra group in as a
  department for approval routing, with each group's owners brought along as the people who
  approve for that department. Re-import any time: existing imported departments are refreshed in
  place, nothing is duplicated, and any department you added by hand is left untouched. You set
  and confirm the pattern right in Settings before importing.

## 9. Auth / Identity
- **100% direct API, no modules.** Authentication runs entirely over REST, so the solution
  works on a clean VM or container with nothing pre-installed.
- **Certificate-based app auth.** The engine signs in as an application using a certificate
  (not a shared secret), defaulting to the machine certificate store.
- **No secrets in configuration.** Access uses a managed identity or a Key Vault pointer;
  settings live in the database and seed files never carry secrets.
- **Tells you exactly which permission is missing.** When a call is refused for lack of
  permission, the tool no longer stops at a bare "access denied" — it names the precise
  permission to grant (for the automation identity) or the privileged role you need to
  activate (when you are signed in as yourself), and points at the one script that grants
  it. No more guessing which consent is missing. *(✅ 2026-06-14)* The same "name the exact
  fix" guidance now also covers **Azure resource (RBAC) refusals** — an Azure
  "AuthorizationFailed" is recognised as a missing **Azure role at the scope** (not a
  directory consent), so the hint says to grant or activate the right Azure role on the
  subscription / management group rather than pointing you at the wrong place — and the
  newer workload connectors (Microsoft Defender XDR, Intune, and granting a group an app
  role in any enterprise application) each name their own exact permission too. *(✅ 2026-06-17)*
- **Tells you what to activate BEFORE you act — not after a failure.** When you are signed
  in as yourself and start a privileged change (for example configuring a PIM policy,
  managing an administrative unit, or assigning an app role), the tool checks up front
  whether the directory role that action needs is **currently active** for you. If it is
  only *eligible* and not yet activated, you get a clear "activate this role in PIM first"
  prompt **before** the change is attempted — so you activate once and proceed, instead of
  driving all the way to an "access denied" and then starting over. If the right role is
  already active you are never interrupted, and an emergency super-admin path is never
  blocked. *(✅ 2026-06-17)*
- **Always shows the account picker — never reuses a stale login silently.** Interactive
  sign-in always lets you confirm which account you are using, and forces a fresh sign-in
  when the cached account is not the one you expected, so you can't accidentally act as the
  wrong identity. *(✅ 2026-06-14)*
- **Explains on-prem AD failures instead of hiding them.** If an Active Directory action
  fails, the tool reports *why* — the identity it actually ran as, whether it had a domain
  logon and Kerberos tickets, and whether a domain controller was reachable — so you know
  whether to fix the credential, the network/DNS, or the target object's rights. *(✅ 2026-06-14)*
- **MFA-gated admin console (optional).** The privileged Manager console can require a fresh
  multi-factor sign-in before it opens, so a copied script can't be replayed without you
  passing MFA. When the console runs centrally behind Entra sign-in, that gateway already
  enforces MFA, so the local gate stays out of the way. *(✅ 2026-06-14)*

## 10. Delegation model
- **Two-tier group nesting at the core.** Admins are added to direct groups (by role, task,
  process, cross-org or department) which nest into permission groups that hold the actual
  roles and scopes. This delivers least-privilege access across many apps by reusing group
  nesting and RBAC — and it's the heart of the model.
- **Everything is a group.** The thing you grant is always a group; administrative units
  and Azure scopes are only the *where*, never the *who*. Delegation is simply group
  membership.
- **Every group has an owner — automatically.** Groups are never created without an owner;
  the owner is resolved from the assignment, the sponsor, or the department-to-owner
  mapping.
- **Scoped portal admins.** A delegated/portal admin profile carries the services, tier and
  level ceilings, scopes and the set of admins they may manage. A workload owner sees only
  the groups they own, and even the admin list is filtered so they cannot see the most
  privileged tiers. Super-admins bypass the scoping.
- **Invite an external consultant straight into the delegation model.** ✅ 2026-06-15 Bring an
  external consultant in as a cloud guest and place them into a delegation group in one step:
  the solution prepares the guest invitation and, at the same time, the consultant's admin record
  and their membership in the chosen delegation group — all staged for the normal Review & Save
  flow, so nothing is granted until you confirm and the engine applies it. Guest invitation is
  cloud-only (you cannot invite a guest into on-prem Active Directory), and only an operator with
  the guest-invite delegation right (or a super-admin) may do it.
- **Self-service consultant enable / disable.** ✅ 2026-06-15 A department or service owner can
  switch one of *their own* managed consultants on or off from the console — without a central
  request. The action is allowed only for the consultants that owner manages (a super-admin may
  toggle any), and it is queued as a normal account change that the engine applies, so it is
  audited and reversible like everything else.
- **Local self-service delegation — no central request needed.** ✅ 2026-06-14 When you run
  the solution for your own organisation, your local IT can self-delegate any permission,
  including the most privileged, without raising a request to a managed-service provider —
  full local autonomy. In a managed-service setup that self-grant path is closed instead, and
  an organisation can additionally pin specific privileged groups as "enforced" so they can
  never be locally overridden. Super-admins are never locked out, and a self-delegation is
  recorded as an ordinary assignment so it is audited and offboarded like any other.
- **Two clearly separated approvals — one yours, one the platform's.** ✅ 2026-06-14 *Delegation
  approval* (who may be added to a group) is handled by the solution: it can route to a
  department — automatically resolving the department to its responsible people — and it
  layers and escalates as a request ages. *Activation approval* (approving an activation in
  the moment) is handled natively by Microsoft Entra PIM. Because Entra only accepts named
  people as approvers, the solution automatically turns any department or role persona into
  the actual people before it configures the policy, and refuses to publish an approval rule
  that would end up with nobody to approve. The two are never confused, and the solution never
  sends activation emails — Entra does that.
- **Reachability by classification — privileged-workstation aware, opt-in.** ✅ 2026-06-14
  (opt-in default OFF ✅ 2026-06-15) Each delegation can carry a network-reach classification
  derived from its tier, plane and level — for example the most privileged tier is confined to
  the privileged-workstation (PAW) segment, the management plane is limited, and broad workload
  roles reach the whole corporate network. **Privileged-workstation detection is opt-in and OFF
  by default**: out of the box nothing is confined to a PAW segment (so a tenant that does not
  run privileged workstations is never blocked), and you turn it on with a single setting when
  your environment is ready for it. The classification is fully configurable to match your own
  segmentation, and emergency super-admin access is never locked out.

## 11. GUI / Manager

![PIM Manager — Home / Overview dashboard](img/manager-home.png)
*The Manager opens on a Home dashboard: red/amber/green attention tiles for engine health, validation findings, break-glass, delegation by tier, gaps/orphans, expiring access and pending reviews.*

- **Turn any Manager feature on or off in Settings — roll out gradually.** ✅ 2026-06-16 — every
  screen in the Manager (each tab and major panel) can be switched on or off from a **Features** panel in
  **Settings**, so you can introduce capabilities to your team **one at a time** rather than all at once.
  Turn a feature off and its tab simply disappears from the menu on the next page reload; turn it back on
  when you're ready and it returns. Core, everyday screens are on out of the box; newer or more advanced
  screens start off so you can enable them deliberately as you adopt them. A few essential screens (**Home**,
  **Audit**, and **Settings** itself) are always on, so you can never accidentally hide the way back in.
  Changing the feature set is restricted to a senior administrator and every change is recorded in the audit
  trail. Because the on/off choices are saved in the same place the rest of the Manager reads, what you see
  in the menu always matches what's actually enabled.
- **CISO-friendly consolidated navigation.** ✅ 2026-06-16 (live-verified on the hosted Manager) — the
  Manager's ~20 flat tabs are folded into **six clearly-named top-level menus** so a security leader or a
  first-time admin can find anything in seconds: **Overview** · **Provisioning & Access** · **Change
  Control** · **Operations** · **Governance** · **Audit & Settings**. Each menu opens a collapsible group of
  the underlying screens and carries an attention dot + per-item count, so what needs action is visible
  without opening every tab. The grouping is a pure navigation layer over the existing screens — nothing was
  removed or renamed, and the classic flat tab strip is still there underneath.

  ![The consolidated six-menu navigation with a dropdown open](img/manager-nav.png)
  *The ~20 flat tabs folded into six clearly-named top-level menus, each with an attention dot and per-item count.*

- **In-context guidance + consistent panel states on every screen.** ✅ 2026-06-17 — every screen now
  carries a short, collapsible **"what this is & how to use it"** banner at the top, so a first-time admin
  always knows what a tab is for and the next step to take — no guessing. Across the whole Manager the
  **loading, empty and error** moments look and read the same: a screen is never left blank, an "empty"
  result says so in plain language (rather than showing nothing), and a problem is shown as a tidy,
  readable message instead of a raw technical error. Screens that talk in terms of privilege **tiers and
  planes** (the delegation map, role lookup and reports) include the same plain-language **tier / plane
  legend** inline, so the vocabulary is explained right where it's used. The guidance can be collapsed once
  you know your way around, and it's a presentation layer only — it changes nothing about how the Manager
  behaves.
- **Home / Overview — "what needs my attention" at a glance.** ✅ 2026-06-15 — the Manager now
  opens on a **Home** dashboard instead of dropping you straight into the map. It summarises the
  health of your privileged-access estate in clear red/amber/green tiles, each of which you can
  click to jump to the tab that owns the detail:
  - **Failed jobs / engine health** — how many background jobs failed, what's running now, when the
    last run was and whether it succeeded, and when the next run is due (so an overnight failure is
    visible the moment you log in, not buried).
  - **Validation findings** — the current count of blocking errors and warnings from the pre-flight
    checks.
  - **Break-glass** — whether an emergency override is active right now, who activated it, and when
    it expires.
  - **Delegation by tier (L0–L5)** — how your delegation groups are spread across privilege levels.
  - **Gaps, orphans & unmanaged** — groups that reach nothing, admins who reach nothing, and
    targets no group manages.
  - **Expiring access (next 14 days)** and **pending access reviews** — what needs renewing,
    revoking or deciding soon.
  Every tile is backed by real engine/job/validation/audit data with an honest empty state — there
  are no decorative or dead tiles. A red badge on the Home tab shows the total number of items
  needing attention.
- **Alerting — get told when something goes wrong.** ✅ 2026-06-15 — choose who is emailed and
  which events raise an alert (an **engine/job run failure**, **configuration drift**, **access
  expiring soon**, or **break-glass use**) from the Home/Settings **Alerting** panel. Alerts are
  delivered through the same notification path as every other PIM email. If no sender mailbox is
  configured yet, the panel says so plainly ("configure to enable") and prepares the alert without
  sending — it never silently drops or fakes a notification. A **Send test alert** button confirms
  the wiring end-to-end.
- **Alerts you can trust — a feed of what was pushed out, with proof of delivery.** ✅ 2026-06-17 —
  alerting now keeps a durable **Recent alerts** feed: every alert that fired is recorded with **when**
  it fired, **which event** it was, **who was notified**, and whether it was actually **delivered** or
  only **prepared** (when no sender mailbox is configured yet). This turns a claim like "the owners were
  notified when break-glass was used" into something you can **verify** — the feed is the proof. Two
  more refinements ship with it: **access expiring soon** now actually raises an alert when the Manager
  finds time-bound access about to lapse (previously it was an option you could tick but nothing fired
  it), and a **debounce** stops the same recurring condition (for example, the same drift on every run)
  from emailing you over and over — you get told once, not on a loop. The feed appears on the Home/Settings
  **Alerting** panel with a one-line "delivered vs not delivered" summary, and a compact "Recent alerts"
  rollup is on the **Home** dashboard. As with all PIM email, when no sender mailbox is configured the
  alert is recorded honestly as "prepared, not delivered" — never faked.
- **Operational policy — configure the defaults from the tool, not out-of-band.** ✅ 2026-06-16 — an
  **Operational policy** panel in **Settings** lets an administrator set the core operational defaults
  in one place, so they no longer have to be applied by hand or left unset:
  - **Expiry defaults** — the default and maximum length of a time-bound activation, and the ceiling
    for an eligible assignment, chosen from sensible standard durations.
  - **Require MFA on activation** — a single toggle for whether activating privileged access must be
    backed by multi-factor authentication.
  - **Connection-sanity** — the timeouts and required-checks used to validate the tenant and database
    connection (how long a SQL or Graph probe may take, and whether each must succeed).
  Settings are saved to the same configuration store the engine and scheduled jobs read, so what you
  see in the panel is what the system actually uses. Invalid entries are **rejected or safely clamped
  with an explanation shown in the panel** — never silently dropped — and a sensible secure default is
  always in place (MFA on, conservative durations) even before anything is customised.

  ![Settings — naming conventions and operational policy](img/manager-settings.png)
  *Settings is where you tune naming conventions, operational-policy defaults, alerting and the per-screen feature toggles — all persisted to the store the engine reads.*
- **"Who can do what" report — and the reverse.** ✅ 2026-06-16 — a **Reports** tab answers the two
  questions every access audit starts with, instantly and with evidence to hand to security or auditors:
  - **Pick a person → everything they can reach.** See every privileged target the person can
    activate — Entra roles, Administrative-Unit-scoped roles, and Azure resource roles at their scope —
    and, for each one, the **exact path** that grants it (which role group, through which nested groups).
    It is real reachability, not a flat list: access inherited through nested groups is followed and shown.
  - **Pick a role → who can activate it.** The reverse view lists every person who can reach that role
    or target, again with the path. It honestly reports zero when nothing grants a role.
  Both views read the live delegation model (the same data the Delegation Map draws), and both are
  **printable and exportable to CSV**.

  ![Reports — "who can do what", showing a person's reachable targets and the exact granting path](img/manager-reports.png)
  *The Reports tab: pick a person to see every target they can reach (and the exact granting path), or pick a role to see who can activate it.*
- **Tier-impact report — every user who can reach your most privileged assets.** ✅ 2026-06-17 — a
  third **Reports** mode answers the question a security review opens with: *who can reach a Tier-0 or
  Tier-1 target?* It lists **every** user with a path to high-privilege access — and crucially it counts
  reach **inherited through nested groups**, not just roles assigned to a person directly, so it surfaces
  the hidden privilege a flat "what roles does this person hold" list misses entirely. Each row shows the
  user, the **highest tier** they can reach (Tier-0 flagged most strongly), **how many** distinct
  high-tier targets they reach, the **worst** target, whether they get there **directly or through a
  nested group**, and the **exact granting path**. The list is sorted most-privileged-first, with a
  one-line summary (how many of all scanned users can reach Tier-0 vs top out at Tier-1), and a switch to
  narrow it to **Tier-0 only**. It reads the same live delegation model the Delegation Map and the other
  reports use — so it is real reachability, never a guess — and is **printable and exportable to CSV** for
  an audit or a board report. When nothing reaches high tier it says so honestly rather than inventing
  rows. *(Offline-verified end-to-end against a booted Manager; the hosted Manager GUI smoke is the live
  gate before publish.)*
- **Global search — one box, jump to any object.** ✅ 2026-06-16 — a search box in the header finds any
  **person, group, role, scope or tag** across the whole estate and takes you straight to it: a person or
  role result opens the matching "who can do what" report; a group, scope or tag focuses it on the
  Delegation Map. No more hunting through grids to find the object in question.
- **Export everywhere — CSV and print on every operational view.** ✅ 2026-06-16 (Role Lookup + active
  assignments added ✅ 2026-06-17) — the **Reports**, **Delegation Map**, **Validate**, **Access Review**
  and **Audit** views each carry an **Export CSV** and **Print** action, so any screen can become evidence
  for a review, a ticket or a management report without re-keying. The same one-click export now also covers
  the **Role Lookup** tab — in all four of its modes — and the **Maintenance** "active assignments" list:
  - **Role permissions for a least-privilege ticket.** From *what a role can do*, export the role's concrete
    permissions (every allowed and excluded action, with its area) straight into a ticket — no retyping a
    permission set by hand.
  - **The narrowest role for an action.** From *find roles by action*, export the ranked, least-privilege-first
    list of roles that grant an operation (with each role's total permission count and whether it grants the
    action only through a broad wildcard), so a reviewer can see and justify the tightest fit.
  - **Who can activate a role — with the path.** From *who can activate a role*, export every person who can
    reach it together with the exact granting path, as genuine audit evidence.
  - **A role-vs-role split.** From *compare two roles*, export who can activate both versus only one.
  - **Who has what is active right now.** From the **Maintenance** view, export the live, currently-active
    privileged assignments shown (principal, role/group, scope, type, when it was activated and when it
    expires, and the justification) as a point-in-time "who has access" extract for a review or audit.

  Exports are spreadsheet-safe — values that could be misread as formulas are neutralised, so a CSV opened in
  Excel can never execute injected content. Printing opens a clean, titled, tenant-stamped page (date + row
  count), not the whole application.
- **Browser-based delegation editor — "PIM Manager".** Create, map, delete, bulk-edit,
  revoke and clone delegations through a browser grid with guided wizards.
- **Role tiers with the right powers.** Reader, Admin, Super-Admin and Delegated roles.
  Super-Admin sees everything, skips validation, and can update the schema; the hosted role
  comes from configuration; and the system fails closed to read-only if a role can't be
  determined.
- **Authoring helpers that turn many clicks into one.** ✅ 2026-06-14 — the Manager now
  generates whole sets of rows for you, which you then approve through the normal Review &
  Save flow (the engine remains the only thing that writes to your tenant):
  - **Bulk-attach wizard** — pick several directory roles, Azure scopes and administrative
    units at once and attach them all to one permission/role group in a single action.
  - **Clone** — duplicate a role, group or definition onto several new groups at once, and
    clone an Azure role assignment to a different Azure role (or to several) at the same scope.
  - **Administrative-Unit wizard** — define a new AU (and optionally bind roles to it) without
    hand-editing files.
  - **Admin bulk import** — paste a list of people (first name / last name / initials, plus
    optional department) and have each row expanded against a chosen admin template, with
    initials and display names filled in automatically.
  - **Replace-mode admin move** — move an admin from one role group to another as a single
    all-or-nothing change (the old grant is removed and the new one added together).
  - **Multi-select delete** — remove several selected assignment rows in one step.
  - **Role-permission drill-down** — see the concrete permissions behind any directory role,
    grouped by area, for review or export.
- **Review & Save shows what really changed — reordering a row is not a change.** ✅ 2026-06-16 —
  the commit preview now compares your edited rows to the current ones by each row's **identity**
  (the natural key the system already uses to recognise that row — e.g. its group tag, department,
  administrative unit, or the combination that uniquely names an assignment), not by its position in
  the list. So if you simply move rows around — after an Excel round-trip, a sort, or an authoring
  reorder — the preview correctly shows **no changes** instead of falsely flagging modifies, removes
  and adds. A genuine edit to a row still shows as exactly one modify (with the changed columns
  highlighted), a new row as one add, and a deleted row as one remove. If two rows can't be told
  apart by their key, the preview falls back to comparing them by content rather than guessing — it
  never miscounts or errors out. The result is a Review & Save diff you can trust to say exactly what
  the commit will do.
- **Every save is backed up first, all-or-nothing, and reversible.** ✅ 2026-06-16 — committing your
  changes on Review & Save is now safe to do and easy to undo. **Before** anything is written, the
  Manager takes a **timestamped backup** of the affected data, so there is always a point to return to.
  The save itself is **all-or-nothing**: if something goes wrong part-way through, the whole change is
  **rolled back automatically** and your data is left exactly as it was, with a clear message telling
  you the commit was reversed — never a half-applied, half-changed state. And if you commit something
  and then change your mind, the new **Backups / Undo** view on the Review & Save tab lists the recent
  pre-commit snapshots per data set and lets you **roll back to any of them** in one click. The most
  recent backups are kept automatically (older ones are pruned), so the safety net stays tidy. This
  applies whether the Manager is running against the central SQL store or a local file store.

  ![Review & Save — the keyed diff and commit gate](img/manager-review-save.png)
  *Review & Save: a keyed diff (reordering a row is not a change) and an explicit commit gate — every save is backed up first, all-or-nothing, and reversible.*

- **Authoring panel.** ✅ 2026-06-15 — a dedicated **Authoring** tab puts the bulk-attach, clone,
  admin-import and admin-move helpers behind simple forms. Each action composes the rows for you
  and stages them straight into the pending list, so you finish on the familiar **Review & Save**
  tab. It is available to Administrators (and above) and is read-only for everyone else.
- **Authoring — see exactly what each action will change before you commit.** ✅ 2026-06-16 — every
  Authoring action (Move admin, clone, clone to another Azure role, clone an administrative unit,
  bulk-attach, import administrators, delete rows) now shows an **inline preview** the moment you run
  it, and stages nothing until you confirm. The preview lists precisely what will be **added,
  changed (with the specific columns), or removed**, matched by each row's identity (so simply
  reordering rows is correctly shown as "no change"), and it raises a clear **destructive warning**
  whenever an action would remove existing rows — including the operations that used to happen
  silently behind the scenes. **Moving an administrator between groups can no longer lose rows:** the
  move re-points only the chosen assignment and carries every other row through untouched, and the
  system refuses to produce a plan that would drop any row. *Why it matters:* you always know what an
  authoring action will do before it happens, so there are no surprises and no silent data loss.
- **A second pair of eyes on the most sensitive changes.** ✅ 2026-06-16 — the most sensitive
  Authoring and Onboarding actions now require a **second administrator to approve them before they
  commit**. This covers **attaching a privileged role or scope** to a delegation group (for example a
  highly-privileged directory role, an Azure Owner assignment, or any Tier-0 / control-plane access),
  **placing a guest / external account into a privileged group**, and **disabling or offboarding an
  account**. One administrator (the *maker*) stages the change as usual; before it can be committed a
  **different** administrator (the *checker*) must approve it on the Approvals tab — **you cannot
  approve your own change**. Ordinary, non-privileged authoring is completely unaffected and commits as
  before. When a staged change needs that second approval, the Manager tells you exactly why and takes
  you straight to the Approvals tab to raise the request; it uses the **same approval queue and audit
  trail** as the rest of the platform, so there is nothing new to learn. *Why it matters:* the changes
  that could do the most damage can no longer be made by a single person without an independent check.
- **Approval-gated offboarding — request, approve, then execute.** ✅ 2026-06-17 — disabling or
  offboarding an account is now a **deliberate, two-person, recorded** flow instead of a single
  unguarded click. One administrator **raises** an offboard request (with a justification and ticket); a
  **different** administrator **approves** it on the Approvals tab — **nobody can approve their own
  request**; and only then can an administrator **execute** it. Executing runs the **guided offboard
  sequence** — disable the account, revoke its active access, and **schedule** (never immediately
  perform) deletion — through the platform's existing account-status path, and the request is **consumed
  once** so it can never run a second time. The flow **cannot run automatically** and refuses to act on
  an **empty** target outright or on a **bulk / multi-account** target without an explicit extra
  confirmation; the platform's mass-change safety brake and the protection for break-glass / emergency
  accounts **still apply and are never overridden** by an approval. *Why it matters:* offboarding is
  destructive and irreversible enough that it deserves the same human-approved path as onboarding —
  directly addressing the class of accidental mass-disable incident the safety brake was built to
  prevent.
- **Approval-gated bulk revoke — preview, approve, then execute.** ✅ 2026-06-17 — revoking many active
  privileged assignments at once is the single most destructive thing you can do in the Manager, so it is
  no longer a raw, one-click action. The tab where it lives is now clearly named **Maintenance & Revoke**
  (with an up-front warning) so it is never buried behind an innocuous label. Before anything happens you
  get a **what-if preview** — exactly which assignments would be revoked, which **break-glass / emergency
  accounts are protected and skipped**, and whether the batch is large enough to need a **second-person
  approval**. A **small** batch can be revoked after a typed confirmation, as before. A **large** batch
  (over a configurable safety threshold) is **blocked until a recorded approval exists**: one administrator
  raises a *revoke* request, a **different** administrator approves it on the Approvals tab — **nobody can
  approve their own request** — and only then does the revoke run. Every revoke is **audited** (who, what,
  when, and the business justification, which is mandatory), break-glass accounts are **always excluded**
  whether or not there is an approval, and an approved large-batch request is **consumed once** so it can
  never silently run again. *Why it matters:* one click could previously strip live access across the
  estate with no preview and no record — exactly the class of incident the platform's mass-change safety
  brake exists to prevent; bulk revoke now gets the same human-approved, fully-recorded treatment as
  offboarding.
- **Onboarding panel.** ✅ 2026-06-15 — a dedicated **Onboarding** tab to **invite an external
  consultant as a guest** straight into the delegation model (it prepares the invitation and the
  account + group placement for you to review and commit) and to **enable or disable a managed
  consultant** with one toggle. As everywhere else, the system itself remains the only thing that
  writes to your tenant — the panel only prepares the change for your approval, and the live
  invitation send is a separate, deliberate step.
- **Role Lookup panel.** ✅ 2026-06-15 — a read-only **Role Lookup** tab that lets you **see
  exactly what a directory role can do before you delegate it**. Type any role name and it drills
  into the role's concrete permissions live from the tenant, grouped by area. It never changes
  anything. When the tenant connection (or directory-read access) isn't available yet, it shows a
  clear "not available yet — connect and retry" message with a one-click **Retry**, rather than a
  technical error.
- **Role Lookup answers every role question — and forgives a typo.** ✅ 2026-06-16
  (search-by-action added ✅ 2026-06-17) — the Role Lookup tab now does far more than show a role's
  permissions, with four modes you switch between:
  - **What a role can do** — the permission drill-down above, now **typo-tolerant**: a misspelled
    or partial role name no longer errors out. Instead you get a ranked **"did you mean…"** list of
    the closest real role names; click one to look it up. A name that genuinely matches nothing
    simply shows no suggestions — never a technical error.
  - **Find roles by action** — the inverse question. When you know the **operation** you need to
    delegate (for example "update a user's password"), type the action and get **every role that
    grants it, ranked least-privileged first** (fewest total permissions), each with the matched
    permission(s). A role that grants the action only through a broad wildcard is flagged "broad" and
    ranked last, so the narrowest fit is always at the top — exactly what you want for a
    least-privilege request. A namespace wildcard also works to find every role that touches an area.
  - **Who can activate a role** — the reverse question. Pick a role and see **every person who can
    activate it**, each with the **exact path** that grants it (which role group, through which
    nested groups). It honestly reports "no one" when nothing grants the role. This reads the same
    live delegation model the Delegation Map and reports use, so the answer is real and auditable.
  - **Compare two roles** — pick two roles and instantly see **who can activate both** versus **who
    can activate only one**, side by side — ideal for spotting over-lapping privilege or confirming
    a least-privilege split. Everything stays read-only.

  ![Role Lookup — what a role can do, find roles by action, who can activate it, compare two](img/manager-role-lookup.png)
  *Role Lookup's modes: what a role can do, find the least-privileged role for an action, who can activate a role, and comparing two roles side by side — read-only and typo-tolerant.*
- **Cutover ceremony panel.** ✅ 2026-06-15 — a guided **Cutover** tab that walks an operator
  through moving the configuration store from files to a database, one gated step at a time
  (check → upgrade → import → switch → re-check → finalise). It shows exactly which step is next,
  what kind of store you are pointing at, and whether that store is safe to make authoritative.
  The source files are only ever read, the final "make it authoritative" step is confirmed
  explicitly, and the system refuses to finalise onto anything other than a production-grade
  database.
- **Abort a cutover before the point of no return — and a stage audit you can actually read.** ✅ 2026-06-17 —
  a database cutover is a multi-step ceremony, and until now there was no clean way to change your mind
  partway through. You can now **abort** a cutover at any time before you finalise it. Aborting puts you
  back exactly where you started: it returns the configuration source to your existing files (so the
  Manager reopens on the file store), and because the source files are only ever **read** during a
  cutover, nothing of yours was changed — the abort is completely safe. The Cutover tab shows, in plain
  language, exactly what the abort will do before you confirm it. **Finalise is still the point of no
  return** — once you have made the database authoritative, abort is no longer offered (start a fresh
  forward migration instead). At the same time, the **per-step audit is now human-readable** rather than a
  wall of raw technical data: each completed step is summarised in plain sentences (what the pre-check
  found and what the upgrade will change, how many rows were imported per area, when the source was
  flipped, and so on), so an admin can read the trail of what the ceremony did at a glance. *(Offline-verified
  end-to-end against a real local database; the hosted Manager GUI smoke is the live gate before publish.)*
- **Clearer top banner — you always know which tenant you're working in.** ✅ 2026-06-15 — the
  banner now shows the **connected tenant by name with its ID beside it**, grouped under a clear
  *Tenant* label, and (when you manage more than one) the **instance/environment switcher under its
  own label** — no more jumbled run-on text. The tenant name and ID are read from your real
  connection, and the *mode / source / generated* status reads cleanly on a single line.
![Delegation Map — admin to role group to permission bundle to target, with the risk overlay on](img/manager-delegation-map.png)
*The Delegation Map traces admin → role group → permission bundle → target, with a live risk overlay highlighting orphans, stale and over-privileged nodes.*

- **Delegation Map now spells out the actual permissions and their targets.** ✅ 2026-06-15 —
  the Delegation Map's fourth column, **Permissions & Targets**, no longer leaves you guessing.
  Select any capability bundle or role group and you see exactly what it grants, grouped into
  **Entra ID roles**, **AU-scoped roles** and **Azure RBAC @ scope**: each entry shows a short,
  readable label (for example *Owner @ mg-platform-identity* or *User Administrator @
  AU-Users-Standard*) and reveals the **full detail on hover or click-to-expand** — the complete
  Azure scope path with its kind (management group / subscription / resource group / resource /
  Power BI workspace / Azure DevOps project), or the exact administrative unit for an AU-scoped
  role. Everything shown is read live from your real delegation data, so what you see on the map
  is what is actually granted.
- **Delegation Map search now gives you a clickable result list — and jumps you there.** ✅ 2026-06-16 —
  typing in the Delegation Map's search box no longer just fades the rest of the board. You get a **typed,
  ordered result list** (people first, then groups, then roles and scopes) of everything that matches —
  by name, tag, role, scope or description — and **clicking a result jumps the board straight to that
  object**, centring and selecting it so its full reach lights up. Use the arrow keys and Enter to pick the
  top hit without the mouse. Finding the one group or role you care about in a large estate is now a couple
  of keystrokes instead of a scroll-and-squint.
- **Delegation Map risk overlay — see what needs cleaning up at a glance.** ✅ 2026-06-16 — a **Risk overlay**
  toggle on the Delegation Map highlights the parts of your delegation that deserve attention, computed live
  from your real model: **orphans** (a delegation or permission group that no admin can actually reach — dead
  delegation — or a target nobody reaches at all), **stale** (a node past its review horizon, shown only when
  your data carries a last-reviewed date), and **over-privileged** (a person or group that reaches a
  Tier-0/Tier-1 target, or reaches an unusually large number of targets compared with the rest of your
  estate). The "unusually large" line is learned from your own data — the typical reach across your estate —
  not a fixed number, so it stays meaningful whether you have ten delegations or ten thousand. Hover any
  flagged box for the exact reason. Turn the overlay off to return to the plain map. The visual now drives a
  hunt for what to clean up, instead of just showing the estate.
- **Revoke a grant straight from the Delegation Map.** ✅ 2026-06-17 — the map could already *add* a grant
  from the visual; now you can also *remove* one. Select a node the risk overlay flagged (or any node that
  participates in a grant) and choose **Stage removal**, and the Manager works out exactly which assignment
  rows that revocation touches — the admin's membership, a nested group, or the role/AU/Azure grant that
  attaches a target — and stages their removal. It is never a one-click delete: the removal goes through the
  **same safe path as every other change** — a clear preview that shows precisely which rows will be removed
  (with a loud destructive notice), the second-person approval gate when the grant being revoked is privileged
  (a *different* administrator must approve it first), and the Review & Save commit with its automatic backup
  and one-click undo. So you can hunt for over-privileged or orphaned access on the map and act on it right
  there, without ever leaving the picture, and without any risk of an accidental destructive write.
- **Template Rollout — a reviewable register of every exemption, with revoke.** ✅ 2026-06-17 — an exemption is
  a deliberate, time-boxed waiver that stops one missing template item from being flagged as a gap. You could
  always grant one, but until now you couldn't *see* the ones you had — so they quietly piled up and only ever
  ended when each lapsed on its own. The Template Rollout screen now shows an **active-exemptions register** for
  the selected template: every waiver with its item, the reason, who approved it, its expiry, **how many days
  are left**, and a clear status — **Active**, **Expiring soon** (within 30 days), **Expired**, or **Invalid**
  (a waiver with no usable expiry, which never suppressed a gap and is surfaced so you can clean it up). The
  list is sorted soonest-to-lapse first, so what needs attention is at the top, and a one-line summary tells you
  the totals at a glance. Each row has a **Revoke** button (administrator only) that ends the waiver
  immediately and re-checks its item on the next reconcile — so exemptions can be reviewed and retired
  deliberately instead of accumulating out of sight. Every exemption still requires an expiry, exactly as
  before. *(Offline-verified; the hosted Manager GUI smoke is the live gate before publish.)*
- **Template Rollout across the whole fleet — see and drive conformance for every tenant from one place.** ✅ 2026-06-17 —
  the Template Rollout screen used to show only the tenant you were connected to: to check whether ten managed
  tenants were current you had to switch into each one in turn. It now has a **This tenant / Fleet (all tenants)**
  switch. The **Fleet** view shows a single **tenants × templates matrix**: one row per managed tenant, one column
  per approved template, and each cell tells you at a glance whether that tenant is **up to date**, **behind by N
  versions**, **never deployed**, or **ahead** (on a newer version than the approved one — worth a look). Tenants
  that need attention sort to the top, and a one-line summary tells you how many tenants are fully current versus
  behind on at least one template. Underneath, a **ring-wide rollout** view lets you pick a template and see, per
  **ring band** (rollout wave), how many tenants a wave to that ring would touch and which of them are behind — so
  you can plan "roll this version to the early ring first, then the rest" instead of guessing. The actual deploy to
  each tenant still happens through the same proven, ring-gated, dry-run-first path as before (the fleet view is the
  bird's-eye planner; it never writes to a tenant by itself), and only **approved** templates ever appear as columns
  (a draft is never rolled out). *Why it matters:* a managed-service provider can finally see template conformance
  across the entire fleet — and decide where a rollout should go next — from one screen, instead of one tenant at a
  time. *(Offline-verified end-to-end against a booted Manager; the hosted Manager GUI smoke is the live gate before publish.)*
- **Delegation Map reads Excel-saved exports correctly — no more "empty map" on a valid file.** ✅ 2026-06-16 —
  when your delegation data comes from a spreadsheet (saved as a semicolon CSV), the column headings are
  often wrapped in quotation marks and the first heading can carry an invisible byte-order mark, and people
  sometimes add a space after the separator. The Manager now reads all of those exactly the same way it
  reads a plain file: it quietly cleans each heading (drops the invisible mark, trims spaces, removes the
  surrounding quotes) before matching columns, while leaving your actual data values untouched — so a value
  that legitimately contains a semicolon still comes through intact. The result: the Delegation Map shows
  your real delegation instead of rendering blank on a perfectly valid export, so you no longer mistake a
  parsing glitch for "there is nothing to see here."
- **Jobs panel — see what the automation is doing.** ✅ 2026-06-15 — a new **Jobs** tab lists the
  scheduled background work that keeps your environment in sync: the tenant-list cache refresh, the
  reminder/escalation checks, the per-area reconciliation runs, the scheduled daily-summary and
  Tier 0/1 reports, and the discovery passes. Anything **currently running is shown at the top**;
  everything else is listed below with its **schedule (how often it runs), whether it's enabled, when
  it last ran and how that went, and when it's due next**. Each run has a **Logs** button that opens
  that run's log, and for a job that's in progress you can switch on **live tail** to watch it
  finish. The panel is read-only — it reflects the real schedule and run history; the background
  runner does the work.
- **Jobs tab tells you when a run failed or never fired — and lets you act.** ✅ 2026-06-16 — the
  Jobs tab no longer just shows the last result. A **"needs attention" banner** at the top calls out
  any job that is **overdue** (it should have fired by now but didn't — so you can tell a missed run
  apart from a healthy one) or **failing** (its most recent run failed and hasn't been cleared).
  Each job shows an **overdue badge** and a **recent-failure count**, and a **History** button opens
  the recent runs for that job with **pass/fail and when** for each, so you can see whether failures
  are a one-off or a pattern and open any run's log. For a job that needs attention you can
  **re-run it now** (it executes immediately and you watch it move running → completed) and, once a
  failure is understood and handled, **acknowledge** it to clear the alert — the run record is kept
  for the audit trail; only the warning is muted.
- **One-click "Import departments from Entra" in Settings.** ✅ 2026-06-15 — the Settings →
  Departments area has an **Import** button: set or confirm a group naming pattern (default
  `ORG-*`) and the matching Entra groups are pulled in as departments for approval routing, with
  each group's owners brought along. You get an at-a-glance result (how many were created, updated
  and skipped), re-import is safe and never duplicates, and departments you added by hand are kept.
- **Bulk "Import approvers/owners from CSV" in Settings.** ✅ 2026-06-15 — upload a simple CSV
  (`Department;GroupName;approver1,approver2,…`) to set the approvers/owners for many departments
  at once, and optionally **rename** a department with an extra column. The file is read in your
  browser and applied through the engine: the departments listed in the file are updated (and any
  not yet present are created), while departments you don't mention are left exactly as they were.
  You get a created / updated / renamed summary.
- **AD OU placement is now editable in Settings.** ✅ 2026-06-15 — the on-premises Active Directory
  organisational units where new admin accounts are created are surfaced in a dedicated card: one
  OU for general admins and one for high-privilege (tier-0) admins. You can read and update both in
  place without editing config files.
- **Clearer "Owner" wording in Settings.** ✅ 2026-06-15 — the Settings tab now spells out the
  difference between the naming token that uses an account owner's **initials** and the **people**
  (sign-in names) listed as department / approval owners, so the two are no longer easy to confuse.
- **Target-first "create access" wizard.** ✅ 2026-06-15 — instead of inventing a group name and
  guessing its level/tier, you work the natural way round: pick **what** you are delegating
  (an Entra service, an Azure scope, or a workload), pick **where** (the subscription /
  management group / administrative unit), then pick the **roles** you want there. The wizard
  derives the rest for you — whether it becomes a single-role service group or a multi-role
  bundle, the correct name, and the level, tier and plane (for example, Global-Admin-class roles
  become the most privileged tier; an Azure subscription sits a tier below the tenant root; an
  administrative-unit-scoped role drops a level). The administrative-unit step only appears when
  every role you picked actually supports it, so you are never offered an option that can't apply.
- **Ready-made delegation template packs.** ✅ 2026-06-15 — the Create tab ships a growing
  library of best-practice permission packs you can adopt with one click instead of authoring
  groups by hand. Each pack is a curated set of permission groups for a Microsoft service, named
  and tiered the right way out of the box, and the Manager shows you exactly which rows your
  instance does not have yet (so a pack that grows later surfaces only the new additions). The
  shipped packs now cover: **Microsoft Defender XDR**, **Microsoft Sentinel**, **Intune /
  Endpoint Manager**, **Exchange Online**, a generic **Azure RBAC** pack (Reader / Contributor /
  Owner / User Access Administrator at a scope you choose), and a common **Entra ID role** pack
  (Helpdesk, User, Authentication, Groups and License administrators, plus Global Reader). The
  workload packs bind the service's own roles directly to the group; the Azure and Entra packs
  also include the matching role-to-group assignment so adopting the pack is complete.
- **More governance pre-flight checks.** ✅ 2026-06-14 — the Validate tab now also flags:
  roles/organisations with no accountable owner or sponsor; admins missing a strong
  (phishing-resistant) sign-in method; Azure assignments pointing at a subscription, resource
  group or resource that no longer exists; and PIM groups that have not been activated within
  a configurable number of days. Each finding comes with a plain-language fix suggestion.
- **Optional audit to Log Analytics.** ✅ 2026-06-14 — in addition to the always-on local
  audit file, every change can optionally be forwarded to Azure Log Analytics (off by default;
  enabled with one configuration setting).
- **Audit tab — see who did what, when.** ✅ 2026-06-15 — a dedicated **Audit** tab gives you the
  full, searchable history of activity, newest first: when it happened, who did it, the action,
  what it affected, and the result. Filter by category with one click — **logins, delegation
  changes, account and access-pass activity, approvals, engine actions** (policy, discovery,
  configuration) and **emergency overrides** — each chip showing how many events it holds. Search
  across actor, action and target, and page through long histories at the page size you prefer.
  Sign-ins to the Manager are now recorded too, so the Logins filter reflects real activity. The
  view is strictly read-only — it reflects the tamper-evident, append-only audit record and never
  changes anything.
- **Audit you can defend — full history, before/after, and export the whole trail.** ✅ 2026-06-17 —
  the Audit tab now answers an auditor's hardest questions. **Reach the whole history:** a **window**
  selector lets you look at the **last 3 months**, the **last 12 months**, or **all history** — every
  month of activity the system has on record, not just the most recent quarter — and a **From / To date
  range** narrows to exactly the period you need. **See what changed:** every entry now shows a clear
  **before → after** summary of the change (for example, *Account enabled: (none) → True*, or
  *Approval required: No → Yes*), with unchanged details left out and creations and removals labelled, so
  "show me the before and after" is answered right in the row. **Export the whole trail:** alongside the
  existing **Export CSV / Print** of the page on screen, a new **Export full trail (CSV)** button downloads
  **every matching event across the selected window** — honouring your current category, search and date
  filters — as a spreadsheet that **includes the before/after change column**. The export is Excel-ready
  (UTF-8, ISO timestamps that read the same on any machine) and hardened against spreadsheet
  formula-injection, so it is safe to open and to hand to an auditor as ticket evidence or a recertification
  record. As before, the whole view is strictly read-only.
- **Support tab — a one-click self-check and a safe bundle to hand off for help.** ✅ 2026-06-16 —
  when something is not working, the **Support** tab now gives you a first-line diagnostics you can run
  yourself. **Run checks** tests the three things the Manager depends on — the **database**, **Microsoft
  Graph** (with the engine's permissions), and **Azure** (only when your delegation includes Azure
  resources) — and shows each as pass or fail with a **plain-language fix** when it fails (for example,
  exactly which permission to grant, or that the database firewall is blocking this host). Alongside the
  checks you get a **health summary**: whether the store is a database or files, how fresh the tenant
  cache is, the outcome of the most recent background run, and which environment you are connected to.
  **Download diagnostics bundle** saves all of that to a single file you can attach to a support request —
  and it is **sanitised**: secrets, certificates, tokens, connection-string credentials and full
  tenant/subscription IDs are masked out before the file is produced, so you can share it safely. The
  existing "Report an issue on GitHub" path stays, now sitting next to a real diagnostics surface instead
  of being the only option.
- **Drift detection with a gated "Apply now".** ✅ 2026-06-16 — the **Governance** tab now shows a
  **Drift — live vs desired** view that compares your real, live estate against the desired configuration
  you defined and lists exactly what has drifted: what is **missing** (defined but not actually live),
  what has **changed** (live but no longer matches intent), and what is **extra** (live but not in your
  desired set). When there is no drift it simply says so. When there is, an admin can tick the rows to fix
  and press **Apply now** — the same proven engine that runs your scheduled reconciles corrects only the
  rows you selected, so you fix configuration that has drifted from intent without hand-crafting the
  correction. It is **safe by design**: missing and changed items are created/updated, but removing an
  **extra** delegation is a deliberate, separate opt-in (it never happens from a single click), and every
  apply still goes through the normal approval gate and lands in the audit trail. *Why it matters:* drift
  from intent is surfaced instead of going unnoticed, and correcting it is one reviewed click rather than a
  manual hunt-and-fix.
- **Access Reviews you can actually complete — attest, assign, and chase from the portal.** ✅ 2026-06-17 —
  the **Access Review** tab is no longer read-only. For each review you can open **Review items** and record a
  per-person decision — **Approve** (keep access), **Deny** (remove access), or **Recertify / Don't-know** —
  one at a time, each with a required justification; every decision is written back to the review and lands in
  the audit trail (who decided what, when). You can **assign the reviewers** for a campaign directly from the
  same place (by email address, object id, a group, or "manager"), so you decide who is asked to attest without
  leaving the tool. A **Send reminders** action emails the reviewers of every review that is **overdue or due
  soon and still has pending items** — it previews exactly who would be contacted before anything is sent,
  never chases a finished review or one with nothing left to decide, and respects a sensible re-send interval so
  nobody is spammed. Finally, **Export** produces the **evidence** an auditor needs — the per-person record of
  who attested what, with the justification and outcome. *Why it matters:* a recertification campaign can be
  run to completion in one place — assign, attest, remind, and prove it — instead of chasing reviewers across
  email and the Entra portal. (Recording decisions and assigning reviewers require the Access Review read-write
  permission on the Manager identity; until it is granted the tool shows an honest "permission not granted yet"
  message rather than failing, and renders sample data so the surface is never blank.)

## 12. Notifications / Email
- **Built-in, template-driven email.** The engine sends notifications (new admin, new role,
  new permission, time-limited access pass delivery) by rendering HTML templates with simple
  placeholder tokens. Templates are fully customizable, and a lab redirect option keeps test
  mail out of real inboxes. Rendering and sending are separated so you can preview output.
- **Customize mail templates in the portal — no rebuild.** ✅ 2026-06-15 — Edit any
  notification email directly in the admin portal (Governance → Mail templates): open a
  template, change the wording, and save. Your version is stored centrally and takes effect
  immediately — it survives restarts and product updates, with no file editing and no
  container/image rebuild. The portal clearly shows which templates are still the shipped
  default and which you have customized, and a one-click **Reset** restores the original at
  any time. (Editing a template file on disk still works for teams that prefer it.)

## 13. Lifecycle / Governance / Approvals
- **Scheduled account creation and time-limited access pass.** ✅ 2026-06-14 — Admin
  accounts can be staged for a future date and time (for example, "create on the 1st
  workday of next month, after the mailbox is provisioned"), using plain or symbolic
  dates. The access pass is held back until just before it is actually needed (a
  configurable lead window), so a pass scheduled weeks out is not issued early. The
  scheduler checks each cycle which staged accounts have come due and never re-creates one.
- **Lifecycle calendar with reminders and auto-renewal.** ✅ 2026-06-14 — A single pass
  produces a calendar of access that is expiring soon (within a configurable horizon,
  soonest first), sends escalating reminders to the right people as the deadline nears
  (with configurable stages and a sensible re-send interval so nobody is spammed), and
  automatically renews items that are explicitly marked for auto-extension before they
  lapse. Renewals flow through the normal review/commit pipeline.
- **Access review with a feedback loop.** ✅ 2026-06-14 — Owners approve continued access
  before it is extended, with one exception: rows explicitly opted into auto-extension
  skip the owner step. A removal/deny decision is remembered, so the engine does not
  silently re-add a person the owner just removed; the most recent decision always wins.
- **Emergency break-glass override.** ✅ 2026-06-14 — In a genuine emergency an authorized
  super-admin can temporarily lift the approval requirement on the affected privileged
  access, gated by a passphrase. The passphrase is verified against a secret held in your
  key vault (with a local fallback), using a timing-safe comparison, a short lockout after
  repeated wrong attempts, and a bounded time-to-live (defaults to 4 hours, capped at 24).
  Every step is audited and the owners are notified, and normal approval policy is
  restored automatically when the window expires. It works from a client PC, so it still
  functions even if the central console is unavailable.

## 14. Scale / Performance
- **Built for large tenants.** The solution never bulk-lists hundreds of thousands of users
  or groups. It looks users up on demand and queries only the PIM-managed groups by name
  prefix on the server side, so context builds in seconds even in very large directories.
- **One efficient role-schedule read.** Tenant-wide directory-role schedules are read once
  and indexed, rather than queried over and over.
- **Validate-and-skip with smart retries.** Anything that already exists is skipped; access
  durations that are too long are retried at shorter durations down to permanent; and
  nesting that Entra disallows is skipped cleanly instead of erroring.
- **No artificial caps.** Scaling is empirical — measure, adapt, prune — never arbitrary
  "max N" limits that hide real problems.

## 16. PIM Activator (browser extension)
- **One-click bulk activation.** A browser extension for Edge and Chrome lets an admin pick
  the privileged groups they need from a checkbox list, enter a justification and duration,
  and activate them all at once — instead of clicking through the portal one role at a time.
  It covers eligible Entra roles, Azure RBAC and group-based access, and expands nested
  memberships so activating one group folds out everything it grants.
- **See and manage what's active.** The popup shows your currently active access with a live
  expiry countdown, lets you mark favourites, and supports single or bulk self-deactivation —
  and it only shows what you actually have, hiding empty categories.
- **A confirm step for large activations.** When you activate several roles at once, the button
  asks you to click again to confirm — a quick guard against an accidental click elevating far
  more access than you meant to. Small selections activate straight away.
- **The confirm step is tunable to your tenant.** ✅ 2026-06-15 The number of roles that triggers
  the click-again-to-confirm guard is an administrator setting: lower it for extra caution, or
  raise it for teams that routinely activate many roles at once. It is set centrally per tenant
  (and can differ per tenant in a multi-tenant catalog) — never left to individual users.
- **A one-time getting-started tip.** ✅ 2026-06-15 The first time you open the activate list after
  setup, a short dismissible note explains the two things that save the most time: tick several
  roles and activate them in one click, and use the My Access tab to see and end what is currently
  active. Dismiss it once and it never comes back.
- **Simple, secure sign-in.** Sign-in uses the browser's built-in flow (no extra software to
  bundle), and a first-run onboarding wizard guides setup when nothing is configured yet.
- **Works for one tenant or many.** Point it at a single tenant for a silent experience, or
  publish a multi-tenant catalog centrally so admins get a tenant switcher. Tenant settings
  can be deployed centrally (managed policy) or entered by the admin for a single tenant.
- **Fleet-friendly deployment.** Ship it to managed devices through Intune or straight to the
  browser policy on non-managed boxes (per-machine or per-user), with automatic updates from
  a published feed and self-healing recovery for the rare case a browser marks the extension
  corrupted.

## 17. Naming
- **Naming lives in config, never hardcoded.** All admin, group and resource naming
  patterns are defined in configuration with per-tenant overrides, using simple tokens for
  initials, level, tier and platform — so you can match your own conventions without
  touching code.

## 18. Launchers / Structure
- (Delivered items in this area are internal structure/release-engineering; see DESIGN.md.)

## 19. REST migration
- **Direct-API engine and pagination.** The core runs entirely on direct API calls, with
  robust handling of large, paged result sets — no reliance on module-specific behavior.

## 20. Testing / Validation
- **Tested for real, never faked.** Validation runs against real test tenants — actually
  creating groups, delegations, org-group access, emails, time-limited passes and schedules,
  then verifying and cleaning them up — not just logic checks.
- **Safe, self-cleaning test data.** Test data lives in the database and is deployed by the
  engine under a dedicated marker, so test objects are created, verified and deleted without
  ever touching production groups.
- **Verified end to end.** Delegations are confirmed to be genuinely applied in PIM, Azure
  resource access is validated against real sample resource groups, and a rerunnable offline
  test suite covers the engine and Manager flows.
- **Deploy-validation that proves what got built.** ✅ 2026-06-14 After a first-time deploy, an
  automated suite reads the desired configuration straight from the database and confirms —
  against the live tenant — that **every** group, administrative unit, role assignment, admin
  delegation and approval policy was actually created. Both test tenants pass this round-trip
  check completely.

## 21. Docs
- **Clear documentation set.** A concise design document and this detailed feature catalog
  describe both how the system works and what it does for you.

---

*Items still in progress or planned are tracked internally in REQUIREMENTS.md and are not
listed here. Only delivered, verified capabilities appear in this catalog.*
