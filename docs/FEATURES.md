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

## 5. SQL / Data
- **Single source of truth in SQL.** Configuration, settings, access rules and delegation
  profiles all live in the database — no scattered files or shares to keep in sync.
- **Passwordless database auth.** Cloud databases use Entra/managed-identity authentication
  only (no SQL logins or stored passwords); on-prem uses integrated Windows auth.
- **One consistent data path for the app.** The Manager reads and writes through a single
  database-aware layer, shows you which database you're connected to, and lets you switch
  between databases from a dropdown.
- **Run against a local database with zero extra setup.** ✅ 2026-06-14 Besides the hosted
  cloud database, the engine reads its desired configuration from a **local database** using
  the signed-in machine identity — ideal for a management server, an on-prem deployment, or a
  break-glass run. No cloud connection, no separate database login, and no token juggling are
  needed; just point the engine at the local instance and run.

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
- **Full set of building blocks.** The engine covers administrative units, groups and group
  owners, admins and their time-limited access passes, Entra roles and role-scoped
  administrative units, group and admin membership, Azure resources, group policies and
  access reviews — all through direct API calls.
- **Import roles, don't type them.** The Manager reads the live list of available roles for
  a service so you pick from real roles instead of risking typos, diffs them against what
  you already have, and lets a super-admin confirm before importing.

## 9. Auth / Identity
- **100% direct API, no modules.** Authentication runs entirely over REST, so the solution
  works on a clean VM or container with nothing pre-installed.
- **Certificate-based app auth.** The engine signs in as an application using a certificate
  (not a shared secret), defaulting to the machine certificate store.
- **No secrets in configuration.** Access uses a managed identity or a Key Vault pointer;
  settings live in the database and seed files never carry secrets.

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
- **Cloud-only guest invite and self-service consultant enable/disable.** Invite a
  cloud-only guest and let consultants be switched on or off through self-service.

## 11. GUI / Manager
- **Browser-based delegation editor — "PIM Manager".** Create, map, delete, bulk-edit,
  revoke and clone delegations through a browser grid with guided wizards.
- **Role tiers with the right powers.** Reader, Admin, Super-Admin and Delegated roles.
  Super-Admin sees everything, skips validation, and can update the schema; the hosted role
  comes from configuration; and the system fails closed to read-only if a role can't be
  determined.

## 12. Notifications / Email
- **Built-in, template-driven email.** The engine sends notifications (new admin, new role,
  new permission, time-limited access pass delivery) by rendering HTML templates with simple
  placeholder tokens. Templates are fully customizable, and a lab redirect option keeps test
  mail out of real inboxes. Rendering and sending are separated so you can preview output.

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
