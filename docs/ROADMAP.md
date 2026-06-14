# PIM4EntraPS — Roadmap

> Planned & upcoming **features**, grouped by area. A high-level overview — for what is
> already available see the product's feature catalog. Bug fixes are not listed here.
>
> **Auto-generated from the internal backlog at publish time — do not hand-edit.**

## Hosting / Runtime

- Host the Manager 24/7, internal-only, no public IP
- ACA, not App Service
- az containerapp ... --yaml, not multi-token --command
- Hub-spoke VNet; Manager co-located with SQL; portal separate
- Entra GSA / Private Access integration
- App Service MI token path
- Cheapest viable tiers; region
- Consider native .NET 8 / ACA for all roles
- Local + emergency editions

## Containers

- One parameterized engine image; config-driven worker matrix
- No secrets/customer data in the image
- Zero-downtime update
- Internal flavour parity

## Setup / Deploy

- One setup-script family: container / VM / MSP / emergency-local
- Install-PimEngineAppRegistration.ps1
- Cert reuse + machine-store default
- Deploy banners
- Bootstrap: auto-extend .custom, rename legacy CSVs
- Tenant catalog

## MSP

- Two DBs
- MI + SQL stay tenant-local; image distributed via az acr import
- Ring-based rollout
- Signed baseline + revoke kill-switch; local decrypts without the key
- Remove CK_LocalAdmins_NoHighPriv guardrail
- Avoid GDAP
- Support multiple MSP/sync models
- Side-by-side editions
- Shared platform/data model with TenantManager

## SQL / Data

- CSV→SQL migration + schema upgrade
- Idempotent schema preflight (MSP + local)
- DB cutover ceremony gated in the Manager
- Support Azure + on-prem/hybrid SQL
- Deploy-validation test scope
- On-demand recalc on SQL change

## Engine — Core

- Re-apply policy on template change
- Offboarding cleanup
- PIM v1 direct assignments
- Hybrid AD provisioning, explicit credential
- gMSA/sMSA legacy accounts
- No double Exchange connect
- Conformance versioning (Pro)
- sync-automateit job
- Always run the latest on-disk version
- Cloud launcher resolves Tenant.KeyVaultName
- Template state-hash gating (skip-unchanged) in the REST engine
- PIM-for-Groups policy: Expiration + Notification rules (v1→v2 parity) — LIVE-VERIFY
- Azure-RBAC (ARM) PIM activation policy — approval/MFA on the Azure scope
- Directory-role (Entra role) PIM policies — design decision
- Empty-description guard (Graph 1–1024 char rule)
- Offboarding Lifecycle=Retire + OffboardDate/DeleteAfterDays + drift-cleanup modes

## Engine — Providers / Connectors

- Per-workload connectors (remaining)
- Wire the workload applier into the pull cycle
- Nested-membership adapter
- GroupsCreateModifyPolicy / Workloads-as-provider
- Auto-load roles when creating a service
- Generic entra-approle connector
- Connector build order by demand
- Each connector enables its RBAC prerequisite

## Discovery

- Three jobs: Entra / Azure / Power BI (VM + container)
- Auto-detect new subs/MGs (never auto-map)
- Reconcile via change-queue, no orphans
- Auto-detect Power BI workspaces
- Auto-detect Power Platform environments/workspaces
- Enumerate services for new built-in roles
- Delta detection design

## Auth / Identity

- Internal vs community SPN
- Missing-role hint, not hard-fail
- Weigh SQL vs KV for secret storage
- MFA-gated Manager login
- Sign-in prompts for account
- Inspect AD identity on failure

## Delegation model

- Indirect group dimensions
- Delegated/portal-admin facets
- Local self-delegation
- Layered approvers/escalation
- PAW device support (opt-in)
- Reachability-by-classification

## GUI / Manager

- Activator branding
- ~25-tenant config dropdown
- Grid + graph + side panel
- Target-first reversed wizard
- Auto-load roles on new-service
- Group TAP settings; move admin ring; metadata
- Portal-admins table (drop separate portal)
- MFA login; SQL cutover; conformance endpoints
- Dev "switch admin" personas (auth off)
- Finalize the half-built Manager freely

## Notifications / Email

- Daily summary email
- Tier-0 emails + timed escalation/reminders
- ServiceNow→Manager intake (inbound only, secure)
- Tier 0/1 report
- Welcome/TAP mail to a real mailbox

## Lifecycle / Governance / Approvals

- Scheduled admin creation
- Scheduled TAP
- Symbolic time variables
- Reusable admin templates
- Per-role policy templates
- Per-role approval differences
- Access reviews with feed-back loop
- Lifecycle calendar
- Resource approvers/owners (Phase 8)
- Role sponsor/owner for validation/audit/renewal
- Account status lifecycle + central kill
- Approval delivery when Manager is down
- Auto-approve own commits; require approval for others
- Full audit logging
- Emergency break-glass override
- Access-review tombstone suppression layer
- Emergency override passphrase via Key Vault
- Unified append-only jsonl audit schema

## Licensing

- Core (free) + Pro (paid), one engine
- Offline signed license

## PIM Activator

- MV3 + PKCE (no MSAL)
- Onboarding wizard
- One-click bulk activate (all 3 types + nested)
- Keep transitiveRoleAssignments
- My Access + favorites + countdown
- Resolve AU GUIDs to names
- Managed deployment
- Deploy-PimActivatorBackend.ps1
- Per-tenant registry catalog
- Update script + gh-pages auto-update
- Repack only from mgmt1 master key
- Verbose update output
- Remove legacy config mechanisms

## Naming

- Day-to-day admin = Admin-CCC-ID
- Patterns
- Drop "CSV"; single PIM-Engine -Scope
- No version/stage numbers in names; no "Runner"
- Routing from UserName markers

## Launchers / Structure

- SI-mirror layout
- Three flavours + banner + transcript
- Shared module + legacy shim
- gitignore exception for locked configs
- Publish strips BOTH internal flavours
- Dual git tags per release
- Migrate 3 solutions off v1

## REST migration

- Write/activator/setup/EXO path
- Pre-mint workload tokens

## Testing / Validation

- Two real test tenants
- MSP + local simulation w/ deployed SQL
- Live workload-owner simulation
- Pester validates Azure roles exist for the sample resources

## Docs

- README + curated RELEASENOTES + VERSION per release
- Version banners
- Session handoff before model switches
- Document container runtime; remove orphaned code/dead scripts

## Manager authoring / reporting / governance backlog

- Bulk attach wizard
- Clone Azure RBAC delegation to a different role at the same scope
- Bulk / cross-entity clone
- AU wizard
- Bulk admin import
- Admin metadata fields
- Role-permission drill-down (live)
- Auth-method validator
- Per-ROW approval + notification overrides
- Stale-group detection
- Outbound notification channels
- Audit to Log Analytics
- Replace-mode admin move
- Tier-impact report
- Gated orphan-scope cleanup job
- Entra Access Package integration
- Multi-operator concurrency
- Per-cell change history

## Date / TAP / scheduling

- Date-expression grammar + live GUI preview
- TAPLifetimeHours column
- TAP deferral lead-window

## Mail routing & people directory — no per-admin manager maintenance

- Department-linked recipients instead of per-person links
- Central mail-routing override
- "Person left" reference sweep
- "Contacts & email flow" Governance sub-tab

## Self-service delegation layers

- Delegation units as a data layer
- Inactivity auto-disable sweep
- Self-service front end = the §12 intake, not a new trust path

## Two-plane network topology

- Admin plane vs self-service plane as separate networks

## MSP — vary the edges, never the core

- Pluggable auth profiles behind one contract
- Pluggable storage profiles behind one contract
- Per-tenant cert lifecycle automation (first-class, not polish)
- Optional Enforced baseline entries
- Two separate kinds of approval kept distinct
- Notification ownership follows the same split
- One conformance test suite per profile; no speculative profiles
- Shared substrate with TenantManager via Product
