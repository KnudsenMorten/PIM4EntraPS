# Workload connectors — status + mechanism map

A connector binds a PIM group to a workload role so JIT activation actually grants
access in that workload. The engine (`Apply-PimWorkloadAssignments` in
`engine/_shared/PIM-Functions.psm1`) drives any connector whose API fits the
**flat assignment model**: *list role definitions* + *list assignment objects that
each carry a `principalId` and a `roleId`* + *create/delete such an object*. Most
Microsoft role APIs fit this (Graph directory/app roles, ARM, Defender/Intune
unified RBAC). Some workloads use a **nested membership** model (a container —
team/group/role-group — holds members and roles separately) or are **cmdlet /
portal only**; those are called out below so nothing here is a fake stub.

## Shipped (flat model — framework-driven, schema-validated by the Pester suite)

| Connector | auth | Covers | Status |
|-----------|------|--------|--------|
| `entra-roles` | graph | Entra **directory roles** | **Live-tested** (145 roles listed) |
| `entra-approle` | graph | **Generic gallery/SaaS app-role grant** — SAP, ServiceNow, Salesforce, and any enterprise app that publishes Entra app roles. Per-row `Resource` = target SP object id. This is the "100+ apps" connector. | Structure built; live-validation pending a target SP with app roles |
| `azure-rbac` | arm | **Azure RBAC** role assignments at any ARM scope (subscription / RG / resource). Per-row `Scope`. | Structure built; live-validation pending an ARM token + writable scope |
| `powerbi` | powerbi | Power BI / Fabric workspace roles | Structure built; pending a Power BI SP with workspace access |
| `defender-xdr` | graph | Defender XDR Unified RBAC (once portal-activated) | Built; prereq = portal activation (no Graph activation endpoint) |
| `intune` | graph | Intune RBAC (always-on, 10 built-in roles) | Built |
| `power-platform` | powerplatform | Power Platform **environment roles** (Environment Admin / Maker) | Structure built; pairs with the environment-discovery planner; live-validation pending a Power Platform admin SP |

`entra-approle` is the high-leverage one: the *catalog* of 100+ Entra-integrated
apps (`docs/ENTRA-GROUP-APP-CATALOG.md`) collapses to **this single connector**
for every app whose access is an Entra app role. Finance/HR/SecOps JIT use cases
that need *app-level* access (get into SAP / ServiceNow / a custom app) are
covered here.

## Nested-membership adapter (SHIPPED) — container-then-role connectors

Some workloads have no flat assignment object carrying both a principal and a
role. Instead a **container** is resolved from the group, then roles are attached
to that container. The engine now supports this natively: a connector sets
`"membershipModel": true` and adds a `resolveContainer` op (group → container id);
`Apply-PimWorkloadAssignments` resolves the container, lists its roles
(`listContainerRoles`), and attaches/detaches via `assign`/`remove` using the
`{container}` token. (`Get-PimWorkloadContainerId` does the resolve.)

- **`dataverse` (SHIPPED on the adapter)** — Dynamics 365 / Power Platform in-app
  **security roles** (HR org-restructure JIT). Entra group → **group team**
  (`teams?$filter=azureactivedirectoryobjectid eq {groupId} and teamtype eq 2`) →
  roles via `teams({container})/teamroles_association`. Per-environment `baseUrl`
  uses `{resource}` (the org host). Structure built + unit-tested; live-validation
  pending a Dataverse env with the group provisioned as a group team. Roles are
  business-unit scoped — pick the team's BU.
- **`business-central` (SHIPPED on the adapter)** — Dynamics 365 Business Central
  finance **permission sets** (chart-of-accounts JIT). Entra group → BC **security
  group** container (`securityGroups?$filter=azureGroupId eq {groupId}`) → permission
  sets via `securityGroups({container})/permissionSets`. Per-row `Resource =
  tenantId/environment`; `baseUrl = https://api.businesscentral.dynamics.com/v2.0/{resource}/api/microsoft/automation/v2.0`.
  Structure built + unit-tested; **live gap:** confirm the Automation-API entity/path
  names against a live environment's `$metadata` + provision the security group + a
  SUPER app user before flipping to delivered.
- **`azure-devops` (SHIPPED on the adapter)** — Azure DevOps org/project access is
  group **nesting**, not a flat role, so it uses the membership adapter: the "roles"
  are the org/project **security groups** (`_apis/graph/groups`), resolveContainer =
  the Entra group's **subject descriptor** (picked client-side where `originId ==
  groupId` — the new `matchField`/`matchToken` selector), and assign =
  `PUT _apis/graph/memberships/{subject}/{group}`. Per-row `Resource = org`.
  Structure built + unit-tested; **live gap:** an Entra-backed org the engine SPN
  administers (so the group has a subject descriptor).

## Power Platform discovery companion (SHIPPED — planner)

- **`power-platform`** — Power Platform **environment roles** (Environment Admin /
  Maker): flat `roleAssignments` on the BAP admin environment scope, static roles,
  per-row `Resource = environment id`. Pairs with **`PIM-PowerPlatformDiscovery.ps1`**
  (engine `_shared`): a pure planner that derives a `PIM-PowerPlatform-*-T1-WDP-RES`
  group per discovered environment and reconciles discovered-vs-existing
  (create+pending / rename-on-displayName-drift / orphan), **propose-don't-auto-map**
  by default (auto-import only on an explicit rule) — same shape as the Azure scope
  discovery. **Live gap:** wire the launcher's live BAP environment listing
  (`api.bap.microsoft.com/.../environments`) + a Power Platform admin SPN.

## Cmdlet / portal only, or not role-based (no role connector)

- **Exchange Online RBAC role groups** — `Add-RoleGroupMember` (EXO PowerShell).
  *Exchange admin via Entra directory role* is already covered by `entra-roles`.
- **Microsoft Purview** compliance role groups — Security & Compliance PowerShell.
- **Defender for Identity (MDI)** — role groups assigned in the MDI portal; no
  public group-assignment Graph API.
- **Defender for Cloud Apps (MDCA)** & **Defender for Office (MDO)** — admin
  access is Entra directory roles (use `entra-roles`) / part of Defender XDR
  Unified RBAC (use `defender-xdr`); no separate group-role REST.

## Adding a connector

Drop a `*.connector.json` here. Required: `id`, `auth` (graph/arm/powerbi/devops/
businesscentral/dataverse/powerplatform), `api.assign`, `api.remove`, and either
`api.listRoles` or a static `roles[]`. Set `perRowResource: true` to require a per-row
`Resource` column. For nested-membership connectors set `membershipModel: true` +
`api.resolveContainer` (+ optional `matchField`/`matchToken` for client-side container
selection) + `api.listContainerRoles`. The Pester suite (`tests/PIM.Tests.ps1`)
validates every connector file.
