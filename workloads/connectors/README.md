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

`entra-approle` is the high-leverage one: the *catalog* of 100+ Entra-integrated
apps (`docs/ENTRA-GROUP-APP-CATALOG.md`) collapses to **this single connector**
for every app whose access is an Entra app role. Finance/HR/SecOps JIT use cases
that need *app-level* access (get into SAP / ServiceNow / a custom app) are
covered here.

## Needs a nested-membership adapter (documented spec, NOT shipped as flat JSON)

These do **not** fit the flat model: there is no assignment object carrying both a
principal and a role. Instead a container is resolved from the group, then roles
are attached to the container. A future `nestedMembership` connector mode would
add a `resolveContainer` step (group → container id) before list/assign/remove.
The exact REST is captured here so the build is a spec, not a guess:

- **Dataverse / Dynamics 365** (HR org-restructure, in-app **security roles**):
  Entra group → **group team** (`GET /api/data/v9.2/teams?$filter=azureactivedirectoryobjectid eq {groupId} and teamtype eq 2`), then roles via
  `teams({teamid})/teamroles_association` (`POST .../$ref` with `{"@odata.id":"{baseUrl}/roles({roleId})"}`, `DELETE .../teamroles_association({roleId})/$ref`). Roles: `GET /roles`. Per-environment `baseUrl = https://{org}.crm*.dynamics.com` (token via `$global:PIM_WorkloadTokens['dataverse']`). Note: roles are business-unit scoped — pick the team's BU.
- **Business Central** (finance chart-of-accounts, **permission sets**): BC
  Automation API per environment (`baseUrl = https://api.businesscentral.dynamics.com/v2.0/{tenantId}/{environment}/api/...`). Entra security group → permission set. Entity/path names must be read from the environment's `$metadata` first; not assumed here.
- **Azure DevOps** (org/project access): group **membership**, not roles —
  `POST https://vssps.dev.azure.com/{org}/_apis/graph/memberships/{subjectDescriptor}/{containerDescriptor}`. Requires resolving subject + container descriptors first.

## Cmdlet / portal only (no group-role REST — out of scope for a REST connector)

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
businesscentral/dataverse), `api.assign`, `api.remove`, and either `api.listRoles`
or a static `roles[]`. Set `perRowResource: true` to require a per-row `Resource`
column. The Pester suite (`tests/PIM.Tests.ps1`) validates every connector file.
