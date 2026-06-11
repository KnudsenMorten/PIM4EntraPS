# Workload Connectors -- applying PIM groups to workload RBAC

Status: DESIGN (approved direction, implementation phased)
Owner: maintainer-curated; connectors ship with the repo like permission templates.

## Problem

PIM v2 delegates least privilege by nesting admins into PIM groups. The LAST
mile -- binding those groups to each workload's own RBAC (Defender XDR Unified
RBAC, Intune's 14+ built-in roles, Power BI workspace roles, Dataverse/Dynamics
security roles, Business Central permission sets, Azure-hosted AI services) --
is manual portal work today. The Manager + engine must do it.

## Principles

1. **GUI stages, engine applies.** The Manager never writes to workloads
   directly. Operators stage desired state; the tenant's engine applies it on
   its normal pull cycle with its own SPN. Same trust model as everything else.
2. **Everything maintainable as text files.** New workload, new endpoint, new
   role mapping = edit JSON / CSV, never code (as long as the auth adapter
   exists).
3. **SQL-ready.** Desired state is row-shaped; connectors are documents.

## The three layers

### 1. Connector definitions (maintainer-curated, shipped via repo)

`workloads/connectors/<id>.connector.json` describes HOW to talk to one
workload: which auth adapter, which endpoints, how to list roles, how to
assign/remove a group. Adding a workload or a new API version = drop/edit a
JSON file.

```json
{
  "id": "defender-xdr",
  "name": "Microsoft Defender XDR (Unified RBAC)",
  "auth": "graph",
  "permissionsNeeded": ["RoleManagement.ReadWrite.Defender"],
  "api": {
    "baseUrl": "https://graph.microsoft.com/beta",
    "listRoles": {
      "method": "GET", "path": "/roleManagement/defender/roleDefinitions",
      "itemsPath": "value", "roleId": "id", "roleName": "displayName"
    },
    "listAssignments": {
      "method": "GET", "path": "/roleManagement/defender/roleAssignments",
      "itemsPath": "value", "principalIds": "principalIds", "roleId": "roleDefinitionId"
    },
    "assign": {
      "method": "POST", "path": "/roleManagement/defender/roleAssignments",
      "body": {
        "displayName": "PIM4EntraPS: {groupTag} -> {roleName}",
        "roleDefinitionId": "{roleId}",
        "principalIds": ["{groupId}"],
        "directoryScopeIds": ["{scope|/}"]
      }
    },
    "remove": { "method": "DELETE", "path": "/roleManagement/defender/roleAssignments/{assignmentId}" }
  }
}
```

`{tokens}` are substituted by the engine: `{groupId}` (resolved from GroupTag
via the group cache), `{roleId}` (resolved live from listRoles by name),
`{scope|default}`, `{assignmentId}` (from the diff). Roles are never hardcoded
-- they load live, so when Microsoft adds roles, pickers and validation see
them with zero maintenance. For workloads without a role-listing API the
connector may carry a static `"roles": [...]` array instead (same JSON file,
still no code).

### 2. Desired state (per tenant, operator-edited)

`config/PIM-Assignments-Workloads.custom.csv` -- the 15th configuration file,
same lifecycle as the other 14 (Manager grid + Delegation Map staging +
Review & Save + MSP sync + ring-independent, since these are group-level):

```
Workload;RoleName;GroupTag;Scope;Action;Notes
defender-xdr;Security operator;Defender-XDR-SecurityOperations-Operator-L3;/;Assign;
intune;Help Desk Operator;Intune-Helpdesk-L3;;Assign;
powerbi;Admin;PowerBI-Workspace-Finance-Admin-L2;{workspaceId};Assign;Finance workspace
```

Manager UX: the **Maintenance** tab gains a Workload Delegation panel --
pick workload (from connectors) -> roles load LIVE via the connector ->
pick PIM group (groups cache) -> stage the row. No typed role names.

### 3. Engine applier

`Apply-PimWorkloadAssignments` (PIM-Functions.psm1) runs as a launcher step:

1. Read desired rows; resolve GroupTag -> group objectId (cached).
2. Per workload: acquire token via the AUTH ADAPTER, list roles, list current
   assignments, **diff** desired vs actual.
3. Apply: POST missing assigns, DELETE rows marked Action=Remove. Idempotent;
   honors -WhatIfMode (prints the plan); logs one line per change.

## Auth adapters (code, small, stable)

| Adapter | Token | Used by |
|---|---|---|
| `graph` | existing app-only Graph session (Modern SPN) | Defender XDR (`/roleManagement/defender/*`, perm `RoleManagement.ReadWrite.Defender`), Intune (`/deviceManagement/roleDefinitions` + `/roleAssignments`, perm `DeviceManagementRBAC.ReadWrite.All`), Entra-adjacent workloads |
| `arm` | Az token | Azure-hosted AI (Azure OpenAI / AI Foundry / Cognitive Services) -- these are PLAIN ARM RBAC and largely already covered by `PIM-Assignments-Azure-Resources` (e.g. role "Cognitive Services OpenAI User" at resource scope); a connector only adds role-name pickers |
| `powerbi` | resource `https://analysis.windows.net/powerbi/api` (SP must be allowed in Power BI tenant settings) | Workspace roles via `POST /v1.0/myorg/groups/{workspaceId}/users` with `groupUserAccessRight` Admin/Member/Contributor/Viewer and the PIM group as principal |
| `dataverse` | per-environment resource (`https://{org}.crm.dynamics.com`) + app user | Dynamics CRM/CE: create/ensure an **Entra group team** bound to the PIM group, then associate Dataverse **security roles** to that team (`/api/data/v9.2/teams`, `teamroles_association`) |
| `businesscentral` | BC service-to-service (admin + automation APIs) | BC supports Entra **security groups**: assign permission sets to the group via the automation API (`/api/microsoft/automation/v2.0/.../securityGroups`) |

Adapters are the only code; everything above them is JSON + CSV.

## Discovery companions (same framework)

Connectors may also declare a `discover` endpoint (e.g. Power BI
`GET /v1.0/myorg/groups` for workspaces; ARM for new subscriptions /
management groups). Discovery results stage PROPOSED definition rows
("new workspace 'Finance' found -- create PIM groups + workload assignment?")
into pending, so new resources become delegable on the Delegation Map
minutes after they exist.

## Phasing

1. **Phase 1 (SHIPPED v2.4.142)**: connector schema + `defender-xdr` +
   `intune` connectors (both pure Graph, same token we already hold);
   `PIM-Assignments-Workloads` CSV + engine applier
   (`Apply-PimWorkloadAssignments -WhatIfMode`); Manager panel on the
   Maintenance tab with live role pickers.
2. **Phase 2**: `powerbi` adapter + workspace discovery.
3. **Phase 3**: `dataverse` (group teams) + `businesscentral` (security
   groups); both need per-environment app users -- bootstrap docs per tenant.
4. **Phase 4**: drift report -- engine compares desired vs actual per workload
   and the Validate tab shows workload-side drift like any other finding.

## Lifecycle / maintenance phases (operator-requested)

5. **Right-sizing recommendations from activation stats**: pull PIM
   activation history (Graph audit logs / `roleAssignmentScheduleInstances`)
   per group + role; surface "0 activations in N days" findings on the
   Validate tab with a one-click stage-for-removal -- least privilege by
   subtraction, driven by evidence.
6. **Deleted-resource auto-cleanup**: when discovery sees an Azure scope (or
   Power BI workspace) referenced by `PIM-Assignments-Azure-Resources` /
   workload rows that no longer exists, stage removal of the rows AND mark the
   backing PIM groups + workload delegations for backend cleanup (engine
   deletes the Entra groups it created once nothing references them) -- no
   leftovers in config or tenant.
7. **Orphaned PIM-group detection**: tenant-side groups matching the PIM
   naming convention with no corresponding Definitions row (or vice versa) --
   reported as drift with stage-to-adopt / stage-to-delete actions.
