# PIM4EntraPS — live delegation lab

End-to-end **live** validation of the delegation model: a workload owner delegating
access to resources across two Azure subscriptions + Power BI, an AU-scoped helpdesk
(L2), an L2 approver (helpdesk manager), and an external consultant (guest) whose
access the workload owner manages. Provisions real objects in a tenant, then runs the
real engine decision functions over them.

## What it provisions (live)
- **Administrative Unit** `PIMLAB-AU-Helpdesk` (HiddenMembership)
- **Personas**: `pimlab-owner-azure`, `pimlab-owner-powerbi`, `pimlab-admin-helpdesk`,
  `pimlab-admin-helpdeskmanager` (on the routing onmicrosoft.com domain)
- **External consultant**: a guest invitation (cloud-only), `sendInvitationMessage=false`
- **PIM groups** (naming grammar `PIM-{Service}-{Name}-L{Level}-T{Tier}-{Code}-{Domain}`):
  `PIM-PBI-WorkspaceContributor-L1-T1-APP-ID`, `PIM-AzRes-ResourceOwner-L1-T1-APP-RES`,
  `PIM-Entra-Helpdesk-L2-T2-USER-ID`
- **AU-scoped Helpdesk Administrator** (the L2 admin, scoped to the AU only)
- **Azure RBAC**: `rg-pimlab-test` + Contributor → the AzRes PIM group, in **both** subs
- **Power BI**: workspaces `PIMLAB-Workspace-Finance` / `-Sales`

State (object ids) is written to `pimlab-state.json` (gitignored — holds tenant
identifiers, no secrets).

## Run
```powershell
# 1) provision (reuses your `az login`; idempotent find-or-create)
.\Provision-PimLab.ps1 -UpnDomain '<tenant>.onmicrosoft.com' -Subs '<sub1>','<sub2>'

# 2) validate the engine against the live objects (pure logic, no further writes)
.\Test-PimLabDelegation.ps1

# 3) tear down everything it created
.\Provision-PimLab.ps1 -UpnDomain '<tenant>.onmicrosoft.com' -Subs '<sub1>','<sub2>' -Cleanup
```

Auth: tokens for Graph / ARM / Power BI come from `az account get-access-token`, so
there's no Graph-module version coupling. Needs a signed-in user with directory-write
(create users/groups/AUs/scoped roles), Owner/UAA on the subs, and Power BI workspace
creation rights.

## What the validation asserts (28 checks)
A) naming-grammar facet parsing · B) approver routing (workload×tier×level) ·
C) L2 approval flow (helpdesk manager approves, Power BI owner cannot) ·
D) business owner manages the external consultant + access, with cross-workload and
scope isolation · E) helpdesk L2 AU/level/service scoping (can't touch T0/L0 or other
workloads) · F) layered approval + time-based escalation · G) PAW gate is opt-in (off
by default).
