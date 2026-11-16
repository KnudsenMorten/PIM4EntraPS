# Support fix catalog (SUPPORT-FIX-API-1, framework §12.30) -- PIM Manager 3.1.31

`POST /api/app/support/fix { failureId, fixId, reason }` (the Support role only; `reason` carries `SUP-YYYY-NNNNN`) applies a
fix ONLY when (1) the fixId is in this catalog and (2) it is offered for the failure's code (by the failure catalog, or for
`create-defender-role` by this catalog's own code list). It locates exactly one row from the failure's own values (never a
guess: no match or several = 409), saves through the normal commit path and its guards (or queues one engine action),
mails the install's alert recipients and audits `support.change` with the app and the ticket. The same ticket + fix sent
again answers "already applied" and writes nothing. With SupportFixMode = approve the fix becomes a proposal an Admin or
SuperAdmin of the install approves.

| fixId | what it changes | never | offered for |
|---|---|---|---|
| `delete-row` | removes the one row the failure names (stops managing it) | adds access; touches a person-only setting or Account-Definitions-Companies | AZ-SUB-PLACEHOLDER, AZ-SUB-NOT-FOUND, ARM-ROLE-NOT-FOUND, ENTRA-ROLE-NOT-IN-TENANT, WORKLOAD-REMOVE-NEEDS-DATA, WORKLOAD-CONNECTOR-UNKNOWN, WORKLOAD-ROLE-GONE, WORKLOAD-ROLE-NOT-FOUND, WORKLOAD-RESOURCE-MISSING |
| `make-eligible` | sets `AssignmentType = Eligible` on the one row the failure names | adds access; changes any other column | AZ-POLICY-MAX-DURATION, AZ-POLICY-MFA, ENTRA-NESTING-ROLE-ASSIGNABLE |
| `create-defender-role` | creates the ONE missing Defender XDR custom role with exactly the name and the permissions (allowedResourceActions) PIM's definition lists, and PIM's managed-role description marker -- by the ENGINE identity through one queued action (`defender-role-create`), never the Support app's token. Counted as 1 row in the hourly limit. | creates anything else, a permission that is not `microsoft.xdr/...`, or a second role of the same name; a Defender refusal (e.g. Data Operations without Sentinel: "not a valid permission for storage") is reported plainly and nothing is created | DEFENDER-ROLE-MISSING only (owner 2026-11-16 "Support creates them on a ticket"; the one exception to "PIM never creates a Defender role", which stays true for the engine's own runs) |

Source of truth: `Get-PimManagerAppSupportFixCatalog` (engine/_shared/PIM-ManagerApiApps.ps1); the engine half:
`Invoke-PimQueueDefenderRoleCreate` (engine/_shared/PIM-QueueActions.ps1). `tests/Test-PimManagerSettingsApi.ps1` O3 fails
when the failure catalog offers a fix that is not in this catalog, or a catalog fix could change a person-only setting; F1-F7
cover create-defender-role.
