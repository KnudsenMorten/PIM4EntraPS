# PIM4EntraPS — /legacy (retired components)

Where superseded engine files + launchers move once the REST/SQL solution replaces
them. **Move a file here only when it is no longer referenced by the active path**
(manager, scheduler, REST engine, launchers, tests) — verify, move, then run the full
test suite before committing.

## Why this is incremental (not a big-bang move)

As of now the **legacy CSV engine is still the active apply path**:
- `engine/PIM-Engine/PIM-Engine.ps1` routes every `-Scope` to
  `engine/PIM-Baseline-Management-CSV[-*Only]/…` (admins, EntraRoles, AzRes, AUs,
  groups assign/policy/create-modify, export). Those scripts + their `launcher/*`
  flavours are **wired and live** — moving them breaks the engine and the customer
  `sync-automateit` download.

So retirement is gated on two things, in order:
1. the **REST write-path** replacing each `-Scope`'s apply (the de-CSV work), and
2. **coordination with the sync/rebrand** download path so customers aren't broken.

## Retirement order (move each only after its REST replacement is green)
- [ ] `PIM-Baseline-Management-CSV-AdminsOnly` → REST admins apply
- [ ] `…-EntraIDRolesOnly` → REST entra PIM apply
- [ ] `…-AzResOnly` → REST azure PIM apply
- [ ] `…-AdministrativeUnitsOnly` → REST AU apply
- [ ] `…-PIM4GroupsAssignmentOnly` / `…GroupsPoliciesOnly` / `…GroupsCreateModifyPolicyOnly`
- [ ] `PIM-Baseline-Management-CSV` (the all-scope legacy entrypoint)
- [ ] the matching `launcher/*` flavours for each of the above
- [ ] any standalone tools confirmed unreferenced

Keep this checklist updated as items move; each move is its own commit with the test
suite green.
