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

## Retired so far

| Moved | When | Why it was safe |
|---|---|---|
| `config/PIM-SQL-import-export-CSV.locked.ps1` → `legacy/config/` <br> `launcher/PIM-SQL-import-export-CSV/` → `legacy/launcher/` | 2026-08-06 (REQUIREMENTS §33 · **IMP-05**) | A 1,005-line one-time SQL bootstrap helper that built ~24 statements by string interpolation. **Not on the active path** — verified by repo-wide grep: nothing under `engine/`, `tools/`, the scheduler or the tests referenced it; the only references were its own launcher flavours, which moved with it. Its replacement is `PIM-SqlStore.ps1`, which binds every statement with `SqlParameter`. Hardening a file scheduled to leave was the wrong trade. |

⚠️ **`legacy/` still PUBLISHES.** The `publish.yml` strip removes `internal`, `logs`, `staging`,
`demo` and `output` — **not** `legacy`. Retiring a component moves it out of the active path, not
out of the customer download, so it must still be clean: `legacy` is included in the
`$shippedDirs` scanned by `tests/Test-PimSourceSanitization.ps1` for exactly that reason.

`config/SQL-Connect.locked.ps1` (+ `launcher/SQL-Connect/`) is the same one-time SQL-onboarding
vintage and is the obvious next candidate — **not** moved yet, because unlike the above it has not
been confirmed unreferenced. Confirm, then move.

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
