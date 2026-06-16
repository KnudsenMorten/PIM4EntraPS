# `tests/scenario/` — end-to-end engine+GUI scenario simulation (REQUIREMENTS §20)

Proves the **engine AND the Manager GUI work together** over a realistic estate, with rich
test data, evaluated critically at three levels (system / UX / use-case). Full reference:
**`docs/TESTS.md` §2.4**.

## Run

```powershell
# both halves via the umbrella runner
powershell -NoProfile -File ..\Run-AllPimTests.ps1 -Scenario

# engine half only (offline; needs SQLEXPRESS, self-skips otherwise)
powershell -NoProfile -File .\Test-PimScenarioSim.ps1

# GUI half only (Playwright; needs Node + SQLEXPRESS)
powershell -NoProfile -File .\Test-PimScenarioGui.ps1 -Install   # first time (npm + Chromium)
powershell -NoProfile -File .\Test-PimScenarioGui.ps1
```

Both halves **self-skip (exit 0)** when prerequisites are missing — a skip is not a pass and
not a failure (mirrors the Live-test doctrine).

## Files

| File | Role |
|---|---|
| `PIM-ScenarioSeedSpec.ps1` | the rich desired-set (paramless, dot-source-safe) — single source of truth |
| `Seed-PimScenarioDataset.ps1` | writes the rich set into the SQL desired store (`pim.Rows`); `-Clear` removes it |
| `PIM-FakeTenant.ps1` | stateful in-memory fake Graph+ARM tenant (lets the REAL engine run offline) |
| `PIM-ScenarioHarness.ps1` | shared harness (store provisioning, engine run, asserts, cache reset) |
| `Test-PimScenarioSim.ps1` | **engine half** — 6 scenarios + idempotency (3-level asserts) |
| `Test-PimScenarioGui.ps1` | **GUI half** wrapper (Playwright) — self-skips without Node/Playwright |
| `gui/` | Playwright specs + a self-contained Manager boot harness (`Start-PimScenarioManager.ps1`) |

## Coordination with the GUI-test PR (`feat/pim-gui-tests` / PR #13)

This suite is **self-contained**: `gui/Start-PimScenarioManager.ps1` boots the SAME
`tools/pim-manager/Open-PimManager.ps1` the GUI-test PR harness boots, with the **same stdout
contract** (`loopback listening on http://127.0.0.1:<port>/` + `session token: <tok>`), so the
two harnesses are drop-in compatible. It deliberately puts the rich scenario specs/data in
**NEW files** under `tests/scenario/` so there is **no merge conflict** with the GUI-test PR's
`tests/playwright/` tree.

When PR #13 merges, the scenario specs can optionally be migrated to reuse its shared
`fixtures.js` + `pages/ManagerPage.js` (page object) instead of the local request-context
helpers here; until then they talk to the documented `/api` contract directly so they run
independently of that PR's merge state.

## Found issues (logged in REQUIREMENTS §11/§20, TESTS.md §2.4a)

The sim is critical, not rubber-stamp. It surfaced three SQL-mode Manager defects:
1. `GET /` 500s in SQL mode (`Build-PimGraphData` path assumption).
2. `GET /api/preflight` 500s in SQL mode (validator's CSV-oriented reader).
3. `PIM-Definitions-Departments` grid edits don't persist (blank store key).
