# PIM Manager GUI test suite — feature-suite (Playwright)

Browser-automation tests that drive the **real** PIM4EntraPS Manager GUI
(`tools/pim-manager/pim-manager.html`, served by `Open-PimManager.ps1 -Server`)
end-to-end, asserting both the rendered result of each GUI action **and** its API
effect. Each spec maps to a chapter of `docs/FEATURES.md`.

Lives at `tests/playwright/feature-suite/`. It is **distinct from** the co-located
per-tab real-browser render validator (`tests/playwright/manager-gui-validation.spec.ts`,
driven by `tools/Run-PimGuiValidation.ps1`); the two suites keep separate
`package.json` + Playwright config so neither shadows the other.

> Internal test asset — not published.

## Harness model

**Primary — local instance (default).** `harness/Start-PimManagerForGui.ps1`:
1. seeds a throwaway, marker-fenced (`PIMCOREENGINE-`) desired-set into a local
   SQLEXPRESS `pim.Rows` database (via `tests/live/Seed-PimBaselineDataset.ps1`,
   which auto-creates the DB + schema) — no tenant, no Graph, no Azure;
2. boots `Open-PimManager.ps1 -Server -NoLaunch` in **SQL mode**
   (`PIM_SqlServer`/`PIM_SqlDatabase` → the Manager's SQL-only store path),
   captures the per-session bearer token printed at launch, and writes
   `harness/.manager.json` = `{ baseUrl, token, pid, role, db }`;
3. `harness/global-setup.js` reads that sidecar; the `pim` fixture loads
   `baseUrl/?token=<token>` so the page's own `/api/*` calls are authenticated, and
   the `api` fixture attaches `Authorization: Bearer <token>` for direct API
   assertions. A heartbeat keeps the loopback server alive (it self-exits after
   ~30 s of silence). `global-teardown.js` stops the Manager and drops the DB.

Driving a **local** instance exercises the real GUI + real backend without the
Entra Easy Auth wall on the hosted `ca-pim-manager` (which is impractical to drive
interactively).

**Optional — live smoke.** Set `PIM_GUI_LIVE_URL` + `PIM_GUI_LIVE_TOKEN` (an
injected Easy-Auth/session bearer) to point the suite at the hosted Manager
instead of booting locally; run `@live`-tagged specs with `-Live`.

**Self-skip.** If Node, the `@playwright/test` package, a Chromium browser, or a
reachable SQLEXPRESS is missing, the runner prints a SKIP and exits 0 — absence is
not a failure (mirrors the PowerShell Live-test rule). `@live` specs are excluded
unless `PIM_GUI_LIVE` is set.

## Run it

```powershell
# first-time setup (npm deps + Chromium) then run the offline suite:
powershell -NoProfile -File tests\playwright\feature-suite\Run-PimGuiTests.ps1 -Install

# normal offline run:
powershell -NoProfile -File tests\playwright\feature-suite\Run-PimGuiTests.ps1

# role-tier matrix (boots once per SuperAdmin/Admin/Reader/Delegated):
powershell -NoProfile -File tests\playwright\feature-suite\Run-PimGuiTests.ps1 -AllRoles

# include @live specs against the hosted Manager:
powershell -NoProfile -File tests\playwright\feature-suite\Run-PimGuiTests.ps1 -Live `
  -LiveUrl https://<ca-pim-manager-url> -LiveToken <bearer>

# via the umbrella runner:
powershell -NoProfile -File tests\Run-AllPimTests.ps1 -Gui
```

Or directly with the Playwright CLI (after `-Install` once):

```powershell
cd tests\playwright\feature-suite
$env:PIM_SqlServer='.\SQLEXPRESS'; $env:PIM_SqlDatabase='PimGuiTest'
npx playwright test            # all offline specs
npx playwright test --ui       # interactive
npx playwright show-report     # last HTML report
```

## Layout

```
tests/playwright/feature-suite/
  package.json                  @playwright/test dependency + npm scripts
  playwright.config.js          one chromium project, single worker, @live grep-invert
  fixtures.js                   pim / api / mgr fixtures (auth + heartbeat + self-skip)
  pages/ManagerPage.js          page object — every selector taken from the HTML
  harness/
    Start-PimManagerForGui.ps1  seed local SQL + boot Manager + emit sidecar (+ -Stop)
    global-setup.js             boot (or accept live URL) and write the sidecar
    global-teardown.js          stop the Manager + drop the throwaway DB
  specs/                        one file per FEATURES.md area (see coverage matrix in docs/TESTS.md)
  Run-PimGuiTests.ps1           prerequisite-checked entrypoint (self-skips)
```

The per-feature coverage matrix lives in `docs/TESTS.md` (§ "GUI suite").
