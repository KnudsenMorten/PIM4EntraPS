# Release notes for PIM4EntraPS

## v1.0.1

Latest 30 commits touching SOLUTIONS/PIM4EntraPS/ in the upstream monorepo monorepo:

- release: PIM4EntraPS v1.0.1 - hotfix: 14 .locked.csv data files were silently ignored by monorepo .gitignore (SOLUTIONS/**/config/* rule had no exception for *.locked.*) and missing from v1.0.0 public mirror (0fe0d6d5)
- release: PIM4EntraPS v1.0.0 - restructure to SecurityInsight conventions + .locked/.custom split + customer naming/filter extension points + generic Build-PimContext helper (additive, no engine rewire yet) (12616959)
- port: v1 -> v2 on 14 user-selected solutions (67 engines) (fbe39214)
- rename: SOLUTIONS/PlatformOnboarding -> SOLUTIONS/PlatformConfiguration (368f422e)
- Merge remote-tracking branch 'origin/dev' into HEAD (b8556ec1)
- launchers: fix 4 template bugs preventing internal-vm engine invocation (de585260)
- move Update-Platform.ps1 into SOLUTIONS/PlatformOnboarding/INTERNAL/ (b4a46912)
- chore: standardize PS headers, port Setup-CSA, INTERNAL tooling, README (a060047e)
- feat: portable launcher paths + bundled dependencies in published releases (ccb4b679)
- chore: strip 'AutomateIT' branding from user-facing launcher + doc content (653bac5f)
- rename: TestVariables -> LauncherConfig across the repo (b60390f0)
- restructure: Phase 4a -- launcher renames legacy->vm, cloud->azure (64578bad)
- restructure: Phase 3 -- discovery-based publish workflow + solution.publish.json (f612c18e)
- restructure: Phase 2 -- rewrite all path references to SOLUTIONS layout (d62d155a)
- restructure: Phase 1 -- mechanical move to SOLUTIONS/<X>/<TYPE>/ (3557ece1)

---

# Release notes -- PIM4EntraPS

> **Curated changelog.** The publish workflow auto-prepends recent monorepo commits as a raw activity log; this file is the human-friendly narrative on top.

---

## v1.0.1 -- Hotfix: 14 `.locked.csv` data files were silently ignored by the monorepo `.gitignore` and never reached the public mirror in v1.0.0.

### Why

`SOLUTIONS/**/config/*` rule in the monorepo `.gitignore` had an exception for `*.sample.*` (so `.custom.sample.csv` files shipped) but no exception for `*.locked.*`. The `.locked.ps1` files in v1.0.0 were unaffected because they were renamed from already-tracked `CUSTOMSCRIPTS/` files (`git mv` preserves tracked status); the 14 `.locked.csv` files were newly copied with `cp` and got silently ignored.

### What changed

- Added `!SOLUTIONS/**/config/*.locked.*` exception to the monorepo `.gitignore`.
- Staged + committed the 14 `.locked.csv` files that were missing from v1.0.0.
- No engine, launcher, or helper-file changes.

### Verification

Public mirror `config/` should now show 14 `.locked.csv` files in addition to the 14 `.custom.sample.csv` and 8 `.locked.ps1` / `.custom.sample.ps1` files that shipped in v1.0.0.

---

## v1.0.0 -- Solution restructure to match SecurityInsight conventions; logging, .locked/.custom split, and customer naming/filter extension points.

### Why

PIM4EntraPS was a flat layout of SCRIPTS/, CUSTOMSCRIPTS/, and LAUNCHERS/. As the solution grew (15+ engines, 20+ launcher tasks, 14 CSV data files) the conventions used by SecurityInsight became the right model: per-engine folders, per-task launchers with 4-flavour templates, shared init lib, .locked/.custom split for customer-overridable artifacts, and runtime log + output folders.

### What changed

**Layout (mirror of SecurityInsight)**

- `SCRIPTS/*.ps1` -> `engine/<task>/<task>.ps1` (one folder per engine).
- `LAUNCHERS/<task>/` -> `launcher/<task>/` (subfolder names preserved; 4-flavour templates + manifest + LauncherConfig.sample unchanged).
- `CUSTOMSCRIPTS/<x>.ps1` -> `config/<x>.locked.ps1` (these were policy + helper PS sourced by launchers; now ship as `.locked` so the .custom pattern applies).

**New: shared module**

- `engine/_shared/PIM-Functions.psm1` -- the canonical function library (~542 KB). All engines import this module instead of relying on the legacy 2LINKIT-Functions.psm1. Customer + community editions ship the same module.

**New: config/ folder with .locked / .custom split**

For every CSV (14 files) and PS1 (6 files) that ships from the repo:
- `<name>.locked.<ext>` -- bundled defaults from the repo (authoritative). Engine reads this if no .custom override exists.
- `<name>.custom.sample.<ext>` -- header-only (CSV) or stub (PS1) template a customer copies to `<name>.custom.<ext>`.
- `<name>.custom.<ext>` -- gitignored. Lives only on the customer's VM. Engine prefers this over `.locked` when present.

**New: customer naming + filter extension points**

Two new declarative customization layers in `config/`:

- `PIM4EntraPS.NamingConventions.locked.ps1` (+ `.custom.sample.ps1`) -- name patterns for admin accounts, PIM groups, resource groups, etc. Customers override patterns without forking engine code.
- `PIM4EntraPS.Filters.locked.ps1` (+ `.custom.sample.ps1`) -- scriptblocks that filter which users/groups/roles become PIM candidates. Locked file ships 5 filter kinds matching what the engines have historically done inline: `AdminCandidate`, `PimGroup`, `PimGroupResourceSyncAD`, `PimGroupServiceSyncAD`, `AURoleAllowed`, plus `AzureSubscription` for scope.

**New: generic context builder** (`engine/_shared/PIM-ContextBuilder.ps1`)

Removes the duplicated `Get-MgUser` + `Get-MgGroup` + `Where-Object` blocks from engine scripts. Two functions:

- `Build-PimContext [-Refresh] [-CacheSeconds 300]` -- fetches raw Entra lists once, applies every `$global:PIM_Filters` scriptblock, assigns results to the legacy `$Global:*_Definitions_ID` variable names (backward compatible with current engines). Cached 5min by default; re-call within window is a no-op.
- `Get-PimList -Kind <name>` -- convenience accessor (`Admins`, `PimGroups`, `AURoles`, etc). Auto-triggers `Build-PimContext` on first call.

Engines that adopt this pattern collapse 50+ lines of duplicated Graph-fetch-plus-filter to two lines. The pattern is additive in v1.0.0 -- existing engines keep working unchanged; rewire happens in a follow-up release.

Plus the launcher escape hatch:
- `launcher/<task>/launcher.custom.<flavour>.ps1` -- gitignored. Customer drops a fully replaced launcher here when neither config-driven naming nor filters are enough.

**New: launcher/_lib/ shared init**

- `PIM4EntraPS.shared-defaults.ps1` -- solution-wide default variables (Layer 0).
- `Initialize-LauncherConfig.ps1` -- layered config loader: shared defaults -> .locked PS -> .custom PS -> LauncherConfig.defaults -> LauncherConfig.custom. Final layer wins.
- `Start-LauncherTranscript.ps1` -- creates `logs/<engine>_<flavour>_<utcStamp>.log` on launcher entry.
- `Stop-LauncherTranscript.ps1` -- prunes logs older than `$global:PIM_LogRetentionDays` (default 30).

**New: runtime folders**

- `logs/` -- transcript output, gitignored.
- `output/` -- engine CSV/JSON exports, gitignored.

**New: top-level metadata**

- `VERSION` -- starts at `1.0.0`.
- `.gitignore` -- protects `*.custom.*`, runtime folders, and customer launcher overrides from public publish.

### Migration notes

- **Engines not yet rewired to use new helpers.** The file moves preserve git history (used `git mv`) but engine scripts still source paths via their old launchers; engines will be updated in a follow-up to: (a) import `engine/_shared/PIM-Functions.psm1`, (b) read `.custom.csv` with `.locked.csv` fallback, (c) call `Resolve-AdminName` / `Test-AdminCandidate` helpers instead of hardcoded patterns.
- **Existing customer overrides**: any customer-private files that were previously sitting outside the repo continue to be respected. The new `.custom.*` naming is for new installs; existing customers can rename their override files when convenient.
- **Publish workflow unchanged**: `launcher.internal-*.template.ps1` and folders named `internal/` are still stripped by `.github/workflows/publish.yml`. The new `engine/`, `launcher/`, and `config/` folders all ship to the public mirror.

### GUI mapper design notes (Phase 2, not in v1.0.0)

The CSVs model a 3-tier group-nesting design:

```
Admin                Role group              Permission groups          Target
ADMIN-MOK-ID  --E->  PIM-ROLE-CloudEngineer  --E--> PIM-Entra-ID-AppAdmin-L1-T0-CP-ID --E--> Entra ID role
                                             --A--> PIM-AzDevOps-TeamsContrib-...     --A--> AzDevOps
                                             --E--> PIM-AzRes-MP-Platform-...         --E--> Azure SQL VM / Cosmos
                                             --E--> PIM-PowerBI-WS-MyKPIs-...         --E--> Power BI

Edge labels: E = Eligible, A = Active (PIM activation type)
```

CSV mapping:
- `PIM-Assignments-Admins.csv` = tier 1 edges (admin -> role group, Eligible/Active)
- `PIM-Assignments-Groups.csv` = tier 2 nesting (role group -> permission group)
- `PIM-Assignments-Roles-Groups.csv` / `-Roles-AUs.csv` / `-Azure-Resources.csv` = tier 3 (permission group -> target)

Permission-group names follow `PIM-<Service>-<Name>-L<Level>-T<Tier>-<Code>-<Domain>`, generated from `$global:PIM_NamingConventions.PimGroupPattern`.

The Phase 2 GUI is therefore a **graph editor**, not a flat CSV grid:

1. Tree/sankey view of admin -> role group -> permission groups -> targets.
2. New-admin / new-permission / refactor-role workflows; names auto-generated from the naming-conventions pattern.
3. FK validation: every assignment target must exist in the matching Definitions CSV; naming-pattern match before save.
4. Save semantics: writes `.custom.csv` only (never `.locked.csv`), with diff preview before commit.

### Verification

- `git status` shows all moves as renames (history preserved).
- `engine/` contains 15 task folders + `_shared/PIM-Functions.psm1`.
- `launcher/` contains 21 task folders + `_lib/` (4 lib files).
- `config/` contains 28 CSVs (14 .locked + 14 .custom.sample) + 6 .locked.ps1 (from CUSTOMSCRIPTS) + 2 .locked + 2 .custom.sample (naming + filters).
- `logs/` and `output/` exist with `.gitignore` blocking content.

