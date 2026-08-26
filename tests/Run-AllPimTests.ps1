#Requires -Version 5.1
<#
.SYNOPSIS
    Run the full PIM4EntraPS test suite. Offline -- no live tenant required.
.DESCRIPTION
    ONE CANONICAL INVENTORY, DISCOVERED FROM DISK (audit findings TEST-01 / TEST-02).

    This runner used to carry TWO hand-maintained suite lists -- one inside the Pester
    branch (via PIM.Tests.ps1's fan-out) and a separate hardcoded list in the else-branch
    -- and they drifted. The consequences were invisible and lasted months:

      * 9 suites ran ONLY when Pester was ABSENT, i.e. never on a normal dev box:
        EngineCore, DisableGuard, MapRisk, Governance, AccessReporting, FeatureCatalog,
        ExemptionRegister, AlertChannels, GuiConformanceModal -- 362 green assertions,
        including the 50 covering the ACCOUNT-DISABLE CIRCUIT BREAKER (the 2026-06-15
        incident). Two more (Drift, InactivitySweep) ran only when Pester WAS present.
      * 5 suites were in NEITHER list and never ran at all. Two of those had quietly
        gone red -- not because the product broke, but because the tests had gone stale
        (the locked schema gained columns; the maker/checker gate shipped). Dropping a
        suite from the runner was easier than updating it, so nobody saw them again.

    So the lists are gone. The inventory is now DISCOVERED FROM DISK and every file must
    be accounted for in exactly one bucket:

      StandaloneGates  -- run DIRECTLY in BOTH branches (never selector-skippable)
      PesterFormat     -- *.Tests.ps1 (+ Test-PimDownlinkJob.ps1) driven by Invoke-Pester
      Functional       -- everything else: Test-Pim*.ps1 run as child processes
      Excluded         -- explicit, WITH A REASON (see $ExcludedSuites)

    A Test-Pim*.ps1 that is in none of those FAILS THE RUN with "unaccounted suite".
    You can still exclude a suite -- you just cannot do it silently. That check is the
    whole point: it is what stops this class of rot recurring.

    In the Pester branch the functional suites already fanned out by PIM.Tests.ps1 are
    detected by PARSING it at runtime, so they are not run twice and the two paths cannot
    drift apart again.
.PARAMETER Scenario
    Also run the end-to-end engine+GUI SCENARIO SIMULATION (REQUIREMENTS.md §20).
.PARAMETER Gui
    Also run the Playwright Manager GUI suite (tests/playwright/feature-suite/Run-PimGuiTests.ps1).
.PARAMETER GuiInstall
    Pass -Install to the GUI runner (npm install + Chromium) before running it.
.EXAMPLE
    powershell -NoProfile -File tests\Run-AllPimTests.ps1
.EXAMPLE
    powershell -NoProfile -File tests\Run-AllPimTests.ps1 -Scenario       # +engine+GUI scenario sim
.EXAMPLE
    powershell -NoProfile -File tests\Run-AllPimTests.ps1 -Gui            # +browser-automation GUI suite
#>
[CmdletBinding()] param(
    [switch]$Scenario,
    [switch]$Gui,
    [switch]$GuiInstall
)
$here = $PSScriptRoot
$exitCode = 0

# Belt-and-braces: clear any leftover headless Manager from a prior crashed/aborted run
# so a zombie never holds a port or leaks a token into a fresh run's stdout.
. (Join-Path $here '_shared\PimManagerBoot.ps1')
try { Stop-PimStaleManagers } catch {}

# =====================================================================================
# CANONICAL INVENTORY
# =====================================================================================

# Standalone gates -- run directly, in BOTH branches. These are the release gates; an
# auth/doc/enforcement gate must never depend on whether Pester happens to be installed.
$StandaloneGates = [ordered]@{
    'Test-PimDocImages.ps1'                 = 'DOC-IMAGE PRESENCE GATE'
    'Test-PimActivatorPublishedVersion.ps1' = 'ACTIVATOR PUBLISHED-VERSION GATE'
    'Test-PimSmokeVersionCheck.ps1'         = 'HOSTED-SMOKE VERSION-CHECK GATE'
    'Test-PimManagerServerEnforcement.ps1'  = 'SERVER-SIDE ENFORCEMENT GATE'
    'Test-PimHostedAuth.ps1'                = 'HOSTED PRINCIPAL AUTH GATE (SEC-01)'
}

# Pester-format files. Discovered (*.Tests.ps1) plus the one Test-Pim*-named file that is
# actually written as Pester rather than as a standalone script.
$PesterExtra = @('Test-PimDownlinkJob.ps1','Test-PimReachability.ps1')

# EXPLICIT exclusions. Every entry needs a REASON. An empty table is the healthy state.
# Adding one here is a deliberate, reviewable act -- which is exactly what was missing
# when five suites silently fell out of the runner.
$ExcludedSuites = [ordered]@{
    # 'Test-PimSomething.ps1' = 'why this cannot run in the offline gate'
}

# =====================================================================================
# OUT-OF-TREE SUITES (TEST-07)
# =====================================================================================
# The anti-rot guard below originally scanned tests/ ONLY, and non-recursively -- so a
# test-shaped file anywhere else in the solution was invisible to it. That is exactly
# the rot TEST-01/TEST-02 closed, still open one directory over: it hid
# Test-PimActivatorIntuneDiscovery.ps1, the SOLE cover for Intune managed-policy
# discovery, which was run by nothing at all.
#
# Every test-shaped .ps1 outside tests/ must now appear in ONE of these two tables.
# Anything else fails the run, by path, with the same "unaccounted" message.

# Out-of-tree suites that DO run here (offline, no network, no tenant, no browser).
$OutOfTreeSuites = [ordered]@{
    'tools\pim-activator\tests\Test-PimActivatorIntuneDiscovery.ps1' = 'Intune policy discovery + merge (offline, mock policies) -- TEST-07'
}

# Out-of-tree suites that do NOT run here. Same contract as $ExcludedSuites: a reason is
# mandatory, and "it lives somewhere awkward" is not one.
$OutOfTreeExcluded = [ordered]@{
    'tests\live\PIM.DeployValidation.Tests.ps1'           = 'LIVE: needs a real tenant (docs/TESTS.md ss3)'
    'tests\live\Test-PimLabDelegation.ps1'                = 'LIVE: needs the provisioned delegation lab'
    'tests\live\Test-PimManagerHostedSmoke.ps1'           = 'LIVE: post-deploy gate against the hosted Manager (ss1a)'
    'tests\live\Test-PimRestEngineLive.ps1'               = 'LIVE: needs a real tenant'
    'tests\live\Test-PimRestNoModules.ps1'                = 'LIVE: needs a real tenant'
    'tests\live\Test-PimScenarioMatrix.ps1'               = 'LIVE: needs the seeded scenario dataset'
    'tests\live\Test-PimScenarioCleanupComplete.ps1'      = 'LIVE + DESTRUCTIVE: it RUNS the real PIMSCEN sweep against every tenant in -TenantJson, so it can only be run deliberately, after a scenario run, against the test tenants. Proves 33.7.f criterion 6 (cleanup is COMPLETE and CONTAINED) -- docs/TESTS.md ss3.3'
    'tests\live\Test-PimFunctionalMatrix.ps1'             = 'LIVE + DESTRUCTIVE (TEST-11): needs a real TEST tenant and creates/disables/deletes PIMTEST-marked objects in it. It refuses to run unless the connected tenant is in PIM_TestTenantIds, so it can never run from this offline suite -- and it must not, or a CI runner with ambient credentials would start mutating a directory. Run it deliberately (docs/TESTS.md ss3.4)'
    'tests\live\Test-PimTieredDelegation.ps1'             = 'LIVE: needs a real tenant'
    'tests\scenario\Test-PimScenarioGui.ps1'              = 'runs under -Scenario (Invoke-PimScenarioSuites)'
    'tests\scenario\Test-PimScenarioSim.ps1'              = 'runs under -Scenario (Invoke-PimScenarioSuites)'
    'tests\scenario\Test-PimScenarioMspPair.ps1'          = 'runs under -Scenario (Invoke-PimScenarioSuites)'
    'tests\gui\Verify-PimManagerSafetyGui.ps1'            = 'Playwright driver: needs a browser + a booted Manager'
    'tools\pim-activator\Test-PimActivatorFlow.ps1'       = 'needs INTERACTIVE Graph sign-in (delegated scopes)'
    'tools\pim-activator\Test-PushTenantCatalog.ps1'      = 'writes a real Intune configuration profile'
    'tools\pim-activator\Verify-PimActivatorIntunePolicy.ps1' = 'runs ON a managed endpoint; reads HKLM after an Intune sync'
    'tools\pim-activator\Test-PimActivatorPackage.ps1'    = 'a dot-sourceable linter, already driven by tests\PIM.Activator.Tests.ps1'
    'tools\pim-activator\tests\Test-PimActivatorHybrid.ps1' = 'REDUNDANT: tests\PIM.ActivatorHybrid.Tests.ps1 covers the same builder/parity/registry-plan ground, in the run path'
    'tools\setup\Test-PimDeployedVersionDrift.ps1' = 'LIVE + SCHEDULED (TEST-09): needs az + a deployed fleet, and must NOT run from a deploy/CI gate or it inherits the blind spot it closes. Its pure core is covered by tests\Test-PimVersionDrift.ps1'
    'tools\setup\Test-PimTenantReady.ps1'          = 'NOT A TEST -- it is the DEPLOY-TIME READINESS PROBE (framework DEPLOY-2 ss6), named Test-Pim* because it answers "is this tenant ready", so the anti-rot scan finds it. Run as a suite it reports NOT READY (0/7) against whatever tenant it is not pointed at, which is correct behaviour and a meaningless suite verdict. Its offline cover -- contract shape, framework-interpreter round-trip, fail-closed degradation, read-only -- is tests\Test-PimTenantReady.ps1, which IS in the run path'
}

$allTestPim   = @(Get-ChildItem $here -File -Filter 'Test-Pim*.ps1' | Select-Object -ExpandProperty Name | Sort-Object)
$pesterOnDisk = @(Get-ChildItem $here -File -Filter '*.Tests.ps1'   | Select-Object -ExpandProperty Name | Sort-Object)
$PesterFiles  = @($pesterOnDisk + ($PesterExtra | Where-Object { $allTestPim -contains $_ })) | Sort-Object -Unique
$Functional   = @($allTestPim | Where-Object {
                    -not $StandaloneGates.Contains($_) -and
                    $PesterFiles -notcontains $_ -and
                    -not $ExcludedSuites.Contains($_)
                 }) | Sort-Object

# ---- the anti-rot check: nothing test-shaped on disk may be unaccounted for ----------
# NOTE the scan is DELIBERATELY BROADER than the discovery pattern above. Anything named
# Test-Pim*.ps1 lands in $Functional by construction and therefore auto-runs -- so
# checking only that pattern would be a tautology that can never fire (it was, on the
# first cut of this). The gap that actually bites is a suite named OUTSIDE the Test-Pim*
# convention -- Verify-*, Test-<something-not-Pim>* -- which discovery would skip in
# silence. Nothing enforces the naming convention, so the guard must not assume it.
$script:PimInventoryProblems = @()
$KnownNonSuites = @('Run-AllPimTests.ps1')
$testShaped = @(Get-ChildItem $here -File -Filter '*.ps1' |
                Select-Object -ExpandProperty Name |
                Where-Object { $_ -match '^(Test|Verify)-' -or $_ -match '\.Tests\.ps1$' } |
                Where-Object { $KnownNonSuites -notcontains $_ } | Sort-Object -Unique)
$accounted   = @($StandaloneGates.Keys) + $PesterFiles + $Functional + @($ExcludedSuites.Keys)
$unaccounted = @($testShaped | Where-Object { $accounted -notcontains $_ })

# ---- TEST-07: the same guard, over the WHOLE solution, by relative path --------------
# Scans every test-shaped .ps1 outside the tests/ ROOT (the block above owns that) and
# requires each to be in $OutOfTreeSuites or $OutOfTreeExcluded. Paths are compared
# case-insensitively with normalised separators so it behaves the same however the
# repo was cloned. node_modules is skipped -- third-party test files are not ours.
$solutionRoot   = Split-Path -Parent $here
$outOfTreeFound = @()
try {
    $outOfTreeFound = @(Get-ChildItem -LiteralPath $solutionRoot -Recurse -File -Filter '*.ps1' -ErrorAction SilentlyContinue |
        Where-Object {
            $leaf = $_.Name
            ($leaf -match '^(Test|Verify)-' -or $leaf -match '\.Tests\.ps1$') -and
            $_.FullName -notmatch '\\node_modules\\' -and
            $KnownNonSuites -notcontains $leaf -and
            # the tests/ ROOT is handled by the in-tree guard above; subfolders are NOT
            (Split-Path -Parent $_.FullName) -ne $here
        } |
        ForEach-Object { $_.FullName.Substring($solutionRoot.Length).TrimStart('\','/') } | Sort-Object -Unique)
} catch { $outOfTreeFound = @() }

$outOfTreeKnown = @(@($OutOfTreeSuites.Keys) + @($OutOfTreeExcluded.Keys) | ForEach-Object { "$_".Replace('/','\').ToLowerInvariant() })
$outOfTreeUnaccounted = @($outOfTreeFound | Where-Object { $outOfTreeKnown -notcontains "$_".Replace('/','\').ToLowerInvariant() })

# A declared entry that no longer exists on disk is also rot -- it reads as coverage.
$outOfTreeFoundLc = @($outOfTreeFound | ForEach-Object { "$_".Replace('/','\').ToLowerInvariant() })
$outOfTreeMissing = @(@(@($OutOfTreeSuites.Keys) + @($OutOfTreeExcluded.Keys)) |
                      Where-Object { $outOfTreeFoundLc -notcontains "$_".Replace('/','\').ToLowerInvariant() })

Write-Host ("`n== SUITE INVENTORY (discovered from disk) ==") -ForegroundColor Magenta
Write-Host ("   standalone gates : {0}" -f $StandaloneGates.Count)
Write-Host ("   Pester-format    : {0}" -f $PesterFiles.Count)
Write-Host ("   functional       : {0}" -f $Functional.Count)
Write-Host ("   out-of-tree      : {0} run, {1} excluded (of {2} found)" -f $OutOfTreeSuites.Count, $OutOfTreeExcluded.Count, $outOfTreeFound.Count)
if ($ExcludedSuites.Count) {
    Write-Host ("   EXCLUDED         : {0}" -f $ExcludedSuites.Count) -ForegroundColor Yellow
    foreach ($k in $ExcludedSuites.Keys) { Write-Host ("     - {0} -- {1}" -f $k, $ExcludedSuites[$k]) -ForegroundColor Yellow }
}
if ($unaccounted.Count) {
    Write-Host ("`n  UNACCOUNTED SUITE(S) -- {0} test file(s) exist on disk but are in no run path:" -f $unaccounted.Count) -ForegroundColor Red
    foreach ($u in $unaccounted) { Write-Host ("    - $u") -ForegroundColor Red }
    Write-Host "  Add each to a run path, or to `$ExcludedSuites WITH A REASON. A test that" -ForegroundColor Red
    Write-Host "  silently never runs is worse than no test -- it reads as coverage." -ForegroundColor Red
    $exitCode = 1
    $script:PimInventoryProblems += ("{0} unaccounted suite(s) in tests\: {1}" -f $unaccounted.Count, ($unaccounted -join ', '))
}
if ($outOfTreeUnaccounted.Count) {
    Write-Host ("`n  UNACCOUNTED OUT-OF-TREE SUITE(S) -- {0} test file(s) outside tests\ are in no run path:" -f $outOfTreeUnaccounted.Count) -ForegroundColor Red
    foreach ($u in $outOfTreeUnaccounted) { Write-Host ("    - $u") -ForegroundColor Red }
    Write-Host "  Add each to `$OutOfTreeSuites (it runs) or `$OutOfTreeExcluded (WITH A REASON)." -ForegroundColor Red
    $exitCode = 1
    $script:PimInventoryProblems += ("{0} unaccounted out-of-tree suite(s): {1}" -f $outOfTreeUnaccounted.Count, ($outOfTreeUnaccounted -join ', '))
}
if ($outOfTreeMissing.Count) {
    Write-Host ("`n  DECLARED OUT-OF-TREE SUITE(S) MISSING FROM DISK -- {0}:" -f $outOfTreeMissing.Count) -ForegroundColor Red
    foreach ($m in $outOfTreeMissing) { Write-Host ("    - $m") -ForegroundColor Red }
    Write-Host "  A declared suite that no longer exists reads as coverage. Remove or fix the entry." -ForegroundColor Red
    $exitCode = 1
    $script:PimInventoryProblems += ("{0} declared out-of-tree suite(s) missing from disk: {1}" -f $outOfTreeMissing.Count, ($outOfTreeMissing -join ', '))
}

function Invoke-PimScenarioSuites {
    # Records failures by name into $script:PimFailedSuites; RETURNS NOTHING.
    #
    # ⚠️ TEST-28: this function used to `return $fail`, and it was the LAST one still doing so
    # -- the exact defect the block below this one documents as fixed. `& powershell.exe`
    # inside a function writes the child's stdout into the FUNCTION'S OUTPUT STREAM, so
    # `$scnFail = Invoke-PimScenarioSuites ...` captured every line the three scenario suites
    # printed PLUS the count. That is a non-empty ARRAY, which is always truthy, so
    # `-Scenario` forced exit 1 even on a fully green scenario run. Same shape, same cause,
    # same fix: record by name, read .Count at the end.
    #
    # It also hard-coded powershell.exe, so a scenario suite declaring `#Requires -Version 7`
    # would have been refused at line 1 exactly as the two DEPLOY-2 suites were. All three
    # are 5.1 today; the launcher no longer cares either way.
    param([string]$Root)
    $scnDir = Join-Path $Root 'scenario'
    Write-Host "`n############ ENGINE+GUI SCENARIO SIMULATION (REQUIREMENTS.md §20) ############" -ForegroundColor Magenta
    foreach ($s in 'Test-PimScenarioSim.ps1','Test-PimScenarioMspPair.ps1','Test-PimScenarioGui.ps1') {
        $p = Join-Path $scnDir $s
        if (-not (Test-Path $p)) { continue }
        Write-Host "`n---- $s ----" -ForegroundColor Cyan
        Invoke-PimSuiteChild -Path $p -Label "scenario\$s"
    }
}

# Failures are recorded BY NAME in a script-scoped list, and these runners return NOTHING.
#
# ⚠️ Do not "simplify" them back to `return $fail`. Inside a function, `& powershell.exe`
# writes the child's stdout into the FUNCTION'S OUTPUT STREAM -- so `$fail = Invoke-...`
# captures every line the child printed PLUS the count, making the result a non-empty
# ARRAY that is always truthy. That silently forced exit 1 on a fully green run (and it
# swallowed the child output, so nothing said why). Recording into $script:PimFailedSuites
# and reading .Count keeps the decision independent of the output stream -- and because
# these functions now return NOTHING, the child output simply flows through to the host
# (and to a `*>` redirected log) instead of being captured into a variable.
$script:PimFailedSuites = New-Object System.Collections.Generic.List[string]

# ---- TEST-28: run each suite under an interpreter that satisfies its OWN #Requires ----
#
# 🔴 THE DEFECT THIS CLOSES. This runner launched EVERY child suite with `powershell.exe`
# -- Windows PowerShell 5.1. Two suites added by the DEPLOY-2 / BUG-67 work declare
# `#Requires -Version 7`, so 5.1 refused them at line 1 with ScriptRequiresUnmatchedPSVersion
# and they were counted as FAILED. Measured 2026-08-17: the full suite had been RED since
# `1c042e6d`/`075fbb01`, and NEITHER new suite had ever actually executed inside it --
# Test-PimDeployDescriptor.ps1 is 13/0 green under pwsh 7.
#
# 🪤 The `#Requires -Version 7` on both is GENUINE, not decorative -- verified by relaxing it
# in a scratch copy and running it: Test-PimDeployDescriptor.ps1 uses PS7-only PARSER syntax
# (the `? :` ternary), and Test-PimTenantReady.ps1 INVOKES the readiness probe, which is
# itself `#Requires -Version 7`. So "just drop the #Requires" is not available; the runner is
# what has to adapt.
#
# ⚠️ CORRECTION 2026-08-19: the "PS7-only PARSER syntax (the ternary)" claim above was WRONG.
# Test-PimDeployDescriptor.ps1 contains ZERO ternaries. It was UTF-8 with NO BOM, and Windows
# PowerShell 5.1 reads a BOM-less file as ANSI, mangling the emoji in its strings until the parse
# breaks. ENCODING, not syntax. With a BOM it passes 13/0 on 5.1, and PIM now has NO PS7 suites at
# all (operator: "it must run on ps 5.1"; framework HOST-1) -- so today this function routes
# everything to powershell.exe. It stays because the RULE is right and the next PS7 file must not
# silently break the gate again; tests/Test-PimHostCompatibility.ps1 is what keeps PIM on 5.1.
#
# DERIVED, NOT HAND-LISTED -- the same principle as the AST-derived parameter check in
# Test-PimSetupHosting.ps1: a list of "the PS7 suites" would rot the moment someone adds the
# third one. The suite's own directive is the single source of truth.
#
# ⚠️ Read with a REGEX, deliberately, NOT with the AST. Under 5.1 the parser reports errors
# on PS7-only syntax, and a failed parse can leave ScriptRequirements null -- which would
# default the suite back to 5.1 and silently reproduce the exact bug being fixed here. The
# text of a `#requires` line is readable without parsing what follows it.
function Get-PimSuiteHost {
    # Returns the interpreter path to launch $Path with, or $null if it needs pwsh and pwsh
    # is not installed (the caller then fails LOUDLY -- never a silent skip).
    param([string]$Path)
    $needMajor = 5
    $txt = Get-Content -LiteralPath $Path -Raw
    foreach ($m in [regex]::Matches($txt, '(?im)^\s*#requires\s+-version\s+(\d+)')) {
        $v = [int]$m.Groups[1].Value
        if ($v -gt $needMajor) { $needMajor = $v }
    }
    if ($needMajor -lt 6) { return 'powershell.exe' }
    $pwsh = Get-Command 'pwsh.exe' -CommandType Application -ErrorAction SilentlyContinue |
                Select-Object -First 1
    if (-not $pwsh) { return $null }
    return $pwsh.Source
}

function Invoke-PimSuiteChild {
    # ONE place that launches a suite child process, so the interpreter rule cannot drift
    # between the three call sites. Records the failure by the label the caller wants.
    param([string]$Path, [string]$Label)
    $exe = Get-PimSuiteHost -Path $Path
    if (-not $exe) {
        Write-Host ("   SKIPPED-AS-FAILED: needs PowerShell 7 and pwsh.exe is not installed") -ForegroundColor Red
        [void]$script:PimFailedSuites.Add("$Label (needs pwsh 7 -- not installed)")
        return
    }
    if ($exe -ne 'powershell.exe') { Write-Host ("   (pwsh 7)") -ForegroundColor DarkGray }
    & $exe -NoProfile -ExecutionPolicy Bypass -File $Path
    if ($LASTEXITCODE -ne 0) { [void]$script:PimFailedSuites.Add($Label) }
}

function Invoke-PimStandaloneGates {
    # Every standalone gate, in BOTH branches. Records failures by name; returns nothing.
    param([string]$Root, [System.Collections.Specialized.OrderedDictionary]$Gates)
    foreach ($name in $Gates.Keys) {
        $p = Join-Path $Root $name
        if (-not (Test-Path $p)) { continue }
        Write-Host ("`n############ {0} ({1}) ############" -f $Gates[$name], $name) -ForegroundColor Cyan
        Invoke-PimSuiteChild -Path $p -Label "$name (gate)"
    }
}

function Invoke-PimFunctionalSuites {
    # Run each functional suite as a child process. Records failures by name; returns nothing.
    param([string]$Root, [string[]]$Suites)
    foreach ($s in $Suites) {
        Write-Host "`n############ $s ############" -ForegroundColor Cyan
        Invoke-PimSuiteChild -Path (Join-Path $Root $s) -Label $s
    }
}

function Invoke-PimOutOfTreeSuites {
    # TEST-07: the same child-process treatment for suites that live outside tests\.
    # Paths are relative to the SOLUTION root, not to tests\.
    param([string]$SolutionRoot, $Suites)
    foreach ($rel in $Suites.Keys) {
        $full = Join-Path $SolutionRoot $rel
        if (-not (Test-Path -LiteralPath $full)) {
            # Not silently skipped -- a declared suite that vanished is rot, and the
            # missing-from-disk check above has already failed the run for it.
            Write-Host "`n############ $rel -- NOT FOUND ############" -ForegroundColor Red
            [void]$script:PimFailedSuites.Add($rel)
            continue
        }
        Write-Host ("`n############ {0} ############" -f $rel) -ForegroundColor Cyan
        Write-Host ("   ({0})" -f $Suites[$rel]) -ForegroundColor DarkGray
        Invoke-PimSuiteChild -Path $full -Label $rel
    }
}

function Write-PimRunSummary {
    # ALWAYS print what failed, by name. Both branches.
    #
    # The INVENTORY failures (unaccounted / missing declared suites) set $exitCode
    # directly, long before this runs -- and this summary used to know nothing about
    # them. Result: a run that exited 1 printed "ALL SUITES GREEN", which is the same
    # false-green class as BUG-09. The summary must never contradict the exit code, so
    # it now takes the inventory verdict too.
    param([int]$PesterFailed = 0, [int]$InventoryFailed = 0, [string[]]$InventoryReasons = @())
    Write-Host "`n================ RUN SUMMARY ================" -ForegroundColor Magenta
    if ($PesterFailed -gt 0) { Write-Host ("  Pester: {0} failed test(s)" -f $PesterFailed) -ForegroundColor Red }
    if ($InventoryFailed -gt 0) {
        Write-Host ("  SUITE INVENTORY: {0} problem(s) -- see above" -f $InventoryFailed) -ForegroundColor Red
        foreach ($r in @($InventoryReasons)) { Write-Host "    - $r" -ForegroundColor Red }
    }
    if ($script:PimFailedSuites.Count -gt 0) {
        Write-Host ("  {0} FAILED suite(s):" -f $script:PimFailedSuites.Count) -ForegroundColor Red
        foreach ($n in $script:PimFailedSuites) { Write-Host "    - $n" -ForegroundColor Red }
    } elseif ($PesterFailed -le 0 -and $InventoryFailed -le 0) {
        Write-Host "  ALL SUITES GREEN" -ForegroundColor Green
    }
}

function Get-PimSuitesCoveredByPester {
    # Which functional suites does PIM.Tests.ps1 already fan out to? Parsed at RUNTIME so
    # the Pester and non-Pester paths can never drift apart again -- this is the join that
    # used to be two hand-maintained lists.
    param([string]$Root)
    $p = Join-Path $Root 'PIM.Tests.ps1'
    if (-not (Test-Path $p)) { return @() }
    $src = Get-Content $p -Raw -Encoding UTF8
    return @([regex]::Matches($src, "Invoke-Suite\s+'([\w\-\.]+\.ps1)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
}

$pester = Get-Module -ListAvailable Pester | Where-Object { $_.Version.Major -ge 5 } | Select-Object -First 1
if ($pester) {
    Import-Module Pester -MinimumVersion 5.0
    $pesterPaths = @($PesterFiles | ForEach-Object { Join-Path $here $_ } | Where-Object { Test-Path $_ })
    $r = Invoke-Pester -Path $pesterPaths -PassThru -Output Detailed
    Write-Host ("`nPESTER RESULT: {0} passed, {1} failed, {2} skipped" -f $r.PassedCount, $r.FailedCount, $r.SkippedCount) -ForegroundColor $(if ($r.FailedCount) {'Red'} else {'Green'})

    # The functional suites PIM.Tests.ps1 does NOT already drive -- previously these
    # simply never ran on a box with Pester installed.
    $covered = Get-PimSuitesCoveredByPester -Root $here
    $remaining = @($Functional | Where-Object { $covered -notcontains $_ })
    if ($remaining.Count) {
        Write-Host ("`n== {0} functional suite(s) not covered by PIM.Tests.ps1 -- running directly ==" -f $remaining.Count) -ForegroundColor Magenta
        Invoke-PimFunctionalSuites -Root $here -Suites $remaining
    }

    # TEST-07: suites outside tests\ -- run in BOTH branches, like the standalone gates.
    if ($OutOfTreeSuites.Count) {
        Write-Host ("`n== {0} out-of-tree suite(s) ==" -f $OutOfTreeSuites.Count) -ForegroundColor Magenta
        Invoke-PimOutOfTreeSuites -SolutionRoot $solutionRoot -Suites $OutOfTreeSuites
    }

    # TEST-28: no $scnFail any more -- the scenario suites record into $PimFailedSuites like
    # every other child suite, so their failures are also NAMED in the summary instead of
    # arriving as an anonymous count.
    if ($Scenario) { Invoke-PimScenarioSuites -Root $here }
    Invoke-PimStandaloneGates -Root $here -Gates $StandaloneGates
    Write-PimRunSummary -PesterFailed ([int]$r.FailedCount) -InventoryFailed $script:PimInventoryProblems.Count -InventoryReasons $script:PimInventoryProblems
    if ($r.FailedCount -or $script:PimFailedSuites.Count) { $exitCode = 1 }
} else {
    Write-Host "Pester 5+ not found -- running the functional suites directly." -ForegroundColor Yellow
    Invoke-PimFunctionalSuites -Root $here -Suites $Functional
    if ($OutOfTreeSuites.Count) {
        Write-Host ("`n== {0} out-of-tree suite(s) ==" -f $OutOfTreeSuites.Count) -ForegroundColor Magenta
        Invoke-PimOutOfTreeSuites -SolutionRoot $solutionRoot -Suites $OutOfTreeSuites
    }
    if ($Scenario) { Invoke-PimScenarioSuites -Root $here }
    Invoke-PimStandaloneGates -Root $here -Gates $StandaloneGates
    Write-PimRunSummary -InventoryFailed $script:PimInventoryProblems.Count -InventoryReasons $script:PimInventoryProblems
    if ($script:PimFailedSuites.Count) { $exitCode = 1 }
}

# GUI (Playwright) suite -- opt-in (-Gui). Self-skips with exit 0 when Node /
# Playwright / SQLEXPRESS are absent, so it never fails the gate spuriously.
if ($Gui) {
    Write-Host "`n############ GUI suite (Playwright) ############" -ForegroundColor Cyan
    $guiRunner = Join-Path $here 'playwright\feature-suite\Run-PimGuiTests.ps1'
    $guiArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$guiRunner`"")
    if ($GuiInstall) { $guiArgs += '-Install' }
    # TEST-28: derive the interpreter here too. It takes an extra -Install argument so it does
    # not fit Invoke-PimSuiteChild's signature, but the trap is identical -- it is 5.1 today,
    # and a future `#Requires -Version 7` must not be refused at line 1 and read as a failure.
    $guiExe = Get-PimSuiteHost -Path $guiRunner
    if (-not $guiExe) {
        Write-Host "   GUI suite needs PowerShell 7 and pwsh.exe is not installed" -ForegroundColor Red
        $exitCode = 1
    } else {
        & $guiExe @guiArgs
        if ($LASTEXITCODE -ne 0) { $exitCode = 1 }
    }
}

if ($exitCode) { exit 1 }
