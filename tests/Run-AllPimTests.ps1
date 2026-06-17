#Requires -Version 5.1
<#
.SYNOPSIS
    Run the full PIM4EntraPS test suite. Prefers the Pester job (PIM.Tests.ps1);
    falls back to invoking the three functional suites directly if Pester is absent.
    Offline -- no live tenant required. Rerun anytime to re-validate every flow.
.DESCRIPTION
    Also runs the browser-automation GUI suite (Playwright, tests/playwright) when
    -Gui is passed. The GUI suite self-skips cleanly when Node/Playwright/SQLEXPRESS
    are unavailable, so it never breaks the offline gate on a box without them.
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
    # Also run the end-to-end engine+GUI SCENARIO SIMULATION (REQUIREMENTS.md §20).
    # The engine sim self-skips without SQLEXPRESS; the GUI sim self-skips without Node/Playwright.
    [switch]$Scenario,
    [switch]$Gui,
    [switch]$GuiInstall
)
$here = $PSScriptRoot
$exitCode = 0

# Belt-and-braces: clear any leftover headless Manager from a prior crashed/aborted
# run so a zombie never holds a port or leaks a token into a fresh run's stdout.
# (The boot tests now use dynamic free ports via _shared\PimManagerBoot.ps1, so a
# zombie no longer causes a hang -- this just keeps the box tidy.)
. (Join-Path $here '_shared\PimManagerBoot.ps1')
try { Stop-PimStaleManagers } catch {}

function Invoke-PimScenarioSuites {
    param([string]$Root)
    $scnDir = Join-Path $Root 'scenario'
    Write-Host "`n############ ENGINE+GUI SCENARIO SIMULATION (REQUIREMENTS.md §20) ############" -ForegroundColor Magenta
    $fail = 0
    foreach ($s in 'Test-PimScenarioSim.ps1','Test-PimScenarioGui.ps1') {
        $p = Join-Path $scnDir $s
        if (-not (Test-Path $p)) { continue }
        Write-Host "`n---- $s ----" -ForegroundColor Cyan
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p
        if ($LASTEXITCODE -ne 0) { $fail++ }
    }
    return $fail
}

# Doc-image presence gate (offline, no Pester needed). Asserts every markdown
# image reference in the PUBLIC docs (README / FEATURES / DESIGN) resolves to a
# real non-empty file and that the key Manager surfaces each have a screenshot.
# Runs in BOTH branches (it's a standalone script, not a Pester file) so missing
# screenshots are caught regardless of whether Pester is installed.
function Invoke-PimDocImageGate {
    param([string]$Root)
    $p = Join-Path $Root 'Test-PimDocImages.ps1'
    if (-not (Test-Path $p)) { return 0 }
    Write-Host "`n############ DOC-IMAGE PRESENCE GATE (Test-PimDocImages.ps1) ############" -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p
    return $(if ($LASTEXITCODE -ne 0) { 1 } else { 0 })
}

$pester = Get-Module -ListAvailable Pester | Where-Object { $_.Version.Major -ge 5 } | Select-Object -First 1
if ($pester) {
    Import-Module Pester -MinimumVersion 5.0
    $pesterFiles = @(
        (Join-Path $here 'PIM.Tests.ps1')
        (Join-Path $here 'PIM.Activator.Tests.ps1')    # browser-extension package validator (offline)
        (Join-Path $here 'PIM.ReadPimRows.Tests.ps1')  # [H1] Read-PimRows header normalisation (BOM/quotes/whitespace) -- in-proc offline
        (Join-Path $here 'PIM.KeyedReviewDiff.Tests.ps1')  # [M2] Review & Save diff is keyed (reorder != change) -- in-proc offline
        (Join-Path $here 'PIM.AuthoringPreview.Tests.ps1') # [M3] Authoring inline preview/diff before commit; move-admin never drops rows -- offline
        (Join-Path $here 'PIM.MapRemovalStaging.Tests.ps1') # [M8] stage a removal (revoke a grant) from the Delegation Map; routes through keyed diff + maker/checker; destructive guard -- offline
        (Join-Path $here 'PIM.DeployAll.Tests.ps1')     # [§3] one-shot deploy-everything orchestration core + orchestrator (injected runner) -- offline
        (Join-Path $here 'PIM.OffboardExecution.Tests.ps1') # [H4] approval-gated offboarding EXECUTOR (request->approve->execute, once-only, mocked pipeline) -- offline
        (Join-Path $here 'PIM.RevokeExecution.Tests.ps1')   # [H3] approval-gated bulk-revoke EXECUTOR (over-threshold->approve->execute, once-only, break-glass excluded, mocked pipeline) -- offline
    ) | Where-Object { Test-Path $_ }
    $r = Invoke-Pester -Path $pesterFiles -PassThru -Output Detailed
    Write-Host ("`nPESTER RESULT: {0} passed, {1} failed, {2} skipped" -f $r.PassedCount, $r.FailedCount, $r.SkippedCount) -ForegroundColor $(if ($r.FailedCount) {'Red'} else {'Green'})
    $scnFail = 0
    if ($Scenario) { $scnFail = Invoke-PimScenarioSuites -Root $here }
    $docImgFail = Invoke-PimDocImageGate -Root $here
    if ($r.FailedCount -or $scnFail -or $docImgFail) { $exitCode = 1 }
} else {
    Write-Host "Pester 5+ not found -- running the functional suites directly." -ForegroundColor Yellow
    $failed = 0
    foreach ($s in 'Test-PimEngineCore.ps1','Test-PimDisableGuard.ps1','Test-PimApprovalGate.ps1','Test-PimSensitiveAuthoring.ps1','Test-PimFeatures.ps1','Test-PimManagerEndpoints.ps1','Test-PimGuiEngineAlignment.ps1','Test-PimManagerGuiPanels.ps1','Test-PimManagerGuiComprehensive.ps1','Test-PimManagerSafety.ps1','Test-PimAuthoringDropdowns.ps1','Test-PimMapPermissionsTargets.ps1','Test-PimMapReach.ps1','Test-PimMapRisk.ps1','Test-PimManagerHostedSql.ps1','Test-PimScenarios.ps1','Test-PimManagerHostedSim.ps1','Test-PimSettingsAdmin.ps1','Test-PimCutover.ps1','Test-PimCutoverEndpoints.ps1','Test-PimCutoverAbort.ps1','Test-PimCommitBackup.ps1','Test-PimAuthDiagnostics.ps1','Test-PimLicensing.ps1','Test-PimNamingMigration.ps1','Test-PimScheduler.ps1','Test-PimGovernance.ps1','Test-PimMailTemplates.ps1','Test-PimSetupHosting.ps1','Test-PimSyncAutomateIT.ps1','Test-PimUpdateLifecycle.ps1','Test-PimRestExoSetup.ps1','Test-PimAccessReviews.ps1','Test-PimWarningOverrides.ps1','Test-PimHomeOverview.ps1','Test-PimApprovalsGui.ps1','Test-PimAccessReporting.ps1','Test-PimOperationalPolicy.ps1','Test-PimRoleLookup.ps1','Test-PimTierImpact.ps1','Test-PimFeatureFlags.ps1','Test-PimAuditQuery.ps1','Test-PimExemptionRegister.ps1','Test-PimFleetConformance.ps1','Test-PimFleetEndpoints.ps1','Test-PimAlertFeed.ps1','Test-PimRolePermissionsExport.ps1') {
        Write-Host "`n############ $s ############" -ForegroundColor Cyan
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here $s)
        if ($LASTEXITCODE -ne 0) { $failed++ }
    }
    if ($Scenario) { $failed += Invoke-PimScenarioSuites -Root $here }
    $failed += Invoke-PimDocImageGate -Root $here
    if ($failed) { Write-Host " $failed suite(s) FAILED" -ForegroundColor Red; $exitCode = 1 } else { Write-Host " ALL SUITES GREEN" -ForegroundColor Green }
}

# GUI (Playwright) suite -- opt-in (-Gui). Self-skips with exit 0 when Node /
# Playwright / SQLEXPRESS are absent, so it never fails the gate spuriously.
if ($Gui) {
    Write-Host "`n############ GUI suite (Playwright) ############" -ForegroundColor Cyan
    $guiRunner = Join-Path $here 'playwright\feature-suite\Run-PimGuiTests.ps1'
    $guiArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$guiRunner`"")
    if ($GuiInstall) { $guiArgs += '-Install' }
    & powershell.exe @guiArgs
    if ($LASTEXITCODE -ne 0) { $exitCode = 1 }
}

if ($exitCode) { exit 1 }
