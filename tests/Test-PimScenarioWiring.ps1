#Requires -Version 5.1
<#
.SYNOPSIS
    Phase-1 scenario WIRING test (REQUIREMENTS s31.3 a). Proves the deployment scenario
    (S1-S6) is threaded through the deploy/update ENTRY POINTS and drives real behaviour:
    the pure mapping function (Get-PimScenarioEntryPlan) resolves each scenario onto the
    EXISTING knobs (update-source incl. ring-gated from-master, hosting, SPN model, license
    tier -> the s30 edition gate, sync-file location), the update-source plan functions honour
    from-master + ManagedHosting, the per-scenario license gate blocks/allows correctly
    (super-admin never locked out), and each entry point now accepts -Scenario.

.DESCRIPTION
    All OFFLINE (no live tenant, no az, no SQL, no server boot, no real deploy). Layers:

      1. ENTRY-PLAN     -- Get-PimScenarioEntryPlan maps each S1-S6 onto the right
                           update-source / managed-hosting / config-variant / ring-gating /
                           hosting / SPN / sync-file / edition for the entry points.
      2. UPDATE-SOURCE  -- Get-PimUpdateSourceProfile / Get-PimBuildPlan / Get-PimUpdateApplyPlan
                           honour 'from-master' + ManagedHosting (central=ACR/ACA, local=relaunch),
                           ring-gated for the managed downlink; git-pull/sync-automateit unchanged.
      3. LICENSE GATE   -- Test-PimScenarioFeatureAllowed: S2 (Core) blocks Pro features, S4 (Pro)
                           unlocks the MSP/master features, S1/S3/S5/S6 (Pro-DesignPartner) unlock
                           all; super-admin is NEVER locked out; the s30 Test-PimFeatureAvailable
                           agrees when fed the scenario's resolved edition.
      4. ENTRY PARAMS   -- Invoke-PimUpdate / Invoke-PimDeployAll / Build-PimManagerImage all
                           declare a -Scenario parameter (the wiring is present, not just the core).

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'engine\_shared\PIM-ScenarioProfile.ps1')
. (Join-Path $root 'engine\_shared\PIM-SyncAutomateIT.ps1')
. (Join-Path $root 'engine\_shared\PIM-UpdateLifecycle.ps1')
. (Join-Path $root 'engine\_shared\PIM-FeatureCatalog.ps1')

# ---------------------------------------------------------------------------
# 1. ENTRY-PLAN -- the pure mapping function resolves every scenario onto the
#    concrete entry-point knobs. The expected matrix mirrors REQUIREMENTS s31.2.
# ---------------------------------------------------------------------------
Write-Host "`n== 1. ENTRY-PLAN (scenario -> entry-point knobs) ==" -ForegroundColor Cyan
# Each row: id, updateSource, managedHosting, configVariant, ringGated, hosting, spn, syncFile, edition, mspProGate
$expected = @(
    @{ id='S1'; src='sync-automateit'; mh='';        cfg='local'; ring=$false; host='in-tenant';   spn='local-spn';        sf='none';        ed='Pro-DesignPartner'; msp=$false }
    @{ id='S2'; src='git-pull';        mh='';        cfg='local'; ring=$false; host='in-tenant';   spn='local-spn';        sf='none';        ed='Core';              msp=$false }
    @{ id='S3'; src='sync-automateit'; mh='';        cfg='msp';   ring=$false; host='in-tenant';   spn='local-spn';        sf='central-msp'; ed='Pro-DesignPartner'; msp=$false }
    @{ id='S4'; src='git-pull';        mh='';        cfg='msp';   ring=$false; host='in-tenant';   spn='local-spn';        sf='central-msp'; ed='Pro';              msp=$true  }
    @{ id='S5'; src='from-master';     mh='central'; cfg='msp';   ring=$true;  host='central-msp';  spn='multi-tenant-spn'; sf='central-msp'; ed='Pro-DesignPartner'; msp=$false }
    @{ id='S6'; src='from-master';     mh='local';   cfg='msp';   ring=$true;  host='local-slave';  spn='local-spn';        sf='local-slave'; ed='Pro-DesignPartner'; msp=$false }
)
foreach ($e in $expected) {
    $p = Get-PimScenarioEntryPlan -Scenario $e.id
    $ok = ($p.id -eq $e.id) -and
          ($p.updateSource -eq $e.src) -and
          ("$($p.managedHosting)" -eq $e.mh) -and
          ($p.configVariant -eq $e.cfg) -and
          ([bool]$p.ringGated -eq $e.ring) -and
          ($p.hostingLocation -eq $e.host) -and
          ($p.spnModel -eq $e.spn) -and
          ($p.syncFileLocation -eq $e.sf) -and
          ($p.activeEdition -eq $e.ed) -and
          ([bool]$p.mspFeaturesRequirePro -eq $e.msp)
    T "$($e.id) -> src=$($e.src) mh='$($e.mh)' cfg=$($e.cfg) ring=$($e.ring) host=$($e.host) spn=$($e.spn) sf=$($e.sf) ed=$($e.ed)" $ok
    if (-not $ok) {
        Write-Host ("    actual: src=$($p.updateSource) mh='$($p.managedHosting)' cfg=$($p.configVariant) ring=$($p.ringGated) host=$($p.hostingLocation) spn=$($p.spnModel) sf=$($p.syncFileLocation) ed=$($p.activeEdition) mspPro=$($p.mspFeaturesRequirePro)") -ForegroundColor DarkYellow
    }
}
# only the managed scenarios sync admins+permissions
T 'S5+S6 syncAdminsPermissions=$true; S1-S4 = $false' (
    (Get-PimScenarioEntryPlan -Scenario 'S5').syncAdminsPermissions -and
    (Get-PimScenarioEntryPlan -Scenario 'S6').syncAdminsPermissions -and
    -not (Get-PimScenarioEntryPlan -Scenario 'S1').syncAdminsPermissions -and
    -not (Get-PimScenarioEntryPlan -Scenario 'S4').syncAdminsPermissions)
# only the from-master scenarios carry a managed hosting; the rest are blank
T 'managedHosting set ONLY for from-master scenarios (S5 central / S6 local)' (
    "$((Get-PimScenarioEntryPlan -Scenario 'S1').managedHosting)" -eq '' -and
    "$((Get-PimScenarioEntryPlan -Scenario 'S5').managedHosting)" -eq 'central' -and
    "$((Get-PimScenarioEntryPlan -Scenario 'S6').managedHosting)" -eq 'local')
# entry plan accepts a descriptor object too (not just an id) -- built ON Resolve-PimScenarioContext
$desc = Get-PimScenario -Id 'S5'
T 'Get-PimScenarioEntryPlan accepts a descriptor object (not only an id)' ((Get-PimScenarioEntryPlan -Scenario $desc).spnModel -eq 'multi-tenant-spn')

# ---------------------------------------------------------------------------
# 1b. EDITION PAYLOAD round-trips through the s30 edition resolver -- so persisting
#     it under the 'Edition' key makes Get-PimActiveEdition/Test-PimFeatureAvailable
#     gate on the scenario's tier.
# ---------------------------------------------------------------------------
Write-Host "`n== 1b. EDITION PAYLOAD -> s30 resolver ==" -ForegroundColor Cyan
$pay2 = (Get-PimScenarioEntryPlan -Scenario 'S2').editionPayload
$pay4 = (Get-PimScenarioEntryPlan -Scenario 'S4').editionPayload
$pay5 = (Get-PimScenarioEntryPlan -Scenario 'S5').editionPayload
T 'S2 editionPayload resolves to Core via Resolve-PimEdition'             ((Resolve-PimEdition -Raw $pay2).edition -eq 'Core')
T 'S4 editionPayload resolves to Pro (grantBasis=paid)'                   ((Resolve-PimEdition -Raw $pay4).edition -eq 'Pro' -and (Resolve-PimEdition -Raw $pay4).grantBasis -eq 'paid')
T 'S5 editionPayload resolves to Pro-DesignPartner (grantBasis=design-partner)' ((Resolve-PimEdition -Raw $pay5).edition -eq 'Pro-DesignPartner' -and (Resolve-PimEdition -Raw $pay5).grantBasis -eq 'design-partner')

# ---------------------------------------------------------------------------
# 2. UPDATE-SOURCE plan functions honour from-master + ManagedHosting.
# ---------------------------------------------------------------------------
Write-Host "`n== 2. UPDATE-SOURCE PROFILE / BUILD / APPLY (from-master) ==" -ForegroundColor Cyan
$fmCentral = Get-PimUpdateSourceProfile -Source 'from-master' -ManagedHosting 'central'
$fmLocal   = Get-PimUpdateSourceProfile -Source 'from-master' -ManagedHosting 'local'
T 'from-master central -> acr-build/aca-roll, hosted, ring-gated' ($fmCentral.buildMode -eq 'acr-build' -and $fmCentral.deployMode -eq 'aca-roll' -and $fmCentral.isHosted -and $fmCentral.ringGated)
T 'from-master local   -> local-build/local-relaunch, NOT hosted, ring-gated' ($fmLocal.buildMode -eq 'local-build' -and $fmLocal.deployMode -eq 'local-relaunch' -and -not $fmLocal.isHosted -and $fmLocal.ringGated)
# the non-from-master sources are unchanged (regression guard)
$gp = Get-PimUpdateSourceProfile -Source 'git-pull'
$sa = Get-PimUpdateSourceProfile -Source 'sync-automateit'
T 'git-pull unchanged (local-build, not hosted, not ring-gated)' ($gp.buildMode -eq 'local-build' -and -not $gp.isHosted -and -not $gp.ringGated)
T 'sync-automateit unchanged (acr-build, hosted, not ring-gated)' ($sa.buildMode -eq 'acr-build' -and $sa.isHosted -and -not $sa.ringGated)

# Get-PimBuildPlan now accepts from-master + ManagedHosting.
$bpC = Get-PimBuildPlan -GuiUpdateRequired $true -Source 'from-master' -ManagedHosting 'central' -ImageTag '9.9.9'
$bpL = Get-PimBuildPlan -GuiUpdateRequired $true -Source 'from-master' -ManagedHosting 'local'   -ImageTag '9.9.9'
T 'Get-PimBuildPlan from-master central -> acr-build, mentions ring-gated' ($bpC.BuildRequired -and $bpC.buildMode -eq 'acr-build' -and $bpC.reason -match 'ring-gated')
T 'Get-PimBuildPlan from-master local   -> local-build, mentions ring-gated' ($bpL.BuildRequired -and $bpL.buildMode -eq 'local-build' -and $bpL.reason -match 'ring-gated')

# Get-PimUpdateApplyPlan now accepts from-master + ManagedHosting (and produces the 6-step plan).
$det  = Get-PimUpdateDetection -GuiPlan (Get-PimGuiUpdatePlan -PulledContentHash 'aaa' -RunningContentHash 'bbb') -SqlPlan ([pscustomobject]@{ SqlUpdateRequired = $false; reason = 'n/a' })
$apC  = Get-PimUpdateApplyPlan -Detection $det -BuildPlan $bpC -Source 'from-master' -ManagedHosting 'central' -Apply -MonitorInPlace $true
$deployStepC = @($apC.steps | Where-Object { $_.name -eq 'deploy' })[0]
T 'Get-PimUpdateApplyPlan from-master central -> deploy step says "roll ACA"' ($apC.source -eq 'from-master' -and $deployStepC.detail -match 'roll ACA')
$apL  = Get-PimUpdateApplyPlan -Detection $det -BuildPlan $bpL -Source 'from-master' -ManagedHosting 'local' -Apply -MonitorInPlace $true
$deployStepL = @($apL.steps | Where-Object { $_.name -eq 'deploy' })[0]
T 'Get-PimUpdateApplyPlan from-master local -> deploy step says "relaunch the local Manager"' ($deployStepL.detail -match 'relaunch the local Manager')

# ---------------------------------------------------------------------------
# 3. LICENSE GATE per scenario (s31.3 license-tier gating).
# ---------------------------------------------------------------------------
Write-Host "`n== 3. PER-SCENARIO LICENSE GATE ==" -ForegroundColor Cyan
# A Pro feature: blocked for S2 (Core), allowed for S4 (Pro) + S1/S3/S5/S6 (Pro-DesignPartner).
T 'S2 (Core) BLOCKS a Pro feature'                          (-not (Test-PimScenarioFeatureAllowed -Scenario 'S2' -RequiresPro))
T 'S4 (Pro) ALLOWS a Pro feature (MSP/master unlocked)'     (Test-PimScenarioFeatureAllowed -Scenario 'S4' -RequiresPro)
T 'S1 (Pro-DesignPartner) ALLOWS a Pro feature'             (Test-PimScenarioFeatureAllowed -Scenario 'S1' -RequiresPro)
T 'S3 (Pro-DesignPartner) ALLOWS a Pro feature'             (Test-PimScenarioFeatureAllowed -Scenario 'S3' -RequiresPro)
T 'S5 (Pro-DesignPartner) ALLOWS a Pro feature'             (Test-PimScenarioFeatureAllowed -Scenario 'S5' -RequiresPro)
T 'S6 (Pro-DesignPartner) ALLOWS a Pro feature'             (Test-PimScenarioFeatureAllowed -Scenario 'S6' -RequiresPro)
# Core/free features always allowed (even on S2).
T 'a free feature is allowed on S2 (Core)'                  (Test-PimScenarioFeatureAllowed -Scenario 'S2')
# Super-admin is NEVER locked out (even on S2 for a Pro feature).
T 'super-admin is NEVER locked out (S2 + Pro feature + -SuperAdmin)' (Test-PimScenarioFeatureAllowed -Scenario 'S2' -RequiresPro -SuperAdmin)

# The s30 catalog gate AGREES when fed the scenario's resolved edition (one edition value
# drives both). msp.downlink is a 'pro' catalog feature -- enable it via an override so the
# kill switch is on, then assert the LICENSE gate matches the scenario edition.
$gates = @{ gates = @{ 'msp.downlink' = $true } }
$global:PIM_NamingConventions = @{ FeatureGates = $gates }
$edS2 = (Get-PimScenarioEntryPlan -Scenario 'S2').activeEdition
$edS4 = (Get-PimScenarioEntryPlan -Scenario 'S4').activeEdition
# ⚠️ POLICY 2026-08-07 (operator: "no limitations ... full access default"): the licence
# gate is UNENFORCED by default, so the scenario's edition restricts NOTHING. The
# restrictive assertion is kept but moved under explicit enforcement, so the gate is still
# proven to work if it is ever turned back on.
T 's30 DEFAULT: msp.downlink is ALLOWED at the S2 edition (Pro is free)' (Test-PimFeatureAvailable -Key 'msp.downlink' -Edition $edS2 -Quiet)
$global:PIM_EnforceProLicense = $true
try {
    T 's30 ENFORCED: Test-PimFeatureAvailable(msp.downlink) BLOCKS at S2 edition (Core)'  (-not (Test-PimFeatureAvailable -Key 'msp.downlink' -Edition $edS2 -Quiet))
    T 's30 ENFORCED: Test-PimFeatureAvailable(msp.downlink) ALLOWS at S4 edition (Pro)'   (Test-PimFeatureAvailable -Key 'msp.downlink' -Edition $edS4 -Quiet)
    T 's30 ENFORCED: super-admin bypass unlocks msp.downlink even at S2 edition'          (Test-PimFeatureAvailable -Key 'msp.downlink' -Edition $edS2 -SuperAdmin -Quiet)
} finally { Remove-Variable -Name PIM_EnforceProLicense -Scope Global -ErrorAction SilentlyContinue }
$global:PIM_NamingConventions = $null

# ---------------------------------------------------------------------------
# 4. ENTRY POINTS declare a -Scenario parameter (the wiring is present).
# ---------------------------------------------------------------------------
Write-Host "`n== 4. ENTRY POINTS ACCEPT -Scenario ==" -ForegroundColor Cyan
function Test-HasScenarioParam([string]$ScriptPath) {
    if (-not (Test-Path $ScriptPath)) { return $false }
    $errs = $null; $tok = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tok, [ref]$errs)
    if ($errs -and $errs.Count) { return $false }   # also a parse-validity check
    $params = $ast.ParamBlock
    if (-not $params) { return $false }
    foreach ($p in $params.Parameters) { if ($p.Name.VariablePath.UserPath -eq 'Scenario') { return $true } }
    return $false
}
$setup = Join-Path $root 'tools\setup'
T 'Invoke-PimUpdate.ps1 declares -Scenario (+parses clean)'      (Test-HasScenarioParam (Join-Path $setup 'Invoke-PimUpdate.ps1'))
T 'Invoke-PimDeployAll.ps1 declares -Scenario (+parses clean)'   (Test-HasScenarioParam (Join-Path $setup 'Invoke-PimDeployAll.ps1'))
T 'Build-PimManagerImage.ps1 declares -Scenario (+parses clean)' (Test-HasScenarioParam (Join-Path $setup 'Build-PimManagerImage.ps1'))

# ---------------------------------------------------------------------------
# 5. PHASE-2 DOWNLINK + RUNNER WIRING (s31.3 b). Loading the scenario module
#    (which the live matrix loads) makes the master->managed admin/permission
#    SYNC orchestrator + the scenario-bound RUNNER resolvable -- the exact names
#    the live matrix's capability probe + scenario-runner steps Get-Command for.
#    The full pure-core behaviour is covered by tests\Test-PimDownlink.ps1; here
#    we assert the WIRING is present + the entry scripts parse + the matrix probe
#    flips to "built".
# ---------------------------------------------------------------------------
Write-Host "`n== 5. PHASE-2 DOWNLINK / RUNNER WIRING ==" -ForegroundColor Cyan
$syncProbeNames = @('Invoke-PimManagedDownlink','Sync-PimMasterToSlave','Invoke-PimScenarioSync')
$syncBuilt = $false
foreach ($c in $syncProbeNames) { if (Get-Command $c -ErrorAction SilentlyContinue) { $syncBuilt = $true } }
T 'master->managed sync orchestrator resolves (matrix sync-wiring-built probe)' $syncBuilt
T 'scenario-bound runner Invoke-PimScenarioDeploy resolves (matrix scenario-runner probe)' ($null -ne (Get-Command Invoke-PimScenarioDeploy -ErrorAction SilentlyContinue))
# the pure cores are present too (so the orchestrators have something to compose)
T 'pure cores present (Select-PimDownlinkAdmins / Get-PimDownlinkPlan / Get-PimScenarioRunPlan)' (
    (Get-Command Select-PimDownlinkAdmins -ErrorAction SilentlyContinue) -and
    (Get-Command Get-PimDownlinkPlan -ErrorAction SilentlyContinue) -and
    (Get-Command Get-PimScenarioRunPlan -ErrorAction SilentlyContinue))
# the live wrappers exist + parse clean
function Test-ParsesClean([string]$ScriptPath) {
    if (-not (Test-Path $ScriptPath)) { return $false }
    $errs = $null; $tok = $null
    [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tok, [ref]$errs) | Out-Null
    return -not ($errs -and $errs.Count)
}
$setupRoot = Join-Path $root 'setup'
T 'setup\Invoke-PimDownlinkSync.ps1 exists + parses clean' (Test-ParsesClean (Join-Path $setupRoot 'Invoke-PimDownlinkSync.ps1'))
T 'setup\Invoke-PimScenarioRun.ps1 exists + parses clean'  (Test-ParsesClean (Join-Path $setupRoot 'Invoke-PimScenarioRun.ps1'))
# runner topology branch sanity (single=no downlink; managed=downlink first)
T 'runner branch: S2 single = engine-apply only; S5 managed = downlink-sync first' (
    -not (Get-PimScenarioRunPlan -Scenario 'S2').runDownlink -and
    (Get-PimScenarioRunPlan -Scenario 'S5').runDownlink -and
    (Get-PimScenarioRunPlan -Scenario 'S5').steps[0] -eq 'downlink-sync')

# ---------------------------------------------------------------------------
# §33.7.f-2 CROSS-TENANT BLAST RADIUS -- structural assertions on the matrix.
#
# The helpers Get-PimTenantObjectInventory / Compare-PimTenantInventory were added in
# 398d8e6d and then sat in the file, called by NOTHING, through two live matrix runs
# that were reported as fully VERIFIED. A helper nobody calls proves nothing, and the
# matrix's own output could not reveal that -- there was no step to report. These
# assertions exist so the wiring cannot silently disappear the same way twice.
# ---------------------------------------------------------------------------
$mx = Get-Content -Raw (Join-Path $root 'tests\live\Test-PimScenarioMatrix.ps1')
T 'matrix HAS a cross-tenant-blast-radius step' ($mx -match "cross-tenant-blast-radius")
T '  ...and it is REQUIRED (no -Required $false on it)' ($mx -notmatch "cross-tenant-blast-radius'[^\r\n]*-Required \`$false")
T '  ...it CALLS the inventory helper'   ($mx -match 'Get-PimTenantObjectInventory -TenantId \$otherTid')
T '  ...it CALLS the compare helper'     ($mx -match 'Compare-PimTenantInventory -Before \$blastBefore')
T '  ...it captures BEFORE the deploy'   ($mx -match '(?s)\$blastBefore = Get-PimTenantObjectInventory.{0,4000}?\$firstRun = Invoke-PimScenarioDeploy')
# The vacuity guards. Each of these was a real way for this assertion to pass while
# measuring nothing -- the D4.a / ring-gate shape the docs already warn about twice.
T '  ...SKIPS when there is no second tenant'  ($mx -match 'no SECOND tenant distinct from')
T '  ...SKIPS when the other tenant is EMPTY' ($mx -match 'inventoried as EMPTY')
T '  ...SKIPS when no BEFORE was captured'    ($mx -match 'no BEFORE inventory was captured')
T '  ...treats a READ ERROR as unverified, not clean' ($mx -match 'unverified, not clean')
T '  ...reports the SIZE it compared'         ($mx -match 'named object\(s\) compared')
# 🪤 The assertion must read the other tenant with the OTHER tenant's OWN SPN. Reading
# it with the ambient context would inventory the TARGET twice and pass unconditionally
# -- and a leaked ambient identity is exactly BUG-23, the thing this catches.
T '  ...reads the other tenant with ITS OWN SPN' ($mx -match 'Get-PimTenantObjectInventory -TenantId \$otherTid -ClientId \$otherCid -Thumbprint \$otherThb')

# --- TEST-20: blast radius must be RING-AWARE, not "nothing changed" ---------------------
# The MSP model deliberately creates the central admins in every managed tenant, so the old
# "same or leak" assertion could not pass for S5/S6. It must sanction exactly the admins the
# other tenant's RING entitles it to -- and nothing else, or the step becomes unable to fail.
T 'blast radius sanctions ring-entitled central admins' ($mx -match 'sanctionedAdmins')
T '  ...taken from THAT tenant expected set, not a blanket allow' ($mx -match 'expectedAdminUserNames')
T '  ...matched per tenantId' ($mx -match '\$sl\.tenantId.*-eq.*\$otherTid')
T '  ...an unsanctioned ADD still fails' ($mx -match 'unexpectedAdds')
T '  ...any REMOVAL still fails' ($mx -match 'unexpectedRemovals')
T '  ...only users can be sanctioned (a group/AU change is never admin propagation)' ($mx -match "\^\(\?i\)users:")
T '  ...the verdict is the containment flag, not diff.same' ($mx -match "-Name 'cross-tenant-blast-radius' -Ok \`$contained")

# --- BUG-31: the matrix must ACTIVATE each scenario, and prove the store placement -------
# Structural, for the same reason the blast-radius assertions above are structural: the
# wiring vanished once already (criterion 2 sat uncalled through two "VERIFIED" runs), and
# an uncalled mechanism produces no step to report, so only the source can testify.
T 'matrix ACTIVATES the scenario (calls Set-PimScenarioContext)' ($mx -match 'Set-PimScenarioContext -Scenario \$sc')
T '  ...and asserts PIM_ActiveScenario actually took' ($mx -match "'scenario-activated'")
T '  ...as a REQUIRED step' ($mx -notmatch "scenario-activated'[^\r\n]*-Required \`$false")
T 'matrix HAS a store-placement step' ($mx -match "'store-placement'")
T '  ...and it is REQUIRED' ($mx -notmatch "store-placement'[^\r\n]*-Required \`$false")
T '  ...central-msp asserts the CS uses PIM_SqlServerCentral' ($mx -match 'central-msp' -and $mx -match 'env:PIM_SqlServerCentral')
T '  ...central-msp also asserts the CS is PASSWORDLESS (no Integrated Security)' ($mx -match "passwordless=")
T '  ...local-slave asserts the CS uses PIM_SqlServerLocal' ($mx -match 'env:PIM_SqlServerLocal')
# 🪤 The vacuity guard that makes this real: with no server supplied, the resolver falls back
# to ambient, which is INDISTINGUISHABLE from a correct answer. Such a step must SKIP, never pass.
T '  ...SKIPS (never passes) when no central server was supplied' ($mx -match 'UNMEASURED, not correct')
T '  ...SKIPS when no local-slave server was supplied' ($mx -match 'the local slave store is UNMEASURED')
T '  ...in-tenant asserts NO override is applied' ($mx -match "no scenario override")
# Scenario activation mutates global runtime knobs; they must not leak past the loop.
T 'matrix RESTORES the scenario globals after the run' ($mx -match 'savedScenarioGlobals' -and $mx -match 'finally')

Write-Host ""
Write-Host ("==== Scenario-wiring test: {0} passed, {1} failed ====" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 } else { exit 0 }
