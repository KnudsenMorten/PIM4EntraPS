#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS -- ONE-SHOT "deploy everything" orchestrator: stand up OR update the WHOLE
    solution end-to-end for a target customer/environment, then PROVE it with the test-tenant
    validation. REQUIREMENTS.md sec.3 (Setup / Deploy) -- the "one-shot deploy everything" item.

.DESCRIPTION
    A SINGLE entry that runs the full deploy IN ORDER, idempotently (safe to re-run -- a re-run
    becomes the updater, every already-current step is a clean no-op):

      1. APP-REG  -- ensure the engine app-registration + Graph/Azure grants exist
                     (Install-PimEngineAppRegistration.ps1). Skipped when already present.
      2. INFRA    -- stand up / refresh the infra: hosted = containers/ACA env + worker matrix
                     (Setup-PimContainers.ps1); community/VM = scheduled-task host (Setup-PimVM.ps1).
                     Skipped when the env already exists.
      3. SCHEMA   -- idempotent SQL schema upgrade (preflight -> apply -> re-preflight; NEVER
                     destructive). Composed via Invoke-PimUpdate (its DETECT + guarded-DDL path).
      4. CODE     -- build + deploy the Manager/scheduler/engine image
                     (Invoke-PimUpdate.ps1 -Apply: build-from-pulled-code -> roll the ACA revision;
                     community = local build/relaunch). This is the ONLY rollbackable step.
      5. VERIFY   -- prove the deployment works: the hosted smoke
                     (tests/live/Test-PimManagerHostedSmoke.ps1) + the deploy-validation tests
                     (tests/live/PIM.DeployValidation.Tests.ps1).
      6. SUMMARY + VERIFY-THEN-ROLLBACK -- on a verify failure, auto-roll the CODE step back to
                     the captured pre-deploy revision; print + return the run summary.

    The ORCHESTRATION CORE is pure + offline-unit-tested (engine/_shared/PIM-DeployAll.ps1):
    the ordered step plan, the per-step gate/skip/idempotent-no-op decisions, the
    verify-then-rollback verdict, and the rollback plan all live there with NO az/SQL/HTTP. This
    script only GATHERS facts (is the app-reg present? does the ACA env exist? does the DB
    conform? is the image current?) and INVOKES each step's runner. The runners are INJECTABLE
    (-StepRunner) so the whole flow is offline-testable without touching Azure.

    This script does NOT reinvent the pieces -- it ORCHESTRATES the existing setup family:
    Install-PimEngineAppRegistration.ps1, Setup-PimContainers.ps1 / Setup-PimVM.ps1, and
    Invoke-PimUpdate.ps1 (which itself owns the build/deploy/schema/verify/rollback lifecycle).

    MODES:
      -WhatIf        : plan only (DEFAULT-SAFE). Prints the ordered plan; makes NO changes.
      -Apply         : run the needed steps in order (idempotent); verify; rollback on failure.
      -ValidateOnly  : run ONLY the test-tenant validation (smoke + deploy-validation tests).

    Parameterised for ANY tenant -- NO hardcoded tenant/sub/SQL/RG/KV (per CLAUDE.md). Cert-auth,
    unattended-capable. The live deploy+validate against a real test tenant is the RELEASE GATE;
    this script delivers the orchestration -- it does not claim live-verified by itself.

.PARAMETER Source
    'sync-automateit' (hosted: ACA + Azure SQL) or 'git-pull' (community/VM/local). Drives whether
    INFRA is Setup-PimContainers (hosted) or Setup-PimVM (community).

.PARAMETER TenantId / SubscriptionId
    Target tenant + subscription (no defaults -- pass your own, per CLAUDE.md).

.PARAMETER ResourceGroup / VnetName / VnetResourceGroup / AcrName / EnvName
    Hosted infra targets (Setup-PimContainers). Required for a hosted INFRA stand-up.

.PARAMETER SqlServerFqdn / SqlDatabase / SqlConnectionString
    SQL target. SqlConnectionString feeds the schema-drift DETECT + idempotent upgrade.

.PARAMETER ImageTag
    Image tag to build/deploy (default = the pulled VERSION file).

.PARAMETER EngineClientId / EngineCertThumbprint
    Engine SPN identity for the deploy-validation tests (cert-auth, unattended).

.PARAMETER WhatIf / Apply / ValidateOnly
    See MODES above. -WhatIf is the default when neither -Apply nor -ValidateOnly is given.

.PARAMETER StepRunner
    (TEST/advanced) a scriptblock invoked instead of the real per-step runner:
    & $StepRunner $stepKey $context -> returns @{ ok=$bool; ran=$bool; detail='' }. Lets the
    orchestration be exercised end-to-end OFFLINE. Omit it for real deploys.

.EXAMPLE
    .\Invoke-PimDeployAll.ps1 -Source sync-automateit -TenantId <tid> -SubscriptionId <sub> `
        -ResourceGroup rg-pim -VnetName vnet -VnetResourceGroup rg-net -AcrName myacr `
        -SqlServerFqdn my.database.windows.net
    Plan-only (default -WhatIf): print the ordered deploy-everything plan; make no changes.

.EXAMPLE
    .\Invoke-PimDeployAll.ps1 -Source sync-automateit -TenantId <tid> -SubscriptionId <sub> `
        -ResourceGroup rg-pim -VnetName vnet -VnetResourceGroup rg-net -AcrName myacr `
        -SqlServerFqdn my.database.windows.net -SqlConnectionString '<conn>' -Apply
    Stand up / update the whole solution, then verify; auto-rollback the code on a verify failure.

.EXAMPLE
    .\Invoke-PimDeployAll.ps1 -Source sync-automateit -TenantId <tid> -ResourceGroup rg-pim `
        -SqlDatabase PimPlatform -EngineClientId <cid> -EngineCertThumbprint <thumb> -ValidateOnly
    Run ONLY the test-tenant validation against an already-deployed environment.

.NOTES
    PS 5.1-safe. Pure decision core: engine/_shared/PIM-DeployAll.ps1. Offline tests:
    tests/Test-PimDeployAll.ps1. Live deploy+validate against a test tenant = the release gate.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('git-pull','sync-automateit')][string]$Source = 'sync-automateit',
    # s31: stand up the right TOPOLOGY for a deployment SCENARIO (S1..S6). When set, the scenario's
    # resolved update source + managed hosting drive the deploy path (overrides -Source); it is also
    # passed through to Invoke-PimUpdate so the from-master (S5/S6) downlink is honoured end-to-end.
    [ValidateSet('S1','S2','S3','S4','S5','S6')][string]$Scenario,
    [switch]$Apply,
    [switch]$ValidateOnly,

    # --- target tenant / subscription (no real ids baked in; pass your own) ---
    [string]$TenantId,
    [string]$SubscriptionId,

    # --- hosted infra targets (Setup-PimContainers) ---
    [string]$ResourceGroup,
    [string]$VnetName,
    [string]$VnetResourceGroup,
    [string]$AcrName,
    [string]$EnvName        = 'cae-pim',
    [string]$Location       = 'westeurope',
    [string]$ImageRepo      = 'pim-manager',
    [string[]]$Apps         = @('ca-pim-manager','ca-pim-scheduler','ca-pim-engine','ca-pim-connector','ca-pim-deltaqueue','ca-pim-discovery'),
    [string]$ManagerApp     = 'ca-pim-manager',
    [string]$ImageTag,

    # --- SQL ---
    [string]$SqlServerFqdn,
    [string]$SqlDatabase    = 'PimPlatform',
    [string]$SqlConnectionString,

    # --- engine identity for the deploy-validation tests (cert-auth, unattended) ---
    [string]$EngineClientId,
    [string]$EngineCertThumbprint,
    [string]$DeployMarker   = 'PIMCOREENGINE-',

    # --- app-registration installer passthrough ---
    [string]$EngineAppDisplayName = 'PIM4EntraPS Engine',

    # --- verify knobs ---
    [switch]$SkipVerify,                     # opt out of step 5 entirely (NOT recommended)

    # --- TEST seam: inject the per-step runner so the whole flow is offline-testable ---
    [scriptblock]$StepRunner
)
$ErrorActionPreference = 'Stop'
$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)            # SOLUTIONS/PIM4EntraPS
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Info($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }
function Have($cmd){ [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# ---- load the pure decision core (REUSE; never re-implement) ----
. (Join-Path $solRoot 'engine\_shared\PIM-SyncAutomateIT.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateLifecycle.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-DeployAll.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-ScenarioProfile.ps1')     # s31 scenario -> knob resolver

# default-safe: a bare run is plan-only (-WhatIf). -Apply opens the gate.
$applyGate = [bool]$Apply
if ($ValidateOnly) { $applyGate = $true }   # validate-only still "runs" its single step

# ---- s31: a -Scenario resolves the deploy topology, overriding -Source ----
# The DeployAll CORE (Get-PimDeployAllPlan) + the local fact-probes only model git-pull |
# sync-automateit (hosted vs community), so from-master is mapped to a PLAN source by managed
# hosting: central => sync-automateit (ACA/Azure SQL), local => git-pull (local host). The REAL
# from-master downlink is honoured by passing -Scenario through to Invoke-PimUpdate (below).
$planSource    = $Source
$scenarioArgs  = @{}     # splat threaded into Invoke-PimUpdate sub-calls (empty unless -Scenario)
if ($Scenario) {
    $sPlan = Get-PimScenarioEntryPlan -Scenario $Scenario
    $planSource = if ($sPlan.updateSource -eq 'from-master') { if ($sPlan.managedHosting -eq 'central') { 'sync-automateit' } else { 'git-pull' } }
                  elseif ($sPlan.updateSource -eq 'sync-automateit') { 'sync-automateit' } else { 'git-pull' }
    $Source = $planSource
    $scenarioArgs['Scenario'] = $Scenario
    Write-Host ("[scenario] {0} ({1}) -> updateSource={2} managedHosting={3} planSource={4} hosting={5} spn={6} edition={7}" -f `
        $sPlan.id, $sPlan.role, $sPlan.updateSource, $sPlan.managedHosting, $planSource, $sPlan.hostingLocation, $sPlan.spnModel, $sPlan.activeEdition) -ForegroundColor Cyan
}
$srcProfile = Get-PimUpdateSourceProfile -Source $Source
$hosted  = [bool]$srcProfile.isHosted

Write-Host "=== PIM4EntraPS DEPLOY-ALL ($Source; $(if($ValidateOnly){'VALIDATE-ONLY'}elseif($Apply){'APPLY'}else{'WHATIF / PLAN-ONLY'})) ===" -ForegroundColor Cyan
Info "hosted=$hosted; tenant=$(if($TenantId){'set'}else{'(not set)'}); sub=$(if($SubscriptionId){'set'}else{'(not set)'})"

# =============================================================================
# GATHER FACTS -- the side-effecting reads. The DECISIONS stay in the pure core.
# Each fact answers "is this step NEEDED?" ($true = run; $false = already current).
# Absent / unknown => $true (fail-safe: run rather than skip a real change).
# =============================================================================
function Test-EngineAppRegPresent {
    # present when an app with the engine display name exists AND has a credential. Best-effort
    # via az; unknown (no az / not logged in) => NEEDED=$true (let the idempotent installer run).
    if (-not (Have 'az')) { return $null }
    try {
        $id = az ad app list --display-name $EngineAppDisplayName --query "[0].appId" -o tsv 2>$null
        if ("$id".Trim()) { return $true }
        return $false
    } catch { return $null }
}
function Test-AcaEnvPresent {
    if (-not $hosted) { return $false }       # non-hosted: infra step is the VM host (handled below)
    if (-not (Have 'az') -or -not "$ResourceGroup".Trim()) { return $null }
    try {
        $e = az containerapp env show -g $ResourceGroup -n $EnvName --query "name" -o tsv 2>$null
        if ("$e".Trim()) { return $true }
        return $false
    } catch { return $null }
}
function Test-SchemaConformant {
    # reuse Invoke-PimUpdate's SQL DETECT (it reads the deployed columns + builds the plan). We do
    # NOT duplicate that logic -- we call the detect-only path and read SqlUpdateRequired.
    if (-not "$SqlConnectionString".Trim()) { return $null }   # cannot read => run schema step
    try {
        $upd = Join-Path $here 'Invoke-PimUpdate.ps1'
        $det = & $upd -Source $Source @scenarioArgs -DetectOnly -SqlConnectionString $SqlConnectionString `
                    -ResourceGroup $ResourceGroup -ManagerApp $ManagerApp -ImageTag $ImageTag 6>$null
        $last = @($det) | Where-Object { $_ -and ($_.PSObject.Properties.Name -contains 'SqlUpdateRequired') } | Select-Object -Last 1
        if ($last) { return (-not [bool]$last.SqlUpdateRequired) }
        return $null
    } catch { return $null }
}
function Test-ManagerImageCurrent {
    # reuse Invoke-PimUpdate's GUI DETECT (pulled content hash vs running image). Same as above:
    # detect-only, read GuiUpdateRequired. Unknown => run the code step.
    try {
        $upd = Join-Path $here 'Invoke-PimUpdate.ps1'
        $det = & $upd -Source $Source @scenarioArgs -DetectOnly -SqlConnectionString $SqlConnectionString `
                    -ResourceGroup $ResourceGroup -ManagerApp $ManagerApp -ImageTag $ImageTag 6>$null
        $last = @($det) | Where-Object { $_ -and ($_.PSObject.Properties.Name -contains 'GuiUpdateRequired') } | Select-Object -Last 1
        if ($last) { return (-not [bool]$last.GuiUpdateRequired) }
        return $null
    } catch { return $null }
}

# Build the NEEDED facts. A fact of $true => the target is CURRENT => step NOT needed.
# Get-PimDeployAllPlan wants NEEDED=$true to RUN, so we invert "present/current" facts.
# TEST SEAM: when a -StepRunner is injected the whole flow runs OFFLINE, so we must NOT call the
# side-effecting az/SQL fact probes (they'd hit real Azure, be slow, and make the plan depend on
# the host's logged-in tenant). With the seam present, every step is NEEDED (the fail-safe default)
# so the full ordered plan flows through the injected runner.
$facts = @{}
if (-not $ValidateOnly) {
    if ($StepRunner) {
        $facts['appreg'] = $true; $facts['infra'] = $true; $facts['schema'] = $true; $facts['code'] = $true
    } else {
        $appRegPresent = Test-EngineAppRegPresent
        $facts['appreg'] = if ($null -eq $appRegPresent) { $true } else { -not $appRegPresent }      # missing => needed

        $acaPresent = Test-AcaEnvPresent
        $facts['infra'] = if ($null -eq $acaPresent) { $true } else { -not $acaPresent }             # missing => needed

        $schemaOk = Test-SchemaConformant
        $facts['schema'] = if ($null -eq $schemaOk) { $true } else { -not $schemaOk }                # drift => needed

        $imgCurrent = Test-ManagerImageCurrent
        $facts['code'] = if ($null -eq $imgCurrent) { $true } else { -not $imgCurrent }              # stale => needed
    }
}
# verify is always NEEDED (always prove a deploy) unless explicitly skipped.
$facts['verify'] = (-not $SkipVerify)

# =============================================================================
# PLAN -- the pure core fixes the order + gate/skip/no-op decisions.
# =============================================================================
$plan = Get-PimDeployAllPlan -Source $Source -Facts $facts -Apply:$applyGate -ValidateOnly:$ValidateOnly

Write-Host ""
Write-Host "  DEPLOY-ALL PLAN ($(if($plan.whatIf){'WHATIF'}else{'APPLY'}); hosted=$($plan.hosted)):" -ForegroundColor Cyan
$i = 0
foreach ($s in $plan.steps) { $i++; Write-Host ("    {0}. {1,-8} [{2,-20}] {3}" -f $i, $s.key, $s.action, $s.reason) }
Write-Host ""

if ($plan.whatIf) {
    Step 'WHATIF / PLAN-ONLY -- no changes made. Re-run with -Apply to execute the plan above.'
    $global:LASTEXITCODE = 0   # a plan-only run is clean -- don't leak a best-effort az probe's exit code
    return (Get-PimDeploySummary -StepOutcomes @($plan.steps | ForEach-Object { [pscustomobject]@{ key=$_.key; ran=$false; ok=$true } }) -Verdict $null -PlanOnly)
}

# =============================================================================
# default per-step RUNNERS (the real side-effecting work). Each returns
# @{ ok; ran; detail }. Injected -StepRunner overrides ALL of them (offline tests).
# =============================================================================
function Invoke-DefaultStepRunner {
    param([string]$Key,[hashtable]$Ctx)
    switch ($Key) {
        'appreg' {
            $installer = Join-Path $here 'Install-PimEngineAppRegistration.ps1'
            if (-not (Test-Path $installer)) { return @{ ok=$false; ran=$true; detail="installer not found: $installer" } }
            if ($PSCmdlet.ShouldProcess($EngineAppDisplayName, 'ensure engine app-registration + grants')) {
                & $installer -DisplayName $EngineAppDisplayName -TenantId $TenantId -GrantConsent
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                return @{ ok=$ok; ran=$true; detail='app-registration ensured' }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'infra' {
            if ($hosted) {
                $setup = Join-Path $here 'Setup-PimContainers.ps1'
                if (-not (Test-Path $setup)) { return @{ ok=$false; ran=$true; detail="setup not found: $setup" } }
                if ($PSCmdlet.ShouldProcess($ResourceGroup, 'stand up / refresh ACA infra')) {
                    & $setup -SubscriptionId $SubscriptionId -TenantId $TenantId -Location $Location `
                        -ResourceGroup $ResourceGroup -VnetName $VnetName -VnetResourceGroup $VnetResourceGroup `
                        -EnvName $EnvName -AcrName $AcrName -ImageRepo $ImageRepo -ImageTag (Get-EffectiveImageTag) `
                        -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase
                    $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                    return @{ ok=$ok; ran=$true; detail='ACA infra ensured' }
                }
            } else {
                $setup = Join-Path $here 'Setup-PimVM.ps1'
                if (-not (Test-Path $setup)) { return @{ ok=$false; ran=$true; detail="setup not found: $setup" } }
                if ($PSCmdlet.ShouldProcess('local VM host', 'stand up / refresh VM scheduled-task host')) {
                    & $setup -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId
                    $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                    return @{ ok=$ok; ran=$true; detail='VM host ensured' }
                }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'schema' {
            # delegate the idempotent schema upgrade to Invoke-PimUpdate (preflight->apply->re-preflight).
            $upd = Join-Path $here 'Invoke-PimUpdate.ps1'
            if (-not (Test-Path $upd)) { return @{ ok=$false; ran=$true; detail="updater not found: $upd" } }
            if ($PSCmdlet.ShouldProcess($SqlDatabase, 'apply idempotent SQL schema upgrade')) {
                & $upd -Source $Source @scenarioArgs -Apply -SqlConnectionString $SqlConnectionString `
                    -ResourceGroup $ResourceGroup -ManagerApp $ManagerApp -ImageTag (Get-EffectiveImageTag) `
                    -SkipVerify -SkipNotify
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                return @{ ok=$ok; ran=$true; detail='schema upgrade applied (preflight->apply->re-preflight)' }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'code' {
            # build-from-pulled-code + roll the ACA revision via Invoke-PimUpdate (its lifecycle).
            $upd = Join-Path $here 'Invoke-PimUpdate.ps1'
            if (-not (Test-Path $upd)) { return @{ ok=$false; ran=$true; detail="updater not found: $upd" } }
            if ($PSCmdlet.ShouldProcess($ManagerApp, 'build + deploy Manager/scheduler/engine code')) {
                & $upd -Source $Source @scenarioArgs -Apply -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo `
                    -ManagerApp $ManagerApp -Apps $Apps -ImageTag (Get-EffectiveImageTag) `
                    -SqlConnectionString $SqlConnectionString -SkipNotify
                $ok = (-not $LASTEXITCODE) -or ($LASTEXITCODE -eq 0)
                return @{ ok=$ok; ran=$true; detail='code built + deployed' }
            }
            return @{ ok=$true; ran=$false; detail='skipped by ShouldProcess' }
        }
        'verify' {
            return (Invoke-DeployValidation)
        }
    }
    return @{ ok=$false; ran=$true; detail="unknown step '$Key'" }
}

function Get-EffectiveImageTag {
    if ("$ImageTag".Trim()) { return $ImageTag }
    $vf = Join-Path $solRoot 'VERSION'
    if (Test-Path $vf) { return (Get-Content -LiteralPath $vf -Raw).Trim() }
    return 'latest'
}

# ---- VERIFY: hosted smoke + deploy-validation tests (the test-tenant validation) ----
$script:smokeExit = 0
$script:validationExit = 0
function Invoke-DeployValidation {
    $smokeExit = -1; $valExit = -1            # -1 = did not run (self-skip), not a fail
    $smoke = Join-Path $solRoot 'tests\live\Test-PimManagerHostedSmoke.ps1'
    if ($hosted -and (Test-Path $smoke)) {
        Info 'verify: hosted smoke (Test-PimManagerHostedSmoke.ps1)'
        if ($PSCmdlet.ShouldProcess($ManagerApp, 'run hosted smoke')) {
            $env:PIM_HOSTED_APP = $ManagerApp
            if ("$ResourceGroup".Trim()) { $env:PIM_HOSTED_RG = $ResourceGroup }
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $smoke
            $smokeExit = $LASTEXITCODE
        }
    } else { Info 'verify: hosted smoke skipped (community/local or smoke not found)' }

    $val = Join-Path $solRoot 'tests\live\PIM.DeployValidation.Tests.ps1'
    if (Test-Path $val) {
        Info 'verify: deploy-validation tests (PIM.DeployValidation.Tests.ps1)'
        if ($PSCmdlet.ShouldProcess($SqlDatabase, 'run deploy-validation tests')) {
            $env:PIM_TenantId      = $TenantId
            $env:PIM_ClientId      = $EngineClientId
            $env:PIM_CertThumbprint= $EngineCertThumbprint
            $env:PIM_SqlDatabase   = $SqlDatabase
            $env:PIM_DEPLOY_MARKER = $DeployMarker
            try {
                if (Have 'Invoke-Pester') {
                    $r = Invoke-Pester -Path $val -PassThru -Output Minimal
                    $valExit = if ($r.FailedCount -gt 0) { 1 } else { 0 }
                } else {
                    & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Pester -Path '$val' -CI"
                    $valExit = $LASTEXITCODE
                }
            } catch { Warn "deploy-validation tests errored: $($_.Exception.Message)"; $valExit = 1 }
        }
    } else { Info 'verify: deploy-validation tests not found -- UNVERIFIED' }

    $script:smokeExit = $smokeExit
    $script:validationExit = $valExit
    $ok = (($smokeExit -le 0) -and ($valExit -le 0))   # <=0 means passed or self-skipped (not a fail)
    return @{ ok=$ok; ran=(($smokeExit -ge 0) -or ($valExit -ge 0)); detail="smoke=$smokeExit validation=$valExit" }
}

# =============================================================================
# EXECUTE -- walk plan.steps in order; run each 'do' step via the runner; capture
# the pre-deploy rollback target before CODE; verify-then-rollback at the end.
# =============================================================================
$runner = if ($StepRunner) { $StepRunner } else { { param($k,$ctx) Invoke-DefaultStepRunner -Key $k -Ctx $ctx } }
$ctx = @{ source=$Source; hosted=$hosted; tenantId=$TenantId; resourceGroup=$ResourceGroup; managerApp=$ManagerApp; imageTag=$ImageTag }

# capture pre-deploy rollback target (prior ACA revision) BEFORE any code change.
# Skipped under the -StepRunner test seam (would hit real az and probe a non-existent RG).
$prevRev = ''
if (-not $StepRunner -and $hosted -and -not $ValidateOnly -and (Have 'az') -and "$ResourceGroup".Trim()) {
    try { $prevRev = az containerapp revision list -g $ResourceGroup -n $ManagerApp --query "[?properties.active].name | [0]" -o tsv 2>$null } catch { Write-Verbose "active-revision read failed: $($_.Exception.Message)" }
    if (-not "$prevRev".Trim()) { try { $prevRev = az containerapp revision list -g $ResourceGroup -n $ManagerApp --query "[0].name" -o tsv 2>$null } catch { Write-Verbose "fallback-revision read failed: $($_.Exception.Message)" } }
    Info "pre-deploy revision (rollback target): $(if($prevRev){$prevRev}else{'(unknown)'})"
}

$outcomes = New-Object System.Collections.Generic.List[object]
$ranKeys  = New-Object System.Collections.Generic.List[string]
$verifyResult = $null
$halted = $false

foreach ($s in $plan.steps) {
    if (-not $s.do) {
        Step "$($s.key): $($s.action) -- $($s.reason)"
        $outcomes.Add([pscustomobject]@{ key=$s.key; ran=$false; ok=$true }) | Out-Null
        continue
    }
    Step "$($s.key): RUN -- $($s.name)"
    $res = & $runner $s.key $ctx
    if (-not $res) { $res = @{ ok=$false; ran=$true; detail='runner returned nothing' } }
    # A runner may return a hashtable, a PSCustomObject, or (defensively) a scalar.
    # Read 'ok'/'ran'/'detail' WITHOUT assuming ContainsKey (PSCustomObject/String lack it).
    $okRaw = $null; $ranRaw = $null; $detail = ''
    if ($res -is [System.Collections.IDictionary]) {
        if ($res.Contains('ok'))     { $okRaw  = $res['ok'] }
        if ($res.Contains('ran'))    { $ranRaw = $res['ran'] }
        if ($res.Contains('detail')) { $detail = $res['detail'] }
    } else {
        if ($res.PSObject.Properties['ok'])     { $okRaw  = $res.ok }
        if ($res.PSObject.Properties['ran'])    { $ranRaw = $res.ran }
        if ($res.PSObject.Properties['detail']) { $detail = $res.detail }
    }
    $ok  = [bool]$okRaw
    $ran = if ($null -ne $ranRaw) { [bool]$ranRaw } else { $true }
    Info "  -> ok=$ok ran=$ran $detail"
    $outcomes.Add([pscustomobject]@{ key=$s.key; ran=$ran; ok=$ok }) | Out-Null
    if ($ran) { $ranKeys.Add($s.key) | Out-Null }
    if ($s.key -eq 'verify') { $verifyResult = $res }

    # a failed step (other than verify -- verify failure drives rollback below) HALTS the run.
    if (-not $ok -and $s.key -ne 'verify') {
        Warn "step '$($s.key)' FAILED -- halting the deploy."
        $halted = $true
        break
    }
}

# =============================================================================
# VERIFY VERDICT + VERIFY-THEN-ROLLBACK on failure.
# =============================================================================
$codeRan = ($ranKeys -contains 'code')
$verdict = $null
if ($verifyResult -or $halted) {
    $verdict = Get-PimDeployVerifyVerdict -SmokeExitCode $script:smokeExit -ValidationExitCode $script:validationExit `
                -PreviousRevision $prevRev -CodeStepRan $codeRan
}

$rolledBack = $false
$needRollback = $halted -or ($verdict -and -not $verdict.Healthy)
if ($needRollback -and $codeRan) {
    $rbPlan = Get-PimDeployRollbackPlan -RanStepKeys @($ranKeys.ToArray()) -PreviousRevision $prevRev -Hosted $hosted
    foreach ($a in $rbPlan.actions) {
        Warn "ROLLBACK: $($a.key) -> $($a.action) ($($a.detail))"
        if ($a.action -eq 'rollback-revision' -and $hosted) {
            try {
                $roller = Join-Path $here 'Update-PimContainers.ps1'
                if ($PSCmdlet.ShouldProcess($ManagerApp, "rollback to $($a.detail)")) {
                    & $roller -Rollback ("$prevRev".Trim()) -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps -SkipSmoke
                    $rolledBack = $true
                }
            } catch { Warn "auto-rollback failed: $($_.Exception.Message)" }
        }
    }
}

# =============================================================================
# SUMMARY.
# =============================================================================
$summary = Get-PimDeploySummary -StepOutcomes @($outcomes.ToArray()) -Verdict $verdict -RolledBack $rolledBack
Write-Host ""
Step "DONE. status=$($summary.status) healthy=$($summary.healthy) rolledBack=$($summary.rolledBack)"
foreach ($o in $summary.steps) { Info ("  {0,-8} ran={1} ok={2}" -f $o.key, $o.ran, $o.ok) }
if ($summary.failedSteps.Count) { Warn "failed steps: $($summary.failedSteps -join ', ')" }

$summary
if ($summary.status -eq 'failed' -or $summary.status -eq 'rolledback') { exit 1 }
