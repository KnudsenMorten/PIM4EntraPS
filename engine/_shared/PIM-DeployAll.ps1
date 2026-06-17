<#
  PIM4EntraPS -- "deploy everything" core (the PURE, fully-testable decision brain behind the
  ONE-SHOT full-solution stand-up/update orchestrator tools/setup/Invoke-PimDeployAll.ps1).
  REQUIREMENTS.md sec.3 (Setup / Deploy) -- the "one-shot deploy everything" item.

  This file only DECIDES + RENDERS PLANS. No az calls, no HTTP, no PowerShell modules, no git,
  no file writes, no SQL. The thin orchestrator (tools/setup/Invoke-PimDeployAll.ps1) gathers
  the FACTS (is the engine app-reg present? is the infra/ACA env present? does the deployed DB
  conform to the pulled schema? is the Manager image current?) and runs each step's INJECTED
  step-runner. That split keeps every risky decision -- the ordered step list, per-step
  gate/skip decisions, and the verify-then-rollback verdict -- unit-testable OFFLINE without
  touching Azure/SQL.

  It REUSES the existing decision cores instead of re-implementing them:
    * PIM-UpdateLifecycle.ps1 -- Get-PimUpdateSourceProfile (hosted vs community), the SQL/GUI
      detect plans, and Get-PimVerifyVerdict (post-deploy verdict + rollback).
    * PIM-SyncAutomateIT.ps1  -- semver compare / health verdict / rollback plan (transitively).
  This file layers the WHOLE-SOLUTION ordered plan (app-reg -> infra -> schema -> code -> verify
  -> rollback-on-fail) on top.

  PS 5.1-safe: no ?./??/RSA.ImportFromPem; Set-StrictMode -Off; only built-in cmdlets.

  Public functions:
    * Get-PimDeployAllPlan       -- the ordered, gated step plan across the whole stand-up/update
    * Get-PimDeployStepDecision  -- per-step gate/skip decision (do vs skip + why) given a fact
    * Get-PimDeployVerifyVerdict -- turn the validation results into pass/fail + rollback verdict
    * Get-PimDeployRollbackPlan  -- given which steps actually ran, the ordered rollback actions
    * Get-PimDeploySummary       -- the end-of-run summary object (status, per-step outcome)
#>

Set-StrictMode -Off

# Reuse the update-lifecycle + sync decision cores (source profile, verify verdict, rollback,
# semver). Idempotent dot-source -- never re-implement source/hosted detection or the verdict.
if ($PSScriptRoot -and -not (Get-Command Get-PimUpdateSourceProfile -ErrorAction SilentlyContinue)) {
    $__pimUpd = Join-Path $PSScriptRoot 'PIM-UpdateLifecycle.ps1'
    if (Test-Path -LiteralPath $__pimUpd) { . $__pimUpd }
}

# The canonical ordered step list for a whole-solution stand-up/update. Each step carries:
#   key       -- stable identifier (used by runners + rollback + summary)
#   name      -- human label
#   factKey   -- the name of the FACT the orchestrator gathers to decide need (boolean "present"
#                / "current" style fact; see Get-PimDeployStepDecision)
#   rollbackable -- whether a failure AFTER this step ran should be rolled back automatically
#   hostedOnly   -- step applies only to the hosted (ACA) flavour
function Get-PimDeployStepCatalog {
    <#
      The ordered catalog of deploy-all steps (pure data). The orchestrator never hardcodes the
      order -- it walks THIS list. Order is load-bearing: identity/grants must exist before infra,
      infra before schema, schema before code, code before verify; rollback is verify-driven.
    #>
    @(
        [pscustomobject]@{ key='appreg';   name='Engine app-registration + Graph/Azure grants'; rollbackable=$false; hostedOnly=$false }
        [pscustomobject]@{ key='infra';    name='Infra / containers (ACA) or VM setup';          rollbackable=$false; hostedOnly=$false }
        [pscustomobject]@{ key='schema';   name='Idempotent SQL schema upgrade (preflight->apply->re-preflight)'; rollbackable=$false; hostedOnly=$false }
        [pscustomobject]@{ key='code';     name='Build + deploy Manager/scheduler/engine code';  rollbackable=$true;  hostedOnly=$false }
        [pscustomobject]@{ key='verify';   name='Verify (hosted smoke + deploy-validation tests)';rollbackable=$false; hostedOnly=$false }
    )
}

# ---- per-step gate/skip decision (pure) -----------------------------------
function Get-PimDeployStepDecision {
    <#
      Decide whether ONE step should run, given the FACT the orchestrator gathered for it. The
      rule is uniform and idempotent: a step runs only when it is NEEDED (the target is missing
      or not current) AND the gate is open (-Apply). A step that is already current is a clean
      SKIP -- this is what makes a re-run a no-op / turns the deployer into the updater.

      Inputs:
        -Step    : a catalog entry (from Get-PimDeployStepCatalog).
        -Needed  : the gathered fact -- $true when the step must run (target missing / drifted /
                   not current), $false when the target is already in the desired state.
        -Apply   : the master gate. $false (-WhatIf / plan-only) => never 'do', always 'plan'.
        -Hosted  : is this the hosted (ACA) flavour? A hostedOnly step on a non-hosted target
                   is skipped as not-applicable.
        -ValidateOnly : when set, ONLY the 'verify' step may run; every other step is skipped.

      Returns { key; name; do; action; reason }. action in
        { do | plan (WhatIf) | skip-current | skip-not-applicable | skip-validate-only }.
    #>
    param(
        [Parameter(Mandatory)][object]$Step,
        [bool]$Needed = $true,
        [switch]$Apply,
        [bool]$Hosted = $true,
        [switch]$ValidateOnly
    )
    $key = "$($Step.key)"

    # -ValidateOnly: only 'verify' is allowed to run; everything else is skipped.
    if ($ValidateOnly -and $key -ne 'verify') {
        return [pscustomobject]@{ key=$key; name=$Step.name; do=$false; action='skip-validate-only'; reason='-ValidateOnly: only the deploy-validation step runs' }
    }
    # hosted-only step on a non-hosted target => not applicable.
    if ($Step.hostedOnly -and -not $Hosted) {
        return [pscustomobject]@{ key=$key; name=$Step.name; do=$false; action='skip-not-applicable'; reason='step applies only to the hosted (ACA) flavour' }
    }
    # already in the desired state => clean no-op (idempotent re-run).
    if (-not $Needed) {
        return [pscustomobject]@{ key=$key; name=$Step.name; do=$false; action='skip-current'; reason='target already current -- nothing to do (idempotent)' }
    }
    # needed but gate closed => plan-only (WhatIf default-safe).
    if (-not $Apply) {
        return [pscustomobject]@{ key=$key; name=$Step.name; do=$false; action='plan'; reason='needed -- would run on -Apply (WhatIf / plan-only)' }
    }
    return [pscustomobject]@{ key=$key; name=$Step.name; do=$true; action='do'; reason='needed + -Apply -- run this step' }
}

# ---- the whole ordered deploy-all plan (pure) -----------------------------
function Get-PimDeployAllPlan {
    <#
      Build the WHOLE-SOLUTION ordered plan from the catalog + the gathered per-step facts. This
      is the heart of the orchestration: it fixes the order (app-reg -> infra -> schema -> code
      -> verify), applies the gate, and marks each step do/plan/skip with a reason. The
      orchestrator walks plan.steps in order and invokes the injected runner for each 'do' step.

      Inputs:
        -Source        : 'git-pull' | 'sync-automateit' (reuses Get-PimUpdateSourceProfile to
                         derive hosted vs community).
        -Facts         : a hashtable of per-step NEEDED facts keyed by step key, e.g.
                         @{ appreg=$true; infra=$false; schema=$true; code=$true; verify=$true }.
                         A key absent / $null is treated as NEEDED=$true (fail-safe: when we
                         cannot prove the target is current, we run the step rather than skip a
                         real change). 'verify' defaults NEEDED=$true (always verify a deploy).
        -Apply         : the gate. $false => plan-only (-WhatIf default-safe).
        -ValidateOnly  : run ONLY the verify step.

      Returns { source; hosted; whatIf; validateOnly; steps = @( per-step decision in order ) }.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('git-pull','sync-automateit')][string]$Source,
        [hashtable]$Facts,
        [switch]$Apply,
        [switch]$ValidateOnly
    )
    if (-not $Facts) { $Facts = @{} }
    $srcProfile = Get-PimUpdateSourceProfile -Source $Source
    $hosted  = [bool]$srcProfile.isHosted

    $steps = New-Object System.Collections.Generic.List[object]
    foreach ($step in (Get-PimDeployStepCatalog)) {
        $key = "$($step.key)"
        # NEEDED fact: explicit value wins; absent/null => fail-safe NEEDED=$true (verify always).
        $needed = $true
        if ($Facts.ContainsKey($key) -and $null -ne $Facts[$key]) { $needed = [bool]$Facts[$key] }
        $dec = Get-PimDeployStepDecision -Step $step -Needed $needed -Apply:$Apply -Hosted $hosted -ValidateOnly:$ValidateOnly
        # carry the step metadata the orchestrator + rollback need.
        $dec | Add-Member -NotePropertyName rollbackable -NotePropertyValue ([bool]$step.rollbackable) -Force
        $dec | Add-Member -NotePropertyName needed       -NotePropertyValue ([bool]$needed)           -Force
        $steps.Add($dec) | Out-Null
    }

    return [pscustomobject]@{
        source       = $Source
        hosted       = $hosted
        whatIf       = (-not $Apply)
        validateOnly = [bool]$ValidateOnly
        steps        = $steps.ToArray()
    }
}

# ---- post-validate verdict (pure) -----------------------------------------
function Get-PimDeployVerifyVerdict {
    <#
      Turn the validation results into a pass/fail verdict + rollback decision. We REUSE
      Get-PimVerifyVerdict (update-lifecycle) when available -- never re-implement the
      health-verdict/rollback math. Healthy = both the hosted smoke and the deploy-validation
      tests passed (exit 0, zero fails). On failure, the rollback target is the captured
      pre-deploy revision (only the 'code' step is rollbackable).

      Inputs:
        -SmokeExitCode      : Test-PimManagerHostedSmoke.ps1 exit code (0 = healthy; <0 means
                              "did not run" -- self-skip, treated as a non-fail UNVERIFIED note).
        -ValidationExitCode : PIM.DeployValidation.Tests.ps1 exit code (0 = all passed).
        -PreviousRevision   : the captured rollback target (pre-deploy ACA revision).
        -CodeStepRan        : did the 'code' (build+deploy) step actually run this session? (only
                              then is an auto-rollback meaningful).

      Returns { Healthy; smokeRan; validationRan; rollback = { action; revision; reason } }.
    #>
    param(
        [int]$SmokeExitCode = 0,
        [int]$ValidationExitCode = 0,
        [string]$PreviousRevision,
        [bool]$CodeStepRan = $true
    )
    $smokeRan      = ($SmokeExitCode -ge 0)
    $validationRan = ($ValidationExitCode -ge 0)
    # a self-skip (exit < 0) is UNVERIFIED, not a fail. A ran-but-nonzero exit is a fail.
    $smokeOk      = (-not $smokeRan)      -or ($SmokeExitCode -eq 0)
    $validationOk = (-not $validationRan) -or ($ValidationExitCode -eq 0)
    $healthy = ($smokeOk -and $validationOk)

    # build the rollback plan via the reused verifier when we can; else inline.
    $worstExit = 0
    if ($smokeRan -and $SmokeExitCode -ne 0) { $worstExit = $SmokeExitCode }
    if ($validationRan -and $ValidationExitCode -ne 0) { $worstExit = $ValidationExitCode }

    $rb = $null
    if (Get-Command Get-PimVerifyVerdict -ErrorAction SilentlyContinue) {
        $prev = if ($CodeStepRan) { $PreviousRevision } else { '' }   # only roll back code we deployed
        $v = Get-PimVerifyVerdict -ExitCode $worstExit -PreviousRevision $prev
        $rb = $v.rollback
    }
    if (-not $rb) {
        if ($healthy) { $rb = [pscustomobject]@{ action='none'; revision=''; reason='healthy' } }
        elseif ($CodeStepRan -and "$PreviousRevision".Trim()) { $rb = [pscustomobject]@{ action='rollback'; revision="$PreviousRevision".Trim(); reason='validation failed -- roll the code back to the captured revision' } }
        else { $rb = [pscustomobject]@{ action='none'; revision=''; reason='validation failed but no rollbackable code deploy / no rollback target' } }
    }

    return [pscustomobject]@{
        Healthy       = [bool]$healthy
        smokeRan      = $smokeRan
        validationRan = $validationRan
        rollback      = $rb
    }
}

# ---- rollback plan (pure) -------------------------------------------------
function Get-PimDeployRollbackPlan {
    <#
      Given the steps that ACTUALLY RAN this session (in run order) and the captured rollback
      target, produce the ordered list of rollback actions to undo a failed deploy. We only
      auto-undo ROLLBACKABLE steps (the catalog flags 'code' as rollbackable -- rolling the ACA
      revision back). Schema upgrades are idempotent + non-destructive by design, so they are
      NEVER auto-reverted (reverting a schema add could drop a column with data); infra/app-reg
      stand-up is additive and left in place. Rollback is in REVERSE run order.

      Inputs:
        -RanStepKeys      : @('appreg','infra','schema','code') -- keys of steps that ran, in order.
        -PreviousRevision : captured pre-deploy revision (the code rollback target).
        -Hosted           : hosted flavour (only hosted code rolls back to a prior ACA revision).
      Returns { actions = @( { key; action; detail } ) } in the order to execute them.
    #>
    param(
        [string[]]$RanStepKeys,
        [string]$PreviousRevision,
        [bool]$Hosted = $true
    )
    $catalog = @{}
    foreach ($s in (Get-PimDeployStepCatalog)) { $catalog["$($s.key)"] = $s }
    $actions = New-Object System.Collections.Generic.List[object]

    $ran = @($RanStepKeys)
    # reverse run order.
    for ($i = $ran.Count - 1; $i -ge 0; $i--) {
        $k = "$($ran[$i])"
        if (-not $catalog.ContainsKey($k)) { continue }
        $s = $catalog[$k]
        if (-not $s.rollbackable) { continue }
        if ($k -eq 'code') {
            if ($Hosted -and "$PreviousRevision".Trim()) {
                $actions.Add([pscustomobject]@{ key=$k; action='rollback-revision'; detail="reactivate prior ACA revision '$("$PreviousRevision".Trim())'" }) | Out-Null
            } else {
                $actions.Add([pscustomobject]@{ key=$k; action='manual'; detail='no rollback target captured (or community/local deploy) -- MANUAL rollback required' }) | Out-Null
            }
        }
    }
    return [pscustomobject]@{ actions = $actions.ToArray() }
}

# ---- end-of-run summary (pure) --------------------------------------------
function Get-PimDeploySummary {
    <#
      Compose the end-of-run summary the orchestrator prints + returns. PURE: it just classifies
      the overall status from the per-step outcomes + the verify verdict + whether a rollback ran.

      Inputs:
        -StepOutcomes : @( { key; ran; ok } ... ) -- one per executed step (ran=$true) or planned.
        -Verdict      : Get-PimDeployVerifyVerdict result (or $null when verify did not run).
        -RolledBack   : did an auto-rollback execute this session?
        -PlanOnly     : was this a plan-only (-WhatIf) run? (named PlanOnly, not WhatIf, so this
                        PURE classifier never advertises ShouldProcess semantics it does not have.)
      Returns { status; whatIf; healthy; rolledBack; steps; failedSteps }.
        status in { planned | success | unverified | rolledback | failed }.
    #>
    param(
        [object[]]$StepOutcomes,
        [object]$Verdict,
        [bool]$RolledBack = $false,
        [switch]$PlanOnly
    )
    $outcomes = @($StepOutcomes)
    $failed = @($outcomes | Where-Object { $_.ran -and -not $_.ok } | ForEach-Object { "$($_.key)" })

    $status =
        if ($PlanOnly) { 'planned' }
        elseif ($RolledBack) { 'rolledback' }
        elseif ($failed.Count -gt 0) { 'failed' }
        elseif ($Verdict -and -not $Verdict.Healthy) { 'rolledback' }
        elseif ($Verdict -and -not $Verdict.smokeRan -and -not $Verdict.validationRan) { 'unverified' }
        else { 'success' }

    return [pscustomobject]@{
        status      = $status
        whatIf      = [bool]$PlanOnly
        healthy     = $(if ($Verdict) { [bool]$Verdict.Healthy } else { $null })
        rolledBack  = [bool]$RolledBack
        steps       = $outcomes
        failedSteps = $failed
    }
}
