#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS — update all hosted containers to a new image (zero-downtime), or roll back.

.DESCRIPTION
    One image (pim-manager:<tag>) runs every worker. This builds a new tag in ACR (unless
    -SkipBuild) and rolls each container app to it via `az containerapp update --image`,
    which creates a NEW REVISION and shifts traffic with no downtime (min-1 replica). Apps
    pull via their AcrPull managed identity, so no registry creds are needed at update time.

    -Rollback <revisionSuffix> reactivates a prior revision instead of building/updating
    (instant rollback). List revisions with: az containerapp revision list -n <app> -g <rg>.

.EXAMPLE
    .\Update-PimContainers.ps1 -ImageTag 1.1.7
    Build 1.1.7 from current source and roll manager + all workers to it.

.EXAMPLE
    .\Update-PimContainers.ps1 -ImageTag 1.1.5 -SkipBuild
    Roll all apps to an existing tag (no rebuild).

.NOTES
    Re-runnable. Safe: each app updates independently; a failed app doesn't block the rest.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # BUG-25: NOT [Parameter(Mandatory)] any more -- a rollback has no image to tag.
    # Every automatic rollback path in the product (Invoke-PimDeployAll, Invoke-PimUpdate x2,
    # Invoke-PimSyncAutomateIT -- 4 call sites) invokes `-Rollback <rev>` WITHOUT -ImageTag,
    # exactly as documented on -Rollback below ("ignores ImageTag/build"). Mandatory turned
    # all four into an immediate throw:
    #     auto-rollback failed: Cannot process command because of one or more missing
    #     mandatory parameters: ImageTag.
    # So the safety net could never fire -- in an unattended run it cannot even prompt. It is
    # still REQUIRED for a real roll; that is enforced just below, where the mode is known.
    [string]$ImageTag,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$AcrName,
    [string]$ImageRepo     = 'pim-manager',
    # 🔴 EMPTY = DISCOVER. This used to default to a hard-coded list of SIX apps
    # (ca-pim-manager, ca-pim-scheduler, ca-pim-engine, ca-pim-connector, ca-pim-deltaqueue,
    # ca-pim-discovery). Only ca-pim-manager exists in this topology, so a DEFAULT invocation
    # always failed:
    #     (ResourceNotFound) The Resource 'Microsoft.App/containerApps/ca-pim-scheduler' ... not found
    # Recorded as a DEPLOY-3 item on 2026-08-31 -- "the default should be DISCOVERED, not assumed"
    # -- and every deploy since had to pass -Apps ca-pim-manager by hand. That was survivable while
    # a human ran it, and stopped being survivable on 2026-09-03 when the DAILY UNATTENDED update
    # started calling it: the build succeeded, the deploy died on an app that never existed, and
    # the operator's central fix reached nobody.
    # Discovery is also correct as the topology grows -- a new worker is picked up without editing
    # a list here, which is what made the list wrong in the first place.
    [string[]]$Apps        = @(),
    [switch]$SkipBuild,
    [string]$Rollback,     # revision NAME to reactivate (rollback mode; ignores ImageTag/build)
    # 🔴 A REVISION NAME IS NOT A DURABLE ROLLBACK ANCHOR -- §53.6.
    # Container Apps garbage-collects inactive revisions. Measured on the internal environment
    # 2026-09-10: the deploy captured 'ca-pim-manager--0000003' as its rollback target, rolled to
    # --0000004, the smoke gate failed, and the auto-rollback found that --0000003 NO LONGER
    # EXISTED -- `revision list` returned exactly one row. The safety net printed
    #     AUTO-ROLLBACK FAILED ... ROLL BACK BY HAND
    # for a fleet it could in fact have rolled back, because the thing it needed was still sitting
    # in ACR: the IMAGE the old revision was running.
    # 🔑 An image digest cannot be garbage-collected out from under us the way a revision can, and
    # rolling TO it simply creates a new revision from the old bits -- the same end state the
    # reactivate would have produced. So: reactivate when the revision survives (cheaper, keeps
    # the revision history honest), fall back to the image when it does not.
    [string]$RollbackImage,
    [switch]$SkipSmoke,    # opt OUT of the post-deploy GUI smoke gate (NOT recommended)
    # --- inputs the post-deploy gate needs (DOC-06) --------------------------------------
    # The gate used to be invoked as `& $smoke -AsReleaseGate` with NOTHING passed, even though
    # this script already knows the resource group and the Manager's name. So on any deploy that
    # did not happen to have PIM_HOSTED_* set in the environment, the gate could not find the app's
    # revisions or its workspace and failed as "the gate could not RUN" -- which reads like a broken
    # Manager and is not. Same missing-passthrough class as BUG-44/46: the caller had the values and
    # simply never handed them over. Defaults come from the env so an operator shell still works.
    [string]$SmokeWorkspaceId = $(if ($env:PIM_HOSTED_LA_WORKSPACE)   { $env:PIM_HOSTED_LA_WORKSPACE }   else { '' }),
    [string]$SmokeEasyAuthAud = $(if ($env:PIM_HOSTED_EASYAUTH_AUD)   { $env:PIM_HOSTED_EASYAUTH_AUD }   else { '' }),
    [string]$SmokeFqdn        = $(if ($env:PIM_HOSTED_FQDN)           { $env:PIM_HOSTED_FQDN }           else { '' }),
    # BUG-09: a requested app that does not exist is an ERROR, not a silent filter.
    # Set this only for a genuinely partial environment -- it still refuses to roll ZERO.
    [switch]$AllowMissingApps,

    # --- BUG-48: the scheduled tick Job is rolled HERE, with the apps -------------------------
    # In cron mode the reconciling workload is a Container Apps JOB, not an app, and this script
    # had no concept of one. INFRA (Setup-PimContainers) stamped the Job with the digest that the
    # mutable tag pointed at BEFORE the code step rebuilt that same tag, and the code step then
    # rolled only the apps -- so a single deploy run left `manager = <new digest>` and
    # `tick job = <old digest>` and the engine permanently ran one build behind the GUI. Measured
    # live on the production environment across three consecutive runs.
    # 🪤 It SELF-HEALS on the next deploy, which is exactly why it survived: it never looks like a
    # failure, only like "the Job is running yesterday's code". And BUG-40's digest pinning is
    # what makes it DURABLE instead of self-correcting whenever the Job next starts.
    # Rolling the Job from the same place that rolls the apps, off the same resolved digest, is
    # what removes the skew -- there is no longer a second place that decides what the Job runs.
    [string]$TickJobName   = 'ca-pim-tick',
    [switch]$SkipTickJob,
    # The Manager app. A PRODUCT name, identical in every install -- not a customer fact.
    # 🪤 The rollback block below referenced $ManagerApp before this parameter existed, so it read
    # as $null: the "prefer the Manager" filter matched nothing and it silently fell back to the
    # first rolled app. Correct in a single-app deploy, and wrong the moment there are two.
    [string]$ManagerApp    = 'ca-pim-manager',

    # --- BUG-55: a roll that changes DESIRED STATE must be an explicit act --------------------
    # The image is built from `git archive HEAD`, so it carries every desired-state change sitting
    # in HEAD -- not just the fix you meant to ship. One such roll rewrote 217 of 325 production
    # group policies overnight and nothing alerted. The gate below refuses to roll when the shipped
    # policy baseline differs from the one recorded on the target; this switch is how you say "yes,
    # that baseline change is the point of this deploy".
    [switch]$AcceptBaselineChange,

    # 🔴 EVERY az CALL IN THIS SCRIPT USED TO RUN AGAINST THE AMBIENT DEFAULT CONTEXT, and this is
    # the script that WRITES. On a machine logged into more than one directory the default is a
    # coin flip -- on mgmt1 it is frequently a DIFFERENT COMPANY'S subscription (CLAUDE.md: "often
    # the DEFAULT context"), which is how `az containerapp update` could be aimed at somebody
    # else's tenant by an operator who passed exactly the right -ResourceGroup and -AcrName.
    # Same family as SEC-12 and the TEST-09 drift gate: an ambient identity standing in for an
    # explicit one. Every invocation below is scoped with @subArgs.
    [string]$SubscriptionId = $(if ($env:PIM_SUBSCRIPTION_ID) { $env:PIM_SUBSCRIPTION_ID } else { '' }),

    # --- 2026-09-13: THE RING GATE (operator: "nothing releases to ring 2 without my approve") ------
    # Before anything is built or rolled, the environment's in-cloud updater is read. On ring >= 2 this
    # REFUSES to roll to any version channel.json does not approve for that ring (and refuses when the
    # channel cannot be read). Ring 0/1 roll exactly as before. BUG-170: a deployed environment with NO
    # ring (or no updater) is REFUSED too -- it predates the ring. The way past is -OverrideRingGate with
    # -Reason (printed and audited), or -PendingUpdateRing when this same deploy run installs the ring.
    [string]$UpdateJobName = 'ca-pim-update',
    [switch]$OverrideRingGate,
    [string]$Reason,
    [ValidateRange(-1,3)][int]$PendingUpdateRing = -1,
    [string]$PendingUpdateSourceUrl = ''
)

# Built once, spliced into every az invocation. Empty => ambient (a single-directory machine),
# which is stated out loud below rather than assumed.
$subArgs = @()
if ("$SubscriptionId".Trim()) { $subArgs = @('--subscription', "$SubscriptionId".Trim()) }
$ErrorActionPreference = 'Stop'
# BUG-25: -ImageTag is mandatory for a ROLL and meaningless for a ROLLBACK. Enforcing that
# here (rather than on the parameter) keeps the roll path exactly as strict as it was while
# letting the rollback path actually run. Fail loudly, not by prompting: an unattended
# deploy has no console to answer with.
if (-not $Rollback -and -not "$RollbackImage".Trim() -and -not "$ImageTag".Trim()) {
    throw "Update-PimContainers: -ImageTag is required unless you are rolling back. Pass -ImageTag <tag> to roll, or -Rollback <revision> (or -RollbackImage <image>) to roll back."
}
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
# 🔴 BEFORE THE FIRST az CALL, AND BEFORE _PimSetupShared (which is loaded much further down).
# Defines a guarded `az` shadow so a WARNING on az's stderr cannot abort this script under
# $ErrorActionPreference='Stop'. That is not hypothetical: it stopped internal prod deploying
# a correctly-built image on 2026-09-05. Read the header of _PimAz.ps1 before removing this;
# in particular, the `2>$null` on the az calls below does NOT prevent it.
. "$here\_PimAz.ps1"
. "$here\_PimUpdateRing.ps1"    # Assert-PimRollRingGate -- the ring decides, not whoever runs this
$solRoot = Split-Path -Parent (Split-Path -Parent $here)        # ...\PIM4EntraPS
$repoRoot = (Resolve-Path (Join-Path $here '..\..\..\..')).Path   # AutomateIT repo root
# 🔴 §71.41 -- WHICH OTHER JOBS FOLLOW THE MANAGER is decided by the SAME pure function the in-cloud
# updater uses (Get-PimAcaJobRollPlan, §53.5), loaded -- not copied -- so the host and the cloud roller
# cannot disagree about it. Loaded before the dot-source guard so the offline test exercises THIS copy.
# Only its pure functions are called from here; its ARM half (Invoke-PimArm) is never reached.
. (Join-Path $solRoot 'engine\_shared\PIM-ArmContainerApps.ps1')
# BUG-40: the TAG reference is provenance for humans. What is actually rolled is $image, which
# is re-pointed at the immutable digest by the pre-roll guard below once az can resolve it.
$imageTagRef = "$AcrName.azurecr.io/$ImageRepo`:$ImageTag"
$image = $imageTagRef
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
# Defined alongside Step deliberately. Setup-PimContainers.ps1 shipped with calls to a `Warn` it
# never defined, and it killed step 6 of every estate deploy that passed a certificate (BUG-117).
# A missing one-line helper is not a small bug when it only fires on an uncommon branch.
function Note($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }

# BUG-55: the desired-state fingerprint helpers (pure; unit-tested in Test-PimPolicyBaseline.ps1).
$baselineLib = Join-Path $solRoot 'engine\_shared\PIM-PolicyBaseline.ps1'
if (Test-Path -LiteralPath $baselineLib) { . $baselineLib }

# The resource TAG the baseline is recorded under. A tag rather than anything cleverer because it
# travels with the deployed resource, survives revisions, and can be read back with one az call.
$script:PimBaselineTagName = 'pim-policy-baseline'

function Get-PimShippedBaseline {
    # What the image ABOUT TO BE ROLLED wants, read from the tree it is built from.
    # 🪤 Honest limitation, stated where it is relied on: with -SkipBuild and an arbitrary older
    # -ImageTag the local tree is NOT necessarily that image's content, so the comparison is
    # "what this tree would ship" vs "what the target last recorded". In every normal path the
    # image was just built from this tree in the same run, which is when the gate matters.
    if (-not (Get-Command Get-PimPolicyBaselineFingerprint -ErrorAction SilentlyContinue)) { return $null }
    Get-PimPolicyBaselineFingerprint -TemplateDir (Join-Path $solRoot 'templates\policy')
}
function Get-PimRecordedBaseline {
    param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Name)
    # 🪤 DO NOT USE `--query tags.<key>` HERE. Two independent things break it, and together they
    # made this gate silently never fire -- caught only by rolling twice against a live estate
    # environment (the first roll RECORDED the tag, the second still reported "none"):
    #   1. JMESPath: `tags.pim-policy-baseline` is not a lookup, the dashes parse as SUBTRACTION.
    #      It needs `tags."pim-policy-baseline"`.
    #   2. PowerShell strips those inner quotes when passing the string to a native command, so az
    #      receives the unquoted form anyway and answers `invalid jmespath_type value`.
    # Fetching the object and indexing it in PowerShell sidesteps both. `$obj.tags.$Name` resolves
    # a property by VARIABLE, so the dashes never reach a parser.
    # 🪤 `2>$null` is load-bearing: az on this host emits a cryptography UserWarning on stderr that
    # otherwise contaminates the stream and makes ConvertFrom-Json throw on "D:\a\_work...".
    $raw = if ($Kind -eq 'job') { az containerapp job show @subArgs -g $ResourceGroup -n $Name -o json 2>$null }
           else                 { az containerapp show @subArgs     -g $ResourceGroup -n $Name -o json 2>$null }
    if (-not "$raw".Trim()) { return '' }
    $obj = $null
    try { $obj = ($raw | Out-String) | ConvertFrom-Json } catch { return '' }
    if (-not $obj -or -not $obj.tags) { return '' }
    $key = $script:PimBaselineTagName
    $v = "$($obj.tags.$key)".Trim()
    if ($v -eq 'None') { return '' }
    return $v
}
function Set-PimRecordedBaseline {
    param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Hash)
    # 🪤 `az containerapp update --tags` REPLACES the resource's whole tag set, which would quietly
    # delete a customer's cost-centre/owner tags as a side effect of a deploy. `az tag update
    # --operation Merge` is the ARM tags API and adds this one key without touching the others.
    # Best-effort: failing to RECORD must not fail a roll that already succeeded -- it degrades to
    # "unknown" on the next roll, which warns rather than blocks.
    try {
        $rid = if ($Kind -eq 'job') { az containerapp job show @subArgs -g $ResourceGroup -n $Name --query id -o tsv 2>$null }
               else                 { az containerapp show @subArgs     -g $ResourceGroup -n $Name --query id -o tsv 2>$null }
        if (-not "$rid".Trim()) { Write-Warning "  could not resolve the resource id of $Kind '$Name' -- policy baseline NOT recorded."; return }
        az tag update @subArgs --resource-id "$("$rid".Trim())" --operation Merge --tags "$($script:PimBaselineTagName)=$Hash" -o none 2>$null
        if ($LASTEXITCODE -ne 0) { Write-Warning "  could not record the policy baseline on $Kind '$Name' (az tag update exit $LASTEXITCODE) -- the next roll will report it as UNKNOWN." }
    } catch { Write-Warning "  could not record the policy baseline on $Kind '$Name': $($_.Exception.Message)" }
}

# ---------------------------------------------------------------------------
# BUG-09 -- PURE helpers. This script once printed "All apps rolled to 2.4.238 ...
# Done" and exited 0 on a run where it rolled NOTHING: `-Apps` matched no existing
# app, the roll loop had zero iterations, and the summary was a fixed string that
# never consulted reality. Five workers stayed 8 versions behind while the deploy
# reported success -- a plausible mechanism for the 7-week drift in TEST-09.
# These are pure so tests/Test-PimUpdateContainers.ps1 can prove them offline.
# ---------------------------------------------------------------------------
function Resolve-PimAppList {
    <#
      Normalise a -Apps value. A container app name can never contain a comma,
      semicolon or whitespace, so an element carrying one is unambiguously a
      joined string -- which is exactly how this was mis-invoked (a shell passing
      "a,b,c" as ONE argument). Splitting it is a correction, not a guess.
      Returns a de-duplicated string[] preserving order.
    #>
    [CmdletBinding()] param([object[]]$Apps = @())
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($a in @($Apps)) {
        if ($null -eq $a) { continue }
        foreach ($p in ("$a" -split '[,;\s]+')) {
            $t = "$p".Trim()
            if ($t -and -not $out.Contains($t)) { [void]$out.Add($t) }
        }
    }
    return $out.ToArray()
}

function Get-PimAppRollPlan {
    <#
      Decide what to roll. PURE -- takes the requested list and the list that
      actually exists, and returns @{ roll; missing; ok; reason }.
      Rules, in order:
        * NOTHING to roll  -> never ok. A deploy that rolls zero apps is not a
          deploy, whatever the caller asked for or allowed.
        * MISSING apps     -> not ok unless -AllowMissingApps, and they are NAMED.
    #>
    [CmdletBinding()]
    param([string[]]$Requested = @(), [string[]]$Existing = @(), [bool]$AllowMissing = $false)
    $req = @($Requested | Where-Object { "$_".Trim() })
    $ex  = @($Existing  | Where-Object { "$_".Trim() })
    $roll    = @($req | Where-Object { $ex -contains $_ })
    $missing = @($req | Where-Object { $ex -notcontains $_ })
    if ($roll.Count -eq 0) {
        return [pscustomobject]@{ roll=@(); missing=$missing; ok=$false
            reason = "no requested app exists in the resource group -- refusing to report a deploy that rolled nothing (requested: $($req -join ', '))" }
    }
    if ($missing.Count -gt 0 -and -not $AllowMissing) {
        return [pscustomobject]@{ roll=$roll; missing=$missing; ok=$false
            reason = "requested app(s) not found: $($missing -join ', ') -- pass -AllowMissingApps if that is intended" }
    }
    return [pscustomobject]@{ roll=$roll; missing=$missing; ok=$true; reason='' }
}

function Invoke-PimRollSameRepoJobs {
    <#
      §71.41 -- roll every OTHER job in the resource group that runs the Manager's image REPOSITORY
      onto -TargetImage, verify each by reading it back, and return @{ rolled; failed; checked }.

      🔴 This roller used to roll the apps and the tick Job and nothing else, so `ca-pim-downlink-s6`
      (a managed tenant's pull) and `ca-pim-publish` (the master's publisher) kept the tag they were
      deployed with. A pull job left on a pre-§71.35 image refuses every Key Vault signed bundle
      (SIGNATURE INVALID -- it only knows the certificate) while the Manager and tick report the new
      version; a publish job never picks up producer fixes. The in-cloud updater already rolls them
      (§53.5); this makes the SAME decision with the SAME function (Get-PimAcaJobRollPlan).
      🔒 Same REPOSITORY only -- a customer's own job in this group is not ours to retag; a
      multi-container job is skipped, never guessed at. Excluded by name: the tick Job (rolled -- or
      deliberately skipped -- on its own) and the update job (it re-stamps itself and records its own
      LAST_GOOD; Deploy-PimUpdateJob owns its configuration).
      Every job is attempted, so one failure does not leave the rest behind too; the CALLER decides
      what a failure means (fatal on a roll, loud but not fatal on a rollback -- like the tick Job).
      🪤 "Could not look" is not "there was nothing else": a failed enumeration is a failure.
    #>
    param([Parameter(Mandatory)][string]$TargetImage, [string]$Label = '')
    $out = [pscustomobject]@{ rolled = New-Object System.Collections.Generic.List[string]
                              failed = New-Object System.Collections.Generic.List[string]; checked = $false }
    $jobsJson = (@(az containerapp job list @subArgs -g $ResourceGroup -o json 2>$null) -join "`n")
    $ok = ($LASTEXITCODE -eq 0 -and "$jobsJson".Trim())
    $allJobs = @()
    if ($ok) {
        # 🪤 PS 5.1: ConvertFrom-Json emits a JSON array as ONE object; piping it enumerates the items.
        try { $allJobs = @((ConvertFrom-Json $jobsJson) | ForEach-Object { $_ }) } catch { $ok = $false }
    }
    if (-not $ok) {
        [void]$out.failed.Add("<job enumeration> -- az containerapp job list failed in $ResourceGroup, so jobs other than the tick Job were NOT checked")
        return $out
    }
    $out.checked = $true
    $plan = Get-PimAcaJobRollPlan -Jobs $allJobs -TargetImage $TargetImage -Exclude @("$TickJobName".Trim(), "$UpdateJobName".Trim())
    foreach ($s in @($plan.skip)) { Write-Host "  skipping job $($s.name): $($s.reason)" -ForegroundColor DarkGray }
    if (-not @($plan.roll).Count) { Write-Host "  no other job in $ResourceGroup runs $($plan.repo) -- nothing more to roll." -ForegroundColor DarkGray }
    foreach ($j in @($plan.roll)) {
        if ("$($j.from)".Trim() -ieq "$TargetImage".Trim()) {
            [void]$out.rolled.Add($j.name)
            Write-Host "  job '$($j.name)' is already on the target image (no skew)." -ForegroundColor Green
            continue
        }
        if (-not $PSCmdlet.ShouldProcess($j.name, "job update --image $TargetImage")) { continue }
        Step "Roll job $($j.name)$Label (same repository as the Manager)"
        az containerapp job update @subArgs -g $ResourceGroup -n $j.name --image $TargetImage -o none
        if ($LASTEXITCODE -ne 0) {
            [void]$out.failed.Add("$($j.name) -- 'az containerapp job update' exit $LASTEXITCODE (still on $("$($j.from)" -replace '.*[@:]',''))")
            continue
        }
        # Same evidence standard as the apps and the tick Job: a tag match is not proof (BUG-40).
        $live = az containerapp job show @subArgs -g $ResourceGroup -n $j.name --query "properties.template.containers[0].image" -o tsv 2>$null
        $jv = Test-PimImageDeployed -Expected $TargetImage -Running "$live".Trim()
        if (-not $jv.ok) { [void]$out.failed.Add("$($j.name) -- post-roll verification FAILED: $($jv.reason)"); continue }
        [void]$out.rolled.Add($j.name)
        Write-Host "  job '$($j.name)' rolled $("$($j.from)" -replace '.*@','') -> $("$live".Trim() -replace '.*@','') and verified." -ForegroundColor Green
    }
    return $out
}

# Dot-sourced by the offline test -> stop before doing anything live.
if ($MyInvocation.InvocationName -eq '.') { return }

. "$here\_PimSetupShared.ps1"
Show-PimSetupBanner -ScriptName 'Update-PimContainers' -SolutionRoot $solRoot

# Post-deploy GUI smoke gate. After ca-pim-manager rolls to the new image we run the live
# hosted smoke (tests/live/Test-PimManagerHostedSmoke.ps1) and FAIL the deploy if the GUI
# is broken — exactly the symptoms that shipped "green" before: render mode 'static
# (read-only)' instead of SQL, GET /api/active-assignments 500, empty tenant cache,
# "Templates need server mode", read-only GUI. A deploy is NOT "done" until this passes.
# Run with -AsReleaseGate, so a check that cannot run (no az, not logged in) is a FAILURE here (exit 1);
# ad hoc the smoke exits 2 for a skip -- never 0, which is reserved for "ran and passed".
function Invoke-ManagerSmokeGate {
    <#
      BUG-57: RETURNS ITS VERDICT, and the caller must print that rather than a fixed string.

      There are four paths on which this function does not run the gate at all (-WhatIf,
      -SkipSmoke, the Manager was not among the rolled apps, the smoke script is missing) and the
      deploy's closing line used to say "post-deploy GUI smoke gate passed" on every one of them.
      Observed live on 2026-08-11: a `-SkipSmoke` roll printed "skipping post-deploy GUI smoke
      gate" and then, two lines later, "post-deploy GUI smoke gate passed".

      That is precisely the BUG-09 family this file exists to prevent -- a deploy claiming what it
      did not verify -- and the §7a rule is explicit that a self-skip is a SKIP, not a pass. The
      fix is the same shape as BUG-09's: report what actually happened, never a fixed string.
    #>
    param([string]$RepoRoot, [string[]]$RolledApps)
    if (-not $PSCmdlet.ShouldProcess('ca-pim-manager','post-deploy GUI smoke gate')) { return 'NOT RUN (-WhatIf)' }
    if ($SkipSmoke) { Write-Host "==> -SkipSmoke set: skipping post-deploy GUI smoke gate (NOT recommended)." -ForegroundColor Yellow; return 'SKIPPED (-SkipSmoke -- NOT a pass)' }
    if ('ca-pim-manager' -notin $RolledApps) { return 'not applicable (the Manager was not rolled)' }  # gate only when the Manager was actually rolled
    $smoke = Join-Path $RepoRoot 'SOLUTIONS/PIM4EntraPS/tests/live/Test-PimManagerHostedSmoke.ps1'
    if (-not (Test-Path -LiteralPath $smoke)) {
        Write-Host "::warning:: post-deploy GUI smoke not found at $smoke -- cannot gate the deploy." -ForegroundColor Yellow
        return 'NOT RUN (smoke script missing -- NOT a pass)'
    }
    Step "Post-deploy GUI smoke gate (Test-PimManagerHostedSmoke.ps1)"
    # TEST-05: -AsReleaseGate makes a self-skip a FAILURE. On a DEPLOY there is no such
    # thing as "the gate couldn't run, carry on": without an Easy Auth audience the smoke
    # used to skip the whole live-HTTP layer and still exit 0, so the two assertions
    # CLAUDE.md §7a names as the gate (GET / = 200, /api/active-assignments = 200) had
    # never actually been enforced on a deploy. Ad-hoc runs keep the honest skip.
    # Hand the gate everything this script already knows. -ResourceGroup in particular was the
    # difference between "the gate ran" and "the gate could not find the app": the smoke's own
    # default for it is EMPTY, so without this it could not list revisions to read live logs from.
    $smokeArgs = @{ App = 'ca-pim-manager'; ResourceGroup = $ResourceGroup; AsReleaseGate = $true }
    if ("$SmokeWorkspaceId".Trim()) { $smokeArgs['WorkspaceId'] = $SmokeWorkspaceId }
    if ("$SmokeEasyAuthAud".Trim()) { $smokeArgs['EasyAuthAud'] = $SmokeEasyAuthAud }
    if ("$SmokeFqdn".Trim())        { $smokeArgs['Fqdn']        = $SmokeFqdn }
    # 🔴 BUG-102 -- THE FIFTH TOOL WITH THE UNSCOPED-`az` DEFECT.
    # Commit 623fc29a scoped "the whole deploy path to an explicit subscription -- four tools,
    # one defect". This call site was the fifth and was missed, so the release GATE ran against
    # the ambient default context while the DEPLOY it was gating ran against the explicit one.
    # Measured on the 2.4.254 roll: the apps rolled correctly against
    # 54468121-… (myfamilynetwork) and the gate then reported
    #     az context: … / sub 772440e1-… (ambient default)
    # -- ExpertsLiveDK, A DIFFERENT COMPANY (CLAUDE.md: "often the DEFAULT context" on mgmt1).
    # From there it could not read the Log Analytics workspace and could not mint an Easy Auth
    # token, so BOTH layers self-skipped and the gate failed a HEALTHY deployment.
    # The smoke script has accepted -SubscriptionId all along; nobody handed it over. Same
    # missing-passthrough class as BUG-44/46 and the SmokeWorkspaceId fix directly above.
    if ("$SubscriptionId".Trim())   { $smokeArgs['SubscriptionId'] = "$SubscriptionId".Trim() }
    # 🔴 §53.7 -- tell the gate which version we actually put there. The image carries HEAD's
    # VERSION; the working tree can be ahead of HEAD, and when it was, the gate failed a deploy
    # that had done exactly what it was asked to do. The tag we rolled is the honest expectation.
    # Only a version-shaped tag is a version claim: 'latest' or a digest says nothing about what
    # the app should report, and the gate falls back to the VERSION file for those.
    if ("$ImageTag".Trim() -match '^\d+\.\d+\.\d+' -and -not $smokeArgs.ContainsKey('ExpectedVersion')) {
        $smokeArgs['ExpectedVersion'] = "$ImageTag".Trim()
    }
    # 🔴 TEST-16 -- DERIVE THE EASY AUTH AUDIENCE INSTEAD OF DEMANDING IT.
    # Without an audience the gate cannot mint a token, so the whole live-HTTP layer self-skips
    # and -AsReleaseGate turns that into a FAILED DEPLOY -- on every roll where the operator did
    # not happen to export PIM_HOSTED_EASYAUTH_AUD. That is a gate failing for want of a value
    # the app itself publishes: `az containerapp auth show` returns the app's own
    # allowedAudiences, and the app is right there, being deployed by this script.
    # (The Log Analytics workspace is derived the same way, but inside the smoke script, where
    # ad-hoc runs benefit from it too.)
    if (-not $smokeArgs.ContainsKey('EasyAuthAud')) {
        $subArgs = @(); if ("$SubscriptionId".Trim()) { $subArgs = @('--subscription', "$SubscriptionId".Trim()) }
        try {
            $aud = @(az containerapp auth show -n $smokeArgs['App'] -g $ResourceGroup @subArgs `
                        --query "identityProviders.azureActiveDirectory.validation.allowedAudiences" -o tsv 2>$null) |
                   Where-Object { "$_".Trim() } | Select-Object -First 1
            if ("$aud".Trim()) {
                $smokeArgs['EasyAuthAud'] = "$aud".Trim()
                Write-Host "    derived Easy Auth audience from the app's own auth config" -ForegroundColor DarkGray
            }
        } catch { }
    }
    # Write-Host, not a Note helper: this script defines only Step(), and calling an undefined
    # helper is parse-clean and throws at RUNTIME -- inside the gate, on every deploy.
    # Report what the gate is ACTUALLY given -- read $smokeArgs, not the raw parameters. Printed
    # from the parameters it announced "easyAuthAud=(NOT set -- the live-HTTP layer will fail the
    # gate)" on the very line after "derived Easy Auth audience from the app's own auth config",
    # and then the gate passed. A status line that contradicts the run it describes is worth
    # exactly nothing to whoever is reading the deploy log at 2am.
    Write-Host ("    gate inputs: rg=$ResourceGroup " +
                "workspace=$(if ($smokeArgs.ContainsKey('WorkspaceId')) {'set'} else {'(derived by the gate from the Container Apps environment)'}) " +
                "easyAuthAud=$(if ($smokeArgs.ContainsKey('EasyAuthAud')) {'set'} else {'(NOT set -- the live-HTTP layer will fail the gate)'}) " +
                "fqdn=$(if ($smokeArgs.ContainsKey('Fqdn')) {'set'} else {'(derived from az)'})") -ForegroundColor DarkGray
    # 🔴 WAKE THE APP FIRST. THE MANAGER SCALES TO ZERO.
    # It is deployed with --min-replicas 0 on purpose (it is a front end over SQL and holds no
    # state), so after a roll there is NO RUNNING REPLICA until someone asks for a page. The gate's
    # primary evidence is the app's OWN BOOT LOG -- "[store] SQL mode", the active instance, the
    # render mode, the version line -- and a container that has never started has never logged any
    # of it. Measured at a live customer 2026-09-08: four assertions failed and
    # `az containerapp logs show` answered "Could not find a replica for this app", on a deployment
    # that was fine. The gate was reading a log that did not exist yet.
    # 🪤 The failure does not look like "not started". It looks like "started and came up WRONG" --
    # no SQL-mode line reads exactly the same as a Manager that fell back to static. The most
    # alarming possible symptom, produced by an app that simply had not been asked to run.
    # One HTTP GET is the whole fix: any response -- 200, 302 to Easy Auth, even 401 -- means the
    # cold start happened. We deliberately do not care about the status code here; the gate's own
    # live-HTTP layer is what judges the response.
    $wakeFqdn = if ($smokeArgs.ContainsKey('Fqdn')) { "$($smokeArgs['Fqdn'])".Trim() } else {
        $wakeSubArgs = @(); if ("$SubscriptionId".Trim()) { $wakeSubArgs = @('--subscription', "$SubscriptionId".Trim()) }
        @(az containerapp show @wakeSubArgs -g $ResourceGroup -n $smokeArgs['App'] `
            --query "properties.configuration.ingress.fqdn" -o tsv 2>$null) |
          Where-Object { "$_".Trim() } | Select-Object -First 1
    }
    if ("$wakeFqdn".Trim()) {
        Write-Host "    waking $($smokeArgs['App']) (min-replicas 0: no replica = no boot log for the gate to read)" -ForegroundColor DarkGray
        # 🪤 THE FIRST VERSION OF THIS JUDGED THE HTTP RESPONSE, AND THAT WAS THE WRONG QUESTION.
        # It treated "the request came back" as the wake and "the request threw" as a failure. But a
        # cold start behind Easy Auth routinely exceeds a 60s timeout -- ACA holds the connection
        # while it pulls the image and starts the container -- and a timeout raises an exception
        # with NO .Response, so every attempt scored as "could not reach the app" while the app was
        # in fact starting. Measured at a live customer 2026-09-08: six attempts, seven minutes,
        # "could not reach ... to wake the app", and the container was coming up the whole time.
        # 🔑 The request is a TRIGGER, not a measurement. Fire it, ignore whatever it does, and ask
        # AZURE whether a replica exists -- that is the thing we actually need to be true.
        $replicaSubArgs = @(); if ("$SubscriptionId".Trim()) { $replicaSubArgs = @('--subscription', "$SubscriptionId".Trim()) }
        $wakeUrl = "https://$("$wakeFqdn".Trim())/"
        $reps    = @()
        foreach ($attempt in 1..20) {
            try { [void](Invoke-WebRequest -Uri $wakeUrl -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop) } catch { }
            $reps = @(az containerapp replica list @replicaSubArgs -g $ResourceGroup -n $smokeArgs['App'] `
                        --query "[].name" -o tsv 2>$null) | Where-Object { "$_".Trim() }
            if ($reps.Count) { Write-Host "    replica up after ~$($attempt * 15)s -- the gate has a boot log to read." -ForegroundColor DarkGray; break }
            Start-Sleep -Seconds 5
        }
        if (-not $reps.Count) {
            # 🔴 SAY WHY, rather than leaving the gate to infer "broken" from an absent log.
            # "No replica" has two completely different causes -- nothing ever asked the app to
            # start, or it starts and dies -- and they need opposite responses. The gate cannot
            # tell them apart from Log Analytics, because both look like silence. ACA knows.
            Write-Host "    no replica after ~5 minutes of waking attempts. Asking Azure why:" -ForegroundColor Yellow
            $activeRev = @(az containerapp revision list @replicaSubArgs -g $ResourceGroup -n $smokeArgs['App'] `
                            --query "[].{name:name,active:properties.active,created:properties.createdTime}" -o json 2>$null | ConvertFrom-Json) |
                         Where-Object { $_.active } |
                         Sort-Object { try { [datetimeoffset]$_.created } catch { [datetimeoffset]::MinValue } } |
                         Select-Object -Last 1
            if ($activeRev) {
                $state = az containerapp revision show @replicaSubArgs -g $ResourceGroup -n $smokeArgs['App'] `
                            --revision "$($activeRev.name)" `
                            --query "{running:properties.runningState,health:properties.healthState,replicas:properties.replicas}" -o json 2>$null
                Write-Host "      revision $($activeRev.name): $state" -ForegroundColor Yellow
                Write-Host "      A 'Failed'/'Degraded' running state is the app CRASHING ON START -- read its logs." -ForegroundColor Yellow
                Write-Host "      A 'Running'/'RunningAtMaxScale' state with no replica means it scaled back to zero" -ForegroundColor Yellow
                Write-Host "      between the wake and this check, which is harmless and the gate can be re-run." -ForegroundColor Yellow
            }
            Write-Host "    the gate will now report a Manager it could not observe -- read the states above BEFORE believing 'broken'." -ForegroundColor Yellow
        }
    } else {
        Write-Host "    no ingress FQDN resolved -- cannot wake the app before the gate reads its boot log." -ForegroundColor Yellow
    }

    & $smoke @smokeArgs
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "Update-PimContainers: post-deploy GUI smoke FAILED (exit $code). Either the hosted Manager is broken (render mode / active-assignments / tenant cache / read-write) or the gate could not RUN (az login / -EasyAuthAud / FQDN) -- a gate that did not run is not a pass. Roll back with -Rollback <oldRevision>."
    }
    Write-Host "==> Post-deploy GUI smoke gate PASSED (all probes ran; skips count as failures here)." -ForegroundColor Green
    return 'PASSED'
}

# BUG-09: normalise first (a shell can deliver "a,b,c" as ONE argument), then decide
# EXPLICITLY -- a requested app that does not exist must not evaporate into a silent
# intersection. The old line was `$existing = @($Apps | Where-Object { az ... })`, which
# dropped anything misspelled, renamed, in another RG or momentarily unreadable without
# a word, and the summary still claimed every app was rolled.
$Apps = Resolve-PimAppList -Apps $Apps
if (-not $Apps.Count) {
    # 🔒 DISCOVER, because a hard-coded list is a claim about a topology this script cannot see.
    # Only apps whose image comes from THIS repo's image repo are candidates -- rolling something
    # unrelated that happens to live in the same resource group would be worse than rolling
    # nothing. If discovery finds none, say so plainly rather than proceeding with an empty list
    # (Get-PimAppRollPlan already refuses "rolled zero apps", and this makes the reason readable).
    Step "no -Apps given: DISCOVERING container apps in $ResourceGroup"
    $discovered = @(az containerapp list @subArgs -g $ResourceGroup --query "[].name" -o tsv 2>$null |
                    ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if (-not $discovered.Count) {
        throw "Update-PimContainers: no container apps found in '$ResourceGroup'. Nothing to roll -- check the resource group and the az context (a context you cannot see returns EMPTY, not an error)."
    }
    $Apps = @($discovered)
    Note ("discovered: " + ($Apps -join ', '))
}
Step ("apps requested: " + ($Apps -join ', '))
$existing = @($Apps | Where-Object { az containerapp show @subArgs -g $ResourceGroup -n $_ --query name -o tsv 2>$null })

$plan = Get-PimAppRollPlan -Requested $Apps -Existing $existing -AllowMissing:$AllowMissingApps
if ($plan.missing.Count -gt 0) {
    Write-Host ("  NOT FOUND in {0}: {1}" -f $ResourceGroup, ($plan.missing -join ', ')) -ForegroundColor Red
}
if (-not $plan.ok) { throw "Update-PimContainers: $($plan.reason)" }
$existing = @($plan.roll)
Step ("apps present: " + ($existing -join ', '))

if ($Rollback -or "$RollbackImage".Trim()) {   # §53.6: EITHER anchor puts us in rollback mode
    # BUG-09 applies here too: track what was ACTUALLY rolled back. An app with no
    # matching revision was previously skipped in silence and still counted toward
    # "Rollback done." -- and during an incident, a rollback you believe happened but
    # didn't is worse than a failed one.
    $rolledBack = New-Object System.Collections.Generic.List[string]
    $noRevision = New-Object System.Collections.Generic.List[string]
    foreach ($app in $existing) {
        # 🪤 An EMPTY $Rollback makes the filter "*​*", which matches EVERY revision -- the image-only
        # rollback path would then silently reactivate whatever revision the API listed first.
        # No name, no name lookup.
        $rev = $null
        if ("$Rollback".Trim()) {
            $rev = @(az containerapp revision list @subArgs -g $ResourceGroup -n $app --query "[].name" -o tsv 2>$null) |
                       Where-Object { "$_".Trim() -and "$_" -like "*$Rollback*" } | Select-Object -First 1
        }
        if (-not $rev) { [void]$noRevision.Add($app); continue }
        if ($PSCmdlet.ShouldProcess($app,"rollback to $rev")) {
            # 🔴 "ALREADY ACTIVE" IS THE GOAL, NOT A FAILURE.
            # ACA answers `(RevisionAlreadyInRequestedState) Revision X is already active!` when you
            # activate the revision that is already serving. This threw, so every auto-rollback whose
            # target happened to be the current revision reported
            #     AUTO-ROLLBACK FAILED ... the fleet is NOT on the prior revision. ROLL BACK BY HAND
            # about a fleet that was exactly where it was supposed to be. Measured repeatedly at a
            # live customer 2026-09-08, on top of a genuine deploy failure -- so the operator was
            # reading a fabricated second emergency while diagnosing a real first one.
            # 🪤 Alarm text is a feature only when it is true. A safety net that cries wolf during
            # the one situation it exists for is worse than no safety net, because it costs
            # attention exactly when attention is scarcest.
            # 🪤 THE FIRST FIX FOR THIS MATCHED ON THE ERROR TEXT, AND COULD NOT WORK.
            # `az` here is the guarded shadow (_PimAz.ps1), whose entire purpose is that stderr
            # never reaches the caller: it splits the error records out and prints them itself,
            # returning only stdout. So `2>&1` captured nothing, the match never fired, and the
            # throw happened exactly as before -- a fix that shipped, ran, and changed nothing.
            # Measured on the next live run, which printed the identical AUTO-ROLLBACK FAILED.
            # 🔑 Ask the API instead of parsing a message. "Is this revision already the one
            # serving?" is a question with a definite answer, and it does not depend on error text,
            # locale, or which layer swallowed the stream.
            $alreadyActive = @(az containerapp revision list @subArgs -g $ResourceGroup -n $app `
                                --query "[].{name:name,active:properties.active}" -o json 2>$null | ConvertFrom-Json) |
                             Where-Object { $_.active -and "$($_.name)" -eq "$rev" }
            if ($alreadyActive) {
                Write-Host "  $app is ALREADY on $rev -- nothing to roll back." -ForegroundColor Green
                [void]$rolledBack.Add($app)
                continue
            }
            az containerapp revision activate @subArgs -g $ResourceGroup -n $app --revision $rev -o none
            if ($LASTEXITCODE -ne 0) { throw "Update-PimContainers: revision activate FAILED (exit $LASTEXITCODE) for $app -> $rev." }
            az containerapp ingress traffic set @subArgs -g $ResourceGroup -n $app --revision-weight "$rev=100" -o none 2>$null
            Write-Host "  $app -> $rev (100%)" -ForegroundColor Green
            [void]$rolledBack.Add($app)
        }
    }
    if ($noRevision.Count -gt 0) {
        if ("$Rollback".Trim()) {
            Write-Host ("  NO revision matching '{0}': {1}" -f $Rollback, ($noRevision -join ', ')) -ForegroundColor Red
        } else {
            Write-Host ("  no revision name supplied for: {0}" -f ($noRevision -join ', ')) -ForegroundColor DarkGray
        }
        # §53.6 -- the revision was garbage-collected, but the image it ran is still in ACR.
        # Roll to that instead of declaring the fleet unrecoverable.
        if ("$RollbackImage".Trim()) {
            Step ("revision '{0}' is gone -- falling back to the pre-deploy IMAGE: {1}" -f $Rollback, $RollbackImage)
            foreach ($app in @($noRevision.ToArray())) {
                if (-not $PSCmdlet.ShouldProcess($app, "rollback to image $RollbackImage")) { continue }
                $global:LASTEXITCODE = 0
                az containerapp update @subArgs -g $ResourceGroup -n $app --image "$RollbackImage" -o none
                if ($LASTEXITCODE -ne 0) {
                    Write-Host ("  image rollback FAILED for {0} (az exit {1})" -f $app, $LASTEXITCODE) -ForegroundColor Red
                    continue
                }
                # Prove it, the same way the forward roll does -- a rollback believed but not
                # verified is the failure mode this whole block exists to close.
                $now = "$(az containerapp show @subArgs -g $ResourceGroup -n $app --query 'properties.template.containers[0].image' -o tsv 2>$null)".Trim()
                $ver = Test-PimImageDeployed -Expected "$RollbackImage" -Running $now
                if (-not $ver.ok) {
                    Write-Host ("  {0} is NOT on the rollback image -- {1}. Not counting it as rolled back." -f $app, $ver.reason) -ForegroundColor Red
                    continue
                }
                Write-Host ("  {0} -> {1} (new revision from the pre-deploy image)" -f $app, $RollbackImage) -ForegroundColor Green
                [void]$rolledBack.Add($app)
            }
        } else {
            Write-Host "  no -RollbackImage was passed, so there is no second anchor to fall back to." -ForegroundColor DarkGray
        }
    }
    if ($rolledBack.Count -eq 0 -and -not $WhatIfPreference) {
        throw ("Update-PimContainers: rollback matched NO revision named like '$Rollback' on any app" +
               $(if ("$RollbackImage".Trim()) { " and the image fallback to '$RollbackImage' did not take either" } else { " and no -RollbackImage fallback was supplied" }) +
               " -- nothing was rolled back. Refusing to report success. List revisions with: az containerapp revision list -n <app> -g $ResourceGroup")
    }
    Step ("Rollback done for {0} app(s): {1}" -f $rolledBack.Count, ($rolledBack -join ', '))
    # BUG-48, the inverse skew -- and it lands during an incident, which is when it is least
    # affordable. A Container Apps JOB has no revisions, so reactivating an app revision cannot
    # include it: the apps go back and the tick Job keeps running the build being rolled back.
    # 🔴 §52.2 -- THIS USED TO PRINT A WARNING AND STOP THERE, saying "the previous digest is not
    # knowable from a revision name". It is: the revision we just reactivated is RUNNING the
    # previous image, and ACA will tell us which one. Measured at a live customer 2026-09-08 --
    # the auto-rollback put the Manager back and left the tick Job on the failed build, then
    # asked the operator, mid-incident, to reconstruct a digest by hand.
    # 🪤 Ask the API instead of reasoning from a name -- the same correction as §51.2, one step
    # further along the same script.
    if (-not $SkipTickJob -and "$TickJobName".Trim()) {
        $jn = "$TickJobName".Trim()
        $jobImg = "$(az containerapp job show @subArgs -g $ResourceGroup -n $jn --query "properties.template.containers[0].image" -o tsv 2>$null)".Trim()
        if ($jobImg) {
            # The image the ROLLED-BACK-TO revision actually runs. Take it from the Manager when it
            # is among the rolled apps (the Job runs the Manager's image), else the first one.
            $srcApp = @(@($rolledBack.ToArray()) | Where-Object { "$_" -eq "$ManagerApp" }) + @($rolledBack.ToArray()) | Select-Object -First 1
            $srcRev = @(az containerapp revision list @subArgs -g $ResourceGroup -n $srcApp `
                          --query "[?properties.active].{name:name,image:properties.template.containers[0].image}" -o json 2>$null | ConvertFrom-Json) |
                      Where-Object { "$($_.name)" -like "*$Rollback*" } | Select-Object -First 1
            $wantImg = "$($srcRev.image)".Trim()
            if (-not $wantImg) {
                Write-Warning ("  Rollback reactivated app REVISIONS only, and the image of the rolled-back revision could not be read " +
                               "from '$srcApp'. The tick Job '$jn' is still on $jobImg -- the engine and the GUI are on DIFFERENT " +
                               "builds. Put it back explicitly: az containerapp job update -g $ResourceGroup -n $jn --image <previous digest reference>")
            } elseif ($wantImg -eq $jobImg) {
                Write-Host "  tick Job '$jn' is already on the rolled-back image -- no skew." -ForegroundColor Green
            } elseif ($PSCmdlet.ShouldProcess($jn, "roll the tick Job back to $wantImg")) {
                Step "Roll tick Job $jn back -> the image of $($srcRev.name)"
                az containerapp job update @subArgs -g $ResourceGroup -n $jn --image $wantImg -o none
                $jobNow = "$(az containerapp job show @subArgs -g $ResourceGroup -n $jn --query "properties.template.containers[0].image" -o tsv 2>$null)".Trim()
                if ($jobNow -eq $wantImg) {
                    Write-Host "  tick Job '$jn' rolled back $($jobImg -replace '.*@','') -> $($jobNow -replace '.*@','') and verified." -ForegroundColor Green
                } else {
                    # Not fatal -- the APPS are back, which is the point of a rollback -- but never quiet.
                    Write-Warning ("  tick Job '$jn' did NOT roll back (still $jobNow, wanted $wantImg). The engine and the GUI are on " +
                                   "DIFFERENT builds. Stamp it by hand: az containerapp job update -g $ResourceGroup -n $jn --image $wantImg")
                }
            }
            # §71.41 -- the pull / publish jobs follow the rollback too, or they stay on the build being rolled
            # back while the Manager goes back (and the smoke gate's job-skew check fails the rollback).
            # Loud but NOT fatal, like the tick Job above: the APPS are back, which is the point of a rollback.
            if ($wantImg) {
                $rbJobs = Invoke-PimRollSameRepoJobs -TargetImage $wantImg -Label ' back (rollback)'
                foreach ($f in @($rbJobs.failed)) {
                    Write-Warning ("  rollback: $f -- that job and the GUI are on DIFFERENT builds. Stamp it by hand: " +
                                   "az containerapp job update -g $ResourceGroup -n <job> --image $wantImg")
                }
            }
        }
    }
    # A rollback is only "good" if the rolled-back Manager actually serves a healthy GUI.
    # BUG-57: capture the verdict (it is a RETURN VALUE now) and state it. Left uncaptured it
    # would also leak the string into this script's output.
    $rbVerdict = Invoke-ManagerSmokeGate -RepoRoot $repoRoot -RolledApps @($rolledBack.ToArray())
    Step ("Rollback complete; post-deploy GUI smoke gate: {0}" -f $rbVerdict)
    return
}

# ---- 2026-09-13: THE RING GATE, before anything is built or rolled -----------------------------
# A rollback (above) returns an environment to what it was already running and is not a release, so
# it is not gated. A ROLL is. On ring >= 2 the target must be exactly what channel.json approves.
Step "Ring gate: may $ResourceGroup take $ImageTag?"
[void](Assert-PimRollRingGate -ResourceGroup $ResourceGroup -SubscriptionArgs $subArgs -TargetVersion $ImageTag `
          -UpdateJobName $UpdateJobName -OverrideRingGate:$OverrideRingGate -Reason $Reason -Caller 'Update-PimContainers' `
          -PendingUpdateRing $PendingUpdateRing -PendingUpdateSourceUrl $PendingUpdateSourceUrl)

if (-not $SkipBuild) {
    Step "Build $image via Build-PimManagerImage (clean git-archive context)"
    if ($PSCmdlet.ShouldProcess($image,'Build-PimManagerImage')) {
        # Use the dedicated builder, NOT a raw `az acr build . ` of the repo root: the
        # raw context includes .claude/worktrees and blows MAX_PATH on the hosted build,
        # so the build FAILED while a missing $LASTEXITCODE check let the roll proceed to
        # a tag that was never pushed -> ImagePullFailure / ActivationFailed (bit 2.4.227
        # + 2.4.228, 2026-06-18). Build-PimManagerImage builds from a clean `git archive`
        # subtree and throws on failure.
        # 🔴 -SubscriptionId FORWARDED. The builder has DECLARED it all along and this caller never
        # passed it, so `az acr build` ran against the ambient default context -- which on mgmt1 is
        # another company's subscription, and the build died with "the resource 'acrpimmfnpr' could
        # not be found in subscription 'ELDK Event Hub'". Declared-but-not-forwarded: the exact
        # shape of BUG-29 / SEC-10b / BUG-78 / BUG-79, and the reason scoping this script's OWN az
        # calls was not enough -- the one call it delegates was still unscoped.
        $buildArgs = @{ ImageTag = $ImageTag; AcrName = $AcrName; ImageRepo = $ImageRepo }
        if ("$SubscriptionId".Trim()) { $buildArgs['SubscriptionId'] = "$SubscriptionId".Trim() }
        & (Join-Path $PSScriptRoot 'Build-PimManagerImage.ps1') @buildArgs
        if ($LASTEXITCODE -ne 0) { throw "Update-PimContainers: image build FAILED (exit $LASTEXITCODE) for $image -- NOT rolling (a roll to an unbuilt tag creates an ImagePullFailure revision). Fix the build and re-run." }
    }
}

# Pre-roll guard (belt-and-suspenders, runs even with -SkipBuild): NEVER roll to a tag
# that isn't actually in the registry. A failed/skipped build previously rolled to a
# missing tag -> the new revision ImagePullFailures + sits ActivationFailed while the old
# revision keeps serving, so the "deploy" silently does nothing. Fail loudly instead.
if (-not $WhatIfPreference) {
    # 🔴 "I CANNOT READ THE REGISTRY" IS NOT "THE TAG IS ABSENT" -- and this guard could not tell
    # the two apart. `az acr repository show-tags` is a DATA-PLANE call, so on a registry with
    # public network access off it is refused from a deploy host outside the VNet:
    #     Unable to get AAD authorization tokens ... Access to registry 'acrpim<t>.azurecr.io'
    # The refusal text landed in $existingTags and the guard concluded the tag was missing --
    #     image tag '2.4.324' is NOT present in ACR (tags: Username: )
    # note "Username:" in the tag list, which is CLI error text being read as data. Measured at a
    # customer 2026-09-11, on an image `az acr build` had pushed 30 seconds earlier and named by
    # digest in its own output. The deploy then auto-rolled back a perfectly good image.
    # 🔑 THE BUILD OUTPUT IS THE STRONGER EVIDENCE. A digest that came back from `az acr build` is
    # proof the push happened; a failed query is proof of nothing. So an UNREADABLE registry falls
    # back to it, and only a registry that answered -- and answered without this tag -- refuses.
    # Same class as Resolve-PimMiAppId's "a refusal is not a delay": an error must not be read as
    # a negative result. Third place this private-registry assumption has surfaced.
    $global:LASTEXITCODE = 0
    $existingTags = @(az acr repository show-tags @subArgs -n $AcrName --repository $ImageRepo -o tsv 2>$null)
    $tagReadFailed = ($LASTEXITCODE -ne 0) -or
                     (@($existingTags | Where-Object { "$_" -match '(?i)^(Username|Password|WARNING|ERROR):' }).Count -gt 0)
    if ($tagReadFailed) {
        $builtDigest = "$($global:PIM_LastBuiltDigest)".Trim()
        if ($builtDigest -match '^sha256:') {
            Write-Host "  registry tag list UNREADABLE (private registry, no data-plane route from here)." -ForegroundColor DarkGray
            Write-Host "  proceeding on the digest the build just returned: $builtDigest" -ForegroundColor DarkGray
            $existingTags = @($ImageTag)   # the build is the evidence; the query is not available
        } else {
            throw ("Update-PimContainers: could not READ the tag list from ACR '$AcrName' (its public endpoint is " +
                   "off, so this host has no data-plane route), and no digest was published by a build in this run. " +
                   "Refusing to roll blind. Build in the same invocation (so the digest is known), or run from " +
                   "inside the VNet.")
        }
    }
    if ($existingTags -notcontains $ImageTag) {
        throw "Update-PimContainers: image tag '$ImageTag' is NOT present in ACR '$AcrName/$ImageRepo' (tags: $($existingTags -join ', ')) -- refusing to roll (would ImagePullFailure). Build it first (omit -SkipBuild) or pick an existing tag."
    }
    Write-Host "  Verified $ImageRepo`:$ImageTag exists in ACR before rolling." -ForegroundColor Green

    # BUG-40: roll the DIGEST, not the tag. Rebuilding a tag moves the pointer but leaves the
    # app's image field identical, so ARM creates no revision and the platform keeps serving the
    # image it already pulled -- measured live 2026-08-09, where the roll reported success and
    # the next executions ran the previous build. Pinning makes new content a changed field.
    # DECLARED **AND** FORWARDED, same as the builder's call: this is the lookup that pins what
    # actually gets rolled (BUG-40), so resolving it in the wrong subscription is not a cosmetic
    # failure -- it is the difference between deploying the new image and silently keeping the old.
    # 🔑 PREFER THE DIGEST THE BUILD JUST RETURNED. Resolve-PimAcrImageDigest reads the registry's
    # DATA PLANE and THROWS rather than degrading -- correct on a public registry, where an
    # unresolvable tag really does mean the image is absent. On a private one it means only that
    # this host cannot reach the endpoint, and it would fail the roll of an image `az acr build`
    # pushed seconds earlier and named by digest in its own output. Setup-PimContainers already
    # prefers the built digest for exactly this reason; the roller did not, so the same deploy
    # could build successfully and then refuse to deploy what it built.
    $imageDigest = $null
    $builtNow = "$($global:PIM_LastBuiltDigest)".Trim()
    if ($builtNow -match '^sha256:' -and "$($global:PIM_LastBuiltImageRef)" -match [regex]::Escape("$ImageRepo`:$ImageTag")) {
        $imageDigest = $builtNow
        Write-Host "  digest from the build that just ran (registry not queried)" -ForegroundColor DarkGray
    }
    if (-not $imageDigest) {
        $rdArgs = @{ AcrName = $AcrName; Repository = $ImageRepo; Tag = $ImageTag }
        if ("$SubscriptionId".Trim()) { $rdArgs['SubscriptionId'] = "$SubscriptionId".Trim() }
        $imageDigest = Resolve-PimAcrImageDigest @rdArgs
    }
    $image = New-PimImageReference -Registry "$AcrName.azurecr.io" -Repository $ImageRepo -Digest $imageDigest
    Write-Host "  Pinned $ImageRepo`:$ImageTag -> $imageDigest" -ForegroundColor Green
}

# --- BUG-55 GATE: state the DESIRED-STATE delta this image carries, before rolling anything -----
# A deploy that changes what the engine WANTS is a different act from one that changes how it
# WORKS. Nothing distinguished them, so a lease fix shipped an unapproved policy baseline and
# rewrote 217 of 325 production group policies overnight.
# This runs BEFORE the roll on purpose: after the roll the tick can pick the new desired state up
# within one cron interval, and "we noticed afterwards" is what happened last time.
# Runs under -WhatIf too, and REPORTS instead of throwing there: previewing a deploy is exactly
# when you want to know it carries a baseline change, and a preview that stays silent about the
# one thing this gate exists for would be worse than no preview.
$script:PimShippedBaseline = Get-PimShippedBaseline
if ($script:PimShippedBaseline -and $script:PimShippedBaseline.count -gt 0) {
    $readFrom = @($existing)[0]
    $recordedHash = Get-PimRecordedBaseline -Kind 'app' -Name $readFrom
    # Per-template hashes are not carried in the tag (values are length-limited); the combined
    # hash decides, and the local set NAMES what moved when it differs from a known recording.
    $verdict = Compare-PimPolicyBaseline -Current $script:PimShippedBaseline -RecordedHash $recordedHash `
                                         -RecordedTemplates @{} -Accept:$AcceptBaselineChange
    Step "Desired-state check: $($script:PimShippedBaseline.count) policy template(s), fingerprint $($script:PimShippedBaseline.hash)"
    if ($verdict.unknown) {
        Write-Warning ("  $($verdict.reason). Rolling anyway and RECORDING the current fingerprint, so the " +
                       "next roll can answer this. If you did not intend to change desired state, WhatIf the policy " +
                       "scopes now: Invoke-PimEngineCore.ps1 -Scope GroupsPolicies -Mode Full -WhatIf (expect update=0).")
    }
    elseif ($verdict.changed -and -not $verdict.allowed -and $WhatIfPreference) {
        Write-Warning ("  WHAT-IF: this roll WOULD BE REFUSED -- $($verdict.reason). " +
                       "Re-run for real with -AcceptBaselineChange if the baseline change is intended.")
    }
    elseif ($verdict.changed -and -not $verdict.allowed) {
        throw ("Update-PimContainers: REFUSING TO ROLL -- $($verdict.reason). " +
               "Rolling this image changes what the engine WANTS, not just how it works: within one tick interval it " +
               "will start converging every managed scope onto the new baseline (BUG-55 -- this is how 217 of 325 " +
               "production group policies were rewritten overnight). " +
               "If that is the point of this deploy, re-run with -AcceptBaselineChange. If it is NOT, the templates in " +
               "your tree differ from the deployed baseline and you should find out why before shipping. " +
               "Either way, WhatIf it first: Invoke-PimEngineCore.ps1 -Scope GroupsPolicies -Mode Full -WhatIf")
    }
    elseif ($verdict.changed) {
        Write-Warning "  $($verdict.reason) -- proceeding because -AcceptBaselineChange was given. This deploy WILL change desired state."
    }
    else {
        Write-Host "  $($verdict.reason)" -ForegroundColor Green
    }
}

# 🔴 STAMP THE CONTENT HASH SO THE NEXT DEPLOY CAN SKIP A POINTLESS REBUILD.
# `Invoke-PimUpdate` decides whether to rebuild by comparing the pulled Manager content hash with
# the RUNNING one, which it reads from the Manager app's PIM_MANAGER_CONTENT_HASH env var. Nothing
# in the product ever set that variable, so the running hash was ALWAYS blank, the comparison could
# never succeed, and every deploy printed
#     GuiUpdateRequired = True  (running GUI content hash unknown -- cannot prove parity, rebuild to be safe)
# and rebuilt an identical image. Measured at a live customer 2026-09-09 -- and "rebuild to be
# safe" is the correct behaviour for an unknown, so the defect hid behind a sensible-looking line.
# 🪤 The image now BAKES the hash (Dockerfile ARG/ENV), but `az containerapp show` reports only the
# env vars in the app TEMPLATE, not the ones inside the image -- so baking alone changed nothing.
# The value has to be stamped where the reader actually looks.
# 🔴 BUG-174 -- "SAME SOURCE DIRECTORY" WAS NOT TRUE. This stamp hashed tools\pim-manager only, while the
# builder and the Invoke-PimUpdate detector hash the WHOLE solution (what the Dockerfile copies). The
# running hash therefore never equalled the pulled one, GuiUpdateRequired was always True, and every
# host-side update rebuilt an identical image. The file set is now defined ONCE
# (Get-PimSolutionContentHash, PIM-UpdateLifecycle.ps1) and all three call it: agreement by construction.
# 🪤 With -SkipBuild and an OLDER -ImageTag the local tree is not that image's content (the same honest
# limitation as the baseline gate above); the detector still compares VERSION as well, so an older image
# with a newer tree's hash is re-rolled on version, never skipped.
# 🔴 THE BUG-55 POLICY-BASELINE GATE COULD NEVER RUN. It is guarded by
# `Get-Command Get-PimPolicyBaselineFingerprint`, defined in PIM-PolicyBaseline.ps1, which this
# file never loaded -- so every roll reported "no policy baseline recorded on the target yet --
# cannot tell whether this image changes desired state" and rolled anyway. Measured on a live
# rebuild 2026-09-10, and found by the structural audit rather than by reading: like the five
# scheduler jobs and the update mailer, it degraded honestly and so was never chased.
try { . (Join-Path $solRoot 'engine\_shared\PIM-PolicyBaseline.ps1') } catch { }

$mgrHashArgs = @()
try {
    . (Join-Path $solRoot 'engine\_shared\PIM-UpdateLifecycle.ps1')
    $mgrHash = Get-PimSolutionContentHash -SolutionRoot $solRoot
    if ("$mgrHash".Trim()) { $mgrHashArgs = @('--set-env-vars', "PIM_MANAGER_CONTENT_HASH=$mgrHash") }
} catch { Write-Host "  (could not compute the Manager content hash: $($_.Exception.Message) -- the next deploy will rebuild)" -ForegroundColor DarkGray }

$rolled = New-Object System.Collections.Generic.List[string]
foreach ($app in $existing) {
    Step "Roll $app -> $ImageTag"
    if ($PSCmdlet.ShouldProcess($app,"update --image $image")) {
        # Only the MANAGER carries the stamp -- it is the app whose GUI content the hash describes,
        # and the only one the updater reads it from. --set-env-vars adds/updates just this key and
        # leaves every other variable alone.
        $stamp = @(); if ("$app" -eq "$ManagerApp") { $stamp = $mgrHashArgs }
        az containerapp update @subArgs -g $ResourceGroup -n $app --image $image @stamp -o none
        # BUG-09: `az containerapp update` failing was never checked -- a failed roll
        # counted the same as a successful one.
        if ($LASTEXITCODE -ne 0) { throw "Update-PimContainers: 'az containerapp update' FAILED (exit $LASTEXITCODE) for $app -- deploy aborted. Roll back with -Rollback <oldRevision> if a partial roll is a problem." }
        # 🔴 `[0].name` IS NOT THE NEW REVISION. It is whatever the API happens to return first --
        # in practice the OLDEST. Measured at a live customer 2026-09-08: every roll reported
        # "new revision: ca-pim-manager--yt1y3qs" while the revision actually serving was
        # ca-pim-manager--0000016. Two consequences, and the second is the dangerous one:
        # the operator is told a wrong name to roll back to, and this value is what the caller
        # captures as its ROLLBACK TARGET -- so auto-rollback kept trying to activate a revision
        # that was already active ("RevisionAlreadyInRequestedState"), reported AUTO-ROLLBACK
        # FAILED, and left a scary message about a fleet that was never in danger.
        # Read the ACTIVE revision and take the NEWEST by creation time. Sorted in PowerShell:
        # sort_by() cannot be used here (see the --query rule -- cmd.exe eats the parentheses).
        $revRows = @()
        try {
            $revRows = @(az containerapp revision list @subArgs -g $ResourceGroup -n $app `
                            --query "[].{name:name,created:properties.createdTime,active:properties.active}" `
                            -o json 2>$null | ConvertFrom-Json)
        } catch {}
        $rev = @($revRows | Where-Object { $_.active }) |
                   Sort-Object { try { [datetimeoffset]$_.created } catch { [datetimeoffset]::MinValue } } |
                   Select-Object -Last 1 | ForEach-Object { $_.name }
        if (-not "$rev".Trim()) { $rev = '(could not resolve the active revision)' }
        Write-Host "  $app new revision: $rev" -ForegroundColor Green
        [void]$rolled.Add($app)
    }
}

# BUG-09: VERIFY, then claim. Re-read each app's live image and assert it really is what we
# rolled. This is the only statement that earns the words "all apps on X" -- the previous
# summary was a fixed string printed regardless of what happened.
#
# BUG-40 CHANGED WHAT "IS" MEANS HERE. This check used to compare the live TAG against the
# requested TAG, and that is not a verification: when a tag is rebuilt, the live tag and the
# requested tag are the SAME STRING while the running content is stale. It passed, on the exact
# deploy that silently kept running week-old code. Comparing DIGESTS is what makes it real, and
# Test-PimImageDeployed refuses to accept a tag match as evidence when a digest was expected.
if (-not $WhatIfPreference -and $rolled.Count -gt 0) {
    $notOnImage = New-Object System.Collections.Generic.List[string]
    foreach ($app in $rolled) {
        $live = az containerapp show @subArgs -g $ResourceGroup -n $app --query "properties.template.containers[0].image" -o tsv 2>$null
        $v = Test-PimImageDeployed -Expected $image -Running "$live".Trim()
        if (-not $v.ok) { [void]$notOnImage.Add("$app -- $($v.reason)") }
    }
    if ($notOnImage.Count -gt 0) {
        throw "Update-PimContainers: post-roll verification FAILED -- $($notOnImage.Count) app(s) are NOT running $image`: $($notOnImage -join '; '). The roll reported success but the live image disagrees; do NOT treat this deploy as done."
    }
    Write-Host ("  Verified {0} app(s) now running {1} (tag {2}): {3}" -f $rolled.Count, $image, $ImageTag, ($rolled -join ', ')) -ForegroundColor Green
}

if ($rolled.Count -eq 0 -and -not $WhatIfPreference) {
    throw "Update-PimContainers: nothing was rolled -- refusing to report success."
}
Step ("Rolled {0} app(s) to {1} (zero-downtime rolling revisions): {2}" -f $rolled.Count, $ImageTag, ($rolled -join ', '))

# --- BUG-48: roll the scheduled tick Job to the SAME digest, from the same place ---------------
# Not a separate resolve: $image is the digest reference the apps were just verified on, so the
# Job cannot end up on a different build than the GUI. Absence of the Job is NORMAL (always-on
# mode has no Job), so it is a skip -- but a skip that SAYS SO, because "no Job here" and "we
# forgot the Job" looked identical before.
if (-not $SkipTickJob) {
    $jobName = "$TickJobName".Trim()
    if (-not $jobName) {
        Write-Host "  tick Job: -TickJobName is blank -- skipping." -ForegroundColor DarkGray
    }
    else {
        $jobExists = az containerapp job show @subArgs -g $ResourceGroup -n $jobName --query name -o tsv 2>$null
        if (-not "$jobExists".Trim()) {
            Write-Host "  tick Job '$jobName' does not exist in $ResourceGroup -- nothing to roll (expected in always-on mode)." -ForegroundColor DarkGray
        }
        elseif ($PSCmdlet.ShouldProcess($jobName, "job update --image $image")) {
            Step "Roll tick Job $jobName -> $ImageTag"
            $jobBefore = az containerapp job show @subArgs -g $ResourceGroup -n $jobName --query "properties.template.containers[0].image" -o tsv 2>$null
            az containerapp job update @subArgs -g $ResourceGroup -n $jobName --image $image -o none
            if ($LASTEXITCODE -ne 0) {
                throw "Update-PimContainers: 'az containerapp job update' FAILED (exit $LASTEXITCODE) for $jobName -- the APPS are already on $ImageTag, so the deploy is now SKEWED: the apps and the scheduled job are on different images. Re-run this script, or stamp the Job by hand: az containerapp job update -g $ResourceGroup -n $jobName --image $image"
            }
            # Same evidence standard as the apps: a tag match is not proof (BUG-40).
            $jobLive = az containerapp job show @subArgs -g $ResourceGroup -n $jobName --query "properties.template.containers[0].image" -o tsv 2>$null
            $jv = Test-PimImageDeployed -Expected $image -Running "$jobLive".Trim()
            if (-not $jv.ok) {
                throw "Update-PimContainers: tick Job '$jobName' post-roll verification FAILED -- $($jv.reason). The apps are on $image but the Job is not; do NOT treat this deploy as done."
            }
            if ("$jobBefore".Trim() -eq "$jobLive".Trim()) {
                Write-Host "  tick Job '$jobName' was ALREADY on $image (no skew)." -ForegroundColor Green
            } else {
                Write-Host "  tick Job '$jobName' rolled $("$jobBefore".Trim() -replace '.*@','') -> $("$jobLive".Trim() -replace '.*@','') and verified." -ForegroundColor Green
            }
            if ($script:PimShippedBaseline -and $script:PimShippedBaseline.count -gt 0) {
                Set-PimRecordedBaseline -Kind 'job' -Name $jobName -Hash $script:PimShippedBaseline.hash
            }
        }
    }
}

# --- §71.41: EVERY OTHER JOB THAT RUNS THE MANAGER'S IMAGE follows it, off the same digest ---------
# The decision and the read-back live in Invoke-PimRollSameRepoJobs (above), shared with the rollback
# path. 🔴 On a ROLL a job left on the previous build is a FAILED deploy, not a warning -- the same
# standard as the tick Job, and the same wording as the in-cloud updater ("NOT FULLY UPDATED").
$otherJobsRolled = New-Object System.Collections.Generic.List[string]
if ($rolled.Count -gt 0 -or $WhatIfPreference) {
    Step "Roll every other job running the Manager's image repository"
    $sameRepo = Invoke-PimRollSameRepoJobs -TargetImage $image -Label " -> $ImageTag"
    foreach ($n in @($sameRepo.rolled)) {
        [void]$otherJobsRolled.Add($n)
        if ($script:PimShippedBaseline -and $script:PimShippedBaseline.count -gt 0) {
            Set-PimRecordedBaseline -Kind 'job' -Name $n -Hash $script:PimShippedBaseline.hash
        }
    }
    if (@($sameRepo.failed).Count -gt 0) {
        throw ("Update-PimContainers: NOT FULLY UPDATED -- the apps are on $image but these jobs are still on the previous build: " +
               (@($sameRepo.failed) -join '; ') + ". The engine's jobs and the GUI are now on DIFFERENT builds (a pull job on an old " +
               "image can refuse every signed bundle); do NOT treat this deploy as done. Re-run this script, or stamp each by hand: " +
               "az containerapp job update -g $ResourceGroup -n <job> --image $image")
    }
}

# BUG-55: record the fingerprint ONLY after the roll has been verified. Recording it earlier would
# mean a failed or partial deploy still moved the recorded baseline forward, and the next roll
# would compare against a state that was never actually deployed -- the gate would then wave
# through exactly the change it exists to catch.
if (-not $WhatIfPreference -and $rolled.Count -gt 0 -and $script:PimShippedBaseline -and $script:PimShippedBaseline.count -gt 0) {
    foreach ($app in $rolled) { Set-PimRecordedBaseline -Kind 'app' -Name $app -Hash $script:PimShippedBaseline.hash }
    Write-Host "  Recorded policy baseline $($script:PimShippedBaseline.hash) on $($rolled.Count) app(s)." -ForegroundColor DarkGray
}

# GATE: a deploy is not "done" until the hosted Manager GUI smoke passes. This FAILS the
# script (non-zero exit) if the live GUI is broken, so a broken deploy can't be reported
# as success. Roll back with -Rollback <oldRevision> if it fails.
$smokeVerdict = Invoke-ManagerSmokeGate -RepoRoot $repoRoot -RolledApps @($rolled)

# BUG-57: print WHAT HAPPENED, never a fixed string. This line used to assert the gate passed even
# on the four paths where it never ran.
Step ("Done. {0} app(s) verified on {1}; other job(s) verified on it: {2}; post-deploy GUI smoke gate: {3} (rollback with -Rollback <oldRevision>)." -f `
      $rolled.Count, $ImageTag, $(if ($otherJobsRolled.Count) { $otherJobsRolled -join ', ' } else { 'none' }), $smokeVerdict)
