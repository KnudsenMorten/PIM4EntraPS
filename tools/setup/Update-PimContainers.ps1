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
    [string[]]$Apps        = @('ca-pim-manager','ca-pim-scheduler','ca-pim-engine','ca-pim-connector','ca-pim-deltaqueue','ca-pim-discovery'),
    [switch]$SkipBuild,
    [string]$Rollback,     # revision NAME to reactivate (rollback mode; ignores ImageTag/build)
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

    # --- BUG-55: a roll that changes DESIRED STATE must be an explicit act --------------------
    # The image is built from `git archive HEAD`, so it carries every desired-state change sitting
    # in HEAD -- not just the fix you meant to ship. One such roll rewrote 217 of 325 production
    # group policies overnight and nothing alerted. The gate below refuses to roll when the shipped
    # policy baseline differs from the one recorded on the target; this switch is how you say "yes,
    # that baseline change is the point of this deploy".
    [switch]$AcceptBaselineChange
)
$ErrorActionPreference = 'Stop'
# BUG-25: -ImageTag is mandatory for a ROLL and meaningless for a ROLLBACK. Enforcing that
# here (rather than on the parameter) keeps the roll path exactly as strict as it was while
# letting the rollback path actually run. Fail loudly, not by prompting: an unattended
# deploy has no console to answer with.
if (-not $Rollback -and -not "$ImageTag".Trim()) {
    throw "Update-PimContainers: -ImageTag is required unless you are rolling back. Pass -ImageTag <tag> to roll, or -Rollback <revision> to reactivate a prior revision."
}
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)        # ...\PIM4EntraPS
$repoRoot = (Resolve-Path (Join-Path $here '..\..\..\..')).Path   # AutomateIT repo root
# BUG-40: the TAG reference is provenance for humans. What is actually rolled is $image, which
# is re-pointed at the immutable digest by the pre-roll guard below once az can resolve it.
$imageTagRef = "$AcrName.azurecr.io/$ImageRepo`:$ImageTag"
$image = $imageTagRef
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }

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
    $raw = if ($Kind -eq 'job') { az containerapp job show -g $ResourceGroup -n $Name -o json 2>$null }
           else                 { az containerapp show     -g $ResourceGroup -n $Name -o json 2>$null }
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
        $rid = if ($Kind -eq 'job') { az containerapp job show -g $ResourceGroup -n $Name --query id -o tsv 2>$null }
               else                 { az containerapp show     -g $ResourceGroup -n $Name --query id -o tsv 2>$null }
        if (-not "$rid".Trim()) { Write-Warning "  could not resolve the resource id of $Kind '$Name' -- policy baseline NOT recorded."; return }
        az tag update --resource-id "$("$rid".Trim())" --operation Merge --tags "$($script:PimBaselineTagName)=$Hash" -o none 2>$null
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

# Dot-sourced by the offline test -> stop before doing anything live.
if ($MyInvocation.InvocationName -eq '.') { return }

. "$here\_PimSetupShared.ps1"
Show-PimSetupBanner -ScriptName 'Update-PimContainers' -SolutionRoot $solRoot

# Post-deploy GUI smoke gate. After ca-pim-manager rolls to the new image we run the live
# hosted smoke (tests/live/Test-PimManagerHostedSmoke.ps1) and FAIL the deploy if the GUI
# is broken — exactly the symptoms that shipped "green" before: render mode 'static
# (read-only)' instead of SQL, GET /api/active-assignments 500, empty tenant cache,
# "Templates need server mode", read-only GUI. A deploy is NOT "done" until this passes.
# The smoke self-skips cleanly (exit 0) when az is unavailable / not logged in.
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
    # Write-Host, not a Note helper: this script defines only Step(), and calling an undefined
    # helper is parse-clean and throws at RUNTIME -- inside the gate, on every deploy.
    Write-Host ("    gate inputs: rg=$ResourceGroup workspace=$(if ("$SmokeWorkspaceId".Trim()) {'set'} else {'(from env/default)'}) " +
                "easyAuthAud=$(if ("$SmokeEasyAuthAud".Trim()) {'set'} else {'(NOT set -- the live-HTTP layer will fail the gate)'}) " +
                "fqdn=$(if ("$SmokeFqdn".Trim()) {'set'} else {'(derived from az)'})") -ForegroundColor DarkGray
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
Step ("apps requested: " + ($Apps -join ', '))
$existing = @($Apps | Where-Object { az containerapp show -g $ResourceGroup -n $_ --query name -o tsv 2>$null })

$plan = Get-PimAppRollPlan -Requested $Apps -Existing $existing -AllowMissing:$AllowMissingApps
if ($plan.missing.Count -gt 0) {
    Write-Host ("  NOT FOUND in {0}: {1}" -f $ResourceGroup, ($plan.missing -join ', ')) -ForegroundColor Red
}
if (-not $plan.ok) { throw "Update-PimContainers: $($plan.reason)" }
$existing = @($plan.roll)
Step ("apps present: " + ($existing -join ', '))

if ($Rollback) {
    # BUG-09 applies here too: track what was ACTUALLY rolled back. An app with no
    # matching revision was previously skipped in silence and still counted toward
    # "Rollback done." -- and during an incident, a rollback you believe happened but
    # didn't is worse than a failed one.
    $rolledBack = New-Object System.Collections.Generic.List[string]
    $noRevision = New-Object System.Collections.Generic.List[string]
    foreach ($app in $existing) {
        $rev = az containerapp revision list -g $ResourceGroup -n $app --query "[?contains(name,'$Rollback')].name | [0]" -o tsv 2>$null
        if (-not $rev) { [void]$noRevision.Add($app); continue }
        if ($PSCmdlet.ShouldProcess($app,"rollback to $rev")) {
            az containerapp revision activate -g $ResourceGroup -n $app --revision $rev -o none
            if ($LASTEXITCODE -ne 0) { throw "Update-PimContainers: revision activate FAILED (exit $LASTEXITCODE) for $app -> $rev." }
            az containerapp ingress traffic set -g $ResourceGroup -n $app --revision-weight "$rev=100" -o none 2>$null
            Write-Host "  $app -> $rev (100%)" -ForegroundColor Green
            [void]$rolledBack.Add($app)
        }
    }
    if ($noRevision.Count -gt 0) {
        Write-Host ("  NO revision matching '{0}': {1}" -f $Rollback, ($noRevision -join ', ')) -ForegroundColor Red
    }
    if ($rolledBack.Count -eq 0 -and -not $WhatIfPreference) {
        throw "Update-PimContainers: rollback matched NO revision named like '$Rollback' on any app -- nothing was rolled back. Refusing to report success. List revisions with: az containerapp revision list -n <app> -g $ResourceGroup"
    }
    Step ("Rollback done for {0} app(s): {1}" -f $rolledBack.Count, ($rolledBack -join ', '))
    # BUG-48, the inverse skew -- and it lands during an incident, which is when it is least
    # affordable. A Container Apps JOB has no revisions, so reactivating an app revision cannot
    # include it: the apps go back and the tick Job keeps running the build being rolled back.
    # We cannot fix it here (the previous digest is not knowable from a revision name), so it is
    # stated rather than left for someone to discover from behaviour.
    if (-not $SkipTickJob -and "$TickJobName".Trim()) {
        $jn = "$TickJobName".Trim()
        $jobImg = az containerapp job show -g $ResourceGroup -n $jn --query "properties.template.containers[0].image" -o tsv 2>$null
        if ("$jobImg".Trim()) {
            Write-Warning ("  [BUG-48] Rollback reactivated app REVISIONS only. The tick Job '$jn' has no revisions and was NOT rolled back -- " +
                           "it is still on $("$jobImg".Trim()). The engine and the GUI are now on DIFFERENT builds. Put it back explicitly: " +
                           "az containerapp job update -g $ResourceGroup -n $jn --image <previous digest reference>")
        }
    }
    # A rollback is only "good" if the rolled-back Manager actually serves a healthy GUI.
    # BUG-57: capture the verdict (it is a RETURN VALUE now) and state it. Left uncaptured it
    # would also leak the string into this script's output.
    $rbVerdict = Invoke-ManagerSmokeGate -RepoRoot $repoRoot -RolledApps @($rolledBack.ToArray())
    Step ("Rollback complete; post-deploy GUI smoke gate: {0}" -f $rbVerdict)
    return
}

if (-not $SkipBuild) {
    Step "Build $image via Build-PimManagerImage (clean git-archive context)"
    if ($PSCmdlet.ShouldProcess($image,'Build-PimManagerImage')) {
        # Use the dedicated builder, NOT a raw `az acr build . ` of the repo root: the
        # raw context includes .claude/worktrees and blows MAX_PATH on the hosted build,
        # so the build FAILED while a missing $LASTEXITCODE check let the roll proceed to
        # a tag that was never pushed -> ImagePullFailure / ActivationFailed (bit 2.4.227
        # + 2.4.228, 2026-06-18). Build-PimManagerImage builds from a clean `git archive`
        # subtree and throws on failure.
        & (Join-Path $PSScriptRoot 'Build-PimManagerImage.ps1') -ImageTag $ImageTag -AcrName $AcrName -ImageRepo $ImageRepo
        if ($LASTEXITCODE -ne 0) { throw "Update-PimContainers: image build FAILED (exit $LASTEXITCODE) for $image -- NOT rolling (a roll to an unbuilt tag creates an ImagePullFailure revision). Fix the build and re-run." }
    }
}

# Pre-roll guard (belt-and-suspenders, runs even with -SkipBuild): NEVER roll to a tag
# that isn't actually in the registry. A failed/skipped build previously rolled to a
# missing tag -> the new revision ImagePullFailures + sits ActivationFailed while the old
# revision keeps serving, so the "deploy" silently does nothing. Fail loudly instead.
if (-not $WhatIfPreference) {
    $existingTags = @(az acr repository show-tags -n $AcrName --repository $ImageRepo -o tsv 2>$null)
    if ($existingTags -notcontains $ImageTag) {
        throw "Update-PimContainers: image tag '$ImageTag' is NOT present in ACR '$AcrName/$ImageRepo' (tags: $($existingTags -join ', ')) -- refusing to roll (would ImagePullFailure). Build it first (omit -SkipBuild) or pick an existing tag."
    }
    Write-Host "  Verified $ImageRepo`:$ImageTag exists in ACR before rolling." -ForegroundColor Green

    # BUG-40: roll the DIGEST, not the tag. Rebuilding a tag moves the pointer but leaves the
    # app's image field identical, so ARM creates no revision and the platform keeps serving the
    # image it already pulled -- measured live 2026-08-09, where the roll reported success and
    # the next executions ran the previous build. Pinning makes new content a changed field.
    $imageDigest = Resolve-PimAcrImageDigest -AcrName $AcrName -Repository $ImageRepo -Tag $ImageTag
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
        Write-Warning ("  [BUG-55] $($verdict.reason). Rolling anyway and RECORDING the current fingerprint, so the " +
                       "next roll can answer this. If you did not intend to change desired state, WhatIf the policy " +
                       "scopes now: Invoke-PimEngineCore.ps1 -Scope GroupsPolicies -Mode Full -WhatIf (expect update=0).")
    }
    elseif ($verdict.changed -and -not $verdict.allowed -and $WhatIfPreference) {
        Write-Warning ("  [BUG-55] WHAT-IF: this roll WOULD BE REFUSED -- $($verdict.reason). " +
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
        Write-Warning "  [BUG-55] $($verdict.reason) -- proceeding because -AcceptBaselineChange was given. This deploy WILL change desired state."
    }
    else {
        Write-Host "  $($verdict.reason)" -ForegroundColor Green
    }
}

$rolled = New-Object System.Collections.Generic.List[string]
foreach ($app in $existing) {
    Step "Roll $app -> $ImageTag"
    if ($PSCmdlet.ShouldProcess($app,"update --image $image")) {
        az containerapp update -g $ResourceGroup -n $app --image $image -o none
        # BUG-09: `az containerapp update` failing was never checked -- a failed roll
        # counted the same as a successful one.
        if ($LASTEXITCODE -ne 0) { throw "Update-PimContainers: 'az containerapp update' FAILED (exit $LASTEXITCODE) for $app -- deploy aborted. Roll back with -Rollback <oldRevision> if a partial roll is a problem." }
        $rev = az containerapp revision list -g $ResourceGroup -n $app --query "[0].name" -o tsv 2>$null
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
        $live = az containerapp show -g $ResourceGroup -n $app --query "properties.template.containers[0].image" -o tsv 2>$null
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
        $jobExists = az containerapp job show -g $ResourceGroup -n $jobName --query name -o tsv 2>$null
        if (-not "$jobExists".Trim()) {
            Write-Host "  tick Job '$jobName' does not exist in $ResourceGroup -- nothing to roll (expected in always-on mode)." -ForegroundColor DarkGray
        }
        elseif ($PSCmdlet.ShouldProcess($jobName, "job update --image $image")) {
            Step "Roll tick Job $jobName -> $ImageTag"
            $jobBefore = az containerapp job show -g $ResourceGroup -n $jobName --query "properties.template.containers[0].image" -o tsv 2>$null
            az containerapp job update -g $ResourceGroup -n $jobName --image $image -o none
            if ($LASTEXITCODE -ne 0) {
                throw "Update-PimContainers: 'az containerapp job update' FAILED (exit $LASTEXITCODE) for $jobName -- the APPS are already on $ImageTag, so the deploy is now SKEWED (that is BUG-48's exact failure). Re-run this script, or stamp the Job by hand: az containerapp job update -g $ResourceGroup -n $jobName --image $image"
            }
            # Same evidence standard as the apps: a tag match is not proof (BUG-40).
            $jobLive = az containerapp job show -g $ResourceGroup -n $jobName --query "properties.template.containers[0].image" -o tsv 2>$null
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
Step ("Done. {0} app(s) verified on {1}; post-deploy GUI smoke gate: {2} (rollback with -Rollback <oldRevision>)." -f `
      $rolled.Count, $ImageTag, $smokeVerdict)
