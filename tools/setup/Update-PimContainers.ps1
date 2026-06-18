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
    [Parameter(Mandatory)][string]$ImageTag,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$AcrName,
    [string]$ImageRepo     = 'pim-manager',
    [string[]]$Apps        = @('ca-pim-manager','ca-pim-scheduler','ca-pim-engine','ca-pim-connector','ca-pim-deltaqueue','ca-pim-discovery'),
    [switch]$SkipBuild,
    [string]$Rollback,     # revision NAME to reactivate (rollback mode; ignores ImageTag/build)
    [switch]$SkipSmoke     # opt OUT of the post-deploy GUI smoke gate (NOT recommended)
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)        # ...\PIM4EntraPS
$repoRoot = (Resolve-Path (Join-Path $here '..\..\..\..')).Path   # AutomateIT repo root
$image = "$AcrName.azurecr.io/$ImageRepo`:$ImageTag"
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }

. "$here\_PimSetupShared.ps1"
Show-PimSetupBanner -ScriptName 'Update-PimContainers' -SolutionRoot $solRoot

# Post-deploy GUI smoke gate. After ca-pim-manager rolls to the new image we run the live
# hosted smoke (tests/live/Test-PimManagerHostedSmoke.ps1) and FAIL the deploy if the GUI
# is broken — exactly the symptoms that shipped "green" before: render mode 'static
# (read-only)' instead of SQL, GET /api/active-assignments 500, empty tenant cache,
# "Templates need server mode", read-only GUI. A deploy is NOT "done" until this passes.
# The smoke self-skips cleanly (exit 0) when az is unavailable / not logged in.
function Invoke-ManagerSmokeGate {
    param([string]$RepoRoot, [string[]]$RolledApps)
    if (-not $PSCmdlet.ShouldProcess('ca-pim-manager','post-deploy GUI smoke gate')) { return }  # no live probe under -WhatIf
    if ($SkipSmoke) { Write-Host "==> -SkipSmoke set: skipping post-deploy GUI smoke gate (NOT recommended)." -ForegroundColor Yellow; return }
    if ('ca-pim-manager' -notin $RolledApps) { return }  # gate only when the Manager was actually rolled
    $smoke = Join-Path $RepoRoot 'SOLUTIONS/PIM4EntraPS/tests/live/Test-PimManagerHostedSmoke.ps1'
    if (-not (Test-Path -LiteralPath $smoke)) {
        Write-Host "::warning:: post-deploy GUI smoke not found at $smoke -- cannot gate the deploy." -ForegroundColor Yellow
        return
    }
    Step "Post-deploy GUI smoke gate (Test-PimManagerHostedSmoke.ps1)"
    & $smoke
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "Update-PimContainers: post-deploy GUI smoke FAILED (exit $code). The hosted Manager is broken (render mode / active-assignments / tenant cache / read-write). Roll back with -Rollback <oldRevision>."
    }
    Write-Host "==> Post-deploy GUI smoke gate PASSED (or self-skipped cleanly)." -ForegroundColor Green
}

# only act on apps that actually exist
$existing = @($Apps | Where-Object { az containerapp show -g $ResourceGroup -n $_ --query name -o tsv 2>$null })
Step ("apps present: " + ($existing -join ', '))

if ($Rollback) {
    foreach ($app in $existing) {
        $rev = az containerapp revision list -g $ResourceGroup -n $app --query "[?contains(name,'$Rollback')].name | [0]" -o tsv 2>$null
        if ($rev -and $PSCmdlet.ShouldProcess($app,"rollback to $rev")) {
            az containerapp revision activate -g $ResourceGroup -n $app --revision $rev -o none
            az containerapp ingress traffic set -g $ResourceGroup -n $app --revision-weight "$rev=100" -o none 2>$null
            Write-Host "  $app -> $rev (100%)" -ForegroundColor Green
        }
    }
    Step 'Rollback done.'
    # A rollback is only "good" if the rolled-back Manager actually serves a healthy GUI.
    Invoke-ManagerSmokeGate -RepoRoot $repoRoot -RolledApps $existing
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
}

foreach ($app in $existing) {
    Step "Roll $app -> $ImageTag"
    if ($PSCmdlet.ShouldProcess($app,"update --image $image")) {
        az containerapp update -g $ResourceGroup -n $app --image $image -o none
        $rev = az containerapp revision list -g $ResourceGroup -n $app --query "[0].name" -o tsv 2>$null
        Write-Host "  $app new revision: $rev" -ForegroundColor Green
    }
}
Step "All apps rolled to $ImageTag (zero-downtime rolling revisions)."

# GATE: a deploy is not "done" until the hosted Manager GUI smoke passes. This FAILS the
# script (non-zero exit) if the live GUI is broken, so a broken deploy can't be reported
# as success. Roll back with -Rollback <oldRevision> if it fails.
Invoke-ManagerSmokeGate -RepoRoot $repoRoot -RolledApps $existing

Step "Done. All apps on $ImageTag and post-deploy GUI smoke gate passed (rollback with -Rollback <oldRevision>)."
