#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS -- sync-automateit: controlled container auto-update with safe roll +
    post-update health check + auto-rollback. (REQUIREMENTS sec.1/sec.2/sec.6)

.DESCRIPTION
    The container-side of the "sync-automateit" mechanism. One controlled path that:

      1. Resolves the LATEST released engine/manager image tag in ACR (semver-sorted),
         or honours an explicit -PinnedTag (a controlled, deliberate target).
      2. Resolves the tag CURRENTLY deployed on the manager Container App.
      3. Decides via the pure core (PIM-SyncAutomateIT.ps1) whether an update is needed --
         ONLY when a strictly-newer valid version exists (never re-roll the same tag, never
         take an unparseable tag).
      4. Gating: by default this is DRY-RUN (decide + report only). Pass -Apply (or run it
         from the scheduled task / in-container job inside the maintenance window) to act.
      5. Captures the manager's pre-update revision, then rolls every app to the new tag via
         the existing zero-downtime roller (Update-PimContainers.ps1 -SkipBuild) -- ACA
         creates a new revision and shifts traffic with min-1 replica.
      6. Runs the post-update HEALTH CHECK by reusing the hosted smoke
         (tests/live/Test-PimManagerHostedSmoke.ps1). On a real failure it AUTO-ROLLS-BACK
         to the captured pre-update revision (Update-PimContainers.ps1 -Rollback).

    REST/cert + MI only via az (the apps pull through their AcrPull MI; no registry creds at
    update time). ACA via Update-PimContainers (which uses --yaml for workers). PS 5.1-safe.
    Region: West Europe / Denmark East only (inherited from the existing deployment).

.PARAMETER PinnedTag
    Update to THIS exact tag (still only if it is newer than the deployed one). When omitted,
    the newest semver tag in the ACR repo is the candidate.

.PARAMETER Apply
    Actually roll. Without it (and without an open schedule gate) the script only decides and
    prints the plan -- the controlled/gated default.

.PARAMETER SkipHealthCheck
    Skip the post-update hosted smoke (NOT recommended; only for a registry that has no live
    hosted Manager to probe, e.g. a pure worker-only deployment).

.EXAMPLE
    .\Invoke-PimSyncAutomateIT.ps1
    Dry-run: report whether a newer released image exists and what it would do.

.EXAMPLE
    .\Invoke-PimSyncAutomateIT.ps1 -Apply
    Roll to the newest released image if newer, then health-check + auto-rollback on failure.

.EXAMPLE
    .\Invoke-PimSyncAutomateIT.ps1 -PinnedTag 1.1.9 -Apply
    Controlled, explicit roll to 1.1.9 (only if newer than the deployed tag).

.NOTES
    Re-runnable + idempotent: a no-op when already on the newest tag. Decides via the pure,
    unit-tested core in engine/_shared/PIM-SyncAutomateIT.ps1 (tests/Test-PimSyncAutomateIT.ps1).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ResourceGroup   = 'rg-pim-manager-web',
    [string]$AcrName         = 'acrsecurityinsight',
    [string]$ImageRepo       = 'pim-manager',
    [string]$ManagerApp      = 'ca-pim-manager',
    [string[]]$Apps          = @('ca-pim-manager','ca-pim-scheduler','ca-pim-engine','ca-pim-connector','ca-pim-deltaqueue','ca-pim-discovery'),
    [string]$PinnedTag,
    [switch]$Apply,
    [switch]$SkipHealthCheck
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)        # SOLUTIONS/PIM4EntraPS
. (Join-Path $solRoot 'engine\_shared\PIM-SyncAutomateIT.ps1')

function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Info($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }
function Have($cmd){ [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

Write-Host "=== PIM4EntraPS sync-automateit (controlled container auto-update) ===" -ForegroundColor Cyan

# ---- preconditions: az present + logged in --------------------------------
if (-not (Have 'az')) {
    Warn 'azure CLI (az) not found -- this orchestrator needs az to query/roll Container Apps. Nothing done.'
    return
}
$acct = $null
try { $acct = az account show -o json 2>$null | ConvertFrom-Json } catch {}
if (-not $acct) { Warn 'az not logged in (az login) -- nothing done.'; return }
Info ("az context: {0} / sub {1}" -f $acct.user.name, $acct.id)

# ---- 1. latest released tag in ACR (semver-sorted) ------------------------
Step "Resolve candidate image tag in ACR ($AcrName / $ImageRepo)"
$latestTag = ''
try {
    $tags = az acr repository show-tags -n $AcrName --repository $ImageRepo -o tsv 2>$null
    $tagList = @(($tags -split "`r?`n") | Where-Object { "$_".Trim() })
    if ($tagList.Count) {
        # pick the newest VALID semver tag via the PURE comparer (numeric, not string).
        $best = $null
        foreach ($t in $tagList) {
            $sv = ConvertTo-PimSemVer -Tag $t
            if (-not $sv.valid) { continue }
            if ($null -eq $best -or (Compare-PimSemVer -A $sv -B (ConvertTo-PimSemVer -Tag $best)) -gt 0) { $best = $t }
        }
        $latestTag = "$best"
    }
} catch { Warn "could not list ACR tags: $($_.Exception.Message)" }
if ("$PinnedTag".Trim()) { Info "pinned target requested: $PinnedTag" }
Info ("newest released tag: " + $(if ($latestTag) { $latestTag } else { '(none found)' }))

# ---- 2. currently-deployed tag on the manager app -------------------------
Step "Resolve currently-deployed tag on $ManagerApp"
$currentTag = ''
try {
    $img = az containerapp show -g $ResourceGroup -n $ManagerApp --query "properties.template.containers[0].image" -o tsv 2>$null
    if ("$img".Trim()) { $currentTag = ("$img" -split ':')[-1] }
} catch {}
if (-not "$currentTag".Trim()) { Warn "could not read the deployed image tag for $ManagerApp (is it deployed in $ResourceGroup?). Nothing done."; return }
Info "deployed tag: $currentTag"

# ---- 3. decide (pure core) ------------------------------------------------
# Gate is OPEN when -Apply is passed (or the caller is the scheduled task running in-window).
$decision = Get-PimSyncDecision -CurrentTag $currentTag -LatestTag $latestTag -PinnedTag $PinnedTag -RequireGate -GateOpen:$Apply
Step "Decision: $($decision.action) -- $($decision.reason)"

if ($decision.action -eq 'noop') { Info 'Nothing to do.'; return }
if ($decision.action -eq 'blocked') {
    Warn "A newer version ($($decision.targetTag)) is available but the gate is closed."
    Warn "Re-run with -Apply (or let the scheduled sync task run it in the maintenance window) to roll."
    return
}

# action == 'update'
$targetTag = $decision.targetTag

# ---- 4. capture pre-update revision (rollback target) ---------------------
Step "Capture $ManagerApp current revision (rollback target)"
$prevRev = ''
try { $prevRev = az containerapp revision list -g $ResourceGroup -n $ManagerApp --query "[?properties.active].name | [0]" -o tsv 2>$null } catch {}
if (-not "$prevRev".Trim()) { try { $prevRev = az containerapp revision list -g $ResourceGroup -n $ManagerApp --query "[0].name" -o tsv 2>$null } catch {} }
Info ("pre-update revision: " + $(if ($prevRev) { $prevRev } else { '(unknown -- auto-rollback will be unavailable)' }))

# ---- 5. roll to the new tag via the existing zero-downtime roller ----------
$roller = Join-Path $here 'Update-PimContainers.ps1'
Step "Roll all apps -> $targetTag (zero-downtime, via Update-PimContainers.ps1 -SkipBuild)"
if ($PSCmdlet.ShouldProcess("$($Apps -join ', ')", "update -> $targetTag")) {
    & $roller -ImageTag $targetTag -SkipBuild -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "Update-PimContainers.ps1 failed (exit $LASTEXITCODE)." }
}

# ---- 6. post-update health check (reuse the hosted smoke) + auto-rollback --
if ($SkipHealthCheck) {
    Warn 'post-update health check SKIPPED (-SkipHealthCheck). The new revision is live unverified.'
    Step "Done. Rolled to $targetTag (no health check)."
    return
}

Step "Post-update health check (reuse hosted smoke: Test-PimManagerHostedSmoke.ps1)"
$smoke = Join-Path $solRoot 'tests\live\Test-PimManagerHostedSmoke.ps1'
$healthy = $false
if (Test-Path $smoke) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $smoke
    $code = $LASTEXITCODE
    $healthy = Test-PimSyncHealthVerdict -ExitCode $code -FailCount 0
    Info "hosted smoke exit code: $code (healthy=$healthy)"
} else {
    Warn "hosted smoke not found at $smoke -- treating as UNVERIFIED (will roll back to be safe)."
    $healthy = $false
}

$rb = Get-PimSyncRollbackPlan -Healthy $healthy -PreviousRevision $prevRev
if ($rb.action -eq 'rollback') {
    Warn $rb.reason
    Step "AUTO-ROLLBACK -> $($rb.revision)"
    if ($PSCmdlet.ShouldProcess($ManagerApp, "rollback to $($rb.revision)")) {
        & $roller -Rollback $rb.revision -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps
    }
    throw "sync-automateit: post-update health check FAILED -- rolled back to $($rb.revision)."
} elseif ($rb.action -eq 'none' -and -not $healthy) {
    throw "sync-automateit: post-update health check FAILED and no rollback target was captured -- MANUAL rollback required (az containerapp revision list -n $ManagerApp -g $ResourceGroup)."
}

Step "Done. Rolled to $targetTag and health check PASSED (kept the new revision)."
