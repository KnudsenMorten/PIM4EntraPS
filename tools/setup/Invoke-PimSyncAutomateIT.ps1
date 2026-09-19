#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS -- sync-automateit: controlled container auto-update with safe roll +
    post-update health check + auto-rollback. (REQUIREMENTS sec.1/sec.2/sec.6)

.DESCRIPTION
    The container-side of the "sync-automateit" mechanism. One controlled path that:

      1. Resolves the version THIS ENVIRONMENT'S RING APPROVES -- the ringN entry of channel.json,
         read through the environment's own updater (PIM_UPDATE_RING + PIM_UPDATE_SOURCE_URL) --
         or honours an explicit -PinnedTag (a deliberate target, still ring-gated by the roller).
         🔴 BUG-172: this used to take the NEWEST semver tag in the ACR, i.e. whatever had been
         built, and relied on the roller's ring gate to stop it. A version nobody approved was the
         candidate by default. An environment with no ring, an unreadable updater or a channel that
         approves nothing gets NO candidate: nothing moves, and the run says why (non-zero).
      2. Resolves the tag CURRENTLY deployed on the manager Container App.
      3. Decides via the pure core (PIM-SyncAutomateIT.ps1) whether an update is needed --
         ONLY when a strictly-newer valid version exists (never re-roll the same tag, never
         take an unparseable tag, never move backward).
      4. Gating: by default this is DRY-RUN (decide + report only). Pass -Apply (or run it
         from the scheduled task inside the maintenance window) to act.
      5. Captures the manager's pre-update revision, then rolls every app to the new tag via
         the existing zero-downtime roller (Update-PimContainers.ps1 -SkipBuild) -- ACA
         creates a new revision and shifts traffic with min-1 replica. The roller re-checks the
         ring gate before it touches anything.
      6. Runs the post-update HEALTH CHECK by reusing the hosted smoke
         (tests/live/Test-PimManagerHostedSmoke.ps1) as a RELEASE GATE, with the app, resource
         group, subscription and the version just rolled. Anything but a clean pass -- a failure
         OR a skipped check (a skip is not a pass) -- AUTO-ROLLS-BACK to the captured pre-update
         revision (Update-PimContainers.ps1 -Rollback).

    REST/cert + MI only via az (the apps pull through their AcrPull MI; no registry creds at
    update time). Every az call names -SubscriptionId when it is given. PS 5.1-safe. The region
    is whatever the existing deployment uses; nothing here chooses one.

.PARAMETER PinnedTag
    Update to THIS exact tag (still only if it is newer than the deployed one, and still subject to
    the roller's ring gate). When omitted, the version the environment's ring approves is the
    candidate.

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
    Roll to the version this environment's ring approves if it is newer, then health-check +
    auto-rollback on anything but a clean pass.

.EXAMPLE
    .\Invoke-PimSyncAutomateIT.ps1 -PinnedTag 1.1.9 -Apply
    Controlled, explicit roll to 1.1.9 (only if newer than the deployed tag).

.NOTES
    Re-runnable + idempotent: a no-op when already on the newest tag. Decides via the pure,
    unit-tested core in engine/_shared/PIM-SyncAutomateIT.ps1 (tests/Test-PimSyncAutomateIT.ps1).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ResourceGroup   = "$($env:PIM_ResourceGroup)",
    [string]$AcrName         = "$($env:PIM_AcrName)",
    [string]$ImageRepo       = 'pim-manager',
    [string]$ManagerApp      = 'ca-pim-manager',
    [string[]]$Apps          = # empty = DISCOVER (Update-PimContainers.ps1 enumerates the resource group).
    # The hard-coded six-app list was wrong for every real topology -- only ca-pim-manager
    # exists -- and it was copy-pasted into FOUR entry points, so fixing one changed nothing.
    @(),
    [string]$PinnedTag,
    # BUG-48: this is the CUSTOMER auto-update path, so the tick Job has to be re-stamped here
    # too -- otherwise a customer's GUI advances and their reconciling engine stays on the old
    # build indefinitely. Inert where it does not apply: the roller SKIPS a Job that does not
    # exist, which is the normal always-on shape.
    [string]$TickJobName     = 'ca-pim-tick',
    # Scopes every az call to this subscription. Optional (unchanged behaviour when blank), and
    # defaults to the deploy's own env var like _PimSetupShared.ps1 does.
    [string]$SubscriptionId  = $(if ($env:PIM_SUBSCRIPTION_ID) { $env:PIM_SUBSCRIPTION_ID } else { '' }),
    [switch]$Apply,
    [switch]$SkipHealthCheck,
    # 2026-09-13 -- the roller refuses to move an environment on ring >= 2 to a version its ring does not
    # approve. The override is audited and needs a reason; it is forwarded to the roller unchanged.
    [switch]$OverrideRingGate,
    [string]$Reason,
    [string]$UpdateJobName   = 'ca-pim-update'
)
$subArgs = @(); if ("$SubscriptionId".Trim()) { $subArgs = @('--subscription', "$SubscriptionId".Trim()) }
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
# Guarded `az` shadow -- see _PimAz.ps1. az writes ordinary WARNINGS to stderr and PowerShell 5.1
# makes any such write terminating under $ErrorActionPreference='Stop'. Must precede the first az call.
. "$here\_PimAz.ps1"
$solRoot = Split-Path -Parent (Split-Path -Parent $here)        # SOLUTIONS/PIM4EntraPS
. (Join-Path $solRoot 'engine\_shared\PIM-SyncAutomateIT.ps1')
. "$here\_PimUpdateRing.ps1"    # the environment's ring + what channel.json approves for it (BUG-172)
# Every roller call gets the subscription too, so the roll, its gate and its rollback read the SAME one.
$rollSub = @{}; if ("$SubscriptionId".Trim()) { $rollSub['SubscriptionId'] = "$SubscriptionId".Trim() }

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
try { $acct = az account show @subArgs -o json 2>$null | ConvertFrom-Json } catch {}
if (-not $acct) { Warn 'az not logged in (az login) -- nothing done.'; return }
Info ("az context: {0} / sub {1}{2}" -f $acct.user.name, $acct.id, $(if ($subArgs.Count) { ' (explicit)' } else { ' (AMBIENT default -- pass -SubscriptionId)' }))

# ---- 1. the version this environment's RING approves ----------------------
# 🔴 BUG-172: NOT the newest tag in the registry. What was BUILT is not what was APPROVED; the ring
# entry in channel.json is the approval (ring 2 moves only when the operator edits it). Read through
# the environment's OWN updater, exactly as its in-cloud job reads it. No ring / unreadable / nothing
# approved => NO candidate: fail closed and say why, never fall back to "newest".
Step "Resolve the version this environment's ring approves ($UpdateJobName in $ResourceGroup)"
$latestTag = ''
$ringNote = ''
$upd = Get-PimEnvironmentUpdaterEnv -ResourceGroup $ResourceGroup -SubscriptionArgs $subArgs -UpdateJobName $UpdateJobName
$ringRaw = if ($upd.ok -and $upd.found -and $upd.env.Contains('PIM_UPDATE_RING')) { "$($upd.env['PIM_UPDATE_RING'])".Trim() } else { '' }
$ringNum = ConvertTo-PimUpdateRingNumber $ringRaw
if (-not $upd.ok) {
    $ringNote = "could not read '$UpdateJobName' ($($upd.reason)) -- the ring cannot be checked"
} elseif (-not $ringRaw) {
    $ringNote = $(if ($upd.found) { "'$UpdateJobName' carries no PIM_UPDATE_RING" } else { "no '$UpdateJobName' in $ResourceGroup" }) + ' -- no ring approves any version for this environment'
} elseif ($null -eq $ringNum) {
    $ringNote = "PIM_UPDATE_RING='$ringRaw' is not a ring"
} else {
    $srcTpl = if ($upd.env.Contains('PIM_UPDATE_SOURCE_URL')) { "$($upd.env['PIM_UPDATE_SOURCE_URL'])".Trim() } else { '' }
    $rep = Get-PimUpdateRingChannelReport -SourceUrlTemplate $srcTpl -Ring $ringNum -CurrentVersion ''
    if ($rep.ok -and "$($rep.approved)".Trim()) { $latestTag = "$($rep.approved)".Trim(); Info "ring $ringNum approves $latestTag" }
    else { $ringNote = "ring $ringNum`: $($rep.message)" }
}
if ("$PinnedTag".Trim()) {
    Info "pinned target requested: $PinnedTag (the roller's ring gate still decides whether it may be rolled)"
} elseif (-not $latestTag) {
    Warn "NO approved version: $ringNote."
    Warn 'Nothing is rolled. Give the environment a ring (Deploy-PimUpdateJob.ps1 -UpdateRing <n>) or fix channel.json;'
    Warn 'a deliberate one-off roll is -PinnedTag <version> -OverrideRingGate -Reason ''<why>'' (audited).'
    throw "sync-automateit: no version is approved for this environment ($ringNote) -- nothing rolled."
}

# ---- 2. currently-deployed tag on the manager app -------------------------
Step "Resolve currently-deployed tag on $ManagerApp"
$currentTag = ''
try {
    $img = az containerapp show @subArgs -g $ResourceGroup -n $ManagerApp --query "properties.template.containers[0].image" -o tsv 2>$null
    if ("$img".Trim()) { $currentTag = ("$img" -split ':')[-1] }
} catch {}
if (-not "$currentTag".Trim()) { Warn "could not read the deployed image tag for $ManagerApp (is it deployed in $ResourceGroup?). Nothing done."; return }
# 🔴 FORWARD-ONLY NEEDS A READABLE CURRENT VERSION. Every roll pins the image BY DIGEST (BUG-40), so the
# "tag" split off `repo@sha256:<hex>` is the hex -- not a version. The pure core sorts an unparseable
# current version LOWEST, so the ring's version always looked newer: an environment AHEAD of its ring
# would have been rolled BACKWARD to it. Resolve the digest to its tag in the registry; if that cannot
# be done, refuse -- "cannot prove this is forward" is a reason not to move, never a reason to.
if (-not (ConvertTo-PimSemVer -Tag $currentTag).valid) {
    $resolved = ''
    if ("$img" -match '^(?<reg>[^/]+)/(?<repo>[^@:]+)@(?<dig>sha256:[0-9a-f]+)') {
        $acrFromImg = ($Matches['reg'] -split '\.')[0]
        $dig = $Matches['dig']; $repoName = $Matches['repo']
        $acrForLookup = if ("$AcrName".Trim()) { "$AcrName".Trim() } else { $acrFromImg }
        try {
            $global:LASTEXITCODE = 0
            $tagsRaw = @(az acr manifest list-metadata @subArgs --registry $acrForLookup --name $repoName --query "[?digest=='$dig'].tags[]" -o tsv 2>$null)
            if ($LASTEXITCODE -eq 0) {
                foreach ($tg in @($tagsRaw | ForEach-Object { "$_".Trim() } | Where-Object { $_ })) {
                    $sv = ConvertTo-PimSemVer -Tag $tg
                    if ($sv.valid -and (-not $resolved -or (Compare-PimSemVer -A $sv -B (ConvertTo-PimSemVer -Tag $resolved)) -gt 0)) { $resolved = $tg }
                }
            }
        } catch { $resolved = '' }
    }
    if (-not $resolved) {
        throw "sync-automateit: $ManagerApp runs '$img', whose version cannot be read (digest with no resolvable version tag) -- REFUSING to move it: a roll that cannot prove it is forward does not happen."
    }
    Info "deployed image is pinned by digest; its version tag in the registry: $resolved"
    $currentTag = $resolved
}
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
try { $prevRev = @(az containerapp revision list @subArgs -g $ResourceGroup -n $ManagerApp --query "[?properties.active].name" -o tsv 2>$null) | Select-Object -First 1 } catch {}
if (-not "$prevRev".Trim()) { try { $prevRev = az containerapp revision list @subArgs -g $ResourceGroup -n $ManagerApp --query "[0].name" -o tsv 2>$null } catch {} }
Info ("pre-update revision: " + $(if ($prevRev) { $prevRev } else { '(unknown -- auto-rollback will be unavailable)' }))
# 🔴 §53.6 -- the revision name is not a durable anchor: Container Apps prunes inactive revisions,
# so the target captured here can be gone by the time the health check fails. This path runs
# unattended against customer environments, which is precisely where "ROLL BACK BY HAND" is the
# least useful sentence available. The IMAGE survives in ACR; roll to it when the revision is gone.
$prevImage = ''
try { $prevImage = "$(az containerapp show @subArgs -g $ResourceGroup -n $ManagerApp --query 'properties.template.containers[0].image' -o tsv 2>$null)".Trim() } catch { Write-Verbose "pre-update image read failed: $($_.Exception.Message)" }
Info ("pre-update image: " + $(if ($prevImage) { $prevImage } else { '(unknown)' }))

# ---- 5. roll to the new tag via the existing zero-downtime roller ----------
$roller = Join-Path $here 'Update-PimContainers.ps1'
Step "Roll all apps -> $targetTag (zero-downtime, via Update-PimContainers.ps1 -SkipBuild)"
if ($PSCmdlet.ShouldProcess("$($Apps -join ', ')", "update -> $targetTag")) {
    $ringGateArgs = @{}
    if ($OverrideRingGate) { $ringGateArgs = @{ OverrideRingGate = $true; Reason = $Reason } }
    & $roller -ImageTag $targetTag -SkipBuild -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps -TickJobName $TickJobName @ringGateArgs @rollSub
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
$state = 'unverified'
if (Test-Path $smoke) {
    # 🔴 BUG-172 -- THIS CALL PASSED NOTHING, AND A SKIP READ AS HEALTHY. With no app, resource group or
    # subscription the smoke could not find the app, skipped every check and exited 0, and exit 0 was
    # "healthy / cleanly-skipped" -- so an unattended customer roll KEPT a revision nothing had checked.
    # Now: the smoke gets what this script knows, runs as a RELEASE GATE (a check that cannot run is a
    # failure), expects the version just rolled, and exit 2 ("skipped") is UNVERIFIED -- never healthy.
    $smokeArgs = @('-App', $ManagerApp, '-ResourceGroup', $ResourceGroup, '-AsReleaseGate')
    if ("$SubscriptionId".Trim()) { $smokeArgs += @('-SubscriptionId', "$SubscriptionId".Trim()) }
    if ("$targetTag".Trim() -match '^\d+\.\d+\.\d+') { $smokeArgs += @('-ExpectedVersion', "$targetTag".Trim()) }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $smoke @smokeArgs
    $code = $LASTEXITCODE
    $state = Get-PimSyncHealthState -ExitCode $code -FailCount 0
    $healthy = ($state -eq 'healthy')
    Info "hosted smoke exit code: $code ($state)"
} else {
    Warn "hosted smoke not found at $smoke -- treating as UNVERIFIED (will roll back to be safe)."
    $healthy = $false
}

# An UNVERIFIED revision is not kept as healthy: it is rolled back exactly like a failed one.
$rb = Get-PimSyncRollbackPlan -Healthy $healthy -PreviousRevision $prevRev -Unverified:($state -eq 'unverified')
if ($rb.action -eq 'rollback') {
    Warn $rb.reason
    Step "AUTO-ROLLBACK -> $($rb.revision)"
    if ($PSCmdlet.ShouldProcess($ManagerApp, "rollback to $($rb.revision)")) {
        # §53.6: the image anchor rides along; the roller uses it only if the revision is gone.
        $rbArgs = @{}; if ("$prevImage".Trim()) { $rbArgs['RollbackImage'] = "$prevImage".Trim() }
        & $roller -Rollback $rb.revision -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps @rbArgs @rollSub
    }
    throw "sync-automateit: post-update health check $(if ($state -eq 'unverified') { 'did NOT run in full (a skip is not a pass)' } else { 'FAILED' }) -- rolled back to $($rb.revision)."
} elseif ($rb.action -eq 'none' -and -not $healthy) {
    # §53.6: no revision name -- but the pre-update IMAGE is a rollback target in its own right,
    # and this is an unattended customer run. Try it before declaring a manual rollback.
    if ("$prevImage".Trim()) {
        Warn "no pre-update revision was captured, but the pre-update IMAGE was -- rolling back to it."
        Step "AUTO-ROLLBACK (image) -> $prevImage"
        if ($PSCmdlet.ShouldProcess($ManagerApp, "rollback to image $prevImage")) {
            & $roller -RollbackImage "$prevImage".Trim() -ResourceGroup $ResourceGroup -AcrName $AcrName -ImageRepo $ImageRepo -Apps $Apps @rollSub
        }
        throw "sync-automateit: post-update health check FAILED -- rolled back to the pre-update image $prevImage."
    }
    throw "sync-automateit: post-update health check FAILED and NEITHER a rollback revision nor a pre-update image was captured -- MANUAL rollback required (az containerapp revision list -n $ManagerApp -g $ResourceGroup$(if ($subArgs.Count) { ' ' + ($subArgs -join ' ') }))."
}

Step "Done. Rolled to $targetTag and health check PASSED (kept the new revision)."
