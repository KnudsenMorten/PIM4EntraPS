#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS -- BUILD a fresh Manager image FROM THE PULLED CODE (the gap the update-lifecycle
    fills). REQUIREMENTS.md sec.2 (Containers) + sec.1 (Hosting/Runtime).

.DESCRIPTION
    Update-PimContainers.ps1 -SkipBuild and the sync-automateit roll only ROLL a pre-built image;
    nothing builds the new image from a freshly-pulled tree. THIS does that build, two ways:

      * HOSTED  (-Source sync-automateit, default): `az acr build` of
        SOLUTIONS/PIM4EntraPS/tools/pim-manager/Dockerfile from the repo root into ACR, tagged
        <ImageRepo>:<ImageTag>. The Container Apps pull it via their AcrPull MI -- no registry
        creds at build/roll time. Region inherited from the ACR (West Europe / Denmark East only).

      * COMMUNITY (-Source git-pull): a LOCAL build/package + relaunch -- builds the image with the
        local container engine if one is present (docker/podman), else packages the pulled
        tools/pim-manager tree into output/manager-package/ for a direct local relaunch (no ACR).

    This script ONLY builds (and, for local, optionally relaunches). It does NOT detect, deploy to
    ACA, run the smoke, or notify -- the orchestrator (Invoke-PimUpdate.ps1) sequences those. It is
    safe to run standalone and is idempotent (re-tagging the same content is harmless).

    PS 5.1-safe, REST/cert + MI only (no PowerShell modules). Use -WhatIf to print the plan only.

.PARAMETER ImageTag
    The tag to build (the orchestrator derives it from the pulled VERSION). Required.

.PARAMETER Source
    'sync-automateit' (hosted ACR build, default) or 'git-pull' (community local build/package).

.PARAMETER AcrName
    ACR to build into (hosted). Required for -Source sync-automateit.

.EXAMPLE
    .\Build-PimManagerImage.ps1 -ImageTag 2.4.220 -AcrName <acr>
    Hosted: build pim-manager:2.4.220 in ACR from the pulled code.

.EXAMPLE
    .\Build-PimManagerImage.ps1 -ImageTag 2.4.220 -Source git-pull
    Community: local build (docker/podman) or package the pulled Manager for local relaunch.

.NOTES
    Re-runnable. The post-build content hash it prints is what Get-PimGuiUpdatePlan compares
    against the running image to decide future rolls.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ImageTag,
    [ValidateSet('git-pull','sync-automateit')][string]$Source = 'sync-automateit',
    # s31: resolve the build source from a deployment SCENARIO (S1..S6). When set it OVERRIDES
    # -Source: the scenario's resolved build path maps to acr-build (central/hosted => sync-automateit)
    # or local-build (local/community => git-pull). from-master central=>sync-automateit, local=>git-pull.
    [ValidateSet('S1','S2','S3','S4','S5','S6')][string]$Scenario,
    [string]$AcrName,
    # Run the build on a dedicated agent pool inside the VNet. Required when the registry has no
    # public network access -- see the note at the $acrSubArgs assignment below.
    [string]$AcrAgentPool,
    [string]$ImageRepo  = 'pim-manager',
    [string]$Dockerfile = 'SOLUTIONS/PIM4EntraPS/tools/pim-manager/Dockerfile',
    [switch]$Relaunch,            # community only: relaunch the local Manager after packaging
    [string]$RelaunchScript,      # community only: path to the local relaunch script

    # --- OPTIONAL explicit sign-in (hosted) -----------------------------------------------
    # By default this script uses whatever az context is already active, which is right when a
    # human runs it. An UNATTENDED estate run cannot rely on that: the orchestrator runs every
    # step in its OWN process, so there is no ambient context to inherit -- and worse, on a host
    # that manages several tenants the ambient context may belong to a DIFFERENT one, which is
    # the BUG-23 class (a credential path that succeeds while being wrong). Supply these and the
    # script signs in itself, into an ISOLATED az profile so the host's shared context is never
    # disturbed.
    [string]$TenantId,
    [string]$SubscriptionId,
    [string]$AdminAppId,
    # ONE of secret / cert. This was the THIRD place a client secret was structurally required
    # (after New-PimHostingPrerequisites and Grant-PimMiSql), all found on 2026-08-09 deploying
    # PIM §34. A cert-only tenant -- every real customer, per the repo-root rule -- could supply
    # neither, and the only reason this one was not a hard blocker is that it falls back to the
    # ambient az context.
    [string]$AdminSecret,
    [string]$AdminCertPem
)
$ErrorActionPreference = 'Stop'

# 🔴 SCOPE THE BUILD, DO NOT MUTATE THE MACHINE. -SubscriptionId was only ever applied inside the
# SPN-login path via `az account set`, so a caller that was already logged in (the normal case)
# passed a subscription that was silently ignored -- and `az acr build` then ran against the
# ambient default, which on mgmt1 is another company's. Measured: "the resource 'acrpimmfnpr'
# could not be found in subscription 'ELDK Event Hub'".
# 🔒 Scoped PER CALL rather than by `az account set`, because this machine runs ~3 sessions at once
# and flipping the shared default would break whichever of them is legitimately using the other
# tenant. A build must not have side effects on somebody else's shell.
$acrSubArgs = @()
if ("$SubscriptionId".Trim()) { $acrSubArgs = @('--subscription', "$SubscriptionId".Trim()) }
# 🔑 A PRIVATE REGISTRY CANNOT BE BUILT FROM OUTSIDE ITS VNET. ACR Tasks run in ACR's own
# infrastructure and reach the registry over its data plane, so with public access off `az acr
# build` fails from any host that is not on the network -- which would make the deploy depend on
# WHERE it was run from. A dedicated agent pool runs the task inside the VNet instead, so the same
# command reproduces from anywhere. Created by New-PimHostingPrerequisites -AcrAgentPoolName.
if ("$AcrAgentPool".Trim()) {
    $acrSubArgs += @('--agent-pool', "$AcrAgentPool".Trim())
    Write-Host "  build runs on agent pool '$AcrAgentPool' (inside the VNet)" -ForegroundColor DarkGray
}
$here     = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
# Guarded `az` shadow -- see _PimAz.ps1. The digest lookup at the end of this script already
# had to hand-roll half of this (BUG-128); the guard makes it the default for every az call.
. "$here\_PimAz.ps1"
$solRoot  = Split-Path -Parent (Split-Path -Parent $here)          # SOLUTIONS/PIM4EntraPS
$repoRoot = (Resolve-Path (Join-Path $here '..\..\..\..')).Path     # AutomateIT repo root
$mgrDir   = Join-Path $solRoot 'tools\pim-manager'
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Info($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }
# 🔴 BUG-154 -- THE PUBLIC COMMUNITY EDITION IS THE SOLUTION FLATTENED TO ITS OWN REPO ROOT.
# `$repoRoot` above is then two folders ABOVE the clone, the default -Dockerfile
# (SOLUTIONS/PIM4EntraPS/...) does not exist there, and the build threw "Dockerfile not found" --
# a community user could not build a Manager image at all. In the flat layout the build now runs
# from a STAGED context that recreates SOLUTIONS/PIM4EntraPS (engine/_shared/PIM-BuildContext.ps1).
# 🔒 The monorepo, the synced tree and every customer install resolve 'monorepo' and keep the
# branches below exactly as they were.
. (Join-Path $solRoot 'engine\_shared\PIM-BuildContext.ps1')
$buildLayout = Get-PimBuildLayout -SolutionRoot $solRoot -RepoRoot $repoRoot
if ($buildLayout -eq 'flat') {
    Write-Host "  layout: FLAT (public community edition) -- the image context is staged as SOLUTIONS/PIM4EntraPS" -ForegroundColor DarkGray
}

# Explicit sign-in, when the caller supplied one. Isolated AZURE_CONFIG_DIR keyed on the
# registry so concurrent per-environment builds cannot trample each other's profile.
if ($AdminSecret -and $AdminCertPem) { throw 'pass EITHER -AdminSecret OR -AdminCertPem, not both.' }
if ($TenantId -and $AdminAppId -and ($AdminSecret -or $AdminCertPem)) {
    $cfgDir = Join-Path $env:TEMP ("azcfg-build-" + $(if ($AcrName) { $AcrName } else { 'pim' }))
    New-Item -ItemType Directory -Force $cfgDir | Out-Null
    $env:AZURE_CONFIG_DIR = $cfgDir
    # Drop the cached token before signing in -- this directory persists between runs, so a
    # permission granted BETWEEN runs is otherwise invisible to the next one and surfaces as
    # "Insufficient privileges" against a permission that is already correct. See the long note at
    # the same point in Setup-PimContainers.ps1; the three sign-ins must not disagree.
    az account clear --only-show-errors 2>&1 | Out-Null
    az config set extension.use_dynamic_install=yes_without_prompt --only-show-errors 2>&1 | Out-Null
    if ($AdminCertPem) {
        if (-not (Test-Path $AdminCertPem)) { throw "certificate PEM not found: $AdminCertPem" }
        Step "az login (service principal, CERTIFICATE) -> tenant $TenantId"
        az login --service-principal -u $AdminAppId --certificate $AdminCertPem --tenant $TenantId --only-show-errors -o none
    } else {
        Step "az login (service principal, client secret) -> tenant $TenantId"
        az login --service-principal -u $AdminAppId -p $AdminSecret --tenant $TenantId --only-show-errors -o none
    }
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az login failed for tenant $TenantId (exit $LASTEXITCODE)." }
    if ($SubscriptionId) {
        az account set --subscription $SubscriptionId --only-show-errors
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az account set failed for subscription $SubscriptionId (exit $LASTEXITCODE)." }
    }
    Info "signed in; subscription $(az account show --query id -o tsv --only-show-errors 2>$null)"
}
function Have($cmd){ [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# reuse the pure content-hash helper so the post-build marker matches what detection compares.
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateLifecycle.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-ScenarioProfile.ps1')     # s31 scenario -> knob resolver

# ---- s31: a -Scenario maps to the build source the build paths understand ----
if ($Scenario) {
    $plan = Get-PimScenarioEntryPlan -Scenario $Scenario
    $resolvedBuildSource =
        if ($plan.updateSource -eq 'from-master') { if ($plan.managedHosting -eq 'central') { 'sync-automateit' } else { 'git-pull' } }
        elseif ($plan.updateSource -eq 'sync-automateit') { 'sync-automateit' }
        else { 'git-pull' }
    $Source = $resolvedBuildSource
    Write-Host ("[scenario] {0} -> build source={1} (edition={2}, hosting={3})" -f $plan.id, $Source, $plan.activeEdition, $plan.hostingLocation) -ForegroundColor Cyan
}

# best-effort banner (shared by the setup family).
$bannerShared = Join-Path $here '_PimSetupShared.ps1'
if (Test-Path $bannerShared) { . $bannerShared; if (Get-Command Show-PimSetupBanner -ErrorAction SilentlyContinue) { Show-PimSetupBanner -ScriptName 'Build-PimManagerImage' -SolutionRoot $solRoot } }

Write-Host "=== PIM4EntraPS BUILD Manager image ($Source) -> $ImageRepo`:$ImageTag ===" -ForegroundColor Cyan

# ---- compute the content hash of the pulled Manager image ---------------------
# 🔴 BUG-174: the file set is defined ONCE, in engine/_shared/PIM-UpdateLifecycle.ps1
# (Get-PimSolutionContentHash), and this builder, the roller's PIM_MANAGER_CONTENT_HASH stamp and the
# Invoke-PimUpdate detector all call it. Three private copies of the walk is how the roller came to stamp
# a tools\pim-manager-only hash that never matched, so every host-side update rebuilt an identical image.
<#
      🔴 HASH WHAT THE IMAGE CONTAINS, NOT ONE FOLDER INSIDE IT.

      This used to hash `tools/pim-manager` only. The Dockerfile copies the WHOLE solution --
      `COPY SOLUTIONS/PIM4EntraPS /app/PIM4EntraPS` -- so the Manager also runs engine/_shared,
      sql/ and the rest, and a change to any of them changed the running behaviour while leaving
      this hash IDENTICAL. `Test-ManagerImageCurrent` then reported the image current, `image` and
      `code` both skipped, and the fix never reached the environment.

      🔑 MEASURED, AND IT WAS THE WORST POSSIBLE FIX TO MISS. On 2026-09-12 a SEC-01 defect in
      engine/_shared/PIM-HostedAuth.ps1 locked every human out of the hosted Manager. It was fixed,
      committed, and the customer's master tenant was re-deployed -- which reported success, end to
      end, having rebuilt NOTHING. The same blindness applies to the nightly in-cloud updater, so
      the entire fleet would have kept the lockout indefinitely: a self-updating system that cannot
      see its own engine change is not self-updating.

      🪤 DENY-LIST, NOT ALLOW-LIST. Naming the folders that matter (tools/pim-manager + engine)
      fails silently the next time something runtime-relevant lives elsewhere -- which is exactly
      how this happened. Hash everything that ships and exclude only what CANNOT affect runtime, so
      a new directory is covered by default and the failure mode is an unnecessary rebuild rather
      than a missed one.
#>
# The SOLUTION root -- what the Dockerfile copies -- not tools/pim-manager.
$contentHash = Get-PimSolutionContentHash -SolutionRoot $solRoot
Info "pulled Manager content hash: $contentHash"

# 🔴 WHERE THE CODE COMES FROM IS NOT HOW THE IMAGE IS BUILT, AND CONFLATING THEM BROKE S6.
# The scenario map sends "from-master, locally hosted" (S6 -- a managed/slave tenant) to the
# git-pull path, because its UPDATE SOURCE is the master rather than the AutomateIT sync. But an S6
# slave still hosts its OWN containers, out of its OWN registry -- and on a greenfield slave that
# registry is empty. The git-pull path packages the Manager into a local output folder, pushes
# NOTHING, and then the step reported
#     -> ok=True ran=True built acrpimrj466/pim-manager:2.4.324
# naming an ACR image that does not exist. Infra refused two lines later, correctly:
#     ERROR: the specified tag does not exist
# Measured rebuilding a managed/slave tenant 2026-09-12.
# 🔑 THE SIGNAL IS -AcrName. A registry was supplied, so this environment HAS one and its containers
# pull from it; a community local install (S1/S2) passes none and is unaffected. Ring-gated updates
# from the master are unchanged -- this only decides how the FIRST image gets into the slave's own
# registry, which nothing else does.
$buildSource = $Source
if ($buildSource -ne 'sync-automateit' -and "$AcrName".Trim() -and (Have 'az')) {
    Step "hosted registry '$AcrName' supplied -- building INTO it (the update source stays '$Source')"
    Info '  a local package cannot be pulled by Container Apps; the slave needs a real image in its own ACR.'
    $buildSource = 'sync-automateit'
}

if ($buildSource -eq 'sync-automateit') {
    # ---- HOSTED: az acr build ------------------------------------------------
    if (-not (Have 'az')) { Warn 'azure CLI (az) not found -- hosted build needs az. Nothing done.'; return }
    if (-not "$AcrName".Trim()) { throw "-AcrName is required for -Source sync-automateit (hosted ACR build)." }
    if ($buildLayout -ne 'flat') {
        $dfPath = if ([System.IO.Path]::IsPathRooted($Dockerfile)) { $Dockerfile } else { Join-Path $repoRoot $Dockerfile }
        if (-not (Test-Path $dfPath)) { throw "Dockerfile not found: $dfPath" }
    }

    # Build from a CLEAN `git archive` export of HEAD, not the live working tree.
    # The repo root hosts agent git-worktrees under .claude/worktrees/ + .wt/, each a
    # full nested repo copy. `az acr build` tars the whole context and STATS every file
    # BEFORE applying .dockerignore, so a >260-char path inside a worktree (e.g. a deep
    # SecurityInsight sample, fine in the main tree but over Windows MAX_PATH once the
    # worktree prefix is added) aborts the tar walk with WinError 3. `git archive` emits
    # only tracked files in the repo layout the Dockerfile expects — no worktrees, no
    # untracked junk — so the context is small, deterministic, and walk-safe.
    Step "az acr build $ImageRepo`:$ImageTag in $AcrName (clean git-archive context of HEAD)"
    if ($PSCmdlet.ShouldProcess("$AcrName/$ImageRepo`:$ImageTag", 'az acr build')) {
      if ($buildLayout -eq 'flat') {
        # BUG-154: stage SOLUTIONS/PIM4EntraPS from the public clone, then build exactly as the
        # monorepo does. Short root for the same MAX_PATH reason as the git-archive branch below.
        $ctxRoot = Join-Path $env:SystemDrive 'pimbld'
        New-Item -ItemType Directory -Force $ctxRoot | Out-Null
        $flatCtx = Join-Path $ctxRoot ("f" + (Get-Random -Maximum 99999))
        try {
            $ctx = New-PimFlatBuildContext -SolutionRoot $solRoot -OutDir $flatCtx
            Info ("staged build context ({0}, {1} files) at {2}" -f $ctx.Method, $ctx.Files, $ctx.Path)
            Push-Location $flatCtx
            try {
                az acr build @acrSubArgs -r $AcrName -t "$ImageRepo`:$ImageTag" -f $Dockerfile . `
                    --build-arg "PIM_MANAGER_CONTENT_HASH=$contentHash" 2>&1 |
                    Tee-Object -Variable acrBuildOut | Out-Host
                $script:PimAcrBuildOutput = $acrBuildOut
                if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az acr build failed (exit $LASTEXITCODE)." }
            } finally { Pop-Location }
        } finally {
            Remove-Item -LiteralPath $flatCtx -Recurse -Force -ErrorAction SilentlyContinue
        }
      } else {
        $haveGit = [bool](Get-Command git  -ErrorAction SilentlyContinue)
        $haveTar = [bool](Get-Command tar  -ErrorAction SilentlyContinue)
        # 🔴 HAVING git IS NOT THE SAME AS BEING IN A git REPO, and conflating the two is what made
        # the daily update unbuildable on every CUSTOMER host. Measured 2026-09-04:
        #     git -C C:\AutomateIT archive ... HEAD  ->  exit 128
        #     fatal: not a git repository (or any of the parent directories): .git
        # `C:\AutomateIT` is the SYNCED PROD TREE -- Sync-AutomateIT.ps1 lays down released FILES,
        # it does not clone -- so it has no .git, while git.exe is obviously still on PATH. The old
        # gate therefore chose the git-archive path and died, and the repo-root fallback below (the
        # one that would have worked) was reachable only on a host with no git at all.
        # 🪤 This is why the nightly pull had nowhere to land: the tree the pull REFRESHES is the one
        # tree the build could not consume. Only a dev clone ever built, which is exactly the host
        # where a pull is least needed.
        # Falling back is SAFE here for the same reason git-archive was chosen: the danger it guards
        # against is deep agent worktrees + untracked junk under a DEV clone. A synced payload has
        # neither -- it is already the clean, released file set.
        # 🪤 PROBE WITHOUT INVOKING git IF POSSIBLE. The first version of this ran
        #     git -C $repoRoot rev-parse --git-dir 2>&1 | Out-Null
        # which is fine in PowerShell 7 and THROWS in PowerShell 5.1: `2>&1` turns a native
        # command's stderr into ErrorRecords, and the update runs with ErrorActionPreference='Stop',
        # so the probe itself became the fatal error -- reported as the very message it was written
        # to avoid ("fatal: not a git repository"), from inside the check meant to prevent it.
        # 🔴 It passed every interactive test because the scheduled task runs powershell.exe (5.1)
        # while a console here is 7.x. Testing the fix in the wrong host is how it shipped.
        # Test-Path needs no subprocess, cannot throw, and is version-independent. It is also
        # correct for both shapes: .git is a directory in a normal clone and a FILE in a worktree.
        $isRepo = Test-Path -LiteralPath (Join-Path $repoRoot '.git')
        if (-not $isRepo -and $haveGit) {
            # Fallback for a nested checkout whose root is elsewhere. Guarded three ways.
            $prevEA = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                & git -C $repoRoot rev-parse --git-dir 2>$null | Out-Null
                $isRepo = ($LASTEXITCODE -eq 0)
            } catch { $isRepo = $false }
            finally { $ErrorActionPreference = $prevEA; $global:LASTEXITCODE = 0 }
        }
        # 🪤 Write-Host, NOT Note: this file defines Step/Warn but NOT Note. Calling an undefined
        # helper is BUG-117 exactly -- Setup-PimContainers.ps1 shipped a Warn-less script and killed
        # every estate deploy that reached the line. A log helper must never be the thing that fails.
        if (-not $isRepo) { Write-Host "    build context: '$repoRoot' is not a git clone (synced/released tree) -- using it directly instead of a git-archive export." -ForegroundColor DarkGray }
        if ($haveGit -and $haveTar -and $isRepo) {
            # Short temp ROOT (not %TEMP%\<guid>): keeps extracted paths well under
            # Windows MAX_PATH. Archive ONLY the paths the image context needs
            # (.dockerignore whitelists SOLUTIONS/PIM4EntraPS) -- this also keeps the
            # long-named sample files of OTHER solutions (e.g. SecurityInsight) entirely
            # out of the context, so neither the tar walk nor extraction can choke.
            $ctxRoot = Join-Path $env:SystemDrive 'pimbld'
            New-Item -ItemType Directory -Force $ctxRoot | Out-Null
            $tmpCtx = Join-Path $ctxRoot ("c" + (Get-Random -Maximum 99999))
            $tarPath = "$tmpCtx.tar"
            New-Item -ItemType Directory -Force $tmpCtx | Out-Null
            try {
                git -C $repoRoot archive --format=tar -o $tarPath HEAD -- .dockerignore SOLUTIONS/PIM4EntraPS
                if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "git archive failed (exit $LASTEXITCODE)." }
                # Extract with RELATIVE paths, from the directory that holds both the archive
                # and the context folder.
                #
                # This used to pass absolute paths plus --force-local, because GNU tar reads
                # a Windows path's "C:" as a remote host (host:path) and aborts. That worked
                # only where `tar` was GNU tar. Windows now ships bsdtar as System32\tar.exe,
                # which REJECTS the flag outright --
                #     tar.exe: Option --force-local is not supported
                # -- so every deploy on such a host died at the build step (observed
                # 2026-08-07, blocking the whole fleet roll).
                #
                # No absolute path means no colon, which means neither tar can mistake the
                # archive for a remote host -- so the flag is not needed by either. Works
                # with GNU tar and bsdtar, which is what "runs on the operator's machine"
                # has to mean.
                Push-Location $ctxRoot
                try {
                    tar -x -f (Split-Path -Leaf $tarPath) -C (Split-Path -Leaf $tmpCtx)
                    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "tar extract of git archive failed (exit $LASTEXITCODE)." }
                } finally { Pop-Location }
                Push-Location $tmpCtx
                try {
                    # 🔑 CAPTURE THE BUILD OUTPUT: on a registry with public access OFF, the digest
                    # CANNOT be looked up afterwards from this host -- that query goes over the
                    # registry's data plane, which is exactly what is closed. But ACR prints the
                    # digest it just pushed, so read it from there rather than asking the registry.
                    az acr build @acrSubArgs -r $AcrName -t "$ImageRepo`:$ImageTag" -f $Dockerfile . `
                        --build-arg "PIM_MANAGER_CONTENT_HASH=$contentHash" 2>&1 |
                        Tee-Object -Variable acrBuildOut | Out-Host
                    $script:PimAcrBuildOutput = $acrBuildOut
                    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az acr build failed (exit $LASTEXITCODE)." }
                } finally { Pop-Location }
            } finally {
                Remove-Item $tarPath -Force -ErrorAction SilentlyContinue
                Remove-Item $tmpCtx  -Recurse -Force -ErrorAction SilentlyContinue
            }
        } else {
            # Fallback (no git/tar): build from the repo root directly. Works when the
            # tree carries no deep-path worktrees.
            # Say WHICH condition sent us here. "git/tar not found" was printed on the synced-tree
            # path too, where git IS installed -- sending anyone who read the log to diagnose a
            # missing tool that was never missing.
            $why = if (-not $isRepo) { "'$repoRoot' is not a git clone" } else { 'git/tar not found' }
            Warn "$why -- falling back to repo-root build context (no clean export)."
            Push-Location $repoRoot
            try {
                # 🪤 THE SAME CAPTURE AS THE GIT-ARCHIVE BRANCH ABOVE, AND IT WAS MISSED HERE.
                # Only one of the two branches was patched, so a SYNCED tree (not a git clone --
                # which is every customer install) took this path, produced no captured output, and
                # fell back to querying a registry it cannot reach. Measured at a customer
                # 2026-09-11: "'D:\AutomateIT' is not a git clone -- falling back to repo-root
                # build context", then "could not resolve the built image's digest".
                az acr build @acrSubArgs -r $AcrName -t "$ImageRepo`:$ImageTag" -f $Dockerfile . `
                    --build-arg "PIM_MANAGER_CONTENT_HASH=$contentHash" 2>&1 |
                    Tee-Object -Variable acrBuildOut | Out-Host
                $script:PimAcrBuildOutput = $acrBuildOut
                if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az acr build failed (exit $LASTEXITCODE)." }
            } finally { Pop-Location }
        }
      }   # end of the monorepo/synced-tree branch (BUG-154)
        Write-Host "  built $AcrName.azurecr.io/$ImageRepo`:$ImageTag (content $contentHash)" -ForegroundColor Green
        # BUG-40: report the DIGEST the tag now points at. Rebuilding an existing tag moves this
        # pointer, and that move is invisible in every tag-shaped log line above -- which is how a
        # rebuild came to be deployed "successfully" while the platform kept the previous image.
        # Printing it here gives a human the one value that identifies the content, and the deploy
        # scripts resolve the same value to pin what they roll.
        # 🔑 PREFER THE DIGEST ACR JUST PRINTED. Resolve-PimAcrImageDigest queries the registry's
        # DATA PLANE, which a private registry does not expose to this host at all -- so on an
        # internal-only deployment the lookup can never succeed, and the deploy then refuses to
        # pin by tag (correctly, BUG-40) and stops. Measured at a customer 2026-09-11: the build
        # itself succeeded on an in-VNet agent pool and printed
        #     2.4.324: digest: sha256:<...> size: 1369
        # while the follow-up query failed with "Could not connect to the registry login server".
        # The authoritative value was already on screen; asking the registry for it again was the
        # only thing that needed network access.
        $builtDigest = $null
        if ($script:PimAcrBuildOutput) {
            $m = [regex]::Match(($script:PimAcrBuildOutput -join "`n"), 'digest:\s*(sha256:[0-9a-f]{64})')
            if ($m.Success) {
                $builtDigest = $m.Groups[1].Value
                Write-Host "  digest $builtDigest  <- from the build output (registry not queried)" -ForegroundColor Green
                # PUBLISH IT. The infra step pins the digest and would otherwise ask the registry
                # for something this process already knows -- which a private registry will not
                # answer from outside its VNet. Keyed to the exact image so a stale value from an
                # earlier build of a DIFFERENT tag can never be picked up by mistake.
                $global:PIM_LastBuiltDigest   = $builtDigest
                $global:PIM_LastBuiltImageRef = "$AcrName/$ImageRepo`:$ImageTag"
            }
        }
        if (-not $builtDigest -and (Get-Command Resolve-PimAcrImageDigest -ErrorAction SilentlyContinue)) {
            try {
                # DECLARED **AND** FORWARDED -- the resolver accepts a subscription and this caller
                # not passing it is what sent the lookup into another company's tenant.
                $rdArgs = @{ AcrName = $AcrName; Repository = $ImageRepo; Tag = $ImageTag }
                if ("$SubscriptionId".Trim()) { $rdArgs['SubscriptionId'] = "$SubscriptionId".Trim() }
                $builtDigest = Resolve-PimAcrImageDigest @rdArgs
                Write-Host "  digest $builtDigest  <- this, not the tag, is what the deploy pins" -ForegroundColor Green
            } catch {
                Warn "could not resolve the built image's digest: $($_.Exception.Message)"
                # BUG-128: the digest lookup is NON-FATAL by design -- but the az call inside it
                # left its failure in $LASTEXITCODE, and Invoke-PimUpdate judges THE BUILD by that
                # same variable. Swallowing the error without clearing the code reported a
                # SUCCESSFUL build as "exit -1" and aborted the deploy. A caught error is not an
                # exit status: clear it, or a warning silently becomes a release failure.
                $global:LASTEXITCODE = 0
            }
        }
    }
    Step "Done. Roll it with Update-PimContainers.ps1 -ImageTag $ImageTag (NOT -SkipBuild already covered)."
    return
}

# ---- COMMUNITY: local build / package + relaunch -----------------------------
$engine = if (Have 'docker') { 'docker' } elseif (Have 'podman') { 'podman' } else { '' }
if ($engine) {
    Step "local $engine build $ImageRepo`:$ImageTag (context: $repoRoot)"
    if ($PSCmdlet.ShouldProcess("$ImageRepo`:$ImageTag", "$engine build")) {
        # BUG-154: a flat (public) clone builds from a staged SOLUTIONS/PIM4EntraPS context.
        $localCtx = $repoRoot; $localTmp = $null
        if ($buildLayout -eq 'flat') {
            $localTmp = Join-Path (Join-Path $env:SystemDrive 'pimbld') ("l" + (Get-Random -Maximum 99999))
            $localCtx = (New-PimFlatBuildContext -SolutionRoot $solRoot -OutDir $localTmp).Path
        }
        Push-Location $localCtx
        try {
            & $engine build -t "$ImageRepo`:$ImageTag" -f $Dockerfile --build-arg "PIM_MANAGER_CONTENT_HASH=$contentHash" .
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "$engine build failed (exit $LASTEXITCODE)." }
        } finally {
            Pop-Location
            if ($localTmp) { Remove-Item -LiteralPath $localTmp -Recurse -Force -ErrorAction SilentlyContinue }
        }
        Write-Host "  built local $ImageRepo`:$ImageTag (content $contentHash)" -ForegroundColor Green
    }
} else {
    # no container engine -- package the pulled Manager tree for a direct local relaunch.
    $pkgDir = Join-Path $solRoot 'output\manager-package'
    Step "no container engine -- package the pulled Manager into $pkgDir"
    if ($PSCmdlet.ShouldProcess($pkgDir, 'package Manager for local relaunch')) {
        if (-not (Test-Path $pkgDir)) { New-Item -ItemType Directory -Force $pkgDir | Out-Null }
        Copy-Item -Path (Join-Path $mgrDir '*') -Destination $pkgDir -Recurse -Force -Exclude 'cache','*.custom.*'
        @{ imageTag = $ImageTag; contentHash = $contentHash; packagedUtc = [datetime]::UtcNow.ToString('o') } |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $pkgDir 'manager-package.json') -Encoding UTF8
        Write-Host "  packaged $ImageRepo`:$ImageTag (content $contentHash) -> $pkgDir" -ForegroundColor Green
    }
}

if ($Relaunch) {
    $rl = if ("$RelaunchScript".Trim()) { $RelaunchScript } else { Join-Path $mgrDir 'Open-PimManager.ps1' }
    Step "relaunch local Manager via $rl"
    if ((Test-Path $rl) -and $PSCmdlet.ShouldProcess($rl, 'relaunch')) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $rl
    } elseif (-not (Test-Path $rl)) { Warn "relaunch script not found: $rl (skipping relaunch)." }
}
Step "Done. Community local build/package complete (content $contentHash)."
