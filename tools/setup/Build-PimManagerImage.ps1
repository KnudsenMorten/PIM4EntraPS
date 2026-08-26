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
$here     = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot  = Split-Path -Parent (Split-Path -Parent $here)          # SOLUTIONS/PIM4EntraPS
$repoRoot = (Resolve-Path (Join-Path $here '..\..\..\..')).Path     # AutomateIT repo root
$mgrDir   = Join-Path $solRoot 'tools\pim-manager'
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Info($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }

# Explicit sign-in, when the caller supplied one. Isolated AZURE_CONFIG_DIR keyed on the
# registry so concurrent per-environment builds cannot trample each other's profile.
if ($AdminSecret -and $AdminCertPem) { throw 'pass EITHER -AdminSecret OR -AdminCertPem, not both.' }
if ($TenantId -and $AdminAppId -and ($AdminSecret -or $AdminCertPem)) {
    $cfgDir = Join-Path $env:TEMP ("azcfg-build-" + $(if ($AcrName) { $AcrName } else { 'pim' }))
    New-Item -ItemType Directory -Force $cfgDir | Out-Null
    $env:AZURE_CONFIG_DIR = $cfgDir
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

# ---- compute the content hash of the pulled Manager GUI surface ---------------
function Get-ManagerContentHash {
    param([string]$Dir)
    if (-not (Test-Path $Dir)) { return '' }
    $files = @(Get-ChildItem -Path $Dir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\cache\\' -and $_.Name -notmatch '\.custom\.' })
    $digests = foreach ($f in $files) {
        $rel = $f.FullName.Substring($Dir.Length).TrimStart('\','/')
        [pscustomobject]@{ path = $rel; sha256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash }
    }
    Get-PimContentHash -FileDigests @($digests)
}
$contentHash = Get-ManagerContentHash -Dir $mgrDir
Info "pulled Manager content hash: $contentHash"

if ($Source -eq 'sync-automateit') {
    # ---- HOSTED: az acr build ------------------------------------------------
    if (-not (Have 'az')) { Warn 'azure CLI (az) not found -- hosted build needs az. Nothing done.'; return }
    if (-not "$AcrName".Trim()) { throw "-AcrName is required for -Source sync-automateit (hosted ACR build)." }
    $dfPath = if ([System.IO.Path]::IsPathRooted($Dockerfile)) { $Dockerfile } else { Join-Path $repoRoot $Dockerfile }
    if (-not (Test-Path $dfPath)) { throw "Dockerfile not found: $dfPath" }

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
        $haveGit = [bool](Get-Command git  -ErrorAction SilentlyContinue)
        $haveTar = [bool](Get-Command tar  -ErrorAction SilentlyContinue)
        if ($haveGit -and $haveTar) {
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
                    az acr build -r $AcrName -t "$ImageRepo`:$ImageTag" -f $Dockerfile . `
                        --build-arg "PIM_MANAGER_CONTENT_HASH=$contentHash"
                    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az acr build failed (exit $LASTEXITCODE)." }
                } finally { Pop-Location }
            } finally {
                Remove-Item $tarPath -Force -ErrorAction SilentlyContinue
                Remove-Item $tmpCtx  -Recurse -Force -ErrorAction SilentlyContinue
            }
        } else {
            # Fallback (no git/tar): build from the repo root directly. Works when the
            # tree carries no deep-path worktrees.
            Warn 'git/tar not found -- falling back to repo-root build context (no clean export).'
            Push-Location $repoRoot
            try {
                az acr build -r $AcrName -t "$ImageRepo`:$ImageTag" -f $Dockerfile . `
                    --build-arg "PIM_MANAGER_CONTENT_HASH=$contentHash"
                if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az acr build failed (exit $LASTEXITCODE)." }
            } finally { Pop-Location }
        }
        Write-Host "  built $AcrName.azurecr.io/$ImageRepo`:$ImageTag (content $contentHash)" -ForegroundColor Green
        # BUG-40: report the DIGEST the tag now points at. Rebuilding an existing tag moves this
        # pointer, and that move is invisible in every tag-shaped log line above -- which is how a
        # rebuild came to be deployed "successfully" while the platform kept the previous image.
        # Printing it here gives a human the one value that identifies the content, and the deploy
        # scripts resolve the same value to pin what they roll.
        if (Get-Command Resolve-PimAcrImageDigest -ErrorAction SilentlyContinue) {
            try {
                $builtDigest = Resolve-PimAcrImageDigest -AcrName $AcrName -Repository $ImageRepo -Tag $ImageTag
                Write-Host "  digest $builtDigest  <- this, not the tag, is what the deploy pins" -ForegroundColor Green
            } catch { Warn "could not resolve the built image's digest: $($_.Exception.Message)" }
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
        Push-Location $repoRoot
        try {
            & $engine build -t "$ImageRepo`:$ImageTag" -f $Dockerfile --build-arg "PIM_MANAGER_CONTENT_HASH=$contentHash" .
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "$engine build failed (exit $LASTEXITCODE)." }
        } finally { Pop-Location }
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
