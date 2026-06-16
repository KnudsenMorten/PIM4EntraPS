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
    [string]$AcrName,
    [string]$ImageRepo  = 'pim-manager',
    [string]$Dockerfile = 'SOLUTIONS/PIM4EntraPS/tools/pim-manager/Dockerfile',
    [switch]$Relaunch,            # community only: relaunch the local Manager after packaging
    [string]$RelaunchScript       # community only: path to the local relaunch script
)
$ErrorActionPreference = 'Stop'
$here     = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot  = Split-Path -Parent (Split-Path -Parent $here)          # SOLUTIONS/PIM4EntraPS
$repoRoot = (Resolve-Path (Join-Path $here '..\..\..\..')).Path     # AutomateIT repo root
$mgrDir   = Join-Path $solRoot 'tools\pim-manager'
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Info($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }
function Have($cmd){ [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# reuse the pure content-hash helper so the post-build marker matches what detection compares.
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateLifecycle.ps1')

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

    Step "az acr build $ImageRepo`:$ImageTag in $AcrName (context: $repoRoot)"
    if ($PSCmdlet.ShouldProcess("$AcrName/$ImageRepo`:$ImageTag", 'az acr build')) {
        Push-Location $repoRoot
        try {
            az acr build -r $AcrName -t "$ImageRepo`:$ImageTag" -f $Dockerfile . `
                --build-arg "PIM_MANAGER_CONTENT_HASH=$contentHash"
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "az acr build failed (exit $LASTEXITCODE)." }
        } finally { Pop-Location }
        Write-Host "  built $AcrName.azurecr.io/$ImageRepo`:$ImageTag (content $contentHash)" -ForegroundColor Green
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
