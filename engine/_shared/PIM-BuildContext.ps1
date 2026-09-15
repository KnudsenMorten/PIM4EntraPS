#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-154 -- build the Manager image from EITHER repository layout.

.DESCRIPTION
    The Manager Dockerfile copies `SOLUTIONS/PIM4EntraPS` into the image, and the build scripts
    were written for the monorepo, where the solution lives at exactly that path under the repo
    root. The PUBLIC community edition is the same solution FLATTENED to the root of its own
    repository (.github/scripts/publish-stage.ps1). From a public clone the build therefore looked
    for the Dockerfile two folders ABOVE the clone and threw "Dockerfile not found": a community
    user could not produce a Manager image at all, so a hosted S2 install could not start.

    🔒 THE MONOREPO PATH DOES NOT CHANGE. Get-PimBuildLayout returns 'monorepo' whenever the
    solution really sits at <repoRoot>\SOLUTIONS\PIM4EntraPS -- the dev clone, the synced
    C:\AutomateIT tree and every customer install -- and the build keeps its existing branch.
    Only a tree where that is NOT true ('flat') gets a staged context.

    🔑 THE STAGED CONTEXT RECREATES THE LAYOUT THE DOCKERFILE EXPECTS, instead of editing the
    Dockerfile. `ctx\SOLUTIONS\PIM4EntraPS\` is filled from the clone -- via `git archive HEAD`
    when the solution root is a git repository (committed code only, the same property the
    monorepo branch relies on), otherwise by a filtered copy -- and a `.dockerignore` with the
    monorepo's rules is written beside it. Customer files (`*.custom.*`, licences, keys, caches)
    never enter the context, whichever way it was filled.

    Pure/offline-testable: no az, no network. tests/Test-PimBuildContext.ps1.
#>

function Get-PimBuildLayout {
    <#
      'monorepo' when the solution is <RepoRoot>\SOLUTIONS\PIM4EntraPS (same directory, compared by
      full path); 'flat' otherwise. Never throws: an unresolvable RepoRoot is simply not a monorepo.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SolutionRoot,
        [AllowEmptyString()][string]$RepoRoot
    )
    try {
        $sol = [System.IO.Path]::GetFullPath($SolutionRoot).TrimEnd('\', '/')
        if (-not "$RepoRoot".Trim()) { return 'flat' }
        $expected = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot 'SOLUTIONS\PIM4EntraPS')).TrimEnd('\', '/')
        if (($sol -ieq $expected) -and (Test-Path -LiteralPath (Join-Path $expected 'tools\pim-manager\Dockerfile'))) {
            return 'monorepo'
        }
    } catch { }
    return 'flat'
}

function Get-PimBuildContextDockerIgnore {
    # The monorepo's .dockerignore rules for the solution, for a context that holds ONLY the
    # solution. Kept in step with the repo-root .dockerignore by tests/Test-PimBuildContext.ps1.
    @(
        '# Staged by engine/_shared/PIM-BuildContext.ps1 (BUG-154) -- mirrors the monorepo .dockerignore.'
        'SOLUTIONS/PIM4EntraPS/**/*.custom.json'
        'SOLUTIONS/PIM4EntraPS/**/*.custom.ps1'
        'SOLUTIONS/PIM4EntraPS/**/*.custom.csv'
        'SOLUTIONS/PIM4EntraPS/**/*.pimlicense'
        'SOLUTIONS/PIM4EntraPS/**/cache/'
        'SOLUTIONS/PIM4EntraPS/**/*state*.json'
        'SOLUTIONS/PIM4EntraPS/**/pimlab-state.json'
        'SOLUTIONS/PIM4EntraPS/**/*.pem'
        'SOLUTIONS/PIM4EntraPS/**/*.key'
        '**/.git'
        '**/.claude/'
        '**/.wt/'
    ) -join "`n"
}

function Test-PimBuildContextExcluded {
    <# PURE: is a solution-relative path one the image must never receive? (copy-mode filter) #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RelativePath)
    $p = $RelativePath.Replace('\', '/').TrimStart('/')
    $segs = $p -split '/'
    foreach ($s in $segs[0..([Math]::Max(0, $segs.Count - 2))]) {
        if ($segs.Count -gt 1 -and ($s -in @('.git', '.claude', '.wt', 'cache', 'logs', 'output', 'node_modules'))) { return $true }
    }
    $leaf = $segs[-1]
    if ($leaf -eq '.git') { return $true }
    if ($leaf -match '\.custom\.(json|ps1|csv)$') { return $true }
    if ($leaf -match '\.(pimlicense|aitlicense|pem|key|pfx)$') { return $true }
    if ($leaf -cmatch 'state.*\.json$') { return $true }   # the monorepo rule '*state*.json' (case-sensitive, as Docker is)
    return $false
}

function New-PimFlatBuildContext {
    <#
      Stage `<OutDir>\SOLUTIONS\PIM4EntraPS\` + `<OutDir>\.dockerignore` from a flat clone.
      Returns @{ Path; Method = 'git-archive'|'copy'; Files = <count> }. Throws when the solution
      has no Manager Dockerfile (not a PIM4EntraPS tree) or git archive fails on a git clone --
      a partial context would build an image silently missing code.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SolutionRoot,
        [Parameter(Mandatory)][string]$OutDir,
        [switch]$NoGit
    )
    $sol = [System.IO.Path]::GetFullPath($SolutionRoot).TrimEnd('\', '/')
    if (-not (Test-Path -LiteralPath (Join-Path $sol 'tools\pim-manager\Dockerfile'))) {
        throw "New-PimFlatBuildContext: '$sol' has no tools\pim-manager\Dockerfile -- not a PIM4EntraPS solution root."
    }
    $dest = Join-Path $OutDir 'SOLUTIONS\PIM4EntraPS'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null

    $isGit = (-not $NoGit) -and (Test-Path -LiteralPath (Join-Path $sol '.git')) -and [bool](Get-Command git -ErrorAction SilentlyContinue) -and [bool](Get-Command tar -ErrorAction SilentlyContinue)
    $method = 'copy'
    if ($isGit) {
        $tarPath = Join-Path $OutDir 'ctx.tar'
        $prevEA = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & git -C $sol archive --format=tar -o $tarPath HEAD 2>$null
            $gitExit = $LASTEXITCODE
        } finally { $ErrorActionPreference = $prevEA }
        if ($gitExit -ne 0 -or -not (Test-Path -LiteralPath $tarPath)) {
            throw "New-PimFlatBuildContext: git archive of '$sol' failed (exit $gitExit). Commit your changes or pass -NoGit."
        }
        # Relative paths only: GNU tar reads 'C:' as a remote host, and bsdtar refuses --force-local.
        Push-Location $dest
        try {
            & tar -x -f (Join-Path '..\..' 'ctx.tar')
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "New-PimFlatBuildContext: tar extract failed (exit $LASTEXITCODE)." }
        } finally { Pop-Location }
        Remove-Item -LiteralPath $tarPath -Force -ErrorAction SilentlyContinue
        $method = 'git-archive'
        # git archive carries only TRACKED files, but a tracked customer file is still a customer
        # file -- apply the same exclusion to what was extracted.
        foreach ($f in @(Get-ChildItem -LiteralPath $dest -Recurse -File -Force)) {
            $rel = $f.FullName.Substring($dest.Length).TrimStart('\', '/')
            if (Test-PimBuildContextExcluded -RelativePath $rel) { Remove-Item -LiteralPath $f.FullName -Force }
        }
    } else {
        foreach ($f in @(Get-ChildItem -LiteralPath $sol -Recurse -File -Force)) {
            $rel = $f.FullName.Substring($sol.Length).TrimStart('\', '/')
            if (Test-PimBuildContextExcluded -RelativePath $rel) { continue }
            $target = Join-Path $dest $rel
            $tdir = Split-Path -Parent $target
            if (-not (Test-Path -LiteralPath $tdir)) { New-Item -ItemType Directory -Force -Path $tdir | Out-Null }
            Copy-Item -LiteralPath $f.FullName -Destination $target -Force
        }
    }
    Set-Content -LiteralPath (Join-Path $OutDir '.dockerignore') -Value (Get-PimBuildContextDockerIgnore) -Encoding ascii
    $count = @(Get-ChildItem -LiteralPath $dest -Recurse -File -Force).Count
    if (-not (Test-Path -LiteralPath (Join-Path $dest 'tools\pim-manager\Dockerfile'))) {
        throw "New-PimFlatBuildContext: the staged context has no Dockerfile -- refusing to build an incomplete image."
    }
    return [pscustomobject]@{ Path = [System.IO.Path]::GetFullPath($OutDir); Method = $method; Files = $count }
}
