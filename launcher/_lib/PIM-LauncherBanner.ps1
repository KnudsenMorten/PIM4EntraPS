#Requires -Version 5.1
<#
.SYNOPSIS
    Shared launcher banner for every PIM4EntraPS launcher.*.ps1 -- output
    format matches SecurityInsight's Write-Banner 1:1 so the two solutions
    look identical at run start.

.DESCRIPTION
    Dot-sourced + called from each PIM launcher right after Resolve-RepoRoot:

        . (Join-Path $InstallPath 'SOLUTIONS\PIM4EntraPS\launcher\_lib\PIM-LauncherBanner.ps1')
        Write-PimLauncherBanner -LauncherPath $PSCommandPath -RepoRoot $InstallPath

    EngineName + flavour are auto-derived from the launcher's $PSCommandPath
    (parent folder = engine, filename suffix = flavour).
    Version comes from <repoRoot>\SOLUTIONS\PIM4EntraPS\VERSION (same file
    PIM-Functions.psm1 reads at module-load).

    Output (Cyan, 88-char delimiter -- IDENTICAL format to SI's Write-Banner
    in SOLUTIONS\SecurityInsight\launcher\<engine>\launcher.*.ps1):

      ========================================================================================
        PIM4EntraPS -- PIM-Baseline-Management-CSV    [internal-vm]   v2.4.71

        Developed by Morten Knudsen -- Microsoft MVP
        Blog:    https://mortenknudsen.net   (aka.ms/morten)
        GitHub:  https://github.com/KnudsenMorten
        Support: GitHub Issues on the public repo, or mok@mortenknudsen.net (internal)
      ========================================================================================

.NOTES
    Introduced  : PIM4EntraPS v2.4.66 -- reformatted to SI parity in v2.4.71
    Designed by : Morten Knudsen, 2linkIT
#>

function Write-PimLauncherBanner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LauncherPath,
        [Parameter(Mandatory)][string]$RepoRoot
    )

    # LauncherPath shape:
    #   <repo>\SOLUTIONS\PIM4EntraPS\launcher\<EngineName>\launcher.<flavour>.ps1
    $engineName = Split-Path -Parent $LauncherPath | Split-Path -Leaf
    $fileName   = Split-Path -Leaf $LauncherPath
    $flavour    = if ($fileName -match '^launcher\.([\w-]+)\.ps1$') { $Matches[1] } else { '(unknown)' }

    $verFile = Join-Path $RepoRoot 'SOLUTIONS\PIM4EntraPS\VERSION'
    $ver     = '(dev)'
    if (Test-Path -LiteralPath $verFile) {
        try { $ver = "v" + (Get-Content -LiteralPath $verFile -Raw).Trim() } catch {}
    }

    $line = '=' * 88
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  {0} -- {1}    [{2}]   {3}" -f 'PIM4EntraPS', $engineName, $flavour, $ver) -ForegroundColor Cyan
    Write-Host '' -ForegroundColor Cyan
    Write-Host '  Developed by Morten Knudsen -- Microsoft MVP' -ForegroundColor Cyan
    Write-Host '  Blog:    https://mortenknudsen.net   (aka.ms/morten)' -ForegroundColor Cyan
    Write-Host '  GitHub:  https://github.com/KnudsenMorten' -ForegroundColor Cyan
    Write-Host '  Support: GitHub Issues on the public repo, or mok@mortenknudsen.net (internal)' -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ''
}
