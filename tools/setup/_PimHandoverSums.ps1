#Requires -Version 5.1
<#
  _PimHandoverSums.ps1 -- PIM REQUIREMENTS 100.30: the docs hand-over folder (C:\ProgramData\Invardia\handover\docs\
  pim-manager\<version>\) carries ONE SHA256SUMS.txt over EVERY file in it. Each builder that writes into the folder
  (Build-PimSettingsDocs, Build-PimSecurityPack, Build-PimSetupCatalog) calls Write-PimHandoverSums last, so whichever runs
  last leaves a complete list -- the 2.4.538 folder's sums missed security-pack.* because each builder wrote its own.
  Format: '<sha256 lower-case>  <relative path, forward slashes>' per line, LF, ordinal order; SHA256SUMS.txt itself is
  not listed. No modules; local files only.
#>
Set-StrictMode -Off

function Get-PimHandoverSumsText {
    <# The SHA256SUMS.txt text for every file under -Dir (recursive), SHA256SUMS.txt itself excluded. #>
    param([Parameter(Mandatory)][string]$Dir)
    $root = (Resolve-Path -LiteralPath $Dir).ProviderPath.TrimEnd('\', '/')
    $files = @(Get-ChildItem -LiteralPath $root -File -Recurse | Where-Object { $_.Name -ne 'SHA256SUMS.txt' -or $_.DirectoryName.TrimEnd('\', '/') -ne $root })
    $rows = New-Object System.Collections.Generic.List[string]
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        foreach ($f in $files) {
            $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/').Replace('\', '/')
            $h = ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($f.FullName)))).Replace('-', '').ToLowerInvariant()
            $rows.Add("$h  $rel")
        }
    } finally { $sha.Dispose() }
    [string[]]$sorted = $rows.ToArray()
    [Array]::Sort($sorted, [Comparison[string]] { param($a, $b) [string]::CompareOrdinal($a.Substring(66), $b.Substring(66)) })
    if (-not $sorted.Count) { return '' }
    return (($sorted -join "`n") + "`n")
}

function Write-PimHandoverSums {
    <# (Re)writes -Dir\SHA256SUMS.txt over every file in -Dir. Returns the number of files listed. #>
    param([Parameter(Mandatory)][string]$Dir)
    $txt = Get-PimHandoverSumsText -Dir $Dir
    [IO.File]::WriteAllText((Join-Path $Dir 'SHA256SUMS.txt'), $txt, (New-Object System.Text.UTF8Encoding $false))
    return @($txt -split "`n" | Where-Object { $_ }).Count
}
