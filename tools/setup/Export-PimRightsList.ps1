#Requires -Version 5.1

<#
.SYNOPSIS
    RIGHTS-LIVE-1 (framework, owner 2026-11-10): writes PIM Manager's approved rights list for one version --
    pim-manager-rights-<version>.json in Invardia's normalised shape ("schema": "invardia-rights/1") + SHA256SUMS.txt.

.DESCRIPTION
    The list is GENERATED FROM THE CODE'S OWN GRANT SETS (engine\_shared\PIM-RightsList.ps1 Get-PimApprovedRightsList), so
    it cannot drift from what setup and the updater grant (tests\Test-PimRightsList.ps1 holds both directions).
    The hand-over folder Invardia reads is handover\rights\pim-manager\<version>\ -- ONE .json + SHA256SUMS.txt; pass it
    as -OutDir. Local files only: it signs in to nothing and changes nothing in Azure or Entra.
    SHA256SUMS.txt: '<sha256 lower-case>  <file name>' + LF, the json only.

.PARAMETER Version
    The PIM Manager version the list belongs to (e.g. 3.0.76). Default: the solution's VERSION file.

.PARAMETER OutDir
    The folder to write to (created when missing).

.PARAMETER Approval
    The approval text in the list. Default: released with that version, generated from the code.

.EXAMPLE
    pwsh -File tools\setup\Export-PimRightsList.ps1 -Version 3.0.76 -OutDir C:\ProgramData\Invardia\handover\rights\pim-manager\3.0.76
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Version = '',
    [Parameter(Mandatory)][string]$OutDir,
    [string]$Approval = ''
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $solRoot 'engine\_shared\PIM-RightsList.ps1')

if (-not "$Version".Trim()) { $Version = "$(Get-Content -Raw -LiteralPath (Join-Path $solRoot 'VERSION'))".Trim() }
$list = Get-PimApprovedRightsList -Version $Version -Approval $Approval
$json = ConvertTo-PimRightsListJson -List $list
$name = "pim-manager-rights-$($list.version).json"
$enc = New-Object System.Text.UTF8Encoding $false
$bytes = $enc.GetBytes($json)
$sha = [System.Security.Cryptography.SHA256]::Create()
try { $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
$sums = "$hash  $name`n"

if ($PSCmdlet.ShouldProcess($OutDir, "write $name + SHA256SUMS.txt")) {
    if (-not (Test-Path -LiteralPath $OutDir)) { [void](New-Item -ItemType Directory -Force -Path $OutDir) }
    [IO.File]::WriteAllBytes((Join-Path $OutDir $name), $bytes)
    [IO.File]::WriteAllText((Join-Path $OutDir 'SHA256SUMS.txt'), $sums, $enc)
    $n = 0; foreach ($i in @($list.identities)) { $n += @($i.rights).Count }
    Write-Host "rights list $name written to ${OutDir}: $(@($list.identities).Count) identities, $n rights (sha256 $hash)"
}
[pscustomobject]@{ file = $name; sha256 = $hash; identities = @($list.identities).Count; outDir = $OutDir }
