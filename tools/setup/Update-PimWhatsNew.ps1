#Requires -Version 7.0
<#
.SYNOPSIS
    WHATS-NEW-1 (framework REQUIREMENTS "## WHATS-NEW-1"): after a whats-new/<version>.json is added or changed, refresh
    the two files made FROM the folder -- whats-new/SHA256SUMS.txt and the Community repo's WHATSNEW.md. Never hand-write either.

.DESCRIPTION
    1. Checks the folder with Invardia's ONE conformance check (tools/whatsnew/ConvertTo-WhatsNewMarkdown.ps1 -Check: the
       schema, the easy-to-read limits, no commit hash / ticket number). A failing folder changes nothing (exit 1).
    2. Writes whats-new/SHA256SUMS.txt: one "<sha256>  <file>" line per <version>.json, sorted by name, LF.
    3. Writes WHATSNEW.md at the solution root with the same renderer (-ProductName "PIM Manager"), which the public
       mirror carries to GitHub and the README links. tests/Test-PimWhatsNew.ps1 fails when either file is stale.
    No module, no network.

.EXAMPLE
    pwsh -NoProfile -File tools\setup\Update-PimWhatsNew.ps1
#>
[CmdletBinding()] param([string]$SolutionRoot = '')
$ErrorActionPreference = 'Stop'
if (-not "$SolutionRoot".Trim()) { $SolutionRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
$dir = Join-Path $SolutionRoot 'whats-new'
$conv = Join-Path $SolutionRoot 'tools/whatsnew/ConvertTo-WhatsNewMarkdown.ps1'
$pwshExe = (Get-Process -Id $PID).Path

& $pwshExe -NoProfile -File $conv -Folder $dir -Check
if ($LASTEXITCODE) { Write-Host 'NOT updated: the What''s new files do not pass the check (above).' -ForegroundColor Red; exit 1 }

$all = @(Get-ChildItem -LiteralPath $dir -File -Filter '*.json')
$stray = @($all | Where-Object { $_.Name -notmatch '^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]{1,30})?\.json$' })
if ($stray.Count) { Write-Host "NOT updated: whats-new holds files that are not <version>.json: $($stray.Name -join ', ')" -ForegroundColor Red; exit 1 }
$lines = foreach ($f in @($all | Sort-Object Name)) {
    '{0}  {1}' -f (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $f.Name
}
[IO.File]::WriteAllText((Join-Path $dir 'SHA256SUMS.txt'), ((@($lines) -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
Write-Host "written $(Join-Path $dir 'SHA256SUMS.txt') ($(@($lines).Count) files)"

& $pwshExe -NoProfile -File $conv -Folder $dir -OutFile (Join-Path $SolutionRoot 'WHATSNEW.md') -ProductName 'PIM Manager'
if ($LASTEXITCODE) { exit 1 }
exit 0
