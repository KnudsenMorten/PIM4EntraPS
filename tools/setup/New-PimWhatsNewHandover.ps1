#Requires -Version 7.0
<#
.SYNOPSIS
    WHATS-NEW-1 (framework point 4): the release hand-over's whats-new part -- every release's <version>.json plus a
    SHA256SUMS.txt over them, in the folder Invardia reads (handover\whats-new\pim-manager\<version>\). Invardia imports it
    for invardia.com (/products/pim-manager/whats-new) and the rings 2/3 approval mail.

.DESCRIPTION
    Built from the solution tree it sits in (the release TAG tree, like the other hand-over generators). Refuses (exit 1,
    writes nothing) when this version has no whats-new/<Version>.json, or the folder fails Invardia's conformance check
    (tools/whatsnew/ConvertTo-WhatsNewMarkdown.ps1 -Check). The files are copied byte for byte; SHA256SUMS.txt is computed
    from the copies ("<sha256>  <file>", LF). Only <version>.json files and SHA256SUMS.txt are written -- the shape
    Invardia's import accepts. No module, no network.

.EXAMPLE
    pwsh -NoProfile -File tools\setup\New-PimWhatsNewHandover.ps1 -Version 3.1.23 -OutDir C:\ProgramData\Invardia\handover\whats-new\pim-manager\3.1.23
#>
[CmdletBinding()] param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$src = Join-Path $sol 'whats-new'
$conv = Join-Path $sol 'tools/whatsnew/ConvertTo-WhatsNewMarkdown.ps1'

if (-not (Test-Path -LiteralPath (Join-Path $src "$Version.json"))) { Write-Host "NOT built: whats-new/$Version.json is missing -- every release needs its What's new file." -ForegroundColor Red; exit 1 }
& ((Get-Process -Id $PID).Path) -NoProfile -File $conv -Folder $src -Check
if ($LASTEXITCODE) { Write-Host 'NOT built: the What''s new files do not pass the check (above).' -ForegroundColor Red; exit 1 }

$files = @(Get-ChildItem -LiteralPath $src -File -Filter '*.json' | Where-Object { $_.Name -match '^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]{1,30})?\.json$' } | Sort-Object Name)
$wnName = '^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]{1,30})?\.json$'
if (Test-Path -LiteralPath $OutDir) {
    # only ever clears an earlier What's new hand-over: a folder that holds anything else (a mistyped -OutDir) is refused
    $foreign = @(Get-ChildItem -LiteralPath $OutDir -Force | Where-Object { $_.PSIsContainer -or ($_.Name -ne 'SHA256SUMS.txt' -and $_.Name -notmatch $wnName) })
    if ($foreign.Count) { Write-Host "NOT built: $OutDir holds other files ($(@($foreign | Select-Object -First 3 | ForEach-Object Name) -join ', ')) -- not a What's new hand-over folder." -ForegroundColor Red; exit 1 }
    Get-ChildItem -LiteralPath $OutDir -File | Remove-Item -Force
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$lines = foreach ($f in $files) {
    $dest = Join-Path $OutDir $f.Name
    [IO.File]::WriteAllBytes($dest, [IO.File]::ReadAllBytes($f.FullName))
    '{0}  {1}' -f (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash.ToLowerInvariant(), $f.Name
}
$sums = Join-Path $OutDir 'SHA256SUMS.txt'
[IO.File]::WriteAllText($sums, ((@($lines) -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
Write-Host "What's new hand-over $Version`: $($files.Count) release file(s) + SHA256SUMS.txt -> $OutDir (SHA256SUMS.txt sha256 $((Get-FileHash -LiteralPath $sums -Algorithm SHA256).Hash.ToLowerInvariant()))"
exit 0
