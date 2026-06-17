#Requires -Version 5.1
<#
.SYNOPSIS
    Offline doc-image presence gate. Asserts that:
      1. EVERY markdown image reference in the PUBLIC docs (README.md,
         docs/FEATURES.md, docs/DESIGN.md) resolves to a real, NON-EMPTY file
         (path resolved relative to the referencing file).
      2. The key Manager surfaces (Home, navigation, Delegation Map, Review &
         Save, Settings, Role Lookup, Reports) each have at least one screenshot
         embedded somewhere in the public docs.
      3. Every PNG under docs/img is actually referenced by at least one doc
         (no orphan screenshots that silently rot).

    Catches the "screenshot in README but not in FEATURES/DESIGN", the broken /
    moved image path, and the empty-file cases -- in CI, before publish.

    No tenant, no DB, no browser. PS 5.1-safe.

        powershell -NoProfile -File .\tests\Test-PimDocImages.ps1
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$root    = Split-Path -Parent $PSScriptRoot          # SOLUTIONS/PIM4EntraPS
$imgDir  = Join-Path $root 'docs\img'

$fail = New-Object System.Collections.Generic.List[string]; $pass = 0
function A($cond, $name) { if ($cond) { $script:pass++; Write-Host "  [PASS] $name" -ForegroundColor Green } else { $script:fail.Add($name); Write-Host "  [FAIL] $name" -ForegroundColor Red } }

# Public docs we scan (paths relative to the solution root).
$publicDocs = @('README.md', 'docs\FEATURES.md', 'docs\DESIGN.md')

# Markdown inline-image syntax: ![alt](path)  -- ignore remote (http/https) and data: URIs.
$imgRegex = [regex]'!\[[^\]]*\]\(\s*([^)\s]+?)\s*(?:"[^"]*")?\s*\)'

# Collect (doc, rawPath, resolvedFullPath) for every local image reference.
$refs = New-Object System.Collections.Generic.List[object]
foreach ($rel in $publicDocs) {
    $docPath = Join-Path $root $rel
    if (-not (Test-Path -LiteralPath $docPath)) { $fail.Add("public doc missing: $rel"); continue }
    $body = Get-Content -LiteralPath $docPath -Raw
    $docDir = Split-Path -Parent $docPath
    foreach ($m in $imgRegex.Matches($body)) {
        $p = $m.Groups[1].Value
        if ($p -match '^[a-z][a-z0-9+.-]*://' -or $p -match '^data:') { continue }  # remote / data URI -- out of scope
        # Resolve relative to the referencing file (README -> docs/img/..., docs/*.md -> img/...).
        $full = [System.IO.Path]::GetFullPath((Join-Path $docDir $p))
        $refs.Add([pscustomobject]@{ Doc = $rel; Raw = $p; Full = $full })
    }
}

Write-Host "R: every local image reference resolves to a real, non-empty file" -ForegroundColor Cyan
A ($refs.Count -gt 0) ("found image references to validate ({0})" -f $refs.Count)
foreach ($r in $refs) {
    $exists  = Test-Path -LiteralPath $r.Full -PathType Leaf
    $nonZero = $exists -and ((Get-Item -LiteralPath $r.Full).Length -gt 0)
    A $nonZero ("{0} -> {1} resolves to a non-empty file" -f $r.Doc, $r.Raw)
}

Write-Host "S: key Manager surfaces each have at least one screenshot in the public docs" -ForegroundColor Cyan
# surface label -> the screenshot file that must be referenced by name somewhere.
$requiredSurfaces = [ordered]@{
    'Home / Overview' = 'manager-home.png'
    'Navigation'      = 'manager-nav.png'
    'Delegation Map'  = 'manager-delegation-map.png'
    'Review & Save'   = 'manager-review-save.png'
    'Settings'        = 'manager-settings.png'
    'Role Lookup'     = 'manager-role-lookup.png'
    'Reports'         = 'manager-reports.png'
}
# Set of referenced basenames (case-insensitive) across all public docs.
$referencedNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($r in $refs) { [void]$referencedNames.Add((Split-Path -Leaf $r.Full)) }
foreach ($k in $requiredSurfaces.Keys) {
    $png = $requiredSurfaces[$k]
    A ($referencedNames.Contains($png)) ("surface '{0}' has a screenshot ({1}) referenced" -f $k, $png)
    # And the file itself exists + is non-empty on disk.
    $onDisk = Join-Path $imgDir $png
    A ((Test-Path -LiteralPath $onDisk -PathType Leaf) -and ((Get-Item -LiteralPath $onDisk -ErrorAction SilentlyContinue).Length -gt 0)) ("surface '{0}' screenshot file present + non-empty ({1})" -f $k, $png)
}

Write-Host "O: no orphan PNGs under docs/img (every screenshot is referenced)" -ForegroundColor Cyan
if (Test-Path -LiteralPath $imgDir) {
    $onDiskPngs = @(Get-ChildItem -LiteralPath $imgDir -Filter '*.png' -File -ErrorAction SilentlyContinue)
    foreach ($f in $onDiskPngs) {
        A ($referencedNames.Contains($f.Name)) ("docs/img/{0} is referenced by at least one public doc" -f $f.Name)
    }
} else {
    $fail.Add('docs/img directory missing')
}

Write-Host ('=' * 70)
if ($fail.Count -eq 0) { Write-Host ("ALL {0} ASSERTIONS PASSED." -f $pass) -ForegroundColor Green; exit 0 }
else { Write-Host ("{0} passed, {1} FAILED:" -f $pass, $fail.Count) -ForegroundColor Red; $fail | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
