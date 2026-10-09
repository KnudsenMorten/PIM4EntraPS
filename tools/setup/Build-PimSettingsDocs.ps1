#Requires -Version 5.1
<#
.SYNOPSIS
    Hand the PIM Manager settings catalog over to Invardia for the per-setting documentation pages (framework section 12.9
    SETTING-INFO-1, owner 2026-10-09: "make more docs on invardia with more info").

.DESCRIPTION
    The settings catalog (tools\pim-manager\settings-catalog.json) is the ONE source of the "More info" panel next to
    every setting in PIM Manager and of the confirmation shown before a destructive or security-reducing setting is
    switched. Invardia renders the long version of the same text as one page per setting:
        https://invardia.com/docs/pim/settings/<key>/        (index: https://invardia.com/docs/pim/settings/)
    A setting tied to a product feature carries that feature's slug (`feature`); its page is the existing feature page
    https://invardia.com/products/pim-manager/features/<slug>/ built from the product-pages hand-over -- so NO separate
    features file is handed over here (Invardia, 2026-10-09).

    The script checks the catalog first (every entry has a key, a label and the seven info fields what / enabled /
    disabled / risk / requires / recommended / docUrl, docUrl = the page above, no duplicate key) and writes NOTHING when
    a check fails. It then writes into -OutDir:
        settings-catalog.json   the catalog, stamped with the PIM version it was built from
        SHA256SUMS.txt          its checksum
        README.txt              what the folder is, for Invardia
    The hand-over folder for a release is C:\ProgramData\Invardia\handover\docs\pim-manager\<version>\ (the same
    handover\docs\<product>\<version>\ pattern the other products use). Run it with every release that changes the
    catalog. Tests point -OutDir at a temporary folder.

    No PowerShell modules; reads and writes local files only.

.PARAMETER OutDir
    The folder to write to (created when missing).

.PARAMETER CatalogPath
    The catalog to hand over (default: tools\pim-manager\settings-catalog.json next to this script's folder).

.EXAMPLE
    .\tools\setup\Build-PimSettingsDocs.ps1 -OutDir C:\ProgramData\Invardia\handover\docs\pim-manager\2.4.538
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutDir,
    [string]$CatalogPath
)
$ErrorActionPreference = 'Stop'
$setup = $PSScriptRoot
$tools = Split-Path $setup -Parent
$solution = Split-Path $tools -Parent
if (-not $CatalogPath) { $CatalogPath = Join-Path $tools 'pim-manager\settings-catalog.json' }
$version = "$(Get-Content -Raw -LiteralPath (Join-Path $solution 'VERSION'))".Trim()

function Test-PimSettingsCatalogDoc {
    # PURE. The problems in a parsed catalog (empty = fit to hand over).
    param([object]$Doc)
    $problems = New-Object System.Collections.Generic.List[string]
    $entries = @($(if ($Doc -and $Doc.PSObject.Properties['settings']) { $Doc.settings } else { @() }))
    if (-not $entries.Count) { $problems.Add('the catalog has no settings'); return $problems.ToArray() }
    $seen = @{}
    foreach ($e in $entries) {
        $k = "$($e.key)".Trim()
        if (-not $k) { $problems.Add('an entry has no key'); continue }
        if ($seen.ContainsKey($k.ToLowerInvariant())) { $problems.Add("duplicate key: $k") }
        $seen[$k.ToLowerInvariant()] = $true
        if (-not "$($e.label)".Trim()) { $problems.Add("${k}: no label") }
        $info = $e.info
        foreach ($f in 'what', 'enabled', 'disabled', 'risk', 'requires', 'recommended', 'docUrl') {
            $v = if ($info -and $info.PSObject.Properties[$f]) { "$($info.$f)".Trim() } else { '' }
            if (-not $v) { $problems.Add("${k}: info.$f is missing") }
        }
        if ($info -and "$($info.docUrl)" -ne "https://invardia.com/docs/pim/settings/$k/") { $problems.Add("${k}: info.docUrl is not https://invardia.com/docs/pim/settings/$k/") }
    }
    return $problems.ToArray()
}

if (-not (Test-Path -LiteralPath $CatalogPath)) { throw "settings catalog not found: $CatalogPath" }
$raw = [IO.File]::ReadAllText($CatalogPath)
$doc = $raw | ConvertFrom-Json
$problems = @(Test-PimSettingsCatalogDoc -Doc $doc)
if ($problems.Count) { throw ("the settings catalog is not fit to hand over -- nothing was written:`n  " + ($problems -join "`n  ")) }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out = [ordered]@{ product = 'pim-manager'; version = $version; builtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
foreach ($p in $doc.PSObject.Properties) { if (-not $out.Contains($p.Name)) { $out[$p.Name] = $p.Value } }
$utf8 = New-Object System.Text.UTF8Encoding $false
$catOut = Join-Path $OutDir 'settings-catalog.json'
[IO.File]::WriteAllText($catOut, (($out | ConvertTo-Json -Depth 12) + "`n"), $utf8)

$sha = [System.Security.Cryptography.SHA256]::Create()
try { $hash = ([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($catOut)))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
[IO.File]::WriteAllText((Join-Path $OutDir 'SHA256SUMS.txt'), "$hash  settings-catalog.json`n", $utf8)

$n = @($doc.settings).Count
$readme = @"
PIM Manager $version -- settings documentation hand-over (framework 12.9 SETTING-INFO-1)

settings-catalog.json  $n settings. Each entry: key, label, where (menu path), route, type, default, feature (product
                       feature slug or empty), confirmOn / confirmOff (the GUI asks before the switch), and info:
                       what, enabled, disabled, risk (incl. how to reverse it), requires, recommended, docUrl.
Render one page per setting at info.docUrl = https://invardia.com/docs/pim/settings/<key>/ and an index at
https://invardia.com/docs/pim/settings/. A non-empty feature links https://invardia.com/products/pim-manager/features/<feature>/.
For value settings (type other than boolean) 'enabled' reads "When set" and 'disabled' "When blank or default".
The same text is shown in PIM Manager's More info panel, which ends with "Read more on invardia.com".
"@
[IO.File]::WriteAllText((Join-Path $OutDir 'README.txt'), $readme.Replace("`r`n", "`n"), $utf8)
Write-Host ("Settings catalog {0}: {1} settings -> {2}" -f $version, $n, $OutDir) -ForegroundColor Green
[pscustomobject]@{ ok = $true; version = $version; settings = $n; outDir = $OutDir; files = @('settings-catalog.json', 'SHA256SUMS.txt', 'README.txt') }
