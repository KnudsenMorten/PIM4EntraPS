#Requires -Version 5.1
<#
.SYNOPSIS
    Hand PIM Manager's UPLINK-SETUP closed lists over to Invardia: setup-catalog.json = { product, version, steps[],
    findings[], controls[] } (framework DOCS/REQUIREMENTS.md 8.7, PIM REQUIREMENTS 100.10).

.DESCRIPTION
    Invardia accepts a Kind=setup uplink report only with ids from the product's closed lists (data/setup/pim-manager.json);
    an unknown id rejects the WHOLE report. This script writes those lists from the ONE source PIM itself reports from
    (engine\_shared\PIM-UplinkSetup.ps1: the control list, the Get Started step ids, the findings), so the hand-over and the
    reports cannot drift. Invardia imports it with tools/import-setup-catalog.ts (ids are never removed there: one this
    hand-over drops is kept as retired). Entries:
        steps     { id, title, why, fix, docUrl?, required }
        findings  { id, title, why, fix, productDefect }
        controls  { id, title, why, fix, enum?, critical? }      critical defaults to true at Invardia
    The framework MINIMUM control ids are always in it (Invardia refuses a catalog without them). The file is checked
    first (ids lower-case a-z 0-9 . -, no duplicates, title / why / fix 1-600 characters, enum 1-10 distinct lower-case
    values) and NOTHING is written when a check fails.
    Writes into -OutDir:  setup-catalog.json, then (re)writes the folder's ONE SHA256SUMS.txt over every file in it
    (tools\setup\_PimHandoverSums.ps1 -- the same writer Build-PimSettingsDocs and Build-PimSecurityPack use).
    The release folder is C:\ProgramData\Invardia\handover\docs\pim-manager\<version>\ (the default). Tests use a temp dir.
    After Invardia has imported it, set PIM_UPLINK_SETUP_EXTENDED=1 on the tick job so the reports carry PIM's own ids.
    No PowerShell modules; reads and writes local files only.

.PARAMETER OutDir
    The folder to write to (created when missing). Default C:\ProgramData\Invardia\handover\docs\pim-manager\<VERSION>.

.EXAMPLE
    .\tools\setup\Build-PimSetupCatalog.ps1
.EXAMPLE
    .\tools\setup\Build-PimSetupCatalog.ps1 -OutDir $env:TEMP\handover-test
#>
[CmdletBinding()]
param([string]$OutDir)
$ErrorActionPreference = 'Stop'
$setup = $PSScriptRoot
$solution = Split-Path (Split-Path $setup -Parent) -Parent
$version = "$(Get-Content -Raw -LiteralPath (Join-Path $solution 'VERSION'))".Trim()
if (-not $OutDir) { $OutDir = Join-Path $env:ProgramData ("Invardia\handover\docs\pim-manager\" + $version) }
. (Join-Path $solution 'engine\_shared\PIM-UplinkSetup.ps1')
. (Join-Path $solution 'engine\_shared\PIM-GetStartedReminder.ps1')
. (Join-Path $setup '_PimHandoverSums.ps1')

function New-PimSetupCatalogDoc {
    # PURE. The catalog object from the one source.
    param([string]$Version)
    $steps = @(foreach ($s in $script:PimSetupSteps) {
        [ordered]@{ id = $s.id; title = $s.title; why = $s.why; fix = "Open PIM Manager > Get Started > $($s.title) and complete the step."; docUrl = (Get-PimGetStartedDocUrl -StepId $s.id); required = [bool]$s.required } })
    $findings = @(foreach ($f in $script:PimSetupFindings) {
        [ordered]@{ id = $f.id; title = $f.title; why = $f.why; fix = $f.fix; productDefect = [bool]$f.productDefect } })
    $controls = @(foreach ($c in @(Get-PimSetupControlCatalog -Extended)) {
        $o = [ordered]@{ id = $c.id; title = $c.title; why = $c.why; fix = $c.fix }
        if ($c.Contains('enum')) { $o['enum'] = @($c.enum) }
        if ($c.Contains('critical')) { $o['critical'] = [bool]$c.critical }
        $o })
    return [ordered]@{ product = 'pim-manager'; version = $Version; steps = $steps; findings = $findings; controls = $controls }
}

function Test-PimSetupCatalogDoc {
    # PURE. The problems (empty = fit to hand over) -- the same rules as Invardia's checkSetupCatalog.
    param([object]$Doc)
    $p = New-Object System.Collections.Generic.List[string]
    $keys = @{ steps = @('id', 'title', 'why', 'fix', 'docUrl', 'required', 'retired'); findings = @('id', 'title', 'why', 'fix', 'docUrl', 'productDefect', 'retired')
               controls = @('id', 'title', 'why', 'fix', 'docUrl', 'enum', 'critical', 'retired') }
    foreach ($k in @($Doc.Keys)) { if ("$k" -notin @('product', 'version', 'steps', 'findings', 'controls')) { $p.Add("unknown field '$k'") } }
    if ("$($Doc.product)" -ne 'pim-manager') { $p.Add('product is not pim-manager') }
    if (-not "$($Doc.version)".Trim()) { $p.Add('no version') }
    foreach ($list in 'steps', 'findings', 'controls') {
        $seen = @{}
        foreach ($x in @($Doc[$list])) {
            $id = "$($x.id)"
            if ($id -cnotmatch '^[a-z0-9][a-z0-9.-]{0,59}$') { $p.Add("${list}: bad id '$id'"); continue }
            if ($seen.ContainsKey($id)) { $p.Add("${list}: '$id' twice") }; $seen[$id] = $true
            foreach ($f in @($x.Keys)) { if ("$f" -notin $keys[$list]) { $p.Add("$list '$id': unknown field '$f'") } }
            foreach ($f in 'title', 'why', 'fix') { $v = "$($x[$f])"; if (-not $v.Trim() -or $v.Length -gt 600) { $p.Add("$list '$id': $f missing or longer than 600") } }
            if ($x.Contains('docUrl') -and "$($x.docUrl)" -notmatch '^https://[^\s"<>]{1,300}$') { $p.Add("$list '$id': docUrl must be an https link") }
            if ($list -eq 'steps' -and -not ($x['required'] -is [bool])) { $p.Add("steps '$id': required must be true / false") }
            if ($list -eq 'controls' -and $x.Contains('enum')) {
                $e = @($x.enum)
                if ($e.Count -lt 1 -or $e.Count -gt 10 -or @($e | Where-Object { "$_" -cnotmatch '^[a-z0-9][a-z0-9.-]{0,29}$' }).Count -or @($e | Select-Object -Unique).Count -ne $e.Count) { $p.Add("controls '$id': enum must be 1-10 distinct lower-case values") }
            }
        }
        if ($list -eq 'controls') { foreach ($m in 'updater-deployed', 'updater-schedule', 'update-ring', 'uplink-key', 'licence-valid', 'mail-sender', 'alert-recipients', 'identity-permissions', 'last-run-24h', 'backup-configured') { if (-not $seen.ContainsKey($m)) { $p.Add("controls: the framework minimum '$m' is missing") } } }
    }
    return $p.ToArray()
}

$doc = New-PimSetupCatalogDoc -Version $version
$problems = @(Test-PimSetupCatalogDoc -Doc $doc)
if ($problems.Count) { throw ("the setup catalog is not fit to hand over -- nothing was written:`n  " + ($problems -join "`n  ")) }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding $false
[IO.File]::WriteAllText((Join-Path $OutDir 'setup-catalog.json'), (($doc | ConvertTo-Json -Depth 8) + "`n"), $utf8)
$n = Write-PimHandoverSums -Dir $OutDir
Write-Host ("Setup catalog {0}: {1} steps, {2} findings, {3} controls -> {4} (SHA256SUMS.txt: {5} files)" -f $version, @($doc.steps).Count, @($doc.findings).Count, @($doc.controls).Count, $OutDir, $n) -ForegroundColor Green
[pscustomobject]@{ ok = $true; version = $version; outDir = $OutDir; steps = @($doc.steps).Count; findings = @($doc.findings).Count; controls = @($doc.controls).Count; summed = $n }
