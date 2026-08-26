#Requires -Version 5.1
<#
  HOST-1 (framework) for PIM4EntraPS -- PIM RUNS ON WINDOWS POWERSHELL 5.1, so its shipped code
  must PARSE AND LOAD on 5.1. Operator directive 2026-08-19: "it must run on ps 5.1".

  🔴 WHY THIS SUITE EXISTS, AND WHY IT MUST RUN UNDER 5.1 ITSELF.
  Framework HOST-1 (raised by SecurityInsight 2026-08-18) records that a suite running on a
  different host from the product cannot see host-sensitive defects -- it let a targeted SI fix
  pass 8 dedicated tests and a green gate while being completely inert in production for six days.
  It also makes the point this file is built on: `#Requires -Version 5.1` declares a MINIMUM and is
  satisfied by pwsh 7, so marking a file 5.1 does NOT prove anything runs there. Only executing on
  5.1 does.

  🪤 THE DEFECT THIS CAUGHT ON ITS FIRST RUN, and it had been shipping.
  FOUR shipped setup scripts carried `#Requires -Version 7` -- including
  tools/setup/Test-PimTenantReady.ps1, the readiness probe THE FRAMEWORK RUNS AFTER EVERY DEPLOY.
  On a customer host where powershell.exe (5.1) is the default they would be refused at line 1 with
  ScriptRequiresUnmatchedPSVersion -- the exact production analogue of TEST-28. None of the four
  needed PS7 at all: all parse and load on 5.1 unchanged.

  🪤 AND THE REASON THE REQUIREMENT LOOKED GENUINE WAS WRONG.
  TEST-28 recorded that tests/Test-PimDeployDescriptor.ps1 "uses PS7-only PARSER syntax (the
  ternary)". It does not -- it contains ZERO ternaries. It is UTF-8 with NO BOM, and Windows
  PowerShell 5.1 reads a BOM-less file as ANSI, mangling the emoji inside its strings until the
  parse breaks ("Missing closing ')'"). Adding a BOM makes it parse and pass on 5.1 unchanged. The
  earlier verification reached the wrong conclusion because the scratch copy it tested was written
  by pwsh 7, whose -Encoding UTF8 omits the BOM -- so the probe reproduced the ENCODING fault and
  it was read as a SYNTAX fault.

  So: encoding, not syntax. Which is why this suite asserts the property that actually matters --
  DOES IT PARSE ON 5.1 -- rather than trusting any declaration.
#>
param()
$ErrorActionPreference = 'Stop'

$here    = $PSScriptRoot
$solRoot = Split-Path -Parent $here

$script:pass = 0; $script:fail = 0
function T { param([string]$Name, [bool]$Cond, [string]$Detail = '')
    if ($Cond) { $script:pass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name$(if ($Detail) { " -- $Detail" })" -ForegroundColor Red } }

Write-Host "`n== 0. THIS SUITE IS ACTUALLY RUNNING ON 5.1 ==" -ForegroundColor Cyan
# Without this the whole file is theatre: every assertion below would be evaluated by whatever host
# happened to launch it, which is precisely the HOST-1 defect. TEST-28's runner routes a suite by
# its own #requires, so declaring 5.1 is what puts this file on powershell.exe.
T ("the host is Windows PowerShell 5.x (actual: $($PSVersionTable.PSVersion), $($PSVersionTable.PSEdition))") `
    ($PSVersionTable.PSVersion.Major -eq 5)

# The ONE deliberate exception: the container engine. Its image is
# mcr.microsoft.com/powershell and its ENTRYPOINT is pwsh, so PS7 is its real runtime and a
# ternary there is correct. Exempted BY PATH, with the reason, never by a blanket rule.
$ContainerOnly = @('engine\container\Start-PimEngineContainer.ps1')

Write-Host "`n== 1. EVERY SHIPPED .ps1 PARSES ON 5.1 ==" -ForegroundColor Cyan
$files = @(Get-ChildItem $solRoot -Recurse -Filter *.ps1 -File |
           Where-Object { $_.FullName -notlike '*\legacy\*' -and $_.FullName -notlike '*\node_modules\*' })
T "found a plausible number of scripts to check ($($files.Count))" ($files.Count -gt 100)

$broken = New-Object System.Collections.Generic.List[string]
$noBom  = 0
foreach ($f in $files) {
    $rel = $f.FullName.Substring($solRoot.Length).TrimStart('\')
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $nonAscii = $false
    foreach ($b in $bytes) { if ($b -gt 127) { $nonAscii = $true; break } }
    if ($nonAscii -and -not $hasBom) { $noBom++ }
    $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$e)
    if ($e.Count -and ($ContainerOnly -notcontains $rel)) { [void]$broken.Add("$rel ($($e.Count) error(s); bom=$hasBom)") }
}
T 'no shipped script fails to parse on 5.1' ($broken.Count -eq 0) ($broken -join ' | ')
Write-Host ("   ($noBom file(s) carry non-ASCII with no BOM -- latent, and only a problem when it breaks the parse above)") -ForegroundColor DarkGray

Write-Host "`n== 2. NOTHING DECLARES PS7 EXCEPT THE CONTAINER ENGINE ==" -ForegroundColor Cyan
# A gratuitous `#Requires -Version 7` is not cosmetic: on a 5.1 host the script is REFUSED AT LINE 1
# before a single line of it runs, and the refusal reads like a broken script rather than a wrong
# declaration. Four shipped setup scripts carried one, and none of them needed it.
$ps7 = New-Object System.Collections.Generic.List[string]
foreach ($f in $files) {
    $rel = $f.FullName.Substring($solRoot.Length).TrimStart('\')
    if ($ContainerOnly -contains $rel) { continue }
    $first = (Get-Content -LiteralPath $f.FullName -TotalCount 5) -join "`n"
    if ($first -match '(?im)^\s*#requires\s+-version\s+[6-9]') { [void]$ps7.Add($rel) }
}
T 'no shipped or test script requires PS6+ outside the container' ($ps7.Count -eq 0) ($ps7 -join ' | ')
T 'the container engine IS still declared PS7 (its ENTRYPOINT is pwsh -- do not "fix" this)' `
    ((Get-Content -LiteralPath (Join-Path $solRoot $ContainerOnly[0]) -TotalCount 1) -match '(?i)#requires\s+-version\s+7')

Write-Host "`n== 3. THE SETUP SCRIPTS THE FRAMEWORK INVOKES ACTUALLY LOAD HERE ==" -ForegroundColor Cyan
# Parsing is necessary and not sufficient: Get-Command honours #requires AND binds the param block,
# which is what the deploy catalog and the framework readiness gate really do to these files.
foreach ($rel in 'tools\setup\Test-PimTenantReady.ps1',
                 'tools\setup\Initialize-PimMailSender.ps1',
                 'tools\setup\New-PimEngineCertificate.ps1',
                 'tools\setup\Set-PimFeatureBaseline.ps1',
                 'tools\setup\Invoke-PimDeployAll.ps1',
                 'tools\setup\Setup-PimContainers.ps1',
                 'tools\setup\New-PimHostingPrerequisites.ps1',
                 'tools\setup\Build-PimManagerImage.ps1') {
    $p = Join-Path $solRoot $rel
    if (-not (Test-Path -LiteralPath $p)) { T "$rel exists" $false 'missing'; continue }
    $ok = $false; $why = ''
    try { $null = Get-Command $p -ErrorAction Stop; $ok = $true } catch { $why = $_.Exception.Message }
    T "loads on 5.1: $rel" $ok $why
}

Write-Host "`n== 4. THE READINESS PROBE IS THE ONE THAT MATTERED MOST ==" -ForegroundColor Cyan
# solution.deploy.json declares it, and the FRAMEWORK runs it after every deploy and fails the
# deploy non-zero on a not-ready verdict. A probe that cannot start on the host the framework runs
# it from is a gate that never runs -- and a skip is not a pass.
$probe = Join-Path $solRoot 'tools\setup\Test-PimTenantReady.ps1'
T 'the probe no longer demands PS7' ((Get-Content -LiteralPath $probe -TotalCount 1) -notmatch '(?i)#requires\s+-version\s+[6-9]')
$contract = Join-Path $solRoot 'solution.deploy.json'
T 'and it is still the probe the contract declares' ((Get-Content -LiteralPath $contract -Raw) -match 'Test-PimTenantReady\.ps1')

Write-Host ("`n==== host compatibility (HOST-1): {0} passed, {1} failed ====" -f $script:pass, $script:fail) `
    -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
exit 0
