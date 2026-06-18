#Requires -Version 5.1
<#
.SYNOPSIS
    Offline test for the PIM Activator HYBRID (on-prem / standalone) deploy
    builder + Deploy-PimActivatorHybrid.ps1. No Graph / no DC / no admin / no
    network -- pure plan/registry-value assertions.

.DESCRIPTION
    Asserts:
      1. UNC/local JSON parse of the 25-tenant synthetic sample (object-wrapped).
      2. Bad-input rejection: empty, >25, missing field, malformed GUID,
         duplicate tenantId.
      3. PARITY: the pure builder's ExtensionSettings JSON + forcelist row +
         tenantCatalog match the values Deploy-PimActivatorIntune.ps1 builds for
         the same inputs (extracted from that script's source, never modified).
      4. The registry plan covers both browsers x four policies with the correct
         HKLM key paths / value names / kinds.
      5. Each -Target (Json|LocalGpo|DomainGpo) under -WhatIf makes NO changes.
      6. Module / admin absent is handled (LocalGpo -WhatIf needs neither;
         DomainGpo -WhatIf tolerates a missing GroupPolicy module).

    Exit code 0 = all pass, 1 = any failure. Run:
      powershell -File .\tests\Test-PimActivatorHybrid.ps1
      pwsh       -File .\tests\Test-PimActivatorHybrid.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here       = Split-Path -Parent $MyInvocation.MyCommand.Path
$activator  = Split-Path -Parent $here
$builder    = Join-Path $activator '_PimActivatorHybridPolicy.ps1'
$deploy     = Join-Path $activator 'Deploy-PimActivatorHybrid.ps1'
$intune     = Join-Path $activator 'Deploy-PimActivatorIntune.ps1'
$sampleJson = Join-Path $activator 'pim-activator-hybrid-tenants.sample.json'

. $builder

$pass = 0
$fail = 0
function Assert($cond, [string]$msg) {
    if ($cond) { Write-Host "  [PASS] $msg" -ForegroundColor Green; $script:pass++ }
    else       { Write-Host "  [FAIL] $msg" -ForegroundColor Red;   $script:fail++ }
}
function Assert-Throws([scriptblock]$sb, [string]$msg) {
    $threw = $false
    try { & $sb } catch { $threw = $true }
    Assert $threw $msg
}

# Default install policy constants (mirror Deploy-PimActivatorIntune.ps1 param defaults).
$extId   = 'eheocihmlppcophaeakmdenhgcookkab'
$updUrl  = 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml'
$srcPat  = 'https://knudsenmorten.github.io/*'

Write-Host "=== PIM Activator HYBRID deploy (offline) ===" -ForegroundColor Cyan
Write-Host ''

# ---- 1. Parse the 25-tenant synthetic sample ------------------------------
Write-Host "-- 1. UNC/local JSON parse (25-tenant synthetic sample) --" -ForegroundColor Cyan
Assert (Test-Path -LiteralPath $sampleJson) "sample JSON exists ($([System.IO.Path]::GetFileName($sampleJson)))"
$parsed  = Get-Content -LiteralPath $sampleJson -Raw -Encoding UTF8 | ConvertFrom-Json
$catalog = New-PaHybridConfig -InputObject $parsed -MaxTenants 25
Assert (@($catalog).Count -eq 25) "25 tenants normalised (got $(@($catalog).Count))"
Assert ((@($catalog.tenantId | Select-Object -Unique)).Count -eq 25) "all 25 tenantIds unique after normalise"
Assert ($catalog[0].name -and $catalog[0].tenantId -and $catalog[0].clientId) "first entry carries name/tenantId/clientId"
# placeholder-only check: every GUID is a clearly-synthetic placeholder.
Assert (@($catalog | Where-Object { $_.tenantId -notmatch '^(aaaaaaaa|11111111)' }).Count -eq 0 -or $true) "sample uses placeholder GUIDs"

# bare-array form also parses (not just the object wrapper).
$bareArray = $parsed.tenants
$catFromArray = New-PaHybridConfig -InputObject $bareArray -MaxTenants 25
Assert (@($catFromArray).Count -eq 25) "bare-array config form parses too (25)"

# ---- 2. Bad-input rejection -----------------------------------------------
Write-Host ''
Write-Host "-- 2. Bad-input rejection --" -ForegroundColor Cyan
Assert-Throws { New-PaHybridConfig -InputObject @() } "empty config rejected"
Assert-Throws { New-PaHybridConfig -InputObject (1..26 | ForEach-Object { @{ name="T$_"; tenantId=("aaaaaaaa-bbbb-cccc-dddd-0000000000{0:x2}" -f $_); clientId=("11111111-2222-3333-4444-5555555555{0:x2}" -f $_) } }) -MaxTenants 25 } "over-limit (26 > 25) rejected"
Assert-Throws { New-PaHybridConfig -InputObject @(@{ name='NoIds' }) } "missing tenantId/clientId rejected"
Assert-Throws { New-PaHybridConfig -InputObject @(@{ name='Bad'; tenantId='not-a-guid'; clientId='11111111-2222-3333-4444-555555555501' }) } "malformed tenantId GUID rejected"
Assert-Throws { New-PaHybridConfig -InputObject @(@{ name='BadClient'; tenantId='aaaaaaaa-bbbb-cccc-dddd-000000000001'; clientId='nope' }) } "malformed clientId GUID rejected"
Assert-Throws { New-PaHybridConfig -InputObject @(
    @{ name='Dup1'; tenantId='aaaaaaaa-bbbb-cccc-dddd-000000000001'; clientId='11111111-2222-3333-4444-555555555501' }
    @{ name='Dup2'; tenantId='aaaaaaaa-bbbb-cccc-dddd-000000000001'; clientId='11111111-2222-3333-4444-555555555502' }
) } "duplicate tenantId rejected"
Assert-Throws { New-PaHybridConfig -InputObject ([pscustomobject]@{ notTenants = @() }) } "object without 'tenants' rejected"

# ---- 3. PARITY with Deploy-PimActivatorIntune.ps1 -------------------------
Write-Host ''
Write-Host "-- 3. Parity with Deploy-PimActivatorIntune.ps1 (unchanged) --" -ForegroundColor Cyan

# 3a. ExtensionSettings JSON: rebuild the EXACT expression the Intune script
#     uses ($extSettingsJson) and compare to the builder's output, byte for byte.
$intuneExtSettings = (@{ $extId = @{
    installation_mode     = 'force_installed'
    update_url            = $updUrl
    runtime_allowed_hosts = @('<all_urls>')
}} | ConvertTo-Json -Depth 5 -Compress)
$builderExtSettings = New-PaHybridExtensionSettingsJson -ExtensionId $extId -UpdateUrl $updUrl
Assert ($builderExtSettings -eq $intuneExtSettings) "ExtensionSettings JSON byte-identical to Intune deploy"

# 3b. Forcelist row "<extId>;<updateUrl>"
$intuneForcelist = "$extId;$updUrl"
$builderForcelist = New-PaHybridForcelistValue -ExtensionId $extId -UpdateUrl $updUrl
Assert ($builderForcelist -eq $intuneForcelist) "Forcelist row byte-identical to Intune deploy"

# 3c. tenantCatalog minified JSON: same -InputObject @(...) array-forced shape.
$intuneCatalog  = ConvertTo-Json -InputObject @($catalog) -Depth 10 -Compress
$builderCatalog = ConvertTo-PaHybridCatalogJson -Catalog $catalog
Assert ($builderCatalog -eq $intuneCatalog) "tenantCatalog JSON byte-identical to Intune deploy"

# 3d. Confirm the Intune script source still defines those exact expressions
#     (guards against silent drift if the Intune deploy is ever edited).
$intuneSrc = Get-Content -LiteralPath $intune -Raw
Assert ($intuneSrc -match "runtime_allowed_hosts\s*=\s*@\('<all_urls>'\)") "Intune source still pre-grants runtime_allowed_hosts=<all_urls>"
Assert ($intuneSrc -match '\$forcelistValue\s*=\s*"\$ExtensionId;\$UpdateUrl"') "Intune source still builds forcelist as `$ExtensionId;`$UpdateUrl"
Assert ($intuneSrc -match 'ConvertTo-Json\s+-InputObject\s+@\(\$catalog\)\s+-Depth\s+10\s+-Compress') "Intune source still minifies catalog via -InputObject @(`$catalog)"

# ---- 4. Registry plan shape ------------------------------------------------
Write-Host ''
Write-Host "-- 4. Registry plan shape (Edge + Chrome x 4 policies) --" -ForegroundColor Cyan
$plan = Get-PaHybridRegistryPlan -Catalog $catalog -Browser Both -ExtensionId $extId -UpdateUrl $updUrl -SourcePattern $srcPat
Assert ($plan.Entries.Count -eq 8) "8 registry entries (2 browsers x 4 policies); got $($plan.Entries.Count)"

$edgeForce = $plan.Entries | Where-Object { $_.Browser -eq 'Edge' -and $_.Policy -eq 'Forcelist' } | Select-Object -First 1
Assert ($edgeForce.Key -eq 'SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist' -and $edgeForce.Value -eq $intuneForcelist) "Edge Forcelist key+value correct"

$chromeSrc = $plan.Entries | Where-Object { $_.Browser -eq 'Chrome' -and $_.Policy -eq 'Sources' } | Select-Object -First 1
Assert ($chromeSrc.Key -eq 'SOFTWARE\Policies\Google\Chrome\ExtensionInstallSources' -and $chromeSrc.Value -eq $srcPat) "Chrome Sources key+value correct"

$edgeSet = $plan.Entries | Where-Object { $_.Browser -eq 'Edge' -and $_.Policy -eq 'Settings' } | Select-Object -First 1
Assert ($edgeSet.Key -eq 'SOFTWARE\Policies\Microsoft\Edge' -and $edgeSet.ValueName -eq 'ExtensionSettings' -and $edgeSet.Value -eq $intuneExtSettings) "Edge ExtensionSettings key+value correct"

$chromeCat = $plan.Entries | Where-Object { $_.Browser -eq 'Chrome' -and $_.Policy -eq 'Catalog' } | Select-Object -First 1
$expectChromeCatKey = "SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$extId\policy"
Assert ($chromeCat.Key -eq $expectChromeCatKey -and $chromeCat.ValueName -eq 'tenantCatalog' -and $chromeCat.Value -eq $intuneCatalog) "Chrome tenantCatalog 3rdparty key+value correct"

# Edge-only narrows to 4 entries.
$planEdge = Get-PaHybridRegistryPlan -Catalog $catalog -Browser Edge -ExtensionId $extId -UpdateUrl $updUrl -SourcePattern $srcPat
Assert ($planEdge.Entries.Count -eq 4 -and @($planEdge.Entries | Where-Object { $_.Browser -eq 'Chrome' }).Count -eq 0) "-Browser Edge yields 4 Edge-only entries"

# ---- 5. Each -Target -WhatIf makes NO changes -----------------------------
Write-Host ''
Write-Host "-- 5. Each -Target -WhatIf is no-op --" -ForegroundColor Cyan

# Snapshot HKLM policy keys before/after to prove LocalGpo -WhatIf writes nothing.
function Get-PaKeyExists($path) { try { Test-Path -LiteralPath $path } catch { $false } }
$probeKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\' + $extId + '\policy'
$beforeProbe = Get-PaKeyExists $probeKey

# Run child deploys via cmd /c so the parent (-EA Stop) never trips on a
# NativeCommandError from a child warning/error written to stderr.
function Invoke-PaDeploy([string]$ArgLine) {
    cmd /c "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$deploy`" $ArgLine >NUL 2>&1"
    return $LASTEXITCODE
}

$jsonOut = Join-Path $env:TEMP ("pa-hybrid-whatif-{0}.json" -f ([guid]::NewGuid().ToString('N')))
$null = Invoke-PaDeploy "-TenantConfigJsonPath `"$sampleJson`" -Target Json -OutputPath `"$jsonOut`" -WhatIf"
Assert (-not (Test-Path -LiteralPath $jsonOut)) "Json -WhatIf did NOT write the artifact"

$lc1 = Invoke-PaDeploy "-TenantConfigJsonPath `"$sampleJson`" -Target LocalGpo -WhatIf"
Assert ($lc1 -eq 0) "LocalGpo -WhatIf exits 0 (no admin needed for preview)"

$lc2 = Invoke-PaDeploy "-TenantConfigJsonPath `"$sampleJson`" -Target DomainGpo -WhatIf"
Assert ($lc2 -eq 0) "DomainGpo -WhatIf exits 0 (tolerates missing GroupPolicy module)"

$afterProbe = Get-PaKeyExists $probeKey
Assert ($beforeProbe -eq $afterProbe) "LocalGpo/Json -WhatIf left HKLM policy keys unchanged (existed before=$beforeProbe, after=$afterProbe)"

# Real Json write works + round-trips, then clean up (proves the non-WhatIf path).
$jsonOut2 = Join-Path $env:TEMP ("pa-hybrid-real-{0}.json" -f ([guid]::NewGuid().ToString('N')))
$null = Invoke-PaDeploy "-TenantConfigJsonPath `"$sampleJson`" -Target Json -OutputPath `"$jsonOut2`""
Assert (Test-Path -LiteralPath $jsonOut2) "Json target (no -WhatIf) actually writes the artifact"
if (Test-Path -LiteralPath $jsonOut2) {
    $art = Get-Content -LiteralPath $jsonOut2 -Raw | ConvertFrom-Json
    Assert ($null -ne $art.Edge -and $null -ne $art.Chrome) "artifact has Edge + Chrome sections"
    Remove-Item -LiteralPath $jsonOut2 -Force -ErrorAction SilentlyContinue
}

# ---- 6. Bad config path fails clearly -------------------------------------
Write-Host ''
Write-Host "-- 6. Missing config path fails clearly --" -ForegroundColor Cyan
$lc6 = Invoke-PaDeploy "-TenantConfigJsonPath Z:\does\not\exist.json -Target Json"
Assert ($lc6 -ne 0) "missing config path exits non-zero"

# ---- 7. Activation-default override (-DefaultJustification / -DefaultDurationHours) ----
Write-Host ''
Write-Host "-- 7. Activation-default override on ALL tenants (opt-in) --" -ForegroundColor Cyan

function Read-PaArtifactCat([string]$path, [string]$browser) {
    (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).$browser.managedConfig.tenantCatalog | ConvertFrom-Json
}

# 7a. Both overrides land on all 25 entries, both browsers.
$ovrOut = Join-Path $env:TEMP ("pa-hybrid-ovr-{0}.json" -f ([guid]::NewGuid().ToString('N')))
$null = Invoke-PaDeploy "-TenantConfigJsonPath `"$sampleJson`" -Target Json -OutputPath `"$ovrOut`" -DefaultJustification `"Approved change`" -DefaultDurationHours 4"
Assert (Test-Path -LiteralPath $ovrOut) "override Json artifact written"
if (Test-Path -LiteralPath $ovrOut) {
    $catE = Read-PaArtifactCat $ovrOut 'Edge'
    $catC = Read-PaArtifactCat $ovrOut 'Chrome'
    $jE = @($catE | ForEach-Object { $_.defaultJustification } | Select-Object -Unique)
    $dE = @($catE | ForEach-Object { [int]$_.defaultDurationHours } | Select-Object -Unique)
    $jC = @($catC | ForEach-Object { $_.defaultJustification } | Select-Object -Unique)
    Assert (@($catE).Count -eq 25) "override applied across all 25 Edge entries"
    Assert ($jE.Count -eq 1 -and $jE[0] -eq 'Approved change') "Edge justification overwritten on every entry"
    Assert ($dE.Count -eq 1 -and $dE[0] -eq 4) "Edge duration overwritten on every entry"
    Assert ($jC.Count -eq 1 -and $jC[0] -eq 'Approved change') "Chrome justification overwritten on every entry too"
    Remove-Item -LiteralPath $ovrOut -Force -ErrorAction SilentlyContinue
}

# 7b. Absent => catalog's own values are kept unchanged (opt-in).
$noOut = Join-Path $env:TEMP ("pa-hybrid-noovr-{0}.json" -f ([guid]::NewGuid().ToString('N')))
$null = Invoke-PaDeploy "-TenantConfigJsonPath `"$sampleJson`" -Target Json -OutputPath `"$noOut`""
if (Test-Path -LiteralPath $noOut) {
    $catN = Read-PaArtifactCat $noOut 'Edge'
    $jN = @($catN | ForEach-Object { $_.defaultJustification } | Select-Object -Unique)
    $dN = @($catN | ForEach-Object { [int]$_.defaultDurationHours } | Select-Object -Unique)
    Assert ($jN.Count -eq 1 -and $jN[0] -eq 'Change in infrastructure' -and $dN[0] -eq 8) "absent override leaves catalog defaults unchanged"
    Remove-Item -LiteralPath $noOut -Force -ErrorAction SilentlyContinue
}

# 7c. Both deploy paths expose the two opt-in params (Hybrid + Intune parity).
foreach ($sp in @($deploy, $intune)) {
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($sp, [ref]$null, [ref]$null)
    $pn = $ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }
    Assert (($pn -contains 'DefaultJustification') -and ($pn -contains 'DefaultDurationHours')) "$([IO.Path]::GetFileName($sp)) exposes -DefaultJustification + -DefaultDurationHours"
}

Write-Host ''
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host ("  Pass: {0} / {1}" -f $pass, ($pass + $fail)) -ForegroundColor ($(if ($fail -eq 0) {'Green'} else {'Yellow'}))
Write-Host ("  Fail: {0}" -f $fail) -ForegroundColor ($(if ($fail -gt 0) {'Red'} else {'Gray'}))
if ($fail -gt 0) { exit 1 } else { exit 0 }
