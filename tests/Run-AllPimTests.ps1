#Requires -Version 5.1
<#
.SYNOPSIS
    Run the full PIM4EntraPS rerunnable test suite (engine + Manager + scenarios).
.DESCRIPTION
    Invokes each suite in its own child powershell.exe (clean assembly state per
    run) and aggregates the result. Offline -- no live tenant required.
      * Test-PimFeatures.ps1        -- engine functions (40 assertions)
      * Test-PimManagerEndpoints.ps1-- Manager HTTP server + /api/* (14)
      * Test-PimScenarios.ps1       -- validator + lifecycle scenarios (14)
.EXAMPLE
    powershell -NoProfile -File tests\Run-AllPimTests.ps1
#>
[CmdletBinding()] param()
$here = $PSScriptRoot
$suites = 'Test-PimFeatures.ps1','Test-PimManagerEndpoints.ps1','Test-PimScenarios.ps1'
$failed = 0
foreach ($s in $suites) {
    Write-Host "`n############ $s ############" -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here $s)
    if ($LASTEXITCODE -ne 0) { $failed++ ; Write-Host "  >> $s FAILED" -ForegroundColor Red }
}
Write-Host "`n=====================================================" -ForegroundColor Cyan
if ($failed) { Write-Host " SUITE RESULT: $failed suite(s) FAILED" -ForegroundColor Red; exit 1 }
else { Write-Host " SUITE RESULT: ALL SUITES GREEN" -ForegroundColor Green }
