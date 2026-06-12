#Requires -Version 5.1
<#
.SYNOPSIS
    Run the full PIM4EntraPS test suite. Prefers the Pester job (PIM.Tests.ps1);
    falls back to invoking the three functional suites directly if Pester is absent.
    Offline -- no live tenant required. Rerun anytime to re-validate every flow.
.EXAMPLE
    powershell -NoProfile -File tests\Run-AllPimTests.ps1
#>
[CmdletBinding()] param()
$here = $PSScriptRoot
$pester = Get-Module -ListAvailable Pester | Where-Object { $_.Version.Major -ge 5 } | Select-Object -First 1
if ($pester) {
    Import-Module Pester -MinimumVersion 5.0
    $r = Invoke-Pester -Path (Join-Path $here 'PIM.Tests.ps1') -PassThru -Output Detailed
    Write-Host ("`nPESTER RESULT: {0} passed, {1} failed, {2} skipped" -f $r.PassedCount, $r.FailedCount, $r.SkippedCount) -ForegroundColor $(if ($r.FailedCount) {'Red'} else {'Green'})
    if ($r.FailedCount) { exit 1 }
    return
}
Write-Host "Pester 5+ not found -- running the functional suites directly." -ForegroundColor Yellow
$failed = 0
foreach ($s in 'Test-PimFeatures.ps1','Test-PimManagerEndpoints.ps1','Test-PimScenarios.ps1') {
    Write-Host "`n############ $s ############" -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here $s)
    if ($LASTEXITCODE -ne 0) { $failed++ }
}
if ($failed) { Write-Host " $failed suite(s) FAILED" -ForegroundColor Red; exit 1 } else { Write-Host " ALL SUITES GREEN" -ForegroundColor Green }
