#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-23 -- the MSP fan-out must hand the caller's ambient identity back exactly as it
    found it, so work that FOLLOWS a fan-out cannot run against the wrong customer.

    What happened: Invoke-PimMspFanout.ps1 repoints $global:PIM_TenantId / _ClientId /
    _CertThumbprint at each customer tenant in turn -- it has to, that is the fan-out --
    and then simply ended. Whatever ran next in the same process inherited the LAST
    tenant the loop happened to touch.

    Observed live 2026-08-06 in the TEST-12 S6 scenario: the managed downlink fanned out
    (local slave, then central slave) and the engine apply that followed authenticated as
    the CENTRAL tenant's SPN and reconciled THAT tenant's estate -- for a run whose target
    was the local slave. The verifier caught it because all six managed groups were
    missing from the tenant that was supposedly just reconciled. That pass was
    read-shaped; a write-shaped one is a cross-tenant write into a customer directory.

    Related to BUG-22 (the token cache was keyed by audience alone) but independent: BUG-22
    handed the wrong TOKEN to the right context; this hands the right token to the wrong
    CONTEXT. Both had to be fixed before S6 could be trusted at all.

    These assertions are STRUCTURAL, and deliberately so: the fan-out's body needs a live
    registry, real per-tenant certificates and Graph, so the loop itself cannot run
    offline. What CAN be pinned offline is the contract -- capture before, restore in a
    finally (so a throw restores too), covering every global the loop writes. The
    behavioural proof is the live S6 scenario going VERIFIED.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
$fanout  = Join-Path $solRoot 'setup\Invoke-PimMspFanout.ps1'

Write-Host "=== BUG-23: the MSP fan-out restores the ambient identity ===" -ForegroundColor Cyan

Assert "the fan-out script exists" (Test-Path -LiteralPath $fanout)
$src  = Get-Content -LiteralPath $fanout -Raw
$code = ($src -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

# It must still be parseable -- a try/finally added around a long loop is exactly the kind
# of edit that unbalances braces.
$perr = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$perr)
Assert "it parses cleanly" (-not $perr -or @($perr).Count -eq 0)

Write-Host "`n-- the contract --" -ForegroundColor Yellow
# Every global the loop repoints must be captured up front...
foreach ($g in @('PIM_TenantId', 'PIM_ClientId', 'PIM_CertThumbprint', 'PIM_UseManagedIdentity', 'PIM_Interactive')) {
    Assert "captures the previous value of $g" ($code -match ("\`$__prev\w+\s*=\s*\`$global:$g"))
}
# ...and restored.
Assert "there is a finally block"                    ($code -match '(?ms)^\s*finally\s*\{')
$fin = [regex]::Match($code, '(?ms)^\s*finally\s*\{.*?^\}').Value
foreach ($g in @('PIM_TenantId', 'PIM_ClientId', 'PIM_CertThumbprint', 'PIM_UseManagedIdentity', 'PIM_Interactive')) {
    Assert "restores $g in finally" ($fin -match ("\`$global:$g\s*=\s*\`$__prev"))
}

Write-Host "`n-- restore must be on the FAILURE path too --" -ForegroundColor Yellow
# A restore placed after the loop (not in a finally) would leave a THROWN fan-out pointing
# at a customer tenant -- the worse half of the bug.
$iTry = $code.IndexOf('try {')
$iForeach = $code.IndexOf('foreach ($grp in $byTenant)')
Assert "the tenant loop is INSIDE the try" ($iTry -ge 0 -and $iForeach -gt $iTry)

Write-Host "`n-- the capture happens before the loop --" -ForegroundColor Yellow
$iCapture = $code.IndexOf('$__prevTenantId')
Assert "identity is captured before the loop starts" ($iCapture -ge 0 -and $iCapture -lt $iForeach)

Write-Host "`n=== $pass passed / $fail failed ===" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
