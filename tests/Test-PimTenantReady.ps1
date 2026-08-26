#Requires -Version 5.1
<#
  OFFLINE tests for PIM's readiness probe (tools/setup/Test-PimTenantReady.ps1) and for the
  `readiness` + `vaultIsolation` declarations in solution.deploy.json.

  What can and cannot be tested here, stated honestly: the probe's VERDICTS need a live tenant,
  so they are not asserted. What IS asserted offline is everything that would make the probe
  useless without anyone noticing:
    * it parses, and it is actually declared in the contract (a probe nobody runs is not a gate)
    * it honours the framework result shape -- verified by feeding its output through the REAL
      framework interpreter (sync/_AitReadiness.ps1) rather than a local imitation of it
    * it degrades to FAILED rather than crashing when nothing is reachable, which is the state it
      will be in on any machine that is not the target -- including this one
    * it is READ-ONLY
#>
param()
$ErrorActionPreference = 'Stop'

$sol  = Split-Path -Parent $PSScriptRoot
$repo = Split-Path -Parent (Split-Path -Parent $sol)
$probe = Join-Path $sol 'tools\setup\Test-PimTenantReady.ps1'

$script:pass = 0; $script:fail = 0
function T { param([string]$Name, [bool]$Cond, [string]$Detail = '')
    if ($Cond) { $script:pass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name$(if ($Detail) { " -- $Detail" })" -ForegroundColor Red } }

Write-Host "`n== 1. THE PROBE EXISTS AND IS DECLARED ==" -ForegroundColor Cyan
T 'the probe script exists' (Test-Path -LiteralPath $probe)
$errs = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($probe, [ref]$null, [ref]$errs)
T '  ...and parses clean' (@($errs).Count -eq 0) (($errs | Select-Object -First 1) -join '')

$contract = Get-Content (Join-Path $sol 'solution.deploy.json') -Raw | ConvertFrom-Json
T 'solution.deploy.json DECLARES a readiness probe (a probe nobody runs is not a gate)' ($null -ne $contract.readiness)
T '  ...pointing at this script' ("$($contract.readiness.script)" -eq 'tools/setup/Test-PimTenantReady.ps1')
T '  ...and the declared path actually resolves' (Test-Path -LiteralPath (Join-Path $sol ("$($contract.readiness.script)" -replace '/', '\')))
T '  ...marked REQUIRED, so a not-ready verdict blocks the deploy' ([bool]$contract.readiness.required)
T 'solution.deploy.json declares vaultIsolation dedicated-required' ("$($contract.vaultIsolation)" -eq 'dedicated-required')

Write-Host "`n== 2. IT HONOURS THE FRAMEWORK CONTRACT (checked with the REAL interpreter) ==" -ForegroundColor Cyan
# Run the probe with nothing reachable. On this machine every dependency is absent, which is
# precisely the "cannot evaluate" state -- and the contract says that must be reported as FAILED
# checks, not as a crash and not as a pass.
$raw = & $probe -TenantId '00000000-0000-0000-0000-000000000000' -SqlServerFqdn '' 2>&1
T 'the probe does not crash when nothing is reachable' ($true)

$framework = Join-Path $repo 'sync\_AitReadiness.ps1'
T 'the framework readiness interpreter is present' (Test-Path -LiteralPath $framework)
. $framework
$norm = ConvertFrom-AitReadinessResult -Result $raw
T 'the REAL framework interpreter can read the probe output' (-not $norm.Malformed) $norm.Reason
T '  ...and finds a non-empty check list' (@($norm.Checks).Count -ge 5)
T '  ...with every check carrying a name' ((@($norm.Checks | Where-Object { -not "$($_.Name)".Trim() })).Count -eq 0)

$verdict = Get-AitReadinessVerdict -Declared $true -Required $true -Ran $true -Result $norm
T '🔴 with nothing reachable the verdict is NOT READY (never a silent pass)' (-not $verdict.Ready)
T '  ...and each failure explains why it could not be evaluated' ((($verdict.Reasons -join ' ') -match 'could not evaluate|could not be read|no SQL connection'))

Write-Host "`n== 3. IT COVERS THE SIX MEASURED FAILURES ==" -ForegroundColor Cyan
# Guards against the probe quietly losing a check during a later refactor: each of these was a
# real, silent breakage on a live tenant (DEPLOY-2 §7 / §33 MSP-5).
$names = (@($norm.Checks | ForEach-Object { "$($_.Name)" }) -join ' | ').ToLowerInvariant()
T 'checks the store/schema (BUG-50: a 3-table store passed every health check)' ($names -match 'store|schema')
T 'checks the feature gates (IMP-07: a gate-skip logs ok=True)'                 ($names -match 'gate')
T 'checks the persisted sender (mail-mute environments send nothing, silently)' ($names -match 'sender persisted')
T 'checks the sender MAILBOX exists (separate failure from the setting)'        ($names -match 'mailbox')
T 'checks the tick job identity (IMP-08: a permissionless MI 403s on every scope)' ($names -match 'tick job')
T 'checks desired admins exist (control #1)'                                    ($names -match 'admin accounts exist')
T 'checks a requested TAP can actually be DELIVERED (IMP-14)'                   ($names -match 'tap')

Write-Host "`n== 4. READ-ONLY ==" -ForegroundColor Cyan
$src = [IO.File]::ReadAllText($probe)
$code = @(($src -split "`n") | Where-Object { "$_".Trim() -and -not "$_".TrimStart().StartsWith('#') })
$writes = @($code | Where-Object { $_ -match '(?i)-Method\s+(POST|PATCH|PUT|DELETE)|Set-PimSqlRow|Set-PimSqlSetting|Remove-PimSqlRow|Invoke-PimSqlNonQuery' })
T 'a readiness probe never writes (no POST/PATCH/PUT/DELETE, no store writes)' ($writes.Count -eq 0) ($writes -join ' | ')

Write-Host "`n==== PIM readiness probe: $($script:pass) passed, $($script:fail) failed ====" -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
exit 0
