#Requires -Version 5.1
<#
.SYNOPSIS
  Offline functional tests for sync-automateit -- the controlled container/VM auto-update
  decision core (engine/_shared/PIM-SyncAutomateIT.ps1) + scheduler wiring.

  Asserts the RISKY decisions without touching Azure:
    * semver parse + NUMERIC compare (2.4.218 > 2.4.99; v-prefix; pre-release < release)
    * update needed ONLY when a strictly-newer VALID version exists (never re-roll same tag,
      never act on an unparseable 'latest'); -PinnedTag = controlled explicit target
    * gate: -RequireGate blocks until the gate is open (scheduled / -Apply)
    * health verdict: healthy only on exit 0 + zero fails
    * rollback plan: roll back on a failed health check to the captured prior revision
    * SEPARATION (operator correction 2026-06-18): the scheduler exposes NO 'sync-automateit' /
      update job type or handler, and Register-PimSyncAutomateItHandler is gone -- the update is a
      standalone mechanism (Invoke-PimUpdate.ps1) run by VisualCron / Task Scheduler / the bootstrap
      post-sync hook, never triggered by the engine or the in-container scheduler.

  Rerunnable, no live tenant. Exits 0 green / 1 on any failure.
.EXAMPLE
  powershell -NoProfile -File tests\Test-PimSyncAutomateIT.ps1
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$sol  = Split-Path -Parent $here
. (Join-Path $sol 'engine\_shared\PIM-SyncAutomateIT.ps1')
. (Join-Path $sol 'engine\_shared\PIM-Scheduler.ps1')

$pass=0; $fail=0
function T($n,$cond){ if($cond){Write-Host "  PASS $n" -ForegroundColor Green;$script:pass++}else{Write-Host "  FAIL $n" -ForegroundColor Red;$script:fail++} }

Write-Host "=== sync-automateit decision core ===" -ForegroundColor Cyan

# ---- ConvertTo-PimSemVer --------------------------------------------------
$v = ConvertTo-PimSemVer -Tag '2.4.218'
T 'parse 2.4.218 -> 2/4/218 valid' ($v.valid -and $v.major -eq 2 -and $v.minor -eq 4 -and $v.patch -eq 218)
$v = ConvertTo-PimSemVer -Tag 'v1.1.7'
T 'parse v1.1.7 (v-prefix) -> 1/1/7' ($v.valid -and $v.major -eq 1 -and $v.minor -eq 1 -and $v.patch -eq 7)
$v = ConvertTo-PimSemVer -Tag '2.5.0-rc1'
T 'parse 2.5.0-rc1 -> pre=rc1' ($v.valid -and $v.pre -eq 'rc1' -and $v.patch -eq 0)
$v = ConvertTo-PimSemVer -Tag '2'
T 'parse 2 -> 2/0/0 (missing parts default 0)' ($v.valid -and $v.major -eq 2 -and $v.minor -eq 0)
T 'parse "" -> invalid'            (-not (ConvertTo-PimSemVer -Tag '').valid)
T 'parse "latest" -> invalid'      (-not (ConvertTo-PimSemVer -Tag 'latest').valid)
T 'parse "1.2.x" -> invalid'       (-not (ConvertTo-PimSemVer -Tag '1.2.x').valid)

# ---- Compare-PimSemVer (NUMERIC, not string) ------------------------------
T '2.4.218 > 2.4.99 (numeric, not string)'  ((Compare-PimSemVer -A (ConvertTo-PimSemVer '2.4.218') -B (ConvertTo-PimSemVer '2.4.99')) -gt 0)
T '1.1.7 == 1.1.7'                          ((Compare-PimSemVer -A (ConvertTo-PimSemVer '1.1.7')   -B (ConvertTo-PimSemVer '1.1.7'))  -eq 0)
T '1.0.0 < 2.0.0'                           ((Compare-PimSemVer -A (ConvertTo-PimSemVer '1.0.0')   -B (ConvertTo-PimSemVer '2.0.0'))  -lt 0)
T '2.5.0 > 2.5.0-rc1 (release beats pre)'   ((Compare-PimSemVer -A (ConvertTo-PimSemVer '2.5.0')   -B (ConvertTo-PimSemVer '2.5.0-rc1')) -gt 0)
T 'invalid sorts LOWEST'                    ((Compare-PimSemVer -A (ConvertTo-PimSemVer 'latest')  -B (ConvertTo-PimSemVer '0.0.1'))  -lt 0)

# ---- Test-PimSyncUpdateNeeded ---------------------------------------------
T 'update needed: 1.1.5 -> 1.1.7'           (Test-PimSyncUpdateNeeded -CurrentTag '1.1.5' -LatestTag '1.1.7')
T 'no update: already on latest'            (-not (Test-PimSyncUpdateNeeded -CurrentTag '1.1.7' -LatestTag '1.1.7'))
T 'no update: latest is OLDER'              (-not (Test-PimSyncUpdateNeeded -CurrentTag '1.1.7' -LatestTag '1.1.5'))
T 'no update: latest unparseable'           (-not (Test-PimSyncUpdateNeeded -CurrentTag '1.1.7' -LatestTag 'garbage'))
T 'pin newer than current -> update'        (Test-PimSyncUpdateNeeded -CurrentTag '1.1.5' -LatestTag '9.9.9' -PinnedTag '1.1.6')
T 'pin not newer than current -> no update' (-not (Test-PimSyncUpdateNeeded -CurrentTag '1.1.7' -LatestTag '9.9.9' -PinnedTag '1.1.6'))

# ---- Get-PimSyncDecision (gate) -------------------------------------------
$d = Get-PimSyncDecision -CurrentTag '1.1.7' -LatestTag '1.1.7'
T 'decision noop when up to date' ($d.action -eq 'noop')
$d = Get-PimSyncDecision -CurrentTag '1.1.5' -LatestTag '1.1.7' -RequireGate
T 'decision blocked when gate closed' ($d.action -eq 'blocked' -and $d.gated -and $d.targetTag -eq '1.1.7')
$d = Get-PimSyncDecision -CurrentTag '1.1.5' -LatestTag '1.1.7' -RequireGate -GateOpen
T 'decision update when gate open' ($d.action -eq 'update' -and $d.targetTag -eq '1.1.7')
$d = Get-PimSyncDecision -CurrentTag '1.1.5' -LatestTag '1.1.7' -PinnedTag '1.1.6' -RequireGate -GateOpen
T 'decision honours pin as target' ($d.action -eq 'update' -and $d.targetTag -eq '1.1.6')

# ---- Test-PimSyncHealthVerdict --------------------------------------------
T 'healthy: exit 0, 0 fail'          (Test-PimSyncHealthVerdict -ExitCode 0 -FailCount 0)
T 'unhealthy: nonzero exit'          (-not (Test-PimSyncHealthVerdict -ExitCode 1 -FailCount 0))
T 'unhealthy: fail count > 0'        (-not (Test-PimSyncHealthVerdict -ExitCode 0 -FailCount 2))

# ---- Get-PimSyncRollbackPlan ----------------------------------------------
$rb = Get-PimSyncRollbackPlan -Healthy $true -PreviousRevision 'ca-pim-manager--abc123'
T 'healthy -> no rollback' ($rb.action -eq 'none')
$rb = Get-PimSyncRollbackPlan -Healthy $false -PreviousRevision 'ca-pim-manager--abc123'
T 'unhealthy + prev revision -> rollback to it' ($rb.action -eq 'rollback' -and $rb.revision -eq 'ca-pim-manager--abc123')
$rb = Get-PimSyncRollbackPlan -Healthy $false -PreviousRevision ''
T 'unhealthy + no prev revision -> none (manual)' ($rb.action -eq 'none')

# ---- SEPARATION: the scheduler must NOT own / trigger the update ------------
# operator correction 2026-06-18: the update (code/SQL-schema/Manager-GUI roll) is a STANDALONE
# mechanism run by VisualCron / Task Scheduler / the bootstrap post-sync hook -- the engine + the
# in-container scheduler are for engine runs / slave data downlink only. These assertions LOCK that
# separation so a future change can't silently re-couple the update to the scheduler.
Write-Host "=== separation: update NOT a scheduler job ===" -ForegroundColor Cyan
$sched = @(Get-PimDefaultJobSchedule)
$syncJob = $sched | Where-Object { $_.type -eq 'sync-automateit' -or $_.type -eq 'update' } | Select-Object -First 1
T 'default schedule has NO sync-automateit/update job' ($null -eq $syncJob)
T "'sync-automateit' is NOT a registered job TYPE" (-not ($script:PimJobTypes -contains 'sync-automateit'))

Initialize-PimDefaultJobHandlers
T 'NO sync-automateit handler registered' ($null -eq (Get-PimJobHandler -Type 'sync-automateit'))
T 'Register-PimSyncAutomateItHandler removed (no scheduler->update seam)' ($null -eq (Get-Command Register-PimSyncAutomateItHandler -ErrorAction SilentlyContinue))
# dispatching the (now-unknown) update type must NOT act -- the scheduler has no handler for it.
$res = Invoke-PimScheduledJob -Job ([pscustomobject]@{ name='sync'; type='sync-automateit'; enabled=$true }) -NowUtc ([datetime]::UtcNow)
T 'unknown update job type does not run (no-handler-registered)' ($res.detail -match 'no-handler-registered')

# the STANDALONE update entry points still exist (they just are not scheduler-driven).
$orch    = Join-Path $sol 'tools\setup\Invoke-PimSyncAutomateIT.ps1'
$updEntry = Join-Path $sol 'tools\setup\Invoke-PimUpdate.ps1'
$vcron    = Join-Path $sol 'tools\setup\Register-PimSyncSchedule.ps1'
T 'standalone roll orchestrator exists (Invoke-PimSyncAutomateIT.ps1)' (Test-Path $orch)
T 'standalone update entry exists (Invoke-PimUpdate.ps1)' (Test-Path $updEntry)
T 'standalone VisualCron/Task-Scheduler registrar exists (Register-PimSyncSchedule.ps1)' (Test-Path $vcron)

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass,$fail) -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 } else { exit 0 }
