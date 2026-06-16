#Requires -Version 5.1
<#
.SYNOPSIS
  Offline functional tests for the FULL update-lifecycle automation -- the pure decision core
  (engine/_shared/PIM-UpdateLifecycle.ps1) behind detect -> build -> deploy -> verify -> notify
  -> ensure-monitor. REQUIREMENTS.md sec.1/sec.2/sec.5/sec.20.

  Asserts every RISKY decision WITHOUT touching Azure/SQL/HTTP/git:
    * content hash: stable, order-independent, empty sentinel
    * GUI detect: changed hash / newer VERSION / unknown running hash => update; equal => no-op
    * SQL detect: column drift / missing table / newer schema version => upgrade; conformant => no-op
    * combined detection payload { SqlUpdateRequired; GuiUpdateRequired; details }
    * source profile: git-pull (local build/relaunch) vs sync-automateit (acr build/aca roll)
    * build plan: build only when GUI update needed; mode by source
    * apply plan: detect-only is a no-op (steps 2-6 skip); -Apply runs needed steps in order;
      verify+notify run when deployed; ensure-monitor runs when monitor not in place
    * verify verdict: healthy on exit 0 / rollback plan on failure
    * notify plan: subject/severity/tokens by outcome; noop => send=$false
    * ensure-monitor: ensure (missing) / refresh (stale) / noop (in place + fresh); 5-15m clamp

  Rerunnable, no live tenant. Exits 0 green / 1 on any failure.
.EXAMPLE
  powershell -NoProfile -File tests\Test-PimUpdateLifecycle.ps1
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$sol  = Split-Path -Parent $here
. (Join-Path $sol 'engine\_shared\PIM-SyncAutomateIT.ps1')
. (Join-Path $sol 'engine\_shared\PIM-SchemaConformance.ps1')
. (Join-Path $sol 'engine\_shared\PIM-UpdateLifecycle.ps1')

$pass=0; $fail=0
function T($n,$cond){ if($cond){Write-Host "  PASS $n" -ForegroundColor Green;$script:pass++}else{Write-Host "  FAIL $n" -ForegroundColor Red;$script:fail++} }

Write-Host "=== update-lifecycle decision core ===" -ForegroundColor Cyan

# ---- Get-PimContentHash ---------------------------------------------------
$a = Get-PimContentHash -FileDigests @(
    [pscustomobject]@{ path='pim-manager.html'; sha256='AAAA' },
    [pscustomobject]@{ path='Dockerfile';       sha256='BBBB' })
$b = Get-PimContentHash -FileDigests @(   # same set, different ENUMERATION order
    [pscustomobject]@{ path='Dockerfile';       sha256='BBBB' },
    [pscustomobject]@{ path='pim-manager.html'; sha256='AAAA' })
T 'content hash is order-independent' ($a -eq $b)
$c = Get-PimContentHash -FileDigests @(
    [pscustomobject]@{ path='pim-manager.html'; sha256='CHANGED' },
    [pscustomobject]@{ path='Dockerfile';       sha256='BBBB' })
T 'content hash changes when a file digest changes' ($a -ne $c)
T 'empty input => fixed sentinel (no collision with content)' ((Get-PimContentHash -FileDigests @()) -match '^EMPTY-' )

# ---- Get-PimGuiUpdatePlan -------------------------------------------------
$g = Get-PimGuiUpdatePlan -PulledContentHash 'abc' -RunningContentHash 'abc'
T 'GUI: equal content hash => no update' (-not $g.GuiUpdateRequired)
$g = Get-PimGuiUpdatePlan -PulledContentHash 'abc' -RunningContentHash 'xyz'
T 'GUI: changed content hash => update' ($g.GuiUpdateRequired)
$g = Get-PimGuiUpdatePlan -PulledContentHash 'abc' -RunningContentHash ''
T 'GUI: unknown running hash => update (cannot prove parity)' ($g.GuiUpdateRequired)
$g = Get-PimGuiUpdatePlan -PulledContentHash 'abc' -RunningContentHash 'abc' -PulledVersion '2.4.220' -RunningVersion '2.4.219'
T 'GUI: equal hash but newer VERSION => update' ($g.GuiUpdateRequired)
$g = Get-PimGuiUpdatePlan -PulledContentHash 'abc' -RunningContentHash 'abc' -PulledVersion '2.4.219' -RunningVersion '2.4.219'
T 'GUI: equal hash + equal version => no update' (-not $g.GuiUpdateRequired)

# ---- Get-PimSqlUpdatePlan -------------------------------------------------
$lockedSql = Get-PimLockedSqlSchema      # pim.LocalAdmins requires Purpose, deprecates TierLevel
# conformant: deployed has Purpose, no TierLevel
$dep = @{ 'pim.LocalAdmins' = @('UserName','DisplayName','Purpose','Owner') }
$s = Get-PimSqlUpdatePlan -DeployedColumns $dep -LockedSqlSchema $lockedSql
T 'SQL: conformant deployed columns => no upgrade' (-not $s.SqlUpdateRequired)
# drift: deployed still has the deprecated TierLevel + is missing Purpose
$dep = @{ 'pim.LocalAdmins' = @('UserName','DisplayName','TierLevel','Owner') }
$s = Get-PimSqlUpdatePlan -DeployedColumns $dep -LockedSqlSchema $lockedSql
T 'SQL: column drift (missing Purpose / has deprecated TierLevel) => upgrade' ($s.SqlUpdateRequired)
T 'SQL: drift plan reports the table non-conformant' (@($s.tables | Where-Object { $_.table -eq 'pim.LocalAdmins' -and -not $_.conformant }).Count -eq 1)
# missing table entirely
$s = Get-PimSqlUpdatePlan -DeployedColumns @{} -LockedSqlSchema $lockedSql
T 'SQL: table absent => upgrade (needs create)' ($s.SqlUpdateRequired -and $s.missingTables -contains 'pim.LocalAdmins')
# schema-version bump forces upgrade even when columns look clean
$dep = @{ 'pim.LocalAdmins' = @('UserName','DisplayName','Purpose','Owner') }
$s = Get-PimSqlUpdatePlan -DeployedColumns $dep -LockedSqlSchema $lockedSql -DeployedSchemaVersion '1.0.0' -PulledSchemaVersion '1.1.0'
T 'SQL: conformant cols but newer schema version => upgrade (data migration)' ($s.SqlUpdateRequired)
$s = Get-PimSqlUpdatePlan -DeployedColumns $dep -LockedSqlSchema $lockedSql -DeployedSchemaVersion '1.1.0' -PulledSchemaVersion '1.1.0'
T 'SQL: conformant cols + equal schema version => no upgrade' (-not $s.SqlUpdateRequired)

# ---- Get-PimUpdateDetection ----------------------------------------------
$guiYes = Get-PimGuiUpdatePlan -PulledContentHash 'a' -RunningContentHash 'b'
$guiNo  = Get-PimGuiUpdatePlan -PulledContentHash 'a' -RunningContentHash 'a'
$sqlNo  = Get-PimSqlUpdatePlan -DeployedColumns @{ 'pim.LocalAdmins'=@('UserName','DisplayName','Purpose','Owner') } -LockedSqlSchema $lockedSql
$d = Get-PimUpdateDetection -GuiPlan $guiYes -SqlPlan $sqlNo
T 'detection: GUI yes / SQL no => Gui=true Sql=false Any=true' ($d.GuiUpdateRequired -and -not $d.SqlUpdateRequired -and $d.AnyUpdateRequired)
T 'detection: details carries gui + sql sub-plans' ($null -ne $d.details.gui -and $null -ne $d.details.sql)
$d = Get-PimUpdateDetection -GuiPlan $guiNo -SqlPlan $sqlNo
T 'detection: both no => AnyUpdateRequired=false' (-not $d.AnyUpdateRequired)

# ---- Get-PimUpdateSourceProfile ------------------------------------------
$p = Get-PimUpdateSourceProfile -Source 'git-pull'
T 'source git-pull => local build / local relaunch / not hosted' ($p.buildMode -eq 'local-build' -and $p.deployMode -eq 'local-relaunch' -and -not $p.isHosted)
$p = Get-PimUpdateSourceProfile -Source 'sync-automateit'
T 'source sync-automateit => acr build / aca roll / hosted' ($p.buildMode -eq 'acr-build' -and $p.deployMode -eq 'aca-roll' -and $p.isHosted)

# ---- Get-PimBuildPlan -----------------------------------------------------
$bp = Get-PimBuildPlan -GuiUpdateRequired $true -Source 'sync-automateit' -ImageTag '2.4.220'
T 'build: GUI update + hosted => BuildRequired, acr-build' ($bp.BuildRequired -and $bp.buildMode -eq 'acr-build' -and $bp.imageTag -eq '2.4.220')
$bp = Get-PimBuildPlan -GuiUpdateRequired $false -Source 'sync-automateit' -ImageTag '2.4.220'
T 'build: no GUI update => BuildRequired=false (SQL-only needs no image)' (-not $bp.BuildRequired)
$bp = Get-PimBuildPlan -GuiUpdateRequired $true -Source 'git-pull' -ImageTag '2.4.220'
T 'build: GUI update + community => local-build' ($bp.BuildRequired -and $bp.buildMode -eq 'local-build')

# ---- Get-PimUpdateApplyPlan ----------------------------------------------
$detGuiSql = Get-PimUpdateDetection -GuiPlan $guiYes -SqlPlan (Get-PimSqlUpdatePlan -DeployedColumns @{ 'pim.LocalAdmins'=@('UserName','TierLevel') } -LockedSqlSchema $lockedSql)
$bpYes = Get-PimBuildPlan -GuiUpdateRequired $true -Source 'sync-automateit' -ImageTag '2.4.220'
# detect-only: every step 2-6 must skip; step 1 detect always runs.
$plan = Get-PimUpdateApplyPlan -Detection $detGuiSql -BuildPlan $bpYes -Source 'sync-automateit' -MonitorInPlace $false
T 'apply plan: detect-only => detectOnly=true' ($plan.detectOnly)
T 'apply plan: detect-only => step1 detect runs' ((($plan.steps | Where-Object { $_.name -eq 'detect' }).do))
T 'apply plan: detect-only => build/deploy/verify/notify/ensure-monitor all SKIP' `
    (-not (($plan.steps | Where-Object { $_.name -in @('build','deploy','verify','notify','ensure-monitor') -and $_.do }).Count))
# -Apply with GUI+SQL update + monitor missing: build, deploy, verify, notify, ensure-monitor all DO.
$plan = Get-PimUpdateApplyPlan -Detection $detGuiSql -BuildPlan $bpYes -Source 'sync-automateit' -Apply -MonitorInPlace $false
$names = @($plan.steps | Where-Object { $_.do } | ForEach-Object { $_.name })
T 'apply -Apply: order is detect,build,deploy,verify,notify,ensure-monitor (all do)' `
    (($names -join ',') -eq 'detect,build,deploy,verify,notify,ensure-monitor')
# -Apply, SQL-only (no GUI): build SKIPS, deploy/verify/notify still DO (schema applied).
$detSqlOnly = Get-PimUpdateDetection -GuiPlan $guiNo -SqlPlan (Get-PimSqlUpdatePlan -DeployedColumns @{ 'pim.LocalAdmins'=@('UserName','TierLevel') } -LockedSqlSchema $lockedSql)
$bpNo = Get-PimBuildPlan -GuiUpdateRequired $false -Source 'sync-automateit' -ImageTag '2.4.220'
$plan = Get-PimUpdateApplyPlan -Detection $detSqlOnly -BuildPlan $bpNo -Source 'sync-automateit' -Apply -MonitorInPlace $true
T 'apply -Apply SQL-only: build SKIPS' (-not (($plan.steps | Where-Object { $_.name -eq 'build' }).do))
T 'apply -Apply SQL-only: deploy DOES (schema upgrade)' (($plan.steps | Where-Object { $_.name -eq 'deploy' }).do)
T 'apply -Apply SQL-only + monitor in place: ensure-monitor SKIPS' (-not (($plan.steps | Where-Object { $_.name -eq 'ensure-monitor' }).do))
# -Apply, no update but monitor missing: only ensure-monitor DOES.
$detNone = Get-PimUpdateDetection -GuiPlan $guiNo -SqlPlan $sqlNo
$plan = Get-PimUpdateApplyPlan -Detection $detNone -BuildPlan $bpNo -Source 'sync-automateit' -Apply -MonitorInPlace $false
T 'apply -Apply no-update + monitor missing: ensure-monitor DOES' (($plan.steps | Where-Object { $_.name -eq 'ensure-monitor' }).do)
T 'apply -Apply no-update: build/deploy/verify/notify all SKIP' `
    (-not (($plan.steps | Where-Object { $_.name -in @('build','deploy','verify','notify') -and $_.do }).Count))

# ---- Get-PimVerifyVerdict (rollback-on-fail) -----------------------------
$v = Get-PimVerifyVerdict -ExitCode 0 -PreviousRevision 'rev-old'
T 'verify: exit 0 => healthy, no rollback' ($v.Healthy -and $v.rollback.action -eq 'none')
$v = Get-PimVerifyVerdict -ExitCode 1 -PreviousRevision 'rev-old'
T 'verify: exit 1 + prev revision => unhealthy, rollback to prev' ((-not $v.Healthy) -and $v.rollback.action -eq 'rollback' -and $v.rollback.revision -eq 'rev-old')
$v = Get-PimVerifyVerdict -ExitCode 1 -PreviousRevision ''
T 'verify: exit 1 + no prev revision => unhealthy, no rollback target' ((-not $v.Healthy) -and $v.rollback.action -eq 'none')

# ---- Get-PimNotifyPlan ----------------------------------------------------
$n = Get-PimNotifyPlan -Outcome 'success' -Source 'sync-automateit' -Detection $detGuiSql -Built $true -Deployed $true -SchemaUpgraded $true -ImageTag '2.4.220'
T 'notify success: send=true, severity info, type update-outcome' ($n.send -and $n.severity -eq 'info' -and $n.type -eq 'update-outcome')
T 'notify success: subject mentions OK' ($n.subject -match 'OK')
T 'notify success: WhatHappened token lists built+deployed+schema' ($n.tokens.WhatHappened -match 'built' -and $n.tokens.WhatHappened -match 'deployed' -and $n.tokens.WhatHappened -match 'schema')
T 'notify success: default recipient is the owner mailbox' ($n.recipient -eq 'mok@mortenknudsen.net')
$n = Get-PimNotifyPlan -Outcome 'failure' -Source 'git-pull' -Detection $detGuiSql -ErrorDetail 'boom'
T 'notify failure: severity critical, error token carried' ($n.severity -eq 'critical' -and $n.tokens.ErrorDetail -eq 'boom')
$n = Get-PimNotifyPlan -Outcome 'rolledback' -Source 'sync-automateit' -Detection $detGuiSql
T 'notify rolledback: severity warning' ($n.severity -eq 'warning')
$n = Get-PimNotifyPlan -Outcome 'noop' -Source 'sync-automateit' -Detection $detNone
T 'notify noop: send=false (nothing to email)' (-not $n.send)

# ---- Get-PimMonitorEnsurePlan --------------------------------------------
$m = Get-PimMonitorEnsurePlan -MonitorDeployed $false
T 'monitor: not deployed => ensure' ($m.action -eq 'ensure')
$m = Get-PimMonitorEnsurePlan -MonitorDeployed $true -DeployedMonitorHash 'h1' -PulledMonitorHash 'h2'
T 'monitor: deployed but pulled differs => refresh' ($m.action -eq 'refresh')
$m = Get-PimMonitorEnsurePlan -MonitorDeployed $true -DeployedMonitorHash 'h1' -PulledMonitorHash 'h1'
T 'monitor: deployed + same hash => noop' ($m.action -eq 'noop')
$m = Get-PimMonitorEnsurePlan -MonitorDeployed $true -PulledMonitorHash 'h2'   # deployed hash unknown
T 'monitor: deployed + unknown deployed hash => refresh' ($m.action -eq 'refresh')
$m = Get-PimMonitorEnsurePlan -MonitorDeployed $false -IntervalMinutes 60
T 'monitor: interval clamps to <=15m' ($m.intervalMinutes -eq 15)
$m = Get-PimMonitorEnsurePlan -MonitorDeployed $false -IntervalMinutes 1
T 'monitor: interval clamps to >=5m' ($m.intervalMinutes -eq 5)

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 }
