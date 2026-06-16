#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS -- VM-host equivalent of the container auto-update: a scheduled task that
    runs the controlled sync-automateit pull on a cadence. (REQUIREMENTS sec.1/sec.6)

.DESCRIPTION
    The Container Apps deployment can run sync-automateit as an in-container scheduler job
    (handler 'sync-automateit', see engine/_shared/PIM-Scheduler.ps1). For the VM host
    (Setup-PimVM.ps1) there is no Container Apps Jobs cron, so this registers a Windows
    Scheduled Task that runs Invoke-PimSyncAutomateIT.ps1 -Apply daily inside a maintenance
    window. Same controlled behaviour: it only rolls when a strictly-newer released version
    exists, then health-checks and auto-rolls-back on failure.

    On a VM the roll target is the local image / process, not Container Apps revisions. By
    default this task drives Invoke-PimSyncAutomateIT.ps1 against the configured Container
    Apps (a VM that manages the ACA deployment) -- pass -LocalPull to instead run a
    customer-supplied -PullScript (e.g. `docker pull` + recreate, or a git/sync pull of the
    released engine code) so the same scheduled cadence works for a pure-VM, no-ACA host.

.PARAMETER AtHour
    Hour of day (0-23, local time) to run the daily sync. Default 03 (low-traffic window).

.PARAMETER RunAsUser
    Service account the task runs as (must be able to `az login`/MI + reach the deployment).

.PARAMETER LocalPull
    Drive a local pull (-PullScript) instead of the ACA orchestrator (for a no-ACA VM host).

.PARAMETER PullScript
    Path to the local pull script invoked when -LocalPull is set.

.EXAMPLE
    .\Register-PimSyncSchedule.ps1
    Register a daily 03:00 task that runs the controlled ACA sync-automateit pull.

.EXAMPLE
    .\Register-PimSyncSchedule.ps1 -LocalPull -PullScript C:\AutomateIT\Sync-AutomateIT.ps1 -AtHour 4
    Daily 04:00 local pull on a pure-VM host.

.NOTES
    Re-runnable (-Force overwrites the task). Mirrors Setup-PimVM.ps1's scheduled-task style.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(0,23)][int]$AtHour = 3,
    [string]$TaskName  = 'PIM-SyncAutomateIT',
    [string]$RunAsUser = 'NT AUTHORITY\NETWORK SERVICE',
    [switch]$LocalPull,
    [string]$PullScript,
    # passthrough to the ACA orchestrator
    [string]$ResourceGroup = 'rg-pim-manager-web',
    [string]$AcrName       = 'acrsecurityinsight',
    [string]$ImageRepo     = 'pim-manager'
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }

if ($LocalPull) {
    if (-not "$PullScript".Trim()) { throw "-LocalPull requires -PullScript <path to the local pull script>." }
    $exe = 'powershell.exe'
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PullScript`""
    Step "Scheduled Task '$TaskName' -> local pull: $PullScript (daily $([string]::Format('{0:00}:00', $AtHour)))"
} else {
    $orch = Join-Path $here 'Invoke-PimSyncAutomateIT.ps1'
    if (-not (Test-Path $orch)) { throw "orchestrator not found: $orch" }
    $exe = 'powershell.exe'
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$orch`" -Apply -ResourceGroup `"$ResourceGroup`" -AcrName `"$AcrName`" -ImageRepo `"$ImageRepo`""
    Step "Scheduled Task '$TaskName' -> ACA sync-automateit (daily $([string]::Format('{0:00}:00', $AtHour)))"
}

if ($PSCmdlet.ShouldProcess($TaskName, 'register daily sync task')) {
    $a = New-ScheduledTaskAction -Execute $exe -Argument $arg
    $t = New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.AddHours($AtHour))
    $p = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType ServiceAccount -RunLevel Highest
    # don't pile up overlapping runs; a roll can take minutes.
    $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    Register-ScheduledTask -TaskName $TaskName -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
    Write-Host "    registered: '$TaskName' runs daily at $([string]::Format('{0:00}:00', $AtHour)) as $RunAsUser" -ForegroundColor Green
}

Step "Done. Inspect/run on demand:  Start-ScheduledTask -TaskName '$TaskName'  |  Get-ScheduledTaskInfo -TaskName '$TaskName'"
