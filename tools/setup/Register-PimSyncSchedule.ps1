#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS -- register the STANDALONE update on a VisualCron / Windows Task Scheduler
    cadence. This is the unattended host for the update mechanism. (REQUIREMENTS sec.1/sec.6;
    "Update is SEPARATE from the PIM engine + job-scheduler", operator correction 2026-06-18.)

.DESCRIPTION
    The UPDATE (code -> SQL-schema upgrade + Manager GUI build/roll) is a STANDALONE mechanism,
    NOT a PIM engine or in-container scheduler job. Customers run it from VisualCron or Windows
    Task Scheduler (the standalone host). This script registers a Windows Scheduled Task (the
    same XML VisualCron imports / mirrors) that fires the update unattended, cert-auth, no prompts.

    By DEFAULT (-UpdateMode Full) the task runs the FULL update lifecycle
    (tools/setup/Invoke-PimUpdate.ps1 -Apply): detect -> build the Manager image from the pulled
    code (when the GUI changed) -> roll -> apply the idempotent SQL schema upgrade -> verify
    (hosted smoke) -> notify -> ensure-monitor, with auto-rollback on a failed verify. This is the
    correct standalone entry because it handles the WHOLE dependency chain (schema AND GUI), for
    BOTH the VM and container editions.

    -UpdateMode RollOnly registers the lighter image-roll-only path (Invoke-PimSyncAutomateIT.ps1
    -Apply): it only rolls a strictly-newer ALREADY-BUILT released image, health-checks, and
    auto-rolls-back. Use it when you keep a separate build pipeline and just want a controlled roll.

    -Source selects the pull edition the update uses:
      * sync-automateit (default) -- INTERNAL edition: hosted ACA + Azure SQL (az acr build / ACA roll).
      * git-pull                  -- COMMUNITY edition: local/VM (local build/relaunch + local SQL upgrade).
    -ManagedHosting central|local applies to the from-master (MSP slave) downlink.

    -LocalPull (community pure-VM hosts) instead drives a customer-supplied -PullScript (e.g. a
    git/sync pull of the released code that THEN calls Invoke-PimUpdate.ps1), so the same scheduled
    cadence works for a no-ACA host. (On the internal edition the bootstrap post-sync deploy hook
    fires Invoke-PimUpdate.ps1 automatically after each sync-automateit pull; this scheduled task is
    the explicit standalone alternative / the VM-host path.)

.PARAMETER AtHour
    Hour of day (0-23, local time) to run the daily update. Default 03 (low-traffic window).

.PARAMETER UpdateMode
    'Full' (default) = the full update lifecycle (Invoke-PimUpdate.ps1 -Apply: schema + GUI build/roll
    + verify + rollback). 'RollOnly' = image roll only (Invoke-PimSyncAutomateIT.ps1 -Apply).

.PARAMETER Source
    Update pull edition: 'sync-automateit' (internal, default) or 'git-pull' (community). Only used
    by -UpdateMode Full (passed through to Invoke-PimUpdate.ps1 -Source).

.PARAMETER ManagedHosting
    'central'|'local' for the from-master (MSP slave) downlink; passed through to Invoke-PimUpdate.ps1.

.PARAMETER RunAsUser
    Service account the task runs as (must be able to `az login`/MI + reach the deployment).

.PARAMETER LocalPull
    Drive a local pull (-PullScript) instead of the update entry (for a no-ACA community VM host).

.PARAMETER PullScript
    Path to the local pull script invoked when -LocalPull is set.

.EXAMPLE
    .\Register-PimSyncSchedule.ps1
    Daily 03:00 standalone FULL update of the internal/hosted deployment (schema + GUI build/roll).

.EXAMPLE
    .\Register-PimSyncSchedule.ps1 -Source git-pull -AtHour 4
    Daily 04:00 standalone FULL update of a COMMUNITY (git-pull) deployment.

.EXAMPLE
    .\Register-PimSyncSchedule.ps1 -UpdateMode RollOnly
    Daily 03:00 controlled image ROLL only (no build/schema) of the hosted deployment.

.EXAMPLE
    .\Register-PimSyncSchedule.ps1 -LocalPull -PullScript C:\AutomateIT\Sync-AutomateIT.ps1 -AtHour 4
    Daily 04:00 local pull on a pure-VM community host (the pull script then runs Invoke-PimUpdate.ps1).

.NOTES
    Re-runnable (-Force overwrites the task). Mirrors Setup-PimVM.ps1's scheduled-task style. The
    task XML can be exported (`Export-ScheduledTask -TaskName <name>`) and imported into VisualCron.
    The update is unattended + cert-auth (no prompts) by design. This script NEVER wires the update
    into the engine or the in-container scheduler -- it is the standalone host.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(0,23)][int]$AtHour = 3,
    [string]$TaskName  = 'PIM-Update',
    [ValidateSet('Full','RollOnly')][string]$UpdateMode = 'Full',
    [ValidateSet('sync-automateit','git-pull')][string]$Source = 'sync-automateit',
    [ValidateSet('central','local')][string]$ManagedHosting,
    [string]$RunAsUser = 'NT AUTHORITY\NETWORK SERVICE',
    [switch]$LocalPull,
    [string]$PullScript,
    # passthrough to the update / roll orchestrator
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
} elseif ($UpdateMode -eq 'RollOnly') {
    # lighter path: roll a strictly-newer ALREADY-BUILT image (no build / no schema).
    $orch = Join-Path $here 'Invoke-PimSyncAutomateIT.ps1'
    if (-not (Test-Path $orch)) { throw "roll orchestrator not found: $orch" }
    $exe = 'powershell.exe'
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$orch`" -Apply -ResourceGroup `"$ResourceGroup`" -AcrName `"$AcrName`" -ImageRepo `"$ImageRepo`""
    Step "Scheduled Task '$TaskName' -> ROLL ONLY (Invoke-PimSyncAutomateIT.ps1, daily $([string]::Format('{0:00}:00', $AtHour)))"
} else {
    # default FULL update lifecycle: schema upgrade + GUI build/roll + verify + rollback. This is
    # the correct STANDALONE update entry -- it handles the whole dependency chain for VM + container.
    $orch = Join-Path $here 'Invoke-PimUpdate.ps1'
    if (-not (Test-Path $orch)) { throw "update entry not found: $orch" }
    $exe = 'powershell.exe'
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$orch`" -Apply -Source `"$Source`" -ResourceGroup `"$ResourceGroup`" -AcrName `"$AcrName`" -ImageRepo `"$ImageRepo`""
    if ("$ManagedHosting".Trim()) { $arg += " -ManagedHosting `"$ManagedHosting`"" }
    Step "Scheduled Task '$TaskName' -> FULL update (Invoke-PimUpdate.ps1 -Source $Source, daily $([string]::Format('{0:00}:00', $AtHour)))"
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
