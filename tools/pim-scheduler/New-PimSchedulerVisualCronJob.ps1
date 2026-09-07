#Requires -Version 5.1
<#
.SYNOPSIS
    Create the PIM v2 "scheduler tick" job in VisualCron by CLONING the working delta job.

.DESCRIPTION
    🔴 MUST RUN UNDER WINDOWS POWERSHELL 5.1, NOT pwsh 7. VisualCronAPI.dll is a .NET
    FRAMEWORK assembly and its transport needs WCF. Under PowerShell 7 the connect fails with
        Could not load type 'System.ServiceModel.ServiceBehaviorAttribute'
    which reads like a broken install and is only the wrong host. Verified both ways on mgmt1.

    🔒 WHY CLONE INSTEAD OF BUILDING A JOB FROM SCRATCH. The existing
    'PIM for Entra ID (v2) - Delta change' job already carries the credentials, the run-as
    context, the hidden-window setting, the exit-code handling and the {USERVAR(...)} wiring
    that are PROVEN to work on this server. Constructing an equivalent by hand means
    reproducing all of that from guesses, and the only place it would show up is a failed
    nightly. Clone, then change exactly two things.

    WHAT IT CHANGES, and nothing else:
      1. the task arguments lose ` -Jobs engine-delta`, so the tick runs EVERY DUE JOB rather
         than only the nine engine-delta ones;
      2. the SQL event trigger is REMOVED and no trigger is created -- add a 5-minute time
         trigger in the VisualCron client. See the block at the trigger code for why the API
         cannot be trusted to set the schedule.

    🪤 WHY THE ARGUMENT CHANGE IS A DELETION, NOT A NEW STRING. -Jobs filters by HANDLER TYPE,
    not by job name, so 'engine-delta' covers delta-admins, delta-admin-tap, delta-pim-entra,
    delta-pim-azure, delta-pim-au, delta-groups-assign, delta-groups-deploy, delta-policies and
    delta-workloads. Everything ELSE -- queue-apply, escalations, reminders, discovery-*,
    tenant-cache, scheduled-creation, servicenow-intake, daily-summary, tier-report,
    full-reconcile -- has never had a runner. Removing the filter is what adds them.

    ⚠️ NO FILTER MEANS MAIL AND ACCOUNT CREATION RUN. reminders / daily-summary / tier-report
    send mail; scheduled-creation creates admin accounts and mints TAPs. That is correct for the
    main tick and is the point of the job -- but it is why this is a deliberate, reviewed change
    rather than something to run casually against a production tenant.

    🔒 SAFE TO RE-RUN: it refuses if a job of the same name already exists, and it never
    modifies the source job.

.PARAMETER Activate
    Create the job ENABLED. Omitted (the default), the job is created disabled -- which is the
    right default here anyway, because the job has NO TRIGGER until you add one in the client,
    and a tick that runs against production is worth looking at once before it starts firing.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\New-PimSchedulerVisualCronJob.ps1 -WhatIf
    Show what would be created, touching nothing.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\New-PimSchedulerVisualCronJob.ps1 -Activate
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SourceJobName = 'PIM for Entra ID (v2) - Delta change',
    [string]$NewJobName    = 'PIM for Entra ID (v2) - Scheduler tick (all due jobs)',
    [switch]$Activate,
    [string]$ApiDll = 'C:\Program Files (x86)\VisualCron\VisualCronAPI.dll',
    [string]$Address = 'localhost',
    [int]$Port = 16444
)

$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -eq 'Core') {
    throw "Run this under Windows PowerShell 5.1 (powershell.exe). VisualCronAPI needs .NET Framework WCF; under pwsh 7 the connect fails with a misleading System.ServiceModel type-load error."
}
if (-not (Test-Path -LiteralPath $ApiDll)) { throw "VisualCronAPI.dll not found: $ApiDll" }
Add-Type -Path $ApiDll

# Local trust: the VisualCron server runs on this machine, so no username/password is needed.
# (A remote connection would need credentials; that is what ConnectionT::Remote is for.)
$conn = New-Object VisualCronAPI.Connection
$conn.ConnectionType = [VisualCronAPI.Connection+ConnectionT]::Local
$conn.Address = $Address
$conn.Port    = $Port
$srv = (New-Object VisualCronAPI.Client).Connect($conn, $true, $false)
if (-not $srv) { throw "Could not connect to the VisualCron server at $Address`:$Port." }
Write-Host "connected to VisualCron ($Address`:$Port, local trust)" -ForegroundColor Cyan

if ($srv.Jobs.GetJobByName($NewJobName)) {
    Write-Host "job already exists, nothing to do: $NewJobName" -ForegroundColor Yellow
    return
}
$src = $srv.Jobs.GetJobByName($SourceJobName)
if (-not $src) { throw "Source job not found: '$SourceJobName'. Nothing was changed." }

$job = $src.Clone()
# A clone keeps the source's ids. Leaving them would collide with the job it was cloned from,
# which is the sort of thing that corrupts a scheduler rather than failing cleanly.
$job.Id          = [guid]::NewGuid().ToString()
$job.Name        = $NewJobName
$job.Description = 'PIM v2: ticks the in-process scheduler so every DUE job runs (queue-apply, escalations, reminders, discovery, tenant-cache, full-reconcile, scheduled-creation, servicenow-intake, daily-summary, tier-report). Cadences live in pim.Settings JobSchedule, not in VisualCron.'

foreach ($t in @($job.Tasks)) {
    $t.Id = [guid]::NewGuid().ToString()
    $a = $t.Execute.Arguments
    if ($a -match '\s-Jobs\s+\S+') {
        $t.Execute.Arguments = ($a -replace '\s-Jobs\s+\S+', '')
        Write-Host "  args -> $($t.Execute.Arguments)" -ForegroundColor DarkGray
    } else {
        Write-Warning "  the source task had no -Jobs filter to remove; arguments left as-is."
    }
}

# 🔴 THE JOB IS CREATED WITH **NO TRIGGER**, DELIBERATELY. Add the time trigger in the client.
#
# This script did originally build one. The schedule model is a cron-style set of boolean arrays
# (AllHours + Minutes[0,5,...] + Seconds[0] == "every 5 minutes"), and the arrays SET CORRECTLY
# in-process -- verified in isolation: a fresh TimeClass accepts Minutes[0,5,...,55] and AllHours,
# and reads them straight back. They do NOT survive the API round-trip. Measured 2026-09-04, the
# job as stored on the server came back:
#     AllHours=False  AllDays=False  AllMonths=False  Minutes ON: 28  Seconds ON: 39
# i.e. the server substituted a randomised once-an-hour schedule, while the trigger DESCRIPTION
# still read "Every 5 minutes".
#
# 🪤 THAT COMBINATION IS WORSE THAN NO TRIGGER, which is why this now creates none. A job whose
# description says every 5 minutes and whose schedule says :28 past the hour will be believed --
# and the failure is invisible, because a scheduler tick that runs 12x less often than intended
# still succeeds every time it runs. Nothing would ever go red; PIM would just reconcile late.
#
# What the API DOES do reliably is the fiddly half: clone the working job, keep its credentials,
# run-as context and {USERVAR} wiring, and strip the -Jobs filter. Setting "every 5 minutes" in
# the client afterwards takes seconds and cannot silently be something else.
$job.Triggers.Clear()

# 🪤 ACTIVATION IS A SERVER OPERATION, NOT A PROPERTY. `$job.Active = $true` fails with
# "The property 'Active' cannot be found on this object" -- which is also why reading .Active on an
# existing job returns blank. The Jobs collection exposes Activate()/DeActivate() instead, and they
# are called AFTER the job exists on the server. Measured on the third run of this script.

if ($PSCmdlet.ShouldProcess($NewJobName, "create VisualCron job (no trigger; activate=$([bool]$Activate))")) {
    $srv.Jobs.Add($job)
    Write-Host "CREATED: $NewJobName  (NO trigger -- add a 5-minute time trigger in the client)" -ForegroundColor Green
    $check = $srv.Jobs.GetJobByName($NewJobName)
    if (-not $check) { throw "Job was added but cannot be read back -- inspect the VisualCron client before relying on it." }
    Write-Host ("verified: tasks={0} triggers={1}" -f @($check.Tasks).Count, @($check.Triggers).Count) -ForegroundColor Green
    if ($Activate) {
        # 🪤 Enabling a job with NO trigger does nothing useful and looks like success. Say so.
        if (@($check.Triggers).Count -eq 0) {
            Write-Warning "activating a job with NO trigger -- it will never fire until you add the time trigger in the client."
        }
        $srv.Jobs.Activate($check.Id)
        Write-Host "ACTIVATED" -ForegroundColor Green
    } else {
        Write-Host "left DISABLED -- review it in the VisualCron client, then enable it (or re-run with -Activate)." -ForegroundColor Yellow
    }
} else {
    Write-Host "WhatIf: would create '$NewJobName' (no trigger -- add it in the client); nothing written." -ForegroundColor Yellow
}
