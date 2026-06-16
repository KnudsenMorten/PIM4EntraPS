#Requires -Version 5.1
<#
.SYNOPSIS
  Seed a realistic scheduler state + run-history dataset so the Manager's Jobs tab
  (/api/jobs) renders a populated, representative view without a live scheduler loop.

.DESCRIPTION
  Writes two files next to each other (the same pair the live scheduler writes):
    * pim-scheduler-state.json  -- the configured schedule with last/next run stamps
    * pim-scheduler-runs.json   -- a bounded ring of recent run records (incl. logs)

  Coverage by design: one IN-PROGRESS run (an engine full-reconcile mid-flight, no
  finishedUtc) so the GUI's "in-progress at the TOP" ordering + live-tail are exercised,
  plus completed (ok + no-op) and failed runs across the real job types -- tenant-cache
  12h refresh, access-review/reminders, per-scope engine deltas, scheduled mails
  (daily-summary / tier-report) and discovery.

  This is a DEMO / TEST seed, not customer data: no tenant/customer specifics.

.PARAMETER StateDir
  Directory to write the two JSON files into. Defaults to the solution's
  output\scheduler dir -- the same location Start-PimScheduler.ps1 and the Manager
  (/api/jobs) default to, so a seed shows up in the GUI immediately.

.PARAMETER NowUtc
  Reference "now" (UTC) the relative timestamps are computed from. Defaults to now.

.OUTPUTS
  The state-file path (string).
#>
[CmdletBinding()]
param(
    [string]$StateDir,
    [datetime]$NowUtc = [datetime]::UtcNow
)
$ErrorActionPreference = 'Stop'
$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tools\pim-scheduler' }
$shared  = Resolve-Path "$here\..\..\engine\_shared"
. "$shared\PIM-Scheduler.ps1"

if (-not "$StateDir".Trim()) {
    $StateDir = Join-Path (Resolve-Path "$here\..\..").Path 'output\scheduler'
}
if (-not (Test-Path -LiteralPath $StateDir)) { [void](New-Item -ItemType Directory -Path $StateDir -Force) }

$now = $NowUtc.ToUniversalTime()
$statePath = Join-Path $StateDir 'pim-scheduler-state.json'
$global:PIM_SchedulerStatePath = $statePath

# --- build the configured schedule with realistic last/next-run stamps ----------
$schedule = @(Get-PimDefaultJobSchedule)
$jobs = New-Object System.Collections.Generic.List[object]
foreach ($j in $schedule) {
    $iv = [int]$j.intervalMinutes; if ($iv -le 0) { $iv = 60 }
    if ("$($j.name)" -eq 'escalations') {
        # [M6] one deliberately OVERDUE job: last run + next-run well in the past so the
        # Jobs tab's overdue detection + "needs attention" banner render against real data.
        $last = $now.AddMinutes(-($iv * 4))
        $j | Add-Member -NotePropertyName lastRunUtc -NotePropertyValue $last.ToString('o') -Force
        $j | Add-Member -NotePropertyName nextRunUtc -NotePropertyValue (Get-PimNextRunUtc -Job $j -FromUtc $last).ToString('o') -Force
        $jobs.Add($j)
        continue
    }
    # last run somewhere within the last cadence window; next = last + interval
    $lastAgo = [int]([Math]::Min($iv, [Math]::Max(1, $iv * 0.4)))
    $last = $now.AddMinutes(-$lastAgo)
    $j | Add-Member -NotePropertyName lastRunUtc -NotePropertyValue $last.ToString('o') -Force
    $j | Add-Member -NotePropertyName nextRunUtc -NotePropertyValue (Get-PimNextRunUtc -Job $j -FromUtc $last).ToString('o') -Force
    $jobs.Add($j)
}
# NOTE (PS 5.1): @(List[object] of PSCustomObjects) throws "Argument types do not
# match" -- use .ToArray() to materialize the schedule before persisting.
Save-PimSchedulerState -State ([pscustomobject]@{ jobs = $jobs.ToArray(); lastWatermark = ''; updatedUtc = $now.ToString('o') })

# --- seed a representative run-history ring --------------------------------------
$script:PimRunHistory = $null
Save-PimJobRunHistory -Runs @()

function Seed-Run {
    param([string]$Name,[string]$Type,[string]$Scope,[bool]$Ok,[bool]$Ran,[string]$Detail,[datetime]$Started,[int]$DurMs,[string]$Status='completed',[string[]]$Log)
    $fin = if ($Status -eq 'running') { '' } else { $Started.AddMilliseconds($DurMs).ToString('o') }
    $logText = if ($Log) { (@("[{0}] job '{1}' (type={2}{3})" -f $Started.ToString('o'), $Name, $Type, $(if ($Scope) { " scope=$Scope" } else { '' })) + $Log) -join "`n" } else { "[{0}] job '{1}'" -f $Started.ToString('o'), $Name }
    $rec = [pscustomobject]@{
        runId='seed-' + [guid]::NewGuid().ToString('N'); name=$Name; type=$Type; scope=$Scope
        ok=$Ok; ran=$Ran; status=$Status; detail=$Detail; trigger=$false; reason=''
        startedUtc=$Started.ToUniversalTime().ToString('o'); finishedUtc=$fin
        durationMs=$(if ($Status -eq 'running') { 0 } else { $DurMs }); log=$logText
    }
    Add-PimJobRunRecord -Run $rec
}

# completed (ok) runs across the real job types ...
Seed-Run -Name 'tenant-cache' -Type 'tenant-cache' -Scope '' -Ok $true -Ran $true `
    -Detail 'tenant-cache refreshed entra-roles=412 administrative-units=37 pim-groups=callPim=58 azure-scopes=21 rbac-roles=140' `
    -Started $now.AddMinutes(-90) -DurMs 8200 -Log @('result.ok      = True','refreshing entra-roles ... 412','refreshing administrative-units ... 37','refreshing pim-groups ... 58','refreshing azure-scopes ... 21','refreshing rbac-roles ... 140','cache written')
Seed-Run -Name 'reminders' -Type 'reminders' -Scope '' -Ok $true -Ran $true `
    -Detail 'upcoming=6 renew=2' -Started $now.AddMinutes(-200) -DurMs 1400 -Log @('result.ok      = True','ran            = True','upcoming expirations within window: 6','auto-extend renewals queued: 2')
Seed-Run -Name 'delta-pim-entra' -Type 'engine-delta' -Scope 'EntraRoles' -Ok $true -Ran $true `
    -Detail 'engine Delta [EntraRoles] EntraRoles:c0/u2/r0' -Started $now.AddMinutes(-12) -DurMs 5300 -Log @('result.ok      = True','reconciling EntraRoles ...','create=0 update=2 remove=0','done')
Seed-Run -Name 'daily-summary' -Type 'daily-summary' -Scope '' -Ok $true -Ran $true `
    -Detail 'daily-summary changes=14 recipients=2' -Started $now.AddHours(-7) -DurMs 2600 -Log @('result.ok      = True','folded 24h audit into digest: 14 changes','sent to 2 digest recipients')
Seed-Run -Name 'tier-report' -Type 'tier-report' -Scope '' -Ok $true -Ran $true `
    -Detail 'tier-report users=23 recipients=1' -Started $now.AddHours(-7) -DurMs 1900 -Log @('result.ok      = True','Tier 0/1 privileged users: 23','sent to 1 recipient')

# a no-op completed run (handler present but nothing to do) ...
Seed-Run -Name 'queue-apply' -Type 'queue-apply' -Scope '' -Ok $true -Ran $false `
    -Detail 'queue-apply-plan' -Started $now.AddMinutes(-3) -DurMs 220 -Log @('result.ok      = True','ran            = False','no pending change-queue items to apply')

# a failed run ...
Seed-Run -Name 'discovery-azure' -Type 'discovery' -Scope 'Azure' -Ok $false -Ran $false `
    -Detail 'error: AuthorizationFailed enumerating subscriptions' -Started $now.AddHours(-2) -DurMs 4100 -Status 'failed' `
    -Log @('result.ok      = False','enumerating Azure subscriptions ...','ERROR: AuthorizationFailed -- engine SPN lacks Reader on 1 subscription')

# an IN-PROGRESS run (no finishedUtc) -> must render at the TOP, live-tail-able ...
Seed-Run -Name 'full-reconcile' -Type 'engine-full' -Scope 'All' -Ok $true -Ran $true `
    -Detail 'engine Full [All] running ...' -Started $now.AddMinutes(-2) -DurMs 0 -Status 'running' `
    -Log @('result.ok      = True','starting full reconcile of all scopes','phase Admins ... done','phase GroupsAssignment ... done','phase EntraRoles ... in progress')

Write-Host ("[seed] wrote scheduler state + run history to {0}" -f $StateDir) -ForegroundColor Green
Write-Host ("[seed]   state:   {0}" -f $statePath) -ForegroundColor DarkGray
Write-Host ("[seed]   history: {0} ({1} records, 1 in-progress)" -f (Get-PimRunHistoryPath), @(Get-PimJobRunHistory).Count) -ForegroundColor DarkGray
return $statePath
