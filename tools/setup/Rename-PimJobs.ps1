#Requires -Version 5.1

<#
.SYNOPSIS
  Renames each PIM Manager job of one install to its standard name caj-pim-<purpose> by creating the new job with the same spec, proving it, switching to it and disabling the old job -- the old job is deleted only with -DeleteOld, after the proof and the switch.

.DESCRIPTION
  JOB-RENAME (PIM 3.0.68; framework NAMING-PROGRAMME-1 / RIGHTS-1, owner 2026-11-09). Azure cannot rename a Container Apps
  job, so for each job: ca-pim-tick -> caj-pim-engine, ca-pim-update -> caj-pim-updater, ca-pim-dbinit -> caj-pim-dbinit,
  ca-pim-publish -> caj-pim-publish (MSP managing installs), ca-pim-downlink-s<N> -> caj-pim-downlink (MSP managed installs),
  caj-pim-asbuilt -> caj-pim-docs (Installation documentation; it keeps its identity id-pim-asbuilt in this step).
  Web apps are never renamed.

  Without -Apply the script only PLANS (read-only): per job the spec to copy, the identity it runs as, its secrets (references
  only), the job-scoped role assignments to copy, the settings that name it (the Manager's and other jobs' variables,
  pim.Settings SchedulerTickJobId and InstallNames), whether an execution is running, and what blocks it (a job still on its
  system-assigned identity is never renamed). The plan is printed as plain text for the approval and written as JSON.

  With -Apply -Role <role> it renames that ONE role, each step read back: create the new job with a Manual trigger -> copy
  the job-scoped role assignments -> start ONE run of the new job and prove it -> switch (the old schedule on the new job,
  every setting that names the old job) -> the old job's trigger set to Manual (disabled, kept with its identity and its
  rights). With -DeleteOld (default off) the old job is then DELETED as a separate final step -- its rollback record (full
  spec + job-scoped role assignments) written first, read back 404 -- and so are the old id-pim-* user-assigned identities
  nothing attaches any more. A failed proof switches and deletes nothing. A running execution of the old job is never
  interrupted: the script waits and reports 'waiting'. No role assignment is ever deleted. Every write is in the record
  (-LogDir) with its exact undo. -WhatIf writes nothing.

  Run it in a PowerShell session connected to the install's tenant through the Invardia Support app (its REST context and
  Invoke-InvardiaSupportSql for pim.Settings).

.PARAMETER SubscriptionId
  The subscription of the PIM install.
.PARAMETER ResourceGroup
  The resource group of the PIM install (its container apps and jobs).
.PARAMETER Apply
  Rename the role in -Role. Without it the script only plans.
.PARAMETER Role
  The ONE role to rename with -Apply: engine, updater, dbinit, publish, downlink, docs.
.PARAMETER LogDir
  Where the plan, the plan text and the per-role record are written.
.PARAMETER DeleteOld
  After the new job is proven and the switch reads back, DELETE the old job (its system-assigned identity goes with it),
  and the old id-pim-* user-assigned identities nothing attaches any more. Each delete writes its rollback record to -LogDir
  first and is read back (404). Default off: without it the old job is disabled and kept. No role assignment is deleted.
.PARAMETER SqlServer
  The install's SQL server (for pim.Settings). Default: PIM_SqlServer of the Manager app.
.PARAMETER SqlDatabase
  The install's database. Default: PIM_SqlDatabase of the Manager app, else PimPlatform.
.PARAMETER SqlViaJob
  For an install whose database is PRIVATE (public network access off), where the Support app's audited SQL cannot reach
  it: pim.Settings 'SchedulerTickJobId' and 'InstallNames' are read and written by a ONE-TIME job (caj-pim-renamesql)
  inside the install's own environment, with the identity the install's database job (caj-pim-dbinit, else ca-pim-dbinit)
  signs in to SQL with. Each run is created, started once, its result read from its log lines (Log Analytics), and the
  job is ALWAYS removed and read back gone. One run reads both settings; each write is one run that reads them back. The
  value is passed to the job base64-encoded in an environment value and written with a parameterised UPDATE (INSERT only
  when the row is missing). A plan without -Apply runs read jobs only; -WhatIf creates no job (pim.Settings not read).
  -SqlServer / -SqlDatabase, when given, must be the database the database job names.

.EXAMPLE
  .\Rename-PimJobs.ps1 -SubscriptionId <sub> -ResourceGroup <rg>
.EXAMPLE
  .\Rename-PimJobs.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -Apply -Role engine -LogDir C:\temp\rename
.EXAMPLE
  .\Rename-PimJobs.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -Apply -Role engine -LogDir C:\temp\rename -SqlViaJob
  A private database: pim.Settings through one-time jobs inside the install's network.

.NOTES
  Requirements:
    PowerShell: 5.1 or 7.
    Role: the Invardia Support app (Contributor + User Access Administrator at the PIM resource group; the database role that writes pim.Settings).
    Hosts: management.azure.com, login.microsoftonline.com, <server>.database.windows.net
    With -SqlViaJob: nothing to the database from this computer; api.loganalytics.io for the one-time job's result lines
    (Log Analytics Reader on the install's workspace).

.LINK
  https://invardia.com/docs/pim/scripts/Rename-PimJobs/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [switch]$Apply,
    [ValidateSet('', 'engine', 'updater', 'dbinit', 'publish', 'downlink', 'docs')][string]$Role = '',
    [string]$LogDir = '',
    # owner 2026-11-09 (relayed by the coordinator): delete the old job (after proof + switch) and orphaned old identities
    [switch]$DeleteOld,
    [string]$SqlServer = '',
    [string]$SqlDatabase = '',
    # a PRIVATE database: pim.Settings through a one-time job inside the install's network (tools\setup\_PimJobRenameSqlJob.ps1)
    [switch]$SqlViaJob,
    # TEST seams (tests\Test-PimJobRename.ps1, tests\Test-PimJobRenameSqlJob.ps1): replace ARM / pim.Settings / the proof / the
    # wait / the one-time job's log lines
    [scriptblock]$Arm,
    [scriptblock]$Sql,
    [scriptblock]$Prove,
    [scriptblock]$Sleep,
    [scriptblock]$SqlJobLogs
)
$ErrorActionPreference = 'Stop'
$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)   # tools\setup -> tools -> <solution root>
. (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-InstallNames.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-IdentitySplit.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-IdentityMove.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-JobRename.ps1')
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Rename-PimJobs'
try {
    function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }
    $dry = [bool]$WhatIfPreference
    if (-not $Arm)   { $Arm   = { param($m, $p, $b) if ($null -ne $b) { Invoke-PimArm -Method $m -Path $p -Body $b } else { Invoke-PimArm -Method $m -Path $p } } }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    if (-not "$LogDir".Trim()) { $LogDir = Join-Path ([IO.Path]::GetTempPath()) 'pim-job-rename' }
    if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $stamp = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    if ($Apply -and -not "$Role".Trim()) { throw '-Apply needs -Role (one role at a time: engine, updater, dbinit, publish, downlink, docs)' }
    if ($SqlViaJob -and $Sql) { throw '-SqlViaJob and -Sql are two ways to reach pim.Settings -- pass one' }

    Say "=== JOB-RENAME: $ResourceGroup ($(if ($Apply) { if ($dry) { 'APPLY, What if' } else { "APPLY $Role" } } else { 'PLAN, read-only' })) ===" 'Cyan'
    # pim.Settings through the Support app's AUDITED SQL (Invoke-InvardiaSupportSql), when this session has it
    $jrInst = Read-PimJobRenameInstall -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
    if ($SqlViaJob) {
        # a PRIVATE database: each read / write of pim.Settings is a one-time job inside the install's network (created,
        # started once, its result line read, ALWAYS removed and read back gone)
        . (Join-Path $PSScriptRoot '_PimSupportSqlJob.ps1')      # the one-time job's pure helpers (api, tag, command, log query)
        . (Join-Path $PSScriptRoot '_PimJobRenameSqlJob.ps1')    # the job-rename read / write through it
        $jrSqlLogs = if ($SqlJobLogs) { $SqlJobLogs } else { { param($w, $e) Get-PimJobRenameSqlJobLogLines -WorkspaceId $w -Execution $e } }
        $jrSqlJobState = New-PimJobRenameSqlJobState -Arm $Arm -Logs $jrSqlLogs -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -SqlServer $SqlServer -SqlDatabase $SqlDatabase -Sleep $Sleep -WhatIfOnly:$dry
        # a PLAIN scriptblock (never a bound closure): it finds $jrSqlJobState and the dot-sourced functions in this script's scope
        $Sql = { param($a, $n, $v) Invoke-PimJobRenameSqlJobSeam -State $jrSqlJobState -Action $a -Name $n -Value $v }
        Say "  pim.Settings through a one-time job inside the install's network ($(Get-PimJobRenameSqlJobName), the database job's identity)$(if ($dry) { ' -- What if: no job is created, pim.Settings is not read' })" 'DarkGray'
    }
    if (-not $Sql -and (Get-Command Invoke-InvardiaSupportSql -ErrorAction SilentlyContinue)) {
        $jrMgr = @($jrInst.apps | Where-Object { $_ -and (Test-PimInstallNameIsRole -Role web -Name "$($_.name)") }) | Select-Object -First 1
        $jrEnv = @{}
        foreach ($jrC in @($jrMgr.properties.template.containers)) { foreach ($jrE in @($jrC.env)) { if ($jrE -and "$($jrE.name)" -and -not $jrEnv.ContainsKey("$($jrE.name)")) { $jrEnv["$($jrE.name)"] = "$($jrE.value)" } } }
        $jrSrv = if ("$SqlServer".Trim()) { "$SqlServer".Trim() } else { "$($jrEnv['PIM_SqlServer'])".Trim() }
        if ($jrSrv -and $jrSrv -notmatch '\.') { $jrSrv = "$jrSrv.database.windows.net" }
        $jrDb = if ("$SqlDatabase".Trim()) { "$SqlDatabase".Trim() } elseif ("$($jrEnv['PIM_SqlDatabase'])".Trim()) { "$($jrEnv['PIM_SqlDatabase'])".Trim() } else { 'PimPlatform' }
        if ($jrSrv) {
            $Sql = {
                param($a, $n, $v)
                if ($n -notin @('SchedulerTickJobId', 'InstallNames')) { throw "refusing pim.Settings '$n' (this step writes SchedulerTickJobId and InstallNames only)" }
                if ($a -eq 'get') {
                    $r = Invoke-InvardiaSupportSql -Server $jrSrv -Database $jrDb -Query "SELECT ValueJson FROM pim.Settings WHERE Name = N'$n'" -Reason "PIM job rename: read pim.Settings $n" -ReadOnly
                    $raw = "$(@($r.Rows)[0].ValueJson)"; if (-not $raw.Trim()) { return $null }
                    try { return ($raw | ConvertFrom-Json) } catch { return $raw }
                }
                $j = (ConvertTo-Json -InputObject $v -Compress -Depth 8) -replace "'", "''"
                [void](Invoke-InvardiaSupportSql -Server $jrSrv -Database $jrDb -Reason "PIM job rename: switch pim.Settings $n" -Query "UPDATE pim.Settings SET ValueJson = N'$j', UpdatedUtc = SYSUTCDATETIME() WHERE Name = N'$n'; IF @@ROWCOUNT = 0 INSERT INTO pim.Settings (Name, ValueJson, UpdatedUtc) VALUES (N'$n', N'$j', SYSUTCDATETIME());")
                # UPDATE first, INSERT only when the row is missing: a MERGE needs the INSERT permission even when the row
                # exists, and the Support app's SQL access may update pim.Settings without inserting (internal 2026-11-09:
                # "The INSERT permission was denied on the object 'Settings'")
            }
            Say "  pim.Settings through the Support app's audited SQL: $jrSrv / $jrDb" 'DarkGray'
        }
    }
    $plan = Get-PimJobRenamePlan -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Sql $Sql -Install $jrInst -DeleteOld:$DeleteOld
    $report = ConvertTo-PimJobRenameReport -Plan $plan
    Say ''
    foreach ($jrLine in @($report -split "`n")) { Say "  $jrLine" $(if ($jrLine -match '^\[blocked\]|BLOCKED') { 'Yellow' } elseif ($jrLine -match '^\[') { 'White' } else { 'Gray' }) }
    $planOut = Join-Path $LogDir "job-rename-plan-$stamp.json"
    Set-Content -LiteralPath $planOut -Value ([pscustomobject]$plan | ConvertTo-Json -Depth 12) -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $LogDir "job-rename-plan-$stamp.txt") -Value $report -Encoding UTF8
    Say "`n  plan written: $planOut (+ .txt for the approval)" 'DarkGray'

    if (-not $Apply) { Say "`nPLAN ONLY -- nothing was changed. Rename a role with -Apply -Role <role>." 'Cyan'; exit 0 }

    Say "`n--- $Role ---" 'Cyan'
    if ($dry) { Say "What if: Performing the operation `"rename the $Role job`" on target `"$ResourceGroup`" -- every step below is what WOULD happen; nothing is written." 'Yellow' }
    $rec = Invoke-PimJobRename -Plan $plan -Role $Role -Arm $Arm -Sql $Sql -Prove $Prove -Sleep $Sleep -DryRun:$dry -LogDir $(if ($dry) { '' } else { $LogDir }) -DeleteOld:$DeleteOld
    if ($DeleteOld -and $rec.state -in @('done', 'dry-run', 'nothing-to-do')) {
        # the old identities NOTHING attaches any more (re-checked at delete time; record first; 404 read back)
        foreach ($jrO in @(Remove-PimJobRenameOrphanIdentities -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -LogDir $LogDir -DryRun:$dry -Sleep $Sleep)) {
            $rec.steps.Add([pscustomobject]@{ step = 'identity'; what = "$($jrO.name): $($jrO.state) -- $($jrO.detail)"; readBack = $(if ($jrO.state -eq 'deleted') { 'read back: 404' } else { '' }); undo = $(if ($jrO.record) { "re-create from the record $($jrO.record)" } else { '' }); atUtc = [datetime]::UtcNow.ToString('o') })
            if ($jrO.state -eq 'failed') { $rec.state = 'failed'; $rec.error = "the old identity $($jrO.name): $($jrO.detail)" }
        }
    }
    foreach ($jrStep in @($rec.steps.ToArray())) {
        $jrL = '  [' + [string]$jrStep.step + '] ' + [string]$jrStep.what
        if ([string]$jrStep.readBack) { $jrL += '  (' + [string]$jrStep.readBack + ')' }
        Say $jrL 'Gray'
    }
    $col = switch ($rec.state) { 'done' { 'Green' } 'nothing-to-do' { 'Green' } 'dry-run' { 'Yellow' } 'waiting' { 'Yellow' } default { 'Red' } }
    Say "  RESULT $Role : $($rec.state)$(if ($rec.error) { ' -- ' + $rec.error })" $col
    if ($rec.state -eq 'failed') {
        Say "  STOPPED at step '$($rec.failedStep)'. Nothing was deleted. To undo what this run did (newest first):" 'Red'
        foreach ($jrU in @($rec.rollback)) { Say "    $($jrU.undo)" 'Red' }
    }
    if (-not $dry) { Say "  record written to $LogDir" 'DarkGray' }
    if ($dry) { Say "`nWhat if: nothing was changed." 'Yellow' }
    if ($rec.state -in @('failed', 'blocked')) { exit 1 }
    exit 0
} finally {
    Stop-PimScriptRun -Script 'Rename-PimJobs'
}
