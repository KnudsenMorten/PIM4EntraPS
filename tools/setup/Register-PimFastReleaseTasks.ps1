#Requires -Version 5.1
<#
.SYNOPSIS
    The two scheduled tasks behind the FAST RELEASE PATH (PIM REQUIREMENTS 100.20; framework 12.1 SPEED RULE item 2), as
    Windows Task Scheduler DEFINITIONS -- written as XML and printed; registered only with -Apply (schtasks.exe, no modules).

.DESCRIPTION
      PIM nightly full suite       daily at -NightlyAt (default 01:30): Invoke-PimNightlySuite.ps1 -- the whole offline
                                   suite on origin/main on the test VM; red -> a fix request.
      PIM post-roll smoke watcher  every -WatchEveryMinutes (default 15): Invoke-PimPostRollSmoke.ps1 -EnvironmentsFile
                                   <file> -IfChanged -- every Manager roll in the listed ring-1 environments (the in-cloud
                                   updater's included) is smoked once; red -> rolled back to the last-good image.
                                   Defined only when -EnvironmentsFile exists.
    Both run as the CURRENT user with an interactive token (the az profiles and the VM key are that user's; a stored
    password is the operator's choice: -LogonType Password, schtasks prompts for it). The XML goes to -OutDir. Without
    -Apply nothing is registered -- this is the step the operator takes on the machine that should run them.
.EXAMPLE
    .\tools\setup\Register-PimFastReleaseTasks.ps1 -EnvironmentsFile C:\ProgramData\pim\ops\ring1-envs.json          # definitions only
.EXAMPLE
    .\tools\setup\Register-PimFastReleaseTasks.ps1 -EnvironmentsFile C:\ProgramData\pim\ops\ring1-envs.json -Apply   # register
#>
[CmdletBinding()]
param(
    [string]$NightlyAt = '01:30',
    [ValidateRange(5, 240)][int]$WatchEveryMinutes = 15,
    [string]$EnvironmentsFile = '',
    [string]$OutDir = $(Join-Path $env:ProgramData 'pim\tasks'),
    [ValidateSet('InteractiveToken', 'Password')][string]$LogonType = 'InteractiveToken',
    [string]$TaskFolder = '\PIM\',
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
if ($NightlyAt -notmatch '^([01]\d|2[0-3]):[0-5]\d$') { throw "-NightlyAt: HH:mm, not '$NightlyAt'" }
$pw = Get-Command pwsh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$pwPath = if ($pw) { $pw.Source } else { 'pwsh.exe' }
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
function ConvertTo-XmlText([string]$s) { return [Security.SecurityElement]::Escape($s) }
function New-PimTaskXml([string]$Description, [string]$TriggerXml, [string]$Arguments, [int]$LimitHours) {
@"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>$(ConvertTo-XmlText $Description)</Description><Author>PIM Manager (Register-PimFastReleaseTasks.ps1)</Author></RegistrationInfo>
  <Triggers>$TriggerXml</Triggers>
  <Principals><Principal id="Author"><UserId>$(ConvertTo-XmlText $user)</UserId><LogonType>$LogonType</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT${LimitHours}H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>$(ConvertTo-XmlText $pwPath)</Command><Arguments>$(ConvertTo-XmlText $Arguments)</Arguments></Exec></Actions>
</Task>
"@
}
$start = (Get-Date).Date.AddDays(1).ToString('yyyy-MM-dd') + 'T' + $NightlyAt + ':00'
$tasks = [ordered]@{}
$tasks['PIM nightly full suite'] = New-PimTaskXml -Description 'PIM fast release path: the full offline suite on origin/main on the test VM; red -> a fix request (fix-requests.jsonl).' `
    -TriggerXml "<CalendarTrigger><StartBoundary>$start</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>" `
    -Arguments ('-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $PSScriptRoot 'Invoke-PimNightlySuite.ps1') + '"') -LimitHours 4
if ($EnvironmentsFile -and (Test-Path -LiteralPath $EnvironmentsFile)) {
    $wStart = (Get-Date).AddMinutes(5).ToString('yyyy-MM-ddTHH:mm:00')
    $tasks['PIM post-roll smoke watcher'] = New-PimTaskXml -Description 'PIM fast release path: smoke every Manager roll once (-IfChanged); red -> roll back to the last-good image and hold the updater.' `
        -TriggerXml "<TimeTrigger><StartBoundary>$wStart</StartBoundary><Repetition><Interval>PT${WatchEveryMinutes}M</Interval></Repetition></TimeTrigger>" `
        -Arguments ('-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $PSScriptRoot 'Invoke-PimPostRollSmoke.ps1') + '" -EnvironmentsFile "' + $EnvironmentsFile + '" -IfChanged') -LimitHours 1
} else {
    Write-Host "  (no -EnvironmentsFile: the post-roll watcher is not defined -- a JSON list of { name, subscriptionId, resourceGroup, azureConfigDir })" -ForegroundColor Yellow
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
foreach ($name in $tasks.Keys) {
    $file = Join-Path $OutDir (($name -replace '[^A-Za-z0-9]+', '-') + '.xml')
    [IO.File]::WriteAllText($file, $tasks[$name], [Text.Encoding]::Unicode)
    Write-Host "  $TaskFolder$name  ->  $file" -ForegroundColor Cyan
    $cmd = @('/Create', '/TN', "$TaskFolder$name", '/XML', $file, '/F')
    if ($LogonType -eq 'Password') { $cmd += @('/RU', $user) }
    Write-Host ("    > schtasks.exe {0}" -f ($cmd -join ' '))
    if ($Apply) {
        & schtasks.exe @cmd
        if ($LASTEXITCODE) { throw "schtasks /Create '$name' failed (exit $LASTEXITCODE)" }
    }
}
if (-not $Apply) { Write-Host '  definitions written; nothing registered (pass -Apply on the machine that should run them).' -ForegroundColor Yellow }
exit 0
