#Requires -Version 5.1
<#
.SYNOPSIS
    71.18 -- schedule the MSP master's signed-baseline publish (setup\New-PimBaselineBundle.ps1) as a DAILY task on the
    signing host, certificate identity only.

.DESCRIPTION
    A bundle is valid -ValidDays (default 30) and every managed tenant REFUSES an expired one. Nothing re-published it:
    a master built on Friday would silently stop reaching its tenants a month later, and a registry change (a new admin,
    a re-targeted group, a newly registered tenant) reached nobody until someone published by hand. The publish must run
    where the CN=PIM4EntraPS-Baseline signing key is (LocalMachine\My), so this is a Windows scheduled task, like the
    read-link rotation. SYSTEM by default (it can read the machine certificate private keys).

    -Register creates or replaces the task and exits (it does not also publish). -RunNow publishes once in this process.

.EXAMPLE
    .\Register-PimBaselinePublish.ps1 -Register -CentralServer sql-ait-wa678.database.windows.net -StorageAccount stpimbaselinewa678 `
        -TenantId <master tenant> -ClientId <publisher app> -CertThumbprint <thumb> -TaskName PIM-BaselinePublish-wa678
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CentralServer,
    [string]$Database = 'PimPlatform',
    [Parameter(Mandatory)][string]$StorageAccount,
    [string]$Container = 'baselines',
    [string]$Scope = 'fleet',
    [int]$ValidDays = 30,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$CertThumbprint,
    [switch]$Register,
    [switch]$RunNow,
    [string]$TaskName = 'PIM-BaselinePublish',
    [ValidateRange(0, 23)][int]$AtHour = 4,
    [string]$RunAsUser = 'NT AUTHORITY\SYSTEM',
    [string]$BundleScriptPath
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $solRoot 'engine\_shared\PIM-MspBuild.ps1')
if (-not "$BundleScriptPath".Trim()) { $BundleScriptPath = Join-Path $solRoot 'setup\New-PimBaselineBundle.ps1' }
if (-not (Test-Path -LiteralPath $BundleScriptPath)) { throw "bundle script not found: $BundleScriptPath" }
if (-not (Get-Item -LiteralPath "Cert:\LocalMachine\My\$CertThumbprint" -ErrorAction SilentlyContinue)) { throw "publishing certificate $CertThumbprint is not in Cert:\LocalMachine\My on this host." }
if (-not @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq 'CN=PIM4EntraPS-Baseline' -and $_.HasPrivateKey }).Count) {
    throw 'the signing certificate CN=PIM4EntraPS-Baseline (with its private key) is not in Cert:\LocalMachine\My -- the bundle can only be published on the signing host.'
}
$argLine = Get-PimBaselinePublishTaskArgLine -ScriptPath $BundleScriptPath -CentralServer $CentralServer -Database $Database -StorageAccount $StorageAccount `
    -Container $Container -Scope $Scope -ValidDays $ValidDays -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint

if ($Register) {
    $exe = (Get-Command powershell.exe -CommandType Application | Select-Object -First 1).Source
    Write-Host "==> registering DAILY task '$TaskName' ($($AtHour):00, as $RunAsUser) -- bundle valid $ValidDays days" -ForegroundColor Cyan
    $a = New-ScheduledTaskAction -Execute $exe -Argument $argLine
    $t = New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.AddHours($AtHour))
    $p = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType ServiceAccount -RunLevel Highest
    $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    Register-ScheduledTask -TaskName $TaskName -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
    $back = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $back -or "$($back.Actions[0].Arguments)" -ne $argLine) { throw "read-back FAILED: task '$TaskName' is not registered with the expected command line." }
    Write-Host "    registered and read back. Run now: Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor DarkGray
    exit 0
}
if ($RunNow) {
    & $BundleScriptPath -CentralServer $CentralServer -Database $Database -StorageAccount $StorageAccount -Container $Container -Scope $Scope -ValidDays $ValidDays `
        -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint
    exit $(if ($?) { 0 } else { 1 })
}
Write-Host "task command line (pass -Register to arm it, -RunNow to publish once):`n  powershell.exe $argLine"
