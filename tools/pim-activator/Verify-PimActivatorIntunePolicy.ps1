#Requires -Version 5.1
<#
.SYNOPSIS
    Verify on an Intune-managed Windows endpoint that all three policies of
    the PIM Activator setup have landed in HKLM after the latest Intune sync:
      1. ExtensionInstallForcelist
      2. ExtensionInstallSources
      3. tenantCatalog (under 3rdparty\extensions\<id>\policy)

.DESCRIPTION
    Run on the TARGET laptop / VDI / kiosk after assigning the
    '[PimActivator] All-in-one ...' Configuration Profile to its device
    group. Optionally forces an Intune sync first.

    Does NOT require Microsoft Graph -- pure local registry reads.

.PARAMETER ExtensionId
    Chrome/Edge extension id. Default 'eheocihmlppcophaeakmdenhgcookkab'.

.PARAMETER ForceIntuneSync
    Trigger an immediate Intune MDM sync via Get-ScheduledTask + Start. Use
    when you don't want to wait the ~8h scheduled cycle.

.EXAMPLE
    # After Intune profile assignment, on the target laptop:
    .\Verify-PimActivatorIntunePolicy.ps1 -ForceIntuneSync
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId = 'eheocihmlppcophaeakmdenhgcookkab',

    [Parameter()]
    [switch]$ForceIntuneSync
)

# ---- Intune enrollment + sync check ---------------------------------------
Write-Host '=== Intune enrollment ===' -ForegroundColor Cyan
$enrollKey = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue |
    Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).EnrollmentType -eq 6 } |
    Select-Object -First 1
if (-not $enrollKey) {
    Write-Host '  NOT enrolled in Intune (no MDM enrollment with EnrollmentType=6 found in registry).' -ForegroundColor Red
    Write-Host '  Intune Configuration Profiles will NOT apply on this machine.' -ForegroundColor Red
} else {
    $upn = (Get-ItemProperty $enrollKey.PSPath -ErrorAction SilentlyContinue).UPN
    Write-Host ('  Enrolled: GUID=' + $enrollKey.PSChildName + '  UPN=' + $upn) -ForegroundColor Green
}

if ($ForceIntuneSync) {
    Write-Host ''
    Write-Host '=== Forcing Intune sync ===' -ForegroundColor Cyan
    try {
        $task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -TaskName 'PushLaunch' -ErrorAction Stop | Select-Object -First 1
        if ($task) {
            Start-ScheduledTask -InputObject $task
            Write-Host '  Triggered PushLaunch task. Sync usually completes in 60-180 seconds.' -ForegroundColor Green
            Write-Host '  Waiting 90 seconds before checking registry...' -ForegroundColor Gray
            Start-Sleep -Seconds 90
        } else {
            Write-Host '  PushLaunch task not found. Trigger sync manually: Settings -> Accounts -> Access work or school -> Info -> Sync.' -ForegroundColor Yellow
        }
    } catch {
        Write-Host ('  Could not trigger sync: ' + $_.Exception.Message) -ForegroundColor Yellow
    }
}

# ---- Registry checks ------------------------------------------------------
$checks = @(
    @{ Browser='Edge';   Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist'; Kind='List' }
    @{ Browser='Edge';   Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallSources';   Kind='List' }
    @{ Browser='Edge';   Path=('HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\' + $ExtensionId + '\policy'); Kind='Value'; Name='tenantCatalog' }
    @{ Browser='Chrome'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist'; Kind='List' }
    @{ Browser='Chrome'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallSources';   Kind='List' }
    @{ Browser='Chrome'; Path=('HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\' + $ExtensionId + '\policy'); Kind='Value'; Name='tenantCatalog' }
)

$pass = 0
$fail = 0
foreach ($c in $checks) {
    Write-Host ''
    Write-Host ('=== [' + $c.Browser + '] ' + $c.Path + ' ===') -ForegroundColor Cyan
    if (-not (Test-Path -LiteralPath $c.Path)) {
        Write-Host '  MISSING -- registry path does not exist (policy not landed yet on this device)' -ForegroundColor Red
        $fail++
        continue
    }
    if ($c.Kind -eq 'List') {
        $item = Get-Item -LiteralPath $c.Path
        $props = $item.GetValueNames() | Sort-Object
        if ($props.Count -eq 0) {
            Write-Host '  PRESENT but EMPTY (no slot values)' -ForegroundColor Yellow
            $fail++
        } else {
            foreach ($p in $props) {
                $v = (Get-ItemProperty -LiteralPath $c.Path -Name $p).$p
                Write-Host ("  slot '$p' = $v") -ForegroundColor Green
            }
            $pass++
        }
    } else {
        try {
            $v = (Get-ItemProperty -LiteralPath $c.Path -Name $c.Name -ErrorAction Stop).($c.Name)
            $preview = if ($v.Length -gt 200) { $v.Substring(0,200) + '... (' + $v.Length + ' chars)' } else { $v }
            Write-Host ('  ' + $c.Name + ' = ' + $preview) -ForegroundColor Green
            $pass++
        } catch {
            Write-Host ("  MISSING value '" + $c.Name + "': " + $_.Exception.Message) -ForegroundColor Red
            $fail++
        }
    }
}

Write-Host ''
Write-Host '=== Summary ===' -ForegroundColor Cyan
$summaryColor = if ($fail -eq 0) { 'Green' } else { 'Yellow' }
$failColor    = if ($fail -gt 0) { 'Red' }   else { 'Gray' }
Write-Host ('  Pass: ' + $pass + ' / ' + ($pass + $fail)) -ForegroundColor $summaryColor
Write-Host ('  Fail: ' + $fail) -ForegroundColor $failColor
if ($fail -gt 0) {
    Write-Host ''
    Write-Host 'If anything is MISSING:' -ForegroundColor Yellow
    Write-Host '  1. Confirm the Intune profile is assigned to a group THIS device is in.' -ForegroundColor Yellow
    Write-Host '  2. Force a sync: Settings -> Accounts -> Access work or school -> Info -> Sync.' -ForegroundColor Yellow
    Write-Host '  3. Re-run this script with -ForceIntuneSync after 2-3 min.' -ForegroundColor Yellow
    Write-Host '  4. In Intune admin center, check the profile reports -> per-setting status for THIS device.' -ForegroundColor Yellow
}
