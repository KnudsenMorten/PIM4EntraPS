#Requires -Version 5.1
<#
.SYNOPSIS
    Uploads a Detect + Remediate script pair to Intune as a Remediation -- creates it, or updates it in place when a
    Remediation with the same name exists (its assignments are kept). Optional: assign it to a group.

.DESCRIPTION
    For Detect-PimActivator.ps1 + Remediate-PimActivator.ps1 in .\intune-remediation (after you have edited their
    SETTINGS block -- identically in both).
    Always uploaded as: run as SYSTEM, 64-bit PowerShell, no signature check.
    Needs a Microsoft Graph connection first:  Connect-MgGraph -Scopes DeviceManagementScripts.ReadWrite.All

.EXAMPLE
    .\Publish-PimActivatorRemediation.ps1 -Name 'PIM Activator settings (TEST)' `
        -DetectScript .\Detect-PimActivator-TEST.ps1 -RemediateScript .\Remediate-PimActivator-TEST.ps1
.EXAMPLE
    ..\Publish-PimActivatorRemediation.ps1 -Name 'PIM Activator settings (PROD)' `
        -DetectScript .\Detect-PimActivator-PROD.ps1 -RemediateScript .\Remediate-PimActivator-PROD.ps1 `
        -AssignToGroupId <group-id> -EveryHours 1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$DetectScript,
    [Parameter(Mandatory)][string]$RemediateScript,
    [string]$Description = '',
    # Assign to this Entra group (user or device group), daily. REPLACES the Remediation's assignments. Not given = unchanged.
    [ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$AssignToGroupId,
    [ValidatePattern('^\d{2}:\d{2}$')][string]$DailyTime = '09:00',
    # With -AssignToGroupId: run every N hours instead of daily (e.g. 1 = every hour).
    [ValidateRange(1, 23)][int]$EveryHours
)
$ErrorActionPreference = 'Stop'
foreach ($f in $DetectScript, $RemediateScript) { if (-not (Test-Path -LiteralPath $f)) { throw "Script not found: $f" } }
if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue) -or -not (Get-MgContext -ErrorAction SilentlyContinue)) {
    throw 'Connect to Microsoft Graph first: Connect-MgGraph -Scopes DeviceManagementScripts.ReadWrite.All'
}
$base = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'

# find an existing Remediation with this exact name
$all = @(); $resp = Invoke-MgGraphRequest -Method GET -Uri "$base`?`$select=id,displayName"
$all += @($resp.value); while ($resp.'@odata.nextLink') { $resp = Invoke-MgGraphRequest -Method GET -Uri $resp.'@odata.nextLink'; $all += @($resp.value) }
$match = @($all | Where-Object { "$($_.displayName)" -eq $Name })
if ($match.Count -gt 1) { throw "More than one Remediation is named '$Name' -- rename or delete the extras first (refusing to guess which to update)." }

$body = [ordered]@{
    displayName              = $Name
    description              = $(if ($Description) { $Description } else { "PIM Activator -- uploaded by Publish-PimActivatorRemediation.ps1 $((Get-Date).ToString('yyyy-MM-dd HH:mm'))" })
    publisher                = 'PIM4EntraPS'
    runAsAccount             = 'system'
    runAs32Bit               = $false
    enforceSignatureCheck    = $false
    detectionScriptContent   = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $DetectScript)))
    remediationScriptContent = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $RemediateScript)))
}
if ($match) {
    $id = "$($match[0].id)"
    Invoke-MgGraphRequest -Method PATCH -Uri "$base/$id" -Body ($body | ConvertTo-Json) -ContentType 'application/json' | Out-Null
    Write-Host "[OK] Updated '$Name' ($id) -- assignments unchanged." -ForegroundColor Green
} else {
    $body['roleScopeTagIds'] = @('0')
    $id = "$((Invoke-MgGraphRequest -Method POST -Uri $base -Body ($body | ConvertTo-Json) -ContentType 'application/json').id)"
    Write-Host "[OK] Created '$Name' ($id)." -ForegroundColor Green
}

# read it back -- Intune must hold exactly what was uploaded
$back = Invoke-MgGraphRequest -Method GET -Uri "$base/$id"
if ("$($back.detectionScriptContent)" -ne $body.detectionScriptContent -or "$($back.remediationScriptContent)" -ne $body.remediationScriptContent -or "$($back.runAsAccount)" -ne 'system' -or [bool]$back.runAs32Bit) {
    throw "'$Name' ($id) did not read back as uploaded -- check it in Intune."
}
Write-Host '     read back OK: same scripts, runs as SYSTEM, 64-bit.' -ForegroundColor DarkGray

if ($AssignToGroupId) {
    $schedule = if ($EveryHours) { @{ '@odata.type' = '#microsoft.graph.deviceHealthScriptHourlySchedule'; interval = $EveryHours } }
                else { @{ '@odata.type' = '#microsoft.graph.deviceHealthScriptDailySchedule'; interval = 1; useUtc = $false; time = "$DailyTime`:00" } }
    $asg = @{ deviceHealthScriptAssignments = @(@{
        target               = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $AssignToGroupId }
        runRemediationScript = $true
        runSchedule          = $schedule
    }) }
    Invoke-MgGraphRequest -Method POST -Uri "$base/$id/assign" -Body ($asg | ConvertTo-Json -Depth 8) -ContentType 'application/json' | Out-Null
    Write-Host ("[OK] Assigned to group $AssignToGroupId, {0}." -f $(if ($EveryHours) { "every $EveryHours hour(s)" } else { "daily at $DailyTime" })) -ForegroundColor Green
} else {
    $n = @((Invoke-MgGraphRequest -Method GET -Uri "$base/$id/assignments").value).Count
    Write-Host ("     assignments: {0}" -f $(if ($n) { "$n (unchanged)" } else { 'none yet -- assign it in Intune or re-run with -AssignToGroupId' })) -ForegroundColor $(if ($n) { 'DarkGray' } else { 'Yellow' })
}
