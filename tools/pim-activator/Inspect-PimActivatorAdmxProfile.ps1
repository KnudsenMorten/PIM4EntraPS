#Requires -Version 5.1
<#
.SYNOPSIS
    Dump every presentationValue inside the [PimActivator] client settings
    ADMX profile so we can see whether the forcelist field is actually set
    or if it got cleared.
.DESCRIPTION
    Intune "green" on an ADMX policy just means IME successfully wrote what
    the policy said. If the policy's forcelist field is empty / cleared,
    "green" means "I wrote nothing, successfully" -- which is why HKLM
    doesn't have PIM Activator even though the policy reports success.
    Read-only. No writes.
#>
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All' -UseDeviceCode -NoWelcome | Out-Null
$ctx = Get-MgContext
Write-Host ("Connected: {0} (tenant {1})" -f $ctx.Account, $ctx.TenantId) -ForegroundColor Cyan
Write-Host ''

$gpResp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations'
$configs = @($gpResp.value)
while ($gpResp.'@odata.nextLink') { $gpResp = Invoke-MgGraphRequest -Method GET -Uri $gpResp.'@odata.nextLink'; $configs += $gpResp.value }

$pim = $configs | Where-Object { $_.displayName -match 'PimActivator' }
if (-not $pim) { Write-Host "No [PimActivator] client settings profile found" -ForegroundColor Red; exit }

foreach ($p in $pim) {
    Write-Host ("=== {0} (id {1}) ===" -f $p.displayName, $p.id) -ForegroundColor Cyan

    $dvResp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/{0}/definitionValues?`$expand=definition" -f $p.id)
    $dvs = @($dvResp.value)
    while ($dvResp.'@odata.nextLink') { $dvResp = Invoke-MgGraphRequest -Method GET -Uri $dvResp.'@odata.nextLink'; $dvs += $dvResp.value }

    foreach ($dv in $dvs) {
        $defName = $dv.definition.displayName
        Write-Host ("  Definition: {0}" -f $defName) -ForegroundColor Yellow
        Write-Host ("    enabled : {0}" -f $dv.enabled)
        $pvResp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/{0}/definitionValues/{1}/presentationValues?`$expand=presentation" -f $p.id, $dv.id)
        $pvs = @($pvResp.value)
        if (-not $pvs) { Write-Host "    (no presentation values)" -ForegroundColor DarkGray; continue }
        foreach ($pv in $pvs) {
            $pres = $pv.presentation.label
            if (-not $pres) { $pres = $pv.presentation.'@odata.type' }
            Write-Host ("    Presentation: {0}" -f $pres) -ForegroundColor Green
            if ($pv.values) {
                if (@($pv.values).Count -eq 0) {
                    Write-Host "      (values array is EMPTY)" -ForegroundColor Red
                } else {
                    foreach ($v in @($pv.values)) {
                        if ($v -is [System.Collections.IDictionary]) {
                            if ($v.ContainsKey('name')) { Write-Host ("      [{0}] {1}" -f $v['name'], $v['value']) }
                            else                       { Write-Host ("      " + ($v | ConvertTo-Json -Compress)) }
                        } else { Write-Host ("      " + [string]$v) }
                    }
                }
            } elseif ($pv.value) {
                Write-Host ("      {0}" -f $pv.value)
            } else {
                Write-Host ("      raw: " + ($pv | ConvertTo-Json -Depth 5 -Compress)) -ForegroundColor DarkGray
            }
        }
    }
    Write-Host ''

    # Assignments
    $asResp = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/{0}/assignments" -f $p.id)
    Write-Host "  Assignments:" -ForegroundColor Yellow
    if ($asResp.value.Count -eq 0) { Write-Host "    (not assigned to any group)" -ForegroundColor Red }
    foreach ($a in $asResp.value) {
        $t = $a.target.'@odata.type'
        $g = $a.target.groupId
        Write-Host ("    {0}  groupId={1}" -f $t, $g)
    }
    Write-Host ''
}
