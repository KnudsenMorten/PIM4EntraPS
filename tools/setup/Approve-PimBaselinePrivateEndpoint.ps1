#Requires -Version 5.1
<#
.SYNOPSIS
    100.59 -- the MANAGING tenant approves the pending private endpoint connections on its bundle store, from the managed
    tenants it LISTS only (baseline.access = "crossTenantPrivateEndpoint", slaves[i].access = "privateEndpoint").

.DESCRIPTION
    Reads the store's privateEndpointConnections and decides with Get-PimBaselinePeApprovalPlan (engine/msp/PIM-MspBuild.ps1):
      * a PENDING connection whose endpoint lives in a listed managed tenant's SUBSCRIPTION (ARM asserts it) and whose request
        message names no other tenant -> APPROVED (description: who it was approved for)
      * a pending connection from any other subscription -> LEFT PENDING and reported. Never "approve all".
      * this tenant's own connection (the publisher's endpoint) -> not touched
      * -RejectTenantId <id> -> that tenant's connections are REJECTED (revoke from this side)
    Then READS BACK. Exit codes: 0 every listed tenant is approved; 10 STOP POINT -- a listed tenant has not requested its
    endpoint yet (its administrator runs its pullendpoint step; the exact command is printed); 1 refused / a write did not hold.

    -AllowedTenant: one string per managed tenant, 'tenantId|subscriptionId|access|proven|subnetId|displayName' (the build
    writes it from slaves[]; ConvertTo-PimMspSlaveSpec). Nothing here is a credential.

    100.41 (framework 12.17 NO-AZ): ARM REST through PIM-Rest's one token client. No az, no module, no SAS, no key.

.EXAMPLE
    .\Approve-PimBaselinePrivateEndpoint.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -StorageAccount <store> -AllowedTenant '<tenant>|<sub>|privateEndpoint||| Managed tenant one'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$StorageAccount,
    [string[]]$AllowedTenant = @(),
    [string]$RejectTenantId,
    [string]$ResumeCommand
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (Test-Path -LiteralPath ($__msp = Join-Path $solRoot 'engine\msp\PIM-MspBuild.ps1')) { . $__msp } else { throw 'This script is part of PIM Manager Pro (multi-tenant / MSP): engine\msp\PIM-MspBuild.ps1 is not in this installation.' }
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
$S = "$SubscriptionId".Trim()
$resume = if ("$ResumeCommand".Trim()) { "$ResumeCommand".Trim() } else { "$($MyInvocation.MyCommand.Name) (the same arguments)" }
$allowed = @(@($AllowedTenant | Where-Object { "$_".Trim() }) | ForEach-Object { ConvertFrom-PimMspSlaveSpec -Spec "$_" })
foreach ($a in $allowed) { if (-not $a.ok) { throw "REFUSED: -AllowedTenant: $($a.reason)" } }
$allowed = @($allowed | Where-Object { $_.access -eq 'privateEndpoint' })

if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $S) }
$sa = Get-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount -ErrorAsNull
if (-not $sa) { throw "storage account '$StorageAccount' not found in $ResourceGroup / $S$(if ($global:PimSetupRestLastError) { " ($($global:PimSetupRestLastError))" })" }
$storeId = "$($sa.id)".Trim()
$readConns = { @(Invoke-PimSetupArm -Path "$storeId/privateEndpointConnections" -ApiVersion (Get-PimSetupApiVersion storage) -All -NotFoundOk | Where-Object { $null -ne $_ }) }

Step "private endpoint connections on $StorageAccount"
$conns = @(& $readConns)
Note "$($conns.Count) connection(s) on the store"
if (-not $allowed.Count -and -not "$RejectTenantId".Trim()) {
    # Nothing is listed: report what is there and approve nothing (an unattributed request is never approved).
    foreach ($c in $conns) { $v = ConvertTo-PimPeConnectionView -Connection $c; Note ("{0}: {1} (subscription {2}) -- not changed" -f $v.name, $v.status, $v.subscriptionId) }
    Write-Host '    nothing to approve: no managed tenant is listed with access privateEndpoint (slaves[i].access). Every request stays as it is.' -ForegroundColor Yellow
    return
}
$plan = Get-PimBaselinePeApprovalPlan -Connections $conns -Allowed $allowed -OwnSubscriptionId $S -RejectTenantId $RejectTenantId
if (-not $plan.ok) { throw $plan.reason }
foreach ($l in $plan.lines) { Note $l }

$writes = @(@($plan.approve | ForEach-Object { @{ name = $_.name; status = 'Approved'; text = "approved by the PIM Manager build for managed tenant $($_.displayName) ($($_.tenantId))" } }) +
            @($plan.reject | ForEach-Object { @{ name = $_.name; status = 'Rejected'; text = "rejected (revoked) by the PIM Manager build for managed tenant $($_.displayName) ($($_.tenantId))" } }))
foreach ($w in $writes) {
    if (-not $PSCmdlet.ShouldProcess("$StorageAccount/$($w.name)", "$($w.status) private endpoint connection")) { continue }
    $body = @{ properties = @{ privateLinkServiceConnectionState = @{ status = $w.status; description = $w.text; actionRequired = 'None' } } }
    [void](Invoke-PimSetupArm -Method PUT -Path "$storeId/privateEndpointConnections/$($w.name)" -Body $body -ApiVersion (Get-PimSetupApiVersion storage))
    Note "$($w.status): $($w.name)"
}

if ($writes.Count -and -not $WhatIfPreference) {
    Step 'read back'
    Start-Sleep -Seconds 5
    $after = @(& $readConns | ForEach-Object { ConvertTo-PimPeConnectionView -Connection $_ })
    $bad = @(foreach ($w in $writes) { $now = @($after | Where-Object { $_.name -eq $w.name })[0]; if (-not $now -or $now.status -ne $w.status) { "$($w.name) reads '$(if ($now) { $now.status } else { 'absent' })', want $($w.status)" } })
    if ($bad.Count) { throw "the approval did not hold: $($bad -join '; ')" }
    Note "every write reads back ($($writes.Count))"
}
if (@($plan.unknown).Count -or @($plan.mismatch).Count) {
    Write-Host "    $(@($plan.unknown).Count + @($plan.mismatch).Count) request(s) LEFT PENDING (not a listed managed tenant, or the request names another tenant) -- reject them in the portal if they are not yours." -ForegroundColor Yellow
}
if (@($plan.waiting).Count) {
    Write-Host ''
    Write-Host '    STOP POINT -- these managed tenants have not requested their endpoint yet. Each one''s administrator runs:' -ForegroundColor Yellow
    foreach ($w in $plan.waiting) {
        Write-Host "      $($w.displayName) ($($w.tenantId), subscription $($w.subscriptionId)):" -ForegroundColor Yellow
        Write-Host "        Invoke-PimMspBuild.ps1 -Role Slave -ConfigPath <that tenant's build config> -Apply -From pullendpoint" -ForegroundColor Yellow
        Write-Host "        (its config: master.access = 'crossTenantPrivateEndpoint', master.subscriptionId = '$S', master.resourceGroup = '$ResourceGroup', master.storageAccount = '$StorageAccount')" -ForegroundColor DarkGray
    }
    Write-Host "    Then resume here: $resume" -ForegroundColor Yellow
    if ($WhatIfPreference) { return }
    exit 10
}
Write-Host "    PASS: every listed managed tenant's private endpoint is approved on $StorageAccount ($(@($plan.approve).Count) now, $(@($plan.approved).Count) before)$(if (@($plan.reject).Count) { "; $(@($plan.reject).Count) rejected" })." -ForegroundColor Green
