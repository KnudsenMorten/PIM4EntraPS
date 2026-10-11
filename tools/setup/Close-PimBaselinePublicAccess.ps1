#Requires -Version 5.1
<#
.SYNOPSIS
    100.59 -- the MANAGING tenant closes the public-but-signed path of its bundle store, reader by reader, once each reader's
    pull is PROVEN over its own approved private endpoint; public network access is DISABLED only when EVERY reader is private.

.DESCRIPTION
    Reads the store (publicNetworkAccess, its virtual network rules) and its privateEndpointConnections, and decides with
    Get-PimBaselinePublicClosePlan (engine/msp/PIM-MspBuild.ps1):
      * a reader with access privateEndpoint, marked PROVEN (slaves[i].privateEndpointProven -- set after its pullproof step
        printed PROVEN) and with an Approved connection -> its public VNet rule is REMOVED
      * a reader marked proven WITHOUT an approved connection -> REFUSED (its rule is kept)
      * a reader not yet approved / not yet proven -> its rule stays; STOP POINT (exit 10) with the managed tenant's command
      * a reader still public-but-signed -> its rule stays; public network access stays Enabled (reported)
      * every reader private AND the publisher has its own approved endpoint -> public network access DISABLED, last
    Then READS BACK. Exit codes: 0 done (every proven reader private; readers still public reported); 10 STOP POINT;
    1 refused / a write did not hold.

    ROLLBACK (-Rollback): public network access back to Enabled and the VNet rule of every reader given in -Slave that has a
    subnet id put back (merged; nothing else removed). The endpoints stay (harmless).

    -Slave: one string per managed tenant, 'tenantId|subscriptionId|access|proven|subnetId|displayName' (the build writes it
    from slaves[]; ConvertTo-PimMspSlaveSpec). Nothing here is a credential.

    100.41 (framework 12.17 NO-AZ): ARM REST through PIM-Rest's one token client. No az, no module, no SAS, no key.

.EXAMPLE
    .\Close-PimBaselinePublicAccess.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -StorageAccount <store> -Slave '<tenant>|<sub>|privateEndpoint|proven|<subnet id>|Managed tenant one'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$StorageAccount,
    [string[]]$Slave = @(),
    [string]$ResumeCommand,
    [switch]$Rollback
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $solRoot 'engine\msp\PIM-MspBuild.ps1')
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
$S = "$SubscriptionId".Trim()
$resume = if ("$ResumeCommand".Trim()) { "$ResumeCommand".Trim() } else { "$($MyInvocation.MyCommand.Name) (the same arguments)" }
$slaves = @(@($Slave | Where-Object { "$_".Trim() }) | ForEach-Object { ConvertFrom-PimMspSlaveSpec -Spec "$_" })
foreach ($x in $slaves) { if (-not $x.ok) { throw "REFUSED: -Slave: $($x.reason)" } }

if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $S) }
$readStore = { Get-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount -ErrorAsNull }
$sa = & $readStore
if (-not $sa) { throw "storage account '$StorageAccount' not found in $ResourceGroup / $S$(if ($global:PimSetupRestLastError) { " ($($global:PimSetupRestLastError))" })" }
$storeId = "$($sa.id)".Trim()
$ruleIds = { param($acct) @(@($acct.properties.networkAcls.virtualNetworkRules) | Where-Object { $_ } | ForEach-Object { "$($_.id)" }) }
# READ-MODIFY-WRITE of the whole networkAcls (the same shape Set-PimBaselineNetworkAccess.ps1 writes): only the virtual
# network rules change; default action, bypass and IP rules are written back as they are.
$writeRules = {
    param($acct, [string[]]$Ids)
    $acl = $acct.properties.networkAcls
    $ips = @(@($acl.ipRules) | Where-Object { $_ } | ForEach-Object { @{ value = "$($_.value)"; action = 'Allow' } })
    $new = @{ defaultAction = $(if ("$($acl.defaultAction)") { "$($acl.defaultAction)" } else { 'Deny' }); bypass = $(if ("$($acl.bypass)") { "$($acl.bypass)" } else { 'AzureServices' })
              virtualNetworkRules = @(@($Ids) | Where-Object { "$_".Trim() } | ForEach-Object { @{ id = "$_".Trim(); action = 'Allow' } }); ipRules = @($ips) }
    [void](Update-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount -Properties @{ networkAcls = $new })
}

if ($Rollback) {
    Step "ROLLBACK on ${StorageAccount}: public network access Enabled + the readers' VNet rules back (endpoints left in place)"
    $want = New-Object System.Collections.Generic.List[string]
    foreach ($r in @(& $ruleIds $sa)) { $want.Add($r) }
    foreach ($x in $slaves) { if ($x.subnetId -and -not @($want | Where-Object { $_ -ieq $x.subnetId }).Count) { $want.Add($x.subnetId); Note "rule back: $($x.displayName)" } }
    if ($PSCmdlet.ShouldProcess($StorageAccount, 'public network access Enabled + VNet rules back')) {
        & $writeRules $sa @($want.ToArray())
        [void](Update-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount -Properties @{ publicNetworkAccess = 'Enabled' })
        Start-Sleep -Seconds 5
        $sa2 = & $readStore
        $miss = @($want | Where-Object { $w = $_; -not @(& $ruleIds $sa2 | Where-Object { $_ -ieq $w }).Count })
        if ("$($sa2.properties.publicNetworkAccess)" -ne 'Enabled' -or $miss.Count) { throw "rollback read-back: publicNetworkAccess '$($sa2.properties.publicNetworkAccess)', missing rules: $($miss -join ', ')" }
        Write-Host "    ROLLED BACK: public network access Enabled, $($want.Count) VNet rule(s) on $StorageAccount." -ForegroundColor Green
    }
    return
}

Step "close the public path of $StorageAccount, reader by reader"
$conns = @(Invoke-PimSetupArm -Path "$storeId/privateEndpointConnections" -ApiVersion (Get-PimSetupApiVersion storage) -All -NotFoundOk | Where-Object { $null -ne $_ })
$plan = Get-PimBaselinePublicClosePlan -Slaves $slaves -Connections $conns -OwnSubscriptionId $S -CurrentSubnetRules @(& $ruleIds $sa) -PublicNetworkAccess "$($sa.properties.publicNetworkAccess)"
foreach ($l in $plan.lines) { Note $l }
Note "publisher endpoint approved: $($plan.publisherOnPe); public network access now: $($sa.properties.publicNetworkAccess)"
if (-not $plan.ok) { throw ($plan.reasons -join ' | ') }

$remove = @($plan.actions | Where-Object { $_.op -eq 'remove-subnet' } | ForEach-Object { "$($_.value)" })
$disable = [bool]@($plan.actions | Where-Object { $_.op -eq 'disable-public' }).Count
if ($remove.Count -and $PSCmdlet.ShouldProcess($StorageAccount, "remove $($remove.Count) proven reader rule(s)")) {
    $keep = @(@(& $ruleIds $sa) | Where-Object { $r = $_; -not @($remove | Where-Object { $_ -ieq $r }).Count })
    & $writeRules $sa $keep
    Note "removed: $($remove -join ', ')"
}
if ($disable -and $PSCmdlet.ShouldProcess($StorageAccount, 'disable public network access')) {
    [void](Update-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount -Properties @{ publicNetworkAccess = 'Disabled' })
    Note 'public network access DISABLED'
}
if (($remove.Count -or $disable) -and -not $WhatIfPreference) {
    Step 'read back'
    Start-Sleep -Seconds 5
    $sa2 = & $readStore
    $left = @($remove | Where-Object { $r = $_; @(& $ruleIds $sa2 | Where-Object { $_ -ieq $r }).Count })
    if ($left.Count) { throw "read-back: rule(s) still present: $($left -join ', ')" }
    if ($disable -and "$($sa2.properties.publicNetworkAccess)" -ne 'Disabled') { throw "read-back: publicNetworkAccess is '$($sa2.properties.publicNetworkAccess)', want Disabled" }
    Note "read back: rules $(@(& $ruleIds $sa2).Count), publicNetworkAccess $($sa2.properties.publicNetworkAccess)"
}
if (@($plan.stillPublic).Count) { Write-Host "    still public-but-signed (their rule stays, public access stays Enabled): $(@($plan.stillPublic | ForEach-Object { $_.displayName }) -join ', ')" -ForegroundColor Yellow }
if (@($plan.waitingProof).Count) {
    Write-Host ''
    Write-Host '    STOP POINT -- these readers are not proven over their endpoint yet (their public rule stays):' -ForegroundColor Yellow
    foreach ($w in $plan.waitingProof) {
        Write-Host "      $($w.displayName) ($($w.tenantId)): its administrator runs Invoke-PimMspBuild.ps1 -Role Slave -ConfigPath <that tenant's build config> -Apply -From pullendpoint" -ForegroundColor Yellow
        Write-Host '        (pullendpoint then pullproof; when pullproof printed PROVEN, set slaves[<n>].privateEndpointProven = true in THIS build config)' -ForegroundColor DarkGray
    }
    Write-Host "    Then resume here: $resume" -ForegroundColor Yellow
    if ($WhatIfPreference) { return }
    exit 10
}
Write-Host ("    PASS: {0} reader(s) private{1}." -f @($plan.private).Count, $(if ($plan.closed) { "; $StorageAccount public network access Disabled -- reachable only through private endpoints" } else { '; public network access stays Enabled for the readers above' })) -ForegroundColor Green
