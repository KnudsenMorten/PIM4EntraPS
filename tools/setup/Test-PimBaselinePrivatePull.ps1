#Requires -Version 5.1
<#
.SYNOPSIS
    100.59 (3) -- the MANAGED tenant PROVES its pull over its own cross-tenant private endpoint before the managing tenant
    removes the public path (master.access = "crossTenantPrivateEndpoint").

.DESCRIPTION
    Two halves, both read back (Test-PimCrossTenantPullProof in engine/msp/PIM-MspBuild.ps1 decides):
      network  the endpoint pe-<store>-blob-xt is Approved and has a private address; this tenant's
               privatelink.blob.core.windows.net zone holds EXACTLY that address for <store> and is linked (NxDomainRedirect)
               to the VNet of the pull job's Container Apps environment -- so the job resolves <store>.blob.core.windows.net
               to the endpoint, not to the public address
      pull     ONE execution of the pull job started for the proof: Succeeded, and its log shows the bundle loaded (the pull
               refuses a bundle whose signature does not verify, so 'loaded' is the signature verdict; 'UNCHANGED' means it was
               fetched and is the bundle last verified)
    Exit codes: 0 PROVEN (prints what the managing tenant does next); 10 STOP POINT -- no real pull ran (the cadence gate
    skipped it, or its log is not in Log Analytics yet): the exact way to get one is printed; 1 the network is not as intended
    or the pull failed.
    -NoStart judges the newest execution instead of starting one.

    100.41 (framework 12.17 NO-AZ): ARM REST through PIM-Rest's one token client. No az, no module, no SAS, no key.

.EXAMPLE
    .\Test-PimBaselinePrivatePull.ps1 -SubscriptionId <sub> -ResourceGroup rg-automateit-<token> -EnvName cae-pim-ext -MasterStorageAccount <store> -JobName ca-pim-downlink-s6
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$EnvName,
    [Parameter(Mandatory)][string]$MasterStorageAccount,
    [Parameter(Mandatory)][string]$JobName,
    [string]$TenantId,
    [string]$PrivateDnsResourceGroup,
    [int]$TimeoutMinutes = 20,
    [string]$ResumeCommand,
    [switch]$NoStart
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (Test-Path -LiteralPath ($__msp = Join-Path $solRoot 'engine\msp\PIM-MspBuild.ps1')) { . $__msp } else { throw 'This script is part of PIM Manager Pro (multi-tenant / MSP): engine\msp\PIM-MspBuild.ps1 is not in this installation.' }
. (Join-Path $solRoot 'engine\_shared\PIM-JobCadence.ps1')   # the cadence gate's skip marker
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
$S = "$SubscriptionId".Trim()
$store = "$MasterStorageAccount".Trim().ToLowerInvariant()
if ($store -notmatch '^[a-z0-9]{3,24}$') { throw "'$MasterStorageAccount' is not a storage account name" }
$zone = 'privatelink.blob.core.windows.net'
$dnsRg = if ("$PrivateDnsResourceGroup".Trim()) { "$PrivateDnsResourceGroup".Trim() } else { $ResourceGroup }
$peName = Get-PimCrossTenantPeName -StorageAccount $store
$resume = if ("$ResumeCommand".Trim()) { "$ResumeCommand".Trim() } else { "$($MyInvocation.MyCommand.Name) (the same arguments)" }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $S) }

Step "network: $peName, this tenant's $zone record and link"
$pe = Get-PimArmPrivateEndpoint -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $peName -ErrorAsNull
if (-not $pe) { throw "the private endpoint '$peName' does not exist -- run the pullendpoint step first (Request-PimBaselinePrivateEndpoint.ps1)" }
$conn = @(@($pe.properties.manualPrivateLinkServiceConnections) + @($pe.properties.privateLinkServiceConnections) | Where-Object { $null -ne $_ })[0]
$connStatus = "$($conn.properties.privateLinkServiceConnectionState.status)".Trim()
$nicIp = ''
$nicId = "$(@($pe.properties.networkInterfaces)[0].id)"
if ($nicId) { $nicIp = "$(@((Get-PimArmResource -ResourceId $nicId -Kind network -ErrorAsNull).properties.ipConfigurations)[0].properties.privateIPAddress)".Trim() }
$snId = "$((Get-PimArmAcaEnv -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $EnvName -ErrorAsNull).properties.vnetConfiguration.infrastructureSubnetId)".Trim()
$vnetId = if ($snId -match '^(.*/virtualNetworks/[^/]+)/subnets/') { $Matches[1] } else { '' }
if (-not $vnetId) { throw "the Container Apps environment '$EnvName' names no infrastructure subnet -- the pull job's VNet cannot be read" }
$linkName = "link-$(($vnetId -split '/')[-1])"
$lk = Get-PimArmPrivateDnsLink -SubscriptionId $S -ResourceGroup $dnsRg -ZoneName $zone -Name $linkName -ErrorAsNull
$recIps = @(@((Get-PimArmPrivateDnsARecord -SubscriptionId $S -ResourceGroup $dnsRg -ZoneName $zone -Name $store -ErrorAsNull).properties.aRecords) | Where-Object { $_ } | ForEach-Object { "$($_.ipv4Address)".Trim() } | Where-Object { $_ })
$state = @{ connectionStatus = $connStatus; endpointIp = $nicIp; dnsRecordIps = $recIps; linkVnetId = "$($lk.properties.virtualNetwork.id)"; expectedVnetId = $vnetId
            linkResolutionPolicy = "$($lk.properties.resolutionPolicy)"; executionStatus = ''; logText = ''; cadenceSkipped = $false }
$net = Test-PimCrossTenantPullProof -State $state
if (@($net.reasons).Count) { foreach ($l in $net.lines) { Note $l }; throw "the private path is NOT as intended: $($net.reasons -join '; ')" }

Step "pull: one execution of $JobName over that path"
$exec = ''
if (-not $NoStart) {
    if (-not $PSCmdlet.ShouldProcess($JobName, 'start one pull execution (the proof)')) { foreach ($l in $net.lines) { Note $l }; Note "What if: start $JobName and judge that execution"; return }
    $exec = Start-PimArmAcaJob -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $JobName
    if (-not "$exec".Trim()) { throw "starting $JobName FAILED: $($global:PimSetupRestLastError)" }
    Note "execution $exec started"
} else {
    $all = @(Get-PimArmAcaJobExecutions -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $JobName | Where-Object { $_ } | Sort-Object { try { [datetime]$_.properties.startTime } catch { [datetime]::MinValue } } -Descending)
    if ($all.Count) { $exec = "$($all[0].name)" }
    if (-not $exec) { throw "-NoStart: $JobName has no execution to judge" }
    Note "judging the newest execution $exec"
}
$deadline = (Get-Date).AddMinutes([Math]::Max(1, $TimeoutMinutes))
$st = ''
while ($true) {
    $st = "$((Get-PimArmAcaJobExecution -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $JobName -Execution $exec).properties.status)".Trim()
    if ($st -and $st -notmatch '(?i)^(Running|Processing|Pending)$') { break }
    if ((Get-Date) -ge $deadline) { break }
    Start-Sleep -Seconds 15
}
Note "execution status: $(if ($st) { $st } else { 'unknown' })"
# the console lines reach the environment's Log Analytics workspace a few minutes after the execution
$log = ''
while ($st -and $st -notmatch '(?i)^(Running|Processing|Pending)$') {
    $log = @(Get-PimArmAcaJobLogs -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $JobName -Execution $exec -Tail 300 -EnvironmentName $EnvName) -join "`n"
    if ("$log".Trim() -match '(?i)downlink JOB (SUCCEEDED|FAILED|UNCHANGED|HELD)|nothing to do on this trigger') { break }
    if ((Get-Date) -ge $deadline) { break }
    Start-Sleep -Seconds 30
}
$state.executionStatus = $st; $state.logText = $log; $state.cadenceSkipped = [bool](Get-PimJobCadenceSkipFromLog -LogText $log).skipped
$v = Test-PimCrossTenantPullProof -State $state
foreach ($l in $v.lines) { Note $l }
if ($v.stop) {
    Write-Host ''
    Write-Host "    STOP POINT -- no real pull over the endpoint yet (execution $exec):" -ForegroundColor Yellow
    if ($state.cadenceSkipped) { Write-Host "      the cadence gate skipped it. In THIS tenant's PIM Manager: Jobs > Job schedule > Managed-tenant pull > Run pull now, wait for it, then resume." -ForegroundColor Yellow }
    else { Write-Host '      the execution has not finished, or its log is not in Log Analytics yet -- wait a few minutes, then resume.' -ForegroundColor Yellow }
    Write-Host "    Resume: $resume" -ForegroundColor Yellow
    exit 10
}
if (-not $v.ok) { throw "the pull is NOT proven over the private endpoint: $($v.reasons -join '; ')" }
$tidTxt = if ("$TenantId".Trim()) { "tenantId '$("$TenantId".Trim().ToLowerInvariant())'" } else { 'this tenant' }
Write-Host "    PROVEN: $JobName pulled the signed bundle over $peName ($store -> $nicIp)." -ForegroundColor Green
Write-Host "    Next, on the MANAGING tenant: set slaves[<n>].privateEndpointProven = true for $tidTxt in its build config and run" -ForegroundColor Yellow
Write-Host "      Invoke-PimMspBuild.ps1 -Role Master -ConfigPath <the managing tenant's build config> -Apply -From peclose" -ForegroundColor Yellow
Write-Host '    (it removes this tenant''s public rule; public network access is disabled once every reader is private).' -ForegroundColor DarkGray
