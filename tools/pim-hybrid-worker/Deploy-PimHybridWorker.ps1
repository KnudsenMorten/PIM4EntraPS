#Requires -Version 5.1

<#
.SYNOPSIS
    PIM Manager hybrid worker (PIM for Active Directory): deploy it end to end with one command -- in Azure (a new Azure VM)
    or on your own on-premises Windows server that is Azure Arc-enabled.

.DESCRIPTION
    Deploys the PIM for Active Directory hybrid worker in the right order, step by step, and remembers where it got to so it can stop for the Active Directory step and continue later.
    It runs the worker's own scripts (tools\pim-hybrid-worker) in this order:

      -Target Azure   1 infra      New-PimHybridWorkerInfra.ps1 (resource group, VNet, deny-all NSG, NAT gateway egress, the VM)
                      2 peering    Set-PimHybridWorkerPeering.ps1 -State Show (the peerings are there and connected)
                      3 egress     Set-PimHybridWorkerEgress.ps1 (no public IP on the VM; outbound through the NAT gateway)
                      4 ad         printed: the exact Initialize-PimHybridWorkerAd.ps1 command for the AD administrator to run on
                                   a domain controller -- then STOP (exit 10) until it is done
                      5 join       Install-PimHybridWorker.ps1 -Phase Join through run-command (offline domain join + reboot)
                      6 grant      Grant-PimHybridWorkerAccess.ps1 (SQL contained user, Graph read roles, source-store reader)
                      7 kds        a KDS root key created by the AD step is usable only ~10 hours later: STOP (exit 12) until then
                      8 configure  Install-PimHybridWorker.ps1 -Phase Configure through run-command (needs the grant from 6)
                      9 verify     the Configure run finished, the tasks are registered
      -Target Arc     the same without infra / peering / egress / join: 1 checks the Arc machine (connected, Windows,
                      a system-assigned identity) and builds NOTHING in Azure; the on-premises network is yours.

    PLAN FIRST: without -Apply it prints the plan and the commands it would run, and changes nothing (-WhatIf is the same).
    -Apply runs the steps. -Resume continues from the state file ($env:LOCALAPPDATA\pim\hybrid\deploy-<target>-<name>.json;
    the newest one when -StatePath is not given) -- every value given on the first run is remembered (never a secret: the
    offline-join blob is passed again with -OdjBlob / -OdjBlobFile). Exit codes: 0 done, 10 waiting for the AD step, 11
    waiting for a script the server administrator runs locally (run-command was not available), 12 waiting for the KDS root
    key, 1 failed.

    Network options (§100.63), passed to the infra step only when given: -UseRemoteGateways -GatewayVnetId <hub>
    -AllowForwardedTraffic (DCs behind a hub VPN / ExpressRoute gateway), -PrivateSqlDnsZoneId / -PrivateDnsLinkVnetId /
    -CreatePrivateDnsZone -PrivateDnsZoneResourceGroup / -PrivateSql / -DnsForwarderIp (a private-only PIM database: the
    standard privatelink zone is linked, the DNS forwarder for your DCs is printed). Remove-PimHybridWorker.ps1 undoes it all.

    One REST session, pinned to -TenantId (the Invardia Support app's session, or the person signed in in the browser),
    shared by every step. No az, no PowerShell module.

.EXAMPLE
    # on-premises (Azure Arc): plan, then apply
    .\Deploy-PimHybridWorker.ps1 -Target Arc -SubscriptionId <sub> -TenantId <tenant> `
        -ArcMachineResourceId /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.HybridCompute/machines/<server> `
        -SqlServerId <sql-server-id> -SourceContainerId <storage-id>/blobServices/default/containers/pim-src -Ring 2 `
        -AdDomain CORP -ComputerOu 'OU=Tier0 Servers,DC=corp,DC=local' -GmsaOu 'OU=Service Accounts,DC=corp,DC=local' `
        -GroupsOu 'OU=PIM Groups,DC=corp,DC=local' -AdminAccountsOu 'OU=Admin Accounts,DC=corp,DC=local'
    .\Deploy-PimHybridWorker.ps1 ...same... -Apply              # stops at the AD step (exit 10)
    .\Deploy-PimHybridWorker.ps1 -Resume -Apply                  # after the AD administrator ran the printed command

.LINK
    https://invardia.com/docs/pim/scripts/Deploy-PimHybridWorker/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Azure', 'Arc')][string]$Target,
    [string]$SubscriptionId,
    [string]$TenantId,
    # Azure
    [string]$ResourceGroup = 'rg-pimhybridwrk',
    [string]$Location = 'westeurope',
    [string]$VmName = 'PIMHYBRIDWRK',
    [string]$VmSize = 'Standard_B2s',
    [string]$VnetName = 'vnet-pimhybridwrk',
    [string]$AddressPrefix = '10.221.16.0/24',
    [string]$SubnetPrefix = '10.221.16.0/27',
    [string[]]$PeerVnetId = @(),
    [string[]]$DnsServers = @(),
    [ValidateSet('NatGateway', 'None')][string]$Egress = 'NatGateway',
    # §100.63 DCs behind a hub VPN / ExpressRoute gateway (Set-PimHybridWorkerPeering.ps1 sets the flags)
    [switch]$UseRemoteGateways,
    [string]$GatewayVnetId = '',
    [switch]$AllowForwardedTraffic,
    # §100.63 a private-only PIM SQL: link the standard privatelink.database.windows.net zone + print the DNS forwarder
    [string]$PrivateSqlDnsZoneId = '',
    [string[]]$PrivateDnsLinkVnetId = @(),
    [switch]$CreatePrivateDnsZone,
    [string]$PrivateDnsZoneResourceGroup = '',
    [switch]$PrivateSql,
    [string]$DnsForwarderIp = '',
    # Arc
    [string]$ArcMachineResourceId = '',
    [string[]]$SqlAllowedPublicIp = @(),
    # the PIM environment
    [string]$SqlServerId = '',
    [string]$SqlDatabase = 'PimPlatform',
    [string]$SqlUserName = 'PIMHYBRIDWRK',
    [string]$SourceContainerId = '',
    [string]$Ring = '',
    [string]$Version = '',
    [switch]$GrantMailSend,
    [switch]$PlanOnly,
    # Active Directory (printed for the AD administrator; the worker is configured with them)
    [string]$AdDomain = '',
    [string]$WorkerComputerName = '',
    [string]$ComputerOu = '',
    [string]$GmsaName = 'gMSA-PIM-L1-T0',
    [string]$GmsaOu = '',
    [string]$GroupsOu = '',
    [string[]]$AdminAccountsOu = @(),
    [string]$ServerGmsaName = '',
    [string[]]$ServerOu = @(),
    [switch]$GrantProtectedGroupMembership,
    [switch]$CreateKdsRootKey,
    [string]$AdServer = '',
    # flow
    [switch]$Apply,
    [switch]$Resume,
    [string]$StatePath = '',
    [string]$KdsRootKeyCreatedUtc = '',
    [string]$OdjBlob = '',
    [string]$OdjBlobFile = '',
    [switch]$PrintOnly,
    [int]$JoinRebootWaitSeconds = 240,
    [string]$ScriptRoot = ''
)
$ErrorActionPreference = 'Stop'

# 12.7 run frame: "<Script> version <x.y.z> - documentation: <page>" as the first line + a transcript in the temp folder.
. (Join-Path $PSScriptRoot '..\setup\_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Deploy-PimHybridWorker'
$exitCode = 0
try {

function Step($m) { Write-Host "[deploy] $m" -ForegroundColor Cyan }
function Info($m) { Write-Host "         $m" -ForegroundColor Gray }
function Warn($m) { Write-Host "         $m" -ForegroundColor Yellow }
$here = if ("$ScriptRoot".Trim()) { "$ScriptRoot".Trim() } else { $PSScriptRoot }   # test seam: the child scripts' folder
function Child([string]$Name) { Join-Path $here $Name }

# ---------------------------------------------------------------------------------------------------------- state
$stateDir = Join-Path $(if ("$env:LOCALAPPDATA".Trim()) { $env:LOCALAPPDATA } else { [IO.Path]::GetTempPath() }) 'pim\hybrid'
$remember = @('Target', 'SubscriptionId', 'TenantId', 'ResourceGroup', 'Location', 'VmName', 'VmSize', 'VnetName', 'AddressPrefix', 'SubnetPrefix',
              'PeerVnetId', 'DnsServers', 'Egress', 'ArcMachineResourceId', 'SqlAllowedPublicIp', 'SqlServerId', 'SqlDatabase', 'SqlUserName',
              'SourceContainerId', 'Ring', 'Version', 'GrantMailSend', 'PlanOnly', 'AdDomain', 'WorkerComputerName', 'ComputerOu', 'GmsaName',
              'GmsaOu', 'GroupsOu', 'AdminAccountsOu', 'ServerGmsaName', 'ServerOu', 'GrantProtectedGroupMembership', 'CreateKdsRootKey', 'AdServer',
              'UseRemoteGateways', 'GatewayVnetId', 'AllowForwardedTraffic', 'PrivateSqlDnsZoneId', 'PrivateDnsLinkVnetId', 'CreatePrivateDnsZone',
              'PrivateDnsZoneResourceGroup', 'PrivateSql', 'DnsForwarderIp')
$state = $null
if ($Resume) {
    $sp = "$StatePath".Trim()
    if (-not $sp) { $sp = @(Get-ChildItem -LiteralPath $stateDir -Filter 'deploy-*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1 | ForEach-Object { $_.FullName })[0] }
    if (-not $sp -or -not (Test-Path -LiteralPath $sp)) { throw "-Resume: no state file found (looked in $stateDir) -- start without -Resume" }
    $state = [IO.File]::ReadAllText($sp) | ConvertFrom-Json
    $StatePath = $sp
    foreach ($k in $remember) {
        if ($PSBoundParameters.ContainsKey($k)) { continue }                    # a value given now wins
        $p = $state.parameters.PSObject.Properties[$k]
        if (-not $p) { continue }
        $v = $p.Value
        if ((Get-Variable -Name $k).Value -is [switch]) { Set-Variable -Name $k -Value ([switch][bool]$v) }
        elseif ((Get-Variable -Name $k).Value -is [array]) { Set-Variable -Name $k -Value @($v | Where-Object { $null -ne $_ } | ForEach-Object { "$_" }) }
        else { Set-Variable -Name $k -Value "$v" }
    }
    Step "resuming $StatePath"
}
if (-not $Target) { throw '-Target Azure|Arc is required (or -Resume)' }
foreach ($req in 'SubscriptionId', 'TenantId', 'SqlServerId', 'SourceContainerId', 'AdDomain', 'ComputerOu', 'GmsaOu', 'GroupsOu') {
    if (-not "$((Get-Variable -Name $req).Value)".Trim()) { throw "-$req is required" }
}
if (-not "$Ring".Trim() -and -not "$Version".Trim()) { throw '-Ring (the update ring this environment follows) or -Version is required' }
if ($Target -eq 'Azure') {
    if (-not @($PeerVnetId).Count -or -not @($DnsServers).Count) { throw '-Target Azure needs -PeerVnetId (the network with the domain controllers) and -DnsServers (the DCs)' }
    if ($VmName -notmatch '^[A-Za-z0-9-]{1,15}$') { throw "-VmName '$VmName' is not a valid computer name" }
} else {
    if ($ArcMachineResourceId -notmatch '^/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/Microsoft\.HybridCompute/machines/([^/]+)$') { throw '-Target Arc needs -ArcMachineResourceId (/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.HybridCompute/machines/<server>)' }
    if ($Matches[1] -ne $SubscriptionId) { throw "the Arc machine is in subscription $($Matches[1]), not -SubscriptionId $SubscriptionId" }
}
if ($SqlServerId -notmatch '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Sql/servers/([^/]+)$') { throw "-SqlServerId is not a SQL server resource id: '$SqlServerId'" }
$sqlFqdn = "$($Matches[1]).database.windows.net"
if ($SourceContainerId -notmatch '/providers/Microsoft\.Storage/storageAccounts/([^/]+)/blobServices/default/containers/([^/]+)$') { throw "-SourceContainerId is not a blob container resource id: '$SourceContainerId'" }
$sourceUrl = "https://$($Matches[1]).blob.core.windows.net/$($Matches[2])"
$machineName = if ($Target -eq 'Azure') { $VmName } else { ($ArcMachineResourceId -split '/')[-1] }
if (-not "$WorkerComputerName".Trim()) { $WorkerComputerName = $machineName }
if (-not "$StatePath".Trim()) { $StatePath = Join-Path $stateDir ("deploy-{0}-{1}.json" -f $Target.ToLowerInvariant(), $machineName.ToLowerInvariant()) }
if (-not $state) {
    $state = [pscustomobject]@{ target = $Target; createdUtc = (Get-Date).ToUniversalTime().ToString('o'); steps = [pscustomobject]@{}; machineId = ''; principalId = ''; kdsRootKeyCreatedUtc = ''; parameters = [pscustomobject]@{} }
}
if ("$KdsRootKeyCreatedUtc".Trim()) { $state.kdsRootKeyCreatedUtc = "$KdsRootKeyCreatedUtc".Trim() }
$pp = [ordered]@{}; foreach ($k in $remember) { $v = (Get-Variable -Name $k).Value; $pp[$k] = $(if ($v -is [switch]) { [bool]$v } else { $v }) }
$state.parameters = [pscustomobject]$pp
function Save-State {
    if (-not $Apply) { return }
    $d = Split-Path -Parent $StatePath
    if (-not (Test-Path -LiteralPath $d)) { [void](New-Item -ItemType Directory -Path $d -Force -WhatIf:$false -Confirm:$false) }
    [IO.File]::WriteAllText($StatePath, ($state | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
}
function Get-StepStatus([string]$Name) { $p = $state.steps.PSObject.Properties[$Name]; if ($p) { return "$($p.Value.status)" }; return '' }
function Set-StepStatus([string]$Name, [string]$Status, [string]$Detail = '') {
    $v = [pscustomobject]@{ status = $Status; atUtc = (Get-Date).ToUniversalTime().ToString('o'); detail = $Detail }
    if ($state.steps.PSObject.Properties[$Name]) { $state.steps.$Name = $v } else { $state.steps | Add-Member -NotePropertyName $Name -NotePropertyValue $v }
    Save-State
}

# ---------------------------------------------------------------------------------------------------------- the steps
$steps = if ($Target -eq 'Azure') { @('infra', 'peering', 'egress', 'ad', 'join', 'grant', 'kds', 'configure', 'verify') } else { @('infra', 'ad', 'grant', 'kds', 'configure', 'verify') }
$gmsaFull = "$AdDomain\$GmsaName"
$srvFull = if ("$ServerGmsaName".Trim()) { "$AdDomain\$ServerGmsaName" } else { '' }
function Get-AdCommand {
    $q = { param($s) "'" + ("$s" -replace "'", "''") + "'" }
    $c = ".\Initialize-PimHybridWorkerAd.ps1 -WorkerComputerName $WorkerComputerName -ComputerOu $(& $q $ComputerOu) -GmsaName $GmsaName -GmsaOu $(& $q $GmsaOu) -GroupsOu $(& $q $GroupsOu)"
    if (@($AdminAccountsOu | Where-Object { "$_".Trim() }).Count) { $c += ' -AdminAccountsOu ' + ((@($AdminAccountsOu | Where-Object { "$_".Trim() } | ForEach-Object { & $q $_ })) -join ',') }
    if ("$ServerGmsaName".Trim()) { $c += " -ServerGmsaName $ServerGmsaName -ServerOu " + ((@($ServerOu | Where-Object { "$_".Trim() } | ForEach-Object { & $q $_ })) -join ',') }
    if ($GrantProtectedGroupMembership) { $c += ' -GrantProtectedGroupMembership' }
    if ($CreateKdsRootKey) { $c += ' -CreateKdsRootKey' }
    if ($Target -eq 'Azure') { $c += ' -ProvisionOdj' }
    return $c
}
function Get-InstallArgs([string]$Phase) {
    $a = @{ HostType = $(if ($Target -eq 'Arc') { 'Arc' } else { 'AzureVm' }) }
    if ($Phase -eq 'Configure') {
        $a.GmsaName = $gmsaFull; $a.SqlServer = $sqlFqdn; $a.SqlDatabase = $SqlDatabase; $a.TenantId = $TenantId; $a.SourceContainerUrl = $sourceUrl
        if ("$Ring".Trim()) { $a.Ring = "$Ring".Trim() }
        if ("$Version".Trim()) { $a.Version = "$Version".Trim() }
        if ($srvFull) { $a.ServerGmsaName = $srvFull }
        if ("$AdServer".Trim()) { $a.AdServer = "$AdServer".Trim() }
        if ($PlanOnly) { $a.PlanOnly = $true }
    }
    return $a
}
function Get-InfraOptions {
    # §100.63 the optional network settings, passed ONLY when given (so the infra step's plain call stays as it was)
    $o = @{}
    if ($Target -eq 'Azure') {
        if ($UseRemoteGateways) { $o.UseRemoteGateways = $true }
        if ($AllowForwardedTraffic) { $o.AllowForwardedTraffic = $true }
        if ("$GatewayVnetId".Trim()) { $o.GatewayVnetId = "$GatewayVnetId".Trim() }
    }
    if ("$PrivateSqlDnsZoneId".Trim()) { $o.PrivateSqlDnsZoneId = "$PrivateSqlDnsZoneId".Trim() }
    if (@($PrivateDnsLinkVnetId | Where-Object { "$_".Trim() }).Count) { $o.PrivateDnsLinkVnetId = @($PrivateDnsLinkVnetId | Where-Object { "$_".Trim() }) }
    if ($CreatePrivateDnsZone) { $o.CreatePrivateDnsZone = $true }
    if ("$PrivateDnsZoneResourceGroup".Trim()) { $o.PrivateDnsZoneResourceGroup = "$PrivateDnsZoneResourceGroup".Trim() }
    if ($PrivateSql) { $o.PrivateSql = $true }
    if ("$DnsForwarderIp".Trim()) { $o.DnsForwarderIp = "$DnsForwarderIp".Trim() }
    return $o
}
if ($Target -eq 'Arc' -and ($UseRemoteGateways -or $AllowForwardedTraffic -or "$GatewayVnetId".Trim())) { throw '-UseRemoteGateways / -AllowForwardedTraffic / -GatewayVnetId are for -Target Azure (an Arc server''s network is yours)' }
$netNote = @(
    $(if ($UseRemoteGateways) { "hub gateway via $(("$GatewayVnetId" -split '/')[-1])" }),
    $(if ($AllowForwardedTraffic) { 'forwarded traffic accepted' }),
    $(if ("$PrivateSqlDnsZoneId".Trim() -or "$PrivateDnsZoneResourceGroup".Trim()) { 'private SQL DNS zone linked' } elseif ($PrivateSql) { 'private SQL (DNS forwarder printed)' })) | Where-Object { $_ }
$describe = @{
    infra     = $(if ($Target -eq 'Azure') { "New-PimHybridWorkerInfra.ps1: resource group $ResourceGroup, VNet $VnetName ($AddressPrefix), deny-all NSG, egress $Egress, VM $VmName ($VmSize), peered to $(@($PeerVnetId).Count) network(s)$(if (@($netNote).Count) { "; " + (@($netNote) -join ", ") })" } else { "New-PimHybridWorkerInfra.ps1 -ArcMachineResourceId: check the Arc machine $machineName (connected, Windows, system-assigned identity); build nothing in Azure" })
    peering   = "Set-PimHybridWorkerPeering.ps1 -State Show: the peerings of $VnetName are connected"
    egress    = "Set-PimHybridWorkerEgress.ps1: no public IP on $VmName, outbound through the NAT gateway"
    ad        = "the AD administrator runs on a domain controller: $(Get-AdCommand)"
    join      = "Install-PimHybridWorker.ps1 -Phase Join on $VmName through run-command (offline domain join, reboot)"
    grant     = "Grant-PimHybridWorkerAccess.ps1: SQL user $SqlUserName on $sqlFqdn/$SqlDatabase (db_datareader + db_datawriter), Graph read roles$(if ($GrantMailSend) { ' + Mail.Send' }), Storage Blob Data Reader on the source container"
    kds       = 'wait until a KDS root key created by the AD step is ~10 hours old (gMSAs cannot be used before)'
    configure = "Install-PimHybridWorker.ps1 -Phase Configure on $machineName through run-command (gMSA $gmsaFull$(if ($srvFull) { " + $srvFull" }), ring $Ring$Version$(if ($PlanOnly) { ', PLAN ONLY' }))"
    verify    = 'the Configure run finished and the worker tasks are registered'
}

if (-not $Apply -or $WhatIfPreference) {
    Step "PLAN (-Target $Target, $machineName) -- nothing is changed; add -Apply to run it"
    $i = 0
    foreach ($s in $steps) { $i++; $st = Get-StepStatus $s; Info ("{0}. {1,-9} {2}{3}" -f $i, $s, $describe[$s], $(if ($st) { "  [$st]" } else { '' })) }
    Info "state file: $StatePath"
    return
}

# one REST session, pinned to -TenantId, shared by every child script (they reuse it: PIM_SetupRestMode is set)
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId) }
if ("$($global:PIM_TenantId)".Trim() -and "$($global:PIM_TenantId)".Trim().ToLowerInvariant() -ne "$TenantId".Trim().ToLowerInvariant()) { throw "the REST session is signed in to tenant '$($global:PIM_TenantId)', not '$TenantId' -- refusing" }
$acct = Get-PimArmSubscription -SubscriptionId $SubscriptionId
if ("$($acct.tenantId)" -ne $TenantId) { throw "subscription $SubscriptionId reads tenant '$($acct.tenantId)', not '$TenantId' -- refusing" }
Step "tenant $TenantId, subscription $SubscriptionId, -Target $Target ($machineName)"
Save-State

$common = @{ SubscriptionId = $SubscriptionId; TenantId = $TenantId }
$stopped = $false
foreach ($s in $steps) {
    $st = Get-StepStatus $s
    if ($st -eq 'done') { Info "$s -- done earlier"; continue }
    if ($st -eq 'local-script') { Warn "$s -- the server administrator was to run the local script; taken as done (re-run that step's script if it was not)"; Set-StepStatus $s 'done' 'local script (by the administrator)'; continue }
    Step "$s -- $($describe[$s])"
    switch ($s) {
        'infra' {
            $opt = Get-InfraOptions
            $r = if ($Target -eq 'Azure') {
                & (Child 'New-PimHybridWorkerInfra.ps1') @common -ResourceGroup $ResourceGroup -Location $Location -VmName $VmName -VmSize $VmSize -VnetName $VnetName `
                    -AddressPrefix $AddressPrefix -SubnetPrefix $SubnetPrefix -PeerVnetId $PeerVnetId -DnsServers $DnsServers -SqlServerId $SqlServerId -Egress $Egress @opt
            } else {
                & (Child 'New-PimHybridWorkerInfra.ps1') @common -ArcMachineResourceId $ArcMachineResourceId -SqlServerId $SqlServerId -SqlAllowedPublicIp $SqlAllowedPublicIp @opt
            }
            $o = @($r | Where-Object { $_ -and $_.PSObject.Properties['principalId'] })[-1]
            if (-not $o -or -not "$($o.principalId)".Trim()) { throw 'the infra step returned no managed identity' }
            $state.principalId = "$($o.principalId)"; $state.machineId = "$($o.machineId)"
            Set-StepStatus 'infra' 'done' "identity $($state.principalId)"
        }
        'peering' { & (Child 'Set-PimHybridWorkerPeering.ps1') @common -State Show -ResourceGroup $ResourceGroup -VnetName $VnetName; Set-StepStatus 'peering' 'done' }
        'egress' { & (Child 'Set-PimHybridWorkerEgress.ps1') @common -ResourceGroup $ResourceGroup -Location $Location -VmName $VmName -VnetName $VnetName; Set-StepStatus 'egress' 'done' }
        'ad' {
            if ($st -eq 'waiting') {
                # the AD administrator said it is done by letting us -Resume (the KDS time, when a key was created, comes with it)
                Set-StepStatus 'ad' 'done' $(if ($state.kdsRootKeyCreatedUtc) { "KDS root key created $($state.kdsRootKeyCreatedUtc)" } else { '' })
                break
            }
            Set-StepStatus 'ad' 'waiting'
            Write-Host ''
            Write-Host '[deploy] STOP -- the Active Directory step. On a domain controller (or a domain-joined admin host), as an account that may create gMSAs, groups and OU rights, run:' -ForegroundColor Yellow
            Write-Host "         $(Get-AdCommand)" -ForegroundColor White
            Write-Host "         then continue here:  .\Deploy-PimHybridWorker.ps1 -Resume -Apply$(if ($CreateKdsRootKey) { " -KdsRootKeyCreatedUtc '<the time it printed>'" })$(if ($Target -eq 'Azure') { ' -OdjBlobFile <file with the ODJ blob it printed>' })" -ForegroundColor Yellow
            $exitCode = 10; $stopped = $true
        }
        'join' {
            $blob = "$OdjBlob".Trim()
            if (-not $blob -and "$OdjBlobFile".Trim()) { $blob = ([IO.File]::ReadAllText($OdjBlobFile) -split "`r?`n" | Where-Object { "$_".Trim() -and $_ -notmatch '^ODJ-BLOB-(BEGIN|END)$' } | Select-Object -First 1).Trim() }
            if (-not $blob) { throw 'the join step needs the offline-join blob the AD step printed: -OdjBlob <blob> or -OdjBlobFile <file>' }
            $a = Get-InstallArgs 'Join'; $a.OdjBlob = $blob
            $r = & (Child 'Invoke-PimHybridWorkerRunCommand.ps1') @common -MachineResourceId $state.machineId -Phase Join -InstallParameters $a -PrintOnly:$PrintOnly
            $o = @($r | Where-Object { $_ -and $_.PSObject.Properties['delivered'] })[-1]
            if ("$($o.delivered)" -eq 'local-script') { Set-StepStatus 'join' 'local-script' "$($o.script)"; $exitCode = 11; $stopped = $true; break }
            if (-not $o.ok) { throw "the Join phase failed on $machineName ($($o.state), exit $($o.exitCode))" }
            Set-StepStatus 'join' 'done'
            if ($JoinRebootWaitSeconds -gt 0) { Info "waiting $JoinRebootWaitSeconds s for the reboot that completes the domain join"; Start-Sleep -Seconds $JoinRebootWaitSeconds }
        }
        'grant' {
            $g = @{} + $common
            if ($Target -eq 'Arc') { $g.ArcMachineResourceId = $ArcMachineResourceId } else { $g.PrincipalId = $state.principalId }
            & (Child 'Grant-PimHybridWorkerAccess.ps1') @g -SqlServer $sqlFqdn -SqlDatabase $SqlDatabase -SqlUserName $SqlUserName -SourceContainerId $SourceContainerId -GrantMailSend:$GrantMailSend
            Set-StepStatus 'grant' 'done'
        }
        'kds' {
            $k = "$($state.kdsRootKeyCreatedUtc)".Trim()
            if ($k) {
                $at = ([datetimeoffset]::Parse($k, [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime.AddHours(10)
                if ((Get-Date).ToUniversalTime() -lt $at) {
                    Set-StepStatus 'kds' 'waiting' "usable from $($at.ToString('o'))"
                    Write-Host ''
                    Write-Host ("[deploy] STOP -- the new KDS root key is usable from about {0:yyyy-MM-dd HH:mm} UTC (~10 h after it was created). Continue then: .\Deploy-PimHybridWorker.ps1 -Resume -Apply" -f $at) -ForegroundColor Yellow
                    $exitCode = 12; $stopped = $true; break
                }
            }
            Set-StepStatus 'kds' 'done' $(if ($k) { 'the KDS root key is old enough' } else { 'no new KDS root key' })
        }
        'configure' {
            $r = & (Child 'Invoke-PimHybridWorkerRunCommand.ps1') @common -MachineResourceId $state.machineId -Phase Configure -InstallParameters (Get-InstallArgs 'Configure') -PrintOnly:$PrintOnly
            $o = @($r | Where-Object { $_ -and $_.PSObject.Properties['delivered'] })[-1]
            if ("$($o.delivered)" -eq 'local-script') { Set-StepStatus 'configure' 'local-script' "$($o.script)"; $exitCode = 11; $stopped = $true; break }
            if (-not $o.ok) { throw "the Configure phase failed on $machineName ($($o.state), exit $($o.exitCode)) -- see the output above" }
            $state | Add-Member -NotePropertyName configureOutput -NotePropertyValue "$($o.output)" -Force
            Set-StepStatus 'configure' 'done'
        }
        'verify' {
            $outText = "$($state.configureOutput)"
            if ($outText -and $outText -notmatch "done: 'PIM Hybrid Worker'") { Warn "the Configure output does not show the task summary -- check $machineName (C:\PIM\logs, Task Scheduler)" }
            Set-StepStatus 'verify' 'done'
            Write-Host ''
            Write-Host "[deploy] DONE -- the hybrid worker on $machineName is installed. In PIM Manager: Jobs -> hybrid-ad-* show the worker live within ~5 minutes; Settings -> Hybrid Active Directory shows one status per worker job." -ForegroundColor Green
        }
    }
    if ($stopped) { break }
}
Info "state file: $StatePath"

} catch {
    Write-Host "[deploy] FAILED: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
} finally { Stop-PimScriptRun -Script 'Deploy-PimHybridWorker' }
if ($exitCode) { exit $exitCode }
