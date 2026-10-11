#Requires -Version 5.1

<#
.SYNOPSIS
    PIM Manager hybrid worker (PIM for Active Directory): remove it -- the Azure VM worker with everything its scripts
    built, or the on-premises Azure Arc worker's grants and tasks (never the Arc machine).

.DESCRIPTION
    Removes the PIM for Active Directory hybrid worker and everything PIM's worker scripts created for it, and prints the Active Directory clean-up for the AD administrator.

    PLAN FIRST: without -Apply it prints what it would delete and what it keeps, and changes nothing (-WhatIf is the same).

    -Target Azure (the worker VM New-PimHybridWorkerInfra.ps1 built), in this order:
        1 grants     the VM identity's Graph read roles (Group.Read.All, User.Read.All,
                     PrivilegedAssignmentSchedule.Read.AzureADGroup, Mail.Send when granted), its Storage Blob Data Reader
                     on -SourceContainerId, its SQL contained user (-SqlUserName; dropped ONLY when it carries the identity's
                     SID -- a same-named user of anything else stays)
        2 sql rules  the SQL VNet rule 'pimhybridwrk' (only when it names the worker subnet)
        3 dns        the privatelink zone's link to the worker VNet (-PrivateSqlDnsZoneId); links to OTHER VNets and the zone
                     itself are kept (other workloads may resolve through them) and listed
        4 peerings   the hub/DC-side peerings PIM created ('<remote>-to-pimhybridwrk' pointing at the worker VNet), then the
                     worker-side ones; a remote peering PIM did not create is listed, never touched
        5 the VM     the VM, then its NIC(s) and OS disk (created with it), the worker VNet (refused while anything else
                     sits in its subnet), the NAT gateway + its public IP, the NSG, and the resource group when PIM created
                     it and it is empty
    -Target Arc: 1 grants and 2 the SQL firewall rules 'pimhybridwrk-arc-<server>-<n>' as above, then 3 the worker's tasks
        and rights ON the server through run-command (Install-PimHybridWorker.ps1 -Phase Remove; the self-contained
        script for the server's administrator when run-command cannot be used). The Arc machine, its agent and its
        identity are NEVER removed.

    WHAT IS DELETED -- only what PIM's worker scripts made: a resource carries the tag pim-hybrid-worker = <worker name>
    (New-PimHybridWorkerInfra.ps1 / Set-PimHybridWorkerEgress.ps1 tag what they create), or is the NIC / OS disk of such a
    VM, or is one of the fixed-name objects the scripts create (peerings '<remote>-to-pimhybridwrk', SQL rule
    'pimhybridwrk', firewall rules 'pimhybridwrk-arc-<server>-<n>'), each checked against the worker. A worker built
    before the tags existed: -IncludeUntagged also accepts an untagged resource carrying EXACTLY the name the scripts
    give it, in -ResourceGroup. Everything else is listed as kept.

    ACTIVE DIRECTORY is never changed by this script: it PRINTS the exact clean-up for the AD administrator (the worker
    computer account, the gMSAs and their -PermissionGroup / -PrincipalsAllowedAccess groups, the ACEs those groups hold
    on the OUs and AdminSDHolder, the servers GPO) -- dsacls / dsrm (in-box on a DC) and the GroupPolicy module.
    -StatePath reads every value not given from a Deploy-PimHybridWorker.ps1 state file.

    One REST session pinned to -TenantId (the Invardia Support app's session, or the person signed in). No az, no module.

.EXAMPLE
    .\Remove-PimHybridWorker.ps1 -Target Azure -SubscriptionId <sub> -TenantId <tenant> -SqlServerId <sql-server-id> `
        -SourceContainerId <storage-id>/blobServices/default/containers/pim-src -AdDomain CORP -GmsaOu 'OU=Service Accounts,DC=corp,DC=local'
    .\Remove-PimHybridWorker.ps1 ...same... -Apply

.EXAMPLE
    .\Remove-PimHybridWorker.ps1 -Target Arc -SubscriptionId <sub> -TenantId <tenant> `
        -ArcMachineResourceId /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.HybridCompute/machines/<server> -SqlServerId <sql-server-id> -Apply

.LINK
    https://invardia.com/docs/pim/scripts/Remove-PimHybridWorker/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$TenantId,
    [ValidateSet('Azure', 'Arc')][string]$Target,
    # Azure
    [string]$ResourceGroup = 'rg-pimhybridwrk',
    [ValidatePattern('^[A-Za-z0-9-]{1,15}$')][string]$VmName = 'PIMHYBRIDWRK',
    [string]$VnetName = 'vnet-pimhybridwrk',
    [string]$NatGatewayName = '',
    [string]$PublicIpName = '',
    [string]$PrivateSqlDnsZoneId = '',
    [switch]$IncludeUntagged,
    # Arc
    [string]$ArcMachineResourceId = '',
    [string]$ArcApiVersion = '2024-07-10',
    [switch]$PrintOnly,
    # the PIM environment
    [string]$SqlServerId = '',
    [string]$SqlDatabase = 'PimPlatform',
    [string]$SqlUserName = 'PIMHYBRIDWRK',
    [switch]$KeepSqlUser,
    [string]$SourceContainerId = '',
    # Active Directory (PRINTED for the AD administrator)
    [string]$AdDomain = '',
    [string]$GmsaName = 'gMSA-PIM-L1-T0',
    [string]$GmsaOu = '',
    [string]$ServerGmsaName = '',
    [string[]]$ServerOu = @(),
    [string]$ServerAdminGpoName = '',
    [string]$ComputerOu = '',
    [string]$GroupsOu = '',
    [string[]]$AdminAccountsOu = @(),
    [switch]$GrantProtectedGroupMembership,
    # flow
    [string]$StatePath = '',
    [switch]$Apply,
    [int]$PollSeconds = 10
)
$ErrorActionPreference = 'Stop'

# 12.7 run frame: "<Script> version <x.y.z> - documentation: <page>" as the first line + a transcript in the temp folder.
. (Join-Path $PSScriptRoot '..\setup\_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Remove-PimHybridWorker'
try {

function Step($m) { Write-Host "[remove] $m" -ForegroundColor Cyan }
function Info($m) { Write-Host "         $m" -ForegroundColor Gray }
function Warn($m) { Write-Host "         $m" -ForegroundColor Yellow }

# ---------------------------------------------------------------------------------------------------- Deploy state values
$fromState = @('Target', 'ResourceGroup', 'VmName', 'VnetName', 'ArcMachineResourceId', 'SqlServerId', 'SqlDatabase', 'SqlUserName', 'SourceContainerId',
               'PrivateSqlDnsZoneId', 'AdDomain', 'GmsaName', 'GmsaOu', 'ServerGmsaName', 'ServerOu', 'ComputerOu', 'GroupsOu', 'AdminAccountsOu', 'GrantProtectedGroupMembership')
if ("$StatePath".Trim()) {
    if (-not (Test-Path -LiteralPath $StatePath)) { throw "-StatePath not found: $StatePath" }
    $st = [IO.File]::ReadAllText($StatePath) | ConvertFrom-Json
    foreach ($k in $fromState) {
        if ($PSBoundParameters.ContainsKey($k)) { continue }
        $p = $st.parameters.PSObject.Properties[$k]
        if (-not $p -or $null -eq $p.Value -or "$($p.Value)" -eq '') { continue }
        $cur = (Get-Variable -Name $k).Value
        if ($cur -is [switch]) { Set-Variable -Name $k -Value ([switch][bool]$p.Value) }
        elseif ($cur -is [array]) { Set-Variable -Name $k -Value @($p.Value | Where-Object { $null -ne $_ } | ForEach-Object { "$_" }) }
        else { Set-Variable -Name $k -Value "$($p.Value)" }
    }
    Step "values read from the deploy state $StatePath"
}
if (-not $Target) { throw '-Target Azure|Arc is required (or -StatePath with a deploy state)' }
if ($Target -eq 'Arc') {
    if ($ArcMachineResourceId -notmatch '^/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/Microsoft\.HybridCompute/machines/([^/]+)$') { throw '-Target Arc needs -ArcMachineResourceId (/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.HybridCompute/machines/<server>)' }
    if ($Matches[1] -ne $SubscriptionId) { throw "the Arc machine is in subscription $($Matches[1]), not -SubscriptionId $SubscriptionId -- refusing" }
}
if ($SqlServerId -and $SqlServerId -notmatch '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Sql/servers/[^/]+$') { throw "-SqlServerId is not a SQL server resource id: '$SqlServerId'" }
if ($PrivateSqlDnsZoneId -and $PrivateSqlDnsZoneId -notmatch '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/privateDnsZones/privatelink\.database\.windows\.net$') { throw "-PrivateSqlDnsZoneId must be the privatelink.database.windows.net zone's resource id: '$PrivateSqlDnsZoneId'" }

$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId) }
if ("$($global:PIM_TenantId)".Trim() -and "$($global:PIM_TenantId)".Trim().ToLowerInvariant() -ne "$TenantId".Trim().ToLowerInvariant()) { throw "the REST session is signed in to tenant '$($global:PIM_TenantId)', not '$TenantId' -- refusing" }
$acct = Get-PimArmSubscription -SubscriptionId $SubscriptionId
if ("$($acct.tenantId)" -ne $TenantId) { throw "subscription $SubscriptionId reads tenant '$($acct.tenantId)', not '$TenantId' -- refusing" }
$net = Get-PimSetupApiVersion network
$computeApi = '2024-03-01'; $diskApi = '2023-04-02'

# ---------------------------------------------------------------------------------------------------- ownership (PURE)
function Get-PimHwOwnership {
    <#
      PURE. Why may this resource be deleted? 'tag' (pim-hybrid-worker = the worker), 'name' (-IncludeUntagged + no such tag
      + exactly the name the scripts give it), or '' (not PIM's -- kept). A tag naming ANOTHER worker is never accepted.
    #>
    param($Resource, [string]$Worker, [string]$ExpectedName, [bool]$AllowName)
    if (-not $Resource) { return '' }
    $tv = $null
    if ($Resource.tags) { $tp = $Resource.tags.PSObject.Properties['pim-hybrid-worker']; if (-not $tp -and $Resource.tags -is [hashtable] -and $Resource.tags.ContainsKey('pim-hybrid-worker')) { $tv = "$($Resource.tags['pim-hybrid-worker'])" } elseif ($tp) { $tv = "$($tp.Value)" } }
    if ($null -ne $tv) { if ($tv -ieq $Worker) { return 'tag' } else { return '' } }
    if ($AllowName -and $ExpectedName -and "$($Resource.name)" -ieq $ExpectedName) { return 'name' }
    return ''
}

# ---------------------------------------------------------------------------------------------------- the plan
$plan = New-Object System.Collections.Generic.List[object]
$kept = New-Object System.Collections.Generic.List[string]
function Add-Action([string]$Phase, [string]$What, [string]$Why, [string]$Kind, [hashtable]$A = @{}) { $plan.Add([pscustomobject]@{ phase = $Phase; what = $What; why = $Why; kind = $Kind; a = $A }) }
function Add-Kept([string]$Line) { $kept.Add($Line) }
function Remove-ArmWait([string]$Id, [string]$Api) {
    # DELETE (a missing resource is success), then wait until it reads back 404 -- the next delete often depends on it
    [void](Invoke-PimSetupArm -Method DELETE -Path $Id -ApiVersion $Api -NotFoundOk)
    $deadline = (Get-Date).AddSeconds(1800)
    while ((Get-Date) -lt $deadline) {
        if ($null -eq (Invoke-PimSetupArm -Path $Id -ApiVersion $Api -NotFoundOk -ErrorAsNull)) { return }
        if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
    }
    throw "$(($Id -split '/')[-1]) is still there after 30 minutes"
}

$worker = if ($Target -eq 'Arc') { ($ArcMachineResourceId -split '/')[-1] } else { $VmName }
$lower = $worker.ToLowerInvariant()
if (-not $NatGatewayName) { $NatGatewayName = "natgw-$lower" }
if (-not $PublicIpName) { $PublicIpName = "pip-$lower" }
$principalId = ''
$vmOwned = $false
$vnetId = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/virtualNetworks' $VnetName
$subnetId = "$vnetId/subnets/snet-worker"
$vm = $null; $nicIds = @(); $diskId = ''

if ($Target -eq 'Azure') {
    $vmId = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Compute/virtualMachines' $VmName
    $vm = Invoke-PimSetupArm -Path $vmId -ApiVersion $computeApi -NotFoundOk
    $own = Get-PimHwOwnership -Resource $vm -Worker $worker -ExpectedName $VmName -AllowName ([bool]$IncludeUntagged)
    if ($vm -and $own) {
        $vmOwned = $true
        $principalId = "$($vm.identity.principalId)"
        $nicIds = @(@($vm.properties.networkProfile.networkInterfaces) | Where-Object { $_ } | ForEach-Object { "$($_.id)" })
        $diskId = "$($vm.properties.storageProfile.osDisk.managedDisk.id)"
    } elseif ($vm) { Add-Kept "VM $VmName -- not tagged pim-hybrid-worker=$worker$(if (-not $IncludeUntagged) { ' (built before the tags? check it, then add -IncludeUntagged)' }); nothing that hangs off its identity is touched" }
    else { Info "VM $VmName not found in $ResourceGroup" }
} else {
    $m = Invoke-PimSetupArm -Path $ArcMachineResourceId -ApiVersion $ArcApiVersion -NotFoundOk
    if (-not $m) { throw "Arc machine not found: $ArcMachineResourceId" }
    $principalId = "$($m.identity.principalId)"
    Add-Kept "the Arc machine $worker, its Connected Machine agent and its identity -- NEVER removed by PIM"
}

# ---- 1 grants (only what Grant-PimHybridWorkerAccess.ps1 grants)
$appId = ''
if ($principalId) {
    $sp = Invoke-PimSetupGraph -Path "/servicePrincipals/$principalId`?`$select=id,appId,displayName" -NotFoundOk
    $appId = "$($sp.appId)"
    if ($sp) {
        $gsp = @(Invoke-PimSetupGraph -Path "/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles" -All | Where-Object { $_ })[0]
        $pimRoles = @('Group.Read.All', 'User.Read.All', 'PrivilegedAssignmentSchedule.Read.AzureADGroup', 'Mail.Send')
        $roleIds = @{}; foreach ($r in @($gsp.appRoles)) { if ($pimRoles -contains "$($r.value)") { $roleIds["$($r.id)"] = "$($r.value)" } }
        foreach ($a in @(@(Invoke-PimSetupGraph -Path "/servicePrincipals/$principalId/appRoleAssignments" -All) | Where-Object { $_ -and "$($_.resourceId)" -eq "$($gsp.id)" -and $roleIds.ContainsKey("$($_.appRoleId)") })) {
            Add-Action 'grants' "Graph $($roleIds["$($a.appRoleId)"]) of $($sp.displayName)" 'granted by Grant-PimHybridWorkerAccess.ps1' 'graph-delete' @{ path = "/servicePrincipals/$principalId/appRoleAssignments/$($a.id)" }
        }
    } else { Info "identity $principalId has no service principal any more -- no Graph grant to remove" }
    if ($SourceContainerId) {
        foreach ($ra in @(@(Get-PimArmRoleAssignments -Scope $SourceContainerId -PrincipalId $principalId -Role 'Storage Blob Data Reader' -SubscriptionId (Get-PimArmIdPart -Id $SourceContainerId -Segment 'subscriptions')) | Where-Object { $_ -and $_.id })) {
            Add-Action 'grants' 'Storage Blob Data Reader on the source container' 'granted by Grant-PimHybridWorkerAccess.ps1' 'arm-delete' @{ id = "$($ra.id)"; api = (Get-PimSetupApiVersion authorization) }
        }
    }
    if ($SqlServerId -and $appId -and -not $KeepSqlUser) {
        $fq = "$(($SqlServerId -split '/')[-1]).database.windows.net"
        Add-Action 'grants' "SQL user $SqlUserName on $fq/$SqlDatabase" 'DROP USER only when it carries the worker identity''s SID' 'sql-drop' @{ server = $fq; appId = $appId }
    } elseif ($SqlServerId -and $KeepSqlUser) { Add-Kept "SQL user $SqlUserName (-KeepSqlUser)" }
}

# ---- 2 SQL network rules
if ($SqlServerId) {
    $sSub = Get-PimArmIdPart -Id $SqlServerId -Segment 'subscriptions'; $sRg = Get-PimArmIdPart -Id $SqlServerId -Segment 'resourceGroups'; $sName = ($SqlServerId -split '/')[-1]
    if ($Target -eq 'Azure') {
        foreach ($r in @(Get-PimArmSqlVnetRules -SubscriptionId $sSub -ResourceGroup $sRg -Server $sName | Where-Object { "$($_.name)" -eq 'pimhybridwrk' })) {
            if ("$($r.properties.virtualNetworkSubnetId)" -ine $subnetId) { Add-Kept "SQL VNet rule pimhybridwrk -- names $($r.properties.virtualNetworkSubnetId), not this worker's subnet"; continue }
            Add-Action 'sql rules' "SQL VNet rule pimhybridwrk on $sName" 'created by New-PimHybridWorkerInfra.ps1 for the worker subnet' 'arm-delete' @{ id = "$SqlServerId/virtualNetworkRules/pimhybridwrk"; api = (Get-PimSetupApiVersion sql) }
        }
    } else {
        $rx = '^pimhybridwrk-arc-' + [regex]::Escape($lower) + '-\d+$'
        foreach ($r in @(Get-PimArmSqlFirewallRules -SubscriptionId $sSub -ResourceGroup $sRg -Server $sName | Where-Object { "$($_.name)" -match $rx })) {
            Add-Action 'sql rules' "SQL firewall rule $($r.name) ($($r.properties.startIpAddress)) on $sName" 'created by New-PimHybridWorkerInfra.ps1 -SqlAllowedPublicIp' 'arm-delete' @{ id = "$SqlServerId/firewallRules/$($r.name)"; api = (Get-PimSetupApiVersion sql) }
        }
    }
}

# ---- 3 private DNS links
if ($PrivateSqlDnsZoneId) {
    $zSub = Get-PimArmIdPart -Id $PrivateSqlDnsZoneId -Segment 'subscriptions'; $zRg = Get-PimArmIdPart -Id $PrivateSqlDnsZoneId -Segment 'resourceGroups'
    foreach ($l in @(Get-PimArmPrivateDnsLinks -SubscriptionId $zSub -ResourceGroup $zRg -ZoneName 'privatelink.database.windows.net' -ErrorAsNull)) {
        $lv = "$($l.properties.virtualNetwork.id)"
        $own = Get-PimHwOwnership -Resource $l -Worker $worker -ExpectedName "link-pimhybridwrk-$($VnetName.ToLowerInvariant())" -AllowName ([bool]$IncludeUntagged)
        if (-not $own) { continue }
        if ($Target -eq 'Azure' -and $lv -ieq $vnetId) {
            Add-Action 'dns' "private DNS link $($l.name) (privatelink.database.windows.net -> $VnetName)" 'created by New-PimHybridWorkerInfra.ps1' 'arm-wait' @{ id = "$PrivateSqlDnsZoneId/virtualNetworkLinks/$($l.name)"; api = (Get-PimSetupApiVersion privateDns) }
        } else { Add-Kept "private DNS link $($l.name) -> $(($lv -split '/')[-1]) (created for this worker, but other workloads may resolve through it -- delete it yourself if not)" }
    }
    Add-Kept 'the privatelink.database.windows.net zone itself (your private endpoints resolve through it)'
}

# ---- Arc: the worker on the server, through run-command
if ($Target -eq 'Arc') {
    Add-Action 'server' "on $worker`: the worker's scheduled tasks, its gMSA rights, C:\PIM\app + bin (Install-PimHybridWorker.ps1 -Phase Remove, run-command)" 'installed by Install-PimHybridWorker.ps1' 'arc-remove' @{}
}

# ---- 4 + 5 Azure network and the VM
if ($Target -eq 'Azure') {
    $vnet = Invoke-PimSetupArm -Path $vnetId -ApiVersion $net -NotFoundOk
    $vnetOwn = Get-PimHwOwnership -Resource $vnet -Worker $worker -ExpectedName $VnetName -AllowName ([bool]$IncludeUntagged)
    if ($vnet -and -not $vnetOwn) { Add-Kept "VNet $VnetName -- not tagged pim-hybrid-worker=$worker; its peerings are not touched either" }
    if ($vnet -and $vnetOwn) {
        foreach ($p in @(Invoke-PimSetupArm -Path "$vnetId/virtualNetworkPeerings" -ApiVersion $net -All -ErrorAsNull | Where-Object { $_ -and $_.name })) {
            $remote = "$($p.properties.remoteVirtualNetwork.id)"
            if ($remote -match '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.Network/virtualNetworks/([^/]+)$') {
                $rN = $Matches[3]
                foreach ($b in @(Invoke-PimSetupArm -Path "$remote/virtualNetworkPeerings" -ApiVersion $net -All -ErrorAsNull | Where-Object { $_ -and "$($_.properties.remoteVirtualNetwork.id)" -ieq $vnetId })) {
                    if ("$($b.name)" -ieq "$rN-to-pimhybridwrk") {
                        Add-Action 'peerings' "peering $rN/$($b.name)" 'created by New-PimHybridWorkerInfra.ps1 (remote side)' 'arm-wait' @{ id = "$remote/virtualNetworkPeerings/$($b.name)"; api = $net }
                    } else { Add-Kept "peering $rN/$($b.name) -- points at the worker VNet but PIM did not create it (its owner removes it; it shows Disconnected once the worker VNet is gone)" }
                }
            }
            Add-Action 'peerings' "peering $VnetName/$($p.name)" 'the worker VNet''s own side' 'arm-wait' @{ id = "$vnetId/virtualNetworkPeerings/$($p.name)"; api = $net }
        }
    }
    if ($vmOwned) {
        $vid = "$($vm.id)"; if (-not $vid) { $vid = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Compute/virtualMachines' $VmName }
        Add-Action 'vm' "VM $VmName (its system-assigned identity goes with it)" 'tagged / built by New-PimHybridWorkerInfra.ps1' 'arm-wait' @{ id = $vid; api = $computeApi }
        foreach ($n in $nicIds) { Add-Action 'vm' "NIC $(($n -split '/')[-1])" "the NIC of VM $VmName" 'arm-wait' @{ id = $n; api = $net } }
        if ($diskId) { Add-Action 'vm' "OS disk $(($diskId -split '/')[-1])" "the OS disk of VM $VmName" 'arm-wait' @{ id = $diskId; api = $diskApi } }
    }
    $foreign = @()
    if ($vnet -and $vnetOwn) {
        $foreign = @(@($vnet.properties.subnets) | ForEach-Object { @($_.properties.ipConfigurations) } | Where-Object { $_ -and $_.id } | ForEach-Object { "$($_.id)" } |
                     Where-Object { $i = $_; -not @($nicIds | Where-Object { $i -like "$_/*" }).Count })
        if ($foreign.Count) { Add-Kept "VNet $VnetName -- something else sits in it ($(($foreign | Select-Object -First 3 | ForEach-Object { ($_ -split '/')[8] }) -join ', ')): not deleted" }
        else { Add-Action 'network' "VNet $VnetName" 'tagged / built by New-PimHybridWorkerInfra.ps1' 'arm-wait' @{ id = $vnetId; api = $net } }
    }
    # the NAT gateway and the NSG are attached to the worker subnet: they can only go when the VNet goes
    $vnetStays = [bool]$vnet -and -not ($vnetOwn -and -not $foreign.Count)
    $natId = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/natGateways' $NatGatewayName
    $nat = Invoke-PimSetupArm -Path $natId -ApiVersion $net -NotFoundOk
    $natPips = @()
    if ($nat -and $vnetStays) { Add-Kept "NAT gateway $NatGatewayName and its public IP -- attached to the worker subnet, which stays" }
    elseif ($nat) {
        if (Get-PimHwOwnership -Resource $nat -Worker $worker -ExpectedName "natgw-$lower" -AllowName ([bool]$IncludeUntagged)) {
            $natPips = @(@($nat.properties.publicIpAddresses) | Where-Object { $_ } | ForEach-Object { "$($_.id)" })
            Add-Action 'network' "NAT gateway $NatGatewayName" 'created by Set-PimHybridWorkerEgress.ps1' 'arm-wait' @{ id = $natId; api = $net }
        } else { Add-Kept "NAT gateway $NatGatewayName -- not tagged pim-hybrid-worker=$worker" }
    }
    foreach ($pipId in @(@($natPips) + @($(if (-not $vnetStays) { Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/publicIPAddresses' $PublicIpName })) | Where-Object { $_ } | Select-Object -Unique)) {
        $pip = Invoke-PimSetupArm -Path $pipId -ApiVersion $net -NotFoundOk
        if (-not $pip) { continue }
        if (Get-PimHwOwnership -Resource $pip -Worker $worker -ExpectedName "pip-$lower" -AllowName ([bool]$IncludeUntagged)) {
            Add-Action 'network' "public IP $(($pipId -split '/')[-1]) (the NAT gateway's outbound address)" 'created by Set-PimHybridWorkerEgress.ps1' 'arm-wait' @{ id = $pipId; api = $net }
        } else { Add-Kept "public IP $(($pipId -split '/')[-1]) -- not tagged pim-hybrid-worker=$worker" }
    }
    $nsgId = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Network/networkSecurityGroups' "nsg-$lower"
    $nsg = Invoke-PimSetupArm -Path $nsgId -ApiVersion $net -NotFoundOk
    if ($nsg -and $vnetStays) { Add-Kept "NSG nsg-$lower -- attached to the worker subnet, which stays" }
    elseif ($nsg) {
        if (Get-PimHwOwnership -Resource $nsg -Worker $worker -ExpectedName "nsg-$lower" -AllowName ([bool]$IncludeUntagged)) { Add-Action 'network' "NSG nsg-$lower" 'created by New-PimHybridWorkerInfra.ps1' 'arm-wait' @{ id = $nsgId; api = $net } }
        else { Add-Kept "NSG nsg-$lower -- not tagged pim-hybrid-worker=$worker" }
    }
    $rg = Get-PimArmResourceGroup -SubscriptionId $SubscriptionId -Name $ResourceGroup
    if ($rg) {
        if (Get-PimHwOwnership -Resource $rg -Worker $worker -ExpectedName '' -AllowName $false) {
            Add-Action 'network' "resource group $ResourceGroup -- only if it is EMPTY by then" 'created by New-PimHybridWorkerInfra.ps1' 'rg-if-empty' @{ id = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" }
        } else { Add-Kept "resource group $ResourceGroup -- not created by PIM (no pim-hybrid-worker tag): kept even when empty" }
    }
}

function Invoke-PimHwRemoveAction($Action) {
    $a = $Action.a
    switch ($Action.kind) {
        'graph-delete' { [void](Invoke-PimSetupGraph -Method DELETE -Path $a.path -NotFoundOk) }
        'arm-delete'   { [void](Invoke-PimSetupArm -Method DELETE -Path $a.id -ApiVersion $a.api -NotFoundOk) }
        'arm-wait'     { Remove-ArmWait -Id $a.id -Api $a.api }
        'sql-drop' {
            . (Join-Path $PSScriptRoot '_PimHybridWorkerSql.ps1')
            $tok = "$(Get-PimRestToken -Resource 'https://database.windows.net' -TenantId $TenantId)"
            $r = @(Invoke-PimHybridWorkerSql -Server $a.server -Database $SqlDatabase -AccessToken $tok -Batches @(Get-PimHwSqlDropUserSql -UserName $SqlUserName -AppId $a.appId))
            Info "SQL user ${SqlUserName}: $($r[-1])"
        }
        'arc-remove' {
            $r = & (Join-Path $PSScriptRoot 'Invoke-PimHybridWorkerRunCommand.ps1') -SubscriptionId $SubscriptionId -TenantId $TenantId -MachineResourceId $ArcMachineResourceId -Phase Remove -InstallParameters @{ HostType = 'Arc' } -PrintOnly:$PrintOnly
            $o = @($r | Where-Object { $_ -and $_.PSObject.Properties['delivered'] })[-1]
            if ("$($o.delivered)" -eq 'local-script') { $script:LocalScript = "$($o.script)" }
            elseif (-not $o.ok) { throw "the Remove phase failed on the server ($($o.state), exit $($o.exitCode))" }
        }
        'rg-if-empty' {
            $left = @(Invoke-PimSetupArm -Path "$($a.id)/resources" -ApiVersion (Get-PimSetupApiVersion resources) -All -ErrorAsNull | Where-Object { $_ -and $_.id })
            if ($left.Count) { Warn "resource group $ResourceGroup still holds $($left.Count) resource(s) ($((@($left | Select-Object -First 3 | ForEach-Object { $_.name })) -join ', ')) -- kept"; return }
            Remove-ArmWait -Id $a.id -Api (Get-PimSetupApiVersion resources)
        }
        default { throw "unknown action kind '$($Action.kind)'" }
    }
}

# ---------------------------------------------------------------------------------------------------- AD (printed)
function Get-PimHwAdCleanupLines {
    # PURE-ish: the AD administrator's clean-up, in a safe order. PIM never changes AD from here.
    $dom = if ("$AdDomain".Trim()) { "$AdDomain".Trim() } else { '<DOMAIN>' }
    $gou = if ("$GmsaOu".Trim()) { "$GmsaOu".Trim() } else { '<GmsaOu>' }
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add('# On a domain controller, as an account that may delete these objects (dsacls / dsrm are in-box on a DC):')
    $ids = @($GmsaName); if ("$ServerGmsaName".Trim()) { $ids += "$ServerGmsaName".Trim() }
    $l.Add('# 1. take back the rights the worker''s PermissionGroup holds (before the group is deleted, or the ACEs stay as orphaned SIDs)')
    $ous = @(@($GroupsOu) + @($AdminAccountsOu) | Where-Object { "$_".Trim() })
    if (-not $ous.Count) { $ous = @('<GroupsOu>', '<each AdminAccountsOu>') }
    foreach ($ou in $ous) { $l.Add("dsacls `"$ou`" /R `"$dom\$GmsaName-PermissionGroup`"") }
    if ($GrantProtectedGroupMembership) { $l.Add("dsacls `"CN=AdminSDHolder,CN=System,<domain DN>`" /R `"$dom\$GmsaName-PermissionGroup`"   # it held 'member' on AdminSDHolder (Tier 0)") }
    else { $l.Add("# (only if the worker was given -GrantProtectedGroupMembership:) dsacls `"CN=AdminSDHolder,CN=System,<domain DN>`" /R `"$dom\$GmsaName-PermissionGroup`"") }
    if ("$ServerGmsaName".Trim()) {
        $gpo = if ("$ServerAdminGpoName".Trim()) { "$ServerAdminGpoName".Trim() } else { "PIM for AD: $("$ServerGmsaName".Trim())-PermissionGroup is local administrator (servers)" }
        $l.Add('# 2. the servers GPO (GroupPolicy module, on a DC / GPMC host): unlink from each -ServerOu, then delete')
        $sous = @($ServerOu | Where-Object { "$_".Trim() }); if (-not $sous.Count) { $sous = @('<each ServerOu>') }
        foreach ($so in $sous) { $l.Add("Remove-GPLink -Name '$gpo' -Target '$so'") }
        $l.Add("Remove-GPO -Name '$gpo'")
    } else { $l.Add('# 2. no servers GPO (no -ServerGmsaName was used)') }
    $l.Add('# 3. the identities: the gMSA and its two groups, for each worker identity')
    foreach ($g in $ids) {
        foreach ($o in @($g, "$g-PermissionGroup", "$g-PrincipalsAllowedAccess")) { $l.Add("dsrm `"CN=$o,$gou`" -noprompt") }
    }
    if ($Target -eq 'Azure') {
        $cou = if ("$ComputerOu".Trim()) { "$ComputerOu".Trim() } else { '<ComputerOu>' }
        $l.Add("# 4. the worker VM's computer account (created by -ProvisionOdj)")
        $l.Add("dsrm `"CN=$VmName,$cou`" -noprompt")
    } else { $l.Add("# 4. the Arc server's computer account is YOURS -- it stays (remove it from any <gMSA>-PrincipalsAllowedAccess group only; deleting the group above does that)") }
    $l.Add('# KEEP the KDS root key (forest-wide; other gMSAs depend on it). The AD groups and admin accounts the worker created and managed stay -- remove them yourself if you no longer want them.')
    return , $l.ToArray()
}

# ---------------------------------------------------------------------------------------------------- show / apply
Write-Host ''
Step "$(if ($Apply -and -not $WhatIfPreference) { 'REMOVING' } else { 'PLAN -- nothing is changed; add -Apply to run it' }) (-Target $Target, worker $worker)"
$i = 0
foreach ($a in $plan) { $i++; Info ("{0,2}. [{1}] delete {2}  ({3})" -f $i, $a.phase, $a.what, $a.why) }
if (-not $plan.Count) { Info 'nothing PIM created was found to delete' }
foreach ($k in $kept) { Info "kept: $k" }

$done = New-Object System.Collections.Generic.List[string]
$script:LocalScript = ''
if ($Apply -and -not $WhatIfPreference) {
    foreach ($a in $plan) {
        if (-not $PSCmdlet.ShouldProcess($a.what, 'delete')) { continue }
        Invoke-PimHwRemoveAction $a
        $done.Add($a.what)
        Info "deleted: $($a.what)"
    }
}

Write-Host ''
Write-Host '[remove] ACTIVE DIRECTORY -- PIM does not change AD. The AD administrator removes:' -ForegroundColor Yellow
foreach ($l in (Get-PimHwAdCleanupLines)) { Write-Host "         $l" -ForegroundColor White }
if ($script:LocalScript) { Warn "the server part was NOT delivered by run-command: on $worker, elevated, run $($script:LocalScript)" }
Write-Host ''
Step $(if ($Apply -and -not $WhatIfPreference) { "done: $($done.Count) of $($plan.Count) deleted" } else { "plan: $($plan.Count) to delete, $($kept.Count) kept" })
[pscustomobject]@{ target = $Target; worker = $worker; planned = @($plan | ForEach-Object { "[$($_.phase)] $($_.what)" }); kept = @($kept); deleted = @($done); localScript = $script:LocalScript }

} finally { Stop-PimScriptRun -Script 'Remove-PimHybridWorker' }
