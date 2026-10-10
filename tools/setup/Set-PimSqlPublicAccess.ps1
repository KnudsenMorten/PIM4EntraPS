#Requires -Version 5.1

<#
.SYNOPSIS
    Turns the PIM SQL server's public network access off (-Disable) or back on (-Enable). Disable is refused unless the
    server has a private endpoint whose connection is Approved. Plan-only unless -Apply.

.DESCRIPTION
    Turns the public network access of the PIM Manager's Azure SQL server off (-Disable) or back on (-Enable), over Azure Resource Manager REST. -Disable is refused unless the server has at least one private endpoint connection in the state Approved, because without one the PIM Manager and the engine could no longer reach their database. It reads the server and its private endpoint connections, prints the plan, and changes nothing unless -Apply is given; after the change it reads the server back.

    REQUIREMENTS 100.64 (c): the last step of a conversion to private (the guide convert-external-to-private.md, Step 7;
    Convert-PimToPrivate.ps1 -SqlPrivate calls it last). It replaces "turn it off in the portal".
      * -Disable: PATCH properties.publicNetworkAccess = 'Disabled'. REFUSED (exit 1, nothing changed) unless a private
        endpoint connection of the server is Approved (pending, rejected or disconnected connections do not count). With
        public access off, the server's firewall rules and VNet rules no longer apply: the PIM Manager, the jobs and
        every later deploy reach SQL through the private endpoint only (run deploys from inside the network).
      * -Enable: PATCH properties.publicNetworkAccess = 'Enabled' (the rollback). The existing firewall and VNet rules
        apply again.
      * Already in the wanted state: nothing to do (exit 0). Run it as often as you like.
    A refusal by Azure (for example an Azure Policy that denies the change) is printed with Azure's message and exits 1.
    The change is read back; a server that does not report the wanted state after the PATCH exits 1.

    SIGN-IN. ONE REST session (engine/_shared/PIM-Rest.ps1): a calling script's session is reused as it is (for example
    Convert-PimToPrivate.ps1's); standalone, the Invardia Support app's session for -TenantId, else you sign in in the
    browser. A session of another tenant than -TenantId is refused. No Azure CLI, no PowerShell modules.
    Exit codes: 0 done, nothing to do, or the plan; 1 refused or failed.

.EXAMPLE
    # the plan (reads the server and its private endpoints; changes nothing)
    .\tools\setup\Set-PimSqlPublicAccess.ps1 -TenantId <tenant-id> -SubscriptionId <subscription-id> -ResourceGroup rg-pim -ServerName sql-pim -Disable

.EXAMPLE
    # turn public access off; the rollback is the same command with -Enable
    .\tools\setup\Set-PimSqlPublicAccess.ps1 -TenantId <tenant-id> -SubscriptionId <subscription-id> -ResourceGroup rg-pim -ServerName sql-pim -Disable -Apply

.LINK
    https://invardia.com/docs/pim/scripts/Set-PimSqlPublicAccess/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    # the SQL server name or its FQDN (sql-x or sql-x.database.windows.net)
    [Parameter(Mandatory)][string]$ServerName,
    [switch]$Disable,
    [switch]$Enable,
    [string]$TenantId,
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Set-PimSqlPublicAccess'
try {
if ($WhatIfPreference -and $Apply) { Write-Host '  -WhatIf: plan only -- -Apply is ignored, nothing is changed.' -ForegroundColor Yellow }
$spPlanOnly = (-not $Apply) -or [bool]$WhatIfPreference
function Say([string]$m, [string]$c = 'Gray') { Write-Host "  $m" -ForegroundColor $c }

function Get-PimSqlPublicAccessDecision {
    <#
      PURE. May the server's public network access be set as asked?
        -Current      the server's properties.publicNetworkAccess ('' = never set = Enabled)
        -Connections  its private endpoint connections (ARM objects: properties.privateLinkServiceConnectionState.status)
        -Want         Disable | Enable
      Returns @{ change; refuse; target; reason; approved[]; notApproved[] }.
    #>
    param([string]$Current, [object[]]$Connections = @(), [Parameter(Mandatory)][ValidateSet('Disable', 'Enable')][string]$Want)
    $cur = if ("$Current".Trim()) { "$Current".Trim() } else { 'Enabled' }
    $target = if ($Want -eq 'Disable') { 'Disabled' } else { 'Enabled' }
    $approved = New-Object System.Collections.Generic.List[string]
    $notApproved = New-Object System.Collections.Generic.List[string]
    foreach ($c in @($Connections | Where-Object { $_ })) {
        $peId = "$($c.properties.privateEndpoint.id)".Trim()
        $label = if ($peId) { ($peId -split '/')[-1] } else { "$($c.name)" }
        $st = "$($c.properties.privateLinkServiceConnectionState.status)".Trim()
        if ($st -eq 'Approved') { $approved.Add($label) } else { $notApproved.Add("$label ($(if ($st) { $st } else { 'no state' }))") }
    }
    $r = @{ change = $false; refuse = $false; target = $target; reason = ''; approved = @($approved); notApproved = @($notApproved) }
    if ($cur -eq $target) { $r.reason = "public network access is already $target -- nothing to do"; return $r }
    if ($Want -eq 'Disable' -and $approved.Count -lt 1) {
        $r.refuse = $true
        $r.reason = 'the server has NO Approved private endpoint' + $(if ($notApproved.Count) { " (not approved: $($notApproved -join ', '))" } else { '' }) +
                    ' -- with public access off the PIM Manager and the engine could not reach their database. Add one first (New-PimHostingPrerequisites.ps1 -SqlPrivateEndpoint) and approve it.'
        return $r
    }
    $r.change = $true
    $r.reason = if ($Want -eq 'Disable') { "public network access $cur -> Disabled (Approved private endpoint: $($approved -join ', '))" } else { "public network access $cur -> Enabled (the firewall and VNet rules apply again)" }
    return $r
}

if ([bool]$Disable -eq [bool]$Enable) { Say 'REFUSED -- give exactly one of -Disable or -Enable.' 'Red'; exit 1 }
$spWant = if ($Disable) { 'Disable' } else { 'Enable' }
$spSrv = ("$ServerName".Trim() -replace '^tcp:', '' -replace ',\d+$', '').Split('.')[0].ToLowerInvariant()
if ($spSrv -notmatch '^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$') { Say "REFUSED -- not a SQL server name: $ServerName" 'Red'; exit 1 }
$spSub = "$SubscriptionId".Trim()
$spTid = "$TenantId".Trim().ToLowerInvariant()

# ONE REST layer (framework 12.17 NO-AZ): a caller's session is reused as it is; standalone, sign in once.
$spSolRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $spSolRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $spSolRoot 'engine\_shared\PIM-ArmSetup.ps1') }
$spCurTid = "$($global:PIM_TenantId)".Trim().ToLowerInvariant()
if ("$($global:PIM_SetupRestMode)".Trim()) {
    if ($spTid -and $spCurTid -and $spCurTid -ne $spTid) { Say "REFUSED -- this shell's REST session is for tenant $spCurTid, not $spTid. Open a new PowerShell window and run again." 'Red'; exit 1 }
} else {
    try { [void](Connect-PimSetupRest -SubscriptionId $spSub -TenantId $spTid) }
    catch { Say "REFUSED -- no REST session: $($_.Exception.Message)" 'Red'; exit 1 }
    $spCurTid = "$($global:PIM_TenantId)".Trim().ToLowerInvariant()
    if ($spTid -and $spCurTid -and $spCurTid -ne $spTid) { Say "REFUSED -- the sign-in landed in tenant $spCurTid, not $spTid." 'Red'; exit 1 }
}
$spSubObj = Get-PimArmSubscription -SubscriptionId $spSub -ErrorAsNull
if (-not $spSubObj -or "$($spSubObj.subscriptionId)".Trim() -ne $spSub) { Say "REFUSED -- this sign-in cannot see subscription $spSub." 'Red'; exit 1 }
if ($spTid -and "$($spSubObj.tenantId)".Trim() -and "$($spSubObj.tenantId)".Trim().ToLowerInvariant() -ne $spTid) { Say "REFUSED -- subscription $spSub belongs to tenant $($spSubObj.tenantId), not $spTid." 'Red'; exit 1 }

Write-Host "==> SQL server $spSrv in $ResourceGroup -- public network access: $spWant ($(if ($spPlanOnly) { 'PLAN ONLY' } else { 'APPLY' }))" -ForegroundColor Cyan
$spServer = Get-PimArmSqlServer -SubscriptionId $spSub -ResourceGroup $ResourceGroup -Name $spSrv -ErrorAsNull
if (-not $spServer) { Say "REFUSED -- SQL server '$spSrv' was not found in resource group '$ResourceGroup' (subscription $spSub)." 'Red'; exit 1 }
# the private endpoint connections: the server's own list (child resource) and the copy on the server object, by id
$spConns = @{}
$spList = @(Invoke-PimSetupArm -Path "$("$($spServer.id)".TrimEnd('/'))/privateEndpointConnections" -ApiVersion (Get-PimSetupApiVersion sql) -All -ErrorAsNull)
foreach ($c in @(@($spList) + @($spServer.properties.privateEndpointConnections))) {
    if (-not $c) { continue }
    $k = if ("$($c.id)".Trim()) { "$($c.id)".Trim().ToLowerInvariant() } else { "$($c.properties.privateEndpoint.id)".Trim().ToLowerInvariant() }
    if (-not $spConns.ContainsKey($k)) { $spConns[$k] = $c }
}
$spCur = "$($spServer.properties.publicNetworkAccess)".Trim()
$d = Get-PimSqlPublicAccessDecision -Current $spCur -Connections @($spConns.Values) -Want $spWant
Say "now        : public network access $(if ($spCur) { $spCur } else { 'Enabled (not set)' })"
Say "private    : $(if ($d.approved.Count) { 'Approved: ' + ($d.approved -join ', ') } else { 'no Approved private endpoint' })$(if ($d.notApproved.Count) { '; not approved: ' + ($d.notApproved -join ', ') })"
if ($d.refuse) { Say "REFUSED -- $($d.reason)" 'Red'; exit 1 }
if (-not $d.change) { Say $d.reason 'Green'; exit 0 }
if ($spPlanOnly) {
    Say "PLAN ONLY -- would set $($d.reason). Re-run with -Apply." 'Yellow'
    exit 0
}
if ($PSCmdlet.ShouldProcess($spSrv, "set public network access $($d.target)")) {
    try { [void](Update-PimArmSqlServer -SubscriptionId $spSub -ResourceGroup $ResourceGroup -Name $spSrv -Properties @{ publicNetworkAccess = $d.target }) }
    catch { Say "FAILED -- Azure refused to set public network access $($d.target) on '$spSrv': $($_.Exception.Message) (an Azure Policy may govern Microsoft.Sql/servers/publicNetworkAccess)." 'Red'; exit 1 }
}
$spAfter = "$((Get-PimArmSqlServer -SubscriptionId $spSub -ResourceGroup $ResourceGroup -Name $spSrv -ErrorAsNull).properties.publicNetworkAccess)".Trim()
if ($spAfter -ne $d.target) { Say "FAILED -- '$spSrv' reports public network access '$spAfter' after the change, not $($d.target) (a policy may reset it)." 'Red'; exit 1 }
Say "public network access $($d.target) (read back)" 'Green'
if ($spWant -eq 'Disable') {
    Say 'From now on SQL is reached through the private endpoint only: deploys, Confirm-PimInstall.ps1 and Set-PimLicense.ps1 run from inside the network.' 'Yellow'
    Say "Rollback: the same command with -Enable instead of -Disable." 'Yellow'
}
exit 0
} finally { Stop-PimScriptRun -Script 'Set-PimSqlPublicAccess' }
