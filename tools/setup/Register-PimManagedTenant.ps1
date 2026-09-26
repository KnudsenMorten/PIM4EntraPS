#Requires -Version 5.1
<#
.SYNOPSIS
    71.18 -- register (or update, or disable) a MANAGED tenant on the MSP MASTER: platform.Tenants ring + tags.

.DESCRIPTION
    Replaces the documented hand SQL step (§71 gap 2: "no product command registers a managed tenant"). The master's
    bundle producer reads this row's TAGS and signs them into the bundle (targeting). Idempotent (MERGE on TenantId),
    READ BACK after the write, audited ('msp.tenant.register') in pim.AuditEvents. Certificate identity only; the
    identity must be in the master store's SQL admin group.

    BUG-175 -- THE RING HERE IS THE MASTER'S COPY, NOT THE TENANT'S RING. Every ring is LOCAL in the slave: the pull
    is gated by the managed tenant's OWN -SlaveRing (its downlink job argument, set in the slave). The bundle producer
    does NOT read this Ring (it reads only Tags), and nothing reconciles the two values. The master uses its copy only
    for its own previews (the Manager's reach preview, overview and dry run, each labelled "master's copy") -- keep it
    equal to the slave's -SlaveRing, or those previews describe a ring the tenant is not on.

.PARAMETER ManagedTenantId / DisplayName / Ring / Tags
    The managed tenant. Ring 0..2 (0 = dev, 1 = test, 2 = broad -- §77.20) -- the MASTER'S COPY of the ring the tenant set
    locally (see above). Tags: 'region:eu;wave:pilot' or an array.

.PARAMETER Disable
    Keep the row, set Enabled = 0 (the tenant stops receiving; nothing is deleted).

.PARAMETER List
    Print the registered tenants and exit.

.EXAMPLE
    .\Register-PimManagedTenant.ps1 -SqlServerFqdn sql-ait-wa678.database.windows.net -ManagedTenantId <slave tenant> `
        -DisplayName RIDE -Ring 2 -Tags 'region:eu','wave:pilot' -TenantId <master tenant> -ClientId <app> -CertThumbprint <thumb>
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [string]$ManagedTenantId,
    [string]$DisplayName,
    [ValidateRange(0, 2)][int]$Ring = 0,
    [string[]]$Tags = @(),
    [string]$Notes = '',
    [switch]$Disable,
    [switch]$List,
    [Parameter(Mandatory)][string]$TenantId,
    # Certificate identity -- OR -UseSignedInAccount (71.33: the signed-in az user, a member of the SQL admin group).
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseSignedInAccount
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot '_PimSetupSql.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-MspBuild.ps1')
# REQ-N: the ONE writer of a platform.Tenants row, shared with the Manager's "Managed tenant registry" page.
. (Join-Path $solRoot 'engine\_shared\PIM-MspRegistry.ps1')
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }

$cs = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -UseSignedInAccount:$UseSignedInAccount
if (-not "$(Invoke-PimSqlScalar -ConnectionString $cs -Sql "SELECT OBJECT_ID('platform.Tenants')")".Trim()) {   # DBNull renders empty
    throw "platform.Tenants does not exist on $SqlServerFqdn/$SqlDatabase -- this is not an MSP master yet. Run tools\setup\Initialize-PimMasterRegistry.ps1 first."
}
$readRows = { @(Invoke-PimSqlQuery -ConnectionString $cs -Sql "SELECT CONVERT(nvarchar(50), TenantId) AS TenantId, DisplayName, Ring, Enabled, Tags FROM platform.Tenants ORDER BY Ring, DisplayName") }
if ($List) {
    Step "managed tenants registered on $SqlServerFqdn"
    & $readRows | Format-Table -AutoSize | Out-String | Write-Host
    return
}

$reg = Get-PimManagedTenantRegistration -TenantId $ManagedTenantId -DisplayName $DisplayName -Ring $Ring -Tags $Tags -Enabled (-not $Disable) -Notes $Notes
if (-not $reg.ok) { throw "REFUSED: $($reg.reason)" }
$before = @(& $readRows | Where-Object { "$($_.TenantId)".ToLowerInvariant() -eq $reg.parameters.tid })[0]
Step ("{0} managed tenant {1} ({2}) ring {3} tags '{4}'" -f $(if ($Disable) { 'DISABLE' } elseif ($before) { 'update' } else { 'register' }), $reg.parameters.name, $reg.parameters.tid, $Ring, $reg.parameters.tags)
if ($PSCmdlet.ShouldProcess($reg.parameters.tid, 'MERGE platform.Tenants')) {
    # REQ-N: the ONE writer (Set-PimManagedTenantRegistration) -- the same refusals, MERGE and read-back as the Manager's
    # registry page. -TenantId here is the MASTER's tenant (the one this store belongs to), so it cannot be registered.
    # -Notes only when given: re-running to change a tag no longer wipes the notes.
    $wArgs = @{ ConnectionString = $cs; TenantId = $ManagedTenantId; DisplayName = $DisplayName; Ring = $Ring; Tags = $Tags; Enabled = (-not $Disable); Mode = 'Upsert'; MasterTenantId = $TenantId }
    if ($PSBoundParameters.ContainsKey('Notes')) { $wArgs['Notes'] = $Notes }
    $w = Set-PimManagedTenantRegistration @wArgs
    if (-not $w.ok) { throw "REFUSED ($($w.status)): $($w.reason)" }
    $after = @(& $readRows | Where-Object { "$($_.TenantId)".ToLowerInvariant() -eq $reg.parameters.tid })[0]
    Write-PimSetupAudit -ConnectionString $cs -Action 'msp.tenant.register' -Target $reg.parameters.tid -Before $before -After $w.parameters
    Note "read back OK: ring $($after.Ring) (the master's copy -- the tenant's own -SlaveRing gates its pull), enabled $($after.Enabled), tags '$($after.Tags)'"
    Note 'next: publish the bundle (start the master''s ca-pim-publish job, Start-PimBaselinePublish.ps1) so the tenant''s tags are signed into it.'
}
