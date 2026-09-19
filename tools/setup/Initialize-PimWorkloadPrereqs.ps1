#Requires -Version 5.1
<#
.SYNOPSIS
    REQ-U (prereqs) -- check, and fix where an API can, the prerequisites of ONE workload PIM delegates into; then record
    the result in the environment's store so the Manager shows it green / amber / red.

.DESCRIPTION
    Operator, 2026-09-19: "make prereqscript that i must run per workload" / "dont put in template" / "refer to script
    in gui and show with green if prereq has run".

    Run it once per workload you delegate (-Workload DefenderXdr | Intune | PowerBI | AzureRbac | EntraRoles), and again
    whenever the Manager's chip turns amber (never run, older than 30 days, or a step still to confirm) or red.

    Per workload it CHECKS every prerequisite in the catalog (engine\_shared\PIM-WorkloadPrereqs.ps1 -- the Manager and
    the tests read the same definitions) and FIXES what an API can fix, reading every change back:
      DefenderXdr  engine Graph role RoleManagement.ReadWrite.Defender (grant) | Unified RBAC answers (beta
                   roleManagement/defender/roleDefinitions) | activated workloads (PORTAL ONLY, inferred from the live
                   roles) | Data Operations: Sentinel enabled on a workspace (ARM onboardingStates) and connected to the
                   Defender portal / data lake (PORTAL ONLY). -SkipDataOperations when no Data Operations role is used.
                   -EnableSentinel (OPT-IN, billed per GB ingested): enables Sentinel on a DEDICATED security workspace
                   (-SentinelWorkspaceId, else law-sentinel-<suffix> in -ResourceGroup, created empty when missing);
                   refused on PIM's own log workspace (law-pim-*).
      Intune       engine Graph role DeviceManagementRBAC.ReadWrite.All (grant) | deviceManagement/roleDefinitions answers.
      PowerBI      security group (create) | engine identity is a member (add) | no admin-consent Power BI application
                   permission on it (Microsoft's rule for read-only admin APIs; reported, never removed automatically) |
                   Fabric tenant setting "Service principals can access read-only admin APIs" for that group (Fabric
                   admin API, keeping every existing group; portal step when the caller may not) | GET admin/groups as
                   the engine (only when its certificate is here: -EngineAppId + -EngineCertThumbprint).
      AzureRbac    User Access Administrator (or Owner) for the engine identity at every scope in your
                   PIM-Assignments-Azure-Resources rows (+ -AzureScope). Assigning it is OPT-IN
                   (-GrantAzureUserAccessAdministrator): it is standing privilege (SEC-34).
      EntraRoles   the full Graph role map (grant) | the AAD_PREMIUM_P2 service plan.
    What only a human can do is reported with the exact portal path and the Microsoft Learn link. After doing a
    portal-only step, confirm it: -ConfirmPortalStep <check id> (recorded as "confirmed", attested -- never as verified).

    The result is written to pim.Settings 'WorkloadPrereqs' = { <workload>: { ranUtc, ranBy, ok, state, checks[] } }
    (the other workloads are kept), READ BACK, and audited (Write-PimSetupAudit). -WhatIf changes nothing, not even the
    store.

    Identity: a CERTIFICATE identity (-ClientId + -CertThumbprint, cert in LocalMachine\My) or -UseSignedInAccount (the
    signed-in az user). Never a client secret, never interactive. The same identity reaches the store (a member of the
    SQL admin group), Graph, ARM and Fabric; every call names its target explicitly -- no default az context is used.
    The CALLER needs, for the checks: Application.Read.All, RoleManagement.Read.Defender, DeviceManagementRBAC.Read.All,
    Group.Read.All, Organization.Read.All, Reader on the workspaces / scopes; for the fixes: AppRoleAssignment.ReadWrite.All,
    Group.ReadWrite.All (or GroupMember.ReadWrite.All), a Fabric admin role, User Access Administrator at the scope.
    A check the caller cannot read is recorded as NOT CHECKED with the reason -- never as passed.

.EXAMPLE
    .\tools\setup\Initialize-PimWorkloadPrereqs.ps1 -Workload DefenderXdr -TenantId <tenant> -SubscriptionId <hosting-sub> `
        -ResourceGroup <rg> -SqlServerFqdn <server>.database.windows.net -ClientId <management-app-id> -CertThumbprint <thumb>

.EXAMPLE
    # after activating the workloads and connecting Sentinel in the Defender portal:
    .\tools\setup\Initialize-PimWorkloadPrereqs.ps1 -Workload DefenderXdr ... -ConfirmPortalStep defender.urbacWorkloads,defender.sentinelInDefender
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('DefenderXdr', 'Intune', 'PowerBI', 'AzureRbac', 'EntraRoles')][string]$Workload,
    [Parameter(Mandatory)][string]$TenantId,
    # The HOSTING subscription + resource group (where ca-pim-tick runs). Used to find the engine identity; every ARM
    # call below names its full path, so no default az context is ever relied on.
    [Parameter(Mandatory)][string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$TickJobName = 'ca-pim-tick',
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    # Certificate identity -- OR -UseSignedInAccount.
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseSignedInAccount,
    # The ENGINE identity, when it is not the hosted tick job's managed identity (e.g. an engine application on a VM).
    [string]$EngineObjectId,
    [string]$EngineAppId,
    # Only with an engine APPLICATION whose certificate is on this host: lets PowerBI test the admin API as the engine.
    [string]$EngineCertThumbprint,
    [string[]]$ConfirmPortalStep = @(),
    [switch]$SkipDataOperations,
    [string]$SentinelWorkspaceId,
    [switch]$EnableSentinel,
    [string]$PowerBiSecurityGroupName = 'grp-pim-powerbi-admin-api',
    [string[]]$AzureScope = @(),
    [switch]$GrantAzureUserAccessAdministrator
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimSetupShared.ps1')   # Get-PimGraphAppRoleMap / Get-PimEngineSpnGraphRoles (the one role map)
. (Join-Path $PSScriptRoot '_PimSetupSql.ps1')      # Connect-PimSetupStore / Write-PimSetupAudit (+ PIM-Rest, PIM-SqlStore)
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $solRoot 'engine\_shared\PIM-WorkloadPrereqs.ps1')
. (Join-Path $PSScriptRoot '_PimWorkloadPrereqRunner.ps1')
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }

if ("$TenantId".Trim() -notmatch '^[0-9a-fA-F-]{36}$') { throw "-TenantId must be the tenant GUID (got '$TenantId')." }
$unknown = @($ConfirmPortalStep | Where-Object { "$_".Trim() -and -not (Get-PimWorkloadPrereqCheckDef -Id "$_".Trim()) })
if ($unknown.Count) { throw "-ConfirmPortalStep: unknown check id(s): $($unknown -join ', '). Known for ${Workload}: $((@((Get-PimWorkloadPrereqCatalog -Workload $Workload)[$Workload].checks) | ForEach-Object { $_.id }) -join ', ')" }

Step "Workload prerequisites: $Workload (tenant $TenantId)"
$cs = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -UseSignedInAccount:$UseSignedInAccount

# The CALLER's Graph token: asserted to be for this tenant, and read for what it may do (a 403 is only evidence about
# the tenant when the caller holds the permission -- Get-PimPrereqProbeVerdict).
$claims = ConvertFrom-PimPrereqJwt -Token (Get-PimRestToken -Resource 'graph' -TenantId $TenantId)
if (-not $claims -or "$($claims.tid)" -ne "$TenantId".Trim()) { throw "REFUSING: the Graph token is for tenant '$($claims.tid)', expected '$TenantId'." }
$ranBy = if ("$($claims.upn)".Trim()) { "$($claims.upn)" } elseif ("$($global:PIM_SetupActor)".Trim()) { "$($global:PIM_SetupActor)" } else { "app $($claims.appid)" }
Note "caller: $ranBy"

$engine = Resolve-PimPrereqEngineIdentity -EngineObjectId $EngineObjectId -EngineAppId $EngineAppId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -TickJobName $TickJobName
Note "engine identity: $($engine.displayName) ($($engine.objectId), $($engine.kind))"

$__cmdlet = $PSCmdlet   # captured for the -WhatIf / -Confirm gate the runner calls before every change
$ctx = @{
    tenantId = "$TenantId".Trim(); engine = $engine; callerClaims = $claims; ranBy = $ranBy
    roleMap = (Get-PimGraphAppRoleMap -RoleSet Engine); engineRoleNames = @(Get-PimEngineSpnGraphRoles)
    confirm = @($ConfirmPortalStep); skipDataOperations = [bool]$SkipDataOperations; sentinelWorkspaceId = $SentinelWorkspaceId
    enableSentinel = [bool]$EnableSentinel; hostingSubscriptionId = $SubscriptionId; hostingResourceGroup = $ResourceGroup; pollSeconds = 5
    powerBiGroupName = $PowerBiSecurityGroupName; azureScopes = @($AzureScope); grantUaa = [bool]$GrantAzureUserAccessAdministrator
    engineCertThumbprint = $EngineCertThumbprint; graphSp = $null; engineAssignments = $null; azureRows = @()
    should = { param($t, $a) $__cmdlet.ShouldProcess($t, $a) }.GetNewClosure()
}
if ($Workload -eq 'AzureRbac') { $ctx.azureRows = @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Assignments-Azure-Resources') }

$checks = @(Invoke-PimWorkloadPrereqRun -Workload $Workload -Ctx $ctx)
$result = Get-PimWorkloadPrereqResult -Workload $Workload -Checks $checks -RanUtc ([datetime]::UtcNow) -RanBy $ranBy `
            -ToolVersion (Get-PimSetupSolutionVersion) -TenantId $TenantId -EngineIdentity "$($engine.displayName) ($($engine.objectId))"

foreach ($c in $checks) {
    $col = switch ($c.status) { { $_ -in 'ok', 'fixed', 'confirmed', 'skipped' } { 'Green' } 'failed' { 'Red' } default { 'Yellow' } }
    Write-Host ("  [{0,-10}] {1}{2}" -f $c.status, $c.name, $(if (-not $c.required) { ' (optional)' })) -ForegroundColor $col
    if ($c.detail) { Note "   $($c.detail)" }
    if ($c.manualStep) { Write-Host "      TO DO: $($c.manualStep)" -ForegroundColor Yellow; Write-Host "      Learn: $($c.learn)" -ForegroundColor DarkYellow }
}
$stateCol = switch ($result.state) { 'ok' { 'Green' } 'failed' { 'Red' } default { 'Yellow' } }
Write-Host "  => $Workload prerequisites: $($result.state.ToUpperInvariant())" -ForegroundColor $stateCol

if ($PSCmdlet.ShouldProcess("pim.Settings WorkloadPrereqs", "record the $Workload result")) {
    $cur = Get-PimSqlSetting -ConnectionString $cs -Name 'WorkloadPrereqs'
    $before = $null
    if ($cur -and $cur.PSObject.Properties[$Workload]) { $before = @{ state = "$($cur.$Workload.state)"; ranUtc = "$($cur.$Workload.ranUtc)" } }
    $merged = Merge-PimWorkloadPrereqsSetting -Current $cur -Result $result
    Set-PimSqlSetting -ConnectionString $cs -Name 'WorkloadPrereqs' -ValueJson (ConvertTo-Json -InputObject $merged -Depth 12 -Compress)
    $back = Get-PimSqlSetting -ConnectionString $cs -Name 'WorkloadPrereqs'
    $bw = if ($back -and $back.PSObject.Properties[$Workload]) { $back.$Workload } else { $null }
    $backRan = if ($bw -and $bw.ranUtc -is [datetime]) { $bw.ranUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } elseif ($bw) { "$($bw.ranUtc)" } else { '' }
    if (-not $bw -or "$($bw.state)" -ne $result.state -or $backRan -ne $result.ranUtc) { throw "read-back FAILED: pim.Settings WorkloadPrereqs.$Workload is '$($bw.state)' @ '$backRan', expected '$($result.state)' @ '$($result.ranUtc)'." }
    Write-PimSetupAudit -ConnectionString $cs -Action 'settings.workloadprereqs.record' -Target "WorkloadPrereqs:$Workload" -Before $before -After @{ state = $result.state; ranUtc = $result.ranUtc; failed = @($result.failed); pending = @($result.pending) }
    Note 'recorded in pim.Settings WorkloadPrereqs and read back -- the Manager shows it on the template cards and Coverage & gaps.'
}
if ($result.state -eq 'failed') { exit 1 }
if ($result.state -ne 'ok') { exit 2 }
exit 0
