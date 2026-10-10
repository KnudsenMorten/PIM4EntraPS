#Requires -Version 5.1
<#
.SYNOPSIS
    71.18 -- converge the hosting identities' access on an EXISTING environment: the tick's Graph app roles (Engine set),
    the Manager's Graph app roles (read-only Manager set), the Manager's right to start the tick now
    ('Container Apps Jobs Operator' on ca-pim-tick only), the tick's right to read its own executions ('Reader' on
    ca-pim-tick only, BUG-268), pim.Settings 'SchedulerTickJobId' and -- §97 -- the tick's Reader at the TENANT ROOT
    management group (Discovery cannot see Azure without it; User Access Administrator there only with
    -EngineAzureRootUserAccessAdmin), and -- PIM 100.22 (b) -- the Manager's 'Reader' on the PIM resource group ONLY (the
    Environment report reads the architecture with it).

.DESCRIPTION
    Before this script those four were done ONLY inside Setup-PimContainers.ps1 (the infra step) -- or not at all (the
    Jobs Operator role and SchedulerTickJobId had no script). Invoke-PimDeployAll SKIPS infra on an environment whose probe
    says current, so a rebuilt or existing environment never got them: measured 2026-09-15, EFIF and RIDE's ca-pim-tick
    held 12 Graph roles and ca-pim-manager 9, both without the five required ones (AccessReview.Read.All,
    AppRoleAssignment.ReadWrite.All, Application.Read.All, RoleManagement.ReadWrite.Defender,
    DeviceManagementRBAC.ReadWrite.All), and "Run now" could only wait for the next cron start.

    Idempotent: Grant-PimMiGraph adds only what is missing (and refuses a token for the wrong tenant); the role assignment
    is created only when absent; the setting is written only when it differs, then READ BACK and audited.
    Certificate identity only: az must already be logged in to -SubscriptionId (Invoke-PimMspBuild does that), and the
    store is reached with -ClientId/-CertThumbprint.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [string]$TickJobName = 'ca-pim-tick',
    [string]$ManagerApp = 'ca-pim-manager',
    [Parameter(Mandatory)][string]$TenantId,
    # Certificate identity -- OR -UseSignedInAccount (71.33: the signed-in az user, a member of the SQL admin group).
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseSignedInAccount,
    [switch]$SkipGraph,
    # §97 (owner 2026-10-08): the engine (tick) identity gets Reader at the tenant root management group by DEFAULT
    # (read-only; Discovery lists management groups + subscriptions with it). User Access Administrator there is OPT-IN
    # (SEC-34): this switch. A refusal never fails this script -- it warns and prints the exact Grant-PimEnginePermissions.ps1 command.
    [switch]$EngineAzureRootUserAccessAdmin,
    [switch]$SkipAzureRootAccess,
    [switch]$SkipTickStart,
    # PIM 100.22 (b): skip the Manager's Reader on the resource group (the Environment report then cannot read the architecture)
    [switch]$SkipManagerRgReader
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimSetupShared.ps1')
. (Join-Path $PSScriptRoot '_PimSetupSql.ps1')
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-ConvergeDefaults.ps1')   # 100.40 Set-PimTickJobIdSetting
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
$sub = @('--subscription', $SubscriptionId)
$ErrorActionPreference = 'Continue'   # native az stderr (warnings) must not be fatal on 5.1; every az call is checked
$tickId = az containerapp job show @sub -g $ResourceGroup -n $TickJobName --query id -o tsv --only-show-errors 2>$null
$tickOid = az containerapp job show @sub -g $ResourceGroup -n $TickJobName --query identity.principalId -o tsv --only-show-errors 2>$null
$mgrOid = az containerapp show @sub -g $ResourceGroup -n $ManagerApp --query identity.principalId -o tsv --only-show-errors 2>$null
$ErrorActionPreference = 'Stop'
if (-not "$tickId".Trim() -or -not "$tickOid".Trim()) { throw "tick job '$TickJobName' (or its system identity) not found in $ResourceGroup -- run the hosting step first." }
if (-not "$mgrOid".Trim()) { throw "Manager app '$ManagerApp' (or its system identity) not found in $ResourceGroup -- run the hosting step first." }
$tickId = "$tickId".Trim(); $tickOid = "$tickOid".Trim(); $mgrOid = "$mgrOid".Trim()

if (-not $SkipGraph) {
    Step "Graph app roles: $TickJobName (Engine set)"
    if ($PSCmdlet.ShouldProcess($tickOid, 'Grant-PimMiGraph Engine')) { Grant-PimMiGraph -MiObjectId $tickOid -SubscriptionId $SubscriptionId -ExpectedTenantId $TenantId -RoleSet Engine }
    Step "Graph app roles: $ManagerApp (read-only Manager set)"
    if ($PSCmdlet.ShouldProcess($mgrOid, 'Grant-PimMiGraph Manager')) { Grant-PimMiGraph -MiObjectId $mgrOid -SubscriptionId $SubscriptionId -ExpectedTenantId $TenantId -RoleSet Manager }
}

# §97 -- the engine's Azure sight. Live 2026-10-08 on a production managing tenant: Discovery 403'd on the management-group
# list and Home went red, because the tick held Reader on its hosting subscription only.
if (-not $SkipAzureRootAccess) {
    Step "Azure: Reader$(if ($EngineAzureRootUserAccessAdmin) { ' + User Access Administrator' }) for $TickJobName at the tenant root management group"
    $rootAccess = Grant-PimEngineRootAzureAccess -MiObjectId $tickOid -Name $TickJobName -TenantId $TenantId -SubscriptionId $SubscriptionId `
                      -IncludeUserAccessAdministrator:$EngineAzureRootUserAccessAdmin
    if ($rootAccess.ok) { Note 'present and read back' } else { Note 'NOT granted -- see the warning above; the install continues and Get Started > Engine permissions shows the fix' }
}

if (-not $SkipTickStart) {
    Step "'Container Apps Jobs Operator' for $ManagerApp on $TickJobName only"
    $ErrorActionPreference = 'Continue'
    $have = az role assignment list @sub --assignee $mgrOid --scope $tickId --role 'Container Apps Jobs Operator' --query "[].id" -o tsv --only-show-errors 2>$null
    if ("$have".Trim()) { Note 'already assigned' }
    elseif ($PSCmdlet.ShouldProcess($tickId, 'role assignment Container Apps Jobs Operator')) {
        az role assignment create @sub --assignee-object-id $mgrOid --assignee-principal-type ServicePrincipal --role 'Container Apps Jobs Operator' --scope $tickId -o none --only-show-errors 2>$null
        if ($LASTEXITCODE -ne 0) { $ErrorActionPreference = 'Stop'; throw "could not assign 'Container Apps Jobs Operator' to $ManagerApp on $TickJobName (the deploying identity needs User Access Administrator or Owner on the resource group)." }
        $have = az role assignment list @sub --assignee $mgrOid --scope $tickId --role 'Container Apps Jobs Operator' --query "[].id" -o tsv --only-show-errors 2>$null
        if (-not "$have".Trim()) { $ErrorActionPreference = 'Stop'; throw "read-back FAILED: the role assignment is not listed on $tickId." }
        Note 'assigned and read back'
    }

    # BUG-268: the tick reads the status of the execution that holds its lease, so a lease left by an execution the
    # platform ended is taken over at the next tick instead of after its 15-minute TTL. Read-only, this job only.
    Step "'Reader' for $TickJobName on itself (lease holder's execution status)"
    $have = az role assignment list @sub --assignee $tickOid --scope $tickId --role 'Reader' --query "[].id" -o tsv --only-show-errors 2>$null
    if ("$have".Trim()) { Note 'already assigned' }
    elseif ($PSCmdlet.ShouldProcess($tickId, 'role assignment Reader (tick identity)')) {
        az role assignment create @sub --assignee-object-id $tickOid --assignee-principal-type ServicePrincipal --role 'Reader' --scope $tickId -o none --only-show-errors 2>$null
        if ($LASTEXITCODE -ne 0) { $ErrorActionPreference = 'Stop'; throw "could not assign 'Reader' to $TickJobName on itself (the deploying identity needs User Access Administrator or Owner on the resource group)." }
        $have = az role assignment list @sub --assignee $tickOid --scope $tickId --role 'Reader' --query "[].id" -o tsv --only-show-errors 2>$null
        if (-not "$have".Trim()) { $ErrorActionPreference = 'Stop'; throw "read-back FAILED: the Reader assignment is not listed on $tickId." }
        Note 'assigned and read back'
    }
    $ErrorActionPreference = 'Stop'

    Step "pim.Settings SchedulerTickJobId = $tickId"
    $cs = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -UseSignedInAccount:$UseSignedInAccount
    $cur = "$(Get-PimSqlSetting -ConnectionString $cs -Name 'SchedulerTickJobId')".Trim().Trim('"')
    if ($cur -eq $tickId) { Note 'already set' }
    elseif ($PSCmdlet.ShouldProcess('SchedulerTickJobId', 'set')) {
        # 100.40: the ONE write of this setting (engine/_shared/PIM-ConvergeDefaults.ps1) -- the updater's step 2d uses the
        # same function on an existing install (only when absent). -Overwrite: the install knows the tick it deployed.
        $tickStore = {
            param($op, $name, $value)
            switch ($op) {
                'get'   { return (Get-PimSqlSetting -ConnectionString $cs -Name $name) }
                'set'   { Set-PimSqlSetting -ConnectionString $cs -Name $name -Value $value; return $null }
                'audit' { Write-PimSetupAudit -ConnectionString $cs -Action 'settings.scheduler.tickjobid' -Target $name -Before $value.before -After $value.after; return $null }
            }
        }
        $r = Set-PimTickJobIdSetting -TickJobId $tickId -Store $tickStore -Overwrite
        if ($r.action -eq 'set' -and $r.after -ne $tickId) { throw "read-back FAILED: SchedulerTickJobId is '$($r.after)'" }
        Note 'set and read back (the Manager starts the tick immediately after a commit)'
    }
}

# PIM 100.22 (b) (owner 2026-10-09): the Manager's managed identity gets 'Reader' on THIS resource group only, so the
# Environment report (Operations > Environment report) reads the installation's own architecture. Idempotent, read back;
# last, so a refusal (the deploying identity lacks User Access Administrator / Owner here) stops nothing above it.
if (-not $SkipManagerRgReader) {
    Step "'Reader' for $ManagerApp on the resource group $ResourceGroup only (the Environment report)"
    if ($PSCmdlet.ShouldProcess("$ManagerApp @ $ResourceGroup", 'role assignment Reader (resource group only)')) {
        $rgr = Grant-PimManagerRgReader -MiObjectId $mgrOid -Name $ManagerApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
        if ($rgr.ok) { Note "$($rgr.reason)" } else { throw "$($rgr.reason)" }
    }
}
