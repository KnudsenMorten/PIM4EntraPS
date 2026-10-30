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
    says current, so a rebuilt or existing environment never got them: measured 2026-09-15, both test tenants' ca-pim-tick
    held 12 Graph roles and ca-pim-manager 9, both without the five required ones (AccessReview.Read.All,
    AppRoleAssignment.ReadWrite.All, Application.Read.All, RoleManagement.ReadWrite.Defender,
    DeviceManagementRBAC.ReadWrite.All), and "Run now" could only wait for the next cron start.

    Idempotent: Grant-PimMiGraph adds only what is missing (and refuses a token for the wrong tenant); the role assignment
    is created only when absent; the setting is written only when it differs, then READ BACK and audited.
    100.41 (NO-AZ): every Azure read and write is ARM REST (engine/_shared/PIM-ArmSetup.ps1) over PIM-Rest's ONE token
    client -- the certificate identity (-ClientId/-CertThumbprint), or with -UseSignedInAccount the Invardia Support app's
    REST session / the person's browser sign-in. No az CLI is needed on the machine.
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
# 100.41: PIM-Rest's identity -- kept when the caller (the MSP build's step launcher) already set one up; else the
# certificate identity, else the signed-in one (the Invardia Support app's REST session, or the browser).
if (-not $global:PIM_SetupRestMode -and -not "$($global:PIM_ClientId)".Trim()) {
    if ("$ClientId".Trim() -and "$CertThumbprint".Trim() -and -not $UseSignedInAccount) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint) }
    else { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId) }
}
$tickJob = Get-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $TickJobName -ErrorAsNull
$mgrObj  = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -ErrorAsNull
$tickId  = if ($tickJob) { "$($tickJob.id)" } else { '' }
$tickOid = if ($tickJob -and $tickJob.identity) { "$($tickJob.identity.principalId)" } else { '' }
$mgrOid  = if ($mgrObj -and $mgrObj.identity) { "$($mgrObj.identity.principalId)" } else { '' }
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
    # 100.41: ARM REST -- Get-PimArmRoleAssignments / New-PimArmRoleAssignment (az role assignment list / create), exact scope.
    $haveRole = { param($oid, $role) try { [bool](@(Get-PimArmRoleAssignments -SubscriptionId $SubscriptionId -PrincipalId $oid -Scope $tickId -Role $role).Count) } catch { $false } }
    if (& $haveRole $mgrOid 'Container Apps Jobs Operator') { Note 'already assigned' }
    elseif ($PSCmdlet.ShouldProcess($tickId, 'role assignment Container Apps Jobs Operator')) {
        try { [void](New-PimArmRoleAssignment -SubscriptionId $SubscriptionId -PrincipalId $mgrOid -PrincipalType ServicePrincipal -Role 'Container Apps Jobs Operator' -Scope $tickId) }
        catch { throw "could not assign 'Container Apps Jobs Operator' to $ManagerApp on $TickJobName (the deploying identity needs User Access Administrator or Owner on the resource group): $($_.Exception.Message)" }
        if (-not (& $haveRole $mgrOid 'Container Apps Jobs Operator')) { throw "read-back FAILED: the role assignment is not listed on $tickId." }
        Note 'assigned and read back'
    }

    # BUG-268: the tick reads the status of the execution that holds its lease, so a lease left by an execution the
    # platform ended is taken over at the next tick instead of after its 15-minute TTL. Read-only, this job only.
    Step "'Reader' for $TickJobName on itself (lease holder's execution status)"
    if (& $haveRole $tickOid 'Reader') { Note 'already assigned' }
    elseif ($PSCmdlet.ShouldProcess($tickId, 'role assignment Reader (tick identity)')) {
        try { [void](New-PimArmRoleAssignment -SubscriptionId $SubscriptionId -PrincipalId $tickOid -PrincipalType ServicePrincipal -Role 'Reader' -Scope $tickId) }
        catch { throw "could not assign 'Reader' to $TickJobName on itself (the deploying identity needs User Access Administrator or Owner on the resource group): $($_.Exception.Message)" }
        if (-not (& $haveRole $tickOid 'Reader')) { throw "read-back FAILED: the Reader assignment is not listed on $tickId." }
        Note 'assigned and read back'
    }

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

# PIM 100.61: the as-built job the in-cloud updater created on an EXISTING environment needs the two rights its Contributor
# identity cannot give (Invoke-PimAsBuiltConverge reports them and names this script): the job identity's Storage Blob
# Data Contributor on the 'asbuilt' container ONLY, and the support custom role definition (start the job + read its
# executions; ASSIGNED to the Support app only by Grant-PimSupportAccess.ps1, with the customer's consent). Skipped when
# the job does not exist. Idempotent, read back.
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\PIM-AsBuilt.ps1')
$abJob = Get-PimArmAcaJob -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name (Get-PimAsBuiltJobName) -ErrorAsNull
# The writer is the job's USER-ASSIGNED identity id-pim-asbuilt (live fix 2026-10-11) -- read over ARM, also before the
# updater's converge has switched an older system-identity job to it; the job's own system identity only when there is none.
$abUami = Get-PimArmIdentity -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name (Get-PimAsBuiltIdentityName) -ErrorAsNull
$abOid = "$($abUami.properties.principalId)".Trim()
if (-not $abOid -and $abJob) { $abOid = "$((Get-PimAsBuiltJobIdentity -Job $abJob).principalId)".Trim() }
if ($abJob -and $abOid) {
    $abAcct = "$(@(@($abJob.properties.template.containers)[0].env) | Where-Object { "$($_.name)" -eq 'PIM_ASBUILT_STORAGE' } | ForEach-Object { $_.value } | Select-Object -First 1)".Trim()
    if ($abAcct -match '^[a-z0-9]{3,24}$') {
        $abScope = Get-PimArmResourceId $SubscriptionId $ResourceGroup 'Microsoft.Storage/storageAccounts' $abAcct "blobServices/default/containers/$(Get-PimAsBuiltContainerName)"
        Step "'Storage Blob Data Contributor' for $(Get-PimAsBuiltJobName)$(if ($abUami) { " (identity $(Get-PimAsBuiltIdentityName))" }) on $abAcct/$(Get-PimAsBuiltContainerName) only (it writes the as-built PDF)"
        $abHave = { [bool](@(try { Get-PimArmRoleAssignments -SubscriptionId $SubscriptionId -PrincipalId $abOid -Scope $abScope -Role 'Storage Blob Data Contributor' } catch { @() }).Count) }
        if (& $abHave) { Note 'already assigned' }
        elseif ($PSCmdlet.ShouldProcess($abScope, 'role assignment Storage Blob Data Contributor (as-built job)')) {
            [void](New-PimArmRoleAssignment -SubscriptionId $SubscriptionId -PrincipalId $abOid -PrincipalType ServicePrincipal -Role 'Storage Blob Data Contributor' -Scope $abScope)
            if (-not (& $abHave)) { throw "read-back FAILED: Storage Blob Data Contributor is not listed on $abScope." }
            Note 'assigned and read back'
        }
    }
    $abRd = Get-PimAsBuiltRoleDefinition -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
    Step "custom role '$($abRd.body.properties.roleName)' (definition only -- nobody is assigned here)"
    if (Invoke-PimSetupArm -Path $abRd.path -ApiVersion (Get-PimSetupApiVersion authorization) -NotFoundOk -ErrorAsNull) { Note 'exists' }
    elseif ($PSCmdlet.ShouldProcess($abRd.path, 'create the custom role definition')) {
        [void](Invoke-PimSetupArm -Method PUT -Path $abRd.path -Body $abRd.body -ApiVersion (Get-PimSetupApiVersion authorization))
        Note 'created'
    }
}
