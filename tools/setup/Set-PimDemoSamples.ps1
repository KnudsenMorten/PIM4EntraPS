#Requires -Version 5.1
<#
.SYNOPSIS
    PIM REQUIREMENTS 98.5 -- put a believable SAMPLE CONFIGURATION on the live demo environment (one made-up company,
    its departments, made-up admin accounts and their delegations, as real PIM Manager definitions), or take exactly
    those rows away again (-Remove). Plan by default; -Apply to change.

.DESCRIPTION
    The sample (engine/_shared/PIM-DemoSamples.ps1) is the fictional company "Quillmere": 8 departments (IT, Finance,
    HR, Sales, Marketing, Operations, Legal, Customer Support), 14 admin accounts in three tiers, 6 job-function groups,
    8 department groups, 1 organization group, 10 Entra-role permission groups and 41 delegation rows -- a few of them
    time-limited. Not to be confused with Set-PimDemoMode.ps1: that one seeds a display-only dataset the engine never
    reads. THESE are ordinary definitions.

    WHAT HAPPENS AFTER -Apply: on its next run the engine CREATES the matching objects in the tenant -- 14 admin user
    accounts (each gets a Temporary Access Pass, mailed with a new-admin notice to the owner(s) of its department), 25
    security groups (16 of them role-assignable), 10 eligible Entra role assignments (never Global Administrator,
    Privileged Role Administrator or Privileged Authentication Administrator) and the memberships. That is intended on
    the demo tenant, and it is why this script REFUSES anywhere else.

    REFUSED -- before anything is read or written -- unless the environment is PROVEN to be the demo one, with the same
    proof Set-PimDemoMode.ps1 -Enable uses (Get-PimDemoEnvironmentProof): the update ring is recorded and is 0 or 1,
    AND the stored licence verifies and names an internal / demo licensee. Ring 2 / 3, a ring that is not recorded or
    cannot be read, no licence, an invalid one or a customer's licence = refused.

    The rows are written through the store's own upsert-only, transactional, journaled writer (the one the supported
    importer uses), under the change-journal source 'demo-samples', after the Manager's own pre-flight validator has
    checked the result. A row the store already holds is never overwritten, so a second -Apply adds nothing.

    -Remove deletes exactly the rows whose latest change-journal entry is the sample's own (a row a person changed
    afterwards is left alone and named), assignments first. It is allowed anywhere: it can only delete sample rows.
    After a removal the engine's daily reconcile removes the groups and assignments it had created for those rows; it
    never deletes or disables an admin account -- the 14 sample accounts stay in the tenant until someone deletes them.

    It never touches a setting: not the SuperAdmin / Manager access, not the break-glass accounts, nothing else.

.PARAMETER Domain
    The tenant's own verified domain -- the sample admins are admin-<initials>-id@<Domain>. Required with -Apply.

.PARAMETER DepartmentOwnerUpn
    One or more EXISTING accounts of the tenant (user@domain) that own the 8 departments, given in rotation. They
    become the owners of the groups and RECEIVE the engine's mail about the sample admins (new-admin notice, Temporary
    Access Pass). Required with -Apply -- an invented address would have a credential mailed to nobody.

.PARAMETER UsageLocation
    Two-letter country code for the sample accounts (default US).

.PARAMETER ConnectionString
    An already-open store connection string (from an ops session). Otherwise give -SqlServerFqdn + -TenantId and an identity.

.EXAMPLE
    .\Set-PimDemoSamples.ps1 -SqlServerFqdn <server>.database.windows.net -TenantId <tenant> -UseSignedInAccount -Domain <domain> -DepartmentOwnerUpn <owner@domain>
    (plan only) ... -Apply (write) ... -Remove (plan) ... -Remove -Apply (take the sample rows away)
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Add')]
param(
    [Parameter(ParameterSetName = 'Remove', Mandatory)][switch]$Remove,
    [switch]$Apply,
    [Parameter(ParameterSetName = 'Add')][string]$Domain,
    [Parameter(ParameterSetName = 'Add')][string[]]$DepartmentOwnerUpn = @(),
    [Parameter(ParameterSetName = 'Add')][string]$UsageLocation = 'US',
    [string]$ConnectionString,
    [string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseSignedInAccount
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ("$ConnectionString".Trim()) {
    foreach ($f in 'PIM-Rest.ps1', 'PIM-ChangeQueue.ps1', 'PIM-SqlStore.ps1') { . (Join-Path $solRoot "engine\_shared\$f") }
    $cs = $ConnectionString
} else {
    if (-not "$SqlServerFqdn".Trim() -or -not "$TenantId".Trim()) { throw 'give -ConnectionString, or -SqlServerFqdn + -TenantId with an identity (-ClientId/-CertThumbprint or -UseSignedInAccount).' }
    . (Join-Path $PSScriptRoot '_PimSetupSql.ps1')
    $cs = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -UseSignedInAccount:$UseSignedInAccount
}
. (Join-Path $solRoot 'engine\_shared\PIM-DemoData.ps1')      # the ONE demo-environment proof (Get-PimDemoEnvironmentProof)
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateState.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-License.ps1')
if (-not (Get-Command New-PimCommitJournalContext -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-CommitJournal.ps1') }
. (Join-Path $solRoot 'engine\_shared\PIM-DemoSamples.ps1')

$action = if ($Remove) { 'Remove' } else { 'Apply' }
# -WhatIf never writes: it is the plan, whatever -Apply says.
$write = [bool]$Apply
if ($write -and -not $PSCmdlet.ShouldProcess("the PIM store ($(Get-PimDemoSampleSource))", $(if ($Remove) { 'remove the sample configuration rows' } else { 'add the sample configuration rows' }))) { $write = $false }
Write-Host "==> sample configuration: $(if ($Remove) { 'REMOVE' } else { 'ADD' }) ($(if ($write) { 'APPLY' } else { 'plan only -- add -Apply to change' }))" -ForegroundColor Cyan

$actor = if ("$($global:PIM_ClientId)".Trim()) { "$($global:PIM_ClientId)" } else { "$($global:PIM_SetupActor)" }
$store = New-PimDemoSampleSqlStore -ConnectionString $cs -Actor $actor

$elig = $null; $model = $null; $validate = $null
if ($action -eq 'Apply') {
    # 1. THE PROOF FIRST -- before the model is built or a row is read.
    $elig = Get-PimDemoEnvironmentProof -ConnectionString $cs
    Write-Host ("    ring: {0}   licence: {1} {2}" -f $(if ($elig.ringRecorded) { $elig.ringText } else { 'not recorded' }), $elig.licenceStatus, $(if ($elig.customer) { "($($elig.customer))" } else { '' })) -ForegroundColor DarkGray
    if (-not $elig.allowed) {
        foreach ($r in $elig.reasons) { Write-Host "    REFUSED: $r" -ForegroundColor Red }
        throw 'REFUSED: the sample configuration is allowed only on the demo environment. Nothing was written.'
    }
    # 2. the model
    $placeholder = $false
    if (-not "$Domain".Trim() -or -not @($DepartmentOwnerUpn | Where-Object { "$_".Trim() }).Count) {
        if ($write) { throw 'REFUSED: -Apply needs -Domain (the tenant''s own verified domain) and -DepartmentOwnerUpn (one or more EXISTING accounts that own the departments and receive the mail about the sample admins). Nothing was written.' }
        $placeholder = $true
        if (-not "$Domain".Trim()) { $Domain = 'your-domain.example' }
        if (-not @($DepartmentOwnerUpn | Where-Object { "$_".Trim() }).Count) { $DepartmentOwnerUpn = @("department-owner@$Domain") }
        Write-Host '    (plan with placeholders: give -Domain and -DepartmentOwnerUpn to see the real names; both are required with -Apply)' -ForegroundColor Yellow
    }
    $model = Get-PimDemoSampleModel -Domain $Domain -DepartmentOwnerUpn $DepartmentOwnerUpn -UsageLocation $UsageLocation
    Write-Host ("    company {0}: {1} departments, {2} admins, {3} groups, {4} delegation rows ({5} time-limited), {6} rows in all" -f $model.company, $model.counts.departments, $model.counts.admins, $model.counts.groups, $model.counts.delegationRows, $model.counts.timeLimited, $model.counts.rows)
    Write-Host '    the ENGINE will then create in the tenant:' -ForegroundColor Yellow
    foreach ($l in $model.engineObjects) { Write-Host "      * $l" -ForegroundColor Yellow }
    # 3. the Manager's own validator over the result. It must be able to run: no validator = no write.
    # ($script: names: these blocks run deep inside the validator, whose own locals must not shadow them.)
    $script:PimDemoSampleValidatorPath = Join-Path $solRoot 'tools\pim-manager\_validator.ps1'
    $script:PimDemoSampleCs = $cs
    $script:PimDemoSampleNaming = @{}
    try { $nc = Get-PimSqlSetting -ConnectionString $cs -Name 'NamingConventions'; if ($nc -and $nc -isnot [string]) { foreach ($p in $nc.PSObject.Properties) { $script:PimDemoSampleNaming[$p.Name] = $p.Value } } }
    catch { Write-Warning "the naming conventions could not be read -- the validator uses the shipped ones: $($_.Exception.Message)" }
    $script:PimDemoSampleRowCache = @{}
    $validate = {
        param($pending)
        Get-PimDemoSampleValidationErrors -ValidatorPath $script:PimDemoSampleValidatorPath -Naming $script:PimDemoSampleNaming -Pending $pending -ReadRows {
            param($entity)
            if (-not $script:PimDemoSampleRowCache.ContainsKey("$entity")) { $script:PimDemoSampleRowCache["$entity"] = @(Get-PimSqlRows -ConnectionString $script:PimDemoSampleCs -Entity "$entity") }
            return @($script:PimDemoSampleRowCache["$entity"])
        }
    }
}

$res = Invoke-PimDemoSampleChange -Action $action -Store $store -Model $model -Eligibility $elig -Apply:$write -Validate $validate -Actor $actor
foreach ($l in $res.plan) { Write-Host "    $l" }
if ($action -eq 'Apply') {
    if ($write) { Write-Host ("    done: {0} row(s) added (commit {1}, source {2}), {3} already there, {4} kept as they were -- read back OK" -f $res.added, $(if ($res.commitId) { $res.commitId } else { '-' }), $res.source, $res.present, $res.kept) -ForegroundColor Green }
    else { Write-Host ("    would add {0} row(s); {1} already there; {2} kept as they are" -f $res.toAdd, $res.present, $res.kept) }
} else {
    if ($write) { Write-Host ("    done: {0} sample row(s) removed (commit {1}); {2} left alone because someone changed them" -f $res.removed, $(if ($res.commitId) { $res.commitId } else { '-' }), $res.changed) -ForegroundColor Green }
    else { Write-Host ("    would remove {0} sample row(s); {1} left alone because someone changed them" -f $res.toRemove, $res.changed) }
    Write-Host '    note: the engine''s daily reconcile then removes the groups and assignments it created for these rows (when its removal rules hold); it never deletes or disables an admin account -- the sample accounts stay until someone deletes them.' -ForegroundColor DarkGray
}
$res
