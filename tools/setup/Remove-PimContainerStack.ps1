#Requires -Version 5.1

<#
.SYNOPSIS
    71.36 -- remove ONE environment's Container Apps stack (every Container Apps job + app + the managed environment in the
    resource group) and the role assignments held by those apps' system identities -- so the environment can be rebuilt
    with a different EXPOSURE. Plan-only unless -Apply.

.DESCRIPTION
    Removes the Container Apps part of one PIM Manager environment (every Container Apps job and app and the Container Apps environment in the resource group, plus the Azure role assignments held by their system identities) so the environment can be deployed again with a different exposure. Data is kept: the SQL database, the registry, Key Vault, storage, the VNet, the user-assigned identities and Log Analytics. It only lists what it would remove unless -Apply is given.

    A Container Apps environment's internal/external setting is IMMUTABLE. Moving a live environment from external to
    internal ("private only") therefore means: delete the stack, then run the build with exposure internal. Everything
    else is KEPT and re-used by the build: the SQL server + database (all data), the registry + its images, the Key Vault,
    the storage accounts, the VNet, the user-assigned identities, Log Analytics.
    What is deleted: Microsoft.App/jobs, Microsoft.App/containerApps, Microsoft.App/managedEnvironments in -ResourceGroup
    (all of them, listed first), plus the Azure role assignments (in -SubscriptionId) whose principal is one of those
    apps'/jobs' SYSTEM identities (they would be orphaned). Their Graph app-role grants and SQL admin group membership go
    with the identity; the build grants the new identities again.
    NOT touched: user-assigned identities and their grants, anything outside the resource group, Entra objects.
    READ BACK after -Apply: no Microsoft.App resource left, no listed role assignment left.
    -WhatIf: the plan (the same reads and the same list as a run without -Apply); nothing is deleted, even with -Apply.

.EXAMPLE
    ./Remove-PimContainerStack.ps1 -SubscriptionId <subscription-id> -ResourceGroup rg-pim            # plan
    ./Remove-PimContainerStack.ps1 -SubscriptionId <subscription-id> -ResourceGroup rg-pim -Apply     # delete

.LINK
    https://invardia.com/docs/pim/scripts/Remove-PimContainerStack/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [switch]$Apply
)
$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Remove-PimContainerStack'
try {
# 12.7: -WhatIf is the plan -- it wins over -Apply, nothing is deleted.
if ($WhatIfPreference -and $Apply) { Write-Host '  -WhatIf: plan only -- -Apply is ignored, nothing is deleted.' -ForegroundColor Yellow }
if ($WhatIfPreference) { $Apply = $false }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
# 100.41 (framework 12.17 NO-AZ): ARM REST through PIM-Rest's one token client (engine/_shared/PIM-ArmSetup.ps1). A calling
# build's REST session is used as it is; standalone, the Invardia Support app's session or the person signed in. No az.
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
$S = "$SubscriptionId".Trim()
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $S) }
# Every call names the subscription in its ARM path (no default context to depend on): assert THIS subscription is visible.
$acct = "$((Get-PimArmSubscription -SubscriptionId $S -ErrorAsNull).subscriptionId)".Trim()
if ($acct -ne $S) { throw "this sign-in cannot see subscription '$SubscriptionId' (read '$acct') -- refusing." }
$authV = Get-PimSetupApiVersion authorization
function Get-StackResources {
    # az resource list -g RG, filtered to Microsoft.App/*: name, type, id.
    @(Invoke-PimSetupArm -Path "/subscriptions/$S/resourceGroups/$ResourceGroup/resources" -ApiVersion (Get-PimSetupApiVersion resources) -All -ErrorAsNull |
        Where-Object { $_ -and "$($_.type)" -like 'Microsoft.App/*' } | ForEach-Object { [pscustomobject]@{ n = "$($_.name)"; t = "$($_.type)"; id = "$($_.id)" } })
}
function Remove-Logged([string]$Id, [string]$Kind, [string]$Label, [switch]$Wait) {
    # az ... delete --yes: DELETE by id (a missing resource is success). The outcome is said, never swallowed.
    try { Remove-PimArmResource -ResourceId $Id -Kind $Kind -Wait:$Wait; Note "$Label delete: ok" }
    catch { Note "$Label delete FAILED: $($_.Exception.Message)" }
}
Write-Host "==> Container Apps stack in $ResourceGroup ($(if ($Apply) { 'APPLY' } else { 'PLAN ONLY' }))" -ForegroundColor Cyan
$res = @(Get-StackResources)
$jobs = @($res | Where-Object { $_.t -eq 'Microsoft.App/jobs' }); $apps = @($res | Where-Object { $_.t -eq 'Microsoft.App/containerApps' }); $envs = @($res | Where-Object { $_.t -eq 'Microsoft.App/managedEnvironments' })
$pids = @()
foreach ($x in @($jobs) + @($apps)) {
    $p = "$((Get-PimArmResource -ResourceId $x.id -Kind aca -ErrorAsNull).identity.principalId)".Trim()
    if ($p) { $pids += $p }
    Note ("{0,-32} {1,-30} system identity {2}" -f $x.n, $x.t, $(if ($p) { $p } else { '(none)' }))
}
foreach ($e in $envs) { Note ("{0,-32} {1}" -f $e.n, $e.t) }
$ras = @()
foreach ($p in $pids) {
    # az role assignment list --all --assignee P: every assignment of P at, above or below the subscription.
    $f = [uri]::EscapeDataString("principalId eq '$p'")
    foreach ($a in @(Invoke-PimSetupArm -Path "/subscriptions/$S/providers/Microsoft.Authorization/roleAssignments?`$filter=$f" -ApiVersion $authV -All -ErrorAsNull)) {
        if (-not $a -or "$($a.properties.principalId)" -ine $p) { continue }
        $ras += [pscustomobject]@{ id = "$($a.id)"; role = (Get-PimArmRoleName -RoleDefinitionId "$($a.properties.roleDefinitionId)"); scope = "$($a.properties.scope)" }
    }
}
foreach ($r in $ras) { Note "role assignment: $($r.role) @ $($r.scope)" }
if (-not $Apply) { Write-Host "    PLAN ONLY: $($jobs.Count) job(s), $($apps.Count) app(s), $($envs.Count) environment(s), $($ras.Count) role assignment(s). Re-run with -Apply." -ForegroundColor Yellow; return }
# Jobs and apps are waited on (gone before the environment that hosts them is deleted); the environment is polled below.
foreach ($j in $jobs) { Remove-Logged -Id $j.id -Kind aca -Label "job $($j.n)" -Wait }
foreach ($a in $apps) { Remove-Logged -Id $a.id -Kind aca -Label "app $($a.n)" -Wait }
foreach ($r in $ras) { if ("$($r.scope)" -like "/subscriptions/$SubscriptionId*") { Remove-Logged -Id $r.id -Kind authorization -Label "role assignment $($r.role)" } }
foreach ($e in $envs) { Remove-Logged -Id $e.id -Kind aca -Label "environment $($e.n) (can take ~10 minutes)" }
# The resource list lags a completed delete by minutes (measured: an environment whose delete had returned was still
# listed) -- poll before calling it a failure.
$left = @()
for ($w = 0; $w -lt 20; $w++) {
    $left = @(Get-StackResources | ForEach-Object { $_.n })
    if (-not $left.Count) { break }
    Note "still listed: $($left -join ', ') -- waiting 30s"; Start-Sleep -Seconds 30
}
# A deleted role assignment reads back 404 by its own id.
$raLeft = @($ras | Where-Object { "$($_.scope)" -like "/subscriptions/$SubscriptionId*" -and $null -ne (Invoke-PimSetupArm -Path $_.id -ApiVersion $authV -NotFoundOk -ErrorAsNull) })
if ($left.Count -or $raLeft.Count) { throw "read-back: still present -- Microsoft.App: $($left -join ', '); role assignments: $($raLeft.Count)" }
Write-Host '    PASS: no Container Apps resource and none of the listed role assignments remain' -ForegroundColor Green
} finally { Stop-PimScriptRun -Script 'Remove-PimContainerStack' }
