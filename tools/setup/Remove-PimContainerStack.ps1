#Requires -Version 5.1
<#
.SYNOPSIS
    71.36 -- remove ONE environment's Container Apps stack (every Container Apps job + app + the managed environment in the
    resource group) and the role assignments held by those apps' system identities -- so the environment can be rebuilt
    with a different EXPOSURE. Plan-only unless -Apply.

.DESCRIPTION
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
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [switch]$Apply
)
$ErrorActionPreference = 'Continue'
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
$sub = @('--subscription', "$SubscriptionId".Trim())
$acct = "$(az account show --query id -o tsv 2>$null)".Trim()
if ($acct -ne "$SubscriptionId".Trim()) { throw "az context is '$acct', not '$SubscriptionId' -- refusing." }
Write-Host "==> Container Apps stack in $ResourceGroup ($(if ($Apply) { 'APPLY' } else { 'PLAN ONLY' }))" -ForegroundColor Cyan
$res = @(az resource list @sub -g $ResourceGroup --query "[].{n:name,t:type,id:id}" -o json --only-show-errors 2>$null | Out-String | ConvertFrom-Json | Where-Object { "$($_.t)" -like 'Microsoft.App/*' })
$jobs = @($res | Where-Object { $_.t -eq 'Microsoft.App/jobs' }); $apps = @($res | Where-Object { $_.t -eq 'Microsoft.App/containerApps' }); $envs = @($res | Where-Object { $_.t -eq 'Microsoft.App/managedEnvironments' })
$pids = @()
foreach ($x in @($jobs) + @($apps)) {
    $p = "$(az resource show @sub --ids $x.id --query identity.principalId -o tsv --only-show-errors 2>$null)".Trim()
    if ($p) { $pids += $p }
    Note ("{0,-32} {1,-30} system identity {2}" -f $x.n, $x.t, $(if ($p) { $p } else { '(none)' }))
}
foreach ($e in $envs) { Note ("{0,-32} {1}" -f $e.n, $e.t) }
$ras = @()
foreach ($p in $pids) { $ras += @(az role assignment list @sub --all --assignee $p --query "[].{id:id,role:roleDefinitionName,scope:scope}" -o json --only-show-errors 2>$null | Out-String | ConvertFrom-Json) }
foreach ($r in $ras) { Note "role assignment: $($r.role) @ $($r.scope)" }
if (-not $Apply) { Write-Host "    PLAN ONLY: $($jobs.Count) job(s), $($apps.Count) app(s), $($envs.Count) environment(s), $($ras.Count) role assignment(s). Re-run with -Apply." -ForegroundColor Yellow; return }
foreach ($j in $jobs) { az containerapp job delete @sub -g $ResourceGroup -n $j.n --yes -o none --only-show-errors; Note "job $($j.n) delete exit=$LASTEXITCODE" }
foreach ($a in $apps) { az containerapp delete @sub -g $ResourceGroup -n $a.n --yes -o none --only-show-errors; Note "app $($a.n) delete exit=$LASTEXITCODE" }
foreach ($r in $ras) { if ("$($r.scope)" -like "/subscriptions/$SubscriptionId*") { az role assignment delete @sub --ids $r.id -o none --only-show-errors; Note "role assignment $($r.role) delete exit=$LASTEXITCODE" } }
foreach ($e in $envs) { az containerapp env delete @sub -g $ResourceGroup -n $e.n --yes -o none --only-show-errors; Note "environment $($e.n) delete exit=$LASTEXITCODE (can take ~10 minutes)" }
# The resource list lags a completed delete by minutes (measured: an environment whose delete had returned 0 was still
# listed) -- poll before calling it a failure.
for ($w = 0; $w -lt 20; $w++) {
    $left = @(az resource list @sub -g $ResourceGroup --query "[].{n:name,t:type}" -o json --only-show-errors 2>$null | Out-String | ConvertFrom-Json | Where-Object { "$($_.t)" -like 'Microsoft.App/*' } | ForEach-Object { $_.n })
    if (-not $left.Count) { break }
    Note "still listed: $($left -join ', ') -- waiting 30s"; Start-Sleep -Seconds 30
}
$raIdsNow = @(az role assignment list @sub --all --query "[].id" -o tsv --only-show-errors 2>$null); $raLeft = @($ras | Where-Object { $raIdsNow -contains $_.id })
if ($left.Count -or $raLeft.Count) { throw "read-back: still present -- Microsoft.App: $($left -join ', '); role assignments: $($raLeft.Count)" }
Write-Host '    PASS: no Container Apps resource and none of the listed role assignments remain' -ForegroundColor Green
