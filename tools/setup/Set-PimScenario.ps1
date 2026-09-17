#Requires -Version 5.1
<#
.SYNOPSIS
    71.18 -- set the deployment scenario (S1..S6) of a deployed environment: pim.Settings 'Scenario'.

.DESCRIPTION
    The only writer used to be the Manager's PUT /api/settings/scenario (a signed-in SuperAdmin), so every build ended
    with a hand step -- and an unset scenario resolves as S1 (single tenant): an MSP master then publishes nothing and a
    managed tenant never pulls. Same stored shape as the Manager ({"scenario":"S3"}), validated against the scenario
    catalog, READ BACK, audited ('settings.scenario.save', like the Manager). Certificate identity only.

.EXAMPLE
    .\Set-PimScenario.ps1 -SqlServerFqdn sql-ait-wa678.database.windows.net -Scenario S3 -TenantId <t> -ClientId <app> -CertThumbprint <thumb>
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [Parameter(Mandatory)][ValidateSet('S1','S2','S3','S4','S5','S6')][string]$Scenario,
    [Parameter(Mandatory)][string]$TenantId,
    # Certificate identity -- OR -UseSignedInAccount (71.33: the signed-in az user, a member of the SQL admin group).
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseSignedInAccount
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot '_PimSetupSql.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-ScenarioProfile.ps1')
$sc = Get-PimScenario -Id $Scenario
if (-not $sc) { throw "scenario '$Scenario' is not in the scenario catalog." }

$cs = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -UseSignedInAccount:$UseSignedInAccount
$before = Get-PimSqlSetting -ConnectionString $cs -Name 'Scenario'
$beforeId = if ($before -is [string]) { "$before".Trim() } elseif ($before) { "$($before.scenario)".Trim() } else { '' }
Write-Host ("==> scenario on {0}: '{1}' -> '{2}' ({3})" -f $SqlServerFqdn, $(if ($beforeId) { $beforeId } else { '(unset = S1)' }), $sc.id, $sc.role) -ForegroundColor Cyan
if ($beforeId -eq $sc.id) { Write-Host '    already set -- nothing to do' -ForegroundColor DarkGray; return }
if ($PSCmdlet.ShouldProcess($SqlServerFqdn, "pim.Settings Scenario = $($sc.id)")) {
    Set-PimSqlSetting -ConnectionString $cs -Name 'Scenario' -Value ([ordered]@{ scenario = "$($sc.id)" })
    $after = Get-PimSqlSetting -ConnectionString $cs -Name 'Scenario'
    if ("$($after.scenario)" -ne $sc.id) { throw "read-back FAILED: pim.Settings Scenario is '$($after | ConvertTo-Json -Compress)', expected $($sc.id)" }
    Write-PimSetupAudit -ConnectionString $cs -Action 'settings.scenario.save' -Target 'Scenario' -Before $before -After @{ scenario = $sc.id }
    Write-Host "    read back OK: $($sc.id)" -ForegroundColor DarkGray
}
