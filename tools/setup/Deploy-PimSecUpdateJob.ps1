#Requires -Version 5.1
<#
.SYNOPSIS
    SEC-PATCH-PIPELINE-1 (1)-(3) -- the security image job caj-pim-secupdate on an install (cron 7,22,37,52, image-only, separate
    from the normal updater). OFF BY DEFAULT: nothing is created unless -Enable is passed or pim.Settings 'SecUpdateJob' is
    already on.

.DESCRIPTION
    Idempotent, every step read back (engine/_shared/PIM-SecUpdate.ps1 Invoke-PimSecUpdateConverge):
      1. the switch: -Enable writes pim.Settings 'SecUpdateJob' = { enabled: true } (needs -SqlServerFqdn + -TenantId); without
         -Enable the setting is READ -- not on = "OFF", exit 0, nothing created (the default for every install);
      2. the rights check: every right the job uses must be on the approved rights list (RIGHTS-1, PIM-RightsList.ps1) --
         one that is not = nothing created, reported; this script grants NO right (the job runs as the updater identity
         and uses only its Contributor on the resource group + AcrPull on the registry);
      3. the job: derived from the updater job (same image, environment, identity, store settings, registry pull), a Schedule
         trigger 7,22,37,52 (off the updater quarter minutes), one execution at a time, the secupdate entry; created when missing, re-written when it drifts.
    -WhatIf: every write is printed, none is sent. The cost basis (Get-PimSecUpdateCostBasis) is printed with the plan.

.EXAMPLE
    .\Deploy-PimSecUpdateJob.ps1 -SubscriptionId <s> -ResourceGroup rg-pim -WhatIf
    .\Deploy-PimSecUpdateJob.ps1 -SubscriptionId <s> -ResourceGroup rg-pim -TenantId <t> -SqlServerFqdn sql-pim.database.windows.net -Enable
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$UpdateJobName = '',
    [string]$TenantId = '',
    [string]$SqlServerFqdn = '',
    [string]$SqlDatabase = 'PimPlatform',
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseSignedInAccount,
    # the owner's / Invardia's switch for THIS install: writes pim.Settings 'SecUpdateJob' = on, then creates the job
    [switch]$Enable
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
. (Join-Path $solRoot 'engine\_shared\PIM-SecUpdate.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-RightsList.ps1')
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m) { Write-Host "    $m" -ForegroundColor Yellow }

$S = "$SubscriptionId".Trim()
Write-Host "`n=== PIM Manager security image job ($(Get-PimSecUpdateJobName)) ===" -ForegroundColor Cyan
$cb = Get-PimSecUpdateCostBasis
Note ("cost basis: {0} runs / month x {1} s x {2} vCPU / {3} = ~{4} USD; ACR Tasks {5} builds x {6} s = ~{7} USD; total ~{8} USD / month ({9})" -f $cb.runsPerMonth, $cb.runSeconds, $cb.cpu, $cb.memory, $cb.jobUsdPerMonth, $cb.acrBuildsPerMonth, $cb.acrBuildSeconds, $cb.acrUsdPerMonth, $cb.totalUsdPerMonth, $cb.note)

# ---- 1. the switch -------------------------------------------------------------------------------------------------
$cs = $null
if ("$SqlServerFqdn".Trim() -and "$TenantId".Trim()) {
    . (Join-Path $here '_PimSetupSql.ps1')
    try { $cs = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -UseSignedInAccount:$UseSignedInAccount }
    catch { Warn "the store could not be reached from this host ($((("$($_.Exception.Message)") -split "`n")[0]))" }
}
$cur = $null; if ($cs) { try { $cur = Get-PimSqlSetting -ConnectionString $cs -Name (Get-PimSecUpdateSettingName) } catch { $cur = $null } }
if ($Enable) {
    if (-not $cs) { throw "-Enable writes pim.Settings '$(Get-PimSecUpdateSettingName)' -- pass -SqlServerFqdn and -TenantId (a reachable store); nothing created" }
    if ($PSCmdlet.ShouldProcess("pim.Settings '$(Get-PimSecUpdateSettingName)'", 'switch the security image job ON')) {
        Set-PimSqlSetting -ConnectionString $cs -Name (Get-PimSecUpdateSettingName) -ValueJson ((New-PimSecUpdateSettingValue -By 'Deploy-PimSecUpdateJob') | ConvertTo-Json -Compress)
        $cur = Get-PimSqlSetting -ConnectionString $cs -Name (Get-PimSecUpdateSettingName)
    } else { Note "WhatIf: pim.Settings '$(Get-PimSecUpdateSettingName)' = { enabled: true }"; $cur = New-PimSecUpdateSettingValue }
}
$en = Test-PimSecUpdateEnabled -Value $cur
if (-not $en.enabled) { Write-Host "==> OFF: $($en.reason). Nothing created. (-Enable switches it on for this install.)" -ForegroundColor Yellow; exit 0 }
Note $en.reason

# ---- 2 + 3. the rights check and the job -------------------------------------------------------------------------------
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $S) }
if (-not "$UpdateJobName".Trim()) {
    foreach ($n in @('caj-pim-updater', 'ca-pim-update')) { if (-not "$UpdateJobName".Trim() -and (Get-PimArmAcaJob -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $n -ErrorAsNull)) { $UpdateJobName = $n } }
}
if (-not "$UpdateJobName".Trim()) { throw "no updater job (caj-pim-updater / ca-pim-update) in $ResourceGroup -- install the updater first." }
$ver = "$([IO.File]::ReadAllText((Join-Path $solRoot 'VERSION')))".Trim()
$list = Get-PimApprovedRightsList -Version $ver
$arm = {
    param($m, $p, $b)
    if ($m -eq 'GET') { return (Invoke-PimSetupArm -Path $p -ApiVersion (Get-PimSecUpdateAcaApiVersion) -NotFoundOk -ErrorAsNull) }
    if ($WhatIfPreference) { Note "WhatIf: $m $(($p -split '\?')[0])"; return $null }
    return (Invoke-PimSetupArm -Method $m -Path $p -Body $b -ApiVersion (Get-PimSecUpdateAcaApiVersion))
}
Step "converge: $(Get-PimSecUpdateJobName) from the updater job $UpdateJobName"
$r = Invoke-PimSecUpdateConverge -SubscriptionId $S -ResourceGroup $ResourceGroup -UpdaterJob $UpdateJobName -Enabled $true -EnabledReason $en.reason -Arm $arm -RightsList $list
foreach ($l in @($r.lines)) { if ($l.level -eq 'warn') { Warn $l.text } else { Note $l.text } }
if ($r.state -eq 'refused') { throw 'a right the job needs is not on the approved rights list -- nothing created (see above)' }
if ($r.state -ne 'ok' -and -not $WhatIfPreference) { throw "the security image job is not in place ($(@($r.lines | Where-Object { $_.level -eq 'warn' } | ForEach-Object { $_.text }) -join ' | '))" }
Write-Host "==> security image job ready: $(Get-PimSecUpdateJobName), $(if ("$($r.cron)".Trim()) { $r.cron } else { Get-PimSecUpdateCron }) UTC (off the updater's minutes), image-only, as the updater identity (no right granted here)." -ForegroundColor Green
exit 0
