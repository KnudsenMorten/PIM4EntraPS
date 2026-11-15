#Requires -Version 5.1
<#
.SYNOPSIS
    WAKE-1 (framework SECURE-WEB-1 point 1, 3.1.26) -- the wake queue, the wake job (caj-pim-wake) and their rights on an
    install: Commit / Run now in the Manager then start the engine within a minute, with no job right for the web app.

.DESCRIPTION
    Idempotent, every step read back (engine/_shared/PIM-Wake.ps1 Invoke-PimWakeConverge -Grant). In order:
      1. the queue 'pim-wake' in the install's own storage account (the PIM storage account the as-built step creates:
         Entra-only, shared-key access OFF -- refused otherwise);
      2. the job caj-pim-wake: an EVENT-triggered Container Apps job (KEDA azure-queue rule, authenticated as the engine's
         user-assigned identity -- no key, no connection string), derived from the engine job: the same image, environment,
         size, store settings and identity, the wake entry tools/pim-engine/wake-job-entry.ps1 instead of the scheduler;
      3. the rights on THAT queue only: the web identity 'Storage Queue Data Message Sender'; the engine identity 'Storage
         Queue Data Message Processor' + 'Storage Queue Data Reader' (granted when missing, read back -- this needs an Owner /
         User Access Administrator of the resource group; the in-cloud updater only REPORTS a missing one);
      4. with -SqlServerFqdn: pim.Settings 'WakeQueue' (the storage account the Manager sends to). Without it the updater's
         next run records it.
    The web identity gets NO job right here or anywhere: the wake job checks every message itself (its age, a job name from
    its shipped allow-list, nothing else) and audits it.

.EXAMPLE
    .\Deploy-PimWakeJob.ps1 -SubscriptionId <s> -ResourceGroup rg-pim -TenantId <t> -SqlServerFqdn sql-pim.database.windows.net
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$TickJobName = '',
    [string]$ManagerApp = '',
    [string]$StorageAccount = '',
    [string]$TenantId = '',
    [string]$SqlServerFqdn = '',
    [string]$SqlDatabase = 'PimPlatform',
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseSignedInAccount,
    # report only: create the queue and the job, grant nothing (what the updater does)
    [switch]$SkipGrant
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
. (Join-Path $solRoot 'engine\_shared\PIM-Wake.ps1')
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m) { Write-Host "    $m" -ForegroundColor Yellow }

$S = "$SubscriptionId".Trim()
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $S) }
$rgId = "/subscriptions/$S/resourceGroups/$ResourceGroup"
# the engine job and the web app by the names this install runs with (new-name installs: caj-pim-engine / ca-pim-web)
if (-not "$TickJobName".Trim()) {
    foreach ($n in @('caj-pim-engine', 'ca-pim-engine', 'ca-pim-tick')) { if (-not "$TickJobName".Trim() -and (Get-PimArmAcaJob -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $n -ErrorAsNull)) { $TickJobName = $n } }
}
if (-not "$TickJobName".Trim()) { throw "no engine job (caj-pim-engine / ca-pim-tick) in $ResourceGroup -- deploy the hosting step first." }
if (-not "$ManagerApp".Trim()) {
    foreach ($n in @('ca-pim-web', 'ca-pim-manager')) { if (-not "$ManagerApp".Trim() -and (Get-PimArmAcaApp -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $n -ErrorAsNull)) { $ManagerApp = $n } }
    if (-not "$ManagerApp".Trim()) { $ManagerApp = 'ca-pim-manager' }
}
$abJob = ''
foreach ($n in @('caj-pim-docs', 'caj-pim-asbuilt')) { if (-not $abJob -and (Get-PimArmAcaJob -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $n -ErrorAsNull)) { $abJob = $n } }
Write-Host "`n=== PIM Manager wake queue + wake job ($(Get-PimWakeJobName)) ===" -ForegroundColor Cyan
Note "engine job $TickJobName ; web app $ManagerApp ; resource group $ResourceGroup"

# ARM seam: the path carries its api-version (PIM-Wake.ps1); a GET of an absent resource answers $null
$arm = {
    param($m, $p, $b)
    if ($m -eq 'GET') { return (Invoke-PimSetupArm -Path $p -ApiVersion '2024-03-01' -NotFoundOk -ErrorAsNull) }
    if ($WhatIfPreference) { Note "WhatIf: $m $(($p -split '\?')[0])"; return $null }
    return (Invoke-PimSetupArm -Method $m -Path $p -Body $b -ApiVersion '2024-03-01')
}
$grant = $null
if (-not $SkipGrant) {
    $grant = {
        param($scope, $oid, $roleId)
        if ($WhatIfPreference) { Note "WhatIf: grant role $roleId to $oid on $scope"; return $null }
        [void](New-PimArmRoleAssignment -SubscriptionId $S -Scope $scope -PrincipalId $oid -PrincipalType ServicePrincipal -Role $roleId)
    }
}
$store = $null; $cs = $null
if (-not ("$SqlServerFqdn".Trim() -and "$TenantId".Trim())) { Note 'no -SqlServerFqdn / -TenantId: pim.Settings ''WakeQueue'' is recorded by the in-cloud updater on its next run' }
else {
    . (Join-Path $here '_PimSetupSql.ps1')
    $cs = $null
    try { $cs = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -UseSignedInAccount:$UseSignedInAccount }
    catch { Warn "the store could not be reached from this host ($((("$($_.Exception.Message)") -split "`n")[0])) -- pim.Settings 'WakeQueue' is recorded by the in-cloud updater on its next run" }
}
if ($cs) {
    $store = {
        param($op, $name, $value)
        switch ($op) {
            'get' { return (Get-PimSqlSetting -ConnectionString $cs -Name $name) }
            'set' { if ($WhatIfPreference) { Note "WhatIf: pim.Settings $name"; return $null }; Set-PimSqlSetting -ConnectionString $cs -Name $name -Value $value; return $null }
        }
    }
}

$cvArgs = @{ SubscriptionId = $S; ResourceGroup = $ResourceGroup; EngineJob = $TickJobName; ManagerApp = $ManagerApp; Arm = $arm }
if ("$StorageAccount".Trim()) { $cvArgs['StorageAccount'] = "$StorageAccount".Trim() }
if ($abJob) { $cvArgs['AsBuiltJob'] = $abJob }
if ($grant) { $cvArgs['Grant'] = $grant }
if ($store) { $cvArgs['Store'] = $store }
Step 'converge: queue, job, rights on the queue, the Manager''s setting'
$r = Invoke-PimWakeConverge @cvArgs
foreach ($l in @($r.lines)) { if ($l.level -eq 'warn') { Warn $l.text } else { Note $l.text } }
if ($r.state -ne 'ok') { throw "the wake queue / job is not in place ($(@($r.lines | Where-Object { $_.level -eq 'warn' } | ForEach-Object { $_.text }) -join ' | ')) -- Commit / Run now keep waiting for the next scheduled start" }
if ($r.rights -eq 'missing' -and -not $SkipGrant -and -not $WhatIfPreference) { throw 'a right on the wake queue did not read back (see above) -- this needs an Owner / User Access Administrator of the resource group' }
Write-Host "==> wake ready: $($r.account)/$(Get-PimWakeQueueName) -> $(Get-PimWakeJobName) (rights: $($r.rights)). The web app holds no job right." -ForegroundColor Green
exit 0
