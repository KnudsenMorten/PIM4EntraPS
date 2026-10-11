#Requires -Version 5.1
<#
.SYNOPSIS
    PIM REQUIREMENTS 100.68 (b) -- put the synthetic DEMO DATASET on the internal demo environment (-Enable), or remove it
    completely (-Disable). Plan by default; -Apply to change.

.DESCRIPTION
    The demo dataset (engine/_shared/PIM-DemoData.ps1) is thousands of generic users / groups / roles and months of
    activity with every health check green, so the Dashboard can be shown to a prospect. It lives in its own SQL schema
    (pimdemo), never in a table the engine reads, and the Dashboard, footer and every export say "Demo data" while it is on.

    -Enable REFUSES -- before anything is written -- unless the environment is PROVEN to be the internal demo one:
      * its update ring is recorded (pim.Settings UpdateState) and is 0 or 1 -- ring 2 / 3 are customer rings, and a ring
        that is not recorded or cannot be read is unsure, so refused;
      * it holds a valid licence (pim.Settings License, verified offline) whose customer is an internal / demo licensee
        (customer text matching "internal" or "demo") -- no licence, an invalid one or a customer's licence is refused.
    -Disable is allowed anywhere: it only drops the pimdemo schema.

    The environment variable PIM_DEMO_MODE on the Manager can switch the display OFF (PIM_DEMO_MODE=off) without removing
    the data; PIM_DEMO_MODE=on without the flag this script writes does nothing.

.PARAMETER ConnectionString
    An already-open store connection string (from an ops session). Otherwise give -SqlServerFqdn + -TenantId and an identity.

.EXAMPLE
    .\Set-PimDemoMode.ps1 -SqlServerFqdn <server>.database.windows.net -TenantId <tenant> -UseSignedInAccount -Enable
    (plan only) ... -Enable -Apply (seed) ... -Disable -Apply (remove everything)
#>
[CmdletBinding(DefaultParameterSetName = 'Enable')]
param(
    [Parameter(ParameterSetName = 'Enable', Mandatory)][switch]$Enable,
    [Parameter(ParameterSetName = 'Disable', Mandatory)][switch]$Disable,
    [switch]$Apply,
    [string]$ConnectionString,
    [string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseSignedInAccount,
    [int]$Seed = 1068,
    [int]$Months = 6
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
. (Join-Path $solRoot 'engine\_shared\PIM-DemoData.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateState.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-License.ps1')

$action = if ($Disable) { 'Disable' } else { 'Enable' }
Write-Host "==> demo dataset: $action ($(if ($Apply) { 'APPLY' } else { 'plan only -- add -Apply to change' }))" -ForegroundColor Cyan

$elig = $null
if ($action -eq 'Enable') {
    $ring = ''; $ringRec = $false; $ringErr = ''
    try {
        $rec = Read-PimUpdateState -ConnectionString $cs
        $v = Get-PimUpdateStateVerdict -Record $rec
        $ringRec = [bool]$v.recorded; $ring = "$($v.ring)"
    } catch { $ringErr = "$($_.Exception.Message)" }
    $licStatus = ''; $licCustomer = ''; $licErr = ''
    try {
        $raw = Get-PimSqlSettingRaw -ConnectionString $cs -Name 'License'
        if ("$raw".TrimStart().StartsWith('"')) { $raw = "$raw" | ConvertFrom-Json }   # stored as a JSON string of the document
        if ("$raw".Trim()) { $lic = Get-PimLicense -LicenseText "$raw"; $licStatus = "$($lic.Status)"; $licCustomer = "$($lic.Customer)" } else { $licStatus = 'Missing' }
    } catch { $licErr = "$($_.Exception.Message)" }
    $elig = Get-PimDemoModeEligibility -Ring $ring -RingRecorded $ringRec -RingError $ringErr -LicenceStatus $licStatus -LicenceCustomer $licCustomer -LicenceError $licErr
    Write-Host ("    ring: {0}   licence: {1} {2}" -f $(if ($ringRec) { $ring } else { 'not recorded' }), $licStatus, $(if ($licCustomer) { "($licCustomer)" } else { '' })) -ForegroundColor DarkGray
    if (-not $elig.allowed) {
        foreach ($r in $elig.reasons) { Write-Host "    REFUSED: $r" -ForegroundColor Red }
        throw "REFUSED: demo data is allowed only on the internal demo environment. Nothing was written."
    }
}

$ds = if ($action -eq 'Enable') { New-PimDemoDataset -Seed $Seed -Months $Months } else { $null }
$res = Invoke-PimDemoModeChange -Action $action -ConnectionString $cs -Eligibility $elig -Apply:$Apply -Dataset $ds
foreach ($p in $res.plan) { Write-Host "    $(if ($Apply) { 'done' } else { 'would' }): $p" }
if ($Apply) {
    $flag = Read-PimDemoFlag -ConnectionString $cs
    if ($action -eq 'Enable' -and $flag -ne 'true') { throw 'read-back FAILED: pimdemo.Meta DemoEnvironment is not true' }
    if ($action -eq 'Disable' -and $flag) { throw 'read-back FAILED: the demo schema is still there' }
    try {
        $actor = if ("$($global:PIM_ClientId)".Trim()) { "$($global:PIM_ClientId)" } else { "$($global:PIM_SetupActor)" }
        Write-PimSqlAuditEvent -ConnectionString $cs -Actor $actor -ActorSource 'setup' -Action "demo-data.$($action.ToLowerInvariant())" -Target 'pimdemo' -After ([ordered]@{ counts = $res.counts; seed = $Seed })
    } catch { Write-Warning "audit 'demo-data.$($action.ToLowerInvariant())' could not be written: $($_.Exception.Message)" }
    Write-Host "    read back OK" -ForegroundColor Green
}
$res
