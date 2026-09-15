#Requires -Version 5.1
<#
.SYNOPSIS
    Report every credential a PIM environment depends on, with days remaining. Read-only.

.DESCRIPTION
    🔴 WHY THIS EXISTS. The identity design leaves exactly two credentials in play -- the Easy Auth
    client secret and the operator/deploy SPN secret -- and both EXPIRE. Neither failure is loud:

      * Easy Auth secret expires  -> NOBODY CAN SIGN IN. The app is healthy, the store is fine, the
        engine keeps running; the login redirect just stops working. Reads as an outage with no
        deploy to blame, at whatever hour it happens to fall.
      * Operator SPN secret expires -> no troubleshooting access, discovered at the worst moment,
        which is while troubleshooting something else.
      * Engine SPN secret (legacy environments) expires -> the nightly 03:00 run starts failing, and
        the fleet silently falls behind.

    A credential that dies on a timer needs a calendar, not a memory. This is the calendar.

    Everything is read-only: it reads app-registration credentials via Graph and lists the ACA
    secret NAMES (never values -- a value cannot be read back out of Container Apps, by design, and
    this script never tries).

.PARAMETER WarnDays / FailDays
    Thresholds. Default: warn at 60 days, fail at 21. Exits 1 when anything is inside -FailDays, so
    this can gate a nightly check rather than being something someone remembers to run.

.EXAMPLE
    .\Test-PimCredentialExpiry.ps1 -ResourceGroup rg-automateit-pk417 -SubscriptionId <sub>
    .\Test-PimCredentialExpiry.ps1 -ResourceGroup <rg> -SubscriptionId <sub> -FailDays 30
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$SubscriptionId,
    [string]$ManagerApp = 'ca-pim-manager',
    # Extra app registrations to include (operator/deploy SPNs). The Easy Auth app is discovered
    # from the container app itself, so it never has to be named.
    [string[]]$AppId = @(),
    [int]$WarnDays = 60,
    [int]$FailDays = 21
)
$ErrorActionPreference = 'Stop'

$subArgs = @(); if ("$SubscriptionId".Trim()) { $subArgs = @('--subscription', "$SubscriptionId".Trim()) }
$rows = @()
$worst = [int]::MaxValue

function Add-Row($scope, $kind, $name, $endUtc, $detail) {
    $days = $null
    if ($endUtc) { $days = [int][Math]::Floor((([datetime]$endUtc).ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalDays) }
    if ($null -ne $days -and $days -lt $script:worst) { $script:worst = $days }
    $script:rows += [pscustomobject]@{
        Scope = $scope; Kind = $kind; Name = $name
        Expires = $(if ($endUtc) { ([datetime]$endUtc).ToUniversalTime().ToString('yyyy-MM-dd') } else { '(none)' })
        Days = $days; Detail = $detail
    }
}

Write-Host ""
Write-Host "=== PIM credential expiry -- $ResourceGroup ===" -ForegroundColor Cyan

# ---- 1. the Easy Auth app registration, discovered from the app itself --------------------------
# Discovered rather than named: the whole point is that nobody has to remember which registration
# a given environment's sign-in depends on.
$easyAuthAppId = "$(az containerapp auth show @subArgs -g $ResourceGroup -n $ManagerApp --query 'identityProviders.azureActiveDirectory.registration.clientId' -o tsv 2>$null)".Trim()
$secretSettingName = "$(az containerapp auth show @subArgs -g $ResourceGroup -n $ManagerApp --query 'identityProviders.azureActiveDirectory.registration.clientSecretSettingName' -o tsv 2>$null)".Trim()
if ($easyAuthAppId) {
    Write-Host "  easy auth app : $easyAuthAppId  (secret setting: $(if ($secretSettingName) { $secretSettingName } else { '(none -- implicit flow)' }))" -ForegroundColor DarkGray
    if (-not $secretSettingName) {
        Add-Row 'easy-auth' 'none' '(implicit flow)' $null 'no client secret configured -- nothing to expire'
    }
    $AppId = @($AppId) + $easyAuthAppId
}

# ---- 2. app-registration credentials -----------------------------------------------------------
foreach ($id in (@($AppId) | Where-Object { "$_".Trim() } | Select-Object -Unique)) {
    $disp = "$(az ad app show --id $id --query displayName -o tsv 2>$null)".Trim()
    $label = $(if ($disp) { "$disp" } else { $id })
    $scope = $(if ($id -eq $easyAuthAppId) { 'easy-auth' } else { 'spn' })

    $pw = az ad app credential list --id $id --query "[].{n:displayName,e:endDateTime}" -o json 2>$null
    if ($LASTEXITCODE -ne 0) { Write-Warning "  cannot read credentials for $label -- this identity may lack directory read"; continue }
    foreach ($c in @(($pw | ConvertFrom-Json))) {
        if ($c) { Add-Row $scope 'secret' "$label / $(if ($c.n) { $c.n } else { '(unnamed)' })" $c.e $id }
    }
    $cert = az ad app credential list --id $id --cert --query "[].{n:displayName,e:endDateTime}" -o json 2>$null
    foreach ($c in @(($cert | ConvertFrom-Json))) {
        if ($c) { Add-Row $scope 'certificate' "$label / $(if ($c.n) { $c.n } else { '(unnamed)' })" $c.e $id }
    }
}

# ---- 3. what the environment actually references ------------------------------------------------
# A secret NAME present on the app is not proof the credential behind it is valid -- but its ABSENCE
# is proof sign-in is broken, so it is worth stating either way.
$acaSecretNames = @(az containerapp secret list @subArgs -g $ResourceGroup -n $ManagerApp --query "[].name" -o tsv 2>$null)
Write-Host ("  aca secrets   : {0}" -f $(if ($acaSecretNames.Count) { $acaSecretNames -join ', ' } else { '(none)' })) -ForegroundColor DarkGray
if ($secretSettingName -and $acaSecretNames -notcontains $secretSettingName) {
    Write-Host "  [FAIL] Easy Auth references ACA secret '$secretSettingName' which DOES NOT EXIST on $ManagerApp -- sign-in is broken now." -ForegroundColor Red
    $worst = -1
}

# ---- 4. report ----------------------------------------------------------------------------------
Write-Host ""
if (-not $rows.Count) { Write-Host '  no credentials found (all-managed-identity environment, or no directory read).' -ForegroundColor Green }
else {
    $rows | Sort-Object { if ($null -eq $_.Days) { [int]::MaxValue } else { $_.Days } } |
        Format-Table -AutoSize @{L='Scope';E={$_.Scope}}, @{L='Kind';E={$_.Kind}}, @{L='Name';E={$_.Name}},
                     @{L='Expires';E={$_.Expires}}, @{L='Days';E={$_.Days}} | Out-Host
}

Write-Host ""
foreach ($r in ($rows | Where-Object { $null -ne $_.Days })) {
    if     ($r.Days -lt 0)          { Write-Host ("  EXPIRED   {0} -- {1} ({2} days ago)" -f $r.Kind, $r.Name, [Math]::Abs($r.Days)) -ForegroundColor Red }
    elseif ($r.Days -le $FailDays)  { Write-Host ("  CRITICAL  {0} -- {1} expires in {2} day(s)" -f $r.Kind, $r.Name, $r.Days) -ForegroundColor Red }
    elseif ($r.Days -le $WarnDays)  { Write-Host ("  WARN      {0} -- {1} expires in {2} day(s)" -f $r.Kind, $r.Name, $r.Days) -ForegroundColor Yellow }
}

if ($worst -eq [int]::MaxValue) { Write-Host '  nothing expires -- this environment holds no time-limited credential.' -ForegroundColor Green; exit 0 }
if ($worst -le $FailDays) {
    Write-Host ""
    Write-Host "  ROTATE IT:" -ForegroundColor Yellow
    Write-Host "    Easy Auth : Set-PimManagerEasyAuth.ps1 -App $ManagerApp -ResourceGroup $ResourceGroup -RotateSecret" -ForegroundColor White
    Write-Host "    an SPN    : az ad app credential reset --id <appId> --append --years 2   (--append, or you revoke the others)" -ForegroundColor White
    exit 1
}
Write-Host ("  OK -- nearest expiry is {0} day(s) away (warn at {1}, fail at {2})." -f $worst, $WarnDays, $FailDays) -ForegroundColor Green
exit 0
