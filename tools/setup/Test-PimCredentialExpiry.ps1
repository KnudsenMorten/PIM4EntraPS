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
    # Mandatory (BUG-215): without it every containerapp read went to whatever subscription happened to
    # be the az default -- another tenant's, on a host signed in to two -- and then "found nothing".
    [Parameter(Mandatory)][string]$SubscriptionId,
    [string]$ManagerApp = 'ca-pim-manager',
    # Extra app registrations to include (operator/deploy SPNs). The Easy Auth app is discovered
    # from the container app itself, so it never has to be named.
    [string[]]$AppId = @(),
    [int]$WarnDays = 60,
    [int]$FailDays = 21
)
$ErrorActionPreference = 'Stop'

# 100.41 (framework 12.17 NO-AZ): ARM + Graph REST through PIM-Rest's one token client (engine/_shared/PIM-ArmSetup.ps1).
# A calling run's REST session is used as it is; standalone, the Invardia Support app's session or the person signed in.
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
$S = "$SubscriptionId".Trim()
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $S) }
$rows = @()
$worst = [int]::MaxValue
# 🔴 BUG-196 -- WHAT COULD NOT BE READ. Every read below used to fail quietly into "no rows", and the
# end of the script then said "nothing expires -- this environment holds no time-limited credential"
# and exited 0: a report that read NOTHING scored as the healthiest possible answer. Each failed read is
# recorded here, and any entry makes the run INCOMPLETE (exit 1) -- a skip is not a pass.
$unread = New-Object System.Collections.Generic.List[string]

function Get-PimCredentialExpiryVerdict {
    # PURE (BUG-196). exit 0 only when EVERYTHING was read and nothing is inside -FailDays.
    param([int]$Worst = [int]::MaxValue, [int]$FailDays = 21, [string[]]$Unread = @())
    $u = @($Unread | Where-Object { "$_".Trim() })
    if ($Worst -le $FailDays) { return @{ exit = 1; status = 'critical' } }
    if ($u.Count)             { return @{ exit = 1; status = 'incomplete' } }
    if ($Worst -eq [int]::MaxValue) { return @{ exit = 0; status = 'none' } }
    return @{ exit = 0; status = 'ok' }
}

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
# One read, checked: an unreadable auth config is recorded, not taken as "no Easy Auth".
$easyAuthAppId = ''; $secretSettingName = ''
# az containerapp auth show = GET authConfigs/current. A 404 (no Easy Auth) answers $null; any other failure is UNREAD.
$authRead = $true
$auth = $null
try { $auth = Get-PimArmAcaAuthConfig -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $ManagerApp } catch { $authRead = $false }
if (-not $authRead -or -not $auth) { $unread.Add("the Easy Auth configuration of $ManagerApp") }
else {
    $easyAuthAppId     = "$($auth.properties.identityProviders.azureActiveDirectory.registration.clientId)".Trim()
    $secretSettingName = "$($auth.properties.identityProviders.azureActiveDirectory.registration.clientSecretSettingName)".Trim()
}
if ($easyAuthAppId) {
    Write-Host "  easy auth app : $easyAuthAppId  (secret setting: $(if ($secretSettingName) { $secretSettingName } else { '(none -- implicit flow)' }))" -ForegroundColor DarkGray
    if (-not $secretSettingName) {
        Add-Row 'easy-auth' 'none' '(implicit flow)' $null 'no client secret configured -- nothing to expire'
    }
    $AppId = @($AppId) + $easyAuthAppId
}

# ---- 2. app-registration credentials -----------------------------------------------------------
foreach ($id in (@($AppId) | Where-Object { "$_".Trim() } | Select-Object -Unique)) {
    # az ad app show + az ad app credential list [--cert] = ONE Graph read of the application: its passwordCredentials
    # (secrets) and keyCredentials (certificates) carry displayName + endDateTime. Unreadable = UNREAD, never "none".
    $app = $null; $appErr = ''
    try { $app = Get-PimGraphApplication -Id $id } catch { $appErr = "$($_.Exception.Message)" }
    if (-not $app) {
        Write-Warning "  cannot read credentials for $id -- this identity may lack directory read$(if ($appErr) { " ($appErr)" })"
        $unread.Add("the secrets of $id"); $unread.Add("the certificates of $id"); continue
    }
    $disp = "$($app.displayName)".Trim()
    $label = $(if ($disp) { "$disp" } else { $id })
    $scope = $(if ($id -eq $easyAuthAppId) { 'easy-auth' } else { 'spn' })
    foreach ($c in @($app.passwordCredentials)) {
        if ($c) { Add-Row $scope 'secret' "$label / $(if ($c.displayName) { $c.displayName } else { '(unnamed)' })" $c.endDateTime $id }
    }
    foreach ($c in @($app.keyCredentials)) {
        if ($c) { Add-Row $scope 'certificate' "$label / $(if ($c.displayName) { $c.displayName } else { '(unnamed)' })" $c.endDateTime $id }
    }
}

# ---- 3. what the environment actually references ------------------------------------------------
# A secret NAME present on the app is not proof the credential behind it is valid -- but its ABSENCE
# is proof sign-in is broken, so it is worth stating either way.
# az containerapp secret list --query "[].name" = POST listSecrets; only the NAMES are kept (values are never printed).
$secretsRead = $true
$acaSecretNames = @()
try { $acaSecretNames = @(Get-PimArmAcaAppSecrets -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $ManagerApp | ForEach-Object { "$($_.name)".Trim() } | Where-Object { $_ }) } catch { $secretsRead = $false }
if (-not $secretsRead) { $unread.Add("the secret names on $ManagerApp") }
Write-Host ("  aca secrets   : {0}" -f $(if ($acaSecretNames.Count) { $acaSecretNames -join ', ' } else { '(none)' })) -ForegroundColor DarkGray
if ($secretsRead -and $secretSettingName -and $acaSecretNames -notcontains $secretSettingName) {
    Write-Host "  [FAIL] Easy Auth references ACA secret '$secretSettingName' which DOES NOT EXIST on $ManagerApp -- sign-in is broken now." -ForegroundColor Red
    $worst = -1
}

# ---- 4. report ----------------------------------------------------------------------------------
Write-Host ""
if (-not $rows.Count -and $unread.Count) { Write-Host '  no credentials could be listed -- see INCOMPLETE below.' -ForegroundColor Red }
elseif (-not $rows.Count) { Write-Host '  no credentials found (all-managed-identity environment).' -ForegroundColor Green }
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

$verdict = Get-PimCredentialExpiryVerdict -Worst $worst -FailDays $FailDays -Unread @($unread.ToArray())
if ($unread.Count) {
    Write-Host ""
    Write-Host "  INCOMPLETE -- could not read $($unread.Count) credential source(s); this is NOT a pass:" -ForegroundColor Red
    foreach ($u in $unread) { Write-Host "    - $u" -ForegroundColor Red }
    Write-Host "  Re-run as an identity that can read the container app and the app registrations (directory read)." -ForegroundColor Yellow
}
if ($verdict.status -eq 'critical') {
    Write-Host ""
    Write-Host "  ROTATE IT:" -ForegroundColor Yellow
    Write-Host "    Easy Auth : Set-PimManagerEasyAuth.ps1 -App $ManagerApp -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId -TenantId <tenant> -RotateSecret" -ForegroundColor White
    Write-Host "    an SPN    : az ad app credential reset --id <appId> --append --years 2   (--append, or you revoke the others)" -ForegroundColor White
}
elseif ($verdict.status -eq 'none') { Write-Host '  nothing expires -- this environment holds no time-limited credential (every source was read).' -ForegroundColor Green }
elseif ($verdict.status -eq 'ok') { Write-Host ("  OK -- nearest expiry is {0} day(s) away (warn at {1}, fail at {2})." -f $worst, $WarnDays, $FailDays) -ForegroundColor Green }
exit $verdict.exit
