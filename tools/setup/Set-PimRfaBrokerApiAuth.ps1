#Requires -Version 5.1
<#
.SYNOPSIS
    REQ 90 -- let the access request broker accept Microsoft Entra APPLICATION tokens on /api/v1 (the recommended way
    for ServiceNow, Logic Apps and other systems to sign in). PLANS by default; changes nothing without -Apply.

.DESCRIPTION
    The broker deploy switches Easy Auth on (anonymous allowed: the PIN portal and API keys need no Entra sign-in), but
    an Entra token is only accepted once the broker knows WHICH audience to accept. This script:

      1. finds or creates the API application ("PIM access request API") in the tenant, with the identifier URI
         api://<its app id>, and its service principal (so callers can request a token for it);
      2. registers it as the Entra provider of the broker's Easy Auth with that audience -- token VALIDATION only: no
         client secret, no sign-in page; anonymous calls still reach the broker, which answers 401 to an /api/v1 call
         without a valid token or API key;
      3. reads both back.

    Callers then request a token with scope  api://<api app id>/.default  (client credentials, certificate), and their
    OWN application id is allow-listed in the PIM Manager (Settings > Access requests > API applications). Allow-listing
    stays in PIM, where it is audited -- Easy Auth only proves the token is genuine and meant for this API.

    Run in an az profile signed in to the tenant (certificate identity that may create app registrations); the script
    refuses to write to any other tenant than -TenantId.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$TenantId,
    [string]$BrokerApp = 'ca-pim-rfa',
    [string]$ApiAppDisplayName = 'PIM access request API',
    [string]$AzureConfigDir,
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
if ("$AzureConfigDir".Trim()) { $env:AZURE_CONFIG_DIR = $AzureConfigDir }

function Get-PimRfaApiAuthPlan {
    <#
      PURE. What to do, from what exists. -App = the existing API application (or $null), -Auth = the broker's current
      Easy Auth (containerapp auth show). Returns @{ steps = @('create-app'|'set-uri'|'create-sp'|'register-provider');
      audience; reason }.
    #>
    param([AllowNull()][object]$App, [AllowNull()][object]$Sp, [AllowNull()][object]$Auth, [Parameter(Mandatory)][string]$TenantId)
    $steps = New-Object System.Collections.Generic.List[string]
    $appId = if ($App) { "$($App.appId)" } else { '' }
    if (-not $appId) { $steps.Add('create-app') | Out-Null }
    $uri = if ($appId) { "api://$appId" } else { 'api://<new app id>' }
    if (-not $appId -or @($App.identifierUris) -notcontains $uri) { $steps.Add('set-uri') | Out-Null }
    if (-not $Sp) { $steps.Add('create-sp') | Out-Null }
    $aad = if ($Auth -and $Auth.PSObject.Properties['identityProviders'] -and $Auth.identityProviders) { $Auth.identityProviders.azureActiveDirectory } else { $null }
    $boundId = if ($aad -and $aad.registration) { "$($aad.registration.clientId)" } else { '' }
    $aud = if ($aad -and $aad.validation -and $aad.validation.allowedAudiences) { @($aad.validation.allowedAudiences) } else { @() }
    $issuer = if ($aad -and $aad.registration) { "$($aad.registration.openIdIssuer)" } else { '' }
    $wantIssuer = "https://login.microsoftonline.com/$TenantId/v2.0"
    if (-not $appId -or $boundId -ne $appId -or $aud -notcontains $uri -or $issuer -ne $wantIssuer) { $steps.Add('register-provider') | Out-Null }
    $unauth = if ($Auth -and $Auth.PSObject.Properties['globalValidation'] -and $Auth.globalValidation) { "$($Auth.globalValidation.unauthenticatedClientAction)" } else { '' }
    $why = if ($steps.Count) { "to do: $($steps -join ', ')" } else { 'nothing to do -- the broker accepts Entra tokens for this API' }
    if ($unauth -and $unauth -ne 'AllowAnonymous') { $why += " (NOTE: unauthenticated callers are '$unauth' -- the PIN portal and API keys need AllowAnonymous)" }
    return [pscustomobject]@{ steps = @($steps); audience = $uri; issuer = $wantIssuer; reason = $why }
}

function Invoke-AzJson([string[]]$A) {
    $ErrorActionPreference = 'Continue'
    $o = & az @A -o json --only-show-errors 2>$null
    $code = $LASTEXITCODE; $ErrorActionPreference = 'Stop'
    if ($code -ne 0) { throw "az $($A[0..2] -join ' ') failed (exit $code)" }
    $t = (@($o) -join "`n").Trim(); if (-not $t) { return $null }
    return ($t | ConvertFrom-Json)
}

function Invoke-AzJsonRetry([string[]]$A, [int]$Tries = 8) {
    # a just-created application is not readable at once (directory replication: "Resource ... does not exist") -- retry
    for ($i = 1; $i -le $Tries; $i++) {
        try { return (Invoke-AzJson $A) } catch { if ($i -eq $Tries) { throw }; Start-Sleep -Seconds (5 * $i) }
    }
}

if ($MyInvocation.InvocationName -eq '.') { return }   # dot-sourced by a test: the pure plan only

# 🔒 the tenant az would write to -- Graph follows the profile's DEFAULT tenant, not --subscription
$acct = Invoke-AzJson @('account', 'show')
if ("$($acct.tenantId)" -ne $TenantId) { throw "the az profile is signed in to tenant '$($acct.tenantId)', not '$TenantId' -- refusing to write app registrations there. Use -AzureConfigDir with a profile for $TenantId." }

$app = @(Invoke-AzJson @('ad', 'app', 'list', '--display-name', $ApiAppDisplayName)) | Where-Object { $_ } | Select-Object -First 1
$sp = if ($app) { Invoke-AzJson @('ad', 'sp', 'list', '--filter', "appId eq '$($app.appId)'") | Select-Object -First 1 } else { $null }
$auth = Invoke-AzJson @('containerapp', 'auth', 'show', '--subscription', $SubscriptionId, '-g', $ResourceGroup, '-n', $BrokerApp)
$plan = Get-PimRfaApiAuthPlan -App $app -Sp $sp -Auth $auth -TenantId $TenantId
Write-Host "==> broker '$BrokerApp' / API application '$ApiAppDisplayName': $($plan.reason)" -ForegroundColor Cyan
if (-not $plan.steps.Count) { return $plan }
if (-not $Apply) { Write-Host '    PLAN ONLY -- re-run with -Apply.' -ForegroundColor Yellow; return $plan }

if ($plan.steps -contains 'create-app') { $app = Invoke-AzJson @('ad', 'app', 'create', '--display-name', $ApiAppDisplayName, '--sign-in-audience', 'AzureADMyOrg'); Write-Host "    created application $($app.appId)" }
$uri = "api://$($app.appId)"
if ($plan.steps -contains 'set-uri' -or $plan.steps -contains 'create-app') { [void](Invoke-AzJsonRetry @('ad', 'app', 'update', '--id', "$($app.appId)", '--identifier-uris', $uri)); Write-Host "    identifier URI $uri" }
if (-not $sp) { $sp = Invoke-AzJsonRetry @('ad', 'sp', 'create', '--id', "$($app.appId)"); Write-Host "    service principal $($sp.id)" }
[void](Invoke-AzJsonRetry @('containerapp', 'auth', 'microsoft', 'update', '--subscription', $SubscriptionId, '-g', $ResourceGroup, '-n', $BrokerApp,
    '--client-id', "$($app.appId)", '--issuer', $plan.issuer, '--allowed-audiences', "$uri,$($app.appId)", '--yes'))   # ONE comma-separated value (two arguments = 'unrecognized arguments')
[void](Invoke-AzJson @('containerapp', 'auth', 'update', '--subscription', $SubscriptionId, '-g', $ResourceGroup, '-n', $BrokerApp, '--unauthenticated-client-action', 'AllowAnonymous', '--enabled', 'true'))

# read back
$app2 = Invoke-AzJson @('ad', 'app', 'show', '--id', "$($app.appId)")
$auth2 = Invoke-AzJson @('containerapp', 'auth', 'show', '--subscription', $SubscriptionId, '-g', $ResourceGroup, '-n', $BrokerApp)
$after = Get-PimRfaApiAuthPlan -App $app2 -Sp $sp -Auth $auth2 -TenantId $TenantId
if ($after.steps.Count) { throw "read-back: still $($after.reason)" }
Write-Host "==> done. Callers request a token with scope '$uri/.default' and their client id is allow-listed in the PIM Manager." -ForegroundColor Green
return $after
