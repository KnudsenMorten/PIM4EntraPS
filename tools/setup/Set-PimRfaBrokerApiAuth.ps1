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

    Graph + ARM REST through PIM-Rest's one token client (no az, 100.41 / framework 12.17): the calling run's session, else
    the Invardia Support app's session, else the person signed in in the browser -- an identity that may create app
    registrations; the script refuses to write to any other tenant than -TenantId.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$TenantId,
    [string]$BrokerApp = 'ca-pim-rfa',
    [string]$ApiAppDisplayName = 'PIM access request API',
    [string]$AzureConfigDir,   # IGNORED since 100.41 (no az): kept so existing command lines still bind
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
if ("$AzureConfigDir".Trim()) { Write-Host '  -AzureConfigDir is ignored: this script no longer uses the az CLI (100.41) -- it signs in through PIM-Rest.' -ForegroundColor DarkYellow }

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

function Invoke-PimRfaRetry([scriptblock]$Call, [int]$Tries = 8) {
    # a just-created application is not readable at once (directory replication: "Resource ... does not exist") -- retry
    for ($i = 1; $i -le $Tries; $i++) {
        try { return (& $Call) } catch { if ($i -eq $Tries) { throw }; Start-Sleep -Seconds (5 * $i) }
    }
}

function ConvertTo-PimRfaAuthView($AuthResource) {
    # The authConfigs/current resource -> the shape `az containerapp auth show` printed (its .properties at the top), which
    # is what Get-PimRfaApiAuthPlan reads.
    if ($AuthResource -and $AuthResource.PSObject.Properties['properties'] -and $AuthResource.properties) { return $AuthResource.properties }
    return $null
}

if ($MyInvocation.InvocationName -eq '.') { return }   # dot-sourced by a test: the pure plan only

# 100.41 (framework 12.17 NO-AZ): Graph + ARM REST through PIM-Rest's ONE token client (engine/_shared/PIM-ArmSetup.ps1). A
# calling run's REST session is used as it is; standalone, the Invardia Support app's session or the person signed in.
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId) }

# 🔒 the tenant Graph would write to -- the REST session's tenant, which must be -TenantId
if ("$($global:PIM_TenantId)".Trim().ToLowerInvariant() -ne "$TenantId".Trim().ToLowerInvariant()) { throw "the REST session is signed in to tenant '$($global:PIM_TenantId)', not '$TenantId' -- refusing to write app registrations there." }

$app = @(Find-PimGraphApplications -DisplayName $ApiAppDisplayName) | Where-Object { $_ } | Select-Object -First 1
$sp = if ($app) { Get-PimGraphServicePrincipal -Id "$($app.appId)" } else { $null }
$auth = ConvertTo-PimRfaAuthView (Get-PimArmAcaAuthConfig -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $BrokerApp)
$plan = Get-PimRfaApiAuthPlan -App $app -Sp $sp -Auth $auth -TenantId $TenantId
Write-Host "==> broker '$BrokerApp' / API application '$ApiAppDisplayName': $($plan.reason)" -ForegroundColor Cyan
if (-not $plan.steps.Count) { return $plan }
if (-not $Apply) { Write-Host '    PLAN ONLY -- re-run with -Apply.' -ForegroundColor Yellow; return $plan }

if ($plan.steps -contains 'create-app') { $app = New-PimGraphApplication -Body @{ displayName = $ApiAppDisplayName; signInAudience = 'AzureADMyOrg' }; Write-Host "    created application $($app.appId)" }
$uri = "api://$($app.appId)"
if ($plan.steps -contains 'set-uri' -or $plan.steps -contains 'create-app') {
    $appIdForUri = "$($app.appId)"
    [void](Invoke-PimRfaRetry { Update-PimGraphApplication -Id $appIdForUri -Properties @{ identifierUris = @($uri) } }); Write-Host "    identifier URI $uri"
}
if (-not $sp) { $newAppId = "$($app.appId)"; $sp = Invoke-PimRfaRetry { New-PimGraphServicePrincipal -AppId $newAppId }; Write-Host "    service principal $($sp.id)" }
# az containerapp auth microsoft update --client-id --issuer --allowed-audiences "<uri>,<appId>" + az containerapp auth update
# --unauthenticated-client-action AllowAnonymous --enabled true: ONE read-modify-write of authConfigs/current (token VALIDATION
# only -- no client secret).
$apiAppId = "$($app.appId)"; $issuer = $plan.issuer
[void](Invoke-PimRfaRetry { Set-PimArmAcaAuthConfig -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $BrokerApp -Mutate {
    param($p)
    $ip = if ($p.PSObject.Properties['identityProviders'] -and $p.identityProviders) { $p.identityProviders } else { [pscustomobject]@{} }
    $aad = if ($ip.PSObject.Properties['azureActiveDirectory'] -and $ip.azureActiveDirectory) { $ip.azureActiveDirectory } else { [pscustomobject]@{} }
    $reg = if ($aad.PSObject.Properties['registration'] -and $aad.registration) { $aad.registration } else { [pscustomobject]@{} }
    $reg | Add-Member -NotePropertyName clientId -NotePropertyValue $apiAppId -Force
    $reg | Add-Member -NotePropertyName openIdIssuer -NotePropertyValue $issuer -Force
    $val = if ($aad.PSObject.Properties['validation'] -and $aad.validation) { $aad.validation } else { [pscustomobject]@{} }
    $val | Add-Member -NotePropertyName allowedAudiences -NotePropertyValue @($uri, $apiAppId) -Force
    $aad | Add-Member -NotePropertyName enabled -NotePropertyValue $true -Force
    $aad | Add-Member -NotePropertyName registration -NotePropertyValue $reg -Force
    $aad | Add-Member -NotePropertyName validation -NotePropertyValue $val -Force
    $ip | Add-Member -NotePropertyName azureActiveDirectory -NotePropertyValue $aad -Force
    $p | Add-Member -NotePropertyName identityProviders -NotePropertyValue $ip -Force
    $pl = if ($p.PSObject.Properties['platform'] -and $p.platform) { $p.platform } else { [pscustomobject]@{} }
    $pl | Add-Member -NotePropertyName enabled -NotePropertyValue $true -Force
    $p | Add-Member -NotePropertyName platform -NotePropertyValue $pl -Force
    $gv = if ($p.PSObject.Properties['globalValidation'] -and $p.globalValidation) { $p.globalValidation } else { [pscustomobject]@{} }
    $gv | Add-Member -NotePropertyName unauthenticatedClientAction -NotePropertyValue 'AllowAnonymous' -Force
    $p | Add-Member -NotePropertyName globalValidation -NotePropertyValue $gv -Force
} })

# read back
$app2 = Get-PimGraphApplication -Id "$($app.appId)"
$auth2 = ConvertTo-PimRfaAuthView (Get-PimArmAcaAuthConfig -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $BrokerApp)
$after = Get-PimRfaApiAuthPlan -App $app2 -Sp $sp -Auth $auth2 -TenantId $TenantId
if ($after.steps.Count) { throw "read-back: still $($after.reason)" }
Write-Host "==> done. Callers request a token with scope '$uri/.default' and their client id is allow-listed in the PIM Manager." -ForegroundColor Green
return $after
