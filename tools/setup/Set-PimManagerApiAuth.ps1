#Requires -Version 5.1
<#
.SYNOPSIS
    Prepares the PIM Manager so a script or a service can sign in to its API with its own application identity.
    PLANS by default; changes nothing without -Apply.

.DESCRIPTION
    By default no application can use the PIM Manager API. This script prepares the Manager's own application
    registration so that it can, and prints how a script gets its sign-in. On the Manager's existing application (found
    from the container app -- never created here) it:

      1. adds the identifier URI  api://<app id>                          (existing URIs are kept)
      2. adds the application role 'PimManager.Api'                       (existing roles are kept)
      3. lets the Manager's sign-in accept a token for that API           (the people's sign-in is unchanged)
      4. sets the Manager's PIM_API_APP_AUDIENCE                          (a new revision rolls)
      5. with -ClientAppId: gives that one application the role in Entra ID (an Entra admin consent for that app)

    It does NOT let any application in by itself. After this, a SuperAdmin lists the application in PIM Manager
    (Settings > API applications) with the role it gets there -- Reader or Admin -- and a second SuperAdmin approves that
    change. Until then every call from it is refused.

    How a script signs in (REST only -- no PowerShell module, no Azure CLI): the script's own application requests a
    token from Microsoft Entra ID with the client-credentials grant and a certificate, for the scope
    api://<app id>/.default, and sends it as 'Authorization: Bearer <token>' to https://<manager>/api/app/<route>
    (for example GET https://<manager>/api/app/drift). The printed example shows the exact calls.

    Graph + ARM REST through PIM-Rest's one token client: the calling run's session, else the Invardia Support app's
    session, else the person signed in in the browser. The script refuses to write to any other tenant than -TenantId.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$TenantId,
    [string]$ManagerApp = 'ca-pim-manager',
    # optional: the calling application's client id -- it gets the application role in Entra ID (step 5)
    [string]$ClientAppId = '',
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
$script:PimApiRoleValue = 'PimManager.Api'

function Get-PimManagerApiAuthPlan {
    <#
      PURE. From the Manager's application (Graph: appId, identifierUris, appRoles), its sign-in (Easy Auth config or the
      sign-in front's env) and the Manager container's env -> @{ steps; patch; audiences; envValue; frontBearerPaths; roleId;
      ok; reason }. -NewRoleId is the id a NEW role gets (passed in so the plan stays pure). Everything MERGES.
      -FrontEnv: the sign-in front container's env (@{ name = value }) or $null when there is no front.
    #>
    param([Parameter(Mandatory)][object]$App, [AllowNull()][object]$Auth, [Parameter(Mandatory)][string]$NewRoleId,
          [object[]]$EnvVars = @(), [AllowNull()][hashtable]$FrontEnv = $null)
    $appId = "$($App.appId)"; $uri = "api://$appId"
    $steps = New-Object System.Collections.Generic.List[string]
    $uris = @(@($App.identifierUris) | Where-Object { "$_".Trim() })
    if ($uris -notcontains $uri) { $steps.Add('identifier-uri') | Out-Null; $uris = @($uris) + $uri }
    $roles = @(@($App.appRoles) | Where-Object { $_ })
    $r = @($roles | Where-Object { "$($_.value)" -eq $script:PimApiRoleValue })[0]
    $roleId = if ($r) { "$($r.id)" } else { $NewRoleId }
    if (-not $r) {
        $steps.Add('app-role') | Out-Null
        $roles = @($roles) + [pscustomobject][ordered]@{ id = $NewRoleId; value = $script:PimApiRoleValue; isEnabled = $true; allowedMemberTypes = @('Application')
            displayName = 'Use the PIM Manager API as an application'; description = 'Lets an application call the PIM Manager API. What it may do is decided by the role it is given in PIM Manager.' }
    } elseif (-not [bool]$r.isEnabled -or @($r.allowedMemberTypes) -notcontains 'Application') {
        $steps.Add('app-role') | Out-Null
        $roles = @($roles | ForEach-Object { if ("$($_.value)" -eq $script:PimApiRoleValue) { $_.isEnabled = $true; $_.allowedMemberTypes = @(@($_.allowedMemberTypes) + 'Application' | Select-Object -Unique) }; $_ })
    }
    $aad = if ($Auth -and $Auth.PSObject.Properties['identityProviders'] -and $Auth.identityProviders) { $Auth.identityProviders.azureActiveDirectory } else { $null }
    $eaOn = [bool]($Auth -and $Auth.PSObject.Properties['platform'] -and $Auth.platform -and $Auth.platform.enabled)
    $have = @(if ($aad -and $aad.validation -and $aad.validation.allowedAudiences) { @($aad.validation.allowedAudiences) })
    $aud = @(@($have) + @($uri, $appId) | Where-Object { "$_".Trim() } | Select-Object -Unique)
    if ($eaOn -and @($uri, $appId | Where-Object { $have -notcontains $_ }).Count) { $steps.Add('audiences') | Out-Null }
    $bp = ''
    if ($null -ne $FrontEnv) {
        $cur = @("$($FrontEnv['SIGNIN_BEARER_PATHS'])" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if (-not $cur.Count) { $cur = @('/mcp', '/.well-known') }
        $bp = (@($cur) + '/api/app' | Select-Object -Unique) -join ','
        if ($cur -notcontains '/api/app') { $steps.Add('front-bearer-path') | Out-Null }
    }
    $envValue = "$uri,$appId"
    $envHave = "$((@($EnvVars) | Where-Object { "$($_.name)" -eq 'PIM_API_APP_AUDIENCE' } | Select-Object -First 1).value)"
    if ($envHave -ne $envValue) { $steps.Add('audience-env') | Out-Null }
    $boundId = if ($aad -and $aad.registration) { "$($aad.registration.clientId)" } else { '' }
    $frontId = if ($null -ne $FrontEnv) { "$($FrontEnv['SIGNIN_CLIENT_ID'])".Trim() } else { '' }
    $ok = $true; $why = ''
    if ($eaOn -and $boundId -and $boundId -ne $appId) { $ok = $false; $why = "the Manager's sign-in is bound to $boundId, not $appId -- refusing" }
    elseif ($frontId -and $frontId -ne $appId) { $ok = $false; $why = "the sign-in front is bound to $frontId, not $appId -- refusing" }
    elseif ($steps.Count) { $why = "to do: $($steps -join ', ')" } else { $why = 'nothing to do -- the Manager is ready for application sign-in' }
    return [pscustomobject]@{ steps = @($steps); ok = $ok; reason = $why; roleId = $roleId; audiences = $aud; envValue = $envValue; frontBearerPaths = $bp
        patch = [ordered]@{ identifierUris = @($uris); appRoles = @($roles) } }
}

function Get-PimManagerApiTokenExample {
    # PURE. The text a person copies into their script: REST only (Invoke-RestMethod + .NET), a certificate, no module.
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ApiAppId, [string]$ManagerHost = '<manager host>')
    $lines = @(
        '# 1) the token: client credentials with a certificate (client assertion), REST only',
        ('$tenant = ''' + $TenantId + '''; $clientId = ''<your application (client) id>'''),
        '$cert = Get-Item Cert:\CurrentUser\My\<thumbprint>    # the certificate registered on your application',
        '$b64u = { param([byte[]]$b) [Convert]::ToBase64String($b).TrimEnd(''='').Replace(''+'', ''-'').Replace(''/'', ''_'') }',
        '$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()',
        '$hdr = @{ alg = ''RS256''; typ = ''JWT''; x5t = (& $b64u $cert.GetCertHash()) } | ConvertTo-Json -Compress',
        '$pl = @{ aud = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token"; iss = $clientId; sub = $clientId; jti = [guid]::NewGuid().ToString(); nbf = $now; exp = $now + 300 } | ConvertTo-Json -Compress',
        '$in = (& $b64u ([Text.Encoding]::UTF8.GetBytes($hdr))) + ''.'' + (& $b64u ([Text.Encoding]::UTF8.GetBytes($pl)))',
        '$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)',
        '$sig = $rsa.SignData([Text.Encoding]::ASCII.GetBytes($in), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)',
        '$tok = (Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Body @{',
        ('    grant_type = ''client_credentials''; client_id = $clientId; scope = ''api://' + $ApiAppId + '/.default'''),
        '    client_assertion_type = ''urn:ietf:params:oauth:client-assertion-type:jwt-bearer''; client_assertion = $in + ''.'' + (& $b64u $sig) }).access_token',
        '# 2) the call: the same routes as the page, under /api/app/',
        ('Invoke-RestMethod -Uri ''https://' + $ManagerHost + '/api/app/drift'' -Headers @{ Authorization = "Bearer $tok" }')
    )
    return ($lines -join [Environment]::NewLine)
}

function Get-PimManagerApiFrontEnv($CaApp) {
    # the sign-in front container's env as @{ name = value }, or $null when this Manager has no front
    $f = @(@($CaApp.properties.template.containers) | Where-Object { $_ -and "$($_.name)" -eq 'signin-front' })[0]
    if (-not $f) { return $null }
    $h = @{}; foreach ($e in @($f.env)) { if ($e -and "$($e.name)") { $h["$($e.name)"] = "$($e.value)" } }
    return $h
}
function Get-PimManagerApiManagerContainer($CaApp) {
    $cs = @(@($CaApp.properties.template.containers) | Where-Object { $_ })
    $c = @($cs | Where-Object { "$($_.name)" -eq $ManagerApp })[0]
    if (-not $c) { $c = @($cs | Where-Object { "$($_.name)" -ne 'signin-front' })[0] }
    return $c
}

if ($MyInvocation.InvocationName -eq '.') { return }   # dot-sourced by a test: the pure plan only

$solRootApi = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRootApi 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRootApi 'engine\_shared\PIM-ArmSetup.ps1') }
if ("$ClientAppId".Trim() -and "$ClientAppId".Trim() -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { throw "-ClientAppId '$ClientAppId' is not an application (client) id" }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId) }
if ("$($global:PIM_TenantId)".Trim() -and "$($global:PIM_TenantId)".Trim().ToLowerInvariant() -ne "$TenantId".Trim().ToLowerInvariant()) {
    throw "the REST session in this shell is for tenant '$($global:PIM_TenantId)', not '$TenantId' -- refusing."
}

$authRes = Get-PimArmAcaAuthConfig -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp
$auth = if ($authRes -and $authRes.properties) { $authRes.properties } else { $null }
$ca = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp
if (-not $ca) { throw "container app $ManagerApp not found in $ResourceGroup" }
$front = Get-PimManagerApiFrontEnv $ca
$appId = "$($auth.identityProviders.azureActiveDirectory.registration.clientId)".Trim()
if (-not $appId -and $front) { $appId = "$($front['SIGNIN_CLIENT_ID'])".Trim() }
if (-not $appId) { throw "$ManagerApp has no sign-in application -- set up the Manager's sign-in first" }
$app = Get-PimGraphApplication -Id $appId
if (-not $app) { throw "the Manager's application $appId was not found in tenant $TenantId" }
$mc = Get-PimManagerApiManagerContainer $ca
$plan = Get-PimManagerApiAuthPlan -App $app -Auth $auth -NewRoleId ([guid]::NewGuid().ToString()) -EnvVars @($mc.env) -FrontEnv $front
Write-Host "==> $ManagerApp / application $appId : $($plan.reason)" -ForegroundColor Cyan
if (-not $plan.ok) { throw $plan.reason }
$needGrant = [bool]"$ClientAppId".Trim()
if (-not $Apply) {
    if ($plan.steps.Count -or $needGrant) { Write-Host ('    PLAN ONLY -- re-run with -Apply.' + $(if ($needGrant) { " (-ClientAppId: the role '$($script:PimApiRoleValue)' would be given to $ClientAppId)" } else { '' })) -ForegroundColor Yellow }
    Write-Host ''; Write-Host (Get-PimManagerApiTokenExample -TenantId $TenantId -ApiAppId $appId) -ForegroundColor DarkGray
    return $plan
}

if (@($plan.steps | Where-Object { $_ -in @('identifier-uri', 'app-role') }).Count) {
    [void](Invoke-PimSetupGraph -Method PATCH -Path "/applications/$($app.id)" -Body ([ordered]@{ identifierUris = @($plan.patch.identifierUris); appRoles = @($plan.patch.appRoles) }))
}
if ($plan.steps -contains 'audiences') {
    [void](Set-PimArmAcaAuthConfig -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -Mutate {
        param($p)
        $ip = $p.identityProviders.azureActiveDirectory
        if ($null -eq $ip.validation) { $ip | Add-Member -NotePropertyName validation -NotePropertyValue ([pscustomobject]@{}) -Force }
        $ip.validation | Add-Member -NotePropertyName allowedAudiences -NotePropertyValue @($plan.audiences) -Force
    })
}
if ($plan.steps -contains 'front-bearer-path') {
    [void](Set-PimArmAcaAppEnvVars -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -Env @{ SIGNIN_BEARER_PATHS = "$($plan.frontBearerPaths)" } -ContainerName 'signin-front')
}
if ($plan.steps -contains 'audience-env') {
    [void](Set-PimArmAcaAppEnvVars -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -Env @{ PIM_API_APP_AUDIENCE = "$($plan.envValue)" } -ContainerName "$($mc.name)")
}
if ($needGrant) {
    # the Entra side of the consent: the client application's service principal gets the role on the Manager's API
    $res = Get-PimGraphServicePrincipal -Id $appId
    if (-not $res) { $res = Invoke-PimSetupGraph -Method POST -Path '/servicePrincipals' -Body @{ appId = $appId } }
    $cli = Get-PimGraphServicePrincipal -Id "$ClientAppId".Trim()
    if (-not $cli) { throw "the application $ClientAppId has no service principal in tenant $TenantId" }
    $have = @(Invoke-PimSetupGraph -Path "/servicePrincipals/$($cli.id)/appRoleAssignments" -All | Where-Object { "$($_.resourceId)" -eq "$($res.id)" -and "$($_.appRoleId)" -eq "$($plan.roleId)" })
    if (-not $have.Count) {
        [void](Invoke-PimSetupGraph -Method POST -Path "/servicePrincipals/$($res.id)/appRoleAssignedTo" -Body @{ principalId = "$($cli.id)"; resourceId = "$($res.id)"; appRoleId = "$($plan.roleId)" })
        Write-Host "    the role '$($script:PimApiRoleValue)' is given to $ClientAppId in Entra ID" -ForegroundColor Green
    }
}
$app2 = Get-PimGraphApplication -Id $appId
$a2 = Get-PimArmAcaAuthConfig -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp
$ca2 = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp
$after = Get-PimManagerApiAuthPlan -App $app2 -Auth $(if ($a2) { $a2.properties } else { $null }) -NewRoleId ([guid]::NewGuid().ToString()) -EnvVars @((Get-PimManagerApiManagerContainer $ca2).env) -FrontEnv (Get-PimManagerApiFrontEnv $ca2)
if ($after.steps.Count) { throw "read-back: still $($after.reason)" }
Write-Host "==> done. Next: a SuperAdmin lists the application in PIM Manager (Settings > API applications) and a second SuperAdmin approves it." -ForegroundColor Green
Write-Host ''; Write-Host (Get-PimManagerApiTokenExample -TenantId $TenantId -ApiAppId $appId) -ForegroundColor DarkGray
return $after
