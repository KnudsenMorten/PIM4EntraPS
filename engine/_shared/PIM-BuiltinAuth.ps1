#Requires -Version 5.1
<#
.SYNOPSIS
    BUILT-IN-AUTH-1 (owner 2026-11-14: Microsoft built-in sign-in is the standard for every PIM Manager) -- the ONE definition
    of that standard: what setup writes (tools/setup/Set-PimManagerEasyAuth.ps1) and what the updater only REPORTS
    (tools/pim-engine/update-job-entry.ps1 converge + the setup step 'builtin-signin').

.DESCRIPTION
    The standard (proven on every install on 2026-11-14 by the operations switch; the same fields its read-only consistency
    check compares):
      * Container Apps built-in authentication ON (authConfigs/current, api 2024-10-02-preview): RedirectToLoginPage to the
        Microsoft provider; registration = the sign-in app registration, its credential = the container-app setting
        'override-use-mi-fic-assertion-client-id' (the web identity's CLIENT id -- a federated credential, NO client secret);
        issuer https://login.microsoftonline.com/<tenant>/v2.0; audiences api://<id> and <id>; on the PROVIDER's login block
        loginParameters 'scope=openid profile email offline_access api://<id>/user_impersonation' (AUTH-MODERN-1: an access
        token for this app, renewed silently) and 'prompt=select_account' (the picker); the token store in a blob container 'pim-auth-tokens' of the
        install's own storage account (shared-key access off), reached as id-pim-web; the session ends after 8 hours (FixedTime).
      * the app registration trusts id-pim-web by a federated credential (issuer <tenant>/v2.0, subject = the web identity's
        PRINCIPAL id, audience api://AzureADTokenExchange); ID tokens on, implicit-grant access tokens off; reply URL
        https://<fqdn>/.auth/login/aad/callback; it EXPOSES api://<id> with the delegated scope user_impersonation (the Azure
        CLI pre-authorised for it, so scripts use az / MSAL).
      * AUTH-MODERN-1: the Manager verifies the ACCESS token (scp user_impersonation, aud = the app, this tenant, expiry); the
        ID token only as a reported fallback for an install not yet on these loginParameters.
      * the Manager container verifies the signed ID token itself: PIM_HOSTED_AUTH_LAYER=easyauth,
        PIM_HOSTED_REQUIRE_SIGNED_TOKEN=true, PIM_HOSTED_EASYAUTH_AUD=<client id>, PIM_HOSTED_AUTH_TENANT=<tenant>,
        PORT=<the ingress port>. One container: the Manager (the sign-in front is opt-in, never put back).
      * id-pim-web holds Storage Blob Data Contributor on THAT container only, and no Key Vault role.
    PURE first (offline-tested in tests/Test-PimBuiltinAuth.ps1), then ONE read-only check through seams
    (Invoke-PimBuiltinAuthCheck: ARM + Graph GET only; never writes, never throws). PS 5.1 + 7, no modules, ASCII only.
#>
Set-StrictMode -Off

function Get-PimBuiltinAuthStandard {
    <# PURE. LITERAL (child-scope safe). The fixed values of the standard. #>
    return @{
        authApi = '2024-10-02-preview'; appApi = '2024-03-01'; msiApi = '2023-01-31'; storageApi = '2023-01-01'; raApi = '2022-04-01'
        secretName = 'override-use-mi-fic-assertion-client-id'
        tokenContainer = 'pim-auth-tokens'
        blobDataContributor = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
        cookieConvention = 'FixedTime'; cookieTime = '08:00:00'
        loginParameters = @('prompt=select_account')   # the account picker; the scope entry is per app (Get-PimBuiltinAuthLoginParameters)
        apiScope = 'user_impersonation'                 # AUTH-MODERN-1: the delegated scope the Manager verifies on the access token
        azureCliAppId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'   # Microsoft Azure CLI (first-party public client), pre-authorised for scripts
        ficAudience = 'api://AzureADTokenExchange'
        ficName = 'builtin-auth-id-pim-web'
        webIdentityName = 'id-pim-web'
        layer = 'easyauth'
        # every built-in Key Vault data / admin role (the web identity must hold none of them, anywhere)
        keyVaultRoles = @('4633458b-17de-408a-b874-0445c86b69e6', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7', '00482a5a-887f-4fb3-b363-3b7fe8e74483',
                          'f25e0fa2-a7c8-4377-a976-54943a77a395', 'e147488a-f6f5-4113-8e2d-b22465e65bf6', '12338af0-0e69-4776-bea7-57ae8d297424',
                          '8b54135c-b56d-4d72-a534-26097cfdc8d8', '14b46e9e-c2b7-41b4-b07b-48a6ebf60603')
    }
}

function Get-PimBuiltinAuthField {
    <# PURE. A property of an object or a dictionary; $null when absent. #>
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    if ($Object -is [string]) { return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Get-PimBuiltinAuthPath {
    <# PURE. The value at a dotted path ('identityProviders.azureActiveDirectory.registration.clientId'); $null when absent. #>
    param([AllowNull()][object]$Object, [Parameter(Mandatory)][string]$Path)
    $cur = $Object
    foreach ($seg in ($Path -split '\.')) { $cur = Get-PimBuiltinAuthField $cur $seg; if ($null -eq $cur) { return $null } }
    return $cur
}

function Get-PimBuiltinAuthIssuer {
    <# PURE. The v2 issuer of the tenant (never the v1 sts.windows.net form: it asks for the retired Azure AD Graph). #>
    param([Parameter(Mandatory)][string]$TenantId)
    return "https://login.microsoftonline.com/$("$TenantId".Trim())/v2.0"
}

function Get-PimBuiltinAuthLoginParameters {
    <#
      PURE. AUTH-MODERN-1 / SIGNIN-TOKEN-LIFETIME-1 (owner 2026-11-15 "use only modern and secure method"): what the sign-in asks
      Microsoft Entra ID for, on the PROVIDER's login block (identityProviders.azureActiveDirectory.login.loginParameters -- the
      top-level login block refuses loginParameters with HTTP 400):
        scope=openid profile email offline_access api://<id>/user_impersonation   an ACCESS token for this app (the Manager verifies
                                                                                 it: scp, aud, tenant, expiry) + offline_access so
                                                                                 the platform can renew it (/.auth/refresh)
        prompt=select_account                                                    the account picker
    #>
    param([Parameter(Mandatory)][string]$ClientId)
    $std = Get-PimBuiltinAuthStandard
    return @("scope=openid profile email offline_access api://$("$ClientId".Trim())/$($std.apiScope)", 'prompt=select_account')
}

function Get-PimBuiltinAuthExcludedPaths {
    <#
      PURE. LITERAL. AUTH-MODERN-1 (group ruling 2026-11-15): the ONLY paths of the Manager the platform lets through
      unauthenticated -- the RFC 9728 protected-resource metadata documents. /mcp is NOT one of them: it stays behind the
      platform (layer 1) and is validated by the Manager (layer 2).
    #>
    return @('/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/*')
}

function Test-PimBuiltinAuthLoginParametersStandard {
    <# PURE. Do these loginParameters request offline_access AND this app's API scope (and the picker)? @{ ok; missing[] } #>
    param([AllowNull()][object[]]$LoginParameters, [Parameter(Mandatory)][string]$ClientId)
    $std = Get-PimBuiltinAuthStandard
    $lp = @(@($LoginParameters) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $miss = New-Object System.Collections.Generic.List[string]
    if ($lp -notcontains 'prompt=select_account') { $miss.Add('account picker missing') }
    $sc = @($lp | Where-Object { $_ -match '^(?i)scope=' } | ForEach-Object { ($_ -replace '^(?i)scope=', '') -split '\s+' } | Where-Object { $_ })
    if ($sc -notcontains 'offline_access') { $miss.Add('sign-in does not request offline_access (no silent renewal)') }
    if ($sc -notcontains "api://$("$ClientId".Trim())/$($std.apiScope)") { $miss.Add("sign-in does not request the API scope api://$("$ClientId".Trim())/$($std.apiScope) (the Manager falls back to the ID token)") }
    return @{ ok = ($miss.Count -eq 0); missing = @($miss.ToArray()) }
}

function Get-PimBuiltinAuthApiScopePlan {
    <#
      PURE. AUTH-MODERN-1: the app registration change that EXPOSES the delegated scope the sign-in asks for (idempotent):
        identifierUris contains api://<id>; api.oauth2PermissionScopes has an enabled 'user_impersonation'; the Azure CLI
        (04b07795-...) is pre-authorised for it, so a script can use `az account get-access-token --resource api://<id>` or
        MSAL without a consent prompt. Everything already there (other URIs, scopes, pre-authorisations) is KEPT.
      -AppReg: the Graph application (appId, identifierUris, api). -NewScopeId: the id a NEW scope gets (passed in: pure).
      @{ steps[]; scopeId; patchScopes (identifierUris + api.oauth2PermissionScopes, $null = nothing); patchPreAuth
         (api.preAuthorizedApplications, $null = nothing) } -- a scope must exist before it is pre-authorised (two PATCHes).
    #>
    param([Parameter(Mandatory)][object]$AppReg, [Parameter(Mandatory)][string]$NewScopeId, [switch]$NoAzureCli)
    $std = Get-PimBuiltinAuthStandard
    $appId = "$(Get-PimBuiltinAuthField $AppReg 'appId')".Trim()
    $uri = "api://$appId"
    $steps = New-Object System.Collections.Generic.List[string]
    $uris = @(@(Get-PimBuiltinAuthField $AppReg 'identifierUris') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $api = Get-PimBuiltinAuthField $AppReg 'api'
    $scopes = @(@(Get-PimBuiltinAuthField $api 'oauth2PermissionScopes') | Where-Object { $_ })
    $sc = @($scopes | Where-Object { "$(Get-PimBuiltinAuthField $_ 'value')" -eq $std.apiScope }) | Select-Object -First 1
    $scopeId = if ($sc) { "$(Get-PimBuiltinAuthField $sc 'id')" } else { "$NewScopeId".Trim() }
    $patchScopes = $null
    if ($uris -notcontains $uri) { $steps.Add('identifier-uri'); $uris = @(@($uris) + $uri) }
    if (-not $sc) {
        $steps.Add('scope')
        $scopes = @(@($scopes) + [pscustomobject][ordered]@{ id = $scopeId; value = $std.apiScope; type = 'User'; isEnabled = $true
            adminConsentDisplayName = 'Sign in to PIM Manager'; adminConsentDescription = 'Lets the signed-in person use the PIM Manager (web page, API and MCP), within that person''s PIM Manager role.'
            userConsentDisplayName = 'Sign in to PIM Manager'; userConsentDescription = 'Lets you use the PIM Manager, within your PIM Manager role.' })
    } elseif ("$(Get-PimBuiltinAuthField $sc 'isEnabled')" -match '^(?i)false$') {
        $steps.Add('scope-enable')
        $scopes = @($scopes | ForEach-Object { if ("$(Get-PimBuiltinAuthField $_ 'value')" -eq $std.apiScope) { $o = $_ | ConvertTo-Json -Depth 5 | ConvertFrom-Json; $o.isEnabled = $true; $o } else { $_ } })
    }
    if ($steps.Count) { $patchScopes = [ordered]@{ identifierUris = @($uris); api = [ordered]@{ oauth2PermissionScopes = @($scopes) } } }
    $patchPre = $null
    if (-not $NoAzureCli) {
        $pre = @(@(Get-PimBuiltinAuthField $api 'preAuthorizedApplications') | Where-Object { $_ })
        $cli = @($pre | Where-Object { "$(Get-PimBuiltinAuthField $_ 'appId')" -eq $std.azureCliAppId }) | Select-Object -First 1
        if (-not $cli) { $steps.Add('preauthorize-azure-cli'); $pre = @(@($pre) + [pscustomobject]@{ appId = $std.azureCliAppId; delegatedPermissionIds = @($scopeId) }) }
        elseif (@(Get-PimBuiltinAuthField $cli 'delegatedPermissionIds') -notcontains $scopeId) {
            $steps.Add('preauthorize-azure-cli')
            $pre = @($pre | ForEach-Object { if ("$(Get-PimBuiltinAuthField $_ 'appId')" -eq $std.azureCliAppId) { [pscustomobject]@{ appId = $std.azureCliAppId; delegatedPermissionIds = @(@(Get-PimBuiltinAuthField $_ 'delegatedPermissionIds') + $scopeId | Select-Object -Unique) } } else { $_ } })
        }
        if ($steps -contains 'preauthorize-azure-cli') { $patchPre = [ordered]@{ api = [ordered]@{ preAuthorizedApplications = @($pre) } } }
    }
    return @{ steps = @($steps.ToArray()); scopeId = $scopeId; patchScopes = $patchScopes; patchPreAuth = $patchPre }
}

function Test-PimBuiltinAuthApiScopeExposed {
    <# PURE. Does the app registration expose api://<id> with an ENABLED user_impersonation scope? #>
    param([AllowNull()][object]$AppReg)
    if ($null -eq $AppReg) { return $false }
    $std = Get-PimBuiltinAuthStandard
    $appId = "$(Get-PimBuiltinAuthField $AppReg 'appId')".Trim()
    $uris = @(@(Get-PimBuiltinAuthField $AppReg 'identifierUris') | ForEach-Object { "$_".Trim() })
    $sc = @(@(Get-PimBuiltinAuthPath $AppReg 'api.oauth2PermissionScopes') | Where-Object { $_ -and "$(Get-PimBuiltinAuthField $_ 'value')" -eq $std.apiScope -and "$(Get-PimBuiltinAuthField $_ 'isEnabled')" -notmatch '^(?i)false$' })
    return [bool]($appId -and $uris -contains "api://$appId" -and $sc.Count)
}

function Get-PimBuiltinAuthCallbackUri {
    <# PURE. The built-in sign-in reply URL of an app FQDN. #>
    param([Parameter(Mandatory)][string]$Fqdn)
    return "https://$("$Fqdn".Trim().TrimEnd('/'))/.auth/login/aad/callback"
}

function Get-PimBuiltinAuthDefaultStorageName {
    <#
      PURE. The install's own PIM storage account name when none exists yet: the SAME name the as-built converge uses
      ('stpimab' + 12 hex of SHA-256(subscription/resourceGroup), engine/_shared/PIM-AsBuilt.ps1 Get-PimAsBuiltStorageAccountName),
      so the token store and the as-built blobs share one account instead of two.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hx = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(("$SubscriptionId/$ResourceGroup").ToLowerInvariant())))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    return ('stpimab' + $hx.Substring(0, 12))
}

function Select-PimBuiltinAuthStorageAccount {
    <#
      PURE. The storage account of the token store, from the resource group's accounts (ARM list): one with shared-key access
      OFF (the as-built account 'stpimab*' first, then by name). None = create -DefaultName (create = $true) -- unless an account
      of that name exists with shared-key access ON: refused (it is not changed here; that is the account owner's decision).
      @{ ok; name; create; reason }
    #>
    param([AllowEmptyCollection()][object[]]$Accounts = @(), [Parameter(Mandatory)][string]$DefaultName)
    $all = @(@($Accounts) | Where-Object { $null -ne $_ })
    $off = @($all | Where-Object { "$(Get-PimBuiltinAuthPath $_ 'properties.allowSharedKeyAccess')" -match '^(?i)false$' } |
             Sort-Object { if ("$($_.name)" -like 'stpimab*') { 0 } else { 1 } }, { "$($_.name)" })
    if ($off.Count) { return @{ ok = $true; name = "$($off[0].name)"; create = $false; reason = "the install's storage account $($off[0].name) (shared-key access off)" } }
    $same = @($all | Where-Object { "$($_.name)" -ieq $DefaultName })
    if ($same.Count) { return @{ ok = $false; name = $DefaultName; create = $false; reason = "the storage account $DefaultName allows shared-key access -- the token store needs an account with shared-key access OFF (switch it off, then run this again)" } }
    return @{ ok = $true; name = $DefaultName; create = $true; reason = "no storage account with shared-key access off in the resource group -- $DefaultName is created (Standard LRS, TLS 1.2, no public blob, shared-key access off)" }
}

function Get-PimBuiltinAuthRoleAssignmentName {
    <# PURE. A role assignment's name -- a GUID from scope + principal + role, so a re-run finds the one it made (MD5, PS 5.1-safe). #>
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$RoleDefinitionId)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { $h = $md5.ComputeHash([Text.Encoding]::UTF8.GetBytes("$Scope|$PrincipalId|$RoleDefinitionId".ToLowerInvariant())) } finally { $md5.Dispose() }
    return ([guid]::new([byte[]]$h)).ToString()
}

function Get-PimBuiltinAuthWebIdentity {
    <#
      PURE. The web identity id-pim-web ATTACHED to the app (ARM object): @{ ok; resourceId; clientId; principalId; reason }.
      Only the standard name counts -- the shared id-pim-<token> registry identity is never the sign-in identity.
    #>
    param([AllowNull()][object]$App, [string]$Name = 'id-pim-web')
    $ua = Get-PimBuiltinAuthPath $App 'identity.userAssignedIdentities'
    $pairs = @()
    if ($ua -is [System.Collections.IDictionary]) { $pairs = @($ua.Keys | ForEach-Object { @{ k = "$_"; v = $ua[$_] } }) }
    elseif ($ua) { $pairs = @($ua.PSObject.Properties | ForEach-Object { @{ k = "$($_.Name)"; v = $_.Value } }) }
    $hit = @($pairs | Where-Object { "$($_.k)" -match ("(?i)/" + [regex]::Escape($Name) + '$') }) | Select-Object -First 1
    if (-not $hit) { return @{ ok = $false; resourceId = ''; clientId = ''; principalId = ''; reason = "the app has no $Name identity attached" } }
    return @{ ok = $true; resourceId = "$($hit.k)"; clientId = "$(Get-PimBuiltinAuthField $hit.v 'clientId')"; principalId = "$(Get-PimBuiltinAuthField $hit.v 'principalId')"; reason = "$Name is attached" }
}

function New-PimBuiltinAuthIdentityBody {
    <#
      PURE. The identity block that ATTACHES -AddId to the app (ARM object as read), every identity already there kept: the
      system-assigned one (type keeps 'SystemAssigned') and every user-assigned one. $null when it is already attached.
    #>
    param([AllowNull()][object]$App, [Parameter(Mandatory)][string]$AddId)
    $ident = Get-PimBuiltinAuthField $App 'identity'
    $type = "$(Get-PimBuiltinAuthField $ident 'type')"
    $ua = Get-PimBuiltinAuthField $ident 'userAssignedIdentities'
    $keys = @()
    if ($ua -is [System.Collections.IDictionary]) { $keys = @($ua.Keys | ForEach-Object { "$_" }) } elseif ($ua) { $keys = @($ua.PSObject.Properties | ForEach-Object { "$($_.Name)" }) }
    if (@($keys | Where-Object { $_ -ieq $AddId }).Count) { return $null }
    $map = [ordered]@{}; foreach ($k in $keys) { $map[$k] = @{} }; $map[$AddId] = @{}
    $newType = if ($type -match '(?i)SystemAssigned') { 'SystemAssigned,UserAssigned' } else { 'UserAssigned' }
    return @{ type = $newType; userAssignedIdentities = $map }
}

function New-PimBuiltinAuthConfig {
    <#
      PURE. The authConfigs/current PROPERTIES of the standard (the body is @{ properties = <this> }, api 2024-10-02-preview).
        -ClientId              the app registration (registration.clientId; audiences api://<id> + <id>)
        -SecretSettingName     the container-app setting holding the federated identity's client id ('' = no login credential:
                               token VALIDATION only, the request portal on a system-assigned identity)
        -BlobContainerUri / -WebIdentityResourceId   the token store (both, or -NoTokenStore)
        -UnauthenticatedAction RedirectToLoginPage (the Manager) | Return401 (the request portal: an API, no sign-in page)
        -ExcludedPaths         paths the platform lets through unauthenticated -- each one a NAMED exception of the caller
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId,
          [AllowEmptyString()][string]$SecretSettingName = 'override-use-mi-fic-assertion-client-id',
          [AllowEmptyString()][string]$BlobContainerUri = '', [AllowEmptyString()][string]$WebIdentityResourceId = '', [switch]$NoTokenStore,
          [ValidateSet('RedirectToLoginPage', 'Return401')][string]$UnauthenticatedAction = 'RedirectToLoginPage',
          [AllowEmptyCollection()][string[]]$ExcludedPaths = @())
    $std = Get-PimBuiltinAuthStandard
    $cid = "$ClientId".Trim()
    if ($cid -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { throw "New-PimBuiltinAuthConfig: '$cid' is not an application (client) id" }
    if (-not $NoTokenStore -and (-not "$BlobContainerUri".Trim() -or -not "$WebIdentityResourceId".Trim())) { throw 'New-PimBuiltinAuthConfig: the token store needs -BlobContainerUri and -WebIdentityResourceId (or -NoTokenStore)' }
    $gv = [ordered]@{ unauthenticatedClientAction = $UnauthenticatedAction; redirectToProvider = 'azureactivedirectory' }
    $ex = @(@($ExcludedPaths) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if ($ex.Count) { $gv['excludedPaths'] = @($ex) }
    $reg = [ordered]@{ clientId = $cid }
    if ("$SecretSettingName".Trim()) { $reg['clientSecretSettingName'] = "$SecretSettingName".Trim() }
    $reg['openIdIssuer'] = Get-PimBuiltinAuthIssuer -TenantId $TenantId
    $aad = [ordered]@{ enabled = $true; registration = $reg; validation = [ordered]@{ allowedAudiences = @("api://$cid", $cid) } }
    # the scope (an access token for this app + offline_access) and the account picker belong to the PROVIDER's login block
    # (the top-level login block refuses loginParameters: HTTP 400) -- AUTH-MODERN-1, Get-PimBuiltinAuthLoginParameters
    if ($UnauthenticatedAction -eq 'RedirectToLoginPage') { $aad['login'] = [ordered]@{ loginParameters = @(Get-PimBuiltinAuthLoginParameters -ClientId $cid) } }
    $p = [ordered]@{ platform = [ordered]@{ enabled = $true }; globalValidation = $gv; identityProviders = [ordered]@{ azureActiveDirectory = $aad } }
    $login = [ordered]@{}
    if (-not $NoTokenStore) { $login['tokenStore'] = [ordered]@{ enabled = $true; azureBlobStorage = [ordered]@{ blobContainerUri = "$BlobContainerUri".Trim(); managedIdentityResourceId = "$WebIdentityResourceId".Trim() } } }
    if ($UnauthenticatedAction -eq 'RedirectToLoginPage') { $login['cookieExpiration'] = [ordered]@{ convention = $std.cookieConvention; timeToExpiration = $std.cookieTime } }
    if ($login.Count) { $p['login'] = $login }
    return $p
}

function Get-PimBuiltinAuthManagerEnv {
    <# PURE. The Manager container's settings of the standard (LAYER 2: the signed ID token verified by the Manager itself). #>
    param([Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][int]$Port)
    return [ordered]@{ PIM_HOSTED_AUTH_LAYER = 'easyauth'; PIM_HOSTED_REQUIRE_SIGNED_TOKEN = 'true'; PIM_HOSTED_EASYAUTH_AUD = "$ClientId".Trim()
                       PIM_HOSTED_AUTH_TENANT = "$TenantId".Trim(); PORT = "$Port" }
}

function Get-PimBuiltinAuthFicBody {
    <# PURE. The federated credential on the app registration that lets -PrincipalId (a managed identity) sign in for it. #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$PrincipalId, [string]$Name = 'builtin-auth-id-pim-web',
          [string]$Description = 'PIM Manager built-in sign-in (no client secret): the web identity')
    $std = Get-PimBuiltinAuthStandard
    return [ordered]@{ name = $Name; issuer = (Get-PimBuiltinAuthIssuer -TenantId $TenantId); subject = "$PrincipalId".Trim(); audiences = @($std.ficAudience); description = $Description }
}

function Test-PimBuiltinAuthFicPresent {
    <# PURE. Does the registration's federated credential list trust -PrincipalId (subject, this tenant's issuer, the exchange audience)? #>
    param([AllowEmptyCollection()][object[]]$Fics = @(), [Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$TenantId)
    $std = Get-PimBuiltinAuthStandard
    return [bool](@(@($Fics) | Where-Object { $_ -and "$($_.subject)" -eq "$PrincipalId".Trim() -and @($_.audiences) -contains $std.ficAudience -and "$($_.issuer)" -like "*$("$TenantId".Trim())*" }).Count)
}

function Get-PimBuiltinAuthSecretCleanupPlan {
    <#
      PURE. The client secrets the move to built-in sign-in leaves without a use: the registration's password credentials whose
      display name starts with 'easyauth' (what the old Easy Auth step minted). Anything else may belong to something that works
      -- listed, never removed. @{ remove = @(keyId, name); keep = @(...) }.
    #>
    param([AllowEmptyCollection()][object[]]$PasswordCredentials = @())
    $rm = @(); $keep = @()
    foreach ($p in @($PasswordCredentials)) {
        if (-not $p) { continue }
        $o = [pscustomobject]@{ keyId = "$($p.keyId)"; name = "$($p.displayName)" }
        if ("$($p.displayName)" -match '^(?i)easyauth') { $rm += $o } else { $keep += $o }
    }
    return @{ remove = @($rm); keep = @($keep) }
}

function Test-PimBuiltinAuthStandard {
    <#
      PURE. Is the Manager app on the standard? Field by field, the same comparison as the operations consistency check.
        -App            the container app (ARM, api 2024-03-01: identity, template, configuration.secrets NAMES, ingress)
        -AuthConfig     authConfigs/current (ARM resource or its properties, api 2024-10-02-preview); $null = none (= OFF)
        -RoleAssignments the web identity's role assignments ($null = not read)
        -AppReg         the app registration (id, web) ($null = not read); -Fics its federated credentials ($null = not read)
      @{ state = ok | missing | n/a | unknown; deviations[]; notRead[]; detail }. The opt-in sign-in front (a 'signin-front'
      container with PIM_HOSTED_AUTH_LAYER=signin-front) = n/a: that install chose the front, and nothing here moves it back.
    #>
    param([AllowNull()][object]$App, [AllowNull()][object]$AuthConfig, [Parameter(Mandatory)][string]$TenantId,
          [AllowNull()][object[]]$RoleAssignments = $null, [AllowNull()][object]$AppReg = $null, [AllowNull()][object[]]$Fics = $null,
          [string]$ManagerContainer = 'ca-pim-manager')
    $std = Get-PimBuiltinAuthStandard
    $dev = New-Object System.Collections.Generic.List[string]
    $unread = New-Object System.Collections.Generic.List[string]
    $mk = { param($st, $d) [ordered]@{ state = $st; deviations = @($dev.ToArray()); notRead = @($unread.ToArray()); detail = $d } }
    if ($null -eq $App) { $unread.Add('the Manager app'); return (& $mk 'unknown' 'not read: the Manager app could not be read') }
    $tid = "$TenantId".Trim()
    $ctr = @(@(Get-PimBuiltinAuthPath $App 'properties.template.containers') | Where-Object { $_ })
    $front = @($ctr | Where-Object { "$($_.name)" -eq 'signin-front' })
    $mgr = @($ctr | Where-Object { "$($_.name)" -eq $ManagerContainer }) | Select-Object -First 1
    if (-not $mgr) { $mgr = @($ctr | Where-Object { "$($_.name)" -ne 'signin-front' }) | Select-Object -First 1 }
    $ev = @{}; foreach ($x in @(Get-PimBuiltinAuthField $mgr 'env')) { if ($x) { $ev["$($x.name)"] = "$($x.value)" } }
    if ($front.Count -and "$($ev['PIM_HOSTED_AUTH_LAYER'])".Trim() -ieq 'signin-front') {
        return (& $mk 'n/a' 'the opt-in sign-in front is in use on this install (its own choice; the built-in standard does not apply)')
    }
    $clientId = "$($ev['PIM_HOSTED_EASYAUTH_AUD'])".Trim()
    $port = "$(Get-PimBuiltinAuthPath $App 'properties.configuration.ingress.targetPort')".Trim()
    $fqdn = "$(Get-PimBuiltinAuthPath $App 'properties.configuration.ingress.fqdn')".Trim()
    if ($ctr.Count -ne 1 -or -not $mgr) { $dev.Add("containers $(@($ctr | ForEach-Object { $_.name }) -join '+') (only the Manager)") }
    if ("$($ev['PIM_HOSTED_AUTH_LAYER'])" -ne 'easyauth') { $dev.Add("PIM_HOSTED_AUTH_LAYER=$($ev['PIM_HOSTED_AUTH_LAYER'])") }
    if ("$($ev['PIM_HOSTED_REQUIRE_SIGNED_TOKEN'])" -notmatch '^(?i)(true|1)$') { $dev.Add("PIM_HOSTED_REQUIRE_SIGNED_TOKEN=$($ev['PIM_HOSTED_REQUIRE_SIGNED_TOKEN'])") }
    if (-not $clientId) { $dev.Add('PIM_HOSTED_EASYAUTH_AUD missing') }
    if ("$($ev['PIM_HOSTED_AUTH_TENANT'])".Trim() -ine $tid) { $dev.Add("PIM_HOSTED_AUTH_TENANT=$($ev['PIM_HOSTED_AUTH_TENANT'])") }
    if ($port -and "$($ev['PORT'])".Trim() -ne $port) { $dev.Add("PORT=$($ev['PORT']) (ingress $port)") }
    foreach ($k in @($ev.Keys | Where-Object { $_ -match '^(PIM_SIGNIN_FRONT_|SIGNIN_)' } | Sort-Object)) { $dev.Add("leftover setting $k") }
    $secNames = @(@(Get-PimBuiltinAuthPath $App 'properties.configuration.secrets') | Where-Object { $_ } | ForEach-Object { "$($_.name)" })
    if ($secNames -notcontains $std.secretName) { $dev.Add("setting $($std.secretName) missing") }
    $wi = Get-PimBuiltinAuthWebIdentity -App $App -Name $std.webIdentityName
    if (-not $wi.ok) { $dev.Add("$($std.webIdentityName) not attached") }
    # the auth config
    $a = $AuthConfig
    if ($a -and (Get-PimBuiltinAuthField $a 'properties')) { $a = Get-PimBuiltinAuthField $a 'properties' }
    if ("$(Get-PimBuiltinAuthPath $a 'platform.enabled')" -notmatch '^(?i)true$') { $dev.Add('built-in authentication OFF') }
    else {
        $aad = Get-PimBuiltinAuthPath $a 'identityProviders.azureActiveDirectory'
        if ("$(Get-PimBuiltinAuthPath $a 'globalValidation.unauthenticatedClientAction')" -ne 'RedirectToLoginPage') { $dev.Add("unauthenticated=$(Get-PimBuiltinAuthPath $a 'globalValidation.unauthenticatedClientAction')") }
        if ($clientId -and "$(Get-PimBuiltinAuthPath $aad 'registration.clientId')" -ne $clientId) { $dev.Add('auth client id <> PIM_HOSTED_EASYAUTH_AUD') }
        if ("$(Get-PimBuiltinAuthPath $aad 'registration.clientSecretSettingName')" -ne $std.secretName) { $dev.Add("credential setting=$(Get-PimBuiltinAuthPath $aad 'registration.clientSecretSettingName')") }
        if ("$(Get-PimBuiltinAuthPath $aad 'registration.openIdIssuer')" -ne (Get-PimBuiltinAuthIssuer -TenantId $tid)) { $dev.Add("issuer=$(Get-PimBuiltinAuthPath $aad 'registration.openIdIssuer')") }
        $aud = @(@(Get-PimBuiltinAuthPath $aad 'validation.allowedAudiences') | ForEach-Object { "$_" } | Sort-Object)
        $audWant = (@("api://$clientId", $clientId) | Sort-Object) -join ','
        if ($clientId -and (($aud -join ',') -ne $audWant)) { $dev.Add("audiences=$($aud -join ',')") }
        # AUTH-MODERN-1: the picker AND an access token for this app (its API scope) + offline_access (silent renewal)
        $lpChk = Test-PimBuiltinAuthLoginParametersStandard -LoginParameters @(Get-PimBuiltinAuthPath $aad 'login.loginParameters') -ClientId $(if ($clientId) { $clientId } else { "$(Get-PimBuiltinAuthPath $aad 'registration.clientId')" })
        foreach ($m in @($lpChk.missing)) { $dev.Add($m) }
        # only the protected-resource metadata may be outside the sign-in (never /mcp, never the page or the API)
        foreach ($xp in @(@(Get-PimBuiltinAuthPath $a 'globalValidation.excludedPaths') | ForEach-Object { "$_".Trim() } | Where-Object { $_ -and (Get-PimBuiltinAuthExcludedPaths) -notcontains $_ })) { $dev.Add("excluded path $xp (only the protected-resource metadata may bypass the sign-in)") }
        if ("$(Get-PimBuiltinAuthPath $a 'login.tokenStore.enabled')" -notmatch '^(?i)true$') { $dev.Add('token store OFF') }
        else {
            if ("$(Get-PimBuiltinAuthPath $a 'login.tokenStore.azureBlobStorage.blobContainerUri')" -notmatch "/$([regex]::Escape($std.tokenContainer))/?$") { $dev.Add('token store container is not pim-auth-tokens') }
            if ("$(Get-PimBuiltinAuthPath $a 'login.tokenStore.azureBlobStorage.managedIdentityResourceId')" -notmatch '(?i)/id-pim-web$') { $dev.Add('token store identity is not id-pim-web') }
        }
        if ("$(Get-PimBuiltinAuthPath $a 'login.cookieExpiration.convention')" -ne $std.cookieConvention -or "$(Get-PimBuiltinAuthPath $a 'login.cookieExpiration.timeToExpiration')" -ne $std.cookieTime) {
            $dev.Add("session=$(Get-PimBuiltinAuthPath $a 'login.cookieExpiration.convention') $(Get-PimBuiltinAuthPath $a 'login.cookieExpiration.timeToExpiration')")
        }
    }
    # the web identity's rights
    if ($null -eq $RoleAssignments) { $unread.Add('the web identity''s role assignments') }
    else {
        $ras = @(@($RoleAssignments) | Where-Object { $_ })
        $rd = { param($r) "$(Get-PimBuiltinAuthPath $r 'properties.roleDefinitionId')".Split('/')[-1].ToLowerInvariant() }
        $sc = { param($r) "$(Get-PimBuiltinAuthPath $r 'properties.scope')" }
        if (@($ras | Where-Object { $std.keyVaultRoles -contains (& $rd $_) }).Count) { $dev.Add('id-pim-web holds a Key Vault role') }
        $blob = @($ras | Where-Object { (& $rd $_) -eq $std.blobDataContributor })
        if (-not @($blob | Where-Object { (& $sc $_) -match "/containers/$([regex]::Escape($std.tokenContainer))$" }).Count) { $dev.Add('no Blob Data Contributor on pim-auth-tokens') }
        if (@($blob | Where-Object { (& $sc $_) -notmatch "/containers/$([regex]::Escape($std.tokenContainer))$" }).Count) { $dev.Add('Blob Data Contributor also on another scope') }
    }
    # the app registration
    if ($null -eq $AppReg) { $unread.Add('the app registration') }
    else {
        if ("$(Get-PimBuiltinAuthPath $AppReg 'web.implicitGrantSettings.enableIdTokenIssuance')" -notmatch '^(?i)true$') { $dev.Add('ID-token issuance OFF') }
        if ("$(Get-PimBuiltinAuthPath $AppReg 'web.implicitGrantSettings.enableAccessTokenIssuance')" -match '^(?i)true$') { $dev.Add('access-token issuance ON') }
        if ($fqdn -and @(Get-PimBuiltinAuthPath $AppReg 'web.redirectUris') -notcontains (Get-PimBuiltinAuthCallbackUri -Fqdn $fqdn)) { $dev.Add('reply URL missing') }
        if (-not (Test-PimBuiltinAuthApiScopeExposed -AppReg $AppReg)) { $dev.Add("API scope $($std.apiScope) not exposed (api://<id>)") }
        if ($null -eq $Fics) { $unread.Add('the federated credentials') }
        elseif ($wi.ok -and -not (Test-PimBuiltinAuthFicPresent -Fics @($Fics) -PrincipalId $wi.principalId -TenantId $tid)) { $dev.Add('no federated credential for id-pim-web') }
    }
    if ($dev.Count) { return (& $mk 'missing' ("not the standard: " + ($dev -join '; '))) }
    if ($unread.Count) { return (& $mk 'unknown' ("the platform settings are the standard; not read: " + ($unread -join ', '))) }
    return (& $mk 'ok' 'Microsoft built-in sign-in, no client secret (federated credential), token store, account picker, 8-hour session, an access token for the API scope (renewed with offline_access); the Manager verifies the access token')
}

function Invoke-PimBuiltinAuthCheck {
    <#
      READ ONLY (never writes, never throws): the standard read through seams and judged by Test-PimBuiltinAuthStandard.
        -Arm   { param($Method, $Path, $Body) }  called with GET only; Path carries its api-version; a 404 may throw or be $null
        -Graph { param($Method, $Path, $Body) }  called with GET only; Path is Graph v1.0-relative
      @{ state; detail; deviations; notRead; lines = @(@{ level = info|warn; text }) }
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$Graph, [Parameter(Mandatory)][string]$SubscriptionId,
          [Parameter(Mandatory)][string]$ResourceGroup, [string]$ManagerApp = 'ca-pim-manager', [AllowEmptyString()][string]$TenantId = '')
    $std = Get-PimBuiltinAuthStandard
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $appPath = "$rg/providers/Microsoft.App/containerApps/$ManagerApp"
    $get = { param($p) try { & $Arm 'GET' $p $null } catch { if ("$($_.Exception.Message)" -match '(?i)\b404\b|NotFound') { $null } else { throw } } }
    $app = $null; try { $app = & $get "$appPath`?api-version=$($std.appApi)" } catch { $app = $null }
    $auth = $null; $authRead = $true
    try { $auth = & $get "$appPath/authConfigs/current?api-version=$($std.authApi)" } catch { $authRead = $false }
    $tid = "$TenantId".Trim()
    if (-not $tid -and $app) { foreach ($c in @(Get-PimBuiltinAuthPath $app 'properties.template.containers')) { foreach ($e in @(Get-PimBuiltinAuthField $c 'env')) { if ($e -and "$($e.name)" -eq 'PIM_HOSTED_AUTH_TENANT' -and "$($e.value)".Trim()) { $tid = "$($e.value)".Trim() } } } }
    $wi = Get-PimBuiltinAuthWebIdentity -App $app -Name $std.webIdentityName
    $ras = $null
    if ($wi.ok -and "$($wi.principalId)".Trim()) {
        $f = [uri]::EscapeDataString("principalId eq '$($wi.principalId)'")
        foreach ($scope in @("/subscriptions/$SubscriptionId", $rg)) {
            try { $r = & $get "$scope/providers/Microsoft.Authorization/roleAssignments?`$filter=$f&api-version=$($std.raApi)"; $ras = @(if ($r -and (Get-PimBuiltinAuthField $r 'value')) { @($r.value) } elseif ($r) { @() } else { @() }); break } catch { $ras = $null }
        }
    }
    $reg = $null; $fics = $null
    $cid = ''; if ($app) { foreach ($c in @(Get-PimBuiltinAuthPath $app 'properties.template.containers')) { foreach ($e in @(Get-PimBuiltinAuthField $c 'env')) { if ($e -and "$($e.name)" -eq 'PIM_HOSTED_EASYAUTH_AUD' -and "$($e.value)".Trim()) { $cid = "$($e.value)".Trim() } } } }
    if ($Graph -and $cid) {
        try {
            $r = & $Graph 'GET' "/applications?`$filter=$([uri]::EscapeDataString("appId eq '$cid'"))&`$select=id,appId,web,identifierUris,api" $null
            $reg = @(@(if ($r -and (Get-PimBuiltinAuthField $r 'value')) { @($r.value) } else { @($r) }) | Where-Object { $_ -and "$($_.appId)" -eq $cid }) | Select-Object -First 1
            if ($reg) { $fr = & $Graph 'GET' "/applications/$($reg.id)/federatedIdentityCredentials" $null; $fics = @(if ($fr -and (Get-PimBuiltinAuthField $fr 'value')) { @($fr.value) } else { @() }) }
        } catch { $reg = $null; $fics = $null }
    }
    if (-not $authRead) { $v = [ordered]@{ state = 'unknown'; deviations = @(); notRead = @('the authentication settings'); detail = 'not read: the authentication settings could not be read' } }
    elseif (-not $tid) { $v = [ordered]@{ state = $(if ($app) { 'missing' } else { 'unknown' }); deviations = @(); notRead = @(); detail = $(if ($app) { 'not the standard: PIM_HOSTED_AUTH_TENANT missing' } else { 'not read: the Manager app could not be read' }) } }
    else { $v = Test-PimBuiltinAuthStandard -App $app -AuthConfig $auth -TenantId $tid -RoleAssignments $ras -AppReg $reg -Fics $fics }
    $lines = New-Object System.Collections.Generic.List[object]
    switch ("$($v.state)") {
        'ok'      { $lines.Add(@{ level = 'info'; text = "built-in sign-in: the standard -- $($v.detail)" }) }
        'n/a'     { $lines.Add(@{ level = 'info'; text = "built-in sign-in: $($v.detail)" }) }
        'missing' { $lines.Add(@{ level = 'warn'; text = "built-in sign-in: $($v.detail) -- REPORTED only (the updater never writes sign-in settings or roles); fixed by setup: Set-PimManagerEasyAuth.ps1 through the Support app" }) }
        default   { $lines.Add(@{ level = 'warn'; text = "built-in sign-in: $($v.detail)" }) }
    }
    return @{ state = "$($v.state)"; detail = "$($v.detail)"; deviations = @($v.deviations); notRead = @($v.notRead); lines = @($lines.ToArray()) }
}
