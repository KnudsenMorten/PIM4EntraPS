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

    3.1.27 (rule "five years, no contact: updates via the updater alone") -- two CONVERGE steps the updater runs with the
    install's OWN identity (tests/Test-PimBuiltinAuthConverge.ps1), both through seams, both idempotent and read back:
      * Invoke-PimBuiltinAuthConverge (AUTH-CONVERGE-1): an install ALREADY on the built-in sign-in is brought to the current
        standard -- the API scope exposed on the app registration the updater OWNS (+ the Azure CLI pre-authorised), then the
        provider loginParameters and the excluded paths (exactly the two metadata paths) on authConfigs/current. Never a
        secret, never a wider excluded path; a registration it does not own is reported, never forced; the scope is never
        asked for before it is exposed. Turning the built-in sign-in ON stays setup's.
      * Invoke-PimSigninFrontLeftoverClean (FRONT-LEFTOVER-CLEAN-1): once NO role assignment remains on a signin-front key,
        the retired sign-in front's leftovers go -- its database state (schema signin), the Manager's PIM_SIGNIN_FRONT_* /
        SIGNIN_* settings, the old /signin-oidc reply URL (on a registration it owns); the role-less signin-front key itself is
        ACCEPTED-INERT (kept, never deleted, an OK state). A key with a role assignment, or a front still on the Manager, =
        NOTHING removed. A right it lacks is reported.
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

# ======================================================================================================================
# AUTH-CONVERGE-1 + FRONT-LEFTOVER-CLEAN-1 (3.1.27, rule "five years, no contact: updates via the updater alone").
# The updater's converge steps with the install's OWN identity. Both take seams (tests hand in fakes), never throw, and
# return @{ state; changed; warnings; steps; lines = @(@{ level = info|changed|warn; text }); detail }.
#   -Arm   { param($Method, $Path, $Body) }   ARM; Path carries its api-version; a 404 may throw or return $null
#   -Graph { param($Method, $Path, $Body) }   Graph v1.0-relative paths
# ======================================================================================================================
if (-not (Get-Command Get-PimAppRegOwnerOwners -ErrorAction SilentlyContinue)) {
    $__pimBaOwner = Join-Path $PSScriptRoot 'PIM-AppRegOwner.ps1'
    if (Test-Path -LiteralPath $__pimBaOwner) { . $__pimBaOwner }
}

function Get-PimBuiltinAuthConvergeRefusal {
    <# PURE. The first line of an error text, and whether it is a refusal (403 / Authorization / Forbidden). #>
    param([AllowNull()][object]$ErrorRecord)
    $t = ((("$(if ($ErrorRecord -and $ErrorRecord.Exception) { $ErrorRecord.Exception.Message } else { $ErrorRecord })") -split "`n")[0]).Trim()
    return @{ text = $t; refused = [bool]($t -match '(?i)\b403\b|Forbidden|AuthorizationFailed|Authorization_RequestDenied|Insufficient privileges|does not have (secrets|keys) \w+ permission|not authorized|permission was denied|denied') }
}

function Get-PimBuiltinAuthConvergeAuthPlan {
    <#
      PURE. AUTH-CONVERGE-1: authConfigs/current as read -> what the updater changes on it, nothing else:
        * identityProviders.azureActiveDirectory.login.loginParameters = EXACTLY the standard (Get-PimBuiltinAuthLoginParameters)
          -- skipped with -NoLoginParameters (the API scope is not exposed yet: asking for it would break the sign-in)
        * globalValidation.excludedPaths = EXACTLY the two protected-resource metadata paths (anything else is removed --
          never a wider path)
      Everything else in the config is kept as read (secretless registration, token store, session). Only an install that
      is ALREADY on the built-in sign-in is converged: platform off, another client id or another unauthenticated action
      = ok $false (setup's change, through the Support app).
      @{ ok; reason; steps[]; properties (the full properties to PUT; $null = nothing to change); removedPaths[] }
    #>
    param([AllowNull()][object]$AuthConfig, [Parameter(Mandatory)][string]$ClientId, [switch]$NoLoginParameters)
    $no = { param($why) @{ ok = $false; reason = $why; steps = @(); properties = $null; removedPaths = @() } }
    if ($null -eq $AuthConfig) { return (& $no 'the built-in authentication settings are not there (setup turns the built-in sign-in on)') }
    $src = $AuthConfig
    if (Get-PimBuiltinAuthField $src 'properties') { $src = Get-PimBuiltinAuthField $src 'properties' }
    $p = $src | ConvertTo-Json -Depth 30 | ConvertFrom-Json
    $cid = "$ClientId".Trim()
    if ("$(Get-PimBuiltinAuthPath $p 'platform.enabled')" -notmatch '^(?i)true$') { return (& $no 'built-in authentication is OFF (setup turns it on -- the updater only converges an install already on it)') }
    if ("$(Get-PimBuiltinAuthPath $p 'globalValidation.unauthenticatedClientAction')" -ne 'RedirectToLoginPage') { return (& $no "unauthenticated callers are '$(Get-PimBuiltinAuthPath $p 'globalValidation.unauthenticatedClientAction')' (the Manager redirects to the sign-in; setup decides that)") }
    $aad = Get-PimBuiltinAuthPath $p 'identityProviders.azureActiveDirectory'
    if ($null -eq $aad) { return (& $no 'the Microsoft provider is not configured (setup)') }
    if ("$(Get-PimBuiltinAuthPath $aad 'registration.clientId')".Trim() -ne $cid) { return (& $no "the sign-in registration '$(Get-PimBuiltinAuthPath $aad 'registration.clientId')' is not the Manager's ($cid) -- not changed") }
    $steps = New-Object System.Collections.Generic.List[string]
    if (-not $NoLoginParameters) {
        $want = @(Get-PimBuiltinAuthLoginParameters -ClientId $cid)
        $cur = @(@(Get-PimBuiltinAuthPath $aad 'login.loginParameters') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if ((@($cur | Sort-Object) -join '|') -cne (@($want | Sort-Object) -join '|')) {
            $steps.Add('login-parameters')
            $lg = Get-PimBuiltinAuthField $aad 'login'
            if ($null -eq $lg -or $lg -is [string]) { $aad | Add-Member -NotePropertyName login -NotePropertyValue ([pscustomobject]@{ loginParameters = @($want) }) -Force }
            else { $lg | Add-Member -NotePropertyName loginParameters -NotePropertyValue @($want) -Force }
        }
    }
    $wantEx = @(Get-PimBuiltinAuthExcludedPaths)
    $gv = Get-PimBuiltinAuthField $p 'globalValidation'
    $curEx = @(@(Get-PimBuiltinAuthField $gv 'excludedPaths') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $removed = @($curEx | Where-Object { $wantEx -notcontains $_ } | Select-Object -Unique)
    if ((@($curEx | Select-Object -Unique | Sort-Object) -join '|') -cne (@($wantEx | Sort-Object) -join '|')) {
        $steps.Add('excluded-paths')
        $gv | Add-Member -NotePropertyName excludedPaths -NotePropertyValue @($wantEx) -Force
    }
    return @{ ok = $true; reason = ''; steps = @($steps.ToArray()); properties = $(if ($steps.Count) { $p } else { $null }); removedPaths = @($removed) }
}

function Test-PimBuiltinAuthConvergeAuthReadBack {
    <# PURE. Does authConfigs/current (as read back) carry the steps this run wrote? @{ ok; missing[] } #>
    param([AllowNull()][object]$AuthConfig, [Parameter(Mandatory)][string]$ClientId, [string[]]$Steps = @())
    $a = $AuthConfig; if ($a -and (Get-PimBuiltinAuthField $a 'properties')) { $a = Get-PimBuiltinAuthField $a 'properties' }
    $miss = New-Object System.Collections.Generic.List[string]
    if ($null -eq $a) { $miss.Add('the settings could not be read back'); return @{ ok = $false; missing = @($miss.ToArray()) } }
    if (@($Steps) -contains 'login-parameters') {
        $lp = @(@(Get-PimBuiltinAuthPath $a 'identityProviders.azureActiveDirectory.login.loginParameters') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if ((@($lp | Sort-Object) -join '|') -cne (@(@(Get-PimBuiltinAuthLoginParameters -ClientId $ClientId) | Sort-Object) -join '|')) { $miss.Add('loginParameters') }
    }
    if (@($Steps) -contains 'excluded-paths') {
        $ex = @(@(Get-PimBuiltinAuthPath $a 'globalValidation.excludedPaths') | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
        if ((@($ex | Sort-Object) -join '|') -cne (@(@(Get-PimBuiltinAuthExcludedPaths) | Sort-Object) -join '|')) { $miss.Add('excludedPaths') }
    }
    if ("$(Get-PimBuiltinAuthPath $a 'platform.enabled')" -notmatch '^(?i)true$') { $miss.Add('platform.enabled') }
    return @{ ok = ($miss.Count -eq 0); missing = @($miss.ToArray()) }
}

function Test-PimBuiltinAuthUpdaterOwns {
    <#
      READ ONLY. Is -UpdaterObjectId an owner of the application object -ObjectId? @{ owns = $true|$false|$null; reason }.
      $null = not known (no updater id, owners not readable) -- treated as NOT owned by every caller: nothing is written.
      Reuses engine/_shared/PIM-AppRegOwner.ps1 Get-PimAppRegOwnerOwners.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$ObjectId, [AllowEmptyString()][string]$UpdaterObjectId = '')
    $me = "$UpdaterObjectId".Trim().ToLowerInvariant()
    if ($me -notmatch '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$') { return @{ owns = $null; reason = 'the updater''s own object id is not known in this run' } }
    if (-not (Get-Command Get-PimAppRegOwnerOwners -ErrorAction SilentlyContinue)) { return @{ owns = $null; reason = 'the owner read is not loaded (engine/_shared/PIM-AppRegOwner.ps1)' } }
    $o = Get-PimAppRegOwnerOwners -Graph $Graph -ObjectId $ObjectId
    if (-not $o.ok) { return @{ owns = $null; reason = "$($o.reason)" } }
    if (@(@($o.owners) | Where-Object { "$($_.id)" -eq $me }).Count) { return @{ owns = $true; reason = 'the updater is an owner' } }
    return @{ owns = $false; reason = 'the updater is not an owner of this app registration' }
}

function Invoke-PimBuiltinAuthConverge {
    <#
      AUTH-CONVERGE-1 (3.1.27). The updater APPLIES the built-in sign-in standard on an install that is already on the
      built-in sign-in, in this order (a scope must exist before the sign-in asks for it):
        1. the app registration it OWNS (PIM_HOSTED_EASYAUTH_AUD): api://<id> + the delegated scope user_impersonation + the
           Azure CLI (04b07795-...) pre-authorised -- Get-PimBuiltinAuthApiScopePlan (two PATCHes, read back). Not an owner
           (or the owners not readable) = REPORTED, never forced.
        2. authConfigs/current (api 2024-10-02-preview, read-modify-PUT of what was read): the provider loginParameters
           (scope=openid profile email offline_access api://<id>/user_impersonation, prompt=select_account) -- ONLY when the
           scope reads back as exposed -- and excludedPaths EXACTLY the two /.well-known/oauth-protected-resource paths
           (Get-PimBuiltinAuthConvergeAuthPlan). Read back.
      NEVER a secret or a password credential, never a role, never a wider excluded path, never the top-level login block
      (it refuses loginParameters with HTTP 400). Nothing applies on an install with the sign-in front, on another layer, or
      with built-in authentication off (setup's change). Never throws.
        -WaitSeconds  the read-back retries of the app registration (Graph replication); tests pass @(0)
        -NewScopeId   the id a NEW scope gets ('' = a new GUID)
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$Graph, [Parameter(Mandatory)][string]$SubscriptionId,
          [Parameter(Mandatory)][string]$ResourceGroup, [string]$ManagerApp = 'ca-pim-manager', [AllowEmptyString()][string]$UpdaterObjectId = '',
          [int[]]$WaitSeconds = @(0, 5, 10, 20), [AllowEmptyString()][string]$NewScopeId = '', [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $std = Get-PimBuiltinAuthStandard
    $lines = New-Object System.Collections.Generic.List[object]
    $steps = New-Object System.Collections.Generic.List[string]
    $r = @{ state = 'unknown'; changed = 0; warnings = 0; steps = @(); lines = @(); detail = ''; scopeExposed = $null }
    $say = { param($lv, $t) $lines.Add(@{ level = $lv; text = "built-in sign-in converge: $t" }) | Out-Null; if ($lv -eq 'warn') { $r.warnings++ } }
    $done = { param($st, $d) $r.state = $st; $r.detail = $d; $r.steps = @($steps.ToArray()); $r.lines = @($lines.ToArray()); return $r }
    $get = { param($p) try { & $Arm 'GET' $p $null } catch { if ("$($_.Exception.Message)" -match '(?i)\b404\b|NotFound') { $null } else { throw } } }
    try {
        $appPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$ManagerApp"
        $app = $null; try { $app = & $get "$appPath`?api-version=$($std.appApi)" } catch { $app = $null }
        if ($null -eq $app) { & $say 'warn' 'the Manager app could not be read -- nothing applied'; return (& $done 'unknown' 'the Manager app could not be read') }
        $ctr = @(@(Get-PimBuiltinAuthPath $app 'properties.template.containers') | Where-Object { $_ })
        $mgr = @($ctr | Where-Object { "$($_.name)" -ne 'signin-front' }) | Select-Object -First 1
        $ev = @{}; foreach ($x in @(Get-PimBuiltinAuthField $mgr 'env')) { if ($x) { $ev["$($x.name)"] = "$($x.value)" } }
        if (@($ctr | Where-Object { "$($_.name)" -eq 'signin-front' }).Count -or "$($ev['PIM_HOSTED_AUTH_LAYER'])".Trim() -ieq 'signin-front') {
            & $say 'info' 'the sign-in front is on this Manager -- the built-in sign-in standard does not apply, nothing changed'
            return (& $done 'n/a' 'the sign-in front is on this Manager')
        }
        if ("$($ev['PIM_HOSTED_AUTH_LAYER'])".Trim() -ne 'easyauth') {
            & $say 'warn' "the Manager is not on the built-in sign-in (PIM_HOSTED_AUTH_LAYER=$($ev['PIM_HOSTED_AUTH_LAYER'])) -- nothing applied; setup moves it (Set-PimManagerEasyAuth.ps1 through the Support app)"
            return (& $done 'not-applied' 'the Manager is not on the built-in sign-in')
        }
        $cid = "$($ev['PIM_HOSTED_EASYAUTH_AUD'])".Trim()
        if ($cid -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            & $say 'warn' 'PIM_HOSTED_EASYAUTH_AUD is not an application id -- nothing applied'
            return (& $done 'not-applied' 'PIM_HOSTED_EASYAUTH_AUD is not an application id')
        }
        # ---- 1. the app registration: the API scope + the Azure CLI pre-authorised (only on a registration it owns) ----
        $exposed = $null
        if (-not $Graph) { & $say 'warn' 'no Graph access in this run -- the API scope was not checked' }
        else {
            $reg = $null; $regErr = ''
            try {
                $rr = & $Graph 'GET' "/applications?`$filter=$([uri]::EscapeDataString("appId eq '$cid'"))&`$select=id,appId,identifierUris,api,web" $null
                $reg = @(@(if ($rr -and (Get-PimBuiltinAuthField $rr 'value')) { @($rr.value) } else { @() }) | Where-Object { $_ -and "$($_.appId)" -eq $cid }) | Select-Object -First 1
            } catch { $regErr = (Get-PimBuiltinAuthConvergeRefusal $_).text }
            if (-not $reg) { & $say 'warn' "the Manager's app registration ($cid) could not be read$(if ($regErr) { ": $regErr" }) -- the API scope was not checked" }
            else {
                $sid = if ("$NewScopeId".Trim()) { "$NewScopeId".Trim() } else { [guid]::NewGuid().ToString() }
                $plan = Get-PimBuiltinAuthApiScopePlan -AppReg $reg -NewScopeId $sid
                if (-not @($plan.steps).Count) { $exposed = $true; & $say 'info' "the API scope api://$cid/$($std.apiScope) is exposed and the Azure CLI pre-authorised (nothing to change)" }
                else {
                    $own = Test-PimBuiltinAuthUpdaterOwns -Graph $Graph -ObjectId "$($reg.id)" -UpdaterObjectId $UpdaterObjectId
                    if ($own.owns -ne $true) {
                        $exposed = [bool](Test-PimBuiltinAuthApiScopeExposed -AppReg $reg)
                        & $say 'warn' "the app registration needs $(@($plan.steps) -join ', ') but $(if ($own.owns -eq $false) { 'the updater does not own it' } else { "ownership is not known ($($own.reason))" }) -- REPORTED, never forced (an owner adds the updater as owner, or setup runs Set-PimManagerEasyAuth.ps1 through the Support app)"
                    } else {
                        try {
                            if ($plan.patchScopes) { [void](& $Graph 'PATCH' "/applications/$($reg.id)" $plan.patchScopes); $steps.Add('api-scope') }
                            $ok = $false; $now = $null
                            foreach ($w in @($WaitSeconds)) {
                                if ([int]$w -gt 0) { & $Sleep ([int]$w) }
                                $now = & $Graph 'GET' "/applications/$($reg.id)?`$select=id,appId,identifierUris,api,web" $null
                                if (-not (Test-PimBuiltinAuthApiScopeExposed -AppReg $now)) { continue }
                                $pp = Get-PimBuiltinAuthApiScopePlan -AppReg $now -NewScopeId $plan.scopeId
                                if ($pp.patchPreAuth) { [void](& $Graph 'PATCH' "/applications/$($reg.id)" $pp.patchPreAuth); if ($steps -notcontains 'preauthorize-azure-cli') { $steps.Add('preauthorize-azure-cli') }; continue }
                                $ok = $true; break
                            }
                            $exposed = [bool](Test-PimBuiltinAuthApiScopeExposed -AppReg $now)
                            if ($ok) { $r.changed++; & $say 'changed' "the API scope api://$cid/$($std.apiScope) is exposed and the Azure CLI pre-authorised (read back)" }
                            else { & $say 'warn' "the API scope / the Azure CLI pre-authorisation did not read back yet -- the next run checks it again" }
                        } catch {
                            $e = Get-PimBuiltinAuthConvergeRefusal $_
                            & $say 'warn' "the app registration was not changed: $($e.text)$(if ($e.refused) { ' -- the updater lacks the right to change it (Application.ReadWrite.OwnedBy as an owner); reported, not added' })"
                        }
                    }
                }
            }
        }
        $r.scopeExposed = $exposed
        # ---- 2. authConfigs/current: the provider loginParameters (only with the scope exposed) + the excluded paths ----
        $authPath = "$appPath/authConfigs/current?api-version=$($std.authApi)"
        $auth = $null; try { $auth = & $get $authPath } catch { & $say 'warn' "the authentication settings could not be read: $((Get-PimBuiltinAuthConvergeRefusal $_).text) -- nothing applied"; return (& $done 'unknown' 'the authentication settings could not be read') }
        $ap = Get-PimBuiltinAuthConvergeAuthPlan -AuthConfig $auth -ClientId $cid -NoLoginParameters:($exposed -ne $true)
        if (-not $ap.ok) { & $say 'warn' "$($ap.reason) -- nothing applied"; return (& $done 'not-applied' "$($ap.reason)") }
        if ($exposed -ne $true) {
            $lpNow = Test-PimBuiltinAuthLoginParametersStandard -LoginParameters @(Get-PimBuiltinAuthPath $auth 'properties.identityProviders.azureActiveDirectory.login.loginParameters') -ClientId $cid
            if (-not $lpNow.ok) { & $say 'warn' 'the sign-in is not asked for the API scope while the scope is not exposed (asking would break the sign-in) -- the Manager keeps verifying the ID token until then' }
        }
        if (-not @($ap.steps).Count) { & $say 'info' 'the provider loginParameters and the excluded paths are the standard (nothing to change)' }
        else {
            try {
                [void](& $Arm 'PUT' $authPath @{ properties = $ap.properties })
                $back = & $get $authPath
                $rb = Test-PimBuiltinAuthConvergeAuthReadBack -AuthConfig $back -ClientId $cid -Steps @($ap.steps)
                foreach ($s in @($ap.steps)) { $steps.Add($s) }
                if ($rb.ok) {
                    $r.changed++
                    & $say 'changed' ("$(@($ap.steps) -join ' + ') applied and read back$(if (@($ap.removedPaths).Count) { " (excluded paths removed: $(@($ap.removedPaths) -join ', '))" }) -- excluded paths: $((Get-PimBuiltinAuthExcludedPaths) -join ', ') only")
                } else { & $say 'warn' "written, but did not read back: $(@($rb.missing) -join ', ') -- the next run tries again" }
            } catch {
                $e = Get-PimBuiltinAuthConvergeRefusal $_
                & $say 'warn' "the authentication settings were not changed: $($e.text)$(if ($e.refused) { ' -- the updater lacks Microsoft.App/containerApps/authConfigs/write on the Manager; reported, not added' })"
            }
        }
        $st = if ($r.warnings) { 'partial' } elseif ($r.changed) { 'changed' } else { 'ok' }
        return (& $done $st $(switch ($st) { 'ok' { 'the built-in sign-in is the standard (nothing to change)' } 'changed' { "applied: $(@($steps.ToArray()) -join ', ')" } default { "not everything applied ($($r.warnings) to fix)" } }))
    } catch {
        & $say 'warn' "not converged: $((Get-PimBuiltinAuthConvergeRefusal $_).text)"
        return (& $done 'unknown' 'not converged (an unexpected error)')
    }
}

function Get-PimSigninFrontLeftoverSql {
    <#
      PURE. LITERAL. FRONT-LEFTOVER-CLEAN-1: the retired sign-in front's database state -- schema signin (signin.Cache = the
      sessions / OIDC state, signin.DataProtectionKeys = its key ring, wrapped by the signin-front key) -- dropped: its
      foreign keys, tables, views / procedures / functions, then the schema. Idempotent (no schema = nothing done). Only
      schema signin: nothing in pim or any other schema is named.
    #>
    return (@(
        "IF SCHEMA_ID(N'signin') IS NOT NULL"
        "BEGIN"
        "  DECLARE @fk NVARCHAR(MAX) = N''; SELECT @fk += N'ALTER TABLE signin.' + QUOTENAME(OBJECT_NAME(parent_object_id)) + N' DROP CONSTRAINT ' + QUOTENAME(name) + N';' FROM sys.foreign_keys WHERE schema_id = SCHEMA_ID(N'signin'); IF @fk <> N'' EXEC (@fk);"
        "  DECLARE @tb NVARCHAR(MAX) = N''; SELECT @tb += N'DROP TABLE signin.' + QUOTENAME(name) + N';' FROM sys.tables WHERE schema_id = SCHEMA_ID(N'signin'); IF @tb <> N'' EXEC (@tb);"
        "  DECLARE @ob NVARCHAR(MAX) = N''; SELECT @ob += CASE type WHEN 'V' THEN N'DROP VIEW ' WHEN 'P' THEN N'DROP PROCEDURE ' ELSE N'DROP FUNCTION ' END + N'signin.' + QUOTENAME(name) + N';' FROM sys.objects WHERE schema_id = SCHEMA_ID(N'signin') AND type IN ('V', 'P', 'FN', 'IF', 'TF'); IF @ob <> N'' EXEC (@ob);"
        "  EXEC (N'DROP SCHEMA signin');"
        "END"
    ) -join "`n")
}

function Get-PimSigninFrontLeftoverEnvNames {
    <# PURE. The Manager settings only the retired sign-in front used (the same family Test-PimBuiltinAuthStandard names as leftovers). #>
    param([AllowEmptyCollection()][object[]]$Env = @())
    return @(@($Env) | Where-Object { $_ -and "$($_.name)" -match '^(PIM_SIGNIN_FRONT_|SIGNIN_)' } | ForEach-Object { "$($_.name)" } | Sort-Object -Unique)
}

function Get-PimSigninFrontLeftoverRedirects {
    <#
      PURE. The front's old reply URLs on an app registration: https://<host>/signin-oidc for a host of THIS Manager (its
      platform FQDN or a custom domain). Everything else -- the built-in callback /.auth/login/aad/callback included -- is
      kept. @{ remove[]; keep[] }
    #>
    param([AllowEmptyCollection()][string[]]$RedirectUris = @(), [AllowEmptyCollection()][string[]]$Hosts = @())
    $hs = @(@($Hosts) | ForEach-Object { "$_".Trim().TrimEnd('/').ToLowerInvariant() } | Where-Object { $_ })
    $rm = @(); $keep = @()
    foreach ($u in @($RedirectUris)) {
        $t = "$u".Trim(); if (-not $t) { continue }
        $m = [regex]::Match($t, '^(?i)https://([^/]+)/signin-oidc/?$')
        if ($m.Success -and $hs -contains $m.Groups[1].Value.ToLowerInvariant()) { $rm += $t } else { $keep += $t }
    }
    return @{ remove = @($rm); keep = @($keep) }
}

function Invoke-PimSigninFrontLeftoverClean {
    <#
      FRONT-LEFTOVER-CLEAN-1 (3.1.27). The retired sign-in front's leftovers, removed by the install's OWN identity -- ONLY
      after it reads back that NO role assignment remains on <vault>/keys/signin-front (the control plane removes those):
        a. the front's database state: schema signin (Get-PimSigninFrontLeftoverSql), read back (skipped while -SqlSkipReason)
        b. the Manager's PIM_SIGNIN_FRONT_* / SIGNIN_* settings (one template PATCH, read back)
        c. https://<fqdn>/signin-oidc on the app registration(s) the front used -- on a registration the updater OWNS; the
           built-in callback /.auth/login/aad/callback is kept. Not owned = reported, never forced.
        d. the signin-front KEY with no role assignment on it: ACCEPTED-INERT (Invardia decision 2026-11-15, framework
           FRONT-LEFTOVER-CLEAN-1) -- KEPT, never deleted, no new right needed; keyState 'accepted-inert' and, when nothing
           else changed, state 'accepted-inert' (an OK state, not a warning). A key WITH a role assignment stays a reported
           leftover (keyState 'held', state 'waiting'). No key = keyState 'absent'. -PurgeKey is accepted and ignored.
      GATES (each = NOTHING removed): the Manager not read; a 'signin-front' container still on the Manager or
      PIM_HOSTED_AUTH_LAYER=signin-front (the install is not switched); the vaults not read; a key's role assignments not
      read; ANY role assignment on a signin-front key. A right the updater lacks is REPORTED -- never added. Never throws.
        -Kv        { param($Method, $Url) }  Key Vault data plane -- NEVER called (the key is never deleted); optional, kept for the seam
        -SqlExec   { param($Sql) }  /  -SqlScalar { param($Sql) }   the updater's own database connection ($null = not reached)
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$Graph, [scriptblock]$Kv, [scriptblock]$SqlExec, [scriptblock]$SqlScalar,
          [AllowEmptyString()][string]$SqlSkipReason = '', [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string]$ManagerApp = 'ca-pim-manager', [AllowEmptyString()][string]$UpdaterObjectId = '', [switch]$PurgeKey)
    $std = Get-PimBuiltinAuthStandard
    $kvApi = '2023-07-01'
    $lines = New-Object System.Collections.Generic.List[object]
    $removed = New-Object System.Collections.Generic.List[string]
    $r = @{ state = 'unknown'; changed = 0; warnings = 0; removed = @(); remaining = @(); lines = @(); detail = ''; keyRoleAssignments = $null; keyState = $null; inertKeys = @() }
    $left = New-Object System.Collections.Generic.List[string]
    $say = { param($lv, $t) $lines.Add(@{ level = $lv; text = "sign-in front leftovers: $t" }) | Out-Null; if ($lv -eq 'warn') { $r.warnings++ } }
    $done = { param($st, $d) $r.state = $st; $r.detail = $d; $r.removed = @($removed.ToArray()); $r.remaining = @($left.ToArray()); $r.lines = @($lines.ToArray()); return $r }
    $get = { param($p) try { & $Arm 'GET' $p $null } catch { if ("$($_.Exception.Message)" -match '(?i)\b404\b|NotFound|KeyNotFound') { $null } else { throw } } }
    $items = { param($x) if ($null -eq $x) { @() } elseif (Get-PimBuiltinAuthField $x 'value') { @($x.value) } elseif ($x -is [array]) { @($x) } else { @() } }
    try {
        $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        $appPath = "$rg/providers/Microsoft.App/containerApps/$ManagerApp"
        $app = $null; try { $app = & $get "$appPath`?api-version=$($std.appApi)" } catch { $app = $null }
        if ($null -eq $app) { & $say 'warn' 'the Manager app could not be read -- NOTHING removed'; return (& $done 'unknown' 'the Manager app could not be read') }
        $ctr = @(@(Get-PimBuiltinAuthPath $app 'properties.template.containers') | Where-Object { $_ })
        $mgr = @($ctr | Where-Object { "$($_.name)" -ne 'signin-front' }) | Select-Object -First 1
        $ev = @{}; foreach ($x in @(Get-PimBuiltinAuthField $mgr 'env')) { if ($x) { $ev["$($x.name)"] = "$($x.value)" } }
        if (@($ctr | Where-Object { "$($_.name)" -eq 'signin-front' }).Count -or "$($ev['PIM_HOSTED_AUTH_LAYER'])".Trim() -ieq 'signin-front') {
            & $say 'info' 'the sign-in front container is still on the Manager (the install is not switched) -- NOTHING removed'
            return (& $done 'blocked' 'the sign-in front is still on the Manager')
        }
        if ("$($ev['PIM_HOSTED_AUTH_LAYER'])".Trim() -ne 'easyauth') {
            & $say 'warn' "the Manager is not on the built-in sign-in (PIM_HOSTED_AUTH_LAYER=$($ev['PIM_HOSTED_AUTH_LAYER'])) -- NOTHING removed"
            return (& $done 'blocked' 'the Manager is not on the built-in sign-in')
        }
        # ---- the gate: the signin-front keys and the role assignments ON them ----------------------------------------
        $vaults = $null
        try { $vaults = @(& $items (& $get "$rg/providers/Microsoft.KeyVault/vaults?api-version=$kvApi")) } catch { $vaults = $null }
        if ($null -eq $vaults) { & $say 'warn' 'the Key Vaults could not be read -- NOTHING removed (no proof that no role remains on the key)'; return (& $done 'unknown' 'the Key Vaults could not be read') }
        $keys = New-Object System.Collections.Generic.List[object]
        foreach ($v in $vaults) {
            $vid = "$(Get-PimBuiltinAuthField $v 'id')".Trim(); if (-not $vid) { $vid = "$rg/providers/Microsoft.KeyVault/vaults/$($v.name)" }
            $k = $null
            try { $k = & $get "$vid/keys/signin-front?api-version=$kvApi" } catch { & $say 'warn' "the key signin-front in $($v.name) could not be read -- NOTHING removed"; return (& $done 'unknown' "the key in $($v.name) could not be read") }
            if ($null -eq $k) { continue }
            $scope = "$vid/keys/signin-front"
            $ras = $null
            try { $ras = @(& $items (& $Arm 'GET' "$scope/providers/Microsoft.Authorization/roleAssignments?api-version=$($std.raApi)" $null)) } catch { $ras = $null }
            if ($null -eq $ras) { & $say 'warn' "the role assignments on $($v.name)/keys/signin-front could not be read -- NOTHING removed"; return (& $done 'unknown' 'the role assignments on the key could not be read') }
            $onKey = @($ras | Where-Object { "$(Get-PimBuiltinAuthPath $_ 'properties.scope')".Trim().TrimEnd('/') -ieq $scope })
            $keys.Add([pscustomobject]@{ vault = "$($v.name)"; vaultId = $vid; vaultUri = "$(Get-PimBuiltinAuthPath $v 'properties.vaultUri')".Trim().TrimEnd('/'); purgeProtection = ("$(Get-PimBuiltinAuthPath $v 'properties.enablePurgeProtection')" -match '^(?i)true$'); roles = $onKey.Count }) | Out-Null
        }
        $held = @($keys | Where-Object { $_.roles -gt 0 })
        $r.keyRoleAssignments = [int](@($keys | ForEach-Object { $_.roles }) | Measure-Object -Sum).Sum
        if ($held.Count) {
            foreach ($h in $held) { $left.Add("$($h.vault)/keys/signin-front ($($h.roles) role assignments)") }
            $r.keyState = 'held'
            & $say 'info' ("$(@($held | ForEach-Object { "$($_.roles) role assignment(s) still on $($_.vault)/keys/signin-front" }) -join '; ') -- NOTHING removed (the role assignments go first)")
            return (& $done 'waiting' 'role assignments remain on the signin-front key')
        }
        # ---- a. the front's database state ----------------------------------------------------------------------------
        if (-not $SqlScalar) { & $say 'info' 'the database was not reached in this run -- the front''s state is checked next run' }
        else {
            try {
                $has = "$(& $SqlScalar "SELECT CASE WHEN SCHEMA_ID(N'signin') IS NULL THEN 0 ELSE 1 END")".Trim()
                if ($has -ne '1') { & $say 'info' 'the front''s database state (schema signin) is not there' }
                elseif ("$SqlSkipReason".Trim()) { $left.Add('schema signin'); & $say 'info' "the front's database state (schema signin) waits: $SqlSkipReason" }
                elseif (-not $SqlExec) { $left.Add('schema signin'); & $say 'warn' 'the front''s database state is there but no write connection was given' }
                else {
                    & $SqlExec (Get-PimSigninFrontLeftoverSql) | Out-Null
                    $after = "$(& $SqlScalar "SELECT CASE WHEN SCHEMA_ID(N'signin') IS NULL THEN 0 ELSE 1 END")".Trim()
                    if ($after -eq '0') { $removed.Add('schema signin'); $r.changed++; & $say 'changed' 'the front''s database state (schema signin: its sessions and key ring) removed (read back)' }
                    else { $left.Add('schema signin'); & $say 'warn' 'the front''s database state did not read back as removed -- the next run tries again' }
                }
            } catch {
                $e = Get-PimBuiltinAuthConvergeRefusal $_; $left.Add('schema signin')
                & $say 'warn' "the front's database state was not removed: $($e.text)$(if ($e.refused -or $e.text -match '(?i)permission') { ' -- the updater''s database user lacks the right to drop it (db_ddladmin); reported, not added' })"
            }
        }
        # ---- b. the Manager's front-only settings ---------------------------------------------------------------------
        $frontCids = @(@("$($ev['PIM_SIGNIN_FRONT_CLIENT_ID'])" -split '[,;]+') + @("$($ev['PIM_HOSTED_EASYAUTH_AUD'])") | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' } | Select-Object -Unique)
        $drop = @(Get-PimSigninFrontLeftoverEnvNames -Env @(Get-PimBuiltinAuthField $mgr 'env'))
        if (-not $drop.Count) { & $say 'info' 'the Manager carries no sign-in front setting' }
        else {
            try {
                $tpl = (Get-PimBuiltinAuthPath $app 'properties.template') | ConvertTo-Json -Depth 30 | ConvertFrom-Json
                foreach ($c in @($tpl.containers)) {
                    if ("$($c.name)" -ne "$($mgr.name)") { continue }
                    $c | Add-Member -NotePropertyName env -NotePropertyValue @(@($c.env) | Where-Object { $_ -and $drop -notcontains "$($_.name)" }) -Force
                }
                [void](& $Arm 'PATCH' "$appPath`?api-version=$($std.appApi)" @{ properties = @{ template = $tpl } })
                $back = & $get "$appPath`?api-version=$($std.appApi)"
                $bm = @(@(Get-PimBuiltinAuthPath $back 'properties.template.containers') | Where-Object { $_ -and "$($_.name)" -eq "$($mgr.name)" }) | Select-Object -First 1
                $still = @(Get-PimSigninFrontLeftoverEnvNames -Env @(Get-PimBuiltinAuthField $bm 'env'))
                if (-not $bm) { foreach ($n in $drop) { $left.Add("setting $n") }; & $say 'warn' 'the Manager did not read back -- the next run checks the settings again' }
                elseif ($still.Count) { foreach ($n in $still) { $left.Add("setting $n") }; & $say 'warn' "still on the Manager after the write: $($still -join ', ') -- the next run tries again" }
                else { foreach ($n in $drop) { $removed.Add("setting $n") }; $r.changed++; & $say 'changed' "the Manager's sign-in front settings removed: $($drop -join ', ') (read back)" }
            } catch {
                $e = Get-PimBuiltinAuthConvergeRefusal $_; foreach ($n in $drop) { $left.Add("setting $n") }
                & $say 'warn' "the Manager's sign-in front settings were not removed: $($e.text)$(if ($e.refused) { ' -- the updater lacks write on the Manager app; reported, not added' })"
            }
        }
        # ---- c. the old /signin-oidc reply URL on the registration(s) the front used ----------------------------------
        $hosts = @(@("$(Get-PimBuiltinAuthPath $app 'properties.configuration.ingress.fqdn')") + @(@(Get-PimBuiltinAuthPath $app 'properties.configuration.ingress.customDomains') | ForEach-Object { "$(Get-PimBuiltinAuthField $_ 'name')" }) | Where-Object { "$_".Trim() })
        if (-not $Graph) { & $say 'info' 'no Graph access in this run -- the old reply URL is checked next run' }
        else {
            foreach ($fc in $frontCids) {
                try {
                    $rr = & $Graph 'GET' "/applications?`$filter=$([uri]::EscapeDataString("appId eq '$fc'"))&`$select=id,appId,web" $null
                    $reg = @(@(if ($rr -and (Get-PimBuiltinAuthField $rr 'value')) { @($rr.value) } else { @() }) | Where-Object { $_ -and "$($_.appId)" -eq $fc }) | Select-Object -First 1
                    if (-not $reg) { & $say 'info' "the app registration $fc is not readable here -- its reply URLs were not checked"; continue }
                    $plan = Get-PimSigninFrontLeftoverRedirects -RedirectUris @(Get-PimBuiltinAuthPath $reg 'web.redirectUris') -Hosts $hosts
                    if (-not @($plan.remove).Count) { continue }
                    $own = Test-PimBuiltinAuthUpdaterOwns -Graph $Graph -ObjectId "$($reg.id)" -UpdaterObjectId $UpdaterObjectId
                    if ($own.owns -ne $true) {
                        foreach ($u in @($plan.remove)) { $left.Add("reply URL $u") }
                        & $say 'warn' "the old reply URL $(@($plan.remove) -join ', ') stays on $fc -- $(if ($own.owns -eq $false) { 'the updater does not own that app registration' } else { "ownership is not known ($($own.reason))" }); REPORTED, never forced"
                        continue
                    }
                    [void](& $Graph 'PATCH' "/applications/$($reg.id)" @{ web = @{ redirectUris = @($plan.keep) } })
                    $now = & $Graph 'GET' "/applications/$($reg.id)?`$select=id,appId,web" $null
                    $chk = Get-PimSigninFrontLeftoverRedirects -RedirectUris @(Get-PimBuiltinAuthPath $now 'web.redirectUris') -Hosts $hosts
                    $keptAll = -not @(@($plan.keep) | Where-Object { @(Get-PimBuiltinAuthPath $now 'web.redirectUris') -notcontains $_ }).Count
                    if (-not @($chk.remove).Count -and $keptAll) { foreach ($u in @($plan.remove)) { $removed.Add("reply URL $u") }; $r.changed++; & $say 'changed' "the old reply URL $(@($plan.remove) -join ', ') removed from $fc (the built-in callback kept; read back)" }
                    else { foreach ($u in @($plan.remove)) { $left.Add("reply URL $u") }; & $say 'warn' "the reply URLs of $fc did not read back as written -- the next run tries again" }
                } catch {
                    $e = Get-PimBuiltinAuthConvergeRefusal $_
                    & $say 'warn' "the reply URLs of $fc were not changed: $($e.text)$(if ($e.refused) { ' -- the updater lacks the right to change that registration (Application.ReadWrite.OwnedBy as an owner); reported, not added' })"
                }
            }
        }
        # ---- d. the signin-front key: ACCEPTED-INERT (Invardia decision 2026-11-15, framework FRONT-LEFTOVER-CLEAN-1) ----
        # A retired signin-front key with NO role assignment on it (the gate above proved that) is inert: no identity can use
        # it. It is KEPT -- never deleted, never force-deleted, no new right asked for -- and reported as an OK state.
        # (-PurgeKey is accepted for compatibility and ignored: there is no key delete any more.)
        if (-not $keys.Count) { & $say 'info' 'no signin-front key in the install''s vaults'; $r.keyState = 'absent' }
        else {
            foreach ($k in $keys) { $r.inertKeys += "$($k.vault)/keys/signin-front" }
            $r.keyState = 'accepted-inert'
            & $say 'info' "the key $(@($r.inertKeys) -join ', ') holds no role assignment -- accepted as inert (kept; nothing can use it)"
        }
        $st = if ($left.Count -or $r.warnings) { 'partial' } elseif ($r.changed) { 'changed' } elseif ($r.keyState -eq 'accepted-inert') { 'accepted-inert' } else { 'ok' }
        return (& $done $st $(switch ($st) { 'ok' { 'no sign-in front leftover on this install' } 'accepted-inert' { "no sign-in front leftover; the role-less key is accepted as inert: $(@($r.inertKeys) -join ', ')" } 'changed' { "removed: $(@($removed.ToArray()) -join ', ')$(if ($r.keyState -eq 'accepted-inert') { "; the role-less key is accepted as inert: $(@($r.inertKeys) -join ', ')" })" } default { "left: $(@($left.ToArray()) -join ', ')" } }))
    } catch {
        & $say 'warn' "not cleaned: $((Get-PimBuiltinAuthConvergeRefusal $_).text)"
        return (& $done 'unknown' 'not cleaned (an unexpected error)')
    }
}

# ---- framework 8.17 SignIn: the sign-in layer, read-only detection ------------------------------------------------------
# Moved here from the removed engine/_shared/PIM-SigninFrontImage.ps1 (SECURE-WEB-1 ONE STANDARD (a), 2026-11-19): the front
# is not built, shipped or rolled any more, but a Manager that still carries a 'signin-front' container is REPORTED as such
# (a leftover the owner must see), never hidden.
function Get-PimSignInLayer {
    <#
      PURE. Framework 8.17 SignIn (agreed SI + PIM + Invardia 2026-10-20): the web app's sign-in layer, read from the RUNNING
      app, never from a config file. -App = the Manager container app (ARM), -AuthConfig = its authConfigs/current (ARM) and
      -AuthRead = that read answered (a missing auth config is $null with -AuthRead $true = no Easy Auth).
        a container named 'signin-front'           -> layer 'signin-front', version = its image tag up to the first '-'
                                                      (signin-front:1.2.1-src-<hash> -> '1.2.1'; no tag = $null)
        else authConfigs/current platform.enabled  -> 'easyauth' (version $null)
        else                                       -> 'none'     (an OPEN web app is reported, never left out)
      No app, or the auth config was not read on an app without the front = $null (not known -- never a guess).
      @{ layer; version; checkedUtc }
    #>
    param([AllowNull()][object]$App, [AllowNull()][object]$AuthConfig = $null, [bool]$AuthRead = $false, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $App -or $null -eq $App.properties) { return $null }
    $ts = $NowUtc.ToUniversalTime().ToString('o')
    $fr = @(@($App.properties.template.containers) | Where-Object { $_ -and "$($_.name)" -eq 'signin-front' })
    if ($fr.Count) {
        $img = "$($fr[0].image)"
        $tag = if ($img -match ':([^:/@]+)$') { $Matches[1] } else { '' }
        $ver = (($tag -split '-')[0]).Trim()
        return [ordered]@{ layer = 'signin-front'; version = $(if ($ver) { $ver } else { $null }); checkedUtc = $ts }
    }
    if (-not $AuthRead) { return $null }
    $on = $false
    if ($AuthConfig -and $AuthConfig.properties -and $AuthConfig.properties.platform) { $on = ("$($AuthConfig.properties.platform.enabled)" -match '^(?i)true$') }
    return [ordered]@{ layer = $(if ($on) { 'easyauth' } else { 'none' }); version = $null; checkedUtc = $ts }
}
