#Requires -Version 5.1
<#
.SYNOPSIS
  GUIDED-INSTALL-FRONT (PIM docs/REQUIREMENTS.md; owner 2026-10-21, trial end-to-end: "no quick dirty" / "biz depends on it
  works"): a NEW guided install of PIM Manager ends on the shared sign-in front (framework 12.11g, pinned version, state in
  SQL, keys wrapped by the install's own Key Vault, access token upstream) -- never on Easy Auth.

.DESCRIPTION
  Install-PimManager.ps1 runs this after the deploy, the licence and the support access, while it can still reach the
  database. Five steps, each idempotent and each its own progress event (step ids below); -Resume skips the ones done:
    signin-front-vault   the install's own Key Vault (a vault per install, owner 2026-10-21: Standard, RBAC, soft delete
                         90 days, purge protection), an RSA key 'signin-front' (wrapKey / unwrapKey) and "Key Vault Crypto
                         Service Encryption User" on THAT key for the Manager's web identity
    signin-front-state   the front's place in the database: a contained user for the web identity (from its client id),
                         schema 'signin' owned by it, GRANT CREATE TABLE -- nothing else
    signin-front-app     the sign-in registration: identifierUri api://<client id>, delegated scope 'user_impersonation',
                         its AllPrincipals self-grant (the front asks for an ACCESS token for the Manager)
    signin-front-image   signin-front:<pinned version> in the install's registry, built from THIS release's source (the
                         same REST ACR build as the Manager image); a copy without the front's source leaves it to the
                         install's updater (Set-PimManagerSigninFront starts one run)
    signin-front         Set-PimManagerSigninFront.ps1 -Apply: federated credential, redirect URIs, the two-container
                         revision with SIGNIN_SQL_SERVER / SIGNIN_SQL_DATABASE / SIGNIN_KEYVAULT_KEY_ID /
                         SIGNIN_UPSTREAM_SCOPE, Easy Auth OFF only once the front serves, the read-back -- or its rollback
  The deploy still creates the sign-in registration through its 'easyauth' step (the registration, its members group and
  'assignment required' are the same contract: -EasyAuthAllowedPrincipals / -EasyAuthAllowAllTenantUsers say who may sign
  in); this step moves it behind the front before the install reports 'completed'.
  Fresh-tenant timing: a new identity's role assignment (PrincipalNotFound), a new application's service principal, and the
  first database sign-in of a new server are retried with bounded waits; anything else fails the step with its reason.

  PURE functions are offline-tested (tests/Test-PimGuidedInstallFront.ps1); the I/O is injected (-Io), so the whole
  orchestration runs with no Azure at all. PS 5.1 + 7, REST / .NET only, no modules.
#>

$script:PimSfiKeyName = 'signin-front'
$script:PimSfiScope = 'user_impersonation'
$script:PimSfiCryptoUserRole = 'e147488a-f6f5-4113-8e2d-b22465e65bf6'   # Key Vault Crypto Service Encryption User
$script:PimSfiStepIds = @('signin-front-vault', 'signin-front-state', 'signin-front-app', 'signin-front-image', 'signin-front')

function Get-PimInstallSigninFrontStepIds { return @($script:PimSfiStepIds) }

function Test-PimInstallKeyVaultName {
    <# PURE. A Key Vault name Azure accepts: 3-24 letters, digits and dashes, starts with a letter, ends with a letter or digit, no '--'. #>
    param([AllowEmptyString()][string]$Name)
    $n = "$Name".Trim()
    return ($n -match '^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$' -and $n -notmatch '--')
}

function Get-PimInstallKeyVaultName {
    <#
      PURE. The install's vault name: -Configured (config 'keyVaultName', the customer's own naming) when it is a valid name,
      else 'kv-pim-<token>' (the install's name token, so it is globally unique like the registry and the SQL server).
      @{ ok; name; reason }.
    #>
    param([AllowEmptyString()][string]$Configured = '', [Parameter(Mandatory)][string]$Token)
    $c = "$Configured".Trim()
    if ($c) {
        if (Test-PimInstallKeyVaultName $c) { return @{ ok = $true; name = $c.ToLowerInvariant(); reason = 'the name from the answers (keyVaultName)' } }
        return @{ ok = $false; name = ''; reason = "keyVaultName '$c' is not a valid Key Vault name (3-24 letters, digits and dashes; starts with a letter; no '--')" }
    }
    $t = ("$Token".Trim().ToLowerInvariant() -replace '[^a-z0-9]', '')
    if (-not $t) { return @{ ok = $false; name = ''; reason = 'no name token to derive the Key Vault name from' } }
    $n = "kv-pim-$t"
    if ($n.Length -gt 24) { $n = $n.Substring(0, 24).TrimEnd('-') }
    return @{ ok = $true; name = $n; reason = 'derived from the install''s name token' }
}

function New-PimInstallKeyVaultBody {
    <# PURE. The vault: Standard (no monthly fee), RBAC, soft delete 90 days, purge protection (owner 2026-10-21: "A vault per install"). #>
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$TenantId)
    return [ordered]@{
        location = $Location; tags = [ordered]@{ product = 'pim-manager'; purpose = 'signin-front' }
        properties = [ordered]@{ tenantId = $TenantId; sku = [ordered]@{ family = 'A'; name = 'standard' }; enableRbacAuthorization = $true
                                 enableSoftDelete = $true; softDeleteRetentionInDays = 90; enablePurgeProtection = $true; publicNetworkAccess = 'Enabled' }
    }
}

function Get-PimInstallKeyRoleAssignmentName {
    <# PURE. The role assignment's name -- a GUID from key + principal + role, so a re-run finds the one it made (MD5, PS 5.1-safe). #>
    param([Parameter(Mandatory)][string]$KeyPath, [Parameter(Mandatory)][string]$PrincipalId, [string]$RoleDefinitionId = $script:PimSfiCryptoUserRole)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { $h = $md5.ComputeHash([Text.Encoding]::UTF8.GetBytes("$KeyPath|$PrincipalId|$RoleDefinitionId".ToLowerInvariant())) } finally { $md5.Dispose() }
    return ([guid]::new([byte[]]$h)).ToString()
}

function ConvertTo-PimSqlSidLiteral {
    <# PURE. A managed identity's client id as the SID literal CREATE USER ... WITH SID = ... TYPE = E takes. #>
    param([Parameter(Mandatory)][string]$ClientId)
    return '0x' + ((([guid]"$ClientId").ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Get-PimInstallSigninFrontSqlPlan {
    <#
      PURE. What the database still needs, from what was read: -User (the user whose SID is the identity's, '' = none),
      -Owner (the schema signin's owner, '' = no schema), -CreateTableGranted. The statements, in order. Never a role.
    #>
    param([AllowEmptyString()][string]$User = '', [AllowEmptyString()][string]$Owner = '', [bool]$CreateTableGranted = $false,
          [Parameter(Mandatory)][string]$IdentityName, [Parameter(Mandatory)][string]$Sid)
    if ($IdentityName -notmatch '^[A-Za-z0-9_.-]{1,128}$') { throw "not a database user name: $IdentityName" }
    if ($Sid -notmatch '^0x[0-9A-F]{32}$') { throw "not a SID literal: $Sid" }
    $plan = New-Object System.Collections.Generic.List[string]
    $u = if ("$User".Trim()) { "$User".Trim() } else { $IdentityName }
    if (-not "$User".Trim()) { $plan.Add("CREATE USER [$IdentityName] WITH SID = $Sid, TYPE = E") }
    if (-not "$Owner".Trim()) { $plan.Add("EXEC(N'CREATE SCHEMA signin AUTHORIZATION [$u]')") }
    elseif ("$Owner".Trim() -ne $u) { $plan.Add("ALTER AUTHORIZATION ON SCHEMA::signin TO [$u]") }
    if (-not $CreateTableGranted) { $plan.Add("GRANT CREATE TABLE TO [$u]") }
    return @($plan)
}

function Get-PimInstallSigninFrontAppPlan {
    <#
      PURE. The registration's change for access-token mode, from the registration read (-AppReg: identifierUris, api).
      @{ needUri; needScope; body (the PATCH, $null when nothing to do); scopeValue; upstreamScope }.
    #>
    param([Parameter(Mandatory)][object]$AppReg, [Parameter(Mandatory)][string]$ClientId, [scriptblock]$NewId = { [guid]::NewGuid().ToString() })
    $uri = "api://$("$ClientId".Trim())"
    $scopes = @(if ($AppReg.api -and $AppReg.api.oauth2PermissionScopes) { @($AppReg.api.oauth2PermissionScopes) })
    $has = @($scopes | Where-Object { $_ -and "$($_.value)" -eq $script:PimSfiScope }).Count -gt 0
    $needUri = @($AppReg.identifierUris) -notcontains $uri
    $out = @{ needUri = $needUri; needScope = -not $has; body = $null; scopeValue = $script:PimSfiScope; upstreamScope = "$uri/$($script:PimSfiScope)" }
    if (-not $needUri -and $has) { return $out }
    $body = [ordered]@{}
    if (-not $has) {
        $new = [pscustomobject][ordered]@{ id = "$(& $NewId)"; value = $script:PimSfiScope; type = 'Admin'; isEnabled = $true
            adminConsentDisplayName = 'Sign in to PIM Manager'; adminConsentDescription = 'Lets the PIM Manager sign-in front call the PIM Manager for the signed-in user.'
            userConsentDisplayName = 'Sign in to PIM Manager'; userConsentDescription = 'Lets the sign-in front call the PIM Manager for you.' }
        $body['api'] = [ordered]@{ oauth2PermissionScopes = @(@($scopes | Where-Object { $_ }) + $new) }
    }
    if ($needUri) { $body['identifierUris'] = @(@(@($AppReg.identifierUris) | Where-Object { "$_".Trim() }) + $uri | Select-Object -Unique) }
    $out.body = $body
    return $out
}

function Test-PimInstallRetryable {
    <#
      PURE. A fresh-tenant timing answer worth waiting for (bounded by the caller): a just-made identity not yet known to
      authorization (PrincipalNotFound), a just-made application's service principal not found yet, a new server's first
      database sign-in (18456 / login failed / token not yet valid), a busy app (409 OperationInProgress). Anything else: no.
    #>
    param([AllowEmptyString()][string]$Message = '', [ValidateSet('role', 'graph', 'sql', 'arm')][string]$Kind = 'arm')
    $m = "$Message"
    switch ($Kind) {
        'role'  { return [bool]($m -match '(?i)PrincipalNotFound|does not exist in the directory|AuthorizationFailed.*principal') }
        'graph' { return [bool]($m -match '(?i)HTTP 404|Request_ResourceNotFound|does not exist or one of its queried reference-property objects are not present') }
        'sql'   { return [bool]($m -match '(?i)\b18456\b|Login failed|token-identified principal|not yet valid|Cannot open server|transport-level error|timeout') }
        default { return [bool]($m -match '(?i)HTTP 409|OperationInProgress|AnotherOperationInProgress') }
    }
}

function Invoke-PimInstallWithRetry {
    <# Run -Action; on a -Kind retryable failure wait (-Waits seconds, bounded) and run it again. The last failure is thrown. #>
    param([Parameter(Mandatory)][scriptblock]$Action, [ValidateSet('role', 'graph', 'sql', 'arm')][string]$Kind = 'arm',
          [int[]]$Waits = @(15, 30, 30, 60, 60), [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$OnWait)
    $i = 0
    while ($true) {
        try { return (& $Action) }
        catch {
            $msg = "$($_.Exception.Message)"
            if ($i -ge $Waits.Count -or -not (Test-PimInstallRetryable -Message $msg -Kind $Kind)) { throw }
            if ($OnWait) { try { & $OnWait $Waits[$i] $msg } catch { } }
            & $Sleep $Waits[$i]; $i++
        }
    }
}

function Get-PimInstallSigninFrontWebIdentity {
    <#
      PURE. The Manager's web identity (the user-assigned managed identity the front's federated credential and its state
      use): exactly one attached = that one; several = the one the Manager container names (AZURE_CLIENT_ID /
      PIM_MI_CLIENT_ID / PIM_ManagedIdentityClientId), else refused. @{ ok; resourceId; name; clientId; principalId; reason }.
    #>
    param([Parameter(Mandatory)][object]$App)
    $ua = $null; if ($App.identity -and $App.identity.PSObject.Properties['userAssignedIdentities']) { $ua = $App.identity.userAssignedIdentities }
    $ids = @(if ($ua) { @($ua.PSObject.Properties | ForEach-Object { [pscustomobject]@{ id = "$($_.Name)"; clientId = "$($_.Value.clientId)"; principalId = "$($_.Value.principalId)" } }) })
    $mk = { param($x, $why) @{ ok = $true; resourceId = $x.id; name = (($x.id -split '/')[-1]); clientId = $x.clientId; principalId = $x.principalId; reason = $why } }
    if ($ids.Count -eq 0) { return @{ ok = $false; resourceId = ''; name = ''; clientId = ''; principalId = ''; reason = 'the PIM Manager has no user-assigned managed identity -- the deploy did not finish' } }
    if ($ids.Count -eq 1) { return (& $mk $ids[0] 'the one identity on the PIM Manager') }
    $named = ''
    foreach ($c in @($App.properties.template.containers)) {
        if (-not $c -or "$($c.name)" -eq 'signin-front') { continue }
        foreach ($e in @($c.env)) { if ($e -and "$($e.name)" -in 'AZURE_CLIENT_ID', 'PIM_MI_CLIENT_ID', 'PIM_ManagedIdentityClientId' -and "$($e.value)".Trim()) { $named = "$($e.value)".Trim() } }
    }
    $pick = @($ids | Where-Object { $named -and "$($_.clientId)" -eq $named }) | Select-Object -First 1
    if ($pick) { return (& $mk $pick 'the identity the PIM Manager container names') }
    return @{ ok = $false; resourceId = ''; name = ''; clientId = ''; principalId = ''; reason = "the PIM Manager carries $($ids.Count) identities and names none of them -- the web identity cannot be chosen" }
}

function Test-PimInstallSigninFrontLive {
    <#
      PURE. Is the install already ON the sign-in front with everything this step sets: a 'signin-front' container carrying
      SIGNIN_SQL_SERVER, SIGNIN_SQL_DATABASE, SIGNIN_KEYVAULT_KEY_ID and SIGNIN_UPSTREAM_SCOPE, and Easy Auth OFF.
      @{ live; complete; missing[] }.
    #>
    param([Parameter(Mandatory)][object]$App, [AllowNull()][object]$Auth)
    $fr = @(@($App.properties.template.containers) | Where-Object { $_ -and "$($_.name)" -eq 'signin-front' }) | Select-Object -First 1
    $eaOn = $false; if ($Auth -and $Auth.platform -and $Auth.platform.PSObject.Properties['enabled']) { $eaOn = [bool]$Auth.platform.enabled }
    if (-not $fr) { return @{ live = $false; complete = $false; missing = @('signin-front container') } }
    $miss = @('SIGNIN_SQL_SERVER', 'SIGNIN_SQL_DATABASE', 'SIGNIN_KEYVAULT_KEY_ID', 'SIGNIN_UPSTREAM_SCOPE' | Where-Object { $n = $_; -not @(@($fr.env) | Where-Object { $_ -and "$($_.name)" -eq $n -and "$($_.value)".Trim() }).Count })
    if ($eaOn) { $miss += 'Easy Auth still on' }
    return @{ live = (-not $eaOn); complete = ($miss.Count -eq 0); missing = @($miss) }
}

function Invoke-PimInstallSigninFront {
    <#
      The five steps. -Done = step ids already completed (resume). -OnStep { param($Id, $State, $Message) } reports each.
      -Io (scriptblocks; the real ones come from New-PimInstallSigninFrontIo):
        Arm    { param($Method, $Path, $Body, $ApiVersion) }      ARM; a 404 answers $null on GET
        Graph  { param($Method, $Path, $Body) }                   Microsoft Graph v1.0; a 404 answers $null on GET
        Sql    { param($Sql) }                                    one scalar from the PIM database (as the installer)
        Build  { param($ContextPath, $ImageName) } -> @{ ok; status; seconds; runId }
        TagCheck { param($LoginServer, $Tag) } -> 'true' | 'false' | 'unknown'
        Move   { param([hashtable]$MoveArgs) } -> the Set-PimManagerSigninFront.ps1 result (throws on a rolled-back move)
        Sleep  { param($Seconds) }
      Returns @{ ok; failedStep; reason; completed[]; keyVaultId; keyId; upstreamScope; frontImage }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$TenantId,
          [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$ManagerApp, [Parameter(Mandatory)][string]$AcrName,
          [Parameter(Mandatory)][string]$SqlDatabase, [Parameter(Mandatory)][string]$KeyVaultName, [Parameter(Mandatory)][string]$RepoRoot,
          [string]$UpdateJob = 'ca-pim-update', [string]$StateFile = '', [string[]]$Done = @(),
          [scriptblock]$OnStep, [Parameter(Mandatory)][hashtable]$Io, [string]$WorkDir = ([IO.Path]::GetTempPath()))
    $res = @{ ok = $false; failedStep = ''; reason = ''; completed = (New-Object System.Collections.Generic.List[string]); keyVaultId = ''; keyId = ''; upstreamScope = ''; frontImage = '' }
    $say = { param($id, $st, $msg) if ($OnStep) { try { & $OnStep $id $st $msg } catch { } } }
    $sleep = if ($Io.Sleep) { $Io.Sleep } else { { param($s) Start-Sleep -Seconds $s } }
    $kvApi = '2023-07-01'; $acaApi = '2024-03-01'; $authApi = '2022-04-01'
    $appPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$ManagerApp"
    $step = ''
    try {
        $app = & $Io.Arm 'GET' $appPath $null $acaApi
        if (-not $app) { throw "the PIM Manager app '$ManagerApp' was not found in $ResourceGroup" }
        $auth = $null; try { $a0 = & $Io.Arm 'GET' "$appPath/authConfigs/current" $null $acaApi; if ($a0) { $auth = $a0.properties } } catch { $auth = $null }
        $wi = Get-PimInstallSigninFrontWebIdentity -App $app
        if (-not $wi.ok) { throw $wi.reason }
        $mgr = @(@($app.properties.template.containers) | Where-Object { $_ -and "$($_.name)" -ne 'signin-front' }) | Select-Object -First 1
        $envOf = { param($c, $n) "$(@(@($c.env) | Where-Object { $_ -and "$($_.name)" -eq $n } | ForEach-Object { $_.value }) | Select-Object -First 1)".Trim() }
        $sqlServer = & $envOf $mgr 'PIM_SqlServer'
        if (-not $sqlServer) { throw 'the PIM Manager carries no PIM_SqlServer -- the front''s state has no database to live in' }
        $live = Test-PimInstallSigninFrontLive -App $app -Auth $auth
        if ($live.live -and $live.complete) {
            foreach ($id in $script:PimSfiStepIds) { & $say $id 'skipped' 'the PIM Manager already runs behind the sign-in front, with its state and the access token'; $res.completed.Add($id) | Out-Null }
            $res.ok = $true; $res.reason = 'already on the sign-in front'; return $res
        }

        # ---- 1. vault + key + role ---------------------------------------------------------------------------------------
        $step = 'signin-front-vault'
        $vaultPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.KeyVault/vaults/$KeyVaultName"
        $keyPath = "$vaultPath/keys/$($script:PimSfiKeyName)"
        if ($Done -contains $step) { & $say $step 'skipped' 'already done (resume)' }
        else {
            & $say $step 'started' "the install's own Key Vault $KeyVaultName and its key for the sign-in front"
            $vault = & $Io.Arm 'GET' $vaultPath $null $kvApi
            if (-not $vault) {
                $avail = & $Io.Arm 'POST' "/subscriptions/$SubscriptionId/providers/Microsoft.KeyVault/checkNameAvailability" @{ name = $KeyVaultName; type = 'Microsoft.KeyVault/vaults' } $kvApi
                if ($avail -and $avail.PSObject.Properties['nameAvailable'] -and -not [bool]$avail.nameAvailable) {
                    throw ("the Key Vault name '$KeyVaultName' is taken ($($avail.reason)) -- a deleted vault keeps its name for 90 days. " +
                           "Set another name in the answers (keyVaultName) and resume the installation")
                }
                $vault = & $Io.Arm 'PUT' $vaultPath (New-PimInstallKeyVaultBody -Location $Location -TenantId $TenantId) $kvApi
                for ($i = 0; $i -lt 36 -and "$($vault.properties.provisioningState)" -notin 'Succeeded', ''; $i++) { & $sleep 5; $vault = & $Io.Arm 'GET' $vaultPath $null $kvApi }
                if (-not $vault) { throw "the Key Vault $KeyVaultName was not created" }
            }
            if (-not [bool]$vault.properties.enableRbacAuthorization) { throw "the Key Vault $KeyVaultName does not use Azure RBAC -- the install's vault must (it was not made by this install)" }
            $key = & $Io.Arm 'GET' $keyPath $null $kvApi
            if (-not $key) { $key = & $Io.Arm 'PUT' $keyPath @{ properties = @{ kty = 'RSA'; keySize = 2048; keyOps = @('wrapKey', 'unwrapKey') } } $kvApi }
            if (-not $key) { throw "the key '$($script:PimSfiKeyName)' could not be created in $KeyVaultName" }
            $raName = Get-PimInstallKeyRoleAssignmentName -KeyPath $keyPath -PrincipalId $wi.principalId
            $raPath = "$keyPath/providers/Microsoft.Authorization/roleAssignments/$raName"
            $ra = & $Io.Arm 'GET' $raPath $null $authApi
            if (-not $ra) {
                $raBody = @{ properties = @{ roleDefinitionId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$($script:PimSfiCryptoUserRole)"; principalId = $wi.principalId; principalType = 'ServicePrincipal' } }
                [void](Invoke-PimInstallWithRetry -Kind 'role' -Sleep $sleep -Action { & $Io.Arm 'PUT' $raPath $raBody $authApi } -OnWait { param($s, $m) & $say $step 'waiting' "the web identity is not known to Azure yet -- waiting $s s" })
            }
            & $say $step 'ok' "Key Vault $KeyVaultName (RBAC, purge protection), key '$($script:PimSfiKeyName)', the web identity $($wi.name) may wrap and unwrap with it"
            $res.completed.Add($step) | Out-Null
        }
        $res.keyVaultId = $vaultPath
        $res.keyId = "https://$KeyVaultName.vault.azure.net/keys/$($script:PimSfiKeyName)"
        try { $k2 = & $Io.Arm 'GET' $keyPath $null $kvApi; if ($k2 -and "$($k2.properties.keyUri)".Trim()) { $res.keyId = "$($k2.properties.keyUri)".Trim() } } catch { }

        # ---- 2. the database ---------------------------------------------------------------------------------------------
        $step = 'signin-front-state'
        if ($Done -contains $step) { & $say $step 'skipped' 'already done (resume)' }
        else {
            & $say $step 'started' "the sign-in front's place in the PIM database (schema signin)"
            $sid = ConvertTo-PimSqlSidLiteral -ClientId $wi.clientId
            $q = $Io.Sql
            $read = { param($s) Invoke-PimInstallWithRetry -Kind 'sql' -Sleep $sleep -Action { & $q $s } -OnWait { param($w, $m) & $say $step 'waiting' "the database does not accept the sign-in yet -- waiting $w s" } }
            $user = "$(& $read "SELECT name FROM sys.database_principals WHERE sid = $sid")".Trim()
            $owner = "$(& $read "SELECT USER_NAME(principal_id) FROM sys.schemas WHERE name = N'signin'")".Trim()
            $grant = "$(& $read "SELECT COUNT(*) FROM sys.database_permissions p JOIN sys.database_principals u ON u.principal_id = p.grantee_principal_id WHERE u.sid = $sid AND p.permission_name = 'CREATE TABLE' AND p.state IN ('G','W')")".Trim()
            $plan = Get-PimInstallSigninFrontSqlPlan -User $user -Owner $owner -CreateTableGranted ($grant -and $grant -ne '0') -IdentityName $wi.name -Sid $sid
            foreach ($s in $plan) { [void](& $read $s) }
            $user = "$(& $read "SELECT name FROM sys.database_principals WHERE sid = $sid")".Trim()
            $owner = "$(& $read "SELECT USER_NAME(principal_id) FROM sys.schemas WHERE name = N'signin'")".Trim()
            $grant = "$(& $read "SELECT COUNT(*) FROM sys.database_permissions p JOIN sys.database_principals u ON u.principal_id = p.grantee_principal_id WHERE u.sid = $sid AND p.permission_name = 'CREATE TABLE' AND p.state IN ('G','W')")".Trim()
            if (-not $user -or $owner -ne $user -or -not $grant -or $grant -eq '0') { throw "read-back: database user '$user', schema signin owner '$owner', CREATE TABLE granted '$grant' -- not in place" }
            & $say $step 'ok' "database user [$user] owns the schema signin and may create its two tables -- no other right"
            $res.completed.Add($step) | Out-Null
        }

        # ---- 3. the registration: api://<id>, user_impersonation, self-grant -----------------------------------------------
        $step = 'signin-front-app'
        $clientId = "$($auth.identityProviders.azureActiveDirectory.registration.clientId)".Trim()
        if (-not $clientId) {
            $fr0 = @(@($app.properties.template.containers) | Where-Object { $_ -and "$($_.name)" -eq 'signin-front' }) | Select-Object -First 1
            if ($fr0) { $clientId = & $envOf $fr0 'SIGNIN_CLIENT_ID' }
        }
        if (-not $clientId) { throw 'the PIM Manager names no sign-in application (the deploy''s sign-in step did not finish)' }
        $res.upstreamScope = "api://$clientId/$($script:PimSfiScope)"
        if ($Done -contains $step) { & $say $step 'skipped' 'already done (resume)' }
        else {
            & $say $step 'started' 'the sign-in application: its own scope for the PIM Manager (access token, no secret)'
            $regR = Invoke-PimInstallWithRetry -Kind 'graph' -Sleep $sleep -Action { $r = & $Io.Graph 'GET' "/applications?`$filter=$([uri]::EscapeDataString("appId eq '$clientId'"))&`$select=id,appId,identifierUris,api" $null; $x = @($r.value | Where-Object { $_ })[0]; if (-not $x) { throw "HTTP 404 application $clientId not found yet" }; $x }
            $ap = Get-PimInstallSigninFrontAppPlan -AppReg $regR -ClientId $clientId
            if ($ap.body) { [void](& $Io.Graph 'PATCH' "/applications/$($regR.id)" $ap.body) }
            $sp = Invoke-PimInstallWithRetry -Kind 'graph' -Sleep $sleep -Action { $r = & $Io.Graph 'GET' "/servicePrincipals?`$filter=$([uri]::EscapeDataString("appId eq '$clientId'"))&`$select=id" $null; $x = @($r.value | Where-Object { $_ })[0]; if (-not $x) { throw "HTTP 404 service principal of $clientId not found yet" }; $x }
            $gs = & $Io.Graph 'GET' "/oauth2PermissionGrants?`$filter=$([uri]::EscapeDataString("clientId eq '$($sp.id)' and resourceId eq '$($sp.id)'"))" $null
            $grantObj = @(@($gs.value) | Where-Object { $_ -and "$($_.consentType)" -eq 'AllPrincipals' }) | Select-Object -First 1
            $scopeV = $script:PimSfiScope
            if (-not ($grantObj -and (" $($grantObj.scope) " -match " $scopeV "))) {
                # the scope just added may not be visible to the consent API for a moment: bounded retry on a refusal naming it
                [void](Invoke-PimInstallWithRetry -Kind 'graph' -Sleep $sleep -Action {
                    if ($grantObj) { & $Io.Graph 'PATCH' "/oauth2PermissionGrants/$($grantObj.id)" @{ scope = ("$($grantObj.scope) $scopeV").Trim() } }
                    else { & $Io.Graph 'POST' '/oauth2PermissionGrants' @{ clientId = $sp.id; consentType = 'AllPrincipals'; resourceId = $sp.id; scope = $scopeV } } })
            }
            & $say $step 'ok' "the sign-in application exposes api://$clientId/$($script:PimSfiScope), consented for the organisation"
            $res.completed.Add($step) | Out-Null
        }

        # ---- 4. the front image ------------------------------------------------------------------------------------------
        $step = 'signin-front-image'
        $pin = "$(Get-PimSigninFrontPinnedVersion -SolutionRoot (Join-Path $RepoRoot 'SOLUTIONS\PIM4EntraPS'))".Trim()
        if (-not $pin) { throw 'this release pins no sign-in front version (tools/pim-manager/signin-front.version)' }
        $loginServer = "$("$AcrName".ToLowerInvariant()).azurecr.io"
        $frontImage = Get-PimSigninFrontImageRef -LoginServer $loginServer -Version $pin
        $res.frontImage = $frontImage
        if ($Done -contains $step) { & $say $step 'skipped' 'already done (resume)' }
        else {
            & $say $step 'started' "the sign-in front image signin-front:$pin in this install's registry"
            $tp = 'unknown'; try { $tp = "$(& $Io.TagCheck $loginServer $pin)" } catch { $tp = 'unknown' }
            if ($tp -eq 'true') { & $say $step 'ok' "signin-front:$pin is already in the registry" }
            else {
                $ctxFile = Join-Path $WorkDir ("signin-front-ctx-{0}.tar.gz" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
                try {
                    $ctx = New-PimSigninFrontBuildContextFromFolder -RepoRoot $RepoRoot -OutFile $ctxFile
                    if (-not $ctx.ok) {
                        # a copy without the front's source: the move asks the install's updater to build it (one run)
                        $res.frontImage = ''
                        & $say $step 'ok' "not built here ($($ctx.reason)) -- the install's updater builds it in the next step"
                    } else {
                        $b = & $Io.Build $ctxFile "signin-front:$pin"
                        if (-not $b -or -not $b.ok) { throw "the sign-in front image was not built ($(if ($b) { $b.status } else { 'no answer' }))" }
                        try { [void](& $Io.Arm 'PATCHENV' "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$UpdateJob" @{ PIM_SIGNIN_FRONT_BUILT = $pin } $acaApi) } catch { }
                        & $say $step 'ok' "built signin-front:$pin in $($b.seconds) s from this release's source"
                    }
                } finally { Remove-Item -LiteralPath $ctxFile -Force -ErrorAction SilentlyContinue }
            }
            $res.completed.Add($step) | Out-Null
        }

        # ---- 5. the switch -----------------------------------------------------------------------------------------------
        $step = 'signin-front'
        & $say $step 'started' 'the PIM Manager moves behind the sign-in front (Easy Auth goes off only once the front answers)'
        $mv = @{ SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup; TenantId = $TenantId; ManagerApp = $ManagerApp
                 KeyVaultKeyId = $res.keyId; UpstreamScope = $res.upstreamScope; WebIdentityResourceId = $wi.resourceId; UpdateJob = $UpdateJob; Apply = $true }
        if ($res.frontImage) { $mv['FrontImage'] = $res.frontImage }
        if ("$StateFile".Trim()) { $mv['StateFile'] = "$StateFile".Trim() }
        [void](& $Io.Move $mv)
        $app2 = & $Io.Arm 'GET' $appPath $null $acaApi
        $auth2 = $null; try { $a2 = & $Io.Arm 'GET' "$appPath/authConfigs/current" $null $acaApi; if ($a2) { $auth2 = $a2.properties } } catch { }
        $chk = Test-PimInstallSigninFrontLive -App $app2 -Auth $auth2
        if (-not ($chk.live -and $chk.complete)) { throw "read-back after the switch: $($chk.missing -join ', ')" }
        & $say $step 'ok' 'the PIM Manager signs people in through the sign-in front (state in the database, keys wrapped by the install''s Key Vault, access token to the Manager); Easy Auth is off'
        $res.completed.Add($step) | Out-Null
        $res.ok = $true; $res.reason = 'on the sign-in front'
    } catch {
        $res.ok = $false; $res.failedStep = $(if ($step) { $step } else { 'signin-front-vault' })
        $res.reason = "$((("$($_.Exception.Message)") -split "`n")[0])"
        & $say $res.failedStep 'failed' $res.reason
    }
    return $res
}

function New-PimInstallSigninFrontIo {
    <#
      The real I/O for Invoke-PimInstallSigninFront: ARM / Graph over PIM-ArmSetup (the installer's own sign-in), the
      database as the signed-in installer (-SqlServerFqdn / -SqlDatabase), the registry build over PIM-AcrBuild, the move
      by Set-PimManagerSigninFront.ps1 in THIS session (its REST session is the installer's). The caller loads PIM-ArmSetup,
      PIM-AcrBuild, PIM-SqlStore and PIM-SigninFrontImage at ITS file scope (Install-PimManager does).
      🪤 NO GetNewClosure(): a closure is bound to a module of its own and does not see the installer's dot-sourced
      functions (Invoke-PimSetupArm, ...). Each block reads its context from $Io.Ctx -- $Io being the hashtable
      Invoke-PimInstallSigninFront receives, found through the call chain when the block runs there.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$TenantId,
          [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SqlServerFqdn, [Parameter(Mandatory)][string]$SqlDatabase,
          [Parameter(Mandatory)][string]$SetupDir)
    return @{
        Ctx = @{ sub = $SubscriptionId; rg = $ResourceGroup; acr = $AcrName; fqdn = $SqlServerFqdn; db = $SqlDatabase; tid = $TenantId; sd = $SetupDir }
        Arm = {
            param($Method, $Path, $Body, $ApiVersion)
            if ($Method -eq 'PATCHENV') { return (Set-PimArmAcaJobEnvVars -SubscriptionId $Io.Ctx.sub -ResourceGroup $Io.Ctx.rg -Name (($Path -split '/')[-1]) -Env $Body) }
            if ($Method -eq 'GET') { return (Invoke-PimSetupArm -Path $Path -ApiVersion $ApiVersion -NotFoundOk) }
            return (Invoke-PimSetupArm -Method $Method -Path $Path -Body $Body -ApiVersion $ApiVersion)
        }
        Graph = {
            param($Method, $Path, $Body)
            # a filtered list answers { value = @(...) } -- the shape the step reads -- whatever paging PIM-Rest did
            if ($Method -eq 'GET' -and $Path -match '\?\$filter=') { return @{ value = @(Invoke-PimSetupGraph -Path $Path -All -NotFoundOk | Where-Object { $_ }) } }
            if ($Method -eq 'GET') { return (Invoke-PimSetupGraph -Path $Path -NotFoundOk) }
            return (Invoke-PimSetupGraph -Method $Method -Path $Path -Body $Body)
        }
        Sql = {
            param($Sql)
            $tok = "$(Get-PimRestToken -Resource 'https://database.windows.net' -TenantId $Io.Ctx.tid)".Trim()
            $c = New-Object (Resolve-PimSqlClientType).FullName "Server=tcp:$($Io.Ctx.fqdn),1433;Database=$($Io.Ctx.db);Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;Pooling=False"
            $c.AccessToken = $tok
            try { $c.Open(); $cmd = $c.CreateCommand(); $cmd.CommandText = $Sql; $cmd.CommandTimeout = 60; return "$($cmd.ExecuteScalar())" } finally { try { $c.Close() } catch { } }
        }
        Build = {
            param($ContextPath, $ImageName)
            Invoke-PimAcrRestBuild -SubscriptionId $Io.Ctx.sub -ResourceGroup $Io.Ctx.rg -RegistryName $Io.Ctx.acr -ContextPath $ContextPath -ImageNames @($ImageName) -DockerFilePath 'Dockerfile'
        }
        TagCheck = { param($LoginServer, $Tag) Test-PimSigninFrontImagePresent -LoginServer $LoginServer -Tag $Tag }
        Move = { param([hashtable]$MoveArgs) & (Join-Path $Io.Ctx.sd 'Set-PimManagerSigninFront.ps1') @MoveArgs }
        Sleep = { param($s) Start-Sleep -Seconds $s }
    }
}