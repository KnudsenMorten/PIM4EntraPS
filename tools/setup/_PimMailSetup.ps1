# _PimMailSetup.ps1 -- the pieces behind Initialize-PimMailSender.ps1 and Set-PimSmtpRelayPassword.ps1: which way the
# script signs in, the BROWSER sign-in itself, and a per-API token cache. Dot-source it; it defines functions only (no
# side effects on load).
#
# MAIL-1 (framework DOCS/REQUIREMENTS.md 12.3, owner 2026-10-08): "we dont use certificates here, either interactive login
# or secret. not certificates". So the published scripts sign in in the BROWSER (an Exchange or Global Administrator) or
# with the Invardia Support app's secret; a certificate stays accepted for old callers and is never what a page prints.
#
# NO MODULES (owner 2026-10-07: "neither pim, si or invardia must have dependencies"): plain Invoke-RestMethod + .NET.
# Sign-in is auth code + PKCE on a localhost loopback, Microsoft Edge launched explicitly (the default browser when Edge
# is missing) -- the pattern of _PimEnginePermissions.ps1 (Get-PimEpInteractiveToken), DUPLICATED here on purpose: each
# published script is ONE standalone file (tools/setup/Build-PimSupportScripts.ps1 inlines this), and isolation beats
# DRY between two scripts that ship separately. Never device code.
#
# The public clients (first-party, present in every tenant, no app registration needed):
#   * Exchange Online admin API -- "Microsoft Exchange REST API Based Powershell", the client the ExchangeOnlineManagement
#     V3 module itself signs in with; the token is for https://outlook.office365.com and drives the same
#     /adminapi/beta/<tenant>/InvokeCommand endpoint the module calls.
#   * Microsoft Graph -- "Microsoft Graph Command Line Tools" (as Grant-PimEnginePermissions.ps1).
#   * Azure Resource Manager, Azure SQL, Key Vault -- "Microsoft Azure PowerShell"; one sign-in, the other two from its
#     refresh token (the client is pre-authorised for all three).

# ---- constants --------------------------------------------------------------------------------------------------------
function Get-PimMsExchangeClientId { 'fb78d390-0c51-40cd-8e17-fdbfab77341b' }        # Microsoft Exchange REST API Based Powershell
function Get-PimMsGraphCliClientId { '14d82eec-204b-4c2f-b7e8-296a70dab67e' }        # Microsoft Graph Command Line Tools
function Get-PimMsAzurePowerShellClientId { '1950a258-227b-4e31-a9cf-717495945fc2' } # Microsoft Azure PowerShell
# The delegated Graph rights the shared-mailbox setup reads / changes with: the Exchange plan (subscribedSkus) and the
# initial domain (organization), the service principals (managed identities, Graph), the mailbox's directory user, and
# the removal of a tenant-wide Mail.Send consent (the scope rule of MAIL-1).
function Get-PimMsGraphScopes { @('Organization.Read.All', 'Application.Read.All', 'AppRoleAssignment.ReadWrite.All', 'User.Read.All') }

# ---- which way to sign in (PURE) ----------------------------------------------------------------------------------------
function Resolve-PimMailSetupAuthMode {
    <#
      Decide how the setup script authenticates, BEFORE anything is touched. Returns @{ mode; reason } where mode is
      'browser' | 'secret' | 'certificate' | 'signedIn' and a non-empty reason is a refusal:
        * nothing passed                       -> 'browser' (the person signs in; -AdminAppId is not needed)
        * -AdminSecret (+ -AdminAppId)         -> 'secret'  (the Invardia Support app)
        * -AdminCertThumbprint (+ -AdminAppId) -> 'certificate' (back-compat; never printed)
        * -UseSignedInAccount                  -> 'signedIn' (the signed-in az session)
      Refused: both a secret and a certificate; -UseSignedInAccount with a credential; a credential without -AdminAppId;
      -AdminAppId without a credential (ambiguous: was a secret forgotten?).
    #>
    param([string]$AdminAppId, [string]$AdminSecret, [string]$AdminCertThumbprint, [switch]$UseSignedInAccount)
    $app = "$AdminAppId".Trim(); $sec = "$AdminSecret".Trim(); $cert = "$AdminCertThumbprint".Trim()
    if ($sec -and $cert) { return @{ mode = ''; reason = 'pass EITHER -AdminSecret OR -AdminCertThumbprint, not both.' } }
    if ($UseSignedInAccount) {
        if ($sec -or $cert) { return @{ mode = ''; reason = '-UseSignedInAccount takes no -AdminSecret / -AdminCertThumbprint.' } }
        return @{ mode = 'signedIn'; reason = '' }
    }
    if ($sec -or $cert) {
        if (-not $app) { return @{ mode = ''; reason = '-AdminAppId is required with -AdminSecret / -AdminCertThumbprint (the app the credential belongs to).' } }
        return @{ mode = $(if ($sec) { 'secret' } else { 'certificate' }); reason = '' }
    }
    if ($app) { return @{ mode = ''; reason = "-AdminAppId $app was passed without its credential: add -AdminSecret (the Invardia Support app's secret), or leave -AdminAppId out to sign in in the browser." } }
    return @{ mode = 'browser'; reason = '' }
}

function Test-PimMsInteractiveHost {
    # A browser sign-in needs a person at this console. An unattended run (a deploy step, a scheduled task, a redirected
    # stdin) must be REFUSED instead -- it would otherwise open a browser nobody sees and wait five minutes.
    try { if (-not [Environment]::UserInteractive) { return $false } } catch { }
    try { if ([Console]::IsInputRedirected) { return $false } } catch { }
    return $true
}

function Get-PimMsExoAnchor {
    # X-AnchorMailbox for the Exchange admin API: the signed-in person's own UPN with a delegated token, the system
    # mailbox of the initial domain with an app-only one (what the EXO V3 module sends in each case).
    param([string]$Mode, [string]$Upn, [string]$InitialDomain)
    if ($Mode -eq 'browser' -and "$Upn".Trim()) { return "UPN:$("$Upn".Trim())" }
    return "UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@$("$InitialDomain".Trim())"
}

# ---- browser sign-in --------------------------------------------------------------------------------------------------
function ConvertTo-PimMsB64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# The claims of a JWT (no signature check; only tid / upn / exp are read). $null when not a readable JWT.
function ConvertFrom-PimMsJwtClaims {
    param([AllowEmptyString()][string]$Token)
    if (-not $Token) { return $null }
    $parts = $Token -split '\.'
    if ($parts.Count -lt 2) { return $null }
    $s = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    try { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) | ConvertFrom-Json } catch { $null }
}

function New-PimMsPkcePair {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $verifier = ConvertTo-PimMsB64Url $bytes
    $challenge = ConvertTo-PimMsB64Url ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))
    [pscustomobject]@{ Verifier = $verifier; Challenge = $challenge }
}

# The delegated scope string: bare Graph names are qualified, OIDC basics appended once.
function Get-PimMsScopeString {
    param([Parameter(Mandatory)][string[]]$Scopes)
    $q = @($Scopes | Where-Object { $_ } | ForEach-Object { if ($_ -match '^(https?://|openid$|profile$|offline_access$)') { $_ } else { "https://graph.microsoft.com/$_" } })
    (@($q) + @('openid', 'profile', 'offline_access') | Select-Object -Unique) -join ' '
}

function New-PimMsAuthorizeUrl {
    param(
        [Parameter(Mandatory)][string]$Tenant, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$RedirectUri,
        [Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$State, [Parameter(Mandatory)][string]$CodeChallenge,
        [string]$LoginHint
    )
    $u = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/authorize" +
        "?client_id=$ClientId&response_type=code&response_mode=query" +
        "&redirect_uri=$([uri]::EscapeDataString($RedirectUri))" +
        "&scope=$([uri]::EscapeDataString($Scope))&state=$State" +
        "&code_challenge=$CodeChallenge&code_challenge_method=S256"
    if ($LoginHint) { $u += "&login_hint=$([uri]::EscapeDataString($LoginHint))" } else { $u += '&prompt=select_account' }
    $u
}

function Get-PimMsEdgePath {
    @(
        $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe' }),
        $(if ($env:ProgramFiles) { Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe' }),
        $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\Application\msedge.exe' })
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}

function Get-PimMsSignInFailureHint {
    # PURE: one sentence for a sign-in error the person can act on ('' when there is nothing specific to say).
    param([string]$ErrorText)
    $e = "$ErrorText"
    if ($e -match 'AADSTS50011|redirect') { return 'This tenant refuses the local sign-in answer address for this Microsoft client. Run the script with the Invardia Support app instead: -AdminAppId <support app id> -AdminSecret <its secret>.' }
    if ($e -match 'AADSTS65001|consent') { return 'The sign-in needs an administrator''s consent: sign in as a Global Administrator once, or run with the Invardia Support app (-AdminAppId + -AdminSecret).' }
    if ($e -match 'AADSTS50105|AADSTS50020|not assigned|does not exist in tenant') { return 'Sign in with an account of THIS tenant (an Exchange Administrator or Global Administrator).' }
    return ''
}

# Interactive sign-in: auth code + PKCE on a loopback TcpListener (works without elevation), Edge launched explicitly,
# the default browser when Edge is missing. Returns the token response (access_token, refresh_token, expires_in).
function Get-PimMsInteractiveToken {
    param(
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string[]]$Scopes,
        [string]$Tenant = 'organizations',
        [bool]$UseEdge = $true,
        [string]$LoginHint,
        [string]$What = 'sign-in'
    )
    $pkce  = New-PimMsPkcePair
    $state = [guid]::NewGuid().ToString('N')
    $scope = Get-PimMsScopeString -Scopes $Scopes
    $tcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $tcp.Start()
    $redirect = "http://localhost:$(([System.Net.IPEndPoint]$tcp.LocalEndpoint).Port)/"
    $authUrl  = New-PimMsAuthorizeUrl -Tenant $Tenant -ClientId $ClientId -RedirectUri $redirect -Scope $scope -State $state -CodeChallenge $pkce.Challenge -LoginHint $LoginHint
    $query = $null
    try {
        $edge = if ($UseEdge) { Get-PimMsEdgePath } else { $null }
        Write-Host "Signing in for $What -- the browser answers to $redirect ..." -ForegroundColor Yellow
        if ($edge) { Start-Process -FilePath $edge -ArgumentList @('--new-window', $authUrl) -WhatIf:$false }
        else {
            if ($UseEdge) { Write-Host 'Microsoft Edge not found -- using the default browser.' -ForegroundColor DarkYellow }
            Start-Process $authUrl -WhatIf:$false
        }
        Write-Host "If no browser opened, open this address yourself:`n  $authUrl" -ForegroundColor DarkGray
        $deadline = (Get-Date).AddMinutes(5)
        while (-not $query) {
            if ((Get-Date) -gt $deadline) { throw 'Timed out (5 minutes) waiting for the browser to finish the sign-in.' }
            if (-not $tcp.Pending()) { Start-Sleep -Milliseconds 200; continue }
            $client = $tcp.AcceptTcpClient()
            try {
                $stream      = $client.GetStream()
                $requestLine = (New-Object System.IO.StreamReader($stream)).ReadLine()
                $html   = '<html><body style="font-family:sans-serif"><h3>Sign-in complete.</h3>You can close this tab and return to PowerShell.</body></html>'
                $writer = New-Object System.IO.StreamWriter($stream)
                $writer.Write("HTTP/1.1 200 OK`r`nContent-Type: text/html`r`nContent-Length: $($html.Length)`r`nConnection: close`r`n`r`n$html")
                $writer.Flush()
                if ($requestLine -match '^GET /\?(\S+) HTTP') { $query = $Matches[1] }
            } finally { $client.Close() }
        }
    } finally { $tcp.Stop() }
    $kv = @{}
    foreach ($pair in ($query -split '&')) {
        $k, $v = $pair -split '=', 2
        $kv[$k] = if ($null -ne $v) { [uri]::UnescapeDataString(($v -replace '\+', ' ')) } else { '' }
    }
    if ($kv['error']) {
        $hint = Get-PimMsSignInFailureHint -ErrorText "$($kv['error']) $($kv['error_description'])"
        throw "Sign-in failed: $($kv['error']) -- $($kv['error_description'])$(if ($hint) { " $hint" })"
    }
    if ($kv['state'] -ne $state) { throw 'The browser answer did not come from this sign-in attempt. Close ALL browser windows and run the script again.' }
    if (-not $kv['code'])        { throw 'The browser answer carried no authorization code.' }
    Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id     = $ClientId
        grant_type    = 'authorization_code'
        code          = $kv['code']
        redirect_uri  = $redirect
        code_verifier = $pkce.Verifier
        scope         = $scope
    }
}

# A token for another resource (or a fresh one) from a refresh token of the same public client -- no second browser tab.
function Get-PimMsRefreshedToken {
    param([Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$RefreshToken, [Parameter(Mandatory)][string[]]$Scopes, [string]$Tenant = 'organizations')
    Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id = $ClientId; grant_type = 'refresh_token'; refresh_token = $RefreshToken; scope = (Get-PimMsScopeString -Scopes $Scopes)
    }
}

# ---- the per-API token cache -------------------------------------------------------------------------------------------
function Get-PimMsBrowserApi {
    <#
      PURE: which public client + scopes serve a resource, and which sign-in it shares.
      Returns @{ api; clientId; scopes; family } -- family is the refresh-token group: 'azure' covers ARM, SQL and Key
      Vault (one sign-in), 'graph' and 'exchange' have their own.
    #>
    param([Parameter(Mandatory)][string]$Resource)
    $r = "$Resource".Trim().TrimEnd('/').ToLowerInvariant()
    switch -regex ($r) {
        '^(graph|https://graph\.microsoft\.com)$'          { return @{ api = 'graph'; clientId = (Get-PimMsGraphCliClientId); scopes = @(Get-PimMsGraphScopes); family = 'graph' } }
        '^(exchange|https://outlook\.office365\.com)$'     { return @{ api = 'exchange'; clientId = (Get-PimMsExchangeClientId); scopes = @('https://outlook.office365.com/.default'); family = 'exchange' } }
        '^(arm|https://management\.azure\.com)$'           { return @{ api = 'arm'; clientId = (Get-PimMsAzurePowerShellClientId); scopes = @('https://management.azure.com/.default'); family = 'azure' } }
        '^(sql|https://database\.windows\.net)$'           { return @{ api = 'sql'; clientId = (Get-PimMsAzurePowerShellClientId); scopes = @('https://database.windows.net/.default'); family = 'azure' } }
        '^(keyvault|https://vault\.azure\.net)$'           { return @{ api = 'keyvault'; clientId = (Get-PimMsAzurePowerShellClientId); scopes = @('https://vault.azure.net/.default'); family = 'azure' } }
    }
    throw "no browser sign-in is defined for '$Resource'"
}

function Get-PimMsBrowserToken {
    <#
      An access token for -Resource as the person who signed in, cached per API for the run. The first call of a family
      opens the browser (the next ones carry the first sign-in's account as the login hint, so the browser does not ask
      again); a family's other APIs and an expiring token are served from its refresh token.
      Test seam: $script:PimMsAcquire = { param($ClientId, $Scopes, $Tenant, $LoginHint, $RefreshToken) <token response> }.
    #>
    param([Parameter(Mandatory)][string]$Resource, [Parameter(Mandatory)][string]$TenantId)
    if (-not $script:PimMsTokens) { $script:PimMsTokens = @{} }
    if (-not $script:PimMsRefresh) { $script:PimMsRefresh = @{} }
    $spec = Get-PimMsBrowserApi -Resource $Resource
    $now = (Get-Date).ToUniversalTime()
    $hit = $script:PimMsTokens[$spec.api]
    if ($hit -and $hit.expires -gt $now.AddMinutes(5)) { return $hit.token }
    $acquire = $script:PimMsAcquire
    $rt = $script:PimMsRefresh[$spec.family]
    $resp = $null
    if ($rt) {
        try {
            $resp = if ($acquire) { & $acquire $spec.clientId $spec.scopes $TenantId $script:PimMsLoginHint $rt }
                    else { Get-PimMsRefreshedToken -ClientId $spec.clientId -RefreshToken $rt -Scopes $spec.scopes -Tenant $TenantId }
        } catch { $resp = $null }
    }
    if (-not $resp) {
        if (-not $acquire -and -not (Test-PimMsInteractiveHost)) { throw 'a browser sign-in needs a person at this console, and this session is not interactive -- run the command in a PowerShell window, or pass -AdminAppId + -AdminSecret (the Invardia Support app).' }
        $what = switch ($spec.family) { 'graph' { 'Microsoft Graph' } 'exchange' { 'Exchange Online' } default { 'Azure' } }
        $resp = if ($acquire) { & $acquire $spec.clientId $spec.scopes $TenantId $script:PimMsLoginHint $null }
                else { Get-PimMsInteractiveToken -ClientId $spec.clientId -Scopes $spec.scopes -Tenant $TenantId -LoginHint $script:PimMsLoginHint -What $what }
    }
    $tok = "$($resp.access_token)"
    if (-not $tok) { throw "the sign-in returned no access token for $($spec.api)" }
    $claims = ConvertFrom-PimMsJwtClaims -Token $tok
    if ($claims -and "$($claims.tid)".Trim() -and "$($claims.tid)".Trim() -ine "$TenantId".Trim()) {
        throw "you signed in to tenant $($claims.tid), not $TenantId -- sign in with an account of the tenant this environment runs in."
    }
    if ($claims -and -not $script:PimMsLoginHint) {
        $u = "$(if ($claims.upn) { $claims.upn } elseif ($claims.preferred_username) { $claims.preferred_username } else { $claims.unique_name })".Trim()
        if ($u) { $script:PimMsLoginHint = $u }
    }
    if ("$($resp.refresh_token)".Trim()) { $script:PimMsRefresh[$spec.family] = "$($resp.refresh_token)" }
    $secs = 3000; try { if ([int]$resp.expires_in -gt 0) { $secs = [int]$resp.expires_in } } catch { }
    $script:PimMsTokens[$spec.api] = @{ token = $tok; expires = $now.AddSeconds($secs) }
    return $tok
}

function Get-PimMsSignedInUpn {
    # The person who signed in (the first token's upn), '' before any sign-in.
    "$($script:PimMsLoginHint)".Trim()
}

function Get-PimMsAppToken {
    # An app-only token for -Resource as the Invardia Support app (client credentials, its secret). No module.
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$ClientSecret, [Parameter(Mandatory)][string]$Resource)
    $spec = Get-PimMsBrowserApi -Resource $Resource
    $scope = (@($spec.scopes) | Where-Object { $_ -match '^https://' } | Select-Object -First 1)
    if (-not $scope) { $scope = 'https://graph.microsoft.com/.default' }
    $scope = ($scope -replace '/[^/]+$', '/.default')
    (Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id = $ClientId; client_secret = $ClientSecret; grant_type = 'client_credentials'; scope = $scope }).access_token
}

# ---- the SMTP relay password in Key Vault (PURE pieces; Set-PimSmtpRelayPassword.ps1 does the calls) -------------------
function Get-PimKvRoleId {
    # Built-in Azure roles by name (the ids are the same in every tenant).
    param([Parameter(Mandatory)][ValidateSet('SecretsUser', 'SecretsOfficer')][string]$Role)
    switch ($Role) { 'SecretsUser' { '4633458b-17de-408a-b874-0445c86b69e6' } 'SecretsOfficer' { 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' } }
}

function Select-PimKvVault {
    # PURE: the ONE vault called -Name in a subscription's vault list (ARM value[]), or @{ vault = $null; reason }.
    param([object[]]$Vaults = @(), [Parameter(Mandatory)][string]$Name)
    $hits = @(@($Vaults) | Where-Object { $_ -and "$($_.name)" -ieq "$Name".Trim() })
    if ($hits.Count -eq 1) { return @{ vault = $hits[0]; reason = '' } }
    if ($hits.Count -gt 1) { return @{ vault = $null; reason = "more than one Key Vault is called $Name -- refusing to pick one" } }
    return @{ vault = $null; reason = "no Key Vault called $Name in this subscription" }
}

function Get-PimKvSecretScope {
    # PURE: the Azure RBAC scope of ONE secret -- the read right is granted on the secret, never on the whole vault.
    param([Parameter(Mandatory)][string]$VaultId, [Parameter(Mandatory)][string]$SecretName)
    "$("$VaultId".TrimEnd('/'))/secrets/$SecretName"
}

function New-PimKvRoleAssignmentRequest {
    # PURE: the ARM PUT of one role assignment (deterministic name per scope + principal + role, so a re-run is the same
    # request and ARM answers "already exists" instead of creating a second one).
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$RoleId,
          [Parameter(Mandatory)][string]$PrincipalId, [ValidateSet('ServicePrincipal', 'User', 'Group')][string]$PrincipalType = 'ServicePrincipal')
    $md5 = [Security.Cryptography.MD5]::Create()
    $bytes = $md5.ComputeHash([Text.Encoding]::UTF8.GetBytes(("{0}|{1}|{2}" -f $Scope.ToLowerInvariant(), $PrincipalId.ToLowerInvariant(), $RoleId.ToLowerInvariant())))
    $name = ([guid]::new($bytes)).ToString()
    @{
        path = "$Scope/providers/Microsoft.Authorization/roleAssignments/$name`?api-version=2022-04-01"
        body = @{ properties = @{ roleDefinitionId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$RoleId"; principalId = $PrincipalId; principalType = $PrincipalType } }
    }
}
