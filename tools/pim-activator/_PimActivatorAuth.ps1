# _PimActivatorAuth.ps1 -- shared Microsoft Graph sign-in for the pim-activator deploy scripts. Dot-source from a
# sibling script; defines functions only (no side effects on load).
#
# NO MODULES (owner 2026-10-07: "neither pim, si or invardia must have dependencies"): plain REST + .NET, nothing from
# the PowerShell Gallery. The token lives in a script variable ($script:PaGraphToken, see _PimActivatorBackend.ps1) and
# every Graph call goes through Invoke-PaGraph. Three ways in:
#   * Interactive: browser sign-in, auth code + PKCE on a localhost loopback (the first-party "Microsoft Graph Command
#     Line Tools" public client, so no extra app registration). Edge is launched explicitly -- servers whose default
#     browser is legacy Internet Explorer mangle the redirect -- with the system default browser as the fallback when
#     Edge is not installed.
#   * App-only: -AppId + -CertificateThumbprint + -TenantId. The token is minted here: client_credentials with an RS256
#     client assertion signed by the certificate (Cert:\CurrentUser\My or Cert:\LocalMachine\My). Windows PowerShell
#     5.1 and PowerShell 7.
#   * A token you already have (-AccessToken), for automation.
# Also used by Deploy-PimActivatorClient.ps1 for its version banner only.

# VERSION lives at the PIM4EntraPS solution root, two levels up from tools/pim-activator/. A standalone (built) copy
# has no VERSION file next to it: then the version is read from the header line the build writes into the file.
function Get-PimActivatorSolutionVersion {
    $f = Join-Path $PSScriptRoot '..\..\VERSION'
    if (Test-Path -LiteralPath $f) { return 'v' + (Get-Content -LiteralPath $f -TotalCount 1).Trim() }
    foreach ($self in @($PSCommandPath, $MyInvocation.ScriptName) | Where-Object { $_ }) {
        try {
            $head = @(Get-Content -LiteralPath $self -TotalCount 5 -ErrorAction Stop)
            foreach ($l in $head) { if ($l -match '^# PIM Manager (\S+) --') { return 'v' + $Matches[1] + ' (standalone)' } }
        } catch { }
    }
    '(VERSION file not found)'
}

# Troubleshooting banner: script + solution version and the PowerShell runtime. -GraphModules / -AzModules are still
# accepted for scripts that use those modules on an optional path (Deploy-PimActivatorClient.ps1); they are REPORTED
# (installed version or "not installed"), never loaded. -GraphOptional is accepted for compatibility and changes
# nothing any more -- nothing here can fail on a missing module.
function Show-PimActivatorBanner {
    param(
        [Parameter(Mandatory)][string]$ScriptName,
        [string[]]$GraphModules,
        [string[]]$AzModules,
        [switch]$GraphOptional
    )
    Write-Host "$ScriptName -- PIM4EntraPS $(Get-PimActivatorSolutionVersion)" -ForegroundColor Cyan
    foreach ($m in @(@($GraphModules) + @($AzModules) | Where-Object { $_ })) {
        $mod = Get-Module -Name $m -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $mod) { $mod = Get-Module -ListAvailable -Name $m -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1 }
        $v = if ($mod) { "v$($mod.Version)" } else { 'not installed' }
        Write-Host ("{0,-11}: {1}" -f $m, $v) -ForegroundColor Cyan
    }
    Write-Host "PowerShell : $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))" -ForegroundColor Cyan
}

# The guidance shown whenever a host cannot complete the sign-in.
function Get-PaBrokenAuthHelp {
    @"
This host cannot complete the sign-in. Known causes + fixes, in order of likelihood:
  1. The system default browser is legacy Internet Explorer, which mangles the auth redirect. This script launches Microsoft Edge explicitly (-UseEdge, the default); if you passed -UseEdge:`$false, drop it. To fix the host itself: Settings > Default apps > set Microsoft Edge as default for HTTP/HTTPS.
  2. Stale pending sign-in tabs answering the listener with an old state: close ALL browser windows, retry once.
  3. Something on this host blocks the localhost listener the browser answers to (a local firewall or proxy rule for 127.0.0.1): allow it, or run this script from another machine where sign-in works (it only talks to Microsoft Graph -- nothing tenant-side requires this host).
  4. Bring a token: sign in somewhere that works, mint a Microsoft Graph access token with Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All and DelegatedPermissionGrant.ReadWrite.All, and pass it with -AccessToken <token> (valid ~1 hour).
"@
}

# base64url (RFC 7515 section 2): no padding, URL-safe alphabet.
function ConvertTo-PaB64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}
function ConvertFrom-PaB64Url {
    param([Parameter(Mandatory)][string]$Text)
    $s = $Text.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    [Convert]::FromBase64String($s)
}

# The claims of a JWT (no signature check -- Graph checks it; we only read tid/upn/wids/scp/roles/exp). $null when the
# string is not a readable JWT (an opaque token, or garbage).
function ConvertFrom-PaJwtClaims {
    param([AllowEmptyString()][string]$Token)
    if (-not $Token) { return $null }
    $parts = $Token -split '\.'
    if ($parts.Count -lt 2) { return $null }
    try { [Text.Encoding]::UTF8.GetString((ConvertFrom-PaB64Url $parts[1])) | ConvertFrom-Json } catch { $null }
}

# Seconds since the Unix epoch (5.1-safe: no DateTimeOffset.ToUnixTimeSeconds dependency on the caller).
function Get-PaUnixTime {
    param([datetime]$Utc = [datetime]::UtcNow)
    if ($Utc.Kind -eq [DateTimeKind]::Unspecified) { $Utc = [datetime]::SpecifyKind($Utc, [DateTimeKind]::Utc) }
    [long][Math]::Floor(($Utc.ToUniversalTime() - (New-Object datetime(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc))).TotalSeconds)
}

# Store a Graph access token as THE session token: claims decoded, expiry noted, renewal recipe kept. -Refresh is a
# plain hashtable (no scriptblock closures -- those cannot see this file's functions): @{ Kind = 'AppOnly'; TenantId;
# ClientId; Thumbprint } or @{ Kind = 'RefreshToken'; RefreshToken; Tenant; Scopes }. None = cannot be renewed (a token
# passed with -AccessToken).
function Set-PaGraphSession {
    param(
        [Parameter(Mandatory)][string]$AccessToken,
        [ValidateSet('Interactive', 'AppOnly', 'ProvidedToken')][string]$AuthType = 'ProvidedToken',
        [int]$ExpiresInSeconds = 0,
        [hashtable]$Refresh
    )
    $script:PaGraphToken  = $AccessToken
    $script:PaTokenClaims = ConvertFrom-PaJwtClaims $AccessToken
    $script:PaAuthType    = $AuthType
    $exp = $null
    if ($script:PaTokenClaims -and $script:PaTokenClaims.PSObject.Properties['exp']) { $exp = (New-Object datetime(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)).AddSeconds([double]$script:PaTokenClaims.exp) }
    elseif ($ExpiresInSeconds -gt 0) { $exp = [datetime]::UtcNow.AddSeconds($ExpiresInSeconds) }
    $script:PaGraphTokenExpiresUtc = $exp
    $script:PaGraphTokenRefresh    = $Refresh
}

# Renew the session token from its recipe (called by Get-PaGraphAccessToken when the token is about to expire).
function Update-PaGraphSession {
    $r = $script:PaGraphTokenRefresh
    if (-not $r) { return }
    switch ($r.Kind) {
        'AppOnly' {
            $tok = Get-PaAppOnlyToken -TenantId $r.TenantId -ClientId $r.ClientId -CertificateThumbprint $r.Thumbprint
            Set-PaGraphSession -AccessToken "$($tok.access_token)" -AuthType AppOnly -ExpiresInSeconds ([int]"0$($tok.expires_in)") -Refresh $r
        }
        'RefreshToken' {
            $tok = Get-PaRefreshedToken -RefreshToken $r.RefreshToken -Tenant $r.Tenant -Scopes $r.Scopes
            if ($tok.refresh_token) { $r.RefreshToken = "$($tok.refresh_token)" }
            Set-PaGraphSession -AccessToken "$($tok.access_token)" -AuthType Interactive -ExpiresInSeconds ([int]"0$($tok.expires_in)") -Refresh $r
        }
    }
}

# PKCE verifier + S256 challenge (RFC 7636).
function New-PaPkcePair {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $verifier = ConvertTo-PaB64Url $bytes
    $challenge = ConvertTo-PaB64Url ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))
    [pscustomobject]@{ Verifier = $verifier; Challenge = $challenge }
}

# The Graph delegated scope string: bare names are qualified with the Graph resource, OIDC basics appended once.
function Get-PaDelegatedScopeString {
    param([Parameter(Mandatory)][string[]]$Scopes)
    $q = @($Scopes | Where-Object { $_ } | ForEach-Object {
        if ($_ -match '^(https?://|openid$|profile$|offline_access$|email$)') { $_ } else { "https://graph.microsoft.com/$_" }
    })
    (@($q) + @('openid', 'profile', 'offline_access') | Select-Object -Unique) -join ' '
}

# The authorize URL for the loopback auth-code + PKCE flow (pure, unit-tested).
function New-PaAuthorizeUrl {
    param(
        [Parameter(Mandatory)][string]$Tenant,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$RedirectUri,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$State,
        [Parameter(Mandatory)][string]$CodeChallenge
    )
    "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/authorize" +
        "?client_id=$ClientId&response_type=code&response_mode=query" +
        "&redirect_uri=$([uri]::EscapeDataString($RedirectUri))" +
        "&scope=$([uri]::EscapeDataString($Scope))&state=$State" +
        "&code_challenge=$CodeChallenge&code_challenge_method=S256&prompt=select_account"
}

# msedge.exe, or $null.
function Get-PaEdgePath {
    @(
        $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe' }),
        $(if ($env:ProgramFiles) { Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe' }),
        $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\Application\msedge.exe' })
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}

# Microsoft Graph Command Line Tools (first-party public client; the same app the Graph PowerShell SDK signs in with).
function Get-PaGraphCliClientId { '14d82eec-204b-4c2f-b7e8-296a70dab67e' }

# Interactive browser sign-in: auth code + PKCE on a loopback TcpListener (no HttpListener URL-ACL, works non-elevated),
# Edge launched explicitly (default browser when Edge is missing or -UseEdge:$false). Returns the token response.
function Get-PaInteractiveToken {
    param(
        [Parameter(Mandatory)][string[]]$Scopes,
        [string]$Tenant = 'organizations',
        [bool]$UseEdge = $true
    )
    $clientId = Get-PaGraphCliClientId
    $pkce  = New-PaPkcePair
    $state = [guid]::NewGuid().ToString('N')
    $scope = Get-PaDelegatedScopeString -Scopes $Scopes

    # OS-assigned free port; first-party public clients accept any localhost port on the redirect URI.
    $tcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $tcp.Start()
    $redirect = "http://localhost:$(([System.Net.IPEndPoint]$tcp.LocalEndpoint).Port)/"
    $authUrl  = New-PaAuthorizeUrl -Tenant $Tenant -ClientId $clientId -RedirectUri $redirect -Scope $scope -State $state -CodeChallenge $pkce.Challenge

    $query = $null
    try {
        $edge = if ($UseEdge) { Get-PaEdgePath } else { $null }
        if ($edge) {
            Write-Host "Launching Edge for sign-in (loopback listener on $redirect)..." -ForegroundColor Yellow
            Start-Process -FilePath $edge -ArgumentList @('--new-window', $authUrl)
        } else {
            if ($UseEdge) { Write-Host 'Microsoft Edge not found -- using the default browser.' -ForegroundColor DarkYellow }
            Write-Host "Opening the default browser for sign-in (loopback listener on $redirect)..." -ForegroundColor Yellow
            Start-Process $authUrl
        }
        Write-Host "If no browser opened, open this URL yourself:`n  $authUrl" -ForegroundColor DarkGray
        $deadline = (Get-Date).AddMinutes(5)
        while (-not $query) {
            if ((Get-Date) -gt $deadline) { throw 'Timed out (5 min) waiting for the sign-in redirect from the browser.' }
            if (-not $tcp.Pending()) { Start-Sleep -Milliseconds 200; continue }
            $client = $tcp.AcceptTcpClient()
            try {
                $stream      = $client.GetStream()
                $requestLine = (New-Object System.IO.StreamReader($stream)).ReadLine()
                $html   = '<html><body style="font-family:sans-serif"><h3>Sign-in complete.</h3>You can close this tab and return to PowerShell.</body></html>'
                $writer = New-Object System.IO.StreamWriter($stream)
                $writer.Write("HTTP/1.1 200 OK`r`nContent-Type: text/html`r`nContent-Length: $($html.Length)`r`nConnection: close`r`n`r`n$html")
                $writer.Flush()
                if ($requestLine -match '^GET /\?(\S+) HTTP') { $query = $Matches[1] }   # favicon & co. are answered and ignored
            } finally { $client.Close() }
        }
    } finally { $tcp.Stop() }

    $kv = @{}
    foreach ($pair in ($query -split '&')) {
        $k, $v = $pair -split '=', 2
        $kv[$k] = if ($null -ne $v) { [uri]::UnescapeDataString(($v -replace '\+', ' ')) } else { '' }
    }
    if ($kv['error'])            { throw "Sign-in failed: $($kv['error']) -- $($kv['error_description'])" }
    if ($kv['state'] -ne $state) { throw 'State mismatch on the loopback redirect -- the response did not come from this sign-in attempt. Close ALL browser windows and retry.' }
    if (-not $kv['code'])        { throw 'Sign-in redirect carried no authorization code.' }

    Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id     = $clientId
        grant_type    = 'authorization_code'
        code          = $kv['code']
        redirect_uri  = $redirect
        code_verifier = $pkce.Verifier
        scope         = $scope
    }
}

# Renew a delegated token with its refresh token (same public client, same scopes).
function Get-PaRefreshedToken {
    param([Parameter(Mandatory)][string]$RefreshToken, [Parameter(Mandatory)][string]$Tenant, [Parameter(Mandatory)][string[]]$Scopes)
    Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id     = (Get-PaGraphCliClientId)
        grant_type    = 'refresh_token'
        refresh_token = $RefreshToken
        scope         = (Get-PaDelegatedScopeString -Scopes $Scopes)
    }
}

# The certificate (with its private key) by thumbprint: CurrentUser\My first, then LocalMachine\My.
function Get-PaCertificate {
    param([Parameter(Mandatory)][string]$Thumbprint)
    $tp = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    foreach ($loc in 'CurrentUser', 'LocalMachine') {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', $loc)
        try {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $hit = @($store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $tp, $false)) | Select-Object -First 1
        } finally { $store.Close() }
        if ($hit) {
            if (-not $hit.HasPrivateKey) { throw "Certificate $tp found in Cert:\$loc\My but without its private key -- app-only sign-in needs the key." }
            return $hit
        }
    }
    throw "Certificate $tp not found in Cert:\CurrentUser\My or Cert:\LocalMachine\My."
}

# RS256 signature over $Data with the certificate's private key. Old CSP-stored keys (PROV_RSA_FULL) cannot hash SHA-256;
# for those the same key container is reopened under the enhanced (AES) provider, the classic 5.1 workaround.
function Invoke-PaRsaSha256Sign {
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [Parameter(Mandatory)][byte[]]$Data)
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if (-not $rsa) { throw "Certificate $($Certificate.Thumbprint) has no RSA private key." }
    try {
        return $rsa.SignData($Data, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } catch {
        if ($rsa -isnot [System.Security.Cryptography.RSACryptoServiceProvider]) { throw }
        $info = $rsa.CspKeyContainerInfo
        $cp = New-Object System.Security.Cryptography.CspParameters(24, 'Microsoft Enhanced RSA and AES Cryptographic Provider', $info.KeyContainerName)
        $cp.KeyNumber = [int]$info.KeyNumber
        $cp.Flags = [System.Security.Cryptography.CspProviderFlags]::UseExistingKey
        if ($info.MachineKeyStore) { $cp.Flags = $cp.Flags -bor [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore }
        $csp = New-Object System.Security.Cryptography.RSACryptoServiceProvider($cp)
        try { return $csp.SignData($Data, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) } finally { $csp.Dispose() }
    }
}

# The client assertion for client_credentials (RFC 7523): header {alg RS256, typ JWT, x5t = base64url(SHA-1 cert hash)},
# claims {aud = the v2 token endpoint, iss = sub = client id, jti, nbf, exp (10 min)}. Pure apart from the signature.
function New-PaClientAssertion {
    param(
        [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$TenantId,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [int]$LifetimeSeconds = 600
    )
    $now = Get-PaUnixTime -Utc $NowUtc
    $header = [ordered]@{ alg = 'RS256'; typ = 'JWT'; x5t = (ConvertTo-PaB64Url $Certificate.GetCertHash()) }
    $claims = [ordered]@{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        iss = $ClientId
        sub = $ClientId
        jti = [guid]::NewGuid().ToString()
        nbf = $now
        exp = $now + $LifetimeSeconds
    }
    $enc = [Text.Encoding]::UTF8
    $unsigned = (ConvertTo-PaB64Url $enc.GetBytes(($header | ConvertTo-Json -Compress))) + '.' + (ConvertTo-PaB64Url $enc.GetBytes(($claims | ConvertTo-Json -Compress)))
    $sig = Invoke-PaRsaSha256Sign -Certificate $Certificate -Data $enc.GetBytes($unsigned)
    $unsigned + '.' + (ConvertTo-PaB64Url $sig)
}

# App-only Graph token: client_credentials with the certificate assertion. Returns the token response.
function Get-PaAppOnlyToken {
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$CertificateThumbprint)
    $cert = Get-PaCertificate -Thumbprint $CertificateThumbprint
    Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id             = $ClientId
        grant_type            = 'client_credentials'
        scope                 = 'https://graph.microsoft.com/.default'
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = (New-PaClientAssertion -Certificate $cert -ClientId $ClientId -TenantId $TenantId)
    }
}

# Active directory role template ids from the session token's wids claim (the user's ACTIVE roles at issuance, readable
# without any directory-read scope -- unlike /me/memberOf, which hides roles from lean tokens). $null = unknown (no
# token, or no wids claim), not "no roles".
function Get-PaTokenRoleIds {
    if ($script:PaTokenClaims -and $script:PaTokenClaims.PSObject.Properties['wids']) { return @($script:PaTokenClaims.wids) }
    $null
}

# Ensure the session token carries at least one of the given directory role template ids. Typical failure: the operator
# activated the PIM role AFTER signing in, so the token predates the activation -- then run -Reconnect ONCE to mint a
# fresh token, and re-check. Without -Reconnect (a token passed in, which cannot be renewed here) it stops with the
# fix. -SoftFail warns and continues instead of throwing. No-op when the session's roles cannot be determined.
function Assert-PaSessionRole {
    param(
        [Parameter(Mandatory)][string[]]$AnyOfRoleIds,
        [Parameter(Mandatory)][string]$RoleDescription,
        [scriptblock]$Reconnect,
        [switch]$SoftFail
    )
    $wids = Get-PaTokenRoleIds
    if ($null -eq $wids) { return }   # cannot introspect -- let the API be the judge
    if (@($wids | Where-Object { $_ -in $AnyOfRoleIds }).Count -gt 0) { return }

    Write-Host "Session token does not carry $RoleDescription." -ForegroundColor Yellow
    if (-not $Reconnect) {
        if ($SoftFail) { Write-Host 'Continuing anyway (expect a 403 if the role is really missing).' -ForegroundColor DarkYellow; return }
        throw "The access token does not carry $RoleDescription. Activate the role in PIM, mint a NEW token after the activation, and run this script again."
    }
    Write-Host 'If you activated it in PIM after signing in, the token predates the activation -- signing in again to pick it up...' -ForegroundColor Yellow
    & $Reconnect

    $wids = Get-PaTokenRoleIds
    if ($null -eq $wids -or @($wids | Where-Object { $_ -in $AnyOfRoleIds }).Count -gt 0) { return }
    if ($SoftFail) {
        Write-Host "Still no $RoleDescription in the fresh token -- continuing anyway (a scoped RBAC assignment may still authorize the writes; expect a 403 otherwise)." -ForegroundColor DarkYellow
        return
    }
    throw "Even after a fresh sign-in, the session does not carry $RoleDescription. Activate it in PIM, wait for the activation to complete, then re-run this script."
}

# One-stop sign-in. Establishes the session token (Set-PaGraphSession) and returns a context object:
#   TenantId, Account, ClientId, AuthType (Interactive | AppOnly | ProvidedToken), Scopes (delegated scp), Roles (app roles).
#   * -AccessToken           : use that token as is (no renewal; scope check reported, not enforced).
#   * -AppId + -CertificateThumbprint (+ -TenantId) : app-only; the app needs the equivalent APPLICATION permissions
#                              (Application.ReadWrite.All; DelegatedPermissionGrant.ReadWrite.All for consent grants).
#   * otherwise              : interactive browser sign-in (Edge unless -UseEdge:$false).
# Then a cheap probe (/me, or one application for app-only) proves the token works before any write.
function Connect-PimActivatorGraph {
    param(
        [Parameter(Mandatory)][string[]]$RequiredScopes,
        [string]$TenantId,
        [bool]$UseEdge = $true,
        [string]$AppId,
        [string]$CertificateThumbprint,
        [string]$AccessToken
    )
    $isGuid = { param($s) $s -match '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' }

    if ($AccessToken) {
        Set-PaGraphSession -AccessToken $AccessToken -AuthType ProvidedToken
        Write-Host 'Using the access token passed with -AccessToken (no renewal -- valid ~1 hour from when it was minted).' -ForegroundColor Cyan
    } elseif ($AppId -and $CertificateThumbprint) {
        if (-not $TenantId) { throw 'App-only sign-in requires -TenantId.' }
        $recipe = @{ Kind = 'AppOnly'; TenantId = $TenantId; ClientId = $AppId; Thumbprint = $CertificateThumbprint }
        try { $tok = Get-PaAppOnlyToken -TenantId $TenantId -ClientId $AppId -CertificateThumbprint $CertificateThumbprint }
        catch { throw "App-only token request failed (app $AppId, certificate $CertificateThumbprint, tenant $TenantId): $($_.Exception.Message)" }
        Set-PaGraphSession -AccessToken "$($tok.access_token)" -AuthType AppOnly -ExpiresInSeconds ([int]"0$($tok.expires_in)") -Refresh $recipe
    } else {
        $tenant = if ($TenantId) { $TenantId } else { 'organizations' }
        Write-Host "Signing in to Microsoft Graph in the browser (scopes: $($RequiredScopes -join ', '))..." -ForegroundColor Yellow
        try { $tok = Get-PaInteractiveToken -Scopes $RequiredScopes -Tenant $tenant -UseEdge $UseEdge }
        catch { throw ("Sign-in failed: $($_.Exception.Message)`n$(Get-PaBrokenAuthHelp)") }
        $refresh = $null
        if ($tok.refresh_token) { $refresh = @{ Kind = 'RefreshToken'; RefreshToken = "$($tok.refresh_token)"; Tenant = $tenant; Scopes = $RequiredScopes } }
        Set-PaGraphSession -AccessToken "$($tok.access_token)" -AuthType Interactive -ExpiresInSeconds ([int]"0$($tok.expires_in)") -Refresh $refresh
        Write-Host 'Signed in (token valid ~1 hour, renewed automatically).' -ForegroundColor Green
    }

    $c = $script:PaTokenClaims
    $ctx = [pscustomobject]@{
        TenantId = $(if ($c -and $c.PSObject.Properties['tid']) { "$($c.tid)" } elseif (& $isGuid $TenantId) { $TenantId } else { $null })
        Account  = $(if ($c) { foreach ($n in 'upn', 'preferred_username', 'unique_name', 'app_displayname') { if ($c.PSObject.Properties[$n] -and $c.$n) { "$($c.$n)"; break } } })
        ClientId = $(if ($c -and $c.PSObject.Properties['appid']) { "$($c.appid)" } elseif ($c -and $c.PSObject.Properties['azp']) { "$($c.azp)" } else { $AppId })
        AuthType = $script:PaAuthType
        Scopes   = @($(if ($c -and $c.PSObject.Properties['scp']) { "$($c.scp)" -split ' ' | Where-Object { $_ } }))
        Roles    = @($(if ($c -and $c.PSObject.Properties['roles']) { $c.roles }))
    }

    if ($TenantId -and (& $isGuid $TenantId) -and $ctx.TenantId -and $ctx.TenantId -ne $TenantId) {
        throw "Signed in to tenant $($ctx.TenantId) but -TenantId says $TenantId. Sign in to the correct tenant (or fix -TenantId)."
    }

    if ($ctx.AuthType -eq 'AppOnly') {
        try { Invoke-PaGraph -Method GET -Path '/applications?$top=1&$select=id' | Out-Null }
        catch { throw "App-only token minted but a test read failed: $($_.Exception.Message)" }
        Write-Host "Connected app-only as appId $($ctx.ClientId) in tenant $($ctx.TenantId)." -ForegroundColor Green
        return $ctx
    }

    if ($ctx.AuthType -eq 'ProvidedToken' -and $ctx.Roles.Count -gt 0 -and $ctx.Scopes.Count -eq 0) {
        Write-Host 'The -AccessToken is an app-only token: skipping the delegated scope check.' -ForegroundColor DarkYellow
        try { Invoke-PaGraph -Method GET -Path '/applications?$top=1&$select=id' | Out-Null }
        catch { throw "The -AccessToken was rejected: $($_.Exception.Message)" }
        return $ctx
    }

    $missing = @($RequiredScopes | Where-Object { $_ -notin $ctx.Scopes })
    if ($missing.Count -gt 0 -and $ctx.Scopes.Count -gt 0) {
        $msg = "The token is missing required delegated scopes: $($missing -join ', ')."
        if ($ctx.AuthType -eq 'Interactive') { throw "$msg Consent to them for 'Microsoft Graph Command Line Tools' (an administrator may have to grant it) and run again." }
        Write-Host "$msg Continuing -- calls that need them will fail with 403." -ForegroundColor DarkYellow
    }

    try {
        $me = Invoke-PaGraph -Method GET -Path '/me?$select=id,userPrincipalName'
        if (-not $ctx.Account -and $me) { $ctx.Account = "$($me.userPrincipalName)" }
    } catch {
        if ($ctx.AuthType -eq 'ProvidedToken') {
            throw ("The -AccessToken was rejected: $($_.Exception.Message)`nTokens expire after ~1 hour -- mint a fresh one.")
        }
        throw ("Signed in, but Microsoft Graph rejected the token: $($_.Exception.Message)`n$(Get-PaBrokenAuthHelp)")
    }
    $ctx
}
