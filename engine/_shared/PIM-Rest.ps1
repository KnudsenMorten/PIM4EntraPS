<#
  PIM4EntraPS -- pure-REST auth + data plane (NO Graph/Az/MSAL modules).

  One place the whole solution gets tokens and calls Microsoft REST APIs, so the
  engine runs identically on Windows PowerShell 5.1, PowerShell 7, a VM, or a Linux
  container -- with nothing to Install-Module and no Azure.Core/Graph version clash.

  Token acquisition (auto-detected, override per call):
    * Managed Identity  -- App Service ($env:IDENTITY_ENDPOINT) or IMDS (VM)
    * Client secret     -- SPN client_credentials (v2 token endpoint)
    * Client certificate-- SPN, signed RS256 JWT client_assertion (no secret, no MSAL)
    * az CLI fallback   -- dev convenience when already `az login`-ed

  Resolution order for credentials (all overridable via params):
    explicit params -> $global:PIM_* -> Managed Identity -> az CLI.

  Data plane: Invoke-PimGraph / -PimArm / -PimPowerBI / -PimRest with @odata/nextLink
  paging (-All) and 429/Retry-After backoff. PS 5.1 + 7 compatible (cert signing uses
  X509 GetRSAPrivateKey, NOT RSA.ImportFromPem which is PS7-only).
#>

Set-StrictMode -Off

# resource (audience) per logical API. Built by a FUNCTION so any scope can re-seed it --
# see the trap note in Resolve-PimRestResource: a dot-sourced function's $script: follows
# the CALLER's scope, so a script that loaded PIM-SqlStore without this file found these
# tables null and silently ended up with no SQL credential at all.
function Get-PimRestResourceMap {
  @{
    graph    = 'https://graph.microsoft.com'
    arm      = 'https://management.azure.com'
    powerbi  = 'https://analysis.windows.net/powerbi/api'
    defender = 'https://api.securitycenter.microsoft.com'
    exo      = 'https://outlook.office365.com'   # Exchange Online REST admin API (app-only ManageAsApp)
  }
}
$script:PimRestResources = Get-PimRestResourceMap
$script:PimTokenCache = @{}   # "audience|tenant|clientId|credentialKind" -> @{ token; expiresUtc }

function Clear-PimRestTokenCache {
    <#
      Drop every cached token. The cache is keyed by full identity (BUG-22), so this is
      NOT needed to switch tenants any more -- it exists for an explicit "forget
      everything" (a rotated credential mid-process, or a test).
    #>
    [CmdletBinding()] param()
    $script:PimTokenCache = @{}
}

function Resolve-PimRestResource {
  param([Parameter(Mandatory)][string]$Resource)
  # 🪤 $script: IS NOT A CLOSURE FOR A DOT-SOURCED FUNCTION. It binds to the script scope
  # the function is CALLED from, so when another script dot-sources PIM-SqlStore (or the
  # downlink) WITHOUT this file, these tables are $null there and `.ContainsKey()` throws
  # "You cannot call a method on a null-valued expression". New-PimSqlConnection catches
  # that, tries the next credential, and ends up presenting NO credential -- Azure SQL then
  # answers "Login failed for user ''", which sends everyone looking at permissions.
  # Re-seeding here makes the alias table work from any scope; the value is a constant map,
  # so there is nothing to lose by rebuilding it.
  if (-not $script:PimRestResources) { $script:PimRestResources = Get-PimRestResourceMap }
  if ($script:PimRestResources.ContainsKey($Resource)) { return $script:PimRestResources[$Resource] }
  return ($Resource -replace '/+$','')   # already a full audience URL
}

function ConvertTo-PimBase64Url {
  param([Parameter(Mandatory)][byte[]]$Bytes)
  [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function Get-PimTenantId {
  param([string]$TenantId)
  if ($TenantId) { return $TenantId }
  if ($global:PIM_TenantId) { return $global:PIM_TenantId }
  if ($env:PIM_TenantId) { return $env:PIM_TenantId }
  if ($env:AZURE_TENANT_ID) { return $env:AZURE_TENANT_ID }
  return $null
}

# ---- Managed Identity (App Service / IMDS) --------------------------------
function ConvertTo-PimTokenExpiry {
  param($ExpiresOn)
  # App Service IDENTITY_ENDPOINT -> unix seconds; older MSI/some -> a date string.
  try { if ("$ExpiresOn" -match '^\d+$') { return ([datetimeoffset]::FromUnixTimeSeconds([int64]$ExpiresOn)).UtcDateTime } } catch {}
  try { return ([datetimeoffset]"$ExpiresOn").UtcDateTime } catch {}
  return (Get-Date).ToUniversalTime().AddMinutes(50)
}
function Get-PimManagedIdentityToken {
  param([Parameter(Mandatory)][string]$Audience)
  $res = [uri]::EscapeDataString($Audience)
  # App Service / Functions (current): IDENTITY_ENDPOINT + IDENTITY_HEADER (api 2019-08-01)
  if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
    $u = "$($env:IDENTITY_ENDPOINT)?resource=$res&api-version=2019-08-01"
    # 🔴 BUG-76 -- THIS BRANCH IGNORED THE CONFIGURED MI CLIENT ID, AND THE IMDS BRANCH BELOW DOES
    # NOT. That asymmetry is the whole defect: with a USER-ASSIGNED-ONLY identity there is nothing
    # for the endpoint to default to, so no token is issued and the caller ends up presenting no
    # credential at all. Azure SQL then answers "Login failed for user '<token-identified
    # principal>'", which reads as a missing database user -- and it is not.
    # MEASURED on the greenfield slave 2026-08-27: ca-pim-tick carries `SystemAssigned,
    # UserAssigned` and logs "[mi] token via IDENTITY_ENDPOINT" happily, while ca-pim-downlink-s6
    # carries UserAssigned ALONE and logs that line NOT AT ALL -- the absence was the clue. Its
    # engine apply failed every run on `Preflight FAILED: ... no SELECT 1`, which sent the search
    # to contained users and grants (where a user was duly created, and changed nothing).
    # Container Apps is exactly the host that attaches a user-assigned identity on its own.
    $miCid = if ($global:PIM_ManagedIdentityClientId) { "$($global:PIM_ManagedIdentityClientId)".Trim() }
             elseif ($env:PIM_ManagedIdentityClientId) { "$($env:PIM_ManagedIdentityClientId)".Trim() } else { '' }
    if ($miCid) { $u += "&client_id=$([uri]::EscapeDataString($miCid))" }
    $r = Invoke-RestMethod -Method GET -Uri $u -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER }
    if ("$($r.access_token)") { try { [System.Console]::Out.WriteLine("  [mi] token via IDENTITY_ENDPOINT (len $($r.access_token.Length))") } catch {} }  # Console.Out (not Write-Host): headless-safe from any scope (App Service has no console buffer; Write-Host throws there even from module scope)
    return [pscustomobject]@{ token = $r.access_token; expiresUtc = (ConvertTo-PimTokenExpiry $r.expires_on) }
  }
  # App Service (older / some Linux SKUs): MSI_ENDPOINT + MSI_SECRET (api 2017-09-01, header 'Secret')
  if ($env:MSI_ENDPOINT -and $env:MSI_SECRET) {
    $u = "$($env:MSI_ENDPOINT)?resource=$res&api-version=2017-09-01"
    $r = Invoke-RestMethod -Method GET -Uri $u -Headers @{ 'Secret' = $env:MSI_SECRET }
    if ("$($r.access_token)") { try { [System.Console]::Out.WriteLine("  [mi] token via MSI_ENDPOINT (len $($r.access_token.Length))") } catch {} }  # Console.Out: headless-safe from any scope
    return [pscustomobject]@{ token = $r.access_token; expiresUtc = (ConvertTo-PimTokenExpiry $r.expires_on) }
  }
  # IMDS (Azure VM)
  $u = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$res"
  if ($global:PIM_ManagedIdentityClientId) { $u += "&client_id=$($global:PIM_ManagedIdentityClientId)" }
  $r = Invoke-RestMethod -Method GET -Uri $u -Headers @{ Metadata = 'true' } -TimeoutSec 5
  return [pscustomobject]@{ token = $r.access_token; expiresUtc = (ConvertTo-PimTokenExpiry $r.expires_on) }
}

# ---- SPN client secret ----------------------------------------------------
function Get-PimClientSecretToken {
  param([Parameter(Mandatory)][string]$TenantId,[Parameter(Mandatory)][string]$ClientId,[Parameter(Mandatory)][string]$ClientSecret,[Parameter(Mandatory)][string]$Audience)
  $body = @{ grant_type='client_credentials'; client_id=$ClientId; client_secret=$ClientSecret; scope="$Audience/.default" }
  $r = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body $body
  return [pscustomobject]@{ token = $r.access_token; expiresUtc = (Get-Date).ToUniversalTime().AddSeconds([int]$r.expires_in - 60) }
}

# ---- SPN certificate (signed JWT assertion) -------------------------------
function Get-PimClientCertToken {
  param([Parameter(Mandatory)][string]$TenantId,[Parameter(Mandatory)][string]$ClientId,[Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,[Parameter(Mandatory)][string]$Audience)
  $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
  $now = [DateTimeOffset]::UtcNow
  $x5t = ConvertTo-PimBase64Url -Bytes $Certificate.GetCertHash()   # SHA1 thumbprint bytes
  $header = @{ alg='RS256'; typ='JWT'; x5t=$x5t } | ConvertTo-Json -Compress
  $claims = @{ aud=$tokenUrl; iss=$ClientId; sub=$ClientId; jti=([guid]::NewGuid().ToString())
              nbf=$now.ToUnixTimeSeconds(); exp=$now.AddMinutes(10).ToUnixTimeSeconds() } | ConvertTo-Json -Compress
  $h = ConvertTo-PimBase64Url -Bytes ([Text.Encoding]::UTF8.GetBytes($header))
  $c = ConvertTo-PimBase64Url -Bytes ([Text.Encoding]::UTF8.GetBytes($claims))
  $unsigned = "$h.$c"
  $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
  if (-not $rsa) { throw "Certificate has no usable RSA private key for JWT signing." }
  $sigBytes = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($unsigned), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $jwt = "$unsigned." + (ConvertTo-PimBase64Url -Bytes $sigBytes)
  $body = @{ grant_type='client_credentials'; client_id=$ClientId; scope="$Audience/.default"
            client_assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer'; client_assertion=$jwt }
  $r = Invoke-RestMethod -Method POST -Uri $tokenUrl -ContentType 'application/x-www-form-urlencoded' -Body $body
  return [pscustomobject]@{ token = $r.access_token; expiresUtc = (Get-Date).ToUniversalTime().AddSeconds([int]$r.expires_in - 60) }
}

function Get-PimTokenTenantId {
    <#
      SEC-12 -- read the tenant a JWT actually belongs to, from its own claims.

      🔑 ASKING FOR A TENANT IS NOT THE SAME AS BEING GIVEN ONE, and until this existed there was
      no way to tell the difference: a token for the wrong directory is a perfectly valid string
      that succeeds at the call site and fails somewhere else as a permissions error. One
      `Split('.')[1]` turns that into a fact.

      PURE: no network, no validation of the signature (that is the resource's job) -- this only
      reads what the token SAYS about itself, which is exactly what is needed to catch "you asked
      for A and something handed you B". Returns the lowercased `tid`, or '' when the string is
      not a readable JWT -- never throws, because a caller reaching for a sanity check must not be
      broken BY the sanity check.
    #>
    [CmdletBinding()] param([string]$Token)
    try {
        $parts = "$Token".Split('.')
        if ($parts.Count -lt 2) { return '' }
        $p = $parts[1].Replace('-', '+').Replace('_', '/')
        while ($p.Length % 4) { $p += '=' }
        $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
        return "$($claims.tid)".Trim().ToLowerInvariant()
    } catch { return '' }
}

function Get-PimTokenAppId {
    <# SEC-12 companion: the appid a JWT claims. Same contract as Get-PimTokenTenantId. #>
    [CmdletBinding()] param([string]$Token)
    try {
        $parts = "$Token".Split('.')
        if ($parts.Count -lt 2) { return '' }
        $p = $parts[1].Replace('-', '+').Replace('_', '/')
        while ($p.Length % 4) { $p += '=' }
        $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
        return "$($claims.appid)".Trim().ToLowerInvariant()
    } catch { return '' }
}

function Resolve-PimCertificate {
  param([string]$Thumbprint)
  $tp = if ($Thumbprint) { $Thumbprint } elseif ($global:PIM_CertThumbprint) { $global:PIM_CertThumbprint } else { $null }
  if (-not $tp) { return $null }
  $tp = ($tp -replace '\s','').ToUpperInvariant()
  foreach ($store in @('Cert:\CurrentUser\My','Cert:\LocalMachine\My')) {
    $c = Get-ChildItem $store -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $tp } | Select-Object -First 1
    if ($c) { return $c }
  }
  return $null
}

# ---- interactive (delegated) -- BREAK-GLASS / emergency on a client PC ----
# Dependency-free auth-code + PKCE loopback. No MSAL, no Graph/Az modules.
# Used when there is no MI and no SPN credential (a cloud-only admin PC running
# the emergency edition): the operator signs in as THEMSELVES, so the resulting
# SQL/Graph/ARM action is audited under the human identity, not a shared app.
# Returns a raw access token for $Audience. Edge is launched explicitly to avoid
# the system-default-browser state-mismatch bug; any first-party public client
# accepts an arbitrary localhost redirect port.
function Get-PimInteractiveToken {
  param([Parameter(Mandatory)][string]$Audience,[string]$TenantId,[string]$ClientId,
        # section 9 account sign-in clarity: force a brand-new credential prompt (prompt=login)
        # instead of reusing a cached account. -ExpectedAccount, if the cached account
        # differs, also forces a fresh prompt so a stale account is never used silently.
        [switch]$ForceFreshAccount,[string]$ExpectedAccount)
  $tenant = if ($TenantId) { $TenantId } elseif (Get-PimTenantId) { Get-PimTenantId } else { 'organizations' }
  # Default to the Microsoft Graph CLI public client (same app Connect-MgGraph uses);
  # it has consent for delegated tokens to Graph/ARM/Azure SQL via .default.
  $cid = if ($ClientId) { $ClientId } elseif ($global:PIM_InteractiveClientId) { $global:PIM_InteractiveClientId } else { '14d82eec-204b-4c2f-b7e8-296a70dab67e' }

  $bytes = New-Object byte[] 32
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $verifier  = ConvertTo-PimBase64Url -Bytes $bytes
  $sha       = [System.Security.Cryptography.SHA256]::Create()
  $challenge = ConvertTo-PimBase64Url -Bytes ($sha.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($verifier)))
  $state     = [guid]::NewGuid().ToString('N')

  $tcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
  $tcp.Start()
  $port     = ([System.Net.IPEndPoint]$tcp.LocalEndpoint).Port
  $redirect = "http://localhost:$port/"

  # section 9 prompt clarity: select_account (always show the picker so a stale cached account
  # is never reused silently) unless a fresh sign-in is forced -> login. ConvertTo-
  # PimAuthCodePrompt is in PIM-AuthDiagnostics; fall back if it isn't dot-sourced.
  if (Get-Command ConvertTo-PimAuthCodePrompt -ErrorAction SilentlyContinue) {
    $prompt = ConvertTo-PimAuthCodePrompt -ForceFresh:$ForceFreshAccount -KnownStaleAccount $ExpectedAccount
  } else { $prompt = if ($ForceFreshAccount) { 'login' } else { 'select_account' } }

  $scope   = "$Audience/.default offline_access openid profile"
  $authUrl = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/authorize" +
             "?client_id=$cid&response_type=code&response_mode=query" +
             "&redirect_uri=$([uri]::EscapeDataString($redirect))" +
             "&scope=$([uri]::EscapeDataString($scope))&state=$state" +
             "&code_challenge=$challenge&code_challenge_method=S256&prompt=$prompt"
  if ("$ExpectedAccount".Trim()) { $authUrl += "&login_hint=$([uri]::EscapeDataString($ExpectedAccount.Trim()))" }

  $edge = @(
    (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),
    (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe')
  ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
  Write-Host "  [interactive] sign-in required for $Audience (loopback $redirect)" -ForegroundColor Yellow
  if ($edge) { Start-Process -FilePath $edge -ArgumentList @('--new-window', $authUrl) }
  else { Start-Process $authUrl }   # fall back to default browser if Edge absent

  $query = $null
  try {
    $deadline = (Get-Date).AddMinutes(5)
    while (-not $query) {
      if ((Get-Date) -gt $deadline) { throw 'Timed out (5 min) waiting for the sign-in redirect.' }
      if (-not $tcp.Pending()) { Start-Sleep -Milliseconds 200; continue }
      $client = $tcp.AcceptTcpClient()
      try {
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $requestLine = $reader.ReadLine()
        $html = '<html><body style="font-family:sans-serif"><h3>Sign-in complete.</h3>You can close this tab and return to the PIM emergency console.</body></html>'
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.Write("HTTP/1.1 200 OK`r`nContent-Type: text/html`r`nContent-Length: $($html.Length)`r`nConnection: close`r`n`r`n$html")
        $writer.Flush()
        if ($requestLine -match '^GET /\?(\S+) HTTP') { $query = $Matches[1] }
      } finally { $client.Close() }
    }
  } finally { $tcp.Stop() }

  $kv = @{}
  foreach ($pair in ($query -split '&')) { $k,$v = $pair -split '=',2; $kv[$k] = if ($null -ne $v) { [uri]::UnescapeDataString(($v -replace '\+',' ')) } else { '' } }
  if ($kv['error'])            { throw "Sign-in failed: $($kv['error']) -- $($kv['error_description'])" }
  if ($kv['state'] -ne $state) { throw 'State mismatch on the loopback redirect -- close ALL browser windows and retry.' }
  if (-not $kv['code'])        { throw 'Sign-in redirect carried no authorization code.' }

  $r = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
    client_id     = $cid
    grant_type    = 'authorization_code'
    code          = $kv['code']
    redirect_uri  = $redirect
    code_verifier = $verifier
    scope         = $scope
  }
  return [pscustomobject]@{ token = $r.access_token; expiresUtc = (Get-Date).ToUniversalTime().AddSeconds([int]$r.expires_in - 60) }
}

# ---- the one entry point: get a token for a resource ----------------------
function Get-PimRestToken {
  [CmdletBinding()]
  param(
    [string]$Resource = 'graph',
    [string]$TenantId,[string]$ClientId,[string]$ClientSecret,
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,[string]$CertThumbprint,
    [switch]$UseManagedIdentity,[switch]$Interactive,[switch]$Force
  )
  $aud = Resolve-PimRestResource -Resource $Resource

  # The identity is resolved BEFORE the cache is consulted, because it is part of the
  # cache key. See BUG-22 below -- this ordering is the fix, do not move the lookup back
  # above these lines.
  $tenant = Get-PimTenantId -TenantId $TenantId
  $cid    = if ($ClientId) { $ClientId } elseif ($global:PIM_ClientId) { $global:PIM_ClientId } elseif ($env:AZURE_CLIENT_ID) { $env:AZURE_CLIENT_ID } else { $null }
  $sec    = if ($ClientSecret) { $ClientSecret } elseif ($global:PIM_ClientSecret) { $global:PIM_ClientSecret } elseif ($env:AZURE_CLIENT_SECRET) { $env:AZURE_CLIENT_SECRET } else { $null }
  # Cert thumbprint: explicit -CertThumbprint, else the engine SPN global / env. This is
  # the engine's real app-only auth (SPN + certificate, no secret) -- e.g. the
  # PIM4EntraPS-Engine cert in LocalMachine\My / CurrentUser\My.
  $thumb  = if ($CertThumbprint) { $CertThumbprint } elseif ($global:PIM_CertThumbprint) { $global:PIM_CertThumbprint } elseif ($env:PIM_CERT_THUMBPRINT) { $env:PIM_CERT_THUMBPRINT } else { $null }
  $cert   = if ($Certificate) { $Certificate } else { Resolve-PimCertificate -Thumbprint $thumb }

  # 🔴 SEC-12 -- WHAT THE CALLER ASKED FOR, which is NOT the same as what resolution produced.
  # Deliberately keyed on $thumb (the thumbprint that was REQUESTED), never on $cert (the object
  # that was RESOLVED): a certificate that was named and could not be loaded is a FAILURE TO
  # HONOUR the request, not the absence of one. Reading $cert here is exactly how a missing cert
  # became "no explicit identity was asked for" and slid onto the ambient az fallback below.
  $explicitIdentity = [bool]("$tenant".Trim()) -and [bool]("$cid".Trim()) -and
                      ([bool]("$sec".Trim()) -or [bool]("$thumb".Trim()) -or [bool]$Certificate)

  # BUG-22 (2026-08-06): this cache was keyed by the AUDIENCE ALONE -- no tenant, no client
  # id. In any process that touches TWO tenants, the second one silently reused the first
  # one's token, so every call meant for tenant B went to tenant A. That is precisely the
  # MSP master->slave fanout this product exists to run, and the failure is invisible: the
  # calls SUCCEED, against the wrong directory.
  #
  # Proven live: an S6 (local-slave) run targeting a tenant with ZERO PIM groups reported
  # "Groups live=85" -- the MASTER's group count -- and the verifier then found all six
  # groups missing from the slave it was supposed to be managing. A write-shaped run would
  # have applied the customer's desired state to the MSP's own tenant.
  #
  # The key is now the full identity: audience + tenant + client + credential KIND (and the
  # cert thumbprint, so rotating a cert re-mints rather than serving the old token). No
  # secret material goes into the key.
  $mode = if ($Interactive -or $global:PIM_Interactive) { 'interactive' }
          elseif ($UseManagedIdentity -or $global:PIM_UseManagedIdentity -or ($env:IDENTITY_ENDPOINT -and -not $cid)) { 'mi' }
          elseif ($sec) { 'secret' }
          elseif ($cert) { "cert:$thumb" }
          else { 'unknown' }
  $key = ("$aud|$tenant|$cid|$mode").ToLowerInvariant()
  # same cross-scope guard as Resolve-PimRestResource: an unseeded cache must mean "cache
  # miss", never a thrown method call that the caller reads as "authentication failed".
  if (-not $script:PimTokenCache) { $script:PimTokenCache = @{} }
  if (-not $Force -and $script:PimTokenCache.ContainsKey($key)) {
    $e = $script:PimTokenCache[$key]
    if ($e.expiresUtc -gt (Get-Date).ToUniversalTime().AddMinutes(2)) { return $e.token }
  }

  $res = $null
  # Explicit interactive request (break-glass): sign in as the human up front.
  if ($Interactive -or $global:PIM_Interactive) {
    try { $res = Get-PimInteractiveToken -Audience $aud -TenantId $tenant } catch { Write-Verbose "PIM-Rest interactive auth failed for ${Resource}: $($_.Exception.Message)" }
  }
  $primaryErr = $null
  if (-not $res) {
    try {
      if ($UseManagedIdentity -or $global:PIM_UseManagedIdentity -or ($env:IDENTITY_ENDPOINT -and -not $cid)) {
        $res = Get-PimManagedIdentityToken -Audience $aud
      }
      elseif ($tenant -and $cid -and $sec) {
        $res = Get-PimClientSecretToken -TenantId $tenant -ClientId $cid -ClientSecret $sec -Audience $aud
      }
      elseif ($tenant -and $cid -and $cert) {
        $res = Get-PimClientCertToken -TenantId $tenant -ClientId $cid -Certificate $cert -Audience $aud
      }
    } catch {
      # 🔴 SEC-12: KEEP the reason. This was Write-Verbose only, so the one fact that explained
      # everything downstream was discarded at the moment it was known.
      $primaryErr = "$($_.Exception.Message)"
      Write-Verbose "PIM-Rest primary auth failed for ${Resource}: $primaryErr"
    }
  }

  # =====================================================================================
  # 🔴 SEC-12 -- AN EXPLICIT IDENTITY THAT CANNOT BE HONOURED IS AN ERROR, NOT A CUE TO
  # BECOME SOMEBODY ELSE.
  #
  # MEASURED 2026-08-28: a caller asked for tenant f0fa27a0 (myfamilynetwork) + the PIM engine
  # client id + its certificate thumbprint, and got back a token for tenant 7825c48b
  # (ExpertsLiveDK -- A DIFFERENT COMPANY) with a different appid. Nothing in the return value
  # said so. The certificate had failed to resolve, the failure went to Write-Verbose, and the
  # "dev convenience" az fallback below then minted a token for whatever subscription happened
  # to be the az DEFAULT context -- which on the dev machine is frequently another tenant
  # entirely, a hazard CLAUDE.md already documents for hand-typed az commands.
  #
  # 🔑 THE POINT IS NOT THAT THE FALLBACK EXISTS. It is that it ran AFTER the caller had named a
  # tenant, a client id and a credential. That caller has said exactly who it wants to be, and
  # answering with a different principal is WORSE than answering with an error: the token works,
  # so the failure surfaces far away as "Login failed" or "permission denied" and reads like an
  # RBAC problem. It cost a session's time to chase, and the answer was three layers up.
  #
  # 📌 Same family as BUG-34, which fixed precisely this shape one layer down in
  # New-PimSqlConnection ("a valid-but-wrong-tenant token was taken, so the explicitly
  # configured SPN never got a turn") and left the az branch here standing.
  # =====================================================================================
  if (-not $res -and $explicitIdentity) {
    $why = if ("$thumb".Trim() -and -not $cert) {
             "certificate '$thumb' was not found in CurrentUser\My or LocalMachine\My, or has no usable private key"
           } elseif ($primaryErr) { $primaryErr } else { 'the credential was not accepted' }
    throw ("PIM-Rest: REFUSING to fall back to an ambient identity for '$Resource'. " +
           "An explicit identity was requested (tenant '$tenant', client '$cid') and could not be honoured: $why. " +
           'Fix the credential rather than letting the call authenticate as somebody else -- a token for the wrong ' +
           'principal succeeds and then fails far away as a permissions error.')
  }

  if (-not $res) {
    # dev convenience: reuse an existing az session. Only reached when NO explicit identity was
    # requested (see the refusal above), so this is genuinely "whoever the operator is".
    try {
      # 🔒 --tenant is not optional. Without it az answers for its DEFAULT context, which on a
      # machine logged into several directories is a coin flip -- and on this one it lands on a
      # different company's tenant.
      $azArgs = @('account','get-access-token','--resource',$aud,'-o','json')
      if ("$tenant".Trim()) { $azArgs += @('--tenant', "$tenant") }
      $j = & az @azArgs 2>$null | ConvertFrom-Json
      if ($j.accessToken) {
        # 🔒 AND VERIFY IT. Asking for a tenant is not the same as being given one; the whole
        # defect was trusting a token nobody had looked at. A mismatch is discarded, not used.
        $claimed = Get-PimTokenTenantId -Token "$($j.accessToken)"
        if ("$tenant".Trim() -and $claimed -and ($claimed -ne "$tenant".Trim().ToLowerInvariant())) {
          Write-Warning ("  [rest] DISCARDED an az token for '$Resource': it belongs to tenant $claimed, not the requested $tenant.")
        } else {
          $exp = (Get-Date).ToUniversalTime().AddMinutes(50)
          try { $exp = ([datetime]$j.expiresOn).ToUniversalTime() } catch {}
          $res = [pscustomobject]@{ token = $j.accessToken; expiresUtc = $exp }
        }
      }
    } catch {}
  }
  # LAST-RESORT interactive prompt — ONLY when an attended caller opts in via
  # $global:PIM_InteractiveFallback (the interactive admin tools set this; the engine /
  # headless cron NEVER does, so an unattended run still fails fast instead of hanging on
  # a browser prompt). This is what makes the admin deploy scripts "just sign me in" when
  # no MI/secret/cert/az session is available, rather than throwing.
  if (-not $res -and $global:PIM_InteractiveFallback) {
    Write-Host "PIM-Rest: no MI/secret/cert/az token for '$Resource' -- falling back to interactive sign-in..." -ForegroundColor Yellow
    try { $res = Get-PimInteractiveToken -Audience $aud -TenantId $tenant } catch { Write-Verbose "PIM-Rest interactive fallback failed for ${Resource}: $($_.Exception.Message)" }
  }
  if (-not $res) { throw "PIM-Rest: could not acquire a token for '$Resource'. Provide MI, ClientId+Secret/Cert (+TenantId), -Interactive (break-glass), or run az login." }

  $script:PimTokenCache[$key] = $res
  return $res.token
}

# ---- REST error reporting (BUG-27) ----------------------------------------
# A REST failure used to be logged as, verbatim:
#     PUT https://management.azure.com/.../roleEligibilityScheduleRequests/...
#         -> HTTP 409 :
# The colon is where the reason should be. ARM had actually answered
#     { "error": { "code": "ReadOnlyDisabledSubscription",
#                  "message": "The subscription '...' is disabled and therefore
#                              marked as read only." } }
# and the engine threw it away. Three wrong hypotheses were checked with live ARM
# queries before replaying the same PUT by hand produced the answer instantly.
#
# The whole audit rests on believing what the engine reports: a scope reporting
# "errors=1" with no cause is indistinguishable from a real code defect. In a
# customer tenant the same line is a support round-trip instead of a fix.
# ---------------------------------------------------------------------------

function Get-PimRestErrorBody {
  <#
    Read the error body from a terminating REST error, from BOTH sources.

    🪤 The old code was `if (ErrorDetails.Message) {...} else { read the stream }`. On
    Windows PowerShell 5.1 ErrorDetails.Message is frequently PRESENT BUT EMPTY, so the
    else-branch never ran and the stream -- which held the real answer -- was never read.
    Take the LONGER of the two instead of trusting either.
  #>
  [CmdletBinding()] param([Parameter(Mandatory)][object]$ErrorRecord)
  $fromDetails = ''
  try { if ($ErrorRecord.ErrorDetails) { $fromDetails = "$($ErrorRecord.ErrorDetails.Message)" } } catch {}
  $fromStream = ''
  try {
    $resp = $ErrorRecord.Exception.Response
    if ($resp) {
      $stream = $resp.GetResponseStream()
      if ($stream) {
        # The stream may already have been consumed; rewind when we are allowed to.
        try { if ($stream.CanSeek) { $stream.Position = 0 } } catch {}
        $sr = New-Object System.IO.StreamReader($stream)
        try { $fromStream = $sr.ReadToEnd() } finally { $sr.Dispose() }
      }
    }
  } catch {}
  if ("$fromStream".Trim().Length -gt "$fromDetails".Trim().Length) { return $fromStream }
  return $fromDetails
}

function Get-PimRestErrorDetail {
  <#
    PURE. Turn an ARM/Graph error body into the SHORT reason a human needs.

    Returns "<code> -- <message>", or $null when the body carries nothing usable (the
    caller must then say so explicitly rather than printing an empty reason).

    🔒 CODE + MESSAGE ONLY, NEVER THE WHOLE BODY. The raw body can carry subscription
    ids, principal ids and request ids; it is also mostly noise. code+message is the
    part that ends the diagnosis, so it is the right amount to log.

    Handles the shapes both APIs actually return:
      ARM      { "error": { "code": ..., "message": ... } }
      Graph    { "error": { "code": ..., "message": ..., "innerError": {...} } }
      flat     { "code": ..., "message": ... }
      odata    { "odata.error": { "code": ..., "message": { "value": ... } } }
      non-JSON (HTML error pages, plain text) -- returned trimmed + truncated.
  #>
  [CmdletBinding()] param([Parameter()][AllowNull()][AllowEmptyString()][string]$Body, [int]$MaxLength = 400)

  $raw = "$Body".Trim()
  if (-not $raw) { return $null }

  $obj = $null
  try { $obj = $raw | ConvertFrom-Json } catch { $obj = $null }

  # Property lookup is CASE-INSENSITIVE. `-contains` is not, and Azure is not consistent:
  # ARM/Graph send "message", some services send "Message". A case-sensitive check would
  # silently miss those and fall through to printing the raw body.
  $prop = {
    param($o, $name)
    try { foreach ($p in $o.PSObject.Properties) { if ("$($p.Name)" -ieq "$name") { return $p.Value } } } catch {}
    return $null
  }

  if ($obj) {
    $err = $null
    foreach ($k in @('error', 'odata.error')) {
      $v = & $prop $obj $k
      if ($null -ne $v) { $err = $v; break }
    }
    if ($null -eq $err) { $err = $obj }          # flat { code, message }

    $code = "$(& $prop $err 'code')".Trim()
    $m = & $prop $err 'message'
    $msg = ''
    if ($null -ne $m) {
      # odata nests the text one level deeper: message.value
      if ($m -isnot [string]) {
        $inner = & $prop $m 'value'
        $msg = if ($null -ne $inner) { "$inner".Trim() } else { "$m".Trim() }
      } else { $msg = "$m".Trim() }
    }

    if ($code -or $msg) {
      $joined = if ($code -and $msg) { "$code -- $msg" } elseif ($code) { $code } else { $msg }
      $joined = ($joined -replace '\s+', ' ').Trim()
      if ($joined.Length -gt $MaxLength) { $joined = $joined.Substring(0, $MaxLength) + '...' }
      return $joined
    }

    # Valid JSON that carries no code and no message -- e.g. "{}". Echoing it back would
    # print "HTTP 409 : {}", which is exactly as useless as the empty colon this whole
    # function exists to eliminate. Report NOTHING USABLE and let the caller say so.
    $hasAny = $false
    try { $hasAny = @($obj.PSObject.Properties).Count -gt 0 } catch {}
    if (-not $hasAny) { return $null }
  }

  # Not JSON (HTML error page, plain text), or JSON whose useful part we could not name:
  # return it trimmed + truncated. Better than nothing, and still bounded -- an error
  # page must not flood the log.
  $flat = ($raw -replace '\s+', ' ').Trim()
  if (-not $flat) { return $null }
  if ($flat.Length -gt $MaxLength) { $flat = $flat.Substring(0, $MaxLength) + '...' }
  return $flat
}

# ---- data plane -----------------------------------------------------------
function Invoke-PimRest {
  [CmdletBinding()]
  param(
    [string]$Method = 'GET',
    [Parameter(Mandatory)][string]$Url,
    [object]$Body,
    [string]$Resource = 'graph',
    [hashtable]$Headers = @{},
    [switch]$All,                # follow @odata.nextLink / nextLink, aggregate .value
    [int]$MaxRetry = 5,
    # Authenticate THIS call as the host's managed identity even when an engine SPN is configured
    # (mail send, operator decision 2026-09-13: the hosted engine sends as its managed identity).
    [switch]$UseManagedIdentity
  )
  # Keep a scheduler lease alive through a long live read (minutes of paged calls). No-op outside
  # a leased tick; time-gated in Invoke-PimSchedulerLeaseHeartbeat (PIM-Scheduler.ps1).
  if ($global:PIM_LeaseHeartbeat -and (Get-Command Invoke-PimSchedulerLeaseHeartbeat -ErrorAction SilentlyContinue)) { [void](Invoke-PimSchedulerLeaseHeartbeat) }
  $token = if ($UseManagedIdentity) { Get-PimRestToken -Resource $Resource -UseManagedIdentity } else { Get-PimRestToken -Resource $Resource }
  $h = @{ Authorization = "Bearer $token" } + $Headers
  $agg = New-Object System.Collections.Generic.List[object]
  $next = $Url
  while ($next) {
    $attempt = 0
    while ($true) {
      try {
        $args = @{ Method = $Method; Uri = $next; Headers = $h }
        # (see Get-PimRestErrorBody / Get-PimRestErrorDetail above for the failure path)
        if ($null -ne $Body -and $Method -ne 'GET') {
          $args.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 }
          $args.ContentType = 'application/json'
        }
        $resp = Invoke-RestMethod @args
        break
      } catch {
        $code = $null; try { $code = [int]$_.Exception.Response.StatusCode } catch {}
        # BUG-27: surface the API error body. Try BOTH sources and keep the longer of the
        # two -- on 5.1 ErrorDetails.Message is frequently present but EMPTY, and the old
        # `if/else` took it and never looked at the stream, which is how a real ARM
        # explanation became the bare log line "-> HTTP 409 :" (note the empty colon).
        $body = Get-PimRestErrorBody -ErrorRecord $_
        # retry transient + freshly-created-principal replication (ARM 400 PrincipalNotFound)
        $isReplDelay = ($code -eq 400 -and "$body" -match 'PrincipalNotFound|does not exist in the directory')
        if (($code -eq 429 -or $code -ge 500 -or $isReplDelay) -and $attempt -lt $MaxRetry) {
          $wait = [Math]::Min(60, [Math]::Pow(2, $attempt + 1))
          try { $ra = [int]("$($_.Exception.Response.Headers['Retry-After'])"); if ($ra -gt 0) { $wait = $ra } } catch {}
          Start-Sleep -Seconds $wait; $attempt++; continue
        }
        # section 9 missing-role hint: on a 403 / insufficient-privileges, append the EXACT
        # Graph app-role to grant (engine SPN, app-only) so the operator isn't left
        # guessing. Best-effort: only when the hint helper is loaded (PIM-Functions /
        # PIM-AuthDiagnostics dot-sourced) and the failure is a permissions failure.
        $hintText = ''
        if (Get-Command Get-PimMissingRoleHint -ErrorAction SilentlyContinue) {
            try {
                $appOnly = -not [bool]$global:PIM_Interactive
                $h = Get-PimMissingRoleHint -Path $next -StatusCode ([int]("$code")) -ErrorBody "$body" -AppOnly:$appOnly
                if ($h) { $hintText = "  >> $($h.Hint)" }
            } catch {}
        }
        # BUG-27: report error.code + error.message, NOT the raw body. The raw body can
        # carry ids and is usually mostly noise; code+message is the part that ends the
        # diagnosis. And a body that yields nothing usable must SAY SO -- "HTTP 409 :"
        # with an empty reason reads as "no reason exists", which sent a whole session
        # chasing three wrong hypotheses while ARM had the answer all along
        # ("ReadOnlyDisabledSubscription -- the subscription is disabled and therefore
        # marked as read only").
        $detail = Get-PimRestErrorDetail -Body $body
        if ($detail) { throw "$Method $next -> HTTP $code : $detail$hintText" }
        throw "$Method $next -> HTTP $code : (no error body returned by the service)$hintText"
      }
    }
    if (-not $All) { return $resp }
    if ($null -ne $resp.value) { foreach ($v in $resp.value) { $agg.Add($v) } } else { $agg.Add($resp) }
    $next = $null
    if ($resp.'@odata.nextLink') { $next = $resp.'@odata.nextLink' }
    elseif ($resp.nextLink)      { $next = $resp.nextLink }
  }
  return $agg.ToArray()
}

function ConvertTo-PimSdkShape {
  # Make a Graph REST object look like a Graph PowerShell SDK object: add a
  # PascalCase alias for every camelCase property (userPrincipalName ->
  # UserPrincipalName, displayName -> DisplayName, id -> Id) so existing engine
  # filters/consumers that expect SDK casing keep working over pure REST.
  param([Parameter(ValueFromPipeline)][object]$InputObject)
  process {
    if ($null -eq $InputObject) { return }
    $o = [ordered]@{}
    foreach ($p in $InputObject.PSObject.Properties) {
      $o[$p.Name] = $p.Value
      if ($p.Name.Length -ge 1) {
        $pascal = $p.Name.Substring(0,1).ToUpperInvariant() + $p.Name.Substring(1)
        if (-not $o.Contains($pascal)) { $o[$pascal] = $p.Value }
      }
    }
    [pscustomobject]$o
  }
}

function Invoke-PimGraph {
  param([string]$Method='GET',[Parameter(Mandatory)][string]$Path,[object]$Body,[switch]$All,[switch]$Beta,[hashtable]$Headers=@{},[switch]$UseManagedIdentity)
  $base = if ($Beta) { 'https://graph.microsoft.com/beta' } else { 'https://graph.microsoft.com/v1.0' }
  $url = if ($Path -match '^https?://') { $Path } else { "$base$Path" }
  Invoke-PimRest -Method $Method -Url $url -Body $Body -Resource 'graph' -All:$All -Headers $Headers -UseManagedIdentity:$UseManagedIdentity
}
function Test-PimGraphBatchReadsEnabled {
  # Kill switch for the batched live reads (pim.Settings / $global:PIM_ / env 'GraphBatchReads').
  # ON by default; 'false' makes every caller take its original one-request-per-path loop.
  $v = $null
  if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) { try { $v = Get-PimPolicySetting -Name 'GraphBatchReads' -Default $null } catch { $v = $null } }
  elseif ($null -ne $global:PIM_GraphBatchReads) { $v = $global:PIM_GraphBatchReads }
  elseif ("$env:PIM_GraphBatchReads".Trim()) { $v = $env:PIM_GraphBatchReads }
  return -not ("$v".Trim() -match '^(?i)(false|0|no|off|disabled?)$')
}

function Invoke-PimGraphBatchGet {
  <#
    Run many Graph GETs through /$batch (20 per round-trip, Graph's maximum) and return ONE result per
    input path, IN INPUT ORDER: { path; ok; status; items; body; error }.
      items  = what `Invoke-PimGraph -All -Path <path>` returns: the aggregated .value across every
               @odata.nextLink page, or the body itself when it carries no .value.
      body   = what `Invoke-PimGraph -Path <path>` returns (the first page / the single object).
    A sub-request that is throttled (429), failed server-side (5xx) or came back missing is collected; the
    largest Retry-After is waited ONCE (max 30 s) and the collected items are sent again as a batch, up to 3
    rounds (§70.9). Only what is still unanswered after that is re-run on its own through Invoke-PimGraph,
    which owns the retry/backoff -- so a batch never loses a read that the sequential loop would have got.
    $script:PimBatchStats holds the counters of the last call. Any other 4xx is a final failure (ok=$false, error set), exactly
    what the sequential loop's `try { Invoke-PimGraph ... } catch { }` produced.
    A $batch response without `responses` (a proxy, a stub, a host that does not batch) falls back to
    the sequential path for that slice.
  #>
  param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Paths, [ValidateRange(1, 20)][int]$BatchSize = 20)
  $n = @($Paths).Count
  $results = New-Object object[] $n
  if ($n -eq 0) { return ,$results }
  $single = {
    param([string]$p)
    try {
      $first = Invoke-PimGraph -Path $p
      $items = New-Object System.Collections.Generic.List[object]
      $pg = $first
      while ($null -ne $pg) {
        if ($pg.PSObject -and $pg.PSObject.Properties['value']) { foreach ($v in @($pg.value)) { $items.Add($v) } } else { $items.Add($pg) }
        $nl = $null; if ($pg.PSObject -and $pg.PSObject.Properties['@odata.nextLink']) { $nl = "$($pg.'@odata.nextLink')" }
        if (-not $nl) { break }
        $pg = Invoke-PimGraph -Path $nl
      }
      [pscustomobject]@{ path = $p; ok = $true; status = 200; items = $items.ToArray(); body = $first; error = $null }
    } catch {
      [pscustomobject]@{ path = $p; ok = $false; status = 0; items = @(); body = $null; error = "$($_.Exception.Message)" }
    }
  }
  # 🔴 §70.9 (2026-09-13) -- THROTTLED ITEMS ARE WAITED OUT AND RE-BATCHED, NOT FIRED ONE BY ONE.
  # A 429 / 5xx sub-response used to be re-run IMMEDIATELY as its own single request, ignoring the Retry-After the
  # sub-response carried -- so under throttling a 20-item round-trip became up to 20 more calls into the same
  # throttle, each backing off on its own (2/4/8/16/32 s). Measured on internal: ~10 s per round-trip on the
  # group-membership read (35 round-trips, ~6 min) and the policy read (~570 s), with the cause invisible because
  # nothing counted the throttling. Now: collect the throttled items, wait the largest Retry-After once (bounded),
  # send them again AS A BATCH (up to 3 rounds), and only then fall back to the single-request path. Every call that
  # was throttled or slow says so in one [graph-batch] line.
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $script:PimBatchStats = @{ roundTrips = 0; throttled = 0; serverErrors = 0; retryRounds = 0; waitedSeconds = 0; singles = 0 }
  $sendBatch = {
    param([int[]]$Indexes)
    $pending = New-Object System.Collections.Generic.List[int]   # throttled / missing -> retry
    $maxRetryAfter = 0
    $requests = New-Object System.Collections.Generic.List[object]
    foreach ($i in $Indexes) {
      $rel = ("$($Paths[$i])" -replace '^https://graph\.microsoft\.com/(v1\.0|beta)', '')
      $requests.Add(@{ id = "$i"; method = 'GET'; url = $rel })
    }
    $resp = $null
    $script:PimBatchStats.roundTrips++
    try { $resp = Invoke-PimGraph -Method POST -Path 'https://graph.microsoft.com/v1.0/$batch' -Body @{ requests = $requests.ToArray() } } catch { $resp = $null }
    $subs = $null
    if ($null -ne $resp -and $resp.PSObject -and $resp.PSObject.Properties['responses']) { $subs = @($resp.responses) }
    if ($null -eq $subs) { return [pscustomobject]@{ pending = @(); maxRetryAfter = 0; batched = $false } }   # no batch support -> singles
    $want = @{}; foreach ($i in $Indexes) { $want[$i] = $true }
    foreach ($br in $subs) {
        if ($null -eq $br) { continue }
        $idx = -1; if (-not [int]::TryParse("$($br.id)", [ref]$idx)) { continue }
        if (-not $want.ContainsKey($idx)) { continue }
        $status = 0; [void][int]::TryParse("$($br.status)", [ref]$status)
        if ($status -eq 429 -or $status -ge 500) {
          if ($status -eq 429) { $script:PimBatchStats.throttled++ } else { $script:PimBatchStats.serverErrors++ }
          $ra = 0
          try { if ($br.headers) { foreach ($hp in $br.headers.PSObject.Properties) { if ("$($hp.Name)" -ieq 'Retry-After') { [void][int]::TryParse("$($hp.Value)", [ref]$ra) } } } } catch { }
          if ($ra -gt $maxRetryAfter) { $maxRetryAfter = $ra }
          $pending.Add($idx)
          continue
        }
        $body = $br.body
        if ($status -ge 200 -and $status -lt 300) {
          $items = New-Object System.Collections.Generic.List[object]
          $pg = $body; $ok = $true; $err = $null
          while ($null -ne $pg) {
            if ($pg.PSObject -and $pg.PSObject.Properties['value']) { foreach ($v in @($pg.value)) { $items.Add($v) } } else { $items.Add($pg) }
            $nl = $null; if ($pg.PSObject -and $pg.PSObject.Properties['@odata.nextLink']) { $nl = "$($pg.'@odata.nextLink')" }
            if (-not $nl) { break }
            try { $pg = Invoke-PimGraph -Path $nl } catch { $ok = $false; $err = "$($_.Exception.Message)"; break }
          }
          $results[$idx] = [pscustomobject]@{ path = $Paths[$idx]; ok = $ok; status = $status; items = @(if ($ok) { $items.ToArray() }); body = $body; error = $err }
        } else {
          $code = ''; $msg = ''
          if ($body -and $body.PSObject -and $body.PSObject.Properties['error'] -and $body.error) { $code = "$($body.error.code)"; $msg = "$($body.error.message)" }
          $results[$idx] = [pscustomobject]@{ path = $Paths[$idx]; ok = $false; status = $status; items = @(); body = $null
            error = ("GET {0} -> HTTP {1} : {2}{3}" -f $Paths[$idx], $status, $code, $(if ($msg) { " -- $msg" } else { '' })) }
        }
    }
    # an id Graph did not answer at all is retried like a throttled one
    foreach ($i in $Indexes) { if ($null -eq $results[$i] -and -not $pending.Contains($i)) { $pending.Add($i) } }
    return [pscustomobject]@{ pending = @($pending.ToArray()); maxRetryAfter = $maxRetryAfter; batched = $true }
  }
  $retryQueue = New-Object System.Collections.Generic.List[int]
  $maxRa = 0
  for ($ofs = 0; $ofs -lt $n; $ofs += $BatchSize) {
    $last = [Math]::Min($ofs + $BatchSize, $n) - 1
    $r = & $sendBatch -Indexes @($ofs..$last)
    foreach ($p in @($r.pending)) { $retryQueue.Add([int]$p) }
    if ($r.maxRetryAfter -gt $maxRa) { $maxRa = $r.maxRetryAfter }
  }
  # Up to 3 rounds: wait out the throttle ONCE for the whole queue, then send the queue again in batches.
  $round = 0
  while ($retryQueue.Count -gt 0 -and $round -lt 3) {
    $round++
    $script:PimBatchStats.retryRounds = $round
    $wait = [Math]::Min(30, [Math]::Max($maxRa, [int][Math]::Pow(2, $round)))
    $script:PimBatchStats.waitedSeconds += $wait
    if ($script:PimBatchSleep -is [scriptblock]) { & $script:PimBatchSleep $wait } else { Start-Sleep -Seconds $wait }   # test seam
    $queue = @($retryQueue.ToArray() | Where-Object { $null -eq $results[$_] })
    $retryQueue.Clear(); $maxRa = 0
    for ($o = 0; $o -lt $queue.Count; $o += $BatchSize) {
      $slice = @($queue[$o..([Math]::Min($o + $BatchSize, $queue.Count) - 1)])
      $r = & $sendBatch -Indexes $slice
      foreach ($p in @($r.pending)) { $retryQueue.Add([int]$p) }
      if ($r.maxRetryAfter -gt $maxRa) { $maxRa = $r.maxRetryAfter }
    }
  }
  # Anything still unanswered (still throttled after the rounds, or a host that does not batch): the single-request
  # path, which owns its own Retry-After/backoff -- so a batch never loses a read the sequential loop would have got.
  for ($i = 0; $i -lt $n; $i++) { if ($null -eq $results[$i]) { $script:PimBatchStats.singles++; $results[$i] = & $single $Paths[$i] } }
  $sw.Stop()
  $st = $script:PimBatchStats
  if ($st.throttled -or $st.serverErrors -or $st.singles -or $sw.Elapsed.TotalSeconds -ge 20) {
    Write-Host ("  [graph-batch] {0} path(s), {1} round-trip(s), {2} throttled (429), {3} server error(s), {4} retry round(s) waiting {5}s, {6} single fallback(s), {7:N1}s" -f `
      $n, $st.roundTrips, $st.throttled, $st.serverErrors, $st.retryRounds, $st.waitedSeconds, $st.singles, $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
  }
  return ,$results
}

function Get-PimArmActiveRoleAssignmentsViaArg {
  <#
    EVERY Azure RBAC role assignment visible to the engine identity, in ONE Azure Resource Graph query
    (POST /providers/Microsoft.ResourceGraph/resources, paged by $skipToken) -- management groups,
    subscriptions, resource groups and resources alike, with the role NAME joined in the same query.
    REST only: no Az module (REQUIREMENTS 67.3). Throws when the query fails, so a caller can say so
    and fall back instead of rendering an empty list as "no assignments".
    Output: { Id; Name; Scope; PrincipalId; PrincipalType; RoleDefinitionId (GUID); RoleDefinitionName }.
  #>
  param([int]$PageSize = 1000)
  $kql = @(
    'authorizationresources'
    '| where type =~ ''microsoft.authorization/roleassignments'''
    '| extend roleGuid = tolower(extract(''([^/]+)$'', 1, tostring(properties.roleDefinitionId)))'
    '| project id, name, scope = tostring(properties.scope), principalId = tostring(properties.principalId), principalType = tostring(properties.principalType), roleDefinitionId = tostring(properties.roleDefinitionId), roleGuid'
    '| join kind=leftouter (authorizationresources | where type =~ ''microsoft.authorization/roledefinitions'' | extend roleGuid = tolower(name) | summarize roleName = any(tostring(properties.roleName)) by roleGuid) on roleGuid'
    '| project id, name, scope, principalId, principalType, roleDefinitionId, roleGuid, roleName'
  ) -join ' '
  $out = New-Object System.Collections.Generic.List[object]
  $skipToken = $null
  do {
    $opts = @{ '$top' = $PageSize; resultFormat = 'objectArray' }
    if ($skipToken) { $opts['$skipToken'] = $skipToken }
    $resp = Invoke-PimArm -Method POST -Path '/providers/Microsoft.ResourceGraph/resources' -ApiVersion '2021-03-01' -Body @{ query = $kql; options = $opts }
    foreach ($r in @($resp.data)) {
      if ($null -eq $r) { continue }
      $guid = "$($r.roleGuid)"; if (-not $guid) { $guid = ("$($r.roleDefinitionId)" -split '/')[-1] }
      $out.Add([pscustomobject]@{
        Id = "$($r.id)"; Name = "$($r.name)"; Scope = "$($r.scope)"; PrincipalId = "$($r.principalId)"; PrincipalType = "$($r.principalType)"
        RoleDefinitionId = $guid; RoleDefinitionName = $(if ("$($r.roleName)".Trim()) { "$($r.roleName)" } else { $null })
      })
    }
    $skipToken = $null
    if ($resp -and $resp.PSObject.Properties['$skipToken'] -and "$($resp.'$skipToken')".Trim()) { $skipToken = "$($resp.'$skipToken')" }
  } while ($skipToken)
  # Unrolled on purpose: `@(Get-PimArmActiveRoleAssignmentsViaArg | ForEach-Object ...)` must see ROWS, not one array.
  return $out.ToArray()
}

function Invoke-PimArm {
  param([string]$Method='GET',[Parameter(Mandatory)][string]$Path,[object]$Body,[string]$ApiVersion='2022-04-01',[switch]$All,[hashtable]$Headers=@{})
  $url = if ($Path -match '^https?://') { $Path } else { "https://management.azure.com$Path" }
  if ($url -notmatch 'api-version=') { $url += ($(if ($url -match '\?') {'&'} else {'?'}) + "api-version=$ApiVersion") }
  Invoke-PimRest -Method $Method -Url $url -Body $Body -Resource 'arm' -All:$All -Headers $Headers
}
function Invoke-PimPowerBI {
  param([string]$Method='GET',[Parameter(Mandatory)][string]$Path,[object]$Body,[switch]$All,[hashtable]$Headers=@{})
  $url = if ($Path -match '^https?://') { $Path } else { "https://api.powerbi.com/v1.0/myorg$Path" }
  Invoke-PimRest -Method $Method -Url $url -Body $Body -Resource 'powerbi' -All:$All -Headers $Headers
}

# ---- Exchange Online (app-only, pure REST, NO ExchangeOnlineManagement) ----
# The EXO V3 PowerShell module's "REST-backed cmdlets" are thin wrappers around
# the Exchange admin REST endpoint:
#   POST https://outlook.office365.com/adminapi/beta/<tenant>/InvokeCommand
#   body { CmdletInput: { CmdletName: '<Verb-Noun>', Parameters: { ... } } }
# authenticated with an app-only token for the https://outlook.office365.com
# audience (the same Exchange.ManageAsApp consent the module needs). Calling
# this endpoint directly means the engine sets mailbox forwarding etc. with the
# engine SPN + certificate over PIM-Rest -- no module to Install-Module, no EXO
# V3 runspace-state bug, PS 5.1-safe. Anti-affinity routing (X-AnchorMailbox /
# Prefer) is unnecessary for tenant-admin cmdlets against the beta endpoint.
#
# NOTE on feasibility: NOT every EXO cmdlet is reachable this way -- some are
# session-bound or stream large result sets the InvokeCommand shape doesn't
# return cleanly. The engine's ONLY runtime EXO need is Set-Mailbox mail
# forwarding, which is a simple parameterized cmdlet and works over this path.
# Connect-ExchangeOnline itself becomes a no-op (token-per-call, no session).
function Get-PimExoTenantSegment {
  # The InvokeCommand path takes the tenant's *initial* domain or tenant GUID.
  param([string]$TenantId)
  $t = if ($TenantId) { $TenantId } elseif ($global:PIM_ExoOrganization) { $global:PIM_ExoOrganization } elseif ($global:PIM_TenantId) { $global:PIM_TenantId } else { Get-PimTenantId }
  if (-not $t) { throw "Invoke-PimExoCmdlet: no tenant/organization. Set -Organization, `$global:PIM_ExoOrganization (initial .onmicrosoft.com domain) or `$global:PIM_TenantId." }
  return $t
}
function Invoke-PimExoCmdlet {
  <#
    Run a single Exchange Online admin cmdlet app-only over REST.
      Invoke-PimExoCmdlet -CmdletName 'Set-Mailbox' -Parameters @{ Identity='u@x'; ForwardingSmtpAddress='a@b'; DeliverToMailboxAndForward=$false }
    Returns the cmdlet's .value payload (array) or the raw response.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$CmdletName,
    [hashtable]$Parameters = @{},
    [string]$Organization,
    [int]$MaxRetry = 5
  )
  $seg = Get-PimExoTenantSegment -TenantId $Organization
  $url = "https://outlook.office365.com/adminapi/beta/$seg/InvokeCommand"
  $body = @{ CmdletInput = @{ CmdletName = $CmdletName; Parameters = $Parameters } }
  $resp = Invoke-PimRest -Method POST -Url $url -Body $body -Resource 'exo' -MaxRetry $MaxRetry
  if ($null -ne $resp -and ($resp.PSObject.Properties.Name -contains 'value')) { return $resp.value }
  return $resp
}
function Test-PimMailForwardAddressIsReal {
  <#
    Shared sentinel predicate -- the engine apply path and the Manager validator
    (tools/pim-manager/_validator.ps1, PIM-DOMAIN-001) MUST agree on what counts
    as a real forwarding address. The Account-Definitions schema reuses the
    literal string 'FALSE' (and blanks / 'no' / '0' / 'none' / 'n/a') to mean
    "no forwarding address", so those values are NOT addresses and must never be
    forwarded to. Returns $true only for something shaped like an email address.
  #>
  [CmdletBinding()]
  param([AllowNull()][object]$Value)
  $s = ([string]$Value).Trim()
  if (-not $s) { return $false }
  switch ($s.ToUpperInvariant()) {
    'FALSE' { return $false }
    'NO'    { return $false }
    '0'     { return $false }
    'NONE'  { return $false }
    'N/A'   { return $false }
    default { return ($s -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') }
  }
}

function Get-PimAdminMailRecipient {
  <#
    THE ONE RECIPIENT RULE for mail PIM sends about an admin account (new-admin, tap-delivery).
    Shared by the engine (PIM-EngineProviders.ps1) and the Manager (Get-PimAdminTapRecipient), so
    the screen's "Sends to" is exactly the address the engine mails.

      ForwardMailsToContact = TRUE  AND  MailForwardAddress is a real address  -> MailForwardAddress
      else ManagerEmail, if it is a real address                               -> ManagerEmail
      else                                                                     -> ''  (caller refuses)

    🔑 Operator, 2026-09-12 ("Both"): MailForwardAddress is the admin OWNER's office user. An admin
    account has no mailbox of its own, so PIM's own mail goes to that office user; and where the admin
    account DOES have a mailbox, the engine also sets Exchange forwarding to it (gated, see
    Invoke-PimAdminMailboxForwarding). The columns were retired 2026-08-12 and are un-retired with
    this meaning.
    🪤 An address that is not an address ('FALSE'/'true' -- measured as live v1 data on internal) is
    NOT a recipient. Test-PimMailForwardAddressIsReal is the shared predicate; 'true' fails its
    address shape and is rejected here explicitly as well.
  #>
  [CmdletBinding()]
  param([AllowNull()][object]$Row)
  if ($null -eq $Row) { return '' }
  $get = {
    param($name)
    if ($Row -is [System.Collections.IDictionary]) { return "$($Row[$name])".Trim() }
    $p = $Row.PSObject.Properties[$name]
    if ($p) { return "$($p.Value)".Trim() }
    return ''
  }
  $isAddr = { param($v) ("$v" -notmatch '(?i)^(true|yes|1)$') -and (Test-PimMailForwardAddressIsReal -Value $v) }
  $fwdOn = ((& $get 'ForwardMailsToContact') -match '(?i)^(true|yes|1)$')
  $fwd   = & $get 'MailForwardAddress'
  if ($fwdOn -and (& $isAddr $fwd)) { return $fwd }
  $mgr = & $get 'ManagerEmail'
  if (& $isAddr $mgr) { return $mgr }
  return ''
}

function Test-PimAdminMailboxForwardingEnabled {
  <#
    Opt-in gate for setting Exchange mailbox forwarding on admin accounts. DEFAULT OFF, so rolling an
    image changes nothing until an operator turns it on: it needs an Exchange app permission
    (Exchange.ManageAsApp + an EXO role) whose grant model is still unresolved (§65.11).
    $global:PIM_AdminMailboxForwarding first, then $env:PIM_AdminMailboxForwarding (SEC-07 order,
    so a container-app setting is honoured). Only an explicit true/1/yes enables it.
  #>
  [CmdletBinding()]
  param([object]$Override = $null)
  $v = if ($null -ne $Override) { $Override }
       elseif ($null -ne $global:PIM_AdminMailboxForwarding -and "$($global:PIM_AdminMailboxForwarding)".Trim()) { $global:PIM_AdminMailboxForwarding }
       else { $env:PIM_AdminMailboxForwarding }
  return ("$v".Trim() -match '(?i)^(true|1|yes|on)$')
}

function Invoke-PimAdminMailboxForwarding {
  <#
    BEST-EFFORT, INERT-SAFE mailbox forwarding for ONE admin account. Never throws -- an admin
    apply must not fail because forwarding could not be set.

      gate OFF                                  -> 'disabled'   (no call at all)
      account has no mailbox                    -> 'no-mailbox' (Verbose only -- the NORMAL case:
                                                                 admin accounts usually hold no licence)
      flag TRUE + real address                  -> forward to it, DeliverToMailboxAndForward=$false
      flag not TRUE, mailbox currently forwards -> clear it
      flag not TRUE, nothing forwarded          -> 'nochange'
      401/403 from Graph or EXO                 -> ONE warning per run naming the permission, 'forbidden'

    -GraphInvoker / -ExoInvoker exist for offline tests; production uses Invoke-PimGraph and
    Set-PimMailboxForwarding / Invoke-PimExoCmdlet.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowNull()][object]$Row,
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [string]$UserId,
    [object]$Enabled = $null,
    [scriptblock]$GraphInvoker,
    [scriptblock]$ExoInvoker
  )
  try {
    if (-not (Test-PimAdminMailboxForwardingEnabled -Override $Enabled)) { return 'disabled' }
    $id = if ("$UserId".Trim()) { "$UserId".Trim() } else { $UserPrincipalName }
    $isForbidden = { param($err) ("$err" -match '(?i)\b(401|403)\b|Forbidden|Unauthorized|AccessDenied|Authorization_RequestDenied') }
    $warnOnce = {
      param($what)
      if (-not $script:PimAdminFwdForbiddenWarned) {
        $script:PimAdminFwdForbiddenWarned = $true
        Write-Warning ("  [AdminForwarding] $what was refused (401/403). Mailbox forwarding needs the Exchange " +
          "application permission Exchange.ManageAsApp plus an Exchange role (e.g. Mail Recipients) for the identity " +
          "the engine runs as. Skipping forwarding for every admin this run; nothing else is affected.")
      }
    }
    # 1. Does the account have a mailbox? (cheap: one GET, and the answer is usually "no")
    try {
      $null = if ($GraphInvoker) { & $GraphInvoker 'GET' "/users/$id/mailboxSettings" }
              else { Invoke-PimGraph -Method GET -Path "/users/$id/mailboxSettings" }
    } catch {
      $m = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
      if ($m -match '(?i)MailboxNotEnabledForRESTAPI|MailboxNotFound|ResourceNotFound|\b404\b|not found') {
        Write-Verbose "  [AdminForwarding] $UserPrincipalName has no mailbox -- nothing to forward."
        return 'no-mailbox'
      }
      if (& $isForbidden $m) { & $warnOnce 'Reading mailboxSettings'; return 'forbidden' }
      Write-Verbose "  [AdminForwarding] $UserPrincipalName mailbox probe failed: $m"
      return 'error'
    }
    # 2. Apply or clear.
    $flagOn = ("$(if ($Row -is [System.Collections.IDictionary]) { $Row['ForwardMailsToContact'] } else { $Row.ForwardMailsToContact })".Trim() -match '(?i)^(true|yes|1)$')
    $addr   = "$(if ($Row -is [System.Collections.IDictionary]) { $Row['MailForwardAddress'] } else { $Row.MailForwardAddress })".Trim()
    $exo = {
      param($cmd, $params)
      if ($ExoInvoker) { return (& $ExoInvoker $cmd $params) }
      return (Invoke-PimExoCmdlet -CmdletName $cmd -Parameters $params)
    }
    try {
      if ($flagOn -and (Test-PimMailForwardAddressIsReal -Value $addr) -and ($addr -notmatch '(?i)^(true|yes|1)$')) {
        & $exo 'Set-Mailbox' @{ Identity = $UserPrincipalName; ForwardingSmtpAddress = $addr; DeliverToMailboxAndForward = $false } | Out-Null
        return 'forwarded'
      }
      $cur = @(& $exo 'Get-Mailbox' @{ Identity = $UserPrincipalName })
      $curFwd = if ($cur.Count) { "$($cur[0].ForwardingSmtpAddress)".Trim() } else { '' }
      if (-not $curFwd) { return 'nochange' }
      & $exo 'Set-Mailbox' @{ Identity = $UserPrincipalName; ForwardingSmtpAddress = $null; DeliverToMailboxAndForward = $false } | Out-Null
      return 'cleared'
    } catch {
      $m = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
      if (& $isForbidden $m) { & $warnOnce 'Set-Mailbox'; return 'forbidden' }
      Write-Warning "  [AdminForwarding] $UserPrincipalName -- forwarding could not be set: $m (the admin account itself was applied)."
      return 'error'
    }
  } catch {
    Write-Verbose "  [AdminForwarding] $UserPrincipalName -- unexpected: $($_.Exception.Message)"
    return 'error'
  }
}

function Set-PimMailboxForwarding {
  <#
    Pure-REST equivalent of the engine's only runtime EXO call:
      Set-Mailbox -Identity <upn> -ForwardingSmtpAddress <smtp> -DeliverToMailboxAndForward:$false
    Pass -ForwardingSmtpAddress '' to CLEAR forwarding.

    Safety net: a 'FALSE'/sentinel address is treated as "no address" (clears
    forwarding) so the engine never forwards mail to the literal string 'FALSE'
    even if a caller forgets the upstream guard. Aligns with
    Test-PimMailForwardAddressIsReal in the validator.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Identity,
    [string]$ForwardingSmtpAddress,
    [bool]$DeliverToMailboxAndForward = $false,
    [string]$Organization
  )
  $p = @{ Identity = $Identity; DeliverToMailboxAndForward = $DeliverToMailboxAndForward }
  # EXO accepts a null to clear forwarding; an empty string is rejected. A
  # sentinel ('FALSE'/'no'/'0'/...) is NOT a real address -> clear instead.
  if (-not (Test-PimMailForwardAddressIsReal -Value $ForwardingSmtpAddress)) { $p['ForwardingSmtpAddress'] = $null }
  else { $p['ForwardingSmtpAddress'] = $ForwardingSmtpAddress }
  Invoke-PimExoCmdlet -CmdletName 'Set-Mailbox' -Parameters $p -Organization $Organization | Out-Null
}
