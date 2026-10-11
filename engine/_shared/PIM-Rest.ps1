<#
  PIM4EntraPS -- pure-REST auth + data plane (NO Graph/Az/MSAL modules).

  One place the whole solution gets tokens and calls Microsoft REST APIs, so the
  engine runs identically on Windows PowerShell 5.1, PowerShell 7, a VM, or a Linux
  container -- with nothing to Install-Module and no Azure.Core/Graph version clash.

  Token acquisition (auto-detected, override per call):
    * Managed Identity  -- App Service / Container Apps ($env:IDENTITY_ENDPOINT + IDENTITY_HEADER), an Azure Arc-enabled
                           server (IDENTITY_ENDPOINT + IMDS_ENDPOINT, 401 key-file challenge) or IMDS (VM)
    * Client secret     -- SPN client_credentials (v2 token endpoint)
    * Client certificate-- SPN, signed RS256 JWT client_assertion (no secret, no MSAL)
    * Signed-in source  -- a registered $global:PIM_TokenProvider (tools\setup\_PimSignedIn.ps1): the Invardia
                           Support session, else the person's browser sign-in (auth code + PKCE). No CLI, no module.

  Resolution order for credentials (all overridable via params):
    explicit params -> $global:PIM_* -> Managed Identity -> the signed-in token source -> (opt-in) browser sign-in.

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

function Add-PimRestSessionToken {
    <#
      97.1 -- hand a token the CALLER already holds (a setup script's browser sign-in: auth code + PKCE, no modules) to
      the token cache, so every Invoke-PimGraph / Invoke-PimArm / Invoke-PimRest / SQL call in THIS process uses it.
      Only for the attended interactive mode ($global:PIM_Interactive): the key is exactly the one Get-PimRestToken
      computes for that mode, so the engine's own identities (managed identity, certificate) can never pick it up.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Resource, [Parameter(Mandatory)][string]$Token, [datetime]$ExpiresUtc = ((Get-Date).ToUniversalTime().AddMinutes(50)), [string]$TenantId)
    $aud = Resolve-PimRestResource -Resource $Resource
    $tenant = Get-PimTenantId -TenantId $TenantId
    $cid = if ($global:PIM_ClientId) { $global:PIM_ClientId } elseif ($env:AZURE_CLIENT_ID) { $env:AZURE_CLIENT_ID } else { $null }
    if (-not $script:PimTokenCache) { $script:PimTokenCache = @{} }
    $script:PimTokenCache[("$aud|$tenant|$cid|interactive").ToLowerInvariant()] = [pscustomobject]@{ token = $Token; expiresUtc = $ExpiresUtc.ToUniversalTime() }
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
function Set-PimManagedIdentityHomeTenant {
  # LIC anti-copy (2026-10-03): the tid claim of a MANAGED IDENTITY token = the tenant this environment really runs in.
  # Recorded once per process in $global:PIM_ManagedIdentityTenantId; PIM-License.ps1 checks the licence against it, so a
  # licence cannot be made valid elsewhere by editing PIM_TenantId. Never throws.
  param([string]$Token)
  try {
    $seg = "$Token".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($seg.Length % 4) { $seg += '=' }
    $tid = "$(([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg)) | ConvertFrom-Json).tid)".Trim().ToLowerInvariant()
    if ($tid -match '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$') { $global:PIM_ManagedIdentityTenantId = $tid }
  } catch { }
}
# ---- Azure Arc-enabled server (§100.63(b), the on-premises hybrid worker) ---------------------------------------------
# The Arc agent (himds) serves the machine's system-assigned identity on http://localhost:40342 and sets IDENTITY_ENDPOINT
# + IMDS_ENDPOINT machine-wide -- but NO IDENTITY_HEADER (that is App Service / Container Apps). Its token call is a
# CHALLENGE: the first GET answers 401 with `WWW-Authenticate: Basic realm=<path to a .key file>`; the caller proves it may
# use the identity by READING that file (only local Administrators and the local group "Hybrid agent extension
# applications" can) and retries with `Authorization: Basic <file content>`. The file is single-use and short-lived.
# 🔒 The realm is checked before anything is read: a .key file directly under %ProgramData%\AzureConnectedMachineAgent\Tokens,
# at most 4 KB -- an endpoint that names any other file is refused (else a rogue local listener could make us send it the
# content of an arbitrary file we can read).
$script:PimArcDefaultEndpoint = 'http://localhost:40342/metadata/identity/oauth2/token'
function Get-PimArcTokenDirectory {
  if ("$($global:PIM_ArcTokenDirectory)".Trim()) { return "$($global:PIM_ArcTokenDirectory)".Trim() }   # offline test seam
  $pd = if ("$env:ProgramData".Trim()) { $env:ProgramData } else { 'C:\ProgramData' }
  return (Join-Path $pd 'AzureConnectedMachineAgent\Tokens')
}
function Get-PimArcIdentityEndpoint {
  # '' = not an Arc host. Arc = IDENTITY_ENDPOINT + IMDS_ENDPOINT set and no IDENTITY_HEADER / MSI_SECRET, or (env not yet
  # visible to this process -- a service started before the agent was installed) the himds service is present.
  if ($global:PIM_ArcIdentityEndpoint) { return "$($global:PIM_ArcIdentityEndpoint)" }   # offline test seam
  if ("$env:IDENTITY_HEADER".Trim() -or "$env:MSI_SECRET".Trim()) { return '' }
  if ("$env:IDENTITY_ENDPOINT".Trim() -and "$env:IMDS_ENDPOINT".Trim()) { return "$env:IDENTITY_ENDPOINT".Trim() }
  if ($global:PIM_NoManagedIdentity -or $global:PIM_NoArcProbe) { return '' }
  if ($null -eq $script:PimArcHimdsPresent) {
    $script:PimArcHimdsPresent = $false
    if ("$env:OS" -eq 'Windows_NT') { try { $script:PimArcHimdsPresent = [bool](Get-Service -Name 'himds' -ErrorAction Stop) } catch { $script:PimArcHimdsPresent = $false } }
  }
  if ($script:PimArcHimdsPresent) { return $script:PimArcDefaultEndpoint }
  return ''
}
function Test-PimArcKeyFilePath {
  # PURE. Is this realm path a file the Arc agent would hand out? Directly under the token directory, *.key, no traversal.
  param([AllowEmptyString()][string]$Path, [Parameter(Mandatory)][string]$TokenDirectory)
  $p = "$Path".Trim().Trim('"')
  if (-not $p -or $p -match '\.\.' -or $p -notmatch '(?i)\.key$') { return $false }
  $full = $null; $dir = $null
  try { $full = [IO.Path]::GetFullPath($p); $dir = [IO.Path]::GetFullPath($TokenDirectory).TrimEnd('\', '/') } catch { $full = $null }
  if (-not $full -or -not $dir) { return $false }
  return ([IO.Path]::GetDirectoryName($full).TrimEnd('\', '/') -ieq $dir)
}
function Invoke-PimArcIdentityHttp {
  # ONE GET against the local Arc endpoint that never throws on an HTTP status: returns status, WWW-Authenticate, body.
  # No proxy (on-premises servers often have a system proxy; localhost must never go through it). Seam: PIM_ArcIdentityHttpStub.
  param([Parameter(Mandatory)][string]$Uri, [hashtable]$Headers = @{}, [int]$TimeoutSec = 30)
  if ($global:PIM_ArcIdentityHttpStub -is [scriptblock]) { return (& $global:PIM_ArcIdentityHttpStub $Uri $Headers) }
  $req = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Uri)
  $req.Method = 'GET'; $req.Proxy = $null; $req.Timeout = $TimeoutSec * 1000; $req.ReadWriteTimeout = $TimeoutSec * 1000
  foreach ($k in $Headers.Keys) { $req.Headers[$k] = "$($Headers[$k])" }
  $resp = $null
  try { $resp = $req.GetResponse() }
  catch [System.Net.WebException] { $resp = $_.Exception.Response; if (-not $resp) { throw } }
  catch { if ($_.Exception.InnerException -is [System.Net.WebException] -and $_.Exception.InnerException.Response) { $resp = $_.Exception.InnerException.Response } else { throw } }
  $out = $null
  try {
    $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
    $body = $sr.ReadToEnd(); $sr.Close()
    $out = [pscustomobject]@{ status = [int]$resp.StatusCode; wwwAuthenticate = "$($resp.Headers['WWW-Authenticate'])"; body = $body }
  } finally { $resp.Close() }
  return $out
}
function Get-PimArcManagedIdentityToken {
  param([Parameter(Mandatory)][string]$Audience, [string]$Endpoint = '')
  $ep = if ("$Endpoint".Trim()) { "$Endpoint".Trim() } else { Get-PimArcIdentityEndpoint }
  if (-not $ep) { throw 'not an Azure Arc-enabled server (no IDENTITY_ENDPOINT/IMDS_ENDPOINT and no himds service)' }
  $u = "$($ep)?resource=$([uri]::EscapeDataString($Audience))&api-version=2020-06-01"
  $first = Invoke-PimArcIdentityHttp -Uri $u -Headers @{ Metadata = 'true' }
  $r = $first
  if ($first.status -eq 401) {
    $m = [regex]::Match("$($first.wwwAuthenticate)", '(?i)Basic\s+realm\s*=\s*"?([^"]+?)"?\s*$')
    if (-not $m.Success) { throw "Arc identity endpoint answered 401 without a Basic realm (WWW-Authenticate: '$($first.wwwAuthenticate)')" }
    $keyPath = $m.Groups[1].Value
    $dir = Get-PimArcTokenDirectory
    if (-not (Test-PimArcKeyFilePath -Path $keyPath -TokenDirectory $dir)) { throw "Arc identity endpoint named a key file outside '$dir' ('$keyPath') -- refusing to read it" }
    $len = -1; try { $len = (New-Object IO.FileInfo($keyPath)).Length } catch { $len = -1 }
    if ($len -gt 4096) { throw "Arc key file '$keyPath' is $len bytes (more than 4 KB) -- refusing" }
    $secret = $null; $readErr = $null
    try { $secret = [IO.File]::ReadAllText($keyPath).Trim() } catch { $readErr = $_.Exception }
    if ($readErr -is [System.UnauthorizedAccessException] -or ($readErr -and $readErr.InnerException -is [System.UnauthorizedAccessException])) {
      throw "cannot read the Arc key file '$keyPath' as $([Security.Principal.WindowsIdentity]::GetCurrent().Name) -- add this account to the local group 'Hybrid agent extension applications' (or run as a local administrator), then start a new process"
    }
    if ($readErr) { throw "cannot read the Arc key file '$keyPath': $($readErr.Message)" }
    if (-not $secret) { throw "the Arc key file '$keyPath' is empty" }
    $r = Invoke-PimArcIdentityHttp -Uri $u -Headers @{ Metadata = 'true'; Authorization = "Basic $secret" }
    $secret = $null
  }
  if ($r.status -ne 200) { throw "Arc identity endpoint answered HTTP $($r.status) for $Audience : $("$($r.body)".Substring(0, [Math]::Min(300, "$($r.body)".Length)))" }
  $j = "$($r.body)" | ConvertFrom-Json
  if (-not "$($j.access_token)") { throw "Arc identity endpoint returned no access_token for $Audience" }
  return [pscustomobject]@{ token = "$($j.access_token)"; expiresUtc = (ConvertTo-PimTokenExpiry $j.expires_on) }
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
    $r = Invoke-RestMethod -Method GET -Uri $u -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER } -TimeoutSec 60
    # §100.46: in the tick this is a start-up diagnostic (printed with the start-up block: on change / first of the day / PIM_LOG_VERBOSE=1)
    if ("$($r.access_token)") { $__mil = "  [mi] token via IDENTITY_ENDPOINT (len $($r.access_token.Length))"; if ($global:PIM_LogQuiet -and (Get-Command Write-PimStartupLine -ErrorAction SilentlyContinue)) { Write-PimStartupLine -Message $__mil } else { try { [System.Console]::Out.WriteLine($__mil) } catch {} } }  # Console.Out (not Write-Host): headless-safe from any scope (App Service has no console buffer; Write-Host throws there even from module scope)
    Set-PimManagedIdentityHomeTenant -Token "$($r.access_token)"; return [pscustomobject]@{ token = $r.access_token; expiresUtc = (ConvertTo-PimTokenExpiry $r.expires_on) }
  }
  # App Service (older / some Linux SKUs): MSI_ENDPOINT + MSI_SECRET (api 2017-09-01, header 'Secret')
  if ($env:MSI_ENDPOINT -and $env:MSI_SECRET) {
    $u = "$($env:MSI_ENDPOINT)?resource=$res&api-version=2017-09-01"
    $r = Invoke-RestMethod -Method GET -Uri $u -Headers @{ 'Secret' = $env:MSI_SECRET } -TimeoutSec 60
    if ("$($r.access_token)") { try { [System.Console]::Out.WriteLine("  [mi] token via MSI_ENDPOINT (len $($r.access_token.Length))") } catch {} }  # Console.Out: headless-safe from any scope
    Set-PimManagedIdentityHomeTenant -Token "$($r.access_token)"; return [pscustomobject]@{ token = $r.access_token; expiresUtc = (ConvertTo-PimTokenExpiry $r.expires_on) }
  }
  # Azure Arc-enabled server (on-premises hybrid worker, §100.63(b)): IDENTITY_ENDPOINT without IDENTITY_HEADER, 401 challenge
  if (Get-PimArcIdentityEndpoint) {
    $a = Get-PimArcManagedIdentityToken -Audience $Audience
    try { [System.Console]::Out.WriteLine("  [mi] token via the Azure Arc agent (len $($a.token.Length))") } catch {}
    Set-PimManagedIdentityHomeTenant -Token "$($a.token)"; return $a
  }
  # IMDS (Azure VM)
  $u = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$res"
  if ($global:PIM_ManagedIdentityClientId) { $u += "&client_id=$($global:PIM_ManagedIdentityClientId)" }
  $r = Invoke-RestMethod -Method GET -Uri $u -Headers @{ Metadata = 'true' } -TimeoutSec 5
  Set-PimManagedIdentityHomeTenant -Token "$($r.access_token)"; return [pscustomobject]@{ token = $r.access_token; expiresUtc = (ConvertTo-PimTokenExpiry $r.expires_on) }
}

# ---- SPN client secret ----------------------------------------------------
function Get-PimClientSecretToken {
  param([Parameter(Mandatory)][string]$TenantId,[Parameter(Mandatory)][string]$ClientId,[Parameter(Mandatory)][string]$ClientSecret,[Parameter(Mandatory)][string]$Audience)
  $body = @{ grant_type='client_credentials'; client_id=$ClientId; client_secret=$ClientSecret; scope="$Audience/.default" }
  $r = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body $body -TimeoutSec 60
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
  $r = Invoke-RestMethod -Method POST -Uri $tokenUrl -ContentType 'application/x-www-form-urlencoded' -Body $body -TimeoutSec 60
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
function Get-PimInteractiveClientId {
  <# PURE. The first-party public client for a browser sign-in to -Audience: Graph -> the Microsoft Graph CLI client
     (pre-authorised for Graph only); everything else (ARM, Azure SQL, Key Vault, Storage) -> the Microsoft Azure CLI
     client APP ID (an app registration id used over REST, not the az program). AADSTS650057 on ARM, 2026-10-10. #>
  param([string]$Audience)
  # ONE client for every audience (2026-10-10, a customer's install stalled on a hidden SECOND sign-in window when Graph
  # used a different client): the Azure CLI first-party public client is pre-authorised for Graph AND ARM / SQL / Key
  # Vault / Storage in every tenant, so ONE browser sign-in serves all of them through its refresh token.
  return '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
}

# REQ 100.76 (2026-10-11, a new customer's hosting step: "Login failed for user '<token-identified principal>'"): a signed-in
# build hands its step processes the person's REFRESH token(s) for the target tenant in $env:PIM_HANDOFF_REFRESH
# ({ "<tenant>|<public client id>": "<refresh token>" }, that process's environment only), instead of a pre-minted Azure SQL
# ACCESS token. The step creates the SQL server, sets its Entra admin and adds the person to the SQL admin group AFTER the
# build minted, so only a token minted at connect time carries that right. Entries for another tenant are never taken.
function Import-PimHandoffRefresh {
  param([string]$TenantId, [string]$Json = "$env:PIM_HANDOFF_REFRESH")
  if (-not "$Json".Trim()) { return 0 }
  if (-not ($global:PimInteractiveRefresh -is [hashtable])) { $global:PimInteractiveRefresh = @{} }
  $want = "$TenantId".Trim().ToLowerInvariant(); $n = 0
  try { $o = "$Json" | ConvertFrom-Json } catch { Write-Verbose "PIM_HANDOFF_REFRESH unreadable: $($_.Exception.Message)"; return 0 }
  foreach ($p in @($o.PSObject.Properties)) {
    $k = "$($p.Name)".Trim().ToLowerInvariant(); $v = "$($p.Value)".Trim()
    if (-not $v -or $k -notmatch '^[^|]+\|[^|]+$') { continue }
    if ($want -and $k.Split('|')[0] -ne $want) { continue }
    if (-not $global:PimInteractiveRefresh.ContainsKey($k)) { $global:PimInteractiveRefresh[$k] = $v; $n++ }
  }
  return $n
}

# REQ 100.76: the refresh tokens a signed-in build hands a step for -TenantId, as the JSON for $env:PIM_HANDOFF_REFRESH
# ('' when there are none). Pure over -Map (default: this process's in-memory refresh map).
function Get-PimHandoffRefreshJson {
  param([Parameter(Mandatory)][string]$TenantId, [object]$Map = $global:PimInteractiveRefresh)
  if (-not ($Map -is [hashtable]) -or -not $Map.Count) { return '' }
  $want = "$TenantId".Trim().ToLowerInvariant(); $out = [ordered]@{}
  foreach ($k in @($Map.Keys)) { $kl = "$k".ToLowerInvariant(); if ($kl.Split('|')[0] -eq $want -and "$($Map[$k])".Trim()) { $out[$kl] = "$($Map[$k])" } }
  if (-not $out.Count) { return '' }
  return ($out | ConvertTo-Json -Compress)
}

function Get-PimInteractiveToken {
  param([Parameter(Mandatory)][string]$Audience,[string]$TenantId,[string]$ClientId,
        # section 9 account sign-in clarity: force a brand-new credential prompt (prompt=login)
        # instead of reusing a cached account. -ExpectedAccount, if the cached account
        # differs, also forces a fresh prompt so a stale account is never used silently.
        [switch]$ForceFreshAccount,[string]$ExpectedAccount,
        # REQ 100.76: only the silent refresh-token exchange -- $null instead of a browser window when there is none.
        [switch]$RefreshOnly)
  $tenant = if ($TenantId) { $TenantId } elseif (Get-PimTenantId) { Get-PimTenantId } else { 'organizations' }
  # Default public client PER AUDIENCE (2026-10-10, a customer's managed install failed with AADSTS650057 "Invalid
  # resource" for ARM): the Microsoft Graph CLI client (14d82eec-...) is pre-authorised for GRAPH only. Azure Resource
  # Manager, Azure SQL, Key Vault and Storage use the Microsoft Azure CLI first-party public client APP ID
  # (04b07795-..., an app registration id used over REST -- not the az program), pre-authorised for those in every tenant.
  $cid = if ($ClientId) { $ClientId } elseif ($global:PIM_InteractiveClientId) { $global:PIM_InteractiveClientId } else { Get-PimInteractiveClientId -Audience $Audience }

  # ONE sign-in: a refresh token from an earlier browser sign-in (same tenant + client) is exchanged for this audience --
  # no second window. Falls through to the browser only when there is none or the exchange is refused.
  if (-not $global:PimInteractiveRefresh) { $global:PimInteractiveRefresh = @{} }
  $rtKey = "$tenant|$cid".ToLowerInvariant()
  if (-not $global:PimInteractiveRefresh.ContainsKey($rtKey)) { [void](Import-PimHandoffRefresh -TenantId $tenant) }
  if ($global:PimInteractiveRefresh.ContainsKey($rtKey) -and -not $ForceFreshAccount) {
    try {
      $rr = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id = $cid; grant_type = 'refresh_token'; refresh_token = $global:PimInteractiveRefresh[$rtKey]
        scope = "$Audience/.default offline_access openid profile" }
      if ($rr.refresh_token) { $global:PimInteractiveRefresh[$rtKey] = $rr.refresh_token }
      if ($rr.access_token) { return [pscustomobject]@{ token = $rr.access_token; expiresUtc = (Get-Date).ToUniversalTime().AddSeconds([int]$rr.expires_in - 60) } }
    } catch { Write-Verbose "refresh-token exchange for $Audience refused: $($_.Exception.Message) -- browser sign-in" }
  }
  if ($RefreshOnly) { return $null }

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
  # 2026-10-10: tell the installer's progress feed BEFORE a browser window opens (a hidden window waited silently and the
  # customer saw "nothing happening"); the installer registers $global:PIM_SignInNotify.
  if ($global:PIM_SignInNotify -is [scriptblock]) { try { & $global:PIM_SignInNotify $Audience $tenant } catch { } }
  # A person whose browser opens in the wrong profile can paste the address into the right one (2026-10-10).
  Write-Host "  If the browser opens in the wrong profile or account, open this address in the browser profile of an admin of tenant ${tenant}:" -ForegroundColor Yellow
  Write-Host "  $authUrl" -ForegroundColor DarkGray
  # 2026-10-10 (a customer's install): a normal Edge window opens the DEFAULT profile, whose saved account signs in silently
  # -- the person never got a credential prompt and landed in the wrong tenant. An InPrivate window has no saved account,
  # so the sign-in form always appears. PIM_SIGNIN_BROWSER=none: open nothing, the person pastes the address above.
  $mode = "$env:PIM_SIGNIN_BROWSER".Trim().ToLowerInvariant()
  if ($mode -eq 'none') { Write-Host '  (PIM_SIGNIN_BROWSER=none: no browser opened -- paste the address above into the right browser)' -ForegroundColor Yellow }
  elseif ($edge) { Start-Process -FilePath $edge -ArgumentList @('--inprivate', '--new-window', $authUrl) -WhatIf:$false }
  else { Start-Process $authUrl -WhatIf:$false }   # fall back to default browser if Edge absent

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
  # The account must belong to the TARGET tenant: a token from another tenant (wrong browser profile / account) stops here,
  # before any call is made with it.
  if ($tenant -match '^[0-9a-fA-F-]{36}$') {
    $tid = ''
    try {
      $pp = "$($r.access_token)".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($pp.Length % 4) { $pp += '=' }
      $tid = "$(([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($pp)) | ConvertFrom-Json).tid)".Trim()
    } catch { $tid = '' }
    if ($tid -and $tid -ne $tenant) { throw "You signed in to tenant $tid, but this is for tenant $tenant -- sign in with an account of $tenant (use that admin's browser profile)." }
  }
  if ($r.refresh_token) { $global:PimInteractiveRefresh["$tenant|$cid".ToLowerInvariant()] = $r.refresh_token }   # in memory only, never written
  return [pscustomobject]@{ token = $r.access_token; expiresUtc = (Get-Date).ToUniversalTime().AddSeconds([int]$r.expires_in - 60) }
}

# ---- framework 8.13 INSTALL-HANDOFF: one sign-in across Invardia's bootstrap and the product installer ----
# Invardia's bootstrap (Install-Invardia) signs the person in ONCE (browser PKCE, or the Cloud Shell user token) and, in
# the SAME process, just before it calls Install-PimManager, sets $env:PIM_HANDOFF_TOKENS =
#   { "https://management.azure.com/": { "access_token": "...", "expires_on": <epoch seconds> }, "https://graph.microsoft.com/": {...},
#     "https://database.windows.net/": {...} }
# ACCESS tokens only (no refresh token crosses the boundary); an audience it could not get is simply absent; it removes
# the variable in a finally block. Install-PimManager reads it ONCE (Import-PimHandoffTokens), clears it, and keeps only
# the tokens that pass the checks below in $global:PimHandoffTokens -- memory only, never a file, log, transcript or event.
# Every check is on the token's OWN claims (no signature check: this is our own process boundary, and the resource still
# validates the signature on every call).
#   tid       == the installation's tenant (config.tenantId). A mismatch on ANY audience refuses the WHOLE handoff: the
#                bootstrap signed in to a different tenant than the answers name, so none of it is trusted.
#   a USER    the token must be DELEGATED: Entra puts 'scp' only in delegated (user) tokens and 'roles' only (no scp) in
#                application tokens; 'idtyp' is an OPTIONAL claim, so 'idtyp = app' refuses but its absence proves nothing.
#                Rule: idtyp is not 'app' AND scp is present AND oid is a GUID. ('roles' beside scp is allowed: a user can
#                hold app roles.)
#   expiry    the earlier of expires_on and the JWT's exp must be more than 5 minutes away.
# A token failing a check (other than the tenant) is refused for ITS audience only; that audience falls back to PIM's own
# browser sign-in (Get-PimInteractiveToken, pinned to the tenant) when it is first needed, and that sign-in's in-memory
# refresh token then covers the other audiences PIM needs later.

function Get-PimHandoffAudienceKey {
  # PURE. The comparison key of an audience: 'https://management.azure.com/' and 'https://management.azure.com' are one.
  param([string]$Audience)
  return "$Audience".Trim().TrimEnd('/').ToLowerInvariant()
}

function ConvertFrom-PimHandoffJwt {
  # PURE. The payload claims of a JWT, or $null for anything that is not one. Never throws; never returns the token.
  param([string]$Token)
  try {
    $parts = "$Token".Split('.')
    if ($parts.Count -ne 3 -or -not $parts[1]) { return $null }
    $p = $parts[1].Replace('-', '+').Replace('_', '/')
    while ($p.Length % 4) { $p += '=' }
    $c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $c -or $c -is [string] -or $c -is [ValueType]) { return $null }
    return $c
  } catch { return $null }
}

function ConvertTo-PimHandoffExpiry {
  # PURE. expires_on as a bootstrap hands it over -- epoch seconds (number or digit string: the MSAL / managed-identity /
  # Cloud Shell shape) or a date -- as a UTC [datetime], or $null when it cannot be read.
  param($Value)
  if ($null -eq $Value) { return $null }
  if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
  if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
  $s = "$Value".Trim()
  if (-not $s) { return $null }
  if ($s -match '^\d{9,11}(\.\d+)?$') { try { return [DateTimeOffset]::FromUnixTimeSeconds([long][math]::Floor([double]$s)).UtcDateTime } catch { return $null } }
  $d = [DateTimeOffset]::MinValue
  if ([DateTimeOffset]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d.UtcDateTime }
  return $null
}

function Test-PimHandoffToken {
  <#
    PURE given -NowUtc. Check ONE handed-over access token (see the block above). Returns
    @{ ok; tenantMismatch; reason; expiresUtc; userName }. The reason never contains token text.
  #>
  param([string]$Token, $ExpiresOn, [Parameter(Mandatory)][string]$TenantId, [datetime]$NowUtc = [datetime]::UtcNow, [int]$MinValidityMinutes = 5)
  $no = { param($why, [bool]$mismatch = $false) @{ ok = $false; tenantMismatch = $mismatch; reason = $why; expiresUtc = $null; userName = '' } }
  if (-not "$Token".Trim()) { return (& $no 'no access token was handed over') }
  $c = ConvertFrom-PimHandoffJwt -Token $Token
  if (-not $c) { return (& $no 'it is not a readable access token') }
  $want = "$TenantId".Trim().ToLowerInvariant()
  $tid = "$($c.tid)".Trim().ToLowerInvariant()
  if (-not $tid) { return (& $no 'it names no tenant (no tid claim)') }
  if ($tid -ne $want) { return (& $no "it is for tenant $tid, not this installation's tenant $want" $true) }
  $idtyp = "$($c.idtyp)".Trim().ToLowerInvariant()
  if ($idtyp -eq 'app' -or -not "$($c.scp)".Trim()) { return (& $no 'it is an application token, not a signed-in user''s (idtyp=app or no delegated scp claim)') }
  if ("$($c.oid)".Trim() -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return (& $no 'it carries no user object id (oid)') }
  $given = ConvertTo-PimHandoffExpiry -Value $ExpiresOn
  $jwtExp = $null
  if ("$($c.exp)".Trim() -match '^\d+$') { try { $jwtExp = [DateTimeOffset]::FromUnixTimeSeconds([long]"$($c.exp)".Trim()).UtcDateTime } catch { $jwtExp = $null } }
  $eff = @(@($given, $jwtExp) | Where-Object { $_ } | Sort-Object) | Select-Object -First 1
  if (-not $eff) { return (& $no 'it carries no expiry (no expires_on and no exp claim)') }
  if ($eff -le $NowUtc.ToUniversalTime().AddMinutes($MinValidityMinutes)) {
    return (& $no ("it expires at {0:yyyy-MM-dd HH:mm} UTC -- less than {1} minutes left" -f $eff, $MinValidityMinutes))
  }
  $upn = "$(if ($c.upn) { $c.upn } elseif ($c.unique_name) { $c.unique_name } elseif ($c.preferred_username) { $c.preferred_username } else { '' })".Trim()
  return @{ ok = $true; tenantMismatch = $false; reason = ''; expiresUtc = $eff; userName = $upn }
}

function Import-PimHandoffTokens {
  <#
    PURE given -NowUtc. Read the bootstrap's PIM_HANDOFF_TOKENS JSON and check every audience against -TenantId.
    Returns @{ present; refused; reason; accepted = @{ <audience key> = @{ token; expiresUtc } }; fallback = @(@{ audience; reason }) }.
      refused = a token for ANOTHER tenant was handed over: NOTHING is accepted (reason names the audience and both tenants).
      fallback = audiences that were handed over but refused (each falls back to the browser sign-in when it is needed).
    The values in 'accepted' are the only place the tokens go; the caller keeps them in memory and never prints them.
  #>
  param([string]$Json, [Parameter(Mandatory)][string]$TenantId, [datetime]$NowUtc = [datetime]::UtcNow)
  $out = @{ present = $false; refused = $false; reason = ''; accepted = @{}; fallback = @() }
  if (-not "$Json".Trim()) { return $out }
  $out.present = $true
  $o = $null
  try { $o = $Json | ConvertFrom-Json -ErrorAction Stop } catch { $o = $null }
  if ($null -eq $o -or $o -is [string] -or $o -is [ValueType] -or $o -is [System.Array]) {
    $out.fallback = @(@{ audience = '(all)'; reason = 'the handed-over sign-in could not be read (not a JSON object)' })
    return $out
  }
  $mismatch = @()
  foreach ($p in $o.PSObject.Properties) {
    $v = $p.Value
    $tok = ''; $exp = $null
    if ($v -is [string]) { $tok = $v }
    elseif ($null -ne $v -and $v.PSObject.Properties['access_token']) { $tok = "$($v.access_token)"; if ($v.PSObject.Properties['expires_on']) { $exp = $v.expires_on } }
    $t = Test-PimHandoffToken -Token $tok -ExpiresOn $exp -TenantId $TenantId -NowUtc $NowUtc
    if ($t.tenantMismatch) { $mismatch += "$($p.Name): $($t.reason)" }
    elseif ($t.ok) { $out.accepted[(Get-PimHandoffAudienceKey $p.Name)] = @{ token = $tok; expiresUtc = $t.expiresUtc; userName = $t.userName } }
    else { $out.fallback += @{ audience = "$($p.Name)"; reason = $t.reason } }
    $tok = $null
  }
  if ($mismatch.Count) {
    $out.refused = $true
    $out.accepted = @{}
    $out.reason = ('the sign-in handed over by Invardia''s installer is REFUSED as a whole -- ' + ($mismatch -join '; ') +
                   '. It signed in to a different tenant than the installation answers name; nothing from it is used.')
  }
  return $out
}

function Get-PimHandoffToken {
  <# The validated handed-over access token for -Audience in -TenantId ($global:PimHandoffTokens, memory only), or '' when
     there is none, it is for another tenant, or it has under 2 minutes left (then the normal sign-in answers). #>
  param([string]$Audience, [string]$TenantId)
  $h = $global:PimHandoffTokens
  if (-not ($h -is [hashtable]) -or -not ($h.tokens -is [hashtable]) -or -not $h.tokens.Count) { return '' }
  if (-not "$TenantId".Trim() -or "$($h.tenantId)".Trim().ToLowerInvariant() -ne "$TenantId".Trim().ToLowerInvariant()) { return '' }
  $e = $h.tokens[(Get-PimHandoffAudienceKey $Audience)]
  if (-not $e -or -not "$($e.token)".Trim()) { return '' }
  if ($e.expiresUtc -le [datetime]::UtcNow.AddMinutes(2)) { return '' }
  return "$($e.token)"
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
  # became "no explicit identity was asked for" and slid onto the (since removed) ambient command-line fallback.
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
  # groups missing from the managed tenant it was supposed to be managing. A write-shaped run would
  # have applied the customer's desired state to the MSP's own tenant.
  #
  # The key is now the full identity: audience + tenant + client + credential KIND (and the
  # cert thumbprint, so rotating a cert re-mints rather than serving the old token). No
  # secret material goes into the key.
  $mode = if ($Interactive -or $global:PIM_Interactive) { 'interactive' }
          elseif ($UseManagedIdentity -or $global:PIM_UseManagedIdentity -or ($env:IDENTITY_ENDPOINT -and -not $cid)) { 'mi' }
          elseif ($sec) { 'secret' }
          elseif ($cert) { "cert:$thumb" }
          elseif ($global:PIM_TokenProvider -is [scriptblock]) { 'signed-in' }
          else { 'unknown' }
  $key = ("$aud|$tenant|$cid|$mode").ToLowerInvariant()
  # same cross-scope guard as Resolve-PimRestResource: an unseeded cache must mean "cache
  # miss", never a thrown method call that the caller reads as "authentication failed".
  if (-not $script:PimTokenCache) { $script:PimTokenCache = @{} }
  if (-not $Force -and $script:PimTokenCache.ContainsKey($key)) {
    $e = $script:PimTokenCache[$key]
    if ($e.expiresUtc -gt (Get-Date).ToUniversalTime().AddMinutes(2)) { return $e.token }
  }

  # Framework 8.13 INSTALL-HANDOFF (REQ 100.66): the sign-in Invardia's bootstrap handed this process, already validated by
  # Import-PimHandoffTokens (this tenant, a USER, >5 min left) and held in memory only, answers FIRST for its audiences --
  # but never for a caller that named an explicit identity, and never for an explicit browser request (-Interactive, which
  # may need scopes the handed-over token does not carry). An audience it does not cover falls through to the sign-in below.
  # 🔴 2026-10-11 (HOGYM managed install, live): NEVER for Azure SQL. The handed-over database token is minted by the bootstrap
  # BEFORE this run creates the SQL server and makes the signed-in admin (or its group) the server's Entra admin -- that token
  # carries no such membership, and the schema step failed "Login failed for user '<token-identified principal>'". The
  # database audience always comes from a sign-in made now (after the assignment).
  if (-not $explicitIdentity -and -not ($Interactive -or $global:PIM_Interactive) -and "$aud" -notmatch '(?i)database\.windows\.net') {
    $hk = Get-PimHandoffToken -Audience $aud -TenantId $tenant
    if ($hk) { return $hk }
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
  # client id + its certificate thumbprint, and got back a token for ANOTHER company's tenant
  # (A DIFFERENT COMPANY's tenant) with a different appid. Nothing in the return value
  # said so. The certificate had failed to resolve, the failure went to Write-Verbose, and the
  # "dev convenience" command-line fallback (since removed, REQ 100.42) then minted a token for whatever
  # subscription happened to be that tool's DEFAULT context -- which on the dev machine is frequently another
  # tenant entirely.
  #
  # 🔑 THE POINT IS NOT THAT THE FALLBACK EXISTS. It is that it ran AFTER the caller had named a
  # tenant, a client id and a credential. That caller has said exactly who it wants to be, and
  # answering with a different principal is WORSE than answering with an error: the token works,
  # so the failure surfaces far away as "Login failed" or "permission denied" and reads like an
  # RBAC problem. It cost a session's time to chase, and the answer was three layers up.
  #
  # 📌 Same family as BUG-34, which fixed precisely this shape one layer down in
  # New-PimSqlConnection ("a valid-but-wrong-tenant token was taken, so the explicitly
  # configured SPN never got a turn") and left the command-line branch here standing (removed since, REQ 100.42).
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

  # §100.42 / framework §12.17 (owner 2026-10-09: "modern single connect only"): the command-line fallback ("reuse
  # whoever is signed in to the CLI") is GONE. A signed-in setup run does not borrow a tool's session any more:
  # tools\setup\_PimSignedIn.ps1 (Set-PimSignedInGlobals) REGISTERS its token source here --
  # the Invardia Support-app session's Get-InvardiaSupportToken when that session is open in the shell, otherwise the
  # person's own browser sign-in (Get-PimInteractiveToken, auth-code + PKCE). Only reached when NO explicit identity
  # was requested (the refusal above still throws for one that cannot be honoured).
  # 2026-10-10: a setup step's OWN child processes (e.g. the schema step) inherit PIM_HANDOFF_TOKENS from the build -- answer
  # from it first, so no grandchild process opens a silent browser sign-in.
  # 8.13: either shape is read -- the build's own (audience -> token string) or the bootstrap's (audience -> {access_token,
  # expires_on}) -- and a token whose tid is not the requested tenant is never returned (SEC-12).
  if (-not $res -and "$env:PIM_HANDOFF_TOKENS".Trim() -and -not $explicitIdentity) {
    try {
      $ho = "$env:PIM_HANDOFF_TOKENS" | ConvertFrom-Json
      foreach ($pp in $ho.PSObject.Properties) {
        if ("$($pp.Name)".TrimEnd('/').ToLowerInvariant() -eq "$aud".TrimEnd('/').ToLowerInvariant()) {
          # REQ 100.76: with a handed-over refresh token, Azure SQL is never answered from a pre-minted access token.
          if ("$aud" -match '(?i)database\.windows\.net' -and "$env:PIM_HANDOFF_REFRESH".Trim()) { continue }
          $hv = if ($pp.Value -is [string]) { "$($pp.Value)" } elseif ($pp.Value -and $pp.Value.PSObject.Properties['access_token']) { "$($pp.Value.access_token)" } else { '' }
          if (-not "$hv".Trim()) { continue }
          $hvTid = Get-PimTokenTenantId -Token $hv
          if ("$tenant".Trim() -and $hvTid -and $hvTid -ne "$tenant".Trim().ToLowerInvariant()) { Write-Verbose "PIM_HANDOFF_TOKENS: the token for $aud is for another tenant -- not used"; continue }
          return $hv
        }
      }
    } catch { Write-Verbose "PIM_HANDOFF_TOKENS unreadable: $($_.Exception.Message)" }
  }
  # REQ 100.76: a step's child process with no token source of its own mints from the handed-over refresh token -- silently,
  # at the moment it is asked (never a browser window from here).
  if (-not $res -and "$env:PIM_HANDOFF_REFRESH".Trim() -and -not $explicitIdentity -and -not ($global:PIM_TokenProvider -is [scriptblock])) {
    try { $res = Get-PimInteractiveToken -Audience $aud -TenantId $tenant -RefreshOnly } catch { Write-Verbose "PIM_HANDOFF_REFRESH exchange for ${Resource} failed: $($_.Exception.Message)" }
  }
  if (-not $res -and ($global:PIM_TokenProvider -is [scriptblock])) {
    $pt = $null
    try { $pt = & $global:PIM_TokenProvider $aud $tenant } catch { throw "PIM-Rest: the signed-in token source failed for '$Resource': $($_.Exception.Message)" }
    if ($pt -is [string]) { $pt = [pscustomobject]@{ token = $pt; expiresUtc = (Get-Date).ToUniversalTime().AddMinutes(30) } }
    if ($pt -and "$($pt.token)".Trim()) {
      # 🔒 VERIFY IT (SEC-12): asking for a tenant is not the same as being given one.
      $claimed = Get-PimTokenTenantId -Token "$($pt.token)"
      if ("$tenant".Trim() -and $claimed -and ($claimed -ne "$tenant".Trim().ToLowerInvariant())) {
        throw "PIM-Rest: REFUSED a signed-in token for '$Resource': it belongs to tenant $claimed, not the requested $tenant."
      }
      $res = $pt
    }
  }
  # LAST-RESORT interactive prompt — ONLY when an attended caller opts in via
  # $global:PIM_InteractiveFallback (the interactive admin tools set this; the engine /
  # headless cron NEVER does, so an unattended run still fails fast instead of hanging on
  # a browser prompt). This is what makes the admin deploy scripts "just sign me in" when
  # no MI/secret/cert token is available, rather than throwing.
  if (-not $res -and $global:PIM_InteractiveFallback) {
    Write-Host "PIM-Rest: no MI/secret/cert token for '$Resource' -- falling back to interactive sign-in..." -ForegroundColor Yellow
    try { $res = Get-PimInteractiveToken -Audience $aud -TenantId $tenant } catch { Write-Verbose "PIM-Rest interactive fallback failed for ${Resource}: $($_.Exception.Message)" }
  }
  if (-not $res) { throw "PIM-Rest: could not acquire a token for '$Resource'. Provide a managed identity, ClientId + certificate (+TenantId), the Invardia Support-app session, or -Interactive (browser sign-in)." }

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
# Every REST call is bounded (see Invoke-PimRest). $global:PIM_RestTimeoutSec overrides; floor 10 s, default 180 s.
function Get-PimRestTimeoutSec {
  $v = 0; if ($global:PIM_RestTimeoutSec) { [void][int]::TryParse("$($global:PIM_RestTimeoutSec)", [ref]$v) }
  if ($v -ge 10) { return $v }
  return 180
}
function Test-PimRestTimeoutError {
  # pwsh 7: HttpClient's timeout surfaces as TaskCanceledException / TimeoutException ("The request was canceled due to the
  # configured HttpClient.Timeout"); PS 5.1: WebException status Timeout ("The operation has timed out").
  param($ErrorRecord)
  $e = $null; try { $e = $ErrorRecord.Exception } catch { }
  while ($e) {
    if ($e -is [System.TimeoutException] -or $e -is [System.Threading.Tasks.TaskCanceledException]) { return $true }
    if ($e -is [System.Net.WebException] -and $e.Status -eq [System.Net.WebExceptionStatus]::Timeout) { return $true }
    $e = $e.InnerException
  }
  return ("$($ErrorRecord)" -match 'HttpClient\.Timeout|operation has timed out|request was canceled')
}
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
        # 🔴 2026-10-02: NO -TimeoutSec = wait FOREVER on pwsh 7. One Graph call that never answered froze the hybrid worker's
        # continuous AD sync for 22 hours (process alive, task "Running", IgnoreNew -> never restarted). Every call is bounded now.
        $args = @{ Method = $Method; Uri = $next; Headers = $h; TimeoutSec = (Get-PimRestTimeoutSec) }
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
        # a call that hit -TimeoutSec is retried ONCE (a second full wait is the most a stuck endpoint may cost), then fails
        $isTimeout = (-not $code) -and (Test-PimRestTimeoutError -ErrorRecord $_)
        if ($isTimeout -and $attempt -lt 1) { $attempt++; continue }
        if ($isTimeout) { throw "$Method $next -> timed out after $(Get-PimRestTimeoutSec) s (twice) -- the service did not answer" }
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
        # 2026-09-21 (operator: "can you provide graph or arm errors in here as i have nothing to work with"): the
        # thrown message stays code+message (above), but the full body of the LAST failure is kept for a caller that
        # needs more -- e.g. a policy-rule PATCH that adds the request-id and what it sent (Invoke-PimPolicyRulePatch).
        # 100.50: the Retry-After of that failure too (seconds; 0 = none) -- an ARM write refused with 409 OperationInProgress
        # is waited out by Invoke-PimArmBusyRetry (PIM-ArmContainerApps.ps1), which honours it when the service sent one.
        $raLast = 0
        try { $d = $_.Exception.Response.Headers.RetryAfter.Delta; if ($d) { $raLast = [int][Math]::Ceiling($d.TotalSeconds) } } catch { }
        if (-not $raLast) { try { [void][int]::TryParse("$($_.Exception.Response.Headers['Retry-After'])", [ref]$raLast) } catch { } }
        $global:PimLastRestError = [pscustomobject]@{ method = $Method; url = $next; status = $code; body = "$body"; atUtc = [datetime]::UtcNow; retryAfter = $raLast }
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
  $script:PimBatchStats = @{ roundTrips = 0; throttled = 0; serverErrors = 0; retryRounds = 0; waitedSeconds = 0; singles = 0; pacedSeconds = 0; batchSize = $BatchSize }
  # 🔴 PACING (2026-09-27, internal, measured in Log Analytics): the first pass fired every round-trip back to back, so once
  # Graph started throttling, almost every later round-trip came back 429 too -- two 712-path reads per drift snapshot
  # (group memberships, group policies) each drew ~1,240 throttled answers, ~190 single fallbacks and ~225 s. Now a
  # round-trip that came back throttled is followed by a pause (its Retry-After, at most 10 s) before the NEXT round-trip.
  # The pauses share a 120 s budget per call; once it is spent the reader behaves as before (never slower than unpaced).
  # Tunables (script scope, for measuring on a live tenant): the pause cap and the per-call budget.
  $paceCap = if ($script:PimBatchPaceMaxSeconds -gt 0) { [int]$script:PimBatchPaceMaxSeconds } else { 10 }
  $paceBudget = if ($script:PimBatchPaceBudgetSeconds -gt 0) { [int]$script:PimBatchPaceBudgetSeconds } else { 120 }
  $pace = {
    param([int]$RetryAfter)
    if ($script:PimBatchStats.pacedSeconds -ge $paceBudget) { return }
    $p = [Math]::Min($paceCap, [Math]::Max(1, $RetryAfter))
    $p = [Math]::Min($p, $paceBudget - $script:PimBatchStats.pacedSeconds)
    $script:PimBatchStats.pacedSeconds += $p; $script:PimBatchStats.waitedSeconds += $p
    if ($script:PimBatchSleep -is [scriptblock]) { & $script:PimBatchSleep $p } else { Start-Sleep -Seconds $p }
  }
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
  # 🔑 SHRINK ON THROTTLE (2.4.457, measured on ig798 with 712 PIM-for-Groups schedule reads): every batch size took the same
  # 259-287 s -- the tenant's own Graph ceiling (~2.7 reads/s), which no pacing beats -- but 20 per round-trip drew 444
  # throttled answers and 49 single fallbacks, 10 drew 63 and none, 5 drew 20 and none. So a read starts at $BatchSize and
  # halves it (down to 5) after each throttled round-trip: an unthrottled read keeps full batches, a throttled one stops
  # piling 429s onto the ceiling. $script:PimBatchStats.batchSize is the size it ended on.
  $curSize = $BatchSize
  $ofs = 0
  while ($ofs -lt $n) {
    $last = [Math]::Min($ofs + $curSize, $n) - 1
    $r = & $sendBatch -Indexes @($ofs..$last)
    $ofs = $last + 1
    foreach ($p in @($r.pending)) { $retryQueue.Add([int]$p) }
    if ($r.maxRetryAfter -gt $maxRa) { $maxRa = $r.maxRetryAfter }
    if (@($r.pending).Count) {
      if ($curSize -gt 5) { $curSize = [Math]::Max(5, [int][Math]::Floor($curSize / 2)) }
      if ($ofs -lt $n) { & $pace $r.maxRetryAfter }   # throttled: let it clear before the next
    }
  }
  $script:PimBatchStats.batchSize = $curSize
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
    $o = 0
    while ($o -lt $queue.Count) {
      $slice = @($queue[$o..([Math]::Min($o + $curSize, $queue.Count) - 1)])
      $o += $slice.Count
      $r = & $sendBatch -Indexes $slice
      foreach ($p in @($r.pending)) { $retryQueue.Add([int]$p) }
      if ($r.maxRetryAfter -gt $maxRa) { $maxRa = $r.maxRetryAfter }
      if (@($r.pending).Count) {
        if ($curSize -gt 5) { $curSize = [Math]::Max(5, [int][Math]::Floor($curSize / 2)) }
        if ($o -lt $queue.Count) { & $pace $r.maxRetryAfter }
      }
    }
  }
  $script:PimBatchStats.batchSize = $curSize
  # Anything still unanswered (still throttled after the rounds, or a host that does not batch): the single-request
  # path, which owns its own Retry-After/backoff -- so a batch never loses a read the sequential loop would have got.
  for ($i = 0; $i -lt $n; $i++) { if ($null -eq $results[$i]) { $script:PimBatchStats.singles++; $results[$i] = & $single $Paths[$i] } }
  $sw.Stop()
  $st = $script:PimBatchStats
  if ($st.throttled -or $st.serverErrors -or $st.singles -or $sw.Elapsed.TotalSeconds -ge 20) {
    Write-Host ("  [graph-batch] {0} path(s), {1} round-trip(s), {2} throttled (429), {3} server error(s), {4} retry round(s) waiting {5}s (paced {8}s), {6} single fallback(s), batch {9}->{10}, {7:N1}s" -f `
      $n, $st.roundTrips, $st.throttled, $st.serverErrors, $st.retryRounds, $st.waitedSeconds, $st.singles, $sw.Elapsed.TotalSeconds, $st.pacedSeconds, $BatchSize, $st.batchSize) -ForegroundColor DarkGray
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
    -Stream (100.31 SNAPSHOT-OOM, 2026-10-09): emit each row to the pipeline as its page arrives instead of returning
    the whole set at the end, so a caller that projects rows (`... -Stream | ForEach-Object { }`) holds ONE page of
    raw rows, not every role assignment in the tenant twice.
  #>
  param([int]$PageSize = 1000, [switch]$Stream)
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
      $o = [pscustomobject]@{
        Id = "$($r.id)"; Name = "$($r.name)"; Scope = "$($r.scope)"; PrincipalId = "$($r.principalId)"; PrincipalType = "$($r.principalType)"
        RoleDefinitionId = $guid; RoleDefinitionName = $(if ("$($r.roleName)".Trim()) { "$($r.roleName)" } else { $null })
      }
      if ($Stream) { $o } else { $out.Add($o) }
    }
    if ($resp -and $resp.PSObject.Properties['data']) { $resp.data = $null }   # the raw page goes as soon as it is projected
    $skipToken = $null
    if ($resp -and $resp.PSObject.Properties['$skipToken'] -and "$($resp.'$skipToken')".Trim()) { $skipToken = "$($resp.'$skipToken')" }
  } while ($skipToken)
  if ($Stream) { return }
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
      else the admin's SPONSOR DEPARTMENT's Owners                             -> all of them
      else ManagerEmail, if it is a real address                               -> LEGACY ONLY
      else                                                                     -> ''  (caller refuses)

    🔑 The rule, and the reason for each step, live on Get-PimAdminMailRecipientPlan below -- this is
    only the string-returning wrapper. Read that comment before changing anything here. In particular
    the sponsor is a DEPARTMENT, not a person (operator, 2026-09-16), and ManagerEmail survives solely
    so existing data keeps working; it is reported as 'manager-legacy' so callers can say "move this
    to the department".
    🔑 Operator, 2026-09-12 ("Both"): MailForwardAddress is the admin OWNER's office user. An admin
    account has no mailbox of its own, so PIM's own mail goes to that office user; and where the admin
    account DOES have a mailbox, the engine also sets Exchange forwarding to it (gated, see
    Invoke-PimAdminMailboxForwarding). The columns were retired 2026-08-12 and are un-retired with
    this meaning.
    🪤 An address that is not an address ('FALSE'/'true' -- measured as live v1 data on internal) is
    NOT a recipient. Test-PimMailForwardAddressIsReal is the shared predicate; 'true' fails its
    address shape and is rejected here explicitly as well.
    🪤 This wrapper returns only the FIRST recipient. Anything that mails a department (which can have
    several owners) must call Get-PimAdminMailRecipientPlan and use .recipients.
  #>
  [CmdletBinding()]
  param([AllowNull()][object]$Row, [hashtable]$DepartmentOwners)
  $plan = if ($PSBoundParameters.ContainsKey('DepartmentOwners')) { Get-PimAdminMailRecipientPlan -Row $Row -DepartmentOwners $DepartmentOwners }
          else { Get-PimAdminMailRecipientPlan -Row $Row }
  return "$($plan.recipient)"
}

function Split-PimMailRecipients {
  # PURE. A recipient list as the model writes it (pipe-joined UPNs per the Manager UX; ';' and ',' accepted too) --
  # the SAME parsing the group-owner path uses (Split-PimOwners), so an admin's department owners and a group's owners
  # can never be read differently.
  param([AllowNull()][string]$Raw)
  @("$Raw" -split '[|;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-PimAdminMailRecipientPlan {
  <#
    🔑 71.19 -- THE SPONSOR IS A DEPARTMENT, NOT A PERSON (operator, 2026-09-16: *"the logic is that an admin is linked
    to a dept (sponsor) and the dept has owners ... change the code, as i think logic is wrong"*; REQUIREMENTS §62:
    *"we dont add a manager on the person"*, *"whoever is the actual manager of the dept gets the emails, approvals
    etc"*, *"otherwise you are vulnerable for org changes"*).

    Who receives PIM's mail about an admin account (new-admin notice, TAP delivery), in order:

      1. ForwardMailsToContact = TRUE AND MailForwardAddress is a real address
         -> that address. The deliberate PER-ADMIN OVERRIDE (operator 2026-09-12 "Both": the admin owner's office
            user). Kept because it is an explicit statement on the row, not a person-as-manager guess.
      2. the admin's SPONSOR DEPARTMENT's owners: Account-Definitions-Admins.Department -> the
         PIM-Definitions-Departments row for that department -> its Owners (pipe/;/,-joined UPNs)
         -> ALL of them. This is the rule.
      3. ManagerEmail, if it is a real address -> LEGACY ONLY, so existing data keeps working. It is reported as
         'manager-legacy' so the validator, the Manager and the readiness check can say "move this to the department".
      4. nothing -> '' and a reason that names the admin, its department and what to set.

    The department index is INJECTED (-DepartmentOwners: department name in lower case -> owners string) because this
    file is the transport layer and must not read the store; the engine passes Get-PimDepartmentOwnerIndex, the Manager
    and the validator pass their own. Without it, step 2 is skipped and the reason says the index was not supplied --
    never silently "no department".

    Returns @{ recipients = @(all); recipient = <first>; source = forward|department|manager-legacy|none;
               department; reason; legacy = [bool] }.
  #>
  [CmdletBinding()]
  param([AllowNull()][object]$Row, [hashtable]$DepartmentOwners = $null)
  $out = [ordered]@{ recipients = @(); recipient = ''; source = 'none'; department = ''; reason = ''; legacy = $false }
  if ($null -eq $Row) { $out['reason'] = 'no admin row'; return $out }
  $get = {
    param($name)
    if ($Row -is [System.Collections.IDictionary]) { return "$($Row[$name])".Trim() }
    $p = $Row.PSObject.Properties[$name]
    if ($p) { return "$($p.Value)".Trim() }
    return ''
  }
  $isAddr = { param($v) ("$v" -notmatch '(?i)^(true|yes|1)$') -and (Test-PimMailForwardAddressIsReal -Value $v) }
  $who = & $get 'UserPrincipalName'; if (-not $who) { $who = & $get 'UserName' }
  $dept = & $get 'Department'
  # When the caller did not inject one, use the engine's own index if this process has it loaded (the engine and the
  # Manager both do). Wrapped: a store read that fails must leave the reason "not supplied", never pretend "no owners".
  if ($null -eq $DepartmentOwners -and (Get-Command Get-PimDepartmentOwnerIndex -ErrorAction SilentlyContinue)) {
    try { $DepartmentOwners = Get-PimDepartmentOwnerIndex } catch { $DepartmentOwners = $null }
  }
  $out['department'] = $dept

  $fwdOn = ((& $get 'ForwardMailsToContact') -match '(?i)^(true|yes|1)$')
  $fwd   = & $get 'MailForwardAddress'
  if ($fwdOn -and (& $isAddr $fwd)) {
    $out['recipients'] = @($fwd); $out['recipient'] = $fwd; $out['source'] = 'forward'
    $out['reason'] = "per-admin override: ForwardMailsToContact=TRUE + MailForwardAddress on $who"
    return $out
  }

  if ($dept) {
    if ($null -eq $DepartmentOwners) {
      $out['reason'] = "the department owner index was not supplied to this call, so '$dept' could not be resolved (load the store / pass -DepartmentOwners)"
    } else {
      $key = $dept.ToLowerInvariant()
      if ($DepartmentOwners.ContainsKey($key)) {
        $owners = @(Split-PimMailRecipients ("$($DepartmentOwners[$key])")) | Where-Object { & $isAddr $_ }
        if (@($owners).Count) {
          $out['recipients'] = @($owners); $out['recipient'] = @($owners)[0]; $out['source'] = 'department'
          $out['reason'] = "sponsor department '$dept' owner(s): $(@($owners) -join ', ')"
          return $out
        }
        $out['reason'] = "the sponsor department '$dept' of $who has no usable Owners -- set Owners on that department (PIM-Definitions-Departments)"
      } else {
        $out['reason'] = "$who names department '$dept', but there is no PIM-Definitions-Departments row for it -- add the department (with Owners), or correct the admin's Department"
      }
    }
  } else {
    $out['reason'] = "$who has no Department -- an admin's mail goes to its SPONSOR DEPARTMENT's owners, so set the admin's Department and give that department Owners"
  }

  $mgr = & $get 'ManagerEmail'
  if (& $isAddr $mgr) {
    $out['recipients'] = @($mgr); $out['recipient'] = $mgr; $out['source'] = 'manager-legacy'; $out['legacy'] = $true
    $out['reason'] = "LEGACY: using ManagerEmail ($mgr) on $who. The rule is the sponsor department's owners -- $($out['reason'])"
    return $out
  }
  # 5. 2026-09-21 (operator: "i cannot set tap on managing tenant either" / "we must also get email from managed tenants when account is
  #    created/replicated down"): with no override, no department owner and no legacy manager, the mail about this admin
  #    (new-admin notice, TAP) goes to THIS tenant's ALERT RECIPIENTS (PIM_AlertRecipient + Manager > Alerting) -- the
  #    people who run the environment. Before, there was nobody to send to, so no TAP could be issued at all and a
  #    replicated admin arrived in a managed tenant without anyone being told. Reported as 'alert-recipients' so the screens
  #    still say "set a sponsor department" for the proper route.
  $alert = @()
  try {
    if (Get-Command Get-PimSafetyAlertRecipients -ErrorAction SilentlyContinue) { $alert = @(Get-PimSafetyAlertRecipients) }
    elseif (Get-Command Get-PimAlertingConfig -ErrorAction SilentlyContinue) { $alert = @((Get-PimAlertingConfig).recipients) }
  } catch { $alert = @() }
  $alert = @($alert | ForEach-Object { "$_".Trim() } | Where-Object { & $isAddr $_ } | Select-Object -Unique)
  if ($alert.Count) {
    $out['recipients'] = @($alert); $out['recipient'] = $alert[0]; $out['source'] = 'alert-recipients'
    $out['reason'] = "no sponsor department owner for $who -- sent to this tenant's alert recipients ($($alert -join ', ')). $($out['reason'])"
    return $out
  }
  return $out
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
