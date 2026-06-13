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

# resource (audience) per logical API
$script:PimRestResources = @{
  graph    = 'https://graph.microsoft.com'
  arm      = 'https://management.azure.com'
  powerbi  = 'https://analysis.windows.net/powerbi/api'
  defender = 'https://api.securitycenter.microsoft.com'
}
$script:PimTokenCache = @{}   # resourceKey -> @{ token; expiresUtc }

function Resolve-PimRestResource {
  param([Parameter(Mandatory)][string]$Resource)
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
function Get-PimManagedIdentityToken {
  param([Parameter(Mandatory)][string]$Audience)
  # App Service / Functions / Container Apps inject these:
  if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
    $u = "$($env:IDENTITY_ENDPOINT)?resource=$([uri]::EscapeDataString($Audience))&api-version=2019-08-01"
    $r = Invoke-RestMethod -Method GET -Uri $u -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER }
    return [pscustomobject]@{ token = $r.access_token; expiresUtc = ([datetimeoffset]::FromUnixTimeSeconds([int64]$r.expires_on)).UtcDateTime }
  }
  # IMDS (Azure VM)
  $u = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$([uri]::EscapeDataString($Audience))"
  if ($global:PIM_ManagedIdentityClientId) { $u += "&client_id=$($global:PIM_ManagedIdentityClientId)" }
  $r = Invoke-RestMethod -Method GET -Uri $u -Headers @{ Metadata = 'true' } -TimeoutSec 5
  return [pscustomobject]@{ token = $r.access_token; expiresUtc = ([datetimeoffset]::FromUnixTimeSeconds([int64]$r.expires_on)).UtcDateTime }
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

# ---- the one entry point: get a token for a resource ----------------------
function Get-PimRestToken {
  [CmdletBinding()]
  param(
    [string]$Resource = 'graph',
    [string]$TenantId,[string]$ClientId,[string]$ClientSecret,
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,[string]$CertThumbprint,
    [switch]$UseManagedIdentity,[switch]$Force
  )
  $aud = Resolve-PimRestResource -Resource $Resource
  $key = $aud.ToLowerInvariant()
  if (-not $Force -and $script:PimTokenCache.ContainsKey($key)) {
    $e = $script:PimTokenCache[$key]
    if ($e.expiresUtc -gt (Get-Date).ToUniversalTime().AddMinutes(2)) { return $e.token }
  }

  $tenant = Get-PimTenantId -TenantId $TenantId
  $cid    = if ($ClientId) { $ClientId } elseif ($global:PIM_ClientId) { $global:PIM_ClientId } elseif ($env:AZURE_CLIENT_ID) { $env:AZURE_CLIENT_ID } else { $null }
  $sec    = if ($ClientSecret) { $ClientSecret } elseif ($global:PIM_ClientSecret) { $global:PIM_ClientSecret } elseif ($env:AZURE_CLIENT_SECRET) { $env:AZURE_CLIENT_SECRET } else { $null }
  $cert   = if ($Certificate) { $Certificate } else { Resolve-PimCertificate -Thumbprint $CertThumbprint }

  $res = $null
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
  } catch { Write-Verbose "PIM-Rest primary auth failed for ${Resource}: $($_.Exception.Message)" }

  if (-not $res) {
    # dev convenience: reuse an existing az session
    try {
      $j = az account get-access-token --resource $aud -o json 2>$null | ConvertFrom-Json
      if ($j.accessToken) {
        $exp = (Get-Date).ToUniversalTime().AddMinutes(50)
        try { $exp = ([datetime]$j.expiresOn).ToUniversalTime() } catch {}
        $res = [pscustomobject]@{ token = $j.accessToken; expiresUtc = $exp }
      }
    } catch {}
  }
  if (-not $res) { throw "PIM-Rest: could not acquire a token for '$Resource'. Provide MI, ClientId+Secret/Cert (+TenantId), or run az login." }

  $script:PimTokenCache[$key] = $res
  return $res.token
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
    [int]$MaxRetry = 5
  )
  $token = Get-PimRestToken -Resource $Resource
  $h = @{ Authorization = "Bearer $token" } + $Headers
  $agg = New-Object System.Collections.Generic.List[object]
  $next = $Url
  while ($next) {
    $attempt = 0
    while ($true) {
      try {
        $args = @{ Method = $Method; Uri = $next; Headers = $h }
        if ($null -ne $Body -and $Method -ne 'GET') {
          $args.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 }
          $args.ContentType = 'application/json'
        }
        $resp = Invoke-RestMethod @args
        break
      } catch {
        $code = $null; try { $code = [int]$_.Exception.Response.StatusCode } catch {}
        if (($code -eq 429 -or $code -ge 500) -and $attempt -lt $MaxRetry) {
          $wait = [Math]::Min(60, [Math]::Pow(2, $attempt))
          try { $ra = [int]("$($_.Exception.Response.Headers['Retry-After'])"); if ($ra -gt 0) { $wait = $ra } } catch {}
          Start-Sleep -Seconds $wait; $attempt++; continue
        }
        throw
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
  param([string]$Method='GET',[Parameter(Mandatory)][string]$Path,[object]$Body,[switch]$All,[switch]$Beta,[hashtable]$Headers=@{})
  $base = if ($Beta) { 'https://graph.microsoft.com/beta' } else { 'https://graph.microsoft.com/v1.0' }
  $url = if ($Path -match '^https?://') { $Path } else { "$base$Path" }
  Invoke-PimRest -Method $Method -Url $url -Body $Body -Resource 'graph' -All:$All -Headers $Headers
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
