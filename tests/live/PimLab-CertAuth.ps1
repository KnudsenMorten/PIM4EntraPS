<#
.SYNOPSIS
  Cert-only auth helpers for the PIM4EntraPS live lab (no interactive sign-in,
  no device-code, no client secret, no dependency on the ambient `az` session).

  Authenticates each SPN by CERTIFICATE (private key on mgmt1 LocalMachine\My,
  selected by thumbprint) using a signed client-assertion (RS256 JWT) against the
  v2.0 token endpoint. Tokens are minted directly so the lab does not couple to a
  particular Graph/Az module version or to the az CLI's (sometimes broken) auth
  profile.

  Connection VALUES are read from kv-automatit-dev when reachable; when KV is not
  reachable from the current context, the caller may pass the engine/mgmt SPN
  identity explicitly (the values live in internal/ENGINE-IDENTITY.md, never here).

.NOTES
  Per repo policy: certificate auth ONLY. NEVER mok@2linkit.net, NEVER a secret,
  NEVER device-code. Private keys never leave mgmt1.
#>
Set-StrictMode -Off

function ConvertTo-PimB64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-PimLabSpnToken {
    <#
      Mint an app-only access token for an SPN using its certificate (client
      assertion). $Resource is the audience root, e.g. 'https://graph.microsoft.com'
      or 'https://management.azure.com'. Returns the raw access_token string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$CertificateThumbprint,
        [Parameter(Mandatory)][string]$Resource
    )
    $cert = $null
    foreach ($store in @('Cert:\LocalMachine\My', 'Cert:\CurrentUser\My')) {
        $c = Get-Item (Join-Path $store $CertificateThumbprint) -ErrorAction SilentlyContinue
        if ($c -and $c.HasPrivateKey) { $cert = $c; break }
    }
    if (-not $cert) { throw "Get-PimLabSpnToken: certificate $CertificateThumbprint with a private key was not found in LocalMachine\My or CurrentUser\My." }

    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $header  = @{ alg = 'RS256'; typ = 'JWT'; x5t = (ConvertTo-PimB64Url $cert.GetCertHash()) } | ConvertTo-Json -Compress
    $payload = @{ aud = $aud; iss = $ClientId; sub = $ClientId; jti = [guid]::NewGuid().ToString(); nbf = $now; exp = $now + 600 } | ConvertTo-Json -Compress
    $unsigned = (ConvertTo-PimB64Url ([Text.Encoding]::UTF8.GetBytes($header))) + '.' + (ConvertTo-PimB64Url ([Text.Encoding]::UTF8.GetBytes($payload)))
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if (-not $rsa) { throw "Get-PimLabSpnToken: could not obtain an RSA private key from $CertificateThumbprint." }
    $sig = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($unsigned), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $assertion = $unsigned + '.' + (ConvertTo-PimB64Url $sig)

    $scope = ($Resource.TrimEnd('/')) + '/.default'
    $body = @{
        client_id             = $ClientId
        scope                 = $scope
        grant_type            = 'client_credentials'
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $assertion
    }
    $resp = Invoke-RestMethod -Method POST -Uri $aud -ContentType 'application/x-www-form-urlencoded' -Body $body
    if (-not $resp.access_token) { throw "Get-PimLabSpnToken: token endpoint returned no access_token." }
    return $resp.access_token
}

function Get-PimLabKvSecret {
    <#
      Read a single secret value from kv-automatit-dev via the az CLI. Returns
      $null if the read fails (e.g. az context not aligned) so callers can fall
      back to an explicitly-supplied identity.
    #>
    param([Parameter(Mandatory)][string]$Name, [string]$Vault = 'kv-automatit-dev')
    try {
        $v = az keyvault secret show --vault-name $Vault --name $Name --query value -o tsv 2>$null
        if ($LASTEXITCODE -eq 0 -and "$v".Trim()) { return "$v".Trim() }
    } catch { }
    return $null
}

function Resolve-PimLabTenantConnection {
    <#
      Resolve { TenantId, EngineClientId, EngineThumb, MgmtClientId, MgmtThumb }
      for a domain. Prefers kv-automatit-dev; falls back to the documented
      myfamilynetwork identities (internal/ENGINE-IDENTITY.md) when KV is not
      reachable. Mgmt thumbprint is resolved from the cert store by subject when
      not in KV (it is not a documented KV secret name on its own).
    #>
    param([string]$Domain = 'myfamilynetwork')

    $tid   = Get-PimLabKvSecret "tenant-id-$Domain"
    $ecid  = Get-PimLabKvSecret "PIM4EntraPS-spn-clientid-$Domain"
    $ethmb = Get-PimLabKvSecret "PIM4EntraPS-certificatethumbprint-$Domain"
    $mcid  = Get-PimLabKvSecret "management-spn-clientid-$Domain"
    $mthmb = Get-PimLabKvSecret "management-spn-certificatethumbprint-$Domain"

    if ($Domain -eq 'myfamilynetwork') {
        if (-not $tid)   { $tid   = 'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e' }
        if (-not $ecid)  { $ecid  = '7c0f9a79-f317-4c19-8000-0ac8f2ce9d12' }
        if (-not $ethmb) { $ethmb = '642E1F8FE7A60CD8B971CC85AA22A8992A6644F9' }
        if (-not $mcid)  { $mcid  = '6b4dde9b-2aaf-480e-bc94-f21dc417f180' }
        # Verified mgmt SPN cert for myfamilynetwork (CN=...-MGMT1-myfamilynetwork).
        if (-not $mthmb) { $mthmb = '78E4197442BF1414A33F7F9471038ED97DB67F71' }
    }
    if (-not $mthmb -and $mcid) {
        # Find the mgmt SPN cert in the store by its PER-TENANT subject (the subject
        # carries the domain: CN=AutomateIT-HighPrivileged-Tier0-MGMT1-<domain>) so we
        # never grab another tenant's mgmt cert (which would 401 / "key not found").
        $c = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
             Where-Object { $_.Subject -match ("HighPrivileged-Tier0-MGMT1-" + [regex]::Escape($Domain) + '\b') -and $_.HasPrivateKey } |
             Sort-Object NotAfter -Descending | Select-Object -First 1
        if ($c) { $mthmb = $c.Thumbprint }
    }
    if (-not $tid -or -not $ecid -or -not $ethmb) {
        throw "Resolve-PimLabTenantConnection: could not resolve engine SPN connection for '$Domain' (KV unreachable and no fallback)."
    }
    return [pscustomobject]@{
        Domain         = $Domain
        TenantId       = $tid
        EngineClientId = $ecid
        EngineThumb    = $ethmb
        MgmtClientId   = $mcid
        MgmtThumb      = $mthmb
    }
}
