#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline-courier CONSUMER (LIFECYCLE-GOVERNANCE § 19): pull the MSP's signed
    baseline bundle over HTTPS and verify it offline before applying.

.DESCRIPTION
    The MSP publishes a signed baseline bundle to private-endpoint blob storage.
    The local engine PULLS it (HTTPS GET, reach stays outbound) and verifies:
      * RSA-SHA256 signature over the exact payload bytes, against the PUBLIC
        baseline certificate embedded below (the private key never leaves the
        MSP management host -- same trust model as the offline .pimlicense).
      * product == PIM4EntraPS and kind == baseline.
      * not expired (validToUtc).
      * version is monotonic vs the last-applied marker (anti-rollback).
    Only on full success are the Owner=MSP rows returned for the merge.

    No secret key is needed locally -- verification uses the PUBLIC cert only.
    The bundle is signed, not encrypted: the customer can read exactly what the
    MSP ships (transparency), and any tampering in transit/at-rest is rejected.

    PS 5.1-safe: X509Certificate2 from raw bytes + RSACertificateExtensions
    (no ImportFromPem).
#>

# PUBLIC certificate of the baseline signing key (CN=PIM4EntraPS-Baseline).
$script:PimBaselinePublicCertB64 = 'MIID+TCCAmGgAwIBAgIQNSAUfKUEGLRHFcG6VRAUzjANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQDDBRQSU00RW50cmFQUy1CYXNlbGluZTAeFw0yNjA2MTIxOTU5NTZaFw00MTA2MTIyMDA5NTNaMB8xHTAbBgNVBAMMFFBJTTRFbnRyYVBTLUJhc2VsaW5lMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtuUzkuPYVYLK2TCHv0I9WFlmm0wQTf7WVSUAi8TMzHw+e4lNF3LgoI0fVDPf7ZGn+DArdVoEGKEwkuL5Lyeq45Q/4z9O2sogty/3iaxbd7VkjUrll6+xe9Wg+1nGSVPpuaLvgX0ku1l3mQNf7PM0obKuZ9HZhESDP5KMnxXmVN7vaBLERxyYcvYZmxFu8aDvvBN2Aw1dHnJAppEQgfNYMJjdc6ecqQsHBIW/LUNqJX69wqvaPTKcq5tjDgWQO5jrQtZSM1YHj7ixP1E3my/aaj5mWGZzVze8LfmWbB+ZeeE0B1tqJd7vE7vl/MJQQaFNEksx9c2zX0CuRZbOQD/Wmmg4gztq1XlivvvuktgtLgDzb1vU6Cv3czP3e6CasX3fg0Zk+ijXAgjB25bhMWMCw0wV3NcT8gQhtEKaE97SHz8WGtWA9ZTeiHWetm/g1aLIeMK/fIP26e4ShegFIdOE3PsGXjQwj62vwRTAzSjYYgNjvCp8Yhw20zchsjo21gZpAgMBAAGjMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUbDXIa2sLKE+daVIaD5AW2URZKogwDQYJKoZIhvcNAQELBQADggGBAFAg3rU33A9h/75XoY/5uN9txUlA15vueWWIElUNY6wKVi1TdpR9kKN8rETeU4RHIwq/wL7hGN1XFUc58ZTEuGJHQ5hXviQGpjJGi/lSZsp4fqh7Pe8ETTj1yg3S6xwmDsrr/a8PSKkdBFf/mEZs9iudHPOQruuLT7n6hBTznoYTUc1I7m3iattLU4IBgTw2vBhlpmRdDPqskPiaj1eN21BqiqzuxseTWQjmTDWgr5xFAOQ0MmnrK3Etn1DCto0eWH3ybfgXTz67sSw3w52gawLx8zuz1Lm+riaQWf0wSaFt0BcltLELDwKzG20fTKCWSjAbIk0bPbCCu8kbiRDynmf+rPD3dH1J5cLVtt3gAkP/z6z4WQN0cSNtYmA+tNTBgdASxrNOYd94imB1N5c7DTf7UYz9eKZBHK5aarMpXRrOtm+toSAkFYlT2AobGJEmdZ+OAHsyEzjLP+Lo/RQzHxC6Qvs9pRO8NSj3uPdWddIfBk/WASRP/VzsvZq8dr8dkw=='

function Get-PimBaselineStateFile {
    $dir = if (Get-Command Get-PimConfigDir -ErrorAction SilentlyContinue) { try { Get-PimConfigDir } catch { $null } } else { $null }
    if (-not $dir) { $dir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'output\state' }
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
    Join-Path $dir 'baseline-state.json'
}

# -----------------------------------------------------------------------------
# 71.35 -- KEY VAULT SIGNED BUNDLES (the cloud publish job, ca-pim-publish).
#
# A bundle published by the master's Container Apps job is signed by an RSA key in the
# master's Key Vault (non-exportable; RS256 = RSASSA-PKCS1-v1_5 over SHA-256, the SAME
# primitive the certificate path uses). Such a bundle CARRIES its public key
# (signingKey = { kty, n, e, kid }), and that is NOT what makes it trusted: the key's
# RFC 7638 JWK thumbprint must be one this tenant PINS (PIM_BaselineTrustedKeys, a
# config value given by the slave build -- never fetched from the bundle store). Several
# keys may be pinned at once, so a key roll is: pin the new id everywhere, then switch.
# A bundle WITHOUT signingKey is verified exactly as before, against the embedded
# CN=PIM4EntraPS-Baseline certificate (legacy, still live on EFIF -> RIDE).
# PS 5.1-safe: RSAParameters import, no ImportFromPem / ImportSubjectPublicKeyInfo.
# -----------------------------------------------------------------------------
function ConvertFrom-PimBaselineB64 {
    # base64 OR base64url, padding optional -> [byte[]]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $s = "$Value".Trim().TrimEnd('=').Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } 1 { throw "not base64: length $($s.Length)" } }
    return , ([Convert]::FromBase64String($s))
}

function ConvertTo-PimBaselineB64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    return ([Convert]::ToBase64String($Bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-PimBaselineUnsignedBytes {
    # a big-endian unsigned integer without leading zero octets (JWK n/e form, RFC 7518 6.3.1)
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $i = 0
    while ($i -lt ($Bytes.Length - 1) -and $Bytes[$i] -eq 0) { $i++ }
    if ($i -eq 0) { return , $Bytes }
    $out = New-Object byte[] ($Bytes.Length - $i)
    [Array]::Copy($Bytes, $i, $out, 0, $out.Length)
    return , $out
}

function Get-PimBaselineKeyId {
    # RFC 7638 JWK SHA-256 thumbprint of an RSA public key, base64url (43 chars). -N / -E may be base64 or base64url,
    # with or without leading zero octets: the SAME key always yields the SAME id, whoever printed n and e.
    param([Parameter(Mandatory)][string]$N, [Parameter(Mandatory)][string]$E)
    $nB = Get-PimBaselineUnsignedBytes -Bytes (ConvertFrom-PimBaselineB64 -Value $N)
    $eB = Get-PimBaselineUnsignedBytes -Bytes (ConvertFrom-PimBaselineB64 -Value $E)
    $json = '{"e":"' + (ConvertTo-PimBaselineB64Url -Bytes $eB) + '","kty":"RSA","n":"' + (ConvertTo-PimBaselineB64Url -Bytes $nB) + '"}'
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($json)) } finally { $sha.Dispose() }
    return (ConvertTo-PimBaselineB64Url -Bytes $h)
}

function Test-PimBaselineKeyIdFormat {
    param([string]$KeyId)
    return [bool]("$KeyId".Trim() -cmatch '^[A-Za-z0-9_-]{43}$')
}

function Get-PimBaselineTrustedKeyIds {
    # The signing keys THIS tenant pins. Explicit -TrustedKeyIds wins (an explicit empty list pins nothing); else
    # $global:PIM_BaselineTrustedKeys; else $env:PIM_BaselineTrustedKeys (the pull job's env, comma-separated).
    # Anything that is not a 43-char base64url thumbprint is ignored (never widened into "trust anything").
    param([string[]]$TrustedKeyIds)
    if ($PSBoundParameters.ContainsKey('TrustedKeyIds')) { $raw = @($TrustedKeyIds) }
    elseif ("$(@($global:PIM_BaselineTrustedKeys) -join ',')".Trim()) { $raw = @($global:PIM_BaselineTrustedKeys) }
    else { $raw = @("$($env:PIM_BaselineTrustedKeys)") }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($r in $raw) {
        foreach ($x in @("$r" -split '[,;\s]+')) {
            $t = "$x".Trim()
            if ((Test-PimBaselineKeyIdFormat -KeyId $t) -and -not $out.Contains($t)) { $out.Add($t) }
        }
    }
    return @($out.ToArray())
}

function New-PimBaselineRsaPublicKey {
    param([Parameter(Mandatory)][string]$N, [Parameter(Mandatory)][string]$E)
    $p = New-Object System.Security.Cryptography.RSAParameters
    $p.Modulus  = Get-PimBaselineUnsignedBytes -Bytes (ConvertFrom-PimBaselineB64 -Value $N)
    $p.Exponent = Get-PimBaselineUnsignedBytes -Bytes (ConvertFrom-PimBaselineB64 -Value $E)
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportParameters($p)
    return $rsa
}

function Test-PimBaselineKeySignature {
    # Verify a Key Vault signed document: the carried key must be PINNED, then RS256 must verify. Returns the key id.
    param(
        [Parameter(Mandatory)][object]$SigningKey,
        [Parameter(Mandatory)][byte[]]$PayloadBytes,
        [Parameter(Mandatory)][byte[]]$SignatureBytes,
        [AllowEmptyCollection()][string[]]$TrustedKeyIds = @()
    )
    $get = { param($k) if ($SigningKey -is [System.Collections.IDictionary]) { $SigningKey[$k] } else { $p = $SigningKey.PSObject.Properties[$k]; if ($p) { $p.Value } else { $null } } }
    $kty = "$(& $get 'kty')".Trim()
    if ($kty -and $kty -notmatch '^RSA(-HSM)?$') { throw "unsupported signing key type '$kty' (RSA only)" }
    $n = "$(& $get 'n')".Trim(); $e = "$(& $get 'e')".Trim()
    if (-not $n -or -not $e) { throw 'signingKey carries no RSA public key (n/e missing)' }
    $modBytes = Get-PimBaselineUnsignedBytes -Bytes (ConvertFrom-PimBaselineB64 -Value $n)
    if (($modBytes.Length * 8) -lt 2048) { throw "signing key is $($modBytes.Length * 8) bits -- refused (2048 minimum)" }
    $id = Get-PimBaselineKeyId -N $n -E $e
    if (@($TrustedKeyIds) -cnotcontains $id) {
        throw ("UNTRUSTED SIGNING KEY -- the bundle is signed by key $id, which this tenant does not pin " +
               "($(@($TrustedKeyIds).Count) key(s) pinned in PIM_BaselineTrustedKeys). A bundle store is not a trust anchor: add the " +
               "master's key id to this tenant's build config (master.signingKeyIds) if, and only if, the master gave it to you.")
    }
    $rsa = New-PimBaselineRsaPublicKey -N $n -E $e
    try {
        $ok = $rsa.VerifyData($PayloadBytes, $SignatureBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } catch { $ok = $false }
    finally { $rsa.Dispose() }
    if (-not $ok) { throw "SIGNATURE INVALID -- bundle tampered or not signed by the pinned key $id" }
    return $id
}

function Test-PimBaselineDoc {
    # Verify the signature + shape of a signed document. Returns the parsed
    # payload object on success; throws on any failure. The SAME crypto verifies
    # any artifact the MSP signs with the baseline key -- the baseline bundle
    # (default) and the central-kill manifest (-AllowedKind 'central-kill', see
    # PIM-Substrate.ps1). Signer: the embedded PUBLIC baseline cert, or (71.35) a
    # Key Vault key the document carries AND this tenant pins (-TrustedKeyIds, else
    # $global:/$env:PIM_BaselineTrustedKeys).
    param(
        [Parameter(Mandatory)][object]$Doc,
        [string[]]$AllowedKind = @('baseline'),
        [string[]]$TrustedKeyIds
    )
    if (-not $Doc.payloadB64 -or -not $Doc.signature) { throw "not a signed bundle (payloadB64/signature missing)" }
    $payloadBytes = [Convert]::FromBase64String($Doc.payloadB64)
    $sigBytes     = [Convert]::FromBase64String($Doc.signature)
    $signingKey = $null
    if ($Doc -is [System.Collections.IDictionary]) { if ($Doc.Contains('signingKey')) { $signingKey = $Doc['signingKey'] } }
    else { $skp = $Doc.PSObject.Properties['signingKey']; if ($skp) { $signingKey = $skp.Value } }
    if ($null -ne $signingKey) {
        $tk = @{}; if ($PSBoundParameters.ContainsKey('TrustedKeyIds')) { $tk['TrustedKeyIds'] = @($TrustedKeyIds) }
        $null = Test-PimBaselineKeySignature -SigningKey $signingKey -PayloadBytes $payloadBytes -SignatureBytes $sigBytes -TrustedKeyIds @(Get-PimBaselineTrustedKeyIds @tk)
    } else {
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($script:PimBaselinePublicCertB64))
    $rsa  = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
    $ok   = $rsa.VerifyData($payloadBytes, $sigBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    if (-not $ok) { throw "SIGNATURE INVALID -- bundle tampered or not signed by the PIM4EntraPS baseline key" }
    }
    $p = [System.Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json
    if ("$($p.product)" -ne 'PIM4EntraPS') { throw "unexpected bundle product '$($p.product)'" }
    if (@($AllowedKind) -notcontains "$($p.kind)") { throw "unexpected bundle kind '$($p.kind)' (allowed: $($AllowedKind -join ', '))" }
    $p
}

function Get-PimBaselineBundle {
    <#
    .SYNOPSIS
        HTTPS-pull a signed baseline bundle, verify it, enforce expiry +
        anti-rollback, and return its Owner=MSP rows.
    .PARAMETER Url
        HTTPS blob URL of the bundle (over the private endpoint in prod).
    .PARAMETER AccessToken
        Bearer token for the storage account (Entra). Minted by the caller:
        (Get-AzAccessToken -ResourceUrl 'https://storage.azure.com/').Token
    .PARAMETER SkipRollbackCheck
        Don't compare against the last-applied version marker (first run / tests).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [string]$AccessToken,
        [switch]$SkipRollbackCheck
    )
    $headers = @{ 'x-ms-version' = '2021-08-06' }
    if ($AccessToken) { $headers['Authorization'] = "Bearer $AccessToken" }
    $raw = Invoke-RestMethod -Method GET -Uri $Url -Headers $headers -ErrorAction Stop
    if ($raw -is [string]) {
        $br = $raw.IndexOf('{'); if ($br -gt 0) { $raw = $raw.Substring($br) }   # strip any BOM/preamble
        $doc = $raw | ConvertFrom-Json
    } else { $doc = $raw }

    $payload = Test-PimBaselineDoc -Doc $doc

    if ($payload.validToUtc) {
        $validTo = [datetime]::Parse("$($payload.validToUtc)", [System.Globalization.CultureInfo]::InvariantCulture)
        if ([datetime]::UtcNow -gt $validTo.ToUniversalTime()) { throw "baseline bundle expired ($($payload.validToUtc))" }
    }

    if (-not $SkipRollbackCheck) {
        $stateFile = Get-PimBaselineStateFile
        $lastVer = 0
        if (Test-Path $stateFile) { try { $lastVer = [int64]((Get-Content $stateFile -Raw | ConvertFrom-Json).version) } catch { $lastVer = 0 } }
        if ([int64]$payload.version -lt $lastVer) { throw "baseline rollback refused: bundle version $($payload.version) < last-applied $lastVer" }
    }

    [pscustomobject]@{
        Version       = [int64]$payload.version
        GeneratedAtUtc = "$($payload.generatedAtUtc)"
        ValidToUtc    = "$($payload.validToUtc)"
        Scope         = "$($payload.scope)"
        Rows          = @($payload.rows)
        SignerThumbprint = "$($doc.keyThumbprint)"
    }
}

function Set-PimBaselineApplied {
    # Record the applied version (anti-rollback marker) after a successful merge.
    param([Parameter(Mandatory)][int64]$Version)
    @{ version = $Version; appliedAtUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') } | ConvertTo-Json |
        Set-Content -LiteralPath (Get-PimBaselineStateFile) -Encoding UTF8
}
