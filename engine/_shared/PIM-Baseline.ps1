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

function Test-PimBaselineDoc {
    # Verify the signature + shape of a signed document. Returns the parsed
    # payload object on success; throws on any failure. The SAME crypto verifies
    # any artifact the MSP signs with the baseline key -- the baseline bundle
    # (default) and the central-kill manifest (-AllowedKind 'central-kill', see
    # PIM-Substrate.ps1). The signer is always the embedded PUBLIC baseline cert.
    param(
        [Parameter(Mandatory)][object]$Doc,
        [string[]]$AllowedKind = @('baseline')
    )
    if (-not $Doc.payloadB64 -or -not $Doc.signature) { throw "not a signed bundle (payloadB64/signature missing)" }
    $payloadBytes = [Convert]::FromBase64String($Doc.payloadB64)
    $sigBytes     = [Convert]::FromBase64String($Doc.signature)
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($script:PimBaselinePublicCertB64))
    $rsa  = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
    $ok   = $rsa.VerifyData($payloadBytes, $sigBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    if (-not $ok) { throw "SIGNATURE INVALID -- bundle tampered or not signed by the PIM4EntraPS baseline key" }
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
