#Requires -Version 5.1
<#
.SYNOPSIS
    SEC-01 -- hosted Manager principal authentication gate (engine/_shared/PIM-HostedAuth.ps1).
.DESCRIPTION
    Offline, no tenant, no network, no browser. Proves the two layers that stop a client
    naming itself a SuperAdmin via a forged X-MS-CLIENT-PRINCIPAL-NAME header:

      LAYER 1 (always on) -- auth-edge header consistency:
        * name header WITHOUT the companion principal blob  -> REJECTED (the spoof signature)
        * blob that is not base64 / not JSON / has no name   -> REJECTED
        * blob whose name disagrees with the name header     -> REJECTED
        * no headers at all                                  -> unauthenticated (not trusted)
        * a coherent edge-injected set                       -> trusted

      LAYER 2 (PIM_HOSTED_REQUIRE_SIGNED_TOKEN=1) -- signed Entra token:
        * a REAL RS256 token signed by a generated key, verified against its JWKS -> trusted
        * the same token with ONE byte of payload flipped                         -> REJECTED
        * alg 'none' / HMAC downgrade                                             -> REJECTED
        * expired / wrong issuer / wrong audience                                 -> REJECTED
        * strict mode with no token, or no JWKS                                   -> REJECTED (fails closed)
        * verified-token identity disagreeing with the header identity            -> REJECTED

    The signing key is generated in-process, so the signature assertions exercise the
    REAL verification path (no fixture, no network).
.EXAMPLE
    powershell -NoProfile -File tests\Test-PimHostedAuth.ps1
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
. (Join-Path $here '..\engine\_shared\PIM-HostedAuth.ps1')

$script:fail = 0
$script:pass = 0
function Assert {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:pass++; Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor DarkGreen }
    else { $script:fail++; Write-Host ("  FAIL  {0} {1}" -f $Name, $Detail) -ForegroundColor Red }
}

function New-Blob {
    # Build an X-MS-CLIENT-PRINCIPAL blob the way the auth edge does.
    param([string]$Name, [string]$Typ = 'preferred_username')
    $obj = @{ auth_typ = 'aad'; name_typ = $Typ; role_typ = 'roles'
              claims = @(@{ typ = $Typ; val = $Name }) }
    $json = $obj | ConvertTo-Json -Depth 6 -Compress
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($json))
}

Write-Host "`n== LAYER 1: auth-edge header consistency ==" -ForegroundColor Cyan

$r = Test-PimEdgeHeadersConsistent -PrincipalName 'admin@contoso.test' -PrincipalBlob ''
Assert 'name header WITHOUT the principal blob is REJECTED (the spoof signature)' (-not $r.trusted) $r.reason
Assert '  ...and says why'  ($r.reason -match 'WITHOUT the companion')

$r = Test-PimEdgeHeadersConsistent -PrincipalName '' -PrincipalBlob ''
Assert 'no auth headers at all -> not trusted (unauthenticated)' (-not $r.trusted)

$r = Test-PimEdgeHeadersConsistent -PrincipalName 'admin@contoso.test' -PrincipalBlob '!!!not-base64!!!'
Assert 'non-base64 principal blob is REJECTED' (-not $r.trusted) $r.reason

$r = Test-PimEdgeHeadersConsistent -PrincipalName 'admin@contoso.test' -PrincipalBlob ([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('not json')))
Assert 'non-JSON principal blob is REJECTED' (-not $r.trusted) $r.reason

$r = Test-PimEdgeHeadersConsistent -PrincipalName 'admin@contoso.test' -PrincipalBlob ([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"auth_typ":"aad","claims":[]}')))
Assert 'principal blob with NO name claim is REJECTED' (-not $r.trusted) $r.reason

$r = Test-PimEdgeHeadersConsistent -PrincipalName 'attacker@evil.test' -PrincipalBlob (New-Blob -Name 'admin@contoso.test')
Assert 'blob/name DISAGREEMENT is REJECTED' (-not $r.trusted) $r.reason

$r = Test-PimEdgeHeadersConsistent -PrincipalName 'admin@contoso.test' -PrincipalBlob (New-Blob -Name 'admin@contoso.test')
Assert 'a coherent edge-injected set IS trusted' ($r.trusted -and $r.identity -eq 'admin@contoso.test') $r.reason

$r = Test-PimEdgeHeadersConsistent -PrincipalName 'ADMIN@Contoso.TEST' -PrincipalBlob (New-Blob -Name 'admin@contoso.test')
Assert 'identity comparison is case-insensitive' ($r.trusted)

$r = Test-PimEdgeHeadersConsistent -PrincipalName '' -PrincipalBlob (New-Blob -Name 'admin@contoso.test')
Assert 'blob alone (no name header) is trusted and yields the identity' ($r.trusted -and $r.identity -eq 'admin@contoso.test')

foreach ($typ in 'upn','email','name') {
    $r = Test-PimEdgeHeadersConsistent -PrincipalName 'admin@contoso.test' -PrincipalBlob (New-Blob -Name 'admin@contoso.test' -Typ $typ)
    Assert ("blob name claim type '$typ' is understood") ($r.trusted)
}

Write-Host "`n== the composite in NON-strict mode ==" -ForegroundColor Cyan

$d = Resolve-PimHostedPrincipal -PrincipalName 'admin@contoso.test' -PrincipalBlob '' -RequireSignedToken $false
Assert 'composite: forged name header alone is REFUSED' (-not $d.trusted) $d.reason
Assert '  ...attributed to the edge-consistency layer' ($d.layer -eq 'edge-consistency')

$d = Resolve-PimHostedPrincipal -PrincipalName 'admin@contoso.test' -PrincipalBlob (New-Blob -Name 'admin@contoso.test') -RequireSignedToken $false
Assert 'composite: coherent set is trusted without a signed token' ($d.trusted -and $d.identity -eq 'admin@contoso.test')

Write-Host "`n== LAYER 2: signed Entra token (real RS256 verification) ==" -ForegroundColor Cyan

# --- generate a real key + JWKS, and sign real tokens with it ------------------
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$kp  = $rsa.ExportParameters($false)
function B64Url { param([byte[]]$Bytes) ([Convert]::ToBase64String($Bytes)).TrimEnd('=').Replace('+','-').Replace('/','_') }
$jwks = @{ keys = @(@{ kty='RSA'; kid='test-key-1'; n=(B64Url $kp.Modulus); e=(B64Url $kp.Exponent) }) }

function New-SignedJwt {
    param([hashtable]$Payload, [string]$Alg = 'RS256', [string]$Kid = 'test-key-1', [switch]$Tamper)
    $h = @{ alg = $Alg; typ = 'JWT'; kid = $Kid } | ConvertTo-Json -Compress
    $p = $Payload | ConvertTo-Json -Depth 6 -Compress
    $hb = B64Url ([System.Text.Encoding]::UTF8.GetBytes($h))
    $pb = B64Url ([System.Text.Encoding]::UTF8.GetBytes($p))
    $signingInput = "$hb.$pb"
    $sig = $rsa.SignData([System.Text.Encoding]::ASCII.GetBytes($signingInput),
                         [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                         [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    if ($Tamper) {
        # Re-issue the payload as a DIFFERENT user but keep the original signature.
        $Payload['preferred_username'] = 'attacker@evil.test'
        $p2 = $Payload | ConvertTo-Json -Depth 6 -Compress
        $pb = B64Url ([System.Text.Encoding]::UTF8.GetBytes($p2))
    }
    return "$hb.$pb." + (B64Url $sig)
}

$now = [datetime]::UtcNow
$goodClaims = @{
    iss = 'https://login.microsoftonline.com/tid/v2.0'
    aud = 'api://pim-manager'
    preferred_username = 'admin@contoso.test'
    exp = [int64]([datetimeoffset]$now.AddMinutes(30)).ToUnixTimeSeconds()
    nbf = [int64]([datetimeoffset]$now.AddMinutes(-5)).ToUnixTimeSeconds()
}
$issuers = @('https://login.microsoftonline.com/tid/v2.0')
$auds    = @('api://pim-manager')

$tok = New-SignedJwt -Payload $goodClaims.Clone()
$d = Resolve-PimHostedPrincipal -PrincipalName 'admin@contoso.test' -PrincipalBlob (New-Blob -Name 'admin@contoso.test') `
        -SignedToken $tok -Jwks $jwks -ExpectedIssuers $issuers -ExpectedAudiences $auds -RequireSignedToken $true -NowUtc $now
Assert 'a properly signed token is VERIFIED and trusted' ($d.trusted -and $d.identity -eq 'admin@contoso.test') $d.reason
Assert '  ...attributed to the signed-token layer' ($d.layer -eq 'signed-token')

$tampered = New-SignedJwt -Payload $goodClaims.Clone() -Tamper
$d = Resolve-PimHostedPrincipal -PrincipalName 'attacker@evil.test' -PrincipalBlob (New-Blob -Name 'attacker@evil.test') `
        -SignedToken $tampered -Jwks $jwks -ExpectedIssuers $issuers -ExpectedAudiences $auds -RequireSignedToken $true -NowUtc $now
Assert 'a TAMPERED payload fails signature verification' (-not $d.trusted) $d.reason
Assert '  ...and names the signature as the reason' ($d.reason -match 'signature')

$noneTok = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.' + (B64Url ([System.Text.Encoding]::UTF8.GetBytes(($goodClaims | ConvertTo-Json -Compress)))) + '.'
$d = Resolve-PimHostedPrincipal -PrincipalName 'admin@contoso.test' -PrincipalBlob (New-Blob -Name 'admin@contoso.test') `
        -SignedToken $noneTok -Jwks $jwks -ExpectedIssuers $issuers -ExpectedAudiences $auds -RequireSignedToken $true -NowUtc $now
Assert "alg 'none' downgrade is REFUSED" (-not $d.trusted) $d.reason

$hsTok = New-SignedJwt -Payload $goodClaims.Clone() -Alg 'HS256'
$d = Resolve-PimHostedPrincipal -PrincipalName 'admin@contoso.test' -PrincipalBlob (New-Blob -Name 'admin@contoso.test') `
        -SignedToken $hsTok -Jwks $jwks -ExpectedIssuers $issuers -ExpectedAudiences $auds -RequireSignedToken $true -NowUtc $now
Assert 'HMAC alg-confusion downgrade is REFUSED' (-not $d.trusted) $d.reason

$wrongKid = New-SignedJwt -Payload $goodClaims.Clone() -Kid 'not-a-known-key'
$d = Resolve-PimHostedPrincipal -PrincipalName 'admin@contoso.test' -PrincipalBlob (New-Blob -Name 'admin@contoso.test') `
        -SignedToken $wrongKid -Jwks $jwks -ExpectedIssuers $issuers -ExpectedAudiences $auds -RequireSignedToken $true -NowUtc $now
Assert 'an unknown kid is REFUSED' (-not $d.trusted) $d.reason

$expired = $goodClaims.Clone()
$expired['exp'] = [int64]([datetimeoffset]$now.AddHours(-2)).ToUnixTimeSeconds()
$d = Resolve-PimHostedPrincipal -PrincipalName 'admin@contoso.test' -PrincipalBlob (New-Blob -Name 'admin@contoso.test') `
        -SignedToken (New-SignedJwt -Payload $expired) -Jwks $jwks -ExpectedIssuers $issuers -ExpectedAudiences $auds -RequireSignedToken $true -NowUtc $now
Assert 'an EXPIRED token is REFUSED' (-not $d.trusted) $d.reason

$d = Resolve-PimHostedPrincipal -PrincipalName 'admin@contoso.test' -PrincipalBlob (New-Blob -Name 'admin@contoso.test') `
        -SignedToken $tok -Jwks $jwks -ExpectedIssuers @('https://login.microsoftonline.com/OTHER/v2.0') -ExpectedAudiences $auds -RequireSignedToken $true -NowUtc $now
Assert 'a WRONG ISSUER is REFUSED' (-not $d.trusted) $d.reason

$d = Resolve-PimHostedPrincipal -PrincipalName 'admin@contoso.test' -PrincipalBlob (New-Blob -Name 'admin@contoso.test') `
        -SignedToken $tok -Jwks $jwks -ExpectedIssuers $issuers -ExpectedAudiences @('api://something-else') -RequireSignedToken $true -NowUtc $now
Assert 'a WRONG AUDIENCE is REFUSED' (-not $d.trusted) $d.reason

$d = Resolve-PimHostedPrincipal -PrincipalName 'admin@contoso.test' -PrincipalBlob (New-Blob -Name 'admin@contoso.test') `
        -SignedToken '' -Jwks $jwks -ExpectedIssuers $issuers -ExpectedAudiences $auds -RequireSignedToken $true -NowUtc $now
Assert 'strict mode with NO token FAILS CLOSED' (-not $d.trusted) $d.reason

$d = Resolve-PimHostedPrincipal -PrincipalName 'admin@contoso.test' -PrincipalBlob (New-Blob -Name 'admin@contoso.test') `
        -SignedToken $tok -Jwks $null -ExpectedIssuers $issuers -ExpectedAudiences $auds -RequireSignedToken $true -NowUtc $now
Assert 'strict mode with NO JWKS FAILS CLOSED (never trusts an unverifiable token)' (-not $d.trusted) $d.reason

$d = Resolve-PimHostedPrincipal -PrincipalName 'someone.else@contoso.test' -PrincipalBlob (New-Blob -Name 'someone.else@contoso.test') `
        -SignedToken $tok -Jwks $jwks -ExpectedIssuers $issuers -ExpectedAudiences $auds -RequireSignedToken $true -NowUtc $now
Assert 'header identity disagreeing with the VERIFIED token is REFUSED' (-not $d.trusted) $d.reason

try { $rsa.Dispose() } catch {}

Write-Host "`n== startup posture ==" -ForegroundColor Cyan
$p = Test-PimHostedAuthPosture -Hosted $false
Assert 'local mode reports posture=local and ok' ($p.level -eq 'local' -and $p.ok)
$p = Test-PimHostedAuthPosture -Hosted $true -RequireSignedToken $false
Assert 'hosted non-strict reports edge-consistency and is NOT ok (a real warning)' ($p.level -eq 'edge-consistency' -and -not $p.ok)
$p = Test-PimHostedAuthPosture -Hosted $true -RequireSignedToken $true
Assert 'hosted strict reports signed-token and is ok' ($p.level -eq 'signed-token' -and $p.ok)

Write-Host "`n== claim/segment edge cases ==" -ForegroundColor Cyan
Assert 'malformed JWT (2 segments) is rejected by the parser' ($null -eq (Get-PimJwtParts -Token 'aa.bb'))
Assert 'empty JWT is rejected by the parser'                  ($null -eq (Get-PimJwtParts -Token ''))
Assert 'JWT with an empty segment is rejected'                ($null -eq (Get-PimJwtParts -Token 'aa..cc'))
Assert 'base64url with an impossible length is rejected'      ($null -eq (ConvertFrom-PimBase64Url -Text 'abcde'))
$c = Test-PimJwtClaims -Payload ([pscustomobject]@{ aud='x' }) -NowUtc $now
Assert 'a payload with NO exp is rejected (no unexpiring principal)' (-not $c.valid) $c.reason

Write-Host ""
if ($script:fail -gt 0) {
    Write-Host ("HOSTED-AUTH GATE: {0} passed, {1} FAILED" -f $script:pass, $script:fail) -ForegroundColor Red
    exit 1
}
Write-Host ("HOSTED-AUTH GATE: {0} passed, 0 failed" -f $script:pass) -ForegroundColor Green
exit 0
