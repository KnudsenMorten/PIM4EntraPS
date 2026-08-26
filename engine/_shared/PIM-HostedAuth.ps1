<#
  PIM4EntraPS -- HOSTED Manager principal authentication (SEC-01).

  WHY THIS EXISTS (audit finding SEC-01, REQUIREMENTS §33.3)
  ---------------------------------------------------------
  The hosted Manager used to resolve the calling identity from ONE plaintext request
  header -- X-MS-CLIENT-PRINCIPAL-NAME -- and hand that identity straight to
  Get-PimManagerRole, which grants SuperAdmin to any UPN listed in PIM_SuperAdmins.
  Nothing in the solution verified that the header actually came from the platform's
  authentication edge. Worse, GET / served the /api bearer token to ANY caller, so the
  token was not a second factor: two requests (GET / for the token, then any /api call
  with a forged principal header) reached SuperAdmin on the privileged-access control
  plane.

  WHAT AUTHENTICITY IS ACTUALLY AVAILABLE TO US
  ---------------------------------------------
  Be precise about this, because it decides what a real fix can promise:

    * X-MS-CLIENT-PRINCIPAL-NAME / -ID / -IDP are CONVENIENCE headers. They carry no
      signature. An app CANNOT cryptographically verify them. They are trustworthy only
      because the auth edge strips any inbound copy and re-injects its own.
    * X-MS-CLIENT-PRINCIPAL is the base64 claims blob the edge injects ALONGSIDE those
      headers. Also unsigned -- but its PRESENCE and its AGREEMENT with the name header
      are a reliable EDGE SIGNATURE: a genuine Easy Auth / Container Apps auth edge
      always injects the set together and consistently.
    * X-MS-TOKEN-AAD-ID-TOKEN is a REAL signed Entra JWT (RS256). This is the only
      artifact the app can verify on its own -- issuer, audience, expiry and signature
      against the tenant JWKS. It is present only when the auth edge is configured to
      store tokens.

  THE TWO LAYERS THIS MODULE IMPLEMENTS
  -------------------------------------
    LAYER 1 -- EDGE-CONSISTENCY (always on, zero lockout risk).
             A name header that arrives WITHOUT the companion X-MS-CLIENT-PRINCIPAL
             blob, or with a blob that disagrees with it, is a SPOOF SIGNATURE: a
             working edge can never produce it. Reject -> unauthenticated.
             This cannot lock out a correctly-fronted deployment, because a correctly
             fronted deployment always sends the whole consistent set.

    LAYER 2 -- SIGNED-TOKEN (strict; opt-in via PIM_HOSTED_REQUIRE_SIGNED_TOKEN).
             Verify X-MS-TOKEN-AAD-ID-TOKEN properly: RS256 signature against the
             tenant JWKS, plus issuer / audience / exp / nbf. Identity is then taken
             from the VERIFIED token, not from any header. This is the layer that makes
             spoofing cryptographically impossible rather than merely inconsistent.
             It is opt-in because it REQUIRES the auth edge to store tokens; turning it
             on without that would lock the Manager out. Enable it after confirming the
             token is present (Test-PimHostedAuthPosture reports exactly that).

  Layer 1 is on by default because it can only reject requests a genuine edge would
  never send. Layer 2 is the real fix and should be enabled once verified live.

  PS 5.1-safe: no ?./??, no ternary, no RSA.ImportFromPem (JWKS n/e -> RSAParameters),
  null-guarded throughout. The decision functions are PURE (no I/O) so they are fully
  unit-testable offline and behave identically live -- tests/Test-PimHostedAuth.ps1.
#>

Set-StrictMode -Off

# ---- base64url / JWT decoding (pure) -----------------------------------------

function ConvertFrom-PimBase64Url {
    # Decode a base64url string (JWT segments, JWKS modulus/exponent) to bytes.
    # Returns $null on anything malformed -- never throws.
    [CmdletBinding()]
    param([string]$Text)
    if ($null -eq $Text) { return $null }
    $s = "$Text".Trim()
    if (-not $s) { return $null }
    $s = $s.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) {
        2 { $s = $s + '==' }
        3 { $s = $s + '=' }
        1 { return $null }   # never a valid base64 length
    }
    try { return [Convert]::FromBase64String($s) } catch { return $null }
}

function ConvertFrom-PimJwtSegment {
    # Decode one JWT segment (header or payload) into an object. $null when malformed.
    [CmdletBinding()]
    param([string]$Segment)
    $bytes = ConvertFrom-PimBase64Url -Text $Segment
    if ($null -eq $bytes) { return $null }
    try { return ([System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json) } catch { return $null }
}

function Get-PimJwtParts {
    # Split a compact JWS into its parts + the exact signing input. Returns $null unless
    # the token is well-formed with three non-empty segments.
    [CmdletBinding()]
    param([string]$Token)
    if (-not "$Token".Trim()) { return $null }
    $parts = "$Token".Trim() -split '\.'
    if ($parts.Count -ne 3) { return $null }
    foreach ($p in $parts) { if (-not "$p".Trim()) { return $null } }
    $header  = ConvertFrom-PimJwtSegment -Segment $parts[0]
    $payload = ConvertFrom-PimJwtSegment -Segment $parts[1]
    if ($null -eq $header -or $null -eq $payload) { return $null }
    return [pscustomobject]@{
        header       = $header
        payload      = $payload
        signature    = $parts[2]
        signingInput = ($parts[0] + '.' + $parts[1])
    }
}

# ---- claim validation (pure) --------------------------------------------------

function Test-PimJwtClaims {
    # PURE: are this token's claims acceptable? Checks issuer, audience, exp and nbf
    # with a small clock-skew allowance. Returns @{ valid; reason }.
    # An EMPTY expected-issuer / expected-audience list means "do not constrain that
    # dimension" -- but exp is ALWAYS enforced (an unexpiring principal is never ok).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Payload,
        [string[]]$ExpectedIssuers = @(),
        [string[]]$ExpectedAudiences = @(),
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int]$ClockSkewSeconds = 300
    )
    if ($null -eq $Payload) { return @{ valid = $false; reason = 'no payload' } }

    # exp -- mandatory. Unix seconds.
    $expRaw = "$($Payload.exp)".Trim()
    if (-not $expRaw -or $expRaw -notmatch '^\d+$') { return @{ valid = $false; reason = 'missing/!numeric exp claim' } }
    $expUtc = ([datetimeoffset]::FromUnixTimeSeconds([int64]$expRaw)).UtcDateTime
    if ($NowUtc.ToUniversalTime() -gt $expUtc.AddSeconds($ClockSkewSeconds)) {
        return @{ valid = $false; reason = ("token expired at {0:o}" -f $expUtc) }
    }
    # nbf -- optional, enforced when present.
    $nbfRaw = "$($Payload.nbf)".Trim()
    if ($nbfRaw -and $nbfRaw -match '^\d+$') {
        $nbfUtc = ([datetimeoffset]::FromUnixTimeSeconds([int64]$nbfRaw)).UtcDateTime
        if ($NowUtc.ToUniversalTime() -lt $nbfUtc.AddSeconds(-$ClockSkewSeconds)) {
            return @{ valid = $false; reason = ("token not valid before {0:o}" -f $nbfUtc) }
        }
    }
    # iss
    $issuers = @($ExpectedIssuers | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($issuers.Count -gt 0) {
        $iss = "$($Payload.iss)".Trim()
        if (-not $iss) { return @{ valid = $false; reason = 'missing iss claim' } }
        $ok = $false
        foreach ($i in $issuers) { if ($iss -eq $i) { $ok = $true; break } }
        if (-not $ok) { return @{ valid = $false; reason = ("issuer '$iss' is not an expected issuer") } }
    }
    # aud -- may be a string or an array.
    $auds = @($ExpectedAudiences | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($auds.Count -gt 0) {
        $tokenAuds = @(@($Payload.aud) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if ($tokenAuds.Count -eq 0) { return @{ valid = $false; reason = 'missing aud claim' } }
        $ok = $false
        foreach ($a in $tokenAuds) { if ($auds -contains $a) { $ok = $true; break } }
        if (-not $ok) { return @{ valid = $false; reason = ("audience '{0}' is not an expected audience" -f ($tokenAuds -join ',')) } }
    }
    return @{ valid = $true; reason = 'claims ok' }
}

# ---- signature validation (pure given a key set) ------------------------------

function Test-PimJwtSignature {
    # PURE given $Jwks: verify the RS256 signature of a parsed JWT against a JWKS-shaped
    # key set (@{ keys = @( @{ kid; n; e; kty } ) }). Returns @{ valid; reason }.
    # Only RS256/RS384/RS512 are accepted -- 'none' and HMAC algs are REFUSED outright
    # (the classic alg-confusion downgrade).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Jwt,
        [Parameter(Mandatory)][object]$Jwks
    )
    if ($null -eq $Jwt -or $null -eq $Jwt.header) { return @{ valid = $false; reason = 'no parsed token' } }
    $alg = "$($Jwt.header.alg)".Trim().ToUpperInvariant()
    $hash = $null
    if     ($alg -eq 'RS256') { $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
    elseif ($alg -eq 'RS384') { $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA384 }
    elseif ($alg -eq 'RS512') { $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA512 }
    else { return @{ valid = $false; reason = ("unsupported/unsafe alg '$alg' (only RS256/384/512 accepted)") } }

    $kid = "$($Jwt.header.kid)".Trim()
    $keys = @()
    if ($Jwks -and $Jwks.keys) { $keys = @($Jwks.keys) }
    if ($keys.Count -eq 0) { return @{ valid = $false; reason = 'empty key set' } }

    $match = $null
    foreach ($k in $keys) {
        if ($null -eq $k) { continue }
        if ($kid -and "$($k.kid)".Trim() -ne $kid) { continue }
        if ("$($k.kty)".Trim() -and "$($k.kty)".Trim().ToUpperInvariant() -ne 'RSA') { continue }
        $match = $k; break
    }
    if ($null -eq $match) { return @{ valid = $false; reason = ("no JWKS key matches kid '$kid'") } }

    $modulus  = ConvertFrom-PimBase64Url -Text "$($match.n)"
    $exponent = ConvertFrom-PimBase64Url -Text "$($match.e)"
    if ($null -eq $modulus -or $null -eq $exponent) { return @{ valid = $false; reason = 'JWKS key modulus/exponent unreadable' } }
    $sig = ConvertFrom-PimBase64Url -Text "$($Jwt.signature)"
    if ($null -eq $sig) { return @{ valid = $false; reason = 'signature is not valid base64url' } }

    $rsa = $null
    try {
        # RSAParameters import -- NOT ImportFromPem (unavailable on PS 5.1, see §22).
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $p = New-Object System.Security.Cryptography.RSAParameters
        $p.Modulus  = $modulus
        $p.Exponent = $exponent
        $rsa.ImportParameters($p)
        $data = [System.Text.Encoding]::ASCII.GetBytes($Jwt.signingInput)
        $ok = $rsa.VerifyData($data, $sig, $hash, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        if ($ok) { return @{ valid = $true;  reason = 'signature verified' } }
        return         @{ valid = $false; reason = 'signature verification FAILED' }
    } catch {
        return @{ valid = $false; reason = ("signature check errored: " + $_.Exception.Message) }
    } finally {
        if ($null -ne $rsa) { try { $rsa.Dispose() } catch {} }
    }
}

# ---- LAYER 1: edge consistency (pure) -----------------------------------------

function Get-PimPrincipalNameFromBlob {
    # Extract the caller name from a decoded X-MS-CLIENT-PRINCIPAL claims blob.
    # Shape: @{ auth_typ; name_typ; claims = @( @{ typ; val } ) }. Falls back across the
    # usual name claim types. Returns '' when nothing name-like is present.
    [CmdletBinding()]
    param([object]$Blob)
    if ($null -eq $Blob) { return '' }
    $claims = @()
    if ($Blob.claims) { $claims = @($Blob.claims) }
    $preferred = @()
    if ("$($Blob.name_typ)".Trim()) { $preferred += "$($Blob.name_typ)".Trim() }
    $preferred += @(
        'preferred_username',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
        'upn',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        'name',
        'email'
    )
    foreach ($typ in $preferred) {
        foreach ($c in $claims) {
            if ($null -eq $c) { continue }
            if ("$($c.typ)".Trim() -eq $typ -and "$($c.val)".Trim()) { return "$($c.val)".Trim() }
        }
    }
    return ''
}

function Test-PimEdgeHeadersConsistent {
    # PURE -- LAYER 1. Given the raw header values, decide whether this request carries a
    # coherent auth-edge identity. Returns @{ trusted; identity; reason }.
    #
    # The SPOOF SIGNATURE this catches: a name header with NO companion principal blob,
    # or a blob whose name disagrees with the name header. A genuine edge always injects
    # the set together and consistently, so rejecting this can never lock out a
    # correctly-fronted deployment.
    [CmdletBinding()]
    param(
        [string]$PrincipalName = '',      # X-MS-CLIENT-PRINCIPAL-NAME
        [string]$PrincipalBlob = ''       # X-MS-CLIENT-PRINCIPAL (base64 JSON)
    )
    $name = "$PrincipalName".Trim()
    $blob = "$PrincipalBlob".Trim()

    if (-not $name -and -not $blob) {
        return @{ trusted = $false; identity = ''; reason = 'no auth-edge headers present (unauthenticated)' }
    }
    if ($name -and -not $blob) {
        # THE spoof signature.
        return @{ trusted = $false; identity = ''; reason = 'X-MS-CLIENT-PRINCIPAL-NAME present WITHOUT the companion X-MS-CLIENT-PRINCIPAL blob -- did not come from the auth edge (rejected)' }
    }
    $bytes = ConvertFrom-PimBase64Url -Text $blob
    if ($null -eq $bytes) {
        return @{ trusted = $false; identity = ''; reason = 'X-MS-CLIENT-PRINCIPAL is not valid base64 (rejected)' }
    }
    $decoded = $null
    try { $decoded = ([System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json) } catch { $decoded = $null }
    if ($null -eq $decoded) {
        return @{ trusted = $false; identity = ''; reason = 'X-MS-CLIENT-PRINCIPAL is not valid JSON (rejected)' }
    }
    $blobName = Get-PimPrincipalNameFromBlob -Blob $decoded
    if (-not $blobName) {
        return @{ trusted = $false; identity = ''; reason = 'X-MS-CLIENT-PRINCIPAL carries no name/upn claim (rejected)' }
    }
    if ($name -and ($blobName.ToLowerInvariant() -ne $name.ToLowerInvariant())) {
        return @{ trusted = $false; identity = ''; reason = ("X-MS-CLIENT-PRINCIPAL-NAME ('$name') disagrees with the principal blob ('$blobName') -- rejected") }
    }
    $identity = $name
    if (-not $identity) { $identity = $blobName }
    return @{ trusted = $true; identity = $identity; reason = 'auth-edge headers consistent' }
}

# ---- the composite decision ---------------------------------------------------

function Test-PimHostedSignedTokenRequired {
    # Is LAYER 2 (signed-token verification) required? Opt-in, because it needs the auth
    # edge to store tokens. Explicit $Override wins (tests / callers).
    [CmdletBinding()]
    param([object]$Override = $null)
    if ($null -ne $Override) {
        if (Get-Command Test-PimExplicitFlagValue -ErrorAction SilentlyContinue) {
            $ov = Test-PimExplicitFlagValue -Value $Override
            if ($null -ne $ov) { return [bool]$ov }
        } elseif ($Override -is [bool]) { return [bool]$Override }
    }
    $v = "$env:PIM_HOSTED_REQUIRE_SIGNED_TOKEN".Trim().ToLowerInvariant()
    return ($v -in @('1', 'true', 'yes', 'y', 'on', 'enable', 'enabled'))
}

function Resolve-PimHostedPrincipal {
    # THE decision the hosted request loop asks for every request. Composes layer 1 and
    # (when required) layer 2, and FAILS CLOSED on anything it cannot positively trust.
    # Returns @{ trusted; identity; layer; reason }.
    #
    # $SignedToken is X-MS-TOKEN-AAD-ID-TOKEN. $Jwks/$ExpectedIssuers/$ExpectedAudiences
    # are supplied by the caller (fetched + cached outside this pure decision) so this
    # function stays I/O-free and unit-testable.
    [CmdletBinding()]
    param(
        [string]$PrincipalName = '',
        [string]$PrincipalBlob = '',
        [string]$SignedToken = '',
        [object]$Jwks = $null,
        [string[]]$ExpectedIssuers = @(),
        [string[]]$ExpectedAudiences = @(),
        [object]$RequireSignedToken = $null,
        [datetime]$NowUtc = ([datetime]::UtcNow)
    )
    # LAYER 1 -- always.
    $edge = Test-PimEdgeHeadersConsistent -PrincipalName $PrincipalName -PrincipalBlob $PrincipalBlob
    $strict = Test-PimHostedSignedTokenRequired -Override $RequireSignedToken
    if (-not $edge.trusted) {
        return @{ trusted = $false; identity = ''; layer = 'edge-consistency'; reason = $edge.reason }
    }
    if (-not $strict) {
        return @{ trusted = $true; identity = $edge.identity; layer = 'edge-consistency'; reason = $edge.reason }
    }

    # LAYER 2 -- signed token required.
    if (-not "$SignedToken".Trim()) {
        return @{ trusted = $false; identity = ''; layer = 'signed-token'; reason = 'PIM_HOSTED_REQUIRE_SIGNED_TOKEN is on but no X-MS-TOKEN-AAD-ID-TOKEN was supplied (enable token store on the auth edge)' }
    }
    $jwt = Get-PimJwtParts -Token $SignedToken
    if ($null -eq $jwt) {
        return @{ trusted = $false; identity = ''; layer = 'signed-token'; reason = 'X-MS-TOKEN-AAD-ID-TOKEN is not a well-formed JWT' }
    }
    if ($null -eq $Jwks) {
        # Fail CLOSED: strict mode with no key set cannot verify anything.
        return @{ trusted = $false; identity = ''; layer = 'signed-token'; reason = 'no JWKS available to verify the token (failing closed)' }
    }
    $sig = Test-PimJwtSignature -Jwt $jwt -Jwks $Jwks
    if (-not $sig.valid) {
        return @{ trusted = $false; identity = ''; layer = 'signed-token'; reason = ("token signature rejected: " + $sig.reason) }
    }
    $cl = Test-PimJwtClaims -Payload $jwt.payload -ExpectedIssuers $ExpectedIssuers -ExpectedAudiences $ExpectedAudiences -NowUtc $NowUtc
    if (-not $cl.valid) {
        return @{ trusted = $false; identity = ''; layer = 'signed-token'; reason = ("token claims rejected: " + $cl.reason) }
    }
    # Identity comes from the VERIFIED token, never from the headers.
    $tokenName = ''
    foreach ($p in @('preferred_username', 'upn', 'email', 'unique_name')) {
        $v = "$($jwt.payload.$p)".Trim()
        if ($v) { $tokenName = $v; break }
    }
    if (-not $tokenName) {
        return @{ trusted = $false; identity = ''; layer = 'signed-token'; reason = 'verified token carries no username claim' }
    }
    # The header identity must match the verified token, or the headers are lying.
    if ($edge.identity -and ($edge.identity.ToLowerInvariant() -ne $tokenName.ToLowerInvariant())) {
        return @{ trusted = $false; identity = ''; layer = 'signed-token'; reason = ("header identity ('$($edge.identity)') disagrees with the VERIFIED token identity ('$tokenName') -- rejected") }
    }
    return @{ trusted = $true; identity = $tokenName; layer = 'signed-token'; reason = 'signed token verified (signature + claims)' }
}

# ---- startup posture ----------------------------------------------------------

function Test-PimHostedAuthPosture {
    # PURE: describe the authentication posture at boot so the operator is told, loudly,
    # exactly which layer is protecting the Manager. Returns
    # @{ hosted; strict; level; ok; message }.
    [CmdletBinding()]
    param(
        [bool]$Hosted = $false,
        [object]$RequireSignedToken = $null
    )
    $strict = Test-PimHostedSignedTokenRequired -Override $RequireSignedToken
    if (-not $Hosted) {
        return @{ hosted = $false; strict = $false; level = 'local'; ok = $true
                  message = 'LOCAL mode: identity is the Windows user; the listener binds to loopback.' }
    }
    if ($strict) {
        return @{ hosted = $true; strict = $true; level = 'signed-token'; ok = $true
                  message = 'HOSTED auth: STRICT -- the signed Entra token is verified (signature + issuer + audience + expiry) on every request.' }
    }
    return @{ hosted = $true; strict = $false; level = 'edge-consistency'; ok = $false
              message = @(
                  'HOSTED auth: EDGE-CONSISTENCY ONLY (not cryptographically verified).'
                  '  A request is trusted when its auth-edge headers are internally consistent, which'
                  '  blocks naive spoofing but still ASSUMES the auth edge is in front of this app.'
                  '  To close SEC-01 fully: enable token store on the auth edge, confirm'
                  '  X-MS-TOKEN-AAD-ID-TOKEN arrives, then set PIM_HOSTED_REQUIRE_SIGNED_TOKEN=1.'
              ) -join [Environment]::NewLine }
}
