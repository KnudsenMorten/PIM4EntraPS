<#
  PIM4EntraPS -- HOSTED Manager principal authentication (SEC-01).

  WHAT THIS FILE ENFORCES (SEC-01, REQUIREMENTS §33.3)
  ----------------------------------------------------
  The hosted Manager accepts a calling identity only when the platform's authentication
  edge vouches for it (the rules below), before Get-PimManagerRole maps it to a role.
  GET / and every /api call require that positively-trusted principal; the page and the
  token it carries are never served to an unauthenticated caller.

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

  🔴 SEC-28 / SEC-31 (§33.28) -- LAYER 1 IS ONLY AS GOOD AS THE EDGE IN FRONT OF IT.
  A client can build a consistent name header + principal blob itself; the pair is
  trustworthy only because Easy Auth STRIPS client-supplied X-MS-* headers ("External
  requests aren't allowed to set these headers" -- Container Apps / App Service docs).
  Where no Easy Auth is in front (a VM from Setup-PimVM, a container app created before
  its Easy Auth step) the headers are the caller's own words. So the AUTH LAYER in front
  is now an explicit fact (Get-PimHostedAuthLayer):
    easyauth      -- the platform edge strips + injects the headers (layer 1, + layer 2
                     when PIM_HOSTED_REQUIRE_SIGNED_TOKEN is on).
    signed-token  -- layer 2 is REQUIRED; with no edge headers at all the identity may
                     come from the verified token alone, but only with the issuer AND
                     audience pinned (an unpinned check accepts any tenant's token).
    none          -- nothing strips the headers: every header identity is REFUSED.
  PIM_HOSTED_AUTH_LAYER sets it explicitly. Unset, it is derived from the PLATFORM:
  Container Apps (CONTAINER_APP_NAME) and App Service (WEBSITE_SITE_NAME) are the only
  hosts that offer Easy Auth, so they keep 'easyauth' (every live Manager is one of them
  -- nothing is locked out); anything else hosted is 'none'.
  🪤 Layer 2 is deliberately NOT turned on by default: Set-PimManagerEasyAuth does not
  enable the token store, so X-MS-TOKEN-AAD-ID-TOKEN is absent on every Manager except
  the one where it was enabled by hand -- default-on would reject every sign-in there.

  🟡 CR7 / framework §12.11g -- WEB SIGN-IN WITHOUT A SECRET (lane build 2026-10-18, OFF by default).
  A FOURTH layer, 'signin-front', for the shared sign-in front (FRAMEWORK/signin-front/, one
  component for PIM and SI; RETIRED 2026-11-19, framework SECURE-WEB-1 ONE STANDARD (a) -- no longer built or shipped): the front is the only
  container the ingress reaches, it strips EVERY inbound identity header and forwards the user's
  signed ID token as 'Authorization: Bearer <JWT>' on each request; this Manager
  listens on 127.0.0.1 only (Get-PimHostedListenerPrefix) and takes identity from that VERIFIED
  token alone (Resolve-PimSigninFrontPrincipal) -- X-MS-* headers are never read in this layer.
  Selected ONLY by PIM_HOSTED_AUTH_LAYER=signin-front; unset, every Manager keeps today's
  Easy Auth path unchanged.

  PS 5.1-safe syntax: no ?./??, no ternary (the token library itself needs PowerShell 7 / .NET 10 -- see PIM-TokenValidation.ps1),
  null-guarded throughout. The decision functions are PURE (no I/O) so they are fully
  unit-testable offline and behave identically live -- tests/Test-PimHostedAuth.ps1.
#>

Set-StrictMode -Off

# AUTH-MODERN-1 (framework decision c5704c10): every token SIGNATURE / issuer / audience / lifetime check below goes through
# Microsoft.IdentityModel (engine/_shared/PIM-TokenValidation.ps1, the vendored, hash-pinned library). This file keeps only
# the AUTHORIZATION facts (tenant, scope, a person, the edge headers) and the unverified base64 / kid readers.
. (Join-Path $PSScriptRoot 'PIM-TokenValidation.ps1')

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

function Get-PimJwtAppOnlyReason {
    <#
      PURE. SEC-89: is this (already parsed) token an APPLICATION's token rather than a person's? Every path that
      expects a PERSON calls it explicitly, so an app-only token is refused for what it is -- never only because it
      happens to lack a username claim. Returns '' for a person's token, else the refusal reason:
        * idtyp = app                                   -> an application token
        * application roles (roles) and no user claim   -> a token with application roles and no user
          (user claims: preferred_username, upn, unique_name, email, name)
      /api/app and the RFA broker accept applications on purpose and do NOT call this.
    #>
    [CmdletBinding()] param([AllowNull()][object]$Payload)
    if ($null -eq $Payload) { return '' }
    $get = {
        param($n)
        if ($Payload -is [System.Collections.IDictionary]) { if ($Payload.Contains($n)) { return $Payload[$n] }; return $null }
        $p = $Payload.PSObject.Properties[$n]; if ($p) { return $p.Value }; return $null
    }
    if ("$(& $get 'idtyp')".Trim().ToLowerInvariant() -eq 'app') {
        return 'an application token (idtyp = app) was presented where a person must sign in -- refused'
    }
    $roles = @(@(& $get 'roles') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($roles.Count) {
        $user = ''
        # 'name' counts too: a person's token carries it even where a tenant drops the optional username claims; an
        # app-only token has none. (It never rescues idtyp = app, refused above.)
        foreach ($c in @('preferred_username', 'upn', 'unique_name', 'email', 'name')) { $v = "$(& $get $c)".Trim(); if ($v) { $user = $v; break } }
        if (-not $user) { return 'a token with application roles and no user was presented where a person must sign in -- refused' }
    }
    return ''
}

# (the hand-written claim / signature checks Test-PimJwtClaims / Test-PimJwtSignature are gone -- AUTH-MODERN-1: every token
#  is validated by Microsoft.IdentityModel through Invoke-PimTokenValidation, PIM-TokenValidation.ps1)

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

function Get-PimPrincipalNamesFromBlob {
    <#
      EVERY name-like value in the blob, not just the preferred one.

      🔴 WHY THIS EXISTS. The edge-consistency check compared X-MS-CLIENT-PRINCIPAL-NAME against
      Get-PimPrincipalNameFromBlob, which prefers `preferred_username` -- the UPN. But Easy Auth
      populates that HEADER from whichever claim the provider designates as its name claim, and for
      an Entra v2 token that is routinely `name` -- the DISPLAY name. So a completely legitimate
      sign-in produced:
          X-MS-CLIENT-PRINCIPAL-NAME ('Morten Knudsen (Admin, Cloud, ID)')
          disagrees with the principal blob ('x-Admin-MOK-ID@contoso.example')
      and every human was locked out of a correctly-deployed Manager. Measured at a customer
      2026-09-12, on an environment whose sign-in had otherwise completed: "Login completed for
      'Mo**PII**'. Provider: 'aad'".

      🔑 THE SECURITY INTENT IS UNCHANGED. What the check defends against is a caller setting the
      NAME header WITHOUT a matching blob (the spoof signature), or with a blob describing someone
      else. "Do they describe the same principal?" is answered correctly by matching the header
      against ANY name-like claim the blob carries -- the display name and the UPN are two true
      names for one person. An attacker still has to produce a consistent blob, which is the same
      bar as before; nothing is relaxed about what must be present.
    #>
    [CmdletBinding()]
    param([object]$Blob)
    if ($null -eq $Blob) { return @() }
    $claims = @()
    if ($Blob.claims) { $claims = @($Blob.claims) }
    $wanted = @(
        'preferred_username',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
        'upn',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        'name',
        'email',
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
    )
    if ("$($Blob.name_typ)".Trim()) { $wanted = @("$($Blob.name_typ)".Trim()) + $wanted }
    $out = @()
    foreach ($c in $claims) {
        if ($null -eq $c) { continue }
        $t = "$($c.typ)".Trim(); $v = "$($c.val)".Trim()
        if (-not $v) { continue }
        if ($wanted -contains $t) { $out += $v }
    }
    return @($out | Select-Object -Unique)
}

function Get-PimPrincipalObjectIdFromBlob {
    # SEC-90: the Entra object id (oid) in a decoded X-MS-CLIENT-PRINCIPAL claims blob, lower-case, or '' when the blob
    # carries none (or a value that is not a GUID). Read only AFTER the blob passed the edge-consistency check.
    [CmdletBinding()]
    param([object]$Blob)
    if ($null -eq $Blob -or -not $Blob.claims) { return '' }
    foreach ($typ in @('http://schemas.microsoft.com/identity/claims/objectidentifier', 'oid')) {
        foreach ($c in @($Blob.claims)) {
            if ($null -eq $c) { continue }
            $v = "$($c.val)".Trim()
            if ("$($c.typ)".Trim() -eq $typ -and $v -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return $v.ToLowerInvariant() }
        }
    }
    return ''
}

function Get-PimJwtObjectId {
    # SEC-90: the oid claim of a VERIFIED token payload, lower-case, or '' (none / not a GUID).
    [CmdletBinding()]
    param([object]$Payload)
    if ($null -eq $Payload) { return '' }
    $v = "$($Payload.oid)".Trim()
    if ($v -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return $v.ToLowerInvariant() }
    return ''
}

function ConvertFrom-PimEdgeHeaderValue {
    <#
      PURE. Every spelling an auth edge may have written a name claim into an ASCII-only HTTP header:
      percent-encoded ('S%C3%B8rensen'), form-encoded with '+' for spaces, or both. Returns the decoded
      forms (never the input, and never $null entries) -- the caller compares them ALONGSIDE the raw
      value, so a decode that fails or changes nothing simply adds nothing.
      🔒 Decoding is deliberately tolerant: a malformed escape returns no extra form rather than
      throwing, because a header this function cannot read must fall through to the normal rejection,
      not take the request down.
    #>
    [CmdletBinding()]
    param([string]$Value = '')
    $v = "$Value"
    if (-not $v.Trim()) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    $try = {
        param($s)
        if ($null -eq $s -or "$s" -eq '' -or "$s" -eq $v) { return }
        if (-not $out.Contains("$s")) { $out.Add("$s") }
    }
    # 1. percent-decoding only (a name that genuinely contains '+' must survive)
    try { & $try ([System.Uri]::UnescapeDataString($v)) } catch { }
    # 2. form-decoding: '+' means space as well
    if ($v.IndexOf('+') -ge 0) {
        try { & $try ([System.Uri]::UnescapeDataString($v.Replace('+', ' '))) } catch { }
        try { & $try ($v.Replace('+', ' ')) } catch { }
    }
    return @($out.ToArray())
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
    # 🔑 MATCH AGAINST EVERY NAME THE BLOB CARRIES, not only the preferred one. The header is the
    # provider's designated name claim (often the DISPLAY name); the blob's preferred value is the
    # UPN. Demanding they be the same string locked every human out of a correctly-fronted Manager
    # -- see Get-PimPrincipalNamesFromBlob for the measured case. A header that matches NONE of the
    # blob's names is still rejected, which is the property this check exists for.
    $blobNames = @(Get-PimPrincipalNamesFromBlob -Blob $decoded)
    # 🔴 THE HEADER IS URL-ENCODED, THE BLOB IS NOT (live, a test tenant, 2026-09-22). An HTTP header may only
    # carry ASCII, so the auth edge percent-encodes the name claim and writes spaces as '+':
    #     header 'Avery+Jordan+Lind+S%C3%B8rensen+(adm-e-alin-t0-c)'
    #     blob   'Avery Jordan Lind Sørensen (adm-e-alin-t0-c)'
    # Compared literally those never match, so THIS CHECK LOCKED OUT every user whose display name
    # carries a space or a non-ASCII letter -- the measured 401 was
    #     "no authenticated principal -- this app must be reached through its authentication edge",
    # which reads as a missing auth edge when the edge was working perfectly.
    # 🔑 The decoded form is compared IN ADDITION to the raw one: decoding is a widening of what the
    # check accepts for the same identity, never of WHICH identities it accepts -- a header that
    # matches none of the blob's names, encoded or not, is still rejected.
    $nameForms = @($name)
    foreach ($dec in @(ConvertFrom-PimEdgeHeaderValue -Value $name)) { if ($dec -and $nameForms -notcontains $dec) { $nameForms += $dec } }
    $nameAgrees = $false
    foreach ($bn in $blobNames) {
        foreach ($nf in $nameForms) { if ("$bn".ToLowerInvariant() -eq "$nf".ToLowerInvariant()) { $nameAgrees = $true; break } }
        if ($nameAgrees) { break }
    }
    if ($name -and -not $nameAgrees) {
        # List what the blob DID carry -- "disagrees with ('<one value>')" sent the last diagnosis
        # looking for a tampering that was not there, when the real answer was "the header is the
        # display name and I was only comparing the UPN".
        return @{ trusted = $false; identity = ''; reason = ("X-MS-CLIENT-PRINCIPAL-NAME ('$name') matches none of the principal blob's names (" +
                  (($blobNames | ForEach-Object { "'$_'" }) -join ', ') + ") -- rejected") }
    }
    # 🔴 THE IDENTITY IS THE UPN, NEVER THE DISPLAY NAME. Everything downstream authorises on UPN --
    # ManagerAccess, the SuperAdmin list, the audit trail. Returning the header here meant a user
    # whose NAME header is a display name ('Morten Knudsen (Admin, Cloud, ID)') would authenticate
    # and then be denied as an unknown principal, or worse be recorded in the audit under a name
    # that matches no account. Get-PimPrincipalNameFromBlob already prefers preferred_username/upn,
    # so prefer IT and keep the header only as the fallback for an edge that sends no blob claims.
    $identity = $blobName
    if (-not $identity) { $identity = $name }
    return @{ trusted = $true; identity = $identity; oid = (Get-PimPrincipalObjectIdFromBlob -Blob $decoded); reason = 'auth-edge headers consistent' }
}

function Get-PimAccessTokenAudiences {
    <#
      PURE. AUTH-MODERN-1: the audiences an access token for THIS app may carry -- each pinned value as given plus its
      api:// form (a v2 token names the bare client id, a v1 token the api:// URI). Empty in = empty out (never "any").
    #>
    [CmdletBinding()] param([string[]]$Audiences = @())
    $a = @($Audiences | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    return @(@($a) + @($a | Where-Object { $_ -notmatch '^api://' } | ForEach-Object { "api://$_" }) + @($a | Where-Object { $_ -match '^api://' } | ForEach-Object { $_.Substring(6) }) | Select-Object -Unique)
}

function Resolve-PimAccessTokenCaller {
    <#
      AUTH-MODERN-1 / SIGNIN-TOKEN-LIFETIME-1: is this a PERSON's Entra ACCESS token for THIS app, from THIS tenant, now?
      The token itself (signature RS256, issuer = this tenant v1 / v2, audience = this app as id or api://id, exp / nbf with
      5 minutes clock skew) is validated by Microsoft.IdentityModel (Invoke-PimTokenValidation). Then the AUTHORIZATION facts:
      tid = this tenant, not an application's token (SEC-89), a delegated scope (scp) holding one of -Scopes, a user
      (preferred_username / upn / unique_name -- never the email claim) and an oid. Each refusal names its reason.
      Used by the web path (the sign-in's access token, a script's bearer), /mcp and the sign-in front.
      @{ trusted; identity; oid; reason; kind = 'access'; scopes }.
    #>
    [CmdletBinding()]
    param(
        [string]$Token = '',
        [object]$Jwks = $null,
        [string[]]$ExpectedIssuers = @(),
        [string[]]$ExpectedAudiences = @(),
        [string]$TenantId = '',
        [string[]]$Scopes = @('user_impersonation')
    )
    $no = { param($why) return @{ trusted = $false; identity = ''; oid = ''; reason = $why; kind = 'access'; scopes = @() } }
    $want = @($Scopes | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($want.Count -eq 0) { return (& $no 'access token: no scope is pinned -- failing closed') }
    $t = "$Token".Trim()
    if (-not $t) { return (& $no 'no access token on the request') }
    if ($null -eq (Get-PimJwtParts -Token $t)) { return (& $no 'the access token is not a well-formed JWT (an API key or any other non-Entra value is never accepted)') }
    $v = Invoke-PimTokenValidation -Token $t -Jwks $Jwks -ExpectedIssuers $ExpectedIssuers -ExpectedAudiences (Get-PimAccessTokenAudiences -Audiences $ExpectedAudiences)
    if (-not $v.valid) { return (& $no ("access token: " + $v.reason)) }
    $pl = $v.payload
    $tid = "$TenantId".Trim(); $tokTid = "$($pl.tid)".Trim()
    if ($tid -and -not $tokTid) { return (& $no 'access token: no tid claim (refused)') }
    if ($tid -and $tokTid -ine $tid) { return (& $no "access token: tid '$tokTid' is not this tenant") }
    $appOnly = Get-PimJwtAppOnlyReason -Payload $pl
    if ($appOnly) { return (& $no ("access token: " + $appOnly)) }
    $scp = @("$($pl.scp)".Trim() -split '\s+' | Where-Object { $_ })
    if ($scp.Count -eq 0) { return (& $no 'not a person''s access token (no scp -- an ID token or an application token is refused)') }
    if (-not @($scp | Where-Object { $want -contains $_ }).Count) { return (& $no ("access token scope '$($scp -join ' ')' is not '$($want -join ''' or ''')'")) }
    $who = ''
    foreach ($c in @('preferred_username', 'upn', 'unique_name')) { $x = "$($pl.$c)".Trim(); if ($x) { $who = $x; break } }
    $oid = Get-PimJwtObjectId -Payload $pl
    if (-not $who -or -not $oid) { return (& $no 'access token names no user (preferred_username / upn and oid)') }
    return @{ trusted = $true; identity = $who; oid = $oid; reason = 'access token validated by Microsoft.IdentityModel; tenant, person and scope authorised'; kind = 'access'; scopes = @($scp) }
}

function Get-PimJwtAudienceUnverified {
    <#
      PURE. The aud claim(s) of a token WITHOUT verifying it -- used ONLY to tell "an access token for another resource"
      (the platform's default token when the sign-in does not request this app's API scope yet) from "an access token for
      THIS app" (which must then verify, or the request is refused). It never decides trust.
    #>
    [CmdletBinding()] param([string]$Token = '')
    $j = Get-PimJwtParts -Token $Token
    if ($null -eq $j) { return @() }
    return @(@($j.payload.aud) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
}

function Resolve-PimMcpBearer {
    <#
      PURE given its inputs. REQ 93 -- who is calling /mcp, proven by the BEARER TOKEN itself, never by edge headers.
      🔴 BUG-283 (live, internal 2026-10-03): once Easy Auth accepted the api://<app> audience, an APP-ONLY token (client
      credentials -- any service principal in the tenant, no person) passed it with a principal, and an unknown principal
      is Reader. §93.2 decided "the person signs in": a delegated token carries the scope in `scp`; an app-only one does not.
      🔑 Verified HERE (signature against the tenant JWKS, issuer + audience pinned, exp) so /mcp can sit outside Easy Auth
      (excludedPaths) and answer an unauthenticated client 401 + WWW-Authenticate -- the MCP sign-in discovery -- instead of
      a 302 to the login page. Outside Easy Auth the X-MS-* headers are the caller's own words, so they are never read.
      Returns @{ ok; status (401 = no / bad token, 403 = valid token but not allowed, 503 = not configured); identity; reason }.
      AUTH-MODERN-1 (owner 2026-11-15 "use only modern and secure method"): the token is checked by Test-PimAccessToken --
      RS256 only, issuer + tid pinned to this tenant, aud = this app (id or api://id), exp / nbf with clock skew, a
      delegated scope (-Scopes: user_impersonation, the standard; mcp.access, the scope earlier MCP setups created), a user
      + oid. An API key, a non-JWT, the wrong audience / tenant, an expired token or a token without scp (an ID token, an
      application token) = 401. Only a VALID person's token for another scope is 403 (insufficient scope). Applications
      reach the API through the allow-listed /api/app path (PIM-ManagerApiApps.ps1), never through /mcp.
    #>
    [CmdletBinding()]
    param(
        [string]$Authorization = '',
        [object]$Jwks = $null,
        [string[]]$ExpectedIssuers = @(),
        [string[]]$ExpectedAudiences = @(),
        [string[]]$Scopes = @('user_impersonation', 'mcp.access'),
        [string]$TenantId = '',
        [datetime]$NowUtc = ([datetime]::UtcNow)
    )
    $iss = @($ExpectedIssuers | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $aud = @($ExpectedAudiences | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $want = @($Scopes | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($iss.Count -eq 0 -or $aud.Count -eq 0) {
        return @{ ok = $false; status = 503; identity = ''; reason = 'MCP sign-in is not configured on this Manager (no pinned issuer / audience: PIM_HOSTED_AUTH_TENANT + PIM_HOSTED_EASYAUTH_AUD, or PIM_MCP_AUDIENCE)' }
    }
    if ("$Authorization" -notmatch '^\s*Bearer\s+(\S+)\s*$') { return @{ ok = $false; status = 401; identity = ''; reason = 'no bearer token' } }
    $tok = $Matches[1]
    $jwt = Get-PimJwtParts -Token $tok
    if ($null -eq $jwt) { return @{ ok = $false; status = 401; identity = ''; reason = 'the bearer token is not a well-formed JWT (an API key or any other non-Entra value is never accepted)' } }
    if ($null -eq $Jwks) { return @{ ok = $false; status = 503; identity = ''; reason = 'the tenant signing keys could not be fetched -- cannot verify any token (refused)' } }
    $v = Resolve-PimAccessTokenCaller -Token $tok -Jwks $Jwks -ExpectedIssuers $iss -ExpectedAudiences $aud -TenantId $TenantId -Scopes $want
    if (-not $v.trusted) {
        # a VALID person's token that only lacks the scope is 403 (insufficient_scope); everything else is 401
        $st = 401
        if ("$($v.reason)" -match '^access token scope ') { $st = 403 }
        return @{ ok = $false; status = $st; identity = ''; reason = ("MCP: " + $v.reason + $(if ($st -eq 403) { " -- request a token for api://<this Manager>/$($want[0])" } else { '' })) }
    }
    return @{ ok = $true; status = 200; identity = "$($v.identity)"; oid = "$($v.oid)"; reason = 'delegated access token verified'; token = $tok }
}

# ---- the composite decision ---------------------------------------------------

function Get-PimHostedAuthLayer {
    # PURE given its inputs: WHICH authentication layer stands in front of this hosted
    # Manager -- 'easyauth' | 'signed-token' | 'signin-front' | 'none' (SEC-28/SEC-31, CR7,
    # see the header). 'signin-front' is never derived from the platform -- only an explicit
    # PIM_HOSTED_AUTH_LAYER selects it, so no existing install changes path by itself.
    #   * explicit PIM_HOSTED_AUTH_LAYER wins; an UNRECOGNISED value is 'none' (a typo in
    #     a security setting must fail closed, never open);
    #   * unset: Container Apps / App Service (the hosts that offer Easy Auth) -> 'easyauth',
    #     any other host -> 'none'.
    # -Value / -EnvMap are for tests; the defaults read the process environment.
    [CmdletBinding()]
    param(
        [AllowNull()][object]$Value = $null,
        [hashtable]$EnvMap = $null
    )
    $get = {
        param($n)
        if ($null -ne $EnvMap) { if ($EnvMap.ContainsKey($n)) { return "$($EnvMap[$n])" }; return '' }
        return "$([Environment]::GetEnvironmentVariable($n))"
    }
    $raw = if ($null -ne $Value) { "$Value" } else { & $get 'PIM_HOSTED_AUTH_LAYER' }
    $v = "$raw".Trim().ToLowerInvariant()
    if ($v) {
        switch -Regex ($v) {
            '^(easyauth|easy-auth|edge)$'              { return 'easyauth' }
            '^(signed-token|signedtoken|token|strict)$' { return 'signed-token' }
            '^(signin-front|sign-in-front|signinfront)$' { return 'signin-front' }
            default                                    { return 'none' }
        }
    }
    if ("$(& $get 'CONTAINER_APP_NAME')".Trim() -or "$(& $get 'WEBSITE_SITE_NAME')".Trim()) { return 'easyauth' }
    return 'none'
}

function Get-PimHostedDefaultIssuers {
    # PURE: the Entra issuers a token for THIS tenant carries (v2 + v1). Used to pin layer 2
    # when PIM_HOSTED_AUTH_ISSUERS is unset. 🔴 Without a pin, "signature verified" proves
    # only that SOME Entra tenant signed the token -- the signing keys are shared across
    # tenants, so a token minted in an attacker's own tenant verifies too.
    [CmdletBinding()] param([string]$TenantId = '')
    $t = "$TenantId".Trim()
    if (-not $t -or $t -eq 'common' -or $t -eq 'organizations') { return @() }
    return @("https://login.microsoftonline.com/$t/v2.0", "https://sts.windows.net/$t/")
}

function Test-PimHostedSignedTokenRequired {
    # Is LAYER 2 (signed-token verification) required? Opt-in, because it needs the auth
    # edge to store tokens. Explicit $Override wins (tests / callers). An auth layer of
    # 'signed-token' (PIM_HOSTED_AUTH_LAYER) requires it too.
    [CmdletBinding()]
    param([object]$Override = $null)
    if ($null -ne $Override) {
        if (Get-Command Test-PimExplicitFlagValue -ErrorAction SilentlyContinue) {
            $ov = Test-PimExplicitFlagValue -Value $Override
            if ($null -ne $ov) { return [bool]$ov }
        } elseif ($Override -is [bool]) { return [bool]$Override }
    }
    $v = "$env:PIM_HOSTED_REQUIRE_SIGNED_TOKEN".Trim().ToLowerInvariant()
    if ($v -in @('1', 'true', 'yes', 'y', 'on', 'enable', 'enabled')) { return $true }
    return ("$env:PIM_HOSTED_AUTH_LAYER".Trim() -and (Get-PimHostedAuthLayer) -eq 'signed-token')
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
        [datetime]$NowUtc = ([datetime]::UtcNow),
        # SEC-28: which auth layer is in front ('easyauth' | 'signed-token' | 'none'). The
        # decision stays PURE: the caller (Get-PimEasyAuthPrincipal) resolves the layer from
        # env/platform with Get-PimHostedAuthLayer and passes it. Empty = 'easyauth' (the
        # pre-SEC-28 contract); an unrecognised value is 'none'.
        [string]$AuthLayer = '',
        # front 1.4.0: refuse the ID token behind the front (the caller reads PIM_SIGNIN_FRONT_REQUIRE_ACCESS_TOKEN)
        [bool]$RequireFrontAccessToken = $false,
        # AUTH-MODERN-1 (strict layer): the raw Authorization header (a script's / MCP client's own access token, or nothing),
        # the sign-in's X-MS-TOKEN-AAD-ACCESS-TOKEN, this tenant (tid), the delegated scope, and whether the ID token may still
        # be used when no access token for this app is present (PIM_HOSTED_ID_TOKEN_FALLBACK, default on)
        [string]$Authorization = '',
        [string]$AccessToken = '',
        [string]$TenantId = '',
        [string[]]$AccessScopes = @('user_impersonation'),
        [bool]$AllowIdTokenFallback = $true
    )

    $layerIn = "$AuthLayer".Trim().ToLowerInvariant()
    if (-not $layerIn) { $layerIn = 'easyauth' }
    elseif ($layerIn -notin @('easyauth', 'signed-token', 'signin-front', 'none')) { $layerIn = Get-PimHostedAuthLayer -Value $layerIn }
    if ($layerIn -eq 'signin-front') {
        # CR7: the shared sign-in front. Identity from the VERIFIED forwarded ID token ONLY --
        # -PrincipalName / -PrincipalBlob are deliberately not consulted (the front strips them,
        # and nothing but the front can reach a loopback-bound Manager).
        return (Resolve-PimSigninFrontPrincipal -IdToken $SignedToken -Jwks $Jwks -ExpectedIssuers $ExpectedIssuers `
                    -ExpectedAudiences $ExpectedAudiences -NowUtc $NowUtc -RequireAccessToken $RequireFrontAccessToken)
    }
    if ($layerIn -eq 'none') {
        # 🔴 SEC-28: nothing in front strips client-supplied X-MS-* headers, so a "consistent"
        # header set is only the caller's own claim. Refuse -- never trust what anyone can write.
        return @{ trusted = $false; identity = ''; layer = 'no-auth-edge'
                  reason = 'no authentication edge is in front of this hosted Manager (auth layer = none), so identity headers are refused -- put Easy Auth in front, or a proxy that forwards a signed Entra ID token (PIM_HOSTED_AUTH_LAYER=signed-token)' }
    }
    $strict = ($layerIn -eq 'signed-token') -or (Test-PimHostedSignedTokenRequired -Override $RequireSignedToken)
    $noEdgeHeaders = (-not "$PrincipalName".Trim() -and -not "$PrincipalBlob".Trim())
    if ($layerIn -eq 'signed-token' -and $noEdgeHeaders) {
        # A signed-token proxy with no Easy Auth headers: identity from the VERIFIED token only,
        # and only with BOTH issuer and audience pinned -- otherwise any tenant's token verifies.
        $pinIss = @($ExpectedIssuers | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        $pinAud = @($ExpectedAudiences | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if ($pinIss.Count -eq 0 -or $pinAud.Count -eq 0) {
            return @{ trusted = $false; identity = ''; layer = 'signed-token'
                      reason = 'token-only sign-in needs BOTH the issuer (PIM_HOSTED_AUTH_ISSUERS or the tenant id) and the audience (PIM_HOSTED_EASYAUTH_AUD) pinned -- failing closed' }
        }
        $edge = @{ trusted = $true; identity = ''; oid = ''; reason = 'no edge headers (signed-token layer)' }
    } else {
        # LAYER 1 -- always when an edge is expected.
        $edge = Test-PimEdgeHeadersConsistent -PrincipalName $PrincipalName -PrincipalBlob $PrincipalBlob
    }
    if (-not $edge.trusted) {
        return @{ trusted = $false; identity = ''; layer = 'edge-consistency'; reason = $edge.reason }
    }
    if (-not $strict) {
        return @{ trusted = $true; identity = $edge.identity; oid = "$($edge.oid)"; layer = 'edge-consistency'; reason = $edge.reason }
    }

    # LAYER 2 -- AUTH-MODERN-1 (owner 2026-11-15; framework decision c5704c10): every token is validated by Microsoft's
    # library (Invoke-PimTokenValidation / Resolve-PimAccessTokenCaller: signature RS256, issuer, audience, lifetime), then
    # authorised here. The ACCESS token first -- a script's / MCP client's own 'Authorization: Bearer', else the sign-in's
    # X-MS-TOKEN-AAD-ACCESS-TOKEN (scp user_impersonation, tid = this tenant). The ID token ONLY as the FALLBACK for an
    # install whose sign-in does not request this app's API scope yet -- the result names the path (tokenPath).
    $tid = "$TenantId".Trim()
    $refuse = { param($why, $pth) return @{ trusted = $false; identity = ''; layer = 'signed-token'; tokenPath = "$pth"; reason = $why } }
    $path = ''; $tok = ''; $kind = ''; $who = ''; $oid = ''; $note = ''
    $ah = "$Authorization".Trim()
    if ($ah) {
        if ($ah -notmatch '^(?i)Bearer\s+(\S+)$') { return (& $refuse 'the Authorization header is not a Bearer access token (only an Entra access token is accepted there) -- refused' 'bearer') }
        $tok = $Matches[1]
        if ($null -eq (Get-PimJwtParts -Token $tok)) { return (& $refuse 'the Authorization bearer is not a signed Entra token (an API key or a page token is never accepted there) -- refused' 'bearer') }
        $v = Resolve-PimAccessTokenCaller -Token $tok -Jwks $Jwks -ExpectedIssuers $ExpectedIssuers -ExpectedAudiences $ExpectedAudiences -TenantId $tid -Scopes $AccessScopes
        if (-not $v.trusted) { return (& $refuse "bearer: $($v.reason)" 'bearer') }
        $path = 'bearer'; $kind = 'access'; $who = "$($v.identity)"; $oid = "$($v.oid)"
    } else {
        $at = "$AccessToken".Trim()
        if ($at) {
            $mine = @(Get-PimAccessTokenAudiences -Audiences $ExpectedAudiences)
            $ta = @(Get-PimJwtAudienceUnverified -Token $at)
            if ($mine.Count -and @($ta | Where-Object { $mine -contains $_ }).Count) {
                # an access token FOR THIS APP: it must validate (an expired one is refused; the page renews it)
                $v = Resolve-PimAccessTokenCaller -Token $at -Jwks $Jwks -ExpectedIssuers $ExpectedIssuers -ExpectedAudiences $ExpectedAudiences -TenantId $tid -Scopes $AccessScopes
                if (-not $v.trusted) { return (& $refuse "X-MS-TOKEN-AAD-ACCESS-TOKEN: $($v.reason)" 'access-token') }
                $path = 'access-token'; $kind = 'access'; $tok = $at; $who = "$($v.identity)"; $oid = "$($v.oid)"
            } else { $note = "the sign-in's access token is for another resource ($(if ($ta.Count) { $ta -join ',' } else { 'unreadable' })) -- the sign-in does not request this app's API scope yet" }
        } else { $note = 'no access token on the request -- the sign-in does not request this app''s API scope yet' }
    }
    if (-not $path) {
        if (-not $AllowIdTokenFallback) { return (& $refuse "$note; the ID-token fallback is off -- refused" 'none') }
        # ---- the ID-token FALLBACK, validated by the same library
        if (-not "$SignedToken".Trim()) {
            return @{ trusted = $false; identity = ''; layer = 'signed-token'; tokenPath = 'none'; reason = 'PIM_HOSTED_REQUIRE_SIGNED_TOKEN is on but no X-MS-TOKEN-AAD-ID-TOKEN was supplied (enable token store on the auth edge)' }
        }
        if ($null -eq (Get-PimJwtParts -Token $SignedToken)) { return (& $refuse 'X-MS-TOKEN-AAD-ID-TOKEN is not a well-formed JWT' 'id-token-fallback') }
        $v = Invoke-PimTokenValidation -Token $SignedToken -Jwks $Jwks -ExpectedIssuers $ExpectedIssuers -ExpectedAudiences $ExpectedAudiences
        if (-not $v.valid) { return (& $refuse ("token rejected: " + $v.reason) 'id-token-fallback') }
        $pl = $v.payload
        # SEC-89: an application's token is refused explicitly -- not only because it carries no username claim.
        $appOnly = Get-PimJwtAppOnlyReason -Payload $pl
        if ($appOnly) { return (& $refuse $appOnly 'id-token-fallback') }
        if ($tid -and "$($pl.tid)".Trim() -and "$($pl.tid)".Trim() -ine $tid) { return (& $refuse "the token's tid '$($pl.tid)' is not this tenant" 'id-token-fallback') }
        foreach ($p in @('preferred_username', 'upn', 'email', 'unique_name')) { $x = "$($pl.$p)".Trim(); if ($x) { $who = $x; break } }
        if (-not $who) { return (& $refuse 'verified token carries no username claim' 'id-token-fallback') }
        $oid = Get-PimJwtObjectId -Payload $pl
        $path = 'id-token-fallback'; $kind = 'id'; $tok = "$SignedToken".Trim()
    }
    # The edge headers must describe the SAME person as the validated token: the object id when both carry one, else the name.
    if ("$($edge.oid)" -and $oid) {
        if ("$($edge.oid)" -ne $oid) { return (& $refuse ("header object id ('$($edge.oid)') disagrees with the VERIFIED token object id ('$oid') -- rejected") $path) }
    } elseif ($edge.identity -and ("$($edge.identity)".ToLowerInvariant() -ne $who.ToLowerInvariant())) {
        return (& $refuse ("header identity ('$($edge.identity)') disagrees with the VERIFIED token identity ('$who') -- rejected") $path)
    }
    return @{ trusted = $true; identity = $who; oid = $oid; layer = 'signed-token'; tokenPath = $path; tokenKind = $kind; token = $tok
              reason = $(if ($path -eq 'id-token-fallback') { "signed ID token validated by Microsoft.IdentityModel -- FALLBACK: $note" } else { "access token validated by Microsoft.IdentityModel ($path)" }) }
}

# ---- CR7: the shared sign-in front (framework §12.11g) -------------------------

function Get-PimAuthorizationBearer {
    <#
      PURE. The JWT in an 'Authorization: Bearer <JWT>' header value, or '' for anything else. The shared sign-in
      front's contract (FRAMEWORK/signin-front/README.md "Upstream contract", 1.0.0): it removes every inbound
      Authorization and sets exactly ONE -- on browser routes the signed-in user's ID token.
    #>
    [CmdletBinding()] param([string]$Authorization = '')
    if ("$Authorization" -match '^\s*Bearer\s+(\S+)\s*$') { return $Matches[1] }
    return ''
}

function Test-PimManagerFrontBearerPath {
    <#
      PURE. Is this one of the paths the sign-in front treats as a BEARER path (its SIGNIN_BEARER_PATHS default
      /mcp,/.well-known -- segment-exact)? There the Authorization header is the caller's own access token (or none),
      not the front's ID token: /mcp verifies it itself (Resolve-PimMcpBearer) and /.well-known is public metadata.
    #>
    # PIM 93.4: /api/app is one too WHEN the setup added it to the front's list (Set-PimManagerApiAuth.ps1): there the
    # caller is an application with its own token, verified by the Manager itself (Invoke-PimManagerAppSignIn), never a page.
    [CmdletBinding()] param([string]$Path = '')
    $p = "$Path"
    return ($p -eq '/mcp' -or $p -like '/mcp/*' -or $p -eq '/.well-known' -or $p -like '/.well-known/*' -or $p -eq '/api/app' -or $p -like '/api/app/*')
}

function Test-PimManagerPageToken {
    <#
      PURE. The /api page token (one per Manager process, embedded in the page; the SEC-31 second factor next to the
      identity). AUTH-MODERN-1 (owner 2026-11-15): on EVERY layer the page token travels in X-PIM-Token and only that
      header counts -- 'Authorization' belongs to Entra access tokens alone, so a page token there is never accepted
      (-Authorization and -Front are kept for the callers' signature and are not consulted). Constant-time comparison.
    #>
    [CmdletBinding()]
    param([string]$Authorization = '', [string]$PageTokenHeader = '', [string]$ExpectedToken = '', [bool]$Front = $false)
    $a = "$PageTokenHeader"; $b = "$ExpectedToken"
    if (-not $b -or -not $a -or $a.Length -ne $b.Length) { return $false }
    $d = 0
    for ($i = 0; $i -lt $a.Length; $i++) { $d = $d -bor ([int][char]$a[$i] -bxor [int][char]$b[$i]) }
    return ($d -eq 0)
}

function Resolve-PimSigninFrontPrincipal {
    <#
      PURE given its inputs. CR7: who is calling, proven by the token the shared sign-in front forwarded -- since front
      1.4.0 an ACCESS token for this app's own API scope (-AccessScope, aud = the client id or api://<client id>, v1 or
      v2 issuer), before it the user's ID token (no scp; refused with -RequireAccessToken).
      Validated by Microsoft.IdentityModel (Invoke-PimTokenValidation), the same helper as every other token path.
      Fails CLOSED on: issuer or audience not pinned (any tenant's token would verify), no token, a malformed
      token, no key set, a bad signature, bad iss / aud / exp / nbf, an access token without -AccessScope in its scp,
      an ID token when -RequireAccessToken, an application's token (SEC-89: idtyp = app, or roles with no user --
      each its own reason), and a token that names no user.
      Returns @{ trusted; identity; layer = 'signin-front'; reason } -- the Resolve-PimHostedPrincipal shape.
    #>
    [CmdletBinding()]
    param(
        [string]$IdToken = '',
        [object]$Jwks = $null,
        [string[]]$ExpectedIssuers = @(),
        [string[]]$ExpectedAudiences = @(),
        [datetime]$NowUtc = ([datetime]::UtcNow),
        # front 1.4.0: the delegated scope an access token must carry (the app registration's own scope)
        [string]$AccessScope = 'user_impersonation',
        # once every front forwards the access token: refuse the ID token
        [bool]$RequireAccessToken = $false
    )
    $no = { param($why) return @{ trusted = $false; identity = ''; layer = 'signin-front'; reason = $why } }
    $iss = @($ExpectedIssuers | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $aud = @($ExpectedAudiences | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($iss.Count -eq 0 -or $aud.Count -eq 0) {
        return (& $no 'sign-in front: the issuer (this tenant) AND the audience (PIM_SIGNIN_FRONT_CLIENT_ID or PIM_HOSTED_EASYAUTH_AUD) must both be pinned -- failing closed')
    }
    $tok = "$IdToken".Trim()
    if (-not $tok) { return (& $no 'sign-in front: no forwarded token on this request (refused)') }
    if ($null -eq (Get-PimJwtParts -Token $tok)) { return (& $no 'sign-in front: the forwarded token is not a well-formed JWT') }
    if ($null -eq $Jwks) { return (& $no 'sign-in front: no JWKS available to verify the token (failing closed)') }
    # AUTH-MODERN-1: the token is validated by Microsoft.IdentityModel (signature RS256, issuer, audience = the client id or
    # api://<client id>, lifetime) -- then authorised here.
    $v = Invoke-PimTokenValidation -Token $tok -Jwks $Jwks -ExpectedIssuers $iss -ExpectedAudiences (Get-PimAccessTokenAudiences -Audiences $aud)
    if (-not $v.valid) { return (& $no ('sign-in front: token rejected: ' + $v.reason)) }
    $pl = $v.payload
    # SEC-89: a token without `scp` is NOT automatically an ID token -- an application's access token has none either.
    $appOnly = Get-PimJwtAppOnlyReason -Payload $pl
    if ($appOnly) { return (& $no ('sign-in front: ' + $appOnly)) }
    $scp = @("$($pl.scp)".Trim() -split '\s+' | Where-Object { $_ })
    $kind = 'ID token'
    if ($scp.Count) {
        # front 1.4.0 (framework 12.11g item 10): an ACCESS token for the app's OWN API, with the scope the front asks for
        $kind = 'access token'
        if ($scp -notcontains "$AccessScope".Trim()) {
            return (& $no ("sign-in front: the forwarded access token carries scope '$($scp -join ' ')', not '$AccessScope' -- refused"))
        }
    } else {
        if ($RequireAccessToken) { return (& $no 'sign-in front: an ID token was forwarded, but this Manager accepts only the access token (PIM_SIGNIN_FRONT_REQUIRE_ACCESS_TOKEN) -- refused') }
        # an ID token names the app as a bare client id, never as the api:// URI
        if (@(@($pl.aud) | Where-Object { "$_" -match '^api://' }).Count -and -not @(@($pl.aud) | Where-Object { $aud -contains "$_" }).Count) { return (& $no 'sign-in front: token claims rejected: an ID token for the api:// audience') }
    }
    $who = ''
    foreach ($c in @('preferred_username', 'upn', 'email', 'unique_name')) { $x = "$($pl.$c)".Trim(); if ($x) { $who = $x; break } }
    if (-not $who) { return (& $no 'sign-in front: the verified token carries no username claim') }
    return @{ trusted = $true; identity = $who; oid = (Get-PimJwtObjectId -Payload $pl); layer = 'signin-front'; reason = "sign-in front $kind validated by Microsoft.IdentityModel" }
}

function Get-PimHostedListenerPrefix {
    <#
      PURE. The HttpListener prefix for the HOSTED container branch of Open-PimManager.
        'signin-front' -> http://127.0.0.1:<port>/  (§12.11g item 2: PIM's server bound to 127.0.0.1 ONLY;
                          the sign-in front, in the same revision, is the only thing that can reach it)
        anything else  -> http://+:<port>/          (today's path, unchanged: Easy Auth sits in front)
    #>
    [CmdletBinding()] param([string]$AuthLayer = '', [int]$Port = 8080)
    if ("$AuthLayer".Trim().ToLowerInvariant() -eq 'signin-front') { return "http://127.0.0.1:$Port/" }
    return "http://+:$Port/"
}

# ---- startup posture ----------------------------------------------------------

function Test-PimHostedAuthPosture {
    # PURE: describe the authentication posture at boot so the operator is told, loudly,
    # exactly which layer is protecting the Manager. Returns
    # @{ hosted; strict; level; ok; message }.
    [CmdletBinding()]
    param(
        [bool]$Hosted = $false,
        [object]$RequireSignedToken = $null,
        # SEC-28: the layer in front, as Get-PimHostedAuthLayer resolved it (the Manager passes
        # it). '' = 'easyauth', the same default Resolve-PimHostedPrincipal applies.
        [string]$AuthLayer = ''
    )
    $strict = Test-PimHostedSignedTokenRequired -Override $RequireSignedToken
    if (-not $Hosted) {
        return @{ hosted = $false; strict = $false; level = 'local'; ok = $true
                  message = 'LOCAL mode: identity is the Windows user; the listener binds to loopback.' }
    }
    $layer = "$AuthLayer".Trim().ToLowerInvariant()
    if (-not $layer) { $layer = 'easyauth' }
    elseif ($layer -notin @('easyauth', 'signed-token', 'signin-front', 'none')) { $layer = Get-PimHostedAuthLayer -Value $layer }
    if ($layer -eq 'signin-front') {
        return @{ hosted = $true; strict = $true; level = 'signin-front'; ok = $true
                  message = @(
                      'HOSTED auth: SIGN-IN FRONT (CR7) -- listening on 127.0.0.1 only; identity = the signed ID token'
                      '  the front forwards as Authorization: Bearer, verified on every request (signature + issuer +'
                      '  audience + expiry). X-MS-* identity headers are never read. A request without the token is refused.'
                  ) -join [Environment]::NewLine }
    }
    if ($layer -eq 'none') {
        return @{ hosted = $true; strict = $false; level = 'no-auth-edge'; ok = $false
                  message = @(
                      'HOSTED auth: NO AUTHENTICATION EDGE -- EVERY REQUEST IS REFUSED (401).'
                      '  Nothing in front of this Manager strips client-supplied identity headers, so they'
                      '  cannot be trusted (SEC-28). Put Easy Auth in front (Container Apps / App Service),'
                      '  or a proxy that forwards a signed Entra ID token and set'
                      '  PIM_HOSTED_AUTH_LAYER=signed-token + PIM_HOSTED_EASYAUTH_AUD. The local break-glass'
                      '  console (Start-PimEmergency.ps1) still works on the host itself.'
                  ) -join [Environment]::NewLine }
    }
    if ($layer -eq 'signed-token') { $strict = $true }
    if ($strict) {
        return @{ hosted = $true; strict = $true; level = 'signed-token'; ok = $true
                  message = @(
                      'HOSTED auth: STRICT -- two layers: Microsoft''s built-in sign-in in front (layer 1), and the Manager validates the'
                      '  Entra token on every request with Microsoft.IdentityModel (layer 2: RS256 signature, this tenant, audience = this'
                      '  app, expiry) -- the ACCESS token (a script / MCP bearer, else the sign-in''s token; scope user_impersonation), the'
                      '  ID token only as the reported fallback while the sign-in does not request the API scope.'
                  ) -join [Environment]::NewLine }
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
