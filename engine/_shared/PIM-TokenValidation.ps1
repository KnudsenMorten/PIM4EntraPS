<#
  PIM Manager -- AUTH-MODERN-1: Entra token validation with MICROSOFT's library (framework decision c5704c10, owner
  2026-11-15 "ms standard authn, not our own code").

  ONE helper for every place PIM checks an Entra token itself: the Manager's web path (the sign-in's access token, a
  script's / MCP client's 'Authorization: Bearer', the ID token as the reported fallback), the opt-in sign-in front path,
  the application path (/api/app) and the engine's signed-request check. The signature, algorithm, issuer, audience and
  lifetime are checked by Microsoft.IdentityModel (JsonWebTokenHandler.ValidateTokenAsync); PIM adds only the
  AUTHORIZATION facts afterwards (tenant id, delegated scope, a person, the application allow-list, PIM roles).

  THE LIBRARY is vendored next to this file (engine/_shared/vendor/identitymodel): Microsoft.IdentityModel 8.23.0, the
  net10.0 builds of Abstractions, Logging, Tokens and JsonWebTokens, signed by Microsoft. It is a .NET ASSEMBLY, not a
  PowerShell module. Each file's SHA-256 is PINNED IN THIS FILE (not only in the manifest that sits next to the DLLs):
  before Add-Type -Path every file is hashed, and ANY missing file or mismatch leaves the token layer OFF -- every token
  check then refuses (fail closed) with one clear log line. The net10.0 build runs on PowerShell 7.6 / .NET 10 (the image);
  a Windows PowerShell 5.1 host cannot load it and therefore refuses every token check (fail closed) -- the hosted Manager
  and the engine never run there.
#>
Set-StrictMode -Off

function Get-PimIdentityModelPins {
    <# PURE. LITERAL (child-scope safe). The vendored assemblies in LOAD order, each with its pinned SHA-256. #>
    return [ordered]@{
        'Microsoft.IdentityModel.Abstractions.dll'  = '46f14d67dfc1894eb24d80282895526db25a854af227eee2fa06a0383fd09e4c'
        'Microsoft.IdentityModel.Logging.dll'       = '90b6fa70f28a3b7711fe95aa30a0c5551f1e6aa28565187aa7b3681194215c84'
        'Microsoft.IdentityModel.Tokens.dll'        = '84409b8c3a52313fe4f4f621fce39544f42074109e870ac2631e627c8b70210f'
        'Microsoft.IdentityModel.JsonWebTokens.dll' = 'b48515aeaa4a8fadc5fcacb45978c808a4d5bbffaf74f8894cc57c0769a9fb9e'
    }
}

function Get-PimIdentityModelVersion { '8.23.0' }

function Get-PimIdentityModelDefaultDir {
    # engine/_shared/vendor/identitymodel (Join-Path twice: a backslash is not a separator on Linux)
    return (Join-Path (Join-Path $PSScriptRoot 'vendor') 'identitymodel')
}

function Get-PimFileSha256 {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($Path)))).Replace('-', '').ToLowerInvariant()) } finally { $sha.Dispose() }
}

function Test-PimIdentityModelFiles {
    <#
      Every pinned file present in -Dir with ITS pinned SHA-256? @{ ok; reason; files = @(@{ name; sha256; ok }) }. Never throws.
    #>
    param([string]$Dir = '')
    if (-not "$Dir".Trim()) { $Dir = Get-PimIdentityModelDefaultDir }
    $pins = Get-PimIdentityModelPins
    $files = New-Object System.Collections.Generic.List[object]
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($n in $pins.Keys) {
        $p = [IO.Path]::Combine($Dir, $n)
        if (-not [IO.File]::Exists($p)) { $bad.Add("$n missing"); $files.Add(@{ name = $n; sha256 = ''; ok = $false }); continue }
        $h = ''; try { $h = Get-PimFileSha256 -Path $p } catch { $h = '' }
        $ok = ($h -eq $pins[$n])
        if (-not $ok) { $bad.Add("$n SHA-256 $h is not the pinned $($pins[$n])") }
        $files.Add(@{ name = $n; sha256 = $h; ok = $ok })
    }
    return @{ ok = ($bad.Count -eq 0); reason = $(if ($bad.Count) { $bad -join '; ' } else { "Microsoft.IdentityModel $(Get-PimIdentityModelVersion): every file matches its pinned SHA-256" }); files = @($files.ToArray()) }
}

function Initialize-PimIdentityModel {
    <#
      Loads the vendored Microsoft.IdentityModel ONCE per process -- only after every file matched its pinned SHA-256. The
      state is $global:PIM_IdentityModelState @{ ok; reason; dir }. A mismatch / missing file / load failure = ok $false and
      ONE red log line; every token check then refuses (fail closed). -Force re-checks (tests).
    #>
    param([string]$Dir = '', [switch]$Force)
    $st = $global:PIM_IdentityModelState
    if (-not $Force -and $st -is [hashtable] -and $st.ContainsKey('ok')) { return $st }
    if (-not "$Dir".Trim()) { $Dir = Get-PimIdentityModelDefaultDir }
    $chk = Test-PimIdentityModelFiles -Dir $Dir
    if (-not $chk.ok) {
        $global:PIM_IdentityModelState = @{ ok = $false; dir = $Dir; reason = "the token library is NOT loaded -- $($chk.reason). Every token check is refused (fail closed)." }
        Write-Host ("  [auth] {0}" -f $global:PIM_IdentityModelState.reason) -ForegroundColor Red
        return $global:PIM_IdentityModelState
    }
    try {
        $pins = Get-PimIdentityModelPins
        foreach ($n in $pins.Keys) {
            $an = [IO.Path]::GetFileNameWithoutExtension($n)
            $already = @([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq $an }) | Select-Object -First 1
            if ($already) {
                # loaded before (this process): it must be a file with the pinned hash, wherever it came from
                $loc = "$($already.Location)"
                if (-not $loc -or -not [IO.File]::Exists($loc) -or (Get-PimFileSha256 -Path $loc) -ne $pins[$n]) { throw "$an is already loaded from '$loc', which is not the pinned file" }
                continue
            }
            Add-Type -Path ([IO.Path]::Combine($Dir, $n)) -ErrorAction Stop
        }
        [void][Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler]
        $global:PIM_IdentityModelState = @{ ok = $true; dir = $Dir; reason = "Microsoft.IdentityModel $(Get-PimIdentityModelVersion) loaded (every file matched its pinned SHA-256)" }
    } catch {
        $global:PIM_IdentityModelState = @{ ok = $false; dir = $Dir; reason = "the token library could not be loaded: $($_.Exception.Message). Every token check is refused (fail closed)." }
        Write-Host ("  [auth] {0}" -f $global:PIM_IdentityModelState.reason) -ForegroundColor Red
    }
    return $global:PIM_IdentityModelState
}

function ConvertTo-PimSigningKeys {
    <#
      The tenant key set (the JWKS PIM already fetches and caches: @{ keys = @(@{ kid; kty; n; e; ... }) }) as the library's
      signing keys (JsonWebKey). Cached per key-set content. RSA keys only.
    #>
    param([AllowNull()][object]$Jwks)
    $list = New-Object 'System.Collections.Generic.List[Microsoft.IdentityModel.Tokens.SecurityKey]'
    if ($null -eq $Jwks) { return ,$list }
    $keys = @(); if ($Jwks -is [System.Collections.IDictionary]) { $keys = @($Jwks['keys']) } elseif ($Jwks.keys) { $keys = @($Jwks.keys) }
    $json = ($keys | Where-Object { $_ } | ConvertTo-Json -Depth 6 -Compress)
    $c = $global:PIM_SigningKeyCache
    if ($c -is [hashtable] -and "$($c.json)" -eq "$json" -and $c.keys) { return ,$c.keys }
    foreach ($k in @($keys)) {
        if ($null -eq $k) { continue }
        $kty = "$(if ($k -is [System.Collections.IDictionary]) { $k['kty'] } else { $k.kty })".Trim().ToUpperInvariant()
        if ($kty -and $kty -ne 'RSA') { continue }
        try { $list.Add([Microsoft.IdentityModel.Tokens.JsonWebKey]::new(($k | ConvertTo-Json -Depth 6 -Compress))) } catch { }
    }
    $global:PIM_SigningKeyCache = @{ json = $json; keys = $list }
    return ,$list
}

function ConvertFrom-PimLibraryClaims {
    # The validated token's claims (IDictionary<string, object>) as a plain object: arrays -> string[], others as they are.
    param([AllowNull()][object]$Claims)
    $o = [ordered]@{}
    if ($null -eq $Claims) { return [pscustomobject]$o }
    foreach ($k in @($Claims.Keys)) {
        $v = $Claims[$k]
        if ($null -ne $v -and $v -isnot [string] -and $v -is [System.Collections.IEnumerable]) { $o["$k"] = @(@($v) | ForEach-Object { "$_" }) }
        else { $o["$k"] = $v }
    }
    return [pscustomobject]$o
}

function Invoke-PimTokenValidation {
    <#
      THE helper. Microsoft.IdentityModel JsonWebTokenHandler.ValidateTokenAsync with:
        ValidIssuers = -ExpectedIssuers (this tenant v1 + v2), ValidAudiences = -ExpectedAudiences (id, api://id),
        IssuerSigningKeys = the tenant JWKS, ValidAlgorithms = RS256, RequireSignedTokens, RequireExpirationTime,
        ValidateLifetime (exp / nbf), ClockSkew 5 minutes (-ClockSkewSeconds: a caller with a tighter contract, e.g. the
        request portal's API: 120 s).
      -NoLifetime: the engine's signed-request check (it judges the token at its CAPTURE time, iat <= captured <= exp, itself).
      The lifetime is always judged at the REAL clock by Microsoft's code (no caller-supplied time).
      Pins missing (issuer or audience) / no key set / the library not loaded = refused (fail closed).
      @{ valid; reason; payload (the validated claims); kid }.
    #>
    param([string]$Token = '', [AllowNull()][object]$Jwks = $null, [string[]]$ExpectedIssuers = @(), [string[]]$ExpectedAudiences = @(),
          [switch]$NoLifetime, [int]$ClockSkewSeconds = 300)
    $no = { param($why) return @{ valid = $false; reason = $why; payload = $null; kid = '' } }
    $st = Initialize-PimIdentityModel
    if (-not $st.ok) { return (& $no "$($st.reason)") }
    $t = "$Token".Trim()
    if (-not $t) { return (& $no 'no token') }
    $iss = @($ExpectedIssuers | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $aud = @($ExpectedAudiences | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($iss.Count -eq 0 -or $aud.Count -eq 0) { return (& $no 'the issuer (this tenant) and the audience (this app) must both be pinned -- failing closed') }
    if ($ClockSkewSeconds -lt 0 -or $ClockSkewSeconds -gt 300) { return (& $no 'the clock skew must be 0-300 seconds -- failing closed') }
    if ($null -eq $Jwks) { return (& $no 'the tenant signing keys are not available (failing closed)') }
    try {
        $keys = ConvertTo-PimSigningKeys -Jwks $Jwks
        if ($keys.Count -eq 0) { return (& $no 'the tenant key set holds no RSA key (failing closed)') }
        $p = New-Object Microsoft.IdentityModel.Tokens.TokenValidationParameters
        $p.IssuerSigningKeys = $keys
        $p.ValidAlgorithms = [string[]]@('RS256')
        $p.RequireSignedTokens = $true
        $p.ValidateIssuerSigningKey = $true
        # the token's kid must name a key of the set (Entra always sends one): never "try every key"
        $p.TryAllIssuerSigningKeys = $false
        $p.ClockSkew = [TimeSpan]::FromSeconds($ClockSkewSeconds)
        $p.ValidIssuers = [string[]]$iss; $p.ValidateIssuer = $true
        $p.ValidAudiences = [string[]]$aud; $p.ValidateAudience = $true
        $p.RequireExpirationTime = $true
        $p.ValidateLifetime = (-not $NoLifetime)
        $h = New-Object Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler
        $r = $h.ValidateTokenAsync($t, $p).GetAwaiter().GetResult()
        if (-not $r.IsValid) {
            $m = if ($r.Exception) { "$($r.Exception.GetType().Name): $($r.Exception.Message)" } else { 'not valid' }
            return (& $no ("token rejected by Microsoft.IdentityModel -- " + $m))
        }
        $kid = ''; try { $kid = "$($r.SecurityToken.Kid)" } catch { }
        return @{ valid = $true; reason = 'token validated by Microsoft.IdentityModel (signature RS256, issuer, audience, lifetime)'; payload = (ConvertFrom-PimLibraryClaims -Claims $r.Claims); kid = $kid }
    } catch {
        return (& $no ("token check errored (refused): " + $_.Exception.Message))
    }
}

function Test-PimIdentityModelSelfCheck {
    <#
      WEB-AUTH-SELF-CHECK-1 (framework, binding): run at the Manager's START (before the HTTP listener opens) and in the engine's
      job entry (before it verifies signed requests), with no person. Checks the pinned hashes and loads Microsoft.IdentityModel
      (Initialize-PimIdentityModel), then sends three made-up tokens through the SAME function a request takes
      (Resolve-PimAccessTokenCaller -> Invoke-PimTokenValidation), with a throwaway RSA key and a made-up tenant / app that match
      nothing real (never the live config):
        1. signed with the throwaway key (given as the JWKS) -> must be ACCEPTED (the whole path works end to end)
        2. signed with ANOTHER key                           -> must be REFUSED by Microsoft's library
        3. alg none                                          -> must be REFUSED
      @{ ok; passed (0-3); line } -- line = the one log line ("[auth] token library self-check OK (Microsoft.IdentityModel
      8.23.0, 3/3)" or "... FAILED ..."). Not ok = the caller exits non-zero (fail closed: an unhealthy revision / a failed job).
      -Dir: the library folder (tests). Never throws.
    #>
    param([string]$Dir = '')
    $ver = Get-PimIdentityModelVersion
    $fail = { param([int]$n, [string]$why) @{ ok = $false; passed = $n; line = "[auth] token library self-check FAILED (Microsoft.IdentityModel $ver, $n/3): $why -- refusing to start (fail closed)" } }
    $st = if ("$Dir".Trim()) { Initialize-PimIdentityModel -Dir $Dir -Force } else { Initialize-PimIdentityModel }
    if (-not $st.ok) { return (& $fail 0 "$($st.reason)") }
    if (-not (Get-Command Resolve-PimAccessTokenCaller -ErrorAction SilentlyContinue)) { return (& $fail 0 'the request validation path (PIM-HostedAuth.ps1) is not loaded') }
    $b64u = { param([byte[]]$b) [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $good = $null; $other = $null
    try {
        $good = [System.Security.Cryptography.RSA]::Create(2048); $other = [System.Security.Cryptography.RSA]::Create(2048)
        $tid = [guid]::NewGuid().ToString(); $app = [guid]::NewGuid().ToString()
        $rp = $good.ExportParameters($false)
        $jwks = @{ keys = @(@{ kid = 'pim-selfcheck'; kty = 'RSA'; use = 'sig'; n = (& $b64u $rp.Modulus); e = (& $b64u $rp.Exponent) }) }
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $body = & $b64u ([Text.Encoding]::UTF8.GetBytes(([ordered]@{ iss = "https://login.microsoftonline.com/$tid/v2.0"; tid = $tid; aud = $app; scp = 'user_impersonation'
                    oid = [guid]::NewGuid().ToString(); preferred_username = 'selfcheck@example.invalid'; iat = $now - 60; nbf = $now - 60; exp = $now + 600 } | ConvertTo-Json -Compress)))
        $make = { param($key, [string]$alg)
            $h = & $b64u ([Text.Encoding]::UTF8.GetBytes((@{ alg = $alg; typ = 'JWT'; kid = 'pim-selfcheck' } | ConvertTo-Json -Compress)))
            if (-not $key) { return "$h.$body.AA" }   # alg none with a junk signature segment: it must reach the library and be refused there
            "$h.$body." + (& $b64u ($key.SignData([Text.Encoding]::ASCII.GetBytes("$h.$body"), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1))) }
        $iss = @("https://login.microsoftonline.com/$tid/v2.0", "https://sts.windows.net/$tid/")
        $chk = { param($t) Resolve-PimAccessTokenCaller -Token $t -Jwks $jwks -ExpectedIssuers $iss -ExpectedAudiences @($app) -TenantId $tid -Scopes @('user_impersonation') }
        $r1 = & $chk (& $make $good 'RS256')
        if (-not $r1.trusted) { return (& $fail 0 "the accepted case was refused: $($r1.reason)") }
        $r2 = & $chk (& $make $other 'RS256')
        if ($r2.trusted -or "$($r2.reason)" -notmatch 'Microsoft\.IdentityModel') { return (& $fail 1 "the other-key case was not refused by Microsoft's library: $($r2.reason)") }
        $r3 = & $chk (& $make $null 'none')
        if ($r3.trusted) { return (& $fail 2 'the alg none case was accepted') }
        return @{ ok = $true; passed = 3; line = "[auth] token library self-check OK (Microsoft.IdentityModel $ver, 3/3)" }
    } catch {
        return (& $fail 0 ("the self-check errored: " + $_.Exception.Message))
    } finally {
        if ($good) { try { $good.Dispose() } catch { } }; if ($other) { try { $other.Dispose() } catch { } }
    }
}