#Requires -Version 5.1
<#
.SYNOPSIS
    PRO-PACKAGE-FROM-INVARDIA (2026-11-03; framework INSTALL-1 "github should be for community only" / "pro installs from
    invardia"; Invardia DESIGN ch 8 "BINDING SPEC - Pro installs download the Pro package from Invardia"): the Pro copy of
    Start-PimManagerInstall.ps1 takes the PIM Manager package from Invardia, never from GitHub.

.DESCRIPTION
    Loaded by Start-PimManagerInstall.ps1 (inlined into both published copies by Build-PimSupportScripts; only the Pro copy --
    $script:PimInstallChannel = 'pro' -- calls it, the Community copy keeps its GitHub path exactly as it was).

      1. SIGN-IN   the person's own browser sign-in (auth code + PKCE on the localhost loopback, the Azure CLI first-party
                   public client id over REST -- the same client PIM-Rest uses, so no module, no az, never device code), for
                   the TARGET tenant only, audience https://management.azure.com. The token's tid must be -TenantId.
      2. ASK       GET https://invardia.com/api/install/pim-manager/package?ring=<0-3>&tenantId=<guid>
                   Authorization: Bearer <that ARM token>. Invardia checks issuer, tid == tenantId, expiry, and audits it.
      3. VERIFY    the answer is the SAME signed manifest the ring serves the updater: RS256 over manifestB64 by a key in the
                   EMBEDDED trusted list (InvardiaUpdate.verify.ps1 -- Invardia's GET /api/updates/keys, embedded; a key
                   fetched at run time is never trusted), product pim-manager, kind code, THIS ring, a version, SHA-256, size.
      4. DOWNLOAD  the short-lived link into a NEW folder in the temp folder; the zip's size + SHA-256 must be the signed ones,
                   or the folder is removed and nothing runs.
    NO GitHub fallback: any failure is ONE calm line ("Invardia could not be reached" / "Invardia refused ...") and a non-zero
    exit. Nothing here writes outside the new temp folder; no token is printed, logged or written.

    !!! THE ANSWER'S SHAPE IS NOT FINAL. Invardia sends the exact fields and status codes when the route is live; until then
    ConvertFrom-PimInstallProPackageAnswer (below) reads the updater's manifest shape. It is the ONE place to change.
#>

. (Join-Path $PSScriptRoot '../../engine/_shared/InvardiaUpdate.verify.ps1')
. (Join-Path $PSScriptRoot '_PimLoopbackAnswer.ps1')

$script:PimInstallProBaseUrl = 'https://invardia.com'
$script:PimInstallProProduct = 'pim-manager'
$script:PimInstallArmAudience = 'https://management.azure.com'
# the Microsoft Azure CLI first-party public client APP ID, used over REST (not the az program) -- pre-authorised for ARM in
# every tenant; the same id PIM-Rest's browser sign-in uses (Get-PimInteractiveClientId)
$script:PimInstallSignInClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
$script:PimInstallGuidRx = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

function Get-PimInstallProPackageUrl {
    <# PURE. The package route for -Ring and -TenantId (lower-cased). #>
    param([string]$BaseUrl = '', [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring, [Parameter(Mandatory)][string]$TenantId)
    $base = if ("$BaseUrl".Trim()) { "$BaseUrl".Trim().TrimEnd('/') } else { $script:PimInstallProBaseUrl }
    return ("{0}/api/install/{1}/package?ring={2}&tenantId={3}" -f $base, $script:PimInstallProProduct, $Ring, "$TenantId".Trim().ToLowerInvariant())
}

function ConvertFrom-PimInstallProPackageAnswer {
    <#
      THE ONE PLACE THAT KNOWS THE SHAPE OF INVARDIA'S ANSWER (PRO-PACKAGE-FROM-INVARDIA). FINAL shape from Invardia
      2026-11-03 (apps/front/src/installpackage.ts), tests/Test-PimGuidedInstall.ps1 PP* pin it:
        200  FLAT { product; version; sequence; ring; manifest; manifestB64; signature; keyId; downloadUrl; sha256; size } --
             the signature is over manifestB64's bytes with keyId's key (/api/updates/keys); the archive is then checked
             against the SIGNED manifest's sha256 + size (never the unsigned top-level copies). 'package' nesting still read.
        401 notSignedIn | 403 wrongTenant (the token's tid != tenantId) | 404 noEnvironment / nothingReleased / notFound |
        422 invalid | 503 notConfigured -- each { error; message }: the message is shown, the launcher exits 3.
      PURE. Returns @{ ok; response (the object Test-InvardiaManifest reads); refused (Invardia said no) ; reason (one calm
      sentence, never a token) }.
    #>
    param([int]$Status, [AllowNull()][object]$Body, [string]$ErrorText = '', [int]$Ring = 3)
    $g = { param($o, $n) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { return $o[$n] }; $pp = $o.PSObject.Properties[$n]; if ($pp) { $pp.Value } }
    # Invardia's refusal is { error; message }: its plain message first, then the code (older answers: 'reason')
    $why = "$(& $g $Body 'message')".Trim(); if (-not $why) { $why = "$(& $g $Body 'reason')".Trim() }; if (-not $why) { $why = "$(& $g $Body 'error')".Trim() }
    if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' }
    $whyTxt = if ($why) { " ($why)" } else { '' }
    switch ($Status) {
        200 {
            $o = $Body
            if (-not "$(& $g $o 'manifestB64')".Trim() -and $null -ne (& $g $o 'package')) { $o = & $g $o 'package' }
            if (-not "$(& $g $o 'manifestB64')".Trim()) { return @{ ok = $false; refused = $false; response = $null; reason = 'Invardia answered, but without a signed package manifest' } }
            return @{ ok = $true; refused = $false; response = [pscustomobject]@{ manifestB64 = "$(& $g $o 'manifestB64')"; signature = "$(& $g $o 'signature')"; keyId = "$(& $g $o 'keyId')"; downloadUrl = "$(& $g $o 'downloadUrl')" }; reason = '' }
        }
        204 { return @{ ok = $false; refused = $true; response = $null; reason = "Invardia has no PIM Manager release for ring $Ring yet" } }
        401 { return @{ ok = $false; refused = $true; response = $null; reason = "Invardia refused the sign-in$whyTxt -- sign in with an administrator account of the tenant you install into" } }
        403 { return @{ ok = $false; refused = $true; response = $null; reason = "Invardia refused the download for this tenant$whyTxt -- sign in with an account of the tenant you install into (-TenantId)" } }
        404 { return @{ ok = $false; refused = $true; response = $null; reason = "Invardia has no PIM Manager package for this tenant and ring $Ring$whyTxt" } }
        422 { return @{ ok = $false; refused = $true; response = $null; reason = "Invardia could not use the request$whyTxt" } }
        503 { return @{ ok = $false; refused = $false; response = $null; reason = "Invardia's install service is not ready$whyTxt -- run the command again later" } }
        429 { return @{ ok = $false; refused = $true; response = $null; reason = 'Invardia asked to wait (rate limit) -- run the command again in a few minutes' } }
        0   { return @{ ok = $false; refused = $false; response = $null; reason = "Invardia could not be reached$(if ("$ErrorText".Trim()) { " ($("$ErrorText".Trim()))" })" } }
        default { return @{ ok = $false; refused = ($Status -ge 400 -and $Status -lt 500); response = $null; reason = "Invardia answered HTTP $Status$whyTxt" } }
    }
}

function Invoke-PimInstallProHttp {
    <# The real seam: one GET with the bearer token, 60 s, @{ status; body; error }. A non-2xx is a status, never a throw;
       the error text never carries the token. #>
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Token)
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.ServicePointManager]::SecurityProtocol } catch { }
    try {
        $r = Invoke-WebRequest -Uri $Url -Method GET -Headers @{ Authorization = "Bearer $Token"; Accept = 'application/json'; 'User-Agent' = 'PIM-Manager-Installer' } -TimeoutSec 60 -UseBasicParsing -ErrorAction Stop
        $b = $null; if ("$($r.Content)".Trim()) { try { $b = "$($r.Content)" | ConvertFrom-Json } catch { $b = $null } }
        return @{ status = [int]$r.StatusCode; body = $b; error = '' }
    } catch {
        $code = 0; try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { $code = 0 }
        $b = $null; try { $t = "$($_.ErrorDetails.Message)".Trim(); if ($t.StartsWith('{')) { $b = $t | ConvertFrom-Json } } catch { $b = $null }
        $e = ((("$($_.Exception.Message)") -split "`n")[0]); if ($e.Contains($Token)) { $e = 'the request failed' }
        return @{ status = $code; body = $b; error = $e }
    }
}

function Get-PimInstallJwtClaims {
    # PURE. The payload claims of a JWT (claims read only, to ASSERT the tenant before it is used; the resource validates the token), or $null.
    param([string]$Token)
    try { $p = "$Token".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }; return ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json) } catch { return $null }
}

function Get-PimInstallSignInToken {
    <#
      The person's browser sign-in for the TARGET tenant: auth code + PKCE on the localhost loopback (IPv4 and, where the
      machine has it, IPv6 on the same port), the Azure CLI public client id over REST, -Audience (default ARM). An InPrivate
      Edge window when Edge is there (a saved profile account never signs in silently), else the default browser; the
      address is printed too. Never device code. Returns @{ token; expiresOn (epoch seconds) } in memory only; throws on a
      failed or timed-out sign-in, or a token for another tenant.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [string]$Audience = $script:PimInstallArmAudience)
    $tenant = "$TenantId".Trim().ToLowerInvariant()
    $rnd = New-Object byte[] 32; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rnd)
    $b64u = { param([byte[]]$B) [Convert]::ToBase64String($B).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $verifier = & $b64u $rnd
    $sha = [System.Security.Cryptography.SHA256]::Create(); try { $challenge = & $b64u ($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier))) } finally { $sha.Dispose() }
    $state = [guid]::NewGuid().ToString('N')
    $v4 = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $v4.Start()
    $listeners = @($v4)
    $port = ([System.Net.IPEndPoint]$v4.LocalEndpoint).Port
    if ([System.Net.Sockets.Socket]::OSSupportsIPv6) { try { $v6 = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::IPv6Loopback, $port); $v6.Start(); $listeners += $v6 } catch { } }
    $redirect = "http://localhost:$port/"
    $scope = "$("$Audience".TrimEnd('/'))/.default offline_access openid profile"
    $authUrl = "https://login.microsoftonline.com/$tenant/oauth2/v2.0/authorize?client_id=$($script:PimInstallSignInClientId)&response_type=code&response_mode=query" +
               "&redirect_uri=$([uri]::EscapeDataString($redirect))&scope=$([uri]::EscapeDataString($scope))&state=$state" +
               "&code_challenge=$challenge&code_challenge_method=S256&prompt=select_account"
    Write-Host "Sign in in the browser as an administrator of tenant $tenant (PIM Manager Pro is downloaded from Invardia for that tenant)." -ForegroundColor Yellow
    Write-Host "  If the browser opens in the wrong profile or account, open this address in the right one: $authUrl" -ForegroundColor DarkGray
    $query = $null
    try {
        $edge = @((Join-Path "${env:ProgramFiles(x86)}" 'Microsoft\Edge\Application\msedge.exe'), (Join-Path "$env:ProgramFiles" 'Microsoft\Edge\Application\msedge.exe')) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
        if ("$env:PIM_SIGNIN_BROWSER".Trim() -ieq 'none') { }
        elseif ($edge) { Start-Process -FilePath $edge -ArgumentList @('--inprivate', '--new-window', $authUrl) -WhatIf:$false }
        else { try { Start-Process $authUrl -WhatIf:$false } catch { } }   # no browser here (Cloud Shell): the printed address
        $query = Wait-PimLoopbackAnswer -Listeners $listeners -Seconds 300 -TimeoutMessage 'the sign-in did not come back within 5 minutes'
    } finally { foreach ($l in $listeners) { try { $l.Stop() } catch { } } }
    $kv = @{}
    foreach ($pair in ("$query" -split '&')) { $k, $v = $pair -split '=', 2; $kv[$k] = if ($null -ne $v) { [uri]::UnescapeDataString(($v -replace '\+', ' ')) } else { '' } }
    if ($kv['error']) { throw "the sign-in failed: $($kv['error'])" }
    if ($kv['state'] -ne $state -or -not $kv['code']) { throw 'the sign-in answer was not this sign-in''s' }
    $r = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 -Body @{
        client_id = $script:PimInstallSignInClientId; grant_type = 'authorization_code'; code = $kv['code']; redirect_uri = $redirect; code_verifier = $verifier; scope = $scope }
    $tok = "$($r.access_token)"
    $c = Get-PimInstallJwtClaims -Token $tok
    if (-not $c -or "$($c.tid)".Trim().ToLowerInvariant() -ne $tenant) { throw "you signed in to another tenant than $tenant -- sign in with an administrator account of $tenant" }
    $exp = [long]0; if (-not [long]::TryParse("$($c.exp)", [ref]$exp)) { $exp = [DateTimeOffset]::UtcNow.AddSeconds([int]$r.expires_in).ToUnixTimeSeconds() }
    return @{ token = $tok; expiresOn = $exp }
}

function Get-PimInstallProPackage {
    <#
      The Pro copy's whole download, every outside call a seam:
        -GetToken { param($TenantId) } -> @{ token; expiresOn } (or a token string)   default: Get-PimInstallSignInToken
        -Http     { param($Url, $Token) } -> @{ status; body; error }                 default: Invoke-PimInstallProHttp
        -Download { param($Url, $OutFile) }                                         the launcher's own download
      Returns @{ ok; reason; dir; zip; version; sha256; size; token; expiresOn }. ok=$false -> reason is ONE calm sentence
      (never a token, never a link); the new folder is removed. Nothing is ever asked of GitHub.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$TenantId, [ValidateRange(0, 3)][int]$Ring = 3, [string]$Version = '',
          [scriptblock]$GetToken, [scriptblock]$Http, [Parameter(Mandatory)][scriptblock]$Download,
          [object[]]$TrustedKeys = $script:InvardiaUpdateTrustedKeys, [string]$BaseUrl = '', [string]$TempRoot = ([IO.Path]::GetTempPath()))
    $res = @{ ok = $false; reason = ''; dir = ''; zip = ''; version = ''; sha256 = ''; size = 0; token = ''; expiresOn = 0 }
    $tid = "$TenantId".Trim().ToLowerInvariant()
    if ($tid -notmatch $script:PimInstallGuidRx) { $res.reason = 'PIM Manager Pro is downloaded for a tenant: give -TenantId (the tenant id, a GUID)'; return $res }
    if (-not $GetToken) { $GetToken = { param($t) Get-PimInstallSignInToken -TenantId $t } }
    if (-not $Http) { $Http = { param($u, $k) Invoke-PimInstallProHttp -Url $u -Token $k } }
    # 1. sign-in
    $tk = $null
    try { $tk = & $GetToken $tid } catch { $res.reason = "the sign-in for the download did not complete ($((("$($_.Exception.Message)") -split "`n")[0]))"; return $res }
    $token = if ($tk -is [string]) { $tk } else { "$($tk.token)" }
    if (-not $token.Trim()) { $res.reason = 'the sign-in for the download did not complete (no token)'; return $res }
    $res.token = $token; $res.expiresOn = $(if ($tk -isnot [string]) { [long]"$($tk.expiresOn)" } else { 0 })
    # 2. ask Invardia
    $a = $null
    try { $a = & $Http (Get-PimInstallProPackageUrl -BaseUrl $BaseUrl -Ring $Ring -TenantId $tid) $token } catch { $a = @{ status = 0; body = $null; error = 'the request failed' } }
    $p = ConvertFrom-PimInstallProPackageAnswer -Status ([int]$a.status) -Body $a.body -ErrorText "$($a.error)" -Ring $Ring
    if (-not $p.ok) { $res.reason = $p.reason; return $res }
    # 3. verify the signed manifest exactly as the updater does (this ring, kind code)
    $v = Test-InvardiaManifest -Response $p.response -TrustedKeys $TrustedKeys -Kind 'code' -Product $script:PimInstallProProduct -Ring $Ring
    if (-not $v.ok) { $res.reason = "the package Invardia sent did not verify ($($v.reason)) -- refused"; return $res }
    if ($v.hold) { $res.reason = "the release Invardia holds for ring $Ring cannot be installed by this command ($($v.reason))"; return $res }
    if ("$Version".Trim() -and "$($v.version)" -ne "$Version".Trim().TrimStart('v')) { $res.reason = "ring $Ring holds PIM Manager $($v.version), not $Version"; return $res }
    # 4. download into a NEW folder; size + SHA-256 must be the signed ones
    $dir = Join-Path $TempRoot ("pim-manager-release-{0}-{1}" -f $v.version, [guid]::NewGuid().ToString('N').Substring(0, 6))
    [void][IO.Directory]::CreateDirectory($dir)
    $zip = Join-Path $dir 'release.zip'
    Write-Host "PIM Manager Pro $($v.version) (ring $Ring, signed by Invardia) -- downloading into $dir"
    try { & $Download "$($v.downloadUrl)" $zip } catch { Write-Verbose "download: $((("$($_.Exception.Message)") -split "`n")[0] -replace '\?\S+', '?***')" }
    $chk = if (Test-Path -LiteralPath $zip -PathType Leaf) { Test-InvardiaArchiveFile -Path $zip -ExpectedSha256 $v.sha256 -ExpectedSize $v.size } else { @{ ok = $false; reason = 'the download did not complete' } }
    if (-not $chk.ok) { try { [IO.Directory]::Delete($dir, $true) } catch { }; $res.reason = "$($chk.reason) -- nothing was installed, the folder is removed"; return $res }
    $res.ok = $true; $res.dir = $dir; $res.zip = $zip; $res.version = "$($v.version)"; $res.sha256 = $v.sha256; $res.size = $v.size
    return $res
}
