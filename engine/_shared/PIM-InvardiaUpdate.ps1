#Requires -Version 5.1
<#
.SYNOPSIS
  §95.4 -- the Pro UPDATE CLIENT: a Pro install takes its updates from Invardia's update platform, and claims the
  install key that authorises it. Contract: Invardia docs/design/PRO-UPDATE-PLATFORM.md §10-11 (FROZEN 2026-10-04).

.DESCRIPTION
  CLAIM  (job 'install-key', feature 'updates.invardia') when this install has no install key:
           POST <base>/api/install-keys/claim  { product; tenantId (the REAL one); licence (the file text) }
           -> 201 { key; environment; ... }   409 keyExists (somebody must reset it -- never retried by itself)
         The key is kept in pim.Settings 'InvardiaInstallKey' -- a setting no API or page returns. A key delivered as the
         Container Apps secret PIM_UPLINK_KEY (the guided install's bundle) wins and is never replaced.
  PULL   (the update job ca-pim-update, PIM_UPDATE_SOURCE=invardia):
           POST <base>/api/updates/pim-manager/manifest  { kind: 'code'; licence }   header X-Invardia-Install-Key
           -> 200 { manifestB64; signature; keyId; downloadUrl }  204 nothing released for this ring
  VERIFY before anything moves -- nothing Invardia sends is trusted until it verifies HERE:
           * RS256 (PKCS#1 v1.5, SHA-256) over the bytes behind manifestB64, by a key in the EMBEDDED trusted list
             (never a key fetched at run time: a key list served next to the manifest proves nothing);
           * product pim-manager, kind code, a release version, a 64-hex SHA-256;
           * sequence >= the last APPLIED one (an old, validly signed manifest is not replayed);
           * manualStep set -> HOLD (the text is shown, nothing applied); minFromVersion above the running version -> HOLD;
           * the archive's SHA-256 (and size) against the manifest before it is unpacked.
  BUILD  the zip (top folder pim-manager-src-<v>/, repo-root shaped inside) is re-packed as the tar.gz build context the
         registry build has always taken; from there the updater's own steps run unchanged (build, schema, roll, verify,
         rollback).

  🔒 The trusted key list is EMPTY until Invardia creates its update-signing key (CN=Invardia-Updates) and the public key
     is embedded here in a release. Until then every manifest is REFUSED with that reason -- fail closed.
  🔒 OFF by default twice over: the claim needs the feature 'updates.invardia'; the pull needs PIM_UPDATE_SOURCE=invardia
     on the update job (Deploy-PimUpdateJob -UpdateSource Invardia). Community installs keep their GitHub / pim-src source.
#>

$script:PimInvardiaProduct = 'pim-manager'
$script:PimInvardiaDefaultBase = 'https://invardia.com'
# The trusted update-signing public keys (RSA, JWK n/e base64url), Invardia's list at GET /api/updates/keys, EMBEDDED.
# Add a key here -- never remove the old one in the same release.
# CN=Invardia-Updates (RSA 4096, valid to 2036-10-04, cert SHA-1 DDFF1C84930C290ECF234FB4C3F3C1D5B3F532F2), delivered by
# the Invardia session 2026-10-04 and checked here against Invardia's committed public certificate (modulus identical).
# /api/updates/keys still answered { keys: [] } then (Invardia fix a775b0b, not yet deployed): compare once it lists it.
$script:PimInvardiaUpdateTrustedKeys = @(
    @{ keyId = 'https://kv-invardia-gml64wkoe7np.vault.azure.net/keys/invardia-updates'; e = 'AQAB'
       n = 'tLDrlMq1et3H3vIomcjokhFXfkkyaYVT2F-BByLGk8Pa7lrN7xd-53AbJ3keqv0ZZSQG_V0rKFxbt5b0m7YTNKbBUXvsgLLFQQbouDu-Am-8blzNBjIyDKoQKYKYaYfCbL3Tjdil7RD5pFNV6Qt3wW54jzhPEmyArr2xRjVUOg2WYQe9CpD_pd6-ww9dFlGQwtT_VJvLs0xcXsJkitfxe5tJ7PV8BUKoDpXJQNl6j2M6iqILxAujBxFB3_fGHEfooDJGWu1jkqp2mW2yXots_3ZtKUlnAmwANQNAsVWAxLq-8bLy6b3VTIvMMWw9JyZubBhU8OriW3OBKK6O2k5CV_-O5b0zf_TaQSr64Mq2VPtKkzY1weiFRlwDzEfq-aiLzr-HWx1tB43QEISNoBkrdhC-G9wjCQRgWSoINWbnL--2HOnwdivT9GRaJ38Mng9gqPdrPFfrv6t2ZIn6g5X9GOz_ua1Fi0WyfRJ1ICzzQgiivB0bBdlUtxfV89b0TXwIT9JynV7VYS9uv5H56IXpcuDaWzIueq6bVlWqk6p-cEMviDKMdaME3JW_Q-qNBCF1Q-cCAGl269KtFWQt2aLU2f50JkwW8h5slY1I05PXbJaX26n-Zu9pdrq-us3la8D1v_V9ehsR2s6Xj4cKZRZAURd5ut42R8h7EIe7K17KeZE' }
)

function ConvertFrom-PimInvardiaBase64Url {
    <# PURE. base64url (or plain base64) text -> bytes. #>
    param([AllowEmptyString()][string]$Text)
    $t = "$Text".Trim().Replace('-', '+').Replace('_', '/')
    switch ($t.Length % 4) { 2 { $t += '==' } 3 { $t += '=' } }
    return [Convert]::FromBase64String($t)
}

function Compare-PimReleaseVersion {
    <# PURE. -1 / 0 / 1 for two dotted numeric versions ('2.4.491'); a non-numeric part compares as 0. #>
    param([string]$A, [string]$B)
    $pa = @("$A".Trim() -split '\.'); $pb = @("$B".Trim() -split '\.')
    for ($i = 0; $i -lt [Math]::Max($pa.Count, $pb.Count); $i++) {
        $x = 0; $y = 0
        if ($i -lt $pa.Count) { [void][int]::TryParse($pa[$i], [ref]$x) }
        if ($i -lt $pb.Count) { [void][int]::TryParse($pb[$i], [ref]$y) }
        if ($x -lt $y) { return -1 }; if ($x -gt $y) { return 1 }
    }
    return 0
}

function Test-PimInvardiaManifestSignature {
    <#
      PURE (crypto only). RS256 over the bytes behind -ManifestB64, signature base64, by the key -KeyId of -TrustedKeys
      (@( @{ keyId; n; e } )). Returns @{ ok; reason }. PS 5.1-safe: RSAParameters + ImportParameters, no ImportFromPem.
    #>
    param([string]$ManifestB64, [string]$Signature, [string]$KeyId, [object[]]$TrustedKeys = $script:PimInvardiaUpdateTrustedKeys)
    $keys = @($TrustedKeys | Where-Object { $_ })
    if (-not $keys.Count) { return @{ ok = $false; reason = 'no trusted update-signing key is embedded in this version yet -- every manifest is refused until one is' } }
    $k = @($keys | Where-Object { "$($_.keyId)" -ceq "$KeyId" })[0]
    if (-not $k) { return @{ ok = $false; reason = "the manifest is signed by key '$KeyId', which this version does not trust" } }
    try {
        $data = [Convert]::FromBase64String("$ManifestB64".Trim())
        $sig = [Convert]::FromBase64String("$Signature".Trim())
        $p = New-Object System.Security.Cryptography.RSAParameters
        $p.Modulus = ConvertFrom-PimInvardiaBase64Url "$($k.n)"
        $p.Exponent = ConvertFrom-PimInvardiaBase64Url "$($k.e)"
        $rsa = [System.Security.Cryptography.RSA]::Create()
        try {
            $rsa.ImportParameters($p)
            $ok = $rsa.VerifyData($data, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        } finally { $rsa.Dispose() }
        if ($ok) { return @{ ok = $true; reason = '' } }
        return @{ ok = $false; reason = 'the manifest signature does not verify' }
    } catch { return @{ ok = $false; reason = "the manifest signature could not be checked: $($_.Exception.Message)" } }
}

function Test-PimInvardiaManifest {
    <#
      PURE (given the trusted keys). Everything about a 200 answer, before anything is downloaded. Returns
      @{ ok; hold; reason; version; sequence; sha256; size; downloadUrl; manifest }.
        ok=$false            refused (signature, shape, product, kind, replay) -- nothing moves
        ok=$true, hold=$true  verified, but the release asks for a manual step or a newer starting version -- nothing moves
    #>
    param([Parameter(Mandatory)][object]$Response, [object[]]$TrustedKeys = $script:PimInvardiaUpdateTrustedKeys,
          [string]$Kind = 'code', [int]$AppliedSequence = 0, [string]$RunningVersion = '', [string]$Product = $script:PimInvardiaProduct)
    $no = { param($why) @{ ok = $false; hold = $false; reason = $why; version = ''; sequence = 0; sha256 = ''; size = 0; downloadUrl = ''; manifest = $null } }
    $g = { param($o, $n) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { return $o[$n] }; $pp = $o.PSObject.Properties[$n]; if ($pp) { $pp.Value } }
    $b64 = "$(& $g $Response 'manifestB64')".Trim()
    if (-not $b64) { return (& $no 'the answer carries no manifest') }
    $sv = Test-PimInvardiaManifestSignature -ManifestB64 $b64 -Signature "$(& $g $Response 'signature')" -KeyId "$(& $g $Response 'keyId')" -TrustedKeys $TrustedKeys
    if (-not $sv.ok) { return (& $no $sv.reason) }
    # Only the SIGNED bytes are read; the answer's own 'manifest' object is ignored.
    $m = $null; try { $m = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)) | ConvertFrom-Json } catch { return (& $no 'the signed manifest is not JSON') }
    if ("$($m.product)" -cne $Product) { return (& $no "the manifest is for '$($m.product)', not $Product") }
    if ("$($m.kind)" -cne $Kind) { return (& $no "the manifest is kind '$($m.kind)', not $Kind") }
    $ver = "$($m.version)".Trim(); if ($ver -notmatch '^\d+\.\d+\.\d+$') { return (& $no "the manifest names no release version ('$ver')") }
    $sha = "$($m.sha256)".Trim().ToLowerInvariant(); if ($sha -notmatch '^[0-9a-f]{64}$') { return (& $no 'the manifest carries no SHA-256') }
    $seq = 0; if (-not [int]::TryParse("$($m.sequence)", [ref]$seq) -or $seq -lt 1) { return (& $no 'the manifest carries no sequence') }
    if ($seq -lt $AppliedSequence) { return (& $no "REPLAY refused: sequence $seq is lower than the $AppliedSequence already applied here") }
    $size = [int64]0; [void][int64]::TryParse("$($m.size)", [ref]$size)
    $url = "$(& $g $Response 'downloadUrl')".Trim()
    if ($url -notmatch '^https://') { return (& $no 'the download link is not https') }
    $r = @{ ok = $true; hold = $false; reason = "signed manifest: $ver (ring $($m.ring), sequence $seq)"; version = $ver; sequence = $seq; sha256 = $sha; size = $size; downloadUrl = $url; manifest = $m }
    if ("$($m.manualStep)".Trim()) { $r.hold = $true; $r.reason = "HELD -- $ver asks for a manual step first: $("$($m.manualStep)".Trim())" ; return $r }
    $mf = "$($m.minFromVersion)".Trim()
    if ($mf -and "$RunningVersion".Trim() -and (Compare-PimReleaseVersion "$RunningVersion" $mf) -lt 0) {
        $r.hold = $true; $r.reason = "HELD -- $ver can only be installed from $mf or later; this environment runs $RunningVersion"; return $r
    }
    return $r
}

function Get-PimInvardiaPullReason {
    <# PURE. The admin's sentence for a non-200 pull answer. #>
    param([int]$Status, [AllowNull()][object]$Body, [string]$ErrorText = '')
    $why = if ($Body -and $Body.PSObject.Properties['reason']) { " ($($Body.reason))" } else { '' }
    switch ($Status) {
        204 { return 'nothing is released to this environment''s ring yet' }
        401 { return 'Invardia refused the install key (revoked, reset or wrong) -- claim a new one or set PIM_UPLINK_KEY' }
        403 { return "Invardia refused the licence$why -- updates need a valid Invardia-issued Pro licence for this tenant" }
        404 { return 'Invardia does not know the product' }
        429 { return 'Invardia asked to wait (rate limit) -- the next run asks again' }
        0   { return "Invardia could not be reached: $ErrorText" }
        default { return "Invardia answered HTTP $Status$why" }
    }
}

function Invoke-PimInvardiaManifestPull {
    <# The pull. -Http { param($Method, $Url, $Body, $Headers) } -> @{ status; body; error } (Invoke-PimLicenceHttp). #>
    param([Parameter(Mandatory)][scriptblock]$Http, [string]$BaseUrl = '', [Parameter(Mandatory)][string]$InstallKey, [Parameter(Mandatory)][string]$LicenceText, [string]$Kind = 'code')
    $base = if ("$BaseUrl".Trim()) { "$BaseUrl".Trim().TrimEnd('/') } else { $script:PimInvardiaDefaultBase }
    $r = & $Http 'POST' "$base/api/updates/$($script:PimInvardiaProduct)/manifest" @{ kind = $Kind; licence = $LicenceText } @{ 'X-Invardia-Install-Key' = $InstallKey }
    $pullStatus = [int]$r.status
    return @{ status = $pullStatus; body = $r.body; reason = $(if ($pullStatus -eq 200) { '' } else { Get-PimInvardiaPullReason -Status $pullStatus -Body $r.body -ErrorText "$($r.error)" }) }
}

function Save-PimInvardiaArchive {
    <# Download the release zip and prove it is the one the manifest names (zip magic, size, SHA-256). @{ ok; bytes; reason }. #>
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$OutFile, [Parameter(Mandatory)][string]$ExpectedSha256, [int64]$ExpectedSize = 0, [int]$TimeoutSeconds = 300)
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.ServicePointManager]::SecurityProtocol } catch { }
    try { Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec $TimeoutSeconds -ErrorAction Stop }
    catch { return @{ ok = $false; bytes = 0; reason = "download failed: $($_.Exception.Message -replace '\?t=[^\s''"]+', '?t=***')" } }
    return (Test-PimInvardiaArchiveFile -Path $OutFile -ExpectedSha256 $ExpectedSha256 -ExpectedSize $ExpectedSize)
}

function Test-PimInvardiaArchiveFile {
    <# PURE (file read). The downloaded file is a zip of the size and SHA-256 the SIGNED manifest names. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ExpectedSha256, [int64]$ExpectedSize = 0)
    if (-not (Test-Path -LiteralPath $Path)) { return @{ ok = $false; bytes = 0; reason = 'the download produced no file' } }
    $len = (Get-Item -LiteralPath $Path).Length
    $magic = New-Object byte[] 2
    $fs = [System.IO.File]::OpenRead($Path); try { [void]$fs.Read($magic, 0, 2) } finally { $fs.Dispose() }
    if ($magic[0] -ne 0x50 -or $magic[1] -ne 0x4B) { return @{ ok = $false; bytes = $len; reason = 'the downloaded file is not a zip' } }
    if ($ExpectedSize -gt 0 -and $len -ne $ExpectedSize) { return @{ ok = $false; bytes = $len; reason = "the archive is $len bytes, the signed manifest says $ExpectedSize" } }
    $sha = [System.Security.Cryptography.SHA256]::Create(); $fh = [System.IO.File]::OpenRead($Path)
    try { $h = ([BitConverter]::ToString($sha.ComputeHash($fh))).Replace('-', '').ToLowerInvariant() } finally { $fh.Dispose(); $sha.Dispose() }
    if ($h -ne "$ExpectedSha256".Trim().ToLowerInvariant()) { return @{ ok = $false; bytes = $len; reason = "the archive's SHA-256 ($h) is not the one the signed manifest names -- refused" } }
    return @{ ok = $true; bytes = $len; reason = '' }
}

function ConvertTo-PimBuildContextFromZip {
    <#
      The release zip (top folder pim-manager-src-<v>/, repo-root shaped inside) -> the tar.gz build context the registry
      build takes (.dockerignore + SOLUTIONS/PIM4EntraPS at its root, the shape Publish-PimSourceArchive has always made).
      Refuses a zip whose SOLUTIONS/PIM4EntraPS/VERSION is not the manifest's version. @{ ok; path; reason }.
    #>
    param([Parameter(Mandatory)][string]$ZipPath, [Parameter(Mandatory)][string]$OutFile, [Parameter(Mandatory)][string]$Version)
    $work = Join-Path ([IO.Path]::GetTempPath()) ("pim-inv-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    try {
        Expand-Archive -LiteralPath $ZipPath -DestinationPath $work -Force
        $top = Join-Path $work "$($script:PimInvardiaProduct)-src-$Version"
        if (-not (Test-Path -LiteralPath $top)) { return @{ ok = $false; path = ''; reason = "the archive has no top folder $($script:PimInvardiaProduct)-src-$Version/" } }
        $vf = Join-Path $top 'SOLUTIONS/PIM4EntraPS/VERSION'
        if (-not (Test-Path -LiteralPath $vf)) { return @{ ok = $false; path = ''; reason = 'the archive holds no SOLUTIONS/PIM4EntraPS (not repo-root shaped)' } }
        $inside = "$(Get-Content -Raw -LiteralPath $vf)".Trim()
        if ($inside -ne $Version) { return @{ ok = $false; path = ''; reason = "the archive holds version $inside, the signed manifest says $Version" } }
        $items = @('SOLUTIONS'); if (Test-Path -LiteralPath (Join-Path $top '.dockerignore')) { $items = @('.dockerignore') + $items }
        Push-Location -LiteralPath $top
        try {
            # A RELATIVE output name, then a move: GNU tar reads 'C:' in an absolute Windows path as a remote host.
            & tar -czf 'context.tar.gz' @items
            if ($LASTEXITCODE -ne 0) { return @{ ok = $false; path = ''; reason = "tar failed (exit $LASTEXITCODE)" } }
        } finally { Pop-Location }
        Move-Item -LiteralPath (Join-Path $top 'context.tar.gz') -Destination $OutFile -Force
        return @{ ok = $true; path = $OutFile; reason = '' }
    } catch { return @{ ok = $false; path = ''; reason = "the archive could not be unpacked: $($_.Exception.Message)" } }
    finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

function ConvertTo-PimInvardiaLicenceText {
    <# PURE. pim.Settings 'License' as Get-PimSqlSetting returns it (a string, or the parsed document) -> the file text,
       exactly as Get-PimLicenseFromStore does. Invardia compares the payload + signature, never the formatting. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    return (ConvertTo-Json -InputObject $Value -Depth 6 -Compress)
}

function Resolve-PimInvardiaInstallKey {
    <# The install key: the Container Apps secret PIM_UPLINK_KEY wins; else the claimed one in pim.Settings. '' = none. #>
    param([scriptblock]$GetSetting)
    $k = "$env:PIM_UPLINK_KEY".Trim()
    if ($k) { return $k }
    if ($GetSetting) { try { $k = "$(& $GetSetting 'InvardiaInstallKey')".Trim() } catch { $k = '' } }
    if ($k -match '^inv-[A-Za-z0-9_-]{20,100}$') { return $k }
    return ''
}

function Invoke-PimInstallKeyClaimCycle {
    <#
      One claim decision with every seam injected. Returns @{ action = none|claimed|refused|failed; message }.
        a key already here (secret or claimed)  -> none
        no Pro licence for this tenant           -> none (Invardia would refuse; nothing is sent)
        201 -> the key is stored ('InvardiaInstallKey'); 409 keyExists -> 'refused', NOT retried by itself until the
        licence changes (a reset at Invardia, then a new licence or 'Claim again' in Settings > Licence clears it);
        403 -> 'refused' with Invardia's reason, retried only after the licence changes; anything else -> retried next run.
    #>
    param([Parameter(Mandatory)][scriptblock]$Http, [Parameter(Mandatory)][scriptblock]$GetSetting, [Parameter(Mandatory)][scriptblock]$SetSetting,
          [string]$LicenceText = '', [bool]$ProHere = $false, [string]$TenantId = '', [string]$BaseUrl = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $save = { param($a, $m, $licHash) & $SetSetting 'InstallKeyClaimState' ([pscustomobject][ordered]@{ action = $a; message = $m; atUtc = $NowUtc.ToUniversalTime().ToString('o'); licenceHash = $licHash }) ; @{ action = $a; message = $m } }
    if (Resolve-PimInvardiaInstallKey -GetSetting $GetSetting) { return @{ action = 'none'; message = 'this install has its install key' } }
    if (-not $ProHere -or -not "$LicenceText".Trim()) { return @{ action = 'none'; message = 'no Pro licence for this tenant -- an install key is claimed with one' } }
    if ("$TenantId" -notmatch '^[0-9a-fA-F-]{36}$') { return @{ action = 'none'; message = 'the real tenant id is not known' } }
    $lh = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes("$LicenceText"))).Replace('-', '').ToLowerInvariant()
    $prev = & $GetSetting 'InstallKeyClaimState'
    if ($prev -and "$($prev.action)" -eq 'refused' -and "$($prev.licenceHash)" -eq $lh) { return @{ action = 'none'; message = "not asked again: $($prev.message)" } }
    $base = if ("$BaseUrl".Trim()) { "$BaseUrl".Trim().TrimEnd('/') } else { $script:PimInvardiaDefaultBase }
    $r = & $Http 'POST' "$base/api/install-keys/claim" @{ product = $script:PimInvardiaProduct; tenantId = "$TenantId".ToLowerInvariant(); licence = "$LicenceText" } @{}
    $claimStatus = [int]$r.status
    if ($claimStatus -eq 201 -and "$($r.body.key)" -match '^inv-[A-Za-z0-9_-]{20,100}$') {
        & $SetSetting 'InvardiaInstallKey' "$($r.body.key)"
        return (& $save 'claimed' "install key claimed for environment $($r.body.environment)" $lh)
    }
    if ($claimStatus -eq 409) {
        $m = if ("$($r.body.error)" -eq 'tenantBelongsToAnotherCompany') { 'Invardia has this tenant under another company -- contact Invardia support' }
             else { 'this environment already has an install key at Invardia (another install, or a lost key) -- reset it in the Invardia portal (Remote support) or ask Invardia, then claim again' }
        return (& $save 'refused' $m $lh)
    }
    if ($claimStatus -eq 403) { return (& $save 'refused' "Invardia refused the licence ($($r.body.reason)) -- the claim needs a valid Invardia-issued Pro licence for this tenant" $lh) }
    return (& $save 'failed' "the claim did not complete: $(Get-PimInvardiaPullReason -Status $claimStatus -Body $r.body -ErrorText "$($r.error)") -- retried next run" '')
}

function Invoke-PimInstallKeyJob {
    <#
      Job 'install-key' (every 6 h). Inert unless the feature 'updates.invardia' is ON. Settings: InvardiaInstallKey (never
      returned by any API), InstallKeyClaimState (shown in Settings > Licence), LicenceRequestBaseUrl (shared; default Invardia).
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $on = [bool]((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and (Test-PimFeatureAvailable -Key 'updates.invardia' -Quiet))
    if (-not $on) { return [pscustomobject]@{ ran = $false; whatIf = [bool]$WhatIf; detail = "install-key: off (feature 'updates.invardia')" } }
    $cs = $null
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
    if (-not $cs) { throw '[install-key] no SQL store -- the licence and the key cannot be read' }
    # PLAIN scriptblocks, never .GetNewClosure() (Test-PimHybridWorker L19): they read $cs / $WhatIf through dynamic scope.
    $get = { param($n) Get-PimSqlSetting -ConnectionString $cs -Name $n }
    $set = { param($n, $v) if (-not $WhatIf) { Set-PimSqlSetting -ConnectionString $cs -Name $n -Value $v } }
    $tid = ''; if (Get-Command Resolve-PimLicenseTenantId -ErrorAction SilentlyContinue) { try { $tid = "$(Resolve-PimLicenseTenantId)" } catch { } }
    $licText = ConvertTo-PimInvardiaLicenceText -Value $(try { & $get 'License' } catch { $null })
    $lic = $null; try { $lic = Get-PimLicense } catch { $lic = $null }
    $proHere = $false; if ($lic -and (Get-Command Test-PimLicenseIsProForTenant -ErrorAction SilentlyContinue)) { try { $proHere = [bool](Test-PimLicenseIsProForTenant -License $lic -TenantId $tid).pro } catch { } }
    $base = "$(& $get 'LicenceRequestBaseUrl')".Trim()
    $http = { param($m, $u, $b, $h) if ($WhatIf) { @{ status = 0; body = $null; error = 'what-if: not sent' } } else { Invoke-PimLicenceHttp -Method $m -Url $u -Body $b -Headers $h } }
    $r = Invoke-PimInstallKeyClaimCycle -Http $http -GetSetting $get -SetSetting $set -LicenceText $licText -ProHere $proHere -TenantId $tid -BaseUrl $base -NowUtc $NowUtc
    [pscustomobject]@{ ran = ($r.action -ne 'none'); whatIf = [bool]$WhatIf; detail = "install-key: $($r.action) -- $($r.message)" }
}

function Get-PimInvardiaUpdateTarget {
    <#
      The update job's whole Invardia step, seams injected: pull, verify, and (when a build is needed) download + re-pack.
      Returns @{ ok; version; sequence; hold; reason; contextPath }:
        ok=$true + version ''        nothing released / nothing new           -> the job reports 'none'
        ok=$true + hold              verified but held (manual step, minFrom)  -> the job reports 'none' with the reason
        ok=$true + version           the approved version; contextPath set when -NeedBuild (the tar.gz to build)
        ok=$false                    refused or failed                          -> the job reports 'failed', nothing moves
    #>
    param([Parameter(Mandatory)][scriptblock]$Http, [AllowEmptyString()][string]$InstallKey = '', [AllowEmptyString()][string]$LicenceText = '',
          [string]$BaseUrl = '', [int]$AppliedSequence = 0, [string]$RunningVersion = '', [string]$LastBuiltVersion = '',
          [object[]]$TrustedKeys = $script:PimInvardiaUpdateTrustedKeys, [scriptblock]$Download, [string]$WorkDir = ([IO.Path]::GetTempPath()))
    $res = @{ ok = $false; version = ''; sequence = 0; hold = $false; reason = ''; contextPath = '' }
    if (-not "$InstallKey".Trim()) { $res.reason = 'this install has no install key (PIM_UPLINK_KEY, or claimed by the install-key job)'; return $res }
    if (-not "$LicenceText".Trim()) { $res.reason = 'no licence is installed -- Pro updates need the Invardia-issued Pro licence'; return $res }
    $p = Invoke-PimInvardiaManifestPull -Http $Http -BaseUrl $BaseUrl -InstallKey $InstallKey -LicenceText $LicenceText
    if ($p.status -eq 204) { $res.ok = $true; $res.reason = $p.reason; return $res }
    if ($p.status -ne 200) { $res.reason = $p.reason; return $res }
    $v = Test-PimInvardiaManifest -Response $p.body -TrustedKeys $TrustedKeys -AppliedSequence $AppliedSequence -RunningVersion $RunningVersion
    if (-not $v.ok) { $res.reason = $v.reason; return $res }
    $res.sequence = $v.sequence; $res.reason = $v.reason
    if ($v.hold) { $res.ok = $true; $res.hold = $true; return $res }
    $res.version = $v.version
    if ("$LastBuiltVersion".Trim() -eq $v.version) { $res.ok = $true; $res.reason = "$($v.reason) -- already built here"; return $res }
    $zip = Join-Path $WorkDir ("$($script:PimInvardiaProduct)-src-$($v.version).zip")
    $ctx = Join-Path $WorkDir ("pim-src-$($v.version).tar.gz")
    try {
        $d = if ($Download) { & $Download $v.downloadUrl $zip $v.sha256 $v.size } else { Save-PimInvardiaArchive -Url $v.downloadUrl -OutFile $zip -ExpectedSha256 $v.sha256 -ExpectedSize $v.size }
        if (-not $d.ok) { $res.version = ''; $res.reason = "archive refused: $($d.reason)"; return $res }
        $c = ConvertTo-PimBuildContextFromZip -ZipPath $zip -OutFile $ctx -Version $v.version
        if (-not $c.ok) { $res.version = ''; $res.reason = "archive refused: $($c.reason)"; return $res }
        $res.ok = $true; $res.contextPath = $ctx
        return $res
    } finally { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
}
