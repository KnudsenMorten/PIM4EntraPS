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

  🔒 The trusted key list (CN=Invardia-Updates) lives in InvardiaUpdate.verify.ps1, the product-neutral verifier every product
     copies byte-identical (framework UPDATE-1). An empty list refuses every manifest -- fail closed.
  🔒 OFF by default twice over: the claim needs the feature 'updates.invardia'; the pull needs PIM_UPDATE_SOURCE=invardia
     on the update job (Deploy-PimUpdateJob -UpdateSource Invardia). Community installs keep their GitHub / pim-src source.
#>

$script:PimInvardiaProduct = 'pim-manager'
$script:PimInvardiaDefaultBase = 'https://invardia.com'
# The product-NEUTRAL verifier (UPDATE-1): a byte-identical copy in every product, pinned by Test-PimInvardiaUpdate. The
# functions below keep PIM's names and pass PIM's product id; the logic lives in InvardiaUpdate.verify.ps1 only.
. (Join-Path $PSScriptRoot 'InvardiaUpdate.verify.ps1')
$script:PimInvardiaDefaultBase = $script:InvardiaUpdateDefaultBase
$script:PimInvardiaUpdateTrustedKeys = $script:InvardiaUpdateTrustedKeys

function ConvertFrom-PimInvardiaBase64Url { param([AllowEmptyString()][string]$Text) ConvertFrom-InvardiaBase64Url -Text $Text }
function Compare-PimReleaseVersion { param([string]$A, [string]$B) Compare-InvardiaReleaseVersion -A $A -B $B }
function Test-PimInvardiaManifestSignature {
    param([string]$ManifestB64, [string]$Signature, [string]$KeyId, [object[]]$TrustedKeys = $script:InvardiaUpdateTrustedKeys)
    Test-InvardiaManifestSignature -ManifestB64 $ManifestB64 -Signature $Signature -KeyId $KeyId -TrustedKeys $TrustedKeys
}
function Test-PimInvardiaManifest {
    param([Parameter(Mandatory)][object]$Response, [object[]]$TrustedKeys = $script:InvardiaUpdateTrustedKeys,
          [string]$Kind = 'code', [int]$AppliedSequence = 0, [string]$RunningVersion = '', [string]$Product = $script:PimInvardiaProduct, [int]$Ring = -1)
    Test-InvardiaManifest -Response $Response -TrustedKeys $TrustedKeys -Kind $Kind -AppliedSequence $AppliedSequence -RunningVersion $RunningVersion -Product $Product -Ring $Ring
}
function Get-PimInvardiaPullReason {
    param([int]$Status, [AllowNull()][object]$Body, [string]$ErrorText = '')
    $r = Get-InvardiaPullReason -Status $Status -Body $Body -ErrorText $ErrorText
    # PIM's own hint for a refused key: where PIM keeps it.
    if ($Status -eq 401) { $r = "$r (PIM: the Container Apps secret PIM_UPLINK_KEY, or the key the install-key job claimed)" }
    $r
}
function Invoke-PimInvardiaManifestPull {
    # -InstallId (INV-S16): the install's lasting id (Resolve-PimInvardiaInstallId, PIM-LicenceRequest.ps1) -> header
    # X-Invardia-Install-Id; '' = no header.
    param([Parameter(Mandatory)][scriptblock]$Http, [string]$BaseUrl = '', [Parameter(Mandatory)][string]$InstallKey, [Parameter(Mandatory)][string]$LicenceText, [string]$Kind = 'code',
          [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring, [AllowEmptyString()][AllowNull()][string]$InstallId = '',
          [int[]]$RetryDelaysSec = $script:PimInvardiaPullRetryDelaysSec)
    # UPD-RETRY (2026-11-03, two ring-2 production installs): ONE 30 s timeout while Invardia swapped a deploy slot marked a whole
    # nightly run failed, although the update itself had gone through. A pull that got NO answer (status 0) or a gateway
    # answer (502/503/504) is asked again after each delay in -RetryDelaysSec; every other answer (200, 204, 401, 403, 404,
    # 422, 429, ...) is final at once. The PIM wrapper only -- the verifier stays byte-identical across products (UPDATE-1).
    $delays = @($RetryDelaysSec | Where-Object { $null -ne $_ })
    $attempt = 0
    while ($true) {
        $p = Invoke-InvardiaManifestPull -Product $script:PimInvardiaProduct -Http $Http -BaseUrl $BaseUrl -InstallKey $InstallKey -LicenceText $LicenceText -Kind $Kind -Ring $Ring -InstallId $InstallId
        if (-not (Test-PimInvardiaPullRetryable -Status ([int]$p.status)) -or $attempt -ge $delays.Count) { break }
        $wait = [Math]::Max(0, [int]$delays[$attempt]); $attempt++
        Write-Verbose "Invardia pull: no usable answer ($($p.reason)) -- asking again in $wait s (attempt $($attempt + 1) of $($delays.Count + 1))"
        if ($wait -gt 0) { Start-Sleep -Seconds $wait }
    }
    $p['attempts'] = $attempt + 1
    if ($attempt -gt 0 -and [int]$p.status -ne 200 -and [int]$p.status -ne 204 -and "$($p.reason)") { $p.reason = "$($p.reason) (asked $($attempt + 1) times)" }
    if ($p.status -eq 401) { $p.reason = Get-PimInvardiaPullReason -Status 401 -Body $p.body }
    $p
}
# Waits between the manifest pull's attempts (UPD-RETRY): 30 s, 60 s, 120 s -- with the 30 s request timeout a run gives
# Invardia about 6 minutes before it records a failure. The nightly updater has hours; nobody waits on it.
$script:PimInvardiaPullRetryDelaysSec = @(30, 60, 120)
function Test-PimInvardiaPullRetryable {
    <# PURE. A pull answer worth asking again: no answer at all (0 -- timeout, connection refused/reset) or a gateway status. #>
    param([int]$Status)
    return ($Status -eq 0 -or $Status -eq 502 -or $Status -eq 503 -or $Status -eq 504)
}
# ---- framework 8.18 UPDATE-NOW -- the signal (PIM-UpdateNow.ps1 decides what it means) ------------------------------
# GET <base>/api/updates/pim-manager/signal?ring=N, the SAME install key header as the manifest pull, If-None-Match with
# the ETag of the last answer. 200 { updateNow; version; raisedAt; by; scope } + ETag, 304 unchanged. Never throws.
function Invoke-PimInvardiaSignalHttp {
    <# The real seam: one GET, 15 s, @{ status; body; etag; error }. A non-2xx (304 / 404 / 5xx) is a status, never a throw. #>
    param([Parameter(Mandatory)][string]$Url, [hashtable]$Headers = @{})
    try {
        $r = Invoke-WebRequest -Uri $Url -Method GET -Headers $Headers -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
        $et = ''; try { $et = "$(@($r.Headers['ETag'])[0])".Trim() } catch { $et = '' }
        $b = $null; if ("$($r.Content)".Trim()) { try { $b = "$($r.Content)" | ConvertFrom-Json } catch { $b = $null } }
        return @{ status = [int]$r.StatusCode; body = $b; etag = $et; error = '' }
    } catch {
        $code = 0; try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { $code = 0 }
        return @{ status = $code; body = $null; etag = ''; error = ((("$($_.Exception.Message)") -split "`n")[0]) }
    }
}

function Invoke-PimInvardiaUpdateSignal {
    <#
      Ask Invardia whether an "update now" is raised for this environment's ring (or this environment). -Http { param($Url,
      $Headers) } -> @{ status; body; etag } (default Invoke-PimInvardiaSignalHttp). No install key = NO call (status 0,
      reason 'no install key'). Never throws.
    #>
    param([scriptblock]$Http, [string]$BaseUrl = '', [AllowEmptyString()][string]$InstallKey = '', [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring, [AllowEmptyString()][string]$ETag = '')
    if (-not "$InstallKey".Trim()) { return @{ status = 0; body = $null; etag = ''; error = 'no install key' } }
    $base = if ("$BaseUrl".Trim()) { "$BaseUrl".Trim().TrimEnd('/') } else { $script:PimInvardiaDefaultBase }
    if ($base -notmatch '^(?i)https://') { return @{ status = 0; body = $null; etag = ''; error = 'the update address is not https' } }
    $url = "$base/api/updates/$($script:PimInvardiaProduct)/signal?ring=$Ring"
    $h = @{ 'X-Invardia-Install-Key' = "$InstallKey".Trim() }
    if ("$ETag".Trim()) { $h['If-None-Match'] = "$ETag".Trim() }
    try {
        if ($Http) { return (& $Http $url $h) }
        return (Invoke-PimInvardiaSignalHttp -Url $url -Headers $h)
    } catch { return @{ status = 0; body = $null; etag = ''; error = ((("$($_.Exception.Message)") -split "`n")[0]) } }
}

# ---- UPDATE-NOW-HEAD (Invardia 2026-11-03, Invardia DESIGN 12 "Quicker updates") -- the quick check ------------------
# POST <base>/api/updates/pim-manager/head, the SAME install key header (+ X-Invardia-Install-Id) and the SAME licence text as
# the manifest pull, body { kind; licence; ring }. 200 { version; sequence; wave?; expedite? }; refusals as the manifest pull
# (401 / 403 / 422); 404 = an older Invardia without /head (PIM-UpdateNow.ps1 then asks GET /signal). Writes nothing at
# Invardia. NO retry here (unlike the nightly pull, UPD-RETRY): the updater's next 15-minute slot is the retry.
function Invoke-PimInvardiaHeadHttp {
    <#
      The real seam: one JSON POST, 15 s, @{ status; body; error }. Unlike the manifest pull's helper it also reads the BODY
      of a refusal (401 / 403 / 422 -- ErrorDetails on PowerShell 7 and Windows PowerShell 5.1), so a 403 licence is told
      from a 403 installKeyBound / ring. A non-2xx is a status, never a throw.
    #>
    param([string]$Method = 'POST', [Parameter(Mandatory)][string]$Url, $Body, [hashtable]$Headers = @{})
    $a = @{ Method = $Method; Uri = $Url; Headers = $Headers; ContentType = 'application/json'; TimeoutSec = 15; UseBasicParsing = $true }
    if ($null -ne $Body) { $a['Body'] = ($Body | ConvertTo-Json -Depth 6 -Compress) }
    try {
        $r = Invoke-WebRequest @a -ErrorAction Stop
        $b = $null; if ("$($r.Content)".Trim()) { try { $b = "$($r.Content)" | ConvertFrom-Json } catch { $b = $null } }
        return @{ status = [int]$r.StatusCode; body = $b; error = '' }
    } catch {
        $code = 0; try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { $code = 0 }
        $b = $null
        try { $t = "$($_.ErrorDetails.Message)".Trim(); if ($t.StartsWith('{')) { $b = $t | ConvertFrom-Json } } catch { $b = $null }
        return @{ status = $code; body = $b; error = ((("$($_.Exception.Message)") -split "`n")[0]) }
    }
}

function Invoke-PimInvardiaUpdateHead {
    <#
      One POST, never throws: @{ status; body; error }. -Http { param($Method, $Url, $Body, $Headers) } (default
      Invoke-PimInvardiaHeadHttp). No install key / no licence = NO call (status 0, error 'no install key' / 'no licence').
      Neither the key nor the licence is ever put in 'error' or any other returned text.
    #>
    param([scriptblock]$Http, [string]$BaseUrl = '', [AllowEmptyString()][string]$InstallKey = '', [AllowEmptyString()][AllowNull()][string]$LicenceText = '',
          [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring, [AllowEmptyString()][AllowNull()][string]$InstallId = '', [string]$Kind = 'code')
    # COMMUNITY-CLAIM-ON-YES (Invardia 2026-11-11): -Kind community = a Community install with its key -- NO licence is needed
    # or sent; Invardia answers the "Update now" mark the same way. Kind code (Pro) is unchanged: no licence = no call.
    $community = ("$Kind" -eq 'community')
    if (-not "$InstallKey".Trim()) { return @{ status = 0; body = $null; error = 'no install key' } }
    if (-not $community -and -not "$LicenceText".Trim()) { return @{ status = 0; body = $null; error = 'no licence' } }
    $base = if ("$BaseUrl".Trim()) { "$BaseUrl".Trim().TrimEnd('/') } else { $script:PimInvardiaDefaultBase }
    if ($base -notmatch '^(?i)https://') { return @{ status = 0; body = $null; error = 'the update address is not https' } }
    $url = "$base/api/updates/$($script:PimInvardiaProduct)/head"
    $h = @{ 'X-Invardia-Install-Key' = "$InstallKey".Trim() }
    $iid = "$InstallId".Trim().ToLowerInvariant()
    if ($iid -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $h['X-Invardia-Install-Id'] = $iid }
    $body = if ($community) { [ordered]@{ kind = 'community'; ring = $Ring } } else { [ordered]@{ kind = $Kind; licence = "$LicenceText"; ring = $Ring } }
    $r = $null
    try {
        if ($Http) { $r = & $Http 'POST' $url $body $h }
        else { $r = Invoke-PimInvardiaHeadHttp -Method 'POST' -Url $url -Body $body -Headers $h }
    } catch { return @{ status = 0; body = $null; error = 'the request failed' } }
    $code = 0; try { $code = [int]$r.status } catch { $code = 0 }
    # the error text is a transport message; scrub anything that could carry the key or the licence before it goes anywhere
    $err = ((("$($r.error)") -split "`n")[0])
    if ($err -and ($err.Contains("$InstallKey".Trim()) -or ("$LicenceText" -and $err.Contains("$LicenceText")))) { $err = 'the request failed' }
    return @{ status = $code; body = $r.body; error = $err }
}

function Save-PimInvardiaArchive {
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$OutFile, [Parameter(Mandatory)][string]$ExpectedSha256, [int64]$ExpectedSize = 0, [int]$TimeoutSeconds = 300)
    Save-InvardiaArchive -Url $Url -OutFile $OutFile -ExpectedSha256 $ExpectedSha256 -ExpectedSize $ExpectedSize -TimeoutSeconds $TimeoutSeconds
}
function Test-PimInvardiaArchiveFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ExpectedSha256, [int64]$ExpectedSize = 0)
    Test-InvardiaArchiveFile -Path $Path -ExpectedSha256 $ExpectedSha256 -ExpectedSize $ExpectedSize
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
        # CR7 (PIM 100.168): a release that carries the shared sign-in front's source keeps it in the context, so an opted-in
        # install builds signin-front from it. The Manager build never sees it (.dockerignore keeps SOLUTIONS/PIM4EntraPS only).
        # 3.0.58: a release packed while the framework was past PIM's pin carries no FRAMEWORK/ -- the vendored copy (at the
        # pin) is placed there instead, exactly as the Community context does it (the front step prefers vendor/ anyway).
        $vsfPro = Join-Path $top 'SOLUTIONS/PIM4EntraPS/vendor/signin-front'
        if (-not (Test-Path -LiteralPath (Join-Path $top 'FRAMEWORK/signin-front/src/Dockerfile')) -and
            (Test-Path -LiteralPath (Join-Path $vsfPro 'src/Dockerfile')) -and (Test-Path -LiteralPath (Join-Path $vsfPro 'VERSION'))) {
            $fwPro = Join-Path $top 'FRAMEWORK/signin-front'
            New-Item -ItemType Directory -Force -Path $fwPro | Out-Null
            Copy-Item -LiteralPath (Join-Path $vsfPro 'src') -Destination $fwPro -Recurse -Force
            Copy-Item -LiteralPath (Join-Path $vsfPro 'VERSION') -Destination $fwPro -Force
        }
        if (Test-Path -LiteralPath (Join-Path $top 'FRAMEWORK/signin-front/src/Dockerfile')) { $items += 'FRAMEWORK' }
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
    <# The install key: the Container Apps secret PIM_UPLINK_KEY wins; else the claimed one in pim.Settings. '' = none.
       COMMUNITY-CLAIM-ON-YES: a Community install whose choice 'Connect this install to Invardia' is OFF (pim.Settings
       'InvardiaConnect' { connect = false }) keeps a key it claimed earlier but does not USE it: '' here, so the heartbeat,
       the update track, Update now and every other Invardia call stay anonymous / off. Only that explicit 'no' counts (a
       Pro install never has the record). #>
    param([scriptblock]$GetSetting)
    $k = "$env:PIM_UPLINK_KEY".Trim()
    if ($k) { return $k }
    if ($GetSetting) {
        if ((Get-PimCommunityConnectChoice -GetSetting $GetSetting) -eq 'no') { return '' }
        try { $k = "$(& $GetSetting 'InvardiaInstallKey')".Trim() } catch { $k = '' }
    }
    if ($k -match '^inv-[A-Za-z0-9_-]{20,100}$') { return $k }
    return ''
}

# ---- COMMUNITY-CLAIM-ON-YES (owner decisions 2026-11-11, framework PRO-COMMUNITY-SAME) ------------------------------------
# Pro and Community install and run the same way. A Community install claims an Invardia install key ONLY on the user's
# yes to ONE question, the same words in every product (Get-PimCommunityConnectQuestion). Yes = the key is claimed through
# Invardia's Community claim route and stored exactly where Pro keeps its key (pim.Settings 'InvardiaInstallKey'); from
# then on the heartbeat, the update track and Update now run as for Pro (they look only at the key). No = anonymous: no
# key, no Update now; everything else the same. The choice is pim.Settings 'InvardiaConnect' { connect; source; atUtc }.
# 🔌 THE CLAIM (Invardia's contract, LIVE 2026-11-11): the SAME route as the Pro claim, POST <base>/api/install-keys/claim,
#    body { product; tenantId; edition = 'community' } and NO licence; the answer has the Pro claim's shape. Get-PimCommunityClaimRoute
#    names it (the one place to change it). An older Invardia without it (404 / 405 / 501) = anonymous + one plain line.
function Get-PimCommunityConnectQuestion { <# PURE. LITERAL. The question, exactly, in every product. #> return 'Connect this install to Invardia: health reports + updates on request' }
function Get-PimCommunityConnectSettingName { <# PURE. LITERAL. #> return 'InvardiaConnect' }
function Get-PimCommunityClaimRoute { <# PURE. LITERAL. THE claim route: POST <base><route> (the Pro claim's route; edition community, no licence). #> return '/api/install-keys/claim' }

function ConvertFrom-PimCommunityConnectValue {
    <# PURE. The stored choice -> 'yes' | 'no' | '' (none recorded / not readable). Only a real boolean counts: { connect =
       $true|$false } (object, dictionary or its JSON text) or a bare boolean. Any other value (a key text, a word) = ''. #>
    param([AllowNull()][object]$Value)
    $v = $Value
    if ($v -is [string]) { $t = $v.Trim(); if (-not $t.StartsWith('{')) { return '' }; try { $v = $t | ConvertFrom-Json -ErrorAction Stop } catch { return '' } }
    if ($v -is [bool]) { return $(if ($v) { 'yes' } else { 'no' }) }
    $c = $null
    if ($v -is [System.Collections.IDictionary]) { if ($v.Contains('connect')) { $c = $v['connect'] } }
    elseif ($null -ne $v -and $v.PSObject.Properties['connect']) { $c = $v.connect }
    if ($c -is [bool]) { return $(if ($c) { 'yes' } else { 'no' }) }
    return ''
}

function Get-PimCommunityConnectChoice {
    <# The recorded choice through -GetSetting { param($Name) }: 'yes' | 'no' | ''. Never throws. #>
    param([scriptblock]$GetSetting)
    if (-not $GetSetting) { return '' }
    $v = $null; try { $v = & $GetSetting (Get-PimCommunityConnectSettingName) } catch { return '' }
    return (ConvertFrom-PimCommunityConnectValue -Value $v)
}

function New-PimCommunityConnectRecord {
    <# PURE. The stored choice: { connect; source = installer|manager; atUtc }. #>
    param([Parameter(Mandatory)][bool]$Connect, [ValidateSet('installer', 'manager')][string]$Source = 'installer', [datetime]$NowUtc = [datetime]::UtcNow)
    return [pscustomobject][ordered]@{ connect = $Connect; source = $Source; atUtc = $NowUtc.ToUniversalTime().ToString('o') }
}

function Resolve-PimCommunityConnectAnswer {
    <#
      PURE (the prompt is a seam). The installer's answer for a COMMUNITY install. Returns @{ connect; source; asked; line }.
        -Mode yes  (-ConnectToInvardia)    -> connect, not asked
        -Mode no   (-NoConnectToInvardia)  -> anonymous, not asked
        -Mode ask  (the default)           -> the question, exactly, through -ReadAnswer { param($Question) } when the run is
                                              -Interactive; y / yes = connect; anything else, no answer, or a run nobody
                                              can answer (not interactive, no reader, the reader throws) = NO.
    #>
    param([ValidateSet('ask', 'yes', 'no')][string]$Mode = 'ask', [bool]$Interactive = $false, [scriptblock]$ReadAnswer)
    $q = Get-PimCommunityConnectQuestion
    $yes = "$q -- yes: the install key is claimed; health reports, the update track and Update now work as for Pro"
    $no = "$q -- no: this install stays anonymous (no install key, no Update now); everything else is the same. Change it later in PIM Manager > Settings > Licence"
    if ($Mode -eq 'yes') { return @{ connect = $true; source = 'parameter'; asked = $false; line = "$yes (-ConnectToInvardia)" } }
    if ($Mode -eq 'no') { return @{ connect = $false; source = 'parameter'; asked = $false; line = "$no (-NoConnectToInvardia)" } }
    if (-not $Interactive -or -not $ReadAnswer) { return @{ connect = $false; source = 'no-answer'; asked = $false; line = "$no (nobody could answer here; -ConnectToInvardia answers yes)" } }
    $a = ''; try { $a = "$(& $ReadAnswer $q)".Trim() } catch { $a = '' }
    if ($a -match '^(?i)(y|yes|j|ja)$') { return @{ connect = $true; source = 'answer'; asked = $true; line = $yes } }
    return @{ connect = $false; source = 'answer'; asked = $true; line = $no }
}

function Invoke-PimCommunityConnectHttp {
    <# The real seam: one JSON POST, 30 s, @{ status; body; error }. A non-2xx is a status (its JSON body read), never a throw. #>
    param([string]$Method = 'POST', [Parameter(Mandatory)][string]$Url, $Body, [hashtable]$Headers = @{})
    $a = @{ Method = $Method; Uri = $Url; Headers = $(if ($Headers) { $Headers } else { @{} }); ContentType = 'application/json'; TimeoutSec = 30; UseBasicParsing = $true }
    if ($null -ne $Body) { $a['Body'] = ($Body | ConvertTo-Json -Depth 6 -Compress) }
    try {
        $r = Invoke-WebRequest @a -ErrorAction Stop
        $b = $null; if ("$($r.Content)".Trim()) { try { $b = "$($r.Content)" | ConvertFrom-Json } catch { $b = $null } }
        return @{ status = [int]$r.StatusCode; body = $b; error = '' }
    } catch {
        $code = 0; try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { $code = 0 }
        $b = $null; try { $t = "$($_.ErrorDetails.Message)".Trim(); if ($t.StartsWith('{')) { $b = $t | ConvertFrom-Json } } catch { $b = $null }
        return @{ status = $code; body = $b; error = ((("$($_.Exception.Message)") -split "`n")[0]) }
    }
}

function Invoke-PimCommunityInstallKeyClaim {
    <#
      One Community claim decision, every seam injected; NEVER throws, never fails an install. Returns @{ action; message }:
        a usable key already here                -> none
        the choice is not 'yes'                  -> none (anonymous by choice: NO call)
        the real tenant id is not known          -> none
        a refusal / keyExists recorded AFTER the latest yes -> none (asked again only when the user says yes again)
        POST <base>/api/install-keys/claim { product = 'pim-manager'; tenantId; edition = 'community' } -- NO licence
             header X-Invardia-Install-Id (when the install has its lasting id; never in the body)
          201 / 200 + { key = inv-... }          -> stored as 'InvardiaInstallKey' (where Pro keeps it), 'claimed'
          409 tenantKnown                        -> 'refused': the tenant belongs to a company with a licence -- "claim with
                                                    your licence" (Settings > Licence); NOT retried
          409 keyExists                          -> 'exists': a repeat -- already connected at Invardia; not a failure, NOT
                                                    retried (no key arrives with it)
          429                                    -> 'later': "try again later" (5 per IP per hour, or the daily cap); the
                                                    install continues without a key; the install-key job asks again (6 h)
          404 / 405 / 501                        -> 'anonymous': an Invardia without the Community claim -- one plain line;
                                                    asked again every 6 hours
          403 / another 409                      -> 'refused' (Invardia's reason); not asked again until a new yes
          anything else (no answer, 5xx)         -> 'failed', asked again on the next run
      The state for the admin: pim.Settings 'CommunityConnectState' { action; message; atUtc }. The key is never in it.
    #>
    param([Parameter(Mandatory)][scriptblock]$Http, [Parameter(Mandatory)][scriptblock]$GetSetting, [Parameter(Mandatory)][scriptblock]$SetSetting,
          [string]$TenantId = '', [AllowEmptyString()][AllowNull()][string]$InstallId = '', [string]$BaseUrl = '', [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        $now = $NowUtc.ToUniversalTime()
        $save = { param($a, $m) try { & $SetSetting 'CommunityConnectState' ([pscustomobject][ordered]@{ action = $a; message = $m; atUtc = $now.ToString('o') }) } catch { }; @{ action = $a; message = $m } }
        if (Resolve-PimInvardiaInstallKey -GetSetting $GetSetting) { return @{ action = 'none'; message = 'this install has its install key' } }
        if ((Get-PimCommunityConnectChoice -GetSetting $GetSetting) -ne 'yes') { return @{ action = 'none'; message = 'not connected to Invardia (the choice is no, or not made) -- anonymous, nothing is sent' } }
        if ("$TenantId" -notmatch '^[0-9a-fA-F-]{36}$') { return @{ action = 'none'; message = 'the real tenant id is not known -- nothing is sent' } }
        $prev = $null; try { $prev = & $GetSetting 'CommunityConnectState' } catch { $prev = $null }
        if ($prev -is [string] -and "$prev".Trim().StartsWith('{')) { try { $prev = "$prev" | ConvertFrom-Json } catch { $prev = $null } }
        if ($prev -and "$($prev.action)" -in @('refused', 'exists')) {
            $choiceAt = $null; $refusedAt = $null
            try { $cv = & $GetSetting (Get-PimCommunityConnectSettingName); if ($cv -is [string]) { $cv = $cv | ConvertFrom-Json }; $choiceAt = ([datetime]"$($cv.atUtc)").ToUniversalTime() } catch { $choiceAt = $null }
            try { $refusedAt = ([datetime]"$($prev.atUtc)").ToUniversalTime() } catch { $refusedAt = $null }
            if ($refusedAt -and (-not $choiceAt -or $choiceAt -le $refusedAt)) { return @{ action = 'none'; message = "not asked again: $($prev.message)" } }
        }
        $base = if ("$BaseUrl".Trim()) { "$BaseUrl".Trim().TrimEnd('/') } else { $script:PimInvardiaDefaultBase }
        if ($base -notmatch '^(?i)https://') { return (& $save 'failed' 'the Invardia address is not https -- nothing is sent') }
        $body = [ordered]@{ product = $script:PimInvardiaProduct; tenantId = "$TenantId".ToLowerInvariant(); edition = 'community' }
        $h = @{}
        $iid = "$InstallId".Trim().ToLowerInvariant()
        if ($iid -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $h['X-Invardia-Install-Id'] = $iid }
        $r = $null; try { $r = & $Http 'POST' "$base$(Get-PimCommunityClaimRoute)" $body $h } catch { $r = @{ status = 0; body = $null; error = ((("$($_.Exception.Message)") -split "`n")[0]) } }
        $st = 0; try { $st = [int]$r.status } catch { $st = 0 }
        if (($st -eq 201 -or $st -eq 200) -and "$($r.body.key)" -match '^inv-[A-Za-z0-9_-]{20,100}$') {
            & $SetSetting 'InvardiaInstallKey' "$($r.body.key)"
            try { $eid = "$($r.body.environmentId)".Trim().ToLowerInvariant(); if ($eid -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { & $SetSetting 'InvardiaEnvironmentId' $eid } } catch { }
            return (& $save 'claimed' 'connected to Invardia: the install key is claimed -- health reports, the update track and Update now work as for Pro')
        }
        $code = "$($r.body.error)$(if (-not "$($r.body.error)") { "$($r.body.code)" })".Trim()
        if ($st -eq 409 -and $code -eq 'tenantKnown') {
            return (& $save 'refused' 'this tenant belongs to a company that holds a licence at Invardia -- claim with your licence (PIM Manager > Settings > Licence); not asked again')
        }
        if ($st -eq 409 -and $code -eq 'keyExists') {
            return (& $save 'exists' 'already connected: Invardia already holds an install key for this install (a repeat) -- nothing more to claim; not asked again')
        }
        if ($st -eq 429) {
            return (& $save 'later' 'Invardia is busy (too many claims from this address, or the daily limit) -- try again later; the install continues without a key and the engine asks again within 6 hours')
        }
        if ($st -in @(404, 405, 501)) {
            return (& $save 'anonymous' "Invardia does not take Community connections yet -- this install stays anonymous for now and connects by itself once Invardia does (asked again every 6 hours)")
        }
        if ($st -eq 409 -or $st -eq 403) {
            $why = "$($r.body.error)$(if ("$($r.body.reason)") { " $($r.body.reason)" })".Trim()
            return (& $save 'refused' "Invardia refused the Community connection$(if ($why) { " ($why)" }) -- this install stays anonymous; switch 'Connect this install to Invardia' off and on in Settings > Licence to ask again")
        }
        $err = ((("$($r.error)") -split "`n")[0])
        return (& $save 'failed' "the Community connection did not complete ($(if ($st) { "HTTP $st" } else { "no answer$(if ($err) { ": $err" })" })) -- asked again on the next run; this install stays anonymous until then")
    } catch {
        return @{ action = 'failed'; message = "the Community connection was not tried ($((("$($_.Exception.Message)") -split "`n")[0])) -- asked again on the next run" }
    }
}

function Get-PimUpdateNowHeadKind {
    <# PURE. The kind the 15-minute quick check sends on POST /head (UPDATE-NOW for both editions, Invardia 2026-11-11): Pro
       (source 'invardia' / anything not Community) = 'code' with its licence, exactly as before; a Community install (source
       'invardia-community') = 'community' and NO licence -- with its install key Invardia answers the "Update now" mark.
       Without a key nothing is asked (the quick check's own gate, Invoke-PimUpdateNowQuickCheck). #>
    param([AllowEmptyString()][AllowNull()][string]$UpdateSource = '')
    if ("$UpdateSource".Trim() -ieq 'invardia-community') { return 'community' }
    return 'code'
}

function Get-PimInvardiaCommunityApproval {
    <#
      The version a Community ring approves right now, read the way the nightly Community run reads it (the anonymous channel,
      the SAME verifier, kind community, this ring) WITHOUT downloading anything: @{ version; reason }. '' = nothing approved
      / not readable (an Update now signal then starts nothing). Seam -Http { param($Url) }. Never throws.
    #>
    param([scriptblock]$Http, [string]$BaseUrl = '', [AllowEmptyString()][string]$Ring = '', [int]$AppliedSequence = 0,
          [string]$RunningVersion = '', [object[]]$TrustedKeys = $script:PimInvardiaUpdateTrustedKeys)
    try {
        $ringN = -1
        if (-not [int]::TryParse("$Ring".Trim(), [ref]$ringN) -or $ringN -notin (Get-PimCommunityChannelRings)) { return @{ version = ''; reason = "no Community ring ('$Ring')" } }
        $p = Invoke-PimInvardiaCommunityPull -Http $Http -BaseUrl $BaseUrl -Ring $ringN
        if ($p.status -eq 204) { return @{ version = ''; reason = 'nothing is released to the Community channel for this ring' } }
        if ($p.status -ne 200) { return @{ version = ''; reason = "the ring's Community manifest could not be read ($($p.reason))" } }
        $v = Test-PimInvardiaManifest -Response $p.body -TrustedKeys $TrustedKeys -Kind 'community' -AppliedSequence $AppliedSequence -RunningVersion $RunningVersion -Ring $ringN
        if (-not $v.ok) { return @{ version = ''; reason = "the ring's Community manifest was refused ($($v.reason))" } }
        if ($v.hold) { return @{ version = ''; reason = "the ring's Community manifest is held ($($v.reason))" } }
        return @{ version = "$($v.version)"; reason = "the signed Community manifest for ring $ringN" }
    } catch { return @{ version = ''; reason = "the ring's Community approval could not be read ($((("$($_.Exception.Message)") -split "`n")[0]))" } }
}

function Get-PimCommunityContactGate {
    <#
      PURE. Owner rule (2026-11-11, relayed by Invardia): a COMMUNITY install sends NOTHING that identifies it to Invardia -- no
      licence ask, no heartbeat, no key claim, no update track -- UNLESS its user said yes to the question. The anonymous signed
      Community update channel is not behind this gate (it carries nothing of the install). Returns @{ community; allowed;
      reason }:
        community = no Pro licence for this tenant (-ProHere), no licence file held (-HasLicenceFile), not installed as trial /
                    pro (-InstallEdition), and no usable install key that predates the choice (-HasKey with no choice
                    recorded = an older Pro-intended install) -- i.e. the free edition
        allowed   = not community, or the choice is 'yes', or a usable key is here (a usable key is only ever there after a
                    yes, or on a Pro-intended install: a 'no' hides the key, Resolve-PimInvardiaInstallKey)
      Pro (any of the Pro signs) is never gated: allowed, exactly as before.
    #>
    param([bool]$HasKey = $false, [bool]$ProHere = $false, [bool]$HasLicenceFile = $false, [AllowEmptyString()][AllowNull()][string]$InstallEdition = '',
          [AllowEmptyString()][AllowNull()][string]$Choice = '')
    $ed = "$InstallEdition".Trim().ToLowerInvariant()
    $c = "$Choice".Trim().ToLowerInvariant()
    $proSign = ($ProHere -or $HasLicenceFile -or $ed -in @('trial', 'pro') -or ($HasKey -and -not $c))
    if ($proSign) { return @{ community = $false; allowed = $true; reason = 'a Pro install (licence, install edition or install key) -- unchanged' } }
    if ($c -eq 'yes') { return @{ community = $true; allowed = $true; reason = 'a Community install connected to Invardia (the user said yes)' } }
    return @{ community = $true; allowed = $false
              reason = "a Community install that is not connected to Invardia ($(if ($c -eq 'no') { 'the user said no' } else { 'no answer' })) -- nothing that identifies it is sent; Settings > Licence > 'Connect this install to Invardia' switches it on" }
}

function Get-PimCommunityConnectView {
    <#
      PURE. What the Manager's Settings > Licence shows about the Community switch. -Community = this install is Community (no
      Pro licence for this tenant, not installed as trial / Pro). Returns @{ shown; connect; hasKey; keyUsed; question; state;
      text }. A Pro install: shown = $false (it is licensed and always connected; the switch is not offered).
    #>
    param([bool]$Community, [AllowEmptyString()][string]$Choice = '', [bool]$HasStoredKey = $false, [AllowNull()][object]$State)
    $st = $State; if ($st -is [string] -and "$st".Trim().StartsWith('{')) { try { $st = "$st" | ConvertFrom-Json } catch { $st = $null } }
    $o = [ordered]@{ shown = [bool]$Community; connect = ($Choice -eq 'yes'); hasKey = $HasStoredKey; keyUsed = ($HasStoredKey -and $Choice -ne 'no')
                     question = (Get-PimCommunityConnectQuestion); state = "$(if ($st) { $st.action })"; text = '' }
    if (-not $Community) { $o.text = 'Pro installs are always connected to Invardia (licensed).'; return $o }
    if ($Choice -eq 'yes' -and $HasStoredKey) { $o.text = 'Connected: health reports, the update track and Update now work as for Pro.' }
    elseif ($Choice -eq 'yes') { $o.text = "Connecting: $(if ($st -and "$($st.message)") { "$($st.message)" } else { 'the install key is claimed by the engine within a few minutes.' })" }
    elseif ($Choice -eq 'no' -and $HasStoredKey) { $o.text = 'Not connected: reports are anonymous and Update now is off. The install key claimed earlier is kept but not used; switch on to use it again.' }
    else { $o.text = 'Not connected: reports are anonymous and Update now is off. New versions still arrive with the nightly update.' }
    return $o
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
        # PIM 100.167 (lane G): Invardia's id of this environment, when the claim answer carries one (today it names the
        # handle only) -> 'InvardiaEnvironmentId', the customer alert mail's portal link. Never fails the claim.
        try {
            $eid = "$($r.body.environmentId)".Trim().ToLowerInvariant()
            if ($eid -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { & $SetSetting 'InvardiaEnvironmentId' $eid }
        } catch { }
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
    # COMMUNITY-CLAIM-ON-YES: no Pro licence here -> the Community claim, ONLY when the user said yes (inert otherwise). A
    # route that is not live yet (404) is 'anonymous', asked again on this job's next run -- the claim switches on by itself.
    if (-not $proHere -and $r.action -eq 'none') {
        $iid = ''; if (Get-Command Resolve-PimInvardiaInstallId -ErrorAction SilentlyContinue) { try { $iid = Resolve-PimInvardiaInstallId -GetSetting $get } catch { $iid = '' } }
        $chttp = { param($m, $u, $b, $h) if ($WhatIf) { @{ status = 0; body = $null; error = 'what-if: not sent' } } else { Invoke-PimCommunityConnectHttp -Method $m -Url $u -Body $b -Headers $h } }
        $c = Invoke-PimCommunityInstallKeyClaim -Http $chttp -GetSetting $get -SetSetting $set -TenantId $tid -InstallId $iid -BaseUrl $base -NowUtc $NowUtc
        if ($c.action -ne 'none') { $r = $c }
    }
    [pscustomobject]@{ ran = ($r.action -ne 'none'); whatIf = [bool]$WhatIf; detail = "install-key: $($r.action) -- $($r.message)" }
}

# ---- 2026-10-09 -- THE REPLAY WATERMARK IS PER RING -------------------------------------------------------------------
# MEASURED (2026-10-09 03:00 UTC, two ring-2 environments rolled ahead through ring 1 by the operator's ops script, which
# sets PIM_UPDATE_RING=1 for one run and back to 2): "Invardia: REPLAY refused: sequence 7 is lower than the 24 already
# applied here". Invardia numbers its sequences PER RING (ring 1 was at 24, ring 2 at 7), while this environment kept ONE
# applied value (PIM_UPDATE_INVARDIA_SEQ). After any ring move the home ring's lower sequence was refused as a replay forever.
# So the watermark is kept per ring -- PIM_UPDATE_INVARDIA_SEQ_R<ring> -- and only the CURRENT ring's is read and written.
# Within a ring the replay rule is unchanged.
function Get-PimInvardiaSequenceVariableName {
    <# PURE. The job env variable holding the applied Invardia sequence for one ring ('' when the ring is not 0-3).
       -Kind community: Invardia numbers the Community channel on its OWN counter (per product / kind / ring), so its
       watermark is a separate variable (PIM_UPDATE_INVARDIA_CSEQ_R<n>) -- one shared value would refuse a valid release
       after an install moved between editions. #>
    param([AllowEmptyString()][AllowNull()][string]$Ring, [ValidateSet('code', 'community')][string]$Kind = 'code')
    $n = -1
    if (-not [int]::TryParse("$Ring".Trim(), [ref]$n) -or $n -lt 0 -or $n -gt 3) { return '' }
    if ($Kind -eq 'community') { return "PIM_UPDATE_INVARDIA_CSEQ_R$n" }
    return "PIM_UPDATE_INVARDIA_SEQ_R$n"
}

# ---- COMMUNITY-INCLOUD-UPDATER (owner 2026-10-28: "we must have one way to do this: same for si and pim") -------------
# The Community edition takes its updates the SAME way as Pro -- the in-cloud updater, a signed manifest, the same verifier
# -- from Invardia's Community channel. Contract (Invardia, apps/front/src/updates.ts, 2026-10-28):
#   GET <base>/api/updates/pim-manager/community/<2|3>, ANONYMOUS (no install key, no licence). Rings 2 and 3 only.
#   200 { manifest; manifestB64; signature; keyId; downloadUrl }   204 nothing released yet   404 other rings
#   manifest { product pim-manager; kind community; ring; sequence; version; archive; sha256; size; minFromVersion;
#              manualStep; releasedAt; url } -- the url is the public GitHub release zip (the mirror tree at its root).
# Only the SIGNED bytes (manifestB64) are read; downloadUrl repeats manifest.url.
function Get-PimCommunityChannelRings { <# PURE. LITERAL. The rings Invardia's Community channel serves. #> return @(2, 3) }

function Invoke-PimInvardiaCommunityHttp {
    <# The real seam: one anonymous GET, 30 s, @{ status; body; error }. A non-2xx is a status, never a throw. #>
    param([Parameter(Mandatory)][string]$Url)
    try {
        $r = Invoke-WebRequest -Uri $Url -Method GET -TimeoutSec 30 -UseBasicParsing -ErrorAction Stop
        $b = $null; if ("$($r.Content)".Trim()) { try { $b = "$($r.Content)" | ConvertFrom-Json } catch { $b = $null } }
        return @{ status = [int]$r.StatusCode; body = $b; error = '' }
    } catch {
        $code = 0; try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { $code = 0 }
        return @{ status = $code; body = $null; error = ((("$($_.Exception.Message)") -split "`n")[0]) }
    }
}

function Invoke-PimInvardiaCommunityPull {
    <#
      The Community pull: an anonymous GET of the channel for -Ring (2 or 3). -Http { param($Url) } -> @{ status; body; error }
      (default Invoke-PimInvardiaCommunityHttp). Returns @{ status; body; reason }. Never throws.
    #>
    # -RetryDelaysSec (UPD-RETRY): waits before asking again after no answer / 502-504. Default NONE here (an admin's
    # interactive check answers at once); the update job's step (Get-PimInvardiaCommunityTarget) passes the shipped waits.
    param([scriptblock]$Http, [string]$BaseUrl = '', [Parameter(Mandatory)][int]$Ring, [int[]]$RetryDelaysSec = @())
    if ($Ring -notin (Get-PimCommunityChannelRings)) {
        return @{ status = 0; body = $null; reason = "the Community channel serves rings 2 and 3 only (this environment is on ring $Ring)" }
    }
    $base = if ("$BaseUrl".Trim()) { "$BaseUrl".Trim().TrimEnd('/') } else { $script:PimInvardiaDefaultBase }
    if ($base -notmatch '^(?i)https://') { return @{ status = 0; body = $null; reason = 'the update address is not https' } }
    $url = "$base/api/updates/$($script:PimInvardiaProduct)/community/$Ring"
    $delays = @($RetryDelaysSec | Where-Object { $null -ne $_ })
    $attempt = 0
    while ($true) {
        $r = $null
        try { $r = if ($Http) { & $Http $url } else { Invoke-PimInvardiaCommunityHttp -Url $url } }
        catch { $r = @{ status = 0; body = $null; error = ((("$($_.Exception.Message)") -split "`n")[0]) } }
        if (-not (Test-PimInvardiaPullRetryable -Status ([int]$r.status)) -or $attempt -ge $delays.Count) { break }
        $wait = [Math]::Max(0, [int]$delays[$attempt]); $attempt++
        Write-Verbose "Invardia Community pull: no usable answer (HTTP $([int]$r.status)) -- asking again in $wait s"
        if ($wait -gt 0) { Start-Sleep -Seconds $wait }
    }
    $st = [int]$r.status
    $why = switch ($st) {
        200 { '' }
        204 { 'nothing is released to the Community channel for this ring yet' }
        404 { "Invardia's Community channel does not serve ring $Ring" }
        429 { 'Invardia asked to wait (rate limit) -- the next run asks again' }
        0   { "Invardia could not be reached: $($r.error)" }
        default { "Invardia answered HTTP $st" }
    }
    if ($attempt -gt 0 -and $st -ne 200 -and $st -ne 204) { $why = "$why (asked $($attempt + 1) times)" }
    return @{ status = $st; body = $r.body; reason = $why; attempts = $attempt + 1 }
}

function Test-PimUpdateMajorJump {
    <#
      PURE. Framework PUB-8 ("update clients refuse a major jump"): may this environment move from -RunningVersion to -Target?
      Returns @{ ok; reason }. Refused: a target whose MAJOR is higher than the running one, when the running major is 3 or
      more. Allowed: 2.x -> 3.0 (the owner's renumbering of 2026-10-28 -- no breaking change, and every 2.x install must reach
      3.x), any move inside one major, an unknown running version (a first install has nothing to compare), and -AllowMajor
      (PIM_UPDATE_ALLOW_MAJOR=1: the owner's planned major, set on purpose for one environment).
    #>
    param([AllowEmptyString()][string]$RunningVersion = '', [Parameter(Mandatory)][string]$Target, [switch]$AllowMajor)
    $rm = 0; $tm = 0
    if ("$RunningVersion".Trim() -notmatch '^(\d+)\.') { return @{ ok = $true; reason = 'the running version is not known -- nothing to compare' } }
    $rm = [int]$Matches[1]
    if ("$Target".Trim() -notmatch '^(\d+)\.') { return @{ ok = $false; reason = "the target version '$Target' is not a release version" } }
    $tm = [int]$Matches[1]
    if ($tm -le $rm) { return @{ ok = $true; reason = '' } }
    if ($rm -lt 3) { return @{ ok = $true; reason = "$RunningVersion -> ${Target}: the move from 2.x to 3.x is allowed (PUB-8)" } }
    if ($AllowMajor) { return @{ ok = $true; reason = "$RunningVersion -> ${Target}: a major jump, allowed by PIM_UPDATE_ALLOW_MAJOR=1" } }
    return @{ ok = $false; reason = ("$RunningVersion -> $Target is a MAJOR jump -- refused (framework PUB-8: a new major is a new generation that " +
                                    'can break; only the owner plans it). Nothing moved. To take it on purpose, set PIM_UPDATE_ALLOW_MAJOR=1 on the update job for one run.') }
}

function ConvertTo-PimBuildContextFromCommunityZip {
    <#
      The public GitHub release zip (the mirror tree AT ITS ROOT: VERSION, tools/, engine/ ... -- no top folder, no
      SOLUTIONS/PIM4EntraPS) -> the SAME tar.gz build context the Pro path makes (SOLUTIONS/PIM4EntraPS at its root, which is
      what the Dockerfile's COPY reads). Refuses a zip whose VERSION is not the signed manifest's. @{ ok; path; reason }.
    #>
    param([Parameter(Mandatory)][string]$ZipPath, [Parameter(Mandatory)][string]$OutFile, [Parameter(Mandatory)][string]$Version)
    $work = Join-Path ([IO.Path]::GetTempPath()) ("pim-cinv-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    try {
        $sol = Join-Path $work 'SOLUTIONS/PIM4EntraPS'
        New-Item -ItemType Directory -Force -Path $sol | Out-Null
        Expand-Archive -LiteralPath $ZipPath -DestinationPath $sol -Force
        # a zip with ONE top folder (a GitHub source zip) is taken from inside it
        $vf = Join-Path $sol 'VERSION'
        if (-not (Test-Path -LiteralPath $vf)) {
            $tops = @(Get-ChildItem -LiteralPath $sol -Directory)
            if ($tops.Count -eq 1 -and (Test-Path -LiteralPath (Join-Path $tops[0].FullName 'VERSION'))) {
                $inner = $tops[0].FullName
                Get-ChildItem -LiteralPath $inner -Force | ForEach-Object { Move-Item -LiteralPath $_.FullName -Destination $sol -Force }
                Remove-Item -LiteralPath $inner -Recurse -Force
            }
        }
        if (-not (Test-Path -LiteralPath $vf)) { return @{ ok = $false; path = ''; reason = 'the archive holds no VERSION at its root (not the PIM Manager release tree)' } }
        if (-not (Test-Path -LiteralPath (Join-Path $sol 'tools/pim-manager/Dockerfile'))) { return @{ ok = $false; path = ''; reason = 'the archive holds no tools/pim-manager/Dockerfile' } }
        $inside = "$(Get-Content -Raw -LiteralPath $vf)".Trim()
        if ($inside -ne $Version) { return @{ ok = $false; path = ''; reason = "the archive holds version $inside, the signed manifest says $Version" } }
        # OPEN-26 / BUG-COMMUNITY-ARCHIVE-NO-SIGNIN-FRONT (2026-11-04; owner: "no diff in the core security between pro and
        # community"): the mirror tree carries the sign-in front's source as vendor/signin-front (src + VERSION), never as
        # FRAMEWORK/ -- so the Community context had no front and a Community install could never build signin-front (gp185:
        # "the source archive carries no FRAMEWORK/signin-front/src"). Place that copy where the front step reads it, exactly as
        # the Pro context carries it; the Manager build never sees it (.dockerignore / the Dockerfile COPY read the solution).
        $items = @('SOLUTIONS')
        $vsf = Join-Path $sol 'vendor/signin-front'
        if ((Test-Path -LiteralPath (Join-Path $vsf 'src/Dockerfile')) -and (Test-Path -LiteralPath (Join-Path $vsf 'VERSION'))) {
            $fw = Join-Path $work 'FRAMEWORK/signin-front'
            New-Item -ItemType Directory -Force -Path $fw | Out-Null
            Copy-Item -LiteralPath (Join-Path $vsf 'src') -Destination $fw -Recurse -Force
            Copy-Item -LiteralPath (Join-Path $vsf 'VERSION') -Destination $fw -Force
            $items += 'FRAMEWORK'
        }
        Push-Location -LiteralPath $work
        try {
            # A RELATIVE output name, then a move: GNU tar reads 'C:' in an absolute Windows path as a remote host.
            & tar -czf 'context.tar.gz' @items
            if ($LASTEXITCODE -ne 0) { return @{ ok = $false; path = ''; reason = "tar failed (exit $LASTEXITCODE)" } }
        } finally { Pop-Location }
        Move-Item -LiteralPath (Join-Path $work 'context.tar.gz') -Destination $OutFile -Force
        return @{ ok = $true; path = $OutFile; reason = '' }
    } catch { return @{ ok = $false; path = ''; reason = "the archive could not be unpacked: $($_.Exception.Message)" } }
    finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

function Get-PimInvardiaCommunityTarget {
    <#
      The update job's whole COMMUNITY step, seams injected: pull (anonymous), verify (the SAME verifier and keys as Pro, kind
      community, this ring), and -- when a build is needed -- download, size + SHA-256 check, re-pack. Returns the SAME shape
      as Get-PimInvardiaUpdateTarget (@{ ok; version; sequence; hold; reason; contextPath; ahead; attention; noKey; wave;
      manifestVersion; served }), so the job handles both editions with one path. No install key and no licence: never noKey.
    #>
    param([scriptblock]$Http, [string]$BaseUrl = '', [int]$AppliedSequence = 0, [string]$RunningVersion = '', [string]$LastBuiltVersion = '',
          [object[]]$TrustedKeys = $script:PimInvardiaUpdateTrustedKeys, [scriptblock]$Download, [string]$WorkDir = ([IO.Path]::GetTempPath()),
          [string]$Ring = '', [string]$HighestKnownVersion = '', [switch]$AllowDowngrade, [switch]$AllowMajor,
          [int[]]$RetryDelaysSec = $script:PimInvardiaPullRetryDelaysSec)
    $res = @{ ok = $false; version = ''; sequence = 0; hold = $false; reason = ''; contextPath = ''; ahead = $false; attention = $false; noKey = $false
              wave = ''; manifestVersion = ''; served = $false }
    $ringN = -1
    if (-not [int]::TryParse("$Ring".Trim(), [ref]$ringN) -or $ringN -notin (Get-PimCommunityChannelRings)) {
        $res.reason = "this Community environment has no Community ring (PIM_UPDATE_RING = '$Ring', expected 2 or 3) -- nothing is pulled"; return $res
    }
    $p = Invoke-PimInvardiaCommunityPull -Http $Http -BaseUrl $BaseUrl -Ring $ringN -RetryDelaysSec $RetryDelaysSec
    if ($p.status -eq 204) { $res.ok = $true; $res.served = $true; $res.reason = $p.reason; return $res }
    if ($p.status -ne 200) { $res.reason = $p.reason; return $res }
    $v = Test-PimInvardiaManifest -Response $p.body -TrustedKeys $TrustedKeys -Kind 'community' -AppliedSequence $AppliedSequence -RunningVersion $RunningVersion -Ring $ringN
    if (-not $v.ok) { $res.reason = $v.reason; return $res }
    $res.served = $true; $res.manifestVersion = "$($v.version)"; $res.sequence = $v.sequence; $res.reason = $v.reason
    if ($v.hold) { $res.ok = $true; $res.hold = $true; return $res }
    $mj = Test-PimUpdateMajorJump -RunningVersion "$(if ("$RunningVersion".Trim()) { $RunningVersion } else { $HighestKnownVersion })" -Target $v.version -AllowMajor:$AllowMajor
    if (-not $mj.ok) { $res.attention = $true; $res.reason = "$($v.reason) -- $($mj.reason)"; return $res }
    $res.version = $v.version
    $signedRollback = ($AppliedSequence -gt 0 -and $v.sequence -gt $AppliedSequence)
    if ("$HighestKnownVersion".Trim() -and (Compare-PimReleaseVersion $v.version "$HighestKnownVersion".Trim()) -lt 0 -and -not $signedRollback -and -not $AllowDowngrade) {
        $res.ok = $true; $res.ahead = $true
        $res.reason = "$($v.reason) -- this environment already runs $("$HighestKnownVersion".Trim()), newer than the Community ring approves: nothing to fetch"
        return $res
    }
    if ("$LastBuiltVersion".Trim() -eq $v.version) { $res.ok = $true; $res.reason = "$($v.reason) -- already built here"; return $res }
    $zip = Join-Path $WorkDir ("$($script:PimInvardiaProduct)-community-$($v.version).zip")
    $ctx = Join-Path $WorkDir ("pim-src-$($v.version).tar.gz")
    try {
        $d = if ($Download) { & $Download $v.downloadUrl $zip $v.sha256 $v.size } else { Save-PimInvardiaArchive -Url $v.downloadUrl -OutFile $zip -ExpectedSha256 $v.sha256 -ExpectedSize $v.size }
        if (-not $d.ok) { $res.version = ''; $res.reason = "archive refused: $($d.reason)"; return $res }
        $c = ConvertTo-PimBuildContextFromCommunityZip -ZipPath $zip -OutFile $ctx -Version $v.version
        if (-not $c.ok) { $res.version = ''; $res.reason = "archive refused: $($c.reason)"; return $res }
        $res.ok = $true; $res.contextPath = $ctx
        return $res
    } finally { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
}

function Get-PimHybridWorkerUpdateTarget {
    <#
      SEC-95 (SECAUDIT-1, 2026-11-01): the hybrid worker's daily update through the SAME signed path as the cloud updater.
      The worker used to take channel.json + pim-src-<v>.tar.gz from a blob container with no signature at all -- one blob
      write reached a Tier 0 machine that writes AD. Now: the install's own licence + install key (pim.Settings, which the
      worker identity may read), the signed manifest for the worker's ring, verified by the keys EMBEDDED in the code already
      installed on the machine, then the archive's SHA-256 / size, then the re-pack with its VERSION check
      (Get-PimInvardiaUpdateTarget does all of it). Seams: -GetSetting { param($name) }, -Http, -Download.
      -State: the worker's own watermark @{ ring; sequence } (bin\update-state.json) -- a sequence recorded for another ring
      does not guard this one. Returns Get-PimInvardiaUpdateTarget's answer: version '' = nothing moves.
    #>
    param([Parameter(Mandatory)][scriptblock]$GetSetting, [Parameter(Mandatory)][scriptblock]$Http, [Parameter(Mandatory)][string]$Ring,
          [AllowNull()][object]$State, [AllowEmptyString()][string]$RunningVersion = '', [scriptblock]$Download,
          [string]$WorkDir = ([IO.Path]::GetTempPath()), [object[]]$TrustedKeys = $script:PimInvardiaUpdateTrustedKeys, [switch]$AllowMajor)
    $read = { param($n) try { & $GetSetting $n } catch { $null } }
    $lic = ConvertTo-PimInvardiaLicenceText -Value (& $read 'License')
    $key = Resolve-PimInvardiaInstallKey -GetSetting $GetSetting
    # INV-S16: the SAME install's lasting id, READ from the store (the worker never creates one); unreadable / none = no header
    $iid = ''; if (Get-Command Resolve-PimInvardiaInstallId -ErrorAction SilentlyContinue) { $iid = Resolve-PimInvardiaInstallId -GetSetting $GetSetting }
    $base = "$(& $read 'LicenceRequestBaseUrl')".Trim()
    $applied = 0
    if ($State -and "$($State.ring)".Trim() -eq "$Ring".Trim()) { [void][int]::TryParse("$($State.sequence)", [ref]$applied) }
    $run = "$RunningVersion".Trim()
    $a = @{ Http = $Http; InstallKey = $key; InstallId = $iid; LicenceText = $lic; BaseUrl = $base; AppliedSequence = $applied; RunningVersion = $run
            LastBuiltVersion = $run; HighestKnownVersion = $run; Ring = "$Ring".Trim(); TrustedKeys = $TrustedKeys; WorkDir = $WorkDir; AllowMajor = $AllowMajor }
    if ($Download) { $a['Download'] = $Download }
    return (Get-PimInvardiaUpdateTarget @a)
}

function Resolve-PimInvardiaAppliedSequence {
    <#
      PURE. Which applied sequence guards THIS ring's pull. -JobEnv is the update job's environment (any IDictionary, or
      $env-like object read by name). Returns @{ applied; unprovenLegacy; source; variable; reason }:
        source 'ring'               PIM_UPDATE_INVARDIA_SEQ_R<ring> -- the per-ring watermark (strict replay check)
               'legacy-same-ring'   the legacy single value, recorded with PIM_UPDATE_INVARDIA_SEQ_RING = this ring
               'legacy-other-ring'  the legacy value belongs to ANOTHER ring (evidence: _SEQ_RING) -> no watermark here yet
               'legacy-unproven'    a legacy value with NO ring recorded beside it -> applied 0, unprovenLegacy = that value:
                                    the caller refuses a lower manifest sequence as NEEDS ATTENTION (it cannot tell a ring
                                    move from a replay), and accepts an equal or higher one (that is the old rule anyway)
               'none'               nothing recorded
      🔒 Never guesses a ring for a legacy value: without evidence, a lower sequence still does not pass.
    #>
    # Not named $Env: that is the environment-variable drive, and shadowing it is a trap for the next editor.
    param([AllowNull()][object]$JobEnv, [AllowEmptyString()][AllowNull()][string]$Ring, [ValidateSet('code', 'community')][string]$Kind = 'code')
    $get = { param($n)
        if ($null -eq $JobEnv) { return '' }
        if ($JobEnv -is [System.Collections.IDictionary]) { if ($JobEnv.Contains($n)) { return "$($JobEnv[$n])".Trim() }; return '' }
        $p = $JobEnv.PSObject.Properties[$n]; if ($p) { return "$($p.Value)".Trim() }; return '' }
    $res = @{ applied = 0; unprovenLegacy = 0; source = 'none'; variable = (Get-PimInvardiaSequenceVariableName -Ring $Ring -Kind $Kind); reason = '' }
    $ringN = -1; [void][int]::TryParse("$Ring".Trim(), [ref]$ringN)
    $x = 0
    if ($res.variable -and [int]::TryParse((& $get $res.variable), [ref]$x) -and $x -ge 0) {
        $res.applied = $x; $res.source = 'ring'; $res.reason = "applied sequence for ring $ringN`: $x ($($res.variable))"; return $res
    }
    # The Community channel has its own counter and no legacy single value (it started with the per-ring variables).
    if ($Kind -eq 'community') { $res.reason = "no applied Community sequence recorded for ring $ringN yet"; return $res }
    $legacy = 0
    if (-not ([int]::TryParse((& $get 'PIM_UPDATE_INVARDIA_SEQ'), [ref]$legacy) -and $legacy -gt 0)) { $res.reason = "no applied sequence recorded for ring $ringN yet"; return $res }
    $lr = -1
    if ([int]::TryParse((& $get 'PIM_UPDATE_INVARDIA_SEQ_RING'), [ref]$lr)) {
        if ($lr -eq $ringN) { $res.applied = $legacy; $res.source = 'legacy-same-ring'; $res.reason = "applied sequence $legacy (PIM_UPDATE_INVARDIA_SEQ, recorded for ring $lr)"; return $res }
        $res.source = 'legacy-other-ring'
        $res.reason = "ring changed: the recorded sequence $legacy belongs to ring $lr, so ring $ringN has no applied sequence yet"
        return $res
    }
    $res.unprovenLegacy = $legacy; $res.source = 'legacy-unproven'
    $res.reason = "applied sequence $legacy (PIM_UPDATE_INVARDIA_SEQ, recorded before watermarks were kept per ring -- its ring is not recorded)"
    return $res
}

# ---- 100.69 -- AN UPDATE RUN BEFORE THE INSTALL KEY IS CLAIMED IS WAITING, NOT FAILED ----------------------------------
# MEASURED (a trial environment, 2026-10-11): an updater run started ~5 minutes after install, before the tick's install-key job
# claimed the key, exited 1 with "this install has no install key" -> execution Failed, UpdateState 'failed', failure
# telemetry. Nothing was wrong: the key is claimed by the engine within ~5 minutes of install, and the next run updated.
# So: no key YET = 'waiting' (exit 0, no failure telemetry). No key a day after install, or a claim Invardia REFUSED, is a
# real problem -- reported as 'attention' (a warning naming Settings > Licence), still never a failed run.
$script:PimInvardiaNoKeyGraceHours = 24

function Get-PimInvardiaNoKeyOutcome {
    <#
      PURE. What an Invardia update run with NO install key records. Returns @{ outcome = waiting|attention; reason;
      waitingSinceUtc; ageHours }.
        -InstalledUtc     when this environment was installed (the Manager app's systemData.createdAt); may be '' / unreadable
        -PreviousState    the UpdateState record this run replaces: its waitingSinceUtc (an earlier waiting run) and a
                          deployment record's recordedUtc count as "installed no later than"
        -ClaimState       pim.Settings 'InstallKeyClaimState' (Invoke-PimInstallKeyClaimCycle): a 'refused' claim is
                          never "not yet" -- it is a warning at once
      The EARLIEST readable time wins; none readable = now (a first run cannot prove it has waited a day).
    #>
    param([AllowNull()][object]$InstalledUtc, [AllowNull()][object]$PreviousState, [AllowNull()][object]$ClaimState,
          [datetime]$NowUtc = [datetime]::UtcNow, [double]$GraceHours = $script:PimInvardiaNoKeyGraceHours)
    $now = $NowUtc.ToUniversalTime()
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    $field = { param($o, $k)
        if ($null -eq $o) { return '' }
        if ($o -is [string]) { try { $o = $o | ConvertFrom-Json -ErrorAction Stop } catch { return '' } }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($k)) { return "$($o[$k])".Trim() }; return '' }
        $p = $o.PSObject.Properties[$k]; if ($p) { return "$($p.Value)".Trim() }; return '' }
    $cands = New-Object System.Collections.Generic.List[datetime]
    $add = { param($v)
        if ($null -eq $v) { return }
        if ($v -is [datetime]) { $cands.Add(([datetime]$v).ToUniversalTime()); return }
        $d = [datetime]::MinValue
        if ("$v".Trim() -and [datetime]::TryParse("$v".Trim(), [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { $cands.Add($d) } }
    & $add $InstalledUtc
    & $add (& $field $PreviousState 'waitingSinceUtc')
    if ((& $field $PreviousState 'kind') -ieq 'deploy') { & $add (& $field $PreviousState 'recordedUtc') }
    $since = $now
    foreach ($c in $cands) { if ($c -lt $since) { $since = $c } }
    $age = [math]::Round([math]::Max(0, ($now - $since).TotalHours), 1)
    $res = @{ outcome = 'waiting'; reason = ''; waitingSinceUtc = $since.ToString('o'); ageHours = $age }
    $claimAction = & $field $ClaimState 'action'
    $claimMsg    = & $field $ClaimState 'message'
    if ($claimAction -eq 'refused') {
        $res.outcome = 'attention'
        $res.reason  = "no install key: Invardia refused the claim ($claimMsg). Nothing moved, PIM keeps running its current version. " +
                       'What to do: open Settings > Licence -- the install key status there says why and offers "Claim again" once it is fixed.'
        return $res
    }
    if ($age -ge $GraceHours) {
        $claimTxt = if ($claimAction) { " The last claim attempt: $claimAction -- $claimMsg." } else { ' No claim attempt is recorded yet (the install-key job needs the Pro licence for this tenant and the updates.invardia feature).' }
        $res.outcome = 'attention'
        $res.reason  = ("this install still has no install key $([int][math]::Floor($age)) h after it was installed (the engine normally claims it within about 5 minutes). " +
                        "Nothing moved, PIM keeps running its current version.$claimTxt What to do: open Settings > Licence and check the install key status and that the Pro licence for this tenant is installed.")
        return $res
    }
    $res.reason = 'waiting for the install key (the engine claims it within about 5 minutes of install) -- the next scheduled update run proceeds once it is claimed'
    return $res
}

function Get-PimInvardiaUpdateTarget {
    <#
      The update job's whole Invardia step, seams injected: pull, verify, and (when a build is needed) download + re-pack.
      Returns @{ ok; version; sequence; hold; reason; contextPath }:
        ok=$true + version ''        nothing released / nothing new           -> the job reports 'none'
        ok=$true + hold              verified but held (manual step, minFrom)  -> the job reports 'none' with the reason
        ok=$true + version           the approved version; contextPath set when -NeedBuild (the tar.gz to build)
        ok=$false                    refused or failed                          -> the job reports 'failed', nothing moves
        ok=$false + attention        the replay watermark's ring is unknown     -> the job reports 'attention', nothing moves
        ok=$false + noKey            no install key (yet)                       -> Get-PimInvardiaNoKeyOutcome: 'waiting' / 'attention', exit 0
        ok=$true + ahead             the ring approves an OLDER version         -> the job reports 'ahead', exit 0, nothing fetched
    #>
    param([Parameter(Mandatory)][scriptblock]$Http, [AllowEmptyString()][string]$InstallKey = '', [AllowEmptyString()][string]$LicenceText = '',
          [string]$BaseUrl = '', [int]$AppliedSequence = 0, [string]$RunningVersion = '', [string]$LastBuiltVersion = '',
          [object[]]$TrustedKeys = $script:PimInvardiaUpdateTrustedKeys, [scriptblock]$Download, [string]$WorkDir = ([IO.Path]::GetTempPath()),
          # UPDATE-1.7: the environment's OWN ring (PIM_UPDATE_RING), sent with the pull; the manifest must be for it.
          [string]$Ring = '',
          # 2026-10-09: a legacy applied sequence whose ring is NOT recorded (Resolve-PimInvardiaAppliedSequence
          # 'legacy-unproven'). A manifest sequence below it is refused as NEEDS ATTENTION, never accepted on a guess.
          [int]$UnprovenLegacySequence = 0,
          # 2026-10-09: the highest version this environment is known to have reached (running / last built / last good).
          # A manifest naming an OLDER version that is not a signed rollback is AHEAD: nothing is downloaded.
          [string]$HighestKnownVersion = '',
          [switch]$AllowDowngrade,
          # PUB-8: PIM_UPDATE_ALLOW_MAJOR=1 -- the owner's planned major, for one run.
          [switch]$AllowMajor,
          # INV-S16: the install's lasting id -> X-Invardia-Install-Id on the pull; '' = no header.
          [AllowEmptyString()][AllowNull()][string]$InstallId = '')
    # PIM 100.158 / framework 12.11e CR3: wave = the wave name from the SIGNED manifest ('' = served outside any wave);
    # manifestVersion = the version that signed manifest names (also on a hold / ahead / already-built answer). served = a
    # manifest (or a 204 "nothing released") was VERIFIED this run -- only then is the wave recorded.
    $res = @{ ok = $false; version = ''; sequence = 0; hold = $false; reason = ''; contextPath = ''; ahead = $false; attention = $false; noKey = $false
              wave = ''; manifestVersion = ''; served = $false }
    # 100.69: noKey tells the job this is the "not claimed YET" case (Get-PimInvardiaNoKeyOutcome decides waiting / warning),
    # never a failed run. Nothing is sent to Invardia without a key.
    if (-not "$InstallKey".Trim()) { $res.noKey = $true; $res.reason = 'this install has no install key (PIM_UPLINK_KEY, or claimed by the install-key job)'; return $res }
    if (-not "$LicenceText".Trim()) { $res.reason = 'no licence is installed -- Pro updates need the Invardia-issued Pro licence'; return $res }
    $ringN = -1
    if (-not [int]::TryParse("$Ring".Trim(), [ref]$ringN) -or $ringN -lt 0 -or $ringN -gt 3) {
        $res.reason = "this environment has no update ring (PIM_UPDATE_RING = '$Ring', expected 0-3) -- PIM decides the ring, so a Pro pull without one is not made"; return $res
    }
    $p = Invoke-PimInvardiaManifestPull -Http $Http -BaseUrl $BaseUrl -InstallKey $InstallKey -LicenceText $LicenceText -Ring $ringN -InstallId $InstallId
    if ($p.status -eq 204) { $res.ok = $true; $res.served = $true; $res.reason = $p.reason; return $res }
    if ($p.status -ne 200) { $res.reason = $p.reason; return $res }
    $v = Test-PimInvardiaManifest -Response $p.body -TrustedKeys $TrustedKeys -AppliedSequence $AppliedSequence -RunningVersion $RunningVersion -Ring $ringN
    if (-not $v.ok) { $res.reason = $v.reason; return $res }
    $res.served = $true; $res.manifestVersion = "$($v.version)"
    if ($v.manifest -and $v.manifest.PSObject.Properties['wave'] -and "$($v.manifest.wave)".Trim()) { $res.wave = "$($v.manifest.wave)".Trim() }
    if ($UnprovenLegacySequence -gt 0 -and $v.sequence -lt $UnprovenLegacySequence) {
        # 🔒 Not a guess either way: the legacy value may be another ring's (a ring move -- harmless) or this ring's (a
        # replay -- refused). Without the ring recorded beside it nothing moves, and the operator is told the one fix.
        $res.attention = $true; $res.sequence = $v.sequence
        $rn = "$Ring".Trim()
        $res.reason = ("replay check needs a decision: ring $rn is at sequence $($v.sequence), but this environment last applied sequence " +
                       "$UnprovenLegacySequence (PIM_UPDATE_INVARDIA_SEQ), recorded before watermarks were kept per ring, so a ring move " +
                       "cannot be told from a replay. Nothing moved. Fix: if this environment was moved between rings, set " +
                       "PIM_UPDATE_INVARDIA_SEQ_RING=<the ring that sequence came from> on the update job; to accept ring $rn's current " +
                       "release, set PIM_UPDATE_INVARDIA_SEQ_R$rn=$($v.sequence) on the update job.")
        return $res
    }
    $res.sequence = $v.sequence; $res.reason = $v.reason
    if ($v.hold) { $res.ok = $true; $res.hold = $true; return $res }
    # Framework PUB-8: a major jump (from 3.x on) is refused for Pro too -- 'attention', nothing moves.
    $mj = Test-PimUpdateMajorJump -RunningVersion "$(if ("$RunningVersion".Trim()) { $RunningVersion } else { $HighestKnownVersion })" -Target $v.version -AllowMajor:$AllowMajor
    if (-not $mj.ok) { $res.attention = $true; $res.reason = "$($v.reason) -- $($mj.reason)"; return $res }
    $res.version = $v.version
    # 2026-10-09 (BUG-162 kept): an environment rolled AHEAD of its ring is not moved back and nothing is fetched for it.
    # Only a SIGNED ROLLBACK (a higher sequence than this ring's applied one, which must exist) or the operator's
    # PIM_UPDATE_ALLOW_DOWNGRADE may go down -- the same rule the update job applies after this.
    $signedRollback = ($AppliedSequence -gt 0 -and $v.sequence -gt $AppliedSequence)
    if ("$HighestKnownVersion".Trim() -and (Compare-PimReleaseVersion $v.version "$HighestKnownVersion".Trim()) -lt 0 -and -not $signedRollback -and -not $AllowDowngrade) {
        $res.ok = $true; $res.ahead = $true
        $res.reason = "$($v.reason) -- this environment already runs $("$HighestKnownVersion".Trim()), newer than the ring approves: nothing to fetch"
        return $res
    }
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
