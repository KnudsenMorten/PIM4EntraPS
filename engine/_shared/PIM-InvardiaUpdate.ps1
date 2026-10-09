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
    param([Parameter(Mandatory)][scriptblock]$Http, [string]$BaseUrl = '', [Parameter(Mandatory)][string]$InstallKey, [Parameter(Mandatory)][string]$LicenceText, [string]$Kind = 'code',
          [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring)
    $p = Invoke-InvardiaManifestPull -Product $script:PimInvardiaProduct -Http $Http -BaseUrl $BaseUrl -InstallKey $InstallKey -LicenceText $LicenceText -Kind $Kind -Ring $Ring
    if ($p.status -eq 401) { $p.reason = Get-PimInvardiaPullReason -Status 401 -Body $p.body }
    $p
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

# ---- 2026-10-09 -- THE REPLAY WATERMARK IS PER RING -------------------------------------------------------------------
# MEASURED (2026-10-09 03:00 UTC, two ring-2 environments rolled ahead through ring 1 by the operator's ops script, which
# sets PIM_UPDATE_RING=1 for one run and back to 2): "Invardia: REPLAY refused: sequence 7 is lower than the 24 already
# applied here". Invardia numbers its sequences PER RING (ring 1 was at 24, ring 2 at 7), while this environment kept ONE
# applied value (PIM_UPDATE_INVARDIA_SEQ). After any ring move the home ring's lower sequence was refused as a replay forever.
# So the watermark is kept per ring -- PIM_UPDATE_INVARDIA_SEQ_R<ring> -- and only the CURRENT ring's is read and written.
# Within a ring the replay rule is unchanged.
function Get-PimInvardiaSequenceVariableName {
    <# PURE. The job env variable holding the applied Invardia sequence for one ring ('' when the ring is not 0-3). #>
    param([AllowEmptyString()][AllowNull()][string]$Ring)
    $n = -1
    if (-not [int]::TryParse("$Ring".Trim(), [ref]$n) -or $n -lt 0 -or $n -gt 3) { return '' }
    return "PIM_UPDATE_INVARDIA_SEQ_R$n"
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
    param([AllowNull()][object]$JobEnv, [AllowEmptyString()][AllowNull()][string]$Ring)
    $get = { param($n)
        if ($null -eq $JobEnv) { return '' }
        if ($JobEnv -is [System.Collections.IDictionary]) { if ($JobEnv.Contains($n)) { return "$($JobEnv[$n])".Trim() }; return '' }
        $p = $JobEnv.PSObject.Properties[$n]; if ($p) { return "$($p.Value)".Trim() }; return '' }
    $res = @{ applied = 0; unprovenLegacy = 0; source = 'none'; variable = (Get-PimInvardiaSequenceVariableName -Ring $Ring); reason = '' }
    $ringN = -1; [void][int]::TryParse("$Ring".Trim(), [ref]$ringN)
    $x = 0
    if ($res.variable -and [int]::TryParse((& $get $res.variable), [ref]$x) -and $x -ge 0) {
        $res.applied = $x; $res.source = 'ring'; $res.reason = "applied sequence for ring $ringN`: $x ($($res.variable))"; return $res
    }
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

function Get-PimInvardiaUpdateTarget {
    <#
      The update job's whole Invardia step, seams injected: pull, verify, and (when a build is needed) download + re-pack.
      Returns @{ ok; version; sequence; hold; reason; contextPath }:
        ok=$true + version ''        nothing released / nothing new           -> the job reports 'none'
        ok=$true + hold              verified but held (manual step, minFrom)  -> the job reports 'none' with the reason
        ok=$true + version           the approved version; contextPath set when -NeedBuild (the tar.gz to build)
        ok=$false                    refused or failed                          -> the job reports 'failed', nothing moves
        ok=$false + attention        the replay watermark's ring is unknown     -> the job reports 'attention', nothing moves
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
          [switch]$AllowDowngrade)
    $res = @{ ok = $false; version = ''; sequence = 0; hold = $false; reason = ''; contextPath = ''; ahead = $false; attention = $false }
    if (-not "$InstallKey".Trim()) { $res.reason = 'this install has no install key (PIM_UPLINK_KEY, or claimed by the install-key job)'; return $res }
    if (-not "$LicenceText".Trim()) { $res.reason = 'no licence is installed -- Pro updates need the Invardia-issued Pro licence'; return $res }
    $ringN = -1
    if (-not [int]::TryParse("$Ring".Trim(), [ref]$ringN) -or $ringN -lt 0 -or $ringN -gt 3) {
        $res.reason = "this environment has no update ring (PIM_UPDATE_RING = '$Ring', expected 0-3) -- PIM decides the ring, so a Pro pull without one is not made"; return $res
    }
    $p = Invoke-PimInvardiaManifestPull -Http $Http -BaseUrl $BaseUrl -InstallKey $InstallKey -LicenceText $LicenceText -Ring $ringN
    if ($p.status -eq 204) { $res.ok = $true; $res.reason = $p.reason; return $res }
    if ($p.status -ne 200) { $res.reason = $p.reason; return $res }
    $v = Test-PimInvardiaManifest -Response $p.body -TrustedKeys $TrustedKeys -AppliedSequence $AppliedSequence -RunningVersion $RunningVersion -Ring $ringN
    if (-not $v.ok) { $res.reason = $v.reason; return $res }
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
