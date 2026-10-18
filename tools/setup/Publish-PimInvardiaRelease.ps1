#Requires -Version 5.1
<#
.SYNOPSIS
  Publish a PIM release to Invardia's Pro update platform as PIM's OWN publisher identity (Invardia DESIGN §10; framework
  UPDATE-1: Pro installs take their updates from Invardia, verified against the Invardia update-signing key).

.DESCRIPTION
  1. The release zip, from the TAGGED commit (never the working tree): `git archive --format=zip
     --prefix=pim-manager-src-<v>/ <tag> -- .dockerignore SOLUTIONS/PIM4EntraPS` -- the exact shape the updater re-packs
     (ConvertTo-PimBuildContextFromZip: top folder pim-manager-src-<v>/, repo-root shaped inside).
  2. Checks before anything leaves this machine: the tag exists, VERSION inside the zip IS the version, the top folder,
     the zip magic; its SHA-256 and size are printed.
  3. With -Apply only: sign in as the publisher app (client credentials, CERTIFICATE -- never a secret) for the Invardia
     Back Office audience, and POST https://invardia.com/api/releases/pim-manager?kind=code&version=<v> with the zip as
     the body. The app holds only the role Invardia.Publisher.pim-manager: it can publish pim-manager releases, nothing
     else. Framework UPDATE-1.7 (operator 2026-10-06: "Solution (si, pim) decides WHAT version and WHICH Ring to release
     in updates, Invardia relays only"): -Ring <0-3> publishes AND releases to that ring in one call (&ring=N); without
     -Ring the version is only registered. Ring 2 / 3 reach customers, so they need -OperatorApproval carrying the
     operator's own words ("release <version> to ring 2"), printed in the plan and the result.
  Without -Apply it is a plan: the zip is built and checked, nothing is sent.

  Identity: client id + certificate thumbprint from -KeyVault (invardia-publisher-clientid-pim-manager /
  invardia-publisher-thumbprint-pim-manager) unless passed; the certificate (key not exportable) is in
  Cert:\LocalMachine\My on the publishing machine.

.EXAMPLE
  .\tools\setup\Publish-PimInvardiaRelease.ps1 -Version 2.4.496 -TenantId <tenant of the publisher app>          # plan
  .\tools\setup\Publish-PimInvardiaRelease.ps1 -Version 2.4.496 -TenantId <tenant of the publisher app> -Apply   # publish
#>
[CmdletBinding()]
param(
    [string]$Version = '',
    [Parameter(Mandatory)][string]$TenantId,
    [string]$ClientId = '',
    [string]$CertThumbprint = '',
    [string]$KeyVault = '',
    [string]$KeyVaultSubscription = '',
    [string]$Endpoint = 'https://invardia.com',
    [string]$Audience = 'api://a5a57537-c847-482b-8878-9a229cbca61b',
    [ValidateSet('code')][string]$Kind = 'code',
    [string]$OutDir = '',
    [ValidateRange(-1, 3)][int]$Ring = -1,
    [string]$OperatorApproval = '',
    # 2026-10-07: RELEASE an already-published version to -Ring (POST /api/releases/pim-manager/<kind>/rings/<ring> {version}).
    # Versions are immutable: publishing one twice answers 409 versionExists -- promoting it to another ring is this call.
    [switch]$Promote,
    [switch]$Apply,
    # PIM 100.158 CR3: where the "Invardia refused changedScopes" mark is kept for 24 h (default: the temp folder of this machine)
    [string]$StateDir = '',
    # REQUIREMENTS 33.0 RELEASE CONTEXT (owner 2026-10-16): the fix list for the owner's approval mail, the FALLBACK of
    # Publish-PimInvardiaReleaseNotes.ps1 -- one point per entry, sent as the header X-Release-Notes on the PUBLISH call
    # only (never the ring / promote call): [uri]::EscapeDataString of the points joined with a line feed (%0A between
    # points), at most 8000 characters raw, never refused by Invardia. Not given = no header (no behaviour change).
    # PIM_PUBLISH_RELEASENOTES = 0 / off / false / no turns the header off without a release (framework 12.22 3(b)).
    [string[]]$ReleaseNotes = @()
)
$ErrorActionPreference = 'Stop'
function Step([string]$m) { Write-Host "==> $m" -ForegroundColor Cyan }
# PIM 100.158 / framework 12.11e CR3 -- changedScopes on the publish call (&changedScopes=a,b | *) and the ring call
# ("changedScopes": [..] | ["*"]), from the files this release changed since the previous release tag (PIM-ReleaseControl.ps1
# maps files to scopes). Switch PIM_PUBLISH_CHANGEDSCOPES: ON for every ring by default since Invardia confirmed the field
# (2026-10-16, 1.0.480); off / 0 / false / no = off (it was AUTO = ring 0 only until then). Invardia refusing the FIELD (400 / 422 naming it) -> the call goes ONCE more without it, and the
# field is held for 24 h (a mark file). A 409 notApproved is never that: it is shown plainly and never retried.
. (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'engine\_shared\PIM-ReleaseControl.ps1')
if (-not "$StateDir".Trim()) { $StateDir = Join-Path ([IO.Path]::GetTempPath()) 'pim-invardia-release' }
$scopesMark = Join-Path $StateDir 'changedscopes-refused.json'
function Get-PimScopesMark { param([string]$Path) try { if (Test-Path -LiteralPath $Path) { return ((Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json).refusedUtc) } } catch { }; return $null }
function Set-PimScopesMark { param([string]$Path) try { New-Item -ItemType Directory -Force -Path (Split-Path $Path -Parent) | Out-Null; @{ refusedUtc = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress | Set-Content -LiteralPath $Path -Encoding ascii } catch { } }
function Get-PimPreviousReleaseTag {
    # The highest PIM4EntraPS-v<x> tag below -Version ('' when none).
    param([string]$RepoRoot, [string]$Version)
    $p = @(& git -C $RepoRoot tag -l 'PIM4EntraPS-v2.*' 2>$null | ForEach-Object { $v = "$_" -replace '^PIM4EntraPS-v', ''; try { [pscustomobject]@{ tag = "$_"; v = [version]$v } } catch { } } |
           Where-Object { $_.v -lt [version]$Version } | Sort-Object v -Descending | Select-Object -First 1)
    if ($p.Count) { return "$($p[0].tag)" }
    return ''
}
function Get-PimReleaseScopes {
    # changedScopes for <tag> against the previous release tag. No previous tag, or a diff that cannot be read = @('*').
    param([string]$RepoRoot, [string]$Tag, [string]$PrevTag)
    if (-not "$PrevTag".Trim()) { return @('*') }
    $files = @(& git -C $RepoRoot diff --name-only "$PrevTag" "$Tag" -- 'SOLUTIONS/PIM4EntraPS' 2>$null)
    if ($LASTEXITCODE -ne 0) { return @('*') }
    return @(Get-PimChangedScopes -Files $files)
}
function Invoke-PimInvardiaCall {
    # One HTTP call, PS 5.1 + 7: a non-2xx answer is read from the exception's response. @{ status; content }.
    # -ExtraHeaders: more request headers (the publish call's X-Release-Notes); Authorization is never replaced by them.
    param([string]$Method, [string]$Url, [string]$Token, $Body, [string]$ContentType, [int]$TimeoutSec = 120, [hashtable]$ExtraHeaders = @{})
    try {
        $h = @{ Authorization = "Bearer $Token" }
        if ($ExtraHeaders) { foreach ($k in @($ExtraHeaders.Keys)) { if ("$k" -ne 'Authorization') { $h["$k"] = "$($ExtraHeaders[$k])" } } }
        $r = Invoke-WebRequest -Method $Method -Uri $Url -Headers $h -Body $Body -ContentType $ContentType -TimeoutSec $TimeoutSec -UseBasicParsing
        return @{ status = [int]$r.StatusCode; content = "$($r.Content)" }
    } catch {
        $resp = $_.Exception.Response
        if (-not $resp) { throw "the request failed: $($_.Exception.Message)" }
        $c = "$($_.ErrorDetails.Message)"; if (-not $c) { $c = "$($_.Exception.Message)" }
        return @{ status = [int]$resp.StatusCode; content = $c }
    }
}

# Framework §12.22 WRITE-CALLS 3(c) (owner approved 2026-10-14, PIM 100.154): a 5xx on a call that CHANGES something is
# "unknown", never "failed" and never "done" -- the state is READ BACK first:
#   GET <endpoint>/api/releases/pim-manager/state?kind=<kind>&version=<v>  (the publisher identity)
#   -> { version: { version, exists, sha256, engineChanged, publishedAt }, rings: { "<n>": { version, sequence, releasedAt } } }
function Get-PimInvardiaReadBackVerdict {
    <# PURE. What a read-back says about the call that answered 5xx: @{ verdict = done | not-done | unknown; reason }.
       -Call publish: done = the version exists with OUR sha256. -Call promote: done = ring <n> carries the version. #>
    param([AllowNull()]$State, [Parameter(Mandatory)][ValidateSet('publish', 'promote')][string]$Call, [string]$Version, [string]$Sha256 = '', [int]$Ring = -1)
    if ($null -eq $State) { return @{ verdict = 'unknown'; reason = 'the state could not be read back -- check by hand before any retry' } }
    if ($Call -eq 'publish') {
        $v = $State.version
        if ($null -eq $v -or $null -eq $v.exists) { return @{ verdict = 'unknown'; reason = 'the read-back did not say whether the version exists' } }
        if (-not [bool]$v.exists) { return @{ verdict = 'not-done'; reason = "version $Version is not stored at Invardia" } }
        if ("$Sha256".Trim() -and "$($v.sha256)".Trim() -and "$($v.sha256)".Trim().ToLowerInvariant() -ne "$Sha256".Trim().ToLowerInvariant()) { return @{ verdict = 'unknown'; reason = "version $Version is stored with a DIFFERENT archive (sha256 $($v.sha256)) -- check by hand" } }
        return @{ verdict = 'done'; reason = "version $Version is stored (sha256 matches) -- the 5xx came after the commit" }
    }
    $rg = $null; if ($State.rings) { $rp = $State.rings.PSObject.Properties["$Ring"]; if ($rp) { $rg = $rp.Value } }
    if ($null -eq $rg) { return @{ verdict = 'not-done'; reason = "ring $Ring carries no release of this kind" } }
    if ("$($rg.version)".Trim() -eq "$Version") { return @{ verdict = 'done'; reason = "ring $Ring carries $Version (sequence $($rg.sequence)) -- the 5xx came after the commit" } }
    return @{ verdict = 'not-done'; reason = "ring $Ring carries $($rg.version), not $Version" }
}
function Invoke-PimInvardiaReadBack {
    # The GET itself; $null when it cannot be read (a route not live yet, a network error) -- the caller then says "unknown".
    param([string]$Endpoint, [string]$Token, [string]$Kind, [string]$Version)
    try {
        $u = "$($Endpoint.TrimEnd('/'))/api/releases/pim-manager/state?kind=$Kind&version=$Version"
        return (Invoke-RestMethod -Method GET -Uri $u -Headers @{ Authorization = "Bearer $Token" } -TimeoutSec 60)
    } catch { return $null }
}
function Get-PimReleaseNotesHeaderValue {
    <# PURE. The X-Release-Notes value for the publish call (Invardia 2026-10-16): the points trimmed (empty ones and line
       breaks inside a point dropped), joined with a line feed, cut at 8000 characters RAW, then [uri]::EscapeDataString (UTF-8;
       %0A between points). @{ value = '' when there is nothing to send; raw; points; cut }. #>
    param([string[]]$Points = @(), [int]$MaxRaw = 8000)
    $p = @(@($Points) | ForEach-Object { ("$_" -replace '[\x00-\x1F]', ' ').Trim() } | Where-Object { $_ })
    if (-not $p.Count) { return @{ value = ''; raw = ''; points = 0; cut = $false } }
    $raw = $p -join "`n"; $cut = $false
    if ($raw.Length -gt $MaxRaw) { $raw = $raw.Substring(0, $MaxRaw); $cut = $true }
    return @{ value = [uri]::EscapeDataString($raw); raw = $raw; points = $p.Count; cut = $cut }
}
$sol = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$repo = Split-Path (Split-Path $sol -Parent) -Parent
if (-not "$Version".Trim()) { $Version = (Get-Content -LiteralPath (Join-Path $sol 'VERSION') -Raw).Trim() }
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "not a release version: '$Version'" }
$tag = "PIM4EntraPS-v$Version"

Step "release $Version (tag $tag)"
& git -C $repo rev-parse --verify --quiet "refs/tags/$tag" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "the tag $tag does not exist -- publish only a tagged release" }

if ($Promote) {
    if ($Ring -lt 0) { throw '-Promote needs -Ring <0-3>' }
    if ($Ring -ge 2 -and -not "$OperatorApproval".Trim()) { throw "ring $Ring reaches customers -- pass -OperatorApproval with the operator's own words (e.g. 'release $Version to ring $Ring'); nothing was sent" }
    $purl = "$($Endpoint.TrimEnd('/'))/api/releases/pim-manager/$Kind/rings/$Ring"
    Write-Host ("    promote: {0} -> ring {1}{2}" -f $Version, $Ring, $(if ("$OperatorApproval".Trim()) { " -- operator: '$OperatorApproval'" } else { '' }))
    # PIM 100.158 CR3: changedScopes on the ring call (switch + 24 h hold, see the top of this file)
    $pScopes = @()
    $pScopesOn = (Test-PimChangedScopesOn -Value "$env:PIM_PUBLISH_CHANGEDSCOPES") -and -not (Test-PimChangedScopesHeld -RefusedUtc (Get-PimScopesMark $scopesMark))
    if ($pScopesOn) { $pScopes = @(Get-PimReleaseScopes -RepoRoot $repo -Tag $tag -PrevTag (Get-PimPreviousReleaseTag -RepoRoot $repo -Version $Version)) }
    Write-Host ("    changedScopes: {0}" -f $(if ($pScopes.Count) { $pScopes -join ',' } elseif ($pScopesOn) { '(none -- docs / tests only; not sent)' } else { '(not sent: PIM_PUBLISH_CHANGEDSCOPES off, or held after a refusal)' }))
    $pBody = [ordered]@{ version = $Version }; if ($pScopes.Count) { $pBody['changedScopes'] = @($pScopes) }
    if (-not $Apply) { Write-Host "`nPLAN ONLY -- nothing was sent. With -Apply: POST $purl $($pBody | ConvertTo-Json -Compress)." -ForegroundColor Yellow; return [pscustomobject]@{ promoted = $false; version = $Version; ring = $Ring; url = $purl; changedScopes = @($pScopes) } }
    if (-not $ClientId -or -not $CertThumbprint) {
        if (-not $KeyVault -or -not $KeyVaultSubscription) { throw "pass -ClientId and -CertThumbprint, or -KeyVault and -KeyVaultSubscription to read them" }
        $kvArgs = @('keyvault', 'secret', 'show', '--vault-name', $KeyVault, '--subscription', $KeyVaultSubscription, '--query', 'value', '-o', 'tsv')
        if (-not $ClientId) { $ClientId = (& az @kvArgs --name 'invardia-publisher-clientid-pim-manager' 2>$null | Select-Object -Last 1).Trim() }
        if (-not $CertThumbprint) { $CertThumbprint = (& az @kvArgs --name 'invardia-publisher-thumbprint-pim-manager' 2>$null | Select-Object -Last 1).Trim() }
    }
    if ($ClientId -notmatch '^[0-9a-fA-F-]{36}$' -or $CertThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'publisher client id / certificate thumbprint not found (Key Vault or parameters)' }
    . (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
    $token = Get-PimRestToken -Resource $Audience -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -Force
    if (-not "$token".Trim()) { throw 'no token for the Invardia Back Office audience' }
    # Invardia 2026-10-16: a RING call carries the UNION from the ring's CURRENT version to the target (the publish call keeps
    # the release's own delta). The ring's version is read from Invardia's state; unreadable / empty = the previous-tag delta.
    if ($pScopesOn) {
        $ringBase = Get-PimRingBaseVersion -State (Invoke-PimInvardiaReadBack -Endpoint $Endpoint -Token $token -Kind $Kind -Version $Version) -Ring $Ring -Target $Version
        if ($ringBase) {
            & git -C $repo rev-parse --verify --quiet "refs/tags/PIM4EntraPS-v$ringBase" | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $pScopes = @(Get-PimReleaseScopes -RepoRoot $repo -Tag $tag -PrevTag "PIM4EntraPS-v$ringBase")
                Write-Host ("    changedScopes (ring {0} holds {1} -> union to {2}): {3}" -f $Ring, $ringBase, $Version, $(if ($pScopes.Count) { $pScopes -join ',' } else { '(none)' }))
                $pBody.Remove('changedScopes'); if ($pScopes.Count) { $pBody['changedScopes'] = @($pScopes) }
            }
        }
    }
    Step "POST $purl"
    $pr = Invoke-PimInvardiaCall -Method POST -Url $purl -Token $token -Body ($pBody | ConvertTo-Json -Compress) -ContentType 'application/json'
    if ($pBody.Contains('changedScopes') -and (Test-PimChangedScopesRefusal -Status $pr.status -Content $pr.content)) {
        # Invardia refused the FIELD: once more without it, and the field is held for 24 h
        Write-Host ("    Invardia refused changedScopes (HTTP {0}) -- sent once more without it; held for 24 h" -f $pr.status) -ForegroundColor Yellow
        Set-PimScopesMark $scopesMark
        $pBody.Remove('changedScopes')
        $pr = Invoke-PimInvardiaCall -Method POST -Url $purl -Token $token -Body ($pBody | ConvertTo-Json -Compress) -ContentType 'application/json'
    }
    $status = [int]$pr.status; $content = "$($pr.content)"
    $ok = ($status -in 200, 201, 202)
    Write-Host ("    HTTP {0} {1}" -f $status, $content.Substring(0, [Math]::Min(400, $content.Length))) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
    $na = Get-PimNotApprovedText -Status $status -Content $content -Version $Version -Ring $Ring
    if ($na) { throw $na }
    if (-not $ok -and $status -ge 500) {
        # §12.22 3(c): a 5xx is "unknown" -- read the ring back before any retry or failure report
        $rb = Get-PimInvardiaReadBackVerdict -State (Invoke-PimInvardiaReadBack -Endpoint $Endpoint -Token $token -Kind $Kind -Version $Version) -Call promote -Version $Version -Ring $Ring
        Write-Host ("    read-back after HTTP {0}: {1} -- {2}" -f $status, $rb.verdict, $rb.reason) -ForegroundColor $(if ($rb.verdict -eq 'done') { 'Green' } else { 'Yellow' })
        if ($rb.verdict -eq 'done') { return [pscustomobject]@{ promoted = $true; version = $Version; ring = $Ring; status = $status; url = $purl; readBack = $rb.reason } }
        if ($rb.verdict -eq 'unknown') { throw "UNKNOWN -- the promotion answered HTTP $status and the ring could not be confirmed ($($rb.reason)); do not retry before checking" }
    }
    if (-not $ok) { throw "Invardia refused the promotion (HTTP $status)" }
    return [pscustomobject]@{ promoted = $true; version = $Version; ring = $Ring; status = $status; url = $purl; changedScopes = @($(if ($pBody.Contains('changedScopes')) { $pScopes })) }
}
Step 'build the release zip from the tag'
if (-not $OutDir) { $OutDir = Join-Path ([IO.Path]::GetTempPath()) 'pim-invardia-release' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$zip = Join-Path $OutDir "pim-manager-src-$Version.zip"
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
# CR7 (framework 12.11g, PIM 100.168): a tag that carries the shared sign-in front's source packs it too (FRAMEWORK/signin-front/src
# + VERSION), so an opted-in install's updater can build signin-front:<pinned version>. An older tag has none and packs as
# before (git archive refuses a pathspec that matches nothing). The updater re-pack keeps it; an updater already in the field
# re-packs only .dockerignore + SOLUTIONS and builds the Manager exactly as before (tests/Test-PimSigninFront.ps1 IMG-F*).
$zipPaths = @('.dockerignore', 'SOLUTIONS/PIM4EntraPS')
# ls-tree, not an existence probe with cat-file: a missing path prints NOTHING (cat-file writes "fatal: ..." to stderr, which PS 5.1 with
# ErrorActionPreference Stop turns into a terminating error -- measured on the test VM, 2026-10-18).
foreach ($sfp in @('FRAMEWORK/signin-front/src', 'FRAMEWORK/signin-front/VERSION')) { if (@(& git -C $repo ls-tree --name-only $tag -- $sfp).Count) { $zipPaths += $sfp } }
& git -C $repo archive --format=zip "--prefix=pim-manager-src-$Version/" -o $zip $tag -- @zipPaths
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $zip)) { throw "git archive failed (exit $LASTEXITCODE)" }

Step 'check the zip'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$z = [IO.Compression.ZipFile]::OpenRead($zip)
try {
    $bad = @($z.Entries | Where-Object { -not $_.FullName.StartsWith("pim-manager-src-$Version/") })
    if ($bad.Count) { throw "the zip has entries outside pim-manager-src-$Version/ (e.g. $($bad[0].FullName))" }
    $ve = $z.Entries | Where-Object { $_.FullName -eq "pim-manager-src-$Version/SOLUTIONS/PIM4EntraPS/VERSION" } | Select-Object -First 1
    if (-not $ve) { throw 'the zip carries no SOLUTIONS/PIM4EntraPS/VERSION' }
    $sr = New-Object IO.StreamReader($ve.Open()); try { $inner = $sr.ReadToEnd().Trim() } finally { $sr.Dispose() }
    if ($inner -ne $Version) { throw "VERSION inside the zip is '$inner', not $Version" }
    $count = $z.Entries.Count
} finally { $z.Dispose() }
$bytes = [IO.File]::ReadAllBytes($zip)
if ($bytes.Length -lt 4 -or $bytes[0] -ne 0x50 -or $bytes[1] -ne 0x4B) { throw 'not a zip' }
$sha = [System.Security.Cryptography.SHA256]::Create(); try { $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
Write-Host ("    {0}`n    {1} entries, {2:N0} bytes, SHA-256 {3}" -f $zip, $count, $bytes.Length, $hash)

# Framework §12.11b GUARD-STRICT (CR4) item 1: engineChanged on the publish call -- true when the ENGINE code differs from
# the previous release. engineHash = SHA-256 over "<path> <blob id>" of every file under the engine folders in the TAGGED
# tree (git ls-tree: content-addressed, so no checkout and no working-tree drift); the previous release = the highest
# PIM4EntraPS-v<x> tag below this version. No previous release, or a hash that cannot be computed = true (Strict is the
# safe side). A GUI / template / text-only release keeps Normal.
function Get-PimEngineHashAtTag([string]$RepoRoot, [string]$Ref) {
    $paths = @('SOLUTIONS/PIM4EntraPS/engine', 'SOLUTIONS/PIM4EntraPS/tools/pim-engine', 'SOLUTIONS/PIM4EntraPS/tools/pim-scheduler', 'SOLUTIONS/PIM4EntraPS/sql')
    $lines = @(& git -C $RepoRoot ls-tree -r $Ref -- @paths 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $lines.Count) { return '' }
    $norm = @($lines | ForEach-Object { $p = "$_" -split "`t", 2; if ($p.Count -eq 2) { $p[1] + ' ' + (($p[0] -split ' ')[2]) } } | Sort-Object -CaseSensitive)
    $s = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($s.ComputeHash([Text.Encoding]::UTF8.GetBytes(($norm -join "`n"))))).Replace('-', '').ToLowerInvariant() } finally { $s.Dispose() }
}
$engineHash = Get-PimEngineHashAtTag $repo $tag
$prevTag = @(& git -C $repo tag -l 'PIM4EntraPS-v2.*' 2>$null | ForEach-Object { $v = "$_" -replace '^PIM4EntraPS-v', ''; try { [pscustomobject]@{ tag = "$_"; v = [version]$v } } catch { } } |
             Where-Object { $_.v -lt [version]$Version } | Sort-Object v -Descending | Select-Object -First 1)
$prevHash = if ($prevTag) { Get-PimEngineHashAtTag $repo $prevTag[0].tag } else { '' }
$engineChanged = (-not $engineHash -or -not $prevHash -or $engineHash -ne $prevHash)
# Joint rule (owner approved 2026-10-14, PIM 100.154 (b)): a new field on a changing call can be turned OFF without a release.
# PIM_PUBLISH_ENGINECHANGED = 0 / off / false / no -> the publish call carries no engineChanged (Invardia then treats the
# release as it did before the field existed).
$sendEngineChanged = -not ("$env:PIM_PUBLISH_ENGINECHANGED".Trim() -match '^(?i)(0|off|false|no)$')
if (-not $sendEngineChanged) { Write-Host '    engineChanged NOT sent (PIM_PUBLISH_ENGINECHANGED is off)' -ForegroundColor Yellow }
Write-Host ("    engine: {0} vs {1} -> engineChanged={2}" -f $(if ($engineHash) { $engineHash.Substring(0, 12) } else { '(none)' }), $(if ($prevTag) { "$($prevTag[0].tag) $(if ($prevHash) { $prevHash.Substring(0, 12) })" } else { '(no previous release)' }), $engineChanged.ToString().ToLowerInvariant())

# UPDATE-1.7: PIM decides the ring. Ring 2 / 3 reach customers: only on the operator's own words (memory/ring-2 rule).
if ($Ring -ge 2 -and -not "$OperatorApproval".Trim()) { throw "ring $Ring reaches customers -- pass -OperatorApproval with the operator's own words (e.g. 'release $Version to ring $Ring'); nothing was sent" }
$url = "$($Endpoint.TrimEnd('/'))/api/releases/pim-manager?kind=$Kind&version=$Version" + $(if ($Ring -ge 0) { "&ring=$Ring" } else { '' }) + $(if ($sendEngineChanged) { "&engineChanged=$($engineChanged.ToString().ToLowerInvariant())" } else { '' })
# PIM 100.158 CR3: changedScopes on the publish call (switch + 24 h hold, see the top of this file)
$scopes = @()
$scopesOn = (Test-PimChangedScopesOn -Value "$env:PIM_PUBLISH_CHANGEDSCOPES") -and -not (Test-PimChangedScopesHeld -RefusedUtc (Get-PimScopesMark $scopesMark))
if ($scopesOn) { $scopes = @(Get-PimReleaseScopes -RepoRoot $repo -Tag $tag -PrevTag $(if ($prevTag) { "$($prevTag[0].tag)" } else { '' })) }
$scopesQuery = ConvertTo-PimChangedScopesQuery -Scopes $scopes
$urlNoScopes = $url
if ($scopesQuery) { $url = "$url&changedScopes=$scopesQuery" }
Write-Host ("    changedScopes: {0}" -f $(if ($scopes.Count) { $scopes -join ',' } elseif ($scopesOn) { '(none -- docs / tests only; not sent)' } else { '(not sent: PIM_PUBLISH_CHANGEDSCOPES off, or held after a refusal)' }))
Write-Host ("    ring: {0}{1}" -f $(if ($Ring -ge 0) { "$Ring (published AND released to it)" } else { 'none (registered only, released to no ring)' }), $(if ("$OperatorApproval".Trim()) { " -- operator: '$OperatorApproval'" } else { '' }))
# REQUIREMENTS 33.0 RELEASE CONTEXT: the fix list as X-Release-Notes on the PUBLISH call only (switch PIM_PUBLISH_RELEASENOTES)
$notesHeaders = @{}
$notesHdr = Get-PimReleaseNotesHeaderValue -Points @($ReleaseNotes)
if ($notesHdr.value -and ("$env:PIM_PUBLISH_RELEASENOTES".Trim() -match '^(?i)(0|off|false|no)$')) {
    Write-Host '    release notes NOT sent (PIM_PUBLISH_RELEASENOTES is off)' -ForegroundColor Yellow
} elseif ($notesHdr.value) {
    $notesHeaders['X-Release-Notes'] = $notesHdr.value
    Write-Host ("    release notes: {0} point(s), {1} characters raw{2} (X-Release-Notes on the publish call)" -f $notesHdr.points, $notesHdr.raw.Length, $(if ($notesHdr.cut) { ' -- CUT at 8000' } else { '' }))
}
if (-not $Apply) {
    Write-Host "`nPLAN ONLY -- nothing was sent. With -Apply the zip is POSTed to $url as Invardia.Publisher.pim-manager (tenant $TenantId)." -ForegroundColor Yellow
    return [pscustomobject]@{ published = $false; version = $Version; ring = $Ring; zip = $zip; sha256 = $hash; size = $bytes.Length; url = $url; engineHash = $engineHash; engineChanged = $engineChanged; changedScopes = @($scopes); releaseNotesHeader = "$($notesHeaders['X-Release-Notes'])" }
}

Step 'publisher identity (certificate, from Key Vault unless passed)'
if (-not $ClientId -or -not $CertThumbprint) {
    # No vault or subscription is baked in (the source ships publicly): name them, or pass -ClientId and -CertThumbprint.
    if (-not $KeyVault -or -not $KeyVaultSubscription) { throw "pass -ClientId and -CertThumbprint, or -KeyVault and -KeyVaultSubscription to read them" }
    $kvArgs = @('keyvault', 'secret', 'show', '--vault-name', $KeyVault, '--subscription', $KeyVaultSubscription, '--query', 'value', '-o', 'tsv')
    if (-not $ClientId) { $ClientId = (& az @kvArgs --name 'invardia-publisher-clientid-pim-manager' 2>$null | Select-Object -Last 1).Trim() }
    if (-not $CertThumbprint) { $CertThumbprint = (& az @kvArgs --name 'invardia-publisher-thumbprint-pim-manager' 2>$null | Select-Object -Last 1).Trim() }
}
if ($ClientId -notmatch '^[0-9a-fA-F-]{36}$' -or $CertThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'publisher client id / certificate thumbprint not found (Key Vault or parameters)' }
. (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
$token = Get-PimRestToken -Resource $Audience -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -Force
if (-not "$token".Trim()) { throw 'no token for the Invardia Back Office audience' }

Step "POST $url"
# Windows PowerShell 5.1 as well as 7 (HOST-1: scripts in tools\setup must run on both): a non-2xx answer is read from the
# exception's response instead of -SkipHttpErrorCheck (PS 7 only).
$pub = Invoke-PimInvardiaCall -Method POST -Url $url -Token $token -Body $bytes -ContentType 'application/zip' -TimeoutSec 600 -ExtraHeaders $notesHeaders
if ($scopesQuery -and (Test-PimChangedScopesRefusal -Status $pub.status -Content $pub.content)) {
    # PIM 100.158: Invardia refused the FIELD -- once more without it, and it is held for 24 h
    Write-Host ("    Invardia refused changedScopes (HTTP {0}) -- sent once more without it; held for 24 h" -f $pub.status) -ForegroundColor Yellow
    Set-PimScopesMark $scopesMark
    $url = $urlNoScopes; $scopes = @()
    $pub = Invoke-PimInvardiaCall -Method POST -Url $url -Token $token -Body $bytes -ContentType 'application/zip' -TimeoutSec 600 -ExtraHeaders $notesHeaders
}
$status = [int]$pub.status; $content = "$($pub.content)"
$ok = ($status -in 200, 201, 202)
Write-Host ("    HTTP {0} {1}" -f $status, $content.Substring(0, [Math]::Min(400, $content.Length))) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
$naP = Get-PimNotApprovedText -Status $status -Content $content -Version $Version -Ring $Ring
if ($naP) { throw $naP }
if (-not $ok -and $status -ge 500) {
    # §12.22 3(c): a 5xx is "unknown" -- read the version back before any retry or failure report
    $rb = Get-PimInvardiaReadBackVerdict -State (Invoke-PimInvardiaReadBack -Endpoint $Endpoint -Token $token -Kind $Kind -Version $Version) -Call publish -Version $Version -Sha256 $hash
    Write-Host ("    read-back after HTTP {0}: {1} -- {2}" -f $status, $rb.verdict, $rb.reason) -ForegroundColor $(if ($rb.verdict -eq 'done') { 'Green' } else { 'Yellow' })
    if ($rb.verdict -eq 'done') { return [pscustomobject]@{ published = $true; version = $Version; sha256 = $hash; size = $bytes.Length; status = $status; url = $url; engineHash = $engineHash; engineChanged = $engineChanged; readBack = $rb.reason } }
    if ($rb.verdict -eq 'unknown') { throw "UNKNOWN -- the publish answered HTTP $status and the version could not be confirmed ($($rb.reason)); do not retry before checking" }
}
if (-not $ok) { throw "Invardia refused the release (HTTP $status)" }
[pscustomobject]@{ published = $true; version = $Version; sha256 = $hash; size = $bytes.Length; status = $status; url = $url; engineHash = $engineHash; engineChanged = $engineChanged; changedScopes = @($scopes) }
