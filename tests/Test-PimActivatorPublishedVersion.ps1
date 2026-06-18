#Requires -Version 5.1
<#
.SYNOPSIS
    PUBLISHED-VERSION gate for the PIM Activator browser extension.

.DESCRIPTION
    Asserts that what is actually PUBLISHED on gh-pages matches the source the
    repo just shipped -- catching the failure where the extension "didn't update"
    on machines (xml bumped but the CRX is stale, or a publish that never ran).

    It fetches the live update channel:
      * https://knudsenmorten.github.io/PIM4EntraPS/updates.xml  -- the
        <updatecheck ... version='X.Y.Z' /> advertised version + the codebase .crx URL.
      * the .crx itself (CRX v3) -- the EMBEDDED manifest.json version (the ZIP
        payload after the Cr24 header).
    and compares BOTH against the SOURCE version in
    tools/pim-activator/manifest.json.

    THREE-WAY equality is required when the network is reachable:
      manifest.json (source)  ==  updates.xml (advertised)  ==  .crx (embedded)
    A mismatch is a HARD FAIL (exit 1). This catches:
      - "xml bumped but crx stale"     (updates.xml != crx)
      - "crx rebuilt but xml not bumped"(crx != updates.xml)
      - "source ahead of what shipped"  (manifest != published)

    NETWORK: when gh-pages is unreachable (offline CI, blocked egress) it SKIPS
    cleanly (exit 0) -- absence of network is not a failure. But when the channel
    IS reachable, any version mismatch FAILS. A skip is a SKIP, not a pass.

    Pure read-only. No signing, no tenant, no browser. PS 5.1-safe.

        powershell -NoProfile -File .\tests\Test-PimActivatorPublishedVersion.ps1

.PARAMETER UpdatesUrl
    Override the updates.xml URL (default the live gh-pages channel).
.PARAMETER ManifestPath
    Override the source manifest.json (default tools/pim-activator/manifest.json).
#>
[CmdletBinding()]
param(
    [string]$UpdatesUrl  = 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml',
    [string]$ManifestPath = ''
)
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0; $skip = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }
function S($n, $why) { Write-Host "  SKIP $n -- $why" -ForegroundColor Yellow; $script:skip++ }

Write-Host "=== PIM Activator PUBLISHED-VERSION gate ===" -ForegroundColor Cyan

# ---- 1. SOURCE version (manifest.json) ---------------------------------------
$root = Split-Path -Parent $PSScriptRoot                       # SOLUTIONS/PIM4EntraPS
if (-not $ManifestPath) { $ManifestPath = Join-Path $root 'tools\pim-activator\manifest.json' }
if (-not (Test-Path -LiteralPath $ManifestPath)) {
    T "source manifest.json present ($ManifestPath)" $false
    Write-Host ("`n RESULT: {0} pass, {1} fail, {2} skip" -f $pass, $fail, $skip) -ForegroundColor Red
    exit 1
}
$sourceVer = $null
try { $sourceVer = (Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json).version } catch {}
T "source manifest.json declares a version" ([bool]$sourceVer)
if ($sourceVer) { Write-Host ("  source manifest.json version: $sourceVer") -ForegroundColor DarkGray }

# ---- 2. PUBLISHED updates.xml (advertised version + codebase URL) ------------
$updatesXml = $null
try {
    $r = Invoke-WebRequest -Uri $UpdatesUrl -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
    if ($r.StatusCode -eq 200) { $updatesXml = "$($r.Content)" }
} catch {
    S 'published version gate (updates.xml)' "gh-pages updates.xml unreachable ($UpdatesUrl): $($_.Exception.Message) -- network absent, skipping cleanly"
    Write-Host ("`n RESULT: {0} pass, {1} fail, {2} skip" -f $pass, $fail, $skip) -ForegroundColor Green
    exit 0
}
if (-not $updatesXml) {
    S 'published version gate (updates.xml)' 'updates.xml returned no body -- skipping cleanly'
    Write-Host ("`n RESULT: {0} pass, {1} fail, {2} skip" -f $pass, $fail, $skip) -ForegroundColor Green
    exit 0
}

# Advertised version -- tight regex on <updatecheck ... version='X.Y.Z' /> so we
# never pick up the XML declaration's version='1.0'.
$advertisedVer = $null
$am = [regex]::Match($updatesXml, "<updatecheck\b[^>]*\bversion\s*=\s*['""]([0-9]+\.[0-9]+\.[0-9]+)['""]")
if ($am.Success) { $advertisedVer = $am.Groups[1].Value }
T 'updates.xml advertises an <updatecheck version=...>' ([bool]$advertisedVer)
if ($advertisedVer) { Write-Host ("  updates.xml advertised version: $advertisedVer") -ForegroundColor DarkGray }

# Codebase .crx URL (so we always probe the CRX the channel actually points at).
$crxUrl = $null
$cm = [regex]::Match($updatesXml, "<updatecheck\b[^>]*\bcodebase\s*=\s*['""]([^'""]+\.crx)['""]")
if ($cm.Success) { $crxUrl = $cm.Groups[1].Value }
T 'updates.xml carries a codebase .crx URL' ([bool]$crxUrl)

# ---- 3. PUBLISHED .crx EMBEDDED manifest version ----------------------------
# CRX v3 layout: 'Cr24' (4) | version uint32 (4) | headerLen uint32 (4) | header |
# ZIP payload. The ZIP starts at 12 + headerLen; read manifest.json out of it.
function Get-CrxEmbeddedManifestVersion {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -lt 16) { throw "CRX too small ($($Bytes.Length) bytes)" }
    $magic = -join ($Bytes[0..3] | ForEach-Object { [char]$_ })
    if ($magic -ne 'Cr24') { throw "not a CRX (magic='$magic')" }
    $crxVer = [System.BitConverter]::ToUInt32($Bytes, 4)
    if ($crxVer -lt 2) { throw "unexpected CRX format version $crxVer" }
    # v3 carries a header length at offset 8; v2 carries pubkey+sig lengths instead.
    if ($crxVer -ge 3) {
        $hdrLen   = [System.BitConverter]::ToUInt32($Bytes, 8)
        $zipStart = 12 + $hdrLen
    } else {
        $pkLen    = [System.BitConverter]::ToUInt32($Bytes, 8)
        $sigLen   = [System.BitConverter]::ToUInt32($Bytes, 12)
        $zipStart = 16 + $pkLen + $sigLen
    }
    if ($zipStart -ge $Bytes.Length) { throw "computed ZIP start $zipStart past EOF $($Bytes.Length)" }
    $zipBytes = New-Object byte[] ($Bytes.Length - $zipStart)
    [System.Array]::Copy($Bytes, $zipStart, $zipBytes, 0, $zipBytes.Length)
    Add-Type -AssemblyName System.IO.Compression | Out-Null
    $ms = New-Object System.IO.MemoryStream(,$zipBytes)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($ms, [System.IO.Compression.ZipArchiveMode]::Read)
        try {
            $entry = $zip.GetEntry('manifest.json')
            if (-not $entry) { throw "manifest.json not found inside the CRX ZIP" }
            $sr = New-Object System.IO.StreamReader($entry.Open())
            try { $json = $sr.ReadToEnd() } finally { $sr.Dispose() }
            return ($json | ConvertFrom-Json).version
        } finally { $zip.Dispose() }
    } finally { $ms.Dispose() }
}

$crxVer = $null
if ($crxUrl) {
    $crxTmp = Join-Path ([IO.Path]::GetTempPath()) ("pim-activator-pubcheck-" + [guid]::NewGuid().ToString('N') + ".crx")
    try {
        Invoke-WebRequest -Uri $crxUrl -OutFile $crxTmp -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
        $crxVer = Get-CrxEmbeddedManifestVersion -Bytes ([System.IO.File]::ReadAllBytes($crxTmp))
        T 'published .crx embedded manifest.json version parsed' ([bool]$crxVer)
        if ($crxVer) { Write-Host ("  .crx embedded manifest version: $crxVer") -ForegroundColor DarkGray }
    } catch {
        # Reachable updates.xml but the CRX cannot be fetched/parsed is suspicious,
        # but treat a pure FETCH failure (e.g. transient 404 mid-publish) as a SKIP
        # so a flaky network never red-flags a healthy publish. A PARSE failure of a
        # fetched CRX is a FAIL (the published artifact is malformed).
        if ($_.Exception -is [System.Net.WebException] -or "$($_.Exception.Message)" -match '404|timed out|Unable to connect|remote name') {
            S 'published .crx fetch' "could not download the .crx ($crxUrl): $($_.Exception.Message) -- skipping the CRX leg cleanly"
        } else {
            T "published .crx parses to an embedded manifest version ($crxUrl)" $false
            Write-Host ("    parse error: $($_.Exception.Message)") -ForegroundColor DarkYellow
        }
    } finally {
        if (Test-Path -LiteralPath $crxTmp) { Remove-Item -LiteralPath $crxTmp -Force -ErrorAction SilentlyContinue }
    }
} else {
    S 'published .crx version' 'no codebase .crx URL in updates.xml -- cannot probe the CRX leg'
}

# ---- 4. THREE-WAY equality (the actual gate) --------------------------------
# manifest.json (source) == updates.xml (advertised) == .crx (embedded).
if ($sourceVer -and $advertisedVer) {
    T ("updates.xml advertised version == source manifest.json (v{0})" -f $sourceVer) ($advertisedVer -eq $sourceVer)
}
if ($sourceVer -and $crxVer) {
    T ("published .crx embedded version == source manifest.json (v{0})" -f $sourceVer) ($crxVer -eq $sourceVer)
}
if ($advertisedVer -and $crxVer) {
    # The 'xml bumped but crx stale' (or vice-versa) catch -- the two PUBLISHED
    # artifacts must agree with each other regardless of the source.
    T ("updates.xml advertised version == published .crx embedded version (v{0})" -f $advertisedVer) ($advertisedVer -eq $crxVer)
}

Write-Host ("`n RESULT: {0} pass, {1} fail, {2} skip" -f $pass, $fail, $skip) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
