#Requires -Version 5.1
<#
.SYNOPSIS
    Unstick the PIM Activator extension on a laptop that's pinned to an
    old version (or showing ERR_FILE_NOT_FOUND on icon click). Run as the
    USER who owns the Chrome / Edge profiles. Re-runnable, idempotent.

.DESCRIPTION
    Symptoms this script fixes:
      - chrome://extensions shows PIM Activator at an OLD version (e.g.
        1.1.1) while gh-pages updates.xml advertises a newer one.
      - Clicking the PIM Activator icon shows
        "Your file couldn't be accessed -- ERR_FILE_NOT_FOUND".
      - Pushing fresh CRX versions to gh-pages and waiting changes nothing.

    What's actually wrong:
      Chrome's `<UserData>\Default\Secure Preferences` carries a
      registration block for the extension claiming it's installed at
      version X. Chrome's force_installed_metrics reads that, logs
      "All forced extensions seem to be installed", and skips the
      install pipeline. So a newer CRX on gh-pages is never downloaded.

      If the on-disk files for version X have been deleted (which the
      Update-PimActivator-Extension.ps1 flush step does), clicking the
      icon hits ERR_FILE_NOT_FOUND -- but Chrome still won't re-install
      because the registration entry "proves" the extension is installed.

    Fix this script applies:
      1. Closes Chrome + Edge gracefully (so the prefs files aren't locked).
      2. For every Chrome AND Edge profile folder (Default, Profile 1,
         Profile 2, ...) under the running user, surgically removes the
         extension's entry from:
           - <profile>\Preferences            extensions.settings.<id>
           - <profile>\Preferences            extensions.pinned_extensions
           - <profile>\Secure Preferences     extensions.settings.<id>
           - <profile>\Secure Preferences     protection.macs.extensions.settings.<id>
         A timestamped .bak.<YYYYMMDDHHmmss> sidecar is written next to
         each modified file -- recovery from the script is a single
         Copy-Item if anything goes wrong.
      3. Tells you to reopen Chrome.

    Once Chrome relaunches with no stale registration AND the
    ExtensionInstallForcelist policy in HKLM, Chrome runs a clean
    forcelist install and downloads the current CRX from gh-pages.

    PS 5.1 compatibility:
      Uses raw text + brace-counting string surgery instead of
      ConvertFrom-Json / ConvertTo-Json. The 2026-06-09 incident proved
      that PS 5.1's ConvertTo-Json corrupts Chromium's Preferences shape
      on round-trip and can brick the profile -- this script never round-
      trips the JSON, so that can't happen.

.PARAMETER ExtensionId
    Chrome/Edge extension id. Default 'eheocihmlppcophaeakmdenhgcookkab'.

.PARAMETER Browser
    'Both' (default), 'Edge', or 'Chrome' -- which browser's profiles to clean.

.PARAMETER NoBrowserKill
    Skip closing the browser. Default is to kill it first so the file is
    unlocked. Pass this only if you've already closed the browser yourself.

.EXAMPLE
    # Standard run -- close browsers, purge, exit. Re-open Chrome yourself.
    .\Fix-PimActivatorStuck.ps1

.EXAMPLE
    # Chrome only, browser already closed
    .\Fix-PimActivatorStuck.ps1 -Browser Chrome -NoBrowserKill
#>
[CmdletBinding()]
param(
    [string]$ExtensionId = 'eheocihmlppcophaeakmdenhgcookkab',

    [ValidateSet('Both','Edge','Chrome')]
    [string]$Browser = 'Both',

    [switch]$NoBrowserKill
)

$ErrorActionPreference = 'Stop'

# --- Helpers ----------------------------------------------------------------

function Write-Step { param([string]$Msg) Write-Host "`n>> $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "   $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "   $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "   $Msg" -ForegroundColor Red }

function Close-Browser {
    param([string]$ProcessName)
    $procs = @(Get-Process $ProcessName -ErrorAction SilentlyContinue)
    if (-not $procs) { Write-Warn "$ProcessName : not running"; return }
    foreach ($p in $procs) {
        try { if ($p.MainWindowHandle -ne 0) { [void]$p.CloseMainWindow() } } catch {}
    }
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline -and (Get-Process $ProcessName -ErrorAction SilentlyContinue)) {
        Start-Sleep -Milliseconds 300
    }
    Get-Process $ProcessName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Ok "$ProcessName : closed ($($procs.Count) process(es) terminated)"
}

# Surgical brace-matched JSON property removal.
# Reads file as raw UTF-8 (no BOM), walks the text to find "<ExtensionId>":
# entries, identifies the value's extent (object / array / string / scalar),
# and removes the key+value PLUS the trailing or leading comma so the
# resulting JSON stays valid.
# Returns the number of entries removed.
function Remove-JsonProperty {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$PropertyName
    )
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $utf8noBom = New-Object System.Text.UTF8Encoding($false)
    $text      = [System.IO.File]::ReadAllText($Path, $utf8noBom)
    $original  = $text
    $removed   = 0
    $searchKey = '"' + $PropertyName + '":'

    # Loop in case the property appears more than once (it does: registration
    # under extensions.settings.<id>, HMAC under protection.macs.extensions.settings.<id>,
    # and possibly other places).
    while ($true) {
        $startIdx = $text.IndexOf($searchKey)
        if ($startIdx -lt 0) { break }

        # Find start of value (skip whitespace).
        $valueStart = $startIdx + $searchKey.Length
        while ($valueStart -lt $text.Length -and [char]::IsWhiteSpace($text[$valueStart])) { $valueStart++ }
        if ($valueStart -ge $text.Length) { break }
        $ch = $text[$valueStart]

        # Determine value's end.
        $endIdx = -1
        if ($ch -eq '{' -or $ch -eq '[') {
            $open  = $ch
            $close = if ($open -eq '{') { '}' } else { ']' }
            $depth = 1
            $i = $valueStart + 1
            while ($depth -gt 0 -and $i -lt $text.Length) {
                $c = $text[$i]
                if ($c -eq '"') {
                    # Walk through string respecting backslash escapes.
                    $i++
                    while ($i -lt $text.Length -and $text[$i] -ne '"') {
                        if ($text[$i] -eq '\') { $i++ }
                        $i++
                    }
                } elseif ($c -eq $open)  { $depth++ }
                elseif   ($c -eq $close) { $depth-- }
                $i++
            }
            $endIdx = $i
        } elseif ($ch -eq '"') {
            $i = $valueStart + 1
            while ($i -lt $text.Length -and $text[$i] -ne '"') {
                if ($text[$i] -eq '\') { $i++ }
                $i++
            }
            $endIdx = $i + 1
        } else {
            # Scalar (number / bool / null) -- read until comma or container close.
            $i = $valueStart
            while ($i -lt $text.Length -and $text[$i] -notin @(',','}',']')) { $i++ }
            $endIdx = $i
        }
        if ($endIdx -lt 0 -or $endIdx -gt $text.Length) { break }

        # Expand cut to swallow ONE comma (preceding if present, else trailing)
        # so the surrounding JSON stays syntactically valid.
        $cutStart = $startIdx
        $cutEnd   = $endIdx
        $j = $cutStart - 1
        while ($j -ge 0 -and [char]::IsWhiteSpace($text[$j])) { $j-- }
        if ($j -ge 0 -and $text[$j] -eq ',') {
            $cutStart = $j
        } else {
            $k = $cutEnd
            while ($k -lt $text.Length -and [char]::IsWhiteSpace($text[$k])) { $k++ }
            if ($k -lt $text.Length -and $text[$k] -eq ',') { $cutEnd = $k + 1 }
        }

        $text = $text.Substring(0, $cutStart) + $text.Substring($cutEnd)
        $removed++
    }

    # Also strip the extension id from the pinned_extensions array if present.
    # Looks like: "pinned_extensions":["<id>","<id2>",...] -- we just remove
    # the entry plus a leading or trailing comma.
    $pinPattern = '"' + $ExtensionId + '"'
    if ($text -match ('"pinned_extensions"\s*:\s*\[[^]]*' + [regex]::Escape($pinPattern) + '[^]]*\]')) {
        # Two passes: (1) with leading comma, (2) without.
        $text = [regex]::Replace($text, '\s*,\s*"' + [regex]::Escape($ExtensionId) + '"', '')
        $text = [regex]::Replace($text, '"' + [regex]::Escape($ExtensionId) + '"\s*,\s*', '')
        $text = [regex]::Replace($text, '"' + [regex]::Escape($ExtensionId) + '"', '')
        $removed++
    }

    if ($removed -gt 0 -and $text -ne $original) {
        $stamp  = (Get-Date).ToString('yyyyMMddHHmmss')
        $backup = "$Path.bak.$stamp"
        Copy-Item -LiteralPath $Path -Destination $backup -Force
        [System.IO.File]::WriteAllText($Path, $text, $utf8noBom)
        Write-Ok ("removed {0} entries from {1}  (backup: {2})" -f $removed, (Split-Path -Leaf $Path), (Split-Path -Leaf $backup))
    }
    return $removed
}

# --- 1. Close browsers ------------------------------------------------------

Write-Step "Closing browser(s) so the prefs files are unlocked"
if (-not $NoBrowserKill) {
    if ($Browser -in @('Both','Chrome')) { Close-Browser -ProcessName 'chrome' }
    if ($Browser -in @('Both','Edge'))   { Close-Browser -ProcessName 'msedge' }
} else {
    Write-Warn "Skipping browser kill (-NoBrowserKill). Make sure no chrome.exe / msedge.exe is running before continuing."
}

# --- 2. Walk profile folders + purge ----------------------------------------

Write-Step "Purging stale '$ExtensionId' entries from every profile"
$roots = @()
if ($Browser -in @('Both','Chrome')) { $roots += "$env:LOCALAPPDATA\Google\Chrome\User Data" }
if ($Browser -in @('Both','Edge'))   { $roots += "$env:LOCALAPPDATA\Microsoft\Edge\User Data" }

$totalRemoved = 0
$profilesScanned = 0
foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root)) {
        Write-Warn "$root not present -- browser never run by this user"
        continue
    }
    $profileDirs = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(Default|Profile \d+)$' }
    foreach ($pd in $profileDirs) {
        $profilesScanned++
        foreach ($prefName in 'Preferences','Secure Preferences') {
            $prefPath = Join-Path $pd.FullName $prefName
            $n = Remove-JsonProperty -Path $prefPath -PropertyName $ExtensionId
            $totalRemoved += $n
        }
    }
}

# --- 3. Report --------------------------------------------------------------

Write-Step "Done"
Write-Ok  "Profiles scanned       : $profilesScanned"
Write-Ok  "Total entries removed  : $totalRemoved"
if ($totalRemoved -eq 0) {
    Write-Warn "No stale entries found. The stuck-version symptom is something else (could be CDN caching, policy not applied, or signing key mismatch). Check chrome://policy for ExtensionInstallForcelist + ExtensionSettings status."
} else {
    Write-Ok  ""
    Write-Ok  "Reopen Chrome (or Edge) -- the forcelist policy will trigger a clean"
    Write-Ok  "install of the latest CRX from gh-pages within ~60 seconds. PIM Activator"
    Write-Ok  "icon will turn live + clicking it will open the popup (no more ERR_FILE_NOT_FOUND)."
}
