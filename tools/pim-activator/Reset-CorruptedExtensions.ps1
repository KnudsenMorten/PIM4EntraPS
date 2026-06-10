#Requires -Version 5.1
<#
.SYNOPSIS
    Self-heal Chrome / Edge profiles whose extension registrations got
    flagged DISABLE_CORRUPTED (Chrome's content-hash verifier marked the
    extension as tampered). On next browser launch, the forcelist (or
    sync) re-installs the extension clean.

.DESCRIPTION
    Chrome's extension content-verification system periodically checks
    every installed extension's files against `_metadata\computed_hashes.json`
    that was written at install time. Any mismatch sets a bit in
    extensions.settings.<id>.disable_reasons -- usually 1024
    (DISABLE_CORRUPTED). Once set, Chrome refuses to load the extension
    AND refuses to retry the install -- the only path back to a working
    state is removing the extension's registration entry from Preferences
    and Secure Preferences and letting the forcelist installer run fresh.

    Common triggers for DISABLE_CORRUPTED on managed fleets:
      - Antivirus repair / quarantine touching a file in the extension
      - OneDrive / Sync collisions on cached extension folders
      - CRX download interrupted mid-write
      - Disk repair / chkdsk

    Solution: deploy this script as a logon scheduled task (or via Intune
    Proactive Remediation if you ever change your mind about those). It
    walks every Chrome + Edge profile, finds any extension entry with
    DISABLE_CORRUPTED (or any other "transient" reason -- configurable),
    and surgically removes that entry from Preferences + Secure
    Preferences + the HMAC. On next launch, the forcelist re-evaluates
    and the install lands clean again.

    Pure string-surgery brace counting. No PS 5.1 ConvertTo-Json round-
    trip (which has documented profile-corruption bugs of its own --
    see 2026-06-09 incident notes in Update-PimActivator-Extension.ps1).

.PARAMETER ResetReasonsBitmask
    Bitmask of Chromium disable_reasons that this script considers
    "safely resettable". Defaults to 1024 (DISABLE_CORRUPTED) only.

    The full reason map (from Chromium's extension_disable_reason.h):
        1     DISABLE_USER_ACTION                -- user explicitly disabled; do NOT reset
        2     DISABLE_PERMISSIONS_INCREASE       -- needs accept; safe to reset on managed force-installed
        4     DISABLE_RELOAD                     -- transient
        8     DISABLE_UNSUPPORTED_REQUIREMENT    -- e.g. needs newer Chrome
        256   DISABLE_NOT_VERIFIED               -- transient
        512   DISABLE_GREYLIST                   -- blocklist-soft
        1024  DISABLE_CORRUPTED                  -- THIS ONE
        2048  DISABLE_REMOTE_INSTALL
        8192  DISABLE_UPDATE_REQUIRED_BY_POLICY
        32768 DISABLE_BLOCKED_BY_POLICY          -- explicitly blocked; do NOT reset

.PARAMETER Browser
    Both / Edge / Chrome. Default Both.

.PARAMETER NoBrowserKill
    Skip closing the browser. Default behavior closes it first so the
    prefs files aren't locked.

.PARAMETER DryRun
    Report what WOULD be reset without modifying anything. Useful as the
    detection half of a scheduled-task pair.

.EXAMPLE
    .\Reset-CorruptedExtensions.ps1
    # Resets every DISABLE_CORRUPTED entry across Chrome + Edge.

.EXAMPLE
    # Schedule at logon (manual one-time setup; survives reboots):
    schtasks /create /tn "PIM-ResetCorruptedExtensions" /sc onlogon /rl HIGHEST `
        /tr "powershell -NoProfile -ExecutionPolicy Bypass -File C:\path\to\Reset-CorruptedExtensions.ps1 -NoBrowserKill"

.EXAMPLE
    .\Reset-CorruptedExtensions.ps1 -DryRun
    # See what would be reset, write nothing.
#>
[CmdletBinding()]
param(
    [int]$ResetReasonsBitmask = 1024,

    [ValidateSet('Both','Edge','Chrome')]
    [string]$Browser = 'Both',

    [switch]$NoBrowserKill,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Close-Browser {
    param([string]$ProcessName)
    $procs = @(Get-Process $ProcessName -ErrorAction SilentlyContinue)
    if (-not $procs) { return }
    foreach ($p in $procs) { try { if ($p.MainWindowHandle -ne 0) { $null = $p.CloseMainWindow() } } catch {} }
    $deadline = (Get-Date).AddSeconds(8)
    while ((Get-Date) -lt $deadline -and (Get-Process $ProcessName -ErrorAction SilentlyContinue)) { Start-Sleep -Milliseconds 300 }
    Get-Process $ProcessName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Surgical brace-matched JSON property removal (same pattern as
# Fix-PimActivatorStuck.ps1 -- pure text surgery, no ConvertTo-Json).
function Remove-JsonProperty {
    param([string]$Path, [string]$PropertyName)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $text = [System.IO.File]::ReadAllText($Path, $utf8)
    $original = $text
    $removed = 0
    $searchKey = '"' + $PropertyName + '":'
    while ($true) {
        $startIdx = $text.IndexOf($searchKey)
        if ($startIdx -lt 0) { break }
        $valueStart = $startIdx + $searchKey.Length
        while ($valueStart -lt $text.Length -and [char]::IsWhiteSpace($text[$valueStart])) { $valueStart++ }
        if ($valueStart -ge $text.Length) { break }
        $ch = $text[$valueStart]
        $endIdx = -1
        if ($ch -eq '{' -or $ch -eq '[') {
            $open  = $ch; $close = if ($open -eq '{') { '}' } else { ']' }
            $depth = 1; $i = $valueStart + 1
            while ($depth -gt 0 -and $i -lt $text.Length) {
                $c = $text[$i]
                if ($c -eq '"') { $i++; while ($i -lt $text.Length -and $text[$i] -ne '"') { if ($text[$i] -eq '\') { $i++ }; $i++ } }
                elseif ($c -eq $open) { $depth++ }
                elseif ($c -eq $close) { $depth-- }
                $i++
            }
            $endIdx = $i
        } elseif ($ch -eq '"') {
            $i = $valueStart + 1
            while ($i -lt $text.Length -and $text[$i] -ne '"') { if ($text[$i] -eq '\') { $i++ }; $i++ }
            $endIdx = $i + 1
        } else {
            $i = $valueStart
            while ($i -lt $text.Length -and $text[$i] -notin @(',','}',']')) { $i++ }
            $endIdx = $i
        }
        if ($endIdx -lt 0) { break }
        $cutStart = $startIdx; $cutEnd = $endIdx
        $j = $cutStart - 1
        while ($j -ge 0 -and [char]::IsWhiteSpace($text[$j])) { $j-- }
        if ($j -ge 0 -and $text[$j] -eq ',') { $cutStart = $j }
        else {
            $k = $cutEnd
            while ($k -lt $text.Length -and [char]::IsWhiteSpace($text[$k])) { $k++ }
            if ($k -lt $text.Length -and $text[$k] -eq ',') { $cutEnd = $k + 1 }
        }
        $text = $text.Substring(0, $cutStart) + $text.Substring($cutEnd)
        $removed++
    }
    if ($removed -gt 0 -and $text -ne $original -and -not $DryRun) {
        $stamp = (Get-Date).ToString('yyyyMMddHHmmss')
        Copy-Item -LiteralPath $Path -Destination "$Path.bak.$stamp" -Force
        [System.IO.File]::WriteAllText($Path, $text, $utf8)
    }
    return $removed
}

# Find extension IDs in a given profile's Secure Preferences whose
# disable_reasons bitfield intersects $ResetReasonsBitmask.
function Find-CorruptedIds {
    param([string]$SecurePrefsPath)
    if (-not (Test-Path -LiteralPath $SecurePrefsPath)) { return @() }
    $sp = Get-Content -LiteralPath $SecurePrefsPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction SilentlyContinue
    if (-not $sp.extensions.settings) { return @() }
    $hits = @()
    foreach ($prop in $sp.extensions.settings.PSObject.Properties) {
        $entry = $prop.Value
        if ($entry.disable_reasons) {
            $sum = 0
            foreach ($r in @($entry.disable_reasons)) { $sum = $sum -bor [int]$r }
            if ($sum -band $ResetReasonsBitmask) {
                $hits += [pscustomobject]@{
                    Id     = $prop.Name
                    Sum    = $sum
                    Reasons = @($entry.disable_reasons)
                }
            }
        }
    }
    return $hits
}

# --- Main -------------------------------------------------------------------

Write-Host "Reset-CorruptedExtensions  (bitmask=$ResetReasonsBitmask, DryRun=$($DryRun.IsPresent))" -ForegroundColor Cyan

if (-not $NoBrowserKill -and -not $DryRun) {
    if ($Browser -in @('Both','Chrome')) { Close-Browser -ProcessName 'chrome' }
    if ($Browser -in @('Both','Edge'))   { Close-Browser -ProcessName 'msedge' }
}

$roots = @()
if ($Browser -in @('Both','Chrome')) { $roots += "$env:LOCALAPPDATA\Google\Chrome\User Data" }
if ($Browser -in @('Both','Edge'))   { $roots += "$env:LOCALAPPDATA\Microsoft\Edge\User Data" }

$totalEntries = 0; $totalRemoved = 0
foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $profileDirs = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(Default|Profile \d+)$' }
    foreach ($pd in $profileDirs) {
        $sp = Join-Path $pd.FullName 'Secure Preferences'
        $hits = Find-CorruptedIds -SecurePrefsPath $sp
        if (-not $hits) { continue }
        $totalEntries += $hits.Count
        foreach ($h in $hits) {
            $bn = (Split-Path -Leaf $root)
            Write-Host ("  [{0}\{1}] {2}  disable_reasons=({3})  -> bitmask hit" -f $bn, $pd.Name, $h.Id, ($h.Reasons -join ',')) -ForegroundColor Yellow
            if (-not $DryRun) {
                $n1 = Remove-JsonProperty -Path (Join-Path $pd.FullName 'Preferences')        -PropertyName $h.Id
                $n2 = Remove-JsonProperty -Path (Join-Path $pd.FullName 'Secure Preferences') -PropertyName $h.Id
                $totalRemoved += ($n1 + $n2)
                Write-Host ("       removed {0} JSON entries across Preferences + Secure Preferences" -f ($n1 + $n2)) -ForegroundColor Green
            }
        }
    }
}

Write-Host ''
if ($totalEntries -eq 0) {
    Write-Host 'No corrupted extension registrations found. All profiles are clean.' -ForegroundColor Green
} else {
    if ($DryRun) {
        Write-Host ("DryRun: would reset {0} extension registration(s). Re-run without -DryRun to apply." -f $totalEntries) -ForegroundColor Cyan
    } else {
        Write-Host ("Reset complete: cleared $totalEntries extension registration(s) ($totalRemoved JSON entries removed)") -ForegroundColor Green
        Write-Host 'Next browser launch will trigger a clean forcelist install of each affected extension.' -ForegroundColor Green
    }
}
