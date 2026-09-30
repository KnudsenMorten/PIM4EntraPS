# =====================================================================================================================
#  PIM Activator for Microsoft Edge and Google Chrome -- settings + "repair on request"   Intune Remediation: REMEDIATION
# =====================================================================================================================
#
#  WHAT IT DOES -- two jobs, in this order
#
#   1. SETTINGS (every run). Writes the PIM Activator extension's settings on this device, so users get the right
#      tenants, defaults and limits without any setup -- for every browser in $Browsers (Edge, Chrome or both). Only
#      these registry values are written (the browser hands them to the extension as "managed storage"):
#
#        Edge:    HKLM\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<extension id>\policy
#        Chrome:  HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<extension id>\policy
#            tenantCatalog                  REG_SZ     the tenants (JSON)                       always written
#            autoActivateMaxGroups          REG_DWORD  the auto-activate cap                    written, or removed when $null
#            bulkActivateConfirmThreshold   REG_DWORD  the "click again to confirm" threshold   written, or removed when $null
#
#      The extension id is the same in both browsers (one signed package). Each key belongs to the extension alone, so it
#      never conflicts with any other extension policy. This part never touches the browsers themselves and works while
#      they are open. A browser left out of $Browsers is not touched (its values stay as they are).
#
#   2. REPAIR (only when somebody asked for it). If the extension is stuck (e.g. an old version that does not update),
#      a user or an admin sets the repair flag:
#
#        user, no admin rights needed (run in the user's own session, e.g. from a Command Prompt):
#            reg add HKCU\Software\PIM4EntraPS\PimActivator /v RepairStuck /t REG_DWORD /d 1 /f
#        admin, for the whole device:
#            reg add HKLM\SOFTWARE\PIM4EntraPS\PimActivator /v RepairStuck /t REG_DWORD /d 1 /f
#
#      On the next run this script then, for every Edge / Chrome profile (the browsers in $Browsers) of every user:
#        - cuts PIM Activator's entries out of the profile's "Preferences" and "Secure Preferences" files
#          (each file is copied to "<file>.bak-<date-time>" first), and
#        - deletes PIM Activator's installed program files (the "Extensions\<extension id>" folder),
#      and finally DELETES the flag. The next time the browser starts, the policy that force-installs the extension
#      (Edge: the Edge management service; Chrome: its ExtensionInstallForcelist policy) installs the current version fresh.
#
#      HOW THE FILES ARE CHANGED -- and why it is done this way: the entries are cut out as TEXT (only the
#      "<extension id>": { ... } blocks are removed; every other byte of the file stays exactly as Edge wrote it).
#      The files are NOT read and re-written with PowerShell's JSON converter: on 2026-06-09 that method corrupted a
#      Preferences file under Windows PowerShell 5.1 and Edge reset the whole profile (bookmarks, history, tabs).
#      A file that does not look like Edge's JSON before or after the cut is left untouched.
#
#      What the repair does NOT touch: bookmarks, passwords, history, cookies, other extensions, sync.
#      What the user will notice: PIM Activator is reinstalled, so the user signs in to it again, and its own saved
#      data (favorites, "auto" ticks, an imported catalog) may be gone -- Edge treats it as a new install.
#
#      The browser must be CLOSED for the repair: it rewrites these files when it exits, which would undo it. So while
#      Edge or Chrome (those in $Browsers) is running the repair does nothing, keeps the flag and says so -- the next run
#      tries again (e.g. every hour). Set $CloseEdge = $true to close the browsers instead -- it covers Edge AND Chrome
#      (the name is kept so existing copies keep working); open tabs come back when the user reopens the browser.
#      Note: a browser set to keep running in the background ("Startup boost" / "Continue running background
#      extensions and apps when ... is closed") counts as running.
#
#  WHAT IT DOES NOT DO
#    It does NOT install the extension -- the browser policy does: for Edge the Microsoft Edge management service (a
#    Cloud policy that forces the extension with its update URL -- see README.md, step 1); for Chrome the
#    ExtensionInstallForcelist policy with the same id + update URL.
#
#  HOW TO USE IT
#    1. Copy this script AND Detect-PimActivator.ps1.
#    2. Edit the SETTINGS block below -- the SAME values in both scripts (the Detect script compares against them).
#    3. Intune admin center -> Devices -> Scripts and remediations -> Create:
#         Detection script file   = Detect-PimActivator.ps1
#         Remediation script file = this file
#         Run this script using the logged-on credentials = No    (runs as SYSTEM -- needed to write under
#                                                                  HKLM\SOFTWARE\Policies and to repair every profile)
#         Enforce script signature check                  = No    (unless you sign the scripts)
#         Run script in 64-bit PowerShell                 = Yes
#       Assign it to the same group as the Edge policy that installs the extension (a user group works: it runs on
#       that user's devices), and schedule it -- every hour is a good choice (a requested repair then happens within
#       the hour once Edge is closed). Or upload it with ..\Publish-PimActivatorRemediation.ps1.
#    4. Edge picks up new settings on its next policy refresh; edge://policy -> "Reload policies" shows them at once.
#
#  ONE REMEDIATION PER CHANNEL AND SET OF VALUES
#    Production and test are two extensions (two ids): one Remediation each, e.g. "PIM Activator settings (PROD)"
#    ($Channel = 'Released') and "PIM Activator settings (TEST)" ($Channel = 'Test'). Groups that need DIFFERENT values
#    need their own Remediation and should not overlap (a device in both runs both; the last one wins).
#    The repair clears BOTH PIM Activator extensions (production and test) on a flagged device -- a healthy one is
#    simply reinstalled by its Edge policy.
#
#  RESULT CODES (shown in Intune)
#    exit 0 = settings written, and the repair done if one was requested
#    exit 1 = settings could not be written, OR a requested repair is still waiting for Edge to be closed
#             (the output says which; the next run tries again)
# =====================================================================================================================

# ================================================ SETTINGS -- edit these ================================================

# Which extension: 'Released' = production (id eheocihmlppcophaeakmdenhgcookkab)
#                  'Test'     = test build   (id glldnbmjpdkjemcnficagdhgienfdpoo)
$Channel = 'Released'

# Which browsers get the settings (and the repair): 'Edge', 'Chrome', or both. Same extension id in both.
$Browsers = @('Edge', 'Chrome')

# The tenants users can sign in to -- one { ... } per tenant, separated by commas. The first one is the default.
#   Required fields
#     "name"                 name shown in the tenant switcher
#     "tenantId"             the Entra tenant id (GUID)
#     "clientId"             the application id of the "PIM Activator" app registration in THAT tenant (GUID)
#   Optional fields
#     "defaultJustification" pre-filled justification on the Activate form   (default "Change in infrastructure")
#     "defaultDurationHours" pre-filled duration in hours, 1-24              (default 8; each role's PIM policy can cap it)
#     "prefix"               only list groups whose name starts with this, e.g. "PIM-" (or a list: ["PIM-","ADM-"])
#     "entraPrefix"          name text that puts a group in the "Entra" section,  e.g. ["PIM-Entra","PIM-AAD"]
#     "azurePrefix"          name text that puts a group in the "Azure" section,  e.g. ["PIM-Azure","PIM-AzRes"]
#     "groupNameFilter"      advanced: a regular expression instead of "prefix"      (wins over "prefix")
#     "entraGroupRegex"      advanced: a regular expression instead of "entraPrefix" (default "Entra")
#     "azureGroupRegex"      advanced: a regular expression instead of "azurePrefix" (default "AzRes|Azure")
#     "bulkActivateConfirmThreshold"  this tenant's own confirm threshold (overrides the device-wide one below)
#   Groups that match neither the Entra nor the Azure text are listed under "PIM for Groups".
$TenantCatalog = @'
[
  { "name": "Contoso", "tenantId": "00000000-0000-0000-0000-000000000000", "clientId": "00000000-0000-0000-0000-000000000000",
    "defaultJustification": "Change in infrastructure", "defaultDurationHours": 8 }
]
'@

# Auto-activate cap: how many groups a user may tick as "auto" (activated automatically when the popup opens).
#   $null  = no limit (the value is removed from the device)
#   0      = auto-activation is turned OFF on this device
#   1-100  = at most this many groups. Ticking one more is refused with a message; if more are already ticked,
#            only the first N are activated and the rest are marked "Not auto-activated".
#   Needs PIM Activator 1.6.128 or later (older versions ignore it).
$AutoActivateMaxGroups = $null

# Confirm threshold: when a user selects at least this many roles, the Activate button asks for a second click.
#   $null  = the built-in default (5) -- the value is removed from the device
#   1-100  = your threshold. A tenant's own "bulkActivateConfirmThreshold" in the catalog wins over this.
$BulkActivateConfirmThreshold = $null

# Repair on request: what to do when the RepairStuck flag is set but the browser (Edge / Chrome) is open.
#   $false = wait -- change nothing, keep the flag, try again on the next run (recommended)
#   $true  = close the browsers and repair now
$CloseEdge = $false

# ========================================================================================================================

# --- nothing to edit below this line ---
$ExtensionId  = if ($Channel -eq 'Test') { 'glldnbmjpdkjemcnficagdhgienfdpoo' } else { 'eheocihmlppcophaeakmdenhgcookkab' }
$AllExtensionIds = @('eheocihmlppcophaeakmdenhgcookkab', 'glldnbmjpdkjemcnficagdhgienfdpoo')   # production, test
# Per browser: its policy root, its process name and where each user's profiles are (the SAME extension id in both).
$BrowserInfo  = @{
    Edge   = @{ Root = 'SOFTWARE\Policies\Microsoft\Edge'; Process = 'msedge'; UserData = 'AppData\Local\Microsoft\Edge\User Data' }
    Chrome = @{ Root = 'SOFTWARE\Policies\Google\Chrome';  Process = 'chrome'; UserData = 'AppData\Local\Google\Chrome\User Data' }
}
$Selected     = @($Browsers | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
$unknown      = @($Selected | Where-Object { -not $BrowserInfo.ContainsKey($_) })
if (-not $Selected.Count -or $unknown.Count) { Write-Output "FAILED: `$Browsers must be 'Edge', 'Chrome' or both (got '$($Browsers -join "', '")')."; exit 1 }
# The catalog is stored compact and always as a list [ ... ]. The "| ForEach-Object { $_ }" keeps it a plain list on
# Windows PowerShell 5.1 (which Intune uses) -- without it 5.1 stores {"value":[...],"Count":1} and sign-in breaks.
$Catalog      = ConvertTo-Json -InputObject @($TenantCatalog | ConvertFrom-Json | ForEach-Object { $_ }) -Depth 10 -Compress
# Where the repair flag can be: the device (HKLM) and every signed-in user (their HKCU = HKEY_USERS\<user SID>).
$FlagKeys     = @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\PIM4EntraPS\PimActivator') +
                @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                  Where-Object { $_.PSChildName -like 'S-1-*' -and $_.PSChildName -notlike '*_Classes' } |
                  ForEach-Object { "Registry::$($_.Name)\Software\PIM4EntraPS\PimActivator" })

# ---- 1. SETTINGS -----------------------------------------------------------------------------------------------------
try {
    foreach ($b in $Selected) {
        # The 64-bit registry on purpose: Intune runs scripts 32-bit unless told otherwise, and neither browser reads the
        # 32-bit copy (WOW6432Node).
        $keyPath = "$($BrowserInfo[$b].Root)\3rdparty\extensions\$ExtensionId\policy"
        $key = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64').CreateSubKey($keyPath, $true)
        $key.SetValue('tenantCatalog', $Catalog, 'String')
        if ($null -ne $AutoActivateMaxGroups)        { $key.SetValue('autoActivateMaxGroups', [int]$AutoActivateMaxGroups, 'DWord') }
        else                                         { $key.DeleteValue('autoActivateMaxGroups', $false) }
        if ($null -ne $BulkActivateConfirmThreshold) { $key.SetValue('bulkActivateConfirmThreshold', [int]$BulkActivateConfirmThreshold, 'DWord') }
        else                                         { $key.DeleteValue('bulkActivateConfirmThreshold', $false) }
        $key.Close()
    }
    Write-Output ("Settings written ({0}; {4}): {1} tenant(s), cap = {2}, confirm threshold = {3}." -f $Channel,
        @($TenantCatalog | ConvertFrom-Json | ForEach-Object { $_ }).Count,
        $(if ($null -eq $AutoActivateMaxGroups) { 'none' } else { $AutoActivateMaxGroups }),
        $(if ($null -eq $BulkActivateConfirmThreshold) { 'default' } else { $BulkActivateConfirmThreshold }),
        ($Selected -join ' + '))
} catch {
    Write-Output "FAILED to write the PIM Activator settings: $($_.Exception.Message)"
    exit 1
}

# ---- 2. REPAIR, only when the flag is set ----------------------------------------------------------------------------
$flagged = @($FlagKeys | Where-Object { (Get-ItemProperty -Path $_ -Name RepairStuck -ErrorAction SilentlyContinue).RepairStuck -eq 1 })
if (-not $flagged) { exit 0 }

$procNames = @($Selected | ForEach-Object { $BrowserInfo[$_].Process })
$running = @(Get-Process -Name $procNames -ErrorAction SilentlyContinue)
if ($running -and -not $CloseEdge) {
    $open = (@($running | ForEach-Object { if ($_.ProcessName -eq 'chrome') { 'Chrome' } else { 'Edge' } } | Select-Object -Unique)) -join ' and '
    Write-Output "Repair requested, but $open is open -- nothing changed in the browser, the request is kept and the next run tries again."
    exit 1
}
if ($running) { $running | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 3 }

# Cut every  "<key>": <value>  out of JSON TEXT (value = { }, [ ], a string or a plain value) plus one neighbouring
# comma, so the JSON stays valid. Text only -- the rest of the file is kept byte for byte (see the header for why).
# The same method Update-PimActivator-Extension.ps1 uses since the 2026-06-09 incident.
function Remove-PaJsonKey([string]$Text, [string]$Key) {
    $needle = '"' + $Key + '":'
    while ($true) {
        $s = $Text.IndexOf($needle); if ($s -lt 0) { break }
        $v = $s + $needle.Length
        while ($v -lt $Text.Length -and [char]::IsWhiteSpace($Text[$v])) { $v++ }
        if ($v -ge $Text.Length) { break }
        $c0 = $Text[$v]
        if ($c0 -eq '{' -or $c0 -eq '[') {
            $open = $c0; $close = if ($open -eq '{') { '}' } else { ']' }; $depth = 1; $i = $v + 1
            while ($depth -gt 0 -and $i -lt $Text.Length) {
                $c = $Text[$i]
                if ($c -eq '"') { $i++; while ($i -lt $Text.Length -and $Text[$i] -ne '"') { if ($Text[$i] -eq '\') { $i++ }; $i++ } }
                elseif ($c -eq $open) { $depth++ } elseif ($c -eq $close) { $depth-- }
                $i++
            }
            $end = $i
        } elseif ($c0 -eq '"') {
            $i = $v + 1; while ($i -lt $Text.Length -and $Text[$i] -ne '"') { if ($Text[$i] -eq '\') { $i++ }; $i++ }; $end = $i + 1
        } else {
            $i = $v; while ($i -lt $Text.Length -and $Text[$i] -notin @(',', '}', ']')) { $i++ }; $end = $i
        }
        $cs = $s; $ce = $end
        $j = $cs - 1; while ($j -ge 0 -and [char]::IsWhiteSpace($Text[$j])) { $j-- }
        if ($j -ge 0 -and $Text[$j] -eq ',') { $cs = $j }
        else { $k = $ce; while ($k -lt $Text.Length -and [char]::IsWhiteSpace($Text[$k])) { $k++ }; if ($k -lt $Text.Length -and $Text[$k] -eq ',') { $ce = $k + 1 } }
        $Text = $Text.Substring(0, $cs) + $Text.Substring($ce)
    }
    return $Text
}
# True when the text is ONE balanced { ... } object (braces/brackets counted outside strings) -- a cheap check that the
# cut left a well-formed file, done without re-serialising anything.
function Test-PaJsonBalanced([string]$Text) {
    $t = $Text.Trim(); if (-not ($t.StartsWith('{') -and $t.EndsWith('}'))) { return $false }
    $depth = 0; $i = 0
    while ($i -lt $t.Length) {
        $c = $t[$i]
        if ($c -eq '"') { $i++; while ($i -lt $t.Length -and $t[$i] -ne '"') { if ($t[$i] -eq '\') { $i++ }; $i++ } }
        elseif ($c -eq '{' -or $c -eq '[') { $depth++ }
        elseif ($c -eq '}' -or $c -eq ']') { $depth--; if ($depth -lt 0) { return $false }; if ($depth -eq 0 -and $i -ne $t.Length - 1) { return $false } }
        $i++
    }
    return ($depth -eq 0)
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$cleared = 0
# Every user's Edge / Chrome profiles -- the script runs as SYSTEM, so it walks C:\Users rather than its own profile.
$userDataDirs = foreach ($b in $Selected) { Get-ChildItem -Path "$env:SystemDrive\Users\*\$($BrowserInfo[$b].UserData)" -Directory -ErrorAction SilentlyContinue }
foreach ($userData in @($userDataDirs)) {
    foreach ($browserProfile in Get-ChildItem -LiteralPath $userData.FullName -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }) {
        foreach ($id in $AllExtensionIds) {
            # PIM Activator's installed program files -- Edge downloads the current version again on its next start.
            $installed = Join-Path $browserProfile.FullName "Extensions\$id"
            if (Test-Path -LiteralPath $installed) { Remove-Item -LiteralPath $installed -Recurse -Force -ErrorAction SilentlyContinue }
        }
        foreach ($file in 'Preferences', 'Secure Preferences') {
            $path = Join-Path $browserProfile.FullName $file
            if (-not (Test-Path -LiteralPath $path)) { continue }
            $utf8 = New-Object System.Text.UTF8Encoding($false)
            $text = [IO.File]::ReadAllText($path, $utf8)
            if (-not $text.TrimStart().StartsWith('{')) { continue }   # not Edge's JSON -- leave it alone
            $new = $text
            foreach ($id in $AllExtensionIds) { $new = Remove-PaJsonKey -Text $new -Key $id }
            if ($new -eq $text) { continue }                          # PIM Activator not in this file
            # safety check: the result must still be one JSON object (balanced braces, outside strings)
            if (-not (Test-PaJsonBalanced $new)) { Write-Output "Skipped (safety check): $($browserProfile.FullName)\$file was left unchanged"; continue }
            Copy-Item -LiteralPath $path -Destination "$path.bak-$stamp" -Force
            [IO.File]::WriteAllText($path, $new, $utf8)
            $cleared++
            Write-Output "Repaired: cut PIM Activator out of $($browserProfile.FullName)\$file (backup: $file.bak-$stamp)"
        }
    }
}
# The request is done -- delete the flag everywhere it was set.
foreach ($k in $flagged) { Remove-ItemProperty -Path $k -Name RepairStuck -ErrorAction SilentlyContinue }
Write-Output "Repair done ($($Selected -join ' + ')): $cleared file(s) cleared, RepairStuck flag deleted. The browser installs the current PIM Activator on its next start."
exit 0
