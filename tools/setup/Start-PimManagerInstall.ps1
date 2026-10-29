#Requires -Version 5.1
# BUILD-NO-OPTIONAL-LOADS

<#
.SYNOPSIS
  Install PIM Manager with one command: download the public PIM Manager release into a new folder, check the download, and run its guided installer (Install-PimManager) with the parameters you give.
  INSTALL-SAMPLES (owner 2026-10-29: "samples to install interactive is missing ... so i am loosing business").

.DESCRIPTION
  The ONE file a person downloads to install PIM Manager (https://invardia.com/support/pim/Start-PimManagerInstall.ps1).
  Line 1 downloads it, line 2 runs it (see the examples). It:
    1. reads the public release from GitHub (the latest, or -Version), and downloads its zip into a NEW, empty folder in
       the temp folder;
    2. computes the SHA-256 of the download and, when the release publishes one for the zip, compares the two -- a
       difference stops here, the folder is removed and nothing is installed;
    3. unpacks it and runs tools/setup/Install-PimManager.ps1 FROM that folder with exactly the parameters you gave (the
       same parameters as Install-PimManager; its help has the details), and ends with its exit code;
    4. prints where the files are. -Resume uses that folder again (no new download); the folder is remembered per tenant
       and subscription in the temp folder. When it is gone (a new Cloud Shell session), -Resume downloads the release
       again -- the installation's own progress is kept in its state folder, so it still continues where it stopped.
  -ReleasePath <folder> runs the installer from a release you already have (nothing is downloaded).

  Browser sign-in (your own administrator account): no Azure CLI, no PowerShell modules, no secret, no certificate.
  PowerShell 7 (Azure Cloud Shell, or PowerShell 7 on Windows, macOS or Linux). Only -TenantId and -SubscriptionId are
  needed; without a licence file or an enrollment key it installs PIM Manager Community (free). Several tenants (MSP)
  are PIM Manager Pro through Invardia's managed-tenant installation, not this command.

  Exit codes: those of Install-PimManager (0 done, 1 a step failed -- fix it and -Resume, 2 a check failed -- nothing was
  changed, 3 bad answers -- nothing was changed); 3 also when the release cannot be read or the download does not match.

.EXAMPLE
  Invoke-WebRequest https://invardia.com/support/pim/Start-PimManagerInstall.ps1 -OutFile Start-PimManagerInstall.ps1
  .\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>'
  The most common: PIM Manager Community in your own subscription, signed in in the browser, every other answer a default.
.EXAMPLE
  Invoke-WebRequest https://invardia.com/support/pim/Start-PimManagerInstall.ps1 -OutFile Start-PimManagerInstall.ps1
  .\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -WhatIf
  To see the plan first: the checks run, then every step the installation would take is printed, and nothing is changed.
.EXAMPLE
  Invoke-WebRequest https://invardia.com/support/pim/Start-PimManagerInstall.ps1 -OutFile Start-PimManagerInstall.ps1
  .\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -Location westeurope -ResourceGroup rg-pim-manager -SuperAdmins 'admin1@contoso.com','admin2@contoso.com' -AlertRecipients 'pim-alerts@contoso.com'
  When you choose the region and the resource group yourself, and name the PIM Manager administrators and who gets the alerts.
.EXAMPLE
  Invoke-WebRequest https://invardia.com/support/pim/Start-PimManagerInstall.ps1 -OutFile Start-PimManagerInstall.ps1
  .\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -EnrollmentKey '<enrollment key>'
  Pro or a trial: the same, plus the enrollment key from Invardia's portal or your trial mail (or -LicencePath <your licence file> instead).
.EXAMPLE
  Invoke-WebRequest https://invardia.com/support/pim/Start-PimManagerInstall.ps1 -OutFile Start-PimManagerInstall.ps1
  .\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -Resume
  After a stop: run the same command with -Resume; the downloaded release is used again and finished steps are skipped.

.NOTES
  Reads: the release metadata at api.github.com (public, no sign-in) and the release zip it names. Writes: a new folder
  in the temp folder (the zip and its unpacked files) and a small note there with that folder's path; everything else is
  the installer's (see Install-PimManager).

.LINK
  https://invardia.com/docs/pim/scripts/Start-PimManagerInstall/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # --- the installer's parameters, passed through unchanged (Install-PimManager has the details) ---
    [string]$TenantId = '',
    [string]$SubscriptionId = '',
    [string]$Location = '',
    [string]$ResourceGroup = '',
    [string[]]$SuperAdmins = @(),
    [string[]]$AlertRecipients = @(),
    [string]$MailSender = '',
    [string]$VnetAddressPrefix = '',
    [string]$SubnetAddressPrefix = '',
    [string]$Exposure = '',
    [ValidateSet('', 'Community', 'Trial', 'Pro')][string]$Edition = '',
    [string]$InstallId = '',
    [string]$SupportAppId = '',
    [ValidateSet('', 'troubleshoot', 'setup', 'asbuilt')][string]$SupportAccess = '',
    [string]$LicencePath = '',
    [string]$EnrollmentKey = '',
    [string]$ConfigPath = '',
    [scriptblock]$Reporter,
    [string]$StatePath = '',
    [switch]$Resume,
    [switch]$PreflightOnly,
    [string]$InvardiaBaseUrl = '',
    [int]$EnrollmentTimeoutSeconds = 0,
    # --- this launcher's own ---
    # the release to install (e.g. 3.0.5); default: the latest public release
    [string]$Version = '',
    # a folder that already holds the unpacked release: nothing is downloaded
    [string]$ReleasePath = '',
    # --- test seams (offline tests/Test-PimGuidedInstall.ps1 + the -WhatIf case); omit them for a real install ---
    [scriptblock]$GetRelease,
    [scriptblock]$Download,
    [scriptblock]$RunInstaller
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')     # framework 12.7: the version line + the transcript (inlined in the published file)
$null = Start-PimScriptRun -Script 'Start-PimManagerInstall'
$launchCode = 0
try {
    $pimRepo = 'KnudsenMorten/PIM4EntraPS'
    if ($PSVersionTable.PSVersion.Major -lt 7) { Write-Host 'This runs best in PowerShell 7 (Azure Cloud Shell, or pwsh on your machine).' -ForegroundColor Yellow }
    if (-not $GetRelease) {
        $GetRelease = { param([string]$Url) Invoke-RestMethod -Method GET -Uri $Url -Headers @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'PIM-Manager-Installer' } -TimeoutSec 60 }
    }
    if (-not $Download) {
        $Download = { param([string]$Url, [string]$OutFile) Invoke-WebRequest -Method GET -Uri $Url -OutFile $OutFile -UseBasicParsing -Headers @{ 'User-Agent' = 'PIM-Manager-Installer' } -TimeoutSec 900 | Out-Null }
    }
    if (-not $RunInstaller) {
        $RunInstaller = { param([string]$Path, [hashtable]$A) $global:LASTEXITCODE = 0; & $Path @A | Out-Host; [int]$LASTEXITCODE }
    }
    $tempRoot = [IO.Path]::GetTempPath()
    $sha256Hex = {
        param([string]$Path)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $fs = [IO.File]::OpenRead($Path)
        try { return (-join ($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') })) } finally { $fs.Dispose(); $sha.Dispose() }
    }
    # the folder note: one per tenant + subscription (or answers file), so -Resume finds the release it downloaded
    $noteKeySrc = if ("$TenantId".Trim() -and "$SubscriptionId".Trim()) { ("{0}|{1}" -f "$TenantId".Trim(), "$SubscriptionId".Trim()).ToLowerInvariant() } elseif ("$ConfigPath".Trim()) { "$ConfigPath".Trim().ToLowerInvariant() } else { 'default' }
    $sha0 = [System.Security.Cryptography.SHA256]::Create()
    try { $noteKey = -join ($sha0.ComputeHash([Text.Encoding]::UTF8.GetBytes($noteKeySrc))[0..5] | ForEach-Object { $_.ToString('x2') }) } finally { $sha0.Dispose() }
    $notePath = Join-Path $tempRoot "pim-manager-install-$noteKey.json"
    $findTree = {
        # the release tree inside an unpacked folder: VERSION at the top, or in its one sub-folder
        param([string]$Dir)
        if (Test-Path -LiteralPath (Join-Path $Dir 'tools/setup/Install-PimManager.ps1')) { return $Dir }
        $tops = @(Get-ChildItem -LiteralPath $Dir -Directory -ErrorAction SilentlyContinue)
        if ($tops.Count -eq 1 -and (Test-Path -LiteralPath (Join-Path $tops[0].FullName 'tools/setup/Install-PimManager.ps1'))) { return $tops[0].FullName }
        return ''
    }

    # one pass; a stop on the way sets $launchCode and leaves it with 'break' (the exit code is set after the transcript closes)
    do {
    # ---------------------------------------------------------------- 1. the release folder: given, remembered, or new
    $tree = ''
    if ("$ReleasePath".Trim()) {
        $tree = & $findTree ([IO.Path]::GetFullPath("$ReleasePath".Trim()))
        if (-not $tree) { Write-Host "The folder '$ReleasePath' does not hold a PIM Manager release (tools/setup/Install-PimManager.ps1 is not there)." -ForegroundColor Red; $launchCode = 3; break }
        Write-Host "Using the release in $tree (nothing is downloaded)."
    } elseif ($Resume -and (Test-Path -LiteralPath $notePath)) {
        $note = $null; try { $note = [IO.File]::ReadAllText($notePath) | ConvertFrom-Json } catch { $note = $null }
        if ($note -and "$($note.path)".Trim() -and (Test-Path -LiteralPath "$($note.path)")) {
            $tree = & $findTree "$($note.path)"
            if ($tree) { Write-Host "Resume: using the release downloaded before ($($note.version)) in $tree -- nothing is downloaded." }
        }
        if (-not $tree) { Write-Host 'Resume: the release folder of the first run is not there any more, so the release is downloaded again. The installation keeps its own progress, so it still continues where it stopped.' -ForegroundColor Yellow }
    }
    if (-not $tree) {
        $relUrl = if ("$Version".Trim()) { "https://api.github.com/repos/$pimRepo/releases/tags/v$("$Version".Trim().TrimStart('v'))" } else { "https://api.github.com/repos/$pimRepo/releases/latest" }
        $rel = $null
        try { $rel = & $GetRelease $relUrl } catch { $rel = $null; Write-Verbose "$($_.Exception.Message)" }
        if (-not $rel) { Write-Host "The PIM Manager release could not be read from GitHub ($relUrl). Check the network and run the command again." -ForegroundColor Red; $launchCode = 3; break }
        $relVer = "$($rel.tag_name)".Trim().TrimStart('v')
        $asset = @(@($rel.assets) | Where-Object { "$($_.name)" -match '^PIM4EntraPS-v[0-9][0-9A-Za-z.+-]*\.zip$' }) | Select-Object -First 1
        if (-not $asset -or -not "$($asset.browser_download_url)".Trim()) { Write-Host "The release $relVer has no PIM Manager zip to download." -ForegroundColor Red; $launchCode = 3; break }
        $published = if ("$($asset.digest)" -match '^(?i)sha256:([0-9a-f]{64})$') { $Matches[1].ToLowerInvariant() } else { '' }
        $dir = Join-Path $tempRoot ("pim-manager-release-{0}-{1}" -f $relVer, [guid]::NewGuid().ToString('N').Substring(0, 6))
        [void][IO.Directory]::CreateDirectory($dir)
        $zip = Join-Path $dir 'release.zip'
        Write-Host "PIM Manager release $relVer -- downloading $($asset.name) into $dir"
        try { & $Download "$($asset.browser_download_url)" $zip } catch { Write-Verbose "$($_.Exception.Message)" }
        if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) { Write-Host 'The download did not complete. Check the network and run the command again.' -ForegroundColor Red; try { [IO.Directory]::Delete($dir, $true) } catch { }; $launchCode = 3; break }
        $got = & $sha256Hex $zip
        if ($published -and $got -ne $published) {
            Write-Host "The download does not match the SHA-256 the release publishes ($published; the download has $got). Nothing was installed; the folder is removed. Run the command again." -ForegroundColor Red
            try { [IO.Directory]::Delete($dir, $true) } catch { }
            $launchCode = 3; break
        }
        Write-Host $(if ($published) { "SHA-256 $got -- matches the SHA-256 the release publishes" } else { "SHA-256 $got" })
        $unpack = Join-Path $dir 'release'
        if (-not ('System.IO.Compression.ZipFile' -as [type])) { Add-Type -AssemblyName System.IO.Compression.FileSystem }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $unpack)
        $tree = & $findTree $unpack
        if (-not $tree) { Write-Host "The release $relVer does not hold tools/setup/Install-PimManager.ps1." -ForegroundColor Red; $launchCode = 3; break }
        $treeVer = $(try { "$([IO.File]::ReadAllText((Join-Path $tree 'VERSION')))".Trim() } catch { '' })
        if ("$Version".Trim() -and $treeVer -and $treeVer -ne "$Version".Trim().TrimStart('v')) { Write-Host "The release holds version $treeVer, not $Version." -ForegroundColor Red; $launchCode = 3; break }
        # -WhatIf writes nothing outside this new temp folder: the note is written by a real run only
        if (-not $WhatIfPreference) {
            try { [IO.File]::WriteAllText($notePath, ([ordered]@{ path = $tree; version = $(if ($treeVer) { $treeVer } else { $relVer }); savedUtc = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json), (New-Object Text.UTF8Encoding($false))) } catch { Write-Verbose "$($_.Exception.Message)" }
        }
    }
    Write-Host "Release files: $tree"
    Write-Host '  (to continue after a stop, run the same command again with -Resume -- this folder is used again)' -ForegroundColor DarkGray

    # ---------------------------------------------------------------- 2. run the installer from the release, same parameters
    $pass = @{}
    foreach ($k in @('TenantId', 'SubscriptionId', 'Location', 'ResourceGroup', 'SuperAdmins', 'AlertRecipients', 'MailSender', 'VnetAddressPrefix', 'SubnetAddressPrefix', 'Exposure', 'Edition', 'InstallId', 'SupportAppId', 'SupportAccess', 'LicencePath', 'EnrollmentKey', 'ConfigPath', 'Reporter', 'StatePath', 'Resume', 'PreflightOnly', 'InvardiaBaseUrl', 'EnrollmentTimeoutSeconds')) {
        if ($PSBoundParameters.ContainsKey($k)) { $pass[$k] = $PSBoundParameters[$k] }
    }
    if ($WhatIfPreference) { $pass['WhatIf'] = $true }
    $installer = Join-Path $tree 'tools/setup/Install-PimManager.ps1'
    $launchCode = [int](@(& $RunInstaller $installer $pass) | Select-Object -Last 1)
    if ($launchCode -ne 0) { Write-Host "Release files: $tree -- the same command with -Resume continues from here." -ForegroundColor Yellow }
    } while ($false)
} finally {
    Stop-PimScriptRun -Script 'Start-PimManagerInstall'   # framework 12.7: "Log written: <path>" on every exit
}
$global:LASTEXITCODE = $launchCode
exit $launchCode
