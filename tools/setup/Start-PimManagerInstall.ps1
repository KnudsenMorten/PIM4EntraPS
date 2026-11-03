#Requires -Version 7.0
# BUILD-NO-OPTIONAL-LOADS

<#
.SYNOPSIS
  Install PIM Manager with one command: download the public PIM Manager release into a new folder, check the download, and run its guided installer (Install-PimManager) with the parameters you give.
  Two short lines: line 1 downloads this file from the public release, line 2 runs the install with your values.

.DESCRIPTION
  The ONE file a person downloads to install PIM Manager. It is a file of the public PIM Manager release on GitHub:
  line 1 downloads it, line 2 runs it with your values (see the examples). It:
    1. checks that this file is the one published with its release -- a difference stops here, nothing is installed;
    2. reads the public release from GitHub (the latest, or -Version), and downloads its zip into a NEW, empty folder in
       the temp folder;
    3. checks the download against the release -- a difference stops here, the folder is removed and nothing is installed;
    4. unpacks it and runs tools/setup/Install-PimManager.ps1 FROM that folder with exactly the parameters you gave (the
       same parameters as Install-PimManager; its help has the details), and ends with its exit code;
    5. prints where the files are. -Resume uses that folder again (no new download); the folder is remembered per tenant
       and subscription in the temp folder. When it is gone (a new Cloud Shell session), -Resume downloads the release
       again -- the installation's own progress is kept in its state folder, so it still continues where it stopped.
  -ReleasePath <folder> runs the installer from a release you already have (nothing is downloaded).
  The copy Invardia gives Pro and trial customers does steps 2-3 with Invardia instead of GitHub: you sign in in the browser
  (an administrator of -TenantId), it asks Invardia for the PIM Manager Pro package of your update ring for that tenant, checks
  that Invardia sealed it (its signed manifest) and the download's size and SHA-256 against it, and then runs the installer from it the same
  way. If Invardia cannot be reached or refuses, it says so in one line and installs nothing -- it never falls back to GitHub.

  Browser sign-in (your own administrator account): no Azure CLI, no PowerShell modules, no secret, no certificate, no
  key and no licence in the command. PowerShell 7 (Azure Cloud Shell, or PowerShell 7 on Windows, macOS or Linux). Only
  -TenantId and -SubscriptionId are needed. The edition comes with the file, never with a parameter: the copy of the
  public GitHub release installs PIM Manager Community (free); the copy Invardia gives Pro and trial customers installs
  PIM Manager Pro, without a licence -- the installation asks Invardia for its licence by itself right after the
  install. Updates follow ring 3 (broad) unless -UpdateRing 2 is given. The Invardia Support app is named by its id with
  -SupportAppId, never found by name: it then gets 'troubleshoot' access unless -SupportAccess names another level;
  without -SupportAppId nothing is granted. -ViaSupportApp runs the install as the Invardia Support app: it needs a
  Connect-InvardiaSupport session for the same tenant in this PowerShell window. Several tenants (MSP) are set up with
  the managing-tenant build, not this command.
  Public network by default; -PrivateNetwork installs the private shape (no public address) with the same two lines, with
  SI's network parameters (-VnetId, -VnetAddressPrefix, -VnetName, -AppsSubnetName / -AppsSubnetPrefix,
  -EndpointsSubnetName / -EndpointsSubnetPrefix, -PrivateDnsZonesResourceGroupId, -HubVnetId with -PeerToHub /
  -LinkZonesToHub, -WebAppAccess); Install-PimManager's help has the details.

  Exit codes: those of Install-PimManager (0 done, 1 a step failed -- fix it and -Resume, 2 a check failed -- nothing was
  changed, 3 bad answers -- nothing was changed); 3 also when the release cannot be read or a check of the download fails.

.EXAMPLE
  Invoke-WebRequest https://github.com/KnudsenMorten/PIM4EntraPS/releases/latest/download/Start-PimManagerInstall.ps1 -OutFile Start-PimManagerInstall.ps1
  .\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>'
  The most common: PIM Manager Community in your own subscription, signed in in the browser, every other answer a default.
.EXAMPLE
  Invoke-WebRequest https://github.com/KnudsenMorten/PIM4EntraPS/releases/latest/download/Start-PimManagerInstall.ps1 -OutFile Start-PimManagerInstall.ps1
  .\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -WhatIf
  To see the plan first: the checks run, then every step the installation would take is printed, and nothing is changed.
.EXAMPLE
  Invoke-WebRequest https://github.com/KnudsenMorten/PIM4EntraPS/releases/latest/download/Start-PimManagerInstall.ps1 -OutFile Start-PimManagerInstall.ps1
  .\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -Location westeurope -ResourceGroup rg-pim-manager -SuperAdmins 'admin1@contoso.com','admin2@contoso.com' -AlertRecipients 'pim-alerts@contoso.com'
  When you choose the region and the resource group yourself, and name the PIM Manager administrators and who gets the alerts.
.EXAMPLE
  Invoke-WebRequest https://github.com/KnudsenMorten/PIM4EntraPS/releases/latest/download/Start-PimManagerInstall.ps1 -OutFile Start-PimManagerInstall.ps1
  .\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -SuperAdmins 'admin1@contoso.com' -ViaSupportApp
  Through the Invardia Support app, after Connect-InvardiaSupport for this tenant: the installation runs as that app, so name the PIM Manager administrators.
.EXAMPLE
  Invoke-WebRequest https://github.com/KnudsenMorten/PIM4EntraPS/releases/latest/download/Start-PimManagerInstall.ps1 -OutFile Start-PimManagerInstall.ps1
  .\Start-PimManagerInstall.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -Resume
  After a stop: run the same command with -Resume; the downloaded release is used again and finished steps are skipped.

.NOTES
  Requirements:
    PowerShell: 7.0 or later (pwsh; Azure Cloud Shell has it). Windows PowerShell 5.1 is not supported.
    Role: Owner on the target subscription (Azure); Privileged Role Administrator and Application Administrator
          (Microsoft Entra); Exchange Administrator only for the mail sender (optional).
    Hosts: github.com, api.github.com, objects.githubusercontent.com, release-assets.githubusercontent.com (the release);
           the Pro copy instead: login.microsoftonline.com (your browser sign-in) and invardia.com (the Pro package and the
           short-lived download link it names);
           then the installer's: login.microsoftonline.com, management.azure.com, graph.microsoft.com,
           *.database.windows.net (port 1433), *.azurecr.io, outlook.office365.com (mail sender)

  Reads: the release metadata at api.github.com (public, no sign-in) and the release zip it names (the Pro copy: the signed
  package answer from invardia.com, with your sign-in, and the zip it names). Writes: a new folder
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
    [string[]]$PortalUsers = @(),
    [switch]$AllowAllMembers,
    [string]$VnetAddressPrefix = '',
    [Parameter(DontShow)][string]$SubnetAddressPrefix = '',   # old name of -AppsSubnetPrefix (one release)
    [Parameter(DontShow)][string]$Exposure = '',              # old name: -Exposure internal = -PrivateNetwork (one release)
    # --- PRIVATE NETWORK (framework INSTALL-1 item 5): SI's names, passed through unchanged; public without -PrivateNetwork ---
    [switch]$PrivateNetwork,
    [string]$VnetId = '',
    [string]$VnetName = '',
    [string]$AppsSubnetName = '',
    [string]$AppsSubnetPrefix = '',
    [string]$EndpointsSubnetName = '',
    [string]$EndpointsSubnetPrefix = '',
    [string]$PrivateDnsZonesResourceGroupId = '',
    [string]$HubVnetId = '',
    [switch]$LinkZonesToHub,
    [switch]$PeerToHub,
    [ValidateSet('', 'external', 'internal')][string]$WebAppAccess = '',
    # INSTALL-1 ALIGN: not documented any more (the copy decides the edition, $script:PimInstallChannel below). Accepted for
    # ONE release so the 3.0.17 command lines keep working; when given it wins. Drop it in the next release.
    [ValidateSet('', 'Community', 'Trial', 'Pro')][string]$Edition = '',
    [ValidateSet('', '2', '3')][string]$UpdateRing = '3',
    [string]$KeyVaultName = '',
    [switch]$EngineAzureRootUserAccessAdmin,
    [string]$InstallId = '',
    [string]$SupportAppId = '',
    [ValidateSet('', 'troubleshoot', 'setup', 'asbuilt')][string]$SupportAccess = '',
    [scriptblock]$Reporter,
    [string]$StatePath = '',
    [switch]$Resume,
    [switch]$PreflightOnly,
    # run as the Invardia Support app: requires a Connect-InvardiaSupport session for -TenantId in this PowerShell window
    [switch]$ViaSupportApp,
    # --- this launcher's own ---
    # the release to install (e.g. 3.0.5); default: the latest public release
    [string]$Version = '',
    # a folder that already holds the unpacked release: nothing is downloaded
    [string]$ReleasePath = '',
    # --- test seams (offline tests/Test-PimGuidedInstall.ps1 + the -WhatIf case); omit them for a real install ---
    [scriptblock]$GetRelease,
    [scriptblock]$Download,
    [scriptblock]$RunInstaller,
    [string]$TestSelfVersion = '',
    # --- the Pro copy's seams (PRO-PACKAGE-FROM-INVARDIA): the sign-in { param($TenantId) } and Invardia's answer { param($Url, $Token) }
    [scriptblock]$GetInstallToken,
    [scriptblock]$InvardiaHttp
)
$ErrorActionPreference = 'Stop'
# INSTALL-1 ALIGN (owner 2026-11-02: "trial and pro are th same functionality. license is different in time (backend)"):
# the ONE line that differs between the two copies. The repository and the GitHub release say 'community'; the copy built
# for Invardia (Build-PimSupportScripts) says 'pro'. Trial and Pro are the same install -- Invardia decides by the licence.
$script:PimInstallChannel = 'community'   # INSTALL-CHANNEL: 'community' (the GitHub release copy) | 'pro' (the copy handed to Invardia)
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')     # framework 12.7: the version line + the transcript (inlined in the published file)
. (Join-Path $PSScriptRoot '_PimInstallProPackage.ps1')   # PRO-PACKAGE-FROM-INVARDIA: the Pro copy's download (inlined; only 'pro' calls it)
$null = Start-PimScriptRun -Script 'Start-PimManagerInstall'
$launchCode = 0
try {
    $pimRepo = 'KnudsenMorten/PIM4EntraPS'
    $selfAsset = 'Start-PimManagerInstall.ps1'
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
    $publishedSha = { param($Asset) if ("$($Asset.digest)" -match '^(?i)sha256:([0-9a-f]{64})$') { $Matches[1].ToLowerInvariant() } else { '' } }
    $releaseUrl = { param([string]$Ver) if ("$Ver".Trim()) { "https://api.github.com/repos/$pimRepo/releases/tags/v$("$Ver".Trim().TrimStart('v'))" } else { "https://api.github.com/repos/$pimRepo/releases/latest" } }
    # the folder note: one per tenant + subscription, so -Resume finds the release it downloaded
    $noteKeySrc = if ("$TenantId".Trim() -and "$SubscriptionId".Trim()) { ("{0}|{1}" -f "$TenantId".Trim(), "$SubscriptionId".Trim()).ToLowerInvariant() } else { 'default' }
    $sha0 = [System.Security.Cryptography.SHA256]::Create()
    try { $noteKey = -join ($sha0.ComputeHash([Text.Encoding]::UTF8.GetBytes($noteKeySrc))[0..5] | ForEach-Object { $_.ToString('x2') }) } finally { $sha0.Dispose() }
    $notePath = Join-Path $tempRoot "pim-manager-install-$noteKey.json"
    $findTree = {
        # the release tree inside an unpacked folder: VERSION at the top, or in its one sub-folder -- and the REPO-SHAPED Pro
        # package from Invardia (pim-manager-src-<v>/SOLUTIONS/PIM4EntraPS/...: the tree is its SOLUTIONS/PIM4EntraPS, the
        # layout the installer runs from in the repository)
        param([string]$Dir)
        $cands = @($Dir)
        $tops = @(Get-ChildItem -LiteralPath $Dir -Directory -ErrorAction SilentlyContinue)
        if ($tops.Count -eq 1) { $cands += $tops[0].FullName }
        foreach ($c in $cands) {
            if (Test-Path -LiteralPath (Join-Path $c 'tools/setup/Install-PimManager.ps1')) { return $c }
            $sol = Join-Path (Join-Path $c 'SOLUTIONS') 'PIM4EntraPS'
            if (Test-Path -LiteralPath (Join-Path $sol 'tools/setup/Install-PimManager.ps1')) { return $sol }
        }
        return ''
    }

    # one pass; a stop on the way sets $launchCode and leaves it with 'break' (the exit code is set after the transcript closes)
    do {
    # ---------------------------------------------------------------- INSTALL-1 ALIGN (6): -ViaSupportApp needs the session
    # Without the switch nothing changes (a Support-app session is still used when there is one). With it, the run stops
    # here -- before anything is downloaded -- unless Connect-InvardiaSupport connected THIS tenant in this window.
    $isa = $global:InvardiaSupportState
    if ($ViaSupportApp -and -not ($isa -is [hashtable] -and "$TenantId".Trim() -and "$($isa.TenantId)".Trim() -ieq "$TenantId".Trim())) {
        Write-Host "-ViaSupportApp: this PowerShell window has no Invardia Support session for tenant '$TenantId' -- run Connect-InvardiaSupport.ps1 -Environment <handle> for that tenant first, then this command again. Nothing was installed." -ForegroundColor Red
        $launchCode = 2; break
    }
    # ---------------------------------------------------------------- 0. this file is the one its release publishes
    # A downloaded copy carries the release version it was published with; a copy run from a release folder or the source
    # tree carries none and is already part of that tree. -ReleasePath downloads nothing, so it is not checked here.
    # The Pro copy is not a GitHub release file (Invardia hands it out with its own SHA256SUMS), so it is not checked here.
    $selfVer = if ("$TestSelfVersion".Trim()) { "$TestSelfVersion".Trim() } else { "$($script:PimScriptDocVersion)".Trim() }
    if ($selfVer -and -not "$ReleasePath".Trim() -and "$script:PimInstallChannel" -ne 'pro') {
        $selfRel = $null
        try { $selfRel = & $GetRelease (& $releaseUrl $selfVer) } catch { $selfRel = $null; Write-Verbose "$($_.Exception.Message)" }
        if (-not $selfRel) { Write-Host "The PIM Manager release $selfVer could not be read from GitHub. Check the network and run the command again." -ForegroundColor Red; $launchCode = 3; break }
        $selfPub = & $publishedSha (@(@($selfRel.assets) | Where-Object { "$($_.name)" -eq $selfAsset }) | Select-Object -First 1)
        if (-not $selfPub -or (& $sha256Hex $PSCommandPath) -ne $selfPub) {
            Write-Host "This copy of $selfAsset is not the one published with PIM Manager release $selfVer. Nothing was installed. Download it again with the first line of the command, then run it again." -ForegroundColor Red
            $launchCode = 3; break
        }
        Write-Host "$selfAsset matches the one published with release $selfVer"
    }

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
    $proHandoff = $null
    if (-not $tree -and "$script:PimInstallChannel" -eq 'pro') {
        # PRO-PACKAGE-FROM-INVARDIA (framework INSTALL-1: "github should be for community only"): the Pro copy downloads the
        # Pro package from Invardia after a browser sign-in -- the SAME signed manifest + zip its ring serves the updater,
        # verified the same way. NO GitHub fallback: a failure is one calm line and exit 3.
        $proRing = if ("$UpdateRing".Trim()) { [int]"$UpdateRing".Trim() } else { 3 }
        if (-not $GetInstallToken) {
            $GetInstallToken = if ($ViaSupportApp -and (Get-Command Get-InvardiaSupportToken -ErrorAction SilentlyContinue)) { { param($t) Get-InvardiaSupportToken -Resource 'https://management.azure.com' } }
                               else { { param($t) Get-PimInstallSignInToken -TenantId $t } }
        }
        $pro = Get-PimInstallProPackage -TenantId "$TenantId" -Ring $proRing -Version "$Version" -GetToken $GetInstallToken -Http $InvardiaHttp -Download $Download -TempRoot $tempRoot
        if (-not $pro.ok) { Write-Host "PIM Manager Pro could not be downloaded from Invardia: $($pro.reason). Nothing was installed." -ForegroundColor Red; $launchCode = 3; break }
        Write-Host "SHA-256 $($pro.sha256) -- matches the SHA-256 Invardia signed"
        $unpack = Join-Path $pro.dir 'release'
        if (-not ('System.IO.Compression.ZipFile' -as [type])) { Add-Type -AssemblyName System.IO.Compression.FileSystem }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($pro.zip, $unpack)
        $tree = & $findTree $unpack
        if (-not $tree) { Write-Host "The PIM Manager Pro package $($pro.version) does not hold tools/setup/Install-PimManager.ps1. Nothing was installed." -ForegroundColor Red; $launchCode = 3; break }
        $treeVer = $(try { "$([IO.File]::ReadAllText((Join-Path $tree 'VERSION')))".Trim() } catch { '' })
        if ($treeVer -and $treeVer -ne $pro.version) { Write-Host "The package holds version $treeVer, not the signed $($pro.version). Nothing was installed." -ForegroundColor Red; $launchCode = 3; break }
        if (-not $WhatIfPreference) {
            try { [IO.File]::WriteAllText($notePath, ([ordered]@{ path = $tree; version = $pro.version; savedUtc = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json), (New-Object Text.UTF8Encoding($false))) } catch { Write-Verbose "$($_.Exception.Message)" }
        }
        # framework 8.13 INSTALL-HANDOFF: the person signed in once here -- the installer (same process) takes that ARM ACCESS
        # token from PIM_HANDOFF_TOKENS (checked on its own claims there, removed from the environment at once). Never with
        # -ViaSupportApp (the installer uses the Support session itself); never a refresh token.
        if (-not $ViaSupportApp -and "$($pro.token)".Trim() -and [long]$pro.expiresOn -gt 0) {
            $proHandoff = ([ordered]@{ 'https://management.azure.com/' = [ordered]@{ access_token = "$($pro.token)"; expires_on = [long]$pro.expiresOn } } | ConvertTo-Json -Compress)
        }
        $pro.token = ''
    } elseif (-not $tree) {
        $relUrl = & $releaseUrl $Version
        $rel = $null
        try { $rel = & $GetRelease $relUrl } catch { $rel = $null; Write-Verbose "$($_.Exception.Message)" }
        if (-not $rel) { Write-Host "The PIM Manager release could not be read from GitHub ($relUrl). Check the network and run the command again." -ForegroundColor Red; $launchCode = 3; break }
        $relVer = "$($rel.tag_name)".Trim().TrimStart('v')
        $asset = @(@($rel.assets) | Where-Object { "$($_.name)" -match '^PIM4EntraPS-v[0-9][0-9A-Za-z.+-]*\.zip$' }) | Select-Object -First 1
        if (-not $asset -or -not "$($asset.browser_download_url)".Trim()) { Write-Host "The release $relVer has no PIM Manager zip to download." -ForegroundColor Red; $launchCode = 3; break }
        $published = & $publishedSha $asset
        if (-not $published) { Write-Host "The release $relVer does not publish the checksum of its zip, so it cannot be checked. Nothing was installed." -ForegroundColor Red; $launchCode = 3; break }
        $dir = Join-Path $tempRoot ("pim-manager-release-{0}-{1}" -f $relVer, [guid]::NewGuid().ToString('N').Substring(0, 6))
        [void][IO.Directory]::CreateDirectory($dir)
        $zip = Join-Path $dir 'release.zip'
        Write-Host "PIM Manager release $relVer -- downloading $($asset.name) into $dir"
        try { & $Download "$($asset.browser_download_url)" $zip } catch { Write-Verbose "$($_.Exception.Message)" }
        if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) { Write-Host 'The download did not complete. Check the network and run the command again.' -ForegroundColor Red; try { [IO.Directory]::Delete($dir, $true) } catch { }; $launchCode = 3; break }
        $got = & $sha256Hex $zip
        if ($got -ne $published) {
            Write-Host "The download does not match the SHA-256 the release publishes ($published; the download has $got). Nothing was installed; the folder is removed. Run the command again." -ForegroundColor Red
            try { [IO.Directory]::Delete($dir, $true) } catch { }
            $launchCode = 3; break
        }
        Write-Host "SHA-256 $got -- matches the SHA-256 the release publishes"
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
    foreach ($k in @('TenantId', 'SubscriptionId', 'Location', 'ResourceGroup', 'SuperAdmins', 'AlertRecipients', 'MailSender', 'PortalUsers', 'AllowAllMembers', 'VnetAddressPrefix', 'SubnetAddressPrefix', 'Exposure', 'Edition', 'UpdateRing', 'KeyVaultName', 'EngineAzureRootUserAccessAdmin', 'InstallId', 'SupportAppId', 'SupportAccess', 'Reporter', 'StatePath', 'Resume', 'PreflightOnly', 'ViaSupportApp')) {
        if ($PSBoundParameters.ContainsKey($k)) { $pass[$k] = $PSBoundParameters[$k] }
    }
    # PRIVATE NETWORK (INSTALL-1 item 5): the network parameters, passed through unchanged
    foreach ($k in @('PrivateNetwork', 'VnetId', 'VnetName', 'AppsSubnetName', 'AppsSubnetPrefix', 'EndpointsSubnetName', 'EndpointsSubnetPrefix', 'PrivateDnsZonesResourceGroupId', 'HubVnetId', 'LinkZonesToHub', 'PeerToHub', 'WebAppAccess')) {
        if ($PSBoundParameters.ContainsKey($k)) { $pass[$k] = $PSBoundParameters[$k] }
    }
    # INSTALL-1 ALIGN: the edition comes from this copy (a given -Edition still wins for one release); the ring defaults to 3
    if (-not "$($pass['Edition'])".Trim()) { $pass['Edition'] = $(if ("$script:PimInstallChannel" -eq 'pro') { 'Pro' } else { 'Community' }) }
    if (-not "$($pass['UpdateRing'])".Trim()) { $pass['UpdateRing'] = $UpdateRing }
    if ($WhatIfPreference) { $pass['WhatIf'] = $true }
    $installer = Join-Path $tree 'tools/setup/Install-PimManager.ps1'
    if ($proHandoff -and -not "$env:PIM_HANDOFF_TOKENS".Trim()) { $env:PIM_HANDOFF_TOKENS = $proHandoff }
    try { $launchCode = [int](@(& $RunInstaller $installer $pass) | Select-Object -Last 1) }
    finally { if ($proHandoff) { $env:PIM_HANDOFF_TOKENS = $null; $proHandoff = $null } }
    if ($launchCode -ne 0) { Write-Host "Release files: $tree -- the same command with -Resume continues from here." -ForegroundColor Yellow }
    } while ($false)
} finally {
    Stop-PimScriptRun -Script 'Start-PimManagerInstall'   # framework 12.7: "Log written: <path>" on every exit
}
$global:LASTEXITCODE = $launchCode
exit $launchCode
