#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Authentication
<#
.SYNOPSIS
    One-command turnkey installer for the PIM Activator Edge / Chrome extension.

.DESCRIPTION
    Orchestrates everything a customer needs to roll out the PIM Activator on
    a new tenant. Works generically for any customer + any computer because
    the extension ID is deterministic (derived from the public key baked into
    manifest.json's `key` field).

    Steps it runs in order:

      1. Generates the 4 placeholder icons (icon-16/32/48/128) if the icons
         folder is empty -- Edge / Chrome "Load unpacked" refuses to install
         otherwise.
      1.5. (Optional, -PublishToGitHubPages) Publishes the extension to a
           GitHub Pages branch (free, public, anonymously readable). Verifies
           gh CLI + repo, generates or re-uses a local RSA signing key, packs
           the .crx via msedge.exe, derives the deterministic extension ID
           from the CRX SPKI, refreshes manifest.json's `key`, writes
           updates.xml pointing at the eventual pages URL, commits + pushes
           both to the gh-pages branch via a shallow worktree clone, and
           auto-derives -CrxUpdateUrl for step 6. Re-runnable end-to-end.
      2. Computes the deterministic extension ID from the public key in
         manifest.json (no need for the operator to sideload first to learn
         the ID).
      3. Triggers ONE interactive Microsoft Graph sign-in (browser by default;
         pass -UseDeviceCode for headless hosts), OR connects via SPN (cert
         or secret) when the Unattended parameter set is used.
      4. Creates / updates the "PIM Activator" app registration with the right
         SPA + Public Client redirect URIs and delegated permissions, then
         grants tenant-wide admin consent.
      5. Writes config.js with the resulting tenantId + clientId so the
         extension popup is wired on first launch.
      6. Three rollout modes (mutually compatible with all auth modes):

         a) DEFAULT (no flag) -- prints the URLs at the end. Maintainer
            copies them into Intune manually. No registry writes.

         b) -PrintIntuneConfig -- PRIMARY PRODUCTION PATH. Same as default
            plus emits exact copy-pasteable values for the Intune Admin
            Center (ExtensionInstallForcelist value + managed-storage JSON
            payload). No registry writes. Combines with
            -PublishToGitHubPages to auto-derive the updates.xml URL.

         c) -PushPolicy -- dev/testing only. Writes the
            ExtensionInstallForcelist + managed-storage policy registry
            keys for Edge and/or Chrome (per -TargetBrowser) so the
            browser auto-installs the extension on next launch.

            -PushPolicyScope User (DEFAULT)    HKCU writes only. No admin
                                               required. No conflict with
                                               Intune-managed policy.
                                               Easy to revert.
            -PushPolicyScope Machine           HKLM writes. CONFLICTS with
                                               Intune. Only use on
                                               isolated test machines.

            When combined with -PublishToGitHubPages, -CrxUpdateUrl is
            auto-derived from the just-published updates.xml.

    Re-runnable: every step is idempotent. Same tenant -> updates the existing
    app reg in place. Same machine -> overwrites config.js + policy keys.
    Same repo -> overwrites the CRX + updates.xml in the gh-pages branch.

.PARAMETER TenantId
    Optional. If omitted, the script uses whatever tenant Connect-MgGraph
    defaulted to. Pass explicitly to be sure you target the right tenant.

.PARAMETER UseDeviceCode
    Use device-code Connect-MgGraph flow instead of browser. Slower (120-second
    sign-in window) but works on hosts without a default browser.

.PARAMETER BootstrapSpnAppId
    AppId of a pre-staged bootstrap SPN with the three admin-consented Graph
    application permissions (Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All,
    DelegatedPermissionGrant.ReadWrite.All). Required for fully-unattended runs.

.PARAMETER BootstrapSpnCertificateThumbprint
    Certificate thumbprint of the bootstrap SPN's client credential (preferred
    over -BootstrapSpnClientSecret).

.PARAMETER BootstrapSpnClientSecret
    Plain-text client secret of the bootstrap SPN. Fallback when cert auth is
    not available; rotate to a certificate for production.

.PARAMETER PushPolicy
    Dev/testing only. Writes the ExtensionInstallForcelist + managed-storage
    policy registry keys so the target browser(s) auto-install the extension
    on next launch.

    Scope is controlled by -PushPolicyScope:
      User    (DEFAULT) HKCU writes. No admin, no Intune conflict, easy revert.
      Machine           HKLM writes. CONFLICTS with Intune-managed policy.
                        Only use on isolated test machines NOT managed by Intune.

    For production rollouts to fleets of devices, use -PrintIntuneConfig
    instead and paste the values into Intune (Intune is the authoritative
    policy source in customer environments).

.PARAMETER PushPolicyScope
    'User' (default) writes the policy keys under HKCU -- no admin required,
    affects only the current Windows user, won't conflict with Intune-managed
    HKLM policy, trivially revertible.
    'Machine' writes under HKLM -- requires admin, affects every user on the
    box, AND CONFLICTS with Intune-managed ExtensionInstallForcelist policy.
    Only use Machine on isolated test machines that are NOT Intune-managed.

.PARAMETER PrintIntuneConfig
    PRIMARY PRODUCTION PATH. After publishing the CRX + writing config.js,
    print the exact strings the customer's Intune admin pastes into the
    Intune Admin Center to deploy the extension fleet-wide (forcelist value
    + managed-storage JSON payload + step-by-step path through the UI).
    No registry writes anywhere. Compose with -PublishToGitHubPages to
    auto-derive the updates.xml URL the Intune payload references.

.PARAMETER CrxUpdateUrl
    URL where the .crx update manifest is hosted. Only used with -PushPolicy.
    Mandatory if -PushPolicy is set, UNLESS -PublishToGitHubPages is also set
    (in which case the URL is auto-derived from the published updates.xml).
    Example: 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml'.

.PARAMETER TargetBrowser
    Which browser(s) the -PushPolicy step targets. 'Edge', 'Chrome', or 'Both'.
    Default: 'Both'. Maps directly to Deploy-PimActivatorClient.ps1 -Browser.

.PARAMETER PublishToGitHubPages
    Publish the packaged extension (.crx + updates.xml) to a GitHub Pages
    branch via the gh CLI. Free, anonymous-readable, no Azure cost. Composes
    with EITHER interactive or unattended auth. Requires the gh CLI to be
    installed and authenticated (`gh auth status`).

.PARAMETER GitHubRepo
    Owner/repo to publish to. Default 'KnudsenMorten/PIM4EntraPS'. The repo
    must already exist; the script does NOT create it. Public repos work on
    the GitHub Pages free tier; private repos require GitHub Pro/Team/Enterprise.

.PARAMETER GitHubBranch
    Branch hosting the CRX. Default 'gh-pages' -- GitHub Pages auto-serves
    from this branch when enabled. The script creates the branch as an
    orphan if it doesn't exist.

.PARAMETER GitHubPath
    Sub-path within the branch to publish to. Default '' (root). If you set
    this, the resulting URLs are 'https://<owner>.github.io/<repo>/<path>/...'.

.PARAMETER LocalSigningKeyPath
    Where the RSA 2048 CRX signing PEM lives on disk. The script reuses it if
    it exists, otherwise lets msedge.exe generate a fresh keypair and moves
    the PEM here. This file is the MAINTAINER'S SECRET -- losing it means you
    can never publish a signed update for this extension ID again. The
    default location ($env:USERPROFILE\.pim-activator\signing-key.pem) is
    outside the repo and therefore not at risk of accidental commit.

.EXAMPLE
    # Developer workstation: app reg + admin consent + config.js,
    # then operator does "Load unpacked" once in Edge.
    .\Setup-PimActivator.ps1 -TenantId 'f0fa27a0-...'

.EXAMPLE
    # Production rollout (the normal customer flow): publish to GitHub Pages +
    # print the exact Intune Admin Center values for the maintainer to paste.
    # No registry writes anywhere -- Intune is the authoritative policy source.
    .\Setup-PimActivator.ps1 -TenantId 'f0fa27a0-...' `
        -PublishToGitHubPages -PrintIntuneConfig

.EXAMPLE
    # Dev-box testing: HKCU policy (no admin, no Intune conflict, easy revert).
    # The forcelist + managed-storage keys are written under HKCU\SOFTWARE\Policies\
    # for the current Windows user only.
    .\Setup-PimActivator.ps1 -TenantId 'f0fa27a0-...' `
        -PublishToGitHubPages -PushPolicy -PushPolicyScope User

.EXAMPLE
    # Isolated test machine NOT managed by Intune -- explicit Machine scope
    # (HKLM, requires admin, will collide with Intune if present).
    .\Setup-PimActivator.ps1 -TenantId 'f0fa27a0-...' -PushPolicy `
        -PushPolicyScope Machine `
        -CrxUpdateUrl 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml' `
        -TargetBrowser Both

.EXAMPLE
    # FULLY UNATTENDED production rollout (Intune Win32 / scheduled task /
    # Azure Function). Bootstrap SPN must have 3 app permissions admin-consented
    # in the target tenant:
    #   Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All
    # Cert thumbprint is preferred over plaintext secret.
    .\Setup-PimActivator.ps1 -TenantId 'f0fa27a0-...' `
        -BootstrapSpnAppId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
        -BootstrapSpnCertificateThumbprint 'ABCDEF0123456789ABCDEF0123456789ABCDEF01' `
        -PublishToGitHubPages -PrintIntuneConfig

.NOTES
    Solution       : PIM4EntraPS
    Component      : tools/pim-activator
    Developed by   : Morten Knudsen, Microsoft MVP
#>
[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [string]$TenantId,

    # --- Interactive auth (default) ---
    [Parameter(ParameterSetName = 'Interactive')]
    [switch]$UseDeviceCode,

    # --- Fully-unattended SPN auth (for Intune / Azure Function / scheduled runs) ---
    # Pass these to skip browser/device-code entirely. The bootstrap SPN needs
    # 3 application permissions admin-consented in the target tenant:
    #   Application.ReadWrite.All
    #   AppRoleAssignment.ReadWrite.All
    #   DelegatedPermissionGrant.ReadWrite.All
    # Cert auth is preferred (no secret in scripts/transcripts); secret is
    # accepted as a fallback. ONE of -BootstrapSpnCertificateThumbprint OR
    # -BootstrapSpnClientSecret must be supplied alongside -BootstrapSpnAppId.
    [Parameter(ParameterSetName = 'Unattended', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$BootstrapSpnAppId,

    [Parameter(ParameterSetName = 'Unattended')]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$BootstrapSpnCertificateThumbprint,

    [Parameter(ParameterSetName = 'Unattended')]
    [string]$BootstrapSpnClientSecret,

    [switch]$PushPolicy,

    [ValidateSet('User','Machine')]
    [string]$PushPolicyScope = 'User',

    [switch]$PrintIntuneConfig,

    [string]$CrxUpdateUrl,

    [ValidateSet('Edge','Chrome','Both')]
    [string]$TargetBrowser = 'Both',

    # --- GitHub Pages CRX hosting (re-runnable: pack + sign + commit + push) ---
    [switch]$PublishToGitHubPages,

    [string]$GitHubRepo = 'KnudsenMorten/PIM4EntraPS',

    [string]$GitHubBranch = 'gh-pages',

    [string]$GitHubPath = '',

    [string]$LocalSigningKeyPath = (Join-Path $env:USERPROFILE '.pim-activator\signing-key.pem')
)

$ErrorActionPreference = 'Stop'

$activatorDir = $PSScriptRoot
$manifestPath = Join-Path $activatorDir 'manifest.json'
$iconsDir     = Join-Path $activatorDir 'icons'
$configPath   = Join-Path $activatorDir 'config.js'

if ($PushPolicy -and -not $CrxUpdateUrl -and -not $PublishToGitHubPages) {
    throw "-PushPolicy requires -CrxUpdateUrl (the .crx update-manifest URL), unless -PublishToGitHubPages is also set (in which case the URL is auto-derived)."
}

if ($PushPolicy -and $PrintIntuneConfig) {
    Write-Host ""
    Write-Host "  NOTE: both -PushPolicy and -PrintIntuneConfig were supplied. The script" -ForegroundColor Yellow
    Write-Host "  will write the registry policy AND print the Intune copy-paste values." -ForegroundColor Yellow
    Write-Host "  In production, prefer ONE source of truth (Intune) -- skip -PushPolicy." -ForegroundColor Yellow
    Write-Host ""
}

if ($PushPolicy -and $PushPolicyScope -eq 'Machine') {
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Yellow
    Write-Host "  WARNING: -PushPolicy -PushPolicyScope Machine" -ForegroundColor Yellow
    Write-Host "  HKLM ExtensionInstallForcelist writes CONFLICT with Intune-" -ForegroundColor Yellow
    Write-Host "  managed policy. Only use Machine scope on isolated test" -ForegroundColor Yellow
    Write-Host "  machines that are NOT managed by Intune / GPO." -ForegroundColor Yellow
    Write-Host "  Production rollouts should use -PrintIntuneConfig instead." -ForegroundColor Yellow
    Write-Host "  ============================================================" -ForegroundColor Yellow
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Helper: deterministic extension ID from SPKI DER bytes
# ---------------------------------------------------------------------------

function Invoke-MsedgePackWithPlaceholder {
    <#
    .SYNOPSIS
        Run msedge.exe --pack-extension with a PLACEHOLDER config.js so the
        CRX doesn't bake in the maintainer's tenantId / clientId.
    .DESCRIPTION
        Customers push real tenantId + clientId via Intune managed_storage
        (popup.js's loadConfig() reads chrome.storage.managed first, falls
        back to bundled config.js). If we ship the maintainer's actual
        tenant in the CRX's config.js, any customer who forgets the Intune
        managed_storage setup accidentally signs their users into the
        maintainer's tenant. This wrapper temporarily swaps config.js with
        config.template.js content before packing, then restores the local
        config.js (used for sideload-dev) after packing.
    #>
    param(
        [Parameter(Mandatory)][string]$EdgeExe,
        [Parameter(Mandatory)][string]$ActivatorDir,
        [string]$KeyPath
    )
    $cfgPath  = Join-Path $ActivatorDir 'config.js'
    $tmplPath = Join-Path $ActivatorDir 'config.template.js'
    $savedCfg = $null
    if (Test-Path $cfgPath) { $savedCfg = Get-Content -LiteralPath $cfgPath -Raw }
    try {
        if (Test-Path $tmplPath) {
            Copy-Item -LiteralPath $tmplPath -Destination $cfgPath -Force
        } else {
            $minimalPlaceholder = @'
// Placeholder bundled in CRX -- customer admin pushes real values via Intune chrome.storage.managed.
window.PIM_CONFIG = {
  tenantId:             "00000000-0000-0000-0000-000000000000",
  clientId:             "00000000-0000-0000-0000-000000000000",
  groupNameFilter:      "^PIM-",
  defaultDurationHours: 8,
  defaultJustification: "Daily ops"
};
'@
            Set-Content -LiteralPath $cfgPath -Value $minimalPlaceholder -Encoding UTF8 -NoNewline
        }
        if ($KeyPath) {
            & $EdgeExe "--pack-extension=$ActivatorDir" "--pack-extension-key=$KeyPath" 2>&1 | Out-Null
        } else {
            & $EdgeExe "--pack-extension=$ActivatorDir" 2>&1 | Out-Null
        }
    } finally {
        if ($savedCfg) {
            Set-Content -LiteralPath $cfgPath -Value $savedCfg -Encoding UTF8 -NoNewline
        } elseif (Test-Path $cfgPath) {
            Remove-Item -LiteralPath $cfgPath -Force
        }
    }
}

function Get-ExtensionIdFromSpkiDer {
    param([byte[]]$SpkiDer)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $h = $sha.ComputeHash($SpkiDer)
    } finally { $sha.Dispose() }
    $hex = ($h[0..15] | ForEach-Object { $_.ToString('x2') }) -join ''
    $m = @{ '0'='a'; '1'='b'; '2'='c'; '3'='d'; '4'='e'; '5'='f'; '6'='g'; '7'='h';
            '8'='i'; '9'='j'; 'a'='k'; 'b'='l'; 'c'='m'; 'd'='n'; 'e'='o'; 'f'='p' }
    return ($hex.ToCharArray() | ForEach-Object { $m["$_"] }) -join ''
}

# ---------------------------------------------------------------------------
# Helper: extract SPKI DER bytes from a CRX3 file's header (no PEM parsing).
# Used both by the GitHub Pages flow and any future re-pack scenarios.
# ---------------------------------------------------------------------------

function Get-SpkiFromCrx {
    param([Parameter(Mandatory)][string]$CrxPath)
    $bytes = [System.IO.File]::ReadAllBytes($CrxPath)
    if ($bytes.Length -lt 16) { throw "CRX file too short to parse." }
    $magic = [System.Text.Encoding]::ASCII.GetString($bytes, 0, 4)
    if ($magic -ne 'Cr24') { throw "Not a CRX file (magic was '$magic', expected 'Cr24')." }
    $version    = [BitConverter]::ToUInt32($bytes, 4)
    $headerSize = [BitConverter]::ToUInt32($bytes, 8)
    if ($version -ne 3) { throw "Only CRX3 supported (file is CRX$version)." }
    if (12 + $headerSize -gt $bytes.Length) { throw "CRX header size $headerSize overflows file." }
    $header = New-Object byte[] $headerSize
    [Array]::Copy($bytes, 12, $header, 0, $headerSize)
    # Walk the header protobuf looking for tag 0x12 (sha256_with_rsa, field 2 wire-type 2).
    $i = 0
    function _ReadVarint([byte[]]$buf, [ref]$pos) {
        $result = 0L; $shift = 0
        while ($true) {
            $b = $buf[$pos.Value]; $pos.Value++
            $result = $result -bor ((($b -band 0x7F) -as [long]) -shl $shift)
            if (($b -band 0x80) -eq 0) { break }
            $shift += 7
        }
        return $result
    }
    while ($i -lt $header.Length) {
        $tagPos = [ref]$i
        $tag = _ReadVarint $header $tagPos
        $i = $tagPos.Value
        $wireType  = [int]($tag -band 7)
        $fieldNum  = [int]($tag -shr 3)
        if ($wireType -eq 2) {
            $lenPos = [ref]$i
            $len = [int](_ReadVarint $header $lenPos)
            $i = $lenPos.Value
            if ($fieldNum -eq 2) {
                # Found a sha256_with_rsa AsymmetricKeyProof message. Inside, field 1 = public_key (bytes).
                $sub = New-Object byte[] $len
                [Array]::Copy($header, $i, $sub, 0, $len)
                $j = 0
                while ($j -lt $sub.Length) {
                    $subTagPos = [ref]$j
                    $subTag = _ReadVarint $sub $subTagPos
                    $j = $subTagPos.Value
                    $subWire = [int]($subTag -band 7)
                    $subField = [int]($subTag -shr 3)
                    if ($subWire -eq 2) {
                        $subLenPos = [ref]$j
                        $subLen = [int](_ReadVarint $sub $subLenPos)
                        $j = $subLenPos.Value
                        if ($subField -eq 1) {
                            $spki = New-Object byte[] $subLen
                            [Array]::Copy($sub, $j, $spki, 0, $subLen)
                            return ,$spki
                        }
                        $j += $subLen
                    } else {
                        throw "Unexpected wire-type $subWire inside sha256_with_rsa."
                    }
                }
            }
            $i += $len
        } else {
            throw "Unsupported wire-type $wireType at offset $($tagPos.Value)."
        }
    }
    throw "No sha256_with_rsa.public_key field found in CRX header."
}

# ---------------------------------------------------------------------------
# Step 1: ensure icons exist
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[ 1 / 6 ] Ensuring extension icons exist ..." -ForegroundColor Cyan

if (-not (Test-Path $iconsDir)) { New-Item -ItemType Directory -Path $iconsDir -Force | Out-Null }

$needIcons = @(16, 32, 48, 128) | Where-Object { -not (Test-Path (Join-Path $iconsDir "icon-$_.png")) }
if ($needIcons) {
    Add-Type -AssemblyName System.Drawing
    foreach ($size in $needIcons) {
        $bmp = New-Object System.Drawing.Bitmap $size, $size
        $g   = [System.Drawing.Graphics]::FromImage($bmp)
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.Clear([System.Drawing.Color]::FromArgb(0, 120, 212))
        $fontSize = [Math]::Max(6, [int]($size * 0.42))
        $font  = New-Object System.Drawing.Font('Segoe UI', $fontSize, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
        $brush = [System.Drawing.Brushes]::White
        $fmt   = New-Object System.Drawing.StringFormat
        $fmt.Alignment = [System.Drawing.StringAlignment]::Center
        $fmt.LineAlignment = [System.Drawing.StringAlignment]::Center
        $rect = New-Object System.Drawing.RectangleF(0, 0, $size, $size)
        $g.DrawString('PIM', $font, $brush, $rect, $fmt)
        $font.Dispose(); $fmt.Dispose(); $g.Dispose()
        $bmp.Save((Join-Path $iconsDir "icon-$size.png"), [System.Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()
    }
    Write-Host "[ 1 / 6 ] OK -- generated $($needIcons.Count) icon(s)" -ForegroundColor Green
} else {
    Write-Host "[ 1 / 6 ] OK -- all 4 icons already present" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Step 1.5: (optional) GitHub Pages CRX hosting
# ---------------------------------------------------------------------------

# Will be populated when -PublishToGitHubPages succeeds; used by step 6 fallback.
$autoDerivedCrxUpdateUrl = $null
$ghPagesCrxUrl     = $null
$ghPagesUpdatesUrl = $null

if ($PublishToGitHubPages) {

    Write-Host ""
    Write-Host "[1.5/ 6 ] GitHub Pages -- packaging + signing + publishing CRX ..." -ForegroundColor Cyan

    # --- 1.5.1 Verify gh CLI installed + authenticated ------------------------
    $ghExe = (Get-Command 'gh' -ErrorAction SilentlyContinue).Source
    if (-not $ghExe) {
        throw "GitHub CLI (gh) not found on PATH. Install from https://cli.github.com and re-run."
    }
    $ghAuthOut = & $ghExe auth status 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "gh CLI is not authenticated. Run 'gh auth login' (or set GH_TOKEN / GITHUB_TOKEN env var) and re-run.`n$ghAuthOut"
    }
    Write-Host "          gh CLI          : $ghExe (authenticated)"

    # --- 1.5.2 Verify repo exists + reachable (warn if private) ---------------
    $repoJson = & $ghExe repo view $GitHubRepo --json visibility,defaultBranchRef,nameWithOwner,owner,name 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "gh repo view '$GitHubRepo' failed. Confirm the repo exists and the authenticated gh user has access.`n$repoJson"
    }
    $repoMeta = $repoJson | ConvertFrom-Json
    $repoOwner = $repoMeta.owner.login
    $repoName  = $repoMeta.name
    $defaultBranchName = if ($repoMeta.defaultBranchRef) { $repoMeta.defaultBranchRef.name } else { 'main' }
    Write-Host "          Repo            : $($repoMeta.nameWithOwner) (default branch: $defaultBranchName)"
    if ($repoMeta.visibility -eq 'PRIVATE') {
        Write-Host "          WARNING: repo visibility is PRIVATE -- GitHub Pages will only serve from PRIVATE repos on Pro/Team/Enterprise plans." -ForegroundColor Yellow
    }

    # GitHub Pages URLs use the OWNER lowercased and the repo name with its
    # exact case. Build them once + reuse below.
    $repoOwnerLower = $repoOwner.ToLowerInvariant()
    $pathSegment = ''
    if ($GitHubPath -and $GitHubPath.Trim('/').Length -gt 0) {
        $pathSegment = '/' + $GitHubPath.Trim('/')
    }
    $pagesBaseUrl = "https://$repoOwnerLower.github.io/$repoName$pathSegment"
    $ghPagesCrxUrl     = "$pagesBaseUrl/pim-activator.crx"
    $ghPagesUpdatesUrl = "$pagesBaseUrl/updates.xml"

    # --- 1.5.3 Resolve msedge.exe ---------------------------------------------
    $edgeCandidates = @(
        (Join-Path ${env:ProgramFiles}      'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe')
    )
    $edgeExe = $edgeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $edgeExe) {
        throw "msedge.exe not found in either Program Files location. Install Microsoft Edge (used as the CRX packager)."
    }
    Write-Host "          msedge.exe      : $edgeExe"

    # --- 1.5.4 Ensure local signing key ---------------------------------------
    $signingKeyDir = Split-Path -Parent $LocalSigningKeyPath
    if (-not (Test-Path -LiteralPath $signingKeyDir)) {
        New-Item -ItemType Directory -Path $signingKeyDir -Force | Out-Null
    }

    $packedCrx     = "$activatorDir.crx"
    $sideEffectPem = "$activatorDir.pem"  # only written by msedge when -key not supplied

    if (Test-Path -LiteralPath $LocalSigningKeyPath) {
        Write-Host "          Signing key     : Re-using existing key at $LocalSigningKeyPath" -ForegroundColor Green
        if (Test-Path $packedCrx)     { Remove-Item -LiteralPath $packedCrx -Force }
        if (Test-Path $sideEffectPem) { Remove-Item -LiteralPath $sideEffectPem -Force }
        Invoke-MsedgePackWithPlaceholder -EdgeExe $edgeExe -ActivatorDir $activatorDir -KeyPath $LocalSigningKeyPath
        $deadline = (Get-Date).AddSeconds(20)
        while (-not (Test-Path $packedCrx) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
        if (-not (Test-Path $packedCrx)) {
            throw "msedge.exe --pack-extension did not produce $packedCrx (using existing key)."
        }
    } else {
        Write-Host "          Signing key     : Not found -- having msedge.exe generate a fresh keypair ..." -ForegroundColor Yellow
        if (Test-Path $packedCrx)     { Remove-Item -LiteralPath $packedCrx -Force }
        if (Test-Path $sideEffectPem) { Remove-Item -LiteralPath $sideEffectPem -Force }
        # Edge with no -key: generates new key, writes <dir>.crx + <dir>.pem next to <dir>.
        Invoke-MsedgePackWithPlaceholder -EdgeExe $edgeExe -ActivatorDir $activatorDir
        $deadline = (Get-Date).AddSeconds(20)
        while (-not ((Test-Path $packedCrx) -and (Test-Path $sideEffectPem)) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
        if (-not (Test-Path $sideEffectPem)) {
            throw "msedge.exe --pack-extension did not produce a PEM ($sideEffectPem)."
        }
        Move-Item -LiteralPath $sideEffectPem -Destination $LocalSigningKeyPath -Force
        Write-Host ""
        Write-Host "          *** A NEW RSA 2048 SIGNING KEY WAS JUST GENERATED ***" -ForegroundColor Red
        Write-Host "          Stored at: $LocalSigningKeyPath" -ForegroundColor Red
        Write-Host "          BACK THIS UP NOW (1Password / KV / printed paper)." -ForegroundColor Red
        Write-Host "          Without it you can NEVER publish a signed update for this" -ForegroundColor Red
        Write-Host "          extension ID again -- users would have to uninstall + reinstall" -ForegroundColor Red
        Write-Host "          under a brand-new ID, losing all per-tenant config + state." -ForegroundColor Red
        Write-Host ""
    }

    # --- 1.5.5 Extract SPKI + compute extension ID; sync manifest.json.key ----
    $spkiDer      = Get-SpkiFromCrx -CrxPath $packedCrx
    $spkiB64      = [Convert]::ToBase64String($spkiDer)
    $derivedExtId = Get-ExtensionIdFromSpkiDer -SpkiDer $spkiDer

    $manifestJson = Get-Content $manifestPath -Raw | ConvertFrom-Json
    $manifestKey = $null
    if ($manifestJson.PSObject.Properties.Name -contains 'key') { $manifestKey = $manifestJson.key }
    if ($manifestKey -ne $spkiB64) {
        Write-Host "          manifest.json 'key' differs from signing key -- rewriting." -ForegroundColor Yellow
        if ($manifestJson.PSObject.Properties.Name -contains 'key') {
            $manifestJson.key = $spkiB64
        } else {
            $manifestJson | Add-Member -NotePropertyName 'key' -NotePropertyValue $spkiB64 -Force
        }
        ($manifestJson | ConvertTo-Json -Depth 32) | Set-Content -LiteralPath $manifestPath -Encoding UTF8
        Write-Host "          OK -- manifest.json updated; new extension ID: $derivedExtId" -ForegroundColor Green

        # Re-pack the CRX so its embedded manifest matches the on-disk one we
        # just touched (Edge bakes the manifest INTO the zip body of the crx).
        Remove-Item -LiteralPath $packedCrx -Force
        Invoke-MsedgePackWithPlaceholder -EdgeExe $edgeExe -ActivatorDir $activatorDir -KeyPath $LocalSigningKeyPath
        $deadline = (Get-Date).AddSeconds(20)
        while (-not (Test-Path $packedCrx) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
        if (-not (Test-Path $packedCrx)) { throw "msedge.exe --pack-extension (re-pack after manifest sync) did not produce $packedCrx." }
    } else {
        Write-Host "          manifest.json 'key' already matches signing key; extension ID stays: $derivedExtId" -ForegroundColor Green
    }

    # --- 1.5.6 Generate updates.xml -------------------------------------------
    $extVersion = $manifestJson.version
    if (-not $extVersion) { throw "manifest.json has no 'version' field; cannot generate updates.xml." }

    $updatesXml = @"
<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='$derivedExtId'>
    <updatecheck codebase='$ghPagesCrxUrl' version='$extVersion' />
  </app>
</gupdate>
"@
    $tempUpdatesPath = Join-Path $env:TEMP 'pim-activator-updates.xml'
    Set-Content -LiteralPath $tempUpdatesPath -Value $updatesXml -Encoding UTF8

    # --- 1.5.7 Publish to gh-pages branch via worktree clone ------------------
    $worktreeRoot = Join-Path $env:TEMP ("pim-activator-ghpages-" + [Guid]::NewGuid().ToString('N'))
    try {
        Write-Host "          Cloning $GitHubRepo branch '$GitHubBranch' (shallow) ..."
        $cloneOut = & $ghExe repo clone $GitHubRepo $worktreeRoot -- --branch $GitHubBranch --single-branch --depth 1 2>&1
        if ($LASTEXITCODE -ne 0) {
            # Branch likely doesn't exist -- clone default branch and create an orphan branch
            Write-Host "          Branch '$GitHubBranch' not found on remote -- creating as an orphan." -ForegroundColor Yellow
            if (Test-Path -LiteralPath $worktreeRoot) { Remove-Item -LiteralPath $worktreeRoot -Recurse -Force }
            $cloneOut2 = & $ghExe repo clone $GitHubRepo $worktreeRoot -- --depth 1 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "gh repo clone $GitHubRepo failed (default-branch fallback).`n$cloneOut2"
            }
            Push-Location $worktreeRoot
            try {
                & git checkout --orphan $GitHubBranch 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "git checkout --orphan $GitHubBranch failed inside $worktreeRoot." }
                & git rm -rf . 2>&1 | Out-Null
                # ignore exit code; empty repo case is fine
            } finally { Pop-Location }
        }

        # Compute destination directory inside the worktree
        $destDir = $worktreeRoot
        if ($GitHubPath -and $GitHubPath.Trim('/').Length -gt 0) {
            $destDir = Join-Path $worktreeRoot ($GitHubPath.Trim('/') -replace '/', '\')
            if (-not (Test-Path -LiteralPath $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
        }

        Copy-Item -LiteralPath $packedCrx       -Destination (Join-Path $destDir 'pim-activator.crx') -Force
        Copy-Item -LiteralPath $tempUpdatesPath -Destination (Join-Path $destDir 'updates.xml')       -Force

        # Also drop a tiny .nojekyll file at the root so Pages serves files
        # whose names start with underscore (defensive; cheap to include).
        $noJekyllPath = Join-Path $worktreeRoot '.nojekyll'
        if (-not (Test-Path -LiteralPath $noJekyllPath)) {
            Set-Content -LiteralPath $noJekyllPath -Value '' -Encoding ASCII -NoNewline
        }

        Push-Location $worktreeRoot
        try {
            & git add . 2>&1 | Out-Null
            # Check whether anything is actually staged before attempting commit
            $statusOut = & git status --porcelain
            if (-not $statusOut) {
                Write-Host "          No changes to commit -- gh-pages branch already up-to-date." -ForegroundColor DarkGray
            } else {
                $commitMsg = "Publish pim-activator $extVersion (extId $derivedExtId)"
                & git commit -m $commitMsg 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    throw "git commit failed in $worktreeRoot. Inspect git config user.email / user.name."
                }
                Write-Host "          Committed: $commitMsg"
                & git push origin $GitHubBranch 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    throw "git push origin $GitHubBranch failed."
                }
                Write-Host "          Pushed to origin/$GitHubBranch" -ForegroundColor Green
            }
        } finally { Pop-Location }
    } finally {
        if (Test-Path -LiteralPath $worktreeRoot) {
            # Some files (.git/objects/pack) are read-only on Windows; clear attr first.
            Get-ChildItem -LiteralPath $worktreeRoot -Recurse -Force -ErrorAction SilentlyContinue |
                ForEach-Object { try { $_.IsReadOnly = $false } catch {} }
            Remove-Item -LiteralPath $worktreeRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $tempUpdatesPath) {
            Remove-Item -LiteralPath $tempUpdatesPath -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host ""
    Write-Host "          CRX URL         : $ghPagesCrxUrl" -ForegroundColor Cyan
    Write-Host "          updates.xml URL : $ghPagesUpdatesUrl" -ForegroundColor Cyan
    Write-Host "          REMINDER        : Enable GitHub Pages once for this repo --" -ForegroundColor Yellow
    Write-Host "                            Settings -> Pages -> Source: Deploy from a branch" -ForegroundColor Yellow
    Write-Host "                            Branch: $GitHubBranch  Folder: / (root)" -ForegroundColor Yellow

    # --- 1.5.8 Auto-derive -CrxUpdateUrl when PushPolicy + no explicit URL ----
    if ($PushPolicy -and -not $CrxUpdateUrl) {
        $CrxUpdateUrl = $ghPagesUpdatesUrl
        $autoDerivedCrxUpdateUrl = $ghPagesUpdatesUrl
        Write-Host "          -CrxUpdateUrl auto-derived from publish: $CrxUpdateUrl" -ForegroundColor Green
    }

    Write-Host "[1.5/ 6 ] OK -- GitHub Pages CRX published" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Step 2: compute deterministic extension ID from manifest.json's `key`
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[ 2 / 6 ] Computing deterministic extension ID from manifest key ..." -ForegroundColor Cyan

$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
if (-not $manifest.key) {
    throw "manifest.json has no 'key' field. Re-run with -PublishToGitHubPages to let msedge.exe generate a fresh keypair, or restore the key from version control / your backup."
}
$spkiDer2 = [Convert]::FromBase64String($manifest.key)
$extensionId = Get-ExtensionIdFromSpkiDer -SpkiDer $spkiDer2
Write-Host "[ 2 / 6 ] OK -- Extension ID: $extensionId" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 3: interactive Microsoft Graph sign-in (browser or device code)
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[ 3 / 6 ] Connecting to Microsoft Graph ..." -ForegroundColor Cyan
$ctx = Get-MgContext -ErrorAction SilentlyContinue
$requiredScopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All')

$needConnect = $true
$isUnattended = $PSCmdlet.ParameterSetName -eq 'Unattended'

if ($isUnattended) {
    # --- Fully unattended path: cert or secret on a pre-staged bootstrap SPN ---
    if (-not $TenantId) {
        throw "-TenantId is required in unattended mode (the tenant the activator app reg lives in)."
    }
    if (-not $BootstrapSpnCertificateThumbprint -and -not $BootstrapSpnClientSecret) {
        throw "Unattended mode requires either -BootstrapSpnCertificateThumbprint or -BootstrapSpnClientSecret."
    }
    if ($ctx) {
        # disconnect any stale interactive session so we get a clean app-only context
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
    if ($BootstrapSpnCertificateThumbprint) {
        Write-Host "          Unattended (certificate) -- thumbprint $BootstrapSpnCertificateThumbprint"
        Connect-MgGraph -ClientId $BootstrapSpnAppId `
                        -CertificateThumbprint $BootstrapSpnCertificateThumbprint `
                        -TenantId $TenantId -NoWelcome
    } else {
        Write-Host "          Unattended (client secret) -- consider rotating to a certificate for production."
        $sec = New-Object System.Security.SecureString
        foreach ($c in $BootstrapSpnClientSecret.ToCharArray()) { $sec.AppendChar($c) }
        $sec.MakeReadOnly()
        $cred = New-Object System.Management.Automation.PSCredential($BootstrapSpnAppId, $sec)
        Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $cred -NoWelcome
    }
    $ctx = Get-MgContext
    Write-Host "[ 3 / 6 ] OK -- connected as app '$BootstrapSpnAppId' on $($ctx.TenantId) (app-only, no user)" -ForegroundColor Green
    $needConnect = $false
} elseif ($ctx) {
    # Reuse existing valid session if scopes match (interactive only)
    $missing = $requiredScopes | Where-Object { $_ -notin $ctx.Scopes }
    if (-not $missing) {
        if (-not $TenantId -or $ctx.TenantId -eq $TenantId) {
            Write-Host "[ 3 / 6 ] Reusing existing Graph session ($($ctx.Account) on $($ctx.TenantId))" -ForegroundColor Green
            $needConnect = $false
        }
    }
}

if ($needConnect) {
    if ($UseDeviceCode) {
        Write-Host "          Device-code flow -- visit the URL + enter code shown below."
        $connectArgs = @{ Scopes = $requiredScopes; UseDeviceCode = $true; NoWelcome = $true }
    } else {
        Write-Host "          Browser flow -- default browser will open. Sign in as Privileged Role Admin / Global Admin."
        $connectArgs = @{ Scopes = $requiredScopes; NoWelcome = $true }
    }
    if ($TenantId) { $connectArgs.TenantId = $TenantId }
    Connect-MgGraph @connectArgs
    $ctx = Get-MgContext
    Write-Host "[ 3 / 6 ] OK -- connected as $($ctx.Account) on $($ctx.TenantId)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Step 4: run Deploy-PimActivatorBackend.ps1
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[ 4 / 6 ] Creating / updating activator app registration ..." -ForegroundColor Cyan
$installer = Join-Path $activatorDir 'Deploy-PimActivatorBackend.ps1'
if (-not (Test-Path $installer)) { throw "Deploy-PimActivatorBackend.ps1 not found at $installer" }
& $installer -ExtensionId $extensionId -GrantConsent

# Recover the created app reg's AppId so we can wire config.js
$app = Get-MgApplication -Filter "displayName eq 'PIM Activator'" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $app) { throw "Install-PimActivatorAppRegistration succeeded but the 'PIM Activator' app reg can't be found in this tenant -- ABORT." }
Write-Host "[ 4 / 6 ] OK -- App registration: $($app.DisplayName) (AppId $($app.AppId))" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 5: write config.js
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[ 5 / 6 ] Writing config.js ..." -ForegroundColor Cyan
$configContent = @"
// Auto-generated by Setup-PimActivator.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')
// Edit groupNameFilter / defaultDurationHours / defaultJustification as needed;
// tenantId + clientId are pinned to this tenant + the just-created app reg.
window.PIM_CONFIG = {
  tenantId:             "$($ctx.TenantId)",
  clientId:             "$($app.AppId)",
  groupNameFilter:      "^PIM-",
  defaultDurationHours: 8,
  defaultJustification: "Daily ops"
};
"@
Set-Content -LiteralPath $configPath -Value $configContent -Encoding UTF8
Write-Host "[ 5 / 6 ] OK -- wrote $configPath" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 6: optional browser policy push (HKLM ExtensionInstallForcelist)
# ---------------------------------------------------------------------------

Write-Host ""

# ---- 6a: -PushPolicy (dev/testing only) ------------------------------------
if ($PushPolicy) {
    if (-not $CrxUpdateUrl) {
        throw "-PushPolicy is set but -CrxUpdateUrl is empty (and -PublishToGitHubPages did not run successfully to auto-derive one)."
    }
    $hiveLabel = if ($PushPolicyScope -eq 'Machine') { 'HKLM' } else { 'HKCU' }
    Write-Host "[ 6 / 6 ] Pushing browser policy ($TargetBrowser, $PushPolicyScope scope / $hiveLabel) ..." -ForegroundColor Cyan
    if ($PushPolicyScope -eq 'User') {
        Write-Host "          HKCU-only -- won't affect other users or Intune-managed policy." -ForegroundColor Green
    }
    if ($autoDerivedCrxUpdateUrl) {
        Write-Host "          Using auto-derived CRX update URL: $CrxUpdateUrl" -ForegroundColor DarkGray
    }
    $policyInstaller = Join-Path $activatorDir 'Deploy-PimActivatorClient.ps1'
    if (-not (Test-Path $policyInstaller)) { throw "Deploy-PimActivatorClient.ps1 not found at $policyInstaller" }
    & $policyInstaller -ExtensionId $extensionId -UpdateUrl $CrxUpdateUrl -TenantId $ctx.TenantId -ClientId $app.AppId -Scope $PushPolicyScope -Browser $TargetBrowser
    Write-Host "[ 6 / 6 ] OK -- $TargetBrowser will auto-install the extension on next launch. Restart the browser(s) to trigger." -ForegroundColor Green

    if ($PushPolicyScope -eq 'Machine') {
        Write-Host ""
        Write-Host "  ============================================================" -ForegroundColor Yellow
        Write-Host "  REMINDER: HKLM writes were just applied. In an Intune-managed" -ForegroundColor Yellow
        Write-Host "  environment Intune policy will fight these on every refresh." -ForegroundColor Yellow
        Write-Host "  Production rollouts: revert with Deploy-PimActivatorClient.ps1" -ForegroundColor Yellow
        Write-Host "  -Uninstall, then push the same payload via Intune (run this" -ForegroundColor Yellow
        Write-Host "  script with -PrintIntuneConfig to get the exact values)." -ForegroundColor Yellow
        Write-Host "  ============================================================" -ForegroundColor Yellow
    }

# ---- 6b: -PrintIntuneConfig (PRIMARY PRODUCTION PATH) ----------------------
} elseif ($PrintIntuneConfig) {

    # Resolve the updates.xml URL the Intune forcelist value will reference.
    $intuneUpdateUrl = $CrxUpdateUrl
    if (-not $intuneUpdateUrl -and $ghPagesUpdatesUrl) { $intuneUpdateUrl = $ghPagesUpdatesUrl }
    if (-not $intuneUpdateUrl) {
        throw "-PrintIntuneConfig needs the updates.xml URL: pass -CrxUpdateUrl, or combine with -PublishToGitHubPages to auto-derive it from the just-published manifest."
    }

    # Forcelist value: '<extensionId>;<updateUrl>' -- same format Chromium reads.
    $forcelistValue = "$extensionId;$intuneUpdateUrl"

    # Managed-storage payload: identical shape to what Deploy-PimActivatorClient
    # writes to the registry (tenantId / clientId / groupNameFilter /
    # defaultDurationHours / defaultJustification). Single-line so the admin
    # can paste it straight into the Intune "Configure extension management
    # settings" value field.
    $managedStorageMap = [ordered]@{
        "$extensionId" = [ordered]@{
            installation_mode = 'force_installed'
            update_url        = $intuneUpdateUrl
            managed_storage   = [ordered]@{
                tenantId             = "$($ctx.TenantId)"
                clientId             = "$($app.AppId)"
                groupNameFilter      = '^PIM-'
                defaultDurationHours = 8
                defaultJustification = 'Daily ops'
            }
        }
    }
    $managedStorageJson = ($managedStorageMap | ConvertTo-Json -Depth 5 -Compress)

    Write-Host "[ 6 / 6 ] Intune deployment config (copy these into the Intune Admin Center) ..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ----- VALUES TO PASTE -----------------------------------------" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ExtensionInstallForcelist value:" -ForegroundColor Yellow
    Write-Host "    $forcelistValue"
    Write-Host ""
    Write-Host "  ExtensionSettings (managed-storage JSON, single line):" -ForegroundColor Yellow
    Write-Host "    $managedStorageJson"
    Write-Host ""
    Write-Host "  ----- INTUNE ADMIN CENTER STEPS -------------------------------" -ForegroundColor Cyan

    if ($TargetBrowser -in @('Edge','Both')) {
        Write-Host ""
        Write-Host "  Microsoft Edge configuration profile:" -ForegroundColor Green
        Write-Host "    1. Devices -> Configuration -> Create -> Windows 10/11 -> Settings catalog"
        Write-Host "    2. Add settings: 'Microsoft Edge\Extensions\Configure which extensions are installed silently'"
        Write-Host "         Paste the ExtensionInstallForcelist value above."
        Write-Host "    3. Add settings: 'Microsoft Edge\Extensions\Configure extension management settings'"
        Write-Host "         Paste the ExtensionSettings JSON above."
        Write-Host "    4. Assign to the desired device or user group."
        Write-Host "    5. Result: Edge auto-installs the CRX on next launch + auto-updates"
        Write-Host "         on every poll thereafter from $intuneUpdateUrl"
    }

    if ($TargetBrowser -in @('Chrome','Both')) {
        Write-Host ""
        Write-Host "  Google Chrome configuration profile:" -ForegroundColor Green
        Write-Host "    1. Devices -> Configuration -> Create -> Windows 10/11 -> Settings catalog"
        Write-Host "    2. Add settings: 'Google Chrome\Extensions\Configure the list of force-installed apps and extensions'"
        Write-Host "         Paste the ExtensionInstallForcelist value above."
        Write-Host "    3. Add settings: 'Google Chrome\Extensions\Extension management settings'"
        Write-Host "         Paste the ExtensionSettings JSON above."
        Write-Host "    4. Assign to the desired device or user group."
        Write-Host "    5. Result: Chrome auto-installs the CRX on next launch + auto-updates"
        Write-Host "         on every poll thereafter from $intuneUpdateUrl"
    }

    Write-Host ""
    Write-Host "  ----- WHY THIS BEATS -PushPolicy ------------------------------" -ForegroundColor Cyan
    Write-Host "    Intune is the authoritative policy source in customer envs." -ForegroundColor DarkGray
    Write-Host "    Local HKLM writes from -PushPolicy would fight Intune on" -ForegroundColor DarkGray
    Write-Host "    every refresh. Pushing via Intune is the production path." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "[ 6 / 6 ] OK -- Intune payload printed above. No registry writes performed." -ForegroundColor Green

# ---- 6c: default -- print the URLs, nothing else ---------------------------
} else {
    Write-Host "[ 6 / 6 ] Skipped policy push (no -PushPolicy / -PrintIntuneConfig)." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Sideload manually (developer workstation):" -ForegroundColor Yellow
    Write-Host "    1. Edge -> edge://extensions/   (or Chrome -> chrome://extensions/)"
    Write-Host "    2. Toggle Developer mode ON (top-right)"
    Write-Host "    3. Click 'Load unpacked', browse to:"
    Write-Host "       $activatorDir"
    Write-Host "    4. Extension card appears -- verify the ID matches: $extensionId"
    Write-Host "    5. Pin via the puzzle (Extensions) icon"
    Write-Host ""
    Write-Host "  Production rollout: re-run with -PrintIntuneConfig to get the" -ForegroundColor DarkGray
    Write-Host "  exact Intune Admin Center copy-paste values." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  Activator setup complete" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  Tenant         : $($ctx.TenantId)"
Write-Host "  Extension ID   : $extensionId"
Write-Host "  App reg name   : $($app.DisplayName)"
Write-Host "  App reg AppId  : $($app.AppId)"
Write-Host "  Redirect URI   : https://$extensionId.chromiumapp.org/"
Write-Host "  config.js      : $configPath"
if ($PublishToGitHubPages) {
    Write-Host "  GitHub repo    : $GitHubRepo (branch $GitHubBranch)"
    Write-Host "  Signing key    : $LocalSigningKeyPath  (BACK UP -- maintainer secret)"
    Write-Host "  CRX URL        : $ghPagesCrxUrl"
    Write-Host "  updates.xml    : $ghPagesUpdatesUrl"
    Write-Host "  Pages reminder : Enable once via Settings -> Pages -> Branch '$GitHubBranch'"
}
if ($PushPolicy)         { Write-Host "  Policy push    : APPLIED for $TargetBrowser ($PushPolicyScope scope) -- restart browser(s) to auto-install" }
if ($PrintIntuneConfig)  { Write-Host "  Intune config  : PRINTED above -- paste into Intune Admin Center (no registry writes performed)" }
Write-Host ""
Write-Host "Re-runnable: same command in this tenant updates the app reg in" -ForegroundColor DarkGray
Write-Host "place, re-writes config.js, leaves the extension ID stable." -ForegroundColor DarkGray
