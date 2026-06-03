#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Authentication
<#
.SYNOPSIS
    One-command turnkey installer for the PIM Activator Edge extension.

.DESCRIPTION
    Orchestrates everything a customer needs to roll out the PIM Activator on
    a new tenant. Works generically for any customer + any computer because
    the extension ID is deterministic (derived from the public key baked into
    manifest.json's `key` field).

    Steps it runs in order:

      1. Generates the 4 placeholder icons (icon-16/32/48/128) if the icons
         folder is empty -- Edge "Load unpacked" refuses to install otherwise.
      2. Computes the deterministic extension ID from the public key in
         manifest.json (no need for the operator to sideload first to learn
         the ID).
      3. Triggers ONE interactive Microsoft Graph sign-in (browser by default;
         pass -UseDeviceCode for headless hosts). Customer admin signs in once
         per tenant.
      4. Creates / updates the "PIM Activator" app registration with the right
         SPA + Public Client redirect URIs and delegated permissions, then
         grants tenant-wide admin consent.
      5. Writes config.js with the resulting tenantId + clientId so the
         extension popup is wired on first launch.
      6. (Optional, -PushPolicy) Writes the Edge ExtensionInstallForcelist
         policy registry keys so Edge auto-installs the extension on next
         launch -- no manual "Load unpacked" step. Requires admin rights to
         write to HKLM.

    Re-runnable: every step is idempotent. Same tenant -> updates the existing
    app reg in place. Same machine -> overwrites config.js + policy keys.

.PARAMETER TenantId
    Optional. If omitted, the script uses whatever tenant Connect-MgGraph
    defaulted to. Pass explicitly to be sure you target the right tenant.

.PARAMETER UseDeviceCode
    Use device-code Connect-MgGraph flow instead of browser. Slower (120-second
    sign-in window) but works on hosts without a default browser.

.PARAMETER PushPolicy
    Also write the HKLM Edge ExtensionInstallForcelist registry keys so Edge
    auto-installs the extension on next launch. Requires the script to be
    running as Administrator. Skip on developer workstations; use on
    production rollouts (Intune Win32 wrapper).

.PARAMETER CrxUpdateUrl
    URL where the .crx update manifest is hosted. Only used with -PushPolicy.
    Mandatory if -PushPolicy is set. Example:
    'https://yourstorage.blob.core.windows.net/pim-activator/updates.xml'.

.EXAMPLE
    # Developer workstation: app reg + admin consent + config.js,
    # then operator does "Load unpacked" once in Edge.
    .\Setup-PimActivator.ps1 -TenantId 'f0fa27a0-...'

.EXAMPLE
    # Production rollout: also push Edge policy so it auto-installs.
    .\Setup-PimActivator.ps1 -TenantId 'f0fa27a0-...' -PushPolicy `
        -CrxUpdateUrl 'https://stcorp.blob.core.windows.net/pim-activator/updates.xml'

.EXAMPLE
    # FULLY UNATTENDED rollout (Intune / scheduled task / Azure Function).
    # Bootstrap SPN must have 3 app permissions admin-consented in the target tenant:
    #   Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All
    # Cert thumbprint is preferred over plaintext secret.
    .\Setup-PimActivator.ps1 -TenantId 'f0fa27a0-...' `
        -BootstrapSpnAppId 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' `
        -BootstrapSpnCertificateThumbprint 'ABCDEF0123456789ABCDEF0123456789ABCDEF01' `
        -PushPolicy -CrxUpdateUrl 'https://stcorp.blob.core.windows.net/pim-activator/updates.xml'

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
    [string]$CrxUpdateUrl
)

$ErrorActionPreference = 'Stop'

$activatorDir = $PSScriptRoot
$manifestPath = Join-Path $activatorDir 'manifest.json'
$iconsDir     = Join-Path $activatorDir 'icons'
$configPath   = Join-Path $activatorDir 'config.js'

if ($PushPolicy -and -not $CrxUpdateUrl) {
    throw "-PushPolicy requires -CrxUpdateUrl (the .crx update-manifest URL)."
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
# Step 2: compute deterministic extension ID from manifest.json's `key`
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[ 2 / 6 ] Computing deterministic extension ID from manifest key ..." -ForegroundColor Cyan

$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
if (-not $manifest.key) {
    throw "manifest.json has no 'key' field. Run the one-time key-bootstrap (Setup-PimActivator can regenerate it if you delete this script + re-run, but typically the key should NEVER change). Re-generate via Generate-PimActivatorKey.ps1 (or restore from version control)."
}
$spkiDer = [Convert]::FromBase64String($manifest.key)
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $hash = $sha256.ComputeHash($spkiDer)
} finally { $sha256.Dispose() }
$first16 = $hash[0..15]
$hex = ($first16 | ForEach-Object { $_.ToString('x2') }) -join ''
$map = @{ '0'='a'; '1'='b'; '2'='c'; '3'='d'; '4'='e'; '5'='f'; '6'='g'; '7'='h';
          '8'='i'; '9'='j'; 'a'='k'; 'b'='l'; 'c'='m'; 'd'='n'; 'e'='o'; 'f'='p' }
$extensionId = ($hex.ToCharArray() | ForEach-Object { $map["$_"] }) -join ''
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
# Step 4: run Install-PimActivatorAppRegistration.ps1
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "[ 4 / 6 ] Creating / updating activator app registration ..." -ForegroundColor Cyan
$installer = Join-Path $activatorDir 'Install-PimActivatorAppRegistration.ps1'
if (-not (Test-Path $installer)) { throw "Install-PimActivatorAppRegistration.ps1 not found at $installer" }
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
  defaultDurationHours: 1,
  defaultJustification: "Daily ops"
};
"@
Set-Content -LiteralPath $configPath -Value $configContent -Encoding UTF8
Write-Host "[ 5 / 6 ] OK -- wrote $configPath" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 6: optional Edge policy push (HKLM ExtensionInstallForcelist)
# ---------------------------------------------------------------------------

Write-Host ""
if ($PushPolicy) {
    Write-Host "[ 6 / 6 ] Pushing Edge policy (HKLM ExtensionInstallForcelist) ..." -ForegroundColor Cyan
    $policyInstaller = Join-Path $activatorDir 'Install-PimActivator.ps1'
    if (-not (Test-Path $policyInstaller)) { throw "Install-PimActivator.ps1 not found at $policyInstaller" }
    & $policyInstaller -ExtensionId $extensionId -UpdateUrl $CrxUpdateUrl -TenantId $ctx.TenantId -ClientId $app.AppId -Scope Machine
    Write-Host "[ 6 / 6 ] OK -- Edge will auto-install the extension on next launch. Restart Edge to trigger." -ForegroundColor Green
} else {
    Write-Host "[ 6 / 6 ] Skipped Edge policy push (no -PushPolicy)." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Sideload manually (developer workstation):" -ForegroundColor Yellow
    Write-Host "    1. Edge -> edge://extensions/"
    Write-Host "    2. Toggle Developer mode ON (top-right)"
    Write-Host "    3. Click 'Load unpacked', browse to:"
    Write-Host "       $activatorDir"
    Write-Host "    4. Extension card appears -- verify the ID matches: $extensionId"
    Write-Host "    5. Pin via the puzzle (Extensions) icon"
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
if ($PushPolicy) { Write-Host "  Policy push    : APPLIED -- restart Edge to auto-install" }
Write-Host ""
Write-Host "Re-runnable: same command in this tenant updates the app reg in" -ForegroundColor DarkGray
Write-Host "place, re-writes config.js, leaves the extension ID stable." -ForegroundColor DarkGray
