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
      1.5. (Optional, -DeployAzureCrxHost) Provisions Azure plumbing:
           subscription/RG/KV preflight, get-or-create the RSA 2048 CRX
           signing key in KV, refresh manifest.json's `key` field, ensure
           storage account + public-blob container, package the extension
           as a .crx with msedge.exe, generate updates.xml, and upload
           both blobs. Re-runnable end-to-end.
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
         write to HKLM. When combined with -DeployAzureCrxHost, the
         -CrxUpdateUrl is auto-derived from the just-uploaded updates.xml.

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
    Mandatory if -PushPolicy is set, UNLESS -DeployAzureCrxHost is also set
    (in which case the URL is auto-derived from the just-uploaded updates.xml).
    Example: 'https://yourstorage.blob.core.windows.net/pim-activator/updates.xml'.

.PARAMETER DeployAzureCrxHost
    Provision (idempotent) the Azure plumbing needed to host the CRX +
    updates.xml: validates the existing Key Vault, gets-or-creates the RSA
    2048 signing key as a KV secret, ensures storage account + container,
    packages the extension as .crx via msedge.exe, and uploads both files
    to a public-blob container. Composes with EITHER interactive or
    unattended auth.

.PARAMETER AzSubscriptionId
    Optional. If supplied, the script will Set-AzContext to that subscription
    before any Az calls. If omitted, uses whatever the current Az context
    points at.

.PARAMETER AzResourceGroup
    Resource group hosting the storage account. Created if missing.
    Default: 'rg-pim-activator'.

.PARAMETER AzLocation
    Azure region for the resource group + storage account. Default:
    'westeurope'.

.PARAMETER AzStorageAccountName
    Storage account name. If omitted, derived as 'stpim' + first 10 hex
    chars of sha256(tenantId) to keep it stable per tenant + globally
    unique-ish.

.PARAMETER AzStorageContainerName
    Blob container that will hold pim-activator.crx + updates.xml.
    Default: 'pim-activator'. Public blob access is enabled on individual
    blobs (so the URL is anonymously readable by Edge).

.PARAMETER AzKeyVaultName
    Existing Key Vault to store the CRX signing key in. Mandatory when
    -DeployAzureCrxHost is set. The vault is NOT created by this script
    -- the caller is expected to have one already.

.PARAMETER AzKeyVaultSecretName
    KV secret name holding the PEM-encoded RSA private key.
    Default: 'pim-activator-crx-signing-key-pem'.

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

.EXAMPLE
    # All-in-one re-runnable deployment: storage + KV signing key + CRX package + upload + policy push.
    .\Setup-PimActivator.ps1 -TenantId 'f0fa27a0-...' `
        -DeployAzureCrxHost `
        -AzSubscriptionId '54468121-98ba-48ba-ba59-ba10a9711ed3' `
        -AzKeyVaultName 'kv-2linkit-automation-p' `
        -PushPolicy

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
    [string]$CrxUpdateUrl,

    # --- NEW: Azure CRX hosting (re-runnable storage + KV + CRX package + upload) ---
    [switch]$DeployAzureCrxHost,

    [string]$AzSubscriptionId,
    [string]$AzResourceGroup = 'rg-pim-activator',
    [ValidateSet('westeurope','northeurope','eastus','westus','centralus','uksouth','australiaeast')]
    [string]$AzLocation = 'westeurope',
    [string]$AzStorageAccountName,  # default auto-derived: 'stpim' + first 10 hex of sha256(tenantId)
    [string]$AzStorageContainerName = 'pim-activator',
    [string]$AzKeyVaultName,  # mandatory if -DeployAzureCrxHost (no sensible default since KV must already exist)
    [string]$AzKeyVaultSecretName = 'pim-activator-crx-signing-key-pem'
)

$ErrorActionPreference = 'Stop'

$activatorDir = $PSScriptRoot
$manifestPath = Join-Path $activatorDir 'manifest.json'
$iconsDir     = Join-Path $activatorDir 'icons'
$configPath   = Join-Path $activatorDir 'config.js'

if ($PushPolicy -and -not $CrxUpdateUrl -and -not $DeployAzureCrxHost) {
    throw "-PushPolicy requires -CrxUpdateUrl (the .crx update-manifest URL), unless -DeployAzureCrxHost is also set (in which case the URL is auto-derived)."
}

if ($DeployAzureCrxHost -and -not $AzKeyVaultName) {
    throw "-DeployAzureCrxHost requires -AzKeyVaultName (the existing Key Vault to store the CRX signing key in)."
}

# ---------------------------------------------------------------------------
# Helper: deterministic extension ID from SPKI DER bytes
# ---------------------------------------------------------------------------

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
# Step 1.5: (optional) Azure CRX hosting (subscription/RG/KV/key/storage/CRX/upload)
# ---------------------------------------------------------------------------

# Will be populated when -DeployAzureCrxHost succeeds; used by step 6 fallback.
$autoDerivedCrxUpdateUrl = $null

if ($DeployAzureCrxHost) {

    Write-Host ""
    Write-Host "[1.5/ 6 ] Azure CRX hosting -- provisioning storage + signing key + CRX package + upload ..." -ForegroundColor Cyan

    # --- 1.5.1 Az preflight ----------------------------------------------------
    $azCtx = $null
    try { $azCtx = Get-AzContext -ErrorAction Stop } catch { $azCtx = $null }
    if (-not $azCtx -or -not $azCtx.Account) {
        throw "No Az context found. Run Connect-AzAccount (interactive) or Connect-AzAccount -ServicePrincipal ... before invoking -DeployAzureCrxHost."
    }
    if ($AzSubscriptionId) {
        $null = Set-AzContext -SubscriptionId $AzSubscriptionId -ErrorAction Stop
        $azCtx = Get-AzContext
    }
    if ($TenantId -and ($azCtx.Tenant.Id -ne $TenantId)) {
        throw "Az context tenant ($($azCtx.Tenant.Id)) does not match -TenantId ($TenantId). Reconnect Az to the right tenant first."
    }
    Write-Host "          Az subscription : $($azCtx.Subscription.Name) ($($azCtx.Subscription.Id))"
    Write-Host "          Az tenant       : $($azCtx.Tenant.Id)"

    # --- 1.5.2 Ensure resource group ------------------------------------------
    $rg = Get-AzResourceGroup -Name $AzResourceGroup -ErrorAction SilentlyContinue
    if (-not $rg) {
        Write-Host "          Resource group '$AzResourceGroup' not found -- creating in $AzLocation ..."
        $rg = New-AzResourceGroup -Name $AzResourceGroup -Location $AzLocation
        Write-Host "          OK -- created RG $AzResourceGroup"
    } else {
        Write-Host "          Resource group '$AzResourceGroup' already exists ($($rg.Location))"
    }

    # --- 1.5.3 Validate KV exists ---------------------------------------------
    $kv = Get-AzKeyVault -VaultName $AzKeyVaultName -ErrorAction Stop
    if (-not $kv) { throw "Key Vault '$AzKeyVaultName' not found in the current subscription." }
    Write-Host "          Key Vault       : $AzKeyVaultName (RG $($kv.ResourceGroupName))"

    # --- 1.5.4 Get or create the CRX signing key ------------------------------
    $existingPem = $null
    try {
        $existingPem = Get-AzKeyVaultSecret -VaultName $AzKeyVaultName -Name $AzKeyVaultSecretName -AsPlainText -ErrorAction SilentlyContinue
    } catch { $existingPem = $null }

    $rsa = $null
    if ($existingPem) {
        Write-Host "          Re-using existing signing key from KV (secret '$AzKeyVaultSecretName')." -ForegroundColor Green
        # Parse PEM -> PKCS#8 DER -> RSA
        $b64 = ($existingPem -replace '-----BEGIN PRIVATE KEY-----','' `
                              -replace '-----END PRIVATE KEY-----','' `
                              -replace '\s','')
        $pkcs8 = [Convert]::FromBase64String($b64)
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $bytesRead = 0
        $rsa.ImportPkcs8PrivateKey($pkcs8, [ref]$bytesRead)
    } else {
        Write-Host "          Signing key not found in KV -- generating fresh RSA 2048 ..."
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $pkcs8 = $rsa.ExportPkcs8PrivateKey()
        $pemB64 = [Convert]::ToBase64String($pkcs8)
        # Wrap at 64-char lines for canonical PEM
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('-----BEGIN PRIVATE KEY-----')
        for ($i = 0; $i -lt $pemB64.Length; $i += 64) {
            $end = [Math]::Min($i + 64, $pemB64.Length)
            [void]$sb.AppendLine($pemB64.Substring($i, $end - $i))
        }
        [void]$sb.AppendLine('-----END PRIVATE KEY-----')
        $pemText = $sb.ToString()
        $secureVal = ConvertTo-SecureString -String $pemText -AsPlainText -Force
        $null = Set-AzKeyVaultSecret -VaultName $AzKeyVaultName -Name $AzKeyVaultSecretName -SecretValue $secureVal
        Write-Host "          Generated new signing key + stored in KV (secret '$AzKeyVaultSecretName')." -ForegroundColor Green
    }

    # Get the PEM text (for CRX packaging below) -- re-read in plain-text form
    $signingPemText = Get-AzKeyVaultSecret -VaultName $AzKeyVaultName -Name $AzKeyVaultSecretName -AsPlainText -ErrorAction Stop

    # SPKI DER for manifest + extension-ID computation
    $spkiDer = $rsa.ExportSubjectPublicKeyInfo()
    $spkiB64 = [Convert]::ToBase64String($spkiDer)
    $derivedExtId = Get-ExtensionIdFromSpkiDer -SpkiDer $spkiDer

    # --- 1.5.5 Update manifest.json's `key` field -----------------------------
    $manifestJson = Get-Content $manifestPath -Raw | ConvertFrom-Json
    $manifestKey = $null
    if ($manifestJson.PSObject.Properties.Name -contains 'key') { $manifestKey = $manifestJson.key }
    if ($manifestKey -ne $spkiB64) {
        Write-Host "          manifest.json 'key' differs from KV signing key -- rewriting." -ForegroundColor Yellow
        if ($manifestJson.PSObject.Properties.Name -contains 'key') {
            $manifestJson.key = $spkiB64
        } else {
            $manifestJson | Add-Member -NotePropertyName 'key' -NotePropertyValue $spkiB64 -Force
        }
        ($manifestJson | ConvertTo-Json -Depth 32) | Set-Content -LiteralPath $manifestPath -Encoding UTF8
        Write-Host "          OK -- manifest.json updated; new extension ID: $derivedExtId" -ForegroundColor Green
    } else {
        Write-Host "          manifest.json 'key' already matches KV signing key; extension ID stays: $derivedExtId" -ForegroundColor Green
    }

    # --- 1.5.6 Ensure storage account -----------------------------------------
    if (-not $AzStorageAccountName) {
        $tenantForName = $TenantId
        if (-not $tenantForName) { $tenantForName = $azCtx.Tenant.Id }
        $shaName = [System.Security.Cryptography.SHA256]::Create()
        try {
            $h2 = $shaName.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($tenantForName))
        } finally { $shaName.Dispose() }
        $hex2 = ($h2 | ForEach-Object { $_.ToString('x2') }) -join ''
        $AzStorageAccountName = ('stpim' + $hex2.Substring(0,10)).ToLower()
        Write-Host "          Storage account name auto-derived: $AzStorageAccountName"
    }

    if ($AzStorageAccountName.Length -lt 3 -or $AzStorageAccountName.Length -gt 24 -or $AzStorageAccountName -notmatch '^[a-z0-9]+$') {
        throw "Storage account name '$AzStorageAccountName' is invalid (must be 3-24 lowercase alphanumeric chars)."
    }

    $sa = Get-AzStorageAccount -ResourceGroupName $AzResourceGroup -Name $AzStorageAccountName -ErrorAction SilentlyContinue
    if (-not $sa) {
        Write-Host "          Storage account '$AzStorageAccountName' not found -- creating ..."
        $sa = New-AzStorageAccount -ResourceGroupName $AzResourceGroup `
                                   -Name $AzStorageAccountName `
                                   -Location $AzLocation `
                                   -SkuName 'Standard_LRS' `
                                   -Kind 'StorageV2' `
                                   -AllowBlobPublicAccess $true `
                                   -EnableHttpsTrafficOnly $true `
                                   -MinimumTlsVersion 'TLS1_2'
        Write-Host "          OK -- created storage account $AzStorageAccountName"
    } else {
        Write-Host "          Storage account '$AzStorageAccountName' already exists ($($sa.Location), $($sa.Sku.Name))"
    }

    # --- 1.5.7 Ensure container with public blob access -----------------------
    $saKey = (Get-AzStorageAccountKey -ResourceGroupName $AzResourceGroup -Name $AzStorageAccountName | Select-Object -First 1).Value
    $storageCtx = New-AzStorageContext -StorageAccountName $AzStorageAccountName -StorageAccountKey $saKey
    $container = Get-AzStorageContainer -Name $AzStorageContainerName -Context $storageCtx -ErrorAction SilentlyContinue
    if (-not $container) {
        Write-Host "          Container '$AzStorageContainerName' not found -- creating (public blob access) ..."
        $null = New-AzStorageContainer -Name $AzStorageContainerName -Context $storageCtx -Permission Blob
        Write-Host "          OK -- created container $AzStorageContainerName"
    } else {
        Write-Host "          Container '$AzStorageContainerName' already exists"
    }

    # --- 1.5.8 Package extension as CRX (via msedge.exe) ----------------------
    $edgeCandidates = @(
        (Join-Path ${env:ProgramFiles} 'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe')
    )
    $edgeExe = $edgeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $edgeExe) {
        throw "msedge.exe not found in either Program Files location. Install Microsoft Edge (or supply the .crx out-of-band)."
    }
    Write-Host "          Using Edge for CRX packaging: $edgeExe"

    $tempPemPath = Join-Path $env:TEMP 'pim-activator-signing.pem'
    Set-Content -LiteralPath $tempPemPath -Value $signingPemText -Encoding ASCII -NoNewline
    $expectedCrx = $activatorDir.TrimEnd('\') + '.crx'
    if (Test-Path $expectedCrx) {
        Remove-Item -LiteralPath $expectedCrx -Force -ErrorAction SilentlyContinue
    }

    $crxOk = $false
    try {
        $packArgs = @("--pack-extension=$activatorDir", "--pack-extension-key=$tempPemPath")
        $proc = Start-Process -FilePath $edgeExe -ArgumentList $packArgs -NoNewWindow -Wait -PassThru
        if ($proc.ExitCode -ne 0) {
            Write-Host "          msedge.exe --pack-extension exited with code $($proc.ExitCode)" -ForegroundColor Red
        }
        if (Test-Path $expectedCrx) {
            $crxOk = $true
            Write-Host "          OK -- packaged CRX: $expectedCrx" -ForegroundColor Green
        } else {
            Write-Host "          ERROR -- expected CRX not found at $expectedCrx. Fall back to a manual CRX3 build (not implemented in this release)." -ForegroundColor Red
        }
    } finally {
        # Always remove the temp PEM (don't leave a private key on disk).
        if (Test-Path $tempPemPath) { Remove-Item -LiteralPath $tempPemPath -Force -ErrorAction SilentlyContinue }
    }

    if (-not $crxOk) {
        throw "CRX packaging failed -- aborting Azure deployment step. Re-run after confirming msedge.exe can pack the extension manually."
    }

    # --- 1.5.9 Generate updates.xml -------------------------------------------
    $extVersion = $manifestJson.version
    if (-not $extVersion) { throw "manifest.json has no 'version' field; cannot generate updates.xml." }
    $crxBlobName     = 'pim-activator.crx'
    $updatesBlobName = 'updates.xml'
    $crxPublicUrl     = "https://$AzStorageAccountName.blob.core.windows.net/$AzStorageContainerName/$crxBlobName"
    $updatesPublicUrl = "https://$AzStorageAccountName.blob.core.windows.net/$AzStorageContainerName/$updatesBlobName"

    $updatesXml = @"
<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='$derivedExtId'>
    <updatecheck codebase='$crxPublicUrl' version='$extVersion' />
  </app>
</gupdate>
"@
    $tempUpdatesPath = Join-Path $env:TEMP 'pim-activator-updates.xml'
    Set-Content -LiteralPath $tempUpdatesPath -Value $updatesXml -Encoding UTF8

    # --- 1.5.10 Upload to blob -----------------------------------------------
    Write-Host "          Uploading $crxBlobName ..."
    $null = Set-AzStorageBlobContent -File $expectedCrx `
                                     -Container $AzStorageContainerName `
                                     -Blob $crxBlobName `
                                     -Context $storageCtx `
                                     -Properties @{ContentType='application/x-chrome-extension'} `
                                     -Force
    Write-Host "          Uploading $updatesBlobName ..."
    $null = Set-AzStorageBlobContent -File $tempUpdatesPath `
                                     -Container $AzStorageContainerName `
                                     -Blob $updatesBlobName `
                                     -Context $storageCtx `
                                     -Properties @{ContentType='application/xml'} `
                                     -Force
    if (Test-Path $tempUpdatesPath) { Remove-Item -LiteralPath $tempUpdatesPath -Force -ErrorAction SilentlyContinue }

    Write-Host "          CRX URL         : $crxPublicUrl" -ForegroundColor Cyan
    Write-Host "          updates.xml URL : $updatesPublicUrl" -ForegroundColor Cyan

    # --- 1.5.11 Auto-derive -CrxUpdateUrl when PushPolicy + no explicit URL ---
    if ($PushPolicy -and -not $CrxUpdateUrl) {
        $CrxUpdateUrl = $updatesPublicUrl
        $autoDerivedCrxUpdateUrl = $updatesPublicUrl
        Write-Host "          -CrxUpdateUrl auto-derived from upload: $CrxUpdateUrl" -ForegroundColor Green
    }

    if ($rsa) { $rsa.Dispose() }

    Write-Host "[1.5/ 6 ] OK -- Azure CRX host ready" -ForegroundColor Green
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
    if (-not $CrxUpdateUrl) {
        throw "-PushPolicy is set but -CrxUpdateUrl is empty (and -DeployAzureCrxHost did not run successfully to auto-derive one)."
    }
    Write-Host "[ 6 / 6 ] Pushing Edge policy (HKLM ExtensionInstallForcelist) ..." -ForegroundColor Cyan
    if ($autoDerivedCrxUpdateUrl) {
        Write-Host "          Using auto-derived CRX update URL: $CrxUpdateUrl" -ForegroundColor DarkGray
    }
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
if ($DeployAzureCrxHost) {
    Write-Host "  Azure RG       : $AzResourceGroup ($AzLocation)"
    Write-Host "  Storage acct   : $AzStorageAccountName"
    Write-Host "  Container      : $AzStorageContainerName"
    Write-Host "  Key Vault      : $AzKeyVaultName (secret '$AzKeyVaultSecretName')"
    Write-Host "  CRX URL        : https://$AzStorageAccountName.blob.core.windows.net/$AzStorageContainerName/pim-activator.crx"
    Write-Host "  updates.xml    : https://$AzStorageAccountName.blob.core.windows.net/$AzStorageContainerName/updates.xml"
}
if ($PushPolicy) { Write-Host "  Policy push    : APPLIED -- restart Edge to auto-install" }
Write-Host ""
Write-Host "Re-runnable: same command in this tenant updates the app reg in" -ForegroundColor DarkGray
Write-Host "place, re-writes config.js, leaves the extension ID stable." -ForegroundColor DarkGray
