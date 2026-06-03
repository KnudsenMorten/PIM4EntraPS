#Requires -Version 5.1
<#
.SYNOPSIS
    Shared launcher-side auth helper for PIM4EntraPS community launchers.

.DESCRIPTION
    Mirrors SecurityInsight's launcher.community-vm.ps1 auth pattern verbatim
    so a customer who already uses SI does not need to learn a different model.

    Detects authentication method from $global:* set by the layered config
    (PIM4EntraPS.custom.ps1 + LauncherConfig.custom.ps1) and runs the
    Connect-AzAccount + Connect-MgGraph calls for the chosen method.

    Priority order (matches SI's launcher.community-vm.ps1):
      1. $global:UseManagedIdentity = $true                      -> Managed Identity
      2. $global:SpnKeyVaultName + $global:SpnSecretName + AppId -> SPN + KV secret
      3. $global:SpnCertificateThumbprint + ClientId             -> SPN + certificate
      4. $global:SpnClientSecret + $global:SpnClientId           -> SPN + plaintext (TESTING ONLY)
      5. (nothing matched) -> throws with the explicit 4-method message

    On success the helper sets $global:SpnAuthMode to one of:
      'ManagedIdentity' | 'KeyVaultSecret' | 'Certificate' | 'PlainTextSecret'
    so the engine (or post-helper launcher code) can branch on it.

    Required globals depending on method:
      ALL methods   : $global:SpnTenantId
      Method 1 (MI) : (only SpnTenantId)
      Method 2 (KV) : SpnClientId + SpnKeyVaultName + SpnSecretName
                      (calling identity must have KV "Get" on the named secret;
                       Az.KeyVault module must be installed)
      Method 3 (cert): SpnClientId + SpnCertificateThumbprint
                       (cert with private key must exist in either
                        Cert:\LocalMachine\My or Cert:\CurrentUser\My;
                        helper validates this BEFORE attempting Connect-AzAccount)
      Method 4 (plain): SpnClientId + SpnClientSecret

.PARAMETER GraphScopes
    Optional. If supplied AND Microsoft.Graph.Authentication is available,
    Connect-MgGraph is called with these scopes (relevant for MI mode where
    the SDK accepts -Scopes; for app+cert / app+secret modes scopes come from
    the app registration's permissions and this parameter is ignored).

.PARAMETER WhatIfMode
    Reserved for future dry-run support. Currently passed through to the
    caller's $global:WhatIfMode (already set by launcher) -- no helper-side
    effect today.

.NOTES
    Function : Connect-PimLauncherAuth
    Solution : PIM4EntraPS
    Pattern  : Mirrors SecurityInsight launcher.community-vm.ps1 inline
               auth block (the canonical SI implementation; SI does not have
               a standalone Connect-* helper at the launcher layer).
    Developed by : Morten Knudsen, Microsoft MVP
#>

function ConvertTo-PimSecureStringSafe {
    # SecureString built via constructor instead of ConvertTo-SecureString
    # to dodge the PS7/PS5.1 Microsoft.PowerShell.Security TypeData clash.
    param([Parameter(Mandatory)][string]$Plain)
    $ss = New-Object System.Security.SecureString
    foreach ($c in $Plain.ToCharArray()) { $ss.AppendChar($c) }
    $ss.MakeReadOnly()
    return $ss
}

function Test-PimLauncherModule {
    # Lightweight module presence + optional install. Mirrors SI's
    # Test-LauncherModule helper from launcher.community-vm.ps1.
    param(
        [Parameter(Mandatory)][string]$Name,
        [switch]$Required,
        [switch]$AutoInstall
    )
    $mod = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($mod) { return $true }
    if ($AutoInstall) {
        Write-Host ("[WARN]  module '{0}' missing -- attempting Install-Module -Scope CurrentUser" -f $Name) -ForegroundColor Yellow
        try {
            Install-Module $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Host ("[OK]    installed '{0}'" -f $Name) -ForegroundColor Green
            return $true
        } catch {
            if ($Required) { throw "Required module '$Name' could not be installed: $($_.Exception.Message)" }
            Write-Host ("[WARN]  optional module '{0}' install failed: {1} (continuing)" -f $Name, $_.Exception.Message) -ForegroundColor Yellow
            return $false
        }
    }
    if ($Required) { throw "Required module '$Name' is not installed. Run: Install-Module $Name -Scope CurrentUser" }
    Write-Host ("[WARN]  optional module '{0}' not installed (some features may be unavailable)" -f $Name) -ForegroundColor Yellow
    return $false
}

function Resolve-PimCertStoreLocation {
    # Probe both stores for a thumbprint with a usable private key.
    # Returns 'LocalMachine' | 'CurrentUser' | $null (not found).
    param([Parameter(Mandatory)][string]$Thumbprint)
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return $null }
    $clean = $Thumbprint -replace '\s', ''
    $lm = Get-ChildItem 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $clean -and $_.HasPrivateKey } |
            Select-Object -First 1
    if ($lm) { return 'LocalMachine' }
    $cu = Get-ChildItem 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $clean -and $_.HasPrivateKey } |
            Select-Object -First 1
    if ($cu) { return 'CurrentUser' }
    return $null
}

function Connect-PimLauncherAuth {
    [CmdletBinding()]
    param(
        [string[]]$GraphScopes,
        [switch]$WhatIfMode
    )

    function _AuthStep ([string]$m) { Write-Host "[STEP]  $m" -ForegroundColor Cyan }
    function _AuthInfo ([string]$m) { Write-Host "[INFO]  $m" -ForegroundColor White }
    function _AuthOk   ([string]$m) { Write-Host "[OK]    $m" -ForegroundColor Green }
    function _AuthWarn ([string]$m) { Write-Host "[WARN]  $m" -ForegroundColor Yellow }
    function _AuthErr  ([string]$m) { Write-Host "[ERROR] $m" -ForegroundColor Red }

    _AuthStep "Resolving authentication"

    if (-not $global:SpnTenantId -or [string]::IsNullOrWhiteSpace([string]$global:SpnTenantId)) {
        throw @"
Launcher: `$global:SpnTenantId is required but not set.

Put your SPN / Managed Identity credentials in ONE of these files:
  * config\PIM4EntraPS.custom.ps1                  (solution-wide -- recommended; covers every PIM4EntraPS engine)
  * launcher\<engine>\LauncherConfig.custom.ps1    (per-engine override; closest wins)

Copy the matching .sample.ps1 next to the target file and fill in your values.
"@
    }

    try {
        [void](Test-PimLauncherModule -Name 'Az.Accounts' -Required -AutoInstall)
        Import-Module Az.Accounts -ErrorAction Stop -WarningAction SilentlyContinue
    } catch {
        _AuthErr "Failed to load Az.Accounts: $($_.Exception.Message)"
        throw
    }

    $haveKv = Test-PimLauncherModule -Name 'Az.KeyVault' -AutoInstall
    $haveMg = Test-PimLauncherModule -Name 'Microsoft.Graph.Authentication' -AutoInstall

    $authMethodUsed = $null
    try {
        # ----- Method 1: Managed Identity -----
        if ([bool]$global:UseManagedIdentity) {
            _AuthStep "Auth method: Managed Identity"
            Connect-AzAccount -Identity -WarningAction SilentlyContinue | Out-Null
            if ($haveMg) {
                Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
                if ($GraphScopes) {
                    Connect-MgGraph -Identity -Scopes $GraphScopes -NoWelcome -WarningAction SilentlyContinue | Out-Null
                } else {
                    Connect-MgGraph -Identity -NoWelcome -WarningAction SilentlyContinue | Out-Null
                }
            }
            $authMethodUsed = 'ManagedIdentity'
        }
        # ----- Method 2: SPN + Key Vault secret -----
        elseif ($global:SpnKeyVaultName -and $global:SpnSecretName) {
            _AuthStep ("Auth method: SPN + Key Vault  (kv='{0}', secret='{1}')" -f $global:SpnKeyVaultName, $global:SpnSecretName)
            if (-not $haveKv)             { throw "Az.KeyVault is required for Key Vault auth." }
            if (-not $global:SpnClientId) { throw "`$global:SpnClientId is required for SPN + Key Vault auth." }
            Import-Module Az.KeyVault -ErrorAction Stop -WarningAction SilentlyContinue
            # Use MI / interactive context already present in the session to read the KV secret,
            # then re-Connect as the SPN. Mirrors SI's flow.
            Connect-AzAccount -Identity -WarningAction SilentlyContinue | Out-Null
            $secretSecure = (Get-AzKeyVaultSecret -VaultName $global:SpnKeyVaultName -Name $global:SpnSecretName -ErrorAction Stop).SecretValue
            if (-not $secretSecure) { throw "Key Vault returned no value for secret '$($global:SpnSecretName)' in '$($global:SpnKeyVaultName)'." }
            Disconnect-AzAccount -WarningAction SilentlyContinue | Out-Null
            $cred = [pscredential]::new($global:SpnClientId, $secretSecure)
            Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
            # Surface the plaintext secret onto $global:SpnClientSecret so engine
            # code that already reads it (e.g. AzLogDcrIngestPS / Connect-MgGraph
            # ClientSecretCredential below) continues to work.
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretSecure)
            try   { $global:SpnClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
            if ($haveMg) {
                Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
                $credForGraph = [pscredential]::new($global:SpnClientId, (ConvertTo-PimSecureStringSafe -Plain $global:SpnClientSecret))
                Connect-MgGraph -TenantId $global:SpnTenantId -ClientSecretCredential $credForGraph -NoWelcome -WarningAction SilentlyContinue | Out-Null
            }
            $authMethodUsed = 'KeyVaultSecret'
        }
        # ----- Method 3: SPN + certificate -----
        elseif ($global:SpnCertificateThumbprint) {
            _AuthStep ("Auth method: SPN + certificate (thumbprint='{0}')" -f $global:SpnCertificateThumbprint)
            if (-not $global:SpnClientId) { throw "`$global:SpnClientId is required for SPN + certificate auth." }
            $store = Resolve-PimCertStoreLocation -Thumbprint $global:SpnCertificateThumbprint
            if (-not $store) {
                throw ("SPN certificate with thumbprint '{0}' was not found (with private key) in Cert:\LocalMachine\My or Cert:\CurrentUser\My. Install the cert in one of those stores and retry." -f $global:SpnCertificateThumbprint)
            }
            if ($store -eq 'CurrentUser') {
                _AuthWarn ("cert found only in Cert:\CurrentUser\My (HasPrivateKey=True). For production / scheduled-task / SYSTEM service-account use, install in Cert:\LocalMachine\My so it's available to every account on this host.")
            }
            Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId `
                -ApplicationId $global:SpnClientId -CertificateThumbprint $global:SpnCertificateThumbprint `
                -WarningAction SilentlyContinue | Out-Null
            if ($haveMg) {
                Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
                Connect-MgGraph -TenantId $global:SpnTenantId -ClientId $global:SpnClientId `
                    -CertificateThumbprint $global:SpnCertificateThumbprint -NoWelcome -WarningAction SilentlyContinue | Out-Null
            }
            $authMethodUsed = 'Certificate'
        }
        # ----- Method 4: SPN + plaintext secret -----
        elseif ($global:SpnClientId -and $global:SpnClientSecret) {
            _AuthStep "Auth method: SPN + plaintext secret  [TESTING ONLY]"
            _AuthWarn "Plaintext SPN secret in config / LauncherConfig is acceptable for labs but NOT recommended for production. Switch to Managed Identity, SPN + Key Vault, or SPN + certificate when you can."
            $secretSecure = ConvertTo-PimSecureStringSafe -Plain $global:SpnClientSecret
            $cred = [pscredential]::new($global:SpnClientId, $secretSecure)
            Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
            if ($haveMg) {
                Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
                Connect-MgGraph -TenantId $global:SpnTenantId -ClientSecretCredential $cred -NoWelcome -WarningAction SilentlyContinue | Out-Null
            }
            $authMethodUsed = 'PlainTextSecret'
        }
        else {
            throw @"
No authentication method configured.
Populate ONE of (see config\PIM4EntraPS.custom.sample.ps1 or launcher\<engine>\LauncherConfig.custom.sample.ps1 for copy-pasteable blocks):
  1. `$global:UseManagedIdentity = `$true                              (Managed Identity)
  2. `$global:SpnKeyVaultName + `$global:SpnSecretName + SpnClientId   (SPN + KV secret)
  3. `$global:SpnCertificateThumbprint + SpnClientId                   (SPN + cert)
  4. `$global:SpnClientSecret + SpnClientId                            (SPN + plaintext, TESTING ONLY)
"@
        }
    } catch {
        _AuthErr "Authentication failed: $($_.Exception.Message)"
        throw
    }

    $global:SpnAuthMode = $authMethodUsed
    _AuthOk ("Authentication established ({0})" -f $authMethodUsed)
    return $authMethodUsed
}
