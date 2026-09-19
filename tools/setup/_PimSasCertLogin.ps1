#Requires -Version 5.1
<#
.SYNOPSIS
    CERTIFICATE-ONLY az login into a restricted, per-run profile directory. Dot-sourced by the one-shot MSP build
    (tools/setup/Invoke-PimMspBuild.ps1); the file name is historical.

.DESCRIPTION
    SEC-27 (operator 2026-09-18): the SAS transport is RETIRED. This file used to carry the certificate login for the
    weekly baseline read-link (SAS) rotation -- Test-PimSasCertLoginConfig, Get-PimSasRotationTaskArgLine and
    Invoke-PimSasCertLogin -- together with Update-PimBaselineSas.ps1, New-PimSasCertLoginConfig.ps1 and
    internal/Invoke-PimEstateSasPreAuth.ps1 (which logged in with an onboarding client SECRET on the az.cmd command line).
    All of that is deleted: the downlink is public-but-signed or private-endpoint (DESIGN 13.7), with no read link and
    no rotation. What remains is the generic, secret-free certificate login the MSP build uses:

      * ConvertTo-PimCertificatePem   -- a LocalMachine\My certificate WITH its key as the PEM az expects;
      * New-PimRestrictedProfileDir   -- a directory only SYSTEM, Administrators and the running account can read;
      * Invoke-PimCertAzLogin         -- az logs in as ONE certificate identity into that directory (an isolated
                                         AZURE_CONFIG_DIR -- never the machine's default profile) and the context is
                                         read back. The caller removes the directory when the run ends.
#>

function ConvertTo-PimCertificatePem {
    <#
      A certificate WITH its private key as the PEM az expects (PKCS#8 key + certificate). Works on Windows
      PowerShell 5.1 (CNG export) and pwsh 7 (ExportPkcs8PrivateKey). Throws when the key is absent or not
      exportable -- never returns a PEM without its key.
    #>
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    if (-not $Certificate.HasPrivateKey) { throw "certificate $($Certificate.Thumbprint) has no private key on this host" }
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if ($null -eq $rsa) { throw "certificate $($Certificate.Thumbprint) does not carry an RSA key" }
    $pkcs8 = $null
    if ($rsa.PSObject.Methods['ExportPkcs8PrivateKey']) { $pkcs8 = $rsa.ExportPkcs8PrivateKey() }
    elseif ($rsa -is [System.Security.Cryptography.RSACng]) { $pkcs8 = $rsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob) }
    else { throw "certificate $($Certificate.Thumbprint): the private key cannot be exported as PKCS#8 on this host ($($rsa.GetType().Name))" }
    $b = '-----BEGIN ' + 'PRIVATE KEY-----'; $e = '-----END ' + 'PRIVATE KEY-----'
    return ($b + "`n" + [Convert]::ToBase64String($pkcs8, 'InsertLineBreaks') + "`n" + $e + "`n" +
            "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($Certificate.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n")
}

function New-PimRestrictedProfileDir {
    # A per-run directory only SYSTEM, Administrators and the running account can read (it holds certificate PEMs).
    param([Parameter(Mandatory)][string]$Path)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    foreach ($id in @($me, 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators') | Select-Object -Unique) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -Path $Path -AclObject $acl
    return $Path
}

function Invoke-PimCertAzLogin {
    <#
      71.18 -- log az in as ONE certificate identity into -ProfileDir (created + ACL'd) and select -SubscriptionId. Used by the
      one-shot MSP build (Invoke-PimMspBuild.ps1). Returns @{ ok; reason; pemPath }. The PEM stays in -ProfileDir for the
      steps that need a PEM file (the hosting prerequisites) and is removed with the directory by the CALLER.
      The `az account set` below runs INSIDE the isolated -ProfileDir (AZURE_CONFIG_DIR), never the machine's default profile.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$CertThumbprint,
          [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ProfileDir, [string]$Name = 'deploy')
    $null = New-PimRestrictedProfileDir -Path $ProfileDir
    $env:AZURE_CONFIG_DIR = $ProfileDir
    # az spawns a DETACHED telemetry uploader that keeps writing into the profile after the command returns, which
    # stops the caller from removing the directory. No telemetry, nothing left behind.
    $env:AZURE_CORE_COLLECT_TELEMETRY = 'false'
    # Windows PowerShell 5.1 turns ANY native stderr line into a terminating NativeCommandError under
    # $ErrorActionPreference='Stop' -- and az prints a harmless 32-bit-Python warning on login. The exit code is checked.
    $ErrorActionPreference = 'Continue'
    $cert = Get-Item -LiteralPath "Cert:\LocalMachine\My\$CertThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) { return @{ ok = $false; reason = "certificate $CertThumbprint is not in Cert:\LocalMachine\My" } }
    try { $pem = ConvertTo-PimCertificatePem -Certificate $cert } catch { return @{ ok = $false; reason = "$($_.Exception.Message)" } }
    $pemPath = Join-Path $ProfileDir "$Name.pem"
    [IO.File]::WriteAllText($pemPath, $pem, [Text.Encoding]::ASCII); $pem = $null
    az login --service-principal -u $ClientId --tenant $TenantId --certificate $pemPath --allow-no-subscriptions -o none --only-show-errors 2>$null
    if ($LASTEXITCODE -ne 0) { return @{ ok = $false; reason = "az certificate login failed for $ClientId in $TenantId" } }
    az account set --subscription $SubscriptionId --only-show-errors 2>$null
    if ($LASTEXITCODE -ne 0) { return @{ ok = $false; reason = "$ClientId cannot select subscription $SubscriptionId" } }
    $cur = az account show --query "{s:id,t:tenantId}" -o json --only-show-errors 2>$null | ConvertFrom-Json
    if ("$($cur.s)" -ne $SubscriptionId -or "$($cur.t)" -ne $TenantId) { return @{ ok = $false; reason = "az context read back as $($cur.s)/$($cur.t), expected $SubscriptionId/$TenantId" } }
    return @{ ok = $true; reason = "az logged in by certificate as $ClientId (tenant $TenantId, subscription $SubscriptionId)"; pemPath = $pemPath }
}
