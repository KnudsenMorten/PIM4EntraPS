#Requires -Version 5.1
<#
.SYNOPSIS
    CERTIFICATE-ONLY sign-in (PIM-Rest, no az) with its PEM in a restricted, per-run directory. Dot-sourced by the one-shot MSP build
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
      * Invoke-PimCertAzLogin         -- PIM-Rest's token client signs in as ONE certificate identity (100.41: no az,
                                         no az profile), the PEM lands in that directory, and the subscription is read
                                         back over ARM. The caller removes the directory when the run ends.
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
    # SIDs, never names (2026-10-10: on a Danish Windows 'BUILTIN\Administrators' / 'NT AUTHORITY\SYSTEM' do not exist --
    # 'Some or all identity references could not be translated' stopped a customer's install): current user, SYSTEM, Administrators.
    foreach ($id in @([System.Security.Principal.WindowsIdentity]::GetCurrent().User, (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')), (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -Path $Path -AclObject $acl
    return $Path
}

function Invoke-PimCertAzLogin {
    <#
      71.18 -- sign in as ONE certificate identity and prove it can see -SubscriptionId. Used by the one-shot MSP build
      (Invoke-PimMspBuild.ps1). Returns @{ ok; reason; pemPath }. The PEM is written into -ProfileDir (created + ACL'd)
      for the steps that take a PEM path ({{pem:deploy}} -- they find the certificate BY THUMBPRINT in the store), and is
      removed with the directory by the CALLER. The name is historical.
      100.41 NO-AZ: no az, no AZURE_CONFIG_DIR. PIM-Rest's ONE token client is pointed at the certificate
      (Connect-PimSetupRest, certificate mode) and the subscription is read back over ARM: it must exist, be visible to
      that identity, and belong to -TenantId. -Connect / -ReadSubscription are the offline test seams.
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$CertThumbprint,
          [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ProfileDir, [string]$Name = 'deploy',
          [scriptblock]$Connect, [scriptblock]$ReadSubscription)
    $null = New-PimRestrictedProfileDir -Path $ProfileDir
    $cert = Get-Item -LiteralPath "Cert:\LocalMachine\My\$CertThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) { return @{ ok = $false; reason = "certificate $CertThumbprint is not in Cert:\LocalMachine\My" } }
    try { $pem = ConvertTo-PimCertificatePem -Certificate $cert } catch { return @{ ok = $false; reason = "$($_.Exception.Message)" } }
    $pemPath = Join-Path $ProfileDir "$Name.pem"
    [IO.File]::WriteAllText($pemPath, $pem, [Text.Encoding]::ASCII); $pem = $null
    if (-not $Connect) {
        if (-not (Get-Command Connect-PimSetupRest -ErrorAction SilentlyContinue)) {
            $sh = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared'
            if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $sh 'PIM-Rest.ps1') }
            . (Join-Path $sh 'PIM-ArmSetup.ps1')
        }
        $Connect = { param($t, $c, $th, $s) [void](Connect-PimSetupRest -TenantId $t -ClientId $c -CertThumbprint $th -SubscriptionId $s) }
    }
    if (-not $ReadSubscription) { $ReadSubscription = { param($s) Get-PimArmSubscription -SubscriptionId $s -ErrorAsNull } }
    try { & $Connect $TenantId $ClientId $CertThumbprint $SubscriptionId } catch { return @{ ok = $false; reason = "certificate sign-in failed for $ClientId in ${TenantId}: $($_.Exception.Message)"; pemPath = $pemPath } }
    $cur = $null
    try { $cur = & $ReadSubscription $SubscriptionId } catch { $cur = $null }
    if (-not $cur) { return @{ ok = $false; reason = "$ClientId cannot see subscription $SubscriptionId$(if ($global:PimSetupRestLastError) { " ($($global:PimSetupRestLastError))" })"; pemPath = $pemPath } }
    if ("$($cur.subscriptionId)" -ne $SubscriptionId -or "$($cur.tenantId)" -ne $TenantId) { return @{ ok = $false; reason = "subscription read back as $($cur.subscriptionId)/$($cur.tenantId), expected $SubscriptionId/$TenantId"; pemPath = $pemPath } }
    return @{ ok = $true; reason = "signed in by certificate as $ClientId (tenant $TenantId, subscription $SubscriptionId)"; pemPath = $pemPath }
}
