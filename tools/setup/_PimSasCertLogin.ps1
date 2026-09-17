#Requires -Version 5.1
<#
.SYNOPSIS
    71.16 -- CERTIFICATE-ONLY unattended login for the weekly baseline read-link (SAS) rotation
    (Update-PimBaselineSas.ps1 -CertLoginConfig). Dot-sourced; the pure parts are offline-tested in
    tests/Test-PimBaselineSasRotation.ps1.

.DESCRIPTION
    The rotation needs an az context in TWO tenants: the MASTER (to mint the read-only SAS on its bundle blob)
    and the MANAGED tenant (to write it into the pull job's ACA secret). Neither tenant's managed identity can
    act in the other tenant, so this cannot be an in-cloud job; it runs on the operator host as a weekly
    scheduled task.

    The only pre-auth the product had (internal/Invoke-PimEstateSasPreAuth.ps1) logs in with each tenant's
    onboarding client SECRET. Found 2026-09-15: the armed task PIM-BaselineSasRotation had failed its last run
    (result 1), and -Register had never carried -PreAuthScript / -AzureConfigDir / -MasterSubscriptionId into the
    task at all, so an armed task could not have authenticated even when the pre-auth worked.

    This helper is the no-secret path:
      * a machine-local JSON config names, per side, ONLY { tenantId, clientId, certThumbprint, subscriptionId }.
        Any other property (a clientSecret, a password, ...) is REFUSED -- the config cannot carry a secret.
      * each certificate is read from Cert:\LocalMachine\My by thumbprint and exported to a PEM inside a per-run
        profile directory whose ACL admits only SYSTEM, Administrators and the running account;
      * az logs in as each SPN with that certificate into that directory (managed tenant first, master last so the
        master is the active context), and the caller deletes the directory when the run ends.
#>

$script:PimSasCertLoginFields = @('tenantId', 'clientId', 'certThumbprint', 'subscriptionId')

function Test-PimSasCertLoginConfig {
    <#
      PURE. Validate the certificate-login config. Returns @{ ok; reason; master; slave } where master/slave are
      @{ tenantId; clientId; certThumbprint; subscriptionId } (thumbprint upper-cased).
      FAIL CLOSED: a missing side, a malformed id, a non-40-hex thumbprint, or ANY property outside the four
      certificate-identity fields refuses the whole config.
    #>
    param([AllowNull()][object]$Config)
    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    if ($null -eq $Config) { return @{ ok = $false; reason = 'no certificate-login config' } }
    $out = @{ ok = $true; reason = ''; master = $null; slave = $null }
    $top = @($Config.PSObject.Properties | ForEach-Object { $_.Name })
    $extraTop = @($top | Where-Object { $_ -notin @('master', 'slave', '_comment') })
    if ($extraTop.Count) { return @{ ok = $false; reason = "unexpected top-level propert$(if ($extraTop.Count -eq 1) { 'y' } else { 'ies' }) '$($extraTop -join "', '")' -- only master / slave are accepted" } }
    foreach ($side in 'master', 'slave') {
        $s = $Config.$side
        if ($null -eq $s) { return @{ ok = $false; reason = "the '$side' identity is missing" } }
        $names = @($s.PSObject.Properties | ForEach-Object { $_.Name })
        $extra = @($names | Where-Object { $_ -notin $script:PimSasCertLoginFields })
        if ($extra.Count) {
            return @{ ok = $false; reason = "REFUSED: '$side' carries '$($extra -join "', '")' -- a certificate-login config holds ONLY tenantId, clientId, certThumbprint and subscriptionId (never a secret)" }
        }
        $v = @{}
        foreach ($f in $script:PimSasCertLoginFields) { $v[$f] = "$($s.$f)".Trim() }
        foreach ($f in 'tenantId', 'clientId', 'subscriptionId') {
            if ($v[$f] -notmatch $guid) { return @{ ok = $false; reason = "'$side.$f' is not a GUID ('$($v[$f])')" } }
        }
        if ($v['certThumbprint'] -notmatch '^[0-9a-fA-F]{40}$') { return @{ ok = $false; reason = "'$side.certThumbprint' is not a 40-hex certificate thumbprint" } }
        $v['certThumbprint'] = $v['certThumbprint'].ToUpperInvariant()
        $out[$side] = $v
    }
    if ($out.master.tenantId -eq $out.slave.tenantId -and $out.master.subscriptionId -eq $out.slave.subscriptionId) {
        return @{ ok = $false; reason = 'master and slave name the same tenant and subscription -- the rotation writes into the MANAGED tenant' }
    }
    return $out
}

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

function Get-PimSasRotationTaskArgLine {
    <#
      PURE. The powershell.exe argument line the WEEKLY task runs. Every context input the run needs travels
      with it -- the defect this replaces dropped -PreAuthScript, -AzureConfigDir and -MasterSubscriptionId, so the
      armed task started with no way to authenticate.
    #>
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$StorageAccount,
        [string]$Container = 'baselines', [string]$Blob = 'baseline-latest.json',
        [string]$ResourceGroup, [string]$JobName = 'ca-pim-downlink-s6', [string]$SecretName = 'pim-baseline-url',
        [int]$ValidDays = 30, [string]$SubscriptionId, [string]$MasterSubscriptionId,
        [string]$CertLoginConfig, [string]$PreAuthScript, [string]$AzureConfigDir
    )
    $q = { param($v) '"' + "$v" + '"' }
    $line = ('-NoProfile -ExecutionPolicy Bypass -File {0} -StorageAccount {1} -Container {2} -Blob {3} -ResourceGroup {4} -JobName {5} -SecretName {6} -ValidDays {7}' -f `
             (& $q $ScriptPath), $StorageAccount, $Container, $Blob, $ResourceGroup, $JobName, $SecretName, $ValidDays)
    if ("$SubscriptionId".Trim())       { $line += " -SubscriptionId $("$SubscriptionId".Trim())" }
    if ("$MasterSubscriptionId".Trim()) { $line += " -MasterSubscriptionId $("$MasterSubscriptionId".Trim())" }
    if ("$CertLoginConfig".Trim())      { $line += " -CertLoginConfig $(& $q "$CertLoginConfig".Trim())" }
    if ("$PreAuthScript".Trim())        { $line += " -PreAuthScript $(& $q "$PreAuthScript".Trim())" }
    if ("$AzureConfigDir".Trim())       { $line += " -AzureConfigDir $(& $q "$AzureConfigDir".Trim())" }
    return $line
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
    #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string]$CertThumbprint,
          [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ProfileDir, [string]$Name = 'deploy')
    $null = New-PimRestrictedProfileDir -Path $ProfileDir
    $env:AZURE_CONFIG_DIR = $ProfileDir
    $env:AZURE_CORE_COLLECT_TELEMETRY = 'false'
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

function Invoke-PimSasCertLogin {
    <#
      Log az in as BOTH certificate identities into -ProfileDir (created here, ACL'd to SYSTEM, Administrators and
      the running account). Managed tenant first, master last and selected, so the caller's context check sees the
      master. Returns @{ ok; reason }. Never prints a credential; the PEMs live only inside -ProfileDir, which the
      CALLER removes when the run ends.
    #>
    param([Parameter(Mandatory)][hashtable]$Config, [Parameter(Mandatory)][string]$ProfileDir)
    New-Item -ItemType Directory -Force -Path $ProfileDir | Out-Null
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    foreach ($id in @($me, 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators') | Select-Object -Unique) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -Path $ProfileDir -AclObject $acl
    $env:AZURE_CONFIG_DIR = $ProfileDir
    # az spawns a DETACHED telemetry uploader that keeps writing into the profile after the command returns, which
    # stopped the caller from removing the directory (measured on the first run). No telemetry, nothing left behind.
    $env:AZURE_CORE_COLLECT_TELEMETRY = 'false'
    # Windows PowerShell 5.1 turns ANY native stderr line into a terminating NativeCommandError under
    # $ErrorActionPreference='Stop' -- and az prints a harmless 32-bit-Python warning on login. The exit code is
    # what is checked, so native output must not throw here.
    $ErrorActionPreference = 'Continue'
    foreach ($side in 'slave', 'master') {
        $s = $Config[$side]
        $cert = Get-Item -LiteralPath "Cert:\LocalMachine\My\$($s.certThumbprint)" -ErrorAction SilentlyContinue
        if (-not $cert) { return @{ ok = $false; reason = "$side certificate $($s.certThumbprint) is not in Cert:\LocalMachine\My" } }
        try { $pem = ConvertTo-PimCertificatePem -Certificate $cert }
        catch { return @{ ok = $false; reason = "$side certificate: $($_.Exception.Message)" } }
        $pemPath = Join-Path $ProfileDir "$side.pem"
        [IO.File]::WriteAllText($pemPath, $pem, [Text.Encoding]::ASCII)
        $pem = $null
        az login --service-principal -u $s.clientId --tenant $s.tenantId --certificate $pemPath --allow-no-subscriptions -o none --only-show-errors 2>$null
        if ($LASTEXITCODE -ne 0) { return @{ ok = $false; reason = "az certificate login failed for the $side identity ($($s.clientId) in $($s.tenantId))" } }
    }
    az account set --subscription $Config.master.subscriptionId --only-show-errors 2>$null
    if ($LASTEXITCODE -ne 0) { return @{ ok = $false; reason = "the master identity cannot select subscription $($Config.master.subscriptionId)" } }
    return @{ ok = $true; reason = "az logged in by certificate: slave $($Config.slave.clientId), master $($Config.master.clientId) (active)" }
}
