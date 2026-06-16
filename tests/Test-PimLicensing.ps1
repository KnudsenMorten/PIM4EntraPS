#Requires -Version 5.1
<#
.SYNOPSIS
    Functional, rerunnable suite for the Core/Pro licensing split + the OFFLINE
    signed-license verification (REQUIREMENTS section 15). Offline, no live tenant.
    Mirrors the Pester 'Licensing (Core/Pro split + offline signed license)'
    Describe so the suite is green with or without Pester.

.DESCRIPTION
    The maintainer's PRIVATE signing key only ever lives on mgmt1 (LocalMachine\My),
    and the shipped code only ever VERIFIES (embedded PUBLIC cert). So this suite
    NEVER touches that key. Instead it mints an EPHEMERAL test RSA keypair at
    runtime, signs valid / expired / not-yet-valid / tenant-bound payloads with
    it, builds a TAMPERED fixture, and drives Get-PimLicense with the test public
    cert (-PublicCertB64) so the verification path is exercised end-to-end with
    valid / invalid / tampered inputs -- all PS 5.1-safe (CertificateRequest +
    raw-bytes X509Certificate2 + RSACertificateExtensions, NO ImportFromPem).

    It also asserts the distribution POLICY:
      * Pro is granted FREE by default (gate passes silently, no nag).
      * Core is NEVER gated.
      * Super-admins are NEVER locked out.
      * Only an internal harness ($global:PIM_EnforceProLicense=$true) actually
        blocks an unlicensed Pro feature.

.EXAMPLE
    powershell -NoProfile -File tests\Test-PimLicensing.ps1
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$script:pass = 0; $script:fail = 0
function T { param($n,[scriptblock]$b)
    try { $r = & $b; if ($r) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }
    catch { Write-Host "  FAIL $n -- $($_.Exception.Message.Split([char]10)[0])" -ForegroundColor Red; $script:fail++ } }
function Section($t){ Write-Host "`n== $t ==" -ForegroundColor Cyan }

$root = Split-Path -Parent $PSScriptRoot
$global:PIM_ConfigVariant = 'test'
Import-Module (Join-Path $root 'engine\_shared\PIM-Functions.psm1') -Force -DisableNameChecking

# --- Ephemeral TEST signing key (stands in for the real mgmt1-only key) -------
$script:TestRsa  = [System.Security.Cryptography.RSA]::Create(2048)
$script:TestDn   = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new('CN=PIM4EntraPS-Licensing-TEST')
$script:TestReq  = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($script:TestDn, $script:TestRsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$script:TestCert = $script:TestReq.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(5))
$script:TestCertB64 = [Convert]::ToBase64String($script:TestCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

# A DIFFERENT keypair -> stands in for "signed by some other (untrusted) key".
$script:WrongRsa  = [System.Security.Cryptography.RSA]::Create(2048)

function New-TestLicenseFile {
    param(
        [hashtable]$Payload,
        [System.Security.Cryptography.RSA]$SignWith = $script:TestRsa,
        [switch]$TamperPayload
    )
    $payloadJson  = ($Payload | ConvertTo-Json -Compress)
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)
    $sig          = $SignWith.SignData($payloadBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $payloadB64   = [Convert]::ToBase64String($payloadBytes)
    if ($TamperPayload) {
        # Re-encode a MODIFIED payload but keep the original signature -> the
        # bytes no longer match the signature == tamper detection.
        $tampered = $Payload.Clone(); $tampered.sku = 'TAMPERED'; $tampered.features = @('*')
        $payloadB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($tampered | ConvertTo-Json -Compress)))
    }
    $doc = [ordered]@{ product = 'PIM4EntraPS'; payloadB64 = $payloadB64; signature = [Convert]::ToBase64String($sig) }
    $f = Join-Path $env:TEMP ("pimlic-{0}.pimlicense" -f ([guid]::NewGuid().ToString('N')))
    ($doc | ConvertTo-Json -Compress) | Set-Content -LiteralPath $f -Encoding UTF8
    $f
}

$today    = (Get-Date).Date
$fmt      = { param($d) $d.ToString('yyyy-MM-dd') }
$basePay  = @{ licenseId='LIC-TEST-1'; customer='Acme'; sku='Pro'; features=@('*'); tenantIds=@(); validFrom=(& $fmt $today.AddDays(-10)); validTo=(& $fmt $today.AddDays(365)); graceDays=30 }

$validFile      = New-TestLicenseFile -Payload $basePay
$expiredPay     = $basePay.Clone(); $expiredPay.validFrom=(& $fmt $today.AddDays(-400)); $expiredPay.validTo=(& $fmt $today.AddDays(-60)); $expiredPay.graceDays=30
$expiredFile    = New-TestLicenseFile -Payload $expiredPay
$gracePay       = $basePay.Clone(); $gracePay.validFrom=(& $fmt $today.AddDays(-400)); $gracePay.validTo=(& $fmt $today.AddDays(-5)); $gracePay.graceDays=30
$graceFile      = New-TestLicenseFile -Payload $gracePay
$futurePay      = $basePay.Clone(); $futurePay.validFrom=(& $fmt $today.AddDays(10)); $futurePay.validTo=(& $fmt $today.AddDays(400))
$futureFile     = New-TestLicenseFile -Payload $futurePay
$tenantPay      = $basePay.Clone(); $tenantPay.tenantIds=@('11111111-1111-1111-1111-111111111111')
$tenantFile     = New-TestLicenseFile -Payload $tenantPay
$narrowPay      = $basePay.Clone(); $narrowPay.features=@('MspFanout')   # explicit, NOT '*'
$narrowFile     = New-TestLicenseFile -Payload $narrowPay
$tamperedFile   = New-TestLicenseFile -Payload $basePay -TamperPayload
$wrongKeyFile   = New-TestLicenseFile -Payload $basePay -SignWith $script:WrongRsa
$garbageFile    = Join-Path $env:TEMP ("pimlic-junk-{0}.pimlicense" -f ([guid]::NewGuid().ToString('N')))
'{ "not": "a license" }' | Set-Content -LiteralPath $garbageFile -Encoding UTF8

$created = @($validFile,$expiredFile,$graceFile,$futureFile,$tenantFile,$narrowFile,$tamperedFile,$wrongKeyFile,$garbageFile)

try {
    Section 'Pure signature verify (Test-PimLicenseSignature)'
    $okPayload = [System.Text.Encoding]::UTF8.GetBytes('hello-pim')
    $okSig     = $script:TestRsa.SignData($okPayload, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    T 'valid signature verifies against the matching public cert' { Test-PimLicenseSignature -PayloadBytes $okPayload -SignatureBytes $okSig -PublicCertB64 $script:TestCertB64 }
    T 'tampered payload fails (one byte flipped)' {
        $bad = $okPayload.Clone(); $bad[0] = [byte](($bad[0] + 1) % 256)
        -not (Test-PimLicenseSignature -PayloadBytes $bad -SignatureBytes $okSig -PublicCertB64 $script:TestCertB64) }
    T 'wrong-key signature fails against the trusted cert' {
        $wrongSig = $script:WrongRsa.SignData($okPayload, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        -not (Test-PimLicenseSignature -PayloadBytes $okPayload -SignatureBytes $wrongSig -PublicCertB64 $script:TestCertB64) }
    T 'garbage cert bytes -> false, never throws' { -not (Test-PimLicenseSignature -PayloadBytes $okPayload -SignatureBytes $okSig -PublicCertB64 'bm90LWEtY2VydA==') }

    Section 'Get-PimLicense statuses (valid / expired / grace / not-yet-valid)'
    T 'VALID license -> Status Valid'        { (Get-PimLicense -PublicCertB64 $script:TestCertB64 -Path $validFile).Status -eq 'Valid' }
    T 'EXPIRED (past grace) -> Status Expired'{ (Get-PimLicense -PublicCertB64 $script:TestCertB64 -Path $expiredFile).Status -eq 'Expired' }
    T 'GRACE window -> Status Grace'         { (Get-PimLicense -PublicCertB64 $script:TestCertB64 -Path $graceFile).Status -eq 'Grace' }
    T 'NOT-YET-VALID -> Status NotYetValid'  { (Get-PimLicense -PublicCertB64 $script:TestCertB64 -Path $futureFile).Status -eq 'NotYetValid' }
    T 'valid license reports its customer'   { (Get-PimLicense -PublicCertB64 $script:TestCertB64 -Path $validFile).Customer -eq 'Acme' }

    Section 'Get-PimLicense rejects bad / tampered / wrong-key / garbage'
    T 'TAMPERED payload -> Status Invalid'   { (Get-PimLicense -PublicCertB64 $script:TestCertB64 -Path $tamperedFile).Status -eq 'Invalid' }
    T 'WRONG-KEY signed -> Status Invalid'   { (Get-PimLicense -PublicCertB64 $script:TestCertB64 -Path $wrongKeyFile).Status -eq 'Invalid' }
    T 'GARBAGE file -> Status Invalid'       { (Get-PimLicense -PublicCertB64 $script:TestCertB64 -Path $garbageFile).Status -eq 'Invalid' }
    T 'VALID file under the REAL (production) cert -> Invalid (not our key)' { (Get-PimLicense -Path $validFile).Status -eq 'Invalid' }
    T 'override loads are NOT cached (real session cache untouched)' {
        $null = Get-PimLicense -PublicCertB64 $script:TestCertB64 -Path $validFile
        (Get-PimLicense -Refresh).Status -eq 'Missing' }   # no .pimlicense in test config dir

    Section 'Distribution policy: Pro is FREE by default (no nag, no block)'
    Remove-Variable -Name PIM_EnforceProLicense -Scope Global -ErrorAction SilentlyContinue
    T 'enforcement OFF by default'           { -not (Test-PimProLicenseEnforced) }
    T 'unlicensed Pro feature is ALLOWED (free)' { Test-PimProFeature -Feature 'MspFanout' -Quiet }
    T 'every Pro catalog feature is allowed free' {
        $cat = 'MspFanout','WorkloadConnectors','Intake','AccessReviews','SelfService','ContactsRouting','Conformance','Rings','ApproverMatrix','PawPolicy','Lifecycle','AzureDiscovery','DefinitionImport','PortalAdmins','PermissionWizard'
        ($cat | Where-Object { -not (Test-PimProFeature -Feature $_ -Quiet) }).Count -eq 0 }
    T 'edition is Community without a license, no exception' { (Get-PimEdition) -in @('Community','Pro') }

    Section 'Super-admins are NEVER locked out (even when enforced)'
    $global:PIM_EnforceProLicense = $true
    try {
        T 'enforcement ON honoured'              { Test-PimProLicenseEnforced }
        T 'unlicensed Pro feature BLOCKED when enforced' { -not (Test-PimProFeature -Feature 'MspFanout' -Quiet) }
        T 'SuperAdmin bypass ALWAYS allowed when enforced' { Test-PimProFeature -Feature 'MspFanout' -SuperAdmin -Quiet }
    } finally { Remove-Variable -Name PIM_EnforceProLicense -Scope Global -ErrorAction SilentlyContinue }

    Section 'SQL store is Core (never licensed)'
    T 'Pro feature catalog contains NO SQL/store entry' {
        $cat = Get-PimProFeatureCatalog
        ($cat | Where-Object { $_ -match '(?i)sql|store|database|data' }).Count -eq 0 }
    T 'catalog still includes the expected Pro features' {
        $cat = Get-PimProFeatureCatalog
        ($cat -contains 'MspFanout') -and ($cat -contains 'AccessReviews') -and ($cat -contains 'WorkloadConnectors') }
}
finally {
    foreach ($f in $created) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    Remove-Variable -Name PIM_EnforceProLicense -Scope Global -ErrorAction SilentlyContinue
}

Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host (" RESULT: {0} pass, {1} fail" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) {'Red'} else {'Green'})
Write-Host "=====================================================" -ForegroundColor Cyan
if ($script:fail) { exit 1 }
