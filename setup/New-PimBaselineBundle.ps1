#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline-courier PRODUCER (LIFECYCLE-GOVERNANCE § 19): export the MSP's
    Owner=MSP baseline from the central registry, sign it, and publish the
    signed bundle to private-endpoint blob storage for local engines to pull.

.DESCRIPTION
    MSP-side. Reads pim.CentralAdmins WHERE Owner='MSP' from the central
    registry, builds a versioned payload, signs it RSA-SHA256 with the
    CN=PIM4EntraPS-Baseline private key (non-exportable, machine cert store --
    never distributed), and uploads {payloadB64, signature, keyThumbprint} to
    the baseline container. Local engines pull + verify with the embedded
    PUBLIC cert (engine/_shared/PIM-Baseline.ps1). The bundle is signed, not
    encrypted -- integrity + authenticity, full transparency.

    SQL + blob are both reached over their private endpoints; no Graph here, so
    no Azure.Core isolation needed.
#>
[CmdletBinding()]
param(
    [string]$CentralServer,
    [string]$Database = 'PimPlatform',
    [string]$StorageAccount,
    [string]$Container = 'baselines',
    [string]$Scope = 'fleet',
    [int]$ValidDays = 30
)

$ErrorActionPreference = 'Stop'
Import-Module SqlServer -ErrorAction Stop
Import-Module Az.Storage -ErrorAction Stop

if (-not $CentralServer)  { $CentralServer  = (Get-Content C:\TMP\pim-sqlserver-name.txt -Raw).Trim() + '.database.windows.net' }
if (-not $StorageAccount) { $StorageAccount = (Get-Content C:\TMP\pim-baseline-storage.txt -Raw).Trim() }

# 1. Read the Owner=MSP baseline rows from the central registry.
$sqlTok = (Get-AzAccessToken -ResourceUrl 'https://database.windows.net/').Token
if ($sqlTok -is [securestring]) { $sqlTok = [System.Net.NetworkCredential]::new('', $sqlTok).Password }
$rows = Invoke-Sqlcmd -ServerInstance $CentralServer -Database $Database -AccessToken $sqlTok -Encrypt Mandatory `
    -Query "SELECT UserName, DisplayName, FirstName, LastName, Initials, UsageLocation, Purpose, Ring, Template FROM pim.CentralAdmins WHERE Owner='MSP' AND Enabled=1 ORDER BY Ring"
$rowObjs = @($rows | Select-Object UserName, DisplayName, FirstName, LastName, Initials, UsageLocation, Purpose, Ring, Template)
Write-Host "baseline rows (Owner=MSP): $($rowObjs.Count)"

# 2. Build + sign the payload.
$version = [int64](Get-Date -Format 'yyMMddHHmm')
$payload = [ordered]@{
    product        = 'PIM4EntraPS'
    kind           = 'baseline'
    version        = $version
    scope          = $Scope
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    validToUtc     = (Get-Date).ToUniversalTime().AddDays($ValidDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    rows           = $rowObjs
}
$payloadJson  = ($payload | ConvertTo-Json -Depth 6 -Compress)
$payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)

$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq 'CN=PIM4EntraPS-Baseline' -and $_.HasPrivateKey } | Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { throw "CN=PIM4EntraPS-Baseline signing certificate not found in Cert:\LocalMachine\My -- bundles can only be produced on the MSP management host that owns the key." }
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$sig = $rsa.SignData($payloadBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

$doc = [ordered]@{
    product       = 'PIM4EntraPS'
    payloadB64    = [Convert]::ToBase64String($payloadBytes)
    signature     = [Convert]::ToBase64String($sig)
    keyThumbprint = $cert.Thumbprint
}
$docJson = ($doc | ConvertTo-Json -Depth 3)

# 3. Upload to the private-endpoint blob (versioned + latest).
$tmp = Join-Path $env:TEMP ("baseline-v$version.json")
[System.IO.File]::WriteAllText($tmp, $docJson, (New-Object System.Text.UTF8Encoding($false)))   # no BOM
$ctx = New-AzStorageContext -StorageAccountName $StorageAccount -UseConnectedAccount
foreach ($name in @("baseline-v$version.json", 'baseline-latest.json')) {
    Set-AzStorageBlobContent -File $tmp -Container $Container -Blob $name -Context $ctx -Force | Out-Null
    Write-Host "  uploaded $name"
}
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

Write-Host "BASELINE PUBLISHED: v$version ($($rowObjs.Count) rows, signer $($cert.Thumbprint)) -> https://$StorageAccount.blob.core.windows.net/$Container/baseline-latest.json"
