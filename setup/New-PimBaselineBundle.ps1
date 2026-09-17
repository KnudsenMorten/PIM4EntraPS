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

    SQL + blob are both reached over their private endpoints. Tokens (Azure SQL
    + blob storage) are minted over PURE REST via PIM-Rest (SPN + certificate /
    Managed Identity), so this script no longer needs Az.Accounts or Az.Storage
    -- only the SqlServer module for the registry read (SQL data plane). The
    blob upload uses the REST Put Blob API (Send-PimRestBlob).
#>
[CmdletBinding()]
param(
    [string]$CentralServer,
    [string]$Database = 'PimPlatform',
    [string]$StorageAccount,
    [string]$Container = 'baselines',
    [string]$Scope = 'fleet',
    [int]$ValidDays = 30,
    # TEST-12: produce a bundle WITHOUT publishing it. The S5/S6 downlink accepts a local
    # document (-BaselineDocPath), so the scenario matrix can exercise the real signed-pull
    # path with no blob account -- and a signing change can be verified before anything is
    # published to the fleet. When set, the upload step is skipped entirely.
    [string]$OutFile,
    # TEST-12: read the registry from a LOCAL SQL instance (the scratch scenario store)
    # using Windows auth, instead of Azure SQL + a bearer token. Chosen automatically for a
    # non-Azure server name, so nothing changes for the real MSP path.
    [switch]$LocalSql,
    # 71.18: the publishing identity by CERTIFICATE, as parameters -- so the scheduled publish
    # (Register-PimBaselinePublish.ps1) needs no caller-set globals. Absent => the PIM_* globals, as before.
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertThumbprint
)

$ErrorActionPreference = 'Stop'
if ("$TenantId".Trim())       { $global:PIM_TenantId       = "$TenantId".Trim() }
if ("$ClientId".Trim())       { $global:PIM_ClientId       = "$ClientId".Trim() }
if ("$CertThumbprint".Trim()) { $global:PIM_CertThumbprint = "$CertThumbprint".Trim(); $global:PIM_UseGraphSdk = $false }

# Pure-REST token acquisition + blob upload (drops Az.Accounts / Az.Storage).
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-Rest.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-AccountRest.ps1')

if (-not $CentralServer)  { $CentralServer  = (Get-Content C:\TMP\pim-sqlserver-name.txt -Raw).Trim() + '.database.windows.net' }
if (-not $StorageAccount -and -not $OutFile) { $StorageAccount = (Get-Content C:\TMP\pim-baseline-storage.txt -Raw).Trim() }

# A local instance is anything that is not an Azure SQL endpoint.
$useLocal = $LocalSql -or ($CentralServer -notmatch '\.database\.windows\.net$')

# 71.35 -- WHAT SHIPS AND HOW IT IS SERIALISED LIVES IN ONE PLACE: engine/_shared/PIM-BaselinePublish.ps1
# (Get-PimBaselineBundlePayload). This script and the master's cloud publish job (ca-pim-publish) both call it, so a
# managed tenant receives the same payload whichever publisher produced it. Only the connection and the SIGNER differ.
if ($useLocal) {
    # Module-free, same helpers the engine uses (the SqlServer module is deliberately not a
    # dependency here -- it drags an older Azure.Core that poisons app-only Graph auth).
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-ChangeQueue.ps1')
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-SqlStore.ps1')
    $global:PIM_SqlServer = $CentralServer; $global:PIM_SqlDatabase = $Database
    Write-Host "reading registry from LOCAL SQL $CentralServer / $Database (Windows auth)"
    $cs = Get-PimSqlConnectionString
    # NO .GetNewClosure() HERE (found while building 71). A closure runs in a NEW module scope that
    # chains to GLOBAL, not to this script -- so Invoke-PimSqlQuery, dot-sourced into THIS script's
    # scope two lines up, was invisible inside it whenever the caller had not also loaded it globally.
    # Every defensive re-read then threw, was caught as "the registry predates the column", and
    # the bundle silently shipped with NO Target and NO policy -- a failure that WIDENS reach. A plain
    # scriptblock resolves through this script's scope, where both the function and $cs live.
    $runQuery = { param($q) @(Invoke-PimSqlQuery -ConnectionString $cs -Sql $q) }
} else {
    # Azure SQL access token via REST (SPN cert / MI) -- no Get-AzAccessToken.
    Import-Module SqlServer -ErrorAction Stop      # SQL data plane only -- no Az.* / Microsoft.Graph
    $sqlTok = Get-PimRestToken -Resource 'https://database.windows.net'
    $runQuery = { param($q) @(Invoke-Sqlcmd -ServerInstance $CentralServer -Database $Database -AccessToken $sqlTok -Encrypt Mandatory -Query $q) }.GetNewClosure()
}
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-BaselinePublish.ps1')
$built = Get-PimBaselineBundlePayload -RunQuery $runQuery -Scope $Scope -ValidDays $ValidDays
$version = $built.version
$payloadBytes = $built.payloadBytes

# 2. Sign -- the LEGACY signer: the CN=PIM4EntraPS-Baseline machine certificate (the cloud job signs with Key Vault).
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq 'CN=PIM4EntraPS-Baseline' -and $_.HasPrivateKey } | Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { throw "CN=PIM4EntraPS-Baseline signing certificate not found in Cert:\LocalMachine\My -- bundles can only be produced on the MSP management host that owns the key." }
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$sig = $rsa.SignData($payloadBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

$docJson = ConvertTo-PimBaselineDocJson -PayloadBytes $payloadBytes -SignatureBytes $sig -KeyThumbprint $cert.Thumbprint

# 3. Upload to the private-endpoint blob (versioned + latest) over REST
#    (Put Blob API, OAuth bearer token) -- no Az.Storage module / account key.
if ($OutFile) {
    # TEST-12: signed, but NOT published. Same bytes the blob would carry, so the downlink
    # verifies exactly what the fleet would verify.
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($OutFile, $docJson, (New-Object System.Text.UTF8Encoding($false)))   # no BOM
    Write-Host "BASELINE SIGNED (not published): v$version ($($built.rowCount) rows, $($built.assignmentCount) assignments, signer $($cert.Thumbprint)) -> $OutFile"
    return
}

$tmp = Join-Path $env:TEMP ("baseline-v$version.json")
[System.IO.File]::WriteAllText($tmp, $docJson, (New-Object System.Text.UTF8Encoding($false)))   # no BOM
try {
    foreach ($name in @("baseline-v$version.json", 'baseline-latest.json')) {
        Send-PimRestBlob -StorageAccount $StorageAccount -Container $Container -Blob $name -FilePath $tmp
        Write-Host "  uploaded $name"
    }
} finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }

Write-Host "BASELINE PUBLISHED: v$version ($($built.rowCount) rows, $($built.assignmentCount) assignments, signer $($cert.Thumbprint)) -> https://$StorageAccount.blob.core.windows.net/$Container/baseline-latest.json"
