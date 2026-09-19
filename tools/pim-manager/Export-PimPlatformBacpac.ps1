<#
.SYNOPSIS
    6-hourly portable BACPAC export of the PimPlatform Azure SQL database, run from INSIDE the
    PIM VNET (a management host or a VNET-injected runner), with retention pruning. Cert-only auth.

.DESCRIPTION
    PimPlatform's logical server and its backup storage account both have
    PublicNetworkAccess = Disabled (private endpoint only).
    The serverless Azure SQL export service (New-AzSqlDatabaseExport / 'az sql db export')
    runs OUTSIDE the VNET and therefore CANNOT reach these private endpoints, so the native
    export path does not work for PIM without opening public access (a security regression we
    will NOT make).

    This script instead exports with SqlPackage.exe from a host that IS on the allowed VNET
    (the management host, or a VNET-injected runner). It:
      1. Connects as the caller-supplied SPN via CERTIFICATE (Connect-AzAccount).
      2. Acquires an Entra access token for SQL (https://database.windows.net/) - no SQL password.
      3. SqlPackage /a:Export writes a local .bacpac, authenticating with /AccessToken.
      4. Uploads the .bacpac to the private 'sqlbackups' container on the backup storage
         account WITH ENTRA AUTH (New-AzStorageContext -UseConnectedAccount) -- never an
         account key -- then prunes anything older than RetentionDays.

    Rights the SPN needs: a database user in the PIM database (read), and 'Storage Blob Data
    Contributor' on the backup storage account (or its container). SqlPackage must be installed:
        dotnet tool install --global microsoft.sqlpackage
    or downloaded from https://aka.ms/sqlpackage-windows .

.NOTES
    IMP-49 j: SPN + certificate only, and BOTH values are passed in (-ApplicationId,
    -CertificateThumbprint) -- the script no longer names any Key Vault or secret of the
    environment it happens to be developed in, and it no longer reads a storage ACCOUNT KEY
    (a key is full control of every container in the account, and it is not audited per caller).
    No secrets, no device-code. AccessToken is passed to SqlPackage in-process and not logged.
#>
[CmdletBinding()]
param(
    # SEC-02: real ids are environment values, not defaults baked into a script under the
    # published tree. Pass them, or set PIM_TenantId / PIM_SqlSubscriptionId.
    # Real values: internal/REAL-IDENTIFIERS.md (never published).
    [string] $TenantId            = "$($env:PIM_TenantId)",
    [string] $SubscriptionId      = "$($env:PIM_SqlSubscriptionId)",
    [string] $ApplicationId,                 # the exporting SPN's client id (from YOUR secret store; required)
    [string] $CertificateThumbprint,         # its certificate thumbprint, in LocalMachine\My or CurrentUser\My (required)
    # SEC-02, same rule: a server FQDN / resource group / storage account name IS a real
    # environment identifier. Pass them, or set PIM_SqlServerFqdn / PIM_SqlResourceGroup /
    # PIM_BackupStorageAccount. Real values: internal/REAL-IDENTIFIERS.md (never published).
    [string] $ServerFqdn          = "$($env:PIM_SqlServerFqdn)",
    [string] $DatabaseName        = 'PimPlatform',
    # IMP-49 j: no longer read (it only served the account-key lookup); accepted so existing callers still bind.
    # audit:unused-ok ResourceGroupName
    [string] $ResourceGroupName   = "$($env:PIM_SqlResourceGroup)",
    [string] $StorageAccountName  = "$($env:PIM_BackupStorageAccount)",
    [string] $ContainerName       = 'sqlbackups',
    [string] $WorkDir             = "$env:TEMP\pimbacpac",
    [string] $SqlPackagePath      = 'SqlPackage',   # on PATH after dotnet tool install
    [int]    $RetentionDays       = 7
)

$ErrorActionPreference = 'Stop'

# IMP-49 j: every identity value is an INPUT. This used to fall back to reading two named secrets from one specific
# internal Key Vault -- environment detail inside a solution file, and a silent switch to a different identity whenever
# a caller forgot a parameter. Refuse instead, before anything is touched.
$missingIn = @(foreach ($p in @(@('TenantId', $TenantId), @('SubscriptionId', $SubscriptionId), @('ApplicationId', $ApplicationId),
                              @('CertificateThumbprint', $CertificateThumbprint), @('ServerFqdn', $ServerFqdn), @('StorageAccountName', $StorageAccountName))) {
    if (-not "$($p[1])".Trim()) { "-$($p[0])" } })
if ($missingIn.Count) { throw "Export-PimPlatformBacpac: $($missingIn -join ', ') required (SPN + certificate; no value is read from any vault by this script)." }
Disable-AzContextAutosave -Scope Process | Out-Null

Connect-AzAccount -ServicePrincipal -ApplicationId $ApplicationId -Tenant $TenantId `
    -CertificateThumbprint $CertificateThumbprint -SubscriptionId $SubscriptionId -WarningAction SilentlyContinue | Out-Null

# AAD token for SQL data plane
$tokObj = Get-AzAccessToken -ResourceUrl 'https://database.windows.net/'
$accessToken = if ($tokObj.Token -is [System.Security.SecureString]) {
    [System.Net.NetworkCredential]::new('', $tokObj.Token).Password
} else { $tokObj.Token }

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$stamp    = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$bacpac   = Join-Path $WorkDir "$DatabaseName-$stamp.bacpac"

Write-Output "[$(Get-Date -Format o)] SqlPackage export $ServerFqdn/$DatabaseName -> $bacpac"
& $SqlPackagePath /a:Export `
    /SourceServerName:$ServerFqdn `
    /SourceDatabaseName:$DatabaseName `
    /AccessToken:$accessToken `
    /TargetFile:$bacpac `
    /p:VerifyExtraction=true
if ($LASTEXITCODE -ne 0) { throw "SqlPackage export failed with exit code $LASTEXITCODE" }

# Upload to private blob (this host reaches the private endpoint over the VNET).
# IMP-49 j: ENTRA auth as the connected SPN (Storage Blob Data Contributor), never the account key.
$stCtx = New-AzStorageContext -StorageAccountName $StorageAccountName -UseConnectedAccount
if (-not (Get-AzStorageContainer -Name $ContainerName -Context $stCtx -ErrorAction SilentlyContinue)) {
    New-AzStorageContainer -Name $ContainerName -Context $stCtx -Permission Off | Out-Null
}
$blobName = Split-Path $bacpac -Leaf
Set-AzStorageBlobContent -File $bacpac -Container $ContainerName -Blob $blobName -Context $stCtx -Force | Out-Null
Write-Output "[$(Get-Date -Format o)] Uploaded $blobName"
Remove-Item $bacpac -Force

# Retention prune (both blob and any stray local files)
$cutoff = (Get-Date).ToUniversalTime().AddDays(-$RetentionDays)
Get-AzStorageBlob -Container $ContainerName -Context $stCtx |
    Where-Object { $_.Name -like "$DatabaseName-*.bacpac" -and $_.LastModified.UtcDateTime -lt $cutoff } |
    ForEach-Object {
        Write-Output "[$(Get-Date -Format o)] Pruning $($_.Name)"
        Remove-AzStorageBlob -Container $ContainerName -Blob $_.Name -Context $stCtx -Force
    }
Write-Output "[$(Get-Date -Format o)] Done."
