<#
.SYNOPSIS
    6-hourly portable BACPAC export of the PimPlatform Azure SQL database, run from INSIDE the
    PIM VNET (mgmt1 or a VNET-injected runner), with retention pruning. Cert-only auth.

.DESCRIPTION
    PimPlatform's logical server and its backup storage account both have
    PublicNetworkAccess = Disabled (private endpoint only).
    The serverless Azure SQL export service (New-AzSqlDatabaseExport / 'az sql db export')
    runs OUTSIDE the VNET and therefore CANNOT reach these private endpoints, so the native
    export path does not work for PIM without opening public access (a security regression we
    will NOT make).

    This script instead exports with SqlPackage.exe from a host that IS on the allowed VNET
    (mgmt1, or the ca-pim-scheduler container if SqlPackage is baked into its image). It:
      1. Connects as the PIM management SPN via certificate (Connect-AzAccount).
      2. Acquires an AAD access token for SQL (https://database.windows.net/) - no SQL password.
      3. SqlPackage /a:Export writes a local .bacpac, authenticating with /AccessToken.
      4. Uploads the .bacpac to the private 'sqlbackups' container on the backup storage
         account (mgmt1 reaches the private blob endpoint over the VNET), then prunes
         anything older than RetentionDays.

    The running SPN must be a database user in PimPlatform (the management SPN is the AAD
    admin on the server, so it already is). SqlPackage must be installed:
        dotnet tool install --global microsoft.sqlpackage
    or downloaded from https://aka.ms/sqlpackage-windows .

.NOTES
    Auth model per CLAUDE.md: SPN + certificate; ids/thumbprint read from kv-automatit-dev.
    No secrets, no device-code. AccessToken is passed to SqlPackage in-process and not logged.
#>
[CmdletBinding()]
param(
    # SEC-02: real ids are environment values, not defaults baked into a script under the
    # published tree. Pass them, or set PIM_TenantId / PIM_SqlSubscriptionId.
    # Real values: internal/REAL-IDENTIFIERS.md (never published).
    [string] $TenantId            = "$($env:PIM_TenantId)",
    [string] $SubscriptionId      = "$($env:PIM_SqlSubscriptionId)",
    [string] $ApplicationId,                 # PIM management SPN client id (from kv-automatit-dev)
    [string] $CertificateThumbprint,         # its cert thumbprint (from kv-automatit-dev)
    # SEC-02, same rule: a server FQDN / resource group / storage account name IS a real
    # environment identifier. Pass them, or set PIM_SqlServerFqdn / PIM_SqlResourceGroup /
    # PIM_BackupStorageAccount. Real values: internal/REAL-IDENTIFIERS.md (never published).
    [string] $ServerFqdn          = "$($env:PIM_SqlServerFqdn)",
    [string] $DatabaseName        = 'PimPlatform',
    [string] $ResourceGroupName   = "$($env:PIM_SqlResourceGroup)",
    [string] $StorageAccountName  = "$($env:PIM_BackupStorageAccount)",
    [string] $ContainerName       = 'sqlbackups',
    [string] $WorkDir             = "$env:TEMP\pimbacpac",
    [string] $SqlPackagePath      = 'SqlPackage',   # on PATH after dotnet tool install
    [int]    $RetentionDays       = 7
)

$ErrorActionPreference = 'Stop'
Disable-AzContextAutosave -Scope Process | Out-Null

# If ids not supplied, read them from the central vault using the already-present Az login on mgmt1.
if (-not $ApplicationId -or -not $CertificateThumbprint) {
    $ApplicationId        = Get-AzKeyVaultSecret -VaultName kv-automatit-dev -Name management-spn-clientid-myfamilynetwork -AsPlainText
    $CertificateThumbprint = Get-AzKeyVaultSecret -VaultName kv-automatit-dev -Name management-spn-certificatethumbprint-myfamilynetwork -AsPlainText
}

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

# Upload to private blob (mgmt1 reaches the private endpoint over the VNET)
$key   = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName)[0].Value
$stCtx = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $key
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
