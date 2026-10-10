<#
.SYNOPSIS
    6-hourly portable BACPAC export of the PimPlatform Azure SQL database, run from INSIDE the
    PIM VNET (a management host or a VNET-injected runner), with retention pruning. Cert-only auth.

.DESCRIPTION
    PimPlatform's logical server and its backup storage account both have
    PublicNetworkAccess = Disabled (private endpoint only).
    The serverless Azure SQL export service ('az sql db export' and friends)
    runs OUTSIDE the VNET and therefore CANNOT reach these private endpoints, so the native
    export path does not work for PIM without opening public access (a security regression we
    will NOT make).

    This script instead exports with SqlPackage.exe from a host that IS on the allowed VNET
    (the management host, or a VNET-injected runner). It:
      1. Mints tokens as the caller-supplied SPN via CERTIFICATE -- PIM-Rest's one token client
         (Get-PimRestToken: a signed JWT client assertion, no PowerShell modules, framework 12.17).
      2. Acquires an Entra access token for SQL (https://database.windows.net/) - no SQL password.
      3. SqlPackage /a:Export writes a local .bacpac, authenticating with /AccessToken.
      4. Uploads the .bacpac to the private 'sqlbackups' container on the backup storage
         account over the Blob REST API WITH ENTRA AUTH (a bearer token for https://storage.azure.com/)
         -- never an account key -- then prunes anything older than RetentionDays.

    Rights the SPN needs: a database user in the PIM database (read), and 'Storage Blob Data
    Contributor' on the backup storage account (or its container). SqlPackage must be installed:
        dotnet tool install --global microsoft.sqlpackage
    or downloaded from https://aka.ms/sqlpackage-windows .

.NOTES
    IMP-49 j: SPN + certificate only, and BOTH values are passed in (-ApplicationId,
    -CertificateThumbprint) -- the script no longer names any Key Vault or secret of the
    environment it happens to be developed in, and it no longer reads a storage ACCOUNT KEY
    (a key is full control of every container in the account, and it is not audited per caller).
    No secrets, no device-code, no PowerShell modules. AccessToken is passed to SqlPackage in-process and not logged.
#>
[CmdletBinding()]
param(
    # SEC-02: real ids are environment values, not defaults baked into a script under the
    # published tree. Pass them, or set PIM_TenantId / PIM_SqlSubscriptionId.
    # Real values: internal/REAL-IDENTIFIERS.md (never published).
    [string] $TenantId            = "$($env:PIM_TenantId)",
    # REQ 100.42: no longer read (it only scoped the Az PowerShell context); accepted so existing callers still bind.
    # audit:unused-ok SubscriptionId
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
$missingIn = @(foreach ($p in @(@('TenantId', $TenantId), @('ApplicationId', $ApplicationId),
                              @('CertificateThumbprint', $CertificateThumbprint), @('ServerFqdn', $ServerFqdn), @('StorageAccountName', $StorageAccountName))) {
    if (-not "$($p[1])".Trim()) { "-$($p[0])" } })
if ($missingIn.Count) { throw "Export-PimPlatformBacpac: $($missingIn -join ', ') required (SPN + certificate; no value is read from any vault by this script)." }
if ($StorageAccountName -notmatch '^[a-z0-9]{3,24}$') { throw "Export-PimPlatformBacpac: '$StorageAccountName' is not a storage account name." }
if ($ContainerName -notmatch '^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$') { throw "Export-PimPlatformBacpac: '$ContainerName' is not a blob container name." }

# The ONE connect path (owner 2026-10-09: "modern single connect only"): PIM-Rest's token client, certificate JWT.
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
$idArgs = @{ TenantId = $TenantId; ClientId = $ApplicationId; CertThumbprint = $CertificateThumbprint }

# AAD token for SQL data plane
$accessToken = Get-PimRestToken -Resource 'https://database.windows.net' @idArgs

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
$accessToken = $null
if ($LASTEXITCODE -ne 0) { throw "SqlPackage export failed with exit code $LASTEXITCODE" }

# ---- Blob REST (this host reaches the private endpoint over the VNET) -------------------------------------------------
# IMP-49 j: ENTRA auth as the SPN (Storage Blob Data Contributor), never the account key.
$blobBase = "https://$StorageAccountName.blob.core.windows.net/$ContainerName"
function Get-PimBlobHeaders {
    param([hashtable]$Extra = @{})
    $t = Get-PimRestToken -Resource 'https://storage.azure.com' @idArgs
    return (@{ Authorization = "Bearer $t"; 'x-ms-version' = '2023-11-03'; 'x-ms-date' = [datetime]::UtcNow.ToString('R') } + $Extra)
}
function Invoke-PimBlob {
    # One Blob REST call; returns the response (Invoke-WebRequest), or $null on 404 when -AllowNotFound.
    param([string]$Method, [string]$Url, [object]$Body, [hashtable]$Headers = @{}, [switch]$AllowNotFound)
    $a = @{ Method = $Method; Uri = $Url; Headers = (Get-PimBlobHeaders -Extra $Headers); UseBasicParsing = $true; TimeoutSec = 600 }
    if ($null -ne $Body) { $a.Body = $Body; $a.ContentType = 'application/octet-stream' }
    try { return (Invoke-WebRequest @a) }
    catch {
        $code = $null; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
        if ($AllowNotFound -and $code -eq 404) { return $null }
        throw "$Method $Url -> HTTP $code : $($_.Exception.Message)"
    }
}

if (-not (Invoke-PimBlob -Method GET -Url "$blobBase`?restype=container" -AllowNotFound)) {
    # no x-ms-blob-public-access header = PRIVATE container
    [void](Invoke-PimBlob -Method PUT -Url "$blobBase`?restype=container" -Body ([byte[]]@()))
}
$blobName = Split-Path $bacpac -Leaf
$blobUrl = "$blobBase/$([uri]::EscapeDataString($blobName))"
# Put Block + Put Block List in 8 MiB blocks: a BACPAC can exceed the single-PUT limit, and a block upload never holds
# the whole file in memory.
$blockSize = 8MB
$ids = New-Object System.Collections.Generic.List[string]
$fs = [IO.File]::OpenRead($bacpac)
try {
    $buf = New-Object byte[] $blockSize
    $n = 0
    while (($read = $fs.Read($buf, 0, $blockSize)) -gt 0) {
        $id = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(('block-{0:D6}' -f $n)))
        $chunk = if ($read -eq $blockSize) { $buf } else { $c = New-Object byte[] $read; [Array]::Copy($buf, $c, $read); $c }
        [void](Invoke-PimBlob -Method PUT -Url "$blobUrl`?comp=block&blockid=$([uri]::EscapeDataString($id))" -Body $chunk)
        $ids.Add($id); $n++
    }
} finally { $fs.Dispose() }
$list = '<?xml version="1.0" encoding="utf-8"?><BlockList>' + (($ids | ForEach-Object { "<Latest>$_</Latest>" }) -join '') + '</BlockList>'
[void](Invoke-PimBlob -Method PUT -Url "$blobUrl`?comp=blocklist" -Body ([Text.Encoding]::UTF8.GetBytes($list)) -Headers @{ 'x-ms-blob-content-type' = 'application/octet-stream' })
Write-Output "[$(Get-Date -Format o)] Uploaded $blobName ($($ids.Count) block(s))"
Remove-Item $bacpac -Force

# Retention prune (List Blobs, paged by NextMarker)
$cutoff = (Get-Date).ToUniversalTime().AddDays(-$RetentionDays)
$marker = ''
do {
    $u = "$blobBase`?restype=container&comp=list&prefix=$([uri]::EscapeDataString("$DatabaseName-"))"
    if ($marker) { $u += "&marker=$([uri]::EscapeDataString($marker))" }
    $r = Invoke-PimBlob -Method GET -Url $u
    $txt = "$($r.Content)"; if ($txt.Length -and [int][char]$txt[0] -eq 0xFEFF) { $txt = $txt.Substring(1) }
    $xml = [xml]$txt
    foreach ($b in @($xml.EnumerationResults.Blobs.Blob)) {
        if ($null -eq $b) { continue }
        $name = "$($b.Name)"
        $lm = [datetime]::Parse("$($b.Properties.'Last-Modified')", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal)
        if ($name -like "$DatabaseName-*.bacpac" -and $lm -lt $cutoff) {
            Write-Output "[$(Get-Date -Format o)] Pruning $name"
            [void](Invoke-PimBlob -Method DELETE -Url "$blobBase/$([uri]::EscapeDataString($name))")
        }
    }
    $marker = "$($xml.EnumerationResults.NextMarker)".Trim()
} while ($marker)
Write-Output "[$(Get-Date -Format o)] Done."
