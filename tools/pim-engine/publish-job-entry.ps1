#Requires -Version 5.1
<#
.SYNOPSIS
    71.35 -- the in-container entry point of the MSP master's signed-baseline PUBLISH job (ca-pim-publish).

.DESCRIPTION
    Operator decision 2026-09-17: "go with cloud job publish". The bundle used to be produced on the MSP management host,
    signed with a machine certificate and scheduled as a SYSTEM task. That tied every master to one host and one
    certificate, and it could not exist for a customer that deploys as a signed-in administrator with no automation VM.

    This job runs on the master's own Container Apps environment, on a cron (daily) and on demand, as its
    SYSTEM-ASSIGNED MANAGED IDENTITY. It holds no certificate, no secret, no SAS and no account key:
      1. reads the master store (Azure SQL, as the identity -- a member of grp-pim-sql-admins)
      2. builds the payload with the SHARED producer (engine/_shared/PIM-BaselinePublish.ps1, the same function
         setup/New-PimBaselineBundle.ps1 uses)
      3. signs it through Key Vault: RS256 over the SHA-256 digest with a NON-EXPORTABLE key
         (Key Vault Crypto User on that key only)
      4. verifies the signature with the managed tenant's own verifier, pinned to exactly that key, BEFORE uploading
      5. writes baseline-v<version>.json and baseline-latest.json (Storage Blob Data Contributor on that container only)
      6. reads baseline-latest.json back ANONYMOUSLY -- from this subnet, which the store's firewall allows, exactly as a
         managed tenant reads it -- and verifies it again
    Exit 0 only when all six happened. Anything else exits non-zero, so the execution status IS the verification.

.NOTES
    Every input is an environment variable written by tools/setup/Deploy-PimBaselinePublishJob.ps1:
      PIM_SqlServer, PIM_SqlDatabase, PIM_BaselineStorageAccount, PIM_BaselineContainer,
      PIM_BaselineSigningKeyId (a VERSIONED Key Vault key URL), PIM_BaselineValidDays, PIM_BaselineScope
    ASCII only.
#>
[CmdletBinding()]
param(
    [string]$SqlServer      = "$($env:PIM_SqlServer)",
    [string]$SqlDatabase    = $(if ("$($env:PIM_SqlDatabase)".Trim()) { "$($env:PIM_SqlDatabase)".Trim() } else { 'PimPlatform' }),
    [string]$StorageAccount = "$($env:PIM_BaselineStorageAccount)",
    [string]$Container      = $(if ("$($env:PIM_BaselineContainer)".Trim()) { "$($env:PIM_BaselineContainer)".Trim() } else { 'baselines' }),
    [string]$SigningKeyId   = "$($env:PIM_BaselineSigningKeyId)",
    [string]$ValidDays      = $(if ("$($env:PIM_BaselineValidDays)".Trim()) { "$($env:PIM_BaselineValidDays)".Trim() } else { '30' }),
    [string]$Scope          = $(if ("$($env:PIM_BaselineScope)".Trim()) { "$($env:PIM_BaselineScope)".Trim() } else { 'fleet' })
)
$ErrorActionPreference = 'Stop'
function JobLog { param([string]$m, [string]$lvl = 'INFO') Write-Host ("[{0}] [publish-job] [{1}] {2}" -f ([datetime]::UtcNow.ToString('o')), $lvl, $m) }

# Two levels up: <solution>\tools\pim-engine -> <solution> (the update job's measured lesson).
$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
$shared  = Join-Path $solRoot 'engine\_shared'
if (-not (Test-Path -LiteralPath (Join-Path $shared 'PIM-Rest.ps1'))) { JobLog "engine shared folder not found at '$shared'" 'ERROR'; exit 3 }

JobLog '==== PIM4EntraPS signed-baseline PUBLISH job starting ===='

# ---- the identity: the job's MANAGED IDENTITY, and nothing else ----------------------------------------------------
# A client id, a secret or a certificate thumbprint in this process would make the token layer authenticate as
# somebody else (Get-PimRestToken takes the managed identity only when no client id is set). Refuse, loudly.
$foreign = @(@('AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_CLIENT_CERTIFICATE_PATH', 'PIM_ClientId', 'PIM_CertThumbprint', 'PIM_CERT_THUMBPRINT') |
             Where-Object { "$([Environment]::GetEnvironmentVariable($_))".Trim() })
if ($foreign.Count) { JobLog ("REFUSED: $($foreign -join ', ') is set -- this job runs as its managed identity only") 'ERROR'; exit 2 }
if (-not "$($env:IDENTITY_ENDPOINT)".Trim()) { JobLog 'REFUSED: no managed identity endpoint (IDENTITY_ENDPOINT) -- this entry runs inside a Container Apps job with a system-assigned identity' 'ERROR'; exit 2 }

$missing = @()
foreach ($pair in @(@('PIM_SqlServer', $SqlServer), @('PIM_BaselineStorageAccount', $StorageAccount), @('PIM_BaselineSigningKeyId', $SigningKeyId))) { if (-not "$($pair[1])".Trim()) { $missing += $pair[0] } }
if ($missing.Count) { JobLog "REFUSED: not configured: $($missing -join ', ')" 'ERROR'; exit 2 }
$vd = 0; if (-not [int]::TryParse("$ValidDays", [ref]$vd) -or $vd -lt 2) { JobLog "REFUSED: PIM_BaselineValidDays '$ValidDays' (2 or more)" 'ERROR'; exit 2 }

$global:PIM_UseGraphSdk = $false
$global:PIM_UseManagedIdentity = $true
$global:PIM_SqlServer = "$SqlServer".Trim(); $global:PIM_SqlDatabase = "$SqlDatabase".Trim()

. (Join-Path $shared 'PIM-Rest.ps1')
. (Join-Path $shared 'PIM-AccountRest.ps1')          # Send-PimRestBlob (Put Blob, bearer token)
. (Join-Path $shared 'PIM-ChangeQueue.ps1')
. (Join-Path $shared 'PIM-SqlStore.ps1')             # Get-PimSqlConnectionString / Invoke-PimSqlQuery (managed identity)
. (Join-Path $shared 'PIM-Baseline.ps1')             # the verifier the managed tenants run
. (Join-Path $shared 'PIM-BaselinePublish.ps1')      # the shared producer + the Key Vault signer

JobLog ("store {0}/{1} -> https://{2}.blob.core.windows.net/{3}/ ; signing key {4} ; valid {5} days ; scope {6}" -f $SqlServer, $SqlDatabase, $StorageAccount, $Container, $SigningKeyId, $vd, $Scope)

$cs = Get-PimSqlConnectionString -Server "$SqlServer".Trim() -Database "$SqlDatabase".Trim()
# A PLAIN scriptblock (no GetNewClosure): it resolves $cs and Invoke-PimSqlQuery through this script's scope.
$runQuery = { param($q) @(Invoke-PimSqlQuery -ConnectionString $cs -Sql $q) }
$signer   = { param([byte[]]$b) Invoke-PimBaselineKeyVaultSign -KeyId "$SigningKeyId".Trim() -PayloadBytes $b }
$uploader = {
    param($blob, [string]$json)
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("pim-baseline-" + [guid]::NewGuid().ToString('N') + '.json')
    try {
        [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))   # no BOM
        Send-PimRestBlob -StorageAccount "$StorageAccount".Trim() -Container "$Container".Trim() -Blob $blob -FilePath $tmp
        JobLog "uploaded $blob"
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}
# ANONYMOUS: no Authorization header. This is the managed tenant's read path, taken from an allowed network.
$fetcher  = {
    param($blob)
    $u = "https://$("$StorageAccount".Trim()).blob.core.windows.net/$("$Container".Trim())/$blob"
    $r = Invoke-WebRequest -Method GET -Uri $u -Headers @{ 'x-ms-version' = '2021-08-06' } -UseBasicParsing -ErrorAction Stop
    if ($r.Content -is [byte[]]) { return [System.Text.Encoding]::UTF8.GetString($r.Content) }
    return "$($r.Content)"
}

try {
    $res = Invoke-PimBaselinePublishRun -RunQuery $runQuery -Signer $signer -Upload $uploader -Fetch $fetcher -Scope $Scope -ValidDays $vd
} catch {
    JobLog ("PUBLISH FAILED: " + $_.Exception.Message) 'ERROR'
    exit 1
}
if (-not $res.ok) { JobLog ("PUBLISH FAILED: " + $res.reason) 'ERROR'; exit 1 }
JobLog ("BASELINE PUBLISHED: {0}; signing key id {1}; sha256 {2}; blobs {3}; read-back: {4}" -f $res.reason, $res.keyId, $res.sha256, ($res.blobs -join ', '), $res.readBack)
JobLog '==== done ===='
exit 0
