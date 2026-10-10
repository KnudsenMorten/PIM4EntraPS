#Requires -Version 5.1
<#
.SYNOPSIS
    PIM REQUIREMENTS 100.61 -- the in-container entry point of the as-built job (caj-pim-asbuilt): renders the as-built PDF
    of THIS installation and writes it to https://<PIM storage account>.blob.core.windows.net/asbuilt/<executionName>.pdf.

.DESCRIPTION
    Framework DOCS/REQUIREMENTS.md 8.12 (replacement contract, owner 2026-10-10): nothing leaves the customer. Invardia support
    -- with the customer's consent (tools/setup/Grant-PimSupportAccess.ps1) -- starts this job, polls the execution until it
    Succeeded and reads that ONE blob; a lifecycle rule deletes it after 1 day (tools/setup/Deploy-PimAsBuiltJob.ps1).
    The document is the SAME one an admin downloads from the Manager (engine/_shared/PIM-AsBuilt.ps1 is the one generator).

    Runs as the job's SYSTEM-ASSIGNED managed identity, which holds exactly:
      * SELECT on pim.vw_AsBuiltSettings -- the settings the document needs, with people and secrets REDUCED to counts in SQL
        (never pim.Settings itself);
      * Storage Blob Data Contributor on the container 'asbuilt' only.
    Exit 0 only when the PDF was written and read back (its size); anything else exits non-zero, so the execution status IS the
    result Invardia polls.

.NOTES
    Inputs (environment variables written by tools/setup/Deploy-PimAsBuiltJob.ps1): PIM_SqlServer, PIM_SqlDatabase,
    PIM_ASBUILT_STORAGE, PIM_ASBUILT_CONTAINER; CONTAINER_APP_JOB_EXECUTION_NAME (set by Container Apps).
    ASCII only.
#>
[CmdletBinding()]
param(
    [string]$SqlServer      = "$($env:PIM_SqlServer)",
    [string]$SqlDatabase    = $(if ("$($env:PIM_SqlDatabase)".Trim()) { "$($env:PIM_SqlDatabase)".Trim() } else { 'PimPlatform' }),
    [string]$StorageAccount = "$($env:PIM_ASBUILT_STORAGE)",
    [string]$Container      = $(if ("$($env:PIM_ASBUILT_CONTAINER)".Trim()) { "$($env:PIM_ASBUILT_CONTAINER)".Trim() } else { 'asbuilt' }),
    [string]$ExecutionName  = "$($env:CONTAINER_APP_JOB_EXECUTION_NAME)"
)
$ErrorActionPreference = 'Stop'
function JobLog { param([string]$m, [string]$lvl = 'INFO') Write-Host ("[{0}] [asbuilt-job] [{1}] {2}" -f ([datetime]::UtcNow.ToString('o')), $lvl, $m) }

$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
$shared  = Join-Path $solRoot 'engine\_shared'
if (-not (Test-Path -LiteralPath (Join-Path $shared 'PIM-Rest.ps1'))) { JobLog "engine shared folder not found at '$shared'" 'ERROR'; exit 3 }
JobLog '==== PIM Manager as-built job starting ===='

# ---- the identity: the job's MANAGED IDENTITY, and nothing else (the publish job's rule) ----------------------------
$foreign = @(@('AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_CLIENT_CERTIFICATE_PATH', 'PIM_ClientId', 'PIM_CertThumbprint', 'PIM_CERT_THUMBPRINT') |
             Where-Object { "$([Environment]::GetEnvironmentVariable($_))".Trim() })
if ($foreign.Count) { JobLog ("REFUSED: $($foreign -join ', ') is set -- this job runs as its managed identity only") 'ERROR'; exit 2 }
if (-not "$($env:IDENTITY_ENDPOINT)".Trim()) { JobLog 'REFUSED: no managed identity endpoint (IDENTITY_ENDPOINT) -- this entry runs inside a Container Apps job with a system-assigned identity' 'ERROR'; exit 2 }
$missing = @()
foreach ($pair in @(@('PIM_SqlServer', $SqlServer), @('PIM_ASBUILT_STORAGE', $StorageAccount), @('CONTAINER_APP_JOB_EXECUTION_NAME', $ExecutionName))) { if (-not "$($pair[1])".Trim()) { $missing += $pair[0] } }
if ($missing.Count) { JobLog "REFUSED: not configured: $($missing -join ', ')" 'ERROR'; exit 2 }
if ("$StorageAccount" -notmatch '^[a-z0-9]{3,24}$') { JobLog "REFUSED: PIM_ASBUILT_STORAGE '$StorageAccount' is not a storage account name" 'ERROR'; exit 2 }
if ("$ExecutionName" -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,99}$') { JobLog "REFUSED: execution name '$ExecutionName' is not a Container Apps execution name" 'ERROR'; exit 2 }

$global:PIM_UseGraphSdk = $false
$global:PIM_UseManagedIdentity = $true
$global:PIM_SqlServer = "$SqlServer".Trim(); $global:PIM_SqlDatabase = "$SqlDatabase".Trim()

. (Join-Path $shared 'PIM-Rest.ps1')
. (Join-Path $shared 'PIM-SqlStore.ps1')          # Get-PimSqlConnectionString / Invoke-PimSqlScalar (managed identity)
. (Join-Path $shared 'PIM-FeatureCatalog.ps1')    # Resolve-PimFeatureGate / Get-PimFeatureCatalogEntry (pure)
. (Join-Path $shared 'PIM-License.ps1')           # Get-PimLicense -LicenseText / Test-PimLicenseIsProForTenant
. (Join-Path $shared 'PIM-ScenarioProfile.ps1')   # Get-PimScenario (the scenario's role)
. (Join-Path $shared 'PIM-Uplink.ps1')            # New-PimUplinkEndpoints (100.56)
. (Join-Path $shared 'PIM-AccountRest.ps1')       # Send-PimRestBlob (Put Blob, bearer token)
. (Join-Path $shared 'PIM-AsBuilt.ps1')

$cs = Get-PimSqlConnectionString -Server "$SqlServer".Trim() -Database "$SqlDatabase".Trim()
$view = 'pim.vw_AsBuiltSettings'
# Every setting through the job's ONE view (never pim.Settings: it also holds who is SuperAdmin).
$getSetting = { param($n) $j = Invoke-PimSqlScalar -ConnectionString $cs -Sql "SELECT ValueJson FROM $view WHERE Name=@n" -Parameters @{ n = "$n" }; if ($null -eq $j -or $j -is [DBNull]) { $null } else { "$j" } }
try { [void](& $getSetting 'FeatureGates') }
catch { JobLog "the store cannot be read through $view as this identity: $($_.Exception.Message) -- re-run tools/setup/Deploy-PimAsBuiltJob.ps1 (it creates the view and the job's reader user)" 'ERROR'; exit 4 }

# Features: the stored gate map over the catalog defaults. A feature that is switched on by DATA presence alone (no stored
# value) cannot be decided from the view -> $null = left out of the document, never guessed.
$gateState = Resolve-PimFeatureGate -Raw (& $getSetting 'FeatureGates')
$featureOn = {
    param($k)
    $e = Get-PimFeatureCatalogEntry -Key $k
    if (-not $e) { return $null }
    $isExplicit = ($gateState.explicit -is [hashtable]) -and $gateState.explicit.ContainsKey("$($e.key)")
    if (-not $isExplicit -and @($e.autoEnableWhenData).Count -gt 0) { return $null }
    return [bool]$gateState.gates["$($e.key)"]
}

# Licence: the signed document through the view, checked for THIS tenant (the managed identity's home tenant).
$lic = $null; $proHere = $null
try {
    $lt = ConvertFrom-PimLicenseSettingRaw (& $getSetting 'License')
    if ("$lt".Trim()) {
        $lic = Get-PimLicense -LicenseText "$lt"
        $tid = "$($env:PIM_TenantId)".Trim()
        if (-not $tid -and "$($env:IDENTITY_HEADER)".Trim()) { try { $tid = Get-PimTokenTenantId -Token "$((Get-PimManagedIdentityToken -Audience 'https://database.windows.net/').token)" } catch { $tid = '' } }
        $proHere = [bool](Test-PimLicenseIsProForTenant -License $lic -TenantId $tid).pro
    } else { $proHere = $false }
} catch { JobLog "the licence could not be read -- the edition is left out: $($_.Exception.Message)" 'WARN'; $lic = $null; $proHere = $null }

$verFile = Join-Path $solRoot 'VERSION'
$ver = if (Test-Path -LiteralPath $verFile) { "$(Get-Content -Raw -LiteralPath $verFile)".Trim().TrimStart([char]0xFEFF) } else { '' }
$sqlSo = { Invoke-PimSqlScalar -ConnectionString $cs -Sql "SELECT CAST(DATABASEPROPERTYEX(DB_NAME(), 'ServiceObjective') AS nvarchar(64))" }

$facts = Read-PimAsBuiltFacts -GetSetting $getSetting -FeatureOn $featureOn -Version $ver -License $lic -ProHere $proHere -SqlServiceObjective $sqlSo
$model = New-PimAsBuiltModel -Facts $facts -GeneratedBy job
JobLog ("model: {0} facts, {1} endpoints, {2} answered questions, {3} left out" -f @($model.facts).Count, @($model.endpoints).Count, (@($model.sections | ForEach-Object { @($_.rows).Count }) | Measure-Object -Sum).Sum, @($model.omitted).Count)

try { $bytes = ConvertTo-PimAsBuiltPdf -Model $model }
catch { JobLog "the PDF could not be rendered: $($_.Exception.Message)" 'ERROR'; exit 5 }
if (-not $bytes -or $bytes.Length -lt 500) { JobLog 'the PDF came out empty' 'ERROR'; exit 5 }

$blob = "$ExecutionName.pdf"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("asbuilt-" + [guid]::NewGuid().ToString('N') + '.pdf')
try {
    [IO.File]::WriteAllBytes($tmp, $bytes)
    Send-PimRestBlob -StorageAccount "$StorageAccount".Trim() -Container "$Container".Trim() -Blob $blob -FilePath $tmp | Out-Null
} catch { JobLog "the PDF could not be written to https://$StorageAccount.blob.core.windows.net/$Container/$blob : $($_.Exception.Message)" 'ERROR'; exit 6 }
finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }

# Read back: the blob's size (HEAD, same identity, same token layer).
try {
    $tok = Get-PimRestToken -Resource 'https://storage.azure.com'
    $head = Invoke-WebRequest -Method Head -UseBasicParsing -Uri "https://$StorageAccount.blob.core.windows.net/$Container/$blob" -Headers @{ Authorization = "Bearer $tok"; 'x-ms-version' = '2021-08-06' }
    $len = 0; [void][int64]::TryParse("$(@($head.Headers['Content-Length'])[0])", [ref]$len)
    if ($len -ne $bytes.Length) { JobLog "read-back: the blob holds $len bytes, $($bytes.Length) were written" 'ERROR'; exit 6 }
} catch { JobLog "read-back of the blob failed: $($_.Exception.Message)" 'ERROR'; exit 6 }

JobLog ("==== as-built PDF written: https://{0}.blob.core.windows.net/{1}/{2} ({3} bytes; deleted automatically after 1 day) ====" -f $StorageAccount, $Container, $blob, $bytes.Length)
exit 0
