#Requires -Version 5.1
<#
.SYNOPSIS
    71.35 -- the in-container entry point of the MSP master's signed-baseline PUBLISH job (ca-pim-publish).

.DESCRIPTION
    Operator decision 2026-09-17: "go with cloud job publish". The bundle used to be produced on the MSP management host,
    signed with a machine certificate and scheduled as a SYSTEM task. That tied every master to one host and one
    certificate, and it could not exist for a customer that deploys as a signed-in administrator with no automation VM.

    This job runs on the master's own Container Apps environment, on a cron and on demand, as its
    SYSTEM-ASSIGNED MANAGED IDENTITY. It holds no certificate, no secret, no SAS and no account key:
      0. decides whether a publish is DUE (operator 2026-09-18: the cadence is set in the Manager's Job schedule). The cron
         fires every 5 minutes; the gate reads the master's own PublishSchedule / PublishRunNow / PublishLastRun through
         two narrow views (engine/_shared/PIM-JobCadence.ps1). Not due = one "[cadence] SKIPPED:" line and exit 0.
         Nothing stored = daily, as before.
     0b. REQ-Y: refuses (exit 2, nothing published) unless the master holds a Pro licence that covers MSP for its tenant
         (Invoke-PimMspLicenseGate, engine/_shared/PIM-License.ps1); a licence in its grace window publishes with a WARN.
      1. reads the master store (Azure SQL, as the identity -- its own reader database user (SELECT on the 4 registry tables))
      2. builds the payload with the producer (engine/_shared/PIM-BaselinePublish.ps1; the pre-71.35 host publisher
         setup/New-PimBaselineBundle.ps1 is retired, SEC-27). An optional table/column that cannot be READ (anything
         but a genuinely missing object) refuses the publish -- it is never read as "absent", which would widen reach
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
. (Join-Path $shared 'PIM-SqlStore.ps1')             # Get-PimSqlConnectionString / Invoke-PimSqlQuery (managed identity)
. (Join-Path $shared 'PIM-JobCadence.ps1')           # the cadence gate (the Manager's Job schedule)

$cs = Get-PimSqlConnectionString -Server "$SqlServer".Trim() -Database "$SqlDatabase".Trim()

# ---- 0. THE CADENCE GATE (operator 2026-09-18: the publish cadence is set in the Manager's Job schedule) -------------
# The cron fires every 5 minutes; whether THIS execution publishes is decided from the master's OWN store: PublishSchedule
# / PublishRunNow / PublishLastRun, read through pim.vw_PublishJobControl and recorded through pim.vw_PublishJobLastRun --
# this identity's reader user (SEC-39) holds no right on pim.Settings itself, which also holds who is SuperAdmin.
# Nothing stored = the daily cadence this job always had. A store that cannot be read = PUBLISH ANYWAY, loudly (a publish
# is verified end to end before and after upload). The producer and the signer are loaded only when a publish is due.
$cadenceLog = { param($m, $l) JobLog $m $l }
$cadenceGate = Invoke-PimJobCadenceGate -Job 'publish' -Log $cadenceLog `
    -ExecutionName "$env:CONTAINER_APP_JOB_EXECUTION_NAME" -DeployedUtc "$env:PIM_CadenceDeployedUtc" `
    -ReadValues { param($names) Read-PimJobCadenceValues -ConnectionString $cs -Object 'pim.vw_PublishJobControl' -Names $names } `
    -CompareAndSet { param($n, $v, $e) Set-PimJobCadenceValueIfUnchanged -ConnectionString $cs -Object 'pim.vw_PublishJobLastRun' -Name $n -NewJson $v -ExpectedJson $e }
if (-not $cadenceGate.run) { JobLog '==== nothing to publish on this trigger (see the cadence line above) ===='; exit 0 }
function Stop-PublishJob {
    param([int]$Code, [ValidateSet('succeeded', 'failed')][string]$State, [string]$Detail, [string]$Version = '')
    [void](Complete-PimJobCadenceRun -Gate $cadenceGate -State $State -Detail $Detail -Version $Version -Log $cadenceLog `
        -Write { param($n, $j) Write-PimJobCadenceValue -ConnectionString $cs -Object 'pim.vw_PublishJobLastRun' -Name $n -Json $j })
    exit $Code
}

# ---- 0b. REQ-Y: AN MSP MASTER NEEDS A PRO LICENCE (operator 2026-09-19: "msp master slave require license pro") --------
# After the store is reachable and the cadence says a publish is due; BEFORE anything is built, signed or uploaded. The
# licence is pim.Settings['License'], read through the same least-privilege view as the cadence (it carries that row).
# The tenant is PIM_TenantId when the job has one, else the tenant of this job's own managed identity (the token's tid).
# Not ok = one ERROR line naming the contact and the register command, recorded as the job's result, exit 2 (a refusal).
# Grace = a WARN line, then publish. Independent of the global Pro switch, which stays off.
. (Join-Path $shared 'PIM-License.ps1')
$licText = ''; $licErr = ''
try { $licText = ConvertFrom-PimLicenseSettingRaw ((Read-PimJobCadenceValues -ConnectionString $cs -Object 'pim.vw_PublishJobControl' -Names @('License'))['License']) }
catch { $licErr = "$($_.Exception.Message)" }
$licTenant = "$($env:PIM_TenantId)".Trim()
# The Container Apps identity endpoint only (IDENTITY_ENDPOINT + IDENTITY_HEADER): never the az / IMDS fallbacks, which
# would answer for some other identity. No tenant = a tenant-bound licence cannot be matched, which the check says.
if (-not $licTenant -and "$($env:IDENTITY_HEADER)".Trim()) {
    try { $licTenant = Get-PimTokenTenantId -Token "$((Get-PimManagedIdentityToken -Audience 'https://database.windows.net/').token)" } catch { $licTenant = '' }
}
$mspLic = Invoke-PimMspLicenseGate -Role Master -TenantId $licTenant -LicenseText $licText -StoreError $licErr -SqlServer "$SqlServer".Trim() -Log $cadenceLog
if (-not $mspLic.ok) { Stop-PublishJob -Code 2 -State failed -Detail "$($mspLic.message)" }

. (Join-Path $shared 'PIM-AccountRest.ps1')          # Send-PimRestBlob (Put Blob, bearer token)
. (Join-Path $shared 'PIM-ChangeQueue.ps1')
. (Join-Path $shared 'PIM-Baseline.ps1')             # the verifier the managed tenants run
. (Join-Path $shared 'PIM-BaselinePublish.ps1')      # the shared producer + the Key Vault signer
# REQ-REV-DOWN-1 / REQ-REN-1: the authorised withdrawals + renames this bundle carries (pure).
$__dlIntents = Join-Path $shared 'PIM-DownlinkIntents.ps1'
if (Test-Path -LiteralPath $__dlIntents) { . $__dlIntents }

JobLog ("store {0}/{1} -> https://{2}.blob.core.windows.net/{3}/ ; signing key {4} ; valid {5} days ; scope {6}" -f $SqlServer, $SqlDatabase, $StorageAccount, $Container, $SigningKeyId, $vd, $Scope)
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

# REQ-REV-DOWN-1 / REQ-REN-1 -- the withdrawals and renames the operator authorised centrally, read
# from the master's own store (pim.Settings 'DownlinkIntents') and carried in the SIGNED bundle.
# 🔒 Failing to read them must NOT fail the publish and must NOT invent any: a bundle with no
# intents is the old behaviour, which withdraws nothing. Silence here can only ever under-act.
$intents = @()
try {
    # 🔴 §79.6 live E2E (2026-09-25): this read Get-PimSqlSetting -ConnectionString $global:PIM_SqlConnectionString --
    # a variable nothing in this job sets, and a table (pim.Settings) its identity has no right on. Every publish since
    # 2.4.406 logged "could not be read (... ConnectionString ... empty string)" and shipped NO intents: no central
    # withdrawal, rename or session revoke ever reached a managed tenant. It reads what every other setting here reads:
    # the job's own connection ($cs), through pim.vw_PublishJobControl, which carries the 'DownlinkIntents' row.
    if (Get-Command Read-PimJobCadenceValues -ErrorAction SilentlyContinue) {
        $rawIntents = (Read-PimJobCadenceValues -ConnectionString $cs -Object 'pim.vw_PublishJobControl' -Names @('DownlinkIntents'))['DownlinkIntents']
        if ("$rawIntents".Trim()) {
            $parsed = if ($rawIntents -is [string]) { $rawIntents | ConvertFrom-Json } else { $rawIntents }
            $sel = if (Get-Command Select-PimDownlinkIntents -ErrorAction SilentlyContinue) { Select-PimDownlinkIntents -Intents @($parsed) } else { @{ intents = @($parsed); dropped = @() } }
            $intents = @($sel.intents)
            if (@($sel.dropped).Count) { JobLog ("dropped {0} stale intent(s) older than the intent lifetime" -f @($sel.dropped).Count) 'WARN' }
            if ($intents.Count) { JobLog ("carrying {0} authorised withdrawal/rename intent(s) in this bundle" -f $intents.Count) }
        }
    }
} catch {
    JobLog ("the authorised-withdrawal list could not be read ({0}) -- publishing WITHOUT it, so nothing is withdrawn downstream" -f $_.Exception.Message) 'WARN'
    $intents = @()
}
try {
    $res = Invoke-PimBaselinePublishRun -RunQuery $runQuery -Signer $signer -Upload $uploader -Fetch $fetcher -Scope $Scope -ValidDays $vd -Intents $intents
} catch {
    JobLog ("PUBLISH FAILED: " + $_.Exception.Message) 'ERROR'
    Stop-PublishJob -Code 1 -State failed -Detail ("PUBLISH FAILED: " + $_.Exception.Message)
}
if (-not $res.ok) { JobLog ("PUBLISH FAILED: " + $res.reason) 'ERROR'; Stop-PublishJob -Code 1 -State failed -Detail ("PUBLISH FAILED: " + $res.reason) -Version "$($res.version)" }
JobLog ("BASELINE PUBLISHED: {0}; signing key id {1}; sha256 {2}; blobs {3}; read-back: {4}" -f $res.reason, $res.keyId, $res.sha256, ($res.blobs -join ', '), $res.readBack)
JobLog '==== done ===='
Stop-PublishJob -Code 0 -State succeeded -Detail "$($res.reason)" -Version "$($res.version)"
