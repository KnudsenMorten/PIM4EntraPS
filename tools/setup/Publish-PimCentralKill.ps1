#Requires -Version 5.1
<#
.SYNOPSIS
    SEC-25 -- publish (or withdraw) the MSP master's SIGNED central-kill manifest, which every managed tenant's pull checks
    before it takes anything from the master.

.DESCRIPTION
    The managed-tenant pull already CONSUMES a signed kind='central-kill' manifest at <bundle container>/central-kill.json
    (engine/_shared/PIM-Downlink.ps1: Get-PimCentralKillSource -> Get-PimCentralKillState). A verified manifest with
    entries is ACTIVE: the pull refuses, loudly, naming who is killed, until the manifest is withdrawn or expires. 404 at
    that location = no kill. Nothing on a master published one until this script.

    PUBLISH (-Kill ... -Reason ...):
      1. builds the payload { product, kind='central-kill', version, generatedAtUtc, validToUtc, reason, kills[] }
         (New-PimCentralKillPayload; each kill = upn or userName + status Disabled|Revoked, the only two the consumer takes);
      2. signs it through Key Vault with the master's NON-EXPORTABLE bundle signing key -- the SAME signer and document
         shape as the bundle (Invoke-PimBaselineKeyVaultSign + ConvertTo-PimBaselineDocJson), so the managed tenants
         verify it with the key they already pin (PIM_BaselineTrustedKeys);
      3. SELF-VERIFIES with the managed tenant's own verdict (Get-PimCentralKillState, pinned to that key) = 'active'
         -- nothing is uploaded otherwise;
      4. uploads central-kill-v<version>.json (audit copy) and central-kill.json to the bundle container;
      5. reads central-kill.json back ANONYMOUSLY through Get-PimCentralKillSource, exactly as the pull does, compares it
         with what was uploaded, and asks the verdict again = 'active'.
    WITHDRAW (-Withdraw): deletes central-kill.json (the audit copies stay) and reads the location back through the
    consumer: it must answer 404 = 'none'.
    -WhatIf: builds and prints the payload (or the blob a withdraw would delete). No signing, no upload, no network.

    Exit 0 only when the consumer's own verdict on the published location is the intended one ('active' / 'none').

.NOTES
    WHERE IT RUNS -- the bundle store's firewall denies every network except the ones it names (DESIGN 13.7), for
    authenticated writes as much as for anonymous reads. Run this from a network the store allows (the master's VNet /
    the publish job's subnet). From anywhere else the upload fails with 403 AuthorizationFailure, and the script says so.
    IDENTITY -- a service principal with a CERTIFICATE (-TenantId -ClientId -CertThumbprint; the cert in the local store),
    or the managed identity of the host it runs on (-UseManagedIdentity). Never a client secret. It needs:
      Key Vault Crypto User          on the signing KEY (sign + read the public half)
      Storage Blob Data Contributor  on the bundle CONTAINER (write + delete central-kill*.json)
    The signing key is the VERSIONED key URL the publish job uses (PIM_BaselineSigningKeyId on ca-pim-publish).
    A kill EXPIRES (-ValidHours, default 72): a forgotten one cannot stand for ever; re-publish to extend it.

.EXAMPLE
    .\Publish-PimCentralKill.ps1 -StorageAccount <store> -SigningKeyId https://<vault>.vault.azure.net/keys/pim-baseline-signing/<version> `
        -Kill 'leaver@contoso.example:Revoked' -Reason 'CISO: compromised admin, ticket 123' -TenantId <tid> -ClientId <appid> -CertThumbprint <thumb> -WhatIf
.EXAMPLE
    .\Publish-PimCentralKill.ps1 -StorageAccount <store> -Withdraw -TenantId <tid> -ClientId <appid> -CertThumbprint <thumb>
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Publish')]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9]{3,24}$')][string]$StorageAccount,
    [string]$Container = 'baselines',
    [Parameter(ParameterSetName = 'Publish', Mandatory)][string]$SigningKeyId,
    # 'upn' (Disabled) or 'upn:Disabled' / 'upn:Revoked'; or hashtables { upn|userName; status; statusChangeCode; reason }.
    [Parameter(ParameterSetName = 'Publish', Mandatory)][object[]]$Kill,
    [Parameter(ParameterSetName = 'Publish', Mandatory)][string]$Reason,
    [Parameter(ParameterSetName = 'Publish')][ValidateRange(1, 720)][int]$ValidHours = 72,
    [Parameter(ParameterSetName = 'Withdraw', Mandatory)][switch]$Withdraw,
    # The anonymous URL the managed tenants read. Default: the sibling of the bundle (what the pull derives).
    [string]$KillUrl,
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseManagedIdentity
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$shared  = Join-Path $solRoot 'engine\_shared'
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }

. (Join-Path $shared 'PIM-Rest.ps1')
. (Join-Path $shared 'PIM-AccountRest.ps1')          # Send-PimRestBlob (Put Blob, bearer token)
. (Join-Path $shared 'PIM-BaselinePublish.ps1')      # the producer + the Key Vault signer (loads PIM-Downlink + PIM-Baseline)

$Container = "$Container".Trim()
if ($Container -notmatch '^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$') { Write-Host "REFUSED: '$Container' is not a blob container name" -ForegroundColor Red; exit 2 }
if (-not "$KillUrl".Trim()) { $KillUrl = "https://$StorageAccount.blob.core.windows.net/$Container/central-kill.json" }
if ("$KillUrl" -match '[?#]') { Write-Host 'REFUSED: -KillUrl carries a query string -- the managed tenants read it anonymously; no SAS, no credential in a URL' -ForegroundColor Red; exit 2 }

# ---- -WhatIf: the plan, and nothing live -----------------------------------------------------------------------------
if ($Withdraw) {
    if (-not $PSCmdlet.ShouldProcess($KillUrl, 'DELETE the central-kill manifest (lift the kill)')) {
        Note "WhatIf: would delete $KillUrl (the central-kill-v*.json audit copies stay) and prove it answers 404 = 'none'."
        exit 0
    }
} else {
    $plan = $null
    try { $plan = New-PimCentralKillPayload -Kills @($Kill) -Reason $Reason -ValidHours $ValidHours }
    catch { Write-Host "REFUSED: $($_.Exception.Message)" -ForegroundColor Red; exit 2 }
    $url = "$SigningKeyId".Trim().TrimEnd('/')
    if (-not (Test-PimBaselineSigningKeyUrl -KeyId $url) -or $url -notmatch '/[0-9a-fA-F]{32}$') {
        Write-Host "REFUSED: -SigningKeyId '$SigningKeyId' must be the VERSIONED Key Vault key URL the publish job signs with (https://<vault>.vault.azure.net/keys/<name>/<version>)" -ForegroundColor Red; exit 2
    }
    Step "central kill v$($plan.version): $($plan.count) account(s), valid to $($plan.payload.validToUtc)"
    foreach ($k in @($plan.payload.kills)) { Note ("  {0}{1} -> {2}  ({3})" -f $k['upn'], $(if ($k['userName']) { " [$($k['userName'])]" } else { '' }), $k['status'], $k['reason']) }
    if (-not $PSCmdlet.ShouldProcess($KillUrl, "SIGN (Key Vault) and PUBLISH the central-kill manifest for $($plan.count) account(s)")) {
        Note 'WhatIf: nothing signed, nothing uploaded. The payload that would be signed:'
        Note $plan.payloadJson
        exit 0
    }
}

# ---- the identity: a certificate or a managed identity, never a secret ----------------------------------------------
if ($UseManagedIdentity) {
    if ($ClientId -or $CertThumbprint) { Write-Host 'REFUSED: pass -UseManagedIdentity OR -ClientId/-CertThumbprint, not both' -ForegroundColor Red; exit 2 }
    $global:PIM_UseManagedIdentity = $true
} else {
    if (-not "$TenantId".Trim() -or -not "$ClientId".Trim() -or -not "$CertThumbprint".Trim()) {
        Write-Host 'REFUSED: pass -TenantId, -ClientId and -CertThumbprint (a service principal with a CERTIFICATE), or -UseManagedIdentity. A client secret is never accepted.' -ForegroundColor Red; exit 2
    }
    $global:PIM_TenantId = "$TenantId".Trim(); $global:PIM_ClientId = "$ClientId".Trim(); $global:PIM_CertThumbprint = "$CertThumbprint".Trim()
    $global:PIM_ClientSecret = $null
}
$global:PIM_UseGraphSdk = $false

# The CONSUMER's own read: anonymous (no Authorization header), the same call the pull makes.
$fetcher = { param($u, $h) Invoke-RestMethod -Method GET -Uri $u -Headers $h -ErrorAction Stop }
$blobUrl = { param($name) "https://$StorageAccount.blob.core.windows.net/$Container/$name" }
$explainNetwork = {
    param($err)
    if ("$err" -match '(?i)AuthorizationFailure|403') {
        return " -- 403 from the store: either this identity lacks 'Storage Blob Data Contributor' on the container, or (more often) this host's network is not one the store's firewall allows. Run it from the master's VNet / the publish job's subnet."
    }
    return ''
}

if ($Withdraw) {
    Step "WITHDRAW the central kill at $KillUrl"
    $delete = {
        param($name)
        $tok = Get-PimRestToken -Resource 'https://storage.azure.com'
        $h = @{ Authorization = "Bearer $tok"; 'x-ms-version' = '2021-08-06'; 'x-ms-date' = ([DateTime]::UtcNow.ToString('R')) }
        try { Invoke-RestMethod -Method DELETE -Uri (& $blobUrl $name) -Headers $h -ErrorAction Stop | Out-Null; Note "deleted $name" }
        catch {
            $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { $code = 0 }
            if ($code -eq 404) { Note "$name was not there (no kill was standing)"; return }
            throw "DELETE $name failed$(if ($code) { " (HTTP $code)" }): $($_.Exception.Message)$(& $explainNetwork $_.Exception.Message)"
        }
    }
    try { $res = Invoke-PimCentralKillWithdrawRun -Delete $delete -Fetcher $fetcher -KillUrl $KillUrl }
    catch { Write-Host "WITHDRAW FAILED: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
    if (-not $res.ok) { Write-Host $res.reason -ForegroundColor Red; exit 1 }
    Write-Host "==> $($res.reason)" -ForegroundColor Green
    exit 0
}

Step "SIGN through Key Vault ($SigningKeyId) and PUBLISH to $KillUrl"
$signer   = { param([byte[]]$b) Invoke-PimBaselineKeyVaultSign -KeyId "$SigningKeyId".Trim() -PayloadBytes $b }
$uploader = {
    param($blob, [string]$json)
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("pim-central-kill-" + [guid]::NewGuid().ToString('N') + '.json')
    try {
        [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))   # no BOM
        try { Send-PimRestBlob -StorageAccount $StorageAccount -Container $Container -Blob $blob -FilePath $tmp }
        catch { throw "upload of $blob failed: $($_.Exception.Message)$(& $explainNetwork $_.Exception.Message)" }
        Note "uploaded $blob"
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}
try {
    $res = Invoke-PimCentralKillPublishRun -Kills @($Kill) -Reason $Reason -ValidHours $ValidHours -Signer $signer -Upload $uploader -Fetcher $fetcher -KillUrl $KillUrl
} catch {
    Write-Host "PUBLISH FAILED: $($_.Exception.Message)" -ForegroundColor Red; exit 1
}
if (-not $res.ok) { Write-Host "PUBLISH FAILED: $($res.reason)" -ForegroundColor Red; exit 1 }
Write-Host ("==> {0}; signing key id {1}; sha256 {2}; blobs {3}" -f $res.reason, $res.keyId, $res.sha256, ($res.blobs -join ', ')) -ForegroundColor Green
Write-Host '    Every managed tenant REFUSES its pull while this stands. Lift it with -Withdraw, or let it expire.' -ForegroundColor Yellow
exit 0
