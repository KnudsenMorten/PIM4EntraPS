#Requires -Version 5.1
<#
.SYNOPSIS
    71.35 -- the MSP master's baseline SIGNING KEY: a non-exportable RSA key in the master's Key Vault, created once, and
    its KEY ID (RFC 7638 thumbprint) printed for every managed tenant to pin.

.DESCRIPTION
    Replaces the CN=PIM4EntraPS-Baseline machine certificate for a master that publishes from its cloud job
    (ca-pim-publish). Idempotent, and never re-versions a key:
      1. the vault: must exist (the build's keyvault step, or an existing tenant vault); with -CreateVaultIfMissing it is
         created RBAC-mode with purge protection. Its SKU decides the key type: premium -> RSA-HSM, standard -> RSA.
      2. the key, over the ARM CONTROL PLANE (Microsoft.KeyVault/vaults/keys PUT): created only when absent, with
         key_ops sign + verify and NO release policy (non-exportable). ARM never creates a new version of an existing
         key, and this script does not even send the PUT for one. An existing key that is not RSA, can do more than
         sign/verify, is under 2048 bits or is exportable is REFUSED.
      3. the PUBLIC half: read from the data plane as the identity running the build, which is given
         'Key Vault Reader' scoped to THIS KEY ONLY (read the public key; it cannot sign, decrypt or read secrets).
      4. the key id: printed, and written to the pipeline. It is NOT a secret -- it is the value each managed tenant puts
         in master.signingKeyIds. Several ids may be pinned at once, so a key roll never breaks a managed tenant.

    Works in certificate mode and in signed-in mode (71.33): it uses the az context the build established.

.OUTPUTS
    The key id (43-character base64url string).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$KeyVaultName,
    [string]$KeyVaultResourceGroup,
    [string]$Location = 'swedencentral',
    [string]$KeyName = 'pim-baseline-signing',
    [ValidateSet(2048, 3072, 4096)][int]$KeySize = 3072,
    [switch]$CreateVaultIfMissing,
    [ValidateRange(1, 30)][int]$PropagationTimeoutMinutes = 10,
    # §71.40 (2026-09-18) -- the MASTER's own Manager verifies its published bundle only against a pinned key id, and that
    # id first exists HERE (hosting runs earlier). Name the Manager app and the id is MERGED into its
    # PIM_BaselineTrustedKeys (existing pins kept -- a key roll pins the new id beside the old) and read back.
    [string]$PinOnManagerApp
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $solRoot 'engine\_shared\PIM-Baseline.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-BaselinePublish.ps1')
. (Join-Path $here '_PimAz.ps1')                 # the guarded az shadow (an az WARNING on stderr must not abort)
. (Join-Path $here '_PimUpdateRing.ps1')          # New-PimSubscriptionArmInvoker (tenant-checked ARM caller)
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }

if ("$KeyName" -notmatch '^[A-Za-z0-9-]{1,127}$') { throw "key name '$KeyName' is invalid (letters, digits, '-')" }
if (-not "$KeyVaultResourceGroup".Trim()) { $KeyVaultResourceGroup = $ResourceGroup }
$arm = New-PimSubscriptionArmInvoker -SubscriptionId $SubscriptionId
$kvApi = '2023-07-01'
$vaultPath = "/subscriptions/$SubscriptionId/resourceGroups/$KeyVaultResourceGroup/providers/Microsoft.KeyVault/vaults/$KeyVaultName"

# ---- 1. the vault ------------------------------------------------------------------------------------------------
Step "signing key vault $KeyVaultName ($KeyVaultResourceGroup)"
$vault = $null
try { $vault = & $arm -Method GET -Path $vaultPath -ApiVersion $kvApi } catch { if ("$($_.Exception.Message)" -notmatch 'HTTP 404') { throw } }
if (-not $vault) {
    if (-not $CreateVaultIfMissing) { throw "Key Vault '$KeyVaultName' does not exist in $KeyVaultResourceGroup. Run the build's keyvault step, name an existing vault (baseline.signingKeyVaultName), or pass -CreateVaultIfMissing." }
    if ($PSCmdlet.ShouldProcess($KeyVaultName, 'create Key Vault (RBAC, purge protection)')) {
        $tid = "$(((az account show --subscription $SubscriptionId -o json 2>$null) | Out-String | ConvertFrom-Json).tenantId)".Trim()
        $vault = & $arm -Method PUT -Path $vaultPath -ApiVersion $kvApi -Body @{ location = $Location; properties = @{ tenantId = $tid; sku = @{ family = 'A'; name = 'standard' }; enableRbacAuthorization = $true; enablePurgeProtection = $true; enableSoftDelete = $true; softDeleteRetentionInDays = 90 } }
        for ($i = 0; $i -lt 30 -and "$($vault.properties.provisioningState)" -ne 'Succeeded'; $i++) { Start-Sleep -Seconds 5; $vault = & $arm -Method GET -Path $vaultPath -ApiVersion $kvApi }
        Note 'created (standard, RBAC, purge protection)'
    }
}
if (-not [bool]$vault.properties.enableRbacAuthorization) { throw "Key Vault '$KeyVaultName' uses ACCESS POLICIES, not Azure RBAC -- the publish job's key-scoped grant needs RBAC mode. Use an RBAC vault (baseline.signingKeyVaultName)." }
$sku = "$($vault.properties.sku.name)".ToLowerInvariant()
$vaultUri = "$($vault.properties.vaultUri)".TrimEnd('/')
Note "sku $sku, RBAC, $vaultUri"

# ---- 2. the key (control plane; never re-versioned) --------------------------------------------------------------
$keyPath = "$vaultPath/keys/$KeyName"
$existing = $null
try { $existing = & $arm -Method GET -Path $keyPath -ApiVersion $kvApi } catch { if ("$($_.Exception.Message)" -notmatch 'HTTP 404') { throw } }
$plan = Get-PimBaselineSigningKeyPlan -Existing $existing -VaultSku $sku -KeySize $KeySize
Step "signing key $KeyName -- $($plan.reason)"
if ($plan.action -eq 'refuse') { throw "REFUSED: $($plan.reason)" }
if ($plan.action -eq 'create' -and $PSCmdlet.ShouldProcess($KeyName, "create $($plan.kty) $KeySize")) {
    $existing = & $arm -Method PUT -Path $keyPath -ApiVersion $kvApi -Body $plan.body
}
if ($WhatIfPreference) { Note 'WhatIf: stopping before the read-back'; return }
$back = & $arm -Method GET -Path $keyPath -ApiVersion $kvApi
$check = Get-PimBaselineSigningKeyPlan -Existing $back -VaultSku $sku -KeySize $KeySize
if ($check.action -ne 'none') { throw "read-back FAILED: the key as stored does not meet the signing-key rules ($($check.reason))" }
$keyUriWithVersion = "$($back.properties.keyUriWithVersion)".Trim()
Note "read back: $($back.properties.kty) $($back.properties.keySize) ops=$(@($back.properties.keyOps) -join '+') $keyUriWithVersion"

# ---- 3. the public half, read as the identity running the build (Key Vault Reader on THIS KEY only) ----------------
$tokRaw = (az account get-access-token --subscription $SubscriptionId --resource https://management.azure.com/ -o json 2>$null) | Out-String | ConvertFrom-Json
$pl = "$($tokRaw.accessToken)".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($pl.Length % 4) { $pl += '=' }
$claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($pl)) | ConvertFrom-Json
$callerOid = "$($claims.oid)".Trim()
$callerType = if ("$($claims.idtyp)" -eq 'app' -or -not "$($claims.upn)$($claims.unique_name)".Trim()) { 'ServicePrincipal' } else { 'User' }
if (-not $callerOid) { throw 'could not read the object id of the identity running the build from its ARM token.' }
$keyScope = "$vaultPath/keys/$KeyName"
Step "Key Vault Reader on the key for the build identity ($callerType $callerOid) -- read the public half only"
# (single-line --query with no '|' -- az is az.cmd on Windows; the filter is applied here, not in JMESPath)
$has = @(az role assignment list --subscription $SubscriptionId --assignee $callerOid --scope $keyScope --query "[].roleDefinitionName" -o tsv 2>$null |
         ForEach-Object { "$_".Trim() } | Where-Object { $_ -in @('Key Vault Reader', 'Key Vault Crypto User', 'Key Vault Crypto Officer', 'Key Vault Administrator') })
if ($has.Count) { Note "already holds $($has -join ', ')" }
else {
    az role assignment create --subscription $SubscriptionId --assignee-object-id $callerOid --assignee-principal-type $callerType --role 'Key Vault Reader' --scope $keyScope -o none --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "could not grant Key Vault Reader on $keyScope to the build identity (az exit $LASTEXITCODE) -- it needs Owner or User Access Administrator." }
    Note 'granted'
}
$deadline = (Get-Date).AddMinutes($PropagationTimeoutMinutes)
$pub = $null; $lastErr = ''; $waited = 0
while ((Get-Date) -lt $deadline) {
    $kvTok = "$(((az account get-access-token --subscription $SubscriptionId --resource https://vault.azure.net -o json 2>$null) | Out-String | ConvertFrom-Json).accessToken)"
    try { $pub = Invoke-RestMethod -Method GET -Uri ($keyUriWithVersion + '?api-version=7.4') -Headers @{ Authorization = "Bearer $kvTok" } -ErrorAction Stop; break }
    catch {
        $lastErr = "$($_.Exception.Message)"
        $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
        if ($code -ne 403 -and $code -ne 401) { throw "reading the public key failed (not an RBAC delay): $lastErr" }
        Note "  not yet authorised on the data plane (${waited}s) -- waiting 30s for RBAC propagation"
        Start-Sleep -Seconds 30; $waited += 30
    }
}
if (-not $pub) { throw "could not read the public key within $PropagationTimeoutMinutes minute(s): $lastErr" }
if ("$($pub.key.kid)".Trim() -ne $keyUriWithVersion) { throw "read-back FAILED: the data plane returned kid '$($pub.key.kid)', ARM says '$keyUriWithVersion'" }
$keyId = Get-PimBaselineKeyId -N "$($pub.key.n)" -E "$($pub.key.e)"

Write-Host ''
Write-Host '  SIGNING KEY ID -- give it to EVERY managed tenant (an identifier, not a credential):' -ForegroundColor Yellow
Write-Host "    master.signingKeyIds += $keyId" -ForegroundColor Yellow
Write-Host "    key: $keyUriWithVersion ($($back.properties.kty) $($back.properties.keySize), sign+verify, not exportable)" -ForegroundColor DarkGray
Write-Host '  A managed tenant REFUSES a bundle signed by a key it does not pin. Pin a new id everywhere BEFORE a key roll.' -ForegroundColor DarkGray

# ---- 4. §71.40 -- pin it on this master's OWN Manager (merge, never replace; read back) ---------------------------------
if ("$PinOnManagerApp".Trim()) {
    . (Join-Path $solRoot 'engine\_shared\PIM-DownlinkManager.ps1')
    Step "pin the key id on the Manager $PinOnManagerApp (PIM_BaselineTrustedKeys, merged)"
    $cur = "$(@(az containerapp show --subscription $SubscriptionId -g $ResourceGroup -n $PinOnManagerApp --query "properties.template.containers[0].env[?name=='PIM_BaselineTrustedKeys'].value" -o tsv 2>$null) -join ',')".Trim()
    $merge = Get-PimManagerBaselineEnvPlan -TrustedKeys @($cur, $keyId)
    if (-not $merge.ok) { throw "the Manager's existing pins could not be merged: $($merge.reason)" }
    $curKeys = @("$cur" -split '[,;\s]+' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($curKeys -ccontains $keyId) {
        Note "already pinned ($($merge.keys -join ', '))"
    } elseif ($PSCmdlet.ShouldProcess($PinOnManagerApp, "set PIM_BaselineTrustedKeys=$($merge.keys -join ',')")) {
        $pinEnv = @($merge.env | Where-Object { $_ -like 'PIM_BaselineTrustedKeys=*' })
        az containerapp update --subscription $SubscriptionId -g $ResourceGroup -n $PinOnManagerApp --set-env-vars @pinEnv -o none --only-show-errors
        if ($LASTEXITCODE -ne 0) { throw "could not set PIM_BaselineTrustedKeys on $PinOnManagerApp (az exit $LASTEXITCODE)." }
        $back = "$(@(az containerapp show --subscription $SubscriptionId -g $ResourceGroup -n $PinOnManagerApp --query "properties.template.containers[0].env[?name=='PIM_BaselineTrustedKeys'].value" -o tsv 2>$null) -join ',')".Trim()
        if ((@($back -split '[,;\s]+') -notcontains $keyId)) { throw "read-back FAILED: $PinOnManagerApp's PIM_BaselineTrustedKeys reads '$back', which does not contain $keyId." }
        Note "pinned and read back: $back"
    }
}
Write-Output $keyId
exit 0
