#requires -Version 5.1
<#
.SYNOPSIS
    Stand up the MASTER's signed-baseline publish target: storage account + `baselines`
    container + data-plane rights for the publishing identity. Idempotent, and VERIFIED
    after it runs.

.DESCRIPTION
    🔴 WHY THIS SCRIPT EXISTS. internal/DEPLOY-SCENARIOS.md documents this as a four-step
    chain and says, in its own words, that it "needs four things that nothing sets up for
    you". That was true: measured 2026-09-03, NOTHING in tools/, setup/ or the platform
    provisioner creates a storage account at all. EFIF's `stpimbaselinewa678` was made by
    hand in session 30 and never written down as code, so a GREENFIELD master could not
    publish a baseline -- which means it could not onboard a managed tenant. An onboarding
    step that exists only as prose in a runbook is not an onboarding step.

    The four steps, in the order the runbook establishes (each is a trap if skipped):

      1. REGISTER Microsoft.Storage on the master's subscription. Skipping this is the
         trap, not the work: Azure answers an unregistered provider with
         (SubscriptionNotFound) "Subscription <id> was not found", which reads as a
         permissions or wrong-tenant problem and sends you hunting in the wrong place.
      2. CREATE the account + container. Standard_LRS is ample -- bundles are a few KB --
         and public blob access is disabled: the SIGNATURE establishes trust, not the
         network, and a slave reads with a SAS (BUG-73).
      3. GRANT the PUBLISHING identity 'Storage Blob Data Contributor'. That is the
         master's ENGINE SPN (Modern-AppId), NOT the bootstrap SPN -- the bootstrap SPN is
         Key Vault data-plane only and will 401 here, which looks exactly like a missing
         role assignment.
      4. VERIFY by actually writing and reading a probe blob AS THAT IDENTITY. A deploy
         that reports its own success is the failure mode this whole solution keeps
         relearning; the only thing that proves a publish target works is a publish.

    ⏳ RBAC ON STORAGE IS NOT INSTANT. A grant can take minutes to reach the data plane, so
    a 401 straight after the assignment means "wait", not "wrong". Step 4 therefore RETRIES
    rather than failing on the first 401 -- and reports how long it waited, because that
    number is the difference between "propagating" and "the identity is wrong".

.PARAMETER SubscriptionId / ResourceGroup / Location
    The MASTER's subscription, its resource group and region.

.PARAMETER StorageAccount
    Account name. Defaults to stpimbaseline<token> where <token> is derived from the
    resource group (rg-automateit-<token>), matching the estate's naming contract.

.PARAMETER PublisherObjectId
    Object id (NOT the app id) of the identity that will publish bundles -- the master's
    engine SPN. Resolved from -PublisherAppId when omitted.

.PARAMETER PublisherAppId
    App id of the publishing SPN; its object id is looked up. Use this when you have the
    Modern-AppId from the tenant's Key Vault, which is the usual case.

.EXAMPLE
    ./New-PimBaselineStorage.ps1 -SubscriptionId <master-sub> -ResourceGroup rg-automateit-dp998 `
        -Location swedencentral -PublisherAppId <Modern-AppId>
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$Location = 'swedencentral',
    [string]$StorageAccount,
    [string]$Container = 'baselines',
    [string]$PublisherObjectId,
    [string]$PublisherAppId,
    # 71.33: the publisher may be a signed-in USER (a signed-in build) rather than an application.
    [ValidateSet('ServicePrincipal', 'User', 'Group')][string]$PublisherPrincipalType = 'ServicePrincipal',
    # 71.34 PUBLIC-BUT-SIGNED (DESIGN 13.7): anonymous read of the bundle BLOB (no listing), storage firewall Deny,
    # and allow rules for the publishing host -- via Set-PimBaselineNetworkAccess.ps1 -EnsurePosture. No SAS anywhere.
    # The publishing host must be named, or Deny locks the publish itself out: a subnet id when the host is in the
    # storage account's region (IP rules do not apply to same-region traffic), otherwise its public egress IP.
    [switch]$PublicSignedRead,
    [string[]]$PublisherSubnetResourceIds = @(),
    [string[]]$PublisherIpAddresses = @(),
    # 71.35 CLOUD PUBLISH: the publisher is the master's own Container Apps job (ca-pim-publish), so the allowed publisher
    # network is the subnet of THIS Container Apps environment (read from it; its storage service endpoint is set first by
    # Initialize-PimBaselinePullNetwork.ps1). Its VNet rule is added BEFORE default-action Deny, in the same call.
    [string]$PublisherEnvName,
    # 71.35: the host running this script does not publish (the job's identity does; Deploy-PimBaselinePublishJob.ps1 grants
    # it). No publisher role for the build identity and no write/read probe from this host -- its network is not allowed.
    [switch]$NoHostPublisher,
    [ValidateRange(0, 30)][int]$VerifyTimeoutMinutes = 10
)

$ErrorActionPreference = 'Stop'
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }

# The estate's naming contract: rg-automateit-<token> -> stpimbaseline<token>.
if (-not "$StorageAccount".Trim()) {
    $token = ($ResourceGroup -replace '^rg-automateit-', '')
    if ($token -eq $ResourceGroup) { throw "cannot derive a storage name from '$ResourceGroup' (expected rg-automateit-<token>) -- pass -StorageAccount." }
    $StorageAccount = "stpimbaseline$token"
}
Step "Baseline publish target: $StorageAccount/$Container  (rg $ResourceGroup, sub $SubscriptionId)"

# 🪤 The account name is not free-form: 3-24 chars, lowercase alphanumeric. Say so here rather
# than letting az reject it after the provider registration has already run.
if ($StorageAccount -notmatch '^[a-z0-9]{3,24}$') {
    throw "storage account name '$StorageAccount' is invalid (3-24 lowercase alphanumerics)."
}

# --- context must be the MASTER's subscription --------------------------------
$acct = az account show --query id -o tsv 2>$null
if ($LASTEXITCODE -ne 0 -or -not "$acct".Trim()) { throw "no az context. Log in to the master tenant first." }
if ("$acct".Trim() -ne "$SubscriptionId".Trim()) {
    # Same family as ESTATE-14: "a context exists" is not "the right context", and on this host
    # the default is routinely another tenant entirely.
    throw "az context is subscription '$acct' but the master is '$SubscriptionId' -- refusing to create storage in the wrong subscription. Fix: az account set --subscription $SubscriptionId"
}
Note "az context verified: $acct"
# 🔴 Every call below splats this. It was referenced by the create calls but never DEFINED, so it
# expanded to nothing and those calls ran in whatever the default context was (2026-09-13).
$subArgs = @('--subscription', $SubscriptionId)

# --- 1) provider ---------------------------------------------------------------
Step 'Microsoft.Storage provider registration'
$state = az provider show @subArgs -n Microsoft.Storage --query registrationState -o tsv 2>$null
if ("$state" -eq 'Registered') { Note 'already Registered' }
elseif ($PSCmdlet.ShouldProcess('Microsoft.Storage', 'register provider')) {
    Note "state '$state' -- registering (this can take a minute)"
    az provider register @subArgs -n Microsoft.Storage --wait -o none 2>&1 | Out-Null
    $state = az provider show @subArgs -n Microsoft.Storage --query registrationState -o tsv 2>$null
    if ("$state" -ne 'Registered') { throw "Microsoft.Storage did not reach Registered (state '$state'). Every step below would fail as (SubscriptionNotFound)." }
    Note 'Registered'
}

# --- 2) account + container ----------------------------------------------------
Step "storage account $StorageAccount"
$exists = az storage account show @subArgs -n $StorageAccount -g $ResourceGroup --query name -o tsv 2>$null
if ("$exists".Trim()) { Note 'account exists (find-or-create)' }
elseif ($PSCmdlet.ShouldProcess($StorageAccount, 'create storage account')) {
    az storage account create @subArgs -n $StorageAccount -g $ResourceGroup -l $Location `
        --sku Standard_LRS --kind StorageV2 --allow-blob-public-access $(if ($PublicSignedRead) { 'true' } else { 'false' }) -o none 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "az storage account create failed (exit $LASTEXITCODE)." }
    Note "created ($Location, Standard_LRS, public blob access DISABLED)"
}
$saId = az storage account show @subArgs -n $StorageAccount -g $ResourceGroup --query id -o tsv 2>$null
if (-not "$saId".Trim()) { throw "could not read the resource id of '$StorageAccount' after create." }

# 🔴 --auth-mode login, NOT an account key. A key would work and would also mean this script
# handled a credential it never needs: container creation is an RBAC operation for the caller.
Step "container $Container"
# 71.35: CONTROL PLANE (container-rm). The data-plane form needs a data role for the caller AND a network the firewall
# allows -- and once default-action is Deny, a re-run of this step from a build host would fail on a container that exists.
$hasC = az storage container-rm exists @subArgs -g $ResourceGroup --storage-account $StorageAccount -n $Container --query exists -o tsv 2>$null
if ("$hasC".Trim() -eq 'true') { Note 'container exists' }
elseif ($PSCmdlet.ShouldProcess($Container, 'create container')) {
    az storage container-rm create @subArgs -g $ResourceGroup --storage-account $StorageAccount -n $Container -o none 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "az storage container-rm create failed (exit $LASTEXITCODE)." }
    Note 'created'
}

# 71.35: the master's own Container Apps subnet is the publisher network (the cloud publish job runs there).
if ("$PublisherEnvName".Trim()) {
    $pubSubnet = "$(az containerapp env show @subArgs -g $ResourceGroup -n $PublisherEnvName --query properties.vnetConfiguration.infrastructureSubnetId -o tsv 2>$null)".Trim()
    if (-not $pubSubnet) { throw "the Container Apps environment '$PublisherEnvName' names no infrastructure subnet -- the publish job's network cannot be allowed on the store." }
    Note "publisher network: the '$PublisherEnvName' subnet $pubSubnet (the cloud publish job)"
    $PublisherSubnetResourceIds = @(@($PublisherSubnetResourceIds) + $pubSubnet | Where-Object { "$_".Trim() } | Select-Object -Unique)
}

# --- 3) data-plane rights for the PUBLISHER ------------------------------------
if ($NoHostPublisher) {
    Note 'publisher role: not granted here -- the publish job''s own identity gets Storage Blob Data Contributor on the container (Deploy-PimBaselinePublishJob.ps1)'
} else {
if (-not "$PublisherObjectId".Trim()) {
    if (-not "$PublisherAppId".Trim()) { throw 'pass -PublisherObjectId or -PublisherAppId (the master ENGINE SPN, not the bootstrap SPN).' }
    $PublisherObjectId = az ad sp show --id $PublisherAppId --query id -o tsv 2>$null
    if (-not "$PublisherObjectId".Trim()) { throw "could not resolve an object id for app id '$PublisherAppId'." }
    Note "publisher appId $PublisherAppId -> objectId $PublisherObjectId"
}
Step "'Storage Blob Data Contributor' for $PublisherObjectId"
$have = az role assignment list @subArgs --assignee $PublisherObjectId --scope $saId `
        --query "[?roleDefinitionName=='Storage Blob Data Contributor'].id" -o tsv 2>$null
if ("$have".Trim()) { Note 'already assigned' }
elseif ($PSCmdlet.ShouldProcess($StorageAccount, 'grant Storage Blob Data Contributor')) {
    az role assignment create @subArgs --assignee-object-id $PublisherObjectId --assignee-principal-type $PublisherPrincipalType `
        --role 'Storage Blob Data Contributor' --scope $saId -o none 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "role assignment failed (exit $LASTEXITCODE)." }
    Note 'granted'
}
}

if ($PublicSignedRead) {
    Step 'public-but-signed posture: anonymous blob read, firewall Deny, the publishing host allowed (no SAS, nothing expires)'
    if (-not (@($PublisherSubnetResourceIds | Where-Object { "$_".Trim() }).Count + @($PublisherIpAddresses | Where-Object { "$_".Trim() }).Count)) {
        throw '-PublicSignedRead needs -PublisherSubnetResourceIds or -PublisherIpAddresses (or -PublisherEnvName, the cloud publish job''s environment): the firewall denies every network not named, including the publisher.'
    }
    & (Join-Path $PSScriptRoot 'Set-PimBaselineNetworkAccess.ps1') -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -StorageAccount $StorageAccount -Container $Container `
        -SubnetResourceId $PublisherSubnetResourceIds -IpAddress $PublisherIpAddresses -EnsurePosture -WhatIf:$WhatIfPreference
}

# --- 4) VERIFY by actually writing and reading, as the publisher ---------------
# A role assignment that exists in ARM is not the same as one the DATA plane honours yet.
if ($WhatIfPreference) { Step 'WhatIf: skipping the write/read probe.'; return }
if ($NoHostPublisher) {
    # The proof that the store works is the FIRST PUBLISH: the job writes, then reads the blob back anonymously from its
    # allowed subnet and verifies it (Start-PimBaselinePublish.ps1 waits for that execution to succeed).
    Step 'Done (no probe from this host: its network is not an allowed source -- the first publish proves the store).'
    [pscustomobject]@{ StorageAccount = $StorageAccount; Container = $Container; ResourceId = $saId; PublisherObjectId = '' }
    return
}
Step 'verifying the publish target with a real write + read (RBAC can lag several minutes)'
$probe   = "_publish-probe.json"
$tmp     = Join-Path ([System.IO.Path]::GetTempPath()) "pim-baseline-probe-$PID.json"
Set-Content -LiteralPath $tmp -Value (@{ probe = 'New-PimBaselineStorage'; utc = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json) -Encoding utf8
$deadline = (Get-Date).AddMinutes($VerifyTimeoutMinutes)
$ok = $false; $lastErr = ''; $waited = 0
while ((Get-Date) -lt $deadline) {
    $out = az storage blob upload @subArgs --account-name $StorageAccount -c $Container -n $probe -f $tmp --overwrite --auth-mode login -o none 2>&1
    if ($LASTEXITCODE -eq 0) { $ok = $true; break }
    $lastErr = ($out | Out-String).Trim()
    # 🪤 az DOES NOT SAY "403" HERE. The first cut of this matched 401|403|not authorized and threw
    # on the very case it exists to wait through, because the CLI's actual wording for a data-plane
    # RBAC gap is "You do not have the required permissions needed to perform this operation.
    # Depending on your operation, you may need to be assigned one of the following roles: ...".
    # No status code, no "not authorized". Measured on the greenfield master 2026-09-03, seconds
    # after the role assignment succeeded.
    # 🔑 Matching on a phrase list is what caused this, so the list is now broad and the TIMEOUT is
    # what bounds the wait -- a wrong configuration costs $VerifyTimeoutMinutes and then reports
    # the real error, which is far better than a correct one failing instantly on new phrasing.
    if ($lastErr -notmatch '(?i)401|403|Authorization|not authorized|required permissions|assigned one of the following roles|AuthenticationFailed') {
        throw "upload failed for a reason that is NOT propagation: $lastErr"
    }
    Warn "  not yet authorised on the data plane -- ${waited}s elapsed, waiting 30s (RBAC propagation)"
    Start-Sleep -Seconds 30; $waited += 30
}
Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
if (-not $ok) {
    throw ("could not write to $StorageAccount/$Container within $VerifyTimeoutMinutes minute(s). " +
           $(if ($PublicSignedRead) { "With -PublicSignedRead a 403 'AuthorizationFailure' also means THIS host's network is not one of the allowed sources (same region as the account => a subnet rule, not an IP rule). " } else { '' }) +
           "If a DIRECT upload works but the publisher still 401s, the identity is wrong, not the role " +
           "(the bootstrap SPN is Key Vault data-plane only). Last error: $lastErr")
}
Note "write OK$(if ($waited) { " after ${waited}s of RBAC propagation" })"
$read = az storage blob download @subArgs --account-name $StorageAccount -c $Container -n $probe --file (Join-Path ([System.IO.Path]::GetTempPath()) "pim-probe-read-$PID.json") --auth-mode login -o none 2>&1
if ($LASTEXITCODE -ne 0) { throw "wrote the probe but could not read it back: $(($read | Out-String).Trim())" }
Remove-Item -LiteralPath (Join-Path ([System.IO.Path]::GetTempPath()) "pim-probe-read-$PID.json") -Force -ErrorAction SilentlyContinue
if ($PublicSignedRead) {
    # The reader's path, proven: an ANONYMOUS GET (no token, no SAS) of the blob from an allowed network.
    try { $null = Invoke-RestMethod -Method GET -Uri ("https://{0}.blob.core.windows.net/{1}/{2}" -f $StorageAccount, $Container, $probe) -Headers @{ 'x-ms-version' = '2021-08-06' } -ErrorAction Stop; Note 'anonymous read OK (no credential)' }
    catch { throw "anonymous read of the probe blob FAILED from an allowed network -- the public-but-signed posture is not effective: $($_.Exception.Message)" }
}
az storage blob delete @subArgs --account-name $StorageAccount -c $Container -n $probe --auth-mode login -o none 2>&1 | Out-Null
Note 'read OK, probe removed'

Step 'Done.'
Write-Host ("  publish target ready: https://{0}.blob.core.windows.net/{1}/" -f $StorageAccount, $Container) -ForegroundColor Green
Write-Host  "  next: setup/New-PimBaselineBundle.ps1 -CentralServer <master sql> -Database PimPlatform -StorageAccount $StorageAccount -Container $Container -Scope fleet" -ForegroundColor DarkGray
[pscustomobject]@{ StorageAccount = $StorageAccount; Container = $Container; ResourceId = $saId; PublisherObjectId = $PublisherObjectId }
