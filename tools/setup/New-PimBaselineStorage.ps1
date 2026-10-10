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

      1. REGISTER Microsoft.Storage on the managing tenant's subscription. Skipping this is the
         trap, not the work: Azure answers an unregistered provider with
         (SubscriptionNotFound) "Subscription <id> was not found", which reads as a
         permissions or wrong-tenant problem and sends you hunting in the wrong place.
      2. CREATE the account + container. Standard_LRS is ample -- bundles are a few KB. The
         SIGNATURE establishes trust, not the network. There is NO SAS anywhere (71.34):
         with -PublicSignedRead a managed tenant reads the bundle blob ANONYMOUSLY (blob
         public access on, no listing) from a network the storage firewall allows
         (default-action Deny); without it, public blob access stays OFF.
      3. GRANT the PUBLISHING identity 'Storage Blob Data Contributor' -- unless
         -NoHostPublisher: since 71.35 the publisher is the managing tenant's cloud publish job
         (ca-pim-publish), whose own identity Deploy-PimBaselinePublishJob.ps1 grants on the
         container. With a host publisher it is the identity that publishes, NOT the bootstrap
         SPN -- the bootstrap SPN is Key Vault data-plane only and will 401 here, which looks
         exactly like a missing role assignment.
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
    Object id (NOT the app id) of a HOST identity that will publish bundles. Not used with
    -NoHostPublisher (the cloud publish job, 71.35). Resolved from -PublisherAppId when omitted.

.PARAMETER PublisherAppId
    App id of a host publishing SPN; its object id is looked up.

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
    # 71.35 CLOUD PUBLISH: the publisher is the managing tenant's own Container Apps job (ca-pim-publish), so the allowed publisher
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
# 100.41 (framework 12.17 NO-AZ): every call below is ARM / blob REST through PIM-Rest's one token client
# (engine/_shared/PIM-ArmSetup.ps1), addressed BY subscription -- there is no machine-wide default context to change or to
# fall into. A calling build's REST session is used as it is; standalone, the Invardia Support app's session or the person.
$solRootBs = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRootBs 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRootBs 'engine\_shared\PIM-ArmSetup.ps1') }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId) }
$acct = "$((Get-PimArmSubscription -SubscriptionId $SubscriptionId -ErrorAsNull).subscriptionId)"
if (-not "$acct".Trim()) { throw "the signed-in identity cannot read subscription '$SubscriptionId'. Sign in to the managing tenant first." }
if ("$acct".Trim() -ne "$SubscriptionId".Trim()) {
    # Same family as ESTATE-14: "a context exists" is not "the right context".
    throw "ARM resolved subscription '$acct', not the managing tenant '$SubscriptionId' -- refusing to create storage in the wrong subscription."
}
Note "subscription verified: $acct"

# --- 1) provider ---------------------------------------------------------------
Step 'Microsoft.Storage provider registration'
$state = Get-PimArmProviderState -SubscriptionId $SubscriptionId -Namespace Microsoft.Storage
if ("$state" -eq 'Registered') { Note 'already Registered' }
elseif ($PSCmdlet.ShouldProcess('Microsoft.Storage', 'register provider')) {
    Note "state '$state' -- registering (this can take a minute)"
    $state = Register-PimArmProvider -SubscriptionId $SubscriptionId -Namespace Microsoft.Storage -Wait
    if ("$state" -ne 'Registered') { throw "Microsoft.Storage did not reach Registered (state '$state'). Every step below would fail as (SubscriptionNotFound)." }
    Note 'Registered'
}

# --- 2) account + container ----------------------------------------------------
Step "storage account $StorageAccount"
$exists = "$((Get-PimArmStorageAccount -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $StorageAccount -ErrorAsNull).name)"
if ("$exists".Trim()) { Note 'account exists (find-or-create)' }
elseif ($PSCmdlet.ShouldProcess($StorageAccount, 'create storage account')) {
    try { [void](New-PimArmStorageAccount -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $StorageAccount -Location $Location -Sku Standard_LRS -Kind StorageV2 -AllowBlobPublicAccess ([bool]$PublicSignedRead)) }
    catch { throw "storage account create failed: $($_.Exception.Message)" }
    # DOC-17 k: say what was actually created -- with -PublicSignedRead blob public access is ON (anonymous read of the
    # signed bundle blob from the networks the firewall allows); it said "DISABLED" either way.
    Note "created ($Location, Standard_LRS, public blob access $(if ($PublicSignedRead) { 'ENABLED (anonymous read of the signed bundle blob; the firewall names who can reach it)' } else { 'DISABLED' }))"
}
$saId = "$((Get-PimArmStorageAccount -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $StorageAccount -ErrorAsNull).id)"
if (-not "$saId".Trim()) { throw "could not read the resource id of '$StorageAccount' after create." }

# 🔴 An Entra token, NOT an account key. A key would work and would also mean this script
# handled a credential it never needs: container creation is an RBAC operation for the caller.
Step "container $Container"
# 71.35: CONTROL PLANE (blobServices/default/containers). The data-plane form needs a data role for the caller AND a network
# the firewall allows -- and once default-action is Deny, a re-run of this step from a build host would fail on a container that exists.
$hasC = [bool](Get-PimArmBlobContainer -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Account $StorageAccount -Name $Container -ErrorAsNull)
if ($hasC) { Note 'container exists' }
elseif ($PSCmdlet.ShouldProcess($Container, 'create container')) {
    try { [void](Set-PimArmBlobContainer -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Account $StorageAccount -Name $Container -Create) }
    catch { throw "container create failed: $($_.Exception.Message)" }
    Note 'created'
}

# 71.35: the managing tenant's own Container Apps subnet is the publisher network (the cloud publish job runs there).
if ("$PublisherEnvName".Trim()) {
    $pubSubnet = "$((Get-PimArmAcaEnv -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $PublisherEnvName -ErrorAsNull).properties.vnetConfiguration.infrastructureSubnetId)".Trim()
    if (-not $pubSubnet) { throw "the Container Apps environment '$PublisherEnvName' names no infrastructure subnet -- the publish job's network cannot be allowed on the store." }
    Note "publisher network: the '$PublisherEnvName' subnet $pubSubnet (the cloud publish job)"
    $PublisherSubnetResourceIds = @(@($PublisherSubnetResourceIds) + $pubSubnet | Where-Object { "$_".Trim() } | Select-Object -Unique)
}

# --- 3) data-plane rights for the PUBLISHER ------------------------------------
if ($NoHostPublisher) {
    Note 'publisher role: not granted here -- the publish job''s own identity gets Storage Blob Data Contributor on the container (Deploy-PimBaselinePublishJob.ps1)'
} else {
if (-not "$PublisherObjectId".Trim()) {
    if (-not "$PublisherAppId".Trim()) { throw 'pass -PublisherObjectId or -PublisherAppId (the managing tenant ENGINE SPN, not the bootstrap SPN).' }
    $PublisherObjectId = "$((Get-PimGraphServicePrincipal -Id $PublisherAppId -Select 'id' -ErrorAsNull).id)"
    if (-not "$PublisherObjectId".Trim()) { throw "could not resolve an object id for app id '$PublisherAppId'." }
    Note "publisher appId $PublisherAppId -> objectId $PublisherObjectId"
}
Step "'Storage Blob Data Contributor' for $PublisherObjectId"
$have = @(Get-PimArmRoleAssignments -Scope $saId -PrincipalId $PublisherObjectId -Role 'Storage Blob Data Contributor' -SubscriptionId $SubscriptionId)
if ($have.Count) { Note 'already assigned' }
elseif ($PSCmdlet.ShouldProcess($StorageAccount, 'grant Storage Blob Data Contributor')) {
    try { [void](New-PimArmRoleAssignment -Scope $saId -PrincipalId $PublisherObjectId -PrincipalType $PublisherPrincipalType -Role 'Storage Blob Data Contributor' -SubscriptionId $SubscriptionId) }
    catch { throw "role assignment failed: $($_.Exception.Message)" }
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
$probeBody = (@{ probe = 'New-PimBaselineStorage'; utc = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json)
$deadline = (Get-Date).AddMinutes($VerifyTimeoutMinutes)
$ok = $false; $lastErr = ''; $waited = 0
while ((Get-Date) -lt $deadline) {
    try { [void](Invoke-PimBlobData -Method PUT -Account $StorageAccount -Container $Container -Blob $probe -Content $probeBody); $ok = $true; break }
    catch { $lastErr = "$($_.Exception.Message)".Trim() }
    # 🪤 A data-plane RBAC gap right after the grant is "wait", not "wrong" -- and its wording is not stable (az said
    # "You do not have the required permissions needed to perform this operation" with no status code; REST says
    # HTTP 403 AuthorizationPermissionMismatch). Measured on the greenfield master 2026-09-03, seconds after the grant.
    # 🔑 Matching on a phrase list is what caused that, so the list is broad and the TIMEOUT is what bounds the wait --
    # a wrong configuration costs $VerifyTimeoutMinutes and then reports the real error, which is far better than a
    # correct one failing instantly on new phrasing.
    if ($lastErr -notmatch '(?i)401|403|Authorization|not authorized|required permissions|assigned one of the following roles|AuthenticationFailed') {
        throw "upload failed for a reason that is NOT propagation: $lastErr"
    }
    Warn "  not yet authorised on the data plane -- ${waited}s elapsed, waiting 30s (RBAC propagation)"
    Start-Sleep -Seconds 30; $waited += 30
}
if (-not $ok) {
    throw ("could not write to $StorageAccount/$Container within $VerifyTimeoutMinutes minute(s). " +
           $(if ($PublicSignedRead) { "With -PublicSignedRead a 403 'AuthorizationFailure' also means THIS host's network is not one of the allowed sources (same region as the account => a subnet rule, not an IP rule). " } else { '' }) +
           "If a DIRECT upload works but the publisher still 401s, the identity is wrong, not the role " +
           "(the bootstrap SPN is Key Vault data-plane only). Last error: $lastErr")
}
Note "write OK$(if ($waited) { " after ${waited}s of RBAC propagation" })"
try { [void](Invoke-PimBlobData -Method GET -Account $StorageAccount -Container $Container -Blob $probe) }
catch { throw "wrote the probe but could not read it back: $($_.Exception.Message)" }
if ($PublicSignedRead) {
    # The reader's path, proven: an ANONYMOUS GET (no token, no SAS) of the blob from an allowed network.
    try { $null = Invoke-RestMethod -Method GET -Uri ("https://{0}.blob.core.windows.net/{1}/{2}" -f $StorageAccount, $Container, $probe) -Headers @{ 'x-ms-version' = '2021-08-06' } -ErrorAction Stop; Note 'anonymous read OK (no credential)' }
    catch { throw "anonymous read of the probe blob FAILED from an allowed network -- the public-but-signed posture is not effective: $($_.Exception.Message)" }
}
try { [void](Invoke-PimBlobData -Method DELETE -Account $StorageAccount -Container $Container -Blob $probe) } catch { Write-Verbose "probe delete: $($_.Exception.Message)" }
Note 'read OK, probe removed'

Step 'Done.'
Write-Host ("  publish target ready: https://{0}.blob.core.windows.net/{1}/" -f $StorageAccount, $Container) -ForegroundColor Green
Write-Host  "  next: Deploy-PimBaselinePublishJob.ps1 (the ca-pim-publish job writes here), then Start-PimBaselinePublish.ps1 -SubscriptionId <subscription> -ResourceGroup <resource group>" -ForegroundColor DarkGray
[pscustomobject]@{ StorageAccount = $StorageAccount; Container = $Container; ResourceId = $saId; PublisherObjectId = $PublisherObjectId }
