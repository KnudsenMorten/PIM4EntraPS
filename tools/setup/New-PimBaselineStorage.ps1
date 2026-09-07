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

# --- 1) provider ---------------------------------------------------------------
Step 'Microsoft.Storage provider registration'
$state = az provider show -n Microsoft.Storage --query registrationState -o tsv 2>$null
if ("$state" -eq 'Registered') { Note 'already Registered' }
elseif ($PSCmdlet.ShouldProcess('Microsoft.Storage', 'register provider')) {
    Note "state '$state' -- registering (this can take a minute)"
    az provider register @subArgs -n Microsoft.Storage --wait -o none 2>&1 | Out-Null
    $state = az provider show -n Microsoft.Storage --query registrationState -o tsv 2>$null
    if ("$state" -ne 'Registered') { throw "Microsoft.Storage did not reach Registered (state '$state'). Every step below would fail as (SubscriptionNotFound)." }
    Note 'Registered'
}

# --- 2) account + container ----------------------------------------------------
Step "storage account $StorageAccount"
$exists = az storage account show -n $StorageAccount -g $ResourceGroup --query name -o tsv 2>$null
if ("$exists".Trim()) { Note 'account exists (find-or-create)' }
elseif ($PSCmdlet.ShouldProcess($StorageAccount, 'create storage account')) {
    az storage account create @subArgs -n $StorageAccount -g $ResourceGroup -l $Location `
        --sku Standard_LRS --kind StorageV2 --allow-blob-public-access false -o none 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "az storage account create failed (exit $LASTEXITCODE)." }
    Note "created ($Location, Standard_LRS, public blob access DISABLED)"
}
$saId = az storage account show -n $StorageAccount -g $ResourceGroup --query id -o tsv 2>$null
if (-not "$saId".Trim()) { throw "could not read the resource id of '$StorageAccount' after create." }

# 🔴 --auth-mode login, NOT an account key. A key would work and would also mean this script
# handled a credential it never needs: container creation is an RBAC operation for the caller.
Step "container $Container"
$hasC = az storage container exists -n $Container --account-name $StorageAccount --auth-mode login --query exists -o tsv 2>$null
if ("$hasC" -eq 'true') { Note 'container exists' }
elseif ($PSCmdlet.ShouldProcess($Container, 'create container')) {
    az storage container create @subArgs -n $Container --account-name $StorageAccount --auth-mode login -o none 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "az storage container create failed (exit $LASTEXITCODE). If this is a 403, the CALLER needs a data-plane role on $StorageAccount too." }
    Note 'created'
}

# --- 3) data-plane rights for the PUBLISHER ------------------------------------
if (-not "$PublisherObjectId".Trim()) {
    if (-not "$PublisherAppId".Trim()) { throw 'pass -PublisherObjectId or -PublisherAppId (the master ENGINE SPN, not the bootstrap SPN).' }
    $PublisherObjectId = az ad sp show --id $PublisherAppId --query id -o tsv 2>$null
    if (-not "$PublisherObjectId".Trim()) { throw "could not resolve an object id for app id '$PublisherAppId'." }
    Note "publisher appId $PublisherAppId -> objectId $PublisherObjectId"
}
Step "'Storage Blob Data Contributor' for $PublisherObjectId"
$have = az role assignment list --assignee $PublisherObjectId --scope $saId `
        --query "[?roleDefinitionName=='Storage Blob Data Contributor'].id" -o tsv 2>$null
if ("$have".Trim()) { Note 'already assigned' }
elseif ($PSCmdlet.ShouldProcess($StorageAccount, 'grant Storage Blob Data Contributor')) {
    az role assignment create @subArgs --assignee-object-id $PublisherObjectId --assignee-principal-type ServicePrincipal `
        --role 'Storage Blob Data Contributor' --scope $saId -o none 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "role assignment failed (exit $LASTEXITCODE)." }
    Note 'granted'
}

# --- 4) VERIFY by actually writing and reading, as the publisher ---------------
# A role assignment that exists in ARM is not the same as one the DATA plane honours yet.
if ($WhatIfPreference) { Step 'WhatIf: skipping the write/read probe.'; return }
Step 'verifying the publish target with a real write + read (RBAC can lag several minutes)'
$probe   = "_publish-probe.json"
$tmp     = Join-Path ([System.IO.Path]::GetTempPath()) "pim-baseline-probe-$PID.json"
Set-Content -LiteralPath $tmp -Value (@{ probe = 'New-PimBaselineStorage'; utc = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json) -Encoding utf8
$deadline = (Get-Date).AddMinutes($VerifyTimeoutMinutes)
$ok = $false; $lastErr = ''; $waited = 0
while ((Get-Date) -lt $deadline) {
    $out = az storage blob upload --account-name $StorageAccount -c $Container -n $probe -f $tmp --overwrite --auth-mode login -o none 2>&1
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
           "If a DIRECT upload works but the publisher still 401s, the identity is wrong, not the role " +
           "(the bootstrap SPN is Key Vault data-plane only). Last error: $lastErr")
}
Note "write OK$(if ($waited) { " after ${waited}s of RBAC propagation" })"
$read = az storage blob download --account-name $StorageAccount -c $Container -n $probe --file (Join-Path ([System.IO.Path]::GetTempPath()) "pim-probe-read-$PID.json") --auth-mode login -o none 2>&1
if ($LASTEXITCODE -ne 0) { throw "wrote the probe but could not read it back: $(($read | Out-String).Trim())" }
Remove-Item -LiteralPath (Join-Path ([System.IO.Path]::GetTempPath()) "pim-probe-read-$PID.json") -Force -ErrorAction SilentlyContinue
az storage blob delete @subArgs --account-name $StorageAccount -c $Container -n $probe --auth-mode login -o none 2>&1 | Out-Null
Note 'read OK, probe removed'

Step 'Done.'
Write-Host ("  publish target ready: https://{0}.blob.core.windows.net/{1}/" -f $StorageAccount, $Container) -ForegroundColor Green
Write-Host  "  next: setup/New-PimBaselineBundle.ps1 -CentralServer <master sql> -Database PimPlatform -StorageAccount $StorageAccount -Container $Container -Scope fleet" -ForegroundColor DarkGray
[pscustomobject]@{ StorageAccount = $StorageAccount; Container = $Container; ResourceId = $saId; PublisherObjectId = $PublisherObjectId }
