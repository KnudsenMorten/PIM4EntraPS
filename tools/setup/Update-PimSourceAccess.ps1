#Requires -Version 5.1
<#
.SYNOPSIS
    Extend or REVOKE customers' access to the source feed -- centrally, without touching a single
    customer environment. §59.

.DESCRIPTION
    🔴 THE QUESTION THIS ANSWERS: "how do i change the sas on 1000 customers?"
    With an ad-hoc SAS the answer is "you cannot" -- the expiry and permissions live INSIDE each
    issued token, so changing either means reissuing every token and reaching into every
    environment that holds one. And the only revocation lever is rotating the storage account key,
    which invalidates EVERY customer's URL at once and leaves none of them able to fetch the
    replacement: a fleet-wide outage as the only security control.

    🔑 Publish-PimSourceArchive signs against a STORED ACCESS POLICY instead. A policy-backed SAS
    carries no expiry of its own -- it takes validity from the policy at read time. So:

        extend   -> move the policy's expiry forward. Every issued URL keeps working. Nobody is
                    contacted, nothing is redeployed, no environment changes.
        revoke   -> delete the policy. Every URL signed against it stops working immediately.

    🪤 SCOPE IS DECIDED AT PUBLISH TIME, NOT HERE. A customer published into the SHARED container
    shares one policy, so revoking them revokes everyone. Publishing with -CustomerId gives that
    customer their own container and policy, which is what makes single-customer revocation
    possible at all. Azure allows only five policies per container, which is why isolation is a
    container per customer rather than a policy per customer.

.PARAMETER Revoke
    Delete the policy instead of extending it. Every URL signed against it stops working.

.EXAMPLE
    .\Update-PimSourceAccess.ps1 -StorageAccount <acct> -Days 400
    Push the shared feed's expiry out by 400 days. No customer is touched.

.EXAMPLE
    .\Update-PimSourceAccess.ps1 -StorageAccount <acct> -CustomerId contoso -Revoke
    Cut off ONE customer, immediately, leaving every other customer working.

.EXAMPLE
    .\Update-PimSourceAccess.ps1 -StorageAccount <acct> -All -Days 400
    Extend every per-customer feed in the account in one pass.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$StorageAccount,
    [string]$SubscriptionId,
    [string]$Container = 'pim-src',
    [string]$CustomerId,
    [string]$PolicyName = 'srcread',
    [int]$Days = 400,
    [switch]$Revoke,
    [switch]$All
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
. (Join-Path $here '_PimAz.ps1')

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m) { Write-Host "    $m" -ForegroundColor Yellow }

$sub = @(); if ("$SubscriptionId".Trim()) { $sub = @('--subscription', "$SubscriptionId".Trim()) }
if ("$CustomerId".Trim()) {
    $cid = ("$CustomerId".Trim().ToLowerInvariant() -replace '[^a-z0-9-]', '-').Trim('-')
    if (-not $cid) { throw "Update-PimSourceAccess: -CustomerId '$CustomerId' contains no usable characters." }
    $Container = "pim-src-$cid"
}

Write-Host "`n=== PIM source access ($(if ($Revoke) { 'REVOKE' } else { "extend +$Days days" })) ===" -ForegroundColor Cyan

# 🔑 The key is read here (a management-plane call) and never leaves this process. What customers
# hold is a read-only SAS to one container; the key itself is never distributed.
$key = "$(az storage account keys list --account-name $StorageAccount @sub --query "[0].value" -o tsv 2>$null)".Trim()
if (-not $key) { throw "Update-PimSourceAccess: could not read a key for '$StorageAccount'." }

$targets = @()
if ($All) {
    # 🪤 ONLY the source containers. A prefix match keeps this away from anything else in the
    # account -- a revoke loop that wandered into unrelated containers would be unrecoverable.
    $targets = @(az storage container list --account-name $StorageAccount --account-key $key --query "[].name" -o tsv 2>$null) |
               ForEach-Object { "$_".Trim() } | Where-Object { $_ -and ($_ -eq 'pim-src' -or $_ -like 'pim-src-*') }
    if (-not $targets.Count) { throw "Update-PimSourceAccess: no 'pim-src*' containers found in '$StorageAccount'." }
    Note "$($targets.Count) source container(s) found"
} else {
    $targets = @($Container)
}

$expiry = (Get-Date).ToUniversalTime().AddDays($Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
$done = 0; $failed = @()
foreach ($c in $targets) {
    if ($Revoke) {
        if (-not $PSCmdlet.ShouldProcess("$StorageAccount/$c", "REVOKE policy '$PolicyName'")) { continue }
        Step "revoke $c"
        $global:LASTEXITCODE = 0
        az storage container policy delete --account-name $StorageAccount -c $c -n $PolicyName --account-key $key -o none 2>$null
        # 🔴 PROVE IT IS GONE. A revoke that silently did nothing is the worst possible outcome
        # here: the operator believes access is cut and it is not.
        $still = "$(az storage container policy show --account-name $StorageAccount -c $c -n $PolicyName --account-key $key --query expiry -o tsv 2>$null)".Trim()
        if ($still) { $failed += $c; Warn "  STILL PRESENT -- access is NOT revoked on $c" }
        else { $done++; Note '  revoked + verified' }
        continue
    }
    if (-not $PSCmdlet.ShouldProcess("$StorageAccount/$c", "extend policy '$PolicyName' to $expiry")) { continue }
    Step "extend $c"
    $global:LASTEXITCODE = 0
    az storage container policy update --account-name $StorageAccount -c $c -n $PolicyName `
        --permissions r --expiry $expiry --account-key $key -o none 2>$null
    if ($LASTEXITCODE -ne 0) {
        # Not there yet (a container published before policies existed, or a fresh one).
        az storage container policy create --account-name $StorageAccount -c $c -n $PolicyName `
            --permissions r --expiry $expiry --account-key $key -o none 2>$null
    }
    $global:LASTEXITCODE = 0
    $back = "$(az storage container policy show --account-name $StorageAccount -c $c -n $PolicyName --account-key $key --query expiry -o tsv 2>$null)".Trim()
    if (-not $back) { $failed += $c; Warn "  could NOT read the policy back on $c -- treat its URLs as unchanged" }
    else { $done++; Note "  expires $back" }
}

Write-Host ''
if ($failed.Count) {
    Write-Host ("==> {0} container(s) done, {1} FAILED: {2}" -f $done, $failed.Count, ($failed -join ', ')) -ForegroundColor Red
    exit 1
}
Write-Host "==> $done container(s) updated. NO customer environment was contacted." -ForegroundColor Green
if (-not $Revoke) {
    Note 'Every URL already issued against this policy keeps working with the new expiry.'
} else {
    Note 'Every URL signed against the deleted policy is now refused. Re-publish to issue new ones.'
}
exit 0
