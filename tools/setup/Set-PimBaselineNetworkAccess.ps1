#Requires -Version 5.1
<#
.SYNOPSIS
    71.34 -- PUBLIC-BUT-SIGNED access to the MSP master's signed-baseline store (DESIGN 13.7): let exactly the named
    networks read the bundle blob anonymously, and nobody else. No SAS, no stored access policy, no account key, and
    nothing in the access path that expires.

.DESCRIPTION
    Operator 2026-09-17: "go back to original design. we can not release the current." The SAS read link had an
    expiry, needed the master's certificate on the managed tenant's side and a weekly SYSTEM rotation task. This
    replaces all of it with what DESIGN 13.7 always described:

      TRUST  = the RSA signature. Every pull verifies it against the public certificate embedded in the product and
               REFUSES a bundle that does not verify (engine/_shared/PIM-Baseline.ps1 Test-PimBaselineDoc).
      ACCESS = the network. The container allows anonymous read of BLOBS only (no listing), the account's firewall
               default action is Deny, and one allow rule names each reader:
                 * a VIRTUAL NETWORK RULE for the managed tenant's Container Apps subnet -- the default. It may be in
                   another Microsoft Entra tenant (by fully qualified subnet id). The subnet needs the
                   Microsoft.Storage (same region) or Microsoft.Storage.Global (any region) service endpoint, which the
                   managed tenant's own build sets (Initialize-PimBaselinePullNetwork.ps1).
                 * an IP RULE only for a reader with a fixed PUBLIC egress address in ANOTHER region. IP rules have no
                   effect on requests from the same Azure region as the storage account (Microsoft documents this).

    Adds are idempotent; -Remove takes away exactly the named sources and nothing else (and refuses to leave the store
    with no allowed network at all). Every change is READ BACK from ARM, and audited in the master store
    ('msp.tenant.network') when -SqlServerFqdn is given. Firewall and public-access settings are control-plane
    operations, so this works even though the data plane is firewalled.

.PARAMETER SubnetResourceId / IpAddress
    The reader(s): /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/virtualNetworks/<vnet>/subnets/<subnet>
    and/or a public IPv4 address or range.

.PARAMETER EnsurePosture
    Also make the store public-but-signed: allowBlobPublicAccess=true, container public access 'blob', default action
    Deny (applied LAST, after the allow rules exist). New-PimBaselineStorage.ps1 -PublicSignedRead passes it.

.PARAMETER Remove
    Remove the named source(s) -- a managed tenant that no longer receives the baseline.

.EXAMPLE
    .\Set-PimBaselineNetworkAccess.ps1 -SubscriptionId <master sub> -ResourceGroup rg-automateit-m1 -StorageAccount stpimbaselinem1 `
        -SubnetResourceId /subscriptions/<slave sub>/resourceGroups/rg-automateit-s1/providers/Microsoft.Network/virtualNetworks/vnet-pim-s1/subnets/snet-pim-aca
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$StorageAccount,
    [string]$Container = 'baselines',
    [string[]]$SubnetResourceId = @(),
    [string[]]$IpAddress = @(),
    [switch]$Remove,
    [switch]$EnsurePosture,
    # Audit (optional): the master store and the identity that writes the audit row.
    [string]$ManagedTenantId,
    [string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseSignedInAccount
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $solRoot 'engine\_shared\PIM-MspBuild.ps1')
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }

$sub = @('--subscription', "$SubscriptionId".Trim())
function Read-PimBaselineStoreNetwork {
    $ErrorActionPreference = 'Continue'
    $acct = $null
    try { $acct = (az storage account show @sub -g $ResourceGroup -n $StorageAccount -o json --only-show-errors 2>$null) | Out-String | ConvertFrom-Json } catch { $acct = $null }
    $cont = ''
    try { $cont = "$(az storage container-rm show @sub -g $ResourceGroup --storage-account $StorageAccount -n $Container --query publicAccess -o tsv --only-show-errors 2>$null)".Trim() } catch { $cont = '' }
    if (-not $acct) { return $null }
    return @{
        defaultAction         = "$($acct.networkRuleSet.defaultAction)"
        allowBlobPublicAccess = [bool]$acct.allowBlobPublicAccess
        containerPublicAccess = $cont
        subnetIds             = @(@($acct.networkRuleSet.virtualNetworkRules) | Where-Object { $_ } | ForEach-Object { "$($_.virtualNetworkResourceId)" })
        ipRules               = @(@($acct.networkRuleSet.ipRules) | Where-Object { $_ } | ForEach-Object { "$($_.ipAddressOrRange)" })
    }
}

Step ("bundle store network access: {0}/{1} -- {2}" -f $StorageAccount, $Container, $(if ($Remove) { 'REMOVE' } else { 'allow' }))
$before = Read-PimBaselineStoreNetwork
if (-not $before) { throw "storage account '$StorageAccount' not found in $ResourceGroup (subscription $SubscriptionId) -- run New-PimBaselineStorage.ps1 first." }
$plan = Get-PimBaselineNetworkPlan -Current $before -SubnetIds $SubnetResourceId -IpAddresses $IpAddress -Remove:$Remove -EnsurePosture:$EnsurePosture
if (-not $plan.ok) { throw $plan.reason }
if (-not @($plan.actions).Count) { Note 'already as requested -- nothing to change' }

foreach ($a in @($plan.actions)) {
    if (-not $PSCmdlet.ShouldProcess("$StorageAccount", "$($a.op) $($a.value)")) { continue }
    $azArgs = switch ($a.op) {
        'add-subnet'               { @('storage', 'account', 'network-rule', 'add', '-g', $ResourceGroup, '--account-name', $StorageAccount, '--subnet', $a.value) }
        'remove-subnet'            { @('storage', 'account', 'network-rule', 'remove', '-g', $ResourceGroup, '--account-name', $StorageAccount, '--subnet', $a.value) }
        'add-ip'                   { @('storage', 'account', 'network-rule', 'add', '-g', $ResourceGroup, '--account-name', $StorageAccount, '--ip-address', $a.value) }
        'remove-ip'                { @('storage', 'account', 'network-rule', 'remove', '-g', $ResourceGroup, '--account-name', $StorageAccount, '--ip-address', $a.value) }
        'allow-blob-public-access' { @('storage', 'account', 'update', '-g', $ResourceGroup, '-n', $StorageAccount, '--allow-blob-public-access', 'true') }
        'container-public-access'  { @('storage', 'container-rm', 'update', '-g', $ResourceGroup, '--storage-account', $StorageAccount, '-n', $Container, '--public-access', 'blob') }
        'default-deny'             { @('storage', 'account', 'update', '-g', $ResourceGroup, '-n', $StorageAccount, '--default-action', 'Deny') }
    }
    Note "$($a.op) $($a.value)"
    $ErrorActionPreference = 'Continue'
    az @azArgs @sub -o none --only-show-errors
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($code -ne 0) {
        $hint = if ($a.op -eq 'allow-blob-public-access') { ' (an Azure Policy that forbids anonymous blob access on storage accounts refuses exactly this -- it needs an exemption for this one account)' }
                elseif ($a.op -like '*subnet') { (' (the subnet must exist and carry a Microsoft.Storage / Microsoft.Storage.Global service endpoint. A LinkedAuthorizationFailed here means ARM wanted ' +
                                                  'this identity to hold Microsoft.Network/virtualNetworks/subnets/joinViaServiceEndpoint/action on a subnet in ANOTHER tenant -- the managed tenant grants that ' +
                                                  'once on its subnet, or the pull uses a private endpoint to this store instead, DESIGN 13.7 option 1)') } else { '' }
        throw "az failed ($code) on '$($a.op) $($a.value)'$hint. Nothing after it was applied; re-run after fixing (idempotent)."
    }
}

# ---- READ BACK: the store must now be exactly what was asked -----------------------------------------------------
$after = Read-PimBaselineStoreNetwork
$problems = @()
$subsAfter = @($after.subnetIds | ForEach-Object { "$_".ToLowerInvariant() })
foreach ($s in @($SubnetResourceId | Where-Object { "$_".Trim() })) {
    $has = $subsAfter -contains "$s".Trim().ToLowerInvariant()
    if ($Remove -and $has) { $problems += "subnet rule still present: $s" } elseif (-not $Remove -and -not $has) { $problems += "subnet rule missing: $s" }
}
foreach ($p in @($IpAddress | Where-Object { "$_".Trim() })) {
    $has = @($after.ipRules) -contains "$p".Trim()
    if ($Remove -and $has) { $problems += "IP rule still present: $p" } elseif (-not $Remove -and -not $has) { $problems += "IP rule missing: $p" }
}
if ($EnsurePosture) {
    if (-not $after.allowBlobPublicAccess) { $problems += 'allowBlobPublicAccess is not true' }
    if ("$($after.containerPublicAccess)".ToLowerInvariant() -ne 'blob') { $problems += "container '$Container' public access is '$($after.containerPublicAccess)', not 'blob' (anonymous blob read, no listing)" }
    if ("$($after.defaultAction)" -ne 'Deny') { $problems += "firewall default action is '$($after.defaultAction)', not Deny" }
}
if ($problems.Count) { throw ("read-back FAILED: " + ($problems -join '; ')) }
Note ("read back: default={0} anonymousBlobRead={1}/{2} subnets={3} ips={4}" -f $after.defaultAction, $after.allowBlobPublicAccess, $after.containerPublicAccess, @($after.subnetIds).Count, @($after.ipRules).Count)

if ("$SqlServerFqdn".Trim() -and @($plan.actions).Count -and -not $WhatIfPreference) {
    try {
        . (Join-Path $PSScriptRoot '_PimSetupSql.ps1')
        $cs = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -UseSignedInAccount:$UseSignedInAccount
        $target = if ("$ManagedTenantId".Trim()) { "$ManagedTenantId".Trim().ToLowerInvariant() } else { "$StorageAccount/$Container" }
        Write-PimSetupAudit -ConnectionString $cs -Action 'msp.tenant.network' -Target $target `
            -Before @{ subnets = @($before.subnetIds); ips = @($before.ipRules); defaultAction = $before.defaultAction } `
            -After @{ store = "$StorageAccount/$Container"; subnets = @($after.subnetIds); ips = @($after.ipRules); defaultAction = $after.defaultAction; removed = [bool]$Remove }
        Note 'audited: msp.tenant.network'
    } catch { Write-Warning "the network change is applied and read back, but its audit row could not be written: $($_.Exception.Message)" }
}
Write-Host ("==> OK -- {0}: {1}" -f $StorageAccount, $(if ($Remove) { 'access removed' } else { 'the named networks can read the signed bundle; nothing expires' })) -ForegroundColor Green
exit 0
